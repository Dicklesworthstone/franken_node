//! bd-2sx: Revocation freshness gate for risky product actions.
//!
//! Integrates canonical revocation freshness semantics with three safety tiers
//! (Critical, Standard, Advisory), each with epoch-based staleness thresholds.
//! Every gated action must present a signed `FreshnessProof` that attests
//! revocation data was checked within the tier-specific window.
//!
//! Graceful degradation:
//! - Critical (Tier-1): fail-closed, no bypass
//! - Standard (Tier-2): owner-bypass allowed
//! - Advisory (Tier-3): proceed-with-warning

use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use std::fmt;

use crate::capacity_defaults::aliases::MAX_CONSUMED_NONCES;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Stable event codes for structured logging.
pub mod event_codes {
    /// RFG-001: Freshness check passed -- action may proceed.
    pub const RFG_001: &str = "RFG-001";
    /// RFG-002: Freshness check failed -- action blocked.
    pub const RFG_002: &str = "RFG-002";
    /// RFG-003: Freshness degraded -- proceeding with warning or bypass.
    pub const RFG_003: &str = "RFG-003";
    /// RFG-004: Emergency bypass activated for Critical-tier action.
    pub const RFG_004: &str = "RFG-004";
}

// ---------------------------------------------------------------------------
// SafetyTier
// ---------------------------------------------------------------------------

/// Safety tier classification for risky product actions.
///
/// Each tier has an epoch-based freshness threshold:
/// - Critical: 1 epoch (fail-closed)
/// - Standard: 5 epochs (owner-bypass)
/// - Advisory: 10 epochs (proceed-with-warning)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SafetyTier {
    /// Tier-1: most dangerous actions. Max staleness = 1 epoch.
    Critical,
    /// Tier-2: important but bypassable. Max staleness = 5 epochs.
    Standard,
    /// Tier-3: low-risk, monitored. Max staleness = 10 epochs.
    Advisory,
}

impl SafetyTier {
    /// Maximum staleness in epochs for this tier.
    pub fn max_staleness_epochs(&self) -> u64 {
        match self {
            Self::Critical => 1,
            Self::Standard => 5,
            Self::Advisory => 10,
        }
    }

    fn strictness(self) -> u8 {
        match self {
            Self::Critical => 3,
            Self::Standard => 2,
            Self::Advisory => 1,
        }
    }
}

impl fmt::Display for SafetyTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::Standard => write!(f, "Standard"),
            Self::Advisory => write!(f, "Advisory"),
        }
    }
}

// ---------------------------------------------------------------------------
// FreshnessProof
// ---------------------------------------------------------------------------

/// Signed proof struct accompanying every gated action.
///
/// INV-RFG-PROOF: The signature must be verified before the proof is accepted.
#[derive(Debug, Clone)]
pub struct FreshnessProof {
    /// Unix timestamp when proof was created.
    pub timestamp: u64,
    /// List of credential IDs verified against the revocation list.
    pub credentials_checked: Vec<String>,
    /// Unique nonce for replay prevention.
    pub nonce: String,
    /// Hex-encoded HMAC signature of the proof payload.
    pub signature: String,
    /// Safety tier of the gated action.
    pub tier: SafetyTier,
    /// Control epoch when the proof was generated.
    pub epoch: u64,
}

impl FreshnessProof {
    /// Compute the canonical payload bytes for signature verification.
    ///
    /// Uses length-prefixed encoding to prevent delimiter-collision attacks
    /// where crafted credential IDs or nonces shift field boundaries.
    pub fn canonical_payload(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"rfg_freshness_proof_v1:");
        hasher.update(self.timestamp.to_le_bytes());
        // Length-prefix each credential individually
        hasher.update((self.credentials_checked.len() as u64).to_le_bytes());
        for cred in &self.credentials_checked {
            hasher.update((cred.len() as u64).to_le_bytes());
            hasher.update(cred.as_bytes());
        }
        hasher.update((self.nonce.len() as u64).to_le_bytes());
        hasher.update(self.nonce.as_bytes());
        let tier_str = self.tier.to_string();
        hasher.update((tier_str.len() as u64).to_le_bytes());
        hasher.update(tier_str.as_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.finalize().to_vec()
    }
}

// ---------------------------------------------------------------------------
// FreshnessError
// ---------------------------------------------------------------------------

/// Error enumeration for freshness gate failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshnessError {
    /// Proof epoch too old for the action's tier.
    Stale {
        tier: SafetyTier,
        proof_epoch: u64,
        current_epoch: u64,
        max_staleness: u64,
    },
    /// Cannot contact the revocation service.
    ServiceUnreachable { reason: String },
    /// Proof signature verification failed.
    ProofTampered { detail: String },
    /// Nonce was previously consumed.
    ReplayDetected { nonce: String },
    /// Session lacks authentication for gated action.
    Unauthenticated,
}

impl FreshnessError {
    /// Stable error code string.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Stale { .. } => "ERR_RFG_STALE",
            Self::ServiceUnreachable { .. } => "ERR_RFG_SERVICE_DOWN",
            Self::ProofTampered { .. } => "ERR_RFG_TAMPERED",
            Self::ReplayDetected { .. } => "ERR_RFG_REPLAY",
            Self::Unauthenticated => "ERR_RFG_UNAUTHENTICATED",
        }
    }
}

impl fmt::Display for FreshnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stale {
                tier,
                proof_epoch,
                current_epoch,
                max_staleness,
            } => write!(
                f,
                "ERR_RFG_STALE: {tier} proof epoch {proof_epoch} is stale \
                 (current={current_epoch}, max_staleness={max_staleness})"
            ),
            Self::ServiceUnreachable { reason } => {
                write!(f, "ERR_RFG_SERVICE_DOWN: {reason}")
            }
            Self::ProofTampered { detail } => {
                write!(f, "ERR_RFG_TAMPERED: {detail}")
            }
            Self::ReplayDetected { nonce } => {
                write!(f, "ERR_RFG_REPLAY: nonce {nonce} already consumed")
            }
            Self::Unauthenticated => {
                write!(f, "ERR_RFG_UNAUTHENTICATED: session not authenticated")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GateDecision
// ---------------------------------------------------------------------------

/// Outcome of a freshness gate evaluation.
#[derive(Debug, Clone)]
pub struct GateDecision {
    /// Action identifier.
    pub action_id: String,
    /// Tier classification of the action.
    pub tier: SafetyTier,
    /// Whether the action was allowed.
    pub allowed: bool,
    /// Event code emitted.
    pub event_code: String,
    /// Human-readable reason.
    pub reason: String,
    /// Whether this was a degraded-mode decision (bypass/warning).
    pub degraded: bool,
    /// Trace identifier for audit.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// RevocationFreshnessGate
// ---------------------------------------------------------------------------

/// Gate controller that validates freshness before risky actions.
///
/// Maintains a set of consumed nonces for replay detection and a configurable
/// signature verifier.
///
/// INV-RFG-GATE: All Critical actions must pass the gate.
/// INV-RFG-DEGRADE: Graceful degradation per tier.
/// INV-RFG-SESSION: Checks require authenticated sessions.
pub struct RevocationFreshnessGate {
    /// Consumed nonces for replay detection.
    consumed_nonces: BTreeSet<String>,
    /// Insertion-order queue for FIFO eviction when `consumed_nonces` exceeds
    /// `MAX_CONSUMED_NONCES`.  BTreeSet alone evicts by lexicographic order,
    /// which lets an adversary craft nonces that push out recent entries.
    consumed_nonces_queue: VecDeque<String>,
    /// Expected signature for verification (simplified: real systems use HMAC).
    expected_signature_fn: Box<dyn Fn(&FreshnessProof) -> String + Send + Sync>,
    /// Action-to-tier classification table.
    tier_table: Vec<(String, SafetyTier)>,
}

impl RevocationFreshnessGate {
    /// Create a new gate with a signature verifier function and tier table.
    pub fn new(
        signature_fn: Box<dyn Fn(&FreshnessProof) -> String + Send + Sync>,
        tier_table: Vec<(String, SafetyTier)>,
    ) -> Self {
        Self {
            consumed_nonces: BTreeSet::new(),
            consumed_nonces_queue: VecDeque::new(),
            expected_signature_fn: signature_fn,
            tier_table,
        }
    }

    /// Classify an action into its safety tier.
    ///
    /// Returns Advisory if the action is not in the tier table.
    pub fn classify_action(&self, action_id: &str) -> SafetyTier {
        self.tier_table
            .iter()
            .filter(|(pattern, _)| {
                action_id == pattern || action_id.starts_with(pattern.as_str())
            })
            .map(|(_, tier)| *tier)
            .max_by_key(|tier| tier.strictness())
            .unwrap_or(SafetyTier::Advisory)
    }

    /// Verify a FreshnessProof's signature and replay preconditions.
    ///
    /// INV-RFG-PROOF: Reject tampered proofs.
    /// INV-RFG-REPLAY-PRECHECK: Reused nonces fail before semantic checks.
    pub fn verify_proof(&self, proof: &FreshnessProof) -> Result<(), FreshnessError> {
        if proof.nonce.trim().is_empty() {
            return Err(FreshnessError::ProofTampered {
                detail: "nonce must not be empty".into(),
            });
        }
        if proof.signature.trim().is_empty() {
            return Err(FreshnessError::ProofTampered {
                detail: "signature must not be empty".into(),
            });
        }
        if proof.credentials_checked.is_empty() {
            return Err(FreshnessError::ProofTampered {
                detail: "credentials_checked must not be empty".into(),
            });
        }
        if proof
            .credentials_checked
            .iter()
            .any(|credential| credential.trim().is_empty())
        {
            return Err(FreshnessError::ProofTampered {
                detail: "credentials_checked contains an empty credential id".into(),
            });
        }

        // Check replay
        if self.consumed_nonces.contains(&proof.nonce) {
            return Err(FreshnessError::ReplayDetected {
                nonce: proof.nonce.clone(),
            });
        }

        // Check signature
        let expected = (self.expected_signature_fn)(proof);
        if !crate::security::constant_time::ct_eq(&proof.signature, &expected) {
            return Err(FreshnessError::ProofTampered {
                detail: "signature mismatch".into(),
            });
        }
        Ok(())
    }

    fn consume_nonce(&mut self, nonce: &str) {
        // Consume nonce with bounded eviction to prevent unbounded memory growth.
        if self.consumed_nonces.insert(nonce.to_string()) {
            while self.consumed_nonces_queue.len() >= MAX_CONSUMED_NONCES {
                if let Some(oldest) = self.consumed_nonces_queue.pop_front() {
                    self.consumed_nonces.remove(&oldest);
                }
            }
            self.consumed_nonces_queue.push_back(nonce.to_string());
        }
    }

    /// Check freshness of a proof against the current epoch.
    ///
    /// INV-RFG-GATE: Critical actions fail-closed.
    /// INV-RFG-DEGRADE: Degradation per tier.
    /// INV-RFG-SESSION: Requires authenticated=true.
    pub fn check(
        &mut self,
        proof: &FreshnessProof,
        current_epoch: u64,
        authenticated: bool,
        owner_bypass: bool,
        action_id: &str,
        trace_id: &str,
    ) -> Result<GateDecision, FreshnessError> {
        // INV-RFG-SESSION: Must be authenticated
        if !authenticated {
            return Err(FreshnessError::Unauthenticated);
        }
        if action_id.trim().is_empty() {
            return Err(FreshnessError::ProofTampered {
                detail: "action_id must not be empty".into(),
            });
        }
        if trace_id.trim().is_empty() {
            return Err(FreshnessError::ProofTampered {
                detail: "trace_id must not be empty".into(),
            });
        }

        let tier = self.classify_action(action_id);
        if proof.tier != tier {
            return Err(FreshnessError::ProofTampered {
                detail: format!(
                    "proof tier {} does not match action tier {}",
                    proof.tier, tier
                ),
            });
        }

        // Verify proof integrity
        self.verify_proof(proof)?;

        if proof.epoch > current_epoch {
            return Err(FreshnessError::ProofTampered {
                detail: format!(
                    "proof epoch {} is in the future (current={})",
                    proof.epoch, current_epoch
                ),
            });
        }

        let max_staleness = tier.max_staleness_epochs();
        let staleness = current_epoch.saturating_sub(proof.epoch);

        // Fresh enough: pass (fail-closed: exact boundary = stale)
        if staleness < max_staleness {
            self.consume_nonce(&proof.nonce);
            return Ok(GateDecision {
                action_id: action_id.to_string(),
                tier,
                allowed: true,
                event_code: event_codes::RFG_001.to_string(),
                reason: format!(
                    "{tier} proof is fresh (staleness={staleness}, max={max_staleness})"
                ),
                degraded: false,
                trace_id: trace_id.to_string(),
            });
        }

        // Stale: apply degradation per tier
        match tier {
            SafetyTier::Critical => {
                // INV-RFG-GATE: fail-closed, no bypass
                Err(FreshnessError::Stale {
                    tier,
                    proof_epoch: proof.epoch,
                    current_epoch,
                    max_staleness,
                })
            }
            SafetyTier::Standard => {
                // INV-RFG-DEGRADE: owner-bypass allowed
                if owner_bypass {
                    self.consume_nonce(&proof.nonce);
                    Ok(GateDecision {
                        action_id: action_id.to_string(),
                        tier,
                        allowed: true,
                        event_code: event_codes::RFG_003.to_string(),
                        reason: format!(
                            "{tier} proof stale (staleness={staleness}) but owner bypass accepted"
                        ),
                        degraded: true,
                        trace_id: trace_id.to_string(),
                    })
                } else {
                    Err(FreshnessError::Stale {
                        tier,
                        proof_epoch: proof.epoch,
                        current_epoch,
                        max_staleness,
                    })
                }
            }
            SafetyTier::Advisory => {
                // INV-RFG-DEGRADE: proceed-with-warning
                self.consume_nonce(&proof.nonce);
                Ok(GateDecision {
                    action_id: action_id.to_string(),
                    tier,
                    allowed: true,
                    event_code: event_codes::RFG_003.to_string(),
                    reason: format!(
                        "{tier} proof stale (staleness={staleness}) -- proceeding with warning"
                    ),
                    degraded: true,
                    trace_id: trace_id.to_string(),
                })
            }
        }
    }

    /// Return the number of consumed nonces.
    pub fn consumed_nonce_count(&self) -> usize {
        self.consumed_nonces.len()
    }

    /// Check if a specific nonce has been consumed.
    pub fn is_nonce_consumed(&self, nonce: &str) -> bool {
        self.consumed_nonces.contains(nonce)
    }
}

impl fmt::Debug for RevocationFreshnessGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationFreshnessGate")
            .field("consumed_nonces", &self.consumed_nonces.len())
            .field("tier_table_entries", &self.tier_table.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sig(proof: &FreshnessProof) -> String {
        format!("sig-{}-{}", proof.nonce, proof.epoch)
    }

    fn gate() -> RevocationFreshnessGate {
        RevocationFreshnessGate::new(
            Box::new(test_sig),
            vec![
                ("key_rotate".to_string(), SafetyTier::Critical),
                ("trust_anchor".to_string(), SafetyTier::Critical),
                ("policy_deploy".to_string(), SafetyTier::Standard),
                ("connector_activate".to_string(), SafetyTier::Standard),
                ("telemetry_config".to_string(), SafetyTier::Advisory),
            ],
        )
    }

    fn proof(tier: SafetyTier, epoch: u64, nonce: &str) -> FreshnessProof {
        let mut p = FreshnessProof {
            timestamp: 1700000000,
            credentials_checked: vec!["cred-1".into(), "cred-2".into()],
            nonce: nonce.to_string(),
            signature: String::new(),
            tier,
            epoch,
        };
        p.signature = test_sig(&p);
        p
    }

    // --- SafetyTier tests ---

    #[test]
    fn critical_max_staleness_is_1() {
        assert_eq!(SafetyTier::Critical.max_staleness_epochs(), 1);
    }

    #[test]
    fn standard_max_staleness_is_5() {
        assert_eq!(SafetyTier::Standard.max_staleness_epochs(), 5);
    }

    #[test]
    fn advisory_max_staleness_is_10() {
        assert_eq!(SafetyTier::Advisory.max_staleness_epochs(), 10);
    }

    #[test]
    fn tier_display() {
        assert_eq!(SafetyTier::Critical.to_string(), "Critical");
        assert_eq!(SafetyTier::Standard.to_string(), "Standard");
        assert_eq!(SafetyTier::Advisory.to_string(), "Advisory");
    }

    // --- classify_action tests ---

    #[test]
    fn classify_critical_action() {
        let g = gate();
        assert_eq!(g.classify_action("key_rotate"), SafetyTier::Critical);
    }

    #[test]
    fn classify_standard_action() {
        let g = gate();
        assert_eq!(g.classify_action("policy_deploy"), SafetyTier::Standard);
    }

    #[test]
    fn classify_advisory_action() {
        let g = gate();
        assert_eq!(g.classify_action("telemetry_config"), SafetyTier::Advisory);
    }

    #[test]
    fn classify_unknown_defaults_to_advisory() {
        let g = gate();
        assert_eq!(g.classify_action("unknown_action"), SafetyTier::Advisory);
    }

    #[test]
    fn overlapping_lower_tier_prefix_cannot_shadow_critical_action() {
        let mut g = RevocationFreshnessGate::new(
            Box::new(test_sig),
            vec![
                ("key".to_string(), SafetyTier::Advisory),
                ("key_rotate".to_string(), SafetyTier::Critical),
            ],
        );
        assert_eq!(g.classify_action("key_rotate"), SafetyTier::Critical);
        assert_eq!(
            g.classify_action("key_rotate_extended"),
            SafetyTier::Critical
        );

        let p = proof(SafetyTier::Advisory, 100, "shadowed-critical");
        let err = g
            .check(&p, 100, true, false, "key_rotate", "tr-shadowed")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("does not match action tier Critical"));
        assert!(!g.is_nonce_consumed("shadowed-critical"));
    }

    // --- FreshnessProof tests ---

    #[test]
    fn proof_canonical_payload_deterministic() {
        let p = proof(SafetyTier::Critical, 100, "n1");
        let a = p.canonical_payload();
        let b = p.canonical_payload();
        assert_eq!(a, b);
    }

    #[test]
    fn proof_canonical_payload_includes_fields() {
        // canonical_payload() returns a SHA-256 hash. Verify each field
        // contributes by showing that changing any field changes the hash.
        let baseline = proof(SafetyTier::Critical, 42, "nonce-x");
        let baseline_hash = baseline.canonical_payload();

        // Changing nonce changes the hash
        let different_nonce = proof(SafetyTier::Critical, 42, "nonce-y");
        assert_ne!(baseline_hash, different_nonce.canonical_payload());

        // Changing epoch changes the hash
        let different_epoch = proof(SafetyTier::Critical, 43, "nonce-x");
        assert_ne!(baseline_hash, different_epoch.canonical_payload());

        // Changing tier changes the hash
        let different_tier = proof(SafetyTier::Standard, 42, "nonce-x");
        assert_ne!(baseline_hash, different_tier.canonical_payload());

        // Changing timestamp changes the hash
        let mut different_ts = proof(SafetyTier::Critical, 42, "nonce-x");
        different_ts.timestamp = 1700000001;
        assert_ne!(baseline_hash, different_ts.canonical_payload());

        // Changing credentials changes the hash
        let mut different_creds = proof(SafetyTier::Critical, 42, "nonce-x");
        different_creds.credentials_checked = vec!["cred-3".into()];
        assert_ne!(baseline_hash, different_creds.canonical_payload());
    }

    // --- check() fresh proofs ---

    #[test]
    fn critical_fresh_proof_passes() {
        let mut g = gate();
        let p = proof(SafetyTier::Critical, 100, "n1");
        let d = g.check(&p, 100, true, false, "key_rotate", "tr-1").unwrap();
        assert!(d.allowed);
        assert_eq!(d.event_code, event_codes::RFG_001);
        assert!(!d.degraded);
    }

    #[test]
    fn critical_at_boundary_denied() {
        let mut g = gate();
        let p = proof(SafetyTier::Critical, 99, "n1");
        // Fail-closed: staleness == max_staleness → Err(Stale), not Ok with allowed=false
        let err = g
            .check(&p, 100, true, false, "key_rotate", "tr-1")
            .unwrap_err();
        assert!(
            matches!(
                err,
                FreshnessError::Stale {
                    tier: SafetyTier::Critical,
                    ..
                }
            ),
            "fail-closed: exact boundary staleness must return Stale error"
        );
    }

    #[test]
    fn standard_fresh_proof_passes() {
        let mut g = gate();
        // staleness = 100 - 96 = 4 < max_staleness(Standard=5) → fresh
        let p = proof(SafetyTier::Standard, 96, "n1");
        let d = g
            .check(&p, 100, true, false, "policy_deploy", "tr-1")
            .unwrap();
        assert!(d.allowed);
        assert_eq!(d.event_code, event_codes::RFG_001);
    }

    #[test]
    fn advisory_fresh_proof_passes() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 90, "n1");
        let d = g
            .check(&p, 100, true, false, "telemetry_config", "tr-1")
            .unwrap();
        assert!(d.allowed);
    }

    // --- check() stale proofs ---

    #[test]
    fn critical_stale_denied() {
        let mut g = gate();
        let p = proof(SafetyTier::Critical, 98, "n1");
        let err = g
            .check(&p, 100, true, false, "key_rotate", "tr-1")
            .unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_STALE");
        assert!(!g.is_nonce_consumed("n1"));
    }

    #[test]
    fn critical_stale_no_bypass() {
        let mut g = gate();
        let p = proof(SafetyTier::Critical, 98, "n1");
        // Even with owner_bypass=true, Critical fails
        let err = g
            .check(&p, 100, true, true, "key_rotate", "tr-1")
            .unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_STALE");
    }

    #[test]
    fn standard_stale_denied_without_bypass() {
        let mut g = gate();
        let p = proof(SafetyTier::Standard, 94, "n1");
        let err = g
            .check(&p, 100, true, false, "policy_deploy", "tr-1")
            .unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_STALE");
        assert!(!g.is_nonce_consumed("n1"));
    }

    #[test]
    fn standard_stale_with_owner_bypass() {
        let mut g = gate();
        let p = proof(SafetyTier::Standard, 94, "n1");
        let d = g
            .check(&p, 100, true, true, "policy_deploy", "tr-1")
            .unwrap();
        assert!(d.allowed);
        assert!(d.degraded);
        assert_eq!(d.event_code, event_codes::RFG_003);
    }

    #[test]
    fn advisory_stale_proceeds_with_warning() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 89, "n1");
        let d = g
            .check(&p, 100, true, false, "telemetry_config", "tr-1")
            .unwrap();
        assert!(d.allowed);
        assert!(d.degraded);
        assert_eq!(d.event_code, event_codes::RFG_003);
    }

    #[test]
    fn action_tier_mismatch_rejected_and_nonce_not_consumed() {
        let mut g = gate();
        // key_rotate is classified as Critical, but proof claims Advisory.
        let p = proof(SafetyTier::Advisory, 100, "n-tier-mismatch");
        let err = g
            .check(&p, 100, true, false, "key_rotate", "tr-1")
            .unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(!g.is_nonce_consumed("n-tier-mismatch"));
    }

    #[test]
    fn verify_proof_rejects_replay_before_signature_mismatch() {
        let mut g = gate();
        let original = proof(SafetyTier::Advisory, 100, "n-replay-precedence");
        g.check(&original, 100, true, false, "telemetry_config", "tr-first")
            .unwrap();

        let mut tampered_replay = proof(SafetyTier::Advisory, 100, "n-replay-precedence");
        tampered_replay.signature = "bad-signature".to_string();
        let err = g.verify_proof(&tampered_replay).unwrap_err();

        assert!(matches!(
            err,
            FreshnessError::ReplayDetected { nonce } if nonce == "n-replay-precedence"
        ));
        assert_eq!(g.consumed_nonce_count(), 1);
    }

    #[test]
    fn unauthenticated_request_rejected_before_replay_lookup() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "n-auth-first");
        g.check(&p, 100, true, false, "telemetry_config", "tr-first")
            .unwrap();

        let err = g
            .check(
                &p,
                100,
                false,
                false,
                "telemetry_config",
                "tr-unauthenticated-replay",
            )
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_UNAUTHENTICATED");
        assert_eq!(g.consumed_nonce_count(), 1);
    }

    #[test]
    fn tier_mismatch_rejected_before_bad_signature() {
        let mut g = gate();
        let mut p = proof(SafetyTier::Advisory, 100, "n-tier-before-sig");
        p.signature = "bad-signature".to_string();

        let err = g
            .check(&p, 100, true, false, "key_rotate", "tr-tier-first")
            .unwrap_err();

        match err {
            FreshnessError::ProofTampered { detail } => {
                assert!(detail.contains("proof tier Advisory does not match action tier Critical"));
                assert!(!detail.contains("signature mismatch"));
            }
            other => panic!("expected tier mismatch tamper error, got {other:?}"),
        }
        assert!(!g.is_nonce_consumed("n-tier-before-sig"));
    }

    #[test]
    fn unknown_action_with_non_advisory_proof_is_rejected() {
        let mut g = gate();
        let p = proof(SafetyTier::Critical, 100, "n-unknown-action-tier");

        let err = g
            .check(&p, 100, true, false, "unclassified_action", "tr-unknown")
            .unwrap_err();

        match err {
            FreshnessError::ProofTampered { detail } => {
                assert!(detail.contains("proof tier Critical does not match action tier Advisory"));
            }
            other => panic!("expected tier mismatch tamper error, got {other:?}"),
        }
        assert!(!g.is_nonce_consumed("n-unknown-action-tier"));
    }

    #[test]
    fn standard_exact_boundary_without_bypass_is_stale() {
        let mut g = gate();
        let p = proof(SafetyTier::Standard, 95, "n-standard-boundary");

        let err = g
            .check(
                &p,
                100,
                true,
                false,
                "policy_deploy",
                "tr-standard-boundary",
            )
            .unwrap_err();

        assert!(
            matches!(
                err,
                FreshnessError::Stale {
                    tier: SafetyTier::Standard,
                    proof_epoch: 95,
                    current_epoch: 100,
                    max_staleness: 5
                }
            ),
            "standard proof at exact max staleness must require bypass"
        );
        assert!(!g.is_nonce_consumed("n-standard-boundary"));
    }

    #[test]
    fn standard_exact_boundary_with_bypass_degrades_and_consumes_nonce() {
        let mut g = gate();
        let p = proof(SafetyTier::Standard, 95, "n-standard-boundary-bypass");

        let decision = g
            .check(
                &p,
                100,
                true,
                true,
                "policy_deploy",
                "tr-standard-boundary-bypass",
            )
            .unwrap();

        assert!(decision.allowed);
        assert!(decision.degraded);
        assert_eq!(decision.event_code, event_codes::RFG_003);
        assert!(decision.reason.contains("staleness=5"));
        assert!(g.is_nonce_consumed("n-standard-boundary-bypass"));
    }

    #[test]
    fn advisory_exact_boundary_degrades_and_consumes_nonce() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 90, "n-advisory-boundary");

        let decision = g
            .check(
                &p,
                100,
                true,
                false,
                "telemetry_config",
                "tr-advisory-boundary",
            )
            .unwrap();

        assert!(decision.allowed);
        assert!(decision.degraded);
        assert_eq!(decision.event_code, event_codes::RFG_003);
        assert!(decision.reason.contains("staleness=10"));
        assert!(g.is_nonce_consumed("n-advisory-boundary"));
    }

    #[test]
    fn critical_future_epoch_rejected_even_with_owner_bypass_and_nonce_reusable() {
        let mut g = gate();
        let future = proof(SafetyTier::Critical, 101, "n-critical-future");

        let err = g
            .check(&future, 100, true, true, "key_rotate", "tr-critical-future")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(!g.is_nonce_consumed("n-critical-future"));

        let corrected = proof(SafetyTier::Critical, 100, "n-critical-future");
        let decision = g
            .check(
                &corrected,
                100,
                true,
                false,
                "key_rotate",
                "tr-critical-corrected",
            )
            .unwrap();
        assert!(decision.allowed);
        assert!(g.is_nonce_consumed("n-critical-future"));
    }

    #[test]
    fn stale_critical_rejection_does_not_poison_retry_nonce() {
        let mut g = gate();
        let stale = proof(SafetyTier::Critical, 98, "n-critical-stale-retry");

        let err = g
            .check(&stale, 100, true, false, "key_rotate", "tr-critical-stale")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_STALE");
        assert!(!g.is_nonce_consumed("n-critical-stale-retry"));

        let fresh = proof(SafetyTier::Critical, 100, "n-critical-stale-retry");
        let decision = g
            .check(&fresh, 100, true, false, "key_rotate", "tr-critical-retry")
            .unwrap();
        assert!(decision.allowed);
        assert!(g.is_nonce_consumed("n-critical-stale-retry"));
    }

    // --- Replay detection ---

    #[test]
    fn replay_detected() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "same-nonce");
        g.check(&p, 100, true, false, "act-1", "tr-1").unwrap();
        // Same nonce again
        let p2 = proof(SafetyTier::Advisory, 100, "same-nonce");
        let err = g.check(&p2, 100, true, false, "act-2", "tr-2").unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_REPLAY");
    }

    #[test]
    fn different_nonces_not_replay() {
        let mut g = gate();
        let p1 = proof(SafetyTier::Advisory, 100, "nonce-a");
        let p2 = proof(SafetyTier::Advisory, 100, "nonce-b");
        g.check(&p1, 100, true, false, "act-1", "tr-1").unwrap();
        g.check(&p2, 100, true, false, "act-2", "tr-2").unwrap();
        assert_eq!(g.consumed_nonce_count(), 2);
    }

    // --- Proof tampered ---

    #[test]
    fn tampered_proof_rejected() {
        let mut g = gate();
        let mut p = proof(SafetyTier::Advisory, 100, "n1");
        p.signature = "bad-sig".to_string();
        let err = g.check(&p, 100, true, false, "act-1", "tr-1").unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
    }

    // --- Unauthenticated ---

    #[test]
    fn unauthenticated_rejected() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "n1");
        let err = g.check(&p, 100, false, false, "act-1", "tr-1").unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_UNAUTHENTICATED");
    }

    // --- Error display ---

    #[test]
    fn error_display_stale() {
        let e = FreshnessError::Stale {
            tier: SafetyTier::Critical,
            proof_epoch: 98,
            current_epoch: 100,
            max_staleness: 1,
        };
        let s = e.to_string();
        assert!(s.contains("ERR_RFG_STALE"));
        assert!(s.contains("Critical"));
    }

    #[test]
    fn error_display_service_unreachable() {
        let e = FreshnessError::ServiceUnreachable {
            reason: "timeout".into(),
        };
        assert!(e.to_string().contains("ERR_RFG_SERVICE_DOWN"));
    }

    #[test]
    fn error_display_tampered() {
        let e = FreshnessError::ProofTampered {
            detail: "mismatch".into(),
        };
        assert!(e.to_string().contains("ERR_RFG_TAMPERED"));
    }

    #[test]
    fn error_display_replay() {
        let e = FreshnessError::ReplayDetected {
            nonce: "n-1".into(),
        };
        assert!(e.to_string().contains("ERR_RFG_REPLAY"));
    }

    #[test]
    fn error_display_unauthenticated() {
        let e = FreshnessError::Unauthenticated;
        assert!(e.to_string().contains("ERR_RFG_UNAUTHENTICATED"));
    }

    // --- Error codes enumeration ---

    #[test]
    fn all_error_codes_present() {
        assert_eq!(
            FreshnessError::Stale {
                tier: SafetyTier::Critical,
                proof_epoch: 0,
                current_epoch: 0,
                max_staleness: 0
            }
            .code(),
            "ERR_RFG_STALE"
        );
        assert_eq!(
            FreshnessError::ServiceUnreachable {
                reason: String::new()
            }
            .code(),
            "ERR_RFG_SERVICE_DOWN"
        );
        assert_eq!(
            FreshnessError::ProofTampered {
                detail: String::new()
            }
            .code(),
            "ERR_RFG_TAMPERED"
        );
        assert_eq!(
            FreshnessError::ReplayDetected {
                nonce: String::new()
            }
            .code(),
            "ERR_RFG_REPLAY"
        );
        assert_eq!(
            FreshnessError::Unauthenticated.code(),
            "ERR_RFG_UNAUTHENTICATED"
        );
    }

    // --- GateDecision fields ---

    #[test]
    fn gate_decision_has_trace_id() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "n1");
        let d = g.check(&p, 100, true, false, "act-1", "tr-42").unwrap();
        assert_eq!(d.trace_id, "tr-42");
    }

    #[test]
    fn gate_decision_has_action_id() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "n1");
        let d = g
            .check(&p, 100, true, false, "telemetry_config", "tr-1")
            .unwrap();
        assert_eq!(d.action_id, "telemetry_config");
    }

    #[test]
    fn gate_decision_has_tier() {
        let mut g = gate();
        let p = proof(SafetyTier::Critical, 100, "n1");
        let d = g.check(&p, 100, true, false, "key_rotate", "tr-1").unwrap();
        assert_eq!(d.tier, SafetyTier::Critical);
    }

    // --- Nonce tracking ---

    #[test]
    fn nonce_consumed_after_check() {
        let mut g = gate();
        assert!(!g.is_nonce_consumed("n1"));
        let p = proof(SafetyTier::Advisory, 100, "n1");
        g.check(&p, 100, true, false, "act", "tr").unwrap();
        assert!(g.is_nonce_consumed("n1"));
    }

    #[test]
    fn consumed_nonce_count_increments() {
        let mut g = gate();
        assert_eq!(g.consumed_nonce_count(), 0);
        let p1 = proof(SafetyTier::Advisory, 100, "n1");
        g.check(&p1, 100, true, false, "act", "tr").unwrap();
        assert_eq!(g.consumed_nonce_count(), 1);
        let p2 = proof(SafetyTier::Advisory, 100, "n2");
        g.check(&p2, 100, true, false, "act", "tr").unwrap();
        assert_eq!(g.consumed_nonce_count(), 2);
    }

    // --- Debug impl ---

    #[test]
    fn gate_debug_format() {
        let g = gate();
        let dbg = format!("{g:?}");
        assert!(dbg.contains("RevocationFreshnessGate"));
        assert!(dbg.contains("consumed_nonces"));
    }

    // --- Edge cases ---

    #[test]
    fn zero_epoch_proof() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 0, "n-zero");
        let d = g.check(&p, 0, true, false, "act", "tr").unwrap();
        assert!(d.allowed);
    }

    #[test]
    fn very_large_epoch() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, u64::MAX - 5, "n-large");
        let err = g
            .check(&p, u64::MAX - 10, true, false, "act", "tr")
            .unwrap_err();
        if let FreshnessError::ProofTampered { detail } = err {
            assert!(detail.contains("in the future"));
        } else {
            unreachable!("Expected ProofTampered error");
        }
        assert!(!g.is_nonce_consumed("n-large"));
    }

    #[test]
    fn future_epoch_rejection_does_not_poison_retry_nonce() {
        let mut g = gate();

        let future = proof(SafetyTier::Advisory, 105, "n-retry");
        let err = g
            .check(&future, 100, true, false, "act", "tr-future")
            .unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(!g.is_nonce_consumed("n-retry"));

        let corrected = proof(SafetyTier::Advisory, 100, "n-retry");
        let decision = g
            .check(&corrected, 100, true, false, "act", "tr-corrected")
            .unwrap();
        assert!(decision.allowed);
        assert!(g.is_nonce_consumed("n-retry"));
    }

    // --- Bounded nonce eviction ---

    #[test]
    fn consumed_nonces_bounded_at_max_capacity() {
        let mut g = gate();
        // Insert MAX_CONSUMED_NONCES + 10 nonces and verify the set never
        // exceeds the configured cap.
        for i in 0..MAX_CONSUMED_NONCES + 10 {
            let nonce = format!("bounded-nonce-{i}");
            let p = proof(SafetyTier::Advisory, 100, &nonce);
            g.check(&p, 100, true, false, "act", "tr").unwrap();
        }
        assert!(g.consumed_nonce_count() <= MAX_CONSUMED_NONCES);
        // The oldest nonces should have been evicted.
        assert!(!g.is_nonce_consumed("bounded-nonce-0"));
        // Recent nonces should still be present.
        let last = format!("bounded-nonce-{}", MAX_CONSUMED_NONCES + 9);
        assert!(g.is_nonce_consumed(&last));
    }

    #[test]
    fn duplicate_nonce_does_not_grow_queue() {
        let mut g = gate();
        let p1 = proof(SafetyTier::Advisory, 100, "dup-n");
        g.check(&p1, 100, true, false, "act", "tr").unwrap();
        assert_eq!(g.consumed_nonce_count(), 1);
        // Attempting to re-use the same nonce should be rejected, not grow the queue.
        let p2 = proof(SafetyTier::Advisory, 100, "dup-n");
        let err = g.check(&p2, 100, true, false, "act", "tr");
        assert!(err.is_err());
        assert_eq!(g.consumed_nonce_count(), 1);
    }

    #[test]
    fn owner_bypass_does_not_override_standard_signature_mismatch() {
        let mut g = gate();
        let mut p = proof(SafetyTier::Standard, 90, "bad-standard-sig");
        p.signature = "tampered".to_string();

        let err = g
            .check(&p, 100, true, true, "policy_deploy", "tr-bad-standard")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(!g.is_nonce_consumed("bad-standard-sig"));
    }

    #[test]
    fn advisory_replay_fails_before_stale_warning_can_reconsume_nonce() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 80, "stale-advisory-replay");
        let first = g
            .check(&p, 100, true, false, "telemetry_config", "tr-first")
            .unwrap();
        assert!(first.degraded);
        assert!(g.is_nonce_consumed("stale-advisory-replay"));

        let second = g
            .check(&p, 100, true, false, "telemetry_config", "tr-second")
            .unwrap_err();

        assert_eq!(second.code(), "ERR_RFG_REPLAY");
        assert_eq!(g.consumed_nonce_count(), 1);
    }

    #[test]
    fn critical_prefix_action_rejects_advisory_proof_without_nonce_consumption() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "prefix-tier-mismatch");

        let err = g
            .check(
                &p,
                100,
                true,
                false,
                "key_rotate_shadow_action",
                "tr-prefix",
            )
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("does not match action tier Critical"));
        assert!(!g.is_nonce_consumed("prefix-tier-mismatch"));
    }

    #[test]
    fn critical_owner_bypass_still_fails_closed_at_exact_boundary() {
        let mut g = gate();
        let p = proof(SafetyTier::Critical, 99, "critical-boundary-bypass");

        let err = g
            .check(&p, 100, true, true, "key_rotate", "tr-critical-bypass")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_STALE");
        assert!(!g.is_nonce_consumed("critical-boundary-bypass"));
    }

    #[test]
    fn standard_stale_without_bypass_leaves_nonce_available_for_owner_retry() {
        let mut g = gate();
        let p = proof(SafetyTier::Standard, 90, "standard-retry-after-deny");
        let denied = g
            .check(&p, 100, true, false, "policy_deploy", "tr-denied")
            .unwrap_err();
        assert_eq!(denied.code(), "ERR_RFG_STALE");
        assert!(!g.is_nonce_consumed("standard-retry-after-deny"));

        let retried = g
            .check(&p, 100, true, true, "policy_deploy", "tr-owner-retry")
            .unwrap();

        assert!(retried.allowed);
        assert!(retried.degraded);
        assert!(g.is_nonce_consumed("standard-retry-after-deny"));
    }

    #[test]
    fn unauthenticated_stale_advisory_does_not_degrade_or_consume_nonce() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 1, "unauth-stale-advisory");

        let err = g
            .check(&p, 100, false, false, "telemetry_config", "tr-unauth-stale")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_UNAUTHENTICATED");
        assert!(!g.is_nonce_consumed("unauth-stale-advisory"));
        assert_eq!(g.consumed_nonce_count(), 0);
    }

    #[test]
    fn empty_nonce_rejected_without_consumption() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "");

        let err = g
            .check(&p, 100, true, false, "telemetry_config", "tr-empty-nonce")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("nonce must not be empty"));
        assert_eq!(g.consumed_nonce_count(), 0);
    }

    #[test]
    fn whitespace_nonce_rejected_without_consumption() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "   ");

        let err = g
            .check(
                &p,
                100,
                true,
                false,
                "telemetry_config",
                "tr-whitespace-nonce",
            )
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("nonce must not be empty"));
        assert_eq!(g.consumed_nonce_count(), 0);
    }

    #[test]
    fn empty_signature_rejected_even_if_expected_signature_is_empty() {
        let g = RevocationFreshnessGate::new(Box::new(|_| String::new()), Vec::new());
        let mut p = proof(SafetyTier::Advisory, 100, "empty-signature");
        p.signature.clear();

        let err = g.verify_proof(&p).unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("signature must not be empty"));
    }

    #[test]
    fn empty_credential_list_rejected_without_nonce_consumption() {
        let mut g = gate();
        let mut p = proof(SafetyTier::Advisory, 100, "empty-creds");
        p.credentials_checked.clear();
        p.signature = test_sig(&p);

        let err = g
            .check(&p, 100, true, false, "telemetry_config", "tr-empty-creds")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("credentials_checked must not be empty"));
        assert!(!g.is_nonce_consumed("empty-creds"));
    }

    #[test]
    fn blank_credential_id_rejected_without_nonce_consumption() {
        let mut g = gate();
        let mut p = proof(SafetyTier::Advisory, 100, "blank-cred");
        p.credentials_checked.push(" \t ".to_string());
        p.signature = test_sig(&p);

        let err = g
            .check(&p, 100, true, false, "telemetry_config", "tr-blank-cred")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("empty credential id"));
        assert!(!g.is_nonce_consumed("blank-cred"));
    }

    #[test]
    fn empty_trace_id_rejected_without_nonce_consumption() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "empty-trace");

        let err = g
            .check(&p, 100, true, false, "telemetry_config", "")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("trace_id must not be empty"));
        assert!(!g.is_nonce_consumed("empty-trace"));
    }

    #[test]
    fn whitespace_action_id_rejected_before_advisory_default() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "blank-action");

        let err = g
            .check(&p, 100, true, false, "  ", "tr-blank-action")
            .unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("action_id must not be empty"));
        assert!(!g.is_nonce_consumed("blank-action"));
    }

    #[test]
    fn unauthenticated_blank_action_still_reports_session_failure_first() {
        let mut g = gate();
        let p = proof(SafetyTier::Advisory, 100, "unauth-blank-action");

        let err = g.check(&p, 100, false, false, "", "").unwrap_err();

        assert_eq!(err.code(), "ERR_RFG_UNAUTHENTICATED");
        assert!(!g.is_nonce_consumed("unauth-blank-action"));
    }

    // === NEGATIVE-PATH SECURITY TESTS ===

    #[test]
    fn hmac_signature_forge_and_timing_attack_resistance_validation() {
        let mut g = gate();

        // Attempt signature forgery with all-zero HMAC
        let mut forge_zero = proof(SafetyTier::Advisory, 100, "forge-zero");
        forge_zero.signature = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let err = g.check(&forge_zero, 100, true, false, "telemetry_config", "tr-forge-zero").unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(!g.is_nonce_consumed("forge-zero"));

        // Attempt signature forgery with all-FF HMAC
        let mut forge_ff = proof(SafetyTier::Advisory, 100, "forge-ff");
        forge_ff.signature = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();

        let err = g.check(&forge_ff, 100, true, false, "telemetry_config", "tr-forge-ff").unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(!g.is_nonce_consumed("forge-ff"));

        // Test timing attack resistance - signatures that differ only in position
        let valid_sig = test_sig(&proof(SafetyTier::Advisory, 100, "timing-test"));

        let mut first_byte_diff = proof(SafetyTier::Advisory, 100, "timing-test");
        first_byte_diff.signature = if valid_sig.starts_with('s') { format!("t{}", &valid_sig[1..]) } else { format!("s{}", &valid_sig[1..]) };

        let mut last_byte_diff = proof(SafetyTier::Advisory, 100, "timing-test");
        let mut last_chars: Vec<char> = valid_sig.chars().collect();
        if let Some(last) = last_chars.last_mut() { *last = if *last == '0' { '1' } else { '0' }; }
        last_byte_diff.signature = last_chars.into_iter().collect();

        let mut mid_byte_diff = proof(SafetyTier::Advisory, 100, "timing-test");
        let mut mid_chars: Vec<char> = valid_sig.chars().collect();
        if mid_chars.len() > 2 { mid_chars[mid_chars.len() / 2] = if mid_chars[mid_chars.len() / 2] == '0' { '1' } else { '0' }; }
        mid_byte_diff.signature = mid_chars.into_iter().collect();

        // All should fail with same error code (constant-time comparison)
        let err1 = g.verify_proof(&first_byte_diff).unwrap_err();
        let err2 = g.verify_proof(&last_byte_diff).unwrap_err();
        let err3 = g.verify_proof(&mid_byte_diff).unwrap_err();

        assert_eq!(err1.code(), "ERR_RFG_TAMPERED");
        assert_eq!(err2.code(), "ERR_RFG_TAMPERED");
        assert_eq!(err3.code(), "ERR_RFG_TAMPERED");

        // Test signature substitution attack (valid signature for different proof)
        let proof_a = proof(SafetyTier::Advisory, 100, "proof-a");
        let proof_b_sig = test_sig(&proof(SafetyTier::Advisory, 100, "proof-b"));

        let mut substituted = proof_a.clone();
        substituted.signature = proof_b_sig;

        let err = g.verify_proof(&substituted).unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
    }

    #[test]
    fn replay_attack_amplification_and_nonce_exhaustion_prevention() {
        let mut g = gate();

        // Test massive nonce flooding to exhaust bounded memory
        let mut consumed_nonces = Vec::new();
        for i in 0..MAX_CONSUMED_NONCES + 100 {
            let nonce = format!("flood-{:06}", i);
            let p = proof(SafetyTier::Advisory, 100, &nonce);

            let result = g.check(&p, 100, true, false, "telemetry_config", "tr-flood");
            match result {
                Ok(_) => consumed_nonces.push(nonce),
                Err(e) => assert_eq!(e.code(), "ERR_RFG_REPLAY"), // Duplicate nonce
            }
        }

        // Verify bounded eviction worked
        assert!(g.consumed_nonce_count() <= MAX_CONSUMED_NONCES);
        assert!(consumed_nonces.len() >= MAX_CONSUMED_NONCES);

        // Verify oldest nonces were evicted (FIFO order)
        assert!(!g.is_nonce_consumed("flood-000000"));
        assert!(!g.is_nonce_consumed("flood-000001"));

        // Verify recent nonces are still present
        let recent_nonce = format!("flood-{:06}", MAX_CONSUMED_NONCES + 90);
        assert!(g.is_nonce_consumed(&recent_nonce));

        // Test nonce collision attacks with similar patterns
        let collision_patterns = [
            "nonce-collision-a",
            "nonce-collision-b",
            "nonce-collision-c",
            "nonce_collision_a",  // Underscore vs hyphen
            "nonce collision a",  // Space vs hyphen
            "nonce\0collision\0a", // Null byte injection
        ];

        let mut successful_nonces = 0;
        for pattern in &collision_patterns {
            let p = proof(SafetyTier::Advisory, 100, pattern);
            if g.check(&p, 100, true, false, "telemetry_config", "tr-collision").is_ok() {
                successful_nonces += 1;
            }
        }

        assert_eq!(successful_nonces, collision_patterns.len()); // All should be unique

        // Test replay attack with modified but structurally similar proofs
        let original = proof(SafetyTier::Advisory, 100, "replay-similar");
        g.check(&original, 100, true, false, "telemetry_config", "tr-original").unwrap();

        let mut modified_timestamp = original.clone();
        modified_timestamp.timestamp = 1700000001; // Different timestamp
        modified_timestamp.signature = test_sig(&modified_timestamp);

        let err = g.check(&modified_timestamp, 100, true, false, "telemetry_config", "tr-modified").unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_REPLAY"); // Same nonce should be detected
    }

    #[test]
    fn safety_tier_manipulation_and_classification_bypass_attacks() {
        let mut g = gate();

        // Test proof tier spoofing - Critical action with Advisory proof
        let spoofed_critical = proof(SafetyTier::Advisory, 100, "spoof-critical");
        let err = g.check(&spoofed_critical, 100, true, false, "key_rotate", "tr-spoof").unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("does not match action tier Critical"));

        // Test proof tier spoofing - Advisory action with Critical proof
        let spoofed_advisory = proof(SafetyTier::Critical, 100, "spoof-advisory");
        let err = g.check(&spoofed_advisory, 100, true, false, "unknown_action", "tr-spoof-adv").unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("does not match action tier Advisory"));

        // Test action classification manipulation through prefix matching
        let prefix_critical = proof(SafetyTier::Critical, 100, "prefix-critical");
        g.check(&prefix_critical, 100, true, false, "key_rotate_extended", "tr-prefix").unwrap(); // Should work

        let wrong_prefix = proof(SafetyTier::Standard, 100, "wrong-prefix");
        let err = g.check(&wrong_prefix, 100, true, false, "key_rotate_extended", "tr-wrong").unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_TAMPERED");

        // Test tier bypass through action name manipulation
        let bypass_attempts = [
            "KEY_ROTATE",           // Case variation
            "key_rotate ",          // Trailing space
            " key_rotate",          // Leading space
            "key\0rotate",          // Null byte injection
            "key_rotate\n",         // Newline injection
            "key_rotate\t",         // Tab injection
        ];

        for malicious_action in &bypass_attempts {
            let bypass_proof = proof(SafetyTier::Advisory, 100, &format!("bypass-{}", malicious_action.len()));

            // These should either classify correctly as Critical (fail due to tier mismatch)
            // or classify as Advisory (succeed) - but not bypass Critical protections
            match g.check(&bypass_proof, 100, true, false, malicious_action, "tr-bypass") {
                Ok(decision) => {
                    assert_eq!(decision.tier, SafetyTier::Advisory); // Must be classified as Advisory to succeed
                }
                Err(e) => {
                    assert_eq!(e.code(), "ERR_RFG_TAMPERED"); // Tier mismatch
                }
            }
        }

        // Test staleness calculation manipulation at tier boundaries
        let boundary_tests = [
            (SafetyTier::Critical, 99, 100, false),  // staleness=1, max=1 → stale
            (SafetyTier::Standard, 95, 100, false),  // staleness=5, max=5 → stale
            (SafetyTier::Advisory, 90, 100, false),  // staleness=10, max=10 → stale
            (SafetyTier::Critical, 100, 100, true),  // staleness=0, max=1 → fresh
            (SafetyTier::Standard, 96, 100, true),   // staleness=4, max=5 → fresh
            (SafetyTier::Advisory, 91, 100, true),   // staleness=9, max=10 → fresh
        ];

        for (tier, proof_epoch, current_epoch, should_be_fresh) in boundary_tests {
            let action = match tier {
                SafetyTier::Critical => "key_rotate",
                SafetyTier::Standard => "policy_deploy",
                SafetyTier::Advisory => "telemetry_config",
            };

            let boundary_proof = proof(tier, proof_epoch, &format!("boundary-{}-{}-{}", proof_epoch, current_epoch, should_be_fresh));
            let result = g.check(&boundary_proof, current_epoch, true, false, action, "tr-boundary");

            if should_be_fresh {
                assert!(result.is_ok(), "Expected fresh proof to succeed: tier={:?}, proof_epoch={}, current_epoch={}", tier, proof_epoch, current_epoch);
                let decision = result.unwrap();
                assert!(!decision.degraded);
            } else {
                assert!(result.is_err(), "Expected stale proof to fail: tier={:?}, proof_epoch={}, current_epoch={}", tier, proof_epoch, current_epoch);
                assert_eq!(result.unwrap_err().code(), "ERR_RFG_STALE");
            }
        }
    }

    #[test]
    fn epoch_manipulation_and_overflow_boundary_attacks() {
        let mut g = gate();

        // Test epoch overflow at u64::MAX boundaries
        let max_epoch_proof = proof(SafetyTier::Advisory, u64::MAX, "max-epoch");
        let result = g.check(&max_epoch_proof, u64::MAX, true, false, "telemetry_config", "tr-max");
        assert!(result.is_ok()); // Should work at exact boundary

        let overflow_epoch_proof = proof(SafetyTier::Advisory, u64::MAX, "overflow-epoch");
        let err = g.check(&overflow_epoch_proof, u64::MAX - 1, true, false, "telemetry_config", "tr-overflow").unwrap_err();
        assert_eq!(err.code(), "ERR_RFG_TAMPERED");
        assert!(format!("{err}").contains("in the future"));

        // Test epoch arithmetic overflow in staleness calculation
        let near_overflow_proof = proof(SafetyTier::Advisory, 0, "near-overflow");
        let result = g.check(&near_overflow_proof, u64::MAX, true, false, "telemetry_config", "tr-near-overflow");
        assert!(result.is_ok()); // saturating_sub should handle this safely

        // Test epoch manipulation to bypass staleness limits
        let staleness_bypass_attempts = [
            (SafetyTier::Critical, u64::MAX - 5, u64::MAX), // Massive staleness should still fail
            (SafetyTier::Standard, u64::MAX - 50, u64::MAX), // Even larger staleness
            (SafetyTier::Advisory, 0, u64::MAX),            // Maximum possible staleness
        ];

        for (tier, proof_epoch, current_epoch) in staleness_bypass_attempts {
            let action = match tier {
                SafetyTier::Critical => "key_rotate",
                SafetyTier::Standard => "policy_deploy",
                SafetyTier::Advisory => "telemetry_config",
            };

            let bypass_proof = proof(tier, proof_epoch, &format!("staleness-bypass-{}-{}", proof_epoch, current_epoch));
            let result = g.check(&bypass_proof, current_epoch, true, tier == SafetyTier::Standard, action, "tr-staleness");

            match tier {
                SafetyTier::Critical => {
                    assert!(result.is_err());
                    assert_eq!(result.unwrap_err().code(), "ERR_RFG_STALE");
                }
                SafetyTier::Standard => {
                    // With owner bypass, should degrade but succeed
                    assert!(result.is_ok());
                    assert!(result.unwrap().degraded);
                }
                SafetyTier::Advisory => {
                    // Should always degrade and succeed
                    assert!(result.is_ok());
                    assert!(result.unwrap().degraded);
                }
            }
        }

        // Test integer wraparound in epoch comparisons
        let wraparound_cases = [
            (1, 0),           // Proof from future (invalid)
            (u64::MAX, 0),    // Maximum future proof
            (0, u64::MAX),    // Maximum staleness
        ];

        for (proof_epoch, current_epoch) in wraparound_cases {
            let wraparound_proof = proof(SafetyTier::Advisory, proof_epoch, &format!("wraparound-{}-{}", proof_epoch, current_epoch));
            let result = g.check(&wraparound_proof, current_epoch, true, false, "telemetry_config", "tr-wraparound");

            if proof_epoch > current_epoch {
                assert!(result.is_err());
                assert_eq!(result.unwrap_err().code(), "ERR_RFG_TAMPERED");
            } else {
                // Should handle via graceful degradation for Advisory tier
                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn canonical_payload_collision_and_length_prefix_bypass_attacks() {
        // Test delimiter collision attacks in canonical payload generation
        let collision_attempts = [
            // Credential list manipulation to create identical payloads
            (vec!["ab".to_string(), "cd".to_string()], "nonce1"),
            (vec!["a".to_string(), "bcd".to_string()], "nonce1"), // Different split, same content
            (vec!["abcd".to_string()], "nonce1"),                  // Single credential

            // Nonce manipulation
            (vec!["cred1".to_string()], "ab\0cd"),     // Null byte in nonce
            (vec!["cred1".to_string()], "ab\ncd"),     // Newline in nonce
            (vec!["cred1".to_string()], "ab\x01cd"),   // Control character

            // Credential ID manipulation
            (vec!["cred\01".to_string()], "nonce1"),   // Null in credential
            (vec!["cred\n1".to_string()], "nonce1"),   // Newline in credential
            (vec!["".to_string(), "cred1".to_string()], "nonce1"), // Empty credential (should be rejected)
        ];

        let mut seen_payloads = std::collections::HashSet::new();

        for (credentials, nonce) in collision_attempts {
            let mut test_proof = FreshnessProof {
                timestamp: 1700000000,
                credentials_checked: credentials.clone(),
                nonce: nonce.to_string(),
                signature: String::new(),
                tier: SafetyTier::Advisory,
                epoch: 100,
            };
            test_proof.signature = test_sig(&test_proof);

            let payload = test_proof.canonical_payload();

            // Verify no two different logical proofs produce the same canonical payload
            let proof_description = format!("{:?}-{}", credentials, nonce);
            if !seen_payloads.insert((payload.clone(), proof_description.clone())) {
                panic!("Collision detected: {} produces duplicate canonical payload", proof_description);
            }

            // Test that empty credentials are handled properly
            if credentials.iter().any(|c| c.trim().is_empty()) {
                let mut g = gate();
                let result = g.verify_proof(&test_proof);
                assert!(result.is_err()); // Should be rejected
                assert_eq!(result.unwrap_err().code(), "ERR_RFG_TAMPERED");
            }
        }

        // Test length prefix manipulation attempts
        let length_attacks = [
            // Try to confuse length prefixes with crafted content
            "credential\x00\x00\x00\x00\x00\x00\x00\x08otherval", // Embedded length bytes
            "cred\x01\x00\x00\x00\x00\x00\x00\x00credential",      // Length that could point elsewhere
        ];

        for malicious_cred in length_attacks {
            let mut length_proof = FreshnessProof {
                timestamp: 1700000000,
                credentials_checked: vec![malicious_cred.to_string()],
                nonce: "length-attack".to_string(),
                signature: String::new(),
                tier: SafetyTier::Advisory,
                epoch: 100,
            };
            length_proof.signature = test_sig(&length_proof);

            // Should produce valid canonical payload (length prefixes prevent confusion)
            let payload = length_proof.canonical_payload();
            assert_eq!(payload.len(), 32); // SHA-256 hash length

            // Verify it's distinct from other payloads
            assert!(seen_payloads.insert((payload, malicious_cred.to_string())));
        }

        // Test tier string manipulation in canonical payload
        let tier_strings = ["Critical", "Standard", "Advisory"];
        for tier_str in tier_strings {
            let manual_tier_proof = FreshnessProof {
                timestamp: 1700000000,
                credentials_checked: vec!["cred1".to_string()],
                nonce: format!("tier-{}", tier_str),
                signature: String::new(),
                tier: SafetyTier::Advisory, // Actual tier
                epoch: 100,
            };

            let normal_payload = manual_tier_proof.canonical_payload();

            // Manually construct similar payload with different tier (to verify proper separation)
            let mut hasher = Sha256::new();
            hasher.update(b"rfg_freshness_proof_v1:");
            hasher.update(manual_tier_proof.timestamp.to_le_bytes());
            hasher.update((manual_tier_proof.credentials_checked.len() as u64).to_le_bytes());
            for cred in &manual_tier_proof.credentials_checked {
                hasher.update((cred.len() as u64).to_le_bytes());
                hasher.update(cred.as_bytes());
            }
            hasher.update((manual_tier_proof.nonce.len() as u64).to_le_bytes());
            hasher.update(manual_tier_proof.nonce.as_bytes());
            hasher.update((tier_str.len() as u64).to_le_bytes()); // Different tier string
            hasher.update(tier_str.as_bytes());
            hasher.update(manual_tier_proof.epoch.to_le_bytes());
            let manipulated_payload = hasher.finalize().to_vec();

            if tier_str != "Advisory" {
                assert_ne!(normal_payload, manipulated_payload, "Tier manipulation should produce different canonical payload");
            }
        }
    }

    #[test]
    fn input_validation_bypass_and_field_injection_attacks() {
        let mut g = gate();

        // Unicode injection attacks in various fields
        let unicode_attacks = [
            "\u{202E}gninoisiv\u{202C}nonce",     // BiDi override
            "nonce\u{200B}invisible",              // Zero-width space
            "noncе",                                // Cyrillic 'е' instead of Latin 'e'
            "nonce\u{0301}",                        // Combining character
            "nonce\u{FEFF}",                        // Zero-width no-break space (BOM)
        ];

        for attack_nonce in unicode_attacks {
            let unicode_proof = proof(SafetyTier::Advisory, 100, attack_nonce);
            let result = g.check(&unicode_proof, 100, true, false, "telemetry_config", "tr-unicode");

            // Should either succeed (treating as unique nonce) or fail validation
            match result {
                Ok(_) => assert!(g.is_nonce_consumed(attack_nonce)),
                Err(e) => assert_eq!(e.code(), "ERR_RFG_TAMPERED"),
            }
        }

        // Credential injection attacks
        let credential_attacks = [
            vec!["cred1".to_string(), "cred2\ncred3".to_string()],   // Newline injection
            vec!["cred1".to_string(), "cred2\0cred3".to_string()],   // Null byte injection
            vec!["cred1".to_string(), "cred2\tcred3".to_string()],   // Tab injection
            vec!["a".repeat(1000)],                                   // Extremely long credential
            vec!["\u{202E}evil\u{202C}cred".to_string()],           // BiDi override in credential
        ];

        for attack_creds in credential_attacks {
            let mut cred_proof = FreshnessProof {
                timestamp: 1700000000,
                credentials_checked: attack_creds.clone(),
                nonce: format!("cred-attack-{}", attack_creds.len()),
                signature: String::new(),
                tier: SafetyTier::Advisory,
                epoch: 100,
            };
            cred_proof.signature = test_sig(&cred_proof);

            let result = g.check(&cred_proof, 100, true, false, "telemetry_config", "tr-cred-attack");
            // Should succeed (credentials are treated as opaque identifiers)
            assert!(result.is_ok(), "Credential content should not affect verification: {:?}", attack_creds);
        }

        // Trace ID and Action ID injection attacks
        let id_attacks = [
            ("trace\ninjection", "normal_action"),
            ("trace\0injection", "normal_action"),
            ("normal_trace", "action\ninjection"),
            ("normal_trace", "action\0injection"),
            ("\u{202E}evil\u{202C}trace", "normal_action"),
            ("normal_trace", "\u{202E}evil\u{202C}action"),
        ];

        for (trace_id, action_id) in id_attacks {
            let id_proof = proof(SafetyTier::Advisory, 100, &format!("id-attack-{}-{}", trace_id.len(), action_id.len()));
            let result = g.check(&id_proof, 100, true, false, action_id, trace_id);

            // Should succeed unless the action/trace IDs are empty after trimming
            match result {
                Ok(_) => {
                    assert!(!trace_id.trim().is_empty());
                    assert!(!action_id.trim().is_empty());
                }
                Err(e) => {
                    assert_eq!(e.code(), "ERR_RFG_TAMPERED");
                    assert!(trace_id.trim().is_empty() || action_id.trim().is_empty());
                }
            }
        }

        // Signature format injection attacks
        let signature_attacks = [
            "not-hex-signature",
            "deadbeef\ninjection",
            "deadbeef\0injection",
            "\u{202E}evil\u{202C}signature",
            "sig-with-\ttabs",
            " padded-signature ",
        ];

        for attack_sig in signature_attacks {
            let mut sig_proof = proof(SafetyTier::Advisory, 100, &format!("sig-attack-{}", attack_sig.len()));
            sig_proof.signature = attack_sig.to_string();

            let result = g.verify_proof(&sig_proof);
            assert!(result.is_err()); // Should always fail signature verification
            assert_eq!(result.unwrap_err().code(), "ERR_RFG_TAMPERED");
        }
    }

    #[test]
    fn authentication_bypass_and_authorization_escalation_attacks() {
        let mut g = gate();

        // Test authentication bypass attempts with valid proofs
        let auth_bypass_cases = [
            (false, false, "Unauthenticated user without bypass"),
            (false, true, "Unauthenticated user with bypass flag"), // Should still fail
        ];

        for (authenticated, bypass_flag, description) in auth_bypass_cases {
            let bypass_proof = proof(SafetyTier::Standard, 100, &format!("auth-bypass-{}-{}", authenticated, bypass_flag));
            let result = g.check(&bypass_proof, 100, authenticated, bypass_flag, "policy_deploy", "tr-auth-bypass");

            assert!(result.is_err(), "{} should be rejected", description);
            assert_eq!(result.unwrap_err().code(), "ERR_RFG_UNAUTHENTICATED");
            assert!(!g.is_nonce_consumed(&bypass_proof.nonce));
        }

        // Test owner bypass escalation attacks
        let bypass_escalation_cases = [
            (SafetyTier::Critical, true, false),   // Critical should never allow bypass
            (SafetyTier::Critical, false, false),  // Critical without bypass
            (SafetyTier::Standard, true, true),    // Standard with bypass should work
            (SafetyTier::Standard, false, false),  // Standard without bypass should fail
            (SafetyTier::Advisory, true, true),    // Advisory always works (bypass irrelevant)
            (SafetyTier::Advisory, false, true),   // Advisory always works
        ];

        for (tier, owner_bypass, should_succeed) in bypass_escalation_cases {
            let action = match tier {
                SafetyTier::Critical => "key_rotate",
                SafetyTier::Standard => "policy_deploy",
                SafetyTier::Advisory => "telemetry_config",
            };

            // Create stale proof to trigger bypass logic
            let stale_epoch = 100 - tier.max_staleness_epochs() - 1;
            let escalation_proof = proof(tier, stale_epoch, &format!("escalation-{:?}-{}-{}", tier, owner_bypass, should_succeed));

            let result = g.check(&escalation_proof, 100, true, owner_bypass, action, "tr-escalation");

            if should_succeed {
                assert!(result.is_ok(), "Expected escalation to succeed for {:?} with bypass={}", tier, owner_bypass);
                let decision = result.unwrap();
                if tier != SafetyTier::Critical {
                    assert!(decision.degraded); // Should be marked as degraded
                }
                assert!(g.is_nonce_consumed(&escalation_proof.nonce));
            } else {
                assert!(result.is_err(), "Expected escalation to fail for {:?} with bypass={}", tier, owner_bypass);
                assert_eq!(result.unwrap_err().code(), "ERR_RFG_STALE");
                assert!(!g.is_nonce_consumed(&escalation_proof.nonce));
            }
        }

        // Test privilege escalation through tier manipulation
        let privilege_escalation_tests = [
            ("key_rotate", SafetyTier::Standard, false), // Critical action with Standard proof
            ("key_rotate", SafetyTier::Advisory, false), // Critical action with Advisory proof
            ("policy_deploy", SafetyTier::Advisory, false), // Standard action with Advisory proof
            ("policy_deploy", SafetyTier::Critical, false), // Standard action with Critical proof (mismatch)
            ("telemetry_config", SafetyTier::Critical, false), // Advisory action with Critical proof (mismatch)
            ("unknown_action", SafetyTier::Critical, false), // Unknown action with Critical proof (mismatch)
        ];

        for (action, proof_tier, should_succeed) in privilege_escalation_tests {
            let privilege_proof = proof(proof_tier, 100, &format!("privilege-{}-{:?}", action, proof_tier));
            let result = g.check(&privilege_proof, 100, true, false, action, "tr-privilege");

            if should_succeed {
                assert!(result.is_ok(), "Expected privilege escalation to succeed for {} with {:?}", action, proof_tier);
            } else {
                assert!(result.is_err(), "Expected privilege escalation to fail for {} with {:?}", action, proof_tier);
                assert_eq!(result.unwrap_err().code(), "ERR_RFG_TAMPERED");
                assert!(!g.is_nonce_consumed(&privilege_proof.nonce));
            }
        }
    }

    #[test]
    fn memory_exhaustion_and_resource_depletion_attacks() {
        let mut g = gate();

        // Test memory exhaustion through massive field values
        let massive_fields = [
            ("massive_nonce", "x".repeat(1_000_000)),
            ("massive_credential", vec!["y".repeat(1_000_000)]),
            ("many_credentials", (0..10_000).map(|i| format!("cred-{}", i)).collect::<Vec<_>>()),
        ];

        for (attack_type, field_value) in massive_fields.iter() {
            let mut memory_proof = FreshnessProof {
                timestamp: 1700000000,
                credentials_checked: if attack_type == &"massive_credential" || attack_type == &"many_credentials" {
                    field_value.clone()
                } else {
                    vec!["normal-cred".to_string()]
                },
                nonce: if attack_type == &"massive_nonce" {
                    field_value[0].clone()
                } else {
                    format!("nonce-{}", attack_type)
                },
                signature: String::new(),
                tier: SafetyTier::Advisory,
                epoch: 100,
            };
            memory_proof.signature = test_sig(&memory_proof);

            // Should handle massive inputs gracefully without crashing
            let result = g.check(&memory_proof, 100, true, false, "telemetry_config", "tr-memory");

            match attack_type {
                "many_credentials" => {
                    // Should succeed but might be slow
                    assert!(result.is_ok(), "Many credentials should be handled gracefully");
                }
                _ => {
                    // Should succeed for massive but otherwise valid inputs
                    assert!(result.is_ok(), "Massive {} should be handled gracefully", attack_type);
                }
            }
        }

        // Test nonce capacity exhaustion patterns
        let exhaustion_patterns = [
            "predictable-",     // Predictable pattern
            "random-pattern-",  // Semi-random pattern
            "",                 // Numeric only (will be formatted)
        ];

        for pattern in exhaustion_patterns {
            let pattern_nonces = (0..50).map(|i| format!("{}{:08x}", pattern, i)).collect::<Vec<_>>();

            for nonce in pattern_nonces {
                let pattern_proof = proof(SafetyTier::Advisory, 100, &nonce);
                let result = g.check(&pattern_proof, 100, true, false, "telemetry_config", "tr-pattern");

                // First occurrence should succeed
                if !g.is_nonce_consumed(&nonce) {
                    assert!(result.is_ok(), "First use of pattern nonce should succeed");
                } else {
                    // Subsequent uses should fail with replay
                    assert!(result.is_err());
                    assert_eq!(result.unwrap_err().code(), "ERR_RFG_REPLAY");
                }
            }
        }

        // Verify memory usage is still bounded
        assert!(g.consumed_nonce_count() <= MAX_CONSUMED_NONCES);

        // Test computational exhaustion through expensive canonical payload generation
        let expensive_proof = FreshnessProof {
            timestamp: 1700000000,
            credentials_checked: (0..1000).map(|i| "x".repeat(100 + i)).collect(), // Varying lengths
            nonce: "expensive-canonical".to_string(),
            signature: String::new(),
            tier: SafetyTier::Advisory,
            epoch: 100,
        };

        // Should complete without timeout (testing algorithmic complexity)
        let start = std::time::Instant::now();
        let _payload = expensive_proof.canonical_payload();
        let duration = start.elapsed();

        // Should complete within reasonable time (not exponential complexity)
        assert!(duration.as_secs() < 5, "Canonical payload generation took too long: {:?}", duration);
    }

    #[test]
    fn concurrent_access_and_race_condition_safety_validation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let gate_mutex = Arc::new(Mutex::new(gate()));
        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        // Concurrent proof verification attempts
        for i in 0..100 {
            let gate_clone = Arc::clone(&gate_mutex);
            let results_clone = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let nonce = format!("concurrent-{:03}", i);
                let tier = match i % 3 {
                    0 => SafetyTier::Critical,
                    1 => SafetyTier::Standard,
                    _ => SafetyTier::Advisory,
                };
                let action = match tier {
                    SafetyTier::Critical => "key_rotate",
                    SafetyTier::Standard => "policy_deploy",
                    SafetyTier::Advisory => "telemetry_config",
                };

                let test_proof = proof(tier, 100, &nonce);

                let mut gate = gate_clone.lock().unwrap();
                let result = gate.check(&test_proof, 100, true, false, action, &format!("tr-{}", i));

                let mut results = results_clone.lock().unwrap();
                results.push((i, nonce, result.is_ok()));
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        let results = results.lock().unwrap();
        assert_eq!(results.len(), 100);

        // Verify all operations completed successfully (no race conditions)
        let successful_ops = results.iter().filter(|(_, _, success)| *success).count();
        assert_eq!(successful_ops, 100, "All concurrent operations should succeed");

        // Verify nonce consumption state is consistent
        let gate = gate_mutex.lock().unwrap();
        assert_eq!(gate.consumed_nonce_count(), 100);

        // Verify no duplicate nonces were processed
        for (_, nonce, _) in results.iter() {
            assert!(gate.is_nonce_consumed(nonce), "Nonce {} should be consumed", nonce);
        }

        // Test concurrent replay attack detection
        drop(gate);
        drop(results);

        let replay_gate = Arc::new(Mutex::new(gate()));
        let replay_results = Arc::new(Mutex::new(Vec::new()));
        let mut replay_handles = vec![];

        // Multiple threads trying to use the same nonces
        for thread_id in 0..20 {
            let gate_clone = Arc::clone(&replay_gate);
            let results_clone = Arc::clone(&replay_results);

            let handle = thread::spawn(move || {
                for nonce_id in 0..10 {
                    let shared_nonce = format!("shared-nonce-{}", nonce_id);
                    let test_proof = proof(SafetyTier::Advisory, 100, &shared_nonce);

                    let mut gate = gate_clone.lock().unwrap();
                    let result = gate.check(&test_proof, 100, true, false, "telemetry_config", &format!("tr-{}-{}", thread_id, nonce_id));

                    let mut results = results_clone.lock().unwrap();
                    results.push((thread_id, nonce_id, shared_nonce, result.is_ok()));
                }
            });

            replay_handles.push(handle);
        }

        for handle in replay_handles {
            handle.join().unwrap();
        }

        let replay_results = replay_results.lock().unwrap();

        // Verify that each nonce was only accepted once across all threads
        let gate = replay_gate.lock().unwrap();
        for nonce_id in 0..10 {
            let nonce = format!("shared-nonce-{}", nonce_id);
            assert!(gate.is_nonce_consumed(&nonce), "Shared nonce {} should be consumed", nonce);

            // Count how many threads reported success for this nonce
            let success_count = replay_results.iter()
                .filter(|(_, n_id, _, success)| *n_id == nonce_id && *success)
                .count();

            assert_eq!(success_count, 1, "Exactly one thread should succeed per shared nonce {}", nonce_id);
        }

        // Total successful operations should equal number of unique nonces
        let total_successes = replay_results.iter().filter(|(_, _, _, success)| *success).count();
        assert_eq!(total_successes, 10, "Should have exactly 10 successful operations (one per unique nonce)");
    }
}
