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

use std::collections::BTreeSet;
use std::fmt;

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
    pub fn canonical_payload(&self) -> Vec<u8> {
        let creds = self.credentials_checked.join(",");
        format!(
            "{}:{}:{}:{}:{}",
            self.timestamp, creds, self.nonce, self.tier, self.epoch
        )
        .into_bytes()
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
            expected_signature_fn: signature_fn,
            tier_table,
        }
    }

    /// Classify an action into its safety tier.
    ///
    /// Returns Advisory if the action is not in the tier table.
    pub fn classify_action(&self, action_id: &str) -> SafetyTier {
        for (pattern, tier) in &self.tier_table {
            if action_id == pattern || action_id.starts_with(pattern.as_str()) {
                return *tier;
            }
        }
        SafetyTier::Advisory
    }

    /// Verify a FreshnessProof's signature and nonce uniqueness.
    ///
    /// INV-RFG-PROOF: Reject tampered proofs.
    pub fn verify_proof(&mut self, proof: &FreshnessProof) -> Result<(), FreshnessError> {
        // Check replay
        if self.consumed_nonces.contains(&proof.nonce) {
            return Err(FreshnessError::ReplayDetected {
                nonce: proof.nonce.clone(),
            });
        }

        // Check signature
        let expected = (self.expected_signature_fn)(proof);
        if proof.signature != expected {
            return Err(FreshnessError::ProofTampered {
                detail: "signature mismatch".into(),
            });
        }

        // Consume nonce
        self.consumed_nonces.insert(proof.nonce.clone());
        Ok(())
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

        // Fresh enough: pass
        if staleness <= max_staleness {
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
        let p = proof(SafetyTier::Critical, 42, "nonce-x");
        let payload = String::from_utf8(p.canonical_payload()).unwrap();
        assert!(payload.contains("1700000000"));
        assert!(payload.contains("cred-1,cred-2"));
        assert!(payload.contains("nonce-x"));
        assert!(payload.contains("Critical"));
        assert!(payload.contains("42"));
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
    fn critical_at_boundary_passes() {
        let mut g = gate();
        let p = proof(SafetyTier::Critical, 99, "n1");
        let d = g.check(&p, 100, true, false, "key_rotate", "tr-1").unwrap();
        assert!(d.allowed);
        assert_eq!(d.event_code, event_codes::RFG_001);
    }

    #[test]
    fn standard_fresh_proof_passes() {
        let mut g = gate();
        let p = proof(SafetyTier::Standard, 95, "n1");
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
        let err = g.check(&p, u64::MAX - 10, true, false, "act", "tr").unwrap_err();
        match err {
            FreshnessError::ProofTampered { detail } => {
                assert!(detail.contains("in the future"));
            }
            _ => panic!("Expected ProofTampered error"),
        }
    }
}
