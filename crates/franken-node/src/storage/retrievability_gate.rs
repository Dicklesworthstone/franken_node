//! bd-1fck: Retrievability-before-eviction proofs for L2→L3 lifecycle transitions.
//!
//! When trust artifacts transition from L2 (warm) to L3 (archive), the L2 copy
//! must not be evicted until a positive retrievability proof demonstrates the L3
//! copy is intact and fetchable. This module implements the safety interlock.
//!
//! # Invariants
//!
//! - **INV-RG-BLOCK-EVICTION**: Eviction requires a successful retrievability proof; no bypass.
//! - **INV-RG-PROOF-BINDING**: Each proof is bound to a specific (artifact_id, segment_id, target_tier).
//! - **INV-RG-FAIL-CLOSED**: Failed proofs block eviction unconditionally; no override or timeout bypass.
//! - **INV-RG-AUDIT-TRAIL**: Every proof attempt (pass or fail) is logged with structured diagnostics.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const RG_PROOF_PASSED: &str = "RG_PROOF_PASSED";
pub const RG_PROOF_FAILED: &str = "RG_PROOF_FAILED";
pub const RG_EVICTION_BLOCKED: &str = "RG_EVICTION_BLOCKED";
pub const RG_EVICTION_PERMITTED: &str = "RG_EVICTION_PERMITTED";
pub const RG_GATE_INITIALIZED: &str = "RG_GATE_INITIALIZED";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_HASH_MISMATCH: &str = "ERR_HASH_MISMATCH";
pub const ERR_LATENCY_EXCEEDED: &str = "ERR_LATENCY_EXCEEDED";
pub const ERR_TARGET_UNREACHABLE: &str = "ERR_TARGET_UNREACHABLE";
pub const ERR_EVICTION_BLOCKED: &str = "ERR_EVICTION_BLOCKED";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unique identifier for an artifact in the storage system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub String);

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Unique identifier for a storage segment being retired.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SegmentId(pub String);

impl fmt::Display for SegmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Storage tier in the tiered hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageTier {
    L1Hot,
    L2Warm,
    L3Archive,
}

impl StorageTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::L1Hot => "L1_hot",
            Self::L2Warm => "L2_warm",
            Self::L3Archive => "L3_archive",
        }
    }
}

impl fmt::Display for StorageTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Reason a retrievability proof failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofFailureReason {
    HashMismatch { expected: String, actual: String },
    LatencyExceeded { limit_ms: u64, actual_ms: u64 },
    TargetUnreachable { detail: String },
}

impl ProofFailureReason {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::HashMismatch { .. } => ERR_HASH_MISMATCH,
            Self::LatencyExceeded { .. } => ERR_LATENCY_EXCEEDED,
            Self::TargetUnreachable { .. } => ERR_TARGET_UNREACHABLE,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::HashMismatch { .. } => "hash_mismatch",
            Self::LatencyExceeded { .. } => "latency_exceeded",
            Self::TargetUnreachable { .. } => "target_unreachable",
        }
    }
}

impl fmt::Display for ProofFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashMismatch { expected, actual } => {
                write!(f, "hash mismatch: expected={}, actual={}", expected, actual)
            }
            Self::LatencyExceeded {
                limit_ms,
                actual_ms,
            } => {
                write!(
                    f,
                    "latency exceeded: limit={}ms, actual={}ms",
                    limit_ms, actual_ms
                )
            }
            Self::TargetUnreachable { detail } => {
                write!(f, "target unreachable: {}", detail)
            }
        }
    }
}

/// A successful retrievability proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievabilityProof {
    pub artifact_id: ArtifactId,
    pub segment_id: SegmentId,
    pub source_tier: StorageTier,
    pub target_tier: StorageTier,
    pub content_hash: String,
    pub proof_timestamp: u64,
    pub latency_ms: u64,
}

/// Error from a retrievability check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievabilityError {
    pub code: String,
    pub reason: ProofFailureReason,
    pub artifact_id: ArtifactId,
    pub segment_id: SegmentId,
    pub target_tier: StorageTier,
}

impl fmt::Display for RetrievabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] artifact={}, segment={}, tier={}: {}",
            self.code,
            self.artifact_id,
            self.segment_id,
            self.target_tier.label(),
            self.reason
        )
    }
}

/// Configuration for the retrievability gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievabilityConfig {
    /// Maximum acceptable fetch latency in milliseconds.
    pub max_latency_ms: u64,
    /// Whether to require exact content hash match.
    pub require_hash_match: bool,
}

impl Default for RetrievabilityConfig {
    fn default() -> Self {
        Self {
            max_latency_ms: 5000,
            require_hash_match: true,
        }
    }
}

/// A proof receipt record for audit persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofReceipt {
    pub artifact_id: String,
    pub segment_id: String,
    pub source_tier: String,
    pub target_tier: String,
    pub content_hash: String,
    pub proof_timestamp: u64,
    pub latency_ms: u64,
    pub passed: bool,
    pub failure_reason: Option<String>,
}

/// Structured event emitted by the gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateEvent {
    pub code: String,
    pub artifact_id: String,
    pub segment_id: String,
    pub detail: String,
}

/// Simulated target tier state for proof checking.
#[derive(Debug, Clone)]
pub struct TargetTierState {
    pub content_hash: String,
    pub reachable: bool,
    pub fetch_latency_ms: u64,
}

// ---------------------------------------------------------------------------
// RetrievabilityGate
// ---------------------------------------------------------------------------

/// Gate that enforces retrievability proofs before L2→L3 eviction.
pub struct RetrievabilityGate {
    config: RetrievabilityConfig,
    /// Simulated target tier contents: (artifact_id, target_tier) -> state
    target_state: BTreeMap<(String, String), TargetTierState>,
    receipts: Vec<ProofReceipt>,
    events: Vec<GateEvent>,
    /// Monotonic timestamp counter for deterministic testing.
    timestamp_counter: u64,
}

impl RetrievabilityGate {
    pub fn new(config: RetrievabilityConfig) -> Self {
        let mut gate = Self {
            config,
            target_state: BTreeMap::new(),
            receipts: Vec::new(),
            events: Vec::new(),
            timestamp_counter: 1000,
        };
        gate.events.push(GateEvent {
            code: RG_GATE_INITIALIZED.to_string(),
            artifact_id: String::new(),
            segment_id: String::new(),
            detail: format!(
                "Gate initialized: max_latency={}ms, require_hash={}",
                gate.config.max_latency_ms, gate.config.require_hash_match
            ),
        });
        gate
    }

    /// Register simulated target tier state for testing.
    pub fn register_target(
        &mut self,
        artifact_id: &ArtifactId,
        target_tier: StorageTier,
        state: TargetTierState,
    ) {
        self.target_state.insert(
            (artifact_id.0.clone(), target_tier.label().to_string()),
            state,
        );
    }

    /// Check retrievability of an artifact at the target tier.
    /// Returns a proof on success or an error on failure.
    ///
    /// # INV-RG-FAIL-CLOSED
    /// Any failure returns Err — there is no bypass.
    #[allow(clippy::result_large_err)]
    pub fn check_retrievability(
        &mut self,
        artifact_id: &ArtifactId,
        segment_id: &SegmentId,
        source_tier: StorageTier,
        target_tier: StorageTier,
        expected_hash: &str,
    ) -> Result<RetrievabilityProof, RetrievabilityError> {
        self.timestamp_counter = self.timestamp_counter.saturating_add(1);
        let ts = self.timestamp_counter;

        let key = (artifact_id.0.clone(), target_tier.label().to_string());
        let state = self.target_state.get(&key);

        // Check reachability
        let state = match state {
            Some(s) if !s.reachable => {
                let reason = ProofFailureReason::TargetUnreachable {
                    detail: format!(
                        "tier {} not reachable for artifact {}",
                        target_tier.label(),
                        artifact_id
                    ),
                };
                let err = RetrievabilityError {
                    code: ERR_TARGET_UNREACHABLE.to_string(),
                    reason: reason.clone(),
                    artifact_id: artifact_id.clone(),
                    segment_id: segment_id.clone(),
                    target_tier,
                };
                self.record_failure(
                    artifact_id,
                    segment_id,
                    source_tier,
                    target_tier,
                    expected_hash,
                    ts,
                    &reason,
                    0,
                );
                return Err(err);
            }
            None => {
                let reason = ProofFailureReason::TargetUnreachable {
                    detail: format!(
                        "no target state registered for artifact {} at {}",
                        artifact_id,
                        target_tier.label()
                    ),
                };
                let err = RetrievabilityError {
                    code: ERR_TARGET_UNREACHABLE.to_string(),
                    reason: reason.clone(),
                    artifact_id: artifact_id.clone(),
                    segment_id: segment_id.clone(),
                    target_tier,
                };
                self.record_failure(
                    artifact_id,
                    segment_id,
                    source_tier,
                    target_tier,
                    expected_hash,
                    ts,
                    &reason,
                    0,
                );
                return Err(err);
            }
            Some(s) => s,
        };

        // Check latency
        if state.fetch_latency_ms > self.config.max_latency_ms {
            let reason = ProofFailureReason::LatencyExceeded {
                limit_ms: self.config.max_latency_ms,
                actual_ms: state.fetch_latency_ms,
            };
            let err = RetrievabilityError {
                code: ERR_LATENCY_EXCEEDED.to_string(),
                reason: reason.clone(),
                artifact_id: artifact_id.clone(),
                segment_id: segment_id.clone(),
                target_tier,
            };
            self.record_failure(
                artifact_id,
                segment_id,
                source_tier,
                target_tier,
                expected_hash,
                ts,
                &reason,
                state.fetch_latency_ms,
            );
            return Err(err);
        }

        // Check hash match
        if self.config.require_hash_match && state.content_hash != expected_hash {
            let reason = ProofFailureReason::HashMismatch {
                expected: expected_hash.to_string(),
                actual: state.content_hash.clone(),
            };
            let err = RetrievabilityError {
                code: ERR_HASH_MISMATCH.to_string(),
                reason: reason.clone(),
                artifact_id: artifact_id.clone(),
                segment_id: segment_id.clone(),
                target_tier,
            };
            self.record_failure(
                artifact_id,
                segment_id,
                source_tier,
                target_tier,
                expected_hash,
                ts,
                &reason,
                state.fetch_latency_ms,
            );
            return Err(err);
        }

        // Success
        let proof = RetrievabilityProof {
            artifact_id: artifact_id.clone(),
            segment_id: segment_id.clone(),
            source_tier,
            target_tier,
            content_hash: expected_hash.to_string(),
            proof_timestamp: ts,
            latency_ms: state.fetch_latency_ms,
        };

        self.receipts.push(ProofReceipt {
            artifact_id: artifact_id.0.clone(),
            segment_id: segment_id.0.clone(),
            source_tier: source_tier.label().to_string(),
            target_tier: target_tier.label().to_string(),
            content_hash: expected_hash.to_string(),
            proof_timestamp: ts,
            latency_ms: state.fetch_latency_ms,
            passed: true,
            failure_reason: None,
        });

        self.events.push(GateEvent {
            code: RG_PROOF_PASSED.to_string(),
            artifact_id: artifact_id.0.clone(),
            segment_id: segment_id.0.clone(),
            detail: format!(
                "Proof passed: {}→{}, latency={}ms, hash={}",
                source_tier.label(),
                target_tier.label(),
                state.fetch_latency_ms,
                &expected_hash[..8.min(expected_hash.len())]
            ),
        });

        Ok(proof)
    }

    /// Attempt eviction of an L2 segment. This is the gated entry point.
    ///
    /// # INV-RG-BLOCK-EVICTION
    /// Eviction only proceeds if check_retrievability succeeds.
    /// # INV-RG-FAIL-CLOSED
    /// Failed proof blocks eviction unconditionally.
    #[allow(clippy::result_large_err)]
    pub fn attempt_eviction(
        &mut self,
        artifact_id: &ArtifactId,
        segment_id: &SegmentId,
        expected_hash: &str,
    ) -> Result<EvictionPermit, RetrievabilityError> {
        let proof = self.check_retrievability(
            artifact_id,
            segment_id,
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            expected_hash,
        )?;

        self.events.push(GateEvent {
            code: RG_EVICTION_PERMITTED.to_string(),
            artifact_id: artifact_id.0.clone(),
            segment_id: segment_id.0.clone(),
            detail: format!(
                "Eviction permitted after proof at ts={}",
                proof.proof_timestamp
            ),
        });

        Ok(EvictionPermit {
            proof,
            permit_id: format!("evict-{}-{}", segment_id.0, self.timestamp_counter),
        })
    }

    /// Return all proof receipts.
    pub fn receipts(&self) -> &[ProofReceipt] {
        &self.receipts
    }

    /// Return all gate events.
    pub fn events(&self) -> &[GateEvent] {
        &self.events
    }

    /// Return the gate configuration.
    pub fn config(&self) -> &RetrievabilityConfig {
        &self.config
    }

    /// Count of passed proofs.
    pub fn passed_count(&self) -> usize {
        self.receipts.iter().filter(|r| r.passed).count()
    }

    /// Count of failed proofs.
    pub fn failed_count(&self) -> usize {
        self.receipts.iter().filter(|r| !r.passed).count()
    }

    /// Export receipts as JSON string.
    pub fn receipts_json(&self) -> String {
        serde_json::to_string_pretty(&self.receipts).unwrap_or_default()
    }

    #[allow(clippy::too_many_arguments)]
    fn record_failure(
        &mut self,
        artifact_id: &ArtifactId,
        segment_id: &SegmentId,
        source_tier: StorageTier,
        target_tier: StorageTier,
        expected_hash: &str,
        ts: u64,
        reason: &ProofFailureReason,
        latency_ms: u64,
    ) {
        self.receipts.push(ProofReceipt {
            artifact_id: artifact_id.0.clone(),
            segment_id: segment_id.0.clone(),
            source_tier: source_tier.label().to_string(),
            target_tier: target_tier.label().to_string(),
            content_hash: expected_hash.to_string(),
            proof_timestamp: ts,
            latency_ms,
            passed: false,
            failure_reason: Some(reason.to_string()),
        });

        self.events.push(GateEvent {
            code: RG_PROOF_FAILED.to_string(),
            artifact_id: artifact_id.0.clone(),
            segment_id: segment_id.0.clone(),
            detail: format!("Proof failed: {}", reason),
        });

        self.events.push(GateEvent {
            code: RG_EVICTION_BLOCKED.to_string(),
            artifact_id: artifact_id.0.clone(),
            segment_id: segment_id.0.clone(),
            detail: format!("Eviction blocked: {}", reason.error_code()),
        });
    }
}

/// Permit returned on successful eviction gate check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvictionPermit {
    pub proof: RetrievabilityProof,
    pub permit_id: String,
}

/// Compute SHA-256 content hash for a byte slice.
pub fn content_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"retrievability_gate_hash_v1:");
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<RetrievabilityGate>();
    assert_sync::<RetrievabilityGate>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gate() -> RetrievabilityGate {
        RetrievabilityGate::new(RetrievabilityConfig::default())
    }

    fn aid(s: &str) -> ArtifactId {
        ArtifactId(s.to_string())
    }

    fn sid(s: &str) -> SegmentId {
        SegmentId(s.to_string())
    }

    fn good_state(hash: &str) -> TargetTierState {
        TargetTierState {
            content_hash: hash.to_string(),
            reachable: true,
            fetch_latency_ms: 100,
        }
    }

    // -- Config defaults --

    #[test]
    fn test_default_config() {
        let cfg = RetrievabilityConfig::default();
        assert_eq!(cfg.max_latency_ms, 5000);
        assert!(cfg.require_hash_match);
    }

    // -- Successful proof --

    #[test]
    fn test_successful_proof() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("abc123"));
        let proof = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "abc123",
            )
            .unwrap();
        assert_eq!(proof.artifact_id, aid("a1"));
        assert_eq!(proof.segment_id, sid("s1"));
        assert_eq!(proof.source_tier, StorageTier::L2Warm);
        assert_eq!(proof.target_tier, StorageTier::L3Archive);
        assert_eq!(proof.content_hash, "abc123");
    }

    #[test]
    fn test_successful_proof_emits_event() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("abc123"));
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "abc123",
        )
        .unwrap();
        let pass_events: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == RG_PROOF_PASSED)
            .collect();
        assert_eq!(pass_events.len(), 1);
    }

    #[test]
    fn test_successful_proof_creates_receipt() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("abc123"));
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "abc123",
        )
        .unwrap();
        assert_eq!(gate.receipts().len(), 1);
        assert!(gate.receipts()[0].passed);
        assert!(gate.receipts()[0].failure_reason.is_none());
    }

    // -- Hash mismatch --

    #[test]
    fn test_hash_mismatch_blocks() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("wrong_hash"));
        let err = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "expected_hash",
            )
            .unwrap_err();
        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_hash_mismatch_emits_failure_event() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("wrong"));
        let _ = gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "expected",
        );
        let fail_events: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == RG_PROOF_FAILED)
            .collect();
        assert_eq!(fail_events.len(), 1);
    }

    #[test]
    fn test_hash_mismatch_records_receipt() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("wrong"));
        let _ = gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "expected",
        );
        assert_eq!(gate.receipts().len(), 1);
        assert!(!gate.receipts()[0].passed);
        assert!(gate.receipts()[0].failure_reason.is_some());
    }

    // -- Latency exceeded --

    #[test]
    fn test_latency_exceeded_blocks() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "abc".to_string(),
                reachable: true,
                fetch_latency_ms: 10000, // exceeds 5000 default
            },
        );
        let err = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "abc",
            )
            .unwrap_err();
        assert_eq!(err.code, ERR_LATENCY_EXCEEDED);
    }

    #[test]
    fn test_latency_at_limit_passes() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "abc".to_string(),
                reachable: true,
                fetch_latency_ms: 5000, // exactly at limit
            },
        );
        let proof = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "abc",
            )
            .unwrap();
        assert_eq!(proof.latency_ms, 5000);
    }

    // -- Target unreachable --

    #[test]
    fn test_unreachable_target_blocks() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "abc".to_string(),
                reachable: false,
                fetch_latency_ms: 0,
            },
        );
        let err = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "abc",
            )
            .unwrap_err();
        assert_eq!(err.code, ERR_TARGET_UNREACHABLE);
    }

    #[test]
    fn test_unregistered_target_blocks() {
        let mut gate = make_gate();
        // No target registered
        let err = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "abc",
            )
            .unwrap_err();
        assert_eq!(err.code, ERR_TARGET_UNREACHABLE);
    }

    // -- Eviction gate --

    #[test]
    fn test_eviction_succeeds_with_proof() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("hash1"));
        let permit = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), "hash1")
            .unwrap();
        assert!(permit.permit_id.contains("evict"));
        assert_eq!(permit.proof.artifact_id, aid("a1"));
    }

    #[test]
    fn test_eviction_blocked_without_proof() {
        let mut gate = make_gate();
        // No target registered → eviction must fail
        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), "hash1")
            .unwrap_err();
        assert_eq!(err.code, ERR_TARGET_UNREACHABLE);
    }

    #[test]
    fn test_eviction_blocked_emits_event() {
        let mut gate = make_gate();
        let _ = gate.attempt_eviction(&aid("a1"), &sid("s1"), "hash1");
        let blocked_events: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == RG_EVICTION_BLOCKED)
            .collect();
        assert_eq!(blocked_events.len(), 1);
    }

    #[test]
    fn test_eviction_permitted_emits_event() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("h1"));
        gate.attempt_eviction(&aid("a1"), &sid("s1"), "h1").unwrap();
        let permit_events: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == RG_EVICTION_PERMITTED)
            .collect();
        assert_eq!(permit_events.len(), 1);
    }

    // -- Proof binding --

    #[test]
    fn test_proof_bound_to_segment() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("h1"));
        let proof = gate
            .check_retrievability(
                &aid("a1"),
                &sid("seg-42"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "h1",
            )
            .unwrap();
        assert_eq!(proof.segment_id, sid("seg-42"));
    }

    #[test]
    fn test_proof_bound_to_artifact() {
        let mut gate = make_gate();
        gate.register_target(&aid("art-99"), StorageTier::L3Archive, good_state("h1"));
        let proof = gate
            .check_retrievability(
                &aid("art-99"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "h1",
            )
            .unwrap();
        assert_eq!(proof.artifact_id, aid("art-99"));
    }

    #[test]
    fn test_proof_bound_to_target_tier() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("h1"));
        let proof = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "h1",
            )
            .unwrap();
        assert_eq!(proof.target_tier, StorageTier::L3Archive);
    }

    // -- Counters --

    #[test]
    fn test_passed_count() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("h1"));
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "h1",
        )
        .unwrap();
        assert_eq!(gate.passed_count(), 1);
        assert_eq!(gate.failed_count(), 0);
    }

    #[test]
    fn test_failed_count() {
        let mut gate = make_gate();
        let _ = gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "h1",
        );
        assert_eq!(gate.passed_count(), 0);
        assert_eq!(gate.failed_count(), 1);
    }

    #[test]
    fn test_mixed_counts() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("h1"));
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "h1",
        )
        .unwrap();
        let _ = gate.check_retrievability(
            &aid("a2"),
            &sid("s2"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "h2",
        );
        assert_eq!(gate.passed_count(), 1);
        assert_eq!(gate.failed_count(), 1);
    }

    // -- Content hash utility --

    #[test]
    fn test_content_hash_deterministic() {
        let h1 = content_hash(b"hello world");
        let h2 = content_hash(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_content_hash_different_inputs() {
        let h1 = content_hash(b"hello");
        let h2 = content_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_content_hash_hex_format() {
        let h = content_hash(b"test");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    // -- Receipts JSON export --

    #[test]
    fn test_receipts_json_valid() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("h1"));
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "h1",
        )
        .unwrap();
        let json_str = gate.receipts_json();
        let parsed: Vec<ProofReceipt> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    // -- Init event --

    #[test]
    fn test_gate_init_event() {
        let gate = make_gate();
        assert_eq!(gate.events().len(), 1);
        assert_eq!(gate.events()[0].code, RG_GATE_INITIALIZED);
    }

    // -- Storage tier labels --

    #[test]
    fn test_storage_tier_labels() {
        assert_eq!(StorageTier::L1Hot.label(), "L1_hot");
        assert_eq!(StorageTier::L2Warm.label(), "L2_warm");
        assert_eq!(StorageTier::L3Archive.label(), "L3_archive");
    }

    // -- Failure reason codes --

    #[test]
    fn test_failure_reason_error_codes() {
        let hm = ProofFailureReason::HashMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert_eq!(hm.error_code(), ERR_HASH_MISMATCH);
        let le = ProofFailureReason::LatencyExceeded {
            limit_ms: 100,
            actual_ms: 200,
        };
        assert_eq!(le.error_code(), ERR_LATENCY_EXCEEDED);
        let tu = ProofFailureReason::TargetUnreachable { detail: "x".into() };
        assert_eq!(tu.error_code(), ERR_TARGET_UNREACHABLE);
    }

    #[test]
    fn test_failure_reason_labels() {
        let hm = ProofFailureReason::HashMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert_eq!(hm.label(), "hash_mismatch");
        let le = ProofFailureReason::LatencyExceeded {
            limit_ms: 100,
            actual_ms: 200,
        };
        assert_eq!(le.label(), "latency_exceeded");
        let tu = ProofFailureReason::TargetUnreachable { detail: "x".into() };
        assert_eq!(tu.label(), "target_unreachable");
    }

    // -- Error display --

    #[test]
    fn test_error_display() {
        let err = RetrievabilityError {
            code: ERR_HASH_MISMATCH.to_string(),
            reason: ProofFailureReason::HashMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            artifact_id: aid("a1"),
            segment_id: sid("s1"),
            target_tier: StorageTier::L3Archive,
        };
        let s = err.to_string();
        assert!(s.contains(ERR_HASH_MISMATCH));
        assert!(s.contains("a1"));
    }

    // -- Serde roundtrips --

    #[test]
    fn test_proof_serde_roundtrip() {
        let proof = RetrievabilityProof {
            artifact_id: aid("a1"),
            segment_id: sid("s1"),
            source_tier: StorageTier::L2Warm,
            target_tier: StorageTier::L3Archive,
            content_hash: "abc".to_string(),
            proof_timestamp: 1000,
            latency_ms: 50,
        };
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: RetrievabilityProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, proof);
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let receipt = ProofReceipt {
            artifact_id: "a1".into(),
            segment_id: "s1".into(),
            source_tier: "L2_warm".into(),
            target_tier: "L3_archive".into(),
            content_hash: "abc".into(),
            proof_timestamp: 1000,
            latency_ms: 50,
            passed: true,
            failure_reason: None,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: ProofReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.artifact_id, "a1");
    }

    #[test]
    fn test_eviction_permit_serde() {
        let permit = EvictionPermit {
            proof: RetrievabilityProof {
                artifact_id: aid("a1"),
                segment_id: sid("s1"),
                source_tier: StorageTier::L2Warm,
                target_tier: StorageTier::L3Archive,
                content_hash: "abc".to_string(),
                proof_timestamp: 1000,
                latency_ms: 50,
            },
            permit_id: "evict-s1-1001".to_string(),
        };
        let json = serde_json::to_string(&permit).unwrap();
        let parsed: EvictionPermit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.permit_id, "evict-s1-1001");
    }

    // -- Config serde --

    #[test]
    fn test_config_serde_roundtrip() {
        let cfg = RetrievabilityConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: RetrievabilityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_latency_ms, 5000);
    }

    // -- Event codes defined --

    #[test]
    fn test_event_codes_defined() {
        assert!(!RG_PROOF_PASSED.is_empty());
        assert!(!RG_PROOF_FAILED.is_empty());
        assert!(!RG_EVICTION_BLOCKED.is_empty());
        assert!(!RG_EVICTION_PERMITTED.is_empty());
        assert!(!RG_GATE_INITIALIZED.is_empty());
    }

    // -- Error codes defined --

    #[test]
    fn test_error_codes_defined() {
        assert!(!ERR_HASH_MISMATCH.is_empty());
        assert!(!ERR_LATENCY_EXCEEDED.is_empty());
        assert!(!ERR_TARGET_UNREACHABLE.is_empty());
        assert!(!ERR_EVICTION_BLOCKED.is_empty());
    }

    // -- No bypass: failed proof always blocks eviction --

    #[test]
    fn test_no_bypass_hash_mismatch() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("wrong"));
        assert!(
            gate.attempt_eviction(&aid("a1"), &sid("s1"), "expected")
                .is_err()
        );
    }

    #[test]
    fn test_no_bypass_latency() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "h1".to_string(),
                reachable: true,
                fetch_latency_ms: 99999,
            },
        );
        assert!(gate.attempt_eviction(&aid("a1"), &sid("s1"), "h1").is_err());
    }

    #[test]
    fn test_no_bypass_unreachable() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "h1".to_string(),
                reachable: false,
                fetch_latency_ms: 0,
            },
        );
        assert!(gate.attempt_eviction(&aid("a1"), &sid("s1"), "h1").is_err());
    }

    // -- Multiple artifacts --

    #[test]
    fn test_multiple_artifacts_independent() {
        let mut gate = make_gate();
        gate.register_target(&aid("a1"), StorageTier::L3Archive, good_state("h1"));
        gate.register_target(&aid("a2"), StorageTier::L3Archive, good_state("h2"));
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "h1",
        )
        .unwrap();
        gate.check_retrievability(
            &aid("a2"),
            &sid("s2"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "h2",
        )
        .unwrap();
        assert_eq!(gate.passed_count(), 2);
    }

    // -- Failure reason display --

    #[test]
    fn test_failure_reason_display() {
        let hm = ProofFailureReason::HashMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(hm.to_string().contains("hash mismatch"));
        let le = ProofFailureReason::LatencyExceeded {
            limit_ms: 100,
            actual_ms: 200,
        };
        assert!(le.to_string().contains("latency exceeded"));
        let tu = ProofFailureReason::TargetUnreachable {
            detail: "down".into(),
        };
        assert!(tu.to_string().contains("target unreachable"));
    }
}
