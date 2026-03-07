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

use crate::security::constant_time::ct_eq;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const RG_PROOF_PASSED: &str = "RG_PROOF_PASSED";
pub const RG_PROOF_FAILED: &str = "RG_PROOF_FAILED";
pub const RG_EVICTION_BLOCKED: &str = "RG_EVICTION_BLOCKED";
pub const RG_EVICTION_PERMITTED: &str = "RG_EVICTION_PERMITTED";
pub const RG_GATE_INITIALIZED: &str = "RG_GATE_INITIALIZED";

/// Maximum number of events before oldest-first eviction.
const MAX_EVENTS: usize = 4096;

/// Maximum number of proof receipts before oldest-first eviction.
const MAX_RECEIPTS: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    items.push(item);
    if items.len() > cap {
        let overflow = items.len() - cap;
        items.drain(0..overflow);
    }
}

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
        // No overflow check needed here — this is the first event in a new gate.
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
        if state.fetch_latency_ms >= self.config.max_latency_ms {
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
        if self.config.require_hash_match && !ct_eq(&state.content_hash, expected_hash) {
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

        push_bounded(&mut self.receipts, ProofReceipt {
            artifact_id: artifact_id.0.clone(),
            segment_id: segment_id.0.clone(),
            source_tier: source_tier.label().to_string(),
            target_tier: target_tier.label().to_string(),
            content_hash: expected_hash.to_string(),
            proof_timestamp: ts,
            latency_ms: state.fetch_latency_ms,
            passed: true,
            failure_reason: None,
        }, MAX_RECEIPTS);

        push_bounded(&mut self.events, GateEvent {
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
        }, MAX_EVENTS);

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
        let proof = match self.check_retrievability(
            artifact_id,
            segment_id,
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            expected_hash,
        ) {
            Ok(p) => p,
            Err(err) => {
                push_bounded(&mut self.events, GateEvent {
                    code: RG_EVICTION_BLOCKED.to_string(),
                    artifact_id: artifact_id.0.clone(),
                    segment_id: segment_id.0.clone(),
                    detail: format!("Eviction blocked: {}", err.reason.error_code()),
                }, MAX_EVENTS);
                return Err(err);
            }
        };

        push_bounded(&mut self.events, GateEvent {
            code: RG_EVICTION_PERMITTED.to_string(),
            artifact_id: artifact_id.0.clone(),
            segment_id: segment_id.0.clone(),
            detail: format!(
                "Eviction permitted after proof at ts={}",
                proof.proof_timestamp
            ),
        }, MAX_EVENTS);

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
        push_bounded(&mut self.receipts, ProofReceipt {
            artifact_id: artifact_id.0.clone(),
            segment_id: segment_id.0.clone(),
            source_tier: source_tier.label().to_string(),
            target_tier: target_tier.label().to_string(),
            content_hash: expected_hash.to_string(),
            proof_timestamp: ts,
            latency_ms,
            passed: false,
            failure_reason: Some(reason.to_string()),
        }, MAX_RECEIPTS);

        push_bounded(&mut self.events, GateEvent {
            code: RG_PROOF_FAILED.to_string(),
            artifact_id: artifact_id.0.clone(),
            segment_id: segment_id.0.clone(),
            detail: format!("Proof failed: {}", reason),
        }, MAX_EVENTS);
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
    fn test_latency_at_limit_is_rejected() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "abc".to_string(),
                reachable: true,
                fetch_latency_ms: 5000, // exactly at limit → fail-closed
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
    fn test_latency_below_limit_passes() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "abc".to_string(),
                reachable: true,
                fetch_latency_ms: 4999, // one below limit → passes
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
        assert_eq!(proof.latency_ms, 4999);
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

// ===========================================================================
// Integration tests: Storage → Migration (bd-17ds.5.4)
// ===========================================================================

#[cfg(test)]
mod storage_migration_integration_tests {
    use super::*;
    use crate::migration::bpet_migration_gate::{
        self, GateVerdict, RolloutHealthSnapshot, RolloutPhase, StabilityThresholds,
        TrajectorySnapshot, evaluate_admission, evaluate_rollout_health,
    };

    fn aid(s: &str) -> ArtifactId {
        ArtifactId(s.to_string())
    }

    fn sid(s: &str) -> SegmentId {
        SegmentId(s.to_string())
    }

    fn good_target(hash: &str) -> TargetTierState {
        TargetTierState {
            content_hash: hash.to_string(),
            reachable: true,
            fetch_latency_ms: 80,
        }
    }

    fn stable_trajectory() -> TrajectorySnapshot {
        TrajectorySnapshot {
            instability_score: 0.20,
            drift_score: 0.18,
            regime_shift_probability: 0.10,
        }
    }

    fn mild_projected() -> TrajectorySnapshot {
        TrajectorySnapshot {
            instability_score: 0.23,
            drift_score: 0.20,
            regime_shift_probability: 0.14,
        }
    }

    fn severe_projected() -> TrajectorySnapshot {
        TrajectorySnapshot {
            instability_score: 0.70,
            drift_score: 0.40,
            regime_shift_probability: 0.53,
        }
    }

    // -- 1. Successful retrievability proof enables direct migration admission --

    #[test]
    fn retrievability_proof_enables_direct_migration_admission() {
        let hash = content_hash(b"artifact-payload-v1");
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(&aid("art-1"), StorageTier::L3Archive, good_target(&hash));

        // Proof succeeds → eviction permitted
        let permit = gate
            .attempt_eviction(&aid("art-1"), &sid("seg-1"), &hash)
            .unwrap();
        assert_eq!(permit.proof.content_hash, hash);

        // Stable trajectory → direct admit
        let decision = evaluate_admission(
            "trace-sm-1",
            stable_trajectory(),
            mild_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        assert_eq!(decision.verdict, GateVerdict::Allow);

        // Both gates passed: eviction proof + stable admission
        assert_eq!(gate.passed_count(), 1);
        assert!(decision.additional_evidence_required.is_empty());
    }

    // -- 2. Failed retrievability proof blocks eviction regardless of stable migration --

    #[test]
    fn failed_proof_blocks_eviction_even_when_migration_stable() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        // No target registered → unreachable
        let err = gate
            .attempt_eviction(&aid("art-2"), &sid("seg-2"), "somehash")
            .unwrap_err();
        assert_eq!(err.code, ERR_TARGET_UNREACHABLE);

        // Migration would allow it, but storage gate already blocked
        let decision = evaluate_admission(
            "trace-sm-2",
            stable_trajectory(),
            mild_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        assert_eq!(decision.verdict, GateVerdict::Allow);

        // Gate recorded failure
        assert_eq!(gate.failed_count(), 1);
        assert_eq!(gate.passed_count(), 0);
    }

    // -- 3. Hash mismatch + migration evidence requirement both block --

    #[test]
    fn hash_mismatch_and_migration_evidence_both_gate() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(
            &aid("art-3"),
            StorageTier::L3Archive,
            good_target("corrupted_hash"),
        );

        // Storage gate: hash mismatch
        let err = gate
            .attempt_eviction(&aid("art-3"), &sid("seg-3"), "expected_hash")
            .unwrap_err();
        assert_eq!(err.code, ERR_HASH_MISMATCH);

        // Migration gate: moderate risk → evidence required
        let moderate = TrajectorySnapshot {
            instability_score: 0.33,
            drift_score: 0.29,
            regime_shift_probability: 0.26,
        };
        let decision = evaluate_admission(
            "trace-sm-3",
            stable_trajectory(),
            moderate,
            StabilityThresholds::default(),
            "v3.0.0",
        );
        assert_eq!(decision.verdict, GateVerdict::RequireAdditionalEvidence);

        // Both subsystems independently gating
        assert_eq!(gate.failed_count(), 1);
        assert!(!decision.additional_evidence_required.is_empty());
    }

    // -- 4. Eviction permit + severe migration triggers staged rollout --

    #[test]
    fn eviction_permit_with_severe_migration_requires_staged_rollout() {
        let hash = content_hash(b"payload-severe");
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(&aid("art-4"), StorageTier::L3Archive, good_target(&hash));

        // Storage gate passes
        let permit = gate
            .attempt_eviction(&aid("art-4"), &sid("seg-4"), &hash)
            .unwrap();
        assert!(permit.permit_id.contains("evict"));

        // Migration gate: severe → staged rollout
        let decision = evaluate_admission(
            "trace-sm-4",
            stable_trajectory(),
            severe_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        assert_eq!(decision.verdict, GateVerdict::StagedRolloutRequired);
        let rollout = decision.staged_rollout.as_ref().unwrap();
        assert_eq!(rollout.steps.len(), 4);
        assert_eq!(rollout.steps[0].phase, RolloutPhase::Canary);
    }

    // -- 5. Staged rollout health check with retrievability receipts --

    #[test]
    fn rollout_health_check_correlates_with_proof_receipts() {
        let hash = content_hash(b"payload-rollout");
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(&aid("art-5"), StorageTier::L3Archive, good_target(&hash));

        // Storage proof passes
        gate.attempt_eviction(&aid("art-5"), &sid("seg-5"), &hash)
            .unwrap();
        let receipts = gate.receipts();
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].passed);

        // Migration: severe → staged rollout plan
        let decision = evaluate_admission(
            "trace-sm-5",
            stable_trajectory(),
            severe_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        let rollout = decision.staged_rollout.unwrap();

        // Canary health check: within limits → advance
        let healthy = RolloutHealthSnapshot {
            phase: RolloutPhase::Canary,
            observed: TrajectorySnapshot {
                instability_score: 0.58,
                drift_score: 0.32,
                regime_shift_probability: 0.41,
            },
        };
        let rollback = evaluate_rollout_health("trace-sm-5", &rollout, &healthy);
        assert!(!rollback.should_rollback);
        assert_eq!(
            rollback.event.code,
            bpet_migration_gate::event_codes::PHASE_ADVANCED
        );
    }

    // -- 6. Rollback triggered during staged rollout after eviction --

    #[test]
    fn rollback_triggered_after_eviction_completed() {
        let hash = content_hash(b"payload-rollback");
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(&aid("art-6"), StorageTier::L3Archive, good_target(&hash));

        // Eviction completed
        gate.attempt_eviction(&aid("art-6"), &sid("seg-6"), &hash)
            .unwrap();

        // Staged rollout plan
        let decision = evaluate_admission(
            "trace-sm-6",
            stable_trajectory(),
            severe_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        let rollout = decision.staged_rollout.unwrap();

        // Canary goes bad → rollback
        let unhealthy = RolloutHealthSnapshot {
            phase: RolloutPhase::Canary,
            observed: TrajectorySnapshot {
                instability_score: 0.80,
                drift_score: 0.50,
                regime_shift_probability: 0.65,
            },
        };
        let rollback = evaluate_rollout_health("trace-sm-6", &rollout, &unhealthy);
        assert!(rollback.should_rollback);
        assert_eq!(
            rollback.event.code,
            bpet_migration_gate::event_codes::ROLLBACK_TRIGGERED
        );

        // Eviction receipt still recorded — rollback is migration-level, not storage-level
        assert_eq!(gate.passed_count(), 1);
    }

    // -- 7. Content hash verified across storage-migration boundary --

    #[test]
    fn content_hash_deterministic_across_boundary() {
        let payload = b"migration-artifact-content";
        let hash = content_hash(payload);
        let hash2 = content_hash(payload);
        assert_eq!(hash, hash2);
        assert_eq!(hash.len(), 64); // SHA-256

        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(&aid("art-7"), StorageTier::L3Archive, good_target(&hash));

        // Proof binds the content hash
        let proof = gate
            .check_retrievability(
                &aid("art-7"),
                &sid("seg-7"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                &hash,
            )
            .unwrap();
        assert_eq!(proof.content_hash, hash);

        // Same hash used in migration report context
        let decision = evaluate_admission(
            "trace-sm-7",
            stable_trajectory(),
            mild_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        let report = bpet_migration_gate::build_migration_report(
            &format!("migrate-{}", &hash[..16]),
            decision,
        );
        assert!(report.migration_id.starts_with("migrate-"));
        assert_eq!(report.admission.verdict, GateVerdict::Allow);
    }

    // -- 8. Latency-exceeded storage failure + stable migration --

    #[test]
    fn latency_failure_blocks_despite_stable_migration() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(
            &aid("art-8"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "h1".to_string(),
                reachable: true,
                fetch_latency_ms: 15000, // exceeds 5000ms limit
            },
        );

        let err = gate
            .attempt_eviction(&aid("art-8"), &sid("seg-8"), "h1")
            .unwrap_err();
        assert_eq!(err.code, ERR_LATENCY_EXCEEDED);

        // Migration is stable
        let decision = evaluate_admission(
            "trace-sm-8",
            stable_trajectory(),
            mild_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        assert_eq!(decision.verdict, GateVerdict::Allow);

        // Storage still blocked — latency failure is unconditional
        assert_eq!(gate.failed_count(), 1);
    }

    // -- 9. Multiple artifacts: mixed pass/fail with admission --

    #[test]
    fn multiple_artifacts_mixed_proofs_with_admission() {
        let hash_a = content_hash(b"artifact-a");
        let hash_b = content_hash(b"artifact-b");

        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(&aid("art-a"), StorageTier::L3Archive, good_target(&hash_a));
        // art-b not registered → will fail

        let _permit_a = gate
            .attempt_eviction(&aid("art-a"), &sid("seg-a"), &hash_a)
            .unwrap();
        let err_b = gate
            .attempt_eviction(&aid("art-b"), &sid("seg-b"), &hash_b)
            .unwrap_err();
        assert_eq!(err_b.code, ERR_TARGET_UNREACHABLE);

        assert_eq!(gate.passed_count(), 1);
        assert_eq!(gate.failed_count(), 1);

        // Single admission decision covers the batch
        let decision = evaluate_admission(
            "trace-sm-9",
            stable_trajectory(),
            mild_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        assert_eq!(decision.verdict, GateVerdict::Allow);
    }

    // -- 10. Fallback plan references match storage artifact structure --

    #[test]
    fn fallback_plan_structure_consistent_with_storage_receipts() {
        let hash = content_hash(b"payload-fb");
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(&aid("art-fb"), StorageTier::L3Archive, good_target(&hash));
        gate.attempt_eviction(&aid("art-fb"), &sid("seg-fb"), &hash)
            .unwrap();

        let decision = evaluate_admission(
            "trace-sm-10",
            stable_trajectory(),
            severe_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        let rollout = decision.staged_rollout.unwrap();

        // Fallback plan has rollback version and required artifacts
        assert!(rollout.fallback.rollback_to_version.contains("previous"));
        assert!(rollout.fallback.quarantine_window_minutes > 0);
        assert!(!rollout.fallback.required_artifacts.is_empty());

        // Storage receipts JSON is valid and includes our proof
        let json = gate.receipts_json();
        let receipts: Vec<ProofReceipt> = serde_json::from_str(&json).unwrap();
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].passed);
        assert_eq!(receipts[0].content_hash, hash);
    }

    // -- 11. Audit events span both storage and migration gates --

    #[test]
    fn audit_events_span_storage_and_migration() {
        let hash = content_hash(b"audit-trail");
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(&aid("art-au"), StorageTier::L3Archive, good_target(&hash));
        gate.attempt_eviction(&aid("art-au"), &sid("seg-au"), &hash)
            .unwrap();

        // Storage events: init + proof_passed + eviction_permitted
        let storage_events = gate.events();
        assert!(storage_events.iter().any(|e| e.code == RG_GATE_INITIALIZED));
        assert!(storage_events.iter().any(|e| e.code == RG_PROOF_PASSED));
        assert!(
            storage_events
                .iter()
                .any(|e| e.code == RG_EVICTION_PERMITTED)
        );

        // Migration events: baseline captured + admission
        let decision = evaluate_admission(
            "trace-sm-11",
            stable_trajectory(),
            mild_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.code == bpet_migration_gate::event_codes::BASELINE_CAPTURED)
        );
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.code == bpet_migration_gate::event_codes::ADMISSION_ALLOWED)
        );

        // Combined audit trail covers both subsystems
        let total_events = storage_events.len() + decision.events.len();
        assert!(total_events >= 5);
    }

    // -- 12. Progressive rollout phases with storage gate interlock --

    #[test]
    fn progressive_rollout_phases_after_eviction() {
        let hash = content_hash(b"progressive-payload");
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());
        gate.register_target(&aid("art-prog"), StorageTier::L3Archive, good_target(&hash));
        gate.attempt_eviction(&aid("art-prog"), &sid("seg-prog"), &hash)
            .unwrap();

        let decision = evaluate_admission(
            "trace-sm-12",
            stable_trajectory(),
            severe_projected(),
            StabilityThresholds::default(),
            "v3.0.0",
        );
        let rollout = decision.staged_rollout.unwrap();

        // Walk through each phase: Canary → Limited → Progressive → General
        let phases = [
            RolloutPhase::Canary,
            RolloutPhase::Limited,
            RolloutPhase::Progressive,
            RolloutPhase::General,
        ];
        for (i, &phase) in phases.iter().enumerate() {
            let step = &rollout.steps[i];
            assert_eq!(step.phase, phase);

            // Observe within limits → no rollback
            let snap = RolloutHealthSnapshot {
                phase,
                observed: TrajectorySnapshot {
                    instability_score: step.max_instability_score * 0.95,
                    drift_score: 0.30,
                    regime_shift_probability: step.max_regime_shift_probability * 0.95,
                },
            };
            let rb = evaluate_rollout_health("trace-sm-12", &rollout, &snap);
            assert!(!rb.should_rollback, "phase {:?} should not rollback", phase);
        }

        // Storage gate was passed once for the artifact
        assert_eq!(gate.passed_count(), 1);
    }
}
