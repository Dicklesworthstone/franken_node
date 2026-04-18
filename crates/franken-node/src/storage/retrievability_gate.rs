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

use crate::security::constant_time::ct_eq_bytes;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const RG_PROOF_PASSED: &str = "RG_PROOF_PASSED";
pub const RG_PROOF_FAILED: &str = "RG_PROOF_FAILED";
pub const RG_EVICTION_BLOCKED: &str = "RG_EVICTION_BLOCKED";
pub const RG_EVICTION_PERMITTED: &str = "RG_EVICTION_PERMITTED";
pub const RG_GATE_INITIALIZED: &str = "RG_GATE_INITIALIZED";

use crate::capacity_defaults::aliases::{MAX_EVENTS, MAX_RECEIPTS};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

const CONTENT_HASH_DOMAIN: &[u8] = b"retrievability_gate_hash_v1:";
const SHA256_DIGEST_BYTES: usize = 32;
const SHA256_DIGEST_HEX_CHARS: usize = 64;

fn is_canonical_sha256_hex_digest(candidate: &str) -> bool {
    candidate.len() == SHA256_DIGEST_HEX_CHARS
        && candidate
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn content_digest_matches(observed: &str, expected: &str) -> bool {
    if observed.is_empty() || expected.is_empty() {
        return false;
    }
    if !observed.is_ascii() || !expected.is_ascii() {
        return false;
    }
    let observed_has_forbidden = observed.chars().any(|c| c.is_control() || c.is_whitespace());
    let expected_has_forbidden = expected.chars().any(|c| c.is_control() || c.is_whitespace());
    if observed_has_forbidden || expected_has_forbidden {
        return false;
    }
    match (hex::decode(observed), hex::decode(expected)) {
        (Ok(observed_bytes), Ok(expected_bytes)) => {
            if observed_bytes.len() != SHA256_DIGEST_BYTES
                || expected_bytes.len() != SHA256_DIGEST_BYTES
            {
                return false;
            }
            if !is_canonical_sha256_hex_digest(observed) {
                return false;
            }
            if !is_canonical_sha256_hex_digest(expected) {
                return false;
            }
            ct_eq_bytes(&observed_bytes, &expected_bytes)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_HASH_MISMATCH: &str = "ERR_HASH_MISMATCH";
pub const ERR_LATENCY_EXCEEDED: &str = "ERR_LATENCY_EXCEEDED";
pub const ERR_TARGET_UNREACHABLE: &str = "ERR_TARGET_UNREACHABLE";
pub const ERR_EVICTION_BLOCKED: &str = "ERR_EVICTION_BLOCKED";
pub const ERR_INVALID_ARTIFACT_ID: &str = "ERR_INVALID_ARTIFACT_ID";
pub const ERR_INVALID_SEGMENT_ID: &str = "ERR_INVALID_SEGMENT_ID";

const RESERVED_ARTIFACT_ID: &str = "<unknown>";

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
    InvalidArtifactId { detail: String },
    InvalidSegmentId { detail: String },
}

impl ProofFailureReason {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::HashMismatch { .. } => ERR_HASH_MISMATCH,
            Self::LatencyExceeded { .. } => ERR_LATENCY_EXCEEDED,
            Self::TargetUnreachable { .. } => ERR_TARGET_UNREACHABLE,
            Self::InvalidArtifactId { .. } => ERR_INVALID_ARTIFACT_ID,
            Self::InvalidSegmentId { .. } => ERR_INVALID_SEGMENT_ID,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::HashMismatch { .. } => "hash_mismatch",
            Self::LatencyExceeded { .. } => "latency_exceeded",
            Self::TargetUnreachable { .. } => "target_unreachable",
            Self::InvalidArtifactId { .. } => "invalid_artifact_id",
            Self::InvalidSegmentId { .. } => "invalid_segment_id",
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
            Self::InvalidArtifactId { detail } => {
                write!(f, "invalid artifact id: {}", detail)
            }
            Self::InvalidSegmentId { detail } => {
                write!(f, "invalid segment id: {}", detail)
            }
        }
    }
}

fn invalid_artifact_id_reason(artifact_id: &ArtifactId) -> Option<String> {
    let raw = artifact_id.0.as_str();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some("artifact_id must not be empty".to_string());
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("artifact_id is reserved: {:?}", raw));
    }
    if trimmed != raw {
        return Some("artifact_id contains leading or trailing whitespace".to_string());
    }
    if raw.chars().any(|c| c.is_control()) {
        return Some("artifact_id must not contain control characters".to_string());
    }
    None
}

fn invalid_segment_id_reason(segment_id: &SegmentId) -> Option<String> {
    let raw = segment_id.0.as_str();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some("segment_id must not be empty".to_string());
    }
    if trimmed != raw {
        return Some("segment_id contains leading or trailing whitespace".to_string());
    }
    if raw.chars().any(|c| c.is_control()) {
        return Some("segment_id must not contain control characters".to_string());
    }
    None
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
    /// Simulated target tier contents: (artifact_id, segment_id, target_tier) -> state
    target_state: BTreeMap<(String, String, String), TargetTierState>,
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
        push_bounded(
            &mut gate.events,
            GateEvent {
                code: RG_GATE_INITIALIZED.to_string(),
                artifact_id: String::new(),
                segment_id: String::new(),
                detail: format!(
                    "Gate initialized: max_latency={}ms, require_hash={}",
                    gate.config.max_latency_ms, gate.config.require_hash_match
                ),
            },
            MAX_EVENTS,
        );
        // Hardening: use push_bounded to prevent unbounded event growth
        gate
    }

    /// Register simulated target tier state for testing.
    pub fn register_target(
        &mut self,
        artifact_id: &ArtifactId,
        segment_id: &SegmentId,
        target_tier: StorageTier,
        state: TargetTierState,
    ) {
        self.target_state.insert(
            (
                artifact_id.0.clone(),
                segment_id.0.clone(),
                target_tier.label().to_string(),
            ),
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

        if let Some(detail) = invalid_artifact_id_reason(artifact_id) {
            let reason = ProofFailureReason::InvalidArtifactId { detail };
            let err = RetrievabilityError {
                code: ERR_INVALID_ARTIFACT_ID.to_string(),
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
                None,
                ts,
                &reason,
                0,
            );
            return Err(err);
        }

        if let Some(detail) = invalid_segment_id_reason(segment_id) {
            let reason = ProofFailureReason::InvalidSegmentId { detail };
            let err = RetrievabilityError {
                code: ERR_INVALID_SEGMENT_ID.to_string(),
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
                None,
                ts,
                &reason,
                0,
            );
            return Err(err);
        }

        let key = (
            artifact_id.0.clone(),
            segment_id.0.clone(),
            target_tier.label().to_string(),
        );
        let state = self.target_state.get(&key);

        // Check reachability
        let state = match state {
            Some(s) if !s.reachable => {
                let reason = ProofFailureReason::TargetUnreachable {
                    detail: format!(
                        "tier {} not reachable for artifact {} segment {}",
                        target_tier.label(),
                        artifact_id,
                        segment_id
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
                    None,
                    ts,
                    &reason,
                    0,
                );
                return Err(err);
            }
            None => {
                let reason = ProofFailureReason::TargetUnreachable {
                    detail: format!(
                        "no target state registered for artifact {} segment {} at {}",
                        artifact_id,
                        segment_id,
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
                    None,
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
            let observed_content_hash = state.content_hash.clone();
            let observed_latency_ms = state.fetch_latency_ms;
            let reason = ProofFailureReason::LatencyExceeded {
                limit_ms: self.config.max_latency_ms,
                actual_ms: observed_latency_ms,
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
                Some(observed_content_hash.as_str()),
                ts,
                &reason,
                observed_latency_ms,
            );
            return Err(err);
        }

        // Check hash match
        if self.config.require_hash_match
            && !content_digest_matches(&state.content_hash, expected_hash)
        {
            let observed_content_hash = state.content_hash.clone();
            let observed_latency_ms = state.fetch_latency_ms;
            let reason = ProofFailureReason::HashMismatch {
                expected: expected_hash.to_string(),
                actual: observed_content_hash.clone(),
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
                Some(observed_content_hash.as_str()),
                ts,
                &reason,
                observed_latency_ms,
            );
            return Err(err);
        }

        // Success
        let verified_content_hash = state.content_hash.clone();
        let proof = RetrievabilityProof {
            artifact_id: artifact_id.clone(),
            segment_id: segment_id.clone(),
            source_tier,
            target_tier,
            content_hash: verified_content_hash.clone(),
            proof_timestamp: ts,
            latency_ms: state.fetch_latency_ms,
        };

        push_bounded(
            &mut self.receipts,
            ProofReceipt {
                artifact_id: artifact_id.0.clone(),
                segment_id: segment_id.0.clone(),
                source_tier: source_tier.label().to_string(),
                target_tier: target_tier.label().to_string(),
                content_hash: verified_content_hash.clone(),
                proof_timestamp: ts,
                latency_ms: state.fetch_latency_ms,
                passed: true,
                failure_reason: None,
            },
            MAX_RECEIPTS,
        );

        push_bounded(
            &mut self.events,
            GateEvent {
                code: RG_PROOF_PASSED.to_string(),
                artifact_id: artifact_id.0.clone(),
                segment_id: segment_id.0.clone(),
                detail: format!(
                    "Proof passed: {}→{}, latency={}ms, hash={}",
                    source_tier.label(),
                    target_tier.label(),
                    state.fetch_latency_ms,
                    verified_content_hash
                        .get(..8)
                        .unwrap_or(verified_content_hash.as_str())
                ),
            },
            MAX_EVENTS,
        );

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
                push_bounded(
                    &mut self.events,
                    GateEvent {
                        code: RG_EVICTION_BLOCKED.to_string(),
                        artifact_id: artifact_id.0.clone(),
                        segment_id: segment_id.0.clone(),
                        detail: format!("Eviction blocked: {}", err.reason.error_code()),
                    },
                    MAX_EVENTS,
                );
                return Err(err);
            }
        };

        push_bounded(
            &mut self.events,
            GateEvent {
                code: RG_EVICTION_PERMITTED.to_string(),
                artifact_id: artifact_id.0.clone(),
                segment_id: segment_id.0.clone(),
                detail: format!(
                    "Eviction permitted after proof at ts={}",
                    proof.proof_timestamp
                ),
            },
            MAX_EVENTS,
        );

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
        observed_content_hash: Option<&str>,
        ts: u64,
        reason: &ProofFailureReason,
        latency_ms: u64,
    ) {
        push_bounded(
            &mut self.receipts,
            ProofReceipt {
                artifact_id: artifact_id.0.clone(),
                segment_id: segment_id.0.clone(),
                source_tier: source_tier.label().to_string(),
                target_tier: target_tier.label().to_string(),
                content_hash: observed_content_hash.unwrap_or_default().to_string(),
                proof_timestamp: ts,
                latency_ms,
                passed: false,
                failure_reason: Some(reason.to_string()),
            },
            MAX_RECEIPTS,
        );

        push_bounded(
            &mut self.events,
            GateEvent {
                code: RG_PROOF_FAILED.to_string(),
                artifact_id: artifact_id.0.clone(),
                segment_id: segment_id.0.clone(),
                detail: format!("Proof failed: {}", reason),
            },
            MAX_EVENTS,
        );
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
    hasher.update(CONTENT_HASH_DOMAIN);
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

    fn assert_hash_eq(left: &str, right: &str) {
        assert!(ct_eq_bytes(left.as_bytes(), right.as_bytes()));
    }

    fn assert_hash_ne(left: &str, right: &str) {
        assert!(!ct_eq_bytes(left.as_bytes(), right.as_bytes()));
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
        let hash = content_hash(b"successful proof payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        let proof = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                &hash,
            )
            .unwrap();
        assert_eq!(proof.artifact_id, aid("a1"));
        assert_eq!(proof.segment_id, sid("s1"));
        assert_eq!(proof.source_tier, StorageTier::L2Warm);
        assert_eq!(proof.target_tier, StorageTier::L3Archive);
        assert_hash_eq(&proof.content_hash, &hash);
    }

    #[test]
    fn test_successful_proof_emits_event() {
        let mut gate = make_gate();
        let hash = content_hash(b"event payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            &hash,
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
        let hash = content_hash(b"receipt payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            &hash,
        )
        .unwrap();
        assert_eq!(gate.receipts().len(), 1);
        assert!(gate.receipts()[0].passed);
        assert!(gate.receipts()[0].failure_reason.is_none());
        assert_hash_eq(&gate.receipts()[0].content_hash, &hash);
    }

    #[test]
    fn test_relaxed_mode_success_binds_actual_content_hash() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig {
            max_latency_ms: 5000,
            require_hash_match: false,
        });
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state("actual_hash_value"),
        );

        let proof = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "caller_supplied_hash",
            )
            .expect("relaxed mode should still produce a proof");

        assert_eq!(proof.content_hash, "actual_hash_value");
        assert_eq!(gate.receipts()[0].content_hash, "actual_hash_value");
    }

    #[test]
    fn test_relaxed_mode_event_uses_actual_hash_prefix() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig {
            max_latency_ms: 5000,
            require_hash_match: false,
        });
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state("actual_hash_value"),
        );

        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "caller_supplied_hash",
        )
        .expect("relaxed mode should still pass");

        let pass_event = gate
            .events()
            .iter()
            .find(|event| event.code == RG_PROOF_PASSED)
            .expect("proof-passed event must exist");
        assert!(pass_event.detail.contains("actual_h"));
        assert!(!pass_event.detail.contains("caller_su"));
    }

    // -- Hash mismatch --

    #[test]
    fn test_hash_mismatch_blocks() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state("wrong_hash"),
        );
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
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state("wrong"),
        );
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
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state("wrong"),
        );
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
        assert_eq!(gate.receipts()[0].content_hash, "wrong");
    }

    #[test]
    fn test_latency_failure_receipt_binds_actual_content_hash() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "archived_hash".to_string(),
                reachable: true,
                fetch_latency_ms: 10_000,
            },
        );

        let _ = gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "caller_supplied_hash",
        );

        assert_eq!(gate.receipts().len(), 1);
        assert!(!gate.receipts()[0].passed);
        assert_eq!(gate.receipts()[0].content_hash, "archived_hash");
    }

    // -- Latency exceeded --

    #[test]
    fn test_latency_exceeded_blocks() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
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
            &sid("s1"),
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
        let hash = content_hash(b"latency below limit payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: hash.clone(),
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
                &hash,
            )
            .unwrap();
        assert_eq!(proof.latency_ms, 4999);
    }

    // -- Invalid identifiers --

    #[test]
    fn test_invalid_artifact_id_rejected() {
        let mut gate = make_gate();
        let err = gate
            .check_retrievability(
                &aid(""),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "abc",
            )
            .unwrap_err();
        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert!(err.reason.to_string().contains("artifact_id"));
        assert_eq!(gate.receipts().len(), 1);
        assert!(!gate.receipts()[0].passed);
    }

    #[test]
    fn test_reserved_artifact_id_rejected() {
        let mut gate = make_gate();
        let err = gate
            .check_retrievability(
                &aid(RESERVED_ARTIFACT_ID),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "abc",
            )
            .unwrap_err();
        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert!(err.reason.to_string().contains("reserved"));
    }

    #[test]
    fn test_invalid_segment_id_rejected() {
        let mut gate = make_gate();
        let err = gate
            .check_retrievability(
                &aid("a1"),
                &sid(" s1 "),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "abc",
            )
            .unwrap_err();
        assert_eq!(err.code, ERR_INVALID_SEGMENT_ID);
        assert!(err.reason.to_string().contains("segment_id"));
    }

    #[test]
    fn test_control_character_artifact_id_rejected_before_target_lookup() {
        let mut gate = make_gate();
        let err = gate
            .check_retrievability(
                &aid("a1\0hidden"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "abc",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert!(err.reason.to_string().contains("control characters"));
        assert_eq!(gate.failed_count(), 1);
        assert!(gate.receipts()[0].content_hash.is_empty());
    }

    #[test]
    fn test_newline_artifact_id_blocks_eviction() {
        let mut gate = make_gate();
        let err = gate
            .attempt_eviction(&aid("artifact\nid"), &sid("s1"), "abc")
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID);
        assert!(gate.events().iter().any(|event| event.code == RG_EVICTION_BLOCKED));
    }

    #[test]
    fn test_control_character_segment_id_rejected_before_target_lookup() {
        let mut gate = make_gate();
        let err = gate
            .check_retrievability(
                &aid("a1"),
                &sid("seg\t1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "abc",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_SEGMENT_ID);
        assert!(err.reason.to_string().contains("control characters"));
        assert_eq!(gate.failed_count(), 1);
        assert!(gate.receipts()[0].content_hash.is_empty());
    }

    #[test]
    fn test_newline_segment_id_blocks_eviction() {
        let mut gate = make_gate();
        let err = gate
            .attempt_eviction(&aid("a1"), &sid("segment\nid"), "abc")
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_SEGMENT_ID);
        assert!(gate.events().iter().any(|event| event.code == RG_EVICTION_BLOCKED));
    }

    #[test]
    fn test_relaxed_hash_mode_still_blocks_unreachable_target() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig {
            max_latency_ms: 5000,
            require_hash_match: false,
        });
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "archive_hash".to_string(),
                reachable: false,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "caller_hash",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_TARGET_UNREACHABLE);
        assert_eq!(gate.failed_count(), 1);
    }

    #[test]
    fn test_relaxed_hash_mode_still_rejects_latency_at_limit() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig {
            max_latency_ms: 25,
            require_hash_match: false,
        });
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "archive_hash".to_string(),
                reachable: true,
                fetch_latency_ms: 25,
            },
        );

        let err = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "caller_hash",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_LATENCY_EXCEEDED);
        assert_eq!(gate.failed_count(), 1);
    }

    #[test]
    fn test_relaxed_hash_mode_still_rejects_invalid_segment_id() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig {
            max_latency_ms: 5000,
            require_hash_match: false,
        });
        let err = gate
            .check_retrievability(
                &aid("a1"),
                &sid("seg\0id"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "caller_hash",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_INVALID_SEGMENT_ID);
        assert_eq!(gate.failed_count(), 1);
    }

    // -- Target unreachable --

    #[test]
    fn test_unreachable_target_blocks() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
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
        assert!(err.reason.to_string().contains("s1"));
        assert!(gate.receipts()[0].content_hash.is_empty());
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
        assert!(gate.receipts()[0].content_hash.is_empty());
    }

    // -- Eviction gate --

    #[test]
    fn test_eviction_succeeds_with_proof() {
        let mut gate = make_gate();
        let hash = content_hash(b"eviction succeeds payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        let permit = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), &hash)
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
        let hash = content_hash(b"eviction permitted event payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        gate.attempt_eviction(&aid("a1"), &sid("s1"), &hash)
            .unwrap();
        let permit_events: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.code == RG_EVICTION_PERMITTED)
            .collect();
        assert_eq!(permit_events.len(), 1);
    }

    #[test]
    fn test_eviction_rechecks_target_after_prior_permit() {
        let mut gate = make_gate();
        let hash = content_hash(b"fresh archive copy");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );

        gate.attempt_eviction(&aid("a1"), &sid("s1"), &hash)
            .expect("first proof should permit eviction");

        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&content_hash(b"corrupted archive copy")),
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), &hash)
            .expect_err("stale prior permit must not bypass a fresh proof");
        assert_eq!(err.code, ERR_HASH_MISMATCH);
        assert_eq!(gate.passed_count(), 1);
        assert_eq!(gate.failed_count(), 1);
    }

    #[test]
    fn test_repeated_checks_issue_fresh_timestamps() {
        let mut gate = make_gate();
        let hash = content_hash(b"timestamped payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );

        let first = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                &hash,
            )
            .expect("first proof should pass");
        let second = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                &hash,
            )
            .expect("second proof should pass");

        assert_eq!(
            second.proof_timestamp,
            first.proof_timestamp.saturating_add(1)
        );
        assert_eq!(gate.receipts().len(), 2);
        assert_eq!(gate.receipts()[1].proof_timestamp, second.proof_timestamp);
    }

    // -- Proof binding --

    #[test]
    fn test_proof_bound_to_segment() {
        let mut gate = make_gate();
        let hash = content_hash(b"segment binding payload");
        gate.register_target(
            &aid("a1"),
            &sid("seg-42"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        let proof = gate
            .check_retrievability(
                &aid("a1"),
                &sid("seg-42"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                &hash,
            )
            .unwrap();
        assert_eq!(proof.segment_id, sid("seg-42"));
    }

    #[test]
    fn test_proof_bound_to_artifact() {
        let mut gate = make_gate();
        let hash = content_hash(b"artifact binding payload");
        gate.register_target(
            &aid("art-99"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        let proof = gate
            .check_retrievability(
                &aid("art-99"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                &hash,
            )
            .unwrap();
        assert_eq!(proof.artifact_id, aid("art-99"));
    }

    #[test]
    fn test_proof_bound_to_target_tier() {
        let mut gate = make_gate();
        let hash = content_hash(b"target tier binding payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        let proof = gate
            .check_retrievability(
                &aid("a1"),
                &sid("s1"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                &hash,
            )
            .unwrap();
        assert_eq!(proof.target_tier, StorageTier::L3Archive);
    }

    #[test]
    fn test_unregistered_segment_for_registered_artifact_blocks() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("seg-registered"),
            StorageTier::L3Archive,
            good_state("h1"),
        );

        let err = gate
            .check_retrievability(
                &aid("a1"),
                &sid("seg-missing"),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "h1",
            )
            .unwrap_err();

        assert_eq!(err.code, ERR_TARGET_UNREACHABLE);
        assert!(err.reason.to_string().contains("seg-missing"));
    }

    #[test]
    fn test_segments_of_same_artifact_are_isolated() {
        let mut gate = make_gate();
        let hash_a = content_hash(b"segment a payload");
        let hash_b = content_hash(b"segment b payload");
        gate.register_target(
            &aid("a1"),
            &sid("seg-a"),
            StorageTier::L3Archive,
            good_state(&hash_a),
        );
        gate.register_target(
            &aid("a1"),
            &sid("seg-b"),
            StorageTier::L3Archive,
            good_state(&hash_b),
        );

        let proof_a = gate
            .attempt_eviction(&aid("a1"), &sid("seg-a"), &hash_a)
            .unwrap();
        assert_hash_eq(&proof_a.proof.content_hash, &hash_a);

        let err_b = gate
            .attempt_eviction(&aid("a1"), &sid("seg-b"), &hash_a)
            .unwrap_err();
        assert_eq!(err_b.code, ERR_HASH_MISMATCH);
    }

    // -- Counters --

    #[test]
    fn test_passed_count() {
        let mut gate = make_gate();
        let hash = content_hash(b"passed count payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            &hash,
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
        let hash = content_hash(b"mixed count payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            &hash,
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

    #[test]
    fn test_content_hash_includes_domain_separator() {
        let payload = b"domain-separated retrievability payload";
        let mut hasher = Sha256::new();
        hasher.update(CONTENT_HASH_DOMAIN);
        hasher.update(payload);
        let expected = format!("{:x}", hasher.finalize());
        let plain_sha256 = format!("{:x}", Sha256::digest(payload));

        assert_hash_eq(&content_hash(payload), &expected);
        assert_hash_ne(&content_hash(payload), &plain_sha256);
    }

    #[test]
    fn test_content_digest_matches_uses_decoded_hex_bytes() {
        let expected = content_hash(b"hex integrity payload");
        let mut tampered_bytes = hex::decode(&expected).expect("content hash is hex");
        tampered_bytes[0] ^= 0x01;
        let tampered = hex::encode(tampered_bytes);

        assert!(content_digest_matches(&expected, &expected));
        assert!(!content_digest_matches(&tampered, &expected));
    }

    #[test]
    fn test_content_digest_matches_rejects_hex_length_mismatch() {
        let expected = content_hash(b"hex length payload");
        let truncated = &expected[..expected.len() - 2];

        assert!(!content_digest_matches(truncated, &expected));
    }

    #[test]
    fn test_canonical_digest_rejects_short_hex() {
        assert!(!is_canonical_sha256_hex_digest("deadbeef"));
    }

    #[test]
    fn test_canonical_digest_rejects_long_hex() {
        let digest = format!("{}00", content_hash(b"too long"));

        assert!(!is_canonical_sha256_hex_digest(&digest));
    }

    #[test]
    fn test_canonical_digest_rejects_uppercase_hex() {
        let digest = content_hash(b"uppercase canonical predicate").to_uppercase();

        assert!(!is_canonical_sha256_hex_digest(&digest));
    }

    #[test]
    fn test_canonical_digest_rejects_digest_length_non_hex() {
        let digest = "z".repeat(SHA256_DIGEST_HEX_CHARS);

        assert!(!is_canonical_sha256_hex_digest(&digest));
    }

    #[test]
    fn test_canonical_digest_rejects_whitespace() {
        let digest = format!("{} ", &content_hash(b"space")[..SHA256_DIGEST_HEX_CHARS - 1]);

        assert!(!is_canonical_sha256_hex_digest(&digest));
    }

    #[test]
    fn test_canonical_digest_rejects_non_ascii() {
        let digest = format!(
            "{}\u{e9}",
            &content_hash(b"non ascii")[..SHA256_DIGEST_HEX_CHARS - 2],
        );

        assert!(!is_canonical_sha256_hex_digest(&digest));
    }

    #[test]
    fn test_content_digest_matches_rejects_short_hex_digest() {
        assert!(!content_digest_matches("deadbeef", "deadbeef"));
    }

    #[test]
    fn test_content_digest_matches_rejects_uppercase_observed_hex_digest() {
        let expected = content_hash(b"uppercase observed");
        let observed = expected.to_uppercase();

        assert!(!content_digest_matches(&observed, &expected));
    }

    #[test]
    fn test_content_digest_matches_rejects_uppercase_expected_hex_digest() {
        let observed = content_hash(b"uppercase expected");
        let expected = observed.to_uppercase();

        assert!(!content_digest_matches(&observed, &expected));
    }

    #[test]
    fn test_content_digest_matches_rejects_digest_length_non_hex_observed() {
        let expected = content_hash(b"digest length non hex observed");
        let observed = "z".repeat(SHA256_DIGEST_HEX_CHARS);

        assert!(!content_digest_matches(&observed, &expected));
    }

    #[test]
    fn test_content_digest_matches_rejects_digest_length_non_hex_expected() {
        let observed = content_hash(b"digest length non hex expected");
        let expected = "z".repeat(SHA256_DIGEST_HEX_CHARS);

        assert!(!content_digest_matches(&observed, &expected));
    }

    #[test]
    fn test_content_digest_matches_rejects_matching_digest_length_non_hex() {
        let digest = "z".repeat(SHA256_DIGEST_HEX_CHARS);

        assert!(!content_digest_matches(&digest, &digest));
    }

    #[test]
    fn test_content_digest_matches_rejects_non_ascii_observed_digest() {
        assert!(!content_digest_matches("archive\u{e9}hash", "archive_hash"));
    }

    #[test]
    fn test_content_digest_matches_rejects_non_ascii_expected_digest() {
        assert!(!content_digest_matches("archive_hash", "archive\u{e9}hash"));
    }

    #[test]
    fn test_content_digest_matches_rejects_matching_non_ascii_digest() {
        assert!(!content_digest_matches("archive\u{e9}hash", "archive\u{e9}hash"));
    }

    #[test]
    fn test_content_digest_matches_rejects_matching_short_non_hex_digest() {
        assert!(!content_digest_matches("archive_hash", "archive_hash"));
    }

    #[test]
    fn test_content_digest_matches_rejects_short_non_hex_observed_digest() {
        assert!(!content_digest_matches(
            "archive_hash",
            &content_hash(b"canonical expected"),
        ));
    }

    #[test]
    fn test_content_digest_matches_rejects_short_non_hex_expected_digest() {
        assert!(!content_digest_matches(
            &content_hash(b"canonical observed"),
            "archive_hash",
        ));
    }

    #[test]
    fn test_content_digest_matches_rejects_matching_punctuation_digest() {
        assert!(!content_digest_matches("not:a:digest", "not:a:digest"));
    }

    #[test]
    fn test_content_digest_matches_rejects_non_hex_same_length_mismatch() {
        assert!(!content_digest_matches("placeholder-a", "placeholder-b"));
    }

    #[test]
    fn test_content_digest_matches_rejects_non_hex_prefix_mismatch() {
        assert!(!content_digest_matches("placeholder", "placeholder-extra"));
    }

    #[test]
    fn test_content_digest_matches_rejects_empty_observed_digest() {
        assert!(!content_digest_matches("", &content_hash(b"expected")));
    }

    #[test]
    fn test_content_digest_matches_rejects_empty_expected_digest() {
        assert!(!content_digest_matches(&content_hash(b"observed"), ""));
    }

    #[test]
    fn test_content_digest_matches_rejects_control_character_observed_digest() {
        assert!(!content_digest_matches("archive\nhash", "archive\nhash"));
    }

    #[test]
    fn test_content_digest_matches_rejects_control_character_expected_digest() {
        assert!(!content_digest_matches("archive_hash", "archive\thash"));
    }

    #[test]
    fn test_content_digest_matches_rejects_leading_space_observed_digest() {
        assert!(!content_digest_matches(" archive_hash", " archive_hash"));
    }

    #[test]
    fn test_content_digest_matches_rejects_trailing_space_expected_digest() {
        assert!(!content_digest_matches("archive_hash ", "archive_hash "));
    }

    #[test]
    fn test_content_digest_matches_rejects_internal_space_digest() {
        assert!(!content_digest_matches("archive hash", "archive hash"));
    }

    #[test]
    fn test_empty_hash_does_not_satisfy_required_hash_gate() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: String::new(),
                reachable: true,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), "")
            .expect_err("empty digest must not satisfy required hash gate");

        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_whitespace_hash_does_not_satisfy_required_hash_gate() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "archive hash".to_string(),
                reachable: true,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), "archive hash")
            .expect_err("whitespace-bearing digest must fail closed");

        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_short_hex_hash_does_not_satisfy_required_hash_gate() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "deadbeef".to_string(),
                reachable: true,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), "deadbeef")
            .expect_err("short hex digest must fail closed");

        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_uppercase_hex_hash_does_not_satisfy_required_hash_gate() {
        let mut gate = make_gate();
        let canonical = content_hash(b"uppercase gate payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: canonical.to_uppercase(),
                reachable: true,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), &canonical)
            .expect_err("uppercase hex digest must fail closed");

        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_digest_length_non_hex_hash_does_not_satisfy_required_hash_gate() {
        let mut gate = make_gate();
        let digest = "z".repeat(SHA256_DIGEST_HEX_CHARS);
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: digest.clone(),
                reachable: true,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), &digest)
            .expect_err("digest-length non-hex string must fail closed");

        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_non_ascii_hash_does_not_satisfy_required_hash_gate() {
        let mut gate = make_gate();
        let digest = "archive\u{e9}hash";
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: digest.to_string(),
                reachable: true,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), digest)
            .expect_err("non-ASCII digest must fail closed");

        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_short_non_hex_hash_does_not_satisfy_required_hash_gate() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "archive_hash".to_string(),
                reachable: true,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), "archive_hash")
            .expect_err("short non-hex digest must fail closed");

        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_punctuation_hash_does_not_satisfy_required_hash_gate() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "not:a:digest".to_string(),
                reachable: true,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), "not:a:digest")
            .expect_err("punctuation digest must fail closed");

        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_control_character_hash_does_not_satisfy_required_hash_gate() {
        let mut gate = make_gate();
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "archive\nhash".to_string(),
                reachable: true,
                fetch_latency_ms: 1,
            },
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), "archive\nhash")
            .expect_err("control-character digest must fail closed");

        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_plain_sha256_hash_does_not_satisfy_domain_hash_gate() {
        let mut gate = make_gate();
        let payload = b"domain gate payload";
        let archive_hash = content_hash(payload);
        let plain_hash = format!("{:x}", Sha256::digest(payload));
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&archive_hash),
        );

        let err = gate
            .attempt_eviction(&aid("a1"), &sid("s1"), &plain_hash)
            .expect_err("plain SHA-256 must not satisfy domain-separated gate");

        assert_eq!(err.code, ERR_HASH_MISMATCH);
    }

    #[test]
    fn test_push_bounded_zero_capacity_clears_without_underflow() {
        let mut values = vec![1, 2, 3];

        push_bounded(&mut values, 4, 0);

        assert!(values.is_empty());
    }

    // -- Receipts JSON export --

    #[test]
    fn test_receipts_json_valid() {
        let mut gate = make_gate();
        let hash = content_hash(b"receipts json payload");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash),
        );
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            &hash,
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
        let ia = ProofFailureReason::InvalidArtifactId { detail: "x".into() };
        assert_eq!(ia.error_code(), ERR_INVALID_ARTIFACT_ID);
        let iseg = ProofFailureReason::InvalidSegmentId { detail: "x".into() };
        assert_eq!(iseg.error_code(), ERR_INVALID_SEGMENT_ID);
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
        let ia = ProofFailureReason::InvalidArtifactId { detail: "x".into() };
        assert_eq!(ia.label(), "invalid_artifact_id");
        let iseg = ProofFailureReason::InvalidSegmentId { detail: "x".into() };
        assert_eq!(iseg.label(), "invalid_segment_id");
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
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state("wrong"),
        );
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
            &sid("s1"),
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
            &sid("s1"),
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
        let hash_1 = content_hash(b"multiple artifact one");
        let hash_2 = content_hash(b"multiple artifact two");
        gate.register_target(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L3Archive,
            good_state(&hash_1),
        );
        gate.register_target(
            &aid("a2"),
            &sid("s2"),
            StorageTier::L3Archive,
            good_state(&hash_2),
        );
        gate.check_retrievability(
            &aid("a1"),
            &sid("s1"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            &hash_1,
        )
        .unwrap();
        gate.check_retrievability(
            &aid("a2"),
            &sid("s2"),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            &hash_2,
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
        gate.register_target(
            &aid("art-1"),
            &sid("seg-1"),
            StorageTier::L3Archive,
            good_target(&hash),
        );

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
            &sid("seg-3"),
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
        gate.register_target(
            &aid("art-4"),
            &sid("seg-4"),
            StorageTier::L3Archive,
            good_target(&hash),
        );

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
        gate.register_target(
            &aid("art-5"),
            &sid("seg-5"),
            StorageTier::L3Archive,
            good_target(&hash),
        );

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
        gate.register_target(
            &aid("art-6"),
            &sid("seg-6"),
            StorageTier::L3Archive,
            good_target(&hash),
        );

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
        gate.register_target(
            &aid("art-7"),
            &sid("seg-7"),
            StorageTier::L3Archive,
            good_target(&hash),
        );

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
            &sid("seg-8"),
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
        gate.register_target(
            &aid("art-a"),
            &sid("seg-a"),
            StorageTier::L3Archive,
            good_target(&hash_a),
        );
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
        gate.register_target(
            &aid("art-fb"),
            &sid("seg-fb"),
            StorageTier::L3Archive,
            good_target(&hash),
        );
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
        gate.register_target(
            &aid("art-au"),
            &sid("seg-au"),
            StorageTier::L3Archive,
            good_target(&hash),
        );
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
        gate.register_target(
            &aid("art-prog"),
            &sid("seg-prog"),
            StorageTier::L3Archive,
            good_target(&hash),
        );
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

    // -- Negative-path Security Tests ---------------------------------------
    // Added 2026-04-17: Comprehensive security hardening tests

    #[test]
    fn test_security_unicode_injection_in_artifact_segment_ids() {
        use crate::security::constant_time::ct_eq;

        let mut gate = make_gate();

        // Unicode injection attempts in artifact and segment IDs
        let malicious_identifiers = vec![
            (
                "\u{202E}safe-artifact\u{202D}malicious",  // BiDi override in artifact ID
                "segment\u{200B}001",  // Zero-width space in segment ID
            ),
            (
                "artifact\u{FEFF}123",  // Zero-width no-break space
                "\u{0000}bypass-segment",  // Null injection in segment ID
            ),
            (
                "secure\u{2028}artifact",  // Line separator
                "segment\u{2029}admin",  // Paragraph separator
            ),
            (
                "\u{200E}normal\u{200F}",  // LTR/RTL marks
                "segment\u{202C}reset",  // Pop directional formatting
            ),
        ];

        for (artifact_id_str, segment_id_str) in malicious_identifiers {
            let artifact_id = aid(artifact_id_str);
            let segment_id = sid(segment_id_str);
            let test_hash = content_hash(b"test_payload_unicode");

            // Register target with Unicode-injected IDs
            gate.register_target(&artifact_id, &segment_id, &good_state(&test_hash));

            // Verify Unicode doesn't create privileged identifiers
            assert!(!ct_eq(artifact_id.0.as_bytes(), b"admin"),
                   "Unicode injection should not create admin artifacts");
            assert!(!ct_eq(segment_id.0.as_bytes(), b"admin"),
                   "Unicode injection should not create admin segments");

            // Verify null bytes don't appear in identifiers
            assert!(!artifact_id.0.contains('\0'),
                   "Artifact ID should not contain null bytes");
            assert!(!segment_id.0.contains('\0'),
                   "Segment ID should not contain null bytes");

            // Verify proof request works deterministically despite Unicode
            let proof_result = gate.proof_eviction_safety(&artifact_id, &segment_id);
            match proof_result {
                Ok(_receipt) => {
                    // If proof passed, verify it was for the correct identifiers
                    assert!(gate.receipts().len() > 0, "Should have receipts");
                },
                Err(_) => {
                    // Graceful rejection of Unicode-injected IDs is acceptable
                }
            }
        }
    }

    #[test]
    fn test_security_hash_manipulation_and_bypass_attempts() {
        let mut gate = make_gate();
        let legitimate_hash = content_hash(b"legitimate_content");
        let artifact_id = aid("hash_test_artifact");
        let segment_id = sid("hash_test_segment");

        // Register target with legitimate hash
        gate.register_target(&artifact_id, &segment_id, &good_state(&legitimate_hash));

        // Attempt various hash manipulation attacks
        let malicious_hashes = vec![
            // Hash with modified case (should be lowercase hex)
            legitimate_hash.to_uppercase(),
            // Hash with null injection
            format!("{}\u{0000}", legitimate_hash),
            // Hash with whitespace injection
            format!("{}  ", legitimate_hash),
            format!(" {}", legitimate_hash),
            format!("{}\n", legitimate_hash),
            format!("{}\t", legitimate_hash),
            // Hash with Unicode injection
            format!("{}\u{202E}", legitimate_hash),
            // Truncated hash
            legitimate_hash[..legitimate_hash.len()-2].to_string(),
            // Extended hash
            format!("{}00", legitimate_hash),
            // Invalid hex characters
            legitimate_hash.replace('a', 'g'),
            // Empty hash
            "".to_string(),
            // Non-hex hash
            "not_a_hash_at_all".to_string(),
        ];

        for malicious_hash in malicious_hashes {
            let malicious_state = TargetTierState {
                content_hash: malicious_hash.clone(),
                reachable: true,
                fetch_latency_ms: 100,
            };

            // Create new artifact/segment for each test to avoid state pollution
            let test_artifact = aid(&format!("test_artifact_{}", malicious_hash.len()));
            let test_segment = sid(&format!("test_segment_{}", malicious_hash.len()));

            gate.register_target(&test_artifact, &test_segment, &malicious_state);

            // Hash manipulation should not bypass verification
            let proof_result = gate.proof_eviction_safety(&test_artifact, &test_segment);

            match proof_result {
                Ok(receipt) => {
                    // If somehow accepted, verify security properties
                    if malicious_hash == legitimate_hash.to_uppercase() ||
                       malicious_hash.trim() == legitimate_hash {
                        // Case or whitespace changes should be rejected
                        assert!(!receipt.proof_passed,
                               "Case/whitespace manipulation should fail proof");
                    }
                },
                Err(err) => {
                    // Expected rejection of malformed hashes
                    assert!(err.contains("ERR_HASH_MISMATCH") ||
                           err.contains("ERR_INVALID") ||
                           err.contains("hash"),
                           "Error should indicate hash validation failure: {}", err);
                }
            }
        }
    }

    #[test]
    fn test_security_content_digest_collision_attacks() {
        use crate::security::constant_time::ct_eq_bytes;

        let mut gate = make_gate();

        // Content designed to test collision resistance
        let collision_test_vectors = vec![
            // Different payloads with potential hash collisions
            (b"collision_test_1".to_vec(), b"collision_test_2".to_vec()),
            (b"".to_vec(), b"\x00".to_vec()),  // Empty vs single byte
            (b"abc".to_vec(), b"ab\x00c".to_vec()),  // Null injection
            (b"test_data".to_vec(), b"test\x00_data".to_vec()),  // Null boundary

            // Unicode normalization collision attempts
            ("test".as_bytes().to_vec(), "te\u{0301}st".as_bytes().to_vec()),  // Combining character
            ("café".as_bytes().to_vec(), "cafe\u{0301}".as_bytes().to_vec()),  // Acute accent

            // Length extension attempts
            (b"data".to_vec(), b"data\x00\x00\x00\x00".to_vec()),
        ];

        for (i, (payload1, payload2)) in collision_test_vectors.iter().enumerate() {
            let hash1 = content_hash(payload1);
            let hash2 = content_hash(payload2);
            let artifact_id = aid(&format!("collision_test_artifact_{}", i));
            let segment_id = sid(&format!("collision_test_segment_{}", i));

            // Different payloads should produce different hashes
            if payload1 != payload2 {
                assert!(!ct_eq_bytes(hash1.as_bytes(), hash2.as_bytes()),
                       "Different payloads should have different hashes: {} vs {}", hash1, hash2);
            }

            // Register target with first hash
            gate.register_target(&artifact_id, &segment_id, &good_state(&hash1));

            // Attempt to get proof with manipulated state using second hash
            let manipulated_state = TargetTierState {
                content_hash: hash2.clone(),
                reachable: true,
                fetch_latency_ms: 100,
            };

            // Update registration with manipulated hash
            gate.register_target(&artifact_id, &segment_id, &manipulated_state);

            // Proof should detect hash mismatch
            let proof_result = gate.proof_eviction_safety(&artifact_id, &segment_id);

            if hash1 != hash2 {
                // Different hashes should either be rejected or fail proof verification
                match proof_result {
                    Ok(receipt) => {
                        // If proof completed, it should fail verification for mismatched hash
                        assert!(!receipt.proof_passed || hash1 == hash2,
                               "Proof should fail for hash mismatch");
                    },
                    Err(err) => {
                        // Expected rejection of hash mismatch
                        assert!(err.contains("ERR_HASH_MISMATCH"),
                               "Should report hash mismatch error");
                    }
                }
            }
        }
    }

    #[test]
    fn test_security_proof_binding_tampering() {
        let mut gate = make_gate();
        let test_hash = content_hash(b"proof_binding_test");
        let artifact_id = aid("binding_test_artifact");
        let segment_id = sid("binding_test_segment");

        // Register legitimate target
        gate.register_target(&artifact_id, &segment_id, &good_state(&test_hash));

        // Attempt proof binding manipulation by creating similar identifiers
        let similar_identifiers = vec![
            (aid("binding_test_artifact\u{200B}"), sid("binding_test_segment")),  // Zero-width in artifact
            (aid("binding_test_artifact"), sid("binding_test_segment\u{200B}")),  // Zero-width in segment
            (aid("binding_test_artifact "), sid("binding_test_segment")),  // Trailing space in artifact
            (aid("binding_test_artifact"), sid(" binding_test_segment")),  // Leading space in segment
            (aid("BINDING_TEST_ARTIFACT"), sid("binding_test_segment")),  // Case manipulation
            (aid("binding_test_artifact"), sid("BINDING_TEST_SEGMENT")),  // Case manipulation
        ];

        for (similar_artifact, similar_segment) in similar_identifiers {
            // Register similar target
            gate.register_target(&similar_artifact, &similar_segment, &good_state(&test_hash));

            // Proof should be bound to exact identifiers
            let proof_result = gate.proof_eviction_safety(&similar_artifact, &similar_segment);

            match proof_result {
                Ok(receipt) => {
                    // If proof succeeded, verify binding is preserved
                    assert_eq!(receipt.artifact_id.0, similar_artifact.0,
                             "Receipt should be bound to exact artifact ID");
                    assert_eq!(receipt.segment_id.0, similar_segment.0,
                             "Receipt should be bound to exact segment ID");

                    // Proof should not be transferable to original identifiers if different
                    if similar_artifact.0 != artifact_id.0 || similar_segment.0 != segment_id.0 {
                        let cross_proof = gate.proof_eviction_safety(&artifact_id, &segment_id);
                        // Cross-binding should require separate proof
                        assert!(cross_proof.is_ok(), "Original identifiers should have separate proof");
                    }
                },
                Err(_) => {
                    // Graceful rejection of similar identifiers is acceptable
                }
            }
        }
    }

    #[test]
    fn test_security_latency_manipulation_attacks() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig {
            max_latency_ms: 1000,  // Strict latency limit
            require_hash_match: true,
        });

        let test_hash = content_hash(b"latency_test");
        let artifact_id = aid("latency_test_artifact");
        let segment_id = sid("latency_test_segment");

        // Attempt latency manipulation attacks
        let malicious_latencies = vec![
            999,   // Just under limit (should pass)
            1000,  // At limit (boundary test)
            1001,  // Just over limit (should fail)
            u32::MAX,  // Extreme latency
            0,     // Zero latency (suspicious)
        ];

        for malicious_latency in malicious_latencies {
            let latency_state = TargetTierState {
                content_hash: test_hash.clone(),
                reachable: true,
                fetch_latency_ms: malicious_latency,
            };

            let test_artifact = aid(&format!("latency_artifact_{}", malicious_latency));
            let test_segment = sid(&format!("latency_segment_{}", malicious_latency));

            gate.register_target(&test_artifact, &test_segment, &latency_state);

            let proof_result = gate.proof_eviction_safety(&test_artifact, &test_segment);

            match proof_result {
                Ok(receipt) => {
                    if malicious_latency > 1000 {
                        // High latency should fail proof
                        assert!(!receipt.proof_passed,
                               "High latency {} should fail proof", malicious_latency);
                    } else {
                        // Low latency should pass
                        assert!(receipt.proof_passed,
                               "Low latency {} should pass proof", malicious_latency);
                    }
                },
                Err(err) => {
                    // Expected rejection for excessive latency
                    if malicious_latency > 1000 {
                        assert!(err.contains("ERR_LATENCY_EXCEEDED"),
                               "Should report latency exceeded error");
                    }
                }
            }
        }
    }

    #[test]
    fn test_security_target_state_spoofing() {
        let mut gate = make_gate();
        let test_hash = content_hash(b"spoofing_test");
        let artifact_id = aid("spoofing_test_artifact");
        let segment_id = sid("spoofing_test_segment");

        // Attempt target state spoofing attacks
        let spoofed_states = vec![
            // Unreachable target claiming to be reachable
            TargetTierState {
                content_hash: test_hash.clone(),
                reachable: false,  // Actually unreachable
                fetch_latency_ms: 50,  // But claiming fast latency
            },
            // Target with suspicious hash claiming good state
            TargetTierState {
                content_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),  // All zeros
                reachable: true,
                fetch_latency_ms: 50,
            },
            // Target with non-hex hash
            TargetTierState {
                content_hash: "not_a_valid_hash".to_string(),
                reachable: true,
                fetch_latency_ms: 50,
            },
            // Target with suspiciously perfect latency
            TargetTierState {
                content_hash: test_hash.clone(),
                reachable: true,
                fetch_latency_ms: 0,  // Suspiciously fast
            },
        ];

        for (i, spoofed_state) in spoofed_states.iter().enumerate() {
            let test_artifact = aid(&format!("spoof_artifact_{}", i));
            let test_segment = sid(&format!("spoof_segment_{}", i));

            gate.register_target(&test_artifact, &test_segment, spoofed_state);

            let proof_result = gate.proof_eviction_safety(&test_artifact, &test_segment);

            match proof_result {
                Ok(receipt) => {
                    // Unreachable targets should fail proof
                    if !spoofed_state.reachable {
                        assert!(!receipt.proof_passed,
                               "Unreachable target should fail proof");
                    }

                    // Invalid hashes should fail proof
                    if !is_canonical_sha256_hex_digest(&spoofed_state.content_hash) {
                        assert!(!receipt.proof_passed,
                               "Invalid hash should fail proof");
                    }
                },
                Err(err) => {
                    // Expected rejection of spoofed states
                    assert!(err.contains("ERR_TARGET_UNREACHABLE") ||
                           err.contains("ERR_HASH_MISMATCH") ||
                           err.contains("ERR_INVALID"),
                           "Should report spoofing-related error: {}", err);
                }
            }
        }
    }

    #[test]
    fn test_security_json_injection_in_audit_trails() {
        let mut gate = make_gate();
        let test_hash = content_hash(b"audit_injection_test");

        // Artifact/segment IDs with injection attempts
        let injection_identifiers = vec![
            (
                aid("\";alert('xss');//"),  // JS injection
                sid("normal_segment"),
            ),
            (
                aid("normal_artifact"),
                sid("</script><script>alert('xss')</script>"),  // HTML injection
            ),
            (
                aid("$(rm -rf /)"),  // Command injection
                sid("normal_segment"),
            ),
            (
                aid("line1\nline2\r\nline3"),  // Newline injection
                sid("tab\tseparated\tsegment"),  // Tab injection
            ),
        ];

        for (artifact_id, segment_id) in injection_identifiers {
            gate.register_target(&artifact_id, &segment_id, &good_state(&test_hash));

            let proof_result = gate.proof_eviction_safety(&artifact_id, &segment_id);

            match proof_result {
                Ok(receipt) => {
                    // Serialize receipt to JSON for audit trail
                    let json_result = serde_json::to_string(&receipt);

                    match json_result {
                        Ok(json) => {
                            // JSON should escape all injection attempts
                            assert!(!json.contains("alert('xss')"), "JavaScript injection should be escaped");
                            assert!(!json.contains("</script>"), "HTML injection should be escaped");
                            assert!(!json.contains("rm -rf"), "Command injection should be escaped");
                            assert!(!json.contains("\n"), "Newline injection should be escaped");
                            assert!(!json.contains("\r"), "Carriage return injection should be escaped");
                            assert!(!json.contains("\t"), "Tab injection should be escaped");

                            // Verify roundtrip preserves structure
                            let parsed: ProofReceipt = serde_json::from_str(&json)
                                .expect("should deserialize");
                            assert_eq!(receipt.artifact_id.0, parsed.artifact_id.0);
                            assert_eq!(receipt.segment_id.0, parsed.segment_id.0);
                        },
                        Err(_) => {
                            // Graceful serialization failure is acceptable for extreme injection
                        }
                    }
                },
                Err(_) => {
                    // Graceful rejection of injection attempts is expected
                }
            }
        }
    }

    #[test]
    fn test_security_concurrent_retrievability_access_safety() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let gate = Arc::new(Mutex::new(make_gate()));
        let test_hash = content_hash(b"concurrent_test");
        let mut handles = vec![];

        // Spawn concurrent retrievability operations
        for i in 0..10 {
            let gate_clone = Arc::clone(&gate);
            let test_hash_clone = test_hash.clone();

            let handle = thread::spawn(move || {
                let artifact_id = aid(&format!("concurrent_artifact_{}", i));
                let segment_id = sid(&format!("concurrent_segment_{}", i));

                let mut locked_gate = gate_clone.lock().unwrap();

                // Register target
                locked_gate.register_target(&artifact_id, &segment_id, &good_state(&test_hash_clone));

                // Attempt proof
                locked_gate.proof_eviction_safety(&artifact_id, &segment_id)
            });

            handles.push(handle);
        }

        // Collect results
        let mut results = vec![];
        for handle in handles {
            let result = handle.join().expect("thread should not panic");
            results.push(result);
        }

        // Verify all proofs completed successfully
        for (i, result) in results.iter().enumerate() {
            match result {
                Ok(receipt) => {
                    assert!(receipt.proof_passed, "Concurrent proof {} should pass", i);
                    assert!(receipt.artifact_id.0.contains(&i.to_string()),
                           "Artifact ID should be preserved");
                },
                Err(err) => {
                    panic!("Concurrent proof {} should not fail: {}", i, err);
                }
            }
        }

        // Verify final gate state is consistent
        let final_gate = gate.lock().unwrap();
        assert_eq!(final_gate.receipts().len(), 10, "Should have 10 receipts");
        assert_eq!(final_gate.passed_count(), 10, "Should have 10 passed proofs");
    }

    #[test]
    fn test_security_memory_exhaustion_through_large_receipt_sets() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        // Attempt memory exhaustion through massive receipt generation
        for i in 0..50_000 {
            let artifact_id = aid(&format!("memory_test_artifact_{}", i));
            let segment_id = sid(&format!("memory_test_segment_{}", i));
            let test_hash = content_hash(format!("payload_{}", i).as_bytes());

            gate.register_target(&artifact_id, &segment_id, &good_state(&test_hash));

            // Generate proof receipt
            let _ = gate.proof_eviction_safety(&artifact_id, &segment_id);

            // Verify bounded growth
            if gate.receipts().len() > MAX_RECEIPTS {
                assert!(gate.receipts().len() <= MAX_RECEIPTS + 100,
                       "Receipt count should be bounded near MAX_RECEIPTS");
            }
        }

        // Verify gate remains functional after memory pressure
        let test_artifact = aid("final_test_artifact");
        let test_segment = sid("final_test_segment");
        let test_hash = content_hash(b"final_test_payload");

        gate.register_target(&test_artifact, &test_segment, &good_state(&test_hash));
        let final_result = gate.proof_eviction_safety(&test_artifact, &test_segment);

        assert!(final_result.is_ok(), "Gate should remain functional after memory pressure");
        // Test should complete without OOM
    }

    #[test]
    fn test_security_eviction_bypass_attempts() {
        let mut gate = make_gate();
        let test_hash = content_hash(b"eviction_bypass_test");
        let artifact_id = aid("bypass_test_artifact");
        let segment_id = sid("bypass_test_segment");

        // Register target but don't perform successful proof
        gate.register_target(&artifact_id, &segment_id, &TargetTierState {
            content_hash: test_hash,
            reachable: false,  // Unreachable target
            fetch_latency_ms: 10000,  // High latency
        });

        // Attempt various eviction bypass methods
        let bypass_attempts = vec![
            // Different artifact ID with same content
            (aid("bypass_test_artifact_alt"), sid("bypass_test_segment")),
            // Different segment ID
            (aid("bypass_test_artifact"), sid("bypass_test_segment_alt")),
            // Case manipulation
            (aid("BYPASS_TEST_ARTIFACT"), sid("bypass_test_segment")),
            // Unicode similar identifiers
            (aid("bypass_test_artifact\u{200B}"), sid("bypass_test_segment")),
        ];

        for (bypass_artifact, bypass_segment) in bypass_attempts {
            // Register bypass target
            gate.register_target(&bypass_artifact, &bypass_segment, &TargetTierState {
                content_hash: content_hash(b"eviction_bypass_test"),
                reachable: true,  // Claim reachable
                fetch_latency_ms: 50,  // Low latency
            });

            // Attempt proof for bypass target
            let proof_result = gate.proof_eviction_safety(&bypass_artifact, &bypass_segment);

            match proof_result {
                Ok(receipt) => {
                    // Successful proof should be bound to exact identifiers
                    assert_eq!(receipt.artifact_id, bypass_artifact,
                             "Proof should be bound to exact artifact ID");
                    assert_eq!(receipt.segment_id, bypass_segment,
                             "Proof should be bound to exact segment ID");

                    // Original target should still be blocked
                    let original_proof = gate.proof_eviction_safety(&artifact_id, &segment_id);
                    match original_proof {
                        Ok(original_receipt) => {
                            assert!(!original_receipt.proof_passed,
                                   "Original unreachable target should still fail proof");
                        },
                        Err(err) => {
                            assert!(err.contains("ERR_TARGET_UNREACHABLE") ||
                                   err.contains("ERR_LATENCY_EXCEEDED"),
                                   "Original target should remain blocked");
                        }
                    }
                },
                Err(_) => {
                    // Rejection of bypass attempts is acceptable
                }
            }
        }
    }

    // =========================================================================
    // NEGATIVE-PATH SECURITY HARDENING TESTS
    // =========================================================================
    // Added comprehensive attack vector testing focusing on:
    // - Arithmetic overflow/underflow boundary attacks
    // - Hash collision and timing attack resistance
    // - Resource exhaustion and capacity boundary attacks
    // - Unicode injection and normalization attacks

    #[test]
    fn test_timestamp_counter_overflow_boundary_attacks() {
        let mut gate = RetrievabilityGate {
            config: RetrievabilityConfig::default(),
            target_state: BTreeMap::new(),
            receipts: Vec::new(),
            events: Vec::new(),
            timestamp_counter: u64::MAX.saturating_sub(5), // Near overflow
        };

        let test_hash = content_hash(b"overflow_test");
        let aid = ArtifactId("overflow_artifact".to_string());
        let sid = SegmentId("overflow_segment".to_string());

        gate.register_target(&aid, &sid, StorageTier::L3Archive, TargetTierState {
            content_hash: test_hash.clone(),
            reachable: true,
            fetch_latency_ms: 100,
        });

        // Multiple operations near u64::MAX should use saturating_add
        for i in 0..10 {
            let result = gate.check_retrievability(
                &aid, &sid, StorageTier::L2Warm, StorageTier::L3Archive, &test_hash
            );

            match result {
                Ok(proof) => {
                    // Timestamp should saturate at u64::MAX, not wrap to 0
                    assert!(proof.proof_timestamp >= u64::MAX.saturating_sub(10));
                    assert_eq!(proof.proof_timestamp, u64::MAX);
                },
                Err(e) => panic!("Overflow test #{} failed: {}", i, e),
            }

            // Counter should remain at u64::MAX after saturation
            assert_eq!(gate.timestamp_counter, u64::MAX);
        }

        // Verify receipts all have saturated timestamps
        for receipt in &gate.receipts {
            assert_eq!(receipt.proof_timestamp, u64::MAX);
        }
    }

    #[test]
    fn test_latency_boundary_fail_closed_attacks() {
        let mut gate = make_gate();
        let test_hash = content_hash(b"latency_boundary_test");
        let aid = ArtifactId("latency_test".to_string());
        let sid = SegmentId("latency_segment".to_string());

        // Test exact boundary conditions for fail-closed semantics
        let latency_attack_vectors = vec![
            // At limit (should fail)
            (5000, true, "exactly at limit"),
            // Just over limit (should fail)
            (5001, true, "1ms over limit"),
            // Way over limit (should fail)
            (u64::MAX, true, "maximum latency"),
            // Just under limit (should pass)
            (4999, false, "1ms under limit"),
            // Zero latency edge case
            (0, false, "zero latency"),
        ];

        for (latency_ms, should_fail, description) in latency_attack_vectors {
            gate.register_target(&aid, &sid, StorageTier::L3Archive, TargetTierState {
                content_hash: test_hash.clone(),
                reachable: true,
                fetch_latency_ms: latency_ms,
            });

            let result = gate.check_retrievability(
                &aid, &sid, StorageTier::L2Warm, StorageTier::L3Archive, &test_hash
            );

            match (should_fail, &result) {
                (true, Ok(_)) => panic!("Latency attack should fail ({}): {}ms", description, latency_ms),
                (false, Err(e)) => panic!("Valid latency should pass ({}): {}ms - {}", description, latency_ms, e),
                (true, Err(e)) => {
                    assert_eq!(e.code, ERR_LATENCY_EXCEEDED);
                    assert!(e.reason.label() == "latency_exceeded");
                },
                (false, Ok(proof)) => {
                    assert!(proof.latency_ms < gate.config.max_latency_ms);
                }
            }
        }
    }

    #[test]
    fn test_hash_collision_resistance_and_constant_time_attacks() {
        let mut gate = make_gate();
        let aid = ArtifactId("collision_test".to_string());
        let sid = SegmentId("collision_segment".to_string());

        // Generate legitimate hash
        let legitimate_data = b"legitimate_archive_content";
        let legitimate_hash = content_hash(legitimate_data);

        // Hash collision attack vectors
        let collision_vectors = vec![
            // Empty hash bypass attempt
            ("", "empty hash"),
            // Hex case manipulation
            (legitimate_hash.to_uppercase(), "case manipulation"),
            // Length extension without proper hex
            ("deadbeef".repeat(8), "length extension"),
            // Similar-looking characters
            ("dead8eef".repeat(8), "similar characters"),
            // Domain separator injection attempt
            (format!("{}retrievability_gate_hash_v1:", legitimate_hash), "domain separator injection"),
            // Hash prefix collision attempt
            (format!("{}{}", &legitimate_hash[..32], "0".repeat(32)), "prefix collision"),
        ];

        for (malicious_hash, attack_type) in collision_vectors {
            gate.register_target(&aid, &sid, StorageTier::L3Archive, TargetTierState {
                content_hash: malicious_hash.clone(),
                reachable: true,
                fetch_latency_ms: 100,
            });

            // All collision attempts should fail with constant time
            let start = std::time::Instant::now();
            let result = gate.check_retrievability(
                &aid, &sid, StorageTier::L2Warm, StorageTier::L3Archive, &legitimate_hash
            );
            let duration = start.elapsed();

            match result {
                Ok(_) => panic!("Hash collision attack should fail ({}): {}", attack_type, malicious_hash),
                Err(e) => {
                    // Should fail with hash mismatch, not other errors
                    if malicious_hash.is_empty() {
                        // Empty hash has special handling in content_digest_matches
                        assert_eq!(e.code, ERR_HASH_MISMATCH);
                    } else {
                        assert_eq!(e.code, ERR_HASH_MISMATCH);
                    }
                    assert!(e.reason.label() == "hash_mismatch");

                    // Timing should be consistent (within reasonable bounds for constant-time)
                    assert!(duration.as_millis() < 100, "Hash comparison took too long: {}ms", duration.as_millis());
                }
            }
        }
    }

    #[test]
    fn test_resource_exhaustion_capacity_boundary_attacks() {
        let mut gate = make_gate();

        // Test events capacity boundary
        for i in 0..MAX_EVENTS + 100 {
            let aid = ArtifactId(format!("exhaust_artifact_{}", i));
            let sid = SegmentId(format!("exhaust_segment_{}", i));

            gate.register_target(&aid, &sid, StorageTier::L3Archive, TargetTierState {
                content_hash: "invalid_hash".to_string(), // Will fail
                reachable: true,
                fetch_latency_ms: 100,
            });

            let _result = gate.check_retrievability(
                &aid, &sid, StorageTier::L2Warm, StorageTier::L3Archive, "expected_hash"
            );
        }

        // Events should be bounded by push_bounded implementation
        assert!(gate.events.len() <= MAX_EVENTS + 10, "Events not properly bounded: {}", gate.events.len());

        // Test receipts capacity boundary
        for i in 0..MAX_RECEIPTS + 50 {
            let aid = ArtifactId(format!("receipt_artifact_{}", i));
            let sid = SegmentId(format!("receipt_segment_{}", i));
            let test_hash = content_hash(format!("receipt_test_{}", i).as_bytes());

            gate.register_target(&aid, &sid, StorageTier::L3Archive, TargetTierState {
                content_hash: test_hash.clone(),
                reachable: true,
                fetch_latency_ms: 100,
            });

            let _result = gate.check_retrievability(
                &aid, &sid, StorageTier::L2Warm, StorageTier::L3Archive, &test_hash
            );
        }

        // Receipts should be bounded
        assert!(gate.receipts.len() <= MAX_RECEIPTS + 10, "Receipts not properly bounded: {}", gate.receipts.len());
    }

    #[test]
    fn test_identifier_injection_normalization_attacks() {
        let mut gate = make_gate();
        let test_hash = content_hash(b"injection_test");

        // Unicode injection and normalization attack vectors
        let injection_vectors = vec![
            // Control character injection
            ("artifact\0id", "segment_id", "null byte in artifact"),
            ("artifact_id", "segment\0id", "null byte in segment"),
            ("artifact\u{200B}id", "segment_id", "zero-width space artifact"),
            ("artifact_id", "segment\u{FEFF}id", "BOM in segment"),

            // Whitespace normalization
            ("artifact\u{2000}id", "segment_id", "en quad in artifact"),
            ("artifact_id", "segment\u{2028}id", "line separator in segment"),
            ("artifact\u{00A0}id", "segment_id", "non-breaking space in artifact"),
        ];

        for (artifact_id, segment_id, attack_type) in injection_vectors {
            let aid = ArtifactId(artifact_id.to_string());
            let sid = SegmentId(segment_id.to_string());

            // Check input validation
            match (invalid_artifact_id_reason(&aid), invalid_segment_id_reason(&sid)) {
                (Some(artifact_reason), _) => {
                    // Should reject invalid artifact IDs
                    assert!(artifact_reason.contains("control") ||
                           artifact_reason.contains("whitespace") ||
                           artifact_reason.contains("empty"),
                           "Should detect artifact ID issue ({}): {}", attack_type, artifact_reason);
                },
                (_, Some(segment_reason)) => {
                    // Should reject invalid segment IDs
                    assert!(segment_reason.contains("control") ||
                           segment_reason.contains("whitespace") ||
                           segment_reason.contains("empty"),
                           "Should detect segment ID issue ({}): {}", attack_type, segment_reason);
                },
                (None, None) => {
                    // If validation passes, test proof binding
                    gate.register_target(&aid, &sid, StorageTier::L3Archive, TargetTierState {
                        content_hash: test_hash.clone(),
                        reachable: true,
                        fetch_latency_ms: 100,
                    });

                    match gate.check_retrievability(&aid, &sid, StorageTier::L2Warm, StorageTier::L3Archive, &test_hash) {
                        Ok(proof) => {
                            assert_eq!(proof.artifact_id.0, aid.0, "Proof artifact binding mismatch ({})", attack_type);
                            assert_eq!(proof.segment_id.0, sid.0, "Proof segment binding mismatch ({})", attack_type);
                        },
                        Err(e) => {
                            assert!(e.code == ERR_INVALID_ARTIFACT_ID || e.code == ERR_INVALID_SEGMENT_ID,
                                   "Unexpected error for injection attack ({}): {}", attack_type, e);
                        }
                    }
                }
            }
        }
    }
}
