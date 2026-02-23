//! bd-2ms: Rollback/fork detection in control-plane state propagation.
//!
//! Detects when control-plane state has diverged or been rolled back across
//! distributed nodes. Integrates canonical divergence detection and marker
//! proofs from Section 10.14's append-only marker stream.
//!
//! # Invariants
//!
//! - INV-RFD-DETECT-FORK: Any fork in state history is detected within one
//!   propagation cycle.
//! - INV-RFD-DETECT-ROLLBACK: Unauthorized rollbacks detected by parent-hash
//!   chain validation.
//! - INV-RFD-HALT-ON-DIVERGENCE: On fork or rollback, emit CRITICAL log and
//!   block further mutations.
//! - INV-RFD-PROOF-SERIALIZABLE: RollbackProof is serializable for audit and
//!   external verification.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::control_plane::marker_stream::MarkerStream;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Stable event codes for structured logging (prefix RFD).
pub mod event_codes {
    /// CRITICAL: Fork or rollback detected between replicas.
    pub const RFD_DIVERGENCE_DETECTED: &str = "RFD_DIVERGENCE_DETECTED";
    /// INFO: Two replicas confirmed converged at same epoch.
    pub const RFD_CONVERGENCE_VERIFIED: &str = "RFD_CONVERGENCE_VERIFIED";
    /// INFO: Marker proof validated successfully against stream.
    pub const RFD_MARKER_VERIFIED: &str = "RFD_MARKER_VERIFIED";
    /// WARN: Reconciliation suggestion generated for operator.
    pub const RFD_RECONCILIATION_SUGGESTED: &str = "RFD_RECONCILIATION_SUGGESTED";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// Error codes for fork detection operations (prefix RFD).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkDetectionError {
    /// State hashes diverge at the same epoch.
    RfdForkDetected {
        epoch: u64,
        local_hash: String,
        remote_hash: String,
    },
    /// Parent hash chain is broken (rollback).
    RfdRollbackDetected {
        epoch: u64,
        expected_parent: String,
        actual_parent: String,
    },
    /// Epoch gap exceeds 1 between replicas.
    RfdGapDetected { local_epoch: u64, remote_epoch: u64 },
    /// Marker not found in stream at claimed epoch.
    RfdMarkerNotFound {
        marker_id: String,
        claimed_epoch: u64,
    },
}

impl ForkDetectionError {
    /// Stable error code string for structured logging.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::RfdForkDetected { .. } => "RFD_FORK_DETECTED",
            Self::RfdRollbackDetected { .. } => "RFD_ROLLBACK_DETECTED",
            Self::RfdGapDetected { .. } => "RFD_GAP_DETECTED",
            Self::RfdMarkerNotFound { .. } => "RFD_MARKER_NOT_FOUND",
        }
    }
}

impl fmt::Display for ForkDetectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RfdForkDetected {
                epoch,
                local_hash,
                remote_hash,
            } => write!(
                f,
                "RFD_FORK_DETECTED: epoch={epoch}, local_hash={local_hash}, remote_hash={remote_hash}"
            ),
            Self::RfdRollbackDetected {
                epoch,
                expected_parent,
                actual_parent,
            } => write!(
                f,
                "RFD_ROLLBACK_DETECTED: epoch={epoch}, expected_parent={expected_parent}, actual_parent={actual_parent}"
            ),
            Self::RfdGapDetected {
                local_epoch,
                remote_epoch,
            } => write!(
                f,
                "RFD_GAP_DETECTED: local_epoch={local_epoch}, remote_epoch={remote_epoch}"
            ),
            Self::RfdMarkerNotFound {
                marker_id,
                claimed_epoch,
            } => write!(
                f,
                "RFD_MARKER_NOT_FOUND: marker_id={marker_id}, claimed_epoch={claimed_epoch}"
            ),
        }
    }
}

impl std::error::Error for ForkDetectionError {}

// ---------------------------------------------------------------------------
// StateVector
// ---------------------------------------------------------------------------

/// Canonical snapshot of control-plane state at a specific epoch.
///
/// Contains all fields needed for divergence comparison:
/// - epoch: monotonic control epoch number
/// - marker_id: TrustObjectId with MARKER domain (from bd-1l5)
/// - state_hash: SHA-256 of canonical-serialized state at this epoch
/// - parent_state_hash: SHA-256 of previous epoch state
/// - timestamp: Unix timestamp of snapshot
/// - node_id: originating node identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateVector {
    pub epoch: u64,
    pub marker_id: String,
    pub state_hash: String,
    pub parent_state_hash: String,
    pub timestamp: u64,
    pub node_id: String,
}

impl StateVector {
    /// Compute a deterministic state hash from the given payload.
    ///
    /// In production this would be SHA-256 over canonical serialization.
    /// For the crate's purposes we use a deterministic hasher.
    #[must_use]
    pub fn compute_state_hash(payload: &str) -> String {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"fork_detection_state_v1:");
        sha2::Digest::update(&mut hasher, payload.as_bytes());
        format!("{:x}", sha2::Digest::finalize(hasher))
    }
}

// ---------------------------------------------------------------------------
// DetectionResult
// ---------------------------------------------------------------------------

/// Result of comparing two StateVectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionResult {
    /// Both replicas share identical state at the same epoch.
    Converged,
    /// Same epoch but different state hashes.
    Forked,
    /// Epoch difference exceeds 1.
    GapDetected,
    /// Parent hash chain broken: unauthorized rollback.
    RollbackDetected,
}

impl DetectionResult {
    /// Human-readable label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Converged => "CONVERGED",
            Self::Forked => "FORKED",
            Self::GapDetected => "GAP_DETECTED",
            Self::RollbackDetected => "ROLLBACK_DETECTED",
        }
    }

    /// Whether this result indicates a safe (non-divergent) state.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Converged)
    }
}

impl fmt::Display for DetectionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// RollbackProof
// ---------------------------------------------------------------------------

/// Serializable proof of rollback or fork for audit logging.
///
/// INV-RFD-PROOF-SERIALIZABLE: This struct MUST be serializable for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackProof {
    /// The local state vector.
    pub local_state: StateVector,
    /// The remote/divergent state vector.
    pub remote_state: StateVector,
    /// Expected parent hash (from the older state vector).
    pub expected_parent_hash: String,
    /// Actual parent hash found in the newer state vector.
    pub actual_parent_hash: String,
    /// Unix timestamp when divergence was detected.
    pub detection_timestamp: u64,
    /// Trace correlation identifier.
    pub trace_id: String,
    /// Classification of the detection.
    pub detection_result: DetectionResult,
}

// ---------------------------------------------------------------------------
// ReconciliationSuggestion
// ---------------------------------------------------------------------------

/// Actionable suggestion for operator reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconciliationSuggestion {
    /// No action needed; replicas are converged.
    NoAction,
    /// Gap detected: includes range of missing epochs.
    FillGap {
        missing_start: u64,
        missing_end: u64,
    },
    /// Fork detected: includes both competing state hashes for operator review.
    ResolveConflict {
        epoch: u64,
        local_hash: String,
        remote_hash: String,
    },
    /// Rollback detected: full proof for operator review.
    InvestigateRollback { proof: Box<RollbackProof> },
}

// ---------------------------------------------------------------------------
// StructuredLogEvent
// ---------------------------------------------------------------------------

/// Structured divergence log event for observability pipelines.
///
/// INV-RFD-HALT-ON-DIVERGENCE: emitted at CRITICAL severity on detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceLogEvent {
    pub event_code: String,
    pub severity: String,
    pub detection_result: DetectionResult,
    pub local_epoch: u64,
    pub remote_epoch: u64,
    pub local_state_hash: String,
    pub remote_state_hash: String,
    pub trace_id: String,
    pub node_id: String,
    pub epoch_id: u64,
    pub detection_latency_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// DivergenceDetector
// ---------------------------------------------------------------------------

/// Compares two StateVectors from different replicas to detect forks,
/// rollbacks, and gaps.
///
/// INV-RFD-DETECT-FORK: fork in state history detected within one cycle.
/// INV-RFD-DETECT-ROLLBACK: rollback detected by parent-hash validation.
pub struct DivergenceDetector {
    /// History of state vectors seen by this detector (for audit).
    history: Vec<StateVector>,
    /// Whether mutations are blocked due to detected divergence.
    halted: bool,
    /// The last detection result.
    last_result: Option<DetectionResult>,
}

impl DivergenceDetector {
    /// Create a new DivergenceDetector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            history: Vec::new(),
            halted: false,
            last_result: None,
        }
    }

    /// Whether this detector is in halted state (divergence detected).
    #[must_use]
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    /// The last detection result, if any.
    #[must_use]
    pub fn last_result(&self) -> Option<&DetectionResult> {
        self.last_result.as_ref()
    }

    /// Number of state vectors in history.
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Record a state vector into history.
    pub fn record_state(&mut self, sv: StateVector) {
        self.history.push(sv);
    }

    /// Compare two StateVectors and return the detection result.
    ///
    /// Classification logic:
    /// 1. If epochs match and state_hashes match => CONVERGED
    /// 2. If epochs match and state_hashes differ => FORKED
    /// 3. If epochs differ by >1 => GAP_DETECTED
    /// 4. If parent_state_hash of newer != state_hash of older => ROLLBACK_DETECTED
    pub fn compare(
        &mut self,
        local: &StateVector,
        remote: &StateVector,
    ) -> (DetectionResult, Option<RollbackProof>) {
        let trace_id = format!("rfd-{}-{}-{}", local.node_id, remote.node_id, local.epoch);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Record both vectors
        self.record_state(local.clone());
        self.record_state(remote.clone());

        // Determine which is newer
        let (older, newer) = if local.epoch >= remote.epoch {
            (remote, local)
        } else {
            (local, remote)
        };

        // Check 3: epoch gap > 1
        if newer.epoch.saturating_sub(older.epoch) > 1 {
            self.last_result = Some(DetectionResult::GapDetected);
            // Gaps don't halt but emit a warning
            return (DetectionResult::GapDetected, None);
        }

        // Check 1 & 2: epochs match
        if local.epoch == remote.epoch {
            if local.state_hash == remote.state_hash {
                // Same state but different parent chain → rollback detected.
                if local.parent_state_hash != remote.parent_state_hash {
                    self.halted = true;
                    let proof = RollbackProof {
                        local_state: local.clone(),
                        remote_state: remote.clone(),
                        expected_parent_hash: local.parent_state_hash.clone(),
                        actual_parent_hash: remote.parent_state_hash.clone(),
                        detection_timestamp: now,
                        trace_id,
                        detection_result: DetectionResult::RollbackDetected,
                    };
                    self.last_result = Some(DetectionResult::RollbackDetected);
                    return (DetectionResult::RollbackDetected, Some(proof));
                }
                self.last_result = Some(DetectionResult::Converged);
                // Do NOT reset halted here — only operator_reset() clears halt.
                return (DetectionResult::Converged, None);
            }

            // FORKED: same epoch, different hashes
            // INV-RFD-HALT-ON-DIVERGENCE
            self.halted = true;
            let proof = RollbackProof {
                local_state: local.clone(),
                remote_state: remote.clone(),
                expected_parent_hash: local.state_hash.clone(),
                actual_parent_hash: remote.state_hash.clone(),
                detection_timestamp: now,
                trace_id,
                detection_result: DetectionResult::Forked,
            };
            self.last_result = Some(DetectionResult::Forked);
            return (DetectionResult::Forked, Some(proof));
        }

        // Check 4: parent hash chain validation
        // The newer state's parent_state_hash should match the older state's state_hash
        if newer.parent_state_hash != older.state_hash {
            // ROLLBACK_DETECTED
            // INV-RFD-HALT-ON-DIVERGENCE
            self.halted = true;
            let proof = RollbackProof {
                local_state: local.clone(),
                remote_state: remote.clone(),
                expected_parent_hash: older.state_hash.clone(),
                actual_parent_hash: newer.parent_state_hash.clone(),
                detection_timestamp: now,
                trace_id,
                detection_result: DetectionResult::RollbackDetected,
            };
            self.last_result = Some(DetectionResult::RollbackDetected);
            return (DetectionResult::RollbackDetected, Some(proof));
        }

        // Adjacent epochs with valid parent chain
        self.last_result = Some(DetectionResult::Converged);
        // Do NOT reset halted here — only operator_reset() clears halt.
        (DetectionResult::Converged, None)
    }

    /// Compare and produce a structured log event.
    pub fn compare_and_log(
        &mut self,
        local: &StateVector,
        remote: &StateVector,
    ) -> (DetectionResult, Option<RollbackProof>, DivergenceLogEvent) {
        let (result, proof) = self.compare(local, remote);

        let event_code = match &result {
            DetectionResult::Converged => event_codes::RFD_CONVERGENCE_VERIFIED,
            _ => event_codes::RFD_DIVERGENCE_DETECTED,
        };

        let severity = match &result {
            DetectionResult::Converged => "INFO",
            DetectionResult::GapDetected => "WARN",
            _ => "CRITICAL",
        };

        let log_event = DivergenceLogEvent {
            event_code: event_code.to_string(),
            severity: severity.to_string(),
            detection_result: result.clone(),
            local_epoch: local.epoch,
            remote_epoch: remote.epoch,
            local_state_hash: local.state_hash.clone(),
            remote_state_hash: remote.state_hash.clone(),
            trace_id: format!("rfd-{}-{}-{}", local.node_id, remote.node_id, local.epoch),
            node_id: local.node_id.clone(),
            epoch_id: local.epoch,
            detection_latency_ms: None,
        };

        (result, proof, log_event)
    }

    /// Generate a reconciliation suggestion from the detection result.
    #[must_use]
    pub fn suggest_reconciliation(
        local: &StateVector,
        remote: &StateVector,
        result: &DetectionResult,
        proof: Option<RollbackProof>,
    ) -> ReconciliationSuggestion {
        match result {
            DetectionResult::Converged => ReconciliationSuggestion::NoAction,
            DetectionResult::GapDetected => {
                let (lo, hi) = if local.epoch < remote.epoch {
                    (local.epoch.saturating_add(1), remote.epoch)
                } else {
                    (remote.epoch.saturating_add(1), local.epoch)
                };
                ReconciliationSuggestion::FillGap {
                    missing_start: lo,
                    missing_end: hi,
                }
            }
            DetectionResult::Forked => ReconciliationSuggestion::ResolveConflict {
                epoch: local.epoch,
                local_hash: local.state_hash.clone(),
                remote_hash: remote.state_hash.clone(),
            },
            DetectionResult::RollbackDetected => {
                if let Some(p) = proof {
                    ReconciliationSuggestion::InvestigateRollback { proof: Box::new(p) }
                } else {
                    ReconciliationSuggestion::ResolveConflict {
                        epoch: local.epoch,
                        local_hash: local.state_hash.clone(),
                        remote_hash: remote.state_hash.clone(),
                    }
                }
            }
        }
    }

    /// Reset the halted state (requires explicit operator authorization).
    pub fn operator_reset(&mut self) {
        self.halted = false;
        self.last_result = None;
    }
}

impl Default for DivergenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RollbackDetector (convenience wrapper for repeated comparisons)
// ---------------------------------------------------------------------------

/// Detects unauthorized rollbacks by tracking a chain of state vectors.
///
/// INV-RFD-DETECT-ROLLBACK: validates parent-hash chain continuity.
pub struct RollbackDetector {
    /// Last known good state vector.
    last_known: Option<StateVector>,
    /// All rollback proofs generated.
    proofs: Vec<RollbackProof>,
}

impl RollbackDetector {
    /// Create a new RollbackDetector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_known: None,
            proofs: Vec::new(),
        }
    }

    /// Feed a new state vector. Returns Err with RollbackProof if rollback detected.
    pub fn feed(&mut self, sv: StateVector) -> Result<(), ForkDetectionError> {
        if let Some(ref last) = self.last_known {
            // Reject backward or same-epoch state vectors as rollbacks.
            if sv.epoch <= last.epoch {
                let proof = RollbackProof {
                    local_state: last.clone(),
                    remote_state: sv.clone(),
                    expected_parent_hash: last.state_hash.clone(),
                    actual_parent_hash: sv.parent_state_hash.clone(),
                    detection_timestamp: sv.timestamp,
                    trace_id: format!("rbd-{}-{}", last.epoch, sv.epoch),
                    detection_result: DetectionResult::RollbackDetected,
                };
                self.proofs.push(proof);
                return Err(ForkDetectionError::RfdRollbackDetected {
                    epoch: sv.epoch,
                    expected_parent: last.state_hash.clone(),
                    actual_parent: sv.parent_state_hash.clone(),
                });
            }
            // The new state's parent_state_hash must match the last state's state_hash
            if sv.parent_state_hash != last.state_hash {
                let proof = RollbackProof {
                    local_state: last.clone(),
                    remote_state: sv.clone(),
                    expected_parent_hash: last.state_hash.clone(),
                    actual_parent_hash: sv.parent_state_hash.clone(),
                    detection_timestamp: sv.timestamp,
                    trace_id: format!("rbd-{}-{}", last.epoch, sv.epoch),
                    detection_result: DetectionResult::RollbackDetected,
                };
                self.proofs.push(proof);
                return Err(ForkDetectionError::RfdRollbackDetected {
                    epoch: sv.epoch,
                    expected_parent: last.state_hash.clone(),
                    actual_parent: sv.parent_state_hash.clone(),
                });
            }
        }
        self.last_known = Some(sv);
        Ok(())
    }

    /// Get all rollback proofs generated so far.
    #[must_use]
    pub fn proofs(&self) -> &[RollbackProof] {
        &self.proofs
    }

    /// Number of rollback proofs.
    #[must_use]
    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    /// Last known state vector.
    #[must_use]
    pub fn last_known(&self) -> Option<&StateVector> {
        self.last_known.as_ref()
    }
}

impl Default for RollbackDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MarkerProofVerifier
// ---------------------------------------------------------------------------

/// Validates that a state vector's marker_id appears in the append-only
/// marker stream at the claimed epoch.
///
/// Returns Ok(()) on success, or MarkerNotFound / MarkerEpochMismatch on failure.
pub struct MarkerProofVerifier;

impl MarkerProofVerifier {
    /// Verify that `marker_id` appears in `stream` at position `claimed_epoch`.
    ///
    /// The marker stream is zero-indexed by sequence number. We check that:
    /// 1. A marker exists at the claimed epoch's sequence index.
    /// 2. The marker's marker_hash matches the state vector's marker_id.
    pub fn verify(
        stream: &MarkerStream,
        marker_id: &str,
        claimed_epoch: u64,
    ) -> Result<(), ForkDetectionError> {
        let marker =
            stream
                .get(claimed_epoch)
                .ok_or_else(|| ForkDetectionError::RfdMarkerNotFound {
                    marker_id: marker_id.to_string(),
                    claimed_epoch,
                })?;

        if marker.marker_hash != marker_id {
            return Err(ForkDetectionError::RfdMarkerNotFound {
                marker_id: marker_id.to_string(),
                claimed_epoch,
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::marker_stream::{MarkerEventType, MarkerStream};

    fn make_sv(epoch: u64, hash_seed: &str, parent_seed: &str, node: &str) -> StateVector {
        StateVector {
            epoch,
            marker_id: format!("marker-{epoch}"),
            state_hash: StateVector::compute_state_hash(hash_seed),
            parent_state_hash: StateVector::compute_state_hash(parent_seed),
            timestamp: 1000 + epoch,
            node_id: node.to_string(),
        }
    }

    fn make_chain(count: u64, node: &str) -> Vec<StateVector> {
        let mut chain = Vec::new();
        let mut prev_hash = StateVector::compute_state_hash("genesis");
        for i in 0..count {
            let seed = format!("state-{node}-{i}");
            let hash = StateVector::compute_state_hash(&seed);
            chain.push(StateVector {
                epoch: i,
                marker_id: format!("marker-{i}"),
                state_hash: hash.clone(),
                parent_state_hash: prev_hash.clone(),
                timestamp: 1000 + i,
                node_id: node.to_string(),
            });
            prev_hash = hash;
        }
        chain
    }

    // ---- DetectionResult ----

    #[test]
    fn detection_result_labels() {
        assert_eq!(DetectionResult::Converged.label(), "CONVERGED");
        assert_eq!(DetectionResult::Forked.label(), "FORKED");
        assert_eq!(DetectionResult::GapDetected.label(), "GAP_DETECTED");
        assert_eq!(
            DetectionResult::RollbackDetected.label(),
            "ROLLBACK_DETECTED"
        );
    }

    #[test]
    fn detection_result_is_safe() {
        assert!(DetectionResult::Converged.is_safe());
        assert!(!DetectionResult::Forked.is_safe());
        assert!(!DetectionResult::GapDetected.is_safe());
        assert!(!DetectionResult::RollbackDetected.is_safe());
    }

    #[test]
    fn detection_result_display() {
        assert_eq!(DetectionResult::Converged.to_string(), "CONVERGED");
        assert_eq!(DetectionResult::Forked.to_string(), "FORKED");
    }

    #[test]
    fn detection_result_serde_roundtrip() {
        for result in [
            DetectionResult::Converged,
            DetectionResult::Forked,
            DetectionResult::GapDetected,
            DetectionResult::RollbackDetected,
        ] {
            let json = serde_json::to_string(&result).unwrap();
            let parsed: DetectionResult = serde_json::from_str(&json).unwrap();
            assert_eq!(result, parsed);
        }
    }

    // ---- StateVector ----

    #[test]
    fn state_vector_compute_hash_deterministic() {
        let h1 = StateVector::compute_state_hash("test-payload");
        let h2 = StateVector::compute_state_hash("test-payload");
        assert_eq!(h1, h2);
    }

    #[test]
    fn state_vector_compute_hash_different_inputs() {
        let h1 = StateVector::compute_state_hash("payload-a");
        let h2 = StateVector::compute_state_hash("payload-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn state_vector_serde_roundtrip() {
        let sv = make_sv(10, "seed-a", "seed-parent", "node-1");
        let json = serde_json::to_string(&sv).unwrap();
        let parsed: StateVector = serde_json::from_str(&json).unwrap();
        assert_eq!(sv, parsed);
    }

    #[test]
    fn state_vector_fields_populated() {
        let sv = make_sv(42, "hash-seed", "parent-seed", "test-node");
        assert_eq!(sv.epoch, 42);
        assert_eq!(sv.marker_id, "marker-42");
        assert!(!sv.state_hash.is_empty());
        assert!(!sv.parent_state_hash.is_empty());
        assert_eq!(sv.timestamp, 1042);
        assert_eq!(sv.node_id, "test-node");
    }

    // ---- DivergenceDetector: CONVERGED case ----

    #[test]
    fn converged_same_epoch_same_hash() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(5, "same-state", "parent", "node-a");
        let sv2 = StateVector {
            node_id: "node-b".to_string(),
            ..sv1.clone()
        };
        let (result, proof) = detector.compare(&sv1, &sv2);
        assert_eq!(result, DetectionResult::Converged);
        assert!(proof.is_none());
        assert!(!detector.is_halted());
    }

    #[test]
    fn converged_adjacent_epochs_valid_chain() {
        let mut detector = DivergenceDetector::new();
        let parent_hash = StateVector::compute_state_hash("state-at-4");
        let sv1 = StateVector {
            epoch: 4,
            marker_id: "marker-4".to_string(),
            state_hash: parent_hash.clone(),
            parent_state_hash: StateVector::compute_state_hash("state-at-3"),
            timestamp: 1004,
            node_id: "node-a".to_string(),
        };
        let sv2 = StateVector {
            epoch: 5,
            marker_id: "marker-5".to_string(),
            state_hash: StateVector::compute_state_hash("state-at-5"),
            parent_state_hash: parent_hash.clone(),
            timestamp: 1005,
            node_id: "node-b".to_string(),
        };
        let (result, proof) = detector.compare(&sv1, &sv2);
        assert_eq!(result, DetectionResult::Converged);
        assert!(proof.is_none());
    }

    // ---- DivergenceDetector: FORKED case ----

    #[test]
    fn forked_same_epoch_different_hash() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(10, "state-a", "parent", "node-a");
        let sv2 = make_sv(10, "state-b", "parent", "node-b");
        let (result, proof) = detector.compare(&sv1, &sv2);
        assert_eq!(result, DetectionResult::Forked);
        assert!(proof.is_some());
        assert!(detector.is_halted());

        let p = proof.unwrap();
        assert_eq!(p.detection_result, DetectionResult::Forked);
        assert_eq!(p.local_state.epoch, 10);
        assert_eq!(p.remote_state.epoch, 10);
    }

    #[test]
    fn forked_halts_detector() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(5, "fork-a", "parent", "node-a");
        let sv2 = make_sv(5, "fork-b", "parent", "node-b");
        detector.compare(&sv1, &sv2);
        assert!(detector.is_halted());
    }

    // ---- DivergenceDetector: GAP_DETECTED case ----

    #[test]
    fn gap_detected_large_epoch_difference() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(1, "state-1", "parent-0", "node-a");
        let sv2 = make_sv(10, "state-10", "parent-9", "node-b");
        let (result, proof) = detector.compare(&sv1, &sv2);
        assert_eq!(result, DetectionResult::GapDetected);
        assert!(proof.is_none());
    }

    #[test]
    fn gap_detected_epoch_diff_exactly_two() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(5, "state-5", "parent-4", "node-a");
        let sv2 = make_sv(7, "state-7", "parent-6", "node-b");
        let (result, _) = detector.compare(&sv1, &sv2);
        assert_eq!(result, DetectionResult::GapDetected);
    }

    // ---- DivergenceDetector: ROLLBACK_DETECTED case ----

    #[test]
    fn rollback_detected_broken_parent_chain() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(5, "state-5", "parent-4", "node-a");
        // sv2 is at epoch 6, but its parent hash does NOT match sv1's state_hash
        let sv2 = StateVector {
            epoch: 6,
            marker_id: "marker-6".to_string(),
            state_hash: StateVector::compute_state_hash("state-6"),
            parent_state_hash: StateVector::compute_state_hash("WRONG-PARENT"),
            timestamp: 1006,
            node_id: "node-b".to_string(),
        };
        let (result, proof) = detector.compare(&sv1, &sv2);
        assert_eq!(result, DetectionResult::RollbackDetected);
        assert!(proof.is_some());
        assert!(detector.is_halted());

        let p = proof.unwrap();
        assert_eq!(p.expected_parent_hash, sv1.state_hash);
        assert_eq!(p.actual_parent_hash, sv2.parent_state_hash);
        assert_ne!(p.expected_parent_hash, p.actual_parent_hash);
    }

    #[test]
    fn rollback_detected_halts_detector() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(10, "state-10", "parent-9", "node-a");
        let sv2 = StateVector {
            epoch: 11,
            marker_id: "marker-11".to_string(),
            state_hash: StateVector::compute_state_hash("state-11"),
            parent_state_hash: StateVector::compute_state_hash("BAD"),
            timestamp: 1011,
            node_id: "node-b".to_string(),
        };
        detector.compare(&sv1, &sv2);
        assert!(detector.is_halted());
    }

    // ---- DivergenceDetector: operator_reset ----

    #[test]
    fn operator_reset_clears_halt() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(1, "fork-a", "parent", "node-a");
        let sv2 = make_sv(1, "fork-b", "parent", "node-b");
        detector.compare(&sv1, &sv2);
        assert!(detector.is_halted());
        detector.operator_reset();
        assert!(!detector.is_halted());
        assert!(detector.last_result().is_none());
    }

    // ---- DivergenceDetector: history ----

    #[test]
    fn history_records_both_vectors() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(1, "a", "p", "n1");
        let sv2 = make_sv(1, "a", "p", "n2");
        detector.compare(&sv1, &sv2);
        assert_eq!(detector.history_len(), 2);
    }

    #[test]
    fn history_accumulates() {
        let mut detector = DivergenceDetector::new();
        for i in 0..5 {
            let sv1 = make_sv(i, "a", "p", "n1");
            let sv2 = StateVector {
                node_id: "n2".to_string(),
                ..sv1.clone()
            };
            detector.compare(&sv1, &sv2);
        }
        assert_eq!(detector.history_len(), 10); // 2 per compare
    }

    // ---- DivergenceDetector: compare_and_log ----

    #[test]
    fn compare_and_log_converged_event() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(1, "same", "p", "n1");
        let sv2 = StateVector {
            node_id: "n2".to_string(),
            ..sv1.clone()
        };
        let (result, proof, event) = detector.compare_and_log(&sv1, &sv2);
        assert_eq!(result, DetectionResult::Converged);
        assert!(proof.is_none());
        assert_eq!(event.event_code, event_codes::RFD_CONVERGENCE_VERIFIED);
        assert_eq!(event.severity, "INFO");
    }

    #[test]
    fn compare_and_log_forked_event() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(5, "fa", "p", "n1");
        let sv2 = make_sv(5, "fb", "p", "n2");
        let (result, proof, event) = detector.compare_and_log(&sv1, &sv2);
        assert_eq!(result, DetectionResult::Forked);
        assert!(proof.is_some());
        assert_eq!(event.event_code, event_codes::RFD_DIVERGENCE_DETECTED);
        assert_eq!(event.severity, "CRITICAL");
    }

    #[test]
    fn compare_and_log_gap_event() {
        let mut detector = DivergenceDetector::new();
        let sv1 = make_sv(1, "a", "p", "n1");
        let sv2 = make_sv(10, "b", "p2", "n2");
        let (_, _, event) = detector.compare_and_log(&sv1, &sv2);
        assert_eq!(event.event_code, event_codes::RFD_DIVERGENCE_DETECTED);
        assert_eq!(event.severity, "WARN");
    }

    // ---- ReconciliationSuggestion ----

    #[test]
    fn reconciliation_no_action_for_converged() {
        let sv1 = make_sv(1, "same", "p", "n1");
        let sv2 = StateVector {
            node_id: "n2".to_string(),
            ..sv1.clone()
        };
        let suggestion = DivergenceDetector::suggest_reconciliation(
            &sv1,
            &sv2,
            &DetectionResult::Converged,
            None,
        );
        assert_eq!(suggestion, ReconciliationSuggestion::NoAction);
    }

    #[test]
    fn reconciliation_fill_gap() {
        let sv1 = make_sv(3, "a", "p", "n1");
        let sv2 = make_sv(10, "b", "p2", "n2");
        let suggestion = DivergenceDetector::suggest_reconciliation(
            &sv1,
            &sv2,
            &DetectionResult::GapDetected,
            None,
        );
        match suggestion {
            ReconciliationSuggestion::FillGap {
                missing_start,
                missing_end,
            } => {
                assert_eq!(missing_start, 4);
                assert_eq!(missing_end, 10);
            }
            _ => panic!("Expected FillGap"),
        }
    }

    #[test]
    fn reconciliation_resolve_conflict() {
        let sv1 = make_sv(5, "fa", "p", "n1");
        let sv2 = make_sv(5, "fb", "p", "n2");
        let suggestion =
            DivergenceDetector::suggest_reconciliation(&sv1, &sv2, &DetectionResult::Forked, None);
        match suggestion {
            ReconciliationSuggestion::ResolveConflict { epoch, .. } => {
                assert_eq!(epoch, 5);
            }
            _ => panic!("Expected ResolveConflict"),
        }
    }

    #[test]
    fn reconciliation_investigate_rollback() {
        let sv1 = make_sv(5, "a", "p", "n1");
        let sv2 = make_sv(6, "b", "WRONG", "n2");
        let proof = RollbackProof {
            local_state: sv1.clone(),
            remote_state: sv2.clone(),
            expected_parent_hash: sv1.state_hash.clone(),
            actual_parent_hash: sv2.parent_state_hash.clone(),
            detection_timestamp: 2000,
            trace_id: "test".to_string(),
            detection_result: DetectionResult::RollbackDetected,
        };
        let suggestion = DivergenceDetector::suggest_reconciliation(
            &sv1,
            &sv2,
            &DetectionResult::RollbackDetected,
            Some(proof),
        );
        assert!(matches!(
            suggestion,
            ReconciliationSuggestion::InvestigateRollback { .. }
        ));
    }

    // ---- RollbackProof serialization ----

    #[test]
    fn rollback_proof_serde_roundtrip() {
        let proof = RollbackProof {
            local_state: make_sv(1, "a", "p", "n1"),
            remote_state: make_sv(2, "b", "WRONG", "n2"),
            expected_parent_hash: "expected".to_string(),
            actual_parent_hash: "actual".to_string(),
            detection_timestamp: 9999,
            trace_id: "trace-001".to_string(),
            detection_result: DetectionResult::RollbackDetected,
        };
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: RollbackProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, parsed);
    }

    #[test]
    fn rollback_proof_contains_required_fields() {
        let proof = RollbackProof {
            local_state: make_sv(10, "ls", "lp", "n1"),
            remote_state: make_sv(11, "rs", "rp", "n2"),
            expected_parent_hash: "exp".to_string(),
            actual_parent_hash: "act".to_string(),
            detection_timestamp: 5000,
            trace_id: "trace-002".to_string(),
            detection_result: DetectionResult::Forked,
        };
        assert!(!proof.local_state.state_hash.is_empty());
        assert!(!proof.remote_state.state_hash.is_empty());
        assert!(!proof.expected_parent_hash.is_empty());
        assert!(!proof.actual_parent_hash.is_empty());
        assert!(proof.detection_timestamp > 0);
        assert!(!proof.trace_id.is_empty());
    }

    // ---- RollbackDetector ----

    #[test]
    fn rollback_detector_accepts_valid_chain() {
        let mut detector = RollbackDetector::new();
        let chain = make_chain(10, "node-a");
        for sv in chain {
            detector.feed(sv).unwrap();
        }
        assert_eq!(detector.proof_count(), 0);
    }

    #[test]
    fn rollback_detector_catches_broken_chain() {
        let mut detector = RollbackDetector::new();
        let chain = make_chain(5, "node-a");
        for sv in &chain[..3] {
            detector.feed(sv.clone()).unwrap();
        }
        // Inject a bad state vector
        let bad = StateVector {
            epoch: 3,
            marker_id: "marker-3".to_string(),
            state_hash: StateVector::compute_state_hash("bad-state"),
            parent_state_hash: StateVector::compute_state_hash("WRONG-PARENT"),
            timestamp: 1003,
            node_id: "node-a".to_string(),
        };
        let err = detector.feed(bad).unwrap_err();
        assert_eq!(err.code(), "RFD_ROLLBACK_DETECTED");
        assert_eq!(detector.proof_count(), 1);
    }

    #[test]
    fn rollback_detector_first_state_always_ok() {
        let mut detector = RollbackDetector::new();
        let sv = make_sv(0, "any", "any-parent", "node");
        detector.feed(sv).unwrap();
        assert!(detector.last_known().is_some());
    }

    #[test]
    fn rollback_detector_multiple_rollbacks() {
        let mut detector = RollbackDetector::new();
        let chain = make_chain(3, "node");
        for sv in &chain {
            let _ = detector.feed(sv.clone());
        }
        // Two bad vectors in sequence
        for i in 3..5 {
            let bad = StateVector {
                epoch: i,
                marker_id: format!("marker-{i}"),
                state_hash: StateVector::compute_state_hash(&format!("bad-{i}")),
                parent_state_hash: StateVector::compute_state_hash(&format!("wrong-{i}")),
                timestamp: 1000 + i,
                node_id: "node".to_string(),
            };
            let _ = detector.feed(bad);
        }
        // Should catch at least the first bad one
        assert!(detector.proof_count() >= 1);
    }

    // ---- MarkerProofVerifier ----

    #[test]
    fn marker_proof_valid() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::PolicyChange, "payload-0", 1000, "trace-0")
            .unwrap();
        let marker_hash = stream.get(0).unwrap().marker_hash.clone();
        let result = MarkerProofVerifier::verify(&stream, &marker_hash, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn marker_proof_invalid_wrong_hash() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::PolicyChange, "payload-0", 1000, "trace-0")
            .unwrap();
        let result = MarkerProofVerifier::verify(&stream, "wrong-marker-id", 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "RFD_MARKER_NOT_FOUND");
    }

    #[test]
    fn marker_proof_invalid_out_of_range() {
        let mut stream = MarkerStream::new();
        stream
            .append(MarkerEventType::PolicyChange, "payload-0", 1000, "trace-0")
            .unwrap();
        let result = MarkerProofVerifier::verify(&stream, "any", 10);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), "RFD_MARKER_NOT_FOUND");
    }

    #[test]
    fn marker_proof_empty_stream() {
        let stream = MarkerStream::new();
        let result = MarkerProofVerifier::verify(&stream, "any", 0);
        assert!(result.is_err());
    }

    #[test]
    fn marker_proof_multi_entry_stream() {
        let mut stream = MarkerStream::new();
        for i in 0..10 {
            stream
                .append(
                    MarkerEventType::PolicyChange,
                    &format!("payload-{i}"),
                    1000 + i,
                    &format!("trace-{i}"),
                )
                .unwrap();
        }
        // Verify each marker
        for i in 0..10 {
            let hash = stream.get(i).unwrap().marker_hash.clone();
            assert!(MarkerProofVerifier::verify(&stream, &hash, i).is_ok());
        }
    }

    // ---- ForkDetectionError ----

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            ForkDetectionError::RfdForkDetected {
                epoch: 0,
                local_hash: "a".into(),
                remote_hash: "b".into(),
            }
            .code(),
            "RFD_FORK_DETECTED"
        );
        assert_eq!(
            ForkDetectionError::RfdRollbackDetected {
                epoch: 0,
                expected_parent: "a".into(),
                actual_parent: "b".into(),
            }
            .code(),
            "RFD_ROLLBACK_DETECTED"
        );
        assert_eq!(
            ForkDetectionError::RfdGapDetected {
                local_epoch: 0,
                remote_epoch: 5,
            }
            .code(),
            "RFD_GAP_DETECTED"
        );
        assert_eq!(
            ForkDetectionError::RfdMarkerNotFound {
                marker_id: "m".into(),
                claimed_epoch: 0,
            }
            .code(),
            "RFD_MARKER_NOT_FOUND"
        );
    }

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<ForkDetectionError> = vec![
            ForkDetectionError::RfdForkDetected {
                epoch: 10,
                local_hash: "lh".into(),
                remote_hash: "rh".into(),
            },
            ForkDetectionError::RfdRollbackDetected {
                epoch: 5,
                expected_parent: "ep".into(),
                actual_parent: "ap".into(),
            },
            ForkDetectionError::RfdGapDetected {
                local_epoch: 1,
                remote_epoch: 10,
            },
            ForkDetectionError::RfdMarkerNotFound {
                marker_id: "m1".into(),
                claimed_epoch: 3,
            },
        ];
        for e in &errors {
            let display = e.to_string();
            assert!(
                display.contains(e.code()),
                "Display for {e:?} should contain code {}",
                e.code()
            );
        }
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = ForkDetectionError::RfdForkDetected {
            epoch: 42,
            local_hash: "abc".into(),
            remote_hash: "def".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: ForkDetectionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, parsed);
    }

    // ---- Event codes ----

    #[test]
    fn event_codes_defined() {
        assert_eq!(
            event_codes::RFD_DIVERGENCE_DETECTED,
            "RFD_DIVERGENCE_DETECTED"
        );
        assert_eq!(
            event_codes::RFD_CONVERGENCE_VERIFIED,
            "RFD_CONVERGENCE_VERIFIED"
        );
        assert_eq!(event_codes::RFD_MARKER_VERIFIED, "RFD_MARKER_VERIFIED");
        assert_eq!(
            event_codes::RFD_RECONCILIATION_SUGGESTED,
            "RFD_RECONCILIATION_SUGGESTED"
        );
    }

    // ---- Invariant tags present in source ----

    #[test]
    fn invariant_tags_defined() {
        // This test validates that invariant tags are present in the source file.
        // They appear as doc comments in this module.
        let source = include_str!("fork_detection.rs");
        assert!(source.contains("INV-RFD-DETECT-FORK"));
        assert!(source.contains("INV-RFD-DETECT-ROLLBACK"));
        assert!(source.contains("INV-RFD-HALT-ON-DIVERGENCE"));
        assert!(source.contains("INV-RFD-PROOF-SERIALIZABLE"));
    }

    // ---- DivergenceLogEvent ----

    #[test]
    fn log_event_serde_roundtrip() {
        let event = DivergenceLogEvent {
            event_code: "RFD_DIVERGENCE_DETECTED".to_string(),
            severity: "CRITICAL".to_string(),
            detection_result: DetectionResult::Forked,
            local_epoch: 10,
            remote_epoch: 10,
            local_state_hash: "lh".to_string(),
            remote_state_hash: "rh".to_string(),
            trace_id: "trace-1".to_string(),
            node_id: "node-1".to_string(),
            epoch_id: 10,
            detection_latency_ms: Some(5),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: DivergenceLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn log_event_contains_required_fields() {
        let event = DivergenceLogEvent {
            event_code: "RFD_CONVERGENCE_VERIFIED".to_string(),
            severity: "INFO".to_string(),
            detection_result: DetectionResult::Converged,
            local_epoch: 1,
            remote_epoch: 1,
            local_state_hash: "h".to_string(),
            remote_state_hash: "h".to_string(),
            trace_id: "t1".to_string(),
            node_id: "n1".to_string(),
            epoch_id: 1,
            detection_latency_ms: None,
        };
        assert!(!event.event_code.is_empty());
        assert!(!event.severity.is_empty());
        assert!(!event.trace_id.is_empty());
        assert!(!event.node_id.is_empty());
    }

    // ---- Integration: 100-epoch simulation with fork injection ----

    #[test]
    fn simulation_100_epochs_fork_at_50() {
        let mut detector = DivergenceDetector::new();

        // Build two chains that share epochs 0-49 and diverge at 50
        let mut local_chain = Vec::new();
        let mut remote_chain = Vec::new();
        let mut prev_hash = StateVector::compute_state_hash("genesis");

        for i in 0..100 {
            let seed = format!("shared-state-{i}");
            let hash = StateVector::compute_state_hash(&seed);
            let sv = StateVector {
                epoch: i,
                marker_id: format!("marker-{i}"),
                state_hash: hash.clone(),
                parent_state_hash: prev_hash.clone(),
                timestamp: 1000 + i,
                node_id: "local".to_string(),
            };
            local_chain.push(sv);
            if i < 50 {
                remote_chain.push(StateVector {
                    node_id: "remote".to_string(),
                    ..local_chain.last().unwrap().clone()
                });
            }
            prev_hash = hash;
        }

        // Build divergent remote chain from epoch 50 onwards
        let mut remote_prev_hash = remote_chain.last().unwrap().state_hash.clone();
        for i in 50..100 {
            let seed = format!("FORKED-remote-state-{i}");
            let hash = StateVector::compute_state_hash(&seed);
            remote_chain.push(StateVector {
                epoch: i,
                marker_id: format!("marker-{i}"),
                state_hash: hash.clone(),
                parent_state_hash: remote_prev_hash.clone(),
                timestamp: 1000 + i,
                node_id: "remote".to_string(),
            });
            remote_prev_hash = hash;
        }

        // Epochs 0-49 should be converged
        for i in 0..50 {
            let (result, _) = detector.compare(&local_chain[i as usize], &remote_chain[i as usize]);
            assert_eq!(
                result,
                DetectionResult::Converged,
                "epoch {i} should converge"
            );
            detector.operator_reset(); // reset halt between checks for this test
        }

        // Epoch 50 should detect fork
        let (result, proof) = detector.compare(&local_chain[50], &remote_chain[50]);
        assert_eq!(result, DetectionResult::Forked);
        assert!(proof.is_some());
        assert!(detector.is_halted());

        // Epoch 51 also forked (if we reset halt)
        detector.operator_reset();
        let (result_51, _) = detector.compare(&local_chain[51], &remote_chain[51]);
        assert_eq!(result_51, DetectionResult::Forked);
    }

    #[test]
    fn simulation_rollback_at_epoch_50() {
        let mut detector = DivergenceDetector::new();

        // Build valid chain up to epoch 49
        let chain = make_chain(50, "local");

        // Create a state vector at epoch 50 with WRONG parent hash (rollback)
        let sv_49 = &chain[49];
        let sv_50_bad = StateVector {
            epoch: 50,
            marker_id: "marker-50".to_string(),
            state_hash: StateVector::compute_state_hash("state-50-rolled-back"),
            parent_state_hash: StateVector::compute_state_hash("TAMPERED-PARENT"),
            timestamp: 1050,
            node_id: "remote".to_string(),
        };

        let (result, proof) = detector.compare(sv_49, &sv_50_bad);
        assert_eq!(result, DetectionResult::RollbackDetected);
        assert!(proof.is_some());
        let p = proof.unwrap();
        assert_eq!(p.expected_parent_hash, sv_49.state_hash);
        assert_ne!(p.actual_parent_hash, sv_49.state_hash);
    }

    // ---- ReconciliationSuggestion serde ----

    #[test]
    fn reconciliation_suggestion_serde_roundtrip() {
        let suggestions = vec![
            ReconciliationSuggestion::NoAction,
            ReconciliationSuggestion::FillGap {
                missing_start: 5,
                missing_end: 10,
            },
            ReconciliationSuggestion::ResolveConflict {
                epoch: 7,
                local_hash: "lh".to_string(),
                remote_hash: "rh".to_string(),
            },
        ];
        for s in &suggestions {
            let json = serde_json::to_string(s).unwrap();
            let parsed: ReconciliationSuggestion = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, parsed);
        }
    }

    // ---- Default impls ----

    #[test]
    fn divergence_detector_default() {
        let d = DivergenceDetector::default();
        assert!(!d.is_halted());
        assert!(d.last_result().is_none());
        assert_eq!(d.history_len(), 0);
    }

    #[test]
    fn rollback_detector_default() {
        let d = RollbackDetector::default();
        assert!(d.last_known().is_none());
        assert_eq!(d.proof_count(), 0);
    }
}
