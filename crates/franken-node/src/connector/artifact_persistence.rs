//! bd-12h8: Persist required artifacts with deterministic replay hooks.
//!
//! Persists invoke/response/receipt/approval/revocation/audit artifacts.
//! Every persisted artifact is replayable from its stored state via replay hooks.

use std::collections::HashMap;

use crate::control_plane::control_epoch::{
    ControlEpoch, EpochArtifactEvent, EpochRejection, ValidityWindowPolicy, check_artifact_epoch,
};

/// Required artifact types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactType {
    Invoke,
    Response,
    Receipt,
    Approval,
    Revocation,
    Audit,
}

impl ArtifactType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Invoke => "invoke",
            Self::Response => "response",
            Self::Receipt => "receipt",
            Self::Approval => "approval",
            Self::Revocation => "revocation",
            Self::Audit => "audit",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "invoke" => Some(Self::Invoke),
            "response" => Some(Self::Response),
            "receipt" => Some(Self::Receipt),
            "approval" => Some(Self::Approval),
            "revocation" => Some(Self::Revocation),
            "audit" => Some(Self::Audit),
            _ => None,
        }
    }

    pub fn all() -> &'static [ArtifactType] {
        &[
            Self::Invoke,
            Self::Response,
            Self::Receipt,
            Self::Approval,
            Self::Revocation,
            Self::Audit,
        ]
    }
}

/// A persisted artifact.
#[derive(Debug, Clone)]
pub struct PersistedArtifact {
    pub artifact_id: String,
    pub artifact_type: ArtifactType,
    pub artifact_epoch: ControlEpoch,
    pub sequence_number: u64,
    pub payload_hash: String,
    pub stored_at: u64,
    pub trace_id: String,
}

/// Replay hook descriptor.
#[derive(Debug, Clone)]
pub struct ReplayHook {
    pub artifact_id: String,
    pub artifact_type: ArtifactType,
    pub sequence_number: u64,
    pub payload_hash: String,
    pub replay_order: u64,
}

/// Result of a persist operation.
#[derive(Debug, Clone)]
pub struct PersistenceResult {
    pub artifact_id: String,
    pub persisted: bool,
    pub artifact_epoch: ControlEpoch,
    pub sequence_number: u64,
    pub epoch_event: EpochArtifactEvent,
    pub trace_id: String,
}

/// Errors from persistence operations.
#[derive(Debug, Clone, PartialEq)]
pub enum PersistenceError {
    UnknownType {
        type_label: String,
    },
    Duplicate {
        artifact_id: String,
    },
    SequenceGap {
        expected: u64,
        got: u64,
    },
    ReplayMismatch {
        artifact_id: String,
        expected_hash: String,
        got_hash: String,
    },
    EpochRejected {
        rejection: EpochRejection,
    },
    InvalidArtifact {
        reason: String,
    },
}

impl PersistenceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownType { .. } => "PRA_UNKNOWN_TYPE",
            Self::Duplicate { .. } => "PRA_DUPLICATE",
            Self::SequenceGap { .. } => "PRA_SEQUENCE_GAP",
            Self::ReplayMismatch { .. } => "PRA_REPLAY_MISMATCH",
            Self::EpochRejected { .. } => "PRA_EPOCH_REJECTED",
            Self::InvalidArtifact { .. } => "PRA_INVALID_ARTIFACT",
        }
    }
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownType { type_label } => write!(f, "PRA_UNKNOWN_TYPE: {type_label}"),
            Self::Duplicate { artifact_id } => write!(f, "PRA_DUPLICATE: {artifact_id}"),
            Self::SequenceGap { expected, got } => {
                write!(f, "PRA_SEQUENCE_GAP: expected={expected} got={got}")
            }
            Self::ReplayMismatch {
                artifact_id,
                expected_hash,
                got_hash,
            } => write!(
                f,
                "PRA_REPLAY_MISMATCH: {artifact_id} expected={expected_hash} got={got_hash}"
            ),
            Self::EpochRejected { rejection } => write!(
                f,
                "PRA_EPOCH_REJECTED: artifact={} artifact_epoch={} current_epoch={} reason={}",
                rejection.artifact_id,
                rejection.artifact_epoch.value(),
                rejection.current_epoch.value(),
                rejection.code(),
            ),
            Self::InvalidArtifact { reason } => write!(f, "PRA_INVALID_ARTIFACT: {reason}"),
        }
    }
}

/// Artifact persistence store with replay hooks.
#[derive(Debug)]
pub struct ArtifactStore {
    artifacts: HashMap<String, PersistedArtifact>,
    /// Ordered list per type for replay
    sequences: HashMap<ArtifactType, Vec<String>>,
    next_sequence: HashMap<ArtifactType, u64>,
    validity_policy: ValidityWindowPolicy,
}

impl Default for ArtifactStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactStore {
    pub fn new() -> Self {
        Self::with_policy(ValidityWindowPolicy::default_for(ControlEpoch::GENESIS))
    }

    pub fn with_policy(validity_policy: ValidityWindowPolicy) -> Self {
        let mut next_sequence = HashMap::new();
        for t in ArtifactType::all() {
            next_sequence.insert(*t, 0);
        }
        Self {
            artifacts: HashMap::new(),
            sequences: HashMap::new(),
            next_sequence,
            validity_policy,
        }
    }

    /// Hot-reload the validity-window policy for subsequent ingests.
    pub fn set_validity_policy(&mut self, policy: ValidityWindowPolicy) {
        self.validity_policy = policy;
    }

    pub fn validity_policy(&self) -> ValidityWindowPolicy {
        self.validity_policy
    }

    /// Persist an artifact.
    ///
    /// INV-PRA-COMPLETE: all 6 types supported.
    /// INV-PRA-DURABLE: stored in memory (production: durable storage).
    /// INV-PRA-ORDERED: sequence numbers monotonically increasing per type.
    pub fn persist(
        &mut self,
        artifact_id: &str,
        artifact_type: ArtifactType,
        artifact_epoch: ControlEpoch,
        payload_hash: &str,
        trace_id: &str,
        now: u64,
    ) -> Result<PersistenceResult, PersistenceError> {
        check_artifact_epoch(artifact_id, artifact_epoch, &self.validity_policy, trace_id)
            .map_err(|rejection| PersistenceError::EpochRejected { rejection })?;

        if artifact_id.is_empty() {
            return Err(PersistenceError::InvalidArtifact {
                reason: "artifact_id must not be empty".into(),
            });
        }
        if payload_hash.is_empty() {
            return Err(PersistenceError::InvalidArtifact {
                reason: "payload_hash must not be empty".into(),
            });
        }

        if self.artifacts.contains_key(artifact_id) {
            return Err(PersistenceError::Duplicate {
                artifact_id: artifact_id.to_string(),
            });
        }

        let seq = *self.next_sequence.get(&artifact_type).unwrap_or(&0);

        let artifact = PersistedArtifact {
            artifact_id: artifact_id.to_string(),
            artifact_type,
            artifact_epoch,
            sequence_number: seq,
            payload_hash: payload_hash.to_string(),
            stored_at: now,
            trace_id: trace_id.to_string(),
        };

        self.artifacts.insert(artifact_id.to_string(), artifact);
        self.sequences
            .entry(artifact_type)
            .or_default()
            .push(artifact_id.to_string());
        self.next_sequence.insert(artifact_type, seq + 1);

        Ok(PersistenceResult {
            artifact_id: artifact_id.to_string(),
            persisted: true,
            artifact_epoch,
            sequence_number: seq,
            epoch_event: EpochArtifactEvent::accepted(
                artifact_id,
                artifact_epoch,
                self.validity_policy.current_epoch(),
                trace_id,
            ),
            trace_id: trace_id.to_string(),
        })
    }

    /// Generate replay hooks for all artifacts of a given type, in order.
    ///
    /// INV-PRA-REPLAY: deterministic replay from stored state.
    /// INV-PRA-ORDERED: returned in insertion order.
    pub fn replay_hooks(&self, artifact_type: ArtifactType) -> Vec<ReplayHook> {
        let ids = match self.sequences.get(&artifact_type) {
            Some(ids) => ids,
            None => return Vec::new(),
        };

        ids.iter()
            .enumerate()
            .filter_map(|(i, id)| {
                self.artifacts.get(id).map(|a| ReplayHook {
                    artifact_id: a.artifact_id.clone(),
                    artifact_type: a.artifact_type,
                    sequence_number: a.sequence_number,
                    payload_hash: a.payload_hash.clone(),
                    replay_order: i as u64,
                })
            })
            .collect()
    }

    /// Verify a replay matches stored hashes.
    pub fn verify_replay(
        &self,
        artifact_id: &str,
        payload_hash: &str,
    ) -> Result<(), PersistenceError> {
        let artifact =
            self.artifacts
                .get(artifact_id)
                .ok_or_else(|| PersistenceError::InvalidArtifact {
                    reason: format!("artifact not found: {artifact_id}"),
                })?;

        if artifact.payload_hash != payload_hash {
            return Err(PersistenceError::ReplayMismatch {
                artifact_id: artifact_id.to_string(),
                expected_hash: artifact.payload_hash.clone(),
                got_hash: payload_hash.to_string(),
            });
        }

        Ok(())
    }

    /// Get an artifact by ID.
    pub fn get(&self, artifact_id: &str) -> Option<&PersistedArtifact> {
        self.artifacts.get(artifact_id)
    }

    /// Count artifacts by type.
    pub fn count_by_type(&self, artifact_type: ArtifactType) -> usize {
        self.sequences.get(&artifact_type).map_or(0, |v| v.len())
    }

    /// Total artifact count.
    pub fn total_count(&self) -> usize {
        self.artifacts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_epoch() -> ControlEpoch {
        ControlEpoch::new(0)
    }

    #[test]
    fn persist_all_six_types() {
        let mut store = ArtifactStore::new();
        for (i, t) in ArtifactType::all().iter().enumerate() {
            let result = store
                .persist(&format!("a{i}"), *t, current_epoch(), "hash", "tr", 1000)
                .unwrap();
            assert!(result.persisted);
        }
        assert_eq!(store.total_count(), 6);
    }

    #[test]
    fn reject_duplicate() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "a1",
                ArtifactType::Invoke,
                current_epoch(),
                "hash",
                "tr",
                1000,
            )
            .unwrap();
        let err = store
            .persist(
                "a1",
                ArtifactType::Invoke,
                current_epoch(),
                "hash",
                "tr",
                1001,
            )
            .unwrap_err();
        assert_eq!(err.code(), "PRA_DUPLICATE");
    }

    #[test]
    fn sequence_numbers_monotonic() {
        let mut store = ArtifactStore::new();
        let r1 = store
            .persist(
                "a1",
                ArtifactType::Invoke,
                current_epoch(),
                "h1",
                "tr",
                1000,
            )
            .unwrap();
        let r2 = store
            .persist(
                "a2",
                ArtifactType::Invoke,
                current_epoch(),
                "h2",
                "tr",
                1001,
            )
            .unwrap();
        assert_eq!(r1.sequence_number, 0);
        assert_eq!(r2.sequence_number, 1);
    }

    #[test]
    fn sequence_per_type() {
        let mut store = ArtifactStore::new();
        let r1 = store
            .persist(
                "a1",
                ArtifactType::Invoke,
                current_epoch(),
                "h1",
                "tr",
                1000,
            )
            .unwrap();
        let r2 = store
            .persist(
                "a2",
                ArtifactType::Response,
                current_epoch(),
                "h2",
                "tr",
                1001,
            )
            .unwrap();
        assert_eq!(r1.sequence_number, 0);
        assert_eq!(r2.sequence_number, 0); // different type, starts at 0
    }

    #[test]
    fn replay_hooks_ordered() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "a1",
                ArtifactType::Invoke,
                current_epoch(),
                "h1",
                "tr",
                1000,
            )
            .unwrap();
        store
            .persist(
                "a2",
                ArtifactType::Invoke,
                current_epoch(),
                "h2",
                "tr",
                1001,
            )
            .unwrap();
        store
            .persist(
                "a3",
                ArtifactType::Invoke,
                current_epoch(),
                "h3",
                "tr",
                1002,
            )
            .unwrap();

        let hooks = store.replay_hooks(ArtifactType::Invoke);
        assert_eq!(hooks.len(), 3);
        assert_eq!(hooks[0].artifact_id, "a1");
        assert_eq!(hooks[0].replay_order, 0);
        assert_eq!(hooks[1].artifact_id, "a2");
        assert_eq!(hooks[1].replay_order, 1);
        assert_eq!(hooks[2].artifact_id, "a3");
        assert_eq!(hooks[2].replay_order, 2);
    }

    #[test]
    fn replay_hooks_empty_type() {
        let store = ArtifactStore::new();
        let hooks = store.replay_hooks(ArtifactType::Audit);
        assert!(hooks.is_empty());
    }

    #[test]
    fn verify_replay_match() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "a1",
                ArtifactType::Invoke,
                current_epoch(),
                "hash123",
                "tr",
                1000,
            )
            .unwrap();
        assert!(store.verify_replay("a1", "hash123").is_ok());
    }

    #[test]
    fn verify_replay_mismatch() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "a1",
                ArtifactType::Invoke,
                current_epoch(),
                "hash123",
                "tr",
                1000,
            )
            .unwrap();
        let err = store.verify_replay("a1", "wrong_hash").unwrap_err();
        assert_eq!(err.code(), "PRA_REPLAY_MISMATCH");
    }

    #[test]
    fn get_artifact() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "a1",
                ArtifactType::Receipt,
                current_epoch(),
                "hash",
                "tr",
                1000,
            )
            .unwrap();
        let a = store.get("a1").unwrap();
        assert_eq!(a.artifact_type, ArtifactType::Receipt);
        assert_eq!(a.payload_hash, "hash");
        assert_eq!(a.artifact_epoch, current_epoch());
    }

    #[test]
    fn count_by_type() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "a1",
                ArtifactType::Invoke,
                current_epoch(),
                "h1",
                "tr",
                1000,
            )
            .unwrap();
        store
            .persist(
                "a2",
                ArtifactType::Invoke,
                current_epoch(),
                "h2",
                "tr",
                1001,
            )
            .unwrap();
        store
            .persist(
                "a3",
                ArtifactType::Response,
                current_epoch(),
                "h3",
                "tr",
                1002,
            )
            .unwrap();
        assert_eq!(store.count_by_type(ArtifactType::Invoke), 2);
        assert_eq!(store.count_by_type(ArtifactType::Response), 1);
        assert_eq!(store.count_by_type(ArtifactType::Audit), 0);
    }

    #[test]
    fn invalid_empty_id() {
        let mut store = ArtifactStore::new();
        let err = store
            .persist(
                "",
                ArtifactType::Invoke,
                current_epoch(),
                "hash",
                "tr",
                1000,
            )
            .unwrap_err();
        assert_eq!(err.code(), "PRA_INVALID_ARTIFACT");
    }

    #[test]
    fn invalid_empty_hash() {
        let mut store = ArtifactStore::new();
        let err = store
            .persist("a1", ArtifactType::Invoke, current_epoch(), "", "tr", 1000)
            .unwrap_err();
        assert_eq!(err.code(), "PRA_INVALID_ARTIFACT");
    }

    #[test]
    fn reject_future_epoch_before_persisting() {
        let mut store = ArtifactStore::new();
        store.set_validity_policy(ValidityWindowPolicy::new(ControlEpoch::new(10), 1));

        let err = store
            .persist(
                "future-artifact",
                ArtifactType::Invoke,
                ControlEpoch::new(11),
                "hash",
                "trace-future",
                1000,
            )
            .expect_err("future epoch must be rejected");

        match err {
            PersistenceError::EpochRejected { rejection } => {
                assert_eq!(rejection.code(), "EPOCH_REJECT_FUTURE");
                let event = rejection.to_rejected_event();
                assert_eq!(event.event_code, "EPOCH_ARTIFACT_REJECTED");
                assert_eq!(event.artifact_id, "future-artifact");
                assert_eq!(event.trace_id, "trace-future");
            }
            other => panic!("expected epoch rejection, got {other:?}"),
        }
    }

    #[test]
    fn hot_reload_policy_changes_admission_window() {
        let mut store = ArtifactStore::new();
        store.set_validity_policy(ValidityWindowPolicy::new(ControlEpoch::new(5), 1));

        let first = store.persist(
            "artifact-old",
            ArtifactType::Invoke,
            ControlEpoch::new(3),
            "hash1",
            "trace-a",
            1000,
        );
        assert!(matches!(first, Err(PersistenceError::EpochRejected { .. })));

        store.set_validity_policy(ValidityWindowPolicy::new(ControlEpoch::new(8), 5));
        let second = store.persist(
            "artifact-old",
            ArtifactType::Invoke,
            ControlEpoch::new(3),
            "hash2",
            "trace-b",
            1001,
        );
        assert!(second.is_ok());
    }

    #[test]
    fn artifact_type_labels() {
        for t in ArtifactType::all() {
            let label = t.label();
            assert_eq!(ArtifactType::from_label(label), Some(*t));
        }
        assert_eq!(ArtifactType::from_label("unknown"), None);
    }

    #[test]
    fn artifact_type_from_label_unknown() {
        let err_label = "PRA_UNKNOWN_TYPE";
        assert_eq!(
            PersistenceError::UnknownType {
                type_label: "x".into()
            }
            .code(),
            err_label
        );
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            PersistenceError::UnknownType {
                type_label: "".into()
            }
            .code(),
            "PRA_UNKNOWN_TYPE"
        );
        assert_eq!(
            PersistenceError::Duplicate {
                artifact_id: "".into()
            }
            .code(),
            "PRA_DUPLICATE"
        );
        assert_eq!(
            PersistenceError::SequenceGap {
                expected: 0,
                got: 0
            }
            .code(),
            "PRA_SEQUENCE_GAP"
        );
        assert_eq!(
            PersistenceError::ReplayMismatch {
                artifact_id: "".into(),
                expected_hash: "".into(),
                got_hash: "".into()
            }
            .code(),
            "PRA_REPLAY_MISMATCH"
        );
        assert_eq!(
            PersistenceError::EpochRejected {
                rejection: EpochRejection {
                    artifact_id: "".into(),
                    artifact_epoch: ControlEpoch::new(0),
                    current_epoch: ControlEpoch::new(0),
                    rejection_reason:
                        crate::control_plane::control_epoch::EpochRejectionReason::FutureEpoch,
                    trace_id: "".into(),
                }
            }
            .code(),
            "PRA_EPOCH_REJECTED"
        );
        assert_eq!(
            PersistenceError::InvalidArtifact { reason: "".into() }.code(),
            "PRA_INVALID_ARTIFACT"
        );
    }

    #[test]
    fn error_display() {
        let e = PersistenceError::Duplicate {
            artifact_id: "a1".into(),
        };
        assert!(e.to_string().contains("PRA_DUPLICATE"));
    }

    #[test]
    fn deterministic_replay() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "a1",
                ArtifactType::Invoke,
                current_epoch(),
                "h1",
                "tr",
                1000,
            )
            .unwrap();
        store
            .persist(
                "a2",
                ArtifactType::Invoke,
                current_epoch(),
                "h2",
                "tr",
                1001,
            )
            .unwrap();
        let h1 = store.replay_hooks(ArtifactType::Invoke);
        let h2 = store.replay_hooks(ArtifactType::Invoke);
        assert_eq!(h1.len(), h2.len());
        for (a, b) in h1.iter().zip(h2.iter()) {
            assert_eq!(a.artifact_id, b.artifact_id);
            assert_eq!(a.payload_hash, b.payload_hash);
            assert_eq!(a.replay_order, b.replay_order);
        }
    }
}
