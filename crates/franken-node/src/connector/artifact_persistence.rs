//! bd-12h8: Persist required artifacts with deterministic replay hooks.
//!
//! Persists invoke/response/receipt/approval/revocation/audit artifacts.
//! Every persisted artifact is replayable from its stored state via replay hooks.

use std::collections::BTreeMap;

use crate::control_plane::control_epoch::{
    ControlEpoch, EpochArtifactEvent, EpochRejection, ValidityWindowPolicy, check_artifact_epoch,
};
use crate::security::constant_time;

const RESERVED_ARTIFACT_ID: &str = "<unknown>";

fn invalid_artifact_id_reason(artifact_id: &str) -> Option<String> {
    let trimmed = artifact_id.trim();
    if trimmed.is_empty() {
        return Some("artifact_id must not be empty".to_string());
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("artifact_id is reserved: {:?}", artifact_id));
    }
    if trimmed != artifact_id {
        return Some("artifact_id contains leading or trailing whitespace".to_string());
    }
    if artifact_id.contains('\0') {
        return Some("artifact_id must not contain null bytes".to_string());
    }
    None
}

/// Required artifact types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

use crate::capacity_defaults::aliases::MAX_TOTAL_ARTIFACTS;
use crate::capacity_defaults::base;

/// Maximum sequence length per artifact type to prevent unbounded growth.
const MAX_SEQUENCE_PER_TYPE: usize = base::STANDARD;

/// Push item to vector with bounded capacity to prevent memory exhaustion.
/// When capacity is exceeded, removes oldest entries to maintain the limit.
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

/// Artifact persistence store with replay hooks.
#[derive(Debug)]
pub struct ArtifactStore {
    artifacts: BTreeMap<String, PersistedArtifact>,
    /// Ordered list per type for replay
    sequences: BTreeMap<ArtifactType, Vec<String>>,
    next_sequence: BTreeMap<ArtifactType, u64>,
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
        let mut next_sequence = BTreeMap::new();
        for t in ArtifactType::all() {
            next_sequence.insert(*t, 0);
        }
        Self {
            artifacts: BTreeMap::new(),
            sequences: BTreeMap::new(),
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

        if let Some(reason) = invalid_artifact_id_reason(artifact_id) {
            return Err(PersistenceError::InvalidArtifact { reason });
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
        let seq_list = self.sequences.entry(artifact_type).or_default();
        push_bounded(seq_list, artifact_id.to_string(), MAX_SEQUENCE_PER_TYPE);
        // Evict oldest artifacts when total exceeds capacity
        if self.artifacts.len() > MAX_TOTAL_ARTIFACTS
            && let Some((_, evict_list)) = self.sequences.iter_mut().max_by_key(|(_, v)| v.len())
            && let Some(evicted_id) = evict_list.first().cloned()
        {
            evict_list.remove(0);
            self.artifacts.remove(&evicted_id);
        }
        self.next_sequence
            .insert(artifact_type, seq.saturating_add(1));

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

        if !constant_time::ct_eq(&artifact.payload_hash, payload_hash) {
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
    fn invalid_reserved_id() {
        let mut store = ArtifactStore::new();
        let err = store
            .persist(
                RESERVED_ARTIFACT_ID,
                ArtifactType::Invoke,
                current_epoch(),
                "hash",
                "tr",
                1000,
            )
            .unwrap_err();
        assert_eq!(err.code(), "PRA_INVALID_ARTIFACT");
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn invalid_whitespace_id() {
        let mut store = ArtifactStore::new();
        let err = store
            .persist(
                " art-1 ",
                ArtifactType::Invoke,
                current_epoch(),
                "hash",
                "tr",
                1000,
            )
            .unwrap_err();
        assert_eq!(err.code(), "PRA_INVALID_ARTIFACT");
        assert!(err.to_string().contains("leading or trailing whitespace"));
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
            other => unreachable!("expected epoch rejection, got {other:?}"),
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

    #[test]
    fn invalid_whitespace_id_after_existing_persist_preserves_store() {
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

        let err = store
            .persist(
                "\nart-2",
                ArtifactType::Invoke,
                current_epoch(),
                "h2",
                "tr",
                1001,
            )
            .unwrap_err();

        assert_eq!(err.code(), "PRA_INVALID_ARTIFACT");
        assert_eq!(store.total_count(), 1);
        assert_eq!(store.count_by_type(ArtifactType::Invoke), 1);
        assert!(store.get("\nart-2").is_none());
        assert_eq!(store.replay_hooks(ArtifactType::Invoke).len(), 1);
    }

    #[test]
    fn empty_hash_after_existing_persist_does_not_consume_sequence() {
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

        let err = store
            .persist("a2", ArtifactType::Invoke, current_epoch(), "", "tr", 1001)
            .unwrap_err();
        let next = store
            .persist(
                "a3",
                ArtifactType::Invoke,
                current_epoch(),
                "h3",
                "tr",
                1002,
            )
            .unwrap();

        assert_eq!(err.code(), "PRA_INVALID_ARTIFACT");
        assert_eq!(next.sequence_number, 1);
        assert!(store.get("a2").is_none());
        assert_eq!(store.count_by_type(ArtifactType::Invoke), 2);
    }

    #[test]
    fn duplicate_persist_does_not_overwrite_original_payload_or_time() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "a1",
                ArtifactType::Receipt,
                current_epoch(),
                "original-hash",
                "tr-original",
                1000,
            )
            .unwrap();

        let err = store
            .persist(
                "a1",
                ArtifactType::Receipt,
                current_epoch(),
                "replacement-hash",
                "tr-replacement",
                2000,
            )
            .unwrap_err();
        let stored = store.get("a1").unwrap();

        assert_eq!(err.code(), "PRA_DUPLICATE");
        assert!(constant_time::ct_eq(&stored.payload_hash, "original-hash"));
        assert_eq!(stored.trace_id, "tr-original");
        assert_eq!(stored.stored_at, 1000);
        assert!(store.verify_replay("a1", "replacement-hash").is_err());
    }

    #[test]
    fn duplicate_persist_does_not_consume_sequence_number() {
        let mut store = ArtifactStore::new();
        store
            .persist("a1", ArtifactType::Audit, current_epoch(), "h1", "tr", 1000)
            .unwrap();
        let duplicate = store.persist("a1", ArtifactType::Audit, current_epoch(), "h2", "tr", 1001);

        let next = store
            .persist("a2", ArtifactType::Audit, current_epoch(), "h3", "tr", 1002)
            .unwrap();

        assert_eq!(duplicate.unwrap_err().code(), "PRA_DUPLICATE");
        assert_eq!(next.sequence_number, 1);
        assert_eq!(store.replay_hooks(ArtifactType::Audit).len(), 2);
    }

    #[test]
    fn epoch_rejection_does_not_store_invalid_artifact_or_consume_sequence() {
        let mut store = ArtifactStore::new();
        store.set_validity_policy(ValidityWindowPolicy::new(ControlEpoch::new(5), 1));

        let err = store
            .persist(
                "too-old",
                ArtifactType::Response,
                ControlEpoch::new(3),
                "h1",
                "tr-old",
                1000,
            )
            .unwrap_err();
        let accepted = store
            .persist(
                "current",
                ArtifactType::Response,
                ControlEpoch::new(5),
                "h2",
                "tr-current",
                1001,
            )
            .unwrap();

        assert!(matches!(err, PersistenceError::EpochRejected { .. }));
        assert!(store.get("too-old").is_none());
        assert_eq!(accepted.sequence_number, 0);
        assert_eq!(store.count_by_type(ArtifactType::Response), 1);
    }

    #[test]
    fn future_epoch_with_invalid_id_reports_epoch_rejection_first_and_no_mutation() {
        let mut store = ArtifactStore::new();
        store.set_validity_policy(ValidityWindowPolicy::new(ControlEpoch::new(1), 0));

        let err = store
            .persist(
                " bad-id ",
                ArtifactType::Approval,
                ControlEpoch::new(2),
                "h1",
                "tr-future",
                1000,
            )
            .unwrap_err();

        assert!(matches!(err, PersistenceError::EpochRejected { .. }));
        assert_eq!(store.total_count(), 0);
        assert!(store.replay_hooks(ArtifactType::Approval).is_empty());
    }

    #[test]
    fn verify_replay_unknown_artifact_is_invalid_artifact_not_mismatch() {
        let store = ArtifactStore::new();

        let err = store.verify_replay("missing", "payload").unwrap_err();

        assert_eq!(err.code(), "PRA_INVALID_ARTIFACT");
        assert!(err.to_string().contains("artifact not found"));
        assert!(!matches!(err, PersistenceError::ReplayMismatch { .. }));
    }

    #[test]
    fn artifact_type_from_label_rejects_case_and_whitespace_variants() {
        assert_eq!(ArtifactType::from_label("Invoke"), None);
        assert_eq!(ArtifactType::from_label(" invoke"), None);
        assert_eq!(ArtifactType::from_label("invoke "), None);
        assert_eq!(ArtifactType::from_label("receipt\n"), None);
        assert_eq!(ArtifactType::from_label("revocation/audit"), None);
    }

    #[test]
    fn reserved_id_with_outer_whitespace_is_rejected_as_reserved_without_mutation() {
        let mut store = ArtifactStore::new();

        let err = store
            .persist(
                " <unknown> ",
                ArtifactType::Audit,
                current_epoch(),
                "h1",
                "tr-reserved",
                1000,
            )
            .unwrap_err();

        assert_eq!(err.code(), "PRA_INVALID_ARTIFACT");
        assert!(err.to_string().contains("reserved"));
        assert_eq!(store.total_count(), 0);
        assert!(store.replay_hooks(ArtifactType::Audit).is_empty());
    }

    #[test]
    fn all_whitespace_id_is_empty_after_trim_and_does_not_consume_sequence() {
        let mut store = ArtifactStore::new();

        let err = store
            .persist(
                "\t\n",
                ArtifactType::Approval,
                current_epoch(),
                "h1",
                "tr-empty-id",
                1000,
            )
            .unwrap_err();
        let accepted = store
            .persist(
                "approval-1",
                ArtifactType::Approval,
                current_epoch(),
                "h2",
                "tr-ok",
                1001,
            )
            .unwrap();

        assert_eq!(err.code(), "PRA_INVALID_ARTIFACT");
        assert!(err.to_string().contains("must not be empty"));
        assert_eq!(accepted.sequence_number, 0);
        assert_eq!(store.count_by_type(ArtifactType::Approval), 1);
    }

    #[test]
    fn verify_replay_mismatch_does_not_remove_artifact_or_hooks() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "receipt-1",
                ArtifactType::Receipt,
                current_epoch(),
                "expected-digest",
                "tr-receipt",
                1000,
            )
            .unwrap();

        let err = store
            .verify_replay("receipt-1", "unexpected-digest")
            .unwrap_err();
        let hooks = store.replay_hooks(ArtifactType::Receipt);
        let stored = store.get("receipt-1").unwrap();

        assert_eq!(err.code(), "PRA_REPLAY_MISMATCH");
        assert_eq!(store.total_count(), 1);
        assert!(constant_time::ct_eq(
            &stored.payload_hash,
            "expected-digest"
        ));
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].artifact_id, "receipt-1");
        assert_eq!(hooks[0].replay_order, 0);
    }

    #[test]
    fn replay_hooks_skip_dangling_sequence_id_without_panicking() {
        let mut store = ArtifactStore::new();
        store
            .sequences
            .entry(ArtifactType::Audit)
            .or_default()
            .push("missing-artifact".to_string());

        let hooks = store.replay_hooks(ArtifactType::Audit);

        assert!(hooks.is_empty());
        assert_eq!(store.total_count(), 0);
    }

    #[test]
    fn replay_hooks_preserve_order_gaps_when_middle_artifact_is_missing() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "audit-1",
                ArtifactType::Audit,
                current_epoch(),
                "h1",
                "tr",
                1000,
            )
            .unwrap();
        store
            .persist(
                "audit-2",
                ArtifactType::Audit,
                current_epoch(),
                "h2",
                "tr",
                1001,
            )
            .unwrap();
        store
            .persist(
                "audit-3",
                ArtifactType::Audit,
                current_epoch(),
                "h3",
                "tr",
                1002,
            )
            .unwrap();

        store.artifacts.remove("audit-2");
        let hooks = store.replay_hooks(ArtifactType::Audit);

        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0].artifact_id, "audit-1");
        assert_eq!(hooks[0].replay_order, 0);
        assert_eq!(hooks[1].artifact_id, "audit-3");
        assert_eq!(hooks[1].replay_order, 2);
    }

    #[test]
    fn epoch_rejection_precedes_empty_hash_without_mutating_store() {
        let mut store = ArtifactStore::new();
        store.set_validity_policy(ValidityWindowPolicy::new(ControlEpoch::new(5), 1));

        let err = store
            .persist(
                "old-empty",
                ArtifactType::Response,
                ControlEpoch::new(3),
                "",
                "tr-old",
                1000,
            )
            .unwrap_err();
        let accepted = store
            .persist(
                "current-response",
                ArtifactType::Response,
                ControlEpoch::new(5),
                "h-ok",
                "tr-current",
                1001,
            )
            .unwrap();

        assert!(matches!(err, PersistenceError::EpochRejected { .. }));
        assert_eq!(accepted.sequence_number, 0);
        assert_eq!(store.total_count(), 1);
        assert!(store.get("old-empty").is_none());
    }

    #[test]
    fn tightening_validity_policy_rejects_later_old_artifact_without_removing_existing() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "kept-response",
                ArtifactType::Response,
                current_epoch(),
                "h-kept",
                "tr-kept",
                1000,
            )
            .unwrap();
        store.set_validity_policy(ValidityWindowPolicy::new(ControlEpoch::new(5), 0));

        let err = store
            .persist(
                "old-response",
                ArtifactType::Response,
                ControlEpoch::new(4),
                "h-old",
                "tr-old",
                1001,
            )
            .unwrap_err();

        assert!(matches!(err, PersistenceError::EpochRejected { .. }));
        assert_eq!(store.total_count(), 1);
        assert!(store.get("kept-response").is_some());
        assert!(store.get("old-response").is_none());
        assert_eq!(store.count_by_type(ArtifactType::Response), 1);
    }

    #[test]
    fn null_byte_artifact_id_is_rejected_without_consuming_sequence() {
        let mut store = ArtifactStore::new();

        let err = store
            .persist(
                "artifact\0id",
                ArtifactType::Invoke,
                current_epoch(),
                "h-null",
                "tr-null",
                1000,
            )
            .unwrap_err();
        let accepted = store
            .persist(
                "artifact-ok",
                ArtifactType::Invoke,
                current_epoch(),
                "h-ok",
                "tr-ok",
                1001,
            )
            .unwrap();

        assert_eq!(err.code(), "PRA_INVALID_ARTIFACT");
        assert!(err.to_string().contains("null bytes"));
        assert_eq!(accepted.sequence_number, 0);
        assert!(store.get("artifact\0id").is_none());
    }

    #[test]
    fn duplicate_id_with_different_type_preserves_original_type_and_hooks() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "same-id",
                ArtifactType::Invoke,
                current_epoch(),
                "h-invoke",
                "tr-invoke",
                1000,
            )
            .unwrap();

        let err = store
            .persist(
                "same-id",
                ArtifactType::Response,
                current_epoch(),
                "h-response",
                "tr-response",
                1001,
            )
            .unwrap_err();

        assert_eq!(err.code(), "PRA_DUPLICATE");
        assert_eq!(store.total_count(), 1);
        assert_eq!(store.count_by_type(ArtifactType::Invoke), 1);
        assert_eq!(store.count_by_type(ArtifactType::Response), 0);
        assert_eq!(
            store.get("same-id").unwrap().artifact_type,
            ArtifactType::Invoke
        );
    }

    #[test]
    fn epoch_rejection_precedes_duplicate_check_and_preserves_original() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "epoch-dup",
                ArtifactType::Receipt,
                current_epoch(),
                "h-original",
                "tr-original",
                1000,
            )
            .unwrap();
        store.set_validity_policy(ValidityWindowPolicy::new(ControlEpoch::new(5), 0));

        let err = store
            .persist(
                "epoch-dup",
                ArtifactType::Receipt,
                ControlEpoch::new(4),
                "h-replacement",
                "tr-old",
                1001,
            )
            .unwrap_err();

        assert!(matches!(err, PersistenceError::EpochRejected { .. }));
        let stored = store.get("epoch-dup").unwrap();
        assert!(constant_time::ct_eq(&stored.payload_hash, "h-original"));
        assert_eq!(stored.trace_id, "tr-original");
        assert_eq!(store.count_by_type(ArtifactType::Receipt), 1);
    }

    #[test]
    fn verify_replay_empty_hash_is_mismatch_and_preserves_artifact() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "empty-replay-hash",
                ArtifactType::Audit,
                current_epoch(),
                "h-audit",
                "tr-audit",
                1000,
            )
            .unwrap();

        let err = store.verify_replay("empty-replay-hash", "").unwrap_err();

        assert_eq!(err.code(), "PRA_REPLAY_MISMATCH");
        assert_eq!(store.total_count(), 1);
        assert_eq!(store.replay_hooks(ArtifactType::Audit).len(), 1);
        assert!(store.get("empty-replay-hash").is_some());
    }

    #[test]
    fn verify_replay_case_changed_hash_is_rejected() {
        let mut store = ArtifactStore::new();
        store
            .persist(
                "case-hash",
                ArtifactType::Approval,
                current_epoch(),
                "deadbeef",
                "tr-case",
                1000,
            )
            .unwrap();

        let err = store.verify_replay("case-hash", "DEADBEEF").unwrap_err();

        assert_eq!(err.code(), "PRA_REPLAY_MISMATCH");
        assert!(matches!(
            err,
            PersistenceError::ReplayMismatch {
                ref expected_hash,
                ref got_hash,
                ..
            } if constant_time::ct_eq(expected_hash, "deadbeef") && constant_time::ct_eq(got_hash, "DEADBEEF")
        ));
    }

    #[test]
    fn artifact_type_from_label_rejects_null_and_zero_width_variants() {
        assert_eq!(ArtifactType::from_label("invoke\0"), None);
        assert_eq!(ArtifactType::from_label("invoke\u{200b}"), None);
        assert_eq!(ArtifactType::from_label("response\0audit"), None);
        assert_eq!(ArtifactType::from_label("\u{200b}receipt"), None);
    }

    #[test]
    fn future_epoch_rejection_after_valid_prefix_does_not_advance_sequence() {
        let mut store = ArtifactStore::new();
        store.set_validity_policy(ValidityWindowPolicy::new(ControlEpoch::new(5), 0));
        store
            .persist(
                "current-audit",
                ArtifactType::Audit,
                ControlEpoch::new(5),
                "h-current",
                "tr-current",
                1000,
            )
            .unwrap();

        let err = store
            .persist(
                "future-audit",
                ArtifactType::Audit,
                ControlEpoch::new(6),
                "h-future",
                "tr-future",
                1001,
            )
            .unwrap_err();
        let accepted = store
            .persist(
                "current-audit-2",
                ArtifactType::Audit,
                ControlEpoch::new(5),
                "h-current-2",
                "tr-current-2",
                1002,
            )
            .unwrap();

        assert!(matches!(err, PersistenceError::EpochRejected { .. }));
        assert_eq!(accepted.sequence_number, 1);
        assert_eq!(store.count_by_type(ArtifactType::Audit), 2);
        assert!(store.get("future-audit").is_none());
    }
}
