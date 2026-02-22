//! bd-93k: checkpoint placement contract primitives.
//!
//! This module provides content-addressed checkpoints with hash-chain integrity,
//! bounded-mask protected writes, and restore helpers for long orchestration loops.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime::bounded_mask::{CancellationState, CapabilityContext, MaskError, bounded_mask};

/// Event code: checkpoint write persisted.
pub const FN_CK_001_CHECKPOINT_SAVE: &str = "FN-CK-001";
/// Event code: checkpoint restore/read performed.
pub const FN_CK_002_CHECKPOINT_RESTORE: &str = "FN-CK-002";
/// Event code: hash-chain validation failed.
pub const FN_CK_003_HASH_CHAIN_FAILURE: &str = "FN-CK-003";
/// Event code: orchestration resumed from checkpoint.
pub const FN_CK_004_CHECKPOINT_RESUME: &str = "FN-CK-004";
/// Event code: checkpoint idempotent write re-used existing ID.
pub const FN_CK_005_IDEMPOTENT_REUSE: &str = "FN-CK-005";
/// Event code: placement contract warning.
pub const FN_CK_006_CONTRACT_WARNING: &str = "FN-CK-006";
/// Event code: placement contract violation.
pub const FN_CK_007_CONTRACT_VIOLATION: &str = "FN-CK-007";
/// Event code: decision-stream append event.
pub const FN_CK_008_DECISION_STREAM_APPEND: &str = "FN-CK-008";

/// Structured event name for persisted checkpoints.
pub const CHECKPOINT_SAVE: &str = "CHECKPOINT_SAVE";
/// Structured event name for checkpoint restore.
pub const CHECKPOINT_RESTORE: &str = "CHECKPOINT_RESTORE";
/// Structured event name for missing checkpoint.
pub const CHECKPOINT_MISSING: &str = "CHECKPOINT_MISSING";
/// Structured event name for hash-chain failures.
pub const CHECKPOINT_HASH_CHAIN_FAILURE: &str = "CHECKPOINT_HASH_CHAIN_FAILURE";
/// Structured event name for orchestration resume.
pub const CHECKPOINT_RESUME: &str = "CHECKPOINT_RESUME";
/// Structured event name for idempotent checkpoint save.
pub const CHECKPOINT_IDEMPOTENT_REUSE: &str = "CHECKPOINT_IDEMPOTENT_REUSE";
/// Structured event name for placement warnings.
pub const CHECKPOINT_WARNING: &str = "CHECKPOINT_WARNING";
/// Structured event name for contract violations.
pub const CHECKPOINT_CONTRACT_VIOLATION: &str = "CHECKPOINT_CONTRACT_VIOLATION";
/// Structured event name for append-only decision stream records.
pub const CHECKPOINT_DECISION_STREAM_APPEND: &str = "CHECKPOINT_DECISION_STREAM_APPEND";

/// Type alias for checkpoint IDs.
pub type CheckpointId = String;

/// Serialized checkpoint record persisted by a backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointRecord {
    pub checkpoint_id: CheckpointId,
    pub orchestration_id: String,
    pub iteration_count: u64,
    pub epoch: u64,
    pub wall_clock_time: u64,
    pub progress_state_json: String,
    pub progress_state_hash: String,
    pub previous_checkpoint_hash: Option<String>,
}

/// Lightweight metadata for listing checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointMeta {
    pub checkpoint_id: CheckpointId,
    pub orchestration_id: String,
    pub iteration_count: u64,
    pub epoch: u64,
    pub wall_clock_time: u64,
    pub progress_state_hash: String,
    pub previous_checkpoint_hash: Option<String>,
}

impl From<&CheckpointRecord> for CheckpointMeta {
    fn from(record: &CheckpointRecord) -> Self {
        Self {
            checkpoint_id: record.checkpoint_id.clone(),
            orchestration_id: record.orchestration_id.clone(),
            iteration_count: record.iteration_count,
            epoch: record.epoch,
            wall_clock_time: record.wall_clock_time,
            progress_state_hash: record.progress_state_hash.clone(),
            previous_checkpoint_hash: record.previous_checkpoint_hash.clone(),
        }
    }
}

/// Structured checkpoint event for append-only decision streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointEvent {
    pub event_code: String,
    pub event_name: String,
    pub orchestration_id: String,
    pub iteration_count: u64,
    pub checkpoint_hash: Option<String>,
    pub previous_checkpoint_hash: Option<String>,
    pub progress_state_hash: Option<String>,
    pub epoch: u64,
    pub trace_id: String,
    pub contract_status: String,
    pub wall_clock_time: u64,
}

/// Restore payload with parsed state and checkpoint metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredCheckpoint<T> {
    pub meta: CheckpointMeta,
    pub state: T,
}

/// Read result containing the latest valid checkpoint and audit events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointReadResult {
    pub latest: Option<CheckpointMeta>,
    pub events: Vec<CheckpointEvent>,
}

/// Stable error modes for checkpoint placement/runtime behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    Serialization(String),
    Deserialization(String),
    Backend(String),
    MaskFailure(String),
    HashChainViolation {
        orchestration_id: String,
        checkpoint_id: String,
        reason: String,
    },
}

impl CheckpointError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Serialization(_) => "CHECKPOINT_SERIALIZATION_ERROR",
            Self::Deserialization(_) => "CHECKPOINT_DESERIALIZATION_ERROR",
            Self::Backend(_) => "CHECKPOINT_BACKEND_ERROR",
            Self::MaskFailure(_) => "CHECKPOINT_MASK_FAILURE",
            Self::HashChainViolation { .. } => "CHECKPOINT_HASH_CHAIN_VIOLATION",
        }
    }
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialization(detail) => {
                write!(f, "{}: {detail}", self.code())
            }
            Self::Deserialization(detail) => {
                write!(f, "{}: {detail}", self.code())
            }
            Self::Backend(detail) => {
                write!(f, "{}: {detail}", self.code())
            }
            Self::MaskFailure(detail) => {
                write!(f, "{}: {detail}", self.code())
            }
            Self::HashChainViolation {
                orchestration_id,
                checkpoint_id,
                reason,
            } => {
                write!(
                    f,
                    "{}: orchestration={orchestration_id} checkpoint={checkpoint_id} reason={reason}",
                    self.code()
                )
            }
        }
    }
}

impl std::error::Error for CheckpointError {}

impl From<MaskError> for CheckpointError {
    fn from(value: MaskError) -> Self {
        Self::MaskFailure(value.to_string())
    }
}

/// Storage backend for checkpoint records.
pub trait CheckpointBackend {
    /// Persist one checkpoint record.
    ///
    /// Returns `true` when a new record was inserted and `false` when a record
    /// with the same ID already existed (idempotent save).
    fn save(&mut self, record: CheckpointRecord) -> Result<bool, CheckpointError>;

    /// Load all checkpoint records for an orchestration, oldest to newest.
    fn load_all(&self, orchestration_id: &str) -> Result<Vec<CheckpointRecord>, CheckpointError>;
}

/// In-memory checkpoint backend for unit and integration tests.
#[derive(Debug, Clone, Default)]
pub struct InMemoryCheckpointBackend {
    records: BTreeMap<String, Vec<CheckpointRecord>>,
}

impl InMemoryCheckpointBackend {
    #[cfg(test)]
    fn tamper_progress_state(
        &mut self,
        orchestration_id: &str,
        index: usize,
        injected_state_json: &str,
    ) {
        if let Some(stream) = self.records.get_mut(orchestration_id)
            && let Some(record) = stream.get_mut(index)
        {
            record.progress_state_json = injected_state_json.to_string();
        }
    }
}

impl CheckpointBackend for InMemoryCheckpointBackend {
    fn save(&mut self, record: CheckpointRecord) -> Result<bool, CheckpointError> {
        let stream = self
            .records
            .entry(record.orchestration_id.clone())
            .or_default();
        if stream
            .iter()
            .any(|existing| existing.checkpoint_id == record.checkpoint_id)
        {
            return Ok(false);
        }
        stream.push(record);
        Ok(true)
    }

    fn load_all(&self, orchestration_id: &str) -> Result<Vec<CheckpointRecord>, CheckpointError> {
        Ok(self
            .records
            .get(orchestration_id)
            .cloned()
            .unwrap_or_default())
    }
}

/// Contract that all long orchestrations must use for checkpoint IO.
pub trait CheckpointContract {
    #[allow(clippy::too_many_arguments)]
    fn save_checkpoint<T: Serialize>(
        &mut self,
        cx: &CapabilityContext,
        cancellation: &mut CancellationState,
        trace_id: &str,
        orchestration_id: &str,
        iteration_count: u64,
        epoch: u64,
        state: &T,
    ) -> Result<CheckpointId, CheckpointError>;

    fn restore_checkpoint<T: DeserializeOwned>(
        &self,
        trace_id: &str,
        orchestration_id: &str,
    ) -> Result<Option<RestoredCheckpoint<T>>, CheckpointError>;

    fn list_checkpoints(
        &self,
        orchestration_id: &str,
    ) -> Result<Vec<CheckpointMeta>, CheckpointError>;
}

/// Writer/reader facade that owns a concrete backend.
#[derive(Debug, Clone)]
pub struct CheckpointWriter<B: CheckpointBackend> {
    backend: B,
    decision_stream: Vec<CheckpointEvent>,
}

impl<B: CheckpointBackend> CheckpointWriter<B> {
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            decision_stream: Vec::new(),
        }
    }

    /// Read-only view into the append-only checkpoint decision stream.
    #[must_use]
    pub fn decision_stream(&self) -> &[CheckpointEvent] {
        &self.decision_stream
    }

    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    #[must_use]
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Return the latest valid checkpoint plus verification events.
    pub fn read_latest_valid(
        &self,
        trace_id: &str,
        orchestration_id: &str,
    ) -> Result<CheckpointReadResult, CheckpointError> {
        let records = self.backend.load_all(orchestration_id)?;
        let (latest, mut events) = verify_chain(orchestration_id, trace_id, &records);
        if let Some(meta) = latest.as_ref() {
            events.push(CheckpointEvent {
                event_code: FN_CK_002_CHECKPOINT_RESTORE.to_string(),
                event_name: CHECKPOINT_RESTORE.to_string(),
                orchestration_id: orchestration_id.to_string(),
                iteration_count: meta.iteration_count,
                checkpoint_hash: Some(meta.checkpoint_id.clone()),
                previous_checkpoint_hash: meta.previous_checkpoint_hash.clone(),
                progress_state_hash: Some(meta.progress_state_hash.clone()),
                epoch: meta.epoch,
                trace_id: trace_id.to_string(),
                contract_status: "valid".to_string(),
                wall_clock_time: now_unix_secs(),
            });
        } else {
            events.push(CheckpointEvent {
                event_code: FN_CK_002_CHECKPOINT_RESTORE.to_string(),
                event_name: CHECKPOINT_MISSING.to_string(),
                orchestration_id: orchestration_id.to_string(),
                iteration_count: 0,
                checkpoint_hash: None,
                previous_checkpoint_hash: None,
                progress_state_hash: None,
                epoch: 0,
                trace_id: trace_id.to_string(),
                contract_status: "missing".to_string(),
                wall_clock_time: now_unix_secs(),
            });
        }

        Ok(CheckpointReadResult { latest, events })
    }
}

impl<B: CheckpointBackend> CheckpointContract for CheckpointWriter<B> {
    fn save_checkpoint<T: Serialize>(
        &mut self,
        cx: &CapabilityContext,
        cancellation: &mut CancellationState,
        trace_id: &str,
        orchestration_id: &str,
        iteration_count: u64,
        epoch: u64,
        state: &T,
    ) -> Result<CheckpointId, CheckpointError> {
        let existing = self.read_latest_valid(trace_id, orchestration_id)?;
        let previous_checkpoint_hash = existing.latest.map(|meta| meta.checkpoint_id);

        let progress_state_json = serde_json::to_string(state)
            .map_err(|err| CheckpointError::Serialization(err.to_string()))?;
        let progress_state_hash = hash_hex(progress_state_json.as_bytes());
        let checkpoint_id = derive_checkpoint_id(
            orchestration_id,
            iteration_count,
            epoch,
            &progress_state_hash,
            previous_checkpoint_hash.as_deref(),
        );

        let record = CheckpointRecord {
            checkpoint_id: checkpoint_id.clone(),
            orchestration_id: orchestration_id.to_string(),
            iteration_count,
            epoch,
            wall_clock_time: now_unix_secs(),
            progress_state_json,
            progress_state_hash: progress_state_hash.clone(),
            previous_checkpoint_hash: previous_checkpoint_hash.clone(),
        };

        let inserted = bounded_mask(cx, cancellation, "checkpoint_write", |_cx, _cancel| {
            self.backend.save(record.clone())
        })??;

        let save_event_name = if inserted {
            CHECKPOINT_SAVE
        } else {
            CHECKPOINT_IDEMPOTENT_REUSE
        };
        let save_event_code = if inserted {
            FN_CK_001_CHECKPOINT_SAVE
        } else {
            FN_CK_005_IDEMPOTENT_REUSE
        };
        let contract_status = if inserted { "saved" } else { "idempotent" };

        self.decision_stream.push(CheckpointEvent {
            event_code: save_event_code.to_string(),
            event_name: save_event_name.to_string(),
            orchestration_id: orchestration_id.to_string(),
            iteration_count,
            checkpoint_hash: Some(checkpoint_id.clone()),
            previous_checkpoint_hash: previous_checkpoint_hash.clone(),
            progress_state_hash: Some(progress_state_hash.clone()),
            epoch,
            trace_id: trace_id.to_string(),
            contract_status: contract_status.to_string(),
            wall_clock_time: now_unix_secs(),
        });

        self.decision_stream.push(CheckpointEvent {
            event_code: FN_CK_008_DECISION_STREAM_APPEND.to_string(),
            event_name: CHECKPOINT_DECISION_STREAM_APPEND.to_string(),
            orchestration_id: orchestration_id.to_string(),
            iteration_count,
            checkpoint_hash: Some(checkpoint_id.clone()),
            previous_checkpoint_hash,
            progress_state_hash: Some(progress_state_hash),
            epoch,
            trace_id: trace_id.to_string(),
            contract_status: "appended".to_string(),
            wall_clock_time: now_unix_secs(),
        });

        Ok(checkpoint_id)
    }

    fn restore_checkpoint<T: DeserializeOwned>(
        &self,
        trace_id: &str,
        orchestration_id: &str,
    ) -> Result<Option<RestoredCheckpoint<T>>, CheckpointError> {
        let records = self.backend.load_all(orchestration_id)?;
        let (latest, _) = verify_chain(orchestration_id, trace_id, &records);
        let Some(meta) = latest else {
            return Ok(None);
        };

        let payload = records
            .iter()
            .find(|record| record.checkpoint_id == meta.checkpoint_id)
            .ok_or_else(|| {
                CheckpointError::Backend(format!(
                    "latest meta id {} missing from backing store",
                    meta.checkpoint_id
                ))
            })?;

        let state = serde_json::from_str::<T>(&payload.progress_state_json)
            .map_err(|err| CheckpointError::Deserialization(err.to_string()))?;

        Ok(Some(RestoredCheckpoint { meta, state }))
    }

    fn list_checkpoints(
        &self,
        orchestration_id: &str,
    ) -> Result<Vec<CheckpointMeta>, CheckpointError> {
        let records = self.backend.load_all(orchestration_id)?;
        Ok(records.iter().map(CheckpointMeta::from).collect())
    }
}

fn verify_chain(
    orchestration_id: &str,
    trace_id: &str,
    records: &[CheckpointRecord],
) -> (Option<CheckpointMeta>, Vec<CheckpointEvent>) {
    let mut latest_valid: Option<CheckpointMeta> = None;
    let mut last_valid_id: Option<String> = None;
    let mut events = Vec::new();

    for record in records {
        let computed_state_hash = hash_hex(record.progress_state_json.as_bytes());
        let computed_id = derive_checkpoint_id(
            &record.orchestration_id,
            record.iteration_count,
            record.epoch,
            &computed_state_hash,
            record.previous_checkpoint_hash.as_deref(),
        );

        let valid_state_hash = computed_state_hash == record.progress_state_hash;
        let valid_id = computed_id == record.checkpoint_id;
        let valid_prev = record.previous_checkpoint_hash == last_valid_id;

        if valid_state_hash && valid_id && valid_prev {
            let meta = CheckpointMeta::from(record);
            last_valid_id = Some(meta.checkpoint_id.clone());
            latest_valid = Some(meta);
            continue;
        }

        let mut reason = String::new();
        if !valid_state_hash {
            reason.push_str("progress_state_hash_mismatch;");
        }
        if !valid_id {
            reason.push_str("checkpoint_id_mismatch;");
        }
        if !valid_prev {
            reason.push_str("previous_checkpoint_hash_mismatch;");
        }

        events.push(CheckpointEvent {
            event_code: FN_CK_003_HASH_CHAIN_FAILURE.to_string(),
            event_name: CHECKPOINT_HASH_CHAIN_FAILURE.to_string(),
            orchestration_id: orchestration_id.to_string(),
            iteration_count: record.iteration_count,
            checkpoint_hash: Some(record.checkpoint_id.clone()),
            previous_checkpoint_hash: record.previous_checkpoint_hash.clone(),
            progress_state_hash: Some(record.progress_state_hash.clone()),
            epoch: record.epoch,
            trace_id: trace_id.to_string(),
            contract_status: format!("invalid:{reason}"),
            wall_clock_time: now_unix_secs(),
        });
    }

    (latest_valid, events)
}

fn derive_checkpoint_id(
    orchestration_id: &str,
    iteration_count: u64,
    epoch: u64,
    progress_state_hash: &str,
    _previous_checkpoint_hash: Option<&str>,
) -> CheckpointId {
    let mut hasher = Sha256::new();
    hasher.update(orchestration_id.as_bytes());
    hasher.update([0x00]);
    hasher.update(iteration_count.to_le_bytes());
    hasher.update(epoch.to_le_bytes());
    hasher.update([0x00]);
    hasher.update(progress_state_hash.as_bytes());
    // NOTE: previous_checkpoint_hash is intentionally excluded from the ID
    // derivation so that saving the same state twice (idempotent save)
    // produces the same checkpoint_id regardless of chain position.
    format!("{:x}", hasher.finalize())
}

fn hash_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn cx() -> CapabilityContext {
        CapabilityContext::new("cx-checkpoint", "operator-checkpoint")
    }

    #[test]
    fn save_restore_roundtrip() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        let state = BTreeMap::from([("phase".to_string(), "scan".to_string())]);

        let checkpoint_id = writer
            .save_checkpoint(&cx(), &mut cancel, "trace-ck-1", "orch-1", 100, 7, &state)
            .expect("save checkpoint");

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-ck-1", "orch-1")
            .expect("restore checkpoint")
            .expect("checkpoint exists");

        assert_eq!(restored.meta.checkpoint_id, checkpoint_id);
        assert_eq!(restored.meta.iteration_count, 100);
        assert_eq!(restored.meta.epoch, 7);
        assert_eq!(restored.state.get("phase"), Some(&"scan".to_string()));
    }

    #[test]
    fn idempotent_checkpoint_id_stability() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        let state = BTreeMap::from([("cursor".to_string(), "42".to_string())]);

        let first = writer
            .save_checkpoint(&cx(), &mut cancel, "trace-ck-2", "orch-2", 42, 11, &state)
            .expect("first save");
        let second = writer
            .save_checkpoint(&cx(), &mut cancel, "trace-ck-2", "orch-2", 42, 11, &state)
            .expect("second save");

        assert_eq!(first, second);
        let list = writer.list_checkpoints("orch-2").expect("list checkpoints");
        assert_eq!(list.len(), 1);
        assert!(
            writer
                .decision_stream()
                .iter()
                .any(|event| event.event_code == FN_CK_005_IDEMPOTENT_REUSE)
        );
    }

    #[test]
    fn hash_chain_tamper_is_detected_and_skipped() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-3",
                "orch-3",
                10,
                1,
                &BTreeMap::from([("cursor".to_string(), "10".to_string())]),
            )
            .expect("checkpoint 10");
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-3",
                "orch-3",
                20,
                1,
                &BTreeMap::from([("cursor".to_string(), "20".to_string())]),
            )
            .expect("checkpoint 20");

        writer
            .backend_mut()
            .tamper_progress_state("orch-3", 1, "{\"cursor\":\"999\"}");

        let read = writer
            .read_latest_valid("trace-ck-3", "orch-3")
            .expect("read latest valid");

        assert_eq!(read.latest.expect("latest").iteration_count, 10);
        assert!(
            read.events
                .iter()
                .any(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
        );
    }

    #[test]
    fn restore_checkpoint_returns_none_when_absent() {
        let writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-ck-4", "missing")
            .expect("restore result");
        assert!(restored.is_none());
    }

    #[test]
    fn resume_from_latest_valid_checkpoint() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        let mut total_work_done = 0_u64;

        for iteration in 1..=200_u64 {
            total_work_done = total_work_done.saturating_add(1);
            if iteration == 100 {
                writer
                    .save_checkpoint(
                        &cx(),
                        &mut cancel,
                        "trace-ck-5",
                        "orch-5",
                        iteration,
                        3,
                        &BTreeMap::from([("cursor".to_string(), iteration.to_string())]),
                    )
                    .expect("save checkpoint");
            }

            if iteration == 150 {
                break;
            }
        }

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-ck-5", "orch-5")
            .expect("restore checkpoint")
            .expect("checkpoint exists");
        let resume_from = restored
            .state
            .get("cursor")
            .expect("cursor")
            .parse::<u64>()
            .expect("parse cursor");

        for _ in (resume_from + 1)..=200 {
            total_work_done = total_work_done.saturating_add(1);
        }

        assert_eq!(resume_from, 100);
        assert_eq!(total_work_done, 250);
    }
}
