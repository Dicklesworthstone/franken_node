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
use crate::security::constant_time::ct_eq;

/// Maximum number of events retained in a decision stream before oldest entries are drained.
const MAX_EVENTS: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    items.push(item);
    if items.len() > cap {
        let overflow = items.len() - cap;
        items.drain(0..overflow);
    }
}

fn checkpoint_progress_violation(
    latest_epoch: u64,
    latest_iteration_count: u64,
    candidate_epoch: u64,
    candidate_iteration_count: u64,
) -> Option<&'static str> {
    if candidate_epoch < latest_epoch {
        Some("epoch_regressed")
    } else if candidate_epoch == latest_epoch {
        if candidate_iteration_count < latest_iteration_count {
            Some("iteration_regressed")
        } else if candidate_iteration_count == latest_iteration_count {
            Some("duplicate_logical_position")
        } else {
            None
        }
    } else {
        None
    }
}

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

    #[cfg(test)]
    fn tamper_previous_checkpoint_hash(
        &mut self,
        orchestration_id: &str,
        index: usize,
        injected_previous_hash: Option<&str>,
    ) {
        if let Some(stream) = self.records.get_mut(orchestration_id)
            && let Some(record) = stream.get_mut(index)
        {
            record.previous_checkpoint_hash = injected_previous_hash.map(ToString::to_string);
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
                wall_clock_time: now_unix_ms(),
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
                wall_clock_time: now_unix_ms(),
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
        if let Some(violation) = first_hash_chain_failure(&existing.events) {
            return Err(CheckpointError::HashChainViolation {
                orchestration_id: orchestration_id.to_string(),
                checkpoint_id: violation
                    .checkpoint_hash
                    .clone()
                    .unwrap_or_else(|| "unknown-checkpoint".to_string()),
                reason: "cannot_append_after_hash_chain_failure".to_string(),
            });
        }
        let progress_state_json = serde_json::to_string(state)
            .map_err(|err| CheckpointError::Serialization(err.to_string()))?;
        let progress_state_hash = hash_hex(progress_state_json.as_bytes());
        if let Some(latest) = existing.latest.as_ref()
            && latest.iteration_count == iteration_count
            && latest.epoch == epoch
            && ct_eq(&latest.progress_state_hash, &progress_state_hash)
        {
            let checkpoint_id = latest.checkpoint_id.clone();
            let previous_checkpoint_hash = latest.previous_checkpoint_hash.clone();

            push_bounded(
                &mut self.decision_stream,
                CheckpointEvent {
                    event_code: FN_CK_005_IDEMPOTENT_REUSE.to_string(),
                    event_name: CHECKPOINT_IDEMPOTENT_REUSE.to_string(),
                    orchestration_id: orchestration_id.to_string(),
                    iteration_count,
                    checkpoint_hash: Some(checkpoint_id.clone()),
                    previous_checkpoint_hash: previous_checkpoint_hash.clone(),
                    progress_state_hash: Some(progress_state_hash.clone()),
                    epoch,
                    trace_id: trace_id.to_string(),
                    contract_status: "idempotent".to_string(),
                    wall_clock_time: now_unix_ms(),
                },
                MAX_EVENTS,
            );

            push_bounded(
                &mut self.decision_stream,
                CheckpointEvent {
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
                    wall_clock_time: now_unix_ms(),
                },
                MAX_EVENTS,
            );

            return Ok(checkpoint_id);
        }

        let previous_checkpoint_hash = existing
            .latest
            .as_ref()
            .map(|meta| meta.checkpoint_id.clone());
        if let Some(latest) = existing.latest.as_ref()
            && let Some(progress_violation) = checkpoint_progress_violation(
                latest.epoch,
                latest.iteration_count,
                epoch,
                iteration_count,
            )
        {
            let attempted_checkpoint_id = derive_checkpoint_id(
                orchestration_id,
                iteration_count,
                epoch,
                &progress_state_hash,
                previous_checkpoint_hash.as_deref(),
            );
            return Err(CheckpointError::HashChainViolation {
                orchestration_id: orchestration_id.to_string(),
                checkpoint_id: attempted_checkpoint_id,
                reason: format!(
                    "{progress_violation}: latest_epoch={} latest_iteration={} attempted_epoch={epoch} attempted_iteration={iteration_count}",
                    latest.epoch, latest.iteration_count
                ),
            });
        }

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
            wall_clock_time: now_unix_ms(),
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

        push_bounded(
            &mut self.decision_stream,
            CheckpointEvent {
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
                wall_clock_time: now_unix_ms(),
            },
            MAX_EVENTS,
        );

        push_bounded(
            &mut self.decision_stream,
            CheckpointEvent {
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
                wall_clock_time: now_unix_ms(),
            },
            MAX_EVENTS,
        );

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
    let mut last_valid_progress: Option<(u64, u64)> = None;
    let mut chain_failed = false;
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

        let valid_state_hash = ct_eq(&computed_state_hash, &record.progress_state_hash);
        let valid_id = ct_eq(&computed_id, &record.checkpoint_id);
        let valid_prev = match (&record.previous_checkpoint_hash, &last_valid_id) {
            (Some(a), Some(b)) => ct_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        let progress_violation =
            last_valid_progress.and_then(|(latest_epoch, latest_iteration_count)| {
                checkpoint_progress_violation(
                    latest_epoch,
                    latest_iteration_count,
                    record.epoch,
                    record.iteration_count,
                )
            });
        let valid_progress = progress_violation.is_none();

        if !chain_failed && valid_state_hash && valid_id && valid_prev && valid_progress {
            let meta = CheckpointMeta::from(record);
            last_valid_id = Some(meta.checkpoint_id.clone());
            last_valid_progress = Some((meta.epoch, meta.iteration_count));
            latest_valid = Some(meta);
            continue;
        }

        let mut reason = String::new();
        if chain_failed {
            reason.push_str("prior_hash_chain_failure;");
        }
        if !valid_state_hash {
            reason.push_str("progress_state_hash_mismatch;");
        }
        if !valid_id {
            reason.push_str("checkpoint_id_mismatch;");
        }
        if !valid_prev {
            reason.push_str("previous_checkpoint_hash_mismatch;");
        }
        if let Some(progress_violation) = progress_violation {
            reason.push_str(progress_violation);
            reason.push(';');
        }
        chain_failed = true;

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
            wall_clock_time: now_unix_ms(),
        });
    }

    (latest_valid, events)
}

fn first_hash_chain_failure(events: &[CheckpointEvent]) -> Option<&CheckpointEvent> {
    events
        .iter()
        .find(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
}

fn derive_checkpoint_id(
    orchestration_id: &str,
    iteration_count: u64,
    epoch: u64,
    progress_state_hash: &str,
    previous_checkpoint_hash: Option<&str>,
) -> CheckpointId {
    let mut hasher = Sha256::new();
    hasher.update(b"checkpoint_content_v2:");
    hasher.update(orchestration_id.as_bytes());
    hasher.update([0x00]);
    hasher.update(iteration_count.to_le_bytes());
    hasher.update(epoch.to_le_bytes());
    hasher.update([0x00]);
    hasher.update(progress_state_hash.as_bytes());
    hasher.update([0x00]);
    match previous_checkpoint_hash {
        Some(previous_hash) => hasher.update(previous_hash.as_bytes()),
        None => hasher.update(b"root"),
    }
    format!("{:x}", hasher.finalize())
}

fn hash_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"checkpoint_hash_v1:");
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
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
        assert!(restored.meta.wall_clock_time >= 1_000_000_000_000);
        assert_eq!(restored.state.get("phase"), Some(&"scan".to_string()));

        let save_event = writer
            .decision_stream()
            .iter()
            .find(|event| event.event_code == FN_CK_001_CHECKPOINT_SAVE)
            .expect("save event");
        assert!(save_event.wall_clock_time >= 1_000_000_000_000);

        let read = writer
            .read_latest_valid("trace-ck-1", "orch-1")
            .expect("read latest valid");
        let restore_event = read
            .events
            .iter()
            .find(|event| event.event_name == CHECKPOINT_RESTORE)
            .expect("restore event");
        assert!(restore_event.wall_clock_time >= 1_000_000_000_000);
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
    fn descendant_reparent_after_midstream_tamper_is_rejected() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        let first = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-3b",
                "orch-3b",
                10,
                1,
                &BTreeMap::from([("cursor".to_string(), "10".to_string())]),
            )
            .expect("checkpoint 10");
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-3b",
                "orch-3b",
                20,
                1,
                &BTreeMap::from([("cursor".to_string(), "20".to_string())]),
            )
            .expect("checkpoint 20");
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-3b",
                "orch-3b",
                30,
                1,
                &BTreeMap::from([("cursor".to_string(), "30".to_string())]),
            )
            .expect("checkpoint 30");

        writer
            .backend_mut()
            .tamper_progress_state("orch-3b", 1, "{\"cursor\":\"999\"}");
        writer
            .backend_mut()
            .tamper_previous_checkpoint_hash("orch-3b", 2, Some(&first));

        let read = writer
            .read_latest_valid("trace-ck-3b", "orch-3b")
            .expect("read latest valid");

        assert_eq!(read.latest.expect("latest").iteration_count, 10);
        assert_eq!(
            read.events
                .iter()
                .filter(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
                .count(),
            2
        );
    }

    #[test]
    fn save_checkpoint_rejects_append_after_midstream_tamper() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-3c",
                "orch-3c",
                10,
                1,
                &BTreeMap::from([("cursor".to_string(), "10".to_string())]),
            )
            .expect("checkpoint 10");
        let second = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-3c",
                "orch-3c",
                20,
                1,
                &BTreeMap::from([("cursor".to_string(), "20".to_string())]),
            )
            .expect("checkpoint 20");

        writer
            .backend_mut()
            .tamper_progress_state("orch-3c", 1, "{\"cursor\":\"999\"}");

        let decision_stream_len = writer.decision_stream().len();
        let checkpoint_count = writer
            .list_checkpoints("orch-3c")
            .expect("list checkpoints before rejection")
            .len();

        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-3c",
                "orch-3c",
                30,
                1,
                &BTreeMap::from([("cursor".to_string(), "30".to_string())]),
            )
            .expect_err("tampered chain must reject append");

        assert!(matches!(
            err,
            CheckpointError::HashChainViolation {
                ref orchestration_id,
                ref checkpoint_id,
                ref reason,
            } if orchestration_id == "orch-3c"
                && checkpoint_id == &second
                && reason == "cannot_append_after_hash_chain_failure"
        ));
        assert_eq!(writer.decision_stream().len(), decision_stream_len);
        assert_eq!(
            writer
                .list_checkpoints("orch-3c")
                .expect("list checkpoints after rejection")
                .len(),
            checkpoint_count
        );

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-ck-3c", "orch-3c")
            .expect("restore checkpoint after rejection")
            .expect("latest valid checkpoint exists");
        assert_eq!(restored.meta.iteration_count, 10);
        assert_eq!(restored.state.get("cursor"), Some(&"10".to_string()));
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
    fn save_checkpoint_rejects_iteration_regression_within_epoch() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4a",
                "orch-4a",
                100,
                7,
                &BTreeMap::from([("cursor".to_string(), "100".to_string())]),
            )
            .expect("checkpoint 100");

        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4a",
                "orch-4a",
                50,
                7,
                &BTreeMap::from([("cursor".to_string(), "050".to_string())]),
            )
            .expect_err("regressive iteration should fail");

        assert!(matches!(
            err,
            CheckpointError::HashChainViolation { ref reason, .. }
                if reason.contains("iteration_regressed")
        ));
        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-ck-4a", "orch-4a")
            .expect("restore checkpoint")
            .expect("checkpoint exists");
        assert_eq!(restored.meta.iteration_count, 100);
    }

    #[test]
    fn save_checkpoint_rejects_non_idempotent_duplicate_position() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4b",
                "orch-4b",
                42,
                7,
                &BTreeMap::from([("cursor".to_string(), "042".to_string())]),
            )
            .expect("checkpoint 42");

        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4b",
                "orch-4b",
                42,
                7,
                &BTreeMap::from([("cursor".to_string(), "changed".to_string())]),
            )
            .expect_err("duplicate logical position should fail");

        assert!(matches!(
            err,
            CheckpointError::HashChainViolation { ref reason, .. }
                if reason.contains("duplicate_logical_position")
        ));
        assert_eq!(
            writer
                .list_checkpoints("orch-4b")
                .expect("list checkpoints")
                .len(),
            1
        );
    }

    #[test]
    fn read_latest_valid_rejects_regressive_checkpoint_progress() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        let first = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4c",
                "orch-4c",
                100,
                7,
                &BTreeMap::from([("cursor".to_string(), "100".to_string())]),
            )
            .expect("checkpoint 100");

        let progress_state_json =
            serde_json::to_string(&BTreeMap::from([("cursor".to_string(), "050".to_string())]))
                .expect("serialize regressive state");
        let progress_state_hash = hash_hex(progress_state_json.as_bytes());
        let regressive = CheckpointRecord {
            checkpoint_id: derive_checkpoint_id(
                "orch-4c",
                50,
                7,
                &progress_state_hash,
                Some(&first),
            ),
            orchestration_id: "orch-4c".to_string(),
            iteration_count: 50,
            epoch: 7,
            wall_clock_time: now_unix_ms(),
            progress_state_json,
            progress_state_hash,
            previous_checkpoint_hash: Some(first),
        };
        writer
            .backend_mut()
            .save(regressive)
            .expect("save regressive record");

        let read = writer
            .read_latest_valid("trace-ck-4c", "orch-4c")
            .expect("read latest valid");

        assert_eq!(read.latest.expect("latest").iteration_count, 100);
        let violation = read
            .events
            .iter()
            .find(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
            .expect("regressive progress violation should be logged");
        assert!(violation.contract_status.contains("iteration_regressed"));
    }

    #[test]
    fn read_latest_valid_rejects_suffix_after_hash_chain_failure() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        let first = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4d",
                "orch-4d",
                10,
                1,
                &BTreeMap::from([("cursor".to_string(), "10".to_string())]),
            )
            .expect("checkpoint 10");
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4d",
                "orch-4d",
                20,
                1,
                &BTreeMap::from([("cursor".to_string(), "20".to_string())]),
            )
            .expect("checkpoint 20");

        writer
            .backend_mut()
            .tamper_progress_state("orch-4d", 1, "{\"cursor\":\"999\"}");

        let progress_state_json =
            serde_json::to_string(&BTreeMap::from([("cursor".to_string(), "30".to_string())]))
                .expect("serialize suffix state");
        let progress_state_hash = hash_hex(progress_state_json.as_bytes());
        let suffix_record = CheckpointRecord {
            checkpoint_id: derive_checkpoint_id(
                "orch-4d",
                30,
                1,
                &progress_state_hash,
                Some(&first),
            ),
            orchestration_id: "orch-4d".to_string(),
            iteration_count: 30,
            epoch: 1,
            wall_clock_time: now_unix_ms(),
            progress_state_json,
            progress_state_hash,
            previous_checkpoint_hash: Some(first),
        };
        writer
            .backend_mut()
            .save(suffix_record)
            .expect("save suffix record");

        let read = writer
            .read_latest_valid("trace-ck-4d", "orch-4d")
            .expect("read latest valid");

        assert_eq!(read.latest.expect("latest").iteration_count, 10);
        let violations = read
            .events
            .iter()
            .filter(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
            .collect::<Vec<_>>();
        assert_eq!(violations.len(), 2);
        assert!(
            violations
                .iter()
                .any(|event| event.contract_status.contains("prior_hash_chain_failure"))
        );

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-ck-4d", "orch-4d")
            .expect("restore checkpoint")
            .expect("latest valid checkpoint exists");
        assert_eq!(restored.meta.iteration_count, 10);
        assert_eq!(restored.state.get("cursor"), Some(&"10".to_string()));
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
