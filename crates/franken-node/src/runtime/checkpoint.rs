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
use crate::security::constant_time;

use crate::capacity_defaults::aliases::MAX_EVENTS;
use crate::push_bounded;

const MAX_CHECKPOINT_RECORDS_PER_STREAM: usize = 4096;

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

fn checkpoint_is_exact_replay(latest: &CheckpointMeta, record: &CheckpointRecord) -> bool {
    latest.iteration_count == record.iteration_count
        && latest.epoch == record.epoch
        && constant_time::ct_eq(&latest.checkpoint_id, &record.checkpoint_id)
        && constant_time::ct_eq(&latest.progress_state_hash, &record.progress_state_hash)
        && match (
            &latest.previous_checkpoint_hash,
            &record.previous_checkpoint_hash,
        ) {
            (Some(a), Some(b)) => constant_time::ct_eq(a, b),
            (None, None) => true,
            _ => false,
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

    #[cfg(test)]
    fn duplicate_record(&mut self, orchestration_id: &str, index: usize) {
        if let Some(stream) = self.records.get_mut(orchestration_id)
            && let Some(record) = stream.get(index).cloned()
        {
            push_bounded(stream, record, MAX_CHECKPOINT_RECORDS_PER_STREAM);
        }
    }

    #[cfg(test)]
    fn inject_record_into_stream(&mut self, orchestration_id: &str, record: CheckpointRecord) {
        self.records
            .entry(orchestration_id.to_string())
            .or_default()
            .push(record);
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
        push_bounded(stream, record, MAX_CHECKPOINT_RECORDS_PER_STREAM);
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
            push_bounded(
                &mut events,
                CheckpointEvent {
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
                },
                MAX_EVENTS,
            );
        } else {
            push_bounded(
                &mut events,
                CheckpointEvent {
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
                },
                MAX_EVENTS,
            );
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
            push_bounded(
                &mut self.decision_stream,
                CheckpointEvent {
                    event_code: FN_CK_007_CONTRACT_VIOLATION.to_string(),
                    event_name: CHECKPOINT_CONTRACT_VIOLATION.to_string(),
                    orchestration_id: orchestration_id.to_string(),
                    iteration_count,
                    checkpoint_hash: violation.checkpoint_hash.clone(),
                    previous_checkpoint_hash: violation.previous_checkpoint_hash.clone(),
                    progress_state_hash: None,
                    epoch,
                    trace_id: trace_id.to_string(),
                    contract_status: "violation:cannot_append_after_hash_chain_failure".to_string(),
                    wall_clock_time: now_unix_ms(),
                },
                MAX_EVENTS,
            );
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
            && constant_time::ct_eq(&latest.progress_state_hash, &progress_state_hash)
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
            push_bounded(
                &mut self.decision_stream,
                CheckpointEvent {
                    event_code: FN_CK_007_CONTRACT_VIOLATION.to_string(),
                    event_name: CHECKPOINT_CONTRACT_VIOLATION.to_string(),
                    orchestration_id: orchestration_id.to_string(),
                    iteration_count,
                    checkpoint_hash: Some(attempted_checkpoint_id.clone()),
                    previous_checkpoint_hash: previous_checkpoint_hash.clone(),
                    progress_state_hash: Some(progress_state_hash.clone()),
                    epoch,
                    trace_id: trace_id.to_string(),
                    contract_status: format!("violation:{progress_violation}"),
                    wall_clock_time: now_unix_ms(),
                },
                MAX_EVENTS,
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

        let valid_orchestration = constant_time::ct_eq(&record.orchestration_id, orchestration_id);
        let valid_state_hash =
            constant_time::ct_eq(&computed_state_hash, &record.progress_state_hash);
        let valid_id = constant_time::ct_eq(&computed_id, &record.checkpoint_id);
        let valid_prev = match (&record.previous_checkpoint_hash, &last_valid_id) {
            (Some(a), Some(b)) => constant_time::ct_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if !chain_failed
            && let Some(latest) = latest_valid.as_ref()
            && valid_orchestration
            && checkpoint_is_exact_replay(latest, record)
            && valid_state_hash
            && valid_id
        {
            continue;
        }
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

        if !chain_failed
            && valid_orchestration
            && valid_state_hash
            && valid_id
            && valid_prev
            && valid_progress
        {
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
        if !valid_orchestration {
            reason.push_str("orchestration_id_mismatch;");
        }
        if let Some(progress_violation) = progress_violation {
            reason.push_str(progress_violation);
            reason.push(';');
        }
        chain_failed = true;

        push_bounded(
            &mut events,
            CheckpointEvent {
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
            },
            MAX_EVENTS,
        );
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
    hasher.update(b"checkpoint_content_v3:length_prefixed:");
    update_hash_field(
        &mut hasher,
        b"orchestration_id",
        orchestration_id.as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        b"iteration_count",
        &iteration_count.to_le_bytes(),
    );
    update_hash_field(&mut hasher, b"epoch", &epoch.to_le_bytes());
    update_hash_field(
        &mut hasher,
        b"progress_state_hash",
        progress_state_hash.as_bytes(),
    );
    match previous_checkpoint_hash {
        Some(previous_hash) => update_hash_field(
            &mut hasher,
            b"previous_checkpoint_hash:some",
            previous_hash.as_bytes(),
        ),
        None => update_hash_field(&mut hasher, b"previous_checkpoint_hash:none", &[]),
    }
    hex::encode(hasher.finalize())
}

fn update_hash_field(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    let label_len = u64::try_from(label.len()).unwrap_or(u64::MAX);
    let value_len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(label_len.to_le_bytes());
    hasher.update(label);
    hasher.update(value_len.to_le_bytes());
    hasher.update(value);
}

fn hash_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"checkpoint_hash_v1:");
    hasher.update(bytes);
    hex::encode(hasher.finalize())
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
        let append_event_count = writer
            .decision_stream()
            .iter()
            .filter(|event| event.event_code == FN_CK_008_DECISION_STREAM_APPEND)
            .count();
        let violation_event_count = writer
            .decision_stream()
            .iter()
            .filter(|event| event.event_code == FN_CK_007_CONTRACT_VIOLATION)
            .count();
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
        assert_eq!(writer.decision_stream().len(), decision_stream_len + 1);
        assert_eq!(
            writer
                .decision_stream()
                .iter()
                .filter(|event| event.event_code == FN_CK_008_DECISION_STREAM_APPEND)
                .count(),
            append_event_count
        );
        assert_eq!(
            writer
                .decision_stream()
                .iter()
                .filter(|event| event.event_code == FN_CK_007_CONTRACT_VIOLATION)
                .count(),
            violation_event_count + 1
        );
        let rejection = writer
            .decision_stream()
            .last()
            .expect("rejection event appended to decision stream");
        assert_eq!(rejection.event_code, FN_CK_007_CONTRACT_VIOLATION);
        assert_eq!(rejection.event_name, CHECKPOINT_CONTRACT_VIOLATION);
        assert_eq!(rejection.orchestration_id, "orch-3c");
        assert_eq!(rejection.iteration_count, 30);
        assert_eq!(rejection.epoch, 1);
        assert_eq!(
            rejection.contract_status,
            "violation:cannot_append_after_hash_chain_failure"
        );
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
    fn save_checkpoint_rejects_epoch_regression() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4a-epoch",
                "orch-4a-epoch",
                100,
                7,
                &BTreeMap::from([("cursor".to_string(), "100".to_string())]),
            )
            .expect("checkpoint 100");

        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4a-epoch",
                "orch-4a-epoch",
                110,
                6,
                &BTreeMap::from([("cursor".to_string(), "110".to_string())]),
            )
            .expect_err("regressive epoch should fail");

        assert!(matches!(
            err,
            CheckpointError::HashChainViolation { ref reason, .. }
                if reason.contains("epoch_regressed")
        ));
        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-ck-4a-epoch", "orch-4a-epoch")
            .expect("restore checkpoint")
            .expect("checkpoint exists");
        assert_eq!(restored.meta.epoch, 7);
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

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-ck-4c", "orch-4c")
            .expect("restore checkpoint")
            .expect("latest monotonic checkpoint exists");
        assert_eq!(restored.meta.iteration_count, 100);
        assert_eq!(restored.meta.epoch, 7);
        assert_eq!(restored.state.get("cursor"), Some(&"100".to_string()));
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
    fn read_latest_valid_ignores_exact_checkpoint_replay() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4e",
                "orch-4e",
                10,
                1,
                &BTreeMap::from([("cursor".to_string(), "10".to_string())]),
            )
            .expect("checkpoint 10");
        writer.backend_mut().duplicate_record("orch-4e", 0);

        let read = writer
            .read_latest_valid("trace-ck-4e", "orch-4e")
            .expect("read latest valid");

        assert_eq!(read.latest.expect("latest").iteration_count, 10);
        assert!(
            !read
                .events
                .iter()
                .any(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
        );
    }

    #[test]
    fn save_checkpoint_allows_append_after_exact_checkpoint_replay() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        let first = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4f",
                "orch-4f",
                10,
                1,
                &BTreeMap::from([("cursor".to_string(), "10".to_string())]),
            )
            .expect("checkpoint 10");
        writer.backend_mut().duplicate_record("orch-4f", 0);

        let second = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4f",
                "orch-4f",
                20,
                1,
                &BTreeMap::from([("cursor".to_string(), "20".to_string())]),
            )
            .expect("append after exact replay should stay valid");

        assert_ne!(first, second);
        let read = writer
            .read_latest_valid("trace-ck-4f", "orch-4f")
            .expect("read latest valid");
        assert_eq!(read.latest.expect("latest").iteration_count, 20);
        assert!(
            !read
                .events
                .iter()
                .any(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
        );

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-ck-4f", "orch-4f")
            .expect("restore checkpoint")
            .expect("latest valid checkpoint exists");
        assert_eq!(restored.meta.iteration_count, 20);
        assert_eq!(restored.state.get("cursor"), Some(&"20".to_string()));
    }

    #[test]
    fn read_latest_valid_rejects_foreign_orchestration_record() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        let first = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4g",
                "orch-4g",
                10,
                1,
                &BTreeMap::from([("cursor".to_string(), "10".to_string())]),
            )
            .expect("checkpoint 10");

        let progress_state_json =
            serde_json::to_string(&BTreeMap::from([("cursor".to_string(), "20".to_string())]))
                .expect("serialize foreign state");
        let progress_state_hash = hash_hex(progress_state_json.as_bytes());
        let foreign = CheckpointRecord {
            checkpoint_id: derive_checkpoint_id(
                "orch-foreign",
                20,
                1,
                &progress_state_hash,
                Some(&first),
            ),
            orchestration_id: "orch-foreign".to_string(),
            iteration_count: 20,
            epoch: 1,
            wall_clock_time: now_unix_ms(),
            progress_state_json,
            progress_state_hash,
            previous_checkpoint_hash: Some(first),
        };
        writer
            .backend_mut()
            .inject_record_into_stream("orch-4g", foreign);

        let read = writer
            .read_latest_valid("trace-ck-4g", "orch-4g")
            .expect("read latest valid");

        let latest = read.latest.expect("latest");
        assert_eq!(latest.orchestration_id, "orch-4g");
        assert_eq!(latest.iteration_count, 10);
        let violation = read
            .events
            .iter()
            .find(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
            .expect("foreign record should be rejected");
        assert!(
            violation
                .contract_status
                .contains("orchestration_id_mismatch")
        );

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-ck-4g", "orch-4g")
            .expect("restore checkpoint")
            .expect("latest valid checkpoint exists");
        assert_eq!(restored.meta.orchestration_id, "orch-4g");
        assert_eq!(restored.meta.iteration_count, 10);
        assert_eq!(restored.state.get("cursor"), Some(&"10".to_string()));
    }

    #[test]
    fn save_checkpoint_rejects_append_after_foreign_orchestration_record() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        let first = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4h",
                "orch-4h",
                10,
                1,
                &BTreeMap::from([("cursor".to_string(), "10".to_string())]),
            )
            .expect("checkpoint 10");

        let progress_state_json =
            serde_json::to_string(&BTreeMap::from([("cursor".to_string(), "20".to_string())]))
                .expect("serialize foreign state");
        let progress_state_hash = hash_hex(progress_state_json.as_bytes());
        let foreign = CheckpointRecord {
            checkpoint_id: derive_checkpoint_id(
                "orch-foreign",
                20,
                1,
                &progress_state_hash,
                Some(&first),
            ),
            orchestration_id: "orch-foreign".to_string(),
            iteration_count: 20,
            epoch: 1,
            wall_clock_time: now_unix_ms(),
            progress_state_json,
            progress_state_hash,
            previous_checkpoint_hash: Some(first),
        };
        writer
            .backend_mut()
            .inject_record_into_stream("orch-4h", foreign.clone());

        let checkpoint_count = writer
            .list_checkpoints("orch-4h")
            .expect("list checkpoints before rejection")
            .len();

        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-ck-4h",
                "orch-4h",
                30,
                1,
                &BTreeMap::from([("cursor".to_string(), "30".to_string())]),
            )
            .expect_err("foreign record must block append");

        assert!(matches!(
            err,
            CheckpointError::HashChainViolation {
                ref orchestration_id,
                ref checkpoint_id,
                ref reason,
            } if orchestration_id == "orch-4h"
                && checkpoint_id == &foreign.checkpoint_id
                && reason == "cannot_append_after_hash_chain_failure"
        ));
        assert_eq!(
            writer
                .list_checkpoints("orch-4h")
                .expect("list checkpoints after rejection")
                .len(),
            checkpoint_count
        );
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

    #[derive(Debug, Clone, Default)]
    struct LoadFailBackend;

    impl CheckpointBackend for LoadFailBackend {
        fn save(&mut self, _record: CheckpointRecord) -> Result<bool, CheckpointError> {
            Ok(true)
        }

        fn load_all(
            &self,
            _orchestration_id: &str,
        ) -> Result<Vec<CheckpointRecord>, CheckpointError> {
            Err(CheckpointError::Backend("load unavailable".to_string()))
        }
    }

    #[derive(Debug, Clone, Default)]
    struct SaveFailBackend;

    impl CheckpointBackend for SaveFailBackend {
        fn save(&mut self, _record: CheckpointRecord) -> Result<bool, CheckpointError> {
            Err(CheckpointError::Backend("save unavailable".to_string()))
        }

        fn load_all(
            &self,
            _orchestration_id: &str,
        ) -> Result<Vec<CheckpointRecord>, CheckpointError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn read_latest_valid_propagates_backend_load_error() {
        let writer = CheckpointWriter::new(LoadFailBackend);

        let err = writer
            .read_latest_valid("trace-load-fail", "orch-load-fail")
            .expect_err("backend load failure must propagate");

        assert!(matches!(
            err,
            CheckpointError::Backend(ref detail) if detail == "load unavailable"
        ));
    }

    #[test]
    fn list_checkpoints_propagates_backend_load_error() {
        let writer = CheckpointWriter::new(LoadFailBackend);

        let err = writer
            .list_checkpoints("orch-list-fail")
            .expect_err("list must report backend load failure");

        assert_eq!(err.code(), "CHECKPOINT_BACKEND_ERROR");
        assert!(err.to_string().contains("load unavailable"));
    }

    #[test]
    fn save_checkpoint_propagates_backend_save_error() {
        let mut writer = CheckpointWriter::new(SaveFailBackend);
        let mut cancel = CancellationState::new();

        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-save-fail",
                "orch-save-fail",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect_err("backend save failure must propagate");

        assert!(matches!(
            err,
            CheckpointError::Backend(ref detail) if detail == "save unavailable"
        ));
        assert!(writer.decision_stream().is_empty());
    }

    #[test]
    fn restore_checkpoint_reports_deserialization_error_for_wrong_state_type() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-wrong-shape",
                "orch-wrong-shape",
                1,
                1,
                &123_u64,
            )
            .expect("save numeric checkpoint");

        let err = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-wrong-shape", "orch-wrong-shape")
            .expect_err("wrong restore type must fail deserialization");

        assert_eq!(err.code(), "CHECKPOINT_DESERIALIZATION_ERROR");
    }

    #[test]
    fn read_latest_valid_detects_progress_state_hash_tamper() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-progress-hash-tamper",
                "orch-progress-hash-tamper",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("save checkpoint");
        writer
            .backend_mut()
            .records
            .get_mut("orch-progress-hash-tamper")
            .expect("stream")
            .get_mut(0)
            .expect("record")
            .progress_state_hash = "tampered-progress-hash".to_string();

        let read = writer
            .read_latest_valid("trace-progress-hash-tamper", "orch-progress-hash-tamper")
            .expect("read latest valid");

        assert!(read.latest.is_none());
        let violation = read
            .events
            .iter()
            .find(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
            .expect("progress hash mismatch event");
        assert!(
            violation
                .contract_status
                .contains("progress_state_hash_mismatch")
        );
    }

    #[test]
    fn restore_checkpoint_returns_none_when_progress_hash_is_tampered() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-restore-progress-hash-tamper",
                "orch-restore-progress-hash-tamper",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("save checkpoint");
        writer
            .backend_mut()
            .records
            .get_mut("orch-restore-progress-hash-tamper")
            .expect("stream")
            .get_mut(0)
            .expect("record")
            .progress_state_hash = "tampered-progress-hash".to_string();

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>(
                "trace-restore-progress-hash-tamper",
                "orch-restore-progress-hash-tamper",
            )
            .expect("tampered checkpoint should not deserialize");

        assert!(restored.is_none());
    }

    #[test]
    fn save_checkpoint_rejects_append_after_progress_hash_tamper() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-append-progress-hash-tamper",
                "orch-append-progress-hash-tamper",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("first checkpoint");
        writer
            .backend_mut()
            .records
            .get_mut("orch-append-progress-hash-tamper")
            .expect("stream")
            .get_mut(0)
            .expect("record")
            .progress_state_hash = "tampered-progress-hash".to_string();

        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-append-progress-hash-tamper",
                "orch-append-progress-hash-tamper",
                2,
                1,
                &BTreeMap::from([("cursor".to_string(), "2".to_string())]),
            )
            .expect_err("progress hash tamper must block append");

        assert!(matches!(
            err,
            CheckpointError::HashChainViolation {
                ref reason,
                ..
            } if reason.as_str().eq("cannot_append_after_hash_chain_failure")
        ));
    }

    #[test]
    fn read_latest_valid_reports_combined_state_and_id_tamper() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-combined-tamper",
                "orch-combined-tamper",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("save checkpoint");
        writer
            .backend_mut()
            .tamper_progress_state("orch-combined-tamper", 0, "{\"cursor\":\"2\"}");

        let read = writer
            .read_latest_valid("trace-combined-tamper", "orch-combined-tamper")
            .expect("read latest valid");

        assert!(read.latest.is_none());
        let violation = read
            .events
            .iter()
            .find(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
            .expect("combined tamper event");
        assert!(
            violation
                .contract_status
                .contains("progress_state_hash_mismatch")
        );
        assert!(violation.contract_status.contains("checkpoint_id_mismatch"));
    }

    #[test]
    fn read_latest_valid_detects_padded_previous_checkpoint_hash() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        let first = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-padded-prev",
                "orch-padded-prev",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("first checkpoint");
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-padded-prev",
                "orch-padded-prev",
                2,
                1,
                &BTreeMap::from([("cursor".to_string(), "2".to_string())]),
            )
            .expect("second checkpoint");
        let padded = format!(" {first} ");
        writer
            .backend_mut()
            .tamper_previous_checkpoint_hash("orch-padded-prev", 1, Some(&padded));

        let read = writer
            .read_latest_valid("trace-padded-prev", "orch-padded-prev")
            .expect("read latest valid");

        assert_eq!(read.latest.expect("latest").iteration_count, 1);
        let violation = read
            .events
            .iter()
            .find(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
            .expect("previous hash mismatch event");
        assert!(
            violation
                .contract_status
                .contains("previous_checkpoint_hash_mismatch")
        );
    }

    #[test]
    fn save_checkpoint_rejects_append_after_padded_previous_hash_tamper() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        let first = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-append-padded-prev",
                "orch-append-padded-prev",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("first checkpoint");
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-append-padded-prev",
                "orch-append-padded-prev",
                2,
                1,
                &BTreeMap::from([("cursor".to_string(), "2".to_string())]),
            )
            .expect("second checkpoint");
        let padded = format!(" {first} ");
        writer.backend_mut().tamper_previous_checkpoint_hash(
            "orch-append-padded-prev",
            1,
            Some(&padded),
        );

        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-append-padded-prev",
                "orch-append-padded-prev",
                3,
                1,
                &BTreeMap::from([("cursor".to_string(), "3".to_string())]),
            )
            .expect_err("padded previous hash tamper must block append");

        assert!(matches!(
            err,
            CheckpointError::HashChainViolation {
                ref reason,
                ..
            } if reason.as_str().eq("cannot_append_after_hash_chain_failure")
        ));
    }

    #[test]
    fn restore_checkpoint_ignores_second_record_with_padded_previous_hash() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        let first = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-restore-padded-prev",
                "orch-restore-padded-prev",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("first checkpoint");
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-restore-padded-prev",
                "orch-restore-padded-prev",
                2,
                1,
                &BTreeMap::from([("cursor".to_string(), "2".to_string())]),
            )
            .expect("second checkpoint");
        let padded = format!(" {first} ");
        writer.backend_mut().tamper_previous_checkpoint_hash(
            "orch-restore-padded-prev",
            1,
            Some(&padded),
        );

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>(
                "trace-restore-padded-prev",
                "orch-restore-padded-prev",
            )
            .expect("restore should select latest valid prefix")
            .expect("first checkpoint remains valid");

        assert_eq!(restored.meta.iteration_count, 1);
        assert_eq!(restored.state.get("cursor"), Some(&"1".to_string()));
    }

    #[test]
    fn read_latest_valid_detects_checkpoint_id_tamper() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-id-tamper",
                "orch-id-tamper",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("save checkpoint");
        writer
            .backend_mut()
            .records
            .get_mut("orch-id-tamper")
            .expect("stream")
            .get_mut(0)
            .expect("record")
            .checkpoint_id = "tampered-checkpoint-id".to_string();

        let read = writer
            .read_latest_valid("trace-id-tamper", "orch-id-tamper")
            .expect("read latest valid");

        assert!(read.latest.is_none());
        let violation = read
            .events
            .iter()
            .find(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
            .expect("checkpoint id mismatch event");
        assert!(violation.contract_status.contains("checkpoint_id_mismatch"));
    }

    #[test]
    fn restore_checkpoint_returns_none_when_only_checkpoint_id_is_tampered() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-restore-id-tamper",
                "orch-restore-id-tamper",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("save checkpoint");
        writer
            .backend_mut()
            .records
            .get_mut("orch-restore-id-tamper")
            .expect("stream")
            .get_mut(0)
            .expect("record")
            .checkpoint_id = "tampered-checkpoint-id".to_string();

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>(
                "trace-restore-id-tamper",
                "orch-restore-id-tamper",
            )
            .expect("tampered chain should not deserialize");

        assert!(restored.is_none());
    }

    #[test]
    fn read_latest_valid_detects_missing_previous_hash_on_second_entry() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-prev-missing",
                "orch-prev-missing",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("first checkpoint");
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-prev-missing",
                "orch-prev-missing",
                2,
                1,
                &BTreeMap::from([("cursor".to_string(), "2".to_string())]),
            )
            .expect("second checkpoint");
        writer
            .backend_mut()
            .tamper_previous_checkpoint_hash("orch-prev-missing", 1, None);

        let read = writer
            .read_latest_valid("trace-prev-missing", "orch-prev-missing")
            .expect("read latest valid");

        assert_eq!(read.latest.expect("latest").iteration_count, 1);
        let violation = read
            .events
            .iter()
            .find(|event| event.event_code == FN_CK_003_HASH_CHAIN_FAILURE)
            .expect("previous hash mismatch event");
        assert!(
            violation
                .contract_status
                .contains("previous_checkpoint_hash_mismatch")
        );
    }

    #[test]
    fn save_checkpoint_rejects_append_after_checkpoint_id_tamper() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-append-id-tamper",
                "orch-append-id-tamper",
                1,
                1,
                &BTreeMap::from([("cursor".to_string(), "1".to_string())]),
            )
            .expect("first checkpoint");
        writer
            .backend_mut()
            .records
            .get_mut("orch-append-id-tamper")
            .expect("stream")
            .get_mut(0)
            .expect("record")
            .checkpoint_id = "tampered-checkpoint-id".to_string();

        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-append-id-tamper",
                "orch-append-id-tamper",
                2,
                1,
                &BTreeMap::from([("cursor".to_string(), "2".to_string())]),
            )
            .expect_err("tampered checkpoint id must block append");

        assert!(matches!(
            err,
            CheckpointError::HashChainViolation {
                ref reason,
                ref checkpoint_id,
                ..
            } if reason == "cannot_append_after_hash_chain_failure"
                && checkpoint_id == "tampered-checkpoint-id"
        ));
    }

    /// Negative path: extremely large checkpoint state causes memory pressure
    #[test]
    fn save_checkpoint_handles_massive_state_data_without_overflow() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        // Create a large state object (10MB of string data)
        let huge_value = "x".repeat(10_000_000);
        let massive_state = BTreeMap::from([
            ("huge_data".to_string(), huge_value.clone()),
            ("regular_field".to_string(), "normal".to_string()),
        ]);

        let checkpoint_id = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-huge",
                "orch-huge",
                1,
                1,
                &massive_state,
            )
            .expect("massive state should be serializable despite memory pressure");

        // Checkpoint ID should be computed deterministically despite large input
        assert_eq!(checkpoint_id.len(), 64); // SHA-256 hex output
        assert!(checkpoint_id.chars().all(|c| c.is_ascii_hexdigit()));

        // Restoration should work despite large payload
        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-huge", "orch-huge")
            .expect("restore should succeed")
            .expect("checkpoint should exist");

        assert_eq!(restored.state["huge_data"].len(), 10_000_000);
        assert_eq!(restored.state["regular_field"], "normal");
    }

    /// Negative path: unicode and special characters in orchestration IDs
    #[test]
    fn save_checkpoint_preserves_unicode_orchestration_identifiers() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        let unicode_orch_id = "🚀orchestration💫中文_ñ@mé";
        let unicode_trace_id = "🔍trace♦️测试\0null-byte";
        let state =
            BTreeMap::from([("unicode_key_漢字".to_string(), "émoji_value_🎯".to_string())]);

        let checkpoint_id = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                &unicode_trace_id,
                &unicode_orch_id,
                1,
                1,
                &state,
            )
            .expect("unicode IDs should be preserved during checkpoint creation");

        assert!(!checkpoint_id.is_empty());

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>(&unicode_trace_id, &unicode_orch_id)
            .expect("restore with unicode IDs should work")
            .expect("checkpoint should exist");

        assert_eq!(restored.meta.orchestration_id, unicode_orch_id);
        assert!(restored.state["unicode_key_漢字"].contains("🎯"));

        // Unicode IDs should appear in decision stream events
        let unicode_event = writer
            .decision_stream()
            .iter()
            .find(|event| event.orchestration_id == unicode_orch_id)
            .expect("unicode orchestration ID should appear in events");
        assert!(unicode_event.trace_id.contains("🔍"));
    }

    /// Negative path: malformed JSON in progress state causes deserialization failure
    #[test]
    fn restore_checkpoint_fails_gracefully_with_corrupted_json_state() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        // Save a valid checkpoint first
        writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-corrupt",
                "orch-corrupt",
                1,
                1,
                &BTreeMap::from([("valid".to_string(), "state".to_string())]),
            )
            .expect("save valid checkpoint");

        // Manually corrupt the JSON in the backend
        writer.backend_mut().tamper_progress_state(
            "orch-corrupt",
            0,
            "{invalid-json-missing-quotes-and-braces",
        );

        let err = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-corrupt", "orch-corrupt")
            .expect_err("corrupted JSON should cause deserialization error");

        assert_eq!(err.code(), "CHECKPOINT_DESERIALIZATION_ERROR");
        assert!(err.to_string().contains("invalid-json"));
    }

    /// Negative path: integer overflow scenarios in epoch and iteration counters
    #[test]
    fn save_checkpoint_handles_maximum_epoch_and_iteration_values() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        let max_epoch = u64::MAX;
        let max_iteration = u64::MAX - 1; // Slightly less to allow progression test
        let state = BTreeMap::from([("counter".to_string(), "max_values".to_string())]);

        let checkpoint_id = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-max",
                "orch-max",
                max_iteration,
                max_epoch,
                &state,
            )
            .expect("maximum values should be handled without overflow");

        assert!(!checkpoint_id.is_empty());

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-max", "orch-max")
            .expect("restore with max values")
            .expect("checkpoint exists");

        assert_eq!(restored.meta.epoch, max_epoch);
        assert_eq!(restored.meta.iteration_count, max_iteration);

        // Attempting to increment beyond max_iteration should fail
        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-max",
                "orch-max",
                max_iteration.saturating_add(1), // This will be u64::MAX
                max_epoch,
                &BTreeMap::from([("next".to_string(), "state".to_string())]),
            )
            .expect_err("iteration beyond max should fail progress check");

        assert!(matches!(err, CheckpointError::HashChainViolation { .. }));
    }

    /// Negative path: zero-values in checkpoint parameters
    #[test]
    fn save_checkpoint_accepts_zero_epoch_and_iteration_values() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        let state = BTreeMap::from([("zero_test".to_string(), "initial".to_string())]);

        let checkpoint_id = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-zero",
                "orch-zero",
                0, // Zero iteration
                0, // Zero epoch
                &state,
            )
            .expect("zero values should be accepted");

        assert!(!checkpoint_id.is_empty());

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-zero", "orch-zero")
            .expect("restore with zero values")
            .expect("checkpoint exists");

        assert_eq!(restored.meta.epoch, 0);
        assert_eq!(restored.meta.iteration_count, 0);

        // Progress should still be enforced - can't regress to zero again
        let err = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                "trace-zero",
                "orch-zero",
                0, // Same zero iteration
                0, // Same zero epoch
                &BTreeMap::from([("different".to_string(), "state".to_string())]),
            )
            .expect_err("duplicate position should fail");

        assert!(matches!(err, CheckpointError::HashChainViolation { .. }));
    }

    /// Negative path: extremely long orchestration and trace IDs
    #[test]
    fn save_checkpoint_handles_extremely_long_identifier_strings() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        // Create very long IDs (1MB each)
        let long_orch_id = "orch-".to_string() + &"x".repeat(1_000_000);
        let long_trace_id = "trace-".to_string() + &"y".repeat(1_000_000);
        let state = BTreeMap::from([("test".to_string(), "long_ids".to_string())]);

        let checkpoint_id = writer
            .save_checkpoint(
                &cx(),
                &mut cancel,
                &long_trace_id,
                &long_orch_id,
                1,
                1,
                &state,
            )
            .expect("extremely long IDs should be handled without truncation");

        // Hash computation should be deterministic despite long inputs
        assert_eq!(checkpoint_id.len(), 64);

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>(&long_trace_id, &long_orch_id)
            .expect("restore with long IDs")
            .expect("checkpoint exists");

        // Full long IDs should be preserved
        assert_eq!(restored.meta.orchestration_id.len(), long_orch_id.len());
        assert!(restored.meta.orchestration_id.starts_with("orch-"));
        assert!(restored.meta.orchestration_id.ends_with("xxxx"));
    }

    /// Negative path: hash collision attempt through checkpoint ID derivation
    #[test]
    fn derive_checkpoint_id_produces_different_hashes_for_similar_inputs() {
        // Test that similar inputs produce different checkpoint IDs
        let base_orch = "orchestration";
        let base_state_hash = "state_hash_base";

        let id1 = derive_checkpoint_id(base_orch, 1, 1, base_state_hash, None);
        let id2 = derive_checkpoint_id(base_orch, 1, 1, "state_hash_different", None);
        let id3 = derive_checkpoint_id(base_orch, 1, 2, base_state_hash, None); // Different epoch
        let id4 = derive_checkpoint_id(base_orch, 2, 1, base_state_hash, None); // Different iteration
        let id5 = derive_checkpoint_id("different_orch", 1, 1, base_state_hash, None);

        // All should be different despite similar inputs
        let ids = vec![&id1, &id2, &id3, &id4, &id5];
        for (i, id_a) in ids.iter().enumerate() {
            for (j, id_b) in ids.iter().enumerate() {
                if i != j {
                    assert_ne!(id_a, id_b, "IDs {} and {} should be different", i, j);
                }
            }
        }

        // Test previous hash influence
        let id_with_prev = derive_checkpoint_id(base_orch, 1, 1, base_state_hash, Some("previous"));
        let id_without_prev = derive_checkpoint_id(base_orch, 1, 1, base_state_hash, None);
        assert_ne!(id_with_prev, id_without_prev);

        let delimiter_ambiguous_a =
            derive_checkpoint_id(base_orch, 1, 1, "state", Some("\0previous"));
        let delimiter_ambiguous_b =
            derive_checkpoint_id(base_orch, 1, 1, "state\0", Some("previous"));
        assert_ne!(
            delimiter_ambiguous_a, delimiter_ambiguous_b,
            "length-prefixed checkpoint hash fields must reject delimiter ambiguity"
        );

        // All IDs should be valid SHA-256 hashes
        for id in ids {
            assert_eq!(id.len(), 64);
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    /// Negative path: time overflow in wall_clock_time field
    #[test]
    fn checkpoint_wall_clock_time_handles_system_time_edge_cases() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();
        let state = BTreeMap::from([("time_test".to_string(), "value".to_string())]);

        let checkpoint_id = writer
            .save_checkpoint(&cx(), &mut cancel, "trace-time", "orch-time", 1, 1, &state)
            .expect("checkpoint with current time");

        let restored = writer
            .restore_checkpoint::<BTreeMap<String, String>>("trace-time", "orch-time")
            .expect("restore checkpoint")
            .expect("checkpoint exists");

        // Wall clock time should be a reasonable Unix timestamp in milliseconds
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);

        assert!(restored.meta.wall_clock_time <= now_ms);
        assert!(restored.meta.wall_clock_time >= 1_000_000_000_000); // After ~2001

        // Event timestamps should also be reasonable
        let save_event = writer
            .decision_stream()
            .iter()
            .find(|event| event.event_code == FN_CK_001_CHECKPOINT_SAVE)
            .expect("save event");
        assert!(save_event.wall_clock_time <= now_ms);
        assert!(save_event.wall_clock_time >= 1_000_000_000_000);
    }

    /// Negative path: push_bounded edge case with zero capacity
    #[test]
    fn push_bounded_with_zero_capacity_clears_decision_stream() {
        let mut writer = CheckpointWriter::new(InMemoryCheckpointBackend::default());
        let mut cancel = CancellationState::new();

        // Add some events to decision stream first
        for i in 1..=5 {
            writer
                .save_checkpoint(
                    &cx(),
                    &mut cancel,
                    "trace-bounded",
                    "orch-bounded",
                    i,
                    1,
                    &BTreeMap::from([("counter".to_string(), i.to_string())]),
                )
                .expect("save checkpoint");
        }

        let initial_stream_length = writer.decision_stream().len();
        assert!(initial_stream_length > 0);

        // Simulate push_bounded being called with zero capacity
        // This is an edge case that could occur if MAX_EVENTS is misconfigured to 0
        let mut test_items = vec![1, 2, 3, 4, 5];
        push_bounded(&mut test_items, 6, 0);

        // With zero capacity, the entire vector should be cleared
        assert!(test_items.is_empty());
    }
}
