//! bd-2wsm: Epoch transition barrier protocol across core services.
//!
//! The epoch transition barrier is the coordination protocol ensuring all core
//! services drain in-flight work and acknowledge readiness before the system
//! commits to a new epoch. Without a barrier, split-brain conditions arise where
//! some services operate under epoch N while others have moved to epoch N+1.
//!
//! # Protocol Phases
//!
//! 1. **Propose** — leader announces intent to transition to target epoch.
//! 2. **Drain** — each participant drains in-flight work and sends an ACK.
//! 3. **Commit** — leader commits after all drain ACKs (advances epoch atomically).
//!    OR **Abort** — leader aborts if any drain times out or fails.
//!
//! # Invariants
//!
//! - INV-BARRIER-ALL-ACK: commit requires drain ACKs from every registered participant
//! - INV-BARRIER-NO-PARTIAL: after barrier completes, system is in exactly one epoch
//! - INV-BARRIER-ABORT-SAFE: on abort, no participant operates under the new epoch
//! - INV-BARRIER-SERIALIZED: concurrent barrier attempts are rejected
//! - INV-BARRIER-TRANSCRIPT: every barrier produces a complete audit transcript
//! - INV-BARRIER-TIMEOUT: missing ACKs within timeout trigger abort path

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Schema version for barrier transcripts.
pub const SCHEMA_VERSION: &str = "eb-v1.0";

/// Default global barrier timeout in milliseconds.
pub const DEFAULT_BARRIER_TIMEOUT_MS: u64 = crate::config::timeouts::FLEET_BARRIER_TIMEOUT_MS;

/// Default per-participant drain timeout in milliseconds.
pub const DEFAULT_DRAIN_TIMEOUT_MS: u64 =
    crate::config::timeouts::EPOCH_TRANSITION_DRAIN_TIMEOUT_MS;

use crate::capacity_defaults::aliases::MAX_BARRIER_HISTORY;

/// Max number of transcript entries per barrier before oldest-first eviction.
const MAX_TRANSCRIPT_ENTRIES: usize = 4096;

// ---- Event codes ----

pub mod event_codes {
    /// INV-BARRIER-TRANSCRIPT
    pub const BARRIER_PROPOSED: &str = "BARRIER_PROPOSED";
    pub const BARRIER_DRAIN_ACK: &str = "BARRIER_DRAIN_ACK";
    pub const BARRIER_COMMITTED: &str = "BARRIER_COMMITTED";
    pub const BARRIER_ABORTED: &str = "BARRIER_ABORTED";
    pub const BARRIER_TIMEOUT: &str = "BARRIER_TIMEOUT";
    pub const BARRIER_DRAIN_FAILED: &str = "BARRIER_DRAIN_FAILED";
    pub const BARRIER_ABORT_SENT: &str = "BARRIER_ABORT_SENT";
    pub const BARRIER_CONCURRENT_REJECTED: &str = "BARRIER_CONCURRENT_REJECTED";
    pub const BARRIER_TRANSCRIPT_EXPORTED: &str = "BARRIER_TRANSCRIPT_EXPORTED";
    pub const BARRIER_PARTICIPANT_REGISTERED: &str = "BARRIER_PARTICIPANT_REGISTERED";
}

// ---- Error codes ----

pub mod error_codes {
    pub const ERR_BARRIER_CONCURRENT: &str = "ERR_BARRIER_CONCURRENT";
    pub const ERR_BARRIER_NO_PARTICIPANTS: &str = "ERR_BARRIER_NO_PARTICIPANTS";
    pub const ERR_BARRIER_NOT_ALL_ACKED: &str = "ERR_BARRIER_NOT_ALL_ACKED";
    pub const ERR_BARRIER_TIMEOUT: &str = "ERR_BARRIER_TIMEOUT";
    pub const ERR_BARRIER_DRAIN_FAILED: &str = "ERR_BARRIER_DRAIN_FAILED";
    pub const ERR_BARRIER_ALREADY_COMPLETE: &str = "ERR_BARRIER_ALREADY_COMPLETE";
    pub const ERR_BARRIER_INVALID_PHASE: &str = "ERR_BARRIER_INVALID_PHASE";
    pub const ERR_BARRIER_UNKNOWN_PARTICIPANT: &str = "ERR_BARRIER_UNKNOWN_PARTICIPANT";
    pub const ERR_BARRIER_ID_MISMATCH: &str = "ERR_BARRIER_ID_MISMATCH";
    pub const ERR_BARRIER_EPOCH_MISMATCH: &str = "ERR_BARRIER_EPOCH_MISMATCH";
    pub const ERR_BARRIER_EPOCH_OVERFLOW: &str = "ERR_BARRIER_EPOCH_OVERFLOW";
    pub const ERR_BARRIER_ID_OVERFLOW: &str = "ERR_BARRIER_ID_OVERFLOW";
}

// ---- Core types ----

/// Unique identifier for a barrier instance.
pub type BarrierId = String;

/// Unique identifier for a barrier participant.
pub type ParticipantId = String;

/// Phases of the epoch transition barrier state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BarrierPhase {
    /// Initial state: leader has proposed a transition.
    Proposed,
    /// Draining: waiting for participant ACKs.
    Draining,
    /// All ACKs received; epoch committed.
    Committed,
    /// Barrier aborted (timeout or failure).
    Aborted,
}

impl fmt::Display for BarrierPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proposed => write!(f, "Proposed"),
            Self::Draining => write!(f, "Draining"),
            Self::Committed => write!(f, "Committed"),
            Self::Aborted => write!(f, "Aborted"),
        }
    }
}

/// Result of a participant's drain operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainAck {
    pub participant_id: ParticipantId,
    pub barrier_id: BarrierId,
    pub drained_items: u64,
    pub elapsed_ms: u64,
    pub trace_id: String,
}

/// Reason a barrier was aborted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    /// One or more participants timed out during drain.
    Timeout {
        missing_participants: Vec<ParticipantId>,
    },
    /// A participant's drain operation failed.
    DrainFailed {
        participant_id: ParticipantId,
        detail: String,
    },
    /// Explicit cancellation by the leader.
    Cancelled { detail: String },
}

impl fmt::Display for AbortReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout {
                missing_participants,
            } => {
                write!(
                    f,
                    "timeout: missing ACKs from {}",
                    missing_participants.join(", ")
                )
            }
            Self::DrainFailed {
                participant_id,
                detail,
            } => {
                write!(f, "drain failed: {participant_id}: {detail}")
            }
            Self::Cancelled { detail } => write!(f, "cancelled: {detail}"),
        }
    }
}

/// Errors from barrier operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierError {
    /// A barrier is already in progress (INV-BARRIER-SERIALIZED).
    ConcurrentBarrier { active_barrier_id: BarrierId },
    /// No participants registered.
    NoParticipants,
    /// Drain ACKs are still outstanding, but the barrier has not timed out yet.
    NotAllAcked { missing: Vec<ParticipantId> },
    /// Barrier timed out waiting for drain ACKs.
    Timeout {
        barrier_id: BarrierId,
        missing: Vec<ParticipantId>,
        elapsed_ms: u64,
    },
    /// A participant's drain failed.
    DrainFailed {
        barrier_id: BarrierId,
        participant_id: ParticipantId,
        detail: String,
    },
    /// Operation on a completed/aborted barrier.
    AlreadyComplete { barrier_id: BarrierId },
    /// Invalid phase transition attempted.
    InvalidPhase {
        barrier_id: BarrierId,
        current: BarrierPhase,
        attempted: BarrierPhase,
    },
    /// Unknown participant ID.
    UnknownParticipant { participant_id: ParticipantId },
    /// Drain ACK references the wrong barrier instance.
    BarrierIdMismatch {
        expected: BarrierId,
        provided: BarrierId,
    },
    /// Target epoch does not match expected next epoch.
    EpochMismatch { expected: u64, provided: u64 },
    /// Current epoch is already at the maximum representable epoch.
    EpochOverflow { current: u64 },
    /// Barrier ID counter cannot allocate another distinct barrier ID.
    BarrierIdOverflow { current_counter: u64 },
}

/// Result of attempting to commit a barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierCommitOutcome {
    /// All participants ACKed and the barrier committed successfully.
    Committed { target_epoch: u64 },
    /// The commit attempt auto-aborted the barrier instead of advancing.
    Aborted {
        current_epoch: u64,
        reason: AbortReason,
    },
}

impl BarrierError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ConcurrentBarrier { .. } => error_codes::ERR_BARRIER_CONCURRENT,
            Self::NoParticipants => error_codes::ERR_BARRIER_NO_PARTICIPANTS,
            Self::Timeout { .. } => error_codes::ERR_BARRIER_TIMEOUT,
            Self::DrainFailed { .. } => error_codes::ERR_BARRIER_DRAIN_FAILED,
            Self::AlreadyComplete { .. } => error_codes::ERR_BARRIER_ALREADY_COMPLETE,
            Self::InvalidPhase { .. } => error_codes::ERR_BARRIER_INVALID_PHASE,
            Self::UnknownParticipant { .. } => error_codes::ERR_BARRIER_UNKNOWN_PARTICIPANT,
            Self::BarrierIdMismatch { .. } => error_codes::ERR_BARRIER_ID_MISMATCH,
            Self::EpochMismatch { .. } => error_codes::ERR_BARRIER_EPOCH_MISMATCH,
            Self::EpochOverflow { .. } => error_codes::ERR_BARRIER_EPOCH_OVERFLOW,
            Self::BarrierIdOverflow { .. } => error_codes::ERR_BARRIER_ID_OVERFLOW,
            Self::NotAllAcked { .. } => error_codes::ERR_BARRIER_NOT_ALL_ACKED,
        }
    }
}

impl fmt::Display for BarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConcurrentBarrier { active_barrier_id } => {
                write!(
                    f,
                    "{}: barrier {} already active",
                    self.code(),
                    active_barrier_id
                )
            }
            Self::NoParticipants => write!(f, "{}: no participants registered", self.code()),
            Self::Timeout {
                barrier_id,
                missing,
                elapsed_ms,
            } => {
                write!(
                    f,
                    "{}: barrier {} timed out after {}ms, missing: {}",
                    self.code(),
                    barrier_id,
                    elapsed_ms,
                    missing.join(", ")
                )
            }
            Self::DrainFailed {
                barrier_id,
                participant_id,
                detail,
            } => {
                write!(
                    f,
                    "{}: barrier {} participant {} drain failed: {}",
                    self.code(),
                    barrier_id,
                    participant_id,
                    detail
                )
            }
            Self::AlreadyComplete { barrier_id } => {
                write!(
                    f,
                    "{}: barrier {} already complete",
                    self.code(),
                    barrier_id
                )
            }
            Self::InvalidPhase {
                barrier_id,
                current,
                attempted,
            } => {
                write!(
                    f,
                    "{}: barrier {} cannot transition from {} to {}",
                    self.code(),
                    barrier_id,
                    current,
                    attempted
                )
            }
            Self::UnknownParticipant { participant_id } => {
                write!(f, "{}: unknown participant {}", self.code(), participant_id)
            }
            Self::BarrierIdMismatch { expected, provided } => {
                write!(
                    f,
                    "{}: expected barrier {} but got {}",
                    self.code(),
                    expected,
                    provided
                )
            }
            Self::EpochMismatch { expected, provided } => {
                write!(
                    f,
                    "{}: expected target epoch {} but got {}",
                    self.code(),
                    expected,
                    provided
                )
            }
            Self::EpochOverflow { current } => {
                write!(
                    f,
                    "{}: current epoch {} cannot advance",
                    self.code(),
                    current
                )
            }
            Self::BarrierIdOverflow { current_counter } => {
                write!(
                    f,
                    "{}: barrier counter {} cannot allocate a distinct id",
                    self.code(),
                    current_counter
                )
            }
            Self::NotAllAcked { missing } => {
                write!(
                    f,
                    "{}: missing ACKs from {}",
                    self.code(),
                    missing.join(", ")
                )
            }
        }
    }
}

/// Configuration for the barrier protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BarrierConfig {
    /// Global barrier timeout ceiling in milliseconds.
    pub global_timeout_ms: u64,
    /// Default per-participant drain timeout in milliseconds.
    pub default_drain_timeout_ms: u64,
    /// Per-participant timeout overrides (participant_id -> timeout_ms).
    pub participant_timeouts: BTreeMap<String, u64>,
}

impl BarrierConfig {
    pub fn new(global_timeout_ms: u64, default_drain_timeout_ms: u64) -> Self {
        Self {
            global_timeout_ms,
            default_drain_timeout_ms,
            participant_timeouts: BTreeMap::new(),
        }
    }

    /// Get the effective drain timeout for a participant.
    pub fn drain_timeout_for(&self, participant_id: &str) -> u64 {
        self.participant_timeouts
            .get(participant_id)
            .copied()
            .unwrap_or(self.default_drain_timeout_ms)
            .min(self.global_timeout_ms)
    }

    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.global_timeout_ms == 0 {
            return Err("global_timeout_ms must be > 0".into());
        }
        if self.default_drain_timeout_ms == 0 {
            return Err("default_drain_timeout_ms must be > 0".into());
        }
        if self.default_drain_timeout_ms > self.global_timeout_ms {
            return Err("default_drain_timeout_ms exceeds global_timeout_ms".into());
        }
        for (pid, &t) in &self.participant_timeouts {
            if t == 0 {
                return Err(format!("timeout for participant {} must be > 0", pid));
            }
        }
        Ok(())
    }
}

impl Default for BarrierConfig {
    fn default() -> Self {
        Self::new(DEFAULT_BARRIER_TIMEOUT_MS, DEFAULT_DRAIN_TIMEOUT_MS)
    }
}

/// A single transcript entry recording a barrier event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub event_code: String,
    pub barrier_id: String,
    pub timestamp_ms: u64,
    pub detail: String,
    pub trace_id: String,
}

/// Complete barrier transcript for audit purposes.
/// INV-BARRIER-TRANSCRIPT
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BarrierTranscript {
    pub barrier_id: String,
    pub current_epoch: u64,
    pub target_epoch: u64,
    pub participant_count: usize,
    pub phase: BarrierPhase,
    pub entries: Vec<TranscriptEntry>,
    pub schema_version: String,
}

impl BarrierTranscript {
    fn new(
        barrier_id: &str,
        current_epoch: u64,
        target_epoch: u64,
        participant_count: usize,
    ) -> Self {
        Self {
            barrier_id: barrier_id.to_string(),
            current_epoch,
            target_epoch,
            participant_count,
            phase: BarrierPhase::Proposed,
            entries: Vec::new(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    fn record(&mut self, event_code: &str, detail: &str, timestamp_ms: u64, trace_id: &str) {
        push_bounded(
            &mut self.entries,
            TranscriptEntry {
                event_code: event_code.to_string(),
                barrier_id: self.barrier_id.clone(),
                timestamp_ms,
                detail: detail.to_string(),
                trace_id: trace_id.to_string(),
            },
            MAX_TRANSCRIPT_ENTRIES,
        );
    }

    /// Export transcript as JSONL string.
    pub fn export_jsonl(&self) -> String {
        self.entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Audit record for JSONL export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BarrierAuditRecord {
    pub barrier_id: String,
    pub current_epoch: u64,
    pub target_epoch: u64,
    pub outcome: String,
    pub participant_count: usize,
    pub acks_received: usize,
    pub elapsed_ms: u64,
    pub abort_reason: Option<String>,
    pub schema_version: String,
}

/// A single barrier instance tracking the state machine.
#[derive(Debug, Clone)]
pub struct BarrierInstance {
    pub barrier_id: BarrierId,
    pub current_epoch: u64,
    pub target_epoch: u64,
    pub phase: BarrierPhase,
    pub participants: BTreeSet<ParticipantId>,
    pub acks: BTreeMap<ParticipantId, DrainAck>,
    pub abort_reason: Option<AbortReason>,
    pub propose_timestamp_ms: u64,
    pub commit_timestamp_ms: Option<u64>,
    pub transcript: BarrierTranscript,
    pub trace_id: String,
}

impl BarrierInstance {
    /// Check if all participants have ACKed.
    /// INV-BARRIER-ALL-ACK
    pub fn all_acked(&self) -> bool {
        self.participants.iter().all(|p| self.acks.contains_key(p))
    }

    /// Get participants that have not yet ACKed.
    pub fn missing_acks(&self) -> Vec<ParticipantId> {
        self.participants
            .iter()
            .filter(|p| !self.acks.contains_key(*p))
            .cloned()
            .collect()
    }

    /// Whether this barrier is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self.phase, BarrierPhase::Committed | BarrierPhase::Aborted)
    }

    /// Number of ACKs received.
    pub fn ack_count(&self) -> usize {
        self.acks.len()
    }
}

/// The epoch transition barrier coordinator.
///
/// Manages barrier lifecycle: propose -> drain -> commit/abort.
/// INV-BARRIER-SERIALIZED: only one barrier may be active at a time.
pub struct EpochTransitionBarrier {
    config: BarrierConfig,
    participants: BTreeSet<ParticipantId>,
    active_barrier: Option<BarrierInstance>,
    history: Vec<BarrierAuditRecord>,
    barrier_counter: u64,
}

impl EpochTransitionBarrier {
    /// Create a new barrier coordinator with the given configuration.
    pub fn new(config: BarrierConfig) -> Self {
        Self {
            config,
            participants: BTreeSet::new(),
            active_barrier: None,
            history: Vec::new(),
            barrier_counter: 0,
        }
    }

    /// Register a participant for barrier coordination.
    pub fn register_participant(&mut self, participant_id: &str) {
        self.participants.insert(participant_id.to_string());
    }

    /// Unregister a participant (only when no barrier is active).
    pub fn unregister_participant(&mut self, participant_id: &str) -> Result<(), BarrierError> {
        if self.is_barrier_active() {
            return Err(BarrierError::ConcurrentBarrier {
                active_barrier_id: self
                    .active_barrier
                    .as_ref()
                    .map(|active| active.barrier_id.clone())
                    .unwrap_or_default(),
            });
        }
        self.participants.remove(participant_id);
        Ok(())
    }

    /// Get the set of registered participants.
    pub fn registered_participants(&self) -> &BTreeSet<ParticipantId> {
        &self.participants
    }

    /// Whether a barrier is currently in progress.
    pub fn is_barrier_active(&self) -> bool {
        self.active_barrier
            .as_ref()
            .map(|b| !b.is_terminal())
            .unwrap_or(false)
    }

    /// Get reference to active barrier, if any.
    pub fn active_barrier(&self) -> Option<&BarrierInstance> {
        self.active_barrier.as_ref()
    }

    /// Propose a new epoch transition barrier.
    ///
    /// INV-BARRIER-SERIALIZED: fails if a barrier is already active.
    pub fn propose(
        &mut self,
        current_epoch: u64,
        target_epoch: u64,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&BarrierInstance, BarrierError> {
        // INV-BARRIER-SERIALIZED: reject concurrent barriers
        if self.is_barrier_active() {
            return Err(BarrierError::ConcurrentBarrier {
                active_barrier_id: self
                    .active_barrier
                    .as_ref()
                    .map(|b| b.barrier_id.clone())
                    .unwrap_or_default(),
            });
        }

        if self.participants.is_empty() {
            return Err(BarrierError::NoParticipants);
        }

        // Validate target epoch is current + 1. Overflow must fail closed:
        // otherwise u64::MAX -> u64::MAX would reuse the same epoch-scoped key.
        let expected_epoch = current_epoch
            .checked_add(1)
            .ok_or(BarrierError::EpochOverflow {
                current: current_epoch,
            })?;
        if target_epoch != expected_epoch {
            return Err(BarrierError::EpochMismatch {
                expected: expected_epoch,
                provided: target_epoch,
            });
        }

        self.barrier_counter =
            self.barrier_counter
                .checked_add(1)
                .ok_or(BarrierError::BarrierIdOverflow {
                    current_counter: self.barrier_counter,
                })?;
        let barrier_id = format!("barrier-{:06}", self.barrier_counter);

        let mut transcript = BarrierTranscript::new(
            &barrier_id,
            current_epoch,
            target_epoch,
            self.participants.len(),
        );

        transcript.record(
            event_codes::BARRIER_PROPOSED,
            &format!(
                "proposed transition epoch {} -> {} with {} participants",
                current_epoch,
                target_epoch,
                self.participants.len()
            ),
            timestamp_ms,
            trace_id,
        );

        // Transcript phase must track instance phase — instance starts Draining.
        transcript.phase = BarrierPhase::Draining;

        let instance = BarrierInstance {
            barrier_id,
            current_epoch,
            target_epoch,
            phase: BarrierPhase::Draining,
            participants: self.participants.clone(),
            acks: BTreeMap::new(),
            abort_reason: None,
            propose_timestamp_ms: timestamp_ms,
            commit_timestamp_ms: None,
            transcript,
            trace_id: trace_id.to_string(),
        };

        self.active_barrier = Some(instance);
        self.active_barrier
            .as_ref()
            .ok_or(BarrierError::NoParticipants)
    }

    /// Record a drain ACK from a participant.
    ///
    /// INV-BARRIER-ALL-ACK: ACKs are collected; commit requires all.
    pub fn record_drain_ack(&mut self, ack: DrainAck) -> Result<(), BarrierError> {
        let barrier = self
            .active_barrier
            .as_mut()
            .ok_or(BarrierError::NoParticipants)?;

        if barrier.is_terminal() {
            return Err(BarrierError::AlreadyComplete {
                barrier_id: barrier.barrier_id.clone(),
            });
        }

        if barrier.phase != BarrierPhase::Draining {
            return Err(BarrierError::InvalidPhase {
                barrier_id: barrier.barrier_id.clone(),
                current: barrier.phase,
                attempted: BarrierPhase::Draining,
            });
        }

        if !crate::security::constant_time::ct_eq(&ack.barrier_id, &barrier.barrier_id) {
            return Err(BarrierError::BarrierIdMismatch {
                expected: barrier.barrier_id.clone(),
                provided: ack.barrier_id.clone(),
            });
        }

        if !barrier.participants.contains(&ack.participant_id) {
            return Err(BarrierError::UnknownParticipant {
                participant_id: ack.participant_id.clone(),
            });
        }

        let timestamp_ms = barrier.propose_timestamp_ms.saturating_add(ack.elapsed_ms);
        barrier.transcript.record(
            event_codes::BARRIER_DRAIN_ACK,
            &format!(
                "participant {} drained {} items in {}ms",
                ack.participant_id, ack.drained_items, ack.elapsed_ms
            ),
            timestamp_ms,
            &ack.trace_id,
        );

        barrier.acks.insert(ack.participant_id.clone(), ack);
        Ok(())
    }

    /// Attempt to commit the barrier after all drain ACKs received.
    ///
    /// INV-BARRIER-ALL-ACK: requires N ACKs for N participants.
    /// INV-BARRIER-NO-PARTIAL: on commit, epoch is advanced atomically.
    pub fn try_commit(
        &mut self,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<BarrierCommitOutcome, BarrierError> {
        let barrier = self
            .active_barrier
            .as_mut()
            .ok_or(BarrierError::NoParticipants)?;

        if barrier.is_terminal() {
            return Err(BarrierError::AlreadyComplete {
                barrier_id: barrier.barrier_id.clone(),
            });
        }

        if !barrier.all_acked() {
            let missing = barrier.missing_acks();
            let elapsed = timestamp_ms.saturating_sub(barrier.propose_timestamp_ms);

            // Check if we've exceeded the global timeout
            if elapsed >= self.config.global_timeout_ms {
                let reason = AbortReason::Timeout {
                    missing_participants: missing,
                };
                return self
                    .abort(reason.clone(), timestamp_ms, trace_id)
                    .map(|current_epoch| BarrierCommitOutcome::Aborted {
                        current_epoch,
                        reason,
                    });
            }

            return Err(BarrierError::NotAllAcked { missing });
        }

        // All ACKs received: commit
        let target_epoch = barrier.target_epoch;

        barrier.transcript.record(
            event_codes::BARRIER_COMMITTED,
            &format!(
                "committed: epoch {} -> {}, {} ACKs in {}ms",
                barrier.current_epoch,
                barrier.target_epoch,
                barrier.ack_count(),
                timestamp_ms.saturating_sub(barrier.propose_timestamp_ms)
            ),
            timestamp_ms,
            trace_id,
        );

        barrier.phase = BarrierPhase::Committed;
        barrier.commit_timestamp_ms = Some(timestamp_ms);
        barrier.transcript.phase = BarrierPhase::Committed;

        // Record audit
        push_bounded(
            &mut self.history,
            BarrierAuditRecord {
                barrier_id: barrier.barrier_id.clone(),
                current_epoch: barrier.current_epoch,
                target_epoch: barrier.target_epoch,
                outcome: "COMMITTED".to_string(),
                participant_count: barrier.participants.len(),
                acks_received: barrier.ack_count(),
                elapsed_ms: timestamp_ms.saturating_sub(barrier.propose_timestamp_ms),
                abort_reason: None,
                schema_version: SCHEMA_VERSION.to_string(),
            },
            MAX_BARRIER_HISTORY,
        );

        Ok(BarrierCommitOutcome::Committed { target_epoch })
    }

    /// Abort the current barrier.
    ///
    /// INV-BARRIER-ABORT-SAFE: no participant operates under the new epoch.
    /// INV-BARRIER-NO-PARTIAL: system remains at current epoch.
    pub fn abort(
        &mut self,
        reason: AbortReason,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<u64, BarrierError> {
        let barrier = self
            .active_barrier
            .as_mut()
            .ok_or(BarrierError::NoParticipants)?;

        if barrier.is_terminal() {
            return Err(BarrierError::AlreadyComplete {
                barrier_id: barrier.barrier_id.clone(),
            });
        }

        let reason_str = reason.to_string();

        // Record timeout event if applicable
        if let AbortReason::Timeout {
            ref missing_participants,
        } = reason
        {
            barrier.transcript.record(
                event_codes::BARRIER_TIMEOUT,
                &format!(
                    "timeout after {}ms, missing: {}",
                    timestamp_ms.saturating_sub(barrier.propose_timestamp_ms),
                    missing_participants.join(", ")
                ),
                timestamp_ms,
                trace_id,
            );
        }

        barrier.transcript.record(
            event_codes::BARRIER_ABORTED,
            &format!("aborted: {}", reason_str),
            timestamp_ms,
            trace_id,
        );

        // Record abort-sent for each participant
        for pid in &barrier.participants {
            barrier.transcript.record(
                event_codes::BARRIER_ABORT_SENT,
                &format!("abort sent to {}", pid),
                timestamp_ms,
                trace_id,
            );
        }

        barrier.phase = BarrierPhase::Aborted;
        barrier.abort_reason = Some(reason);
        barrier.transcript.phase = BarrierPhase::Aborted;

        let current_epoch = barrier.current_epoch;

        // Record audit
        push_bounded(
            &mut self.history,
            BarrierAuditRecord {
                barrier_id: barrier.barrier_id.clone(),
                current_epoch: barrier.current_epoch,
                target_epoch: barrier.target_epoch,
                outcome: "ABORTED".to_string(),
                participant_count: barrier.participants.len(),
                acks_received: barrier.ack_count(),
                elapsed_ms: timestamp_ms.saturating_sub(barrier.propose_timestamp_ms),
                abort_reason: Some(reason_str),
                schema_version: SCHEMA_VERSION.to_string(),
            },
            MAX_BARRIER_HISTORY,
        );

        // INV-BARRIER-ABORT-SAFE: return current epoch (not advanced)
        Ok(current_epoch)
    }

    /// Record a participant drain failure and abort the barrier.
    pub fn record_drain_failure(
        &mut self,
        participant_id: &str,
        detail: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<u64, BarrierError> {
        let barrier = self
            .active_barrier
            .as_mut()
            .ok_or(BarrierError::NoParticipants)?;

        if !barrier.participants.contains(participant_id) {
            return Err(BarrierError::UnknownParticipant {
                participant_id: participant_id.to_string(),
            });
        }

        barrier.transcript.record(
            event_codes::BARRIER_DRAIN_FAILED,
            &format!("participant {} drain failed: {}", participant_id, detail),
            timestamp_ms,
            trace_id,
        );

        self.abort(
            AbortReason::DrainFailed {
                participant_id: participant_id.to_string(),
                detail: detail.to_string(),
            },
            timestamp_ms,
            trace_id,
        )
    }

    /// Check for per-participant timeouts and abort if any exceeded.
    pub fn check_participant_timeouts(
        &mut self,
        current_timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<(), BarrierError> {
        let barrier = match &self.active_barrier {
            Some(b) if !b.is_terminal() && b.phase == BarrierPhase::Draining => b,
            _ => return Ok(()),
        };

        let elapsed = current_timestamp_ms.saturating_sub(barrier.propose_timestamp_ms);
        let mut timed_out = Vec::new();

        for pid in &barrier.participants {
            if !barrier.acks.contains_key(pid) {
                let timeout = self.config.drain_timeout_for(pid);
                if elapsed >= timeout {
                    timed_out.push(pid.clone());
                }
            }
        }

        if !timed_out.is_empty() {
            self.abort(
                AbortReason::Timeout {
                    missing_participants: timed_out,
                },
                current_timestamp_ms,
                trace_id,
            )?;
        }

        Ok(())
    }

    /// Get the transcript from the current or last barrier.
    pub fn transcript(&self) -> Option<&BarrierTranscript> {
        self.active_barrier.as_ref().map(|b| &b.transcript)
    }

    /// Get the full audit history.
    pub fn audit_history(&self) -> &[BarrierAuditRecord] {
        &self.history
    }

    /// Export audit history as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.history
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get the configuration.
    pub fn config(&self) -> &BarrierConfig {
        &self.config
    }

    /// Completed barrier count.
    pub fn completed_barrier_count(&self) -> usize {
        self.history.len()
    }
}

impl Default for EpochTransitionBarrier {
    fn default() -> Self {
        Self::new(BarrierConfig::default())
    }
}

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

#[cfg(test)]
mod tests {
    use super::{
        AbortReason, BarrierCommitOutcome, BarrierConfig, BarrierError, BarrierPhase,
        DEFAULT_BARRIER_TIMEOUT_MS, DEFAULT_DRAIN_TIMEOUT_MS, DrainAck, EpochTransitionBarrier,
        MAX_TRANSCRIPT_ENTRIES, SCHEMA_VERSION, error_codes, event_codes,
    };
    use crate::control_plane::control_epoch::ControlEpoch;
    use crate::security::constant_time;
    use crate::security::epoch_scoped_keys::{
        RootSecret, derive_epoch_key, sign_epoch_artifact, verify_epoch_signature,
    };

    fn make_barrier(n_participants: usize) -> EpochTransitionBarrier {
        let mut b = EpochTransitionBarrier::new(BarrierConfig::default());
        for i in 0..n_participants {
            b.register_participant(&format!("svc-{}", i));
        }
        b
    }

    fn make_ack(pid: &str, barrier_id: &str, elapsed_ms: u64) -> DrainAck {
        DrainAck {
            participant_id: pid.to_string(),
            barrier_id: barrier_id.to_string(),
            drained_items: 10,
            elapsed_ms,
            trace_id: format!("trace-{pid}"),
        }
    }

    fn root_secret() -> RootSecret {
        RootSecret::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("valid root secret")
    }

    // ---- Phase transitions ----

    #[test]
    fn propose_creates_draining_barrier() {
        let mut b = make_barrier(3);
        let inst = b.propose(5, 6, 1000, "t1").unwrap();
        assert_eq!(inst.phase, BarrierPhase::Draining);
        assert_eq!(inst.current_epoch, 5);
        assert_eq!(inst.target_epoch, 6);
        assert_eq!(inst.participants.len(), 3);
        assert!(b.is_barrier_active());
    }

    #[test]
    fn propose_sets_transcript_phase_to_draining() {
        let mut b = make_barrier(2);
        let inst = b.propose(0, 1, 1000, "t-phase").unwrap();
        assert_eq!(inst.transcript.phase, BarrierPhase::Draining);
    }

    #[test]
    fn propose_fails_with_no_participants() {
        let mut b = EpochTransitionBarrier::default();
        let err = b.propose(0, 1, 1000, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_NO_PARTICIPANTS);
    }

    #[test]
    fn propose_fails_with_epoch_mismatch() {
        let mut b = make_barrier(2);
        let err = b.propose(5, 7, 1000, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_EPOCH_MISMATCH);
    }

    // ---- INV-BARRIER-SERIALIZED ----

    #[test]
    fn concurrent_barrier_rejected() {
        let mut b = make_barrier(2);
        b.propose(0, 1, 1000, "t1").unwrap();
        let err = b.propose(1, 2, 2000, "t2").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_CONCURRENT);
    }

    // ---- Happy-path commit ----

    #[test]
    fn commit_with_all_acks() {
        let mut b = make_barrier(3);
        b.propose(5, 6, 1000, "t1").unwrap();

        for i in 0..3 {
            let pid = format!("svc-{}", i);
            b.record_drain_ack(make_ack(&pid, "barrier-000001", 50 + i as u64))
                .unwrap();
        }

        let outcome = b.try_commit(1200, "t1").unwrap();
        assert_eq!(outcome, BarrierCommitOutcome::Committed { target_epoch: 6 });
        assert!(!b.is_barrier_active());
        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Committed);
    }

    // ---- INV-BARRIER-ALL-ACK ----

    #[test]
    fn commit_fails_without_all_acks() {
        let mut b = make_barrier(3);
        b.propose(5, 6, 1000, "t1").unwrap();

        // Only 2 of 3 ACKs
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 50))
            .unwrap();
        b.record_drain_ack(make_ack("svc-1", "barrier-000001", 60))
            .unwrap();

        let err = b.try_commit(1100, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_NOT_ALL_ACKED);
        assert_eq!(
            err,
            BarrierError::NotAllAcked {
                missing: vec!["svc-2".into()],
            }
        );
    }

    // ---- INV-BARRIER-ABORT-SAFE ----

    #[test]
    fn abort_returns_current_epoch() {
        let mut b = make_barrier(2);
        b.propose(5, 6, 1000, "t1").unwrap();

        let epoch = b
            .abort(
                AbortReason::Cancelled {
                    detail: "test".into(),
                },
                1500,
                "t1",
            )
            .unwrap();

        assert_eq!(epoch, 5); // current, not target
        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Aborted);
        assert!(!b.is_barrier_active());
    }

    #[test]
    fn timeout_abort_with_missing_acks() {
        let mut b = make_barrier(3);
        b.propose(5, 6, 1000, "t1").unwrap();

        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 50))
            .unwrap();
        // svc-1 and svc-2 missing

        // Exceed global timeout
        let outcome = b
            .try_commit(1000 + DEFAULT_BARRIER_TIMEOUT_MS, "t1")
            .unwrap();
        assert_eq!(
            outcome,
            BarrierCommitOutcome::Aborted {
                current_epoch: 5,
                reason: AbortReason::Timeout {
                    missing_participants: vec!["svc-1".into(), "svc-2".into()],
                },
            }
        );
    }

    // ---- Drain failure ----

    #[test]
    fn drain_failure_aborts_barrier() {
        let mut b = make_barrier(3);
        b.propose(5, 6, 1000, "t1").unwrap();

        let epoch = b
            .record_drain_failure("svc-1", "connection reset", 1100, "t1")
            .unwrap();
        assert_eq!(epoch, 5);
        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Aborted);
    }

    #[test]
    fn drain_failure_unknown_participant() {
        let mut b = make_barrier(2);
        b.propose(5, 6, 1000, "t1").unwrap();

        let err = b
            .record_drain_failure("unknown-svc", "err", 1100, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_UNKNOWN_PARTICIPANT);
    }

    // ---- ACK from unknown participant ----

    #[test]
    fn ack_from_unknown_participant_rejected() {
        let mut b = make_barrier(2);
        b.propose(5, 6, 1000, "t1").unwrap();

        let err = b
            .record_drain_ack(make_ack("unknown", "barrier-000001", 50))
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_UNKNOWN_PARTICIPANT);
    }

    #[test]
    fn ack_with_wrong_barrier_id_rejected() {
        let mut b = make_barrier(2);
        b.propose(5, 6, 1000, "t1").unwrap();

        let err = b
            .record_drain_ack(make_ack("svc-0", "barrier-999999", 50))
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_ID_MISMATCH);
        assert_eq!(b.active_barrier().unwrap().ack_count(), 0);
    }

    #[test]
    fn barrier_id_constant_time_comparison_regression() {
        // Regression test for bd-1k7am: barrier ID comparison must use constant-time
        // to prevent timing attacks on control-plane token validation.
        let mut b = make_barrier(2);
        b.propose(5, 6, 1000, "t1").unwrap();
        let correct_barrier_id = b.active_barrier().unwrap().barrier_id.clone();

        // Test 1: Exact match should succeed (constant-time comparison returns true)
        let exact_match_ack = DrainAck {
            participant_id: "svc-0".to_string(),
            barrier_id: correct_barrier_id.clone(),
            drained_items: 50,
            elapsed_ms: 100,
            trace_id: "exact-match-test".to_string(),
        };
        assert!(b.record_drain_ack(exact_match_ack).is_ok());

        // Reset for next test
        let mut b = make_barrier(2);
        b.propose(5, 6, 1000, "t2").unwrap();

        // Test 2: Same-length mismatch should fail closed (prevents timing attacks)
        // Use same-length string to ensure ct_eq() processes same amount of data
        let same_length_wrong_ack = DrainAck {
            participant_id: "svc-0".to_string(),
            barrier_id: "barrier-000099".to_string(), // Same format, different number
            drained_items: 50,
            elapsed_ms: 100,
            trace_id: "same-length-mismatch-test".to_string(),
        };
        let err = b.record_drain_ack(same_length_wrong_ack).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_ID_MISMATCH);

        // Test 3: Different-length mismatch should also fail closed
        let different_length_ack = DrainAck {
            participant_id: "svc-0".to_string(),
            barrier_id: "short".to_string(),
            drained_items: 50,
            elapsed_ms: 100,
            trace_id: "different-length-test".to_string(),
        };
        let err = b.record_drain_ack(different_length_ack).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_ID_MISMATCH);
    }

    // ---- Operations on completed barrier ----

    #[test]
    fn ack_on_committed_barrier_fails() {
        let mut b = make_barrier(1);
        b.propose(5, 6, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 50))
            .unwrap();
        assert_eq!(
            b.try_commit(1100, "t1").unwrap(),
            BarrierCommitOutcome::Committed { target_epoch: 6 }
        );

        let err = b
            .record_drain_ack(make_ack("svc-0", "barrier-000001", 100))
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_ALREADY_COMPLETE);
    }

    #[test]
    fn abort_on_committed_barrier_fails() {
        let mut b = make_barrier(1);
        b.propose(5, 6, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 50))
            .unwrap();
        assert_eq!(
            b.try_commit(1100, "t1").unwrap(),
            BarrierCommitOutcome::Committed { target_epoch: 6 }
        );

        let err = b
            .abort(
                AbortReason::Cancelled {
                    detail: "test".into(),
                },
                1200,
                "t1",
            )
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_ALREADY_COMPLETE);
    }

    // ---- INV-BARRIER-TRANSCRIPT ----

    #[test]
    fn transcript_records_propose_event() {
        let mut b = make_barrier(2);
        b.propose(5, 6, 1000, "t1").unwrap();

        let t = b.transcript().unwrap();
        assert!(!t.entries.is_empty());
        assert_eq!(t.entries[0].event_code, event_codes::BARRIER_PROPOSED);
        assert_eq!(t.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn transcript_records_full_commit_sequence() {
        let mut b = make_barrier(2);
        b.propose(5, 6, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 50))
            .unwrap();
        b.record_drain_ack(make_ack("svc-1", "barrier-000001", 60))
            .unwrap();
        assert_eq!(
            b.try_commit(1200, "t1").unwrap(),
            BarrierCommitOutcome::Committed { target_epoch: 6 }
        );

        let t = b.transcript().unwrap();
        let codes: Vec<&str> = t.entries.iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::BARRIER_PROPOSED));
        assert!(codes.contains(&event_codes::BARRIER_DRAIN_ACK));
        assert!(codes.contains(&event_codes::BARRIER_COMMITTED));
    }

    #[test]
    fn transcript_records_abort_with_timeout() {
        let mut b = make_barrier(2);
        b.propose(5, 6, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 50))
            .unwrap();

        b.abort(
            AbortReason::Timeout {
                missing_participants: vec!["svc-1".into()],
            },
            2000,
            "t1",
        )
        .unwrap();

        let t = b.transcript().unwrap();
        let codes: Vec<&str> = t.entries.iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::BARRIER_TIMEOUT));
        assert!(codes.contains(&event_codes::BARRIER_ABORTED));
        assert!(codes.contains(&event_codes::BARRIER_ABORT_SENT));
    }

    #[test]
    fn transcript_export_jsonl() {
        let mut b = make_barrier(1);
        b.propose(0, 1, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();
        assert_eq!(
            b.try_commit(1100, "t1").unwrap(),
            BarrierCommitOutcome::Committed { target_epoch: 1 }
        );

        let jsonl = b.transcript().unwrap().export_jsonl();
        assert!(!jsonl.is_empty());
        for line in jsonl.lines() {
            let _: serde_json::Value = serde_json::from_str(line).expect("valid JSON per line");
        }
    }

    // ---- Config validation ----

    #[test]
    fn config_validation_accepts_valid() {
        let cfg = BarrierConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validation_rejects_zero_global() {
        let cfg = BarrierConfig::new(0, 10_000);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_rejects_zero_drain() {
        let cfg = BarrierConfig::new(30_000, 0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_rejects_drain_exceeds_global() {
        let cfg = BarrierConfig::new(5_000, 10_000);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_participant_timeout_override() {
        let mut cfg = BarrierConfig::default();
        cfg.participant_timeouts
            .insert("slow-svc".to_string(), 5_000);
        assert_eq!(cfg.drain_timeout_for("slow-svc"), 5_000);
        assert_eq!(
            cfg.drain_timeout_for("normal-svc"),
            DEFAULT_DRAIN_TIMEOUT_MS
        );
    }

    #[test]
    fn config_participant_timeout_capped_by_global() {
        let mut cfg = BarrierConfig::new(5_000, 3_000);
        cfg.participant_timeouts.insert("over".to_string(), 10_000);
        assert_eq!(cfg.drain_timeout_for("over"), 5_000); // capped at global
    }

    // ---- Per-participant timeout check ----

    #[test]
    fn check_participant_timeouts_aborts_on_exceeded() {
        let mut cfg = BarrierConfig::new(30_000, 100);
        cfg.participant_timeouts.insert("slow-svc".to_string(), 100);
        let mut b = EpochTransitionBarrier::new(cfg);
        b.register_participant("fast-svc");
        b.register_participant("slow-svc");
        b.propose(5, 6, 1000, "t1").unwrap();

        // fast-svc ACKs quickly
        b.record_drain_ack(make_ack("fast-svc", "barrier-000001", 20))
            .unwrap();

        // After 200ms, slow-svc has exceeded its 100ms timeout
        b.check_participant_timeouts(1200, "t1").unwrap();

        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Aborted);
    }

    // ---- Audit history ----

    #[test]
    fn audit_history_records_commits_and_aborts() {
        let mut b = make_barrier(1);

        // First barrier: commit
        b.propose(0, 1, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();
        assert_eq!(
            b.try_commit(1100, "t1").unwrap(),
            BarrierCommitOutcome::Committed { target_epoch: 1 }
        );

        // Second barrier: abort
        b.propose(1, 2, 2000, "t2").unwrap();
        b.abort(
            AbortReason::Cancelled {
                detail: "test".into(),
            },
            2500,
            "t2",
        )
        .unwrap();

        assert_eq!(b.completed_barrier_count(), 2);
        assert_eq!(b.audit_history()[0].outcome, "COMMITTED");
        assert_eq!(b.audit_history()[1].outcome, "ABORTED");
    }

    #[test]
    fn audit_export_jsonl_format() {
        let mut b = make_barrier(1);
        b.propose(0, 1, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();
        assert_eq!(
            b.try_commit(1100, "t1").unwrap(),
            BarrierCommitOutcome::Committed { target_epoch: 1 }
        );

        let jsonl = b.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["outcome"], "COMMITTED");
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }

    // ---- Register/unregister ----

    #[test]
    fn register_and_unregister_participants() {
        let mut b = EpochTransitionBarrier::default();
        b.register_participant("a");
        b.register_participant("b");
        assert_eq!(b.registered_participants().len(), 2);

        b.unregister_participant("a").unwrap();
        assert_eq!(b.registered_participants().len(), 1);
    }

    #[test]
    fn unregister_during_active_barrier_fails() {
        let mut b = make_barrier(2);
        b.propose(0, 1, 1000, "t1").unwrap();
        let err = b.unregister_participant("svc-0").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_BARRIER_CONCURRENT);
    }

    // ---- Barrier counter ----

    #[test]
    fn barrier_ids_are_sequential() {
        let mut b = make_barrier(1);

        b.propose(0, 1, 1000, "t1").unwrap();
        assert_eq!(b.active_barrier().unwrap().barrier_id, "barrier-000001");
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();
        assert_eq!(
            b.try_commit(1100, "t1").unwrap(),
            BarrierCommitOutcome::Committed { target_epoch: 1 }
        );

        b.propose(1, 2, 2000, "t2").unwrap();
        assert_eq!(b.active_barrier().unwrap().barrier_id, "barrier-000002");
    }

    // ---- Missing acks helper ----

    #[test]
    fn missing_acks_returns_unacked_participants() {
        let mut b = make_barrier(3);
        b.propose(5, 6, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-1", "barrier-000001", 50))
            .unwrap();

        let missing = b.active_barrier().unwrap().missing_acks();
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"svc-0".to_string()));
        assert!(missing.contains(&"svc-2".to_string()));
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<BarrierError> = vec![
            BarrierError::ConcurrentBarrier {
                active_barrier_id: "b1".into(),
            },
            BarrierError::NoParticipants,
            BarrierError::NotAllAcked {
                missing: vec!["svc-w".into()],
            },
            BarrierError::Timeout {
                barrier_id: "b2".into(),
                missing: vec!["svc-x".into()],
                elapsed_ms: 5000,
            },
            BarrierError::DrainFailed {
                barrier_id: "b3".into(),
                participant_id: "svc-y".into(),
                detail: "err".into(),
            },
            BarrierError::AlreadyComplete {
                barrier_id: "b4".into(),
            },
            BarrierError::InvalidPhase {
                barrier_id: "b5".into(),
                current: BarrierPhase::Committed,
                attempted: BarrierPhase::Draining,
            },
            BarrierError::UnknownParticipant {
                participant_id: "svc-z".into(),
            },
            BarrierError::BarrierIdMismatch {
                expected: "b6".into(),
                provided: "b7".into(),
            },
            BarrierError::EpochMismatch {
                expected: 6,
                provided: 8,
            },
            BarrierError::EpochOverflow { current: u64::MAX },
            BarrierError::BarrierIdOverflow {
                current_counter: u64::MAX,
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(
                s.contains(e.code()),
                "Display for {:?} should contain code {}",
                e,
                e.code()
            );
        }
    }

    // ---- Abort reason display ----

    #[test]
    fn abort_reason_display() {
        let reasons = vec![
            AbortReason::Timeout {
                missing_participants: vec!["a".into(), "b".into()],
            },
            AbortReason::DrainFailed {
                participant_id: "svc".into(),
                detail: "err".into(),
            },
            AbortReason::Cancelled {
                detail: "test".into(),
            },
        ];
        for r in &reasons {
            assert!(!r.to_string().is_empty());
        }
    }

    // ---- INV-BARRIER-NO-PARTIAL: after commit or abort exactly one epoch ----

    #[test]
    fn after_commit_barrier_is_terminal() {
        let mut b = make_barrier(1);
        b.propose(5, 6, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();
        assert_eq!(
            b.try_commit(1100, "t1").unwrap(),
            BarrierCommitOutcome::Committed { target_epoch: 6 }
        );

        assert!(b.active_barrier().unwrap().is_terminal());
        assert!(!b.is_barrier_active());
    }

    #[test]
    fn after_abort_barrier_is_terminal() {
        let mut b = make_barrier(1);
        b.propose(5, 6, 1000, "t1").unwrap();
        b.abort(
            AbortReason::Cancelled {
                detail: "test".into(),
            },
            1100,
            "t1",
        )
        .unwrap();

        assert!(b.active_barrier().unwrap().is_terminal());
        assert!(!b.is_barrier_active());
    }

    // ---- New barrier after terminal ----

    #[test]
    fn can_propose_after_committed_barrier() {
        let mut b = make_barrier(1);
        b.propose(5, 6, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();
        assert_eq!(
            b.try_commit(1100, "t1").unwrap(),
            BarrierCommitOutcome::Committed { target_epoch: 6 }
        );

        // Should be able to propose new barrier
        b.propose(6, 7, 2000, "t2").unwrap();
        assert!(b.is_barrier_active());
    }

    #[test]
    fn can_propose_after_aborted_barrier() {
        let mut b = make_barrier(1);
        b.propose(5, 6, 1000, "t1").unwrap();
        b.abort(
            AbortReason::Cancelled {
                detail: "test".into(),
            },
            1500,
            "t1",
        )
        .unwrap();

        b.propose(5, 6, 2000, "t2").unwrap();
        assert!(b.is_barrier_active());
    }

    // ---- Default trait ----

    #[test]
    fn default_barrier_has_default_config() {
        let b = EpochTransitionBarrier::default();
        assert_eq!(b.config().global_timeout_ms, DEFAULT_BARRIER_TIMEOUT_MS);
        assert_eq!(
            b.config().default_drain_timeout_ms,
            DEFAULT_DRAIN_TIMEOUT_MS
        );
        assert!(!b.is_barrier_active());
        assert_eq!(b.completed_barrier_count(), 0);
    }

    // ---- Barrier phase display ----

    #[test]
    fn barrier_phase_display() {
        assert_eq!(BarrierPhase::Proposed.to_string(), "Proposed");
        assert_eq!(BarrierPhase::Draining.to_string(), "Draining");
        assert_eq!(BarrierPhase::Committed.to_string(), "Committed");
        assert_eq!(BarrierPhase::Aborted.to_string(), "Aborted");
    }

    // ---- push_bounded integer underflow fix ----

    #[test]
    fn push_bounded_prevents_underflow_when_cap_larger_than_length() {
        let mut items = vec![1, 2]; // length 2
        let cap = 10; // cap > items.len()

        // This should not panic due to integer underflow
        push_bounded(&mut items, 3, cap);

        // Should just append since items.len() < cap
        assert_eq!(items, vec![1, 2, 3]);
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn push_bounded_drains_correctly_when_at_capacity() {
        let mut items = vec![1, 2, 3];
        let cap = 2;

        // Should remove oldest item and add new one
        push_bounded(&mut items, 4, cap);

        assert_eq!(items, vec![3, 4]);
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn push_bounded_handles_edge_cases() {
        // Empty vec
        let mut items = Vec::<i32>::new();
        push_bounded(&mut items, 1, 5);
        assert_eq!(items, vec![1]);

        // Cap of 0 means retain no items, but it must not panic.
        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 0);
        assert!(items.is_empty());

        // Cap of 1 - should only contain new item
        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 1);
        assert_eq!(items, vec![4]);
    }

    // ---- Epoch rollover / half-open concurrent-epoch windows ----

    #[test]
    fn epoch_rollover_rejects_max_epoch_self_transition() {
        let mut b = make_barrier(1);
        let err = b
            .propose(u64::MAX, u64::MAX, 1000, "trace-max")
            .expect_err("u64::MAX cannot advance without reusing the epoch key");

        assert_eq!(err.code(), error_codes::ERR_BARRIER_EPOCH_OVERFLOW);
        assert_eq!(err, BarrierError::EpochOverflow { current: u64::MAX });
        assert!(!b.is_barrier_active());
        assert_eq!(b.completed_barrier_count(), 0);
    }

    #[test]
    fn epoch_rollover_allows_last_representable_increment() {
        let mut b = make_barrier(1);
        let inst = b
            .propose(u64::MAX - 1, u64::MAX, 1000, "trace-last")
            .expect("u64::MAX remains a valid target when reached by +1");

        assert_eq!(inst.current_epoch, u64::MAX - 1);
        assert_eq!(inst.target_epoch, u64::MAX);
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 10))
            .unwrap();
        assert_eq!(
            b.try_commit(1020, "trace-last").unwrap(),
            BarrierCommitOutcome::Committed {
                target_epoch: u64::MAX,
            }
        );
    }

    #[test]
    fn epoch_rollover_rejects_wrapped_zero_target() {
        let mut b = make_barrier(1);
        let err = b
            .propose(u64::MAX - 1, 0, 1000, "trace-wrap")
            .expect_err("wrapped target epoch must not open a barrier");

        assert_eq!(err.code(), error_codes::ERR_BARRIER_EPOCH_MISMATCH);
        assert_eq!(
            err,
            BarrierError::EpochMismatch {
                expected: u64::MAX,
                provided: 0,
            }
        );
        assert!(!b.is_barrier_active());
    }

    #[test]
    fn epoch_rollover_rejects_skip_to_final_epoch() {
        let mut b = make_barrier(1);
        let err = b
            .propose(u64::MAX - 2, u64::MAX, 1000, "trace-skip")
            .expect_err("skipping an epoch would skip a key-derivation boundary");

        assert_eq!(err.code(), error_codes::ERR_BARRIER_EPOCH_MISMATCH);
        assert_eq!(
            err,
            BarrierError::EpochMismatch {
                expected: u64::MAX - 1,
                provided: u64::MAX,
            }
        );
        assert!(!b.is_barrier_active());
    }

    #[test]
    fn barrier_id_counter_rejects_overflow_before_opening_window() {
        let mut b = make_barrier(1);
        b.barrier_counter = u64::MAX;

        let err = b
            .propose(3, 4, 1000, "trace-id-overflow")
            .expect_err("barrier id overflow must not create a half-open window");

        assert_eq!(err.code(), error_codes::ERR_BARRIER_ID_OVERFLOW);
        assert_eq!(
            err,
            BarrierError::BarrierIdOverflow {
                current_counter: u64::MAX,
            }
        );
        assert!(!b.is_barrier_active());
        assert_eq!(b.completed_barrier_count(), 0);
    }

    #[test]
    fn barrier_id_counter_allows_last_representable_id_once() {
        let mut b = make_barrier(1);
        b.barrier_counter = u64::MAX - 1;

        let inst = b
            .propose(3, 4, 1000, "trace-last-id")
            .expect("last unique barrier id should be usable");

        assert_eq!(inst.barrier_id, format!("barrier-{:06}", u64::MAX));
        assert_eq!(b.barrier_counter, u64::MAX);
        assert!(b.is_barrier_active());
    }

    #[test]
    fn epoch_scoped_keys_differ_at_rollover_boundary() {
        let root = root_secret();
        let previous = derive_epoch_key(&root, ControlEpoch::new(u64::MAX - 1), "barrier");
        let final_epoch = derive_epoch_key(&root, ControlEpoch::new(u64::MAX), "barrier");

        assert!(
            !constant_time::ct_eq_bytes(previous.as_bytes(), final_epoch.as_bytes()),
            "adjacent rollover-boundary epochs must derive distinct keys"
        );
        let previous_fingerprint = previous.fingerprint();
        let final_fingerprint = final_epoch.fingerprint();
        assert!(
            !constant_time::ct_eq_bytes(
                previous_fingerprint.as_bytes(),
                final_fingerprint.as_bytes()
            ),
            "fingerprints should reflect distinct epoch-scoped keys"
        );
    }

    #[test]
    fn epoch_scoped_signature_rejects_previous_epoch_at_boundary() {
        let root = root_secret();
        let payload = b"barrier-commit-transcript";
        let signature = sign_epoch_artifact(payload, ControlEpoch::new(u64::MAX), "barrier", &root)
            .expect("signature at final representable epoch");

        let verify_previous = verify_epoch_signature(
            payload,
            &signature,
            ControlEpoch::new(u64::MAX - 1),
            "barrier",
            &root,
        );

        assert!(
            verify_previous.is_err(),
            "final-epoch signature must not verify against the previous epoch key"
        );
    }

    #[test]
    fn epoch_scoped_signature_rejects_wrong_domain_at_boundary() {
        let root = root_secret();
        let payload = b"barrier-commit-transcript";
        let signature = sign_epoch_artifact(payload, ControlEpoch::new(u64::MAX), "barrier", &root)
            .expect("signature at final representable epoch");

        let verify_wrong_domain = verify_epoch_signature(
            payload,
            &signature,
            ControlEpoch::new(u64::MAX),
            "manifest",
            &root,
        );

        assert!(
            verify_wrong_domain.is_err(),
            "final-epoch signature must remain domain-separated"
        );
    }

    #[test]
    fn global_timeout_window_is_half_open_before_deadline() {
        let mut b = make_barrier(2);
        b.propose(41, 42, 1_000, "trace-window").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();

        let err = b
            .try_commit(
                1_000 + DEFAULT_BARRIER_TIMEOUT_MS.saturating_sub(1),
                "trace-before-deadline",
            )
            .expect_err("missing ACKs before the deadline should not auto-abort");

        assert_eq!(err.code(), error_codes::ERR_BARRIER_NOT_ALL_ACKED);
        assert!(b.is_barrier_active());
        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Draining);
        assert_eq!(b.completed_barrier_count(), 0);
    }

    #[test]
    fn global_timeout_window_closes_at_exact_deadline() {
        let mut b = make_barrier(2);
        b.propose(41, 42, 1_000, "trace-window").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();

        let outcome = b
            .try_commit(1_000 + DEFAULT_BARRIER_TIMEOUT_MS, "trace-deadline")
            .expect("deadline is handled through the abort outcome");

        assert_eq!(
            outcome,
            BarrierCommitOutcome::Aborted {
                current_epoch: 41,
                reason: AbortReason::Timeout {
                    missing_participants: vec!["svc-1".into()],
                },
            }
        );
        assert!(!b.is_barrier_active());
        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Aborted);
        assert_eq!(b.completed_barrier_count(), 1);
        assert_eq!(b.audit_history()[0].outcome, "ABORTED");
    }

    #[test]
    fn participant_timeout_window_is_half_open_until_exact_deadline() {
        let mut cfg = BarrierConfig::new(1_000, 100);
        cfg.participant_timeouts.insert("svc-1".into(), 250);
        let mut b = EpochTransitionBarrier::new(cfg);
        b.register_participant("svc-0");
        b.register_participant("svc-1");
        b.propose(7, 8, 5_000, "trace-participant").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();

        b.check_participant_timeouts(5_249, "trace-before").unwrap();
        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Draining);

        b.check_participant_timeouts(5_250, "trace-at").unwrap();
        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Aborted);
        assert_eq!(
            b.active_barrier().unwrap().abort_reason,
            Some(AbortReason::Timeout {
                missing_participants: vec!["svc-1".into()],
            })
        );
    }

    #[test]
    fn participant_timeout_does_not_abort_when_everyone_acked_at_deadline() {
        let mut cfg = BarrierConfig::new(1_000, 100);
        cfg.participant_timeouts.insert("svc-1".into(), 250);
        let mut b = EpochTransitionBarrier::new(cfg);
        b.register_participant("svc-0");
        b.register_participant("svc-1");
        b.propose(7, 8, 5_000, "trace-acked").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();
        b.record_drain_ack(make_ack("svc-1", "barrier-000001", 30))
            .unwrap();

        b.check_participant_timeouts(5_250, "trace-at").unwrap();

        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Draining);
        assert!(b.active_barrier().unwrap().abort_reason.is_none());
        assert_eq!(b.active_barrier().unwrap().ack_count(), 2);
    }

    #[test]
    fn active_barrier_blocks_next_epoch_until_half_open_window_closes() {
        let mut cfg = BarrierConfig::new(500, 500);
        cfg.participant_timeouts.insert("svc-1".into(), 500);
        let mut b = EpochTransitionBarrier::new(cfg);
        b.register_participant("svc-0");
        b.register_participant("svc-1");
        b.propose(9, 10, 1_000, "trace-active").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 50))
            .unwrap();

        let concurrent = b
            .propose(10, 11, 1_499, "trace-concurrent")
            .expect_err("active half-open window must reject the next epoch");
        assert_eq!(concurrent.code(), error_codes::ERR_BARRIER_CONCURRENT);

        let outcome = b.try_commit(1_500, "trace-close").unwrap();
        assert!(matches!(outcome, BarrierCommitOutcome::Aborted { .. }));

        let inst = b
            .propose(9, 10, 1_501, "trace-retry")
            .expect("same epoch transition can be retried after abort");
        assert_eq!(inst.current_epoch, 9);
        assert_eq!(inst.target_epoch, 10);
    }

    #[test]
    fn late_ack_after_timeout_cannot_join_next_epoch_window() {
        let mut b = make_barrier(2);
        b.propose(12, 13, 1_000, "trace-timeout").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 20))
            .unwrap();
        assert!(matches!(
            b.try_commit(1_000 + DEFAULT_BARRIER_TIMEOUT_MS, "trace-close")
                .unwrap(),
            BarrierCommitOutcome::Aborted { .. }
        ));

        let late_ack = b
            .record_drain_ack(make_ack("svc-1", "barrier-000001", 30))
            .expect_err("late ACKs after timeout must not reopen the epoch window");
        assert_eq!(late_ack.code(), error_codes::ERR_BARRIER_ALREADY_COMPLETE);

        b.propose(12, 13, 40_001, "trace-retry").unwrap();
        let stale_barrier_ack = b
            .record_drain_ack(make_ack("svc-1", "barrier-000001", 40))
            .expect_err("ACKs for the old barrier id must not enter the new window");
        assert_eq!(
            stale_barrier_ack.code(),
            error_codes::ERR_BARRIER_ID_MISMATCH
        );
        assert_eq!(b.active_barrier().unwrap().ack_count(), 0);
    }

    #[test]
    fn ack_timestamp_saturates_at_u64_max_boundary() {
        let mut b = make_barrier(1);
        b.propose(30, 31, u64::MAX - 5, "trace-near-max").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 50))
            .unwrap();

        let ack_entry = b
            .transcript()
            .unwrap()
            .entries
            .iter()
            .find(|entry| entry.event_code == event_codes::BARRIER_DRAIN_ACK)
            .expect("ACK event should be recorded");
        assert_eq!(ack_entry.timestamp_ms, u64::MAX);
    }
}

#[cfg(test)]
mod epoch_transition_barrier_comprehensive_negative_tests {
    use super::{
        AbortReason, BarrierCommitOutcome, BarrierConfig, BarrierError, BarrierPhase, DrainAck,
        EpochTransitionBarrier, error_codes,
    };
    use std::collections::HashMap;

    /// Negative test: Unicode injection and encoding attacks in barrier identifiers
    #[test]
    fn negative_unicode_injection_barrier_identifiers() {
        let mut b = EpochTransitionBarrier::default();

        // Test malicious Unicode in participant IDs
        let malicious_participants = vec![
            "svc\u{202e}evil\u{200b}",    // Right-to-left override + zero-width space
            "svc\u{0000}injection",       // Null byte injection
            "svc\u{feff}bom",             // Byte order mark
            "svc\u{2028}newline",         // Line separator
            "svc\u{2029}paragraph",       // Paragraph separator
            "svc\u{200c}\u{200d}joiners", // Zero-width joiners
            "svc\u{034f}combining",       // Combining grapheme joiner
        ];

        for malicious_participant in &malicious_participants {
            b.register_participant(malicious_participant);
        }

        // Should handle Unicode participants without corruption
        assert_eq!(
            b.registered_participants().len(),
            malicious_participants.len()
        );

        // Propose barrier with Unicode participants
        let result = b.propose(0, 1, 1000, "trace-unicode");
        assert!(result.is_ok(), "Should handle Unicode participant IDs");

        let barrier_id = b.active_barrier().unwrap().barrier_id.clone();

        // Test Unicode in trace IDs and drain ACKs
        for (i, participant) in malicious_participants.iter().enumerate() {
            let unicode_trace = format!("trace\u{202e}malicious\u{0000}-{}", i);
            let drain_ack = DrainAck {
                participant_id: participant.to_string(),
                barrier_id: barrier_id.clone(),
                drained_items: 10,
                elapsed_ms: 50,
                trace_id: unicode_trace.clone(),
            };

            let result = b.record_drain_ack(drain_ack);
            match result {
                Ok(_) => {
                    // Unicode was accepted, verify transcript integrity
                    let transcript = b.transcript().unwrap();
                    assert!(transcript.entries.iter().any(|e| {
                        e.trace_id.contains(
                            &unicode_trace
                                .chars()
                                .filter(|c| !c.is_control())
                                .collect::<String>(),
                        )
                    }));
                }
                Err(_) => {
                    // Unicode rejection is also acceptable
                    continue;
                }
            }
        }

        // Test Unicode in abort reason details
        let unicode_abort_detail = "reason\u{202e}evil\u{0000}detail";
        let abort_result = b.abort(
            AbortReason::Cancelled {
                detail: unicode_abort_detail.to_string(),
            },
            2000,
            "trace\u{200b}unicode",
        );

        match abort_result {
            Ok(_) => {
                // Verify Unicode in abort reason doesn't corrupt transcript
                let transcript = b.transcript().unwrap();
                assert!(
                    transcript
                        .entries
                        .iter()
                        .any(|e| e.event_code == event_codes::BARRIER_ABORTED)
                );
            }
            Err(_) => {
                // Unicode handling error is acceptable
            }
        }
    }

    /// Negative test: Arithmetic overflow protection in timestamps and counters
    #[test]
    fn negative_arithmetic_overflow_protection() {
        let mut b = EpochTransitionBarrier::default();
        b.register_participant("test-svc");

        // Test near-maximum timestamp proposal
        let near_max_timestamp = u64::MAX - 1000;
        let result = b.propose(100, 101, near_max_timestamp, "trace-near-max");
        assert!(result.is_ok(), "Should handle near-maximum timestamps");

        // Test maximum timestamp proposal
        b = EpochTransitionBarrier::default();
        b.register_participant("test-svc");
        let result = b.propose(200, 201, u64::MAX, "trace-max");
        assert!(result.is_ok(), "Should handle maximum timestamp");

        // Test barrier counter overflow protection
        b = EpochTransitionBarrier::default();
        b.register_participant("test-svc");
        b.barrier_counter = u64::MAX;

        let overflow_result = b.propose(300, 301, 5000, "trace-counter-overflow");
        assert!(
            overflow_result.is_err(),
            "Should reject barrier counter overflow"
        );
        assert_eq!(
            overflow_result.unwrap_err().code(),
            error_codes::ERR_BARRIER_ID_OVERFLOW
        );

        // Test epoch overflow protection
        b = EpochTransitionBarrier::default();
        b.register_participant("test-svc");

        let epoch_overflow_result = b.propose(u64::MAX, u64::MAX, 5000, "trace-epoch-overflow");
        assert!(
            epoch_overflow_result.is_err(),
            "Should reject epoch overflow"
        );
        assert_eq!(
            epoch_overflow_result.unwrap_err().code(),
            error_codes::ERR_BARRIER_EPOCH_OVERFLOW
        );

        // Test drain ACK with overflow elapsed time
        b = EpochTransitionBarrier::default();
        b.register_participant("overflow-svc");
        b.propose(400, 401, 10000, "trace-ack-overflow").unwrap();

        let overflow_ack = DrainAck {
            participant_id: "overflow-svc".to_string(),
            barrier_id: b.active_barrier().unwrap().barrier_id.clone(),
            drained_items: u64::MAX, // Maximum items drained
            elapsed_ms: u64::MAX,    // Maximum elapsed time
            trace_id: "trace-overflow-ack".to_string(),
        };

        let ack_result = b.record_drain_ack(overflow_ack);
        assert!(
            ack_result.is_ok(),
            "Should handle overflow values in drain ACK"
        );

        // Verify saturating addition in transcript timestamp calculation
        let transcript = b.transcript().unwrap();
        let ack_entry = transcript
            .entries
            .iter()
            .find(|e| e.event_code == event_codes::BARRIER_DRAIN_ACK)
            .unwrap();

        // Should use saturating arithmetic to prevent timestamp rollover
        assert_eq!(ack_entry.timestamp_ms, u64::MAX);

        // Test massive timeout configuration
        let massive_config = BarrierConfig::new(u64::MAX, u64::MAX - 1);
        let validation_result = massive_config.validate();
        assert!(
            validation_result.is_ok(),
            "Should handle maximum timeout values"
        );
    }

    /// Negative test: Memory exhaustion attacks with massive participant sets and logs
    #[test]
    fn negative_memory_exhaustion_massive_participants() {
        let mut b = EpochTransitionBarrier::default();

        // Register massive number of participants with large IDs
        let huge_participant_base = "p".repeat(1000);
        for i in 0..1000 {
            let huge_participant_id = format!("{}-{}", huge_participant_base, i);
            b.register_participant(&huge_participant_id);
        }

        assert_eq!(b.registered_participants().len(), 1000);

        // Propose barrier with massive participant set
        let result = b.propose(0, 1, 1000, "trace-massive-participants");
        assert!(result.is_ok(), "Should handle large participant sets");

        let barrier_id = b.active_barrier().unwrap().barrier_id.clone();

        // Attempt to exhaust memory with massive drain ACKs
        let mut successful_acks: u32 = 0;
        for i in 0..1000 {
            let participant_id = format!("{}-{}", huge_participant_base, i);
            let huge_trace_id = "t".repeat(5000); // Very large trace ID

            let massive_ack = DrainAck {
                participant_id,
                barrier_id: barrier_id.clone(),
                drained_items: u64::MAX,
                elapsed_ms: i as u64 * 10,
                trace_id: format!("{}-{}", huge_trace_id, i),
            };

            match b.record_drain_ack(massive_ack) {
                Ok(_) => successful_acks = successful_acks.saturating_add(1),
                Err(_) => break, // Stop on first error
            }
        }

        // Should process reasonable number without memory exhaustion
        assert!(
            successful_acks > 0,
            "Should process some ACKs without memory exhaustion"
        );

        // Test massive transcript generation
        let transcript = b.transcript().unwrap();
        assert!(transcript.entries.len() <= MAX_TRANSCRIPT_ENTRIES);

        // Test rapid barrier creation/destruction cycles
        for cycle in 0..100 {
            let cycle_config = BarrierConfig::new(1000, 100);
            let mut cycle_barrier = EpochTransitionBarrier::new(cycle_config);

            // Register participants with large IDs
            let cycle_participant = format!("cycle-{}-{}", "x".repeat(100), cycle);
            cycle_barrier.register_participant(&cycle_participant);

            // Create and abort barriers rapidly
            let propose_result = cycle_barrier.propose(
                cycle as u64,
                (cycle as u64).saturating_add(1),
                10000_u64.saturating_add(cycle as u64),
                &format!("cycle-trace-{}-{}", "y".repeat(200), cycle),
            );

            if let Ok(_) = propose_result {
                let abort_result = cycle_barrier.abort(
                    AbortReason::Cancelled {
                        detail: format!("cycle-{}-{}", "z".repeat(300), cycle),
                    },
                    10100 + cycle,
                    &format!("abort-trace-{}", cycle),
                );
                let _ = abort_result; // Memory management should handle this gracefully
            }
        }
    }

    /// Negative test: Concurrent operation safety and race conditions
    #[test]
    fn negative_concurrent_operation_race_conditions() {
        let mut b = EpochTransitionBarrier::default();

        // Register multiple participants for concurrency testing
        let participants = ["svc-a", "svc-b", "svc-c", "svc-d"];
        for participant in &participants {
            b.register_participant(participant);
        }

        // Test concurrent barrier proposals (should be serialized)
        b.propose(10, 11, 5000, "trace-concurrent-1").unwrap();

        let concurrent_result = b.propose(11, 12, 5001, "trace-concurrent-2");
        assert!(
            concurrent_result.is_err(),
            "Concurrent proposals should be rejected"
        );
        assert_eq!(
            concurrent_result.unwrap_err().code(),
            error_codes::ERR_BARRIER_CONCURRENT
        );

        // Test overlapping drain ACK operations
        let barrier_id = b.active_barrier().unwrap().barrier_id.clone();
        let mut ack_results = Vec::new();

        // Simulate concurrent ACKs with overlapping timestamps
        for (i, participant) in participants.iter().enumerate() {
            let ack = DrainAck {
                participant_id: participant.to_string(),
                barrier_id: barrier_id.clone(),
                drained_items: 100 + i as u64,
                elapsed_ms: 50, // Same elapsed time (concurrent)
                trace_id: format!("concurrent-trace-{}", i),
            };

            ack_results.push(b.record_drain_ack(ack));
        }

        // All ACKs should succeed despite concurrency
        for (i, result) in ack_results.iter().enumerate() {
            assert!(
                result.is_ok(),
                "ACK {} should succeed in concurrent scenario",
                i
            );
        }

        // Verify state consistency despite concurrent operations
        assert!(
            b.active_barrier().unwrap().all_acked(),
            "All participants should be ACKed"
        );
        assert_eq!(b.active_barrier().unwrap().ack_count(), participants.len());

        // Test concurrent commit attempts
        let commit_result = b.try_commit(5200, "trace-commit-1");
        assert!(commit_result.is_ok(), "First commit should succeed");

        // Subsequent operations on committed barrier should fail gracefully
        let late_ack = DrainAck {
            participant_id: "svc-a".to_string(),
            barrier_id: barrier_id.clone(),
            drained_items: 200,
            elapsed_ms: 100,
            trace_id: "late-trace".to_string(),
        };

        let late_result = b.record_drain_ack(late_ack);
        assert!(late_result.is_err(), "Late ACK should be rejected");
        assert_eq!(
            late_result.unwrap_err().code(),
            error_codes::ERR_BARRIER_ALREADY_COMPLETE
        );

        // Test concurrent abort on completed barrier
        let concurrent_abort = b.abort(
            AbortReason::Cancelled {
                detail: "concurrent".to_string(),
            },
            5300,
            "trace-concurrent-abort",
        );
        assert!(
            concurrent_abort.is_err(),
            "Abort on completed barrier should fail"
        );
        assert_eq!(
            concurrent_abort.unwrap_err().code(),
            error_codes::ERR_BARRIER_ALREADY_COMPLETE
        );
    }

    /// Negative test: Configuration validation edge cases and boundary attacks
    #[test]
    fn negative_configuration_validation_edge_cases() {
        // Test zero and boundary timeout values
        let zero_global_config = BarrierConfig::new(0, 100);
        assert!(
            zero_global_config.validate().is_err(),
            "Zero global timeout should be invalid"
        );

        let zero_drain_config = BarrierConfig::new(1000, 0);
        assert!(
            zero_drain_config.validate().is_err(),
            "Zero drain timeout should be invalid"
        );

        // Test inverted timeout relationship
        let inverted_config = BarrierConfig::new(100, 1000);
        assert!(
            inverted_config.validate().is_err(),
            "Drain timeout exceeding global should be invalid"
        );

        // Test boundary values
        let boundary_config = BarrierConfig::new(1, 1);
        assert!(
            boundary_config.validate().is_ok(),
            "Minimum valid timeouts should be accepted"
        );

        let max_config = BarrierConfig::new(u64::MAX, u64::MAX);
        assert!(
            max_config.validate().is_err(),
            "Equal max timeouts should be rejected"
        );

        let near_max_config = BarrierConfig::new(u64::MAX, u64::MAX - 1);
        assert!(
            near_max_config.validate().is_ok(),
            "Near-max timeouts should be valid"
        );

        // Test participant timeout overrides with edge cases
        let mut override_config = BarrierConfig::new(10000, 1000);

        // Zero participant timeout
        override_config
            .participant_timeouts
            .insert("zero-svc".to_string(), 0);
        assert!(
            override_config.validate().is_err(),
            "Zero participant timeout should be invalid"
        );

        // Maximum participant timeout
        override_config.participant_timeouts.clear();
        override_config
            .participant_timeouts
            .insert("max-svc".to_string(), u64::MAX);
        assert!(
            override_config.validate().is_ok(),
            "Max participant timeout should be valid"
        );

        // Test capping behavior
        assert_eq!(
            override_config.drain_timeout_for("max-svc"),
            override_config.global_timeout_ms,
            "Participant timeout should be capped by global timeout"
        );

        // Test default fallback
        assert_eq!(
            override_config.drain_timeout_for("unknown-svc"),
            override_config.default_drain_timeout_ms,
            "Unknown participant should use default timeout"
        );

        // Test massive participant timeout map
        let mut massive_config = BarrierConfig::new(30000, 1000);
        for i in 0..10000 {
            massive_config
                .participant_timeouts
                .insert(format!("participant-{}", i), 1000 + (i % 5000) as u64);
        }

        assert!(
            massive_config.validate().is_ok(),
            "Large participant timeout map should be valid"
        );

        // Test timeout lookup performance doesn't degrade
        let start_time = std::time::Instant::now();
        for i in 0..1000 {
            let _ = massive_config.drain_timeout_for(&format!("participant-{}", i));
        }
        let lookup_duration = start_time.elapsed();
        assert!(
            lookup_duration < std::time::Duration::from_millis(100),
            "Timeout lookups should be fast"
        );
    }

    /// Negative test: Transcript integrity under corruption and attack scenarios
    #[test]
    fn negative_transcript_integrity_under_attack() {
        let mut b = EpochTransitionBarrier::default();
        b.register_participant("attack-svc");

        // Test transcript with extremely long event details
        let huge_detail = "x".repeat(100000);
        b.propose(50, 51, 20000, &format!("attack-{}", huge_detail))
            .unwrap();

        // Verify transcript handles large entries without corruption
        let transcript = b.transcript().unwrap();
        assert_eq!(transcript.entries.len(), 1);
        assert!(transcript.entries[0].detail.len() > 50000);

        // Test transcript with malicious JSON-breaking content
        let json_attack_detail =
            r#"{"malicious": "attack", "quote": "\"", "newline": "\n", "null": "\0"}"#;
        let barrier_id = b.active_barrier().unwrap().barrier_id.clone();

        let attack_ack = DrainAck {
            participant_id: "attack-svc".to_string(),
            barrier_id: barrier_id.clone(),
            drained_items: 1,
            elapsed_ms: 100,
            trace_id: json_attack_detail.to_string(),
        };

        let ack_result = b.record_drain_ack(attack_ack);
        assert!(ack_result.is_ok(), "Should handle JSON-breaking content");

        // Test JSONL export integrity
        let jsonl_export = transcript.export_jsonl();
        assert!(!jsonl_export.is_empty(), "JSONL export should not be empty");

        // Verify each line is valid JSON despite attack content
        for line in jsonl_export.lines() {
            if !line.trim().is_empty() {
                let parse_result: Result<serde_json::Value, _> = serde_json::from_str(line);
                assert!(
                    parse_result.is_ok(),
                    "Each JSONL line should be valid JSON: {}",
                    line
                );
            }
        }

        // Test transcript capacity limits with flooding attack
        for flood_idx in 0..MAX_TRANSCRIPT_ENTRIES.saturating_add(1000) {
            let flood_detail = format!("flood-attack-{}-{}", flood_idx, "padding".repeat(100));
            b.active_barrier.as_mut().unwrap().transcript.record(
                "FLOOD_ATTACK",
                &flood_detail,
                20000 + flood_idx as u64,
                &format!("flood-trace-{}", flood_idx),
            );
        }

        // Verify transcript is properly bounded
        let flooded_transcript = b.transcript().unwrap();
        assert!(
            flooded_transcript.entries.len() <= MAX_TRANSCRIPT_ENTRIES,
            "Transcript should be bounded despite flood attack"
        );

        // Test transcript schema version consistency
        assert_eq!(
            flooded_transcript.schema_version, SCHEMA_VERSION,
            "Schema version should remain consistent"
        );

        // Test transcript phase synchronization under attack
        b.abort(
            AbortReason::DrainFailed {
                participant_id: "attack-svc".to_string(),
                detail: "attack-induced failure".to_string(),
            },
            25000,
            "abort-trace",
        )
        .unwrap();

        let final_transcript = b.transcript().unwrap();
        assert_eq!(
            final_transcript.phase,
            BarrierPhase::Aborted,
            "Transcript phase should match barrier phase"
        );

        // Verify audit history integrity
        assert_eq!(b.completed_barrier_count(), 1);
        assert_eq!(b.audit_history()[0].outcome, "ABORTED");

        // Test audit export with attack content
        let audit_jsonl = b.export_audit_log_jsonl();
        assert!(!audit_jsonl.is_empty());

        for line in audit_jsonl.lines() {
            if !line.trim().is_empty() {
                let parse_result: Result<serde_json::Value, _> = serde_json::from_str(line);
                assert!(
                    parse_result.is_ok(),
                    "Audit JSONL should be valid despite attack content"
                );
            }
        }
    }

    /// Negative test: Timing attack resistance in barrier validation and participant lookup
    #[test]
    fn negative_timing_attack_resistance() {
        let mut b = EpochTransitionBarrier::default();

        // Register mix of participants for timing analysis
        let legitimate_participants = ["svc-1", "svc-2", "svc-alpha"];
        let fake_participants = ["svc-99", "nonexistent", "svc-beta"];

        for participant in &legitimate_participants {
            b.register_participant(participant);
        }

        b.propose(30, 31, 15000, "timing-test").unwrap();
        let barrier_id = b.active_barrier().unwrap().barrier_id.clone();

        // Test timing consistency for participant validation
        let mut timing_results = Vec::new();
        let all_test_participants = [&legitimate_participants[..], &fake_participants[..]].concat();

        for participant in &all_test_participants {
            let test_ack = DrainAck {
                participant_id: participant.to_string(),
                barrier_id: barrier_id.clone(),
                drained_items: 50,
                elapsed_ms: 200,
                trace_id: format!("timing-trace-{}", participant),
            };

            let start_time = std::time::Instant::now();
            let _result = b.record_drain_ack(test_ack);
            let duration = start_time.elapsed();
            timing_results.push(duration);
        }

        // Timing should be relatively consistent (no timing-based information leakage)
        let max_timing = timing_results.iter().max().unwrap();
        let min_timing = timing_results.iter().min().unwrap();
        let timing_ratio = max_timing.as_nanos() as f64 / min_timing.as_nanos() as f64;

        assert!(
            timing_ratio.is_finite(),
            "Timing ratio must be finite for meaningful comparison"
        );
        assert!(
            timing_ratio < 5.0,
            "Participant validation timing variance too high: {}",
            timing_ratio
        );

        // Test barrier ID validation timing consistency
        let test_barrier_ids = [
            barrier_id.clone(),
            "barrier-000999".to_string(),
            "barrier-999999".to_string(),
            "nonexistent-barrier".to_string(),
            "".to_string(),
        ];

        let mut barrier_timing_results = Vec::new();
        for test_id in &test_barrier_ids {
            let test_ack = DrainAck {
                participant_id: "svc-1".to_string(),
                barrier_id: test_id.clone(),
                drained_items: 10,
                elapsed_ms: 50,
                trace_id: "barrier-timing-test".to_string(),
            };

            let start_time = std::time::Instant::now();
            let _result = b.record_drain_ack(test_ack);
            let duration = start_time.elapsed();
            barrier_timing_results.push(duration);
        }

        // Barrier ID validation timing should also be consistent
        let max_barrier_timing = barrier_timing_results.iter().max().unwrap();
        let min_barrier_timing = barrier_timing_results.iter().min().unwrap();
        let barrier_timing_ratio =
            max_barrier_timing.as_nanos() as f64 / min_barrier_timing.as_nanos() as f64;

        assert!(
            barrier_timing_ratio.is_finite(),
            "Barrier timing ratio must be finite for meaningful comparison"
        );
        assert!(
            barrier_timing_ratio < 4.0,
            "Barrier ID validation timing variance too high: {}",
            barrier_timing_ratio
        );

        // Test participant timeout check timing consistency
        let mut timeout_barrier = EpochTransitionBarrier::default();
        for participant in &all_test_participants {
            timeout_barrier.register_participant(participant);
        }
        timeout_barrier
            .propose(40, 41, 30000, "timeout-timing-test")
            .unwrap();

        let mut timeout_timing_results = Vec::new();
        for _ in 0..10 {
            let start_time = std::time::Instant::now();
            let _result = timeout_barrier.check_participant_timeouts(35000, "timing-check");
            let duration = start_time.elapsed();
            timeout_timing_results.push(duration);
        }

        // Timeout checking should have consistent performance
        let max_timeout_timing = timeout_timing_results.iter().max().unwrap();
        let min_timeout_timing = timeout_timing_results.iter().min().unwrap();
        let timeout_timing_ratio =
            max_timeout_timing.as_nanos() as f64 / min_timeout_timing.as_nanos() as f64;

        assert!(
            timeout_timing_ratio.is_finite(),
            "Timeout timing ratio must be finite for meaningful comparison"
        );
        assert!(
            timeout_timing_ratio < 3.0,
            "Timeout check timing variance too high: {}",
            timeout_timing_ratio
        );
    }

    /// Negative test: Push_bounded edge cases and audit history capacity attacks
    #[test]
    fn negative_push_bounded_and_audit_capacity_attacks() {
        // Test push_bounded with edge cases
        let mut test_items = vec![1, 2, 3];

        // Test zero capacity (should clear)
        push_bounded(&mut test_items, 4, 0);
        assert!(test_items.is_empty(), "Zero capacity should clear items");

        // Test capacity larger than current size
        let mut small_items = vec![1];
        push_bounded(&mut small_items, 2, 10);
        assert_eq!(small_items, vec![1, 2], "Should append when under capacity");

        // Test exact capacity boundary
        let mut exact_items = vec![1, 2, 3];
        push_bounded(&mut exact_items, 4, 3);
        assert_eq!(
            exact_items,
            vec![2, 3, 4],
            "Should maintain capacity exactly"
        );

        // Test massive overflow scenario
        let mut massive_items: Vec<i32> = (1..50000).collect();
        push_bounded(&mut massive_items, 99999, 100);
        assert_eq!(massive_items.len(), 100, "Should be bounded to capacity");
        assert_eq!(massive_items[99], 99999, "Should contain new item");

        // Test audit history capacity attacks
        let mut b = EpochTransitionBarrier::default();
        b.register_participant("audit-svc");

        // Create many barriers to flood audit history
        for i in 0..MAX_BARRIER_HISTORY.saturating_add(500) {
            let propose_result = b.propose(
                i as u64,
                (i as u64).saturating_add(1),
                (i as u64).saturating_mul(1000),
                &format!("audit-flood-{}", i),
            );

            if let Ok(_) = propose_result {
                // Complete barrier immediately
                let barrier_id = b.active_barrier().unwrap().barrier_id.clone();
                let ack = DrainAck {
                    participant_id: "audit-svc".to_string(),
                    barrier_id,
                    drained_items: 1,
                    elapsed_ms: 10,
                    trace_id: format!("audit-trace-{}", i),
                };

                if b.record_drain_ack(ack).is_ok() {
                    // Note: In stress test, commit may fail due to overflow - that's expected behavior
                    if b.try_commit(
                        (i as u64).saturating_mul(1000).saturating_add(100),
                        &format!("commit-{}", i),
                    )
                    .is_err()
                    {
                        // If commit fails (e.g., overflow), that's part of stress testing - continue
                    }
                }
            } else {
                // If barrier creation fails (e.g., overflow), abort the test
                break;
            }
        }

        // Audit history should be bounded
        assert!(
            b.completed_barrier_count() <= MAX_BARRIER_HISTORY,
            "Audit history should be bounded despite flood attack"
        );

        // Recent entries should be preserved
        if !b.audit_history().is_empty() {
            let latest_audit = &b.audit_history()[b.audit_history().len() - 1];
            assert!(
                latest_audit.barrier_id.contains("barrier-"),
                "Latest audit entry should be well-formed"
            );
        }

        // Test transcript capacity during flooding
        let mut transcript_flood_barrier = EpochTransitionBarrier::default();
        transcript_flood_barrier.register_participant("transcript-svc");
        transcript_flood_barrier
            .propose(1000, 1001, 50000, "transcript-flood")
            .unwrap();

        // Flood transcript with massive number of entries
        for flood_i in 0..MAX_TRANSCRIPT_ENTRIES + 2000 {
            transcript_flood_barrier
                .active_barrier
                .as_mut()
                .unwrap()
                .transcript
                .record(
                    "FLOOD_EVENT",
                    &format!("flood-detail-{}-{}", flood_i, "x".repeat(500)),
                    50000 + flood_i as u64,
                    &format!("flood-trace-{}", flood_i),
                );
        }

        // Verify transcript is properly bounded
        let transcript = transcript_flood_barrier.transcript().unwrap();
        assert!(
            transcript.entries.len() <= MAX_TRANSCRIPT_ENTRIES,
            "Transcript should be bounded despite massive flooding"
        );

        // Recent entries should be preserved (FIFO eviction)
        let last_entry = &transcript.entries[transcript.entries.len() - 1];
        assert!(
            last_entry.event_code == "FLOOD_EVENT",
            "Most recent entries should be preserved"
        );
        assert!(
            last_entry.detail.contains(&format!(
                "flood-detail-{}",
                MAX_TRANSCRIPT_ENTRIES + 2000 - 1
            )),
            "Latest flood entry should be preserved"
        );
    }

    /// Negative test: State consistency under various error conditions and edge cases
    #[test]
    fn negative_state_consistency_under_error_conditions() {
        let mut b = EpochTransitionBarrier::default();
        b.register_participant("consistent-svc");

        // Test state consistency after failed propose due to no participants
        let mut empty_barrier = EpochTransitionBarrier::default();
        let no_participants_result = empty_barrier.propose(0, 1, 1000, "no-participants");
        assert!(no_participants_result.is_err());
        assert!(!empty_barrier.is_barrier_active());
        assert_eq!(empty_barrier.completed_barrier_count(), 0);

        // Test state consistency after epoch mismatch
        let epoch_mismatch_result = b.propose(5, 7, 2000, "epoch-mismatch");
        assert!(epoch_mismatch_result.is_err());
        assert!(!b.is_barrier_active());
        assert_eq!(b.completed_barrier_count(), 0);

        // Create valid barrier for further testing
        b.propose(10, 11, 3000, "valid-barrier").unwrap();
        let barrier_id = b.active_barrier().unwrap().barrier_id.clone();

        // Test state consistency after unknown participant ACK
        let unknown_ack = DrainAck {
            participant_id: "unknown-svc".to_string(),
            barrier_id: barrier_id.clone(),
            drained_items: 10,
            elapsed_ms: 50,
            trace_id: "unknown-trace".to_string(),
        };

        let unknown_result = b.record_drain_ack(unknown_ack);
        assert!(unknown_result.is_err());
        assert_eq!(
            unknown_result.unwrap_err().code(),
            error_codes::ERR_BARRIER_UNKNOWN_PARTICIPANT
        );

        // Barrier should remain in consistent state
        assert!(b.is_barrier_active());
        assert_eq!(b.active_barrier().unwrap().ack_count(), 0);
        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Draining);

        // Test state consistency after barrier ID mismatch
        let wrong_id_ack = DrainAck {
            participant_id: "consistent-svc".to_string(),
            barrier_id: "barrier-999999".to_string(),
            drained_items: 10,
            elapsed_ms: 50,
            trace_id: "wrong-id-trace".to_string(),
        };

        let wrong_id_result = b.record_drain_ack(wrong_id_ack);
        assert!(wrong_id_result.is_err());
        assert_eq!(
            wrong_id_result.unwrap_err().code(),
            error_codes::ERR_BARRIER_ID_MISMATCH
        );

        // State should still be consistent
        assert!(b.is_barrier_active());
        assert_eq!(b.active_barrier().unwrap().ack_count(), 0);

        // Test successful ACK after errors
        let valid_ack = DrainAck {
            participant_id: "consistent-svc".to_string(),
            barrier_id: barrier_id.clone(),
            drained_items: 100,
            elapsed_ms: 200,
            trace_id: "valid-trace".to_string(),
        };

        let valid_result = b.record_drain_ack(valid_ack);
        assert!(valid_result.is_ok());
        assert_eq!(b.active_barrier().unwrap().ack_count(), 1);

        // Test state consistency after commit
        let commit_result = b.try_commit(3500, "commit-trace");
        assert!(commit_result.is_ok());
        assert!(!b.is_barrier_active());
        assert_eq!(b.active_barrier().unwrap().phase, BarrierPhase::Committed);
        assert_eq!(b.completed_barrier_count(), 1);

        // Test operations on committed barrier fail gracefully
        let post_commit_ack = DrainAck {
            participant_id: "consistent-svc".to_string(),
            barrier_id: barrier_id.clone(),
            drained_items: 50,
            elapsed_ms: 100,
            trace_id: "post-commit-trace".to_string(),
        };

        let post_commit_result = b.record_drain_ack(post_commit_ack);
        assert!(post_commit_result.is_err());
        assert_eq!(
            post_commit_result.unwrap_err().code(),
            error_codes::ERR_BARRIER_ALREADY_COMPLETE
        );

        // Test participant registration/deregistration consistency
        let before_participants = b.registered_participants().len();
        b.register_participant("new-svc");
        assert_eq!(b.registered_participants().len(), before_participants + 1);

        // Should be able to unregister after barrier completion
        let unregister_result = b.unregister_participant("new-svc");
        assert!(unregister_result.is_ok());
        assert_eq!(b.registered_participants().len(), before_participants);

        // Test new barrier creation after completion
        b.register_participant("new-barrier-svc");
        let new_barrier_result = b.propose(11, 12, 5000, "new-barrier");
        assert!(new_barrier_result.is_ok());
        assert!(b.is_barrier_active());
        assert_eq!(b.active_barrier().unwrap().current_epoch, 11);
        assert_eq!(b.active_barrier().unwrap().target_epoch, 12);
    }
}
