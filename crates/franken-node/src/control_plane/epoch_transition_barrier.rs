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
pub const DEFAULT_BARRIER_TIMEOUT_MS: u64 = 30_000;

/// Default per-participant drain timeout in milliseconds.
pub const DEFAULT_DRAIN_TIMEOUT_MS: u64 = 10_000;

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
    pub const ERR_BARRIER_TIMEOUT: &str = "ERR_BARRIER_TIMEOUT";
    pub const ERR_BARRIER_DRAIN_FAILED: &str = "ERR_BARRIER_DRAIN_FAILED";
    pub const ERR_BARRIER_ALREADY_COMPLETE: &str = "ERR_BARRIER_ALREADY_COMPLETE";
    pub const ERR_BARRIER_INVALID_PHASE: &str = "ERR_BARRIER_INVALID_PHASE";
    pub const ERR_BARRIER_UNKNOWN_PARTICIPANT: &str = "ERR_BARRIER_UNKNOWN_PARTICIPANT";
    pub const ERR_BARRIER_EPOCH_MISMATCH: &str = "ERR_BARRIER_EPOCH_MISMATCH";
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
    /// Target epoch does not match expected next epoch.
    EpochMismatch { expected: u64, provided: u64 },
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
            Self::EpochMismatch { .. } => error_codes::ERR_BARRIER_EPOCH_MISMATCH,
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
            Self::EpochMismatch { expected, provided } => {
                write!(
                    f,
                    "{}: expected target epoch {} but got {}",
                    self.code(),
                    expected,
                    provided
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
        self.entries.push(TranscriptEntry {
            event_code: event_code.to_string(),
            barrier_id: self.barrier_id.clone(),
            timestamp_ms,
            detail: detail.to_string(),
            trace_id: trace_id.to_string(),
        });
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
        if let Some(active) = &self.active_barrier {
            return Err(BarrierError::ConcurrentBarrier {
                active_barrier_id: active.barrier_id.clone(),
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
                active_barrier_id: self.active_barrier.as_ref().unwrap().barrier_id.clone(),
            });
        }

        if self.participants.is_empty() {
            return Err(BarrierError::NoParticipants);
        }

        // Validate target epoch is current + 1
        if target_epoch != current_epoch + 1 {
            return Err(BarrierError::EpochMismatch {
                expected: current_epoch + 1,
                provided: target_epoch,
            });
        }

        self.barrier_counter += 1;
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
        Ok(self.active_barrier.as_ref().unwrap())
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

        if !barrier.participants.contains(&ack.participant_id) {
            return Err(BarrierError::UnknownParticipant {
                participant_id: ack.participant_id.clone(),
            });
        }

        let timestamp_ms = barrier.propose_timestamp_ms + ack.elapsed_ms;
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
    pub fn try_commit(&mut self, timestamp_ms: u64, trace_id: &str) -> Result<u64, BarrierError> {
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
                return self.abort(
                    AbortReason::Timeout {
                        missing_participants: missing,
                    },
                    timestamp_ms,
                    trace_id,
                );
            }

            return Err(BarrierError::Timeout {
                barrier_id: barrier.barrier_id.clone(),
                missing,
                elapsed_ms: elapsed,
            });
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
        self.history.push(BarrierAuditRecord {
            barrier_id: barrier.barrier_id.clone(),
            current_epoch: barrier.current_epoch,
            target_epoch: barrier.target_epoch,
            outcome: "COMMITTED".to_string(),
            participant_count: barrier.participants.len(),
            acks_received: barrier.ack_count(),
            elapsed_ms: timestamp_ms.saturating_sub(barrier.propose_timestamp_ms),
            abort_reason: None,
            schema_version: SCHEMA_VERSION.to_string(),
        });

        Ok(target_epoch)
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
        self.history.push(BarrierAuditRecord {
            barrier_id: barrier.barrier_id.clone(),
            current_epoch: barrier.current_epoch,
            target_epoch: barrier.target_epoch,
            outcome: "ABORTED".to_string(),
            participant_count: barrier.participants.len(),
            acks_received: barrier.ack_count(),
            elapsed_ms: timestamp_ms.saturating_sub(barrier.propose_timestamp_ms),
            abort_reason: Some(reason_str),
            schema_version: SCHEMA_VERSION.to_string(),
        });

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

#[cfg(test)]
mod tests {
    use super::*;

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

        let new_epoch = b.try_commit(1200, "t1").unwrap();
        assert_eq!(new_epoch, 6);
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
        assert_eq!(err.code(), error_codes::ERR_BARRIER_TIMEOUT);
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
        let epoch = b
            .try_commit(1000 + DEFAULT_BARRIER_TIMEOUT_MS, "t1")
            .unwrap();
        // try_commit triggers abort when timed out and returns current epoch
        // Actually, let me re-read the logic...
        // When not all acked and elapsed >= global_timeout, it calls self.abort()
        // which returns Ok(current_epoch)
        assert_eq!(epoch, 5);
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

    // ---- Operations on completed barrier ----

    #[test]
    fn ack_on_committed_barrier_fails() {
        let mut b = make_barrier(1);
        b.propose(5, 6, 1000, "t1").unwrap();
        b.record_drain_ack(make_ack("svc-0", "barrier-000001", 50))
            .unwrap();
        b.try_commit(1100, "t1").unwrap();

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
        b.try_commit(1100, "t1").unwrap();

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
        b.try_commit(1200, "t1").unwrap();

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
        b.try_commit(1100, "t1").unwrap();

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
        b.try_commit(1100, "t1").unwrap();

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
        b.try_commit(1100, "t1").unwrap();

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
        b.try_commit(1100, "t1").unwrap();

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
            BarrierError::EpochMismatch {
                expected: 6,
                provided: 8,
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
        b.try_commit(1100, "t1").unwrap();

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
        b.try_commit(1100, "t1").unwrap();

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
}
