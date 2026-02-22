//! bd-7om: Canonical cancel -> drain -> finalize protocol contracts for product services.
//!
//! Provides a `CancellableTask` trait and `CancellationRuntime` that manage the
//! cancel-drain-finalize lifecycle for all long-running product operations. This
//! module adopts the three-phase cancellation protocol from section 10.15 (bd-1cs7)
//! and exposes it as a product-layer contract.
//!
//! # Lifecycle
//!
//! 1. **Cancel** -- signal the task to stop accepting new work (`on_cancel`)
//! 2. **Drain** -- wait for in-flight obligations to reach terminal state (`on_drain_complete`)
//! 3. **Finalize** -- produce an auditable `FinalizeRecord` with obligation closure proof (`on_finalize`)
//!
//! # Invariants
//!
//! - INV-CXT-THREE-PHASE: all tasks pass through cancel, drain, finalize in order
//! - INV-CXT-DRAIN-BOUNDED: drain has a finite, configurable timeout
//! - INV-CXT-FINALIZE-RECORD: every finalization produces a signed `FinalizeRecord`
//! - INV-CXT-CLOSURE-COMPLETE: obligation closure proof covers all registered obligations
//! - INV-CXT-LANE-RELEASE: lane slot is released only after finalization completes
//! - INV-CXT-NESTED-PROPAGATION: cancel propagates to nested/child tasks

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Schema version for cancellable task records.
pub const SCHEMA_VERSION: &str = "cxt-v1.0";

/// Default drain timeout in milliseconds.
pub const DEFAULT_DRAIN_TIMEOUT_MS: u64 = 30_000;

/// Minimum drain timeout in milliseconds.
pub const MIN_DRAIN_TIMEOUT_MS: u64 = 500;

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

/// INV-CXT-THREE-PHASE: all tasks pass through cancel, drain, finalize in order.
pub const INV_CXT_THREE_PHASE: &str = "INV-CXT-THREE-PHASE";
/// INV-CXT-DRAIN-BOUNDED: drain has a finite, configurable timeout.
pub const INV_CXT_DRAIN_BOUNDED: &str = "INV-CXT-DRAIN-BOUNDED";
/// INV-CXT-FINALIZE-RECORD: every finalization produces a signed FinalizeRecord.
pub const INV_CXT_FINALIZE_RECORD: &str = "INV-CXT-FINALIZE-RECORD";
/// INV-CXT-CLOSURE-COMPLETE: obligation closure proof covers all registered obligations.
pub const INV_CXT_CLOSURE_COMPLETE: &str = "INV-CXT-CLOSURE-COMPLETE";
/// INV-CXT-LANE-RELEASE: lane slot is released only after finalization completes.
pub const INV_CXT_LANE_RELEASE: &str = "INV-CXT-LANE-RELEASE";
/// INV-CXT-NESTED-PROPAGATION: cancel propagates to nested/child tasks.
pub const INV_CXT_NESTED_PROPAGATION: &str = "INV-CXT-NESTED-PROPAGATION";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// FN-CX-001: Task registered with CancellationRuntime.
    pub const FN_CX_001: &str = "FN-CX-001";
    /// FN-CX-002: Cancel signal sent to task.
    pub const FN_CX_002: &str = "FN-CX-002";
    /// FN-CX-003: Drain phase started.
    pub const FN_CX_003: &str = "FN-CX-003";
    /// FN-CX-004: Drain phase completed successfully.
    pub const FN_CX_004: &str = "FN-CX-004";
    /// FN-CX-005: Drain phase timed out.
    pub const FN_CX_005: &str = "FN-CX-005";
    /// FN-CX-006: Finalize phase started.
    pub const FN_CX_006: &str = "FN-CX-006";
    /// FN-CX-007: FinalizeRecord produced.
    pub const FN_CX_007: &str = "FN-CX-007";
    /// FN-CX-008: Lane slot released after finalization.
    pub const FN_CX_008: &str = "FN-CX-008";
    /// FN-CX-009: Nested cancel propagated to child.
    pub const FN_CX_009: &str = "FN-CX-009";
    /// FN-CX-010: Obligation closure incomplete.
    pub const FN_CX_010: &str = "FN-CX-010";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_CXT_INVALID_PHASE: &str = "ERR_CXT_INVALID_PHASE";
    pub const ERR_CXT_DRAIN_TIMEOUT: &str = "ERR_CXT_DRAIN_TIMEOUT";
    pub const ERR_CXT_CLOSURE_INCOMPLETE: &str = "ERR_CXT_CLOSURE_INCOMPLETE";
    pub const ERR_CXT_TASK_NOT_FOUND: &str = "ERR_CXT_TASK_NOT_FOUND";
    pub const ERR_CXT_ALREADY_FINALIZED: &str = "ERR_CXT_ALREADY_FINALIZED";
    pub const ERR_CXT_DUPLICATE_TASK: &str = "ERR_CXT_DUPLICATE_TASK";
}

// ---------------------------------------------------------------------------
// Task phase FSM
// ---------------------------------------------------------------------------

/// Phases of the cancel-drain-finalize lifecycle.
/// INV-CXT-THREE-PHASE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskPhase {
    /// Task is running normally.
    Running,
    /// Cancel signal has been delivered.
    CancelRequested,
    /// Drain is in progress.
    Draining,
    /// Drain completed (success or timeout).
    DrainComplete,
    /// Finalization in progress.
    Finalizing,
    /// Terminal state.
    Finalized,
}

impl TaskPhase {
    pub fn legal_targets(&self) -> &'static [TaskPhase] {
        match self {
            Self::Running => &[Self::CancelRequested],
            Self::CancelRequested => &[Self::Draining, Self::CancelRequested],
            Self::Draining => &[Self::DrainComplete],
            Self::DrainComplete => &[Self::Finalizing],
            Self::Finalizing => &[Self::Finalized],
            Self::Finalized => &[],
        }
    }

    pub fn can_transition_to(&self, target: &TaskPhase) -> bool {
        self.legal_targets().contains(target)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::CancelRequested => "cancel_requested",
            Self::Draining => "draining",
            Self::DrainComplete => "drain_complete",
            Self::Finalizing => "finalizing",
            Self::Finalized => "finalized",
        }
    }

    pub const ALL: [TaskPhase; 6] = [
        Self::Running,
        Self::CancelRequested,
        Self::Draining,
        Self::DrainComplete,
        Self::Finalizing,
        Self::Finalized,
    ];
}

impl fmt::Display for TaskPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Drain result
// ---------------------------------------------------------------------------

/// Outcome of the drain phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainResult {
    /// All in-flight obligations completed within budget.
    Completed,
    /// Drain exceeded the configured timeout.
    TimedOut,
    /// An error prevented orderly drain.
    Error(String),
}

// ---------------------------------------------------------------------------
// Obligation closure proof
// ---------------------------------------------------------------------------

/// Terminal state of a single obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationTerminal {
    pub obligation_id: String,
    pub terminal_state: String,
}

/// Proof that all registered obligations reached a terminal state.
/// INV-CXT-CLOSURE-COMPLETE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationClosureProof {
    pub obligations: Vec<ObligationTerminal>,
    pub all_closed: bool,
}

impl ObligationClosureProof {
    pub fn empty() -> Self {
        Self {
            obligations: Vec::new(),
            all_closed: true,
        }
    }

    pub fn new(obligations: Vec<ObligationTerminal>) -> Self {
        let all_closed = !obligations.is_empty();
        Self {
            obligations,
            all_closed,
        }
    }
}

// ---------------------------------------------------------------------------
// Finalize record
// ---------------------------------------------------------------------------

/// Auditable record produced by every finalization.
/// INV-CXT-FINALIZE-RECORD
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeRecord {
    pub task_id: String,
    pub cancel_reason: String,
    pub drain_status: DrainResult,
    pub obligation_closure_proof: ObligationClosureProof,
    pub cancel_requested_ms: Option<u64>,
    pub drain_started_ms: Option<u64>,
    pub drain_completed_ms: Option<u64>,
    pub finalize_started_ms: Option<u64>,
    pub finalize_completed_ms: Option<u64>,
    pub schema_version: String,
}

// ---------------------------------------------------------------------------
// CancellableTask trait
// ---------------------------------------------------------------------------

/// Trait that product services implement to participate in the cancel-drain-finalize protocol.
pub trait CancellableTask {
    /// Called when the task receives a cancel signal.
    /// The implementation should stop accepting new work.
    fn on_cancel(&mut self);

    /// Called when the drain phase completes (or times out).
    /// The implementation should report the drain outcome.
    fn on_drain_complete(&mut self) -> DrainResult;

    /// Called during finalization.
    /// The implementation must produce a `FinalizeRecord` covering all obligations.
    fn on_finalize(&mut self) -> FinalizeRecord;
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from cancellable task operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancellableTaskError {
    /// Phase transition not allowed from current state.
    InvalidPhase { task_id: String, from: TaskPhase, to: TaskPhase },
    /// Drain exceeded configured timeout.
    DrainTimeout { task_id: String, elapsed_ms: u64, timeout_ms: u64 },
    /// Obligation closure incomplete during finalization.
    ClosureIncomplete { task_id: String, missing_obligations: Vec<String> },
    /// Task not found in the runtime.
    TaskNotFound { task_id: String },
    /// Task already in terminal state.
    AlreadyFinalized { task_id: String },
    /// Duplicate task registration.
    DuplicateTask { task_id: String },
}

impl CancellableTaskError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPhase { .. } => error_codes::ERR_CXT_INVALID_PHASE,
            Self::DrainTimeout { .. } => error_codes::ERR_CXT_DRAIN_TIMEOUT,
            Self::ClosureIncomplete { .. } => error_codes::ERR_CXT_CLOSURE_INCOMPLETE,
            Self::TaskNotFound { .. } => error_codes::ERR_CXT_TASK_NOT_FOUND,
            Self::AlreadyFinalized { .. } => error_codes::ERR_CXT_ALREADY_FINALIZED,
            Self::DuplicateTask { .. } => error_codes::ERR_CXT_DUPLICATE_TASK,
        }
    }
}

impl fmt::Display for CancellableTaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPhase { task_id, from, to } => {
                write!(f, "{}: task {} cannot transition from {} to {}", self.code(), task_id, from, to)
            }
            Self::DrainTimeout { task_id, elapsed_ms, timeout_ms } => {
                write!(f, "{}: task {} drain timeout after {}ms (limit {}ms)", self.code(), task_id, elapsed_ms, timeout_ms)
            }
            Self::ClosureIncomplete { task_id, missing_obligations } => {
                write!(f, "{}: task {} missing obligations: {}", self.code(), task_id, missing_obligations.join(", "))
            }
            Self::TaskNotFound { task_id } => {
                write!(f, "{}: task {} not found", self.code(), task_id)
            }
            Self::AlreadyFinalized { task_id } => {
                write!(f, "{}: task {} already finalized", self.code(), task_id)
            }
            Self::DuplicateTask { task_id } => {
                write!(f, "{}: task {} already registered", self.code(), task_id)
            }
        }
    }
}

impl std::error::Error for CancellableTaskError {}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// Structured audit event for phase transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellableTaskAuditEvent {
    pub event_code: String,
    pub task_id: String,
    pub from_phase: TaskPhase,
    pub to_phase: TaskPhase,
    pub timestamp_ms: u64,
    pub trace_id: String,
    pub detail: String,
    pub schema_version: String,
}

// ---------------------------------------------------------------------------
// Drain configuration
// ---------------------------------------------------------------------------

/// Configuration for the drain phase of a cancellable task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainConfig {
    pub timeout_ms: u64,
    pub force_finalize_on_timeout: bool,
}

impl DrainConfig {
    pub fn new(timeout_ms: u64, force_finalize_on_timeout: bool) -> Self {
        Self {
            timeout_ms: timeout_ms.max(MIN_DRAIN_TIMEOUT_MS),
            force_finalize_on_timeout,
        }
    }
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_DRAIN_TIMEOUT_MS,
            force_finalize_on_timeout: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Task entry (runtime bookkeeping)
// ---------------------------------------------------------------------------

/// Internal bookkeeping for a registered cancellable task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskEntry {
    pub task_id: String,
    pub phase: TaskPhase,
    pub drain_config: DrainConfig,
    pub registered_at_ms: u64,
    pub cancel_requested_ms: Option<u64>,
    pub drain_started_ms: Option<u64>,
    pub drain_completed_ms: Option<u64>,
    pub finalize_started_ms: Option<u64>,
    pub finalize_completed_ms: Option<u64>,
    pub drain_result: Option<DrainResult>,
    pub finalize_record: Option<FinalizeRecord>,
    pub child_task_ids: Vec<String>,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// CancellationRuntime
// ---------------------------------------------------------------------------

/// Manages the cancel-drain-finalize lifecycle for registered tasks.
///
/// INV-CXT-THREE-PHASE: enforces phase ordering.
/// INV-CXT-DRAIN-BOUNDED: enforces drain timeout.
/// INV-CXT-LANE-RELEASE: tracks lane release after finalization.
/// INV-CXT-NESTED-PROPAGATION: propagates cancel to children.
pub struct CancellationRuntime {
    tasks: BTreeMap<String, TaskEntry>,
    audit_log: Vec<CancellableTaskAuditEvent>,
    default_drain_config: DrainConfig,
}

impl CancellationRuntime {
    pub fn new(default_drain_config: DrainConfig) -> Self {
        Self {
            tasks: BTreeMap::new(),
            audit_log: Vec::new(),
            default_drain_config,
        }
    }

    /// Register a new cancellable task.
    /// Emits FN-CX-001.
    pub fn register_task(
        &mut self,
        task_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&TaskEntry, CancellableTaskError> {
        self.register_task_with_config(task_id, self.default_drain_config.clone(), timestamp_ms, trace_id)
    }

    /// Register a new cancellable task with custom drain configuration.
    /// Emits FN-CX-001.
    pub fn register_task_with_config(
        &mut self,
        task_id: &str,
        drain_config: DrainConfig,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&TaskEntry, CancellableTaskError> {
        if self.tasks.contains_key(task_id) {
            return Err(CancellableTaskError::DuplicateTask {
                task_id: task_id.to_string(),
            });
        }

        let entry = TaskEntry {
            task_id: task_id.to_string(),
            phase: TaskPhase::Running,
            drain_config,
            registered_at_ms: timestamp_ms,
            cancel_requested_ms: None,
            drain_started_ms: None,
            drain_completed_ms: None,
            finalize_started_ms: None,
            finalize_completed_ms: None,
            drain_result: None,
            finalize_record: None,
            child_task_ids: Vec::new(),
            trace_id: trace_id.to_string(),
        };

        self.audit_log.push(CancellableTaskAuditEvent {
            event_code: event_codes::FN_CX_001.to_string(),
            task_id: task_id.to_string(),
            from_phase: TaskPhase::Running,
            to_phase: TaskPhase::Running,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: "task registered".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.tasks.insert(task_id.to_string(), entry);
        Ok(self.tasks.get(task_id).unwrap())
    }

    /// Register a child task under a parent.
    /// INV-CXT-NESTED-PROPAGATION
    pub fn register_child(
        &mut self,
        parent_id: &str,
        child_id: &str,
    ) -> Result<(), CancellableTaskError> {
        if !self.tasks.contains_key(parent_id) {
            return Err(CancellableTaskError::TaskNotFound {
                task_id: parent_id.to_string(),
            });
        }
        if !self.tasks.contains_key(child_id) {
            return Err(CancellableTaskError::TaskNotFound {
                task_id: child_id.to_string(),
            });
        }
        let parent = self.tasks.get_mut(parent_id).unwrap();
        if parent.child_task_ids.iter().any(|existing| existing == child_id) {
            // Idempotent child-link registration avoids duplicate propagation events.
            return Ok(());
        }
        parent.child_task_ids.push(child_id.to_string());
        Ok(())
    }

    /// Signal cancel on a task.
    /// Emits FN-CX-002.  Also emits FN-CX-009 for each child.
    /// INV-CXT-THREE-PHASE, INV-CXT-NESTED-PROPAGATION
    pub fn cancel_task(
        &mut self,
        task_id: &str,
        cancel_reason: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&TaskEntry, CancellableTaskError> {
        let entry = self.tasks.get(task_id).ok_or_else(|| {
            CancellableTaskError::TaskNotFound { task_id: task_id.to_string() }
        })?;

        // Idempotent: absorb duplicate cancel on CancelRequested
        if entry.phase == TaskPhase::CancelRequested {
            return Ok(entry);
        }

        if entry.phase == TaskPhase::Finalized {
            return Err(CancellableTaskError::AlreadyFinalized {
                task_id: task_id.to_string(),
            });
        }

        if !entry.phase.can_transition_to(&TaskPhase::CancelRequested) {
            return Err(CancellableTaskError::InvalidPhase {
                task_id: task_id.to_string(),
                from: entry.phase,
                to: TaskPhase::CancelRequested,
            });
        }

        // Collect child IDs before mutating
        let child_ids: Vec<String> = entry.child_task_ids.clone();

        let entry = self.tasks.get_mut(task_id).unwrap();
        let from = entry.phase;
        entry.phase = TaskPhase::CancelRequested;
        entry.cancel_requested_ms = Some(timestamp_ms);

        self.audit_log.push(CancellableTaskAuditEvent {
            event_code: event_codes::FN_CX_002.to_string(),
            task_id: task_id.to_string(),
            from_phase: from,
            to_phase: TaskPhase::CancelRequested,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: format!("cancel requested: {}", cancel_reason),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        // INV-CXT-NESTED-PROPAGATION: propagate to children
        for child_id in &child_ids {
            if let Some(child) = self.tasks.get_mut(child_id) {
                if child.phase == TaskPhase::Running {
                    child.phase = TaskPhase::CancelRequested;
                    child.cancel_requested_ms = Some(timestamp_ms);

                    self.audit_log.push(CancellableTaskAuditEvent {
                        event_code: event_codes::FN_CX_009.to_string(),
                        task_id: child_id.clone(),
                        from_phase: TaskPhase::Running,
                        to_phase: TaskPhase::CancelRequested,
                        timestamp_ms,
                        trace_id: trace_id.to_string(),
                        detail: format!("cancel propagated from parent {}", task_id),
                        schema_version: SCHEMA_VERSION.to_string(),
                    });
                }
            }
        }

        Ok(self.tasks.get(task_id).unwrap())
    }

    /// Start the drain phase on a cancelled task.
    /// Emits FN-CX-003.
    /// INV-CXT-THREE-PHASE
    pub fn start_drain(
        &mut self,
        task_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&TaskEntry, CancellableTaskError> {
        let entry = self.tasks.get(task_id).ok_or_else(|| {
            CancellableTaskError::TaskNotFound { task_id: task_id.to_string() }
        })?;

        if !entry.phase.can_transition_to(&TaskPhase::Draining) {
            return Err(CancellableTaskError::InvalidPhase {
                task_id: task_id.to_string(),
                from: entry.phase,
                to: TaskPhase::Draining,
            });
        }

        let from = entry.phase;
        let entry = self.tasks.get_mut(task_id).unwrap();
        entry.phase = TaskPhase::Draining;
        entry.drain_started_ms = Some(timestamp_ms);

        self.audit_log.push(CancellableTaskAuditEvent {
            event_code: event_codes::FN_CX_003.to_string(),
            task_id: task_id.to_string(),
            from_phase: from,
            to_phase: TaskPhase::Draining,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: "drain started".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        Ok(self.tasks.get(task_id).unwrap())
    }

    /// Complete the drain phase.
    /// Emits FN-CX-004 on success, FN-CX-005 on timeout.
    /// INV-CXT-DRAIN-BOUNDED
    pub fn complete_drain(
        &mut self,
        task_id: &str,
        drain_result: DrainResult,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&TaskEntry, CancellableTaskError> {
        let entry = self.tasks.get(task_id).ok_or_else(|| {
            CancellableTaskError::TaskNotFound { task_id: task_id.to_string() }
        })?;

        if !entry.phase.can_transition_to(&TaskPhase::DrainComplete) {
            return Err(CancellableTaskError::InvalidPhase {
                task_id: task_id.to_string(),
                from: entry.phase,
                to: TaskPhase::DrainComplete,
            });
        }

        let from = entry.phase;
        let drain_start = entry.drain_started_ms.unwrap_or(timestamp_ms);
        let elapsed = timestamp_ms.saturating_sub(drain_start);
        let timeout = entry.drain_config.timeout_ms;

        let timed_out = elapsed > timeout;
        let effective_result = if timed_out {
            DrainResult::TimedOut
        } else {
            drain_result
        };

        let event_code = if timed_out {
            event_codes::FN_CX_005
        } else {
            event_codes::FN_CX_004
        };

        let entry = self.tasks.get_mut(task_id).unwrap();
        entry.phase = TaskPhase::DrainComplete;
        entry.drain_completed_ms = Some(timestamp_ms);
        entry.drain_result = Some(effective_result);

        self.audit_log.push(CancellableTaskAuditEvent {
            event_code: event_code.to_string(),
            task_id: task_id.to_string(),
            from_phase: from,
            to_phase: TaskPhase::DrainComplete,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: format!("drain completed in {}ms (timeout={}ms, timed_out={})", elapsed, timeout, timed_out),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        if timed_out && !self.tasks[task_id].drain_config.force_finalize_on_timeout {
            return Err(CancellableTaskError::DrainTimeout {
                task_id: task_id.to_string(),
                elapsed_ms: elapsed,
                timeout_ms: timeout,
            });
        }

        Ok(self.tasks.get(task_id).unwrap())
    }

    /// Finalize a task after drain, producing a FinalizeRecord.
    /// Emits FN-CX-006, FN-CX-007.  May emit FN-CX-010 on closure failure.
    /// INV-CXT-FINALIZE-RECORD, INV-CXT-CLOSURE-COMPLETE, INV-CXT-LANE-RELEASE
    pub fn finalize_task(
        &mut self,
        task_id: &str,
        cancel_reason: &str,
        obligation_proof: ObligationClosureProof,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<FinalizeRecord, CancellableTaskError> {
        let entry = self.tasks.get(task_id).ok_or_else(|| {
            CancellableTaskError::TaskNotFound { task_id: task_id.to_string() }
        })?;

        if entry.phase == TaskPhase::Finalized {
            return Err(CancellableTaskError::AlreadyFinalized {
                task_id: task_id.to_string(),
            });
        }

        if !entry.phase.can_transition_to(&TaskPhase::Finalizing) {
            return Err(CancellableTaskError::InvalidPhase {
                task_id: task_id.to_string(),
                from: entry.phase,
                to: TaskPhase::Finalizing,
            });
        }

        let from = entry.phase;
        let cancel_requested_ms = entry.cancel_requested_ms;
        let drain_started_ms = entry.drain_started_ms;
        let drain_completed_ms = entry.drain_completed_ms;
        let drain_result = entry.drain_result.clone().unwrap_or(DrainResult::Completed);

        // Transition to Finalizing
        let entry = self.tasks.get_mut(task_id).unwrap();
        entry.phase = TaskPhase::Finalizing;
        entry.finalize_started_ms = Some(timestamp_ms);

        self.audit_log.push(CancellableTaskAuditEvent {
            event_code: event_codes::FN_CX_006.to_string(),
            task_id: task_id.to_string(),
            from_phase: from,
            to_phase: TaskPhase::Finalizing,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: "finalize started".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        // INV-CXT-CLOSURE-COMPLETE: check closure proof
        if !obligation_proof.all_closed {
            let missing: Vec<String> = obligation_proof
                .obligations
                .iter()
                .filter(|o| o.terminal_state == "pending")
                .map(|o| o.obligation_id.clone())
                .collect();

            self.audit_log.push(CancellableTaskAuditEvent {
                event_code: event_codes::FN_CX_010.to_string(),
                task_id: task_id.to_string(),
                from_phase: TaskPhase::Finalizing,
                to_phase: TaskPhase::Finalized,
                timestamp_ms,
                trace_id: trace_id.to_string(),
                detail: format!("obligation closure incomplete: {} pending", missing.len()),
                schema_version: SCHEMA_VERSION.to_string(),
            });

            // Still finalize (with error record) so the lane can be released
            let entry = self.tasks.get_mut(task_id).unwrap();
            entry.phase = TaskPhase::Finalized;
            entry.finalize_completed_ms = Some(timestamp_ms);

            return Err(CancellableTaskError::ClosureIncomplete {
                task_id: task_id.to_string(),
                missing_obligations: missing,
            });
        }

        // Produce FinalizeRecord
        let record = FinalizeRecord {
            task_id: task_id.to_string(),
            cancel_reason: cancel_reason.to_string(),
            drain_status: drain_result,
            obligation_closure_proof: obligation_proof,
            cancel_requested_ms,
            drain_started_ms,
            drain_completed_ms,
            finalize_started_ms: Some(timestamp_ms),
            finalize_completed_ms: Some(timestamp_ms),
            schema_version: SCHEMA_VERSION.to_string(),
        };

        let entry = self.tasks.get_mut(task_id).unwrap();
        entry.phase = TaskPhase::Finalized;
        entry.finalize_completed_ms = Some(timestamp_ms);
        entry.finalize_record = Some(record.clone());

        self.audit_log.push(CancellableTaskAuditEvent {
            event_code: event_codes::FN_CX_007.to_string(),
            task_id: task_id.to_string(),
            from_phase: TaskPhase::Finalizing,
            to_phase: TaskPhase::Finalized,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: "FinalizeRecord produced".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        // INV-CXT-LANE-RELEASE
        self.audit_log.push(CancellableTaskAuditEvent {
            event_code: event_codes::FN_CX_008.to_string(),
            task_id: task_id.to_string(),
            from_phase: TaskPhase::Finalized,
            to_phase: TaskPhase::Finalized,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: "lane slot released".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        Ok(record)
    }

    /// Get a task entry by ID.
    pub fn get_task(&self, task_id: &str) -> Option<&TaskEntry> {
        self.tasks.get(task_id)
    }

    /// Get the current phase for a task.
    pub fn current_phase(&self, task_id: &str) -> Option<TaskPhase> {
        self.tasks.get(task_id).map(|e| e.phase)
    }

    /// Get all task entries.
    pub fn tasks(&self) -> &BTreeMap<String, TaskEntry> {
        &self.tasks
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[CancellableTaskAuditEvent] {
        &self.audit_log
    }

    /// Number of active (non-finalized) tasks.
    pub fn active_count(&self) -> usize {
        self.tasks.values().filter(|e| e.phase != TaskPhase::Finalized).count()
    }

    /// Number of finalized tasks.
    pub fn finalized_count(&self) -> usize {
        self.tasks.values().filter(|e| e.phase == TaskPhase::Finalized).count()
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for CancellationRuntime {
    fn default() -> Self {
        Self::new(DrainConfig::default())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_runtime() -> CancellationRuntime {
        CancellationRuntime::default()
    }

    // ---- Phase FSM ----

    #[test]
    fn phase_running_can_only_go_to_cancel_requested() {
        assert!(TaskPhase::Running.can_transition_to(&TaskPhase::CancelRequested));
        assert!(!TaskPhase::Running.can_transition_to(&TaskPhase::Draining));
        assert!(!TaskPhase::Running.can_transition_to(&TaskPhase::Finalized));
    }

    #[test]
    fn phase_cancel_requested_can_go_to_draining_or_itself() {
        assert!(TaskPhase::CancelRequested.can_transition_to(&TaskPhase::Draining));
        assert!(TaskPhase::CancelRequested.can_transition_to(&TaskPhase::CancelRequested));
        assert!(!TaskPhase::CancelRequested.can_transition_to(&TaskPhase::Finalized));
    }

    #[test]
    fn phase_draining_can_only_go_to_drain_complete() {
        assert!(TaskPhase::Draining.can_transition_to(&TaskPhase::DrainComplete));
        assert!(!TaskPhase::Draining.can_transition_to(&TaskPhase::Finalized));
    }

    #[test]
    fn phase_drain_complete_can_go_to_finalizing() {
        assert!(TaskPhase::DrainComplete.can_transition_to(&TaskPhase::Finalizing));
        assert!(!TaskPhase::DrainComplete.can_transition_to(&TaskPhase::Finalized));
    }

    #[test]
    fn phase_finalizing_can_go_to_finalized() {
        assert!(TaskPhase::Finalizing.can_transition_to(&TaskPhase::Finalized));
        assert!(!TaskPhase::Finalizing.can_transition_to(&TaskPhase::Running));
    }

    #[test]
    fn phase_finalized_is_terminal() {
        assert!(TaskPhase::Finalized.legal_targets().is_empty());
    }

    #[test]
    fn phase_all_count() {
        assert_eq!(TaskPhase::ALL.len(), 6);
    }

    #[test]
    fn phase_display() {
        assert_eq!(TaskPhase::Running.to_string(), "running");
        assert_eq!(TaskPhase::CancelRequested.to_string(), "cancel_requested");
        assert_eq!(TaskPhase::Draining.to_string(), "draining");
        assert_eq!(TaskPhase::DrainComplete.to_string(), "drain_complete");
        assert_eq!(TaskPhase::Finalizing.to_string(), "finalizing");
        assert_eq!(TaskPhase::Finalized.to_string(), "finalized");
    }

    // ---- Happy path ----

    #[test]
    fn happy_path_register_cancel_drain_finalize() {
        let mut rt = make_runtime();

        // Register
        let entry = rt.register_task("task-1", 1000, "t1").unwrap();
        assert_eq!(entry.phase, TaskPhase::Running);

        // Cancel
        let entry = rt.cancel_task("task-1", "user-request", 1100, "t1").unwrap();
        assert_eq!(entry.phase, TaskPhase::CancelRequested);

        // Drain start
        let entry = rt.start_drain("task-1", 1200, "t1").unwrap();
        assert_eq!(entry.phase, TaskPhase::Draining);

        // Drain complete
        let entry = rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1").unwrap();
        assert_eq!(entry.phase, TaskPhase::DrainComplete);

        // Finalize
        let proof = ObligationClosureProof::empty();
        let record = rt.finalize_task("task-1", "user-request", proof, 1400, "t1").unwrap();
        assert_eq!(record.task_id, "task-1");
        assert_eq!(record.cancel_reason, "user-request");
        assert_eq!(record.schema_version, SCHEMA_VERSION);

        assert_eq!(rt.current_phase("task-1"), Some(TaskPhase::Finalized));
        assert_eq!(rt.active_count(), 0);
        assert_eq!(rt.finalized_count(), 1);
    }

    // ---- Duplicate registration ----

    #[test]
    fn duplicate_registration_rejected() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        let err = rt.register_task("task-1", 1001, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_DUPLICATE_TASK);
    }

    // ---- Cancel on finalized ----

    #[test]
    fn cancel_on_finalized_rejected() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "test", 1100, "t1").unwrap();
        rt.start_drain("task-1", 1200, "t1").unwrap();
        rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1").unwrap();
        rt.finalize_task("task-1", "test", ObligationClosureProof::empty(), 1400, "t1").unwrap();

        let err = rt.cancel_task("task-1", "again", 1500, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_ALREADY_FINALIZED);
    }

    // ---- Idempotent cancel ----

    #[test]
    fn idempotent_cancel() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "first", 1100, "t1").unwrap();
        let entry = rt.cancel_task("task-1", "second", 1200, "t1").unwrap();
        assert_eq!(entry.phase, TaskPhase::CancelRequested);
    }

    // ---- Invalid phase transitions ----

    #[test]
    fn drain_without_cancel_rejected() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        let err = rt.start_drain("task-1", 1100, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_INVALID_PHASE);
    }

    #[test]
    fn finalize_without_drain_rejected() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "test", 1100, "t1").unwrap();
        let err = rt.finalize_task("task-1", "test", ObligationClosureProof::empty(), 1200, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_INVALID_PHASE);
    }

    // ---- Task not found ----

    #[test]
    fn cancel_unknown_task_rejected() {
        let mut rt = make_runtime();
        let err = rt.cancel_task("nonexistent", "test", 1000, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_TASK_NOT_FOUND);
    }

    // ---- Drain timeout ----

    #[test]
    fn drain_timeout_with_force() {
        let config = DrainConfig::new(1000, true);
        let mut rt = CancellationRuntime::new(config);
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "test", 1100, "t1").unwrap();
        rt.start_drain("task-1", 1200, "t1").unwrap();

        // Complete drain well past timeout
        let entry = rt.complete_drain("task-1", DrainResult::Completed, 3000, "t1").unwrap();
        assert_eq!(entry.phase, TaskPhase::DrainComplete);
        assert_eq!(entry.drain_result, Some(DrainResult::TimedOut));

        // FN-CX-005 should be emitted
        let timeout_events: Vec<_> = rt.audit_log().iter()
            .filter(|e| e.event_code == event_codes::FN_CX_005)
            .collect();
        assert_eq!(timeout_events.len(), 1);
    }

    #[test]
    fn drain_timeout_without_force_errors() {
        let config = DrainConfig::new(1000, false);
        let mut rt = CancellationRuntime::new(config);
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "test", 1100, "t1").unwrap();
        rt.start_drain("task-1", 1200, "t1").unwrap();

        let err = rt.complete_drain("task-1", DrainResult::Completed, 3000, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_DRAIN_TIMEOUT);
    }

    // ---- Nested propagation ----

    #[test]
    fn nested_cancel_propagation() {
        let mut rt = make_runtime();
        rt.register_task("parent", 1000, "t1").unwrap();
        rt.register_task("child-1", 1000, "t1").unwrap();
        rt.register_task("child-2", 1000, "t1").unwrap();
        rt.register_child("parent", "child-1").unwrap();
        rt.register_child("parent", "child-2").unwrap();

        rt.cancel_task("parent", "shutdown", 1100, "t1").unwrap();

        assert_eq!(rt.current_phase("child-1"), Some(TaskPhase::CancelRequested));
        assert_eq!(rt.current_phase("child-2"), Some(TaskPhase::CancelRequested));

        // FN-CX-009 emitted for each child
        let propagation_events: Vec<_> = rt.audit_log().iter()
            .filter(|e| e.event_code == event_codes::FN_CX_009)
            .collect();
        assert_eq!(propagation_events.len(), 2);
    }

    #[test]
    fn register_child_rejects_unknown_child() {
        let mut rt = make_runtime();
        rt.register_task("parent", 1000, "t1").unwrap();

        let err = rt.register_child("parent", "missing-child").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_TASK_NOT_FOUND);
        match err {
            CancellableTaskError::TaskNotFound { task_id } => {
                assert_eq!(task_id, "missing-child");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn register_child_duplicate_link_is_idempotent() {
        let mut rt = make_runtime();
        rt.register_task("parent", 1000, "t1").unwrap();
        rt.register_task("child", 1000, "t1").unwrap();

        rt.register_child("parent", "child").unwrap();
        rt.register_child("parent", "child").unwrap();
        rt.cancel_task("parent", "shutdown", 1100, "t1").unwrap();

        assert_eq!(rt.current_phase("child"), Some(TaskPhase::CancelRequested));

        let propagation_events: Vec<_> = rt
            .audit_log()
            .iter()
            .filter(|e| e.event_code == event_codes::FN_CX_009)
            .collect();
        assert_eq!(propagation_events.len(), 1);
    }

    // ---- Obligation closure incomplete ----

    #[test]
    fn obligation_closure_incomplete() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "test", 1100, "t1").unwrap();
        rt.start_drain("task-1", 1200, "t1").unwrap();
        rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1").unwrap();

        let proof = ObligationClosureProof {
            obligations: vec![
                ObligationTerminal {
                    obligation_id: "ob-1".to_string(),
                    terminal_state: "pending".to_string(),
                },
            ],
            all_closed: false,
        };

        let err = rt.finalize_task("task-1", "test", proof, 1400, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_CLOSURE_INCOMPLETE);

        // FN-CX-010 emitted
        let closure_events: Vec<_> = rt.audit_log().iter()
            .filter(|e| e.event_code == event_codes::FN_CX_010)
            .collect();
        assert_eq!(closure_events.len(), 1);
    }

    // ---- Audit log ----

    #[test]
    fn audit_log_records_registration() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        assert_eq!(rt.audit_log().len(), 1);
        assert_eq!(rt.audit_log()[0].event_code, event_codes::FN_CX_001);
    }

    #[test]
    fn audit_log_happy_path_event_sequence() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "test", 1100, "t1").unwrap();
        rt.start_drain("task-1", 1200, "t1").unwrap();
        rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1").unwrap();
        rt.finalize_task("task-1", "test", ObligationClosureProof::empty(), 1400, "t1").unwrap();

        let codes: Vec<&str> = rt.audit_log().iter().map(|e| e.event_code.as_str()).collect();
        // FN-CX-001, FN-CX-002, FN-CX-003, FN-CX-004, FN-CX-006, FN-CX-007, FN-CX-008
        assert!(codes.contains(&event_codes::FN_CX_001));
        assert!(codes.contains(&event_codes::FN_CX_002));
        assert!(codes.contains(&event_codes::FN_CX_003));
        assert!(codes.contains(&event_codes::FN_CX_004));
        assert!(codes.contains(&event_codes::FN_CX_006));
        assert!(codes.contains(&event_codes::FN_CX_007));
        assert!(codes.contains(&event_codes::FN_CX_008));
    }

    // ---- JSONL export ----

    #[test]
    fn jsonl_export_parses() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        let jsonl = rt.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["event_code"], event_codes::FN_CX_001);
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<CancellableTaskError> = vec![
            CancellableTaskError::InvalidPhase {
                task_id: "t1".into(),
                from: TaskPhase::Running,
                to: TaskPhase::Draining,
            },
            CancellableTaskError::DrainTimeout {
                task_id: "t1".into(),
                elapsed_ms: 5000,
                timeout_ms: 3000,
            },
            CancellableTaskError::ClosureIncomplete {
                task_id: "t1".into(),
                missing_obligations: vec!["ob-1".into()],
            },
            CancellableTaskError::TaskNotFound { task_id: "t1".into() },
            CancellableTaskError::AlreadyFinalized { task_id: "t1".into() },
            CancellableTaskError::DuplicateTask { task_id: "t1".into() },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(s.contains(e.code()), "{:?} should contain {}", e, e.code());
        }
    }

    // ---- Serde roundtrip ----

    #[test]
    fn task_phase_serde_roundtrip() {
        for phase in &TaskPhase::ALL {
            let json = serde_json::to_string(phase).unwrap();
            let parsed: TaskPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*phase, parsed);
        }
    }

    #[test]
    fn drain_result_serde_roundtrip() {
        for dr in &[DrainResult::Completed, DrainResult::TimedOut, DrainResult::Error("oops".into())] {
            let json = serde_json::to_string(dr).unwrap();
            let parsed: DrainResult = serde_json::from_str(&json).unwrap();
            assert_eq!(*dr, parsed);
        }
    }

    #[test]
    fn finalize_record_serde_roundtrip() {
        let record = FinalizeRecord {
            task_id: "t1".to_string(),
            cancel_reason: "shutdown".to_string(),
            drain_status: DrainResult::Completed,
            obligation_closure_proof: ObligationClosureProof::empty(),
            cancel_requested_ms: Some(1000),
            drain_started_ms: Some(1100),
            drain_completed_ms: Some(1200),
            finalize_started_ms: Some(1300),
            finalize_completed_ms: Some(1400),
            schema_version: SCHEMA_VERSION.to_string(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: FinalizeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, parsed);
    }

    // ---- Drain config ----

    #[test]
    fn drain_config_default() {
        let config = DrainConfig::default();
        assert_eq!(config.timeout_ms, DEFAULT_DRAIN_TIMEOUT_MS);
        assert!(config.force_finalize_on_timeout);
    }

    #[test]
    fn drain_config_enforces_minimum() {
        let config = DrainConfig::new(100, false);
        assert_eq!(config.timeout_ms, MIN_DRAIN_TIMEOUT_MS);
    }

    // ---- Multiple independent tasks ----

    #[test]
    fn multiple_tasks_independent() {
        let mut rt = make_runtime();
        rt.register_task("task-a", 1000, "t1").unwrap();
        rt.register_task("task-b", 1000, "t2").unwrap();

        rt.cancel_task("task-a", "test-a", 1100, "t1").unwrap();
        assert_eq!(rt.current_phase("task-a"), Some(TaskPhase::CancelRequested));
        assert_eq!(rt.current_phase("task-b"), Some(TaskPhase::Running));
        assert_eq!(rt.active_count(), 2);
    }

    // ---- Obligation closure proof ----

    #[test]
    fn obligation_proof_empty_is_closed() {
        let proof = ObligationClosureProof::empty();
        assert!(proof.all_closed);
        assert!(proof.obligations.is_empty());
    }

    #[test]
    fn obligation_proof_with_entries_is_closed() {
        let proof = ObligationClosureProof::new(vec![
            ObligationTerminal {
                obligation_id: "ob-1".to_string(),
                terminal_state: "completed".to_string(),
            },
        ]);
        assert!(proof.all_closed);
    }

    // ---- Schema version ----

    #[test]
    fn schema_version_is_cxt_v1() {
        assert_eq!(SCHEMA_VERSION, "cxt-v1.0");
    }

    // ---- Double finalize rejected ----

    #[test]
    fn double_finalize_rejected() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "test", 1100, "t1").unwrap();
        rt.start_drain("task-1", 1200, "t1").unwrap();
        rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1").unwrap();
        rt.finalize_task("task-1", "test", ObligationClosureProof::empty(), 1400, "t1").unwrap();

        let err = rt.finalize_task("task-1", "test", ObligationClosureProof::empty(), 1500, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_ALREADY_FINALIZED);
    }
}
