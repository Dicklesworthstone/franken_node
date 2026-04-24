//! bd-7om: Canonical cancel -> drain -> finalize protocol contracts for product services.
//! bd-1xbr: Bounded audit_log capacity with oldest-first eviction.
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
pub const DEFAULT_DRAIN_TIMEOUT_MS: u64 = crate::config::timeouts::RUNTIME_DRAIN_TIMEOUT_MS;

/// Minimum drain timeout in milliseconds.
pub const MIN_DRAIN_TIMEOUT_MS: u64 =
    crate::config::timeouts::CANCELLABLE_TASK_MIN_DRAIN_TIMEOUT_MS;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
const MAX_CHILD_TASKS: usize = 1024;

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
    pub const ERR_CXT_INVALID_PHASE: &str = "ERR-CXT_INVALID_PHASE";
    pub const ERR_CXT_DRAIN_TIMEOUT: &str = "ERR-CXT_DRAIN_TIMEOUT";
    pub const ERR_CXT_CLOSURE_INCOMPLETE: &str = "ERR-CXT_CLOSURE_INCOMPLETE";
    pub const ERR_CXT_TASK_NOT_FOUND: &str = "ERR-CXT_TASK_NOT_FOUND";
    pub const ERR_CXT_ALREADY_FINALIZED: &str = "ERR-CXT_ALREADY_FINALIZED";
    pub const ERR_CXT_DUPLICATE_TASK: &str = "ERR-CXT_DUPLICATE_TASK";
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
}

#[cfg(test)]
mod phase_transition_negative_tests {
    use super::*;

    #[test]
    fn running_cannot_skip_to_draining() {
        assert!(!TaskPhase::Running.can_transition_to(&TaskPhase::Draining));
    }

    #[test]
    fn running_cannot_skip_to_drain_complete() {
        assert!(!TaskPhase::Running.can_transition_to(&TaskPhase::DrainComplete));
    }

    #[test]
    fn running_cannot_skip_to_finalizing() {
        assert!(!TaskPhase::Running.can_transition_to(&TaskPhase::Finalizing));
    }

    #[test]
    fn running_cannot_skip_to_finalized() {
        assert!(!TaskPhase::Running.can_transition_to(&TaskPhase::Finalized));
    }

    #[test]
    fn cancel_requested_cannot_skip_to_drain_complete() {
        assert!(!TaskPhase::CancelRequested.can_transition_to(&TaskPhase::DrainComplete));
    }

    #[test]
    fn cancel_requested_cannot_skip_to_finalizing() {
        assert!(!TaskPhase::CancelRequested.can_transition_to(&TaskPhase::Finalizing));
    }

    #[test]
    fn cancel_requested_cannot_skip_to_finalized() {
        assert!(!TaskPhase::CancelRequested.can_transition_to(&TaskPhase::Finalized));
    }

    #[test]
    fn cancel_requested_cannot_rewind_to_running() {
        assert!(!TaskPhase::CancelRequested.can_transition_to(&TaskPhase::Running));
    }

    #[test]
    fn draining_cannot_rewind_to_running() {
        assert!(!TaskPhase::Draining.can_transition_to(&TaskPhase::Running));
    }

    #[test]
    fn draining_cannot_rewind_to_cancel_requested() {
        assert!(!TaskPhase::Draining.can_transition_to(&TaskPhase::CancelRequested));
    }

    #[test]
    fn draining_cannot_skip_to_finalizing() {
        assert!(!TaskPhase::Draining.can_transition_to(&TaskPhase::Finalizing));
    }

    #[test]
    fn draining_cannot_skip_to_finalized() {
        assert!(!TaskPhase::Draining.can_transition_to(&TaskPhase::Finalized));
    }

    #[test]
    fn drain_complete_cannot_rewind_to_any_earlier_phase() {
        assert!(!TaskPhase::DrainComplete.can_transition_to(&TaskPhase::Running));
        assert!(!TaskPhase::DrainComplete.can_transition_to(&TaskPhase::CancelRequested));
        assert!(!TaskPhase::DrainComplete.can_transition_to(&TaskPhase::Draining));
    }

    #[test]
    fn drain_complete_cannot_skip_to_finalized() {
        assert!(!TaskPhase::DrainComplete.can_transition_to(&TaskPhase::Finalized));
    }

    #[test]
    fn finalizing_cannot_rewind_to_any_earlier_phase() {
        for &phase in &[
            TaskPhase::Running,
            TaskPhase::CancelRequested,
            TaskPhase::Draining,
            TaskPhase::DrainComplete,
        ] {
            assert!(!TaskPhase::Finalizing.can_transition_to(&phase));
        }
    }

    #[test]
    fn finalized_is_truly_terminal_no_transitions_allowed() {
        for &phase in &TaskPhase::ALL {
            if phase != TaskPhase::Finalized {
                assert!(!TaskPhase::Finalized.can_transition_to(&phase));
            }
        }
        // Even self-transition is not allowed according to legal_targets()
        assert!(!TaskPhase::Finalized.can_transition_to(&TaskPhase::Finalized));
    }
}

impl TaskPhase {
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
        let all_closed = obligations.iter().all(|o| o.terminal_state != "pending");
        Self {
            obligations,
            all_closed,
        }
    }
}

#[cfg(test)]
mod obligation_closure_negative_tests {
    use super::*;

    #[test]
    fn single_pending_obligation_marks_not_closed() {
        let proof = ObligationClosureProof::new(vec![ObligationTerminal {
            obligation_id: "pending-obligation".to_string(),
            terminal_state: "pending".to_string(),
        }]);
        assert!(!proof.all_closed);
        assert_eq!(proof.obligations.len(), 1);
    }

    #[test]
    fn mixed_obligations_with_any_pending_marks_not_closed() {
        let proof = ObligationClosureProof::new(vec![
            ObligationTerminal {
                obligation_id: "completed".to_string(),
                terminal_state: "completed".to_string(),
            },
            ObligationTerminal {
                obligation_id: "failed".to_string(),
                terminal_state: "failed".to_string(),
            },
            ObligationTerminal {
                obligation_id: "pending".to_string(),
                terminal_state: "pending".to_string(),
            },
        ]);
        assert!(!proof.all_closed);
        assert_eq!(proof.obligations.len(), 3);
    }

    #[test]
    fn empty_string_terminal_state_is_not_pending() {
        let proof = ObligationClosureProof::new(vec![ObligationTerminal {
            obligation_id: "empty-state".to_string(),
            terminal_state: "".to_string(),
        }]);
        assert!(proof.all_closed);
    }

    #[test]
    fn case_sensitive_pending_detection() {
        let proof = ObligationClosureProof::new(vec![
            ObligationTerminal {
                obligation_id: "uppercase".to_string(),
                terminal_state: "PENDING".to_string(),
            },
            ObligationTerminal {
                obligation_id: "mixed-case".to_string(),
                terminal_state: "Pending".to_string(),
            },
        ]);
        assert!(proof.all_closed); // Only exact "pending" matches
    }

    #[test]
    fn whitespace_around_pending_not_detected() {
        let proof = ObligationClosureProof::new(vec![ObligationTerminal {
            obligation_id: "padded".to_string(),
            terminal_state: " pending ".to_string(),
        }]);
        assert!(proof.all_closed); // Whitespace means it's not exactly "pending"
    }

    #[test]
    fn all_pending_obligations_marks_not_closed() {
        let proof = ObligationClosureProof::new(vec![
            ObligationTerminal {
                obligation_id: "pending1".to_string(),
                terminal_state: "pending".to_string(),
            },
            ObligationTerminal {
                obligation_id: "pending2".to_string(),
                terminal_state: "pending".to_string(),
            },
            ObligationTerminal {
                obligation_id: "pending3".to_string(),
                terminal_state: "pending".to_string(),
            },
        ]);
        assert!(!proof.all_closed);
    }

    #[test]
    fn obligations_with_unusual_but_terminal_states_are_closed() {
        let proof = ObligationClosureProof::new(vec![
            ObligationTerminal {
                obligation_id: "null-state".to_string(),
                terminal_state: "null".to_string(),
            },
            ObligationTerminal {
                obligation_id: "error-state".to_string(),
                terminal_state: "error".to_string(),
            },
            ObligationTerminal {
                obligation_id: "cancelled-state".to_string(),
                terminal_state: "cancelled".to_string(),
            },
        ]);
        assert!(proof.all_closed);
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
    InvalidPhase {
        task_id: String,
        from: TaskPhase,
        to: TaskPhase,
    },
    /// Drain exceeded configured timeout.
    DrainTimeout {
        task_id: String,
        elapsed_ms: u64,
        timeout_ms: u64,
    },
    /// Obligation closure incomplete during finalization.
    ClosureIncomplete {
        task_id: String,
        missing_obligations: Vec<String>,
    },
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
                write!(
                    f,
                    "{}: task {} cannot transition from {} to {}",
                    self.code(),
                    task_id,
                    from,
                    to
                )
            }
            Self::DrainTimeout {
                task_id,
                elapsed_ms,
                timeout_ms,
            } => {
                write!(
                    f,
                    "{}: task {} drain timeout after {}ms (limit {}ms)",
                    self.code(),
                    task_id,
                    elapsed_ms,
                    timeout_ms
                )
            }
            Self::ClosureIncomplete {
                task_id,
                missing_obligations,
            } => {
                write!(
                    f,
                    "{}: task {} missing obligations: {}",
                    self.code(),
                    task_id,
                    missing_obligations.join(", ")
                )
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

#[cfg(test)]
mod drain_config_negative_tests {
    use super::*;

    #[test]
    fn zero_timeout_enforces_minimum() {
        let config = DrainConfig::new(0, false);
        assert_eq!(config.timeout_ms, MIN_DRAIN_TIMEOUT_MS);
        assert!(!config.force_finalize_on_timeout);
    }

    #[test]
    fn sub_minimum_timeout_enforces_minimum() {
        let config = DrainConfig::new(100, true);
        assert_eq!(config.timeout_ms, MIN_DRAIN_TIMEOUT_MS);
        assert!(config.force_finalize_on_timeout);
    }

    #[test]
    fn one_below_minimum_enforces_minimum() {
        let config = DrainConfig::new(MIN_DRAIN_TIMEOUT_MS.saturating_sub(1), false);
        assert_eq!(config.timeout_ms, MIN_DRAIN_TIMEOUT_MS);
    }

    #[test]
    fn exactly_minimum_timeout_preserved() {
        let config = DrainConfig::new(MIN_DRAIN_TIMEOUT_MS, true);
        assert_eq!(config.timeout_ms, MIN_DRAIN_TIMEOUT_MS);
        assert!(config.force_finalize_on_timeout);
    }

    #[test]
    fn u64_max_timeout_preserved_without_overflow() {
        let config = DrainConfig::new(u64::MAX, false);
        assert_eq!(config.timeout_ms, u64::MAX);
        assert!(!config.force_finalize_on_timeout);
    }

    #[test]
    fn very_small_timeout_values_below_minimum() {
        for timeout in [1, 10, 50, 100, 499] {
            let config = DrainConfig::new(timeout, false);
            assert_eq!(
                config.timeout_ms, MIN_DRAIN_TIMEOUT_MS,
                "timeout {} should be clamped to minimum",
                timeout
            );
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

    fn emit_audit(&mut self, event: CancellableTaskAuditEvent) {
        push_bounded(&mut self.audit_log, event, MAX_AUDIT_LOG_ENTRIES);
    }
}

#[cfg(test)]
mod emit_audit_negative_tests {
    use super::*;

    #[test]
    fn emit_audit_overflow_evicts_oldest_events() {
        let mut rt = CancellationRuntime::default();

        // Fill beyond capacity by registering many tasks
        for i in 0..MAX_AUDIT_LOG_ENTRIES + 10 {
            let task_id = format!("task-{}", i);
            let _ = rt.register_task(&task_id, i as u64, "trace");
        }

        assert_eq!(rt.audit_log().len(), MAX_AUDIT_LOG_ENTRIES);

        // Verify oldest events were evicted - should not contain early task IDs
        let event_task_ids: Vec<&str> = rt.audit_log().iter().map(|e| e.task_id.as_str()).collect();
        assert!(!event_task_ids.contains(&"task-0"));
        assert!(!event_task_ids.contains(&"task-5"));

        // Should contain recent task IDs
        let last_task = format!("task-{}", MAX_AUDIT_LOG_ENTRIES + 9);
        assert!(event_task_ids.contains(&last_task.as_str()));
    }

    #[test]
    fn emit_audit_single_event_beyond_capacity_still_recorded() {
        let mut rt = CancellationRuntime::default();

        // Pre-fill to capacity
        for i in 0..MAX_AUDIT_LOG_ENTRIES {
            rt.emit_audit(CancellableTaskAuditEvent {
                event_code: "PREFILL".to_string(),
                task_id: format!("prefill-{}", i),
                from_phase: TaskPhase::Running,
                to_phase: TaskPhase::Running,
                timestamp_ms: i as u64,
                trace_id: "trace".to_string(),
                detail: "prefill event".to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            });
        }

        // Add one more event
        rt.emit_audit(CancellableTaskAuditEvent {
            event_code: "OVERFLOW".to_string(),
            task_id: "overflow-task".to_string(),
            from_phase: TaskPhase::Running,
            to_phase: TaskPhase::CancelRequested,
            timestamp_ms: 99999,
            trace_id: "overflow-trace".to_string(),
            detail: "overflow event".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        assert_eq!(rt.audit_log().len(), MAX_AUDIT_LOG_ENTRIES);

        // Last event should be the overflow event
        let last_event = rt.audit_log().last().expect("should have events");
        assert_eq!(last_event.event_code, "OVERFLOW");
        assert_eq!(last_event.task_id, "overflow-task");

        // First event should no longer be prefill-0
        let first_event = rt.audit_log().first().expect("should have events");
        assert_ne!(first_event.task_id, "prefill-0");
    }

    #[test]
    fn emit_audit_maintains_chronological_order_after_overflow() {
        let mut rt = CancellationRuntime::default();

        // Create events with incrementing timestamps
        for i in 0..(MAX_AUDIT_LOG_ENTRIES + 5) {
            rt.emit_audit(CancellableTaskAuditEvent {
                event_code: "SEQ".to_string(),
                task_id: format!("seq-{}", i),
                from_phase: TaskPhase::Running,
                to_phase: TaskPhase::Running,
                timestamp_ms: i as u64 * 100,
                trace_id: "seq-trace".to_string(),
                detail: format!("sequence {}", i),
                schema_version: SCHEMA_VERSION.to_string(),
            });
        }

        // Verify timestamps are still in order
        let timestamps: Vec<u64> = rt.audit_log().iter().map(|e| e.timestamp_ms).collect();

        for i in 1..timestamps.len() {
            assert!(
                timestamps[i] > timestamps[i - 1],
                "timestamp {} should be > timestamp {}",
                timestamps[i],
                timestamps[i - 1]
            );
        }
    }
}

impl CancellationRuntime {
    /// Register a new cancellable task.
    /// Emits FN-CX-001.
    pub fn register_task(
        &mut self,
        task_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<&TaskEntry, CancellableTaskError> {
        self.register_task_with_config(
            task_id,
            self.default_drain_config.clone(),
            timestamp_ms,
            trace_id,
        )
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

        self.emit_audit(CancellableTaskAuditEvent {
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
        self.tasks
            .get(task_id)
            .ok_or_else(|| CancellableTaskError::TaskNotFound {
                task_id: task_id.to_string(),
            })
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
        let parent =
            self.tasks
                .get_mut(parent_id)
                .ok_or_else(|| CancellableTaskError::TaskNotFound {
                    task_id: parent_id.to_string(),
                })?;
        if parent
            .child_task_ids
            .iter()
            .any(|existing| existing == child_id)
        {
            // Idempotent child-link registration avoids duplicate propagation events.
            return Ok(());
        }
        push_bounded(
            &mut parent.child_task_ids,
            child_id.to_string(),
            MAX_CHILD_TASKS,
        );
        Ok(())
    }
}

#[cfg(test)]
mod register_child_negative_tests {
    use super::*;

    #[test]
    fn register_child_beyond_max_capacity_evicts_oldest() {
        let mut rt = CancellationRuntime::default();
        rt.register_task("parent", 1000, "t1").unwrap();

        // Register MAX_CHILD_TASKS + 5 children
        for i in 0..(MAX_CHILD_TASKS + 5) {
            let child_id = format!("child-{}", i);
            rt.register_task(&child_id, 1000, "t1").unwrap();
            rt.register_child("parent", &child_id).unwrap();
        }

        let parent = rt.get_task("parent").expect("parent should exist");
        assert_eq!(parent.child_task_ids.len(), MAX_CHILD_TASKS);

        // Should not contain early children (evicted)
        assert!(!parent.child_task_ids.contains(&"child-0".to_string()));
        assert!(!parent.child_task_ids.contains(&"child-4".to_string()));

        // Should contain recent children
        let last_child = format!("child-{}", MAX_CHILD_TASKS + 4);
        assert!(parent.child_task_ids.contains(&last_child));
    }

    #[test]
    fn register_child_capacity_overflow_maintains_propagation() {
        let mut rt = CancellationRuntime::default();
        rt.register_task("parent", 1000, "t1").unwrap();

        // Fill to capacity + overflow
        for i in 0..(MAX_CHILD_TASKS + 2) {
            let child_id = format!("child-{}", i);
            rt.register_task(&child_id, 1000, "t1").unwrap();
            rt.register_child("parent", &child_id).unwrap();
        }

        // Cancel parent - should propagate to remaining children only
        rt.cancel_task("parent", "shutdown", 2000, "t1").unwrap();

        // Evicted children should not be cancelled
        assert_eq!(rt.current_phase("child-0"), Some(TaskPhase::Running));
        assert_eq!(rt.current_phase("child-1"), Some(TaskPhase::Running));

        // Remaining children should be cancelled
        let last_child = format!("child-{}", MAX_CHILD_TASKS + 1);
        assert_eq!(
            rt.current_phase(&last_child),
            Some(TaskPhase::CancelRequested)
        );
    }

    #[test]
    fn register_child_duplicate_link_with_capacity_overflow() {
        let mut rt = CancellationRuntime::default();
        rt.register_task("parent", 1000, "t1").unwrap();
        rt.register_task("persistent-child", 1000, "t1").unwrap();

        // Register persistent child first
        rt.register_child("parent", "persistent-child").unwrap();

        // Fill capacity with other children
        for i in 0..MAX_CHILD_TASKS {
            let child_id = format!("temp-{}", i);
            rt.register_task(&child_id, 1000, "t1").unwrap();
            rt.register_child("parent", &child_id).unwrap();
        }

        // Try to re-register the persistent child (should be idempotent)
        rt.register_child("parent", "persistent-child").unwrap();

        let parent = rt.get_task("parent").expect("parent should exist");

        // Should still be at capacity
        assert_eq!(parent.child_task_ids.len(), MAX_CHILD_TASKS);

        // Should still contain the persistent child (not duplicated)
        assert_eq!(
            parent
                .child_task_ids
                .iter()
                .filter(|&id| id == "persistent-child")
                .count(),
            1
        );
    }

    #[test]
    fn register_child_self_reference_rejected() {
        let mut rt = CancellationRuntime::default();
        rt.register_task("task-1", 1000, "t1").unwrap();

        let err = rt.register_child("task-1", "task-1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_TASK_NOT_FOUND);

        // Parent should not have itself as child
        let task = rt.get_task("task-1").expect("task should exist");
        assert!(task.child_task_ids.is_empty());
    }
}

impl CancellationRuntime {
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
        let (phase, child_ids) = {
            let entry =
                self.tasks
                    .get(task_id)
                    .ok_or_else(|| CancellableTaskError::TaskNotFound {
                        task_id: task_id.to_string(),
                    })?;
            (entry.phase, entry.child_task_ids.clone())
        };

        // Idempotent: absorb duplicate cancel on CancelRequested
        if phase == TaskPhase::CancelRequested {
            return self
                .tasks
                .get(task_id)
                .ok_or_else(|| CancellableTaskError::TaskNotFound {
                    task_id: task_id.to_string(),
                });
        }

        if phase == TaskPhase::Finalized {
            return Err(CancellableTaskError::AlreadyFinalized {
                task_id: task_id.to_string(),
            });
        }

        if !phase.can_transition_to(&TaskPhase::CancelRequested) {
            return Err(CancellableTaskError::InvalidPhase {
                task_id: task_id.to_string(),
                from: phase,
                to: TaskPhase::CancelRequested,
            });
        }

        let entry =
            self.tasks
                .get_mut(task_id)
                .ok_or_else(|| CancellableTaskError::TaskNotFound {
                    task_id: task_id.to_string(),
                })?;
        let from = phase;
        entry.phase = TaskPhase::CancelRequested;
        entry.cancel_requested_ms = Some(timestamp_ms);

        self.emit_audit(CancellableTaskAuditEvent {
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
            if let Some(child) = self.tasks.get_mut(child_id)
                && child.phase == TaskPhase::Running
            {
                child.phase = TaskPhase::CancelRequested;
                child.cancel_requested_ms = Some(timestamp_ms);

                self.emit_audit(CancellableTaskAuditEvent {
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

        self.tasks
            .get(task_id)
            .ok_or_else(|| CancellableTaskError::TaskNotFound {
                task_id: task_id.to_string(),
            })
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
        let entry = self
            .tasks
            .get(task_id)
            .ok_or_else(|| CancellableTaskError::TaskNotFound {
                task_id: task_id.to_string(),
            })?;

        if !entry.phase.can_transition_to(&TaskPhase::Draining) {
            return Err(CancellableTaskError::InvalidPhase {
                task_id: task_id.to_string(),
                from: entry.phase,
                to: TaskPhase::Draining,
            });
        }

        let from = entry.phase;
        let entry =
            self.tasks
                .get_mut(task_id)
                .ok_or_else(|| CancellableTaskError::TaskNotFound {
                    task_id: task_id.to_string(),
                })?;
        entry.phase = TaskPhase::Draining;
        entry.drain_started_ms = Some(timestamp_ms);

        self.emit_audit(CancellableTaskAuditEvent {
            event_code: event_codes::FN_CX_003.to_string(),
            task_id: task_id.to_string(),
            from_phase: from,
            to_phase: TaskPhase::Draining,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: "drain started".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.tasks
            .get(task_id)
            .ok_or_else(|| CancellableTaskError::TaskNotFound {
                task_id: task_id.to_string(),
            })
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
        let entry = self
            .tasks
            .get(task_id)
            .ok_or_else(|| CancellableTaskError::TaskNotFound {
                task_id: task_id.to_string(),
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

        let timed_out = elapsed >= timeout;
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

        if timed_out && !self.tasks[task_id].drain_config.force_finalize_on_timeout {
            self.emit_audit(CancellableTaskAuditEvent {
                event_code: event_code.to_string(),
                task_id: task_id.to_string(),
                from_phase: from,
                to_phase: from,
                timestamp_ms,
                trace_id: trace_id.to_string(),
                detail: format!("drain timeout after {}ms (limit {}ms)", elapsed, timeout),
                schema_version: SCHEMA_VERSION.to_string(),
            });

            return Err(CancellableTaskError::DrainTimeout {
                task_id: task_id.to_string(),
                elapsed_ms: elapsed,
                timeout_ms: timeout,
            });
        }

        let entry =
            self.tasks
                .get_mut(task_id)
                .ok_or_else(|| CancellableTaskError::TaskNotFound {
                    task_id: task_id.to_string(),
                })?;
        entry.phase = TaskPhase::DrainComplete;
        entry.drain_completed_ms = Some(timestamp_ms);
        entry.drain_result = Some(effective_result);

        self.emit_audit(CancellableTaskAuditEvent {
            event_code: event_code.to_string(),
            task_id: task_id.to_string(),
            from_phase: from,
            to_phase: TaskPhase::DrainComplete,
            timestamp_ms,
            trace_id: trace_id.to_string(),
            detail: format!(
                "drain completed in {}ms (timeout={}ms, timed_out={})",
                elapsed, timeout, timed_out
            ),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.tasks
            .get(task_id)
            .ok_or_else(|| CancellableTaskError::TaskNotFound {
                task_id: task_id.to_string(),
            })
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
        let entry = self
            .tasks
            .get(task_id)
            .ok_or_else(|| CancellableTaskError::TaskNotFound {
                task_id: task_id.to_string(),
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
        let entry =
            self.tasks
                .get_mut(task_id)
                .ok_or_else(|| CancellableTaskError::TaskNotFound {
                    task_id: task_id.to_string(),
                })?;
        entry.phase = TaskPhase::Finalizing;
        entry.finalize_started_ms = Some(timestamp_ms);

        self.emit_audit(CancellableTaskAuditEvent {
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
            let record = FinalizeRecord {
                task_id: task_id.to_string(),
                cancel_reason: cancel_reason.to_string(),
                drain_status: drain_result.clone(),
                obligation_closure_proof: obligation_proof.clone(),
                cancel_requested_ms,
                drain_started_ms,
                drain_completed_ms,
                finalize_started_ms: Some(timestamp_ms),
                finalize_completed_ms: Some(timestamp_ms),
                schema_version: SCHEMA_VERSION.to_string(),
            };

            self.emit_audit(CancellableTaskAuditEvent {
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
            let entry =
                self.tasks
                    .get_mut(task_id)
                    .ok_or_else(|| CancellableTaskError::TaskNotFound {
                        task_id: task_id.to_string(),
                    })?;
            entry.phase = TaskPhase::Finalized;
            entry.finalize_completed_ms = Some(timestamp_ms);
            entry.finalize_record = Some(record);

            self.emit_audit(CancellableTaskAuditEvent {
                event_code: event_codes::FN_CX_007.to_string(),
                task_id: task_id.to_string(),
                from_phase: TaskPhase::Finalizing,
                to_phase: TaskPhase::Finalized,
                timestamp_ms,
                trace_id: trace_id.to_string(),
                detail: "FinalizeRecord produced with incomplete closure proof".to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            });

            self.emit_audit(CancellableTaskAuditEvent {
                event_code: event_codes::FN_CX_008.to_string(),
                task_id: task_id.to_string(),
                from_phase: TaskPhase::Finalized,
                to_phase: TaskPhase::Finalized,
                timestamp_ms,
                trace_id: trace_id.to_string(),
                detail: "lane slot released after incomplete closure proof".to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            });

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

        let entry =
            self.tasks
                .get_mut(task_id)
                .ok_or_else(|| CancellableTaskError::TaskNotFound {
                    task_id: task_id.to_string(),
                })?;
        entry.phase = TaskPhase::Finalized;
        entry.finalize_completed_ms = Some(timestamp_ms);
        entry.finalize_record = Some(record.clone());

        self.emit_audit(CancellableTaskAuditEvent {
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
        self.emit_audit(CancellableTaskAuditEvent {
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
        self.tasks
            .values()
            .filter(|e| e.phase != TaskPhase::Finalized)
            .count()
    }

    /// Number of finalized tasks.
    pub fn finalized_count(&self) -> usize {
        self.tasks
            .values()
            .filter(|e| e.phase == TaskPhase::Finalized)
            .count()
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .filter_map(|r| match serde_json::to_string(r) {
                Ok(json) => Some(json),
                Err(err) => {
                    tracing::error!(
                        task_id = %r.task_id,
                        error = %err,
                        "failed serializing audit record — record lost"
                    );
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod export_audit_log_negative_tests {
    use super::*;

    #[test]
    fn export_audit_log_empty_log_produces_empty_string() {
        let rt = CancellationRuntime::default();
        let jsonl = rt.export_audit_log_jsonl();
        assert!(jsonl.is_empty());
    }

    #[test]
    fn export_audit_log_single_event_no_trailing_newline() {
        let mut rt = CancellationRuntime::default();
        rt.register_task("task-1", 1000, "t1").unwrap();

        let jsonl = rt.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        assert!(!jsonl.ends_with('\n'));
        assert_eq!(jsonl.lines().count(), 1);
    }

    #[test]
    fn export_audit_log_multiple_events_newline_separated() {
        let mut rt = CancellationRuntime::default();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.register_task("task-2", 2000, "t2").unwrap();

        let jsonl = rt.export_audit_log_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON
        for line in lines {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("each line should be valid JSON");
            assert!(parsed.is_object());
        }
    }

    #[test]
    fn export_audit_log_with_extreme_field_values() {
        let mut rt = CancellationRuntime::default();

        // Create event with extreme values
        rt.emit_audit(CancellableTaskAuditEvent {
            event_code: "".to_string(),        // Empty string
            task_id: "\n\r\t\"\\".to_string(), // Control characters and quotes
            from_phase: TaskPhase::Running,
            to_phase: TaskPhase::Finalized,
            timestamp_ms: u64::MAX,
            trace_id: "x".repeat(10000), // Very long string
            detail: "unicode: 🦀 emoji and ñoño".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        let jsonl = rt.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());

        // Should still be parseable JSON despite extreme values
        let parsed: serde_json::Value =
            serde_json::from_str(&jsonl).expect("should handle extreme field values in JSON");
        assert_eq!(parsed["timestamp_ms"], u64::MAX);
        assert_eq!(parsed["event_code"], "");
    }

    #[test]
    fn export_audit_log_preserves_task_id_order() {
        let mut rt = CancellationRuntime::default();

        let task_ids = ["zebra", "alpha", "beta", "gamma"];
        for &task_id in &task_ids {
            rt.register_task(task_id, 1000, "t1").unwrap();
        }

        let jsonl = rt.export_audit_log_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), task_ids.len());

        // Should preserve insertion order, not alphabetical
        for (i, line) in lines.iter().enumerate() {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["task_id"], task_ids[i]);
        }
    }

    #[test]
    fn export_audit_log_handles_schema_version_consistency() {
        let mut rt = CancellationRuntime::default();
        rt.register_task("task-1", 1000, "t1").unwrap();

        let jsonl = rt.export_audit_log_jsonl();
        let parsed: serde_json::Value = serde_json::from_str(&jsonl).unwrap();

        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
        assert_eq!(parsed["schema_version"], "cxt-v1.0");
    }

    #[test]
    fn export_audit_log_with_zero_timestamp() {
        let mut rt = CancellationRuntime::default();
        rt.register_task("task-1", 0, "t1").unwrap(); // Zero timestamp

        let jsonl = rt.export_audit_log_jsonl();
        let parsed: serde_json::Value = serde_json::from_str(&jsonl).unwrap();

        assert_eq!(parsed["timestamp_ms"], 0);
    }

    #[test]
    fn export_audit_log_very_long_detail_field() {
        let mut rt = CancellationRuntime::default();
        let very_long_detail = "x".repeat(100_000); // 100KB string

        rt.emit_audit(CancellableTaskAuditEvent {
            event_code: event_codes::FN_CX_001.to_string(),
            task_id: "task-1".to_string(),
            from_phase: TaskPhase::Running,
            to_phase: TaskPhase::Running,
            timestamp_ms: 1000,
            trace_id: "t1".to_string(),
            detail: very_long_detail.clone(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        let jsonl = rt.export_audit_log_jsonl();
        assert!(jsonl.len() > 100_000); // Should include the long detail

        let parsed: serde_json::Value = serde_json::from_str(&jsonl).unwrap();
        assert_eq!(parsed["detail"], very_long_detail);
    }
}

impl Default for CancellationRuntime {
    fn default() -> Self {
        Self::new(DrainConfig::default())
    }
}

// ===========================================================================
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
mod push_bounded_negative_tests {
    use super::*;

    #[test]
    fn push_bounded_zero_capacity_always_empty() {
        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 0);
        assert!(items.is_empty()); // All items drained, nothing can stay
    }

    #[test]
    fn push_bounded_capacity_one_keeps_only_last() {
        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 1);
        assert_eq!(items, vec![4]);
        push_bounded(&mut items, 5, 1);
        assert_eq!(items, vec![5]);
    }

    #[test]
    fn push_bounded_at_exact_capacity_removes_oldest() {
        let mut items = vec!["a", "b", "c"];
        push_bounded(&mut items, "d", 3);
        assert_eq!(items, vec!["b", "c", "d"]);
        push_bounded(&mut items, "e", 3);
        assert_eq!(items, vec!["c", "d", "e"]);
    }

    #[test]
    fn push_bounded_way_over_capacity_drains_multiple() {
        let mut items: Vec<i32> = (0..10).collect(); // [0, 1, 2, ..., 9]
        push_bounded(&mut items, 99, 3); // Capacity 3, current 10, need to remove 8
        assert_eq!(items, vec![8, 9, 99]);
    }

    #[test]
    fn push_bounded_massive_overflow_calculation() {
        let mut items: Vec<i32> = (0..1000).collect();
        push_bounded(&mut items, 9999, 1);
        assert_eq!(items, vec![9999]);
    }

    #[test]
    fn push_bounded_empty_vec_under_capacity() {
        let mut items: Vec<String> = Vec::new();
        push_bounded(&mut items, "first".to_string(), 5);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "first");
    }

    #[test]
    fn push_bounded_exactly_at_limit_before_push() {
        let mut items = vec![1, 2, 3, 4, 5]; // len = 5
        push_bounded(&mut items, 6, 5); // cap = 5, so len >= cap triggers drain
        assert_eq!(items.len(), 5);
        assert_eq!(items, vec![2, 3, 4, 5, 6]); // Oldest removed
    }

    #[test]
    fn push_bounded_preserves_order_after_drain() {
        let mut items = vec!['a', 'b', 'c', 'd', 'e', 'f'];
        push_bounded(&mut items, 'x', 2); // Keep only 2, drain 5, then add 'x'
        assert_eq!(items, vec!['f', 'x']); // Last item + new item
    }
}

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
        let entry = rt
            .cancel_task("task-1", "user-request", 1100, "t1")
            .unwrap();
        assert_eq!(entry.phase, TaskPhase::CancelRequested);

        // Drain start
        let entry = rt.start_drain("task-1", 1200, "t1").unwrap();
        assert_eq!(entry.phase, TaskPhase::Draining);

        // Drain complete
        let entry = rt
            .complete_drain("task-1", DrainResult::Completed, 1300, "t1")
            .unwrap();
        assert_eq!(entry.phase, TaskPhase::DrainComplete);

        // Finalize
        let proof = ObligationClosureProof::empty();
        let record = rt
            .finalize_task("task-1", "user-request", proof, 1400, "t1")
            .unwrap();
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
        rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1")
            .unwrap();
        rt.finalize_task(
            "task-1",
            "test",
            ObligationClosureProof::empty(),
            1400,
            "t1",
        )
        .unwrap();

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
        let err = rt
            .finalize_task(
                "task-1",
                "test",
                ObligationClosureProof::empty(),
                1200,
                "t1",
            )
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_INVALID_PHASE);
    }

    // ---- Task not found ----

    #[test]
    fn cancel_unknown_task_rejected() {
        let mut rt = make_runtime();
        let err = rt
            .cancel_task("nonexistent", "test", 1000, "t1")
            .unwrap_err();
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
        let entry = rt
            .complete_drain("task-1", DrainResult::Completed, 3000, "t1")
            .unwrap();
        assert_eq!(entry.phase, TaskPhase::DrainComplete);
        assert_eq!(entry.drain_result, Some(DrainResult::TimedOut));

        // FN-CX-005 should be emitted
        let timeout_events: Vec<_> = rt
            .audit_log()
            .iter()
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

        let err = rt
            .complete_drain("task-1", DrainResult::Completed, 3000, "t1")
            .unwrap_err();
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

        assert_eq!(
            rt.current_phase("child-1"),
            Some(TaskPhase::CancelRequested)
        );
        assert_eq!(
            rt.current_phase("child-2"),
            Some(TaskPhase::CancelRequested)
        );

        // FN-CX-009 emitted for each child
        let propagation_events: Vec<_> = rt
            .audit_log()
            .iter()
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
            other => unreachable!("unexpected error: {other:?}"),
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
        rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1")
            .unwrap();

        let proof = ObligationClosureProof {
            obligations: vec![ObligationTerminal {
                obligation_id: "ob-1".to_string(),
                terminal_state: "pending".to_string(),
            }],
            all_closed: false,
        };

        let err = rt
            .finalize_task("task-1", "test", proof, 1400, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_CLOSURE_INCOMPLETE);
        assert_eq!(rt.current_phase("task-1"), Some(TaskPhase::Finalized));
        assert_eq!(rt.active_count(), 0);
        assert_eq!(rt.finalized_count(), 1);

        let task = rt.get_task("task-1").expect("task should remain tracked");
        let record = task
            .finalize_record
            .as_ref()
            .expect("closure failure should still produce a finalize record");
        assert!(!record.obligation_closure_proof.all_closed);
        assert_eq!(record.finalize_completed_ms, Some(1400));

        let codes: Vec<&str> = rt
            .audit_log()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&event_codes::FN_CX_010));
        assert!(codes.contains(&event_codes::FN_CX_007));
        assert!(codes.contains(&event_codes::FN_CX_008));
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
        rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1")
            .unwrap();
        rt.finalize_task(
            "task-1",
            "test",
            ObligationClosureProof::empty(),
            1400,
            "t1",
        )
        .unwrap();

        let codes: Vec<&str> = rt
            .audit_log()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
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
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
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
            CancellableTaskError::TaskNotFound {
                task_id: "t1".into(),
            },
            CancellableTaskError::AlreadyFinalized {
                task_id: "t1".into(),
            },
            CancellableTaskError::DuplicateTask {
                task_id: "t1".into(),
            },
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
        for dr in &[
            DrainResult::Completed,
            DrainResult::TimedOut,
            DrainResult::Error("oops".into()),
        ] {
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
        let proof = ObligationClosureProof::new(vec![ObligationTerminal {
            obligation_id: "ob-1".to_string(),
            terminal_state: "completed".to_string(),
        }]);
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
        rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1")
            .unwrap();
        rt.finalize_task(
            "task-1",
            "test",
            ObligationClosureProof::empty(),
            1400,
            "t1",
        )
        .unwrap();

        let err = rt
            .finalize_task(
                "task-1",
                "test",
                ObligationClosureProof::empty(),
                1500,
                "t1",
            )
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CXT_ALREADY_FINALIZED);
    }

    // ---- Additional negative paths ----

    #[test]
    fn duplicate_registration_does_not_emit_second_registration_event() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();

        let err = rt.register_task("task-1", 1001, "t1").unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CXT_DUPLICATE_TASK);
        assert_eq!(rt.tasks().len(), 1);
        assert_eq!(
            rt.audit_log()
                .iter()
                .filter(|event| event.event_code == event_codes::FN_CX_001)
                .count(),
            1
        );
    }

    #[test]
    fn register_child_rejects_unknown_parent_without_mutating_child() {
        let mut rt = make_runtime();
        rt.register_task("child", 1000, "t1").unwrap();

        let err = rt.register_child("missing-parent", "child").unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CXT_TASK_NOT_FOUND);
        match err {
            CancellableTaskError::TaskNotFound { task_id } => {
                assert_eq!(task_id, "missing-parent");
            }
            other => unreachable!("unexpected error: {other:?}"),
        }
        let child = rt
            .get_task("child")
            .expect("child should remain registered");
        assert!(child.child_task_ids.is_empty());
    }

    #[test]
    fn start_drain_unknown_task_rejected_without_audit() {
        let mut rt = make_runtime();

        let err = rt.start_drain("missing", 1000, "t1").unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CXT_TASK_NOT_FOUND);
        assert!(rt.audit_log().is_empty());
    }

    #[test]
    fn complete_drain_unknown_task_rejected_without_audit() {
        let mut rt = make_runtime();

        let err = rt
            .complete_drain("missing", DrainResult::Completed, 1000, "t1")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CXT_TASK_NOT_FOUND);
        assert!(rt.audit_log().is_empty());
    }

    #[test]
    fn finalize_unknown_task_rejected_without_audit() {
        let mut rt = make_runtime();

        let err = rt
            .finalize_task(
                "missing",
                "shutdown",
                ObligationClosureProof::empty(),
                1000,
                "t1",
            )
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CXT_TASK_NOT_FOUND);
        assert!(rt.audit_log().is_empty());
    }

    #[test]
    fn complete_drain_without_start_rejected_and_state_preserved() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "shutdown", 1100, "t1").unwrap();

        let err = rt
            .complete_drain("task-1", DrainResult::Completed, 1200, "t1")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CXT_INVALID_PHASE);
        let task = rt.get_task("task-1").expect("task should remain tracked");
        assert_eq!(task.phase, TaskPhase::CancelRequested);
        assert_eq!(task.drain_result, None);
        assert_eq!(task.drain_completed_ms, None);
        assert!(
            !rt.audit_log()
                .iter()
                .any(|event| event.event_code == event_codes::FN_CX_004)
        );
    }

    #[test]
    fn repeated_start_drain_rejected_without_overwriting_timestamp() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "shutdown", 1100, "t1").unwrap();
        rt.start_drain("task-1", 1200, "t1").unwrap();

        let err = rt.start_drain("task-1", 1300, "t1").unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CXT_INVALID_PHASE);
        let task = rt.get_task("task-1").expect("task should remain tracked");
        assert_eq!(task.phase, TaskPhase::Draining);
        assert_eq!(task.drain_started_ms, Some(1200));
        assert_eq!(
            rt.audit_log()
                .iter()
                .filter(|event| event.event_code == event_codes::FN_CX_003)
                .count(),
            1
        );
    }

    #[test]
    fn repeated_complete_drain_rejected_without_overwriting_result() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "shutdown", 1100, "t1").unwrap();
        rt.start_drain("task-1", 1200, "t1").unwrap();
        rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1")
            .unwrap();

        let err = rt
            .complete_drain("task-1", DrainResult::Error("late".into()), 1400, "t1")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CXT_INVALID_PHASE);
        let task = rt.get_task("task-1").expect("task should remain tracked");
        assert_eq!(task.phase, TaskPhase::DrainComplete);
        assert_eq!(task.drain_result, Some(DrainResult::Completed));
        assert_eq!(task.drain_completed_ms, Some(1300));
        assert_eq!(
            rt.audit_log()
                .iter()
                .filter(|event| event.event_code == event_codes::FN_CX_004)
                .count(),
            1
        );
    }

    #[test]
    fn cancel_after_drain_started_rejected_without_new_cancel_audit() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "shutdown", 1100, "t1").unwrap();
        rt.start_drain("task-1", 1200, "t1").unwrap();

        let err = rt
            .cancel_task("task-1", "late-cancel", 1300, "t1")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CXT_INVALID_PHASE);
        assert_eq!(rt.current_phase("task-1"), Some(TaskPhase::Draining));
        assert_eq!(
            rt.audit_log()
                .iter()
                .filter(|event| event.event_code == event_codes::FN_CX_002)
                .count(),
            1
        );
    }

    #[test]
    fn timeout_without_force_keeps_task_draining_and_blocks_finalize() {
        let mut rt = CancellationRuntime::new(DrainConfig::new(1000, false));
        rt.register_task("task-1", 0, "t1").unwrap();
        rt.cancel_task("task-1", "shutdown", 100, "t1").unwrap();
        rt.start_drain("task-1", 1000, "t1").unwrap();

        let timeout_err = rt
            .complete_drain("task-1", DrainResult::Completed, 2000, "t1")
            .unwrap_err();
        let finalize_err = rt
            .finalize_task(
                "task-1",
                "shutdown",
                ObligationClosureProof::empty(),
                2100,
                "t1",
            )
            .unwrap_err();

        assert_eq!(timeout_err.code(), error_codes::ERR_CXT_DRAIN_TIMEOUT);
        assert_eq!(finalize_err.code(), error_codes::ERR_CXT_INVALID_PHASE);
        let task = rt.get_task("task-1").expect("task should remain tracked");
        assert_eq!(task.phase, TaskPhase::Draining);
        assert_eq!(task.drain_completed_ms, None);
        assert_eq!(task.finalize_record, None);
        assert_eq!(
            rt.audit_log()
                .iter()
                .filter(|event| event.event_code == event_codes::FN_CX_005)
                .count(),
            1
        );
    }

    #[test]
    fn cancel_parent_does_not_rewind_child_already_draining() {
        let mut rt = make_runtime();
        rt.register_task("parent", 1000, "t1").unwrap();
        rt.register_task("child", 1000, "t1").unwrap();
        rt.register_child("parent", "child").unwrap();
        rt.cancel_task("child", "child-shutdown", 1100, "t1")
            .unwrap();
        rt.start_drain("child", 1200, "t1").unwrap();

        rt.cancel_task("parent", "parent-shutdown", 1300, "t1")
            .unwrap();

        let child = rt.get_task("child").expect("child should remain tracked");
        assert_eq!(child.phase, TaskPhase::Draining);
        assert_eq!(child.cancel_requested_ms, Some(1100));
        assert!(
            !rt.audit_log()
                .iter()
                .any(|event| event.event_code == event_codes::FN_CX_009)
        );
    }

    #[test]
    fn incomplete_closure_reports_only_pending_obligations_as_missing() {
        let mut rt = make_runtime();
        rt.register_task("task-1", 1000, "t1").unwrap();
        rt.cancel_task("task-1", "shutdown", 1100, "t1").unwrap();
        rt.start_drain("task-1", 1200, "t1").unwrap();
        rt.complete_drain("task-1", DrainResult::Completed, 1300, "t1")
            .unwrap();
        let proof = ObligationClosureProof {
            obligations: vec![
                ObligationTerminal {
                    obligation_id: "closed".to_string(),
                    terminal_state: "completed".to_string(),
                },
                ObligationTerminal {
                    obligation_id: "still-pending".to_string(),
                    terminal_state: "pending".to_string(),
                },
                ObligationTerminal {
                    obligation_id: "failed-terminally".to_string(),
                    terminal_state: "failed".to_string(),
                },
            ],
            all_closed: false,
        };

        let err = rt
            .finalize_task("task-1", "shutdown", proof, 1400, "t1")
            .unwrap_err();

        match err {
            CancellableTaskError::ClosureIncomplete {
                missing_obligations,
                ..
            } => {
                assert_eq!(missing_obligations, vec!["still-pending"]);
            }
            other => unreachable!("unexpected error: {other:?}"),
        }
        assert_eq!(rt.current_phase("task-1"), Some(TaskPhase::Finalized));
    }
}
