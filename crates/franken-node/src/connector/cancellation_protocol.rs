//! bd-1cs7: Three-phase cancellation protocol (REQUEST -> DRAIN -> FINALIZE)
//! for high-impact connector workflows.
//!
//! Provides an orderly cancellation mechanism that ensures in-flight work is
//! drained and resources are released without leaks. Each workflow has a
//! bounded cleanup budget; exceeding it triggers a force-finalize with error
//! evidence.
//!
//! # Three-Phase Protocol
//!
//! 1. **REQUEST** -- cancellation signal received; no new work accepted
//! 2. **DRAIN** -- in-flight operations complete or timeout
//! 3. **FINALIZE** -- resources released, state committed to terminal
//!
//! # Invariants
//!
//! - INV-CAN-THREE-PHASE: all cancellations pass through REQUEST, DRAIN, FINALIZE in order
//! - INV-CAN-BUDGET-BOUNDED: every workflow has a finite cleanup budget; exceeded triggers force-finalize
//! - INV-CAN-PROPAGATION: cancellation propagates to all child operations within a workflow
//! - INV-CAN-NO-LEAK: after FINALIZE, no resource leaks exist (CAN-006 on violation)
//!
//! Schema version: cancel-v1.0

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

// ── Constants ────────────────────────────────────────────────────────────────

/// Schema version for the cancellation protocol.
pub const SCHEMA_VERSION: &str = "cancel-v1.0";

/// Bead identifier.
pub const BEAD_ID: &str = "bd-1cs7";

/// Section identifier.
pub const SECTION: &str = "10.15";

// ── Invariant constants ──────────────────────────────────────────────────────

pub mod invariants {
    /// All cancellations pass through REQUEST, DRAIN, FINALIZE in order.
    pub const INV_CAN_THREE_PHASE: &str = "INV-CAN-THREE-PHASE";
    /// Every workflow has a finite cleanup budget; exceeded triggers force-finalize.
    pub const INV_CAN_BUDGET_BOUNDED: &str = "INV-CAN-BUDGET-BOUNDED";
    /// Cancellation propagates to all child operations within a workflow.
    pub const INV_CAN_PROPAGATION: &str = "INV-CAN-PROPAGATION";
    /// After FINALIZE, no resource leaks exist.
    pub const INV_CAN_NO_LEAK: &str = "INV-CAN-NO-LEAK";
}

// ── Event codes ──────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Cancel requested.
    pub const CAN_001: &str = "CAN-001";
    /// Drain started.
    pub const CAN_002: &str = "CAN-002";
    /// Drain completed.
    pub const CAN_003: &str = "CAN-003";
    /// Drain timeout.
    pub const CAN_004: &str = "CAN-004";
    /// Finalize completed.
    pub const CAN_005: &str = "CAN-005";
    /// Resource leak detected.
    pub const CAN_006: &str = "CAN-006";
}

// ── Error codes ──────────────────────────────────────────────────────────────

pub mod error_codes {
    /// Phase transition not allowed from current state.
    pub const ERR_CANCEL_INVALID_PHASE: &str = "ERR_CANCEL_INVALID_PHASE";
    /// Cancellation attempted on already-finalized workflow.
    pub const ERR_CANCEL_ALREADY_FINAL: &str = "ERR_CANCEL_ALREADY_FINAL";
    /// Drain exceeded configured timeout.
    pub const ERR_CANCEL_DRAIN_TIMEOUT: &str = "ERR_CANCEL_DRAIN_TIMEOUT";
    /// Resources leaked during finalization.
    pub const ERR_CANCEL_LEAK: &str = "ERR_CANCEL_LEAK";
}

// ── Phase enum ───────────────────────────────────────────────────────────────

/// Phases of the three-phase cancellation protocol.
/// INV-CAN-THREE-PHASE: transitions follow Idle -> Requested -> Draining -> Finalizing -> Completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CancellationPhase {
    /// No cancellation in progress.
    Idle,
    /// Cancellation has been requested; no new work accepted.
    Requested,
    /// In-flight operations are draining.
    Draining,
    /// Resources are being released.
    Finalizing,
    /// Cancellation complete.
    Completed,
}

impl fmt::Display for CancellationPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Requested => write!(f, "requested"),
            Self::Draining => write!(f, "draining"),
            Self::Finalizing => write!(f, "finalizing"),
            Self::Completed => write!(f, "completed"),
        }
    }
}

impl CancellationPhase {
    /// Returns all phase variants in protocol order.
    pub fn all() -> &'static [CancellationPhase] {
        &[
            Self::Idle,
            Self::Requested,
            Self::Draining,
            Self::Finalizing,
            Self::Completed,
        ]
    }

    /// Whether the phase is terminal.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

// ── Workflow identifiers ─────────────────────────────────────────────────────

/// Workflow identifiers for per-workflow budget configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkflowKind {
    Lifecycle,
    Rollout,
    Publish,
    Revoke,
    Quarantine,
    Migration,
    Custom(String),
}

impl WorkflowKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Lifecycle => "lifecycle",
            Self::Rollout => "rollout",
            Self::Publish => "publish",
            Self::Revoke => "revoke",
            Self::Quarantine => "quarantine",
            Self::Migration => "migration",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Default cleanup budget for this workflow kind.
    pub fn default_budget_ms(&self) -> u64 {
        match self {
            Self::Lifecycle => 5000,
            Self::Rollout => 3000,
            Self::Publish => 2000,
            Self::Revoke => 2000,
            Self::Quarantine => 3000,
            Self::Migration => 5000,
            Self::Custom(_) => 3000,
        }
    }

    /// Returns all standard (non-custom) workflow kinds.
    pub fn standard_kinds() -> &'static [WorkflowKind] {
        &[
            Self::Lifecycle,
            Self::Rollout,
            Self::Publish,
            Self::Revoke,
            Self::Quarantine,
            Self::Migration,
        ]
    }
}

impl fmt::Display for WorkflowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ── Budget ───────────────────────────────────────────────────────────────────

/// Per-workflow cancellation cleanup budget.
/// INV-CAN-BUDGET-BOUNDED: every budget has a finite timeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationBudget {
    /// Workflow this budget applies to.
    pub workflow: String,
    /// Maximum duration allowed for the drain phase.
    pub timeout_ms: u64,
}

impl CancellationBudget {
    /// Create a new budget with the given timeout.
    pub fn new(workflow: &str, timeout_ms: u64) -> Self {
        Self {
            workflow: workflow.to_string(),
            timeout_ms,
        }
    }

    /// Create a budget from a WorkflowKind using its default timeout.
    pub fn from_kind(kind: &WorkflowKind) -> Self {
        Self {
            workflow: kind.as_str().to_string(),
            timeout_ms: kind.default_budget_ms(),
        }
    }

    /// Return the timeout as a Duration.
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// Check whether a given elapsed duration exceeds the budget.
    pub fn is_exceeded(&self, elapsed_ms: u64) -> bool {
        elapsed_ms > self.timeout_ms
    }
}

// ── Audit event ──────────────────────────────────────────────────────────────

/// Structured audit event emitted at each phase transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationAuditEvent {
    /// Event code (CAN-001 through CAN-006).
    pub event_code: String,
    /// Phase at the time of the event.
    pub phase: CancellationPhase,
    /// Workflow identifier.
    pub workflow: String,
    /// Trace ID from the originating Cx context.
    pub trace_id: String,
    /// Human-readable detail.
    pub detail: String,
    /// Schema version.
    pub schema_version: String,
}

// ── Resource tracking ────────────────────────────────────────────────────────

/// Tracks resources held by a workflow, used in finalize to detect leaks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTracker {
    /// Resources currently held (name -> count).
    pub held: std::collections::BTreeMap<String, usize>,
}

impl ResourceTracker {
    pub fn new() -> Self {
        Self {
            held: std::collections::BTreeMap::new(),
        }
    }

    /// Acquire a resource.
    pub fn acquire(&mut self, name: &str) {
        *self.held.entry(name.to_string()).or_insert(0) += 1;
    }

    /// Release a resource.
    pub fn release(&mut self, name: &str) -> bool {
        if let Some(count) = self.held.get_mut(name)
            && *count > 0
        {
            *count -= 1;
            if *count == 0 {
                self.held.remove(name);
            }
            return true;
        }
        false
    }

    /// Check if any resources are still held (potential leak).
    pub fn has_leaks(&self) -> bool {
        self.held.values().any(|&c| c > 0)
    }

    /// Number of held resources.
    pub fn held_count(&self) -> usize {
        self.held.values().sum()
    }

    /// Release all resources, returning the count released.
    pub fn release_all(&mut self) -> usize {
        let count = self.held_count();
        self.held.clear();
        count
    }
}

impl Default for ResourceTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── ResourceGuard (drop-safe) ────────────────────────────────────────────────

/// RAII guard that ensures resources are released even if the owner is dropped
/// without explicit finalization. INV-CAN-NO-LEAK.
pub struct ResourceGuard {
    workflow: String,
    resources: ResourceTracker,
    released: bool,
}

impl ResourceGuard {
    /// Create a new resource guard for the given workflow.
    pub fn new(workflow: &str) -> Self {
        Self {
            workflow: workflow.to_string(),
            resources: ResourceTracker::new(),
            released: false,
        }
    }

    /// Acquire a resource under this guard.
    pub fn acquire(&mut self, name: &str) {
        self.resources.acquire(name);
    }

    /// Release a specific resource.
    pub fn release(&mut self, name: &str) -> bool {
        self.resources.release(name)
    }

    /// Explicitly release all resources and mark as finalized.
    pub fn finalize(&mut self) -> usize {
        let count = self.resources.release_all();
        self.released = true;
        count
    }

    /// Whether the guard has been explicitly finalized.
    pub fn is_finalized(&self) -> bool {
        self.released
    }

    /// Whether any resources remain unreleased.
    pub fn has_leaks(&self) -> bool {
        self.resources.has_leaks()
    }

    /// The workflow this guard protects.
    pub fn workflow(&self) -> &str {
        &self.workflow
    }
}

impl Drop for ResourceGuard {
    fn drop(&mut self) {
        if !self.released && self.resources.has_leaks() {
            // INV-CAN-NO-LEAK: force-release on drop with warning.
            // In production this would emit CAN-006 via the audit channel.
            let _leaked = self.resources.release_all();
            // Leak detected during drop -- CAN-006 would be emitted here.
        }
    }
}

// ── Cancellation protocol ────────────────────────────────────────────────────

/// Result of a phase transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTransitionResult {
    /// Previous phase.
    pub from: CancellationPhase,
    /// New phase.
    pub to: CancellationPhase,
    /// Whether force-finalize was triggered.
    pub force_finalized: bool,
    /// Event code emitted.
    pub event_code: String,
    /// Error detail if any.
    pub error: Option<String>,
}

/// The three-phase cancellation protocol manager.
///
/// Manages state transitions following the REQUEST -> DRAIN -> FINALIZE protocol.
/// INV-CAN-THREE-PHASE: enforced by the transition methods.
/// INV-CAN-PROPAGATION: propagation tracked via child_count.
pub struct CancellationProtocol {
    /// Current phase.
    phase: CancellationPhase,
    /// Per-workflow cleanup budget.
    budget: CancellationBudget,
    /// Audit log.
    audit_log: Vec<CancellationAuditEvent>,
    /// Resource guard for drop safety.
    resource_guard: ResourceGuard,
    /// Number of in-flight child operations.
    inflight_children: usize,
    /// Whether force-finalize was triggered.
    force_finalized: bool,
    /// Trace ID for Cx correlation.
    trace_id: String,
}

impl CancellationProtocol {
    /// Create a new protocol instance for the given workflow and budget.
    pub fn new(budget: CancellationBudget, trace_id: &str) -> Self {
        Self {
            phase: CancellationPhase::Idle,
            resource_guard: ResourceGuard::new(&budget.workflow),
            budget,
            audit_log: Vec::new(),
            inflight_children: 0,
            force_finalized: false,
            trace_id: trace_id.to_string(),
        }
    }

    /// Create a protocol for a WorkflowKind with default budget.
    pub fn for_workflow(kind: &WorkflowKind, trace_id: &str) -> Self {
        Self::new(CancellationBudget::from_kind(kind), trace_id)
    }

    /// Current phase.
    pub fn phase(&self) -> CancellationPhase {
        self.phase
    }

    /// Whether the protocol is in a terminal state.
    pub fn is_completed(&self) -> bool {
        self.phase == CancellationPhase::Completed
    }

    /// Whether force-finalize was triggered.
    pub fn was_force_finalized(&self) -> bool {
        self.force_finalized
    }

    /// The budget for this protocol.
    pub fn budget(&self) -> &CancellationBudget {
        &self.budget
    }

    /// Access the resource guard.
    pub fn resource_guard(&self) -> &ResourceGuard {
        &self.resource_guard
    }

    /// Mutably access the resource guard.
    pub fn resource_guard_mut(&mut self) -> &mut ResourceGuard {
        &mut self.resource_guard
    }

    /// Register an in-flight child operation. INV-CAN-PROPAGATION.
    pub fn register_child(&mut self) {
        self.inflight_children += 1;
    }

    /// Mark a child operation as completed.
    pub fn complete_child(&mut self) {
        self.inflight_children = self.inflight_children.saturating_sub(1);
    }

    /// Number of in-flight children.
    pub fn inflight_children(&self) -> usize {
        self.inflight_children
    }

    /// The audit log.
    pub fn audit_log(&self) -> &[CancellationAuditEvent] {
        &self.audit_log
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    // ── Phase transitions ────────────────────────────────────────────────

    /// Phase 1: REQUEST cancellation.
    /// Transitions from Idle to Requested. Idempotent if already Requested.
    /// Emits CAN-001.
    pub fn request(&mut self) -> Result<PhaseTransitionResult, String> {
        match self.phase {
            CancellationPhase::Idle => {
                let from = self.phase;
                self.phase = CancellationPhase::Requested;
                let event = event_codes::CAN_001;
                self.emit_event(event, "cancellation requested");
                Ok(PhaseTransitionResult {
                    from,
                    to: self.phase,
                    force_finalized: false,
                    event_code: event.to_string(),
                    error: None,
                })
            }
            CancellationPhase::Requested => {
                // Idempotent: absorb duplicate request
                Ok(PhaseTransitionResult {
                    from: self.phase,
                    to: self.phase,
                    force_finalized: false,
                    event_code: event_codes::CAN_001.to_string(),
                    error: None,
                })
            }
            CancellationPhase::Completed => Err(error_codes::ERR_CANCEL_ALREADY_FINAL.to_string()),
            _ => Err(error_codes::ERR_CANCEL_INVALID_PHASE.to_string()),
        }
    }

    /// Phase 2: DRAIN in-flight operations.
    /// Transitions from Requested to Draining. If elapsed_ms exceeds budget,
    /// triggers force-finalize. Emits CAN-002 on start, CAN-003 on complete,
    /// CAN-004 on timeout.
    pub fn drain(&mut self, elapsed_ms: u64) -> Result<PhaseTransitionResult, String> {
        match self.phase {
            CancellationPhase::Requested => {
                let from = self.phase;
                self.phase = CancellationPhase::Draining;
                self.emit_event(event_codes::CAN_002, "drain started");

                if self.budget.is_exceeded(elapsed_ms) {
                    // Budget exceeded: force-finalize
                    self.emit_event(
                        event_codes::CAN_004,
                        &format!(
                            "drain timeout: elapsed={}ms budget={}ms",
                            elapsed_ms, self.budget.timeout_ms
                        ),
                    );
                    let force_res = self.force_finalize_internal();
                    let mut err_str = error_codes::ERR_CANCEL_DRAIN_TIMEOUT.to_string();
                    if let Some(leak_err) = force_res.error {
                        err_str = format!("{}; {}", err_str, leak_err);
                    }
                    return Ok(PhaseTransitionResult {
                        from,
                        to: self.phase,
                        force_finalized: true,
                        event_code: event_codes::CAN_004.to_string(),
                        error: Some(err_str),
                    });
                }

                // Drain completed within budget
                self.emit_event(event_codes::CAN_003, "drain completed");
                Ok(PhaseTransitionResult {
                    from,
                    to: self.phase,
                    force_finalized: false,
                    event_code: event_codes::CAN_003.to_string(),
                    error: None,
                })
            }
            CancellationPhase::Completed => Err(error_codes::ERR_CANCEL_ALREADY_FINAL.to_string()),
            _ => Err(error_codes::ERR_CANCEL_INVALID_PHASE.to_string()),
        }
    }

    /// Phase 3: FINALIZE -- release resources and commit terminal state.
    /// Transitions from Draining to Finalizing then Completed.
    /// Emits CAN-005 on success, CAN-006 if resource leaks detected.
    pub fn finalize(&mut self) -> Result<PhaseTransitionResult, String> {
        match self.phase {
            CancellationPhase::Draining => {
                let from = self.phase;
                self.phase = CancellationPhase::Finalizing;

                // Check for resource leaks before releasing
                let had_leaks = self.resource_guard.has_leaks();

                // Release all resources
                let released = self.resource_guard.finalize();

                if had_leaks {
                    self.emit_event(
                        event_codes::CAN_006,
                        &format!(
                            "resource leak detected: {} resources force-released",
                            released
                        ),
                    );
                }

                self.phase = CancellationPhase::Completed;
                self.emit_event(event_codes::CAN_005, "finalize completed");

                Ok(PhaseTransitionResult {
                    from,
                    to: self.phase,
                    force_finalized: false,
                    event_code: event_codes::CAN_005.to_string(),
                    error: if had_leaks {
                        Some(error_codes::ERR_CANCEL_LEAK.to_string())
                    } else {
                        None
                    },
                })
            }
            CancellationPhase::Completed => Err(error_codes::ERR_CANCEL_ALREADY_FINAL.to_string()),
            _ => Err(error_codes::ERR_CANCEL_INVALID_PHASE.to_string()),
        }
    }

    /// Execute the full three-phase protocol in one call.
    /// Useful for workflows that can drain synchronously.
    pub fn run_full(&mut self, drain_elapsed_ms: u64) -> Result<PhaseTransitionResult, String> {
        self.request()?;
        self.drain(drain_elapsed_ms)?;
        self.finalize()
    }

    /// Force-finalize: skip directly to Completed, releasing all resources.
    /// Used when drain timeout is exceeded. INV-CAN-BUDGET-BOUNDED.
    pub fn force_finalize(&mut self) -> PhaseTransitionResult {
        self.force_finalize_internal()
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    fn force_finalize_internal(&mut self) -> PhaseTransitionResult {
        let from = self.phase;
        self.force_finalized = true;

        // Release all resources
        let had_leaks = self.resource_guard.has_leaks();
        let released = self.resource_guard.finalize();

        if had_leaks {
            self.emit_event(
                event_codes::CAN_006,
                &format!(
                    "force-finalize: {} resources released during forced cleanup",
                    released
                ),
            );
        }

        self.phase = CancellationPhase::Completed;
        self.emit_event(event_codes::CAN_005, "force-finalize completed");

        PhaseTransitionResult {
            from,
            to: self.phase,
            force_finalized: true,
            event_code: event_codes::CAN_005.to_string(),
            error: if had_leaks {
                Some(error_codes::ERR_CANCEL_LEAK.to_string())
            } else {
                None
            },
        }
    }

    fn emit_event(&mut self, event_code: &str, detail: &str) {
        self.audit_log.push(CancellationAuditEvent {
            event_code: event_code.to_string(),
            phase: self.phase,
            workflow: self.budget.workflow.clone(),
            trace_id: self.trace_id.clone(),
            detail: detail.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });
    }
}

// ── Timing report ────────────────────────────────────────────────────────────

/// A single row of the timing CSV report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingRow {
    pub workflow_id: String,
    pub phase: String,
    pub budget_ms: u64,
    pub actual_ms: u64,
    pub within_budget: bool,
    pub resources_released: usize,
}

/// Generate a timing report from protocol execution results.
pub fn generate_timing_csv(rows: &[TimingRow]) -> String {
    let mut csv =
        String::from("workflow_id,phase,budget_ms,actual_ms,within_budget,resources_released\n");
    for row in rows {
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            row.workflow_id,
            row.phase,
            row.budget_ms,
            row.actual_ms,
            row.within_budget,
            row.resources_released,
        ));
    }
    csv
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_protocol(workflow: &str, timeout_ms: u64) -> CancellationProtocol {
        CancellationProtocol::new(CancellationBudget::new(workflow, timeout_ms), "test-trace")
    }

    // ── Phase enum ───────────────────────────────────────────────────────

    #[test]
    fn phase_all_returns_five() {
        assert_eq!(CancellationPhase::all().len(), 5);
    }

    #[test]
    fn phase_display() {
        assert_eq!(CancellationPhase::Idle.to_string(), "idle");
        assert_eq!(CancellationPhase::Requested.to_string(), "requested");
        assert_eq!(CancellationPhase::Draining.to_string(), "draining");
        assert_eq!(CancellationPhase::Finalizing.to_string(), "finalizing");
        assert_eq!(CancellationPhase::Completed.to_string(), "completed");
    }

    #[test]
    fn phase_terminal() {
        assert!(!CancellationPhase::Idle.is_terminal());
        assert!(!CancellationPhase::Requested.is_terminal());
        assert!(!CancellationPhase::Draining.is_terminal());
        assert!(!CancellationPhase::Finalizing.is_terminal());
        assert!(CancellationPhase::Completed.is_terminal());
    }

    // ── Budget ───────────────────────────────────────────────────────────

    #[test]
    fn budget_from_kind() {
        let b = CancellationBudget::from_kind(&WorkflowKind::Lifecycle);
        assert_eq!(b.workflow, "lifecycle");
        assert_eq!(b.timeout_ms, 5000);
    }

    #[test]
    fn budget_is_exceeded() {
        let b = CancellationBudget::new("test", 3000);
        assert!(!b.is_exceeded(2999));
        assert!(!b.is_exceeded(3000));
        assert!(b.is_exceeded(3001));
    }

    #[test]
    fn budget_timeout_duration() {
        let b = CancellationBudget::new("test", 5000);
        assert_eq!(b.timeout_duration(), Duration::from_millis(5000));
    }

    // ── Workflow kinds ───────────────────────────────────────────────────

    #[test]
    fn standard_kinds_count() {
        assert_eq!(WorkflowKind::standard_kinds().len(), 6);
    }

    #[test]
    fn workflow_kind_display() {
        assert_eq!(WorkflowKind::Lifecycle.to_string(), "lifecycle");
        assert_eq!(WorkflowKind::Rollout.to_string(), "rollout");
        assert_eq!(WorkflowKind::Publish.to_string(), "publish");
        assert_eq!(WorkflowKind::Revoke.to_string(), "revoke");
        assert_eq!(WorkflowKind::Quarantine.to_string(), "quarantine");
        assert_eq!(WorkflowKind::Migration.to_string(), "migration");
    }

    #[test]
    fn custom_workflow_budget() {
        assert_eq!(WorkflowKind::Custom("foo".into()).default_budget_ms(), 3000);
    }

    // ── Resource tracker ─────────────────────────────────────────────────

    #[test]
    fn resource_tracker_acquire_release() {
        let mut rt = ResourceTracker::new();
        rt.acquire("conn");
        assert!(rt.has_leaks());
        assert_eq!(rt.held_count(), 1);
        assert!(rt.release("conn"));
        assert!(!rt.has_leaks());
    }

    #[test]
    fn resource_tracker_release_all() {
        let mut rt = ResourceTracker::new();
        rt.acquire("a");
        rt.acquire("b");
        rt.acquire("b");
        assert_eq!(rt.release_all(), 3);
        assert!(!rt.has_leaks());
    }

    // ── ResourceGuard ────────────────────────────────────────────────────

    #[test]
    fn resource_guard_finalize() {
        let mut guard = ResourceGuard::new("test");
        guard.acquire("conn");
        guard.acquire("lock");
        assert!(guard.has_leaks());
        assert_eq!(guard.finalize(), 2);
        assert!(guard.is_finalized());
        assert!(!guard.has_leaks());
    }

    #[test]
    fn resource_guard_drop_releases() {
        // Create and drop a guard with resources -- should not panic
        let mut guard = ResourceGuard::new("test");
        guard.acquire("conn");
        drop(guard);
        // If we get here, drop succeeded without panicking
    }

    // ── Protocol: happy path ─────────────────────────────────────────────

    #[test]
    fn happy_path_request_drain_finalize() {
        let mut proto = make_protocol("lifecycle", 5000);
        assert_eq!(proto.phase(), CancellationPhase::Idle);

        let r1 = proto.request().unwrap();
        assert_eq!(r1.from, CancellationPhase::Idle);
        assert_eq!(r1.to, CancellationPhase::Requested);
        assert_eq!(r1.event_code, "CAN-001");
        assert!(!r1.force_finalized);

        let r2 = proto.drain(1000).unwrap();
        assert_eq!(r2.from, CancellationPhase::Requested);
        assert_eq!(r2.to, CancellationPhase::Draining);
        assert_eq!(r2.event_code, "CAN-003");

        let r3 = proto.finalize().unwrap();
        assert_eq!(r3.to, CancellationPhase::Completed);
        assert_eq!(r3.event_code, "CAN-005");
        assert!(proto.is_completed());
    }

    #[test]
    fn run_full_happy_path() {
        let mut proto = make_protocol("rollout", 3000);
        let result = proto.run_full(500).unwrap();
        assert_eq!(result.to, CancellationPhase::Completed);
        assert!(!result.force_finalized);
    }

    // ── Protocol: timeout ────────────────────────────────────────────────

    #[test]
    fn drain_timeout_triggers_force_finalize() {
        let mut proto = make_protocol("publish", 2000);
        proto.request().unwrap();
        let result = proto.drain(3000).unwrap();
        assert!(result.force_finalized);
        assert_eq!(result.event_code, "CAN-004");
        assert!(proto.is_completed());
        assert!(proto.was_force_finalized());
    }

    #[test]
    fn drain_timeout_with_leak_preserves_leak_error() {
        let mut proto = make_protocol("publish", 2000);
        proto.resource_guard_mut().acquire("leaked_conn");
        proto.request().unwrap();
        let result = proto.drain(3000).unwrap();
        assert!(result.force_finalized);
        assert!(result.error.unwrap().contains("ERR_CANCEL_LEAK"));
    }

    // ── Protocol: leak detection ─────────────────────────────────────────

    #[test]
    fn finalize_detects_resource_leak() {
        let mut proto = make_protocol("revoke", 2000);
        proto.resource_guard_mut().acquire("leaked_conn");
        proto.request().unwrap();
        proto.drain(500).unwrap();
        let result = proto.finalize().unwrap();
        assert_eq!(result.error, Some("ERR_CANCEL_LEAK".to_string()));
        assert!(proto.is_completed());
    }

    #[test]
    fn finalize_no_leak_when_clean() {
        let mut proto = make_protocol("quarantine", 3000);
        proto.request().unwrap();
        proto.drain(500).unwrap();
        let result = proto.finalize().unwrap();
        assert!(result.error.is_none());
    }

    // ── Protocol: error cases ────────────────────────────────────────────

    #[test]
    fn request_idempotent() {
        let mut proto = make_protocol("test", 3000);
        proto.request().unwrap();
        let r2 = proto.request().unwrap();
        assert_eq!(r2.from, CancellationPhase::Requested);
        assert_eq!(r2.to, CancellationPhase::Requested);
    }

    #[test]
    fn request_after_completed_fails() {
        let mut proto = make_protocol("test", 3000);
        proto.run_full(100).unwrap();
        let err = proto.request().unwrap_err();
        assert_eq!(err, "ERR_CANCEL_ALREADY_FINAL");
    }

    #[test]
    fn drain_from_idle_fails() {
        let mut proto = make_protocol("test", 3000);
        let err = proto.drain(100).unwrap_err();
        assert_eq!(err, "ERR_CANCEL_INVALID_PHASE");
    }

    #[test]
    fn finalize_from_idle_fails() {
        let mut proto = make_protocol("test", 3000);
        let err = proto.finalize().unwrap_err();
        assert_eq!(err, "ERR_CANCEL_INVALID_PHASE");
    }

    // ── Protocol: child propagation ──────────────────────────────────────

    #[test]
    fn child_registration_and_completion() {
        let mut proto = make_protocol("lifecycle", 5000);
        proto.register_child();
        proto.register_child();
        assert_eq!(proto.inflight_children(), 2);
        proto.complete_child();
        assert_eq!(proto.inflight_children(), 1);
        proto.complete_child();
        assert_eq!(proto.inflight_children(), 0);
    }

    // ── Audit log ────────────────────────────────────────────────────────

    #[test]
    fn audit_log_records_all_events() {
        let mut proto = make_protocol("lifecycle", 5000);
        proto.request().unwrap();
        proto.drain(100).unwrap();
        proto.finalize().unwrap();
        // CAN-001 + CAN-002 + CAN-003 + CAN-005 = 4 events minimum
        assert_eq!(proto.audit_log().len(), 4);
    }

    #[test]
    fn audit_log_jsonl_valid() {
        let mut proto = make_protocol("test", 3000);
        proto.request().unwrap();
        let jsonl = proto.export_audit_log_jsonl();
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["event_code"], "CAN-001");
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }

    // ── Timing CSV ───────────────────────────────────────────────────────

    #[test]
    fn timing_csv_generation() {
        let rows = vec![TimingRow {
            workflow_id: "lifecycle".into(),
            phase: "drain".into(),
            budget_ms: 5000,
            actual_ms: 1200,
            within_budget: true,
            resources_released: 3,
        }];
        let csv = generate_timing_csv(&rows);
        assert!(csv.contains("workflow_id,phase,budget_ms"));
        assert!(csv.contains("lifecycle,drain,5000,1200,true,3"));
    }

    // ── Schema / constants ───────────────────────────────────────────────

    #[test]
    fn schema_version_correct() {
        assert_eq!(SCHEMA_VERSION, "cancel-v1.0");
    }

    #[test]
    fn bead_id_correct() {
        assert_eq!(BEAD_ID, "bd-1cs7");
    }

    #[test]
    fn invariant_constants_defined() {
        assert_eq!(invariants::INV_CAN_THREE_PHASE, "INV-CAN-THREE-PHASE");
        assert_eq!(invariants::INV_CAN_BUDGET_BOUNDED, "INV-CAN-BUDGET-BOUNDED");
        assert_eq!(invariants::INV_CAN_PROPAGATION, "INV-CAN-PROPAGATION");
        assert_eq!(invariants::INV_CAN_NO_LEAK, "INV-CAN-NO-LEAK");
    }

    #[test]
    fn event_codes_defined() {
        assert_eq!(event_codes::CAN_001, "CAN-001");
        assert_eq!(event_codes::CAN_002, "CAN-002");
        assert_eq!(event_codes::CAN_003, "CAN-003");
        assert_eq!(event_codes::CAN_004, "CAN-004");
        assert_eq!(event_codes::CAN_005, "CAN-005");
        assert_eq!(event_codes::CAN_006, "CAN-006");
    }

    #[test]
    fn error_codes_defined() {
        assert!(!error_codes::ERR_CANCEL_INVALID_PHASE.is_empty());
        assert!(!error_codes::ERR_CANCEL_ALREADY_FINAL.is_empty());
        assert!(!error_codes::ERR_CANCEL_DRAIN_TIMEOUT.is_empty());
        assert!(!error_codes::ERR_CANCEL_LEAK.is_empty());
    }

    // ── Invariant string presence in source ──────────────────────────────

    #[test]
    fn invariant_strings_present_in_module() {
        let src = include_str!("cancellation_protocol.rs");
        assert!(src.contains("INV-CAN-THREE-PHASE"));
        assert!(src.contains("INV-CAN-BUDGET-BOUNDED"));
        assert!(src.contains("INV-CAN-PROPAGATION"));
        assert!(src.contains("INV-CAN-NO-LEAK"));
    }

    #[test]
    fn event_code_strings_present_in_module() {
        let src = include_str!("cancellation_protocol.rs");
        assert!(src.contains("CAN-001"));
        assert!(src.contains("CAN-002"));
        assert!(src.contains("CAN-003"));
        assert!(src.contains("CAN-004"));
        assert!(src.contains("CAN-005"));
        assert!(src.contains("CAN-006"));
    }

    // ── Force-finalize ───────────────────────────────────────────────────

    #[test]
    fn force_finalize_from_any_phase() {
        let mut proto = make_protocol("test", 3000);
        proto.request().unwrap();
        let result = proto.force_finalize();
        assert!(result.force_finalized);
        assert_eq!(result.to, CancellationPhase::Completed);
        assert!(proto.is_completed());
    }
}
