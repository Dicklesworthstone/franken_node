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

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::CancellationPhase;
    ///
    /// assert_eq!(CancellationPhase::all()[0], CancellationPhase::Idle);
    /// assert_eq!(CancellationPhase::all().last(), Some(&CancellationPhase::Completed));
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::CancellationPhase;
    ///
    /// assert!(!CancellationPhase::Draining.is_terminal());
    /// assert!(CancellationPhase::Completed.is_terminal());
    /// ```
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
    /// Return the stable string identifier for this workflow kind.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::WorkflowKind;
    ///
    /// assert_eq!(WorkflowKind::Publish.as_str(), "publish");
    /// assert_eq!(WorkflowKind::Custom("import".to_string()).as_str(), "import");
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::WorkflowKind;
    ///
    /// assert_eq!(WorkflowKind::Lifecycle.default_budget_ms(), 5000);
    /// assert_eq!(WorkflowKind::Custom("custom".to_string()).default_budget_ms(), 3000);
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::WorkflowKind;
    ///
    /// assert!(WorkflowKind::standard_kinds().contains(&WorkflowKind::Rollout));
    /// assert!(!WorkflowKind::standard_kinds().contains(&WorkflowKind::Custom("x".to_string())));
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::CancellationBudget;
    ///
    /// let budget = CancellationBudget::new("rollout", 3000);
    /// assert_eq!(budget.workflow, "rollout");
    /// assert_eq!(budget.timeout_ms, 3000);
    /// ```
    pub fn new(workflow: &str, timeout_ms: u64) -> Self {
        Self {
            workflow: workflow.to_string(),
            timeout_ms,
        }
    }

    /// Create a budget from a WorkflowKind using its default timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationBudget, WorkflowKind,
    /// };
    ///
    /// let budget = CancellationBudget::from_kind(&WorkflowKind::Quarantine);
    /// assert_eq!(budget.workflow, "quarantine");
    /// assert_eq!(budget.timeout_ms, WorkflowKind::Quarantine.default_budget_ms());
    /// ```
    pub fn from_kind(kind: &WorkflowKind) -> Self {
        Self {
            workflow: kind.as_str().to_string(),
            timeout_ms: kind.default_budget_ms(),
        }
    }

    /// Return the timeout as a Duration.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::CancellationBudget;
    /// use std::time::Duration;
    ///
    /// let budget = CancellationBudget::new("publish", 2000);
    /// assert_eq!(budget.timeout_duration(), Duration::from_millis(2000));
    /// ```
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// Check whether a given elapsed duration exceeds the budget.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::CancellationBudget;
    ///
    /// let budget = CancellationBudget::new("publish", 2000);
    /// assert!(!budget.is_exceeded(1999));
    /// assert!(budget.is_exceeded(2000));
    /// ```
    pub fn is_exceeded(&self, elapsed_ms: u64) -> bool {
        elapsed_ms >= self.timeout_ms
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
    /// Create an empty resource tracker.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceTracker;
    ///
    /// let tracker = ResourceTracker::new();
    /// assert_eq!(tracker.held_count(), 0);
    /// assert!(!tracker.has_leaks());
    /// ```
    pub fn new() -> Self {
        Self {
            held: std::collections::BTreeMap::new(),
        }
    }

    /// Acquire a resource.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceTracker;
    ///
    /// let mut tracker = ResourceTracker::new();
    /// tracker.acquire("socket");
    /// tracker.acquire("socket");
    /// assert_eq!(tracker.held_count(), 2);
    /// ```
    pub fn acquire(&mut self, name: &str) {
        let counter = self.held.entry(name.to_string()).or_insert(0);
        *counter = counter.saturating_add(1);
    }

    /// Release a resource.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceTracker;
    ///
    /// let mut tracker = ResourceTracker::new();
    /// tracker.acquire("socket");
    /// assert!(tracker.release("socket"));
    /// assert!(!tracker.release("socket"));
    /// ```
    pub fn release(&mut self, name: &str) -> bool {
        let should_remove = if let Some(count) = self.held.get_mut(name) {
            if *count > 0 {
                *count = count.saturating_sub(1);
                *count == 0
            } else {
                return false;
            }
        } else {
            return false;
        };

        if should_remove {
            self.held.remove(name);
        }
        true
    }

    /// Check if any resources are still held (potential leak).
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceTracker;
    ///
    /// let mut tracker = ResourceTracker::new();
    /// assert!(!tracker.has_leaks());
    /// tracker.acquire("lock");
    /// assert!(tracker.has_leaks());
    /// ```
    pub fn has_leaks(&self) -> bool {
        self.held.values().any(|&c| c > 0)
    }

    /// Number of held resources.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceTracker;
    ///
    /// let mut tracker = ResourceTracker::new();
    /// tracker.acquire("lock");
    /// tracker.acquire("file");
    /// assert_eq!(tracker.held_count(), 2);
    /// ```
    pub fn held_count(&self) -> usize {
        self.held
            .values()
            .fold(0usize, |acc, v| acc.saturating_add(*v))
    }

    /// Release all resources, returning the count released.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceTracker;
    ///
    /// let mut tracker = ResourceTracker::new();
    /// tracker.acquire("lock");
    /// tracker.acquire("file");
    /// assert_eq!(tracker.release_all(), 2);
    /// assert_eq!(tracker.held_count(), 0);
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceGuard;
    ///
    /// let guard = ResourceGuard::new("rollout");
    /// assert_eq!(guard.workflow(), "rollout");
    /// assert!(!guard.is_finalized());
    /// ```
    pub fn new(workflow: &str) -> Self {
        Self {
            workflow: workflow.to_string(),
            resources: ResourceTracker::new(),
            released: false,
        }
    }

    /// Acquire a resource under this guard.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceGuard;
    ///
    /// let mut guard = ResourceGuard::new("rollout");
    /// guard.acquire("socket");
    /// assert!(guard.has_leaks());
    /// ```
    pub fn acquire(&mut self, name: &str) {
        self.resources.acquire(name);
    }

    /// Release a specific resource.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceGuard;
    ///
    /// let mut guard = ResourceGuard::new("rollout");
    /// guard.acquire("socket");
    /// assert!(guard.release("socket"));
    /// assert!(!guard.has_leaks());
    /// ```
    pub fn release(&mut self, name: &str) -> bool {
        self.resources.release(name)
    }

    /// Explicitly release all resources and mark as finalized.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceGuard;
    ///
    /// let mut guard = ResourceGuard::new("rollout");
    /// guard.acquire("socket");
    /// assert_eq!(guard.finalize(), 1);
    /// assert!(guard.is_finalized());
    /// ```
    pub fn finalize(&mut self) -> usize {
        let count = self.resources.release_all();
        self.released = true;
        count
    }

    /// Whether the guard has been explicitly finalized.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceGuard;
    ///
    /// let mut guard = ResourceGuard::new("rollout");
    /// assert!(!guard.is_finalized());
    /// guard.finalize();
    /// assert!(guard.is_finalized());
    /// ```
    pub fn is_finalized(&self) -> bool {
        self.released
    }

    /// Whether any resources remain unreleased.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceGuard;
    ///
    /// let mut guard = ResourceGuard::new("rollout");
    /// guard.acquire("socket");
    /// assert!(guard.has_leaks());
    /// guard.finalize();
    /// assert!(!guard.has_leaks());
    /// ```
    pub fn has_leaks(&self) -> bool {
        self.resources.has_leaks()
    }

    /// The workflow this guard protects.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::ResourceGuard;
    ///
    /// let guard = ResourceGuard::new("rollout");
    /// assert_eq!(guard.workflow(), "rollout");
    /// ```
    pub fn workflow(&self) -> &str {
        &self.workflow
    }
}

impl Drop for ResourceGuard {
    fn drop(&mut self) {
        if !self.released && self.resources.has_leaks() {
            // INV-CAN-NO-LEAK: force-release on drop with warning.
            let leaked_count = self.resources.release_all();
            // CAN-006: emit structured warning for leak detection audit trail.
            tracing::warn!(
                event_code = event_codes::CAN_006,
                workflow = %self.workflow,
                leaked_resources = leaked_count,
                "Resource leak detected during drop: force-released {} resource(s) for workflow '{}'",
                leaked_count,
                self.workflow,
            );
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationBudget, CancellationPhase, CancellationProtocol,
    /// };
    ///
    /// let protocol = CancellationProtocol::new(CancellationBudget::new("rollout", 3000), "trace-1");
    /// assert_eq!(protocol.phase(), CancellationPhase::Idle);
    /// assert_eq!(protocol.budget().workflow, "rollout");
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// assert_eq!(protocol.budget().workflow, "publish");
    /// assert_eq!(protocol.budget().timeout_ms, WorkflowKind::Publish.default_budget_ms());
    /// ```
    pub fn for_workflow(kind: &WorkflowKind, trace_id: &str) -> Self {
        Self::new(CancellationBudget::from_kind(kind), trace_id)
    }

    /// Current phase.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationPhase, CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// assert_eq!(protocol.phase(), CancellationPhase::Idle);
    /// ```
    pub fn phase(&self) -> CancellationPhase {
        self.phase
    }

    /// Whether the protocol is in a terminal state.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// assert!(!protocol.is_completed());
    /// let _ = protocol.force_finalize();
    /// assert!(protocol.is_completed());
    /// ```
    pub fn is_completed(&self) -> bool {
        self.phase == CancellationPhase::Completed
    }

    /// Whether force-finalize was triggered.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// assert!(!protocol.was_force_finalized());
    /// let _ = protocol.force_finalize();
    /// assert!(protocol.was_force_finalized());
    /// ```
    pub fn was_force_finalized(&self) -> bool {
        self.force_finalized
    }

    /// The budget for this protocol.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let protocol = CancellationProtocol::for_workflow(&WorkflowKind::Migration, "trace-1");
    /// assert_eq!(protocol.budget().workflow, "migration");
    /// ```
    pub fn budget(&self) -> &CancellationBudget {
        &self.budget
    }

    /// Access the resource guard.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let protocol = CancellationProtocol::for_workflow(&WorkflowKind::Rollout, "trace-1");
    /// assert_eq!(protocol.resource_guard().workflow(), "rollout");
    /// ```
    pub fn resource_guard(&self) -> &ResourceGuard {
        &self.resource_guard
    }

    /// Mutably access the resource guard.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Rollout, "trace-1");
    /// protocol.resource_guard_mut().acquire("socket");
    /// assert!(protocol.resource_guard().has_leaks());
    /// ```
    pub fn resource_guard_mut(&mut self) -> &mut ResourceGuard {
        &mut self.resource_guard
    }

    /// Register an in-flight child operation. INV-CAN-PROPAGATION.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Rollout, "trace-1");
    /// protocol.register_child();
    /// assert_eq!(protocol.inflight_children(), 1);
    /// ```
    pub fn register_child(&mut self) {
        self.inflight_children = self.inflight_children.saturating_add(1);
    }

    /// Mark a child operation as completed.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Rollout, "trace-1");
    /// protocol.register_child();
    /// protocol.complete_child();
    /// assert_eq!(protocol.inflight_children(), 0);
    /// ```
    pub fn complete_child(&mut self) {
        self.inflight_children = self.inflight_children.saturating_sub(1);
    }

    /// Number of in-flight children.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Rollout, "trace-1");
    /// protocol.register_child();
    /// protocol.register_child();
    /// assert_eq!(protocol.inflight_children(), 2);
    /// ```
    pub fn inflight_children(&self) -> usize {
        self.inflight_children
    }

    /// The audit log.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// assert!(protocol.audit_log().is_empty());
    /// let _ = protocol.request();
    /// assert_eq!(protocol.audit_log().len(), 1);
    /// ```
    pub fn audit_log(&self) -> &[CancellationAuditEvent] {
        &self.audit_log
    }

    /// Export audit log as JSONL.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// let _ = protocol.request();
    /// let jsonl = protocol.export_audit_log_jsonl();
    /// assert!(jsonl.contains("CAN-001"));
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationPhase, CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// let result = protocol.request().expect("request should be valid from idle");
    /// assert_eq!(result.to, CancellationPhase::Requested);
    /// assert_eq!(protocol.phase(), CancellationPhase::Requested);
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationPhase, CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// protocol.request().expect("request should succeed");
    /// let result = protocol.drain(100).expect("drain should stay within budget");
    /// assert_eq!(result.to, CancellationPhase::Draining);
    /// assert!(!result.force_finalized);
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationPhase, CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// protocol.request().expect("request should succeed");
    /// protocol.drain(100).expect("drain should succeed");
    /// let result = protocol.finalize().expect("finalize should succeed after drain");
    /// assert_eq!(result.to, CancellationPhase::Completed);
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationPhase, CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// let result = protocol.run_full(100).expect("full protocol should succeed");
    /// assert_eq!(result.to, CancellationPhase::Completed);
    /// assert!(protocol.is_completed());
    /// ```
    pub fn run_full(&mut self, drain_elapsed_ms: u64) -> Result<PhaseTransitionResult, String> {
        self.request()?;
        self.drain(drain_elapsed_ms)?;
        self.finalize()
    }

    /// Force-finalize: skip directly to Completed, releasing all resources.
    /// Used when drain timeout is exceeded. INV-CAN-BUDGET-BOUNDED.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::connector::cancellation_protocol::{
    ///     CancellationPhase, CancellationProtocol, WorkflowKind,
    /// };
    ///
    /// let mut protocol = CancellationProtocol::for_workflow(&WorkflowKind::Publish, "trace-1");
    /// let result = protocol.force_finalize();
    /// assert_eq!(result.to, CancellationPhase::Completed);
    /// assert!(protocol.was_force_finalized());
    /// ```
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
        let phase = self.phase;
        let workflow = self.budget.workflow.clone();
        let trace_id = self.trace_id.clone();
        push_bounded(
            &mut self.audit_log,
            CancellationAuditEvent {
                event_code: event_code.to_string(),
                phase,
                workflow,
                trace_id,
                detail: detail.to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
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
///
/// # Examples
///
/// ```
/// use frankenengine_node::connector::cancellation_protocol::{
///     TimingRow, generate_timing_csv,
/// };
///
/// let csv = generate_timing_csv(&[TimingRow {
///     workflow_id: "rollout-1".to_string(),
///     phase: "finalize".to_string(),
///     budget_ms: 3000,
///     actual_ms: 1500,
///     within_budget: true,
///     resources_released: 2,
/// }]);
///
/// assert!(csv.starts_with("workflow_id,phase,budget_ms"));
/// assert!(csv.contains("rollout-1,finalize,3000,1500,true,2"));
/// ```
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

/// Push an item to a bounded Vec, evicting oldest entries if at capacity.
fn push_bounded<T>(vec: &mut Vec<T>, item: T, max: usize) {
    if max == 0 {
        vec.clear();
        return;
    }
    if vec.len() >= max {
        let overflow = vec.len().saturating_sub(max).saturating_add(1);
        vec.drain(0..overflow);
    }
    vec.push(item);
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
        assert!(b.is_exceeded(3000));
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

    #[test]
    fn resource_tracker_release_unknown_resource_is_rejected() {
        let mut rt = ResourceTracker::new();
        rt.acquire("known");

        assert!(!rt.release("missing"));
        assert_eq!(rt.held_count(), 1);
        assert!(rt.has_leaks());
    }

    #[test]
    fn resource_tracker_double_release_is_rejected_without_underflow() {
        let mut rt = ResourceTracker::new();
        rt.acquire("conn");

        assert!(rt.release("conn"));
        assert!(!rt.release("conn"));
        assert_eq!(rt.held_count(), 0);
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

    #[test]
    fn request_from_draining_is_rejected_without_phase_change() {
        let mut proto = make_protocol("test", 3000);
        proto.request().unwrap();
        proto.drain(100).unwrap();

        let err = proto.request().unwrap_err();

        assert_eq!(err, "ERR_CANCEL_INVALID_PHASE");
        assert_eq!(proto.phase(), CancellationPhase::Draining);
    }

    #[test]
    fn drain_from_draining_is_rejected_without_duplicate_events() {
        let mut proto = make_protocol("test", 3000);
        proto.request().unwrap();
        proto.drain(100).unwrap();
        let events_before = proto.audit_log().len();

        let err = proto.drain(100).unwrap_err();

        assert_eq!(err, "ERR_CANCEL_INVALID_PHASE");
        assert_eq!(proto.phase(), CancellationPhase::Draining);
        assert_eq!(proto.audit_log().len(), events_before);
    }

    #[test]
    fn finalize_from_requested_is_rejected_without_releasing_resources() {
        let mut proto = make_protocol("test", 3000);
        proto.resource_guard_mut().acquire("conn");
        proto.request().unwrap();

        let err = proto.finalize().unwrap_err();

        assert_eq!(err, "ERR_CANCEL_INVALID_PHASE");
        assert_eq!(proto.phase(), CancellationPhase::Requested);
        assert!(proto.resource_guard().has_leaks());
    }

    #[test]
    fn drain_after_completed_fails_already_final() {
        let mut proto = make_protocol("test", 3000);
        proto.run_full(100).unwrap();

        let err = proto.drain(100).unwrap_err();

        assert_eq!(err, "ERR_CANCEL_ALREADY_FINAL");
        assert_eq!(proto.phase(), CancellationPhase::Completed);
    }

    #[test]
    fn finalize_after_completed_fails_already_final() {
        let mut proto = make_protocol("test", 3000);
        proto.run_full(100).unwrap();

        let err = proto.finalize().unwrap_err();

        assert_eq!(err, "ERR_CANCEL_ALREADY_FINAL");
        assert_eq!(proto.phase(), CancellationPhase::Completed);
    }

    #[test]
    fn run_full_timeout_force_finalizes_then_reports_already_final() {
        let mut proto = make_protocol("test", 100);

        let err = proto.run_full(100).unwrap_err();

        assert_eq!(err, "ERR_CANCEL_ALREADY_FINAL");
        assert!(proto.was_force_finalized());
        assert_eq!(proto.phase(), CancellationPhase::Completed);
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

    #[test]
    fn completing_child_without_registration_stays_at_zero() {
        let mut proto = make_protocol("lifecycle", 5000);

        proto.complete_child();
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

    #[test]
    fn drain_at_exact_budget_force_finalizes_fail_closed() {
        let mut proto = make_protocol("exact-budget", 100);
        proto.request().unwrap();

        let result = proto.drain(100).unwrap();

        assert!(result.force_finalized);
        assert_eq!(result.from, CancellationPhase::Requested);
        assert_eq!(result.to, CancellationPhase::Completed);
        assert_eq!(result.event_code, event_codes::CAN_004);
        assert_eq!(
            result.error,
            Some(error_codes::ERR_CANCEL_DRAIN_TIMEOUT.to_string())
        );
        assert!(proto.was_force_finalized());
    }

    #[test]
    fn duplicate_request_does_not_append_audit_event() {
        let mut proto = make_protocol("dup-request", 3000);
        proto.request().unwrap();
        let events_before = proto.audit_log().len();

        let result = proto.request().unwrap();

        assert_eq!(result.from, CancellationPhase::Requested);
        assert_eq!(result.to, CancellationPhase::Requested);
        assert_eq!(proto.audit_log().len(), events_before);
    }

    #[test]
    fn finalize_from_idle_does_not_append_audit_event() {
        let mut proto = make_protocol("idle-finalize", 3000);

        let err = proto.finalize().unwrap_err();

        assert_eq!(err, error_codes::ERR_CANCEL_INVALID_PHASE);
        assert_eq!(proto.phase(), CancellationPhase::Idle);
        assert!(proto.audit_log().is_empty());
    }

    #[test]
    fn request_after_manual_force_finalize_fails_already_final() {
        let mut proto = make_protocol("manual-force", 3000);
        proto.resource_guard_mut().acquire("conn");
        let result = proto.force_finalize();

        let err = proto.request().unwrap_err();

        assert_eq!(result.error, Some(error_codes::ERR_CANCEL_LEAK.to_string()));
        assert_eq!(err, error_codes::ERR_CANCEL_ALREADY_FINAL);
        assert_eq!(proto.phase(), CancellationPhase::Completed);
        assert!(!proto.resource_guard().has_leaks());
    }

    #[test]
    fn force_finalize_from_idle_with_leak_records_leak_before_finalize() {
        let mut proto = make_protocol("idle-force-leak", 3000);
        proto.resource_guard_mut().acquire("socket");

        let result = proto.force_finalize();

        assert!(result.force_finalized);
        assert_eq!(result.from, CancellationPhase::Idle);
        assert_eq!(result.error, Some(error_codes::ERR_CANCEL_LEAK.to_string()));
        assert_eq!(proto.audit_log()[0].event_code, event_codes::CAN_006);
        assert_eq!(proto.audit_log()[1].event_code, event_codes::CAN_005);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_appending() {
        let mut items = vec!["old"];

        push_bounded(&mut items, "new", 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_overfull_vector_trims_to_capacity() {
        let mut items = vec![1, 2, 3, 4];

        push_bounded(&mut items, 5, 2);

        assert_eq!(items, vec![4, 5]);
    }

    #[test]
    fn push_bounded_exact_capacity_evicts_oldest_entry() {
        let mut items = vec!["first", "second"];

        push_bounded(&mut items, "third", 2);

        assert_eq!(items, vec!["second", "third"]);
    }

    #[test]
    fn push_bounded_capacity_one_keeps_only_newest_entry() {
        let mut items = vec!["stale"];

        push_bounded(&mut items, "fresh", 1);

        assert_eq!(items, vec!["fresh"]);
    }

    #[test]
    fn zero_timeout_budget_drain_force_finalizes_immediately() {
        let mut proto = make_protocol("zero-timeout", 0);
        proto.request().unwrap();

        let result = proto.drain(0).unwrap();

        assert!(result.force_finalized);
        assert_eq!(result.to, CancellationPhase::Completed);
        assert_eq!(
            result.error,
            Some(error_codes::ERR_CANCEL_DRAIN_TIMEOUT.to_string())
        );
        assert!(proto.was_force_finalized());
    }

    #[test]
    fn export_audit_log_jsonl_empty_before_events() {
        let proto = make_protocol("empty-audit", 3000);

        assert_eq!(proto.export_audit_log_jsonl(), "");
    }

    #[test]
    fn timing_csv_empty_rows_contains_only_header() {
        let csv = generate_timing_csv(&[]);

        assert_eq!(
            csv,
            "workflow_id,phase,budget_ms,actual_ms,within_budget,resources_released\n"
        );
    }

    #[test]
    fn malformed_cancellation_phase_unknown_variant_is_rejected() {
        let err = serde_json::from_str::<CancellationPhase>("\"Paused\"").unwrap_err();

        assert!(err.to_string().contains("Paused"));
    }

    #[test]
    fn malformed_workflow_custom_payload_type_is_rejected() {
        let payload = serde_json::json!({
            "Custom": 42
        });

        let err = serde_json::from_value::<WorkflowKind>(payload).unwrap_err();

        assert!(err.to_string().contains("string"));
    }

    #[test]
    fn malformed_cancellation_budget_missing_timeout_is_rejected() {
        let payload = serde_json::json!({
            "workflow": "rollout"
        });

        let err = serde_json::from_value::<CancellationBudget>(payload).unwrap_err();

        assert!(err.to_string().contains("timeout_ms"));
    }

    #[test]
    fn malformed_audit_event_missing_schema_version_is_rejected() {
        let payload = serde_json::json!({
            "event_code": event_codes::CAN_001,
            "phase": CancellationPhase::Requested,
            "workflow": "rollout",
            "trace_id": "trace-missing-schema",
            "detail": "cancellation requested"
        });

        let err = serde_json::from_value::<CancellationAuditEvent>(payload).unwrap_err();

        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn malformed_phase_transition_string_force_flag_is_rejected() {
        let payload = serde_json::json!({
            "from": CancellationPhase::Requested,
            "to": CancellationPhase::Completed,
            "force_finalized": "true",
            "event_code": event_codes::CAN_005,
            "error": null
        });

        let err = serde_json::from_value::<PhaseTransitionResult>(payload).unwrap_err();

        assert!(err.to_string().contains("boolean"));
    }

    #[test]
    fn malformed_timing_row_missing_resources_released_is_rejected() {
        let payload = serde_json::json!({
            "workflow_id": "rollout",
            "phase": "drain",
            "budget_ms": 3000,
            "actual_ms": 3001,
            "within_budget": false
        });

        let err = serde_json::from_value::<TimingRow>(payload).unwrap_err();

        assert!(err.to_string().contains("resources_released"));
    }

    #[test]
    fn finalize_after_drain_timeout_is_rejected_without_extra_audit_events() {
        let mut proto = make_protocol("timeout-finalize", 100);
        proto.request().unwrap();
        let timeout = proto.drain(100).unwrap();
        let events_after_timeout = proto.audit_log().len();

        let err = proto.finalize().unwrap_err();

        assert!(timeout.force_finalized);
        assert_eq!(err, error_codes::ERR_CANCEL_ALREADY_FINAL);
        assert_eq!(proto.phase(), CancellationPhase::Completed);
        assert_eq!(proto.audit_log().len(), events_after_timeout);
    }

    #[test]
    fn register_child_at_saturated_count_does_not_wrap() {
        let mut proto = make_protocol("saturated-children", 3000);
        proto.inflight_children = usize::MAX;

        proto.register_child();

        assert_eq!(proto.inflight_children(), usize::MAX);
    }
}
