//! Region-owned execution trees for connector lifecycle orchestration.
//!
//! Implements HRI-2 (region-owned lifecycle): every long-running control-plane
//! operation executes within an asupersync region that owns its execution tree.
//! Closing a region implies deterministic quiescence of all child tasks.
//!
//! # Region hierarchy
//!
//! ```text
//! root_region (connector lifecycle)
//! ├── health_gate_region (health-gate evaluation cycles)
//! ├── rollout_region (rollout state transitions)
//! └── fencing_region (fencing token operations)
//! ```
//!
//! # Event codes
//!
//! - `RGN-001`: Region opened
//! - `RGN-002`: Region close initiated
//! - `RGN-003`: Quiescence achieved
//! - `RGN-004`: Child task force-terminated
//! - `RGN-005`: Quiescence timeout

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_CHILD_REGION_IDS: usize = 4096;
const MAX_TASKS: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        return;
    }
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
}

/// Stable event codes for region ownership.
pub mod event_codes {
    pub const REGION_OPENED: &str = "RGN-001";
    pub const REGION_CLOSE_INITIATED: &str = "RGN-002";
    pub const QUIESCENCE_ACHIEVED: &str = "RGN-003";
    pub const CHILD_FORCE_TERMINATED: &str = "RGN-004";
    pub const QUIESCENCE_TIMEOUT: &str = "RGN-005";
}

static REGION_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_region_id() -> RegionId {
    RegionId(atomic_next(&REGION_SEQ))
}

// ---------------------------------------------------------------------------
// asupersync execution context (Cx)
// ---------------------------------------------------------------------------

static CX_SEQ: AtomicU64 = AtomicU64::new(1);

fn atomic_next(counter: &AtomicU64) -> u64 {
    loop {
        let current = counter.load(Ordering::Relaxed);
        let next = current.saturating_add(1);
        if counter
            .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return current;
        }
    }
}

/// asupersync execution context for control-plane operations.
///
/// Every region-owned operation carries a `ControlPlaneCx` that:
/// - Links the operation to the asupersync epoch
/// - Provides a monotonic sequence number for causal ordering
/// - Carries the parent Cx reference for hierarchy reconstruction
/// - Includes a deterministic `cx_id` derived from epoch + seq
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneCx {
    /// asupersync epoch this context belongs to.
    pub epoch: u64,
    /// Monotonic sequence within the epoch.
    pub seq: u64,
    /// Parent context ID, if this is a child context.
    pub parent_cx_id: Option<String>,
    /// Deterministic identifier for this context (SHA-256 of epoch:seq).
    pub cx_id: String,
    /// Connector this context is associated with.
    pub connector_id: String,
    /// Trace ID for distributed tracing correlation.
    pub trace_id: String,
}

impl ControlPlaneCx {
    /// Create a new root Cx for a control-plane lifecycle.
    pub fn new_root(connector_id: &str, trace_id: &str, epoch: u64) -> Self {
        let seq = atomic_next(&CX_SEQ);
        let cx_id = compute_cx_id(epoch, seq);
        Self {
            epoch,
            seq,
            parent_cx_id: None,
            cx_id,
            connector_id: connector_id.to_string(),
            trace_id: trace_id.to_string(),
        }
    }

    /// Derive a child Cx inheriting the epoch and parent linkage.
    pub fn child(&self) -> Self {
        let seq = atomic_next(&CX_SEQ);
        let cx_id = compute_cx_id(self.epoch, seq);
        Self {
            epoch: self.epoch,
            seq,
            parent_cx_id: Some(self.cx_id.clone()),
            cx_id,
            connector_id: self.connector_id.clone(),
            trace_id: self.trace_id.clone(),
        }
    }

    /// Returns true if this context has a parent (i.e., is not a root).
    pub fn is_child(&self) -> bool {
        self.parent_cx_id.is_some()
    }
}

impl fmt::Display for ControlPlaneCx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cx(epoch={}, seq={}, id={})",
            self.epoch,
            self.seq,
            &self.cx_id[..12.min(self.cx_id.len())]
        )
    }
}

/// Compute a deterministic Cx identifier from epoch and sequence.
fn compute_cx_id(epoch: u64, seq: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"region_ownership_cx_v1:");
    hasher.update(epoch.to_le_bytes());
    hasher.update(b":");
    hasher.update(seq.to_le_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Region identity
// ---------------------------------------------------------------------------

/// Unique identifier for a region within the execution tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(pub u64);

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rgn-{}", self.0)
    }
}

/// The kind of region in the hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    /// Root region for the connector lifecycle.
    ConnectorLifecycle,
    /// Child region for health-gate evaluation cycles.
    HealthGate,
    /// Child region for rollout state transitions.
    Rollout,
    /// Child region for fencing token operations.
    Fencing,
}

impl RegionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConnectorLifecycle => "connector_lifecycle",
            Self::HealthGate => "health_gate",
            Self::Rollout => "rollout",
            Self::Fencing => "fencing",
        }
    }
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// State of a child task within a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Running,
    Draining,
    Completed,
    ForceTerminated,
}

/// A child task registered within a region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionTask {
    pub task_id: String,
    pub state: TaskState,
    pub registered_at_ms: u64,
}

/// A structured event emitted during region lifecycle operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionEvent {
    pub event_code: String,
    pub region_id: RegionId,
    pub parent_region_id: Option<RegionId>,
    pub region_kind: RegionKind,
    pub child_task_count: usize,
    pub trace_id: String,
    /// asupersync Cx identifier for causal ordering.
    pub cx_id: String,
    pub detail: String,
}

/// Close result for a region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseResult {
    pub region_id: RegionId,
    pub quiescence_achieved: bool,
    pub tasks_drained: usize,
    pub tasks_force_terminated: usize,
    pub elapsed_ms: u64,
    pub events: Vec<RegionEvent>,
}

/// Errors from region operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code")]
pub enum RegionError {
    #[serde(rename = "RGN_ALREADY_CLOSED")]
    AlreadyClosed { region_id: RegionId },
    #[serde(rename = "RGN_INVALID_TASK_ID")]
    InvalidTaskId {
        region_id: RegionId,
        task_id: String,
        reason: String,
    },
    #[serde(rename = "RGN_CHILD_STILL_OPEN")]
    ChildStillOpen {
        region_id: RegionId,
        child_region_id: RegionId,
    },
    #[serde(rename = "RGN_TASK_NOT_FOUND")]
    TaskNotFound {
        region_id: RegionId,
        task_id: String,
    },
}

impl fmt::Display for RegionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyClosed { region_id } => {
                write!(
                    f,
                    "RGN_ALREADY_CLOSED: region {region_id} is already closed"
                )
            }
            Self::InvalidTaskId {
                region_id,
                task_id,
                reason,
            } => write!(
                f,
                "RGN_INVALID_TASK_ID: task {task_id:?} is invalid in region {region_id}: {reason}"
            ),
            Self::ChildStillOpen {
                region_id,
                child_region_id,
            } => write!(
                f,
                "RGN_CHILD_STILL_OPEN: region {region_id} has open child {child_region_id}"
            ),
            Self::TaskNotFound { region_id, task_id } => write!(
                f,
                "RGN_TASK_NOT_FOUND: task {task_id} not found in region {region_id}"
            ),
        }
    }
}

impl std::error::Error for RegionError {}

fn invalid_task_id_reason(task_id: &str) -> Option<&'static str> {
    if task_id.trim().is_empty() {
        return Some("task_id must be non-empty");
    }
    if task_id.trim() != task_id {
        return Some("task_id must not contain leading or trailing whitespace");
    }
    if task_id.contains('\0') {
        return Some("task_id must not contain NUL bytes");
    }
    None
}

/// An execution region that owns child tasks and enforces quiescence on close.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub id: RegionId,
    pub kind: RegionKind,
    pub parent_id: Option<RegionId>,
    pub connector_id: String,
    pub trace_id: String,
    /// asupersync execution context for this region.
    pub cx: ControlPlaneCx,
    pub tasks: Vec<RegionTask>,
    pub child_region_ids: Vec<RegionId>,
    pub closed: bool,
    pub quiescence_budget_ms: u64,
}

impl Region {
    /// Create a new root region for a connector lifecycle.
    ///
    /// Accepts a `ControlPlaneCx` that links this region to the asupersync epoch.
    pub fn new_root(cx: ControlPlaneCx, quiescence_budget_ms: u64) -> Self {
        let connector_id = cx.connector_id.clone();
        let trace_id = cx.trace_id.clone();
        Self {
            id: next_region_id(),
            kind: RegionKind::ConnectorLifecycle,
            parent_id: None,
            connector_id,
            trace_id,
            cx,
            tasks: Vec::new(),
            child_region_ids: Vec::new(),
            closed: false,
            quiescence_budget_ms,
        }
    }

    /// Create a child region nested under this region.
    ///
    /// Derives a child `ControlPlaneCx` from the parent, maintaining causal linkage.
    pub fn open_child(&mut self, kind: RegionKind, quiescence_budget_ms: u64) -> Region {
        let child_cx = self.cx.child();
        let child = Region {
            id: next_region_id(),
            kind,
            parent_id: Some(self.id),
            connector_id: self.connector_id.clone(),
            trace_id: self.trace_id.clone(),
            cx: child_cx,
            tasks: Vec::new(),
            child_region_ids: Vec::new(),
            closed: false,
            quiescence_budget_ms,
        };
        let child_id = child.id;
        push_bounded(&mut self.child_region_ids, child_id, MAX_CHILD_REGION_IDS);
        child
    }

    /// Register a task within this region.
    pub fn register_task(&mut self, task_id: &str) -> Result<(), RegionError> {
        if self.closed {
            return Err(RegionError::AlreadyClosed { region_id: self.id });
        }
        if let Some(reason) = invalid_task_id_reason(task_id) {
            return Err(RegionError::InvalidTaskId {
                region_id: self.id,
                task_id: task_id.to_string(),
                reason: reason.to_string(),
            });
        }
        push_bounded(
            &mut self.tasks,
            RegionTask {
                task_id: task_id.to_string(),
                state: TaskState::Running,
                registered_at_ms: 0,
            },
            MAX_TASKS,
        );
        Ok(())
    }

    /// Mark a task as completed. Only valid from Running or Draining state.
    pub fn complete_task(&mut self, task_id: &str) -> Result<(), RegionError> {
        if let Some(reason) = invalid_task_id_reason(task_id) {
            return Err(RegionError::InvalidTaskId {
                region_id: self.id,
                task_id: task_id.to_string(),
                reason: reason.to_string(),
            });
        }
        let task = self
            .tasks
            .iter_mut()
            .find(|t| t.task_id == task_id)
            .ok_or_else(|| RegionError::TaskNotFound {
                region_id: self.id,
                task_id: task_id.to_string(),
            })?;
        match task.state {
            TaskState::Running | TaskState::Draining => {
                task.state = TaskState::Completed;
            }
            TaskState::Completed | TaskState::ForceTerminated => {
                // Already in a terminal state — no-op to preserve idempotency.
            }
        }
        Ok(())
    }

    /// Open event for this region.
    pub fn open_event(&self) -> RegionEvent {
        RegionEvent {
            event_code: event_codes::REGION_OPENED.to_string(),
            region_id: self.id,
            parent_region_id: self.parent_id,
            region_kind: self.kind,
            child_task_count: self.tasks.len(),
            trace_id: self.trace_id.clone(),
            cx_id: self.cx.cx_id.clone(),
            detail: format!(
                "region {} ({}) opened for connector {} [cx={}]",
                self.id, self.kind, self.connector_id, self.cx
            ),
        }
    }

    /// Close this region, draining all tasks and enforcing quiescence.
    ///
    /// Tasks that are still running after the drain phase are force-terminated.
    /// Returns a `CloseResult` with the quiescence outcome.
    pub fn close(&mut self) -> Result<CloseResult, RegionError> {
        if self.closed {
            return Err(RegionError::AlreadyClosed { region_id: self.id });
        }

        let start = Instant::now();
        let mut events = Vec::new();

        // Capture counts before mutable iteration
        let total_task_count = self.tasks.len();
        let running_count = self
            .tasks
            .iter()
            .filter(|t| t.state == TaskState::Running)
            .count();

        let cx_id = self.cx.cx_id.clone();

        // Emit close-initiated event
        events.push(RegionEvent {
            event_code: event_codes::REGION_CLOSE_INITIATED.to_string(),
            region_id: self.id,
            parent_region_id: self.parent_id,
            region_kind: self.kind,
            child_task_count: total_task_count,
            trace_id: self.trace_id.clone(),
            cx_id: cx_id.clone(),
            detail: format!(
                "region {} close initiated, {} tasks to drain",
                self.id, running_count
            ),
        });

        // Drain phase: signal all running tasks to drain
        for task in &mut self.tasks {
            if task.state == TaskState::Running {
                task.state = TaskState::Draining;
            }
        }

        // Simulate drain completion for tasks that can complete within budget.
        // In a real async runtime, this would await task completion with a timeout.
        let mut tasks_drained = 0;
        let mut tasks_force_terminated = 0;
        let mut force_terminated_ids: Vec<String> = Vec::new();

        for task in &mut self.tasks {
            match task.state {
                TaskState::Draining => {
                    let elapsed = start.elapsed();
                    if elapsed < Duration::from_millis(self.quiescence_budget_ms) {
                        task.state = TaskState::Completed;
                        tasks_drained += 1;
                    } else {
                        task.state = TaskState::ForceTerminated;
                        tasks_force_terminated += 1;
                        force_terminated_ids.push(task.task_id.clone());
                    }
                }
                TaskState::Completed => {
                    tasks_drained += 1;
                }
                TaskState::ForceTerminated => {
                    tasks_force_terminated += 1;
                }
                TaskState::Running => {} // not yet draining; handled by next drain cycle
            }
        }

        // Emit force-termination events after iteration
        for terminated_id in &force_terminated_ids {
            events.push(RegionEvent {
                event_code: event_codes::CHILD_FORCE_TERMINATED.to_string(),
                region_id: self.id,
                parent_region_id: self.parent_id,
                region_kind: self.kind,
                child_task_count: total_task_count,
                trace_id: self.trace_id.clone(),
                cx_id: cx_id.clone(),
                detail: format!(
                    "task {} force-terminated after budget exceeded",
                    terminated_id
                ),
            });
        }

        let elapsed = start.elapsed();
        let quiescence_achieved = tasks_force_terminated == 0;

        // Emit quiescence event
        if quiescence_achieved {
            events.push(RegionEvent {
                event_code: event_codes::QUIESCENCE_ACHIEVED.to_string(),
                region_id: self.id,
                parent_region_id: self.parent_id,
                region_kind: self.kind,
                child_task_count: total_task_count,
                trace_id: self.trace_id.clone(),
                cx_id: cx_id.clone(),
                detail: format!(
                    "quiescence achieved for region {} in {}ms",
                    self.id,
                    elapsed.as_millis()
                ),
            });
        } else {
            events.push(RegionEvent {
                event_code: event_codes::QUIESCENCE_TIMEOUT.to_string(),
                region_id: self.id,
                parent_region_id: self.parent_id,
                region_kind: self.kind,
                child_task_count: total_task_count,
                trace_id: self.trace_id.clone(),
                cx_id: cx_id.clone(),
                detail: format!(
                    "quiescence timeout for region {}: {} tasks force-terminated",
                    self.id, tasks_force_terminated
                ),
            });
        }

        self.closed = true;

        Ok(CloseResult {
            region_id: self.id,
            quiescence_achieved,
            tasks_drained,
            tasks_force_terminated,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            events,
        })
    }

    /// Returns true if all tasks are in a terminal state (completed or force-terminated).
    pub fn is_quiescent(&self) -> bool {
        self.tasks
            .iter()
            .all(|t| matches!(t.state, TaskState::Completed | TaskState::ForceTerminated))
    }

    /// Returns the number of active (non-terminal) tasks.
    pub fn active_task_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| matches!(t.state, TaskState::Running | TaskState::Draining))
            .count()
    }
}

/// Build a complete region hierarchy for a connector lifecycle.
///
/// Accepts a `ControlPlaneCx` that roots the entire hierarchy in the asupersync
/// epoch. Each child region derives its own Cx with causal linkage to the root.
///
/// Returns (root, health_gate, rollout, fencing) regions with proper parent linkage.
pub fn build_lifecycle_hierarchy(
    cx: ControlPlaneCx,
    root_budget_ms: u64,
    child_budget_ms: u64,
) -> (Region, Region, Region, Region) {
    let mut root = Region::new_root(cx, root_budget_ms);
    let health_gate = root.open_child(RegionKind::HealthGate, child_budget_ms);
    let rollout = root.open_child(RegionKind::Rollout, child_budget_ms);
    let fencing = root.open_child(RegionKind::Fencing, child_budget_ms);
    (root, health_gate, rollout, fencing)
}

/// Generate a quiescence trace as a list of JSONL-formatted region events.
pub fn generate_quiescence_trace(
    regions: &[&Region],
    close_results: &[&CloseResult],
) -> Result<Vec<serde_json::Value>, serde_json::Error> {
    let mut trace: Vec<serde_json::Value> = Vec::new();

    // Open events
    for region in regions {
        trace.push(serde_json::to_value(region.open_event())?);
    }

    // Close events
    for result in close_results {
        for event in &result.events {
            trace.push(serde_json::to_value(event)?);
        }
    }

    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cx() -> ControlPlaneCx {
        ControlPlaneCx::new_root("test-conn", "trace-001", 42)
    }

    #[test]
    fn root_region_creation() {
        let root = Region::new_root(test_cx(), 5000);
        assert_eq!(root.kind, RegionKind::ConnectorLifecycle);
        assert!(root.parent_id.is_none());
        assert!(!root.closed);
        assert_eq!(root.connector_id, "test-conn");
        assert_eq!(root.cx.epoch, 42);
        assert!(!root.cx.cx_id.is_empty());
    }

    #[test]
    fn child_region_linkage() {
        let mut root = Region::new_root(test_cx(), 5000);
        let child = root.open_child(RegionKind::HealthGate, 2000);
        assert_eq!(child.parent_id, Some(root.id));
        assert!(root.child_region_ids.contains(&child.id));
        // Child Cx links to parent
        assert_eq!(
            child.cx.parent_cx_id.as_deref(),
            Some(root.cx.cx_id.as_str())
        );
        assert_eq!(child.cx.epoch, root.cx.epoch);
    }

    #[test]
    fn task_registration_and_completion() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("task-1").unwrap();
        region.register_task("task-2").unwrap();
        assert_eq!(region.active_task_count(), 2);

        region.complete_task("task-1").unwrap();
        assert_eq!(region.active_task_count(), 1);

        region.complete_task("task-2").unwrap();
        assert!(region.is_quiescent());
    }

    #[test]
    fn close_drains_all_tasks() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("task-1").unwrap();
        region.register_task("task-2").unwrap();

        let result = region.close().unwrap();
        assert!(result.quiescence_achieved);
        assert_eq!(result.tasks_drained, 2);
        assert_eq!(result.tasks_force_terminated, 0);
        assert!(region.closed);
    }

    #[test]
    fn close_emits_correct_events() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("task-1").unwrap();

        let result = region.close().unwrap();
        let codes: Vec<&str> = result
            .events
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&"RGN-002")); // close initiated
        assert!(codes.contains(&"RGN-003")); // quiescence achieved
    }

    #[test]
    fn close_events_carry_cx_id() {
        let cx = test_cx();
        let expected_cx_id = cx.cx_id.clone();
        let mut region = Region::new_root(cx, 5000);
        region.register_task("task-1").unwrap();

        let result = region.close().unwrap();
        for event in &result.events {
            assert_eq!(event.cx_id, expected_cx_id);
        }
    }

    #[test]
    fn already_closed_region_rejects_operations() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.close().unwrap();

        let err = region.close().unwrap_err();
        assert!(matches!(err, RegionError::AlreadyClosed { .. }));

        let err = region.register_task("task-1").unwrap_err();
        assert!(matches!(err, RegionError::AlreadyClosed { .. }));
    }

    #[test]
    fn task_not_found_error() {
        let mut region = Region::new_root(test_cx(), 5000);
        let err = region.complete_task("nonexistent").unwrap_err();
        assert!(matches!(err, RegionError::TaskNotFound { .. }));
    }

    #[test]
    fn hierarchy_builder() {
        let cx = ControlPlaneCx::new_root("test-conn", "trace-001", 100);
        let root_cx_id = cx.cx_id.clone();
        let (root, health, rollout, fencing) = build_lifecycle_hierarchy(cx, 5000, 2000);
        assert_eq!(root.child_region_ids.len(), 3);
        assert_eq!(health.parent_id, Some(root.id));
        assert_eq!(rollout.parent_id, Some(root.id));
        assert_eq!(fencing.parent_id, Some(root.id));
        // All child Cx link to root
        assert_eq!(health.cx.parent_cx_id.as_deref(), Some(root_cx_id.as_str()));
        assert_eq!(
            rollout.cx.parent_cx_id.as_deref(),
            Some(root_cx_id.as_str())
        );
        assert_eq!(
            fencing.cx.parent_cx_id.as_deref(),
            Some(root_cx_id.as_str())
        );
    }

    #[test]
    fn quiescence_trace_generation() {
        let mut root = Region::new_root(test_cx(), 5000);
        root.register_task("task-1").unwrap();
        let result = root.close().unwrap();

        let trace = generate_quiescence_trace(&[&root], &[&result]).unwrap();
        assert!(!trace.is_empty());
    }

    #[test]
    fn completed_tasks_counted_as_drained() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("task-1").unwrap();
        region.complete_task("task-1").unwrap();

        let result = region.close().unwrap();
        assert!(result.quiescence_achieved);
        assert_eq!(result.tasks_drained, 1);
    }

    #[test]
    fn region_event_codes_are_stable() {
        assert_eq!(event_codes::REGION_OPENED, "RGN-001");
        assert_eq!(event_codes::REGION_CLOSE_INITIATED, "RGN-002");
        assert_eq!(event_codes::QUIESCENCE_ACHIEVED, "RGN-003");
        assert_eq!(event_codes::CHILD_FORCE_TERMINATED, "RGN-004");
        assert_eq!(event_codes::QUIESCENCE_TIMEOUT, "RGN-005");
    }

    #[test]
    fn serde_roundtrip() {
        let region = Region::new_root(test_cx(), 5000);
        let json = serde_json::to_string(&region).unwrap();
        let parsed: Region = serde_json::from_str(&json).unwrap();
        assert_eq!(region.kind, parsed.kind);
        assert_eq!(region.connector_id, parsed.connector_id);
        assert_eq!(region.cx, parsed.cx);
    }

    // -- ControlPlaneCx tests --

    #[test]
    fn cx_root_has_no_parent() {
        let cx = ControlPlaneCx::new_root("conn-1", "trace-1", 10);
        assert!(cx.parent_cx_id.is_none());
        assert!(!cx.is_child());
        assert_eq!(cx.epoch, 10);
        assert_eq!(cx.connector_id, "conn-1");
        assert_eq!(cx.trace_id, "trace-1");
    }

    #[test]
    fn cx_child_links_to_parent() {
        let root = ControlPlaneCx::new_root("conn-1", "trace-1", 10);
        let child = root.child();
        assert!(child.is_child());
        assert_eq!(child.parent_cx_id.as_deref(), Some(root.cx_id.as_str()));
        assert_eq!(child.epoch, root.epoch);
        assert_ne!(child.cx_id, root.cx_id);
    }

    #[test]
    fn cx_id_deterministic_for_same_epoch_seq() {
        let id1 = compute_cx_id(42, 99);
        let id2 = compute_cx_id(42, 99);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA-256
    }

    #[test]
    fn cx_id_differs_for_different_inputs() {
        let id1 = compute_cx_id(1, 1);
        let id2 = compute_cx_id(1, 2);
        let id3 = compute_cx_id(2, 1);
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn cx_display_format() {
        let cx = ControlPlaneCx::new_root("conn-1", "trace-1", 7);
        let s = cx.to_string();
        assert!(s.contains("epoch=7"));
        assert!(s.contains("cx("));
    }

    #[test]
    fn cx_serde_roundtrip() {
        let cx = ControlPlaneCx::new_root("conn-1", "trace-1", 42);
        let json = serde_json::to_string(&cx).unwrap();
        let parsed: ControlPlaneCx = serde_json::from_str(&json).unwrap();
        assert_eq!(cx, parsed);
    }

    #[test]
    fn open_event_carries_cx_id() {
        let cx = test_cx();
        let expected = cx.cx_id.clone();
        let region = Region::new_root(cx, 5000);
        let event = region.open_event();
        assert_eq!(event.cx_id, expected);
        assert!(event.detail.contains("cx="));
    }

    #[test]
    fn close_with_zero_budget_force_terminates_running_task() {
        let mut region = Region::new_root(test_cx(), 0);
        region.register_task("slow-task").unwrap();

        let result = region.close().unwrap();

        assert!(!result.quiescence_achieved);
        assert_eq!(result.tasks_drained, 0);
        assert_eq!(result.tasks_force_terminated, 1);
        assert_eq!(region.tasks[0].state, TaskState::ForceTerminated);
        assert!(result.events.iter().any(|event| {
            event.event_code == event_codes::CHILD_FORCE_TERMINATED
                && event.detail.contains("slow-task")
        }));
        assert!(
            result
                .events
                .iter()
                .any(|event| event.event_code == event_codes::QUIESCENCE_TIMEOUT)
        );
    }

    #[test]
    fn close_with_existing_force_terminated_task_reports_timeout() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("already-killed").unwrap();
        region.tasks[0].state = TaskState::ForceTerminated;

        let result = region.close().unwrap();

        assert!(!result.quiescence_achieved);
        assert_eq!(result.tasks_drained, 0);
        assert_eq!(result.tasks_force_terminated, 1);
        assert_eq!(region.active_task_count(), 0);
        assert!(region.is_quiescent());
    }

    #[test]
    fn close_twice_preserves_region_id_in_error() {
        let mut region = Region::new_root(test_cx(), 5000);
        let region_id = region.id;
        region.close().unwrap();

        let err = region.close().unwrap_err();

        assert_eq!(err, RegionError::AlreadyClosed { region_id });
        assert!(err.to_string().contains("RGN_ALREADY_CLOSED"));
    }

    #[test]
    fn register_task_after_close_preserves_region_id_in_error() {
        let mut region = Region::new_root(test_cx(), 5000);
        let region_id = region.id;
        region.close().unwrap();

        let err = region.register_task("late-task").unwrap_err();

        assert_eq!(err, RegionError::AlreadyClosed { region_id });
        assert!(region.tasks.is_empty());
    }

    #[test]
    fn complete_missing_task_preserves_task_id_in_error() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("existing-task").unwrap();
        let region_id = region.id;

        let err = region.complete_task("missing-task").unwrap_err();

        assert_eq!(
            err,
            RegionError::TaskNotFound {
                region_id,
                task_id: "missing-task".to_string()
            }
        );
        assert_eq!(region.active_task_count(), 1);
    }

    #[test]
    fn serde_rejects_unknown_region_kind() {
        let err = serde_json::from_str::<RegionKind>(r#""speculative""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_task_state() {
        let err = serde_json::from_str::<TaskState>(r#""zombie""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_task_not_found_error_missing_task_id() {
        let json = serde_json::json!({
            "code": "RGN_TASK_NOT_FOUND",
            "region_id": 7
        });

        let err = serde_json::from_value::<RegionError>(json).unwrap_err();

        assert!(err.to_string().contains("task_id"));
    }

    #[test]
    fn push_bounded_zero_capacity_drops_item_without_panicking() {
        let mut ids = vec![RegionId(1), RegionId(2)];

        push_bounded(&mut ids, RegionId(3), 0);

        assert_eq!(ids, vec![RegionId(1), RegionId(2)]);
    }

    #[test]
    fn push_bounded_over_capacity_discards_oldest_child_ids() {
        let mut ids = vec![RegionId(1), RegionId(2), RegionId(3)];

        push_bounded(&mut ids, RegionId(4), 2);

        assert_eq!(ids, vec![RegionId(3), RegionId(4)]);
    }

    #[test]
    fn malformed_region_error_code_is_rejected() {
        let json = serde_json::json!({
            "code": "RGN_UNKNOWN",
            "region_id": 9
        });

        let err = serde_json::from_value::<RegionError>(json).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn malformed_control_plane_cx_missing_id_is_rejected() {
        let json = serde_json::json!({
            "epoch": 42,
            "seq": 7,
            "parent_cx_id": null,
            "connector_id": "conn-1",
            "trace_id": "trace-1"
        });

        let err = serde_json::from_value::<ControlPlaneCx>(json).unwrap_err();

        assert!(err.to_string().contains("cx_id"));
    }

    #[test]
    fn malformed_region_task_unknown_state_is_rejected() {
        let json = serde_json::json!({
            "task_id": "task-1",
            "state": "wedged",
            "registered_at_ms": 0
        });

        let err = serde_json::from_value::<RegionTask>(json).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn completing_force_terminated_task_does_not_resurrect_it() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("killed").unwrap();
        region.tasks[0].state = TaskState::ForceTerminated;

        region.complete_task("killed").unwrap();

        assert_eq!(region.tasks[0].state, TaskState::ForceTerminated);
        assert_eq!(region.active_task_count(), 0);
        assert!(region.is_quiescent());
    }

    #[test]
    fn close_mixed_completed_and_force_terminated_tasks_reports_timeout() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("done").unwrap();
        region.register_task("killed").unwrap();
        region.tasks[0].state = TaskState::Completed;
        region.tasks[1].state = TaskState::ForceTerminated;

        let result = region.close().unwrap();

        assert!(!result.quiescence_achieved);
        assert_eq!(result.tasks_drained, 1);
        assert_eq!(result.tasks_force_terminated, 1);
        assert!(result.events.iter().any(|event| {
            event.event_code == event_codes::QUIESCENCE_TIMEOUT
                && event.child_task_count == 2
        }));
    }

    #[test]
    fn timeout_close_events_preserve_region_cx_id() {
        let cx = test_cx();
        let expected_cx_id = cx.cx_id.clone();
        let mut region = Region::new_root(cx, 0);
        region.register_task("slow").unwrap();

        let result = region.close().unwrap();

        assert!(!result.quiescence_achieved);
        assert!(result
            .events
            .iter()
            .all(|event| event.cx_id == expected_cx_id));
    }

    #[test]
    fn complete_empty_task_id_is_rejected_without_touching_tasks() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("task-1").unwrap();

        let err = region.complete_task("").unwrap_err();

        assert!(matches!(err, RegionError::InvalidTaskId { .. }));
        assert!(err.to_string().contains("must be non-empty"));
        assert_eq!(region.tasks[0].state, TaskState::Running);
        assert_eq!(region.active_task_count(), 1);
    }

    #[test]
    fn complete_task_is_case_sensitive_and_preserves_original() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("Task-A").unwrap();

        let err = region.complete_task("task-a").unwrap_err();

        assert!(matches!(
            err,
            RegionError::TaskNotFound { ref task_id, .. } if task_id == "task-a"
        ));
        assert_eq!(region.tasks[0].task_id, "Task-A");
        assert_eq!(region.tasks[0].state, TaskState::Running);
    }

    #[test]
    fn register_task_after_close_preserves_existing_terminal_task() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("done").unwrap();
        region.complete_task("done").unwrap();
        region.close().unwrap();

        let err = region.register_task("late").unwrap_err();

        assert!(matches!(err, RegionError::AlreadyClosed { .. }));
        assert_eq!(region.tasks.len(), 1);
        assert_eq!(region.tasks[0].task_id, "done");
        assert_eq!(region.tasks[0].state, TaskState::Completed);
    }

    #[test]
    fn serde_rejects_already_closed_error_missing_region_id() {
        let json = serde_json::json!({
            "code": "RGN_ALREADY_CLOSED"
        });

        let err = serde_json::from_value::<RegionError>(json).unwrap_err();

        assert!(err.to_string().contains("region_id"));
    }

    #[test]
    fn serde_rejects_child_still_open_error_missing_child_region_id() {
        let json = serde_json::json!({
            "code": "RGN_CHILD_STILL_OPEN",
            "region_id": 1
        });

        let err = serde_json::from_value::<RegionError>(json).unwrap_err();

        assert!(err.to_string().contains("child_region_id"));
    }

    #[test]
    fn serde_rejects_region_event_missing_cx_id() {
        let json = serde_json::json!({
            "event_code": "RGN-001",
            "region_id": 1,
            "parent_region_id": null,
            "region_kind": "connector_lifecycle",
            "child_task_count": 0,
            "trace_id": "trace-001",
            "detail": "opened"
        });

        let err = serde_json::from_value::<RegionEvent>(json).unwrap_err();

        assert!(err.to_string().contains("cx_id"));
    }

    #[test]
    fn serde_rejects_close_result_missing_events() {
        let json = serde_json::json!({
            "region_id": 1,
            "quiescence_achieved": true,
            "tasks_drained": 0,
            "tasks_force_terminated": 0,
            "elapsed_ms": 0
        });

        let err = serde_json::from_value::<CloseResult>(json).unwrap_err();

        assert!(err.to_string().contains("events"));
    }

    #[test]
    fn serde_rejects_control_plane_cx_parent_with_wrong_type() {
        let json = serde_json::json!({
            "epoch": 42,
            "seq": 7,
            "parent_cx_id": 99,
            "cx_id": compute_cx_id(42, 7),
            "connector_id": "conn-1",
            "trace_id": "trace-1"
        });

        let err = serde_json::from_value::<ControlPlaneCx>(json).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn register_task_rejects_empty_task_id() {
        let mut region = Region::new_root(test_cx(), 5000);

        let err = region.register_task("").unwrap_err();

        assert!(matches!(err, RegionError::InvalidTaskId { .. }));
        assert!(err.to_string().contains("must be non-empty"));
        assert!(region.tasks.is_empty());
    }

    #[test]
    fn register_task_rejects_blank_task_id() {
        let mut region = Region::new_root(test_cx(), 5000);

        let err = region.register_task("\t ").unwrap_err();

        assert!(matches!(err, RegionError::InvalidTaskId { .. }));
        assert!(err.to_string().contains("must be non-empty"));
        assert!(region.tasks.is_empty());
    }

    #[test]
    fn register_task_rejects_task_id_with_edge_whitespace() {
        let mut region = Region::new_root(test_cx(), 5000);

        let err = region.register_task(" task-1").unwrap_err();

        assert!(matches!(err, RegionError::InvalidTaskId { .. }));
        assert!(err.to_string().contains("leading or trailing whitespace"));
        assert!(region.tasks.is_empty());
    }

    #[test]
    fn register_task_rejects_task_id_with_nul() {
        let mut region = Region::new_root(test_cx(), 5000);

        let err = region.register_task("task\0shadow").unwrap_err();

        assert!(matches!(err, RegionError::InvalidTaskId { .. }));
        assert!(err.to_string().contains("NUL"));
        assert!(region.tasks.is_empty());
    }

    #[test]
    fn complete_task_rejects_empty_task_id_without_lookup() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("task-1").unwrap();

        let err = region.complete_task("").unwrap_err();

        assert!(matches!(err, RegionError::InvalidTaskId { .. }));
        assert_eq!(region.active_task_count(), 1);
        assert_eq!(region.tasks[0].state, TaskState::Running);
    }

    #[test]
    fn complete_task_rejects_nul_task_id_without_mutating_tasks() {
        let mut region = Region::new_root(test_cx(), 5000);
        region.register_task("task-1").unwrap();

        let err = region.complete_task("task-1\0shadow").unwrap_err();

        assert!(matches!(err, RegionError::InvalidTaskId { .. }));
        assert!(err.to_string().contains("NUL"));
        assert_eq!(region.active_task_count(), 1);
        assert_eq!(region.tasks[0].state, TaskState::Running);
    }
}
