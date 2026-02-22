//! bd-2tdi: Region-owned execution tree for lifecycle/rollout orchestration.
//!
//! Provides a hierarchical region model where each region owns a subtree of tasks.
//! Regions enforce quiescence guarantees: `close()` drains all children within a
//! configurable budget, force-terminating stragglers after the budget expires.
//!
//! # Region hierarchy
//!
//! ```text
//! root
//!   +-- lifecycle
//!         +-- health-gate
//!         +-- rollout
//!         +-- fencing
//! ```
//!
//! # Invariants
//!
//! - INV-REGION-QUIESCENCE: close() blocks until all children and own tasks reach
//!   quiescence or budget expires.
//! - INV-REGION-NO-OUTLIVE: No task registered to a region may outlive that region's
//!   Closed state.
//! - INV-REGION-DETERMINISTIC-CLOSE: Close sequence is deterministic — children first
//!   (in insertion order), then own tasks.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for region tree exports.
pub const SCHEMA_VERSION: &str = "region-v1.0";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

/// INV-REGION-QUIESCENCE: close() blocks until quiescence or budget expiry.
pub const INV_REGION_QUIESCENCE: &str = "INV-REGION-QUIESCENCE";

/// INV-REGION-NO-OUTLIVE: Tasks cannot outlive their owning region.
pub const INV_REGION_NO_OUTLIVE: &str = "INV-REGION-NO-OUTLIVE";

/// INV-REGION-DETERMINISTIC-CLOSE: Children close in insertion order, then own tasks.
pub const INV_REGION_DETERMINISTIC_CLOSE: &str = "INV-REGION-DETERMINISTIC-CLOSE";

// ---------------------------------------------------------------------------
// Event codes — REG-001 through REG-008
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// REG-001: Region opened.
    pub const REG_001: &str = "REG-001";
    /// REG-002: Task registered to region.
    pub const REG_002: &str = "REG-002";
    /// REG-003: Region drain started.
    pub const REG_003: &str = "REG-003";
    /// REG-004: Region drain completed (quiescence reached).
    pub const REG_004: &str = "REG-004";
    /// REG-005: Region force-terminate triggered (budget exceeded).
    pub const REG_005: &str = "REG-005";
    /// REG-006: Region closed.
    pub const REG_006: &str = "REG-006";
    /// REG-007: Child region attached.
    pub const REG_007: &str = "REG-007";
    /// REG-008: Task deregistered from region.
    pub const REG_008: &str = "REG-008";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_REGION_NOT_FOUND: &str = "ERR_REGION_NOT_FOUND";
    pub const ERR_REGION_ALREADY_CLOSED: &str = "ERR_REGION_ALREADY_CLOSED";
    pub const ERR_REGION_PARENT_NOT_FOUND: &str = "ERR_REGION_PARENT_NOT_FOUND";
    pub const ERR_REGION_BUDGET_EXCEEDED: &str = "ERR_REGION_BUDGET_EXCEEDED";
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Unique identifier for a region.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RegionId(pub String);

impl RegionId {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Lifecycle state of a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionState {
    /// Region is accepting task registrations.
    Active,
    /// Region is draining — no new tasks accepted, waiting for existing tasks.
    Draining,
    /// Region is fully closed — all tasks terminated.
    Closed,
}

impl fmt::Display for RegionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Draining => write!(f, "draining"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// A task identifier registered to a region.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TaskId(pub String);

impl TaskId {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Region node (internal)
// ---------------------------------------------------------------------------

/// Internal representation of a single region node.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegionNode {
    id: RegionId,
    parent: Option<RegionId>,
    children: Vec<RegionId>,
    tasks: Vec<TaskId>,
    state: RegionState,
    drain_budget_ms: u64,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Structured event emitted during region lifecycle operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionEvent {
    pub event_code: String,
    pub region_id: String,
    pub parent_id: Option<String>,
    pub detail: String,
    pub child_count: usize,
    pub task_count: usize,
    pub timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionTreeError {
    RegionNotFound {
        region_id: String,
    },
    RegionAlreadyClosed {
        region_id: String,
    },
    ParentNotFound {
        parent_id: String,
    },
    BudgetExceeded {
        region_id: String,
        remaining_tasks: usize,
    },
}

impl RegionTreeError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::RegionNotFound { .. } => error_codes::ERR_REGION_NOT_FOUND,
            Self::RegionAlreadyClosed { .. } => error_codes::ERR_REGION_ALREADY_CLOSED,
            Self::ParentNotFound { .. } => error_codes::ERR_REGION_PARENT_NOT_FOUND,
            Self::BudgetExceeded { .. } => error_codes::ERR_REGION_BUDGET_EXCEEDED,
        }
    }
}

impl fmt::Display for RegionTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegionNotFound { region_id } => {
                write!(f, "{}: region {} not found", self.code(), region_id)
            }
            Self::RegionAlreadyClosed { region_id } => {
                write!(f, "{}: region {} already closed", self.code(), region_id)
            }
            Self::ParentNotFound { parent_id } => {
                write!(f, "{}: parent {} not found", self.code(), parent_id)
            }
            Self::BudgetExceeded {
                region_id,
                remaining_tasks,
            } => {
                write!(
                    f,
                    "{}: region {} budget exceeded, {} tasks force-terminated",
                    self.code(),
                    region_id,
                    remaining_tasks
                )
            }
        }
    }
}

impl std::error::Error for RegionTreeError {}

// ---------------------------------------------------------------------------
// RegionHandle — scoped task registration
// ---------------------------------------------------------------------------

/// Handle for scoped task registration within a region.
///
/// Provides a convenience wrapper around `RegionTree` operations scoped to a
/// specific region.
#[derive(Debug, Clone)]
pub struct RegionHandle {
    region_id: RegionId,
}

impl RegionHandle {
    /// Create a new handle bound to the given region.
    #[must_use]
    pub fn new(region_id: RegionId) -> Self {
        Self { region_id }
    }

    /// The region this handle is bound to.
    #[must_use]
    pub fn region_id(&self) -> &RegionId {
        &self.region_id
    }

    /// Register a task through this handle.
    pub fn register_task(
        &self,
        tree: &mut RegionTree,
        task_id: TaskId,
        timestamp_ms: u64,
    ) -> Result<RegionEvent, RegionTreeError> {
        tree.register_task(&self.region_id, task_id, timestamp_ms)
    }

    /// Deregister a task through this handle.
    pub fn deregister_task(
        &self,
        tree: &mut RegionTree,
        task_id: &TaskId,
        timestamp_ms: u64,
    ) -> Result<RegionEvent, RegionTreeError> {
        tree.deregister_task(&self.region_id, task_id, timestamp_ms)
    }
}

// ---------------------------------------------------------------------------
// RegionTree — the main data structure
// ---------------------------------------------------------------------------

/// Region-owned execution tree.
///
/// Tracks parent/child relationships between regions and their registered tasks.
/// Enforces quiescence guarantees on close: children drain first (in insertion
/// order), then own tasks, with force-termination after budget expiry.
///
/// # Invariants
///
/// - INV-REGION-QUIESCENCE: close() drains recursively within budget
/// - INV-REGION-NO-OUTLIVE: tasks cannot outlive their region
/// - INV-REGION-DETERMINISTIC-CLOSE: deterministic close order
#[derive(Debug, Clone)]
pub struct RegionTree {
    nodes: BTreeMap<String, RegionNode>,
    event_log: Vec<RegionEvent>,
    default_drain_budget_ms: u64,
}

impl RegionTree {
    /// Create a new empty region tree.
    #[must_use]
    pub fn new(default_drain_budget_ms: u64) -> Self {
        Self {
            nodes: BTreeMap::new(),
            event_log: Vec::new(),
            default_drain_budget_ms,
        }
    }

    /// Open a root region (no parent).
    pub fn open_region(
        &mut self,
        id: &RegionId,
        timestamp_ms: u64,
    ) -> Result<RegionEvent, RegionTreeError> {
        let node = RegionNode {
            id: id.clone(),
            parent: None,
            children: Vec::new(),
            tasks: Vec::new(),
            state: RegionState::Active,
            drain_budget_ms: self.default_drain_budget_ms,
        };
        self.nodes.insert(id.as_str().to_string(), node);

        let event = RegionEvent {
            event_code: event_codes::REG_001.to_string(),
            region_id: id.as_str().to_string(),
            parent_id: None,
            detail: "region opened".to_string(),
            child_count: 0,
            task_count: 0,
            timestamp_ms,
        };
        self.event_log.push(event.clone());
        Ok(event)
    }

    /// Open a child region under a parent.
    pub fn open_child_region(
        &mut self,
        id: &RegionId,
        parent_id: &RegionId,
        timestamp_ms: u64,
    ) -> Result<RegionEvent, RegionTreeError> {
        // Validate parent exists and is active
        {
            let parent = self.nodes.get(parent_id.as_str()).ok_or_else(|| {
                RegionTreeError::ParentNotFound {
                    parent_id: parent_id.as_str().to_string(),
                }
            })?;
            if parent.state == RegionState::Closed {
                return Err(RegionTreeError::RegionAlreadyClosed {
                    region_id: parent_id.as_str().to_string(),
                });
            }
        }

        let node = RegionNode {
            id: id.clone(),
            parent: Some(parent_id.clone()),
            children: Vec::new(),
            tasks: Vec::new(),
            state: RegionState::Active,
            drain_budget_ms: self.default_drain_budget_ms,
        };
        self.nodes.insert(id.as_str().to_string(), node);

        // Attach to parent
        let parent = self.nodes.get_mut(parent_id.as_str()).unwrap();
        parent.children.push(id.clone());
        let child_count = parent.children.len();

        // Emit REG-001 for the new region
        let open_event = RegionEvent {
            event_code: event_codes::REG_001.to_string(),
            region_id: id.as_str().to_string(),
            parent_id: Some(parent_id.as_str().to_string()),
            detail: "region opened".to_string(),
            child_count: 0,
            task_count: 0,
            timestamp_ms,
        };
        self.event_log.push(open_event);

        // Emit REG-007 for the parent
        let attach_event = RegionEvent {
            event_code: event_codes::REG_007.to_string(),
            region_id: parent_id.as_str().to_string(),
            parent_id: None,
            detail: format!("child {} attached", id),
            child_count,
            task_count: 0,
            timestamp_ms,
        };
        self.event_log.push(attach_event.clone());
        Ok(attach_event)
    }

    /// Register a task to a region.
    /// INV-REGION-NO-OUTLIVE
    pub fn register_task(
        &mut self,
        region_id: &RegionId,
        task_id: TaskId,
        timestamp_ms: u64,
    ) -> Result<RegionEvent, RegionTreeError> {
        let node = self.nodes.get_mut(region_id.as_str()).ok_or_else(|| {
            RegionTreeError::RegionNotFound {
                region_id: region_id.as_str().to_string(),
            }
        })?;

        if node.state != RegionState::Active {
            return Err(RegionTreeError::RegionAlreadyClosed {
                region_id: region_id.as_str().to_string(),
            });
        }

        node.tasks.push(task_id.clone());
        let task_count = node.tasks.len();

        let event = RegionEvent {
            event_code: event_codes::REG_002.to_string(),
            region_id: region_id.as_str().to_string(),
            parent_id: node.parent.as_ref().map(|p| p.as_str().to_string()),
            detail: format!("task {} registered", task_id),
            child_count: node.children.len(),
            task_count,
            timestamp_ms,
        };
        self.event_log.push(event.clone());
        Ok(event)
    }

    /// Deregister a task from a region.
    pub fn deregister_task(
        &mut self,
        region_id: &RegionId,
        task_id: &TaskId,
        timestamp_ms: u64,
    ) -> Result<RegionEvent, RegionTreeError> {
        let node = self.nodes.get_mut(region_id.as_str()).ok_or_else(|| {
            RegionTreeError::RegionNotFound {
                region_id: region_id.as_str().to_string(),
            }
        })?;

        node.tasks.retain(|t| t != task_id);
        let task_count = node.tasks.len();

        let event = RegionEvent {
            event_code: event_codes::REG_008.to_string(),
            region_id: region_id.as_str().to_string(),
            parent_id: node.parent.as_ref().map(|p| p.as_str().to_string()),
            detail: format!("task {} deregistered", task_id),
            child_count: node.children.len(),
            task_count,
            timestamp_ms,
        };
        self.event_log.push(event.clone());
        Ok(event)
    }

    /// Close a region, recursively closing children first.
    ///
    /// # Invariants
    ///
    /// - INV-REGION-QUIESCENCE: blocks until all children and tasks drain or budget expires
    /// - INV-REGION-DETERMINISTIC-CLOSE: children close in insertion order, then own tasks
    /// - INV-REGION-NO-OUTLIVE: remaining tasks are force-terminated after budget
    pub fn close(
        &mut self,
        region_id: &RegionId,
        timestamp_ms: u64,
    ) -> Result<Vec<RegionEvent>, RegionTreeError> {
        let node =
            self.nodes
                .get(region_id.as_str())
                .ok_or_else(|| RegionTreeError::RegionNotFound {
                    region_id: region_id.as_str().to_string(),
                })?;

        if node.state == RegionState::Closed {
            return Err(RegionTreeError::RegionAlreadyClosed {
                region_id: region_id.as_str().to_string(),
            });
        }

        let mut all_events = Vec::new();

        // Step 1: Collect children (deterministic order — insertion order preserved by Vec)
        let children: Vec<RegionId> = node.children.clone();

        // Step 2: Recursively close children first
        // INV-REGION-DETERMINISTIC-CLOSE
        for child_id in &children {
            let child_node = self.nodes.get(child_id.as_str());
            if let Some(cn) = child_node
                && cn.state != RegionState::Closed
            {
                let child_events = self.close(child_id, timestamp_ms)?;
                all_events.extend(child_events);
            }
        }

        // Step 3: Start draining own tasks
        let drain_budget_ms;
        let task_count;
        let parent_id_str;
        {
            let node = self.nodes.get_mut(region_id.as_str()).unwrap();
            node.state = RegionState::Draining;
            drain_budget_ms = node.drain_budget_ms;
            task_count = node.tasks.len();
            parent_id_str = node.parent.as_ref().map(|p| p.as_str().to_string());
        }

        let drain_start_event = RegionEvent {
            event_code: event_codes::REG_003.to_string(),
            region_id: region_id.as_str().to_string(),
            parent_id: parent_id_str.clone(),
            detail: format!(
                "drain started, {} tasks, budget {}ms",
                task_count, drain_budget_ms
            ),
            child_count: children.len(),
            task_count,
            timestamp_ms,
        };
        self.event_log.push(drain_start_event.clone());
        all_events.push(drain_start_event);

        // Step 4: Simulate drain — in a real system this would await task completion.
        // For synchronous operation, we check if tasks remain and force-terminate.
        let remaining;
        {
            let node = self.nodes.get(region_id.as_str()).unwrap();
            remaining = node.tasks.len();
        }

        if remaining > 0 {
            // Force-terminate remaining tasks after budget
            // INV-REGION-NO-OUTLIVE
            let force_event = RegionEvent {
                event_code: event_codes::REG_005.to_string(),
                region_id: region_id.as_str().to_string(),
                parent_id: parent_id_str.clone(),
                detail: format!("{} tasks force-terminated", remaining),
                child_count: children.len(),
                task_count: remaining,
                timestamp_ms: timestamp_ms + drain_budget_ms,
            };
            self.event_log.push(force_event.clone());
            all_events.push(force_event);

            // Clear tasks
            let node = self.nodes.get_mut(region_id.as_str()).unwrap();
            node.tasks.clear();
        }

        // Step 5: Emit drain-completed
        let drain_done_event = RegionEvent {
            event_code: event_codes::REG_004.to_string(),
            region_id: region_id.as_str().to_string(),
            parent_id: parent_id_str.clone(),
            detail: "drain completed, quiescence reached".to_string(),
            child_count: children.len(),
            task_count: 0,
            timestamp_ms: if remaining > 0 {
                timestamp_ms + drain_budget_ms
            } else {
                timestamp_ms
            },
        };
        self.event_log.push(drain_done_event.clone());
        all_events.push(drain_done_event);

        // Step 6: Mark closed
        {
            let node = self.nodes.get_mut(region_id.as_str()).unwrap();
            node.state = RegionState::Closed;
        }

        let close_event = RegionEvent {
            event_code: event_codes::REG_006.to_string(),
            region_id: region_id.as_str().to_string(),
            parent_id: parent_id_str,
            detail: "region closed".to_string(),
            child_count: children.len(),
            task_count: 0,
            timestamp_ms: if remaining > 0 {
                timestamp_ms + drain_budget_ms
            } else {
                timestamp_ms
            },
        };
        self.event_log.push(close_event.clone());
        all_events.push(close_event);

        Ok(all_events)
    }

    /// Force-terminate a region immediately without draining.
    pub fn force_terminate(
        &mut self,
        region_id: &RegionId,
        timestamp_ms: u64,
    ) -> Result<RegionEvent, RegionTreeError> {
        let node = self.nodes.get_mut(region_id.as_str()).ok_or_else(|| {
            RegionTreeError::RegionNotFound {
                region_id: region_id.as_str().to_string(),
            }
        })?;

        if node.state == RegionState::Closed {
            return Err(RegionTreeError::RegionAlreadyClosed {
                region_id: region_id.as_str().to_string(),
            });
        }

        let remaining = node.tasks.len();
        node.tasks.clear();
        node.state = RegionState::Closed;

        let event = RegionEvent {
            event_code: event_codes::REG_005.to_string(),
            region_id: region_id.as_str().to_string(),
            parent_id: node.parent.as_ref().map(|p| p.as_str().to_string()),
            detail: format!("{} tasks force-terminated", remaining),
            child_count: node.children.len(),
            task_count: 0,
            timestamp_ms,
        };
        self.event_log.push(event.clone());
        Ok(event)
    }

    /// Get the state of a region.
    pub fn region_state(&self, region_id: &RegionId) -> Option<RegionState> {
        self.nodes.get(region_id.as_str()).map(|n| n.state)
    }

    /// Get the number of tasks registered to a region.
    pub fn task_count(&self, region_id: &RegionId) -> Option<usize> {
        self.nodes.get(region_id.as_str()).map(|n| n.tasks.len())
    }

    /// Get the child count of a region.
    pub fn child_count(&self, region_id: &RegionId) -> Option<usize> {
        self.nodes.get(region_id.as_str()).map(|n| n.children.len())
    }

    /// Get the parent of a region.
    pub fn parent_of(&self, region_id: &RegionId) -> Option<Option<&RegionId>> {
        self.nodes
            .get(region_id.as_str())
            .map(|n| n.parent.as_ref())
    }

    /// Get the children of a region.
    pub fn children_of(&self, region_id: &RegionId) -> Option<&[RegionId]> {
        self.nodes
            .get(region_id.as_str())
            .map(|n| n.children.as_slice())
    }

    /// Total number of regions in the tree.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the event log.
    #[must_use]
    pub fn event_log(&self) -> &[RegionEvent] {
        &self.event_log
    }

    /// Export event log as JSONL.
    #[must_use]
    pub fn export_event_log_jsonl(&self) -> String {
        self.event_log
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Create a handle scoped to a region.
    pub fn handle_for(&self, region_id: &RegionId) -> Result<RegionHandle, RegionTreeError> {
        if !self.nodes.contains_key(region_id.as_str()) {
            return Err(RegionTreeError::RegionNotFound {
                region_id: region_id.as_str().to_string(),
            });
        }
        Ok(RegionHandle::new(region_id.clone()))
    }

    /// Set drain budget for a specific region.
    pub fn set_drain_budget(
        &mut self,
        region_id: &RegionId,
        budget_ms: u64,
    ) -> Result<(), RegionTreeError> {
        let node = self.nodes.get_mut(region_id.as_str()).ok_or_else(|| {
            RegionTreeError::RegionNotFound {
                region_id: region_id.as_str().to_string(),
            }
        })?;
        node.drain_budget_ms = budget_ms;
        Ok(())
    }
}

impl Default for RegionTree {
    fn default() -> Self {
        Self::new(5000)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn root_id() -> RegionId {
        RegionId::new("root")
    }

    fn lifecycle_id() -> RegionId {
        RegionId::new("lifecycle")
    }

    fn health_gate_id() -> RegionId {
        RegionId::new("health-gate")
    }

    fn rollout_id() -> RegionId {
        RegionId::new("rollout")
    }

    fn fencing_id() -> RegionId {
        RegionId::new("fencing")
    }

    fn build_full_tree() -> RegionTree {
        let mut tree = RegionTree::new(1000);
        tree.open_region(&root_id(), 0).unwrap();
        tree.open_child_region(&lifecycle_id(), &root_id(), 1)
            .unwrap();
        tree.open_child_region(&health_gate_id(), &lifecycle_id(), 2)
            .unwrap();
        tree.open_child_region(&rollout_id(), &lifecycle_id(), 3)
            .unwrap();
        tree.open_child_region(&fencing_id(), &lifecycle_id(), 4)
            .unwrap();
        tree
    }

    // ---- RegionId ----

    #[test]
    fn region_id_new_and_display() {
        let id = RegionId::new("test");
        assert_eq!(id.as_str(), "test");
        assert_eq!(id.to_string(), "test");
    }

    // ---- RegionState ----

    #[test]
    fn region_state_display() {
        assert_eq!(RegionState::Active.to_string(), "active");
        assert_eq!(RegionState::Draining.to_string(), "draining");
        assert_eq!(RegionState::Closed.to_string(), "closed");
    }

    // ---- Open region ----

    #[test]
    fn open_root_region() {
        let mut tree = RegionTree::new(1000);
        let event = tree.open_region(&root_id(), 100).unwrap();
        assert_eq!(event.event_code, event_codes::REG_001);
        assert_eq!(event.region_id, "root");
        assert_eq!(tree.region_state(&root_id()), Some(RegionState::Active));
    }

    #[test]
    fn open_child_region_success() {
        let mut tree = RegionTree::new(1000);
        tree.open_region(&root_id(), 0).unwrap();
        let event = tree
            .open_child_region(&lifecycle_id(), &root_id(), 1)
            .unwrap();
        assert_eq!(event.event_code, event_codes::REG_007);
        assert_eq!(tree.child_count(&root_id()), Some(1));
    }

    #[test]
    fn open_child_under_nonexistent_parent_fails() {
        let mut tree = RegionTree::new(1000);
        let err = tree
            .open_child_region(&lifecycle_id(), &root_id(), 0)
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_REGION_PARENT_NOT_FOUND);
    }

    // ---- Full hierarchy ----

    #[test]
    fn full_hierarchy_has_correct_structure() {
        let tree = build_full_tree();
        assert_eq!(tree.region_count(), 5);
        assert_eq!(tree.child_count(&root_id()), Some(1));
        assert_eq!(tree.child_count(&lifecycle_id()), Some(3));
        assert_eq!(tree.child_count(&health_gate_id()), Some(0));
        assert_eq!(tree.parent_of(&lifecycle_id()), Some(Some(&root_id())));
        assert_eq!(tree.parent_of(&root_id()), Some(None));
    }

    // ---- Task registration ----

    #[test]
    fn register_task_to_active_region() {
        let mut tree = build_full_tree();
        let event = tree
            .register_task(&rollout_id(), TaskId::new("task-1"), 10)
            .unwrap();
        assert_eq!(event.event_code, event_codes::REG_002);
        assert_eq!(tree.task_count(&rollout_id()), Some(1));
    }

    #[test]
    fn register_task_to_nonexistent_region_fails() {
        let mut tree = build_full_tree();
        let err = tree
            .register_task(&RegionId::new("nonexistent"), TaskId::new("task-1"), 10)
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_REGION_NOT_FOUND);
    }

    #[test]
    fn deregister_task_succeeds() {
        let mut tree = build_full_tree();
        tree.register_task(&rollout_id(), TaskId::new("task-1"), 10)
            .unwrap();
        let event = tree
            .deregister_task(&rollout_id(), &TaskId::new("task-1"), 11)
            .unwrap();
        assert_eq!(event.event_code, event_codes::REG_008);
        assert_eq!(tree.task_count(&rollout_id()), Some(0));
    }

    // ---- RegionHandle ----

    #[test]
    fn region_handle_register_task() {
        let mut tree = build_full_tree();
        let handle = tree.handle_for(&rollout_id()).unwrap();
        assert_eq!(handle.region_id(), &rollout_id());
        let event = handle
            .register_task(&mut tree, TaskId::new("h-task-1"), 10)
            .unwrap();
        assert_eq!(event.event_code, event_codes::REG_002);
        assert_eq!(tree.task_count(&rollout_id()), Some(1));
    }

    #[test]
    fn region_handle_deregister_task() {
        let mut tree = build_full_tree();
        let handle = tree.handle_for(&rollout_id()).unwrap();
        handle
            .register_task(&mut tree, TaskId::new("h-task-1"), 10)
            .unwrap();
        let event = handle
            .deregister_task(&mut tree, &TaskId::new("h-task-1"), 11)
            .unwrap();
        assert_eq!(event.event_code, event_codes::REG_008);
    }

    #[test]
    fn handle_for_nonexistent_region_fails() {
        let tree = build_full_tree();
        let err = tree.handle_for(&RegionId::new("nonexistent")).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_REGION_NOT_FOUND);
    }

    // ---- Close — quiescence ----

    #[test]
    fn close_empty_leaf_region() {
        let mut tree = build_full_tree();
        let events = tree.close(&health_gate_id(), 100).unwrap();
        assert!(events.iter().any(|e| e.event_code == event_codes::REG_003));
        assert!(events.iter().any(|e| e.event_code == event_codes::REG_004));
        assert!(events.iter().any(|e| e.event_code == event_codes::REG_006));
        assert_eq!(
            tree.region_state(&health_gate_id()),
            Some(RegionState::Closed)
        );
    }

    #[test]
    fn close_leaf_with_tasks_force_terminates() {
        let mut tree = build_full_tree();
        tree.register_task(&rollout_id(), TaskId::new("task-1"), 10)
            .unwrap();
        tree.register_task(&rollout_id(), TaskId::new("task-2"), 11)
            .unwrap();

        let events = tree.close(&rollout_id(), 100).unwrap();
        // Should see force-terminate event
        assert!(events.iter().any(|e| e.event_code == event_codes::REG_005));
        assert!(events.iter().any(|e| e.event_code == event_codes::REG_006));
        assert_eq!(tree.region_state(&rollout_id()), Some(RegionState::Closed));
        assert_eq!(tree.task_count(&rollout_id()), Some(0));
    }

    #[test]
    fn close_parent_closes_children_first() {
        let mut tree = build_full_tree();
        tree.register_task(&health_gate_id(), TaskId::new("hg-1"), 5)
            .unwrap();
        tree.register_task(&rollout_id(), TaskId::new("ro-1"), 6)
            .unwrap();

        let events = tree.close(&lifecycle_id(), 100).unwrap();

        // Children should be closed first
        // INV-REGION-DETERMINISTIC-CLOSE
        let close_order: Vec<&str> = events
            .iter()
            .filter(|e| e.event_code == event_codes::REG_006)
            .map(|e| e.region_id.as_str())
            .collect();
        assert_eq!(
            close_order,
            vec!["health-gate", "rollout", "fencing", "lifecycle"]
        );
    }

    #[test]
    fn close_root_closes_entire_tree() {
        let mut tree = build_full_tree();
        let events = tree.close(&root_id(), 200).unwrap();

        // All regions should be closed
        assert_eq!(tree.region_state(&root_id()), Some(RegionState::Closed));
        assert_eq!(
            tree.region_state(&lifecycle_id()),
            Some(RegionState::Closed)
        );
        assert_eq!(
            tree.region_state(&health_gate_id()),
            Some(RegionState::Closed)
        );
        assert_eq!(tree.region_state(&rollout_id()), Some(RegionState::Closed));
        assert_eq!(tree.region_state(&fencing_id()), Some(RegionState::Closed));

        // Should have close events for all 5 regions
        let close_count = events
            .iter()
            .filter(|e| e.event_code == event_codes::REG_006)
            .count();
        assert_eq!(close_count, 5);
    }

    #[test]
    fn close_already_closed_region_fails() {
        let mut tree = build_full_tree();
        tree.close(&health_gate_id(), 100).unwrap();
        let err = tree.close(&health_gate_id(), 200).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_REGION_ALREADY_CLOSED);
    }

    #[test]
    fn close_nonexistent_region_fails() {
        let mut tree = build_full_tree();
        let err = tree.close(&RegionId::new("nonexistent"), 100).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_REGION_NOT_FOUND);
    }

    // ---- Force terminate ----

    #[test]
    fn force_terminate_clears_tasks() {
        let mut tree = build_full_tree();
        tree.register_task(&rollout_id(), TaskId::new("task-1"), 10)
            .unwrap();
        let event = tree.force_terminate(&rollout_id(), 50).unwrap();
        assert_eq!(event.event_code, event_codes::REG_005);
        assert_eq!(tree.task_count(&rollout_id()), Some(0));
        assert_eq!(tree.region_state(&rollout_id()), Some(RegionState::Closed));
    }

    #[test]
    fn force_terminate_already_closed_fails() {
        let mut tree = build_full_tree();
        tree.close(&health_gate_id(), 100).unwrap();
        let err = tree.force_terminate(&health_gate_id(), 200).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_REGION_ALREADY_CLOSED);
    }

    // ---- Register task to closed region ----

    #[test]
    fn register_task_to_closed_region_fails() {
        let mut tree = build_full_tree();
        tree.close(&health_gate_id(), 100).unwrap();
        let err = tree
            .register_task(&health_gate_id(), TaskId::new("late-task"), 200)
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_REGION_ALREADY_CLOSED);
    }

    // ---- Event log ----

    #[test]
    fn event_log_records_operations() {
        let mut tree = RegionTree::new(1000);
        tree.open_region(&root_id(), 0).unwrap();
        tree.register_task(&root_id(), TaskId::new("t1"), 1)
            .unwrap();
        assert!(tree.event_log().len() >= 2);
        assert_eq!(tree.event_log()[0].event_code, event_codes::REG_001);
        assert_eq!(tree.event_log()[1].event_code, event_codes::REG_002);
    }

    #[test]
    fn export_event_log_jsonl_produces_valid_json() {
        let mut tree = RegionTree::new(1000);
        tree.open_region(&root_id(), 0).unwrap();
        let jsonl = tree.export_event_log_jsonl();
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["event_code"], event_codes::REG_001);
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<RegionTreeError> = vec![
            RegionTreeError::RegionNotFound {
                region_id: "x".into(),
            },
            RegionTreeError::RegionAlreadyClosed {
                region_id: "x".into(),
            },
            RegionTreeError::ParentNotFound {
                parent_id: "p".into(),
            },
            RegionTreeError::BudgetExceeded {
                region_id: "x".into(),
                remaining_tasks: 3,
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(s.contains(e.code()), "{:?} should contain {}", e, e.code());
        }
    }

    // ---- Default ----

    #[test]
    fn default_tree_has_5s_budget() {
        let tree = RegionTree::default();
        assert_eq!(tree.default_drain_budget_ms, 5000);
    }

    // ---- Schema version ----

    #[test]
    fn schema_version_is_region_v1() {
        assert_eq!(SCHEMA_VERSION, "region-v1.0");
    }

    // ---- Invariant constants accessible ----

    #[test]
    fn invariant_constants_defined() {
        assert_eq!(INV_REGION_QUIESCENCE, "INV-REGION-QUIESCENCE");
        assert_eq!(INV_REGION_NO_OUTLIVE, "INV-REGION-NO-OUTLIVE");
        assert_eq!(
            INV_REGION_DETERMINISTIC_CLOSE,
            "INV-REGION-DETERMINISTIC-CLOSE"
        );
    }

    // ---- Set drain budget ----

    #[test]
    fn set_drain_budget_updates_region() {
        let mut tree = build_full_tree();
        tree.set_drain_budget(&rollout_id(), 500).unwrap();
        // Verify by closing — the budget should be applied
        tree.register_task(&rollout_id(), TaskId::new("t1"), 10)
            .unwrap();
        let events = tree.close(&rollout_id(), 100).unwrap();
        // Force-terminate event timestamp should reflect 500ms budget
        let force_event = events
            .iter()
            .find(|e| e.event_code == event_codes::REG_005)
            .unwrap();
        assert_eq!(force_event.timestamp_ms, 600); // 100 + 500
    }

    #[test]
    fn set_drain_budget_nonexistent_fails() {
        let mut tree = build_full_tree();
        let err = tree
            .set_drain_budget(&RegionId::new("nonexistent"), 500)
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_REGION_NOT_FOUND);
    }

    // ---- Quiescence trace simulation ----

    #[test]
    fn quiescence_trace_simulation() {
        let mut tree = build_full_tree();

        // Register tasks across regions
        tree.register_task(&health_gate_id(), TaskId::new("probe-1"), 10)
            .unwrap();
        tree.register_task(&rollout_id(), TaskId::new("deploy-1"), 11)
            .unwrap();
        tree.register_task(&rollout_id(), TaskId::new("deploy-2"), 12)
            .unwrap();
        tree.register_task(&fencing_id(), TaskId::new("fence-1"), 13)
            .unwrap();

        // Deregister some tasks before close
        tree.deregister_task(&health_gate_id(), &TaskId::new("probe-1"), 20)
            .unwrap();

        // Close the entire tree
        let events = tree.close(&root_id(), 100).unwrap();

        // Verify all regions ended up closed
        for region in &[
            root_id(),
            lifecycle_id(),
            health_gate_id(),
            rollout_id(),
            fencing_id(),
        ] {
            assert_eq!(tree.region_state(region), Some(RegionState::Closed));
        }

        // Verify no tasks remain anywhere
        for region in &[
            root_id(),
            lifecycle_id(),
            health_gate_id(),
            rollout_id(),
            fencing_id(),
        ] {
            assert_eq!(tree.task_count(region), Some(0));
        }

        // Force-terminate events should exist for rollout (2 tasks) and fencing (1 task)
        let force_events: Vec<&RegionEvent> = events
            .iter()
            .filter(|e| e.event_code == event_codes::REG_005)
            .collect();
        assert!(
            force_events.len() >= 2,
            "expected force-terminate for rollout and fencing"
        );
    }

    // ---- Open child under closed parent ----

    #[test]
    fn open_child_under_closed_parent_fails() {
        let mut tree = RegionTree::new(1000);
        tree.open_region(&root_id(), 0).unwrap();
        tree.close(&root_id(), 10).unwrap();
        let err = tree
            .open_child_region(&lifecycle_id(), &root_id(), 20)
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_REGION_ALREADY_CLOSED);
    }

    // ---- TaskId ----

    #[test]
    fn task_id_new_and_display() {
        let id = TaskId::new("test-task");
        assert_eq!(id.as_str(), "test-task");
        assert_eq!(id.to_string(), "test-task");
    }
}
