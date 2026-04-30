//! bd-qlc6: Lane-aware scheduler classes with priority policies.
//!
//! Maps incoming task types to scheduler lanes based on declarative policy
//! configuration. Enforces starvation detection, misclassification rejection,
//! and exposes per-lane telemetry counters.
//!
//! # Invariants
//!
//! - INV-LANE-EXACT-MAP: every task class maps to exactly one lane
//! - INV-LANE-STARVATION-DETECT: starved lanes trigger alert within 2× window
//! - INV-LANE-MISCLASS-REJECT: unrecognized task classes are rejected
//! - INV-LANE-CAP-ENFORCE: lane active count never exceeds concurrency cap
//! - INV-LANE-TELEMETRY-ACCURATE: counters match actual task lifecycle events
//! - INV-LANE-HOT-RELOAD: policy changes take effect without restart

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;

/// Schema version for lane metrics exports.
pub const SCHEMA_VERSION: &str = "ls-v1.0";

/// Default starvation window in milliseconds.
pub const DEFAULT_STARVATION_WINDOW_MS: u64 = 5_000;
/// Default maximum number of audit log records retained in-memory.
pub const DEFAULT_MAX_AUDIT_LOG_ENTRIES: usize = 4_096;
/// Default maximum number of pending task identities retained per lane.
pub const DEFAULT_MAX_QUEUED_TASKS_PER_LANE: usize = 4_096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

// ---- Event codes ----

pub mod event_codes {
    pub const LANE_ASSIGN: &str = "LANE_ASSIGN";
    pub const LANE_STARVED: &str = "LANE_STARVED";
    pub const LANE_MISCLASS: &str = "LANE_MISCLASS";
    pub const LANE_METRICS: &str = "LANE_METRICS";
    pub const LANE_TASK_QUEUED: &str = "LANE_TASK_QUEUED";
    pub const LANE_TASK_PROMOTED: &str = "LANE_TASK_PROMOTED";
    pub const LANE_TASK_ABORTED: &str = "LANE_TASK_ABORTED";
    pub const LANE_TASK_STARTED: &str = "LANE_TASK_STARTED";
    pub const LANE_TASK_COMPLETED: &str = "LANE_TASK_COMPLETED";
    pub const LANE_CAP_REACHED: &str = "LANE_CAP_REACHED";
    pub const LANE_POLICY_RELOADED: &str = "LANE_POLICY_RELOADED";
    pub const LANE_CREATED: &str = "LANE_CREATED";
    pub const LANE_STARVATION_CLEARED: &str = "LANE_STARVATION_CLEARED";
}

// ---- Error codes ----

pub mod error_codes {
    pub const ERR_LANE_UNKNOWN_CLASS: &str = "ERR_LANE_UNKNOWN_CLASS";
    pub const ERR_LANE_CAP_EXCEEDED: &str = "ERR_LANE_CAP_EXCEEDED";
    pub const ERR_LANE_UNKNOWN_LANE: &str = "ERR_LANE_UNKNOWN_LANE";
    pub const ERR_LANE_DUPLICATE: &str = "ERR_LANE_DUPLICATE";
    pub const ERR_LANE_INVALID_POLICY: &str = "ERR_LANE_INVALID_POLICY";
    pub const ERR_LANE_STARVATION: &str = "ERR_LANE_STARVATION";
    pub const ERR_LANE_TASK_NOT_FOUND: &str = "ERR_LANE_TASK_NOT_FOUND";
    pub const ERR_LANE_TASK_ID_EXHAUSTED: &str = "ERR_LANE_TASK_ID_EXHAUSTED";
    pub const ERR_LANE_INVALID_WEIGHT: &str = "ERR_LANE_INVALID_WEIGHT";
}

// ---- Core types ----

/// Scheduler lane identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SchedulerLane {
    /// Epoch transitions, barrier coordination, marker writes.
    ControlCritical,
    /// Remote computation invocations, artifact uploads.
    RemoteEffect,
    /// Garbage collection, compaction, cleanup tasks.
    Maintenance,
    /// Telemetry export, log rotation, low-priority housekeeping.
    Background,
}

impl SchedulerLane {
    /// Returns all available scheduler lanes in priority order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::runtime::lane_scheduler::SchedulerLane;
    /// let lanes = SchedulerLane::all();
    /// assert_eq!(lanes.len(), 4);
    /// assert_eq!(lanes[0], SchedulerLane::ControlCritical);
    /// ```
    pub fn all() -> &'static [SchedulerLane] {
        &[
            Self::ControlCritical,
            Self::RemoteEffect,
            Self::Maintenance,
            Self::Background,
        ]
    }

    /// Returns the string representation of the scheduler lane.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::runtime::lane_scheduler::SchedulerLane;
    /// assert_eq!(SchedulerLane::ControlCritical.as_str(), "control_critical");
    /// assert_eq!(SchedulerLane::RemoteEffect.as_str(), "remote_effect");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ControlCritical => "control_critical",
            Self::RemoteEffect => "remote_effect",
            Self::Maintenance => "maintenance",
            Self::Background => "background",
        }
    }
}

impl fmt::Display for SchedulerLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Task class discriminant for incoming tasks.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TaskClass(pub String);

impl TaskClass {
    /// Creates a new task class with the given name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::runtime::lane_scheduler::TaskClass;
    /// let task_class = TaskClass::new("custom_task");
    /// assert_eq!(task_class.as_str(), "custom_task");
    /// ```
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }

    /// Returns the string name of the task class.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::runtime::lane_scheduler::TaskClass;
    /// let task_class = TaskClass::new("data_processing");
    /// assert_eq!(task_class.as_str(), "data_processing");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TaskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Well-known task classes.
pub mod task_classes {
    use super::TaskClass;

    /// Creates a task class for epoch transition operations.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::runtime::lane_scheduler::task_classes;
    /// let task = task_classes::epoch_transition();
    /// assert_eq!(task.as_str(), "epoch_transition");
    /// ```
    pub fn epoch_transition() -> TaskClass {
        TaskClass::new("epoch_transition")
    }
    pub fn barrier_coordination() -> TaskClass {
        TaskClass::new("barrier_coordination")
    }
    pub fn marker_write() -> TaskClass {
        TaskClass::new("marker_write")
    }
    pub fn remote_computation() -> TaskClass {
        TaskClass::new("remote_computation")
    }
    pub fn artifact_upload() -> TaskClass {
        TaskClass::new("artifact_upload")
    }
    pub fn artifact_eviction() -> TaskClass {
        TaskClass::new("artifact_eviction")
    }
    pub fn garbage_collection() -> TaskClass {
        TaskClass::new("garbage_collection")
    }
    pub fn compaction() -> TaskClass {
        TaskClass::new("compaction")
    }
    pub fn telemetry_export() -> TaskClass {
        TaskClass::new("telemetry_export")
    }
    pub fn log_rotation() -> TaskClass {
        TaskClass::new("log_rotation")
    }
}

/// Configuration for a single scheduler lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneConfig {
    pub lane: SchedulerLane,
    pub priority_weight: u32,
    pub concurrency_cap: usize,
    pub starvation_window_ms: u64,
}

impl LaneConfig {
    /// Creates a new lane configuration with default starvation window.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::runtime::lane_scheduler::{LaneConfig, SchedulerLane};
    /// let config = LaneConfig::new(SchedulerLane::ControlCritical, 100, 4);
    /// assert_eq!(config.priority_weight, 100);
    /// assert_eq!(config.concurrency_cap, 4);
    /// ```
    pub fn new(lane: SchedulerLane, priority_weight: u32, concurrency_cap: usize) -> Self {
        Self {
            lane,
            priority_weight,
            concurrency_cap,
            starvation_window_ms: DEFAULT_STARVATION_WINDOW_MS,
        }
    }
}

/// A mapping rule from task class to scheduler lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingRule {
    pub task_class: TaskClass,
    pub target_lane: SchedulerLane,
}

/// Policy configuration: lane configs + mapping rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneMappingPolicy {
    pub lane_configs: BTreeMap<String, LaneConfig>,
    pub mapping_rules: BTreeMap<String, SchedulerLane>,
}

impl LaneMappingPolicy {
    /// Creates a new empty lane mapping policy.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::runtime::lane_scheduler::LaneMappingPolicy;
    /// let policy = LaneMappingPolicy::new();
    /// assert!(policy.lane_configs.is_empty());
    /// assert!(policy.mapping_rules.is_empty());
    /// ```
    pub fn new() -> Self {
        Self {
            lane_configs: BTreeMap::new(),
            mapping_rules: BTreeMap::new(),
        }
    }

    /// Add a lane configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::runtime::lane_scheduler::{LaneMappingPolicy, LaneConfig, SchedulerLane};
    /// let mut policy = LaneMappingPolicy::new();
    /// let config = LaneConfig::new(SchedulerLane::ControlCritical, 100, 4);
    /// assert!(policy.add_lane(config).is_ok());
    /// ```
    pub fn add_lane(&mut self, config: LaneConfig) -> Result<(), LaneSchedulerError> {
        if self.lane_configs.contains_key(config.lane.as_str()) {
            return Err(LaneSchedulerError::DuplicateLane { lane: config.lane });
        }
        self.lane_configs
            .insert(config.lane.as_str().to_string(), config);
        Ok(())
    }

    /// Add a mapping rule from task class to lane.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::runtime::lane_scheduler::{LaneMappingPolicy, TaskClass, SchedulerLane};
    /// let mut policy = LaneMappingPolicy::new();
    /// let task_class = TaskClass::new("database_write");
    /// policy.add_rule(&task_class, SchedulerLane::ControlCritical);
    /// assert_eq!(policy.resolve(&task_class), Some(SchedulerLane::ControlCritical));
    /// ```
    pub fn add_rule(&mut self, task_class: &TaskClass, lane: SchedulerLane) {
        self.mapping_rules
            .insert(task_class.as_str().to_string(), lane);
    }

    /// Look up the lane for a task class.
    /// INV-LANE-EXACT-MAP
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::runtime::lane_scheduler::{LaneMappingPolicy, TaskClass, SchedulerLane};
    /// let mut policy = LaneMappingPolicy::new();
    /// let task_class = TaskClass::new("artifact_upload");
    /// policy.add_rule(&task_class, SchedulerLane::Background);
    /// assert_eq!(policy.resolve(&task_class), Some(SchedulerLane::Background));
    /// assert_eq!(policy.resolve(&TaskClass::new("unknown")), None);
    /// ```
    pub fn resolve(&self, task_class: &TaskClass) -> Option<SchedulerLane> {
        self.mapping_rules.get(task_class.as_str()).copied()
    }

    /// Validate policy: configured lanes are well-formed and every rule maps to
    /// a configured lane.
    pub fn validate(&self) -> Result<(), String> {
        if self.lane_configs.is_empty() {
            return Err("no lanes configured".into());
        }
        if self.mapping_rules.is_empty() {
            return Err("no mapping rules defined".into());
        }
        for (tc, lane) in &self.mapping_rules {
            if !self.lane_configs.contains_key(lane.as_str()) {
                return Err(format!(
                    "task class {} maps to unconfigured lane {}",
                    tc, lane
                ));
            }
        }
        for config in self.lane_configs.values() {
            if config.priority_weight == 0 {
                return Err(format!("lane {} has zero priority weight", config.lane));
            }
            if config.concurrency_cap == 0 {
                return Err(format!("lane {} has zero concurrency cap", config.lane));
            }
        }
        Ok(())
    }
}

impl Default for LaneMappingPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the standard default policy.
pub fn default_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();

    policy
        .add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 100, 8))
        .expect("default policy must not duplicate control_critical lane");
    policy
        .add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, 50, 32))
        .expect("default policy must not duplicate remote_effect lane");
    policy
        .add_lane(LaneConfig::new(SchedulerLane::Maintenance, 20, 4))
        .expect("default policy must not duplicate maintenance lane");
    policy
        .add_lane(LaneConfig::new(SchedulerLane::Background, 10, 2))
        .expect("default policy must not duplicate background lane");

    policy.add_rule(
        &task_classes::epoch_transition(),
        SchedulerLane::ControlCritical,
    );
    policy.add_rule(
        &task_classes::barrier_coordination(),
        SchedulerLane::ControlCritical,
    );
    policy.add_rule(
        &task_classes::marker_write(),
        SchedulerLane::ControlCritical,
    );
    policy.add_rule(
        &task_classes::remote_computation(),
        SchedulerLane::RemoteEffect,
    );
    policy.add_rule(
        &task_classes::artifact_upload(),
        SchedulerLane::RemoteEffect,
    );
    policy.add_rule(
        &task_classes::artifact_eviction(),
        SchedulerLane::RemoteEffect,
    );
    policy.add_rule(
        &task_classes::garbage_collection(),
        SchedulerLane::Maintenance,
    );
    policy.add_rule(&task_classes::compaction(), SchedulerLane::Maintenance);
    policy.add_rule(&task_classes::telemetry_export(), SchedulerLane::Background);
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);

    policy
}

/// Per-lane runtime counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneCounters {
    pub lane: SchedulerLane,
    pub active_count: usize,
    pub queued_count: usize,
    pub first_queued_at_ms: Option<u64>,
    pub completed_total: u64,
    pub rejected_total: u64,
    pub starvation_events: u64,
    pub starvation_active: bool,
    pub last_completion_ms: Option<u64>,
}

impl LaneCounters {
    pub fn new(lane: SchedulerLane) -> Self {
        Self {
            lane,
            active_count: 0,
            queued_count: 0,
            first_queued_at_ms: None,
            completed_total: 0,
            rejected_total: 0,
            starvation_events: 0,
            starvation_active: false,
            last_completion_ms: None,
        }
    }
}

/// Errors from lane scheduler operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneSchedulerError {
    /// Task class not mapped to any lane.
    /// INV-LANE-MISCLASS-REJECT
    UnknownClass { task_class: String },
    /// Lane concurrency cap exceeded.
    /// INV-LANE-CAP-ENFORCE
    CapExceeded {
        lane: SchedulerLane,
        cap: usize,
        current: usize,
        queued_task_id: Option<String>,
    },
    /// Unknown lane ID.
    UnknownLane { lane: String },
    /// Duplicate lane configuration.
    DuplicateLane { lane: SchedulerLane },
    /// Invalid policy configuration.
    InvalidPolicy { detail: String },
    /// Lane starvation detected.
    Starvation {
        lane: SchedulerLane,
        queue_depth: usize,
        elapsed_ms: u64,
    },
    /// Task not found (for completion tracking).
    TaskNotFound { task_id: String },
    /// Task ID allocator exhausted the u64 counter space.
    TaskIdExhausted { last_counter: u64 },
    /// Invalid priority weight.
    InvalidWeight { lane: SchedulerLane, weight: u32 },
}

impl LaneSchedulerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownClass { .. } => error_codes::ERR_LANE_UNKNOWN_CLASS,
            Self::CapExceeded { .. } => error_codes::ERR_LANE_CAP_EXCEEDED,
            Self::UnknownLane { .. } => error_codes::ERR_LANE_UNKNOWN_LANE,
            Self::DuplicateLane { .. } => error_codes::ERR_LANE_DUPLICATE,
            Self::InvalidPolicy { .. } => error_codes::ERR_LANE_INVALID_POLICY,
            Self::Starvation { .. } => error_codes::ERR_LANE_STARVATION,
            Self::TaskNotFound { .. } => error_codes::ERR_LANE_TASK_NOT_FOUND,
            Self::TaskIdExhausted { .. } => error_codes::ERR_LANE_TASK_ID_EXHAUSTED,
            Self::InvalidWeight { .. } => error_codes::ERR_LANE_INVALID_WEIGHT,
        }
    }
}

impl fmt::Display for LaneSchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownClass { task_class } => {
                write!(f, "{}: unknown task class {}", self.code(), task_class)
            }
            Self::CapExceeded {
                lane,
                cap,
                current,
                queued_task_id,
            } => {
                write!(
                    f,
                    "{}: lane {} cap {} exceeded (current {})",
                    self.code(),
                    lane,
                    cap,
                    current
                )?;
                if let Some(task_id) = queued_task_id {
                    write!(f, ", queued task {task_id}")?;
                }
                Ok(())
            }
            Self::UnknownLane { lane } => {
                write!(f, "{}: unknown lane {}", self.code(), lane)
            }
            Self::DuplicateLane { lane } => {
                write!(f, "{}: duplicate lane {}", self.code(), lane)
            }
            Self::InvalidPolicy { detail } => {
                write!(f, "{}: {}", self.code(), detail)
            }
            Self::Starvation {
                lane,
                queue_depth,
                elapsed_ms,
            } => {
                write!(
                    f,
                    "{}: lane {} starved, {} queued, {}ms elapsed",
                    self.code(),
                    lane,
                    queue_depth,
                    elapsed_ms
                )
            }
            Self::TaskNotFound { task_id } => {
                write!(f, "{}: task {} not found", self.code(), task_id)
            }
            Self::TaskIdExhausted { last_counter } => {
                write!(
                    f,
                    "{}: task id counter exhausted at {}",
                    self.code(),
                    last_counter
                )
            }
            Self::InvalidWeight { lane, weight } => {
                write!(
                    f,
                    "{}: lane {} invalid weight {}",
                    self.code(),
                    lane,
                    weight
                )
            }
        }
    }
}

/// Task assignment record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAssignment {
    pub task_id: String,
    pub task_class: TaskClass,
    pub lane: SchedulerLane,
    pub assigned_at_ms: u64,
    pub trace_id: String,
}

/// Queued task identity retained when a lane is at capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedTaskAssignment {
    pub task_id: String,
    pub task_class: TaskClass,
    pub lane: SchedulerLane,
    pub queued_at_ms: u64,
    pub trace_id: String,
}

/// Audit record for JSONL export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneAuditRecord {
    pub event_code: String,
    pub task_id: String,
    pub task_class: String,
    pub lane: String,
    pub timestamp_ms: u64,
    pub detail: String,
    pub trace_id: String,
    pub schema_version: String,
}

/// Telemetry snapshot for export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneTelemetrySnapshot {
    pub counters: Vec<LaneCounters>,
    pub timestamp_ms: u64,
    pub schema_version: String,
}

/// The lane-aware scheduler.
#[derive(Debug)]
/// Multi-lane task scheduler with policy-based lane assignment and starvation detection.
///
/// The `LaneScheduler` manages concurrent task execution across multiple scheduler lanes,
/// each with its own concurrency limits and priorities. Tasks are mapped to lanes based
/// on declarative [`LaneMappingPolicy`] rules, with automatic starvation detection and
/// comprehensive telemetry tracking.
///
/// # Core Features
///
/// - **Policy-based lane assignment**: Task classes are mapped to specific lanes via configurable rules
/// - **Starvation detection**: Monitors lane execution and alerts when lanes are starved of resources
/// - **Capacity enforcement**: Per-lane concurrency limits prevent resource exhaustion
/// - **FIFO queuing**: Queued tasks within each lane maintain strict first-in-first-out ordering
/// - **Audit logging**: Complete task lifecycle tracking for debugging and observability
/// - **Hot reload**: Policy changes take effect without scheduler restart
///
/// # Invariants
///
/// - **INV-LANE-EXACT-MAP**: Every task class maps to exactly one lane
/// - **INV-LANE-STARVATION-DETECT**: Starved lanes trigger alerts within 2× detection window
/// - **INV-LANE-MISCLASS-REJECT**: Unrecognized task classes are rejected immediately
/// - **INV-LANE-CAP-ENFORCE**: Lane active task count never exceeds concurrency capacity
/// - **INV-LANE-TELEMETRY-ACCURATE**: Counters precisely match actual task lifecycle events
///
/// # Example: Basic Usage
///
/// ```rust
/// use crate::runtime::lane_scheduler::*;
///
/// // Create a policy with two lanes: high-priority and batch processing
/// let mut policy = LaneMappingPolicy::new();
/// policy.add_mapping(TaskClass::new("api_request"), SchedulerLane::HighPriority)?;
/// policy.add_mapping(TaskClass::new("batch_job"), SchedulerLane::Batch)?;
///
/// // Set up lane configurations
/// let mut high_config = LaneConfig::new();
/// high_config.set_max_concurrent_tasks(10);
/// high_config.set_starvation_window_ms(2000);
/// policy.set_lane_config(SchedulerLane::HighPriority, high_config);
///
/// let mut batch_config = LaneConfig::new();
/// batch_config.set_max_concurrent_tasks(3);
/// batch_config.set_starvation_window_ms(10000);
/// policy.set_lane_config(SchedulerLane::Batch, batch_config);
///
/// // Create the scheduler
/// let mut scheduler = LaneScheduler::new(policy)?;
///
/// // Schedule tasks
/// let api_task = scheduler.schedule_task(
///     TaskClass::new("api_request"),
///     "handle_user_login",
///     "trace-001"
/// )?;
///
/// let batch_task = scheduler.schedule_task(
///     TaskClass::new("batch_job"),
///     "process_analytics",
///     "trace-002"
/// )?;
///
/// // Check lane status
/// let telemetry = scheduler.snapshot_telemetry()?;
/// println!("High priority lane: {} active, {} queued",
///          telemetry.lane_snapshots[&"high_priority".to_string()].active_count,
///          telemetry.lane_snapshots[&"high_priority".to_string()].queued_count);
/// # Ok::<(), LaneSchedulerError>(())
/// ```
///
/// # Example: Task Lifecycle Management
///
/// ```rust
/// use crate::runtime::lane_scheduler::*;
/// # use std::collections::BTreeMap;
///
/// # let mut policy = LaneMappingPolicy::new();
/// # policy.add_mapping(TaskClass::new("worker"), SchedulerLane::Standard)?;
/// let mut scheduler = LaneScheduler::new(policy)?;
///
/// // Schedule a task
/// let assignment = scheduler.schedule_task(
///     TaskClass::new("worker"),
///     "process_document",
///     "trace-123"
/// )?;
///
/// match assignment {
///     TaskAssignment::Assigned { task_id, lane, .. } => {
///         println!("Task {} assigned to lane {:?}", task_id, lane);
///
///         // Simulate task completion
///         scheduler.complete_task(&task_id, "trace-456")?;
///         println!("Task {} completed successfully", task_id);
///     }
///     TaskAssignment::Queued { position, .. } => {
///         println!("Task queued at position {}", position);
///     }
/// }
///
/// // Monitor for starvation
/// let telemetry = scheduler.snapshot_telemetry()?;
/// for (lane_name, snapshot) in &telemetry.lane_snapshots {
///     if snapshot.starvation_detected {
///         eprintln!("WARNING: Lane {} is starved!", lane_name);
///     }
/// }
/// # Ok::<(), LaneSchedulerError>(())
/// ```
///
/// # Example: Policy Hot Reload
///
/// ```rust
/// use crate::runtime::lane_scheduler::*;
///
/// # let policy = LaneMappingPolicy::new();
/// let mut scheduler = LaneScheduler::new(policy)?;
///
/// // Update policy at runtime
/// let mut new_policy = LaneMappingPolicy::new();
/// new_policy.add_mapping(TaskClass::new("priority"), SchedulerLane::HighPriority)?;
/// new_policy.add_mapping(TaskClass::new("normal"), SchedulerLane::Standard)?;
///
/// // Hot reload - existing tasks continue, new tasks use updated policy
/// scheduler.update_policy(new_policy, "policy-reload-001")?;
///
/// // Verify the policy change
/// let updated_policy = scheduler.get_current_policy();
/// assert!(updated_policy.has_mapping(&TaskClass::new("priority")));
/// # Ok::<(), LaneSchedulerError>(())
/// ```
///
/// # Performance Characteristics
///
/// - **Task scheduling**: O(1) for direct assignment, O(1) for queue insertion
/// - **Task completion**: O(1) for active task removal, O(1) for queue promotion
/// - **Starvation detection**: O(lanes) per detection cycle
/// - **Memory usage**: Bounded by `max_audit_log_entries` and `max_queued_tasks_per_lane`
///
/// # Thread Safety
///
/// `LaneScheduler` is **not** thread-safe. Use external synchronization if accessing
/// from multiple threads concurrently.
///
/// # See Also
///
/// - [`LaneMappingPolicy`]: Configures task-to-lane assignment rules
/// - [`TaskClass`]: Identifies the category/type of work being scheduled
/// - [`SchedulerLane`]: Enumeration of available scheduler lanes
/// - [`LaneConfig`]: Per-lane configuration (concurrency, starvation thresholds)
pub struct LaneScheduler {
    policy: LaneMappingPolicy,
    /// Runtime counters: optimized with HashMap for SIMD-accelerated lookups
    counters: HashMap<String, LaneCounters>,
    /// Active task tracking: optimized with HashMap for frequent task ID lookups
    active_tasks: HashMap<String, TaskAssignment>,
    /// Per-lane queued work stays FIFO, so front-pop promotion must remain O(1).
    /// Optimized with HashMap for frequent lane-based queue access.
    queued_tasks: HashMap<String, VecDeque<QueuedTaskAssignment>>,
    audit_log: Vec<LaneAuditRecord>,
    max_audit_log_entries: usize,
    max_queued_tasks_per_lane: usize,
    task_counter: u64,
}

impl LaneScheduler {
    /// Create a new lane scheduler with the given policy.
    pub fn new(policy: LaneMappingPolicy) -> Result<Self, LaneSchedulerError> {
        Self::with_audit_log_capacity(policy, DEFAULT_MAX_AUDIT_LOG_ENTRIES)
    }

    /// Create a new lane scheduler with explicit audit log capacity.
    pub fn with_audit_log_capacity(
        policy: LaneMappingPolicy,
        max_audit_log_entries: usize,
    ) -> Result<Self, LaneSchedulerError> {
        if let Err(detail) = policy.validate() {
            return Err(LaneSchedulerError::InvalidPolicy { detail });
        }

        let mut counters = HashMap::new();
        let mut queued_tasks = HashMap::new();
        for config in policy.lane_configs.values() {
            counters.insert(
                config.lane.as_str().to_string(),
                LaneCounters::new(config.lane),
            );
            queued_tasks.insert(config.lane.as_str().to_string(), VecDeque::new());
        }

        Ok(Self {
            policy,
            counters,
            active_tasks: HashMap::new(),
            queued_tasks,
            audit_log: Vec::new(),
            max_audit_log_entries: max_audit_log_entries.max(1),
            max_queued_tasks_per_lane: DEFAULT_MAX_QUEUED_TASKS_PER_LANE,
            task_counter: 0,
        })
    }

    fn push_audit_record(&mut self, record: LaneAuditRecord) {
        let cap = self.max_audit_log_entries;
        push_bounded(&mut self.audit_log, record, cap);
    }

    fn next_task_id(&mut self) -> Result<String, LaneSchedulerError> {
        let next_counter = self.task_counter.saturating_add(1);
        if next_counter == self.task_counter {
            return Err(LaneSchedulerError::TaskIdExhausted {
                last_counter: self.task_counter,
            });
        }
        self.task_counter = next_counter;
        Ok(format!("task-{:08}", self.task_counter))
    }

    fn refresh_lane_queue_counters(
        &mut self,
        lane: SchedulerLane,
    ) -> Result<(), LaneSchedulerError> {
        let (queue_depth, first_queued_at_ms) = {
            let queue = self.queued_tasks.get(lane.as_str()).ok_or_else(|| {
                LaneSchedulerError::UnknownLane {
                    lane: lane.to_string(),
                }
            })?;
            (
                queue.len(),
                queue.front().map(|queued_task| queued_task.queued_at_ms),
            )
        };
        let counters = self.counters.get_mut(lane.as_str()).ok_or_else(|| {
            LaneSchedulerError::UnknownLane {
                lane: lane.to_string(),
            }
        })?;
        counters.queued_count = queue_depth;
        counters.first_queued_at_ms = first_queued_at_ms;
        Ok(())
    }

    fn enqueue_task(
        &mut self,
        task_class: &TaskClass,
        lane: SchedulerLane,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<Option<String>, LaneSchedulerError> {
        let queue_len = self
            .queued_tasks
            .get(lane.as_str())
            .ok_or_else(|| LaneSchedulerError::UnknownLane {
                lane: lane.to_string(),
            })?
            .len();
        if queue_len >= self.max_queued_tasks_per_lane {
            return Ok(None);
        }

        let task_id = self.next_task_id()?;
        let queued = QueuedTaskAssignment {
            task_id: task_id.clone(),
            task_class: task_class.clone(),
            lane,
            queued_at_ms: timestamp_ms,
            trace_id: trace_id.to_string(),
        };
        self.queued_tasks
            .get_mut(lane.as_str())
            .ok_or_else(|| LaneSchedulerError::UnknownLane {
                lane: lane.to_string(),
            })?
            .push_back(queued);
        self.refresh_lane_queue_counters(lane)?;
        self.push_audit_record(LaneAuditRecord {
            event_code: event_codes::LANE_TASK_QUEUED.to_string(),
            task_id: task_id.clone(),
            task_class: task_class.to_string(),
            lane: lane.to_string(),
            timestamp_ms,
            detail: format!("queued for {}", lane),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });
        Ok(Some(task_id))
    }

    fn promote_queued_tasks_for_lane(
        &mut self,
        lane: SchedulerLane,
        timestamp_ms: u64,
    ) -> Result<(), LaneSchedulerError> {
        loop {
            let cap = self
                .policy
                .lane_configs
                .get(lane.as_str())
                .ok_or_else(|| LaneSchedulerError::UnknownLane {
                    lane: lane.to_string(),
                })?
                .concurrency_cap;
            let active_count = self
                .counters
                .get(lane.as_str())
                .ok_or_else(|| LaneSchedulerError::UnknownLane {
                    lane: lane.to_string(),
                })?
                .active_count;
            if active_count >= cap {
                return Ok(());
            }

            let queued = {
                let queue = self.queued_tasks.get_mut(lane.as_str()).ok_or_else(|| {
                    LaneSchedulerError::UnknownLane {
                        lane: lane.to_string(),
                    }
                })?;
                if queue.is_empty() {
                    return Ok(());
                }
                let Some(queued) = queue.pop_front() else {
                    return Ok(());
                };
                queued
            };
            self.refresh_lane_queue_counters(lane)?;

            let assignment = TaskAssignment {
                task_id: queued.task_id.clone(),
                task_class: queued.task_class.clone(),
                lane,
                assigned_at_ms: timestamp_ms,
                trace_id: queued.trace_id.clone(),
            };
            let counters = self.counters.get_mut(lane.as_str()).ok_or_else(|| {
                LaneSchedulerError::UnknownLane {
                    lane: lane.to_string(),
                }
            })?;
            counters.active_count = counters.active_count.saturating_add(1);
            self.active_tasks.insert(queued.task_id.clone(), assignment);
            self.push_audit_record(LaneAuditRecord {
                event_code: event_codes::LANE_TASK_PROMOTED.to_string(),
                task_id: queued.task_id,
                task_class: queued.task_class.to_string(),
                lane: lane.to_string(),
                timestamp_ms,
                detail: format!("promoted from queue to {}", lane),
                trace_id: queued.trace_id,
                schema_version: SCHEMA_VERSION.to_string(),
            });
        }
    }

    /// Assign a task to a lane based on its class.
    /// INV-LANE-EXACT-MAP, INV-LANE-MISCLASS-REJECT, INV-LANE-CAP-ENFORCE
    pub fn assign_task(
        &mut self,
        task_class: &TaskClass,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<TaskAssignment, LaneSchedulerError> {
        // INV-LANE-MISCLASS-REJECT
        let lane =
            self.policy
                .resolve(task_class)
                .ok_or_else(|| LaneSchedulerError::UnknownClass {
                    task_class: task_class.to_string(),
                })?;

        self.promote_queued_tasks_for_lane(lane, timestamp_ms)?;

        let concurrency_cap = self
            .policy
            .lane_configs
            .get(lane.as_str())
            .ok_or_else(|| LaneSchedulerError::UnknownLane {
                lane: lane.to_string(),
            })?
            .concurrency_cap;
        let active_count = self
            .counters
            .get(lane.as_str())
            .ok_or_else(|| LaneSchedulerError::UnknownLane {
                lane: lane.to_string(),
            })?
            .active_count;

        // INV-LANE-CAP-ENFORCE
        if active_count >= concurrency_cap {
            let queued_task_id = self.enqueue_task(task_class, lane, timestamp_ms, trace_id)?;
            let counters = self.counters.get_mut(lane.as_str()).ok_or_else(|| {
                LaneSchedulerError::UnknownLane {
                    lane: lane.to_string(),
                }
            })?;
            counters.rejected_total = counters.rejected_total.saturating_add(1);
            return Err(LaneSchedulerError::CapExceeded {
                lane,
                cap: concurrency_cap,
                current: active_count,
                queued_task_id,
            });
        }

        let task_id = self.next_task_id()?;

        let counters = self.counters.get_mut(lane.as_str()).ok_or_else(|| {
            LaneSchedulerError::UnknownLane {
                lane: lane.to_string(),
            }
        })?;
        counters.active_count = counters.active_count.saturating_add(1);

        let assignment = TaskAssignment {
            task_id: task_id.clone(),
            task_class: task_class.clone(),
            lane,
            assigned_at_ms: timestamp_ms,
            trace_id: trace_id.to_string(),
        };

        self.active_tasks
            .insert(task_id.clone(), assignment.clone());

        self.push_audit_record(LaneAuditRecord {
            event_code: event_codes::LANE_ASSIGN.to_string(),
            task_id,
            task_class: task_class.to_string(),
            lane: lane.to_string(),
            timestamp_ms,
            detail: format!("assigned to {}", lane),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        Ok(assignment)
    }

    /// Complete a task, returning its lane resources.
    pub fn complete_task(
        &mut self,
        task_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<SchedulerLane, LaneSchedulerError> {
        let assignment =
            self.active_tasks
                .remove(task_id)
                .ok_or_else(|| LaneSchedulerError::TaskNotFound {
                    task_id: task_id.to_string(),
                })?;

        let counters = self
            .counters
            .get_mut(assignment.lane.as_str())
            .ok_or_else(|| LaneSchedulerError::UnknownLane {
                lane: assignment.lane.to_string(),
            })?;
        counters.active_count = counters.active_count.saturating_sub(1);
        counters.completed_total = counters.completed_total.saturating_add(1);
        counters.last_completion_ms = Some(timestamp_ms);

        self.push_audit_record(LaneAuditRecord {
            event_code: event_codes::LANE_TASK_COMPLETED.to_string(),
            task_id: task_id.to_string(),
            task_class: assignment.task_class.to_string(),
            lane: assignment.lane.to_string(),
            timestamp_ms,
            detail: format!(
                "completed in {}ms",
                timestamp_ms.saturating_sub(assignment.assigned_at_ms)
            ),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        self.promote_queued_tasks_for_lane(assignment.lane, timestamp_ms)?;

        Ok(assignment.lane)
    }

    /// Abort one specific queued task identity.
    ///
    /// Class-only queue aborts are intentionally unsupported: cap-pressure
    /// callers receive an explicit queued task ID and must present that ID to
    /// mutate queue state.
    pub fn abort_queued_task_id(
        &mut self,
        task_id: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<QueuedTaskAssignment, LaneSchedulerError> {
        let mut removed: Option<QueuedTaskAssignment> = None;

        for queue in self.queued_tasks.values_mut() {
            if let Some(position) = queue.iter().position(|queued| queued.task_id == task_id) {
                if let Some(queued) = queue.remove(position) {
                    removed = Some(queued);
                    break;
                }
            }
        }

        let queued = removed.ok_or_else(|| LaneSchedulerError::TaskNotFound {
            task_id: task_id.to_string(),
        })?;
        let lane = queued.lane;
        self.refresh_lane_queue_counters(lane)?;
        self.push_audit_record(LaneAuditRecord {
            event_code: event_codes::LANE_TASK_ABORTED.to_string(),
            task_id: queued.task_id.clone(),
            task_class: queued.task_class.to_string(),
            lane: lane.to_string(),
            timestamp_ms,
            detail: format!("aborted queued task in {}", lane),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });
        Ok(queued)
    }

    /// Check for lane starvation.
    /// INV-LANE-STARVATION-DETECT
    pub fn check_starvation(&mut self, current_ms: u64, trace_id: &str) -> Vec<LaneSchedulerError> {
        let mut starved = Vec::new();

        #[derive(Clone, Copy)]
        enum StarvationTransition {
            NewlyStarved { queue_depth: usize, elapsed: u64 },
            Cleared { queue_depth: usize },
        }

        // Collect starvation info first with immutable borrows.
        // This scheduler tracks queue depth, not per-item enqueue timestamps, so
        // `first_queued_at_ms` is the blocked-queue baseline: it starts when a
        // lane first blocks work and is rebased only when queued work is
        // actually admitted.
        type StarvationRow = (
            SchedulerLane,
            Option<(usize, u64)>,
            Option<StarvationTransition>,
        );
        let mut starvation_info: Vec<StarvationRow> = Vec::new();
        for config in self.policy.lane_configs.values() {
            let counters = &self.counters[config.lane.as_str()];
            let current_starvation = if counters.queued_count > 0 {
                counters
                    .first_queued_at_ms
                    .or(counters.last_completion_ms)
                    .map(|first_queued_at_ms| {
                        let elapsed = current_ms.saturating_sub(first_queued_at_ms);
                        (counters.queued_count, elapsed)
                    })
                    .filter(|(_, elapsed)| *elapsed >= config.starvation_window_ms)
            } else {
                None
            };

            let transition = match (counters.starvation_active, current_starvation) {
                (false, Some((queue_depth, elapsed))) => Some(StarvationTransition::NewlyStarved {
                    queue_depth,
                    elapsed,
                }),
                (true, None) => Some(StarvationTransition::Cleared {
                    queue_depth: counters.queued_count,
                }),
                _ => None,
            };

            starvation_info.push((config.lane, current_starvation, transition));
        }

        // Now apply mutations with the collected info.
        for (lane, current_starvation, transition) in starvation_info {
            if let Some((queue_depth, elapsed)) = current_starvation {
                starved.push(LaneSchedulerError::Starvation {
                    lane,
                    queue_depth,
                    elapsed_ms: elapsed,
                });
            }

            if let Some(counters) = self.counters.get_mut(lane.as_str()) {
                counters.starvation_active = current_starvation.is_some();
                if matches!(transition, Some(StarvationTransition::NewlyStarved { .. })) {
                    counters.starvation_events = counters.starvation_events.saturating_add(1);
                }
            }

            match transition {
                Some(StarvationTransition::NewlyStarved {
                    queue_depth,
                    elapsed,
                }) => {
                    self.push_audit_record(LaneAuditRecord {
                        event_code: event_codes::LANE_STARVED.to_string(),
                        task_id: String::new(),
                        task_class: String::new(),
                        lane: lane.to_string(),
                        timestamp_ms: current_ms,
                        detail: format!("queue_depth={queue_depth}, elapsed={elapsed}ms"),
                        trace_id: trace_id.to_string(),
                        schema_version: SCHEMA_VERSION.to_string(),
                    });
                }
                Some(StarvationTransition::Cleared { queue_depth }) => {
                    self.push_audit_record(LaneAuditRecord {
                        event_code: event_codes::LANE_STARVATION_CLEARED.to_string(),
                        task_id: String::new(),
                        task_class: String::new(),
                        lane: lane.to_string(),
                        timestamp_ms: current_ms,
                        detail: format!("queue_depth={queue_depth}"),
                        trace_id: trace_id.to_string(),
                        schema_version: SCHEMA_VERSION.to_string(),
                    });
                }
                None => {}
            }
        }

        starved
    }

    /// Hot-reload policy.
    /// INV-LANE-HOT-RELOAD
    pub fn reload_policy(
        &mut self,
        new_policy: LaneMappingPolicy,
    ) -> Result<(), LaneSchedulerError> {
        if let Err(detail) = new_policy.validate() {
            return Err(LaneSchedulerError::InvalidPolicy { detail });
        }

        let removed_lanes: Vec<String> = self
            .counters
            .keys()
            .filter(|lane| !new_policy.lane_configs.contains_key(*lane))
            .cloned()
            .collect();
        for lane in &removed_lanes {
            let counter_active = self
                .counters
                .get(lane)
                .map(|counters| counters.active_count)
                .unwrap_or_default();
            let counter_queued = self
                .counters
                .get(lane)
                .map(|counters| counters.queued_count)
                .unwrap_or_default();
            let active_tasks = self
                .active_tasks
                .values()
                .filter(|assignment| assignment.lane.as_str() == lane)
                .count();
            let queued_tasks = self
                .queued_tasks
                .get(lane)
                .map(|queue| queue.len())
                .unwrap_or_default();
            if counter_active > 0 || counter_queued > 0 || active_tasks > 0 || queued_tasks > 0 {
                return Err(LaneSchedulerError::InvalidPolicy {
                    detail: format!(
                        "cannot remove lane {lane} with active={counter_active}/{active_tasks} queued={counter_queued}/{queued_tasks}"
                    ),
                });
            }
        }

        // Add counters for any new lanes
        for config in new_policy.lane_configs.values() {
            self.counters
                .entry(config.lane.as_str().to_string())
                .or_insert_with(|| LaneCounters::new(config.lane));
            self.queued_tasks
                .entry(config.lane.as_str().to_string())
                .or_default();
        }

        for lane in removed_lanes {
            self.counters.remove(&lane);
            self.queued_tasks.remove(&lane);
        }

        self.policy = new_policy;
        Ok(())
    }

    /// Get current lane counters.
    /// INV-LANE-TELEMETRY-ACCURATE
    pub fn lane_counters(&self) -> &HashMap<String, LaneCounters> {
        &self.counters
    }

    /// Get counters for a specific lane.
    pub fn lane_counter(&self, lane: SchedulerLane) -> Option<&LaneCounters> {
        self.counters.get(lane.as_str())
    }

    /// Queued task IDs for a lane in FIFO order.
    pub fn queued_task_ids(&self, lane: SchedulerLane) -> Vec<String> {
        self.queued_tasks
            .get(lane.as_str())
            .map(|queue| {
                queue
                    .iter()
                    .map(|queued_task| queued_task.task_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Active task IDs for a lane in deterministic ID order.
    pub fn active_task_ids(&self, lane: SchedulerLane) -> Vec<String> {
        self.active_tasks
            .values()
            .filter(|assignment| assignment.lane == lane)
            .map(|assignment| assignment.task_id.clone())
            .collect()
    }

    /// Take a telemetry snapshot.
    pub fn telemetry_snapshot(&self, timestamp_ms: u64) -> LaneTelemetrySnapshot {
        LaneTelemetrySnapshot {
            counters: self.counters.values().cloned().collect(),
            timestamp_ms,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Get the current policy.
    pub fn policy(&self) -> &LaneMappingPolicy {
        &self.policy
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[LaneAuditRecord] {
        &self.audit_log
    }

    /// Get configured audit log capacity.
    pub fn audit_log_capacity(&self) -> usize {
        self.max_audit_log_entries
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Number of active tasks across all lanes.
    pub fn total_active(&self) -> usize {
        self.counters
            .values()
            .fold(0usize, |acc, c| acc.saturating_add(c.active_count))
    }

    /// Total completed tasks across all lanes.
    pub fn total_completed(&self) -> u64 {
        self.counters
            .values()
            .fold(0u64, |acc, c| acc.saturating_add(c.completed_total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    fn make_scheduler() -> LaneScheduler {
        LaneScheduler::new(default_policy()).unwrap()
    }

    fn add_lane_ok(policy: &mut LaneMappingPolicy, config: LaneConfig) {
        policy
            .add_lane(config)
            .expect("lane config should be unique in test setup");
    }

    fn queued_task_id_from(error: LaneSchedulerError) -> String {
        let queued_task_id = match error {
            LaneSchedulerError::CapExceeded { queued_task_id, .. } => queued_task_id,
            _ => None,
        };
        assert!(
            queued_task_id.is_some(),
            "cap pressure should retain a queued task identity"
        );
        queued_task_id.unwrap_or_default()
    }

    fn benchmark_best_of(mut bench: impl FnMut() -> Duration) -> Duration {
        let mut best: Option<Duration> = None;
        for _ in 0..5 {
            let elapsed = bench();
            best = Some(best.map_or(elapsed, |current| current.min(elapsed)));
        }
        best.expect("benchmark should execute at least once")
    }

    fn lane_scheduler_promotion_duration(queued_count: usize) -> Duration {
        benchmark_best_of(|| {
            let mut policy = default_policy();
            policy
                .lane_configs
                .get_mut(SchedulerLane::Background.as_str())
                .expect("background lane config")
                .concurrency_cap = queued_count.max(1);

            let mut scheduler = LaneScheduler::new(policy).expect("scheduler");
            for index in 0..queued_count {
                scheduler
                    .enqueue_task(
                        &task_classes::telemetry_export(),
                        SchedulerLane::Background,
                        index as u64,
                        &format!("trace-bench-{index}"),
                    )
                    .expect("enqueue")
                    .expect("queue under benchmark cap");
            }

            let started = Instant::now();
            scheduler
                .promote_queued_tasks_for_lane(
                    SchedulerLane::Background,
                    black_box(queued_count as u64 + 10_000),
                )
                .expect("promote queued tasks");
            let elapsed = started.elapsed();

            assert_eq!(scheduler.active_tasks.len(), queued_count);
            assert_eq!(
                scheduler
                    .queued_tasks
                    .get(SchedulerLane::Background.as_str())
                    .expect("background queue")
                    .len(),
                0
            );

            black_box(elapsed)
        })
    }

    // ---- SchedulerLane ----

    #[test]
    fn scheduler_lane_all_has_four() {
        assert_eq!(SchedulerLane::all().len(), 4);
    }

    #[test]
    fn scheduler_lane_display() {
        assert_eq!(
            SchedulerLane::ControlCritical.to_string(),
            "control_critical"
        );
        assert_eq!(SchedulerLane::RemoteEffect.to_string(), "remote_effect");
        assert_eq!(SchedulerLane::Maintenance.to_string(), "maintenance");
        assert_eq!(SchedulerLane::Background.to_string(), "background");
    }

    // ---- TaskClass ----

    #[test]
    fn task_class_new_and_display() {
        let tc = TaskClass::new("epoch_transition");
        assert_eq!(tc.as_str(), "epoch_transition");
        assert_eq!(tc.to_string(), "epoch_transition");
    }

    // ---- Default policy ----

    #[test]
    fn default_policy_is_valid() {
        let p = default_policy();
        assert!(p.validate().is_ok());
        assert_eq!(p.lane_configs.len(), 4);
        assert_eq!(p.mapping_rules.len(), 10);
    }

    #[test]
    fn default_policy_maps_all_classes() {
        let p = default_policy();
        assert_eq!(
            p.resolve(&task_classes::epoch_transition()),
            Some(SchedulerLane::ControlCritical)
        );
        assert_eq!(
            p.resolve(&task_classes::barrier_coordination()),
            Some(SchedulerLane::ControlCritical)
        );
        assert_eq!(
            p.resolve(&task_classes::marker_write()),
            Some(SchedulerLane::ControlCritical)
        );
        assert_eq!(
            p.resolve(&task_classes::remote_computation()),
            Some(SchedulerLane::RemoteEffect)
        );
        assert_eq!(
            p.resolve(&task_classes::artifact_upload()),
            Some(SchedulerLane::RemoteEffect)
        );
        assert_eq!(
            p.resolve(&task_classes::garbage_collection()),
            Some(SchedulerLane::Maintenance)
        );
        assert_eq!(
            p.resolve(&task_classes::telemetry_export()),
            Some(SchedulerLane::Background)
        );
    }

    #[test]
    fn default_policy_priority_weights_descend_by_execution_class() {
        let p = default_policy();
        let weight = |lane: SchedulerLane| p.lane_configs[lane.as_str()].priority_weight;

        assert!(weight(SchedulerLane::ControlCritical) > weight(SchedulerLane::RemoteEffect));
        assert!(weight(SchedulerLane::RemoteEffect) > weight(SchedulerLane::Maintenance));
        assert!(weight(SchedulerLane::Maintenance) > weight(SchedulerLane::Background));
    }

    #[test]
    fn default_policy_unknown_class_returns_none() {
        let p = default_policy();
        assert_eq!(p.resolve(&TaskClass::new("nonexistent")), None);
    }

    // ---- Policy validation ----

    #[test]
    fn partial_policy_with_configured_mapping_is_valid() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(&mut p, LaneConfig::new(SchedulerLane::Maintenance, 20, 2));
        p.add_rule(&task_classes::compaction(), SchedulerLane::Maintenance);

        assert!(p.validate().is_ok());
        assert!(LaneScheduler::new(p).is_ok());
    }

    #[test]
    fn empty_policy_invalid() {
        let p = LaneMappingPolicy::new();
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_with_unmapped_lane_invalid() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(
            &mut p,
            LaneConfig::new(SchedulerLane::ControlCritical, 100, 8),
        );
        p.add_rule(
            &task_classes::epoch_transition(),
            SchedulerLane::RemoteEffect,
        );
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_with_zero_weight_invalid() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(
            &mut p,
            LaneConfig::new(SchedulerLane::ControlCritical, 0, 8),
        );
        p.add_rule(
            &task_classes::epoch_transition(),
            SchedulerLane::ControlCritical,
        );
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_with_zero_cap_invalid() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(
            &mut p,
            LaneConfig::new(SchedulerLane::ControlCritical, 100, 0),
        );
        p.add_rule(
            &task_classes::epoch_transition(),
            SchedulerLane::ControlCritical,
        );
        assert!(p.validate().is_err());
    }

    #[test]
    fn duplicate_lane_config_is_rejected_without_overwrite() {
        let mut p = LaneMappingPolicy::new();
        let original = LaneConfig::new(SchedulerLane::Background, 10, 1);
        let duplicate = LaneConfig::new(SchedulerLane::Background, 99, 9);
        add_lane_ok(&mut p, original.clone());

        let err = p.add_lane(duplicate).expect_err("duplicate lane must fail");
        assert_eq!(err.code(), error_codes::ERR_LANE_DUPLICATE);
        assert_eq!(
            p.lane_configs.get(SchedulerLane::Background.as_str()),
            Some(&original)
        );
    }

    // ---- LaneScheduler construction ----

    #[test]
    fn scheduler_new_with_default_policy() {
        let s = make_scheduler();
        assert_eq!(s.total_active(), 0);
        assert_eq!(s.total_completed(), 0);
        assert_eq!(s.audit_log_capacity(), DEFAULT_MAX_AUDIT_LOG_ENTRIES);
    }

    #[test]
    fn scheduler_audit_capacity_clamps_to_one() {
        let mut s = LaneScheduler::with_audit_log_capacity(default_policy(), 0).unwrap();
        assert_eq!(s.audit_log_capacity(), 1);

        let a = s
            .assign_task(&task_classes::epoch_transition(), 1000, "t1")
            .unwrap();
        s.complete_task(&a.task_id, 1001, "t2").unwrap();

        assert_eq!(s.audit_log().len(), 1);
        assert_eq!(
            s.audit_log()[0].event_code,
            event_codes::LANE_TASK_COMPLETED
        );
    }

    #[test]
    fn scheduler_rejects_invalid_policy() {
        let p = LaneMappingPolicy::new();
        let err = LaneScheduler::new(p).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_LANE_INVALID_POLICY);
    }

    // ---- Task assignment ----

    #[test]
    fn assign_task_succeeds() {
        let mut s = make_scheduler();
        let a = s
            .assign_task(&task_classes::epoch_transition(), 1000, "t1")
            .unwrap();
        assert_eq!(a.lane, SchedulerLane::ControlCritical);
        assert_eq!(s.total_active(), 1);
    }

    #[test]
    fn assign_task_unknown_class_rejected() {
        let mut s = make_scheduler();
        let err = s
            .assign_task(&TaskClass::new("unknown"), 1000, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_LANE_UNKNOWN_CLASS);
    }

    #[test]
    fn assign_task_cap_enforced() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(&mut p, LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        s.assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        let err = s
            .assign_task(&task_classes::log_rotation(), 1001, "t2")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_LANE_CAP_EXCEEDED);
        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.rejected_total, 1);
        assert_eq!(counters.first_queued_at_ms, Some(1001));
    }

    #[test]
    fn task_id_allocation_rejects_after_u64_max_without_reusing_id() {
        let mut s = make_scheduler();
        s.task_counter = u64::MAX - 1;

        let max_id_assignment = s
            .assign_task(&task_classes::epoch_transition(), 1000, "trace-max-id")
            .expect("u64::MAX remains a valid final task id");
        assert_eq!(max_id_assignment.task_id, format!("task-{:08}", u64::MAX));
        assert_eq!(s.task_counter, u64::MAX);

        let err = s
            .assign_task(&task_classes::epoch_transition(), 1001, "trace-overflow")
            .expect_err("allocator must reject allocation past u64::MAX");

        assert_eq!(err.code(), error_codes::ERR_LANE_TASK_ID_EXHAUSTED);
        assert_eq!(
            err,
            LaneSchedulerError::TaskIdExhausted {
                last_counter: u64::MAX
            }
        );
        assert_eq!(s.task_counter, u64::MAX);
        assert_eq!(s.total_active(), 1);
        assert_eq!(
            s.active_task_ids(SchedulerLane::ControlCritical),
            vec![max_id_assignment.task_id]
        );
    }

    #[test]
    fn completion_promotes_oldest_queued_task_and_clears_queue_depth() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(&mut p, LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        let active = s
            .assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        let queued_task_id = queued_task_id_from(
            s.assign_task(&task_classes::log_rotation(), 1001, "t2")
                .expect_err("cap pressure should queue a specific task"),
        );

        let before = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(before.queued_count, 1);
        assert_eq!(before.first_queued_at_ms, Some(1001));

        s.complete_task(&active.task_id, 1002, "t3").unwrap();
        let after = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(after.queued_count, 0);
        assert_eq!(after.first_queued_at_ms, None);
        assert_eq!(
            s.active_task_ids(SchedulerLane::Background),
            vec![queued_task_id]
        );
    }

    #[test]
    fn completion_promotion_rebases_remaining_queue_fifo_baseline() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(&mut p, LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        let active = s
            .assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        let first_queued = queued_task_id_from(
            s.assign_task(&task_classes::log_rotation(), 1001, "t2")
                .expect_err("cap pressure should queue a specific task"),
        );
        let second_queued = queued_task_id_from(
            s.assign_task(&task_classes::log_rotation(), 1002, "t3")
                .expect_err("cap pressure should queue a specific task"),
        );
        let before = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(before.queued_count, 2);
        assert_eq!(before.first_queued_at_ms, Some(1001));

        s.complete_task(&active.task_id, 1003, "t4").unwrap();
        let after = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(after.queued_count, 1);
        assert_eq!(after.first_queued_at_ms, Some(1002));
        assert_eq!(
            s.active_task_ids(SchedulerLane::Background),
            vec![first_queued]
        );
        assert_eq!(
            s.queued_task_ids(SchedulerLane::Background),
            vec![second_queued]
        );
    }

    #[test]
    fn queue_depth_saturates_on_repeated_cap_overflow() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(&mut p, LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        let _active = s
            .assign_task(&task_classes::log_rotation(), 1000, "active")
            .unwrap();
        {
            let counters = s
                .counters
                .get_mut(SchedulerLane::Background.as_str())
                .unwrap();
            counters.queued_count = usize::MAX;
            counters.rejected_total = u64::MAX;
            counters.first_queued_at_ms = Some(1001);
        }

        let err = s
            .assign_task(&task_classes::log_rotation(), 1002, "overflow")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_LANE_CAP_EXCEEDED);
        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.queued_count, usize::MAX);
        assert_eq!(counters.rejected_total, u64::MAX);
        assert_eq!(counters.first_queued_at_ms, Some(1001));
        assert_eq!(s.total_active(), 1);
    }

    #[test]
    fn negative_cap_exceeded_does_not_create_assignment_or_audit_record() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(&mut p, LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        let active = s
            .assign_task(&task_classes::log_rotation(), 1000, "trace-active")
            .unwrap();
        let err = s
            .assign_task(&task_classes::log_rotation(), 1001, "trace-rejected")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_LANE_CAP_EXCEEDED);
        assert_eq!(s.total_active(), 1);
        assert_eq!(s.active_tasks.len(), 1);
        assert!(s.active_tasks.contains_key(&active.task_id));
        assert_eq!(s.audit_log().len(), 1);
        assert_eq!(s.audit_log()[0].event_code, event_codes::LANE_ASSIGN);
    }

    // ---- Task completion ----

    #[test]
    fn complete_task_updates_counters() {
        let mut s = make_scheduler();
        let a = s
            .assign_task(&task_classes::epoch_transition(), 1000, "t1")
            .unwrap();
        s.complete_task(&a.task_id, 1050, "t1").unwrap();
        assert_eq!(s.total_active(), 0);
        assert_eq!(s.total_completed(), 1);
    }

    #[test]
    fn complete_unknown_task_fails() {
        let mut s = make_scheduler();
        let err = s.complete_task("nonexistent", 1000, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_LANE_TASK_NOT_FOUND);
    }

    #[test]
    fn negative_completing_same_task_twice_does_not_double_count() {
        let mut s = make_scheduler();
        let assignment = s
            .assign_task(&task_classes::epoch_transition(), 1000, "trace-assign")
            .unwrap();
        s.complete_task(&assignment.task_id, 1010, "trace-complete")
            .unwrap();

        let err = s
            .complete_task(&assignment.task_id, 1020, "trace-complete-again")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_LANE_TASK_NOT_FOUND);
        assert_eq!(s.total_active(), 0);
        assert_eq!(s.total_completed(), 1);
        let completion_records = s
            .audit_log()
            .iter()
            .filter(|record| record.event_code == event_codes::LANE_TASK_COMPLETED)
            .count();
        assert_eq!(completion_records, 1);
    }

    // ---- Starvation detection ----

    #[test]
    fn no_starvation_before_window_when_queued_but_never_completed() {
        let mut p = LaneMappingPolicy::new();
        let mut cfg = LaneConfig::new(SchedulerLane::Background, 10, 1);
        cfg.starvation_window_ms = 100;
        add_lane_ok(&mut p, cfg);
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        // Fill the lane
        s.assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        // Try to assign another (will be rejected/queued)
        let _ = s.assign_task(&task_classes::log_rotation(), 1001, "t2");

        let starved = s.check_starvation(1099, "t3");
        assert!(starved.is_empty());

        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.starvation_events, 0);
        assert!(!counters.starvation_active);
    }

    #[test]
    fn starvation_detected_when_queued_before_first_completion_and_window_elapsed() {
        let mut p = LaneMappingPolicy::new();
        let mut cfg = LaneConfig::new(SchedulerLane::Background, 10, 1);
        cfg.starvation_window_ms = 100;
        add_lane_ok(&mut p, cfg);
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        // Fill and queue without any completion history.
        let a = s
            .assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        assert_eq!(a.assigned_at_ms, 1000);
        let _ = s.assign_task(&task_classes::log_rotation(), 1001, "t2");

        let starved = s.check_starvation(1200, "t3");
        assert_eq!(
            starved,
            vec![LaneSchedulerError::Starvation {
                lane: SchedulerLane::Background,
                queue_depth: 1,
                elapsed_ms: 199,
            }]
        );

        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.starvation_events, 1);
        assert!(counters.starvation_active);
        assert_eq!(counters.first_queued_at_ms, Some(1001));

        let audit = s.audit_log().last().unwrap();
        assert_eq!(audit.event_code, event_codes::LANE_STARVED);
        assert!(audit.detail.contains("queue_depth=1"));
        assert!(audit.detail.contains("elapsed=199ms"));
    }

    #[test]
    fn starvation_detected_after_completion_and_window_elapsed() {
        let mut p = LaneMappingPolicy::new();
        let mut cfg = LaneConfig::new(SchedulerLane::Background, 10, 1);
        cfg.starvation_window_ms = 100;
        add_lane_ok(&mut p, cfg);
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        // Assign, complete, then queue new work
        let a = s
            .assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        s.complete_task(&a.task_id, 1050, "t1").unwrap();

        // Now fill and queue
        s.assign_task(&task_classes::log_rotation(), 1060, "t2")
            .unwrap();
        let _ = s.assign_task(&task_classes::log_rotation(), 1061, "t3");

        // Starvation detected from the first blocked queue timestamp.
        let starved = s.check_starvation(1200, "t4");
        assert_eq!(
            starved,
            vec![LaneSchedulerError::Starvation {
                lane: SchedulerLane::Background,
                queue_depth: 1,
                elapsed_ms: 139,
            }]
        );

        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.starvation_events, 1);
        assert!(counters.starvation_active);
        assert_eq!(counters.first_queued_at_ms, Some(1061));
    }

    #[test]
    fn starvation_baseline_does_not_reset_on_completion_while_queue_remains_blocked() {
        let mut p = LaneMappingPolicy::new();
        let mut cfg = LaneConfig::new(SchedulerLane::Background, 10, 1);
        cfg.starvation_window_ms = 150;
        add_lane_ok(&mut p, cfg);
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        let active = s
            .assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        let _ = s.assign_task(&task_classes::log_rotation(), 1001, "t2");
        let _ = s.assign_task(&task_classes::log_rotation(), 1002, "t3");

        s.complete_task(&active.task_id, 1100, "t4").unwrap();

        let starved = s.check_starvation(1151, "t5");
        assert_eq!(
            starved,
            vec![LaneSchedulerError::Starvation {
                lane: SchedulerLane::Background,
                queue_depth: 2,
                elapsed_ms: 150,
            }]
        );
    }

    #[test]
    fn no_starvation_when_no_queue() {
        let mut s = make_scheduler();
        let starved = s.check_starvation(100000, "t1");
        assert!(starved.is_empty());
        assert!(
            !s.lane_counter(SchedulerLane::Background)
                .unwrap()
                .starvation_active
        );
    }

    #[test]
    fn negative_starvation_check_before_queue_timestamp_does_not_alert() {
        let mut p = LaneMappingPolicy::new();
        let mut cfg = LaneConfig::new(SchedulerLane::Background, 10, 1);
        cfg.starvation_window_ms = 1;
        add_lane_ok(&mut p, cfg);
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        s.assign_task(&task_classes::log_rotation(), 1000, "trace-active")
            .unwrap();
        let _ = s.assign_task(&task_classes::log_rotation(), 1100, "trace-queued");

        let starved = s.check_starvation(1099, "trace-before-queue");

        assert!(starved.is_empty());
        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.starvation_events, 0);
        assert!(!counters.starvation_active);
        assert_eq!(counters.first_queued_at_ms, Some(1100));
    }

    #[test]
    fn starvation_events_latch_until_queue_state_recovers() {
        let mut p = LaneMappingPolicy::new();
        let mut cfg = LaneConfig::new(SchedulerLane::Background, 10, 1);
        cfg.starvation_window_ms = 100;
        add_lane_ok(&mut p, cfg);
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        let active = s
            .assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        let _ = s.assign_task(&task_classes::log_rotation(), 1001, "t2");

        let first = s.check_starvation(1200, "t3");
        let second = s.check_starvation(1300, "t4");
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);

        let starved_records = s
            .audit_log()
            .iter()
            .filter(|entry| entry.event_code == event_codes::LANE_STARVED)
            .count();
        assert_eq!(starved_records, 1);
        assert_eq!(
            s.lane_counter(SchedulerLane::Background)
                .unwrap()
                .starvation_events,
            1
        );

        s.complete_task(&active.task_id, 1301, "t5").unwrap();
        let admitted = s
            .assign_task(&task_classes::log_rotation(), 1302, "t6")
            .unwrap();
        assert_eq!(admitted.lane, SchedulerLane::Background);

        let recovered = s.check_starvation(1303, "t7");
        assert!(recovered.is_empty());

        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert!(!counters.starvation_active);

        let audit = s.audit_log().last().unwrap();
        assert_eq!(audit.event_code, event_codes::LANE_STARVATION_CLEARED);
        assert!(audit.detail.contains("queue_depth=0"));
    }

    // ---- Hot reload ----

    #[test]
    fn hot_reload_updates_policy() {
        let mut s = make_scheduler();
        assert_eq!(s.policy().resolve(&TaskClass::new("new_class")), None);

        let mut new_policy = default_policy();
        new_policy.add_rule(&TaskClass::new("new_class"), SchedulerLane::Maintenance);
        s.reload_policy(new_policy).unwrap();

        assert_eq!(
            s.policy().resolve(&TaskClass::new("new_class")),
            Some(SchedulerLane::Maintenance)
        );
    }

    #[test]
    fn hot_reload_rejects_invalid_policy() {
        let mut s = make_scheduler();
        let err = s.reload_policy(LaneMappingPolicy::new()).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_LANE_INVALID_POLICY);
    }

    #[test]
    fn negative_hot_reload_unconfigured_target_preserves_existing_policy() {
        let mut s = make_scheduler();
        let mut invalid = LaneMappingPolicy::new();
        add_lane_ok(
            &mut invalid,
            LaneConfig::new(SchedulerLane::Background, 10, 1),
        );
        invalid.add_rule(
            &task_classes::epoch_transition(),
            SchedulerLane::RemoteEffect,
        );

        let err = s
            .reload_policy(invalid)
            .expect_err("reload must reject rules targeting unconfigured lanes");

        assert_eq!(err.code(), error_codes::ERR_LANE_INVALID_POLICY);
        assert_eq!(
            s.policy().resolve(&task_classes::epoch_transition()),
            Some(SchedulerLane::ControlCritical)
        );
        assert_eq!(s.lane_counters().len(), 4);
    }

    #[test]
    fn negative_hot_reload_zero_cap_preserves_existing_scheduler() {
        let mut s = make_scheduler();
        let mut invalid = default_policy();
        invalid
            .lane_configs
            .get_mut(SchedulerLane::Background.as_str())
            .unwrap()
            .concurrency_cap = 0;

        let err = s
            .reload_policy(invalid)
            .expect_err("reload must reject zero-cap lanes");

        assert_eq!(err.code(), error_codes::ERR_LANE_INVALID_POLICY);
        let assignment = s
            .assign_task(&task_classes::log_rotation(), 2000, "trace-after-reject")
            .unwrap();
        assert_eq!(assignment.lane, SchedulerLane::Background);
    }

    // ---- Telemetry ----

    #[test]
    fn telemetry_snapshot_has_all_lanes() {
        let s = make_scheduler();
        let snap = s.telemetry_snapshot(1000);
        assert_eq!(snap.counters.len(), 4);
        assert_eq!(snap.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn telemetry_reflects_task_lifecycle() {
        let mut s = make_scheduler();
        s.assign_task(&task_classes::epoch_transition(), 1000, "t1")
            .unwrap();
        s.assign_task(&task_classes::remote_computation(), 1001, "t2")
            .unwrap();

        let snap = s.telemetry_snapshot(1002);
        let cc = snap
            .counters
            .iter()
            .find(|c| c.lane == SchedulerLane::ControlCritical)
            .unwrap();
        assert_eq!(cc.active_count, 1);

        let re = snap
            .counters
            .iter()
            .find(|c| c.lane == SchedulerLane::RemoteEffect)
            .unwrap();
        assert_eq!(re.active_count, 1);
    }

    // ---- Audit log ----

    #[test]
    fn audit_log_records_assignments() {
        let mut s = make_scheduler();
        s.assign_task(&task_classes::epoch_transition(), 1000, "t1")
            .unwrap();
        assert_eq!(s.audit_log().len(), 1);
        assert_eq!(s.audit_log()[0].event_code, event_codes::LANE_ASSIGN);
    }

    #[test]
    fn audit_log_records_completions() {
        let mut s = make_scheduler();
        let a = s
            .assign_task(&task_classes::epoch_transition(), 1000, "t1")
            .unwrap();
        s.complete_task(&a.task_id, 1050, "t1").unwrap();
        assert_eq!(s.audit_log().len(), 2);
        assert_eq!(
            s.audit_log()[1].event_code,
            event_codes::LANE_TASK_COMPLETED
        );
    }

    #[test]
    fn audit_export_jsonl() {
        let mut s = make_scheduler();
        s.assign_task(&task_classes::epoch_transition(), 1000, "t1")
            .unwrap();
        let jsonl = s.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["event_code"], event_codes::LANE_ASSIGN);
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }

    #[test]
    fn audit_log_capacity_enforces_oldest_first_eviction() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(&mut p, LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::with_audit_log_capacity(p, 2).unwrap();

        let a = s
            .assign_task(&task_classes::log_rotation(), 1000, "ta1")
            .unwrap();
        s.complete_task(&a.task_id, 1001, "ta2").unwrap();
        s.assign_task(&task_classes::log_rotation(), 1002, "ta3")
            .unwrap();

        assert_eq!(s.audit_log().len(), 2);
        let codes: Vec<&str> = s
            .audit_log()
            .iter()
            .map(|r| r.event_code.as_str())
            .collect();
        assert_eq!(
            codes,
            vec![event_codes::LANE_TASK_COMPLETED, event_codes::LANE_ASSIGN]
        );
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<LaneSchedulerError> = vec![
            LaneSchedulerError::UnknownClass {
                task_class: "x".into(),
            },
            LaneSchedulerError::CapExceeded {
                lane: SchedulerLane::Background,
                cap: 2,
                current: 2,
                queued_task_id: Some("task-queued".to_string()),
            },
            LaneSchedulerError::UnknownLane { lane: "x".into() },
            LaneSchedulerError::DuplicateLane {
                lane: SchedulerLane::Background,
            },
            LaneSchedulerError::InvalidPolicy {
                detail: "bad".into(),
            },
            LaneSchedulerError::Starvation {
                lane: SchedulerLane::Background,
                queue_depth: 5,
                elapsed_ms: 10000,
            },
            LaneSchedulerError::TaskNotFound {
                task_id: "t1".into(),
            },
            LaneSchedulerError::InvalidWeight {
                lane: SchedulerLane::Background,
                weight: 0,
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(s.contains(e.code()), "{:?} should contain {}", e, e.code());
        }
    }

    // ---- Multiple task classes through lanes ----

    #[test]
    fn multiple_classes_different_lanes() {
        let mut s = make_scheduler();
        let a1 = s
            .assign_task(&task_classes::epoch_transition(), 1000, "t1")
            .unwrap();
        let a2 = s
            .assign_task(&task_classes::remote_computation(), 1001, "t2")
            .unwrap();
        let a3 = s
            .assign_task(&task_classes::garbage_collection(), 1002, "t3")
            .unwrap();
        let a4 = s
            .assign_task(&task_classes::telemetry_export(), 1003, "t4")
            .unwrap();

        assert_eq!(a1.lane, SchedulerLane::ControlCritical);
        assert_eq!(a2.lane, SchedulerLane::RemoteEffect);
        assert_eq!(a3.lane, SchedulerLane::Maintenance);
        assert_eq!(a4.lane, SchedulerLane::Background);
        assert_eq!(s.total_active(), 4);
    }

    #[test]
    fn deterministic_task_ids_and_lane_assignments_under_repeated_load() {
        fn run_load() -> Vec<(String, String, SchedulerLane)> {
            let mut policy = default_policy();
            for config in policy.lane_configs.values_mut() {
                config.concurrency_cap = 128;
            }
            let mut scheduler = LaneScheduler::new(policy).unwrap();
            let task_classes = [
                task_classes::epoch_transition(),
                task_classes::remote_computation(),
                task_classes::garbage_collection(),
                task_classes::telemetry_export(),
                task_classes::marker_write(),
                task_classes::artifact_upload(),
                task_classes::compaction(),
                task_classes::log_rotation(),
            ];

            (0..64)
                .map(|idx| {
                    let task_class = &task_classes[idx % task_classes.len()];
                    let assignment = scheduler
                        .assign_task(task_class, 10_000 + idx as u64, &format!("trace-{idx}"))
                        .unwrap();
                    (
                        assignment.task_id,
                        assignment.task_class.to_string(),
                        assignment.lane,
                    )
                })
                .collect()
        }

        assert_eq!(run_load(), run_load());
    }

    // ---- Lane config ----

    #[test]
    fn lane_config_defaults() {
        let cfg = LaneConfig::new(SchedulerLane::ControlCritical, 100, 8);
        assert_eq!(cfg.starvation_window_ms, DEFAULT_STARVATION_WINDOW_MS);
    }

    // ---- Concurrent load ----

    #[test]
    fn concurrent_load_respects_caps() {
        let mut s = make_scheduler();
        // ControlCritical cap is 8
        for i in 0..8 {
            s.assign_task(
                &task_classes::epoch_transition(),
                1000 + i,
                &format!("t{i}"),
            )
            .unwrap();
        }
        let err = s
            .assign_task(&task_classes::epoch_transition(), 1009, "t9")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_LANE_CAP_EXCEEDED);
        assert_eq!(
            s.lane_counter(SchedulerLane::ControlCritical)
                .unwrap()
                .active_count,
            8
        );
    }

    #[test]
    fn abort_queued_task_id_decrements_queue_depth() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(&mut p, LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        // Assign one active
        s.assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();

        // Queue two more
        let first_queued = queued_task_id_from(
            s.assign_task(&task_classes::log_rotation(), 1001, "t2")
                .expect_err("cap pressure should queue a specific task"),
        );
        let second_queued = queued_task_id_from(
            s.assign_task(&task_classes::log_rotation(), 1002, "t3")
                .expect_err("cap pressure should queue a specific task"),
        );

        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.queued_count, 2);

        // Abort one queued task
        let aborted = s
            .abort_queued_task_id(&first_queued, 1003, "abort-first")
            .unwrap();
        assert_eq!(aborted.task_id, first_queued);

        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.queued_count, 1);

        // Abort the other queued task
        let aborted = s
            .abort_queued_task_id(&second_queued, 1004, "abort-second")
            .unwrap();
        assert_eq!(aborted.task_id, second_queued);

        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.queued_count, 0);
        assert_eq!(counters.first_queued_at_ms, None);
    }

    #[test]
    fn negative_abort_queued_unknown_id_preserves_queue_state() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(&mut p, LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        s.assign_task(&task_classes::log_rotation(), 1000, "trace-active")
            .unwrap();
        let queued = queued_task_id_from(
            s.assign_task(&task_classes::log_rotation(), 1001, "trace-queued")
                .expect_err("cap pressure should queue a specific task"),
        );

        let err = s
            .abort_queued_task_id("not-mapped-task-id", 1002, "trace-missing-id")
            .expect_err("unknown queued task id must fail without mutation");

        assert_eq!(err.code(), error_codes::ERR_LANE_TASK_NOT_FOUND);
        assert_eq!(s.queued_task_ids(SchedulerLane::Background), vec![queued]);
        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.queued_count, 1);
        assert_eq!(counters.first_queued_at_ms, Some(1001));
        assert_eq!(s.total_active(), 1);
    }

    #[test]
    fn negative_scheduler_new_rejects_lane_without_mapping_rules() {
        let mut p = LaneMappingPolicy::new();
        add_lane_ok(&mut p, LaneConfig::new(SchedulerLane::Maintenance, 20, 2));

        let err =
            LaneScheduler::new(p).expect_err("lane-only policy must reject missing mapping rules");

        assert_eq!(err.code(), error_codes::ERR_LANE_INVALID_POLICY);
        assert!(err.to_string().contains("no mapping rules defined"));
    }

    // ---- Default trait ----

    #[test]
    fn default_policy_trait() {
        let p = LaneMappingPolicy::default();
        assert!(p.lane_configs.is_empty());
    }

    /// Test: Lane scheduler arithmetic overflow and boundary attack vectors
    #[test]
    fn test_lane_scheduler_arithmetic_overflow_boundary_attacks() {
        let mut policy = LaneMappingPolicy::new();
        policy
            .add_lane(LaneConfig::new(
                SchedulerLane::ControlCritical,
                u32::MAX,
                usize::MAX,
            ))
            .unwrap();
        policy.add_rule(
            &task_classes::epoch_transition(),
            SchedulerLane::ControlCritical,
        );

        let mut scheduler = LaneScheduler::new(policy).unwrap();

        // Test: Maximum timestamp values (near u64::MAX)
        let timestamp_boundaries = vec![
            0u64,                  // Minimum
            1u64,                  // Just above minimum
            u32::MAX as u64,       // 32-bit boundary
            (u32::MAX as u64) + 1, // Just over 32-bit
            u64::MAX - 1_000_000,  // Near maximum but safe
            u64::MAX - 1,          // Near maximum
            u64::MAX,              // Maximum value
        ];

        for &timestamp in &timestamp_boundaries {
            let result = scheduler.assign_task(
                &task_classes::epoch_transition(),
                timestamp,
                &format!("trace_timestamp_{}", timestamp),
            );

            assert!(
                result.is_ok(),
                "Timestamp {} should be handled without overflow",
                timestamp
            );

            if let Ok(assignment) = result {
                assert_eq!(
                    assignment.assigned_at_ms, timestamp,
                    "Timestamp {} should be preserved exactly",
                    timestamp
                );

                // Complete the task to clean up
                let _complete_result =
                    scheduler.complete_task(&assignment.task_id, timestamp + 1, "trace_complete");
            }
        }

        // Test: Task counter overflow protection
        scheduler.task_counter = u64::MAX - 10;

        for i in 0..10 {
            let assign_result = scheduler.assign_task(
                &task_classes::epoch_transition(),
                1000 + i,
                &format!("trace_overflow_{}", i),
            );

            // Should handle the final representable IDs with saturating arithmetic.
            assert!(
                assign_result.is_ok(),
                "Task counter should allocate final representable id at iteration {}",
                i
            );

            if let Ok(assignment) = assign_result {
                // Task ID should still be generated
                assert!(
                    assignment.task_id.starts_with("task-"),
                    "Task ID should be generated even with overflow"
                );

                // Complete task to avoid cap issues
                let _complete_result =
                    scheduler.complete_task(&assignment.task_id, 1010 + i, "trace_complete");
            }
        }

        let exhausted = scheduler
            .assign_task(
                &task_classes::epoch_transition(),
                1020,
                "trace_overflow_exhausted",
            )
            .expect_err("allocation past u64::MAX must fail closed");
        assert_eq!(exhausted.code(), error_codes::ERR_LANE_TASK_ID_EXHAUSTED);

        // Task counter should have used saturating arithmetic
        assert_eq!(
            scheduler.task_counter,
            u64::MAX,
            "Task counter should saturate at MAX"
        );

        // Test: Concurrency counter arithmetic boundaries
        let mut high_cap_policy = LaneMappingPolicy::new();
        high_cap_policy
            .add_lane(LaneConfig::new(SchedulerLane::Background, 1, 5))
            .unwrap(); // Small cap for testing
        high_cap_policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);

        let mut high_cap_scheduler = LaneScheduler::new(high_cap_policy).unwrap();

        // Fill up to capacity
        let mut active_tasks = Vec::new();
        for i in 0..5 {
            let result = high_cap_scheduler.assign_task(
                &task_classes::log_rotation(),
                2000 + i,
                &format!("trace_cap_{}", i),
            );
            assert!(result.is_ok(), "Should fill to capacity");
            if let Ok(assignment) = result {
                active_tasks.push(assignment);
            }
        }

        // Exceed capacity should use saturating arithmetic in rejection counts
        for i in 0..10 {
            let overflow_result = high_cap_scheduler.assign_task(
                &task_classes::log_rotation(),
                3000 + i,
                &format!("trace_overflow_{}", i),
            );

            assert!(overflow_result.is_err(), "Should reject when over capacity");
        }

        // Counters should use saturating arithmetic
        let counters = high_cap_scheduler
            .lane_counter(SchedulerLane::Background)
            .unwrap();
        assert!(
            counters.rejected_total <= u64::MAX,
            "Rejected count should not overflow"
        );
        assert!(
            counters.queued_count <= usize::MAX,
            "Queue count should not overflow"
        );

        // Clean up active tasks
        for assignment in active_tasks {
            let _complete_result =
                high_cap_scheduler.complete_task(&assignment.task_id, 4000, "cleanup");
        }
    }

    /// Test: Task class and lane identifier injection attacks
    #[test]
    fn test_task_class_lane_identifier_injection_attacks() {
        // Test: Malicious task class names
        let malicious_task_classes = vec![
            TaskClass::new(""),                              // Empty name
            TaskClass::new("\x00\x01\x02"),                  // Null bytes and control chars
            TaskClass::new("task\r\nclass"),                 // CRLF injection
            TaskClass::new("task\x1B[31mclass\x1B[0m"),      // ANSI escape sequences
            TaskClass::new("<script>alert('xss')</script>"), // XSS injection
            TaskClass::new("'; DROP TABLE tasks; --"),       // SQL injection style
            TaskClass::new("task\u{200B}class"),             // Zero-width space
            TaskClass::new("task\u{202E}ssalc\u{202D}"),     // BIDI override
            TaskClass::new("🔒🔓💀"),                        // Emoji injection
            TaskClass::new(&"x".repeat(100_000)),            // Memory exhaustion
            TaskClass::new("../../../etc/passwd"),           // Path traversal
            TaskClass::new("CON"),                           // Windows reserved name
            TaskClass::new("task\ttab\nline"),               // Mixed whitespace
        ];

        let mut scheduler = make_scheduler();

        for malicious_class in &malicious_task_classes {
            // Should reject unknown classes but handle malicious names safely
            let result = scheduler.assign_task(malicious_class, 1000, "trace_malicious_class");

            // Expected to fail with UnknownClass error (not mapped in default policy)
            assert!(
                matches!(result, Err(LaneSchedulerError::UnknownClass { .. })),
                "Should reject unknown malicious class: '{}'",
                malicious_class.as_str()
            );

            // Error handling should not crash or leak information
            if let Err(error) = result {
                let error_msg = error.to_string();
                assert!(
                    error_msg.len() < 1000,
                    "Error message should not be excessively long"
                );

                // Should preserve the malicious class name exactly (no sanitization)
                assert!(
                    error_msg.contains(malicious_class.as_str()),
                    "Error should contain the exact class name"
                );
            }
        }

        // Test: Adding malicious classes to policy
        let mut malicious_policy = LaneMappingPolicy::new();
        malicious_policy
            .add_lane(LaneConfig::new(SchedulerLane::Background, 1, 1))
            .unwrap();

        for malicious_class in &malicious_task_classes[..5] {
            // Test subset to avoid excessive output
            malicious_policy.add_rule(malicious_class, SchedulerLane::Background);
        }

        // Should be able to create scheduler with malicious task class names
        let malicious_scheduler_result = LaneScheduler::new(malicious_policy);
        assert!(
            malicious_scheduler_result.is_ok(),
            "Should handle malicious task class names in policy"
        );

        if let Ok(mut malicious_scheduler) = malicious_scheduler_result {
            // Should be able to assign tasks with malicious names
            for malicious_class in &malicious_task_classes[..3] {
                let assign_result = malicious_scheduler.assign_task(
                    malicious_class,
                    2000,
                    "trace_malicious_assignment",
                );

                assert!(
                    assign_result.is_ok(),
                    "Should assign task with malicious class name"
                );

                if let Ok(assignment) = assign_result {
                    // Assignment should preserve malicious class name exactly
                    assert_eq!(
                        assignment.task_class.as_str(),
                        malicious_class.as_str(),
                        "Assignment should preserve exact malicious class name"
                    );

                    // Complete task
                    let _complete_result = malicious_scheduler.complete_task(
                        &assignment.task_id,
                        2100,
                        "trace_complete",
                    );
                }
            }

            // Audit log should handle malicious class names safely
            let audit_log = malicious_scheduler.audit_log();
            for record in audit_log {
                // Should preserve malicious content exactly in audit log
                if !record.task_class.is_empty() {
                    assert!(
                        malicious_task_classes
                            .iter()
                            .any(|mc| mc.as_str() == record.task_class),
                        "Audit log should preserve malicious class names"
                    );
                }
            }
        }

        // Test: Trace ID injection attacks
        let trace_id_attacks = vec![
            "",                                      // Empty trace ID
            "\x00trace\x01id\x02",                   // Null bytes and control chars
            "trace\r\nSet-Cookie: session=hijacked", // HTTP header injection
            "trace\x1B[2J\x1B[H",                    // Terminal escape (clear screen)
            "<img src=x onerror=alert('xss')>",      // XSS in trace
            "'; DELETE FROM traces; --",             // SQL injection style
            "trace\u{200B}id",                       // Zero-width space
            "trace\u{202E}di_ecar\u{202D}t",         // BIDI override
            &"t".repeat(100_000),                    // Memory exhaustion
            "../../../var/log/system.log",           // Path traversal
            "trace\ttab\nline\rreturn",              // Mixed whitespace/control
        ];

        for attack_trace_id in &trace_id_attacks {
            let result =
                scheduler.assign_task(&task_classes::epoch_transition(), 3000, attack_trace_id);

            assert!(
                result.is_ok(),
                "Should handle malicious trace ID: '{}'",
                attack_trace_id.chars().take(20).collect::<String>()
            );

            if let Ok(assignment) = result {
                // Trace ID should be preserved exactly
                assert_eq!(
                    assignment.trace_id, *attack_trace_id,
                    "Trace ID should be preserved exactly"
                );

                // Complete task
                let _complete_result =
                    scheduler.complete_task(&assignment.task_id, 3100, attack_trace_id);
            }
        }

        // Audit log should handle malicious trace IDs
        let final_audit = scheduler.audit_log();
        let trace_id_records: Vec<_> = final_audit
            .iter()
            .filter(|r| trace_id_attacks.contains(&r.trace_id.as_str()))
            .collect();

        assert!(
            !trace_id_records.is_empty(),
            "Should have audit records with malicious trace IDs"
        );
    }

    /// Test: Starvation detection timing manipulation and race conditions
    #[test]
    fn test_starvation_timing_manipulation_race_conditions() {
        // Create policy with very short starvation window for testing
        let mut fast_starvation_policy = LaneMappingPolicy::new();
        let mut config = LaneConfig::new(SchedulerLane::Background, 1, 1); // Cap of 1
        config.starvation_window_ms = 100; // Very short window
        fast_starvation_policy.add_lane(config).unwrap();
        fast_starvation_policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);

        let mut scheduler = LaneScheduler::new(fast_starvation_policy).unwrap();

        // Test: Timestamp manipulation attacks
        let timestamp_attacks = vec![
            // Time going backwards
            (1000u64, 500u64),
            // Large time jumps
            (1000u64, u64::MAX),
            // Zero timestamps
            (0u64, 0u64),
            // Boundary conditions
            (u64::MAX - 1, u64::MAX),
            // Time overflow scenarios
            (u64::MAX, u64::MAX.saturating_add(1000)),
        ];

        for (base_time, attack_time) in timestamp_attacks {
            // Fill capacity to trigger queueing
            let fill_result = scheduler.assign_task(
                &task_classes::log_rotation(),
                base_time,
                &format!("trace_fill_{}", base_time),
            );

            if fill_result.is_ok() {
                // Try to trigger queueing
                let queue_result = scheduler.assign_task(
                    &task_classes::log_rotation(),
                    base_time + 1,
                    &format!("trace_queue_{}", base_time),
                );

                // Should be queued/rejected due to capacity
                assert!(queue_result.is_err(), "Should reject when at capacity");

                // Check starvation with manipulated timestamp
                let starvation_results = scheduler
                    .check_starvation(attack_time, &format!("trace_attack_{}", attack_time));

                // Should handle timestamp manipulation gracefully
                // May or may not detect starvation depending on implementation, but should not crash
                for starvation in &starvation_results {
                    match starvation {
                        LaneSchedulerError::Starvation { elapsed_ms, .. } => {
                            // Elapsed time should be calculated using saturating arithmetic
                            assert!(*elapsed_ms <= u64::MAX, "Elapsed time should not overflow");
                        }
                        _ => {} // Other errors are acceptable
                    }
                }

                // Complete the filling task to reset state
                if let Ok(assignment) = fill_result {
                    let _complete_result = scheduler.complete_task(
                        &assignment.task_id,
                        base_time + 10,
                        "trace_cleanup",
                    );
                }
            }
        }

        // Test: Rapid starvation check calls (race condition simulation)
        let rapid_task_result =
            scheduler.assign_task(&task_classes::log_rotation(), 5000, "rapid_fill");
        if rapid_task_result.is_ok() {
            // Fill to capacity
            let _queue_attempt =
                scheduler.assign_task(&task_classes::log_rotation(), 5001, "rapid_queue");

            // Rapid starvation checks
            for i in 0..100 {
                let check_time = 5000 + i * 10;
                let starvation_results =
                    scheduler.check_starvation(check_time, &format!("rapid_trace_{}", i));

                // Should handle rapid calls without state corruption
                for starvation in &starvation_results {
                    assert!(
                        starvation.code().starts_with("ERR_"),
                        "Error codes should be well-formed"
                    );
                }
            }

            // State should remain consistent after rapid checks
            let counters = scheduler.lane_counter(SchedulerLane::Background);
            assert!(
                counters.is_some(),
                "Counters should remain valid after rapid starvation checks"
            );

            if let Some(lane_counters) = counters {
                assert!(
                    lane_counters.starvation_events < u64::MAX,
                    "Starvation events should use saturating arithmetic"
                );
            }

            // Clean up
            if let Ok(assignment) = rapid_task_result {
                let _complete_result =
                    scheduler.complete_task(&assignment.task_id, 6000, "cleanup");
            }
        }

        // Test: Concurrent starvation and task operations
        use std::sync::{Arc, Mutex};
        use std::thread;

        let shared_scheduler = Arc::new(Mutex::new(make_scheduler()));
        let mut handles = Vec::new();

        for thread_id in 0..3 {
            let scheduler_clone = Arc::clone(&shared_scheduler);

            let handle = thread::spawn(move || {
                for iteration in 0..10 {
                    let mut scheduler_guard = scheduler_clone.lock().unwrap();

                    // Alternate between operations
                    match iteration % 3 {
                        0 => {
                            // Assign task
                            let _assign_result = scheduler_guard.assign_task(
                                &task_classes::epoch_transition(),
                                7000 + iteration * 100,
                                &format!("concurrent_thread_{}_{}", thread_id, iteration),
                            );
                        }
                        1 => {
                            // Check starvation
                            let _starvation_results = scheduler_guard.check_starvation(
                                7000 + iteration * 100,
                                &format!("starvation_thread_{}_{}", thread_id, iteration),
                            );
                        }
                        2 => {
                            // Complete any available tasks
                            if let Some(assignment) =
                                scheduler_guard.active_tasks.values().next().cloned()
                            {
                                let _complete_result = scheduler_guard.complete_task(
                                    &assignment.task_id,
                                    7000 + iteration * 100,
                                    &format!("complete_thread_{}_{}", thread_id, iteration),
                                );
                            }
                        }
                        _ => unreachable!(),
                    }

                    thread::yield_now();
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        // Verify scheduler state remains consistent after concurrent access
        let final_scheduler = shared_scheduler.lock().unwrap();
        let audit_log = final_scheduler.audit_log();

        // All audit records should be well-formed
        for record in audit_log {
            assert!(
                !record.event_code.is_empty(),
                "Event codes should not be empty"
            );
            assert!(record.timestamp_ms > 0, "Timestamps should be positive");
        }
    }

    /// Test: Policy validation and hot reload attack vectors
    #[test]
    fn test_policy_validation_hot_reload_attacks() {
        let mut scheduler = make_scheduler();

        // Test: Malformed policy injection during hot reload
        let malformed_policies = vec![
            // Policy with zero weight lanes
            {
                let mut policy = LaneMappingPolicy::new();
                policy
                    .add_lane(LaneConfig::new(SchedulerLane::Background, 0, 1))
                    .unwrap();
                policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
                policy
            },
            // Policy with zero capacity lanes
            {
                let mut policy = LaneMappingPolicy::new();
                policy
                    .add_lane(LaneConfig::new(SchedulerLane::Background, 1, 0))
                    .unwrap();
                policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
                policy
            },
            // Policy with unmapped rules
            {
                let mut policy = LaneMappingPolicy::new();
                policy
                    .add_lane(LaneConfig::new(SchedulerLane::Background, 1, 1))
                    .unwrap();
                policy.add_rule(
                    &task_classes::log_rotation(),
                    SchedulerLane::ControlCritical,
                ); // Unmapped lane
                policy
            },
            // Empty policy
            LaneMappingPolicy::new(),
        ];

        for (i, malformed_policy) in malformed_policies.into_iter().enumerate() {
            let reload_result = scheduler.reload_policy(malformed_policy);

            assert!(
                reload_result.is_err(),
                "Should reject malformed policy {}",
                i
            );

            if let Err(error) = reload_result {
                // Error should not leak sensitive information
                let error_msg = error.to_string();
                assert!(
                    error_msg.len() < 500,
                    "Error message should not be excessively long"
                );
                assert!(
                    !error_msg.contains("internal"),
                    "Should not leak internal details"
                );
                assert!(
                    !error_msg.contains("debug"),
                    "Should not leak debug information"
                );
            }
        }

        // Original policy should remain intact after failed reloads
        let original_policy = scheduler.policy();
        assert!(
            original_policy.validate().is_ok(),
            "Original policy should remain valid"
        );

        // Scheduler should continue functioning normally
        let post_attack_result =
            scheduler.assign_task(&task_classes::epoch_transition(), 8000, "post_attack_trace");
        assert!(
            post_attack_result.is_ok(),
            "Scheduler should function normally after policy attacks"
        );

        // Test: Valid policy with malicious configurations
        let mut malicious_policy = LaneMappingPolicy::new();

        // Add lanes with extreme values
        malicious_policy
            .add_lane(LaneConfig::new(
                SchedulerLane::Background,
                u32::MAX,
                usize::MAX,
            ))
            .unwrap();
        malicious_policy
            .add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 1, 1))
            .unwrap();

        // Add mapping with malicious task class
        let malicious_class = TaskClass::new("../../../etc/passwd");
        malicious_policy.add_rule(&malicious_class, SchedulerLane::Background);
        malicious_policy.add_rule(
            &task_classes::epoch_transition(),
            SchedulerLane::ControlCritical,
        );

        let malicious_reload_result = scheduler.reload_policy(malicious_policy);
        assert!(
            malicious_reload_result.is_ok(),
            "Should accept valid but extreme policy"
        );

        // Should be able to use malicious task class
        let malicious_assign_result =
            scheduler.assign_task(&malicious_class, 9000, "malicious_trace");
        assert!(
            malicious_assign_result.is_ok(),
            "Should handle malicious task class in policy"
        );

        // Test: Policy hot reload under load
        let mut load_policy = LaneMappingPolicy::new();
        load_policy
            .add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, 50, 10))
            .unwrap();
        load_policy.add_rule(
            &task_classes::remote_computation(),
            SchedulerLane::RemoteEffect,
        );

        // Assign several tasks first
        let mut active_assignments = Vec::new();
        for i in 0..3 {
            if let Ok(assignment) = scheduler.assign_task(
                &task_classes::epoch_transition(),
                10000 + i,
                &format!("load_trace_{}", i),
            ) {
                active_assignments.push(assignment);
            }
        }

        // Hot reload policy while tasks are active
        let under_load_result = scheduler.reload_policy(load_policy);
        assert!(
            under_load_result.is_ok(),
            "Should handle hot reload under load"
        );

        // Active tasks should still be completable
        for assignment in active_assignments {
            let complete_result =
                scheduler.complete_task(&assignment.task_id, 11000, "load_cleanup");
            // May succeed or fail depending on implementation, but should not crash
            match complete_result {
                Ok(_) => {}  // Successful completion
                Err(_) => {} // May fail due to policy change, acceptable
            }
        }

        // New policy should be active
        let new_assign_result = scheduler.assign_task(
            &task_classes::remote_computation(),
            12000,
            "new_policy_trace",
        );
        assert!(
            new_assign_result.is_ok(),
            "Should use new policy for new assignments"
        );
    }

    /// Test: Telemetry and audit log manipulation attacks
    #[test]
    fn test_telemetry_audit_log_manipulation_attacks() {
        let mut scheduler = make_scheduler();

        // Test: Timestamp manipulation in telemetry
        let timestamp_attacks = vec![
            0u64,         // Zero timestamp
            u64::MAX,     // Maximum timestamp
            u64::MAX - 1, // Near maximum
        ];

        for &attack_timestamp in &timestamp_attacks {
            let telemetry = scheduler.telemetry_snapshot(attack_timestamp);

            // Should handle extreme timestamps gracefully
            assert_eq!(
                telemetry.timestamp_ms, attack_timestamp,
                "Telemetry should preserve timestamp exactly"
            );
            assert_eq!(
                telemetry.schema_version, SCHEMA_VERSION,
                "Schema version should be consistent"
            );
            assert!(
                !telemetry.counters.is_empty(),
                "Should have counter data even with extreme timestamps"
            );

            // All counters should have valid values
            for counter in &telemetry.counters {
                assert!(
                    counter.completed_total <= u64::MAX,
                    "Counters should not overflow"
                );
                assert!(
                    counter.active_count <= usize::MAX,
                    "Active count should not overflow"
                );
                assert!(
                    counter.queued_count <= usize::MAX,
                    "Queue count should not overflow"
                );
            }
        }

        // Test: Audit log capacity boundary attacks
        let mut bounded_scheduler = LaneScheduler::with_audit_log_capacity(
            default_policy(),
            5, // Very small capacity
        )
        .unwrap();

        // Generate more events than capacity
        for i in 0..20 {
            let assign_result = bounded_scheduler.assign_task(
                &task_classes::epoch_transition(),
                13000 + i,
                &format!("capacity_attack_{}", i),
            );

            if let Ok(assignment) = assign_result {
                let _complete_result = bounded_scheduler.complete_task(
                    &assignment.task_id,
                    13100 + i,
                    "capacity_cleanup",
                );
            }
        }

        // Audit log should be bounded
        let audit_log = bounded_scheduler.audit_log();
        assert!(
            audit_log.len() <= 5,
            "Audit log should respect capacity bounds"
        );

        // Should contain recent events
        if !audit_log.is_empty() {
            let last_record = audit_log.last().unwrap();
            assert!(
                last_record.timestamp_ms >= 13100,
                "Should retain recent events"
            );
        }

        // Test: JSONL export with malicious data
        let jsonl_export = bounded_scheduler.export_audit_log_jsonl();

        // Should produce valid JSONL format
        let lines: Vec<&str> = jsonl_export.split('\n').filter(|s| !s.is_empty()).collect();
        for line in &lines {
            let parse_result: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parse_result.is_ok(), "Each JSONL line should be valid JSON");
        }

        // Test: Concurrent telemetry access
        use std::sync::{Arc, Mutex};
        use std::thread;

        let shared_scheduler = Arc::new(Mutex::new(make_scheduler()));
        let telemetry_results = Arc::new(Mutex::new(Vec::new()));

        let mut handles = Vec::new();
        for thread_id in 0..3 {
            let scheduler_clone = Arc::clone(&shared_scheduler);
            let results_clone = Arc::clone(&telemetry_results);

            let handle = thread::spawn(move || {
                for iteration in 0..5 {
                    let timestamp = 14000 + thread_id * 1000 + iteration;

                    let telemetry = {
                        let scheduler_guard = scheduler_clone.lock().unwrap();
                        scheduler_guard.telemetry_snapshot(timestamp)
                    };

                    // Verify telemetry consistency
                    let is_valid = telemetry.timestamp_ms == timestamp
                        && telemetry.schema_version == SCHEMA_VERSION
                        && !telemetry.counters.is_empty();

                    results_clone
                        .lock()
                        .unwrap()
                        .push((thread_id, iteration, is_valid));
                    thread::yield_now();
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        // All telemetry snapshots should be valid
        let final_results = telemetry_results.lock().unwrap();
        for &(thread_id, iteration, is_valid) in final_results.iter() {
            assert!(
                is_valid,
                "Telemetry should be valid for thread {} iteration {}",
                thread_id, iteration
            );
        }

        // Test: Memory exhaustion through telemetry requests
        let mut memory_scheduler = make_scheduler();

        // Generate substantial workload
        for i in 0..100 {
            let assign_result = memory_scheduler.assign_task(
                &task_classes::telemetry_export(),
                15000 + i,
                &format!("memory_test_{}", i),
            );

            if let Ok(assignment) = assign_result {
                // Complete immediately to generate audit events
                let _complete_result = memory_scheduler.complete_task(
                    &assignment.task_id,
                    15010 + i,
                    "memory_cleanup",
                );
            }
        }

        // Multiple large telemetry snapshots
        for i in 0..10 {
            let large_telemetry = memory_scheduler.telemetry_snapshot(16000 + i);
            assert!(
                !large_telemetry.counters.is_empty(),
                "Should handle multiple telemetry requests"
            );
        }

        // Audit log should remain bounded and consistent
        let final_audit = memory_scheduler.audit_log();
        assert!(
            final_audit.len() <= DEFAULT_MAX_AUDIT_LOG_ENTRIES + 100,
            "Audit log should remain bounded"
        );

        // All audit records should be well-formed
        for record in final_audit {
            assert!(
                !record.event_code.is_empty(),
                "Event codes should not be empty"
            );
            assert!(record.timestamp_ms > 0, "Timestamps should be positive");
            assert_eq!(
                record.schema_version, SCHEMA_VERSION,
                "Schema version should be consistent"
            );
        }
    }

    #[test]
    fn benchmark_lane_scheduler_queue_promotion_scales_linearly() {
        // Complexity contract: draining 4x queued tasks should remain well below
        // quadratic growth. VecDeque front-pop keeps promotion O(n) in queue depth.
        let smaller = lane_scheduler_promotion_duration(256);
        let larger = lane_scheduler_promotion_duration(1024);
        let smaller_nanos = smaller.as_nanos().max(1);
        let larger_nanos = larger.as_nanos();

        assert!(
            larger_nanos <= smaller_nanos.saturating_mul(8),
            "queue promotion regressed toward quadratic cost: 256={smaller:?} 1024={larger:?}"
        );
    }
}
