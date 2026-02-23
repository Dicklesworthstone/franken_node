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
use std::collections::BTreeMap;
use std::fmt;

/// Schema version for lane metrics exports.
pub const SCHEMA_VERSION: &str = "ls-v1.0";

/// Default starvation window in milliseconds.
pub const DEFAULT_STARVATION_WINDOW_MS: u64 = 5_000;

// ---- Event codes ----

pub mod event_codes {
    pub const LANE_ASSIGN: &str = "LANE_ASSIGN";
    pub const LANE_STARVED: &str = "LANE_STARVED";
    pub const LANE_MISCLASS: &str = "LANE_MISCLASS";
    pub const LANE_METRICS: &str = "LANE_METRICS";
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
    pub fn all() -> &'static [SchedulerLane] {
        &[
            Self::ControlCritical,
            Self::RemoteEffect,
            Self::Maintenance,
            Self::Background,
        ]
    }

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
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }

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
    pub fn new() -> Self {
        Self {
            lane_configs: BTreeMap::new(),
            mapping_rules: BTreeMap::new(),
        }
    }

    /// Add a lane configuration.
    pub fn add_lane(&mut self, config: LaneConfig) {
        self.lane_configs
            .insert(config.lane.as_str().to_string(), config);
    }

    /// Add a mapping rule.
    pub fn add_rule(&mut self, task_class: &TaskClass, lane: SchedulerLane) {
        self.mapping_rules
            .insert(task_class.as_str().to_string(), lane);
    }

    /// Look up the lane for a task class.
    /// INV-LANE-EXACT-MAP
    pub fn resolve(&self, task_class: &TaskClass) -> Option<SchedulerLane> {
        self.mapping_rules.get(task_class.as_str()).copied()
    }

    /// Validate policy: all lanes configured, all rules map to configured lanes.
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

    policy.add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 100, 8));
    policy.add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, 50, 32));
    policy.add_lane(LaneConfig::new(SchedulerLane::Maintenance, 20, 4));
    policy.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 2));

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
    pub completed_total: u64,
    pub rejected_total: u64,
    pub starvation_events: u64,
    pub last_completion_ms: Option<u64>,
}

impl LaneCounters {
    pub fn new(lane: SchedulerLane) -> Self {
        Self {
            lane,
            active_count: 0,
            queued_count: 0,
            completed_total: 0,
            rejected_total: 0,
            starvation_events: 0,
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
            Self::CapExceeded { lane, cap, current } => {
                write!(
                    f,
                    "{}: lane {} cap {} exceeded (current {})",
                    self.code(),
                    lane,
                    cap,
                    current
                )
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
pub struct LaneScheduler {
    policy: LaneMappingPolicy,
    counters: BTreeMap<String, LaneCounters>,
    active_tasks: BTreeMap<String, TaskAssignment>,
    audit_log: Vec<LaneAuditRecord>,
    task_counter: u64,
}

impl LaneScheduler {
    /// Create a new lane scheduler with the given policy.
    pub fn new(policy: LaneMappingPolicy) -> Result<Self, LaneSchedulerError> {
        if let Err(detail) = policy.validate() {
            return Err(LaneSchedulerError::InvalidPolicy { detail });
        }

        let mut counters = BTreeMap::new();
        for config in policy.lane_configs.values() {
            counters.insert(
                config.lane.as_str().to_string(),
                LaneCounters::new(config.lane),
            );
        }

        Ok(Self {
            policy,
            counters,
            active_tasks: BTreeMap::new(),
            audit_log: Vec::new(),
            task_counter: 0,
        })
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

        let config = &self.policy.lane_configs[lane.as_str()];
        let counters = self.counters.get_mut(lane.as_str()).ok_or_else(|| {
            LaneSchedulerError::UnknownLane {
                lane: lane.to_string(),
            }
        })?;

        // INV-LANE-CAP-ENFORCE
        if counters.active_count >= config.concurrency_cap {
            counters.queued_count += 1;
            return Err(LaneSchedulerError::CapExceeded {
                lane,
                cap: config.concurrency_cap,
                current: counters.active_count,
            });
        }

        // A newly admitted task consumes one pending queue slot, if any.
        if counters.queued_count > 0 {
            counters.queued_count -= 1;
        }
        self.task_counter = self.task_counter.saturating_add(1);
        let task_id = format!("task-{:08}", self.task_counter);

        counters.active_count += 1;

        let assignment = TaskAssignment {
            task_id: task_id.clone(),
            task_class: task_class.clone(),
            lane,
            assigned_at_ms: timestamp_ms,
            trace_id: trace_id.to_string(),
        };

        self.active_tasks
            .insert(task_id.clone(), assignment.clone());

        self.audit_log.push(LaneAuditRecord {
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
        counters.completed_total += 1;
        counters.last_completion_ms = Some(timestamp_ms);

        self.audit_log.push(LaneAuditRecord {
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

        Ok(assignment.lane)
    }

    /// Check for lane starvation.
    /// INV-LANE-STARVATION-DETECT
    pub fn check_starvation(&mut self, current_ms: u64, trace_id: &str) -> Vec<LaneSchedulerError> {
        let mut starved = Vec::new();

        // Collect starvation info first with immutable borrows
        let mut starvation_info: Vec<(SchedulerLane, usize, u64)> = Vec::new();
        for config in self.policy.lane_configs.values() {
            let counters = &self.counters[config.lane.as_str()];
            if counters.queued_count > 0 {
                let last = counters.last_completion_ms.unwrap_or(0);
                let elapsed = current_ms.saturating_sub(last);
                if elapsed >= config.starvation_window_ms {
                    starvation_info.push((config.lane, counters.queued_count, elapsed));
                }
            }
        }

        // Now apply mutations with the collected info
        for (lane, queue_depth, elapsed) in &starvation_info {
            let err = LaneSchedulerError::Starvation {
                lane: *lane,
                queue_depth: *queue_depth,
                elapsed_ms: *elapsed,
            };
            starved.push(err);

            if let Some(c) = self.counters.get_mut(lane.as_str()) {
                c.starvation_events += 1;
            }

            self.audit_log.push(LaneAuditRecord {
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

        // Add counters for any new lanes
        for config in new_policy.lane_configs.values() {
            self.counters
                .entry(config.lane.as_str().to_string())
                .or_insert_with(|| LaneCounters::new(config.lane));
        }

        self.policy = new_policy;
        Ok(())
    }

    /// Get current lane counters.
    /// INV-LANE-TELEMETRY-ACCURATE
    pub fn lane_counters(&self) -> &BTreeMap<String, LaneCounters> {
        &self.counters
    }

    /// Get counters for a specific lane.
    pub fn lane_counter(&self, lane: SchedulerLane) -> Option<&LaneCounters> {
        self.counters.get(lane.as_str())
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
        self.counters.values().map(|c| c.active_count).sum()
    }

    /// Total completed tasks across all lanes.
    pub fn total_completed(&self) -> u64 {
        self.counters.values().map(|c| c.completed_total).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scheduler() -> LaneScheduler {
        LaneScheduler::new(default_policy()).unwrap()
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
    fn default_policy_unknown_class_returns_none() {
        let p = default_policy();
        assert_eq!(p.resolve(&TaskClass::new("nonexistent")), None);
    }

    // ---- Policy validation ----

    #[test]
    fn empty_policy_invalid() {
        let p = LaneMappingPolicy::new();
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_with_unmapped_lane_invalid() {
        let mut p = LaneMappingPolicy::new();
        p.add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 100, 8));
        p.add_rule(
            &task_classes::epoch_transition(),
            SchedulerLane::RemoteEffect,
        );
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_with_zero_weight_invalid() {
        let mut p = LaneMappingPolicy::new();
        p.add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 0, 8));
        p.add_rule(
            &task_classes::epoch_transition(),
            SchedulerLane::ControlCritical,
        );
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_with_zero_cap_invalid() {
        let mut p = LaneMappingPolicy::new();
        p.add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 100, 0));
        p.add_rule(
            &task_classes::epoch_transition(),
            SchedulerLane::ControlCritical,
        );
        assert!(p.validate().is_err());
    }

    // ---- LaneScheduler construction ----

    #[test]
    fn scheduler_new_with_default_policy() {
        let s = make_scheduler();
        assert_eq!(s.total_active(), 0);
        assert_eq!(s.total_completed(), 0);
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
        p.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        s.assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        let err = s
            .assign_task(&task_classes::log_rotation(), 1001, "t2")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_LANE_CAP_EXCEEDED);
    }

    #[test]
    fn completion_does_not_drain_queue_depth_without_admission() {
        let mut p = LaneMappingPolicy::new();
        p.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        let active = s
            .assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        let _ = s.assign_task(&task_classes::log_rotation(), 1001, "t2");

        let before = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(before.queued_count, 1);

        s.complete_task(&active.task_id, 1002, "t3").unwrap();
        let after = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(after.queued_count, 1);
    }

    #[test]
    fn successful_assignment_drains_one_pending_queue_slot() {
        let mut p = LaneMappingPolicy::new();
        p.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 1));
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        let active = s
            .assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        let _ = s.assign_task(&task_classes::log_rotation(), 1001, "t2");
        let _ = s.assign_task(&task_classes::log_rotation(), 1002, "t3");
        let before = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(before.queued_count, 2);

        s.complete_task(&active.task_id, 1003, "t4").unwrap();
        let admitted = s
            .assign_task(&task_classes::log_rotation(), 1004, "t5")
            .unwrap();
        assert_eq!(admitted.lane, SchedulerLane::Background);

        let after = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(after.queued_count, 1);
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

    // ---- Starvation detection ----

    #[test]
    fn starvation_detected_when_queued_and_no_completions() {
        let mut p = LaneMappingPolicy::new();
        let mut cfg = LaneConfig::new(SchedulerLane::Background, 10, 1);
        cfg.starvation_window_ms = 100;
        p.add_lane(cfg);
        p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
        let mut s = LaneScheduler::new(p).unwrap();

        // Fill the lane
        s.assign_task(&task_classes::log_rotation(), 1000, "t1")
            .unwrap();
        // Try to assign another (will be rejected/queued)
        let _ = s.assign_task(&task_classes::log_rotation(), 1001, "t2");

        // Check starvation after window
        let starved = s.check_starvation(1200, "t3");
        assert!(!starved.is_empty());

        let counters = s.lane_counter(SchedulerLane::Background).unwrap();
        assert_eq!(counters.starvation_events, 1);
    }

    #[test]
    fn no_starvation_when_no_queue() {
        let mut s = make_scheduler();
        let starved = s.check_starvation(100000, "t1");
        assert!(starved.is_empty());
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

    // ---- Default trait ----

    #[test]
    fn default_policy_trait() {
        let p = LaneMappingPolicy::default();
        assert!(p.lane_configs.is_empty());
    }
}
