//! bd-cuut: Lane mapping policy for control-plane workloads.
//!
//! Maps control-plane task classes to three lane categories:
//! - Cancel: cancellation handlers, drain operations, region close (highest priority)
//! - Timed: health checks, lease renewals, epoch transitions (deadline-bound)
//! - Ready: background maintenance, telemetry flush, evidence archival (best-effort)
//!
//! Budget allocation: Cancel >= 20%, Timed >= 30%, Ready = remainder.
//!
//! # Invariants
//!
//! - INV-CLM-COMPLETE-MAP: every control-plane task class has a lane assignment
//! - INV-CLM-BUDGET-SUM: budget allocations sum to 100%
//! - INV-CLM-CANCEL-PRIORITY: cancel-lane tasks scheduled before ready-lane when both pending
//! - INV-CLM-STARVATION-DETECT: no lane receives zero slots for > threshold ticks
//! - INV-CLM-CANCEL-MIN-BUDGET: cancel lane gets >= 20% of capacity
//! - INV-CLM-TIMED-MIN-BUDGET: timed lane gets >= 30% of capacity

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Schema version for lane mapping exports.
pub const SCHEMA_VERSION: &str = "clm-v1.0";

/// Default starvation threshold in ticks.
pub const DEFAULT_STARVATION_THRESHOLD_TICKS: u32 = 3;

// ---- Event codes ----

pub mod event_codes {
    pub const CLM_TASK_ASSIGNED: &str = "CLM_TASK_ASSIGNED";
    pub const CLM_STARVATION_ALERT: &str = "CLM_STARVATION_ALERT";
    pub const CLM_BUDGET_VIOLATION: &str = "CLM_BUDGET_VIOLATION";
    pub const CLM_POLICY_LOADED: &str = "CLM_POLICY_LOADED";
    pub const CLM_PRIORITY_OVERRIDE: &str = "CLM_PRIORITY_OVERRIDE";
    pub const CLM_TICK_COMPLETE: &str = "CLM_TICK_COMPLETE";
    pub const CLM_METRICS_EXPORTED: &str = "CLM_METRICS_EXPORTED";
    pub const CLM_STARVATION_CLEARED: &str = "CLM_STARVATION_CLEARED";
}

// ---- Error codes ----

pub mod error_codes {
    pub const ERR_CLM_UNKNOWN_TASK: &str = "ERR_CLM_UNKNOWN_TASK";
    pub const ERR_CLM_BUDGET_OVERFLOW: &str = "ERR_CLM_BUDGET_OVERFLOW";
    pub const ERR_CLM_STARVATION: &str = "ERR_CLM_STARVATION";
    pub const ERR_CLM_INVALID_BUDGET: &str = "ERR_CLM_INVALID_BUDGET";
    pub const ERR_CLM_DUPLICATE_TASK: &str = "ERR_CLM_DUPLICATE_TASK";
    pub const ERR_CLM_INCOMPLETE_MAP: &str = "ERR_CLM_INCOMPLETE_MAP";
}

// ---- Core types ----

/// Control-plane lane categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ControlLane {
    /// Cancellation handlers, drain, region close. Highest priority.
    Cancel,
    /// Health checks, lease renewals, epoch transitions. Deadline-bound.
    Timed,
    /// Background maintenance, telemetry, evidence archival. Best-effort.
    Ready,
}

impl ControlLane {
    pub fn all() -> &'static [ControlLane] {
        &[Self::Cancel, Self::Timed, Self::Ready]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cancel => "cancel",
            Self::Timed => "timed",
            Self::Ready => "ready",
        }
    }

    /// Priority rank (lower = higher priority).
    pub fn priority_rank(&self) -> u32 {
        match self {
            Self::Cancel => 0,
            Self::Timed => 1,
            Self::Ready => 2,
        }
    }
}

impl fmt::Display for ControlLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Control-plane task class.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ControlTaskClass(pub String);

impl ControlTaskClass {
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ControlTaskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Well-known control-plane task classes.
pub mod task_classes {
    use super::ControlTaskClass;

    // Cancel lane
    pub fn cancellation_handler() -> ControlTaskClass {
        ControlTaskClass::new("cancellation_handler")
    }
    pub fn drain_operation() -> ControlTaskClass {
        ControlTaskClass::new("drain_operation")
    }
    pub fn region_close() -> ControlTaskClass {
        ControlTaskClass::new("region_close")
    }
    pub fn shutdown_handler() -> ControlTaskClass {
        ControlTaskClass::new("shutdown_handler")
    }

    // Timed lane
    pub fn health_check() -> ControlTaskClass {
        ControlTaskClass::new("health_check")
    }
    pub fn lease_renewal() -> ControlTaskClass {
        ControlTaskClass::new("lease_renewal")
    }
    pub fn epoch_transition() -> ControlTaskClass {
        ControlTaskClass::new("epoch_transition")
    }
    pub fn barrier_coordination() -> ControlTaskClass {
        ControlTaskClass::new("barrier_coordination")
    }
    pub fn marker_append() -> ControlTaskClass {
        ControlTaskClass::new("marker_append")
    }

    // Ready lane
    pub fn telemetry_flush() -> ControlTaskClass {
        ControlTaskClass::new("telemetry_flush")
    }
    pub fn evidence_archival() -> ControlTaskClass {
        ControlTaskClass::new("evidence_archival")
    }
    pub fn compaction() -> ControlTaskClass {
        ControlTaskClass::new("compaction")
    }
    pub fn garbage_collection() -> ControlTaskClass {
        ControlTaskClass::new("garbage_collection")
    }
    pub fn log_rotation() -> ControlTaskClass {
        ControlTaskClass::new("log_rotation")
    }
}

/// Budget allocation for a lane (percentage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneBudget {
    pub lane: ControlLane,
    pub min_percent: u32,
    pub starvation_threshold_ticks: u32,
}

/// Complete lane mapping policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlLanePolicy {
    pub assignments: BTreeMap<String, ControlLane>,
    pub budgets: BTreeMap<String, LaneBudget>,
}

impl ControlLanePolicy {
    pub fn new() -> Self {
        Self {
            assignments: BTreeMap::new(),
            budgets: BTreeMap::new(),
        }
    }

    /// Assign a task class to a lane.
    pub fn assign(&mut self, task_class: &ControlTaskClass, lane: ControlLane) {
        self.assignments
            .insert(task_class.as_str().to_string(), lane);
    }

    /// Set budget for a lane.
    pub fn set_budget(&mut self, budget: LaneBudget) {
        self.budgets
            .insert(budget.lane.as_str().to_string(), budget);
    }

    /// Resolve a task class to its lane.
    /// INV-CLM-COMPLETE-MAP
    pub fn resolve(&self, task_class: &ControlTaskClass) -> Option<ControlLane> {
        self.assignments.get(task_class.as_str()).copied()
    }

    /// Validate the policy.
    /// INV-CLM-BUDGET-SUM, INV-CLM-CANCEL-MIN-BUDGET, INV-CLM-TIMED-MIN-BUDGET
    pub fn validate(&self) -> Result<(), ControlLanePolicyError> {
        if self.assignments.is_empty() {
            return Err(ControlLanePolicyError::IncompleteMap {
                detail: "no task assignments".into(),
            });
        }

        // Check budget sum
        let total: u32 = self.budgets.values().map(|b| b.min_percent).sum();
        if total > 100 {
            return Err(ControlLanePolicyError::BudgetOverflow {
                total_percent: total,
            });
        }

        // INV-CLM-CANCEL-MIN-BUDGET
        if let Some(cancel) = self.budgets.get("cancel")
            && cancel.min_percent < 20
        {
            return Err(ControlLanePolicyError::InvalidBudget {
                lane: ControlLane::Cancel,
                detail: format!("cancel budget {}% < 20% minimum", cancel.min_percent),
            });
        }

        // INV-CLM-TIMED-MIN-BUDGET
        if let Some(timed) = self.budgets.get("timed")
            && timed.min_percent < 30
        {
            return Err(ControlLanePolicyError::InvalidBudget {
                lane: ControlLane::Timed,
                detail: format!("timed budget {}% < 30% minimum", timed.min_percent),
            });
        }

        Ok(())
    }
}

impl Default for ControlLanePolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the standard control-plane lane policy.
pub fn default_control_lane_policy() -> ControlLanePolicy {
    let mut policy = ControlLanePolicy::new();

    // Cancel lane tasks
    policy.assign(&task_classes::cancellation_handler(), ControlLane::Cancel);
    policy.assign(&task_classes::drain_operation(), ControlLane::Cancel);
    policy.assign(&task_classes::region_close(), ControlLane::Cancel);
    policy.assign(&task_classes::shutdown_handler(), ControlLane::Cancel);

    // Timed lane tasks
    policy.assign(&task_classes::health_check(), ControlLane::Timed);
    policy.assign(&task_classes::lease_renewal(), ControlLane::Timed);
    policy.assign(&task_classes::epoch_transition(), ControlLane::Timed);
    policy.assign(&task_classes::barrier_coordination(), ControlLane::Timed);
    policy.assign(&task_classes::marker_append(), ControlLane::Timed);

    // Ready lane tasks
    policy.assign(&task_classes::telemetry_flush(), ControlLane::Ready);
    policy.assign(&task_classes::evidence_archival(), ControlLane::Ready);
    policy.assign(&task_classes::compaction(), ControlLane::Ready);
    policy.assign(&task_classes::garbage_collection(), ControlLane::Ready);
    policy.assign(&task_classes::log_rotation(), ControlLane::Ready);

    // Budget allocations
    policy.set_budget(LaneBudget {
        lane: ControlLane::Cancel,
        min_percent: 20,
        starvation_threshold_ticks: 1,
    });
    policy.set_budget(LaneBudget {
        lane: ControlLane::Timed,
        min_percent: 30,
        starvation_threshold_ticks: 2,
    });
    policy.set_budget(LaneBudget {
        lane: ControlLane::Ready,
        min_percent: 50,
        starvation_threshold_ticks: DEFAULT_STARVATION_THRESHOLD_TICKS,
    });

    policy
}

/// Per-lane tick counters for starvation detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneTickCounters {
    pub lane: ControlLane,
    pub tasks_run: u64,
    pub tasks_queued: u64,
    pub consecutive_empty_ticks: u32,
    pub starvation_alerts: u64,
}

impl LaneTickCounters {
    pub fn new(lane: ControlLane) -> Self {
        Self {
            lane,
            tasks_run: 0,
            tasks_queued: 0,
            consecutive_empty_ticks: 0,
            starvation_alerts: 0,
        }
    }
}

/// Starvation metrics snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarvationMetrics {
    pub tick: u64,
    pub cancel_tasks_run: u64,
    pub timed_tasks_run: u64,
    pub ready_tasks_run: u64,
    pub cancel_starved: bool,
    pub timed_starved: bool,
    pub ready_starved: bool,
}

/// Policy errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlLanePolicyError {
    UnknownTask {
        task_class: String,
    },
    BudgetOverflow {
        total_percent: u32,
    },
    Starvation {
        lane: ControlLane,
        consecutive_ticks: u32,
    },
    InvalidBudget {
        lane: ControlLane,
        detail: String,
    },
    DuplicateTask {
        task_class: String,
    },
    IncompleteMap {
        detail: String,
    },
}

impl ControlLanePolicyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownTask { .. } => error_codes::ERR_CLM_UNKNOWN_TASK,
            Self::BudgetOverflow { .. } => error_codes::ERR_CLM_BUDGET_OVERFLOW,
            Self::Starvation { .. } => error_codes::ERR_CLM_STARVATION,
            Self::InvalidBudget { .. } => error_codes::ERR_CLM_INVALID_BUDGET,
            Self::DuplicateTask { .. } => error_codes::ERR_CLM_DUPLICATE_TASK,
            Self::IncompleteMap { .. } => error_codes::ERR_CLM_INCOMPLETE_MAP,
        }
    }
}

impl fmt::Display for ControlLanePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTask { task_class } => {
                write!(f, "{}: {}", self.code(), task_class)
            }
            Self::BudgetOverflow { total_percent } => {
                write!(f, "{}: total={}%", self.code(), total_percent)
            }
            Self::Starvation {
                lane,
                consecutive_ticks,
            } => {
                write!(
                    f,
                    "{}: {} starved for {} ticks",
                    self.code(),
                    lane,
                    consecutive_ticks
                )
            }
            Self::InvalidBudget { lane, detail } => {
                write!(f, "{}: {} {}", self.code(), lane, detail)
            }
            Self::DuplicateTask { task_class } => {
                write!(f, "{}: {}", self.code(), task_class)
            }
            Self::IncompleteMap { detail } => {
                write!(f, "{}: {}", self.code(), detail)
            }
        }
    }
}

/// Audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlLaneAuditRecord {
    pub event_code: String,
    pub task_class: String,
    pub lane: String,
    pub timestamp_ms: u64,
    pub detail: String,
    pub trace_id: String,
    pub schema_version: String,
}

/// The control-plane lane scheduler.
pub struct ControlLaneScheduler {
    policy: ControlLanePolicy,
    counters: BTreeMap<String, LaneTickCounters>,
    audit_log: Vec<ControlLaneAuditRecord>,
    current_tick: u64,
}

impl ControlLaneScheduler {
    /// Create a new scheduler with the given policy.
    pub fn new(policy: ControlLanePolicy) -> Result<Self, ControlLanePolicyError> {
        policy.validate()?;

        let mut counters = BTreeMap::new();
        for lane in ControlLane::all() {
            counters.insert(lane.as_str().to_string(), LaneTickCounters::new(*lane));
        }

        Ok(Self {
            policy,
            counters,
            audit_log: Vec::new(),
            current_tick: 0,
        })
    }

    /// Assign a task to its lane.
    /// INV-CLM-COMPLETE-MAP, INV-CLM-CANCEL-PRIORITY
    pub fn assign_task(
        &mut self,
        task_class: &ControlTaskClass,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<ControlLane, ControlLanePolicyError> {
        let lane =
            self.policy
                .resolve(task_class)
                .ok_or_else(|| ControlLanePolicyError::UnknownTask {
                    task_class: task_class.to_string(),
                })?;

        let counters = self.counters.get_mut(lane.as_str()).unwrap();
        counters.tasks_run += 1;
        counters.consecutive_empty_ticks = 0;

        self.audit_log.push(ControlLaneAuditRecord {
            event_code: event_codes::CLM_TASK_ASSIGNED.to_string(),
            task_class: task_class.to_string(),
            lane: lane.to_string(),
            timestamp_ms,
            detail: format!("assigned to {}", lane),
            trace_id: trace_id.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        });

        Ok(lane)
    }

    /// Advance a tick and check for starvation.
    /// INV-CLM-STARVATION-DETECT
    pub fn advance_tick(
        &mut self,
        tasks_by_lane: &BTreeMap<String, u64>,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Vec<ControlLanePolicyError> {
        self.current_tick += 1;
        let mut alerts = Vec::new();

        for lane in ControlLane::all() {
            let lane_key = lane.as_str().to_string();
            let tasks_run = tasks_by_lane.get(&lane_key).copied().unwrap_or(0);
            let counters = self.counters.get_mut(&lane_key).unwrap();

            if tasks_run == 0 && counters.tasks_queued > 0 {
                counters.consecutive_empty_ticks += 1;
            } else {
                counters.consecutive_empty_ticks = 0;
            }
            counters.tasks_run += tasks_run;

            if let Some(budget) = self.policy.budgets.get(&lane_key)
                && counters.consecutive_empty_ticks >= budget.starvation_threshold_ticks
            {
                counters.starvation_alerts += 1;
                alerts.push(ControlLanePolicyError::Starvation {
                    lane: *lane,
                    consecutive_ticks: counters.consecutive_empty_ticks,
                });
                self.audit_log.push(ControlLaneAuditRecord {
                    event_code: event_codes::CLM_STARVATION_ALERT.to_string(),
                    task_class: String::new(),
                    lane: lane.to_string(),
                    timestamp_ms,
                    detail: format!("starved for {} ticks", counters.consecutive_empty_ticks),
                    trace_id: trace_id.to_string(),
                    schema_version: SCHEMA_VERSION.to_string(),
                });
            }
        }

        alerts
    }

    /// Get starvation metrics for current tick.
    pub fn starvation_metrics(&self) -> StarvationMetrics {
        let cancel = &self.counters["cancel"];
        let timed = &self.counters["timed"];
        let ready = &self.counters["ready"];

        let cancel_thresh = self
            .policy
            .budgets
            .get("cancel")
            .map(|b| b.starvation_threshold_ticks)
            .unwrap_or(1);
        let timed_thresh = self
            .policy
            .budgets
            .get("timed")
            .map(|b| b.starvation_threshold_ticks)
            .unwrap_or(2);
        let ready_thresh = self
            .policy
            .budgets
            .get("ready")
            .map(|b| b.starvation_threshold_ticks)
            .unwrap_or(3);

        StarvationMetrics {
            tick: self.current_tick,
            cancel_tasks_run: cancel.tasks_run,
            timed_tasks_run: timed.tasks_run,
            ready_tasks_run: ready.tasks_run,
            cancel_starved: cancel.consecutive_empty_ticks >= cancel_thresh,
            timed_starved: timed.consecutive_empty_ticks >= timed_thresh,
            ready_starved: ready.consecutive_empty_ticks >= ready_thresh,
        }
    }

    /// Export starvation metrics as CSV row.
    pub fn starvation_metrics_csv_row(&self) -> String {
        let m = self.starvation_metrics();
        format!(
            "{},{},{},{},{},{},{}",
            m.tick,
            m.cancel_tasks_run,
            m.timed_tasks_run,
            m.ready_tasks_run,
            m.cancel_starved as u8,
            m.timed_starved as u8,
            m.ready_starved as u8,
        )
    }

    /// Get policy.
    pub fn policy(&self) -> &ControlLanePolicy {
        &self.policy
    }

    /// Get audit log.
    pub fn audit_log(&self) -> &[ControlLaneAuditRecord] {
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

    /// Get lane counters.
    pub fn counters(&self) -> &BTreeMap<String, LaneTickCounters> {
        &self.counters
    }

    /// Set queued count for a lane (for starvation detection).
    pub fn set_queued(&mut self, lane: ControlLane, count: u64) {
        if let Some(c) = self.counters.get_mut(lane.as_str()) {
            c.tasks_queued = count;
        }
    }
}

/// Select which lane to schedule next based on priority.
/// INV-CLM-CANCEL-PRIORITY
pub fn select_next_lane(pending: &BTreeMap<ControlLane, usize>) -> Option<ControlLane> {
    let mut best: Option<ControlLane> = None;
    for (lane, count) in pending {
        if *count == 0 {
            continue;
        }
        match best {
            None => best = Some(*lane),
            Some(current) => {
                if lane.priority_rank() < current.priority_rank() {
                    best = Some(*lane);
                }
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scheduler() -> ControlLaneScheduler {
        ControlLaneScheduler::new(default_control_lane_policy()).unwrap()
    }

    // ---- ControlLane ----

    #[test]
    fn control_lane_all_has_three() {
        assert_eq!(ControlLane::all().len(), 3);
    }

    #[test]
    fn control_lane_display() {
        assert_eq!(ControlLane::Cancel.to_string(), "cancel");
        assert_eq!(ControlLane::Timed.to_string(), "timed");
        assert_eq!(ControlLane::Ready.to_string(), "ready");
    }

    #[test]
    fn cancel_has_highest_priority() {
        assert!(ControlLane::Cancel.priority_rank() < ControlLane::Timed.priority_rank());
        assert!(ControlLane::Timed.priority_rank() < ControlLane::Ready.priority_rank());
    }

    // ---- Default policy ----

    #[test]
    fn default_policy_is_valid() {
        let p = default_control_lane_policy();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn default_policy_has_14_assignments() {
        let p = default_control_lane_policy();
        assert_eq!(p.assignments.len(), 14);
    }

    #[test]
    fn default_policy_has_3_budgets() {
        let p = default_control_lane_policy();
        assert_eq!(p.budgets.len(), 3);
    }

    #[test]
    fn default_policy_budget_sum_is_100() {
        let p = default_control_lane_policy();
        let total: u32 = p.budgets.values().map(|b| b.min_percent).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn cancel_budget_at_least_20() {
        let p = default_control_lane_policy();
        let cancel = p.budgets.get("cancel").unwrap();
        assert!(cancel.min_percent >= 20);
    }

    #[test]
    fn timed_budget_at_least_30() {
        let p = default_control_lane_policy();
        let timed = p.budgets.get("timed").unwrap();
        assert!(timed.min_percent >= 30);
    }

    // ---- Lane assignments ----

    #[test]
    fn cancel_tasks_map_correctly() {
        let p = default_control_lane_policy();
        assert_eq!(
            p.resolve(&task_classes::cancellation_handler()),
            Some(ControlLane::Cancel)
        );
        assert_eq!(
            p.resolve(&task_classes::drain_operation()),
            Some(ControlLane::Cancel)
        );
        assert_eq!(
            p.resolve(&task_classes::region_close()),
            Some(ControlLane::Cancel)
        );
        assert_eq!(
            p.resolve(&task_classes::shutdown_handler()),
            Some(ControlLane::Cancel)
        );
    }

    #[test]
    fn timed_tasks_map_correctly() {
        let p = default_control_lane_policy();
        assert_eq!(
            p.resolve(&task_classes::health_check()),
            Some(ControlLane::Timed)
        );
        assert_eq!(
            p.resolve(&task_classes::lease_renewal()),
            Some(ControlLane::Timed)
        );
        assert_eq!(
            p.resolve(&task_classes::epoch_transition()),
            Some(ControlLane::Timed)
        );
        assert_eq!(
            p.resolve(&task_classes::barrier_coordination()),
            Some(ControlLane::Timed)
        );
        assert_eq!(
            p.resolve(&task_classes::marker_append()),
            Some(ControlLane::Timed)
        );
    }

    #[test]
    fn ready_tasks_map_correctly() {
        let p = default_control_lane_policy();
        assert_eq!(
            p.resolve(&task_classes::telemetry_flush()),
            Some(ControlLane::Ready)
        );
        assert_eq!(
            p.resolve(&task_classes::evidence_archival()),
            Some(ControlLane::Ready)
        );
        assert_eq!(
            p.resolve(&task_classes::compaction()),
            Some(ControlLane::Ready)
        );
        assert_eq!(
            p.resolve(&task_classes::garbage_collection()),
            Some(ControlLane::Ready)
        );
        assert_eq!(
            p.resolve(&task_classes::log_rotation()),
            Some(ControlLane::Ready)
        );
    }

    #[test]
    fn unknown_task_returns_none() {
        let p = default_control_lane_policy();
        assert_eq!(p.resolve(&ControlTaskClass::new("unknown")), None);
    }

    // ---- Policy validation ----

    #[test]
    fn empty_policy_invalid() {
        let p = ControlLanePolicy::new();
        assert!(p.validate().is_err());
    }

    #[test]
    fn budget_overflow_detected() {
        let mut p = ControlLanePolicy::new();
        p.assign(&task_classes::cancellation_handler(), ControlLane::Cancel);
        p.set_budget(LaneBudget {
            lane: ControlLane::Cancel,
            min_percent: 60,
            starvation_threshold_ticks: 1,
        });
        p.set_budget(LaneBudget {
            lane: ControlLane::Timed,
            min_percent: 50,
            starvation_threshold_ticks: 2,
        });
        let err = p.validate().unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLM_BUDGET_OVERFLOW);
    }

    #[test]
    fn cancel_below_20_percent_rejected() {
        let mut p = ControlLanePolicy::new();
        p.assign(&task_classes::cancellation_handler(), ControlLane::Cancel);
        p.set_budget(LaneBudget {
            lane: ControlLane::Cancel,
            min_percent: 10,
            starvation_threshold_ticks: 1,
        });
        let err = p.validate().unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLM_INVALID_BUDGET);
    }

    #[test]
    fn timed_below_30_percent_rejected() {
        let mut p = ControlLanePolicy::new();
        p.assign(&task_classes::cancellation_handler(), ControlLane::Cancel);
        p.set_budget(LaneBudget {
            lane: ControlLane::Cancel,
            min_percent: 20,
            starvation_threshold_ticks: 1,
        });
        p.set_budget(LaneBudget {
            lane: ControlLane::Timed,
            min_percent: 20,
            starvation_threshold_ticks: 2,
        });
        let err = p.validate().unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLM_INVALID_BUDGET);
    }

    // ---- Scheduler ----

    #[test]
    fn scheduler_assigns_cancel_task() {
        let mut s = make_scheduler();
        let lane = s
            .assign_task(&task_classes::cancellation_handler(), 1000, "t1")
            .unwrap();
        assert_eq!(lane, ControlLane::Cancel);
    }

    #[test]
    fn scheduler_rejects_unknown_task() {
        let mut s = make_scheduler();
        let err = s
            .assign_task(&ControlTaskClass::new("unknown"), 1000, "t1")
            .unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLM_UNKNOWN_TASK);
    }

    // ---- Starvation detection ----

    #[test]
    fn starvation_detected_after_threshold() {
        let mut s = make_scheduler();
        s.set_queued(ControlLane::Cancel, 5);

        let empty_tick: BTreeMap<String, u64> = BTreeMap::new();
        let alerts = s.advance_tick(&empty_tick, 1000, "t1");
        // Cancel threshold is 1 tick, so first empty tick triggers
        assert!(!alerts.is_empty());
    }

    #[test]
    fn no_starvation_when_tasks_run() {
        let mut s = make_scheduler();
        let mut tick = BTreeMap::new();
        tick.insert("cancel".to_string(), 1);
        tick.insert("timed".to_string(), 1);
        tick.insert("ready".to_string(), 1);
        let alerts = s.advance_tick(&tick, 1000, "t1");
        assert!(alerts.is_empty());
    }

    // ---- Priority selection ----

    #[test]
    fn cancel_selected_over_ready() {
        let mut pending = BTreeMap::new();
        pending.insert(ControlLane::Cancel, 1);
        pending.insert(ControlLane::Ready, 5);
        assert_eq!(select_next_lane(&pending), Some(ControlLane::Cancel));
    }

    #[test]
    fn timed_selected_over_ready() {
        let mut pending = BTreeMap::new();
        pending.insert(ControlLane::Timed, 1);
        pending.insert(ControlLane::Ready, 5);
        assert_eq!(select_next_lane(&pending), Some(ControlLane::Timed));
    }

    #[test]
    fn empty_pending_returns_none() {
        let pending = BTreeMap::new();
        assert_eq!(select_next_lane(&pending), None);
    }

    // ---- Metrics ----

    #[test]
    fn starvation_metrics_snapshot() {
        let s = make_scheduler();
        let m = s.starvation_metrics();
        assert_eq!(m.tick, 0);
        assert!(!m.cancel_starved);
    }

    #[test]
    fn csv_row_format() {
        let s = make_scheduler();
        let row = s.starvation_metrics_csv_row();
        assert_eq!(row.split(',').count(), 7);
    }

    // ---- Audit log ----

    #[test]
    fn audit_records_assignment() {
        let mut s = make_scheduler();
        s.assign_task(&task_classes::cancellation_handler(), 1000, "t1")
            .unwrap();
        assert_eq!(s.audit_log().len(), 1);
        assert_eq!(s.audit_log()[0].event_code, event_codes::CLM_TASK_ASSIGNED);
    }

    #[test]
    fn audit_export_jsonl() {
        let mut s = make_scheduler();
        s.assign_task(&task_classes::cancellation_handler(), 1000, "t1")
            .unwrap();
        let jsonl = s.export_audit_log_jsonl();
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }

    // ---- Error display ----

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<ControlLanePolicyError> = vec![
            ControlLanePolicyError::UnknownTask {
                task_class: "x".into(),
            },
            ControlLanePolicyError::BudgetOverflow { total_percent: 110 },
            ControlLanePolicyError::Starvation {
                lane: ControlLane::Cancel,
                consecutive_ticks: 5,
            },
            ControlLanePolicyError::InvalidBudget {
                lane: ControlLane::Timed,
                detail: "bad".into(),
            },
            ControlLanePolicyError::DuplicateTask {
                task_class: "x".into(),
            },
            ControlLanePolicyError::IncompleteMap {
                detail: "bad".into(),
            },
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(s.contains(e.code()), "{:?} should contain {}", e, e.code());
        }
    }
}
