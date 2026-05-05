//! bd-cuut: Lane mapping policy for control-plane workloads (Cancel/Timed/Ready).
//!
//! Defines the three lane classes for all control-plane task types with explicit
//! priority, budget policies, and starvation detection thresholds. Builds on the
//! canonical lane-aware scheduler (bd-qlc6, Section 10.14).
//!
//! # Lane Classes
//!
//! - **Cancel**: cancellation handlers, drain operations, region close — highest
//!   priority, guaranteed ≥20% of scheduler capacity.
//! - **Timed**: health checks, lease renewals, epoch transitions — deadline-bound
//!   with timeout enforcement, guaranteed ≥30% of scheduler capacity.
//! - **Ready**: background maintenance, telemetry flush, evidence archival —
//!   best-effort with starvation floor, receives remainder of capacity.
//!
//! # Invariants
//!
//! - INV-CLP-LANE-ASSIGNED: every control-plane task class has a lane assignment
//! - INV-CLP-BUDGET-SUM: lane budget allocations sum to 100%
//! - INV-CLP-CANCEL-PRIORITY: cancel-lane tasks scheduled before ready-lane when both pending
//! - INV-CLP-STARVATION-DETECT: starvation detected if zero slots for N consecutive ticks
//! - INV-CLP-CANCEL-NO-STARVE: cancel lane never starved for more than 1 tick
//! - INV-CLP-PREEMPT: tasks exceeding lane budget are preempted
//! - INV-CLP-TIMED-DEADLINE: deadline-bound lanes fail closed at deadline expiry

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Schema version for control lane policy exports.
pub const SCHEMA_VERSION: &str = "clp-v1.0";

/// Minimum budget percentage for Cancel lane.
pub const CANCEL_LANE_BUDGET_PCT: u8 = 20;

/// Minimum budget percentage for Timed lane.
pub const TIMED_LANE_BUDGET_PCT: u8 = 30;

/// Remainder budget percentage for Ready lane.
pub const READY_LANE_BUDGET_PCT: u8 = 50;

/// Default starvation threshold in consecutive ticks with zero scheduling slots.
pub const DEFAULT_STARVATION_THRESHOLD_TICKS: u32 = 3;

/// Cancel lane maximum starvation tolerance (ticks).
pub const CANCEL_MAX_STARVE_TICKS: u32 = 1;

/// Default maximum entries retained in tick history.
pub const DEFAULT_MAX_TICK_HISTORY_ENTRIES: usize = 4096;

/// Default maximum starvation events retained.
pub const DEFAULT_MAX_STARVATION_EVENTS: usize = 4096;

/// Default maximum preemption events retained.
pub const DEFAULT_MAX_PREEMPTION_EVENTS: usize = 4096;

/// Default maximum audit-log entries retained.
pub const DEFAULT_MAX_AUDIT_LOG_ENTRIES: usize = 4096;

/// Default maximum queued deadline-aware tasks retained.
pub const DEFAULT_MAX_DEADLINE_QUEUE_ENTRIES: usize = 4096;
/// Number of schedulable control-plane task classes in the canonical policy table.
pub const CONTROL_TASK_CLASS_COUNT: usize = 19;
const MAX_TASK_ID_BYTES: usize = 256;

fn invalid_task_id_reason(task_id: &str) -> Option<String> {
    let trimmed = task_id.trim();
    if trimmed.is_empty() {
        return Some("task id must not be empty".to_string());
    }
    if trimmed != task_id {
        return Some("task id must not contain leading or trailing whitespace".to_string());
    }
    if task_id.chars().any(|ch| ch.is_control()) {
        return Some("task id must not contain control characters".to_string());
    }
    if task_id.len() > MAX_TASK_ID_BYTES {
        return Some(format!("task id must not exceed {MAX_TASK_ID_BYTES} bytes"));
    }
    None
}

// ---- Event codes ----

pub mod event_codes {
    /// Task assigned to a control-plane lane.
    pub const LAN_001: &str = "LAN-001";
    /// Lane budget enforced (task scheduled within budget).
    pub const LAN_002: &str = "LAN-002";
    /// Starvation detected for a lane.
    pub const LAN_003: &str = "LAN-003";
    /// Starvation resolved for a lane.
    pub const LAN_004: &str = "LAN-004";
    /// Task preempted for lane budget enforcement.
    pub const LAN_005: &str = "LAN-005";
    /// Task timed out at or beyond its lane deadline.
    pub const LAN_006: &str = "LAN-006";
}

// ---- Error codes ----

pub mod error_codes {
    pub const ERR_CLP_UNKNOWN_TASK: &str = "ERR_CLP_UNKNOWN_TASK";
    pub const ERR_CLP_BUDGET_OVERFLOW: &str = "ERR_CLP_BUDGET_OVERFLOW";
    pub const ERR_CLP_STARVATION: &str = "ERR_CLP_STARVATION";
    pub const ERR_CLP_PREEMPT_FAIL: &str = "ERR_CLP_PREEMPT_FAIL";
    pub const ERR_CLP_CANCEL_STARVED: &str = "ERR_CLP_CANCEL_STARVED";
    pub const ERR_CLP_INVALID_BUDGET: &str = "ERR_CLP_INVALID_BUDGET";
    pub const ERR_CLP_DUPLICATE_CLASS: &str = "ERR_CLP_DUPLICATE_CLASS";
    pub const ERR_CLP_POLICY_MISMATCH: &str = "ERR_CLP_POLICY_MISMATCH";
    pub const ERR_CLP_INVALID_TASK_ID: &str = "ERR_CLP_INVALID_TASK_ID";
    pub const ERR_CLP_DEADLINE_QUEUE_FULL: &str = "ERR_CLP_DEADLINE_QUEUE_FULL";
}

// ---- Core types ----

/// Control-plane lane classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ControlLane {
    /// Cancellation handlers, drain operations, region close.
    /// Highest priority, guaranteed ≥20% capacity.
    Cancel,
    /// Health checks, lease renewals, epoch transitions.
    /// Deadline-bound with timeout enforcement, guaranteed ≥30%.
    Timed,
    /// Background maintenance, telemetry flush, evidence archival.
    /// Best-effort with starvation floor, receives remainder.
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

    /// Priority ordering (lower = higher priority).
    pub fn priority(&self) -> u8 {
        match self {
            Self::Cancel => 0,
            Self::Timed => 1,
            Self::Ready => 2,
        }
    }

    /// Minimum budget percentage for this lane.
    pub fn min_budget_pct(&self) -> u8 {
        match self {
            Self::Cancel => CANCEL_LANE_BUDGET_PCT,
            Self::Timed => TIMED_LANE_BUDGET_PCT,
            Self::Ready => READY_LANE_BUDGET_PCT,
        }
    }

    /// Maximum starvation tolerance in consecutive ticks.
    pub fn max_starve_ticks(&self) -> u32 {
        match self {
            Self::Cancel => CANCEL_MAX_STARVE_TICKS,
            Self::Timed => DEFAULT_STARVATION_THRESHOLD_TICKS,
            Self::Ready => DEFAULT_STARVATION_THRESHOLD_TICKS,
        }
    }
}

impl fmt::Display for ControlLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Control-plane task class — enumeration of all schedulable work types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ControlTaskClass {
    // Cancel lane tasks
    CancellationHandler,
    DrainOperation,
    RegionClose,
    GracefulShutdown,
    AbortCompensation,

    // Timed lane tasks
    HealthCheck,
    LeaseRenewal,
    EpochTransition,
    EpochSeal,
    TransitionBarrier,
    DeadlineEnforcement,
    ForkDetection,

    // Ready lane tasks
    BackgroundMaintenance,
    TelemetryFlush,
    EvidenceArchival,
    MarkerCompaction,
    AuditLogRotation,
    MetricsExport,
    StaleEntryCleanup,
}

impl ControlTaskClass {
    /// Convert task class to array index for O(1) lookups.
    pub const fn as_index(self) -> usize {
        match self {
            Self::CancellationHandler => 0,
            Self::DrainOperation => 1,
            Self::RegionClose => 2,
            Self::GracefulShutdown => 3,
            Self::AbortCompensation => 4,
            Self::HealthCheck => 5,
            Self::LeaseRenewal => 6,
            Self::EpochTransition => 7,
            Self::EpochSeal => 8,
            Self::TransitionBarrier => 9,
            Self::DeadlineEnforcement => 10,
            Self::ForkDetection => 11,
            Self::BackgroundMaintenance => 12,
            Self::TelemetryFlush => 13,
            Self::EvidenceArchival => 14,
            Self::MarkerCompaction => 15,
            Self::AuditLogRotation => 16,
            Self::MetricsExport => 17,
            Self::StaleEntryCleanup => 18,
        }
    }

    /// Returns all known task classes.
    pub fn all() -> &'static [ControlTaskClass] {
        &[
            Self::CancellationHandler,
            Self::DrainOperation,
            Self::RegionClose,
            Self::GracefulShutdown,
            Self::AbortCompensation,
            Self::HealthCheck,
            Self::LeaseRenewal,
            Self::EpochTransition,
            Self::EpochSeal,
            Self::TransitionBarrier,
            Self::DeadlineEnforcement,
            Self::ForkDetection,
            Self::BackgroundMaintenance,
            Self::TelemetryFlush,
            Self::EvidenceArchival,
            Self::MarkerCompaction,
            Self::AuditLogRotation,
            Self::MetricsExport,
            Self::StaleEntryCleanup,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CancellationHandler => "cancellation_handler",
            Self::DrainOperation => "drain_operation",
            Self::RegionClose => "region_close",
            Self::GracefulShutdown => "graceful_shutdown",
            Self::AbortCompensation => "abort_compensation",
            Self::HealthCheck => "health_check",
            Self::LeaseRenewal => "lease_renewal",
            Self::EpochTransition => "epoch_transition",
            Self::EpochSeal => "epoch_seal",
            Self::TransitionBarrier => "transition_barrier",
            Self::DeadlineEnforcement => "deadline_enforcement",
            Self::ForkDetection => "fork_detection",
            Self::BackgroundMaintenance => "background_maintenance",
            Self::TelemetryFlush => "telemetry_flush",
            Self::EvidenceArchival => "evidence_archival",
            Self::MarkerCompaction => "marker_compaction",
            Self::AuditLogRotation => "audit_log_rotation",
            Self::MetricsExport => "metrics_export",
            Self::StaleEntryCleanup => "stale_entry_cleanup",
        }
    }
}

impl fmt::Display for ControlTaskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single lane assignment entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LaneAssignment {
    pub task_class: ControlTaskClass,
    pub lane: ControlLane,
    pub timeout_ms: Option<u64>,
    pub preemptible: bool,
}

/// Budget policy for a single lane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaneBudget {
    pub lane: ControlLane,
    pub min_pct: u8,
    pub max_starve_ticks: u32,
}

/// Per-tick lane scheduling metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaneTickMetrics {
    pub tick: u64,
    pub cancel_lane_tasks_run: u32,
    pub timed_lane_tasks_run: u32,
    pub ready_lane_tasks_run: u32,
    pub cancel_lane_starved: bool,
    pub timed_lane_starved: bool,
    pub ready_lane_starved: bool,
}

impl LaneTickMetrics {
    /// Format as CSV row.
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{}",
            self.tick,
            self.cancel_lane_tasks_run,
            self.timed_lane_tasks_run,
            self.ready_lane_tasks_run,
            self.cancel_lane_starved as u8,
            self.timed_lane_starved as u8,
            self.ready_lane_starved as u8,
        )
    }

    /// CSV header.
    pub fn csv_header() -> &'static str {
        "tick,cancel_lane_tasks_run,timed_lane_tasks_run,ready_lane_tasks_run,cancel_lane_starved,timed_lane_starved,ready_lane_starved"
    }
}

/// Starvation event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarvationEvent {
    pub lane: ControlLane,
    pub consecutive_zero_ticks: u32,
    pub threshold: u32,
    pub event_code: String,
    pub trace_id: String,
}

/// Preemption event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreemptionEvent {
    pub task_id: String,
    pub lane: ControlLane,
    pub budget_remaining_ms: u64,
    pub event_code: String,
    pub trace_id: String,
}

/// Audit record for lane policy decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanePolicyAuditRecord {
    pub timestamp_ms: u64,
    pub event_code: String,
    pub task_class: String,
    pub lane: String,
    pub budget_remaining_ms: u64,
    pub trace_id: String,
}

/// Deadline-aware task queued for a control-lane scheduling tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedControlTask {
    pub task_id: String,
    pub task_class: ControlTaskClass,
    pub lane: ControlLane,
    pub enqueued_at_ms: u64,
    pub deadline_at_ms: Option<u64>,
}

/// Result of a deadline-aware scheduling tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlineAwareTick {
    pub metrics: LaneTickMetrics,
    pub scheduled_task_ids: Vec<String>,
    pub timed_out_task_ids: Vec<String>,
}

/// The control-lane policy engine: maps task classes to lanes, enforces budgets,
/// detects starvation, and tracks scheduling metrics.
#[derive(Debug)]
pub struct ControlLanePolicy {
    assignments: [LaneAssignment; CONTROL_TASK_CLASS_COUNT],
    budgets: BTreeMap<ControlLane, LaneBudget>,
    lane_consecutive_zero: BTreeMap<ControlLane, u32>,
    lane_run_counts: BTreeMap<ControlLane, u32>,
    current_tick: u64,
    tick_history: Vec<LaneTickMetrics>,
    starvation_events: Vec<StarvationEvent>,
    preemption_events: Vec<PreemptionEvent>,
    audit_log: Vec<LanePolicyAuditRecord>,
    deadline_queue: Vec<QueuedControlTask>,
    max_tick_history_entries: usize,
    max_starvation_events: usize,
    max_preemption_events: usize,
    max_audit_log_entries: usize,
    max_deadline_queue_entries: usize,
}

impl ControlLanePolicy {
    /// Create a new policy engine with canonical assignments and budgets.
    pub fn new() -> Self {
        Self::with_history_capacities(
            DEFAULT_MAX_TICK_HISTORY_ENTRIES,
            DEFAULT_MAX_STARVATION_EVENTS,
            DEFAULT_MAX_PREEMPTION_EVENTS,
            DEFAULT_MAX_AUDIT_LOG_ENTRIES,
        )
    }

    /// Create a new policy engine with explicit bounded-history capacities.
    pub fn with_history_capacities(
        max_tick_history_entries: usize,
        max_starvation_events: usize,
        max_preemption_events: usize,
        max_audit_log_entries: usize,
    ) -> Self {
        let mut budgets = BTreeMap::new();

        // Wire canonical lane assignments as array for O(1) lookups
        let assignments = {
            let mut temp = [None; CONTROL_TASK_CLASS_COUNT];
            for tc in ControlTaskClass::all() {
                let lane = Self::canonical_lane(*tc);
                let timeout_ms = Self::canonical_timeout(*tc);
                let preemptible = matches!(lane, ControlLane::Ready);
                temp[tc.as_index()] = Some(LaneAssignment {
                    task_class: *tc,
                    lane,
                    timeout_ms,
                    preemptible,
                });
            }
            // Convert Option array to LaneAssignment array
            temp.map(|opt| opt.expect("all task classes must be assigned"))
        };

        // Wire budgets
        for lane in ControlLane::all() {
            budgets.insert(
                *lane,
                LaneBudget {
                    lane: *lane,
                    min_pct: lane.min_budget_pct(),
                    max_starve_ticks: lane.max_starve_ticks(),
                },
            );
        }

        let mut lane_consecutive_zero = BTreeMap::new();
        let mut lane_run_counts = BTreeMap::new();
        for lane in ControlLane::all() {
            lane_consecutive_zero.insert(*lane, 0u32);
            lane_run_counts.insert(*lane, 0u32);
        }

        Self {
            assignments,
            budgets,
            lane_consecutive_zero,
            lane_run_counts,
            current_tick: 0,
            tick_history: Vec::new(),
            starvation_events: Vec::new(),
            preemption_events: Vec::new(),
            audit_log: Vec::new(),
            deadline_queue: Vec::new(),
            max_tick_history_entries: max_tick_history_entries.max(1),
            max_starvation_events: max_starvation_events.max(1),
            max_preemption_events: max_preemption_events.max(1),
            max_audit_log_entries: max_audit_log_entries.max(1),
            max_deadline_queue_entries: DEFAULT_MAX_DEADLINE_QUEUE_ENTRIES,
        }
    }

    /// The canonical lane for each task class — the core policy table.
    pub fn canonical_lane(tc: ControlTaskClass) -> ControlLane {
        match tc {
            // Cancel lane: immediate, non-deferrable
            ControlTaskClass::CancellationHandler => ControlLane::Cancel,
            ControlTaskClass::DrainOperation => ControlLane::Cancel,
            ControlTaskClass::RegionClose => ControlLane::Cancel,
            ControlTaskClass::GracefulShutdown => ControlLane::Cancel,
            ControlTaskClass::AbortCompensation => ControlLane::Cancel,

            // Timed lane: deadline-bound
            ControlTaskClass::HealthCheck => ControlLane::Timed,
            ControlTaskClass::LeaseRenewal => ControlLane::Timed,
            ControlTaskClass::EpochTransition => ControlLane::Timed,
            ControlTaskClass::EpochSeal => ControlLane::Timed,
            ControlTaskClass::TransitionBarrier => ControlLane::Timed,
            ControlTaskClass::DeadlineEnforcement => ControlLane::Timed,
            ControlTaskClass::ForkDetection => ControlLane::Timed,

            // Ready lane: best-effort background
            ControlTaskClass::BackgroundMaintenance => ControlLane::Ready,
            ControlTaskClass::TelemetryFlush => ControlLane::Ready,
            ControlTaskClass::EvidenceArchival => ControlLane::Ready,
            ControlTaskClass::MarkerCompaction => ControlLane::Ready,
            ControlTaskClass::AuditLogRotation => ControlLane::Ready,
            ControlTaskClass::MetricsExport => ControlLane::Ready,
            ControlTaskClass::StaleEntryCleanup => ControlLane::Ready,
        }
    }

    /// Canonical timeout for each task class (None = no timeout).
    pub fn canonical_timeout(tc: ControlTaskClass) -> Option<u64> {
        match Self::canonical_lane(tc) {
            ControlLane::Cancel => Some(5_000), // 5 second hard limit
            ControlLane::Timed => Some(30_000), // 30 second deadline
            ControlLane::Ready => None,         // best-effort, no deadline
        }
    }

    fn assignment_is_canonical(
        assignment: &LaneAssignment,
        expected_task_class: ControlTaskClass,
    ) -> bool {
        let canonical_lane = Self::canonical_lane(expected_task_class);
        assignment.task_class == expected_task_class
            && assignment.lane == canonical_lane
            && assignment.timeout_ms == Self::canonical_timeout(expected_task_class)
            && assignment.preemptible == matches!(canonical_lane, ControlLane::Ready)
    }

    fn assignment_for(&self, tc: ControlTaskClass) -> Result<LaneAssignment, String> {
        let assignment = self.assignments.get(tc.as_index()).ok_or_else(|| {
            format!(
                "{}: no lane assignment for task class {}",
                error_codes::ERR_CLP_UNKNOWN_TASK,
                tc
            )
        })?;

        if !Self::assignment_is_canonical(assignment, tc) {
            return Err(format!(
                "{}: assignment table mismatch for task class {}",
                error_codes::ERR_CLP_POLICY_MISMATCH,
                tc
            ));
        }

        Ok(*assignment)
    }

    /// Look up the lane assignment for a task class.
    pub fn lookup(&self, tc: ControlTaskClass) -> Option<&LaneAssignment> {
        self.assignments
            .get(tc.as_index())
            .filter(|assignment| Self::assignment_is_canonical(assignment, tc))
    }

    /// Check that every task class has a lane assignment (INV-CLP-LANE-ASSIGNED).
    pub fn verify_all_assigned(&self) -> bool {
        self.assignments.len() == ControlTaskClass::all().len()
            && ControlTaskClass::all().iter().all(|tc| {
                self.assignments
                    .get(tc.as_index())
                    .is_some_and(|assignment| Self::assignment_is_canonical(assignment, *tc))
            })
    }

    /// Check that budgets sum to 100% (INV-CLP-BUDGET-SUM).
    pub fn verify_budget_sum(&self) -> bool {
        let total: u16 = self
            .budgets
            .values()
            .fold(0u16, |acc, b| acc.saturating_add(b.min_pct as u16));
        total == 100
    }

    /// Get the budget policy for a lane.
    pub fn budget(&self, lane: ControlLane) -> Option<&LaneBudget> {
        self.budgets.get(&lane)
    }

    /// Assign a task to a lane with audit logging.
    pub fn assign_task(
        &mut self,
        tc: ControlTaskClass,
        task_id: &str,
        trace_id: &str,
        timestamp_ms: u64,
    ) -> Result<ControlLane, String> {
        if let Some(reason) = invalid_task_id_reason(task_id) {
            return Err(format!(
                "{}: {reason}",
                error_codes::ERR_CLP_INVALID_TASK_ID
            ));
        }
        let assignment = self.assignment_for(tc)?;
        let lane = assignment.lane;

        Self::push_bounded(
            &mut self.audit_log,
            LanePolicyAuditRecord {
                timestamp_ms,
                event_code: event_codes::LAN_001.to_string(),
                task_class: tc.as_str().to_string(),
                lane: lane.as_str().to_string(),
                budget_remaining_ms: assignment.timeout_ms.unwrap_or(0),
                trace_id: trace_id.to_string(),
            },
            self.max_audit_log_entries,
        );

        let run_count = self.lane_run_counts.entry(lane).or_insert(0);
        *run_count = run_count.saturating_add(1);

        Ok(lane)
    }

    /// Queue a task with the canonical lane deadline metadata used by deadline-aware ticks.
    pub fn enqueue_deadline_task(
        &mut self,
        task_class: ControlTaskClass,
        task_id: &str,
        enqueued_at_ms: u64,
        trace_id: &str,
    ) -> Result<QueuedControlTask, String> {
        if let Some(reason) = invalid_task_id_reason(task_id) {
            return Err(format!(
                "{}: {reason}",
                error_codes::ERR_CLP_INVALID_TASK_ID
            ));
        }
        if self.deadline_queue.len() >= self.max_deadline_queue_entries {
            return Err(format!(
                "{}: control lane deadline queue is full",
                error_codes::ERR_CLP_DEADLINE_QUEUE_FULL
            ));
        }

        let assignment = self.assignment_for(task_class)?;
        let lane = assignment.lane;
        let timeout_ms = assignment.timeout_ms;
        let task = QueuedControlTask {
            task_id: task_id.to_string(),
            task_class,
            lane,
            enqueued_at_ms,
            deadline_at_ms: timeout_ms.map(|timeout| enqueued_at_ms.saturating_add(timeout)),
        };

        Self::push_bounded(
            &mut self.audit_log,
            LanePolicyAuditRecord {
                timestamp_ms: enqueued_at_ms,
                event_code: event_codes::LAN_001.to_string(),
                task_class: task_class.as_str().to_string(),
                lane: lane.as_str().to_string(),
                budget_remaining_ms: timeout_ms.unwrap_or(0),
                trace_id: trace_id.to_string(),
            },
            self.max_audit_log_entries,
        );

        Self::push_bounded(
            &mut self.deadline_queue,
            task.clone(),
            self.max_deadline_queue_entries,
        );
        Ok(task)
    }

    /// Schedule queued tasks after expiring deadline-bound work at `now_ms`.
    pub fn tick_deadline_aware(
        &mut self,
        now_ms: u64,
        total_slots: u32,
        trace_id: &str,
    ) -> DeadlineAwareTick {
        let queued_tasks = std::mem::take(&mut self.deadline_queue);
        let mut cancel_tasks = Vec::new();
        let mut timed_tasks = Vec::new();
        let mut ready_tasks = Vec::new();
        let mut timed_out_task_ids = Vec::new();

        for task in queued_tasks {
            if task
                .deadline_at_ms
                .is_some_and(|deadline_at_ms| now_ms >= deadline_at_ms)
            {
                self.record_deadline_timeout(&task, now_ms, trace_id);
                timed_out_task_ids.push(task.task_id);
                continue;
            }

            match task.lane {
                ControlLane::Cancel => cancel_tasks.push(task),
                ControlLane::Timed => timed_tasks.push(task),
                ControlLane::Ready => ready_tasks.push(task),
            }
        }

        cancel_tasks.sort_by_key(|task| (task.enqueued_at_ms, task.task_id.clone()));
        timed_tasks.sort_by_key(|task| {
            (
                task.deadline_at_ms.unwrap_or(u64::MAX),
                task.enqueued_at_ms,
                task.task_id.clone(),
            )
        });
        ready_tasks.sort_by_key(|task| (task.enqueued_at_ms, task.task_id.clone()));

        let cancel_pending = Self::usize_to_u32_saturating(cancel_tasks.len());
        let timed_pending = Self::usize_to_u32_saturating(timed_tasks.len());
        let ready_pending = Self::usize_to_u32_saturating(ready_tasks.len());
        let metrics = self.tick(
            cancel_pending,
            timed_pending,
            ready_pending,
            total_slots,
            trace_id,
        );

        let mut scheduled_task_ids = Vec::new();
        Self::schedule_front_tasks(
            &mut cancel_tasks,
            metrics.cancel_lane_tasks_run,
            &mut scheduled_task_ids,
        );
        Self::schedule_front_tasks(
            &mut timed_tasks,
            metrics.timed_lane_tasks_run,
            &mut scheduled_task_ids,
        );
        Self::schedule_front_tasks(
            &mut ready_tasks,
            metrics.ready_lane_tasks_run,
            &mut scheduled_task_ids,
        );

        self.deadline_queue = cancel_tasks;
        self.deadline_queue.extend(timed_tasks);
        self.deadline_queue.extend(ready_tasks);

        DeadlineAwareTick {
            metrics,
            scheduled_task_ids,
            timed_out_task_ids,
        }
    }

    /// Simulate one scheduling tick: processes pending tasks by lane priority,
    /// enforces budgets, and detects starvation.
    pub fn tick(
        &mut self,
        cancel_pending: u32,
        timed_pending: u32,
        ready_pending: u32,
        total_slots: u32,
        trace_id: &str,
    ) -> LaneTickMetrics {
        self.current_tick = self.current_tick.saturating_add(1);

        // Allocate slots by budget
        let cancel_slots = u32::try_from(
            u64::try_from(total_slots).unwrap_or(u64::MAX) * CANCEL_LANE_BUDGET_PCT as u64 / 100,
        )
        .unwrap_or(u32::MAX);
        let timed_slots = u32::try_from(
            u64::try_from(total_slots).unwrap_or(u64::MAX) * TIMED_LANE_BUDGET_PCT as u64 / 100,
        )
        .unwrap_or(u32::MAX);
        let ready_slots = total_slots
            .saturating_sub(cancel_slots)
            .saturating_sub(timed_slots);

        // Schedule by strict priority. Budget math floors small totals to zero,
        // so each pending higher-priority lane gets a one-slot floor before
        // lower-priority lanes consume scarce capacity.
        let cancel_capacity = if cancel_pending > 0 && total_slots > 0 {
            cancel_slots.max(1).min(total_slots)
        } else {
            cancel_slots.min(total_slots)
        };
        let cancel_run = cancel_pending.min(cancel_capacity);

        let cancel_leftover = cancel_slots.saturating_sub(cancel_run);
        let remaining_total = total_slots.saturating_sub(cancel_run);

        // Timed gets its budget plus any unused Cancel budget, bounded by remaining slots
        let timed_capacity = timed_slots.saturating_add(cancel_leftover);
        let timed_capacity = if timed_pending > 0 && remaining_total > 0 {
            timed_capacity.max(1).min(remaining_total)
        } else {
            timed_capacity.min(remaining_total)
        };
        let timed_run = timed_pending.min(timed_capacity);

        let timed_leftover = timed_capacity.saturating_sub(timed_run);
        let remaining_total = remaining_total.saturating_sub(timed_run);

        // Ready gets its budget plus any unused Timed budget, bounded by remaining slots
        let ready_run = ready_pending.min(
            ready_slots
                .saturating_add(timed_leftover)
                .min(remaining_total),
        );

        // Starvation detection
        let cancel_starved = cancel_pending > 0 && cancel_run == 0;
        let timed_starved = timed_pending > 0 && timed_run == 0;
        let ready_starved = ready_pending > 0 && ready_run == 0;

        // Update consecutive zero counters
        for (lane, starved) in [
            (ControlLane::Cancel, cancel_starved),
            (ControlLane::Timed, timed_starved),
            (ControlLane::Ready, ready_starved),
        ] {
            let counter = self.lane_consecutive_zero.entry(lane).or_insert(0);
            if starved {
                *counter = counter.saturating_add(1);
                let threshold = self
                    .budgets
                    .get(&lane)
                    .map(|b| b.max_starve_ticks)
                    .unwrap_or(DEFAULT_STARVATION_THRESHOLD_TICKS);
                if *counter >= threshold {
                    Self::push_bounded(
                        &mut self.starvation_events,
                        StarvationEvent {
                            lane,
                            consecutive_zero_ticks: *counter,
                            threshold,
                            event_code: event_codes::LAN_003.to_string(),
                            trace_id: trace_id.to_string(),
                        },
                        self.max_starvation_events,
                    );
                }
            } else if *counter > 0 {
                let threshold = self
                    .budgets
                    .get(&lane)
                    .map(|b| b.max_starve_ticks)
                    .unwrap_or(DEFAULT_STARVATION_THRESHOLD_TICKS);
                if *counter >= threshold {
                    Self::push_bounded(
                        &mut self.starvation_events,
                        StarvationEvent {
                            lane,
                            consecutive_zero_ticks: *counter,
                            threshold,
                            event_code: event_codes::LAN_004.to_string(),
                            trace_id: trace_id.to_string(),
                        },
                        self.max_starvation_events,
                    );
                }
                *counter = 0;
            }
        }

        let metrics = LaneTickMetrics {
            tick: self.current_tick,
            cancel_lane_tasks_run: cancel_run,
            timed_lane_tasks_run: timed_run,
            ready_lane_tasks_run: ready_run,
            cancel_lane_starved: cancel_starved,
            timed_lane_starved: timed_starved,
            ready_lane_starved: ready_starved,
        };

        Self::push_bounded(
            &mut self.tick_history,
            metrics.clone(),
            self.max_tick_history_entries,
        );
        metrics
    }

    /// Preempt a task for lane budget enforcement.
    pub fn preempt_task(
        &mut self,
        task_id: &str,
        lane: ControlLane,
        budget_remaining_ms: u64,
        trace_id: &str,
    ) -> Result<PreemptionEvent, String> {
        if let Some(reason) = invalid_task_id_reason(task_id) {
            return Err(format!(
                "{}: {reason}",
                error_codes::ERR_CLP_INVALID_TASK_ID
            ));
        }
        let event = PreemptionEvent {
            task_id: task_id.to_string(),
            lane,
            budget_remaining_ms,
            event_code: event_codes::LAN_005.to_string(),
            trace_id: trace_id.to_string(),
        };
        Self::push_bounded(
            &mut self.preemption_events,
            event.clone(),
            self.max_preemption_events,
        );
        Ok(event)
    }

    /// Check if cancel lane was ever starved for more than 1 tick (INV-CLP-CANCEL-NO-STARVE).
    pub fn verify_cancel_no_starve(&self) -> bool {
        !self.starvation_events.iter().any(|e| {
            e.lane == ControlLane::Cancel
                && e.event_code == event_codes::LAN_003
                && e.consecutive_zero_ticks > CANCEL_MAX_STARVE_TICKS
        })
    }

    /// Get tick history for CSV export.
    pub fn tick_history(&self) -> &[LaneTickMetrics] {
        &self.tick_history
    }

    /// Get the configured tick-history capacity.
    pub fn tick_history_capacity(&self) -> usize {
        self.max_tick_history_entries
    }

    /// Export tick history as CSV string.
    pub fn export_csv(&self) -> String {
        let mut lines = vec![LaneTickMetrics::csv_header().to_string()];
        for m in &self.tick_history {
            lines.push(m.to_csv_row());
        }
        lines.join("\n")
    }

    /// Get starvation events.
    pub fn starvation_events(&self) -> &[StarvationEvent] {
        &self.starvation_events
    }

    /// Get the configured starvation-event capacity.
    pub fn starvation_event_capacity(&self) -> usize {
        self.max_starvation_events
    }

    /// Get preemption events.
    pub fn preemption_events(&self) -> &[PreemptionEvent] {
        &self.preemption_events
    }

    /// Get the configured preemption-event capacity.
    pub fn preemption_event_capacity(&self) -> usize {
        self.max_preemption_events
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[LanePolicyAuditRecord] {
        &self.audit_log
    }

    /// Get pending deadline-aware queued tasks.
    pub fn deadline_queue(&self) -> &[QueuedControlTask] {
        &self.deadline_queue
    }

    /// Get the configured audit-log capacity.
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

    /// Count task classes per lane.
    pub fn class_counts_per_lane(&self) -> BTreeMap<ControlLane, usize> {
        let mut counts = BTreeMap::new();
        for lane in ControlLane::all() {
            counts.insert(*lane, 0_usize);
        }
        for a in &self.assignments {
            let count = counts.entry(a.lane).or_insert(0);
            *count = (*count).saturating_add(1_usize);
        }
        counts
    }

    /// Total number of task classes.
    pub fn total_task_classes(&self) -> usize {
        self.assignments.len()
    }

    /// Scheduling priority comparison: returns true if lane_a should schedule before lane_b.
    pub fn has_priority(lane_a: ControlLane, lane_b: ControlLane) -> bool {
        lane_a.priority() < lane_b.priority()
    }

    fn record_deadline_timeout(&mut self, task: &QueuedControlTask, now_ms: u64, trace_id: &str) {
        Self::push_bounded(
            &mut self.preemption_events,
            PreemptionEvent {
                task_id: task.task_id.clone(),
                lane: task.lane,
                budget_remaining_ms: 0,
                event_code: event_codes::LAN_006.to_string(),
                trace_id: trace_id.to_string(),
            },
            self.max_preemption_events,
        );
        Self::push_bounded(
            &mut self.audit_log,
            LanePolicyAuditRecord {
                timestamp_ms: now_ms,
                event_code: event_codes::LAN_006.to_string(),
                task_class: task.task_class.as_str().to_string(),
                lane: task.lane.as_str().to_string(),
                budget_remaining_ms: 0,
                trace_id: trace_id.to_string(),
            },
            self.max_audit_log_entries,
        );
    }

    fn schedule_front_tasks(
        tasks: &mut Vec<QueuedControlTask>,
        scheduled_count: u32,
        scheduled_task_ids: &mut Vec<String>,
    ) {
        let scheduled_count = usize::try_from(scheduled_count)
            .unwrap_or(usize::MAX)
            .min(tasks.len());
        let remaining_tasks = tasks.split_off(scheduled_count);
        scheduled_task_ids.extend(tasks.drain(..).map(|task| task.task_id));
        *tasks = remaining_tasks;
    }

    fn usize_to_u32_saturating(value: usize) -> u32 {
        u32::try_from(value).unwrap_or(u32::MAX)
    }

    fn push_bounded<T>(entries: &mut Vec<T>, value: T, max_entries: usize) {
        if max_entries == 0 {
            entries.clear();
            return;
        }
        if entries.len() >= max_entries {
            let overflow = entries.len().saturating_sub(max_entries).saturating_add(1);
            let safe_overflow = overflow.min(entries.len());
            entries.drain(0..safe_overflow);
        }
        entries.push(value);
    }
}

impl Default for ControlLanePolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot for policy serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlLanePolicySnapshot {
    pub schema_version: String,
    pub assignments: Vec<LaneAssignment>,
    pub budgets: Vec<LaneBudget>,
    pub task_class_count: usize,
    pub lane_count: usize,
}

impl ControlLanePolicySnapshot {
    pub fn from_policy(policy: &ControlLanePolicy) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            assignments: policy.assignments.to_vec(),
            budgets: policy.budgets.values().cloned().collect(),
            task_class_count: policy.total_task_classes(),
            lane_count: ControlLane::all().len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CANCEL_LANE_BUDGET_PCT, CANCEL_MAX_STARVE_TICKS, CONTROL_TASK_CLASS_COUNT, ControlLane,
        ControlLanePolicy, ControlLanePolicySnapshot, ControlTaskClass,
        DEFAULT_STARVATION_THRESHOLD_TICKS, LaneAssignment, LaneBudget, MAX_TASK_ID_BYTES,
        READY_LANE_BUDGET_PCT, SCHEMA_VERSION, TIMED_LANE_BUDGET_PCT, error_codes, event_codes,
    };

    fn make_policy_with_capacities(
        max_tick_history_entries: usize,
        max_starvation_events: usize,
        max_preemption_events: usize,
        max_audit_log_entries: usize,
    ) -> ControlLanePolicy {
        ControlLanePolicy::with_history_capacities(
            max_tick_history_entries,
            max_starvation_events,
            max_preemption_events,
            max_audit_log_entries,
        )
    }

    #[test]
    fn test_all_task_classes_assigned() {
        let policy = ControlLanePolicy::new();
        assert!(policy.verify_all_assigned(), "INV-CLP-LANE-ASSIGNED");
    }

    #[test]
    fn test_budget_sums_to_100() {
        let policy = ControlLanePolicy::new();
        assert!(policy.verify_budget_sum(), "INV-CLP-BUDGET-SUM");
    }

    #[test]
    fn test_verify_all_assigned_rejects_corrupted_assignment() {
        let mut policy = ControlLanePolicy::new();
        policy.assignments[ControlTaskClass::CancellationHandler.as_index()] = LaneAssignment {
            task_class: ControlTaskClass::HealthCheck,
            lane: ControlLane::Timed,
            timeout_ms: ControlLanePolicy::canonical_timeout(ControlTaskClass::HealthCheck),
            preemptible: false,
        };

        assert!(!policy.verify_all_assigned());
        assert!(
            policy
                .lookup(ControlTaskClass::CancellationHandler)
                .is_none()
        );
        assert_eq!(policy.total_task_classes(), CONTROL_TASK_CLASS_COUNT);
    }

    #[test]
    fn test_assign_task_succeeds_with_array_implementation() {
        let mut policy = ControlLanePolicy::new();
        let timed_before = *policy
            .lane_run_counts
            .get(&ControlLane::Timed)
            .expect("timed run count");

        let lane = policy
            .assign_task(
                ControlTaskClass::HealthCheck,
                "task-1",
                "trace-success",
                1_000,
            )
            .expect("assignment should succeed");

        assert_eq!(lane, ControlLane::Timed);
        assert_eq!(policy.audit_log().len(), 1);
        assert_eq!(
            policy.lane_run_counts.get(&ControlLane::Timed).copied(),
            Some(timed_before)
        );
    }

    #[test]
    fn test_verify_budget_sum_rejects_missing_lane_budget() {
        let mut policy = ControlLanePolicy::new();
        policy.budgets.remove(&ControlLane::Ready);

        assert!(!policy.verify_budget_sum());
        assert!(policy.budget(ControlLane::Ready).is_none());
    }

    #[test]
    fn test_verify_budget_sum_rejects_overallocated_budget() {
        let mut policy = ControlLanePolicy::new();
        policy.budgets.insert(
            ControlLane::Ready,
            LaneBudget {
                lane: ControlLane::Ready,
                min_pct: 99,
                max_starve_ticks: DEFAULT_STARVATION_THRESHOLD_TICKS,
            },
        );

        assert!(!policy.verify_budget_sum());
    }

    #[test]
    fn test_cancel_budget_at_least_20() {
        const { assert!(CANCEL_LANE_BUDGET_PCT >= 20) };
    }

    #[test]
    fn test_timed_budget_at_least_30() {
        const { assert!(TIMED_LANE_BUDGET_PCT >= 30) };
    }

    #[test]
    fn test_ready_budget_is_remainder() {
        assert_eq!(
            CANCEL_LANE_BUDGET_PCT + TIMED_LANE_BUDGET_PCT + READY_LANE_BUDGET_PCT,
            100
        );
    }

    #[test]
    fn test_three_lanes_defined() {
        assert_eq!(ControlLane::all().len(), 3);
    }

    #[test]
    fn test_19_task_classes_defined() {
        assert_eq!(ControlTaskClass::all().len(), 19);
    }

    #[test]
    fn test_cancel_lane_classes() {
        let cancel_classes = [
            ControlTaskClass::CancellationHandler,
            ControlTaskClass::DrainOperation,
            ControlTaskClass::RegionClose,
            ControlTaskClass::GracefulShutdown,
            ControlTaskClass::AbortCompensation,
        ];
        for tc in &cancel_classes {
            assert_eq!(ControlLanePolicy::canonical_lane(*tc), ControlLane::Cancel);
        }
    }

    #[test]
    fn test_timed_lane_classes() {
        let timed_classes = [
            ControlTaskClass::HealthCheck,
            ControlTaskClass::LeaseRenewal,
            ControlTaskClass::EpochTransition,
            ControlTaskClass::EpochSeal,
            ControlTaskClass::TransitionBarrier,
            ControlTaskClass::DeadlineEnforcement,
            ControlTaskClass::ForkDetection,
        ];
        for tc in &timed_classes {
            assert_eq!(ControlLanePolicy::canonical_lane(*tc), ControlLane::Timed);
        }
    }

    #[test]
    fn test_ready_lane_classes() {
        let ready_classes = [
            ControlTaskClass::BackgroundMaintenance,
            ControlTaskClass::TelemetryFlush,
            ControlTaskClass::EvidenceArchival,
            ControlTaskClass::MarkerCompaction,
            ControlTaskClass::AuditLogRotation,
            ControlTaskClass::MetricsExport,
            ControlTaskClass::StaleEntryCleanup,
        ];
        for tc in &ready_classes {
            assert_eq!(ControlLanePolicy::canonical_lane(*tc), ControlLane::Ready);
        }
    }

    #[test]
    fn test_cancel_priority_before_ready() {
        // INV-CLP-CANCEL-PRIORITY
        assert!(ControlLanePolicy::has_priority(
            ControlLane::Cancel,
            ControlLane::Ready
        ));
        assert!(ControlLanePolicy::has_priority(
            ControlLane::Cancel,
            ControlLane::Timed
        ));
        assert!(ControlLanePolicy::has_priority(
            ControlLane::Timed,
            ControlLane::Ready
        ));
    }

    #[test]
    fn test_cancel_has_timeout() {
        for tc in ControlTaskClass::all() {
            let lane = ControlLanePolicy::canonical_lane(*tc);
            if lane == ControlLane::Cancel {
                assert!(ControlLanePolicy::canonical_timeout(*tc).is_some());
            }
        }
    }

    #[test]
    fn test_ready_preemptible() {
        let policy = ControlLanePolicy::new();
        for a in policy.assignments.iter() {
            if a.lane == ControlLane::Ready {
                assert!(a.preemptible, "Ready lane tasks should be preemptible");
            }
        }
    }

    #[test]
    fn test_cancel_not_preemptible() {
        let policy = ControlLanePolicy::new();
        for a in policy.assignments.iter() {
            if a.lane == ControlLane::Cancel {
                assert!(!a.preemptible, "Cancel lane tasks must not be preemptible");
            }
        }
    }

    #[test]
    fn test_tick_basic_scheduling() {
        let mut policy = ControlLanePolicy::new();
        let m = policy.tick(2, 3, 5, 10, "trace-1");
        assert!(m.cancel_lane_tasks_run > 0);
        assert!(m.timed_lane_tasks_run > 0);
        assert!(m.ready_lane_tasks_run > 0);
    }

    #[test]
    fn test_tick_cancel_scheduled_with_zero_total() {
        let mut policy = ControlLanePolicy::new();
        // Even with very few slots, cancel gets at least 1
        let m = policy.tick(1, 0, 0, 1, "trace-2");
        assert_eq!(m.cancel_lane_tasks_run, 1);
    }

    #[test]
    fn test_starvation_detection() {
        let mut policy = ControlLanePolicy::new();
        // Starve the ready lane by giving it no tasks and checking the counter
        for i in 0..5 {
            policy.tick(5, 5, 5, 0, &format!("trace-starve-{}", i));
        }
        // All lanes should experience starvation since total_slots=0
        let starved = policy
            .starvation_events()
            .iter()
            .filter(|e| e.event_code == event_codes::LAN_003)
            .count();
        assert!(starved > 0, "At least one starvation event expected");
    }

    #[test]
    fn test_verify_cancel_no_starve_rejects_repeated_cancel_starvation() {
        let mut policy = ControlLanePolicy::new();
        policy.tick(1, 0, 0, 0, "trace-cancel-starve-1");
        policy.tick(1, 0, 0, 0, "trace-cancel-starve-2");

        assert!(!policy.verify_cancel_no_starve());
        assert!(policy.starvation_events().iter().any(|event| {
            event.lane == ControlLane::Cancel
                && event.event_code == event_codes::LAN_003
                && event.consecutive_zero_ticks > CANCEL_MAX_STARVE_TICKS
        }));
    }

    #[test]
    fn test_starvation_resolution_not_recorded_before_threshold() {
        let mut policy = ControlLanePolicy::new();
        policy.tick(0, 0, 1, 0, "trace-ready-starve-1");
        policy.tick(0, 0, 1, 10, "trace-ready-resolve");

        assert!(policy.starvation_events().is_empty());
    }

    #[test]
    fn negative_zero_slot_tick_starves_all_pending_lanes() {
        let mut policy = ControlLanePolicy::new();

        let metrics = policy.tick(1, 1, 1, 0, "trace-zero-slot");

        assert_eq!(metrics.cancel_lane_tasks_run, 0);
        assert_eq!(metrics.timed_lane_tasks_run, 0);
        assert_eq!(metrics.ready_lane_tasks_run, 0);
        assert!(metrics.cancel_lane_starved);
        assert!(metrics.timed_lane_starved);
        assert!(metrics.ready_lane_starved);
        policy.tick(1, 1, 1, 0, "trace-zero-slot-repeat");
        assert!(!policy.verify_cancel_no_starve());
    }

    #[test]
    fn negative_missing_timed_budget_uses_default_starvation_threshold() {
        let mut policy = ControlLanePolicy::new();
        policy.budgets.remove(&ControlLane::Timed);

        policy.tick(0, 1, 0, 0, "trace-missing-budget-1");
        policy.tick(0, 1, 0, 0, "trace-missing-budget-2");
        policy.tick(0, 1, 0, 0, "trace-missing-budget-3");

        let event = policy
            .starvation_events()
            .iter()
            .find(|event| event.lane == ControlLane::Timed)
            .expect("timed starvation event");
        assert_eq!(event.threshold, DEFAULT_STARVATION_THRESHOLD_TICKS);
        assert_eq!(
            event.consecutive_zero_ticks,
            DEFAULT_STARVATION_THRESHOLD_TICKS
        );
    }

    #[test]
    fn negative_assign_failure_after_success_preserves_existing_audit_log() {
        let mut policy = ControlLanePolicy::new();
        policy
            .assign_task(
                ControlTaskClass::LeaseRenewal,
                "task-good",
                "trace-good",
                10,
            )
            .unwrap();
        policy.assignments[ControlTaskClass::HealthCheck.as_index()] = LaneAssignment {
            task_class: ControlTaskClass::BackgroundMaintenance,
            lane: ControlLane::Ready,
            timeout_ms: ControlLanePolicy::canonical_timeout(
                ControlTaskClass::BackgroundMaintenance,
            ),
            preemptible: true,
        };

        let err = policy
            .assign_task(ControlTaskClass::HealthCheck, "task-bad", "trace-bad", 20)
            .expect_err("corrupted assignment must reject");

        assert!(err.contains(error_codes::ERR_CLP_POLICY_MISMATCH));
        assert_eq!(policy.audit_log().len(), 1);
        assert_eq!(policy.audit_log()[0].trace_id, "trace-good");
    }

    #[test]
    fn negative_zero_capacity_push_bounded_clears_without_panic() {
        let mut values = vec![1, 2, 3];

        ControlLanePolicy::push_bounded(&mut values, 4, 0);

        assert!(values.is_empty());
    }

    #[test]
    fn negative_export_audit_jsonl_capacity_one_keeps_only_latest_record() {
        let mut policy = make_policy_with_capacities(8, 8, 8, 1);
        policy
            .assign_task(ControlTaskClass::HealthCheck, "task-old", "trace-old", 10)
            .unwrap();
        policy
            .assign_task(ControlTaskClass::LeaseRenewal, "task-new", "trace-new", 20)
            .unwrap();

        let jsonl = policy.export_audit_log_jsonl();

        assert_eq!(jsonl.lines().count(), 1);
        assert!(!jsonl.contains("trace-old"));
        assert!(jsonl.contains("trace-new"));
    }

    #[test]
    fn negative_snapshot_reflects_corrupted_missing_assignment() {
        let mut policy = ControlLanePolicy::new();
        policy
            .assignments
            .remove(&ControlTaskClass::AbortCompensation);

        let snapshot = ControlLanePolicySnapshot::from_policy(&policy);

        assert_eq!(
            snapshot.task_class_count,
            ControlTaskClass::all().len().saturating_sub(1)
        );
        assert_eq!(snapshot.lane_count, ControlLane::all().len());
        assert_eq!(snapshot.assignments.len(), snapshot.task_class_count);
    }

    #[test]
    fn test_cancel_no_starve_normal_load() {
        let mut policy = ControlLanePolicy::new();
        // Normal mixed workload: cancel should never starve
        for i in 0..20 {
            policy.tick(2, 5, 10, 10, &format!("trace-norm-{}", i));
        }
        assert!(policy.verify_cancel_no_starve(), "INV-CLP-CANCEL-NO-STARVE");
    }

    #[test]
    fn test_flood_ready_cancel_still_runs() {
        let mut policy = ControlLanePolicy::new();
        // Flood: heavy ready-lane load, but cancel should still be served
        for i in 0..50 {
            let m = policy.tick(1, 0, 1000, 10, &format!("trace-flood-{}", i));
            assert!(
                m.cancel_lane_tasks_run >= 1,
                "Cancel must run on tick {}",
                i
            );
        }
    }

    #[test]
    fn test_preempt_event_recorded() {
        let mut policy = ControlLanePolicy::new();
        let event = policy
            .preempt_task("task-42", ControlLane::Ready, 100, "trace-pre")
            .expect("valid task id should preempt");
        assert_eq!(event.task_id, "task-42");
        assert_eq!(event.event_code, event_codes::LAN_005);
        assert_eq!(policy.preemption_events().len(), 1);
    }

    #[test]
    fn test_history_capacities_clamp_to_one() {
        let policy = make_policy_with_capacities(0, 0, 0, 0);
        assert_eq!(policy.tick_history_capacity(), 1);
        assert_eq!(policy.starvation_event_capacity(), 1);
        assert_eq!(policy.preemption_event_capacity(), 1);
        assert_eq!(policy.audit_log_capacity(), 1);
    }

    #[test]
    fn test_tick_history_capacity_enforces_oldest_first_eviction() {
        let mut policy = make_policy_with_capacities(2, 8, 8, 8);
        policy.tick(1, 1, 1, 5, "trace-tick-1");
        policy.tick(1, 1, 1, 5, "trace-tick-2");
        policy.tick(1, 1, 1, 5, "trace-tick-3");

        let ticks: Vec<u64> = policy.tick_history().iter().map(|m| m.tick).collect();
        assert_eq!(ticks, vec![2, 3]);
    }

    #[test]
    fn test_starvation_event_capacity_enforces_oldest_first_eviction() {
        let mut policy = make_policy_with_capacities(8, 2, 8, 8);
        policy.tick(0, 1, 0, 0, "trace-starve-1");
        policy.tick(0, 1, 0, 0, "trace-starve-2");
        policy.tick(0, 1, 0, 0, "trace-starve-3");
        policy.tick(0, 1, 0, 0, "trace-starve-4");
        policy.tick(0, 1, 0, 10, "trace-starve-resolve");

        let trace_ids: Vec<&str> = policy
            .starvation_events()
            .iter()
            .map(|event| event.trace_id.as_str())
            .collect();
        assert_eq!(trace_ids, vec!["trace-starve-4", "trace-starve-resolve"]);
    }

    #[test]
    fn test_preemption_and_audit_capacities_enforce_oldest_first_eviction() {
        let mut policy = make_policy_with_capacities(8, 8, 2, 2);
        policy
            .preempt_task("task-1", ControlLane::Ready, 100, "trace-preempt-1")
            .unwrap();
        policy
            .preempt_task("task-2", ControlLane::Ready, 90, "trace-preempt-2")
            .unwrap();
        policy
            .preempt_task("task-3", ControlLane::Ready, 80, "trace-preempt-3")
            .unwrap();

        let preempted_tasks: Vec<&str> = policy
            .preemption_events()
            .iter()
            .map(|event| event.task_id.as_str())
            .collect();
        assert_eq!(preempted_tasks, vec!["task-2", "task-3"]);

        policy
            .assign_task(ControlTaskClass::HealthCheck, "task-a", "trace-audit-1", 10)
            .unwrap();
        policy
            .assign_task(
                ControlTaskClass::LeaseRenewal,
                "task-b",
                "trace-audit-2",
                20,
            )
            .unwrap();
        policy
            .assign_task(
                ControlTaskClass::ForkDetection,
                "task-c",
                "trace-audit-3",
                30,
            )
            .unwrap();

        let audit_trace_ids: Vec<&str> = policy
            .audit_log()
            .iter()
            .map(|record| record.trace_id.as_str())
            .collect();
        assert_eq!(audit_trace_ids, vec!["trace-audit-2", "trace-audit-3"]);
    }

    #[test]
    fn test_assign_task_audit_log() {
        let mut policy = ControlLanePolicy::new();
        let lane = policy
            .assign_task(ControlTaskClass::HealthCheck, "task-1", "trace-a", 1000)
            .unwrap();
        assert_eq!(lane, ControlLane::Timed);
        assert_eq!(policy.audit_log().len(), 1);
        assert_eq!(policy.audit_log()[0].event_code, event_codes::LAN_001);
    }

    #[test]
    fn test_csv_export() {
        let mut policy = ControlLanePolicy::new();
        policy.tick(1, 2, 3, 10, "trace-csv");
        let csv = policy.export_csv();
        assert!(csv.starts_with("tick,cancel_lane_tasks_run"));
        assert_eq!(csv.lines().count(), 2); // header + 1 row
    }

    #[test]
    fn test_class_counts_per_lane() {
        let policy = ControlLanePolicy::new();
        let counts = policy.class_counts_per_lane();
        assert_eq!(*counts.get(&ControlLane::Cancel).unwrap(), 5);
        assert_eq!(*counts.get(&ControlLane::Timed).unwrap(), 7);
        assert_eq!(*counts.get(&ControlLane::Ready).unwrap(), 7);
    }

    #[test]
    fn test_assign_task_rejects_invalid_task_id() {
        let mut policy = ControlLanePolicy::new();
        let err = policy
            .assign_task(ControlTaskClass::HealthCheck, " task-bad", "trace-bad", 10)
            .expect_err("surrounding whitespace must be rejected");
        assert!(err.contains(error_codes::ERR_CLP_INVALID_TASK_ID));
        assert!(err.contains("leading or trailing whitespace"));
    }

    #[test]
    fn test_enqueue_deadline_task_rejects_control_characters_and_oversized_ids() {
        let mut policy = ControlLanePolicy::new();
        let oversized = "x".repeat(MAX_TASK_ID_BYTES + 1);

        for (task_id, expected_detail) in [
            ("task\nnewline".to_string(), "control characters"),
            ("task\u{0}nul".to_string(), "control characters"),
            (oversized, "must not exceed"),
        ] {
            let err = policy
                .enqueue_deadline_task(
                    ControlTaskClass::LeaseRenewal,
                    &task_id,
                    10,
                    "trace-invalid-id",
                )
                .expect_err("invalid queued task ids must fail closed");
            assert!(err.contains(error_codes::ERR_CLP_INVALID_TASK_ID));
            assert!(err.contains(expected_detail), "unexpected error: {err}");
        }
    }

    #[test]
    fn test_preempt_task_rejects_invalid_task_id() {
        let mut policy = ControlLanePolicy::new();
        let err = policy
            .preempt_task("task\rbad", ControlLane::Ready, 5, "trace-preempt")
            .expect_err("control characters must be rejected");
        assert!(err.contains(error_codes::ERR_CLP_INVALID_TASK_ID));
        assert!(policy.preemption_events().is_empty());
    }

    #[test]
    fn test_class_counts_reflect_reassigned_lane() {
        let mut policy = ControlLanePolicy::new();
        policy.assignments[ControlTaskClass::StaleEntryCleanup.as_index()].lane =
            ControlLane::Timed;

        let counts = policy.class_counts_per_lane();

        assert_eq!(*counts.get(&ControlLane::Ready).unwrap(), 6);
        assert_eq!(*counts.get(&ControlLane::Timed).unwrap(), 8);
        assert_eq!(counts.values().sum::<usize>(), policy.total_task_classes());
    }

    #[test]
    fn test_snapshot_round_trip() {
        let policy = ControlLanePolicy::new();
        let snap = ControlLanePolicySnapshot::from_policy(&policy);
        let json = serde_json::to_string(&snap).unwrap();
        let restored: ControlLanePolicySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.schema_version, SCHEMA_VERSION);
        assert_eq!(restored.task_class_count, CONTROL_TASK_CLASS_COUNT);
        assert_eq!(restored.lane_count, 3);
    }

    #[test]
    fn test_lane_display() {
        assert_eq!(format!("{}", ControlLane::Cancel), "cancel");
        assert_eq!(format!("{}", ControlLane::Timed), "timed");
        assert_eq!(format!("{}", ControlLane::Ready), "ready");
    }

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::LAN_001, "LAN-001");
        assert_eq!(event_codes::LAN_002, "LAN-002");
        assert_eq!(event_codes::LAN_003, "LAN-003");
        assert_eq!(event_codes::LAN_004, "LAN-004");
        assert_eq!(event_codes::LAN_005, "LAN-005");
        assert_eq!(event_codes::LAN_006, "LAN-006");
    }

    #[test]
    fn test_error_codes_defined() {
        let _ = error_codes::ERR_CLP_UNKNOWN_TASK;
        let _ = error_codes::ERR_CLP_BUDGET_OVERFLOW;
        let _ = error_codes::ERR_CLP_STARVATION;
        let _ = error_codes::ERR_CLP_PREEMPT_FAIL;
        let _ = error_codes::ERR_CLP_CANCEL_STARVED;
        let _ = error_codes::ERR_CLP_INVALID_BUDGET;
        let _ = error_codes::ERR_CLP_DUPLICATE_CLASS;
        let _ = error_codes::ERR_CLP_POLICY_MISMATCH;
        let _ = error_codes::ERR_CLP_INVALID_TASK_ID;
        let _ = error_codes::ERR_CLP_DEADLINE_QUEUE_FULL;
    }

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "clp-v1.0");
    }

    #[test]
    fn test_starvation_threshold_cancel() {
        assert_eq!(ControlLane::Cancel.max_starve_ticks(), 1);
    }

    #[test]
    fn test_starvation_threshold_others() {
        assert_eq!(
            ControlLane::Timed.max_starve_ticks(),
            DEFAULT_STARVATION_THRESHOLD_TICKS
        );
        assert_eq!(
            ControlLane::Ready.max_starve_ticks(),
            DEFAULT_STARVATION_THRESHOLD_TICKS
        );
    }

    #[test]
    fn test_invariant_markers_present() {
        // These are the invariant IDs from the module doc
        let src = include_str!("control_lane_policy.rs");
        assert!(src.contains("INV-CLP-LANE-ASSIGNED"));
        assert!(src.contains("INV-CLP-BUDGET-SUM"));
        assert!(src.contains("INV-CLP-CANCEL-PRIORITY"));
        assert!(src.contains("INV-CLP-STARVATION-DETECT"));
        assert!(src.contains("INV-CLP-CANCEL-NO-STARVE"));
        assert!(src.contains("INV-CLP-PREEMPT"));
    }
}
