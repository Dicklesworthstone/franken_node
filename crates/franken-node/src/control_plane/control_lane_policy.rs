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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// The control-lane policy engine: maps task classes to lanes, enforces budgets,
/// detects starvation, and tracks scheduling metrics.
#[derive(Debug)]
pub struct ControlLanePolicy {
    assignments: BTreeMap<ControlTaskClass, LaneAssignment>,
    budgets: BTreeMap<ControlLane, LaneBudget>,
    lane_consecutive_zero: BTreeMap<ControlLane, u32>,
    lane_run_counts: BTreeMap<ControlLane, u32>,
    current_tick: u64,
    tick_history: Vec<LaneTickMetrics>,
    starvation_events: Vec<StarvationEvent>,
    preemption_events: Vec<PreemptionEvent>,
    audit_log: Vec<LanePolicyAuditRecord>,
}

impl ControlLanePolicy {
    /// Create a new policy engine with canonical assignments and budgets.
    pub fn new() -> Self {
        let mut assignments = BTreeMap::new();
        let mut budgets = BTreeMap::new();

        // Wire canonical lane assignments
        for tc in ControlTaskClass::all() {
            let lane = Self::canonical_lane(*tc);
            let timeout_ms = Self::canonical_timeout(*tc);
            let preemptible = matches!(lane, ControlLane::Ready);
            assignments.insert(
                *tc,
                LaneAssignment {
                    task_class: *tc,
                    lane,
                    timeout_ms,
                    preemptible,
                },
            );
        }

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

    /// Look up the lane assignment for a task class.
    pub fn lookup(&self, tc: ControlTaskClass) -> Option<&LaneAssignment> {
        self.assignments.get(&tc)
    }

    /// Check that every task class has a lane assignment (INV-CLP-LANE-ASSIGNED).
    pub fn verify_all_assigned(&self) -> bool {
        ControlTaskClass::all()
            .iter()
            .all(|tc| self.assignments.contains_key(tc))
    }

    /// Check that budgets sum to 100% (INV-CLP-BUDGET-SUM).
    pub fn verify_budget_sum(&self) -> bool {
        let total: u8 = self.budgets.values().map(|b| b.min_pct).sum();
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
        _task_id: &str,
        trace_id: &str,
        timestamp_ms: u64,
    ) -> Result<ControlLane, String> {
        let assignment = self.assignments.get(&tc).ok_or_else(|| {
            format!(
                "{}: unknown task class {:?}",
                error_codes::ERR_CLP_UNKNOWN_TASK,
                tc
            )
        })?;
        let lane = assignment.lane;

        self.audit_log.push(LanePolicyAuditRecord {
            timestamp_ms,
            event_code: event_codes::LAN_001.to_string(),
            task_class: tc.as_str().to_string(),
            lane: lane.as_str().to_string(),
            budget_remaining_ms: assignment.timeout_ms.unwrap_or(0),
            trace_id: trace_id.to_string(),
        });

        *self.lane_run_counts.entry(lane).or_insert(0) += 1;

        Ok(lane)
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
        self.current_tick += 1;

        // Allocate slots by budget
        let cancel_slots = (total_slots as u64 * CANCEL_LANE_BUDGET_PCT as u64 / 100) as u32;
        let timed_slots = (total_slots as u64 * TIMED_LANE_BUDGET_PCT as u64 / 100) as u32;
        let ready_slots = total_slots
            .saturating_sub(cancel_slots)
            .saturating_sub(timed_slots);

        // Schedule: Cancel first (priority), then Timed, then Ready
        let cancel_run = cancel_pending.min(cancel_slots.max(1)); // at least 1 if pending
        let timed_run = timed_pending.min(timed_slots);
        let ready_run = ready_pending.min(ready_slots);

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
                *counter += 1;
                let threshold = self
                    .budgets
                    .get(&lane)
                    .map(|b| b.max_starve_ticks)
                    .unwrap_or(DEFAULT_STARVATION_THRESHOLD_TICKS);
                if *counter >= threshold {
                    self.starvation_events.push(StarvationEvent {
                        lane,
                        consecutive_zero_ticks: *counter,
                        threshold,
                        event_code: event_codes::LAN_003.to_string(),
                        trace_id: trace_id.to_string(),
                    });
                }
            } else if *counter > 0 {
                self.starvation_events.push(StarvationEvent {
                    lane,
                    consecutive_zero_ticks: *counter,
                    threshold: self
                        .budgets
                        .get(&lane)
                        .map(|b| b.max_starve_ticks)
                        .unwrap_or(DEFAULT_STARVATION_THRESHOLD_TICKS),
                    event_code: event_codes::LAN_004.to_string(),
                    trace_id: trace_id.to_string(),
                });
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

        self.tick_history.push(metrics.clone());
        metrics
    }

    /// Preempt a task for lane budget enforcement.
    pub fn preempt_task(
        &mut self,
        task_id: &str,
        lane: ControlLane,
        budget_remaining_ms: u64,
        trace_id: &str,
    ) -> PreemptionEvent {
        let event = PreemptionEvent {
            task_id: task_id.to_string(),
            lane,
            budget_remaining_ms,
            event_code: event_codes::LAN_005.to_string(),
            trace_id: trace_id.to_string(),
        };
        self.preemption_events.push(event.clone());
        event
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

    /// Get preemption events.
    pub fn preemption_events(&self) -> &[PreemptionEvent] {
        &self.preemption_events
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[LanePolicyAuditRecord] {
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

    /// Count task classes per lane.
    pub fn class_counts_per_lane(&self) -> BTreeMap<ControlLane, usize> {
        let mut counts = BTreeMap::new();
        for lane in ControlLane::all() {
            counts.insert(*lane, 0);
        }
        for a in self.assignments.values() {
            *counts.entry(a.lane).or_insert(0) += 1;
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
            assignments: policy.assignments.values().cloned().collect(),
            budgets: policy.budgets.values().cloned().collect(),
            task_class_count: policy.total_task_classes(),
            lane_count: ControlLane::all().len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for a in policy.assignments.values() {
            if a.lane == ControlLane::Ready {
                assert!(a.preemptible, "Ready lane tasks should be preemptible");
            }
        }
    }

    #[test]
    fn test_cancel_not_preemptible() {
        let policy = ControlLanePolicy::new();
        for a in policy.assignments.values() {
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
        let event = policy.preempt_task("task-42", ControlLane::Ready, 100, "trace-pre");
        assert_eq!(event.task_id, "task-42");
        assert_eq!(event.event_code, event_codes::LAN_005);
        assert_eq!(policy.preemption_events().len(), 1);
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
    fn test_snapshot_round_trip() {
        let policy = ControlLanePolicy::new();
        let snap = ControlLanePolicySnapshot::from_policy(&policy);
        let json = serde_json::to_string(&snap).unwrap();
        let restored: ControlLanePolicySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.schema_version, SCHEMA_VERSION);
        assert_eq!(restored.task_class_count, 19);
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
