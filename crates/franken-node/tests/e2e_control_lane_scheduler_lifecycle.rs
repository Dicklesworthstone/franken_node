//! Mock-free end-to-end test for the control-plane lane scheduler.
//!
//! Drives `frankenengine_node::control_plane::control_lane_mapping` end-to-end:
//!   - `default_control_lane_policy` validates,
//!   - `ControlLaneScheduler::new` accepts the canonical policy,
//!   - `assign_task` resolves every well-known task class to its canonical
//!     lane (Cancel/Timed/Ready) and records an audit record,
//!   - `assign_task` for an UNKNOWN task class returns
//!     `ERR_CLM_UNKNOWN_TASK`,
//!   - `advance_tick` starvation detection fires when a backlogged lane
//!     gets zero tasks_run for `starvation_threshold_ticks` consecutive
//!     ticks (INV-CLM-STARVATION-DETECT),
//!   - `select_next_lane` honors INV-CLM-CANCEL-PRIORITY: Cancel preempts
//!     Timed which preempts Ready,
//!   - validation rejects invalid budgets (cancel < 20%, timed < 30%,
//!     budget total > 100%, total != 100%, starvation_threshold == 0)
//!     and missing canonical task assignments
//!     (INV-CLM-CANCEL-MIN-BUDGET, INV-CLM-TIMED-MIN-BUDGET,
//!     INV-CLM-BUDGET-SUM, INV-CLM-COMPLETE-MAP).
//!
//! Bead: bd-30odw.
//!
//! No mocks: real `ControlLanePolicy`, real `ControlLaneScheduler`, real
//! BTreeMap-backed counters, real audit log. Each phase emits a
//! structured tracing event PLUS a JSON-line on stderr.

use std::collections::BTreeMap;
use std::sync::Once;
use std::time::Instant;

use frankenengine_node::control_plane::control_lane_mapping::{
    ControlLane, ControlLanePolicy, ControlLanePolicyError, ControlLaneScheduler,
    ControlTaskClass, LaneBudget, default_control_lane_policy, select_next_lane, task_classes,
};
use serde_json::json;
use tracing::{error, info};

static TEST_TRACING_INIT: Once = Once::new();

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

#[derive(serde::Serialize)]
struct PhaseLog<'a> {
    timestamp: String,
    test_name: &'a str,
    phase: &'a str,
    duration_ms: u64,
    success: bool,
    detail: serde_json::Value,
}

struct Harness {
    test_name: &'static str,
    started: Instant,
}

impl Harness {
    fn new(test_name: &'static str) -> Self {
        init_test_tracing();
        let h = Self {
            test_name,
            started: Instant::now(),
        };
        h.log_phase("setup", true, json!({}));
        h
    }

    fn log_phase(&self, phase: &str, success: bool, detail: serde_json::Value) {
        let entry = PhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name,
            phase,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            success,
            detail,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&entry).expect("phase log serializes")
        );
        if success {
            info!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase completed"
            );
        } else {
            error!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase failed"
            );
        }
    }
}

#[test]
fn e2e_control_lane_scheduler_canonical_policy_assigns_every_class() {
    let h = Harness::new("e2e_control_lane_scheduler_canonical_policy_assigns_every_class");

    let policy = default_control_lane_policy();
    policy.validate().expect("default policy validates");
    let mut scheduler = ControlLaneScheduler::new(policy).expect("scheduler builds");
    h.log_phase("scheduler_built", true, json!({}));

    // Every canonical task class must resolve to its expected lane.
    let cases = [
        (task_classes::cancellation_handler(), ControlLane::Cancel),
        (task_classes::drain_operation(), ControlLane::Cancel),
        (task_classes::region_close(), ControlLane::Cancel),
        (task_classes::shutdown_handler(), ControlLane::Cancel),
        (task_classes::health_check(), ControlLane::Timed),
        (task_classes::lease_renewal(), ControlLane::Timed),
        (task_classes::epoch_transition(), ControlLane::Timed),
        (task_classes::barrier_coordination(), ControlLane::Timed),
        (task_classes::marker_append(), ControlLane::Timed),
        (task_classes::telemetry_flush(), ControlLane::Ready),
        (task_classes::evidence_archival(), ControlLane::Ready),
        (task_classes::compaction(), ControlLane::Ready),
        (task_classes::garbage_collection(), ControlLane::Ready),
        (task_classes::log_rotation(), ControlLane::Ready),
    ];
    for (cls, expected_lane) in &cases {
        let lane = scheduler
            .assign_task(cls, 1_000, "trace-assign")
            .expect("assign ok");
        assert_eq!(lane, *expected_lane, "{}", cls.as_str());
    }
    h.log_phase("all_canonical_classes", true, json!({"count": cases.len()}));

    // Audit log records each assignment.
    assert_eq!(scheduler.audit_log().len(), cases.len());
    for record in scheduler.audit_log() {
        assert_eq!(record.event_code, "CLM_TASK_ASSIGNED");
    }
    h.log_phase("audit_log_complete", true, json!({"records": cases.len()}));

    // Unknown task → UnknownTask.
    let err = scheduler
        .assign_task(
            &ControlTaskClass::new("not_in_policy"),
            1_001,
            "trace-unknown",
        )
        .expect_err("unknown rejected");
    assert!(matches!(err, ControlLanePolicyError::UnknownTask { .. }));
    assert_eq!(err.code(), "ERR_CLM_UNKNOWN_TASK");
    h.log_phase("unknown_rejected", true, json!({"code": err.code()}));
}

#[test]
fn e2e_control_lane_policy_validation_rejects_bad_budgets() {
    let h = Harness::new("e2e_control_lane_policy_validation_rejects_bad_budgets");

    // INV-CLM-CANCEL-MIN-BUDGET: cancel under 20% rejected.
    let mut bad_cancel = default_control_lane_policy();
    bad_cancel.set_budget(LaneBudget {
        lane: ControlLane::Cancel,
        min_percent: 10,
        starvation_threshold_ticks: 1,
    });
    let err = bad_cancel.validate().expect_err("cancel<20 rejected");
    match err {
        ControlLanePolicyError::InvalidBudget { lane: ControlLane::Cancel, detail } => {
            assert!(detail.contains("cancel"));
            h.log_phase("cancel_min_budget", true, json!({"detail": detail}));
        }
        other => panic!("expected InvalidBudget(Cancel), got {other:?}"),
    }

    // INV-CLM-TIMED-MIN-BUDGET: timed under 30% rejected.
    let mut bad_timed = default_control_lane_policy();
    bad_timed.set_budget(LaneBudget {
        lane: ControlLane::Timed,
        min_percent: 20,
        starvation_threshold_ticks: 2,
    });
    let err = bad_timed.validate().expect_err("timed<30 rejected");
    assert!(matches!(
        err,
        ControlLanePolicyError::InvalidBudget {
            lane: ControlLane::Timed,
            ..
        }
    ));
    h.log_phase("timed_min_budget", true, json!({}));

    // INV-CLM-BUDGET-SUM: total > 100% rejected.
    let mut overflow = default_control_lane_policy();
    overflow.set_budget(LaneBudget {
        lane: ControlLane::Cancel,
        min_percent: 60,
        starvation_threshold_ticks: 1,
    });
    overflow.set_budget(LaneBudget {
        lane: ControlLane::Timed,
        min_percent: 60,
        starvation_threshold_ticks: 2,
    });
    let err = overflow.validate().expect_err("overflow rejected");
    assert!(matches!(
        err,
        ControlLanePolicyError::BudgetOverflow { .. }
    ));
    assert_eq!(err.code(), "ERR_CLM_BUDGET_OVERFLOW");
    h.log_phase("budget_overflow", true, json!({"code": err.code()}));

    // INV-CLM-BUDGET-SUM (≠100): undershoot rejected as InvalidBudget on Ready.
    let mut undershoot = default_control_lane_policy();
    undershoot.set_budget(LaneBudget {
        lane: ControlLane::Ready,
        min_percent: 30, // 20+30+30 = 80 != 100
        starvation_threshold_ticks: 3,
    });
    let err = undershoot.validate().expect_err("undershoot rejected");
    assert!(matches!(
        err,
        ControlLanePolicyError::InvalidBudget { .. }
    ));
    h.log_phase("budget_under_100", true, json!({}));

    // starvation_threshold_ticks=0 rejected.
    let mut zero_thresh = default_control_lane_policy();
    zero_thresh.set_budget(LaneBudget {
        lane: ControlLane::Ready,
        min_percent: 50,
        starvation_threshold_ticks: 0,
    });
    let err = zero_thresh.validate().expect_err("zero threshold rejected");
    assert!(matches!(
        err,
        ControlLanePolicyError::InvalidBudget { .. }
    ));
    h.log_phase("zero_threshold", true, json!({}));
}

#[test]
fn e2e_control_lane_policy_rejects_missing_canonical_assignments() {
    let h = Harness::new("e2e_control_lane_policy_rejects_missing_canonical_assignments");

    // Hand-build a partial policy — missing the canonical task table.
    let mut policy = ControlLanePolicy::new();
    policy.assign(&task_classes::health_check(), ControlLane::Timed);
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
        starvation_threshold_ticks: 3,
    });

    let err = policy.validate().expect_err("incomplete map rejected");
    let code = err.code();
    match &err {
        ControlLanePolicyError::IncompleteMap { detail } => {
            assert!(detail.contains("missing canonical task"));
            assert_eq!(code, "ERR_CLM_INCOMPLETE_MAP");
            h.log_phase("incomplete_map", true, json!({"detail": detail}));
        }
        other => panic!("expected IncompleteMap, got {other:?}"),
    }

    // Empty assignments rejected first.
    let empty = ControlLanePolicy::new();
    let err = empty.validate().expect_err("empty rejected");
    assert!(matches!(err, ControlLanePolicyError::IncompleteMap { .. }));
    h.log_phase("empty_rejected", true, json!({}));
}

#[test]
fn e2e_control_lane_scheduler_starvation_detection() {
    let h = Harness::new("e2e_control_lane_scheduler_starvation_detection");

    let mut scheduler = ControlLaneScheduler::new(default_control_lane_policy()).unwrap();

    // Load up Ready lane with 5 tasks pending.
    for _ in 0..5 {
        scheduler
            .assign_task(&task_classes::compaction(), 100, "trace-load")
            .expect("assign ok");
    }
    h.log_phase("loaded_ready_lane", true, json!({"queued": 5}));

    // Run a tick where Cancel/Timed both run and Ready does NOT — Ready
    // has tasks_assigned=5 but tasks_run=0, so consecutive_empty_ticks
    // increments. After `starvation_threshold_ticks` consecutive empty
    // ticks, an alert fires (INV-CLM-STARVATION-DETECT). Default Ready
    // threshold from `default_control_lane_policy` is 3, so loop 3 ticks.
    let mut by_lane = BTreeMap::new();
    by_lane.insert("cancel".to_string(), 0u64);
    by_lane.insert("timed".to_string(), 0u64);
    by_lane.insert("ready".to_string(), 0u64);
    let mut ready_starvation_alerts = 0;
    for tick in 0..4 {
        let alerts = scheduler.advance_tick(&by_lane, 200 + tick, "trace-tick");
        for a in &alerts {
            if let ControlLanePolicyError::Starvation { lane, .. } = a {
                if *lane == ControlLane::Ready {
                    ready_starvation_alerts += 1;
                }
            }
        }
    }
    assert!(
        ready_starvation_alerts >= 1,
        "expected at least one Ready starvation alert across 4 empty ticks; got {}",
        ready_starvation_alerts
    );
    h.log_phase(
        "ready_starvation_fired",
        true,
        json!({"alerts": ready_starvation_alerts}),
    );

    // Now run a tick that schedules Ready tasks → empty-tick counter resets.
    by_lane.insert("ready".to_string(), 5);
    let alerts = scheduler.advance_tick(&by_lane, 1_000, "trace-recover");
    let still_starved = alerts
        .iter()
        .any(|a| matches!(a, ControlLanePolicyError::Starvation { lane, .. } if *lane == ControlLane::Ready));
    assert!(!still_starved, "Ready should no longer be starved after 5 tasks_run");
    h.log_phase("starvation_cleared", true, json!({}));

    // Metrics snapshot reports the cumulative tasks_run.
    let metrics = scheduler.starvation_metrics();
    assert_eq!(metrics.ready_tasks_run, 5);
    h.log_phase(
        "metrics_snapshot",
        true,
        json!({"ready_tasks_run": metrics.ready_tasks_run, "tick": metrics.tick}),
    );
}

#[test]
fn e2e_control_lane_select_next_lane_priority() {
    let h = Harness::new("e2e_control_lane_select_next_lane_priority");

    // INV-CLM-CANCEL-PRIORITY: Cancel preempts Timed which preempts Ready.
    let mut pending = BTreeMap::new();
    pending.insert(ControlLane::Cancel, 1usize);
    pending.insert(ControlLane::Timed, 5);
    pending.insert(ControlLane::Ready, 100);
    assert_eq!(select_next_lane(&pending), Some(ControlLane::Cancel));
    h.log_phase("cancel_wins", true, json!({}));

    // No Cancel → Timed wins.
    pending.insert(ControlLane::Cancel, 0);
    assert_eq!(select_next_lane(&pending), Some(ControlLane::Timed));
    h.log_phase("timed_wins", true, json!({}));

    // No Cancel and no Timed → Ready wins.
    pending.insert(ControlLane::Timed, 0);
    assert_eq!(select_next_lane(&pending), Some(ControlLane::Ready));
    h.log_phase("ready_wins", true, json!({}));

    // All zero → None.
    pending.insert(ControlLane::Ready, 0);
    assert_eq!(select_next_lane(&pending), None);
    h.log_phase("none_when_all_zero", true, json!({}));

    // Empty map → None.
    let empty = BTreeMap::new();
    assert_eq!(select_next_lane(&empty), None);
    h.log_phase("none_when_empty", true, json!({}));

    // Priority ranks are stable.
    assert_eq!(ControlLane::Cancel.priority_rank(), 0);
    assert_eq!(ControlLane::Timed.priority_rank(), 1);
    assert_eq!(ControlLane::Ready.priority_rank(), 2);
    h.log_phase("priority_ranks_stable", true, json!({}));
}
