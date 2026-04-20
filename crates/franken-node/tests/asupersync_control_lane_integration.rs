use asupersync::obligation::ledger::{LedgerStats, ObligationLedger};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::runtime::RuntimeBuilder;
use asupersync::{CancelKind, Cx, Time};
use frankenengine_node::runtime::lane_scheduler::{
    LaneScheduler, SchedulerLane, default_policy, event_codes, task_classes,
};

#[derive(Debug, PartialEq, Eq)]
struct LaneExecutionReport {
    admitted_lane: SchedulerLane,
    active_after_close: usize,
    pending_obligations_after_close: u64,
    total_committed: u64,
    total_aborted: u64,
    total_leaked: u64,
    cancellation_observed: bool,
    leak_check_clean: bool,
    audit_events: Vec<String>,
}

fn execute_control_lane_with_obligation(
    cx: &Cx,
    scheduler: &mut LaneScheduler,
    ledger: &mut ObligationLedger,
    trace_id: &str,
    start_ms: u64,
    cancel_before_effect_commit: bool,
) -> LaneExecutionReport {
    cx.checkpoint()
        .expect("fresh Cx must pass the initial scheduler checkpoint");

    let task_class = task_classes::epoch_transition();
    let assignment = scheduler
        .assign_task(&task_class, start_ms, trace_id)
        .expect("control-plane task should be admitted to the scheduler");
    assert_eq!(assignment.lane, SchedulerLane::ControlCritical);

    let obligation = ledger.acquire(
        ObligationKind::SemaphorePermit,
        cx.task_id(),
        cx.region_id(),
        Time::from_millis(start_ms),
    );

    let cancellation_observed = if cancel_before_effect_commit {
        cx.cancel_with(CancelKind::User, Some("integration test lane cancellation"));
        let checkpoint_rejected = cx.checkpoint().is_err();
        assert!(checkpoint_rejected, "cancelled Cx must fail a checkpoint");

        let pending_ids = ledger.pending_ids_for_region(cx.region_id());
        assert_eq!(
            pending_ids,
            vec![obligation.id()],
            "the in-flight lane obligation must be visible before cancellation drain"
        );

        ledger.abort(
            obligation,
            Time::from_millis(start_ms.saturating_add(1)),
            ObligationAbortReason::Cancel,
        );
        true
    } else {
        cx.checkpoint()
            .expect("uncancelled lane should pass its pre-commit checkpoint");
        ledger.commit(obligation, Time::from_millis(start_ms.saturating_add(1)));
        false
    };

    scheduler
        .complete_task(&assignment.task_id, start_ms.saturating_add(2), trace_id)
        .expect("completed or cancelled lane must release scheduler capacity");

    let stats = ledger.stats();
    let leak_check = ledger.check_region_leaks(cx.region_id());
    let audit_events = scheduler
        .audit_log()
        .iter()
        .map(|record| record.event_code.clone())
        .collect();

    report_from_stats(
        assignment.lane,
        scheduler.total_active(),
        stats,
        cancellation_observed,
        leak_check.is_clean(),
        audit_events,
    )
}

fn report_from_stats(
    admitted_lane: SchedulerLane,
    active_after_close: usize,
    stats: LedgerStats,
    cancellation_observed: bool,
    leak_check_clean: bool,
    audit_events: Vec<String>,
) -> LaneExecutionReport {
    LaneExecutionReport {
        admitted_lane,
        active_after_close,
        pending_obligations_after_close: stats.pending,
        total_committed: stats.total_committed,
        total_aborted: stats.total_aborted,
        total_leaked: stats.total_leaked,
        cancellation_observed,
        leak_check_clean,
        audit_events,
    }
}

#[test]
fn asupersync_cx_first_control_lane_commits_obligations() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread Asupersync runtime should build");

    let report = runtime.block_on(async {
        let cx = Cx::for_request();
        let mut scheduler = LaneScheduler::new(default_policy())
            .expect("default lane scheduler policy should be valid");
        let mut ledger = ObligationLedger::new();

        execute_control_lane_with_obligation(
            &cx,
            &mut scheduler,
            &mut ledger,
            "trace-asupersync-control-commit",
            1_000,
            false,
        )
    });

    assert_eq!(
        report,
        LaneExecutionReport {
            admitted_lane: SchedulerLane::ControlCritical,
            active_after_close: 0,
            pending_obligations_after_close: 0,
            total_committed: 1,
            total_aborted: 0,
            total_leaked: 0,
            cancellation_observed: false,
            leak_check_clean: true,
            audit_events: vec![
                event_codes::LANE_ASSIGN.to_string(),
                event_codes::LANE_TASK_COMPLETED.to_string(),
            ],
        }
    );
}

#[test]
fn asupersync_cancelled_control_lane_aborts_without_obligation_leak() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread Asupersync runtime should build");

    let report = runtime.block_on(async {
        let cx = Cx::for_request();
        let mut scheduler = LaneScheduler::new(default_policy())
            .expect("default lane scheduler policy should be valid");
        let mut ledger = ObligationLedger::new();

        execute_control_lane_with_obligation(
            &cx,
            &mut scheduler,
            &mut ledger,
            "trace-asupersync-control-cancel",
            2_000,
            true,
        )
    });

    assert_eq!(
        report,
        LaneExecutionReport {
            admitted_lane: SchedulerLane::ControlCritical,
            active_after_close: 0,
            pending_obligations_after_close: 0,
            total_committed: 0,
            total_aborted: 1,
            total_leaked: 0,
            cancellation_observed: true,
            leak_check_clean: true,
            audit_events: vec![
                event_codes::LANE_ASSIGN.to_string(),
                event_codes::LANE_TASK_COMPLETED.to_string(),
            ],
        }
    );
}
