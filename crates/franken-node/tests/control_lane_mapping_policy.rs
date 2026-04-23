use std::collections::BTreeMap;

use frankenengine_node::control_plane::control_lane_mapping::{
    ControlLane, ControlLanePolicyError, ControlLaneScheduler, default_control_lane_policy,
    error_codes, task_classes,
};

fn assert_canonical_lane_error(error: ControlLanePolicyError, task_class: &str) {
    assert_eq!(error.code(), error_codes::ERR_CLM_INCOMPLETE_MAP);
    let detail = error.to_string();
    assert!(
        detail.contains(task_class),
        "error should name downgraded task class: {detail}"
    );
    assert!(
        detail.contains("canonical task"),
        "error should describe canonical lane violation: {detail}"
    );
}

#[test]
fn validate_rejects_cancellation_handler_ready_safety_downgrade() {
    let mut policy = default_control_lane_policy();
    policy.assign(&task_classes::cancellation_handler(), ControlLane::Ready);

    let error = policy
        .validate()
        .expect_err("cancellation_handler must remain on cancel lane");
    assert_canonical_lane_error(error, "cancellation_handler");

    let scheduler_error = ControlLaneScheduler::new(policy)
        .expect_err("scheduler construction must reject wrong-lane cancellation handler");
    assert_canonical_lane_error(scheduler_error, "cancellation_handler");
}

#[test]
fn validate_rejects_lease_renewal_ready_deadline_downgrade() {
    let mut policy = default_control_lane_policy();
    policy.assign(&task_classes::lease_renewal(), ControlLane::Ready);

    let error = policy
        .validate()
        .expect_err("lease_renewal must remain on timed lane");
    assert_canonical_lane_error(error, "lease_renewal");

    let scheduler_error = ControlLaneScheduler::new(policy)
        .expect_err("scheduler construction must reject wrong-lane lease renewal");
    assert_canonical_lane_error(scheduler_error, "lease_renewal");
}

#[test]
fn assignment_without_run_triggers_starvation_instead_of_masking_it() {
    let mut scheduler =
        ControlLaneScheduler::new(default_control_lane_policy()).expect("scheduler");

    let assigned = scheduler
        .assign_task(&task_classes::cancellation_handler(), 1000, "trace-assign")
        .expect("assignment should classify cancel task");
    assert_eq!(assigned, ControlLane::Cancel);

    let cancel_after_assignment = scheduler
        .counters()
        .get("cancel")
        .expect("cancel counters after assignment");
    assert_eq!(cancel_after_assignment.tasks_assigned, 1);
    assert_eq!(cancel_after_assignment.tasks_run, 0);
    assert_eq!(cancel_after_assignment.consecutive_empty_ticks, 0);

    let alerts = scheduler.advance_tick(&BTreeMap::new(), 1001, "trace-empty");
    assert_eq!(
        alerts,
        vec![ControlLanePolicyError::Starvation {
            lane: ControlLane::Cancel,
            consecutive_ticks: 1,
        }]
    );

    let cancel_after_empty_tick = scheduler
        .counters()
        .get("cancel")
        .expect("cancel counters after empty tick");
    assert_eq!(cancel_after_empty_tick.tasks_assigned, 1);
    assert_eq!(cancel_after_empty_tick.tasks_run, 0);
    assert_eq!(cancel_after_empty_tick.consecutive_empty_ticks, 1);

    let mut ran = BTreeMap::new();
    ran.insert("cancel".to_string(), 1);
    let alerts = scheduler.advance_tick(&ran, 1002, "trace-run");
    assert!(alerts.is_empty());

    let cancel_after_run = scheduler
        .counters()
        .get("cancel")
        .expect("cancel counters after actual run");
    assert_eq!(cancel_after_run.tasks_assigned, 1);
    assert_eq!(cancel_after_run.tasks_run, 1);
    assert_eq!(cancel_after_run.consecutive_empty_ticks, 0);
}
