#[path = "../../../tests/conformance/control_lane_policy.rs"]
mod control_lane_policy;

mod security {
    pub mod constant_time {
        pub fn ct_eq(a: &str, b: &str) -> bool {
            frankenengine_node::security::constant_time::ct_eq(a, b)
        }
    }
}

#[path = "../src/control_plane/root_pointer.rs"]
mod root_pointer;

use frankenengine_node::control_plane::cancellation_protocol::{
    CancelPhase, CancelProtocolError, CancellationProtocol, DEFAULT_MAX_RECORDS,
};
use frankenengine_node::control_plane::control_lane_policy::{
    event_codes, ControlLane, ControlLanePolicy, ControlTaskClass,
};

#[test]
fn one_slot_tick_prefers_timed_over_ready_when_cancel_empty() {
    let mut policy = ControlLanePolicy::new();

    let metrics = policy.tick(0, 1, 1, 1, "trace-one-slot-timed");

    assert_eq!(metrics.cancel_lane_tasks_run, 0);
    assert_eq!(metrics.timed_lane_tasks_run, 1);
    assert_eq!(metrics.ready_lane_tasks_run, 0);
    assert!(!metrics.timed_lane_starved);
    assert!(metrics.ready_lane_starved);
}

#[test]
fn two_slot_tick_serves_cancel_and_timed_before_ready() {
    let mut policy = ControlLanePolicy::new();

    let metrics = policy.tick(1, 1, 1, 2, "trace-two-slot-priority");

    assert_eq!(metrics.cancel_lane_tasks_run, 1);
    assert_eq!(metrics.timed_lane_tasks_run, 1);
    assert_eq!(metrics.ready_lane_tasks_run, 0);
    assert!(!metrics.cancel_lane_starved);
    assert!(!metrics.timed_lane_starved);
    assert!(metrics.ready_lane_starved);
}

#[test]
fn deadline_aware_tick_times_out_expired_timed_task_fail_closed() {
    let mut policy = ControlLanePolicy::new();
    policy
        .enqueue_deadline_task(
            ControlTaskClass::LeaseRenewal,
            "lease-expired",
            1_000,
            "trace-enqueue",
        )
        .expect("timed task should enqueue");

    let result = policy.tick_deadline_aware(31_000, 4, "trace-deadline");

    assert_eq!(result.timed_out_task_ids, vec!["lease-expired"]);
    assert!(
        !result
            .scheduled_task_ids
            .iter()
            .any(|task_id| task_id == "lease-expired")
    );
    assert!(policy.deadline_queue().is_empty());
    assert!(policy.preemption_events().iter().any(|event| {
        event.task_id == "lease-expired"
            && event.lane == ControlLane::Timed
            && event.budget_remaining_ms == 0
            && event.event_code == event_codes::LAN_006
    }));
    assert!(policy.audit_log().iter().any(|record| {
        record.event_code == event_codes::LAN_006
            && record.task_class == ControlTaskClass::LeaseRenewal.as_str()
            && record.lane == ControlLane::Timed.as_str()
            && record.budget_remaining_ms == 0
    }));
}

#[test]
fn deadline_aware_tick_schedules_timed_by_earliest_deadline() {
    let mut policy = ControlLanePolicy::new();
    policy
        .enqueue_deadline_task(
            ControlTaskClass::LeaseRenewal,
            "lease-late",
            10_000,
            "trace-late",
        )
        .expect("late task should enqueue");
    policy
        .enqueue_deadline_task(
            ControlTaskClass::HealthCheck,
            "health-early",
            2_000,
            "trace-early",
        )
        .expect("early task should enqueue");

    let result = policy.tick_deadline_aware(20_000, 10, "trace-order");
    let early_position = result
        .scheduled_task_ids
        .iter()
        .position(|task_id| task_id == "health-early")
        .expect("early timed task should schedule");
    let late_position = result
        .scheduled_task_ids
        .iter()
        .position(|task_id| task_id == "lease-late")
        .expect("late timed task should schedule");

    assert!(early_position < late_position);
    assert!(result.timed_out_task_ids.is_empty());
}

#[test]
fn cancellation_records_fail_closed_when_all_active_slots_are_full() {
    let mut protocol = CancellationProtocol::default();

    for index in 0..DEFAULT_MAX_RECORDS {
        let workflow_id = format!("active-cancel-{index}");
        protocol
            .request_cancel(
                &workflow_id,
                1,
                u64::try_from(index).unwrap(),
                "trace-capacity",
            )
            .expect("active cancellation record should be retained");
    }

    let err = protocol
        .request_cancel(
            "overflow-active-cancel",
            1,
            u64::try_from(DEFAULT_MAX_RECORDS).unwrap(),
            "trace-capacity",
        )
        .expect_err("active cancellation capacity must fail closed");

    eprintln!(
        "{}",
        serde_json::json!({
            "suite": "control_lane_policy",
            "surface": "control_plane_cancellation_protocol",
            "phase": "capacity_guard",
            "active_records": protocol.records().len(),
            "error_code": err.code(),
            "event": "active_cancellation_capacity_fail_closed"
        })
    );

    assert_eq!(err.code(), "ERR_CANCEL_INVARIANT");
    assert!(matches!(
        err,
        CancelProtocolError::InvariantViolation { .. }
    ));
    assert_eq!(protocol.records().len(), DEFAULT_MAX_RECORDS);
    assert_eq!(
        protocol.current_phase("active-cancel-0"),
        Some(CancelPhase::CancelRequested)
    );
    assert_eq!(protocol.current_phase("overflow-active-cancel"), None);
}
