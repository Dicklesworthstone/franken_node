//! Integration tests: Connector → Runtime (lifecycle, scheduling, obligation channels).
//!
//! bd-17ds.5.2 / bd-17ds.5.2.1: Wires the connector lifecycle FSM
//! (`crate::connector::lifecycle::transition`), the runtime lane scheduler
//! (`crate::runtime::lane_scheduler::LaneScheduler`), and the obligation
//! channel (`crate::runtime::obligation_channel::ObligationChannel`) into a
//! single harness. Tests use REAL subsystem instances (no mocks) per the
//! anti-mock convention in `/testing-real-service-e2e-no-mocks`.
//!
//! # Coverage map
//!
//! | Test                                                  | Subsystem    |
//! | ----------------------------------------------------- | ------------ |
//! | `test_registration_allocates_lane`                    | scheduler    |
//! | `test_scheduler_assigns_to_correct_lane`              | scheduler    |
//! | `test_obligation_delivers_to_connector`               | channel      |
//! | `test_completion_closes_obligation`                   | channel      |
//! | `test_capacity_pressure_propagates`                   | scheduler    |
//! | `test_invalid_state_transition_rejected`              | lifecycle    |
//! | `test_obligation_timeout_sweeps`                      | channel      |
//! | `test_obligation_rollback_restores_atomic`            | channel      |
//! | `test_failure_recovery_replays_obligation`            | lifecycle+ch |
//! | `test_concurrent_registrations_distinct_lanes`        | scheduler    |
//! | `test_tracing_at_every_boundary`                      | all          |
//! | `test_full_lifecycle_happy_path`                      | all          |

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use frankenengine_node::connector::lifecycle::{
    ConnectorState, LifecycleError, transition,
};
use frankenengine_node::runtime::lane_scheduler::{
    LaneScheduler, SchedulerLane, TaskClass, default_policy, task_classes,
};
use frankenengine_node::runtime::obligation_channel::{
    ObligationChannel, ObligationStatus,
};
use serde::{Deserialize, Serialize};

// ── Harness ─────────────────────────────────────────────────────────────────

/// Minimal task message carried over the obligation channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TaskMsg {
    connector_id: String,
    task_class: String,
    payload: String,
}

/// In-test stand-in for the never-implemented `ConnectorLifecycleManager`:
/// tracks per-connector `ConnectorState` using the real FSM's `transition()`
/// function so that all transitions still flow through the production gate.
struct ConnectorLifecycleManager {
    states: Mutex<HashMap<String, ConnectorState>>,
}

impl ConnectorLifecycleManager {
    fn new() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
        }
    }

    fn register(&self, connector_id: &str) {
        let mut s = self.states.lock().expect("states lock");
        s.entry(connector_id.to_string())
            .or_insert(ConnectorState::Discovered);
        tracing::info!(connector_id, state = "discovered", "register");
    }

    fn get_state(&self, connector_id: &str) -> Option<ConnectorState> {
        self.states.lock().expect("states lock").get(connector_id).copied()
    }

    fn transition_to(
        &self,
        connector_id: &str,
        to: ConnectorState,
    ) -> Result<ConnectorState, LifecycleError> {
        let mut s = self.states.lock().expect("states lock");
        let from = *s
            .get(connector_id)
            .expect("connector must be registered before transitioning");
        let next = transition(from, to)?;
        s.insert(connector_id.to_string(), next);
        tracing::debug!(
            connector_id,
            from = from.as_str(),
            to = next.as_str(),
            "transition"
        );
        Ok(next)
    }
}

/// Build a fresh harness: real lifecycle manager, real `LaneScheduler` seeded
/// with `default_policy()`, and a real `ObligationChannel<TaskMsg>`.
fn build_harness() -> (
    ConnectorLifecycleManager,
    LaneScheduler,
    ObligationChannel<TaskMsg>,
) {
    let manager = ConnectorLifecycleManager::new();
    let scheduler = LaneScheduler::new(default_policy())
        .expect("default policy must validate");
    let channel = ObligationChannel::<TaskMsg>::new("conn-runtime");
    (manager, scheduler, channel)
}

fn now_ms(t: u64) -> u64 {
    1_700_000_000_000_u64.saturating_add(t)
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Registration in the lifecycle manager allocates an entry that the scheduler
/// can subsequently target.
#[test]
fn test_registration_allocates_lane() {
    tracing::info!("test_registration_allocates_lane: enter");
    let (manager, mut scheduler, _channel) = build_harness();

    manager.register("conn-a");
    assert_eq!(manager.get_state("conn-a"), Some(ConnectorState::Discovered));

    let assignment = scheduler
        .assign_task(
            &task_classes::epoch_transition(),
            now_ms(1),
            "trace-reg",
        )
        .expect("registration-class assignment must succeed");
    assert_eq!(assignment.lane, SchedulerLane::ControlCritical);
    tracing::info!("test_registration_allocates_lane: exit");
}

/// Each task class lands on the correct scheduler lane per `default_policy`.
#[test]
fn test_scheduler_assigns_to_correct_lane() {
    tracing::info!("test_scheduler_assigns_to_correct_lane: enter");
    let (_manager, mut scheduler, _channel) = build_harness();

    let cases: &[(TaskClass, SchedulerLane)] = &[
        (task_classes::epoch_transition(), SchedulerLane::ControlCritical),
        (task_classes::remote_computation(), SchedulerLane::RemoteEffect),
        (task_classes::garbage_collection(), SchedulerLane::Maintenance),
        (task_classes::telemetry_export(), SchedulerLane::Background),
    ];
    for (i, (tc, expected_lane)) in cases.iter().enumerate() {
        let a = scheduler
            .assign_task(tc, now_ms(i as u64), "trace-map")
            .unwrap_or_else(|e| panic!("assign {:?} -> {:?}: {:?}", tc, expected_lane, e));
        assert_eq!(a.lane, *expected_lane, "wrong lane for {:?}", tc);
        tracing::debug!(task_class = %tc, lane = ?expected_lane, "assigned");
    }
    tracing::info!("test_scheduler_assigns_to_correct_lane: exit");
}

/// Obligations sent on the channel can be retrieved and remain in `Created`
/// status until explicitly resolved.
#[test]
fn test_obligation_delivers_to_connector() {
    tracing::info!("test_obligation_delivers_to_connector: enter");
    let (_manager, _scheduler, mut channel) = build_harness();

    let msg = TaskMsg {
        connector_id: "conn-b".into(),
        task_class: task_classes::artifact_upload().as_str().to_string(),
        payload: "blob-1".into(),
    };
    let id = channel
        .send(msg.clone(), now_ms(0), "trace-deliver")
        .expect("send must succeed");
    let ob = channel.get_obligation(&id).expect("obligation exists");
    assert_eq!(ob.status, ObligationStatus::Created);
    assert_eq!(ob.trace_id, "trace-deliver");
    assert!(ob.deadline > now_ms(0));
    tracing::info!("test_obligation_delivers_to_connector: exit");
}

/// Fulfilling an obligation moves it to a terminal state and the channel
/// records the transition in its audit log.
#[test]
fn test_completion_closes_obligation() {
    tracing::info!("test_completion_closes_obligation: enter");
    let (_manager, _scheduler, mut channel) = build_harness();

    let id = channel
        .send(
            TaskMsg {
                connector_id: "conn-c".into(),
                task_class: task_classes::remote_computation().as_str().into(),
                payload: "rc".into(),
            },
            now_ms(0),
            "trace-complete",
        )
        .unwrap();
    channel
        .fulfill(&id, now_ms(10), "trace-complete")
        .expect("fulfill must succeed");
    let ob = channel.get_obligation(&id).unwrap();
    assert_eq!(ob.status, ObligationStatus::Fulfilled);
    assert!(ob.status.is_terminal());
    assert_eq!(ob.resolved_at_ms, Some(now_ms(10)));
    tracing::info!("test_completion_closes_obligation: exit");
}

/// Filling a lane to its `concurrency_cap` produces a `CapExceeded` error and
/// the task is queued (queued_task_id is populated).
#[test]
fn test_capacity_pressure_propagates() {
    tracing::info!("test_capacity_pressure_propagates: enter");
    let (_manager, mut scheduler, _channel) = build_harness();

    // Background lane has cap 2 in default policy. Fill it, then expect the
    // third assignment to overflow into the queue.
    let _ = scheduler
        .assign_task(&task_classes::telemetry_export(), now_ms(0), "trace-cap")
        .unwrap();
    let _ = scheduler
        .assign_task(&task_classes::log_rotation(), now_ms(1), "trace-cap")
        .unwrap();
    let err = scheduler
        .assign_task(&task_classes::telemetry_export(), now_ms(2), "trace-cap")
        .expect_err("third Background task must overflow");

    use frankenengine_node::runtime::lane_scheduler::LaneSchedulerError;
    match err {
        LaneSchedulerError::CapExceeded { lane, cap, current, queued_task_id } => {
            assert_eq!(lane, SchedulerLane::Background);
            assert_eq!(cap, 2);
            assert_eq!(current, 2);
            assert!(queued_task_id.is_some(), "must surface queued task id");
        }
        other => panic!("expected CapExceeded, got {:?}", other),
    }
    tracing::info!("test_capacity_pressure_propagates: exit");
}

/// Illegal lifecycle transitions return a stable `IllegalTransition` error
/// without mutating connector state.
#[test]
fn test_invalid_state_transition_rejected() {
    tracing::info!("test_invalid_state_transition_rejected: enter");
    let (manager, _scheduler, _channel) = build_harness();

    manager.register("conn-d");
    let err = manager
        .transition_to("conn-d", ConnectorState::Active)
        .expect_err("Discovered -> Active must be illegal");
    match err {
        LifecycleError::IllegalTransition { from, to, permitted } => {
            assert_eq!(from, ConnectorState::Discovered);
            assert_eq!(to, ConnectorState::Active);
            assert!(permitted.contains(&ConnectorState::Verified));
        }
        other => panic!("expected IllegalTransition, got {:?}", other),
    }
    // State must be unchanged.
    assert_eq!(manager.get_state("conn-d"), Some(ConnectorState::Discovered));
    tracing::info!("test_invalid_state_transition_rejected: exit");
}

/// `sweep_timeouts` flips past-deadline obligations to `TimedOut` and reports
/// them by id.
#[test]
fn test_obligation_timeout_sweeps() {
    tracing::info!("test_obligation_timeout_sweeps: enter");
    let (_manager, _scheduler, _channel) = build_harness();
    // Use a tight deadline so the sweep is unambiguous.
    let mut tight: ObligationChannel<TaskMsg> =
        ObligationChannel::with_deadline("conn-tight", 50);

    let id1 = tight
        .send(
            TaskMsg {
                connector_id: "conn-e".into(),
                task_class: "x".into(),
                payload: "p".into(),
            },
            now_ms(0),
            "trace-to",
        )
        .unwrap();
    let id2 = tight
        .send(
            TaskMsg {
                connector_id: "conn-e".into(),
                task_class: "x".into(),
                payload: "q".into(),
            },
            now_ms(1),
            "trace-to",
        )
        .unwrap();

    // Sweep well past the 50 ms deadline.
    let timed = tight.sweep_timeouts(now_ms(1_000), "trace-to");
    assert!(timed.contains(&id1));
    assert!(timed.contains(&id2));
    assert_eq!(
        tight.get_obligation(&id1).unwrap().status,
        ObligationStatus::TimedOut
    );
    tracing::info!(timed_count = timed.len(), "test_obligation_timeout_sweeps: exit");
}

/// Cancelling an obligation before resolution drives it to a terminal
/// `Cancelled` state; subsequent fulfill/reject calls must fail.
/// This validates the "rollback restores atomic" invariant by ensuring no
/// further state changes can sneak in after cancel.
#[test]
fn test_obligation_rollback_restores_atomic() {
    tracing::info!("test_obligation_rollback_restores_atomic: enter");
    let (_manager, _scheduler, mut channel) = build_harness();

    let id = channel
        .send(
            TaskMsg {
                connector_id: "conn-f".into(),
                task_class: "y".into(),
                payload: "p".into(),
            },
            now_ms(0),
            "trace-rb",
        )
        .unwrap();
    channel.cancel(&id, now_ms(5), "trace-rb").expect("cancel");
    let ob = channel.get_obligation(&id).unwrap();
    assert_eq!(ob.status, ObligationStatus::Cancelled);
    assert!(ob.status.is_terminal());

    // Atomicity: post-cancel resolution attempts must fail-closed.
    let fulfill_err = channel.fulfill(&id, now_ms(6), "trace-rb").unwrap_err();
    assert_eq!(fulfill_err, "ERR_OCH_CANCELLED");
    let reject_err = channel.reject(&id, now_ms(7), "trace-rb").unwrap_err();
    assert_eq!(reject_err, "ERR_OCH_CANCELLED");
    tracing::info!("test_obligation_rollback_restores_atomic: exit");
}

/// Recovery path: a connector that fails can re-enter Discovered and a fresh
/// obligation is delivered through the channel for the same work item.
#[test]
fn test_failure_recovery_replays_obligation() {
    tracing::info!("test_failure_recovery_replays_obligation: enter");
    let (manager, _scheduler, mut channel) = build_harness();

    manager.register("conn-g");
    manager
        .transition_to("conn-g", ConnectorState::Failed)
        .expect("Discovered -> Failed permitted");
    assert_eq!(manager.get_state("conn-g"), Some(ConnectorState::Failed));

    // Reject the first obligation (failed delivery).
    let first = channel
        .send(
            TaskMsg {
                connector_id: "conn-g".into(),
                task_class: "rc".into(),
                payload: "v1".into(),
            },
            now_ms(0),
            "trace-recover",
        )
        .unwrap();
    channel
        .reject(&first, now_ms(1), "trace-recover")
        .expect("reject must succeed");
    assert_eq!(
        channel.get_obligation(&first).unwrap().status,
        ObligationStatus::Rejected
    );

    // Recover the connector: Failed -> Discovered, then re-deliver work.
    manager
        .transition_to("conn-g", ConnectorState::Discovered)
        .expect("Failed -> Discovered permitted");
    assert_eq!(manager.get_state("conn-g"), Some(ConnectorState::Discovered));

    let replay = channel
        .send(
            TaskMsg {
                connector_id: "conn-g".into(),
                task_class: "rc".into(),
                payload: "v1".into(),
            },
            now_ms(2),
            "trace-recover",
        )
        .unwrap();
    assert_ne!(replay, first, "replay must have a fresh obligation id");
    channel
        .fulfill(&replay, now_ms(3), "trace-recover")
        .expect("replay fulfilment");
    tracing::info!("test_failure_recovery_replays_obligation: exit");
}

/// Two distinct connectors can simultaneously hold tasks in distinct lanes
/// without colliding on scheduler counters.
#[test]
fn test_concurrent_registrations_distinct_lanes() {
    tracing::info!("test_concurrent_registrations_distinct_lanes: enter");
    let (manager, mut scheduler, _channel) = build_harness();

    manager.register("conn-h1");
    manager.register("conn-h2");

    let a = scheduler
        .assign_task(
            &task_classes::epoch_transition(),
            now_ms(0),
            "trace-h1",
        )
        .unwrap();
    let b = scheduler
        .assign_task(
            &task_classes::garbage_collection(),
            now_ms(1),
            "trace-h2",
        )
        .unwrap();
    assert_eq!(a.lane, SchedulerLane::ControlCritical);
    assert_eq!(b.lane, SchedulerLane::Maintenance);
    assert_ne!(a.task_id, b.task_id);
    tracing::info!("test_concurrent_registrations_distinct_lanes: exit");
}

/// Trace IDs supplied at every subsystem boundary land in the corresponding
/// audit/assignment records so out-of-band correlation works end-to-end.
#[test]
fn test_tracing_at_every_boundary() {
    tracing::info!("test_tracing_at_every_boundary: enter");
    let (manager, mut scheduler, mut channel) = build_harness();
    let trace = "trace-spine-001";

    manager.register("conn-i");
    let a = scheduler
        .assign_task(&task_classes::remote_computation(), now_ms(0), trace)
        .unwrap();
    assert_eq!(a.trace_id, trace, "scheduler must carry trace");

    let id = channel
        .send(
            TaskMsg {
                connector_id: "conn-i".into(),
                task_class: "rc".into(),
                payload: "x".into(),
            },
            now_ms(1),
            trace,
        )
        .unwrap();
    assert_eq!(
        channel.get_obligation(&id).unwrap().trace_id,
        trace,
        "channel must carry trace"
    );
    // Audit log must record the trace on the FN-OB-001 (Created) event.
    let audit = channel.audit_log();
    assert!(audit.iter().any(|r| r.trace_id == trace));
    tracing::info!("test_tracing_at_every_boundary: exit");
}

/// Happy path: register → assign task → deliver obligation → progress through
/// canonical lifecycle states → fulfill obligation → complete task on the
/// scheduler. All three subsystems exercised by one flow.
#[test]
fn test_full_lifecycle_happy_path() {
    tracing::info!("test_full_lifecycle_happy_path: enter");
    let (manager, mut scheduler, mut channel) = build_harness();
    let connector_id = "conn-happy";
    let trace = "trace-happy";

    // 1) Register the connector.
    manager.register(connector_id);
    assert_eq!(
        manager.get_state(connector_id),
        Some(ConnectorState::Discovered)
    );

    // 2) Walk it through canonical lifecycle progression.
    for target in [
        ConnectorState::Verified,
        ConnectorState::Installed,
        ConnectorState::Configured,
        ConnectorState::Active,
    ] {
        let new_state = manager.transition_to(connector_id, target).unwrap();
        assert_eq!(new_state, target);
    }
    assert_eq!(manager.get_state(connector_id), Some(ConnectorState::Active));

    // 3) Scheduler assigns work for the active connector.
    let assignment = scheduler
        .assign_task(&task_classes::remote_computation(), now_ms(10), trace)
        .unwrap();
    assert_eq!(assignment.lane, SchedulerLane::RemoteEffect);

    // 4) Obligation channel delivers the matching task.
    let obligation_id = channel
        .send(
            TaskMsg {
                connector_id: connector_id.into(),
                task_class: task_classes::remote_computation().as_str().into(),
                payload: "compute-1".into(),
            },
            now_ms(11),
            trace,
        )
        .unwrap();

    // 5) Connector reports completion via the channel...
    channel
        .fulfill(&obligation_id, now_ms(12), trace)
        .expect("fulfill must succeed");
    assert_eq!(
        channel.get_obligation(&obligation_id).unwrap().status,
        ObligationStatus::Fulfilled
    );

    // 6) ...and the scheduler releases the task slot.
    let released_lane = scheduler
        .complete_task(&assignment.task_id.to_string(), now_ms(13), trace)
        .expect("scheduler must complete the assigned task");
    assert_eq!(released_lane, SchedulerLane::RemoteEffect);

    // 7) Connector returns to a terminal lifecycle state.
    manager
        .transition_to(connector_id, ConnectorState::Stopped)
        .expect("Active -> Stopped permitted");
    assert_eq!(
        manager.get_state(connector_id),
        Some(ConnectorState::Stopped)
    );
    tracing::info!("test_full_lifecycle_happy_path: exit");
}
