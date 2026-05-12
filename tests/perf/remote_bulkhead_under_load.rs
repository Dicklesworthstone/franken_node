//! bd-v4l0: Remote bulkhead load contract tests.
//!
//! These are deterministic contract tests that simulate saturation scenarios
//! and verify:
//! - in-flight cap never exceeded
//! - backpressure behavior is deterministic
//! - p99 foreground latency remains within configured target

use frankenengine_node::remote::eviction_saga::RemoteCapLookup;
use frankenengine_node::remote::remote_bulkhead::{
    BackpressurePolicy, BulkheadError, RemoteBulkhead, event_codes,
};

#[derive(Debug)]
struct ScenarioRow {
    test_scenario: &'static str,
    in_flight_count: usize,
    p50_latency_ms: f64,
    p99_latency_ms: f64,
    rejected_count: usize,
    queue_depth: usize,
}

fn simulate(cap: usize, policy: BackpressurePolicy, target_p99_ms: u64) -> Vec<ScenarioRow> {
    let mut bulkhead = RemoteBulkhead::new(cap, policy, target_p99_ms).expect("valid bulkhead");
    let mut rejected = 0usize;

    for idx in 0..(cap + 12) {
        let request_id = format!("req-{idx}");
        let now_ms = u64::try_from(idx).expect("request index fits in u64");
        let result = bulkhead.acquire(RemoteCapLookup::Granted, &request_id, now_ms);
        if matches!(result, Err(BulkheadError::AtCapacity { .. }))
            || matches!(result, Err(BulkheadError::QueueSaturated { .. }))
        {
            rejected = rejected.saturating_add(1);
        }
    }

    for idx in 0..200_u64 {
        // Deterministic synthetic latency model:
        // higher cap raises baseline while preserving <= target p99.
        let baseline = 8 + (cap as u64 / 8);
        let burst = if idx % 50 == 0 { 20 } else { idx % 9 };
        bulkhead.record_foreground_latency(baseline + burst, idx);
    }

    let mut samples = bulkhead
        .latency_samples()
        .iter()
        .map(|sample| sample.latency_ms)
        .collect::<Vec<_>>();
    samples.sort_unstable();
    let median_index = samples.len() / 2;
    let p50 = samples.get(median_index).copied().unwrap_or_default() as f64;
    let p99 = bulkhead.p99_foreground_latency_ms().unwrap_or_default() as f64;

    vec![ScenarioRow {
        test_scenario: match policy {
            BackpressurePolicy::Reject => "reject_policy_saturation",
            BackpressurePolicy::Queue { .. } => "queue_policy_saturation",
        },
        in_flight_count: bulkhead.current_in_flight(),
        p50_latency_ms: p50,
        p99_latency_ms: p99,
        rejected_count: rejected,
        queue_depth: bulkhead.queue_depth(),
    }]
}

#[test]
fn p99_stays_within_target_for_cap_profiles() {
    let caps = [8_usize, 32, 128];
    for cap in caps {
        let rows = simulate(
            cap,
            BackpressurePolicy::Queue {
                max_depth: 64,
                timeout_ms: 500,
            },
            50,
        );
        let row = rows.first().expect("simulation yields one summary row");
        assert_eq!(row.in_flight_count, cap);
        assert!(row.p50_latency_ms > 0.0);
        assert!(
            row.p99_latency_ms <= 50.0,
            "cap={} p99={}ms exceeded target",
            cap,
            row.p99_latency_ms
        );
    }
}

#[test]
fn reject_policy_reports_rejections_under_saturation() {
    let rows = simulate(8, BackpressurePolicy::Reject, 50);
    let row = rows.first().expect("simulation yields one summary row");
    assert_eq!(row.test_scenario, "reject_policy_saturation");
    assert!(row.p50_latency_ms > 0.0);
    assert!(
        row.rejected_count > 0,
        "reject policy should reject overload"
    );
    assert_eq!(row.queue_depth, 0, "reject policy should not queue");
}

#[test]
fn queue_policy_accumulates_queue_depth_under_saturation() {
    let rows = simulate(
        32,
        BackpressurePolicy::Queue {
            max_depth: 64,
            timeout_ms: 500,
        },
        50,
    );
    let row = rows.first().expect("simulation yields one summary row");
    assert_eq!(row.test_scenario, "queue_policy_saturation");
    assert_eq!(row.in_flight_count, 32);
    assert!(row.p50_latency_ms > 0.0);
    assert!(
        row.queue_depth > 0,
        "queue policy should accumulate queued work"
    );
}

#[test]
fn e2e_saturation_flow_preserves_telemetry_and_latency_budget() {
    let mut bulkhead = RemoteBulkhead::new(
        2,
        BackpressurePolicy::Queue {
            max_depth: 2,
            timeout_ms: 50,
        },
        50,
    )
    .expect("valid bulkhead");

    let first = bulkhead
        .acquire(RemoteCapLookup::Granted, "active-a", 1)
        .expect("first permit");
    let second = bulkhead
        .acquire(RemoteCapLookup::Granted, "active-b", 2)
        .expect("second permit");

    let denied = bulkhead
        .acquire(RemoteCapLookup::Denied, "denied", 3)
        .expect_err("denied RemoteCap must fail before queue admission");
    assert!(matches!(denied, BulkheadError::RemoteCapRequired));
    assert_eq!(bulkhead.queue_depth(), 0);

    let queued = bulkhead
        .acquire(RemoteCapLookup::Granted, "waiter-a", 4)
        .expect_err("first waiter should queue");
    assert!(matches!(queued, BulkheadError::Queued { position: 1, .. }));
    let queued = bulkhead
        .acquire(RemoteCapLookup::Granted, "waiter-b", 5)
        .expect_err("second waiter should queue");
    assert!(matches!(queued, BulkheadError::Queued { position: 2, .. }));
    let saturated = bulkhead
        .acquire(RemoteCapLookup::Granted, "overflow", 6)
        .expect_err("bounded queue must reject overflow");
    assert!(matches!(saturated, BulkheadError::QueueSaturated { .. }));

    bulkhead
        .set_max_in_flight(1, 7)
        .expect("cap reduction should enter drain mode");
    assert_eq!(bulkhead.draining_target(), Some(1));
    bulkhead.release(first, 8).expect("release first permit");
    bulkhead.release(second, 9).expect("release second permit");

    let promoted = bulkhead
        .poll_queued("waiter-a", 10)
        .expect("front waiter should promote after drain clears");
    assert_eq!(bulkhead.current_in_flight(), 1);
    bulkhead
        .release(promoted, 11)
        .expect("release promoted permit");

    for (idx, latency) in [18_u64, 22, 30, 45].into_iter().enumerate() {
        let now_ms = 20 + u64::try_from(idx).expect("latency sample index fits in u64");
        bulkhead.record_foreground_latency(latency, now_ms);
    }
    assert!(bulkhead.latency_within_target());

    let has_event_code = |code: &str| {
        bulkhead
            .events()
            .iter()
            .any(|event| event.event_code == code)
    };
    assert!(has_event_code(event_codes::RB_REQUEST_REJECTED));
    assert!(has_event_code(event_codes::RB_REQUEST_QUEUED));
    assert!(has_event_code(event_codes::RB_DRAIN_ACTIVE));
    assert!(has_event_code(event_codes::RB_LATENCY_REPORT));
    assert_eq!(
        bulkhead
            .events()
            .iter()
            .rev()
            .find(|event| event.event_code == event_codes::RB_LATENCY_REPORT)
            .expect("latency event should be present")
            .now_ms,
        23
    );
}
