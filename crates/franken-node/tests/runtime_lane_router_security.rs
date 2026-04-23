use std::collections::BTreeMap;

use frankenengine_node::config::{LaneOverflowPolicy, RuntimeConfig, RuntimeLaneConfig};
use frankenengine_node::runtime::bounded_mask::CapabilityContext;
use frankenengine_node::runtime::lane_router::{LaneRouter, ProductLane, error_codes, event_codes};

fn lane_cfg(max_concurrent: usize, overflow_policy: LaneOverflowPolicy) -> RuntimeLaneConfig {
    RuntimeLaneConfig {
        max_concurrent,
        priority_weight: 10,
        queue_limit: 8,
        enqueue_timeout_ms: 25,
        overflow_policy,
    }
}

fn runtime_config() -> RuntimeConfig {
    let mut lanes = BTreeMap::new();
    lanes.insert(
        "cancel".to_string(),
        lane_cfg(8, LaneOverflowPolicy::Reject),
    );
    lanes.insert(
        "timed".to_string(),
        lane_cfg(12, LaneOverflowPolicy::EnqueueWithTimeout),
    );
    lanes.insert(
        "realtime".to_string(),
        lane_cfg(16, LaneOverflowPolicy::EnqueueWithTimeout),
    );
    lanes.insert(
        "background".to_string(),
        lane_cfg(4, LaneOverflowPolicy::ShedOldest),
    );
    RuntimeConfig {
        preferred: frankenengine_node::config::PreferredRuntime::Auto,
        remote_max_in_flight: 50,
        bulkhead_retry_after_ms: 20,
        lanes,
        drain_timeout_ms: None,
    }
}

#[test]
fn lane_router_rejects_unknown_lane_hint_instead_of_background_downshift() {
    let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
    let cx = CapabilityContext::with_scopes(
        "cx-security",
        "operator-security",
        ["lane.cancel".to_string()],
    );

    let err = router
        .assign_operation(&cx, "unknown-hint-op", Some("cancel-but-not-really"), 10)
        .expect_err("unknown lane hint must fail closed");

    assert_eq!(err.code(), error_codes::LANE_HINT_INVALID);
    assert_eq!(router.unknown_lane_default_count(), 1);
    assert!(
        !router
            .events()
            .iter()
            .any(|event| event.event_code == event_codes::LANE_DEFAULTED_BACKGROUND)
    );
    assert!(router.events().iter().any(|event| {
        event.event_code == event_codes::LANE_SCOPE_MISMATCH
            && event
                .detail
                .contains("unknown_lane_hint_rejected=cancel-but-not-really")
    }));
    assert_eq!(router.metrics_snapshot().total_in_flight, 0);
}

#[test]
fn lane_router_rejects_missing_lane_authorization_without_background_fallback() {
    let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
    let cx = CapabilityContext::new("cx-no-lane", "operator-no-lane");

    let err = router
        .assign_operation(&cx, "missing-lane-op", None, 10)
        .expect_err("missing lane authorization must fail closed");

    assert_eq!(err.code(), error_codes::LANE_ANNOTATION_MISSING);
    assert_eq!(router.unknown_lane_default_count(), 1);
    assert!(
        !router
            .events()
            .iter()
            .any(|event| event.event_code == event_codes::LANE_DEFAULTED_BACKGROUND)
    );
    assert!(router.events().iter().any(|event| {
        event.event_code == event_codes::LANE_SCOPE_MISMATCH
            && event.detail.contains("missing_lane_authorization")
    }));
    assert_eq!(router.metrics_snapshot().total_in_flight, 0);
}

#[test]
fn lane_router_keeps_background_fallback_only_for_background_authorized_work() {
    let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
    let cx = CapabilityContext::with_scopes(
        "cx-background",
        "operator-background",
        ["lane.background".to_string()],
    );

    let assigned = router
        .assign_operation(&cx, "background-op", None, 10)
        .expect("explicitly background-authorized work may use background");

    assert_eq!(assigned.lane, ProductLane::Background);
    assert!(!assigned.queued);
    assert_eq!(router.unknown_lane_default_count(), 0);
}
