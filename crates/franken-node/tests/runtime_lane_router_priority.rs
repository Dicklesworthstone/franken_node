use std::collections::BTreeMap;

use frankenengine_node::config::{LaneOverflowPolicy, RuntimeConfig, RuntimeLaneConfig};
use frankenengine_node::runtime::bounded_mask::CapabilityContext;
use frankenengine_node::runtime::lane_router::{event_codes, LaneRouter};

fn lane_cfg(
    max_concurrent: usize,
    priority_weight: u32,
    overflow_policy: LaneOverflowPolicy,
) -> RuntimeLaneConfig {
    RuntimeLaneConfig {
        max_concurrent,
        priority_weight,
        queue_limit: 8,
        enqueue_timeout_ms: 1_000,
        overflow_policy,
    }
}

fn runtime_config(max_concurrent: usize) -> RuntimeConfig {
    let mut lanes = BTreeMap::new();
    lanes.insert(
        "cancel".to_string(),
        lane_cfg(max_concurrent, 1, LaneOverflowPolicy::EnqueueWithTimeout),
    );
    lanes.insert(
        "timed".to_string(),
        lane_cfg(max_concurrent, 10, LaneOverflowPolicy::EnqueueWithTimeout),
    );
    lanes.insert(
        "realtime".to_string(),
        lane_cfg(max_concurrent, 50, LaneOverflowPolicy::EnqueueWithTimeout),
    );
    lanes.insert(
        "background".to_string(),
        lane_cfg(max_concurrent, 100, LaneOverflowPolicy::ShedOldest),
    );
    RuntimeConfig {
        preferred: frankenengine_node::config::PreferredRuntime::Auto,
        remote_max_in_flight: 8,
        bulkhead_retry_after_ms: 20,
        lanes,
        drain_timeout_ms: None,
    }
}

fn cx(scope: &str) -> CapabilityContext {
    CapabilityContext::with_scopes(
        format!("cx-{scope}"),
        "operator-priority",
        [scope.to_string()],
    )
}

#[test]
fn queued_promotion_respects_configured_priority_weights() {
    let mut router = LaneRouter::from_runtime_config(&runtime_config(1)).expect("router");

    router
        .assign_operation(&cx("lane.timed"), "timed-active", None, 1)
        .expect("timed active");
    router
        .assign_operation(&cx("lane.realtime"), "rt-active", None, 1)
        .expect("realtime active");
    router
        .assign_operation(&cx("lane.background"), "bg-active", None, 1)
        .expect("background active");

    assert!(
        router
            .assign_operation(&cx("lane.timed"), "timed-q", None, 2)
            .expect("timed queued")
            .queued
    );
    assert!(
        router
            .assign_operation(&cx("lane.realtime"), "rt-q", None, 2)
            .expect("realtime queued")
            .queued
    );
    assert!(
        router
            .assign_operation(&cx("lane.background"), "bg-q", None, 2)
            .expect("background queued")
            .queued
    );

    let widened = frankenengine_node::runtime::lane_router::LaneRouterConfig::from_runtime_config(
        &runtime_config(2),
    )
    .expect("widened config");
    router
        .reload_config(widened, 3)
        .expect("reload should widen lane caps");

    let event_count_before_promotion = router.events().len();
    router
        .complete_operation("timed-active", 4, false)
        .expect("completion should promote queued work");

    let promoted: Vec<&str> = router.events()[event_count_before_promotion..]
        .iter()
        .filter(|event| event.event_code == event_codes::LANE_ASSIGNED)
        .map(|event| event.operation_id.as_str())
        .collect();
    assert_eq!(promoted, vec!["bg-q", "rt-q", "timed-q"]);
}
