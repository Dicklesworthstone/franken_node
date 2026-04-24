use std::collections::BTreeMap;

use frankenengine_node::config::{
    CliOverrides, Config, LaneOverflowPolicy, RuntimeConfig, RuntimeLaneConfig,
};
use frankenengine_node::runtime::bounded_mask::CapabilityContext;
use frankenengine_node::runtime::lane_router::{LaneRouter, ProductLane, event_codes};

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

fn env_lookup(map: BTreeMap<String, String>) -> impl Fn(&str) -> Option<String> {
    move |key| map.get(key).cloned()
}

#[test]
fn configured_merge_decision_cap_bounds_resolved_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("franken_node.toml");
    std::fs::write(
        &path,
        r#"
[security]
max_merge_decisions = 2

[runtime]
preferred = "bun"
remote_max_in_flight = 77
bulkhead_retry_after_ms = 33
"#,
    )
    .unwrap();

    let resolved = Config::resolve_with_env(
        Some(&path),
        CliOverrides::default(),
        &env_lookup(BTreeMap::new()),
    )
    .unwrap();

    assert_eq!(resolved.config.security.max_merge_decisions, 2);
    assert_eq!(resolved.decisions.len(), 2);
    let retained_fields: Vec<&str> = resolved
        .decisions
        .iter()
        .map(|decision| decision.field.as_str())
        .collect();
    assert_eq!(
        retained_fields,
        vec![
            "runtime.remote_max_in_flight",
            "runtime.bulkhead_retry_after_ms"
        ]
    );
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

fn lane_metric(
    router: &LaneRouter,
    lane: ProductLane,
) -> frankenengine_node::runtime::lane_router::LaneMetricsSnapshot {
    router
        .metrics_snapshot()
        .lanes
        .into_iter()
        .find(|metric| metric.lane == lane)
        .expect("lane metric")
}

#[test]
fn reload_shrinks_enqueue_with_timeout_queue_by_rejecting_newest_overflow() {
    let mut cfg = runtime_config(1);
    cfg.lanes.get_mut("timed").expect("timed lane").queue_limit = 3;
    let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
    let timed = cx("lane.timed");

    router
        .assign_operation(&timed, "timed-active", None, 1)
        .expect("timed active");
    for (idx, operation_id) in ["timed-q-old", "timed-q-mid", "timed-q-new"]
        .into_iter()
        .enumerate()
    {
        assert!(
            router
                .assign_operation(
                    &timed,
                    operation_id,
                    None,
                    2 + u64::try_from(idx).expect("small index fits u64"),
                )
                .expect("timed queued")
                .queued
        );
    }

    let mut tightened = cfg;
    tightened
        .lanes
        .get_mut("timed")
        .expect("timed lane")
        .queue_limit = 1;
    router
        .reload_config(
            frankenengine_node::runtime::lane_router::LaneRouterConfig::from_runtime_config(
                &tightened,
            )
            .expect("tightened config"),
            10,
        )
        .expect("reload");

    let timed_metric = lane_metric(&router, ProductLane::Timed);
    assert_eq!(timed_metric.queued, 1);
    assert_eq!(timed_metric.rejected, 2);

    let event_count = router.events().len();
    router
        .complete_operation("timed-active", 11, false)
        .expect("complete active timed");
    let promoted: Vec<&str> = router.events()[event_count..]
        .iter()
        .filter(|event| event.event_code == event_codes::LANE_ASSIGNED)
        .map(|event| event.operation_id.as_str())
        .collect();
    assert_eq!(promoted, vec!["timed-q-old"]);
}

#[test]
fn reload_shrinks_shed_oldest_queue_by_rejecting_oldest_overflow() {
    let mut cfg = runtime_config(1);
    cfg.lanes
        .get_mut("background")
        .expect("background lane")
        .queue_limit = 3;
    let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
    let background = cx("lane.background");

    router
        .assign_operation(&background, "background-active", None, 1)
        .expect("background active");
    for (idx, operation_id) in ["background-q-old", "background-q-mid", "background-q-new"]
        .into_iter()
        .enumerate()
    {
        assert!(
            router
                .assign_operation(
                    &background,
                    operation_id,
                    None,
                    2 + u64::try_from(idx).expect("small index fits u64"),
                )
                .expect("background queued")
                .queued
        );
    }

    let mut tightened = cfg;
    tightened
        .lanes
        .get_mut("background")
        .expect("background lane")
        .queue_limit = 1;
    router
        .reload_config(
            frankenengine_node::runtime::lane_router::LaneRouterConfig::from_runtime_config(
                &tightened,
            )
            .expect("tightened config"),
            10,
        )
        .expect("reload");

    let background_metric = lane_metric(&router, ProductLane::Background);
    assert_eq!(background_metric.queued, 1);
    assert_eq!(background_metric.rejected, 2);

    let event_count = router.events().len();
    router
        .complete_operation("background-active", 11, false)
        .expect("complete active background");
    let promoted: Vec<&str> = router.events()[event_count..]
        .iter()
        .filter(|event| event.event_code == event_codes::LANE_ASSIGNED)
        .map(|event| event.operation_id.as_str())
        .collect();
    assert_eq!(promoted, vec!["background-q-new"]);
}
