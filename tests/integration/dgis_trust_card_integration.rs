//! Integration coverage for DGIS topological context risk surfaces.
//!
//! This test target verifies the concrete bd-c97l.1 artifact path without
//! mutating the existing trust-card storage module. The produced snapshot is
//! the context a trust card, adversary posterior surface, or extension risk UI
//! can consume.

use frankenengine_node::security::dgis::risk_surface_integration::{
    PlannedChangeKind, PlannedTopologyChange, RISK_SURFACE_SCHEMA_VERSION, RiskSurfaceError,
    RiskSurfaceInput, RiskSurfaceTier, build_risk_surface_snapshot,
};
use frankenengine_node::security::dgis::update_copilot::TopologyRiskMetrics;

fn metrics(
    fan_out: f64,
    betweenness: f64,
    articulation_point: bool,
    trust: f64,
    transitive_dependency_count: u32,
    max_depth: u32,
) -> TopologyRiskMetrics {
    TopologyRiskMetrics {
        fan_out,
        betweenness_centrality: betweenness,
        articulation_point,
        trust_bottleneck_score: trust,
        transitive_dependency_count,
        max_depth_in_graph: max_depth,
    }
}

fn sample_input() -> RiskSurfaceInput {
    RiskSurfaceInput {
        extension_id: "npm:@acme/auth-guard".to_string(),
        trace_id: "trace-dgis-risk-ui".to_string(),
        base_adversary_posterior: 0.22,
        current_metrics: metrics(80.0, 0.72, true, 0.64, 1840, 9),
        planned_changes: vec![
            PlannedTopologyChange {
                change_kind: PlannedChangeKind::UpdateVersion,
                package_name: "npm:@acme/auth-guard".to_string(),
                from_version: "1.2.3".to_string(),
                to_version: "1.2.4-safer".to_string(),
                post_update_metrics: metrics(70.0, 0.65, true, 0.50, 1500, 8),
            },
            PlannedTopologyChange {
                change_kind: PlannedChangeKind::AddDependency,
                package_name: "npm:@acme/auth-guard".to_string(),
                from_version: "1.2.3".to_string(),
                to_version: "1.3.0-add-oauth".to_string(),
                post_update_metrics: metrics(95.0, 0.80, true, 0.74, 2050, 10),
            },
            PlannedTopologyChange {
                change_kind: PlannedChangeKind::RemoveDependency,
                package_name: "npm:@acme/auth-guard".to_string(),
                from_version: "1.2.3".to_string(),
                to_version: "1.2.4-prune".to_string(),
                post_update_metrics: metrics(40.0, 0.44, false, 0.40, 720, 5),
            },
        ],
    }
}

#[test]
fn topological_context_populates_trust_card_risk_surface() {
    let snapshot = build_risk_surface_snapshot(sample_input()).expect("snapshot");

    assert_eq!(snapshot.schema_version, RISK_SURFACE_SCHEMA_VERSION);
    assert_eq!(
        snapshot.trust_card_context.risk_tier,
        RiskSurfaceTier::Critical
    );
    assert_eq!(
        snapshot.trust_card_context.downstream_transitive_dependents,
        1840
    );
    assert!(snapshot.trust_card_context.articulation_point);
    assert!(
        snapshot
            .trust_card_context
            .operator_summary
            .contains("1840 transitive")
    );
    assert_eq!(snapshot.planned_update_deltas.len(), 3);
}

#[test]
fn planned_update_deltas_cover_add_update_and_remove() {
    let snapshot = build_risk_surface_snapshot(sample_input()).expect("snapshot");
    let kinds = snapshot
        .planned_update_deltas
        .iter()
        .map(|delta| delta.change_kind)
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            PlannedChangeKind::AddDependency,
            PlannedChangeKind::UpdateVersion,
            PlannedChangeKind::RemoveDependency,
        ]
    );

    let add = &snapshot.planned_update_deltas[0];
    let update = &snapshot.planned_update_deltas[1];
    let remove = &snapshot.planned_update_deltas[2];
    assert!(add.risk_delta > 0.07);
    assert!(update.risk_delta < 0.0);
    assert!(remove.risk_delta < -0.50);
}

#[test]
fn posterior_attribution_is_deterministic_and_sums_to_one() {
    let first = build_risk_surface_snapshot(sample_input()).expect("first");
    let second = build_risk_surface_snapshot(sample_input()).expect("second");
    assert_eq!(first.replay_fingerprint, second.replay_fingerprint);
    assert_eq!(
        first.posterior_update.attribution_percentages,
        second.posterior_update.attribution_percentages
    );
    let total: f64 = first
        .posterior_update
        .attribution_percentages
        .values()
        .copied()
        .sum();
    assert!((total - 1.0).abs() < 1.0e-9);
    assert!(first.posterior_update.topology_adjusted_posterior > 0.84);
}

#[test]
fn replay_fingerprint_length_prefixes_extension_and_trace_fields() {
    let mut left = sample_input();
    left.extension_id = "npm:@acme/ab".to_string();
    left.trace_id = "c".to_string();

    let mut right = sample_input();
    right.extension_id = "npm:@acme/a".to_string();
    right.trace_id = "bc".to_string();

    assert_eq!(
        format!("{}{}", left.extension_id, left.trace_id),
        format!("{}{}", right.extension_id, right.trace_id),
        "test inputs must alias under unprefixed concatenation"
    );

    let left = build_risk_surface_snapshot(left).expect("left snapshot");
    let right = build_risk_surface_snapshot(right).expect("right snapshot");

    assert_ne!(
        left.replay_fingerprint, right.replay_fingerprint,
        "length-prefixed identifiers must not alias the replay fingerprint"
    );
}

#[test]
fn risk_surface_rejects_control_char_identifiers_before_ui_snapshot() {
    let mut input = sample_input();
    input.trace_id = "trace-dgis-risk-ui\npoison".to_string();

    let err = build_risk_surface_snapshot(input).expect_err("control character trace must reject");

    assert!(matches!(
        err,
        RiskSurfaceError::InvalidIdentifier {
            field: "trace_id",
            reason: "control_char",
        }
    ));
}

#[test]
fn replay_fingerprint_length_prefixes_planned_delta_fields() {
    let mut left = sample_input();
    left.planned_changes = vec![PlannedTopologyChange {
        change_kind: PlannedChangeKind::UpdateVersion,
        package_name: "npm:@acme/ab".to_string(),
        from_version: "c".to_string(),
        to_version: "1.3.0".to_string(),
        post_update_metrics: metrics(95.0, 0.80, true, 0.74, 2050, 10),
    }];

    let mut right = sample_input();
    right.planned_changes = vec![PlannedTopologyChange {
        change_kind: PlannedChangeKind::UpdateVersion,
        package_name: "npm:@acme/a".to_string(),
        from_version: "bc".to_string(),
        to_version: "1.3.0".to_string(),
        post_update_metrics: metrics(95.0, 0.80, true, 0.74, 2050, 10),
    }];

    assert_eq!(
        format!(
            "{:?}{}{}{}",
            left.planned_changes[0].change_kind,
            left.planned_changes[0].package_name,
            left.planned_changes[0].from_version,
            left.planned_changes[0].to_version
        ),
        format!(
            "{:?}{}{}{}",
            right.planned_changes[0].change_kind,
            right.planned_changes[0].package_name,
            right.planned_changes[0].from_version,
            right.planned_changes[0].to_version
        ),
        "test inputs must alias under unprefixed planned-delta concatenation"
    );

    let left = build_risk_surface_snapshot(left).expect("left snapshot");
    let right = build_risk_surface_snapshot(right).expect("right snapshot");

    assert_ne!(
        left.replay_fingerprint, right.replay_fingerprint,
        "length-prefixed planned-delta fields must not alias the replay fingerprint"
    );
}

#[test]
fn malformed_topology_metric_fails_closed_before_ui_snapshot() {
    let mut input = sample_input();
    input.planned_changes[0]
        .post_update_metrics
        .trust_bottleneck_score = f64::INFINITY;

    let err = build_risk_surface_snapshot(input).expect_err("non-finite metric must reject");
    assert!(matches!(
        err,
        RiskSurfaceError::InvalidMetric {
            field: "planned.post_update.trust_bottleneck_score",
            ..
        }
    ));
}
