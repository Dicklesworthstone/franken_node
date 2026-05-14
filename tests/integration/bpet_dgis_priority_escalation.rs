use frankenengine_node::security::bpet::dgis_fusion::{
    BpetDgisFusionInput, BpetDgisFusionPolicy, DGIS_FUSION_SCHEMA_VERSION, DgisFusionError,
    EscalationLevel, invariants, prioritize_with_dgis,
};
use frankenengine_node::security::bpet::evolution_risk_scorer::{
    FeatureVector, WeightingPolicy, compute_risk_score,
};
use frankenengine_node::security::dgis::update_copilot::TopologyRiskMetrics;

fn bpet_score(drift: f64, regime_shift: f64, hazard: f64, provenance: f64) -> f64 {
    let features = FeatureVector::try_new(drift, regime_shift, hazard, provenance)
        .expect("fixture features are valid");
    let (score, _) = compute_risk_score(&features, &WeightingPolicy::policy_v1())
        .expect("fixture score computes");
    score
}

fn high_centrality_metrics() -> TopologyRiskMetrics {
    TopologyRiskMetrics {
        fan_out: 84.0,
        betweenness_centrality: 0.82,
        articulation_point: true,
        trust_bottleneck_score: 0.91,
        transitive_dependency_count: 4_200,
        max_depth_in_graph: 17,
    }
}

fn low_centrality_metrics() -> TopologyRiskMetrics {
    TopologyRiskMetrics {
        fan_out: 4.0,
        betweenness_centrality: 0.05,
        articulation_point: false,
        trust_bottleneck_score: 0.10,
        transitive_dependency_count: 3,
        max_depth_in_graph: 2,
    }
}

fn fusion_input(package_id: &str, metrics: TopologyRiskMetrics) -> BpetDgisFusionInput {
    BpetDgisFusionInput {
        package_id: package_id.to_string(),
        bpet_risk_score: bpet_score(0.95, 0.78, 0.86, 0.65),
        bpet_confidence: 0.88,
        expected_loss_if_compromised_usd: 750_000.0,
        topology_metrics: metrics,
        trace_id: format!("trace-{package_id}"),
    }
}

#[test]
fn high_centrality_trajectory_anomaly_escalates_with_expected_loss_context() {
    let output = prioritize_with_dgis(
        &fusion_input("npm:@acme/critical-auth", high_centrality_metrics()),
        &BpetDgisFusionPolicy::default(),
    )
    .unwrap();

    assert_eq!(output.schema_version, DGIS_FUSION_SCHEMA_VERSION);
    assert_eq!(output.escalation_level, EscalationLevel::Critical);
    assert!(output.combined_priority_score >= 0.80);
    assert!(output.expected_loss.amplified_expected_loss_usd > 2_000_000.0);
    assert_eq!(output.expected_loss.confidence_basis_points, 8_800);
    assert!(output.recommended_action.contains("quarantine candidate"));
    assert!(
        output
            .invariant_markers
            .contains(&invariants::INV_BPET_DGIS_TOPOLOGY_AMPLIFICATION.to_string())
    );
}

#[test]
fn identical_bpet_score_on_leaf_node_stays_below_high_priority() {
    let high = prioritize_with_dgis(
        &fusion_input("npm:@acme/critical-auth", high_centrality_metrics()),
        &BpetDgisFusionPolicy::default(),
    )
    .unwrap();
    let low = prioritize_with_dgis(
        &fusion_input("npm:@acme/leaf-widget", low_centrality_metrics()),
        &BpetDgisFusionPolicy::default(),
    )
    .unwrap();

    assert_eq!(low.escalation_level, EscalationLevel::Elevated);
    assert!(high.combined_priority_score > low.combined_priority_score);
    assert!(
        high.expected_loss.amplified_expected_loss_usd
            > low.expected_loss.amplified_expected_loss_usd
    );
}

#[test]
fn priority_fusion_is_replay_deterministic() {
    let input = fusion_input("npm:@acme/critical-auth", high_centrality_metrics());
    let policy = BpetDgisFusionPolicy::default();

    let first = prioritize_with_dgis(&input, &policy).unwrap();
    let second = prioritize_with_dgis(&input, &policy).unwrap();
    let first_json = serde_json::to_string(&first).unwrap();
    let second_json = serde_json::to_string(&second).unwrap();

    assert_eq!(first, second);
    assert_eq!(first_json, second_json);
    assert!(first.replay_fingerprint.starts_with("sha256:"));
}

#[test]
fn malformed_topology_metric_is_rejected_before_escalation() {
    let mut input = fusion_input("npm:@acme/bad-metrics", high_centrality_metrics());
    input.topology_metrics.betweenness_centrality = f64::INFINITY;

    let err = prioritize_with_dgis(&input, &BpetDgisFusionPolicy::default())
        .expect_err("non-finite topology input must fail closed");

    assert!(matches!(
        err,
        DgisFusionError::NonFinite {
            field: "topology.betweenness_centrality",
            ..
        }
    ));
}

#[test]
fn malformed_policy_is_rejected_before_expected_loss_math() {
    let policy = BpetDgisFusionPolicy {
        elevated_threshold: 0.90,
        high_threshold: 0.70,
        ..BpetDgisFusionPolicy::default()
    };

    let err = prioritize_with_dgis(
        &fusion_input("npm:@acme/critical-auth", high_centrality_metrics()),
        &policy,
    )
    .expect_err("threshold inversion must fail closed");

    assert!(matches!(err, DgisFusionError::InvalidThresholdOrder));
}
