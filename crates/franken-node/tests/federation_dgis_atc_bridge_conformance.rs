use frankenengine_node::federation::dgis_atc_bridge::{
    consume_federated_cascade_prior, derive_federated_cascade_prior, export_topology_indicators,
    invariants, region_hash_for, window_hash_for, DgisAtcBridgeError, DgisAtcPrivacyPolicy,
    DgisTopologyIndicatorInput,
};
use frankenengine_node::security::dgis::update_copilot::TopologyRiskMetrics;

fn metrics(
    fan_out: f64,
    betweenness_centrality: f64,
    trust_bottleneck_score: f64,
    transitive_dependency_count: u32,
    max_depth_in_graph: u32,
    articulation_point: bool,
) -> TopologyRiskMetrics {
    TopologyRiskMetrics {
        fan_out,
        betweenness_centrality,
        articulation_point,
        trust_bottleneck_score,
        transitive_dependency_count,
        max_depth_in_graph,
    }
}

fn topology_input(
    package_name: &str,
    version: &str,
    trace_id: &str,
    fan_out: f64,
) -> DgisTopologyIndicatorInput {
    DgisTopologyIndicatorInput::new(
        package_name,
        version,
        "cargo-critical-auth-region",
        "2026-05-week-22",
        1_777_000_042,
        metrics(fan_out, 0.84, 0.79, 240, 11, true),
        0.91,
        0.88,
        37,
        trace_id,
    )
}

fn conformance_policy() -> DgisAtcPrivacyPolicy {
    DgisAtcPrivacyPolicy {
        min_k_anonymity: 2,
        max_indicators_per_exchange: 16,
        risk_bucket_count: 24,
        sketch_depth: 4,
        sketch_width: 96,
        epoch_bucket_width: 32,
        ..DgisAtcPrivacyPolicy::default()
    }
}

#[test]
fn dgis_atc_export_redacts_raw_identifiers_and_preserves_contract_markers() {
    let raw_inputs = vec![
        topology_input("secret-auth-leaf-a", "9.9.1", "trace-secret-a", 91.0),
        topology_input("secret-auth-leaf-b", "9.9.2", "trace-secret-b", 82.0),
    ];

    let report = export_topology_indicators(&raw_inputs, &conformance_policy()).unwrap();
    let encoded = serde_json::to_string(&report).unwrap();

    for forbidden in [
        "secret-auth-leaf-a",
        "secret-auth-leaf-b",
        "trace-secret-a",
        "trace-secret-b",
        "cargo-critical-auth-region",
        "2026-05-week-22",
        "9.9.1",
        "9.9.2",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "DGIS/ATC exchange leaked raw identifier {forbidden}"
        );
    }

    assert_eq!(report.indicators.len(), raw_inputs.len());
    assert!(report
        .verifier_checks
        .get("raw_dependency_graph_absent")
        .copied()
        .unwrap_or(false));
    assert!(report
        .invariant_markers
        .contains(&invariants::INV_DGIS_ATC_NO_RAW_DEPENDENCY_LEAKAGE.to_string()));
    assert!(report
        .invariant_markers
        .contains(&invariants::INV_DGIS_ATC_K_ANONYMITY.to_string()));
}

#[test]
fn dgis_atc_export_is_order_deterministic_and_fails_closed_below_k() {
    let first_order = vec![
        topology_input("pkg-alpha", "1.0.0", "trace-alpha", 88.0),
        topology_input("pkg-beta", "1.0.1", "trace-beta", 77.0),
        topology_input("pkg-gamma", "1.0.2", "trace-gamma", 66.0),
    ];
    let mut reversed_order = first_order.clone();
    reversed_order.reverse();

    let first = export_topology_indicators(&first_order, &conformance_policy()).unwrap();
    let second = export_topology_indicators(&reversed_order, &conformance_policy()).unwrap();
    assert_eq!(first.exchange_id, second.exchange_id);
    assert_eq!(first.content_hash, second.content_hash);
    assert_eq!(first.indicators, second.indicators);

    let err = export_topology_indicators(&first_order[..1], &conformance_policy()).unwrap_err();
    assert!(matches!(
        err,
        DgisAtcBridgeError::RegionBelowK {
            count: 1,
            min: 2,
            ..
        }
    ));
}

#[test]
fn dgis_atc_prior_consumption_is_bounded_and_rejects_tampered_contracts() {
    let report = export_topology_indicators(
        &[
            topology_input("pkg-prior-a", "2.0.0", "trace-prior-a", 95.0),
            topology_input("pkg-prior-b", "2.0.1", "trace-prior-b", 92.0),
        ],
        &conformance_policy(),
    )
    .unwrap();
    let region = region_hash_for("cargo-critical-auth-region").unwrap();
    let window = window_hash_for("2026-05-week-22").unwrap();
    let prior = derive_federated_cascade_prior(&report, &region, &window).unwrap();

    assert_eq!(prior.contributor_count, 2);
    assert!(prior.risk_prior.is_finite());
    assert!((0.0..=1.0).contains(&prior.risk_prior));
    assert!((0.0..=1.0).contains(&prior.confidence_prior));

    let local = metrics(4.0, 0.05, 0.04, 2, 1, false);
    let assimilation = consume_federated_cascade_prior(&local, &prior, 0.75).unwrap();
    assert!(assimilation.adjusted_metrics.fan_out >= local.fan_out);
    assert!(assimilation.adjusted_metrics.betweenness_centrality >= local.betweenness_centrality);
    assert!(assimilation.adjusted_metrics.trust_bottleneck_score >= local.trust_bottleneck_score);
    assert!(assimilation.adjusted_metrics.trust_bottleneck_score <= 1.0);
    assert!(assimilation.adjusted_metrics.transitive_dependency_count >= 2);
    assert!(!assimilation.changed_metrics.is_empty());

    let mut tampered = prior;
    tampered.schema_version = "dgis-atc-bridge-v0".to_string();
    let err = consume_federated_cascade_prior(&local, &tampered, 0.5).unwrap_err();
    assert!(matches!(err, DgisAtcBridgeError::InvalidPrior(_)));
}
