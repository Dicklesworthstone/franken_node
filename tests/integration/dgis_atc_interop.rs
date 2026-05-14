#![cfg(feature = "advanced-features")]

use frankenengine_node::federation::atc_sketches::MergeableSketch;
use frankenengine_node::federation::dgis_atc_bridge::{
    DGIS_ATC_BRIDGE_SCHEMA_VERSION, DGIS_ATC_PRIVACY_CONTRACT_VERSION, DgisAtcBridgeError,
    DgisAtcPrivacyPolicy, DgisTopologyIndicatorInput, consume_federated_cascade_prior,
    derive_federated_cascade_prior, export_topology_indicators, invariants, region_hash_for,
    window_hash_for,
};
use frankenengine_node::security::dgis::update_copilot::TopologyRiskMetrics;

fn metrics(
    fan_out: f64,
    betweenness_centrality: f64,
    trust_bottleneck_score: f64,
    articulation_point: bool,
) -> TopologyRiskMetrics {
    TopologyRiskMetrics {
        fan_out,
        betweenness_centrality,
        articulation_point,
        trust_bottleneck_score,
        transitive_dependency_count: 240,
        max_depth_in_graph: 11,
    }
}

fn topology_indicator(
    package_name: &str,
    trace_id: &str,
    fan_out: f64,
    betweenness_centrality: f64,
    trust_bottleneck_score: f64,
) -> DgisTopologyIndicatorInput {
    DgisTopologyIndicatorInput::new(
        package_name,
        "4.8.15",
        "npm-critical-auth-region",
        "2026-05-week-20",
        81,
        metrics(
            fan_out,
            betweenness_centrality,
            trust_bottleneck_score,
            true,
        ),
        0.91,
        0.87,
        37,
        trace_id,
    )
}

#[test]
fn exports_anonymized_dgis_topology_indicators_and_derives_atc_prior() {
    let policy = DgisAtcPrivacyPolicy::default();
    let report = export_topology_indicators(
        &[
            topology_indicator("pkg-alpha", "trace-alpha", 82.0, 0.78, 0.88),
            topology_indicator("pkg-beta", "trace-beta", 74.0, 0.72, 0.83),
        ],
        &policy,
    )
    .unwrap();

    assert_eq!(report.schema_version, DGIS_ATC_BRIDGE_SCHEMA_VERSION);
    assert_eq!(
        report.privacy_contract_version,
        DGIS_ATC_PRIVACY_CONTRACT_VERSION
    );
    assert_eq!(report.indicators.len(), 2);
    assert!(report.verifier_checks["k_anonymity_enforced"]);
    assert!(
        report
            .invariant_markers
            .contains(&invariants::INV_DGIS_ATC_NO_RAW_DEPENDENCY_LEAKAGE.to_string())
    );

    let region_hash = region_hash_for("npm-critical-auth-region").unwrap();
    let window_hash = window_hash_for("2026-05-week-20").unwrap();
    let prior = derive_federated_cascade_prior(&report, &region_hash, &window_hash).unwrap();

    assert_eq!(prior.contributor_count, 2);
    assert!(prior.risk_prior > 0.0);
    assert!(prior.confidence_prior > 0.0);
    assert!(prior.articulation_rate > 0.0);
    assert!(prior.metric_priors.contains_key("betweenness_centrality"));
}

#[test]
fn serialized_exchange_does_not_contain_raw_dependency_graph_identifiers() {
    let report = export_topology_indicators(
        &[
            topology_indicator("secret-package-alpha", "raw-trace-alpha", 82.0, 0.78, 0.88),
            topology_indicator("secret-package-beta", "raw-trace-beta", 74.0, 0.72, 0.83),
        ],
        &DgisAtcPrivacyPolicy::default(),
    )
    .unwrap();

    let encoded = serde_json::to_string(&report).unwrap();
    for forbidden in [
        "secret-package-alpha",
        "secret-package-beta",
        "raw-trace-alpha",
        "raw-trace-beta",
        "npm-critical-auth-region",
        "2026-05-week-20",
        "4.8.15",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "exchange leaked raw dependency graph identifier {forbidden}"
        );
    }
}

#[test]
fn single_member_region_is_rejected_before_export() {
    let err = export_topology_indicators(
        &[topology_indicator(
            "pkg-single",
            "trace-single",
            82.0,
            0.78,
            0.88,
        )],
        &DgisAtcPrivacyPolicy::default(),
    )
    .unwrap_err();

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
fn federated_cascade_prior_consumption_is_bounded_and_verifiable() {
    let report = export_topology_indicators(
        &[
            topology_indicator("pkg-alpha", "trace-alpha", 96.0, 0.9, 0.91),
            topology_indicator("pkg-beta", "trace-beta", 90.0, 0.86, 0.89),
        ],
        &DgisAtcPrivacyPolicy::default(),
    )
    .unwrap();
    let region_hash = region_hash_for("npm-critical-auth-region").unwrap();
    let window_hash = window_hash_for("2026-05-week-20").unwrap();
    let prior = derive_federated_cascade_prior(&report, &region_hash, &window_hash).unwrap();
    let local = metrics(12.0, 0.1, 0.1, false);
    let assimilation = consume_federated_cascade_prior(&local, &prior, 0.5).unwrap();

    assert_eq!(assimilation.prior_id, prior.prior_id);
    assert!(assimilation.adjusted_metrics.fan_out >= local.fan_out);
    assert!(assimilation.adjusted_metrics.betweenness_centrality >= local.betweenness_centrality);
    assert!(assimilation.adjusted_metrics.trust_bottleneck_score <= 1.0);
    assert!(!assimilation.content_hash.is_empty());

    let risk_bucket_key = format!(
        "topology_risk_bucket:{}",
        report.indicators[0].topology_risk_bucket
    );
    assert!(report.aggregate_sketch.estimate(risk_bucket_key.as_bytes()) >= 1);
}

#[test]
fn malformed_prior_contract_is_rejected_before_metric_adjustment() {
    let report = export_topology_indicators(
        &[
            topology_indicator("pkg-alpha", "trace-alpha", 96.0, 0.9, 0.91),
            topology_indicator("pkg-beta", "trace-beta", 90.0, 0.86, 0.89),
        ],
        &DgisAtcPrivacyPolicy::default(),
    )
    .unwrap();
    let region_hash = region_hash_for("npm-critical-auth-region").unwrap();
    let window_hash = window_hash_for("2026-05-week-20").unwrap();
    let mut prior = derive_federated_cascade_prior(&report, &region_hash, &window_hash).unwrap();
    prior.privacy_contract_version = "old-contract".to_string();

    let err =
        consume_federated_cascade_prior(&metrics(12.0, 0.1, 0.1, false), &prior, 0.5).unwrap_err();
    assert!(matches!(err, DgisAtcBridgeError::InvalidPrior(_)));
}
