#![cfg(feature = "advanced-features")]

use frankenengine_node::federation::atc_sketches::MergeableSketch;
use frankenengine_node::federation::bpet_atc_bridge::{
    BPET_ATC_BRIDGE_SCHEMA_VERSION, BPET_ATC_PRIVACY_CONTRACT_VERSION, BpetAtcBridgeError,
    BpetAtcPrivacyPolicy, BpetTrajectoryExchangeInput, cohort_hash_for,
    consume_federated_temporal_prior, derive_federated_temporal_prior, export_anonymized_exchange,
    invariants, window_hash_for,
};
use frankenengine_node::security::bpet::evolution_risk_scorer::{
    FeatureVector, WeightingPolicy, compute_risk_score,
};

fn trajectory(
    package_name: &str,
    trace_id: &str,
    drift: f64,
    regime_shift: f64,
    hazard: f64,
) -> BpetTrajectoryExchangeInput {
    let features = FeatureVector {
        drift,
        regime_shift,
        hazard,
        provenance: 0.2,
    };
    let (risk_score, explanation) =
        compute_risk_score(&features, &WeightingPolicy::policy_v1()).unwrap();
    BpetTrajectoryExchangeInput::from_explanation(
        package_name,
        "2.4.6",
        "ecosystem-cohort-alpha",
        "2026-05-week-20",
        81,
        risk_score,
        0.86,
        &explanation,
        24,
        trace_id,
    )
}

#[test]
fn exports_anonymized_bpet_summaries_and_derives_atc_prior() {
    let policy = BpetAtcPrivacyPolicy::default();
    let report = export_anonymized_exchange(
        &[
            trajectory("pkg-alpha", "trace-alpha", 0.82, 0.3, 0.7),
            trajectory("pkg-beta", "trace-beta", 0.78, 0.4, 0.65),
        ],
        &policy,
    )
    .unwrap();

    assert_eq!(report.schema_version, BPET_ATC_BRIDGE_SCHEMA_VERSION);
    assert_eq!(
        report.privacy_contract_version,
        BPET_ATC_PRIVACY_CONTRACT_VERSION
    );
    assert_eq!(report.summaries.len(), 2);
    assert!(report.verifier_checks["k_anonymity_enforced"]);
    assert!(
        report
            .invariant_markers
            .contains(&invariants::INV_BPET_ATC_NO_RAW_LONGITUDINAL_LEAKAGE.to_string())
    );

    let cohort_hash = cohort_hash_for("ecosystem-cohort-alpha").unwrap();
    let window_hash = window_hash_for("2026-05-week-20").unwrap();
    let prior = derive_federated_temporal_prior(&report, &cohort_hash, &window_hash).unwrap();

    assert_eq!(prior.contributor_count, 2);
    assert!(prior.risk_prior > 0.0);
    assert!(prior.confidence_prior > 0.0);
    assert!(!prior.dominant_feature_priors.is_empty());
}

#[test]
fn serialized_exchange_does_not_contain_raw_longitudinal_identifiers() {
    let report = export_anonymized_exchange(
        &[
            trajectory("secret-package-alpha", "raw-trace-alpha", 0.82, 0.3, 0.7),
            trajectory("secret-package-beta", "raw-trace-beta", 0.78, 0.4, 0.65),
        ],
        &BpetAtcPrivacyPolicy::default(),
    )
    .unwrap();

    let encoded = serde_json::to_string(&report).unwrap();
    for forbidden in [
        "secret-package-alpha",
        "secret-package-beta",
        "raw-trace-alpha",
        "raw-trace-beta",
        "ecosystem-cohort-alpha",
        "2026-05-week-20",
        "2.4.6",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "exchange leaked raw identifier {forbidden}"
        );
    }
}

#[test]
fn single_member_cohort_is_rejected_before_export() {
    let err = export_anonymized_exchange(
        &[trajectory("pkg-single", "trace-single", 0.82, 0.3, 0.7)],
        &BpetAtcPrivacyPolicy::default(),
    )
    .unwrap_err();

    assert!(matches!(
        err,
        BpetAtcBridgeError::CohortBelowK {
            count: 1,
            min: 2,
            ..
        }
    ));
}

#[test]
fn federated_prior_consumption_is_bounded_and_verifiable() {
    let report = export_anonymized_exchange(
        &[
            trajectory("pkg-alpha", "trace-alpha", 0.9, 0.4, 0.8),
            trajectory("pkg-beta", "trace-beta", 0.88, 0.5, 0.75),
        ],
        &BpetAtcPrivacyPolicy::default(),
    )
    .unwrap();
    let cohort_hash = cohort_hash_for("ecosystem-cohort-alpha").unwrap();
    let window_hash = window_hash_for("2026-05-week-20").unwrap();
    let prior = derive_federated_temporal_prior(&report, &cohort_hash, &window_hash).unwrap();
    let local = FeatureVector {
        drift: 0.1,
        regime_shift: 0.1,
        hazard: 0.1,
        provenance: 0.1,
    };
    let assimilation = consume_federated_temporal_prior(&local, &prior, 0.5).unwrap();

    assert_eq!(assimilation.prior_id, prior.prior_id);
    assert!(assimilation.adjusted_features.drift >= local.drift);
    assert!(assimilation.adjusted_features.hazard >= local.hazard);
    assert!(assimilation.adjusted_features.regime_shift <= 1.0);
    assert!(!assimilation.content_hash.is_empty());

    let risk_bucket_key = format!("risk_bucket:{}", report.summaries[0].risk_bucket);
    assert!(report.aggregate_sketch.estimate(risk_bucket_key.as_bytes()) >= 1);
}
