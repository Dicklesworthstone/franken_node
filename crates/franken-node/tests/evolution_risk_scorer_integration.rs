//! Integration tests for the unified evolution-risk scorer (bd-1jpc).
//!
//! `crates/franken-node/Cargo.toml` sets `test = false` on `[lib]`, so the
//! inline `#[cfg(test)] mod tests` block inside
//! `crates/franken-node/src/security/bpet/evolution_risk_scorer.rs` does
//! not run under `cargo test`. This file re-exercises the same 15
//! contracts through the public API so the scorer is actually verified by
//! `cargo test -p frankenengine-node`.

use std::collections::BTreeMap;

use frankenengine_node::security::bpet::evolution_risk_scorer::{
    ConfidenceInterval, ExplanationVector, FeatureVector, NoiseDistribution, POLICY_V1_VERSION,
    SCHEMA_VERSION, SUM_TOLERANCE, ScorerError, WeightingPolicy, compute_confidence_interval,
    compute_risk_score, feature_names,
};

fn features(drift: f64, regime: f64, hazard: f64, provenance: f64) -> FeatureVector {
    FeatureVector {
        drift,
        regime_shift: regime,
        hazard,
        provenance,
    }
}

// ---------------------------------------------------------------------------
// Weighting policy invariants
// ---------------------------------------------------------------------------

#[test]
fn policy_v1_weights_sum_to_one() {
    let p = WeightingPolicy::policy_v1();
    let sum = p.drift_weight + p.regime_weight + p.hazard_weight + p.provenance_weight;
    assert!((sum - 1.0).abs() <= SUM_TOLERANCE, "policy_v1 sum = {sum}");
    assert!(p.validate().is_ok());
}

#[test]
fn policy_v1_matches_section_10_21_catalog() {
    let p = WeightingPolicy::policy_v1();
    assert_eq!(p.drift_weight, 0.35);
    assert_eq!(p.regime_weight, 0.25);
    assert_eq!(p.hazard_weight, 0.30);
    assert_eq!(p.provenance_weight, 0.10);
    assert_eq!(WeightingPolicy::version_label(), "policy_v1");
}

#[test]
fn policy_rejects_non_sum_to_one_weights() {
    let bad = WeightingPolicy::try_new(0.5, 0.5, 0.5, 0.5);
    assert!(matches!(bad, Err(ScorerError::WeightsDoNotSumToOne { .. })));
}

#[test]
fn policy_rejects_negative_weight() {
    let bad = WeightingPolicy::try_new(-0.1, 0.5, 0.4, 0.2);
    assert!(matches!(bad, Err(ScorerError::NegativeWeight { .. })));
}

#[test]
fn policy_rejects_nan_weight() {
    let bad = WeightingPolicy::try_new(f64::NAN, 0.5, 0.4, 0.1);
    assert!(matches!(bad, Err(ScorerError::NonFiniteWeight(_))));
}

// ---------------------------------------------------------------------------
// Feature validation
// ---------------------------------------------------------------------------

#[test]
fn feature_vector_rejects_nan() {
    let fv = features(f64::NAN, 0.2, 0.3, 0.4);
    let err = compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap_err();
    assert!(matches!(err, ScorerError::NonFiniteFeature(_)));
}

#[test]
fn feature_vector_rejects_infinity() {
    let fv = features(0.1, f64::INFINITY, 0.3, 0.4);
    let err = compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap_err();
    assert!(matches!(err, ScorerError::NonFiniteFeature(_)));
}

#[test]
fn feature_vector_rejects_out_of_range() {
    let fv = features(0.1, 0.2, 1.5, 0.4);
    let err = compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap_err();
    assert!(matches!(err, ScorerError::FeatureOutOfRange { .. }));
}

// ---------------------------------------------------------------------------
// Scoring correctness + explanation contract
// ---------------------------------------------------------------------------

#[test]
fn weighted_sum_matches_hand_computation() {
    let fv = features(0.6, 0.4, 0.5, 0.2);
    let p = WeightingPolicy::policy_v1();
    let (score, _) = compute_risk_score(&fv, &p).unwrap();
    let expected = 0.35 * 0.6 + 0.25 * 0.4 + 0.30 * 0.5 + 0.10 * 0.2;
    assert!(
        (score - expected).abs() < 1e-12,
        "score={score} expected={expected}"
    );
}

#[test]
fn explanation_contributions_sum_to_score_and_use_btreemap() {
    let fv = features(0.6, 0.4, 0.5, 0.2);
    let (score, exp): (f64, ExplanationVector) =
        compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap();
    assert!((exp.total_contribution() - score).abs() < 1e-12);
    assert_eq!(exp.schema_version, SCHEMA_VERSION);
    assert_eq!(exp.weighting_policy_version, POLICY_V1_VERSION);
    assert_eq!(exp.feature_contributions.len(), 4);

    // BTreeMap iterates in sorted key order — exercise that contract.
    let keys: Vec<&String> = exp.feature_contributions.keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);

    // Sanity: contributions are a BTreeMap<String, f64>.
    let _typed: &BTreeMap<String, f64> = &exp.feature_contributions;
}

#[test]
fn explanation_identifies_dominant_feature() {
    let drift_dominant = features(1.0, 0.0, 0.0, 0.0);
    let (_, exp) = compute_risk_score(&drift_dominant, &WeightingPolicy::policy_v1()).unwrap();
    assert_eq!(exp.dominant_feature, feature_names::DRIFT);

    let hazard_dominant = features(0.0, 0.0, 1.0, 0.0);
    let (_, exp) = compute_risk_score(&hazard_dominant, &WeightingPolicy::policy_v1()).unwrap();
    assert_eq!(exp.dominant_feature, feature_names::HAZARD);
}

// ---------------------------------------------------------------------------
// Monotonicity
// ---------------------------------------------------------------------------

#[test]
fn higher_drift_yields_higher_score() {
    let p = WeightingPolicy::policy_v1();
    let low = compute_risk_score(&features(0.10, 0.3, 0.3, 0.3), &p)
        .unwrap()
        .0;
    let high = compute_risk_score(&features(0.90, 0.3, 0.3, 0.3), &p)
        .unwrap()
        .0;
    assert!(
        high > low,
        "expected monotonic in drift: low={low} high={high}"
    );
}

#[test]
fn higher_hazard_yields_higher_score() {
    let p = WeightingPolicy::policy_v1();
    let low = compute_risk_score(&features(0.3, 0.3, 0.10, 0.3), &p)
        .unwrap()
        .0;
    let high = compute_risk_score(&features(0.3, 0.3, 0.90, 0.3), &p)
        .unwrap()
        .0;
    assert!(high > low);
}

// ---------------------------------------------------------------------------
// Bootstrap CI: determinism + bounds
// ---------------------------------------------------------------------------

#[test]
fn bootstrap_is_deterministic_under_fixed_seed() {
    let fv = features(0.5, 0.4, 0.6, 0.3);
    let p = WeightingPolicy::policy_v1();
    let noise = NoiseDistribution::try_new(0.05, 42).unwrap();
    let ci_a: ConfidenceInterval = compute_confidence_interval(&fv, &p, &noise, 200).unwrap();
    let ci_b: ConfidenceInterval = compute_confidence_interval(&fv, &p, &noise, 200).unwrap();
    assert_eq!(ci_a, ci_b, "same seed must yield identical CI");
}

#[test]
fn bootstrap_with_zero_noise_collapses_to_point_estimate() {
    let fv = features(0.5, 0.4, 0.6, 0.3);
    let p = WeightingPolicy::policy_v1();
    let noise = NoiseDistribution::try_new(0.0, 9).unwrap();
    let ci = compute_confidence_interval(&fv, &p, &noise, 100).unwrap();
    let (point, _) = compute_risk_score(&fv, &p).unwrap();
    assert!((ci.lower - point).abs() < 1e-12);
    assert!((ci.upper - point).abs() < 1e-12);
    assert!((ci.point - point).abs() < 1e-12);
}

#[test]
fn bootstrap_rejects_zero_iterations_and_bad_noise() {
    let fv = features(0.5, 0.4, 0.6, 0.3);
    let p = WeightingPolicy::policy_v1();
    let noise = NoiseDistribution::default();
    let err = compute_confidence_interval(&fv, &p, &noise, 0).unwrap_err();
    assert!(matches!(err, ScorerError::ZeroBootstrapIterations));

    assert!(matches!(
        NoiseDistribution::try_new(f64::NAN, 1).unwrap_err(),
        ScorerError::InvalidNoiseStdDev(_)
    ));
    assert!(matches!(
        NoiseDistribution::try_new(-0.1, 1).unwrap_err(),
        ScorerError::InvalidNoiseStdDev(_)
    ));
}
