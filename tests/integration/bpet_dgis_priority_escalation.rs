use std::collections::BTreeMap;

use frankenengine_node::security::bpet::camouflage_detector::{
    CAMOUFLAGE_CONFORMAL_RISK_CLASS, DetectorConfig, detect_calibrated_camouflage,
};
use frankenengine_node::security::bpet::dgis_fusion::{
    BpetDgisFusionInput, BpetDgisFusionPolicy, DGIS_CONFORMAL_RISK_CLASS,
    DGIS_FUSION_SCHEMA_VERSION, DgisFusionError, EscalationLevel, invariants,
    prioritize_with_calibrated_dgis, prioritize_with_dgis,
};
use frankenengine_node::security::bpet::economic_integration::{
    BpetGuidance, BpetMitigationPlaybook, CompromisePricing, InterventionRecommendation,
    InterventionRoi, MotifMatch, PlaybookAction, PlaybookUrgency,
};
use frankenengine_node::security::bpet::evolution_risk_scorer::{
    EVOLUTION_CONFORMAL_RISK_CLASS, FeatureVector, WeightingPolicy, compute_calibrated_risk_score,
    compute_risk_score,
};
use frankenengine_node::security::bpet::trust_surface_integration::{
    assess_guidance_for_calibrated_trust_surface, render_calibrated_trust_surface_transcript,
    trust_card_mutation_from_calibrated_guidance,
};
use frankenengine_node::security::conformal::{
    CONFORMAL_FROZEN_QUANTILE_SCHEMA_VERSION, CONFORMAL_GENERATED_AT,
    CONFORMAL_SAMPLE_SCHEMA_VERSION, ConformalScoreSample, FrozenConformalArtifact,
    FrozenConformalQuantile, event_codes, freeze_quantiles, score_nonconformity_samples,
};
use frankenengine_node::security::dgis::update_copilot::TopologyRiskMetrics;
use frankenengine_node::security::trajectory_gaming::{
    TrajectorySample, TrajectorySeries, append_sample,
};
use frankenengine_node::supply_chain::trust_card::{RiskLevel, TrustCardMutation};
use sha2::{Digest, Sha256};

type CapabilitySampleRow = (i64, BTreeMap<String, f64>, BTreeMap<String, f64>);

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

fn calibrated_dgis_input() -> BpetDgisFusionInput {
    BpetDgisFusionInput {
        package_id: "npm:@acme/critical-auth".to_string(),
        bpet_risk_score: 0.84,
        bpet_confidence: 0.88,
        expected_loss_if_compromised_usd: 750_000.0,
        topology_metrics: high_centrality_metrics(),
        trace_id: "trace-bpet-dgis-fusion".to_string(),
    }
}

fn guidance_for_package(package_name: &str) -> BpetGuidance {
    BpetGuidance {
        guidance_id: format!("guidance-{package_name}"),
        package_name: package_name.to_string(),
        compromise_propensity: 0.12,
        pricing: CompromisePricing {
            package_name: package_name.to_string(),
            compromise_propensity: 0.12,
            expected_loss_if_compromised: 100_000.0,
            risk_adjusted_cost: 12_000.0,
            insurance_premium_equivalent: 14_400.0,
            confidence: 0.81,
        },
        motif_matches: vec![MotifMatch {
            motif_id: "motif-maintainer-turnover".to_string(),
            motif_name: "Sudden Maintainer Turnover".to_string(),
            match_score: 0.25,
            matched_indicators: vec!["dependency_churn".to_string()],
            estimated_time_to_compromise_days: 30.0,
        }],
        top_interventions: vec![InterventionRoi {
            intervention_name: "sandbox_barriers".to_string(),
            intervention_cost: 500.0,
            risk_reduction: 0.3,
            expected_loss_avoided: 30_000.0,
            roi_ratio: 60.0,
            payback_period_days: 7.0,
            recommendation: InterventionRecommendation::StronglyRecommended,
        }],
        playbook: BpetMitigationPlaybook {
            playbook_id: "playbook-test".to_string(),
            urgency: PlaybookUrgency::Routine,
            recommended_actions: vec![PlaybookAction {
                action_name: "Apply sandbox escalation".to_string(),
                description: "Tighten sandbox tier".to_string(),
                priority: 1,
                estimated_effort_hours: 2.0,
            }],
            monitoring_escalation: vec!["phenotype_drift_score".to_string()],
            fallback_strategy: "auto-quarantine at critical threshold".to_string(),
        },
        summary: "test guidance".to_string(),
        timestamp: "2026-05-14T00:00:00Z".to_string(),
        trace_id: format!("trace-{package_name}"),
    }
}

fn bpet_conformal_artifact() -> FrozenConformalArtifact {
    FrozenConformalArtifact {
        schema_version: "conformal.frozen_quantile_artifact.v1".to_string(),
        generated_at: "1970-01-01T00:00:00Z".to_string(),
        sample_schema_version: "conformal.score_sample.v1".to_string(),
        corpus_hash: "sha256:test-bpet-trust-surface".to_string(),
        sample_count: 64,
        risk_class_count: 3,
        target_alpha_bp: 500,
        quantiles: vec![
            FrozenConformalQuantile {
                risk_class: EVOLUTION_CONFORMAL_RISK_CLASS.to_string(),
                sample_count: 20,
                positive_count: 10,
                negative_count: 10,
                target_alpha_bp: 500,
                quantile_rank: 19,
                quantile_bp: 3_000,
                min_nonconformity_bp: 100,
                max_nonconformity_bp: 3_000,
                finite_sample_coverage_floor_bp: 9_500,
            },
            FrozenConformalQuantile {
                risk_class: CAMOUFLAGE_CONFORMAL_RISK_CLASS.to_string(),
                sample_count: 20,
                positive_count: 10,
                negative_count: 10,
                target_alpha_bp: 500,
                quantile_rank: 19,
                quantile_bp: 2_500,
                min_nonconformity_bp: 100,
                max_nonconformity_bp: 2_500,
                finite_sample_coverage_floor_bp: 9_500,
            },
            FrozenConformalQuantile {
                risk_class: DGIS_CONFORMAL_RISK_CLASS.to_string(),
                sample_count: 24,
                positive_count: 12,
                negative_count: 12,
                target_alpha_bp: 500,
                quantile_rank: 23,
                quantile_bp: 3_000,
                min_nonconformity_bp: 100,
                max_nonconformity_bp: 3_000,
                finite_sample_coverage_floor_bp: 9_500,
            },
        ],
        event_codes: vec![
            "FN-CONFORMAL-001".to_string(),
            "FN-CONFORMAL-002".to_string(),
        ],
        audit_notes: vec![
            "split conformal coverage assumes exchangeability; ACI tracks shift instead of overclaiming distribution-free guarantees".to_string(),
        ],
    }
}

fn conformal_sample(
    id: &str,
    risk_class: &str,
    score_bp: u16,
    positive: bool,
) -> ConformalScoreSample {
    ConformalScoreSample {
        sample_id: id.to_string(),
        risk_class: risk_class.to_string(),
        score_bp,
        positive,
    }
}

fn phase0_style_conformal_samples() -> Vec<ConformalScoreSample> {
    vec![
        conformal_sample("s4", "evolution", 4_000, false),
        conformal_sample("s1", "evolution", 9_000, true),
        conformal_sample("s3", "evolution", 2_000, false),
        conformal_sample("s2", "evolution", 8_000, true),
        conformal_sample("c1", "camouflage", 6_000, true),
        conformal_sample("c2", "camouflage", 1_000, false),
    ]
}

fn cap(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_string(), *value))
        .collect()
}

fn build_series(samples: &[CapabilitySampleRow]) -> TrajectorySeries {
    let mut series = TrajectorySeries::new(0, i64::MAX).expect("valid window");
    for (ts, observed, declared) in samples {
        let sample =
            TrajectorySample::new(*ts, observed.clone(), declared.clone()).expect("finite values");
        append_sample(&mut series, sample).expect("append sample");
    }
    series
}

fn phase_shift_series(n: usize, low: f64, high: f64) -> TrajectorySeries {
    let rows = (0..n)
        .map(|idx| {
            let observed = if idx < n / 2 { low } else { high };
            (
                i64::try_from(idx).expect("test index fits i64"),
                cap(&[("net.egress", observed)]),
                cap(&[("net.egress", 0.5)]),
            )
        })
        .collect::<Vec<_>>();
    build_series(&rows)
}

fn assert_high_coverage_trust_card(mutation: TrustCardMutation) {
    let risk = mutation
        .user_facing_risk_assessment
        .expect("risk assessment present");
    assert_eq!(risk.level, RiskLevel::High);
    assert!(risk.summary.contains("calibrated BPET risk set=positive"));
    assert!(risk.summary.contains("95.00% empirical coverage"));
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
fn phase0_style_frozen_quantile_artifact_matches_canonical_contract() {
    let mut samples = phase0_style_conformal_samples();
    samples.rotate_left(3);

    let scored = score_nonconformity_samples(&samples).unwrap();
    let scored_contract = scored
        .iter()
        .map(|sample| {
            (
                sample.sample_id.as_str(),
                sample.risk_class.as_str(),
                sample.score_bp,
                sample.positive,
                sample.nonconformity_bp,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        scored_contract,
        vec![
            ("c1", "camouflage", 6_000, true, 4_000),
            ("c2", "camouflage", 1_000, false, 1_000),
            ("s1", "evolution", 9_000, true, 1_000),
            ("s2", "evolution", 8_000, true, 2_000),
            ("s3", "evolution", 2_000, false, 2_000),
            ("s4", "evolution", 4_000, false, 4_000),
        ]
    );

    let artifact = freeze_quantiles(&samples, 2_000).unwrap();

    assert_eq!(
        artifact.schema_version,
        CONFORMAL_FROZEN_QUANTILE_SCHEMA_VERSION
    );
    assert_eq!(
        artifact.sample_schema_version,
        CONFORMAL_SAMPLE_SCHEMA_VERSION
    );
    assert_eq!(artifact.generated_at, CONFORMAL_GENERATED_AT);
    assert_eq!(
        artifact.corpus_hash,
        "sha256:31a0705613c893c1e67f772b1db5ea7ecdd3a8b56efd933e51e2f0bd010bfc67"
    );
    assert_eq!(artifact.sample_count, 6);
    assert_eq!(artifact.risk_class_count, 2);
    assert_eq!(artifact.target_alpha_bp, 2_000);
    assert_eq!(
        artifact.event_codes,
        vec![
            event_codes::CONFORMAL_ARTIFACT_EMITTED.to_string(),
            event_codes::CONFORMAL_SET_EMITTED.to_string(),
        ]
    );
    assert_eq!(
        artifact.quantiles,
        vec![
            FrozenConformalQuantile {
                risk_class: "camouflage".to_string(),
                sample_count: 2,
                positive_count: 1,
                negative_count: 1,
                target_alpha_bp: 2_000,
                quantile_rank: 2,
                quantile_bp: 4_000,
                min_nonconformity_bp: 1_000,
                max_nonconformity_bp: 4_000,
                finite_sample_coverage_floor_bp: 6_666,
            },
            FrozenConformalQuantile {
                risk_class: "evolution".to_string(),
                sample_count: 4,
                positive_count: 2,
                negative_count: 2,
                target_alpha_bp: 2_000,
                quantile_rank: 4,
                quantile_bp: 4_000,
                min_nonconformity_bp: 1_000,
                max_nonconformity_bp: 4_000,
                finite_sample_coverage_floor_bp: 8_000,
            },
        ]
    );

    let canonical = artifact.canonical_bytes().unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&canonical)),
        "0a7142f10dcc1c0868aa8fd62e176d536ee2797e45639f796d11b7da91e7c5a2"
    );
}

#[test]
fn calibrated_bpet_wrappers_surface_on_trust_cards_with_golden_transcript() {
    let artifact = bpet_conformal_artifact();
    let evolution = compute_calibrated_risk_score(
        "npm:@acme/evolution@1.0.0",
        EVOLUTION_CONFORMAL_RISK_CLASS,
        &FeatureVector::try_new(1.0, 1.0, 1.0, 1.0).expect("valid feature vector"),
        &WeightingPolicy::policy_v1(),
        &artifact,
    )
    .expect("evolution risk calibrates");
    let camouflage = detect_calibrated_camouflage(
        "npm:@acme/camouflage@1.0.0",
        CAMOUFLAGE_CONFORMAL_RISK_CLASS,
        &phase_shift_series(16, 0.05, 0.95),
        &DetectorConfig {
            phase_shift_threshold: 0.2,
            window_size: 4,
            min_samples_for_detection: 4,
            ..DetectorConfig::default()
        },
        &artifact,
    )
    .expect("camouflage severity calibrates");
    let dgis = prioritize_with_calibrated_dgis(
        "npm:@acme/critical-auth@1.0.0",
        DGIS_CONFORMAL_RISK_CLASS,
        &calibrated_dgis_input(),
        &BpetDgisFusionPolicy::default(),
        &artifact,
    )
    .expect("DGIS priority calibrates");

    let evolution_guidance = guidance_for_package("npm:@acme/evolution");
    let camouflage_guidance = guidance_for_package("npm:@acme/camouflage");
    let dgis_guidance = guidance_for_package("npm:@acme/critical-auth");

    let evolution_assessment = assess_guidance_for_calibrated_trust_surface(
        &evolution_guidance,
        8_000,
        Some(&evolution.explanation),
        &evolution.risk_set,
        evolution.empirical_coverage_basis_points,
    )
    .expect("evolution trust surface assesses");
    let camouflage_assessment = assess_guidance_for_calibrated_trust_surface(
        &camouflage_guidance,
        8_000,
        None,
        &camouflage.risk_set,
        camouflage.empirical_coverage_basis_points,
    )
    .expect("camouflage trust surface assesses");
    let dgis_assessment = assess_guidance_for_calibrated_trust_surface(
        &dgis_guidance,
        8_000,
        None,
        &dgis.risk_set,
        dgis.empirical_coverage_basis_points,
    )
    .expect("DGIS trust surface assesses");

    assert_high_coverage_trust_card(
        trust_card_mutation_from_calibrated_guidance(
            &evolution_guidance,
            8_000,
            Some(&evolution.explanation),
            &evolution.risk_set,
            evolution.empirical_coverage_basis_points,
        )
        .expect("evolution trust-card mutation"),
    );
    assert_high_coverage_trust_card(
        trust_card_mutation_from_calibrated_guidance(
            &camouflage_guidance,
            8_000,
            None,
            &camouflage.risk_set,
            camouflage.empirical_coverage_basis_points,
        )
        .expect("camouflage trust-card mutation"),
    );
    assert_high_coverage_trust_card(
        trust_card_mutation_from_calibrated_guidance(
            &dgis_guidance,
            8_000,
            None,
            &dgis.risk_set,
            dgis.empirical_coverage_basis_points,
        )
        .expect("DGIS trust-card mutation"),
    );

    let transcript = render_calibrated_trust_surface_transcript(&[
        evolution_assessment,
        camouflage_assessment,
        dgis_assessment,
    ]);

    assert_eq!(
        transcript,
        concat!(
            "event=FN-CONFORMAL-001 package=npm:@acme/evolution risk_class=bpet_evolution level=High labels=positive score_bp=10000 quantile_bp=3000 coverage_bp=9500\n",
            "event=FN-CONFORMAL-001 package=npm:@acme/camouflage risk_class=bpet_camouflage level=High labels=positive score_bp=10000 quantile_bp=2500 coverage_bp=9500\n",
            "event=FN-CONFORMAL-001 package=npm:@acme/critical-auth risk_class=bpet_dgis_fusion level=High labels=positive score_bp=8047 quantile_bp=3000 coverage_bp=9500"
        )
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
