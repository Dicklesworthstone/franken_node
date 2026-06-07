use frankenengine_node::security::bpet::calibration_benchmark::{
    CALIBRATION_ARTIFACT_SCHEMA_VERSION, CALIBRATION_TARGET_ALPHA_BP, RELIABILITY_BIN_COUNT,
    generate_signed_calibration_artifact, verify_signed_calibration_artifact,
};

#[test]
fn calibration_artifact_is_canonical_deterministic_and_signed() {
    let first = generate_signed_calibration_artifact().expect("first artifact");
    let second = generate_signed_calibration_artifact().expect("second artifact");

    assert_eq!(first.schema_version, CALIBRATION_ARTIFACT_SCHEMA_VERSION);
    assert_eq!(first.target_alpha_bp, CALIBRATION_TARGET_ALPHA_BP);
    assert_eq!(first, second);
    assert_eq!(
        first.canonical_bytes().expect("canonical first"),
        second.canonical_bytes().expect("canonical second")
    );
    assert!(verify_signed_calibration_artifact(&first).expect("signature verifies"));
    assert_eq!(first.signature.payload_hash.len(), 71);
    assert_eq!(first.signature.signature.len(), 71);
}

#[test]
fn calibration_artifact_reports_all_phase_zero_signals() {
    let artifact = generate_signed_calibration_artifact().expect("artifact");
    let signal_ids = artifact
        .signals
        .iter()
        .map(|signal| signal.signal_id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        signal_ids,
        vec![
            "bpet.evolution_risk_scorer",
            "bpet.camouflage_detector",
            "dgis.spof_topology_signal"
        ]
    );

    for signal in &artifact.signals {
        let metrics = &signal.metrics;
        assert!(
            metrics.sample_count > 0,
            "{} has no samples",
            signal.signal_id
        );
        assert!(
            metrics.positive_count > 0,
            "{} has no positive examples",
            signal.signal_id
        );
        assert!(
            metrics.negative_count > 0,
            "{} has no benign examples",
            signal.signal_id
        );
        assert_eq!(metrics.reliability_bins.len(), RELIABILITY_BIN_COUNT);
        assert!(metrics.roc_auc_bp <= 10_000);
        assert!(metrics.pr_auc_bp <= 10_000);
        assert!(metrics.brier_score_bp <= 10_000);
        assert!(metrics.expected_calibration_error_bp <= 10_000);
    }
}

#[test]
fn calibration_signature_detects_signal_tampering() {
    let mut artifact = generate_signed_calibration_artifact().expect("artifact");
    artifact.signals[1].metrics.coverage_at_target_alpha_bp = artifact.signals[1]
        .metrics
        .coverage_at_target_alpha_bp
        .saturating_add(1);

    assert!(!verify_signed_calibration_artifact(&artifact).expect("verification result"));
}
