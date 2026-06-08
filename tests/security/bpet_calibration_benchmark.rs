use frankenengine_node::security::bpet::calibration_benchmark::{
    CALIBRATION_ARTIFACT_SCHEMA_VERSION, CALIBRATION_TARGET_ALPHA_BP, CalibrationSignalSamples,
    RELIABILITY_BIN_COUNT, generate_calibration_verifier_input,
    generate_signed_calibration_artifact, verify_signed_calibration_artifact,
};
use frankenengine_verifier_sdk::calibration::{
    CalibrationSample as SdkCalibrationSample,
    CalibrationSignalSamples as SdkCalibrationSignalSamples, CalibrationVerificationError,
    FN_VSDK_CALIBRATION_ARTIFACT_PASS, FN_VSDK_CALIBRATION_METRICS_RECOMPUTED,
    FN_VSDK_CALIBRATION_RECOMPUTE_START, verify_calibration_artifact_recomputed,
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
    let signal = artifact
        .signals
        .get_mut(1)
        .expect("artifact includes a second signal");
    signal.metrics.coverage_at_target_alpha_bp =
        signal.metrics.coverage_at_target_alpha_bp.saturating_add(1);

    assert!(!verify_signed_calibration_artifact(&artifact).expect("verification result"));
}

#[test]
fn verifier_sdk_recomputes_calibration_artifact_from_published_inputs() {
    let artifact = generate_signed_calibration_artifact().expect("artifact");
    let verifier_input = generate_calibration_verifier_input().expect("verifier input");
    let artifact_bytes = artifact.canonical_bytes().expect("artifact bytes");
    let signal_samples = sdk_signal_samples(&verifier_input.signals);

    let verified = verify_calibration_artifact_recomputed(
        &artifact_bytes,
        &verifier_input.corpus_record_canonical_bytes,
        &signal_samples,
    )
    .expect("sdk recomputes artifact");

    assert_eq!(verified.corpus_hash, artifact.corpus_hash);
    assert_eq!(verified.corpus_record_count, artifact.corpus_record_count);
    assert_eq!(verified.signal_count, artifact.signals.len());
    assert_eq!(
        verified.event_codes,
        vec![
            FN_VSDK_CALIBRATION_RECOMPUTE_START.to_string(),
            FN_VSDK_CALIBRATION_METRICS_RECOMPUTED.to_string(),
            FN_VSDK_CALIBRATION_ARTIFACT_PASS.to_string()
        ]
    );
}

#[test]
fn verifier_sdk_rejects_calibration_sample_mismatch() {
    let artifact = generate_signed_calibration_artifact().expect("artifact");
    let verifier_input = generate_calibration_verifier_input().expect("verifier input");
    let artifact_bytes = artifact.canonical_bytes().expect("artifact bytes");
    let mut signal_samples = sdk_signal_samples(&verifier_input.signals);
    let first_sample = signal_samples
        .first_mut()
        .and_then(|signal| signal.samples.first_mut())
        .expect("fixture has at least one calibration sample");
    first_sample.positive = !first_sample.positive;

    let error = verify_calibration_artifact_recomputed(
        &artifact_bytes,
        &verifier_input.corpus_record_canonical_bytes,
        &signal_samples,
    )
    .expect_err("sample mismatch must fail");

    assert!(matches!(
        error,
        CalibrationVerificationError::ArtifactMismatch {
            surface: "unsigned_payload"
        }
    ));
}

#[test]
fn verifier_sdk_rejects_corpus_hash_mismatch() {
    let artifact = generate_signed_calibration_artifact().expect("artifact");
    let mut verifier_input = generate_calibration_verifier_input().expect("verifier input");
    let artifact_bytes = artifact.canonical_bytes().expect("artifact bytes");
    let signal_samples = sdk_signal_samples(&verifier_input.signals);
    let first_corpus_record = verifier_input
        .corpus_record_canonical_bytes
        .first_mut()
        .expect("fixture has at least one corpus record");
    *first_corpus_record = br#"{"record_id":"synthetic-bpet-v1:tampered"}"#.to_vec();

    let error = verify_calibration_artifact_recomputed(
        &artifact_bytes,
        &verifier_input.corpus_record_canonical_bytes,
        &signal_samples,
    )
    .expect_err("corpus hash mismatch must fail");

    assert!(matches!(
        error,
        CalibrationVerificationError::CorpusHashMismatch { .. }
    ));
}

fn sdk_signal_samples(signals: &[CalibrationSignalSamples]) -> Vec<SdkCalibrationSignalSamples> {
    signals
        .iter()
        .map(|signal| SdkCalibrationSignalSamples {
            signal_id: signal.signal_id.clone(),
            signal_schema_version: signal.signal_schema_version.clone(),
            metric_notes: signal.metric_notes.clone(),
            samples: signal
                .samples
                .iter()
                .map(|sample| SdkCalibrationSample {
                    sample_id: sample.sample_id.clone(),
                    score_bp: sample.score_bp,
                    positive: sample.positive,
                })
                .collect(),
        })
        .collect()
}
