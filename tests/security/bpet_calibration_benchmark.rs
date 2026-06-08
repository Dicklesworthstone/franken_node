use std::io::Write as _;

use frankenengine_node::schema_versions;
use frankenengine_node::security::bpet::adversarial_scenarios::{
    REAL_LABELED_CORPUS_MIN_RECORDS, real_labeled_corpus_records, synthesize_labeled_corpus_records,
};
use frankenengine_node::security::bpet::calibration_benchmark::{
    CALIBRATION_ARTIFACT_SCHEMA_VERSION, CALIBRATION_E2E_TRACE_SCHEMA_VERSION,
    CALIBRATION_TARGET_ALPHA_BP, CORPUS_EXCHANGEABILITY_TRANSFER_SCHEMA_VERSION, CalibrationSample,
    CalibrationSignalSamples, FN_CALIB_ARTIFACT_SIGNED, FN_CALIB_SDK_RECOMPUTE_PASS,
    FN_CALIB_VERIFIER_INPUT_PREPARED, FN_CORPUS_CANONICAL_ROUNDTRIP_PASS, FN_CORPUS_GENERATE_START,
    RELIABILITY_BIN_COUNT, calibration_e2e_structured_log_events,
    calibration_signal_report_from_samples, calibration_structured_log_jsonl,
    generate_calibration_verifier_input, generate_corpus_exchangeability_transfer_report,
    generate_signed_calibration_artifact, verify_signed_calibration_artifact,
};
use frankenengine_node::security::bpet::phenotype_extractor::{
    ADVERSARY_CORPUS_RECORD_SCHEMA_VERSION, CorpusGroundTruthLabel, CorpusProvenanceKind,
    CorpusRecordError, decode_canonical_corpus_record, load_corpus_record,
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
fn corpus_records_round_trip_through_canonical_loader_and_schema_registry() {
    let first = synthesize_labeled_corpus_records().expect("first corpus generation");
    let second = synthesize_labeled_corpus_records().expect("second corpus generation");

    assert_eq!(first.len(), 16);
    assert_eq!(second.len(), 16);
    assert!(
        schema_versions::all_versions()
            .iter()
            .any(|(name, version)| {
                *name == "adversary_corpus_record"
                    && *version == ADVERSARY_CORPUS_RECORD_SCHEMA_VERSION
            })
    );

    let first_bytes = first
        .iter()
        .map(|record| record.canonical_bytes().expect("canonical record"))
        .collect::<Vec<_>>();
    let second_bytes = second
        .iter()
        .map(|record| record.canonical_bytes().expect("canonical record"))
        .collect::<Vec<_>>();
    assert_eq!(first_bytes, second_bytes);

    let campaign_members = first
        .iter()
        .filter(|record| record.ground_truth.label == CorpusGroundTruthLabel::CampaignMember)
        .count();
    let benign_controls = first
        .iter()
        .filter(|record| record.ground_truth.label == CorpusGroundTruthLabel::Benign)
        .count();
    assert_eq!(campaign_members, 8);
    assert_eq!(benign_controls, 8);

    for (record, bytes) in first.iter().zip(&first_bytes) {
        assert_eq!(
            record.schema_version,
            ADVERSARY_CORPUS_RECORD_SCHEMA_VERSION
        );
        let decoded = decode_canonical_corpus_record(bytes).expect("canonical decode");
        assert_eq!(decoded, *record);
        assert_eq!(decoded.canonical_bytes().expect("re-encoded bytes"), *bytes);
    }

    let first_record_bytes = first_bytes.first().expect("first corpus record bytes");
    let first_record = first.first().expect("first corpus record");
    let first_record_len =
        u64::try_from(first_record_bytes.len()).expect("first corpus record length fits u64");

    let mut file = tempfile::NamedTempFile::new().expect("temp corpus record");
    file.write_all(first_record_bytes)
        .expect("write canonical corpus record");
    let loaded =
        load_corpus_record(file.path(), first_record_len).expect("bounded load accepts exact size");
    assert_eq!(&loaded, first_record);
    let undersized_limit = first_record_len.saturating_sub(1);
    let err = load_corpus_record(file.path(), undersized_limit)
        .expect_err("bounded_read guard must reject truncated load budget");
    assert!(matches!(err, CorpusRecordError::Io { .. }));
}

#[test]
fn real_labeled_fixture_seed_preserves_provenance_and_confidence() {
    let records = real_labeled_corpus_records();

    assert!(records.len() >= REAL_LABELED_CORPUS_MIN_RECORDS);
    assert_eq!(
        records
            .iter()
            .filter(|record| record.ground_truth.label == CorpusGroundTruthLabel::Malicious)
            .count(),
        2
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record.ground_truth.label == CorpusGroundTruthLabel::Benign)
            .count(),
        2
    );
    assert!(records.iter().any(|record| {
        record
            .provenance
            .iter()
            .any(|provenance| provenance.kind == CorpusProvenanceKind::RealAdvisory)
    }));
    assert!(records.iter().any(|record| {
        record
            .provenance
            .iter()
            .any(|provenance| provenance.kind == CorpusProvenanceKind::RegistrySnapshot)
    }));
    assert!(
        records
            .iter()
            .all(|record| record.ground_truth.confidence_basis_points > 0)
    );

    for record in &records {
        record.validate().expect("real corpus record validates");
        let bytes = record.canonical_bytes().expect("canonical bytes");
        let decoded = decode_canonical_corpus_record(&bytes).expect("canonical decode");
        assert_eq!(decoded, *record);
        assert!(
            record
                .provenance
                .iter()
                .all(|provenance| provenance.uri.starts_with("https://"))
        );
    }
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
    assert_eq!(artifact.corpus_record_count, 20);

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
fn transfer_report_compares_synthetic_and_real_labeled_cohorts() {
    let report = generate_corpus_exchangeability_transfer_report().expect("transfer report");

    assert_eq!(
        report.schema_version,
        CORPUS_EXCHANGEABILITY_TRANSFER_SCHEMA_VERSION
    );
    assert_eq!(report.synthetic.record_count, 16);
    assert!(report.real.record_count >= u64::try_from(REAL_LABELED_CORPUS_MIN_RECORDS).unwrap());
    assert_eq!(report.real.positive_count, 2);
    assert_eq!(report.real.benign_count, 2);
    assert!(
        report
            .real
            .provenance_kinds
            .contains(&"real_advisory".to_string())
    );
    assert!(
        report
            .real
            .provenance_kinds
            .contains(&"registry_snapshot".to_string())
    );
    assert!(
        report
            .audit_notes
            .iter()
            .any(|note| note.contains("documented minimum"))
    );

    let signal_ids = report
        .signal_summaries
        .iter()
        .map(|summary| summary.signal_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        signal_ids,
        vec!["bpet.evolution_risk_scorer", "dgis.spof_topology_signal"]
    );

    for summary in &report.signal_summaries {
        assert_eq!(summary.synthetic_metrics.sample_count, 16);
        assert_eq!(summary.real_metrics.sample_count, 4);
        assert!(summary.coverage_delta_bp <= 10_000);
        assert!(summary.false_alarm_delta_bp <= 10_000);
        assert!(summary.expected_calibration_error_delta_bp <= 10_000);
        assert!(summary.roc_auc_delta_bp <= 10_000);
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
fn calibration_metrics_recover_known_planted_signal_coverage() {
    let report = calibration_signal_report_from_samples(&CalibrationSignalSamples {
        signal_id: "test.planted.detector".to_string(),
        signal_schema_version: "test.planted.detector.v1".to_string(),
        metric_notes: vec!["planted two-hit one-miss detector fixture".to_string()],
        samples: vec![
            CalibrationSample {
                sample_id: "positive-hit-a".to_string(),
                score_bp: 9_000,
                positive: true,
            },
            CalibrationSample {
                sample_id: "positive-hit-b".to_string(),
                score_bp: 7_000,
                positive: true,
            },
            CalibrationSample {
                sample_id: "positive-miss".to_string(),
                score_bp: 2_000,
                positive: true,
            },
            CalibrationSample {
                sample_id: "negative-clean-a".to_string(),
                score_bp: 1_000,
                positive: false,
            },
            CalibrationSample {
                sample_id: "negative-clean-b".to_string(),
                score_bp: 3_000,
                positive: false,
            },
            CalibrationSample {
                sample_id: "negative-false-alarm".to_string(),
                score_bp: 8_000,
                positive: false,
            },
        ],
    })
    .expect("planted calibration report");

    assert_eq!(report.metrics.sample_count, 6);
    assert_eq!(report.metrics.positive_count, 3);
    assert_eq!(report.metrics.negative_count, 3);
    assert_eq!(report.metrics.coverage_at_target_alpha_bp, 6_667);
    assert_eq!(
        report.metrics.false_alarm_under_sequential_peeking_bp,
        3_333
    );
    assert_eq!(report.metrics.reliability_bins.len(), RELIABILITY_BIN_COUNT);
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

    let events =
        calibration_e2e_structured_log_events(&artifact, &verifier_input, &verified.event_codes);
    let event_codes = events
        .iter()
        .map(|event| event.event_code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        event_codes,
        vec![
            FN_CORPUS_GENERATE_START,
            FN_CORPUS_CANONICAL_ROUNDTRIP_PASS,
            FN_CALIB_VERIFIER_INPUT_PREPARED,
            FN_CALIB_ARTIFACT_SIGNED,
            FN_CALIB_SDK_RECOMPUTE_PASS,
        ]
    );
    assert!(
        events
            .iter()
            .all(|event| event.schema_version == CALIBRATION_E2E_TRACE_SCHEMA_VERSION)
    );

    let jsonl = calibration_structured_log_jsonl(&events).expect("structured log jsonl");
    let expected_jsonl = format!(
        "{{\"artifact_schema_version\":\"bpet.calibration_artifact.v1\",\"corpus_hash\":\"{hash}\",\"corpus_record_count\":20,\"detail\":\"deterministic corpus generation accepted\",\"event_code\":\"FN-CORPUS-GENERATE-START\",\"event_index\":0,\"schema_version\":\"bpet.calibration_e2e_trace.v1\",\"signal_count\":3,\"trace_id\":\"bpet-calibration-e2e-v1\"}}\n\
         {{\"artifact_schema_version\":\"bpet.calibration_artifact.v1\",\"corpus_hash\":\"{hash}\",\"corpus_record_count\":20,\"detail\":\"canonical corpus records round-tripped byte-identically\",\"event_code\":\"FN-CORPUS-CANONICAL-ROUNDTRIP-PASS\",\"event_index\":1,\"schema_version\":\"bpet.calibration_e2e_trace.v1\",\"signal_count\":3,\"trace_id\":\"bpet-calibration-e2e-v1\"}}\n\
         {{\"artifact_schema_version\":\"bpet.calibration_artifact.v1\",\"corpus_hash\":\"{hash}\",\"corpus_record_count\":20,\"detail\":\"calibration verifier input prepared\",\"event_code\":\"FN-CALIB-VERIFIER-INPUT-PREPARED\",\"event_index\":2,\"schema_version\":\"bpet.calibration_e2e_trace.v1\",\"signal_count\":3,\"trace_id\":\"bpet-calibration-e2e-v1\"}}\n\
         {{\"artifact_schema_version\":\"bpet.calibration_artifact.v1\",\"corpus_hash\":\"{hash}\",\"corpus_record_count\":20,\"detail\":\"signed calibration artifact generated\",\"event_code\":\"FN-CALIB-ARTIFACT-SIGNED\",\"event_index\":3,\"schema_version\":\"bpet.calibration_e2e_trace.v1\",\"signal_count\":3,\"trace_id\":\"bpet-calibration-e2e-v1\"}}\n\
         {{\"artifact_schema_version\":\"bpet.calibration_artifact.v1\",\"corpus_hash\":\"{hash}\",\"corpus_record_count\":20,\"detail\":\"verifier sdk recompute passed after 3 sdk events\",\"event_code\":\"FN-CALIB-SDK-RECOMPUTE-PASS\",\"event_index\":4,\"schema_version\":\"bpet.calibration_e2e_trace.v1\",\"signal_count\":3,\"trace_id\":\"bpet-calibration-e2e-v1\"}}\n",
        hash = artifact.corpus_hash
    );
    assert_eq!(jsonl, expected_jsonl);
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
