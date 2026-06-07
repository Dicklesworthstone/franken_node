//! BPET phenotype extraction conformance tests (bd-2xgs.1).
//!
//! This harness exercises the public extractor API alongside the inline
//! library tests.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

use frankenengine_node::security::bpet::phenotype_extractor::{
    ADVERSARY_CORPUS_RECORD_SCHEMA_VERSION, AdversaryCorpusRecord, CodeMetadata,
    CorpusDependencyTopologyContext, CorpusFeatureObservation, CorpusFilesystemSurface,
    CorpusGroundTruth, CorpusGroundTruthLabel, CorpusNetworkSurface, CorpusProvenanceKind,
    CorpusProvenanceRef, CorpusRecordError, CorpusTrajectoryPoint, DEFAULT_MAX_CORPUS_RECORD_BYTES,
    DependencyDeclaration, EvidenceSource, ExtractedFeature, GENOME_DIMENSIONS, ManifestEvidence,
    PHENOTYPE_EXTRACTOR_SCHEMA_VERSION, PhenotypeExtractionError, PhenotypeExtractor,
    RuntimeEvidence, UncertaintyCode, VersionEvidence, canonical_corpus_record_bytes,
    decode_canonical_corpus_record, event_codes, feature_names, load_corpus_record,
};
use serde_json::Value;
use tempfile::NamedTempFile;

const TRACE_ID: &str = "trace-bpet-feature-001";
type TestResult = Result<(), Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

fn map<const N: usize>(items: [(&str, u64); N]) -> BTreeMap<String, u64> {
    items
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

fn full_fixture(version: &str) -> VersionEvidence {
    VersionEvidence {
        package_name: "pkg-alpha".to_string(),
        version: version.to_string(),
        runtime: Some(RuntimeEvidence {
            capability_invocations: Some(map([("fs.read", 120), ("net.fetch", 30)])),
            cpu_time_ms: Some(300_000),
            memory_peak_bytes: Some(536_870_912),
            network_accesses: Some(map([("api.example.test", 10), ("cdn.example.test", 4)])),
            network_egress_bytes: Some(10_485_760),
            filesystem_read_ops: Some(25_000),
            filesystem_write_ops: Some(5_000),
        }),
        manifest: Some(ManifestEvidence {
            declared_permissions: Some(vec![
                "fs:read".to_string(),
                "net:fetch".to_string(),
                "process:env".to_string(),
            ]),
            dependency_declarations: Some(vec![
                DependencyDeclaration {
                    name: "serde".to_string(),
                    version_requirement: Some("1".to_string()),
                    direct: true,
                },
                DependencyDeclaration {
                    name: "url".to_string(),
                    version_requirement: Some("2".to_string()),
                    direct: false,
                },
            ]),
            api_surface_declarations: Some(vec!["run".to_string(), "verify".to_string()]),
        }),
        code: Some(CodeMetadata {
            cyclomatic_complexity: Some(200),
            binary_size_bytes: Some(10_485_760),
            exported_symbol_count: Some(100),
            dependency_tree_depth: Some(4),
        }),
        trace_id: TRACE_ID.to_string(),
    }
}

fn partial_fixture() -> VersionEvidence {
    VersionEvidence {
        package_name: "pkg-beta".to_string(),
        version: "0.2.0".to_string(),
        runtime: None,
        manifest: Some(ManifestEvidence {
            declared_permissions: Some(vec![
                "fs:read".to_string(),
                "fs:read".to_string(),
                " ".to_string(),
            ]),
            dependency_declarations: None,
            api_surface_declarations: None,
        }),
        code: Some(CodeMetadata {
            cyclomatic_complexity: Some(10),
            binary_size_bytes: None,
            exported_symbol_count: Some(5),
            dependency_tree_depth: None,
        }),
        trace_id: "trace-bpet-feature-partial".to_string(),
    }
}

fn expected_full_values() -> BTreeMap<&'static str, f64> {
    BTreeMap::from([
        (feature_names::CAPABILITY_INVOCATION_INTENSITY, 0.015_187_5),
        (feature_names::RESOURCE_ENVELOPE_PRESSURE, 0.5),
        (feature_names::NETWORK_SURFACE_AREA, 0.057_812_5),
        (feature_names::FILESYSTEM_SURFACE_AREA, 0.3),
        (feature_names::DECLARED_PERMISSION_SURFACE, 0.015_625),
        (feature_names::CODE_COMPLEXITY, 0.07),
        (feature_names::DEPENDENCY_SURFACE, 0.033_203_125),
    ])
}

fn assert_close(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() <= 1.0e-12,
        "actual={actual} expected={expected}"
    );
}

fn artifact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/10.21/bpet_feature_samples.jsonl")
}

fn corpus_golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/adversary_corpus_record_v1.json")
}

fn corpus_record_fixture() -> AdversaryCorpusRecord {
    let phenotype_features = BTreeMap::from([
        (
            feature_names::CAPABILITY_INVOCATION_INTENSITY.to_string(),
            CorpusFeatureObservation::known(1_519, EvidenceSource::RuntimeEvidence, "prov-runtime"),
        ),
        (
            feature_names::NETWORK_SURFACE_AREA.to_string(),
            CorpusFeatureObservation::known(578, EvidenceSource::RuntimeEvidence, "prov-runtime"),
        ),
        (
            feature_names::FILESYSTEM_SURFACE_AREA.to_string(),
            CorpusFeatureObservation::known(3_000, EvidenceSource::RuntimeEvidence, "prov-runtime"),
        ),
        (
            feature_names::DEPENDENCY_SURFACE.to_string(),
            CorpusFeatureObservation::partial(
                332,
                EvidenceSource::Derived,
                UncertaintyCode::PartialEvidence,
                "prov-lockfile",
            ),
        ),
    ]);

    AdversaryCorpusRecord {
        schema_version: ADVERSARY_CORPUS_RECORD_SCHEMA_VERSION.to_string(),
        record_id: "corpus-record-0001".to_string(),
        package_name: "npm:@example/benign-tool".to_string(),
        package_version: "1.2.3".to_string(),
        observation_timestamp: "2026-06-07T03:31:00Z".to_string(),
        phenotype_features,
        capability_invocations: BTreeMap::from([
            ("fs.read".to_string(), 12),
            ("net.fetch".to_string(), 3),
        ]),
        network_surface: CorpusNetworkSurface {
            destination_classes: BTreeMap::from([
                ("cdn".to_string(), 2),
                ("registry".to_string(), 1),
            ]),
            unique_destination_count: 2,
            egress_bytes: 4096,
        },
        filesystem_surface: CorpusFilesystemSurface {
            path_classes: BTreeMap::from([
                ("package_manifest".to_string(), 1),
                ("source_file".to_string(), 7),
            ]),
            read_ops: 12,
            write_ops: 0,
        },
        dependency_topology: CorpusDependencyTopologyContext {
            direct_dependency_count: 2,
            transitive_dependency_count: 9,
            max_depth: 3,
            maintainer_overlap_count: 1,
            single_point_of_failure_score_bp: 1_250,
        },
        longitudinal_trajectory: vec![
            CorpusTrajectoryPoint {
                observed_at: "2026-06-01T00:00:00Z".to_string(),
                package_version: "1.2.1".to_string(),
                feature_values_bp: BTreeMap::from([
                    (
                        feature_names::CAPABILITY_INVOCATION_INTENSITY.to_string(),
                        1_200,
                    ),
                    (feature_names::NETWORK_SURFACE_AREA.to_string(), 500),
                ]),
                risk_score_bp: 2_000,
            },
            CorpusTrajectoryPoint {
                observed_at: "2026-06-07T03:31:00Z".to_string(),
                package_version: "1.2.3".to_string(),
                feature_values_bp: BTreeMap::from([
                    (
                        feature_names::CAPABILITY_INVOCATION_INTENSITY.to_string(),
                        1_519,
                    ),
                    (feature_names::NETWORK_SURFACE_AREA.to_string(), 578),
                ]),
                risk_score_bp: 2_100,
            },
        ],
        ground_truth: CorpusGroundTruth {
            label: CorpusGroundTruthLabel::Benign,
            campaign_id: None,
            confidence_basis_points: 9_500,
            evidence_refs: vec!["prov-runtime".to_string(), "prov-lockfile".to_string()],
            rationale: "seed benign control with low-risk runtime behavior".to_string(),
        },
        provenance: vec![
            CorpusProvenanceRef {
                provenance_id: "prov-runtime".to_string(),
                kind: CorpusProvenanceKind::RuntimeTrace,
                uri: "fixtures/runtime/pkg-alpha-trace.jsonl".to_string(),
                captured_at: "2026-06-07T03:31:00Z".to_string(),
                labeler: "SilverMaple".to_string(),
            },
            CorpusProvenanceRef {
                provenance_id: "prov-lockfile".to_string(),
                kind: CorpusProvenanceKind::RegistrySnapshot,
                uri: "fixtures/lockfiles/pkg-alpha-lock.json".to_string(),
                captured_at: "2026-06-07T03:31:00Z".to_string(),
                labeler: "SilverMaple".to_string(),
            },
        ],
    }
}

fn golden_without_trailing_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.ends_with(b"\n") {
        bytes.pop();
    }
    bytes
}

#[test]
fn full_evidence_extraction_is_deterministic_and_provenanced() -> TestResult {
    let evidence = full_fixture("1.2.3");
    let mut first = PhenotypeExtractor::new();
    let mut second = PhenotypeExtractor::new();

    let first_vector = first.extract_version(&evidence)?;
    let second_vector = second.extract_version(&evidence)?;

    assert_eq!(first_vector, second_vector);
    assert_eq!(
        first_vector.schema_version,
        PHENOTYPE_EXTRACTOR_SCHEMA_VERSION
    );
    assert_eq!(first_vector.package_name, "pkg-alpha");
    assert_eq!(first_vector.version, "1.2.3");

    let actual_dimensions: BTreeSet<&str> =
        first_vector.features.keys().map(String::as_str).collect();
    let expected_dimensions: BTreeSet<&str> = GENOME_DIMENSIONS.into_iter().collect();
    assert_eq!(actual_dimensions, expected_dimensions);

    for (name, expected) in expected_full_values() {
        let feature = first_vector
            .features
            .get(name)
            .ok_or_else(|| test_error("expected feature dimension"))?;
        assert!(matches!(feature, ExtractedFeature::Known { .. }));
        let value = feature
            .value()
            .ok_or_else(|| test_error("expected known value"))?;
        assert_close(value, expected);

        let provenance = first_vector
            .provenance
            .get(name)
            .ok_or_else(|| test_error("expected provenance"))?;
        assert_eq!(provenance.feature, name);
        assert_close(provenance.confidence, 1.0);
    }

    let event_codes: Vec<&str> = first_vector
        .events
        .iter()
        .map(|event| event.event_code.as_str())
        .collect();
    assert_eq!(
        event_codes.first().copied(),
        Some(event_codes::BPET_EXTRACT_INPUT_ACCEPTED)
    );
    assert_eq!(
        event_codes.last().copied(),
        Some(event_codes::BPET_EXTRACT_VECTOR_EMITTED)
    );
    assert_eq!(
        event_codes
            .iter()
            .filter(|code| **code == event_codes::BPET_EXTRACT_FEATURE_KNOWN)
            .count(),
        GENOME_DIMENSIONS.len()
    );
    assert_eq!(first.audit_log(), first_vector.events.as_slice());
    Ok(())
}

#[test]
fn missing_evidence_is_typed_uncertainty_not_zero() -> TestResult {
    let mut extractor = PhenotypeExtractor::new();
    let vector = extractor.extract_version(&partial_fixture())?;

    for name in [
        feature_names::CAPABILITY_INVOCATION_INTENSITY,
        feature_names::RESOURCE_ENVELOPE_PRESSURE,
        feature_names::NETWORK_SURFACE_AREA,
        feature_names::FILESYSTEM_SURFACE_AREA,
    ] {
        let feature = vector
            .features
            .get(name)
            .ok_or_else(|| test_error("runtime feature present"))?;
        assert!(
            matches!(
                feature,
                ExtractedFeature::Unknown { uncertainty }
                    if uncertainty.code == UncertaintyCode::SourceMissing
                        && uncertainty.source == EvidenceSource::RuntimeEvidence
            ),
            "{name} should be unknown due to missing runtime evidence"
        );
        assert!(
            feature.value().is_none(),
            "unknown feature should not report zero"
        );
        assert_close(
            vector
                .provenance
                .get(name)
                .ok_or_else(|| test_error("runtime provenance"))?
                .confidence,
            0.0,
        );
    }

    let declared = vector
        .features
        .get(feature_names::DECLARED_PERMISSION_SURFACE)
        .ok_or_else(|| test_error("declared permission feature present"))?;
    assert!(matches!(
        declared,
        ExtractedFeature::Partial { uncertainty, .. }
            if uncertainty.code == UncertaintyCode::PartialEvidence
                && uncertainty.source == EvidenceSource::ManifestMetadata
    ));
    let declared_value = declared
        .value()
        .ok_or_else(|| test_error("declared permission partial value"))?;
    assert_close(declared_value, 0.007_812_5);
    assert_close(
        vector
            .provenance
            .get(feature_names::DECLARED_PERMISSION_SURFACE)
            .ok_or_else(|| test_error("declared permission provenance"))?
            .confidence,
        0.6,
    );

    let dependency = vector
        .features
        .get(feature_names::DEPENDENCY_SURFACE)
        .ok_or_else(|| test_error("dependency feature present"))?;
    assert!(matches!(
        dependency,
        ExtractedFeature::Unknown { uncertainty }
            if uncertainty.code == UncertaintyCode::FieldMissing
                && uncertainty.source == EvidenceSource::Derived
    ));
    Ok(())
}

#[test]
fn batch_extraction_sorts_versions_and_rejects_invalid_batches() -> TestResult {
    let mut extractor = PhenotypeExtractor::new();
    let vectors = extractor.extract_batch(&[full_fixture("2.0.0"), full_fixture("1.0.0")])?;
    let versions: Vec<&str> = vectors
        .iter()
        .map(|vector| vector.version.as_str())
        .collect();
    assert_eq!(versions, vec!["1.0.0", "2.0.0"]);

    let duplicate = match extractor.extract_batch(&[full_fixture("1.0.0"), full_fixture("1.0.0")]) {
        Ok(_) => return Err(test_error("duplicate package/version should fail closed")),
        Err(err) => err,
    };
    assert!(matches!(
        duplicate,
        PhenotypeExtractionError::DuplicateVersion { .. }
    ));

    let empty = match extractor.extract_batch(&[]) {
        Ok(_) => return Err(test_error("empty batch should fail closed")),
        Err(err) => err,
    };
    assert_eq!(empty, PhenotypeExtractionError::EmptyBatch);

    let too_large = match PhenotypeExtractor::with_max_batch_versions(1)
        .extract_batch(&[full_fixture("1.0.0"), full_fixture("2.0.0")])
    {
        Ok(_) => return Err(test_error("oversized batch should fail closed")),
        Err(err) => err,
    };
    assert!(matches!(
        too_large,
        PhenotypeExtractionError::BatchTooLarge { len: 2, max: 1 }
    ));
    Ok(())
}

#[test]
fn drift_sample_and_jsonl_artifact_match_extractor_output() -> TestResult {
    let mut extractor = PhenotypeExtractor::new();
    let vector = extractor.extract_version(&full_fixture("1.2.3"))?;
    let sample = vector.to_drift_sample(1_714_000_000);

    assert_eq!(sample.ts, 1_714_000_000);
    assert_eq!(sample.fields.len(), GENOME_DIMENSIONS.len());
    for (name, expected) in expected_full_values() {
        assert_close(
            *sample
                .fields
                .get(name)
                .ok_or_else(|| test_error("expected drift sample field"))?,
            expected,
        );
    }

    let raw = fs::read_to_string(artifact_path())?;
    let first_line = raw
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| test_error("artifact should contain a JSONL record"))?;
    let artifact: Value = serde_json::from_str(first_line)?;
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("bpet.phenotype_extractor.samples.v1")
    );
    assert_eq!(
        artifact
            .get("source_schema_version")
            .and_then(Value::as_str),
        Some(PHENOTYPE_EXTRACTOR_SCHEMA_VERSION)
    );
    assert_eq!(
        artifact.get("package_name").and_then(Value::as_str),
        Some(vector.package_name.as_str())
    );
    assert_eq!(
        artifact.get("version").and_then(Value::as_str),
        Some(vector.version.as_str())
    );

    let known_values = artifact
        .get("known_feature_values")
        .and_then(Value::as_object)
        .ok_or_else(|| test_error("artifact known_feature_values object missing"))?;
    for (name, value) in vector.known_feature_values() {
        let artifact_value = known_values
            .get(name.as_str())
            .and_then(Value::as_f64)
            .ok_or_else(|| test_error("artifact missing feature"))?;
        assert_close(artifact_value, value);
    }
    Ok(())
}

#[test]
fn corpus_record_canonical_bytes_match_golden_and_round_trip() -> TestResult {
    let record = corpus_record_fixture();
    let bytes = canonical_corpus_record_bytes(&record)?;
    let golden = golden_without_trailing_newline(fs::read(corpus_golden_path())?);

    assert_eq!(
        String::from_utf8(bytes.clone())?,
        String::from_utf8(golden)?,
        "adversary corpus record canonical bytes drifted from golden"
    );
    assert!(
        !bytes.windows(2).any(|window| window == b".0"),
        "corpus canonical encoding must avoid floating-point JSON literals"
    );

    let decoded = decode_canonical_corpus_record(&bytes)?;
    assert_eq!(decoded, record);
    assert_eq!(decoded.canonical_bytes()?, bytes);
    Ok(())
}

#[test]
fn corpus_record_loader_is_bounded_and_rejects_float_json() -> TestResult {
    let record = corpus_record_fixture();
    let bytes = record.canonical_bytes()?;
    let file = NamedTempFile::new()?;
    fs::write(file.path(), &bytes)?;

    let loaded = load_corpus_record(file.path(), DEFAULT_MAX_CORPUS_RECORD_BYTES)?;
    assert_eq!(loaded, record);
    assert!(
        load_corpus_record(file.path(), bytes.len().saturating_sub(1) as u64).is_err(),
        "bounded loader must reject files above the caller-supplied limit"
    );

    let mut with_float = serde_json::from_slice::<Value>(&bytes)?;
    let features = with_float
        .get_mut("phenotype_features")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("fixture missing phenotype_features"))?;
    let network_surface = features
        .get_mut(feature_names::NETWORK_SURFACE_AREA)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("fixture missing network surface feature"))?;
    network_surface.insert("value_basis_points".to_string(), serde_json::json!(57.8));
    let float_bytes = serde_json::to_vec(&with_float)?;
    let err = decode_canonical_corpus_record(&float_bytes)
        .expect_err("float-valued corpus record must fail closed");
    assert!(matches!(err, CorpusRecordError::FloatingPointValue { .. }));
    Ok(())
}
