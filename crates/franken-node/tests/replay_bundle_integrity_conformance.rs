use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundle, generate_replay_bundle, to_canonical_json,
    validate_bundle_integrity,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const REPLAY_BUNDLE_INTEGRITY_VECTORS_JSON: &str =
    include_str!("../../../artifacts/conformance/replay_bundle_integrity_vectors.json");

type TestResult = Result<(), String>;

#[derive(Debug, Deserialize)]
struct ReplayBundleConformanceVectors {
    schema_version: String,
    coverage: Vec<CoverageRow>,
    vectors: Vec<ReplayBundleVector>,
}

#[derive(Debug, Deserialize)]
struct CoverageRow {
    spec_section: String,
    level: String,
    tested: bool,
}

#[derive(Debug, Deserialize)]
struct ReplayBundleVector {
    name: String,
    incident_id: String,
    events: Vec<RawEvent>,
    expected: Option<ExpectedReplayBundle>,
    #[serde(default)]
    expected_wire_artifact: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExpectedReplayBundle {
    bundle_id: String,
    created_at: String,
    incident_id: String,
    integrity_hash: String,
    manifest: ExpectedManifest,
    chunks: Vec<ExpectedChunk>,
    timeline: Vec<ExpectedTimelineEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExpectedManifest {
    event_count: usize,
    first_timestamp: Option<String>,
    last_timestamp: Option<String>,
    time_span_micros: u64,
    compressed_size_bytes: u64,
    chunk_count: u32,
    decision_sequence_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExpectedChunk {
    chunk_index: u32,
    total_chunks: u32,
    event_count: usize,
    first_sequence_number: u64,
    last_sequence_number: u64,
    compressed_size_bytes: u64,
    chunk_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExpectedTimelineEvent {
    sequence_number: u64,
    timestamp: String,
    event_type: String,
    payload: Value,
    causal_parent: Option<u64>,
}

fn conformance_vectors() -> Result<ReplayBundleConformanceVectors, String> {
    serde_json::from_str(REPLAY_BUNDLE_INTEGRITY_VECTORS_JSON)
        .map_err(|err| format!("replay-bundle integrity vectors must parse: {err}"))
}

fn expected_from_bundle(bundle: &ReplayBundle) -> ExpectedReplayBundle {
    ExpectedReplayBundle {
        bundle_id: bundle.bundle_id.to_string(),
        created_at: bundle.created_at.clone(),
        incident_id: bundle.incident_id.clone(),
        integrity_hash: bundle.integrity_hash.clone(),
        manifest: ExpectedManifest {
            event_count: bundle.manifest.event_count,
            first_timestamp: bundle.manifest.first_timestamp.clone(),
            last_timestamp: bundle.manifest.last_timestamp.clone(),
            time_span_micros: bundle.manifest.time_span_micros,
            compressed_size_bytes: bundle.manifest.compressed_size_bytes,
            chunk_count: bundle.manifest.chunk_count,
            decision_sequence_hash: bundle.manifest.decision_sequence_hash.clone(),
        },
        chunks: bundle
            .chunks
            .iter()
            .map(|chunk| ExpectedChunk {
                chunk_index: chunk.chunk_index,
                total_chunks: chunk.total_chunks,
                event_count: chunk.event_count,
                first_sequence_number: chunk.first_sequence_number,
                last_sequence_number: chunk.last_sequence_number,
                compressed_size_bytes: chunk.compressed_size_bytes,
                chunk_hash: chunk.chunk_hash.clone(),
            })
            .collect(),
        timeline: bundle
            .timeline
            .iter()
            .map(|event| ExpectedTimelineEvent {
                sequence_number: event.sequence_number,
                timestamp: event.timestamp.clone(),
                event_type: event.event_type.as_str().to_string(),
                payload: event.payload.clone(),
                causal_parent: event.causal_parent,
            })
            .collect(),
    }
}

fn generated_bundle(vector: &ReplayBundleVector) -> Result<ReplayBundle, String> {
    generate_replay_bundle(&vector.incident_id, &vector.events)
        .map_err(|err| format!("{} must generate replay bundle: {err}", vector.name))
}

fn workspace_artifact(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn load_expected_wire_json(vector: &ReplayBundleVector) -> Result<String, String> {
    let artifact = vector
        .expected_wire_artifact
        .as_ref()
        .ok_or_else(|| format!("{} must declare expected_wire_artifact", vector.name))?;
    let path = workspace_artifact(artifact);
    std::fs::read_to_string(&path)
        .map(|contents| contents.trim_end_matches('\n').to_string())
        .map_err(|err| {
            format!(
                "{} expected wire artifact {} must be readable: {err}",
                vector.name,
                path.display()
            )
        })
}

fn assert_fail_closed(result: Result<bool, impl std::fmt::Display>, context: &str) -> TestResult {
    match result {
        Ok(false) | Err(_) => Ok(()),
        Ok(true) => Err(format!("{context} must fail closed")),
    }
}

#[cfg(feature = "advanced-features")]
#[test]
fn repro_bundle_evidence_ref_rejects_nul_byte_relative_path() {
    let evidence_ref = frankenengine_node::tools::repro_bundle_export::EvidenceRef {
        evidence_id: "evidence-1".to_string(),
        decision_kind: "admit".to_string(),
        epoch_id: 7,
        relative_path: "logs/evidence\0.json".to_string(),
    };

    assert!(!evidence_ref.is_portable());
}

#[test]
fn replay_bundle_integrity_vectors_cover_required_contract() -> TestResult {
    let vectors = conformance_vectors()?;
    assert_eq!(
        vectors.schema_version,
        "franken-node/replay-bundle-integrity-conformance/v1"
    );
    assert!(
        !vectors.vectors.is_empty(),
        "conformance artifact must publish at least one vector"
    );

    for required in [
        "INV-RB-DETERMINISTIC",
        "INV-RB-INTEGRITY",
        "INV-RB-CHUNKING",
    ] {
        assert!(
            vectors
                .coverage
                .iter()
                .any(|row| row.spec_section == required && row.level == "MUST" && row.tested),
            "{required} must be covered by the conformance matrix"
        );
    }

    Ok(())
}

#[test]
fn replay_bundle_canonical_wire_format_matches_artifact() -> TestResult {
    let vectors = conformance_vectors()?;
    let mut generated = Vec::new();
    let print_generated = std::env::var_os("REPLAY_BUNDLE_WIRE_CONFORMANCE_PRINT").is_some();

    for vector in &vectors.vectors {
        let bundle = generated_bundle(vector)?;
        let actual = to_canonical_json(&bundle)
            .map_err(|err| format!("{} canonical wire json failed: {err}", vector.name))?;

        if print_generated {
            generated.push(serde_json::json!({
                "name": vector.name,
                "expected_wire_json": actual,
            }));
            continue;
        }

        let expected = load_expected_wire_json(vector)?;
        assert_eq!(
            actual, expected,
            "{} canonical replay bundle wire format drifted from checked-in artifact",
            vector.name
        );

        let parsed: ReplayBundle = serde_json::from_str(&actual)
            .map_err(|err| format!("{} canonical wire json must parse: {err}", vector.name))?;
        let reparsed = to_canonical_json(&parsed).map_err(|err| {
            format!(
                "{} canonical wire json must be stable after parse: {err}",
                vector.name
            )
        })?;
        assert_eq!(
            reparsed, actual,
            "{} canonical wire json must round-trip byte-for-byte",
            vector.name
        );
    }

    if print_generated {
        let rendered = serde_json::to_string_pretty(&generated)
            .map_err(|err| format!("generated wire vector json must serialize: {err}"))?;
        println!("REPLAY_BUNDLE_WIRE_CONFORMANCE_GENERATED={rendered}");
    }

    Ok(())
}

#[test]
fn replay_bundle_integrity_vectors_match_runtime_contract() -> TestResult {
    let vectors = conformance_vectors()?;
    let mut generated = Vec::new();

    for vector in &vectors.vectors {
        let bundle = generated_bundle(vector)?;
        let actual = expected_from_bundle(&bundle);
        generated.push(serde_json::json!({
            "name": vector.name,
            "expected": actual,
        }));

        if std::env::var_os("REPLAY_BUNDLE_CONFORMANCE_PRINT").is_some() {
            continue;
        }

        let expected = vector
            .expected
            .as_ref()
            .ok_or_else(|| format!("{} must include checked-in expected values", vector.name))?;
        assert_eq!(
            &actual, expected,
            "{} replay bundle header/chunk/integrity fields drifted from artifact vector",
            vector.name
        );
        let valid = validate_bundle_integrity(&bundle)
            .map_err(|err| format!("{} integrity validation errored: {err}", vector.name))?;
        assert!(valid, "{} generated bundle must validate", vector.name);
    }

    if std::env::var_os("REPLAY_BUNDLE_CONFORMANCE_PRINT").is_some() {
        let rendered = serde_json::to_string_pretty(&generated)
            .map_err(|err| format!("generated vector json must serialize: {err}"))?;
        println!("REPLAY_BUNDLE_CONFORMANCE_GENERATED={}", rendered);
    }

    Ok(())
}

#[test]
fn replay_bundle_preserves_last_original_causal_parent_after_timestamp_sort() -> TestResult {
    let events = vec![
        RawEvent::new(
            "2026-02-20T10:00:00.000200Z",
            EventType::PolicyEval,
            json!({"decision":"quarantine"}),
        )
        .with_causal_parent(2),
        RawEvent::new(
            "2026-02-20T10:00:00.000100Z",
            EventType::ExternalSignal,
            json!({"signal":"anomaly"}),
        ),
    ];

    let bundle = generate_replay_bundle("INC-CAUSAL-LAST-PARENT", &events)
        .map_err(|err| format!("bundle generation must preserve remapped parent: {err}"))?;
    assert_eq!(bundle.timeline[0].payload, json!({"signal":"anomaly"}));
    assert_eq!(bundle.timeline[0].causal_parent, None);
    assert_eq!(bundle.timeline[1].payload, json!({"decision":"quarantine"}));
    assert_eq!(bundle.timeline[1].causal_parent, Some(1));
    assert!(
        validate_bundle_integrity(&bundle)
            .map_err(|err| format!("remapped parent bundle must validate: {err}"))?,
        "remapped parent bundle must pass integrity validation"
    );
    Ok(())
}

#[test]
fn replay_bundle_orders_same_timestamp_forward_parent_before_child() -> TestResult {
    let events = vec![
        RawEvent::new(
            "2026-02-20T10:00:00.000100Z",
            EventType::PolicyEval,
            json!({"decision":"quarantine"}),
        )
        .with_causal_parent(2),
        RawEvent::new(
            "2026-02-20T10:00:00.000100Z",
            EventType::ExternalSignal,
            json!({"signal":"anomaly"}),
        ),
    ];

    let bundle = generate_replay_bundle("INC-SAME-TIMESTAMP-FORWARD-PARENT", &events)
        .map_err(|err| format!("same-timestamp forward parent bundle must build: {err}"))?;

    let [parent, child] = bundle.timeline.as_slice() else {
        return Err(format!(
            "expected two timeline events, got {}",
            bundle.timeline.len()
        ));
    };
    assert_eq!(parent.payload, json!({"signal":"anomaly"}));
    assert_eq!(parent.causal_parent, None);
    assert_eq!(child.payload, json!({"decision":"quarantine"}));
    assert_eq!(child.causal_parent, Some(1));
    assert!(
        validate_bundle_integrity(&bundle)
            .map_err(|err| format!("same-timestamp forward parent bundle must validate: {err}"))?,
        "same-timestamp forward parent bundle must pass integrity validation"
    );
    Ok(())
}

#[test]
fn replay_bundle_integrity_vectors_fail_closed_on_tampering() -> TestResult {
    let vectors = conformance_vectors()?;

    for vector in &vectors.vectors {
        if vector.expected.is_none()
            && std::env::var_os("REPLAY_BUNDLE_CONFORMANCE_PRINT").is_some()
        {
            continue;
        }

        let bundle = generated_bundle(vector)?;

        let mut bad_integrity = bundle.clone();
        bad_integrity.integrity_hash.push('0');
        assert_fail_closed(
            validate_bundle_integrity(&bad_integrity),
            "tampered integrity hash",
        )?;

        let mut bad_manifest = bundle.clone();
        bad_manifest.manifest.decision_sequence_hash.push('0');
        assert_fail_closed(
            validate_bundle_integrity(&bad_manifest),
            "tampered manifest decision_sequence_hash",
        )?;

        let mut bad_chunk = bundle.clone();
        let first_chunk = bad_chunk
            .chunks
            .first_mut()
            .ok_or_else(|| format!("{} vector must include at least one chunk", vector.name))?;
        first_chunk.chunk_hash.push('0');
        assert_fail_closed(validate_bundle_integrity(&bad_chunk), "tampered chunk hash")?;
    }

    Ok(())
}

// MOCK-FREE E2E TESTS FOR REPLAY BUNDLE FILE I/O ROUNDTRIPS
// These tests replace in-memory fixtures with real file system operations

/// Structured logger for test phases
struct TestLogger {
    test_name: String,
    start_time: SystemTime,
}

impl TestLogger {
    fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            start_time: SystemTime::now(),
        }
    }

    fn log_phase(&self, phase: &str, event: &str, data: Value) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        eprintln!(
            "{}",
            json!({
                "ts": format!("{}", timestamp),
                "suite": "replay_bundle_file_io_roundtrip",
                "test": self.test_name,
                "phase": phase,
                "event": event,
                "data": data
            })
        );
    }

    fn log_file_operation(&self, operation: &str, path: &Path, size_bytes: u64) {
        self.log_phase(
            "file_io",
            operation,
            json!({
                "path": path.display().to_string(),
                "size_bytes": size_bytes
            }),
        );
    }

    fn log_assertion(&self, field: &str, expected: Value, actual: Value, matches: bool) {
        self.log_phase(
            "assert",
            "assertion",
            json!({
                "field": field,
                "expected": expected,
                "actual": actual,
                "match": matches
            }),
        );
    }

    fn log_test_complete(&self, result: &str, files_created: usize) {
        let duration = self.start_time.elapsed().unwrap_or(Duration::ZERO);
        self.log_phase(
            "teardown",
            "test_complete",
            json!({
                "result": result,
                "duration_ms": duration.as_millis(),
                "files_created": files_created
            }),
        );
    }
}

/// Production safety guard - ensure we're in test environment
fn validate_test_environment() {
    if std::env::var("NODE_ENV") == Ok("production".to_string()) {
        panic!("File I/O roundtrip tests must not run in production environment");
    }

    // Ensure we're running in test context
    assert!(
        std::env::var("CARGO").is_ok() || std::env::var("RUST_TEST_TIME_UNIT").is_ok(),
        "File I/O tests must run in controlled test environment"
    );
}

/// Create deterministic test event log for roundtrip testing
fn create_test_event_log() -> Vec<RawEvent> {
    vec![
        RawEvent::new(
            "2026-04-25T10:00:00Z",
            EventType::StateChange,
            json!({
                "component": "replay_engine",
                "action": "start",
                "sequence": 1
            }),
        )
        .with_policy_version("1.0.0"),
        RawEvent::new(
            "2026-04-25T10:00:01Z",
            EventType::PolicyEval,
            json!({
                "policy_id": "test_policy",
                "decision": "allow",
                "confidence": 0.95
            }),
        )
        .with_causal_parent(1),
        RawEvent::new(
            "2026-04-25T10:00:02Z",
            EventType::ExternalSignal,
            json!({
                "source": "operator",
                "signal_type": "checkpoint",
                "data": {
                    "checkpoint_id": "cp_001",
                    "verified": true
                }
            }),
        )
        .with_state_snapshot(json!({
            "active_sessions": 3,
            "pending_operations": 0
        })),
        RawEvent::new(
            "2026-04-25T10:00:03Z",
            EventType::OperatorAction,
            json!({
                "operator_id": "admin_001",
                "action": "validate_bundle",
                "target": "incident_replay_001"
            }),
        )
        .with_causal_parent(2),
    ]
}

/// Test replay bundle file I/O roundtrip with real disk persistence
#[test]
fn test_replay_bundle_file_io_roundtrip_preserves_integrity() {
    validate_test_environment();
    let logger = TestLogger::new("file_io_roundtrip_integrity");

    logger.log_phase(
        "setup",
        "test_start",
        json!({
            "test_type": "file_io_roundtrip",
            "mock_free": true
        }),
    );

    // Create temporary workspace for real file operations
    let workspace = tempfile::tempdir().expect("create temporary workspace");
    logger.log_phase(
        "setup",
        "workspace_created",
        json!({
            "workspace_path": workspace.path().display().to_string()
        }),
    );

    // Generate replay bundle from deterministic event log
    let incident_id = "incident_roundtrip_test_001";
    let event_log = create_test_event_log();

    logger.log_phase(
        "generate",
        "bundle_creation_start",
        json!({
            "incident_id": incident_id,
            "event_count": event_log.len()
        }),
    );

    let original_bundle = generate_replay_bundle(incident_id, &event_log)
        .expect("generate_replay_bundle should succeed with valid input");

    // Validate original bundle integrity
    let integrity_valid = validate_bundle_integrity(&original_bundle)
        .expect("validate_bundle_integrity should succeed");
    assert!(
        integrity_valid,
        "Original bundle must pass integrity validation"
    );

    logger.log_phase(
        "generate",
        "bundle_created",
        json!({
            "bundle_id": original_bundle.bundle_id,
            "event_count": original_bundle.timeline.len(),
            "chunk_count": original_bundle.chunks.len()
        }),
    );

    // Export bundle to real file system
    let bundle_file_path = workspace.path().join("replay_bundle.json");
    let canonical_json =
        to_canonical_json(&original_bundle).expect("to_canonical_json should succeed");

    let json_size = u64::try_from(canonical_json.len()).unwrap_or(u64::MAX);
    fs::write(&bundle_file_path, &canonical_json).expect("writing bundle to file should succeed");

    logger.log_file_operation("write", &bundle_file_path, json_size);

    // Verify file actually exists and has expected size
    let file_metadata =
        fs::metadata(&bundle_file_path).expect("bundle file should exist after write");

    logger.log_assertion(
        "file_size_matches",
        json!(json_size),
        json!(file_metadata.len()),
        file_metadata.len() == json_size,
    );
    assert_eq!(
        file_metadata.len(),
        json_size,
        "Written file size must match JSON size"
    );

    // Import bundle from real file system
    let file_contents =
        fs::read_to_string(&bundle_file_path).expect("reading bundle from file should succeed");

    logger.log_file_operation(
        "read",
        &bundle_file_path,
        u64::try_from(file_contents.len()).unwrap_or(u64::MAX),
    );

    let imported_bundle: ReplayBundle = serde_json::from_str(&file_contents)
        .expect("deserializing bundle from file should succeed");

    // Validate imported bundle integrity
    let imported_integrity_valid = validate_bundle_integrity(&imported_bundle)
        .expect("validate_bundle_integrity should succeed on imported bundle");
    assert!(
        imported_integrity_valid,
        "Imported bundle must pass integrity validation"
    );

    logger.log_phase(
        "import",
        "bundle_imported",
        json!({
            "bundle_id": imported_bundle.bundle_id,
            "event_count": imported_bundle.timeline.len(),
            "chunk_count": imported_bundle.chunks.len()
        }),
    );

    // Verify roundtrip preserves exact data
    logger.log_assertion(
        "bundle_id_preserved",
        json!(original_bundle.bundle_id),
        json!(imported_bundle.bundle_id),
        original_bundle.bundle_id == imported_bundle.bundle_id,
    );
    assert_eq!(
        original_bundle.bundle_id, imported_bundle.bundle_id,
        "Bundle ID must be preserved across roundtrip"
    );

    logger.log_assertion(
        "incident_id_preserved",
        json!(original_bundle.incident_id),
        json!(imported_bundle.incident_id),
        original_bundle.incident_id == imported_bundle.incident_id,
    );
    assert_eq!(
        original_bundle.incident_id, imported_bundle.incident_id,
        "Incident ID must be preserved across roundtrip"
    );

    logger.log_assertion(
        "timeline_preserved",
        json!(original_bundle.timeline.len()),
        json!(imported_bundle.timeline.len()),
        original_bundle.timeline.len() == imported_bundle.timeline.len(),
    );
    assert_eq!(
        original_bundle.timeline, imported_bundle.timeline,
        "Timeline must be preserved across roundtrip"
    );

    logger.log_assertion(
        "manifest_preserved",
        json!(original_bundle.manifest.event_count),
        json!(imported_bundle.manifest.event_count),
        original_bundle.manifest == imported_bundle.manifest,
    );
    assert_eq!(
        original_bundle.manifest, imported_bundle.manifest,
        "Manifest must be preserved across roundtrip"
    );

    logger.log_assertion(
        "chunks_preserved",
        json!(original_bundle.chunks.len()),
        json!(imported_bundle.chunks.len()),
        original_bundle.chunks == imported_bundle.chunks,
    );
    assert_eq!(
        original_bundle.chunks, imported_bundle.chunks,
        "Chunks must be preserved across roundtrip"
    );

    // Verify canonical JSON is stable across multiple serializations
    let re_exported_json =
        to_canonical_json(&imported_bundle).expect("re-export to canonical JSON should succeed");

    logger.log_assertion(
        "canonical_json_stable",
        json!(canonical_json.len()),
        json!(re_exported_json.len()),
        canonical_json == re_exported_json,
    );
    assert_eq!(
        canonical_json, re_exported_json,
        "Canonical JSON must be stable across import/export cycle"
    );

    logger.log_test_complete("passed", 1);
}

/// Test replay bundle corruption detection during file I/O roundtrip
#[test]
fn test_replay_bundle_file_corruption_detection() {
    validate_test_environment();
    let logger = TestLogger::new("file_corruption_detection");

    logger.log_phase(
        "setup",
        "test_start",
        json!({
            "test_type": "corruption_detection",
            "mock_free": true
        }),
    );

    let workspace = tempfile::tempdir().expect("create temporary workspace");

    // Generate valid bundle
    let incident_id = "incident_corruption_test_001";
    let event_log = create_test_event_log();
    let original_bundle = generate_replay_bundle(incident_id, &event_log)
        .expect("generate_replay_bundle should succeed");

    // Write bundle to file
    let bundle_file_path = workspace.path().join("bundle_corruption_test.json");
    let canonical_json =
        to_canonical_json(&original_bundle).expect("to_canonical_json should succeed");

    fs::write(&bundle_file_path, &canonical_json).expect("writing bundle to file should succeed");

    logger.log_file_operation(
        "write",
        &bundle_file_path,
        u64::try_from(canonical_json.len()).unwrap_or(u64::MAX),
    );

    // Corrupt the file by truncating it
    let corrupted_json = &canonical_json[..canonical_json.len() / 2];
    let corrupted_path = workspace.path().join("bundle_corrupted.json");
    fs::write(&corrupted_path, corrupted_json).expect("writing corrupted bundle should succeed");

    logger.log_file_operation(
        "write_corrupted",
        &corrupted_path,
        u64::try_from(corrupted_json.len()).unwrap_or(u64::MAX),
    );

    // Attempt to import corrupted bundle
    let corrupted_contents =
        fs::read_to_string(&corrupted_path).expect("reading corrupted bundle should succeed");

    let import_result: Result<ReplayBundle, _> = serde_json::from_str(&corrupted_contents);

    logger.log_assertion(
        "corruption_detected",
        json!(false),
        json!(import_result.is_ok()),
        import_result.is_err(),
    );
    assert!(import_result.is_err(), "Corrupted bundle import must fail");

    // Verify intact file still works
    let intact_contents =
        fs::read_to_string(&bundle_file_path).expect("reading intact bundle should succeed");

    let intact_import: ReplayBundle =
        serde_json::from_str(&intact_contents).expect("intact bundle import must succeed");

    let intact_valid = validate_bundle_integrity(&intact_import)
        .expect("validate_bundle_integrity should succeed");
    assert!(intact_valid, "Intact bundle must pass integrity validation");

    logger.log_assertion(
        "intact_bundle_valid",
        json!(true),
        json!(intact_valid),
        intact_valid,
    );

    logger.log_test_complete("passed", 2);
}
