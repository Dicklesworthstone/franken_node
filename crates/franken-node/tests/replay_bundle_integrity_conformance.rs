use frankenengine_node::tools::replay_bundle::{
    RawEvent, ReplayBundle, generate_replay_bundle, to_canonical_json, validate_bundle_integrity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

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
