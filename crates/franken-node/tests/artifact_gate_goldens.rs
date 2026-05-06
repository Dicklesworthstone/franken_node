use insta::{Settings, assert_json_snapshot};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};

fn repo_root() -> Result<PathBuf, Box<dyn Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| IoError::new(ErrorKind::NotFound, "workspace root").into())
}

fn load_scrubbed_artifact(relative_path: &str) -> Result<Value, Box<dyn Error>> {
    let path = repo_root()?.join(relative_path);
    let raw = std::fs::read_to_string(&path)?;
    let mut value: Value = serde_json::from_str(&raw)?;
    scrub_dynamic_fields(&mut value);
    Ok(sort_value(value))
}

fn scrub_dynamic_fields(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (key, child) in fields.iter_mut() {
                let normalized_key = key.to_ascii_lowercase();
                if is_timestamp_key(&normalized_key) {
                    *child = Value::String("[TIMESTAMP]".to_string());
                } else if normalized_key == "trace_id" {
                    *child = Value::String("[TRACE_ID]".to_string());
                } else if normalized_key.contains("uuid") {
                    *child = Value::String("[UUID]".to_string());
                } else if normalized_key.contains("nonce") {
                    *child = Value::String("[NONCE]".to_string());
                } else {
                    scrub_dynamic_fields(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_dynamic_fields(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn is_timestamp_key(key: &str) -> bool {
    matches!(
        key,
        "timestamp"
            | "generated_at"
            | "generated_at_utc"
            | "last_verified_utc"
            | "discovered_at_utc"
            | "verified_at"
            | "verified_at_utc"
            | "created_at"
            | "created_at_utc"
            | "updated_at"
            | "updated_at_utc"
    ) || key.ends_with("_timestamp")
        || key.ends_with("_time_utc")
        || key.ends_with("_at_utc")
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut sorted = Map::new();
            let mut entries: Vec<_> = fields.into_iter().collect();
            entries.sort_by_key(|(left, _)| left.clone());
            for (key, child) in entries {
                sorted.insert(key, sort_value(child));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_value).collect()),
        scalar => scalar,
    }
}

fn scrubbed_sha256(value: &Value) -> Result<String, serde_json::Error> {
    serde_json::to_string(value).map(|canonical| hex::encode(Sha256::digest(canonical.as_bytes())))
}

fn top_level_keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .map(|fields| fields.keys().cloned().collect())
        .unwrap_or_default()
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn number_field(value: &Value, key: &str) -> Option<Value> {
    value
        .get(key)
        .and_then(Value::as_number)
        .map(|number| Value::Number(number.clone()))
}

fn array_len(value: &Value, key: &str) -> Option<usize> {
    value.get(key).and_then(Value::as_array).map(Vec::len)
}

fn object_len(value: &Value, key: &str) -> Option<usize> {
    value.get(key).and_then(Value::as_object).map(Map::len)
}

fn present_array_counts(value: &Value, keys: &[&str]) -> Value {
    let mut counts = Map::new();
    for key in keys {
        if let Some(count) = array_len(value, key) {
            counts.insert((*key).to_string(), json!(count));
        }
    }
    Value::Object(counts)
}

fn sample_ids(value: &Value, array_key: &str, id_keys: &[&str], limit: usize) -> Vec<String> {
    value
        .get(array_key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    id_keys.iter().find_map(|key| {
                        item.get(*key)
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    })
                })
                .take(limit)
                .collect()
        })
        .unwrap_or_default()
}

fn event_codes(value: &Value) -> Vec<String> {
    value
        .get("event_codes")
        .or_else(|| value.get("required_event_codes"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn artifact_summary(relative_path: &str, value: &Value) -> Result<Value, Box<dyn Error>> {
    let mut sample_ids_by_array = Map::new();
    for array_key in ["vectors", "checks", "inclusion_cases", "prefix_cases"] {
        let ids = sample_ids(
            value,
            array_key,
            &["vector_id", "name", "id", "check", "computation_name"],
            8,
        );
        if !ids.is_empty() {
            sample_ids_by_array.insert(array_key.to_string(), json!(ids));
        }
    }

    Ok(json!({
        "path": relative_path,
        "scrubbed_sha256": scrubbed_sha256(value)?,
        "top_level_keys": top_level_keys(value),
        "schema_version": string_field(value, "schema_version"),
        "bead_id": string_field(value, "bead_id").or_else(|| string_field(value, "bead")),
        "section": string_field(value, "section"),
        "status": string_field(value, "status").or_else(|| string_field(value, "verdict")),
        "array_counts": present_array_counts(
            value,
            &[
                "vectors",
                "test_vectors",
                "cases",
                "inclusion_cases",
                "prefix_cases",
                "checks",
                "required_event_codes",
                "event_codes",
                "error_codes",
                "impl_error_codes",
                "invariants",
                "impl_invariants",
            ],
        ),
        "sample_ids": Value::Object(sample_ids_by_array),
    }))
}

fn canonical_vector_manifest() -> Result<Value, Box<dyn Error>> {
    let artifact_paths = [
        "artifacts/10.14/epoch_key_vectors.json",
        "artifacts/10.14/idempotency_vectors.json",
        "artifacts/10.14/mmr_proof_vectors.json",
        "artifacts/10.14/seed_derivation_vectors.json",
        "artifacts/10.17/capability_artifact_vectors.json",
        "artifacts/10.17/zk_attestation_vectors.json",
        "artifacts/10.18/vef_receipt_schema_vectors.json",
    ];
    let artifacts = artifact_paths
        .iter()
        .map(|path| {
            let value = load_scrubbed_artifact(path)?;
            artifact_summary(path, &value)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let artifact_count = artifacts.len();

    Ok(json!({
        "surface": "canonical-vector-artifact-gate",
        "golden_strategy": "scrub dynamic fields, then hash canonical JSON and snapshot compact manifest",
        "scrubbing_rules": scrubbing_rules(),
        "artifact_count": artifact_count,
        "artifacts": artifacts,
    }))
}

fn benchmark_specs_manifest() -> Result<Value, Box<dyn Error>> {
    let correctness_path = "artifacts/11/benchmark_correctness_contract.json";
    let specs_path = "artifacts/14/benchmark_specs_package.json";
    let correctness = load_scrubbed_artifact(correctness_path)?;
    let specs = load_scrubbed_artifact(specs_path)?;
    let correctness_summary = artifact_summary(correctness_path, &correctness)?;
    let specs_summary = artifact_summary(specs_path, &specs)?;

    let tracks: Vec<_> = specs
        .get("benchmark_tracks")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|track| {
                    json!({
                        "track_id": string_field(track, "track_id"),
                        "weight": number_field(track, "weight"),
                        "metric_count": array_len(track, "metric_ids"),
                        "pass_threshold": number_field(track, "pass_threshold"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(json!({
        "surface": "benchmark-artifact-gates",
        "golden_strategy": "freeze benchmark contract shape, scoring thresholds, track matrix, and scrubbed full-artifact hashes",
        "scrubbing_rules": scrubbing_rules(),
        "benchmark_correctness_contract": {
            "summary": correctness_summary,
            "required_event_codes": event_codes(&correctness),
            "metric_requirement_count": array_len(&correctness, "benchmark_metric_requirements"),
            "correctness_suite_requirement_count": array_len(&correctness, "correctness_suite_requirements"),
            "artifact_path_policy": correctness.get("artifact_path_policy").cloned(),
        },
        "benchmark_specs_package": {
            "summary": specs_summary,
            "spec_version": string_field(&specs, "spec_version"),
            "track_count": array_len(&specs, "benchmark_tracks"),
            "tracks": tracks,
            "dataset_count": array_len(&specs, "datasets"),
            "sample_score_count": object_len(&specs, "sample_scores"),
            "sample_overall_score": number_field(&specs, "sample_overall_score"),
            "scoring_formula": specs.get("scoring_formula").cloned(),
            "release_report_field_count": array_len(&specs, "release_report_fields"),
            "event_codes": event_codes(&specs),
        },
    }))
}

fn corpus_and_replay_manifest() -> Result<Value, Box<dyn Error>> {
    let corpus_path = "artifacts/13/compatibility_corpus_results.json";
    let replay_path = "artifacts/13/replay_coverage_matrix.json";
    let corpus = load_scrubbed_artifact(corpus_path)?;
    let replay = load_scrubbed_artifact(replay_path)?;
    let corpus_summary = artifact_summary(corpus_path, &corpus)?;
    let replay_summary = artifact_summary(replay_path, &replay)?;

    let api_families = corpus
        .get("api_families")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let replay_artifacts: Vec<_> = replay
        .get("replay_artifacts")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    json!({
                        "incident_type": string_field(item, "incident_type"),
                        "artifact_path": string_field(item, "artifact_path"),
                        "deterministic_runs": number_field(item, "deterministic_runs"),
                        "deterministic_match": item.get("deterministic_match").cloned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(json!({
        "surface": "corpus-and-replay-artifact-gates",
        "golden_strategy": "freeze compatibility matrix and replay coverage contract summaries plus scrubbed full-artifact hashes",
        "scrubbing_rules": scrubbing_rules(),
        "compatibility_corpus_results": {
            "summary": corpus_summary,
            "thresholds": corpus.get("thresholds").cloned(),
            "totals": corpus.get("totals").cloned(),
            "bands": corpus.get("bands").cloned(),
            "api_families": api_families,
            "failing_test_ids": sample_ids(&corpus, "failing_tests_tracking", &["test_id"], 16),
            "per_test_result_count": array_len(&corpus, "per_test_results"),
            "event_codes": event_codes(&corpus),
        },
        "replay_coverage_matrix": {
            "summary": replay_summary,
            "minimum_required_coverage_ratio": number_field(&replay, "minimum_required_coverage_ratio"),
            "new_incident_type_sla_days": number_field(&replay, "new_incident_type_sla_days"),
            "required_incident_types": replay.get("required_incident_types").cloned(),
            "coverage_summary": replay.get("coverage_summary").cloned(),
            "replay_artifacts": replay_artifacts,
        },
    }))
}

fn scrubbing_rules() -> Value {
    json!({
        "timestamps": "[TIMESTAMP]",
        "trace_id": "[TRACE_ID]",
        "uuid_keys": "[UUID]",
        "nonce_keys": "[NONCE]",
        "kept_exact": [
            "schema_version",
            "bead_id",
            "expected hashes",
            "thresholds",
            "family names",
            "pass counts",
            "gate verdicts",
        ],
    })
}

#[test]
fn canonical_vector_benchmark_artifact_gate_goldens() -> Result<(), Box<dyn Error>> {
    let canonical_manifest = canonical_vector_manifest()?;
    let benchmark_manifest = benchmark_specs_manifest()?;
    let corpus_manifest = corpus_and_replay_manifest()?;

    let mut settings = Settings::clone_current();
    settings.set_omit_expression(true);
    settings.set_sort_maps(true);

    settings.bind(|| {
        assert_json_snapshot!(
            "artifact_gates_canonical_vectors_manifest",
            canonical_manifest
        );
        assert_json_snapshot!(
            "artifact_gates_benchmark_specs_manifest",
            benchmark_manifest
        );
        assert_json_snapshot!("artifact_gates_corpus_and_replay_manifest", corpus_manifest);
    });

    Ok(())
}
