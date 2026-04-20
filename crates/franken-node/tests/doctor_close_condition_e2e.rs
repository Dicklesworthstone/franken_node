use assert_cmd::Command;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn write_fixture(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture parent directory");
    }
    fs::write(path, contents).expect("fixture file");
}

fn fixture_root() -> TempDir {
    let root = TempDir::new().expect("fixture root");
    write_fixture(
        &root.path().join("Cargo.toml"),
        r#"
[workspace]
members = ["crates/franken-node"]
"#,
    );
    write_fixture(
        &root.path().join("crates/franken-node/Cargo.toml"),
        r#"
[package]
name = "fixture-franken-node"
version = "0.1.0"
edition = "2024"

[dependencies]
frankenengine-engine = { path = "../../../franken_engine/crates/franken-engine" }
frankenengine-extension-host = { path = "../../../franken_engine/crates/franken-extension-host" }
"#,
    );
    write_fixture(
        &root.path().join("crates/franken-node/src/lib.rs"),
        "pub fn fixture() -> bool { true }\n",
    );
    write_fixture(
        &root.path().join("docs/ENGINE_SPLIT_CONTRACT.md"),
        "franken_engine path dependencies MUST NOT be replaced by local engine crates.\n",
    );
    write_fixture(
        &root.path().join("docs/PRODUCT_CHARTER.md"),
        "Dual-oracle close condition requires all dimensions to be green.\n",
    );
    write_fixture(
        &root
            .path()
            .join("artifacts/13/compatibility_corpus_results.json"),
        r#"{
  "corpus": {
    "corpus_version": "compat-corpus-test"
  },
  "thresholds": {
    "overall_pass_rate_min_pct": 95.0
  },
  "totals": {
    "total_test_cases": 100,
    "passed_test_cases": 98,
    "failed_test_cases": 2,
    "errored_test_cases": 0,
    "skipped_test_cases": 0,
    "overall_pass_rate_pct": 98.0
  }
}"#,
    );
    write_fixture(
        &root
            .path()
            .join("artifacts/section/10.N/gate_verdict/bd-1neb_section_gate.json"),
        r#"{
  "gate": "section_10n_verification",
  "checks": [
    {
      "check_id": "10N-ORACLE",
      "name": "Dual-Oracle Close Condition Gate",
      "status": "PASS"
    }
  ]
}"#,
    );
    root
}

fn canonical_json_value(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).expect("scalar serialization")
        }
        Value::Array(items) => {
            let rendered = items
                .iter()
                .map(canonical_json_value)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{rendered}]")
        }
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let rendered = entries
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key serialization"),
                        canonical_json_value(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{rendered}}}")
        }
    }
}

#[test]
fn doctor_close_condition_writes_dual_oracle_receipt() {
    let root = fixture_root();
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(root.path())
        .env(
            "FRANKEN_NODE_CLOSE_CONDITION_TIMESTAMP_UTC",
            "2026-02-21T00:00:00Z",
        )
        .args(["doctor", "close-condition", "--json"])
        .output()
        .expect("doctor close-condition should run");

    assert!(
        output.status.success(),
        "doctor close-condition failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_receipt: Value =
        serde_json::from_slice(&output.stdout).expect("stdout receipt must be JSON");
    let artifact_path = root
        .path()
        .join("artifacts/oracle/close_condition_receipt.json");
    let artifact_receipt: Value =
        serde_json::from_str(&fs::read_to_string(artifact_path).expect("receipt artifact"))
            .expect("artifact receipt must be JSON");

    assert_eq!(stdout_receipt, artifact_receipt);
    assert_eq!(
        stdout_receipt["schema_version"],
        "oracle-close-condition-receipt/v1"
    );
    assert_eq!(stdout_receipt["generated_at_utc"], "2026-02-21T00:00:00Z");
    assert_eq!(stdout_receipt["composite_verdict"], "GREEN");
    assert_eq!(stdout_receipt["L1_product_oracle"]["pass_rate_pct"], 98.0);
    assert_eq!(
        stdout_receipt["L2_engine_boundary_oracle"]["summary"]["failing_checks"],
        0
    );
    assert_eq!(
        stdout_receipt["release_policy_linkage"]["source"],
        "ci_gate_output"
    );

    let mut unsigned_receipt = stdout_receipt.clone();
    unsigned_receipt
        .as_object_mut()
        .expect("receipt must be object")
        .remove("tamper_evidence");
    let expected_hash = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            canonical_json_value(&unsigned_receipt).as_bytes()
        ))
    );
    assert_eq!(stdout_receipt["tamper_evidence"]["sha256"], expected_hash);
}
