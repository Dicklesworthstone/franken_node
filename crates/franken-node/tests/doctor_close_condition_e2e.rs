use assert_cmd::Command;
use frankenengine_node::ops::close_condition::MAX_CLOSE_CONDITION_CARGO_FILES;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const CLOSE_CONDITION_RECEIPT_PREIMAGE_DOMAIN: &[u8] = b"close_condition_receipt_v1:";

fn write_fixture(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture parent directory");
    }
    fs::write(path, contents).expect("fixture file");
}

fn write_test_signing_key(
    root: &Path,
    file_name: &str,
    seed_byte: u8,
) -> (std::path::PathBuf, ed25519_dalek::SigningKey) {
    let path = root.join(file_name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("signing key parent directory");
    }
    let seed = [seed_byte; 32];
    fs::write(&path, hex::encode(seed)).expect("signing key seed");
    (path, ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn fixture_root_with_ci_gate(include_ci_gate: bool) -> TempDir {
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
    if include_ci_gate {
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
    }
    root
}

fn fixture_root() -> TempDir {
    fixture_root_with_ci_gate(true)
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
            entries.sort_by_key(|(left, _)| *left);
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

fn close_condition_receipt_signed_preimage(canonical_json: &str) -> Vec<u8> {
    let canonical_len = u64::try_from(canonical_json.len()).unwrap_or(u64::MAX);
    let mut preimage = Vec::with_capacity(
        CLOSE_CONDITION_RECEIPT_PREIMAGE_DOMAIN
            .len()
            .saturating_add(std::mem::size_of::<u64>())
            .saturating_add(canonical_json.len()),
    );
    preimage.extend_from_slice(CLOSE_CONDITION_RECEIPT_PREIMAGE_DOMAIN);
    preimage.extend_from_slice(&canonical_len.to_le_bytes());
    preimage.extend_from_slice(canonical_json.as_bytes());
    preimage
}

#[test]
fn doctor_close_condition_writes_dual_oracle_receipt() {
    let root = fixture_root();
    let (signing_key_path, signing_key) =
        write_test_signing_key(root.path(), ".franken-node/keys/oracle-close.key", 41);
    let signing_key_path = signing_key_path.display().to_string();
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(root.path())
        .env(
            "FRANKEN_NODE_CLOSE_CONDITION_TIMESTAMP_UTC",
            "2026-02-21T00:00:00Z",
        )
        .args([
            "doctor",
            "close-condition",
            "--json",
            "--receipt-signing-key",
            signing_key_path.as_str(),
        ])
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
    let unsigned_canonical = canonical_json_value(&unsigned_receipt);
    let signed_preimage = close_condition_receipt_signed_preimage(&unsigned_canonical);
    let expected_hash = format!("sha256:{}", hex::encode(Sha256::digest(&signed_preimage)));
    assert_eq!(
        stdout_receipt["tamper_evidence"]["hash_scope"],
        "close_condition_receipt_v1_len_prefixed_core"
    );
    assert_eq!(stdout_receipt["tamper_evidence"]["sha256"], expected_hash);

    let signature = &stdout_receipt["tamper_evidence"]["signature"];
    assert_eq!(signature["algorithm"], "ed25519");
    assert_eq!(signature["key_source"], "cli");
    assert_eq!(signature["signing_identity"], "oracle-close-condition");
    assert_eq!(signature["trust_scope"], "oracle_close_condition");
    assert_eq!(
        signature["signed_payload_sha256"],
        expected_hash
            .strip_prefix("sha256:")
            .expect("expected prefixed hash")
    );
    assert_eq!(
        signature["public_key_hex"],
        hex::encode(signing_key.verifying_key().to_bytes())
    );
    assert_eq!(
        signature["key_id"],
        frankenengine_node::supply_chain::artifact_signing::KeyId::from_verifying_key(
            &signing_key.verifying_key()
        )
        .to_string()
    );

    let public_key_bytes: [u8; 32] = hex::decode(
        signature["public_key_hex"]
            .as_str()
            .expect("public key hex"),
    )
    .expect("decode public key")
    .try_into()
    .expect("public key length");
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).expect("verifying key");
    let signature_bytes = hex::decode(signature["signature_hex"].as_str().expect("signature hex"))
        .expect("decode signature");
    frankenengine_verifier_sdk::bundle::verify_ed25519_signature(
        &verifying_key,
        &signed_preimage,
        &signature_bytes,
    )
    .expect("trusted oracle close-condition signature should verify");
    let typed_receipt: frankenengine_node::ops::close_condition::CloseConditionReceipt =
        serde_json::from_value(stdout_receipt.clone()).expect("typed close-condition receipt");
    frankenengine_node::ops::close_condition::verify_close_condition_receipt_signature(
        &typed_receipt,
        signature["key_id"].as_str().expect("key id"),
    )
    .expect("typed close-condition receipt verifier should accept trusted receipt");

    let mut tampered_receipt = unsigned_receipt;
    tampered_receipt["composite_verdict"] = Value::String("RED".to_string());
    let tampered_canonical = canonical_json_value(&tampered_receipt);
    let tampered_preimage = close_condition_receipt_signed_preimage(&tampered_canonical);
    assert!(
        frankenengine_verifier_sdk::bundle::verify_ed25519_signature(
            &verifying_key,
            &tampered_preimage,
            &signature_bytes,
        )
        .is_err(),
        "trusted oracle signature must reject tampered receipt core"
    );
}

#[test]
fn doctor_close_condition_reports_red_when_cargo_scan_exceeds_cap() {
    let root = fixture_root();
    for index in 0..MAX_CLOSE_CONDITION_CARGO_FILES {
        write_fixture(
            &root
                .path()
                .join(format!("overflow/member-{index}/Cargo.toml")),
            &format!(
                "[package]\nname = \"overflow-member-{index}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"
            ),
        );
    }
    let (signing_key_path, _) =
        write_test_signing_key(root.path(), ".franken-node/keys/oracle-close.key", 61);
    let signing_key_path = signing_key_path.display().to_string();
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(root.path())
        .env(
            "FRANKEN_NODE_CLOSE_CONDITION_TIMESTAMP_UTC",
            "2026-02-21T00:00:00Z",
        )
        .args([
            "doctor",
            "close-condition",
            "--json",
            "--receipt-signing-key",
            signing_key_path.as_str(),
        ])
        .output()
        .expect("doctor close-condition should run");

    assert!(
        output.status.success(),
        "doctor close-condition should emit a red receipt instead of aborting: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let receipt: Value =
        serde_json::from_slice(&output.stdout).expect("stdout receipt must be JSON");
    assert_eq!(receipt["composite_verdict"], "RED");
    assert!(
        receipt["failing_dimensions"]
            .as_array()
            .expect("failing dimensions")
            .iter()
            .any(|dimension| dimension.as_str() == Some("L2_engine_boundary_oracle"))
    );
    let checks = receipt["L2_engine_boundary_oracle"]["checks"]
        .as_array()
        .expect("split checks");
    let scan_check = checks
        .iter()
        .find(|check| check["id"].as_str() == Some("SPLIT-PATH-DEPS"))
        .expect("path dependency check");
    assert_eq!(scan_check["status"], "RED");
    assert_eq!(
        scan_check["details"]["error"],
        "close_condition_scan_limit_exceeded"
    );
    assert!(
        scan_check["details"]["detail"]
            .as_str()
            .expect("scan-limit detail")
            .contains("cargo-manifest scan exceeded limit")
    );
    assert!(
        receipt["L2_engine_boundary_oracle"]["blocking_findings"]
            .as_array()
            .expect("blocking findings")
            .iter()
            .any(|finding| finding.as_str() == Some("SPLIT-PATH-DEPS failed"))
    );
}

#[test]
fn doctor_close_condition_requires_trusted_signing_key() {
    let root = fixture_root();
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(root.path())
        .env_remove("FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH")
        .args(["doctor", "close-condition", "--json"])
        .output()
        .expect("doctor close-condition should run");

    assert!(
        !output.status.success(),
        "doctor close-condition should fail closed without a trusted key"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no signing key was configured"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn doctor_close_condition_fails_closed_when_release_policy_ci_output_is_missing() {
    let root = fixture_root_with_ci_gate(false);
    let (signing_key_path, _) =
        write_test_signing_key(root.path(), ".franken-node/keys/oracle-close.key", 52);
    let signing_key_path = signing_key_path.display().to_string();
    let receipt_path = root
        .path()
        .join("artifacts/oracle/close_condition_receipt.json");
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(root.path())
        .env(
            "FRANKEN_NODE_CLOSE_CONDITION_TIMESTAMP_UTC",
            "2026-02-21T00:00:00Z",
        )
        .args([
            "doctor",
            "close-condition",
            "--json",
            "--receipt-signing-key",
            signing_key_path.as_str(),
        ])
        .output()
        .expect("doctor close-condition should run");

    assert!(
        !output.status.success(),
        "doctor close-condition should fail closed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed generating close-condition receipt"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        stderr.contains("release-policy CI output not accessible"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !stderr.contains("placeholder_schema"),
        "stderr should not mention placeholder linkage fallback: {stderr}"
    );
    assert!(
        !receipt_path.exists(),
        "close-condition receipt must not be emitted without release-policy data"
    );
    assert!(
        output.stdout.is_empty(),
        "stdout should remain empty on fail-closed linkage outage: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
