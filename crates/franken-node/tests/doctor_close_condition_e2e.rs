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
    // The L2 engine-boundary oracle (`check_engine_path_dependencies` ->
    // `validate_engine_dependency_path`, hardened under bd-3k70d) canonicalizes
    // each declared engine path dependency and requires it to (a) exist on disk
    // and (b) resolve to a directory ending in `franken_engine/crates/<crate>`.
    // The real workspace satisfies this with `../../../franken_engine/...`
    // because the sibling `franken_engine` checkout lives beside `franken_node`.
    // A bare `TempDir` has no such sibling, so we make the fixture self-contained
    // by materializing the engine crate directories INSIDE the TempDir and
    // pointing the path deps at them with a two-segment ascent. This keeps the
    // security check intact (no weakening of the production validator) while
    // making the GREEN fixture independent of the host's `$TMPDIR` layout.
    for engine_crate in ["franken-engine", "franken-extension-host"] {
        fs::create_dir_all(root.path().join("franken_engine/crates").join(engine_crate))
            .expect("fixture engine crate directory");
    }
    write_fixture(
        &root.path().join("crates/franken-node/Cargo.toml"),
        r#"
[package]
name = "fixture-franken-node"
version = "0.1.0"
edition = "2024"

[dependencies]
frankenengine-engine = { path = "../../franken_engine/crates/franken-engine" }
frankenengine-extension-host = { path = "../../franken_engine/crates/franken-extension-host" }
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
    // bd-qr5i2.4: v1 declared-summary acceptance is retired, so the GREEN
    // baseline fixture carries v2 evidence with a genuine re-derivable
    // receipt chain built through the production API.
    write_v2_compatibility_fixture(
        root.path(),
        v2_proof_block(
            &l1_acceptance_chain_entries(),
            serde_json::json!(["fs.read", "fs.write", "http.request"]),
            3,
        ),
    );
    // bd-ry7d1: the gate also consumes the L1 verdict artifact and binds it
    // to the corpus copy, so the GREEN baseline writes both.
    write_bound_l1_verdict_fixture(root.path());
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

fn write_parity_only_compatibility_fixture(root: &Path) {
    write_fixture(
        &root.join("artifacts/13/compatibility_corpus_results.json"),
        r#"{
  "corpus": {
    "corpus_version": "compat-corpus-test"
  },
  "thresholds": {
    "overall_pass_rate_min_pct": 95.0
  },
  "totals": {
    "total_test_cases": 100,
    "passed_test_cases": 100,
    "failed_test_cases": 0,
    "errored_test_cases": 0,
    "skipped_test_cases": 0,
    "overall_pass_rate_pct": 100.0
  }
}"#,
    );
}

/// Proof-carrying host-effect evidence is fully valid (v2, genuine chain),
/// but the compatibility (lockstep parity) corpus is below the required
/// pass-rate threshold. Exercises the `proven-but-parity-RED => FAIL` arm of
/// the acceptance-bar conjunction.
fn write_proof_carrying_but_parity_red_compatibility_fixture(root: &Path) {
    let corpus = serde_json::json!({
        "corpus": { "corpus_version": "compat-corpus-test" },
        "thresholds": { "overall_pass_rate_min_pct": 95.0 },
        "totals": {
            "total_test_cases": 100,
            "passed_test_cases": 90,
            "failed_test_cases": 10,
            "errored_test_cases": 0,
            "skipped_test_cases": 0,
            "overall_pass_rate_pct": 90.0
        },
        "proof_carrying_effects": v2_proof_block(
            &l1_acceptance_chain_entries(),
            serde_json::json!(["fs.read", "fs.write", "http.request"]),
            3,
        )
    });
    write_fixture(
        &root.join("artifacts/13/compatibility_corpus_results.json"),
        &serde_json::to_string_pretty(&corpus).expect("corpus fixture render"),
    );
}

/// Neither leg of the conjunction is satisfied: the parity corpus has zero
/// test cases AND there is no proof-carrying host-effect evidence. Exercises the
/// `both-missing => FAIL` arm of the acceptance-bar conjunction.
fn write_unverified_and_unproven_compatibility_fixture(root: &Path) {
    write_fixture(
        &root.join("artifacts/13/compatibility_corpus_results.json"),
        r#"{
  "corpus": {
    "corpus_version": "compat-corpus-test"
  },
  "thresholds": {
    "overall_pass_rate_min_pct": 95.0
  },
  "totals": {
    "total_test_cases": 0,
    "passed_test_cases": 0,
    "failed_test_cases": 0,
    "errored_test_cases": 0,
    "skipped_test_cases": 0,
    "overall_pass_rate_pct": 0.0
  }
}"#,
    );
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

    let mut public_key_bytes = [0_u8; 32];
    hex::decode_to_slice(
        signature["public_key_hex"]
            .as_str()
            .expect("public key hex"),
        &mut public_key_bytes,
    )
    .expect("decode public key");
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).expect("verifying key");
    let mut signature_bytes = [0_u8; 64];
    hex::decode_to_slice(
        signature["signature_hex"].as_str().expect("signature hex"),
        &mut signature_bytes,
    )
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
fn doctor_close_condition_fails_l1_without_proof_carrying_effect_evidence() {
    let root = fixture_root();
    write_parity_only_compatibility_fixture(root.path());
    write_bound_l1_verdict_fixture(root.path());
    let (signing_key_path, _) =
        write_test_signing_key(root.path(), ".franken-node/keys/oracle-close.key", 62);
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
    assert_eq!(receipt["L1_product_oracle"]["verdict"], "RED");
    assert!(
        receipt["failing_dimensions"]
            .as_array()
            .expect("failing dimensions")
            .iter()
            .any(|dimension| dimension.as_str() == Some("L1_product_oracle"))
    );
    assert!(
        receipt["L1_product_oracle"]["blocking_findings"]
            .as_array()
            .expect("L1 blocking findings")
            .iter()
            .any(|finding| finding
                .as_str()
                .is_some_and(|text| text.contains("proof-carrying host-effect evidence missing"))),
        "L1 should fail closed on parity-only evidence: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"])
            .expect("L1 receipt should render")
    );
}

/// Acceptance-bar conjunction, `proven-but-parity-RED => FAIL` arm (bd-f5b04.2.4.1):
/// even with a fully valid proof-carrying host-effect chain, the L1 product oracle
/// must fail closed when the lockstep parity corpus is below threshold. The two legs
/// of the conjunction (parity-GREEN AND proof-carrying) are independently load-bearing.
#[test]
fn doctor_close_condition_fails_l1_when_proof_carrying_but_parity_red() {
    let root = fixture_root();
    write_proof_carrying_but_parity_red_compatibility_fixture(root.path());
    write_bound_l1_verdict_fixture(root.path());
    let (signing_key_path, _) =
        write_test_signing_key(root.path(), ".franken-node/keys/oracle-close.key", 63);
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
    assert_eq!(receipt["L1_product_oracle"]["verdict"], "RED");
    let findings = receipt["L1_product_oracle"]["blocking_findings"]
        .as_array()
        .expect("L1 blocking findings");
    assert!(
        findings.iter().any(|finding| finding
            .as_str()
            .is_some_and(|text| text.contains("pass rate") && text.contains("below required"))),
        "L1 must fail closed on parity-RED even with valid proof-carrying evidence: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"])
            .expect("L1 receipt should render")
    );
    assert!(
        !findings.iter().any(|finding| finding
            .as_str()
            .is_some_and(|text| text.contains("proof-carrying"))),
        "proof-carrying evidence is valid here; only the parity leg should fail: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"])
            .expect("L1 receipt should render")
    );
}

/// Acceptance-bar conjunction, `both-missing => FAIL` arm (bd-f5b04.2.4.1): when the
/// parity corpus carries zero test cases AND proof-carrying host-effect evidence is
/// absent, the L1 product oracle must fail closed and report BOTH missing legs.
#[test]
fn doctor_close_condition_fails_l1_when_both_parity_and_proof_missing() {
    let root = fixture_root();
    write_unverified_and_unproven_compatibility_fixture(root.path());
    write_bound_l1_verdict_fixture(root.path());
    let (signing_key_path, _) =
        write_test_signing_key(root.path(), ".franken-node/keys/oracle-close.key", 64);
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
    assert_eq!(receipt["L1_product_oracle"]["verdict"], "RED");
    let findings = receipt["L1_product_oracle"]["blocking_findings"]
        .as_array()
        .expect("L1 blocking findings");
    assert!(
        findings.iter().any(|finding| finding
            .as_str()
            .is_some_and(|text| text.contains("zero test cases"))),
        "parity leg must fail closed when the corpus is empty: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"])
            .expect("L1 receipt should render")
    );
    assert!(
        findings.iter().any(|finding| finding
            .as_str()
            .is_some_and(|text| text.contains("proof-carrying host-effect evidence missing"))),
        "proof-carrying leg must fail closed when evidence is absent: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"])
            .expect("L1 receipt should render")
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

/// Acceptance-bar event stream, PASS arm (bd-f5b04.2.4.1): with parity AND
/// proof-carrying evidence both verified, `--structured-logs-jsonl` must emit
/// the stable FN-ACCEPT-001 (evaluated) then FN-ACCEPT-002 (PASS) codes on
/// stderr, carrying the operator-supplied trace id.
#[test]
fn doctor_close_condition_structured_logs_emit_acceptance_pass_codes() {
    let root = fixture_root();
    let (signing_key_path, _) =
        write_test_signing_key(root.path(), ".franken-node/keys/oracle-close.key", 71);
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
            "--structured-logs-jsonl",
            "--trace-id",
            "accept-e2e-pass",
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

    let receipt: Value =
        serde_json::from_slice(&output.stdout).expect("stdout receipt must be JSON");
    assert_eq!(receipt["composite_verdict"], "GREEN");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let events: Vec<Value> = stderr
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(|line| serde_json::from_str(line).expect("stderr JSONL event"))
        .collect();
    let codes: Vec<&str> = events
        .iter()
        .filter_map(|event| event["event_code"].as_str())
        .collect();
    assert_eq!(
        codes,
        vec!["FN-ACCEPT-001", "FN-ACCEPT-002"],
        "unexpected acceptance event stream: {stderr}"
    );
    for event in &events {
        assert_eq!(event["trace_id"], "accept-e2e-pass", "{stderr}");
        assert_eq!(event["surface"], "CLI-DOCTOR-CLOSE-CONDITION", "{stderr}");
        assert_eq!(event["timestamp"], "2026-02-21T00:00:00Z", "{stderr}");
    }
    assert_eq!(events[1]["level"], "info", "{stderr}");
}

/// Acceptance-bar event stream, FAIL-CLOSED arm (bd-f5b04.2.4.1): a
/// parity-GREEN-but-unproven operation set must emit FN-ACCEPT-003
/// (fail-closed, naming the failing dimension) plus one FN-ACCEPT-004 per
/// blocking finding — the event stream a SIEM pins to catch a regression
/// that drops proof-carrying receipts while parity stays green.
#[test]
fn doctor_close_condition_structured_logs_emit_fail_closed_codes() {
    let root = fixture_root();
    write_parity_only_compatibility_fixture(root.path());
    write_bound_l1_verdict_fixture(root.path());
    let (signing_key_path, _) =
        write_test_signing_key(root.path(), ".franken-node/keys/oracle-close.key", 72);
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
            "--structured-logs-jsonl",
            "--trace-id",
            "accept-e2e-fail",
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

    let stderr = String::from_utf8_lossy(&output.stderr);
    let events: Vec<Value> = stderr
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(|line| serde_json::from_str(line).expect("stderr JSONL event"))
        .collect();
    let codes: Vec<&str> = events
        .iter()
        .filter_map(|event| event["event_code"].as_str())
        .collect();
    assert_eq!(codes[0], "FN-ACCEPT-001", "{stderr}");
    assert_eq!(codes[1], "FN-ACCEPT-003", "{stderr}");
    assert!(
        codes[2..].iter().all(|code| *code == "FN-ACCEPT-004"),
        "every trailing event must be a blocking finding: {stderr}"
    );
    assert!(
        events[1]["message"]
            .as_str()
            .is_some_and(|message| message.contains("L1_product_oracle")),
        "fail-closed event must name the failing dimension: {stderr}"
    );
    assert_eq!(events[1]["level"], "error", "{stderr}");
    assert!(
        events[2..].iter().any(|event| event["message"]
            .as_str()
            .is_some_and(|message| message.contains("proof-carrying"))),
        "blocking findings must surface the missing proof-carrying leg: {stderr}"
    );
    for event in &events {
        assert_eq!(event["trace_id"], "accept-e2e-fail", "{stderr}");
    }
}

// ── proof_carrying_effects v2: gate re-derives the embedded chain (bd-qr5i2.1) ──

/// Build a REAL effect-receipt chain covering the three L1 acceptance
/// subjects through the production chain API (no hand-written hashes), so
/// the e2e fixtures carry evidence the gate can actually re-derive.
fn l1_acceptance_chain_entries()
-> Vec<frankenengine_node::runtime::effect_receipt::EffectReceiptChainEntry> {
    use frankenengine_node::runtime::effect_receipt::{
        EffectKind, EffectReceipt, EffectReceiptChain,
    };
    use frankenengine_node::storage::cas::content_hash;

    let mut chain = EffectReceiptChain::new();
    for (seq, kind) in [
        (0_u64, EffectKind::FsRead),
        (1, EffectKind::FsWrite),
        (2, EffectKind::HttpRequest),
    ] {
        let receipt = EffectReceipt::allowed(
            seq,
            "acceptance-evidence-v2-e2e",
            kind,
            "cap-l1-acceptance",
            content_hash(b"pre-state"),
            content_hash(b"args"),
            content_hash(b"result"),
            content_hash(b"post-state"),
            1_774_000_000_000,
        );
        chain.append(receipt).expect("append acceptance receipt");
    }
    chain.entries().to_vec()
}

/// bd-qr5i2.3: cross-language parity pin. The Python CI gate
/// (`scripts/check_oracle_close_condition.py`) re-implements the canonical
/// receipt/chain hash preimages so it can re-derive v2 evidence
/// independently. Both implementations must produce EXACTLY these constants
/// for the deterministic chain built by `l1_acceptance_chain_entries` — the
/// same constants are asserted by
/// `tests/test_check_oracle_close_condition.py::test_parity_pin_hashes`, so
/// any preimage drift breaks exactly one suite immediately and names the
/// divergent side.
#[test]
fn effect_receipt_hash_cross_language_parity_pin_bd_qr5i2_3() {
    let entries = l1_acceptance_chain_entries();
    assert_eq!(
        entries[0].receipt_hash,
        "sha256:4c95c6f0ba9a43d07dbf8646b3876e1588873165b1ee91862490fc4bf4939979",
        "receipt-hash preimage drifted from the Python gate's implementation"
    );
    assert_eq!(
        entries[2].chain_hash,
        "sha256:ff29fcb4bbbff4bcd338d6b7bdaa2a9f137de11990190aebc841feb034c1b3c1",
        "chain-hash preimage drifted from the Python gate's implementation"
    );
}

/// Write a green-parity corpus fixture whose `proof_carrying_effects` block
/// is the supplied v2 evidence object.
fn write_v2_compatibility_fixture(root: &Path, proof_carrying_effects: Value) {
    let corpus = serde_json::json!({
        "corpus": { "corpus_version": "compat-corpus-test" },
        "thresholds": { "overall_pass_rate_min_pct": 95.0 },
        "totals": {
            "total_test_cases": 100,
            "passed_test_cases": 98,
            "failed_test_cases": 2,
            "errored_test_cases": 0,
            "skipped_test_cases": 0,
            "overall_pass_rate_pct": 98.0
        },
        "proof_carrying_effects": proof_carrying_effects
    });
    write_fixture(
        &root.join("artifacts/13/compatibility_corpus_results.json"),
        &serde_json::to_string_pretty(&corpus).expect("corpus fixture render"),
    );
}

fn v2_proof_block(
    entries: &[frankenengine_node::runtime::effect_receipt::EffectReceiptChainEntry],
    verified_subjects: Value,
    effect_receipts_verified: u64,
) -> Value {
    serde_json::json!({
        "schema_version": "franken-node/l1-proof-carrying-effects/v2",
        "required_subjects": ["fs.read", "fs.write", "http.request"],
        "verified_subjects": verified_subjects,
        "effect_receipts_verified": effect_receipts_verified,
        "invalid_receipts": 0,
        "receipt_chain_verified": true,
        "receipt_chain_entries": entries
    })
}

// ── bd-ry7d1: the L1 verdict artifact (lockstep leg + corpus binding) ──

/// A lockstep verdict block whose embedded report is built through the REAL
/// nversion-oracle API (two distinct runtimes, one agreeing check, zero
/// divergences) — internally consistent, so the gate's re-derivation accepts
/// it.
fn l1_lockstep_verdict_block() -> Value {
    use frankenengine_node::runtime::nversion_oracle::{
        BoundaryScope, RuntimeEntry, RuntimeOracle,
    };

    let mut oracle = RuntimeOracle::new("l1-lockstep:doctor-e2e", 100);
    oracle
        .register_runtime(RuntimeEntry {
            runtime_id: "bun".to_string(),
            runtime_name: "bun".to_string(),
            version: "1.0-fixture".to_string(),
            is_reference: true,
        })
        .expect("register bun leg");
    oracle
        .register_runtime(RuntimeEntry {
            runtime_id: "franken-engine-native".to_string(),
            runtime_name: "franken-engine-native".to_string(),
            version: "0.1-fixture".to_string(),
            is_reference: false,
        })
        .expect("register franken leg");
    let mut outputs = std::collections::BTreeMap::new();
    outputs.insert("bun".to_string(), b"l1-lockstep:ok\n".to_vec());
    outputs.insert(
        "franken-engine-native".to_string(),
        b"l1-lockstep:ok\n".to_vec(),
    );
    oracle
        .run_cross_check(
            "l1-lockstep:doctor-e2e:check-0",
            BoundaryScope::IO,
            b"guest-src",
            &outputs,
        )
        .expect("cross check");
    let report = oracle.generate_report(1_774_000_000);
    serde_json::json!({
        "schema_version": "franken-node/l1-lockstep-verdict/v1",
        "trace_id": report.trace_id,
        "produced_at": "2026-07-10T00:00:00+00:00",
        "producer": "doctor-close-condition-e2e",
        "guest_program_content_hash":
            frankenengine_node::storage::cas::content_hash(b"guest-src").as_str(),
        "runtimes": report.runtimes.keys().cloned().collect::<Vec<_>>(),
        "oracle_verdict": report.verdict.label(),
        "checks_total": report.checks.len(),
        "divergence_count": report.divergences.len(),
        "report": report,
    })
}

/// Write the L1 product verdict artifact BOUND to the current corpus fixture:
/// its `proof_carrying_effects` copy is read back from
/// `artifacts/13/compatibility_corpus_results.json`, so the gate's cross-file
/// binding holds by construction. Call after (re)writing the corpus fixture.
fn write_bound_l1_verdict_fixture(root: &Path) {
    let corpus: Value = serde_json::from_str(
        &fs::read_to_string(root.join("artifacts/13/compatibility_corpus_results.json"))
            .expect("corpus fixture must exist before binding the verdict artifact"),
    )
    .expect("parse corpus fixture");
    let mut evidence = serde_json::Map::new();
    if let Some(proof) = corpus.get("proof_carrying_effects") {
        evidence.insert("proof_carrying_effects".to_string(), proof.clone());
    }
    evidence.insert("lockstep_verdict".to_string(), l1_lockstep_verdict_block());
    let artifact = serde_json::json!({
        "dimension": "l1_product",
        "verdict": "GREEN",
        "owner_track": "10.2",
        "timestamp": "2026-07-10T00:00:00+00:00",
        "evidence": Value::Object(evidence),
    });
    write_fixture(
        &root.join("artifacts/oracle/l1_product_verdict.json"),
        &serde_json::to_string_pretty(&artifact).expect("render verdict artifact"),
    );
}

fn run_close_condition_receipt(root: &Path, seed: u8) -> Value {
    let (signing_key_path, _) =
        write_test_signing_key(root, ".franken-node/keys/oracle-close.key", seed);
    let signing_key_path = signing_key_path.display().to_string();
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(root)
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
        "doctor close-condition should emit a receipt instead of aborting: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout receipt must be JSON")
}

fn l1_blocking_findings_contain(receipt: &Value, needle: &str) -> bool {
    receipt["L1_product_oracle"]["blocking_findings"]
        .as_array()
        .expect("L1 blocking findings")
        .iter()
        .any(|finding| finding.as_str().is_some_and(|text| text.contains(needle)))
}

/// bd-qr5i2.4: v1 declared-summary evidence is retired — a fully-populated
/// v1 block that used to pass now fails closed with an unsupported-schema
/// finding pointing the operator at the producer CLI.
#[test]
fn doctor_close_condition_refuses_retired_v1_evidence() {
    let root = fixture_root();
    write_v2_compatibility_fixture(
        root.path(),
        serde_json::json!({
            "schema_version": "franken-node/l1-proof-carrying-effects/v1",
            "required_subjects": ["fs.read", "fs.write", "http.request"],
            "verified_subjects": ["fs.read", "fs.write", "http.request"],
            "effect_receipts_verified": 3,
            "invalid_receipts": 0,
            "receipt_chain_verified": true
        }),
    );
    write_bound_l1_verdict_fixture(root.path());
    let receipt = run_close_condition_receipt(root.path(), 77);
    assert_eq!(receipt["composite_verdict"], "RED");
    assert_eq!(receipt["L1_product_oracle"]["verdict"], "RED");
    assert!(
        l1_blocking_findings_contain(&receipt, "is unsupported"),
        "retired v1 evidence must fail closed with the unsupported-schema finding: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
}

/// GREEN arm: v2 evidence with a genuine, re-derivable receipt chain covering
/// all three acceptance subjects passes the gate end-to-end.
#[test]
fn doctor_close_condition_passes_l1_with_v2_rederived_receipt_chain() {
    let root = fixture_root();
    let entries = l1_acceptance_chain_entries();
    write_v2_compatibility_fixture(
        root.path(),
        v2_proof_block(
            &entries,
            serde_json::json!(["fs.read", "fs.write", "http.request"]),
            3,
        ),
    );
    write_bound_l1_verdict_fixture(root.path());
    let receipt = run_close_condition_receipt(root.path(), 71);
    assert_eq!(
        receipt["composite_verdict"],
        "GREEN",
        "v2 evidence with a valid re-derived chain must be GREEN: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
    assert_eq!(receipt["L1_product_oracle"]["verdict"], "GREEN");
}

/// Tamper arm: flipping one recorded receipt hash breaks re-derivation even
/// though every declared summary field still claims success.
#[test]
fn doctor_close_condition_fails_l1_when_v2_chain_entry_tampered() {
    let root = fixture_root();
    let mut entries = l1_acceptance_chain_entries();
    let mut tampered = entries[1].receipt_hash.clone();
    let flipped = if tampered.ends_with('0') { '1' } else { '0' };
    tampered.pop();
    tampered.push(flipped);
    entries[1].receipt_hash = tampered;
    write_v2_compatibility_fixture(
        root.path(),
        v2_proof_block(
            &entries,
            serde_json::json!(["fs.read", "fs.write", "http.request"]),
            3,
        ),
    );
    write_bound_l1_verdict_fixture(root.path());
    let receipt = run_close_condition_receipt(root.path(), 72);
    assert_eq!(receipt["composite_verdict"], "RED");
    assert_eq!(receipt["L1_product_oracle"]["verdict"], "RED");
    assert!(
        l1_blocking_findings_contain(&receipt, "failed re-derivation"),
        "tampered chain must surface a re-derivation finding: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
}

/// Mismatch arm: the chain is genuine but the declared summary overstates the
/// verified receipt count — the gate must refuse the artifact that lies about
/// its own evidence.
#[test]
fn doctor_close_condition_fails_l1_when_v2_declared_count_inflated() {
    let root = fixture_root();
    let entries = l1_acceptance_chain_entries();
    write_v2_compatibility_fixture(
        root.path(),
        v2_proof_block(
            &entries,
            serde_json::json!(["fs.read", "fs.write", "http.request"]),
            4,
        ),
    );
    write_bound_l1_verdict_fixture(root.path());
    let receipt = run_close_condition_receipt(root.path(), 73);
    assert_eq!(receipt["composite_verdict"], "RED");
    assert!(
        l1_blocking_findings_contain(&receipt, "does not match re-derived 3"),
        "inflated declared count must surface a mismatch finding: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
}

/// Missing-subject arm: an honestly-declared chain that only covers the fs
/// subjects still fails the acceptance requirements on the derived values.
#[test]
fn doctor_close_condition_fails_l1_when_v2_chain_missing_http_subject() {
    use frankenengine_node::runtime::effect_receipt::{
        EffectKind, EffectReceipt, EffectReceiptChain,
    };
    use frankenengine_node::storage::cas::content_hash;

    let root = fixture_root();
    let mut chain = EffectReceiptChain::new();
    for (seq, kind) in [(0_u64, EffectKind::FsRead), (1, EffectKind::FsWrite)] {
        let receipt = EffectReceipt::allowed(
            seq,
            "acceptance-evidence-v2-e2e",
            kind,
            "cap-l1-acceptance",
            content_hash(b"pre-state"),
            content_hash(b"args"),
            content_hash(b"result"),
            content_hash(b"post-state"),
            1_774_000_000_000,
        );
        chain.append(receipt).expect("append acceptance receipt");
    }
    write_v2_compatibility_fixture(
        root.path(),
        v2_proof_block(
            chain.entries(),
            serde_json::json!(["fs.read", "fs.write"]),
            2,
        ),
    );
    write_bound_l1_verdict_fixture(root.path());
    let receipt = run_close_condition_receipt(root.path(), 74);
    assert_eq!(receipt["composite_verdict"], "RED");
    assert!(
        l1_blocking_findings_contain(&receipt, "missing subject http.request"),
        "missing http.request evidence must fail closed: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
    assert!(
        l1_blocking_findings_contain(&receipt, "below required 3"),
        "derived receipt count below the floor must fail closed: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
}

// ── bd-qr5i2.2: real-run producer → re-deriving v2 gate, the full loop ──

/// The evidence produced by a REAL native-engine run (one guest program
/// performing fs.write + fs.read + http.request against a loopback sink)
/// passes the re-deriving v2 gate end to end: producer → corpus artifact →
/// `doctor close-condition` GREEN. No hand-authored receipts anywhere in the
/// loop — this closes the evidence loop that bd-qr5i2.1 opened on the gate
/// side.
#[test]
#[cfg(feature = "engine")]
fn real_run_producer_evidence_passes_v2_close_condition_gate() {
    let evidence =
        frankenengine_node::ops::proof_carrying_evidence::produce_proof_carrying_effects_evidence()
            .expect("producer must emit verified evidence from a real run");

    assert_eq!(
        evidence.schema_version,
        "franken-node/l1-proof-carrying-effects/v2"
    );
    assert_eq!(
        evidence.verified_subjects,
        vec!["fs.read", "fs.write", "http.request"],
        "the producer run must evidence every acceptance subject"
    );
    assert!(evidence.receipt_chain_verified);
    assert_eq!(evidence.invalid_receipts, 0);
    assert!(evidence.effect_receipts_verified >= 3);

    let root = fixture_root();
    write_v2_compatibility_fixture(
        root.path(),
        serde_json::to_value(&evidence).expect("serialize producer evidence"),
    );
    write_bound_l1_verdict_fixture(root.path());
    let receipt = run_close_condition_receipt(root.path(), 75);
    assert_eq!(
        receipt["composite_verdict"],
        "GREEN",
        "real-run producer evidence must re-derive GREEN at the gate: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
    assert_eq!(receipt["L1_product_oracle"]["verdict"], "GREEN");
}

/// Verifier-SDK parity: an external auditor re-derives the producer's effect
/// chain offline from the emitted `receipt_chain_entries` alone, using the
/// public verifier SDK — no trust in the producing runtime.
#[test]
#[cfg(feature = "engine")]
fn real_run_producer_evidence_chain_verifies_via_verifier_sdk() {
    let evidence =
        frankenengine_node::ops::proof_carrying_evidence::produce_proof_carrying_effects_evidence()
            .expect("producer must emit verified evidence from a real run");

    let entries_json = serde_json::to_string(&evidence.receipt_chain_entries)
        .expect("serialize producer chain entries");
    let sdk_entries: Vec<frankenengine_verifier_sdk::bundle::EffectReceiptChainEntry> =
        serde_json::from_str(&entries_json)
            .expect("verifier SDK accepts the producer evidence wire shape");
    let sdk = frankenengine_verifier_sdk::VerifierSdk::new("verifier://bd-qr5i2-2-producer");
    let verdict = sdk
        .verify_effect_chain_entries(&sdk_entries)
        .expect("verifier SDK re-derives the producer effect chain offline");
    assert_eq!(
        u64::try_from(verdict.effect_count).expect("effect count fits u64"),
        evidence.effect_receipts_verified,
        "every producer receipt is an allowed acceptance-subject effect"
    );
}

/// The operator-facing CLI loop: `ops proof-carrying-evidence --merge-corpus`
/// replaces a stale v1 block in the corpus artifact with real v2 evidence,
/// and `doctor close-condition` then re-derives GREEN from it. This is the
/// exact flow slice bd-qr5i2.4 will use to regenerate the committed artifact.
#[test]
#[cfg(feature = "engine")]
fn ops_proof_carrying_evidence_cli_merges_corpus_and_gate_passes() {
    let root = fixture_root(); // corpus starts with the legacy v1 block

    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(root.path())
        .args([
            "ops",
            "proof-carrying-evidence",
            "--merge-corpus",
            "artifacts/13/compatibility_corpus_results.json",
            "--json",
        ])
        .output()
        .expect("ops proof-carrying-evidence should run");
    assert!(
        output.status.success(),
        "producer CLI must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let emitted: Value =
        serde_json::from_slice(&output.stdout).expect("producer CLI stdout must be JSON");
    assert_eq!(
        emitted["schema_version"], "franken-node/l1-proof-carrying-effects/v2",
        "producer CLI must emit the v2 evidence block"
    );

    let merged: Value = serde_json::from_str(
        &fs::read_to_string(
            root.path()
                .join("artifacts/13/compatibility_corpus_results.json"),
        )
        .expect("read merged corpus"),
    )
    .expect("parse merged corpus");
    assert_eq!(
        merged["proof_carrying_effects"]["schema_version"],
        "franken-node/l1-proof-carrying-effects/v2",
        "the corpus artifact must now carry the v2 block"
    );
    assert_eq!(
        merged["totals"]["total_test_cases"], 100,
        "merging must preserve the parity totals"
    );

    // bd-ry7d1: the corpus now carries FRESH producer evidence while the
    // fixture's verdict artifact still holds the baseline copy — rebind so
    // the cross-file binding reflects an operator who regenerated both.
    write_bound_l1_verdict_fixture(root.path());
    let receipt = run_close_condition_receipt(root.path(), 76);
    assert_eq!(
        receipt["composite_verdict"],
        "GREEN",
        "CLI-merged real evidence must re-derive GREEN at the gate: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
}

// ── bd-ry7d1: verdict-artifact consumption, corpus binding, lockstep CLI ──

/// Without the L1 verdict artifact (the file the Python CI gate reads), the
/// Rust gate fails closed — the two gates consume one input set now.
#[test]
fn doctor_close_condition_fails_l1_when_verdict_artifact_unreadable() {
    let root = fixture_root();
    write_fixture(
        &root.path().join("artifacts/oracle/l1_product_verdict.json"),
        "not json",
    );
    let receipt = run_close_condition_receipt(root.path(), 81);
    assert_eq!(receipt["composite_verdict"], "RED");
    assert_eq!(receipt["L1_product_oracle"]["verdict"], "RED");
    assert!(
        l1_blocking_findings_contain(&receipt, "L1 verdict artifact unreadable"),
        "gate must fail closed when the verdict artifact cannot be read: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
}

/// The cross-file binding: a verdict artifact whose proof-carrying copy has
/// drifted from the corpus-results copy fails closed — the two gate inputs
/// can no longer pass while disagreeing.
#[test]
fn doctor_close_condition_fails_l1_when_gate_inputs_drift() {
    let root = fixture_root();
    let path = root.path().join("artifacts/oracle/l1_product_verdict.json");
    let mut artifact: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("verdict artifact"))
            .expect("parse verdict artifact");
    artifact["evidence"]["proof_carrying_effects"]["effect_receipts_verified"] =
        serde_json::json!(99);
    write_fixture(
        &path,
        &serde_json::to_string_pretty(&artifact).expect("render drifted artifact"),
    );
    let receipt = run_close_condition_receipt(root.path(), 82);
    assert_eq!(receipt["composite_verdict"], "RED");
    assert!(
        l1_blocking_findings_contain(&receipt, "does not match the corpus-results copy"),
        "drifted gate inputs must fail closed: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
}

/// A diverged lockstep report — even one whose declared summary is honest —
/// fails the L1 bar end to end.
#[test]
fn doctor_close_condition_fails_l1_when_lockstep_report_diverged() {
    use frankenengine_node::runtime::nversion_oracle::{
        BoundaryScope, RiskTier, RuntimeEntry, RuntimeOracle,
    };

    let mut oracle = RuntimeOracle::new("l1-lockstep:doctor-e2e-diverged", 100);
    for (id, is_reference) in [("bun", true), ("franken-engine-native", false)] {
        oracle
            .register_runtime(RuntimeEntry {
                runtime_id: id.to_string(),
                runtime_name: id.to_string(),
                version: "test".to_string(),
                is_reference,
            })
            .expect("register runtime");
    }
    let mut outputs = std::collections::BTreeMap::new();
    outputs.insert("bun".to_string(), b"left\n".to_vec());
    outputs.insert("franken-engine-native".to_string(), b"right\n".to_vec());
    oracle
        .run_cross_check(
            "l1-lockstep:doctor-e2e-diverged:check-0",
            BoundaryScope::IO,
            b"guest-src",
            &outputs,
        )
        .expect("cross check");
    oracle.classify_divergence(
        "l1-lockstep:doctor-e2e-diverged:div-0",
        "l1-lockstep:doctor-e2e-diverged:check-0",
        BoundaryScope::IO,
        RiskTier::High,
        &outputs,
    );
    let report = oracle.generate_report(1_774_000_000);
    let diverged_block = serde_json::json!({
        "schema_version": "franken-node/l1-lockstep-verdict/v1",
        "trace_id": report.trace_id,
        "produced_at": "2026-07-10T00:00:00+00:00",
        "producer": "doctor-close-condition-e2e",
        "guest_program_content_hash":
            frankenengine_node::storage::cas::content_hash(b"guest-src").as_str(),
        "runtimes": report.runtimes.keys().cloned().collect::<Vec<_>>(),
        "oracle_verdict": report.verdict.label(),
        "checks_total": report.checks.len(),
        "divergence_count": report.divergences.len(),
        "report": report,
    });

    let root = fixture_root();
    let path = root.path().join("artifacts/oracle/l1_product_verdict.json");
    let mut artifact: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("verdict artifact"))
            .expect("parse verdict artifact");
    artifact["evidence"]["lockstep_verdict"] = diverged_block;
    write_fixture(
        &path,
        &serde_json::to_string_pretty(&artifact).expect("render diverged artifact"),
    );

    let receipt = run_close_condition_receipt(root.path(), 83);
    assert_eq!(receipt["composite_verdict"], "RED");
    assert!(
        l1_blocking_findings_contain(&receipt, "diverged across runtimes"),
        "diverged lockstep report must fail closed: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
    assert!(
        l1_blocking_findings_contain(&receipt, "not pass"),
        "non-pass re-derived verdict must fail closed: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
}

/// The full bd-ry7d1 operator loop: `ops proof-carrying-evidence
/// --merge-corpus --merge-l1-verdict` runs the REAL native-engine effect run
/// AND a REAL bun-vs-native-engine lockstep-oracle pass, regenerates both
/// gate inputs bound together, and `doctor close-condition` re-derives GREEN.
/// This is the exact command the committed artifacts are regenerated with.
#[test]
#[cfg(feature = "engine")]
fn ops_proof_carrying_evidence_cli_merges_l1_verdict_and_gate_passes() {
    // The lockstep reference leg is a real bun subprocess; without bun this
    // host cannot produce a genuine cross-runtime verdict, so the flow is
    // untestable here (the producer itself fails closed in that case).
    let bun_available = std::process::Command::new("bun")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !bun_available {
        eprintln!(
            "SKIP ops_proof_carrying_evidence_cli_merges_l1_verdict_and_gate_passes: \
             bun is not on PATH; the lockstep reference leg requires it"
        );
        return;
    }

    let root = fixture_root();
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(root.path())
        .args([
            "ops",
            "proof-carrying-evidence",
            "--merge-corpus",
            "artifacts/13/compatibility_corpus_results.json",
            "--merge-l1-verdict",
            "artifacts/oracle/l1_product_verdict.json",
            "--json",
        ])
        .output()
        .expect("ops proof-carrying-evidence should run");
    assert!(
        output.status.success(),
        "producer CLI with --merge-l1-verdict must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let emitted: Value =
        serde_json::from_slice(&output.stdout).expect("producer CLI stdout must be JSON");
    assert_eq!(
        emitted["proof_carrying_effects"]["schema_version"],
        "franken-node/l1-proof-carrying-effects/v2"
    );
    assert_eq!(
        emitted["lockstep_verdict"]["schema_version"],
        "franken-node/l1-lockstep-verdict/v1"
    );
    assert_eq!(emitted["lockstep_verdict"]["oracle_verdict"], "pass");

    let verdict_artifact: Value = serde_json::from_str(
        &fs::read_to_string(root.path().join("artifacts/oracle/l1_product_verdict.json"))
            .expect("read merged verdict artifact"),
    )
    .expect("parse merged verdict artifact");
    assert_eq!(verdict_artifact["verdict"], "GREEN");
    assert_eq!(
        verdict_artifact["evidence"]["lockstep_verdict"]["report"]["verdict"], "Pass",
        "the embedded report must carry a real Pass verdict"
    );

    let receipt = run_close_condition_receipt(root.path(), 84);
    assert_eq!(
        receipt["composite_verdict"],
        "GREEN",
        "regenerated-and-bound gate inputs must re-derive GREEN: {}",
        serde_json::to_string_pretty(&receipt["L1_product_oracle"]).expect("render")
    );
}
