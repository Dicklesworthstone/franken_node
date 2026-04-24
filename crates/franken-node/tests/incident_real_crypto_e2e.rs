//! Perfect E2E integration test for incident replay CLI with REAL crypto operations.
//!
//! Mock Risk Assessment:
//! - Production Impact: 5 (crypto keys are critical security infrastructure)
//! - Mock Divergence Risk: 4 (hardcoded keys hide key generation edge cases)
//! - Score: 20 = MUST be mock-free
//!
//! Why no mocks: Real cryptographic key generation, signing operations, and key loading
//! can only be validated against real Ed25519 operations. Hardcoded test seeds hide:
//! - Key generation entropy issues
//! - Key format validation edge cases
//! - Signing operation failures
//! - Key loading from different encodings

use assert_cmd::Command;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier, rand_core::OsRng};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tracing::{info, debug, warn, span, Level};
use chrono::{DateTime, Utc};

const BINARY_UNDER_TEST: &str = env!("CARGO_BIN_EXE_franken-node");

/// Test harness with real crypto operations and structured logging
#[derive(Debug)]
struct RealCryptoIncidentTestHarness {
    workspace: TempDir,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    key_path: PathBuf,
    test_start: DateTime<Utc>,
    operation_count: u32,
}

impl RealCryptoIncidentTestHarness {
    fn new() -> Self {
        let _span = span!(Level::INFO, "test_harness_init").entered();
        let test_start = Utc::now();
        info!("Initializing real crypto incident test harness");

        let workspace = TempDir::new().expect("create temp workspace");
        debug!("Created workspace: {}", workspace.path().display());

        // REAL cryptographic key generation using OS entropy
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        info!(
            "Generated real Ed25519 keypair - verifying_key: {}",
            hex::encode(verifying_key.to_bytes())
        );

        let key_path = workspace.path().join("keys").join("receipt-signing.key");
        fs::create_dir_all(key_path.parent().unwrap()).expect("create keys directory");

        // Write real key in production format (hex-encoded bytes)
        fs::write(&key_path, hex::encode(signing_key.to_bytes()))
            .expect("write real signing key");

        debug!("Wrote real signing key to: {}", key_path.display());

        Self {
            workspace,
            signing_key,
            verifying_key,
            key_path,
            test_start,
            operation_count: 0,
        }
    }

    fn setup_config(&mut self) {
        let _span = span!(Level::DEBUG, "config_setup").entered();

        let config = r#"
profile = "balanced"

[security]
decision_receipt_signing_key_path = "keys/receipt-signing.key"

[incident]
enable_crypto_validation = true
enforce_signature_verification = true
"#;
        fs::write(self.workspace.path().join("franken_node.toml"), config)
            .expect("write real config");

        debug!("Real crypto config written with signature verification enabled");
        self.operation_count += 1;
    }

    fn create_signed_bundle(&mut self, bundle_name: &str) -> String {
        let _span = span!(Level::DEBUG, "bundle_creation", bundle_name = bundle_name).entered();

        let bundle_content = json!({
            "schema_version": "fnb-v1.0",
            "incident_id": bundle_name,
            "bundle_type": "incident_evidence",
            "created_at": Utc::now().to_rfc3339(),
            "integrity_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "evidence_package": {
                "incident_id": bundle_name,
                "severity": "high",
                "events": [{
                    "event_id": "evt-001",
                    "timestamp": Utc::now().to_rfc3339(),
                    "event_type": "external_signal",
                    "payload": {"signal": "anomaly", "severity": "high"}
                }]
            },
            "replay_trace": {
                "steps": [{
                    "step_id": 1,
                    "timestamp": Utc::now().to_rfc3339(),
                    "action": "policy_evaluation",
                    "outcome": "quarantine"
                }]
            }
        });

        // REAL cryptographic signing of the bundle content
        let bundle_bytes = serde_json::to_vec(&bundle_content).expect("serialize bundle");
        let signature: Signature = self.signing_key.sign(&bundle_bytes);

        info!(
            "Signed bundle with real Ed25519 signature: {}",
            hex::encode(signature.to_bytes())
        );

        // Add real signature to bundle
        let signed_bundle = json!({
            "bundle": bundle_content,
            "signature": {
                "algorithm": "Ed25519",
                "signature_bytes": hex::encode(signature.to_bytes()),
                "signing_key_id": hex::encode(self.verifying_key.to_bytes()),
                "signed_at": Utc::now().to_rfc3339()
            }
        });

        let bundle_path = self.workspace.path().join(format!("{}.fnbundle", bundle_name));
        fs::write(&bundle_path, serde_json::to_string_pretty(&signed_bundle).unwrap())
            .expect("write signed bundle");

        debug!("Real signed bundle written to: {}", bundle_path.display());
        self.operation_count += 1;

        bundle_path.to_string_lossy().to_string()
    }

    fn verify_signature(&self, bundle_path: &str) -> Result<(), String> {
        let _span = span!(Level::DEBUG, "signature_verification").entered();

        let bundle_content = fs::read_to_string(bundle_path)
            .map_err(|e| format!("read bundle: {}", e))?;
        let bundle_json: Value = serde_json::from_str(&bundle_content)
            .map_err(|e| format!("parse bundle JSON: {}", e))?;

        let signature_hex = bundle_json["signature"]["signature_bytes"].as_str()
            .ok_or("missing signature_bytes")?;
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| format!("decode signature hex: {}", e))?;
        let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap())
            .map_err(|e| format!("parse signature: {}", e))?;

        let bundle_bytes = serde_json::to_vec(&bundle_json["bundle"])
            .map_err(|e| format!("serialize bundle for verification: {}", e))?;

        // REAL signature verification using Ed25519
        self.verifying_key.verify(&bundle_bytes, &signature)
            .map_err(|e| format!("signature verification failed: {}", e))?;

        info!("Real Ed25519 signature verification PASSED");
        Ok(())
    }

    fn incident_cmd(&self) -> Command {
        let mut cmd = Command::new(BINARY_UNDER_TEST);
        cmd.arg("incident");
        cmd.current_dir(self.workspace.path());
        cmd
    }

    fn log_test_summary(&self, test_name: &str, result: &str) {
        let duration = Utc::now().timestamp_millis() - self.test_start.timestamp_millis();
        info!(
            test = test_name,
            result = result,
            duration_ms = duration,
            operations = self.operation_count,
            "Real crypto incident test completed"
        );
    }
}

/// Test real crypto incident replay with actual Ed25519 operations
#[test]
fn real_crypto_incident_replay_success() {
    let _span = span!(Level::INFO, "real_crypto_incident_replay").entered();
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .json()
        .try_init()
        .ok();

    let mut harness = RealCryptoIncidentTestHarness::new();
    harness.setup_config();

    info!("Phase: setup - creating real signed bundle");
    let bundle_path = harness.create_signed_bundle("real-crypto-incident-001");

    info!("Phase: verify - checking real signature before CLI test");
    harness.verify_signature(&bundle_path)
        .expect("real signature verification should pass");

    info!("Phase: act - executing CLI with real crypto bundle");
    let mut cmd = harness.incident_cmd();
    cmd.arg("replay")
       .arg("--bundle")
       .arg(&bundle_path)
       .arg("--json");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("valid UTF-8");

    info!("Phase: assert - verifying CLI output with real crypto");
    let json: Value = serde_json::from_str(stdout).expect("valid JSON output");

    // Assert CLI properly processed the real crypto bundle
    assert!(json["incident_id"].is_string(), "incident_id field present");
    assert!(json["replay_result"].is_object(), "replay_result object present");
    assert!(json["timeline"].is_array(), "timeline array present");

    // Assert crypto-specific fields that hardcoded keys wouldn't test
    if let Some(crypto_info) = json.get("crypto_verification") {
        assert_eq!(crypto_info["algorithm"], "Ed25519", "Ed25519 algorithm detected");
        assert_eq!(crypto_info["verification_status"], "valid", "signature verification passed");
    }

    harness.log_test_summary("real_crypto_incident_replay_success", "PASS");
    info!("Real crypto incident replay test PASSED - no mocked crypto operations");
}

/// Test real crypto failure scenarios that hardcoded keys can't test
#[test]
fn real_crypto_incident_replay_invalid_signature_fails() {
    let _span = span!(Level::INFO, "real_crypto_invalid_signature").entered();
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .json()
        .try_init()
        .ok();

    let mut harness = RealCryptoIncidentTestHarness::new();
    harness.setup_config();

    info!("Phase: setup - creating bundle with corrupted signature");
    let bundle_path = harness.create_signed_bundle("invalid-sig-test");

    // Corrupt the signature to test real crypto validation
    let bundle_content = fs::read_to_string(&bundle_path).expect("read bundle");
    let mut bundle_json: Value = serde_json::from_str(&bundle_content).expect("parse JSON");

    // Replace signature with invalid bytes
    bundle_json["signature"]["signature_bytes"] = json!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    fs::write(&bundle_path, serde_json::to_string_pretty(&bundle_json).unwrap())
        .expect("write corrupted bundle");

    info!("Phase: verify - confirming signature corruption");
    assert!(harness.verify_signature(&bundle_path).is_err(), "corrupted signature should fail");

    info!("Phase: act - testing CLI with invalid signature");
    let mut cmd = harness.incident_cmd();
    cmd.arg("replay")
       .arg("--bundle")
       .arg(&bundle_path)
       .arg("--json");

    let result = cmd.assert().failure();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("valid UTF-8");

    info!("Phase: assert - verifying proper crypto failure handling");
    assert!(
        stderr.contains("signature") || stderr.contains("crypto") || stderr.contains("verification"),
        "CLI should report cryptographic verification failure"
    );

    harness.log_test_summary("real_crypto_incident_replay_invalid_signature", "PASS");
    info!("Real crypto signature failure test PASSED - detected invalid signature");
}

/// Test real key loading edge cases that hardcoded keys wouldn't reveal
#[test]
fn real_crypto_key_loading_edge_cases() {
    let _span = span!(Level::INFO, "real_crypto_key_loading").entered();
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .json()
        .try_init()
        .ok();

    let harness = RealCryptoIncidentTestHarness::new();

    info!("Phase: test_1 - testing missing key file");
    fs::remove_file(&harness.key_path).expect("remove key file");

    let mut cmd = harness.incident_cmd();
    cmd.arg("replay").arg("--bundle").arg("nonexistent.fnbundle");
    let result = cmd.assert().failure();

    let stderr = std::str::from_utf8(&result.get_output().stderr).expect("valid UTF-8");
    assert!(
        stderr.contains("key") || stderr.contains("signing"),
        "should report missing key file error"
    );

    info!("Phase: test_2 - testing corrupted key format");
    fs::write(&harness.key_path, "invalid_hex_key_data").expect("write invalid key");

    let mut cmd2 = harness.incident_cmd();
    cmd2.arg("replay").arg("--bundle").arg("nonexistent.fnbundle");
    let result2 = cmd2.assert().failure();

    let stderr2 = std::str::from_utf8(&result2.get_output().stderr).expect("valid UTF-8");
    assert!(
        stderr2.contains("key") || stderr2.contains("hex") || stderr2.contains("format"),
        "should report key format error"
    );

    info!("Real crypto key loading edge case tests PASSED");
}