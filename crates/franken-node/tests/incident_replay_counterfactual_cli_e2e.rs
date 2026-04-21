//! Enhanced end-to-end integration tests for incident replay and counterfactual CLI commands.
//!
//! These tests exercise the incident CLI through real subprocess invocation
//! to verify replay, counterfactual, and list functionality with comprehensive
//! error boundary testing.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const BINARY_UNDER_TEST: &str = env!("CARGO_BIN_EXE_franken-node");

/// Test helper to create a temporary workspace for incident operations
fn setup_test_workspace() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

/// Test helper to run incident commands with standard arguments
fn incident_cmd() -> Command {
    let mut cmd = Command::new(BINARY_UNDER_TEST);
    cmd.arg("incident");
    cmd
}

/// Create a minimal valid incident bundle for testing
fn create_test_bundle(workspace: &Path, bundle_name: &str) -> String {
    let bundle_path = workspace.join(format!("{}.fnbundle", bundle_name));

    // Create minimal bundle structure - this would need to match the actual format
    let bundle_content = serde_json::json!({
        "schema_version": "fnb-v1.0",
        "incident_id": bundle_name,
        "bundle_type": "incident_evidence",
        "created_at": "2026-04-21T17:00:00.000Z",
        "integrity_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "evidence_package": {
            "incident_id": bundle_name,
            "severity": "high",
            "events": [
                {
                    "event_id": "evt-001",
                    "timestamp": "2026-04-21T16:59:00.000Z",
                    "event_type": "external_signal",
                    "payload": {"signal": "anomaly", "severity": "high"}
                }
            ]
        },
        "replay_trace": {
            "steps": [
                {
                    "step_id": 1,
                    "timestamp": "2026-04-21T16:59:01.000Z",
                    "action": "policy_evaluation",
                    "outcome": "quarantine"
                }
            ]
        }
    });

    fs::write(&bundle_path, serde_json::to_string_pretty(&bundle_content).unwrap())
        .expect("Write test bundle");

    bundle_path.to_string_lossy().to_string()
}

/// Create franken_node.toml config for test workspace
fn setup_test_config(workspace: &Path) {
    let config = r#"
profile = "balanced"

[security]
decision_receipt_signing_key_path = "keys/receipt-signing.key"
"#;
    fs::write(workspace.join("franken_node.toml"), config).expect("Write config");

    // Create dummy signing key
    fs::create_dir_all(workspace.join("keys")).expect("Create keys dir");
    fs::write(
        workspace.join("keys/receipt-signing.key"),
        hex::encode([42_u8; 32])
    ).expect("Write signing key");
}

#[test]
fn incident_replay_success() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-001");

    let mut cmd = incident_cmd();
    cmd.arg("replay")
       .arg("--bundle")
       .arg(&bundle_path)
       .arg("--json")
       .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Parse the JSON output
    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    assert!(json["incident_id"].is_string(), "Expected incident_id field");
    assert!(json["replay_result"].is_object(), "Expected replay_result object");
    assert!(json["timeline"].is_array(), "Expected timeline array");
}

#[test]
fn incident_replay_missing_bundle_fails() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("replay")
       .arg("--bundle")
       .arg("nonexistent.fnbundle")
       .arg("--json")
       .current_dir(workspace.path());

    let result = cmd.assert().failure();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    assert!(stderr.contains("bundle") || stderr.contains("not found"),
            "Expected error about missing bundle: {}", stderr);
}

#[test]
fn incident_replay_malformed_bundle_fails() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());

    let malformed_bundle = workspace.path().join("malformed.fnbundle");
    fs::write(&malformed_bundle, "{invalid json}").expect("Write malformed bundle");

    let mut cmd = incident_cmd();
    cmd.arg("replay")
       .arg("--bundle")
       .arg(malformed_bundle.to_string_lossy())
       .arg("--json")
       .current_dir(workspace.path());

    let result = cmd.assert().failure();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    assert!(stderr.contains("parse") || stderr.contains("invalid"),
            "Expected error about malformed bundle: {}", stderr);
}

#[test]
fn incident_counterfactual_success() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-002");

    let mut cmd = incident_cmd();
    cmd.arg("counterfactual")
       .arg("--bundle")
       .arg(&bundle_path)
       .arg("--policy")
       .arg("legacy-risky")
       .arg("--json")
       .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    assert!(json["incident_id"].is_string(), "Expected incident_id field");
    assert!(json["original_policy"].is_string(), "Expected original_policy field");
    assert!(json["counterfactual_policy"].is_string(), "Expected counterfactual_policy field");
    assert!(json["decision_deltas"].is_array(), "Expected decision_deltas array");
}

#[test]
fn incident_counterfactual_missing_policy_fails() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-003");

    let mut cmd = incident_cmd();
    cmd.arg("counterfactual")
       .arg("--bundle")
       .arg(&bundle_path)
       .arg("--json")
       .current_dir(workspace.path());

    cmd.assert().failure();
}

#[test]
fn incident_counterfactual_invalid_policy_fails() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-004");

    let mut cmd = incident_cmd();
    cmd.arg("counterfactual")
       .arg("--bundle")
       .arg(&bundle_path)
       .arg("--policy")
       .arg("invalid-policy-name")
       .arg("--json")
       .current_dir(workspace.path());

    let result = cmd.assert().failure();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    assert!(stderr.contains("policy") || stderr.contains("invalid"),
            "Expected error about invalid policy: {}", stderr);
}

#[test]
fn incident_list_empty_workspace() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("list")
       .arg("--json")
       .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");
    assert!(json["incidents"].is_array(), "Expected incidents array");

    let incidents = json["incidents"].as_array().unwrap();
    assert_eq!(incidents.len(), 0, "Expected empty incident list");
}

#[test]
fn incident_list_with_filter() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("list")
       .arg("--severity")
       .arg("high")
       .arg("--json")
       .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");
    assert!(json["incidents"].is_array(), "Expected filtered incidents array");
    assert!(json["filters"]["severity"].as_str() == Some("high"), "Expected severity filter");
}

#[test]
fn incident_list_human_output() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("list")
       .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Human-readable output should contain headers or empty message
    assert!(stdout.contains("Incident") || stdout.contains("No incidents") || stdout.contains("ID"),
            "Expected human-readable incident list output");
}

#[test]
fn incident_replay_human_output() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-005");

    let mut cmd = incident_cmd();
    cmd.arg("replay")
       .arg("--bundle")
       .arg(&bundle_path)
       .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Human-readable output should contain replay information
    assert!(stdout.contains("replay") || stdout.contains("timeline") || stdout.contains("step"),
            "Expected human-readable replay output");
}

#[test]
fn incident_counterfactual_human_output() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-006");

    let mut cmd = incident_cmd();
    cmd.arg("counterfactual")
       .arg("--bundle")
       .arg(&bundle_path)
       .arg("--policy")
       .arg("strict")
       .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Human-readable output should contain counterfactual analysis
    assert!(stdout.contains("counterfactual") || stdout.contains("policy") || stdout.contains("delta"),
            "Expected human-readable counterfactual output");
}

#[test]
fn incident_replay_with_verbose_logging() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-007");

    let mut cmd = incident_cmd();
    cmd.arg("replay")
       .arg("--bundle")
       .arg(&bundle_path)
       .arg("--verbose")
       .arg("--json")
       .current_dir(workspace.path())
       .env("RUST_LOG", "debug");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    // Should contain detailed logging output when verbose is enabled
    // The exact format depends on the implementation
}

#[test]
fn incident_help_shows_subcommands() {
    let mut cmd = incident_cmd();
    cmd.arg("--help");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    assert!(stdout.contains("Incident replay and forensics"), "Expected help description");
    assert!(stdout.contains("bundle"), "Expected bundle subcommand");
    assert!(stdout.contains("replay"), "Expected replay subcommand");
    assert!(stdout.contains("counterfactual"), "Expected counterfactual subcommand");
    assert!(stdout.contains("list"), "Expected list subcommand");
}

#[test]
fn incident_replay_help_shows_options() {
    let mut cmd = incident_cmd();
    cmd.arg("replay").arg("--help");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    assert!(stdout.contains("--bundle"), "Expected --bundle option");
    assert!(stdout.contains("--json"), "Expected --json option");
}

#[test]
fn incident_counterfactual_help_shows_options() {
    let mut cmd = incident_cmd();
    cmd.arg("counterfactual").arg("--help");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    assert!(stdout.contains("--bundle"), "Expected --bundle option");
    assert!(stdout.contains("--policy"), "Expected --policy option");
    assert!(stdout.contains("--json"), "Expected --json option");
}

#[test]
fn incident_list_help_shows_options() {
    let mut cmd = incident_cmd();
    cmd.arg("list").arg("--help");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    assert!(stdout.contains("--json"), "Expected --json option");
}