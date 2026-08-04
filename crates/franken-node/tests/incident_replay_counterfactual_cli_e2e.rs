//! Enhanced end-to-end integration tests for incident replay and counterfactual CLI commands.
//!
//! These tests exercise the incident CLI through real subprocess invocation
//! to verify replay, counterfactual, and list functionality with comprehensive
//! error boundary testing.

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use frankenengine_node::supply_chain::artifact_signing::KeyId;
use frankenengine_node::tools::replay_bundle::{
    ReplayBundleSigningMaterial, fixture_incident_events, generate_replay_bundle,
    sign_replay_bundle, write_bundle_to_path_with_trusted_key,
};
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Deterministic test seed shared by the config signing key, the bundle signature
/// and the replay trust anchor so a bundle signed here verifies against the anchor
/// the CLI is given.
const TEST_SIGNING_SEED: [u8; 32] = [0x42_u8; 32];

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

/// Create a genuine, signed, replay-able incident bundle for testing.
///
/// The prior implementation hand-wrote a `schema_version`/`evidence_package`
/// shape that is NOT a `ReplayBundle`, so every replay/counterfactual read
/// failed to deserialize. This builds the bundle through the real prod path
/// (`generate_replay_bundle` + `sign_replay_bundle`), signed with the same
/// deterministic key the workspace config and the replay trust anchor use, so
/// the CLI verifies and replays it deterministically (matched == true).
fn create_test_bundle(workspace: &Path, bundle_name: &str) -> String {
    let bundle_path = workspace.join(format!("{}.fnbundle", bundle_name));

    let events = fixture_incident_events(bundle_name);
    let mut bundle = generate_replay_bundle(bundle_name, &events).expect("generate replay bundle");
    let signing_key = SigningKey::from_bytes(&TEST_SIGNING_SEED);
    let signing_material = ReplayBundleSigningMaterial {
        signing_key: &signing_key,
        key_source: "config",
        signing_identity: "incident-control-plane",
    };
    sign_replay_bundle(&mut bundle, &signing_material).expect("sign replay bundle");
    let trusted_key_id = KeyId::from_verifying_key(&signing_key.verifying_key()).to_string();
    write_bundle_to_path_with_trusted_key(&bundle, &bundle_path, &trusted_key_id)
        .expect("write signed replay bundle");

    bundle_path.to_string_lossy().to_string()
}

/// Write the replay trust anchor (hex-encoded Ed25519 public key of the shared
/// deterministic key) that `incident replay`/`counterfactual` require via
/// `--trusted-public-key`, and return its path as a CLI argument string.
fn setup_trust_anchor(workspace: &Path) -> String {
    let anchor_path = workspace.join("keys/replay-trust-anchor.pub");
    if let Some(parent) = anchor_path.parent() {
        fs::create_dir_all(parent).expect("create trust anchor dir");
    }
    let signing_key = SigningKey::from_bytes(&TEST_SIGNING_SEED);
    fs::write(
        &anchor_path,
        hex::encode(signing_key.verifying_key().to_bytes()),
    )
    .expect("write replay trust anchor");
    anchor_path.to_string_lossy().to_string()
}

/// Create franken_node.toml config for test workspace
fn setup_test_config(workspace: &Path) {
    let config = r#"
profile = "balanced"

[security]
decision_receipt_signing_key_path = "keys/receipt-signing.key"
"#;
    fs::write(workspace.join("franken_node.toml"), config).expect("Write config");

    // Create real ed25519 signing key for decision receipts
    fs::create_dir_all(workspace.join("keys")).expect("Create keys dir");

    // Generate a deterministic signing key for consistent test behavior
    // Note: Using fixed seed for test determinism, not cryptographically random
    let test_seed = [0x42_u8; 32]; // Deterministic test seed
    let signing_key = SigningKey::from_bytes(&test_seed);

    // Write hex-encoded seed bytes as expected by the signing key loader
    fs::write(
        workspace.join("keys/receipt-signing.key"),
        hex::encode(signing_key.to_bytes()),
    )
    .expect("Write signing key");
}

#[test]
fn incident_replay_success() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-001");
    let anchor = setup_trust_anchor(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("replay")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--trusted-public-key")
        .arg(&anchor)
        .arg("--json")
        .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Parse the JSON output
    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    assert!(
        json["incident_id"].is_string(),
        "Expected incident_id field"
    );
    assert!(
        json["replay_result"].is_object(),
        "Expected replay_result object"
    );
    assert!(json["timeline"].is_array(), "Expected timeline array");
}

#[test]
fn incident_replay_missing_bundle_fails() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let anchor = setup_trust_anchor(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("replay")
        .arg("--bundle")
        .arg("nonexistent.fnbundle")
        .arg("--trusted-public-key")
        .arg(&anchor)
        .arg("--json")
        .current_dir(workspace.path());

    let result = cmd.assert().failure();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    assert!(
        stderr.contains("bundle") || stderr.contains("not found"),
        "Expected error about missing bundle: {}",
        stderr
    );
}

#[test]
fn incident_replay_malformed_bundle_fails() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());

    let anchor = setup_trust_anchor(workspace.path());
    let malformed_bundle = workspace.path().join("malformed.fnbundle");
    fs::write(&malformed_bundle, "{invalid json}").expect("Write malformed bundle");

    let mut cmd = incident_cmd();
    cmd.arg("replay")
        .arg("--bundle")
        .arg(&malformed_bundle)
        .arg("--trusted-public-key")
        .arg(&anchor)
        .arg("--json")
        .current_dir(workspace.path());

    let result = cmd.assert().failure();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    // Prod fails closed reading the bundle with `failed reading replay bundle
    // <path>` caused by a `json serialization error: ...` (the deserializer
    // rejects the non-`ReplayBundle` JSON). Assert on that real wording.
    assert!(
        stderr.contains("bundle")
            || stderr.contains("json")
            || stderr.contains("parse")
            || stderr.contains("invalid"),
        "Expected error about malformed bundle: {}",
        stderr
    );
}

#[test]
fn incident_counterfactual_success() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-002");
    let anchor = setup_trust_anchor(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("counterfactual")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--trusted-public-key")
        .arg(&anchor)
        .arg("--policy")
        .arg("strict")
        .arg("--json")
        .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    assert!(
        json["incident_id"].is_string(),
        "Expected incident_id field"
    );
    assert!(
        json["original_policy"].is_string(),
        "Expected original_policy field"
    );
    assert!(
        json["counterfactual_policy"].is_string(),
        "Expected counterfactual_policy field"
    );
    assert!(
        json["decision_deltas"].is_array(),
        "Expected decision_deltas array"
    );
}

#[test]
fn incident_counterfactual_missing_policy_fails() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-003");
    let anchor = setup_trust_anchor(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("counterfactual")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--trusted-public-key")
        .arg(&anchor)
        .arg("--json")
        .current_dir(workspace.path());

    // `--policy` is a required clap arg, so this fails at parse time.
    cmd.assert().failure();
}

#[test]
fn incident_counterfactual_invalid_policy_fails() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-004");
    let anchor = setup_trust_anchor(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("counterfactual")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--trusted-public-key")
        .arg(&anchor)
        .arg("--policy")
        .arg("invalid-policy-name")
        .arg("--json")
        .current_dir(workspace.path());

    let result = cmd.assert().failure();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    assert!(
        stderr.contains("policy") || stderr.contains("invalid"),
        "Expected error about invalid policy: {}",
        stderr
    );
}

#[test]
fn incident_list_empty_workspace() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("list").arg("--json").current_dir(workspace.path());

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
    assert!(
        json["incidents"].is_array(),
        "Expected filtered incidents array"
    );
    assert!(
        json["filters"]["severity"].as_str() == Some("high"),
        "Expected severity filter"
    );
}

#[test]
fn incident_list_human_output() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("list").current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Human-readable output should contain headers or an empty-list message.
    // Prod renders "incident list: no bundles found" on an empty workspace
    // (this exact wording is pinned by a unit test), so match case-insensitively.
    let lower = stdout.to_lowercase();
    assert!(
        lower.contains("incident") || lower.contains("no bundles") || stdout.contains("ID"),
        "Expected human-readable incident list output: {}",
        stdout
    );
}

#[test]
fn incident_replay_human_output() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-005");
    let anchor = setup_trust_anchor(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("replay")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--trusted-public-key")
        .arg(&anchor)
        .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Human-readable output should contain replay information
    assert!(
        stdout.contains("replay") || stdout.contains("timeline") || stdout.contains("step"),
        "Expected human-readable replay output"
    );
}

#[test]
fn incident_counterfactual_human_output() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-006");
    let anchor = setup_trust_anchor(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("counterfactual")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--trusted-public-key")
        .arg(&anchor)
        .arg("--policy")
        .arg("strict")
        .current_dir(workspace.path());

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Human-readable output should contain counterfactual analysis
    assert!(
        stdout.contains("counterfactual") || stdout.contains("policy") || stdout.contains("delta"),
        "Expected human-readable counterfactual output"
    );
}

#[test]
fn incident_replay_with_verbose_logging() {
    let workspace = setup_test_workspace();
    setup_test_config(workspace.path());
    let bundle_path = create_test_bundle(workspace.path(), "test-incident-007");
    let anchor = setup_trust_anchor(workspace.path());

    let mut cmd = incident_cmd();
    cmd.arg("replay")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--trusted-public-key")
        .arg(&anchor)
        .arg("--verbose")
        .arg("--json")
        .current_dir(workspace.path())
        .env("RUST_LOG", "debug");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    // `--verbose` emits an extra diagnostics line on stderr alongside the
    // standard replay-result line.
    assert!(
        stderr.contains("incident replay verbose:"),
        "Expected verbose replay diagnostics on stderr: {}",
        stderr
    );
}

#[test]
fn incident_help_shows_subcommands() {
    let mut cmd = incident_cmd();
    cmd.arg("--help");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    assert!(
        stdout.contains("Incident replay and forensics"),
        "Expected help description"
    );
    assert!(stdout.contains("bundle"), "Expected bundle subcommand");
    assert!(stdout.contains("replay"), "Expected replay subcommand");
    assert!(
        stdout.contains("counterfactual"),
        "Expected counterfactual subcommand"
    );
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
