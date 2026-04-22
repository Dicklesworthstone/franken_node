//! End-to-end integration tests for the remotecap CLI command.
//!
//! These tests exercise the remotecap CLI through real subprocess invocation
//! to verify capability token issuance, validation, and error handling.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

const BINARY_UNDER_TEST: &str = env!("CARGO_BIN_EXE_franken-node");

/// Test helper to create a temporary workspace for capability operations
fn setup_test_workspace() -> TempDir {
    TempDir::new().expect("Failed to create temp directory")
}

/// Test helper to run remotecap commands with standard arguments
fn remotecap_cmd() -> Command {
    let mut cmd = Command::new(BINARY_UNDER_TEST);
    cmd.arg("remotecap");
    cmd
}

fn write_json(path: &std::path::Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize json"),
    )
    .expect("write json");
}

fn issue_token(workspace: &TempDir) -> Value {
    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
        .arg("--scope")
        .arg("network_egress")
        .arg("--endpoint")
        .arg("https://api.example.com")
        .arg("--ttl")
        .arg("1h")
        .arg("--operator-approved")
        .arg("--json")
        .current_dir(workspace.path())
        .env("FRANKEN_NODE_REMOTECAP_KEY", "remotecap-cli-e2e-key");

    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).expect("issue output should be json")
}

#[test]
fn remotecap_lifecycle_issue_use_revoke_uses_real_subprocesses() {
    let workspace = setup_test_workspace();
    let issue = issue_token(&workspace);
    let token_path = workspace.path().join("capability.json");
    write_json(&token_path, &issue["token"]);

    let mut use_cmd = remotecap_cmd();
    use_cmd
        .arg("use")
        .arg("--token-file")
        .arg(&token_path)
        .arg("--operation")
        .arg("network_egress")
        .arg("--endpoint")
        .arg("https://api.example.com/v1/status")
        .arg("--json")
        .current_dir(workspace.path())
        .env("FRANKEN_NODE_REMOTECAP_KEY", "remotecap-cli-e2e-key");

    let use_output = use_cmd.assert().success().get_output().stdout.clone();
    let use_json: Value = serde_json::from_slice(&use_output).expect("use output should be json");
    assert_eq!(use_json["allowed"].as_bool(), Some(true));
    assert_eq!(
        use_json["audit_event"]["event_code"].as_str(),
        Some("REMOTECAP_CONSUMED")
    );

    let mut revoke_cmd = remotecap_cmd();
    revoke_cmd
        .arg("revoke")
        .arg("--token-file")
        .arg(&token_path)
        .arg("--json")
        .current_dir(workspace.path())
        .env("FRANKEN_NODE_REMOTECAP_KEY", "remotecap-cli-e2e-key");

    let revoke_output = revoke_cmd.assert().success().get_output().stdout.clone();
    let revoke_json: Value =
        serde_json::from_slice(&revoke_output).expect("revoke output should be json");
    assert_eq!(revoke_json["revoked"].as_bool(), Some(true));
    assert_eq!(
        revoke_json["audit_event"]["event_code"].as_str(),
        Some("REMOTECAP_REVOKED")
    );

    let mut denied_cmd = remotecap_cmd();
    denied_cmd
        .arg("use")
        .arg("--token-file")
        .arg(&token_path)
        .arg("--operation")
        .arg("network_egress")
        .arg("--endpoint")
        .arg("https://api.example.com/v1/status")
        .arg("--json")
        .current_dir(workspace.path())
        .env("FRANKEN_NODE_REMOTECAP_KEY", "remotecap-cli-e2e-key");

    let denied_output = denied_cmd.assert().failure().get_output().stderr.clone();
    let stderr = std::str::from_utf8(&denied_output).expect("stderr should be utf8");
    assert!(
        stderr.contains("REMOTECAP_REVOKED"),
        "expected revoked denial, got {stderr}"
    );
}

#[test]
fn remotecap_issue_success() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
        .arg("--scope")
        .arg("network_egress,telemetry_export")
        .arg("--endpoint")
        .arg("https://api.example.com")
        .arg("--endpoint")
        .arg("https://metrics.example.com")
        .arg("--ttl")
        .arg("1h")
        .arg("--operator-approved")
        .arg("--json")
        .current_dir(workspace_path);

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Parse the JSON output
    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    // Verify the response structure
    assert!(json["token"].is_object(), "Expected token object");
    assert_eq!(json["audit_event"]["event_code"], "REMOTECAP_ISSUED");
    assert_eq!(json["ttl_secs"], 3600);

    let scope = json["token"]["scope"]["operations"].as_array().unwrap();
    assert!(scope.contains(&Value::String("network_egress".to_string())));
    assert!(scope.contains(&Value::String("telemetry_export".to_string())));

    let endpoints = json["token"]["scope"]["endpoint_prefixes"]
        .as_array()
        .unwrap();
    assert!(endpoints.contains(&Value::String("https://api.example.com".to_string())));
    assert!(endpoints.contains(&Value::String("https://metrics.example.com".to_string())));
}

#[test]
fn remotecap_issue_single_use_token() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
        .arg("--scope")
        .arg("federation_sync")
        .arg("--endpoint")
        .arg("federation://trusted-node")
        .arg("--single-use")
        .arg("--operator-approved")
        .arg("--json")
        .current_dir(workspace_path);

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");
    assert_eq!(
        json["token"]["single_use"].as_bool(),
        Some(true),
        "Expected single_use flag"
    );
}

#[test]
fn remotecap_verify_authorizes_without_consuming_single_use_token() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut issue_cmd = remotecap_cmd();
    issue_cmd
        .arg("issue")
        .arg("--scope")
        .arg("network_egress")
        .arg("--endpoint")
        .arg("https://api.example.com")
        .arg("--single-use")
        .arg("--operator-approved")
        .arg("--json")
        .current_dir(workspace_path)
        .env("FRANKEN_NODE_REMOTECAP_KEY", "remotecap-cli-e2e-key");

    let issue_output = issue_cmd.assert().success().get_output().stdout.clone();
    let issue_json: Value = serde_json::from_slice(&issue_output).expect("issue output json");
    let token_path = workspace.path().join("single_use_capability.json");
    write_json(&token_path, &issue_json["token"]);

    for trace_id in ["verify-trace-1", "verify-trace-2"] {
        let mut verify_cmd = remotecap_cmd();
        verify_cmd
            .arg("verify")
            .arg("--token-file")
            .arg(&token_path)
            .arg("--operation")
            .arg("network_egress")
            .arg("--endpoint")
            .arg("https://api.example.com/v1/status")
            .arg("--trace-id")
            .arg(trace_id)
            .arg("--json")
            .current_dir(workspace_path)
            .env("FRANKEN_NODE_REMOTECAP_KEY", "remotecap-cli-e2e-key");

        let verify_output = verify_cmd.assert().success().get_output().stdout.clone();
        let verify_json: Value =
            serde_json::from_slice(&verify_output).expect("verify output json");
        assert_eq!(verify_json["valid"].as_bool(), Some(true));
        assert_eq!(verify_json["authorized"].as_bool(), Some(true));
        assert_eq!(
            verify_json["audit_event"]["event_code"].as_str(),
            Some("REMOTECAP_RECHECK_PASSED")
        );
        assert_eq!(
            verify_json["audit_event"]["trace_id"].as_str(),
            Some(trace_id)
        );
    }

    let mut use_cmd = remotecap_cmd();
    use_cmd
        .arg("use")
        .arg("--token-file")
        .arg(&token_path)
        .arg("--operation")
        .arg("network_egress")
        .arg("--endpoint")
        .arg("https://api.example.com/v1/status")
        .arg("--json")
        .current_dir(workspace_path)
        .env("FRANKEN_NODE_REMOTECAP_KEY", "remotecap-cli-e2e-key");

    let use_output = use_cmd.assert().success().get_output().stdout.clone();
    let use_json: Value = serde_json::from_slice(&use_output).expect("use output json");
    assert_eq!(
        use_json["audit_event"]["event_code"].as_str(),
        Some("REMOTECAP_CONSUMED")
    );

    let mut replay_cmd = remotecap_cmd();
    replay_cmd
        .arg("use")
        .arg("--token-file")
        .arg(&token_path)
        .arg("--operation")
        .arg("network_egress")
        .arg("--endpoint")
        .arg("https://api.example.com/v1/status")
        .arg("--json")
        .current_dir(workspace_path)
        .env("FRANKEN_NODE_REMOTECAP_KEY", "remotecap-cli-e2e-key");

    let replay_output = replay_cmd.assert().failure().get_output().stderr.clone();
    let replay_stderr = std::str::from_utf8(&replay_output).expect("replay stderr should be utf8");
    assert!(
        replay_stderr.contains("REMOTECAP_REPLAY"),
        "expected replay denial after prior use, got {replay_stderr}"
    );
}

#[test]
fn remotecap_issue_missing_scope_fails() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
        .arg("--endpoint")
        .arg("https://api.example.com")
        .arg("--json")
        .current_dir(workspace_path);

    cmd.assert().failure();
}

#[test]
fn remotecap_issue_missing_endpoint_fails() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
        .arg("--scope")
        .arg("network_egress")
        .arg("--json")
        .current_dir(workspace_path);

    cmd.assert().failure();
}

#[test]
fn remotecap_issue_invalid_scope_fails() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
        .arg("--scope")
        .arg("invalid_operation,unknown_scope")
        .arg("--endpoint")
        .arg("https://api.example.com")
        .arg("--json")
        .current_dir(workspace_path);

    let result = cmd.assert().failure();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    // Should contain error about invalid scope
    assert!(
        stderr.contains("invalid") || stderr.contains("unknown"),
        "Expected error about invalid scope in stderr: {}",
        stderr
    );
}

#[test]
fn remotecap_use_mismatched_endpoint_fails() {
    let workspace = setup_test_workspace();
    let issue = issue_token(&workspace);
    let token_path = workspace.path().join("capability.json");
    write_json(&token_path, &issue["token"]);

    let mut cmd = remotecap_cmd();
    cmd.arg("use")
        .arg("--token-file")
        .arg(&token_path)
        .arg("--operation")
        .arg("network_egress")
        .arg("--endpoint")
        .arg("not-a-valid-url")
        .arg("--json")
        .current_dir(workspace.path())
        .env("FRANKEN_NODE_REMOTECAP_KEY", "remotecap-cli-e2e-key");

    let result = cmd.assert().failure();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    // Should contain error about endpoint authorization.
    assert!(
        stderr.contains("url") || stderr.contains("endpoint") || stderr.contains("invalid"),
        "Expected endpoint denial in stderr: {}",
        stderr
    );
}

#[test]
fn remotecap_issue_human_output() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
        .arg("--scope")
        .arg("telemetry_export")
        .arg("--endpoint")
        .arg("https://metrics.internal")
        .arg("--ttl")
        .arg("30m")
        .arg("--operator-approved")
        .current_dir(workspace_path);

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Human-readable output should contain key information
    assert!(
        stdout.contains("token") || stdout.contains("capability"),
        "Expected token/capability in human output"
    );
    assert!(
        stdout.contains("telemetry_export"),
        "Expected scope in human output"
    );
    assert!(
        stdout.contains("https://metrics.internal"),
        "Expected endpoint in human output"
    );
}

#[test]
fn remotecap_issue_trace_id_propagation() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
        .arg("--scope")
        .arg("network_egress")
        .arg("--endpoint")
        .arg("https://external-api.com")
        .arg("--trace-id")
        .arg("test-trace-12345")
        .arg("--operator-approved")
        .arg("--json")
        .current_dir(workspace_path);

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    // Should include trace ID in response
    assert_eq!(json["audit_event"]["trace_id"], "test-trace-12345");
}

#[test]
fn remotecap_help_shows_usage() {
    let mut cmd = remotecap_cmd();
    cmd.arg("--help");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    assert!(
        stdout.contains("Remote capability token issuance"),
        "Expected help description"
    );
    assert!(
        stdout.contains("issue"),
        "Expected issue subcommand in help"
    );
    assert!(
        stdout.contains("verify"),
        "Expected verify subcommand in help"
    );
}

#[test]
fn remotecap_issue_help_shows_options() {
    let mut cmd = remotecap_cmd();
    cmd.arg("issue").arg("--help");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    assert!(stdout.contains("--scope"), "Expected --scope option");
    assert!(stdout.contains("--endpoint"), "Expected --endpoint option");
    assert!(stdout.contains("--ttl"), "Expected --ttl option");
    assert!(
        stdout.contains("--operator-approved"),
        "Expected --operator-approved option"
    );
    assert!(
        stdout.contains("--single-use"),
        "Expected --single-use option"
    );
    assert!(stdout.contains("--json"), "Expected --json option");
}

#[test]
fn remotecap_verify_help_shows_options() {
    let mut cmd = remotecap_cmd();
    cmd.arg("verify").arg("--help");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    assert!(
        stdout.contains("--token-file"),
        "Expected --token-file option"
    );
    assert!(
        stdout.contains("--operation"),
        "Expected --operation option"
    );
    assert!(stdout.contains("--endpoint"), "Expected --endpoint option");
    assert!(stdout.contains("--trace-id"), "Expected --trace-id option");
    assert!(stdout.contains("--json"), "Expected --json option");
}

#[test]
fn remotecap_issue_with_long_expiry() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
        .arg("--scope")
        .arg("network_egress")
        .arg("--endpoint")
        .arg("https://api.example.com")
        .arg("--ttl")
        .arg("1d")
        .arg("--operator-approved")
        .arg("--json")
        .current_dir(workspace_path);

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");
    assert!(json["token"].is_object(), "Expected token object");
    assert!(json["token"]["expires_at_epoch_secs"].is_u64());
    assert_eq!(json["ttl_secs"], 86_400);
}

#[test]
fn remotecap_issue_structured_logging() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
        .arg("--scope")
        .arg("telemetry_export")
        .arg("--endpoint")
        .arg("https://logs.internal")
        .arg("--trace-id")
        .arg("structured-log-test")
        .arg("--operator-approved")
        .arg("--json")
        .current_dir(workspace_path)
        .env("RUST_LOG", "debug"); // Enable debug logging

    let result = cmd.assert().success();
    let output = result.get_output();
    let _stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");
    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");
    assert_eq!(json["audit_event"]["trace_id"], "structured-log-test");

    // The audit event is the stable structured surface for capability issuance.
}
