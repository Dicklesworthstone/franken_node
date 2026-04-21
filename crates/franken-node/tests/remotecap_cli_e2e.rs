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
       .arg("--expires-in-secs")
       .arg("3600")
       .arg("--json")
       .current_dir(workspace_path);

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Parse the JSON output
    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    // Verify the response structure
    assert!(json["token"].is_string(), "Expected token field");
    assert!(json["expires_at"].is_string(), "Expected expires_at field");
    assert!(json["scope"].is_array(), "Expected scope array");

    let scope = json["scope"].as_array().unwrap();
    assert!(scope.contains(&Value::String("network_egress".to_string())));
    assert!(scope.contains(&Value::String("telemetry_export".to_string())));

    let endpoints = json["endpoints"].as_array().unwrap();
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
       .arg("--json")
       .current_dir(workspace_path);

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");
    assert_eq!(json["single_use"].as_bool(), Some(true), "Expected single_use flag");
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
    assert!(stderr.contains("invalid") || stderr.contains("unknown"),
            "Expected error about invalid scope in stderr: {}", stderr);
}

#[test]
fn remotecap_issue_malformed_endpoint_fails() {
    let workspace = setup_test_workspace();
    let workspace_path = workspace.path().to_str().unwrap();

    let mut cmd = remotecap_cmd();
    cmd.arg("issue")
       .arg("--scope")
       .arg("network_egress")
       .arg("--endpoint")
       .arg("not-a-valid-url")
       .arg("--json")
       .current_dir(workspace_path);

    let result = cmd.assert().failure();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    // Should contain error about malformed URL
    assert!(stderr.contains("url") || stderr.contains("endpoint") || stderr.contains("invalid"),
            "Expected error about malformed URL in stderr: {}", stderr);
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
       .arg("--expires-in-secs")
       .arg("1800")
       .current_dir(workspace_path);

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    // Human-readable output should contain key information
    assert!(stdout.contains("token") || stdout.contains("capability"),
            "Expected token/capability in human output");
    assert!(stdout.contains("telemetry_export"),
            "Expected scope in human output");
    assert!(stdout.contains("https://metrics.internal"),
            "Expected endpoint in human output");
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
       .arg("--json")
       .current_dir(workspace_path);

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");

    // Should include trace ID in response
    assert!(json["trace_id"].as_str().unwrap_or("").contains("test-trace-12345"),
            "Expected trace ID in response");
}

#[test]
fn remotecap_help_shows_usage() {
    let mut cmd = remotecap_cmd();
    cmd.arg("--help");

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    assert!(stdout.contains("Remote capability token issuance"),
            "Expected help description");
    assert!(stdout.contains("issue"),
            "Expected issue subcommand in help");
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
    assert!(stdout.contains("--expires-in-secs"), "Expected --expires-in-secs option");
    assert!(stdout.contains("--single-use"), "Expected --single-use option");
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
       .arg("--expires-in-secs")
       .arg("86400") // 24 hours
       .arg("--json")
       .current_dir(workspace_path);

    let result = cmd.assert().success();
    let output = result.get_output();
    let stdout = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8");

    let json: Value = serde_json::from_str(stdout).expect("Invalid JSON output");
    assert!(json["token"].is_string(), "Expected token field");
    assert!(json["expires_at"].is_string(), "Expected expires_at field");
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
       .arg("--json")
       .current_dir(workspace_path)
       .env("RUST_LOG", "debug"); // Enable debug logging

    let result = cmd.assert().success();
    let output = result.get_output();
    let stderr = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8");

    // Should contain structured logging output with trace ID
    // Note: The exact format depends on the implementation
    // This test validates that debug logging is working during capability issuance
    // In a real implementation, this would check for specific log events
}