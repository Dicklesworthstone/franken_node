//! Golden tests for CLI error conditions.
//!
//! This test suite captures error output for CLI commands with invalid
//! arguments or missing dependencies. Error messages should be stable
//! and informative.

use insta::assert_snapshot;

#[path = "cli_golden_helpers.rs"]
mod cli_golden_helpers;

use cli_golden_helpers::{franken_node_cmd, with_scrubbed_snapshot_settings};

/// Test error output for missing required arguments.
#[test]
fn trust_card_show_missing_extension_id() {
    let mut cmd = franken_node_cmd();
    let assertion = cmd.args(["trust-card", "show"]).assert().failure();

    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    with_scrubbed_snapshot_settings("trust_card_cli", || {
        assert_snapshot!("show_missing_extension_id", stderr);
    });
}

#[test]
fn verify_release_missing_bundle_path() {
    let mut cmd = franken_node_cmd();
    let assertion = cmd.args(["verify", "release"]).assert().failure();

    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    with_scrubbed_snapshot_settings("verify_cli", || {
        assert_snapshot!("release_missing_bundle_path", stderr);
    });
}

#[test]
fn remotecap_issue_missing_scope() {
    let mut cmd = franken_node_cmd();
    let assertion = cmd.args(["remotecap", "issue"]).assert().failure();

    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    with_scrubbed_snapshot_settings("remotecap_cli", || {
        assert_snapshot!("issue_missing_scope", stderr);
    });
}

#[test]
fn fleet_status_invalid_format() {
    let mut cmd = franken_node_cmd();
    let assertion = cmd
        .args(["fleet", "status", "--format", "invalid"])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    with_scrubbed_snapshot_settings("fleet_cli", || {
        assert_snapshot!("status_invalid_format", stderr);
    });
}

#[test]
fn registry_search_invalid_limit() {
    let mut cmd = franken_node_cmd();
    let assertion = cmd
        .args(["registry", "search", "--limit", "invalid"])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    with_scrubbed_snapshot_settings("registry_cli", || {
        assert_snapshot!("search_invalid_limit", stderr);
    });
}

#[test]
fn incident_bundle_missing_path() {
    let mut cmd = franken_node_cmd();
    let assertion = cmd.args(["incident", "bundle"]).assert().failure();

    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    with_scrubbed_snapshot_settings("incident_cli", || {
        assert_snapshot!("bundle_missing_path", stderr);
    });
}

#[test]
fn doctor_invalid_subcommand() {
    let mut cmd = franken_node_cmd();
    let assertion = cmd.args(["doctor", "invalid"]).assert().failure();

    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    with_scrubbed_snapshot_settings("doctor_cli", || {
        assert_snapshot!("invalid_subcommand", stderr);
    });
}
