//! Golden tests for CLI subcommands lacking coverage.
//!
//! This test suite ensures CLI output stability for subcommands that
//! previously lacked golden pinning. Each test captures stdout/stderr
//! with comprehensive scrubbing for non-deterministic values.
//!
//! Note: These tests will fail on first run to create golden snapshots.
//! Run with UPDATE_GOLDENS=1 or `cargo insta review` to accept initial outputs.

use assert_cmd::Command;
use insta::{Settings, assert_json_snapshot, assert_snapshot};
use serde_json::{Value, json};
use std::{error::Error, io, path::Path};
use tempfile::TempDir;

#[path = "cli_golden_helpers.rs"]
mod cli_golden_helpers;

use cli_golden_helpers::{pretty_json_stdout, with_scrubbed_snapshot_settings};

fn with_json_snapshot_settings<R>(snapshot_dir: &str, assertion: impl FnOnce() -> R) -> R {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/goldens")
            .join(snapshot_dir),
    );
    settings.set_prepend_module_to_snapshot(false);
    settings.set_omit_expression(true);
    settings.bind(assertion)
}

fn parse_json_stdout(command_name: &str, stdout: &[u8]) -> Result<Value, io::Error> {
    serde_json::from_slice(stdout).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{command_name} stdout should be JSON: {err}\n{}",
                String::from_utf8_lossy(stdout)
            ),
        )
    })
}

fn canonicalize_doctor_json(value: &mut Value, cwd: &Path) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map.iter_mut() {
                match key.as_str() {
                    "generated_at_utc" | "timestamp" => *nested = json!("[TIMESTAMP]"),
                    "duration_ms" => *nested = json!("[DURATION_MS]"),
                    "source_path" if !nested.is_null() => *nested = json!("[PATH]"),
                    _ => canonicalize_doctor_json(nested, cwd),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                canonicalize_doctor_json(item, cwd);
            }
        }
        Value::String(text) => {
            let cwd = cwd.to_string_lossy();
            if !cwd.is_empty() && text.contains(cwd.as_ref()) {
                *text = text.replace(cwd.as_ref(), "[PATH]");
            }
        }
        _ => {}
    }
}

/// Helper to run CLI commands that may fail gracefully.
fn run_cli_command_with_fallback(
    args: &[&str],
    expect_json: bool,
    command_name: &str,
) -> Result<String, String> {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = cmd.args(args).output().expect("command execution");

    if output.status.success() {
        if expect_json {
            Ok(pretty_json_stdout(command_name, &output.stdout))
        } else {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    } else {
        // Return stderr for failed commands
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

// === help commands (guaranteed to work) ===

#[test]
fn franken_node_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("cli", || {
        assert_snapshot!("franken_node_help", stdout);
    });
}

#[test]
fn trust_card_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["trust-card", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("trust_card_cli", || {
        assert_snapshot!("trust_card_help", stdout);
    });
}

#[test]
fn fleet_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["fleet", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("fleet_cli", || {
        assert_snapshot!("fleet_help", stdout);
    });
}

#[test]
fn doctor_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["doctor", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("doctor_cli", || {
        assert_snapshot!("doctor_help", stdout);
    });
}

#[test]
fn remotecap_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["remotecap", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("remotecap_cli", || {
        assert_snapshot!("remotecap_help", stdout);
    });
}

#[test]
fn verify_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["verify", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("verify_cli", || {
        assert_snapshot!("verify_help", stdout);
    });
}

#[test]
fn registry_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["registry", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("registry_cli", || {
        assert_snapshot!("registry_help", stdout);
    });
}

#[test]
fn incident_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["incident", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("incident_cli", || {
        assert_snapshot!("incident_help", stdout);
    });
}

#[test]
fn bench_run_secure_extension_heavy_json_output() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("franken-node")?;
    let assertion = cmd
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-golden-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .args(["bench", "run", "--scenario", "secure-extension-heavy"])
        .assert()
        .success();

    let stdout = parse_json_stdout("bench run", &assertion.get_output().stdout)?;
    with_json_snapshot_settings("bench_cli", || {
        assert_json_snapshot!("bench_run_secure_extension_heavy_json", stdout);
    });
    Ok(())
}

#[test]
fn doctor_json_output() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mut cmd = Command::cargo_bin("franken-node")?;
    let assertion = cmd
        .current_dir(temp.path())
        .env_remove("FRANKEN_NODE_PROFILE")
        .args([
            "doctor",
            "--json",
            "--profile",
            "strict",
            "--trace-id",
            "golden-doctor-trace",
        ])
        .assert()
        .success();

    let mut stdout = parse_json_stdout("doctor --json", &assertion.get_output().stdout)?;
    canonicalize_doctor_json(&mut stdout, temp.path());
    with_json_snapshot_settings("doctor_cli", || {
        assert_json_snapshot!("doctor_json", stdout);
    });
    Ok(())
}
