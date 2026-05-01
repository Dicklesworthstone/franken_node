//! Golden tests for CLI subcommands lacking coverage.
//!
//! This test suite ensures CLI output stability for subcommands that
//! previously lacked golden pinning. Each test captures stdout/stderr
//! with comprehensive scrubbing for non-deterministic values.
//!
//! Note: These tests will fail on first run to create golden snapshots.
//! Run with UPDATE_GOLDENS=1 or `cargo insta review` to accept initial outputs.

use assert_cmd::Command;
use frankenengine_node::supply_chain::artifact_signing::{build_and_sign_manifest, sign_artifact};
use insta::{Settings, assert_json_snapshot, assert_snapshot};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{error::Error, fs, io, path::Path};
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

fn fixture_signing_key(domain: &[u8], label: &[u8]) -> ed25519_dalek::SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(u64::try_from(label.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(label);
    let seed: [u8; 32] = hasher.finalize().into();
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn write_seed_signing_key(root: &Path, relative_path: &str, seed_byte: u8) -> io::Result<String> {
    let path = root.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, hex::encode([seed_byte; 32]))?;
    Ok(path.display().to_string())
}

fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn write_signed_release_fixture(release_dir: &Path, artifacts: &[(&str, &[u8])]) -> io::Result<()> {
    let signing_key = fixture_signing_key(b"cli_subcommand_goldens_release_key_v1:", b"current");
    let manifest = build_and_sign_manifest(artifacts, &signing_key);

    for (name, bytes) in artifacts {
        let artifact_path = release_dir.join(name);
        ensure_parent_dir(&artifact_path)?;
        fs::write(&artifact_path, bytes)?;

        let signature = sign_artifact(&signing_key, bytes);
        let signature_path = release_dir.join(format!("{name}.sig"));
        ensure_parent_dir(&signature_path)?;
        fs::write(signature_path, hex::encode(signature))?;
    }

    fs::write(release_dir.join("SHA256SUMS"), manifest.canonical_bytes())?;
    fs::write(
        release_dir.join("SHA256SUMS.sig"),
        hex::encode(manifest.signature),
    )?;
    Ok(())
}

fn write_release_key_dir(key_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(key_dir)?;
    let rotated_key = fixture_signing_key(b"cli_subcommand_goldens_release_key_v1:", b"rotated");
    let current_key = fixture_signing_key(b"cli_subcommand_goldens_release_key_v1:", b"current");
    fs::write(
        key_dir.join("00-rotated.pub"),
        hex::encode(rotated_key.verifying_key().as_bytes()),
    )?;
    fs::write(
        key_dir.join("10-current.pub"),
        hex::encode(current_key.verifying_key().as_bytes()),
    )?;
    fs::write(key_dir.join("README.txt"), "non-key metadata")?;
    Ok(())
}

fn canonicalize_verify_release_json(mut value: Value, release_dir: &Path, key_dir: &Path) -> Value {
    let release_exact = release_dir.display().to_string();
    let release_prefix = format!("{release_exact}/");
    let key_exact = key_dir.display().to_string();
    let key_prefix = format!("{key_exact}/");

    fn scrub(
        value: &mut Value,
        release_exact: &str,
        release_prefix: &str,
        key_exact: &str,
        key_prefix: &str,
    ) {
        match value {
            Value::Array(items) => {
                for item in items {
                    scrub(item, release_exact, release_prefix, key_exact, key_prefix);
                }
            }
            Value::Object(map) => {
                for nested in map.values_mut() {
                    scrub(nested, release_exact, release_prefix, key_exact, key_prefix);
                }
            }
            Value::String(text) => {
                if text == release_exact {
                    *value = json!("[release]");
                } else if let Some(path) = text.strip_prefix(release_prefix) {
                    *value = json!(format!("[release]/{path}"));
                } else if text == key_exact {
                    *value = json!("[keys]");
                } else if let Some(path) = text.strip_prefix(key_prefix) {
                    *value = json!(format!("[keys]/{path}"));
                }
            }
            _ => {}
        }
    }

    scrub(
        &mut value,
        &release_exact,
        &release_prefix,
        &key_exact,
        &key_prefix,
    );
    value
}

fn canonicalize_fleet_reconcile_json(mut value: Value, fleet_state_dir: &Path) -> Value {
    let fleet_state_prefix = format!("{}/", fleet_state_dir.display());

    fn scrub(value: &mut Value, fleet_state_prefix: &str) {
        match value {
            Value::Array(items) => {
                for item in items {
                    scrub(item, fleet_state_prefix);
                }
            }
            Value::Object(map) => {
                for (key, nested) in map {
                    match key.as_str() {
                        "operation_id" => {
                            *nested = json!("[operation-id]");
                        }
                        "receipt_id" => {
                            *nested = json!("[receipt-id]");
                        }
                        "signature_hex" => {
                            *nested = json!("[signature-hex]");
                        }
                        "signed_payload_sha256" => {
                            *nested = json!("[signed-payload-sha256]");
                        }
                        "payload_hash" => {
                            *nested = json!("[payload-hash]");
                        }
                        "elapsed_ms" => {
                            *nested = json!(0);
                        }
                        "timestamp" | "signed_at" | "emitted_at" | "recorded_at" | "issued_at"
                        | "completed_at" | "last_seen" | "as_of" | "poll_timestamp" => {
                            *nested = json!(format!("[{key}]"));
                        }
                        "state_dir" => {
                            if let Some(path) = nested.as_str() {
                                *nested = path
                                    .strip_prefix(fleet_state_prefix)
                                    .map(|suffix| json!(format!("[fleet-state]/{suffix}")))
                                    .unwrap_or_else(|| json!("[fleet-state]"));
                            }
                        }
                        _ => scrub(nested, fleet_state_prefix),
                    }
                }
            }
            Value::String(text) => {
                if let Some(path) = text.strip_prefix(fleet_state_prefix) {
                    *value = json!(format!("[fleet-state]/{path}"));
                }
            }
            _ => {}
        }
    }

    scrub(&mut value, &fleet_state_prefix);
    value
}

fn write_close_condition_fixture(root: &Path) -> io::Result<()> {
    fn write_fixture(path: &Path, contents: &str) -> io::Result<()> {
        ensure_parent_dir(path)?;
        fs::write(path, contents)
    }

    write_fixture(
        &root.join("Cargo.toml"),
        r#"
[workspace]
members = ["crates/franken-node"]
"#,
    )?;
    write_fixture(
        &root.join("crates/franken-node/Cargo.toml"),
        r#"
[package]
name = "fixture-franken-node"
version = "0.1.0"
edition = "2024"

[dependencies]
frankenengine-engine = { path = "../../../franken_engine/crates/franken-engine" }
frankenengine-extension-host = { path = "../../../franken_engine/crates/franken-extension-host" }
"#,
    )?;
    write_fixture(
        &root.join("crates/franken-node/src/lib.rs"),
        "pub fn fixture() -> bool { true }\n",
    )?;
    write_fixture(
        &root.join("docs/ENGINE_SPLIT_CONTRACT.md"),
        "franken_engine path dependencies MUST NOT be replaced by local engine crates.\n",
    )?;
    write_fixture(
        &root.join("docs/PRODUCT_CHARTER.md"),
        "Dual-oracle close condition requires all dimensions to be green.\n",
    )?;
    write_fixture(
        &root.join("artifacts/13/compatibility_corpus_results.json"),
        r#"{
  "corpus": {
    "corpus_version": "compat-corpus-golden"
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
    )?;
    write_fixture(
        &root.join("artifacts/section/10.N/gate_verdict/bd-1neb_section_gate.json"),
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
    )?;
    Ok(())
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
        .args([
            "bench",
            "run",
            "--scenario",
            "secure-extension-heavy",
            "--fixture-mode",
        ])
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

#[test]
fn cli_json_golden_verify_release_output() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let release_dir = temp.path().join("release");
    let key_dir = temp.path().join("keys");
    fs::create_dir_all(&release_dir)?;

    let artifacts = [
        (
            "franken-node-linux-x64.tar.xz",
            b"golden-artifact-linux-x64" as &[u8],
        ),
        (
            "franken-node-darwin-arm64.tar.xz",
            b"golden-artifact-darwin-arm64" as &[u8],
        ),
    ];
    write_signed_release_fixture(&release_dir, &artifacts)?;
    write_release_key_dir(&key_dir)?;

    let release_arg = release_dir.display().to_string();
    let key_dir_arg = key_dir.display().to_string();
    let mut cmd = Command::cargo_bin("franken-node")?;
    let assertion = cmd
        .args([
            "verify",
            "release",
            release_arg.as_str(),
            "--key-dir",
            key_dir_arg.as_str(),
            "--json",
        ])
        .assert()
        .success();

    let stdout = parse_json_stdout("verify release --json", &assertion.get_output().stdout)?;
    with_json_snapshot_settings("verify_cli", || {
        assert_json_snapshot!(
            "verify_release_json",
            canonicalize_verify_release_json(stdout, &release_dir, &key_dir)
        );
    });
    Ok(())
}

#[test]
fn cli_json_golden_fleet_reconcile_output() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let fleet_state_dir = temp.path().join("fleet-state");
    let signing_key_path = write_seed_signing_key(temp.path(), "keys/fleet.key", 31)?;

    let mut cmd = Command::cargo_bin("franken-node")?;
    let assertion = cmd
        .current_dir(temp.path())
        .env("FRANKEN_NODE_FLEET_STATE_DIR", &fleet_state_dir)
        .env(
            "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
            signing_key_path,
        )
        .env_remove("FRANKEN_NODE_PROFILE")
        .args(["fleet", "reconcile", "--json"])
        .assert()
        .success();

    let stdout = parse_json_stdout("fleet reconcile --json", &assertion.get_output().stdout)?;
    with_json_snapshot_settings("fleet_cli", || {
        assert_json_snapshot!(
            "fleet_reconcile_json",
            canonicalize_fleet_reconcile_json(stdout, &fleet_state_dir)
        );
    });
    Ok(())
}

#[test]
fn cli_json_golden_doctor_close_condition_output() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    write_close_condition_fixture(temp.path())?;
    let signing_key_path =
        write_seed_signing_key(temp.path(), ".franken-node/keys/oracle-close.key", 41)?;

    let mut cmd = Command::cargo_bin("franken-node")?;
    let assertion = cmd
        .current_dir(temp.path())
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
        .assert()
        .success();

    let stdout = parse_json_stdout(
        "doctor close-condition --json",
        &assertion.get_output().stdout,
    )?;
    with_json_snapshot_settings("doctor_cli", || {
        assert_json_snapshot!("doctor_close_condition_json", stdout);
    });
    Ok(())
}
