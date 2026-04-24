//! Golden tests for runtime lane CLI JSON output.
//!
//! Captures and verifies canonical JSON outputs from runtime lane commands
//! to ensure API stability and prevent unintentional changes to the JSON schema.
//!
//! Coverage:
//! - `runtime lane status --json` - Default lane policy and telemetry snapshot
//! - `runtime lane assign --json` - Task assignment through default scheduler
//!
//! Note: Run with UPDATE_GOLDENS=1 or `cargo insta review` to accept new outputs.

use assert_cmd::Command;
use insta::{Settings, assert_json_snapshot};
use serde_json::Value;
use std::{io, path::Path};
use tempfile::TempDir;

fn with_json_snapshot_settings<R>(snapshot_dir: &str, assertion: impl FnOnce() -> R) -> R {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden_artifacts")
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

fn canonicalize_runtime_lane_json(mut value: Value) -> Value {
    match value {
        Value::Object(ref mut map) => {
            // Scrub timestamps
            if let Some(Value::String(timestamp)) = map.get_mut("timestamp") {
                *timestamp = "[TIMESTAMP]".into();
            }
            if let Some(Value::String(timestamp)) = map.get_mut("created_at") {
                *timestamp = "[TIMESTAMP]".into();
            }
            if let Some(Value::String(timestamp)) = map.get_mut("updated_at") {
                *timestamp = "[TIMESTAMP]".into();
            }

            // Scrub UUIDs and IDs
            if let Some(Value::String(id)) = map.get_mut("assignment_id") {
                *id = "[ASSIGNMENT_ID]".into();
            }
            if let Some(Value::String(id)) = map.get_mut("task_id") {
                *id = "[TASK_ID]".into();
            }
            if let Some(Value::String(id)) = map.get_mut("session_id") {
                *id = "[SESSION_ID]".into();
            }

            // Scrub dynamic numeric values that change between runs
            if let Some(Value::Number(_)) = map.get_mut("memory_usage_bytes") {
                map.insert("memory_usage_bytes".to_string(), Value::String("[MEMORY_USAGE]".to_string()));
            }
            if let Some(Value::Number(_)) = map.get_mut("cpu_time_ns") {
                map.insert("cpu_time_ns".to_string(), Value::String("[CPU_TIME]".to_string()));
            }

            // Recursively canonicalize nested objects and arrays
            for (_, nested_value) in map.iter_mut() {
                *nested_value = canonicalize_runtime_lane_json(nested_value.clone());
            }
        }
        Value::Array(ref mut array) => {
            for item in array.iter_mut() {
                *item = canonicalize_runtime_lane_json(item.clone());
            }
        }
        _ => {}
    }
    value
}

#[test]
fn runtime_lane_status_json_golden() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;

    let mut command = Command::cargo_bin("franken-node")?;
    let output = command
        .current_dir(&temp_dir)
        .args(["runtime", "lane", "status", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();

    let json = parse_json_stdout("runtime lane status", &output.stdout)?;
    let canonical_json = canonicalize_runtime_lane_json(json);

    with_json_snapshot_settings("runtime_lane", || {
        assert_json_snapshot!("status_json_output", canonical_json);
    });

    Ok(())
}

#[test]
fn runtime_lane_assign_minimal_task_json_golden() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;

    let mut command = Command::cargo_bin("franken-node")?;
    let output = command
        .current_dir(&temp_dir)
        .args([
            "runtime", "lane", "assign",
            "epoch_transition",
            "--json"
        ])
        .assert()
        .success()
        .get_output()
        .clone();

    let json = parse_json_stdout("runtime lane assign", &output.stdout)?;
    let canonical_json = canonicalize_runtime_lane_json(json);

    with_json_snapshot_settings("runtime_lane", || {
        assert_json_snapshot!("assign_minimal_task_json", canonical_json);
    });

    Ok(())
}

#[test]
fn runtime_lane_assign_with_timestamp_json_golden() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;

    let mut command = Command::cargo_bin("franken-node")?;
    let output = command
        .current_dir(&temp_dir)
        .args([
            "runtime", "lane", "assign",
            "log_rotation",
            "--json",
            "--timestamp-ms", "1698768000000"
        ])
        .assert()
        .success()
        .get_output()
        .clone();

    let json = parse_json_stdout("runtime lane assign", &output.stdout)?;
    let canonical_json = canonicalize_runtime_lane_json(json);

    with_json_snapshot_settings("runtime_lane", || {
        assert_json_snapshot!("assign_with_timestamp_json", canonical_json);
    });

    Ok(())
}

#[test]
fn runtime_lane_assign_with_custom_trace_json_golden() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;

    let mut command = Command::cargo_bin("franken-node")?;
    let output = command
        .current_dir(&temp_dir)
        .args([
            "runtime", "lane", "assign",
            "log_rotation",
            "--json",
            "--trace-id", "test-custom-trace-123",
            "--timestamp-ms", "1698768000000"
        ])
        .assert()
        .success()
        .get_output()
        .clone();

    let json = parse_json_stdout("runtime lane assign", &output.stdout)?;
    let canonical_json = canonicalize_runtime_lane_json(json);

    with_json_snapshot_settings("runtime_lane", || {
        assert_json_snapshot!("assign_with_custom_trace_json", canonical_json);
    });

    Ok(())
}