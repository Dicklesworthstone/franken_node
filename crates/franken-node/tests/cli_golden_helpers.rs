//! Shared utilities for CLI golden testing.
//!
//! This module provides common functions for testing CLI output with
//! proper scrubbing of non-deterministic values like timestamps, UUIDs,
//! file paths, and memory addresses.

#![allow(dead_code)]

use assert_cmd::Command;
use insta::{Settings, assert_snapshot};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Create a franken-node command instance for testing.
pub fn franken_node_cmd() -> Command {
    Command::cargo_bin("franken-node").expect("franken-node binary")
}

/// Pretty-print JSON stdout with error handling.
pub fn pretty_json_stdout(command_name: &str, stdout: &[u8]) -> String {
    let value: Value = serde_json::from_slice(stdout).unwrap_or_else(|err| {
        panic!(
            "{command_name} stdout should be JSON: {err}\n{}",
            String::from_utf8_lossy(stdout)
        )
    });
    serde_json::to_string_pretty(&value).expect("pretty json")
}

/// Apply comprehensive scrubbing filters for CLI output.
pub fn with_scrubbed_snapshot_settings<R>(snapshot_dir: &str, assertion: impl FnOnce() -> R) -> R {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/goldens")
            .join(snapshot_dir),
    );
    settings.set_prepend_module_to_snapshot(false);
    settings.set_omit_expression(true);

    // UUID scrubbing (various formats)
    settings.add_filter(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "[UUID]",
    );
    settings.add_filter(
        r"[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}",
        "[UUID]",
    );

    // Timestamp scrubbing (ISO 8601 and variants)
    settings.add_filter(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?",
        "[TIMESTAMP]",
    );
    settings.add_filter(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?",
        "[TIMESTAMP]",
    );

    // File path scrubbing (absolute paths)
    settings.add_filter(r"/[A-Za-z0-9_./-]+", "[PATH]");
    settings.add_filter(r"\\[A-Za-z0-9_.\\\-]+", "[PATH]"); // Windows paths

    // Memory address scrubbing
    settings.add_filter(r"0x[0-9a-fA-F]{8,16}", "[ADDR]");

    // Duration scrubbing (various units)
    settings.add_filter(r"\d+(\.\d+)?\s*(ns|μs|ms|s|sec|min|hr)", "[DURATION]");
    settings.add_filter(r"\d+(\.\d+)?ms", "[DURATION]");

    // PID/TID scrubbing
    settings.add_filter(r"pid:\d+", "pid:[PID]");
    settings.add_filter(r"tid:\d+", "tid:[TID]");

    // Hash scrubbing (SHA256, etc.)
    settings.add_filter(r"[a-f0-9]{40,64}", "[HASH]");
    settings.add_filter(r"[A-F0-9]{40,64}", "[HASH]");

    // Port number scrubbing
    settings.add_filter(r":\d{4,5}([/\s]|$)", ":[PORT]$1");

    // Temp directory scrubbing
    settings.add_filter(r"/tmp/[A-Za-z0-9_.-]+", "/tmp/[TEMPDIR]");

    settings.bind(assertion)
}

/// Create fixture path for test data.
pub fn fixture_path(subdir: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(subdir)
        .join(name)
}

/// Assert CLI output matches golden snapshot with scrubbing.
pub fn assert_cli_snapshot(name: &str, output: &str, golden_dir: &str) {
    with_scrubbed_snapshot_settings(golden_dir, || {
        assert_snapshot!(name, output);
    });
}
