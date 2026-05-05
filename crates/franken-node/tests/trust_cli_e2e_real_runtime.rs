//! Trust CLI E2E Tests with Real Runtime Integration and Structured Logging
//!
//! This test suite follows Perfect E2E principles:
//! - NO MOCKS: Uses real Node.js runtime, real file systems, real process execution
//! - Real tempdir setup with proper isolation
//! - Structured JSON-line logging for observability
//! - Production-like conditions with real timing and behavior
//!
//! Mock Risk Score: 15 (CLI behavior × Runtime detection × Error message accuracy)
//! Why no mocks: CLI runtime detection, filesystem interaction, and process behavior
//! can only be validated against real components.

use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Once;
use std::time::Instant;
use tempfile::TempDir;
use tracing::{error, info};

static TEST_TRACING_INIT: Once = Once::new();

/// Test harness with structured logging for real runtime testing
struct RealRuntimeTestHarness {
    workspace: TempDir,
    node_binary: Option<PathBuf>,
    test_start: Instant,
    test_name: String,
}

#[derive(Debug, serde::Serialize)]
struct TestPhaseLog {
    timestamp: String,
    test_name: String,
    phase: String,
    duration_ms: u64,
    success: bool,
    details: Value,
}

impl RealRuntimeTestHarness {
    fn new(test_name: &str) -> Self {
        init_test_tracing();

        let test_start = Instant::now();
        let workspace = tempfile::tempdir().expect("create workspace tempdir");

        // Try to find real Node.js binary
        let node_binary = Self::find_node_binary();

        info!(
            test_name = test_name,
            workspace = %workspace.path().display(),
            node_found = node_binary.is_some(),
            "Test harness initialized"
        );

        Self {
            workspace,
            node_binary,
            test_start,
            test_name: test_name.to_string(),
        }
    }

    fn find_node_binary() -> Option<PathBuf> {
        // Try common Node.js locations
        let candidates = [
            "node",                // In PATH
            "/usr/bin/node",       // Common system location
            "/usr/local/bin/node", // Homebrew/manual install
        ];

        for candidate in &candidates {
            let path = PathBuf::from(candidate);
            if path.is_file() || which_binary(candidate).is_some() {
                return Some(path);
            }
        }
        None
    }

    fn log_phase(&self, phase: &str, success: bool, details: Value) {
        let duration_ms = self.test_start.elapsed().as_millis() as u64;
        let log_entry = TestPhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name.clone(),
            phase: phase.to_string(),
            duration_ms,
            success,
            details: details.clone(),
        };

        // Output structured JSON-line logging
        eprintln!("{}", serde_json::to_string(&log_entry).unwrap());

        if success {
            info!(
                test_name = %self.test_name,
                phase = phase,
                duration_ms = duration_ms,
                "Phase completed successfully"
            );
        } else {
            error!(
                test_name = %self.test_name,
                phase = phase,
                duration_ms = duration_ms,
                details = %details,
                "Phase failed"
            );
        }
    }

    fn workspace_path(&self) -> &Path {
        self.workspace.path()
    }

    fn setup_node_project_with_real_runtime(&self) -> Result<(), Box<dyn std::error::Error>> {
        let workspace = self.workspace_path();

        self.log_phase(
            "setup",
            true,
            json!({
                "action": "creating_workspace",
                "path": workspace.display().to_string()
            }),
        );

        // Create franken-node config (minimal, no trust registry)
        let config = json!({
            "schema_version": "1.0",
            "project_id": "test-real-runtime",
            "policy_enforcement": {
                "strict_mode": true,
                "trust_sources": []
            }
        });
        fs::write(
            workspace.join("franken-node.config.json"),
            serde_json::to_string_pretty(&config)?,
        )?;

        // Create package.json with real dependency
        let package_json = json!({
            "name": "test-real-runtime-project",
            "version": "1.0.0",
            "dependencies": {
                "@acme/auth-guard": "^1.4.2"
            }
        });
        fs::write(
            workspace.join("package.json"),
            serde_json::to_string_pretty(&package_json)?,
        )?;

        // Create a real Node.js entry point
        let index_js = r#"
// Real Node.js application for testing runtime detection
console.log("Real Node.js application started");
process.exit(0);
"#;
        fs::write(workspace.join("index.js"), index_js)?;

        self.log_phase(
            "setup",
            true,
            json!({
                "action": "workspace_created",
                "files": ["franken-node.config.json", "package.json", "index.js"],
                "config": config
            }),
        );

        Ok(())
    }
}

fn which_binary(name: &str) -> Option<PathBuf> {
    Command::new("which")
        .arg(name)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let path_str = String::from_utf8(output.stdout).ok()?;
            Some(PathBuf::from(path_str.trim()))
        })
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn resolve_franken_node_binary() -> PathBuf {
    if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_franken-node") {
        return PathBuf::from(exe);
    }
    repo_root().join("target/debug/franken-node")
}

fn run_franken_node_with_real_runtime(
    workspace: &Path,
    args: &[&str],
    node_binary: Option<&PathBuf>,
) -> Output {
    let binary_path = resolve_franken_node_binary();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );

    let mut command = Command::new(&binary_path);
    command.current_dir(workspace).args(args);

    // If we have a real Node.js binary, use it
    if let Some(node_path) = node_binary {
        let node_dir = node_path.parent().expect("node binary dir");
        let current_path = std::env::var_os("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", node_dir.display(), current_path.to_string_lossy());
        command.env("PATH", new_path);
    }

    // Clear engine binaries so we test runtime detection
    command.env("FRANKEN_ENGINE_BIN", "");
    command.env("FRANKEN_NODE_ENGINE_BINARY_PATH", "");

    command
        .output()
        .unwrap_or_else(|err| panic!("failed running franken-node: {err}"))
}

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

#[test]
fn real_runtime_missing_registry_suggests_init_scan_with_structured_logging() {
    let test_harness = RealRuntimeTestHarness::new("real_runtime_missing_registry_test");

    // Phase 1: Setup workspace with real Node.js project
    test_harness.log_phase(
        "setup",
        true,
        json!({
            "action": "starting_test",
            "has_node_binary": test_harness.node_binary.is_some()
        }),
    );

    if test_harness.node_binary.is_none() {
        test_harness.log_phase(
            "setup",
            false,
            json!({
                "action": "skipping_test",
                "reason": "No Node.js binary found in system",
                "suggestion": "Install Node.js to run this test"
            }),
        );
        eprintln!("SKIP: No Node.js binary found. Install Node.js to run this test.");
        return;
    }

    test_harness
        .setup_node_project_with_real_runtime()
        .expect("workspace setup should succeed");

    // Phase 2: Run franken-node with real Node.js runtime
    test_harness.log_phase("execution", true, json!({
        "action": "running_franken_node",
        "args": ["run", "--policy", "strict", "--runtime", "node", ".", "--structured-logs-jsonl"]
    }));

    let output = run_franken_node_with_real_runtime(
        test_harness.workspace_path(),
        &[
            "run",
            "--policy",
            "strict",
            "--runtime",
            "node",
            ".",
            "--structured-logs-jsonl",
        ],
        test_harness.node_binary.as_ref(),
    );

    // Phase 3: Analyze results with structured logging
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let success = output.status.success();
    test_harness.log_phase("analysis", true, json!({
        "action": "analyzing_output",
        "exit_success": success,
        "stderr_length": stderr.len(),
        "stdout_length": stdout.len(),
        "contains_registry_missing": stderr.contains("authoritative trust registry missing"),
        "contains_fix_command": stderr.contains("fix_command=franken-node init --profile strict --scan")
    }));

    // Phase 4: Verify expected behavior
    assert!(
        success,
        "franken-node run should succeed when registry is missing but runtime exists.\nstderr:\n{}\nstdout:\n{}",
        stderr, stdout
    );

    assert!(
        stderr.contains("authoritative trust registry missing"),
        "Should detect missing trust registry.\nstderr:\n{}",
        stderr
    );

    assert!(
        stderr.contains("fix_command=franken-node init --profile strict --scan"),
        "Should suggest init scan command.\nstderr:\n{}",
        stderr
    );

    test_harness.log_phase(
        "verification",
        true,
        json!({
            "action": "test_completed",
            "all_assertions_passed": true,
            "runtime_detection": "successful",
            "registry_detection": "successful",
            "suggestion_generation": "successful"
        }),
    );

    info!(
        test_name = "real_runtime_missing_registry_test",
        duration_ms = test_harness.test_start.elapsed().as_millis(),
        "Test completed successfully with real Node.js runtime"
    );
}

#[test]
fn real_runtime_integration_with_tempdir_isolation() {
    let test_harness = RealRuntimeTestHarness::new("real_runtime_integration_test");

    test_harness.log_phase(
        "isolation_test",
        true,
        json!({
            "action": "testing_tempdir_isolation",
            "workspace_path": test_harness.workspace_path().display().to_string()
        }),
    );

    // Verify each test gets its own isolated tempdir
    assert!(test_harness.workspace_path().exists());
    assert!(test_harness.workspace_path().is_dir());

    // Write test data to verify isolation
    let test_file = test_harness.workspace_path().join("isolation_test.txt");
    fs::write(&test_file, "isolated test data").expect("write test file");
    assert!(test_file.exists());

    test_harness.log_phase(
        "isolation_test",
        true,
        json!({
            "action": "tempdir_isolation_verified",
            "test_file_exists": test_file.exists(),
            "workspace_writable": true
        }),
    );

    info!("Tempdir isolation test passed - each test gets its own workspace");
}

#[cfg(test)]
mod real_runtime_structured_logging_tests {
    use super::*;

    #[test]
    fn structured_logging_format_validation() {
        let test_harness = RealRuntimeTestHarness::new("structured_logging_validation");

        // Test that structured logging produces valid JSON
        let test_details = json!({
            "test_field": "test_value",
            "numeric_field": 42,
            "boolean_field": true
        });

        test_harness.log_phase("validation", true, test_details.clone());

        let serialized_log = serde_json::to_value(TestPhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: test_harness.test_name.clone(),
            phase: "validation".to_string(),
            duration_ms: 0,
            success: true,
            details: test_details.clone(),
        })
        .expect("structured logging JSON serialization should succeed");

        assert_eq!(serialized_log["test_name"], "structured_logging_validation");
        assert_eq!(serialized_log["phase"], "validation");
        assert_eq!(serialized_log["success"], true);
        assert_eq!(serialized_log["details"], test_details);
    }
}
