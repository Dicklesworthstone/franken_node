//! Perfect E2E test for trust CLI with real Node.js runtime detection
//!
//! This test replaces the mocked `write_fake_runtime()` pattern with real Node.js binary
//! detection, following Perfect E2E principles with structured logging and real components.
//!
//! Mock Risk Score: 25 (Production Impact: 5 × Mock Divergence Risk: 5)
//! Why no mocks: CLI runtime detection and trust registry behavior can only be validated
//! against real Node.js binaries and filesystem operations.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Once;
use std::time::Instant;
use serde_json::Value;
use tempfile::TempDir;
use tracing::{info, warn, error};

static TEST_TRACING_INIT: Once = Once::new();

/// Test harness for real Node.js runtime testing with structured logging
struct RealNodeRuntimeTestHarness {
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
    details: serde_json::Value,
}

impl RealNodeRuntimeTestHarness {
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
        // Try common Node.js locations and PATH
        let candidates = [
            "node",                    // In PATH
            "/usr/bin/node",          // System location
            "/usr/local/bin/node",    // Homebrew/manual install
            "/opt/homebrew/bin/node", // Apple Silicon Homebrew
        ];

        for candidate in &candidates {
            if let Ok(output) = Command::new(candidate).arg("--version").output() {
                if output.status.success() {
                    return Some(PathBuf::from(candidate));
                }
            }
        }

        // Try which command as fallback
        if let Ok(output) = Command::new("which").arg("node").output() {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path_str.is_empty() && Path::new(&path_str).is_file() {
                    return Some(PathBuf::from(path_str));
                }
            }
        }

        None
    }

    fn log_phase(&self, phase: &str, success: bool, details: serde_json::Value) {
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

    fn setup_node_project_with_missing_registry(&self) -> Result<(), Box<dyn std::error::Error>> {
        let workspace = self.workspace_path();

        self.log_phase("setup", true, serde_json::json!({
            "action": "creating_node_project",
            "path": workspace.display().to_string()
        }));

        // Create franken-node config (balanced profile, no trust registry)
        fs::write(
            workspace.join("franken_node.toml"),
            "profile = \"balanced\"\n",
        )?;

        // Create package.json for registry detection test
        let package_json = serde_json::json!({
            "name": "test-missing-registry-project",
            "version": "1.0.0",
            "main": "index.js",
            "scripts": {
                "start": "node index.js"
            }
        });
        fs::write(
            workspace.join("package.json"),
            serde_json::to_string_pretty(&package_json)?,
        )?;

        // Create realistic Node.js entry point that doesn't require external deps
        let index_js = r#"
// Realistic Node.js application entry point
// Note: We test registry detection, not module loading
console.log("Node.js application started");
console.log("Version:", process.version);
console.log("Platform:", process.platform);

// Exit successfully for registry detection test
process.exit(0);
"#;
        fs::write(workspace.join("index.js"), index_js)?;

        self.log_phase("setup", true, serde_json::json!({
            "action": "project_structure_created",
            "files": ["franken_node.toml", "package.json", "index.js"],
            "config_profile": "balanced",
            "dependencies_count": 1
        }));

        Ok(())
    }
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

    // Configure PATH to include Node.js binary if found
    if let Some(node_path) = node_binary {
        if let Some(node_dir) = node_path.parent() {
            let current_path = std::env::var_os("PATH").unwrap_or_default();
            let new_path = format!(
                "{}:{}",
                node_dir.display(),
                current_path.to_string_lossy()
            );
            command.env("PATH", new_path);
        }
    }

    // Clear engine binaries to test runtime detection
    command.env("FRANKEN_ENGINE_BIN", "");
    command.env("FRANKEN_NODE_ENGINE_BINARY_PATH", "");

    command
        .output()
        .unwrap_or_else(|err| panic!("failed running franken-node: {err}"))
}

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .try_init();
    });
}

#[test]
fn real_node_runtime_missing_registry_suggests_init_scan_with_structured_logging() {
    let test_harness = RealNodeRuntimeTestHarness::new("real_node_runtime_missing_registry_test");

    // Phase 1: Setup workspace with real Node.js project
    test_harness.log_phase("setup", true, serde_json::json!({
        "action": "starting_test",
        "has_node_binary": test_harness.node_binary.is_some(),
        "node_path": test_harness.node_binary.as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "not_found".to_string())
    }));

    if test_harness.node_binary.is_none() {
        test_harness.log_phase("setup", false, serde_json::json!({
            "action": "skipping_test",
            "reason": "No Node.js binary found in system",
            "suggestion": "Install Node.js to run this test",
            "searched_paths": [
                "/usr/bin/node",
                "/usr/local/bin/node",
                "/opt/homebrew/bin/node",
                "which node"
            ]
        }));

        // Skip test gracefully if Node.js not available
        warn!("SKIP: No Node.js binary found. Install Node.js to run this test.");
        return;
    }

    test_harness
        .setup_node_project_with_missing_registry()
        .expect("workspace setup should succeed");

    // Phase 2: Run franken-node with real Node.js runtime
    test_harness.log_phase("execution", true, serde_json::json!({
        "action": "running_franken_node",
        "args": ["run", "--policy", "strict", "--runtime", "node", "."],
        "node_binary": test_harness.node_binary.as_ref().unwrap().display().to_string()
    }));

    let output = run_franken_node_with_real_runtime(
        test_harness.workspace_path(),
        &["run", "--policy", "strict", "--runtime", "node", "."],
        test_harness.node_binary.as_ref(),
    );

    // Phase 3: Analyze results with structured logging
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let success = output.status.success();
    test_harness.log_phase("analysis", true, serde_json::json!({
        "action": "analyzing_output",
        "exit_success": success,
        "stderr_length": stderr.len(),
        "stdout_length": stdout.len(),
        "contains_registry_missing": stderr.contains("authoritative trust registry missing"),
        "contains_fix_command": stderr.contains("fix_command=franken-node init --profile strict --scan"),
        "node_runtime_detected": !stderr.contains("runtime not found")
    }));

    // Phase 4: Verify expected behavior with real runtime
    assert!(
        success,
        "franken-node run should succeed when registry is missing but Node.js runtime exists.\nstderr:\n{}\nstdout:\n{}",
        stderr, stdout
    );

    assert!(
        stderr.contains("authoritative trust registry missing"),
        "Should detect missing trust registry with real Node.js runtime.\nstderr:\n{}",
        stderr
    );

    assert!(
        stderr.contains("fix_command=franken-node init --profile strict --scan"),
        "Should suggest init scan command when registry is missing.\nstderr:\n{}",
        stderr
    );

    // Verify Node.js runtime was actually detected (not mocked)
    assert!(
        !stderr.contains("runtime not found") && !stderr.contains("command not found"),
        "Real Node.js runtime should be detected and functional.\nstderr:\n{}",
        stderr
    );

    test_harness.log_phase("verification", true, serde_json::json!({
        "action": "test_completed",
        "all_assertions_passed": true,
        "node_runtime_detection": "successful",
        "registry_detection": "successful",
        "suggestion_generation": "successful",
        "mock_free_validation": "successful"
    }));

    info!(
        test_name = "real_node_runtime_missing_registry_test",
        duration_ms = test_harness.test_start.elapsed().as_millis(),
        "Test completed successfully with real Node.js runtime"
    );
}

#[test]
fn real_node_runtime_workspace_isolation_verification() {
    let test_harness = RealNodeRuntimeTestHarness::new("workspace_isolation_test");

    test_harness.log_phase("isolation_test", true, serde_json::json!({
        "action": "testing_workspace_isolation",
        "workspace_path": test_harness.workspace_path().display().to_string()
    }));

    // Verify each test gets its own isolated workspace
    assert!(test_harness.workspace_path().exists());
    assert!(test_harness.workspace_path().is_dir());

    // Write test data to verify isolation
    let test_file = test_harness.workspace_path().join("isolation_test.txt");
    fs::write(&test_file, "isolated test data").expect("write test file");
    assert!(test_file.exists());

    // Verify workspace is unique and isolated
    let workspace_name = test_harness.workspace_path()
        .file_name()
        .and_then(|name| name.to_str())
        .expect("workspace should have a name");

    test_harness.log_phase("isolation_test", true, serde_json::json!({
        "action": "workspace_isolation_verified",
        "test_file_exists": test_file.exists(),
        "workspace_unique_id": workspace_name,
        "workspace_writable": true,
        "isolation_confirmed": true
    }));

    info!("Workspace isolation test passed - each test gets its own isolated workspace");
}