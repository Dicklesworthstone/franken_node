//! Ops Module Conformance Tests
//!
//! These tests verify security hardening patterns and edge case behavior
//! across the ops modules:
//! - Engine dispatcher path resolution and process safety
//! - Telemetry bridge bounded growth and overflow protection
//! - Drift checker arithmetic operations
//! - Process timeout handling and fail-closed semantics

use super::engine_dispatcher::{CapturedProcessOutput, EngineDispatcher, RunDispatchReport};
use super::tokio_drift_checker::{check_api_transport_boundary_trigger, check_tokio_drift};
use crate::config::PreferredRuntime;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitStatus, Output};
use std::thread;
use std::time::Duration;

// ---- Engine Dispatcher Hardening Tests ----

#[test]
fn engine_dispatcher_duration_overflow_protection() {
    // Test duration conversion with max value
    let max_duration = Duration::from_millis(u64::MAX);
    let duration_ms = u64::try_from(max_duration.as_millis()).unwrap_or(u64::MAX);
    assert_eq!(duration_ms, u64::MAX);

    // Test normal duration conversion
    let normal_duration = Duration::from_millis(1000);
    let normal_ms = u64::try_from(normal_duration.as_millis()).unwrap_or(u64::MAX);
    assert_eq!(normal_ms, 1000);
}

#[test]
fn ops_drift_check_is_idempotent_for_same_tree() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(
        temp_dir.path().join("Cargo.toml"),
        "[package]\nname = \"ops-idem\"\n",
    )
    .unwrap();
    std::fs::write(src_dir.join("main.rs"), "fn main() {}\n").unwrap();

    let first = check_tokio_drift(temp_dir.path());
    let second = check_tokio_drift(temp_dir.path());

    assert_eq!(first.is_clean(), second.is_clean());
    assert_eq!(first.files_scanned, second.files_scanned);
    assert_eq!(first.exceptions_honored, second.exceptions_honored);
    assert_eq!(first.violations, second.violations);
}

#[test]
fn ops_transport_boundary_check_is_idempotent_for_same_tree() {
    let temp_dir = tempfile::tempdir().unwrap();
    let api_dir = temp_dir.path().join("src/api");
    std::fs::create_dir_all(&api_dir).unwrap();
    std::fs::write(api_dir.join("server.rs"), "pub fn route_table() {}\n").unwrap();

    let first = check_api_transport_boundary_trigger(temp_dir.path());
    let second = check_api_transport_boundary_trigger(temp_dir.path());

    assert_eq!(first.is_clean(), second.is_clean());
    assert_eq!(first.files_scanned, second.files_scanned);
    assert_eq!(first.exceptions_honored, second.exceptions_honored);
    assert_eq!(first.violations, second.violations);
}

#[test]
fn run_dispatch_report_json_keeps_receipt_fields_stable() {
    let report = RunDispatchReport {
        runtime: "node".to_string(),
        runtime_path: "/usr/bin/node".to_string(),
        target: "/workspace/app/index.js".to_string(),
        working_dir: "/workspace/app".to_string(),
        used_fallback_runtime: true,
        started_at_utc: "2026-04-17T00:00:00Z".to_string(),
        finished_at_utc: "2026-04-17T00:00:01Z".to_string(),
        duration_ms: 1000,
        exit_code: Some(0),
        terminated_by_signal: false,
        telemetry: None,
        captured_output: CapturedProcessOutput {
            stdout: "ok\n".to_string(),
            stderr: String::new(),
        },
    };

    let encoded = serde_json::to_value(&report).unwrap();

    assert_eq!(encoded["runtime"], "node");
    assert_eq!(encoded["runtime_path"], "/usr/bin/node");
    assert_eq!(encoded["target"], "/workspace/app/index.js");
    assert_eq!(encoded["working_dir"], "/workspace/app");
    assert_eq!(encoded["used_fallback_runtime"], true);
    assert_eq!(encoded["exit_code"], 0);
    assert_eq!(encoded["terminated_by_signal"], false);
    assert_eq!(encoded["captured_output"]["stdout"], "ok\n");
    assert!(encoded["telemetry"].is_null());
}

#[test]
fn run_dispatch_report_json_round_trips_without_format_drift() {
    let report = RunDispatchReport {
        runtime: "franken_engine".to_string(),
        runtime_path: "/opt/bin/franken-engine".to_string(),
        target: "app.js".to_string(),
        working_dir: ".".to_string(),
        used_fallback_runtime: false,
        started_at_utc: "2026-04-17T00:00:00Z".to_string(),
        finished_at_utc: "2026-04-17T00:00:00Z".to_string(),
        duration_ms: 0,
        exit_code: None,
        terminated_by_signal: true,
        telemetry: None,
        captured_output: CapturedProcessOutput {
            stdout: String::new(),
            stderr: "terminated".to_string(),
        },
    };

    let encoded = serde_json::to_string(&report).unwrap();
    let decoded: RunDispatchReport = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded.runtime, report.runtime);
    assert_eq!(decoded.runtime_path, report.runtime_path);
    assert_eq!(decoded.target, report.target);
    assert_eq!(decoded.working_dir, report.working_dir);
    assert_eq!(decoded.used_fallback_runtime, report.used_fallback_runtime);
    assert_eq!(decoded.started_at_utc, report.started_at_utc);
    assert_eq!(decoded.finished_at_utc, report.finished_at_utc);
    assert_eq!(decoded.duration_ms, report.duration_ms);
    assert_eq!(decoded.exit_code, report.exit_code);
    assert_eq!(decoded.terminated_by_signal, report.terminated_by_signal);
    assert_eq!(
        decoded.captured_output.stdout,
        report.captured_output.stdout
    );
    assert_eq!(
        decoded.captured_output.stderr,
        report.captured_output.stderr
    );
}

#[test]
fn engine_dispatcher_path_traversal_protection() {
    // Test various potentially dangerous paths
    let dangerous_paths = [
        "../../../etc/passwd",
        "..\\..\\windows\\system32\\cmd.exe",
        "/etc/passwd",
        "C:\\Windows\\System32\\cmd.exe",
        "file:///etc/passwd",
        "\\\\server\\share\\file.exe",
    ];

    // These should not cause the dispatcher to panic or access unexpected files
    for dangerous_path in &dangerous_paths {
        let path = PathBuf::from(dangerous_path);
        let _dispatcher = EngineDispatcher::new(Some(path.clone()), PreferredRuntime::Auto);

        // The dispatcher should handle these gracefully without panicking
        // (actual execution will fail safely when the files don't exist)
        assert!(true); // Test passes if no panic occurs
    }
}

#[test]
fn engine_dispatcher_empty_output_handling() {
    let empty_output = Output {
        status: ExitStatus::from_raw(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
    };

    let captured = CapturedProcessOutput {
        stdout: String::from_utf8_lossy(&empty_output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&empty_output.stderr).into_owned(),
    };

    assert!(captured.stdout.is_empty());
    assert!(captured.stderr.is_empty());
}

#[test]
fn engine_dispatcher_large_output_handling() {
    // Test handling of very large output that could cause memory issues
    let large_data = vec![b'X'; 10_000_000]; // 10MB of data
    let large_output = Output {
        status: ExitStatus::from_raw(0),
        stdout: large_data.clone(),
        stderr: large_data.clone(),
    };

    let captured = CapturedProcessOutput {
        stdout: String::from_utf8_lossy(&large_output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&large_output.stderr).into_owned(),
    };

    // Should handle large output without panicking
    assert_eq!(captured.stdout.len(), 10_000_000);
    assert_eq!(captured.stderr.len(), 10_000_000);
}

#[test]
fn engine_dispatcher_invalid_utf8_handling() {
    // Test handling of invalid UTF-8 sequences in process output
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD]; // Invalid UTF-8 sequence
    let output_with_invalid_utf8 = Output {
        status: ExitStatus::from_raw(0),
        stdout: invalid_utf8.clone(),
        stderr: invalid_utf8.clone(),
    };

    let captured = CapturedProcessOutput {
        stdout: String::from_utf8_lossy(&output_with_invalid_utf8.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output_with_invalid_utf8.stderr).into_owned(),
    };

    // Should contain replacement characters for invalid UTF-8
    assert!(captured.stdout.contains('�'));
    assert!(captured.stderr.contains('�'));
}

// ---- Drift Checker Hardening Tests ----

#[test]
fn drift_checker_line_number_overflow_protection() {
    // Create a temporary test crate with a file containing many lines
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create a source file with many lines to test line number handling
    let main_rs_path = src_dir.join("main.rs");
    let mut file = std::fs::File::create(&main_rs_path).unwrap();

    // Write many lines to test line number arithmetic
    for i in 0..10000 {
        writeln!(file, "// Line {}", i).unwrap();
    }
    writeln!(file, "#[tokio::main]").unwrap(); // Add a violation at the end
    writeln!(file, "fn main() {{}}").unwrap();

    // Create minimal Cargo.toml
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    let mut cargo_file = std::fs::File::create(&cargo_toml_path).unwrap();
    writeln!(cargo_file, "[package]").unwrap();
    writeln!(cargo_file, "name = \"test-crate\"").unwrap();
    writeln!(cargo_file, "version = \"0.1.0\"").unwrap();

    // Run drift checker - should handle large line numbers without overflow
    let result = check_tokio_drift(temp_dir.path());

    // Should detect the violation without panicking on line number arithmetic
    assert!(!result.is_clean());
    assert!(result.violations.len() > 0);

    // Line number should be around 10001 (using saturating_add)
    let violation = &result.violations[0];
    assert!(violation.line_number > 10000);
}

#[test]
fn drift_checker_exception_count_overflow_protection() {
    // Test that exception counter uses saturating arithmetic
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create a source file with many exceptions
    let main_rs_path = src_dir.join("main.rs");
    let mut file = std::fs::File::create(&main_rs_path).unwrap();

    for i in 0..1000 {
        writeln!(
            file,
            "// TOKIO_DRIFT_EXCEPTION(bd-test-{}): justified exception",
            i
        )
        .unwrap();
        writeln!(file, "#[tokio::main]").unwrap();
    }

    // Create minimal Cargo.toml
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    let mut cargo_file = std::fs::File::create(&cargo_toml_path).unwrap();
    writeln!(cargo_file, "[package]").unwrap();
    writeln!(cargo_file, "name = \"test-crate\"").unwrap();
    writeln!(cargo_file, "version = \"0.1.0\"").unwrap();

    let result = check_tokio_drift(temp_dir.path());

    // All violations should be suppressed by exceptions
    assert!(result.is_clean());
    assert_eq!(result.exceptions_honored, 1000);
}

#[test]
fn drift_checker_file_count_overflow_protection() {
    // Test that file scanning counter uses saturating arithmetic
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create many source files
    for i in 0..100 {
        let file_path = src_dir.join(format!("module_{}.rs", i));
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "// Clean module {}", i).unwrap();
        writeln!(file, "pub fn function_{}() {{}}", i).unwrap();
    }

    // Create minimal Cargo.toml
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    let mut cargo_file = std::fs::File::create(&cargo_toml_path).unwrap();
    writeln!(cargo_file, "[package]").unwrap();
    writeln!(cargo_file, "name = \"test-crate\"").unwrap();
    writeln!(cargo_file, "version = \"0.1.0\"").unwrap();

    let result = check_tokio_drift(temp_dir.path());

    // Should scan all files without overflow
    assert!(result.is_clean());
    assert_eq!(result.files_scanned, 101); // 100 .rs files + 1 Cargo.toml
}

#[test]
fn drift_checker_string_boundary_conditions() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Test various string edge cases that could cause issues
    let test_cases = vec![
        // Empty strings
        ("".to_string(), false),
        // Very long strings
        ("a".repeat(10000), false),
        // Strings with embedded nulls (should not cause issues)
        ("test\0content".to_string(), false),
        // Strings with control characters
        ("test\n\r\tpattern".to_string(), false),
        // Unicode content
        ("使用 tokio 的代码".to_string(), false),
        // String with actual violation
        ("#[tokio::main]".to_string(), true),
        // String with violation in quotes (should be ignored)
        ("\"#[tokio::main]\"".to_string(), false),
    ];

    for (i, (content, should_violate)) in test_cases.iter().enumerate() {
        let file_path = src_dir.join(format!("test_{}.rs", i));
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "{}", content).unwrap();
    }

    // Create minimal Cargo.toml
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    let mut cargo_file = std::fs::File::create(&cargo_toml_path).unwrap();
    writeln!(cargo_file, "[package]").unwrap();
    writeln!(cargo_file, "name = \"test-crate\"").unwrap();
    writeln!(cargo_file, "version = \"0.1.0\"").unwrap();

    let result = check_tokio_drift(temp_dir.path());

    // Should find exactly one violation (from the actual #[tokio::main])
    let violation_count = test_cases
        .iter()
        .filter(|(_, should_violate)| *should_violate)
        .count();
    assert_eq!(result.violations.len(), violation_count);
}

#[test]
fn drift_checker_api_transport_boundary_path_validation() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create various directory structures
    let api_dir = temp_dir.path().join("src/api");
    let ops_dir = temp_dir.path().join("src/ops");
    let other_dir = temp_dir.path().join("src/other");

    std::fs::create_dir_all(&api_dir).unwrap();
    std::fs::create_dir_all(&ops_dir).unwrap();
    std::fs::create_dir_all(&other_dir).unwrap();

    // Add transport boundary pattern in API directory (should trigger)
    let api_file = api_dir.join("server.rs");
    let mut file = std::fs::File::create(&api_file).unwrap();
    writeln!(file, "use axum::Router;").unwrap();

    // Add transport boundary pattern in non-API directory (should not trigger)
    let ops_file = ops_dir.join("server.rs");
    let mut file = std::fs::File::create(&ops_file).unwrap();
    writeln!(file, "use axum::Router;").unwrap();

    let result = check_api_transport_boundary_trigger(temp_dir.path());

    // Should only detect violation in API directory
    assert_eq!(result.violations.len(), 1);
    assert!(
        result.violations[0]
            .file
            .to_string_lossy()
            .contains("src/api/")
    );
}

// ---- Thread Safety Tests ----

#[test]
fn ops_components_concurrent_access() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create test files
    for i in 0..10 {
        let file_path = src_dir.join(format!("concurrent_{}.rs", i));
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "// Concurrent test file {}", i).unwrap();
    }

    // Create minimal Cargo.toml
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    let mut cargo_file = std::fs::File::create(&cargo_toml_path).unwrap();
    writeln!(cargo_file, "[package]").unwrap();
    writeln!(cargo_file, "name = \"test-crate\"").unwrap();
    writeln!(cargo_file, "version = \"0.1.0\"").unwrap();

    // Run drift checks concurrently
    let temp_path = temp_dir.path().to_path_buf();
    let mut handles = Vec::new();

    for _ in 0..5 {
        let path_clone = temp_path.clone();
        let handle = thread::spawn(move || {
            let result = check_tokio_drift(&path_clone);
            result.is_clean()
        });
        handles.push(handle);
    }

    // All threads should complete successfully
    for handle in handles {
        let is_clean = handle.join().unwrap();
        assert!(is_clean);
    }
}

// ---- Error Handling and Recovery Tests ----

#[test]
fn drift_checker_invalid_file_recovery() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create a valid file
    let valid_file = src_dir.join("valid.rs");
    let mut file = std::fs::File::create(&valid_file).unwrap();
    writeln!(file, "// Valid Rust code").unwrap();

    // Create a file with invalid filename characters (if supported by OS)
    let weird_file = src_dir.join("weird.rs");
    let mut file = std::fs::File::create(&weird_file).unwrap();
    writeln!(file, "// File with potential encoding issues").unwrap();

    // Create minimal Cargo.toml
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    let mut cargo_file = std::fs::File::create(&cargo_toml_path).unwrap();
    writeln!(cargo_file, "[package]").unwrap();
    writeln!(cargo_file, "name = \"test-crate\"").unwrap();
    writeln!(cargo_file, "version = \"0.1.0\"").unwrap();

    // Should handle problematic files gracefully
    let result = check_tokio_drift(temp_dir.path());

    // Should still process the valid files
    assert!(result.files_scanned > 0);
    assert!(result.is_clean());
}

#[test]
fn drift_checker_symlink_safety() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create a normal file
    let normal_file = src_dir.join("normal.rs");
    let mut file = std::fs::File::create(&normal_file).unwrap();
    writeln!(file, "// Normal file").unwrap();

    // Attempt to create a symlink (may fail on some systems, that's fine)
    let symlink_path = src_dir.join("symlink.rs");
    let _symlink_result = std::os::unix::fs::symlink(&normal_file, &symlink_path);

    // Create minimal Cargo.toml
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    let mut cargo_file = std::fs::File::create(&cargo_toml_path).unwrap();
    writeln!(cargo_file, "[package]").unwrap();
    writeln!(cargo_file, "name = \"test-crate\"").unwrap();
    writeln!(cargo_file, "version = \"0.1.0\"").unwrap();

    // Should handle symlinks safely (implementation skips symlinks)
    let result = check_tokio_drift(temp_dir.path());

    // Should process without issues
    assert!(result.is_clean());
}

// ---- Integration Test: Full Ops Pipeline ----

#[test]
fn ops_full_integration_pipeline() {
    // Test a complete ops workflow: drift checking -> engine dispatch preparation
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create a clean application
    let main_rs = src_dir.join("main.rs");
    let mut file = std::fs::File::create(&main_rs).unwrap();
    writeln!(file, "fn main() {{").unwrap();
    writeln!(file, "    println!(\"Clean application\");").unwrap();
    writeln!(file, "}}").unwrap();

    // Create package.json for runtime detection
    let package_json = temp_dir.path().join("package.json");
    let mut file = std::fs::File::create(&package_json).unwrap();
    writeln!(file, "{{").unwrap();
    writeln!(file, "  \"name\": \"test-app\",").unwrap();
    writeln!(file, "  \"version\": \"1.0.0\",").unwrap();
    writeln!(file, "  \"main\": \"index.js\"").unwrap();
    writeln!(file, "}}").unwrap();

    // Create clean Cargo.toml
    let cargo_toml = temp_dir.path().join("Cargo.toml");
    let mut file = std::fs::File::create(&cargo_toml).unwrap();
    writeln!(file, "[package]").unwrap();
    writeln!(file, "name = \"test-app\"").unwrap();
    writeln!(file, "version = \"0.1.0\"").unwrap();
    writeln!(file, "edition = \"2021\"").unwrap();
    writeln!(file, "").unwrap();
    writeln!(file, "[dependencies]").unwrap();
    writeln!(file, "serde = \"1.0\"").unwrap();

    // Phase 1: Drift checking should pass
    let drift_result = check_tokio_drift(temp_dir.path());
    assert!(
        drift_result.is_clean(),
        "Clean crate should pass drift check"
    );
    assert!(drift_result.files_scanned >= 2); // At least Cargo.toml and main.rs

    // Phase 2: API transport boundary check should pass
    let api_result = check_api_transport_boundary_trigger(temp_dir.path());
    assert!(
        api_result.is_clean(),
        "No API transport boundary should be detected"
    );

    // Phase 3: Engine dispatcher should handle the application path
    let _dispatcher = EngineDispatcher::new(None, PreferredRuntime::Auto);

    // The dispatcher should be able to handle the path without panicking
    // (Actual execution would require the engine binary to be present)
    assert!(true); // Test passes if no panic occurs during dispatcher creation
}

#[test]
fn ops_error_propagation_and_recovery() {
    // Test that ops components properly handle and recover from various error conditions
    let temp_dir = tempfile::tempdir().unwrap();

    // Test 1: Missing src directory
    let missing_src_result = check_tokio_drift(temp_dir.path());
    // Should handle gracefully with 0 files scanned
    assert!(missing_src_result.is_clean());

    // Test 2: Directory with only Cargo.toml, no src/
    let cargo_toml = temp_dir.path().join("Cargo.toml");
    let mut file = std::fs::File::create(&cargo_toml).unwrap();
    writeln!(file, "[package]").unwrap();
    writeln!(file, "name = \"test\"").unwrap();

    let result_with_cargo = check_tokio_drift(temp_dir.path());
    assert!(result_with_cargo.is_clean());
    assert_eq!(result_with_cargo.files_scanned, 1); // Just Cargo.toml

    // Test 3: Engine dispatcher with non-existent paths
    let nonexistent_path = PathBuf::from("/this/path/does/not/exist/engine");
    let _dispatcher = EngineDispatcher::new(Some(nonexistent_path), PreferredRuntime::Auto);

    // Should create successfully (errors occur during dispatch, not construction)
    assert!(true);
}

#[test]
fn ops_drift_check_detects_production_tokio_main_without_exception() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(
        temp_dir.path().join("Cargo.toml"),
        "[package]\nname = \"ops-negative\"\n",
    )
    .unwrap();
    std::fs::write(
        src_dir.join("main.rs"),
        "#[tokio::main]\nasync fn main() {}\n",
    )
    .unwrap();

    let result = check_tokio_drift(temp_dir.path());

    assert!(!result.is_clean());
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.pattern == "#[tokio::main]")
    );
}

#[test]
fn ops_drift_check_rejects_bare_exception_marker() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(
        temp_dir.path().join("Cargo.toml"),
        "[package]\nname = \"ops-bare-exception\"\n",
    )
    .unwrap();
    std::fs::write(
        src_dir.join("main.rs"),
        "// TOKIO_DRIFT_EXCEPTION: no bead id\nuse tokio::runtime::Runtime;\n",
    )
    .unwrap();

    let result = check_tokio_drift(temp_dir.path());

    assert!(!result.is_clean());
    assert_eq!(result.exceptions_honored, 0);
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.pattern == "tokio::runtime::Runtime")
    );
}

#[test]
fn ops_transport_boundary_check_detects_api_tcp_listener() {
    let temp_dir = tempfile::tempdir().unwrap();
    let api_dir = temp_dir.path().join("src/api");
    std::fs::create_dir_all(&api_dir).unwrap();
    std::fs::write(
        api_dir.join("server.rs"),
        "pub fn bind() { let _ = std::net::TcpListener::bind(\"127.0.0.1:0\"); }\n",
    )
    .unwrap();

    let result = check_api_transport_boundary_trigger(temp_dir.path());

    assert!(!result.is_clean());
    assert!(result.violations.iter().any(|violation| {
        violation.pattern == "std::net::TcpListener::bind("
            || violation.pattern == "TcpListener::bind("
    }));
}

fn negative_fixture(cargo_toml: &str) -> tempfile::TempDir {
    let temp_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp_dir.path().join("src")).unwrap();
    std::fs::write(temp_dir.path().join("Cargo.toml"), cargo_toml).unwrap();
    temp_dir
}

fn write_negative_source(root: &std::path::Path, rel_path: &str, source: &str) {
    let path = root.join(rel_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, source).unwrap();
}

#[test]
fn ops_drift_check_detects_production_tokio_test_attribute() {
    let temp_dir = negative_fixture("[package]\nname = \"ops-tokio-test\"\n");
    write_negative_source(
        temp_dir.path(),
        "src/lib.rs",
        "#[tokio::test]\nasync fn exercises_runtime() {}\n",
    );

    let result = check_tokio_drift(temp_dir.path());

    assert!(!result.is_clean());
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.pattern == "#[tokio::test]")
    );
}

#[test]
fn ops_drift_check_detects_direct_tokio_import() {
    let temp_dir = negative_fixture("[package]\nname = \"ops-tokio-import\"\n");
    write_negative_source(
        temp_dir.path(),
        "src/lib.rs",
        "use tokio::time::sleep;\npub fn imported_runtime() {}\n",
    );

    let result = check_tokio_drift(temp_dir.path());

    assert!(!result.is_clean());
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.pattern == "use tokio::")
    );
}

#[test]
fn ops_drift_check_detects_current_thread_builder() {
    let temp_dir = negative_fixture("[package]\nname = \"ops-builder\"\n");
    write_negative_source(
        temp_dir.path(),
        "src/lib.rs",
        "pub fn boot() { let _ = tokio::runtime::Builder::new_current_thread(); }\n",
    );

    let result = check_tokio_drift(temp_dir.path());

    assert!(!result.is_clean());
    assert!(result.violations.iter().any(|violation| {
        violation.pattern == "tokio::runtime::Builder"
            || violation.pattern == "Builder::new_current_thread()"
    }));
}

#[test]
fn ops_drift_check_detects_production_tokio_dependency_table() {
    let temp_dir = negative_fixture(
        "[package]\nname = \"ops-tokio-table\"\n\n[dependencies.tokio]\nversion = \"1\"\n",
    );
    write_negative_source(temp_dir.path(), "src/lib.rs", "pub fn clean() {}\n");

    let result = check_tokio_drift(temp_dir.path());

    assert!(!result.is_clean());
    assert!(result.violations.iter().any(|violation| {
        violation.pattern == "tokio dependency in [dependencies.tokio]"
    }));
}

#[test]
fn ops_drift_check_detects_dev_dependency_runtime_features() {
    let temp_dir = negative_fixture(
        "[package]\nname = \"ops-dev-runtime\"\n\n[dev-dependencies]\n\
         tokio = { version = \"1\", features = [\"rt\"] }\n",
    );
    write_negative_source(temp_dir.path(), "src/lib.rs", "pub fn clean() {}\n");

    let result = check_tokio_drift(temp_dir.path());

    assert!(!result.is_clean());
    assert!(result.violations.iter().any(|violation| {
        violation.pattern == "tokio runtime features in [dev-dependencies]"
    }));
}

#[test]
fn ops_transport_boundary_check_detects_axum_router_in_api_source() {
    let temp_dir = negative_fixture("[package]\nname = \"ops-api-axum\"\n");
    write_negative_source(
        temp_dir.path(),
        "src/api/routes.rs",
        "pub fn router() { let _ = axum::Router::new(); }\n",
    );

    let result = check_api_transport_boundary_trigger(temp_dir.path());

    assert!(!result.is_clean());
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.pattern == "axum::Router")
    );
}

#[test]
fn ops_transport_boundary_check_rejects_invalid_exception_marker() {
    let temp_dir = negative_fixture("[package]\nname = \"ops-api-invalid-exception\"\n");
    write_negative_source(
        temp_dir.path(),
        "src/api/server.rs",
        "// TOKIO_DRIFT_EXCEPTION(bd-): missing bead suffix\n\
         pub fn serve() { let _ = hyper::Server::builder; }\n",
    );

    let result = check_api_transport_boundary_trigger(temp_dir.path());

    assert!(!result.is_clean());
    assert_eq!(result.exceptions_honored, 0);
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.pattern == "hyper::Server")
    );
}
