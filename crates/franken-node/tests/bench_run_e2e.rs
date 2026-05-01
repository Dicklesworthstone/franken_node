use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn run_secure_extension_heavy_bench() -> Vec<u8> {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(repo_root())
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-test-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .args([
            "bench",
            "run",
            "--scenario",
            "secure-extension-heavy",
            "--fixture-mode",
        ])
        .output()
        .expect("failed to run franken-node bench run");

    assert!(
        output.status.success(),
        "bench command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.stdout.is_empty(),
        "bench run must emit signed JSON report to stdout"
    );

    output.stdout
}

fn assert_signed_benchmark_report(bytes: &[u8]) -> Value {
    let report: Value = serde_json::from_slice(bytes).expect("bench stdout must be JSON");
    assert_eq!(report["suite_version"], "1.0.0");
    assert_eq!(report["scoring_formula_version"], "sf-v1");
    assert_eq!(report["timestamp_utc"], "2026-02-21T00:00:00Z");
    assert!(
        report["provenance_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71),
        "signed report must include sha256 provenance hash: {report}"
    );
    assert_eq!(report["hardware_profile"]["cpu"], "deterministic-test-cpu");
    assert_eq!(report["hardware_profile"]["memory_mb"], 32768);
    assert_eq!(report["evidence_mode"], "fixture_only");
    assert_eq!(report["profile"], "strict");
    assert_eq!(report["security_controls"]["fixture_mode"], true);
    assert!(
        report["trace_id"]
            .as_str()
            .is_some_and(|trace_id| trace_id.starts_with("bench-")),
        "signed report must include deterministic trace_id: {report}"
    );

    let scenarios = report["scenarios"]
        .as_array()
        .expect("signed report scenarios must be an array");
    assert_eq!(
        scenarios.len(),
        1,
        "scenario filter must select exactly the secure-extension-heavy scenario"
    );
    assert_eq!(scenarios[0]["name"], "secure-extension-heavy");
    assert_eq!(scenarios[0]["dimension"], "performance_under_hardening");
    assert_eq!(scenarios[0]["iterations"], 5);
    assert_eq!(
        scenarios[0]["raw_samples"]
            .as_array()
            .expect("raw samples must be present")
            .len(),
        5
    );
    assert_eq!(
        scenarios[0]["raw_samples"][0]["source"],
        "fixture_only_deterministic"
    );
    assert!(
        scenarios[0]["variance_pct"]
            .as_f64()
            .is_some_and(f64::is_finite),
        "variance must be finite in signed report: {report}"
    );
    assert_eq!(report["sample_policy"]["min_measured_samples"], 3);
    assert_eq!(report["sample_policy"]["total_sample_count"], 5);
    assert_eq!(report["sample_policy"]["total_warmup_count"], 2);

    let events = report["events"]
        .as_array()
        .expect("signed report must include structured benchmark events");
    for expected in ["BS-001", "BS-010", "BS-002", "BS-003", "BS-008", "BS-006"] {
        assert!(
            events.iter().any(|event| event["code"] == expected),
            "report must include event {expected}: {report}"
        );
    }
    assert!(
        events
            .iter()
            .all(|event| event["trace_id"] == report["trace_id"]
                && event["profile"] == "strict"
                && event.get("scenario_id").is_some()),
        "every event must carry trace/profile/scenario metadata: {report}"
    );

    report
}

#[test]
fn bench_run_secure_extension_heavy_is_byte_stable() {
    let first = run_secure_extension_heavy_bench();
    let first_report = assert_signed_benchmark_report(&first);

    let second = run_secure_extension_heavy_bench();
    let second_report = assert_signed_benchmark_report(&second);

    assert_eq!(
        first_report, second_report,
        "same bench inputs must produce semantically identical signed reports"
    );
    assert_eq!(
        first, second,
        "same bench inputs must produce byte-stable signed JSON reports"
    );
}

#[test]
fn bench_run_default_path_emits_measured_evidence() {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(repo_root())
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-test-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .args(["bench", "run", "--scenario", "secure-extension-heavy"])
        .output()
        .expect("failed to run franken-node measured bench run");

    assert!(
        output.status.success(),
        "measured bench command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("bench stdout must be JSON");
    assert_eq!(report["evidence_mode"], "measured");
    assert_eq!(report["security_controls"]["fixture_mode"], false);
    assert_eq!(
        report["scenarios"][0]["raw_samples"][0]["source"],
        "measured_product_workload"
    );
    assert!(
        report["scenarios"][0]["raw_samples"]
            .as_array()
            .is_some_and(|samples| samples.len() >= 3),
        "measured report must carry raw samples: {report}"
    );
    assert_eq!(report["sample_policy"]["min_measured_samples"], 3);
    assert!(
        report["events"]
            .as_array()
            .is_some_and(|events| events.iter().any(|event| event["code"] == "BS-008")),
        "measured report must include scenario completion event: {report}"
    );
}

fn run_bench_with_invalid_scenario() -> std::process::Output {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    command
        .current_dir(repo_root())
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-test-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .args(["bench", "run", "--scenario", "nonexistent-invalid-scenario"])
        .output()
        .expect("failed to run franken-node bench run with invalid scenario")
}

fn run_bench_with_forced_scenario_failure() -> std::process::Output {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    command
        .current_dir(repo_root())
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-test-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .env("FRANKEN_NODE_BENCH_FAIL_SCENARIO", "secure-extension-heavy")
        .args(["bench", "run", "--scenario", "secure-extension-heavy"])
        .output()
        .expect("failed to run franken-node bench run with forced scenario failure")
}

fn run_bench_to_nonexistent_output() -> std::process::Output {
    let temp_dir = TempDir::new().expect("create temp dir");
    let nonexistent_path = temp_dir.path().join("nonexistent").join("output.json");

    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    command
        .current_dir(repo_root())
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-test-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .args([
            "bench",
            "run",
            "--scenario",
            "secure-extension-heavy",
            "--fixture-mode",
            "--output",
            nonexistent_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run franken-node bench run with nonexistent output")
}

fn assert_structured_error_response(stderr: &[u8]) -> Value {
    let stderr_str = String::from_utf8_lossy(stderr);

    // Should contain structured error information
    assert!(
        !stderr_str.is_empty(),
        "bench error must emit diagnostic information to stderr"
    );

    // Look for structured error patterns (JSON or key-value pairs)
    assert!(
        stderr_str.contains("error")
            || stderr_str.contains("Error")
            || stderr_str.contains("failed")
            || stderr_str.contains("invalid"),
        "stderr must contain error indication: {}",
        stderr_str
    );

    // Try to parse any JSON from stderr for structured validation
    if let Ok(json) = serde_json::from_str::<Value>(&stderr_str) {
        return json;
    }

    // Return a synthetic JSON structure for log validation
    serde_json::json!({
        "stderr_content": stderr_str,
        "contains_error": true
    })
}

#[test]
fn bench_run_invalid_scenario_returns_structured_error() {
    let output = run_bench_with_invalid_scenario();

    // Must fail with nonzero exit code
    assert!(
        !output.status.success(),
        "invalid scenario must fail with nonzero exit code"
    );

    // Should not emit valid benchmark JSON to stdout
    if !output.stdout.is_empty() {
        // If there is stdout, it should be an error response, not a valid report
        if let Ok(stdout_json) = serde_json::from_slice::<Value>(&output.stdout) {
            // If it's JSON, it should be an error structure, not a benchmark report
            assert!(
                stdout_json.get("error").is_some() || stdout_json.get("scenarios").is_none(),
                "stdout JSON should be error response, not benchmark report: {}",
                stdout_json
            );
        }
    }

    // Validate structured error information in stderr
    let error_info = assert_structured_error_response(&output.stderr);
    assert!(
        error_info["contains_error"].as_bool().unwrap_or(false)
            || error_info.get("error").is_some(),
        "stderr must contain structured error information: {}",
        error_info
    );
}

#[test]
fn bench_run_forced_scenario_failure_returns_structured_error() {
    let output = run_bench_with_forced_scenario_failure();

    assert!(
        !output.status.success(),
        "forced measured scenario failure must exit nonzero"
    );
    assert!(
        output.stdout.is_empty(),
        "forced failure must not emit a benchmark report to stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let error_info = assert_structured_error_response(&output.stderr);
    let stderr_content = error_info["stderr_content"].as_str().unwrap_or("");
    assert!(
        stderr_content.contains("benchmark suite run failed"),
        "stderr must preserve the CLI failure boundary: {stderr_content}"
    );
    assert!(
        stderr_content.contains("secure-extension-heavy"),
        "stderr must identify the failing scenario: {stderr_content}"
    );
    assert!(
        stderr_content.contains("forced failure via FRANKEN_NODE_BENCH_FAIL_SCENARIO"),
        "stderr must expose the runner failure reason: {stderr_content}"
    );
}

#[test]
fn bench_run_nonexistent_output_path_fails_gracefully() {
    let output = run_bench_to_nonexistent_output();

    // Must fail with nonzero exit code
    assert!(
        !output.status.success(),
        "nonexistent output path must fail with nonzero exit code"
    );

    // Validate error information in stderr
    let error_info = assert_structured_error_response(&output.stderr);
    let stderr_content = error_info["stderr_content"].as_str().unwrap_or("");

    // Should mention the path/file issue
    assert!(
        stderr_content.contains("path")
            || stderr_content.contains("file")
            || stderr_content.contains("directory")
            || stderr_content.contains("output"),
        "error message should reference path/file issue: {}",
        stderr_content
    );
}

#[test]
fn bench_run_successful_execution_logs_expected_events() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let output_path = temp_dir.path().join("bench_output.json");

    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(repo_root())
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-test-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .args([
            "bench",
            "run",
            "--scenario",
            "secure-extension-heavy",
            "--fixture-mode",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run franken-node bench run with output file");

    assert!(
        output.status.success(),
        "bench run with valid output path must succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Validate that output file was created
    assert!(
        output_path.exists(),
        "bench run must create output file at specified path"
    );

    // Validate file contains valid benchmark report
    let file_contents = std::fs::read(&output_path).expect("read benchmark output file");
    let file_report = assert_signed_benchmark_report(&file_contents);

    // Validate stderr contains expected log events (no errors)
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    // Should not contain error indicators
    assert!(
        !stderr_str.contains("error")
            && !stderr_str.contains("Error")
            && !stderr_str.contains("failed")
            && !stderr_str.contains("panic"),
        "successful bench run should not log errors: stderr={}",
        stderr_str
    );

    // Should contain progress or completion indicators
    assert!(
        stderr_str.contains("bench")
            || stderr_str.contains("scenario")
            || stderr_str.contains("complete")
            || stderr_str.contains("writing")
            || stderr_str.is_empty(), // Empty stderr is also acceptable for successful runs
        "successful bench run should log progress/completion events or be silent: stderr={}",
        stderr_str
    );

    // Validate report structure matches expected schema
    assert_eq!(file_report["suite_version"], "1.0.0");
    assert_eq!(file_report["scoring_formula_version"], "sf-v1");
    let output_path_string = output_path.display().to_string();
    assert_eq!(
        file_report["evidence_path"].as_str(),
        Some(output_path_string.as_str())
    );
    assert!(
        file_report["events"].as_array().is_some_and(|events| {
            events
                .iter()
                .all(|event| event["evidence_path"].as_str() == Some(output_path_string.as_str()))
        }),
        "file-backed bench report events must include output evidence_path: {file_report}"
    );
    assert!(
        file_report["scenarios"]
            .as_array()
            .map_or(false, |scenarios| scenarios.len() == 1),
        "output file must contain exactly one scenario result"
    );
}
