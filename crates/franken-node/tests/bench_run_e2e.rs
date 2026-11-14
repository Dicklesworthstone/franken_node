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
        "bench run must emit JSON provenance_hash report to stdout"
    );

    output.stdout
}

fn assert_provenance_hash_benchmark_report(bytes: &[u8]) -> Value {
    let report: Value = serde_json::from_slice(bytes).expect("bench stdout must be JSON");
    assert_eq!(report["suite_version"], "1.0.0");
    assert_eq!(report["scoring_formula_version"], "sf-v1");
    assert_eq!(report["timestamp_utc"], "2026-02-21T00:00:00Z");
    assert!(
        report["provenance_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71),
        "provenance_hash report must include sha256 content hash: {report}"
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
        "provenance_hash report must include deterministic trace_id: {report}"
    );

    let scenarios = report["scenarios"]
        .as_array()
        .expect("provenance_hash report scenarios must be an array");
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
        "variance must be finite in provenance_hash report: {report}"
    );
    assert_eq!(report["sample_policy"]["min_measured_samples"], 3);
    assert_eq!(
        report["sample_policy"]["max_raw_samples_per_scenario"],
        4096
    );
    assert_eq!(report["sample_policy"]["total_sample_count"], 5);
    assert_eq!(report["sample_policy"]["total_warmup_count"], 2);

    let events = report["events"]
        .as_array()
        .expect("provenance_hash report must include structured benchmark events");
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
fn bench_run_honors_json_flag() {
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
            "--json",
        ])
        .output()
        .expect("failed to run franken-node bench run --json");

    assert!(
        output.status.success(),
        "bench --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = assert_provenance_hash_benchmark_report(&output.stdout);
    assert_eq!(report["evidence_mode"], "fixture_only");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("benchmark suite:"),
        "bench --json must suppress the human summary on stderr: {stderr}"
    );
}

#[test]
fn bench_run_secure_extension_heavy_is_byte_stable() {
    let first = run_secure_extension_heavy_bench();
    let first_report = assert_provenance_hash_benchmark_report(&first);

    let second = run_secure_extension_heavy_bench();
    let second_report = assert_provenance_hash_benchmark_report(&second);

    assert_eq!(
        first_report, second_report,
        "same bench inputs must produce semantically identical provenance_hash reports"
    );
    assert_eq!(
        first, second,
        "same bench inputs must produce byte-stable provenance_hash JSON reports"
    );
}

#[test]
fn bench_run_default_path_requires_complete_live_runtime_triad() {
    let workspace = TempDir::new().expect("create benchmark workspace");
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(workspace.path())
        .args(["bench", "run", "--json", "--node-bin"])
        .arg(workspace.path().join("missing-node"))
        .arg("--bun-bin")
        .arg(workspace.path().join("missing-bun"))
        .args(["--output", "bench.json"])
        .output()
        .expect("invoke default live benchmark without reference runtimes");

    assert!(
        !output.status.success(),
        "an incomplete runtime population must never become measured evidence"
    );
    let report: Value = serde_json::from_slice(&output.stdout)
        .expect("live benchmark refusal must be machine-readable");
    assert_eq!(report["schema_version"], "franken-node/bench-run-error/v1");
    assert_eq!(report["command"], "bench.run");
    assert_eq!(report["ok"], false);
    assert_eq!(report["fixture_mode"], false);
    assert!(report.get("aggregate_score").is_none());
    assert!(report.get("provenance_hash").is_none());
    assert!(
        !workspace.path().join("bench.json").exists(),
        "a failed live campaign must not publish a success artifact"
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

fn run_bench_with_legacy_scenario_without_fixture_opt_in() -> std::process::Output {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    command
        .current_dir(repo_root())
        .args(["bench", "run", "--scenario", "secure-extension-heavy"])
        .output()
        .expect("invoke legacy benchmark scenario without fixture opt-in")
}

fn run_bench_with_traversal_output() -> std::process::Output {
    let temp_dir = TempDir::new().expect("create temp dir");

    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    command
        .current_dir(temp_dir.path())
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
            "../bench-output.json",
        ])
        .output()
        .expect("failed to run franken-node bench run with traversal output")
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
fn bench_run_invalid_scenario_json_emits_error_report() {
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
            "nonexistent-invalid-scenario",
            "--json",
        ])
        .output()
        .expect("failed to run franken-node bench run --json with invalid scenario");

    assert!(
        !output.status.success(),
        "invalid scenario --json must fail with nonzero exit"
    );
    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("bench --json failure stdout must be JSON");
    assert_eq!(payload["schema_version"], "franken-node/bench-run-error/v1");
    assert_eq!(payload["command"], "bench.run");
    assert_eq!(payload["ok"], false);
    assert_eq!(payload["scenario"], "nonexistent-invalid-scenario");
    let error = payload["error"]
        .as_str()
        .expect("error field must be a string");
    assert!(
        error.contains("benchmark suite run failed"),
        "error must preserve the CLI failure boundary: {error}"
    );
    assert!(
        error.contains("nonexistent-invalid-scenario") || error.contains("unknown scenario"),
        "error must identify the invalid scenario: {error}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Error: benchmark suite run failed"),
        "--json must not append a second human Error line after the JSON report: {stderr}"
    );
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
fn bench_run_legacy_scenario_requires_explicit_fixture_opt_in() {
    let output = run_bench_with_legacy_scenario_without_fixture_opt_in();

    assert!(
        !output.status.success(),
        "a legacy synthetic scenario cannot become live runtime evidence"
    );
    assert!(
        output.stdout.is_empty(),
        "refusal must not emit a benchmark report: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("benchmark suite run failed")
            && stderr.contains("secure-extension-heavy")
            && stderr.contains("--fixture-mode"),
        "the error must name the scenario and its explicit fixture-only mode: {stderr}"
    );
}

#[test]
fn bench_run_traversal_output_path_fails_at_cli_boundary() {
    let output = run_bench_with_traversal_output();

    // Must fail with nonzero exit code
    assert!(
        !output.status.success(),
        "traversal output path must fail with nonzero exit code"
    );

    // Validate error information in stderr
    let error_info = assert_structured_error_response(&output.stderr);
    let stderr_content = error_info["stderr_content"].as_str().unwrap_or("");

    assert!(
        stderr_content.contains("Invalid content path")
            || stderr_content.contains("path traversal")
            || stderr_content.contains("invalid value"),
        "error message should reference CLI path validation: {}",
        stderr_content
    );
}

#[test]
fn bench_run_successful_execution_logs_expected_events() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let output_path = temp_dir.path().join("bench_output.json");

    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(temp_dir.path())
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
            "bench_output.json",
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
    let file_report = assert_provenance_hash_benchmark_report(&file_contents);

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
    assert_eq!(
        file_report["evidence_path"].as_str(),
        Some("bench_output.json")
    );
    assert!(
        file_report["events"].as_array().is_some_and(|events| {
            events
                .iter()
                .all(|event| event["evidence_path"].as_str() == Some("bench_output.json"))
        }),
        "file-backed bench report events must include output evidence_path: {file_report}"
    );
    assert!(
        file_report["scenarios"]
            .as_array()
            .is_some_and(|scenarios| scenarios.len() == 1),
        "output file must contain exactly one scenario result"
    );
}

#[test]
fn bench_run_live_options_reject_fixture_mode_and_invalid_budgets() {
    let cases: &[&[&str]] = &[
        &["--samples", "2"],
        &["--samples", "4097"],
        &["--warmups", "129"],
        &["--timeout-ms", "0"],
        &["--timeout-ms", "300001"],
        &["--budget-ms", "0"],
        &["--budget-ms", "3600001"],
        &["--fixture-mode", "--samples", "3"],
        &["--fixture-mode", "--warmups", "0"],
        &["--fixture-mode", "--timeout-ms", "1000"],
        &["--fixture-mode", "--budget-ms", "1000"],
        &["--fixture-mode", "--seed", "42"],
        &["--fixture-mode", "--node-bin", "/not-executed-node"],
        &["--fixture-mode", "--bun-bin", "/not-executed-bun"],
    ];
    for flags in cases {
        let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
        let output = command
            .args(["bench", "run", "--json"])
            .args(*flags)
            .output()
            .expect("invoke invalid benchmark options");
        assert!(
            !output.status.success(),
            "invalid or conflicting options must fail before runtime discovery: {flags:?}"
        );
        let error: Value = serde_json::from_slice(&output.stdout)
            .expect("benchmark option errors must retain the JSON CLI contract");
        assert_eq!(error["schema_version"], "franken-node/bench-run-error/v1");
        assert_eq!(error["command"], "bench.run");
        assert_eq!(error["ok"], false);
        assert!(error["error"].as_str().is_some_and(|text| !text.is_empty()));
        assert!(error.get("legs").is_none());
        assert!(error.get("provenance_hash").is_none());
    }
}

#[cfg(all(feature = "engine", target_os = "linux"))]
fn reference_runtime_on_path(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;

    let search_path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&search_path) {
        let candidate = directory.join(name);
        if let Ok(metadata) = candidate.metadata()
            && metadata.is_file()
            && metadata.permissions().mode() & 0o111 != 0
        {
            return candidate.canonicalize().ok();
        }
    }
    None
}

#[cfg(all(feature = "engine", target_os = "linux"))]
#[test]
fn bench_run_live_triad_records_real_runtimes_or_refuses_missing_references() {
    let workspace = TempDir::new().expect("create live benchmark workspace");
    let node = reference_runtime_on_path("node");
    let bun = reference_runtime_on_path("bun");
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    command
        .current_dir(workspace.path())
        .timeout(std::time::Duration::from_secs(150))
        .args([
            "bench",
            "run",
            "--scenario",
            "json-array-reduce",
            "--samples",
            "3",
            "--warmups",
            "1",
            "--timeout-ms",
            "30000",
            "--budget-ms",
            "120000",
            "--seed",
            "17",
            "--output",
            "triad.json",
            "--json",
        ]);
    if let Some(path) = &node {
        command.arg("--node-bin").arg(path);
    }
    if let Some(path) = &bun {
        command.arg("--bun-bin").arg(path);
    }
    let output = command.output().expect("run actual native and reference benchmarks");
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("live benchmark output must be JSON");

    if node.is_none() || bun.is_none() {
        // Missing references are a tested refusal, never a smaller population
        // labeled as a successful triad or fabricated benchmark measurements.
        assert!(!output.status.success(), "{report}");
        assert_eq!(report["schema_version"], "franken-node/bench-run-error/v1");
        assert_eq!(report["ok"], false);
        assert!(report.get("legs").is_none());
        assert!(!workspace.path().join("triad.json").exists());
        return;
    }

    assert!(
        output.status.success(),
        "complete live runtime triad failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(report["schema_version"], "franken-node/triad-benchmark/v2");
    assert_eq!(report["workload_name"], "json-array-reduce");
    assert_eq!(report["seed"], 17);
    assert_eq!(report["stdout_parity_verified"], true);
    assert_eq!(report["interleaved_schedule_len"], 9);
    assert!(report.get("aggregate_score").is_none());
    let legs = report["legs"].as_array().expect("three measured runtime legs");
    assert_eq!(legs.len(), 3);
    let names: std::collections::BTreeSet<_> = legs
        .iter()
        .map(|leg| leg["runtime"].as_str().expect("runtime label"))
        .collect();
    assert_eq!(
        names,
        ["franken_node", "node", "bun"].into_iter().collect()
    );
    for leg in legs {
        let samples = leg["samples_ms"].as_array().expect("raw invocation timings");
        assert_eq!(samples.len(), 3);
        assert!(
            samples
                .iter()
                .all(|sample| sample.as_f64().is_some_and(|ms| ms.is_finite() && ms > 0.0)),
            "every measurement must come from a completed live invocation: {leg}"
        );
        assert!(leg["version"].as_str().is_some_and(|text| !text.is_empty()));
        assert!(
            leg["p99"]["upper_95_ms"].is_null(),
            "three observations cannot give a bounded distribution-free p99 upper limit"
        );
    }
    let native = legs
        .iter()
        .find(|leg| leg["runtime"] == "franken_node")
        .expect("native leg");
    assert_eq!(
        PathBuf::from(native["program"].as_str().expect("native program"))
            .canonicalize()
            .expect("canonical native executable"),
        PathBuf::from(env!("CARGO_BIN_EXE_franken-node"))
            .canonicalize()
            .expect("current product executable"),
        "the measured native leg must be the product under test"
    );
    assert_eq!(
        report["comparisons"].as_array().expect("paired comparisons").len(),
        3
    );
    assert!(
        report["provenance_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71)
    );
    let persisted: Value = serde_json::from_slice(
        &std::fs::read(workspace.path().join("triad.json")).expect("persisted triad report"),
    )
    .expect("persisted triad report JSON");
    assert_eq!(persisted, report);
    assert!(
        output.stderr.is_empty(),
        "--json must keep the human benchmark summary out of stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(all(feature = "engine", target_os = "linux"))]
#[test]
fn bench_run_rejects_runtime_aliases_without_publishing_measurements() {
    let workspace = TempDir::new().expect("create alias-refusal workspace");
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(workspace.path())
        .args(["bench", "run", "--json", "--node-bin"])
        .arg(env!("CARGO_BIN_EXE_franken-node"))
        .arg("--bun-bin")
        .arg(env!("CARGO_BIN_EXE_franken-node"))
        .args(["--output", "triad.json"])
        .output()
        .expect("invoke benchmark with aliased runtime binaries");
    assert!(!output.status.success());
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("alias refusal must be JSON");
    assert_eq!(report["ok"], false);
    assert!(
        report["error"]
            .as_str()
            .is_some_and(|error| error.contains("three distinct executable paths")),
        "identical programs cannot qualify as independent runtime legs: {report}"
    );
    assert!(report.get("provenance_hash").is_none());
    assert!(!workspace.path().join("triad.json").exists());
}

#[cfg(unix)]
#[test]
fn bench_run_fixture_mode_never_executes_runtime_discovery_programs() {
    use std::os::unix::fs::PermissionsExt as _;

    let workspace = TempDir::new().expect("create isolated fixture workspace");
    for runtime in ["node", "bun"] {
        let path = workspace.path().join(runtime);
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf 'unexpected runtime probe\\n' > \"$0.invoked\"\nexit 1\n",
        )
        .expect("write runtime discovery sentinel");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("make discovery sentinel executable");
    }

    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(workspace.path())
        .env("PATH", workspace.path())
        .env_remove("FRANKEN_NODE_BENCH_NODE_VERSION")
        .env_remove("FRANKEN_NODE_BENCH_BUN_VERSION")
        .timeout(std::time::Duration::from_secs(30))
        .args([
            "bench",
            "run",
            "--scenario",
            "secure-extension-heavy",
            "--fixture-mode",
            "--json",
        ])
        .output()
        .expect("run fixture benchmark with instrumented PATH");
    assert!(
        output.status.success(),
        "fixture reports must not depend on executable discovery: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("fixture report JSON");
    assert_eq!(report["evidence_mode"], "fixture_only");
    assert_eq!(report["scenarios"][0]["data_source"], "fixture-inputs");
    assert!(report["runtime_versions"]["node"].is_null());
    assert!(report["runtime_versions"]["bun"].is_null());
    for runtime in ["node", "bun"] {
        assert!(
            !workspace.path().join(format!("{runtime}.invoked")).exists(),
            "explicit fixture mode must never execute {runtime} from PATH"
        );
    }
}
