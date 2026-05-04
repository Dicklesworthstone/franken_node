//! Bench Command Conformance Testing
//!
//! Comprehensive conformance harness for the `franken-node bench` command surface.
//! Tests scenario execution, output formats, error handling, and environment
//! configuration across all supported parameter combinations.
//!
//! Generated from /testing-conformance-harnesses skill.

use assert_cmd::Command;
use frankenengine_node::tools::benchmark_suite::{
    BenchRunError, BenchmarkDimension, BenchmarkSecurityControls, BenchmarkSuite,
    MAX_MEASURED_TOTAL_ITERATIONS, MAX_RAW_BENCHMARK_SAMPLES, ScenarioDefinition, ScoringConfig,
    SuiteConfig, coefficient_of_variation, confidence_interval_95, mean, std_dev,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::error::Error;

/// Bench command test configuration
#[derive(Debug, Clone)]
struct BenchTestConfig {
    scenario: Option<&'static str>,
    cpu_override: Option<&'static str>,
    memory_mb_override: Option<&'static str>,
    timestamp_override: Option<&'static str>,
    expected_status: TestExpectation,
    description: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
enum TestExpectation {
    Success,
    Failure,
}

/// Create the conformance test matrix at runtime to avoid const limitations
fn bench_conformance_cases() -> Vec<BenchTestConfig> {
    vec![
        // Valid scenarios
        BenchTestConfig {
            scenario: Some("secure-extension-heavy"),
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("32768"),
            timestamp_override: Some("2026-02-21T00:00:00Z"),
            expected_status: TestExpectation::Success,
            description: "secure-extension-heavy scenario with deterministic environment",
        },
        BenchTestConfig {
            scenario: Some("migration_scanner_throughput"),
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("16384"),
            timestamp_override: Some("2026-02-21T00:00:00Z"),
            expected_status: TestExpectation::Success,
            description: "migration scanner throughput scenario",
        },
        BenchTestConfig {
            scenario: Some("trust_card_materialization"),
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("8192"),
            timestamp_override: Some("2026-02-21T00:00:00Z"),
            expected_status: TestExpectation::Success,
            description: "trust card materialization scenario",
        },
        BenchTestConfig {
            scenario: Some("extension_overhead_ratio"),
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("4096"),
            timestamp_override: Some("2026-02-21T00:00:00Z"),
            expected_status: TestExpectation::Success,
            description: "extension overhead ratio scenario",
        },
        // Default scenario (no explicit scenario argument)
        BenchTestConfig {
            scenario: None,
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("32768"),
            timestamp_override: Some("2026-02-21T00:00:00Z"),
            expected_status: TestExpectation::Success,
            description: "default scenario when none specified",
        },
        // Error conditions
        BenchTestConfig {
            scenario: Some("invalid-scenario-name"),
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("32768"),
            timestamp_override: Some("2026-02-21T00:00:00Z"),
            expected_status: TestExpectation::Failure,
            description: "invalid scenario name should fail",
        },
    ]
}

/// Parse JSON stdout from bench command, handling both valid and error cases
fn parse_bench_json_stdout(stdout: &[u8]) -> Result<Value, String> {
    let stdout_str =
        std::str::from_utf8(stdout).map_err(|e| format!("stdout is not valid UTF-8: {}", e))?;

    serde_json::from_str(stdout_str).map_err(|e| format!("stdout is not valid JSON: {}", e))
}

/// Execute a single bench conformance test
fn execute_bench_test(config: &BenchTestConfig) -> Result<Value, Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("franken-node")?;

    // Set environment variables
    if let Some(cpu) = &config.cpu_override {
        cmd.env("FRANKEN_NODE_BENCH_CPU", cpu);
    }
    if let Some(memory) = &config.memory_mb_override {
        cmd.env("FRANKEN_NODE_BENCH_MEMORY_MB", memory);
    }
    if let Some(timestamp) = &config.timestamp_override {
        cmd.env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", timestamp);
    }

    // Build command arguments
    let mut args = vec!["bench", "run"];
    if let Some(scenario) = &config.scenario {
        args.extend(["--scenario", scenario]);
    }

    let assertion = cmd.args(&args).assert();

    let output = match config.expected_status {
        TestExpectation::Success => assertion.success().get_output().clone(),
        TestExpectation::Failure => assertion.failure().get_output().clone(),
    };

    // Try to parse as JSON first, fall back to structured error representation
    match parse_bench_json_stdout(&output.stdout) {
        Ok(json) => Ok(json),
        Err(_) => {
            // For failed tests, structure the error information
            let stderr_str = std::str::from_utf8(&output.stderr).unwrap_or("<invalid_utf8>");
            let stdout_str = std::str::from_utf8(&output.stdout).unwrap_or("<invalid_utf8>");

            Ok(serde_json::json!({
                "status": "error",
                "exit_code": output.status.code(),
                "stderr": stderr_str,
                "stdout": stdout_str,
                "test_config": {
                    "scenario": config.scenario,
                    "description": config.description
                }
            }))
        }
    }
}

fn assert_bench_result_matches_config(config: &BenchTestConfig, result: &Value) {
    match config.expected_status {
        TestExpectation::Success => {
            assert_eq!(
                result.get("suite_version").and_then(Value::as_str),
                Some("1.0.0"),
                "successful bench output must include the stable suite version"
            );
            assert_eq!(
                result
                    .get("scoring_formula_version")
                    .and_then(Value::as_str),
                Some("sf-v1"),
                "successful bench output must include the stable scoring formula"
            );
            assert_eq!(
                result.get("timestamp_utc").and_then(Value::as_str),
                config.timestamp_override,
                "bench output must honor deterministic timestamp override"
            );
            assert_eq!(
                result
                    .pointer("/hardware_profile/cpu")
                    .and_then(Value::as_str),
                config.cpu_override,
                "bench output must honor deterministic CPU override"
            );
            assert_eq!(
                result
                    .pointer("/hardware_profile/memory_mb")
                    .and_then(Value::as_u64)
                    .map(|memory_mb| memory_mb.to_string())
                    .as_deref(),
                config.memory_mb_override,
                "bench output must honor deterministic memory override"
            );

            let scenarios = result
                .get("scenarios")
                .and_then(Value::as_array)
                .expect("successful bench output must include scenarios");
            assert!(
                !scenarios.is_empty(),
                "successful bench output must contain at least one scenario"
            );

            if let Some(expected_scenario) = config.scenario {
                assert!(
                    scenarios.iter().any(|scenario| {
                        scenario.get("name").and_then(Value::as_str) == Some(expected_scenario)
                    }),
                    "explicit bench scenario `{}` must appear in output",
                    expected_scenario
                );
            } else {
                assert!(
                    scenarios.len() > 1,
                    "default bench run must execute the full scenario set"
                );
            }
        }
        TestExpectation::Failure => {
            assert_eq!(
                result.get("status").and_then(Value::as_str),
                Some("error"),
                "negative bench cases must return structured error output"
            );
            let stderr = result
                .get("stderr")
                .and_then(Value::as_str)
                .expect("negative bench cases must capture stderr");
            assert!(
                stderr.contains("benchmark suite run failed"),
                "negative bench case stderr should preserve the suite error: {stderr}"
            );
        }
    }
}

#[test]
fn bench_conformance_matrix() -> Result<(), Box<dyn Error>> {
    let mut results = BTreeMap::new();

    let matrix = bench_conformance_cases();
    for (idx, config) in matrix.iter().enumerate() {
        let test_name = format!(
            "test_{:02}_{}",
            idx + 1,
            config
                .scenario
                .as_deref()
                .unwrap_or("default")
                .replace('-', "_")
        );

        println!("Running bench conformance test: {}", config.description);

        match execute_bench_test(config) {
            Ok(result) => {
                assert_bench_result_matches_config(config, &result);
                results.insert(
                    test_name.clone(),
                    serde_json::json!({
                        "status": "completed",
                        "config": {
                            "scenario": config.scenario,
                            "expected_status": format!("{:?}", config.expected_status),
                            "description": config.description
                        },
                        "result": result
                    }),
                );
            }
            Err(error) => {
                results.insert(
                    test_name.clone(),
                    serde_json::json!({
                        "status": "test_error",
                        "config": {
                            "scenario": config.scenario,
                            "expected_status": format!("{:?}", config.expected_status),
                            "description": config.description
                        },
                        "error": error.to_string()
                    }),
                );
            }
        }
    }

    let total_tests = matrix.len();
    let successful_tests = results
        .values()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("completed"))
        .count();

    let conformance_report = serde_json::json!({
        "bench_command_conformance": {
            "schema_version": "conformance-report/v1",
            "timestamp": "2026-04-22T04:00:00Z",
            "total_test_cases": total_tests,
            "successful_tests": successful_tests,
            "conformance_score": format!("{:.1}%",
                (successful_tests as f64 / total_tests as f64) * 100.0),
            "test_matrix": results
        }
    });

    assert_eq!(
        conformance_report
            .pointer("/bench_command_conformance/total_test_cases")
            .and_then(Value::as_u64),
        Some(total_tests as u64)
    );
    assert_eq!(
        conformance_report
            .pointer("/bench_command_conformance/successful_tests")
            .and_then(Value::as_u64),
        Some(successful_tests as u64)
    );
    assert_eq!(
        successful_tests, total_tests,
        "bench conformance matrix must complete every case"
    );

    Ok(())
}

#[test]
fn measured_suite_rejects_oversized_warmup_budget_before_workload() {
    assert_eq!(
        u64::try_from(MAX_RAW_BENCHMARK_SAMPLES).ok(),
        Some(MAX_MEASURED_TOTAL_ITERATIONS)
    );

    let retained_iterations = 3;
    let mut suite = BenchmarkSuite::new(SuiteConfig::with_defaults());
    suite.add_scenario(ScenarioDefinition {
        dimension: BenchmarkDimension::PerformanceUnderHardening,
        name: "secure-extension-heavy".to_string(),
        unit: "ms".to_string(),
        iterations: retained_iterations,
        warmup_iterations: u32::MAX,
        sandbox_required: true,
        scoring: ScoringConfig::lower_is_better(250.0, 1000.0),
    });

    let err = suite
        .run_measured(BenchmarkSecurityControls::measured_secure())
        .expect_err("measured run must cap warmup before executing workload");

    assert!(matches!(
        err,
        BenchRunError::TooManyMeasuredIterations {
            scenario,
            max: MAX_MEASURED_TOTAL_ITERATIONS,
            actual
        } if scenario == "secure-extension-heavy"
            && actual == u64::from(retained_iterations).saturating_add(u64::from(u32::MAX))
    ));
    assert!(
        suite
            .events()
            .iter()
            .all(|event| event.scenario_id.as_deref() != Some("secure-extension-heavy")),
        "oversized warmup must fail before scenario execution events are emitted"
    );
}

#[test]
fn bench_help_output_format() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("franken-node")?;
    let assertion = cmd.args(["bench", "--help"]).assert().success();

    let stdout = std::str::from_utf8(&assertion.get_output().stdout)?;
    assert!(stdout.contains("Benchmark suite execution"));
    assert!(stdout.contains("franken-node bench"));
    assert!(stdout.contains("<COMMAND>"));
    assert!(stdout.contains("run   Run benchmark suite and emit signed report"));

    Ok(())
}

#[test]
fn bench_run_help_output_format() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("franken-node")?;
    let assertion = cmd.args(["bench", "run", "--help"]).assert().success();

    let stdout = std::str::from_utf8(&assertion.get_output().stdout)?;
    assert!(stdout.contains("Run benchmark suite and emit signed report"));
    assert!(stdout.contains("franken-node bench run"));
    assert!(stdout.contains("[OPTIONS]"));
    assert!(stdout.contains("--scenario <SCENARIO>"));

    Ok(())
}

#[test]
fn bench_deterministic_output_stability() -> Result<(), Box<dyn Error>> {
    // Run the same bench scenario twice to ensure deterministic output
    let matrix = bench_conformance_cases();
    let config = &matrix[0]; // secure-extension-heavy scenario

    let result1 = execute_bench_test(config)?;
    let result2 = execute_bench_test(config)?;

    // Results should be identical for deterministic scenarios
    assert_eq!(
        result1, result2,
        "Deterministic bench scenarios should produce identical output"
    );

    Ok(())
}

#[test]
fn bench_scenario_coverage() {
    // Verify that our conformance matrix covers expected scenarios
    let matrix = bench_conformance_cases();
    let tested_scenarios: Vec<_> = matrix
        .iter()
        .filter_map(|config| config.scenario.as_deref())
        .collect();

    let expected_scenarios = [
        "secure-extension-heavy",
        "migration_scanner_throughput",
        "trust_card_materialization",
        "extension_overhead_ratio",
        "invalid-scenario-name", // error case
    ];

    for expected in &expected_scenarios {
        assert!(
            tested_scenarios.contains(expected),
            "Conformance matrix must test scenario: {}",
            expected
        );
    }
}

#[test]
fn bench_environment_variable_isolation() -> Result<(), Box<dyn Error>> {
    // Test that bench respects environment variable overrides
    let mut cmd = Command::cargo_bin("franken-node")?;
    let assertion = cmd
        .env("FRANKEN_NODE_BENCH_CPU", "test-cpu-override")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "1024")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-01-01T00:00:00Z")
        .args(["bench", "run", "--scenario", "secure-extension-heavy"])
        .assert();

    let success = assertion.success();
    let output = success.get_output();
    let result = parse_bench_json_stdout(&output.stdout)?;
    assert_eq!(
        result
            .pointer("/hardware_profile/cpu")
            .and_then(Value::as_str),
        Some("test-cpu-override")
    );
    assert_eq!(
        result
            .pointer("/hardware_profile/memory_mb")
            .and_then(Value::as_u64),
        Some(1024)
    );
    assert_eq!(
        result.get("timestamp_utc").and_then(Value::as_str),
        Some("2026-01-01T00:00:00Z")
    );

    Ok(())
}

#[test]
fn bench_statistics_preserve_non_finite_measurements() {
    assert!(mean(&[1.0, f64::NAN, 3.0]).is_nan());
    assert!(std_dev(&[1.0, f64::NAN, 3.0]).is_nan());

    let large_mean = mean(&[f64::MAX / 2.0, f64::MAX / 2.0]);
    assert!(
        large_mean.is_finite(),
        "stable mean must not overflow identical large finite values"
    );

    let cv = coefficient_of_variation(&[f64::MIN_POSITIVE, f64::MAX / 2.0]);
    assert!(
        !cv.is_finite(),
        "overflowed benchmark variation must stay visible to callers"
    );

    let ci = confidence_interval_95(&[1.0, f64::NAN, 3.0]);
    assert!(
        ci.lower.is_nan() && ci.upper.is_nan(),
        "invalid confidence intervals must not be converted to finite defaults"
    );
}
