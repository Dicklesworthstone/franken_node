//! Bench Command Conformance Testing
//!
//! Comprehensive conformance harness for the `franken-node bench` command surface.
//! Tests scenario execution, output formats, error handling, and environment
//! configuration across all supported parameter combinations.
//!
//! Generated from /testing-conformance-harnesses skill.

use assert_cmd::Command;
use insta::{assert_json_snapshot, assert_snapshot, with_settings};
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
            scenario: Some("memory-stress"),
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("16384"),
            timestamp_override: Some("2026-02-21T00:00:00Z"),
            expected_status: TestExpectation::Success,
            description: "memory-stress scenario",
        },
        BenchTestConfig {
            scenario: Some("trust-verification"),
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("8192"),
            timestamp_override: Some("2026-02-21T00:00:00Z"),
            expected_status: TestExpectation::Success,
            description: "trust-verification scenario",
        },
        BenchTestConfig {
            scenario: Some("isolation-overhead"),
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("4096"),
            timestamp_override: Some("2026-02-21T00:00:00Z"),
            expected_status: TestExpectation::Success,
            description: "isolation-overhead scenario",
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
        BenchTestConfig {
            scenario: Some("secure-extension-heavy"),
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("invalid-memory"),
            timestamp_override: Some("2026-02-21T00:00:00Z"),
            expected_status: TestExpectation::Failure,
            description: "invalid memory override should fail",
        },
        BenchTestConfig {
            scenario: Some("secure-extension-heavy"),
            cpu_override: Some("deterministic-golden-cpu"),
            memory_mb_override: Some("32768"),
            timestamp_override: Some("invalid-timestamp"),
            expected_status: TestExpectation::Failure,
            description: "invalid timestamp override should fail",
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

    // Generate conformance report
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

    // Snapshot the complete conformance matrix
    with_settings!({
        description => "Bench command conformance matrix testing all scenarios and error conditions"
    }, {
        assert_json_snapshot!("bench_conformance_matrix", conformance_report);
    });

    Ok(())
}

#[test]
fn bench_help_output_format() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("franken-node")?;
    let assertion = cmd.args(["bench", "--help"]).assert().success();

    let stdout = std::str::from_utf8(&assertion.get_output().stdout)?;
    assert_snapshot!("bench_help_output", stdout);

    Ok(())
}

#[test]
fn bench_run_help_output_format() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("franken-node")?;
    let assertion = cmd.args(["bench", "run", "--help"]).assert().success();

    let stdout = std::str::from_utf8(&assertion.get_output().stdout)?;
    assert_snapshot!("bench_run_help_output", stdout);

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
        "memory-stress",
        "trust-verification",
        "isolation-overhead",
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

    // Should either succeed with overrides or fail predictably
    let output = assertion.get_output();
    let exit_successful = output.status.success();

    // Document the behavior in snapshot
    let result = serde_json::json!({
        "exit_successful": exit_successful,
        "stdout_len": output.stdout.len(),
        "stderr_len": output.stderr.len(),
        "environment_overrides": {
            "cpu": "test-cpu-override",
            "memory_mb": "1024",
            "timestamp": "2026-01-01T00:00:00Z"
        }
    });

    assert_json_snapshot!("bench_environment_override_behavior", result);

    Ok(())
}
