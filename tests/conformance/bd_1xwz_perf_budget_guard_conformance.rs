//! bd-1xwz Performance Budget Guard Conformance Test Suite
//!
//! This conformance test suite verifies full compliance with the bd-1xwz specification
//! for performance budget enforcement on asupersync integration overhead. It implements
//! Pattern 4: Spec-Derived Test Matrix to ensure comprehensive coverage of all
//! MUST and SHOULD requirements.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Import the module under test
use frankenengine_node::policy::perf_budget_guard::{
    BenchmarkMeasurement, BudgetPolicy, ERR_BUDGET_EXCEEDED, ERR_COLD_START_EXCEEDED,
    ERR_FLAMEGRAPH_CAPTURE_FAILED, ERR_NO_MEASUREMENTS, GateResult, HotPath,
    PRF_001_BENCHMARK_STARTED, PRF_002_WITHIN_BUDGET, PRF_003_OVER_BUDGET,
    PRF_004_FLAMEGRAPH_CAPTURED, PRF_005_COLD_START, PRF_006_TIMING_SAMPLE,
    PRF_007_PERCENTILE_COMPUTED, PRF_008_COLD_START_TIMING, PathBudget, PercentileStats,
    PerfBudgetError, PerformanceBudgetGuard, TimingCollector,
};

/// Requirement levels from the bd-1xwz specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

/// Test categories for organizational structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    Unit,
    Integration,
    EdgeCase,
}

/// Test result for conformance verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String },
}

/// Individual conformance test case record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceRecord {
    pub id: String,
    pub section: String,
    pub level: RequirementLevel,
    pub category: TestCategory,
    pub description: String,
    pub result: TestResult,
}

/// Test execution statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ConformanceStats {
    pub must_pass: usize,
    pub must_fail: usize,
    pub should_pass: usize,
    pub should_fail: usize,
    pub may_pass: usize,
    pub may_fail: usize,
    pub skipped: usize,
    pub expected_failures: usize,
}

/// Complete conformance test report
#[derive(Debug, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub timestamp: String,
    pub specification: String,
    pub version: String,
    pub results: BTreeMap<String, ConformanceRecord>,
    pub stats: ConformanceStats,
}

impl ConformanceReport {
    /// Calculate overall compliance score (MUST requirements only)
    pub fn compliance_score(&self) -> f64 {
        let total_must = self.stats.must_pass + self.stats.must_fail;
        if total_must == 0 {
            1.0 // No MUST requirements = fully compliant
        } else {
            self.stats.must_pass as f64 / total_must as f64
        }
    }

    /// Generate human-readable Markdown report
    pub fn to_markdown(&self) -> String {
        let score = self.compliance_score() * 100.0;
        format!(
            r#"# bd-1xwz Performance Budget Guard Conformance Report

Generated: {}
Specification: {}
Version: {}

## Summary

- **Compliance Score**: {:.1}%
- **Total Tests**: {}
- **MUST Requirements**: {} pass, {} fail
- **SHOULD Requirements**: {} pass, {} fail

## Test Results

| ID | Level | Category | Description | Result |
|----|-------|----------|-------------|--------|
{}

## Compliance Assessment

{}
"#,
            self.timestamp,
            self.specification,
            self.version,
            score,
            self.results.len(),
            self.stats.must_pass,
            self.stats.must_fail,
            self.stats.should_pass,
            self.stats.should_fail,
            self.results
                .values()
                .map(|r| format!(
                    "| {} | {:?} | {:?} | {} | {} |",
                    r.id,
                    r.level,
                    r.category,
                    r.description,
                    match &r.result {
                        TestResult::Pass => "✅ PASS",
                        TestResult::Fail { reason } => &format!("❌ FAIL: {}", reason),
                        TestResult::Skipped { reason } => &format!("⏭️ SKIP: {}", reason),
                        TestResult::ExpectedFailure { reason } => &format!("⏳ XFAIL: {}", reason),
                    }
                ))
                .collect::<Vec<_>>()
                .join("\n"),
            if score >= 95.0 {
                "✅ **CONFORMANT** - Meets bd-1xwz specification requirements"
            } else {
                "❌ **NON-CONFORMANT** - Does not meet bd-1xwz specification requirements"
            }
        )
    }
}

/// Individual conformance test case definition
struct ConformanceCase {
    id: &'static str,
    section: &'static str,
    level: RequirementLevel,
    category: TestCategory,
    description: &'static str,
    test_fn: fn() -> Result<(), String>,
}

/// bd-1xwz specification test matrix - all MUST/SHOULD requirements
const BD_1XWZ_CASES: &[ConformanceCase] = &[
    // Core Invariants (MUST)
    ConformanceCase {
        id: "1XWZ-INV-1",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-PBG-BUDGET-ENFORCED: every hot path check compares against policy budget",
        test_fn: test_budget_enforcement_invariant,
    },
    ConformanceCase {
        id: "1XWZ-INV-2",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-PBG-REGRESSION-BLOCKED: measurements exceeding budget blocks gate",
        test_fn: test_regression_blocking_invariant,
    },
    ConformanceCase {
        id: "1XWZ-INV-3",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-PBG-FLAMEGRAPH-ON-FAIL: flamegraph captured on every gate failure",
        test_fn: test_flamegraph_capture_invariant,
    },
    ConformanceCase {
        id: "1XWZ-INV-4",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "INV-PBG-REPORT-ALWAYS: structured report emitted on every gate run",
        test_fn: test_report_always_invariant,
    },
    // Event Code Requirements (MUST)
    ConformanceCase {
        id: "1XWZ-EVT-1",
        section: "events",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "PRF_001_BENCHMARK_STARTED emitted for every measurement",
        test_fn: test_benchmark_started_events,
    },
    ConformanceCase {
        id: "1XWZ-EVT-2",
        section: "events",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "PRF_002_WITHIN_BUDGET emitted for passing measurements",
        test_fn: test_within_budget_events,
    },
    ConformanceCase {
        id: "1XWZ-EVT-3",
        section: "events",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "PRF_003_OVER_BUDGET emitted for failing measurements",
        test_fn: test_over_budget_events,
    },
    ConformanceCase {
        id: "1XWZ-EVT-4",
        section: "events",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "PRF_005_COLD_START emitted for every measurement",
        test_fn: test_cold_start_events,
    },
    // Error Handling Requirements (MUST)
    ConformanceCase {
        id: "1XWZ-ERR-1",
        section: "errors",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "ERR_NO_MEASUREMENTS error for empty measurement list",
        test_fn: test_no_measurements_error,
    },
    ConformanceCase {
        id: "1XWZ-ERR-2",
        section: "errors",
        level: RequirementLevel::Must,
        category: TestCategory::EdgeCase,
        description: "fail-closed behavior on invalid floating point values",
        test_fn: test_fail_closed_on_invalid_values,
    },
    // Budget Policy Requirements (MUST)
    ConformanceCase {
        id: "1XWZ-POL-1",
        section: "policy",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "budget_for() returns correct budget for canonical hot paths",
        test_fn: test_canonical_path_budgets,
    },
    ConformanceCase {
        id: "1XWZ-POL-2",
        section: "policy",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "default budget used for unknown hot paths",
        test_fn: test_default_budget_fallback,
    },
    // Timing Collector Requirements (MUST)
    ConformanceCase {
        id: "1XWZ-TIM-1",
        section: "timing",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "PRF_006_TIMING_SAMPLE emitted for valid timing recordings",
        test_fn: test_timing_sample_events,
    },
    ConformanceCase {
        id: "1XWZ-TIM-2",
        section: "timing",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "percentile computation only for paths with both baseline and integrated",
        test_fn: test_measurement_synthesis_requirements,
    },
    // Edge Cases (SHOULD)
    ConformanceCase {
        id: "1XWZ-EDGE-1",
        section: "edge_cases",
        level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "exact budget boundary values should fail closed",
        test_fn: test_exact_boundary_fail_closed,
    },
    ConformanceCase {
        id: "1XWZ-EDGE-2",
        section: "edge_cases",
        level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "flamegraph path traversal protection",
        test_fn: test_flamegraph_path_traversal_protection,
    },
    ConformanceCase {
        id: "1XWZ-EDGE-3",
        section: "edge_cases",
        level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "CSV report generation with correct format",
        test_fn: test_csv_report_format,
    },
];

// Test implementation functions

fn make_valid_measurement(
    hot_path: &str,
    baseline_p95: f64,
    integrated_p95: f64,
    cold_start: f64,
) -> BenchmarkMeasurement {
    BenchmarkMeasurement {
        hot_path: hot_path.to_string(),
        baseline_p50_us: baseline_p95 * 0.7,
        baseline_p95_us: baseline_p95,
        baseline_p99_us: baseline_p95 * 1.3,
        integrated_p50_us: integrated_p95 * 0.7,
        integrated_p95_us: integrated_p95,
        integrated_p99_us: integrated_p95 * 1.3,
        cold_start_ms: cold_start,
    }
}

fn test_budget_enforcement_invariant() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-inv-1");

    let measurements = vec![
        make_valid_measurement("lifecycle_transition", 100.0, 110.0, 20.0), // 10% overhead
        make_valid_measurement("health_gate_evaluation", 50.0, 65.0, 15.0), // 30% overhead > 15% budget
    ];

    let result = guard
        .evaluate(&measurements)
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    // Verify policy was enforced: one path should pass, one should fail
    if result.paths_within_budget != 1 || result.paths_over_budget != 1 {
        return Err(format!(
            "Expected 1 within budget, 1 over budget; got {} within, {} over",
            result.paths_within_budget, result.paths_over_budget
        ));
    }

    // Verify health_gate_evaluation failed due to p95 budget violation
    let health_result = result
        .path_results
        .iter()
        .find(|r| r.hot_path == "health_gate_evaluation")
        .ok_or("health_gate_evaluation result not found")?;

    if health_result.within_budget {
        return Err("health_gate_evaluation should have failed budget check".to_string());
    }

    if !health_result
        .violations
        .iter()
        .any(|v| v.contains("p95 overhead"))
    {
        return Err("Expected p95 overhead violation for health_gate_evaluation".to_string());
    }

    Ok(())
}

fn test_regression_blocking_invariant() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-inv-2");

    // All measurements within budget = should pass
    let good_measurements = vec![make_valid_measurement(
        "lifecycle_transition",
        100.0,
        110.0,
        20.0,
    )];
    let good_result = guard
        .evaluate(&good_measurements)
        .map_err(|e| format!("Good evaluation failed: {}", e))?;
    if !good_result.overall_pass {
        return Err("Expected overall pass for measurements within budget".to_string());
    }

    // Create new guard for second test
    let mut guard2 = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-inv-2b");

    // Any measurement over budget = should block gate
    let bad_measurements = vec![
        make_valid_measurement("lifecycle_transition", 100.0, 110.0, 20.0), // within budget
        make_valid_measurement("health_gate_evaluation", 50.0, 70.0, 15.0), // 40% > 15% budget
    ];
    let bad_result = guard2
        .evaluate(&bad_measurements)
        .map_err(|e| format!("Bad evaluation failed: {}", e))?;

    if bad_result.overall_pass {
        return Err("Expected overall failure when any measurement exceeds budget".to_string());
    }

    Ok(())
}

fn test_flamegraph_capture_invariant() -> Result<(), String> {
    let temp = tempfile::tempdir().map_err(|e| format!("Failed to create temp dir: {}", e))?;
    let temp_path = temp.path().to_string_lossy().to_string();

    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-inv-3")
        .with_flamegraph_dir(&temp_path);

    // Measurement that will fail budget
    let measurements = vec![
        make_valid_measurement("lifecycle_transition", 100.0, 120.0, 10.0), // 20% > 15% budget
    ];

    let result = guard
        .evaluate(&measurements)
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    // Verify flamegraph was captured for the failing path
    let path_result = &result.path_results[0];
    if path_result.flamegraph_path.is_none() {
        return Err("Expected flamegraph path for failing measurement".to_string());
    }

    let flamegraph_path = path_result.flamegraph_path.as_ref().unwrap();
    if !flamegraph_path.contains("flamegraph_lifecycle_transition") {
        return Err(format!(
            "Unexpected flamegraph path format: {}",
            flamegraph_path
        ));
    }

    // Verify PRF_004 event was emitted
    let has_flamegraph_event = guard
        .events()
        .iter()
        .any(|e| e.code == PRF_004_FLAMEGRAPH_CAPTURED);
    if !has_flamegraph_event {
        return Err("Expected PRF_004_FLAMEGRAPH_CAPTURED event".to_string());
    }

    Ok(())
}

fn test_report_always_invariant() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-inv-4");

    // Test successful case
    let measurements = vec![make_valid_measurement(
        "lifecycle_transition",
        100.0,
        105.0,
        10.0,
    )];
    let result = guard
        .evaluate(&measurements)
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    if result.path_results.is_empty() {
        return Err("Expected path results in report".to_string());
    }
    if result.total_paths != 1 {
        return Err(format!(
            "Expected total_paths=1, got {}",
            result.total_paths
        ));
    }

    // Test failing case - should still generate report
    let mut guard2 = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-inv-4b");
    let bad_measurements = vec![make_valid_measurement(
        "lifecycle_transition",
        100.0,
        150.0,
        10.0,
    )];
    let bad_result = guard2
        .evaluate(&bad_measurements)
        .map_err(|e| format!("Bad evaluation failed: {}", e))?;

    if bad_result.path_results.is_empty() {
        return Err("Expected path results even for failing measurements".to_string());
    }

    Ok(())
}

fn test_benchmark_started_events() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-evt-1");

    let measurements = vec![
        make_valid_measurement("lifecycle_transition", 100.0, 110.0, 20.0),
        make_valid_measurement("health_gate_evaluation", 50.0, 55.0, 15.0),
    ];

    guard
        .evaluate(&measurements)
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    let started_events: Vec<_> = guard
        .events()
        .iter()
        .filter(|e| e.code == PRF_001_BENCHMARK_STARTED)
        .collect();

    if started_events.len() != 2 {
        return Err(format!(
            "Expected 2 PRF_001 events, got {}",
            started_events.len()
        ));
    }

    Ok(())
}

fn test_within_budget_events() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-evt-2");

    let measurements = vec![
        make_valid_measurement("lifecycle_transition", 100.0, 110.0, 20.0), // 10% within 15% budget
    ];

    guard
        .evaluate(&measurements)
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    let within_events: Vec<_> = guard
        .events()
        .iter()
        .filter(|e| e.code == PRF_002_WITHIN_BUDGET)
        .collect();

    if within_events.len() != 1 {
        return Err(format!(
            "Expected 1 PRF_002 event, got {}",
            within_events.len()
        ));
    }

    Ok(())
}

fn test_over_budget_events() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-evt-3");

    let measurements = vec![
        make_valid_measurement("lifecycle_transition", 100.0, 120.0, 20.0), // 20% > 15% budget
    ];

    guard
        .evaluate(&measurements)
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    let over_events: Vec<_> = guard
        .events()
        .iter()
        .filter(|e| e.code == PRF_003_OVER_BUDGET)
        .collect();

    if over_events.len() != 1 {
        return Err(format!(
            "Expected 1 PRF_003 event, got {}",
            over_events.len()
        ));
    }

    Ok(())
}

fn test_cold_start_events() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-evt-4");

    let measurements = vec![make_valid_measurement(
        "lifecycle_transition",
        100.0,
        110.0,
        25.0,
    )];

    guard
        .evaluate(&measurements)
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    let cold_start_events: Vec<_> = guard
        .events()
        .iter()
        .filter(|e| e.code == PRF_005_COLD_START)
        .collect();

    if cold_start_events.len() != 1 {
        return Err(format!(
            "Expected 1 PRF_005 event, got {}",
            cold_start_events.len()
        ));
    }

    Ok(())
}

fn test_no_measurements_error() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-err-1");

    let result = guard.evaluate(&[]);
    match result {
        Ok(_) => Err("Expected error for empty measurements".to_string()),
        Err(e) => {
            if e.code != ERR_NO_MEASUREMENTS {
                Err(format!("Expected ERR_NO_MEASUREMENTS, got {}", e.code))
            } else {
                Ok(())
            }
        }
    }
}

fn test_fail_closed_on_invalid_values() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-err-2");

    let invalid_measurement = BenchmarkMeasurement {
        hot_path: "test".to_string(),
        baseline_p50_us: f64::NAN,
        baseline_p95_us: f64::NAN,
        baseline_p99_us: f64::NAN,
        integrated_p50_us: 10.0,
        integrated_p95_us: 10.0,
        integrated_p99_us: 10.0,
        cold_start_ms: 5.0,
    };

    let result = guard
        .evaluate(&[invalid_measurement])
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    if result.overall_pass {
        return Err("Expected failure for invalid baseline values".to_string());
    }

    if result.path_results[0].violations.is_empty() {
        return Err("Expected violations for invalid measurements".to_string());
    }

    Ok(())
}

fn test_canonical_path_budgets() -> Result<(), String> {
    let policy = BudgetPolicy::default();

    for hot_path in HotPath::canonical() {
        let budget = policy.budget_for(&hot_path);
        if budget.max_overhead_p95_pct <= 0.0 {
            return Err(format!(
                "Invalid p95 budget for {}: {}",
                hot_path.label(),
                budget.max_overhead_p95_pct
            ));
        }
        if budget.max_overhead_p99_pct <= 0.0 {
            return Err(format!(
                "Invalid p99 budget for {}: {}",
                hot_path.label(),
                budget.max_overhead_p99_pct
            ));
        }
        if budget.max_cold_start_ms <= 0.0 {
            return Err(format!(
                "Invalid cold start budget for {}: {}",
                hot_path.label(),
                budget.max_cold_start_ms
            ));
        }
    }

    Ok(())
}

fn test_default_budget_fallback() -> Result<(), String> {
    let policy = BudgetPolicy::default();
    let custom_path = HotPath::Custom("unknown_custom_path".to_string());

    let budget = policy.budget_for(&custom_path);
    let default_budget = &policy.default_budget;

    if (budget.max_overhead_p95_pct - default_budget.max_overhead_p95_pct).abs() > f64::EPSILON {
        return Err("Custom path should use default budget".to_string());
    }

    Ok(())
}

fn test_timing_sample_events() -> Result<(), String> {
    let mut collector = TimingCollector::new("test-tim-1");

    collector.record_baseline("lifecycle_transition", 100.0);
    collector.record_integrated("lifecycle_transition", 110.0);

    let events = collector.events();
    let sample_events: Vec<_> = events
        .iter()
        .filter(|e| e.code == PRF_006_TIMING_SAMPLE)
        .collect();

    if sample_events.len() != 2 {
        return Err(format!(
            "Expected 2 PRF_006 events, got {}",
            sample_events.len()
        ));
    }

    Ok(())
}

fn test_measurement_synthesis_requirements() -> Result<(), String> {
    let mut collector = TimingCollector::new("test-tim-2");

    // Path with only baseline - should not appear in measurements
    collector.record_baseline("path_baseline_only", 100.0);

    // Path with only integrated - should not appear in measurements
    collector.record_integrated("path_integrated_only", 110.0);

    // Path with both - should appear in measurements
    collector.record_baseline("path_complete", 100.0);
    collector.record_integrated("path_complete", 110.0);

    let measurements = collector.to_measurements();

    if measurements.len() != 1 {
        return Err(format!(
            "Expected 1 measurement, got {}",
            measurements.len()
        ));
    }

    if measurements[0].hot_path != "path_complete" {
        return Err(format!(
            "Expected path_complete, got {}",
            measurements[0].hot_path
        ));
    }

    Ok(())
}

fn test_exact_boundary_fail_closed() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-edge-1");

    // Exactly 15% overhead should fail (fail-closed at boundary)
    let boundary_measurement = make_valid_measurement("lifecycle_transition", 100.0, 115.0, 10.0);
    let result = guard
        .evaluate(&[boundary_measurement])
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    if result.overall_pass {
        return Err("Expected failure at exact budget boundary (fail-closed)".to_string());
    }

    Ok(())
}

fn test_flamegraph_path_traversal_protection() -> Result<(), String> {
    let temp = tempfile::tempdir().map_err(|e| format!("Failed to create temp dir: {}", e))?;
    let temp_path = temp.path().to_string_lossy().to_string();

    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-edge-2")
        .with_flamegraph_dir(&temp_path);

    // Path traversal attempt
    let bad_measurement = make_valid_measurement("../escape_path", 100.0, 120.0, 10.0);
    let result = guard
        .evaluate(&[bad_measurement])
        .map_err(|e| format!("Evaluation failed: {}", e))?;

    // Should not capture flamegraph for path traversal attempts
    if result.path_results[0].flamegraph_path.is_some() {
        return Err("Should not capture flamegraph for path traversal attempts".to_string());
    }

    // Should not emit PRF_004 event
    let has_flamegraph_event = guard
        .events()
        .iter()
        .any(|e| e.code == PRF_004_FLAMEGRAPH_CAPTURED);
    if has_flamegraph_event {
        return Err("Should not emit flamegraph event for path traversal".to_string());
    }

    Ok(())
}

fn test_csv_report_format() -> Result<(), String> {
    let mut guard = PerformanceBudgetGuard::new(BudgetPolicy::default(), "test-edge-3");

    let measurements = vec![
        make_valid_measurement("lifecycle_transition", 100.0, 110.0, 20.0),
        make_valid_measurement("health_gate_evaluation", 50.0, 55.0, 15.0),
    ];

    let result = guard
        .evaluate(&measurements)
        .map_err(|e| format!("Evaluation failed: {}", e))?;
    let csv = PerformanceBudgetGuard::to_csv(&result);

    // Check header
    if !csv.starts_with("hot_path,baseline_p50_us,baseline_p95_us") {
        return Err("CSV missing expected header".to_string());
    }

    // Check row count (header + 2 measurements)
    let lines: Vec<_> = csv.trim().lines().collect();
    if lines.len() != 3 {
        return Err(format!("Expected 3 lines in CSV, got {}", lines.len()));
    }

    // Check content includes hot paths
    if !csv.contains("lifecycle_transition") || !csv.contains("health_gate_evaluation") {
        return Err("CSV missing expected hot path names".to_string());
    }

    Ok(())
}

/// Execute the complete bd-1xwz conformance test suite
pub fn run_bd_1xwz_conformance_tests() -> ConformanceReport {
    let mut results = BTreeMap::new();
    let mut stats = ConformanceStats::default();

    for case in BD_1XWZ_CASES {
        let result = match (case.test_fn)() {
            Ok(()) => {
                match case.level {
                    RequirementLevel::Must => stats.must_pass += 1,
                    RequirementLevel::Should => stats.should_pass += 1,
                    RequirementLevel::May => stats.may_pass += 1,
                }
                TestResult::Pass
            }
            Err(reason) => {
                match case.level {
                    RequirementLevel::Must => stats.must_fail += 1,
                    RequirementLevel::Should => stats.should_fail += 1,
                    RequirementLevel::May => stats.may_fail += 1,
                }
                TestResult::Fail { reason }
            }
        };

        let record = ConformanceRecord {
            id: case.id.to_string(),
            section: case.section.to_string(),
            level: case.level,
            category: case.category,
            description: case.description.to_string(),
            result,
        };

        results.insert(case.id.to_string(), record);
    }

    ConformanceReport {
        timestamp: chrono::Utc::now().to_rfc3339(),
        specification: "bd-1xwz".to_string(),
        version: "1.0".to_string(),
        results,
        stats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_suite_execution() {
        let report = run_bd_1xwz_conformance_tests();

        // Verify we have the expected number of test cases
        assert_eq!(report.results.len(), BD_1XWZ_CASES.len());

        // Verify all MUST requirements pass (conformance requirement)
        assert_eq!(
            report.stats.must_fail, 0,
            "All MUST requirements should pass"
        );

        // Verify compliance score calculation
        let score = report.compliance_score();
        assert!(score >= 0.95, "Compliance score should be at least 95%");
    }

    #[test]
    fn conformance_report_markdown_generation() {
        let report = run_bd_1xwz_conformance_tests();
        let markdown = report.to_markdown();

        assert!(markdown.contains("# bd-1xwz Performance Budget Guard Conformance Report"));
        assert!(markdown.contains("Compliance Score"));
        assert!(markdown.contains("1XWZ-INV-1"));
    }

    #[test]
    fn all_test_cases_have_unique_ids() {
        let mut seen_ids = std::collections::HashSet::new();

        for case in BD_1XWZ_CASES {
            if !seen_ids.insert(case.id) {
                panic!("Duplicate test case ID: {}", case.id);
            }
        }
    }

    #[test]
    fn all_invariants_covered() {
        let has_budget_enforced = BD_1XWZ_CASES.iter().any(|c| c.id == "1XWZ-INV-1");
        let has_regression_blocked = BD_1XWZ_CASES.iter().any(|c| c.id == "1XWZ-INV-2");
        let has_flamegraph_fail = BD_1XWZ_CASES.iter().any(|c| c.id == "1XWZ-INV-3");
        let has_report_always = BD_1XWZ_CASES.iter().any(|c| c.id == "1XWZ-INV-4");

        assert!(has_budget_enforced, "Should test INV-PBG-BUDGET-ENFORCED");
        assert!(
            has_regression_blocked,
            "Should test INV-PBG-REGRESSION-BLOCKED"
        );
        assert!(
            has_flamegraph_fail,
            "Should test INV-PBG-FLAMEGRAPH-ON-FAIL"
        );
        assert!(has_report_always, "Should test INV-PBG-REPORT-ALWAYS");
    }
}
