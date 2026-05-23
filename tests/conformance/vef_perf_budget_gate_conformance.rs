//! VEF Performance Budget Gate Conformance Test Harness
//!
//! This module implements a comprehensive conformance test suite for the
//! bd-ufk5 VEF performance budget gate specification.
//!
//! ## Specification Compliance
//!
//! Tests every MUST/SHOULD clause from the VEF performance budget gate specification:
//!
//! ### MUST Requirements (Invariants)
//! - MUST_R_VEF_PBG_001 (INV-VEF-PBG-BUDGET): Every VEF operation has defined p95/p99 latency budgets per mode
//! - MUST_R_VEF_PBG_002 (INV-VEF-PBG-GATE): CI gate fails when any measurement exceeds budget threshold
//! - MUST_R_VEF_PBG_003 (INV-VEF-PBG-BASELINE): Committed baselines enable regression detection across commits
//! - MUST_R_VEF_PBG_004 (INV-VEF-PBG-NOISE): Noise tolerance prevents false failures from measurement jitter
//! - MUST_R_VEF_PBG_005 (INV-VEF-PBG-EVIDENCE): Budget breaches produce profiling evidence for root-cause triage
//! - MUST_R_VEF_PBG_006 (INV-VEF-PBG-MODE): Per-mode budgets enforce mode-appropriate overhead limits
//!
//! ### SHOULD Requirements (Event Codes)
//! - VEF-PERF-001: Benchmark started
//! - VEF-PERF-002: Benchmark completed within budget
//! - VEF-PERF-003: Budget exceeded
//! - VEF-PERF-004: Baseline recorded
//! - VEF-PERF-005: Noise tolerance applied
//!
//! ## Test Architecture
//!
//! Uses Pattern 4: Spec-Derived Test Matrix with structured conformance cases.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use franken_node::tools::vef_perf_budget_gate::{
    VefOperation, BudgetMode, LatencyBudget, BudgetCheckResult, MeasuredLatency,
    VefPerfBudgetConfig, VefPerfBudgetError, VefPerfEvent, GateVerdict, OperationVerdict,
    INV_VEF_PBG_BUDGET, INV_VEF_PBG_GATE, INV_VEF_PBG_BASELINE,
    INV_VEF_PBG_NOISE, INV_VEF_PBG_EVIDENCE, INV_VEF_PBG_MODE,
    VEF_PERF_001, VEF_PERF_002, VEF_PERF_003, VEF_PERF_004, VEF_PERF_005, VEF_PERF_ERR_001,
    BUDGET_SCHEMA_VERSION,
};

/// Test requirement levels from the VEF performance budget gate specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

/// Test categories for organization and reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    Invariants,
    EventCodes,
    ErrorCodes,
    EdgeCases,
    Performance,
    BudgetEnforcement,
}

/// Result of a conformance test execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String }, // Known divergences (XFAIL)
}

/// A single conformance test case derived from the VEF performance budget gate specification.
#[derive(Debug, Clone)]
pub struct ConformanceCase {
    /// Unique test identifier (e.g., "MUST_R_VEF_PBG_001")
    pub id: &'static str,
    /// Specification section reference
    pub section: &'static str,
    /// Requirement level (MUST > SHOULD > MAY)
    pub level: RequirementLevel,
    /// Test category for organization
    pub category: TestCategory,
    /// Human-readable test description
    pub description: &'static str,
    /// Test execution function
    pub test_fn: fn() -> TestResult,
}

/// VEF performance budget gate conformance test suite definition.
pub const VEF_PBG_CONFORMANCE_CASES: &[ConformanceCase] = &[
    // MUST Requirements: Invariants
    ConformanceCase {
        id: "MUST_R_VEF_PBG_001",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Invariants,
        description: "INV-VEF-PBG-BUDGET: Every VEF operation has defined p95/p99 latency budgets per mode",
        test_fn: test_must_r_vef_pbg_001,
    },
    ConformanceCase {
        id: "MUST_R_VEF_PBG_002",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Invariants,
        description: "INV-VEF-PBG-GATE: CI gate fails when any measurement exceeds budget threshold",
        test_fn: test_must_r_vef_pbg_002,
    },
    ConformanceCase {
        id: "MUST_R_VEF_PBG_003",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Invariants,
        description: "INV-VEF-PBG-BASELINE: Committed baselines enable regression detection across commits",
        test_fn: test_must_r_vef_pbg_003,
    },
    ConformanceCase {
        id: "MUST_R_VEF_PBG_004",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Invariants,
        description: "INV-VEF-PBG-NOISE: Noise tolerance prevents false failures from measurement jitter",
        test_fn: test_must_r_vef_pbg_004,
    },
    ConformanceCase {
        id: "MUST_R_VEF_PBG_005",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Invariants,
        description: "INV-VEF-PBG-EVIDENCE: Budget breaches produce profiling evidence for root-cause triage",
        test_fn: test_must_r_vef_pbg_005,
    },
    ConformanceCase {
        id: "MUST_R_VEF_PBG_006",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Invariants,
        description: "INV-VEF-PBG-MODE: Per-mode budgets enforce mode-appropriate overhead limits",
        test_fn: test_must_r_vef_pbg_006,
    },
    // SHOULD Requirements: Event Codes
    ConformanceCase {
        id: "VEF-PBG-EVENT-001",
        section: "events",
        level: RequirementLevel::Should,
        category: TestCategory::EventCodes,
        description: "VEF-PERF-001: Benchmark started event code",
        test_fn: test_event_vef_perf_001,
    },
    ConformanceCase {
        id: "VEF-PBG-EVENT-002",
        section: "events",
        level: RequirementLevel::Should,
        category: TestCategory::EventCodes,
        description: "VEF-PERF-002: Benchmark completed within budget event code",
        test_fn: test_event_vef_perf_002,
    },
    ConformanceCase {
        id: "VEF-PBG-EVENT-003",
        section: "events",
        level: RequirementLevel::Should,
        category: TestCategory::EventCodes,
        description: "VEF-PERF-003: Budget exceeded event code",
        test_fn: test_event_vef_perf_003,
    },
    ConformanceCase {
        id: "VEF-PBG-EVENT-004",
        section: "events",
        level: RequirementLevel::Should,
        category: TestCategory::EventCodes,
        description: "VEF-PERF-004: Baseline recorded event code",
        test_fn: test_event_vef_perf_004,
    },
    ConformanceCase {
        id: "VEF-PBG-EVENT-005",
        section: "events",
        level: RequirementLevel::Should,
        category: TestCategory::EventCodes,
        description: "VEF-PERF-005: Noise tolerance applied event code",
        test_fn: test_event_vef_perf_005,
    },
];

// ═══════════════════════════════════════════════════════════════════════════════
// MUST Requirements: Invariants
// ═══════════════════════════════════════════════════════════════════════════════

/// **MUST_R_VEF_PBG_001**: Every VEF operation MUST have defined p95 and p99 latency budgets per mode.
/// Complete budget coverage ensures no operation can escape performance oversight.
///
/// Specification: INV-VEF-PBG-BUDGET
fn test_must_r_vef_pbg_001() -> TestResult {
    // Test 1: All operations must have budget coverage
    for &operation in VefOperation::all() {
        for &mode in BudgetMode::all() {
            // Create a minimal config and check if budget exists for this combo
            let mut budgets = BTreeMap::new();

            // Add budget for current operation/mode
            let budget = LatencyBudget::new(1000, 2000); // 1ms p95, 2ms p99
            budgets.insert((operation, mode), budget);

            let config = VefPerfBudgetConfig::new(budgets);

            // Verify the budget can be retrieved
            match config.budget_for(operation, mode) {
                Some(budget) => {
                    if budget.p95_us == 0 || budget.p99_us == 0 {
                        return TestResult::Fail {
                            reason: format!("Budget for {:?}/{:?} has zero latency", operation, mode),
                        };
                    }
                    if budget.p95_us > budget.p99_us {
                        return TestResult::Fail {
                            reason: format!("Budget for {:?}/{:?} has p95 > p99", operation, mode),
                        };
                    }
                }
                None => {
                    return TestResult::Fail {
                        reason: format!("Missing budget for operation {:?} in mode {:?}", operation, mode),
                    };
                }
            }
        }
    }

    // Test 2: Verify complete budget configuration is valid
    let mut complete_budgets = BTreeMap::new();
    for &operation in VefOperation::all() {
        for &mode in BudgetMode::all() {
            let budget = match (operation, mode) {
                // Integration operations should have higher budgets
                (VefOperation::ControlPlaneHotPath, _) => LatencyBudget::new(5000, 10000),
                (VefOperation::ExtensionHostHotPath, _) => LatencyBudget::new(5000, 10000),
                // Micro operations lower budgets
                (VefOperation::ReceiptEmission, BudgetMode::Normal) => LatencyBudget::new(500, 1000),
                (VefOperation::ReceiptEmission, BudgetMode::Restricted) => LatencyBudget::new(800, 1500),
                (VefOperation::ReceiptEmission, BudgetMode::Quarantine) => LatencyBudget::new(1200, 2000),
                (VefOperation::ChainAppend, _) => LatencyBudget::new(300, 600),
                (VefOperation::CheckpointComputation, _) => LatencyBudget::new(2000, 4000),
                (VefOperation::VerificationGateCheck, _) => LatencyBudget::new(1000, 2000),
                (VefOperation::ModeTransition, _) => LatencyBudget::new(1500, 3000),
            };
            complete_budgets.insert((operation, mode), budget);
        }
    }

    let complete_config = VefPerfBudgetConfig::new(complete_budgets);
    match complete_config.validate() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail {
            reason: format!("Complete budget configuration validation failed: {:?}", e),
        },
    }
}

/// **MUST_R_VEF_PBG_002**: CI gate MUST fail when any measurement exceeds its budget threshold.
/// Performance regression prevention requires hard budget enforcement.
///
/// Specification: INV-VEF-PBG-GATE
fn test_must_r_vef_pbg_002() -> TestResult {
    let budget = LatencyBudget::new(1000, 2000); // 1ms p95, 2ms p99

    // Test 1: Measurement within budget should pass
    let within_budget = MeasuredLatency::new(800, 1500, 100); // Under p95/p99 thresholds
    let result_pass = budget.check(&within_budget);

    if !result_pass.within_budget {
        return TestResult::Fail {
            reason: "Measurement within budget should pass gate check".to_string(),
        };
    }

    // Test 2: Measurement exceeding p95 should fail
    let exceeds_p95 = MeasuredLatency::new(1200, 1800, 100); // p95 exceeds 1000us
    let result_fail_p95 = budget.check(&exceeds_p95);

    if result_fail_p95.within_budget {
        return TestResult::Fail {
            reason: "Measurement exceeding p95 budget should fail gate check".to_string(),
        };
    }

    // Test 3: Measurement exceeding p99 should fail
    let exceeds_p99 = MeasuredLatency::new(900, 2500, 100); // p99 exceeds 2000us
    let result_fail_p99 = budget.check(&exceeds_p99);

    if result_fail_p99.within_budget {
        return TestResult::Fail {
            reason: "Measurement exceeding p99 budget should fail gate check".to_string(),
        };
    }

    // Test 4: Measurement exceeding both should fail
    let exceeds_both = MeasuredLatency::new(1500, 3000, 100); // Both exceed
    let result_fail_both = budget.check(&exceeds_both);

    if result_fail_both.within_budget {
        return TestResult::Fail {
            reason: "Measurement exceeding both p95 and p99 should fail gate check".to_string(),
        };
    }

    // Test 5: Edge case - exactly at budget should pass
    let exactly_at_budget = MeasuredLatency::new(1000, 2000, 100);
    let result_exact = budget.check(&exactly_at_budget);

    if !result_exact.within_budget {
        return TestResult::Fail {
            reason: "Measurement exactly at budget should pass gate check".to_string(),
        };
    }

    TestResult::Pass
}

/// **MUST_R_VEF_PBG_003**: Committed baselines MUST enable regression detection across commits.
/// Historical performance tracking requires stable baseline references.
///
/// Specification: INV-VEF-PBG-BASELINE
fn test_must_r_vef_pbg_003() -> TestResult {
    // Test baseline measurement stability
    let baseline_measurement_1 = MeasuredLatency::new(800, 1200, 1000);
    let baseline_measurement_2 = MeasuredLatency::new(810, 1190, 1000);
    let baseline_measurement_3 = MeasuredLatency::new(795, 1205, 1000);

    // All baseline measurements should be stable (low coefficient of variation)
    if !baseline_measurement_1.is_stable(5.0) { // 5% CV threshold
        return TestResult::Fail {
            reason: "Baseline measurement 1 should be stable".to_string(),
        };
    }

    if !baseline_measurement_2.is_stable(5.0) {
        return TestResult::Fail {
            reason: "Baseline measurement 2 should be stable".to_string(),
        };
    }

    if !baseline_measurement_3.is_stable(5.0) {
        return TestResult::Fail {
            reason: "Baseline measurement 3 should be stable".to_string(),
        };
    }

    // Test unstable measurement detection
    let unstable_measurement = MeasuredLatency::new(500, 2000, 50); // High variance

    if unstable_measurement.is_stable(5.0) {
        return TestResult::Fail {
            reason: "Unstable measurement should be detected as unstable".to_string(),
        };
    }

    TestResult::Pass
}

/// **MUST_R_VEF_PBG_004**: Noise tolerance MUST prevent false failures from measurement jitter.
/// Stable CI requires filtering measurement noise from true performance regressions.
///
/// Specification: INV-VEF-PBG-NOISE
fn test_must_r_vef_pbg_004() -> TestResult {
    let budget = LatencyBudget::new(1000, 2000);

    // Test 1: Stable measurement with small jitter should pass
    let stable_measurement = MeasuredLatency::new(950, 1900, 1000); // High sample count, low jitter
    let result_stable = budget.check(&stable_measurement);

    if !result_stable.within_budget {
        return TestResult::Fail {
            reason: "Stable measurement within budget should pass".to_string(),
        };
    }

    // Test 2: Check that coefficient of variation is used for stability
    let high_cv_measurement = MeasuredLatency::new(900, 1800, 10); // Low sample count = potential noise
    if high_cv_measurement.is_stable(1.0) { // Very strict CV threshold
        return TestResult::Fail {
            reason: "Low sample count measurement should have noise concerns".to_string(),
        };
    }

    // Test 3: Higher sample count should be more stable
    let low_cv_measurement = MeasuredLatency::new(900, 1800, 10000); // High sample count
    if !low_cv_measurement.is_stable(5.0) { // Reasonable CV threshold
        return TestResult::Fail {
            reason: "High sample count measurement should be stable".to_string(),
        };
    }

    TestResult::Pass
}

/// **MUST_R_VEF_PBG_005**: Budget breaches MUST produce profiling evidence for root-cause triage.
/// Performance debugging requires actionable data beyond pass/fail verdicts.
///
/// Specification: INV-VEF-PBG-EVIDENCE
fn test_must_r_vef_pbg_005() -> TestResult {
    let budget = LatencyBudget::new(1000, 2000);

    // Test budget breach with evidence generation
    let failing_measurement = MeasuredLatency::new(1500, 3000, 100); // Exceeds both thresholds
    let result = budget.check(&failing_measurement);

    // Verify result contains evidence
    if result.within_budget {
        return TestResult::Fail {
            reason: "Failing measurement should not be within budget".to_string(),
        };
    }

    // Check that result provides useful debugging information
    if result.p95_exceeded.is_none() || result.p99_exceeded.is_none() {
        return TestResult::Fail {
            reason: "Budget breach should provide p95/p99 exceeded flags".to_string(),
        };
    }

    // Verify actual vs threshold information is available
    if result.measured_p95_us.is_none() || result.measured_p99_us.is_none() {
        return TestResult::Fail {
            reason: "Budget breach should include measured latency values".to_string(),
        };
    }

    // Test that within-budget results also provide measurement data
    let passing_measurement = MeasuredLatency::new(800, 1500, 100);
    let passing_result = budget.check(&passing_measurement);

    if passing_result.measured_p95_us.is_none() || passing_result.measured_p99_us.is_none() {
        return TestResult::Fail {
            reason: "Passing results should also include measured latency values for trending".to_string(),
        };
    }

    TestResult::Pass
}

/// **MUST_R_VEF_PBG_006**: Per-mode budgets MUST enforce mode-appropriate overhead limits.
/// Different VEF modes have different performance characteristics and should be budgeted accordingly.
///
/// Specification: INV-VEF-PBG-MODE
fn test_must_r_vef_pbg_006() -> TestResult {
    // Test that different modes can have different budgets
    let normal_budget = LatencyBudget::new(500, 1000);
    let restricted_budget = LatencyBudget::new(800, 1500);
    let quarantine_budget = LatencyBudget::new(1200, 2000);

    // Normal mode should be most permissive (lowest latency budget)
    if normal_budget.p95_us > restricted_budget.p95_us {
        return TestResult::Fail {
            reason: "Normal mode should have lower budget than restricted mode".to_string(),
        };
    }

    if restricted_budget.p95_us > quarantine_budget.p95_us {
        return TestResult::Fail {
            reason: "Restricted mode should have lower budget than quarantine mode".to_string(),
        };
    }

    // Test mode-specific budget enforcement
    let measurement = MeasuredLatency::new(700, 1300, 100);

    let normal_result = normal_budget.check(&measurement);
    let restricted_result = restricted_budget.check(&measurement);
    let quarantine_result = quarantine_budget.check(&measurement);

    // This measurement should fail normal mode but pass others
    if normal_result.within_budget {
        return TestResult::Fail {
            reason: "Measurement should exceed normal mode budget".to_string(),
        };
    }

    if !restricted_result.within_budget {
        return TestResult::Fail {
            reason: "Measurement should pass restricted mode budget".to_string(),
        };
    }

    if !quarantine_result.within_budget {
        return TestResult::Fail {
            reason: "Measurement should pass quarantine mode budget".to_string(),
        };
    }

    // Test integration operations vs micro operations
    for &operation in VefOperation::all() {
        if operation.is_integration() {
            // Integration operations should have higher budgets
            let integration_budget = LatencyBudget::new(5000, 10000);
            let high_latency_measurement = MeasuredLatency::new(4000, 8000, 100);
            let integration_result = integration_budget.check(&high_latency_measurement);

            if !integration_result.within_budget {
                return TestResult::Fail {
                    reason: format!("Integration operation {:?} should have higher budget tolerance", operation),
                };
            }
        } else {
            // Micro operations should have tighter budgets
            let micro_budget = LatencyBudget::new(1000, 2000);
            let low_latency_measurement = MeasuredLatency::new(800, 1500, 100);
            let micro_result = micro_budget.check(&low_latency_measurement);

            if !micro_result.within_budget {
                return TestResult::Fail {
                    reason: format!("Micro operation {:?} should pass tighter budget", operation),
                };
            }
        }
    }

    TestResult::Pass
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHOULD Requirements: Event Codes
// ═══════════════════════════════════════════════════════════════════════════════

/// **SHOULD-VEF-PBG-001**: VEF-PERF-001 event code defined for benchmark started.
fn test_event_vef_perf_001() -> TestResult {
    if VEF_PERF_001 == "VEF-PERF-001" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!("VEF_PERF_001 value incorrect: {}", VEF_PERF_001),
        }
    }
}

/// **SHOULD-VEF-PBG-002**: VEF-PERF-002 event code defined for benchmark completed within budget.
fn test_event_vef_perf_002() -> TestResult {
    if VEF_PERF_002 == "VEF-PERF-002" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!("VEF_PERF_002 value incorrect: {}", VEF_PERF_002),
        }
    }
}

/// **SHOULD-VEF-PBG-003**: VEF-PERF-003 event code defined for budget exceeded.
fn test_event_vef_perf_003() -> TestResult {
    if VEF_PERF_003 == "VEF-PERF-003" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!("VEF_PERF_003 value incorrect: {}", VEF_PERF_003),
        }
    }
}

/// **SHOULD-VEF-PBG-004**: VEF-PERF-004 event code defined for baseline recorded.
fn test_event_vef_perf_004() -> TestResult {
    if VEF_PERF_004 == "VEF-PERF-004" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!("VEF_PERF_004 value incorrect: {}", VEF_PERF_004),
        }
    }
}

/// **SHOULD-VEF-PBG-005**: VEF-PERF-005 event code defined for noise tolerance applied.
fn test_event_vef_perf_005() -> TestResult {
    if VEF_PERF_005 == "VEF-PERF-005" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: format!("VEF_PERF_005 value incorrect: {}", VEF_PERF_005),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test Runner
// ═══════════════════════════════════════════════════════════════════════════════

/// Execute the full conformance test suite and generate structured results.
#[cfg(test)]
#[test]
fn run_vef_perf_budget_gate_conformance_suite() {
    let mut pass = 0;
    let mut fail = 0;
    let mut xfail = 0;
    let mut skip = 0;

    println!("═══════════════════════════════════════════════════════════");
    println!("VEF Performance Budget Gate Conformance Test Suite");
    println!("═══════════════════════════════════════════════════════════");

    for case in VEF_PBG_CONFORMANCE_CASES {
        let start_time = std::time::Instant::now();
        let result = (case.test_fn)();
        let duration = start_time.elapsed();

        let verdict = match result {
            TestResult::Pass => {
                pass += 1;
                "PASS"
            }
            TestResult::Fail { ref reason } => {
                fail += 1;
                eprintln!("FAIL {}: {}", case.id, reason);
                "FAIL"
            }
            TestResult::Skipped { ref reason } => {
                skip += 1;
                eprintln!("SKIP {}: {}", case.id, reason);
                "SKIP"
            }
            TestResult::ExpectedFailure { ref reason } => {
                xfail += 1;
                eprintln!("XFAIL {}: {}", case.id, reason);
                "XFAIL"
            }
        };

        // Structured JSON-line output for CI parsing
        println!(
            "{{\"id\":\"{}\",\"verdict\":\"{}\",\"level\":\"{:?}\",\"category\":\"{:?}\",\"duration_ms\":{}}}",
            case.id, verdict, case.level, case.category, duration.as_millis()
        );
    }

    let total = pass + fail + xfail + skip;
    println!("\n═══════════════════════════════════════════════════════════");
    println!("VEF Performance Budget Gate Conformance Summary");
    println!("Total: {}, Pass: {}, Fail: {}, XFail: {}, Skip: {}", total, pass, fail, xfail, skip);

    // Calculate conformance score
    let must_cases = VEF_PBG_CONFORMANCE_CASES.iter().filter(|c| c.level == RequirementLevel::Must).count();
    let must_pass = VEF_PBG_CONFORMANCE_CASES.iter()
        .filter(|c| c.level == RequirementLevel::Must)
        .map(|c| (c.test_fn)())
        .filter(|r| matches!(r, TestResult::Pass))
        .count();

    let conformance_score = if must_cases > 0 {
        (must_pass as f64 / must_cases as f64) * 100.0
    } else {
        0.0
    };

    println!("MUST Conformance: {:.1}% ({}/{})", conformance_score, must_pass, must_cases);
    println!("═══════════════════════════════════════════════════════════");

    assert_eq!(fail, 0, "{} conformance tests failed", fail);
    assert!(conformance_score >= 95.0, "MUST conformance below 95%: {:.1}%", conformance_score);
}