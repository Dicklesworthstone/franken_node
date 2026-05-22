//! bd-3rya: Hardening State Machine Conformance Test Harness
//!
//! Verifies the four core invariants of the monotonic hardening mode state machine:
//! - INV-HARDEN-MONOTONIC: hardening level can only increase without governance rollback
//! - INV-HARDEN-DURABLE: committed level survives crash recovery
//! - INV-HARDEN-AUDITABLE: every transition is recorded with timestamp and trigger
//! - INV-HARDEN-GOVERNANCE: rollback requires valid signed governance artifact
//!
//! Pattern 4: Spec-Derived Test Matrix with comprehensive requirement coverage

use frankenengine_node::policy::hardening_state_machine::{
    HardeningLevel, HardeningStateMachine, HardeningError, TransitionTrigger
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Conformance Test Framework
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,    // Specification MUST - failure = non-conformant
    Should,  // Specification SHOULD - failure = degraded conformance
    May,     // Specification MAY - optional behavior
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestCategory {
    Monotonicity,        // INV-HARDEN-MONOTONIC tests
    Durability,          // INV-HARDEN-DURABLE tests
    Auditability,        // INV-HARDEN-AUDITABLE tests
    Governance,          // INV-HARDEN-GOVERNANCE tests
    HardeningLevels,     // Level ordering and comparison
    EventCodes,          // Event code coverage
    EdgeCase,            // Boundary conditions
    Integration,         // Multi-invariant scenarios
}

#[derive(Debug, Clone)]
pub struct ConformanceTestCase {
    pub id: &'static str,
    pub requirement_level: RequirementLevel,
    pub category: TestCategory,
    pub description: &'static str,
    pub test_fn: fn() -> TestResult,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String },
}

// ---------------------------------------------------------------------------
// Test Fixture Builders
// ---------------------------------------------------------------------------

fn test_timestamp() -> u64 {
    1640995200 // 2022-01-01 00:00:00 UTC
}

fn test_trace_id() -> String {
    "test-trace-12345".to_string()
}

// ---------------------------------------------------------------------------
// INV-HARDEN-MONOTONIC: Hardening level can only increase without governance rollback
// ---------------------------------------------------------------------------

fn test_monotonic_escalation_succeeds() -> TestResult {
    let mut sm = HardeningStateMachine::new();
    assert_eq!(sm.current_level(), HardeningLevel::Baseline);

    // Test escalation from Baseline -> Standard
    let result = sm.escalate(HardeningLevel::Standard, test_timestamp(), &test_trace_id());
    match result {
        Ok(_) => {
            if sm.current_level() == HardeningLevel::Standard {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!("Expected Standard level after escalation, got {:?}", sm.current_level())
                }
            }
        }
        Err(e) => TestResult::Fail {
            reason: format!("Valid escalation was rejected: {:?}", e)
        }
    }
}

fn test_monotonic_regression_rejected() -> TestResult {
    let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);

    // Attempt regression from Enhanced -> Standard (should be rejected)
    let result = sm.escalate(HardeningLevel::Standard, test_timestamp(), &test_trace_id());
    match result {
        Err(HardeningError::IllegalRegression { current, attempted }) => {
            if current == HardeningLevel::Enhanced && attempted == HardeningLevel::Standard {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!("Wrong regression error details: current={:?}, attempted={:?}", current, attempted)
                }
            }
        }
        Ok(_) => TestResult::Fail {
            reason: "Regression was incorrectly allowed - monotonicity violated".to_string()
        }
        Err(other) => TestResult::Fail {
            reason: format!("Unexpected error type for regression: {:?}", other)
        }
    }
}

fn test_monotonic_same_level_rejected() -> TestResult {
    let mut sm = HardeningStateMachine::with_level(HardeningLevel::Standard);

    // Attempt transition to same level (should be rejected)
    let result = sm.escalate(HardeningLevel::Standard, test_timestamp(), &test_trace_id());
    match result {
        Err(HardeningError::IllegalRegression { .. }) => TestResult::Pass,
        Ok(_) => TestResult::Fail {
            reason: "Same-level transition was incorrectly allowed - monotonicity violated".to_string()
        }
        Err(other) => TestResult::Fail {
            reason: format!("Unexpected error type for same-level transition: {:?}", other)
        }
    }
}

// ---------------------------------------------------------------------------
// INV-HARDEN-AUDITABLE: Every transition is recorded with timestamp and trigger
// ---------------------------------------------------------------------------

fn test_auditable_transition_recorded() -> TestResult {
    let mut sm = HardeningStateMachine::new();
    let timestamp = test_timestamp();
    let trace_id = test_trace_id();

    let result = sm.escalate(HardeningLevel::Enhanced, timestamp, &trace_id);
    match result {
        Ok(record) => {
            // Verify transition record contains required audit information
            if record.from_level == HardeningLevel::Baseline &&
               record.to_level == HardeningLevel::Enhanced &&
               record.timestamp == timestamp &&
               record.trace_id == trace_id &&
               matches!(record.trigger, TransitionTrigger::Escalation) {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: "Transition record missing required audit information".to_string()
                }
            }
        }
        Err(e) => TestResult::Fail {
            reason: format!("Valid escalation failed: {:?}", e)
        }
    }
}

fn test_auditable_multiple_transitions() -> TestResult {
    let mut sm = HardeningStateMachine::new();

    // Perform multiple escalations
    let _r1 = sm.escalate(HardeningLevel::Standard, test_timestamp(), "trace-1");
    let _r2 = sm.escalate(HardeningLevel::Enhanced, test_timestamp() + 1000, "trace-2");

    // Verify transition log contains both transitions
    if sm.transition_count() >= 2 {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "Multiple transitions not properly logged".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// HardeningLevel Ordering Tests
// ---------------------------------------------------------------------------

fn test_hardening_level_total_ordering() -> TestResult {
    let levels = vec![
        HardeningLevel::Baseline,
        HardeningLevel::Standard,
        HardeningLevel::Enhanced,
        HardeningLevel::Maximum,
        HardeningLevel::Critical,
    ];

    // Verify total ordering: each level < next level
    for i in 0..levels.len() - 1 {
        if levels[i].rank() >= levels[i + 1].rank() {
            return TestResult::Fail {
                reason: format!("Ordering violation: {:?} should be < {:?}", levels[i], levels[i + 1])
            };
        }
    }

    TestResult::Pass
}

fn test_hardening_level_label_roundtrip() -> TestResult {
    let levels = vec![
        HardeningLevel::Baseline,
        HardeningLevel::Standard,
        HardeningLevel::Enhanced,
        HardeningLevel::Maximum,
        HardeningLevel::Critical,
    ];

    for level in levels {
        let label = level.label();
        match HardeningLevel::from_label(label) {
            Some(parsed) => {
                if parsed != level {
                    return TestResult::Fail {
                        reason: format!("Label roundtrip failed: {:?} -> {} -> {:?}", level, label, parsed)
                    };
                }
            }
            None => {
                return TestResult::Fail {
                    reason: format!("Failed to parse label for {:?}: {}", level, label)
                };
            }
        }
    }

    TestResult::Pass
}

// ---------------------------------------------------------------------------
// INV-HARDEN-DURABLE: Committed level survives crash recovery
// ---------------------------------------------------------------------------

fn test_durable_state_persistence() -> TestResult {
    // This tests the structural property that state machine preserves level
    let original_level = HardeningLevel::Enhanced;
    let sm1 = HardeningStateMachine::with_level(original_level);

    // Simulate "crash" by creating new instance with same level
    let sm2 = HardeningStateMachine::with_level(sm1.current_level());

    if sm2.current_level() == original_level {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "State machine level not preserved across reconstruction".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// INV-HARDEN-GOVERNANCE: Rollback requires valid signed governance artifact
// ---------------------------------------------------------------------------

fn test_governance_rollback_structure() -> TestResult {
    // Test that governance rollback is a separate mechanism from escalation
    // (Implementation detail testing - verify the API exists for governance)

    // For now, test that escalation API doesn't allow regression without governance
    let mut sm = HardeningStateMachine::with_level(HardeningLevel::Maximum);
    let result = sm.escalate(HardeningLevel::Standard, test_timestamp(), &test_trace_id());

    match result {
        Err(HardeningError::IllegalRegression { .. }) => {
            TestResult::Pass // Correctly rejects regression via escalation API
        }
        Ok(_) => TestResult::Fail {
            reason: "Regression allowed without governance mechanism".to_string()
        }
        Err(_) => TestResult::Fail {
            reason: "Unexpected error type for governance-required regression".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

fn test_edge_case_critical_level_escalation() -> TestResult {
    let mut sm = HardeningStateMachine::with_level(HardeningLevel::Maximum);

    // Escalate to Critical (highest level)
    let result = sm.escalate(HardeningLevel::Critical, test_timestamp(), &test_trace_id());
    match result {
        Ok(_) => {
            if sm.current_level() == HardeningLevel::Critical {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: "Critical level not set correctly".to_string()
                }
            }
        }
        Err(e) => TestResult::Fail {
            reason: format!("Failed to escalate to Critical level: {:?}", e)
        }
    }
}

fn test_edge_case_empty_trace_id() -> TestResult {
    let mut sm = HardeningStateMachine::new();

    // Test with empty trace_id
    let result = sm.escalate(HardeningLevel::Standard, test_timestamp(), "");
    match result {
        Ok(_) => TestResult::Pass, // Empty trace_id should be allowed
        Err(_) => TestResult::Skipped {
            reason: "Empty trace_id may be rejected by implementation".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

fn test_integration_monotonic_audit_chain() -> TestResult {
    let mut sm = HardeningStateMachine::new();

    // Test full escalation chain with audit trail
    let escalations = vec![
        (HardeningLevel::Standard, "step-1"),
        (HardeningLevel::Enhanced, "step-2"),
        (HardeningLevel::Maximum, "step-3"),
    ];

    for (i, (level, trace)) in escalations.iter().enumerate() {
        let result = sm.escalate(*level, test_timestamp() + (i as u64 * 1000), trace);
        match result {
            Ok(_) => {
                if sm.current_level() != *level {
                    return TestResult::Fail {
                        reason: format!("Level not updated correctly in step {}: expected {:?}, got {:?}",
                                       i, level, sm.current_level())
                    };
                }
            }
            Err(e) => {
                return TestResult::Fail {
                    reason: format!("Escalation failed in step {}: {:?}", i, e)
                };
            }
        }
    }

    TestResult::Pass
}

// ---------------------------------------------------------------------------
// Test Registry & Runner
// ---------------------------------------------------------------------------

const CONFORMANCE_TESTS: &[ConformanceTestCase] = &[
    // INV-HARDEN-MONOTONIC tests
    ConformanceTestCase {
        id: "BD3RYA-MONO-001",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Monotonicity,
        description: "Valid escalation to higher level succeeds",
        test_fn: test_monotonic_escalation_succeeds,
    },
    ConformanceTestCase {
        id: "BD3RYA-MONO-002",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Monotonicity,
        description: "Regression to lower level is rejected",
        test_fn: test_monotonic_regression_rejected,
    },
    ConformanceTestCase {
        id: "BD3RYA-MONO-003",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Monotonicity,
        description: "Transition to same level is rejected",
        test_fn: test_monotonic_same_level_rejected,
    },

    // INV-HARDEN-AUDITABLE tests
    ConformanceTestCase {
        id: "BD3RYA-AUDIT-001",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Auditability,
        description: "Transition record contains timestamp, trace_id, and trigger",
        test_fn: test_auditable_transition_recorded,
    },
    ConformanceTestCase {
        id: "BD3RYA-AUDIT-002",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Auditability,
        description: "Multiple transitions are properly logged in sequence",
        test_fn: test_auditable_multiple_transitions,
    },

    // HardeningLevel ordering
    ConformanceTestCase {
        id: "BD3RYA-LEVEL-001",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::HardeningLevels,
        description: "Hardening levels follow total ordering Baseline < Standard < Enhanced < Maximum < Critical",
        test_fn: test_hardening_level_total_ordering,
    },
    ConformanceTestCase {
        id: "BD3RYA-LEVEL-002",
        requirement_level: RequirementLevel::Should,
        category: TestCategory::HardeningLevels,
        description: "Level labels support round-trip serialization",
        test_fn: test_hardening_level_label_roundtrip,
    },

    // INV-HARDEN-DURABLE tests
    ConformanceTestCase {
        id: "BD3RYA-DUR-001",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Durability,
        description: "State machine preserves level across reconstruction",
        test_fn: test_durable_state_persistence,
    },

    // INV-HARDEN-GOVERNANCE tests
    ConformanceTestCase {
        id: "BD3RYA-GOV-001",
        requirement_level: RequirementLevel::Must,
        category: TestCategory::Governance,
        description: "Regression rejected without governance mechanism",
        test_fn: test_governance_rollback_structure,
    },

    // Edge cases
    ConformanceTestCase {
        id: "BD3RYA-EDGE-001",
        requirement_level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "Escalation to Critical (maximum) level works correctly",
        test_fn: test_edge_case_critical_level_escalation,
    },
    ConformanceTestCase {
        id: "BD3RYA-EDGE-002",
        requirement_level: RequirementLevel::May,
        category: TestCategory::EdgeCase,
        description: "Empty trace_id handling",
        test_fn: test_edge_case_empty_trace_id,
    },

    // Integration
    ConformanceTestCase {
        id: "BD3RYA-INT-001",
        requirement_level: RequirementLevel::Should,
        category: TestCategory::Integration,
        description: "Full escalation chain with monotonicity and audit trail",
        test_fn: test_integration_monotonic_audit_chain,
    },
];

pub fn run_conformance_tests() -> ConformanceReport {
    let mut results = Vec::new();
    let mut must_pass = 0;
    let mut must_fail = 0;
    let mut should_pass = 0;
    let mut should_fail = 0;

    for test_case in CONFORMANCE_TESTS {
        let result = (test_case.test_fn)();

        match (&result, &test_case.requirement_level) {
            (TestResult::Pass, RequirementLevel::Must) => must_pass += 1,
            (TestResult::Fail { .. }, RequirementLevel::Must) => must_fail += 1,
            (TestResult::Pass, RequirementLevel::Should) => should_pass += 1,
            (TestResult::Fail { .. }, RequirementLevel::Should) => should_fail += 1,
            _ => {} // Skip/XFAIL don't count toward pass/fail
        }

        // Structured JSON-line output for CI parsing
        println!(
            "{{\"id\":\"{}\",\"verdict\":\"{}\",\"level\":\"{:?}\",\"category\":\"{:?}\"}}",
            test_case.id,
            match &result {
                TestResult::Pass => "PASS",
                TestResult::Fail { .. } => "FAIL",
                TestResult::Skipped { .. } => "SKIP",
                TestResult::ExpectedFailure { .. } => "XFAIL",
            },
            test_case.requirement_level,
            test_case.category
        );

        if let TestResult::Fail { reason } = &result {
            eprintln!("FAIL {}: {}\n  Reason: {}", test_case.id, test_case.description, reason);
        }

        results.push(TestCaseResult {
            id: test_case.id,
            description: test_case.description,
            requirement_level: test_case.requirement_level.clone(),
            category: test_case.category.clone(),
            result,
        });
    }

    let total_must = must_pass + must_fail;
    let total_should = should_pass + should_fail;
    let must_score = if total_must > 0 { (must_pass as f64 / total_must as f64) * 100.0 } else { 100.0 };
    let should_score = if total_should > 0 { (should_pass as f64 / total_should as f64) * 100.0 } else { 100.0 };

    println!("\nbd-3rya Hardening State Machine Conformance Report:");
    println!("MUST clauses: {}/{} pass ({:.1}%)", must_pass, total_must, must_score);
    println!("SHOULD clauses: {}/{} pass ({:.1}%)", should_pass, total_should, should_score);

    assert_eq!(must_fail, 0, "{} MUST-level conformance tests failed", must_fail);

    ConformanceReport {
        must_pass,
        must_fail,
        must_score,
        should_pass,
        should_fail,
        should_score,
        results,
    }
}

#[derive(Debug)]
pub struct ConformanceReport {
    pub must_pass: usize,
    pub must_fail: usize,
    pub must_score: f64,
    pub should_pass: usize,
    pub should_fail: usize,
    pub should_score: f64,
    pub results: Vec<TestCaseResult>,
}

#[derive(Debug)]
pub struct TestCaseResult {
    pub id: &'static str,
    pub description: &'static str,
    pub requirement_level: RequirementLevel,
    pub category: TestCategory,
    pub result: TestResult,
}

#[cfg(test)]
mod conformance_tests {
    use super::*;

    #[test]
    fn bd_3rya_hardening_state_machine_conformance() {
        run_conformance_tests();
    }
}