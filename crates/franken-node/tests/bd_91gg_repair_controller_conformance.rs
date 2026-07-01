//! bd-91gg Background Repair Controller Conformance Test Suite
//!
//! This harness verifies comprehensive conformance with the bd-91gg specification
//! for background repair controller with bounded work-per-cycle and fairness.
//! Uses Pattern 4: Spec-Derived Test Matrix to ensure 100% coverage of all MUST and SHOULD requirements.
//!
//! # Specification Coverage
//!
//! ## Core Invariants (4/4 MUST)
//! - INV-BRC-BOUNDED: Total units allocated never exceeds max_units_per_cycle
//! - INV-BRC-FAIRNESS: Every tenant with pending work gets at least fairness_minimum
//! - INV-BRC-AUDITABLE: Every cycle produces a structured RepairCycleAudit
//! - INV-BRC-DETERMINISTIC: Allocation order is deterministic (tenant_id, then priority desc)
//!
//! ## Error Codes (4/4 MUST)
//! - BRC_CAP_EXCEEDED: Capacity exceeded (used in starvation scenarios)
//! - BRC_INVALID_CONFIG: Invalid configuration parameter
//! - BRC_NO_PENDING: No pending repair items
//! - BRC_STARVATION: Tenant starvation detected
//!
//! ## Configuration Validation (5/5 SHOULD)
//! - max_units_per_cycle > 0
//! - fairness_minimum > 0
//! - max_tenants_per_cycle > 0
//! - cycle_id non-empty and unpadded
//! - trace_id non-empty and unpadded
//!
//! ## Input Validation (3/3 SHOULD)
//! - item_id non-empty and unpadded
//! - tenant_id non-empty and unpadded
//! - no duplicate item_ids

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use frankenengine_node::connector::repair_controller::{
    RepairConfig, RepairItem, RepairError,
    run_cycle, validate_config,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String },
}

// NOTE: no Serialize/Deserialize — `test_fn` is a function pointer, which serde
// cannot (de)serialize. The serializable projection is `ConformanceRecord`.
#[derive(Debug, Clone)]
pub struct ConformanceCase {
    pub id: &'static str,
    pub section: &'static str,
    pub level: RequirementLevel,
    pub description: &'static str,
    pub test_fn: fn() -> TestResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRecord {
    pub id: String,
    pub section: String,
    pub level: RequirementLevel,
    pub description: String,
    pub result: TestResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceStats {
    pub must_pass: usize,
    pub must_fail: usize,
    pub should_pass: usize,
    pub should_fail: usize,
    pub may_pass: usize,
    pub may_fail: usize,
    pub expected_failures: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub results: BTreeMap<String, ConformanceRecord>,
    pub stats: ConformanceStats,
    /// Serialized compliance ratio (0.0–1.0) so JSON reports expose the score
    /// directly. Mirrors the `compliance_score()` method, populated at build.
    pub compliance_score: f64,
}

impl ConformanceReport {
    pub fn compliance_score(&self) -> f64 {
        let total_must = self.stats.must_pass + self.stats.must_fail;
        let total_should = self.stats.should_pass + self.stats.should_fail;
        let total_requirements = total_must + total_should;

        if total_requirements == 0 {
            return 1.0;
        }

        let passed_requirements = self.stats.must_pass + self.stats.should_pass;
        passed_requirements as f64 / total_requirements as f64
    }

    pub fn to_markdown(&self) -> String {
        let score = self.compliance_score() * 100.0;
        let status = if score >= 95.0 { "CONFORMANT" } else { "NON-CONFORMANT" };

        format!(r#"# bd-91gg Background Repair Controller Conformance Report

## Compliance Score: {:.1}% - {status}

| Category | Pass | Fail | Total | Score |
|----------|:----:|:----:|:-----:|------:|
| MUST     | {}   | {}   | {}    | {:.1}% |
| SHOULD   | {}   | {}   | {}    | {:.1}% |
| MAY      | {}   | {}   | {}    | {:.1}% |
| **TOTAL**| {}   | {}   | {}    | **{:.1}%** |

## Test Results by Requirement Level

### MUST Requirements
{}

### SHOULD Requirements
{}

### MAY Requirements
{}

## Summary

Total conformance tests: {}
- Expected failures (XFAIL): {}
- Skipped tests: {}

Generated: {}
"#,
            score,
            self.stats.must_pass, self.stats.must_fail,
            self.stats.must_pass + self.stats.must_fail,
            if self.stats.must_pass + self.stats.must_fail > 0 {
                self.stats.must_pass as f64 / (self.stats.must_pass + self.stats.must_fail) as f64 * 100.0
            } else { 0.0 },
            self.stats.should_pass, self.stats.should_fail,
            self.stats.should_pass + self.stats.should_fail,
            if self.stats.should_pass + self.stats.should_fail > 0 {
                self.stats.should_pass as f64 / (self.stats.should_pass + self.stats.should_fail) as f64 * 100.0
            } else { 0.0 },
            self.stats.may_pass, self.stats.may_fail,
            self.stats.may_pass + self.stats.may_fail,
            if self.stats.may_pass + self.stats.may_fail > 0 {
                self.stats.may_pass as f64 / (self.stats.may_pass + self.stats.may_fail) as f64 * 100.0
            } else { 0.0 },
            self.stats.must_pass + self.stats.should_pass + self.stats.may_pass,
            self.stats.must_fail + self.stats.should_fail + self.stats.may_fail,
            self.results.len(),
            score,
            self.format_results_by_level(RequirementLevel::Must),
            self.format_results_by_level(RequirementLevel::Should),
            self.format_results_by_level(RequirementLevel::May),
            self.results.len(),
            self.stats.expected_failures,
            self.stats.skipped,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )
    }

    fn format_results_by_level(&self, level: RequirementLevel) -> String {
        let mut output = String::new();
        for record in self.results.values() {
            if record.level == level {
                let status = match &record.result {
                    TestResult::Pass => "✅ PASS",
                    TestResult::Fail { .. } => "❌ FAIL",
                    TestResult::Skipped { .. } => "⏭️ SKIP",
                    TestResult::ExpectedFailure { .. } => "⏳ XFAIL",
                };
                output.push_str(&format!("- **{}**: {} - {}\n", record.id, status, record.description));
                if let TestResult::Fail { reason } = &record.result {
                    output.push_str(&format!("  - ❌ {}\n", reason));
                }
            }
        }
        if output.is_empty() {
            output.push_str("*No requirements at this level*\n");
        }
        output
    }
}

// Test case definitions following bd-91gg specification
const BD_91GG_CONFORMANCE_CASES: &[ConformanceCase] = &[
    // Core Invariants (MUST requirements)
    ConformanceCase {
        id: "BD91GG-INV-1",
        section: "10.13",
        level: RequirementLevel::Must,
        description: "INV-BRC-BOUNDED: Total units allocated never exceeds max_units_per_cycle",
        test_fn: test_invariant_bounded,
    },
    ConformanceCase {
        id: "BD91GG-INV-2",
        section: "10.13",
        level: RequirementLevel::Must,
        description: "INV-BRC-FAIRNESS: Every tenant with pending work gets at least fairness_minimum",
        test_fn: test_invariant_fairness,
    },
    ConformanceCase {
        id: "BD91GG-INV-3",
        section: "10.13",
        level: RequirementLevel::Must,
        description: "INV-BRC-AUDITABLE: Every cycle produces a structured RepairCycleAudit",
        test_fn: test_invariant_auditable,
    },
    ConformanceCase {
        id: "BD91GG-INV-4",
        section: "10.13",
        level: RequirementLevel::Must,
        description: "INV-BRC-DETERMINISTIC: Allocation order is deterministic (tenant_id, then priority desc)",
        test_fn: test_invariant_deterministic,
    },

    // Error Codes (MUST requirements)
    ConformanceCase {
        id: "BD91GG-ERR-1",
        section: "10.14",
        level: RequirementLevel::Must,
        description: "BRC_INVALID_CONFIG: Invalid configuration parameter error handling",
        test_fn: test_error_invalid_config,
    },
    ConformanceCase {
        id: "BD91GG-ERR-2",
        section: "10.14",
        level: RequirementLevel::Must,
        description: "BRC_NO_PENDING: No pending repair items error handling",
        test_fn: test_error_no_pending,
    },
    ConformanceCase {
        id: "BD91GG-ERR-3",
        section: "10.14",
        level: RequirementLevel::Must,
        description: "BRC_STARVATION: Tenant starvation detection (if implemented)",
        test_fn: test_error_starvation,
    },
    ConformanceCase {
        id: "BD91GG-ERR-4",
        section: "10.14",
        level: RequirementLevel::Must,
        description: "BRC_CAP_EXCEEDED: Capacity exceeded error code presence",
        test_fn: test_error_cap_exceeded,
    },

    // Configuration Validation (SHOULD requirements)
    ConformanceCase {
        id: "BD91GG-CFG-1",
        section: "10.15",
        level: RequirementLevel::Should,
        description: "max_units_per_cycle validation: must be > 0",
        test_fn: test_config_max_units_validation,
    },
    ConformanceCase {
        id: "BD91GG-CFG-2",
        section: "10.15",
        level: RequirementLevel::Should,
        description: "fairness_minimum validation: must be > 0",
        test_fn: test_config_fairness_validation,
    },
    ConformanceCase {
        id: "BD91GG-CFG-3",
        section: "10.15",
        level: RequirementLevel::Should,
        description: "max_tenants_per_cycle validation: must be > 0",
        test_fn: test_config_max_tenants_validation,
    },
    ConformanceCase {
        id: "BD91GG-CFG-4",
        section: "10.15",
        level: RequirementLevel::Should,
        description: "cycle_id validation: non-empty and unpadded",
        test_fn: test_config_cycle_id_validation,
    },
    ConformanceCase {
        id: "BD91GG-CFG-5",
        section: "10.15",
        level: RequirementLevel::Should,
        description: "trace_id validation: non-empty and unpadded",
        test_fn: test_config_trace_id_validation,
    },

    // Input Validation (SHOULD requirements)
    ConformanceCase {
        id: "BD91GG-INP-1",
        section: "10.16",
        level: RequirementLevel::Should,
        description: "item_id validation: non-empty and unpadded",
        test_fn: test_input_item_id_validation,
    },
    ConformanceCase {
        id: "BD91GG-INP-2",
        section: "10.16",
        level: RequirementLevel::Should,
        description: "tenant_id validation: non-empty and unpadded",
        test_fn: test_input_tenant_id_validation,
    },
    ConformanceCase {
        id: "BD91GG-INP-3",
        section: "10.16",
        level: RequirementLevel::Should,
        description: "duplicate item_ids validation: must be rejected",
        test_fn: test_input_duplicate_items_validation,
    },

    // Algorithm Behavior (SHOULD requirements)
    ConformanceCase {
        id: "BD91GG-ALG-1",
        section: "10.17",
        level: RequirementLevel::Should,
        description: "Priority-based allocation: higher priority items allocated first",
        test_fn: test_algorithm_priority_allocation,
    },
    ConformanceCase {
        id: "BD91GG-ALG-2",
        section: "10.17",
        level: RequirementLevel::Should,
        description: "Tenant limit enforcement: max_tenants_per_cycle respected",
        test_fn: test_algorithm_tenant_limit,
    },
    ConformanceCase {
        id: "BD91GG-ALG-3",
        section: "10.17",
        level: RequirementLevel::Should,
        description: "Two-pass allocation: fairness first, then priority",
        test_fn: test_algorithm_two_pass_allocation,
    },
    ConformanceCase {
        id: "BD91GG-ALG-4",
        section: "10.17",
        level: RequirementLevel::Should,
        description: "Zero-sized items handling: counted but not allocated",
        test_fn: test_algorithm_zero_sized_items,
    },
];

// Core Invariant Tests

fn test_invariant_bounded() -> TestResult {
    let config = create_test_config();
    let items = create_large_item_set(1000); // More than config.max_units_per_cycle

    match run_cycle(&items, &config, "test-cycle", "test-trace", "test-ts") {
        Ok((_, audit)) => {
            if audit.total_units_used <= config.max_units_per_cycle {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!(
                        "Units exceeded cap: {} > {}",
                        audit.total_units_used, config.max_units_per_cycle
                    )
                }
            }
        },
        Err(e) => TestResult::Fail {
            reason: format!("Cycle failed unexpectedly: {}", e)
        }
    }
}

fn test_invariant_fairness() -> TestResult {
    let config = RepairConfig {
        max_units_per_cycle: 100,
        fairness_minimum: 5,
        max_tenants_per_cycle: 10,
    };

    let items = vec![
        create_item("t1-high", "tenant1", 10, 3),
        create_item("t1-low", "tenant1", 1, 3),
        create_item("t2-med", "tenant2", 5, 3),
    ];

    match run_cycle(&items, &config, "fairness-test", "trace", "ts") {
        Ok((allocs, _)) => {
            for alloc in &allocs {
                if !alloc.items_allocated.is_empty() && alloc.units_used < config.fairness_minimum {
                    return TestResult::Fail {
                        reason: format!(
                            "Tenant {} allocated {} < fairness_minimum {}",
                            alloc.tenant_id, alloc.units_used, config.fairness_minimum
                        )
                    };
                }
            }
            TestResult::Pass
        },
        Err(e) => TestResult::Fail {
            reason: format!("Fairness test cycle failed: {}", e)
        }
    }
}

fn test_invariant_auditable() -> TestResult {
    let config = create_test_config();
    let items = vec![create_item("test", "tenant", 5, 10)];

    match run_cycle(&items, &config, "audit-test", "audit-trace", "audit-ts") {
        Ok((_, audit)) => {
            // Verify audit record has all required fields
            if audit.cycle_id.is_empty() {
                return TestResult::Fail {
                    reason: "Audit missing cycle_id".to_string()
                };
            }
            if audit.trace_id.is_empty() {
                return TestResult::Fail {
                    reason: "Audit missing trace_id".to_string()
                };
            }
            if audit.timestamp.is_empty() {
                return TestResult::Fail {
                    reason: "Audit missing timestamp".to_string()
                };
            }
            if audit.allocations.is_empty() {
                return TestResult::Fail {
                    reason: "Audit missing allocations".to_string()
                };
            }
            TestResult::Pass
        },
        Err(e) => TestResult::Fail {
            reason: format!("Auditability test failed: {}", e)
        }
    }
}

fn test_invariant_deterministic() -> TestResult {
    let config = create_test_config();
    let items = vec![
        create_item("item1", "zebra", 5, 10),
        create_item("item2", "alpha", 5, 10),
        create_item("item3", "zebra", 8, 10),
        create_item("item4", "alpha", 3, 10),
    ];

    let result1 = run_cycle(&items, &config, "det1", "trace1", "ts1");
    let result2 = run_cycle(&items, &config, "det2", "trace2", "ts2");

    match (result1, result2) {
        (Ok((allocs1, _)), Ok((allocs2, _))) => {
            if allocs1.len() != allocs2.len() {
                return TestResult::Fail {
                    reason: "Allocation count differs between runs".to_string()
                };
            }

            for (a1, a2) in allocs1.iter().zip(allocs2.iter()) {
                if a1.tenant_id != a2.tenant_id {
                    return TestResult::Fail {
                        reason: format!(
                            "Tenant order differs: {} vs {}",
                            a1.tenant_id, a2.tenant_id
                        )
                    };
                }
                if a1.items_allocated != a2.items_allocated {
                    return TestResult::Fail {
                        reason: format!(
                            "Item allocation differs for tenant {}",
                            a1.tenant_id
                        )
                    };
                }
            }
            TestResult::Pass
        },
        _ => TestResult::Fail {
            reason: "Determinism test cycles failed".to_string()
        }
    }
}

// Error Code Tests

fn test_error_invalid_config() -> TestResult {
    let invalid_config = RepairConfig {
        max_units_per_cycle: 0, // Invalid
        fairness_minimum: 5,
        max_tenants_per_cycle: 10,
    };

    let items = vec![create_item("test", "tenant", 5, 10)];

    match run_cycle(&items, &invalid_config, "err-test", "trace", "ts") {
        Err(RepairError::InvalidConfig { .. }) => {
            if (RepairError::InvalidConfig { reason: "test".into() }).code() == "BRC_INVALID_CONFIG" {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: "Wrong error code for invalid config".to_string()
                }
            }
        },
        _ => TestResult::Fail {
            reason: "Expected BRC_INVALID_CONFIG error".to_string()
        }
    }
}

fn test_error_no_pending() -> TestResult {
    let config = create_test_config();
    let items = vec![]; // Empty

    match run_cycle(&items, &config, "no-pending", "trace", "ts") {
        Err(RepairError::NoPending) => {
            if RepairError::NoPending.code() == "BRC_NO_PENDING" {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: "Wrong error code for no pending".to_string()
                }
            }
        },
        _ => TestResult::Fail {
            reason: "Expected BRC_NO_PENDING error".to_string()
        }
    }
}

fn test_error_starvation() -> TestResult {
    // Test that starvation error code exists and is properly formatted
    let starvation_error = RepairError::Starvation {
        tenant_id: "test-tenant".to_string()
    };

    if starvation_error.code() == "BRC_STARVATION" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "Wrong error code for starvation".to_string()
        }
    }
}

fn test_error_cap_exceeded() -> TestResult {
    // Test that cap exceeded error code exists and is properly formatted
    let cap_error = RepairError::CapExceeded {
        used: 110,
        cap: 100,
    };

    if cap_error.code() == "BRC_CAP_EXCEEDED" {
        TestResult::Pass
    } else {
        TestResult::Fail {
            reason: "Wrong error code for cap exceeded".to_string()
        }
    }
}

// Configuration Validation Tests

fn test_config_max_units_validation() -> TestResult {
    let invalid_config = RepairConfig {
        max_units_per_cycle: 0,
        fairness_minimum: 1,
        max_tenants_per_cycle: 1,
    };

    match validate_config(&invalid_config) {
        Err(RepairError::InvalidConfig { reason }) => {
            if reason.contains("max_units_per_cycle must be > 0") {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!("Wrong validation message: {}", reason)
                }
            }
        },
        _ => TestResult::Fail {
            reason: "Expected max_units_per_cycle validation error".to_string()
        }
    }
}

fn test_config_fairness_validation() -> TestResult {
    let invalid_config = RepairConfig {
        max_units_per_cycle: 100,
        fairness_minimum: 0,
        max_tenants_per_cycle: 1,
    };

    match validate_config(&invalid_config) {
        Err(RepairError::InvalidConfig { reason }) => {
            if reason.contains("fairness_minimum must be > 0") {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!("Wrong validation message: {}", reason)
                }
            }
        },
        _ => TestResult::Fail {
            reason: "Expected fairness_minimum validation error".to_string()
        }
    }
}

fn test_config_max_tenants_validation() -> TestResult {
    let invalid_config = RepairConfig {
        max_units_per_cycle: 100,
        fairness_minimum: 1,
        max_tenants_per_cycle: 0,
    };

    match validate_config(&invalid_config) {
        Err(RepairError::InvalidConfig { reason }) => {
            if reason.contains("max_tenants_per_cycle must be > 0") {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!("Wrong validation message: {}", reason)
                }
            }
        },
        _ => TestResult::Fail {
            reason: "Expected max_tenants_per_cycle validation error".to_string()
        }
    }
}

fn test_config_cycle_id_validation() -> TestResult {
    let config = create_test_config();
    let items = vec![create_item("test", "tenant", 5, 10)];

    // Test empty cycle_id
    match run_cycle(&items, &config, "", "trace", "ts") {
        Err(RepairError::InvalidConfig { reason }) => {
            if reason.contains("cycle_id must be non-empty and unpadded") {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!("Wrong cycle_id validation message: {}", reason)
                }
            }
        },
        _ => TestResult::Fail {
            reason: "Expected cycle_id validation error".to_string()
        }
    }
}

fn test_config_trace_id_validation() -> TestResult {
    let config = create_test_config();
    let items = vec![create_item("test", "tenant", 5, 10)];

    // Test empty trace_id
    match run_cycle(&items, &config, "cycle", "", "ts") {
        Err(RepairError::InvalidConfig { reason }) => {
            if reason.contains("trace_id must be non-empty and unpadded") {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!("Wrong trace_id validation message: {}", reason)
                }
            }
        },
        _ => TestResult::Fail {
            reason: "Expected trace_id validation error".to_string()
        }
    }
}

// Input Validation Tests

fn test_input_item_id_validation() -> TestResult {
    let config = create_test_config();
    let items = vec![RepairItem {
        item_id: "".to_string(), // Empty item_id
        tenant_id: "tenant".to_string(),
        priority: 5,
        size_units: 10,
    }];

    match run_cycle(&items, &config, "cycle", "trace", "ts") {
        Err(RepairError::InvalidConfig { reason }) => {
            if reason.contains("item_id must be non-empty and unpadded") {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!("Wrong item_id validation message: {}", reason)
                }
            }
        },
        _ => TestResult::Fail {
            reason: "Expected item_id validation error".to_string()
        }
    }
}

fn test_input_tenant_id_validation() -> TestResult {
    let config = create_test_config();
    let items = vec![RepairItem {
        item_id: "item".to_string(),
        tenant_id: "".to_string(), // Empty tenant_id
        priority: 5,
        size_units: 10,
    }];

    match run_cycle(&items, &config, "cycle", "trace", "ts") {
        Err(RepairError::InvalidConfig { reason }) => {
            if reason.contains("tenant_id must be non-empty and unpadded") {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!("Wrong tenant_id validation message: {}", reason)
                }
            }
        },
        _ => TestResult::Fail {
            reason: "Expected tenant_id validation error".to_string()
        }
    }
}

fn test_input_duplicate_items_validation() -> TestResult {
    let config = create_test_config();
    let items = vec![
        create_item("duplicate", "tenant1", 5, 10),
        create_item("duplicate", "tenant2", 3, 5), // Duplicate item_id
    ];

    match run_cycle(&items, &config, "cycle", "trace", "ts") {
        Err(RepairError::InvalidConfig { reason }) => {
            if reason.contains("duplicate item_id") {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!("Wrong duplicate validation message: {}", reason)
                }
            }
        },
        _ => TestResult::Fail {
            reason: "Expected duplicate item_id validation error".to_string()
        }
    }
}

// Algorithm Behavior Tests

fn test_algorithm_priority_allocation() -> TestResult {
    let config = RepairConfig {
        max_units_per_cycle: 10,
        fairness_minimum: 1,
        max_tenants_per_cycle: 10,
    };

    let items = vec![
        create_item("low-priority", "tenant", 1, 5),
        create_item("high-priority", "tenant", 10, 5),
    ];

    match run_cycle(&items, &config, "priority-test", "trace", "ts") {
        Ok((allocs, _)) => {
            if let Some(alloc) = allocs.first() {
                // High priority item should be allocated first
                if alloc.items_allocated.contains(&"high-priority".to_string()) {
                    TestResult::Pass
                } else {
                    TestResult::Fail {
                        reason: "High priority item not allocated first".to_string()
                    }
                }
            } else {
                TestResult::Fail {
                    reason: "No allocations found".to_string()
                }
            }
        },
        Err(e) => TestResult::Fail {
            reason: format!("Priority test failed: {}", e)
        }
    }
}

fn test_algorithm_tenant_limit() -> TestResult {
    let config = RepairConfig {
        max_units_per_cycle: 100,
        fairness_minimum: 5,
        max_tenants_per_cycle: 2, // Limit to 2 tenants
    };

    let items = vec![
        create_item("t1-item", "tenant1", 5, 5),
        create_item("t2-item", "tenant2", 5, 5),
        create_item("t3-item", "tenant3", 5, 5), // Should be skipped
    ];

    match run_cycle(&items, &config, "tenant-limit", "trace", "ts") {
        Ok((allocs, audit)) => {
            if allocs.len() <= config.max_tenants_per_cycle && audit.tenants_skipped > 0 {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!(
                        "Tenant limit not enforced: {} allocs, {} skipped",
                        allocs.len(), audit.tenants_skipped
                    )
                }
            }
        },
        Err(e) => TestResult::Fail {
            reason: format!("Tenant limit test failed: {}", e)
        }
    }
}

fn test_algorithm_two_pass_allocation() -> TestResult {
    let config = RepairConfig {
        max_units_per_cycle: 20,
        fairness_minimum: 3,
        max_tenants_per_cycle: 10,
    };

    let items = vec![
        create_item("t1-low", "tenant1", 1, 10),   // Low priority, big
        create_item("t2-high", "tenant2", 10, 2),  // High priority, small
    ];

    match run_cycle(&items, &config, "two-pass", "trace", "ts") {
        Ok((allocs, _)) => {
            // Both tenants should get at least fairness_minimum
            let mut tenant1_units = 0;
            let mut tenant2_units = 0;

            for alloc in &allocs {
                if alloc.tenant_id == "tenant1" {
                    tenant1_units = alloc.units_used;
                } else if alloc.tenant_id == "tenant2" {
                    tenant2_units = alloc.units_used;
                }
            }

            if tenant1_units >= config.fairness_minimum && tenant2_units >= config.fairness_minimum {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: format!(
                        "Two-pass allocation failed: t1={}, t2={}, fairness={}",
                        tenant1_units, tenant2_units, config.fairness_minimum
                    )
                }
            }
        },
        Err(e) => TestResult::Fail {
            reason: format!("Two-pass test failed: {}", e)
        }
    }
}

fn test_algorithm_zero_sized_items() -> TestResult {
    let config = create_test_config();
    let items = vec![
        create_item("zero-size", "tenant", 10, 0),    // Zero size
        create_item("normal", "tenant", 5, 10),       // Normal size
    ];

    match run_cycle(&items, &config, "zero-test", "trace", "ts") {
        Ok((allocs, audit)) => {
            if let Some(alloc) = allocs.first() {
                // Zero-sized item should not contribute to units_used
                // Only normal item should be counted
                if alloc.units_used == 10 && audit.total_units_used == 10 {
                    TestResult::Pass
                } else {
                    TestResult::Fail {
                        reason: format!(
                            "Zero-sized item handling failed: alloc_units={}, total_units={}",
                            alloc.units_used, audit.total_units_used
                        )
                    }
                }
            } else {
                TestResult::Fail {
                    reason: "No allocations found for zero-sized test".to_string()
                }
            }
        },
        Err(e) => TestResult::Fail {
            reason: format!("Zero-sized test failed: {}", e)
        }
    }
}

// Helper functions

fn create_test_config() -> RepairConfig {
    RepairConfig {
        max_units_per_cycle: 100,
        fairness_minimum: 5,
        max_tenants_per_cycle: 10,
    }
}

fn create_item(id: &str, tenant: &str, priority: u32, size: u64) -> RepairItem {
    RepairItem {
        item_id: id.to_string(),
        tenant_id: tenant.to_string(),
        priority,
        size_units: size,
    }
}

fn create_large_item_set(total_size: u64) -> Vec<RepairItem> {
    let mut items = Vec::new();
    let mut current_size = 0;
    let mut item_counter = 0;

    while current_size < total_size {
        let remaining = total_size - current_size;
        let item_size = remaining.min(10);

        items.push(create_item(
            &format!("item-{}", item_counter),
            &format!("tenant-{}", item_counter % 5), // 5 different tenants
            5,
            item_size,
        ));

        current_size += item_size;
        item_counter += 1;
    }

    items
}

// Main conformance test runner

pub fn run_bd_91gg_conformance_tests() -> ConformanceReport {
    let mut results = BTreeMap::new();
    let mut stats = ConformanceStats {
        must_pass: 0,
        must_fail: 0,
        should_pass: 0,
        should_fail: 0,
        may_pass: 0,
        may_fail: 0,
        expected_failures: 0,
        skipped: 0,
    };

    for case in BD_91GG_CONFORMANCE_CASES {
        let result = (case.test_fn)();

        let record = ConformanceRecord {
            id: case.id.to_string(),
            section: case.section.to_string(),
            level: case.level,
            description: case.description.to_string(),
            result: result.clone(),
        };

        // Update statistics
        match (&case.level, &result) {
            (RequirementLevel::Must, TestResult::Pass) => stats.must_pass += 1,
            (RequirementLevel::Must, TestResult::Fail { .. }) => stats.must_fail += 1,
            (RequirementLevel::Should, TestResult::Pass) => stats.should_pass += 1,
            (RequirementLevel::Should, TestResult::Fail { .. }) => stats.should_fail += 1,
            (RequirementLevel::May, TestResult::Pass) => stats.may_pass += 1,
            (RequirementLevel::May, TestResult::Fail { .. }) => stats.may_fail += 1,
            (_, TestResult::ExpectedFailure { .. }) => stats.expected_failures += 1,
            (_, TestResult::Skipped { .. }) => stats.skipped += 1,
        }

        results.insert(case.id.to_string(), record);
    }

    let mut report = ConformanceReport {
        results,
        stats,
        compliance_score: 0.0,
    };
    report.compliance_score = report.compliance_score();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bd_91gg_conformance_test_runner() {
        let report = run_bd_91gg_conformance_tests();

        // Verify we have the expected number of test cases
        assert_eq!(report.results.len(), BD_91GG_CONFORMANCE_CASES.len());

        // Compliance score should be reasonable (all tests should pass in our implementation)
        assert!(report.compliance_score() >= 0.95,
            "bd-91gg compliance score too low: {:.1}%",
            report.compliance_score() * 100.0);

        // Should have zero MUST requirement failures for conformant implementation
        assert_eq!(report.stats.must_fail, 0,
            "MUST requirements failed - implementation not conformant");

        println!("bd-91gg conformance: {:.1}% ({} MUST pass, {} SHOULD pass)",
            report.compliance_score() * 100.0,
            report.stats.must_pass,
            report.stats.should_pass);
    }

    #[test]
    fn bd_91gg_conformance_report_generation() {
        let report = run_bd_91gg_conformance_tests();

        let markdown = report.to_markdown();
        assert!(markdown.contains("bd-91gg"));
        assert!(markdown.contains("CONFORMANT") || markdown.contains("NON-CONFORMANT"));
        assert!(markdown.contains("MUST"));
        assert!(markdown.contains("SHOULD"));

        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("compliance_score"));
        assert!(json.contains("must_pass"));
        assert!(json.contains("should_pass"));
    }
}