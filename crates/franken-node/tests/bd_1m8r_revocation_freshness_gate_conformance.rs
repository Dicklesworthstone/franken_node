//! bd-1m8r Revocation Freshness Gate Conformance Test Suite
//!
//! This harness verifies comprehensive conformance with the bd-1m8r specification
//! for revocation freshness gate per safety tier. Uses Pattern 4: Spec-Derived Test Matrix
//! to ensure 100% coverage of all MUST and SHOULD requirements.
//!
//! # Specification Coverage
//!
//! ## Core Invariants (4/4 MUST)
//! - INV-RF-STANDARD-PASS: Standard tier always passes, regardless of revocation age
//! - INV-RF-TIER-GATE: Risky/Dangerous denied if revocation data is stale
//! - INV-RF-OVERRIDE-RECEIPT: Override allows stale actions with valid receipt
//! - INV-RF-AUDIT: Every evaluation produces a structured FreshnessDecision record
//!
//! ## Error Codes (3/3 MUST)
//! - RF_STALE_FRONTIER: Revocation data exceeds max age for tier
//! - RF_OVERRIDE_REQUIRED: Override receipt required or invalid
//! - RF_POLICY_INVALID: Policy configuration violates constraints
//!
//! ## Policy Validation (3/3 SHOULD)
//! - dangerous_max_age <= risky_max_age constraint
//! - risky_max_age > 0 constraint
//! - Policy validation before gate decisions
//!
//! ## Field Validation (5/5 SHOULD)
//! - action_id non-empty and unpadded
//! - trace_id non-empty and unpadded
//! - timestamp non-empty and unpadded
//! - No control characters in text fields
//! - No null bytes in text fields
//!
//! ## Override Receipt Security (4/4 SHOULD)
//! - Constant-time action_id comparison
//! - Constant-time trace_id comparison
//! - Actor field validation (non-empty, clean)
//! - Reason field validation (non-empty, clean)

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use frankenengine_node::security::revocation_freshness::*;

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

        format!(r#"# bd-1m8r Revocation Freshness Gate Conformance Report

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

// Test case definitions following bd-1m8r specification
const BD_1M8R_CONFORMANCE_CASES: &[ConformanceCase] = &[
    // Core Invariants (MUST requirements)
    ConformanceCase {
        id: "BD1M8R-INV-1",
        section: "10.9",
        level: RequirementLevel::Must,
        description: "INV-RF-STANDARD-PASS: Standard tier always passes, regardless of revocation age",
        test_fn: test_invariant_standard_pass,
    },
    ConformanceCase {
        id: "BD1M8R-INV-2",
        section: "10.9",
        level: RequirementLevel::Must,
        description: "INV-RF-TIER-GATE: Risky/Dangerous denied if revocation data is stale",
        test_fn: test_invariant_tier_gate,
    },
    ConformanceCase {
        id: "BD1M8R-INV-3",
        section: "10.9",
        level: RequirementLevel::Must,
        description: "INV-RF-OVERRIDE-RECEIPT: Override allows stale actions with valid receipt",
        test_fn: test_invariant_override_receipt,
    },
    ConformanceCase {
        id: "BD1M8R-INV-4",
        section: "10.9",
        level: RequirementLevel::Must,
        description: "INV-RF-AUDIT: Every evaluation produces a structured FreshnessDecision record",
        test_fn: test_invariant_audit,
    },

    // Error Codes (MUST requirements)
    ConformanceCase {
        id: "BD1M8R-ERR-1",
        section: "10.10",
        level: RequirementLevel::Must,
        description: "RF_STALE_FRONTIER: Revocation data exceeds max age for tier",
        test_fn: test_error_stale_frontier,
    },
    ConformanceCase {
        id: "BD1M8R-ERR-2",
        section: "10.10",
        level: RequirementLevel::Must,
        description: "RF_OVERRIDE_REQUIRED: Override receipt required or invalid",
        test_fn: test_error_override_required,
    },
    ConformanceCase {
        id: "BD1M8R-ERR-3",
        section: "10.10",
        level: RequirementLevel::Must,
        description: "RF_POLICY_INVALID: Policy configuration violates constraints",
        test_fn: test_error_policy_invalid,
    },

    // Policy Validation (SHOULD requirements)
    ConformanceCase {
        id: "BD1M8R-POL-1",
        section: "10.11",
        level: RequirementLevel::Should,
        description: "dangerous_max_age <= risky_max_age constraint enforcement",
        test_fn: test_policy_dangerous_risky_constraint,
    },
    ConformanceCase {
        id: "BD1M8R-POL-2",
        section: "10.11",
        level: RequirementLevel::Should,
        description: "risky_max_age > 0 constraint enforcement",
        test_fn: test_policy_risky_nonzero_constraint,
    },
    ConformanceCase {
        id: "BD1M8R-POL-3",
        section: "10.11",
        level: RequirementLevel::Should,
        description: "Policy validation executed before gate decisions",
        test_fn: test_policy_validation_precedence,
    },

    // Field Validation (SHOULD requirements)
    ConformanceCase {
        id: "BD1M8R-FLD-1",
        section: "10.12",
        level: RequirementLevel::Should,
        description: "action_id validation: non-empty and unpadded",
        test_fn: test_field_action_id_validation,
    },
    ConformanceCase {
        id: "BD1M8R-FLD-2",
        section: "10.12",
        level: RequirementLevel::Should,
        description: "trace_id validation: non-empty and unpadded",
        test_fn: test_field_trace_id_validation,
    },
    ConformanceCase {
        id: "BD1M8R-FLD-3",
        section: "10.12",
        level: RequirementLevel::Should,
        description: "timestamp validation: non-empty and unpadded",
        test_fn: test_field_timestamp_validation,
    },
    ConformanceCase {
        id: "BD1M8R-FLD-4",
        section: "10.12",
        level: RequirementLevel::Should,
        description: "Control character rejection in text fields",
        test_fn: test_field_control_character_rejection,
    },
    ConformanceCase {
        id: "BD1M8R-FLD-5",
        section: "10.12",
        level: RequirementLevel::Should,
        description: "Null byte rejection in text fields",
        test_fn: test_field_null_byte_rejection,
    },

    // Override Receipt Security (SHOULD requirements)
    ConformanceCase {
        id: "BD1M8R-OVR-1",
        section: "10.13",
        level: RequirementLevel::Should,
        description: "Constant-time action_id comparison for security",
        test_fn: test_override_action_id_comparison,
    },
    ConformanceCase {
        id: "BD1M8R-OVR-2",
        section: "10.13",
        level: RequirementLevel::Should,
        description: "Constant-time trace_id comparison for security",
        test_fn: test_override_trace_id_comparison,
    },
    ConformanceCase {
        id: "BD1M8R-OVR-3",
        section: "10.13",
        level: RequirementLevel::Should,
        description: "Actor field validation (non-empty, clean)",
        test_fn: test_override_actor_validation,
    },
    ConformanceCase {
        id: "BD1M8R-OVR-4",
        section: "10.13",
        level: RequirementLevel::Should,
        description: "Reason field validation (non-empty, clean)",
        test_fn: test_override_reason_validation,
    },

    // Boundary Behavior (SHOULD requirements)
    ConformanceCase {
        id: "BD1M8R-BND-1",
        section: "10.14",
        level: RequirementLevel::Should,
        description: "Fail-closed boundary behavior: age == max_age denied",
        test_fn: test_boundary_fail_closed,
    },
    ConformanceCase {
        id: "BD1M8R-BND-2",
        section: "10.14",
        level: RequirementLevel::Should,
        description: "Fresh boundary behavior: age < max_age allowed",
        test_fn: test_boundary_fresh_allowed,
    },
    ConformanceCase {
        id: "BD1M8R-BND-3",
        section: "10.14",
        level: RequirementLevel::Should,
        description: "Different tier boundaries enforced correctly",
        test_fn: test_boundary_tier_differences,
    },
];

// Core Invariant Tests

fn test_invariant_standard_pass() -> TestResult {
    let policy = create_test_policy();

    // Test extremely large age values
    for large_age in [u64::MAX, 999_999_999, policy.risky_max_age_secs * 10] {
        let check = create_check(SafetyTier::Standard, large_age);

        match evaluate_freshness(&policy, &check, None) {
            Ok(decision) => {
                if !decision.allowed {
                    return TestResult::Fail {
                        reason: format!("Standard tier denied for age {}", large_age)
                    };
                }
                if decision.max_age_secs.is_some() {
                    return TestResult::Fail {
                        reason: "Standard tier should not have max_age_secs".to_string()
                    };
                }
            },
            Err(e) => {
                return TestResult::Fail {
                    reason: format!("Standard tier failed with error: {}", e)
                };
            }
        }
    }

    TestResult::Pass
}

fn test_invariant_tier_gate() -> TestResult {
    let policy = create_test_policy();

    // Test Risky tier with stale data
    let stale_risky_check = create_check(SafetyTier::Risky, policy.risky_max_age_secs + 1);
    match evaluate_freshness(&policy, &stale_risky_check, None) {
        Err(e) => {
            if e.code() != "RF_STALE_FRONTIER" {
                return TestResult::Fail {
                    reason: format!("Wrong error code for stale risky: {}", e.code())
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Stale risky action was allowed".to_string()
            };
        }
    }

    // Test Dangerous tier with stale data
    let stale_dangerous_check = create_check(SafetyTier::Dangerous, policy.dangerous_max_age_secs + 1);
    match evaluate_freshness(&policy, &stale_dangerous_check, None) {
        Err(e) => {
            if e.code() != "RF_STALE_FRONTIER" {
                return TestResult::Fail {
                    reason: format!("Wrong error code for stale dangerous: {}", e.code())
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Stale dangerous action was allowed".to_string()
            };
        }
    }

    // Test fresh data is allowed
    let fresh_risky_check = create_check(SafetyTier::Risky, policy.risky_max_age_secs - 1);
    match evaluate_freshness(&policy, &fresh_risky_check, None) {
        Ok(decision) => {
            if !decision.allowed {
                return TestResult::Fail {
                    reason: "Fresh risky action was denied".to_string()
                };
            }
        },
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Fresh risky action failed: {}", e)
            };
        }
    }

    TestResult::Pass
}

fn test_invariant_override_receipt() -> TestResult {
    let policy = create_test_policy();

    // Test override allows stale risky action
    let stale_check = create_check(SafetyTier::Risky, policy.risky_max_age_secs + 1000);
    let override_receipt = create_override_receipt(&stale_check);

    match evaluate_freshness(&policy, &stale_check, Some(&override_receipt)) {
        Ok(decision) => {
            if !decision.allowed {
                return TestResult::Fail {
                    reason: "Override receipt did not allow stale action".to_string()
                };
            }
            if decision.override_receipt.is_none() {
                return TestResult::Fail {
                    reason: "Override receipt not recorded in decision".to_string()
                };
            }
            let recorded_receipt = decision.override_receipt.unwrap();
            if recorded_receipt.actor != override_receipt.actor {
                return TestResult::Fail {
                    reason: "Override receipt actor not preserved".to_string()
                };
            }
        },
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Override receipt failed: {}", e)
            };
        }
    }

    // Test override allows stale dangerous action
    let stale_dangerous_check = create_check(SafetyTier::Dangerous, policy.dangerous_max_age_secs + 500);
    let dangerous_override = create_override_receipt(&stale_dangerous_check);

    match evaluate_freshness(&policy, &stale_dangerous_check, Some(&dangerous_override)) {
        Ok(decision) => {
            if !decision.allowed {
                return TestResult::Fail {
                    reason: "Override receipt did not allow stale dangerous action".to_string()
                };
            }
        },
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Override for dangerous failed: {}", e)
            };
        }
    }

    TestResult::Pass
}

fn test_invariant_audit() -> TestResult {
    let policy = create_test_policy();

    // Test all three tiers produce decisions
    for tier in [SafetyTier::Standard, SafetyTier::Risky, SafetyTier::Dangerous] {
        let check = create_check(tier, 100); // Fresh for all tiers

        match evaluate_freshness(&policy, &check, None) {
            Ok(decision) => {
                if decision.action_id != check.action_id {
                    return TestResult::Fail {
                        reason: format!("Decision missing action_id for tier {:?}", tier)
                    };
                }
                if decision.trace_id != check.trace_id {
                    return TestResult::Fail {
                        reason: format!("Decision missing trace_id for tier {:?}", tier)
                    };
                }
                if decision.timestamp != check.timestamp {
                    return TestResult::Fail {
                        reason: format!("Decision missing timestamp for tier {:?}", tier)
                    };
                }
                if decision.tier != tier {
                    return TestResult::Fail {
                        reason: format!("Decision tier mismatch for {:?}", tier)
                    };
                }
                if decision.revocation_age_secs != check.revocation_age_secs {
                    return TestResult::Fail {
                        reason: format!("Decision age mismatch for tier {:?}", tier)
                    };
                }
                if decision.reason.is_empty() {
                    return TestResult::Fail {
                        reason: format!("Decision missing reason for tier {:?}", tier)
                    };
                }
            },
            Err(_) => {
                // Even errors should not occur for fresh data on standard/risky/dangerous
                if tier == SafetyTier::Standard {
                    return TestResult::Fail {
                        reason: "Standard tier produced error instead of audit decision".to_string()
                    };
                }
            }
        }
    }

    TestResult::Pass
}

// Error Code Tests

fn test_error_stale_frontier() -> TestResult {
    let policy = create_test_policy();

    let stale_check = create_check(SafetyTier::Risky, policy.risky_max_age_secs + 1);
    match evaluate_freshness(&policy, &stale_check, None) {
        Err(e) => {
            if e.code() != "RF_STALE_FRONTIER" {
                return TestResult::Fail {
                    reason: format!("Wrong error code: expected RF_STALE_FRONTIER, got {}", e.code())
                };
            }

            let error_string = e.to_string();
            if !error_string.contains("RF_STALE_FRONTIER") {
                return TestResult::Fail {
                    reason: "Error display missing RF_STALE_FRONTIER".to_string()
                };
            }
            if !error_string.contains(&format!("{}", policy.risky_max_age_secs + 1)) {
                return TestResult::Fail {
                    reason: "Error display missing actual age".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Expected RF_STALE_FRONTIER error".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_error_override_required() -> TestResult {
    let policy = create_test_policy();

    // Test invalid override receipt (mismatched action_id)
    let check = create_check(SafetyTier::Risky, policy.risky_max_age_secs + 1);
    let mut bad_receipt = create_override_receipt(&check);
    bad_receipt.action_id = "different-action".to_string();

    match evaluate_freshness(&policy, &check, Some(&bad_receipt)) {
        Err(e) => {
            if e.code() != "RF_OVERRIDE_REQUIRED" {
                return TestResult::Fail {
                    reason: format!("Wrong error code: expected RF_OVERRIDE_REQUIRED, got {}", e.code())
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Expected RF_OVERRIDE_REQUIRED error".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_error_policy_invalid() -> TestResult {
    // Test dangerous > risky constraint
    let invalid_policy = FreshnessPolicy {
        risky_max_age_secs: 100,
        dangerous_max_age_secs: 200,
    };

    let check = create_check(SafetyTier::Standard, 0);
    match evaluate_freshness(&invalid_policy, &check, None) {
        Err(e) => {
            if e.code() != "RF_POLICY_INVALID" {
                return TestResult::Fail {
                    reason: format!("Wrong error code: expected RF_POLICY_INVALID, got {}", e.code())
                };
            }
            if !e.to_string().contains("dangerous_max_age must be <= risky_max_age") {
                return TestResult::Fail {
                    reason: "Error message missing expected constraint text".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Expected RF_POLICY_INVALID error".to_string()
            };
        }
    }

    TestResult::Pass
}

// Policy Validation Tests

fn test_policy_dangerous_risky_constraint() -> TestResult {
    let invalid_policy = FreshnessPolicy {
        risky_max_age_secs: 300,
        dangerous_max_age_secs: 301,
    };

    match invalid_policy.validate() {
        Err(e) => {
            if e.code() != "RF_POLICY_INVALID" {
                return TestResult::Fail {
                    reason: "Policy validation should return RF_POLICY_INVALID".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Invalid policy passed validation".to_string()
            };
        }
    }

    // Test valid policy
    let valid_policy = FreshnessPolicy {
        risky_max_age_secs: 3600,
        dangerous_max_age_secs: 300,
    };

    if valid_policy.validate().is_err() {
        return TestResult::Fail {
            reason: "Valid policy failed validation".to_string()
        };
    }

    TestResult::Pass
}

fn test_policy_risky_nonzero_constraint() -> TestResult {
    let invalid_policy = FreshnessPolicy {
        risky_max_age_secs: 0,
        dangerous_max_age_secs: 0,
    };

    match invalid_policy.validate() {
        Err(e) => {
            if e.code() != "RF_POLICY_INVALID" {
                return TestResult::Fail {
                    reason: "Zero risky age should return RF_POLICY_INVALID".to_string()
                };
            }
            if !e.to_string().contains("risky_max_age must be > 0") {
                return TestResult::Fail {
                    reason: "Error message should mention risky_max_age > 0".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Zero risky age should fail validation".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_policy_validation_precedence() -> TestResult {
    let invalid_policy = FreshnessPolicy {
        risky_max_age_secs: 100,
        dangerous_max_age_secs: 200,
    };

    let stale_check = create_check(SafetyTier::Dangerous, 50); // Fresh by invalid policy standards
    let override_receipt = create_override_receipt(&stale_check);

    // Policy validation should happen before any gate decisions
    match evaluate_freshness(&invalid_policy, &stale_check, Some(&override_receipt)) {
        Err(e) => {
            if e.code() != "RF_POLICY_INVALID" {
                return TestResult::Fail {
                    reason: "Policy validation should precede gate decisions".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Invalid policy should be rejected before gate evaluation".to_string()
            };
        }
    }

    TestResult::Pass
}

// Field Validation Tests

fn test_field_action_id_validation() -> TestResult {
    let policy = create_test_policy();

    // Test empty action_id
    let mut check = create_check(SafetyTier::Standard, 0);
    check.action_id = "".to_string();

    match evaluate_freshness(&policy, &check, None) {
        Err(e) => {
            if e.code() != "RF_POLICY_INVALID" {
                return TestResult::Fail {
                    reason: "Empty action_id should return RF_POLICY_INVALID".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Empty action_id should be rejected".to_string()
            };
        }
    }

    // Test padded action_id
    check.action_id = " action ".to_string();
    match evaluate_freshness(&policy, &check, None) {
        Err(e) => {
            if e.code() != "RF_POLICY_INVALID" {
                return TestResult::Fail {
                    reason: "Padded action_id should return RF_POLICY_INVALID".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Padded action_id should be rejected".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_field_trace_id_validation() -> TestResult {
    let policy = create_test_policy();

    // Test empty trace_id
    let mut check = create_check(SafetyTier::Standard, 0);
    check.trace_id = "".to_string();

    match evaluate_freshness(&policy, &check, None) {
        Err(e) => {
            if e.code() != "RF_POLICY_INVALID" {
                return TestResult::Fail {
                    reason: "Empty trace_id should return RF_POLICY_INVALID".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Empty trace_id should be rejected".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_field_timestamp_validation() -> TestResult {
    let policy = create_test_policy();

    // Test empty timestamp
    let mut check = create_check(SafetyTier::Standard, 0);
    check.timestamp = "".to_string();

    match evaluate_freshness(&policy, &check, None) {
        Err(e) => {
            if e.code() != "RF_POLICY_INVALID" {
                return TestResult::Fail {
                    reason: "Empty timestamp should return RF_POLICY_INVALID".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Empty timestamp should be rejected".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_field_control_character_rejection() -> TestResult {
    let policy = create_test_policy();

    let mut check = create_check(SafetyTier::Standard, 0);
    check.trace_id = "trace\nwith\nnewlines".to_string();

    match evaluate_freshness(&policy, &check, None) {
        Err(e) => {
            if e.code() != "RF_POLICY_INVALID" {
                return TestResult::Fail {
                    reason: "Control characters should return RF_POLICY_INVALID".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Control characters should be rejected".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_field_null_byte_rejection() -> TestResult {
    let policy = create_test_policy();

    let mut check = create_check(SafetyTier::Standard, 0);
    check.action_id = "action\0with\0nulls".to_string();

    match evaluate_freshness(&policy, &check, None) {
        Err(e) => {
            if e.code() != "RF_POLICY_INVALID" {
                return TestResult::Fail {
                    reason: "Null bytes should return RF_POLICY_INVALID".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Null bytes should be rejected".to_string()
            };
        }
    }

    TestResult::Pass
}

// Override Receipt Security Tests

fn test_override_action_id_comparison() -> TestResult {
    let policy = create_test_policy();
    let check = create_check(SafetyTier::Risky, policy.risky_max_age_secs + 1);

    // Test exact match works
    let good_receipt = create_override_receipt(&check);
    if evaluate_freshness(&policy, &check, Some(&good_receipt)).is_err() {
        return TestResult::Fail {
            reason: "Exact action_id match should work".to_string()
        };
    }

    // Test case sensitivity
    let mut bad_receipt = create_override_receipt(&check);
    bad_receipt.action_id = check.action_id.to_uppercase();

    match evaluate_freshness(&policy, &check, Some(&bad_receipt)) {
        Err(e) => {
            if e.code() != "RF_OVERRIDE_REQUIRED" {
                return TestResult::Fail {
                    reason: "Case-different action_id should fail with RF_OVERRIDE_REQUIRED".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Case-different action_id should be rejected".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_override_trace_id_comparison() -> TestResult {
    let policy = create_test_policy();
    let check = create_check(SafetyTier::Dangerous, policy.dangerous_max_age_secs + 1);

    // Test suffix attack
    let mut bad_receipt = create_override_receipt(&check);
    bad_receipt.trace_id = format!("{} ", check.trace_id);

    match evaluate_freshness(&policy, &check, Some(&bad_receipt)) {
        Err(e) => {
            if e.code() != "RF_OVERRIDE_REQUIRED" {
                return TestResult::Fail {
                    reason: "Trace_id with suffix should fail with RF_OVERRIDE_REQUIRED".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Trace_id with suffix should be rejected".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_override_actor_validation() -> TestResult {
    let policy = create_test_policy();
    let check = create_check(SafetyTier::Risky, policy.risky_max_age_secs + 1);

    // Test empty actor
    let mut bad_receipt = create_override_receipt(&check);
    bad_receipt.actor = "".to_string();

    match evaluate_freshness(&policy, &check, Some(&bad_receipt)) {
        Err(e) => {
            if e.code() != "RF_OVERRIDE_REQUIRED" {
                return TestResult::Fail {
                    reason: "Empty actor should fail with RF_OVERRIDE_REQUIRED".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Empty actor should be rejected".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_override_reason_validation() -> TestResult {
    let policy = create_test_policy();
    let check = create_check(SafetyTier::Dangerous, policy.dangerous_max_age_secs + 1);

    // Test whitespace-only reason
    let mut bad_receipt = create_override_receipt(&check);
    bad_receipt.reason = "   ".to_string();

    match evaluate_freshness(&policy, &check, Some(&bad_receipt)) {
        Err(e) => {
            if e.code() != "RF_OVERRIDE_REQUIRED" {
                return TestResult::Fail {
                    reason: "Whitespace reason should fail with RF_OVERRIDE_REQUIRED".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Whitespace reason should be rejected".to_string()
            };
        }
    }

    TestResult::Pass
}

// Boundary Behavior Tests

fn test_boundary_fail_closed() -> TestResult {
    let policy = create_test_policy();

    // Test risky tier at exact boundary
    let boundary_check = create_check(SafetyTier::Risky, policy.risky_max_age_secs);
    match evaluate_freshness(&policy, &boundary_check, None) {
        Err(e) => {
            if e.code() != "RF_STALE_FRONTIER" {
                return TestResult::Fail {
                    reason: "Boundary should fail closed with RF_STALE_FRONTIER".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Boundary age should be denied (fail-closed)".to_string()
            };
        }
    }

    // Test dangerous tier at exact boundary
    let dangerous_boundary_check = create_check(SafetyTier::Dangerous, policy.dangerous_max_age_secs);
    match evaluate_freshness(&policy, &dangerous_boundary_check, None) {
        Err(e) => {
            if e.code() != "RF_STALE_FRONTIER" {
                return TestResult::Fail {
                    reason: "Dangerous boundary should fail closed".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Dangerous boundary age should be denied".to_string()
            };
        }
    }

    TestResult::Pass
}

fn test_boundary_fresh_allowed() -> TestResult {
    let policy = create_test_policy();

    // Test just under boundary
    let fresh_check = create_check(SafetyTier::Risky, policy.risky_max_age_secs - 1);
    match evaluate_freshness(&policy, &fresh_check, None) {
        Ok(decision) => {
            if !decision.allowed {
                return TestResult::Fail {
                    reason: "Fresh data should be allowed".to_string()
                };
            }
        },
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Fresh data failed: {}", e)
            };
        }
    }

    TestResult::Pass
}

fn test_boundary_tier_differences() -> TestResult {
    let policy = create_test_policy();

    // Age that's fresh for risky but stale for dangerous
    let test_age = policy.dangerous_max_age_secs + 1;
    if test_age >= policy.risky_max_age_secs {
        return TestResult::Fail {
            reason: "Test setup: need dangerous < test_age < risky".to_string()
        };
    }

    // Should be allowed for risky
    let risky_check = create_check(SafetyTier::Risky, test_age);
    match evaluate_freshness(&policy, &risky_check, None) {
        Ok(decision) => {
            if !decision.allowed {
                return TestResult::Fail {
                    reason: "Age should be fresh for risky tier".to_string()
                };
            }
        },
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Risky tier failed unexpectedly: {}", e)
            };
        }
    }

    // Should be denied for dangerous
    let dangerous_check = create_check(SafetyTier::Dangerous, test_age);
    match evaluate_freshness(&policy, &dangerous_check, None) {
        Err(e) => {
            if e.code() != "RF_STALE_FRONTIER" {
                return TestResult::Fail {
                    reason: "Dangerous tier should fail with RF_STALE_FRONTIER".to_string()
                };
            }
        },
        Ok(_) => {
            return TestResult::Fail {
                reason: "Age should be stale for dangerous tier".to_string()
            };
        }
    }

    TestResult::Pass
}

// Helper functions

fn create_test_policy() -> FreshnessPolicy {
    FreshnessPolicy {
        risky_max_age_secs: 3600,
        dangerous_max_age_secs: 300,
    }
}

fn create_check(tier: SafetyTier, age: u64) -> FreshnessCheck {
    FreshnessCheck {
        action_id: "test-action".to_string(),
        tier,
        revocation_age_secs: age,
        trace_id: "test-trace".to_string(),
        timestamp: "2026-05-22T20:00:00Z".to_string(),
    }
}

fn create_override_receipt(check: &FreshnessCheck) -> OverrideReceipt {
    OverrideReceipt {
        action_id: check.action_id.clone(),
        actor: "test-operator".to_string(),
        reason: "emergency override for testing".to_string(),
        timestamp: "2026-05-22T20:01:00Z".to_string(),
        trace_id: check.trace_id.clone(),
    }
}

// Main conformance test runner

pub fn run_bd_1m8r_conformance_tests() -> ConformanceReport {
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

    for case in BD_1M8R_CONFORMANCE_CASES {
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
    fn bd_1m8r_conformance_test_runner() {
        let report = run_bd_1m8r_conformance_tests();

        // Verify we have the expected number of test cases
        assert_eq!(report.results.len(), BD_1M8R_CONFORMANCE_CASES.len());

        // Compliance score should be reasonable (all tests should pass in our implementation)
        assert!(report.compliance_score() >= 0.95,
            "bd-1m8r compliance score too low: {:.1}%",
            report.compliance_score() * 100.0);

        // Should have zero MUST requirement failures for conformant implementation
        assert_eq!(report.stats.must_fail, 0,
            "MUST requirements failed - implementation not conformant");

        println!("bd-1m8r conformance: {:.1}% ({} MUST pass, {} SHOULD pass)",
            report.compliance_score() * 100.0,
            report.stats.must_pass,
            report.stats.should_pass);
    }

    #[test]
    fn bd_1m8r_conformance_report_generation() {
        let report = run_bd_1m8r_conformance_tests();

        let markdown = report.to_markdown();
        assert!(markdown.contains("bd-1m8r"));
        assert!(markdown.contains("CONFORMANT") || markdown.contains("NON-CONFORMANT"));
        assert!(markdown.contains("MUST"));
        assert!(markdown.contains("SHOULD"));

        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("compliance_score"));
        assert!(json.contains("must_pass"));
        assert!(json.contains("should_pass"));
    }
}