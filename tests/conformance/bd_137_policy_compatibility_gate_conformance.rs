//! bd-137 Policy-visible Compatibility Gate APIs Conformance Test Suite
//!
//! This harness verifies comprehensive conformance with the bd-137 specification
//! for policy-visible compatibility gate APIs. Uses Pattern 4: Spec-Derived Test Matrix
//! to ensure 100% coverage of all MUST and SHOULD requirements.
//!
//! # Specification Coverage
//!
//! ## Core Invariants (4/4 MUST)
//! - INV-PCG-VISIBLE: All gate decisions visible via structured API responses
//! - INV-PCG-AUDITABLE: Every gate decision produces structured audit events
//! - INV-PCG-RECEIPT: Every divergence/transition produces signed receipts
//! - INV-PCG-TRANSITION: Mode transitions are policy-gated
//!
//! ## Event Codes (4/4 MUST)
//! - PCG-001: Gate check passed
//! - PCG-002: Gate check failed
//! - PCG-003: Mode transition approved
//! - PCG-004: Divergence receipt issued
//!
//! ## Error Codes (5/5 SHOULD)
//! - ERR_COMPAT_SHIM_CAPACITY: Shim capacity exceeded
//! - ERR_COMPAT_PREDICATE_CAPACITY: Predicate capacity exceeded
//! - ERR_COMPAT_SCOPE_CAPACITY: Scope capacity exceeded
//! - ERR_COMPAT_TRACE_ID_EXHAUSTED: Trace ID exhausted
//! - ERR_COMPAT_RECEIPT_ID_EXHAUSTED: Receipt ID exhausted

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// API-DRIFT REMEDIATION (bd-rjc2m.4): this harness was written as an inline module
// (`crate::` paths); as a registered [[test]] integration target it must import through
// the library crate (renamed franken_node -> frankenengine_node). All imported items
// exist unchanged in api::compat_gate. See docs/specs/API_DRIFT_REMEDIATION.md.
// (INV_PCG_* invariant constants are documented in the case table but not referenced in
// code — not imported, to keep clippy -D warnings clean.)
use frankenengine_node::api::compat_gate::{
    CompatGateOperationError, CompatGateRegistrationError, CompatGateService, CompatMode,
    CompatOperationId, CompatPolicyHook, CompatSideEffectCategory, GateCheckRequest, GateDecision,
    ModeTransitionRequest, PolicyPredicate, ShimMetadata, error_codes, event_codes,
    first_tranche_contract_for, first_tranche_operation_contracts,
    l1_proof_carrying_acceptance_subjects,
};
use frankenengine_node::schema_versions;

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

// API-DRIFT REMEDIATION (bd-rjc2m.4): fn-pointer fields cannot derive Serialize/Deserialize
// (E0277); the case table is compile-time only and never serialized — the serializable
// surface is ConformanceRecord/ConformanceReport below (assertions unchanged).
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
    /// Serialized compliance score (0.0-1.0). The same-named method computes it from
    /// stats; this field carries it into JSON reports (latent bug in the never-run
    /// original: serde cannot serialize a method, so json.contains("compliance_score")
    /// could never pass). Fields and methods occupy distinct namespaces in Rust.
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
        let status = if score >= 95.0 {
            "CONFORMANT"
        } else {
            "NON-CONFORMANT"
        };

        format!(
            r#"# bd-137 Policy-visible Compatibility Gate APIs Conformance Report

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
            self.stats.must_pass,
            self.stats.must_fail,
            self.stats.must_pass + self.stats.must_fail,
            if self.stats.must_pass + self.stats.must_fail > 0 {
                self.stats.must_pass as f64 / (self.stats.must_pass + self.stats.must_fail) as f64
                    * 100.0
            } else {
                0.0
            },
            self.stats.should_pass,
            self.stats.should_fail,
            self.stats.should_pass + self.stats.should_fail,
            if self.stats.should_pass + self.stats.should_fail > 0 {
                self.stats.should_pass as f64
                    / (self.stats.should_pass + self.stats.should_fail) as f64
                    * 100.0
            } else {
                0.0
            },
            self.stats.may_pass,
            self.stats.may_fail,
            self.stats.may_pass + self.stats.may_fail,
            if self.stats.may_pass + self.stats.may_fail > 0 {
                self.stats.may_pass as f64 / (self.stats.may_pass + self.stats.may_fail) as f64
                    * 100.0
            } else {
                0.0
            },
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
                output.push_str(&format!(
                    "- **{}**: {} - {}\n",
                    record.id, status, record.description
                ));
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

// Test case definitions following bd-137 specification
const BD_137_CONFORMANCE_CASES: &[ConformanceCase] = &[
    // Core Invariants (MUST requirements)
    ConformanceCase {
        id: "BD137-INV-1",
        section: "10.5",
        level: RequirementLevel::Must,
        description: "INV-PCG-VISIBLE: All gate decisions visible via structured API responses",
        test_fn: test_invariant_visible,
    },
    ConformanceCase {
        id: "BD137-INV-2",
        section: "10.5",
        level: RequirementLevel::Must,
        description: "INV-PCG-AUDITABLE: Every gate decision produces structured audit events",
        test_fn: test_invariant_auditable,
    },
    ConformanceCase {
        id: "BD137-INV-3",
        section: "10.5",
        level: RequirementLevel::Must,
        description: "INV-PCG-RECEIPT: Every divergence/transition produces signed receipts",
        test_fn: test_invariant_receipt,
    },
    ConformanceCase {
        id: "BD137-INV-4",
        section: "10.5",
        level: RequirementLevel::Must,
        description: "INV-PCG-TRANSITION: Mode transitions are policy-gated",
        test_fn: test_invariant_transition,
    },
    // Event Codes (MUST requirements)
    ConformanceCase {
        id: "BD137-EVT-1",
        section: "10.6",
        level: RequirementLevel::Must,
        description: "PCG-001: Gate check passed event emitted on approval",
        test_fn: test_event_pcg_001_gate_passed,
    },
    ConformanceCase {
        id: "BD137-EVT-2",
        section: "10.6",
        level: RequirementLevel::Must,
        description: "PCG-002: Gate check failed event emitted on denial",
        test_fn: test_event_pcg_002_gate_failed,
    },
    ConformanceCase {
        id: "BD137-EVT-3",
        section: "10.6",
        level: RequirementLevel::Must,
        description: "PCG-003: Mode transition approved event emitted on transitions",
        test_fn: test_event_pcg_003_transition_approved,
    },
    ConformanceCase {
        id: "BD137-EVT-4",
        section: "10.6",
        level: RequirementLevel::Must,
        description: "PCG-004: Divergence receipt issued event emitted on receipts",
        test_fn: test_event_pcg_004_receipt_issued,
    },
    // Error Codes (SHOULD requirements)
    ConformanceCase {
        id: "BD137-ERR-1",
        section: "10.7",
        level: RequirementLevel::Should,
        description: "ERR_COMPAT_SHIM_CAPACITY: Shim capacity exceeded error handling",
        test_fn: test_error_shim_capacity_exceeded,
    },
    ConformanceCase {
        id: "BD137-ERR-2",
        section: "10.7",
        level: RequirementLevel::Should,
        description: "ERR_COMPAT_PREDICATE_CAPACITY: Predicate capacity exceeded error handling",
        test_fn: test_error_predicate_capacity_exceeded,
    },
    ConformanceCase {
        id: "BD137-ERR-3",
        section: "10.7",
        level: RequirementLevel::Should,
        description: "ERR_COMPAT_SCOPE_CAPACITY: Scope capacity exceeded error handling",
        test_fn: test_error_scope_capacity_exceeded,
    },
    ConformanceCase {
        id: "BD137-ERR-4",
        section: "10.7",
        level: RequirementLevel::Should,
        description: "ERR_COMPAT_TRACE_ID_EXHAUSTED: Trace ID exhausted error handling",
        test_fn: test_error_trace_id_exhausted,
    },
    ConformanceCase {
        id: "BD137-ERR-5",
        section: "10.7",
        level: RequirementLevel::Should,
        description: "ERR_COMPAT_RECEIPT_ID_EXHAUSTED: Receipt ID exhausted error handling",
        test_fn: test_error_receipt_id_exhausted,
    },
    // API Operations (SHOULD requirements)
    ConformanceCase {
        id: "BD137-API-1",
        section: "10.8",
        level: RequirementLevel::Should,
        description: "Gate check endpoint: allow/deny/audit decisions with traceability",
        test_fn: test_api_gate_check_endpoint,
    },
    ConformanceCase {
        id: "BD137-API-2",
        section: "10.8",
        level: RequirementLevel::Should,
        description: "Mode query endpoint: current compatibility mode per scope",
        test_fn: test_api_mode_query_endpoint,
    },
    ConformanceCase {
        id: "BD137-API-3",
        section: "10.8",
        level: RequirementLevel::Should,
        description: "Mode transition endpoint: policy-gated mode changes with receipts",
        test_fn: test_api_mode_transition_endpoint,
    },
    ConformanceCase {
        id: "BD137-API-4",
        section: "10.8",
        level: RequirementLevel::Should,
        description: "Receipt query endpoint: divergence receipt retrieval by scope/severity",
        test_fn: test_api_receipt_query_endpoint,
    },
    ConformanceCase {
        id: "BD137-API-5",
        section: "10.8",
        level: RequirementLevel::Should,
        description: "Shim registry query: full typed metadata for all registered shims",
        test_fn: test_api_shim_registry_query,
    },
];

// Core Invariant Tests

fn test_invariant_visible() -> TestResult {
    let mut service = create_test_service();

    // Perform gate check to generate events
    let request = GateCheckRequest {
        package_id: "test-pkg".to_string(),
        requested_mode: CompatMode::Strict,
        scope: "test-scope".to_string(),
        policy_context: None,
    };

    if service.gate_check(&request).is_err() {
        return TestResult::Fail {
            reason: "Gate check failed to execute".to_string(),
        };
    }

    // Verify visible events exist
    let has_gate_events = service.events().iter().any(|e| {
        e.code == event_codes::PCG_001_GATE_PASSED || e.code == event_codes::PCG_002_GATE_FAILED
    });

    if !has_gate_events {
        return TestResult::Fail {
            reason: "No gate decision events found - violates INV-PCG-VISIBLE".to_string(),
        };
    }

    TestResult::Pass
}

fn test_invariant_auditable() -> TestResult {
    let mut service = create_test_service();

    let request = GateCheckRequest {
        package_id: "audit-test".to_string(),
        requested_mode: CompatMode::Balanced,
        scope: "audit-scope".to_string(),
        policy_context: Some("audit-context".to_string()),
    };

    if service.gate_check(&request).is_err() {
        return TestResult::Fail {
            reason: "Gate check failed to execute for audit test".to_string(),
        };
    }

    // Verify all events have trace IDs (auditability requirement)
    let all_auditable = service.events().iter().all(|e| !e.trace_id.is_empty());

    if !all_auditable {
        return TestResult::Fail {
            reason: "Events missing trace IDs - violates INV-PCG-AUDITABLE".to_string(),
        };
    }

    TestResult::Pass
}

fn test_invariant_receipt() -> TestResult {
    let mut service = create_test_service();

    let request = GateCheckRequest {
        package_id: "receipt-test".to_string(),
        requested_mode: CompatMode::Strict,
        scope: "receipt-scope".to_string(),
        policy_context: None,
    };

    if service.gate_check(&request).is_err() {
        return TestResult::Fail {
            reason: "Gate check failed for receipt test".to_string(),
        };
    }

    // Verify receipts were generated
    if service.receipts().is_empty() {
        return TestResult::Fail {
            reason: "No receipts generated - violates INV-PCG-RECEIPT".to_string(),
        };
    }

    // Verify receipt has required fields
    let receipt = &service.receipts()[0];
    if receipt.receipt_id.is_empty()
        || receipt.signature.is_empty()
        || receipt.payload_hash.is_empty()
    {
        return TestResult::Fail {
            reason: "Receipt missing required signed fields - violates INV-PCG-RECEIPT".to_string(),
        };
    }

    TestResult::Pass
}

fn test_invariant_transition() -> TestResult {
    let mut service = create_test_service();
    service
        .set_scope_mode("transition-scope", CompatMode::Strict)
        .unwrap();

    // Test escalation requires justification (policy-gated)
    let escalation_request = ModeTransitionRequest {
        scope_id: "transition-scope".to_string(),
        from_mode: CompatMode::Strict,
        to_mode: CompatMode::LegacyRisky,
        justification: "".to_string(), // Empty justification should be denied
        requestor: "test-user".to_string(),
    };

    let result = service.request_transition(&escalation_request).unwrap();

    // Escalation without justification should be denied (policy-gated)
    if result.approved {
        return TestResult::Fail {
            reason: "Escalation approved without justification - violates INV-PCG-TRANSITION"
                .to_string(),
        };
    }

    // Test de-escalation is auto-approved
    let deescalation_request = ModeTransitionRequest {
        scope_id: "transition-scope".to_string(),
        from_mode: CompatMode::Strict,
        to_mode: CompatMode::Strict, // Same mode should be allowed
        justification: "".to_string(),
        requestor: "test-user".to_string(),
    };

    let result = service.request_transition(&deescalation_request).unwrap();
    if !result.approved {
        return TestResult::Fail {
            reason: "Same-mode transition denied - unexpected policy gate behavior".to_string(),
        };
    }

    TestResult::Pass
}

// Event Code Tests

fn test_event_pcg_001_gate_passed() -> TestResult {
    let mut service = create_test_service();

    let request = GateCheckRequest {
        package_id: "pass-test".to_string(),
        requested_mode: CompatMode::Strict,
        scope: "pass-scope".to_string(),
        policy_context: None,
    };

    service
        .set_scope_mode("pass-scope", CompatMode::Balanced)
        .unwrap();

    if service.gate_check(&request).is_err() {
        return TestResult::Fail {
            reason: "Gate check failed to execute".to_string(),
        };
    }

    let has_pass_event = service
        .events()
        .iter()
        .any(|e| e.code == event_codes::PCG_001_GATE_PASSED);

    if !has_pass_event {
        return TestResult::Fail {
            reason: "PCG-001 event not emitted on gate pass".to_string(),
        };
    }

    TestResult::Pass
}

fn test_event_pcg_002_gate_failed() -> TestResult {
    let mut service = create_test_service();

    let request = GateCheckRequest {
        package_id: "fail-test".to_string(),
        requested_mode: CompatMode::LegacyRisky, // Should be denied by strict scope
        scope: "fail-scope".to_string(),
        policy_context: None,
    };

    service
        .set_scope_mode("fail-scope", CompatMode::Strict)
        .unwrap();

    if service.gate_check(&request).is_err() {
        return TestResult::Fail {
            reason: "Gate check failed to execute".to_string(),
        };
    }

    let has_fail_event = service
        .events()
        .iter()
        .any(|e| e.code == event_codes::PCG_002_GATE_FAILED);

    if !has_fail_event {
        return TestResult::Fail {
            reason: "PCG-002 event not emitted on gate failure".to_string(),
        };
    }

    TestResult::Pass
}

fn test_event_pcg_003_transition_approved() -> TestResult {
    let mut service = create_test_service();
    service
        .set_scope_mode("transition-scope", CompatMode::Balanced)
        .unwrap();

    let request = ModeTransitionRequest {
        scope_id: "transition-scope".to_string(),
        from_mode: CompatMode::Balanced,
        to_mode: CompatMode::Strict, // De-escalation should be auto-approved
        justification: "".to_string(),
        requestor: "test-user".to_string(),
    };

    if service.request_transition(&request).is_err() {
        return TestResult::Fail {
            reason: "Mode transition failed to execute".to_string(),
        };
    }

    let has_transition_event = service
        .events()
        .iter()
        .any(|e| e.code == event_codes::PCG_003_TRANSITION_APPROVED);

    if !has_transition_event {
        return TestResult::Fail {
            reason: "PCG-003 event not emitted on approved transition".to_string(),
        };
    }

    TestResult::Pass
}

fn test_event_pcg_004_receipt_issued() -> TestResult {
    let mut service = create_test_service();

    if service
        .issue_divergence_receipt("receipt-scope", "medium")
        .is_err()
    {
        return TestResult::Fail {
            reason: "Divergence receipt failed to issue".to_string(),
        };
    }

    let has_receipt_event = service
        .events()
        .iter()
        .any(|e| e.code == event_codes::PCG_004_RECEIPT_ISSUED);

    if !has_receipt_event {
        return TestResult::Fail {
            reason: "PCG-004 event not emitted on receipt issue".to_string(),
        };
    }

    TestResult::Pass
}

// Error Code Tests

fn test_error_shim_capacity_exceeded() -> TestResult {
    let mut service = create_test_service();

    // Fill shim capacity
    for i in 0..frankenengine_node::capacity_defaults::aliases::MAX_SHIMS {
        let shim = ShimMetadata {
            shim_id: format!("shim-{}", i),
            description: "test shim".to_string(),
            risk_category: "low".to_string(),
            activation_policy: "balanced".to_string(),
            divergence_rationale: "test".to_string(),
            scope: "test".to_string(),
        };

        if service.register_shim(shim).is_err() {
            return TestResult::Fail {
                reason: "Failed to fill shim capacity".to_string(),
            };
        }
    }

    // Try to exceed capacity
    let overflow_shim = ShimMetadata {
        shim_id: "overflow".to_string(),
        description: "overflow test".to_string(),
        risk_category: "low".to_string(),
        activation_policy: "balanced".to_string(),
        divergence_rationale: "overflow".to_string(),
        scope: "test".to_string(),
    };

    match service.register_shim(overflow_shim) {
        Err(CompatGateRegistrationError::ShimCapacityExceeded { .. }) => {
            if error_codes::ERR_COMPAT_SHIM_CAPACITY == "ERR_COMPAT_SHIM_CAPACITY" {
                TestResult::Pass
            } else {
                TestResult::Fail {
                    reason: "Wrong error code for shim capacity exceeded".to_string(),
                }
            }
        }
        _ => TestResult::Fail {
            reason: "Expected shim capacity exceeded error".to_string(),
        },
    }
}

fn test_error_predicate_capacity_exceeded() -> TestResult {
    let mut service = create_test_service();

    // Fill predicate capacity
    for i in 0..frankenengine_node::capacity_defaults::aliases::MAX_PREDICATES {
        let predicate = PolicyPredicate {
            predicate_id: format!("predicate-{}", i),
            signature: "sig".to_string(),
            attenuation: vec!["scope:test".to_string()],
            activation_condition: "balanced".to_string(),
        };

        if service.register_predicate(predicate).is_err() {
            return TestResult::Fail {
                reason: "Failed to fill predicate capacity".to_string(),
            };
        }
    }

    // Try to exceed capacity
    let overflow_predicate = PolicyPredicate {
        predicate_id: "overflow".to_string(),
        signature: "sig".to_string(),
        attenuation: vec!["scope:test".to_string()],
        activation_condition: "balanced".to_string(),
    };

    match service.register_predicate(overflow_predicate) {
        Err(CompatGateRegistrationError::PredicateCapacityExceeded { .. }) => TestResult::Pass,
        _ => TestResult::Fail {
            reason: "Expected predicate capacity exceeded error".to_string(),
        },
    }
}

fn test_error_scope_capacity_exceeded() -> TestResult {
    let mut service = create_test_service();

    // Fill scope capacity through direct insertion
    for i in 0..frankenengine_node::capacity_defaults::aliases::MAX_ENTRIES {
        if service
            .set_scope_mode(&format!("scope-{}", i), CompatMode::Strict)
            .is_err()
        {
            break; // Capacity reached
        }
    }

    // Try to exceed capacity
    match service.set_scope_mode("overflow-scope", CompatMode::Balanced) {
        Err(CompatGateOperationError::ScopeCapacityExceeded { .. }) => TestResult::Pass,
        _ => TestResult::Fail {
            reason: "Expected scope capacity exceeded error".to_string(),
        },
    }
}

fn test_error_trace_id_exhausted() -> TestResult {
    let mut service = create_test_service();

    // Set up trace ID exhaustion scenario
    // API-DRIFT REMEDIATION (bd-rjc2m.4): direct private-field writes (only possible when
    // this harness lived inside the module) -> test-support accessor.
    service.force_trace_id_exhaustion();

    let request = GateCheckRequest {
        package_id: "exhaustion-test".to_string(),
        requested_mode: CompatMode::Strict,
        scope: "exhaustion-scope".to_string(),
        policy_context: None,
    };

    match service.gate_check(&request) {
        Err(CompatGateOperationError::TraceIdSpaceExhausted) => TestResult::Pass,
        _ => TestResult::Fail {
            reason: "Expected trace ID exhausted error".to_string(),
        },
    }
}

fn test_error_receipt_id_exhausted() -> TestResult {
    let mut service = create_test_service();

    // Set up receipt ID exhaustion scenario
    // API-DRIFT REMEDIATION (bd-rjc2m.4): direct private-field writes (only possible when
    // this harness lived inside the module) -> test-support accessor.
    service.force_receipt_id_exhaustion();

    let request = GateCheckRequest {
        package_id: "receipt-exhaustion".to_string(),
        requested_mode: CompatMode::Strict,
        scope: "receipt-scope".to_string(),
        policy_context: None,
    };

    match service.gate_check(&request) {
        Err(CompatGateOperationError::ReceiptIdSpaceExhausted) => TestResult::Pass,
        _ => TestResult::Fail {
            reason: "Expected receipt ID exhausted error".to_string(),
        },
    }
}

// API Operation Tests

fn test_api_gate_check_endpoint() -> TestResult {
    let mut service = create_test_service();
    service
        .set_scope_mode("api-scope", CompatMode::Balanced)
        .unwrap();

    let request = GateCheckRequest {
        package_id: "api-test".to_string(),
        requested_mode: CompatMode::Strict,
        scope: "api-scope".to_string(),
        policy_context: Some("api-context".to_string()),
    };

    match service.gate_check(&request) {
        Ok(response) => {
            // Verify response structure
            if response.decision != GateDecision::Allow
                && response.decision != GateDecision::Deny
                && response.decision != GateDecision::Audit
            {
                return TestResult::Fail {
                    reason: "Invalid gate decision in response".to_string(),
                };
            }

            if response.trace_id.is_empty() || response.receipt_id.is_empty() {
                return TestResult::Fail {
                    reason: "Missing traceability fields in gate check response".to_string(),
                };
            }

            TestResult::Pass
        }
        Err(_) => TestResult::Fail {
            reason: "Gate check API endpoint failed".to_string(),
        },
    }
}

fn test_api_mode_query_endpoint() -> TestResult {
    let mut service = create_test_service();
    service
        .set_scope_mode("query-scope", CompatMode::LegacyRisky)
        .unwrap();

    match service.query_mode("query-scope") {
        Some(response) => {
            if response.mode != CompatMode::LegacyRisky {
                return TestResult::Fail {
                    reason: "Mode query returned incorrect mode".to_string(),
                };
            }

            if response.activated_at.is_empty() || response.receipt_id.is_empty() {
                return TestResult::Fail {
                    reason: "Mode query missing required activation receipt metadata".to_string(),
                };
            }

            if chrono::DateTime::parse_from_rfc3339(&response.activated_at).is_err() {
                return TestResult::Fail {
                    reason: "Mode query activated_at is not RFC3339".to_string(),
                };
            }

            TestResult::Pass
        }
        None => TestResult::Fail {
            reason: "Mode query failed for existing scope".to_string(),
        },
    }
}

fn test_api_mode_transition_endpoint() -> TestResult {
    let mut service = create_test_service();
    service
        .set_scope_mode("transition-scope", CompatMode::Balanced)
        .unwrap();

    let request = ModeTransitionRequest {
        scope_id: "transition-scope".to_string(),
        from_mode: CompatMode::Balanced,
        to_mode: CompatMode::LegacyRisky,
        justification: "Valid justification for escalation".to_string(),
        requestor: "api-test-user".to_string(),
    };

    match service.request_transition(&request) {
        Ok(response) => {
            if response.transition_id.is_empty() || response.receipt_id.is_empty() {
                return TestResult::Fail {
                    reason: "Transition response missing required fields".to_string(),
                };
            }

            // Should be approved with valid justification
            if !response.approved {
                return TestResult::Fail {
                    reason: "Valid escalation transition was denied".to_string(),
                };
            }

            TestResult::Pass
        }
        Err(_) => TestResult::Fail {
            reason: "Mode transition API endpoint failed".to_string(),
        },
    }
}

fn test_api_receipt_query_endpoint() -> TestResult {
    let mut service = create_test_service();

    // Issue test receipts
    service
        .issue_divergence_receipt("receipt-scope-1", "medium")
        .unwrap();
    service
        .issue_divergence_receipt("receipt-scope-2", "high")
        .unwrap();
    service
        .issue_divergence_receipt("receipt-scope-1", "low")
        .unwrap();

    // Test scope filtering
    let scope1_receipts = service.query_receipts(Some("receipt-scope-1"), None);
    if scope1_receipts.len() != 2 {
        return TestResult::Fail {
            reason: "Receipt scope filtering failed".to_string(),
        };
    }

    // Test severity filtering
    let medium_receipts = service.query_receipts(None, Some("medium"));
    if medium_receipts.len() != 1 {
        return TestResult::Fail {
            reason: "Receipt severity filtering failed".to_string(),
        };
    }

    // Test combined filtering
    let combined_receipts = service.query_receipts(Some("receipt-scope-1"), Some("low"));
    if combined_receipts.len() != 1 {
        return TestResult::Fail {
            reason: "Receipt combined filtering failed".to_string(),
        };
    }

    TestResult::Pass
}

fn test_api_shim_registry_query() -> TestResult {
    let mut service = create_test_service();

    // Register test shims
    let shim1 = ShimMetadata {
        shim_id: "shim-1".to_string(),
        description: "Test shim 1".to_string(),
        risk_category: "low".to_string(),
        activation_policy: "balanced".to_string(),
        divergence_rationale: "test divergence".to_string(),
        scope: "scope-1".to_string(),
    };

    let shim2 = ShimMetadata {
        shim_id: "shim-2".to_string(),
        description: "Test shim 2".to_string(),
        risk_category: "medium".to_string(),
        activation_policy: "manual".to_string(),
        divergence_rationale: "test divergence 2".to_string(),
        scope: "*".to_string(), // Global scope
    };

    service.register_shim(shim1).unwrap();
    service.register_shim(shim2).unwrap();

    // Test scoped query
    let scope1_shims = service.query_shims(Some("scope-1"));
    if scope1_shims.len() != 2 {
        // shim-1 + global shim-2
        return TestResult::Fail {
            reason: "Shim scoped query failed".to_string(),
        };
    }

    // Test global query
    let all_shims = service.query_shims(None);
    if all_shims.len() != 2 {
        return TestResult::Fail {
            reason: "Shim global query failed".to_string(),
        };
    }

    // Verify metadata completeness
    for shim in &all_shims {
        if shim.shim_id.is_empty()
            || shim.description.is_empty()
            || shim.risk_category.is_empty()
            || shim.scope.is_empty()
        {
            return TestResult::Fail {
                reason: "Shim metadata incomplete".to_string(),
            };
        }
    }

    TestResult::Pass
}

// Helper functions

fn create_test_service() -> CompatGateService {
    CompatGateService::new()
}

// Main conformance test runner

pub fn run_bd_137_conformance_tests() -> ConformanceReport {
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

    for case in BD_137_CONFORMANCE_CASES {
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
    fn bd_137_conformance_test_runner() {
        let report = run_bd_137_conformance_tests();

        // Verify we have the expected number of test cases
        assert_eq!(report.results.len(), BD_137_CONFORMANCE_CASES.len());

        // Diagnosability (bd-rjc2m.4): name every failing case before asserting on the
        // aggregate score, so a failure identifies its case instead of just a percentage.
        for (id, record) in &report.results {
            if let TestResult::Fail { reason } = &record.result {
                eprintln!("bd-137 FAILED CASE {id}: {reason}");
            }
        }

        // Compliance score should be reasonable (all tests should pass in our implementation)
        assert!(
            report.compliance_score() >= 0.95,
            "bd-137 compliance score too low: {:.1}%",
            report.compliance_score() * 100.0
        );

        // Should have zero MUST requirement failures for conformant implementation
        assert_eq!(
            report.stats.must_fail, 0,
            "MUST requirements failed - implementation not conformant"
        );

        println!(
            "bd-137 conformance: {:.1}% ({} MUST pass, {} SHOULD pass)",
            report.compliance_score() * 100.0,
            report.stats.must_pass,
            report.stats.should_pass
        );
    }

    #[test]
    fn bd_137_conformance_report_generation() {
        let report = run_bd_137_conformance_tests();

        let markdown = report.to_markdown();
        assert!(markdown.contains("bd-137"));
        assert!(markdown.contains("CONFORMANT") || markdown.contains("NON-CONFORMANT"));
        assert!(markdown.contains("MUST"));
        assert!(markdown.contains("SHOULD"));

        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("compliance_score"));
        assert!(json.contains("must_pass"));
        assert!(json.contains("should_pass"));
    }

    #[test]
    fn first_tranche_operation_contracts_have_registered_schema_versions() {
        let versions = schema_versions::all_versions();
        let registered_schemas: std::collections::BTreeSet<&'static str> =
            versions.iter().map(|(_, version)| *version).collect();

        for contract in first_tranche_operation_contracts() {
            for schema in [
                contract.args_schema,
                contract.result_schema,
                contract.error_schema,
            ] {
                assert!(
                    registered_schemas.contains(schema),
                    "schema version {schema} is missing from schema_versions"
                );
            }

            assert!(
                !contract.node_error_parity.is_empty(),
                "{} must document Node/Bun error parity",
                contract.operation_id.registry_id()
            );
            assert!(
                !contract.policy_hooks.is_empty(),
                "{} must declare policy hooks",
                contract.operation_id.registry_id()
            );
            assert!(
                contract.resource_budget.max_duration_ms > 0,
                "{} must declare a nonzero duration budget",
                contract.operation_id.registry_id()
            );
        }
    }

    #[test]
    fn first_tranche_operation_contracts_match_policy_surface() {
        let http = first_tranche_contract_for(CompatOperationId::HttpRequest)
            .expect("http request contract must be registered");
        assert_eq!(http.operation_id.registry_id(), "compat:http:request");
        assert_eq!(
            http.side_effect_category,
            CompatSideEffectCategory::NetworkEgress
        );
        assert!(http.policy_hooks.contains(&CompatPolicyHook::Capability));
        assert!(http.policy_hooks.contains(&CompatPolicyHook::Ssrf));
        assert!(http.policy_hooks.contains(&CompatPolicyHook::Profile));

        let process_env = first_tranche_contract_for(CompatOperationId::ProcessEnv)
            .expect("process env contract must be registered");
        assert_eq!(
            process_env.side_effect_category,
            CompatSideEffectCategory::EnvironmentRead
        );
        assert!(!process_env.policy_hooks.contains(&CompatPolicyHook::Ssrf));
        assert!(
            process_env
                .node_error_parity
                .iter()
                .any(|entry| entry.node_code == "ERR_ACCESS_DENIED" && entry.bun_code.is_none())
        );
    }

    /// INV-PCG-ACCEPTANCE (bd-f5b04.2.4): the acceptance-invariant subject
    /// list the dual-oracle close-condition gate enforces fail-closed must be
    /// exactly the list derived from the canonical first-tranche operation
    /// contracts, so the contract layer and the release machinery cannot
    /// drift apart. Host-effect operations carry a subject; parity-only
    /// operations must not.
    #[test]
    fn acceptance_invariant_subjects_bind_contract_layer_to_close_condition_gate() {
        assert_eq!(
            l1_proof_carrying_acceptance_subjects(),
            schema_versions::L1_PROOF_CARRYING_ACCEPTANCE_SUBJECTS,
            "compat-gate contract layer and schema_versions acceptance list diverged"
        );

        for contract in first_tranche_operation_contracts() {
            let expects_receipt = matches!(
                contract.side_effect_category,
                CompatSideEffectCategory::FilesystemRead
                    | CompatSideEffectCategory::FilesystemWrite
                    | CompatSideEffectCategory::NetworkEgress
            );
            assert_eq!(
                contract.operation_id.l1_proof_carrying_subject().is_some(),
                expects_receipt,
                "{} proof-carrying subject presence must match its host-effect category",
                contract.operation_id.registry_id()
            );
        }
    }
}
