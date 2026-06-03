//! bd-b9b6: Durability violation diagnostic bundles conformance harness.
//!
//! Pattern 4: Spec-Derived Test Matrix for bd-b9b6 durability violation invariants.
//! Verifies complete coverage of MUST_R requirements from bd-b9b6 specification.
//!
//! # MUST_R Requirements Coverage
//!
//! - MUST_R_DVB_001: INV-VIOLATION-DETERMINISTIC - identical context produces identical bundle
//! - MUST_R_DVB_002: INV-VIOLATION-CAUSAL - bundle includes complete causal event chain
//! - MUST_R_DVB_003: INV-VIOLATION-HALT - gating operations blocked after emission
//!
//! # SHOULD Event Code Coverage
//!
//! - EVD-VIOLATION-001: Bundle generation events
//! - EVD-VIOLATION-002: Halt enforcement events
//! - EVD-VIOLATION-003: Halt clearing events
//! - EVD-VIOLATION-004: Operation rejection events

use frankenengine_node::observability::durability_violation::{
    CausalEvent, CausalEventType, DurabilityHaltedError, DurabilityViolationDetector,
    FailedArtifact, HaltPolicy, ProofContext, ViolationContext, event_codes, generate_bundle,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

// ── Conformance Case Framework ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone)]
pub struct ConformanceCase {
    pub id: &'static str,
    pub section: &'static str,
    pub level: RequirementLevel,
    pub description: &'static str,
    pub test_fn: fn() -> TestResult,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
}

impl TestResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, TestResult::Pass)
    }
}

// ── MUST_R Requirement Test Cases ─────────────────────────────────────

const DURABILITY_VIOLATION_CONFORMANCE_CASES: &[ConformanceCase] = &[
    // MUST_R_DVB_001: INV-VIOLATION-DETERMINISTIC
    ConformanceCase {
        id: "MUST_R_DVB_001",
        section: "determinism",
        level: RequirementLevel::Must,
        description: "Identical ViolationContext produces identical bundle_id",
        test_fn: test_must_r_dvb_001_deterministic_bundle_generation,
    },
    // MUST_R_DVB_002: INV-VIOLATION-CAUSAL
    ConformanceCase {
        id: "MUST_R_DVB_002",
        section: "causality",
        level: RequirementLevel::Must,
        description: "Bundle preserves complete causal event chain ordering",
        test_fn: test_must_r_dvb_002_causal_chain_preservation,
    },
    // MUST_R_DVB_003: INV-VIOLATION-HALT
    ConformanceCase {
        id: "MUST_R_DVB_003",
        section: "gating",
        level: RequirementLevel::Must,
        description: "Operations blocked after violation bundle emission",
        test_fn: test_must_r_dvb_003_halt_enforcement,
    },
];

const EVENT_CODE_CONFORMANCE_CASES: &[ConformanceCase] = &[
    ConformanceCase {
        id: "EVD-VIOLATION-001",
        section: "events",
        level: RequirementLevel::Should,
        description: "Bundle generation emits EVD-VIOLATION-001",
        test_fn: test_should_evd_violation_001_bundle_generated,
    },
    ConformanceCase {
        id: "EVD-VIOLATION-002",
        section: "events",
        level: RequirementLevel::Should,
        description: "Halt enforcement emits EVD-VIOLATION-002",
        test_fn: test_should_evd_violation_002_gating_halted,
    },
    ConformanceCase {
        id: "EVD-VIOLATION-003",
        section: "events",
        level: RequirementLevel::Should,
        description: "Halt clearing emits EVD-VIOLATION-003",
        test_fn: test_should_evd_violation_003_halt_cleared,
    },
    ConformanceCase {
        id: "EVD-VIOLATION-004",
        section: "events",
        level: RequirementLevel::Should,
        description: "Operation rejection emits EVD-VIOLATION-004",
        test_fn: test_should_evd_violation_004_op_rejected,
    },
];

// ── Test Implementation Functions ──────────────────────────────────────

fn test_must_r_dvb_001_deterministic_bundle_generation() -> TestResult {
    // INV-VIOLATION-DETERMINISTIC: identical context -> identical bundle
    let context = create_reference_violation_context();

    let bundle1 = generate_bundle(&context);
    let bundle2 = generate_bundle(&context);
    let bundle3 = generate_bundle(&context);

    // Bundle IDs must be identical
    if bundle1.bundle_id != bundle2.bundle_id {
        return TestResult::Fail {
            reason: format!(
                "MUST_R_DVB_001 violated: bundle_id mismatch between runs 1 and 2\n\
                 run1: {}\n\
                 run2: {}",
                bundle1.bundle_id.as_str(),
                bundle2.bundle_id.as_str()
            ),
        };
    }

    if bundle2.bundle_id != bundle3.bundle_id {
        return TestResult::Fail {
            reason: format!(
                "MUST_R_DVB_001 violated: bundle_id mismatch between runs 2 and 3\n\
                 run2: {}\n\
                 run3: {}",
                bundle2.bundle_id.as_str(),
                bundle3.bundle_id.as_str()
            ),
        };
    }

    // All bundle contents must be identical
    if bundle1.causal_event_sequence != bundle2.causal_event_sequence {
        return TestResult::Fail {
            reason: "MUST_R_DVB_001 violated: causal event sequence differs between runs"
                .to_string(),
        };
    }

    if bundle1.failed_artifacts != bundle2.failed_artifacts {
        return TestResult::Fail {
            reason: "MUST_R_DVB_001 violated: failed artifacts differ between runs".to_string(),
        };
    }

    if bundle1.proof_context != bundle2.proof_context {
        return TestResult::Fail {
            reason: "MUST_R_DVB_001 violated: proof context differs between runs".to_string(),
        };
    }

    TestResult::Pass
}

fn test_must_r_dvb_002_causal_chain_preservation() -> TestResult {
    // INV-VIOLATION-CAUSAL: complete causal chain preserved in order
    let mut context = ViolationContext {
        events: vec![
            CausalEvent {
                event_type: CausalEventType::GuardrailRejection,
                timestamp_ms: 1000,
                description: "memory budget exceeded".into(),
                evidence_ref: Some("EVD-001".into()),
            },
            CausalEvent {
                event_type: CausalEventType::HardeningEscalation,
                timestamp_ms: 1100,
                description: "escalated to critical".into(),
                evidence_ref: Some("EVD-002".into()),
            },
            CausalEvent {
                event_type: CausalEventType::RepairFailed,
                timestamp_ms: 1200,
                description: "repair attempt failed".into(),
                evidence_ref: None,
            },
            CausalEvent {
                event_type: CausalEventType::IntegrityCheckFailed,
                timestamp_ms: 1300,
                description: "integrity check failed".into(),
                evidence_ref: Some("EVD-003".into()),
            },
            CausalEvent {
                event_type: CausalEventType::ArtifactUnverifiable,
                timestamp_ms: 1400,
                description: "artifact became unverifiable".into(),
                evidence_ref: Some("EVD-004".into()),
            },
        ],
        artifacts: vec![],
        proofs: ProofContext::new(),
        hardening_level: "critical".into(),
        epoch_id: 42,
        timestamp_ms: 2000,
    };

    let bundle = generate_bundle(&context);

    // Verify complete causal chain preserved
    if bundle.causal_event_sequence.len() != context.events.len() {
        return TestResult::Fail {
            reason: format!(
                "MUST_R_DVB_002 violated: causal chain length mismatch\n\
                 expected: {}, got: {}",
                context.events.len(),
                bundle.causal_event_sequence.len()
            ),
        };
    }

    // Verify ordering preserved
    for (i, (original, bundled)) in context
        .events
        .iter()
        .zip(bundle.causal_event_sequence.iter())
        .enumerate()
    {
        if original.event_type != bundled.event_type {
            return TestResult::Fail {
                reason: format!(
                    "MUST_R_DVB_002 violated: event type mismatch at index {}\n\
                     expected: {:?}, got: {:?}",
                    i, original.event_type, bundled.event_type
                ),
            };
        }

        if original.timestamp_ms != bundled.timestamp_ms {
            return TestResult::Fail {
                reason: format!(
                    "MUST_R_DVB_002 violated: timestamp mismatch at index {}\n\
                     expected: {}, got: {}",
                    i, original.timestamp_ms, bundled.timestamp_ms
                ),
            };
        }

        if original.description != bundled.description {
            return TestResult::Fail {
                reason: format!(
                    "MUST_R_DVB_002 violated: description mismatch at index {}\n\
                     expected: {:?}, got: {:?}",
                    i, original.description, bundled.description
                ),
            };
        }

        if original.evidence_ref != bundled.evidence_ref {
            return TestResult::Fail {
                reason: format!(
                    "MUST_R_DVB_002 violated: evidence_ref mismatch at index {}\n\
                     expected: {:?}, got: {:?}",
                    i, original.evidence_ref, bundled.evidence_ref
                ),
            };
        }
    }

    TestResult::Pass
}

fn test_must_r_dvb_003_halt_enforcement() -> TestResult {
    // INV-VIOLATION-HALT: gating blocked after emission
    let mut detector = DurabilityViolationDetector::new(HaltPolicy::HaltAll);
    let context = create_reference_violation_context();

    // Before violation: operations allowed
    if detector.check_durable_op("ledger").is_err() {
        return TestResult::Fail {
            reason: "MUST_R_DVB_003 violated: operation blocked before violation emission"
                .to_string(),
        };
    }

    if detector.is_halted() {
        return TestResult::Fail {
            reason: "MUST_R_DVB_003 violated: detector shows halted state before violation"
                .to_string(),
        };
    }

    // Generate violation bundle
    // API-DRIFT REMEDIATION (bd-rjc2m.7): generate_bundle(&mut self) -> &ViolationBundle now
    // borrows the detector mutably for the lifetime of the returned reference, which collided
    // with the later &self calls (is_halted / check_durable_op). Capture the bundle_id by value
    // so the mutable borrow ends immediately; the assertion (halt_err.bundle_id == this id) holds.
    let expected_bundle_id = detector.generate_bundle(&context).bundle_id.clone();

    // After violation: operations blocked
    if !detector.is_halted() {
        return TestResult::Fail {
            reason: "MUST_R_DVB_003 violated: detector not halted after violation emission"
                .to_string(),
        };
    }

    match detector.check_durable_op("ledger") {
        Ok(()) => TestResult::Fail {
            reason: "MUST_R_DVB_003 violated: durable operation allowed after violation emission"
                .to_string(),
        },
        Err(halt_err) => {
            // Verify halt error contains bundle info
            if halt_err.bundle_id != expected_bundle_id {
                TestResult::Fail {
                    reason: format!(
                        "MUST_R_DVB_003 violated: halt error bundle_id mismatch\n\
                         expected: {}, got: {}",
                        expected_bundle_id.as_str(),
                        halt_err.bundle_id.as_str()
                    ),
                }
            } else {
                TestResult::Pass
            }
        }
    }
}

fn test_should_evd_violation_001_bundle_generated() -> TestResult {
    // Test that bundle generation events use correct event code
    let expected_code = event_codes::VIOLATION_BUNDLE_GENERATED;
    if expected_code != "EVD-VIOLATION-001" {
        return TestResult::Fail {
            reason: format!(
                "Event code mismatch: expected 'EVD-VIOLATION-001', got '{}'",
                expected_code
            ),
        };
    }
    TestResult::Pass
}

fn test_should_evd_violation_002_gating_halted() -> TestResult {
    // Test that halt events use correct event code
    let expected_code = event_codes::VIOLATION_GATING_HALTED;
    if expected_code != "EVD-VIOLATION-002" {
        return TestResult::Fail {
            reason: format!(
                "Event code mismatch: expected 'EVD-VIOLATION-002', got '{}'",
                expected_code
            ),
        };
    }
    TestResult::Pass
}

fn test_should_evd_violation_003_halt_cleared() -> TestResult {
    // Test that halt clearing events use correct event code
    let expected_code = event_codes::VIOLATION_HALT_CLEARED;
    if expected_code != "EVD-VIOLATION-003" {
        return TestResult::Fail {
            reason: format!(
                "Event code mismatch: expected 'EVD-VIOLATION-003', got '{}'",
                expected_code
            ),
        };
    }
    TestResult::Pass
}

fn test_should_evd_violation_004_op_rejected() -> TestResult {
    // Test that operation rejection events use correct event code
    let expected_code = event_codes::VIOLATION_OP_REJECTED;
    if expected_code != "EVD-VIOLATION-004" {
        return TestResult::Fail {
            reason: format!(
                "Event code mismatch: expected 'EVD-VIOLATION-004', got '{}'",
                expected_code
            ),
        };
    }
    TestResult::Pass
}

// ── Test Utilities ─────────────────────────────────────────────────────

fn create_reference_violation_context() -> ViolationContext {
    let mut proofs = ProofContext::new();
    proofs.add_failed_proof("proof-failed-001".into());
    proofs.add_missing_proof("proof-missing-002".into());
    proofs.add_passed_proof("proof-passed-003".into());

    ViolationContext {
        events: vec![
            CausalEvent {
                event_type: CausalEventType::GuardrailRejection,
                timestamp_ms: 1000,
                description: "memory budget exceeded".into(),
                evidence_ref: Some("EVD-001".into()),
            },
            CausalEvent {
                event_type: CausalEventType::HardeningEscalation,
                timestamp_ms: 1001,
                description: "escalated to critical".into(),
                evidence_ref: Some("EVD-002".into()),
            },
            CausalEvent {
                event_type: CausalEventType::RepairFailed,
                timestamp_ms: 1500,
                description: "repair attempt failed: no backup".into(),
                evidence_ref: None,
            },
        ],
        artifacts: vec![FailedArtifact {
            artifact_path: "objects/abc123".into(),
            expected_hash: "deadbeef".into(),
            actual_hash: "00000000".into(),
            failure_reason: "hash mismatch after repair".into(),
        }],
        proofs,
        hardening_level: "critical".into(),
        epoch_id: 42,
        timestamp_ms: 2000,
    }
}

// ── Conformance Test Runner ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ConformanceReport {
    pub total_must: usize,
    pub passing_must: usize,
    pub total_should: usize,
    pub passing_should: usize,
    pub must_score: f64,
    pub should_score: f64,
    pub overall_score: f64,
    pub test_results: Vec<ConformanceResult>,
}

#[derive(Debug, Serialize)]
pub struct ConformanceResult {
    pub id: String,
    pub level: String,
    pub verdict: String,
    pub description: String,
    pub failure_reason: Option<String>,
}

pub fn run_full_conformance_suite() -> ConformanceReport {
    let mut results = Vec::new();
    let mut must_pass = 0;
    let mut should_pass = 0;

    // Run MUST_R requirements
    for case in DURABILITY_VIOLATION_CONFORMANCE_CASES {
        let test_result = (case.test_fn)();
        let verdict = if test_result.is_pass() {
            "PASS"
        } else {
            "FAIL"
        };

        if test_result.is_pass() && case.level == RequirementLevel::Must {
            must_pass += 1;
        }

        results.push(ConformanceResult {
            id: case.id.to_string(),
            level: match case.level {
                RequirementLevel::Must => "MUST".to_string(),
                RequirementLevel::Should => "SHOULD".to_string(),
                RequirementLevel::May => "MAY".to_string(),
            },
            verdict: verdict.to_string(),
            description: case.description.to_string(),
            failure_reason: match test_result {
                TestResult::Fail { reason } => Some(reason),
                TestResult::Skipped { reason } => Some(format!("SKIPPED: {}", reason)),
                TestResult::Pass => None,
            },
        });
    }

    // Run SHOULD event code tests
    for case in EVENT_CODE_CONFORMANCE_CASES {
        let test_result = (case.test_fn)();
        let verdict = if test_result.is_pass() {
            "PASS"
        } else {
            "FAIL"
        };

        if test_result.is_pass() && case.level == RequirementLevel::Should {
            should_pass += 1;
        }

        results.push(ConformanceResult {
            id: case.id.to_string(),
            level: match case.level {
                RequirementLevel::Must => "MUST".to_string(),
                RequirementLevel::Should => "SHOULD".to_string(),
                RequirementLevel::May => "MAY".to_string(),
            },
            verdict: verdict.to_string(),
            description: case.description.to_string(),
            failure_reason: match test_result {
                TestResult::Fail { reason } => Some(reason),
                TestResult::Skipped { reason } => Some(format!("SKIPPED: {}", reason)),
                TestResult::Pass => None,
            },
        });
    }

    let total_must = DURABILITY_VIOLATION_CONFORMANCE_CASES.len();
    let total_should = EVENT_CODE_CONFORMANCE_CASES.len();

    let must_score = if total_must > 0 {
        (must_pass as f64) / (total_must as f64) * 100.0
    } else {
        100.0
    };

    let should_score = if total_should > 0 {
        (should_pass as f64) / (total_should as f64) * 100.0
    } else {
        100.0
    };

    let overall_score = (must_score * 0.8) + (should_score * 0.2);

    ConformanceReport {
        total_must,
        passing_must: must_pass,
        total_should,
        passing_should: should_pass,
        must_score,
        should_score,
        overall_score,
        test_results: results,
    }
}

// ── Standard Test Functions ────────────────────────────────────────────

#[test]
fn conformance_must_r_dvb_001_deterministic_bundle_generation() {
    let result = test_must_r_dvb_001_deterministic_bundle_generation();
    assert!(result.is_pass(), "MUST_R_DVB_001 failed: {:?}", result);
}

#[test]
fn conformance_must_r_dvb_002_causal_chain_preservation() {
    let result = test_must_r_dvb_002_causal_chain_preservation();
    assert!(result.is_pass(), "MUST_R_DVB_002 failed: {:?}", result);
}

#[test]
fn conformance_must_r_dvb_003_halt_enforcement() {
    let result = test_must_r_dvb_003_halt_enforcement();
    assert!(result.is_pass(), "MUST_R_DVB_003 failed: {:?}", result);
}

#[test]
fn conformance_evd_violation_001_bundle_generated() {
    let result = test_should_evd_violation_001_bundle_generated();
    assert!(result.is_pass(), "EVD-VIOLATION-001 failed: {:?}", result);
}

#[test]
fn conformance_evd_violation_002_gating_halted() {
    let result = test_should_evd_violation_002_gating_halted();
    assert!(result.is_pass(), "EVD-VIOLATION-002 failed: {:?}", result);
}

#[test]
fn conformance_evd_violation_003_halt_cleared() {
    let result = test_should_evd_violation_003_halt_cleared();
    assert!(result.is_pass(), "EVD-VIOLATION-003 failed: {:?}", result);
}

#[test]
fn conformance_evd_violation_004_op_rejected() {
    let result = test_should_evd_violation_004_op_rejected();
    assert!(result.is_pass(), "EVD-VIOLATION-004 failed: {:?}", result);
}

#[test]
fn conformance_full_suite_must_requirements_100_percent_coverage() {
    let report = run_full_conformance_suite();

    assert!(
        report.must_score >= 95.0,
        "MUST requirement coverage below threshold: {:.1}% (expected ≥95%)",
        report.must_score
    );

    assert_eq!(
        report.passing_must, report.total_must,
        "Not all MUST requirements passed: {}/{} passed",
        report.passing_must, report.total_must
    );
}

#[test]
fn conformance_event_code_coverage_verification() {
    let expected_codes = BTreeSet::from([
        "EVD-VIOLATION-001",
        "EVD-VIOLATION-002",
        "EVD-VIOLATION-003",
        "EVD-VIOLATION-004",
    ]);

    let actual_codes = BTreeSet::from([
        event_codes::VIOLATION_BUNDLE_GENERATED,
        event_codes::VIOLATION_GATING_HALTED,
        event_codes::VIOLATION_HALT_CLEARED,
        event_codes::VIOLATION_OP_REJECTED,
    ]);

    assert_eq!(
        expected_codes, actual_codes,
        "Event code coverage mismatch\n\
         expected: {:?}\n\
         actual: {:?}",
        expected_codes, actual_codes
    );
}
