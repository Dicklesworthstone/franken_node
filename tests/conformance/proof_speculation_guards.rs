//! Conformance checks for `bd-1nl1` proof-carrying speculation report.

use serde::Deserialize;
use std::path::{Path, PathBuf};

const EXPECTED_EVENTS: [&str; 5] = [
    "SPECULATION_GUARD_START",
    "SPECULATION_PROOF_ACCEPTED",
    "SPECULATION_ACTIVATED",
    "SPECULATION_DEGRADED",
    "SPECULATION_SAFE_BASELINE_USED",
];

const EXPECTED_ERRORS: [&str; 6] = [
    "ERR_SPEC_MISSING_PROOF",
    "ERR_SPEC_EXPIRED_PROOF",
    "ERR_SPEC_SIGNATURE_INVALID",
    "ERR_SPEC_INTERFACE_UNAPPROVED",
    "ERR_SPEC_GUARD_REJECTED",
    "ERR_SPEC_TRANSFORM_MISMATCH",
];

#[derive(Debug, Deserialize)]
struct CheckResult {
    check: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct GuardContract {
    requires_receipt: bool,
    requires_approved_interface: bool,
    guard_failure_degrades_to_baseline: bool,
    activation_only_via_approved_franken_engine_interfaces: bool,
}

#[derive(Debug, Deserialize)]
struct SpeculationReport {
    schema_version: String,
    bead_id: String,
    section: String,
    verdict: String,
    total: usize,
    passed: usize,
    failed: usize,
    checks: Vec<CheckResult>,
    event_codes: Vec<String>,
    error_codes: Vec<String>,
    invariants: Vec<String>,
    guard_contract: GuardContract,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn load_report() -> SpeculationReport {
    let path = repo_root().join("artifacts/10.17/speculation_proof_report.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str::<SpeculationReport>(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

#[test]
fn report_identity_fields_are_correct() {
    let report = load_report();
    assert_eq!(report.schema_version, "speculation-proof-v1.0");
    assert_eq!(report.bead_id, "bd-1nl1");
    assert_eq!(report.section, "10.17");
}

#[test]
fn report_summary_counts_are_consistent() {
    let report = load_report();
    let passed = report.checks.iter().filter(|c| c.passed).count();
    let failed = report.checks.iter().filter(|c| !c.passed).count();

    assert_eq!(report.total, report.checks.len());
    assert_eq!(report.passed, passed);
    assert_eq!(report.failed, failed);
    assert_eq!(report.verdict, if failed == 0 { "PASS" } else { "FAIL" });
}

#[test]
fn report_contains_expected_event_and_error_codes() {
    let report = load_report();
    for code in EXPECTED_EVENTS {
        assert!(report.event_codes.contains(&code.to_string()), "missing event code: {code}");
    }
    for code in EXPECTED_ERRORS {
        assert!(report.error_codes.contains(&code.to_string()), "missing error code: {code}");
    }
}

#[test]
fn guard_contract_flags_are_all_true() {
    let report = load_report();
    assert!(report.guard_contract.requires_receipt);
    assert!(report.guard_contract.requires_approved_interface);
    assert!(report.guard_contract.guard_failure_degrades_to_baseline);
    assert!(report.guard_contract.activation_only_via_approved_franken_engine_interfaces);
}

#[test]
fn invariants_include_fail_closed_and_determinism() {
    let report = load_report();
    assert!(report.invariants.iter().any(|i| i == "INV-SPEC-FAIL-CLOSED-TO-BASELINE"));
    assert!(report.invariants.iter().any(|i| i == "INV-SPEC-DETERMINISTIC-BASELINE"));
}

#[test]
fn checks_are_nonempty_and_well_formed() {
    let report = load_report();
    assert!(!report.checks.is_empty());
    for c in &report.checks {
        assert!(!c.check.trim().is_empty());
        assert!(!c.detail.trim().is_empty());
    }
}
