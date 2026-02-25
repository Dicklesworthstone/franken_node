//! Conformance checks for `bd-nbwo` universal verifier SDK capsule replay.
//!
//! These tests verify the verifier SDK certification report and the
//! universal_verifier_sdk module against the replay capsule format
//! specification.

use serde::Deserialize;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Expected codes from bd-nbwo spec
// ---------------------------------------------------------------------------

const EXPECTED_EVENT_CODES: [&str; 5] = [
    "CAPSULE_CREATED",
    "CAPSULE_SIGNED",
    "CAPSULE_REPLAY_START",
    "CAPSULE_VERDICT_REPRODUCED",
    "SDK_VERSION_CHECK",
];

const EXPECTED_ERROR_CODES: [&str; 6] = [
    "ERR_CAPSULE_SIGNATURE_INVALID",
    "ERR_CAPSULE_SCHEMA_MISMATCH",
    "ERR_CAPSULE_REPLAY_DIVERGED",
    "ERR_CAPSULE_VERDICT_MISMATCH",
    "ERR_SDK_VERSION_UNSUPPORTED",
    "ERR_CAPSULE_ACCESS_DENIED",
];

const EXPECTED_INVARIANTS: [&str; 4] = [
    "INV-CAPSULE-STABLE-SCHEMA",
    "INV-CAPSULE-VERSIONED-API",
    "INV-CAPSULE-NO-PRIVILEGED-ACCESS",
    "INV-CAPSULE-VERDICT-REPRODUCIBLE",
];

// ---------------------------------------------------------------------------
// Report structures
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CheckResult {
    check: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct CapsuleContract {
    capsule_replay_deterministic: bool,
    no_privileged_access: bool,
    schema_versioned: bool,
    signature_bound: bool,
}

#[derive(Debug, Deserialize)]
struct CertificationReport {
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
    capsule_contract: CapsuleContract,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn load_report() -> CertificationReport {
    let path = repo_root().join("artifacts/10.17/verifier_sdk_certification_report.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str::<CertificationReport>(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn report_identity_fields_are_correct() {
    let report = load_report();
    assert_eq!(report.schema_version, "verifier-sdk-capsule-v1.0");
    assert_eq!(report.bead_id, "bd-nbwo");
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
    assert_eq!(
        report.verdict,
        if failed == 0 { "PASS" } else { "FAIL" }
    );
}

#[test]
fn report_contains_expected_event_codes() {
    let report = load_report();
    for code in EXPECTED_EVENT_CODES {
        assert!(
            report.event_codes.contains(&code.to_string()),
            "missing event code: {code}"
        );
    }
}

#[test]
fn report_contains_expected_error_codes() {
    let report = load_report();
    for code in EXPECTED_ERROR_CODES {
        assert!(
            report.error_codes.contains(&code.to_string()),
            "missing error code: {code}"
        );
    }
}

#[test]
fn report_contains_expected_invariants() {
    let report = load_report();
    for inv in EXPECTED_INVARIANTS {
        assert!(
            report.invariants.contains(&inv.to_string()),
            "missing invariant: {inv}"
        );
    }
}

#[test]
fn capsule_contract_flags_are_all_true() {
    let report = load_report();
    assert!(report.capsule_contract.capsule_replay_deterministic);
    assert!(report.capsule_contract.no_privileged_access);
    assert!(report.capsule_contract.schema_versioned);
    assert!(report.capsule_contract.signature_bound);
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

#[test]
fn report_has_minimum_check_count() {
    let report = load_report();
    assert!(
        report.total >= 25,
        "expected >= 25 checks, found {}",
        report.total
    );
}
