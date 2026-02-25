//! Conformance checks for `bd-3ku8` capability artifact admission report.

use serde::Deserialize;
use std::path::{Path, PathBuf};

const EXPECTED_EVENTS: [&str; 5] = [
    "ARTIFACT_ADMISSION_START",
    "ARTIFACT_CAPABILITY_VALIDATED",
    "ARTIFACT_ADMISSION_ACCEPTED",
    "ARTIFACT_ENFORCEMENT_CHECK",
    "ARTIFACT_DRIFT_DETECTED",
];

const EXPECTED_ERRORS: [&str; 6] = [
    "ERR_ARTIFACT_MISSING_CONTRACT",
    "ERR_ARTIFACT_INVALID_CAPABILITY",
    "ERR_ARTIFACT_SIGNATURE_INVALID",
    "ERR_ARTIFACT_SCHEMA_MISMATCH",
    "ERR_ARTIFACT_ENFORCEMENT_DRIFT",
    "ERR_ARTIFACT_ADMISSION_DENIED",
];

#[derive(Debug, Deserialize)]
struct CheckResult {
    check: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct ArtifactContract {
    fail_closed_on_missing: bool,
    fail_closed_on_invalid: bool,
    enforcement_matches_envelope: bool,
    no_drift_permitted: bool,
}

#[derive(Debug, Deserialize)]
struct CapabilityArtifactReport {
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
    artifact_contract: ArtifactContract,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn load_report() -> CapabilityArtifactReport {
    let path = repo_root().join("artifacts/10.17/capability_artifact_vectors.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str::<CapabilityArtifactReport>(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

#[test]
fn report_identity_fields_are_correct() {
    let report = load_report();
    assert_eq!(report.schema_version, "capability-artifact-v1.0");
    assert_eq!(report.bead_id, "bd-3ku8");
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
fn artifact_contract_flags_are_all_true() {
    let report = load_report();
    assert!(report.artifact_contract.fail_closed_on_missing);
    assert!(report.artifact_contract.fail_closed_on_invalid);
    assert!(report.artifact_contract.enforcement_matches_envelope);
    assert!(report.artifact_contract.no_drift_permitted);
}

#[test]
fn invariants_include_fail_closed_and_no_drift() {
    let report = load_report();
    assert!(report.invariants.iter().any(|i| i == "INV-ARTIFACT-FAIL-CLOSED"));
    assert!(report.invariants.iter().any(|i| i == "INV-ARTIFACT-NO-DRIFT"));
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
