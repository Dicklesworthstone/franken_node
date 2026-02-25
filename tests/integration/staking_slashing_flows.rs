//! Integration tests for bd-26mk staking and slashing governance.
//!
//! Verifies that the staking ledger report artifact is well-formed
//! and that the check script report conforms to schema expectations.

use serde::Deserialize;
use std::path::{Path, PathBuf};

const EXPECTED_EVENT_CODES: [&str; 5] = [
    "STAKE_DEPOSIT_RECEIVED",
    "STAKE_GATE_EVALUATED",
    "SLASH_INITIATED",
    "SLASH_EXECUTED",
    "APPEAL_FILED",
];

const EXPECTED_ERROR_CODES: [&str; 6] = [
    "ERR_STAKE_INSUFFICIENT",
    "ERR_STAKE_GATE_DENIED",
    "ERR_SLASH_EVIDENCE_INVALID",
    "ERR_SLASH_ALREADY_EXECUTED",
    "ERR_APPEAL_EXPIRED",
    "ERR_STAKE_WITHDRAWAL_LOCKED",
];

const EXPECTED_INVARIANTS: [&str; 4] = [
    "INV-STAKE-GATE-REQUIRED",
    "INV-SLASH-DETERMINISTIC",
    "INV-SLASH-AUDIT-TRAIL",
    "INV-APPEAL-WINDOW",
];

#[derive(Debug, Deserialize)]
struct CheckResult {
    check: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct StakingReport {
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
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn load_report() -> StakingReport {
    let path = repo_root().join("artifacts/10.17/staking_ledger_snapshot.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str::<StakingReport>(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

#[test]
fn report_identity_fields_are_correct() {
    let report = load_report();
    assert_eq!(report.bead_id, "bd-26mk");
    assert_eq!(report.section, "10.17");
    assert!(
        report.schema_version.starts_with("staking-governance"),
        "unexpected schema_version: {}",
        report.schema_version
    );
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
fn checks_are_nonempty_and_well_formed() {
    let report = load_report();
    assert!(!report.checks.is_empty());
    for c in &report.checks {
        assert!(!c.check.trim().is_empty());
        assert!(!c.detail.trim().is_empty());
    }
}

#[test]
fn impl_file_exists() {
    let path = repo_root().join("crates/franken-node/src/registry/staking_governance.rs");
    assert!(path.exists(), "impl file missing: {}", path.display());
}

#[test]
fn spec_file_exists() {
    let path = repo_root().join("docs/policy/security_staking_and_slashing.md");
    assert!(path.exists(), "spec file missing: {}", path.display());
}
