//! Integration / conformance tests for bd-al8i N-version semantic oracle.
//!
//! These tests exercise the report artifact and the harness logic from
//! an integration perspective, complementing the inline unit tests in
//! `connector::n_version_oracle`.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ── Report schema for deserialization ──────────────────────────────────

#[derive(Debug, Deserialize)]
struct OracleCheckResult {
    check: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct OracleDivergenceContract {
    high_risk_blocks_release: bool,
    low_risk_requires_receipt: bool,
    receipts_link_l1_oracle: bool,
    classification_is_deterministic: bool,
}

#[derive(Debug, Deserialize)]
struct OracleReport {
    schema_version: String,
    bead_id: String,
    section: String,
    verdict: String,
    total: usize,
    passed: usize,
    failed: usize,
    checks: Vec<OracleCheckResult>,
    event_codes: Vec<String>,
    error_codes: Vec<String>,
    invariants: Vec<String>,
    divergence_contract: OracleDivergenceContract,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn load_report() -> OracleReport {
    let path = repo_root().join("artifacts/10.17/semantic_oracle_divergence_matrix.csv.report.json");
    // Fall back to the main report location
    let path = if path.exists() {
        path
    } else {
        repo_root().join("artifacts/10.17/semantic_oracle_report.json")
    };
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str::<OracleReport>(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

// ── Tests ──────────────────────────────────────────────────────────────

#[test]
fn report_identity_fields_are_correct() {
    let report = load_report();
    assert_eq!(report.schema_version, "n-version-oracle-v1.0");
    assert_eq!(report.bead_id, "bd-al8i");
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
    let expected = [
        "ORACLE_HARNESS_START",
        "ORACLE_DIVERGENCE_CLASSIFIED",
        "ORACLE_RISK_TIER_ASSIGNED",
        "ORACLE_RELEASE_BLOCKED",
        "ORACLE_POLICY_RECEIPT_ISSUED",
    ];
    for code in expected {
        assert!(
            report.event_codes.contains(&code.to_string()),
            "missing event code: {code}"
        );
    }
}

#[test]
fn report_contains_expected_error_codes() {
    let report = load_report();
    let expected = [
        "ERR_ORACLE_HIGH_RISK_DELTA",
        "ERR_ORACLE_MISSING_RECEIPT",
        "ERR_ORACLE_HARNESS_TIMEOUT",
        "ERR_ORACLE_REFERENCE_UNAVAILABLE",
        "ERR_ORACLE_CLASSIFICATION_AMBIGUOUS",
        "ERR_ORACLE_L1_LINK_BROKEN",
    ];
    for code in expected {
        assert!(
            report.error_codes.contains(&code.to_string()),
            "missing error code: {code}"
        );
    }
}

#[test]
fn divergence_contract_flags_are_all_true() {
    let report = load_report();
    assert!(report.divergence_contract.high_risk_blocks_release);
    assert!(report.divergence_contract.low_risk_requires_receipt);
    assert!(report.divergence_contract.receipts_link_l1_oracle);
    assert!(report.divergence_contract.classification_is_deterministic);
}

#[test]
fn invariants_include_core_set() {
    let report = load_report();
    assert!(report.invariants.iter().any(|i| i == "INV-ORACLE-HIGH-RISK-BLOCKS"));
    assert!(report.invariants.iter().any(|i| i == "INV-ORACLE-LOW-RISK-RECEIPTED"));
    assert!(report
        .invariants
        .iter()
        .any(|i| i == "INV-ORACLE-DETERMINISTIC-CLASSIFICATION"));
    assert!(report.invariants.iter().any(|i| i == "INV-ORACLE-L1-LINKAGE"));
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
