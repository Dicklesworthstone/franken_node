//! Conformance checks for `bd-3l2p` intent firewall evaluation report.

use serde::Deserialize;
use std::path::{Path, PathBuf};

const EXPECTED_EVENTS: [&str; 5] = [
    "FIREWALL_REQUEST_CLASSIFIED",
    "FIREWALL_INTENT_BENIGN",
    "FIREWALL_INTENT_RISKY",
    "FIREWALL_CHALLENGE_ISSUED",
    "FIREWALL_VERDICT_RENDERED",
];

const EXPECTED_ERRORS: [&str; 6] = [
    "ERR_FIREWALL_CLASSIFICATION_FAILED",
    "ERR_FIREWALL_CHALLENGE_TIMEOUT",
    "ERR_FIREWALL_SIMULATE_FAILED",
    "ERR_FIREWALL_QUARANTINE_FULL",
    "ERR_FIREWALL_RECEIPT_UNSIGNED",
    "ERR_FIREWALL_POLICY_MISSING",
];

const EXPECTED_INVARIANTS: [&str; 4] = [
    "INV-FIREWALL-STABLE-CLASSIFICATION",
    "INV-FIREWALL-DETERMINISTIC-RECEIPT",
    "INV-FIREWALL-FAIL-DENY",
    "INV-FIREWALL-RISKY-PATHWAY",
];

#[derive(Debug, Deserialize)]
struct CheckResult {
    check: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct FirewallContract {
    fail_closed_unclassifiable: bool,
    risky_default_deny: bool,
    receipt_every_decision: bool,
    extension_scoped: bool,
}

#[derive(Debug, Deserialize)]
struct FirewallReport {
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
    firewall_contract: FirewallContract,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn load_report() -> FirewallReport {
    let path = repo_root().join("artifacts/10.17/intent_firewall_eval_report.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str::<FirewallReport>(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

#[test]
fn report_identity_fields_are_correct() {
    let report = load_report();
    assert_eq!(report.schema_version, "intent-firewall-v1.0");
    assert_eq!(report.bead_id, "bd-3l2p");
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
        assert!(
            report.event_codes.contains(&code.to_string()),
            "missing event code: {code}"
        );
    }
    for code in EXPECTED_ERRORS {
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
fn firewall_contract_flags_are_all_true() {
    let report = load_report();
    assert!(report.firewall_contract.fail_closed_unclassifiable);
    assert!(report.firewall_contract.risky_default_deny);
    assert!(report.firewall_contract.receipt_every_decision);
    assert!(report.firewall_contract.extension_scoped);
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
