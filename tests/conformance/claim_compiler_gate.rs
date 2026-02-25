//! Conformance checks for `bd-2kd9` claim compiler and public trust scoreboard report.

use serde::Deserialize;
use std::path::{Path, PathBuf};

const EXPECTED_EVENTS: [&str; 5] = [
    "CLAIM_COMPILATION_START",
    "CLAIM_CONTRACT_GENERATED",
    "CLAIM_VERIFICATION_LINKED",
    "SCOREBOARD_UPDATE_PUBLISHED",
    "SCOREBOARD_EVIDENCE_SIGNED",
];

const EXPECTED_ERRORS: [&str; 6] = [
    "ERR_CLAIM_UNVERIFIABLE",
    "ERR_CLAIM_SYNTAX_INVALID",
    "ERR_CLAIM_EVIDENCE_MISSING",
    "ERR_CLAIM_BLOCKED",
    "ERR_SCOREBOARD_SIGNATURE_INVALID",
    "ERR_SCOREBOARD_STALE_EVIDENCE",
];

const EXPECTED_INVARIANTS: [&str; 4] = [
    "INV-CLAIM-EXECUTABLE-CONTRACT",
    "INV-CLAIM-BLOCK-UNVERIFIABLE",
    "INV-SCOREBOARD-SIGNED-EVIDENCE",
    "INV-SCOREBOARD-FRESH-LINKS",
];

#[derive(Debug, Deserialize)]
struct CheckResult {
    check: String,
    passed: bool,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct ClaimCompilerContract {
    fail_closed_on_unverifiable_claims: bool,
    scoreboard_updates_publish_signed_evidence_links: bool,
    deterministic_btreemap_ordering: bool,
    schema_versioned_outputs: bool,
    atomic_scoreboard_updates: bool,
    sha256_digest_binding: bool,
}

#[derive(Debug, Deserialize)]
struct ClaimCompilerReport {
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
    claim_compiler_contract: ClaimCompilerContract,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn load_report() -> ClaimCompilerReport {
    let path = repo_root().join("artifacts/10.17/public_trust_scoreboard_snapshot.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str::<ClaimCompilerReport>(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

#[test]
fn report_identity_fields_are_correct() {
    let report = load_report();
    assert_eq!(report.schema_version, "claim-compiler-v1.0");
    assert_eq!(report.bead_id, "bd-2kd9");
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
fn report_contains_expected_invariants() {
    let report = load_report();
    for inv in EXPECTED_INVARIANTS {
        assert!(report.invariants.contains(&inv.to_string()), "missing invariant: {inv}");
    }
}

#[test]
fn claim_compiler_contract_flags_are_all_true() {
    let report = load_report();
    assert!(report.claim_compiler_contract.fail_closed_on_unverifiable_claims);
    assert!(report.claim_compiler_contract.scoreboard_updates_publish_signed_evidence_links);
    assert!(report.claim_compiler_contract.deterministic_btreemap_ordering);
    assert!(report.claim_compiler_contract.schema_versioned_outputs);
    assert!(report.claim_compiler_contract.atomic_scoreboard_updates);
    assert!(report.claim_compiler_contract.sha256_digest_binding);
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
