//! Conformance checks for the adjacent substrate CI gate report (bd-3u2o).

use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const EXPECTED_EVENT_CODES: [&str; 6] = [
    "SUBSTRATE_GATE_START",
    "SUBSTRATE_GATE_VIOLATION",
    "SUBSTRATE_GATE_WAIVED",
    "SUBSTRATE_GATE_WAIVER_EXPIRED",
    "SUBSTRATE_GATE_PASS",
    "SUBSTRATE_GATE_FAIL",
];

#[derive(Debug, Deserialize)]
struct GateCheck {
    module: String,
    substrate: String,
    rule: String,
    status: String,
    remediation_hint: String,
    waiver_id: String,
}

#[derive(Debug, Deserialize)]
struct GateSummary {
    total_checks: usize,
    passed: usize,
    failed: usize,
    waived: usize,
}

#[derive(Debug, Deserialize)]
struct GateEvent {
    code: String,
}

#[derive(Debug, Deserialize)]
struct GateReport {
    schema_version: String,
    bead_id: String,
    section: String,
    checks: Vec<GateCheck>,
    summary: GateSummary,
    gate_verdict: String,
    events: Vec<GateEvent>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn load_gate_report() -> GateReport {
    let root = repo_root();
    let report_path = root.join("artifacts/10.16/adjacent_substrate_gate_report.json");
    let raw = std::fs::read_to_string(&report_path)
        .unwrap_or_else(|e| panic!("failed to read report {}: {e}", report_path.display()));
    serde_json::from_str::<GateReport>(&raw)
        .unwrap_or_else(|e| panic!("failed to parse report {}: {e}", report_path.display()))
}

#[test]
fn report_identity_and_schema_fields_are_present() {
    let report = load_gate_report();
    assert_eq!(report.schema_version, "1.0.0");
    assert_eq!(report.bead_id, "bd-3u2o");
    assert_eq!(report.section, "10.16");
}

#[test]
fn summary_counts_match_check_statuses() {
    let report = load_gate_report();
    let passed = report.checks.iter().filter(|c| c.status == "pass").count();
    let failed = report.checks.iter().filter(|c| c.status == "fail").count();
    let waived = report.checks.iter().filter(|c| c.status == "waived").count();

    assert_eq!(report.summary.total_checks, report.checks.len());
    assert_eq!(report.summary.passed, passed);
    assert_eq!(report.summary.failed, failed);
    assert_eq!(report.summary.waived, waived);
}

#[test]
fn failure_and_waiver_records_have_required_fields() {
    let report = load_gate_report();
    for check in &report.checks {
        assert!(!check.module.trim().is_empty(), "module field is required");
        assert!(!check.substrate.trim().is_empty(), "substrate field is required");
        assert!(!check.rule.trim().is_empty(), "rule field is required");
        assert!(
            matches!(check.status.as_str(), "pass" | "fail" | "waived"),
            "invalid check status: {}",
            check.status
        );

        if check.status == "fail" {
            assert!(
                !check.remediation_hint.trim().is_empty(),
                "failure entries must include remediation hints"
            );
        }
        if check.status == "waived" {
            assert!(
                !check.waiver_id.trim().is_empty(),
                "waived entries must include waiver_id"
            );
        }
    }
}

#[test]
fn gate_verdict_matches_failed_count() {
    let report = load_gate_report();
    let expected = if report.summary.failed == 0 {
        "pass"
    } else {
        "fail"
    };
    assert_eq!(
        report.gate_verdict, expected,
        "gate_verdict must track failed count"
    );
}

#[test]
fn event_codes_are_known() {
    let report = load_gate_report();
    let known: BTreeSet<&str> = EXPECTED_EVENT_CODES.into_iter().collect();
    for event in &report.events {
        assert!(
            known.contains(event.code.as_str()),
            "unexpected event code in gate report: {}",
            event.code
        );
    }
}

#[test]
fn waiver_expiry_rfc3339_examples_parse() {
    let expiry = DateTime::parse_from_rfc3339("2026-03-01T00:00:00Z").expect("valid RFC3339");
    let now = DateTime::parse_from_rfc3339("2026-02-22T00:00:00Z").expect("valid RFC3339");
    assert!(expiry > now, "sample waiver expiry should be in the future");

    let invalid = DateTime::parse_from_rfc3339("2026-02-31T00:00:00Z");
    assert!(invalid.is_err(), "invalid RFC3339 date must fail parsing");

    let _utc: DateTime<Utc> = now.with_timezone(&Utc);
}
