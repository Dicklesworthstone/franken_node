//! Conformance gate for Cx-first async API policy (bd-2g6r).
//!
//! This test enforces:
//! - no non-excepted violations for public async control-plane APIs
//! - no expired exceptions
//! - regenerated compliance/evidence artifacts for section 10.15

#[path = "../../tools/lints/cx_first_policy.rs"]
mod cx_first_policy;

use chrono::Utc;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
struct VerificationEvidence<'a> {
    bead_id: &'a str,
    gate: &'a str,
    generated_on: String,
    status: &'a str,
    total_functions_checked: usize,
    compliant_functions: usize,
    violations: usize,
    exceptions_applied: usize,
    expired_exceptions: usize,
    violation_details: Vec<&'a cx_first_policy::ViolationRecord>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn write_verification_artifacts(
    report: &cx_first_policy::LintReport,
    root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence_path = root.join("artifacts/section_10_15/bd-2g6r/verification_evidence.json");
    let summary_path = root.join("artifacts/section_10_15/bd-2g6r/verification_summary.md");
    if let Some(parent) = evidence_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = summary_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let status = if report.violations.is_empty() && report.summary.expired_exceptions == 0 {
        "pass"
    } else {
        "fail"
    };

    let evidence = VerificationEvidence {
        bead_id: "bd-2g6r",
        gate: "cx_first_api_gate",
        generated_on: report.generated_on.clone(),
        status,
        total_functions_checked: report.summary.total_functions,
        compliant_functions: report.summary.compliant_functions,
        violations: report.summary.violations,
        exceptions_applied: report.summary.exceptions_applied,
        expired_exceptions: report.summary.expired_exceptions,
        violation_details: report.violations.iter().collect(),
    };
    std::fs::write(evidence_path, serde_json::to_string_pretty(&evidence)?)?;

    let mut summary = String::new();
    summary.push_str("# bd-2g6r Verification Summary\n\n");
    summary.push_str(&format!("- Status: **{}**\n", status.to_uppercase()));
    summary.push_str(&format!("- Generated on: `{}`\n", report.generated_on));
    summary.push_str(&format!(
        "- Total public async APIs checked: `{}`\n",
        report.summary.total_functions
    ));
    summary.push_str(&format!(
        "- Compliant (`CXF-001`): `{}`\n",
        report.summary.compliant_functions
    ));
    summary.push_str(&format!(
        "- Exceptions applied (`CXF-003`): `{}`\n",
        report.summary.exceptions_applied
    ));
    summary.push_str(&format!(
        "- Violations (`CXF-002` + `CXF-004`): `{}`\n",
        report.summary.violations
    ));
    summary.push_str(&format!(
        "- Expired exceptions (`CXF-004`): `{}`\n",
        report.summary.expired_exceptions
    ));
    if !report.violations.is_empty() {
        summary.push_str("\n## Violations\n\n");
        for violation in &report.violations {
            summary.push_str(&format!(
                "- `{}` ({}) - {}\n",
                violation.function_path, violation.event_code, violation.reason
            ));
        }
    }
    std::fs::write(summary_path, summary)?;
    Ok(())
}

#[test]
fn cx_first_policy_gate_has_no_non_excepted_violations() {
    let root = repo_root();
    let config = cx_first_policy::PolicyConfig::for_repo(&root);
    let report = cx_first_policy::run_policy(&config, Utc::now().date_naive())
        .expect("cx-first policy should execute");

    let csv_path = root.join("artifacts/10.15/cx_first_compliance.csv");
    cx_first_policy::write_compliance_csv(&report, &csv_path).expect("compliance csv should write");
    write_verification_artifacts(&report, &root).expect("verification artifacts should write");

    let csv_text = std::fs::read_to_string(csv_path).expect("csv should exist");
    assert!(
        csv_text.starts_with(
            "module_path,function_name,has_cx_first,exception_status,exception_expiry\n"
        ),
        "compliance csv header mismatch"
    );

    assert_eq!(
        report.summary.expired_exceptions, 0,
        "expired exceptions must fail gate"
    );
    assert!(
        report.violations.is_empty(),
        "cx-first violations found:\n{}",
        serde_json::to_string_pretty(&report.violations).expect("serialize")
    );
}
