//! Conformance gate for ambient-authority restrictions (bd-721z).
//!
//! This test enforces:
//! - no non-allowlisted ambient-authority usage in connector/conformance modules
//! - signed + non-expired allowlist exceptions
//! - generated findings + verification artifacts for section 10.15

#[allow(clippy::module_inception)]
#[path = "../../tools/lints/ambient_authority_gate.rs"]
mod ambient_authority_gate;

use chrono::Utc;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
struct VerificationEvidence {
    bead_id: &'static str,
    gate: &'static str,
    generated_on: String,
    status: &'static str,
    modules_scanned: usize,
    findings_total: usize,
    violations: usize,
    allowlisted: usize,
    expired_allowlist: usize,
    invalid_allowlist: usize,
    violation_details: Vec<ambient_authority_gate::ViolationRecord>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn write_verification_artifacts(
    report: &ambient_authority_gate::AmbientAuthorityReport,
    root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence_path = root.join("artifacts/section_10_15/bd-721z/verification_evidence.json");
    let summary_path = root.join("artifacts/section_10_15/bd-721z/verification_summary.md");
    if let Some(parent) = evidence_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = summary_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let status = if report.summary.violations == 0 {
        "pass"
    } else {
        "fail"
    };
    let evidence = VerificationEvidence {
        bead_id: "bd-721z",
        gate: "ambient_authority_gate",
        generated_on: report.generated_on.clone(),
        status,
        modules_scanned: report.summary.modules_scanned,
        findings_total: report.summary.findings_total,
        violations: report.summary.violations,
        allowlisted: report.summary.allowlisted,
        expired_allowlist: report.summary.expired_allowlist,
        invalid_allowlist: report.summary.invalid_allowlist,
        violation_details: report.violations.clone(),
    };
    std::fs::write(evidence_path, serde_json::to_string_pretty(&evidence)?)?;

    let mut summary = String::new();
    summary.push_str("# bd-721z Verification Summary\n\n");
    summary.push_str(&format!("- Status: **{}**\n", status.to_uppercase()));
    summary.push_str(&format!("- Generated on: `{}`\n", report.generated_on));
    summary.push_str(&format!(
        "- Modules scanned: `{}`\n",
        report.summary.modules_scanned
    ));
    summary.push_str(&format!(
        "- Findings total: `{}`\n",
        report.summary.findings_total
    ));
    summary.push_str(&format!(
        "- Violations (`AMB-002`, `AMB-004`): `{}`\n",
        report.summary.violations
    ));
    summary.push_str(&format!(
        "- Allowlisted (`AMB-003`): `{}`\n",
        report.summary.allowlisted
    ));
    summary.push_str(&format!(
        "- Expired allowlist entries: `{}`\n",
        report.summary.expired_allowlist
    ));
    summary.push_str(&format!(
        "- Invalid allowlist entries: `{}`\n",
        report.summary.invalid_allowlist
    ));
    if !report.violations.is_empty() {
        summary.push_str("\n## Violations\n\n");
        for violation in &report.violations {
            summary.push_str(&format!(
                "- `{}`:{} [{}] {}\n",
                violation.module_path, violation.line, violation.ambient_api, violation.reason
            ));
        }
    }
    std::fs::write(summary_path, summary)?;
    Ok(())
}

#[test]
fn ambient_authority_gate_has_no_non_allowlisted_violations() {
    let root = repo_root();
    let config = ambient_authority_gate::AmbientAuthorityConfig::for_repo(&root);
    let report = ambient_authority_gate::run_gate(&config, Utc::now().date_naive())
        .expect("ambient authority gate should execute");

    let findings_path = root.join("artifacts/10.15/ambient_authority_findings.json");
    ambient_authority_gate::write_findings_json(&report, &findings_path)
        .expect("findings artifact should write");
    write_verification_artifacts(&report, &root).expect("verification artifacts should write");

    assert_eq!(
        report.summary.expired_allowlist, 0,
        "expired ambient-authority allowlist entries must fail gate"
    );
    assert_eq!(
        report.summary.invalid_allowlist, 0,
        "invalid ambient-authority allowlist entries must fail gate"
    );
    assert!(
        report.violations.is_empty(),
        "ambient-authority violations found:\n{}",
        serde_json::to_string_pretty(&report.violations).expect("serialize")
    );
}
