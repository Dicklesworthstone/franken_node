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
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, std::io::Error>;

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

#[derive(Debug)]
struct ConformanceCase {
    id: &'static str,
    requirement: &'static str,
    module_body: &'static str,
    allowlist: String,
    expected_event_code: &'static str,
    expected_findings_total: usize,
    expected_violations: usize,
    expected_allowlisted: usize,
    expected_expired_allowlist: usize,
    expected_invalid_allowlist: usize,
    expected_clean_modules: usize,
    expected_api: Option<&'static str>,
}

fn repo_root() -> TestResult<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| failure(format!("repo root canonicalization failed: {error}")))
}

fn write_verification_artifacts(
    report: &ambient_authority_gate::AmbientAuthorityReport,
    root: &Path,
) -> TestResult {
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
    let evidence_json = serde_json::to_string_pretty(&evidence).map_err(|error| {
        failure(format!(
            "verification evidence serialization failed: {error}"
        ))
    })?;
    std::fs::write(evidence_path, evidence_json)?;

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

fn failure(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(failure(message))
    }
}

fn ensure_eq<T>(actual: &T, expected: &T, context: &str) -> TestResult
where
    T: Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(failure(format!(
            "{context}: expected {expected:?}, actual {actual:?}"
        )))
    }
}

fn required_allowlist(
    id: &str,
    module_path: &str,
    ambient_api: &str,
    justification: &str,
    signer: &str,
    expires_on: &str,
    signature: &str,
) -> String {
    format!(
        "[[exceptions]]\n\
         id = \"{id}\"\n\
         module_path = \"{module_path}\"\n\
         ambient_api = \"{ambient_api}\"\n\
         justification = \"{justification}\"\n\
         signer = \"{signer}\"\n\
         expires_on = \"{expires_on}\"\n\
         signature = \"{signature}\"\n"
    )
}

fn signed_allowlist(
    id: &str,
    module_path: &str,
    ambient_api: &str,
    justification: &str,
    signer: &str,
    expires_on: &str,
) -> String {
    let signature = ambient_authority_gate::compute_allowlist_signature(
        module_path,
        ambient_api,
        justification,
        signer,
        expires_on,
    );
    required_allowlist(
        id,
        module_path,
        ambient_api,
        justification,
        signer,
        expires_on,
        &signature,
    )
}

fn setup_fixture_repo(module_body: &str, allowlist: &str) -> TestResult<(TempDir, PathBuf)> {
    let temp = tempfile::tempdir()
        .map_err(|error| failure(format!("fixture tempdir creation failed: {error}")))?;
    let module_path = temp
        .path()
        .join("crates/franken-node/src/connector/sample.rs");
    if let Some(parent) = module_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&module_path, module_body)?;

    let allowlist_path = temp
        .path()
        .join("docs/specs/ambient_authority_allowlist.toml");
    if let Some(parent) = allowlist_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&allowlist_path, allowlist)?;

    Ok((temp, allowlist_path))
}

fn assert_case(case: &ConformanceCase) -> TestResult {
    let (fixture, allowlist_path) = setup_fixture_repo(case.module_body, &case.allowlist)?;
    let config = ambient_authority_gate::AmbientAuthorityConfig {
        repo_root: fixture.path().to_path_buf(),
        target_roots: vec![fixture.path().join("crates/franken-node/src/connector")],
        allowlist_path,
    };
    let today = chrono::NaiveDate::from_ymd_opt(2026, 5, 22)
        .ok_or_else(|| failure("fixture date must be valid"))?;
    let report = ambient_authority_gate::run_gate(&config, today)
        .map_err(|error| failure(format!("{} gate execution failed: {error}", case.id)))?;

    ensure(
        !case.requirement.trim().is_empty(),
        format!("{} requirement text must be non-empty", case.id),
    )?;
    ensure_eq(
        &report.summary.modules_scanned,
        &1,
        &format!("{} modules scanned", case.id),
    )?;
    ensure_eq(
        &report.summary.findings_total,
        &case.expected_findings_total,
        &format!("{} findings total", case.id),
    )?;
    ensure_eq(
        &report.summary.violations,
        &case.expected_violations,
        &format!("{} violations", case.id),
    )?;
    ensure_eq(
        &report.summary.allowlisted,
        &case.expected_allowlisted,
        &format!("{} allowlisted count", case.id),
    )?;
    ensure_eq(
        &report.summary.expired_allowlist,
        &case.expected_expired_allowlist,
        &format!("{} expired allowlist count", case.id),
    )?;
    ensure_eq(
        &report.summary.invalid_allowlist,
        &case.expected_invalid_allowlist,
        &format!("{} invalid allowlist count", case.id),
    )?;
    ensure_eq(
        &report.summary.clean_modules,
        &case.expected_clean_modules,
        &format!("{} clean modules", case.id),
    )?;

    let has_event = report
        .events
        .iter()
        .any(|event| event.event_code == case.expected_event_code);
    ensure(
        has_event,
        format!(
            "{} expected event {} was not emitted",
            case.id, case.expected_event_code
        ),
    )?;

    if let Some(expected_api) = case.expected_api {
        let finding = report
            .findings
            .first()
            .ok_or_else(|| failure(format!("{} expected a finding", case.id)))?;
        ensure_eq(
            &finding.ambient_api.as_str(),
            &expected_api,
            &format!("{} ambient API", case.id),
        )?;
    } else {
        ensure(
            report.findings.is_empty(),
            format!("{} should not emit findings", case.id),
        )?;
    }

    Ok(())
}

#[test]
fn ambient_authority_gate_fixture_matrix_covers_fail_closed_contracts() -> TestResult {
    let module = "crates/franken-node/src/connector/sample.rs";
    let valid_allowlist = signed_allowlist(
        "AAL-CONF-VALID",
        module,
        ambient_authority_gate::API_STD_FS,
        "fixture fs access for conformance",
        "cod_3",
        "2026-12-31",
    );
    let expired_allowlist = signed_allowlist(
        "AAL-CONF-EXPIRED",
        module,
        ambient_authority_gate::API_STD_FS,
        "expired fixture fs access for conformance",
        "cod_3",
        "2024-01-01",
    );
    let forged_allowlist = required_allowlist(
        "AAL-CONF-FORGED",
        module,
        ambient_authority_gate::API_STD_FS,
        "forged fixture fs access for conformance",
        "cod_3",
        "2026-12-31",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    let cases = [
        ConformanceCase {
            id: "AMB-CONF-CLEAN-MODULE",
            requirement: "modules with no ambient-authority calls emit AMB-001 and no findings",
            module_body: "pub fn pure(value: u64) -> u64 {\n    value.saturating_add(1)\n}\n",
            allowlist: "exceptions = []\n".to_string(),
            expected_event_code: ambient_authority_gate::EVENT_MODULE_CLEAN,
            expected_findings_total: 0,
            expected_violations: 0,
            expected_allowlisted: 0,
            expected_expired_allowlist: 0,
            expected_invalid_allowlist: 0,
            expected_clean_modules: 1,
            expected_api: None,
        },
        ConformanceCase {
            id: "AMB-CONF-UNALLOWLISTED-FAILS-CLOSED",
            requirement: "unallowlisted ambient APIs emit AMB-002 and fail closed as violations",
            module_body: "pub fn dial(addr: &str) {\n    let _ = std::net::TcpStream::connect(addr);\n}\n",
            allowlist: "exceptions = []\n".to_string(),
            expected_event_code: ambient_authority_gate::EVENT_VIOLATION,
            expected_findings_total: 1,
            expected_violations: 1,
            expected_allowlisted: 0,
            expected_expired_allowlist: 0,
            expected_invalid_allowlist: 0,
            expected_clean_modules: 0,
            expected_api: Some(ambient_authority_gate::API_STD_NET),
        },
        ConformanceCase {
            id: "AMB-CONF-SIGNED-ALLOWLIST-ONLY",
            requirement: "signed non-expired allowlist entries emit AMB-003 without violations",
            module_body: "pub fn read(path: &std::path::Path) {\n    let _ = std::fs::read_to_string(path);\n}\n",
            allowlist: valid_allowlist,
            expected_event_code: ambient_authority_gate::EVENT_ALLOWLISTED,
            expected_findings_total: 1,
            expected_violations: 0,
            expected_allowlisted: 1,
            expected_expired_allowlist: 0,
            expected_invalid_allowlist: 0,
            expected_clean_modules: 0,
            expected_api: Some(ambient_authority_gate::API_STD_FS),
        },
        ConformanceCase {
            id: "AMB-CONF-EXPIRED-ALLOWLIST-FAILS",
            requirement: "expired signed allowlist entries emit AMB-004 and remain violations",
            module_body: "pub fn read(path: &std::path::Path) {\n    let _ = std::fs::read_to_string(path);\n}\n",
            allowlist: expired_allowlist,
            expected_event_code: ambient_authority_gate::EVENT_ALLOWLIST_INVALID,
            expected_findings_total: 1,
            expected_violations: 1,
            expected_allowlisted: 0,
            expected_expired_allowlist: 1,
            expected_invalid_allowlist: 0,
            expected_clean_modules: 0,
            expected_api: Some(ambient_authority_gate::API_STD_FS),
        },
        ConformanceCase {
            id: "AMB-CONF-FORGED-SIGNATURE-FAILS",
            requirement: "forged allowlist signatures emit AMB-004 and remain violations",
            module_body: "pub fn read(path: &std::path::Path) {\n    let _ = std::fs::read_to_string(path);\n}\n",
            allowlist: forged_allowlist,
            expected_event_code: ambient_authority_gate::EVENT_ALLOWLIST_INVALID,
            expected_findings_total: 1,
            expected_violations: 1,
            expected_allowlisted: 0,
            expected_expired_allowlist: 0,
            expected_invalid_allowlist: 1,
            expected_clean_modules: 0,
            expected_api: Some(ambient_authority_gate::API_STD_FS),
        },
    ];

    for case in cases {
        assert_case(&case)?;
    }

    Ok(())
}

#[test]
fn ambient_authority_gate_has_no_non_allowlisted_violations() -> TestResult {
    let root = repo_root()?;
    let config = ambient_authority_gate::AmbientAuthorityConfig::for_repo(&root);
    let report = ambient_authority_gate::run_gate(&config, Utc::now().date_naive())
        .map_err(|error| failure(format!("ambient authority gate should execute: {error}")))?;

    let findings_path = root.join("artifacts/10.15/ambient_authority_findings.json");
    ambient_authority_gate::write_findings_json(&report, &findings_path)
        .map_err(|error| failure(format!("findings artifact should write: {error}")))?;
    write_verification_artifacts(&report, &root)?;

    ensure_eq(
        &report.summary.expired_allowlist,
        &0,
        "expired ambient-authority allowlist entries must fail gate",
    )?;
    ensure_eq(
        &report.summary.invalid_allowlist,
        &0,
        "invalid ambient-authority allowlist entries must fail gate",
    )?;
    ensure(
        report.violations.is_empty(),
        format!(
            "ambient-authority violations found:\n{}",
            serde_json::to_string_pretty(&report.violations)
                .map_err(|error| failure(format!("violation serialization failed: {error}")))?
        ),
    )
}
