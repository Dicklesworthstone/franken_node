#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::migration::{
    build_rollback_plan, render_audit_report, render_rewrite_report, render_validate_report,
    AuditOutputFormat, MigrationAuditFinding, MigrationAuditReport, MigrationAuditSummary,
    MigrationCategory, MigrationRewriteAction, MigrationRewriteEntry, MigrationRewriteReport,
    MigrationRollbackEntry, MigrationRollbackPlan, MigrationSeverity, MigrationValidateReport,
    MigrationValidateStatus, MigrationValidationCheck, ValidateOutputFormat,
};
use libfuzzer_sys::fuzz_target;

const MAX_ITEMS: usize = 16;
const MAX_TEXT_BYTES: usize = 256;
const MAX_RAW_BYTES: usize = 256 * 1024;

fuzz_target!(|input: FuzzInput| {
    fuzz_structured_reports(&input);
    fuzz_raw_report_json(&input.raw_json);
});

fn fuzz_structured_reports(input: &FuzzInput) {
    let audit = audit_report(input);
    json_roundtrip(&audit);
    let rendered_json =
        render_audit_report(&audit, AuditOutputFormat::Json).expect("audit JSON rendering");
    let rendered_audit: MigrationAuditReport =
        serde_json::from_str(&rendered_json).expect("rendered audit JSON must parse");
    assert_eq!(rendered_audit, audit);
    let _ = render_audit_report(&audit, AuditOutputFormat::Text).expect("audit text rendering");
    let _ = render_audit_report(&audit, AuditOutputFormat::Sarif).expect("audit sarif rendering");

    let rewrite = rewrite_report(input);
    json_roundtrip(&rewrite);
    let _ = render_rewrite_report(&rewrite);
    let rollback = build_rollback_plan(&rewrite);
    assert_eq!(rollback.entry_count, rewrite.rollback_entries.len());
    json_roundtrip(&rollback);

    let explicit_rollback = rollback_plan(input);
    json_roundtrip(&explicit_rollback);

    let validate = validate_report(input);
    json_roundtrip(&validate);
    let _ = render_validate_report(&validate);
    assert_eq!(
        validate.is_pass(),
        matches!(validate.status, MigrationValidateStatus::Pass)
    );

    assert!(AuditOutputFormat::parse("json").is_ok());
    assert!(ValidateOutputFormat::parse("text").is_ok());
}

fn fuzz_raw_report_json(bytes: &[u8]) {
    if bytes.len() > MAX_RAW_BYTES {
        return;
    }

    let _ = serde_json::from_slice::<MigrationAuditReport>(bytes);
    let _ = serde_json::from_slice::<MigrationRewriteReport>(bytes);
    let _ = serde_json::from_slice::<MigrationRollbackPlan>(bytes);
    let _ = serde_json::from_slice::<MigrationValidateReport>(bytes);

    if let Ok(report) = serde_json::from_slice::<MigrationAuditReport>(bytes) {
        if let Ok(rendered) = render_audit_report(&report, AuditOutputFormat::Json) {
            let decoded: MigrationAuditReport =
                serde_json::from_str(&rendered).expect("rendered audit JSON must decode");
            assert_eq!(decoded, report);
        }
    }
}

fn json_roundtrip<T>(value: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + Eq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).expect("report JSON encode");
    let decoded: T = serde_json::from_str(&json).expect("report JSON decode");
    assert_eq!(&decoded, value);
    let pretty = serde_json::to_string_pretty(value).expect("report pretty JSON encode");
    let decoded_pretty: T = serde_json::from_str(&pretty).expect("report pretty JSON decode");
    assert_eq!(&decoded_pretty, value);
}

fn audit_report(input: &FuzzInput) -> MigrationAuditReport {
    let findings = findings(input);
    MigrationAuditReport {
        schema_version: "1.0.0".to_string(),
        project_path: format!("/tmp/fuzz/{}", bounded_text(&input.project)),
        generated_at_utc: "2026-04-21T00:00:00Z".to_string(),
        summary: MigrationAuditSummary {
            files_scanned: input.entries.len().saturating_add(findings.len()),
            js_files: input.entries.len(),
            ts_files: findings.len(),
            package_manifests: usize::from(input.selector % 8),
            risky_scripts: usize::from(input.selector % 4),
            lockfiles: vec!["package-lock.json".to_string()],
        },
        findings,
    }
}

fn rewrite_report(input: &FuzzInput) -> MigrationRewriteReport {
    let entries = input
        .entries
        .iter()
        .take(MAX_ITEMS)
        .enumerate()
        .map(|(index, entry)| MigrationRewriteEntry {
            id: format!("mig-rewrite-{index:03}"),
            path: Some(format!("src/{}.js", bounded_text(&entry.path))),
            action: entry.action.into(),
            detail: bounded_text(&entry.detail),
            applied: entry.flag,
        })
        .collect::<Vec<_>>();
    let rollback_entries = rollback_entries(input);

    MigrationRewriteReport {
        schema_version: "1.0.0".to_string(),
        project_path: format!("/tmp/fuzz/{}", bounded_text(&input.project)),
        generated_at_utc: "2026-04-21T00:00:00Z".to_string(),
        apply_mode: input.flag,
        package_manifests_scanned: entries.len(),
        rewrites_planned: entries.len(),
        rewrites_applied: if input.flag { entries.len() } else { 0 },
        manual_review_items: usize::from(input.selector % 5),
        entries,
        rollback_entries,
    }
}

fn rollback_plan(input: &FuzzInput) -> MigrationRollbackPlan {
    let entries = rollback_entries(input);
    MigrationRollbackPlan {
        schema_version: "1.0.0".to_string(),
        project_path: format!("/tmp/fuzz/{}", bounded_text(&input.project)),
        generated_at_utc: "2026-04-21T00:00:00Z".to_string(),
        apply_mode: input.flag,
        entry_count: entries.len(),
        entries,
    }
}

fn validate_report(input: &FuzzInput) -> MigrationValidateReport {
    let blocking_findings = findings(input);
    let warning_findings = findings(input);
    let status = if input.flag && blocking_findings.is_empty() {
        MigrationValidateStatus::Pass
    } else {
        MigrationValidateStatus::Fail
    };

    MigrationValidateReport {
        schema_version: "1.0.0".to_string(),
        project_path: format!("/tmp/fuzz/{}", bounded_text(&input.project)),
        generated_at_utc: "2026-04-21T00:00:00Z".to_string(),
        status,
        checks: input
            .entries
            .iter()
            .take(MAX_ITEMS)
            .enumerate()
            .map(|(index, entry)| MigrationValidationCheck {
                id: format!("mig-validate-{index:03}"),
                passed: entry.flag,
                message: bounded_text(&entry.detail),
                remediation: Some("Inspect generated fuzz migration report".to_string()),
            })
            .collect(),
        blocking_findings,
        warning_findings,
        #[cfg(target_os = "linux")]
        test_suite: None,
    }
}

fn findings(input: &FuzzInput) -> Vec<MigrationAuditFinding> {
    input
        .entries
        .iter()
        .take(MAX_ITEMS)
        .enumerate()
        .map(|(index, entry)| MigrationAuditFinding {
            id: format!("mig-audit-{index:03}"),
            category: entry.category.into(),
            severity: entry.severity.into(),
            message: bounded_text(&entry.detail),
            path: Some(format!("src/{}", bounded_text(&entry.path))),
            recommendation: Some("Run franken-node migrate rewrite".to_string()),
        })
        .collect()
}

fn rollback_entries(input: &FuzzInput) -> Vec<MigrationRollbackEntry> {
    input
        .entries
        .iter()
        .take(MAX_ITEMS)
        .map(|entry| MigrationRollbackEntry {
            path: format!("src/{}", bounded_text(&entry.path)),
            original_content: bounded_text(&entry.original),
            rewritten_content: bounded_text(&entry.rewritten),
        })
        .collect()
}

fn bounded_text(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_TEXT_BYTES)
        .collect();
    if out.is_empty() {
        out.push('x');
    }
    out
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    project: String,
    entries: Vec<EntryFuzz>,
    selector: u8,
    flag: bool,
    raw_json: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct EntryFuzz {
    path: String,
    detail: String,
    original: String,
    rewritten: String,
    severity: FuzzSeverity,
    category: FuzzCategory,
    action: FuzzRewriteAction,
    flag: bool,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl From<FuzzSeverity> for MigrationSeverity {
    fn from(value: FuzzSeverity) -> Self {
        match value {
            FuzzSeverity::Info => Self::Info,
            FuzzSeverity::Low => Self::Low,
            FuzzSeverity::Medium => Self::Medium,
            FuzzSeverity::High => Self::High,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzCategory {
    Project,
    Dependencies,
    Scripts,
    Runtime,
}

impl From<FuzzCategory> for MigrationCategory {
    fn from(value: FuzzCategory) -> Self {
        match value {
            FuzzCategory::Project => Self::Project,
            FuzzCategory::Dependencies => Self::Dependencies,
            FuzzCategory::Scripts => Self::Scripts,
            FuzzCategory::Runtime => Self::Runtime,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzRewriteAction {
    PinNodeEngine,
    RewritePackageScript,
    RewriteCommonJsRequire,
    RewriteEsmImport,
    ModuleGraphDiscovery,
    ManualModuleReview,
    ManualScriptReview,
    ManifestReadError,
    ManifestParseError,
    NoPackageManifest,
}

impl From<FuzzRewriteAction> for MigrationRewriteAction {
    fn from(value: FuzzRewriteAction) -> Self {
        match value {
            FuzzRewriteAction::PinNodeEngine => Self::PinNodeEngine,
            FuzzRewriteAction::RewritePackageScript => Self::RewritePackageScript,
            FuzzRewriteAction::RewriteCommonJsRequire => Self::RewriteCommonJsRequire,
            FuzzRewriteAction::RewriteEsmImport => Self::RewriteEsmImport,
            FuzzRewriteAction::ModuleGraphDiscovery => Self::ModuleGraphDiscovery,
            FuzzRewriteAction::ManualModuleReview => Self::ManualModuleReview,
            FuzzRewriteAction::ManualScriptReview => Self::ManualScriptReview,
            FuzzRewriteAction::ManifestReadError => Self::ManifestReadError,
            FuzzRewriteAction::ManifestParseError => Self::ManifestParseError,
            FuzzRewriteAction::NoPackageManifest => Self::NoPackageManifest,
        }
    }
}
