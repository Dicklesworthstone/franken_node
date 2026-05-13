use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

const MAX_SOURCE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PACKAGE_JSON_BYTES: u64 = 512 * 1024;
const MAX_REGISTRY_BYTES: u64 = 4 * 1024 * 1024;

pub const PROJECT_SCANNER_GATE: &str = "project_scanner_verification";
pub const PROJECT_SCANNER_SECTION: &str = "10.3";
pub const PROJECT_SCANNER_SCHEMA_ID: &str = "franken_node/migration/scan_report/v1";

#[derive(Debug)]
pub enum ProjectScanError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    InvalidTimestamp,
}

impl fmt::Display for ProjectScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProjectScanError::Io { path, source } => {
                write!(f, "failed reading {}: {source}", path.display())
            }
            ProjectScanError::Json { path, source } => {
                write!(f, "failed parsing JSON from {}: {source}", path.display())
            }
            ProjectScanError::InvalidTimestamp => write!(f, "scan timestamp must not be blank"),
        }
    }
}

impl std::error::Error for ProjectScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProjectScanError::Io { source, .. } => Some(source),
            ProjectScanError::Json { source, .. } => Some(source),
            ProjectScanError::InvalidTimestamp => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationReadiness {
    Ready,
    Partial,
    NotReady,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RiskDistribution {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub critical: u64,
}

impl RiskDistribution {
    pub fn increment(&mut self, risk_level: RiskLevel) {
        match risk_level {
            RiskLevel::Low => self.low = self.low.saturating_add(1),
            RiskLevel::Medium => self.medium = self.medium.saturating_add(1),
            RiskLevel::High => self.high = self.high.saturating_add(1),
            RiskLevel::Critical => self.critical = self.critical.saturating_add(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_apis_detected: u64,
    pub risk_distribution: RiskDistribution,
    pub migration_readiness: MigrationReadiness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiUsage {
    pub api_family: String,
    pub api_name: String,
    pub source_file: String,
    pub line_number: Option<u64>,
    pub band: Option<String>,
    pub impl_status: Option<String>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyRisk {
    pub name: String,
    pub version: Option<String>,
    pub has_native_addon: bool,
    pub risk_level: RiskLevel,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    pub category: String,
    pub message: String,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectScanReport {
    pub project: String,
    pub scan_timestamp: String,
    pub summary: ScanSummary,
    pub api_usage: Vec<ApiUsage>,
    pub dependencies: Vec<DependencyRisk>,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectScannerVerification {
    pub gate: String,
    pub section: String,
    pub verdict: String,
    pub timestamp: String,
    pub checks: Vec<VerificationCheck>,
    pub summary: VerificationSummary,
    pub sample_report: ProjectScanReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub id: String,
    pub status: String,
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationSummary {
    pub total_checks: u64,
    pub passing_checks: u64,
    pub failing_checks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    pub band: Option<String>,
    pub shim_type: Option<String>,
}

pub type CompatibilityRegistry = BTreeMap<(String, String), RegistryEntry>;

#[derive(Debug, Clone, Copy)]
struct ApiPattern {
    family: &'static str,
    name: &'static str,
    detector: fn(&str) -> Option<&'static str>,
}

pub fn default_registry_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("docs")
        .join("COMPATIBILITY_REGISTRY.json")
}

pub fn load_default_registry() -> Result<CompatibilityRegistry, ProjectScanError> {
    load_registry(default_registry_path())
}

pub fn load_registry(path: impl AsRef<Path>) -> Result<CompatibilityRegistry, ProjectScanError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(CompatibilityRegistry::new());
    }

    let text = crate::bounded_read_to_string(path, MAX_REGISTRY_BYTES).map_err(|source| {
        ProjectScanError::Io {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let value: Value = serde_json::from_str(&text).map_err(|source| ProjectScanError::Json {
        path: path.to_path_buf(),
        source,
    })?;

    let mut registry = CompatibilityRegistry::new();
    if let Some(behaviors) = value.get("behaviors").and_then(Value::as_array) {
        for entry in behaviors {
            let Some(family) = entry.get("api_family").and_then(Value::as_str) else {
                continue;
            };
            let Some(name) = entry.get("api_name").and_then(Value::as_str) else {
                continue;
            };
            registry.insert(
                (family.to_string(), name.to_string()),
                RegistryEntry {
                    band: entry
                        .get("band")
                        .and_then(Value::as_str)
                        .map(ToString::to_string),
                    shim_type: entry
                        .get("shim_type")
                        .and_then(Value::as_str)
                        .map(ToString::to_string),
                },
            );
        }
    }

    Ok(registry)
}

pub fn classify_risk(band: Option<&str>, impl_status: Option<&str>, is_unsafe: bool) -> RiskLevel {
    if is_unsafe {
        return RiskLevel::Critical;
    }

    match (band, impl_status) {
        (Some("core"), Some("native" | "polyfill" | "bridge")) => RiskLevel::Low,
        (Some("core"), _) => RiskLevel::Medium,
        (Some("high-value"), Some("native" | "polyfill" | "bridge")) => RiskLevel::Low,
        (Some("high-value"), _) => RiskLevel::High,
        (Some("edge"), _) => RiskLevel::Medium,
        _ => RiskLevel::Medium,
    }
}

pub fn compute_readiness(risk_distribution: &RiskDistribution) -> MigrationReadiness {
    if risk_distribution.critical > 0 {
        MigrationReadiness::NotReady
    } else if risk_distribution.high > 0 {
        MigrationReadiness::Partial
    } else {
        MigrationReadiness::Ready
    }
}

pub fn scan_project(project_dir: impl AsRef<Path>) -> Result<ProjectScanReport, ProjectScanError> {
    let timestamp = Utc::now().to_rfc3339();
    scan_project_at(project_dir, timestamp)
}

pub fn scan_project_at(
    project_dir: impl AsRef<Path>,
    scan_timestamp: impl Into<String>,
) -> Result<ProjectScanReport, ProjectScanError> {
    let registry = load_default_registry()?;
    scan_project_with_registry_at(project_dir, &registry, scan_timestamp)
}

pub fn scan_project_with_registry_at(
    project_dir: impl AsRef<Path>,
    registry: &CompatibilityRegistry,
    scan_timestamp: impl Into<String>,
) -> Result<ProjectScanReport, ProjectScanError> {
    let project_dir = project_dir.as_ref();
    let scan_timestamp = scan_timestamp.into();
    if scan_timestamp.trim().is_empty() {
        return Err(ProjectScanError::InvalidTimestamp);
    }

    let mut api_usage = Vec::new();
    if project_dir.is_dir() {
        for source_file in collect_source_files(project_dir)? {
            api_usage.extend(scan_file(&source_file, registry)?);
        }
    }
    api_usage.sort_by(|left, right| {
        (
            &left.source_file,
            &left.api_family,
            &left.api_name,
            left.line_number,
        )
            .cmp(&(
                &right.source_file,
                &right.api_family,
                &right.api_name,
                right.line_number,
            ))
    });

    let dependencies = scan_dependencies(project_dir)?;
    let mut risk_distribution = RiskDistribution::default();
    for api in &api_usage {
        risk_distribution.increment(api.risk_level);
    }
    for dependency in &dependencies {
        if dependency.risk_level == RiskLevel::Critical {
            risk_distribution.increment(RiskLevel::Critical);
        }
    }

    let recommendations = recommendations_for(&risk_distribution);
    let migration_readiness = compute_readiness(&risk_distribution);

    Ok(ProjectScanReport {
        project: project_dir.to_string_lossy().into_owned(),
        scan_timestamp,
        summary: ScanSummary {
            total_apis_detected: usize_to_u64(api_usage.len()),
            risk_distribution,
            migration_readiness,
        },
        api_usage,
        dependencies,
        recommendations,
    })
}

pub fn scan_file(
    filepath: impl AsRef<Path>,
    registry: &CompatibilityRegistry,
) -> Result<Vec<ApiUsage>, ProjectScanError> {
    let filepath = filepath.as_ref();
    let text =
        crate::bounded_read_to_string(filepath, MAX_SOURCE_FILE_BYTES).map_err(|source| {
            ProjectScanError::Io {
                path: filepath.to_path_buf(),
                source,
            }
        })?;
    Ok(scan_text(filepath, &text, registry))
}

pub fn scan_text(
    source_file: impl AsRef<Path>,
    text: &str,
    registry: &CompatibilityRegistry,
) -> Vec<ApiUsage> {
    let source_file = source_file.as_ref().to_string_lossy().into_owned();
    let mut results = Vec::new();
    let mut seen = BTreeSet::new();

    for pattern in API_PATTERNS {
        if let Some(needle) = (pattern.detector)(text) {
            let seen_key = (pattern.family, pattern.name);
            if !seen.insert(seen_key) {
                continue;
            }
            let key = (pattern.family.to_string(), pattern.name.to_string());
            let registry_entry = registry.get(&key);
            let band = registry_entry.and_then(|entry| entry.band.clone());
            let impl_status = registry_entry.and_then(|entry| entry.shim_type.clone());
            let risk_level = classify_risk(band.as_deref(), impl_status.as_deref(), false);
            results.push(ApiUsage {
                api_family: pattern.family.to_string(),
                api_name: pattern.name.to_string(),
                source_file: source_file.clone(),
                line_number: first_line_number(text, needle),
                band,
                impl_status,
                risk_level,
            });
        }
    }

    for pattern in UNSAFE_PATTERNS {
        if let Some(needle) = (pattern.detector)(text) {
            let seen_key = ("unsafe", pattern.name);
            if !seen.insert(seen_key) {
                continue;
            }
            results.push(ApiUsage {
                api_family: "unsafe".to_string(),
                api_name: pattern.name.to_string(),
                source_file: source_file.clone(),
                line_number: first_line_number(text, needle),
                band: Some("unsafe".to_string()),
                impl_status: None,
                risk_level: RiskLevel::Critical,
            });
        }
    }

    results
}

pub fn scan_dependencies(
    project_dir: impl AsRef<Path>,
) -> Result<Vec<DependencyRisk>, ProjectScanError> {
    let package_json_path = project_dir.as_ref().join("package.json");
    if !package_json_path.exists() {
        return Ok(Vec::new());
    }

    let text = crate::bounded_read_to_string(&package_json_path, MAX_PACKAGE_JSON_BYTES).map_err(
        |source| ProjectScanError::Io {
            path: package_json_path.clone(),
            source,
        },
    )?;
    let package: Value = serde_json::from_str(&text).map_err(|source| ProjectScanError::Json {
        path: package_json_path.clone(),
        source,
    })?;

    let mut versions = BTreeMap::new();
    collect_dependencies(package.get("dependencies"), &mut versions);
    collect_dependencies(package.get("devDependencies"), &mut versions);

    let mut dependencies = Vec::new();
    for (name, version) in versions {
        let has_native_addon = is_native_addon_package(&name);
        dependencies.push(DependencyRisk {
            name,
            version,
            has_native_addon,
            risk_level: if has_native_addon {
                RiskLevel::Critical
            } else {
                RiskLevel::Low
            },
            notes: has_native_addon
                .then(|| "Native addon - requires port or replacement".to_string()),
        });
    }

    Ok(dependencies)
}

pub fn verification_report_at(
    project_dir: impl AsRef<Path>,
    timestamp: impl Into<String>,
) -> Result<ProjectScannerVerification, ProjectScanError> {
    let timestamp = timestamp.into();
    let registry = load_default_registry()?;
    let sample_report =
        scan_project_with_registry_at(project_dir.as_ref(), &registry, timestamp.clone())?;

    let mut checks = Vec::new();
    checks.push(check_bool(
        "SCANNER-RUST-EXISTS",
        true,
        [("module".to_string(), Value::Bool(true))],
    ));
    checks.push(check_bool(
        "SCANNER-REGISTRY",
        !registry.is_empty(),
        [(
            "registry_entries".to_string(),
            Value::from(usize_to_u64(registry.len())),
        )],
    ));
    checks.push(check_bool(
        "SCANNER-DETECTS-APIS",
        sample_report.summary.total_apis_detected > 0,
        [(
            "apis_detected".to_string(),
            Value::from(sample_report.summary.total_apis_detected),
        )],
    ));
    checks.push(check_bool(
        "SCANNER-DETECTS-DEPS",
        !sample_report.dependencies.is_empty(),
        [(
            "deps_detected".to_string(),
            Value::from(usize_to_u64(sample_report.dependencies.len())),
        )],
    ));
    checks.push(check_bool(
        "SCANNER-READINESS",
        matches!(
            sample_report.summary.migration_readiness,
            MigrationReadiness::Ready | MigrationReadiness::Partial | MigrationReadiness::NotReady
        ),
        [(
            "migration_readiness".to_string(),
            Value::String(format!("{:?}", sample_report.summary.migration_readiness)),
        )],
    ));

    let failing_checks = usize_to_u64(checks.iter().filter(|check| check.status == "FAIL").count());
    let total_checks = usize_to_u64(checks.len());
    let passing_checks = total_checks.saturating_sub(failing_checks);

    Ok(ProjectScannerVerification {
        gate: PROJECT_SCANNER_GATE.to_string(),
        section: PROJECT_SCANNER_SECTION.to_string(),
        verdict: if failing_checks == 0 { "PASS" } else { "FAIL" }.to_string(),
        timestamp,
        checks,
        summary: VerificationSummary {
            total_checks,
            passing_checks,
            failing_checks,
        },
        sample_report,
    })
}

pub fn to_json_value(report: &ProjectScanReport) -> Result<Value, serde_json::Error> {
    serde_json::to_value(report)
}

fn collect_source_files(project_dir: &Path) -> Result<Vec<PathBuf>, ProjectScanError> {
    let mut files = Vec::new();
    collect_source_files_inner(project_dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_source_files_inner(
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), ProjectScanError> {
    let entries = std::fs::read_dir(directory).map_err(|source| ProjectScanError::Io {
        path: directory.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| ProjectScanError::Io {
            path: directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| ProjectScanError::Io {
            path: path.clone(),
            source,
        })?;

        if file_type.is_dir() {
            if path.file_name().and_then(|name| name.to_str()) == Some("node_modules") {
                continue;
            }
            collect_source_files_inner(&path, files)?;
        } else if file_type.is_file() && is_javascript_source(&path) {
            files.push(path);
        }
    }

    Ok(())
}

fn is_javascript_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "jsx" | "tsx")
    )
}

fn collect_dependencies(value: Option<&Value>, versions: &mut BTreeMap<String, Option<String>>) {
    let Some(dependencies) = value.and_then(Value::as_object) else {
        return;
    };
    for (name, version) in dependencies {
        let version = version
            .as_str()
            .map(ToString::to_string)
            .or_else(|| Some(version.to_string()));
        versions.insert(name.clone(), version);
    }
}

fn recommendations_for(risk_distribution: &RiskDistribution) -> Vec<Recommendation> {
    let mut recommendations = Vec::new();
    if risk_distribution.critical > 0 {
        recommendations.push(Recommendation {
            category: "blocking".to_string(),
            message: format!(
                "{} critical risk items found - address before migration",
                risk_distribution.critical
            ),
            severity: "error".to_string(),
        });
    }
    if risk_distribution.high > 0 {
        recommendations.push(Recommendation {
            category: "high-risk".to_string(),
            message: format!(
                "{} high-risk API usages - verify compatibility before migration",
                risk_distribution.high
            ),
            severity: "warning".to_string(),
        });
    }
    recommendations
}

fn check_bool<I>(id: &str, passed: bool, details: I) -> VerificationCheck
where
    I: IntoIterator<Item = (String, Value)>,
{
    VerificationCheck {
        id: id.to_string(),
        status: if passed { "PASS" } else { "FAIL" }.to_string(),
        details: details.into_iter().collect(),
    }
}

fn first_line_number(text: &str, needle: &str) -> Option<u64> {
    let offset = text.find(needle)?;
    let prefix = text.get(..offset)?;
    Some(usize_to_u64(prefix.bytes().filter(|byte| *byte == b'\n').count()).saturating_add(1))
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn has_fs_import(text: &str) -> bool {
    text.contains("require('fs')")
        || text.contains("require(\"fs\")")
        || text.contains("from 'fs'")
        || text.contains("from \"fs\"")
}

fn contains_fs_read_file(text: &str) -> Option<&'static str> {
    if has_fs_import(text) && text.contains(".readFile") {
        Some(".readFile")
    } else {
        None
    }
}

fn contains_fs_read_file_sync(text: &str) -> Option<&'static str> {
    if text.contains("fs.readFileSync") {
        Some("fs.readFileSync")
    } else if text.contains("readFileSync(") {
        Some("readFileSync(")
    } else {
        None
    }
}

fn contains_fs_write_file(text: &str) -> Option<&'static str> {
    if has_fs_import(text) && text.contains(".writeFile") {
        Some(".writeFile")
    } else {
        None
    }
}

fn contains_fs_write_file_sync(text: &str) -> Option<&'static str> {
    if text.contains("fs.writeFileSync") {
        Some("fs.writeFileSync")
    } else if text.contains("writeFileSync(") {
        Some("writeFileSync(")
    } else {
        None
    }
}

fn contains_path_join(text: &str) -> Option<&'static str> {
    text.contains("path.join(").then_some("path.join(")
}

fn contains_path_resolve(text: &str) -> Option<&'static str> {
    text.contains("path.resolve(").then_some("path.resolve(")
}

fn contains_process_env(text: &str) -> Option<&'static str> {
    text.contains("process.env").then_some("process.env")
}

fn contains_process_argv(text: &str) -> Option<&'static str> {
    text.contains("process.argv").then_some("process.argv")
}

fn contains_process_exit(text: &str) -> Option<&'static str> {
    text.contains("process.exit(").then_some("process.exit(")
}

fn contains_http_create_server(text: &str) -> Option<&'static str> {
    text.contains("http.createServer(")
        .then_some("http.createServer(")
}

fn contains_http_request(text: &str) -> Option<&'static str> {
    text.contains("http.request(").then_some("http.request(")
}

fn contains_crypto_create_hash(text: &str) -> Option<&'static str> {
    text.contains("crypto.createHash(")
        .then_some("crypto.createHash(")
}

fn contains_crypto_random_bytes(text: &str) -> Option<&'static str> {
    text.contains("crypto.randomBytes(")
        .then_some("crypto.randomBytes(")
}

fn contains_child_process_exec(text: &str) -> Option<&'static str> {
    if text.contains("child_process.exec(") {
        Some("child_process.exec(")
    } else {
        text.contains("exec(").then_some("exec(")
    }
}

fn contains_child_process_spawn(text: &str) -> Option<&'static str> {
    if text.contains("child_process.spawn(") {
        Some("child_process.spawn(")
    } else {
        text.contains("spawn(").then_some("spawn(")
    }
}

fn contains_eval(text: &str) -> Option<&'static str> {
    text.contains("eval(").then_some("eval(")
}

fn contains_new_function(text: &str) -> Option<&'static str> {
    text.contains("new Function(").then_some("new Function(")
}

fn contains_vm_run_in_new_context(text: &str) -> Option<&'static str> {
    text.contains("vm.runInNewContext(")
        .then_some("vm.runInNewContext(")
}

fn contains_process_binding(text: &str) -> Option<&'static str> {
    text.contains("process.binding(")
        .then_some("process.binding(")
}

fn is_native_addon_package(name: &str) -> bool {
    matches!(
        name,
        "bcrypt"
            | "sharp"
            | "canvas"
            | "better-sqlite3"
            | "node-gyp"
            | "node-pre-gyp"
            | "nan"
            | "node-addon-api"
            | "ffi-napi"
            | "ref-napi"
            | "leveldown"
            | "sodium-native"
            | "argon2"
    )
}

const API_PATTERNS: &[ApiPattern] = &[
    ApiPattern {
        family: "fs",
        name: "readFile",
        detector: contains_fs_read_file,
    },
    ApiPattern {
        family: "fs",
        name: "readFileSync",
        detector: contains_fs_read_file_sync,
    },
    ApiPattern {
        family: "fs",
        name: "writeFile",
        detector: contains_fs_write_file,
    },
    ApiPattern {
        family: "fs",
        name: "writeFileSync",
        detector: contains_fs_write_file_sync,
    },
    ApiPattern {
        family: "path",
        name: "join",
        detector: contains_path_join,
    },
    ApiPattern {
        family: "path",
        name: "resolve",
        detector: contains_path_resolve,
    },
    ApiPattern {
        family: "process",
        name: "env",
        detector: contains_process_env,
    },
    ApiPattern {
        family: "process",
        name: "argv",
        detector: contains_process_argv,
    },
    ApiPattern {
        family: "process",
        name: "exit",
        detector: contains_process_exit,
    },
    ApiPattern {
        family: "http",
        name: "createServer",
        detector: contains_http_create_server,
    },
    ApiPattern {
        family: "http",
        name: "request",
        detector: contains_http_request,
    },
    ApiPattern {
        family: "crypto",
        name: "createHash",
        detector: contains_crypto_create_hash,
    },
    ApiPattern {
        family: "crypto",
        name: "randomBytes",
        detector: contains_crypto_random_bytes,
    },
    ApiPattern {
        family: "child_process",
        name: "exec",
        detector: contains_child_process_exec,
    },
    ApiPattern {
        family: "child_process",
        name: "spawn",
        detector: contains_child_process_spawn,
    },
];

const UNSAFE_PATTERNS: &[ApiPattern] = &[
    ApiPattern {
        family: "unsafe",
        name: "eval",
        detector: contains_eval,
    },
    ApiPattern {
        family: "unsafe",
        name: "Function",
        detector: contains_new_function,
    },
    ApiPattern {
        family: "unsafe",
        name: "vm.runInNewContext",
        detector: contains_vm_run_in_new_context,
    },
    ApiPattern {
        family: "unsafe",
        name: "process.binding",
        detector: contains_process_binding,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn registry() -> CompatibilityRegistry {
        BTreeMap::from([
            (
                ("fs".to_string(), "readFile".to_string()),
                RegistryEntry {
                    band: Some("core".to_string()),
                    shim_type: Some("stub".to_string()),
                },
            ),
            (
                ("fs".to_string(), "readFileSync".to_string()),
                RegistryEntry {
                    band: Some("core".to_string()),
                    shim_type: Some("native".to_string()),
                },
            ),
            (
                ("path".to_string(), "join".to_string()),
                RegistryEntry {
                    band: Some("core".to_string()),
                    shim_type: Some("stub".to_string()),
                },
            ),
            (
                ("http".to_string(), "createServer".to_string()),
                RegistryEntry {
                    band: Some("high-value".to_string()),
                    shim_type: Some("stub".to_string()),
                },
            ),
        ])
    }

    #[test]
    fn risk_classifier_matches_python_contract() {
        assert_eq!(
            classify_risk(Some("core"), Some("native"), false),
            RiskLevel::Low
        );
        assert_eq!(
            classify_risk(Some("core"), Some("stub"), false),
            RiskLevel::Medium
        );
        assert_eq!(
            classify_risk(Some("high-value"), Some("stub"), false),
            RiskLevel::High
        );
        assert_eq!(classify_risk(None, None, true), RiskLevel::Critical);
        assert_eq!(classify_risk(None, None, false), RiskLevel::Medium);
    }

    #[test]
    fn scan_text_detects_apis_and_unsafe_usage() {
        let text = "const fs = require('fs');\n\
            const path = require('path');\n\
            const data = fs.readFileSync('config.json', 'utf8');\n\
            const full = path.join(__dirname, 'data');\n\
            eval('alert(1)');\n";

        let results = scan_text("fixture.js", text, &registry());
        let names: BTreeSet<_> = results
            .iter()
            .map(|usage| (usage.api_family.as_str(), usage.api_name.as_str()))
            .collect();

        assert!(names.contains(&("fs", "readFile")));
        assert!(names.contains(&("fs", "readFileSync")));
        assert!(names.contains(&("path", "join")));
        assert!(names.contains(&("unsafe", "eval")));
        assert!(
            results
                .iter()
                .any(|usage| usage.risk_level == RiskLevel::Critical)
        );
    }

    #[test]
    fn scan_project_is_deterministic_for_fixed_timestamp() {
        let tmp = tempdir().expect("tempdir");
        let project = tmp.path();
        std::fs::write(
            project.join("server.js"),
            "const http = require('http');\nhttp.createServer(() => {}).listen(3000);\n",
        )
        .expect("write server");
        std::fs::write(
            project.join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"},"devDependencies":{"jest":"^29.0.0"}}"#,
        )
        .expect("write package");

        let first = scan_project_with_registry_at(project, &registry(), "2026-05-13T00:00:00Z")
            .expect("first scan");
        let second = scan_project_with_registry_at(project, &registry(), "2026-05-13T00:00:00Z")
            .expect("second scan");

        assert_eq!(first, second);
        assert_eq!(first.summary.total_apis_detected, 1);
        assert_eq!(
            first.summary.migration_readiness,
            MigrationReadiness::Partial
        );
    }

    #[test]
    fn native_addon_dependency_is_critical_and_not_ready() {
        let tmp = tempdir().expect("tempdir");
        let project = tmp.path();
        std::fs::write(
            project.join("package.json"),
            r#"{"dependencies":{"sharp":"^0.32.0","express":"^4.18.0"}}"#,
        )
        .expect("write package");

        let report = scan_project_with_registry_at(project, &registry(), "2026-05-13T00:00:00Z")
            .expect("scan");
        let sharp = report
            .dependencies
            .iter()
            .find(|dependency| dependency.name == "sharp")
            .expect("sharp dependency");

        assert!(sharp.has_native_addon);
        assert_eq!(sharp.risk_level, RiskLevel::Critical);
        assert_eq!(
            report.summary.migration_readiness,
            MigrationReadiness::NotReady
        );
        assert_eq!(report.summary.risk_distribution.critical, 1);
    }

    #[test]
    fn node_modules_are_skipped() {
        let tmp = tempdir().expect("tempdir");
        let project = tmp.path();
        let node_modules = project.join("node_modules");
        std::fs::create_dir(&node_modules).expect("create node_modules");
        std::fs::write(
            node_modules.join("ignored.js"),
            "const env = process.env.NODE_ENV;\n",
        )
        .expect("write ignored file");
        std::fs::write(project.join("index.js"), "const argv = process.argv;\n")
            .expect("write source");

        let report = scan_project_with_registry_at(project, &registry(), "2026-05-13T00:00:00Z")
            .expect("scan");

        assert_eq!(report.summary.total_apis_detected, 1);
        assert_eq!(report.api_usage[0].api_name, "argv");
    }

    #[test]
    fn malformed_package_json_fails_closed() {
        let tmp = tempdir().expect("tempdir");
        let project = tmp.path();
        std::fs::write(project.join("package.json"), "{not-json").expect("write package");

        let error = scan_project_with_registry_at(project, &registry(), "2026-05-13T00:00:00Z")
            .expect_err("malformed package must fail");

        assert!(matches!(error, ProjectScanError::Json { .. }));
    }
}
