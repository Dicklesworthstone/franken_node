#![allow(clippy::module_name_repetitions)]

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

pub const EVENT_MODULE_CLEAN: &str = "AMB-001";
pub const EVENT_VIOLATION: &str = "AMB-002";
pub const EVENT_ALLOWLISTED: &str = "AMB-003";
pub const EVENT_ALLOWLIST_INVALID: &str = "AMB-004";

pub const API_STD_NET: &str = "std::net";
pub const API_STD_PROCESS_COMMAND: &str = "std::process::Command";
pub const API_STD_TIME_INSTANT: &str = "std::time::Instant";
pub const API_STD_TIME_SYSTEM_TIME: &str = "std::time::SystemTime";
pub const API_STD_FS: &str = "std::fs";
pub const API_TOKIO_NET: &str = "tokio::net";
pub const API_TOKIO_PROCESS: &str = "tokio::process";
pub const API_TOKIO_TIME_SLEEP: &str = "tokio::time::sleep";
pub const API_TOKIO_TIME_TIMEOUT: &str = "tokio::time::timeout";
pub const API_TOKIO_SPAWN: &str = "tokio::spawn";

#[derive(Debug, Clone)]
pub struct AmbientAuthorityConfig {
    pub repo_root: PathBuf,
    pub target_roots: Vec<PathBuf>,
    pub allowlist_path: PathBuf,
}

impl AmbientAuthorityConfig {
    #[must_use]
    pub fn for_repo(repo_root: impl Into<PathBuf>) -> Self {
        let repo_root = repo_root.into();
        Self {
            target_roots: vec![
                repo_root.join("crates/franken-node/src/connector"),
                repo_root.join("crates/franken-node/src/conformance"),
            ],
            allowlist_path: repo_root.join("docs/specs/ambient_authority_allowlist.toml"),
            repo_root,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbientAuthorityReport {
    pub generated_on: String,
    pub findings: Vec<FindingRecord>,
    pub violations: Vec<ViolationRecord>,
    pub events: Vec<EventRecord>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingRecord {
    pub module_path: String,
    pub ambient_api: String,
    pub line: usize,
    pub callsite: String,
    pub status: FindingStatus,
    pub allowlist_entry_id: Option<String>,
    pub event_code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ViolationRecord {
    pub module_path: String,
    pub ambient_api: String,
    pub line: usize,
    pub callsite: String,
    pub reason: String,
    pub event_code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventRecord {
    pub module_path: String,
    pub ambient_api: Option<String>,
    pub line: Option<usize>,
    pub event_code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub modules_scanned: usize,
    pub findings_total: usize,
    pub violations: usize,
    pub allowlisted: usize,
    pub expired_allowlist: usize,
    pub invalid_allowlist: usize,
    pub clean_modules: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Violation,
    Allowlisted,
    ExpiredAllowlist,
    InvalidAllowlist,
}

#[derive(Debug)]
pub enum GateError {
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Toml(err) => write!(f, "allowlist parse error: {err}"),
        }
    }
}

impl std::error::Error for GateError {}

impl From<std::io::Error> for GateError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for GateError {
    fn from(value: toml::de::Error) -> Self {
        Self::Toml(value)
    }
}

type AllowlistIndex = BTreeMap<(String, String), Vec<AllowlistEntry>>;

pub fn run_gate(
    config: &AmbientAuthorityConfig,
    today: NaiveDate,
) -> Result<AmbientAuthorityReport, GateError> {
    let allowlist = load_allowlist_index(&config.allowlist_path)?;
    let modules = discover_modules(&config.target_roots)?;

    let mut findings = Vec::new();
    let mut violations = Vec::new();
    let mut events = Vec::new();
    let mut clean_modules = 0usize;

    for module_path in &modules {
        let module_rel = make_module_path(&config.repo_root, module_path);
        let source = std::fs::read_to_string(module_path)?;
        let aliases = collect_alias_bindings(&source);
        let module_findings = detect_findings(&source, &aliases);

        if module_findings.is_empty() {
            clean_modules += 1;
            events.push(EventRecord {
                module_path: module_rel,
                ambient_api: None,
                line: None,
                event_code: EVENT_MODULE_CLEAN.to_string(),
                message: "module contains no ambient-authority calls".to_string(),
            });
            continue;
        }

        for raw in module_findings {
            let classified = classify_finding(&module_rel, &raw, &allowlist, today);
            let event_code = classified.event_code.to_string();
            let status = classified.status;
            let reason = classified.reason.clone();
            let allowlist_entry_id = classified.allowlist_entry_id.clone();

            findings.push(FindingRecord {
                module_path: module_rel.clone(),
                ambient_api: raw.ambient_api.clone(),
                line: raw.line,
                callsite: raw.callsite.clone(),
                status,
                allowlist_entry_id: allowlist_entry_id.clone(),
                event_code: event_code.clone(),
            });

            events.push(EventRecord {
                module_path: module_rel.clone(),
                ambient_api: Some(raw.ambient_api.clone()),
                line: Some(raw.line),
                event_code: event_code.clone(),
                message: reason.clone(),
            });

            if matches!(
                status,
                FindingStatus::Violation
                    | FindingStatus::ExpiredAllowlist
                    | FindingStatus::InvalidAllowlist
            ) {
                violations.push(ViolationRecord {
                    module_path: module_rel.clone(),
                    ambient_api: raw.ambient_api.clone(),
                    line: raw.line,
                    callsite: raw.callsite,
                    reason,
                    event_code,
                });
            }
        }
    }

    findings.sort_by(|a, b| {
        a.module_path
            .cmp(&b.module_path)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.ambient_api.cmp(&b.ambient_api))
    });
    violations.sort_by(|a, b| {
        a.module_path
            .cmp(&b.module_path)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.ambient_api.cmp(&b.ambient_api))
    });
    events.sort_by(|a, b| {
        a.module_path
            .cmp(&b.module_path)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.event_code.cmp(&b.event_code))
    });

    let summary = Summary {
        modules_scanned: modules.len(),
        findings_total: findings.len(),
        violations: violations.len(),
        allowlisted: findings
            .iter()
            .filter(|item| matches!(item.status, FindingStatus::Allowlisted))
            .count(),
        expired_allowlist: findings
            .iter()
            .filter(|item| matches!(item.status, FindingStatus::ExpiredAllowlist))
            .count(),
        invalid_allowlist: findings
            .iter()
            .filter(|item| matches!(item.status, FindingStatus::InvalidAllowlist))
            .count(),
        clean_modules,
    };

    Ok(AmbientAuthorityReport {
        generated_on: today.to_string(),
        findings,
        violations,
        events,
        summary,
    })
}

pub fn write_findings_json(
    report: &AmbientAuthorityReport,
    output_path: &Path,
) -> Result<(), GateError> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(report).map_err(std::io::Error::other)?;
    std::fs::write(output_path, json)?;
    Ok(())
}

#[must_use]
pub fn compute_allowlist_signature(
    module_path: &str,
    ambient_api: &str,
    justification: &str,
    signer: &str,
    expires_on: &str,
) -> String {
    let payload = format!("{module_path}\n{ambient_api}\n{justification}\n{signer}\n{expires_on}");
    let mut hasher = Sha256::new();
    hasher.update(b"ambient_authority_signature_v1:");
    hasher.update(payload.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

#[derive(Debug, Clone)]
struct ClassifiedFinding {
    status: FindingStatus,
    event_code: &'static str,
    reason: String,
    allowlist_entry_id: Option<String>,
}

fn classify_finding(
    module_path: &str,
    raw: &RawFinding,
    allowlist: &AllowlistIndex,
    today: NaiveDate,
) -> ClassifiedFinding {
    let key = (module_path.to_string(), raw.ambient_api.clone());

    let Some(entries) = allowlist.get(&key) else {
        return ClassifiedFinding {
            status: FindingStatus::Violation,
            event_code: EVENT_VIOLATION,
            reason: "ambient authority API usage without allowlist entry".to_string(),
            allowlist_entry_id: None,
        };
    };

    let mut first_expired: Option<(String, String)> = None;
    let mut first_invalid: Option<(String, String)> = None;

    for entry in entries {
        match validate_allowlist_entry(entry, today) {
            AllowlistEntryStatus::Valid => {
                return ClassifiedFinding {
                    status: FindingStatus::Allowlisted,
                    event_code: EVENT_ALLOWLISTED,
                    reason: format!("allowlist exception {} applied", entry.id),
                    allowlist_entry_id: Some(entry.id.clone()),
                };
            }
            AllowlistEntryStatus::Expired(expiry) => {
                if first_expired.is_none() {
                    first_expired = Some((entry.id.clone(), expiry));
                }
            }
            AllowlistEntryStatus::InvalidDate(value) => {
                if first_invalid.is_none() {
                    first_invalid =
                        Some((entry.id.clone(), format!("invalid expiry date '{value}'")));
                }
            }
            AllowlistEntryStatus::InvalidSignature => {
                if first_invalid.is_none() {
                    first_invalid = Some((entry.id.clone(), "invalid signature".to_string()));
                }
            }
        }
    }

    if let Some((entry_id, expiry)) = first_expired {
        return ClassifiedFinding {
            status: FindingStatus::ExpiredAllowlist,
            event_code: EVENT_ALLOWLIST_INVALID,
            reason: format!("allowlist entry {entry_id} expired on {expiry}"),
            allowlist_entry_id: Some(entry_id),
        };
    }

    if let Some((entry_id, detail)) = first_invalid {
        return ClassifiedFinding {
            status: FindingStatus::InvalidAllowlist,
            event_code: EVENT_ALLOWLIST_INVALID,
            reason: format!("allowlist entry {entry_id} is invalid: {detail}"),
            allowlist_entry_id: Some(entry_id),
        };
    }

    ClassifiedFinding {
        status: FindingStatus::Violation,
        event_code: EVENT_VIOLATION,
        reason: "ambient authority API usage without valid allowlist entry".to_string(),
        allowlist_entry_id: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InvocationKind {
    Path,
    Function,
    PathOrFunction,
}

#[derive(Debug, Clone)]
struct AliasBinding {
    alias: String,
    ambient_api: String,
    invocation: InvocationKind,
}

#[derive(Debug, Clone)]
struct RawFinding {
    line: usize,
    ambient_api: String,
    callsite: String,
}

fn detect_findings(source: &str, aliases: &[AliasBinding]) -> Vec<RawFinding> {
    let mut findings = Vec::new();
    let mut in_block_comment = false;

    for (idx, raw_line) in source.lines().enumerate() {
        let line = idx + 1;
        let stripped = strip_comments(raw_line, &mut in_block_comment);
        if stripped.trim().is_empty() {
            continue;
        }
        if stripped.trim_start().starts_with("use ") {
            continue;
        }

        let compact: String = stripped.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.is_empty() {
            continue;
        }
        let mut apis = BTreeSet::new();

        if contains_path_usage(&compact, "std::net::") {
            apis.insert(API_STD_NET.to_string());
        }
        if contains_path_usage(&compact, "tokio::net::") {
            apis.insert(API_TOKIO_NET.to_string());
        }
        if contains_path_usage(&compact, "std::process::Command::") {
            apis.insert(API_STD_PROCESS_COMMAND.to_string());
        }
        if contains_path_usage(&compact, "tokio::process::") {
            apis.insert(API_TOKIO_PROCESS.to_string());
        }
        if contains_path_usage(&compact, "std::fs::") {
            apis.insert(API_STD_FS.to_string());
        }
        if contains_path_usage(&compact, "std::time::Instant::") {
            apis.insert(API_STD_TIME_INSTANT.to_string());
        }
        if contains_path_usage(&compact, "std::time::SystemTime::") {
            apis.insert(API_STD_TIME_SYSTEM_TIME.to_string());
        }
        if contains_call_usage(&compact, "tokio::time::sleep")
            && !has_cx_argument(&compact, "tokio::time::sleep")
        {
            apis.insert(API_TOKIO_TIME_SLEEP.to_string());
        }
        if contains_call_usage(&compact, "tokio::time::timeout")
            && !has_cx_argument(&compact, "tokio::time::timeout")
        {
            apis.insert(API_TOKIO_TIME_TIMEOUT.to_string());
        }
        if contains_call_usage(&compact, "tokio::spawn") {
            apis.insert(API_TOKIO_SPAWN.to_string());
        }

        for alias in aliases {
            match alias.invocation {
                InvocationKind::Path => {
                    let token = format!("{}::", alias.alias);
                    if contains_path_usage(&compact, &token) {
                        apis.insert(alias.ambient_api.clone());
                    }
                }
                InvocationKind::Function => {
                    if contains_call_usage(&compact, &alias.alias) {
                        if (alias.ambient_api == API_TOKIO_TIME_SLEEP
                            || alias.ambient_api == API_TOKIO_TIME_TIMEOUT)
                            && has_cx_argument(&compact, &alias.alias)
                        {
                            continue;
                        }
                        apis.insert(alias.ambient_api.clone());
                    }
                }
                InvocationKind::PathOrFunction => {
                    let path_token = format!("{}::", alias.alias);
                    if contains_path_usage(&compact, &path_token)
                        || contains_call_usage(&compact, &alias.alias)
                    {
                        apis.insert(alias.ambient_api.clone());
                    }
                }
            }
        }

        if apis.is_empty() {
            continue;
        }

        let callsite = raw_line.trim().to_string();
        for ambient_api in apis {
            findings.push(RawFinding {
                line,
                ambient_api,
                callsite: callsite.clone(),
            });
        }
    }

    findings.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then_with(|| a.ambient_api.cmp(&b.ambient_api))
    });
    findings
}

fn contains_path_usage(compact_line: &str, token: &str) -> bool {
    contains_token(compact_line, token)
}

fn contains_call_usage(compact_line: &str, callee: &str) -> bool {
    let token = format!("{callee}(");
    contains_token(compact_line, &token)
}

fn contains_token(haystack: &str, token: &str) -> bool {
    for (idx, _) in haystack.match_indices(token) {
        if idx == 0 {
            return true;
        }
        let prev = haystack.as_bytes()[idx - 1];
        if !is_identifier_byte(prev) && prev != b'.' {
            return true;
        }
    }
    false
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn has_cx_argument(compact_line: &str, callee: &str) -> bool {
    let token = format!("{callee}(");
    let Some(start) = compact_line.find(&token) else {
        return false;
    };
    let args_start = start + token.len();
    let Some(close_offset) = compact_line[args_start..].find(')') else {
        return false;
    };
    let args = &compact_line[args_start..args_start + close_offset];
    args.to_ascii_lowercase().contains("cx")
}

fn strip_comments(line: &str, in_block_comment: &mut bool) -> String {
    let mut out = String::new();
    let bytes = line.as_bytes();
    let mut idx = 0usize;

    while idx < bytes.len() {
        if *in_block_comment {
            if idx + 1 < bytes.len() && bytes[idx] == b'*' && bytes[idx + 1] == b'/' {
                *in_block_comment = false;
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }

        if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'/' {
            break;
        }

        if idx + 1 < bytes.len() && bytes[idx] == b'/' && bytes[idx + 1] == b'*' {
            *in_block_comment = true;
            idx += 2;
            continue;
        }

        out.push(char::from(bytes[idx]));
        idx += 1;
    }

    out
}

fn collect_alias_bindings(source: &str) -> Vec<AliasBinding> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for line in source.lines() {
        for import in parse_use_line(line) {
            let Some((ambient_api, invocation)) = path_to_ambient_api(&import.path) else {
                continue;
            };
            let binding = AliasBinding {
                alias: import.alias,
                ambient_api: ambient_api.to_string(),
                invocation,
            };
            let key = (
                binding.alias.clone(),
                binding.ambient_api.clone(),
                binding.invocation,
            );
            if seen.insert(key) {
                out.push(binding);
            }
        }
    }
    out
}

#[derive(Debug, Clone)]
struct ImportedSymbol {
    path: String,
    alias: String,
}

fn parse_use_line(line: &str) -> Vec<ImportedSymbol> {
    let trimmed = line.trim();
    if !trimmed.starts_with("use ") || !trimmed.ends_with(';') {
        return Vec::new();
    }

    let body = trimmed
        .trim_start_matches("use ")
        .trim_end_matches(';')
        .trim();
    if let Some((prefix, remainder)) = body.split_once("::{")
        && let Some(inner) = remainder.strip_suffix('}')
    {
        return split_import_items(inner)
            .into_iter()
            .filter_map(|item| parse_import_item(prefix, item))
            .collect();
    }

    parse_import_item("", body).into_iter().collect()
}

fn split_import_items(inner: &str) -> Vec<&str> {
    inner
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect()
}

fn parse_import_item(prefix: &str, item: &str) -> Option<ImportedSymbol> {
    let (path_part, alias_part) = if let Some((path, alias)) = item.split_once(" as ") {
        (path.trim(), alias.trim())
    } else {
        (item.trim(), "")
    };

    if path_part.is_empty() {
        return None;
    }

    let full_path = if prefix.is_empty() {
        path_part.to_string()
    } else {
        format!("{prefix}::{path_part}")
    };

    if full_path.ends_with("::*") {
        return None;
    }

    let alias = if alias_part.is_empty() {
        full_path
            .rsplit("::")
            .next()
            .unwrap_or_default()
            .to_string()
    } else {
        alias_part.to_string()
    };

    Some(ImportedSymbol {
        path: full_path,
        alias,
    })
}

fn path_to_ambient_api(path: &str) -> Option<(&'static str, InvocationKind)> {
    if path == "std::net" || path.starts_with("std::net::") {
        return Some((API_STD_NET, InvocationKind::Path));
    }
    if path == "std::process::Command" {
        return Some((API_STD_PROCESS_COMMAND, InvocationKind::Path));
    }
    if path == "std::time::Instant" {
        return Some((API_STD_TIME_INSTANT, InvocationKind::Path));
    }
    if path == "std::time::SystemTime" {
        return Some((API_STD_TIME_SYSTEM_TIME, InvocationKind::Path));
    }
    if path == "std::fs" {
        return Some((API_STD_FS, InvocationKind::Path));
    }
    if path.starts_with("std::fs::") {
        return Some((API_STD_FS, InvocationKind::PathOrFunction));
    }
    if path == "tokio::net" || path.starts_with("tokio::net::") {
        return Some((API_TOKIO_NET, InvocationKind::Path));
    }
    if path == "tokio::process" || path.starts_with("tokio::process::") {
        return Some((API_TOKIO_PROCESS, InvocationKind::Path));
    }
    if path == "tokio::time::sleep" {
        return Some((API_TOKIO_TIME_SLEEP, InvocationKind::Function));
    }
    if path == "tokio::time::timeout" {
        return Some((API_TOKIO_TIME_TIMEOUT, InvocationKind::Function));
    }
    if path == "tokio::spawn" {
        return Some((API_TOKIO_SPAWN, InvocationKind::Function));
    }
    None
}

fn discover_modules(target_roots: &[PathBuf]) -> Result<Vec<PathBuf>, GateError> {
    let mut out = Vec::new();
    for root in target_roots {
        collect_rust_files(root, &mut out)?;
    }
    out.sort();
    Ok(out)
}

fn collect_rust_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), GateError> {
    if !root.exists() {
        return Ok(());
    }

    let mut entries = std::fs::read_dir(root)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(GateError::from)?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }

    Ok(())
}

fn make_module_path(repo_root: &Path, full_path: &Path) -> String {
    if let Ok(stripped) = full_path.strip_prefix(repo_root) {
        return stripped.to_string_lossy().replace('\\', "/");
    }
    full_path.to_string_lossy().replace('\\', "/")
}

fn load_allowlist_index(path: &Path) -> Result<AllowlistIndex, GateError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = std::fs::read_to_string(path)?;
    let file: AllowlistFile = toml::from_str(&raw)?;
    let mut out = BTreeMap::new();
    for exception in file.exceptions {
        let key = (exception.module_path.clone(), exception.ambient_api.clone());
        out.entry(key).or_insert_with(Vec::new).push(exception);
    }
    Ok(out)
}

#[derive(Debug, Clone, Deserialize)]
struct AllowlistFile {
    #[serde(default)]
    exceptions: Vec<AllowlistEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct AllowlistEntry {
    id: String,
    module_path: String,
    ambient_api: String,
    justification: String,
    signer: String,
    expires_on: String,
    signature: String,
}

enum AllowlistEntryStatus {
    Valid,
    Expired(String),
    InvalidDate(String),
    InvalidSignature,
}

fn validate_allowlist_entry(entry: &AllowlistEntry, today: NaiveDate) -> AllowlistEntryStatus {
    let expected = compute_allowlist_signature(
        &entry.module_path,
        &entry.ambient_api,
        &entry.justification,
        &entry.signer,
        &entry.expires_on,
    );
    if entry.signature != expected {
        return AllowlistEntryStatus::InvalidSignature;
    }

    let Ok(expiry) = NaiveDate::parse_from_str(&entry.expires_on, "%Y-%m-%d") else {
        return AllowlistEntryStatus::InvalidDate(entry.expires_on.clone());
    };

    if today > expiry {
        return AllowlistEntryStatus::Expired(expiry.to_string());
    }

    AllowlistEntryStatus::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use tempfile::TempDir;

    fn setup_repo(files: &[(&str, &str)], allowlist: &str) -> (TempDir, AmbientAuthorityConfig) {
        let temp = tempfile::tempdir().expect("tempdir");

        for (path, body) in files {
            let full_path = temp.path().join(path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).expect("mkdir");
            }
            std::fs::write(&full_path, body).expect("write fixture");
        }

        let allowlist_path = temp
            .path()
            .join("docs/specs/ambient_authority_allowlist.toml");
        if let Some(parent) = allowlist_path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir allowlist");
        }
        std::fs::write(&allowlist_path, allowlist).expect("write allowlist");

        let config = AmbientAuthorityConfig {
            repo_root: temp.path().to_path_buf(),
            target_roots: vec![temp.path().join("crates/franken-node/src/connector")],
            allowlist_path,
        };

        (temp, config)
    }

    #[test]
    fn detects_fully_qualified_std_net_usage() {
        let (_tmp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub fn call(addr: &str) {\n    let _ = std::net::TcpStream::connect(addr);\n}\n",
            )],
            "exceptions = []\n",
        );

        let report = run_gate(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("gate runs");
        assert_eq!(report.summary.violations, 1);
        assert_eq!(report.violations[0].event_code, EVENT_VIOLATION);
        assert_eq!(report.violations[0].ambient_api, API_STD_NET);
    }

    #[test]
    fn allows_signed_non_expired_exception() {
        let module = "crates/franken-node/src/connector/sample.rs";
        let api = API_STD_FS;
        let justification = "temporary fs bridge";
        let signer = "GateTester";
        let expires = "2099-12-31";
        let sig = compute_allowlist_signature(module, api, justification, signer, expires);
        let allowlist = format!(
            "[[exceptions]]\n\
             id = \"AAL-001\"\n\
             module_path = \"{module}\"\n\
             ambient_api = \"{api}\"\n\
             justification = \"{justification}\"\n\
             signer = \"{signer}\"\n\
             expires_on = \"{expires}\"\n\
             signature = \"{sig}\"\n"
        );

        let (_tmp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub fn persist(path: &std::path::Path, body: &str) {\n    let _ = std::fs::write(path, body);\n}\n",
            )],
            &allowlist,
        );

        let report = run_gate(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("gate runs");
        assert_eq!(report.summary.violations, 0);
        assert_eq!(report.summary.allowlisted, 1);
        assert_eq!(report.findings[0].event_code, EVENT_ALLOWLISTED);
    }

    #[test]
    fn expired_exception_is_a_violation() {
        let module = "crates/franken-node/src/connector/sample.rs";
        let api = API_STD_TIME_SYSTEM_TIME;
        let justification = "legacy time source";
        let signer = "GateTester";
        let expires = "2026-01-01";
        let sig = compute_allowlist_signature(module, api, justification, signer, expires);
        let allowlist = format!(
            "[[exceptions]]\n\
             id = \"AAL-002\"\n\
             module_path = \"{module}\"\n\
             ambient_api = \"{api}\"\n\
             justification = \"{justification}\"\n\
             signer = \"{signer}\"\n\
             expires_on = \"{expires}\"\n\
             signature = \"{sig}\"\n"
        );

        let (_tmp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub fn now() -> u64 {\n    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()\n}\n",
            )],
            &allowlist,
        );

        let report = run_gate(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("gate runs");
        assert_eq!(report.summary.violations, 1);
        assert_eq!(report.summary.expired_allowlist, 1);
        assert_eq!(report.violations[0].event_code, EVENT_ALLOWLIST_INVALID);
    }

    #[test]
    fn invalid_signature_is_a_violation() {
        let allowlist = "[[exceptions]]\n\
             id = \"AAL-003\"\n\
             module_path = \"crates/franken-node/src/connector/sample.rs\"\n\
             ambient_api = \"std::process::Command\"\n\
             justification = \"legacy shell wrapper\"\n\
             signer = \"GateTester\"\n\
             expires_on = \"2099-12-31\"\n\
             signature = \"sha256:deadbeef\"\n";

        let (_tmp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "use std::process::Command;\n\
                 pub fn run() {\n    let _ = Command::new(\"echo\").arg(\"ok\");\n}\n",
            )],
            allowlist,
        );

        let report = run_gate(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("gate runs");
        assert_eq!(report.summary.violations, 1);
        assert_eq!(report.summary.invalid_allowlist, 1);
        assert_eq!(report.violations[0].event_code, EVENT_ALLOWLIST_INVALID);
    }

    #[test]
    fn detects_alias_usage_and_ignores_comment_lookalikes() {
        let (_tmp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "use std::process::Command as Cmd;\n\
                 // Cmd::new(\"rm\");\n\
                 pub fn run() {\n    let _ = Cmd::new(\"echo\").arg(\"ok\");\n}\n",
            )],
            "exceptions = []\n",
        );

        let report = run_gate(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("gate runs");
        assert_eq!(report.summary.violations, 1);
        assert_eq!(report.violations[0].ambient_api, API_STD_PROCESS_COMMAND);
    }

    #[test]
    fn marks_clean_module_with_amb_001_event() {
        let (_tmp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub fn stable_math(a: u64, b: u64) -> u64 {\n    a.saturating_add(b)\n}\n",
            )],
            "exceptions = []\n",
        );

        let report = run_gate(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("gate runs");
        assert_eq!(report.summary.findings_total, 0);
        assert_eq!(report.summary.violations, 0);
        assert_eq!(report.summary.clean_modules, 1);
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].event_code, EVENT_MODULE_CLEAN);
    }

    #[test]
    fn detects_tokio_spawn_without_allowlist() {
        let (_tmp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub async fn launch() {\n    let _handle = tokio::spawn(async move {\n        42usize\n    });\n}\n",
            )],
            "exceptions = []\n",
        );

        let report = run_gate(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("gate runs");
        assert_eq!(report.summary.violations, 1);
        assert_eq!(report.summary.allowlisted, 0);
        assert_eq!(report.violations[0].ambient_api, API_TOKIO_SPAWN);
        assert_eq!(report.violations[0].event_code, EVENT_VIOLATION);
    }

    #[test]
    fn cx_bound_timeout_call_is_not_flagged() {
        let (_tmp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub async fn wait(cx: &Cx) {\n    let _ = tokio::time::timeout(cx.deadline(), async { 1usize }).await;\n}\n",
            )],
            "exceptions = []\n",
        );

        let report = run_gate(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("gate runs");
        assert_eq!(report.summary.findings_total, 0);
        assert_eq!(report.summary.violations, 0);
        assert_eq!(report.summary.clean_modules, 1);
    }

    #[test]
    fn timeout_without_cx_context_is_flagged() {
        let (_tmp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub async fn wait() {\n    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async { 1usize }).await;\n}\n",
            )],
            "exceptions = []\n",
        );

        let report = run_gate(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("gate runs");
        assert_eq!(report.summary.violations, 1);
        assert_eq!(report.summary.allowlisted, 0);
        assert_eq!(report.violations[0].ambient_api, API_TOKIO_TIME_TIMEOUT);
        assert_eq!(report.violations[0].event_code, EVENT_VIOLATION);
    }

    #[test]
    fn forged_tokio_spawn_allowlist_signature_is_rejected() {
        let allowlist = "[[exceptions]]\n\
             id = \"AAL-004\"\n\
             module_path = \"crates/franken-node/src/connector/sample.rs\"\n\
             ambient_api = \"tokio::spawn\"\n\
             justification = \"legacy scheduler bridge\"\n\
             signer = \"GateTester\"\n\
             expires_on = \"2099-12-31\"\n\
             signature = \"sha256:forged\"\n";

        let (_tmp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub async fn launch() {\n    let _h = tokio::spawn(async move { 1usize });\n}\n",
            )],
            allowlist,
        );

        let report = run_gate(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("gate runs");
        assert_eq!(report.summary.violations, 1);
        assert_eq!(report.summary.invalid_allowlist, 1);
        assert_eq!(report.violations[0].ambient_api, API_TOKIO_SPAWN);
        assert_eq!(report.violations[0].event_code, EVENT_ALLOWLIST_INVALID);
    }
}
