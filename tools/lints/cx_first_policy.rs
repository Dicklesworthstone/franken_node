#![allow(clippy::module_name_repetitions)]

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use syn::{FnArg, ImplItem, Item, Pat, Type, Visibility};

const EVENT_PASS: &str = "CXF-001";
const EVENT_FAIL: &str = "CXF-002";
const EVENT_EXCEPTION: &str = "CXF-003";
const EVENT_EXCEPTION_EXPIRED: &str = "CXF-004";

const PATTERN_NO_RETURN: &str = "pub async fn $NAME($$$ARGS) { $$$BODY }";
const PATTERN_WITH_RETURN: &str = "pub async fn $NAME($$$ARGS) -> $RET { $$$BODY }";

#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub repo_root: PathBuf,
    pub target_roots: Vec<PathBuf>,
    pub allowlist_path: PathBuf,
    pub ast_grep_bin: String,
}

impl PolicyConfig {
    #[must_use]
    pub fn for_repo(repo_root: impl Into<PathBuf>) -> Self {
        let repo_root = repo_root.into();
        Self {
            target_roots: vec![
                repo_root.join("crates/franken-node/src/connector"),
                repo_root.join("crates/franken-node/src/conformance"),
            ],
            allowlist_path: repo_root.join("tools/lints/cx_first_allowlist.toml"),
            repo_root,
            ast_grep_bin: "ast-grep".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LintReport {
    pub generated_on: String,
    pub checks: Vec<CheckRecord>,
    pub violations: Vec<ViolationRecord>,
    pub events: Vec<EventRecord>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total_functions: usize,
    pub compliant_functions: usize,
    pub violations: usize,
    pub exceptions_applied: usize,
    pub expired_exceptions: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckRecord {
    pub module_path: String,
    pub function_name: String,
    pub function_path: String,
    pub first_argument: Option<String>,
    pub has_cx_first: bool,
    pub exception_status: ExceptionStatus,
    pub exception_expiry: Option<String>,
    pub event_code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ViolationRecord {
    pub module_path: String,
    pub function_name: String,
    pub function_path: String,
    pub reason: String,
    pub event_code: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventRecord {
    pub event_code: String,
    pub function_path: String,
    pub module_path: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionStatus {
    None,
    Applied,
    Expired,
}

#[derive(Debug)]
pub enum PolicyError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Toml(toml::de::Error),
    AstGrepFailed(String),
    MissingMeta(&'static str),
    InvalidAllowlistDate {
        function_path: String,
        value: String,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Json(err) => write!(f, "json parse error: {err}"),
            Self::Toml(err) => write!(f, "allowlist parse error: {err}"),
            Self::AstGrepFailed(msg) => write!(f, "ast-grep failed: {msg}"),
            Self::MissingMeta(field) => {
                write!(f, "missing required ast-grep meta variable: {field}")
            }
            Self::InvalidAllowlistDate {
                function_path,
                value,
            } => write!(
                f,
                "invalid allowlist expiry date '{value}' for {function_path}; expected YYYY-MM-DD"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<std::io::Error> for PolicyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for PolicyError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<toml::de::Error> for PolicyError {
    fn from(value: toml::de::Error) -> Self {
        Self::Toml(value)
    }
}

pub fn run_policy(config: &PolicyConfig, today: NaiveDate) -> Result<LintReport, PolicyError> {
    let allowlist = load_allowlist(&config.allowlist_path)?;

    let mut raw_matches = run_pattern(config, PATTERN_NO_RETURN)?;
    raw_matches.extend(run_pattern(config, PATTERN_WITH_RETURN)?);

    let mut unique = BTreeSet::new();
    let mut checks = Vec::new();
    let mut events = Vec::new();
    let mut violations = Vec::new();

    for item in raw_matches {
        let function_name = item
            .meta_variables
            .single
            .get("NAME")
            .ok_or(PolicyError::MissingMeta("NAME"))?
            .text
            .clone();
        let module_path = make_module_path(&config.repo_root, &item.file);
        let unique_key = format!("{module_path}::{function_name}::{}", item.range.start.line);
        if !unique.insert(unique_key) {
            continue;
        }

        let function_path = format!("{module_path}::{function_name}");
        let args = item
            .meta_variables
            .multi
            .get("ARGS")
            .cloned()
            .unwrap_or_default();
        let first_argument = first_non_separator_argument(&args);
        let has_cx_first = first_argument
            .as_deref()
            .map(is_cx_first_argument)
            .unwrap_or(false);

        let (exception_status, exception_expiry, event_code, violation_reason) = if has_cx_first {
            (ExceptionStatus::None, None, EVENT_PASS.to_string(), None)
        } else if let Some(exception) = allowlist.get(&function_path) {
            let expiry =
                NaiveDate::parse_from_str(&exception.expires_on, "%Y-%m-%d").map_err(|_| {
                    PolicyError::InvalidAllowlistDate {
                        function_path: function_path.clone(),
                        value: exception.expires_on.clone(),
                    }
                })?;
            if today > expiry {
                (
                    ExceptionStatus::Expired,
                    Some(expiry.to_string()),
                    EVENT_EXCEPTION_EXPIRED.to_string(),
                    Some(format!(
                        "allowlist exception expired on {expiry} ({})",
                        exception.reason
                    )),
                )
            } else {
                (
                    ExceptionStatus::Applied,
                    Some(expiry.to_string()),
                    EVENT_EXCEPTION.to_string(),
                    None,
                )
            }
        } else {
            (
                ExceptionStatus::None,
                None,
                EVENT_FAIL.to_string(),
                Some("missing &Cx/&mut Cx as first parameter".to_string()),
            )
        };

        if let Some(reason) = violation_reason {
            violations.push(ViolationRecord {
                module_path: module_path.clone(),
                function_name: function_name.clone(),
                function_path: function_path.clone(),
                reason: reason.clone(),
                event_code: event_code.clone(),
            });
            events.push(EventRecord {
                event_code: event_code.clone(),
                function_path: function_path.clone(),
                module_path: module_path.clone(),
                message: reason,
            });
        } else {
            let message = match exception_status {
                ExceptionStatus::None => "Cx-first signature check passed".to_string(),
                ExceptionStatus::Applied => {
                    format!(
                        "allowlist exception applied until {}",
                        exception_expiry.clone().unwrap_or_default()
                    )
                }
                ExceptionStatus::Expired => {
                    "expired exception should never be non-violating".to_string()
                }
            };
            events.push(EventRecord {
                event_code: event_code.clone(),
                function_path: function_path.clone(),
                module_path: module_path.clone(),
                message,
            });
        }

        checks.push(CheckRecord {
            module_path,
            function_name,
            function_path,
            first_argument,
            has_cx_first,
            exception_status,
            exception_expiry,
            event_code,
        });
    }

    checks.sort_by(|a, b| {
        a.module_path
            .cmp(&b.module_path)
            .then_with(|| a.function_name.cmp(&b.function_name))
    });
    violations.sort_by(|a, b| {
        a.module_path
            .cmp(&b.module_path)
            .then_with(|| a.function_name.cmp(&b.function_name))
    });

    let summary = Summary {
        total_functions: checks.len(),
        compliant_functions: checks.iter().filter(|c| c.has_cx_first).count(),
        violations: violations.len(),
        exceptions_applied: checks
            .iter()
            .filter(|c| matches!(c.exception_status, ExceptionStatus::Applied))
            .count(),
        expired_exceptions: checks
            .iter()
            .filter(|c| matches!(c.exception_status, ExceptionStatus::Expired))
            .count(),
    };

    Ok(LintReport {
        generated_on: today.to_string(),
        checks,
        violations,
        events,
        summary,
    })
}

pub fn write_compliance_csv(report: &LintReport, output_path: &Path) -> Result<(), PolicyError> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut out =
        String::from("module_path,function_name,has_cx_first,exception_status,exception_expiry\n");
    for check in &report.checks {
        let status = match check.exception_status {
            ExceptionStatus::None => "none",
            ExceptionStatus::Applied => "applied",
            ExceptionStatus::Expired => "expired",
        };
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            check.module_path,
            check.function_name,
            check.has_cx_first,
            status,
            check.exception_expiry.clone().unwrap_or_default(),
        ));
    }
    std::fs::write(output_path, out)?;
    Ok(())
}

fn make_module_path(repo_root: &Path, full_path: &str) -> String {
    let path = Path::new(full_path);
    if let Ok(stripped) = path.strip_prefix(repo_root) {
        return stripped.to_string_lossy().replace('\\', "/");
    }
    path.to_string_lossy().replace('\\', "/")
}

fn first_non_separator_argument(args: &[AstSnippet]) -> Option<String> {
    args.iter()
        .map(|arg| arg.text.trim())
        .find(|value| !value.is_empty() && *value != ",")
        .map(ToString::to_string)
}

fn is_cx_first_argument(arg: &str) -> bool {
    let Some((_, ty)) = arg.split_once(':') else {
        return false;
    };
    let condensed: String = ty.chars().filter(|c| !c.is_whitespace()).collect();
    matches_cx_reference(&condensed)
}

fn matches_cx_reference(ty: &str) -> bool {
    let Some(mut rest) = ty.strip_prefix('&') else {
        return false;
    };

    if let Some(without_tick) = rest.strip_prefix('\'') {
        let mut split_idx = None;
        for (idx, ch) in without_tick.char_indices() {
            if !(ch.is_ascii_alphanumeric() || ch == '_') {
                split_idx = Some(idx);
                break;
            }
        }
        rest = if let Some(idx) = split_idx {
            without_tick[idx..].trim_start()
        } else {
            ""
        };
    }

    if let Some(without_mut) = rest.strip_prefix("mut") {
        rest = without_mut;
    }

    rest == "Cx"
}

fn run_pattern(config: &PolicyConfig, pattern: &str) -> Result<Vec<AstMatch>, PolicyError> {
    match run_pattern_with_ast_grep(config, pattern) {
        Ok(matches) => Ok(matches),
        Err(PolicyError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            // rch workers may not have ast-grep installed. Fall back to a
            // native syn-based AST walk to preserve gate determinism.
            run_pattern_with_syn_fallback(config)
        }
        Err(error) => Err(error),
    }
}

fn run_pattern_with_ast_grep(
    config: &PolicyConfig,
    pattern: &str,
) -> Result<Vec<AstMatch>, PolicyError> {
    let mut cmd = Command::new(&config.ast_grep_bin);
    cmd.args(["run", "-l", "Rust", "-p", pattern, "--json=compact"]);
    for root in &config.target_roots {
        cmd.arg(root);
    }
    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        // ast-grep exits non-zero when no matches found (grep-like behavior);
        // treat empty stderr as "zero matches" rather than a hard error.
        if stderr.trim().is_empty() {
            return Ok(Vec::new());
        }
        return Err(PolicyError::AstGrepFailed(stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<AstMatch>>(&stdout).map_err(PolicyError::from)
}

fn run_pattern_with_syn_fallback(config: &PolicyConfig) -> Result<Vec<AstMatch>, PolicyError> {
    let mut rust_files = Vec::new();
    for root in &config.target_roots {
        collect_rust_files(root, &mut rust_files)?;
    }
    rust_files.sort();

    let mut matches = Vec::new();
    for file in rust_files {
        let source = std::fs::read_to_string(&file)?;
        let parsed = syn::parse_file(&source).map_err(|error| {
            PolicyError::AstGrepFailed(format!(
                "syn fallback parse failed for {}: {error}",
                file.display()
            ))
        })?;
        let file_path = file.to_string_lossy().to_string();
        let mut line_counter = 1usize;
        collect_items_from_module(&parsed.items, &file_path, &mut line_counter, &mut matches);
    }
    Ok(matches)
}

fn collect_rust_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), PolicyError> {
    if !root.exists() {
        return Ok(());
    }
    if root.is_file() {
        if root.extension().is_some_and(|ext| ext == "rs") {
            out.push(root.to_path_buf());
        }
        return Ok(());
    }

    let mut entries = std::fs::read_dir(root)?.collect::<Result<Vec<_>, std::io::Error>>()?;
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

fn collect_items_from_module(
    items: &[Item],
    file_path: &str,
    line_counter: &mut usize,
    out: &mut Vec<AstMatch>,
) {
    for item in items {
        match item {
            Item::Fn(function)
                if visibility_is_public(&function.vis) && function.sig.asyncness.is_some() =>
            {
                push_function_match(
                    function.sig.ident.to_string(),
                    argument_snippets(&function.sig.inputs),
                    file_path,
                    line_counter,
                    out,
                );
            }
            Item::Impl(impl_block) => {
                for impl_item in &impl_block.items {
                    if let ImplItem::Fn(function) = impl_item
                        && visibility_is_public(&function.vis)
                        && function.sig.asyncness.is_some()
                    {
                        push_function_match(
                            function.sig.ident.to_string(),
                            argument_snippets(&function.sig.inputs),
                            file_path,
                            line_counter,
                            out,
                        );
                    }
                }
            }
            Item::Mod(module) => {
                if let Some((_, nested_items)) = &module.content {
                    collect_items_from_module(nested_items, file_path, line_counter, out);
                }
            }
            _ => {}
        }
    }
}

fn visibility_is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

fn argument_snippets(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
) -> Vec<AstSnippet> {
    inputs.iter().map(fn_arg_snippet).collect()
}

fn fn_arg_snippet(argument: &FnArg) -> AstSnippet {
    match argument {
        FnArg::Typed(pat_type) => {
            let binding = match &*pat_type.pat {
                Pat::Ident(ident) => ident.ident.to_string(),
                _ => "_arg".to_string(),
            };
            AstSnippet {
                text: format!("{binding}: {}", type_snippet(&pat_type.ty)),
            }
        }
        FnArg::Receiver(receiver) => AstSnippet {
            text: receiver_snippet(receiver),
        },
    }
}

fn receiver_snippet(receiver: &syn::Receiver) -> String {
    let mut text = String::new();
    if receiver.reference.is_some() {
        text.push('&');
    }
    if receiver.mutability.is_some() {
        text.push_str("mut ");
    }
    text.push_str("self");
    text
}

fn type_snippet(ty: &Type) -> String {
    match ty {
        Type::Reference(reference) => {
            let mut text = String::from("&");
            if let Some(lifetime) = &reference.lifetime {
                text.push('\'');
                text.push_str(&lifetime.ident.to_string());
                text.push(' ');
            }
            if reference.mutability.is_some() {
                text.push_str("mut ");
            }
            text.push_str(&type_snippet(&reference.elem));
            text
        }
        Type::Path(path) => path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Type::Paren(inner) => type_snippet(&inner.elem),
        Type::Group(inner) => type_snippet(&inner.elem),
        _ => "Unknown".to_string(),
    }
}

fn push_function_match(
    function_name: String,
    arguments: Vec<AstSnippet>,
    file_path: &str,
    line_counter: &mut usize,
    out: &mut Vec<AstMatch>,
) {
    let mut single = BTreeMap::new();
    single.insert(
        "NAME".to_string(),
        AstSnippet {
            text: function_name,
        },
    );
    let mut multi = BTreeMap::new();
    multi.insert("ARGS".to_string(), arguments);

    out.push(AstMatch {
        file: file_path.to_string(),
        range: AstRange {
            start: Position {
                line: *line_counter,
            },
        },
        meta_variables: MetaVariables { single, multi },
    });
    *line_counter += 1;
}

fn load_allowlist(path: &Path) -> Result<BTreeMap<String, AllowlistException>, PolicyError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = std::fs::read_to_string(path)?;
    let file: AllowlistFile = toml::from_str(&raw)?;
    let mut out = BTreeMap::new();
    for exception in file.exceptions {
        out.insert(exception.function_path.clone(), exception);
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct AllowlistFile {
    #[serde(default)]
    exceptions: Vec<AllowlistException>,
}

#[derive(Debug, Clone, Deserialize)]
struct AllowlistException {
    function_path: String,
    reason: String,
    expires_on: String,
}

#[derive(Debug, Deserialize)]
struct AstMatch {
    file: String,
    range: AstRange,
    #[serde(rename = "metaVariables")]
    meta_variables: MetaVariables,
}

#[derive(Debug, Deserialize)]
struct AstRange {
    start: Position,
}

#[derive(Debug, Deserialize)]
struct Position {
    line: usize,
}

#[derive(Debug, Deserialize)]
struct MetaVariables {
    #[serde(default)]
    single: BTreeMap<String, AstSnippet>,
    #[serde(default)]
    multi: BTreeMap<String, Vec<AstSnippet>>,
}

#[derive(Debug, Clone, Deserialize)]
struct AstSnippet {
    text: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use tempfile::TempDir;

    fn setup_repo(files: &[(&str, &str)], allowlist: &str) -> (TempDir, PolicyConfig) {
        let temp = tempfile::tempdir().expect("tempdir");
        for (path, body) in files {
            let full_path = temp.path().join(path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).expect("mkdir");
            }
            std::fs::write(&full_path, body).expect("write fixture");
        }
        let allowlist_path = temp.path().join("tools/lints/cx_first_allowlist.toml");
        if let Some(parent) = allowlist_path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir allowlist");
        }
        std::fs::write(&allowlist_path, allowlist).expect("write allowlist");

        let config = PolicyConfig {
            repo_root: temp.path().to_path_buf(),
            target_roots: vec![temp.path().join("crates/franken-node/src/connector")],
            allowlist_path,
            ast_grep_bin: "ast-grep".to_string(),
        };
        (temp, config)
    }

    #[test]
    fn catches_missing_cx_first_and_accepts_valid_one() {
        let (_temp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub async fn ok(cx: &Cx) {}\n\
                 pub async fn bad(input: u64, cx: &Cx) -> Result<(), ()> { Ok(()) }\n",
            )],
            "exceptions = []\n",
        );

        let report = run_policy(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("policy runs");
        assert_eq!(report.summary.total_functions, 2);
        assert_eq!(report.summary.compliant_functions, 1);
        assert_eq!(report.summary.violations, 1);
        assert_eq!(report.violations[0].event_code, EVENT_FAIL);
        assert_eq!(
            report.violations[0].reason,
            "missing &Cx/&mut Cx as first parameter"
        );
    }

    #[test]
    fn valid_exception_suppresses_violation() {
        let (_temp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub async fn bad(input: u64) {}\n",
            )],
            "[[exceptions]]\n\
             function_path = \"crates/franken-node/src/connector/sample.rs::bad\"\n\
             reason = \"legacy exception\"\n\
             expires_on = \"2099-12-31\"\n",
        );

        let report = run_policy(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("policy runs");
        assert_eq!(report.summary.violations, 0);
        assert_eq!(report.summary.exceptions_applied, 1);
        assert_eq!(report.checks[0].event_code, EVENT_EXCEPTION);
    }

    #[test]
    fn expired_exception_is_a_hard_violation() {
        let (_temp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub async fn bad(input: u64) {}\n",
            )],
            "[[exceptions]]\n\
             function_path = \"crates/franken-node/src/connector/sample.rs::bad\"\n\
             reason = \"legacy exception\"\n\
             expires_on = \"2026-01-01\"\n",
        );

        let report = run_policy(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("policy runs");
        assert_eq!(report.summary.violations, 1);
        assert_eq!(report.summary.expired_exceptions, 1);
        assert_eq!(report.violations[0].event_code, EVENT_EXCEPTION_EXPIRED);
    }

    #[test]
    fn ast_level_scan_ignores_comment_lookalikes() {
        let (_temp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "// pub async fn fake(cx: &Cx) {}\n\
                 const NOTE: &str = \"pub async fn ghost(cx: &Cx) {}\";\n",
            )],
            "exceptions = []\n",
        );

        let report = run_policy(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("policy runs");
        assert_eq!(report.summary.total_functions, 0);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn writes_expected_csv_shape() {
        let (_temp, config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub async fn ok(cx: &Cx) {}\n",
            )],
            "exceptions = []\n",
        );

        let report = run_policy(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("policy runs");
        let csv_path = config
            .repo_root
            .join("artifacts/10.15/cx_first_compliance.csv");
        write_compliance_csv(&report, &csv_path).expect("csv");
        let csv = std::fs::read_to_string(csv_path).expect("read csv");
        assert!(csv.starts_with(
            "module_path,function_name,has_cx_first,exception_status,exception_expiry\n"
        ));
        assert!(csv.contains("sample.rs,ok,true"));
    }

    #[test]
    fn falls_back_to_syn_when_ast_grep_binary_missing() {
        let (_temp, mut config) = setup_repo(
            &[(
                "crates/franken-node/src/connector/sample.rs",
                "pub async fn ok(cx: &Cx) {}\n\
                 pub async fn bad(value: u64) {}\n",
            )],
            "exceptions = []\n",
        );
        config.ast_grep_bin = "ast-grep-binary-not-installed".to_string();

        let report = run_policy(&config, NaiveDate::from_ymd_opt(2026, 2, 20).expect("date"))
            .expect("policy runs via syn fallback");
        assert_eq!(report.summary.total_functions, 2);
        assert_eq!(report.summary.compliant_functions, 1);
        assert_eq!(report.summary.violations, 1);
    }
}
