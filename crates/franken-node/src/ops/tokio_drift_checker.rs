//! Deterministic guardrails against ambient Tokio/runtime reintroduction and
//! premature API transport-boundary activation.
//!
//! This module scans `frankenengine-node` source surfaces for forbidden
//! async-executor bootstrap patterns. The dead Tokio bootstrap was removed
//! in bd-1now.2; this checker prevents silent reintroduction.
//!
//! # Exception mechanism
//!
//! A source line matching a banned pattern is allowed **only** if the same
//! file contains a structured exception marker on the immediately preceding
//! line:
//!
//! ```text
//! // TOKIO_DRIFT_EXCEPTION(bd-XXXX): <justification>
//! ```
//!
//! The marker must reference a bead ID so the exception is traceable to an
//! architectural decision record. Bare `// TOKIO_DRIFT_EXCEPTION` without
//! a bead reference is rejected.

use std::path::{Path, PathBuf};

/// Patterns that indicate ambient executor / runtime bootstrap.
const BANNED_PATTERNS: &[&str] = &[
    "#[tokio::main]",
    "#[tokio::test]",
    "tokio::runtime::Runtime",
    "tokio::runtime::Builder",
    "tokio::runtime::Handle",
    "Runtime::new()",
    "Builder::new_multi_thread()",
    "Builder::new_current_thread()",
];

/// Import patterns that suggest direct Tokio dependency usage.
const BANNED_IMPORT_PATTERNS: &[&str] = &["use tokio::", "use tokio;", "extern crate tokio"];

/// API-only patterns that indicate the control-plane service has grown a real
/// transport boundary and should re-evaluate deferred request-region work.
const API_TRANSPORT_BOUNDARY_PATTERNS: &[&str] = &[
    "axum::Router",
    "hyper::Server",
    "tonic::transport::Server",
    "std::net::TcpListener::bind(",
    "TcpListener::bind(",
];

/// Structured exception marker prefix. Must be followed by `(bd-XXXX): <text>`.
const EXCEPTION_PREFIX: &str = "// TOKIO_DRIFT_EXCEPTION(";
/// TOML-style exception marker prefix (Cargo.toml uses `#` comments).
const EXCEPTION_PREFIX_TOML: &str = "# TOKIO_DRIFT_EXCEPTION(";

/// A single violation found by the drift checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftViolation {
    pub file: PathBuf,
    pub line_number: usize,
    pub line_content: String,
    pub pattern: String,
    pub reason: &'static str,
}

impl std::fmt::Display for DriftViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: {} [pattern: `{}`]",
            self.file.display(),
            self.line_number,
            self.reason,
            self.pattern,
        )
    }
}

/// Result of a drift check run.
#[derive(Debug, Clone)]
pub struct DriftCheckResult {
    pub violations: Vec<DriftViolation>,
    pub files_scanned: usize,
    pub exceptions_honored: usize,
}

impl DriftCheckResult {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Check whether a line has a valid exception marker on the preceding line.
///
/// A valid marker looks like:
/// `// TOKIO_DRIFT_EXCEPTION(bd-XXXX): justification text here`
///
/// Requirements:
/// - Must start with `// TOKIO_DRIFT_EXCEPTION(`
/// - Must contain a bead reference matching `bd-` followed by alphanumeric/dot chars
/// - Must have a closing `):`
/// - Must have non-empty justification text after `): `
fn is_valid_exception(preceding_line: Option<&str>) -> bool {
    let Some(line) = preceding_line else {
        return false;
    };
    let trimmed = line.trim();
    let Some(rest) = trimmed
        .strip_prefix(EXCEPTION_PREFIX)
        .or_else(|| trimmed.strip_prefix(EXCEPTION_PREFIX_TOML))
    else {
        return false;
    };
    // Must have closing ): with bead ref inside
    let Some(paren_close) = rest.find("): ") else {
        return false;
    };
    let bead_ref = &rest[..paren_close];
    // Bead ref must start with bd- and have at least one more char
    if !bead_ref.starts_with("bd-") || bead_ref.len() < 4 {
        return false;
    }
    // Bead ref chars: alphanumeric, dash, dot
    if !bead_ref[3..]
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '.')
    {
        return false;
    }
    // Justification must be non-empty
    let justification = &rest[paren_close + 3..];
    !justification.trim().is_empty()
}

/// Returns true if the line is inside a `#[cfg(test)]` module or a `// test`
/// comment context. This is a conservative heuristic: we only skip lines
/// that are clearly in test-only code.
fn is_in_test_context(lines: &[&str], line_idx: usize) -> bool {
    // Walk backwards looking for `#[cfg(test)]` or `mod tests {`
    for i in (0..line_idx).rev() {
        let trimmed = lines[i].trim();
        if trimmed == "#[cfg(test)]" || trimmed.starts_with("mod tests") {
            return true;
        }
        // If we hit a top-level `mod` or `fn main` that isn't test, stop
        if trimmed.starts_with("pub mod ")
            || trimmed.starts_with("mod ") && !trimmed.contains("tests")
        {
            return false;
        }
    }
    false
}

/// Returns true if the pattern match occurs inside a double-quoted string literal.
///
/// This prevents the checker from flagging its own `BANNED_PATTERNS` const
/// definition or other string constants that mention tokio patterns.
fn is_inside_string_literal(line: &str, pattern: &str) -> bool {
    let Some(match_start) = line.find(pattern) else {
        return false;
    };
    // Count unescaped double-quotes before the match position.
    // If odd, we are inside a string literal.
    let before = &line[..match_start];
    let quote_count = before
        .chars()
        .enumerate()
        .filter(|&(i, c)| c == '"' && (i == 0 || before.as_bytes()[i - 1] != b'\\'))
        .count();
    quote_count % 2 == 1
}

/// Returns true if the file lives under `src/api/`.
fn is_api_source_file(file: &Path) -> bool {
    let normalized = file.to_string_lossy().replace('\\', "/");
    normalized.contains("/src/api/") || normalized.starts_with("src/api/")
}

/// Check a single line for banned patterns.
fn check_line_for_violations(
    line: &str,
    line_number: usize,
    preceding_line: Option<&str>,
    file: &Path,
    all_lines: &[&str],
    violations: &mut Vec<DriftViolation>,
    exceptions_honored: &mut usize,
) {
    let trimmed = line.trim();

    // Skip comments (but not attribute macros which start with #[)
    if trimmed.starts_with("//") && !trimmed.starts_with("//!") {
        return;
    }

    // Skip lines in test context
    if is_in_test_context(all_lines, line_number.saturating_sub(1)) {
        return;
    }

    // Check banned bootstrap patterns
    for pattern in BANNED_PATTERNS {
        if trimmed.contains(pattern) && !is_inside_string_literal(trimmed, pattern) {
            if is_valid_exception(preceding_line) {
                *exceptions_honored = exceptions_honored.saturating_add(1);
                return;
            }
            violations.push(DriftViolation {
                file: file.to_path_buf(),
                line_number,
                line_content: line.to_string(),
                pattern: (*pattern).to_string(),
                reason: "Forbidden Tokio runtime bootstrap pattern detected. \
                         This crate must not reintroduce ambient executor scaffolding. \
                         If a real async boundary is needed, add a TOKIO_DRIFT_EXCEPTION \
                         marker referencing an architectural decision bead.",
            });
            return; // One violation per line is enough
        }
    }

    // Check banned import patterns
    for pattern in BANNED_IMPORT_PATTERNS {
        if trimmed.contains(pattern) && !is_inside_string_literal(trimmed, pattern) {
            if is_valid_exception(preceding_line) {
                *exceptions_honored = exceptions_honored.saturating_add(1);
                return;
            }
            violations.push(DriftViolation {
                file: file.to_path_buf(),
                line_number,
                line_content: line.to_string(),
                pattern: (*pattern).to_string(),
                reason: "Direct Tokio import detected in production code. \
                         This crate removed its Tokio dependency in bd-1now.2. \
                         If async runtime support is genuinely needed, add a \
                         TOKIO_DRIFT_EXCEPTION marker referencing a decision bead.",
            });
            return;
        }
    }
}

/// Check a single line for API transport-boundary trigger patterns.
fn check_api_transport_boundary_line_for_violations(
    line: &str,
    line_number: usize,
    preceding_line: Option<&str>,
    file: &Path,
    all_lines: &[&str],
    violations: &mut Vec<DriftViolation>,
    exceptions_honored: &mut usize,
) {
    if !is_api_source_file(file) {
        return;
    }

    let trimmed = line.trim();

    if trimmed.starts_with("//") && !trimmed.starts_with("//!") {
        return;
    }

    if is_in_test_context(all_lines, line_number.saturating_sub(1)) {
        return;
    }

    for pattern in API_TRANSPORT_BOUNDARY_PATTERNS {
        if trimmed.contains(pattern) && !is_inside_string_literal(trimmed, pattern) {
            if is_valid_exception(preceding_line) {
                *exceptions_honored = exceptions_honored.saturating_add(1);
                return;
            }
            violations.push(DriftViolation {
                file: file.to_path_buf(),
                line_number,
                line_content: line.to_string(),
                pattern: (*pattern).to_string(),
                reason: "API transport boundary pattern detected in production code. \
                         This is the wake-up condition for deferred Asupersync \
                         request-region work (bd-1now.6). Add a TOKIO_DRIFT_EXCEPTION \
                         marker referencing the decision bead if the boundary is \
                         intentional and fully reviewed.",
            });
            return;
        }
    }
}

/// Check `Cargo.toml` for a direct tokio dependency.
fn check_cargo_toml(
    cargo_toml_content: &str,
    cargo_toml_path: &Path,
    violations: &mut Vec<DriftViolation>,
    exceptions_honored: &mut usize,
) {
    let lines: Vec<&str> = cargo_toml_content.lines().collect();
    let mut in_dependencies = false;
    let mut in_dev_dependencies = false;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("[dependencies]") || trimmed.starts_with("[dependencies.") {
            in_dependencies = true;
            in_dev_dependencies = false;
            continue;
        }
        if trimmed.starts_with("[dev-dependencies]") || trimmed.starts_with("[dev-dependencies.") {
            in_dependencies = false;
            in_dev_dependencies = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_dependencies = false;
            in_dev_dependencies = false;
            continue;
        }

        // Only flag production dependencies, not dev-dependencies
        if in_dependencies
            && (trimmed.starts_with("tokio") && (trimmed.contains('=') || trimmed.contains('{')))
        {
            let preceding = if idx > 0 { Some(lines[idx - 1]) } else { None };
            if is_valid_exception(preceding) {
                *exceptions_honored = exceptions_honored.saturating_add(1);
                continue;
            }
            violations.push(DriftViolation {
                file: cargo_toml_path.to_path_buf(),
                line_number: idx.saturating_add(1),
                line_content: line.to_string(),
                pattern: "tokio dependency in [dependencies]".to_string(),
                reason: "Direct tokio production dependency detected in Cargo.toml. \
                         This crate intentionally removed Tokio (bd-1now.2). \
                         Add a TOKIO_DRIFT_EXCEPTION marker if reintroduction is \
                         architecturally justified.",
            });
        }

        // Dev-dependencies with tokio are allowed (for test infrastructure)
        // but we note them if someone tries to sneak runtime features in
        if in_dev_dependencies
            && trimmed.starts_with("tokio")
            && (trimmed.contains("rt-multi-thread") || trimmed.contains("rt\""))
        {
            let preceding = if idx > 0 { Some(lines[idx - 1]) } else { None };
            if is_valid_exception(preceding) {
                *exceptions_honored = exceptions_honored.saturating_add(1);
                continue;
            }
            violations.push(DriftViolation {
                file: cargo_toml_path.to_path_buf(),
                line_number: idx.saturating_add(1),
                line_content: line.to_string(),
                pattern: "tokio runtime features in [dev-dependencies]".to_string(),
                reason: "Tokio runtime features in dev-dependencies may mask \
                         ambient executor reintroduction. Use explicit feature \
                         gates or add a TOKIO_DRIFT_EXCEPTION marker.",
            });
        }
    }
}

/// Collect all `.rs` source files under a directory, excluding well-known
/// non-production paths.
fn collect_source_files(src_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_source_files_recursive(src_dir, &mut files);
    files.sort();
    files
}

fn collect_source_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_source_files_recursive(&path, files);
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

/// Run the full Tokio drift check on the `frankenengine-node` crate.
///
/// `crate_root` should point to `crates/franken-node/`.
pub fn check_tokio_drift(crate_root: &Path) -> DriftCheckResult {
    let mut violations = Vec::new();
    let mut files_scanned: usize = 0;
    let mut exceptions_honored: usize = 0;

    // 1. Check Cargo.toml
    let cargo_toml_path = crate_root.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(&cargo_toml_path) {
        check_cargo_toml(
            &content,
            &cargo_toml_path,
            &mut violations,
            &mut exceptions_honored,
        );
        files_scanned = files_scanned.saturating_add(1);
    }

    // 2. Check all .rs files under src/
    let src_dir = crate_root.join("src");
    let source_files = collect_source_files(&src_dir);

    for file_path in &source_files {
        let Ok(content) = std::fs::read_to_string(file_path) else {
            continue;
        };
        files_scanned = files_scanned.saturating_add(1);

        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let line_number = idx.saturating_add(1);
            let preceding = if idx > 0 { Some(lines[idx - 1]) } else { None };
            check_line_for_violations(
                line,
                line_number,
                preceding,
                file_path,
                &lines,
                &mut violations,
                &mut exceptions_honored,
            );
        }
    }

    DriftCheckResult {
        violations,
        files_scanned,
        exceptions_honored,
    }
}

/// Detect whether `src/api/**` has grown a real transport boundary that should
/// wake deferred request-region architecture work.
pub fn check_api_transport_boundary_trigger(crate_root: &Path) -> DriftCheckResult {
    let mut violations = Vec::new();
    let mut files_scanned: usize = 0;
    let mut exceptions_honored: usize = 0;

    let src_dir = crate_root.join("src");
    let source_files = collect_source_files(&src_dir);

    for file_path in &source_files {
        if !is_api_source_file(file_path) {
            continue;
        }

        let Ok(content) = std::fs::read_to_string(file_path) else {
            continue;
        };
        files_scanned = files_scanned.saturating_add(1);

        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let line_number = idx.saturating_add(1);
            let preceding = if idx > 0 { Some(lines[idx - 1]) } else { None };
            check_api_transport_boundary_line_for_violations(
                line,
                line_number,
                preceding,
                file_path,
                &lines,
                &mut violations,
                &mut exceptions_honored,
            );
        }
    }

    DriftCheckResult {
        violations,
        files_scanned,
        exceptions_honored,
    }
}

/// Format a drift check result into a human-readable report.
pub fn format_drift_report(result: &DriftCheckResult) -> String {
    let mut report = String::new();
    report.push_str("=== Async Boundary Guard Report ===\n");
    report.push_str(&format!("Files scanned: {}\n", result.files_scanned));
    report.push_str(&format!(
        "Exceptions honored: {}\n",
        result.exceptions_honored
    ));
    report.push_str(&format!("Violations: {}\n", result.violations.len()));

    if result.is_clean() {
        report.push_str("\nStatus: PASS - No ambient Tokio/runtime drift detected.\n");
    } else {
        report.push_str("\nStatus: FAIL - Tokio drift violations found:\n\n");
        for (i, v) in result.violations.iter().enumerate() {
            report.push_str(&format!(
                "  {}. {}:{}\n     Pattern: `{}`\n     Line: {}\n     {}\n\n",
                i.saturating_add(1),
                v.file.display(),
                v.line_number,
                v.pattern,
                v.line_content.trim(),
                v.reason,
            ));
        }
        report.push_str(
            "Remediation: Remove the forbidden pattern, or add a TOKIO_DRIFT_EXCEPTION \
             marker on the preceding line referencing an architectural decision bead:\n\
             \n  // TOKIO_DRIFT_EXCEPTION(bd-XXXX): <justification>\n",
        );
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ---------------------------------------------------------------
    // Exception marker validation
    // ---------------------------------------------------------------

    #[test]
    fn valid_exception_marker_accepted() {
        assert!(is_valid_exception(Some(
            "    // TOKIO_DRIFT_EXCEPTION(bd-1now.99): real async HTTP boundary added"
        )));
    }

    #[test]
    fn valid_exception_with_simple_bead_id() {
        assert!(is_valid_exception(Some(
            "// TOKIO_DRIFT_EXCEPTION(bd-abc1): justified"
        )));
    }

    #[test]
    fn bare_exception_without_bead_rejected() {
        // Missing bead reference
        assert!(!is_valid_exception(Some(
            "// TOKIO_DRIFT_EXCEPTION(): needs a bead"
        )));
    }

    #[test]
    fn exception_without_justification_rejected() {
        assert!(!is_valid_exception(Some(
            "// TOKIO_DRIFT_EXCEPTION(bd-abc1): "
        )));
    }

    #[test]
    fn exception_without_closing_paren_rejected() {
        assert!(!is_valid_exception(Some(
            "// TOKIO_DRIFT_EXCEPTION(bd-abc1 justified"
        )));
    }

    #[test]
    fn exception_with_no_preceding_line() {
        assert!(!is_valid_exception(None));
    }

    #[test]
    fn exception_with_short_bead_ref_rejected() {
        // "bd-" with no suffix
        assert!(!is_valid_exception(Some(
            "// TOKIO_DRIFT_EXCEPTION(bd-): not enough"
        )));
    }

    #[test]
    fn exception_with_invalid_bead_chars_rejected() {
        assert!(!is_valid_exception(Some(
            "// TOKIO_DRIFT_EXCEPTION(bd-a b c): spaces not allowed"
        )));
    }

    // ---------------------------------------------------------------
    // String literal detection
    // ---------------------------------------------------------------

    #[test]
    fn pattern_inside_string_literal_detected() {
        assert!(is_inside_string_literal(
            r##"    "#[tokio::main]","##,
            "#[tokio::main]"
        ));
    }

    #[test]
    fn pattern_outside_string_literal_not_flagged() {
        assert!(!is_inside_string_literal(
            "#[tokio::main]",
            "#[tokio::main]"
        ));
    }

    #[test]
    fn string_literal_does_not_trigger_violation() {
        let lines = vec![
            "const BANNED: &[&str] = &[",
            r##"    "#[tokio::main]","##,
            "];",
        ];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_line_for_violations(
            lines[1],
            2,
            Some(lines[0]),
            Path::new("test.rs"),
            &lines,
            &mut violations,
            &mut exceptions,
        );
        assert!(
            violations.is_empty(),
            "String literal containing banned pattern should not trigger violation"
        );
    }

    // ---------------------------------------------------------------
    // Source line scanning
    // ---------------------------------------------------------------

    #[test]
    fn detects_tokio_main_attribute() {
        let lines = vec!["#[tokio::main]", "async fn main() {}"];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_line_for_violations(
            lines[0],
            1,
            None,
            Path::new("test.rs"),
            &lines,
            &mut violations,
            &mut exceptions,
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].pattern.contains("tokio::main"));
    }

    #[test]
    fn detects_tokio_runtime_builder() {
        let lines = vec![
            "fn setup() {",
            "    let rt = tokio::runtime::Builder::new_multi_thread()",
            "}",
        ];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_line_for_violations(
            lines[1],
            2,
            Some(lines[0]),
            Path::new("test.rs"),
            &lines,
            &mut violations,
            &mut exceptions,
        );
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_tokio_import() {
        let lines = vec!["use tokio::runtime;"];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_line_for_violations(
            lines[0],
            1,
            None,
            Path::new("test.rs"),
            &lines,
            &mut violations,
            &mut exceptions,
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].pattern.contains("use tokio::"));
    }

    #[test]
    fn detects_api_transport_boundary_pattern() {
        let lines = vec!["let listener = std::net::TcpListener::bind(\"127.0.0.1:9090\");"];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_api_transport_boundary_line_for_violations(
            lines[0],
            1,
            None,
            Path::new("src/api/server.rs"),
            &lines,
            &mut violations,
            &mut exceptions,
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].pattern.contains("TcpListener::bind"));
    }

    #[test]
    fn non_api_transport_boundary_pattern_is_ignored() {
        let lines = vec!["let listener = std::net::TcpListener::bind(\"127.0.0.1:9090\");"];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_api_transport_boundary_line_for_violations(
            lines[0],
            1,
            None,
            Path::new("src/ops/telemetry_bridge.rs"),
            &lines,
            &mut violations,
            &mut exceptions,
        );
        assert!(violations.is_empty());
        assert_eq!(exceptions, 0);
    }

    #[test]
    fn api_transport_boundary_exception_suppresses_violation() {
        let lines = vec![
            "// TOKIO_DRIFT_EXCEPTION(bd-1now.6): reviewed API transport boundary",
            "use axum::Router;",
        ];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_api_transport_boundary_line_for_violations(
            lines[1],
            2,
            Some(lines[0]),
            Path::new("src/api/server.rs"),
            &lines,
            &mut violations,
            &mut exceptions,
        );
        assert!(violations.is_empty());
        assert_eq!(exceptions, 1);
    }

    #[test]
    fn exception_marker_suppresses_violation() {
        let lines = vec![
            "// TOKIO_DRIFT_EXCEPTION(bd-future.1): MCP server requires async HTTP boundary",
            "#[tokio::main]",
            "async fn main() {}",
        ];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_line_for_violations(
            lines[1],
            2,
            Some(lines[0]),
            Path::new("test.rs"),
            &lines,
            &mut violations,
            &mut exceptions,
        );
        assert!(violations.is_empty());
        assert_eq!(exceptions, 1);
    }

    #[test]
    fn test_context_lines_are_skipped() {
        let lines = vec![
            "#[cfg(test)]",
            "mod tests {",
            "    use tokio::runtime;",
            "}",
        ];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        // line index 2 (0-based) = line 3 in the file
        check_line_for_violations(
            lines[2],
            3,
            Some(lines[1]),
            Path::new("test.rs"),
            &lines,
            &mut violations,
            &mut exceptions,
        );
        assert!(violations.is_empty(), "test context should be skipped");
    }

    #[test]
    fn comments_are_skipped() {
        let lines = vec!["// use tokio::runtime; -- old import"];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_line_for_violations(
            lines[0],
            1,
            None,
            Path::new("test.rs"),
            &lines,
            &mut violations,
            &mut exceptions,
        );
        assert!(violations.is_empty(), "comments should be skipped");
    }

    #[test]
    fn clean_code_passes() {
        let lines = vec![
            "use std::thread;",
            "use std::sync::Arc;",
            "",
            "fn main() {",
            "    thread::spawn(|| { });",
            "}",
        ];
        let mut violations = Vec::new();
        let mut exceptions = 0;
        for (idx, line) in lines.iter().enumerate() {
            let preceding = if idx > 0 { Some(lines[idx - 1]) } else { None };
            check_line_for_violations(
                line,
                idx.saturating_add(1),
                preceding,
                Path::new("test.rs"),
                &lines,
                &mut violations,
                &mut exceptions,
            );
        }
        assert!(violations.is_empty());
    }

    // ---------------------------------------------------------------
    // Cargo.toml scanning
    // ---------------------------------------------------------------

    #[test]
    fn detects_tokio_production_dependency() {
        let toml = r#"
[package]
name = "frankenengine-node"

[dependencies]
serde = "1.0"
tokio = { version = "1", features = ["full"] }

[dev-dependencies]
tempfile = "3"
"#;
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_cargo_toml(
            toml,
            Path::new("Cargo.toml"),
            &mut violations,
            &mut exceptions,
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].pattern.contains("tokio dependency"));
    }

    #[test]
    fn allows_tokio_dev_dependency_without_runtime() {
        let toml = r#"
[package]
name = "frankenengine-node"

[dependencies]
serde = "1.0"

[dev-dependencies]
tokio = { version = "1", features = ["macros"] }
"#;
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_cargo_toml(
            toml,
            Path::new("Cargo.toml"),
            &mut violations,
            &mut exceptions,
        );
        assert!(
            violations.is_empty(),
            "dev-dep without runtime features should be allowed"
        );
    }

    #[test]
    fn flags_tokio_dev_dependency_with_runtime_features() {
        let toml = r#"
[package]
name = "frankenengine-node"

[dependencies]
serde = "1.0"

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
"#;
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_cargo_toml(
            toml,
            Path::new("Cargo.toml"),
            &mut violations,
            &mut exceptions,
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].pattern.contains("dev-dependencies"));
    }

    #[test]
    fn cargo_toml_exception_suppresses_violation() {
        let toml = r#"
[package]
name = "frankenengine-node"

[dependencies]
serde = "1.0"
# TOKIO_DRIFT_EXCEPTION(bd-future.1): MCP server needs async HTTP
tokio = { version = "1", features = ["full"] }
"#;
        let mut violations = Vec::new();
        let mut exceptions = 0;
        check_cargo_toml(
            toml,
            Path::new("Cargo.toml"),
            &mut violations,
            &mut exceptions,
        );
        assert!(violations.is_empty());
        assert_eq!(exceptions, 1);
    }

    // ---------------------------------------------------------------
    // Full integration: check real crate (current tree)
    // ---------------------------------------------------------------

    #[test]
    fn real_crate_is_tokio_drift_free() {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let result = check_tokio_drift(&crate_root);
        let report = format_drift_report(&result);

        assert!(
            result.is_clean(),
            "Tokio drift detected in current crate:\n{report}"
        );
        // Sanity: we should have scanned a non-trivial number of files
        assert!(
            result.files_scanned > 10,
            "Expected to scan many files, got {}",
            result.files_scanned
        );
    }

    #[test]
    fn real_crate_has_no_api_transport_boundary_trigger() {
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let result = check_api_transport_boundary_trigger(&crate_root);
        let report = format_drift_report(&result);

        assert!(
            result.is_clean(),
            "Unexpected API transport boundary trigger in current crate:\n{report}"
        );
        assert!(
            result.files_scanned > 0,
            "Expected to scan api source files, got {}",
            result.files_scanned
        );
    }

    // ---------------------------------------------------------------
    // Tempdir-based integration tests
    // ---------------------------------------------------------------

    fn write_test_crate(dir: &Path, cargo_toml: &str, main_rs: &str) {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let mut f = std::fs::File::create(dir.join("Cargo.toml")).unwrap();
        f.write_all(cargo_toml.as_bytes()).unwrap();
        let mut f = std::fs::File::create(dir.join("src/main.rs")).unwrap();
        f.write_all(main_rs.as_bytes()).unwrap();
    }

    #[test]
    fn synthetic_crate_with_tokio_bootstrap_fails() {
        let tmp = tempfile::tempdir().unwrap();
        write_test_crate(
            tmp.path(),
            r#"
[package]
name = "test-crate"
version = "0.1.0"

[dependencies]
tokio = { version = "1", features = ["full"] }
"#,
            r#"
#[tokio::main]
async fn main() {
    println!("hello");
}
"#,
        );

        let result = check_tokio_drift(tmp.path());
        assert!(!result.is_clean());
        // Should have at least 2 violations: Cargo.toml dep + #[tokio::main]
        assert!(
            result.violations.len() >= 2,
            "Expected >= 2 violations, got {}: {:?}",
            result.violations.len(),
            result
                .violations
                .iter()
                .map(|v| &v.pattern)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn synthetic_crate_with_exception_passes() {
        let tmp = tempfile::tempdir().unwrap();
        write_test_crate(
            tmp.path(),
            r#"
[package]
name = "test-crate"
version = "0.1.0"

[dependencies]
# TOKIO_DRIFT_EXCEPTION(bd-future.1): MCP server async boundary
tokio = { version = "1", features = ["full"] }
"#,
            r#"
// TOKIO_DRIFT_EXCEPTION(bd-future.1): MCP server async boundary
#[tokio::main]
async fn main() {
    println!("hello");
}
"#,
        );

        let result = check_tokio_drift(tmp.path());
        assert!(
            result.is_clean(),
            "Expected clean with exceptions, got: {}",
            format_drift_report(&result)
        );
        assert_eq!(result.exceptions_honored, 2);
    }

    #[test]
    fn synthetic_clean_crate_passes() {
        let tmp = tempfile::tempdir().unwrap();
        write_test_crate(
            tmp.path(),
            r#"
[package]
name = "test-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
            r#"
fn main() {
    println!("hello");
}
"#,
        );

        let result = check_tokio_drift(tmp.path());
        assert!(result.is_clean());
        assert_eq!(result.files_scanned, 2); // Cargo.toml + main.rs
    }

    #[test]
    fn synthetic_crate_with_api_transport_boundary_fails_trigger_check() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("src/api")).unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            r#"
[package]
name = "test-crate"
version = "0.1.0"
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("src/api/server.rs"),
            r#"
use axum::Router;

pub fn build_router() {
    let _router = Router::new();
}
"#,
        )
        .unwrap();

        let result = check_api_transport_boundary_trigger(tmp.path());
        assert!(!result.is_clean());
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations[0].pattern.contains("axum::Router"));
    }

    #[test]
    fn report_format_is_human_readable() {
        let result = DriftCheckResult {
            violations: vec![DriftViolation {
                file: PathBuf::from("src/main.rs"),
                line_number: 42,
                line_content: "#[tokio::main]".to_string(),
                pattern: "#[tokio::main]".to_string(),
                reason: "Forbidden pattern",
            }],
            files_scanned: 50,
            exceptions_honored: 0,
        };
        let report = format_drift_report(&result);
        assert!(report.contains("FAIL"));
        assert!(report.contains("src/main.rs:42"));
        assert!(report.contains("#[tokio::main]"));
        assert!(report.contains("TOKIO_DRIFT_EXCEPTION"));
    }
}
