use crate::supply_chain::project_scanner::{ApiUsage, ProjectScanReport, RiskLevel};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const REWRITE_ENGINE_GATE: &str = "rewrite_engine_verification";
pub const REWRITE_ENGINE_SECTION: &str = "10.3";
pub const REWRITE_ENGINE_SCHEMA_ID: &str = "franken_node/migration/rewrite_suggestion_report/v1";

const FALLBACK_SOURCE_FILE: &str = "<unknown>";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RewriteRiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

impl RewriteRiskLevel {
    const fn priority(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
        }
    }
}

impl From<RiskLevel> for RewriteRiskLevel {
    fn from(value: RiskLevel) -> Self {
        match value {
            RiskLevel::Critical => Self::Critical,
            RiskLevel::High => Self::High,
            RiskLevel::Medium => Self::Medium,
            RiskLevel::Low => Self::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RewriteCategory {
    DirectReplacement,
    AdapterNeeded,
    RemovalNeeded,
    ManualReview,
}

impl RewriteCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DirectReplacement => "direct-replacement",
            Self::AdapterNeeded => "adapter-needed",
            Self::RemovalNeeded => "removal-needed",
            Self::ManualReview => "manual-review",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteApiUsage {
    pub api_family: String,
    pub api_name: String,
    pub source_file: String,
    pub line_number: Option<u64>,
    pub risk_level: RewriteRiskLevel,
}

impl From<&ApiUsage> for RewriteApiUsage {
    fn from(value: &ApiUsage) -> Self {
        Self {
            api_family: value.api_family.clone(),
            api_name: value.api_name.clone(),
            source_file: normalize_source_file(&value.source_file),
            line_number: value.line_number,
            risk_level: value.risk_level.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteRollbackCommand {
    pub command: String,
    pub argv: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteSuggestion {
    pub api_family: String,
    pub api_name: String,
    pub source_file: String,
    pub line_number: Option<u64>,
    pub risk_level: RewriteRiskLevel,
    pub category: RewriteCategory,
    pub description: String,
    pub before: String,
    pub after: String,
    pub test_cmd: Option<String>,
    pub rollback: RewriteRollbackCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteRollbackPlan {
    pub project: String,
    pub generated_at: String,
    pub affected_files: Vec<String>,
    pub rollback_commands: Vec<RewriteRollbackCommand>,
    pub suggestion_count: u64,
    pub categories: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteSuggestionReport {
    pub schema_version: String,
    pub project: String,
    pub report_timestamp: String,
    pub suggestions: Vec<RewriteSuggestion>,
    pub rollback_plan: RewriteRollbackPlan,
    pub summary: RewriteSuggestionSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteSuggestionSummary {
    pub total_suggestions: u64,
    pub by_category: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteEngineVerification {
    pub gate: String,
    pub section: String,
    pub verdict: String,
    pub timestamp: String,
    pub checks: Vec<RewriteVerificationCheck>,
    pub summary: RewriteVerificationSummary,
    pub sample_report: RewriteSuggestionReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteVerificationCheck {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteVerificationSummary {
    pub total_checks: u64,
    pub passing_checks: u64,
    pub failing_checks: u64,
}

#[derive(Debug, Clone, Copy)]
struct RewriteRule {
    family: &'static str,
    api_name: &'static str,
    category: RewriteCategory,
    description: &'static str,
    before: &'static str,
    after: &'static str,
    test_cmd: Option<&'static str>,
}

const REWRITE_RULES: &[RewriteRule] = &[
    RewriteRule {
        family: "fs",
        api_name: "readFile",
        category: RewriteCategory::DirectReplacement,
        description: "fs.readFile is available via native shim",
        before: "fs.readFile(path, encoding, callback)",
        after: "fs.readFile(path, encoding, callback) // franken_node native shim",
        test_cmd: Some("franken-node --test-compat fs:readFile"),
    },
    RewriteRule {
        family: "fs",
        api_name: "readFileSync",
        category: RewriteCategory::DirectReplacement,
        description: "fs.readFileSync is available via native shim",
        before: "fs.readFileSync(path, encoding)",
        after: "fs.readFileSync(path, encoding) // franken_node native shim",
        test_cmd: Some("franken-node --test-compat fs:readFileSync"),
    },
    RewriteRule {
        family: "fs",
        api_name: "writeFile",
        category: RewriteCategory::DirectReplacement,
        description: "fs.writeFile is available via native shim",
        before: "fs.writeFile(path, data, callback)",
        after: "fs.writeFile(path, data, callback) // franken_node native shim",
        test_cmd: Some("franken-node --test-compat fs:writeFile"),
    },
    RewriteRule {
        family: "fs",
        api_name: "writeFileSync",
        category: RewriteCategory::DirectReplacement,
        description: "fs.writeFileSync is available via native shim",
        before: "fs.writeFileSync(path, data)",
        after: "fs.writeFileSync(path, data) // franken_node native shim",
        test_cmd: Some("franken-node --test-compat fs:writeFileSync"),
    },
    RewriteRule {
        family: "path",
        api_name: "join",
        category: RewriteCategory::DirectReplacement,
        description: "path.join is available via pure Rust implementation",
        before: "path.join('a', 'b')",
        after: "path.join('a', 'b') // franken_node Rust-native",
        test_cmd: Some("franken-node --test-compat path:join"),
    },
    RewriteRule {
        family: "path",
        api_name: "resolve",
        category: RewriteCategory::DirectReplacement,
        description: "path.resolve is available via pure Rust implementation",
        before: "path.resolve('rel')",
        after: "path.resolve('rel') // franken_node Rust-native",
        test_cmd: Some("franken-node --test-compat path:resolve"),
    },
    RewriteRule {
        family: "process",
        api_name: "env",
        category: RewriteCategory::AdapterNeeded,
        description: "process.env access is mediated through capability gate",
        before: "process.env.NODE_ENV",
        after: "process.env.NODE_ENV // capability-gated in franken_node",
        test_cmd: Some("franken-node --test-compat process:env"),
    },
    RewriteRule {
        family: "process",
        api_name: "exit",
        category: RewriteCategory::DirectReplacement,
        description: "process.exit is available via bridge shim",
        before: "process.exit(1)",
        after: "process.exit(1) // franken_node bridge shim",
        test_cmd: Some("franken-node --test-compat process:exit"),
    },
    RewriteRule {
        family: "http",
        api_name: "createServer",
        category: RewriteCategory::AdapterNeeded,
        description: "http.createServer requires engine-native server adapter",
        before: "http.createServer((req, res) => { ... })",
        after: "http.createServer((req, res) => { ... }) // engine-native adapter",
        test_cmd: Some("franken-node --test-compat http:createServer"),
    },
    RewriteRule {
        family: "crypto",
        api_name: "createHash",
        category: RewriteCategory::AdapterNeeded,
        description: "crypto.createHash requires Rust crypto bridge",
        before: "crypto.createHash('sha256').update(data).digest('hex')",
        after: "crypto.createHash('sha256').update(data).digest('hex') // Rust crypto bridge",
        test_cmd: Some("franken-node --test-compat crypto:createHash"),
    },
    RewriteRule {
        family: "child_process",
        api_name: "exec",
        category: RewriteCategory::ManualReview,
        description: "child_process.exec requires security review for sandbox policy",
        before: "exec('command', callback)",
        after: "// REVIEW: child_process.exec requires sandbox policy approval",
        test_cmd: Some("franken-node --test-compat child_process:exec"),
    },
    RewriteRule {
        family: "child_process",
        api_name: "spawn",
        category: RewriteCategory::ManualReview,
        description: "child_process.spawn requires security review for sandbox policy",
        before: "spawn('cmd', args)",
        after: "// REVIEW: child_process.spawn requires sandbox policy approval",
        test_cmd: Some("franken-node --test-compat child_process:spawn"),
    },
];

const UNSAFE_REWRITES: &[RewriteRule] = &[
    RewriteRule {
        family: "unsafe",
        api_name: "eval",
        category: RewriteCategory::RemovalNeeded,
        description: "eval() is blocked in franken_node and must be removed or replaced",
        before: "eval(code)",
        after: "// REMOVED: eval() is unsafe and blocked by default policy",
        test_cmd: None,
    },
    RewriteRule {
        family: "unsafe",
        api_name: "Function",
        category: RewriteCategory::RemovalNeeded,
        description: "new Function() is blocked; use static alternatives",
        before: "new Function('return ' + expr)()",
        after: "// REMOVED: dynamic Function() blocked by policy",
        test_cmd: None,
    },
    RewriteRule {
        family: "unsafe",
        api_name: "vm.runInNewContext",
        category: RewriteCategory::RemovalNeeded,
        description: "vm.runInNewContext is blocked without explicit sandbox policy opt-in",
        before: "vm.runInNewContext(code, sandbox)",
        after: "// REMOVED: vm.runInNewContext requires explicit policy opt-in",
        test_cmd: None,
    },
    RewriteRule {
        family: "unsafe",
        api_name: "process.binding",
        category: RewriteCategory::RemovalNeeded,
        description: "process.binding() is disabled in franken_node",
        before: "process.binding('natives')",
        after: "// REMOVED: process.binding() disabled per DIV-001",
        test_cmd: None,
    },
];

#[must_use]
pub fn rewrite_rule_count() -> usize {
    REWRITE_RULES.len()
}

#[must_use]
pub fn unsafe_rewrite_count() -> usize {
    UNSAFE_REWRITES.len()
}

#[must_use]
pub fn generate_suggestions_from_scan(scan_report: &ProjectScanReport) -> Vec<RewriteSuggestion> {
    let usages = scan_report
        .api_usage
        .iter()
        .map(RewriteApiUsage::from)
        .collect::<Vec<_>>();
    generate_suggestions(&usages)
}

#[must_use]
pub fn generate_suggestions(usages: &[RewriteApiUsage]) -> Vec<RewriteSuggestion> {
    let mut suggestions = usages.iter().map(suggestion_for_usage).collect::<Vec<_>>();
    suggestions.sort_by(|left, right| {
        left.risk_level
            .priority()
            .cmp(&right.risk_level.priority())
            .then_with(|| left.source_file.cmp(&right.source_file))
            .then_with(|| left.api_family.cmp(&right.api_family))
            .then_with(|| left.api_name.cmp(&right.api_name))
            .then_with(|| left.line_number.cmp(&right.line_number))
    });
    suggestions
}

#[must_use]
pub fn generate_rollback_plan_at(
    suggestions: &[RewriteSuggestion],
    project: impl Into<String>,
    generated_at: impl Into<String>,
) -> RewriteRollbackPlan {
    let mut category_counts = BTreeMap::new();
    let mut command_by_file = BTreeMap::new();

    for suggestion in suggestions {
        let category = suggestion.category.as_str().to_string();
        let count = category_counts.entry(category).or_insert(0_u64);
        *count = count.saturating_add(1);
        command_by_file
            .entry(suggestion.source_file.clone())
            .or_insert_with(|| rollback_command(&suggestion.source_file));
    }

    RewriteRollbackPlan {
        project: project.into(),
        generated_at: generated_at.into(),
        affected_files: command_by_file.keys().cloned().collect(),
        rollback_commands: command_by_file.into_values().collect(),
        suggestion_count: usize_to_u64(suggestions.len()),
        categories: category_counts,
    }
}

#[must_use]
pub fn produce_report(scan_report: &ProjectScanReport) -> RewriteSuggestionReport {
    produce_report_at(scan_report, Utc::now().to_rfc3339())
}

#[must_use]
pub fn produce_report_at(
    scan_report: &ProjectScanReport,
    timestamp: impl Into<String>,
) -> RewriteSuggestionReport {
    let timestamp = timestamp.into();
    let suggestions = generate_suggestions_from_scan(scan_report);
    let rollback_plan =
        generate_rollback_plan_at(&suggestions, scan_report.project.clone(), timestamp.clone());
    RewriteSuggestionReport {
        schema_version: REWRITE_ENGINE_SCHEMA_ID.to_string(),
        project: scan_report.project.clone(),
        report_timestamp: timestamp,
        suggestions,
        summary: RewriteSuggestionSummary {
            total_suggestions: rollback_plan.suggestion_count,
            by_category: rollback_plan.categories.clone(),
        },
        rollback_plan,
    }
}

#[must_use]
pub fn verification_report_at(timestamp: impl Into<String>) -> RewriteEngineVerification {
    let timestamp = timestamp.into();
    let sample_scan = sample_scan_report(&timestamp);
    let sample_report = produce_report_at(&sample_scan, timestamp.clone());
    let mut checks = Vec::new();

    checks.push(check_bool(
        "REWRITE-SUGGESTIONS",
        sample_report.suggestions.len() == 4,
        [(
            "count".to_string(),
            Value::from(usize_to_u64(sample_report.suggestions.len())),
        )],
    ));
    checks.push(check_bool(
        "REWRITE-PRIORITY",
        sample_report
            .suggestions
            .first()
            .is_some_and(|suggestion| suggestion.risk_level == RewriteRiskLevel::Critical),
        [(
            "first_risk".to_string(),
            sample_report
                .suggestions
                .first()
                .map_or(Value::Null, |suggestion| {
                    serde_json::to_value(suggestion.risk_level).unwrap_or(Value::Null)
                }),
        )],
    ));
    checks.push(check_bool(
        "REWRITE-ROLLBACK",
        !sample_report.rollback_plan.affected_files.is_empty()
            && sample_report.rollback_plan.suggestion_count == 4,
        [(
            "affected_files".to_string(),
            Value::from(usize_to_u64(
                sample_report.rollback_plan.affected_files.len(),
            )),
        )],
    ));
    checks.push(check_bool(
        "REWRITE-CATEGORIES",
        !sample_report.summary.by_category.is_empty(),
        [(
            "category_count".to_string(),
            Value::from(usize_to_u64(sample_report.summary.by_category.len())),
        )],
    ));
    checks.push(check_bool(
        "REWRITE-RULES",
        REWRITE_RULES.len() >= 8 && UNSAFE_REWRITES.len() == 4,
        [
            (
                "rule_count".to_string(),
                Value::from(usize_to_u64(REWRITE_RULES.len())),
            ),
            (
                "unsafe_count".to_string(),
                Value::from(usize_to_u64(UNSAFE_REWRITES.len())),
            ),
        ],
    ));

    let failing_checks = usize_to_u64(checks.iter().filter(|check| check.status == "FAIL").count());
    let total_checks = usize_to_u64(checks.len());
    let passing_checks = total_checks.saturating_sub(failing_checks);

    RewriteEngineVerification {
        gate: REWRITE_ENGINE_GATE.to_string(),
        section: REWRITE_ENGINE_SECTION.to_string(),
        verdict: if failing_checks == 0 { "PASS" } else { "FAIL" }.to_string(),
        timestamp,
        checks,
        summary: RewriteVerificationSummary {
            total_checks,
            passing_checks,
            failing_checks,
        },
        sample_report,
    }
}

fn suggestion_for_usage(usage: &RewriteApiUsage) -> RewriteSuggestion {
    let rule = if usage.api_family == "unsafe" {
        find_rule(UNSAFE_REWRITES, &usage.api_family, &usage.api_name)
    } else {
        find_rule(REWRITE_RULES, &usage.api_family, &usage.api_name)
    };
    let (category, description, before, after, test_cmd) = if let Some(rule) = rule {
        (
            rule.category,
            rule.description.to_string(),
            rule.before.to_string(),
            rule.after.to_string(),
            rule.test_cmd.map(ToString::to_string),
        )
    } else {
        (
            RewriteCategory::ManualReview,
            format!(
                "No automated rewrite for {}.{}",
                usage.api_family, usage.api_name
            ),
            format!("{}.{}(...)", usage.api_family, usage.api_name),
            format!(
                "// REVIEW: {}.{} requires compatibility analysis",
                usage.api_family, usage.api_name
            ),
            None,
        )
    };
    let source_file = normalize_source_file(&usage.source_file);

    RewriteSuggestion {
        api_family: usage.api_family.clone(),
        api_name: usage.api_name.clone(),
        source_file: source_file.clone(),
        line_number: usage.line_number,
        risk_level: usage.risk_level,
        category,
        description,
        before,
        after,
        test_cmd,
        rollback: rollback_command(&source_file),
    }
}

fn find_rule<'a>(
    rules: &'a [RewriteRule],
    family: &str,
    api_name: &str,
) -> Option<&'a RewriteRule> {
    rules
        .iter()
        .find(|rule| rule.family == family && rule.api_name == api_name)
}

fn rollback_command(source_file: &str) -> RewriteRollbackCommand {
    let source_file = normalize_source_file(source_file);
    RewriteRollbackCommand {
        command: format!("git restore -- {}", shell_quote(&source_file)),
        argv: vec![
            "git".to_string(),
            "restore".to_string(),
            "--".to_string(),
            source_file.clone(),
        ],
        description: format!("Restore original {source_file} from version control"),
    }
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn normalize_source_file(source_file: &str) -> String {
    let trimmed = source_file.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        FALLBACK_SOURCE_FILE.to_string()
    } else {
        trimmed.replace('\\', "/")
    }
}

fn check_bool(
    id: &str,
    passed: bool,
    details: impl IntoIterator<Item = (String, Value)>,
) -> RewriteVerificationCheck {
    RewriteVerificationCheck {
        id: id.to_string(),
        status: if passed { "PASS" } else { "FAIL" }.to_string(),
        details: details.into_iter().collect(),
    }
}

fn sample_scan_report(timestamp: &str) -> ProjectScanReport {
    ProjectScanReport {
        project: "test-project".to_string(),
        scan_timestamp: timestamp.to_string(),
        summary: crate::supply_chain::project_scanner::ScanSummary {
            total_apis_detected: 4,
            risk_distribution: crate::supply_chain::project_scanner::RiskDistribution {
                low: 2,
                medium: 0,
                high: 1,
                critical: 1,
            },
            migration_readiness: crate::supply_chain::project_scanner::MigrationReadiness::NotReady,
        },
        api_usage: vec![
            ApiUsage {
                api_family: "fs".to_string(),
                api_name: "readFileSync".to_string(),
                source_file: "app.js".to_string(),
                line_number: Some(1),
                band: Some("core".to_string()),
                impl_status: Some("native".to_string()),
                risk_level: RiskLevel::Low,
            },
            ApiUsage {
                api_family: "path".to_string(),
                api_name: "join".to_string(),
                source_file: "app.js".to_string(),
                line_number: Some(2),
                band: Some("core".to_string()),
                impl_status: Some("native".to_string()),
                risk_level: RiskLevel::Low,
            },
            ApiUsage {
                api_family: "http".to_string(),
                api_name: "createServer".to_string(),
                source_file: "server.js".to_string(),
                line_number: Some(1),
                band: Some("high-value".to_string()),
                impl_status: None,
                risk_level: RiskLevel::High,
            },
            ApiUsage {
                api_family: "unsafe".to_string(),
                api_name: "eval".to_string(),
                source_file: "legacy.js".to_string(),
                line_number: Some(1),
                band: Some("unsafe".to_string()),
                impl_status: None,
                risk_level: RiskLevel::Critical,
            },
        ],
        dependencies: Vec::new(),
        recommendations: Vec::new(),
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
