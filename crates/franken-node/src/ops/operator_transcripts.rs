//! Golden operator transcript contract checks.
//!
//! This module validates scrubbed transcript fixtures for operator-facing
//! validation and closeout surfaces. It is deliberately pure: callers provide
//! parsed fixture data and receive a deterministic audit report.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATOR_TRANSCRIPT_GOLDEN_SCHEMA_VERSION: &str =
    "franken-node/operator-transcripts/golden/v1";
pub const OPERATOR_TRANSCRIPT_AUDIT_SCHEMA_VERSION: &str =
    "franken-node/operator-transcripts/audit/v1";
pub const MAX_OPERATOR_TRANSCRIPTS: usize = 64;
pub const MAX_TRANSCRIPT_FIELD_BYTES: usize = 16 * 1024;
pub const MAX_ENV_ENTRIES: usize = 16;

pub mod reason_codes {
    pub const PASS: &str = "OT_PASS";
    pub const FAIL_SCHEMA_VERSION: &str = "OT_FAIL_SCHEMA_VERSION";
    pub const FAIL_MISSING_SURFACE: &str = "OT_FAIL_MISSING_SURFACE";
    pub const FAIL_MISSING_SCENARIO: &str = "OT_FAIL_MISSING_SCENARIO";
    pub const FAIL_DUPLICATE_NAME: &str = "OT_FAIL_DUPLICATE_NAME";
    pub const FAIL_EMPTY_FIELD: &str = "OT_FAIL_EMPTY_FIELD";
    pub const FAIL_FIELD_TOO_LARGE: &str = "OT_FAIL_FIELD_TOO_LARGE";
    pub const FAIL_INVALID_JSON: &str = "OT_FAIL_INVALID_JSON";
    pub const FAIL_MISSING_REASON_CODE_IN_JSON: &str = "OT_FAIL_MISSING_REASON_CODE_IN_JSON";
    pub const FAIL_MISSING_REASON_CODE_IN_HUMAN: &str = "OT_FAIL_MISSING_REASON_CODE_IN_HUMAN";
    pub const FAIL_MISSING_REMEDIATION_HINT: &str = "OT_FAIL_MISSING_REMEDIATION_HINT";
    pub const FAIL_MISSING_ACTION: &str = "OT_FAIL_MISSING_ACTION";
    pub const FAIL_UNSCRUBBED_DYNAMIC_FIELD: &str = "OT_FAIL_UNSCRUBBED_DYNAMIC_FIELD";
    pub const FAIL_SENSITIVE_ENV: &str = "OT_FAIL_SENSITIVE_ENV";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorTranscriptSurface {
    Doctor,
    Readiness,
    ValidationCloseout,
    CommandBudget,
    ImpactMapper,
    TraceabilityAudit,
}

impl OperatorTranscriptSurface {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Doctor => "doctor",
            Self::Readiness => "readiness",
            Self::ValidationCloseout => "validation_closeout",
            Self::CommandBudget => "command_budget",
            Self::ImpactMapper => "impact_mapper",
            Self::TraceabilityAudit => "traceability_audit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorTranscriptScenarioKind {
    Clean,
    Blocked,
    ProxyOnly,
    StaleSibling,
    RchUnavailable,
    ResourceSaturated,
}

impl OperatorTranscriptScenarioKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Blocked => "blocked",
            Self::ProxyOnly => "proxy_only",
            Self::StaleSibling => "stale_sibling",
            Self::RchUnavailable => "rch_unavailable",
            Self::ResourceSaturated => "resource_saturated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorTranscriptGoldenSet {
    pub schema_version: String,
    pub transcripts: Vec<OperatorTranscript>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorTranscript {
    pub name: String,
    pub surface: OperatorTranscriptSurface,
    pub scenario_kind: OperatorTranscriptScenarioKind,
    pub command: String,
    pub sanitized_env: BTreeMap<String, String>,
    pub normalized_human: String,
    pub normalized_json: Value,
    pub expected_reason_codes: Vec<String>,
    pub expected_remediation_hints: Vec<String>,
    pub expected_next_step: String,
    pub dynamic_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorTranscriptAuditStatus {
    Pass,
    Fail,
}

impl OperatorTranscriptAuditStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorTranscriptFinding {
    pub transcript_name: String,
    pub reason_code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorTranscriptAuditReport {
    pub schema_version: String,
    pub status: OperatorTranscriptAuditStatus,
    pub status_label: String,
    pub reason_code: String,
    pub transcript_count: usize,
    pub covered_surfaces: Vec<String>,
    pub covered_scenario_kinds: Vec<String>,
    pub findings: Vec<OperatorTranscriptFinding>,
    pub mutates_bead_state: bool,
    pub human_summary: String,
}

#[must_use]
pub fn audit_operator_transcript_golden_set(
    golden_set: &OperatorTranscriptGoldenSet,
) -> OperatorTranscriptAuditReport {
    let mut findings = Vec::new();

    if golden_set.schema_version != OPERATOR_TRANSCRIPT_GOLDEN_SCHEMA_VERSION {
        push_finding(
            &mut findings,
            "*",
            reason_codes::FAIL_SCHEMA_VERSION,
            format!(
                "schema_version must be {}",
                OPERATOR_TRANSCRIPT_GOLDEN_SCHEMA_VERSION
            ),
        );
    }

    if golden_set.transcripts.is_empty() || golden_set.transcripts.len() > MAX_OPERATOR_TRANSCRIPTS
    {
        push_finding(
            &mut findings,
            "*",
            reason_codes::FAIL_EMPTY_FIELD,
            format!(
                "transcript count must be between 1 and {}",
                MAX_OPERATOR_TRANSCRIPTS
            ),
        );
    }

    let mut names = BTreeSet::new();
    let mut surfaces = BTreeSet::new();
    let mut scenario_kinds = BTreeSet::new();

    for transcript in &golden_set.transcripts {
        if !names.insert(transcript.name.as_str()) {
            push_finding(
                &mut findings,
                &transcript.name,
                reason_codes::FAIL_DUPLICATE_NAME,
                format!("duplicate transcript name {}", transcript.name),
            );
        }
        surfaces.insert(transcript.surface);
        scenario_kinds.insert(transcript.scenario_kind);
        audit_transcript(transcript, &mut findings);
    }

    for surface in required_surfaces() {
        if !surfaces.contains(surface) {
            push_finding(
                &mut findings,
                "*",
                reason_codes::FAIL_MISSING_SURFACE,
                format!("missing surface {}", surface.as_str()),
            );
        }
    }

    for scenario_kind in required_scenario_kinds() {
        if !scenario_kinds.contains(scenario_kind) {
            push_finding(
                &mut findings,
                "*",
                reason_codes::FAIL_MISSING_SCENARIO,
                format!("missing scenario kind {}", scenario_kind.as_str()),
            );
        }
    }

    let status = if findings.is_empty() {
        OperatorTranscriptAuditStatus::Pass
    } else {
        OperatorTranscriptAuditStatus::Fail
    };
    let reason_code = findings
        .first()
        .map(|finding| finding.reason_code.clone())
        .unwrap_or_else(|| reason_codes::PASS.to_string());

    OperatorTranscriptAuditReport {
        schema_version: OPERATOR_TRANSCRIPT_AUDIT_SCHEMA_VERSION.to_string(),
        status,
        status_label: status.as_str().to_string(),
        reason_code,
        transcript_count: golden_set.transcripts.len(),
        covered_surfaces: surfaces
            .into_iter()
            .map(OperatorTranscriptSurface::as_str)
            .map(str::to_string)
            .collect(),
        covered_scenario_kinds: scenario_kinds
            .into_iter()
            .map(OperatorTranscriptScenarioKind::as_str)
            .map(str::to_string)
            .collect(),
        human_summary: format!(
            "operator transcript audit status={} transcripts={} findings={}",
            status.as_str(),
            golden_set.transcripts.len(),
            findings.len()
        ),
        findings,
        mutates_bead_state: false,
    }
}

pub fn render_operator_transcript_audit_json(
    report: &OperatorTranscriptAuditReport,
) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

fn audit_transcript(
    transcript: &OperatorTranscript,
    findings: &mut Vec<OperatorTranscriptFinding>,
) {
    check_required_string(findings, &transcript.name, "name", transcript.name.as_str());
    check_required_string(
        findings,
        &transcript.name,
        "command",
        transcript.command.as_str(),
    );
    check_required_string(
        findings,
        &transcript.name,
        "normalized_human",
        transcript.normalized_human.as_str(),
    );
    check_required_string(
        findings,
        &transcript.name,
        "expected_next_step",
        transcript.expected_next_step.as_str(),
    );

    if !transcript.normalized_json.is_object() {
        push_finding(
            findings,
            &transcript.name,
            reason_codes::FAIL_INVALID_JSON,
            "normalized_json must be an object".to_string(),
        );
    }

    check_collection_nonempty(
        findings,
        &transcript.name,
        "expected_reason_codes",
        transcript.expected_reason_codes.len(),
    );
    check_collection_nonempty(
        findings,
        &transcript.name,
        "expected_remediation_hints",
        transcript.expected_remediation_hints.len(),
    );
    check_collection_nonempty(
        findings,
        &transcript.name,
        "dynamic_fields",
        transcript.dynamic_fields.len(),
    );

    check_dynamic_scrubbing(
        findings,
        &transcript.name,
        "command",
        transcript.command.as_str(),
    );
    check_dynamic_scrubbing(
        findings,
        &transcript.name,
        "normalized_human",
        transcript.normalized_human.as_str(),
    );
    check_dynamic_scrubbing(
        findings,
        &transcript.name,
        "normalized_json",
        transcript.normalized_json.to_string().as_str(),
    );
    audit_env(transcript, findings);

    for reason_code in &transcript.expected_reason_codes {
        check_required_string(findings, &transcript.name, "reason_code", reason_code);
        if !transcript.normalized_human.contains(reason_code) {
            push_finding(
                findings,
                &transcript.name,
                reason_codes::FAIL_MISSING_REASON_CODE_IN_HUMAN,
                format!("human output must include reason code {reason_code}"),
            );
        }
        if !json_contains_string(&transcript.normalized_json, reason_code) {
            push_finding(
                findings,
                &transcript.name,
                reason_codes::FAIL_MISSING_REASON_CODE_IN_JSON,
                format!("json output must include reason code {reason_code}"),
            );
        }
    }

    for hint in &transcript.expected_remediation_hints {
        check_required_string(findings, &transcript.name, "remediation_hint", hint);
        if !transcript.normalized_human.contains(hint)
            || !json_contains_string(&transcript.normalized_json, hint)
        {
            push_finding(
                findings,
                &transcript.name,
                reason_codes::FAIL_MISSING_REMEDIATION_HINT,
                format!("human and json output must include remediation hint {hint}"),
            );
        }
    }

    if !transcript
        .normalized_human
        .contains(transcript.expected_next_step.as_str())
        || !json_contains_string(
            &transcript.normalized_json,
            transcript.expected_next_step.as_str(),
        )
    {
        push_finding(
            findings,
            &transcript.name,
            reason_codes::FAIL_MISSING_ACTION,
            "human and json output must include the expected next step".to_string(),
        );
    }
}

fn audit_env(transcript: &OperatorTranscript, findings: &mut Vec<OperatorTranscriptFinding>) {
    if transcript.sanitized_env.len() > MAX_ENV_ENTRIES {
        push_finding(
            findings,
            &transcript.name,
            reason_codes::FAIL_FIELD_TOO_LARGE,
            format!("sanitized_env must contain at most {MAX_ENV_ENTRIES} entries"),
        );
    }

    for (key, value) in &transcript.sanitized_env {
        if is_sensitive_env_key(key) || !is_allowed_env_key(key) {
            push_finding(
                findings,
                &transcript.name,
                reason_codes::FAIL_SENSITIVE_ENV,
                format!("sanitized_env contains disallowed key {key}"),
            );
        }
        check_required_string(findings, &transcript.name, "sanitized_env value", value);
        check_dynamic_scrubbing(findings, &transcript.name, key, value);
    }
}

fn check_required_string(
    findings: &mut Vec<OperatorTranscriptFinding>,
    transcript_name: &str,
    field: &str,
    value: &str,
) {
    if value.trim().is_empty() {
        push_finding(
            findings,
            transcript_name,
            reason_codes::FAIL_EMPTY_FIELD,
            format!("{field} must be non-empty"),
        );
    }
    if value.len() > MAX_TRANSCRIPT_FIELD_BYTES {
        push_finding(
            findings,
            transcript_name,
            reason_codes::FAIL_FIELD_TOO_LARGE,
            format!("{field} exceeds {MAX_TRANSCRIPT_FIELD_BYTES} bytes"),
        );
    }
}

fn check_collection_nonempty(
    findings: &mut Vec<OperatorTranscriptFinding>,
    transcript_name: &str,
    field: &str,
    len: usize,
) {
    if len == 0 {
        push_finding(
            findings,
            transcript_name,
            reason_codes::FAIL_EMPTY_FIELD,
            format!("{field} must be non-empty"),
        );
    }
}

fn check_dynamic_scrubbing(
    findings: &mut Vec<OperatorTranscriptFinding>,
    transcript_name: &str,
    field: &str,
    value: &str,
) {
    if contains_unscrubbed_dynamic_field(value) {
        push_finding(
            findings,
            transcript_name,
            reason_codes::FAIL_UNSCRUBBED_DYNAMIC_FIELD,
            format!("{field} contains an unsanitized dynamic value"),
        );
    }
}

fn push_finding(
    findings: &mut Vec<OperatorTranscriptFinding>,
    transcript_name: &str,
    reason_code: &'static str,
    message: String,
) {
    findings.push(OperatorTranscriptFinding {
        transcript_name: transcript_name.to_string(),
        reason_code: reason_code.to_string(),
        message,
    });
}

fn required_surfaces() -> &'static [OperatorTranscriptSurface] {
    &[
        OperatorTranscriptSurface::Doctor,
        OperatorTranscriptSurface::Readiness,
        OperatorTranscriptSurface::ValidationCloseout,
        OperatorTranscriptSurface::CommandBudget,
        OperatorTranscriptSurface::ImpactMapper,
        OperatorTranscriptSurface::TraceabilityAudit,
    ]
}

fn required_scenario_kinds() -> &'static [OperatorTranscriptScenarioKind] {
    &[
        OperatorTranscriptScenarioKind::Clean,
        OperatorTranscriptScenarioKind::Blocked,
        OperatorTranscriptScenarioKind::ProxyOnly,
        OperatorTranscriptScenarioKind::StaleSibling,
        OperatorTranscriptScenarioKind::RchUnavailable,
        OperatorTranscriptScenarioKind::ResourceSaturated,
    ]
}

fn json_contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value.contains(needle),
        Value::Array(values) => values
            .iter()
            .any(|value| json_contains_string(value, needle)),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| key.contains(needle) || json_contains_string(value, needle)),
        Value::Bool(_) | Value::Number(_) | Value::Null => false,
    }
}

fn contains_unscrubbed_dynamic_field(value: &str) -> bool {
    [
        "/data/projects/",
        "/home/ubuntu/",
        "/tmp/",
        "2025-",
        "2026-",
        "T00:",
        "T01:",
        "T02:",
        "T03:",
        "T04:",
        "T05:",
        "T06:",
        "T07:",
        "T08:",
        "T09:",
        "T10:",
        "T11:",
        "T12:",
        "T13:",
        "T14:",
        "T15:",
        "T16:",
        "T17:",
        "T18:",
        "T19:",
        "T20:",
        "T21:",
        "T22:",
        "T23:",
    ]
    .iter()
    .any(|pattern| value.contains(pattern))
}

fn is_allowed_env_key(key: &str) -> bool {
    matches!(
        key,
        "AGENT_NAME"
            | "CARGO_BUILD_JOBS"
            | "CARGO_INCREMENTAL"
            | "CARGO_TARGET_DIR"
            | "FRANKEN_NODE_PROFILE"
            | "RCH_PRIORITY"
            | "RCH_VISIBILITY"
            | "RUST_LOG"
    )
}

fn is_sensitive_env_key(key: &str) -> bool {
    let uppercase = key.to_ascii_uppercase();
    ["SECRET", "TOKEN", "PASSWORD", "PRIVATE", "API_KEY"]
        .iter()
        .any(|pattern| uppercase.contains(pattern))
}
