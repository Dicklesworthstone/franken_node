//! Closed-bead compliance auditor.
//!
//! This module audits already-closed bead metadata against concrete evidence.
//! It is deliberately pure: callers provide parsed bead metadata, comments,
//! and proof references, and the auditor returns a report without mutating
//! Beads, Agent Mail, or repository state.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CLOSED_BEAD_COMPLIANCE_SCHEMA_VERSION: &str =
    "franken-node/closed-bead-compliance/report/v1";
pub const CLOSED_BEAD_COMPLIANCE_INPUT_SCHEMA_VERSION: &str =
    "franken-node/closed-bead-compliance/input/v1";
pub const MAX_COMPLIANCE_REQUIREMENTS: usize = 64;
pub const MAX_COMPLIANCE_EVIDENCE: usize = 256;
const MAX_FIELD_BYTES: usize = 4096;

pub mod reason_codes {
    pub const PASS: &str = "CBC_PASS";
    pub const WARN_BLOCKED_PROOF: &str = "CBC_WARN_BLOCKED_PROOF";
    pub const WARN_SOURCE_ONLY: &str = "CBC_WARN_SOURCE_ONLY";
    pub const FAIL_BEAD_NOT_CLOSED: &str = "CBC_FAIL_BEAD_NOT_CLOSED";
    pub const FAIL_MISSING_EVIDENCE: &str = "CBC_FAIL_MISSING_EVIDENCE";
    pub const FAIL_UNRELATED_EVIDENCE: &str = "CBC_FAIL_UNRELATED_EVIDENCE";
    pub const FAIL_STALE_EVIDENCE: &str = "CBC_FAIL_STALE_EVIDENCE";
    pub const FAIL_INVALID_INPUT: &str = "CBC_FAIL_INVALID_INPUT";
}

pub mod event_codes {
    pub const PASS: &str = "CBC-001";
    pub const WARNING: &str = "CBC-002";
    pub const FAILURE: &str = "CBC-003";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosedBeadComplianceStatus {
    Pass,
    Warn,
    Fail,
}

impl ClosedBeadComplianceStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosedBeadEvidenceKind {
    ImplementationCommit,
    SourceFile,
    Test,
    Gate,
    Artifact,
    RchReceipt,
    AgentMailThread,
    BrComment,
}

impl ClosedBeadEvidenceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImplementationCommit => "implementation_commit",
            Self::SourceFile => "source_file",
            Self::Test => "test",
            Self::Gate => "gate",
            Self::Artifact => "artifact",
            Self::RchReceipt => "rch_receipt",
            Self::AgentMailThread => "agent_mail_thread",
            Self::BrComment => "br_comment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosedBeadEvidenceCoverage {
    Direct,
    Proxy,
    Unrelated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosedBeadEvidenceStatus {
    Fresh,
    SourceOnly,
    Blocked,
    Stale,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedBeadComment {
    pub author: String,
    pub body: String,
}

impl ClosedBeadComment {
    #[must_use]
    pub fn new(author: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            author: author.into(),
            body: body.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedBeadMetadata {
    pub bead_id: String,
    pub title: String,
    pub status: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acceptance_criteria: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
    pub comments: Vec<ClosedBeadComment>,
}

impl ClosedBeadMetadata {
    #[must_use]
    pub fn new(
        bead_id: impl Into<String>,
        title: impl Into<String>,
        status: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            bead_id: bead_id.into(),
            title: title.into(),
            status: status.into(),
            description: description.into(),
            acceptance_criteria: None,
            close_reason: None,
            comments: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_acceptance_criteria(mut self, acceptance_criteria: impl Into<String>) -> Self {
        self.acceptance_criteria = Some(acceptance_criteria.into());
        self
    }

    #[must_use]
    pub fn with_close_reason(mut self, close_reason: impl Into<String>) -> Self {
        self.close_reason = Some(close_reason.into());
        self
    }

    #[must_use]
    pub fn with_comments<I>(mut self, comments: I) -> Self
    where
        I: IntoIterator<Item = ClosedBeadComment>,
    {
        self.comments = comments.into_iter().collect();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedBeadEvidenceRef {
    pub evidence_id: String,
    pub bead_id: String,
    pub kind: ClosedBeadEvidenceKind,
    pub coverage: ClosedBeadEvidenceCoverage,
    pub status: ClosedBeadEvidenceStatus,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
}

impl ClosedBeadEvidenceRef {
    #[must_use]
    pub fn new(
        evidence_id: impl Into<String>,
        bead_id: impl Into<String>,
        kind: ClosedBeadEvidenceKind,
        coverage: ClosedBeadEvidenceCoverage,
        status: ClosedBeadEvidenceStatus,
        description: impl Into<String>,
    ) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            bead_id: bead_id.into(),
            kind,
            coverage,
            status,
            description: description.into(),
            path: None,
            command: None,
            git_commit: None,
            thread_id: None,
        }
    }

    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    #[must_use]
    pub fn with_git_commit(mut self, git_commit: impl Into<String>) -> Self {
        self.git_commit = Some(git_commit.into());
        self
    }

    #[must_use]
    pub fn with_thread_id(mut self, thread_id: impl Into<String>) -> Self {
        self.thread_id = Some(thread_id.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedBeadComplianceInput {
    pub schema_version: String,
    pub bead: ClosedBeadMetadata,
    pub evidence: Vec<ClosedBeadEvidenceRef>,
}

impl ClosedBeadComplianceInput {
    #[must_use]
    pub fn new(bead: ClosedBeadMetadata, evidence: Vec<ClosedBeadEvidenceRef>) -> Self {
        Self {
            schema_version: CLOSED_BEAD_COMPLIANCE_INPUT_SCHEMA_VERSION.to_string(),
            bead,
            evidence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedBeadRequirementFinding {
    pub requirement_id: String,
    pub requirement_text: String,
    pub required_kinds: Vec<ClosedBeadEvidenceKind>,
    pub status: ClosedBeadComplianceStatus,
    pub reason_code: String,
    pub matched_evidence_ids: Vec<String>,
    pub missing_kinds: Vec<ClosedBeadEvidenceKind>,
    pub unrelated_evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedBeadEvidenceSummary {
    pub direct_fresh: usize,
    pub direct_source_only: usize,
    pub direct_blocked: usize,
    pub direct_stale: usize,
    pub direct_missing: usize,
    pub proxy_or_unrelated: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedBeadComplianceReport {
    pub schema_version: String,
    pub bead_id: String,
    pub status: ClosedBeadComplianceStatus,
    pub status_label: String,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
    pub mutates_bead_state: bool,
    pub requirements: Vec<ClosedBeadRequirementFinding>,
    pub evidence_summary: ClosedBeadEvidenceSummary,
    pub warnings: Vec<String>,
    pub suggested_br_commands: Vec<String>,
    pub human_summary: String,
}

pub fn audit_closed_bead_compliance(
    input: ClosedBeadComplianceInput,
) -> ClosedBeadComplianceReport {
    let mut warnings = Vec::new();
    let mut suggested_br_commands = Vec::new();
    let bead_id = input.bead.bead_id.trim().to_string();

    if bead_id.is_empty() || input.schema_version != CLOSED_BEAD_COMPLIANCE_INPUT_SCHEMA_VERSION {
        return invalid_input_report(bead_id);
    }

    let requirements = extract_requirements(&input.bead);
    let bounded_evidence_len = input.evidence.len().min(MAX_COMPLIANCE_EVIDENCE);
    let evidence = input
        .evidence
        .get(..bounded_evidence_len)
        .unwrap_or(input.evidence.as_slice());
    let evidence_summary = summarize_evidence(&bead_id, evidence);
    if input.evidence.len() > MAX_COMPLIANCE_EVIDENCE {
        warnings.push(format!(
            "evidence truncated at {MAX_COMPLIANCE_EVIDENCE} records for bead {bead_id}"
        ));
    }
    if !input.bead.status.eq_ignore_ascii_case("closed") {
        warnings.push(format!(
            "bead {} is status={} and cannot be accepted as closed evidence",
            bead_id, input.bead.status
        ));
        suggested_br_commands.push(format!("br show {bead_id}"));
        suggested_br_commands.push(format!(
            "br update {bead_id} --status open --notes \"refresh stale closed-bead compliance state\""
        ));
    }

    let mut findings = Vec::new();
    for (index, requirement_text) in requirements.iter().enumerate() {
        findings.push(evaluate_requirement(
            &bead_id,
            index,
            requirement_text,
            evidence,
        ));
    }

    let mut status = findings
        .iter()
        .map(|finding| finding.status)
        .max()
        .unwrap_or(ClosedBeadComplianceStatus::Fail);
    if !input.bead.status.eq_ignore_ascii_case("closed") {
        status = ClosedBeadComplianceStatus::Fail;
    }

    let (reason_code, event_code, required_action) = if status == ClosedBeadComplianceStatus::Fail {
        if !input.bead.status.eq_ignore_ascii_case("closed") {
            (
                reason_codes::FAIL_BEAD_NOT_CLOSED,
                event_codes::FAILURE,
                "refresh_bead_state_before_accepting_closeout",
            )
        } else if findings
            .iter()
            .any(|finding| finding.reason_code == reason_codes::FAIL_UNRELATED_EVIDENCE)
        {
            (
                reason_codes::FAIL_UNRELATED_EVIDENCE,
                event_codes::FAILURE,
                "replace_proxy_or_unrelated_evidence_with_direct_proof",
            )
        } else if findings
            .iter()
            .any(|finding| finding.reason_code == reason_codes::FAIL_STALE_EVIDENCE)
        {
            (
                reason_codes::FAIL_STALE_EVIDENCE,
                event_codes::FAILURE,
                "rerun_or_refresh_stale_evidence",
            )
        } else {
            (
                reason_codes::FAIL_MISSING_EVIDENCE,
                event_codes::FAILURE,
                "collect_missing_direct_evidence",
            )
        }
    } else if status == ClosedBeadComplianceStatus::Warn {
        if findings
            .iter()
            .any(|finding| finding.reason_code == reason_codes::WARN_BLOCKED_PROOF)
        {
            (
                reason_codes::WARN_BLOCKED_PROOF,
                event_codes::WARNING,
                "inspect_blocked_proof_before_accepting_closeout",
            )
        } else {
            (
                reason_codes::WARN_SOURCE_ONLY,
                event_codes::WARNING,
                "document_source_only_validation_limits",
            )
        }
    } else {
        (reason_codes::PASS, event_codes::PASS, "no_action_required")
    };

    if status != ClosedBeadComplianceStatus::Pass {
        suggested_br_commands.push(format!(
            "br comment {bead_id} --body \"closed-bead compliance {reason_code}: {required_action}\""
        ));
    }
    suggested_br_commands.sort();
    suggested_br_commands.dedup();
    warnings.extend(report_warnings(&findings));
    warnings.sort();
    warnings.dedup();

    let human_summary = render_closed_bead_compliance_human_summary(
        &bead_id,
        status,
        reason_code,
        findings.len(),
        &evidence_summary,
    );

    ClosedBeadComplianceReport {
        schema_version: CLOSED_BEAD_COMPLIANCE_SCHEMA_VERSION.to_string(),
        bead_id,
        status,
        status_label: status.as_str().to_string(),
        reason_code: reason_code.to_string(),
        event_code: event_code.to_string(),
        required_action: required_action.to_string(),
        mutates_bead_state: false,
        requirements: findings,
        evidence_summary,
        warnings,
        suggested_br_commands,
        human_summary,
    }
}

pub fn render_closed_bead_compliance_json(
    report: &ClosedBeadComplianceReport,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

fn invalid_input_report(bead_id: String) -> ClosedBeadComplianceReport {
    ClosedBeadComplianceReport {
        schema_version: CLOSED_BEAD_COMPLIANCE_SCHEMA_VERSION.to_string(),
        bead_id,
        status: ClosedBeadComplianceStatus::Fail,
        status_label: ClosedBeadComplianceStatus::Fail.as_str().to_string(),
        reason_code: reason_codes::FAIL_INVALID_INPUT.to_string(),
        event_code: event_codes::FAILURE.to_string(),
        required_action: "fix_invalid_compliance_input".to_string(),
        mutates_bead_state: false,
        requirements: Vec::new(),
        evidence_summary: ClosedBeadEvidenceSummary {
            direct_fresh: 0,
            direct_source_only: 0,
            direct_blocked: 0,
            direct_stale: 0,
            direct_missing: 0,
            proxy_or_unrelated: 0,
        },
        warnings: vec!["invalid closed-bead compliance input".to_string()],
        suggested_br_commands: Vec::new(),
        human_summary: "closed-bead compliance: invalid input".to_string(),
    }
}

fn extract_requirements(bead: &ClosedBeadMetadata) -> Vec<String> {
    let source = bead
        .acceptance_criteria
        .as_deref()
        .filter(|criteria| !criteria.trim().is_empty())
        .unwrap_or(&bead.description);
    let acceptance_tail = source
        .split_once("Acceptance:")
        .map(|(_, tail)| tail)
        .or_else(|| {
            source
                .split_once("Acceptance Criteria:")
                .map(|(_, tail)| tail)
        })
        .unwrap_or(source);

    let mut requirements = Vec::new();
    for line in acceptance_tail.lines() {
        let trimmed = line
            .trim()
            .trim_start_matches(|ch: char| ch.is_ascii_digit() || matches!(ch, '.' | ')' | '-'))
            .trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut sentence = String::new();
        for segment in trimmed.split('.') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            if !sentence.is_empty() {
                sentence.push_str(". ");
            }
            sentence.push_str(segment);
            break;
        }
        if !sentence.is_empty() {
            requirements.push(truncate_field(sentence));
        }
        if requirements.len() >= MAX_COMPLIANCE_REQUIREMENTS {
            break;
        }
    }

    if requirements.is_empty() {
        requirements.push(
            "closed bead must include direct implementation and validation evidence".to_string(),
        );
    }
    requirements.sort();
    requirements.dedup();
    requirements
}

fn evaluate_requirement(
    bead_id: &str,
    index: usize,
    requirement_text: &str,
    evidence: &[ClosedBeadEvidenceRef],
) -> ClosedBeadRequirementFinding {
    let required_kinds = infer_required_kinds(requirement_text);
    let mut matched_evidence_ids = BTreeSet::new();
    let mut unrelated_evidence_ids = BTreeSet::new();
    let mut missing_kinds = Vec::new();
    let mut worst_status = ClosedBeadComplianceStatus::Pass;
    let mut reason_code = reason_codes::PASS;

    for kind in &required_kinds {
        let candidates = evidence
            .iter()
            .filter(|evidence_ref| evidence_ref.kind == *kind)
            .collect::<Vec<_>>();
        let direct_candidates = candidates
            .iter()
            .copied()
            .filter(|evidence_ref| {
                evidence_ref.bead_id == bead_id
                    && evidence_ref.coverage == ClosedBeadEvidenceCoverage::Direct
            })
            .collect::<Vec<_>>();
        if direct_candidates.is_empty() {
            for candidate in candidates {
                unrelated_evidence_ids.insert(candidate.evidence_id.clone());
            }
            missing_kinds.push(*kind);
            worst_status = ClosedBeadComplianceStatus::Fail;
            reason_code = if unrelated_evidence_ids.is_empty() {
                reason_codes::FAIL_MISSING_EVIDENCE
            } else {
                reason_codes::FAIL_UNRELATED_EVIDENCE
            };
            continue;
        }

        let mut kind_matched = false;
        for candidate in direct_candidates {
            matched_evidence_ids.insert(candidate.evidence_id.clone());
            match candidate.status {
                ClosedBeadEvidenceStatus::Fresh => {
                    kind_matched = true;
                }
                ClosedBeadEvidenceStatus::SourceOnly => {
                    kind_matched = true;
                    if worst_status < ClosedBeadComplianceStatus::Warn {
                        worst_status = ClosedBeadComplianceStatus::Warn;
                        reason_code = reason_codes::WARN_SOURCE_ONLY;
                    }
                }
                ClosedBeadEvidenceStatus::Blocked => {
                    kind_matched = true;
                    if worst_status < ClosedBeadComplianceStatus::Warn {
                        worst_status = ClosedBeadComplianceStatus::Warn;
                        reason_code = reason_codes::WARN_BLOCKED_PROOF;
                    }
                }
                ClosedBeadEvidenceStatus::Stale | ClosedBeadEvidenceStatus::Missing => {
                    worst_status = ClosedBeadComplianceStatus::Fail;
                    reason_code = reason_codes::FAIL_STALE_EVIDENCE;
                }
            }
        }
        if !kind_matched {
            missing_kinds.push(*kind);
        }
    }

    if !missing_kinds.is_empty() {
        worst_status = ClosedBeadComplianceStatus::Fail;
        if reason_code == reason_codes::PASS {
            reason_code = reason_codes::FAIL_MISSING_EVIDENCE;
        }
    }

    ClosedBeadRequirementFinding {
        requirement_id: format!("req-{index:03}"),
        requirement_text: truncate_field(requirement_text.to_string()),
        required_kinds,
        status: worst_status,
        reason_code: reason_code.to_string(),
        matched_evidence_ids: matched_evidence_ids.into_iter().collect(),
        missing_kinds,
        unrelated_evidence_ids: unrelated_evidence_ids.into_iter().collect(),
    }
}

fn infer_required_kinds(requirement_text: &str) -> Vec<ClosedBeadEvidenceKind> {
    let text = requirement_text.to_ascii_lowercase();
    let mut kinds = BTreeSet::new();
    if contains_any(&text, &["implement", "code", "commit"]) {
        kinds.insert(ClosedBeadEvidenceKind::ImplementationCommit);
    }
    if contains_any(&text, &["source file", "file", "path"]) {
        kinds.insert(ClosedBeadEvidenceKind::SourceFile);
    }
    if contains_any(&text, &["test", "fixture", "golden", "e2e", "unit"]) {
        kinds.insert(ClosedBeadEvidenceKind::Test);
    }
    if contains_any(&text, &["gate", "script", "verifier"]) {
        kinds.insert(ClosedBeadEvidenceKind::Gate);
    }
    if contains_any(&text, &["artifact", "evidence", "manifest", "json"]) {
        kinds.insert(ClosedBeadEvidenceKind::Artifact);
    }
    if contains_any(&text, &["rch", "proof", "receipt", "validation"]) {
        kinds.insert(ClosedBeadEvidenceKind::RchReceipt);
    }
    if contains_any(&text, &["agent mail", "mail thread", "thread"]) {
        kinds.insert(ClosedBeadEvidenceKind::AgentMailThread);
    }
    if contains_any(&text, &["blocked", "blocker", "comment", "close reason"]) {
        kinds.insert(ClosedBeadEvidenceKind::BrComment);
    }
    if kinds.is_empty() {
        kinds.insert(ClosedBeadEvidenceKind::ImplementationCommit);
        kinds.insert(ClosedBeadEvidenceKind::Test);
    }
    kinds.into_iter().collect()
}

fn summarize_evidence(
    bead_id: &str,
    evidence: &[ClosedBeadEvidenceRef],
) -> ClosedBeadEvidenceSummary {
    let mut summary = ClosedBeadEvidenceSummary {
        direct_fresh: 0,
        direct_source_only: 0,
        direct_blocked: 0,
        direct_stale: 0,
        direct_missing: 0,
        proxy_or_unrelated: 0,
    };

    for evidence_ref in evidence.iter().take(MAX_COMPLIANCE_EVIDENCE) {
        if evidence_ref.bead_id != bead_id
            || evidence_ref.coverage != ClosedBeadEvidenceCoverage::Direct
        {
            summary.proxy_or_unrelated += 1;
            continue;
        }
        match evidence_ref.status {
            ClosedBeadEvidenceStatus::Fresh => summary.direct_fresh += 1,
            ClosedBeadEvidenceStatus::SourceOnly => summary.direct_source_only += 1,
            ClosedBeadEvidenceStatus::Blocked => summary.direct_blocked += 1,
            ClosedBeadEvidenceStatus::Stale => summary.direct_stale += 1,
            ClosedBeadEvidenceStatus::Missing => summary.direct_missing += 1,
        }
    }
    summary
}

fn report_warnings(findings: &[ClosedBeadRequirementFinding]) -> Vec<String> {
    let mut warnings = Vec::new();
    for finding in findings {
        if finding.status == ClosedBeadComplianceStatus::Pass {
            continue;
        }
        warnings.push(format!(
            "{} {} requires {}",
            finding.requirement_id,
            finding.reason_code,
            if finding.missing_kinds.is_empty() {
                "refresh_or_document_limited_evidence".to_string()
            } else {
                finding
                    .missing_kinds
                    .iter()
                    .map(|kind| kind.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            }
        ));
    }
    warnings
}

fn render_closed_bead_compliance_human_summary(
    bead_id: &str,
    status: ClosedBeadComplianceStatus,
    reason_code: &str,
    requirement_count: usize,
    evidence_summary: &ClosedBeadEvidenceSummary,
) -> String {
    format!(
        "closed-bead compliance: bead={} status={} reason={} requirements={} direct_fresh={} source_only={} blocked={} stale={} missing={} proxy_or_unrelated={}",
        bead_id,
        status.as_str(),
        reason_code,
        requirement_count,
        evidence_summary.direct_fresh,
        evidence_summary.direct_source_only,
        evidence_summary.direct_blocked,
        evidence_summary.direct_stale,
        evidence_summary.direct_missing,
        evidence_summary.proxy_or_unrelated
    )
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn truncate_field(value: String) -> String {
    if value.len() <= MAX_FIELD_BYTES {
        return value;
    }
    let mut truncated = String::new();
    for ch in value.chars() {
        if truncated.len() + ch.len_utf8() > MAX_FIELD_BYTES {
            break;
        }
        truncated.push(ch);
    }
    truncated
}
