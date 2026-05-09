//! Validation receipt closeout summaries for Beads and Agent Mail.
//!
//! This module turns a validated broker receipt into deterministic text that
//! agents can paste into `br close --reason` and Agent Mail completion replies.

use crate::ops::validation_broker::{
    ProofEvidenceSource, RchMode, ValidationBrokerError, ValidationErrorClass, ValidationExitKind,
    ValidationProofCacheReuseEvidence, ValidationProofCoalescerEvidence, ValidationReadinessRef,
    ValidationReceipt, error_codes,
};
use crate::ops::validation_proof_coalescer::{
    ValidationSwarmSchedulerDecision, ValidationSwarmSchedulerDecisionKind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

pub const VALIDATION_CLOSEOUT_REPORT_SCHEMA_VERSION: &str =
    "franken-node/validation-closeout/report/v1";
pub const COMPLETION_AUDIT_LEDGER_SCHEMA_VERSION: &str = "franken-node/completion-audit-ledger/v1";
pub const DEFAULT_MAX_OUTPUT_EXCERPT_BYTES: usize = 4096;
pub const MAX_COMPLETION_AUDIT_REQUIREMENTS: usize = 128;
pub const MAX_COMPLETION_AUDIT_EVIDENCE_REFS: usize = 512;
pub const MAX_COMPLETION_AUDIT_STRING_BYTES: usize = 1024;
pub const MAX_COMPLETION_AUDIT_PATH_BYTES: usize = 4096;

pub mod completion_audit_reason_codes {
    pub const PROVEN: &str = "VC_AUDIT_PROVEN";
    pub const PROXY_ONLY: &str = "VC_AUDIT_PROXY_ONLY";
    pub const MISSING_EVIDENCE: &str = "VC_AUDIT_MISSING_EVIDENCE";
    pub const STALE_EVIDENCE: &str = "VC_AUDIT_STALE_EVIDENCE";
    pub const BLOCKED_PROOF: &str = "VC_AUDIT_BLOCKED_PROOF";
}

pub mod completion_audit_event_codes {
    pub const DIRECT_EVIDENCE_READY: &str = "VC-AUDIT-001";
    pub const PROXY_EVIDENCE_ONLY: &str = "VC-AUDIT-002";
    pub const EVIDENCE_MISSING: &str = "VC-AUDIT-003";
    pub const STALE_STATE: &str = "VC-AUDIT-004";
    pub const PROOF_BLOCKED: &str = "VC-AUDIT-005";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCloseoutStatus {
    Ready,
    SourceOnly,
    Blocked,
    Stale,
    Invalid,
}

impl ValidationCloseoutStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::SourceOnly => "SOURCE_ONLY",
            Self::Blocked => "BLOCKED",
            Self::Stale => "STALE",
            Self::Invalid => "INVALID",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCloseoutOptions {
    pub bead_id: String,
    pub trace_id: String,
    pub max_output_excerpt_bytes: usize,
    pub proof_source: ProofEvidenceSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_cache: Option<ValidationProofCacheReuseEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_coalescer: Option<ValidationProofCoalescerEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swarm_scheduler: Option<ValidationCloseoutSwarmSchedulerEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_audit: Option<PromptToArtifactCompletionAuditLedger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_text: Option<String>,
}

impl ValidationCloseoutOptions {
    #[must_use]
    pub fn new(bead_id: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self {
            bead_id: bead_id.into(),
            trace_id: trace_id.into(),
            max_output_excerpt_bytes: DEFAULT_MAX_OUTPUT_EXCERPT_BYTES,
            proof_source: ProofEvidenceSource::FreshExecution,
            proof_cache: None,
            proof_coalescer: None,
            swarm_scheduler: None,
            completion_audit: None,
            stdout_text: None,
            stderr_text: None,
        }
    }

    #[must_use]
    pub fn with_proof_cache_reuse(
        mut self,
        proof_cache: ValidationProofCacheReuseEvidence,
    ) -> Self {
        self.proof_source = ProofEvidenceSource::ProofCacheHit;
        self.proof_cache = Some(proof_cache);
        self
    }

    #[must_use]
    pub fn with_proof_coalescer(
        mut self,
        proof_source: ProofEvidenceSource,
        proof_coalescer: ValidationProofCoalescerEvidence,
    ) -> Self {
        self.proof_source = proof_source;
        self.proof_coalescer = Some(proof_coalescer);
        self
    }

    #[must_use]
    pub fn with_swarm_scheduler_decision(
        mut self,
        decision: &ValidationSwarmSchedulerDecision,
    ) -> Self {
        self.swarm_scheduler = Some(ValidationCloseoutSwarmSchedulerEvidence::from_decision(
            decision,
        ));
        self
    }

    #[must_use]
    pub fn with_completion_audit(
        mut self,
        completion_audit: PromptToArtifactCompletionAuditLedger,
    ) -> Self {
        self.completion_audit = Some(completion_audit);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCloseoutReport {
    pub schema_version: String,
    pub command: String,
    pub trace_id: String,
    pub generated_at_utc: DateTime<Utc>,
    pub bead_id: String,
    pub thread_id: String,
    pub receipt_id: String,
    pub request_id: String,
    pub status: ValidationCloseoutStatus,
    pub status_label: String,
    pub proof_source: ProofEvidenceSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_cache: Option<ValidationProofCacheReuseEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_coalescer: Option<ValidationProofCoalescerEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swarm_scheduler: Option<ValidationCloseoutSwarmSchedulerEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_audit: Option<PromptToArtifactCompletionAuditLedger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness_ref: Option<ValidationReadinessRef>,
    pub close_reason: String,
    pub agent_mail_markdown: String,
    pub receipt: ValidationCloseoutReceiptSummary,
    pub warnings: Vec<String>,
    pub output_excerpts: Vec<ValidationCloseoutOutputExcerpt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCloseoutReceiptSummary {
    pub schema_version: String,
    pub command_line: String,
    pub command_digest: String,
    pub exit_kind: String,
    pub exit_code: Option<i32>,
    pub timeout_class: String,
    pub error_class: String,
    pub retryable: bool,
    pub rch_mode: String,
    pub rch_worker_id: Option<String>,
    pub rch_remote_required: bool,
    pub source_only_reason: Option<String>,
    pub readiness_ref: Option<ValidationReadinessRef>,
    pub artifact_stdout_path: String,
    pub artifact_stderr_path: String,
    pub artifact_summary_path: String,
    pub artifact_receipt_path: String,
    pub started_at_utc: DateTime<Utc>,
    pub finished_at_utc: DateTime<Utc>,
    pub freshness_expires_at_utc: DateTime<Utc>,
    pub duration_ms: u64,
    pub generated_by: String,
    pub agent_name: String,
    pub git_commit: String,
    pub dirty_worktree: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCloseoutOutputExcerpt {
    pub stream: String,
    pub text: String,
    pub original_bytes: usize,
    pub included_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionAuditLedgerStatus {
    Proven,
    ProxyOnly,
    MissingEvidence,
    Stale,
    Blocked,
}

impl CompletionAuditLedgerStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "PROVEN",
            Self::ProxyOnly => "PROXY_ONLY",
            Self::MissingEvidence => "MISSING_EVIDENCE",
            Self::Stale => "STALE",
            Self::Blocked => "BLOCKED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionAuditEvidenceKind {
    File,
    Command,
    Test,
    Gate,
    Artifact,
    Bead,
    AgentMailThread,
    Manifest,
    Verifier,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionAuditCoverage {
    Direct,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionAuditEvidenceStatus {
    Fresh,
    Stale,
    Missing,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptToArtifactCompletionAuditLedger {
    pub schema_version: String,
    pub objective_id: String,
    pub objective_summary: String,
    pub status: CompletionAuditLedgerStatus,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
    pub direct_evidence_count: usize,
    pub proxy_evidence_count: usize,
    pub requirements: Vec<CompletionAuditRequirement>,
}

impl PromptToArtifactCompletionAuditLedger {
    #[must_use]
    pub fn new(
        objective_id: impl Into<String>,
        objective_summary: impl Into<String>,
        requirements: Vec<CompletionAuditRequirement>,
    ) -> Self {
        Self {
            schema_version: COMPLETION_AUDIT_LEDGER_SCHEMA_VERSION.to_string(),
            objective_id: objective_id.into(),
            objective_summary: objective_summary.into(),
            status: CompletionAuditLedgerStatus::MissingEvidence,
            reason_code: completion_audit_reason_codes::MISSING_EVIDENCE.to_string(),
            event_code: completion_audit_event_codes::EVIDENCE_MISSING.to_string(),
            required_action: "collect_missing_evidence".to_string(),
            direct_evidence_count: 0,
            proxy_evidence_count: 0,
            requirements,
        }
    }

    pub fn validated(mut self) -> Result<Self, CompletionAuditLedgerError> {
        validate_completion_audit_string(
            "schema_version",
            &self.schema_version,
            MAX_COMPLETION_AUDIT_STRING_BYTES,
        )?;
        if self.schema_version != COMPLETION_AUDIT_LEDGER_SCHEMA_VERSION {
            return Err(CompletionAuditLedgerError::InvalidSchema {
                found: self.schema_version,
            });
        }
        validate_completion_audit_required_string("objective_id", &self.objective_id)?;
        validate_completion_audit_required_string("objective_summary", &self.objective_summary)?;
        if self.requirements.is_empty() {
            return Err(CompletionAuditLedgerError::EmptyRequirements);
        }
        if self.requirements.len() > MAX_COMPLETION_AUDIT_REQUIREMENTS {
            return Err(CompletionAuditLedgerError::TooManyRequirements {
                count: self.requirements.len(),
                max: MAX_COMPLETION_AUDIT_REQUIREMENTS,
            });
        }

        self.direct_evidence_count = 0;
        self.proxy_evidence_count = 0;
        for requirement in &mut self.requirements {
            requirement.validate_and_normalize()?;
            self.direct_evidence_count += requirement
                .evidence
                .iter()
                .filter(|evidence| evidence.coverage == CompletionAuditCoverage::Direct)
                .count();
            self.proxy_evidence_count += requirement
                .evidence
                .iter()
                .filter(|evidence| evidence.coverage == CompletionAuditCoverage::Proxy)
                .count();
        }
        self.requirements
            .sort_by(|left, right| left.requirement_id.cmp(&right.requirement_id));

        self.status = self
            .requirements
            .iter()
            .map(|requirement| requirement.status)
            .max()
            .unwrap_or(CompletionAuditLedgerStatus::MissingEvidence);
        let (reason_code, event_code, required_action) =
            completion_audit_status_contract(self.status);
        self.reason_code = reason_code.to_string();
        self.event_code = event_code.to_string();
        self.required_action = required_action.to_string();
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionAuditRequirement {
    pub requirement_id: String,
    pub requirement_text: String,
    pub status: CompletionAuditLedgerStatus,
    pub reason_code: String,
    pub required_action: String,
    pub evidence: Vec<CompletionAuditEvidenceRef>,
}

impl CompletionAuditRequirement {
    #[must_use]
    pub fn new(
        requirement_id: impl Into<String>,
        requirement_text: impl Into<String>,
        evidence: Vec<CompletionAuditEvidenceRef>,
    ) -> Self {
        Self {
            requirement_id: requirement_id.into(),
            requirement_text: requirement_text.into(),
            status: CompletionAuditLedgerStatus::MissingEvidence,
            reason_code: completion_audit_reason_codes::MISSING_EVIDENCE.to_string(),
            required_action: "collect_missing_evidence".to_string(),
            evidence,
        }
    }

    fn validate_and_normalize(&mut self) -> Result<(), CompletionAuditLedgerError> {
        validate_completion_audit_required_string("requirement_id", &self.requirement_id)?;
        validate_completion_audit_required_string("requirement_text", &self.requirement_text)?;
        if self.evidence.len() > MAX_COMPLETION_AUDIT_EVIDENCE_REFS {
            return Err(CompletionAuditLedgerError::TooManyEvidenceRefs {
                requirement_id: self.requirement_id.clone(),
                count: self.evidence.len(),
                max: MAX_COMPLETION_AUDIT_EVIDENCE_REFS,
            });
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        self.evidence
            .sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        self.status = derive_requirement_status(&self.evidence);
        let (reason_code, _event_code, required_action) =
            completion_audit_status_contract(self.status);
        self.reason_code = reason_code.to_string();
        self.required_action = required_action.to_string();
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionAuditEvidenceRef {
    pub evidence_id: String,
    pub kind: CompletionAuditEvidenceKind,
    pub coverage: CompletionAuditCoverage,
    pub status: CompletionAuditEvidenceStatus,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bead_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_mail_thread_id: Option<String>,
}

impl CompletionAuditEvidenceRef {
    #[must_use]
    pub fn new(
        evidence_id: impl Into<String>,
        kind: CompletionAuditEvidenceKind,
        coverage: CompletionAuditCoverage,
        status: CompletionAuditEvidenceStatus,
        description: impl Into<String>,
    ) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            kind,
            coverage,
            status,
            description: description.into(),
            path: None,
            command: None,
            bead_id: None,
            agent_mail_thread_id: None,
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
    pub fn with_bead_id(mut self, bead_id: impl Into<String>) -> Self {
        self.bead_id = Some(bead_id.into());
        self
    }

    #[must_use]
    pub fn with_agent_mail_thread_id(mut self, thread_id: impl Into<String>) -> Self {
        self.agent_mail_thread_id = Some(thread_id.into());
        self
    }

    fn validate(&self) -> Result<(), CompletionAuditLedgerError> {
        validate_completion_audit_required_string("evidence_id", &self.evidence_id)?;
        validate_completion_audit_required_string("description", &self.description)?;
        if let Some(path) = &self.path {
            validate_completion_audit_path("path", path)?;
        }
        if let Some(command) = &self.command {
            validate_completion_audit_required_string("command", command)?;
        }
        if let Some(bead_id) = &self.bead_id {
            validate_completion_audit_required_string("bead_id", bead_id)?;
        }
        if let Some(thread_id) = &self.agent_mail_thread_id {
            validate_completion_audit_required_string("agent_mail_thread_id", thread_id)?;
        }
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CompletionAuditLedgerError {
    #[error("ERR_VC_AUDIT_INVALID_SCHEMA: invalid completion audit schema {found}")]
    InvalidSchema { found: String },
    #[error("ERR_VC_AUDIT_EMPTY_REQUIREMENTS: completion audit must include requirements")]
    EmptyRequirements,
    #[error("ERR_VC_AUDIT_EMPTY_FIELD: {field} is required")]
    EmptyField { field: &'static str },
    #[error("ERR_VC_AUDIT_TOO_MANY_REQUIREMENTS: {count} requirements exceed max {max}")]
    TooManyRequirements { count: usize, max: usize },
    #[error(
        "ERR_VC_AUDIT_TOO_MANY_EVIDENCE_REFS: requirement {requirement_id} has {count} refs, max {max}"
    )]
    TooManyEvidenceRefs {
        requirement_id: String,
        count: usize,
        max: usize,
    },
    #[error("ERR_VC_AUDIT_STRING_TOO_LONG: {field} is {len} bytes, max {max}")]
    StringTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    #[error("ERR_VC_AUDIT_PATH_CONTAINS_NUL: {field} contains a NUL byte")]
    PathContainsNul { field: &'static str },
    #[error("ERR_VC_AUDIT_PATH_TRAVERSAL: {field} contains parent traversal")]
    PathTraversal { field: &'static str },
    #[error("ERR_VC_AUDIT_PROTECTED_PATH: {field} is protected workspace state: {path}")]
    ProtectedPath { field: &'static str, path: String },
}

impl CompletionAuditLedgerError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidSchema { .. } => "ERR_VC_AUDIT_INVALID_SCHEMA",
            Self::EmptyRequirements => "ERR_VC_AUDIT_EMPTY_REQUIREMENTS",
            Self::EmptyField { .. } => "ERR_VC_AUDIT_EMPTY_FIELD",
            Self::TooManyRequirements { .. } => "ERR_VC_AUDIT_TOO_MANY_REQUIREMENTS",
            Self::TooManyEvidenceRefs { .. } => "ERR_VC_AUDIT_TOO_MANY_EVIDENCE_REFS",
            Self::StringTooLong { .. } => "ERR_VC_AUDIT_STRING_TOO_LONG",
            Self::PathContainsNul { .. } => "ERR_VC_AUDIT_PATH_CONTAINS_NUL",
            Self::PathTraversal { .. } => "ERR_VC_AUDIT_PATH_TRAVERSAL",
            Self::ProtectedPath { .. } => "ERR_VC_AUDIT_PROTECTED_PATH",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCloseoutSwarmSchedulerEvidence {
    pub decision_id: String,
    pub trace_id: String,
    pub bead_id: String,
    pub agent: String,
    pub proof_work_key: String,
    pub scheduler_decision: String,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
    pub next_action: String,
    pub fairness_bucket: String,
    pub starvation_risk: String,
    pub queue_age_ms: u64,
    pub worker_id: Option<String>,
    pub coalescer_state: String,
    pub recorder_path: Option<String>,
    pub slo_breached: bool,
    pub retryable: bool,
    pub fail_closed: bool,
}

impl ValidationCloseoutSwarmSchedulerEvidence {
    #[must_use]
    pub fn from_decision(decision: &ValidationSwarmSchedulerDecision) -> Self {
        let required_action = decision.required_action.as_str().to_string();
        Self {
            decision_id: decision.decision_id.clone(),
            trace_id: decision.trace_id.clone(),
            bead_id: decision.bead_id.clone(),
            agent: decision.agent_name.clone(),
            proof_work_key: decision.diagnostics.proof_work_key_hex.clone(),
            scheduler_decision: decision.decision.as_str().to_string(),
            reason_code: decision.reason_code.clone(),
            event_code: decision.event_code.clone(),
            required_action: required_action.clone(),
            next_action: required_action,
            fairness_bucket: decision.fairness_bucket.as_str().to_string(),
            starvation_risk: decision.starvation_risk.as_str().to_string(),
            queue_age_ms: decision.diagnostics.queue_age_ms,
            worker_id: None,
            coalescer_state: decision.diagnostics.coalescer_state.as_str().to_string(),
            recorder_path: decision.diagnostics.recorder_path.clone(),
            slo_breached: swarm_scheduler_decision_breaches_slo(decision),
            retryable: decision.retryable,
            fail_closed: decision.fail_closed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCloseoutStructuredLog {
    pub ts: DateTime<Utc>,
    pub event: String,
    pub severity: String,
    pub detail: ValidationCloseoutStructuredLogDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCloseoutStructuredLogDetail {
    pub trace_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub receipt_id: String,
    pub receipt_path: String,
    pub status: String,
    pub proof_source: String,
    pub proof_work_key: Option<String>,
    pub lease_id: Option<String>,
    pub lease_path: Option<String>,
    pub lease_state: Option<String>,
    pub decision: Option<String>,
    pub reason_code: Option<String>,
    pub event_code: Option<String>,
    pub required_action: Option<String>,
    pub producer_agent: Option<String>,
    pub producer_bead_id: Option<String>,
    pub waiter_agent: Option<String>,
    pub coalescer_receipt_path: Option<String>,
    pub cache_key: Option<String>,
    pub scheduler_decision: Option<String>,
    pub scheduler_reason_code: Option<String>,
    pub scheduler_event_code: Option<String>,
    pub scheduler_required_action: Option<String>,
    pub scheduler_queue_age_ms: Option<u64>,
    pub scheduler_worker_id: Option<String>,
    pub scheduler_recorder_path: Option<String>,
    pub scheduler_fairness_bucket: Option<String>,
    pub scheduler_starvation_risk: Option<String>,
    pub scheduler_slo_breached: Option<bool>,
    pub completion_audit_status: Option<String>,
    pub completion_audit_reason_code: Option<String>,
    pub completion_audit_event_code: Option<String>,
    pub completion_audit_required_action: Option<String>,
    pub completion_audit_direct_evidence_count: Option<usize>,
    pub completion_audit_proxy_evidence_count: Option<usize>,
}

#[derive(Debug, Error)]
pub enum ValidationCloseoutError {
    #[error("bead_id is required")]
    MissingBeadId,
    #[error(
        "receipt bead_id mismatch: requested {requested}, receipt {receipt}, request_ref {request_ref}"
    )]
    BeadMismatch {
        requested: String,
        receipt: String,
        request_ref: String,
    },
    #[error("failed reading validation closeout output excerpt {path}: {source}")]
    ReadOutput {
        path: String,
        source: std::io::Error,
    },
    #[error("failed reading swarm scheduler decision {path}: {source}")]
    ReadSwarmSchedulerDecision {
        path: String,
        source: std::io::Error,
    },
    #[error("failed parsing swarm scheduler decision {path}: {source}")]
    ParseSwarmSchedulerDecision {
        path: String,
        source: serde_json::Error,
    },
    #[error("completion audit ledger failed validation: {0}")]
    CompletionAudit(#[from] CompletionAuditLedgerError),
    #[error("failed encoding validation closeout report JSON: {0}")]
    Encode(serde_json::Error),
}

pub fn read_closeout_output_text(path: &Path) -> Result<String, ValidationCloseoutError> {
    fs::read_to_string(path).map_err(|source| ValidationCloseoutError::ReadOutput {
        path: path.display().to_string(),
        source,
    })
}

pub fn read_swarm_scheduler_decision(
    path: &Path,
) -> Result<ValidationSwarmSchedulerDecision, ValidationCloseoutError> {
    let raw = fs::read_to_string(path).map_err(|source| {
        ValidationCloseoutError::ReadSwarmSchedulerDecision {
            path: path.display().to_string(),
            source,
        }
    })?;
    serde_json::from_str(&raw).map_err(|source| {
        ValidationCloseoutError::ParseSwarmSchedulerDecision {
            path: path.display().to_string(),
            source,
        }
    })
}

pub fn build_validation_closeout_report(
    receipt: &ValidationReceipt,
    options: &ValidationCloseoutOptions,
    now: DateTime<Utc>,
) -> Result<ValidationCloseoutReport, ValidationCloseoutError> {
    let bead_id = options.bead_id.trim();
    if bead_id.is_empty() {
        return Err(ValidationCloseoutError::MissingBeadId);
    }
    if receipt.bead_id != bead_id || receipt.request_ref.bead_id != bead_id {
        return Err(ValidationCloseoutError::BeadMismatch {
            requested: bead_id.to_string(),
            receipt: receipt.bead_id.clone(),
            request_ref: receipt.request_ref.bead_id.clone(),
        });
    }

    let validation_error = receipt.validate_at(now).err();
    let completion_audit = options
        .completion_audit
        .clone()
        .map(PromptToArtifactCompletionAuditLedger::validated)
        .transpose()?;
    let status = closeout_status(receipt, validation_error.as_ref());
    let mut warnings = closeout_warnings(receipt, validation_error.as_ref());
    if let Some(audit) = &completion_audit {
        warnings.extend(completion_audit_warnings(audit));
    }
    let summary = receipt_summary(receipt);
    let output_excerpts = closeout_output_excerpts(options);
    let proof_source = closeout_proof_source(receipt, options);
    let close_reason = render_close_reason(
        receipt,
        status,
        proof_source,
        options.proof_cache.as_ref(),
        options.proof_coalescer.as_ref(),
        options.swarm_scheduler.as_ref(),
        completion_audit.as_ref(),
        &warnings,
    );
    let agent_mail_markdown = render_agent_mail_markdown(
        receipt,
        status,
        proof_source,
        options.proof_cache.as_ref(),
        options.proof_coalescer.as_ref(),
        options.swarm_scheduler.as_ref(),
        completion_audit.as_ref(),
        &summary,
        &warnings,
        &output_excerpts,
    );

    Ok(ValidationCloseoutReport {
        schema_version: VALIDATION_CLOSEOUT_REPORT_SCHEMA_VERSION.to_string(),
        command: "ops validation-closeout".to_string(),
        trace_id: options.trace_id.clone(),
        generated_at_utc: now,
        bead_id: receipt.bead_id.clone(),
        thread_id: receipt.thread_id.clone(),
        receipt_id: receipt.receipt_id.clone(),
        request_id: receipt.request_id.clone(),
        status,
        status_label: status.as_str().to_string(),
        proof_source,
        proof_cache: options.proof_cache.clone(),
        proof_coalescer: options.proof_coalescer.clone(),
        swarm_scheduler: options.swarm_scheduler.clone(),
        completion_audit,
        readiness_ref: receipt.readiness_ref.clone(),
        close_reason,
        agent_mail_markdown,
        receipt: summary,
        warnings,
        output_excerpts,
    })
}

pub fn render_validation_closeout_json(
    report: &ValidationCloseoutReport,
) -> Result<String, ValidationCloseoutError> {
    serde_json::to_string_pretty(report).map_err(ValidationCloseoutError::Encode)
}

pub fn render_validation_closeout_structured_log_jsonl(
    report: &ValidationCloseoutReport,
) -> Result<String, ValidationCloseoutError> {
    let mut line = serde_json::to_string(&structured_log_for_closeout(report))
        .map_err(ValidationCloseoutError::Encode)?;
    line.push('\n');
    Ok(line)
}

pub fn render_validation_closeout_human(report: &ValidationCloseoutReport) -> String {
    report.agent_mail_markdown.clone()
}

#[must_use]
pub fn redact_output_excerpt(
    stream: impl Into<String>,
    text: &str,
    max_bytes: usize,
) -> ValidationCloseoutOutputExcerpt {
    let stream = stream.into();
    let original_bytes = text.len();
    if original_bytes <= max_bytes {
        return ValidationCloseoutOutputExcerpt {
            stream,
            text: text.to_string(),
            original_bytes,
            included_bytes: original_bytes,
            truncated: false,
        };
    }

    let mut excerpt = String::new();
    let mut included_bytes = 0usize;
    for ch in text.chars() {
        let next = included_bytes.saturating_add(ch.len_utf8());
        if next > max_bytes {
            break;
        }
        excerpt.push(ch);
        included_bytes = next;
    }
    excerpt.push_str("\n[truncated]");

    ValidationCloseoutOutputExcerpt {
        stream,
        text: excerpt,
        original_bytes,
        included_bytes,
        truncated: true,
    }
}

fn derive_requirement_status(
    evidence: &[CompletionAuditEvidenceRef],
) -> CompletionAuditLedgerStatus {
    if evidence.iter().any(|item| {
        item.coverage == CompletionAuditCoverage::Direct
            && item.status == CompletionAuditEvidenceStatus::Blocked
    }) {
        return CompletionAuditLedgerStatus::Blocked;
    }
    if evidence.iter().any(|item| {
        item.coverage == CompletionAuditCoverage::Direct
            && item.status == CompletionAuditEvidenceStatus::Stale
    }) {
        return CompletionAuditLedgerStatus::Stale;
    }
    if evidence.iter().any(|item| {
        item.coverage == CompletionAuditCoverage::Direct
            && item.status == CompletionAuditEvidenceStatus::Fresh
    }) {
        return CompletionAuditLedgerStatus::Proven;
    }
    if evidence.iter().any(|item| {
        item.coverage == CompletionAuditCoverage::Proxy
            && item.status == CompletionAuditEvidenceStatus::Fresh
    }) {
        return CompletionAuditLedgerStatus::ProxyOnly;
    }
    CompletionAuditLedgerStatus::MissingEvidence
}

fn completion_audit_status_contract(
    status: CompletionAuditLedgerStatus,
) -> (&'static str, &'static str, &'static str) {
    match status {
        CompletionAuditLedgerStatus::Proven => (
            completion_audit_reason_codes::PROVEN,
            completion_audit_event_codes::DIRECT_EVIDENCE_READY,
            "close_with_direct_evidence",
        ),
        CompletionAuditLedgerStatus::ProxyOnly => (
            completion_audit_reason_codes::PROXY_ONLY,
            completion_audit_event_codes::PROXY_EVIDENCE_ONLY,
            "replace_proxy_with_direct_evidence",
        ),
        CompletionAuditLedgerStatus::MissingEvidence => (
            completion_audit_reason_codes::MISSING_EVIDENCE,
            completion_audit_event_codes::EVIDENCE_MISSING,
            "collect_missing_evidence",
        ),
        CompletionAuditLedgerStatus::Stale => (
            completion_audit_reason_codes::STALE_EVIDENCE,
            completion_audit_event_codes::STALE_STATE,
            "refresh_stale_evidence",
        ),
        CompletionAuditLedgerStatus::Blocked => (
            completion_audit_reason_codes::BLOCKED_PROOF,
            completion_audit_event_codes::PROOF_BLOCKED,
            "record_blocker_and_retry",
        ),
    }
}

fn validate_completion_audit_required_string(
    field: &'static str,
    value: &str,
) -> Result<(), CompletionAuditLedgerError> {
    if value.trim().is_empty() {
        return Err(CompletionAuditLedgerError::EmptyField { field });
    }
    validate_completion_audit_string(field, value, MAX_COMPLETION_AUDIT_STRING_BYTES)
}

fn validate_completion_audit_string(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), CompletionAuditLedgerError> {
    let len = value.len();
    if len > max {
        return Err(CompletionAuditLedgerError::StringTooLong { field, len, max });
    }
    Ok(())
}

fn validate_completion_audit_path(
    field: &'static str,
    value: &str,
) -> Result<(), CompletionAuditLedgerError> {
    if value.trim().is_empty() {
        return Err(CompletionAuditLedgerError::EmptyField { field });
    }
    validate_completion_audit_string(field, value, MAX_COMPLETION_AUDIT_PATH_BYTES)?;
    if value.contains('\0') {
        return Err(CompletionAuditLedgerError::PathContainsNul { field });
    }
    if value.split(['/', '\\']).any(|component| component == "..") {
        return Err(CompletionAuditLedgerError::PathTraversal { field });
    }
    if path_is_protected_workspace_state(value) {
        return Err(CompletionAuditLedgerError::ProtectedPath {
            field,
            path: value.to_string(),
        });
    }
    Ok(())
}

fn path_is_protected_workspace_state(path: &str) -> bool {
    path.split(['/', '\\'])
        .any(|component| matches!(component, ".beads" | ".agent-mail" | "agent-mail"))
}

fn closeout_status(
    receipt: &ValidationReceipt,
    validation_error: Option<&ValidationBrokerError>,
) -> ValidationCloseoutStatus {
    if let Some(ValidationBrokerError::ContractViolation { code, .. }) = validation_error {
        if *code == error_codes::ERR_VB_STALE_RECEIPT {
            return ValidationCloseoutStatus::Stale;
        }
        return ValidationCloseoutStatus::Invalid;
    }
    if validation_error.is_some() {
        return ValidationCloseoutStatus::Invalid;
    }
    if receipt.classifications.source_only_fallback
        || receipt.exit.kind == ValidationExitKind::SourceOnly
    {
        return ValidationCloseoutStatus::SourceOnly;
    }
    match receipt.exit.kind {
        ValidationExitKind::Success => ValidationCloseoutStatus::Ready,
        ValidationExitKind::Failed
        | ValidationExitKind::Timeout
        | ValidationExitKind::Cancelled => ValidationCloseoutStatus::Blocked,
        ValidationExitKind::SourceOnly => ValidationCloseoutStatus::SourceOnly,
    }
}

fn closeout_warnings(
    receipt: &ValidationReceipt,
    validation_error: Option<&ValidationBrokerError>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(error) = validation_error {
        if let ValidationBrokerError::ContractViolation { code, .. } = error
            && *code == error_codes::ERR_VB_STALE_RECEIPT
        {
            warnings.push("stale validation receipt is not closeout evidence".to_string());
        }
        warnings.push(format!("receipt validation failed: {error}"));
    }
    if receipt.rch.require_remote && receipt.rch.mode != RchMode::Remote {
        warnings.push("receipt required remote RCH but did not run remotely".to_string());
    }
    if receipt.rch.mode == RchMode::Remote
        && receipt.rch.worker_id.as_deref().unwrap_or("").is_empty()
    {
        warnings.push("remote RCH receipt is missing worker_id".to_string());
    }
    if let Some(reason) = receipt.classifications.source_only_reason {
        warnings.push(format!(
            "source-only fallback recorded: {}",
            reason.as_str()
        ));
    }
    if receipt.exit.retryable {
        warnings.push(
            "validation result is retryable; prefer a fresh proof before closeout".to_string(),
        );
    }
    warnings
}

fn completion_audit_warnings(audit: &PromptToArtifactCompletionAuditLedger) -> Vec<String> {
    if audit.status == CompletionAuditLedgerStatus::Proven {
        return Vec::new();
    }
    vec![format!(
        "completion audit is {}; green closeout requires direct evidence for every requirement",
        audit.status.as_str()
    )]
}

fn receipt_summary(receipt: &ValidationReceipt) -> ValidationCloseoutReceiptSummary {
    ValidationCloseoutReceiptSummary {
        schema_version: receipt.schema_version.clone(),
        command_line: command_line(&receipt.command.program, &receipt.command.argv),
        command_digest: format!(
            "{}:{}",
            receipt.command_digest.algorithm, receipt.command_digest.hex
        ),
        exit_kind: exit_kind_label(receipt.exit.kind).to_string(),
        exit_code: receipt.exit.code,
        timeout_class: timeout_class_label(receipt.exit.timeout_class).to_string(),
        error_class: error_class_label(receipt.exit.error_class).to_string(),
        retryable: receipt.exit.retryable,
        rch_mode: rch_mode_label(receipt.rch.mode).to_string(),
        rch_worker_id: receipt.rch.worker_id.clone(),
        rch_remote_required: receipt.rch.require_remote,
        source_only_reason: receipt
            .classifications
            .source_only_reason
            .map(|reason| reason.as_str().to_string()),
        readiness_ref: receipt.readiness_ref.clone(),
        artifact_stdout_path: receipt.artifacts.stdout_path.clone(),
        artifact_stderr_path: receipt.artifacts.stderr_path.clone(),
        artifact_summary_path: receipt.artifacts.summary_path.clone(),
        artifact_receipt_path: receipt.artifacts.receipt_path.clone(),
        started_at_utc: receipt.timing.started_at,
        finished_at_utc: receipt.timing.finished_at,
        freshness_expires_at_utc: receipt.timing.freshness_expires_at,
        duration_ms: receipt.timing.duration_ms,
        generated_by: receipt.trust.generated_by.clone(),
        agent_name: receipt.trust.agent_name.clone(),
        git_commit: receipt.trust.git_commit.clone(),
        dirty_worktree: receipt.trust.dirty_worktree,
    }
}

fn closeout_output_excerpts(
    options: &ValidationCloseoutOptions,
) -> Vec<ValidationCloseoutOutputExcerpt> {
    let mut excerpts = Vec::new();
    if let Some(stdout) = &options.stdout_text {
        excerpts.push(redact_output_excerpt(
            "stdout",
            stdout,
            options.max_output_excerpt_bytes,
        ));
    }
    if let Some(stderr) = &options.stderr_text {
        excerpts.push(redact_output_excerpt(
            "stderr",
            stderr,
            options.max_output_excerpt_bytes,
        ));
    }
    excerpts
}

fn structured_log_for_closeout(
    report: &ValidationCloseoutReport,
) -> ValidationCloseoutStructuredLog {
    let coalescer = report.proof_coalescer.as_ref();
    let scheduler = report.swarm_scheduler.as_ref();
    let audit = report.completion_audit.as_ref();
    ValidationCloseoutStructuredLog {
        ts: report.generated_at_utc,
        event: "validation_closeout".to_string(),
        severity: closeout_log_severity(report.status).to_string(),
        detail: ValidationCloseoutStructuredLogDetail {
            trace_id: report.trace_id.clone(),
            bead_id: report.bead_id.clone(),
            thread_id: report.thread_id.clone(),
            receipt_id: report.receipt_id.clone(),
            receipt_path: report.receipt.artifact_receipt_path.clone(),
            status: report.status.as_str().to_string(),
            proof_source: report.proof_source.as_str().to_string(),
            proof_work_key: coalescer.map(|evidence| evidence.proof_work_key_hex.clone()),
            lease_id: coalescer.map(|evidence| evidence.lease_id.clone()),
            lease_path: coalescer.map(|evidence| evidence.lease_path.clone()),
            lease_state: coalescer.map(|evidence| evidence.lease_state.clone()),
            decision: coalescer.map(|evidence| evidence.decision_id.clone()),
            reason_code: coalescer.map(|evidence| evidence.reason_code.clone()),
            event_code: coalescer.map(|evidence| evidence.event_code.clone()),
            required_action: coalescer.map(|evidence| evidence.required_action.clone()),
            producer_agent: coalescer.map(|evidence| evidence.producer_agent.clone()),
            producer_bead_id: coalescer.map(|evidence| evidence.producer_bead_id.clone()),
            waiter_agent: coalescer.and_then(|evidence| evidence.waiter_agent.clone()),
            coalescer_receipt_path: coalescer.and_then(|evidence| evidence.receipt_path.clone()),
            cache_key: coalescer.map(|evidence| evidence.proof_cache_key_hex.clone()),
            scheduler_decision: scheduler.map(|evidence| evidence.scheduler_decision.clone()),
            scheduler_reason_code: scheduler.map(|evidence| evidence.reason_code.clone()),
            scheduler_event_code: scheduler.map(|evidence| evidence.event_code.clone()),
            scheduler_required_action: scheduler.map(|evidence| evidence.required_action.clone()),
            scheduler_queue_age_ms: scheduler.map(|evidence| evidence.queue_age_ms),
            scheduler_worker_id: scheduler.and_then(|evidence| evidence.worker_id.clone()),
            scheduler_recorder_path: scheduler.and_then(|evidence| evidence.recorder_path.clone()),
            scheduler_fairness_bucket: scheduler.map(|evidence| evidence.fairness_bucket.clone()),
            scheduler_starvation_risk: scheduler.map(|evidence| evidence.starvation_risk.clone()),
            scheduler_slo_breached: scheduler.map(|evidence| evidence.slo_breached),
            completion_audit_status: audit.map(|evidence| evidence.status.as_str().to_string()),
            completion_audit_reason_code: audit.map(|evidence| evidence.reason_code.clone()),
            completion_audit_event_code: audit.map(|evidence| evidence.event_code.clone()),
            completion_audit_required_action: audit
                .map(|evidence| evidence.required_action.clone()),
            completion_audit_direct_evidence_count: audit
                .map(|evidence| evidence.direct_evidence_count),
            completion_audit_proxy_evidence_count: audit
                .map(|evidence| evidence.proxy_evidence_count),
        },
    }
}

fn swarm_scheduler_decision_breaches_slo(decision: &ValidationSwarmSchedulerDecision) -> bool {
    decision.starvation_risk.breaches_slo()
        || decision.fail_closed
        || matches!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::FailClosedProduct
                | ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact
        )
}

const fn closeout_log_severity(status: ValidationCloseoutStatus) -> &'static str {
    match status {
        ValidationCloseoutStatus::Ready => "info",
        ValidationCloseoutStatus::SourceOnly | ValidationCloseoutStatus::Stale => "warn",
        ValidationCloseoutStatus::Blocked | ValidationCloseoutStatus::Invalid => "error",
    }
}

fn render_close_reason(
    receipt: &ValidationReceipt,
    status: ValidationCloseoutStatus,
    proof_source: ProofEvidenceSource,
    proof_cache: Option<&ValidationProofCacheReuseEvidence>,
    proof_coalescer: Option<&ValidationProofCoalescerEvidence>,
    swarm_scheduler: Option<&ValidationCloseoutSwarmSchedulerEvidence>,
    completion_audit: Option<&PromptToArtifactCompletionAuditLedger>,
    warnings: &[String],
) -> String {
    let worker = receipt.rch.worker_id.as_deref().unwrap_or("unknown-worker");
    let exit = exit_kind_label(receipt.exit.kind);
    let error = error_class_label(receipt.exit.error_class);
    let command = command_line(&receipt.command.program, &receipt.command.argv);
    let warning_suffix = if warnings.is_empty() {
        String::new()
    } else {
        format!(" warnings={}", warnings.join(" | "))
    };
    let cache_suffix = proof_cache.map_or_else(String::new, |cache| {
        format!(
            " cache_key={} cache_receipt={} cache_entry={}",
            cache.cache_key_hex, cache.receipt_path, cache.entry_path
        )
    });
    let coalescer_suffix = proof_coalescer.map_or_else(String::new, |coalescer| {
        format!(
            " coalescer_decision={} lease_id={} lease_path={} lease_state={} producer={} producer_bead={} waiter={} trace_id={} coalescer_receipt={} coalescer_cache_key={} coalescer_reason={} coalescer_action={} coalescer_event={}",
            coalescer.decision_id,
            coalescer.lease_id,
            coalescer.lease_path,
            coalescer.lease_state,
            coalescer.producer_agent,
            coalescer.producer_bead_id,
            coalescer.waiter_agent.as_deref().unwrap_or("none"),
            coalescer.trace_id,
            coalescer.receipt_path.as_deref().unwrap_or("none"),
            coalescer.proof_cache_key_hex,
            coalescer.reason_code,
            coalescer.required_action,
            coalescer.event_code
        )
    });
    let scheduler_suffix = swarm_scheduler.map_or_else(String::new, |scheduler| {
        format!(
            " scheduler_decision={} scheduler_reason={} scheduler_action={} scheduler_event={} scheduler_queue_age_ms={} scheduler_fairness_bucket={} scheduler_starvation_risk={} scheduler_slo_breached={} scheduler_recorder={} scheduler_proof_work_key={}",
            scheduler.scheduler_decision,
            scheduler.reason_code,
            scheduler.next_action,
            scheduler.event_code,
            scheduler.queue_age_ms,
            scheduler.fairness_bucket,
            scheduler.starvation_risk,
            scheduler.slo_breached,
            scheduler.recorder_path.as_deref().unwrap_or("none"),
            scheduler.proof_work_key
        )
    });
    let readiness_suffix = receipt.readiness_ref.as_ref().map_or_else(String::new, |ref_| {
        format!(
            " readiness_ref={} readiness_digest={}:{} readiness_reason={} readiness_action={} readiness_fresh_until={}",
            ref_.path,
            ref_.digest.algorithm,
            ref_.digest.hex,
            ref_.reason_code,
            ref_.required_action,
            ref_.freshness_expires_at.to_rfc3339()
        )
    });
    let completion_audit_suffix = completion_audit.map_or_else(String::new, |audit| {
        format!(
            " completion_audit_status={} completion_audit_reason={} completion_audit_action={} completion_audit_direct={} completion_audit_proxy={}",
            audit.status.as_str(),
            audit.reason_code,
            audit.required_action,
            audit.direct_evidence_count,
            audit.proxy_evidence_count
        )
    });
    format!(
        "{} validation receipt {} status={} proof_source={} exit={} error_class={} worker={} command=\"{}\" artifacts={}{}{}{}{}{}{}",
        receipt.bead_id,
        receipt.receipt_id,
        status.as_str(),
        proof_source.as_str(),
        exit,
        error,
        worker,
        command,
        receipt.artifacts.summary_path,
        cache_suffix,
        coalescer_suffix,
        scheduler_suffix,
        readiness_suffix,
        completion_audit_suffix,
        warning_suffix
    )
}

fn render_agent_mail_markdown(
    receipt: &ValidationReceipt,
    status: ValidationCloseoutStatus,
    proof_source: ProofEvidenceSource,
    proof_cache: Option<&ValidationProofCacheReuseEvidence>,
    proof_coalescer: Option<&ValidationProofCoalescerEvidence>,
    swarm_scheduler: Option<&ValidationCloseoutSwarmSchedulerEvidence>,
    completion_audit: Option<&PromptToArtifactCompletionAuditLedger>,
    summary: &ValidationCloseoutReceiptSummary,
    warnings: &[String],
    output_excerpts: &[ValidationCloseoutOutputExcerpt],
) -> String {
    let mut lines = vec![
        format!(
            "`{}` validation closeout: `{}`",
            receipt.bead_id,
            status.as_str()
        ),
        String::new(),
        format!("- receipt: `{}`", receipt.receipt_id),
        format!("- request: `{}`", receipt.request_id),
        format!("- proof_source: `{}`", proof_source.as_str()),
        format!("- command: `{}`", summary.command_line),
        format!(
            "- exit: `{}` code={:?} error_class=`{}` timeout_class=`{}` retryable={}",
            summary.exit_kind,
            summary.exit_code,
            summary.error_class,
            summary.timeout_class,
            summary.retryable
        ),
        format!(
            "- rch: mode=`{}` worker=`{}` remote_required={}",
            summary.rch_mode,
            summary.rch_worker_id.as_deref().unwrap_or(""),
            summary.rch_remote_required
        ),
        format!("- summary_artifact: `{}`", summary.artifact_summary_path),
        format!("- receipt_artifact: `{}`", summary.artifact_receipt_path),
    ];

    if let Some(cache) = proof_cache {
        lines.push(format!("- proof_cache_decision: `{}`", cache.decision_id));
        lines.push(format!("- proof_cache_key: `{}`", cache.cache_key_hex));
        lines.push(format!("- proof_cache_entry: `{}`", cache.entry_path));
        lines.push(format!("- proof_cache_receipt: `{}`", cache.receipt_path));
        lines.push(format!(
            "- proof_cache_reason: `{}` action=`{}` event=`{}`",
            cache.reason_code, cache.required_action, cache.event_code
        ));
    }

    if let Some(coalescer) = proof_coalescer {
        lines.push(format!(
            "- proof_coalescer_decision: `{}`",
            coalescer.decision_id
        ));
        lines.push(format!(
            "- proof_work_key: `{}`",
            coalescer.proof_work_key_hex
        ));
        lines.push(format!(
            "- proof_coalescer_lease: `{}` id=`{}` state=`{}`",
            coalescer.lease_path, coalescer.lease_id, coalescer.lease_state
        ));
        lines.push(format!(
            "- proof_coalescer_producer: `{}` bead=`{}`",
            coalescer.producer_agent, coalescer.producer_bead_id
        ));
        lines.push(format!(
            "- proof_coalescer_waiter: `{}`",
            coalescer.waiter_agent.as_deref().unwrap_or("none")
        ));
        lines.push(format!("- proof_coalescer_trace: `{}`", coalescer.trace_id));
        lines.push(format!(
            "- proof_coalescer_receipt: `{}` cache_key=`{}`",
            coalescer.receipt_path.as_deref().unwrap_or("none"),
            coalescer.proof_cache_key_hex
        ));
        lines.push(format!(
            "- proof_coalescer_reason: `{}` action=`{}` event=`{}`",
            coalescer.reason_code, coalescer.required_action, coalescer.event_code
        ));
    }

    if let Some(scheduler) = swarm_scheduler {
        lines.push(format!(
            "- swarm_scheduler_decision: `{}`",
            scheduler.scheduler_decision
        ));
        lines.push(format!(
            "- swarm_scheduler_owner: agent=`{}` bead=`{}` trace=`{}`",
            scheduler.agent, scheduler.bead_id, scheduler.trace_id
        ));
        lines.push(format!(
            "- swarm_scheduler_work: proof_work_key=`{}` queue_age_ms={} coalescer_state=`{}` recorder=`{}`",
            scheduler.proof_work_key,
            scheduler.queue_age_ms,
            scheduler.coalescer_state,
            scheduler.recorder_path.as_deref().unwrap_or("none")
        ));
        lines.push(format!(
            "- swarm_scheduler_slo: fairness_bucket=`{}` starvation_risk=`{}` breached={}",
            scheduler.fairness_bucket, scheduler.starvation_risk, scheduler.slo_breached
        ));
        lines.push(format!(
            "- swarm_scheduler_reason: `{}` action=`{}` event=`{}`",
            scheduler.reason_code, scheduler.next_action, scheduler.event_code
        ));
    }

    if let Some(readiness_ref) = &summary.readiness_ref {
        lines.push(format!("- readiness_ref: `{}`", readiness_ref.path));
        lines.push(format!(
            "- readiness_digest: `{}:{}`",
            readiness_ref.digest.algorithm, readiness_ref.digest.hex
        ));
        lines.push(format!(
            "- readiness_reason: `{}` action=`{}` event=`{}`",
            readiness_ref.reason_code, readiness_ref.required_action, readiness_ref.event_code
        ));
        lines.push(format!(
            "- readiness_fresh_until: `{}`",
            readiness_ref.freshness_expires_at.to_rfc3339()
        ));
    }

    if let Some(audit) = completion_audit {
        lines.push(format!(
            "- completion_audit: status=`{}` reason=`{}` action=`{}` direct={} proxy={}",
            audit.status.as_str(),
            audit.reason_code,
            audit.required_action,
            audit.direct_evidence_count,
            audit.proxy_evidence_count
        ));
        for requirement in &audit.requirements {
            lines.push(format!(
                "  - requirement `{}`: status=`{}` reason=`{}` evidence={}",
                requirement.requirement_id,
                requirement.status.as_str(),
                requirement.reason_code,
                requirement.evidence.len()
            ));
        }
    }

    if warnings.is_empty() {
        lines.push("- warnings: none".to_string());
    } else {
        lines.push("- warnings:".to_string());
        for warning in warnings {
            lines.push(format!("  - {warning}"));
        }
    }

    for excerpt in output_excerpts {
        lines.push(String::new());
        lines.push(format!(
            "{} excerpt ({} / {} bytes{}):",
            excerpt.stream,
            excerpt.included_bytes,
            excerpt.original_bytes,
            if excerpt.truncated { ", truncated" } else { "" }
        ));
        lines.push("```text".to_string());
        lines.push(excerpt.text.clone());
        lines.push("```".to_string());
    }

    lines.join("\n")
}

fn closeout_proof_source(
    receipt: &ValidationReceipt,
    options: &ValidationCloseoutOptions,
) -> ProofEvidenceSource {
    if options.proof_cache.is_some() || options.proof_source == ProofEvidenceSource::ProofCacheHit {
        ProofEvidenceSource::ProofCacheHit
    } else if receipt.classifications.source_only_fallback
        || receipt.exit.kind == ValidationExitKind::SourceOnly
    {
        ProofEvidenceSource::SourceOnlyFallback
    } else {
        options.proof_source
    }
}

fn command_line(program: &str, argv: &[String]) -> String {
    if argv.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", argv.join(" "))
    }
}

const fn exit_kind_label(kind: ValidationExitKind) -> &'static str {
    match kind {
        ValidationExitKind::Success => "success",
        ValidationExitKind::Failed => "failed",
        ValidationExitKind::Timeout => "timeout",
        ValidationExitKind::SourceOnly => "source_only",
        ValidationExitKind::Cancelled => "cancelled",
    }
}

const fn timeout_class_label(
    timeout_class: crate::ops::validation_broker::TimeoutClass,
) -> &'static str {
    match timeout_class {
        crate::ops::validation_broker::TimeoutClass::None => "none",
        crate::ops::validation_broker::TimeoutClass::QueueWait => "queue_wait",
        crate::ops::validation_broker::TimeoutClass::RchDispatch => "rch_dispatch",
        crate::ops::validation_broker::TimeoutClass::SshCommand => "ssh_command",
        crate::ops::validation_broker::TimeoutClass::CargoTestTimeout => "cargo_test_timeout",
        crate::ops::validation_broker::TimeoutClass::ProcessIdle => "process_idle",
        crate::ops::validation_broker::TimeoutClass::ProcessWall => "process_wall",
        crate::ops::validation_broker::TimeoutClass::WorkerUnreachable => "worker_unreachable",
        crate::ops::validation_broker::TimeoutClass::Unknown => "unknown",
    }
}

const fn error_class_label(error_class: ValidationErrorClass) -> &'static str {
    match error_class {
        ValidationErrorClass::None => "none",
        ValidationErrorClass::CompileError => "compile_error",
        ValidationErrorClass::TestFailure => "test_failure",
        ValidationErrorClass::ClippyWarning => "clippy_warning",
        ValidationErrorClass::FormatFailure => "format_failure",
        ValidationErrorClass::TransportTimeout => "transport_timeout",
        ValidationErrorClass::WorkerInfra => "worker_infra",
        ValidationErrorClass::EnvironmentContention => "environment_contention",
        ValidationErrorClass::DiskPressure => "disk_pressure",
        ValidationErrorClass::SourceOnly => "source_only",
        ValidationErrorClass::Unknown => "unknown",
    }
}

const fn rch_mode_label(mode: RchMode) -> &'static str {
    match mode {
        RchMode::Remote => "remote",
        RchMode::LocalFallback => "local_fallback",
        RchMode::NotUsed => "not_used",
        RchMode::Unavailable => "unavailable",
    }
}
