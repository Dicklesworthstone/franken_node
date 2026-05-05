//! Validation receipt closeout summaries for Beads and Agent Mail.
//!
//! This module turns a validated broker receipt into deterministic text that
//! agents can paste into `br close --reason` and Agent Mail completion replies.

use crate::ops::validation_broker::{
    RchMode, ValidationBrokerError, ValidationErrorClass, ValidationExitKind, ValidationReceipt,
    error_codes,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

pub const VALIDATION_CLOSEOUT_REPORT_SCHEMA_VERSION: &str =
    "franken-node/validation-closeout/report/v1";
pub const DEFAULT_MAX_OUTPUT_EXCERPT_BYTES: usize = 4096;

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
            stdout_text: None,
            stderr_text: None,
        }
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
    #[error("failed encoding validation closeout report JSON: {0}")]
    Encode(serde_json::Error),
}

pub fn read_closeout_output_text(path: &Path) -> Result<String, ValidationCloseoutError> {
    fs::read_to_string(path).map_err(|source| ValidationCloseoutError::ReadOutput {
        path: path.display().to_string(),
        source,
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
    let status = closeout_status(receipt, validation_error.as_ref());
    let warnings = closeout_warnings(receipt, validation_error.as_ref());
    let summary = receipt_summary(receipt);
    let output_excerpts = closeout_output_excerpts(options);
    let close_reason = render_close_reason(receipt, status, &warnings);
    let agent_mail_markdown =
        render_agent_mail_markdown(receipt, status, &summary, &warnings, &output_excerpts);

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

fn render_close_reason(
    receipt: &ValidationReceipt,
    status: ValidationCloseoutStatus,
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
    format!(
        "{} validation receipt {} status={} exit={} error_class={} worker={} command=\"{}\" artifacts={}{}",
        receipt.bead_id,
        receipt.receipt_id,
        status.as_str(),
        exit,
        error,
        worker,
        command,
        receipt.artifacts.summary_path,
        warning_suffix
    )
}

fn render_agent_mail_markdown(
    receipt: &ValidationReceipt,
    status: ValidationCloseoutStatus,
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
