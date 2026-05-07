//! Operator-facing validation readiness reporting.
//!
//! This module aggregates validation-broker receipts, proof statuses, Beads
//! state, worker observations, and resource-governor hints into a stable report
//! that explains whether validation evidence is trustworthy right now.

use crate::ops::validation_broker::{
    DigestRef, ProofEvidenceSource, ProofStatusKind, RchMode, SourceOnlyReason,
    ValidationErrorClass, ValidationExitKind, ValidationProofStatus, ValidationReceipt,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub const VALIDATION_READINESS_INPUT_SCHEMA_VERSION: &str =
    "franken-node/validation-readiness/input/v1";
pub const VALIDATION_READINESS_REPORT_SCHEMA_VERSION: &str =
    "franken-node/validation-readiness/report/v1";
pub const VALIDATION_READINESS_FIXTURE_SCHEMA_VERSION: &str =
    "franken-node/validation-readiness/fixtures/v1";
pub const PROOF_LANE_READINESS_CAPSULE_SCHEMA_VERSION: &str =
    "franken-node/proof-lane-readiness/capsule/v1";
pub const PROOF_LANE_READINESS_DECISION_SCHEMA_VERSION: &str =
    "franken-node/proof-lane-readiness/decision/v1";
pub const PROOF_LANE_READINESS_FIXTURE_SCHEMA_VERSION: &str =
    "franken-node/proof-lane-readiness/fixtures/v1";
pub const DEFAULT_MAX_RECEIPT_AGE_SECS: u64 = 60 * 60 * 24;
pub const MAX_PROOF_LANE_WORKERS: usize = 32;
pub const MAX_PROOF_LANE_ARGS: usize = 64;
pub const MAX_PROOF_LANE_STRING_BYTES: usize = 512;
pub const MAX_PROOF_LANE_DETAIL_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationReadinessStatus {
    Pass,
    Warn,
    Fail,
}

impl ValidationReadinessStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Warn => 1,
            Self::Fail => 2,
        }
    }

    const fn max(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationBeadState {
    Open,
    InProgress,
    Blocked,
    Closed,
}

impl ValidationBeadState {
    const fn is_untrusted_without_receipt(self) -> bool {
        matches!(self, Self::Blocked | Self::Closed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedValidationBead {
    pub bead_id: String,
    #[serde(default)]
    pub thread_id: String,
    pub state: ValidationBeadState,
    #[serde(default = "default_requires_receipt")]
    pub requires_receipt: bool,
    #[serde(default)]
    pub source_only_waiver: Option<SourceOnlyReason>,
}

impl TrackedValidationBead {
    #[must_use]
    pub fn new(bead_id: impl Into<String>, state: ValidationBeadState) -> Self {
        let bead_id = bead_id.into();
        Self {
            thread_id: bead_id.clone(),
            bead_id,
            state,
            requires_receipt: true,
            source_only_waiver: None,
        }
    }

    #[must_use]
    pub fn with_source_only_waiver(mut self, reason: SourceOnlyReason) -> Self {
        self.source_only_waiver = Some(reason);
        self
    }

    fn normalized_thread_id(&self) -> &str {
        if self.thread_id.trim().is_empty() {
            &self.bead_id
        } else {
            &self.thread_id
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceContentionSnapshot {
    pub decision: String,
    pub reason_code: String,
    pub reason: String,
    #[serde(default)]
    pub rch_queue_depth: Option<u64>,
    #[serde(default)]
    pub active_proof_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchWorkerReadiness {
    pub worker_id: String,
    pub reachable: bool,
    pub mode: RchMode,
    #[serde(default)]
    pub required_toolchains: Vec<String>,
    #[serde(default)]
    pub observed_toolchains: Vec<String>,
    #[serde(default)]
    pub failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReadinessInput {
    #[serde(default = "default_input_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub tracked_beads: Vec<TrackedValidationBead>,
    #[serde(default)]
    pub proof_statuses: Vec<ValidationProofStatus>,
    #[serde(default)]
    pub receipts: Vec<ValidationReceipt>,
    #[serde(default)]
    pub rch_workers: Vec<RchWorkerReadiness>,
    #[serde(default)]
    pub resource_governor: Option<ResourceContentionSnapshot>,
    #[serde(default = "default_max_receipt_age_secs")]
    pub max_receipt_age_secs: u64,
}

impl Default for ValidationReadinessInput {
    fn default() -> Self {
        Self {
            schema_version: VALIDATION_READINESS_INPUT_SCHEMA_VERSION.to_string(),
            tracked_beads: Vec::new(),
            proof_statuses: Vec::new(),
            receipts: Vec::new(),
            rch_workers: Vec::new(),
            resource_governor: None,
            max_receipt_age_secs: DEFAULT_MAX_RECEIPT_AGE_SECS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReadinessCheck {
    pub code: String,
    pub event_code: String,
    pub scope: String,
    pub status: ValidationReadinessStatus,
    pub message: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReadinessStatusCounts {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofKindCounts {
    pub queued: usize,
    pub leased: usize,
    pub running: usize,
    pub reused: usize,
    pub passed: usize,
    pub failed: usize,
    pub source_only: usize,
    pub cancelled: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationFailureDomain {
    None,
    Product,
    Worker,
    Resource,
    Unknown,
}

pub mod proof_lane_reason_codes {
    pub const HEALTHY_SAME_TOOLCHAIN_LANE: &str = "PLR_HEALTHY_SAME_TOOLCHAIN_LANE";
    pub const OVERRIDE_NOT_HONORED: &str = "PLR_OVERRIDE_NOT_HONORED";
    pub const SAME_TOOLCHAIN_MISSING: &str = "PLR_SAME_TOOLCHAIN_MISSING";
    pub const WORKER_AUTH_FAILED: &str = "PLR_WORKER_AUTH_FAILED";
    pub const WORKER_CAPABILITY_UNKNOWN: &str = "PLR_WORKER_CAPABILITY_UNKNOWN";
    pub const WORKER_PRESSURE_BLOCKED: &str = "PLR_WORKER_PRESSURE_BLOCKED";
    pub const LOCAL_FALLBACK_REFUSED: &str = "PLR_LOCAL_FALLBACK_REFUSED";
    pub const STALE_READINESS_CAPSULE: &str = "PLR_STALE_READINESS_CAPSULE";
    pub const MALFORMED_READINESS_INPUT: &str = "PLR_MALFORMED_READINESS_INPUT";
}

pub mod proof_lane_event_codes {
    pub const HEALTHY_SAME_TOOLCHAIN_LANE: &str = "PLR-001";
    pub const OVERRIDE_NOT_HONORED: &str = "PLR-002";
    pub const SAME_TOOLCHAIN_MISSING: &str = "PLR-003";
    pub const WORKER_AUTH_FAILED: &str = "PLR-004";
    pub const WORKER_CAPABILITY_UNKNOWN: &str = "PLR-005";
    pub const WORKER_PRESSURE_BLOCKED: &str = "PLR-006";
    pub const LOCAL_FALLBACK_REFUSED: &str = "PLR-007";
    pub const STALE_READINESS_CAPSULE: &str = "PLR-008";
    pub const MALFORMED_READINESS_INPUT: &str = "PLR-009";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLaneReadinessDecisionKind {
    ReadyToLaunch,
    QueueUntilReady,
    RetryPreflight,
    SourceOnlyBlocker,
    FailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLaneWorkerAuthStatus {
    NotChecked,
    Ok,
    PermissionDenied,
    Timeout,
    Unreachable,
    Unknown,
}

impl ProofLaneWorkerAuthStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Ok => "ok",
            Self::PermissionDenied => "permission_denied",
            Self::Timeout => "timeout",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }

    const fn blocks_launch(self) -> bool {
        !matches!(self, Self::Ok)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLaneCapabilityStatus {
    Fresh,
    Stale,
    Missing,
    Malformed,
    Unknown,
}

impl ProofLaneCapabilityStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLanePressureStatus {
    Healthy,
    Warning,
    Blocked,
    TelemetryGap,
    Unknown,
}

impl ProofLanePressureStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Blocked => "blocked",
            Self::TelemetryGap => "telemetry_gap",
            Self::Unknown => "unknown",
        }
    }

    const fn blocks_launch(self) -> bool {
        matches!(self, Self::Blocked | Self::TelemetryGap | Self::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneReadinessProducer {
    pub name: String,
    pub agent_name: String,
    pub git_commit: String,
    pub dirty_worktree: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneCommandIntent {
    pub program: String,
    #[serde(default)]
    pub argv: Vec<String>,
    pub cwd: String,
    pub digest: DigestRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneRchSnapshot {
    pub daemon_source: String,
    pub daemon_version: String,
    pub socket_path: String,
    pub require_remote: bool,
    pub local_fallback_allowed: bool,
    pub local_fallback_refused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneWorkerSelection {
    #[serde(default)]
    pub requested_workers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_worker: Option<String>,
    pub override_effective: bool,
    pub selection_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneToolchainRequirement {
    pub local_rustc: String,
    pub required_toolchain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneWorkerCapability {
    pub auth_status: ProofLaneWorkerAuthStatus,
    pub capability_status: ProofLaneCapabilityStatus,
    pub pressure_status: ProofLanePressureStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rustc: Option<String>,
    #[serde(default)]
    pub observed_toolchains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneToolchainSnapshot {
    pub local_rustc: String,
    pub required_toolchain: String,
    pub selected_worker_rustc: String,
    pub same_toolchain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneWorkerAccessSnapshot {
    pub auth_status: ProofLaneWorkerAuthStatus,
    pub capability_status: ProofLaneCapabilityStatus,
    pub pressure_status: ProofLanePressureStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneReadinessInput {
    pub capsule_id: String,
    pub trace_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub created_at: DateTime<Utc>,
    pub freshness_expires_at: DateTime<Utc>,
    pub producer: ProofLaneReadinessProducer,
    pub command: ProofLaneCommandIntent,
    pub rch: ProofLaneRchSnapshot,
    pub worker_selection: ProofLaneWorkerSelection,
    pub toolchain: ProofLaneToolchainRequirement,
    #[serde(default)]
    pub worker_capabilities: BTreeMap<String, ProofLaneWorkerCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_validation_error_class: Option<ValidationErrorClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneReadinessDecision {
    pub schema_version: String,
    pub decision: ProofLaneReadinessDecisionKind,
    pub reason_code: String,
    pub event_code: String,
    pub retryable: bool,
    pub fail_closed: bool,
    pub required_action: String,
    pub operator_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneReadinessCapsule {
    pub schema_version: String,
    pub capsule_id: String,
    pub trace_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub created_at: DateTime<Utc>,
    pub freshness_expires_at: DateTime<Utc>,
    pub producer: ProofLaneReadinessProducer,
    pub command: ProofLaneCommandIntent,
    pub rch: ProofLaneRchSnapshot,
    pub worker_selection: ProofLaneWorkerSelection,
    pub toolchain: ProofLaneToolchainSnapshot,
    pub worker_access: ProofLaneWorkerAccessSnapshot,
    pub decision: ProofLaneReadinessDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReadinessSummary {
    pub tracked_beads: usize,
    pub receipts: usize,
    pub proof_statuses: usize,
    pub proof_counts: ProofKindCounts,
    pub proof_cache_hits: usize,
    pub stale_receipt_count: usize,
    pub malformed_receipt_count: usize,
    pub missing_required_receipts: usize,
    pub product_failure_count: usize,
    pub worker_failure_count: usize,
    pub resource_failure_count: usize,
    pub rch_remote_receipts: usize,
    pub rch_remote_missing_worker_id: usize,
    pub last_successful_cargo_proof_at: Option<DateTime<Utc>>,
    pub contention_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReadinessReport {
    pub schema_version: String,
    pub command: String,
    pub trace_id: String,
    pub generated_at_utc: DateTime<Utc>,
    pub overall_status: ValidationReadinessStatus,
    pub status_counts: ValidationReadinessStatusCounts,
    pub checks: Vec<ValidationReadinessCheck>,
    pub summary: ValidationReadinessSummary,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationReadinessError {
    #[error("failed reading validation readiness input {path}: {source}")]
    ReadInput {
        path: String,
        source: std::io::Error,
    },
    #[error("failed parsing validation readiness input {path}: {source}")]
    ParseInput {
        path: String,
        source: serde_json::Error,
    },
    #[error("failed reading validation receipt {path}: {source}")]
    ReadReceipt {
        path: String,
        source: std::io::Error,
    },
    #[error("failed parsing validation receipt {path}: {source}")]
    ParseReceipt {
        path: String,
        source: serde_json::Error,
    },
    #[error("failed encoding validation readiness report: {0}")]
    EncodeReport(#[from] serde_json::Error),
}

#[must_use]
pub fn build_validation_readiness_report(
    input: &ValidationReadinessInput,
    trace_id: impl Into<String>,
    now: DateTime<Utc>,
) -> ValidationReadinessReport {
    let trace_id = trace_id.into();
    let summary = summarize_validation_readiness(input, now);
    let checks = vec![
        evaluate_schema_check(input),
        evaluate_broker_state_check(input),
        evaluate_required_receipts_check(input, &summary, now),
        evaluate_receipt_freshness_check(input, &summary, now),
        evaluate_proof_status_check(input, &summary),
        evaluate_rch_worker_check(input, &summary),
        evaluate_resource_contention_check(input),
    ];
    let (status_counts, overall_status) = summarize_check_statuses(&checks);

    ValidationReadinessReport {
        schema_version: VALIDATION_READINESS_REPORT_SCHEMA_VERSION.to_string(),
        command: "ops validation-readiness".to_string(),
        trace_id,
        generated_at_utc: now,
        overall_status,
        status_counts,
        checks,
        summary,
    }
}

#[must_use]
pub fn classify_proof_lane_readiness(
    input: &ProofLaneReadinessInput,
    now: DateTime<Utc>,
) -> ProofLaneReadinessCapsule {
    let selected_worker = normalized_selected_worker(&input.worker_selection.selected_worker);
    let selected_capability = selected_worker
        .as_deref()
        .and_then(|worker_id| input.worker_capabilities.get(worker_id));
    let worker_selection = proof_lane_worker_selection(input, selected_worker.clone());
    let toolchain = proof_lane_toolchain(input, selected_capability);
    let worker_access = proof_lane_worker_access(selected_worker.as_deref(), selected_capability);
    let decision = classify_proof_lane_decision(
        input,
        now,
        selected_worker.as_deref(),
        selected_capability,
        &toolchain,
        &worker_access,
    );

    ProofLaneReadinessCapsule {
        schema_version: PROOF_LANE_READINESS_CAPSULE_SCHEMA_VERSION.to_string(),
        capsule_id: input.capsule_id.clone(),
        trace_id: input.trace_id.clone(),
        bead_id: input.bead_id.clone(),
        thread_id: input.thread_id.clone(),
        created_at: input.created_at,
        freshness_expires_at: input.freshness_expires_at,
        producer: input.producer.clone(),
        command: input.command.clone(),
        rch: input.rch.clone(),
        worker_selection,
        toolchain,
        worker_access,
        decision,
    }
}

pub fn read_validation_readiness_input(
    path: &Path,
) -> Result<ValidationReadinessInput, ValidationReadinessError> {
    let raw = fs::read_to_string(path).map_err(|source| ValidationReadinessError::ReadInput {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| ValidationReadinessError::ParseInput {
        path: path.display().to_string(),
        source,
    })
}

pub fn read_validation_receipt(path: &Path) -> Result<ValidationReceipt, ValidationReadinessError> {
    let raw = fs::read_to_string(path).map_err(|source| ValidationReadinessError::ReadReceipt {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| ValidationReadinessError::ParseReceipt {
        path: path.display().to_string(),
        source,
    })
}

pub fn render_validation_readiness_json(
    report: &ValidationReadinessReport,
) -> Result<String, ValidationReadinessError> {
    serde_json::to_string_pretty(report).map_err(ValidationReadinessError::EncodeReport)
}

#[must_use]
pub fn render_validation_readiness_human(report: &ValidationReadinessReport) -> String {
    let last_success = report
        .summary
        .last_successful_cargo_proof_at
        .map(|ts| ts.to_rfc3339())
        .unwrap_or_else(|| "none".to_string());
    let mut lines = vec![
        format!(
            "ops validation-readiness: status={}",
            report.overall_status.as_str()
        ),
        format!("  trace_id={}", report.trace_id),
        format!(
            "  tracked_beads={} receipts={} proof_statuses={}",
            report.summary.tracked_beads, report.summary.receipts, report.summary.proof_statuses
        ),
        format!(
            "  proof_counts=passed:{} reused:{} failed:{} running:{} queued:{} source_only:{} unknown:{} proof_cache_hits:{}",
            report.summary.proof_counts.passed,
            report.summary.proof_counts.reused,
            report.summary.proof_counts.failed,
            report.summary.proof_counts.running,
            report.summary.proof_counts.queued,
            report.summary.proof_counts.source_only,
            report.summary.proof_counts.unknown,
            report.summary.proof_cache_hits
        ),
        format!(
            "  stale_receipts={} missing_required_receipts={} malformed_receipts={}",
            report.summary.stale_receipt_count,
            report.summary.missing_required_receipts,
            report.summary.malformed_receipt_count
        ),
        format!(
            "  product_failures={} worker_failures={} resource_failures={}",
            report.summary.product_failure_count,
            report.summary.worker_failure_count,
            report.summary.resource_failure_count
        ),
        format!("  last_successful_cargo_proof_at={last_success}"),
        format!("  contention_state={}", report.summary.contention_state),
    ];

    for check in &report.checks {
        lines.push(format!(
            "  {} [{}] {}",
            check.code,
            check.status.as_str(),
            check.message
        ));
        if !check.remediation.trim().is_empty() && check.status != ValidationReadinessStatus::Pass {
            lines.push(format!("    remediation={}", check.remediation));
        }
    }

    lines.join("\n")
}

fn summarize_validation_readiness(
    input: &ValidationReadinessInput,
    now: DateTime<Utc>,
) -> ValidationReadinessSummary {
    let mut proof_counts = ProofKindCounts::default();
    let mut stale_receipt_count = 0usize;
    let mut malformed_receipt_count = 0usize;
    let mut product_failure_count = 0usize;
    let mut worker_failure_count = 0usize;
    let mut resource_failure_count = 0usize;
    let mut rch_remote_receipts = 0usize;
    let mut rch_remote_missing_worker_id = 0usize;
    let mut last_successful_cargo_proof_at = None;
    let mut proof_cache_hits = 0usize;

    for status in &input.proof_statuses {
        increment_proof_count(&mut proof_counts, status.status);
        if status.proof_source == ProofEvidenceSource::ProofCacheHit || status.proof_cache.is_some()
        {
            proof_cache_hits = proof_cache_hits.saturating_add(1);
        }
        if status.status == ProofStatusKind::Failed {
            let domain = status
                .exit
                .as_ref()
                .map_or(ValidationFailureDomain::Unknown, failure_domain_for_exit);
            increment_failure_domain(
                domain,
                &mut product_failure_count,
                &mut worker_failure_count,
                &mut resource_failure_count,
            );
        }
    }

    for receipt in &input.receipts {
        match receipt.validate_at(now) {
            Ok(()) => {}
            Err(err) => {
                if err.to_string().contains("ERR_VB_STALE_RECEIPT") {
                    stale_receipt_count = stale_receipt_count.saturating_add(1);
                } else {
                    malformed_receipt_count = malformed_receipt_count.saturating_add(1);
                }
            }
        }

        increment_proof_count(&mut proof_counts, proof_kind_for_receipt(receipt));

        increment_failure_domain(
            failure_domain_for_receipt(receipt),
            &mut product_failure_count,
            &mut worker_failure_count,
            &mut resource_failure_count,
        );

        if receipt.rch.mode == RchMode::Remote {
            rch_remote_receipts = rch_remote_receipts.saturating_add(1);
            if receipt
                .rch
                .worker_id
                .as_ref()
                .is_none_or(|id| id.trim().is_empty())
            {
                rch_remote_missing_worker_id = rch_remote_missing_worker_id.saturating_add(1);
            }
        }

        if receipt.exit.kind == ValidationExitKind::Success && command_uses_cargo(receipt) {
            last_successful_cargo_proof_at = Some(
                last_successful_cargo_proof_at
                    .map_or(receipt.timing.finished_at, |current: DateTime<Utc>| {
                        current.max(receipt.timing.finished_at)
                    }),
            );
        }
    }

    let valid_receipts = input
        .receipts
        .iter()
        .filter(|receipt| receipt.validate_at(now).is_ok())
        .collect::<Vec<_>>();
    let missing_required_receipts = input
        .tracked_beads
        .iter()
        .filter(|bead| bead.requires_receipt)
        .filter(|bead| {
            !has_acceptable_receipt(bead, &valid_receipts) && bead.source_only_waiver.is_none()
        })
        .count();

    ValidationReadinessSummary {
        tracked_beads: input.tracked_beads.len(),
        receipts: input.receipts.len(),
        proof_statuses: input.proof_statuses.len(),
        proof_counts,
        proof_cache_hits,
        stale_receipt_count,
        malformed_receipt_count,
        missing_required_receipts,
        product_failure_count,
        worker_failure_count,
        resource_failure_count,
        rch_remote_receipts,
        rch_remote_missing_worker_id,
        last_successful_cargo_proof_at,
        contention_state: contention_state(input),
    }
}

fn evaluate_schema_check(input: &ValidationReadinessInput) -> ValidationReadinessCheck {
    if input.schema_version == VALIDATION_READINESS_INPUT_SCHEMA_VERSION {
        check(
            "VR-SCHEMA-001",
            "VB-009",
            "validation_readiness.schema",
            ValidationReadinessStatus::Pass,
            "Validation-readiness input schema is supported.",
            "No action required.",
        )
    } else {
        check(
            "VR-SCHEMA-001",
            "VB-009",
            "validation_readiness.schema",
            ValidationReadinessStatus::Fail,
            format!(
                "Validation-readiness input schema is unsupported: {}.",
                input.schema_version
            ),
            format!(
                "Regenerate the snapshot with schema_version={VALIDATION_READINESS_INPUT_SCHEMA_VERSION}."
            ),
        )
    }
}

fn evaluate_broker_state_check(input: &ValidationReadinessInput) -> ValidationReadinessCheck {
    if input.receipts.is_empty() && input.proof_statuses.is_empty() {
        check(
            "VR-BROKER-002",
            "VB-009",
            "validation_broker.state",
            ValidationReadinessStatus::Warn,
            "No validation broker receipts or proof statuses were supplied.",
            "Include broker status or receipt paths before trusting validation readiness.",
        )
    } else {
        check(
            "VR-BROKER-002",
            "VB-009",
            "validation_broker.state",
            ValidationReadinessStatus::Pass,
            format!(
                "Validation broker state supplied (receipts={}, proof_statuses={}).",
                input.receipts.len(),
                input.proof_statuses.len()
            ),
            "No action required.",
        )
    }
}

fn evaluate_required_receipts_check(
    input: &ValidationReadinessInput,
    summary: &ValidationReadinessSummary,
    now: DateTime<Utc>,
) -> ValidationReadinessCheck {
    let mut blocked_without_receipts = Vec::new();
    let mut open_without_receipts = Vec::new();
    let valid_receipts = input
        .receipts
        .iter()
        .filter(|receipt| receipt.validate_at(now).is_ok())
        .collect::<Vec<_>>();

    for bead in &input.tracked_beads {
        if !bead.requires_receipt
            || has_acceptable_receipt(bead, &valid_receipts)
            || bead.source_only_waiver.is_some()
        {
            continue;
        }
        if bead.state.is_untrusted_without_receipt() {
            blocked_without_receipts.push(bead.bead_id.clone());
        } else {
            open_without_receipts.push(bead.bead_id.clone());
        }
    }

    if !blocked_without_receipts.is_empty() {
        check(
            "VR-BEAD-003",
            "VB-009",
            "beads.validation_receipts",
            ValidationReadinessStatus::Fail,
            format!(
                "Blocked or closed Beads lack fresh validation receipts: {}.",
                blocked_without_receipts.join(",")
            ),
            "Attach a fresh validation broker receipt or record an explicit source-only waiver before closeout.",
        )
    } else if !open_without_receipts.is_empty() || summary.missing_required_receipts > 0 {
        check(
            "VR-BEAD-003",
            "VB-009",
            "beads.validation_receipts",
            ValidationReadinessStatus::Warn,
            format!(
                "Open or running Beads still need validation receipts: {}.",
                open_without_receipts.join(",")
            ),
            "Queue broker proof before promoting those Beads to closed.",
        )
    } else {
        check(
            "VR-BEAD-003",
            "VB-009",
            "beads.validation_receipts",
            ValidationReadinessStatus::Pass,
            "Tracked Beads have fresh receipts or explicit source-only waivers.",
            "No action required.",
        )
    }
}

fn evaluate_receipt_freshness_check(
    input: &ValidationReadinessInput,
    summary: &ValidationReadinessSummary,
    now: DateTime<Utc>,
) -> ValidationReadinessCheck {
    if input.receipts.is_empty() {
        return check(
            "VR-RECEIPT-004",
            "VB-009",
            "validation_broker.receipt_freshness",
            ValidationReadinessStatus::Warn,
            "No validation receipts were supplied for freshness checks.",
            "Include receipt paths or a broker snapshot before relying on this report.",
        );
    }
    if summary.stale_receipt_count > 0 || summary.malformed_receipt_count > 0 {
        return check(
            "VR-RECEIPT-004",
            "VB-009",
            "validation_broker.receipt_freshness",
            ValidationReadinessStatus::Fail,
            format!(
                "Receipt freshness failed (stale={}, malformed={}).",
                summary.stale_receipt_count, summary.malformed_receipt_count
            ),
            "Regenerate stale or malformed broker receipts before using them as closeout evidence.",
        );
    }

    let max_age =
        chrono::Duration::seconds(i64::try_from(input.max_receipt_age_secs).unwrap_or(i64::MAX));
    let age_violations = input
        .receipts
        .iter()
        .filter(|receipt| now.signed_duration_since(receipt.timing.finished_at) > max_age)
        .map(|receipt| receipt.receipt_id.clone())
        .collect::<Vec<_>>();
    if !age_violations.is_empty() {
        return check(
            "VR-RECEIPT-004",
            "VB-009",
            "validation_broker.receipt_freshness",
            ValidationReadinessStatus::Warn,
            format!(
                "Receipts are valid but older than max_receipt_age_secs: {}.",
                age_violations.join(",")
            ),
            "Prefer a fresh RCH proof before closing high-risk Beads.",
        );
    }

    check(
        "VR-RECEIPT-004",
        "VB-009",
        "validation_broker.receipt_freshness",
        ValidationReadinessStatus::Pass,
        format!("{} validation receipt(s) are fresh.", input.receipts.len()),
        "No action required.",
    )
}

fn evaluate_proof_status_check(
    input: &ValidationReadinessInput,
    summary: &ValidationReadinessSummary,
) -> ValidationReadinessCheck {
    if summary.product_failure_count > 0 {
        return check(
            "VR-PROOF-005",
            "VB-009",
            "validation_broker.proof_status",
            ValidationReadinessStatus::Fail,
            format!(
                "Validation proof includes product failure(s): {}.",
                summary.product_failure_count
            ),
            "Fix compile/test/format/clippy failures before treating evidence as ready.",
        );
    }
    if summary.worker_failure_count > 0 || summary.resource_failure_count > 0 {
        return check(
            "VR-PROOF-005",
            "VB-009",
            "validation_broker.proof_status",
            ValidationReadinessStatus::Warn,
            format!(
                "Validation proof is blocked by worker/resource failure(s): worker={} resource={}.",
                summary.worker_failure_count, summary.resource_failure_count
            ),
            "Retry on a healthy RCH worker or defer with explicit source-only rationale; do not count this as product green.",
        );
    }
    if summary.proof_counts.queued + summary.proof_counts.leased + summary.proof_counts.running > 0
    {
        return check(
            "VR-PROOF-005",
            "VB-009",
            "validation_broker.proof_status",
            ValidationReadinessStatus::Warn,
            "Validation proof is still queued, leased, or running.",
            "Wait for a terminal broker receipt before closeout.",
        );
    }
    if input.proof_statuses.is_empty() && input.receipts.is_empty() {
        return check(
            "VR-PROOF-005",
            "VB-009",
            "validation_broker.proof_status",
            ValidationReadinessStatus::Warn,
            "No proof status exists yet.",
            "Queue validation or record an explicit source-only waiver.",
        );
    }

    check(
        "VR-PROOF-005",
        "VB-009",
        "validation_broker.proof_status",
        ValidationReadinessStatus::Pass,
        "Validation proofs are terminal and have no product failures.",
        "No action required.",
    )
}

fn evaluate_rch_worker_check(
    input: &ValidationReadinessInput,
    summary: &ValidationReadinessSummary,
) -> ValidationReadinessCheck {
    let mut non_remote_required = 0usize;
    for receipt in &input.receipts {
        if receipt.rch.require_remote && receipt.rch.mode != RchMode::Remote {
            non_remote_required = non_remote_required.saturating_add(1);
        }
    }
    let unreachable_workers = input
        .rch_workers
        .iter()
        .filter(|worker| !worker.reachable || worker.mode != RchMode::Remote)
        .map(|worker| worker.worker_id.clone())
        .collect::<Vec<_>>();

    if non_remote_required > 0 {
        return check(
            "VR-RCH-006",
            "VB-009",
            "rch.worker_readiness",
            ValidationReadinessStatus::Fail,
            format!(
                "{non_remote_required} receipt(s) required remote RCH but did not run remotely."
            ),
            "Rerun proof with RCH_REQUIRE_REMOTE=1 on a reachable worker.",
        );
    }
    if !unreachable_workers.is_empty() || summary.rch_remote_missing_worker_id > 0 {
        return check(
            "VR-RCH-006",
            "VB-009",
            "rch.worker_readiness",
            ValidationReadinessStatus::Warn,
            format!(
                "RCH worker readiness is degraded (unreachable={}, remote_receipts_missing_worker_id={}).",
                unreachable_workers.join(","),
                summary.rch_remote_missing_worker_id
            ),
            "Probe RCH workers before launching broad cargo validation.",
        );
    }
    if summary.rch_remote_receipts == 0 && input.rch_workers.is_empty() {
        return check(
            "VR-RCH-006",
            "VB-009",
            "rch.worker_readiness",
            ValidationReadinessStatus::Warn,
            "No RCH worker observations or remote receipts were supplied.",
            "Include broker receipts or worker capability observations for RCH readiness.",
        );
    }

    check(
        "VR-RCH-006",
        "VB-009",
        "rch.worker_readiness",
        ValidationReadinessStatus::Pass,
        "RCH worker readiness supports remote validation.",
        "No action required.",
    )
}

fn evaluate_resource_contention_check(
    input: &ValidationReadinessInput,
) -> ValidationReadinessCheck {
    let Some(resource) = &input.resource_governor else {
        return check(
            "VR-RESOURCE-007",
            "VB-009",
            "resource_governor.contention",
            ValidationReadinessStatus::Warn,
            "No resource-governor observation was supplied.",
            "Run `franken-node ops resource-governor --json` before launching expensive validation.",
        );
    };
    let decision = resource.decision.to_ascii_lowercase();
    if matches!(
        decision.as_str(),
        "defer" | "source_only" | "dedupe_only" | "reject"
    ) {
        return check(
            "VR-RESOURCE-007",
            "VB-009",
            "resource_governor.contention",
            ValidationReadinessStatus::Warn,
            format!(
                "Resource governor reports validation contention: decision={} reason_code={}.",
                resource.decision, resource.reason_code
            ),
            "Follow the resource-governor next action before starting more RCH work.",
        );
    }

    check(
        "VR-RESOURCE-007",
        "VB-009",
        "resource_governor.contention",
        ValidationReadinessStatus::Pass,
        format!(
            "Resource governor permits validation: decision={} reason_code={}.",
            resource.decision, resource.reason_code
        ),
        "No action required.",
    )
}

fn summarize_check_statuses(
    checks: &[ValidationReadinessCheck],
) -> (ValidationReadinessStatusCounts, ValidationReadinessStatus) {
    let mut counts = ValidationReadinessStatusCounts {
        pass: 0,
        warn: 0,
        fail: 0,
    };
    let mut overall = ValidationReadinessStatus::Pass;
    for check in checks {
        overall = overall.max(check.status);
        match check.status {
            ValidationReadinessStatus::Pass => counts.pass += 1,
            ValidationReadinessStatus::Warn => counts.warn += 1,
            ValidationReadinessStatus::Fail => counts.fail += 1,
        }
    }
    (counts, overall)
}

fn check(
    code: impl Into<String>,
    event_code: impl Into<String>,
    scope: impl Into<String>,
    status: ValidationReadinessStatus,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> ValidationReadinessCheck {
    ValidationReadinessCheck {
        code: code.into(),
        event_code: event_code.into(),
        scope: scope.into(),
        status,
        message: message.into(),
        remediation: remediation.into(),
    }
}

fn increment_proof_count(counts: &mut ProofKindCounts, status: ProofStatusKind) {
    match status {
        ProofStatusKind::Unknown => counts.unknown += 1,
        ProofStatusKind::Queued => counts.queued += 1,
        ProofStatusKind::Leased => counts.leased += 1,
        ProofStatusKind::Running => counts.running += 1,
        ProofStatusKind::Reused => counts.reused += 1,
        ProofStatusKind::Failed => counts.failed += 1,
        ProofStatusKind::Passed => counts.passed += 1,
        ProofStatusKind::SourceOnly => counts.source_only += 1,
        ProofStatusKind::Cancelled => counts.cancelled += 1,
    }
}

fn proof_kind_for_receipt(receipt: &ValidationReceipt) -> ProofStatusKind {
    match receipt.exit.kind {
        ValidationExitKind::Success => ProofStatusKind::Passed,
        ValidationExitKind::Failed | ValidationExitKind::Timeout => ProofStatusKind::Failed,
        ValidationExitKind::SourceOnly => ProofStatusKind::SourceOnly,
        ValidationExitKind::Cancelled => ProofStatusKind::Cancelled,
    }
}

fn failure_domain_for_receipt(receipt: &ValidationReceipt) -> ValidationFailureDomain {
    failure_domain_for_exit(&receipt.exit)
}

fn failure_domain_for_exit(
    exit: &crate::ops::validation_broker::ValidationExit,
) -> ValidationFailureDomain {
    match exit.kind {
        ValidationExitKind::Success | ValidationExitKind::SourceOnly => {
            ValidationFailureDomain::None
        }
        ValidationExitKind::Cancelled => ValidationFailureDomain::Worker,
        ValidationExitKind::Timeout => ValidationFailureDomain::Worker,
        ValidationExitKind::Failed => match exit.error_class {
            ValidationErrorClass::CompileError
            | ValidationErrorClass::TestFailure
            | ValidationErrorClass::ClippyWarning
            | ValidationErrorClass::FormatFailure => ValidationFailureDomain::Product,
            ValidationErrorClass::EnvironmentContention | ValidationErrorClass::DiskPressure => {
                ValidationFailureDomain::Resource
            }
            ValidationErrorClass::TransportTimeout | ValidationErrorClass::WorkerInfra => {
                ValidationFailureDomain::Worker
            }
            ValidationErrorClass::None | ValidationErrorClass::SourceOnly => {
                ValidationFailureDomain::None
            }
            ValidationErrorClass::Unknown => ValidationFailureDomain::Unknown,
        },
    }
}

fn increment_failure_domain(
    domain: ValidationFailureDomain,
    product_failure_count: &mut usize,
    worker_failure_count: &mut usize,
    resource_failure_count: &mut usize,
) {
    match domain {
        ValidationFailureDomain::Product => {
            *product_failure_count = product_failure_count.saturating_add(1);
        }
        ValidationFailureDomain::Worker | ValidationFailureDomain::Unknown => {
            *worker_failure_count = worker_failure_count.saturating_add(1);
        }
        ValidationFailureDomain::Resource => {
            *resource_failure_count = resource_failure_count.saturating_add(1);
        }
        ValidationFailureDomain::None => {}
    }
}

fn has_acceptable_receipt(bead: &TrackedValidationBead, receipts: &[&ValidationReceipt]) -> bool {
    receipts.iter().any(|receipt| {
        receipt.bead_id == bead.bead_id
            && receipt.thread_id == bead.normalized_thread_id()
            && matches!(
                receipt.exit.kind,
                ValidationExitKind::Success | ValidationExitKind::SourceOnly
            )
    })
}

fn command_uses_cargo(receipt: &ValidationReceipt) -> bool {
    receipt.command.program == "cargo" || receipt.command.argv.iter().any(|arg| arg == "cargo")
}

fn contention_state(input: &ValidationReadinessInput) -> String {
    input.resource_governor.as_ref().map_or_else(
        || "unknown".to_string(),
        |resource| {
            if resource.reason_code.trim().is_empty() {
                resource.decision.clone()
            } else {
                format!("{}:{}", resource.decision, resource.reason_code)
            }
        },
    )
}

fn classify_proof_lane_decision(
    input: &ProofLaneReadinessInput,
    now: DateTime<Utc>,
    selected_worker: Option<&str>,
    selected_capability: Option<&ProofLaneWorkerCapability>,
    toolchain: &ProofLaneToolchainSnapshot,
    worker_access: &ProofLaneWorkerAccessSnapshot,
) -> ProofLaneReadinessDecision {
    if let Some(reason) = invalid_proof_lane_input(input) {
        return proof_lane_decision(
            ProofLaneReadinessDecisionKind::FailClosed,
            proof_lane_reason_codes::MALFORMED_READINESS_INPUT,
            proof_lane_event_codes::MALFORMED_READINESS_INPUT,
            false,
            true,
            "fix_readiness_input_schema",
            format!("Readiness input is malformed: {reason}."),
        );
    }
    if now > input.freshness_expires_at {
        return proof_lane_decision(
            ProofLaneReadinessDecisionKind::FailClosed,
            proof_lane_reason_codes::STALE_READINESS_CAPSULE,
            proof_lane_event_codes::STALE_READINESS_CAPSULE,
            true,
            true,
            "regenerate_readiness_capsule",
            format!(
                "Readiness capsule expired at {}; regenerate before launching proof.",
                input.freshness_expires_at.to_rfc3339()
            ),
        );
    }
    if requested_worker_override_missing(&input.worker_selection.requested_workers, selected_worker)
    {
        return proof_lane_decision(
            ProofLaneReadinessDecisionKind::SourceOnlyBlocker,
            proof_lane_reason_codes::OVERRIDE_NOT_HONORED,
            proof_lane_event_codes::OVERRIDE_NOT_HONORED,
            true,
            true,
            "fix_rch_worker_selection_or_use_valid_same_toolchain_worker",
            format!(
                "RCH selected {} even though {} was requested; do not launch this proof as green evidence.",
                selected_worker_label(selected_worker),
                requested_workers_label(&input.worker_selection.requested_workers)
            ),
        );
    }
    if input.rch.require_remote
        && selected_worker.is_none()
        && (!input.rch.local_fallback_allowed || input.rch.local_fallback_refused)
    {
        return proof_lane_decision(
            ProofLaneReadinessDecisionKind::SourceOnlyBlocker,
            proof_lane_reason_codes::LOCAL_FALLBACK_REFUSED,
            proof_lane_event_codes::LOCAL_FALLBACK_REFUSED,
            true,
            true,
            "restore_remote_execution_before_cargo_proof",
            "Remote proof is required, no remote worker was selected, and local fallback is refused.",
        );
    }
    let Some(capability) = selected_capability else {
        return proof_lane_decision(
            ProofLaneReadinessDecisionKind::RetryPreflight,
            proof_lane_reason_codes::WORKER_CAPABILITY_UNKNOWN,
            proof_lane_event_codes::WORKER_CAPABILITY_UNKNOWN,
            true,
            true,
            "refresh_worker_capabilities",
            format!(
                "No fresh capability snapshot exists for selected worker {}; refresh RCH capabilities before proof.",
                selected_worker_label(selected_worker)
            ),
        );
    };
    if capability.auth_status.blocks_launch() {
        return proof_lane_decision(
            ProofLaneReadinessDecisionKind::SourceOnlyBlocker,
            proof_lane_reason_codes::WORKER_AUTH_FAILED,
            proof_lane_event_codes::WORKER_AUTH_FAILED,
            true,
            true,
            "repair_worker_credentials_before_retry",
            format!(
                "Selected worker {} has auth_status={}; repair credentials before proof.",
                selected_worker_label(selected_worker),
                capability.auth_status.as_str()
            ),
        );
    }
    if capability_snapshot_unknown_or_stale(capability, now) {
        return proof_lane_decision(
            ProofLaneReadinessDecisionKind::RetryPreflight,
            proof_lane_reason_codes::WORKER_CAPABILITY_UNKNOWN,
            proof_lane_event_codes::WORKER_CAPABILITY_UNKNOWN,
            true,
            true,
            "refresh_worker_capabilities",
            format!(
                "Selected worker {} has capability_status={}; refresh capabilities before proof.",
                selected_worker_label(selected_worker),
                capability.capability_status.as_str()
            ),
        );
    }
    if !toolchain.same_toolchain {
        return proof_lane_decision(
            ProofLaneReadinessDecisionKind::SourceOnlyBlocker,
            proof_lane_reason_codes::SAME_TOOLCHAIN_MISSING,
            proof_lane_event_codes::SAME_TOOLCHAIN_MISSING,
            true,
            true,
            "sync_toolchain_or_wait_for_matching_worker",
            format!(
                "Selected worker {} does not match required toolchain {}; do not launch this proof.",
                selected_worker_label(selected_worker),
                input.toolchain.required_toolchain
            ),
        );
    }
    if worker_access.pressure_status.blocks_launch() {
        return proof_lane_decision(
            ProofLaneReadinessDecisionKind::QueueUntilReady,
            proof_lane_reason_codes::WORKER_PRESSURE_BLOCKED,
            proof_lane_event_codes::WORKER_PRESSURE_BLOCKED,
            true,
            false,
            "wait_for_pressure_to_clear_or_select_another_valid_worker",
            format!(
                "Selected worker {} has pressure_status={}; wait or select another valid worker.",
                selected_worker_label(selected_worker),
                worker_access.pressure_status.as_str()
            ),
        );
    }

    proof_lane_decision(
        ProofLaneReadinessDecisionKind::ReadyToLaunch,
        proof_lane_reason_codes::HEALTHY_SAME_TOOLCHAIN_LANE,
        proof_lane_event_codes::HEALTHY_SAME_TOOLCHAIN_LANE,
        false,
        false,
        "launch_remote_proof",
        format!(
            "RCH selected {} with fresh capability, valid auth, and matching toolchain; remote proof may launch.",
            selected_worker_label(selected_worker)
        ),
    )
}

fn proof_lane_worker_selection(
    input: &ProofLaneReadinessInput,
    selected_worker: Option<String>,
) -> ProofLaneWorkerSelection {
    let mut selection = input.worker_selection.clone();
    selection.selected_worker = selected_worker;
    selection.override_effective = selected_worker_override_effective(
        &selection.requested_workers,
        selection.selected_worker.as_deref(),
    );
    selection
}

fn proof_lane_toolchain(
    input: &ProofLaneReadinessInput,
    selected_capability: Option<&ProofLaneWorkerCapability>,
) -> ProofLaneToolchainSnapshot {
    let selected_worker_rustc = selected_capability
        .and_then(|capability| capability.rustc.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let same_toolchain = selected_capability.is_some_and(|capability| {
        capability
            .rustc
            .as_ref()
            .is_some_and(|rustc| rustc == &input.toolchain.local_rustc)
            && capability
                .observed_toolchains
                .iter()
                .any(|toolchain| toolchain == &input.toolchain.required_toolchain)
    });

    ProofLaneToolchainSnapshot {
        local_rustc: input.toolchain.local_rustc.clone(),
        required_toolchain: input.toolchain.required_toolchain.clone(),
        selected_worker_rustc,
        same_toolchain,
    }
}

fn proof_lane_worker_access(
    selected_worker: Option<&str>,
    selected_capability: Option<&ProofLaneWorkerCapability>,
) -> ProofLaneWorkerAccessSnapshot {
    selected_capability.map_or_else(
        || ProofLaneWorkerAccessSnapshot {
            auth_status: ProofLaneWorkerAuthStatus::Unknown,
            capability_status: ProofLaneCapabilityStatus::Missing,
            pressure_status: ProofLanePressureStatus::Unknown,
            detail: format!(
                "No capability snapshot exists for selected worker {}.",
                selected_worker_label(selected_worker)
            ),
        },
        |capability| ProofLaneWorkerAccessSnapshot {
            auth_status: capability.auth_status,
            capability_status: capability.capability_status,
            pressure_status: capability.pressure_status,
            detail: capability.detail.clone().unwrap_or_else(|| {
                format!(
                    "Capability snapshot exists for selected worker {}.",
                    selected_worker_label(selected_worker)
                )
            }),
        },
    )
}

fn proof_lane_decision(
    decision: ProofLaneReadinessDecisionKind,
    reason_code: impl Into<String>,
    event_code: impl Into<String>,
    retryable: bool,
    fail_closed: bool,
    required_action: impl Into<String>,
    operator_summary: impl Into<String>,
) -> ProofLaneReadinessDecision {
    ProofLaneReadinessDecision {
        schema_version: PROOF_LANE_READINESS_DECISION_SCHEMA_VERSION.to_string(),
        decision,
        reason_code: reason_code.into(),
        event_code: event_code.into(),
        retryable,
        fail_closed,
        required_action: required_action.into(),
        operator_summary: bounded_operator_summary(operator_summary.into()),
    }
}

fn invalid_proof_lane_input(input: &ProofLaneReadinessInput) -> Option<&'static str> {
    if input.created_at > input.freshness_expires_at {
        return Some("freshness_expires_at precedes created_at");
    }
    if input
        .observed_validation_error_class
        .is_some_and(product_validation_error_class)
    {
        return Some("product validation failure was supplied to proof-lane readiness");
    }
    if !input.command.digest.is_valid_sha256() {
        return Some("command digest is not a valid sha256 digest");
    }
    if !bounded_required(&input.capsule_id)
        || !bounded_required(&input.trace_id)
        || !bounded_required(&input.bead_id)
        || !bounded_required(&input.thread_id)
        || !bounded_required(&input.producer.name)
        || !bounded_required(&input.producer.agent_name)
        || !bounded_required(&input.producer.git_commit)
        || !bounded_required(&input.command.program)
        || !bounded_required(&input.command.cwd)
        || !bounded_required(&input.rch.daemon_source)
        || !bounded_required(&input.rch.daemon_version)
        || !bounded_required(&input.rch.socket_path)
        || !bounded_required(&input.worker_selection.selection_source)
        || !bounded_required(&input.toolchain.local_rustc)
        || !bounded_required(&input.toolchain.required_toolchain)
    {
        return Some("required string field is empty, too long, or contains NUL");
    }
    if input.command.argv.len() > MAX_PROOF_LANE_ARGS
        || input
            .command
            .argv
            .iter()
            .any(|arg| !bounded_optional(arg, MAX_PROOF_LANE_STRING_BYTES))
    {
        return Some("command argv is unbounded or contains NUL");
    }
    if input.worker_selection.requested_workers.len() > MAX_PROOF_LANE_WORKERS
        || input
            .worker_selection
            .requested_workers
            .iter()
            .any(|worker_id| !bounded_required(worker_id))
    {
        return Some("requested worker list is unbounded or malformed");
    }
    if input.worker_capabilities.len() > MAX_PROOF_LANE_WORKERS {
        return Some("worker capability map is unbounded");
    }
    for (worker_id, capability) in &input.worker_capabilities {
        if !bounded_required(worker_id) {
            return Some("worker capability key is empty, too long, or contains NUL");
        }
        if capability.observed_toolchains.len() > MAX_PROOF_LANE_WORKERS
            || capability
                .observed_toolchains
                .iter()
                .any(|toolchain| !bounded_required(toolchain))
        {
            return Some("worker toolchain list is unbounded or malformed");
        }
        if capability
            .rustc
            .as_ref()
            .is_some_and(|rustc| !bounded_required(rustc))
        {
            return Some("worker rustc field is empty, too long, or contains NUL");
        }
        if capability
            .detail
            .as_ref()
            .is_some_and(|detail| !bounded_optional(detail, MAX_PROOF_LANE_DETAIL_BYTES))
        {
            return Some("worker detail is too long or contains NUL");
        }
    }
    if input
        .worker_selection
        .selected_worker
        .as_ref()
        .is_some_and(|worker_id| !bounded_required(worker_id))
    {
        return Some("selected worker is empty, too long, or contains NUL");
    }
    None
}

fn selected_worker_override_effective(
    requested_workers: &[String],
    selected_worker: Option<&str>,
) -> bool {
    selected_worker.is_some_and(|selected| {
        requested_workers.is_empty()
            || requested_workers
                .iter()
                .any(|worker_id| worker_id.trim() == selected)
    })
}

fn requested_worker_override_missing(
    requested_workers: &[String],
    selected_worker: Option<&str>,
) -> bool {
    !requested_workers.is_empty()
        && selected_worker.is_some_and(|selected| {
            !requested_workers
                .iter()
                .any(|worker_id| worker_id.trim() == selected)
        })
}

fn capability_snapshot_unknown_or_stale(
    capability: &ProofLaneWorkerCapability,
    now: DateTime<Utc>,
) -> bool {
    capability.capability_status != ProofLaneCapabilityStatus::Fresh
        || capability.observed_at.is_none()
        || capability
            .freshness_expires_at
            .is_none_or(|expires_at| now > expires_at)
}

fn product_validation_error_class(error_class: ValidationErrorClass) -> bool {
    matches!(
        error_class,
        ValidationErrorClass::CompileError
            | ValidationErrorClass::TestFailure
            | ValidationErrorClass::ClippyWarning
            | ValidationErrorClass::FormatFailure
    )
}

fn bounded_required(value: &str) -> bool {
    !value.trim().is_empty() && bounded_optional(value, MAX_PROOF_LANE_STRING_BYTES)
}

fn bounded_optional(value: &str, max_bytes: usize) -> bool {
    !value.contains('\0') && value.len() <= max_bytes
}

fn normalized_selected_worker(selected_worker: &Option<String>) -> Option<String> {
    selected_worker
        .as_ref()
        .map(|worker_id| worker_id.trim())
        .filter(|worker_id| !worker_id.is_empty())
        .map(ToOwned::to_owned)
}

fn selected_worker_label(selected_worker: Option<&str>) -> &str {
    selected_worker.unwrap_or("none")
}

fn requested_workers_label(requested_workers: &[String]) -> String {
    if requested_workers.is_empty() {
        "no explicit worker".to_string()
    } else {
        requested_workers.join(",")
    }
}

fn bounded_operator_summary(mut summary: String) -> String {
    if summary.len() <= MAX_PROOF_LANE_DETAIL_BYTES {
        return summary;
    }
    let cutoff = summary
        .char_indices()
        .map(|(idx, _)| idx)
        .take_while(|idx| *idx <= MAX_PROOF_LANE_DETAIL_BYTES.saturating_sub(3))
        .last()
        .unwrap_or_default();
    summary.truncate(cutoff);
    summary.push_str("...");
    summary
}

fn default_input_schema_version() -> String {
    VALIDATION_READINESS_INPUT_SCHEMA_VERSION.to_string()
}

const fn default_requires_receipt() -> bool {
    true
}

const fn default_max_receipt_age_secs() -> u64 {
    DEFAULT_MAX_RECEIPT_AGE_SECS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReadinessFixtureCatalog {
    pub schema_version: String,
    pub fixtures: Vec<ValidationReadinessFixture>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReadinessFixture {
    pub name: String,
    pub input: ValidationReadinessInput,
    pub expect_overall_status: ValidationReadinessStatus,
    pub expect_check_codes: Vec<String>,
    pub expect_missing_required_receipts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneReadinessFixtureCatalog {
    pub schema_version: String,
    pub fixtures: Vec<ProofLaneReadinessFixture>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLaneReadinessFixture {
    pub name: String,
    pub input: ProofLaneReadinessInput,
    pub expected_capsule: ProofLaneReadinessCapsule,
}

#[must_use]
pub fn known_check_codes(report: &ValidationReadinessReport) -> BTreeSet<String> {
    report
        .checks
        .iter()
        .map(|check| check.code.clone())
        .collect::<BTreeSet<_>>()
}
