//! Operator-facing validation readiness reporting.
//!
//! This module aggregates validation-broker receipts, proof statuses, Beads
//! state, worker observations, and resource-governor hints into a stable report
//! that explains whether validation evidence is trustworthy right now.

use crate::ops::validation_broker::{
    ProofStatusKind, RchMode, SourceOnlyReason, ValidationErrorClass, ValidationExitKind,
    ValidationProofStatus, ValidationReceipt,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const VALIDATION_READINESS_INPUT_SCHEMA_VERSION: &str =
    "franken-node/validation-readiness/input/v1";
pub const VALIDATION_READINESS_REPORT_SCHEMA_VERSION: &str =
    "franken-node/validation-readiness/report/v1";
pub const VALIDATION_READINESS_FIXTURE_SCHEMA_VERSION: &str =
    "franken-node/validation-readiness/fixtures/v1";
pub const DEFAULT_MAX_RECEIPT_AGE_SECS: u64 = 60 * 60 * 24;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReadinessSummary {
    pub tracked_beads: usize,
    pub receipts: usize,
    pub proof_statuses: usize,
    pub proof_counts: ProofKindCounts,
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
            "  proof_counts=passed:{} failed:{} running:{} queued:{} source_only:{} unknown:{}",
            report.summary.proof_counts.passed,
            report.summary.proof_counts.failed,
            report.summary.proof_counts.running,
            report.summary.proof_counts.queued,
            report.summary.proof_counts.source_only,
            report.summary.proof_counts.unknown
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

    for status in &input.proof_statuses {
        increment_proof_count(&mut proof_counts, status.status);
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

#[must_use]
pub fn known_check_codes(report: &ValidationReadinessReport) -> BTreeSet<String> {
    report
        .checks
        .iter()
        .map(|check| check.code.clone())
        .collect::<BTreeSet<_>>()
}
