//! Proof-pipeline operator status and restart request evaluation.
//!
//! The proof-pipeline surface is intentionally a thin operator layer over the
//! validation broker/readiness model. It reports queue health from broker
//! snapshots and validates restart requests without inventing a second proof
//! worker registry.

use crate::ops::validation_broker::{ProofStatusKind, RchMode, ValidationExitKind};
use crate::ops::validation_readiness::{
    ProofKindCounts, RchWorkerReadiness, ValidationReadinessInput,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const PROOF_PIPELINE_QUEUE_REPORT_SCHEMA_VERSION: &str =
    "franken-node/proof-pipeline/queue-report/v1";
pub const PROOF_PIPELINE_RESTART_REPORT_SCHEMA_VERSION: &str =
    "franken-node/proof-pipeline/restart-report/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofPipelineStatus {
    Healthy,
    Degraded,
    Blocked,
}

impl ProofPipelineStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Blocked => "blocked",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::Degraded => 1,
            Self::Blocked => 2,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofPipelineQueueSummary {
    pub queue_depth: usize,
    pub active_proofs: usize,
    pub terminal_proofs: usize,
    pub failed_proofs: usize,
    pub source_only_proofs: usize,
    pub proof_cache_hits: usize,
    pub reachable_workers: usize,
    pub degraded_workers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofPipelineCheck {
    pub code: String,
    pub status: ProofPipelineStatus,
    pub message: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofPipelineQueueReport {
    pub schema_version: String,
    pub command: String,
    pub trace_id: String,
    pub generated_at_utc: DateTime<Utc>,
    pub status: ProofPipelineStatus,
    pub summary: ProofPipelineQueueSummary,
    pub proof_counts: ProofKindCounts,
    pub workers: Vec<RchWorkerReadiness>,
    pub checks: Vec<ProofPipelineCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofWorkerRestartTarget {
    WorkerId(String),
    AllWorkers,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofWorkerRestartRequest {
    pub operator_id: String,
    pub operator_roles: Vec<String>,
    pub target: ProofWorkerRestartTarget,
    pub reason: String,
    pub confirm: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofWorkerRestartReport {
    pub schema_version: String,
    pub command: String,
    pub trace_id: String,
    pub generated_at_utc: DateTime<Utc>,
    pub ok: bool,
    pub decision: String,
    pub reason_code: String,
    pub operator_id: String,
    pub selected_workers: Vec<String>,
    pub rejected_workers: Vec<String>,
    pub required_action: String,
    pub audit_event: String,
}

#[must_use]
pub fn build_queue_report(
    input: &ValidationReadinessInput,
    trace_id: impl Into<String>,
    now: DateTime<Utc>,
) -> ProofPipelineQueueReport {
    let proof_counts = count_proofs(input);
    let queue_depth = proof_counts
        .queued
        .saturating_add(proof_counts.leased)
        .saturating_add(proof_counts.running);
    let active_proofs = queue_depth;
    let terminal_proofs = proof_counts
        .passed
        .saturating_add(proof_counts.failed)
        .saturating_add(proof_counts.cancelled)
        .saturating_add(proof_counts.source_only)
        .saturating_add(proof_counts.reused);
    let failed_proofs = proof_counts.failed;
    let source_only_proofs = proof_counts.source_only;
    let proof_cache_hits = proof_counts.reused;
    let reachable_workers = input
        .rch_workers
        .iter()
        .filter(|worker| worker_is_ready(worker))
        .count();
    let degraded_workers = input
        .rch_workers
        .iter()
        .filter(|worker| worker_is_degraded(worker))
        .count();

    let summary = ProofPipelineQueueSummary {
        queue_depth,
        active_proofs,
        terminal_proofs,
        failed_proofs,
        source_only_proofs,
        proof_cache_hits,
        reachable_workers,
        degraded_workers,
    };
    let checks = queue_checks(input, &summary);
    let status = checks
        .iter()
        .fold(ProofPipelineStatus::Healthy, |acc, check| {
            acc.max(check.status)
        });

    ProofPipelineQueueReport {
        schema_version: PROOF_PIPELINE_QUEUE_REPORT_SCHEMA_VERSION.to_string(),
        command: "proofs queue status".to_string(),
        trace_id: trace_id.into(),
        generated_at_utc: now,
        status,
        summary,
        proof_counts,
        workers: input.rch_workers.clone(),
        checks,
    }
}

#[must_use]
pub fn render_queue_report_human(report: &ProofPipelineQueueReport) -> String {
    let mut lines = vec![
        format!("proofs queue status: status={}", report.status.as_str()),
        format!("  trace_id={}", report.trace_id),
        format!(
            "  queue_depth={} active_proofs={} terminal_proofs={}",
            report.summary.queue_depth,
            report.summary.active_proofs,
            report.summary.terminal_proofs
        ),
        format!(
            "  proof_counts=passed:{} reused:{} failed:{} running:{} queued:{} source_only:{} unknown:{}",
            report.proof_counts.passed,
            report.proof_counts.reused,
            report.proof_counts.failed,
            report.proof_counts.running,
            report.proof_counts.queued,
            report.proof_counts.source_only,
            report.proof_counts.unknown
        ),
        format!(
            "  workers=reachable:{} degraded:{}",
            report.summary.reachable_workers, report.summary.degraded_workers
        ),
    ];

    for check in &report.checks {
        lines.push(format!(
            "  {} [{}] {}",
            check.code,
            check.status.as_str(),
            check.message
        ));
        if check.status != ProofPipelineStatus::Healthy && !check.remediation.trim().is_empty() {
            lines.push(format!("    remediation={}", check.remediation));
        }
    }

    lines.join("\n")
}

#[must_use]
pub fn evaluate_worker_restart_request(
    input: &ValidationReadinessInput,
    request: &ProofWorkerRestartRequest,
    trace_id: impl Into<String>,
    now: DateTime<Utc>,
) -> ProofWorkerRestartReport {
    let trace_id = trace_id.into();
    if let Some(reason_code) = invalid_restart_request_reason(request) {
        return restart_denied(
            trace_id,
            now,
            request.operator_id.clone(),
            reason_code,
            "restart request is malformed or unconfirmed",
            "Regenerate the request with a non-empty operator, reason, and --confirm.",
            Vec::new(),
        );
    }

    if !request
        .operator_roles
        .iter()
        .any(|role| role == "pipeline_admin")
    {
        return restart_denied(
            trace_id,
            now,
            request.operator_id.clone(),
            "ERR_PROOF_RESTART_PERMISSION_DENIED",
            "operator lacks pipeline_admin role",
            "Escalate to a pipeline_admin before requesting proof worker restart.",
            Vec::new(),
        );
    }

    let selected = match &request.target {
        ProofWorkerRestartTarget::AllWorkers => input
            .rch_workers
            .iter()
            .filter(|worker| worker_is_degraded(worker))
            .map(|worker| worker.worker_id.clone())
            .collect::<Vec<_>>(),
        ProofWorkerRestartTarget::WorkerId(worker_id) => {
            let Some(worker) = input
                .rch_workers
                .iter()
                .find(|worker| worker.worker_id == *worker_id)
            else {
                return restart_denied(
                    trace_id,
                    now,
                    request.operator_id.clone(),
                    "ERR_PROOF_RESTART_WORKER_UNAVAILABLE",
                    "target worker is not present in the supplied readiness snapshot",
                    "Refresh proof queue status and target an observed degraded worker.",
                    vec![worker_id.clone()],
                );
            };
            if !worker_is_degraded(worker) {
                return restart_denied(
                    trace_id,
                    now,
                    request.operator_id.clone(),
                    "ERR_PROOF_RESTART_WORKER_NOT_DEGRADED",
                    "target worker is reachable and remote-capable in the supplied snapshot",
                    "Use restart only for unavailable, local-fallback, or failed workers.",
                    vec![worker.worker_id.clone()],
                );
            }
            vec![worker.worker_id.clone()]
        }
    };

    if selected.is_empty() {
        return restart_denied(
            trace_id,
            now,
            request.operator_id.clone(),
            "ERR_PROOF_RESTART_NO_DEGRADED_WORKERS",
            "all-workers restart requested but no degraded workers were observed",
            "Refresh proof queue status before requesting an all-workers restart.",
            Vec::new(),
        );
    }

    ProofWorkerRestartReport {
        schema_version: PROOF_PIPELINE_RESTART_REPORT_SCHEMA_VERSION.to_string(),
        command: "proofs workers restart".to_string(),
        trace_id,
        generated_at_utc: now,
        ok: true,
        decision: "accepted".to_string(),
        reason_code: "PROOF_RESTART_REQUEST_ACCEPTED".to_string(),
        operator_id: request.operator_id.clone(),
        selected_workers: selected.clone(),
        rejected_workers: Vec::new(),
        required_action: "dispatch_restart_to_deployment_supervisor".to_string(),
        audit_event: format!(
            "operator={} requested proof worker restart for {} worker(s): {}",
            request.operator_id,
            selected.len(),
            selected.join(",")
        ),
    }
}

#[must_use]
pub fn render_restart_report_human(report: &ProofWorkerRestartReport) -> String {
    let workers = if report.selected_workers.is_empty() {
        "none".to_string()
    } else {
        report.selected_workers.join(",")
    };
    let rejected = if report.rejected_workers.is_empty() {
        "none".to_string()
    } else {
        report.rejected_workers.join(",")
    };
    [
        format!("proofs workers restart: decision={}", report.decision),
        format!("  trace_id={}", report.trace_id),
        format!("  reason_code={}", report.reason_code),
        format!("  operator_id={}", report.operator_id),
        format!("  selected_workers={workers}"),
        format!("  rejected_workers={rejected}"),
        format!("  required_action={}", report.required_action),
    ]
    .join("\n")
}

fn queue_checks(
    input: &ValidationReadinessInput,
    summary: &ProofPipelineQueueSummary,
) -> Vec<ProofPipelineCheck> {
    let broker_state = if input.proof_statuses.is_empty() && input.receipts.is_empty() {
        check(
            "PPQ-BROKER-001",
            ProofPipelineStatus::Degraded,
            "No proof statuses or receipts were supplied.",
            "Provide a validation-readiness snapshot or receipt before relying on queue status.",
        )
    } else {
        check(
            "PPQ-BROKER-001",
            ProofPipelineStatus::Healthy,
            "Proof broker state is present.",
            "No action required.",
        )
    };
    let queue = if summary.failed_proofs > 0 {
        check(
            "PPQ-QUEUE-002",
            ProofPipelineStatus::Blocked,
            format!(
                "Proof pipeline has {} failed proof(s).",
                summary.failed_proofs
            ),
            "Inspect failed receipts before scheduling new proof work.",
        )
    } else if summary.queue_depth > 0 {
        check(
            "PPQ-QUEUE-002",
            ProofPipelineStatus::Degraded,
            format!(
                "Proof pipeline has {} active proof(s).",
                summary.queue_depth
            ),
            "Wait for terminal receipts or check worker health before closeout.",
        )
    } else {
        check(
            "PPQ-QUEUE-002",
            ProofPipelineStatus::Healthy,
            "Proof queue has no active backlog.",
            "No action required.",
        )
    };
    let workers = if summary.degraded_workers > 0 {
        check(
            "PPQ-WORKER-003",
            ProofPipelineStatus::Degraded,
            format!(
                "{} degraded proof worker(s) observed.",
                summary.degraded_workers
            ),
            "Restart or drain degraded proof workers before broad validation.",
        )
    } else if input.rch_workers.is_empty() {
        check(
            "PPQ-WORKER-003",
            ProofPipelineStatus::Degraded,
            "No proof worker observations were supplied.",
            "Refresh RCH worker readiness before launching cargo-heavy proof work.",
        )
    } else {
        check(
            "PPQ-WORKER-003",
            ProofPipelineStatus::Healthy,
            "Observed proof workers are reachable and remote-capable.",
            "No action required.",
        )
    };

    vec![broker_state, queue, workers]
}

fn count_proofs(input: &ValidationReadinessInput) -> ProofKindCounts {
    let mut counts = ProofKindCounts::default();
    for status in &input.proof_statuses {
        increment_proof_count(&mut counts, status.status);
    }
    for receipt in &input.receipts {
        let status = match receipt.exit.kind {
            ValidationExitKind::Success => ProofStatusKind::Passed,
            ValidationExitKind::Failed | ValidationExitKind::Timeout => ProofStatusKind::Failed,
            ValidationExitKind::SourceOnly => ProofStatusKind::SourceOnly,
            ValidationExitKind::Cancelled => ProofStatusKind::Cancelled,
        };
        increment_proof_count(&mut counts, status);
    }
    counts
}

fn increment_proof_count(counts: &mut ProofKindCounts, status: ProofStatusKind) {
    match status {
        ProofStatusKind::Unknown => counts.unknown = counts.unknown.saturating_add(1),
        ProofStatusKind::Queued => counts.queued = counts.queued.saturating_add(1),
        ProofStatusKind::Leased => counts.leased = counts.leased.saturating_add(1),
        ProofStatusKind::Running => counts.running = counts.running.saturating_add(1),
        ProofStatusKind::Reused => counts.reused = counts.reused.saturating_add(1),
        ProofStatusKind::Failed => counts.failed = counts.failed.saturating_add(1),
        ProofStatusKind::Passed => counts.passed = counts.passed.saturating_add(1),
        ProofStatusKind::SourceOnly => counts.source_only = counts.source_only.saturating_add(1),
        ProofStatusKind::Cancelled => counts.cancelled = counts.cancelled.saturating_add(1),
    }
}

fn worker_is_ready(worker: &RchWorkerReadiness) -> bool {
    worker.reachable && worker.mode == RchMode::Remote && worker.failure.is_none()
}

fn worker_is_degraded(worker: &RchWorkerReadiness) -> bool {
    !worker_is_ready(worker)
}

fn invalid_restart_request_reason(request: &ProofWorkerRestartRequest) -> Option<&'static str> {
    if request.operator_id.trim().is_empty()
        || request.operator_id.contains('\0')
        || request.operator_id.chars().any(char::is_control)
    {
        return Some("ERR_PROOF_RESTART_OPERATOR_REQUIRED");
    }
    if request.reason.trim().is_empty()
        || request.reason.contains('\0')
        || request.reason.chars().any(char::is_control)
    {
        return Some("ERR_PROOF_RESTART_REASON_REQUIRED");
    }
    if let ProofWorkerRestartTarget::WorkerId(worker_id) = &request.target
        && (worker_id.trim().is_empty()
            || worker_id.contains('\0')
            || worker_id.chars().any(char::is_control))
    {
        return Some("ERR_PROOF_RESTART_WORKER_REQUIRED");
    }
    if !request.confirm {
        return Some("ERR_PROOF_RESTART_CONFIRMATION_REQUIRED");
    }
    None
}

fn restart_denied(
    trace_id: String,
    now: DateTime<Utc>,
    operator_id: String,
    reason_code: &str,
    decision_reason: &str,
    required_action: &str,
    rejected_workers: Vec<String>,
) -> ProofWorkerRestartReport {
    ProofWorkerRestartReport {
        schema_version: PROOF_PIPELINE_RESTART_REPORT_SCHEMA_VERSION.to_string(),
        command: "proofs workers restart".to_string(),
        trace_id,
        generated_at_utc: now,
        ok: false,
        decision: "denied".to_string(),
        reason_code: reason_code.to_string(),
        operator_id,
        selected_workers: Vec::new(),
        rejected_workers,
        required_action: required_action.to_string(),
        audit_event: decision_reason.to_string(),
    }
}

fn check(
    code: &str,
    status: ProofPipelineStatus,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> ProofPipelineCheck {
    ProofPipelineCheck {
        code: code.to_string(),
        status,
        message: message.into(),
        remediation: remediation.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::validation_broker::{ProofEvidenceSource, QueueState, ValidationProofStatus};

    fn now() -> DateTime<Utc> {
        DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH)
    }

    fn degraded_worker() -> RchWorkerReadiness {
        RchWorkerReadiness {
            worker_id: "vmi-proof-1".to_string(),
            reachable: false,
            mode: RchMode::Unavailable,
            required_toolchains: vec!["stable".to_string()],
            observed_toolchains: Vec::new(),
            failure: Some("ssh timeout".to_string()),
        }
    }

    fn input_with_running_proof() -> ValidationReadinessInput {
        ValidationReadinessInput {
            proof_statuses: vec![ValidationProofStatus {
                schema_version: crate::ops::validation_broker::STATUS_SCHEMA_VERSION.to_string(),
                bead_id: "bd-proof".to_string(),
                thread_id: "bd-proof".to_string(),
                request_id: Some("req-1".to_string()),
                queue_id: Some("queue-1".to_string()),
                status: ProofStatusKind::Running,
                proof_source: ProofEvidenceSource::BrokerQueue,
                queue_state: Some(QueueState::Running),
                deduplicated: false,
                queue_depth: 1,
                artifact_paths: None,
                command_digest: None,
                exit: None,
                reason: None,
                proof_coalescer: None,
                proof_cache: None,
                readiness_ref: None,
                flight_recorder_ref: None,
                observed_at: now(),
            }],
            rch_workers: vec![degraded_worker()],
            ..ValidationReadinessInput::default()
        }
    }

    #[test]
    fn queue_report_counts_running_proof_and_degraded_worker() {
        let report = build_queue_report(&input_with_running_proof(), "trace-1", now());

        assert_eq!(report.status, ProofPipelineStatus::Degraded);
        assert_eq!(report.summary.queue_depth, 1);
        assert_eq!(report.summary.degraded_workers, 1);
        assert_eq!(report.proof_counts.running, 1);
    }

    #[test]
    fn restart_all_workers_selects_degraded_workers() {
        let request = ProofWorkerRestartRequest {
            operator_id: "ops-1".to_string(),
            operator_roles: vec!["pipeline_admin".to_string()],
            target: ProofWorkerRestartTarget::AllWorkers,
            reason: "outage drill".to_string(),
            confirm: true,
        };

        let report = evaluate_worker_restart_request(
            &input_with_running_proof(),
            &request,
            "trace-1",
            now(),
        );

        assert!(report.ok);
        assert_eq!(report.selected_workers, vec!["vmi-proof-1"]);
    }

    #[test]
    fn restart_requires_pipeline_admin_role() {
        let request = ProofWorkerRestartRequest {
            operator_id: "ops-1".to_string(),
            operator_roles: vec!["operator".to_string()],
            target: ProofWorkerRestartTarget::AllWorkers,
            reason: "outage drill".to_string(),
            confirm: true,
        };

        let report = evaluate_worker_restart_request(
            &input_with_running_proof(),
            &request,
            "trace-1",
            now(),
        );

        assert!(!report.ok);
        assert_eq!(report.reason_code, "ERR_PROOF_RESTART_PERMISSION_DENIED");
    }

    #[test]
    fn restart_rejects_control_chars_in_operator_id() {
        for bad_id in ["ops\n-injected", "ops\r-cr", "ops\x1b[31m-ansi", "ops\t-tab"] {
            let request = ProofWorkerRestartRequest {
                operator_id: bad_id.to_string(),
                operator_roles: vec!["pipeline_admin".to_string()],
                target: ProofWorkerRestartTarget::AllWorkers,
                reason: "outage drill".to_string(),
                confirm: true,
            };

            let report = evaluate_worker_restart_request(
                &input_with_running_proof(),
                &request,
                "trace-control-char",
                now(),
            );

            assert!(
                !report.ok,
                "accepted operator_id with control char: {bad_id:?}"
            );
            assert_eq!(report.reason_code, "ERR_PROOF_RESTART_OPERATOR_REQUIRED");
        }
    }

    #[test]
    fn restart_rejects_control_chars_in_reason() {
        let request = ProofWorkerRestartRequest {
            operator_id: "ops-1".to_string(),
            operator_roles: vec!["pipeline_admin".to_string()],
            target: ProofWorkerRestartTarget::AllWorkers,
            reason: "drill\nINJECTED_LOG_ENTRY".to_string(),
            confirm: true,
        };

        let report = evaluate_worker_restart_request(
            &input_with_running_proof(),
            &request,
            "trace-reason-injection",
            now(),
        );

        assert!(!report.ok);
        assert_eq!(report.reason_code, "ERR_PROOF_RESTART_REASON_REQUIRED");
    }

    #[test]
    fn restart_rejects_control_chars_in_worker_id() {
        let request = ProofWorkerRestartRequest {
            operator_id: "ops-1".to_string(),
            operator_roles: vec!["pipeline_admin".to_string()],
            target: ProofWorkerRestartTarget::WorkerId("vmi\n-proof-1".to_string()),
            reason: "outage drill".to_string(),
            confirm: true,
        };

        let report = evaluate_worker_restart_request(
            &input_with_running_proof(),
            &request,
            "trace-worker-injection",
            now(),
        );

        assert!(!report.ok);
        assert_eq!(report.reason_code, "ERR_PROOF_RESTART_WORKER_REQUIRED");
    }
}
