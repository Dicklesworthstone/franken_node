//! Proof-pipeline operator status and restart request evaluation.
//!
//! The proof-pipeline surface is intentionally a thin operator layer over the
//! validation broker/readiness model. It reports queue health from broker
//! snapshots and validates restart requests without inventing a second proof
//! worker registry.

use crate::ops::validation_broker::{
    CommandSpec, ProofStatusKind, RchMode, TimeoutClass, ValidationErrorClass, ValidationExitKind,
    ValidationReceipt,
};
use crate::ops::validation_proof_coalescer::{
    ValidationSwarmSchedulerDecision, ValidationSwarmSchedulerDecisionKind,
};
use crate::ops::validation_readiness::{
    ProofKindCounts, RchWorkerReadiness, SwarmSchedulerReadinessSummary, ValidationReadinessInput,
    summarize_swarm_scheduler_decisions,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const PROOF_PIPELINE_QUEUE_REPORT_SCHEMA_VERSION: &str =
    "franken-node/proof-pipeline/queue-report/v1";
pub const PROOF_PIPELINE_RESTART_REPORT_SCHEMA_VERSION: &str =
    "franken-node/proof-pipeline/restart-report/v1";
pub const PROOF_WORKER_SCHEDULING_BASELINE_SCHEMA_VERSION: &str =
    "franken-node/proof-pipeline/worker-scheduling-baseline/v1";

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
pub struct ProofWorkerSchedulingBaselineEnvironment {
    pub environment_id: String,
    pub observed_at_utc: DateTime<Utc>,
    pub rch_status_posture: String,
    pub rch_workers_healthy: u16,
    pub rch_workers_total: u16,
    pub rch_slots_available: u16,
    pub rch_slots_total: u16,
    pub rch_queue_active_builds: u16,
    pub rch_queue_waiting_builds: u16,
    pub worker_probe_reachable: u16,
    pub worker_probe_total: u16,
    #[serde(default)]
    pub storage_pressure_notes: Vec<String>,
    #[serde(default)]
    pub evidence_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofWorkerSchedulingBaselineMetrics {
    pub samples: usize,
    pub service_time_ms_p50: u64,
    pub service_time_ms_p95: u64,
    pub service_time_ms_p99: u64,
    pub service_time_ms_max: u64,
    pub queue_wait_ms_p95: u64,
    pub queue_wait_ms_p99: u64,
    pub queue_wait_ms_max: u64,
    pub retryable_samples: usize,
    pub retry_rate: f64,
    pub worker_exclusion_samples: usize,
    pub worker_exclusion_rate: f64,
    pub remote_selected_samples: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofWorkerSchedulingBaselineSample {
    pub sample_id: String,
    pub source: String,
    pub reference_id: String,
    pub bead_id: String,
    pub trace_id: String,
    pub queue_depth: u16,
    pub selected_worker: Option<String>,
    pub worker_health_class: String,
    pub command_class: String,
    pub queue_wait_ms: u64,
    pub wall_time_ms: u64,
    pub outcome_class: String,
    pub retry_recovery_action: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofWorkerSchedulingBaselineReport {
    pub schema_version: String,
    pub command: String,
    pub trace_id: String,
    pub generated_at_utc: DateTime<Utc>,
    pub status: ProofPipelineStatus,
    pub measurement_mode: String,
    pub environment: ProofWorkerSchedulingBaselineEnvironment,
    pub queue_summary: ProofPipelineQueueSummary,
    pub scheduler_summary: SwarmSchedulerReadinessSummary,
    pub metrics: ProofWorkerSchedulingBaselineMetrics,
    pub samples: Vec<ProofWorkerSchedulingBaselineSample>,
    pub checks: Vec<ProofPipelineCheck>,
}

#[derive(Serialize)]
struct ProofWorkerSchedulingBaselineJsonlRecord<'a> {
    schema_version: &'static str,
    command: &'a str,
    trace_id: &'a str,
    generated_at_utc: DateTime<Utc>,
    measurement_mode: &'a str,
    environment: &'a ProofWorkerSchedulingBaselineEnvironment,
    metrics: &'a ProofWorkerSchedulingBaselineMetrics,
    sample: &'a ProofWorkerSchedulingBaselineSample,
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
pub fn build_worker_scheduling_baseline_report(
    input: &ValidationReadinessInput,
    trace_id: impl Into<String>,
    now: DateTime<Utc>,
    environment: ProofWorkerSchedulingBaselineEnvironment,
) -> ProofWorkerSchedulingBaselineReport {
    let trace_id = trace_id.into();
    let queue_report = build_queue_report(input, trace_id.clone(), now);
    let scheduler_summary = summarize_swarm_scheduler_decisions(&input.swarm_scheduler_decisions);
    let samples = worker_scheduling_baseline_samples(input);
    let metrics = summarize_worker_scheduling_baseline_metrics(&samples);
    let mut checks = queue_report.checks.clone();
    checks.extend(worker_scheduling_baseline_checks(
        &scheduler_summary,
        &metrics,
    ));
    let status = checks
        .iter()
        .fold(ProofPipelineStatus::Healthy, |acc, check| {
            acc.max(check.status)
        });

    ProofWorkerSchedulingBaselineReport {
        schema_version: PROOF_WORKER_SCHEDULING_BASELINE_SCHEMA_VERSION.to_string(),
        command: "proofs workers scheduling-baseline".to_string(),
        trace_id,
        generated_at_utc: now,
        status,
        measurement_mode: "baseline_only_no_performance_improvement_claimed".to_string(),
        environment,
        queue_summary: queue_report.summary,
        scheduler_summary,
        metrics,
        samples,
        checks,
    }
}

pub fn render_worker_scheduling_baseline_jsonl(
    report: &ProofWorkerSchedulingBaselineReport,
) -> Result<String, serde_json::Error> {
    let mut lines = Vec::with_capacity(report.samples.len());
    for sample in &report.samples {
        let record = ProofWorkerSchedulingBaselineJsonlRecord {
            schema_version: PROOF_WORKER_SCHEDULING_BASELINE_SCHEMA_VERSION,
            command: &report.command,
            trace_id: &report.trace_id,
            generated_at_utc: report.generated_at_utc,
            measurement_mode: &report.measurement_mode,
            environment: &report.environment,
            metrics: &report.metrics,
            sample,
        };
        lines.push(serde_json::to_string(&record)?);
    }
    Ok(lines.join("\n"))
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

fn worker_scheduling_baseline_checks(
    scheduler_summary: &SwarmSchedulerReadinessSummary,
    metrics: &ProofWorkerSchedulingBaselineMetrics,
) -> Vec<ProofPipelineCheck> {
    let samples = if metrics.samples == 0 {
        check(
            "PPB-SAMPLES-001",
            ProofPipelineStatus::Degraded,
            "No proof-worker scheduling baseline samples were supplied.",
            "Collect scheduler decisions or validation receipts before using the baseline.",
        )
    } else {
        check(
            "PPB-SAMPLES-001",
            ProofPipelineStatus::Healthy,
            format!(
                "Proof-worker baseline includes {} sample(s).",
                metrics.samples
            ),
            "No action required.",
        )
    };
    let scheduler = if scheduler_summary.decisions == 0 {
        check(
            "PPB-SCHEDULER-002",
            ProofPipelineStatus::Degraded,
            "No swarm-scheduler decisions were supplied.",
            "Add synthetic or live scheduler decisions before comparing worker routing.",
        )
    } else {
        check(
            "PPB-SCHEDULER-002",
            ProofPipelineStatus::Healthy,
            format!(
                "Scheduler baseline covers {} decision(s); queue_age_p95_ms={}.",
                scheduler_summary.decisions, scheduler_summary.queue_age_p95_ms
            ),
            "No action required.",
        )
    };
    let worker_exclusion = if metrics.worker_exclusion_samples > 0 {
        check(
            "PPB-WORKER-003",
            ProofPipelineStatus::Degraded,
            format!(
                "{} sample(s) excluded remote-ready worker execution.",
                metrics.worker_exclusion_samples
            ),
            "Treat exclusion rate as baseline evidence only; collect post-change evidence before claiming improvement.",
        )
    } else {
        check(
            "PPB-WORKER-003",
            ProofPipelineStatus::Healthy,
            "All baseline samples selected remote-ready workers.",
            "No action required.",
        )
    };

    vec![samples, scheduler, worker_exclusion]
}

fn worker_scheduling_baseline_samples(
    input: &ValidationReadinessInput,
) -> Vec<ProofWorkerSchedulingBaselineSample> {
    let mut samples = input
        .swarm_scheduler_decisions
        .iter()
        .enumerate()
        .map(|(index, decision)| scheduler_baseline_sample(input, decision, index))
        .collect::<Vec<_>>();
    samples.extend(
        input
            .receipts
            .iter()
            .enumerate()
            .map(|(index, receipt)| receipt_baseline_sample(receipt, index)),
    );
    samples
}

fn scheduler_baseline_sample(
    input: &ValidationReadinessInput,
    decision: &ValidationSwarmSchedulerDecision,
    index: usize,
) -> ProofWorkerSchedulingBaselineSample {
    let selected_worker = selected_worker_for_scheduler_decision(input, decision);
    let worker_health_class =
        scheduler_worker_health_class(input, decision, selected_worker.as_deref());
    ProofWorkerSchedulingBaselineSample {
        sample_id: format!("scheduler-{index:03}-{}", decision.decision_id),
        source: "swarm_scheduler_decision".to_string(),
        reference_id: decision.decision_id.clone(),
        bead_id: decision.bead_id.clone(),
        trace_id: decision.trace_id.clone(),
        queue_depth: decision.diagnostics.queue_depth,
        selected_worker,
        worker_health_class,
        command_class: scheduler_command_class(decision).to_string(),
        queue_wait_ms: decision.diagnostics.queue_age_ms,
        wall_time_ms: 0,
        outcome_class: decision.decision.as_str().to_string(),
        retry_recovery_action: decision.required_action.as_str().to_string(),
        retryable: decision.retryable,
    }
}

fn receipt_baseline_sample(
    receipt: &ValidationReceipt,
    index: usize,
) -> ProofWorkerSchedulingBaselineSample {
    ProofWorkerSchedulingBaselineSample {
        sample_id: format!("receipt-{index:03}-{}", receipt.receipt_id),
        source: "validation_receipt".to_string(),
        reference_id: receipt.receipt_id.clone(),
        bead_id: receipt.bead_id.clone(),
        trace_id: receipt.request_id.clone(),
        queue_depth: 0,
        selected_worker: receipt.rch.worker_id.clone(),
        worker_health_class: receipt_worker_health_class(receipt).to_string(),
        command_class: classify_command(&receipt.command).to_string(),
        queue_wait_ms: if receipt.exit.timeout_class == TimeoutClass::QueueWait {
            receipt.timing.duration_ms
        } else {
            0
        },
        wall_time_ms: receipt.timing.duration_ms,
        outcome_class: receipt_outcome_class(receipt),
        retry_recovery_action: receipt_recovery_action(receipt).to_string(),
        retryable: receipt.exit.retryable,
    }
}

fn summarize_worker_scheduling_baseline_metrics(
    samples: &[ProofWorkerSchedulingBaselineSample],
) -> ProofWorkerSchedulingBaselineMetrics {
    let service_times = samples
        .iter()
        .filter_map(|sample| (sample.wall_time_ms > 0).then_some(sample.wall_time_ms))
        .collect::<Vec<_>>();
    let queue_wait_times = samples
        .iter()
        .map(|sample| sample.queue_wait_ms)
        .collect::<Vec<_>>();
    let retryable_samples = samples.iter().filter(|sample| sample.retryable).count();
    let worker_exclusion_samples = samples
        .iter()
        .filter(|sample| worker_execution_excluded(sample))
        .count();
    let remote_selected_samples = samples
        .iter()
        .filter(|sample| {
            matches!(
                sample.worker_health_class.as_str(),
                "remote_ready" | "remote_selected"
            )
        })
        .count();

    ProofWorkerSchedulingBaselineMetrics {
        samples: samples.len(),
        service_time_ms_p50: percentile(&service_times, 50),
        service_time_ms_p95: percentile(&service_times, 95),
        service_time_ms_p99: percentile(&service_times, 99),
        service_time_ms_max: service_times.iter().copied().max().unwrap_or_default(),
        queue_wait_ms_p95: percentile(&queue_wait_times, 95),
        queue_wait_ms_p99: percentile(&queue_wait_times, 99),
        queue_wait_ms_max: queue_wait_times.iter().copied().max().unwrap_or_default(),
        retryable_samples,
        retry_rate: ratio(retryable_samples, samples.len()),
        worker_exclusion_samples,
        worker_exclusion_rate: ratio(worker_exclusion_samples, samples.len()),
        remote_selected_samples,
    }
}

fn selected_worker_for_scheduler_decision(
    input: &ValidationReadinessInput,
    decision: &ValidationSwarmSchedulerDecision,
) -> Option<String> {
    if !matches!(
        decision.decision,
        ValidationSwarmSchedulerDecisionKind::RunNow
            | ValidationSwarmSchedulerDecisionKind::StealStaleWork
    ) {
        return None;
    }

    input
        .rch_workers
        .iter()
        .find(|worker| worker_is_ready(worker))
        .map(|worker| worker.worker_id.clone())
}

fn scheduler_worker_health_class(
    input: &ValidationReadinessInput,
    decision: &ValidationSwarmSchedulerDecision,
    selected_worker: Option<&str>,
) -> String {
    if let Some(worker) = selected_worker.and_then(|worker_id| {
        input
            .rch_workers
            .iter()
            .find(|worker| worker.worker_id == worker_id)
    }) {
        return readiness_worker_health_class(worker).to_string();
    }

    match decision.decision {
        ValidationSwarmSchedulerDecisionKind::RunNow
        | ValidationSwarmSchedulerDecisionKind::StealStaleWork => "remote_ready_worker_missing",
        ValidationSwarmSchedulerDecisionKind::JoinExisting => "joined_existing_proof",
        ValidationSwarmSchedulerDecisionKind::WaitForCapacity => "capacity_wait_no_worker_selected",
        ValidationSwarmSchedulerDecisionKind::RejectLowPriority => "deferred_low_priority",
        ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker => "source_only_blocker",
        ValidationSwarmSchedulerDecisionKind::FailClosedProduct => "product_failure_no_worker",
        ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact => {
            "invalid_artifact_no_worker"
        }
    }
    .to_string()
}

fn readiness_worker_health_class(worker: &RchWorkerReadiness) -> &'static str {
    if worker_is_ready(worker) {
        return "remote_ready";
    }
    match worker.mode {
        RchMode::Remote if worker.failure.is_some() => "remote_failed",
        RchMode::Remote => "remote_unreachable",
        RchMode::LocalFallback => "local_fallback",
        RchMode::NotUsed => "not_used",
        RchMode::Unavailable => "unavailable",
    }
}

fn receipt_worker_health_class(receipt: &ValidationReceipt) -> &'static str {
    match receipt.rch.mode {
        RchMode::Remote if receipt.rch.worker_id.is_some() => "remote_selected",
        RchMode::Remote => "remote_missing_worker_id",
        RchMode::LocalFallback => "local_fallback",
        RchMode::NotUsed => "not_used",
        RchMode::Unavailable => "unavailable",
    }
}

fn scheduler_command_class(decision: &ValidationSwarmSchedulerDecision) -> &'static str {
    match decision.decision {
        ValidationSwarmSchedulerDecisionKind::RunNow
        | ValidationSwarmSchedulerDecisionKind::WaitForCapacity
        | ValidationSwarmSchedulerDecisionKind::StealStaleWork => "cargo_validation",
        ValidationSwarmSchedulerDecisionKind::JoinExisting => "proof_join",
        ValidationSwarmSchedulerDecisionKind::RejectLowPriority
        | ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker
        | ValidationSwarmSchedulerDecisionKind::FailClosedProduct
        | ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact => "not_scheduled",
    }
}

fn classify_command(command: &CommandSpec) -> &'static str {
    let is_cargo = command.program == "cargo" || command.argv.iter().any(|arg| arg == "cargo");
    if !is_cargo {
        return "external_command";
    }
    if command.argv.iter().any(|arg| arg == "test") {
        "cargo_test"
    } else if command.argv.iter().any(|arg| arg == "check") {
        "cargo_check"
    } else if command.argv.iter().any(|arg| arg == "clippy") {
        "cargo_clippy"
    } else if command.argv.iter().any(|arg| arg == "fmt") {
        "cargo_fmt"
    } else {
        "cargo_other"
    }
}

fn receipt_outcome_class(receipt: &ValidationReceipt) -> String {
    let exit = validation_exit_kind_as_str(receipt.exit.kind);
    let error = validation_error_class_as_str(receipt.exit.error_class);
    if error == "none" {
        exit.to_string()
    } else {
        format!("{exit}_{error}")
    }
}

fn receipt_recovery_action(receipt: &ValidationReceipt) -> &'static str {
    if receipt.exit.kind == ValidationExitKind::Success {
        return "no_action_required";
    }
    if receipt.exit.kind == ValidationExitKind::SourceOnly
        || receipt.classifications.source_only_fallback
    {
        return "record_source_only_blocker";
    }
    if receipt.exit.retryable {
        return "retry_rch_validation";
    }
    match receipt.exit.error_class {
        ValidationErrorClass::WorkerInfra
        | ValidationErrorClass::TransportTimeout
        | ValidationErrorClass::EnvironmentContention
        | ValidationErrorClass::DiskPressure => "recover_worker_infrastructure",
        ValidationErrorClass::CompileError
        | ValidationErrorClass::TestFailure
        | ValidationErrorClass::ClippyWarning
        | ValidationErrorClass::FormatFailure => "surface_product_failure",
        ValidationErrorClass::None
        | ValidationErrorClass::SourceOnly
        | ValidationErrorClass::Unknown => "manual_review",
    }
}

fn worker_execution_excluded(sample: &ProofWorkerSchedulingBaselineSample) -> bool {
    sample.selected_worker.is_none()
        || !matches!(
            sample.worker_health_class.as_str(),
            "remote_ready" | "remote_selected"
        )
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let index = sorted
        .len()
        .saturating_mul(percentile)
        .saturating_add(99)
        .checked_div(100)
        .unwrap_or(1)
        .saturating_sub(1)
        .min(sorted.len().saturating_sub(1));
    sorted[index]
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn validation_exit_kind_as_str(kind: ValidationExitKind) -> &'static str {
    match kind {
        ValidationExitKind::Success => "success",
        ValidationExitKind::Failed => "failed",
        ValidationExitKind::Timeout => "timeout",
        ValidationExitKind::SourceOnly => "source_only",
        ValidationExitKind::Cancelled => "cancelled",
    }
}

fn validation_error_class_as_str(error_class: ValidationErrorClass) -> &'static str {
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
    use crate::ops::validation_proof_coalescer::{
        ValidationSwarmSchedulerCoalescerState, ValidationSwarmSchedulerDiagnostics,
        ValidationSwarmSchedulerFairnessBucket, ValidationSwarmSchedulerFlightRecorderState,
        ValidationSwarmSchedulerProofDebtClass, ValidationSwarmSchedulerRequiredAction,
        ValidationSwarmSchedulerStarvationRisk,
    };

    fn now() -> DateTime<Utc> {
        DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH)
    }

    fn ready_worker() -> RchWorkerReadiness {
        RchWorkerReadiness {
            worker_id: "vmi-proof-ready".to_string(),
            reachable: true,
            mode: RchMode::Remote,
            required_toolchains: vec!["stable".to_string()],
            observed_toolchains: vec!["stable".to_string()],
            failure: None,
        }
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

    fn baseline_environment() -> ProofWorkerSchedulingBaselineEnvironment {
        ProofWorkerSchedulingBaselineEnvironment {
            environment_id: "test-rch-baseline".to_string(),
            observed_at_utc: now(),
            rch_status_posture: "degraded".to_string(),
            rch_workers_healthy: 1,
            rch_workers_total: 2,
            rch_slots_available: 1,
            rch_slots_total: 8,
            rch_queue_active_builds: 0,
            rch_queue_waiting_builds: 0,
            worker_probe_reachable: 2,
            worker_probe_total: 2,
            storage_pressure_notes: vec!["synthetic fixture".to_string()],
            evidence_notes: vec!["measurement-first baseline".to_string()],
        }
    }

    fn scheduler_decision(
        decision: ValidationSwarmSchedulerDecisionKind,
        decision_id: &str,
        queue_age_ms: u64,
        queue_depth: u16,
        slots_available: u16,
        retryable: bool,
    ) -> ValidationSwarmSchedulerDecision {
        let (required_action, reason_code, event_code, proof_debt_class) = match decision {
            ValidationSwarmSchedulerDecisionKind::RunNow => (
                ValidationSwarmSchedulerRequiredAction::StartRchValidation,
                "VSS_RUN_READY",
                "VSS-001",
                ValidationSwarmSchedulerProofDebtClass::None,
            ),
            ValidationSwarmSchedulerDecisionKind::WaitForCapacity => (
                ValidationSwarmSchedulerRequiredAction::WaitForCapacity,
                "VSS_WAIT_CAPACITY",
                "VSS-003",
                ValidationSwarmSchedulerProofDebtClass::Capacity,
            ),
            ValidationSwarmSchedulerDecisionKind::StealStaleWork => (
                ValidationSwarmSchedulerRequiredAction::StealWithNewFence,
                "VSS_STEAL_STALE",
                "VSS-004",
                ValidationSwarmSchedulerProofDebtClass::StaleProducer,
            ),
            ValidationSwarmSchedulerDecisionKind::JoinExisting => (
                ValidationSwarmSchedulerRequiredAction::JoinExistingProof,
                "VSS_JOIN_IDENTICAL",
                "VSS-002",
                ValidationSwarmSchedulerProofDebtClass::None,
            ),
            ValidationSwarmSchedulerDecisionKind::RejectLowPriority => (
                ValidationSwarmSchedulerRequiredAction::DeferLowPriority,
                "VSS_REJECT_LOW_PRIORITY",
                "VSS-005",
                ValidationSwarmSchedulerProofDebtClass::Capacity,
            ),
            ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker => (
                ValidationSwarmSchedulerRequiredAction::RecordSourceOnlyBlocker,
                "VSS_SOURCE_ONLY_BLOCKER",
                "VSS-006",
                ValidationSwarmSchedulerProofDebtClass::SourceOnly,
            ),
            ValidationSwarmSchedulerDecisionKind::FailClosedProduct => (
                ValidationSwarmSchedulerRequiredAction::SurfaceProductFailure,
                "VSS_FAIL_PRODUCT",
                "VSS-007",
                ValidationSwarmSchedulerProofDebtClass::ProductFailure,
            ),
            ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact => (
                ValidationSwarmSchedulerRequiredAction::RejectArtifact,
                "VSS_FAIL_INVALID_ARTIFACT",
                "VSS-008",
                ValidationSwarmSchedulerProofDebtClass::InvalidArtifact,
            ),
        };

        ValidationSwarmSchedulerDecision {
            schema_version:
                crate::ops::validation_proof_coalescer::SWARM_SCHEDULER_DECISION_SCHEMA_VERSION
                    .to_string(),
            decision_id: decision_id.to_string(),
            input_ref: "synthetic-input".to_string(),
            bead_id: "bd-98xo5.18".to_string(),
            agent_name: "SilverMaple".to_string(),
            trace_id: format!("trace-{decision_id}"),
            decided_at: now(),
            freshness_expires_at: now(),
            decision,
            reason_code: reason_code.to_string(),
            event_code: event_code.to_string(),
            required_action,
            fairness_bucket: ValidationSwarmSchedulerFairnessBucket::Normal,
            starvation_risk: ValidationSwarmSchedulerStarvationRisk::None,
            retryable,
            fail_closed: matches!(
                decision,
                ValidationSwarmSchedulerDecisionKind::FailClosedProduct
                    | ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact
            ),
            green_proof_eligible: matches!(decision, ValidationSwarmSchedulerDecisionKind::RunNow),
            operator_message: "synthetic scheduler fixture".to_string(),
            diagnostics: ValidationSwarmSchedulerDiagnostics {
                proof_work_key_hex: "a".repeat(64),
                command_digest_hex: "b".repeat(64),
                capacity_snapshot_id: "synthetic-capacity".to_string(),
                queue_age_ms,
                slots_total: 8,
                slots_available,
                worker_slots: 4,
                queue_depth,
                coalescer_state: ValidationSwarmSchedulerCoalescerState::None,
                flight_recorder_state: ValidationSwarmSchedulerFlightRecorderState::None,
                proof_debt_class,
                retry_after_ms: retryable.then_some(30_000),
                fencing_token_digest: None,
                recorder_path: Some(format!("artifacts/validation_broker/{decision_id}.json")),
            },
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
    fn worker_scheduling_baseline_records_run_and_capacity_wait_decisions() {
        let mut input = input_with_running_proof();
        input.rch_workers = vec![ready_worker(), degraded_worker()];
        input.swarm_scheduler_decisions = vec![
            scheduler_decision(
                ValidationSwarmSchedulerDecisionKind::RunNow,
                "run-now",
                120,
                3,
                4,
                false,
            ),
            scheduler_decision(
                ValidationSwarmSchedulerDecisionKind::WaitForCapacity,
                "wait-capacity",
                900,
                86,
                0,
                true,
            ),
        ];

        let report = build_worker_scheduling_baseline_report(
            &input,
            "trace-baseline",
            now(),
            baseline_environment(),
        );

        assert_eq!(
            report.schema_version,
            PROOF_WORKER_SCHEDULING_BASELINE_SCHEMA_VERSION
        );
        assert_eq!(
            report.measurement_mode,
            "baseline_only_no_performance_improvement_claimed"
        );
        assert_eq!(report.scheduler_summary.decisions, 2);
        assert_eq!(report.scheduler_summary.capacity_waits, 1);
        assert_eq!(report.metrics.samples, 2);
        assert_eq!(report.metrics.queue_wait_ms_p95, 900);
        assert_eq!(report.metrics.queue_wait_ms_p99, 900);
        assert_eq!(report.metrics.retryable_samples, 1);
        assert_eq!(report.metrics.worker_exclusion_samples, 1);

        let run_now = &report.samples[0];
        assert_eq!(run_now.queue_depth, 3);
        assert_eq!(run_now.selected_worker.as_deref(), Some("vmi-proof-ready"));
        assert_eq!(run_now.worker_health_class, "remote_ready");
        assert_eq!(run_now.command_class, "cargo_validation");
        assert_eq!(run_now.wall_time_ms, 0);
        assert_eq!(run_now.outcome_class, "run_now");
        assert_eq!(run_now.retry_recovery_action, "start_rch_validation");

        let wait = &report.samples[1];
        assert_eq!(wait.queue_depth, 86);
        assert_eq!(wait.selected_worker, None);
        assert_eq!(wait.worker_health_class, "capacity_wait_no_worker_selected");
        assert_eq!(wait.outcome_class, "wait_for_capacity");
        assert_eq!(wait.retry_recovery_action, "wait_for_capacity");
        assert!(wait.retryable);
    }

    #[test]
    fn worker_scheduling_baseline_renders_sample_jsonl_records() {
        let mut input = input_with_running_proof();
        input.rch_workers = vec![ready_worker()];
        input.swarm_scheduler_decisions = vec![scheduler_decision(
            ValidationSwarmSchedulerDecisionKind::RunNow,
            "run-now",
            42,
            1,
            2,
            false,
        )];
        let report = build_worker_scheduling_baseline_report(
            &input,
            "trace-jsonl",
            now(),
            baseline_environment(),
        );

        let jsonl =
            render_worker_scheduling_baseline_jsonl(&report).expect("baseline JSONL should render");
        let record: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().expect("one JSONL line"))
                .expect("baseline JSONL line should parse");

        assert_eq!(
            record["schema_version"].as_str(),
            Some(PROOF_WORKER_SCHEDULING_BASELINE_SCHEMA_VERSION)
        );
        assert_eq!(
            record["measurement_mode"].as_str(),
            Some("baseline_only_no_performance_improvement_claimed")
        );
        assert_eq!(record["sample"]["queue_depth"].as_u64(), Some(1));
        assert_eq!(
            record["sample"]["selected_worker"].as_str(),
            Some("vmi-proof-ready")
        );
        assert_eq!(
            record["sample"]["worker_health_class"].as_str(),
            Some("remote_ready")
        );
        assert_eq!(
            record["sample"]["retry_recovery_action"].as_str(),
            Some("start_rch_validation")
        );
    }

    #[test]
    fn checked_in_baseline_artifact_records_required_jsonl_fields() {
        let artifact = include_str!(
            "../../../../artifacts/validation_broker/bd-98xo5.18/rch-proof-worker-baseline.jsonl"
        );
        let mut lines = artifact.lines().filter(|line| !line.trim().is_empty());
        let record: serde_json::Value = serde_json::from_str(
            lines
                .next()
                .expect("checked-in baseline artifact should include a JSONL record"),
        )
        .expect("checked-in baseline artifact should parse as JSON");

        assert_eq!(
            record["schema_version"].as_str(),
            Some(PROOF_WORKER_SCHEDULING_BASELINE_SCHEMA_VERSION)
        );
        assert_eq!(
            record["measurement_mode"].as_str(),
            Some("baseline_only_no_performance_improvement_claimed")
        );
        assert_eq!(record["environment"]["rch_workers_total"].as_u64(), Some(9));
        assert_eq!(
            record["environment"]["worker_probe_reachable"].as_u64(),
            Some(9)
        );
        for field in [
            "queue_depth",
            "selected_worker",
            "worker_health_class",
            "command_class",
            "wall_time_ms",
            "outcome_class",
            "retry_recovery_action",
        ] {
            assert!(
                record["sample"].get(field).is_some(),
                "missing baseline sample field {field}"
            );
        }
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
        for bad_id in [
            "ops\n-injected",
            "ops\r-cr",
            "ops\x1b[31m-ansi",
            "ops\t-tab",
        ] {
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
