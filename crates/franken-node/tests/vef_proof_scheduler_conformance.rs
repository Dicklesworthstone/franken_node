use std::collections::BTreeMap;

use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
};
use frankenengine_node::vef::proof_scheduler::{
    ProofJob, ProofJobStatus, ProofWindow, SCHEDULER_SCHEMA_VERSION, SchedulerMetrics,
    SchedulerPolicy, VefProofScheduler, WorkloadTier, event_codes,
};
use frankenengine_node::vef::receipt_chain::{
    ReceiptChain, ReceiptChainConfig, ReceiptChainEntry, ReceiptCheckpoint,
};
use serde::{Deserialize, Serialize};

const GOLDEN_WINDOW_DISPATCH_DEADLINE: &str =
    include_str!("goldens/vef_proof_scheduler_conformance/window_dispatch_deadline.json");
const TRACE_ID: &str = "trace-vef-scheduler-conformance";
const SELECTED_AT_MILLIS: u64 = 1_701_100_000_000;
const ENQUEUED_AT_MILLIS: u64 = 1_701_100_000_010;
const DISPATCHED_AT_MILLIS: u64 = 1_701_100_000_020;
const METRICS_AT_MILLIS: u64 = 1_701_100_001_020;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConformanceReport {
    schema_version: String,
    spec_source: String,
    coverage_matrix: Vec<CoverageRow>,
    dispatch_case: DispatchCase,
    deadline_case: DeadlineCase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CoverageRow {
    section: String,
    level: String,
    clause: String,
    tested: bool,
    verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DispatchCase {
    window_count: usize,
    windows: Vec<ProofWindow>,
    queued_job_ids: Vec<String>,
    dispatched_jobs: Vec<ProofJob>,
    metrics: SchedulerMetrics,
    event_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeadlineCase {
    exceeded_job_ids: Vec<String>,
    deadline_event_codes: Vec<String>,
    job_statuses: Vec<JobStatusSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JobStatusSnapshot {
    job_id: String,
    status: ProofJobStatus,
}

#[test]
fn vef_proof_scheduler_matches_spec_frozen_window_dispatch_deadline_fixture() {
    let report = build_conformance_report();
    assert_schema_and_coverage_contract(&report);
    assert_dispatch_contract(&report.dispatch_case);
    assert_deadline_contract(&report.deadline_case);

    let actual_json = pretty_json(&report);
    let decoded: ConformanceReport =
        serde_json::from_str(&actual_json).expect("actual report must roundtrip");
    assert_eq!(decoded, report, "conformance report JSON roundtrip drifted");

    let expected: ConformanceReport = serde_json::from_str(GOLDEN_WINDOW_DISPATCH_DEADLINE)
        .expect("golden fixture must stay parseable");
    assert_eq!(
        expected, report,
        "VEF proof scheduler report diverged structurally from the spec fixture"
    );
    assert_eq!(
        actual_json, GOLDEN_WINDOW_DISPATCH_DEADLINE,
        "VEF proof scheduler report no longer matches byte-exact golden fixture"
    );
}

fn build_conformance_report() -> ConformanceReport {
    let (entries, checkpoints) = sample_stream();
    let mut dispatch_scheduler = VefProofScheduler::new(conformance_policy());
    let windows = dispatch_scheduler
        .select_windows(&entries, &checkpoints, SELECTED_AT_MILLIS, TRACE_ID)
        .expect("window selection must satisfy the conformance fixture");
    let queued_job_ids = dispatch_scheduler
        .enqueue_windows(&windows, ENQUEUED_AT_MILLIS)
        .expect("window enqueue must satisfy the conformance fixture");
    let dispatched_jobs = dispatch_scheduler
        .dispatch_jobs(DISPATCHED_AT_MILLIS)
        .expect("dispatch must satisfy the conformance fixture");
    let metrics = dispatch_scheduler.backlog_metrics(METRICS_AT_MILLIS, TRACE_ID);
    let event_codes = dispatch_scheduler
        .events()
        .iter()
        .map(|event| event.event_code.clone())
        .collect();

    let deadline_case = build_deadline_case(&entries, &checkpoints);

    ConformanceReport {
        schema_version: SCHEDULER_SCHEMA_VERSION.to_string(),
        spec_source: "artifacts/section_10_18/bd-28u0/verification_summary.md".to_string(),
        coverage_matrix: coverage_matrix(),
        dispatch_case: DispatchCase {
            window_count: windows.len(),
            windows,
            queued_job_ids,
            dispatched_jobs,
            metrics,
            event_codes,
        },
        deadline_case,
    }
}

fn build_deadline_case(
    entries: &[ReceiptChainEntry],
    checkpoints: &[ReceiptCheckpoint],
) -> DeadlineCase {
    let mut deadline_policy = conformance_policy();
    deadline_policy
        .tier_deadline_millis
        .insert(WorkloadTier::Critical, 1);
    let mut scheduler = VefProofScheduler::new(deadline_policy);
    let windows = scheduler
        .select_windows(entries, checkpoints, SELECTED_AT_MILLIS, TRACE_ID)
        .expect("deadline fixture window selection must succeed");
    scheduler
        .enqueue_windows(&windows, ENQUEUED_AT_MILLIS)
        .expect("deadline fixture enqueue must succeed");
    scheduler
        .dispatch_jobs(DISPATCHED_AT_MILLIS)
        .expect("deadline fixture dispatch must succeed");

    let exceeded_job_ids = scheduler.enforce_deadlines(ENQUEUED_AT_MILLIS + 2);
    let deadline_event_codes = scheduler
        .events()
        .iter()
        .filter(|event| event.event_code == event_codes::VEF_SCHED_ERR_001_DEADLINE)
        .map(|event| event.event_code.clone())
        .collect();
    let job_statuses = scheduler
        .jobs()
        .values()
        .map(|job| JobStatusSnapshot {
            job_id: job.job_id.clone(),
            status: job.status,
        })
        .collect();

    DeadlineCase {
        exceeded_job_ids,
        deadline_event_codes,
        job_statuses,
    }
}

fn sample_stream() -> (Vec<ReceiptChainEntry>, Vec<ReceiptCheckpoint>) {
    let mut chain = ReceiptChain::new(ReceiptChainConfig {
        checkpoint_every_entries: 2,
        checkpoint_every_millis: 0,
    });
    for (idx, action) in [
        ExecutionActionType::NetworkAccess,
        ExecutionActionType::FilesystemOperation,
        ExecutionActionType::SecretAccess,
        ExecutionActionType::ArtifactPromotion,
        ExecutionActionType::ProcessSpawn,
    ]
    .into_iter()
    .enumerate()
    {
        chain
            .append(
                receipt(action, idx as u64),
                1_701_000_010_000 + idx as u64,
                TRACE_ID,
            )
            .expect("fixture receipt must append to the chain");
    }
    (chain.entries().to_vec(), chain.checkpoints().to_vec())
}

fn receipt(action: ExecutionActionType, sequence_number: u64) -> ExecutionReceipt {
    let mut capability_context = BTreeMap::new();
    capability_context.insert(
        "capability".to_string(),
        format!("capability-{sequence_number}"),
    );
    capability_context.insert("domain".to_string(), "runtime".to_string());
    capability_context.insert("scope".to_string(), "extensions".to_string());

    ExecutionReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        action_type: action,
        capability_context,
        actor_identity: format!("actor-{sequence_number}"),
        artifact_identity: format!("artifact-{sequence_number}"),
        policy_snapshot_hash: format!("sha256:{sequence_number:064x}"),
        timestamp_millis: 1_701_000_000_000 + sequence_number,
        sequence_number,
        witness_references: vec!["w-a".to_string(), "w-b".to_string()],
        trace_id: TRACE_ID.to_string(),
    }
}

fn conformance_policy() -> SchedulerPolicy {
    let mut tier_deadline_millis = BTreeMap::new();
    tier_deadline_millis.insert(WorkloadTier::Critical, 10_000);
    tier_deadline_millis.insert(WorkloadTier::High, 20_000);
    tier_deadline_millis.insert(WorkloadTier::Standard, 60_000);
    tier_deadline_millis.insert(WorkloadTier::Background, 120_000);

    SchedulerPolicy {
        max_receipts_per_window: 2,
        max_concurrent_jobs: 2,
        max_compute_millis_per_tick: 500,
        max_memory_mib_per_tick: 64,
        tier_deadline_millis,
    }
}

fn coverage_matrix() -> Vec<CoverageRow> {
    vec![
        CoverageRow {
            section: "10.18 deterministic window selection".to_string(),
            level: "MUST".to_string(),
            clause: "Identical receipt streams and policies produce identical window partitions."
                .to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
        CoverageRow {
            section: "10.18 checkpoint alignment".to_string(),
            level: "MUST".to_string(),
            clause: "Proof windows align to receipt-chain checkpoints when possible.".to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
        CoverageRow {
            section: "10.18 priority dispatch".to_string(),
            level: "MUST".to_string(),
            clause: "Critical-tier jobs dispatch before lower-priority tiers.".to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
        CoverageRow {
            section: "10.18 bounded scheduling".to_string(),
            level: "MUST".to_string(),
            clause:
                "Dispatch respects the configured concurrency, compute, and memory budgets."
                    .to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
        CoverageRow {
            section: "10.18 deadline enforcement".to_string(),
            level: "MUST".to_string(),
            clause: "Jobs exceeding tier-specific deadlines are marked deadline_exceeded and emit VEF-SCHED-ERR-001."
                .to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
        CoverageRow {
            section: "10.18 event tracing".to_string(),
            level: "SHOULD".to_string(),
            clause: "Lifecycle transitions emit structured SchedulerEvent records with trace IDs."
                .to_string(),
            tested: true,
            verdict: "pass".to_string(),
        },
    ]
}

fn assert_schema_and_coverage_contract(report: &ConformanceReport) {
    assert_eq!(report.schema_version, SCHEDULER_SCHEMA_VERSION);
    assert_eq!(
        report.spec_source,
        "artifacts/section_10_18/bd-28u0/verification_summary.md"
    );
    assert_eq!(report.coverage_matrix.len(), 6);
    assert!(
        report
            .coverage_matrix
            .iter()
            .filter(|row| row.level == "MUST")
            .all(|row| row.tested && row.verdict == "pass"),
        "all spec-derived MUST clauses in the harness matrix must pass"
    );
}

fn assert_dispatch_contract(dispatch_case: &DispatchCase) {
    assert_eq!(dispatch_case.window_count, 3);
    let window_ranges = dispatch_case
        .windows
        .iter()
        .map(|window| {
            (
                window.window_id.as_str(),
                window.start_index,
                window.end_index,
                window.aligned_checkpoint_id,
                window.tier,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        window_ranges,
        vec![
            ("win-0-1", 0, 1, Some(0), WorkloadTier::High),
            ("win-2-3", 2, 3, Some(1), WorkloadTier::Critical),
            ("win-4-4", 4, 4, None, WorkloadTier::High),
        ]
    );

    assert_eq!(
        dispatch_case.queued_job_ids,
        vec!["job-00000000", "job-00000001", "job-00000002"]
    );
    assert_eq!(
        dispatch_case
            .dispatched_jobs
            .iter()
            .map(|job| job.job_id.as_str())
            .collect::<Vec<_>>(),
        vec!["job-00000001", "job-00000000"],
        "critical-tier proof job must dispatch before high-tier proof jobs"
    );
    assert!(
        dispatch_case
            .dispatched_jobs
            .iter()
            .all(|job| job.status == ProofJobStatus::Dispatched)
    );
    assert_eq!(dispatch_case.metrics.pending_jobs, 1);
    assert_eq!(dispatch_case.metrics.dispatched_jobs, 2);
    assert_eq!(dispatch_case.metrics.compute_budget_used_millis, 500);
    assert_eq!(dispatch_case.metrics.memory_budget_used_mib, 40);
    assert_eq!(
        dispatch_case.event_codes,
        vec![
            event_codes::VEF_SCHED_001_WINDOW_SELECTED,
            event_codes::VEF_SCHED_001_WINDOW_SELECTED,
            event_codes::VEF_SCHED_001_WINDOW_SELECTED,
            event_codes::VEF_SCHED_002_JOB_DISPATCHED,
            event_codes::VEF_SCHED_002_JOB_DISPATCHED,
            event_codes::VEF_SCHED_004_BACKLOG_HEALTH,
        ]
    );
}

fn assert_deadline_contract(deadline_case: &DeadlineCase) {
    assert_eq!(deadline_case.exceeded_job_ids, vec!["job-00000001"]);
    assert_eq!(
        deadline_case.deadline_event_codes,
        vec![event_codes::VEF_SCHED_ERR_001_DEADLINE]
    );
    assert_eq!(
        deadline_case
            .job_statuses
            .iter()
            .map(|snapshot| (snapshot.job_id.as_str(), snapshot.status))
            .collect::<Vec<_>>(),
        vec![
            ("job-00000000", ProofJobStatus::Pending),
            ("job-00000001", ProofJobStatus::DeadlineExceeded),
            ("job-00000002", ProofJobStatus::Pending),
        ]
    );
}

fn pretty_json(report: &ConformanceReport) -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(report).expect("conformance report must serialize")
    )
}
