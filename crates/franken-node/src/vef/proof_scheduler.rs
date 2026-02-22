//! bd-28u0: Deterministic VEF proof-window selection and job scheduling.
//!
//! This module schedules proof generation over bounded receipt windows while
//! enforcing latency and resource budgets.

use super::connector::vef_execution_receipt::ExecutionActionType;
use super::receipt_chain::{ReceiptChainEntry, ReceiptCheckpoint};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const SCHEDULER_SCHEMA_VERSION: &str = "vef-proof-scheduler-v1";

pub mod event_codes {
    pub const VEF_SCHED_001_WINDOW_SELECTED: &str = "VEF-SCHED-001";
    pub const VEF_SCHED_002_JOB_DISPATCHED: &str = "VEF-SCHED-002";
    pub const VEF_SCHED_003_JOB_COMPLETED: &str = "VEF-SCHED-003";
    pub const VEF_SCHED_004_BACKLOG_HEALTH: &str = "VEF-SCHED-004";
    pub const VEF_SCHED_ERR_001_DEADLINE: &str = "VEF-SCHED-ERR-001";
    pub const VEF_SCHED_ERR_002_BUDGET: &str = "VEF-SCHED-ERR-002";
    pub const VEF_SCHED_ERR_003_WINDOW: &str = "VEF-SCHED-ERR-003";
    pub const VEF_SCHED_ERR_004_INTERNAL: &str = "VEF-SCHED-ERR-004";
}

pub mod error_codes {
    #[allow(dead_code)]
    pub const ERR_VEF_SCHED_DEADLINE: &str = "ERR-VEF-SCHED-DEADLINE";
    pub const ERR_VEF_SCHED_BUDGET: &str = "ERR-VEF-SCHED-BUDGET";
    pub const ERR_VEF_SCHED_WINDOW: &str = "ERR-VEF-SCHED-WINDOW";
    pub const ERR_VEF_SCHED_INTERNAL: &str = "ERR-VEF-SCHED-INTERNAL";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadTier {
    Critical,
    High,
    Standard,
    Background,
}

impl WorkloadTier {
    pub fn default_deadline_millis(self) -> u64 {
        match self {
            WorkloadTier::Critical => 5_000,
            WorkloadTier::High => 30_000,
            WorkloadTier::Standard => 120_000,
            WorkloadTier::Background => 300_000,
        }
    }

    pub fn priority_score(self) -> u16 {
        match self {
            WorkloadTier::Critical => 400,
            WorkloadTier::High => 300,
            WorkloadTier::Standard => 200,
            WorkloadTier::Background => 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerPolicy {
    pub max_receipts_per_window: usize,
    pub max_concurrent_jobs: usize,
    pub max_compute_millis_per_tick: u64,
    pub max_memory_mib_per_tick: u64,
    pub tier_deadline_millis: BTreeMap<WorkloadTier, u64>,
}

impl Default for SchedulerPolicy {
    fn default() -> Self {
        let mut tier_deadline_millis = BTreeMap::new();
        for tier in [
            WorkloadTier::Critical,
            WorkloadTier::High,
            WorkloadTier::Standard,
            WorkloadTier::Background,
        ] {
            tier_deadline_millis.insert(tier, tier.default_deadline_millis());
        }
        Self {
            max_receipts_per_window: 64,
            max_concurrent_jobs: 8,
            max_compute_millis_per_tick: 20_000,
            max_memory_mib_per_tick: 4_096,
            tier_deadline_millis,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofWindow {
    pub window_id: String,
    pub start_index: u64,
    pub end_index: u64,
    pub entry_count: u64,
    pub aligned_checkpoint_id: Option<u64>,
    pub tier: WorkloadTier,
    pub created_at_millis: u64,
    pub trace_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobStatus {
    Pending,
    Dispatched,
    Completed,
    DeadlineExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJob {
    pub job_id: String,
    pub window_id: String,
    pub tier: WorkloadTier,
    pub priority_score: u16,
    pub deadline_millis: u64,
    pub estimated_compute_millis: u64,
    pub estimated_memory_mib: u64,
    pub status: ProofJobStatus,
    pub created_at_millis: u64,
    pub dispatched_at_millis: Option<u64>,
    pub completed_at_millis: Option<u64>,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerMetrics {
    pub pending_jobs: usize,
    pub dispatched_jobs: usize,
    pub completed_jobs: usize,
    pub deadline_exceeded_jobs: usize,
    pub oldest_pending_age_millis: u64,
    pub compute_budget_used_millis: u64,
    pub memory_budget_used_mib: u64,
    pub windows_observed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerEvent {
    pub event_code: String,
    pub trace_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerError {
    pub code: String,
    pub event_code: String,
    pub message: String,
}

impl SchedulerError {
    #[allow(dead_code)]
    fn deadline(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_SCHED_DEADLINE.to_string(),
            event_code: event_codes::VEF_SCHED_ERR_001_DEADLINE.to_string(),
            message: message.into(),
        }
    }

    fn budget(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_SCHED_BUDGET.to_string(),
            event_code: event_codes::VEF_SCHED_ERR_002_BUDGET.to_string(),
            message: message.into(),
        }
    }

    fn window(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_SCHED_WINDOW.to_string(),
            event_code: event_codes::VEF_SCHED_ERR_003_WINDOW.to_string(),
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_SCHED_INTERNAL.to_string(),
            event_code: event_codes::VEF_SCHED_ERR_004_INTERNAL.to_string(),
            message: message.into(),
        }
    }
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for SchedulerError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VefProofScheduler {
    pub schema_version: String,
    pub policy: SchedulerPolicy,
    windows_seen: BTreeSet<String>,
    jobs: BTreeMap<String, ProofJob>,
    next_job_seq: u64,
    events: Vec<SchedulerEvent>,
}

impl VefProofScheduler {
    pub fn new(policy: SchedulerPolicy) -> Self {
        Self {
            schema_version: SCHEDULER_SCHEMA_VERSION.to_string(),
            policy,
            windows_seen: BTreeSet::new(),
            jobs: BTreeMap::new(),
            next_job_seq: 0,
            events: Vec::new(),
        }
    }

    pub fn jobs(&self) -> &BTreeMap<String, ProofJob> {
        &self.jobs
    }

    #[allow(dead_code)]
    pub fn events(&self) -> &[SchedulerEvent] {
        &self.events
    }

    pub fn select_windows(
        &mut self,
        entries: &[ReceiptChainEntry],
        checkpoints: &[ReceiptCheckpoint],
        now_millis: u64,
        trace_id: &str,
    ) -> Result<Vec<ProofWindow>, SchedulerError> {
        if self.policy.max_receipts_per_window == 0 {
            return Err(SchedulerError::window(
                "max_receipts_per_window must be greater than zero",
            ));
        }
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let mut windows = Vec::new();
        let mut start = 0usize;
        while start < entries.len() {
            let max_end = (start + self.policy.max_receipts_per_window - 1).min(entries.len() - 1);
            let aligned = checkpoints
                .iter()
                .filter(|checkpoint| {
                    let end = checkpoint.end_index as usize;
                    end >= start && end <= max_end
                })
                .map(|checkpoint| {
                    (
                        checkpoint.end_index as usize,
                        Some(checkpoint.checkpoint_id),
                    )
                })
                .max_by_key(|(end, _)| *end);

            let (end, aligned_checkpoint_id) = aligned.unwrap_or((max_end, None));
            if end < start {
                return Err(SchedulerError::internal(format!(
                    "invalid window bounds start={start} end={end}"
                )));
            }

            let tier = infer_window_tier(&entries[start..=end]);
            let window = ProofWindow {
                window_id: format!("win-{}-{}", entries[start].index, entries[end].index),
                start_index: entries[start].index,
                end_index: entries[end].index,
                entry_count: (end - start + 1) as u64,
                aligned_checkpoint_id,
                tier,
                created_at_millis: now_millis,
                trace_id: trace_id.to_string(),
            };
            self.events.push(SchedulerEvent {
                event_code: event_codes::VEF_SCHED_001_WINDOW_SELECTED.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!(
                    "window={} range={}..{} tier={:?}",
                    window.window_id, window.start_index, window.end_index, window.tier
                ),
            });
            windows.push(window);
            start = end + 1;
        }

        Ok(windows)
    }

    pub fn enqueue_windows(
        &mut self,
        windows: &[ProofWindow],
        now_millis: u64,
    ) -> Result<Vec<String>, SchedulerError> {
        let mut queued = Vec::new();
        for window in windows {
            if self.windows_seen.contains(&window.window_id) {
                continue;
            }

            let deadline_span = self
                .policy
                .tier_deadline_millis
                .get(&window.tier)
                .copied()
                .unwrap_or_else(|| window.tier.default_deadline_millis());

            let estimated_compute_millis = 100 * window.entry_count;
            let estimated_memory_mib = 8 * window.entry_count;
            if estimated_compute_millis > self.policy.max_compute_millis_per_tick * 8 {
                return Err(SchedulerError::budget(format!(
                    "window {} estimated compute {}ms exceeds configured envelope",
                    window.window_id, estimated_compute_millis
                )));
            }

            let job_id = format!("job-{:08}", self.next_job_seq);
            self.next_job_seq = self
                .next_job_seq
                .checked_add(1)
                .ok_or_else(|| SchedulerError::internal("job sequence overflow"))?;

            let job = ProofJob {
                job_id: job_id.clone(),
                window_id: window.window_id.clone(),
                tier: window.tier,
                priority_score: window.tier.priority_score(),
                deadline_millis: now_millis + deadline_span,
                estimated_compute_millis,
                estimated_memory_mib,
                status: ProofJobStatus::Pending,
                created_at_millis: now_millis,
                dispatched_at_millis: None,
                completed_at_millis: None,
                trace_id: window.trace_id.clone(),
            };
            self.jobs.insert(job_id.clone(), job);
            self.windows_seen.insert(window.window_id.clone());
            queued.push(job_id);
        }
        Ok(queued)
    }

    pub fn dispatch_jobs(&mut self, now_millis: u64) -> Result<Vec<ProofJob>, SchedulerError> {
        let active_dispatched = self
            .jobs
            .values()
            .filter(|job| job.status == ProofJobStatus::Dispatched)
            .count();
        if active_dispatched >= self.policy.max_concurrent_jobs {
            return Err(SchedulerError::budget("concurrency budget exhausted"));
        }
        let available_slots = self.policy.max_concurrent_jobs - active_dispatched;

        let mut pending = self
            .jobs
            .values()
            .filter(|job| job.status == ProofJobStatus::Pending)
            .cloned()
            .collect::<Vec<_>>();
        pending.sort_by_key(|job| (std::cmp::Reverse(job.priority_score), job.created_at_millis));

        let mut dispatched = Vec::new();
        let mut compute_used = 0_u64;
        let mut memory_used = 0_u64;
        for job in pending.into_iter().take(available_slots) {
            if compute_used + job.estimated_compute_millis > self.policy.max_compute_millis_per_tick
                || memory_used + job.estimated_memory_mib > self.policy.max_memory_mib_per_tick
            {
                break;
            }

            let entry = self
                .jobs
                .get_mut(&job.job_id)
                .ok_or_else(|| SchedulerError::internal(format!("missing job {}", job.job_id)))?;
            entry.status = ProofJobStatus::Dispatched;
            entry.dispatched_at_millis = Some(now_millis);
            compute_used += entry.estimated_compute_millis;
            memory_used += entry.estimated_memory_mib;
            self.events.push(SchedulerEvent {
                event_code: event_codes::VEF_SCHED_002_JOB_DISPATCHED.to_string(),
                trace_id: entry.trace_id.clone(),
                detail: format!("job={} window={}", entry.job_id, entry.window_id),
            });
            dispatched.push(entry.clone());
        }

        Ok(dispatched)
    }

    pub fn mark_completed(&mut self, job_id: &str, now_millis: u64) -> Result<(), SchedulerError> {
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| SchedulerError::window(format!("unknown job_id {job_id}")))?;
        job.status = ProofJobStatus::Completed;
        job.completed_at_millis = Some(now_millis);
        self.events.push(SchedulerEvent {
            event_code: event_codes::VEF_SCHED_003_JOB_COMPLETED.to_string(),
            trace_id: job.trace_id.clone(),
            detail: format!("job={job_id} completed"),
        });
        Ok(())
    }

    pub fn enforce_deadlines(&mut self, now_millis: u64) -> Vec<String> {
        let mut exceeded = Vec::new();
        for job in self.jobs.values_mut() {
            if matches!(
                job.status,
                ProofJobStatus::Completed | ProofJobStatus::DeadlineExceeded
            ) {
                continue;
            }
            if now_millis > job.deadline_millis {
                job.status = ProofJobStatus::DeadlineExceeded;
                exceeded.push(job.job_id.clone());
                self.events.push(SchedulerEvent {
                    event_code: event_codes::VEF_SCHED_ERR_001_DEADLINE.to_string(),
                    trace_id: job.trace_id.clone(),
                    detail: format!("job={} exceeded deadline", job.job_id),
                });
            }
        }
        exceeded
    }

    pub fn backlog_metrics(&mut self, now_millis: u64, trace_id: &str) -> SchedulerMetrics {
        let mut pending_jobs = 0usize;
        let mut dispatched_jobs = 0usize;
        let mut completed_jobs = 0usize;
        let mut deadline_exceeded_jobs = 0usize;
        let mut oldest_pending_created = None::<u64>;
        let mut compute_budget_used_millis = 0_u64;
        let mut memory_budget_used_mib = 0_u64;

        for job in self.jobs.values() {
            match job.status {
                ProofJobStatus::Pending => {
                    pending_jobs += 1;
                    oldest_pending_created = Some(
                        oldest_pending_created
                            .map(|current| current.min(job.created_at_millis))
                            .unwrap_or(job.created_at_millis),
                    );
                    compute_budget_used_millis += job.estimated_compute_millis;
                    memory_budget_used_mib += job.estimated_memory_mib;
                }
                ProofJobStatus::Dispatched => {
                    dispatched_jobs += 1;
                    compute_budget_used_millis += job.estimated_compute_millis;
                    memory_budget_used_mib += job.estimated_memory_mib;
                }
                ProofJobStatus::Completed => completed_jobs += 1,
                ProofJobStatus::DeadlineExceeded => deadline_exceeded_jobs += 1,
            }
        }

        let oldest_pending_age_millis = oldest_pending_created
            .map(|created| now_millis.saturating_sub(created))
            .unwrap_or(0);
        let metrics = SchedulerMetrics {
            pending_jobs,
            dispatched_jobs,
            completed_jobs,
            deadline_exceeded_jobs,
            oldest_pending_age_millis,
            compute_budget_used_millis,
            memory_budget_used_mib,
            windows_observed: self.windows_seen.len(),
        };
        self.events.push(SchedulerEvent {
            event_code: event_codes::VEF_SCHED_004_BACKLOG_HEALTH.to_string(),
            trace_id: trace_id.to_string(),
            detail: format!(
                "pending={} dispatched={} completed={} deadline_exceeded={}",
                metrics.pending_jobs,
                metrics.dispatched_jobs,
                metrics.completed_jobs,
                metrics.deadline_exceeded_jobs
            ),
        });
        metrics
    }
}

fn infer_window_tier(entries: &[ReceiptChainEntry]) -> WorkloadTier {
    let mut tier = WorkloadTier::Background;
    for entry in entries {
        let entry_tier = match entry.receipt.action_type {
            ExecutionActionType::SecretAccess | ExecutionActionType::PolicyTransition => {
                WorkloadTier::Critical
            }
            ExecutionActionType::NetworkAccess | ExecutionActionType::ProcessSpawn => {
                WorkloadTier::High
            }
            ExecutionActionType::FilesystemOperation => WorkloadTier::Standard,
            ExecutionActionType::ArtifactPromotion => WorkloadTier::Background,
        };
        if entry_tier.priority_score() > tier.priority_score() {
            tier = entry_tier;
        }
    }
    tier
}

#[cfg(test)]
mod tests {
    use super::super::connector::vef_execution_receipt::{
        ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
    };
    use super::super::receipt_chain::{ReceiptChain, ReceiptChainConfig};
    use super::*;
    use std::collections::BTreeMap;

    fn receipt(action: ExecutionActionType, n: u64) -> ExecutionReceipt {
        let mut capability_context = BTreeMap::new();
        capability_context.insert("domain".to_string(), "runtime".to_string());
        capability_context.insert("scope".to_string(), "extensions".to_string());
        capability_context.insert("capability".to_string(), format!("capability-{n}"));
        ExecutionReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            action_type: action,
            capability_context,
            actor_identity: format!("actor-{n}"),
            artifact_identity: format!("artifact-{n}"),
            policy_snapshot_hash: format!("sha256:{n:064x}"),
            timestamp_millis: 1_701_000_000_000 + n,
            sequence_number: n,
            witness_references: vec!["w-a".to_string(), "w-b".to_string()],
            trace_id: format!("trace-{n}"),
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
                    "trace-stream",
                )
                .unwrap();
        }
        (chain.entries().to_vec(), chain.checkpoints().to_vec())
    }

    #[test]
    fn deterministic_window_partition_for_same_inputs() {
        let (entries, checkpoints) = sample_stream();
        let policy = SchedulerPolicy {
            max_receipts_per_window: 2,
            ..SchedulerPolicy::default()
        };
        let mut a = VefProofScheduler::new(policy.clone());
        let mut b = VefProofScheduler::new(policy);

        let w1 = a
            .select_windows(&entries, &checkpoints, 1_701_100_000_000, "trace-a")
            .unwrap();
        let w2 = b
            .select_windows(&entries, &checkpoints, 1_701_100_000_000, "trace-b")
            .unwrap();

        assert_eq!(w1.len(), w2.len());
        let bounds_1 = w1
            .iter()
            .map(|w| (w.start_index, w.end_index))
            .collect::<Vec<_>>();
        let bounds_2 = w2
            .iter()
            .map(|w| (w.start_index, w.end_index))
            .collect::<Vec<_>>();
        assert_eq!(bounds_1, bounds_2);
    }

    #[test]
    fn empty_stream_produces_no_windows() {
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());
        let windows = scheduler
            .select_windows(&[], &[], 1_701_100_001_000, "trace-empty")
            .unwrap();
        assert!(windows.is_empty());
    }

    #[test]
    fn enqueue_and_dispatch_respects_concurrency_budget() {
        let (entries, checkpoints) = sample_stream();
        let policy = SchedulerPolicy {
            max_receipts_per_window: 1,
            max_concurrent_jobs: 2,
            ..SchedulerPolicy::default()
        };
        let mut scheduler = VefProofScheduler::new(policy);
        let windows = scheduler
            .select_windows(&entries, &checkpoints, 1_701_100_002_000, "trace-dispatch")
            .unwrap();
        scheduler
            .enqueue_windows(&windows, 1_701_100_002_010)
            .unwrap();
        let dispatched = scheduler.dispatch_jobs(1_701_100_002_020).unwrap();
        assert_eq!(dispatched.len(), 2);
        assert!(
            dispatched
                .iter()
                .all(|job| job.status == ProofJobStatus::Dispatched)
        );
    }

    #[test]
    fn priority_prefers_critical_windows() {
        let (entries, checkpoints) = sample_stream();
        let policy = SchedulerPolicy {
            max_receipts_per_window: 1,
            max_concurrent_jobs: 1,
            ..SchedulerPolicy::default()
        };
        let mut scheduler = VefProofScheduler::new(policy);
        let windows = scheduler
            .select_windows(&entries, &checkpoints, 1_701_100_003_000, "trace-priority")
            .unwrap();
        scheduler
            .enqueue_windows(&windows, 1_701_100_003_010)
            .unwrap();
        let dispatched = scheduler.dispatch_jobs(1_701_100_003_020).unwrap();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].tier, WorkloadTier::Critical);
    }

    #[test]
    fn deadline_enforcement_marks_jobs_as_exceeded() {
        let (entries, checkpoints) = sample_stream();
        let mut policy = SchedulerPolicy {
            max_receipts_per_window: 2,
            max_concurrent_jobs: 2,
            ..SchedulerPolicy::default()
        };
        policy
            .tier_deadline_millis
            .insert(WorkloadTier::Critical, 1);
        let mut scheduler = VefProofScheduler::new(policy);
        let windows = scheduler
            .select_windows(&entries, &checkpoints, 1_701_100_004_000, "trace-deadline")
            .unwrap();
        scheduler
            .enqueue_windows(&windows, 1_701_100_004_000)
            .unwrap();
        scheduler.dispatch_jobs(1_701_100_004_000).unwrap();
        let exceeded = scheduler.enforce_deadlines(1_701_100_005_000);
        assert!(!exceeded.is_empty());
        assert!(
            scheduler
                .jobs()
                .values()
                .any(|job| job.status == ProofJobStatus::DeadlineExceeded)
        );
    }

    #[test]
    fn backlog_metrics_report_pending_age() {
        let (entries, checkpoints) = sample_stream();
        let policy = SchedulerPolicy {
            max_receipts_per_window: 2,
            max_concurrent_jobs: 0,
            ..SchedulerPolicy::default()
        };
        let mut scheduler = VefProofScheduler::new(policy);
        let windows = scheduler
            .select_windows(&entries, &checkpoints, 1_701_100_006_000, "trace-metrics")
            .unwrap();
        scheduler
            .enqueue_windows(&windows, 1_701_100_006_000)
            .unwrap();
        let metrics = scheduler.backlog_metrics(1_701_100_007_000, "trace-metrics");
        assert!(metrics.pending_jobs >= 1);
        assert!(metrics.oldest_pending_age_millis >= 1_000);
    }

    #[test]
    fn mark_completed_transitions_job() {
        let (entries, checkpoints) = sample_stream();
        let policy = SchedulerPolicy {
            max_receipts_per_window: 1,
            max_concurrent_jobs: 1,
            ..SchedulerPolicy::default()
        };
        let mut scheduler = VefProofScheduler::new(policy);
        let windows = scheduler
            .select_windows(&entries, &checkpoints, 1_701_100_008_000, "trace-complete")
            .unwrap();
        let queued = scheduler
            .enqueue_windows(&windows, 1_701_100_008_010)
            .unwrap();
        let job_id = queued[0].clone();
        scheduler.dispatch_jobs(1_701_100_008_020).unwrap();
        scheduler
            .mark_completed(&job_id, 1_701_100_008_030)
            .unwrap();
        assert_eq!(
            scheduler.jobs().get(&job_id).unwrap().status,
            ProofJobStatus::Completed
        );
    }
}
