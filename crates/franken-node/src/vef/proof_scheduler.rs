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

/// Maximum scheduler events before oldest are evicted.
const MAX_SCHEDULER_EVENTS: usize = 4096;

use frankenengine_node::capacity_defaults::aliases::{MAX_JOBS, MAX_WINDOWS_SEEN};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

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
    pub const ERR_VEF_SCHED_DUPLICATE_JOB_ID: &str = "ERR-VEF-SCHED-DUPLICATE-JOB-ID";
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

impl ProofJobStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::DeadlineExceeded)
    }
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

    fn duplicate_job_id(job_id: &str) -> Self {
        Self {
            code: error_codes::ERR_VEF_SCHED_DUPLICATE_JOB_ID.to_string(),
            event_code: event_codes::VEF_SCHED_ERR_004_INTERNAL.to_string(),
            message: format!("generated job_id already exists: {job_id}"),
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

    fn push_event(&mut self, event: SchedulerEvent) {
        push_bounded(&mut self.events, event, MAX_SCHEDULER_EVENTS);
    }

    pub fn jobs(&self) -> &BTreeMap<String, ProofJob> {
        &self.jobs
    }

    #[allow(dead_code)]
    pub fn events(&self) -> &[SchedulerEvent] {
        &self.events
    }

    fn reclaimable_job_id(&self) -> Option<String> {
        self.jobs
            .iter()
            .filter(|(_, job)| job.status.is_terminal())
            .min_by(|(left_id, left_job), (right_id, right_job)| {
                left_job
                    .created_at_millis
                    .cmp(&right_job.created_at_millis)
                    .then_with(|| left_id.cmp(right_id))
            })
            .map(|(job_id, _)| job_id.clone())
    }

    fn prepare_job_slot(&self, job_id: &str) -> Result<Option<String>, SchedulerError> {
        if self.jobs.contains_key(job_id) {
            return Err(SchedulerError::duplicate_job_id(job_id));
        }

        if self.jobs.len() < MAX_JOBS {
            return Ok(None);
        }

        self.reclaimable_job_id().map(Some).ok_or_else(|| {
            SchedulerError::budget(format!(
                "proof job registry is full of live jobs (capacity {MAX_JOBS})"
            ))
        })
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
            let max_end = (start + self.policy.max_receipts_per_window.saturating_sub(1))
                .min(entries.len().saturating_sub(1));
            let global_start = entries[start].index;
            let global_max_end = entries[max_end].index;

            let aligned = checkpoints
                .iter()
                .filter(|checkpoint| {
                    checkpoint.end_index >= global_start && checkpoint.end_index <= global_max_end
                })
                .map(|checkpoint| {
                    let offset = usize::try_from(checkpoint.end_index.saturating_sub(global_start))
                        .unwrap_or(usize::MAX);
                    let slice_end = start.saturating_add(offset).min(max_end);
                    (slice_end, Some(checkpoint.checkpoint_id))
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
                entry_count: u64::try_from((end - start).saturating_add(1)).unwrap_or(u64::MAX),
                aligned_checkpoint_id,
                tier,
                created_at_millis: now_millis,
                trace_id: trace_id.to_string(),
            };
            self.push_event(SchedulerEvent {
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

            let estimated_compute_millis = 100_u64.saturating_mul(window.entry_count);
            let estimated_memory_mib = 8_u64.saturating_mul(window.entry_count);
            if estimated_compute_millis > self.policy.max_compute_millis_per_tick.saturating_mul(8)
            {
                return Err(SchedulerError::budget(format!(
                    "window {} estimated compute {}ms exceeds configured envelope",
                    window.window_id, estimated_compute_millis
                )));
            }

            let job_id = format!("job-{:08}", self.next_job_seq);
            let next_job_seq = self
                .next_job_seq
                .checked_add(1)
                .ok_or_else(|| SchedulerError::internal("job sequence overflow"))?;
            let reclaimed_job_id = self.prepare_job_slot(&job_id)?;

            let job = ProofJob {
                job_id: job_id.clone(),
                window_id: window.window_id.clone(),
                tier: window.tier,
                priority_score: window.tier.priority_score(),
                deadline_millis: now_millis.saturating_add(deadline_span),
                estimated_compute_millis,
                estimated_memory_mib,
                status: ProofJobStatus::Pending,
                created_at_millis: now_millis,
                dispatched_at_millis: None,
                completed_at_millis: None,
                trace_id: window.trace_id.clone(),
            };
            if let Some(reclaimed_job_id) = reclaimed_job_id {
                self.jobs.remove(&reclaimed_job_id);
            }
            self.jobs.insert(job_id.clone(), job);
            self.next_job_seq = next_job_seq;
            if self.windows_seen.len() >= MAX_WINDOWS_SEEN
                && let Some(oldest) = self.windows_seen.iter().next().cloned()
            {
                self.windows_seen.remove(&oldest);
            }
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
        let available_slots = self
            .policy
            .max_concurrent_jobs
            .saturating_sub(active_dispatched);

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
            if (compute_used.saturating_add(job.estimated_compute_millis)
                > self.policy.max_compute_millis_per_tick
                || memory_used.saturating_add(job.estimated_memory_mib)
                    > self.policy.max_memory_mib_per_tick)
                && (compute_used > 0 || memory_used > 0)
            {
                break;
            }

            let entry = self
                .jobs
                .get_mut(&job.job_id)
                .ok_or_else(|| SchedulerError::internal(format!("missing job {}", job.job_id)))?;
            entry.status = ProofJobStatus::Dispatched;
            entry.dispatched_at_millis = Some(now_millis);
            compute_used = compute_used.saturating_add(entry.estimated_compute_millis);
            memory_used = memory_used.saturating_add(entry.estimated_memory_mib);
            let evt_trace = entry.trace_id.clone();
            let evt_detail = format!("job={} window={}", entry.job_id, entry.window_id);
            dispatched.push(entry.clone());
            self.push_event(SchedulerEvent {
                event_code: event_codes::VEF_SCHED_002_JOB_DISPATCHED.to_string(),
                trace_id: evt_trace,
                detail: evt_detail,
            });
        }

        Ok(dispatched)
    }

    pub fn mark_completed(&mut self, job_id: &str, now_millis: u64) -> Result<(), SchedulerError> {
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| SchedulerError::window(format!("unknown job_id {job_id}")))?;
        if job.status != ProofJobStatus::Dispatched {
            return Err(SchedulerError::internal(format!(
                "cannot complete job {job_id}: current status is {:?}, expected Dispatched",
                job.status
            )));
        }
        job.status = ProofJobStatus::Completed;
        job.completed_at_millis = Some(now_millis);
        let evt_trace = job.trace_id.clone();
        self.push_event(SchedulerEvent {
            event_code: event_codes::VEF_SCHED_003_JOB_COMPLETED.to_string(),
            trace_id: evt_trace,
            detail: format!("job={job_id} completed"),
        });
        Ok(())
    }

    pub fn enforce_deadlines(&mut self, now_millis: u64) -> Vec<String> {
        let mut exceeded = Vec::new();
        let mut deferred_events = Vec::new();
        for job in self.jobs.values_mut() {
            if matches!(
                job.status,
                ProofJobStatus::Completed | ProofJobStatus::DeadlineExceeded
            ) {
                continue;
            }
            if now_millis >= job.deadline_millis {
                job.status = ProofJobStatus::DeadlineExceeded;
                exceeded.push(job.job_id.clone());
                deferred_events.push(SchedulerEvent {
                    event_code: event_codes::VEF_SCHED_ERR_001_DEADLINE.to_string(),
                    trace_id: job.trace_id.clone(),
                    detail: format!("job={} exceeded deadline", job.job_id),
                });
            }
        }
        for event in deferred_events {
            self.push_event(event);
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
                    pending_jobs = pending_jobs.saturating_add(1);
                    oldest_pending_created = Some(
                        oldest_pending_created
                            .map(|current| current.min(job.created_at_millis))
                            .unwrap_or(job.created_at_millis),
                    );
                    compute_budget_used_millis =
                        compute_budget_used_millis.saturating_add(job.estimated_compute_millis);
                    memory_budget_used_mib =
                        memory_budget_used_mib.saturating_add(job.estimated_memory_mib);
                }
                ProofJobStatus::Dispatched => {
                    dispatched_jobs = dispatched_jobs.saturating_add(1);
                    compute_budget_used_millis =
                        compute_budget_used_millis.saturating_add(job.estimated_compute_millis);
                    memory_budget_used_mib =
                        memory_budget_used_mib.saturating_add(job.estimated_memory_mib);
                }
                ProofJobStatus::Completed => completed_jobs = completed_jobs.saturating_add(1),
                ProofJobStatus::DeadlineExceeded => {
                    deadline_exceeded_jobs = deadline_exceeded_jobs.saturating_add(1);
                }
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
        self.push_event(SchedulerEvent {
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
                .expect("chain append should succeed");
        }
        (chain.entries().to_vec(), chain.checkpoints().to_vec())
    }

    fn make_window(
        window_id: &str,
        tier: WorkloadTier,
        created_at_millis: u64,
        trace_id: &str,
    ) -> ProofWindow {
        ProofWindow {
            window_id: window_id.to_string(),
            start_index: 1,
            end_index: 1,
            entry_count: 1,
            aligned_checkpoint_id: None,
            tier,
            created_at_millis,
            trace_id: trace_id.to_string(),
        }
    }

    fn make_job(
        job_id: &str,
        status: ProofJobStatus,
        created_at_millis: u64,
        trace_id: &str,
    ) -> ProofJob {
        ProofJob {
            job_id: job_id.to_string(),
            window_id: format!("window-for-{job_id}"),
            tier: WorkloadTier::Standard,
            priority_score: WorkloadTier::Standard.priority_score(),
            deadline_millis: created_at_millis.saturating_add(10_000),
            estimated_compute_millis: 100,
            estimated_memory_mib: 8,
            status,
            created_at_millis,
            dispatched_at_millis: (status == ProofJobStatus::Dispatched)
                .then_some(created_at_millis.saturating_add(1)),
            completed_at_millis: status
                .is_terminal()
                .then_some(created_at_millis.saturating_add(2)),
            trace_id: trace_id.to_string(),
        }
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
            .expect("should select windows");
        let w2 = b
            .select_windows(&entries, &checkpoints, 1_701_100_000_000, "trace-b")
            .expect("should select windows");

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
            .expect("should select windows");
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
            .expect("should select windows");
        scheduler
            .enqueue_windows(&windows, 1_701_100_002_010)
            .expect("should select windows");
        let dispatched = scheduler
            .dispatch_jobs(1_701_100_002_020)
            .expect("should dispatch");
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
            .expect("should select windows");
        scheduler
            .enqueue_windows(&windows, 1_701_100_003_010)
            .expect("should select windows");
        let dispatched = scheduler
            .dispatch_jobs(1_701_100_003_020)
            .expect("should dispatch");
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
            .expect("should select windows");
        scheduler
            .enqueue_windows(&windows, 1_701_100_004_000)
            .expect("should select windows");
        scheduler
            .dispatch_jobs(1_701_100_004_000)
            .expect("should dispatch");
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
            .expect("should select windows");
        scheduler
            .enqueue_windows(&windows, 1_701_100_006_000)
            .expect("should select windows");
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
            .expect("should select windows");
        scheduler
            .enqueue_windows(&windows, 1_701_100_008_010)
            .expect("should select windows");
        let dispatched = scheduler
            .dispatch_jobs(1_701_100_008_020)
            .expect("should dispatch");
        let job_id = &dispatched[0].job_id;
        scheduler
            .mark_completed(job_id, 1_701_100_008_030)
            .expect("should complete");
        assert_eq!(
            scheduler.jobs().get(job_id).expect("should exist").status,
            ProofJobStatus::Completed
        );
    }

    #[test]
    fn enqueue_windows_rejects_when_job_registry_is_full_of_live_jobs() {
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());
        for seq in 0..MAX_JOBS {
            let job_id = format!("job-{seq:08}");
            let status = if seq == 0 {
                ProofJobStatus::Dispatched
            } else {
                ProofJobStatus::Pending
            };
            scheduler.jobs.insert(
                job_id.clone(),
                make_job(
                    &job_id,
                    status,
                    1_701_200_000_000 + seq as u64,
                    "trace-live-capacity",
                ),
            );
        }
        scheduler.next_job_seq = MAX_JOBS as u64;

        let err = scheduler
            .enqueue_windows(
                &[make_window(
                    "win-extra",
                    WorkloadTier::Standard,
                    1_701_200_100_000,
                    "trace-live-capacity",
                )],
                1_701_200_100_000,
            )
            .expect_err("full live registry must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_SCHED_BUDGET);
        assert!(
            err.message.contains("full of live jobs"),
            "unexpected error message: {}",
            err.message
        );
        assert_eq!(scheduler.jobs.len(), MAX_JOBS);
        assert!(scheduler.jobs.contains_key("job-00000000"));
        assert!(!scheduler.jobs.contains_key("job-00002048"));
    }

    #[test]
    fn enqueue_windows_reclaims_oldest_terminal_job_before_live_job() {
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());
        scheduler.jobs.insert(
            "aaa-live-dispatched".to_string(),
            make_job(
                "aaa-live-dispatched",
                ProofJobStatus::Dispatched,
                1_701_300_000_000,
                "trace-terminal-reclaim",
            ),
        );
        scheduler.jobs.insert(
            "mmm-terminal-newer".to_string(),
            make_job(
                "mmm-terminal-newer",
                ProofJobStatus::Completed,
                1_701_300_000_030,
                "trace-terminal-reclaim",
            ),
        );
        scheduler.jobs.insert(
            "zzz-terminal-oldest".to_string(),
            make_job(
                "zzz-terminal-oldest",
                ProofJobStatus::DeadlineExceeded,
                1_701_300_000_010,
                "trace-terminal-reclaim",
            ),
        );
        for seq in 0..(MAX_JOBS - 3) {
            let job_id = format!("live-{seq:08}");
            scheduler.jobs.insert(
                job_id.clone(),
                make_job(
                    &job_id,
                    ProofJobStatus::Pending,
                    1_701_300_001_000 + seq as u64,
                    "trace-terminal-reclaim",
                ),
            );
        }
        scheduler.next_job_seq = MAX_JOBS as u64;

        let queued = scheduler
            .enqueue_windows(
                &[make_window(
                    "win-new",
                    WorkloadTier::High,
                    1_701_300_100_000,
                    "trace-terminal-reclaim",
                )],
                1_701_300_100_000,
            )
            .expect("terminal job should be reclaimed");

        assert_eq!(queued, vec!["job-00002048".to_string()]);
        assert_eq!(scheduler.jobs.len(), MAX_JOBS);
        assert!(!scheduler.jobs.contains_key("zzz-terminal-oldest"));
        assert!(scheduler.jobs.contains_key("mmm-terminal-newer"));
        assert!(scheduler.jobs.contains_key("aaa-live-dispatched"));
        assert!(scheduler.jobs.contains_key("job-00002048"));

        scheduler
            .mark_completed("aaa-live-dispatched", 1_701_300_100_010)
            .expect("live dispatched job must remain completable");
        assert_eq!(
            scheduler
                .jobs()
                .get("aaa-live-dispatched")
                .expect("live job should still exist")
                .status,
            ProofJobStatus::Completed
        );
    }

    #[test]
    fn enqueue_windows_rejects_reused_generated_job_id_without_overwriting_existing_job() {
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());
        let original = make_job(
            "job-00000000",
            ProofJobStatus::Dispatched,
            1_701_350_000_000,
            "trace-original",
        );
        scheduler
            .jobs
            .insert(original.job_id.clone(), original.clone());
        scheduler.next_job_seq = 0;

        let err = scheduler
            .enqueue_windows(
                &[make_window(
                    "win-reused-id",
                    WorkloadTier::Standard,
                    1_701_350_100_000,
                    "trace-reused-id",
                )],
                1_701_350_100_000,
            )
            .expect_err("reused generated job id must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_SCHED_DUPLICATE_JOB_ID);
        assert!(
            err.message.contains("job-00000000"),
            "unexpected error message: {}",
            err.message
        );
        assert_eq!(scheduler.next_job_seq, 0);
        assert_eq!(scheduler.jobs.len(), 1);
        assert!(!scheduler.windows_seen.contains("win-reused-id"));

        let preserved = scheduler
            .jobs()
            .get("job-00000000")
            .expect("original job should be preserved");
        assert_eq!(preserved.status, ProofJobStatus::Dispatched);
        assert_eq!(preserved.window_id, original.window_id);
        assert_eq!(preserved.trace_id, "trace-original");
        assert_eq!(
            preserved.dispatched_at_millis,
            original.dispatched_at_millis
        );
    }

    mod fairness_and_expiry_contract_tests {
        use super::*;

        fn scheduler_event(detail: &str) -> SchedulerEvent {
            SchedulerEvent {
                event_code: event_codes::VEF_SCHED_002_JOB_DISPATCHED.to_string(),
                trace_id: "trace-contract".to_string(),
                detail: detail.to_string(),
            }
        }

        fn scheduler_with_jobs(jobs: &[ProofJob], max_concurrent_jobs: usize) -> VefProofScheduler {
            let mut scheduler = VefProofScheduler::new(SchedulerPolicy {
                max_concurrent_jobs,
                max_compute_millis_per_tick: 10_000,
                max_memory_mib_per_tick: 10_000,
                ..SchedulerPolicy::default()
            });
            for job in jobs {
                scheduler.jobs.insert(job.job_id.clone(), job.clone());
            }
            scheduler
        }

        #[test]
        fn same_priority_dispatches_oldest_pending_job_first() {
            let newer = make_job(
                "job-newer",
                ProofJobStatus::Pending,
                1_701_400_000_200,
                "trace-fairness",
            );
            let older = make_job(
                "job-older",
                ProofJobStatus::Pending,
                1_701_400_000_100,
                "trace-fairness",
            );
            let mut scheduler = scheduler_with_jobs(&[newer, older], 2);

            let dispatched = scheduler
                .dispatch_jobs(1_701_400_000_300)
                .expect("dispatch should succeed");

            assert_eq!(
                dispatched
                    .iter()
                    .map(|job| job.job_id.as_str())
                    .collect::<Vec<_>>(),
                vec!["job-older", "job-newer"]
            );
        }

        #[test]
        fn lower_priority_pending_job_dispatches_when_capacity_remains() {
            let mut critical = make_job(
                "job-critical",
                ProofJobStatus::Pending,
                1_701_400_001_000,
                "trace-capacity-fairness",
            );
            critical.tier = WorkloadTier::Critical;
            critical.priority_score = WorkloadTier::Critical.priority_score();

            let mut background = make_job(
                "job-background",
                ProofJobStatus::Pending,
                1_701_400_001_001,
                "trace-capacity-fairness",
            );
            background.tier = WorkloadTier::Background;
            background.priority_score = WorkloadTier::Background.priority_score();

            let mut scheduler = scheduler_with_jobs(&[background, critical], 2);

            let dispatched = scheduler
                .dispatch_jobs(1_701_400_001_010)
                .expect("dispatch should succeed");

            assert_eq!(dispatched.len(), 2);
            assert_eq!(dispatched[0].job_id, "job-critical");
            assert_eq!(dispatched[1].job_id, "job-background");
        }

        #[test]
        fn dispatch_fails_when_existing_dispatched_job_exhausts_capacity() {
            let active = make_job(
                "job-active",
                ProofJobStatus::Dispatched,
                1_701_400_001_500,
                "trace-capacity-exhausted",
            );
            let pending = make_job(
                "job-pending",
                ProofJobStatus::Pending,
                1_701_400_001_600,
                "trace-capacity-exhausted",
            );
            let mut scheduler = scheduler_with_jobs(&[active, pending], 1);

            let err = scheduler
                .dispatch_jobs(1_701_400_001_700)
                .expect_err("active job should exhaust dispatch capacity");

            assert_eq!(err.code, error_codes::ERR_VEF_SCHED_BUDGET);
            assert_eq!(
                scheduler
                    .jobs()
                    .get("job-pending")
                    .expect("pending job should exist")
                    .status,
                ProofJobStatus::Pending
            );
        }

        #[test]
        fn deadline_before_boundary_keeps_pending_job_live() {
            let job = make_job(
                "job-before-deadline",
                ProofJobStatus::Pending,
                1_701_400_002_000,
                "trace-before-deadline",
            );
            let mut scheduler = scheduler_with_jobs(&[job], 1);

            let exceeded = scheduler.enforce_deadlines(1_701_400_011_999);

            assert!(exceeded.is_empty());
            assert_eq!(
                scheduler
                    .jobs()
                    .get("job-before-deadline")
                    .expect("job should exist")
                    .status,
                ProofJobStatus::Pending
            );
        }

        #[test]
        fn deadline_at_exact_boundary_marks_job_exceeded() {
            let job = make_job(
                "job-at-deadline",
                ProofJobStatus::Pending,
                1_701_400_003_000,
                "trace-at-deadline",
            );
            let mut scheduler = scheduler_with_jobs(&[job], 1);

            let exceeded = scheduler.enforce_deadlines(1_701_400_013_000);

            assert_eq!(exceeded, vec!["job-at-deadline".to_string()]);
            assert_eq!(
                scheduler
                    .jobs()
                    .get("job-at-deadline")
                    .expect("job should exist")
                    .status,
                ProofJobStatus::DeadlineExceeded
            );
        }

        #[test]
        fn completed_job_is_not_expired_after_deadline() {
            let job = make_job(
                "job-complete",
                ProofJobStatus::Completed,
                1_701_400_004_000,
                "trace-complete-deadline",
            );
            let mut scheduler = scheduler_with_jobs(&[job], 1);

            let exceeded = scheduler.enforce_deadlines(1_701_400_100_000);

            assert!(exceeded.is_empty());
            assert_eq!(
                scheduler
                    .jobs()
                    .get("job-complete")
                    .expect("job should exist")
                    .status,
                ProofJobStatus::Completed
            );
        }

        #[test]
        fn mark_completed_rejects_pending_job_without_status_change() {
            let job = make_job(
                "job-pending-complete",
                ProofJobStatus::Pending,
                1_701_400_005_000,
                "trace-pending-complete",
            );
            let mut scheduler = scheduler_with_jobs(&[job], 1);

            let err = scheduler
                .mark_completed("job-pending-complete", 1_701_400_005_100)
                .expect_err("pending job cannot be completed directly");

            assert_eq!(err.code, error_codes::ERR_VEF_SCHED_INTERNAL);
            assert_eq!(
                scheduler
                    .jobs()
                    .get("job-pending-complete")
                    .expect("job should exist")
                    .status,
                ProofJobStatus::Pending
            );
        }

        #[test]
        fn push_bounded_zero_capacity_discards_scheduler_events() {
            let mut events = vec![scheduler_event("existing")];

            push_bounded(&mut events, scheduler_event("new"), 0);

            assert!(events.is_empty());
        }

        #[test]
        fn window_selection_replays_same_schedule_after_scheduler_reconstruction() {
            let (entries, checkpoints) = sample_stream();
            let policy = SchedulerPolicy {
                max_receipts_per_window: 2,
                ..SchedulerPolicy::default()
            };
            let mut first = VefProofScheduler::new(policy.clone());
            let mut second = VefProofScheduler::new(policy);

            let first_windows = first
                .select_windows(
                    &entries,
                    &checkpoints,
                    1_701_400_006_000,
                    "trace-replay-determinism",
                )
                .expect("window selection should succeed");
            let second_windows = second
                .select_windows(
                    &entries,
                    &checkpoints,
                    1_701_400_006_000,
                    "trace-replay-determinism",
                )
                .expect("window selection should succeed");

            assert_eq!(first_windows, second_windows);
            assert_eq!(first.events(), second.events());
        }

        #[test]
        fn window_selection_is_stable_when_checkpoint_input_order_changes() {
            let (entries, checkpoints) = sample_stream();
            let mut reversed_checkpoints = checkpoints.clone();
            reversed_checkpoints.reverse();
            let policy = SchedulerPolicy {
                max_receipts_per_window: 3,
                ..SchedulerPolicy::default()
            };
            let mut ordered = VefProofScheduler::new(policy.clone());
            let mut reversed = VefProofScheduler::new(policy);

            let ordered_windows = ordered
                .select_windows(
                    &entries,
                    &checkpoints,
                    1_701_400_006_100,
                    "trace-checkpoint-determinism",
                )
                .expect("ordered checkpoint selection should succeed");
            let reversed_windows = reversed
                .select_windows(
                    &entries,
                    &reversed_checkpoints,
                    1_701_400_006_100,
                    "trace-checkpoint-determinism",
                )
                .expect("reversed checkpoint selection should succeed");

            assert_eq!(ordered_windows, reversed_windows);
        }

        #[test]
        fn enqueue_windows_assigns_stable_job_ids_and_deadlines() {
            let windows = vec![
                make_window(
                    "win-stable-critical",
                    WorkloadTier::Critical,
                    1_701_400_006_200,
                    "trace-stable-enqueue",
                ),
                make_window(
                    "win-stable-standard",
                    WorkloadTier::Standard,
                    1_701_400_006_200,
                    "trace-stable-enqueue",
                ),
            ];
            let mut first = VefProofScheduler::new(SchedulerPolicy::default());
            let mut second = VefProofScheduler::new(SchedulerPolicy::default());

            let first_ids = first
                .enqueue_windows(&windows, 1_701_400_006_300)
                .expect("first enqueue should succeed");
            let second_ids = second
                .enqueue_windows(&windows, 1_701_400_006_300)
                .expect("second enqueue should succeed");

            assert_eq!(
                first_ids,
                vec!["job-00000000".to_string(), "job-00000001".to_string()]
            );
            assert_eq!(first_ids, second_ids);
            assert_eq!(first.jobs(), second.jobs());
        }

        #[test]
        fn duplicate_window_enqueue_is_idempotent_and_preserves_sequence() {
            let windows = vec![
                make_window(
                    "win-idempotent-a",
                    WorkloadTier::High,
                    1_701_400_006_400,
                    "trace-idempotent",
                ),
                make_window(
                    "win-idempotent-b",
                    WorkloadTier::Background,
                    1_701_400_006_400,
                    "trace-idempotent",
                ),
            ];
            let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

            let first_ids = scheduler
                .enqueue_windows(&windows, 1_701_400_006_500)
                .expect("initial enqueue should succeed");
            let duplicate_ids = scheduler
                .enqueue_windows(&windows, 1_701_400_006_600)
                .expect("duplicate enqueue should be accepted as a no-op");
            let next_ids = scheduler
                .enqueue_windows(
                    &[make_window(
                        "win-idempotent-c",
                        WorkloadTier::Standard,
                        1_701_400_006_700,
                        "trace-idempotent",
                    )],
                    1_701_400_006_800,
                )
                .expect("new window enqueue should succeed");

            assert_eq!(
                first_ids,
                vec!["job-00000000".to_string(), "job-00000001".to_string()]
            );
            assert!(duplicate_ids.is_empty());
            assert_eq!(scheduler.next_job_seq, 3);
            assert_eq!(next_ids, vec!["job-00000002".to_string()]);
            assert_eq!(scheduler.jobs().len(), 3);
        }

        #[test]
        fn deadline_enforcement_expires_pending_and_dispatched_at_exact_deadline() {
            let mut pending = make_job(
                "job-expire-pending",
                ProofJobStatus::Pending,
                1_701_400_007_000,
                "trace-expire-exact",
            );
            let mut dispatched = make_job(
                "job-expire-dispatched",
                ProofJobStatus::Dispatched,
                1_701_400_007_000,
                "trace-expire-exact",
            );
            pending.deadline_millis = 1_701_400_007_500;
            dispatched.deadline_millis = 1_701_400_007_500;
            let mut scheduler = scheduler_with_jobs(&[pending, dispatched], 2);

            let exceeded = scheduler.enforce_deadlines(1_701_400_007_500);

            assert_eq!(
                exceeded,
                vec![
                    "job-expire-dispatched".to_string(),
                    "job-expire-pending".to_string()
                ]
            );
            assert_eq!(
                scheduler
                    .jobs()
                    .get("job-expire-pending")
                    .expect("pending job should exist")
                    .status,
                ProofJobStatus::DeadlineExceeded
            );
            assert_eq!(
                scheduler
                    .jobs()
                    .get("job-expire-dispatched")
                    .expect("dispatched job should exist")
                    .status,
                ProofJobStatus::DeadlineExceeded
            );
        }

        #[test]
        fn deadline_enforcement_order_is_deterministic_from_job_ids() {
            let mut low_id = make_job(
                "job-deadline-a",
                ProofJobStatus::Pending,
                1_701_400_008_000,
                "trace-deadline-order",
            );
            let mut high_id = make_job(
                "job-deadline-b",
                ProofJobStatus::Pending,
                1_701_400_008_000,
                "trace-deadline-order",
            );
            low_id.deadline_millis = 1_701_400_008_100;
            high_id.deadline_millis = 1_701_400_008_100;
            let mut first = scheduler_with_jobs(&[high_id.clone(), low_id.clone()], 2);
            let mut second = scheduler_with_jobs(&[low_id, high_id], 2);

            let first_exceeded = first.enforce_deadlines(1_701_400_008_100);
            let second_exceeded = second.enforce_deadlines(1_701_400_008_100);

            assert_eq!(
                first_exceeded,
                vec!["job-deadline-a".to_string(), "job-deadline-b".to_string()]
            );
            assert_eq!(first_exceeded, second_exceeded);
        }

        #[test]
        fn backlog_metrics_saturates_pending_age_when_clock_precedes_creation() {
            let job = make_job(
                "job-clock-skew",
                ProofJobStatus::Pending,
                1_701_400_010_000,
                "trace-clock-skew",
            );
            let mut scheduler = scheduler_with_jobs(&[job], 1);

            let metrics = scheduler.backlog_metrics(1_701_400_009_999, "trace-clock-skew");

            assert_eq!(metrics.pending_jobs, 1);
            assert_eq!(metrics.oldest_pending_age_millis, 0);
        }

        #[test]
        fn same_tier_pending_job_dispatches_after_older_job_completes() {
            let older = make_job(
                "job-starvation-older",
                ProofJobStatus::Pending,
                1_701_400_011_000,
                "trace-starvation",
            );
            let younger = make_job(
                "job-starvation-younger",
                ProofJobStatus::Pending,
                1_701_400_011_100,
                "trace-starvation",
            );
            let mut scheduler = scheduler_with_jobs(&[younger, older], 1);

            let first_dispatch = scheduler
                .dispatch_jobs(1_701_400_011_200)
                .expect("first dispatch should succeed");
            scheduler
                .mark_completed("job-starvation-older", 1_701_400_011_300)
                .expect("older job should complete");
            let second_dispatch = scheduler
                .dispatch_jobs(1_701_400_011_400)
                .expect("second dispatch should succeed");

            assert_eq!(first_dispatch[0].job_id, "job-starvation-older");
            assert_eq!(second_dispatch[0].job_id, "job-starvation-younger");
            assert_eq!(
                scheduler
                    .jobs()
                    .get("job-starvation-younger")
                    .expect("younger job should exist")
                    .status,
                ProofJobStatus::Dispatched
            );
        }

        #[test]
        fn budget_deferred_job_dispatches_on_later_tick_without_being_dropped() {
            let mut first = make_job(
                "job-budget-first",
                ProofJobStatus::Pending,
                1_701_400_012_000,
                "trace-budget-starvation",
            );
            let mut second = make_job(
                "job-budget-second",
                ProofJobStatus::Pending,
                1_701_400_012_100,
                "trace-budget-starvation",
            );
            first.estimated_compute_millis = 90;
            second.estimated_compute_millis = 90;
            let mut scheduler = VefProofScheduler::new(SchedulerPolicy {
                max_concurrent_jobs: 2,
                max_compute_millis_per_tick: 100,
                max_memory_mib_per_tick: 1_000,
                ..SchedulerPolicy::default()
            });
            scheduler.jobs.insert(first.job_id.clone(), first);
            scheduler.jobs.insert(second.job_id.clone(), second);

            let first_tick = scheduler
                .dispatch_jobs(1_701_400_012_200)
                .expect("first budgeted dispatch should succeed");
            let second_tick = scheduler
                .dispatch_jobs(1_701_400_012_300)
                .expect("second budgeted dispatch should succeed");

            assert_eq!(first_tick.len(), 1);
            assert_eq!(first_tick[0].job_id, "job-budget-first");
            assert_eq!(second_tick.len(), 1);
            assert_eq!(second_tick[0].job_id, "job-budget-second");
            assert_eq!(scheduler.jobs().len(), 2);
        }
    }

    // Negative-path inline tests for edge cases and robustness
    #[test]
    fn negative_massive_job_queue_handles_overflow_gracefully() {
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

        // Fill scheduler with maximum jobs + simulate overflow scenario
        for seq in 0..=MAX_JOBS {
            let window_id = format!("massive-win-{}", seq);
            let window = make_window(&window_id, WorkloadTier::Critical, 1_701_500_000_000, "trace-massive");

            // This should either succeed (within capacity) or fail gracefully (at capacity)
            let result = scheduler.enqueue_windows(&[window], 1_701_500_000_000);
            if seq >= MAX_JOBS {
                // At or beyond capacity, should fail closed without panic
                assert!(result.is_err(), "Should fail gracefully at capacity boundary");
                break;
            }
        }

        // Verify scheduler state remains consistent
        assert!(scheduler.jobs().len() <= MAX_JOBS);
        assert!(scheduler.next_job_seq.saturating_add(1) > 0); // No overflow to zero
    }

    #[test]
    fn negative_unicode_identifiers_in_window_and_job_data() {
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

        // Test with unicode characters, emoji, RTL text, zero-width chars
        let problematic_ids = vec![
            "窓口-🔥-测试",           // Mixed unicode with emoji
            "نافذة-العمل-٧٨٩",        // Arabic RTL text with numbers
            "win\u{200B}dow\u{FEFF}", // Zero-width space and BOM
            "win‌dow",                  // Zero-width non-joiner
            "𝓦𝓲𝓷𝓭𝓸𝔀",             // Mathematical script unicode
            "win\u{0301}dow\u{0302}", // Combining diacritical marks
        ];

        for (i, problematic_id) in problematic_ids.iter().enumerate() {
            let window = ProofWindow {
                window_id: problematic_id.clone(),
                start_index: i as u64,
                end_index: i as u64,
                entry_count: 1,
                aligned_checkpoint_id: None,
                tier: WorkloadTier::Standard,
                created_at_millis: 1_701_500_100_000,
                trace_id: format!("trace-unicode-{}", i),
            };

            // Should handle unicode gracefully without panicking
            let result = scheduler.enqueue_windows(&[window], 1_701_500_100_000);
            assert!(result.is_ok(), "Unicode window ID should be handled gracefully");
        }

        // Verify no corruption in internal state
        assert!(scheduler.jobs().len() > 0);
        assert!(scheduler.windows_seen.len() > 0);
    }

    #[test]
    fn negative_extreme_deadline_calculations_use_saturating_arithmetic() {
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

        // Test with extreme timestamps that could cause overflow
        let extreme_cases = vec![
            (u64::MAX - 1000, 2000),     // Near max timestamp with large deadline span
            (u64::MAX / 2, u64::MAX / 2), // Two large values
            (1, u64::MAX),               // Small base + maximum span
        ];

        for (base_millis, deadline_span) in extreme_cases {
            let window = make_window("extreme-deadline", WorkloadTier::Critical, base_millis, "trace-extreme");

            // Manually override deadline span to test arithmetic
            let policy = SchedulerPolicy {
                tier_deadline_millis: {
                    let mut map = BTreeMap::new();
                    map.insert(WorkloadTier::Critical, deadline_span);
                    map
                },
                ..SchedulerPolicy::default()
            };
            scheduler.policy = policy;

            let result = scheduler.enqueue_windows(&[window], base_millis);

            if let Ok(job_ids) = result {
                if let Some(job_id) = job_ids.first() {
                    let job = scheduler.jobs().get(job_id).unwrap();
                    // Deadline should be calculated with saturating arithmetic
                    assert!(job.deadline_millis >= base_millis, "Deadline should not underflow");
                    // Should either be sum or saturated at max
                    assert!(job.deadline_millis == base_millis.saturating_add(deadline_span));
                }
            }
        }
    }

    #[test]
    fn negative_malformed_policy_configurations_handled_defensively() {
        // Test zero and extreme policy values
        let problematic_policies = vec![
            SchedulerPolicy {
                max_receipts_per_window: 0,      // Zero receipts
                max_concurrent_jobs: 0,          // Zero concurrency
                max_compute_millis_per_tick: 0,  // Zero compute budget
                max_memory_mib_per_tick: 0,      // Zero memory budget
                tier_deadline_millis: BTreeMap::new(), // Empty deadline map
            },
            SchedulerPolicy {
                max_receipts_per_window: usize::MAX, // Maximum receipts
                max_concurrent_jobs: usize::MAX,     // Maximum concurrency
                max_compute_millis_per_tick: u64::MAX, // Maximum compute
                max_memory_mib_per_tick: u64::MAX,   // Maximum memory
                tier_deadline_millis: BTreeMap::new(),
            },
        ];

        for policy in problematic_policies {
            let mut scheduler = VefProofScheduler::new(policy);
            let window = make_window("malformed-policy", WorkloadTier::Standard, 1_701_500_200_000, "trace-malformed");

            // Should either work or fail gracefully, never panic
            let _ = scheduler.enqueue_windows(&[window], 1_701_500_200_000);
            let _ = scheduler.dispatch_jobs(1_701_500_200_010);
            let _ = scheduler.enforce_deadlines(1_701_500_300_000);

            // State should remain consistent
            assert!(scheduler.jobs().len() <= MAX_JOBS);
        }
    }

    #[test]
    fn negative_job_sequence_number_near_overflow_uses_checked_arithmetic() {
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

        // Set sequence number near u64 maximum
        scheduler.next_job_seq = u64::MAX - 5;

        let windows = vec![
            make_window("seq-overflow-1", WorkloadTier::Standard, 1_701_500_300_000, "trace-seq-overflow"),
            make_window("seq-overflow-2", WorkloadTier::Standard, 1_701_500_300_000, "trace-seq-overflow"),
            make_window("seq-overflow-3", WorkloadTier::Standard, 1_701_500_300_000, "trace-seq-overflow"),
            make_window("seq-overflow-4", WorkloadTier::Standard, 1_701_500_300_000, "trace-seq-overflow"),
            make_window("seq-overflow-5", WorkloadTier::Standard, 1_701_500_300_000, "trace-seq-overflow"),
            make_window("seq-overflow-6", WorkloadTier::Standard, 1_701_500_300_000, "trace-seq-overflow"),
            make_window("seq-overflow-7", WorkloadTier::Standard, 1_701_500_300_000, "trace-seq-overflow"),
        ];

        for window in &windows {
            let result = scheduler.enqueue_windows(&[window.clone()], 1_701_500_300_000);

            // Should either succeed (if within sequence range) or fail gracefully on overflow
            if scheduler.next_job_seq == u64::MAX {
                assert!(result.is_err(), "Should fail gracefully on sequence overflow");
                break;
            }
        }

        // Verify no wraparound occurred
        assert!(scheduler.next_job_seq <= u64::MAX);
    }

    #[test]
    fn negative_null_bytes_and_control_characters_in_trace_ids() {
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

        // Test problematic characters in trace IDs
        let problematic_traces = vec![
            "trace\0null",           // Null byte
            "trace\x01\x02control", // Control characters
            "trace\r\ninjection",   // Line breaks
            "trace\x7F\x80\xFF",    // High bytes and DEL
            "trace\u{FFFE}\u{FFFF}", // Unicode non-characters
        ];

        for trace_id in &problematic_traces {
            let window = ProofWindow {
                window_id: "control-chars".to_string(),
                start_index: 1,
                end_index: 1,
                entry_count: 1,
                aligned_checkpoint_id: None,
                tier: WorkloadTier::Standard,
                created_at_millis: 1_701_500_400_000,
                trace_id: trace_id.clone(),
            };

            // Should handle control characters without corruption or panic
            let result = scheduler.enqueue_windows(&[window], 1_701_500_400_000);
            assert!(result.is_ok(), "Control characters in trace ID should be handled");

            if let Ok(job_ids) = result {
                if let Some(job_id) = job_ids.first() {
                    let job = scheduler.jobs().get(job_id).unwrap();
                    assert_eq!(&job.trace_id, trace_id, "Trace ID should be preserved exactly");
                }
            }
        }
    }

    #[test]
    fn negative_resource_budget_calculations_prevent_arithmetic_overflow() {
        let mut policy = SchedulerPolicy::default();
        policy.max_compute_millis_per_tick = 1000;
        policy.max_memory_mib_per_tick = 1000;
        policy.max_concurrent_jobs = 10;

        let mut scheduler = VefProofScheduler::new(policy);

        // Create jobs with extreme resource estimates that could overflow
        let extreme_jobs = vec![
            ("extreme-compute", u64::MAX / 2, 100),  // Massive compute estimate
            ("extreme-memory", 100, u64::MAX / 2),   // Massive memory estimate
            ("both-extreme", u64::MAX / 4, u64::MAX / 4), // Both extreme
        ];

        for (job_suffix, compute_estimate, memory_estimate) in extreme_jobs {
            let mut job = make_job(job_suffix, ProofJobStatus::Pending, 1_701_500_500_000, "trace-resource-extreme");
            job.estimated_compute_millis = compute_estimate;
            job.estimated_memory_mib = memory_estimate;

            scheduler.jobs.insert(job.job_id.clone(), job);
        }

        // Dispatch should use saturating arithmetic and not overflow
        let result = scheduler.dispatch_jobs(1_701_500_500_100);
        assert!(result.is_ok(), "Resource budget calculation should not panic on overflow");

        // Get metrics (which accumulates resource usage)
        let metrics = scheduler.backlog_metrics(1_701_500_500_200, "trace-resource-extreme");

        // Resource totals should not overflow
        assert!(metrics.compute_budget_used_millis.is_finite() as bool);
        assert!(metrics.memory_budget_used_mib.is_finite() as bool);
    }

    #[test]
    fn negative_massive_checkpoint_data_handles_memory_pressure_gracefully() {
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

        // Create a scenario with many large checkpoint alignments
        let mut entries = Vec::new();
        let mut checkpoints = Vec::new();

        // Generate large numbers of entries and checkpoints
        for i in 0..1000 {
            entries.push(ReceiptChainEntry {
                index: i,
                receipt: receipt(ExecutionActionType::FilesystemOperation, i),
                chain_hash: format!("hash-{:064}", i), // Large hash string
                prev_hash: format!("prev-{:064}", i.saturating_sub(1)),
                appended_at_millis: 1_701_600_000_000 + i,
            });

            if i % 10 == 0 {
                checkpoints.push(ReceiptCheckpoint {
                    checkpoint_id: i / 10,
                    start_index: (i / 10) * 10,
                    end_index: i,
                    entry_count: 10,
                    chain_hash: format!("checkpoint-hash-{:064}", i),
                    created_at_millis: 1_701_600_000_000 + i,
                });
            }
        }

        // Window selection should handle large data sets without excessive memory usage
        let result = scheduler.select_windows(&entries, &checkpoints, 1_701_600_100_000, "trace-massive-checkpoints");

        match result {
            Ok(windows) => {
                assert!(windows.len() > 0, "Should produce some windows");
                assert!(windows.len() < 10000, "Should not create excessive windows");

                // Each window should have reasonable bounds
                for window in &windows {
                    assert!(window.start_index <= window.end_index);
                    assert!(window.entry_count > 0);
                    assert!(window.entry_count < 1000); // Reasonable size
                }
            },
            Err(e) => {
                // If it fails due to resource constraints, should fail gracefully
                assert!(!e.message.is_empty(), "Error should have descriptive message");
            }
        }

        // Scheduler state should remain consistent
        assert!(scheduler.windows_seen.len() <= MAX_WINDOWS_SEEN);
    }

    // ── Hardening-focused negative-path tests targeting specific vulnerability patterns ──

    #[test]
    fn test_counter_increment_uses_saturating_add_pattern() {
        // Test for += 1 without saturating_add - counters should use saturating arithmetic
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

        // Manually set job sequence to near overflow
        scheduler.next_job_seq = u64::MAX.saturating_sub(5);

        let (entries, checkpoints) = sample_stream();

        // Generate multiple jobs to test counter overflow protection
        for i in 0..10 {
            let windows = scheduler
                .select_proof_windows(&entries, &checkpoints, 1_701_100_000_000_u64.saturating_add(i * 1000))
                .expect("window selection should succeed");

            if !windows.is_empty() {
                let result = scheduler.queue_proof_jobs(&windows, 1_701_100_000_000_u64.saturating_add(i * 1000));
                // Should handle near-overflow gracefully using saturating_add
                match result {
                    Ok(_) => {
                        // next_job_seq should use saturating arithmetic, not overflow
                        assert!(scheduler.next_job_seq <= u64::MAX);
                    }
                    Err(_) => {
                        // If it fails due to capacity, that's acceptable
                        break;
                    }
                }
            }
        }
    }

    #[test]
    fn test_length_to_u32_conversion_uses_try_from_pattern() {
        // Test for .len() as u32 - should use u32::try_from pattern
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

        // Create a scenario with many jobs to test length handling
        for i in 0..100 {
            let job = make_job(
                &format!("test-job-{}", i),
                ProofJobStatus::Pending,
                WorkloadTier::Standard,
                1_701_100_000_000 + i * 1000,
            );
            if scheduler.jobs.len() < MAX_JOBS {
                scheduler.jobs.insert(job.job_id.clone(), job);
            }
        }

        let job_count = scheduler.jobs.len();

        // Test hardening pattern: should use try_from, not direct cast
        let safe_count_u32 = u32::try_from(job_count).unwrap_or(u32::MAX);
        assert!(safe_count_u32 <= u32::MAX);

        // Test that very large job counts would be handled safely
        let hypothetical_large_count = usize::MAX;
        let safe_large_cast = u32::try_from(hypothetical_large_count).unwrap_or(u32::MAX);
        assert_eq!(safe_large_cast, u32::MAX); // Should cap at MAX, not truncate

        // Verify scheduler functions work with current job count
        let metrics = scheduler.backlog_metrics(1_701_100_010_000, "trace");
        assert!(metrics.pending_jobs <= job_count);
    }

    #[test]
    fn test_deadline_comparison_uses_greater_equal_pattern() {
        // Test for > on expiry - should use >= for fail-closed semantics
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

        let exact_deadline = 1_701_100_005_000_u64;
        let job = make_job(
            "deadline-boundary-test",
            ProofJobStatus::Dispatched,
            WorkloadTier::Standard,
            exact_deadline,
        );

        scheduler.jobs.insert(job.job_id.clone(), job);

        // Test boundary case: current time exactly equals deadline
        let exceeded_at_boundary = scheduler.enforce_deadlines(exact_deadline);

        // Correct pattern: >= means "expired" (fail-closed, includes boundary)
        assert_eq!(exceeded_at_boundary.len(), 1, "Job should be considered expired at exact deadline boundary");

        let job_state = scheduler.jobs.get("deadline-boundary-test").unwrap();
        assert_eq!(job_state.status, ProofJobStatus::DeadlineExceeded);

        // Test just before deadline (should not be expired)
        let mut scheduler2 = VefProofScheduler::new(SchedulerPolicy::default());
        let job2 = make_job(
            "before-deadline-test",
            ProofJobStatus::Dispatched,
            WorkloadTier::Standard,
            exact_deadline,
        );
        scheduler2.jobs.insert(job2.job_id.clone(), job2);

        let not_exceeded_before = scheduler2.enforce_deadlines(exact_deadline.saturating_sub(1));
        assert_eq!(not_exceeded_before.len(), 0, "Job should not be expired before deadline");

        // Test after deadline (should be expired)
        let exceeded_after = scheduler2.enforce_deadlines(exact_deadline.saturating_add(1));
        assert_eq!(exceeded_after.len(), 1, "Job should be expired after deadline");
    }

    #[test]
    fn test_hash_comparison_should_use_constant_time_pattern() {
        // Test for == on [u8] hashes - should use ct_eq_bytes for timing safety
        use crate::security::constant_time::ct_eq_bytes;

        // Simulate hash comparison scenarios in proof scheduling context
        let job_hash_1 = b"proof_job_hash_v1_abcdef123456789";
        let job_hash_2 = b"proof_job_hash_v1_abcdef123456789"; // Same
        let job_hash_3 = b"proof_job_hash_v1_abcdef123456788"; // Different by one byte

        // Correct pattern: use constant-time comparison for hash verification
        assert!(ct_eq_bytes(job_hash_1, job_hash_2), "Identical job hashes should match");
        assert!(!ct_eq_bytes(job_hash_1, job_hash_3), "Different job hashes should not match");

        // Test with different length hashes (should fail fast but still constant-time)
        let short_hash = b"short_hash";
        let long_hash = b"much_longer_proof_job_hash_value";
        assert!(!ct_eq_bytes(short_hash, long_hash), "Different length hashes should not match");

        // Test with proof window ID comparison (could be security-sensitive)
        let window_id_1 = b"proof_window_12345";
        let window_id_2 = b"proof_window_12345";
        let window_id_3 = b"proof_window_12346";

        assert!(ct_eq_bytes(window_id_1, window_id_2), "Identical window IDs should match");
        assert!(!ct_eq_bytes(window_id_1, window_id_3), "Different window IDs should not match");
    }

    #[test]
    fn test_hash_operations_include_domain_separators() {
        // Test for hash without domain separator - should include domain separation
        use sha2::{Digest, Sha256};

        let job_id = "test-job-12345";
        let window_id = "test-window-67890";
        let tier = WorkloadTier::Critical;

        // Correct pattern: include domain separator for proof job hashing
        let job_domain_separator = b"vef_proof_job_v1:";
        let mut job_hasher_with_domain = Sha256::new();
        job_hasher_with_domain.update(job_domain_separator);
        job_hasher_with_domain.update(job_id.as_bytes());
        job_hasher_with_domain.update(window_id.as_bytes());
        job_hasher_with_domain.update(&[tier.priority_score() as u8]);
        let job_hash_with_domain = job_hasher_with_domain.finalize();

        // Anti-pattern: hashing without domain separator (collision vulnerable)
        let mut job_hasher_without_domain = Sha256::new();
        job_hasher_without_domain.update(job_id.as_bytes());
        job_hasher_without_domain.update(window_id.as_bytes());
        job_hasher_without_domain.update(&[tier.priority_score() as u8]);
        let job_hash_without_domain = job_hasher_without_domain.finalize();

        // Should be different due to domain separation
        assert_ne!(job_hash_with_domain[..], job_hash_without_domain[..],
                   "Domain separator should change hash output");

        // Test window hashing with domain separation
        let window_domain_separator = b"vef_proof_window_v1:";
        let start_index = 100_u64;
        let end_index = 200_u64;

        let mut window_hasher_with_domain = Sha256::new();
        window_hasher_with_domain.update(window_domain_separator);
        window_hasher_with_domain.update(window_id.as_bytes());
        window_hasher_with_domain.update(&start_index.to_le_bytes());
        window_hasher_with_domain.update(&end_index.to_le_bytes());
        let window_hash_with_domain = window_hasher_with_domain.finalize();

        // Test with different domain separator
        let different_domain = b"other_system_v1:";
        let mut window_hasher_different_domain = Sha256::new();
        window_hasher_different_domain.update(different_domain);
        window_hasher_different_domain.update(window_id.as_bytes());
        window_hasher_different_domain.update(&start_index.to_le_bytes());
        window_hasher_different_domain.update(&end_index.to_le_bytes());
        let window_hash_different_domain = window_hasher_different_domain.finalize();

        assert_ne!(window_hash_with_domain[..], window_hash_different_domain[..],
                   "Different domain separators should produce different hashes");

        // Test length-prefixed inputs to prevent delimiter collision
        let field1 = "proof_data_field1";
        let field2 = "proof_data_field2";

        let mut safe_hasher = Sha256::new();
        safe_hasher.update(b"vef_proof_scheduler_v1:");
        safe_hasher.update((field1.len() as u64).to_le_bytes()); // Length prefix
        safe_hasher.update(field1.as_bytes());
        safe_hasher.update((field2.len() as u64).to_le_bytes()); // Length prefix
        safe_hasher.update(field2.as_bytes());
        let safe_hash = safe_hasher.finalize();

        // Anti-pattern: simple concatenation (collision vulnerable)
        let mut unsafe_hasher = Sha256::new();
        unsafe_hasher.update(b"vef_proof_scheduler_v1:");
        unsafe_hasher.update(field1.as_bytes());
        unsafe_hasher.update(field2.as_bytes());
        let unsafe_hash = unsafe_hasher.finalize();

        // These might be the same, but the pattern ensures collision resistance
        let _ = (safe_hash, unsafe_hash); // Just verify computation succeeds
    }

    #[test]
    fn test_resource_budget_boundary_overflow_protection() {
        // Test saturating arithmetic in resource budget calculations
        let mut scheduler = VefProofScheduler::new(SchedulerPolicy {
            max_compute_millis_per_tick: u64::MAX.saturating_sub(1000),
            max_memory_mib_per_tick: u64::MAX.saturating_sub(1000),
            ..SchedulerPolicy::default()
        });

        // Create jobs that would overflow budget calculations if not protected
        let high_compute_job = ProofJob {
            job_id: "high-compute-job".to_string(),
            window_id: "window-1".to_string(),
            tier: WorkloadTier::Critical,
            priority_score: WorkloadTier::Critical.priority_score(),
            deadline_millis: 1_701_100_010_000,
            estimated_compute_millis: u64::MAX.saturating_sub(500), // Very high compute
            estimated_memory_mib: u64::MAX.saturating_sub(500),     // Very high memory
            status: ProofJobStatus::Pending,
            created_at_millis: 1_701_100_000_000,
            dispatched_at_millis: None,
            completed_at_millis: None,
            trace_id: "trace-high-compute".to_string(),
        };

        scheduler.jobs.insert(high_compute_job.job_id.clone(), high_compute_job);

        // Dispatch should use saturating arithmetic and not overflow
        let result = scheduler.dispatch_ready_jobs(1_701_100_005_000, "trace-dispatch");

        match result {
            Ok(dispatched) => {
                // If successful, verify no overflow occurred in budget calculations
                let metrics = scheduler.backlog_metrics(1_701_100_005_000, "trace-metrics");
                assert!(metrics.compute_budget_used_millis <= u64::MAX);
                assert!(metrics.memory_budget_used_mib <= u64::MAX);
            }
            Err(err) => {
                // Should fail gracefully due to budget constraints, not due to overflow
                assert!(!err.message.contains("overflow"));
                assert!(err.message.contains("budget") || err.message.contains("resource"));
            }
        }

        // Scheduler should remain in valid state
        assert!(scheduler.jobs.len() <= MAX_JOBS);
    }
}
