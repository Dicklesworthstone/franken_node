use pi::hostcall_queue::{
    BravoBiasMode, ContentionSample, ContentionSignature, HostcallQueueEnqueueResult,
    HostcallQueueMode, HostcallRequestQueue, QueueTenant, S3FifoFallbackReason, S3FifoMode,
};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TenantRequest {
    tenant: Option<&'static str>,
    value: u8,
}

impl QueueTenant for TenantRequest {
    fn tenant_key(&self) -> Option<&str> {
        self.tenant
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SwarmHostcallRequest {
    tenant: String,
    agent_index: usize,
    request_index: u32,
    created_step: u64,
}

impl QueueTenant for SwarmHostcallRequest {
    fn tenant_key(&self) -> Option<&str> {
        Some(&self.tenant)
    }
}

#[derive(Debug, Clone, Copy)]
enum SwarmSchedulingMode {
    Sequential,
    Batched,
    Adaptive,
}

impl SwarmSchedulingMode {
    const fn label(self) -> &'static str {
        match self {
            Self::Sequential => "sequential",
            Self::Batched => "batched",
            Self::Adaptive => "adaptive",
        }
    }
}

#[derive(Debug, Default)]
struct SwarmProfileMetrics {
    mode: &'static str,
    total_requests: u64,
    accepted_requests: u64,
    completed_requests: u64,
    rejected_requests: u64,
    fast_lane_admissions: u64,
    compat_lane_admissions: u64,
    backpressure_events: u64,
    fairness_rejections: u64,
    rollback_events: u64,
    starvation_windows: u64,
    starved_agents: usize,
    fairness_spread: u64,
    p99_tail_latency_steps: u64,
    max_tail_latency_steps: u64,
    max_depth_seen: usize,
    final_s3fifo_mode: &'static str,
    final_reclamation_mode: &'static str,
}

impl SwarmProfileMetrics {
    fn to_json(&self) -> Value {
        json!({
            "mode": self.mode,
            "total_requests": self.total_requests,
            "accepted_requests": self.accepted_requests,
            "completed_requests": self.completed_requests,
            "rejected_requests": self.rejected_requests,
            "fast_lane_admissions": self.fast_lane_admissions,
            "compat_lane_admissions": self.compat_lane_admissions,
            "backpressure_events": self.backpressure_events,
            "fairness_rejections": self.fairness_rejections,
            "rollback_events": self.rollback_events,
            "starvation_windows": self.starvation_windows,
            "starved_agents": self.starved_agents,
            "fairness_spread": self.fairness_spread,
            "p99_tail_latency_steps": self.p99_tail_latency_steps,
            "max_tail_latency_steps": self.max_tail_latency_steps,
            "max_depth_seen": self.max_depth_seen,
            "final_s3fifo_mode": self.final_s3fifo_mode,
            "final_reclamation_mode": self.final_reclamation_mode,
        })
    }
}

const SWARM_AGENTS: usize = 64;
const SWARM_HOSTCALLS_PER_AGENT: u32 = 2;
const SWARM_FAST_CAPACITY: usize = 8;
const SWARM_COMPAT_CAPACITY: usize = 24;
const SWARM_QUEUE_CAPACITY: usize = SWARM_FAST_CAPACITY + SWARM_COMPAT_CAPACITY;
const NOISY_TENANT_PROBE_REQUESTS: u32 = 32;
const FAIRNESS_SPREAD_BUDGET: u64 = 1;
const P99_TAIL_LATENCY_BUDGET_STEPS: u64 = 96;
const MAX_TAIL_LATENCY_BUDGET_STEPS: u64 = 128;

const fn starvation_sample() -> ContentionSample {
    ContentionSample {
        read_acquires: 80,
        write_acquires: 20,
        read_wait_p95_us: 120,
        write_wait_p95_us: 9_000,
        write_timeouts: 3,
    }
}

const fn read_dominant_sample() -> ContentionSample {
    ContentionSample {
        read_acquires: 90,
        write_acquires: 10,
        read_wait_p95_us: 90,
        write_wait_p95_us: 240,
        write_timeouts: 0,
    }
}

const fn write_dominant_sample() -> ContentionSample {
    ContentionSample {
        read_acquires: 20,
        write_acquires: 80,
        read_wait_p95_us: 120,
        write_wait_p95_us: 420,
        write_timeouts: 0,
    }
}

fn hostcall_swarm_report_path() -> PathBuf {
    if let Some(path) = std::env::var_os("PERF_EVIDENCE_DIR")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        let base = if path.is_absolute() {
            path
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
        };
        return base.join("hostcall_admission_swarm_profile.json");
    }

    if let Some(path) = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
    {
        let base = if path.is_absolute() {
            path
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
        };
        return base
            .join("perf")
            .join("hostcall_admission_swarm_profile.json");
    }

    std::env::temp_dir()
        .join("pi_agent_rust")
        .join("hostcall_admission_swarm_profile.json")
}

fn percentile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let rank = (len * numerator).saturating_add(denominator - 1) / denominator;
    rank.saturating_sub(1).min(len - 1)
}

fn p99_latency_steps(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted
        .get(percentile_index(sorted.len(), 99, 100))
        .copied()
        .unwrap_or(0)
}

const fn reclamation_mode_label(mode: HostcallQueueMode) -> &'static str {
    match mode {
        HostcallQueueMode::Ebr => "ebr",
        HostcallQueueMode::SafeFallback => "safe_fallback",
    }
}

const fn s3fifo_mode_label(mode: S3FifoMode) -> &'static str {
    match mode {
        S3FifoMode::Active => "active",
        S3FifoMode::ConservativeFifo => "conservative_fifo",
    }
}

fn enqueue_swarm_request(
    queue: &mut HostcallRequestQueue<SwarmHostcallRequest>,
    metrics: &mut SwarmProfileMetrics,
    step: &mut u64,
    agent_index: usize,
    request_index: u32,
) {
    *step = step.saturating_add(1);
    metrics.total_requests = metrics.total_requests.saturating_add(1);
    let request = SwarmHostcallRequest {
        tenant: format!("ext.agent.{agent_index:02}"),
        agent_index,
        request_index,
        created_step: *step,
    };

    match queue.push_back(request) {
        HostcallQueueEnqueueResult::FastPath { .. } => {
            metrics.accepted_requests = metrics.accepted_requests.saturating_add(1);
            metrics.fast_lane_admissions = metrics.fast_lane_admissions.saturating_add(1);
        }
        HostcallQueueEnqueueResult::OverflowPath { .. } => {
            metrics.accepted_requests = metrics.accepted_requests.saturating_add(1);
            metrics.compat_lane_admissions = metrics.compat_lane_admissions.saturating_add(1);
            metrics.backpressure_events = metrics.backpressure_events.saturating_add(1);
        }
        HostcallQueueEnqueueResult::Rejected { .. } => {
            metrics.rejected_requests = metrics.rejected_requests.saturating_add(1);
            metrics.backpressure_events = metrics.backpressure_events.saturating_add(1);
        }
    }
}

fn drain_swarm_queue(
    queue: &mut HostcallRequestQueue<SwarmHostcallRequest>,
    metrics: &mut SwarmProfileMetrics,
    step: &mut u64,
    completed_by_agent: &mut [u64],
    latency_steps: &mut Vec<u64>,
) {
    for request in queue.drain_all() {
        *step = step.saturating_add(1);
        metrics.completed_requests = metrics.completed_requests.saturating_add(1);
        let latency = step.saturating_sub(request.created_step);
        latency_steps.push(latency);
        if let Some(completed) = completed_by_agent.get_mut(request.agent_index) {
            *completed = completed.saturating_add(1);
        }
        assert!(
            request.request_index < SWARM_HOSTCALLS_PER_AGENT
                || request.agent_index >= SWARM_AGENTS,
            "normal swarm request index should stay within the replay contract"
        );
    }
}

fn feed_contention_replay(
    queue: &mut HostcallRequestQueue<SwarmHostcallRequest>,
    metrics: &mut SwarmProfileMetrics,
) {
    for sample in [
        read_dominant_sample(),
        starvation_sample(),
        write_dominant_sample(),
        write_dominant_sample(),
        write_dominant_sample(),
    ] {
        let decision = queue.observe_contention_window(sample);
        if matches!(
            decision.signature,
            ContentionSignature::WriterStarvationRisk
        ) {
            metrics.starvation_windows = metrics.starvation_windows.saturating_add(1);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run_swarm_admission_profile(mode: SwarmSchedulingMode) -> SwarmProfileMetrics {
    let mut queue = HostcallRequestQueue::with_mode(
        SWARM_FAST_CAPACITY,
        SWARM_COMPAT_CAPACITY,
        HostcallQueueMode::Ebr,
    );
    let mut metrics = SwarmProfileMetrics {
        mode: mode.label(),
        ..Default::default()
    };
    let mut completed_by_agent = vec![0_u64; SWARM_AGENTS];
    let mut latency_steps = Vec::new();
    let mut step = 0_u64;

    feed_contention_replay(&mut queue, &mut metrics);

    match mode {
        SwarmSchedulingMode::Sequential => {
            for chunk_start in (0..SWARM_AGENTS).step_by(8) {
                let chunk_end = chunk_start.saturating_add(8).min(SWARM_AGENTS);
                for request_index in 0..SWARM_HOSTCALLS_PER_AGENT {
                    for agent_index in chunk_start..chunk_end {
                        enqueue_swarm_request(
                            &mut queue,
                            &mut metrics,
                            &mut step,
                            agent_index,
                            request_index,
                        );
                    }
                }
                drain_swarm_queue(
                    &mut queue,
                    &mut metrics,
                    &mut step,
                    &mut completed_by_agent,
                    &mut latency_steps,
                );
            }
        }
        SwarmSchedulingMode::Batched => {
            for chunk_start in (0..SWARM_AGENTS).step_by(16) {
                let chunk_end = chunk_start.saturating_add(16).min(SWARM_AGENTS);
                for request_index in 0..SWARM_HOSTCALLS_PER_AGENT {
                    for agent_index in chunk_start..chunk_end {
                        enqueue_swarm_request(
                            &mut queue,
                            &mut metrics,
                            &mut step,
                            agent_index,
                            request_index,
                        );
                    }
                }
                drain_swarm_queue(
                    &mut queue,
                    &mut metrics,
                    &mut step,
                    &mut completed_by_agent,
                    &mut latency_steps,
                );
            }
        }
        SwarmSchedulingMode::Adaptive => {
            for request_index in 0..SWARM_HOSTCALLS_PER_AGENT {
                for agent_index in 0..SWARM_AGENTS {
                    enqueue_swarm_request(
                        &mut queue,
                        &mut metrics,
                        &mut step,
                        agent_index,
                        request_index,
                    );
                    if queue.len() >= SWARM_QUEUE_CAPACITY.saturating_sub(SWARM_FAST_CAPACITY) {
                        drain_swarm_queue(
                            &mut queue,
                            &mut metrics,
                            &mut step,
                            &mut completed_by_agent,
                            &mut latency_steps,
                        );
                    }
                }
            }
            drain_swarm_queue(
                &mut queue,
                &mut metrics,
                &mut step,
                &mut completed_by_agent,
                &mut latency_steps,
            );
        }
    }

    for request_index in 0..NOISY_TENANT_PROBE_REQUESTS {
        enqueue_swarm_request(
            &mut queue,
            &mut metrics,
            &mut step,
            SWARM_AGENTS,
            request_index,
        );
    }
    drain_swarm_queue(
        &mut queue,
        &mut metrics,
        &mut step,
        &mut completed_by_agent,
        &mut latency_steps,
    );

    let snapshot = queue.snapshot();
    metrics.fairness_rejections = snapshot.s3fifo_fairness_rejected_total;
    metrics.rollback_events = snapshot.bravo_rollbacks;
    metrics.max_depth_seen = snapshot.max_depth_seen;
    metrics.p99_tail_latency_steps = p99_latency_steps(&latency_steps);
    metrics.max_tail_latency_steps = latency_steps.iter().copied().max().unwrap_or(0);
    metrics.final_s3fifo_mode = s3fifo_mode_label(snapshot.s3fifo_mode);
    metrics.final_reclamation_mode = reclamation_mode_label(snapshot.reclamation_mode);
    metrics.starved_agents = completed_by_agent
        .iter()
        .filter(|completed| **completed == 0)
        .count();
    let min_completed = completed_by_agent.iter().copied().min().unwrap_or(0);
    let max_completed = completed_by_agent.iter().copied().max().unwrap_or(0);
    metrics.fairness_spread = max_completed.saturating_sub(min_completed);

    metrics
}

#[test]
fn ebr_mode_reports_retired_backlog_until_epoch_pins_release() {
    let mut queue = HostcallRequestQueue::with_mode(2, 2, HostcallQueueMode::Ebr);
    let pin = queue.pin_epoch();

    assert!(matches!(
        queue.push_back(1_u8),
        HostcallQueueEnqueueResult::FastPath { .. }
    ));
    assert!(matches!(
        queue.push_back(2_u8),
        HostcallQueueEnqueueResult::FastPath { .. }
    ));
    assert!(matches!(
        queue.push_back(3_u8),
        HostcallQueueEnqueueResult::OverflowPath { .. }
    ));

    let drained = queue.drain_all();
    assert_eq!(drained.into_iter().collect::<Vec<_>>(), vec![1, 2, 3]);

    queue.force_reclaim();
    let pinned = queue.snapshot();
    assert_eq!(pinned.reclamation_mode, HostcallQueueMode::Ebr);
    assert_eq!(pinned.active_epoch_pins, 1);
    assert!(pinned.retired_backlog >= 3);
    assert_eq!(pinned.reclaimed_total, 0);

    drop(pin);
    queue.force_reclaim();
    let reclaimed = queue.snapshot();
    assert_eq!(reclaimed.active_epoch_pins, 0);
    assert_eq!(reclaimed.retired_backlog, 0);
    assert!(reclaimed.reclaimed_total >= 3);
    assert!(reclaimed.reclamation_latency_max_epochs >= 1);
}

#[test]
#[allow(clippy::too_many_lines)]
fn swarm_64_core_hostcall_admission_profile_fails_closed_on_tail_and_starvation()
-> Result<(), Box<dyn std::error::Error>> {
    let profiles = [
        run_swarm_admission_profile(SwarmSchedulingMode::Sequential),
        run_swarm_admission_profile(SwarmSchedulingMode::Batched),
        run_swarm_admission_profile(SwarmSchedulingMode::Adaptive),
    ];

    for profile in &profiles {
        assert!(
            profile.fast_lane_admissions > 0,
            "{} profile should exercise the fast lane",
            profile.mode
        );
        assert!(
            profile.compat_lane_admissions > 0,
            "{} profile should exercise the compatibility/overflow lane",
            profile.mode
        );
        assert!(
            profile.backpressure_events > 0,
            "{} profile should record overflow or rejection backpressure",
            profile.mode
        );
        assert!(
            profile.fairness_rejections > 0,
            "{} profile should include a noisy-tenant fairness rejection probe",
            profile.mode
        );
        assert!(
            profile.rollback_events > 0,
            "{} profile should replay BRAVO writer-starvation rollback",
            profile.mode
        );
        assert!(
            profile.starvation_windows > 0,
            "{} profile should record at least one starvation-risk observation",
            profile.mode
        );
        assert_eq!(
            profile.starved_agents, 0,
            "{} profile left one or more swarm agents with zero completions",
            profile.mode
        );
        assert!(
            profile.fairness_spread <= FAIRNESS_SPREAD_BUDGET,
            "{} profile completed calls unevenly across agents: spread={} budget={}",
            profile.mode,
            profile.fairness_spread,
            FAIRNESS_SPREAD_BUDGET
        );
        assert!(
            profile.max_depth_seen <= SWARM_QUEUE_CAPACITY,
            "{} profile exceeded bounded queue capacity: max_depth={} capacity={}",
            profile.mode,
            profile.max_depth_seen,
            SWARM_QUEUE_CAPACITY
        );
        assert!(
            profile.p99_tail_latency_steps <= P99_TAIL_LATENCY_BUDGET_STEPS,
            "{} profile p99 tail latency {} exceeded budget {}",
            profile.mode,
            profile.p99_tail_latency_steps,
            P99_TAIL_LATENCY_BUDGET_STEPS
        );
        assert!(
            profile.max_tail_latency_steps <= MAX_TAIL_LATENCY_BUDGET_STEPS,
            "{} profile max tail latency {} exceeded budget {}",
            profile.mode,
            profile.max_tail_latency_steps,
            MAX_TAIL_LATENCY_BUDGET_STEPS
        );
        assert_eq!(
            profile.completed_requests, profile.accepted_requests,
            "{} profile lost accepted hostcalls before completion",
            profile.mode
        );
    }

    let report_path = hostcall_swarm_report_path();
    let Some(report_parent) = report_path.parent() else {
        return Err("hostcall swarm report path should have a parent directory".into());
    };
    std::fs::create_dir_all(report_parent)?;
    let report = json!({
        "schema": "pi.ext.hostcall_admission_swarm_profile.v1",
        "agents": SWARM_AGENTS,
        "hostcalls_per_agent": SWARM_HOSTCALLS_PER_AGENT,
        "fast_capacity": SWARM_FAST_CAPACITY,
        "compat_capacity": SWARM_COMPAT_CAPACITY,
        "thresholds": {
            "fairness_spread_budget": FAIRNESS_SPREAD_BUDGET,
            "p99_tail_latency_budget_steps": P99_TAIL_LATENCY_BUDGET_STEPS,
            "max_tail_latency_budget_steps": MAX_TAIL_LATENCY_BUDGET_STEPS,
        },
        "profiles": profiles
            .iter()
            .map(SwarmProfileMetrics::to_json)
            .collect::<Vec<_>>(),
    });
    let report_json = serde_json::to_string_pretty(&report)? + "\n";
    std::fs::write(&report_path, report_json)?;
    eprintln!("hostcall admission swarm report: {}", report_path.display());
    Ok(())
}

#[test]
fn enqueue_depths_and_backpressure_counters_stay_consistent() {
    let mut queue = HostcallRequestQueue::with_mode(2, 2, HostcallQueueMode::SafeFallback);

    assert!(matches!(
        queue.push_back(10_u8),
        HostcallQueueEnqueueResult::FastPath { depth: 1 }
    ));
    assert!(matches!(
        queue.push_back(11_u8),
        HostcallQueueEnqueueResult::FastPath { depth: 2 }
    ));
    assert!(matches!(
        queue.push_back(12_u8),
        HostcallQueueEnqueueResult::OverflowPath {
            depth: 3,
            overflow_depth: 1
        }
    ));
    assert!(matches!(
        queue.push_back(13_u8),
        HostcallQueueEnqueueResult::OverflowPath {
            depth: 4,
            overflow_depth: 2
        }
    ));
    assert!(matches!(
        queue.push_back(14_u8),
        HostcallQueueEnqueueResult::Rejected {
            depth: 4,
            overflow_depth: 2
        }
    ));

    let snapshot = queue.snapshot();
    assert_eq!(snapshot.total_depth, 4);
    assert_eq!(snapshot.fast_depth, 2);
    assert_eq!(snapshot.overflow_depth, 2);
    assert_eq!(snapshot.max_depth_seen, 4);
    assert_eq!(snapshot.overflow_enqueued_total, 2);
    assert_eq!(snapshot.overflow_rejected_total, 1);
}

#[test]
fn drain_preserves_fifo_when_overflow_lane_is_engaged() {
    let mut queue = HostcallRequestQueue::with_mode(1, 3, HostcallQueueMode::SafeFallback);

    assert!(matches!(
        queue.push_back(0_u8),
        HostcallQueueEnqueueResult::FastPath { depth: 1 }
    ));
    for (value, expected_depth, expected_overflow_depth) in [
        (1_u8, 2_usize, 1_usize),
        (2_u8, 3_usize, 2_usize),
        (3_u8, 4_usize, 3_usize),
    ] {
        assert!(matches!(
            queue.push_back(value),
            HostcallQueueEnqueueResult::OverflowPath {
                depth,
                overflow_depth
            } if depth == expected_depth && overflow_depth == expected_overflow_depth
        ));
    }
    assert!(matches!(
        queue.push_back(4_u8),
        HostcallQueueEnqueueResult::Rejected {
            depth: 4,
            overflow_depth: 3
        }
    ));

    let drained = queue.drain_all();
    assert_eq!(drained.into_iter().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
}

#[test]
fn force_safe_fallback_is_idempotent_for_transition_counter() {
    let mut queue: HostcallRequestQueue<u8> =
        HostcallRequestQueue::with_mode(2, 2, HostcallQueueMode::Ebr);

    let initial = queue.snapshot();
    assert_eq!(initial.reclamation_mode, HostcallQueueMode::Ebr);
    assert_eq!(initial.fallback_transitions, 0);

    queue.force_safe_fallback();
    let first = queue.snapshot();
    assert_eq!(first.reclamation_mode, HostcallQueueMode::SafeFallback);
    assert_eq!(first.fallback_transitions, 1);

    queue.force_safe_fallback();
    let second = queue.snapshot();
    assert_eq!(second.reclamation_mode, HostcallQueueMode::SafeFallback);
    assert_eq!(second.fallback_transitions, 1);
}

#[test]
fn safe_fallback_mode_remains_operational_and_fifo() {
    let mut queue = HostcallRequestQueue::with_mode(2, 2, HostcallQueueMode::Ebr);
    assert!(matches!(
        queue.push_back(10_u8),
        HostcallQueueEnqueueResult::FastPath { .. }
    ));
    assert!(matches!(
        queue.push_back(11_u8),
        HostcallQueueEnqueueResult::FastPath { .. }
    ));

    queue.force_safe_fallback();
    let snapshot = queue.snapshot();
    assert_eq!(snapshot.reclamation_mode, HostcallQueueMode::SafeFallback);
    assert_eq!(snapshot.fallback_transitions, 1);

    let drained = queue.drain_all();
    assert_eq!(drained.into_iter().collect::<Vec<_>>(), vec![10, 11]);
}

#[test]
fn ebr_stress_run_reclaims_without_backlog_growth() {
    let mut queue = HostcallRequestQueue::with_mode(8, 32, HostcallQueueMode::Ebr);

    for value in 0..20_000_u32 {
        let _ = queue.push_back(value);
        let drained = queue.drain_all();
        assert_eq!(drained.len(), 1);
        if value % 128 == 0 {
            queue.force_reclaim();
        }
    }

    queue.force_reclaim();
    let snapshot = queue.snapshot();
    assert_eq!(snapshot.reclamation_mode, HostcallQueueMode::Ebr);
    assert_eq!(snapshot.retired_backlog, 0);
    assert!(snapshot.reclaimed_total >= 20_000);
}

#[test]
fn s3fifo_fallback_clears_ghost_and_active_tenants_until_reset() {
    let mut queue = HostcallRequestQueue::with_mode(1, 1, HostcallQueueMode::SafeFallback);

    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 0,
        }),
        HostcallQueueEnqueueResult::FastPath { .. }
    ));
    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 1,
        }),
        HostcallQueueEnqueueResult::OverflowPath { .. }
    ));
    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 2,
        }),
        HostcallQueueEnqueueResult::Rejected { .. }
    ));

    let pre_fallback = queue.snapshot();
    assert_eq!(pre_fallback.s3fifo_mode, S3FifoMode::Active);
    assert!(pre_fallback.s3fifo_ghost_depth >= 1);
    assert_eq!(pre_fallback.s3fifo_active_tenants, 1);

    for value in 3_u8..40_u8 {
        let _ = queue.push_back(TenantRequest {
            tenant: None,
            value,
        });
    }

    let fallback = queue.snapshot();
    assert_eq!(fallback.s3fifo_mode, S3FifoMode::ConservativeFifo);
    assert_eq!(
        fallback.s3fifo_fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );
    assert_eq!(fallback.s3fifo_fallback_transitions, 1);
    assert_eq!(fallback.s3fifo_ghost_depth, 0);
    assert_eq!(fallback.s3fifo_active_tenants, 0);
    let fairness_rejections_before = fallback.s3fifo_fairness_rejected_total;

    for value in 40_u8..80_u8 {
        let _ = queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value,
        });
        let _ = queue.drain_all();
    }

    let stable = queue.snapshot();
    assert_eq!(stable.s3fifo_mode, S3FifoMode::ConservativeFifo);
    assert_eq!(
        stable.s3fifo_fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );
    assert_eq!(stable.s3fifo_fallback_transitions, 1);
    assert_eq!(stable.s3fifo_ghost_depth, 0);
    assert_eq!(stable.s3fifo_active_tenants, 0);
    assert_eq!(
        stable.s3fifo_fairness_rejected_total,
        fairness_rejections_before
    );
}

#[test]
fn s3fifo_fallback_latch_does_not_mutate_ebr_pin_reclaim_accounting() {
    let mut queue = HostcallRequestQueue::with_mode(1, 1, HostcallQueueMode::Ebr);
    let pin = queue.pin_epoch();

    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 0,
        }),
        HostcallQueueEnqueueResult::FastPath { .. }
    ));
    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 1,
        }),
        HostcallQueueEnqueueResult::OverflowPath { .. }
    ));
    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 2,
        }),
        HostcallQueueEnqueueResult::Rejected { .. }
    ));

    for value in 3_u8..40_u8 {
        let _ = queue.push_back(TenantRequest {
            tenant: None,
            value,
        });
    }

    let fallback = queue.snapshot();
    assert_eq!(fallback.reclamation_mode, HostcallQueueMode::Ebr);
    assert_eq!(fallback.active_epoch_pins, 1);
    assert_eq!(fallback.s3fifo_mode, S3FifoMode::ConservativeFifo);
    assert_eq!(
        fallback.s3fifo_fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );
    assert_eq!(fallback.s3fifo_fallback_transitions, 1);

    let drained = queue.drain_all();
    assert!(!drained.is_empty());
    queue.force_reclaim();
    let pinned = queue.snapshot();
    assert_eq!(pinned.active_epoch_pins, 1);
    assert!(pinned.retired_backlog >= drained.len());
    assert_eq!(pinned.reclaimed_total, 0);
    assert_eq!(pinned.s3fifo_mode, S3FifoMode::ConservativeFifo);
    assert_eq!(pinned.s3fifo_fallback_transitions, 1);

    drop(pin);
    queue.force_reclaim();
    let reclaimed = queue.snapshot();
    assert_eq!(reclaimed.active_epoch_pins, 0);
    assert_eq!(reclaimed.retired_backlog, 0);
    assert!(reclaimed.reclaimed_total >= drained.len() as u64);
    assert_eq!(reclaimed.s3fifo_mode, S3FifoMode::ConservativeFifo);
    assert_eq!(
        reclaimed.s3fifo_fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );
    assert_eq!(reclaimed.s3fifo_fallback_transitions, 1);
}

#[test]
fn bravo_observations_do_not_perturb_latched_s3fifo_fallback_telemetry() {
    let mut queue = HostcallRequestQueue::with_mode(1, 1, HostcallQueueMode::Ebr);

    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 0,
        }),
        HostcallQueueEnqueueResult::FastPath { .. }
    ));
    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 1,
        }),
        HostcallQueueEnqueueResult::OverflowPath { .. }
    ));
    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 2,
        }),
        HostcallQueueEnqueueResult::Rejected { .. }
    ));
    for value in 3_u8..40_u8 {
        let _ = queue.push_back(TenantRequest {
            tenant: None,
            value,
        });
    }

    let fallback = queue.snapshot();
    assert_eq!(fallback.s3fifo_mode, S3FifoMode::ConservativeFifo);
    assert_eq!(
        fallback.s3fifo_fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );
    assert_eq!(fallback.s3fifo_fallback_transitions, 1);

    let read_dominant = queue.observe_contention_window(ContentionSample {
        read_acquires: 220,
        write_acquires: 10,
        read_wait_p95_us: 15,
        write_wait_p95_us: 150,
        write_timeouts: 0,
    });
    assert_eq!(read_dominant.signature, ContentionSignature::ReadDominant);

    let starvation_risk = queue.observe_contention_window(ContentionSample {
        read_acquires: 20,
        write_acquires: 80,
        read_wait_p95_us: 40,
        write_wait_p95_us: 12_000,
        write_timeouts: 3,
    });
    assert_eq!(
        starvation_risk.signature,
        ContentionSignature::WriterStarvationRisk
    );

    let post_observe = queue.snapshot();
    assert_eq!(post_observe.s3fifo_mode, fallback.s3fifo_mode);
    assert_eq!(
        post_observe.s3fifo_fallback_reason,
        fallback.s3fifo_fallback_reason
    );
    assert_eq!(
        post_observe.s3fifo_fallback_transitions,
        fallback.s3fifo_fallback_transitions
    );
    assert_eq!(post_observe.s3fifo_ghost_depth, fallback.s3fifo_ghost_depth);
    assert_eq!(
        post_observe.s3fifo_active_tenants,
        fallback.s3fifo_active_tenants
    );

    assert_eq!(
        post_observe.bravo_last_signature,
        ContentionSignature::WriterStarvationRisk
    );
    assert!(post_observe.bravo_transitions >= fallback.bravo_transitions);
}

#[test]
fn latched_s3fifo_fallback_freezes_signal_and_fairness_counters_under_queue_activity() {
    let mut queue = HostcallRequestQueue::with_mode(1, 1, HostcallQueueMode::Ebr);

    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 0,
        }),
        HostcallQueueEnqueueResult::FastPath { .. }
    ));
    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 1,
        }),
        HostcallQueueEnqueueResult::OverflowPath { .. }
    ));
    assert!(matches!(
        queue.push_back(TenantRequest {
            tenant: Some("ext.noisy"),
            value: 2,
        }),
        HostcallQueueEnqueueResult::Rejected { .. }
    ));

    for value in 3_u8..40_u8 {
        let _ = queue.push_back(TenantRequest {
            tenant: None,
            value,
        });
    }

    let fallback = queue.snapshot();
    assert_eq!(fallback.s3fifo_mode, S3FifoMode::ConservativeFifo);
    assert_eq!(
        fallback.s3fifo_fallback_reason,
        Some(S3FifoFallbackReason::FairnessInstability)
    );
    assert_eq!(fallback.s3fifo_fallback_transitions, 1);

    let frozen_fairness_rejections = fallback.s3fifo_fairness_rejected_total;
    let frozen_ghost_hits = fallback.s3fifo_ghost_hits_total;
    let frozen_signal_samples = fallback.s3fifo_signal_samples;
    let frozen_signalless_streak = fallback.s3fifo_signalless_streak;
    let frozen_active_tenants = fallback.s3fifo_active_tenants;
    let frozen_ghost_depth = fallback.s3fifo_ghost_depth;

    for value in 40_u8..100_u8 {
        let tenant = if value % 2 == 0 {
            Some("ext.noisy")
        } else {
            None
        };
        let _ = queue.push_back(TenantRequest { tenant, value });
        let _ = queue.drain_all();
    }

    let stable = queue.snapshot();
    assert_eq!(stable.s3fifo_mode, S3FifoMode::ConservativeFifo);
    assert_eq!(
        stable.s3fifo_fallback_reason,
        fallback.s3fifo_fallback_reason
    );
    assert_eq!(stable.s3fifo_fallback_transitions, 1);
    assert_eq!(
        stable.s3fifo_fairness_rejected_total,
        frozen_fairness_rejections
    );
    assert_eq!(stable.s3fifo_ghost_hits_total, frozen_ghost_hits);
    assert_eq!(stable.s3fifo_signal_samples, frozen_signal_samples);
    assert_eq!(stable.s3fifo_signalless_streak, frozen_signalless_streak);
    assert_eq!(stable.s3fifo_active_tenants, frozen_active_tenants);
    assert_eq!(stable.s3fifo_ghost_depth, frozen_ghost_depth);
}

#[test]
fn ebr_bravo_writer_recovery_window_stays_bounded_and_exits_without_stale_counter() {
    let mut queue = HostcallRequestQueue::<u8>::with_mode(4, 4, HostcallQueueMode::Ebr);

    let first = queue.observe_contention_window(starvation_sample());
    assert_eq!(first.signature, ContentionSignature::WriterStarvationRisk);

    let after_first = queue.snapshot();
    assert_eq!(after_first.bravo_mode, BravoBiasMode::WriterRecovery);
    assert!(after_first.bravo_rollbacks >= 1);
    assert!(
        after_first.bravo_writer_recovery_remaining <= 2,
        "writer recovery window must be bounded by config default (2)"
    );

    let second = queue.observe_contention_window(starvation_sample());
    assert_eq!(second.signature, ContentionSignature::WriterStarvationRisk);

    let after_second = queue.snapshot();
    assert_eq!(after_second.bravo_mode, BravoBiasMode::WriterRecovery);
    assert!(after_second.bravo_writer_recovery_remaining <= 2);
    assert!(
        after_second.bravo_writer_recovery_remaining >= after_first.bravo_writer_recovery_remaining
    );

    for _ in 0..4 {
        let decision = queue.observe_contention_window(write_dominant_sample());
        assert_eq!(decision.signature, ContentionSignature::WriteDominant);
    }

    let stable = queue.snapshot();
    assert_eq!(stable.bravo_mode, BravoBiasMode::Balanced);
    assert_eq!(stable.bravo_writer_recovery_remaining, 0);
    assert_eq!(
        stable.bravo_last_signature,
        ContentionSignature::WriteDominant
    );
    assert!(stable.bravo_transitions > after_second.bravo_transitions);
}
