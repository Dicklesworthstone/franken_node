use crate::capacity_defaults::aliases::{
    MAX_BULKHEAD_EVENTS, MAX_EVENTS, MAX_LEASES, MAX_SESSION_EVENTS,
};
use crate::observability::metrics::{MetricValidationError, MetricsRegistry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const RESOURCE_ADMISSION_SCHEMA_VERSION: &str = "franken-node/resource-admission/v1";
pub const RESOURCE_ADMISSION_BEAD_ID: &str = "bd-w7tx8";

pub const RA_ADMIT_WITHIN_BUDGET: &str = "RA_ADMIT_WITHIN_BUDGET";
pub const RA_DEFER_CPU_SLOTS_EXHAUSTED: &str = "RA_DEFER_CPU_SLOTS_EXHAUSTED";
pub const RA_SHED_QUEUE_DEPTH_EXCEEDED: &str = "RA_SHED_QUEUE_DEPTH_EXCEEDED";
pub const RA_REJECT_MEMORY_BUDGET_EXCEEDED: &str = "RA_REJECT_MEMORY_BUDGET_EXCEEDED";
pub const RA_REJECT_IO_LEASES_EXHAUSTED: &str = "RA_REJECT_IO_LEASES_EXHAUSTED";
pub const RA_REJECT_DEADLINE_TOO_SHORT: &str = "RA_REJECT_DEADLINE_TOO_SHORT";
pub const RA_REJECT_INVALID_REQUEST: &str = "RA_REJECT_INVALID_REQUEST";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionWorkClass {
    ControlPlaneLane,
    FleetReconciliation,
    EvidenceAppendExport,
    ReplayIncidentGeneration,
    RemoteComputationDispatch,
    BenchmarkPerfWork,
    ExternalCommandHelper,
}

impl AdmissionWorkClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControlPlaneLane => "control_plane_lane",
            Self::FleetReconciliation => "fleet_reconciliation",
            Self::EvidenceAppendExport => "evidence_append_export",
            Self::ReplayIncidentGeneration => "replay_incident_generation",
            Self::RemoteComputationDispatch => "remote_computation_dispatch",
            Self::BenchmarkPerfWork => "benchmark_perf_work",
            Self::ExternalCommandHelper => "external_command_helper",
        }
    }

    pub fn recovery_hint(self) -> &'static str {
        match self {
            Self::ControlPlaneLane => {
                "Reduce lane fan-out or wait for active control work to drain."
            }
            Self::FleetReconciliation => {
                "Reduce concurrent fleet reconcile batches or widen the reconcile deadline."
            }
            Self::EvidenceAppendExport => {
                "Drain evidence exporters or increase the evidence I/O lease budget."
            }
            Self::ReplayIncidentGeneration => {
                "Run replay or incident generation after queued evidence work completes."
            }
            Self::RemoteComputationDispatch => {
                "Reduce remote dispatch concurrency or move the computation to a healthier node."
            }
            Self::BenchmarkPerfWork => "Defer benchmark/perf work until the node is not saturated.",
            Self::ExternalCommandHelper => {
                "Throttle external command helpers before starting another process."
            }
        }
    }
}

pub fn resource_admission_work_class_inventory() -> Vec<AdmissionWorkClass> {
    vec![
        AdmissionWorkClass::ControlPlaneLane,
        AdmissionWorkClass::FleetReconciliation,
        AdmissionWorkClass::EvidenceAppendExport,
        AdmissionWorkClass::ReplayIncidentGeneration,
        AdmissionWorkClass::RemoteComputationDispatch,
        AdmissionWorkClass::BenchmarkPerfWork,
        AdmissionWorkClass::ExternalCommandHelper,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    Admit,
    Defer,
    Shed,
    Reject,
}

impl AdmissionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Defer => "defer",
            Self::Shed => "shed",
            Self::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub max_cpu_slots: u32,
    pub max_memory_bytes: u64,
    pub max_io_leases: u32,
    pub max_queue_depth: u32,
    pub min_deadline_ms: u64,
}

impl ResourceBudget {
    pub fn swarm_default() -> Self {
        Self {
            max_cpu_slots: 8,
            max_memory_bytes: 512 * 1024 * 1024,
            max_io_leases: clamp_usize_to_u32(MAX_LEASES),
            max_queue_depth: clamp_usize_to_u32(MAX_BULKHEAD_EVENTS),
            min_deadline_ms: 250,
        }
    }

    pub fn evidence_default() -> Self {
        Self {
            max_cpu_slots: 4,
            max_memory_bytes: 128 * 1024 * 1024,
            max_io_leases: 4,
            max_queue_depth: clamp_usize_to_u32(MAX_EVENTS.min(MAX_SESSION_EVENTS)),
            min_deadline_ms: 500,
        }
    }
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self::swarm_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub active_cpu_slots: u32,
    pub committed_memory_bytes: u64,
    pub active_io_leases: u32,
    pub queued_work: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceAdmissionRequest {
    pub work_class: AdmissionWorkClass,
    pub cpu_slots: u32,
    pub memory_bytes: u64,
    pub io_leases: u32,
    pub queue_depth: u32,
    pub deadline_ms: u64,
    pub trace_id: String,
}

impl ResourceAdmissionRequest {
    pub fn new(work_class: AdmissionWorkClass, trace_id: impl Into<String>) -> Self {
        let (cpu_slots, memory_bytes, io_leases, queue_depth, deadline_ms) = match work_class {
            AdmissionWorkClass::ControlPlaneLane => (1, 8 * 1024 * 1024, 1, 1, 1_000),
            AdmissionWorkClass::FleetReconciliation => (2, 16 * 1024 * 1024, 1, 2, 2_000),
            AdmissionWorkClass::EvidenceAppendExport => (1, 32 * 1024 * 1024, 2, 1, 2_500),
            AdmissionWorkClass::ReplayIncidentGeneration => (2, 64 * 1024 * 1024, 2, 2, 5_000),
            AdmissionWorkClass::RemoteComputationDispatch => (2, 24 * 1024 * 1024, 1, 2, 2_000),
            AdmissionWorkClass::BenchmarkPerfWork => (4, 128 * 1024 * 1024, 1, 4, 10_000),
            AdmissionWorkClass::ExternalCommandHelper => (1, 12 * 1024 * 1024, 1, 1, 1_500),
        };

        Self {
            work_class,
            cpu_slots,
            memory_bytes,
            io_leases,
            queue_depth,
            deadline_ms,
            trace_id: trace_id.into(),
        }
    }

    pub fn with_cpu_slots(mut self, cpu_slots: u32) -> Self {
        self.cpu_slots = cpu_slots;
        self
    }

    pub fn with_memory_bytes(mut self, memory_bytes: u64) -> Self {
        self.memory_bytes = memory_bytes;
        self
    }

    pub fn with_io_leases(mut self, io_leases: u32) -> Self {
        self.io_leases = io_leases;
        self
    }

    pub fn with_queue_depth(mut self, queue_depth: u32) -> Self {
        self.queue_depth = queue_depth;
        self
    }

    pub fn with_deadline_ms(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = deadline_ms;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionOutcome {
    pub work_class: AdmissionWorkClass,
    pub decision: AdmissionDecision,
    pub reason_code: String,
    pub recovery_hint: String,
    pub trace_id: String,
    pub usage_before: ResourceUsage,
    pub budget: ResourceBudget,
}

impl AdmissionOutcome {
    pub fn admitted(&self) -> bool {
        self.decision == AdmissionDecision::Admit
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AdmissionDecisionCounts {
    pub admitted: u64,
    pub deferred: u64,
    pub shed: u64,
    pub rejected: u64,
}

impl AdmissionDecisionCounts {
    pub fn record(&mut self, decision: AdmissionDecision) {
        match decision {
            AdmissionDecision::Admit => self.admitted = self.admitted.saturating_add(1),
            AdmissionDecision::Defer => self.deferred = self.deferred.saturating_add(1),
            AdmissionDecision::Shed => self.shed = self.shed.saturating_add(1),
            AdmissionDecision::Reject => self.rejected = self.rejected.saturating_add(1),
        }
    }

    pub fn total(&self) -> u64 {
        self.admitted
            .saturating_add(self.deferred)
            .saturating_add(self.shed)
            .saturating_add(self.rejected)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionTelemetrySnapshot {
    pub schema_version: String,
    pub bead_id: String,
    pub total: AdmissionDecisionCounts,
    pub by_work_class: BTreeMap<String, AdmissionDecisionCounts>,
}

impl Default for AdmissionTelemetrySnapshot {
    fn default() -> Self {
        Self::new(AdmissionDecisionCounts::default(), BTreeMap::new())
    }
}

impl AdmissionTelemetrySnapshot {
    pub fn new(
        total: AdmissionDecisionCounts,
        by_work_class: BTreeMap<String, AdmissionDecisionCounts>,
    ) -> Self {
        Self {
            schema_version: RESOURCE_ADMISSION_SCHEMA_VERSION.to_string(),
            bead_id: RESOURCE_ADMISSION_BEAD_ID.to_string(),
            total,
            by_work_class,
        }
    }

    pub fn readiness_reason_code(&self) -> &'static str {
        if self.total.rejected > 0 {
            RA_REJECT_MEMORY_BUDGET_EXCEEDED
        } else if self.total.shed > 0 {
            RA_SHED_QUEUE_DEPTH_EXCEEDED
        } else if self.total.deferred > 0 {
            RA_DEFER_CPU_SLOTS_EXHAUSTED
        } else {
            RA_ADMIT_WITHIN_BUDGET
        }
    }

    pub fn readiness_hint(&self) -> &'static str {
        if self.total.rejected > 0 {
            "The node is rejecting new over-budget work before mutation; reduce load or raise resource budgets."
        } else if self.total.shed > 0 {
            "The node is shedding queued work; drain queues before adding batch workloads."
        } else if self.total.deferred > 0 {
            "The node is deferring work; wait for active CPU slots to drain."
        } else {
            "Resource admission is within budget."
        }
    }

    pub fn record_observability_metrics(
        &self,
        registry: &mut MetricsRegistry,
    ) -> Result<(), MetricValidationError> {
        let totals = [
            (AdmissionDecision::Admit, self.total.admitted),
            (AdmissionDecision::Defer, self.total.deferred),
            (AdmissionDecision::Shed, self.total.shed),
            (AdmissionDecision::Reject, self.total.rejected),
        ];
        for (decision, value) in totals {
            registry.record_counter(
                "franken_node_resource_admission_decisions_total",
                "Resource admission decisions by outcome.",
                value as f64,
                &[("decision", decision.as_str())],
            )?;
        }

        for (work_class, counts) in &self.by_work_class {
            let per_class = [
                (AdmissionDecision::Admit, counts.admitted),
                (AdmissionDecision::Defer, counts.deferred),
                (AdmissionDecision::Shed, counts.shed),
                (AdmissionDecision::Reject, counts.rejected),
            ];
            for (decision, value) in per_class {
                registry.record_counter(
                    "franken_node_resource_admission_work_class_decisions_total",
                    "Resource admission decisions by work class and outcome.",
                    value as f64,
                    &[
                        ("work_class", work_class.as_str()),
                        ("decision", decision.as_str()),
                    ],
                )?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAdmissionEvidenceCase {
    pub name: String,
    pub work_class: AdmissionWorkClass,
    pub expected_decision: AdmissionDecision,
    pub observed_decision: AdmissionDecision,
    pub reason_code: String,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAdmissionEvidenceReport {
    pub schema_version: String,
    pub bead_id: String,
    pub verdict: String,
    pub work_class_inventory: Vec<AdmissionWorkClass>,
    pub representative_admission_path_work_classes: Vec<AdmissionWorkClass>,
    pub budget: ResourceBudget,
    pub cases: Vec<ResourceAdmissionEvidenceCase>,
    pub admission_counts: AdmissionDecisionCounts,
    pub observability_metric_names: Vec<String>,
    pub readiness_reason_code: String,
    pub readiness_recovery_hint: String,
}

pub struct AdmissionController {
    budget: ResourceBudget,
    usage: ResourceUsage,
    counters: AdmissionDecisionCounts,
    by_work_class: BTreeMap<String, AdmissionDecisionCounts>,
}

impl AdmissionController {
    pub fn new(budget: ResourceBudget) -> Self {
        Self::with_usage(budget, ResourceUsage::default())
    }

    pub fn with_usage(budget: ResourceBudget, usage: ResourceUsage) -> Self {
        Self {
            budget,
            usage,
            counters: AdmissionDecisionCounts::default(),
            by_work_class: BTreeMap::new(),
        }
    }

    pub fn budget(&self) -> &ResourceBudget {
        &self.budget
    }

    pub fn usage(&self) -> &ResourceUsage {
        &self.usage
    }

    pub fn dry_run(&self, request: &ResourceAdmissionRequest) -> AdmissionOutcome {
        let (decision, reason_code, recovery_hint) = self.evaluate(request);
        AdmissionOutcome {
            work_class: request.work_class,
            decision,
            reason_code: reason_code.to_string(),
            recovery_hint: recovery_hint.to_string(),
            trace_id: request.trace_id.clone(),
            usage_before: self.usage.clone(),
            budget: self.budget.clone(),
        }
    }

    pub fn admit(&mut self, request: &ResourceAdmissionRequest) -> AdmissionOutcome {
        let outcome = self.dry_run(request);
        self.record_outcome(&outcome);
        if outcome.admitted() {
            self.usage.active_cpu_slots = self
                .usage
                .active_cpu_slots
                .saturating_add(request.cpu_slots);
            self.usage.committed_memory_bytes = self
                .usage
                .committed_memory_bytes
                .saturating_add(request.memory_bytes);
            self.usage.active_io_leases = self
                .usage
                .active_io_leases
                .saturating_add(request.io_leases);
            self.usage.queued_work = self.usage.queued_work.saturating_add(request.queue_depth);
        }
        outcome
    }

    pub fn complete(&mut self, request: &ResourceAdmissionRequest) {
        self.usage.active_cpu_slots = self
            .usage
            .active_cpu_slots
            .saturating_sub(request.cpu_slots);
        self.usage.committed_memory_bytes = self
            .usage
            .committed_memory_bytes
            .saturating_sub(request.memory_bytes);
        self.usage.active_io_leases = self
            .usage
            .active_io_leases
            .saturating_sub(request.io_leases);
        self.usage.queued_work = self.usage.queued_work.saturating_sub(request.queue_depth);
    }

    pub fn run_if_admitted<T>(
        &mut self,
        request: &ResourceAdmissionRequest,
        expensive_work: impl FnOnce() -> T,
    ) -> Result<(AdmissionOutcome, T), AdmissionOutcome> {
        let outcome = self.admit(request);
        if outcome.admitted() {
            let result = expensive_work();
            Ok((outcome, result))
        } else {
            Err(outcome)
        }
    }

    pub fn telemetry_snapshot(&self) -> AdmissionTelemetrySnapshot {
        AdmissionTelemetrySnapshot::new(self.counters.clone(), self.by_work_class.clone())
    }

    fn record_outcome(&mut self, outcome: &AdmissionOutcome) {
        self.counters.record(outcome.decision);
        self.by_work_class
            .entry(outcome.work_class.as_str().to_string())
            .or_default()
            .record(outcome.decision);
    }

    fn evaluate(
        &self,
        request: &ResourceAdmissionRequest,
    ) -> (AdmissionDecision, &'static str, &'static str) {
        if request.cpu_slots == 0
            && request.memory_bytes == 0
            && request.io_leases == 0
            && request.queue_depth == 0
        {
            return (
                AdmissionDecision::Reject,
                RA_REJECT_INVALID_REQUEST,
                "Requests must declare at least one bounded resource before admission.",
            );
        }

        if request.deadline_ms < self.budget.min_deadline_ms {
            return (
                AdmissionDecision::Reject,
                RA_REJECT_DEADLINE_TOO_SHORT,
                "Increase the work deadline or move the request to a faster node.",
            );
        }

        if self
            .usage
            .committed_memory_bytes
            .saturating_add(request.memory_bytes)
            > self.budget.max_memory_bytes
        {
            return (
                AdmissionDecision::Reject,
                RA_REJECT_MEMORY_BUDGET_EXCEEDED,
                "Reduce request memory or wait for memory-heavy work to complete.",
            );
        }

        if self
            .usage
            .active_io_leases
            .saturating_add(request.io_leases)
            > self.budget.max_io_leases
        {
            return (
                AdmissionDecision::Reject,
                RA_REJECT_IO_LEASES_EXHAUSTED,
                request.work_class.recovery_hint(),
            );
        }

        if self.usage.queued_work.saturating_add(request.queue_depth) > self.budget.max_queue_depth
        {
            return (
                AdmissionDecision::Shed,
                RA_SHED_QUEUE_DEPTH_EXCEEDED,
                "Drain queued work or shrink the batch before retrying.",
            );
        }

        if self
            .usage
            .active_cpu_slots
            .saturating_add(request.cpu_slots)
            > self.budget.max_cpu_slots
        {
            return (
                AdmissionDecision::Defer,
                RA_DEFER_CPU_SLOTS_EXHAUSTED,
                request.work_class.recovery_hint(),
            );
        }

        (
            AdmissionDecision::Admit,
            RA_ADMIT_WITHIN_BUDGET,
            "Resource admission is within budget.",
        )
    }
}

pub fn representative_admission_path_requests() -> Vec<ResourceAdmissionRequest> {
    vec![
        ResourceAdmissionRequest::new(
            AdmissionWorkClass::ControlPlaneLane,
            "trace-resource-admission-control-plane",
        ),
        ResourceAdmissionRequest::new(
            AdmissionWorkClass::EvidenceAppendExport,
            "trace-resource-admission-evidence",
        ),
        ResourceAdmissionRequest::new(
            AdmissionWorkClass::ReplayIncidentGeneration,
            "trace-resource-admission-replay",
        ),
        ResourceAdmissionRequest::new(
            AdmissionWorkClass::RemoteComputationDispatch,
            "trace-resource-admission-remote-dispatch",
        ),
    ]
}

pub fn default_resource_admission_evidence_report() -> ResourceAdmissionEvidenceReport {
    let budget = ResourceBudget {
        max_cpu_slots: 2,
        max_memory_bytes: 256,
        max_io_leases: 2,
        max_queue_depth: 3,
        min_deadline_ms: 100,
    };

    let cases = vec![
        evidence_case(
            "admit_control_plane_lane",
            budget.clone(),
            ResourceUsage::default(),
            ResourceAdmissionRequest::new(
                AdmissionWorkClass::ControlPlaneLane,
                "trace-resource-admission-admit",
            )
            .with_memory_bytes(64),
            AdmissionDecision::Admit,
        ),
        evidence_case(
            "defer_remote_dispatch_cpu",
            budget.clone(),
            ResourceUsage {
                active_cpu_slots: 2,
                ..ResourceUsage::default()
            },
            ResourceAdmissionRequest::new(
                AdmissionWorkClass::RemoteComputationDispatch,
                "trace-resource-admission-defer",
            )
            .with_memory_bytes(64),
            AdmissionDecision::Defer,
        ),
        evidence_case(
            "shed_replay_queue",
            budget.clone(),
            ResourceUsage {
                queued_work: 3,
                ..ResourceUsage::default()
            },
            ResourceAdmissionRequest::new(
                AdmissionWorkClass::ReplayIncidentGeneration,
                "trace-resource-admission-shed",
            )
            .with_memory_bytes(64),
            AdmissionDecision::Shed,
        ),
        evidence_case(
            "reject_evidence_memory",
            budget.clone(),
            ResourceUsage::default(),
            ResourceAdmissionRequest::new(
                AdmissionWorkClass::EvidenceAppendExport,
                "trace-resource-admission-reject-memory",
            )
            .with_memory_bytes(512),
            AdmissionDecision::Reject,
        ),
    ];

    let mut counts = AdmissionDecisionCounts::default();
    for case in &cases {
        counts.record(case.observed_decision);
    }
    let snapshot = AdmissionTelemetrySnapshot::new(counts.clone(), BTreeMap::new());

    ResourceAdmissionEvidenceReport {
        schema_version: RESOURCE_ADMISSION_SCHEMA_VERSION.to_string(),
        bead_id: RESOURCE_ADMISSION_BEAD_ID.to_string(),
        verdict: if cases.iter().all(|case| case.pass) {
            "PASS".to_string()
        } else {
            "FAIL".to_string()
        },
        work_class_inventory: resource_admission_work_class_inventory(),
        representative_admission_path_work_classes: representative_admission_path_requests()
            .into_iter()
            .map(|request| request.work_class)
            .collect(),
        budget,
        cases,
        admission_counts: counts,
        observability_metric_names: vec![
            "franken_node_resource_admission_decisions_total".to_string(),
            "franken_node_resource_admission_work_class_decisions_total".to_string(),
        ],
        readiness_reason_code: snapshot.readiness_reason_code().to_string(),
        readiness_recovery_hint: snapshot.readiness_hint().to_string(),
    }
}

fn evidence_case(
    name: &str,
    budget: ResourceBudget,
    usage: ResourceUsage,
    request: ResourceAdmissionRequest,
    expected_decision: AdmissionDecision,
) -> ResourceAdmissionEvidenceCase {
    let controller = AdmissionController::with_usage(budget, usage);
    let outcome = controller.dry_run(&request);
    ResourceAdmissionEvidenceCase {
        name: name.to_string(),
        work_class: request.work_class,
        expected_decision,
        observed_decision: outcome.decision,
        reason_code: outcome.reason_code,
        pass: outcome.decision == expected_decision,
    }
}

fn clamp_usize_to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
