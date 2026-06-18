//! Operator-facing validation readiness reporting.
//!
//! This module aggregates validation-broker receipts, proof statuses, Beads
//! state, worker observations, and resource-governor hints into a stable report
//! that explains whether validation evidence is trustworthy right now.

use crate::ops::swarm_validation_admission::{
    SwarmValidationAdmissionDecision, SwarmValidationAdmissionDecisionRecord,
    SwarmValidationTargetDirStrategy, SwarmValidationWorkerRequirement,
};
use crate::ops::validation_broker::{
    DigestRef, FlightRecorderAdapterOutcomeClass, ProofEvidenceSource, ProofStatusKind, RchMode,
    SourceOnlyReason, TimeoutClass, ValidationErrorClass, ValidationExit, ValidationExitKind,
    ValidationProofStatus, ValidationReceipt,
};
use crate::ops::validation_proof_coalescer::{
    ValidationSwarmSchedulerDecision, ValidationSwarmSchedulerDecisionKind,
    ValidationSwarmSchedulerProofDebtClass,
};
use crate::ops::validation_recovery_planner::{RecoveryAction, reason_codes};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

pub const VALIDATION_READINESS_INPUT_SCHEMA_VERSION: &str =
    "franken-node/validation-readiness/input/v1";
pub const VALIDATION_READINESS_REPORT_SCHEMA_VERSION: &str =
    "franken-node/validation-readiness/report/v1";
pub const VALIDATION_HANDOFF_SUMMARY_SCHEMA_VERSION: &str =
    "franken-node/validation-handoff-summary/report/v1";
pub const VALIDATION_SWARM_PERFORMANCE_EVIDENCE_SCHEMA_VERSION: &str =
    "franken-node/validation-swarm-performance/evidence/v1";
pub const VALIDATION_SWARM_ADMISSION_READINESS_SCHEMA_VERSION: &str =
    "franken-node/validation-swarm-admission/readiness/v1";
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
pub const MAX_VALIDATION_HANDOFF_ROWS: usize = 128;
pub const MAX_VALIDATION_HANDOFF_FIELD_BYTES: usize = 512;
pub const MAX_VALIDATION_SWARM_PERFORMANCE_OUTPUT_BYTES: usize = 512 * 1024;
pub const MAX_VALIDATION_SWARM_PERFORMANCE_UNIQUE_WORK_KEYS: usize = 16;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub proof_lane_readiness: Vec<ProofLaneReadinessCapsule>,
    #[serde(default)]
    pub swarm_scheduler_decisions: Vec<ValidationSwarmSchedulerDecision>,
    #[serde(default)]
    pub swarm_admission_decisions: Vec<SwarmValidationAdmissionDecisionRecord>,
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
            proof_lane_readiness: Vec::new(),
            swarm_scheduler_decisions: Vec::new(),
            swarm_admission_decisions: Vec::new(),
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

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCoalescerCounts {
    pub producer_proofs: usize,
    pub waiters: usize,
    pub stale_leases: usize,
    pub fenced_leases: usize,
    pub capacity_rejections: usize,
    pub cache_handoffs: usize,
    pub rejected: usize,
}

impl ProofCoalescerCounts {
    fn active_work(&self) -> usize {
        self.producer_proofs.saturating_add(self.waiters)
    }
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

impl ProofLaneReadinessDecisionKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadyToLaunch => "ready_to_launch",
            Self::QueueUntilReady => "queue_until_ready",
            Self::RetryPreflight => "retry_preflight",
            Self::SourceOnlyBlocker => "source_only_blocker",
            Self::FailClosed => "fail_closed",
        }
    }
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
    #[serde(default)]
    pub capsule_path: Option<String>,
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
pub struct ProofLaneReadinessSummary {
    pub capsule_id: String,
    pub capsule_path: Option<String>,
    pub trace_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub decision: ProofLaneReadinessDecisionKind,
    pub reason_code: String,
    pub event_code: String,
    pub requested_worker: String,
    pub selected_worker: Option<String>,
    pub same_toolchain_available: bool,
    pub auth_status: ProofLaneWorkerAuthStatus,
    pub capability_freshness: ProofLaneCapabilityStatus,
    pub pressure_status: ProofLanePressureStatus,
    pub local_fallback_allowed: bool,
    pub local_fallback_refused: bool,
    pub retryable: bool,
    pub fail_closed: bool,
    pub created_at: DateTime<Utc>,
    pub freshness_expires_at: DateTime<Utc>,
    pub required_action: String,
    pub operator_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedAttemptSummary {
    pub bead_id: String,
    pub thread_id: String,
    pub flight_recorder_path: Option<String>,
    pub outcome_class: String,
    pub execution_mode: String,
    pub worker_id: Option<String>,
    pub reason_code: String,
    pub retryable: bool,
    pub product_failure: bool,
    pub last_attempt_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPlanSummary {
    pub bead_id: String,
    pub thread_id: String,
    pub action: String,
    pub reason_code: String,
    pub required_action: String,
    pub retry_after_ms: Option<u64>,
    pub worker_preference: Option<String>,
    pub fail_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmSchedulerReadinessSummary {
    pub decisions: usize,
    pub queue_age_p95_ms: u64,
    pub queue_age_max_ms: u64,
    pub slot_utilization: f64,
    pub fairness_index: f64,
    pub slo_breach_status: SwarmSchedulerSloBreachStatus,
    pub breached_decisions: usize,
    pub capacity_waits: usize,
    pub work_steals: usize,
    pub source_only_blockers: usize,
    pub product_failures: usize,
    pub worker_infra_retries: usize,
    #[serde(default)]
    pub decision_details: Vec<SwarmSchedulerDecisionSummary>,
}

impl Default for SwarmSchedulerReadinessSummary {
    fn default() -> Self {
        Self {
            decisions: 0,
            queue_age_p95_ms: 0,
            queue_age_max_ms: 0,
            slot_utilization: 0.0,
            fairness_index: 1.0,
            slo_breach_status: SwarmSchedulerSloBreachStatus::NoData,
            breached_decisions: 0,
            capacity_waits: 0,
            work_steals: 0,
            source_only_blockers: 0,
            product_failures: 0,
            worker_infra_retries: 0,
            decision_details: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmSchedulerSloBreachStatus {
    NoData,
    Pass,
    Warn,
    Breach,
}

impl SwarmSchedulerSloBreachStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoData => "no_data",
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Breach => "breach",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmSchedulerDecisionSummary {
    pub trace_id: String,
    pub bead_id: String,
    pub agent: String,
    pub proof_work_key: String,
    pub scheduler_decision: String,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
    pub next_action: String,
    pub fairness_bucket: String,
    pub starvation_risk: String,
    pub queue_age_ms: u64,
    pub worker_id: Option<String>,
    pub coalescer_state: String,
    pub recorder_path: Option<String>,
    pub slo_breached: bool,
    pub retryable: bool,
    pub fail_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAdmissionDecisionSummary {
    pub trace_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub agent: String,
    pub decision: String,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
    pub next_action: String,
    pub input_fresh: bool,
    pub proof_work_key: Option<String>,
    pub command_digest: Option<String>,
    pub owner_agent: Option<String>,
    pub safe_command_shape: Option<String>,
    pub target_dir_strategy: String,
    pub target_dir: Option<String>,
    pub worker_requirement: String,
    pub max_parallel_rch_jobs: u16,
    pub retry_after_ms: Option<u64>,
    pub green_proof_eligible: bool,
    pub retryable: bool,
    pub fail_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAdmissionReadinessSummary {
    pub schema_version: String,
    pub decisions: usize,
    pub run: usize,
    pub coalesce: usize,
    pub defer: usize,
    pub handoff: usize,
    pub blocked: usize,
    pub stale_inputs: usize,
    pub fail_closed: usize,
    pub green_proof_eligible: usize,
    pub rch_jobs_budgeted: u16,
    #[serde(default)]
    pub decision_details: Vec<SwarmAdmissionDecisionSummary>,
}

impl Default for SwarmAdmissionReadinessSummary {
    fn default() -> Self {
        Self {
            schema_version: VALIDATION_SWARM_ADMISSION_READINESS_SCHEMA_VERSION.to_string(),
            decisions: 0,
            run: 0,
            coalesce: 0,
            defer: 0,
            handoff: 0,
            blocked: 0,
            stale_inputs: 0,
            fail_closed: 0,
            green_proof_eligible: 0,
            rch_jobs_budgeted: 0,
            decision_details: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationControlTowerSummary {
    pub rows: usize,
    pub green_proofs: usize,
    pub wait_or_join: usize,
    pub source_only_blockers: usize,
    pub worker_infrastructure: usize,
    pub product_failures: usize,
    pub invalid_artifacts: usize,
    pub stale_leases: usize,
    pub no_known_proofs: usize,
    pub capacity_waits: usize,
    #[serde(default)]
    pub entries: Vec<ValidationControlTowerRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationControlTowerRow {
    pub bead_id: String,
    pub agent_name: String,
    pub decision: String,
    pub scheduler_decision: Option<String>,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
    pub next_action: String,
    pub proof_source: String,
    pub proof_debt_class: String,
    pub fairness_bucket: String,
    pub stale_risk: String,
    pub proof_work_key: Option<String>,
    pub command_digest: Option<String>,
    pub coalescer_state: String,
    pub green_proof_eligible: bool,
    pub recorder_path: Option<String>,
    pub recovery_artifact_path: Option<String>,
    pub latest_artifact_path: Option<String>,
    pub rch_slots_total: Option<u16>,
    pub rch_slots_available: Option<u16>,
    pub rch_queue_depth: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationReadinessSummary {
    pub tracked_beads: usize,
    pub receipts: usize,
    pub proof_statuses: usize,
    pub proof_counts: ProofKindCounts,
    pub proof_coalescer: ProofCoalescerCounts,
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
    #[serde(default)]
    pub proof_lane_readiness: Vec<ProofLaneReadinessSummary>,
    #[serde(default)]
    pub swarm_scheduler: SwarmSchedulerReadinessSummary,
    #[serde(default)]
    pub swarm_admission: SwarmAdmissionReadinessSummary,
    #[serde(default)]
    pub control_tower: ValidationControlTowerSummary,
    #[serde(default)]
    pub flight_recorder_refs: usize,
    #[serde(default)]
    pub failed_attempt_details: Vec<FailedAttemptSummary>,
    #[serde(default)]
    pub pending_recoveries: Vec<RecoveryPlanSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationHandoffReport {
    pub schema_version: String,
    pub command: String,
    pub trace_id: String,
    pub generated_at_utc: DateTime<Utc>,
    pub readiness_status: ValidationReadinessStatus,
    pub rows: usize,
    pub truncated: bool,
    pub entries: Vec<ValidationHandoffEntry>,
    pub br_comment_markdown: String,
    pub agent_mail_markdown: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationHandoffEntry {
    pub bead_id: String,
    pub thread_id: String,
    pub agent_name: String,
    pub decision: String,
    pub scheduler_decision: Option<String>,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
    pub next_action: String,
    pub proof_source: String,
    pub proof_debt_class: String,
    pub proof_work_key: Option<String>,
    pub command_digest: Option<String>,
    pub recorder_path: Option<String>,
    pub recovery_artifact_path: Option<String>,
    pub latest_artifact_path: Option<String>,
    pub rch_slots_total: Option<u16>,
    pub rch_slots_available: Option<u16>,
    pub rch_queue_depth: Option<u16>,
    pub green_closeout_allowed: bool,
    pub cargo_launch_allowed: bool,
    pub cargo_action: String,
    pub fail_closed: bool,
    pub field_errors: Vec<String>,
    pub recovery_action: Option<String>,
    pub recovery_required_action: Option<String>,
    pub retry_after_ms: Option<u64>,
    pub worker_preference: Option<String>,
    pub flight_recorder_path: Option<String>,
    pub markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationSwarmPerformanceInputCase {
    pub case_id: String,
    pub equivalent_requests: usize,
    pub configured_waiter_cap: usize,
    pub linked_bead_ids: Vec<String>,
    pub decisions: Vec<ValidationSwarmSchedulerDecision>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationSwarmPerformanceEvidence {
    pub schema_version: String,
    pub command: String,
    pub trace_id: String,
    pub generated_at_utc: DateTime<Utc>,
    pub fixture_mode: String,
    pub optional_heavy_benchmark: ValidationSwarmPerformanceBenchmarkInstructions,
    pub linked_bead_ids: Vec<String>,
    pub summary: ValidationSwarmPerformanceSummary,
    pub cases: Vec<ValidationSwarmPerformanceCaseEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmPerformanceBenchmarkInstructions {
    pub required_wrapper: String,
    pub target_dir_policy_id: String,
    pub example_command: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmPerformanceSummary {
    pub cases: usize,
    pub max_equivalent_requests: usize,
    pub max_total_decisions: usize,
    pub max_unique_work_keys: usize,
    pub max_control_tower_rows: usize,
    pub max_output_size_bytes: usize,
    pub all_duplicate_producers_suppressed: bool,
    pub all_waiter_caps_respected: bool,
    pub all_stale_steals_recovered: bool,
    pub all_output_within_bounds: bool,
    pub all_growth_bounded: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationSwarmPerformanceCaseEvidence {
    pub case_id: String,
    pub equivalent_requests: usize,
    pub total_decisions: usize,
    pub decision_latency: ValidationSwarmPerformanceLatencyDistribution,
    pub memory_growth: ValidationSwarmPerformanceMemoryGrowth,
    pub duplicate_producer_suppression: ValidationSwarmPerformanceDuplicateSuppression,
    pub waiter_cap: ValidationSwarmPerformanceWaiterCap,
    pub stale_steal_recovery: ValidationSwarmPerformanceStaleStealRecovery,
    pub output_size: ValidationSwarmPerformanceOutputSize,
    pub decision_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmPerformanceLatencyDistribution {
    pub p50_queue_age_ms: u64,
    pub p95_queue_age_ms: u64,
    pub p99_queue_age_ms: u64,
    pub max_queue_age_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmPerformanceMemoryGrowth {
    pub class: ValidationSwarmPerformanceMemoryGrowthClass,
    pub decision_vector_len: usize,
    pub control_tower_rows: usize,
    pub unique_work_keys: usize,
    pub bounded_vector_growth: bool,
    pub bounded_map_growth: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSwarmPerformanceMemoryGrowthClass {
    ConstantWorkKeysLinearRows,
    LinearWorkKeysLinearRows,
    Unbounded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmPerformanceDuplicateSuppression {
    pub equivalent_work_key: String,
    pub equivalent_requests: usize,
    pub producer_count: usize,
    pub joined_waiters: usize,
    pub suppressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmPerformanceWaiterCap {
    pub configured_waiter_cap: usize,
    pub max_waiters_observed_per_work_key: usize,
    pub within_cap: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmPerformanceStaleStealRecovery {
    pub stale_steal_count: usize,
    pub recovered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmPerformanceOutputSize {
    pub handoff_rows: usize,
    pub handoff_truncated: bool,
    pub markdown_bytes: usize,
    pub json_bytes: usize,
    pub bounded: bool,
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
        evaluate_proof_coalescer_check(&summary),
        evaluate_swarm_scheduler_slo_check(&summary),
        evaluate_swarm_admission_check(&summary),
        evaluate_rch_worker_check(input, &summary),
        evaluate_proof_lane_readiness_check(&summary),
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
pub fn build_validation_handoff_report(
    input: &ValidationReadinessInput,
    trace_id: impl Into<String>,
    now: DateTime<Utc>,
) -> ValidationHandoffReport {
    let report = build_validation_readiness_report(input, trace_id, now);
    build_validation_handoff_report_from_readiness(input, &report)
}

#[must_use]
pub fn build_validation_handoff_report_from_readiness(
    input: &ValidationReadinessInput,
    report: &ValidationReadinessReport,
) -> ValidationHandoffReport {
    let thread_ids = tracked_thread_ids(input);
    let recoveries = recovery_plans_by_bead(&report.summary.pending_recoveries);
    let failed_attempts = failed_attempts_by_bead(&report.summary.failed_attempt_details);
    let entries = report
        .summary
        .control_tower
        .entries
        .iter()
        .take(MAX_VALIDATION_HANDOFF_ROWS)
        .map(|row| {
            let thread_id = thread_ids
                .get(&row.bead_id)
                .cloned()
                .unwrap_or_else(|| row.bead_id.clone());
            let recovery = recoveries.get(&row.bead_id).copied();
            let failed_attempt = failed_attempts.get(&row.bead_id).copied();
            validation_handoff_entry_from_row(row, thread_id, recovery, failed_attempt)
        })
        .collect::<Vec<_>>();
    let truncated = report.summary.control_tower.entries.len() > entries.len();
    let markdown = render_validation_handoff_entries_markdown(
        report.trace_id.as_str(),
        report.overall_status,
        report.generated_at_utc,
        truncated,
        &entries,
    );

    ValidationHandoffReport {
        schema_version: VALIDATION_HANDOFF_SUMMARY_SCHEMA_VERSION.to_string(),
        command: "ops validation-handoff-summary".to_string(),
        trace_id: report.trace_id.clone(),
        generated_at_utc: report.generated_at_utc,
        readiness_status: report.overall_status,
        rows: entries.len(),
        truncated,
        entries,
        br_comment_markdown: markdown.clone(),
        agent_mail_markdown: markdown,
    }
}

#[must_use]
pub fn render_validation_handoff_markdown(report: &ValidationHandoffReport) -> String {
    report.agent_mail_markdown.clone()
}

#[must_use]
pub fn build_validation_swarm_performance_evidence(
    cases: &[ValidationSwarmPerformanceInputCase],
    trace_id: impl Into<String>,
    now: DateTime<Utc>,
) -> ValidationSwarmPerformanceEvidence {
    let trace_id = trace_id.into();
    let mut sorted_cases = cases.iter().collect::<Vec<_>>();
    sorted_cases.sort_by(|left, right| {
        left.equivalent_requests
            .cmp(&right.equivalent_requests)
            .then_with(|| left.case_id.cmp(&right.case_id))
    });

    let linked_bead_ids = sorted_cases
        .iter()
        .flat_map(|case| case.linked_bead_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let cases = sorted_cases
        .into_iter()
        .map(|case| build_validation_swarm_performance_case(case, trace_id.as_str(), now))
        .collect::<Vec<_>>();
    let summary = summarize_validation_swarm_performance_cases(&cases);

    ValidationSwarmPerformanceEvidence {
        schema_version: VALIDATION_SWARM_PERFORMANCE_EVIDENCE_SCHEMA_VERSION.to_string(),
        command: "ops validation-swarm-performance --source-only".to_string(),
        trace_id,
        generated_at_utc: now,
        fixture_mode: "source_only_in_memory".to_string(),
        optional_heavy_benchmark: ValidationSwarmPerformanceBenchmarkInstructions {
            required_wrapper: "rch exec --".to_string(),
            target_dir_policy_id: "validation-swarm-scheduler/target-dir/off-repo/v1".to_string(),
            example_command: "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_node_swarm_perf cargo bench -p frankenengine-node validation_swarm_scheduler".to_string(),
        },
        linked_bead_ids,
        summary,
        cases,
    }
}

fn build_validation_swarm_performance_case(
    case: &ValidationSwarmPerformanceInputCase,
    trace_id: &str,
    now: DateTime<Utc>,
) -> ValidationSwarmPerformanceCaseEvidence {
    let readiness_input = ValidationReadinessInput {
        swarm_scheduler_decisions: case.decisions.clone(),
        ..ValidationReadinessInput::default()
    };
    let readiness = build_validation_readiness_report(
        &readiness_input,
        format!("{trace_id}/{}", case.case_id),
        now,
    );
    let handoff = build_validation_handoff_report_from_readiness(&readiness_input, &readiness);
    let markdown_bytes = handoff.agent_mail_markdown.len();
    let json_bytes = serde_json::to_vec(&handoff)
        .map(|encoded| encoded.len())
        .unwrap_or(usize::MAX);
    let output_bytes = markdown_bytes.saturating_add(json_bytes);

    let latency = validation_swarm_latency_distribution(&case.decisions);
    let work_key_counts = count_validation_swarm_work_keys(&case.decisions);
    let unique_work_keys = work_key_counts.len();
    let equivalent_work_key = largest_validation_swarm_work_key(&work_key_counts);
    let equivalent = equivalent_work_key
        .as_ref()
        .and_then(|work_key| work_key_counts.get(work_key))
        .copied()
        .unwrap_or_default();
    let max_waiters_observed_per_work_key = work_key_counts
        .values()
        .map(|counts| counts.joined_waiters)
        .max()
        .unwrap_or_default();
    let decision_counts = count_validation_swarm_decision_kinds(&case.decisions);
    let stale_steal_count = decision_counts
        .get(ValidationSwarmSchedulerDecisionKind::StealStaleWork.as_str())
        .copied()
        .unwrap_or_default();

    let total_decisions = case.decisions.len();
    let bounded_vector_growth = readiness.summary.control_tower.rows
        <= total_decisions.saturating_add(case.linked_bead_ids.len());
    let bounded_map_growth = unique_work_keys <= MAX_VALIDATION_SWARM_PERFORMANCE_UNIQUE_WORK_KEYS;
    let growth_class = if bounded_vector_growth && bounded_map_growth {
        ValidationSwarmPerformanceMemoryGrowthClass::ConstantWorkKeysLinearRows
    } else if bounded_vector_growth && unique_work_keys <= total_decisions {
        ValidationSwarmPerformanceMemoryGrowthClass::LinearWorkKeysLinearRows
    } else {
        ValidationSwarmPerformanceMemoryGrowthClass::Unbounded
    };

    ValidationSwarmPerformanceCaseEvidence {
        case_id: case.case_id.clone(),
        equivalent_requests: case.equivalent_requests,
        total_decisions,
        decision_latency: latency,
        memory_growth: ValidationSwarmPerformanceMemoryGrowth {
            class: growth_class,
            decision_vector_len: total_decisions,
            control_tower_rows: readiness.summary.control_tower.rows,
            unique_work_keys,
            bounded_vector_growth,
            bounded_map_growth,
        },
        duplicate_producer_suppression: ValidationSwarmPerformanceDuplicateSuppression {
            equivalent_work_key: equivalent_work_key.unwrap_or_default(),
            equivalent_requests: equivalent.requests,
            producer_count: equivalent.producer_count,
            joined_waiters: equivalent.joined_waiters,
            suppressed: equivalent.requests == case.equivalent_requests
                && equivalent.producer_count == 1
                && equivalent
                    .joined_waiters
                    .saturating_add(equivalent.producer_count)
                    == case.equivalent_requests,
        },
        waiter_cap: ValidationSwarmPerformanceWaiterCap {
            configured_waiter_cap: case.configured_waiter_cap,
            max_waiters_observed_per_work_key,
            within_cap: max_waiters_observed_per_work_key <= case.configured_waiter_cap,
        },
        stale_steal_recovery: ValidationSwarmPerformanceStaleStealRecovery {
            stale_steal_count,
            recovered: stale_steal_count > 0,
        },
        output_size: ValidationSwarmPerformanceOutputSize {
            handoff_rows: handoff.rows,
            handoff_truncated: handoff.truncated,
            markdown_bytes,
            json_bytes,
            bounded: output_bytes <= MAX_VALIDATION_SWARM_PERFORMANCE_OUTPUT_BYTES,
        },
        decision_counts,
    }
}

fn summarize_validation_swarm_performance_cases(
    cases: &[ValidationSwarmPerformanceCaseEvidence],
) -> ValidationSwarmPerformanceSummary {
    ValidationSwarmPerformanceSummary {
        cases: cases.len(),
        max_equivalent_requests: cases
            .iter()
            .map(|case| case.equivalent_requests)
            .max()
            .unwrap_or_default(),
        max_total_decisions: cases
            .iter()
            .map(|case| case.total_decisions)
            .max()
            .unwrap_or_default(),
        max_unique_work_keys: cases
            .iter()
            .map(|case| case.memory_growth.unique_work_keys)
            .max()
            .unwrap_or_default(),
        max_control_tower_rows: cases
            .iter()
            .map(|case| case.memory_growth.control_tower_rows)
            .max()
            .unwrap_or_default(),
        max_output_size_bytes: cases
            .iter()
            .map(|case| {
                case.output_size
                    .markdown_bytes
                    .saturating_add(case.output_size.json_bytes)
            })
            .max()
            .unwrap_or_default(),
        all_duplicate_producers_suppressed: cases
            .iter()
            .all(|case| case.duplicate_producer_suppression.suppressed),
        all_waiter_caps_respected: cases.iter().all(|case| case.waiter_cap.within_cap),
        all_stale_steals_recovered: cases.iter().all(|case| case.stale_steal_recovery.recovered),
        all_output_within_bounds: cases.iter().all(|case| case.output_size.bounded),
        all_growth_bounded: cases.iter().all(|case| {
            case.memory_growth.bounded_vector_growth && case.memory_growth.bounded_map_growth
        }),
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct ValidationSwarmWorkKeyCounts {
    requests: usize,
    producer_count: usize,
    joined_waiters: usize,
}

fn count_validation_swarm_work_keys(
    decisions: &[ValidationSwarmSchedulerDecision],
) -> BTreeMap<String, ValidationSwarmWorkKeyCounts> {
    let mut counts = BTreeMap::<String, ValidationSwarmWorkKeyCounts>::new();
    for decision in decisions {
        let entry = counts
            .entry(decision.diagnostics.proof_work_key_hex.clone())
            .or_default();
        entry.requests = entry.requests.saturating_add(1);
        match decision.decision {
            ValidationSwarmSchedulerDecisionKind::RunNow => {
                entry.producer_count = entry.producer_count.saturating_add(1);
            }
            ValidationSwarmSchedulerDecisionKind::JoinExisting => {
                entry.joined_waiters = entry.joined_waiters.saturating_add(1);
            }
            _ => {}
        }
    }
    counts
}

fn largest_validation_swarm_work_key(
    counts: &BTreeMap<String, ValidationSwarmWorkKeyCounts>,
) -> Option<String> {
    counts
        .iter()
        .max_by(|(left_key, left), (right_key, right)| {
            left.requests
                .cmp(&right.requests)
                .then_with(|| right_key.cmp(left_key))
        })
        .map(|(work_key, _)| work_key.clone())
}

fn count_validation_swarm_decision_kinds(
    decisions: &[ValidationSwarmSchedulerDecision],
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for decision in decisions {
        *counts
            .entry(decision.decision.as_str().to_string())
            .or_insert(0) += 1;
    }
    counts
}

fn validation_swarm_latency_distribution(
    decisions: &[ValidationSwarmSchedulerDecision],
) -> ValidationSwarmPerformanceLatencyDistribution {
    if decisions.is_empty() {
        return ValidationSwarmPerformanceLatencyDistribution::default();
    }
    let mut queue_ages = decisions
        .iter()
        .map(|decision| decision.diagnostics.queue_age_ms)
        .collect::<Vec<_>>();
    queue_ages.sort_unstable();

    ValidationSwarmPerformanceLatencyDistribution {
        p50_queue_age_ms: percentile_sorted(&queue_ages, 50),
        p95_queue_age_ms: percentile_sorted(&queue_ages, 95),
        p99_queue_age_ms: percentile_sorted(&queue_ages, 99),
        max_queue_age_ms: queue_ages.last().copied().unwrap_or_default(),
    }
}

fn percentile_sorted(sorted_values: &[u64], percentile: usize) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }
    let index = sorted_values
        .len()
        .saturating_mul(percentile)
        .saturating_add(99)
        .checked_div(100)
        .unwrap_or(1)
        .saturating_sub(1)
        .min(sorted_values.len().saturating_sub(1));
    sorted_values[index]
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
        capsule_path: None,
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
            "  proof_coalescer=producers:{} waiters:{} stale_leases:{} fenced_leases:{} capacity_rejections:{} cache_handoffs:{} rejected:{}",
            report.summary.proof_coalescer.producer_proofs,
            report.summary.proof_coalescer.waiters,
            report.summary.proof_coalescer.stale_leases,
            report.summary.proof_coalescer.fenced_leases,
            report.summary.proof_coalescer.capacity_rejections,
            report.summary.proof_coalescer.cache_handoffs,
            report.summary.proof_coalescer.rejected
        ),
        format!(
            "  swarm_scheduler=decisions:{} queue_age_p95_ms:{} slot_utilization:{:.3} fairness_index:{:.3} slo_breach_status:{} breached_decisions:{}",
            report.summary.swarm_scheduler.decisions,
            report.summary.swarm_scheduler.queue_age_p95_ms,
            report.summary.swarm_scheduler.slot_utilization,
            report.summary.swarm_scheduler.fairness_index,
            report.summary.swarm_scheduler.slo_breach_status.as_str(),
            report.summary.swarm_scheduler.breached_decisions
        ),
        format!(
            "  swarm_admission=decisions:{} run:{} coalesce:{} defer:{} handoff:{} blocked:{} stale_inputs:{} fail_closed:{} rch_jobs_budgeted:{}",
            report.summary.swarm_admission.decisions,
            report.summary.swarm_admission.run,
            report.summary.swarm_admission.coalesce,
            report.summary.swarm_admission.defer,
            report.summary.swarm_admission.handoff,
            report.summary.swarm_admission.blocked,
            report.summary.swarm_admission.stale_inputs,
            report.summary.swarm_admission.fail_closed,
            report.summary.swarm_admission.rch_jobs_budgeted
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
        format!(
            "  control_tower=rows:{} green:{} wait_or_join:{} capacity_waits:{} source_only:{} worker_infra:{} product_failures:{} invalid_artifacts:{} stale_leases:{} no_known_proofs:{}",
            report.summary.control_tower.rows,
            report.summary.control_tower.green_proofs,
            report.summary.control_tower.wait_or_join,
            report.summary.control_tower.capacity_waits,
            report.summary.control_tower.source_only_blockers,
            report.summary.control_tower.worker_infrastructure,
            report.summary.control_tower.product_failures,
            report.summary.control_tower.invalid_artifacts,
            report.summary.control_tower.stale_leases,
            report.summary.control_tower.no_known_proofs
        ),
    ];

    for entry in &report.summary.control_tower.entries {
        lines.push(format!(
            "    control_tower bead={} agent={} decision={} reason_code={} event_code={} required_action={} proof_source={} proof_debt_class={} fairness_bucket={} stale_risk={} recorder_path={} latest_artifact={} rch_slots={}/{} queue_depth={} green_proof_eligible={}",
            entry.bead_id,
            entry.agent_name,
            entry.decision,
            entry.reason_code,
            entry.event_code,
            entry.required_action,
            entry.proof_source,
            entry.proof_debt_class,
            entry.fairness_bucket,
            entry.stale_risk,
            entry.recorder_path.as_deref().unwrap_or("none"),
            entry.latest_artifact_path.as_deref().unwrap_or("none"),
            entry
                .rch_slots_available
                .map_or_else(|| "n/a".to_string(), |slots| slots.to_string()),
            entry
                .rch_slots_total
                .map_or_else(|| "n/a".to_string(), |slots| slots.to_string()),
            entry
                .rch_queue_depth
                .map_or_else(|| "n/a".to_string(), |depth| depth.to_string()),
            entry.green_proof_eligible
        ));
    }

    if report.summary.proof_lane_readiness.is_empty() {
        lines.push("  proof_lane_readiness=none".to_string());
    } else {
        lines.push(format!(
            "  proof_lane_readiness={} preflight_capsules",
            report.summary.proof_lane_readiness.len()
        ));
        for capsule in &report.summary.proof_lane_readiness {
            lines.push(format!(
                "    capsule_id={} decision={} reason_code={} event_code={} requested_worker={} selected_worker={} same_toolchain_available={} auth_status={} capability_freshness={} pressure_status={} local_fallback_allowed={} local_fallback_refused={} freshness_expires_at={} capsule_path={} required_action={} operator_summary={}",
                capsule.capsule_id,
                capsule.decision.as_str(),
                capsule.reason_code,
                capsule.event_code,
                capsule.requested_worker,
                capsule.selected_worker.as_deref().unwrap_or("none"),
                capsule.same_toolchain_available,
                capsule.auth_status.as_str(),
                capsule.capability_freshness.as_str(),
                capsule.pressure_status.as_str(),
                capsule.local_fallback_allowed,
                capsule.local_fallback_refused,
                capsule.freshness_expires_at.to_rfc3339(),
                capsule.capsule_path.as_deref().unwrap_or("none"),
                capsule.required_action,
                capsule.operator_summary
            ));
        }
    }

    for decision in &report.summary.swarm_scheduler.decision_details {
        if decision.slo_breached
            || matches!(
                decision.scheduler_decision.as_str(),
                "wait_for_capacity"
                    | "steal_stale_work"
                    | "record_source_only_blocker"
                    | "fail_closed_product"
                    | "fail_closed_invalid_artifact"
            )
        {
            lines.push(format!(
                "    swarm_scheduler_decision bead={} agent={} decision={} reason_code={} event_code={} action={} queue_age_ms={} fairness_bucket={} starvation_risk={} proof_work_key={} coalescer_state={} recorder_path={} slo_breached={}",
                decision.bead_id,
                decision.agent,
                decision.scheduler_decision,
                decision.reason_code,
                decision.event_code,
                decision.next_action,
                decision.queue_age_ms,
                decision.fairness_bucket,
                decision.starvation_risk,
                decision.proof_work_key,
                decision.coalescer_state,
                decision.recorder_path.as_deref().unwrap_or("none"),
                decision.slo_breached
            ));
        }
    }

    for decision in &report.summary.swarm_admission.decision_details {
        if matches!(
            decision.decision.as_str(),
            "coalesce" | "defer" | "handoff" | "blocked"
        ) || decision.fail_closed
            || !decision.input_fresh
        {
            lines.push(format!(
                "    swarm_admission bead={} agent={} decision={} reason_code={} event_code={} action={} input_fresh={} proof_work_key={} owner={} target_dir_strategy={} worker_requirement={} max_parallel_rch_jobs={} retry_after_ms={} safe_command={}",
                decision.bead_id,
                decision.agent,
                decision.decision,
                decision.reason_code,
                decision.event_code,
                decision.next_action,
                decision.input_fresh,
                decision.proof_work_key.as_deref().unwrap_or("none"),
                decision.owner_agent.as_deref().unwrap_or("none"),
                decision.target_dir_strategy,
                decision.worker_requirement,
                decision.max_parallel_rch_jobs,
                decision
                    .retry_after_ms
                    .map_or_else(|| "none".to_string(), |retry| retry.to_string()),
                decision.safe_command_shape.as_deref().unwrap_or("none")
            ));
        }
    }

    for check in &report.checks {
        lines.push(format!(
            "  {} [{}] {}",
            check.code,
            check.status.as_str(),
            check.message
        ));
        if !check.remediation.trim().is_empty()
            && !matches!(check.status, ValidationReadinessStatus::Pass)
        {
            lines.push(format!("    remediation={}", check.remediation));
        }
    }

    lines.join("\n")
}

fn tracked_thread_ids(input: &ValidationReadinessInput) -> BTreeMap<String, String> {
    input
        .tracked_beads
        .iter()
        .map(|bead| {
            (
                bead.bead_id.clone(),
                bead.normalized_thread_id().to_string(),
            )
        })
        .collect()
}

fn recovery_plans_by_bead(
    recoveries: &[RecoveryPlanSummary],
) -> BTreeMap<String, &RecoveryPlanSummary> {
    recoveries
        .iter()
        .map(|recovery| (recovery.bead_id.clone(), recovery))
        .collect()
}

fn failed_attempts_by_bead(
    attempts: &[FailedAttemptSummary],
) -> BTreeMap<String, &FailedAttemptSummary> {
    attempts
        .iter()
        .map(|attempt| (attempt.bead_id.clone(), attempt))
        .collect()
}

fn validation_handoff_entry_from_row(
    row: &ValidationControlTowerRow,
    thread_id: String,
    recovery: Option<&RecoveryPlanSummary>,
    failed_attempt: Option<&FailedAttemptSummary>,
) -> ValidationHandoffEntry {
    let mut field_errors = validation_handoff_field_errors(row, thread_id.as_str());
    let fail_closed = !field_errors.is_empty()
        || matches!(
            row.decision.as_str(),
            "fail_closed_invalid_artifact"
                | "invalid_artifact"
                | "fail_closed_product"
                | "product_failure"
                | "record_source_only_blocker"
                | "source_only"
                | "no_known_proof"
        );
    if !field_errors.is_empty() {
        field_errors.sort();
        field_errors.dedup();
    }
    let (cargo_launch_allowed, cargo_action) = if field_errors.is_empty() {
        validation_handoff_cargo_action(row, recovery)
    } else {
        (false, "repair_handoff_input")
    };
    let green_closeout_allowed = field_errors.is_empty() && row.green_proof_eligible;
    let markdown = render_validation_handoff_entry_markdown(
        row,
        thread_id.as_str(),
        cargo_launch_allowed,
        cargo_action,
        fail_closed,
        &field_errors,
        recovery,
        failed_attempt,
    );

    ValidationHandoffEntry {
        bead_id: bounded_handoff_value(row.bead_id.as_str()),
        thread_id: bounded_handoff_value(thread_id.as_str()),
        agent_name: bounded_handoff_value(row.agent_name.as_str()),
        decision: bounded_handoff_value(row.decision.as_str()),
        scheduler_decision: row.scheduler_decision.as_deref().map(bounded_handoff_value),
        reason_code: bounded_handoff_value(row.reason_code.as_str()),
        event_code: bounded_handoff_value(row.event_code.as_str()),
        required_action: bounded_handoff_value(row.required_action.as_str()),
        next_action: bounded_handoff_value(row.next_action.as_str()),
        proof_source: bounded_handoff_value(row.proof_source.as_str()),
        proof_debt_class: bounded_handoff_value(row.proof_debt_class.as_str()),
        proof_work_key: row.proof_work_key.as_deref().map(bounded_handoff_value),
        command_digest: row.command_digest.as_deref().map(bounded_handoff_value),
        recorder_path: row.recorder_path.as_deref().map(bounded_handoff_value),
        recovery_artifact_path: row
            .recovery_artifact_path
            .as_deref()
            .map(bounded_handoff_value),
        latest_artifact_path: row
            .latest_artifact_path
            .as_deref()
            .map(bounded_handoff_value),
        rch_slots_total: row.rch_slots_total,
        rch_slots_available: row.rch_slots_available,
        rch_queue_depth: row.rch_queue_depth,
        green_closeout_allowed,
        cargo_launch_allowed,
        cargo_action: cargo_action.to_string(),
        fail_closed,
        field_errors,
        recovery_action: recovery.map(|item| bounded_handoff_value(item.action.as_str())),
        recovery_required_action: recovery
            .map(|item| bounded_handoff_value(item.required_action.as_str())),
        retry_after_ms: recovery.and_then(|item| item.retry_after_ms),
        worker_preference: recovery
            .and_then(|item| item.worker_preference.as_deref())
            .map(bounded_handoff_value),
        flight_recorder_path: failed_attempt
            .and_then(|item| item.flight_recorder_path.as_deref())
            .map(bounded_handoff_value),
        markdown,
    }
}

fn validation_handoff_field_errors(
    row: &ValidationControlTowerRow,
    thread_id: &str,
) -> Vec<String> {
    let mut errors = Vec::new();
    if row.bead_id.trim().is_empty() {
        errors.push("missing_bead_id".to_string());
    }
    if thread_id.trim().is_empty() {
        errors.push("missing_thread_id".to_string());
    }
    if row.command_digest.as_ref().is_none_or(|value| {
        value.trim().is_empty()
            || value.contains('\0')
            || value.len() > MAX_VALIDATION_HANDOFF_FIELD_BYTES
    }) && !matches!(row.decision.as_str(), "no_known_proof")
    {
        errors.push("missing_or_malformed_command_digest".to_string());
    }
    for (field, path) in [
        ("recorder_path", row.recorder_path.as_deref()),
        (
            "recovery_artifact_path",
            row.recovery_artifact_path.as_deref(),
        ),
        ("latest_artifact_path", row.latest_artifact_path.as_deref()),
    ] {
        if let Some(path) = path
            && !validation_handoff_path_is_safe(path)
        {
            errors.push(format!("malformed_{field}"));
        }
    }
    errors
}

fn validation_handoff_path_is_safe(path: &str) -> bool {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.len() > MAX_VALIDATION_HANDOFF_FIELD_BYTES
    {
        return false;
    }
    !Path::new(trimmed).is_absolute()
        && !Path::new(trimmed).components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

fn validation_handoff_cargo_action(
    row: &ValidationControlTowerRow,
    recovery: Option<&RecoveryPlanSummary>,
) -> (bool, &'static str) {
    if !row.green_proof_eligible
        && matches!(
            row.decision.as_str(),
            "green_proof" | "join_existing" | "running" | "queued" | "leased"
        )
        && row.command_digest.is_none()
    {
        return (false, "repair_handoff_input");
    }

    match row.decision.as_str() {
        "run_now" => (true, "launch_remote_proof"),
        "green_proof" => (false, "do_not_launch_green_proof"),
        "join_existing" | "running" | "queued" | "leased" => (false, "join_existing_or_wait"),
        "wait_for_capacity" => (false, "wait_for_capacity"),
        "steal_stale_work" | "stale_lease" => (true, "retry_remote_with_fresh_fence"),
        "worker_infrastructure" => (
            recovery.is_some_and(|item| !item.fail_closed),
            "retry_remote_after_worker_infra",
        ),
        "record_source_only_blocker" | "source_only" => (false, "record_source_only_blocker"),
        "fail_closed_product" | "product_failure" => (false, "surface_product_failure"),
        "fail_closed_invalid_artifact" | "invalid_artifact" => (false, "reject_invalid_artifact"),
        "no_known_proof" => (true, "launch_remote_proof_or_record_blocker"),
        _ => (false, "inspect_validation_state"),
    }
}

fn render_validation_handoff_entries_markdown(
    trace_id: &str,
    status: ValidationReadinessStatus,
    generated_at: DateTime<Utc>,
    truncated: bool,
    entries: &[ValidationHandoffEntry],
) -> String {
    let mut lines = vec![
        format!(
            "`{}` validation handoff summary: `{}`",
            trace_id,
            status.as_str()
        ),
        format!("- generated_at: `{}`", generated_at.to_rfc3339()),
        format!("- rows: {} truncated={}", entries.len(), truncated),
    ];
    for entry in entries {
        lines.push(String::new());
        lines.push(entry.markdown.clone());
    }
    lines.join("\n")
}

#[expect(
    clippy::too_many_arguments,
    reason = "handoff rendering intentionally keeps each evidence facet explicit"
)]
fn render_validation_handoff_entry_markdown(
    row: &ValidationControlTowerRow,
    thread_id: &str,
    cargo_launch_allowed: bool,
    cargo_action: &str,
    fail_closed: bool,
    field_errors: &[String],
    recovery: Option<&RecoveryPlanSummary>,
    failed_attempt: Option<&FailedAttemptSummary>,
) -> String {
    let mut lines = vec![
        format!("### `{}`", bounded_handoff_value(row.bead_id.as_str())),
        format!("- thread: `{}`", bounded_handoff_value(thread_id)),
        format!(
            "- owner: `{}`",
            bounded_handoff_value(row.agent_name.as_str())
        ),
        format!(
            "- decision: `{}` reason=`{}` event=`{}`",
            bounded_handoff_value(row.decision.as_str()),
            bounded_handoff_value(row.reason_code.as_str()),
            bounded_handoff_value(row.event_code.as_str())
        ),
        format!(
            "- required_action: `{}`",
            bounded_handoff_value(row.required_action.as_str())
        ),
        format!(
            "- next_action: `{}`",
            bounded_handoff_value(row.next_action.as_str())
        ),
        format!(
            "- cargo: launch_allowed={} action=`{}`",
            cargo_launch_allowed, cargo_action
        ),
        format!(
            "- proof: source=`{}` debt=`{}` green_closeout_allowed={} fail_closed={}",
            bounded_handoff_value(row.proof_source.as_str()),
            bounded_handoff_value(row.proof_debt_class.as_str()),
            row.green_proof_eligible && field_errors.is_empty(),
            fail_closed
        ),
        format!(
            "- command_digest: `{}`",
            row.command_digest
                .as_deref()
                .map(bounded_handoff_value)
                .unwrap_or_else(|| "none".to_string())
        ),
        format!(
            "- proof_work_key: `{}`",
            row.proof_work_key
                .as_deref()
                .map(bounded_handoff_value)
                .unwrap_or_else(|| "none".to_string())
        ),
        format!(
            "- artifacts: recorder=`{}` recovery=`{}` latest=`{}`",
            row.recorder_path
                .as_deref()
                .map(bounded_handoff_value)
                .unwrap_or_else(|| "none".to_string()),
            row.recovery_artifact_path
                .as_deref()
                .map(bounded_handoff_value)
                .unwrap_or_else(|| "none".to_string()),
            row.latest_artifact_path
                .as_deref()
                .map(bounded_handoff_value)
                .unwrap_or_else(|| "none".to_string())
        ),
        format!(
            "- rch_capacity: slots={}/{} queue_depth={}",
            row.rch_slots_available
                .map_or_else(|| "n/a".to_string(), |slots| slots.to_string()),
            row.rch_slots_total
                .map_or_else(|| "n/a".to_string(), |slots| slots.to_string()),
            row.rch_queue_depth
                .map_or_else(|| "n/a".to_string(), |depth| depth.to_string())
        ),
    ];

    if let Some(recovery) = recovery {
        lines.push(format!(
            "- recovery: action=`{}` required_action=`{}` retry_after_ms={} worker=`{}`",
            bounded_handoff_value(recovery.action.as_str()),
            bounded_handoff_value(recovery.required_action.as_str()),
            recovery
                .retry_after_ms
                .map_or_else(|| "none".to_string(), |value| value.to_string()),
            recovery
                .worker_preference
                .as_deref()
                .map(bounded_handoff_value)
                .unwrap_or_else(|| "none".to_string())
        ));
    }

    if let Some(failed_attempt) = failed_attempt {
        lines.push(format!(
            "- flight_recorder: path=`{}` outcome=`{}` worker=`{}` retryable={} product_failure={}",
            failed_attempt
                .flight_recorder_path
                .as_deref()
                .map(bounded_handoff_value)
                .unwrap_or_else(|| "none".to_string()),
            bounded_handoff_value(failed_attempt.outcome_class.as_str()),
            failed_attempt
                .worker_id
                .as_deref()
                .map(bounded_handoff_value)
                .unwrap_or_else(|| "none".to_string()),
            failed_attempt.retryable,
            failed_attempt.product_failure
        ));
    }

    if field_errors.is_empty() {
        lines.push("- field_errors: none".to_string());
    } else {
        lines.push(format!("- field_errors: `{}`", field_errors.join(",")));
    }

    lines.join("\n")
}

fn bounded_handoff_value(value: &str) -> String {
    if value.len() <= MAX_VALIDATION_HANDOFF_FIELD_BYTES {
        return value.to_string();
    }
    const TRUNCATED_SUFFIX: &str = "[truncated]";
    let max_value_bytes = MAX_VALIDATION_HANDOFF_FIELD_BYTES.saturating_sub(TRUNCATED_SUFFIX.len());
    let mut bounded = String::new();
    let mut bytes = 0usize;
    for ch in value.chars() {
        let next = bytes.saturating_add(ch.len_utf8());
        if next > max_value_bytes {
            break;
        }
        bounded.push(ch);
        bytes = next;
    }
    bounded.push_str(TRUNCATED_SUFFIX);
    bounded
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
    let mut proof_coalescer = ProofCoalescerCounts::default();
    let swarm_scheduler = summarize_swarm_scheduler_decisions(&input.swarm_scheduler_decisions);
    let swarm_admission = summarize_swarm_admission_decisions(&input.swarm_admission_decisions);
    let control_tower = build_validation_control_tower(input, now);

    for status in &input.proof_statuses {
        increment_proof_count(&mut proof_counts, status.status);
        increment_proof_coalescer_count(&mut proof_coalescer, status);
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

        if matches!(receipt.exit.kind, ValidationExitKind::Success) && command_uses_cargo(receipt) {
            last_successful_cargo_proof_at = Some(
                last_successful_cargo_proof_at
                    .map_or(receipt.timing.finished_at, |current: DateTime<Utc>| {
                        current.max(receipt.timing.finished_at)
                    }),
            );
        }
    }

    // Collect flight recorder information
    let mut flight_recorder_refs_count = 0usize;
    let mut failed_attempt_details = Vec::new();
    let mut pending_recoveries = Vec::new();

    // Process proof statuses for flight recorder data
    for status in &input.proof_statuses {
        if let Some(ref _flight_ref) = status.flight_recorder_ref {
            flight_recorder_refs_count = flight_recorder_refs_count.saturating_add(1);
        }

        if status.status == ProofStatusKind::Failed
            && let Some(ref flight_ref) = status.flight_recorder_ref
        {
            // Extract failure domain information
            let domain = status
                .exit
                .as_ref()
                .map_or(ValidationFailureDomain::Unknown, failure_domain_for_exit);

            // Determine if this failure is retryable based on recovery planner
            let (retryable, recovery_plan) = if let Some(ref exit) = status.exit {
                let decision = recovery_decision_for_exit(exit, status.thread_id.as_str());
                let is_retryable = recovery_action_is_retryable(decision.action);
                (is_retryable, Some(decision))
            } else {
                (false, None)
            };

            failed_attempt_details.push(FailedAttemptSummary {
                bead_id: status.bead_id.clone(),
                thread_id: status.thread_id.clone(),
                flight_recorder_path: Some(flight_ref.attempt_path.clone()),
                outcome_class: flight_outcome_class_as_str(flight_ref.outcome_class).to_string(),
                execution_mode: rch_mode_as_str(flight_ref.execution_mode).to_string(),
                worker_id: flight_ref.worker_id.clone(),
                reason_code: flight_ref.reason_code.clone(),
                retryable,
                product_failure: domain == ValidationFailureDomain::Product,
                last_attempt_at: status.observed_at,
            });

            // Add recovery plan if retryable
            if let Some(recovery) = recovery_plan
                && retryable
            {
                pending_recoveries.push(RecoveryPlanSummary {
                    bead_id: status.bead_id.clone(),
                    thread_id: status.thread_id.clone(),
                    action: format!("{:?}", recovery.action),
                    reason_code: recovery.reason_code,
                    required_action: recovery.required_action,
                    retry_after_ms: recovery.retry_after_ms,
                    worker_preference: recovery.worker_preference,
                    fail_closed: matches!(recovery.action, RecoveryAction::FailClosed),
                });
            }
        }
    }

    // Process receipts for additional flight recorder data
    for receipt in &input.receipts {
        if let Some(ref flight_ref) = receipt.flight_recorder_ref {
            flight_recorder_refs_count = flight_recorder_refs_count.saturating_add(1);

            // If this receipt indicates a failure, add to failed attempts
            if !matches!(receipt.exit.kind, ValidationExitKind::Success) {
                let domain = failure_domain_for_receipt(receipt);

                let (retryable, recovery_plan) = {
                    let decision =
                        recovery_decision_for_exit(&receipt.exit, receipt.thread_id.as_str());
                    let is_retryable = recovery_action_is_retryable(decision.action);
                    (is_retryable, Some(decision))
                };

                failed_attempt_details.push(FailedAttemptSummary {
                    bead_id: receipt.bead_id.clone(),
                    thread_id: receipt.thread_id.clone(),
                    flight_recorder_path: Some(flight_ref.attempt_path.clone()),
                    outcome_class: flight_outcome_class_as_str(flight_ref.outcome_class)
                        .to_string(),
                    execution_mode: rch_mode_as_str(flight_ref.execution_mode).to_string(),
                    worker_id: flight_ref.worker_id.clone(),
                    reason_code: flight_ref.reason_code.clone(),
                    retryable,
                    product_failure: domain == ValidationFailureDomain::Product,
                    last_attempt_at: receipt.timing.finished_at,
                });

                // Add recovery plan if retryable
                if let Some(recovery) = recovery_plan
                    && retryable
                {
                    pending_recoveries.push(RecoveryPlanSummary {
                        bead_id: receipt.bead_id.clone(),
                        thread_id: receipt.thread_id.clone(),
                        action: format!("{:?}", recovery.action),
                        reason_code: recovery.reason_code,
                        required_action: recovery.required_action,
                        retry_after_ms: recovery.retry_after_ms,
                        worker_preference: recovery.worker_preference,
                        fail_closed: matches!(recovery.action, RecoveryAction::FailClosed),
                    });
                }
            }
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
        proof_coalescer,
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
        proof_lane_readiness: input
            .proof_lane_readiness
            .iter()
            .map(summarize_proof_lane_capsule)
            .collect(),
        swarm_scheduler,
        swarm_admission,
        control_tower,
        flight_recorder_refs: flight_recorder_refs_count,
        failed_attempt_details,
        pending_recoveries,
    }
}

fn summarize_proof_lane_capsule(capsule: &ProofLaneReadinessCapsule) -> ProofLaneReadinessSummary {
    ProofLaneReadinessSummary {
        capsule_id: capsule.capsule_id.clone(),
        capsule_path: capsule.capsule_path.clone(),
        trace_id: capsule.trace_id.clone(),
        bead_id: capsule.bead_id.clone(),
        thread_id: capsule.thread_id.clone(),
        decision: capsule.decision.decision,
        reason_code: capsule.decision.reason_code.clone(),
        event_code: capsule.decision.event_code.clone(),
        requested_worker: requested_workers_label(&capsule.worker_selection.requested_workers),
        selected_worker: capsule.worker_selection.selected_worker.clone(),
        same_toolchain_available: capsule.toolchain.same_toolchain,
        auth_status: capsule.worker_access.auth_status,
        capability_freshness: capsule.worker_access.capability_status,
        pressure_status: capsule.worker_access.pressure_status,
        local_fallback_allowed: capsule.rch.local_fallback_allowed,
        local_fallback_refused: capsule.rch.local_fallback_refused,
        retryable: capsule.decision.retryable,
        fail_closed: capsule.decision.fail_closed,
        created_at: capsule.created_at,
        freshness_expires_at: capsule.freshness_expires_at,
        required_action: capsule.decision.required_action.clone(),
        operator_summary: capsule.decision.operator_summary.clone(),
    }
}

fn build_validation_control_tower(
    input: &ValidationReadinessInput,
    now: DateTime<Utc>,
) -> ValidationControlTowerSummary {
    let mut entries = Vec::new();
    let mut seen_beads = BTreeSet::new();

    for decision in &input.swarm_scheduler_decisions {
        seen_beads.insert(decision.bead_id.clone());
        entries.push(control_tower_row_from_scheduler(decision));
    }

    for receipt in &input.receipts {
        seen_beads.insert(receipt.bead_id.clone());
        entries.push(control_tower_row_from_receipt(receipt, now));
    }

    for status in &input.proof_statuses {
        seen_beads.insert(status.bead_id.clone());
        entries.push(control_tower_row_from_status(status));
    }

    for bead in &input.tracked_beads {
        if !seen_beads.contains(&bead.bead_id) {
            entries.push(control_tower_row_for_missing_bead(bead));
        }
    }

    entries.sort_by(|left, right| {
        (
            left.bead_id.as_str(),
            left.agent_name.as_str(),
            left.decision.as_str(),
            left.reason_code.as_str(),
        )
            .cmp(&(
                right.bead_id.as_str(),
                right.agent_name.as_str(),
                right.decision.as_str(),
                right.reason_code.as_str(),
            ))
    });

    summarize_control_tower_entries(entries)
}

fn summarize_control_tower_entries(
    entries: Vec<ValidationControlTowerRow>,
) -> ValidationControlTowerSummary {
    let mut summary = ValidationControlTowerSummary {
        rows: entries.len(),
        entries,
        ..ValidationControlTowerSummary::default()
    };

    for entry in &summary.entries {
        match entry.decision.as_str() {
            "green_proof" => summary.green_proofs = summary.green_proofs.saturating_add(1),
            "join_existing" | "wait_for_capacity" | "running" | "queued" | "leased" => {
                summary.wait_or_join = summary.wait_or_join.saturating_add(1);
            }
            "record_source_only_blocker" | "source_only" => {
                summary.source_only_blockers = summary.source_only_blockers.saturating_add(1);
            }
            "worker_infrastructure" => {
                summary.worker_infrastructure = summary.worker_infrastructure.saturating_add(1);
            }
            "fail_closed_product" | "product_failure" => {
                summary.product_failures = summary.product_failures.saturating_add(1);
            }
            "fail_closed_invalid_artifact" | "invalid_artifact" => {
                summary.invalid_artifacts = summary.invalid_artifacts.saturating_add(1);
            }
            "stale_lease" | "steal_stale_work" => {
                summary.stale_leases = summary.stale_leases.saturating_add(1);
            }
            "no_known_proof" => {
                summary.no_known_proofs = summary.no_known_proofs.saturating_add(1);
            }
            _ => {}
        }
        if matches!(entry.decision.as_str(), "wait_for_capacity") {
            summary.capacity_waits = summary.capacity_waits.saturating_add(1);
        }
    }

    summary
}

fn control_tower_row_from_scheduler(
    decision: &ValidationSwarmSchedulerDecision,
) -> ValidationControlTowerRow {
    let scheduler_decision = decision.decision.as_str().to_string();
    ValidationControlTowerRow {
        bead_id: decision.bead_id.clone(),
        agent_name: decision.agent_name.clone(),
        decision: scheduler_decision.clone(),
        scheduler_decision: Some(scheduler_decision),
        reason_code: decision.reason_code.clone(),
        event_code: decision.event_code.clone(),
        required_action: decision.required_action.as_str().to_string(),
        next_action: decision.required_action.as_str().to_string(),
        proof_source: proof_source_for_scheduler_decision(decision.decision).to_string(),
        proof_debt_class: scheduler_proof_debt_class_as_str(decision.diagnostics.proof_debt_class)
            .to_string(),
        fairness_bucket: decision.fairness_bucket.as_str().to_string(),
        stale_risk: decision.starvation_risk.as_str().to_string(),
        proof_work_key: Some(decision.diagnostics.proof_work_key_hex.clone()),
        command_digest: Some(decision.diagnostics.command_digest_hex.clone()),
        coalescer_state: decision.diagnostics.coalescer_state.as_str().to_string(),
        green_proof_eligible: decision.green_proof_eligible,
        recorder_path: decision.diagnostics.recorder_path.clone(),
        recovery_artifact_path: None,
        latest_artifact_path: decision.diagnostics.recorder_path.clone(),
        rch_slots_total: Some(decision.diagnostics.slots_total),
        rch_slots_available: Some(decision.diagnostics.slots_available),
        rch_queue_depth: Some(decision.diagnostics.queue_depth),
    }
}

fn control_tower_row_from_receipt(
    receipt: &ValidationReceipt,
    now: DateTime<Utc>,
) -> ValidationControlTowerRow {
    let valid = receipt.validate_at(now).is_ok();
    let (decision, reason_code, event_code, required_action) =
        control_tower_receipt_decision(receipt, valid);
    let readiness_ref = receipt.readiness_ref.as_ref();
    let flight_ref = receipt.flight_recorder_ref.as_ref();
    ValidationControlTowerRow {
        bead_id: receipt.bead_id.clone(),
        agent_name: receipt.trust.agent_name.clone(),
        decision: decision.to_string(),
        scheduler_decision: None,
        reason_code: readiness_ref
            .map(|ref_| ref_.reason_code.clone())
            .unwrap_or_else(|| reason_code.to_string()),
        event_code: readiness_ref
            .map(|ref_| ref_.event_code.clone())
            .unwrap_or_else(|| event_code.to_string()),
        required_action: readiness_ref
            .map(|ref_| ref_.required_action.clone())
            .unwrap_or_else(|| required_action.to_string()),
        next_action: readiness_ref
            .map(|ref_| ref_.required_action.clone())
            .unwrap_or_else(|| required_action.to_string()),
        proof_source: proof_source_for_receipt(receipt).to_string(),
        proof_debt_class: proof_debt_class_for_receipt(receipt, valid).to_string(),
        fairness_bucket: "n/a".to_string(),
        stale_risk: if valid { "none" } else { "stale_or_invalid" }.to_string(),
        proof_work_key: None,
        command_digest: Some(receipt.command_digest.hex.clone()),
        coalescer_state: "n/a".to_string(),
        green_proof_eligible: valid && matches!(receipt.exit.kind, ValidationExitKind::Success),
        recorder_path: flight_ref.map(|ref_| ref_.attempt_path.clone()),
        recovery_artifact_path: None,
        latest_artifact_path: Some(receipt.artifacts.receipt_path.clone()),
        rch_slots_total: None,
        rch_slots_available: None,
        rch_queue_depth: None,
    }
}

fn control_tower_row_from_status(status: &ValidationProofStatus) -> ValidationControlTowerRow {
    let proof_coalescer = status.proof_coalescer.as_ref();
    let proof_cache = status.proof_cache.as_ref();
    let flight_ref = status.flight_recorder_ref.as_ref();
    let readiness_ref = status.readiness_ref.as_ref();
    let decision = control_tower_status_decision(status);
    ValidationControlTowerRow {
        bead_id: status.bead_id.clone(),
        agent_name: proof_coalescer
            .and_then(|coalescer| coalescer.waiter_agent.clone())
            .or_else(|| proof_coalescer.map(|coalescer| coalescer.producer_agent.clone()))
            .unwrap_or_else(|| "unknown".to_string()),
        decision: decision.to_string(),
        scheduler_decision: None,
        reason_code: readiness_ref
            .map(|ref_| ref_.reason_code.clone())
            .or_else(|| proof_coalescer.map(|coalescer| coalescer.reason_code.clone()))
            .or_else(|| proof_cache.map(|cache| cache.reason_code.clone()))
            .unwrap_or_else(|| "VCT_STATUS_OBSERVED".to_string()),
        event_code: readiness_ref
            .map(|ref_| ref_.event_code.clone())
            .or_else(|| proof_coalescer.map(|coalescer| coalescer.event_code.clone()))
            .or_else(|| proof_cache.map(|cache| cache.event_code.clone()))
            .unwrap_or_else(|| "VCT-010".to_string()),
        required_action: readiness_ref
            .map(|ref_| ref_.required_action.clone())
            .or_else(|| proof_coalescer.map(|coalescer| coalescer.required_action.clone()))
            .or_else(|| proof_cache.map(|cache| cache.required_action.clone()))
            .unwrap_or_else(|| required_action_for_status(status).to_string()),
        next_action: readiness_ref
            .map(|ref_| ref_.required_action.clone())
            .or_else(|| proof_coalescer.map(|coalescer| coalescer.required_action.clone()))
            .or_else(|| proof_cache.map(|cache| cache.required_action.clone()))
            .unwrap_or_else(|| required_action_for_status(status).to_string()),
        proof_source: status.proof_source.as_str().to_string(),
        proof_debt_class: proof_debt_class_for_status(status).to_string(),
        fairness_bucket: "n/a".to_string(),
        stale_risk: if matches!(decision, "stale_lease") {
            "stale"
        } else {
            "none"
        }
        .to_string(),
        proof_work_key: proof_coalescer.map(|coalescer| coalescer.proof_work_key_hex.clone()),
        command_digest: status
            .command_digest
            .as_ref()
            .map(|digest| digest.hex.clone()),
        coalescer_state: proof_coalescer
            .map(|coalescer| coalescer.lease_state.clone())
            .or_else(|| status.queue_state.map(|state| state.as_str().to_string()))
            .unwrap_or_else(|| "n/a".to_string()),
        green_proof_eligible: matches!(
            status.status,
            ProofStatusKind::Passed | ProofStatusKind::Reused
        ),
        recorder_path: flight_ref.map(|ref_| ref_.attempt_path.clone()),
        recovery_artifact_path: None,
        latest_artifact_path: proof_cache
            .map(|cache| cache.receipt_path.clone())
            .or_else(|| {
                status
                    .artifact_paths
                    .as_ref()
                    .map(|paths| paths.receipt_path.clone())
            }),
        rch_slots_total: None,
        rch_slots_available: None,
        rch_queue_depth: u16::try_from(status.queue_depth).ok(),
    }
}

fn control_tower_row_for_missing_bead(bead: &TrackedValidationBead) -> ValidationControlTowerRow {
    ValidationControlTowerRow {
        bead_id: bead.bead_id.clone(),
        agent_name: "unknown".to_string(),
        decision: "no_known_proof".to_string(),
        scheduler_decision: None,
        reason_code: "VCT_NO_KNOWN_PROOF".to_string(),
        event_code: "VCT-000".to_string(),
        required_action: "record_validation_proof_or_blocker".to_string(),
        next_action: format!(
            "record validation proof or source-only blocker for {}",
            bead.normalized_thread_id()
        ),
        proof_source: "unknown".to_string(),
        proof_debt_class: "unknown".to_string(),
        fairness_bucket: "n/a".to_string(),
        stale_risk: "unknown".to_string(),
        proof_work_key: None,
        command_digest: None,
        coalescer_state: "none".to_string(),
        green_proof_eligible: false,
        recorder_path: None,
        recovery_artifact_path: None,
        latest_artifact_path: None,
        rch_slots_total: None,
        rch_slots_available: None,
        rch_queue_depth: None,
    }
}

fn proof_source_for_scheduler_decision(
    decision: ValidationSwarmSchedulerDecisionKind,
) -> &'static str {
    match decision {
        ValidationSwarmSchedulerDecisionKind::RunNow => "scheduler_run_now",
        ValidationSwarmSchedulerDecisionKind::JoinExisting => {
            ProofEvidenceSource::CoalescedWaiter.as_str()
        }
        ValidationSwarmSchedulerDecisionKind::WaitForCapacity
        | ValidationSwarmSchedulerDecisionKind::RejectLowPriority => {
            ProofEvidenceSource::BrokerQueue.as_str()
        }
        ValidationSwarmSchedulerDecisionKind::StealStaleWork => {
            ProofEvidenceSource::CoalescedInflight.as_str()
        }
        ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker => {
            ProofEvidenceSource::SourceOnlyFallback.as_str()
        }
        ValidationSwarmSchedulerDecisionKind::FailClosedProduct
        | ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact => {
            ProofEvidenceSource::Unknown.as_str()
        }
    }
}

fn scheduler_proof_debt_class_as_str(
    class: ValidationSwarmSchedulerProofDebtClass,
) -> &'static str {
    match class {
        ValidationSwarmSchedulerProofDebtClass::None => "none",
        ValidationSwarmSchedulerProofDebtClass::WorkerInfra => "worker_infra",
        ValidationSwarmSchedulerProofDebtClass::Capacity => "capacity",
        ValidationSwarmSchedulerProofDebtClass::StaleProducer => "stale_producer",
        ValidationSwarmSchedulerProofDebtClass::SourceOnly => "source_only",
        ValidationSwarmSchedulerProofDebtClass::ProductFailure => "product_failure",
        ValidationSwarmSchedulerProofDebtClass::InvalidArtifact => "invalid_artifact",
    }
}

fn proof_source_for_receipt(receipt: &ValidationReceipt) -> &'static str {
    if matches!(receipt.exit.kind, ValidationExitKind::SourceOnly)
        || receipt.classifications.source_only_fallback
    {
        ProofEvidenceSource::SourceOnlyFallback.as_str()
    } else {
        ProofEvidenceSource::FreshExecution.as_str()
    }
}

fn control_tower_receipt_decision(
    receipt: &ValidationReceipt,
    valid: bool,
) -> (&'static str, &'static str, &'static str, &'static str) {
    if !valid {
        return (
            "invalid_artifact",
            "VCT_RECEIPT_INVALID",
            "VCT-004",
            "refresh_or_reject_receipt",
        );
    }
    match receipt.exit.kind {
        ValidationExitKind::Success => (
            "green_proof",
            "VCT_RECEIPT_GREEN",
            "VCT-001",
            "reuse_green_receipt",
        ),
        ValidationExitKind::SourceOnly => (
            "source_only",
            "VCT_RECEIPT_SOURCE_ONLY",
            "VCT-002",
            "record_source_only_blocker",
        ),
        _ if failure_domain_for_receipt(receipt) == ValidationFailureDomain::Product => (
            "product_failure",
            "VCT_RECEIPT_PRODUCT_FAILURE",
            "VCT-003",
            "surface_product_failure",
        ),
        _ => (
            "worker_infrastructure",
            "VCT_RECEIPT_WORKER_INFRA",
            "VCT-005",
            "retry_remote_or_record_blocker",
        ),
    }
}

fn proof_debt_class_for_receipt(receipt: &ValidationReceipt, valid: bool) -> &'static str {
    if !valid {
        "invalid_artifact"
    } else if matches!(receipt.exit.kind, ValidationExitKind::SourceOnly)
        || receipt.classifications.source_only_fallback
    {
        "source_only"
    } else {
        match failure_domain_for_receipt(receipt) {
            ValidationFailureDomain::None => "none",
            ValidationFailureDomain::Product => "product_failure",
            ValidationFailureDomain::Worker => "worker_infra",
            ValidationFailureDomain::Resource => "capacity",
            ValidationFailureDomain::Unknown => "unknown",
        }
    }
}

fn control_tower_status_decision(status: &ValidationProofStatus) -> &'static str {
    match status.status {
        ProofStatusKind::Passed | ProofStatusKind::Reused => "green_proof",
        ProofStatusKind::Queued => "queued",
        ProofStatusKind::Leased => {
            if status
                .proof_coalescer
                .as_ref()
                .is_some_and(|coalescer| coalescer.lease_state == "stale")
            {
                "stale_lease"
            } else {
                "leased"
            }
        }
        ProofStatusKind::Running => "running",
        ProofStatusKind::SourceOnly => "source_only",
        ProofStatusKind::Failed => {
            if status.exit.as_ref().is_some_and(|exit| {
                failure_domain_for_exit(exit) == ValidationFailureDomain::Product
            }) {
                "product_failure"
            } else {
                "worker_infrastructure"
            }
        }
        ProofStatusKind::Cancelled => "worker_infrastructure",
        ProofStatusKind::Unknown => "no_known_proof",
    }
}

fn required_action_for_status(status: &ValidationProofStatus) -> &'static str {
    match status.status {
        ProofStatusKind::Passed | ProofStatusKind::Reused => "reuse_green_receipt",
        ProofStatusKind::Queued | ProofStatusKind::Leased | ProofStatusKind::Running => {
            "wait_for_validation_result"
        }
        ProofStatusKind::SourceOnly => "record_source_only_blocker",
        ProofStatusKind::Failed | ProofStatusKind::Cancelled => "record_blocker_and_retry",
        ProofStatusKind::Unknown => "record_validation_proof_or_blocker",
    }
}

fn proof_debt_class_for_status(status: &ValidationProofStatus) -> &'static str {
    match control_tower_status_decision(status) {
        "green_proof" => {
            if status.proof_source == ProofEvidenceSource::ProofCacheHit {
                "proof_cache_reuse"
            } else {
                "none"
            }
        }
        "queued" => "waiting_for_capacity",
        "leased" | "running" => "worker_infra",
        "stale_lease" => "stale_lease",
        "source_only" => "source_only",
        "product_failure" => "product_failure",
        "worker_infrastructure" => "worker_infra",
        _ => "unknown",
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

fn evaluate_proof_coalescer_check(
    summary: &ValidationReadinessSummary,
) -> ValidationReadinessCheck {
    if summary.proof_coalescer.stale_leases > 0 || summary.proof_coalescer.rejected > 0 {
        return check(
            "VR-PROOF-COALESCER-009",
            "VPCO-006",
            "validation_proof_coalescer.lease_state",
            ValidationReadinessStatus::Fail,
            format!(
                "Validation proof coalescer has fail-closed lease decisions (stale={} fenced={} rejected={} capacity_rejections={}).",
                summary.proof_coalescer.stale_leases,
                summary.proof_coalescer.fenced_leases,
                summary.proof_coalescer.rejected,
                summary.proof_coalescer.capacity_rejections
            ),
            "Repair or fence stale/malformed leases before launching or joining cargo proof work.",
        );
    }
    if summary.proof_coalescer.active_work() > 0 {
        return check(
            "VR-PROOF-COALESCER-009",
            "VPCO-003",
            "validation_proof_coalescer.lease_state",
            ValidationReadinessStatus::Warn,
            format!(
                "Validation proof coalescer has active shared proof work (producers={} waiters={}).",
                summary.proof_coalescer.producer_proofs, summary.proof_coalescer.waiters
            ),
            "Join or wait for the existing lease instead of launching duplicate RCH cargo validation.",
        );
    }
    if summary.proof_coalescer.cache_handoffs > 0 {
        return check(
            "VR-PROOF-COALESCER-009",
            "VPCO-010",
            "validation_proof_coalescer.lease_state",
            ValidationReadinessStatus::Pass,
            format!(
                "Validation proof coalescer completed {} cache handoff(s).",
                summary.proof_coalescer.cache_handoffs
            ),
            "No action required.",
        );
    }

    check(
        "VR-PROOF-COALESCER-009",
        "VPCO-001",
        "validation_proof_coalescer.lease_state",
        ValidationReadinessStatus::Pass,
        "No validation proof coalescer decisions were supplied.",
        "No action required.",
    )
}

#[must_use]
pub fn summarize_swarm_admission_decisions(
    decisions: &[SwarmValidationAdmissionDecisionRecord],
) -> SwarmAdmissionReadinessSummary {
    let mut summary = SwarmAdmissionReadinessSummary {
        decisions: decisions.len(),
        decision_details: decisions
            .iter()
            .map(summarize_swarm_admission_decision)
            .collect::<Vec<_>>(),
        ..SwarmAdmissionReadinessSummary::default()
    };

    for decision in decisions {
        match decision.decision {
            SwarmValidationAdmissionDecision::Run => {
                summary.run = summary.run.saturating_add(1);
            }
            SwarmValidationAdmissionDecision::Coalesce => {
                summary.coalesce = summary.coalesce.saturating_add(1);
            }
            SwarmValidationAdmissionDecision::Defer => {
                summary.defer = summary.defer.saturating_add(1);
            }
            SwarmValidationAdmissionDecision::Handoff => {
                summary.handoff = summary.handoff.saturating_add(1);
            }
            SwarmValidationAdmissionDecision::Blocked => {
                summary.blocked = summary.blocked.saturating_add(1);
            }
        }
        if !decision.diagnostics.input_freshness.fresh {
            summary.stale_inputs = summary.stale_inputs.saturating_add(1);
        }
        if decision.fail_closed {
            summary.fail_closed = summary.fail_closed.saturating_add(1);
        }
        if decision.green_proof_eligible {
            summary.green_proof_eligible = summary.green_proof_eligible.saturating_add(1);
        }
        summary.rch_jobs_budgeted = summary
            .rch_jobs_budgeted
            .saturating_add(decision.execution_hints.lane_budget.max_parallel_rch_jobs);
    }

    summary
}

fn summarize_swarm_admission_decision(
    decision: &SwarmValidationAdmissionDecisionRecord,
) -> SwarmAdmissionDecisionSummary {
    SwarmAdmissionDecisionSummary {
        trace_id: decision.trace_id.clone(),
        bead_id: decision.bead_id.clone(),
        thread_id: decision.thread_id.clone(),
        agent: decision.agent_name.clone(),
        decision: decision.decision.as_str().to_string(),
        reason_code: decision.reason_code.clone(),
        event_code: decision.event_code.clone(),
        required_action: decision.required_action.clone(),
        next_action: decision.required_action.clone(),
        input_fresh: decision.diagnostics.input_freshness.fresh,
        proof_work_key: decision.execution_hints.coalescing_key.clone(),
        command_digest: decision
            .coalescing_target
            .as_ref()
            .and_then(|target| target.command_digest.clone()),
        owner_agent: decision
            .coalescing_target
            .as_ref()
            .and_then(|target| target.owner_agent.clone()),
        safe_command_shape: decision.safe_command_shape.clone(),
        target_dir_strategy: target_dir_strategy_as_str(
            decision.execution_hints.target_dir_strategy,
        )
        .to_string(),
        target_dir: decision.execution_hints.target_dir.clone(),
        worker_requirement: worker_requirement_as_str(decision.execution_hints.worker_requirement)
            .to_string(),
        max_parallel_rch_jobs: decision.execution_hints.lane_budget.max_parallel_rch_jobs,
        retry_after_ms: decision
            .retry_after_ms
            .or(decision.execution_hints.lane_budget.retry_after_ms),
        green_proof_eligible: decision.green_proof_eligible,
        retryable: decision.retryable,
        fail_closed: decision.fail_closed,
    }
}

const fn target_dir_strategy_as_str(strategy: SwarmValidationTargetDirStrategy) -> &'static str {
    match strategy {
        SwarmValidationTargetDirStrategy::NoTargetDirRequired => "no_target_dir_required",
        SwarmValidationTargetDirStrategy::ReuseIsolated => "reuse_isolated",
        SwarmValidationTargetDirStrategy::CreateUniqueTemp => "create_unique_temp",
        SwarmValidationTargetDirStrategy::JoinExistingProofLease => "join_existing_proof_lease",
        SwarmValidationTargetDirStrategy::DeferForTargetDirLease => "defer_for_target_dir_lease",
        SwarmValidationTargetDirStrategy::DeferForDiskPressure => "defer_for_disk_pressure",
    }
}

const fn worker_requirement_as_str(requirement: SwarmValidationWorkerRequirement) -> &'static str {
    match requirement {
        SwarmValidationWorkerRequirement::SourceOnlyLocal => "source_only_local",
        SwarmValidationWorkerRequirement::RequireHealthyRemote => "require_healthy_remote",
        SwarmValidationWorkerRequirement::PreferHighMemoryRemote => "prefer_high_memory_remote",
        SwarmValidationWorkerRequirement::WaitForRchCapacity => "wait_for_rch_capacity",
        SwarmValidationWorkerRequirement::RestoreRchBeforeCargo => "restore_rch_before_cargo",
    }
}

#[must_use]
pub fn summarize_swarm_scheduler_decisions(
    decisions: &[ValidationSwarmSchedulerDecision],
) -> SwarmSchedulerReadinessSummary {
    if decisions.is_empty() {
        return SwarmSchedulerReadinessSummary::default();
    }

    let mut queue_ages = decisions
        .iter()
        .map(|decision| decision.diagnostics.queue_age_ms)
        .collect::<Vec<_>>();
    queue_ages.sort_unstable();
    let p95_index = queue_ages
        .len()
        .saturating_mul(95)
        .saturating_add(99)
        .checked_div(100)
        .unwrap_or(1)
        .saturating_sub(1)
        .min(queue_ages.len().saturating_sub(1));
    let queue_age_p95_ms = queue_ages[p95_index];
    let queue_age_max_ms = queue_ages.last().copied().unwrap_or(0);

    let slots_total = decisions.iter().fold(0_u64, |total, decision| {
        total.saturating_add(u64::from(decision.diagnostics.slots_total))
    });
    let slots_available = decisions.iter().fold(0_u64, |total, decision| {
        total.saturating_add(u64::from(decision.diagnostics.slots_available))
    });
    let slot_utilization = if slots_total == 0 {
        0.0
    } else {
        slots_total.saturating_sub(slots_available) as f64 / slots_total as f64
    };

    let mut bucket_counts = BTreeMap::<&'static str, usize>::new();
    for decision in decisions {
        let bucket = decision.fairness_bucket.as_str();
        *bucket_counts.entry(bucket).or_default() += 1;
    }
    let fairness_index = fairness_index(bucket_counts.values().copied());

    let decision_details = decisions
        .iter()
        .map(summarize_swarm_scheduler_decision)
        .collect::<Vec<_>>();
    let breached_decisions = decision_details
        .iter()
        .filter(|decision| decision.slo_breached)
        .count();
    let capacity_waits = decisions
        .iter()
        .filter(|decision| {
            matches!(
                decision.decision,
                ValidationSwarmSchedulerDecisionKind::WaitForCapacity
            )
        })
        .count();
    let work_steals = decisions
        .iter()
        .filter(|decision| {
            matches!(
                decision.decision,
                ValidationSwarmSchedulerDecisionKind::StealStaleWork
            )
        })
        .count();
    let source_only_blockers = decisions
        .iter()
        .filter(|decision| {
            matches!(
                decision.decision,
                ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker
            )
        })
        .count();
    let product_failures = decisions
        .iter()
        .filter(|decision| {
            matches!(
                decision.decision,
                ValidationSwarmSchedulerDecisionKind::FailClosedProduct
            )
        })
        .count();
    let worker_infra_retries = decisions
        .iter()
        .filter(|decision| {
            decision.retryable
                && matches!(
                    decision.decision,
                    ValidationSwarmSchedulerDecisionKind::WaitForCapacity
                        | ValidationSwarmSchedulerDecisionKind::StealStaleWork
                )
        })
        .count();

    let slo_breach_status = if breached_decisions > 0 {
        SwarmSchedulerSloBreachStatus::Breach
    } else if capacity_waits > 0 || work_steals > 0 || source_only_blockers > 0 {
        SwarmSchedulerSloBreachStatus::Warn
    } else {
        SwarmSchedulerSloBreachStatus::Pass
    };

    SwarmSchedulerReadinessSummary {
        decisions: decisions.len(),
        queue_age_p95_ms,
        queue_age_max_ms,
        slot_utilization,
        fairness_index,
        slo_breach_status,
        breached_decisions,
        capacity_waits,
        work_steals,
        source_only_blockers,
        product_failures,
        worker_infra_retries,
        decision_details,
    }
}

fn summarize_swarm_scheduler_decision(
    decision: &ValidationSwarmSchedulerDecision,
) -> SwarmSchedulerDecisionSummary {
    let required_action = decision.required_action.as_str().to_string();
    SwarmSchedulerDecisionSummary {
        trace_id: decision.trace_id.clone(),
        bead_id: decision.bead_id.clone(),
        agent: decision.agent_name.clone(),
        proof_work_key: decision.diagnostics.proof_work_key_hex.clone(),
        scheduler_decision: decision.decision.as_str().to_string(),
        reason_code: decision.reason_code.clone(),
        event_code: decision.event_code.clone(),
        required_action: required_action.clone(),
        next_action: required_action,
        fairness_bucket: decision.fairness_bucket.as_str().to_string(),
        starvation_risk: decision.starvation_risk.as_str().to_string(),
        queue_age_ms: decision.diagnostics.queue_age_ms,
        worker_id: None,
        coalescer_state: decision.diagnostics.coalescer_state.as_str().to_string(),
        recorder_path: decision.diagnostics.recorder_path.clone(),
        slo_breached: swarm_scheduler_decision_breaches_slo(decision),
        retryable: decision.retryable,
        fail_closed: decision.fail_closed,
    }
}

fn swarm_scheduler_decision_breaches_slo(decision: &ValidationSwarmSchedulerDecision) -> bool {
    decision.starvation_risk.breaches_slo()
        || decision.fail_closed
        || matches!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::FailClosedProduct
                | ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact
        )
}

fn fairness_index(counts: impl IntoIterator<Item = usize>) -> f64 {
    let mut bucket_count = 0_u64;
    let mut total = 0_u64;
    let mut sum_squares = 0_u64;
    for count in counts {
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        if count == 0 {
            continue;
        }
        bucket_count = bucket_count.saturating_add(1);
        total = total.saturating_add(count);
        sum_squares = sum_squares.saturating_add(count.saturating_mul(count));
    }
    if bucket_count <= 1 || total == 0 || sum_squares == 0 {
        1.0
    } else {
        let numerator = total.saturating_mul(total) as f64;
        let denominator = bucket_count.saturating_mul(sum_squares) as f64;
        numerator / denominator
    }
}

fn evaluate_swarm_scheduler_slo_check(
    summary: &ValidationReadinessSummary,
) -> ValidationReadinessCheck {
    match summary.swarm_scheduler.slo_breach_status {
        SwarmSchedulerSloBreachStatus::NoData => check(
            "VR-SWARM-SCHEDULER-010",
            "VSS-001",
            "validation_swarm_scheduler.slo",
            ValidationReadinessStatus::Pass,
            "No swarm-scheduler decisions were supplied.",
            "No action required.",
        ),
        SwarmSchedulerSloBreachStatus::Pass => check(
            "VR-SWARM-SCHEDULER-010",
            "VSS-001",
            "validation_swarm_scheduler.slo",
            ValidationReadinessStatus::Pass,
            format!(
                "Swarm scheduler SLOs are within bounds (decisions={}, queue_age_p95_ms={}, slot_utilization={:.3}, fairness_index={:.3}).",
                summary.swarm_scheduler.decisions,
                summary.swarm_scheduler.queue_age_p95_ms,
                summary.swarm_scheduler.slot_utilization,
                summary.swarm_scheduler.fairness_index
            ),
            "No action required.",
        ),
        SwarmSchedulerSloBreachStatus::Warn => check(
            "VR-SWARM-SCHEDULER-010",
            "VSS-002",
            "validation_swarm_scheduler.slo",
            ValidationReadinessStatus::Warn,
            format!(
                "Swarm scheduler is deferring or rerouting proof work (capacity_waits={}, work_steals={}, source_only_blockers={}, queue_age_p95_ms={}).",
                summary.swarm_scheduler.capacity_waits,
                summary.swarm_scheduler.work_steals,
                summary.swarm_scheduler.source_only_blockers,
                summary.swarm_scheduler.queue_age_p95_ms
            ),
            "Wait, join, steal, retry, or record source-only blocker according to each scheduler next_action.",
        ),
        SwarmSchedulerSloBreachStatus::Breach => check(
            "VR-SWARM-SCHEDULER-010",
            "VSS-003",
            "validation_swarm_scheduler.slo",
            ValidationReadinessStatus::Fail,
            format!(
                "Swarm scheduler SLO breach detected (breached_decisions={}, product_failures={}, queue_age_p95_ms={}, fairness_index={:.3}).",
                summary.swarm_scheduler.breached_decisions,
                summary.swarm_scheduler.product_failures,
                summary.swarm_scheduler.queue_age_p95_ms,
                summary.swarm_scheduler.fairness_index
            ),
            "Do not count breached scheduler decisions as green proof; surface product/source-only failures or refresh capacity evidence.",
        ),
    }
}

fn evaluate_swarm_admission_check(
    summary: &ValidationReadinessSummary,
) -> ValidationReadinessCheck {
    let admission = &summary.swarm_admission;
    if admission.decisions == 0 {
        return check(
            "VR-SWARM-ADMISSION-011",
            "SVA-000",
            "validation_swarm_admission.decisions",
            ValidationReadinessStatus::Pass,
            "No swarm-admission decisions were supplied.",
            "No action required.",
        );
    }

    let failing = admission
        .decision_details
        .iter()
        .filter(|decision| {
            decision.fail_closed || !decision.input_fresh || decision.decision == "blocked"
        })
        .collect::<Vec<_>>();
    if let Some(first_failing) = failing.first() {
        let labels = failing
            .iter()
            .map(|decision| swarm_admission_decision_label(decision))
            .collect::<Vec<_>>()
            .join(",");
        return check(
            "VR-SWARM-ADMISSION-011",
            first_failing.event_code.clone(),
            "validation_swarm_admission.decisions",
            ValidationReadinessStatus::Fail,
            format!("Swarm admission refuses or cannot trust validation launch for {labels}."),
            "Follow each admission required_action; refresh stale inputs before launching or counting proof evidence.",
        );
    }

    let waiting = admission
        .decision_details
        .iter()
        .filter(|decision| matches!(decision.decision.as_str(), "defer" | "handoff"))
        .collect::<Vec<_>>();
    if let Some(first_waiting) = waiting.first() {
        let labels = waiting
            .iter()
            .map(|decision| swarm_admission_decision_label(decision))
            .collect::<Vec<_>>()
            .join(",");
        return check(
            "VR-SWARM-ADMISSION-011",
            first_waiting.event_code.clone(),
            "validation_swarm_admission.decisions",
            ValidationReadinessStatus::Warn,
            format!("Swarm admission is deferring or handing off validation work for {labels}."),
            "Wait, request handoff, reuse target-dir evidence, or join existing proof according to each next_action.",
        );
    }

    check(
        "VR-SWARM-ADMISSION-011",
        "SVA-001",
        "validation_swarm_admission.decisions",
        ValidationReadinessStatus::Pass,
        format!(
            "Swarm admission permits validation progress (run={}, coalesce={}, rch_jobs_budgeted={}).",
            admission.run, admission.coalesce, admission.rch_jobs_budgeted
        ),
        "No action required.",
    )
}

fn swarm_admission_decision_label(decision: &SwarmAdmissionDecisionSummary) -> String {
    format!(
        "{}:{}:{}",
        decision.bead_id, decision.reason_code, decision.next_action
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

fn evaluate_proof_lane_readiness_check(
    summary: &ValidationReadinessSummary,
) -> ValidationReadinessCheck {
    if summary.proof_lane_readiness.is_empty() {
        return check(
            "VR-PROOF-LANE-008",
            "PLR-001",
            "proof_lane_readiness.preflight",
            ValidationReadinessStatus::Pass,
            "No proof-lane readiness capsules were supplied.",
            "No action required.",
        );
    }

    let mut fail_closed = summary
        .proof_lane_readiness
        .iter()
        .filter(|capsule| capsule.fail_closed);
    if let Some(first_blocker) = fail_closed.next() {
        let mut blockers = vec![proof_lane_blocker_label(first_blocker)];
        blockers.extend(fail_closed.map(proof_lane_blocker_label));
        let blockers = blockers.join(",");
        return check(
            "VR-PROOF-LANE-008",
            first_blocker.event_code.clone(),
            "proof_lane_readiness.preflight",
            ValidationReadinessStatus::Fail,
            format!("Proof-lane readiness refuses launch for {blockers}."),
            "Follow each proof-lane required_action before counting cargo proof output as green evidence.",
        );
    }

    let mut retryable = summary.proof_lane_readiness.iter().filter(|capsule| {
        !matches!(
            capsule.decision,
            ProofLaneReadinessDecisionKind::ReadyToLaunch
        )
    });
    if let Some(first_retryable) = retryable.next() {
        let mut queued = vec![proof_lane_blocker_label(first_retryable)];
        queued.extend(retryable.map(proof_lane_blocker_label));
        let queued = queued.join(",");
        return check(
            "VR-PROOF-LANE-008",
            first_retryable.event_code.clone(),
            "proof_lane_readiness.preflight",
            ValidationReadinessStatus::Warn,
            format!("Proof-lane readiness is not launch-ready for {queued}."),
            "Refresh readiness or wait for worker pressure to clear before launching cargo proof.",
        );
    }

    check(
        "VR-PROOF-LANE-008",
        "PLR-001",
        "proof_lane_readiness.preflight",
        ValidationReadinessStatus::Pass,
        "Proof-lane readiness permits remote cargo proof launch.",
        "No action required.",
    )
}

fn proof_lane_blocker_label(capsule: &ProofLaneReadinessSummary) -> String {
    format!(
        "{}:{}:{}",
        capsule.capsule_id, capsule.reason_code, capsule.required_action
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

fn increment_proof_coalescer_count(
    counts: &mut ProofCoalescerCounts,
    status: &ValidationProofStatus,
) {
    match status.proof_source {
        ProofEvidenceSource::CoalescedInflight => {
            counts.producer_proofs = counts.producer_proofs.saturating_add(1);
        }
        ProofEvidenceSource::CoalescedWaiter => {
            counts.waiters = counts.waiters.saturating_add(1);
        }
        ProofEvidenceSource::CoalescedCompleted => {
            counts.cache_handoffs = counts.cache_handoffs.saturating_add(1);
        }
        ProofEvidenceSource::CoalescerRejected => {
            counts.rejected = counts.rejected.saturating_add(1);
        }
        ProofEvidenceSource::Unknown
        | ProofEvidenceSource::BrokerQueue
        | ProofEvidenceSource::FreshExecution
        | ProofEvidenceSource::SourceOnlyFallback
        | ProofEvidenceSource::ProofCacheHit => {}
    }

    let Some(evidence) = &status.proof_coalescer else {
        return;
    };
    let stale_decision = matches!(evidence.lease_state.as_str(), "stale")
        || matches!(
            evidence.reason_code.as_str(),
            "VPCO_RETRY_STALE" | "VPCO_WAIT_FRESH_PRODUCER" | "VPCO_INSUFFICIENT_STALE_EVIDENCE"
        );
    if stale_decision {
        counts.stale_leases = counts.stale_leases.saturating_add(1);
    }
    if matches!(evidence.lease_state.as_str(), "fenced") {
        counts.fenced_leases = counts.fenced_leases.saturating_add(1);
    }
    if matches!(evidence.reason_code.as_str(), "VPCO_REJECT_CAPACITY") {
        counts.capacity_rejections = counts.capacity_rejections.saturating_add(1);
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

fn flight_outcome_class_as_str(outcome_class: FlightRecorderAdapterOutcomeClass) -> &'static str {
    match outcome_class {
        FlightRecorderAdapterOutcomeClass::Passed => "passed",
        FlightRecorderAdapterOutcomeClass::CommandFailed => "command_failed",
        FlightRecorderAdapterOutcomeClass::CompileFailed => "compile_failed",
        FlightRecorderAdapterOutcomeClass::TestFailed => "test_failed",
        FlightRecorderAdapterOutcomeClass::WorkerTimeout => "worker_timeout",
        FlightRecorderAdapterOutcomeClass::WorkerMissingToolchain => "worker_missing_toolchain",
        FlightRecorderAdapterOutcomeClass::WorkerFilesystemError => "worker_filesystem_error",
        FlightRecorderAdapterOutcomeClass::LocalFallbackRefused => "local_fallback_refused",
        FlightRecorderAdapterOutcomeClass::ContentionDeferred => "contention_deferred",
        FlightRecorderAdapterOutcomeClass::BrokerInternalError => "broker_internal_error",
    }
}

fn rch_mode_as_str(mode: RchMode) -> &'static str {
    match mode {
        RchMode::Remote => "remote",
        RchMode::LocalFallback => "local_fallback",
        RchMode::NotUsed => "not_used",
        RchMode::Unavailable => "unavailable",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadinessRecoveryDecision {
    action: RecoveryAction,
    reason_code: String,
    required_action: String,
    retry_after_ms: Option<u64>,
    worker_preference: Option<String>,
}

fn recovery_decision_for_exit(
    exit: &ValidationExit,
    _proof_kind: &str,
) -> ReadinessRecoveryDecision {
    match exit.kind {
        ValidationExitKind::Success => readiness_recovery_decision(
            RecoveryAction::NoRecoveryNeeded,
            reason_codes::NO_RECOVERY_NEEDED,
            "continue proof verification",
            None,
        ),
        ValidationExitKind::SourceOnly => readiness_recovery_decision(
            RecoveryAction::UseSourceOnlyBlocker,
            reason_codes::USE_SOURCE_ONLY_BLOCKER,
            "keep source-only validation blocker",
            None,
        ),
        ValidationExitKind::Cancelled => readiness_recovery_decision(
            RecoveryAction::FailClosed,
            reason_codes::FAIL_CLOSED,
            "manual intervention required for cancelled validation",
            None,
        ),
        ValidationExitKind::Timeout => recovery_decision_for_timeout(exit.timeout_class),
        ValidationExitKind::Failed => recovery_decision_for_error(exit),
    }
}

fn recovery_decision_for_timeout(timeout_class: TimeoutClass) -> ReadinessRecoveryDecision {
    match timeout_class {
        TimeoutClass::QueueWait => readiness_recovery_decision(
            RecoveryAction::QueueUntilCapacity,
            reason_codes::QUEUE_UNTIL_CAPACITY,
            "queue validation until worker capacity is available",
            Some(120_000),
        ),
        TimeoutClass::CargoTestTimeout | TimeoutClass::ProcessWall => readiness_recovery_decision(
            RecoveryAction::RetryRemoteSameWorker,
            reason_codes::RETRY_REMOTE_SAME_WORKER,
            "retry remote validation",
            Some(60_000),
        ),
        TimeoutClass::ProcessIdle => readiness_recovery_decision(
            RecoveryAction::DrainWorkerThenRetry,
            reason_codes::DRAIN_WORKER_THEN_RETRY,
            "drain worker and retry validation",
            Some(120_000),
        ),
        TimeoutClass::None
        | TimeoutClass::RchDispatch
        | TimeoutClass::SshCommand
        | TimeoutClass::WorkerUnreachable
        | TimeoutClass::Unknown => readiness_recovery_decision(
            RecoveryAction::RetryRemoteDifferentWorker,
            reason_codes::RETRY_REMOTE_DIFFERENT_WORKER,
            "retry validation on a different worker",
            Some(45_000),
        ),
    }
}

fn recovery_decision_for_error(exit: &ValidationExit) -> ReadinessRecoveryDecision {
    match exit.error_class {
        ValidationErrorClass::CompileError
        | ValidationErrorClass::TestFailure
        | ValidationErrorClass::ClippyWarning
        | ValidationErrorClass::FormatFailure => readiness_recovery_decision(
            RecoveryAction::FailClosed,
            reason_codes::FAIL_CLOSED,
            "fix product validation failure before retrying",
            None,
        ),
        ValidationErrorClass::TransportTimeout | ValidationErrorClass::WorkerInfra => {
            readiness_recovery_decision(
                RecoveryAction::RetryRemoteDifferentWorker,
                reason_codes::RETRY_REMOTE_DIFFERENT_WORKER,
                "retry validation on a different worker",
                Some(45_000),
            )
        }
        ValidationErrorClass::EnvironmentContention => readiness_recovery_decision(
            RecoveryAction::QueueUntilCapacity,
            reason_codes::QUEUE_UNTIL_CAPACITY,
            "queue validation until capacity is available",
            Some(120_000),
        ),
        ValidationErrorClass::DiskPressure => readiness_recovery_decision(
            RecoveryAction::DrainWorkerThenRetry,
            reason_codes::DRAIN_WORKER_THEN_RETRY,
            "drain storage-pressured worker and retry validation",
            Some(120_000),
        ),
        ValidationErrorClass::SourceOnly | ValidationErrorClass::None => {
            readiness_recovery_decision(
                RecoveryAction::UseSourceOnlyBlocker,
                reason_codes::USE_SOURCE_ONLY_BLOCKER,
                "use source-only validation blocker",
                None,
            )
        }
        ValidationErrorClass::Unknown if exit.retryable => readiness_recovery_decision(
            RecoveryAction::RetryRemoteDifferentWorker,
            reason_codes::RETRY_REMOTE_DIFFERENT_WORKER,
            "retry unknown validation failure on a different worker",
            Some(45_000),
        ),
        ValidationErrorClass::Unknown => readiness_recovery_decision(
            RecoveryAction::FailClosed,
            reason_codes::FAIL_CLOSED,
            "manual intervention required for unknown validation failure",
            None,
        ),
    }
}

fn readiness_recovery_decision(
    action: RecoveryAction,
    reason_code: &str,
    required_action: &str,
    retry_after_ms: Option<u64>,
) -> ReadinessRecoveryDecision {
    ReadinessRecoveryDecision {
        action,
        reason_code: reason_code.to_string(),
        required_action: required_action.to_string(),
        retry_after_ms,
        worker_preference: None,
    }
}

fn recovery_action_is_retryable(action: RecoveryAction) -> bool {
    matches!(
        action,
        RecoveryAction::RetryRemoteSameWorker
            | RecoveryAction::RetryRemoteDifferentWorker
            | RecoveryAction::QueueUntilCapacity
            | RecoveryAction::DrainWorkerThenRetry
            | RecoveryAction::WaitForExistingProof
    )
}

fn failure_domain_for_receipt(receipt: &ValidationReceipt) -> ValidationFailureDomain {
    failure_domain_for_exit(&receipt.exit)
}

fn failure_domain_for_exit(exit: &ValidationExit) -> ValidationFailureDomain {
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
    if now >= input.freshness_expires_at {
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
            .is_none_or(|expires_at| now >= expires_at)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReadinessFixtureCatalog {
    pub schema_version: String,
    pub fixtures: Vec<ValidationReadinessFixture>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[cfg(test)]
mod fail_closed_boundary_tests {
    use super::*;
    use crate::ops::validation_readiness::validation_proof_capabilities::ValidationProofCapabilitySnapshot;

    #[test]
    fn test_freshness_expires_at_boundary_fail_closed() {
        // Test the fix for bd-jlt7p: freshness_expires_at check should use >= for fail-closed semantics
        let trace_id = "test_trace_boundary";
        let expires_at = 1000u64;

        // Test case 1: exactly at expiry time should FAIL (fail-closed)
        let input_at_expiry = ProofLaneReadinessInput {
            schema_version: PROOF_LANE_READINESS_INPUT_SCHEMA_VERSION.to_string(),
            freshness_expires_at: expires_at,
        };

        let decision_at_expiry =
            classify_proof_lane_decision(&input_at_expiry, expires_at, trace_id);
        assert_eq!(
            decision_at_expiry.kind,
            ProofLaneReadinessDecisionKind::FailClosed,
            "At exactly expiry time t={}, should fail closed",
            expires_at
        );
        assert_eq!(
            decision_at_expiry.reason_code,
            proof_lane_reason_codes::STALE_READINESS_CAPSULE
        );

        // Test case 2: one nanosecond before expiry should PASS
        let now_before_expiry = expires_at - 1;
        let decision_before_expiry =
            classify_proof_lane_decision(&input_at_expiry, now_before_expiry, trace_id);
        assert_ne!(
            decision_before_expiry.kind,
            ProofLaneReadinessDecisionKind::FailClosed,
            "At t={} (1 before expiry), should not fail closed",
            now_before_expiry
        );
        assert_ne!(
            decision_before_expiry.reason_code,
            proof_lane_reason_codes::STALE_READINESS_CAPSULE
        );

        // Test case 3: one after expiry should definitely FAIL
        let now_after_expiry = expires_at + 1;
        let decision_after_expiry =
            classify_proof_lane_decision(&input_at_expiry, now_after_expiry, trace_id);
        assert_eq!(
            decision_after_expiry.kind,
            ProofLaneReadinessDecisionKind::FailClosed,
            "At t={} (1 after expiry), should fail closed",
            now_after_expiry
        );
        assert_eq!(
            decision_after_expiry.reason_code,
            proof_lane_reason_codes::STALE_READINESS_CAPSULE
        );
    }

    #[test]
    fn test_capability_freshness_expires_at_boundary_fail_closed() {
        // Test the fix for bd-jlt7p: capability freshness check should use >= for fail-closed semantics
        let expires_at = 2000u64;

        let capability_with_expiry = ValidationProofCapabilitySnapshot {
            capability_name: "test_capability".to_string(),
            status: "active".to_string(),
            observed_at: Some(expires_at - 100), // Observed before expiry
            freshness_expires_at: Some(expires_at),
        };

        // Test case 1: exactly at expiry time should be STALE (fail-closed)
        let is_stale_at_expiry =
            capability_snapshot_unknown_or_stale(&capability_with_expiry, expires_at);
        assert!(
            is_stale_at_expiry,
            "At exactly expiry time t={}, capability should be stale (fail-closed)",
            expires_at
        );

        // Test case 2: one nanosecond before expiry should NOT be stale
        let now_before_expiry = expires_at - 1;
        let is_stale_before_expiry =
            capability_snapshot_unknown_or_stale(&capability_with_expiry, now_before_expiry);
        assert!(
            !is_stale_before_expiry,
            "At t={} (1 before expiry), capability should not be stale",
            now_before_expiry
        );

        // Test case 3: one after expiry should definitely be STALE
        let now_after_expiry = expires_at + 1;
        let is_stale_after_expiry =
            capability_snapshot_unknown_or_stale(&capability_with_expiry, now_after_expiry);
        assert!(
            is_stale_after_expiry,
            "At t={} (1 after expiry), capability should be stale",
            now_after_expiry
        );

        // Test case 4: None expiry should be stale (always fail-closed when no expiry)
        let capability_no_expiry = ValidationProofCapabilitySnapshot {
            capability_name: "test_capability".to_string(),
            status: "active".to_string(),
            observed_at: Some(expires_at),
            freshness_expires_at: None,
        };
        let is_stale_no_expiry =
            capability_snapshot_unknown_or_stale(&capability_no_expiry, expires_at);
        assert!(
            is_stale_no_expiry,
            "Capability with no expiry time should always be stale (fail-closed)"
        );
    }
}
