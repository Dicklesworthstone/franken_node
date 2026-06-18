//! Deterministic fixture model for swarm validation admission.
//!
//! This module is intentionally pure. It does not read Beads, Agent Mail, RCH,
//! or the filesystem; callers provide already-collected snapshots and tests can
//! exercise the same canonical input shape without host-specific probes.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::push_bounded;
use crate::security::constant_time;

use super::{
    validation_planner::{
        ValidationShardProofEvidence, ValidationShardRchQueueState, ValidationShardStatus,
    },
    validation_proof_cache::{ValidationProofCacheDecision, ValidationProofCacheDecisionKind},
    validation_proof_coalescer::{
        ValidationProofCoalescerDecision, ValidationProofCoalescerDecisionKind,
    },
    workspace_pressure_policy::WorkspacePressureInputs,
};

pub const SWARM_VALIDATION_ADMISSION_INPUT_SCHEMA_VERSION: &str =
    "franken-node/swarm-validation-admission/input/v1";
pub const SWARM_VALIDATION_ADMISSION_POLICY_PROFILE_SCHEMA_VERSION: &str =
    "franken-node/swarm-validation-admission/policy-profile/v1";
pub const SWARM_VALIDATION_ADMISSION_FIXTURE_CATALOG_SCHEMA_VERSION: &str =
    "franken-node/swarm-validation-admission/fixture-catalog/v1";
pub const SWARM_VALIDATION_ADMISSION_DECISION_SCHEMA_VERSION: &str =
    "franken-node/swarm-validation-admission/decision/v1";
pub const SWARM_VALIDATION_ADMISSION_EXECUTION_HINT_SCHEMA_VERSION: &str =
    "franken-node/swarm-validation-admission/execution-hints/v1";

pub const MAX_SWARM_ADMISSION_AGENTS: usize = 256;
pub const MAX_SWARM_ADMISSION_RESERVATIONS: usize = 512;
pub const MAX_SWARM_ADMISSION_BUILD_SLOTS: usize = 128;
pub const MAX_SWARM_ADMISSION_PROOF_EVIDENCE: usize = 128;
pub const MAX_SWARM_ADMISSION_UNAVAILABLE_SIGNALS: usize = 32;
pub const MAX_SWARM_ADMISSION_FIXTURES: usize = 64;
pub const MAX_SWARM_ADMISSION_EVIDENCE_REFS: usize = 32;
pub const MAX_SWARM_ADMISSION_BLOCKERS: usize = 32;
pub const MAX_SWARM_ADMISSION_WAITERS: usize = 32;
pub const MAX_SWARM_ADMISSION_COMPATIBILITY_BLOCKERS: usize = 16;
pub const MAX_SWARM_ADMISSION_ADVISORY_NOTES: usize = 12;

const DEFAULT_OBSERVED_AT: &str = "2026-06-18T00:00:00Z";
const DEFAULT_RETRY_AFTER_MS: u64 = 30_000;
const OPERATOR_SUMMARY_MAX_BYTES: usize = 512;
const WORKSPACE_PRESSURE_DEFER_THRESHOLD: f32 = 0.90;
const HIGH_MEMORY_HEADROOM_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const HIGH_MEMORY_HEADROOM_PRESSURE_THRESHOLD: f32 = 0.50;
const DISK_PRESSURE_TARGET_DIR_MULTIPLIER: u64 = 2;
const HIGH_HEADROOM_PARALLEL_RCH_JOBS: u16 = 4;
const DEFAULT_PARALLEL_RCH_JOBS: u16 = 1;
const DEFAULT_CARGO_BUILD_JOBS: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationAdmissionFixtureKind {
    EmptySwarm,
    SingleAgent,
    SaturatedRchQueue,
    DuplicateProofRequest,
    IncompatibleProofRequest,
    ExpiredProofCacheEntry,
    OwnerDeadStaleLease,
    ProofCacheHit,
    StaleLease,
    HighMemoryPressure,
    MissingAgentMailState,
}

impl SwarmValidationAdmissionFixtureKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptySwarm => "empty_swarm",
            Self::SingleAgent => "single_agent",
            Self::SaturatedRchQueue => "saturated_rch_queue",
            Self::DuplicateProofRequest => "duplicate_proof_request",
            Self::IncompatibleProofRequest => "incompatible_proof_request",
            Self::ExpiredProofCacheEntry => "expired_proof_cache_entry",
            Self::OwnerDeadStaleLease => "owner_dead_stale_lease",
            Self::ProofCacheHit => "proof_cache_hit",
            Self::StaleLease => "stale_lease",
            Self::HighMemoryPressure => "high_memory_pressure",
            Self::MissingAgentMailState => "missing_agent_mail_state",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationAdmissionDecision {
    Run,
    Coalesce,
    Defer,
    Handoff,
    Blocked,
}

impl SwarmValidationAdmissionDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Coalesce => "coalesce",
            Self::Defer => "defer",
            Self::Handoff => "handoff",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationAdmissionPriority {
    P0,
    P1,
    P2,
    P3,
    P4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationRequestedAction {
    SourceCheck,
    CargoCheck,
    CargoTest,
    CargoClippy,
    CargoFmt,
    PythonGate,
    EvidenceGate,
    Closeout,
}

impl SwarmValidationRequestedAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceCheck => "source-check",
            Self::CargoCheck => "cargo-check",
            Self::CargoTest => "cargo-test",
            Self::CargoClippy => "cargo-clippy",
            Self::CargoFmt => "cargo-fmt",
            Self::PythonGate => "python-gate",
            Self::EvidenceGate => "evidence-gate",
            Self::Closeout => "closeout",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationBeadStatus {
    Open,
    InProgress,
    Blocked,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationReservationMode {
    Shared,
    Exclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationBuildSlotState {
    Queued,
    Running,
    Completed,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationCoordinationState {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationProofLeaseState {
    None,
    InFlightFresh,
    CompletedFresh,
    Stale,
}

impl SwarmValidationProofLeaseState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::InFlightFresh => "in_flight_fresh",
            Self::CompletedFresh => "completed_fresh",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationUnavailableSignal {
    AgentMail,
    Beads,
    Rch,
    ProofCache,
    ProofCoalescer,
    WorkspacePressure,
    HandoffEvidence,
}

impl SwarmValidationUnavailableSignal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentMail => "agent_mail",
            Self::Beads => "beads",
            Self::Rch => "rch",
            Self::ProofCache => "proof_cache",
            Self::ProofCoalescer => "proof_coalescer",
            Self::WorkspacePressure => "workspace_pressure",
            Self::HandoffEvidence => "handoff_evidence",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationProofSource {
    None,
    SourceOnly,
    FreshExecution,
    CoalescerWaiter,
    ProofCacheHit,
}

impl SwarmValidationProofSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SourceOnly => "source_only",
            Self::FreshExecution => "fresh_execution",
            Self::CoalescerWaiter => "coalescer_waiter",
            Self::ProofCacheHit => "proof_cache_hit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationProofCoalescingStatus {
    None,
    InFlight,
    Joined,
    CompletedCacheHit,
    CacheMiss,
    StaleLease,
    ExpiredProof,
    OwnerDead,
    Incompatible,
    Corrupted,
}

impl SwarmValidationProofCoalescingStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::InFlight => "in_flight",
            Self::Joined => "joined",
            Self::CompletedCacheHit => "completed_cache_hit",
            Self::CacheMiss => "cache_miss",
            Self::StaleLease => "stale_lease",
            Self::ExpiredProof => "expired_proof",
            Self::OwnerDead => "owner_dead",
            Self::Incompatible => "incompatible",
            Self::Corrupted => "corrupted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationProofCompatibility {
    Equivalent,
    DifferentProfile,
    DifferentInputs,
    DifferentCommand,
    Unknown,
}

impl SwarmValidationProofCompatibility {
    #[must_use]
    pub const fn is_equivalent(self) -> bool {
        matches!(self, Self::Equivalent)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::DifferentProfile => "different_profile",
            Self::DifferentInputs => "different_inputs",
            Self::DifferentCommand => "different_command",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationBeadSnapshot {
    pub bead_id: String,
    pub thread_id: String,
    pub status: SwarmValidationBeadStatus,
    pub priority: SwarmValidationAdmissionPriority,
    pub assignee: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub dependency_ids: Vec<String>,
    pub dependent_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationAgentSnapshot {
    pub agent_name: String,
    pub project_key: String,
    pub last_active_age_secs: u64,
    pub ack_required_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationReservationSnapshot {
    pub holder_agent: String,
    pub path_pattern: String,
    pub mode: SwarmValidationReservationMode,
    pub reason: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationBuildSlotSnapshot {
    pub slot: String,
    pub holder_agent: String,
    pub state: SwarmValidationBuildSlotState,
    pub command_digest: Option<String>,
    pub last_progress_age_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationCoordinationSnapshot {
    pub state: SwarmValidationCoordinationState,
    pub active_agents: Vec<SwarmValidationAgentSnapshot>,
    pub reservations: Vec<SwarmValidationReservationSnapshot>,
    pub build_slots: Vec<SwarmValidationBuildSlotSnapshot>,
}

impl SwarmValidationCoordinationSnapshot {
    #[must_use]
    pub fn normalize(mut self) -> Self {
        self.active_agents.sort_by(|left, right| {
            left.agent_name
                .cmp(&right.agent_name)
                .then(left.project_key.cmp(&right.project_key))
        });
        self.active_agents.truncate(MAX_SWARM_ADMISSION_AGENTS);

        self.reservations.sort_by(|left, right| {
            left.path_pattern
                .cmp(&right.path_pattern)
                .then(left.holder_agent.cmp(&right.holder_agent))
        });
        self.reservations.truncate(MAX_SWARM_ADMISSION_RESERVATIONS);

        self.build_slots.sort_by(|left, right| {
            left.slot
                .cmp(&right.slot)
                .then(left.holder_agent.cmp(&right.holder_agent))
        });
        self.build_slots.truncate(MAX_SWARM_ADMISSION_BUILD_SLOTS);

        self
    }

    #[must_use]
    pub fn empty() -> Self {
        Self {
            state: SwarmValidationCoordinationState::Healthy,
            active_agents: Vec::new(),
            reservations: Vec::new(),
            build_slots: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationRchSnapshot {
    pub queue: ValidationShardRchQueueState,
    pub workers_total: u16,
    pub workers_healthy: u16,
    pub worker_pressure_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationProofCoalescingSnapshot {
    pub status: SwarmValidationProofCoalescingStatus,
    pub compatibility: SwarmValidationProofCompatibility,
    pub proof_work_key: Option<String>,
    pub proof_cache_key: Option<String>,
    pub command_digest: Option<String>,
    pub owner_agent: Option<String>,
    pub owner_bead_id: Option<String>,
    pub waiter_agents: Vec<String>,
    pub lease_id: Option<String>,
    pub lease_state: Option<String>,
    pub cache_entry_id: Option<String>,
    pub cache_entry_path: Option<String>,
    pub receipt_id: Option<String>,
    pub receipt_path: Option<String>,
    pub reason_code: Option<String>,
    pub event_code: Option<String>,
    pub required_action: Option<String>,
    pub freshness_expires_at: Option<DateTime<Utc>>,
    pub expected_wait_ms: Option<u64>,
    pub compatibility_blockers: Vec<String>,
}

impl SwarmValidationProofCoalescingSnapshot {
    #[must_use]
    pub fn normalize(mut self) -> Self {
        self.waiter_agents.sort();
        self.waiter_agents.dedup();
        self.waiter_agents.truncate(MAX_SWARM_ADMISSION_WAITERS);
        self.compatibility_blockers.sort();
        self.compatibility_blockers.dedup();
        self.compatibility_blockers
            .truncate(MAX_SWARM_ADMISSION_COMPATIBILITY_BLOCKERS);
        self
    }

    #[must_use]
    pub fn none() -> Self {
        Self {
            status: SwarmValidationProofCoalescingStatus::None,
            compatibility: SwarmValidationProofCompatibility::Unknown,
            proof_work_key: None,
            proof_cache_key: None,
            command_digest: None,
            owner_agent: None,
            owner_bead_id: None,
            waiter_agents: Vec::new(),
            lease_id: None,
            lease_state: None,
            cache_entry_id: None,
            cache_entry_path: None,
            receipt_id: None,
            receipt_path: None,
            reason_code: None,
            event_code: None,
            required_action: None,
            freshness_expires_at: None,
            expected_wait_ms: None,
            compatibility_blockers: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_coalescer_decision(
        decision: &ValidationProofCoalescerDecision,
        expected_wait_ms: Option<u64>,
    ) -> Self {
        let lease_ref = decision.lease_ref.as_ref();
        let status = match decision.decision {
            ValidationProofCoalescerDecisionKind::JoinExistingProof => {
                SwarmValidationProofCoalescingStatus::InFlight
            }
            ValidationProofCoalescerDecisionKind::WaitForReceipt => {
                SwarmValidationProofCoalescingStatus::CompletedCacheHit
            }
            ValidationProofCoalescerDecisionKind::RetryAfterStaleLease => {
                SwarmValidationProofCoalescingStatus::StaleLease
            }
            ValidationProofCoalescerDecisionKind::RejectDirtyPolicy => {
                SwarmValidationProofCoalescingStatus::Incompatible
            }
            ValidationProofCoalescerDecisionKind::RepairState => {
                SwarmValidationProofCoalescingStatus::Corrupted
            }
            ValidationProofCoalescerDecisionKind::QueuedByPolicy => {
                SwarmValidationProofCoalescingStatus::CacheMiss
            }
            ValidationProofCoalescerDecisionKind::RejectCapacity
            | ValidationProofCoalescerDecisionKind::RunLocallyViaRch => {
                SwarmValidationProofCoalescingStatus::None
            }
        };
        let compatibility = match decision.decision {
            ValidationProofCoalescerDecisionKind::RejectDirtyPolicy => {
                SwarmValidationProofCompatibility::DifferentProfile
            }
            ValidationProofCoalescerDecisionKind::RepairState => {
                SwarmValidationProofCompatibility::Unknown
            }
            _ => SwarmValidationProofCompatibility::Equivalent,
        };
        let mut compatibility_blockers = Vec::new();
        if !compatibility.is_equivalent() {
            compatibility_blockers.push(decision.diagnostics.message.clone());
        }

        Self {
            status,
            compatibility,
            proof_work_key: Some(decision.proof_work_key.hex.clone()),
            proof_cache_key: Some(decision.proof_work_key.proof_cache_key.hex.clone()),
            command_digest: Some(decision.proof_work_key.command_digest.hex.clone()),
            owner_agent: lease_ref.map(|lease| lease.owner_agent.clone()),
            owner_bead_id: lease_ref.map(|lease| lease.owner_bead_id.clone()),
            waiter_agents: Vec::new(),
            lease_id: lease_ref.map(|lease| lease.lease_id.clone()),
            lease_state: lease_ref.map(|lease| lease.state.as_str().to_string()),
            cache_entry_id: None,
            cache_entry_path: None,
            receipt_id: None,
            receipt_path: None,
            reason_code: Some(decision.reason_code.clone()),
            event_code: Some(decision.diagnostics.event_code.clone()),
            required_action: Some(decision.required_action.as_str().to_string()),
            freshness_expires_at: None,
            expected_wait_ms,
            compatibility_blockers,
        }
        .normalize()
    }

    #[must_use]
    pub fn from_cache_decision(decision: &ValidationProofCacheDecision) -> Self {
        let status = match decision.decision {
            ValidationProofCacheDecisionKind::Hit => {
                SwarmValidationProofCoalescingStatus::CompletedCacheHit
            }
            ValidationProofCacheDecisionKind::Miss
            | ValidationProofCacheDecisionKind::QuotaBlocked => {
                SwarmValidationProofCoalescingStatus::CacheMiss
            }
            ValidationProofCacheDecisionKind::Stale => {
                SwarmValidationProofCoalescingStatus::ExpiredProof
            }
            ValidationProofCacheDecisionKind::DigestMismatch
            | ValidationProofCacheDecisionKind::PolicyMismatch
            | ValidationProofCacheDecisionKind::DirtyStateMismatch => {
                SwarmValidationProofCoalescingStatus::Incompatible
            }
            ValidationProofCacheDecisionKind::CorruptedEntry => {
                SwarmValidationProofCoalescingStatus::Corrupted
            }
        };
        let compatibility = match decision.decision {
            ValidationProofCacheDecisionKind::Hit
            | ValidationProofCacheDecisionKind::Miss
            | ValidationProofCacheDecisionKind::Stale
            | ValidationProofCacheDecisionKind::QuotaBlocked => {
                SwarmValidationProofCompatibility::Equivalent
            }
            ValidationProofCacheDecisionKind::DigestMismatch => {
                SwarmValidationProofCompatibility::DifferentCommand
            }
            ValidationProofCacheDecisionKind::PolicyMismatch
            | ValidationProofCacheDecisionKind::DirtyStateMismatch => {
                SwarmValidationProofCompatibility::DifferentProfile
            }
            ValidationProofCacheDecisionKind::CorruptedEntry => {
                SwarmValidationProofCompatibility::Unknown
            }
        };
        let mut compatibility_blockers = Vec::new();
        if !compatibility.is_equivalent() {
            compatibility_blockers.push(decision.diagnostics.message.clone());
        }

        Self {
            status,
            compatibility,
            proof_work_key: None,
            proof_cache_key: Some(decision.cache_key.hex.clone()),
            command_digest: Some(decision.cache_key.command_digest.hex.clone()),
            owner_agent: None,
            owner_bead_id: Some(decision.bead_id.clone()),
            waiter_agents: Vec::new(),
            lease_id: None,
            lease_state: None,
            cache_entry_id: decision
                .entry_ref
                .as_ref()
                .map(|entry| entry.entry_id.clone()),
            cache_entry_path: decision.entry_ref.as_ref().map(|entry| entry.path.clone()),
            receipt_id: decision
                .receipt_ref
                .as_ref()
                .map(|receipt| receipt.receipt_id.clone()),
            receipt_path: decision
                .receipt_ref
                .as_ref()
                .map(|receipt| receipt.path.clone()),
            reason_code: Some(decision.reason_code.clone()),
            event_code: Some(decision.diagnostics.event_code.clone()),
            required_action: Some(decision.required_action.as_str().to_string()),
            freshness_expires_at: None,
            expected_wait_ms: None,
            compatibility_blockers,
        }
        .normalize()
    }

    #[must_use]
    pub fn freshness_is_valid_at(&self, observed_at: DateTime<Utc>) -> bool {
        match self.freshness_expires_at {
            Some(expires_at) => expires_at > observed_at,
            None => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationProofSnapshot {
    pub lease_state: SwarmValidationProofLeaseState,
    pub proof_work_key: Option<String>,
    pub command_digest: Option<String>,
    pub owner_agent: Option<String>,
    pub proof_evidence: Vec<ValidationShardProofEvidence>,
    pub coalescing: Option<SwarmValidationProofCoalescingSnapshot>,
}

impl SwarmValidationProofSnapshot {
    #[must_use]
    pub fn normalize(mut self) -> Self {
        self.proof_evidence.sort_by(|left, right| {
            left.command_id
                .cmp(&right.command_id)
                .then(left.evidence_ref.cmp(&right.evidence_ref))
        });
        self.proof_evidence
            .truncate(MAX_SWARM_ADMISSION_PROOF_EVIDENCE);
        self.coalescing = self
            .coalescing
            .map(SwarmValidationProofCoalescingSnapshot::normalize);
        self
    }

    #[must_use]
    pub fn none() -> Self {
        Self {
            lease_state: SwarmValidationProofLeaseState::None,
            proof_work_key: None,
            command_digest: None,
            owner_agent: None,
            proof_evidence: Vec::new(),
            coalescing: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmTargetDirPressureSnapshot {
    pub target_dir_policy_id: String,
    pub active_target_dir_leases: u16,
    pub target_dir_bytes: u64,
    pub isolated_target_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmHostPressureSnapshot {
    pub cpu_cores: u16,
    pub memory_bytes: u64,
    pub memory_pressure: f32,
    pub active_build_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationPolicyProfile {
    pub schema_version: String,
    pub profile_id: String,
    pub require_rch_for_cargo: bool,
    pub fail_closed_on_telemetry_gap: bool,
    pub max_running_proofs: u16,
    pub max_waiters_per_work_key: u16,
    pub max_defer_ms: u64,
    pub stale_handoff_after_ms: u64,
}

impl SwarmValidationPolicyProfile {
    #[must_use]
    pub fn repo_default() -> Self {
        Self {
            schema_version: SWARM_VALIDATION_ADMISSION_POLICY_PROFILE_SCHEMA_VERSION.to_string(),
            profile_id: "franken-node/default-swarm-validation-admission/v1".to_string(),
            require_rch_for_cargo: true,
            fail_closed_on_telemetry_gap: true,
            max_running_proofs: 8,
            max_waiters_per_work_key: 32,
            max_defer_ms: 300_000,
            stale_handoff_after_ms: 1_800_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmValidationAdmissionInputFixture {
    pub schema_version: String,
    pub input_id: String,
    pub trace_id: String,
    pub observed_at: DateTime<Utc>,
    pub freshness_expires_at: DateTime<Utc>,
    pub bead: SwarmValidationBeadSnapshot,
    pub agent_name: String,
    pub requested_action: SwarmValidationRequestedAction,
    pub workspace: WorkspacePressureInputs,
    pub host: SwarmHostPressureSnapshot,
    pub target_dir: SwarmTargetDirPressureSnapshot,
    pub rch: SwarmValidationRchSnapshot,
    pub proof: SwarmValidationProofSnapshot,
    pub coordination: SwarmValidationCoordinationSnapshot,
    pub policy: SwarmValidationPolicyProfile,
    pub missing_signals: Vec<SwarmValidationUnavailableSignal>,
}

impl SwarmValidationAdmissionInputFixture {
    #[must_use]
    pub fn normalize(mut self) -> Self {
        self.bead.dependency_ids.sort();
        self.bead.dependency_ids.dedup();
        self.bead.dependent_ids.sort();
        self.bead.dependent_ids.dedup();
        self.coordination = self.coordination.normalize();
        self.proof = self.proof.normalize();
        self.missing_signals.sort();
        self.missing_signals.dedup();
        self.missing_signals
            .truncate(MAX_SWARM_ADMISSION_UNAVAILABLE_SIGNALS);
        self
    }

    #[must_use]
    pub fn expected_validation_shard_status(&self) -> ValidationShardStatus {
        if self.proof.proof_evidence.iter().any(|evidence| {
            matches!(
                evidence.state,
                super::validation_planner::ValidationShardProofState::CacheHit
                    | super::validation_planner::ValidationShardProofState::CoalescerInFlight
            )
        }) || self.proof.coalescing.as_ref().is_some_and(|coalescing| {
            matches!(
                coalescing.status,
                SwarmValidationProofCoalescingStatus::InFlight
                    | SwarmValidationProofCoalescingStatus::Joined
                    | SwarmValidationProofCoalescingStatus::CompletedCacheHit
            )
        }) {
            return ValidationShardStatus::Reused;
        }

        if !self.rch.queue.rch_available || self.rch.queue.workers_available == 0 {
            return ValidationShardStatus::Waiting;
        }

        if self.missing_signals.is_empty() {
            ValidationShardStatus::Ready
        } else {
            ValidationShardStatus::Blocked
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationAdmissionFixtureExpectation {
    pub decision: SwarmValidationAdmissionDecision,
    pub reason_code: String,
    pub required_action: String,
    pub green_proof_eligible: bool,
    pub retry_after_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationAdmissionInputFreshness {
    pub observed_at: DateTime<Utc>,
    pub freshness_expires_at: DateTime<Utc>,
    pub fresh: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationAdmissionCoalescingTarget {
    pub proof_work_key: Option<String>,
    pub proof_cache_key: Option<String>,
    pub command_digest: Option<String>,
    pub owner_agent: Option<String>,
    pub owner_bead_id: Option<String>,
    pub lease_id: Option<String>,
    pub lease_state: Option<String>,
    pub receipt_id: Option<String>,
    pub receipt_path: Option<String>,
    pub evidence_ref: Option<String>,
    pub reason_code: Option<String>,
    pub required_action: Option<String>,
    pub freshness_expires_at: Option<DateTime<Utc>>,
    pub expected_wait_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationTargetDirStrategy {
    NoTargetDirRequired,
    ReuseIsolated,
    CreateUniqueTemp,
    JoinExistingProofLease,
    DeferForTargetDirLease,
    DeferForDiskPressure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationWorkerRequirement {
    SourceOnlyLocal,
    RequireHealthyRemote,
    PreferHighMemoryRemote,
    WaitForRchCapacity,
    RestoreRchBeforeCargo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationLaneBudgetHint {
    pub max_parallel_rch_jobs: u16,
    pub cargo_build_jobs: u16,
    pub expected_build_slots: u16,
    pub retry_after_ms: Option<u64>,
}

/// Advisory execution hints for agents. Cargo hints preserve the repository
/// rule that heavy validation must use `rch exec -- ...`; they never authorize
/// bare local `cargo` commands on the shared host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmValidationExecutionHints {
    pub schema_version: String,
    pub target_dir_strategy: SwarmValidationTargetDirStrategy,
    pub target_dir: Option<String>,
    pub build_slot_name: Option<String>,
    pub rch_priority: Option<SwarmValidationAdmissionPriority>,
    pub worker_requirement: SwarmValidationWorkerRequirement,
    pub coalescing_key: Option<String>,
    pub lane_budget: SwarmValidationLaneBudgetHint,
    pub advisory_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmValidationAdmissionDiagnostics {
    pub input_freshness: SwarmValidationAdmissionInputFreshness,
    pub validation_shard_status: ValidationShardStatus,
    pub proof_coalescing_status: SwarmValidationProofCoalescingStatus,
    pub rch_available: bool,
    pub rch_workers_available: u16,
    pub rch_queued_builds: u16,
    pub rch_active_builds: u16,
    pub workspace_memory_pressure: f32,
    pub active_reservations: u32,
    pub missing_signals: Vec<SwarmValidationUnavailableSignal>,
    pub blocked_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmValidationAdmissionDecisionRecord {
    pub schema_version: String,
    pub decision_id: String,
    pub input_ref: String,
    pub policy_id: String,
    pub trace_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub agent_name: String,
    pub decided_at: DateTime<Utc>,
    pub freshness_expires_at: DateTime<Utc>,
    pub decision: SwarmValidationAdmissionDecision,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
    pub green_proof_eligible: bool,
    pub retryable: bool,
    pub fail_closed: bool,
    pub source_only_closeout_allowed: bool,
    pub operator_summary: String,
    pub safe_command_shape: Option<String>,
    pub coalescing_target: Option<SwarmValidationAdmissionCoalescingTarget>,
    pub proof_source: SwarmValidationProofSource,
    pub execution_hints: SwarmValidationExecutionHints,
    pub retry_after_ms: Option<u64>,
    pub evidence_refs: Vec<String>,
    pub diagnostics: SwarmValidationAdmissionDiagnostics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmValidationAdmissionFixture {
    pub fixture_id: String,
    pub fixture_kind: SwarmValidationAdmissionFixtureKind,
    pub input: SwarmValidationAdmissionInputFixture,
    pub expectation: SwarmValidationAdmissionFixtureExpectation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmValidationAdmissionFixtureCatalog {
    pub schema_version: String,
    pub generated_at: DateTime<Utc>,
    pub fixtures: Vec<SwarmValidationAdmissionFixture>,
}

impl SwarmValidationAdmissionFixtureCatalog {
    #[must_use]
    pub fn normalize(mut self) -> Self {
        self.fixtures.sort_by(|left, right| {
            left.fixture_kind
                .cmp(&right.fixture_kind)
                .then(left.fixture_id.cmp(&right.fixture_id))
        });
        self.fixtures.truncate(MAX_SWARM_ADMISSION_FIXTURES);
        self
    }

    #[must_use]
    pub fn fixture(
        &self,
        kind: SwarmValidationAdmissionFixtureKind,
    ) -> Option<&SwarmValidationAdmissionFixture> {
        self.fixtures
            .iter()
            .find(|fixture| fixture.fixture_kind == kind)
    }
}

#[must_use]
pub fn plan_swarm_validation_admission(
    input: &SwarmValidationAdmissionInputFixture,
) -> SwarmValidationAdmissionDecisionRecord {
    let normalized = input.clone().normalize();
    let parts = decide_swarm_validation_admission(&normalized);
    decision_record(&normalized, parts)
}

#[must_use]
pub fn deterministic_swarm_validation_admission_fixtures() -> SwarmValidationAdmissionFixtureCatalog
{
    let observed_at = fixture_observed_at();
    let fixtures = vec![
        empty_swarm_fixture(observed_at),
        single_agent_fixture(observed_at),
        saturated_rch_queue_fixture(observed_at),
        duplicate_proof_request_fixture(observed_at),
        incompatible_proof_request_fixture(observed_at),
        expired_proof_cache_entry_fixture(observed_at),
        owner_dead_stale_lease_fixture(observed_at),
        proof_cache_hit_fixture(observed_at),
        stale_lease_fixture(observed_at),
        high_memory_pressure_fixture(observed_at),
        missing_agent_mail_state_fixture(observed_at),
    ];

    SwarmValidationAdmissionFixtureCatalog {
        schema_version: SWARM_VALIDATION_ADMISSION_FIXTURE_CATALOG_SCHEMA_VERSION.to_string(),
        generated_at: observed_at,
        fixtures,
    }
    .normalize()
}

#[derive(Debug, Clone)]
struct SwarmValidationDecisionParts {
    decision: SwarmValidationAdmissionDecision,
    reason_code: &'static str,
    event_code: &'static str,
    required_action: &'static str,
    green_proof_eligible: bool,
    retryable: bool,
    fail_closed: bool,
    source_only_closeout_allowed: bool,
    proof_source: SwarmValidationProofSource,
    retry_after_ms: Option<u64>,
    safe_command_shape: Option<String>,
    coalescing_target: Option<SwarmValidationAdmissionCoalescingTarget>,
    blocked_by: Vec<String>,
}

fn decide_swarm_validation_admission(
    input: &SwarmValidationAdmissionInputFixture,
) -> SwarmValidationDecisionParts {
    let missing_fields = missing_required_input_fields(input);
    if !missing_fields.is_empty() {
        return decision_parts(
            SwarmValidationAdmissionDecision::Blocked,
            "SVA_BLOCKED_MISSING_INPUT",
            "SVA-011",
            "repair_admission_input",
        )
        .fail_closed()
        .with_blocker(format!(
            "missing required admission input fields: {}",
            missing_fields.join(",")
        ));
    }

    if !input_schema_versions_valid(input) {
        return decision_parts(
            SwarmValidationAdmissionDecision::Blocked,
            "SVA_BLOCKED_MALFORMED_INPUT",
            "SVA-011",
            "repair_admission_input",
        )
        .fail_closed()
        .with_blocker("admission input or policy schema version is invalid");
    }

    if input.freshness_expires_at <= input.observed_at {
        return decision_parts(
            SwarmValidationAdmissionDecision::Blocked,
            "SVA_BLOCKED_STALE_OR_INVALID_ARTIFACT",
            "SVA-015",
            "regenerate_evidence",
        )
        .fail_closed()
        .retryable()
        .with_blocker("admission input freshness has expired");
    }

    if requested_action_requires_cargo(input.requested_action)
        && input.policy.require_rch_for_cargo
        && input.proof.command_digest.is_none()
    {
        return decision_parts(
            SwarmValidationAdmissionDecision::Blocked,
            "SVA_BLOCKED_MALFORMED_INPUT",
            "SVA-011",
            "repair_admission_input",
        )
        .fail_closed()
        .with_blocker("cargo/RCH work is missing a command digest");
    }

    if input.policy.fail_closed_on_telemetry_gap && !input.missing_signals.is_empty() {
        return decision_parts(
            SwarmValidationAdmissionDecision::Blocked,
            "SVA_BLOCKED_TELEMETRY_GAP",
            "SVA-016",
            "refresh_required_telemetry",
        )
        .fail_closed()
        .retryable()
        .with_blocker(format!(
            "missing required telemetry: {}",
            input
                .missing_signals
                .iter()
                .map(|signal| signal.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }

    if let Some(decision) = proof_coalescing_decision(input) {
        return decision;
    }

    if let Some(reservation) = active_conflicting_reservation(input) {
        return decision_parts(
            SwarmValidationAdmissionDecision::Blocked,
            "SVA_BLOCKED_ACTIVE_RESERVATION",
            "SVA-014",
            "coordinate_with_reservation_holder",
        )
        .fail_closed()
        .retryable()
        .with_blocker(format!(
            "active exclusive reservation by {} on {}",
            reservation.holder_agent, reservation.path_pattern
        ));
    }

    if requested_action_requires_cargo(input.requested_action)
        && input.policy.require_rch_for_cargo
        && !input.rch.queue.rch_available
    {
        return decision_parts(
            SwarmValidationAdmissionDecision::Blocked,
            "SVA_BLOCKED_LOCAL_FALLBACK",
            "SVA-013",
            "restore_remote_execution_or_record_blocker",
        )
        .fail_closed()
        .retryable()
        .with_blocker("RCH unavailable and local cargo fallback is forbidden");
    }

    if stale_handoff_ready(input) {
        return decision_parts(
            SwarmValidationAdmissionDecision::Handoff,
            "SWARM-STALE-LEASE",
            "SVA-009",
            "request_agent_handoff",
        )
        .retryable()
        .with_blocker(format!(
            "stale owner {} has not made progress",
            input.proof.owner_agent.as_deref().unwrap_or("unknown")
        ));
    }

    if input.proof.lease_state == SwarmValidationProofLeaseState::InFlightFresh {
        return decision_parts(
            SwarmValidationAdmissionDecision::Coalesce,
            "SWARM-COALESCE-IN-FLIGHT",
            "SVA-004",
            "join_existing_proof",
        )
        .green_proof_eligible()
        .retryable()
        .with_proof_source(SwarmValidationProofSource::CoalescerWaiter)
        .with_coalescing_target(coalescing_target(input));
    }

    if input.proof.lease_state == SwarmValidationProofLeaseState::CompletedFresh {
        return decision_parts(
            SwarmValidationAdmissionDecision::Coalesce,
            "SWARM-CACHE-HIT",
            "SVA-005",
            "reuse_fresh_receipt",
        )
        .green_proof_eligible()
        .with_proof_source(SwarmValidationProofSource::ProofCacheHit)
        .with_coalescing_target(coalescing_target(input));
    }

    if workspace_pressure_requires_defer(input) {
        return decision_parts(
            SwarmValidationAdmissionDecision::Defer,
            "SVA_DEFER_WORKSPACE_PRESSURE",
            "SVA-006",
            "refresh_pressure_after_backoff",
        )
        .retryable()
        .with_retry_after(DEFAULT_RETRY_AFTER_MS)
        .with_blocker(format!(
            "workspace memory pressure {:.2}",
            input
                .workspace
                .memory_pressure
                .max(input.host.memory_pressure)
        ));
    }

    if requested_action_uses_target_dir(input.requested_action) && target_dir_disk_pressure(input) {
        return decision_parts(
            SwarmValidationAdmissionDecision::Defer,
            "SVA_DEFER_TARGET_DIR_DISK_PRESSURE",
            "SVA-020",
            "free_target_dir_space_or_reuse_existing_proof",
        )
        .retryable()
        .with_retry_after(DEFAULT_RETRY_AFTER_MS)
        .with_blocker(format!(
            "free_disk_bytes={} target_dir_bytes={}",
            input.workspace.free_disk_bytes,
            input
                .target_dir
                .target_dir_bytes
                .max(input.workspace.target_dir_bytes)
        ));
    }

    if requested_action_requires_cargo(input.requested_action) && rch_queue_saturated(input) {
        return decision_parts(
            SwarmValidationAdmissionDecision::Defer,
            "SVA_DEFER_RCH_QUEUE",
            "SVA-007",
            "wait_for_rch_capacity",
        )
        .retryable()
        .with_retry_after(DEFAULT_RETRY_AFTER_MS)
        .with_blocker(format!(
            "workers_available={} queued_builds={} active_builds={}",
            input.rch.queue.workers_available,
            input.rch.queue.queued_builds,
            input.rch.queue.active_builds
        ));
    }

    if requested_action_requires_cargo(input.requested_action)
        && input.target_dir.active_target_dir_leases > 0
    {
        return decision_parts(
            SwarmValidationAdmissionDecision::Defer,
            "SVA_DEFER_TARGET_DIR_SERIALIZED",
            "SVA-008",
            "wait_for_target_dir_lease",
        )
        .retryable()
        .with_retry_after(DEFAULT_RETRY_AFTER_MS)
        .with_blocker(format!(
            "{} active target-dir leases",
            input.target_dir.active_target_dir_leases
        ));
    }

    run_decision(input)
}

impl SwarmValidationDecisionParts {
    fn fail_closed(mut self) -> Self {
        self.fail_closed = true;
        self
    }

    fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    fn green_proof_eligible(mut self) -> Self {
        self.green_proof_eligible = true;
        self
    }

    fn with_retry_after(mut self, retry_after_ms: u64) -> Self {
        self.retry_after_ms = Some(retry_after_ms);
        self
    }

    fn with_proof_source(mut self, proof_source: SwarmValidationProofSource) -> Self {
        self.proof_source = proof_source;
        self
    }

    fn with_coalescing_target(
        mut self,
        coalescing_target: SwarmValidationAdmissionCoalescingTarget,
    ) -> Self {
        self.coalescing_target = Some(coalescing_target);
        self
    }

    fn with_safe_command_shape(mut self, safe_command_shape: String) -> Self {
        self.safe_command_shape = Some(safe_command_shape);
        self
    }

    fn source_only_closeout_allowed(mut self) -> Self {
        self.source_only_closeout_allowed = true;
        self.proof_source = SwarmValidationProofSource::SourceOnly;
        self
    }

    fn with_blocker(mut self, blocker: impl Into<String>) -> Self {
        push_bounded(
            &mut self.blocked_by,
            blocker.into(),
            MAX_SWARM_ADMISSION_BLOCKERS,
        );
        self
    }
}

fn decision_parts(
    decision: SwarmValidationAdmissionDecision,
    reason_code: &'static str,
    event_code: &'static str,
    required_action: &'static str,
) -> SwarmValidationDecisionParts {
    SwarmValidationDecisionParts {
        decision,
        reason_code,
        event_code,
        required_action,
        green_proof_eligible: false,
        retryable: false,
        fail_closed: false,
        source_only_closeout_allowed: false,
        proof_source: SwarmValidationProofSource::None,
        retry_after_ms: None,
        safe_command_shape: None,
        coalescing_target: None,
        blocked_by: Vec::new(),
    }
}

fn run_decision(input: &SwarmValidationAdmissionInputFixture) -> SwarmValidationDecisionParts {
    match input.requested_action {
        SwarmValidationRequestedAction::SourceCheck => decision_parts(
            SwarmValidationAdmissionDecision::Run,
            "SVA_RUN_SOURCE_ONLY_READY",
            "SVA-001",
            "run_source_only_checks",
        )
        .source_only_closeout_allowed()
        .with_safe_command_shape("git diff --check; ubs <changed-files>".to_string()),
        SwarmValidationRequestedAction::PythonGate
        | SwarmValidationRequestedAction::EvidenceGate => decision_parts(
            SwarmValidationAdmissionDecision::Run,
            "SVA_RUN_PYTHON_GATE_READY",
            "SVA-003",
            "run_python_gate",
        )
        .with_safe_command_shape("python3 scripts/<relevant-gate>.py --json".to_string()),
        SwarmValidationRequestedAction::Closeout => decision_parts(
            SwarmValidationAdmissionDecision::Run,
            "SVA_RUN_SOURCE_ONLY_READY",
            "SVA-001",
            "run_source_only_checks",
        )
        .source_only_closeout_allowed()
        .with_safe_command_shape("br close <bead-id> --reason <validated-reason>".to_string()),
        SwarmValidationRequestedAction::CargoCheck
        | SwarmValidationRequestedAction::CargoTest
        | SwarmValidationRequestedAction::CargoClippy
        | SwarmValidationRequestedAction::CargoFmt => decision_parts(
            SwarmValidationAdmissionDecision::Run,
            "SVA_RUN_RCH_READY",
            "SVA-002",
            "start_rch_validation",
        )
        .green_proof_eligible()
        .with_proof_source(SwarmValidationProofSource::FreshExecution)
        .with_safe_command_shape(safe_rch_command_shape(input)),
    }
}

fn decision_record(
    input: &SwarmValidationAdmissionInputFixture,
    parts: SwarmValidationDecisionParts,
) -> SwarmValidationAdmissionDecisionRecord {
    let evidence_refs = evidence_refs(input);
    let operator_summary = operator_summary(input, &parts, evidence_refs.first());
    let execution_hints = execution_hints(input, &parts);
    SwarmValidationAdmissionDecisionRecord {
        schema_version: SWARM_VALIDATION_ADMISSION_DECISION_SCHEMA_VERSION.to_string(),
        decision_id: format!(
            "sva-decision-{}-{}",
            stable_token(&input.bead.bead_id),
            stable_token(parts.reason_code)
        ),
        input_ref: input.input_id.clone(),
        policy_id: input.policy.profile_id.clone(),
        trace_id: input.trace_id.clone(),
        bead_id: input.bead.bead_id.clone(),
        thread_id: input.bead.thread_id.clone(),
        agent_name: input.agent_name.clone(),
        decided_at: input.observed_at,
        freshness_expires_at: input.freshness_expires_at,
        decision: parts.decision,
        reason_code: parts.reason_code.to_string(),
        event_code: parts.event_code.to_string(),
        required_action: parts.required_action.to_string(),
        green_proof_eligible: parts.green_proof_eligible,
        retryable: parts.retryable,
        fail_closed: parts.fail_closed,
        source_only_closeout_allowed: parts.source_only_closeout_allowed,
        operator_summary,
        safe_command_shape: parts.safe_command_shape,
        coalescing_target: parts.coalescing_target,
        proof_source: parts.proof_source,
        execution_hints,
        retry_after_ms: parts.retry_after_ms,
        evidence_refs,
        diagnostics: SwarmValidationAdmissionDiagnostics {
            input_freshness: SwarmValidationAdmissionInputFreshness {
                observed_at: input.observed_at,
                freshness_expires_at: input.freshness_expires_at,
                fresh: input.freshness_expires_at > input.observed_at,
            },
            validation_shard_status: input.expected_validation_shard_status(),
            proof_coalescing_status: input
                .proof
                .coalescing
                .as_ref()
                .map(|coalescing| coalescing.status)
                .unwrap_or(SwarmValidationProofCoalescingStatus::None),
            rch_available: input.rch.queue.rch_available,
            rch_workers_available: input.rch.queue.workers_available,
            rch_queued_builds: input.rch.queue.queued_builds,
            rch_active_builds: input.rch.queue.active_builds,
            workspace_memory_pressure: input.workspace.memory_pressure,
            active_reservations: input.workspace.active_reservations,
            missing_signals: input.missing_signals.clone(),
            blocked_by: parts.blocked_by,
        },
    }
}

fn missing_required_input_fields(
    input: &SwarmValidationAdmissionInputFixture,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if input.input_id.trim().is_empty() {
        missing.push("input_id");
    }
    if input.trace_id.trim().is_empty() {
        missing.push("trace_id");
    }
    if input.bead.bead_id.trim().is_empty() {
        missing.push("bead.bead_id");
    }
    if input.bead.thread_id.trim().is_empty() {
        missing.push("bead.thread_id");
    }
    if input.agent_name.trim().is_empty() {
        missing.push("agent_name");
    }
    if input.policy.profile_id.trim().is_empty() {
        missing.push("policy.profile_id");
    }
    missing
}

fn input_schema_versions_valid(input: &SwarmValidationAdmissionInputFixture) -> bool {
    input.schema_version == SWARM_VALIDATION_ADMISSION_INPUT_SCHEMA_VERSION
        && input.policy.schema_version == SWARM_VALIDATION_ADMISSION_POLICY_PROFILE_SCHEMA_VERSION
}

fn requested_action_requires_cargo(action: SwarmValidationRequestedAction) -> bool {
    matches!(
        action,
        SwarmValidationRequestedAction::CargoCheck
            | SwarmValidationRequestedAction::CargoTest
            | SwarmValidationRequestedAction::CargoClippy
            | SwarmValidationRequestedAction::CargoFmt
    )
}

fn active_conflicting_reservation(
    input: &SwarmValidationAdmissionInputFixture,
) -> Option<&SwarmValidationReservationSnapshot> {
    input.coordination.reservations.iter().find(|reservation| {
        reservation.mode == SwarmValidationReservationMode::Exclusive
            && reservation.holder_agent != input.agent_name
            && reservation.expires_at > input.observed_at
    })
}

fn proof_coalescing_decision(
    input: &SwarmValidationAdmissionInputFixture,
) -> Option<SwarmValidationDecisionParts> {
    let coalescing = input.proof.coalescing.as_ref()?;

    if let Some(blocker) = proof_signal_mismatch(input, coalescing) {
        return Some(
            decision_parts(
                SwarmValidationAdmissionDecision::Blocked,
                "SWARM-INCOMPATIBLE-PROOF",
                "SVA-017",
                "start_distinct_proof_or_rebuild_key",
            )
            .fail_closed()
            .retryable()
            .with_coalescing_target(coalescing_target(input))
            .with_blocker(blocker),
        );
    }

    if !coalescing.compatibility.is_equivalent() {
        let mut parts = decision_parts(
            SwarmValidationAdmissionDecision::Blocked,
            "SWARM-INCOMPATIBLE-PROOF",
            "SVA-017",
            "start_distinct_proof_or_rebuild_key",
        )
        .fail_closed()
        .retryable()
        .with_blocker(format!(
            "proof compatibility is {}",
            coalescing.compatibility.as_str()
        ));
        for blocker in &coalescing.compatibility_blockers {
            parts = parts.with_blocker(blocker.clone());
        }
        return Some(parts.with_coalescing_target(coalescing_target(input)));
    }

    if !coalescing.freshness_is_valid_at(input.observed_at) {
        return Some(
            decision_parts(
                SwarmValidationAdmissionDecision::Blocked,
                "SWARM-STALE-CACHE",
                "SVA-018",
                "refresh_validation_evidence",
            )
            .fail_closed()
            .retryable()
            .with_coalescing_target(coalescing_target(input))
            .with_blocker("proof cache freshness has expired"),
        );
    }

    match coalescing.status {
        SwarmValidationProofCoalescingStatus::InFlight
        | SwarmValidationProofCoalescingStatus::Joined => Some(
            decision_parts(
                SwarmValidationAdmissionDecision::Coalesce,
                "SWARM-COALESCE-IN-FLIGHT",
                "SVA-004",
                "join_existing_proof",
            )
            .green_proof_eligible()
            .retryable()
            .with_proof_source(SwarmValidationProofSource::CoalescerWaiter)
            .with_coalescing_target(coalescing_target(input)),
        ),
        SwarmValidationProofCoalescingStatus::CompletedCacheHit => Some(
            decision_parts(
                SwarmValidationAdmissionDecision::Coalesce,
                "SWARM-CACHE-HIT",
                "SVA-005",
                "reuse_fresh_receipt",
            )
            .green_proof_eligible()
            .with_proof_source(SwarmValidationProofSource::ProofCacheHit)
            .with_coalescing_target(coalescing_target(input)),
        ),
        SwarmValidationProofCoalescingStatus::StaleLease
        | SwarmValidationProofCoalescingStatus::OwnerDead => Some(
            decision_parts(
                SwarmValidationAdmissionDecision::Handoff,
                "SWARM-STALE-LEASE",
                "SVA-009",
                "request_agent_handoff",
            )
            .retryable()
            .with_coalescing_target(coalescing_target(input))
            .with_blocker(format!(
                "stale proof owner {} requires handoff",
                coalescing
                    .owner_agent
                    .as_deref()
                    .or(input.proof.owner_agent.as_deref())
                    .unwrap_or("unknown")
            )),
        ),
        SwarmValidationProofCoalescingStatus::ExpiredProof => Some(
            decision_parts(
                SwarmValidationAdmissionDecision::Blocked,
                "SWARM-STALE-CACHE",
                "SVA-018",
                "refresh_validation_evidence",
            )
            .fail_closed()
            .retryable()
            .with_coalescing_target(coalescing_target(input))
            .with_blocker("proof cache entry is stale or expired"),
        ),
        SwarmValidationProofCoalescingStatus::Incompatible => Some(
            decision_parts(
                SwarmValidationAdmissionDecision::Blocked,
                "SWARM-INCOMPATIBLE-PROOF",
                "SVA-017",
                "start_distinct_proof_or_rebuild_key",
            )
            .fail_closed()
            .retryable()
            .with_coalescing_target(coalescing_target(input))
            .with_blocker("proof signal is incompatible with requested validation profile"),
        ),
        SwarmValidationProofCoalescingStatus::Corrupted => Some(
            decision_parts(
                SwarmValidationAdmissionDecision::Blocked,
                "SWARM-CORRUPTED-PROOF-STATE",
                "SVA-019",
                "repair_proof_coalescer_state",
            )
            .fail_closed()
            .retryable()
            .with_coalescing_target(coalescing_target(input))
            .with_blocker("proof coalescer or cache state is corrupted"),
        ),
        SwarmValidationProofCoalescingStatus::None
        | SwarmValidationProofCoalescingStatus::CacheMiss => None,
    }
}

fn proof_signal_mismatch(
    input: &SwarmValidationAdmissionInputFixture,
    coalescing: &SwarmValidationProofCoalescingSnapshot,
) -> Option<String> {
    if let (Some(expected), Some(observed)) = (
        input.proof.proof_work_key.as_deref(),
        coalescing.proof_work_key.as_deref(),
    ) && expected != observed
    {
        return Some(format!(
            "proof work key mismatch: expected {expected}, observed {observed}"
        ));
    }
    if let (Some(expected), Some(observed)) = (
        input.proof.command_digest.as_deref(),
        coalescing.command_digest.as_deref(),
    ) && expected != observed
    {
        return Some(format!(
            "command digest mismatch: expected {expected}, observed {observed}"
        ));
    }
    None
}

fn stale_handoff_ready(input: &SwarmValidationAdmissionInputFixture) -> bool {
    let stale_after_secs = input.policy.stale_handoff_after_ms / 1_000;
    let stale_owner = input
        .proof
        .owner_agent
        .as_deref()
        .filter(|owner| *owner != input.agent_name.as_str());

    if input.proof.lease_state == SwarmValidationProofLeaseState::Stale && stale_owner.is_some() {
        return true;
    }

    input.coordination.build_slots.iter().any(|slot| {
        slot.state == SwarmValidationBuildSlotState::Stale
            && slot.holder_agent != input.agent_name
            && slot.last_progress_age_secs >= stale_after_secs
    }) || input.coordination.active_agents.iter().any(|agent| {
        stale_owner == Some(agent.agent_name.as_str())
            && agent.last_active_age_secs >= stale_after_secs
    })
}

fn workspace_pressure_requires_defer(input: &SwarmValidationAdmissionInputFixture) -> bool {
    input.workspace.memory_pressure >= WORKSPACE_PRESSURE_DEFER_THRESHOLD
        || input.host.memory_pressure >= WORKSPACE_PRESSURE_DEFER_THRESHOLD
}

fn rch_queue_saturated(input: &SwarmValidationAdmissionInputFixture) -> bool {
    input.rch.queue.rch_available
        && (input.rch.queue.workers_available == 0
            || input.rch.queue.queued_builds > input.rch.queue.workers_available)
}

fn execution_hints(
    input: &SwarmValidationAdmissionInputFixture,
    parts: &SwarmValidationDecisionParts,
) -> SwarmValidationExecutionHints {
    let requires_rch = requested_action_requires_cargo(input.requested_action);
    let target_dir_strategy = target_dir_strategy(input);
    let coalescing_key = coalescing_key_hint(input, parts);
    let worker_requirement = worker_requirement_hint(input, requires_rch);

    SwarmValidationExecutionHints {
        schema_version: SWARM_VALIDATION_ADMISSION_EXECUTION_HINT_SCHEMA_VERSION.to_string(),
        target_dir_strategy,
        target_dir: target_dir_for_strategy(input, target_dir_strategy),
        build_slot_name: build_slot_name_hint(input, requires_rch),
        rch_priority: requires_rch.then_some(input.bead.priority),
        worker_requirement,
        coalescing_key: coalescing_key.clone(),
        lane_budget: lane_budget_hint(input, parts, requires_rch),
        advisory_notes: advisory_notes(
            input,
            parts,
            target_dir_strategy,
            worker_requirement,
            coalescing_key.as_deref(),
            requires_rch,
        ),
    }
}

fn target_dir_strategy(
    input: &SwarmValidationAdmissionInputFixture,
) -> SwarmValidationTargetDirStrategy {
    if !requested_action_uses_target_dir(input.requested_action) {
        return SwarmValidationTargetDirStrategy::NoTargetDirRequired;
    }

    if target_dir_disk_pressure(input) {
        return SwarmValidationTargetDirStrategy::DeferForDiskPressure;
    }

    if input.target_dir.active_target_dir_leases > 0 {
        return SwarmValidationTargetDirStrategy::DeferForTargetDirLease;
    }

    if input.proof.coalescing.is_some()
        || matches!(
            input.proof.lease_state,
            SwarmValidationProofLeaseState::InFlightFresh
                | SwarmValidationProofLeaseState::CompletedFresh
        )
    {
        return SwarmValidationTargetDirStrategy::JoinExistingProofLease;
    }

    if input.target_dir.isolated_target_dir.is_some() {
        SwarmValidationTargetDirStrategy::ReuseIsolated
    } else {
        SwarmValidationTargetDirStrategy::CreateUniqueTemp
    }
}

fn target_dir_for_strategy(
    input: &SwarmValidationAdmissionInputFixture,
    strategy: SwarmValidationTargetDirStrategy,
) -> Option<String> {
    if strategy == SwarmValidationTargetDirStrategy::NoTargetDirRequired {
        return None;
    }
    Some(target_dir_hint(input))
}

fn target_dir_hint(input: &SwarmValidationAdmissionInputFixture) -> String {
    input
        .target_dir
        .isolated_target_dir
        .clone()
        .unwrap_or_else(|| {
            format!(
                "/tmp/rch_target_franken_node_{}_{}",
                stable_token(&input.bead.bead_id),
                stable_token(input.requested_action.as_str())
            )
        })
}

fn build_slot_name_hint(
    input: &SwarmValidationAdmissionInputFixture,
    requires_rch: bool,
) -> Option<String> {
    if !requires_rch {
        return None;
    }

    if let Some(lease_id) = input
        .proof
        .coalescing
        .as_ref()
        .and_then(|coalescing| coalescing.lease_id.as_deref())
    {
        return Some(format!("rch-proof-{}", stable_token(lease_id)));
    }

    if let Some(slot) = input.coordination.build_slots.iter().find(|slot| {
        optional_command_digest_eq(
            slot.command_digest.as_deref(),
            input.proof.command_digest.as_deref(),
        )
    }) {
        return Some(slot.slot.clone());
    }

    Some(format!(
        "rch-sva-{}-{}",
        stable_token(&input.bead.bead_id),
        stable_token(input.requested_action.as_str())
    ))
}

fn optional_command_digest_eq(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => constant_time::ct_eq(left, right),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

fn coalescing_key_hint(
    input: &SwarmValidationAdmissionInputFixture,
    parts: &SwarmValidationDecisionParts,
) -> Option<String> {
    parts
        .coalescing_target
        .as_ref()
        .and_then(|target| {
            target
                .proof_work_key
                .clone()
                .or_else(|| target.proof_cache_key.clone())
                .or_else(|| target.command_digest.clone())
        })
        .or_else(|| input.proof.proof_work_key.clone())
        .or_else(|| input.proof.command_digest.clone())
}

fn worker_requirement_hint(
    input: &SwarmValidationAdmissionInputFixture,
    requires_rch: bool,
) -> SwarmValidationWorkerRequirement {
    if !requires_rch {
        return SwarmValidationWorkerRequirement::SourceOnlyLocal;
    }

    if !input.rch.queue.rch_available || input.rch.workers_total == 0 {
        return SwarmValidationWorkerRequirement::RestoreRchBeforeCargo;
    }

    if rch_queue_saturated(input) || input.rch.workers_healthy == 0 {
        return SwarmValidationWorkerRequirement::WaitForRchCapacity;
    }

    if high_memory_headroom(input) {
        SwarmValidationWorkerRequirement::PreferHighMemoryRemote
    } else {
        SwarmValidationWorkerRequirement::RequireHealthyRemote
    }
}

fn lane_budget_hint(
    input: &SwarmValidationAdmissionInputFixture,
    parts: &SwarmValidationDecisionParts,
    requires_rch: bool,
) -> SwarmValidationLaneBudgetHint {
    if !requires_rch {
        return SwarmValidationLaneBudgetHint {
            max_parallel_rch_jobs: 0,
            cargo_build_jobs: 0,
            expected_build_slots: 0,
            retry_after_ms: parts.retry_after_ms,
        };
    }

    let max_parallel_rch_jobs = if parts.decision == SwarmValidationAdmissionDecision::Run {
        runnable_parallel_rch_jobs(input)
    } else {
        0
    };

    SwarmValidationLaneBudgetHint {
        max_parallel_rch_jobs,
        cargo_build_jobs: DEFAULT_CARGO_BUILD_JOBS,
        expected_build_slots: 1,
        retry_after_ms: parts.retry_after_ms,
    }
}

fn runnable_parallel_rch_jobs(input: &SwarmValidationAdmissionInputFixture) -> u16 {
    if high_memory_headroom(input) {
        HIGH_HEADROOM_PARALLEL_RCH_JOBS.min(input.rch.queue.workers_available.max(1))
    } else {
        DEFAULT_PARALLEL_RCH_JOBS
    }
}

fn advisory_notes(
    input: &SwarmValidationAdmissionInputFixture,
    parts: &SwarmValidationDecisionParts,
    target_dir_strategy: SwarmValidationTargetDirStrategy,
    worker_requirement: SwarmValidationWorkerRequirement,
    coalescing_key: Option<&str>,
    requires_rch: bool,
) -> Vec<String> {
    let mut notes = Vec::new();

    if requires_rch {
        push_bounded(
            &mut notes,
            "cargo validation must use rch exec --; bare cargo is not allowed on the shared host"
                .to_string(),
            MAX_SWARM_ADMISSION_ADVISORY_NOTES,
        );
    } else {
        push_bounded(
            &mut notes,
            "source-only action does not require RCH or CARGO_TARGET_DIR".to_string(),
            MAX_SWARM_ADMISSION_ADVISORY_NOTES,
        );
    }

    if target_dir_strategy == SwarmValidationTargetDirStrategy::CreateUniqueTemp {
        push_bounded(
            &mut notes,
            "narrow diagnostic probe should use a bead/action-specific CARGO_TARGET_DIR"
                .to_string(),
            MAX_SWARM_ADMISSION_ADVISORY_NOTES,
        );
    }

    if target_dir_disk_pressure(input) {
        push_bounded(
            &mut notes,
            "free disk is below two target-dir footprints; avoid creating another target dir"
                .to_string(),
            MAX_SWARM_ADMISSION_ADVISORY_NOTES,
        );
    }

    if rch_queue_saturated(input)
        || worker_requirement == SwarmValidationWorkerRequirement::WaitForRchCapacity
    {
        push_bounded(
            &mut notes,
            "RCH queue is saturated; wait for remote worker capacity before starting cargo"
                .to_string(),
            MAX_SWARM_ADMISSION_ADVISORY_NOTES,
        );
    }

    if high_memory_headroom(input)
        && worker_requirement == SwarmValidationWorkerRequirement::PreferHighMemoryRemote
    {
        push_bounded(
            &mut notes,
            "host headroom supports limited parallel RCH lanes; keep CARGO_BUILD_JOBS=1 per lane"
                .to_string(),
            MAX_SWARM_ADMISSION_ADVISORY_NOTES,
        );
    }

    if coalescing_key.is_some()
        && matches!(
            parts.decision,
            SwarmValidationAdmissionDecision::Coalesce | SwarmValidationAdmissionDecision::Handoff
        )
    {
        push_bounded(
            &mut notes,
            "matching proof work exists; join by coalescing key instead of starting duplicate cargo"
                .to_string(),
            MAX_SWARM_ADMISSION_ADVISORY_NOTES,
        );
    }

    if requires_rch && parts.decision != SwarmValidationAdmissionDecision::Run {
        push_bounded(
            &mut notes,
            "lane budget blocks new RCH jobs until the admission decision changes".to_string(),
            MAX_SWARM_ADMISSION_ADVISORY_NOTES,
        );
    }

    notes
}

fn requested_action_uses_target_dir(action: SwarmValidationRequestedAction) -> bool {
    matches!(
        action,
        SwarmValidationRequestedAction::CargoCheck
            | SwarmValidationRequestedAction::CargoTest
            | SwarmValidationRequestedAction::CargoClippy
    )
}

fn high_memory_headroom(input: &SwarmValidationAdmissionInputFixture) -> bool {
    input.host.memory_bytes >= HIGH_MEMORY_HEADROOM_BYTES
        && input.host.cpu_cores >= 32
        && input.workspace.memory_pressure < HIGH_MEMORY_HEADROOM_PRESSURE_THRESHOLD
        && input.host.memory_pressure < HIGH_MEMORY_HEADROOM_PRESSURE_THRESHOLD
}

fn target_dir_disk_pressure(input: &SwarmValidationAdmissionInputFixture) -> bool {
    let target_dir_bytes = input
        .target_dir
        .target_dir_bytes
        .max(input.workspace.target_dir_bytes);
    target_dir_bytes > 0
        && input.workspace.free_disk_bytes
            <= target_dir_bytes.saturating_mul(DISK_PRESSURE_TARGET_DIR_MULTIPLIER)
}

fn coalescing_target(
    input: &SwarmValidationAdmissionInputFixture,
) -> SwarmValidationAdmissionCoalescingTarget {
    if let Some(coalescing) = &input.proof.coalescing {
        return SwarmValidationAdmissionCoalescingTarget {
            proof_work_key: coalescing
                .proof_work_key
                .clone()
                .or_else(|| input.proof.proof_work_key.clone()),
            proof_cache_key: coalescing.proof_cache_key.clone(),
            command_digest: coalescing
                .command_digest
                .clone()
                .or_else(|| input.proof.command_digest.clone()),
            owner_agent: coalescing
                .owner_agent
                .clone()
                .or_else(|| input.proof.owner_agent.clone()),
            owner_bead_id: coalescing.owner_bead_id.clone(),
            lease_id: coalescing.lease_id.clone(),
            lease_state: coalescing.lease_state.clone(),
            receipt_id: coalescing.receipt_id.clone(),
            receipt_path: coalescing.receipt_path.clone(),
            evidence_ref: input
                .proof
                .proof_evidence
                .first()
                .map(|evidence| evidence.evidence_ref.clone())
                .or_else(|| coalescing.cache_entry_path.clone())
                .or_else(|| coalescing.receipt_path.clone()),
            reason_code: coalescing.reason_code.clone(),
            required_action: coalescing.required_action.clone(),
            freshness_expires_at: coalescing.freshness_expires_at,
            expected_wait_ms: coalescing.expected_wait_ms,
        };
    }

    SwarmValidationAdmissionCoalescingTarget {
        proof_work_key: input.proof.proof_work_key.clone(),
        proof_cache_key: None,
        command_digest: input.proof.command_digest.clone(),
        owner_agent: input.proof.owner_agent.clone(),
        owner_bead_id: None,
        lease_id: None,
        lease_state: Some(input.proof.lease_state.as_str().to_string()),
        receipt_id: None,
        receipt_path: None,
        evidence_ref: input
            .proof
            .proof_evidence
            .first()
            .map(|evidence| evidence.evidence_ref.clone()),
        reason_code: None,
        required_action: None,
        freshness_expires_at: None,
        expected_wait_ms: None,
    }
}

fn safe_rch_command_shape(input: &SwarmValidationAdmissionInputFixture) -> String {
    match input.requested_action {
        SwarmValidationRequestedAction::CargoCheck => {
            let target_dir = target_dir_hint(input);
            format!(
                "rch exec -- env CARGO_TARGET_DIR={target_dir} cargo check -p frankenengine-node --lib --no-default-features"
            )
        }
        SwarmValidationRequestedAction::CargoTest => {
            let target_dir = target_dir_hint(input);
            format!(
                "rch exec -- env CARGO_TARGET_DIR={target_dir} cargo test -p frankenengine-node --lib --no-default-features swarm_validation_admission"
            )
        }
        SwarmValidationRequestedAction::CargoClippy => {
            let target_dir = target_dir_hint(input);
            format!(
                "rch exec -- env CARGO_TARGET_DIR={target_dir} cargo clippy -p frankenengine-node --lib --no-default-features -- -D warnings"
            )
        }
        SwarmValidationRequestedAction::CargoFmt => "rch exec -- cargo fmt --check".to_string(),
        SwarmValidationRequestedAction::SourceCheck
        | SwarmValidationRequestedAction::PythonGate
        | SwarmValidationRequestedAction::EvidenceGate
        | SwarmValidationRequestedAction::Closeout => String::new(),
    }
}

fn evidence_refs(input: &SwarmValidationAdmissionInputFixture) -> Vec<String> {
    let mut refs = Vec::new();
    for evidence in &input.proof.proof_evidence {
        push_bounded(
            &mut refs,
            evidence.evidence_ref.clone(),
            MAX_SWARM_ADMISSION_EVIDENCE_REFS,
        );
    }
    if let Some(coalescing) = &input.proof.coalescing {
        if let Some(lease_id) = &coalescing.lease_id {
            push_bounded(
                &mut refs,
                format!("validation-proof-coalescer:lease:{lease_id}"),
                MAX_SWARM_ADMISSION_EVIDENCE_REFS,
            );
        }
        if let Some(cache_entry_path) = &coalescing.cache_entry_path {
            push_bounded(
                &mut refs,
                cache_entry_path.clone(),
                MAX_SWARM_ADMISSION_EVIDENCE_REFS,
            );
        }
        if let Some(receipt_path) = &coalescing.receipt_path {
            push_bounded(
                &mut refs,
                receipt_path.clone(),
                MAX_SWARM_ADMISSION_EVIDENCE_REFS,
            );
        }
    }
    for reservation in &input.coordination.reservations {
        push_bounded(
            &mut refs,
            format!(
                "agent-mail-reservation:{}:{}",
                reservation.holder_agent, reservation.path_pattern
            ),
            MAX_SWARM_ADMISSION_EVIDENCE_REFS,
        );
    }
    for slot in &input.coordination.build_slots {
        push_bounded(
            &mut refs,
            format!("rch-build-slot:{}:{}", slot.holder_agent, slot.slot),
            MAX_SWARM_ADMISSION_EVIDENCE_REFS,
        );
    }
    if refs.is_empty() {
        push_bounded(
            &mut refs,
            format!("input:{}", input.input_id),
            MAX_SWARM_ADMISSION_EVIDENCE_REFS,
        );
    }
    refs
}

fn operator_summary(
    input: &SwarmValidationAdmissionInputFixture,
    parts: &SwarmValidationDecisionParts,
    first_evidence_ref: Option<&String>,
) -> String {
    let mut summary = format!(
        "{} decision={} reason={} action={} proof_source={}",
        input.bead.bead_id,
        parts.decision.as_str(),
        parts.reason_code,
        parts.required_action,
        parts.proof_source.as_str()
    );
    if let Some(command) = &parts.safe_command_shape
        && !command.is_empty()
    {
        summary.push_str(" command=");
        summary.push_str(command);
    }
    if let Some(evidence_ref) = first_evidence_ref {
        summary.push_str(" evidence=");
        summary.push_str(evidence_ref);
    }
    truncate_summary(summary)
}

fn truncate_summary(mut summary: String) -> String {
    if summary.len() <= OPERATOR_SUMMARY_MAX_BYTES {
        return summary;
    }

    let mut end = OPERATOR_SUMMARY_MAX_BYTES;
    while !summary.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    summary.truncate(end);
    summary
}

fn stable_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn empty_swarm_fixture(observed_at: DateTime<Utc>) -> SwarmValidationAdmissionFixture {
    fixture(
        SwarmValidationAdmissionFixtureKind::EmptySwarm,
        base_input(
            "empty-swarm",
            observed_at,
            SwarmValidationRequestedAction::SourceCheck,
        ),
        SwarmValidationAdmissionDecision::Run,
        "SVA_RUN_SOURCE_ONLY_READY",
        "run_source_only_checks",
        false,
        None,
    )
}

fn single_agent_fixture(observed_at: DateTime<Utc>) -> SwarmValidationAdmissionFixture {
    let mut input = base_input(
        "single-agent",
        observed_at,
        SwarmValidationRequestedAction::CargoTest,
    );
    input
        .coordination
        .active_agents
        .push(active_agent("NavyTurtle", 12));

    fixture(
        SwarmValidationAdmissionFixtureKind::SingleAgent,
        input,
        SwarmValidationAdmissionDecision::Run,
        "SVA_RUN_RCH_READY",
        "start_rch_validation",
        true,
        None,
    )
}

fn saturated_rch_queue_fixture(observed_at: DateTime<Utc>) -> SwarmValidationAdmissionFixture {
    let mut input = base_input(
        "saturated-rch-queue",
        observed_at,
        SwarmValidationRequestedAction::CargoTest,
    );
    input.rch.queue = ValidationShardRchQueueState::saturated(24, 12);
    input.rch.workers_healthy = 0;
    input.rch.worker_pressure_summary = "queue saturated: 24 queued, 12 active".to_string();

    fixture(
        SwarmValidationAdmissionFixtureKind::SaturatedRchQueue,
        input,
        SwarmValidationAdmissionDecision::Defer,
        "SVA_DEFER_RCH_QUEUE",
        "wait_for_rch_capacity",
        false,
        Some(DEFAULT_RETRY_AFTER_MS),
    )
}

fn duplicate_proof_request_fixture(observed_at: DateTime<Utc>) -> SwarmValidationAdmissionFixture {
    let mut input = base_input(
        "duplicate-proof-request",
        observed_at,
        SwarmValidationRequestedAction::CargoTest,
    );
    input
        .coordination
        .active_agents
        .push(active_agent("ScarletSeal", 8));
    input.proof = SwarmValidationProofSnapshot {
        lease_state: SwarmValidationProofLeaseState::InFlightFresh,
        proof_work_key: Some("sha256:proof-work-key-duplicate".to_string()),
        command_digest: Some("sha256:command-digest-duplicate".to_string()),
        owner_agent: Some("ScarletSeal".to_string()),
        proof_evidence: vec![ValidationShardProofEvidence::coalescer_in_flight(
            "cargo-test-frankenengine-node",
            "validation-proof-coalescer/leases/lease-duplicate",
        )],
        coalescing: Some(coalescing_in_flight(InFlightProofCoalescingArgs {
            proof_work_key: "sha256:proof-work-key-duplicate",
            proof_cache_key: "sha256:proof-cache-key-duplicate",
            command_digest: "sha256:command-digest-duplicate",
            owner_agent: "ScarletSeal",
            owner_bead_id: "bd-0x4fy.4",
            lease_id: "vpco-lease-duplicate",
            freshness_expires_at: observed_at + TimeDelta::minutes(7),
            expected_wait_ms: 45_000,
        })),
    };

    fixture(
        SwarmValidationAdmissionFixtureKind::DuplicateProofRequest,
        input,
        SwarmValidationAdmissionDecision::Coalesce,
        "SWARM-COALESCE-IN-FLIGHT",
        "join_existing_proof",
        true,
        None,
    )
}

fn incompatible_proof_request_fixture(
    observed_at: DateTime<Utc>,
) -> SwarmValidationAdmissionFixture {
    let mut input = base_input(
        "incompatible-proof-request",
        observed_at,
        SwarmValidationRequestedAction::CargoTest,
    );
    input.proof = SwarmValidationProofSnapshot {
        lease_state: SwarmValidationProofLeaseState::InFlightFresh,
        proof_work_key: Some("sha256:proof-work-key-incompatible".to_string()),
        command_digest: Some("sha256:command-digest-incompatible".to_string()),
        owner_agent: Some("ScarletSeal".to_string()),
        proof_evidence: vec![ValidationShardProofEvidence::coalescer_in_flight(
            "cargo-test-frankenengine-node",
            "validation-proof-coalescer/leases/lease-incompatible",
        )],
        coalescing: Some(coalescing_incompatible_profile(
            "sha256:proof-work-key-incompatible",
            "sha256:proof-cache-key-incompatible",
            "sha256:command-digest-incompatible",
            "ScarletSeal",
            "bd-0x4fy.4",
            "vpco-lease-incompatible",
        )),
    };

    fixture(
        SwarmValidationAdmissionFixtureKind::IncompatibleProofRequest,
        input,
        SwarmValidationAdmissionDecision::Blocked,
        "SWARM-INCOMPATIBLE-PROOF",
        "start_distinct_proof_or_rebuild_key",
        false,
        None,
    )
}

fn expired_proof_cache_entry_fixture(
    observed_at: DateTime<Utc>,
) -> SwarmValidationAdmissionFixture {
    let mut input = base_input(
        "expired-proof-cache-entry",
        observed_at,
        SwarmValidationRequestedAction::Closeout,
    );
    input.proof = SwarmValidationProofSnapshot {
        lease_state: SwarmValidationProofLeaseState::CompletedFresh,
        proof_work_key: Some("sha256:proof-work-key-expired".to_string()),
        command_digest: Some("sha256:command-digest-expired".to_string()),
        owner_agent: Some("SunnyIvy".to_string()),
        proof_evidence: vec![ValidationShardProofEvidence::cache_hit(
            "cargo-test-frankenengine-node",
            "validation-proof-cache/entries/entry-expired.json",
        )],
        coalescing: Some(coalescing_expired_cache(
            "sha256:proof-work-key-expired",
            "sha256:proof-cache-key-expired",
            "sha256:command-digest-expired",
            "vpc-entry-expired",
            "validation-proof-cache/entries/entry-expired.json",
            "validation-proof-cache/receipts/receipt-expired.json",
            observed_at - TimeDelta::seconds(1),
        )),
    };

    fixture(
        SwarmValidationAdmissionFixtureKind::ExpiredProofCacheEntry,
        input,
        SwarmValidationAdmissionDecision::Blocked,
        "SWARM-STALE-CACHE",
        "refresh_validation_evidence",
        false,
        None,
    )
}

fn owner_dead_stale_lease_fixture(observed_at: DateTime<Utc>) -> SwarmValidationAdmissionFixture {
    let mut input = base_input(
        "owner-dead-stale-lease",
        observed_at,
        SwarmValidationRequestedAction::CargoTest,
    );
    input
        .coordination
        .active_agents
        .push(active_agent("ScarletSeal", 9_000));
    input.proof = SwarmValidationProofSnapshot {
        lease_state: SwarmValidationProofLeaseState::InFlightFresh,
        proof_work_key: Some("sha256:proof-work-key-owner-dead".to_string()),
        command_digest: Some("sha256:command-digest-owner-dead".to_string()),
        owner_agent: Some("ScarletSeal".to_string()),
        proof_evidence: vec![ValidationShardProofEvidence::coalescer_in_flight(
            "cargo-test-frankenengine-node",
            "validation-proof-coalescer/leases/lease-owner-dead",
        )],
        coalescing: Some(coalescing_owner_dead(
            "sha256:proof-work-key-owner-dead",
            "sha256:proof-cache-key-owner-dead",
            "sha256:command-digest-owner-dead",
            "ScarletSeal",
            "bd-0x4fy.4",
            "vpco-lease-owner-dead",
        )),
    };

    fixture(
        SwarmValidationAdmissionFixtureKind::OwnerDeadStaleLease,
        input,
        SwarmValidationAdmissionDecision::Handoff,
        "SWARM-STALE-LEASE",
        "request_agent_handoff",
        false,
        None,
    )
}

fn proof_cache_hit_fixture(observed_at: DateTime<Utc>) -> SwarmValidationAdmissionFixture {
    let mut input = base_input(
        "proof-cache-hit",
        observed_at,
        SwarmValidationRequestedAction::Closeout,
    );
    input.proof = SwarmValidationProofSnapshot {
        lease_state: SwarmValidationProofLeaseState::CompletedFresh,
        proof_work_key: Some("sha256:proof-work-key-cache-hit".to_string()),
        command_digest: Some("sha256:command-digest-cache-hit".to_string()),
        owner_agent: Some("SunnyIvy".to_string()),
        proof_evidence: vec![ValidationShardProofEvidence::cache_hit(
            "cargo-test-frankenengine-node",
            "validation-proof-cache/receipts/receipt-cache-hit.json",
        )],
        coalescing: Some(coalescing_cache_hit(CacheHitProofCoalescingArgs {
            proof_work_key: "sha256:proof-work-key-cache-hit",
            proof_cache_key: "sha256:proof-cache-key-cache-hit",
            command_digest: "sha256:command-digest-cache-hit",
            cache_entry_id: "vpc-entry-cache-hit",
            cache_entry_path: "validation-proof-cache/entries/entry-cache-hit.json",
            receipt_id: "vbrcpt-cache-hit",
            receipt_path: "validation-proof-cache/receipts/receipt-cache-hit.json",
            freshness_expires_at: observed_at + TimeDelta::minutes(5),
        })),
    };

    fixture(
        SwarmValidationAdmissionFixtureKind::ProofCacheHit,
        input,
        SwarmValidationAdmissionDecision::Coalesce,
        "SWARM-CACHE-HIT",
        "reuse_fresh_receipt",
        true,
        None,
    )
}

fn stale_lease_fixture(observed_at: DateTime<Utc>) -> SwarmValidationAdmissionFixture {
    let mut input = base_input(
        "stale-lease",
        observed_at,
        SwarmValidationRequestedAction::CargoTest,
    );
    input
        .coordination
        .active_agents
        .push(active_agent("RainyFrog", 7_200));
    input
        .coordination
        .build_slots
        .push(stale_build_slot("rch-proof-bd-0x4fy-2", "RainyFrog"));
    input.proof = SwarmValidationProofSnapshot {
        lease_state: SwarmValidationProofLeaseState::Stale,
        proof_work_key: Some("sha256:proof-work-key-stale".to_string()),
        command_digest: Some("sha256:command-digest-stale".to_string()),
        owner_agent: Some("RainyFrog".to_string()),
        proof_evidence: Vec::new(),
        coalescing: None,
    };

    fixture(
        SwarmValidationAdmissionFixtureKind::StaleLease,
        input,
        SwarmValidationAdmissionDecision::Handoff,
        "SWARM-STALE-LEASE",
        "request_agent_handoff",
        false,
        None,
    )
}

fn high_memory_pressure_fixture(observed_at: DateTime<Utc>) -> SwarmValidationAdmissionFixture {
    let mut input = base_input(
        "high-memory-pressure",
        observed_at,
        SwarmValidationRequestedAction::CargoCheck,
    );
    input.workspace.memory_pressure = 0.94;
    input.workspace.active_build_count = 7;
    input.host.memory_pressure = 0.94;
    input.host.active_build_count = 7;

    fixture(
        SwarmValidationAdmissionFixtureKind::HighMemoryPressure,
        input,
        SwarmValidationAdmissionDecision::Defer,
        "SVA_DEFER_WORKSPACE_PRESSURE",
        "refresh_pressure_after_backoff",
        false,
        Some(DEFAULT_RETRY_AFTER_MS),
    )
}

fn missing_agent_mail_state_fixture(observed_at: DateTime<Utc>) -> SwarmValidationAdmissionFixture {
    let mut input = base_input(
        "missing-agent-mail-state",
        observed_at,
        SwarmValidationRequestedAction::CargoTest,
    );
    input.workspace.coordination_healthy = false;
    input.coordination.state = SwarmValidationCoordinationState::Unavailable;
    push_bounded(
        &mut input.missing_signals,
        SwarmValidationUnavailableSignal::AgentMail,
        MAX_SWARM_ADMISSION_UNAVAILABLE_SIGNALS,
    );

    fixture(
        SwarmValidationAdmissionFixtureKind::MissingAgentMailState,
        input,
        SwarmValidationAdmissionDecision::Blocked,
        "SVA_BLOCKED_TELEMETRY_GAP",
        "refresh_required_telemetry",
        false,
        None,
    )
}

fn fixture(
    kind: SwarmValidationAdmissionFixtureKind,
    input: SwarmValidationAdmissionInputFixture,
    decision: SwarmValidationAdmissionDecision,
    reason_code: &str,
    required_action: &str,
    green_proof_eligible: bool,
    retry_after_ms: Option<u64>,
) -> SwarmValidationAdmissionFixture {
    SwarmValidationAdmissionFixture {
        fixture_id: format!("sva-fixture-{}", kind.as_str()),
        fixture_kind: kind,
        input: input.normalize(),
        expectation: SwarmValidationAdmissionFixtureExpectation {
            decision,
            reason_code: reason_code.to_string(),
            required_action: required_action.to_string(),
            green_proof_eligible,
            retry_after_ms,
        },
    }
}

fn base_input(
    fixture_suffix: &str,
    observed_at: DateTime<Utc>,
    requested_action: SwarmValidationRequestedAction,
) -> SwarmValidationAdmissionInputFixture {
    let bead_id = "bd-0x4fy.4".to_string();
    let mut proof = SwarmValidationProofSnapshot::none();
    if requested_action_requires_cargo(requested_action) {
        proof.proof_work_key = Some(format!("sha256:proof-work-key-{fixture_suffix}"));
        proof.command_digest = Some(format!("sha256:command-digest-{fixture_suffix}"));
    }

    SwarmValidationAdmissionInputFixture {
        schema_version: SWARM_VALIDATION_ADMISSION_INPUT_SCHEMA_VERSION.to_string(),
        input_id: format!("sva-input-{fixture_suffix}"),
        trace_id: format!("trace-sva-{fixture_suffix}"),
        observed_at,
        freshness_expires_at: observed_at + TimeDelta::minutes(10),
        bead: SwarmValidationBeadSnapshot {
            bead_id: bead_id.clone(),
            thread_id: bead_id,
            status: SwarmValidationBeadStatus::InProgress,
            priority: SwarmValidationAdmissionPriority::P1,
            assignee: Some("NavyTurtle".to_string()),
            updated_at: observed_at,
            dependency_ids: vec!["bd-0x4fy.2".to_string(), "bd-0x4fy.3".to_string()],
            dependent_ids: vec!["bd-0x4fy.7".to_string(), "bd-0x4fy.8".to_string()],
        },
        agent_name: "NavyTurtle".to_string(),
        requested_action,
        workspace: WorkspacePressureInputs {
            free_disk_bytes: 512 * 1024 * 1024 * 1024,
            target_dir_bytes: 24 * 1024 * 1024 * 1024,
            active_build_count: 0,
            rch_available_slots: Some(4),
            memory_pressure: 0.24,
            active_reservations: 0,
            coordination_healthy: true,
        },
        host: SwarmHostPressureSnapshot {
            cpu_cores: 64,
            memory_bytes: 256 * 1024 * 1024 * 1024,
            memory_pressure: 0.24,
            active_build_count: 0,
        },
        target_dir: SwarmTargetDirPressureSnapshot {
            target_dir_policy_id: "target-dir-policy/off-repo-per-agent/v1".to_string(),
            active_target_dir_leases: 0,
            target_dir_bytes: 24 * 1024 * 1024 * 1024,
            isolated_target_dir: Some("/tmp/rch_target_navyturtle_sva".to_string()),
        },
        rch: SwarmValidationRchSnapshot {
            queue: ValidationShardRchQueueState::default(),
            workers_total: 8,
            workers_healthy: 8,
            worker_pressure_summary: "all workers healthy".to_string(),
        },
        proof,
        coordination: SwarmValidationCoordinationSnapshot::empty(),
        policy: SwarmValidationPolicyProfile::repo_default(),
        missing_signals: Vec::new(),
    }
}

fn active_agent(agent_name: &str, last_active_age_secs: u64) -> SwarmValidationAgentSnapshot {
    SwarmValidationAgentSnapshot {
        agent_name: agent_name.to_string(),
        project_key: "/data/projects/franken_node".to_string(),
        last_active_age_secs,
        ack_required_count: 0,
    }
}

fn stale_build_slot(slot: &str, holder_agent: &str) -> SwarmValidationBuildSlotSnapshot {
    SwarmValidationBuildSlotSnapshot {
        slot: slot.to_string(),
        holder_agent: holder_agent.to_string(),
        state: SwarmValidationBuildSlotState::Stale,
        command_digest: Some("sha256:command-digest-stale".to_string()),
        last_progress_age_secs: 7_200,
    }
}

struct InFlightProofCoalescingArgs<'a> {
    proof_work_key: &'a str,
    proof_cache_key: &'a str,
    command_digest: &'a str,
    owner_agent: &'a str,
    owner_bead_id: &'a str,
    lease_id: &'a str,
    freshness_expires_at: DateTime<Utc>,
    expected_wait_ms: u64,
}

fn coalescing_in_flight(
    args: InFlightProofCoalescingArgs<'_>,
) -> SwarmValidationProofCoalescingSnapshot {
    SwarmValidationProofCoalescingSnapshot {
        status: SwarmValidationProofCoalescingStatus::InFlight,
        compatibility: SwarmValidationProofCompatibility::Equivalent,
        proof_work_key: Some(args.proof_work_key.to_string()),
        proof_cache_key: Some(args.proof_cache_key.to_string()),
        command_digest: Some(args.command_digest.to_string()),
        owner_agent: Some(args.owner_agent.to_string()),
        owner_bead_id: Some(args.owner_bead_id.to_string()),
        waiter_agents: vec!["NavyTurtle".to_string()],
        lease_id: Some(args.lease_id.to_string()),
        lease_state: Some("running".to_string()),
        cache_entry_id: None,
        cache_entry_path: None,
        receipt_id: None,
        receipt_path: None,
        reason_code: Some("SWARM-COALESCE-IN-FLIGHT".to_string()),
        event_code: Some("SVA-004".to_string()),
        required_action: Some("join_existing_lease".to_string()),
        freshness_expires_at: Some(args.freshness_expires_at),
        expected_wait_ms: Some(args.expected_wait_ms),
        compatibility_blockers: Vec::new(),
    }
}

fn coalescing_incompatible_profile(
    proof_work_key: &str,
    proof_cache_key: &str,
    command_digest: &str,
    owner_agent: &str,
    owner_bead_id: &str,
    lease_id: &str,
) -> SwarmValidationProofCoalescingSnapshot {
    SwarmValidationProofCoalescingSnapshot {
        status: SwarmValidationProofCoalescingStatus::Incompatible,
        compatibility: SwarmValidationProofCompatibility::DifferentProfile,
        proof_work_key: Some(proof_work_key.to_string()),
        proof_cache_key: Some(proof_cache_key.to_string()),
        command_digest: Some(command_digest.to_string()),
        owner_agent: Some(owner_agent.to_string()),
        owner_bead_id: Some(owner_bead_id.to_string()),
        waiter_agents: Vec::new(),
        lease_id: Some(lease_id.to_string()),
        lease_state: Some("running".to_string()),
        cache_entry_id: None,
        cache_entry_path: None,
        receipt_id: None,
        receipt_path: None,
        reason_code: Some("SWARM-INCOMPATIBLE-PROOF".to_string()),
        event_code: Some("SVA-017".to_string()),
        required_action: Some("start_distinct_proof_or_rebuild_key".to_string()),
        freshness_expires_at: None,
        expected_wait_ms: None,
        compatibility_blockers: vec![
            "feature/profile input differs from running proof".to_string(),
        ],
    }
}

fn coalescing_expired_cache(
    proof_work_key: &str,
    proof_cache_key: &str,
    command_digest: &str,
    cache_entry_id: &str,
    cache_entry_path: &str,
    receipt_path: &str,
    freshness_expires_at: DateTime<Utc>,
) -> SwarmValidationProofCoalescingSnapshot {
    SwarmValidationProofCoalescingSnapshot {
        status: SwarmValidationProofCoalescingStatus::ExpiredProof,
        compatibility: SwarmValidationProofCompatibility::Equivalent,
        proof_work_key: Some(proof_work_key.to_string()),
        proof_cache_key: Some(proof_cache_key.to_string()),
        command_digest: Some(command_digest.to_string()),
        owner_agent: None,
        owner_bead_id: None,
        waiter_agents: Vec::new(),
        lease_id: None,
        lease_state: None,
        cache_entry_id: Some(cache_entry_id.to_string()),
        cache_entry_path: Some(cache_entry_path.to_string()),
        receipt_id: Some("vbrcpt-expired".to_string()),
        receipt_path: Some(receipt_path.to_string()),
        reason_code: Some("SWARM-STALE-CACHE".to_string()),
        event_code: Some("SVA-018".to_string()),
        required_action: Some("refresh_validation_evidence".to_string()),
        freshness_expires_at: Some(freshness_expires_at),
        expected_wait_ms: None,
        compatibility_blockers: Vec::new(),
    }
}

fn coalescing_owner_dead(
    proof_work_key: &str,
    proof_cache_key: &str,
    command_digest: &str,
    owner_agent: &str,
    owner_bead_id: &str,
    lease_id: &str,
) -> SwarmValidationProofCoalescingSnapshot {
    SwarmValidationProofCoalescingSnapshot {
        status: SwarmValidationProofCoalescingStatus::OwnerDead,
        compatibility: SwarmValidationProofCompatibility::Equivalent,
        proof_work_key: Some(proof_work_key.to_string()),
        proof_cache_key: Some(proof_cache_key.to_string()),
        command_digest: Some(command_digest.to_string()),
        owner_agent: Some(owner_agent.to_string()),
        owner_bead_id: Some(owner_bead_id.to_string()),
        waiter_agents: Vec::new(),
        lease_id: Some(lease_id.to_string()),
        lease_state: Some("running".to_string()),
        cache_entry_id: None,
        cache_entry_path: None,
        receipt_id: None,
        receipt_path: None,
        reason_code: Some("SWARM-STALE-LEASE".to_string()),
        event_code: Some("SVA-009".to_string()),
        required_action: Some("request_agent_handoff".to_string()),
        freshness_expires_at: None,
        expected_wait_ms: None,
        compatibility_blockers: Vec::new(),
    }
}

struct CacheHitProofCoalescingArgs<'a> {
    proof_work_key: &'a str,
    proof_cache_key: &'a str,
    command_digest: &'a str,
    cache_entry_id: &'a str,
    cache_entry_path: &'a str,
    receipt_id: &'a str,
    receipt_path: &'a str,
    freshness_expires_at: DateTime<Utc>,
}

fn coalescing_cache_hit(
    args: CacheHitProofCoalescingArgs<'_>,
) -> SwarmValidationProofCoalescingSnapshot {
    SwarmValidationProofCoalescingSnapshot {
        status: SwarmValidationProofCoalescingStatus::CompletedCacheHit,
        compatibility: SwarmValidationProofCompatibility::Equivalent,
        proof_work_key: Some(args.proof_work_key.to_string()),
        proof_cache_key: Some(args.proof_cache_key.to_string()),
        command_digest: Some(args.command_digest.to_string()),
        owner_agent: None,
        owner_bead_id: None,
        waiter_agents: Vec::new(),
        lease_id: None,
        lease_state: Some("completed".to_string()),
        cache_entry_id: Some(args.cache_entry_id.to_string()),
        cache_entry_path: Some(args.cache_entry_path.to_string()),
        receipt_id: Some(args.receipt_id.to_string()),
        receipt_path: Some(args.receipt_path.to_string()),
        reason_code: Some("SWARM-CACHE-HIT".to_string()),
        event_code: Some("SVA-005".to_string()),
        required_action: Some("reuse_receipt".to_string()),
        freshness_expires_at: Some(args.freshness_expires_at),
        expected_wait_ms: Some(0),
        compatibility_blockers: Vec::new(),
    }
}

fn fixture_observed_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(DEFAULT_OBSERVED_AT)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .unwrap_or_else(|_| DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH))
}

#[cfg(test)]
mod tests {
    use super::super::validation_planner::ValidationShardProofState;
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn default_fixture_catalog_covers_required_scenarios() {
        let catalog = deterministic_swarm_validation_admission_fixtures();

        assert_eq!(
            catalog.schema_version,
            SWARM_VALIDATION_ADMISSION_FIXTURE_CATALOG_SCHEMA_VERSION
        );
        assert_eq!(catalog.fixtures.len(), 11);

        for kind in [
            SwarmValidationAdmissionFixtureKind::EmptySwarm,
            SwarmValidationAdmissionFixtureKind::SingleAgent,
            SwarmValidationAdmissionFixtureKind::SaturatedRchQueue,
            SwarmValidationAdmissionFixtureKind::DuplicateProofRequest,
            SwarmValidationAdmissionFixtureKind::IncompatibleProofRequest,
            SwarmValidationAdmissionFixtureKind::ExpiredProofCacheEntry,
            SwarmValidationAdmissionFixtureKind::OwnerDeadStaleLease,
            SwarmValidationAdmissionFixtureKind::ProofCacheHit,
            SwarmValidationAdmissionFixtureKind::StaleLease,
            SwarmValidationAdmissionFixtureKind::HighMemoryPressure,
            SwarmValidationAdmissionFixtureKind::MissingAgentMailState,
        ] {
            assert!(
                catalog.fixture(kind).is_some(),
                "missing fixture {}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn fixture_serialization_is_stable_and_schema_versioned() {
        let first = serde_json::to_string(&deterministic_swarm_validation_admission_fixtures())
            .expect("fixture catalog serializes");
        let second = serde_json::to_string(&deterministic_swarm_validation_admission_fixtures())
            .expect("fixture catalog serializes deterministically");

        assert_eq!(first, second);
        assert!(first.contains(SWARM_VALIDATION_ADMISSION_INPUT_SCHEMA_VERSION));
        assert!(first.contains(SWARM_VALIDATION_ADMISSION_POLICY_PROFILE_SCHEMA_VERSION));
    }

    #[test]
    fn saturated_rch_fixture_uses_existing_queue_shape() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let fixture = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::SaturatedRchQueue)
            .expect("saturated rch fixture exists");

        assert_eq!(
            fixture.expectation.decision,
            SwarmValidationAdmissionDecision::Defer
        );
        assert_eq!(fixture.input.rch.queue.workers_available, 0);
        assert_eq!(fixture.input.rch.queue.queued_builds, 24);
        assert_eq!(
            fixture.input.expected_validation_shard_status(),
            ValidationShardStatus::Waiting
        );
    }

    #[test]
    fn duplicate_proof_fixture_records_coalescer_evidence() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let fixture = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::DuplicateProofRequest)
            .expect("duplicate proof fixture exists");

        assert_eq!(
            fixture.expectation.decision,
            SwarmValidationAdmissionDecision::Coalesce
        );
        assert_eq!(
            fixture.input.proof.lease_state,
            SwarmValidationProofLeaseState::InFlightFresh
        );
        assert!(
            fixture
                .input
                .proof
                .proof_evidence
                .iter()
                .any(|evidence| { evidence.state == ValidationShardProofState::CoalescerInFlight })
        );
    }

    #[test]
    fn same_hash_in_flight_proof_returns_owner_wait_and_action() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let fixture = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::DuplicateProofRequest)
            .expect("duplicate proof fixture exists");

        let decision = plan_swarm_validation_admission(&fixture.input);
        let target = decision
            .coalescing_target
            .as_ref()
            .expect("coalescing target");

        assert_eq!(decision.reason_code, "SWARM-COALESCE-IN-FLIGHT");
        assert_eq!(target.owner_agent.as_deref(), Some("ScarletSeal"));
        assert_eq!(target.owner_bead_id.as_deref(), Some("bd-0x4fy.4"));
        assert_eq!(target.lease_id.as_deref(), Some("vpco-lease-duplicate"));
        assert_eq!(target.expected_wait_ms, Some(45_000));
        assert_eq!(
            target.required_action.as_deref(),
            Some("join_existing_lease")
        );
        assert!(target.freshness_expires_at.is_some());
        assert_eq!(
            decision.diagnostics.proof_coalescing_status,
            SwarmValidationProofCoalescingStatus::InFlight
        );
    }

    #[test]
    fn incompatible_profile_proof_fails_closed_instead_of_reusing() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let fixture = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::IncompatibleProofRequest)
            .expect("incompatible proof fixture exists");

        let decision = plan_swarm_validation_admission(&fixture.input);

        assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Blocked);
        assert_eq!(decision.reason_code, "SWARM-INCOMPATIBLE-PROOF");
        assert!(decision.fail_closed);
        assert_eq!(
            decision.diagnostics.proof_coalescing_status,
            SwarmValidationProofCoalescingStatus::Incompatible
        );
        assert!(
            decision
                .diagnostics
                .blocked_by
                .iter()
                .any(|blocker| blocker.contains("different_profile"))
        );
    }

    #[test]
    fn expired_cache_entry_fails_closed_with_refresh_action() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let fixture = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::ExpiredProofCacheEntry)
            .expect("expired cache fixture exists");

        let decision = plan_swarm_validation_admission(&fixture.input);
        let target = decision
            .coalescing_target
            .as_ref()
            .expect("expired cache target");

        assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Blocked);
        assert_eq!(decision.reason_code, "SWARM-STALE-CACHE");
        assert_eq!(
            target.required_action.as_deref(),
            Some("refresh_validation_evidence")
        );
        assert_eq!(
            target.evidence_ref.as_deref(),
            Some("validation-proof-cache/entries/entry-expired.json")
        );
        assert!(decision.fail_closed);
    }

    #[test]
    fn owner_dead_in_flight_proof_returns_handoff() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let fixture = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::OwnerDeadStaleLease)
            .expect("owner dead fixture exists");

        let decision = plan_swarm_validation_admission(&fixture.input);

        assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Handoff);
        assert_eq!(decision.reason_code, "SWARM-STALE-LEASE");
        assert_eq!(
            decision
                .coalescing_target
                .as_ref()
                .and_then(|target| target.owner_agent.as_deref()),
            Some("ScarletSeal")
        );
    }

    #[test]
    fn missing_agent_mail_fixture_fails_closed() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let fixture = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::MissingAgentMailState)
            .expect("missing agent mail fixture exists");

        assert_eq!(
            fixture.expectation.decision,
            SwarmValidationAdmissionDecision::Blocked
        );
        assert_eq!(
            fixture.input.coordination.state,
            SwarmValidationCoordinationState::Unavailable
        );
        assert_eq!(
            fixture.input.missing_signals,
            vec![SwarmValidationUnavailableSignal::AgentMail]
        );
        assert_eq!(
            fixture.input.expected_validation_shard_status(),
            ValidationShardStatus::Blocked
        );
    }

    #[test]
    fn fixture_expectations_match_planner_decisions() {
        let catalog = deterministic_swarm_validation_admission_fixtures();

        for fixture in catalog.fixtures {
            let decision = plan_swarm_validation_admission(&fixture.input);

            assert_eq!(
                decision.decision,
                fixture.expectation.decision,
                "decision mismatch for {}",
                fixture.fixture_kind.as_str()
            );
            assert_eq!(
                decision.reason_code,
                fixture.expectation.reason_code,
                "reason mismatch for {}",
                fixture.fixture_kind.as_str()
            );
            assert_eq!(
                decision.required_action,
                fixture.expectation.required_action,
                "action mismatch for {}",
                fixture.fixture_kind.as_str()
            );
            assert_eq!(
                decision.green_proof_eligible,
                fixture.expectation.green_proof_eligible,
                "green proof eligibility mismatch for {}",
                fixture.fixture_kind.as_str()
            );
            assert_eq!(
                decision.retry_after_ms,
                fixture.expectation.retry_after_ms,
                "retry hint mismatch for {}",
                fixture.fixture_kind.as_str()
            );
            assert!(decision.diagnostics.input_freshness.fresh);
            assert!(decision.operator_summary.len() <= OPERATOR_SUMMARY_MAX_BYTES);
        }
    }

    #[test]
    fn planner_covers_all_admission_decision_states() {
        let decisions = deterministic_swarm_validation_admission_fixtures()
            .fixtures
            .into_iter()
            .map(|fixture| plan_swarm_validation_admission(&fixture.input).decision)
            .collect::<BTreeSet<_>>();
        let expected = BTreeSet::from([
            SwarmValidationAdmissionDecision::Run,
            SwarmValidationAdmissionDecision::Coalesce,
            SwarmValidationAdmissionDecision::Defer,
            SwarmValidationAdmissionDecision::Handoff,
            SwarmValidationAdmissionDecision::Blocked,
        ]);

        assert_eq!(decisions, expected);
    }

    #[test]
    fn cargo_run_decisions_only_recommend_rch_commands() {
        let catalog = deterministic_swarm_validation_admission_fixtures();

        for fixture in catalog.fixtures {
            let decision = plan_swarm_validation_admission(&fixture.input);
            if requested_action_requires_cargo(fixture.input.requested_action)
                && decision.decision == SwarmValidationAdmissionDecision::Run
            {
                let command = decision
                    .safe_command_shape
                    .as_deref()
                    .expect("cargo run decision includes command shape");
                assert!(
                    command.starts_with("rch exec --"),
                    "cargo decision must use rch: {command}"
                );
                assert!(
                    !command.starts_with("cargo "),
                    "cargo decision must not recommend bare local cargo"
                );
            }
        }
    }

    #[test]
    fn high_memory_headroom_emits_worker_priority_and_lane_budget_hints() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let mut input = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::SingleAgent)
            .expect("single agent fixture exists")
            .input
            .clone();
        input.rch.queue.workers_available = 4;

        let decision = plan_swarm_validation_admission(&input);
        let hints = &decision.execution_hints;

        assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Run);
        assert_eq!(
            hints.worker_requirement,
            SwarmValidationWorkerRequirement::PreferHighMemoryRemote
        );
        assert_eq!(
            hints.target_dir_strategy,
            SwarmValidationTargetDirStrategy::ReuseIsolated
        );
        assert_eq!(
            hints.target_dir.as_deref(),
            Some("/tmp/rch_target_navyturtle_sva")
        );
        assert_eq!(
            hints.build_slot_name.as_deref(),
            Some("rch-sva-bd-0x4fy-4-cargo-test")
        );
        assert_eq!(
            hints.rch_priority,
            Some(SwarmValidationAdmissionPriority::P1)
        );
        assert_eq!(hints.lane_budget.max_parallel_rch_jobs, 4);
        assert_eq!(hints.lane_budget.cargo_build_jobs, 1);
        assert_eq!(hints.lane_budget.expected_build_slots, 1);
        assert!(
            hints
                .advisory_notes
                .iter()
                .any(|note| note.contains("rch exec --"))
        );
        assert!(
            hints
                .advisory_notes
                .iter()
                .any(|note| note.contains("CARGO_BUILD_JOBS=1"))
        );
    }

    #[test]
    fn disk_pressure_defers_target_dir_churn() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let mut input = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::SingleAgent)
            .expect("single agent fixture exists")
            .input
            .clone();
        input.workspace.free_disk_bytes = 16 * 1024 * 1024 * 1024;
        input.target_dir.target_dir_bytes = 24 * 1024 * 1024 * 1024;

        let decision = plan_swarm_validation_admission(&input);
        let hints = &decision.execution_hints;

        assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Defer);
        assert_eq!(decision.reason_code, "SVA_DEFER_TARGET_DIR_DISK_PRESSURE");
        assert_eq!(
            hints.target_dir_strategy,
            SwarmValidationTargetDirStrategy::DeferForDiskPressure
        );
        assert_eq!(
            hints.worker_requirement,
            SwarmValidationWorkerRequirement::PreferHighMemoryRemote
        );
        assert_eq!(hints.lane_budget.max_parallel_rch_jobs, 0);
        assert_eq!(
            hints.lane_budget.retry_after_ms,
            Some(DEFAULT_RETRY_AFTER_MS)
        );
        assert!(
            hints
                .advisory_notes
                .iter()
                .any(|note| note.contains("free disk"))
        );
    }

    #[test]
    fn saturated_rch_queue_hints_wait_without_new_jobs() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let fixture = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::SaturatedRchQueue)
            .expect("saturated rch fixture exists");

        let decision = plan_swarm_validation_admission(&fixture.input);
        let hints = &decision.execution_hints;

        assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Defer);
        assert_eq!(
            hints.worker_requirement,
            SwarmValidationWorkerRequirement::WaitForRchCapacity
        );
        assert_eq!(hints.lane_budget.max_parallel_rch_jobs, 0);
        assert_eq!(
            hints.lane_budget.retry_after_ms,
            Some(DEFAULT_RETRY_AFTER_MS)
        );
        assert!(
            hints
                .advisory_notes
                .iter()
                .any(|note| note.contains("RCH queue is saturated"))
        );
    }

    #[test]
    fn narrow_diagnostic_probe_uses_unique_target_dir_hint() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let mut input = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::SingleAgent)
            .expect("single agent fixture exists")
            .input
            .clone();
        input.requested_action = SwarmValidationRequestedAction::CargoCheck;
        input.target_dir.isolated_target_dir = None;
        input.host.memory_bytes = 64 * 1024 * 1024 * 1024;

        let decision = plan_swarm_validation_admission(&input);
        let hints = &decision.execution_hints;
        let expected_target_dir = "/tmp/rch_target_franken_node_bd-0x4fy-4_cargo-check";

        assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Run);
        assert_eq!(
            hints.target_dir_strategy,
            SwarmValidationTargetDirStrategy::CreateUniqueTemp
        );
        assert_eq!(hints.target_dir.as_deref(), Some(expected_target_dir));
        assert_eq!(
            hints.build_slot_name.as_deref(),
            Some("rch-sva-bd-0x4fy-4-cargo-check")
        );
        assert_eq!(
            decision.safe_command_shape.as_deref(),
            Some(
                "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_node_bd-0x4fy-4_cargo-check cargo check -p frankenengine-node --lib --no-default-features"
            )
        );
        assert!(
            hints
                .advisory_notes
                .iter()
                .any(|note| note.contains("narrow diagnostic probe"))
        );
    }

    #[test]
    fn coalesce_decisions_include_target_and_proof_source() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let duplicate = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::DuplicateProofRequest)
            .expect("duplicate proof fixture exists");
        let cache_hit = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::ProofCacheHit)
            .expect("proof cache hit fixture exists");

        let duplicate_decision = plan_swarm_validation_admission(&duplicate.input);
        assert_eq!(
            duplicate_decision.proof_source,
            SwarmValidationProofSource::CoalescerWaiter
        );
        assert_eq!(
            duplicate_decision
                .coalescing_target
                .as_ref()
                .and_then(|target| target.owner_agent.as_deref()),
            Some("ScarletSeal")
        );
        assert_eq!(
            duplicate_decision.execution_hints.coalescing_key.as_deref(),
            Some("sha256:proof-work-key-duplicate")
        );
        assert_eq!(
            duplicate_decision.execution_hints.target_dir_strategy,
            SwarmValidationTargetDirStrategy::JoinExistingProofLease
        );
        assert_eq!(
            duplicate_decision
                .execution_hints
                .lane_budget
                .max_parallel_rch_jobs,
            0
        );

        let cache_decision = plan_swarm_validation_admission(&cache_hit.input);
        assert_eq!(
            cache_decision.proof_source,
            SwarmValidationProofSource::ProofCacheHit
        );
        assert_eq!(
            cache_decision
                .coalescing_target
                .as_ref()
                .and_then(|target| target.evidence_ref.as_deref()),
            Some("validation-proof-cache/receipts/receipt-cache-hit.json")
        );
    }

    #[test]
    fn active_external_reservation_blocks_before_run() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let mut input = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::SingleAgent)
            .expect("single agent fixture exists")
            .input
            .clone();
        input
            .coordination
            .reservations
            .push(SwarmValidationReservationSnapshot {
                holder_agent: "ScarletSeal".to_string(),
                path_pattern: "crates/franken-node/src/ops/swarm_validation_admission.rs"
                    .to_string(),
                mode: SwarmValidationReservationMode::Exclusive,
                reason: Some("bd-other".to_string()),
                expires_at: input.observed_at + TimeDelta::minutes(30),
            });

        let decision = plan_swarm_validation_admission(&input);

        assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Blocked);
        assert_eq!(decision.reason_code, "SVA_BLOCKED_ACTIVE_RESERVATION");
        assert!(decision.fail_closed);
    }

    #[test]
    fn cargo_without_command_digest_fails_closed() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let mut input = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::SingleAgent)
            .expect("single agent fixture exists")
            .input
            .clone();
        input.proof.command_digest = None;

        let decision = plan_swarm_validation_admission(&input);

        assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Blocked);
        assert_eq!(decision.reason_code, "SVA_BLOCKED_MALFORMED_INPUT");
        assert!(
            decision
                .diagnostics
                .blocked_by
                .iter()
                .any(|blocker| blocker.contains("command digest"))
        );
    }

    #[test]
    fn rch_unavailable_refuses_local_fallback() {
        let catalog = deterministic_swarm_validation_admission_fixtures();
        let mut input = catalog
            .fixture(SwarmValidationAdmissionFixtureKind::SingleAgent)
            .expect("single agent fixture exists")
            .input
            .clone();
        input.rch.queue = ValidationShardRchQueueState::unavailable();

        let decision = plan_swarm_validation_admission(&input);

        assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Blocked);
        assert_eq!(decision.reason_code, "SVA_BLOCKED_LOCAL_FALLBACK");
        assert!(decision.fail_closed);
    }
}
