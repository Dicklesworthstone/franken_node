//! Deterministic fixture model for swarm validation admission.
//!
//! This module is intentionally pure. It does not read Beads, Agent Mail, RCH,
//! or the filesystem; callers provide already-collected snapshots and tests can
//! exercise the same canonical input shape without host-specific probes.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::push_bounded;

use super::{
    validation_planner::{
        ValidationShardProofEvidence, ValidationShardRchQueueState, ValidationShardStatus,
    },
    workspace_pressure_policy::WorkspacePressureInputs,
};

pub const SWARM_VALIDATION_ADMISSION_INPUT_SCHEMA_VERSION: &str =
    "franken-node/swarm-validation-admission/input/v1";
pub const SWARM_VALIDATION_ADMISSION_POLICY_PROFILE_SCHEMA_VERSION: &str =
    "franken-node/swarm-validation-admission/policy-profile/v1";
pub const SWARM_VALIDATION_ADMISSION_FIXTURE_CATALOG_SCHEMA_VERSION: &str =
    "franken-node/swarm-validation-admission/fixture-catalog/v1";

pub const MAX_SWARM_ADMISSION_AGENTS: usize = 256;
pub const MAX_SWARM_ADMISSION_RESERVATIONS: usize = 512;
pub const MAX_SWARM_ADMISSION_BUILD_SLOTS: usize = 128;
pub const MAX_SWARM_ADMISSION_PROOF_EVIDENCE: usize = 128;
pub const MAX_SWARM_ADMISSION_UNAVAILABLE_SIGNALS: usize = 32;
pub const MAX_SWARM_ADMISSION_FIXTURES: usize = 64;

const DEFAULT_OBSERVED_AT: &str = "2026-06-18T00:00:00Z";
const DEFAULT_RETRY_AFTER_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationAdmissionFixtureKind {
    EmptySwarm,
    SingleAgent,
    SaturatedRchQueue,
    DuplicateProofRequest,
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
pub struct SwarmValidationProofSnapshot {
    pub lease_state: SwarmValidationProofLeaseState,
    pub proof_work_key: Option<String>,
    pub command_digest: Option<String>,
    pub owner_agent: Option<String>,
    pub proof_evidence: Vec<ValidationShardProofEvidence>,
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
pub fn deterministic_swarm_validation_admission_fixtures() -> SwarmValidationAdmissionFixtureCatalog
{
    let observed_at = fixture_observed_at();
    let fixtures = vec![
        empty_swarm_fixture(observed_at),
        single_agent_fixture(observed_at),
        saturated_rch_queue_fixture(observed_at),
        duplicate_proof_request_fixture(observed_at),
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
    };

    fixture(
        SwarmValidationAdmissionFixtureKind::DuplicateProofRequest,
        input,
        SwarmValidationAdmissionDecision::Coalesce,
        "SVA_COALESCE_PROOF_IN_FLIGHT",
        "join_existing_proof",
        true,
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
    };

    fixture(
        SwarmValidationAdmissionFixtureKind::ProofCacheHit,
        input,
        SwarmValidationAdmissionDecision::Coalesce,
        "SVA_COALESCE_PROOF_CACHE_HIT",
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
    };

    fixture(
        SwarmValidationAdmissionFixtureKind::StaleLease,
        input,
        SwarmValidationAdmissionDecision::Handoff,
        "SVA_HANDOFF_STALE_OWNER",
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
    let bead_id = "bd-0x4fy.2".to_string();
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
            dependency_ids: vec!["bd-0x4fy.1".to_string()],
            dependent_ids: vec![
                "bd-0x4fy.3".to_string(),
                "bd-0x4fy.4".to_string(),
                "bd-0x4fy.5".to_string(),
                "bd-0x4fy.6".to_string(),
            ],
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
        proof: SwarmValidationProofSnapshot::none(),
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

fn fixture_observed_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(DEFAULT_OBSERVED_AT)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .unwrap_or_else(|_| DateTime::<Utc>::from(std::time::SystemTime::UNIX_EPOCH))
}

#[cfg(test)]
mod tests {
    use super::super::validation_planner::ValidationShardProofState;
    use super::*;

    #[test]
    fn default_fixture_catalog_covers_required_scenarios() {
        let catalog = deterministic_swarm_validation_admission_fixtures();

        assert_eq!(
            catalog.schema_version,
            SWARM_VALIDATION_ADMISSION_FIXTURE_CATALOG_SCHEMA_VERSION
        );
        assert_eq!(catalog.fixtures.len(), 8);

        for kind in [
            SwarmValidationAdmissionFixtureKind::EmptySwarm,
            SwarmValidationAdmissionFixtureKind::SingleAgent,
            SwarmValidationAdmissionFixtureKind::SaturatedRchQueue,
            SwarmValidationAdmissionFixtureKind::DuplicateProofRequest,
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
}
