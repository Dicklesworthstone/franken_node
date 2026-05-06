//! File-backed in-flight validation proof lease coalescing.
//!
//! The lease store is intentionally independent from planner integration until
//! the downstream beads wire it into validation execution. It gives callers a
//! small durable primitive: exactly one producer creates a lease for a canonical
//! proof-work key, equivalent callers join that lease, stale owners are fenced,
//! and corrupted metadata returns repair decisions instead of being reused.

use crate::ops::validation_broker::{CommandDigest, InputDigest};
use crate::ops::validation_proof_cache::{
    DirtyStatePolicy, ProofCacheDigest, ValidationProofCacheKey,
};
use crate::security::constant_time;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub const WORK_KEY_SCHEMA_VERSION: &str = "franken-node/validation-proof-coalescer/work-key/v1";
pub const LEASE_SCHEMA_VERSION: &str = "franken-node/validation-proof-coalescer/lease/v1";
pub const DECISION_SCHEMA_VERSION: &str = "franken-node/validation-proof-coalescer/decision/v1";
pub const CAPACITY_SNAPSHOT_SCHEMA_VERSION: &str =
    "franken-node/validation-proof-coalescer/rch-capacity-snapshot/v1";
pub const ADMISSION_POLICY_SCHEMA_VERSION: &str =
    "franken-node/validation-proof-coalescer/admission-policy/v1";
pub const ADMISSION_DECISION_SCHEMA_VERSION: &str =
    "franken-node/validation-proof-coalescer/admission-decision/v1";
const SHA256_HEX_LEN: usize = 64;

pub mod error_codes {
    pub const ERR_VPCO_INVALID_SCHEMA_VERSION: &str = "ERR_VPCO_INVALID_SCHEMA_VERSION";
    pub const ERR_VPCO_MALFORMED_WORK_KEY: &str = "ERR_VPCO_MALFORMED_WORK_KEY";
    pub const ERR_VPCO_BAD_WORK_KEY: &str = "ERR_VPCO_BAD_WORK_KEY";
    pub const ERR_VPCO_COMMAND_DIGEST_MISMATCH: &str = "ERR_VPCO_COMMAND_DIGEST_MISMATCH";
    pub const ERR_VPCO_INPUT_DIGEST_MISMATCH: &str = "ERR_VPCO_INPUT_DIGEST_MISMATCH";
    pub const ERR_VPCO_MALFORMED_LEASE: &str = "ERR_VPCO_MALFORMED_LEASE";
    pub const ERR_VPCO_STALE_LEASE: &str = "ERR_VPCO_STALE_LEASE";
    pub const ERR_VPCO_FENCED_OWNER: &str = "ERR_VPCO_FENCED_OWNER";
    pub const ERR_VPCO_DIRTY_POLICY: &str = "ERR_VPCO_DIRTY_POLICY";
    pub const ERR_VPCO_CAPACITY_REJECTED: &str = "ERR_VPCO_CAPACITY_REJECTED";
    pub const ERR_VPCO_CORRUPTED_STATE: &str = "ERR_VPCO_CORRUPTED_STATE";
    pub const ERR_VPCO_MALFORMED_DECISION: &str = "ERR_VPCO_MALFORMED_DECISION";
    pub const ERR_VPCO_MALFORMED_POLICY: &str = "ERR_VPCO_MALFORMED_POLICY";
    pub const ERR_VPCO_DUPLICATE_LEASE: &str = "ERR_VPCO_DUPLICATE_LEASE";
}

pub mod event_codes {
    pub const LOOKUP_STARTED: &str = "VPCO-001";
    pub const PRODUCER_ADMITTED: &str = "VPCO-002";
    pub const WAITER_JOINED: &str = "VPCO-003";
    pub const WAIT_FOR_RECEIPT: &str = "VPCO-004";
    pub const QUEUED_BY_CAPACITY: &str = "VPCO-005";
    pub const STALE_LEASE_FENCED: &str = "VPCO-006";
    pub const DIRTY_POLICY_REJECTED: &str = "VPCO-007";
    pub const CAPACITY_REJECTED: &str = "VPCO-008";
    pub const CORRUPTED_STATE_REPAIR: &str = "VPCO-009";
    pub const RECEIPT_HANDOFF_COMPLETED: &str = "VPCO-010";
}

pub mod reason_codes {
    pub const RUN_NO_LEASE: &str = "VPCO_RUN_NO_LEASE";
    pub const JOIN_RUNNING: &str = "VPCO_JOIN_RUNNING";
    pub const WAIT_COMPLETION: &str = "VPCO_WAIT_COMPLETION";
    pub const QUEUE_CAPACITY: &str = "VPCO_QUEUE_CAPACITY";
    pub const RETRY_STALE: &str = "VPCO_RETRY_STALE";
    pub const REJECT_DIRTY_POLICY: &str = "VPCO_REJECT_DIRTY_POLICY";
    pub const REJECT_CAPACITY: &str = "VPCO_REJECT_CAPACITY";
    pub const REPAIR_CORRUPTED: &str = "VPCO_REPAIR_CORRUPTED";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofPriority {
    Low,
    Normal,
    High,
}

impl ValidationProofPriority {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofTargetDirClass {
    OffRepo,
    Tmp,
    RepoLocal,
    Unknown,
}

impl ValidationProofTargetDirClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OffRepo => "off_repo",
            Self::Tmp => "tmp",
            Self::RepoLocal => "repo_local",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofCapacityMode {
    ObserveOnly,
    QueueWhenBusy,
    RejectWhenBusy,
}

impl ValidationProofCapacityMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObserveOnly => "observe_only",
            Self::QueueWhenBusy => "queue_when_busy",
            Self::RejectWhenBusy => "reject_when_busy",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofRchWorkerCapacity {
    pub worker_id: String,
    pub total_slots: u16,
    pub available_slots: u16,
    pub queue_depth: u16,
    pub degraded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofRchCapacitySnapshot {
    pub schema_version: String,
    pub observed_at: DateTime<Utc>,
    pub workers: Vec<ValidationProofRchWorkerCapacity>,
    pub queue_depth: u16,
    pub oldest_queued_age_seconds: Option<u64>,
    pub disk_pressure_warning: bool,
}

impl ValidationProofRchCapacitySnapshot {
    #[must_use]
    pub fn available_worker_slots(&self) -> u16 {
        self.workers.iter().fold(0_u16, |total, worker| {
            total.saturating_add(worker.available_slots)
        })
    }

    #[must_use]
    pub fn observed_queue_depth(&self) -> u16 {
        self.workers.iter().fold(self.queue_depth, |total, worker| {
            total.saturating_add(worker.queue_depth)
        })
    }

    #[must_use]
    pub fn has_degraded_workers(&self) -> bool {
        self.workers.iter().any(|worker| worker.degraded)
    }
}

pub trait ValidationProofRchCapacityProbe {
    fn sample_capacity(
        &self,
    ) -> Result<ValidationProofRchCapacitySnapshot, ValidationProofCoalescerError>;
}

#[derive(Debug, Clone)]
pub struct StaticValidationProofRchCapacityProbe {
    snapshot: ValidationProofRchCapacitySnapshot,
}

impl StaticValidationProofRchCapacityProbe {
    #[must_use]
    pub fn new(snapshot: ValidationProofRchCapacitySnapshot) -> Self {
        Self { snapshot }
    }
}

impl ValidationProofRchCapacityProbe for StaticValidationProofRchCapacityProbe {
    fn sample_capacity(
        &self,
    ) -> Result<ValidationProofRchCapacitySnapshot, ValidationProofCoalescerError> {
        Ok(self.snapshot.clone())
    }
}

pub fn sample_validation_proof_capacity(
    probe: &impl ValidationProofRchCapacityProbe,
) -> Result<ValidationProofRchCapacitySnapshot, ValidationProofCoalescerError> {
    probe.sample_capacity()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofAdmissionThreshold {
    pub min_available_worker_slots: u16,
    pub max_queue_depth: u16,
    pub max_oldest_queue_age_seconds: u64,
    pub min_timeout_budget_seconds: u64,
    pub allow_degraded_workers: bool,
    pub reject_on_disk_pressure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofAdmissionPolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub capacity_mode: ValidationProofCapacityMode,
    pub dirty_state_policy: DirtyStatePolicy,
    pub low_priority: ValidationProofAdmissionThreshold,
    pub normal_priority: ValidationProofAdmissionThreshold,
    pub high_priority: ValidationProofAdmissionThreshold,
}

impl ValidationProofAdmissionPolicy {
    #[must_use]
    pub fn default_policy(policy_id: impl Into<String>) -> Self {
        Self {
            schema_version: ADMISSION_POLICY_SCHEMA_VERSION.to_string(),
            policy_id: policy_id.into(),
            capacity_mode: ValidationProofCapacityMode::QueueWhenBusy,
            dirty_state_policy: DirtyStatePolicy::CleanRequired,
            low_priority: ValidationProofAdmissionThreshold {
                min_available_worker_slots: 3,
                max_queue_depth: 4,
                max_oldest_queue_age_seconds: 300,
                min_timeout_budget_seconds: 900,
                allow_degraded_workers: false,
                reject_on_disk_pressure: true,
            },
            normal_priority: ValidationProofAdmissionThreshold {
                min_available_worker_slots: 2,
                max_queue_depth: 8,
                max_oldest_queue_age_seconds: 600,
                min_timeout_budget_seconds: 600,
                allow_degraded_workers: false,
                reject_on_disk_pressure: true,
            },
            high_priority: ValidationProofAdmissionThreshold {
                min_available_worker_slots: 1,
                max_queue_depth: 16,
                max_oldest_queue_age_seconds: 900,
                min_timeout_budget_seconds: 300,
                allow_degraded_workers: true,
                reject_on_disk_pressure: false,
            },
        }
    }

    #[must_use]
    pub const fn threshold_for(
        &self,
        priority: ValidationProofPriority,
    ) -> ValidationProofAdmissionThreshold {
        match priority {
            ValidationProofPriority::Low => self.low_priority,
            ValidationProofPriority::Normal => self.normal_priority,
            ValidationProofPriority::High => self.high_priority,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofAdmissionInput {
    pub trace_id: String,
    pub capacity_snapshot: ValidationProofRchCapacitySnapshot,
    pub proof_priority: ValidationProofPriority,
    pub bead_priority: u8,
    pub dirty_worktree: bool,
    pub dirty_state_policy: DirtyStatePolicy,
    pub target_dir_class: ValidationProofTargetDirClass,
    pub timeout_budget_seconds: u64,
    pub current_queue_depth: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofAdmissionDiagnostics {
    pub trace_id: String,
    pub message: String,
    pub fail_closed: bool,
    pub event_code: String,
    pub effective_priority: ValidationProofPriority,
    pub available_worker_slots: u16,
    pub observed_queue_depth: u16,
    pub oldest_queued_age_seconds: Option<u64>,
    pub disk_pressure_warning: bool,
    pub target_dir_class: ValidationProofTargetDirClass,
    pub timeout_budget_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofAdmissionDecision {
    pub schema_version: String,
    pub policy_id: String,
    pub decision: ValidationProofCoalescerDecisionKind,
    pub reason_code: String,
    pub required_action: ValidationProofCoalescerRequiredAction,
    pub diagnostics: ValidationProofAdmissionDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofWorkKey {
    pub schema_version: String,
    pub work_key_id: String,
    pub algorithm: String,
    pub hex: String,
    pub canonical_material: String,
    pub proof_cache_key: ProofCacheDigest,
    pub command_digest: CommandDigest,
    pub input_digests: Vec<InputDigest>,
    pub git_commit: String,
    pub dirty_worktree: bool,
    pub dirty_state_policy: DirtyStatePolicy,
    pub feature_flags: Vec<String>,
    pub cargo_toolchain: String,
    pub package: String,
    pub test_target: String,
    pub environment_policy_id: String,
    pub target_dir_policy_id: String,
}

impl ValidationProofWorkKey {
    pub fn from_parts(
        parts: ValidationProofWorkKeyParts,
    ) -> Result<Self, ValidationProofCoalescerError> {
        let mut input_digests = parts.input_digests;
        input_digests.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then(left.algorithm.cmp(&right.algorithm))
                .then(left.hex.cmp(&right.hex))
        });
        if input_digests.is_empty() || input_digests.iter().any(|digest| !digest.is_valid()) {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_INPUT_DIGEST_MISMATCH,
                "proof work key requires at least one valid input digest",
            ));
        }
        if !parts.command_digest.verifies() {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_COMMAND_DIGEST_MISMATCH,
                "proof work key command digest does not verify",
            ));
        }
        if matches!(parts.dirty_state_policy, DirtyStatePolicy::CleanRequired)
            && parts.dirty_worktree
        {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_DIRTY_POLICY,
                "clean_required coalescer work key cannot admit dirty worktree material",
            ));
        }

        let mut feature_flags = parts.feature_flags;
        feature_flags.sort();
        feature_flags.dedup();
        let canonical_material = canonical_work_key_material(
            &parts.command_digest,
            &input_digests,
            &parts.git_commit,
            parts.dirty_worktree,
            parts.dirty_state_policy,
            &feature_flags,
            &parts.cargo_toolchain,
            &parts.package,
            &parts.test_target,
            &parts.environment_policy_id,
            &parts.target_dir_policy_id,
        );
        let hex = hex::encode(Sha256::digest(canonical_material.as_bytes()));
        Ok(Self {
            schema_version: WORK_KEY_SCHEMA_VERSION.to_string(),
            work_key_id: format!("vpcowork-{}", key_hex_prefix(&hex, 16)),
            algorithm: "sha256".to_string(),
            proof_cache_key: ProofCacheDigest::sha256_material(canonical_material.clone()),
            hex,
            canonical_material,
            command_digest: parts.command_digest,
            input_digests,
            git_commit: parts.git_commit,
            dirty_worktree: parts.dirty_worktree,
            dirty_state_policy: parts.dirty_state_policy,
            feature_flags,
            cargo_toolchain: parts.cargo_toolchain,
            package: parts.package,
            test_target: parts.test_target,
            environment_policy_id: parts.environment_policy_id,
            target_dir_policy_id: parts.target_dir_policy_id,
        })
    }

    #[must_use]
    pub fn from_cache_key(cache_key: &ValidationProofCacheKey) -> Self {
        Self {
            schema_version: WORK_KEY_SCHEMA_VERSION.to_string(),
            work_key_id: format!("vpcowork-{}", key_hex_prefix(&cache_key.hex, 16)),
            algorithm: cache_key.algorithm.clone(),
            hex: cache_key.hex.clone(),
            canonical_material: cache_key.canonical_material.clone(),
            proof_cache_key: ProofCacheDigest::sha256_material(
                cache_key.canonical_material.clone(),
            ),
            command_digest: cache_key.command_digest.clone(),
            input_digests: cache_key.input_digests.clone(),
            git_commit: cache_key.git_commit.clone(),
            dirty_worktree: cache_key.dirty_worktree,
            dirty_state_policy: cache_key.dirty_state_policy,
            feature_flags: cache_key.feature_flags.clone(),
            cargo_toolchain: cache_key.cargo_toolchain.clone(),
            package: cache_key.package.clone(),
            test_target: cache_key.test_target.clone(),
            environment_policy_id: cache_key.environment_policy_id.clone(),
            target_dir_policy_id: cache_key.target_dir_policy_id.clone(),
        }
    }

    #[must_use]
    pub fn verifies(&self) -> bool {
        if !string_eq(&self.schema_version, WORK_KEY_SCHEMA_VERSION)
            || !string_eq(&self.algorithm, "sha256")
            || !is_sha256_hex(&self.hex)
            || !self.proof_cache_key.verifies()
            || !constant_time::ct_eq(&self.proof_cache_key.hex, &self.hex)
            || !self.command_digest.verifies()
            || self.input_digests.is_empty()
            || self.input_digests.iter().any(|digest| !digest.is_valid())
        {
            return false;
        }
        let expected = hex::encode(Sha256::digest(self.canonical_material.as_bytes()));
        constant_time::ct_eq(&expected, &self.hex)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationProofWorkKeyParts {
    pub command_digest: CommandDigest,
    pub input_digests: Vec<InputDigest>,
    pub git_commit: String,
    pub dirty_worktree: bool,
    pub dirty_state_policy: DirtyStatePolicy,
    pub feature_flags: Vec<String>,
    pub cargo_toolchain: String,
    pub package: String,
    pub test_target: String,
    pub environment_policy_id: String,
    pub target_dir_policy_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofLeaseState {
    Proposed,
    Running,
    Joined,
    Completed,
    Stale,
    Fenced,
    Rejected,
    FailedClosed,
}

impl ValidationProofLeaseState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Running => "running",
            Self::Joined => "joined",
            Self::Completed => "completed",
            Self::Stale => "stale",
            Self::Fenced => "fenced",
            Self::Rejected => "rejected",
            Self::FailedClosed => "failed_closed",
        }
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Proposed | Self::Running | Self::Joined)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofCoalescerDecisionKind {
    RunLocallyViaRch,
    JoinExistingProof,
    WaitForReceipt,
    QueuedByPolicy,
    RetryAfterStaleLease,
    RejectDirtyPolicy,
    RejectCapacity,
    RepairState,
}

impl ValidationProofCoalescerDecisionKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunLocallyViaRch => "run_locally_via_rch",
            Self::JoinExistingProof => "join_existing_proof",
            Self::WaitForReceipt => "wait_for_receipt",
            Self::QueuedByPolicy => "queued_by_policy",
            Self::RetryAfterStaleLease => "retry_after_stale_lease",
            Self::RejectDirtyPolicy => "reject_dirty_policy",
            Self::RejectCapacity => "reject_capacity",
            Self::RepairState => "repair_state",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofCoalescerRequiredAction {
    StartRchValidation,
    JoinExistingLease,
    WaitForReceipt,
    QueueValidation,
    RetryWithNewFence,
    FailClosed,
    RepairState,
}

impl ValidationProofCoalescerRequiredAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartRchValidation => "start_rch_validation",
            Self::JoinExistingLease => "join_existing_lease",
            Self::WaitForReceipt => "wait_for_receipt",
            Self::QueueValidation => "queue_validation",
            Self::RetryWithNewFence => "retry_with_new_fence",
            Self::FailClosed => "fail_closed",
            Self::RepairState => "repair_state",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofRchCommand {
    pub argv: Vec<String>,
    pub command_digest: CommandDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCoalescerReceiptRef {
    pub receipt_id: String,
    pub path: String,
    pub bead_id: String,
    pub proof_cache_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCoalescerDiagnostics {
    pub trace_id: String,
    pub event_code: String,
    pub reason_code: String,
    pub producer_agent: String,
    pub waiter_agent: Option<String>,
    pub message: String,
    pub fail_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCoalescerLease {
    pub schema_version: String,
    pub lease_id: String,
    pub proof_work_key: ValidationProofWorkKey,
    pub state: ValidationProofLeaseState,
    pub owner_agent: String,
    pub owner_bead_id: String,
    pub fencing_token: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub waiter_agents: Vec<String>,
    pub admission_policy_id: String,
    pub rch_command: ValidationProofRchCommand,
    pub target_dir_policy_id: String,
    pub receipt_ref: Option<ValidationProofCoalescerReceiptRef>,
    pub proof_cache_key: ProofCacheDigest,
    pub diagnostics: ValidationProofCoalescerDiagnostics,
}

impl ValidationProofCoalescerLease {
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCoalescerLeaseRef {
    pub lease_id: String,
    pub path: String,
    pub state: ValidationProofLeaseState,
    pub owner_agent: String,
    pub owner_bead_id: String,
    pub fencing_token: String,
}

impl ValidationProofCoalescerLeaseRef {
    #[must_use]
    pub fn from_lease(lease: &ValidationProofCoalescerLease, path: impl Into<String>) -> Self {
        Self {
            lease_id: lease.lease_id.clone(),
            path: path.into(),
            state: lease.state,
            owner_agent: lease.owner_agent.clone(),
            owner_bead_id: lease.owner_bead_id.clone(),
            fencing_token: lease.fencing_token.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCoalescerDecisionDiagnostics {
    pub message: String,
    pub fail_closed: bool,
    pub event_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCoalescerDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub proof_work_key: ValidationProofWorkKey,
    pub lease_ref: Option<ValidationProofCoalescerLeaseRef>,
    pub bead_id: String,
    pub agent_name: String,
    pub trace_id: String,
    pub decided_at: DateTime<Utc>,
    pub decision: ValidationProofCoalescerDecisionKind,
    pub reason_code: String,
    pub required_action: ValidationProofCoalescerRequiredAction,
    pub diagnostics: ValidationProofCoalescerDecisionDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationProofCoalescerOutcome {
    pub lease: Option<ValidationProofCoalescerLease>,
    pub lease_path: PathBuf,
    pub decision: ValidationProofCoalescerDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateLeaseRequest {
    pub proof_work_key: ValidationProofWorkKey,
    pub owner_agent: String,
    pub owner_bead_id: String,
    pub trace_id: String,
    pub fencing_token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub admission_policy_id: String,
    pub rch_command: ValidationProofRchCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteLeaseRequest {
    pub proof_work_key: ValidationProofWorkKey,
    pub owner_agent: String,
    pub owner_bead_id: String,
    pub fencing_token: String,
    pub completed_at: DateTime<Utc>,
    pub receipt_ref: ValidationProofCoalescerReceiptRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceStaleLeaseRequest {
    pub proof_work_key: ValidationProofWorkKey,
    pub owner_agent: String,
    pub owner_bead_id: String,
    pub trace_id: String,
    pub fencing_token: String,
    pub fenced_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ValidationProofCoalescerStore {
    root: PathBuf,
}

impl ValidationProofCoalescerStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn lease_path(&self, key: &ValidationProofWorkKey) -> PathBuf {
        self.root
            .join("leases")
            .join(key_hex_prefix(&key.hex, 2))
            .join(format!("{}.json", key.hex))
    }

    #[must_use]
    pub fn relative_lease_path(&self, key: &ValidationProofWorkKey) -> String {
        format!("leases/{}/{}.json", key_hex_prefix(&key.hex, 2), key.hex)
    }

    pub fn read_lease(
        &self,
        key: &ValidationProofWorkKey,
    ) -> Result<Option<ValidationProofCoalescerLease>, ValidationProofCoalescerError> {
        let path = self.lease_path(key);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|source| ValidationProofCoalescerError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let lease: ValidationProofCoalescerLease =
            serde_json::from_slice(&bytes).map_err(|source| {
                ValidationProofCoalescerError::Json {
                    path: path.display().to_string(),
                    source,
                }
            })?;
        validate_lease_metadata(&lease)?;
        Ok(Some(lease))
    }

    pub fn create_or_join(
        &self,
        request: CreateLeaseRequest,
    ) -> Result<ValidationProofCoalescerOutcome, ValidationProofCoalescerError> {
        let path = self.lease_path(&request.proof_work_key);
        let relative_path = self.relative_lease_path(&request.proof_work_key);
        match self.read_lease(&request.proof_work_key) {
            Ok(None) => self.create_new_lease(request, path, relative_path),
            Ok(Some(lease)) => self.join_or_wait(request, lease, path, relative_path),
            Err(error) => Ok(repair_state_outcome(request, path, relative_path, &error)),
        }
    }

    pub fn complete_lease(
        &self,
        request: CompleteLeaseRequest,
    ) -> Result<ValidationProofCoalescerLease, ValidationProofCoalescerError> {
        let path = self.lease_path(&request.proof_work_key);
        let Some(mut lease) = self.read_lease(&request.proof_work_key)? else {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_MALFORMED_LEASE,
                "cannot complete missing validation proof lease",
            ));
        };
        if !same_work_key(&lease.proof_work_key, &request.proof_work_key) {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_BAD_WORK_KEY,
                "completion work key does not match stored lease",
            ));
        }
        if lease.is_expired_at(request.completed_at) {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_STALE_LEASE,
                "stale validation proof lease cannot be completed",
            ));
        }
        if !string_eq(&lease.owner_agent, &request.owner_agent)
            || !string_eq(&lease.owner_bead_id, &request.owner_bead_id)
            || !string_eq(&lease.fencing_token, &request.fencing_token)
        {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_FENCED_OWNER,
                "lease completion owner or fencing token does not match active lease",
            ));
        }
        if matches!(lease.state, ValidationProofLeaseState::Completed)
            || lease.receipt_ref.is_some()
        {
            return Err(ValidationProofCoalescerError::DuplicateLease {
                path: path.display().to_string(),
            });
        }
        if !constant_time::ct_eq(
            &request.receipt_ref.proof_cache_key_hex,
            &lease.proof_cache_key.hex,
        ) {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_BAD_WORK_KEY,
                "completed receipt proof-cache key does not match lease",
            ));
        }

        lease.state = ValidationProofLeaseState::Completed;
        lease.updated_at = request.completed_at;
        lease.receipt_ref = Some(request.receipt_ref);
        lease.diagnostics.event_code = event_codes::RECEIPT_HANDOFF_COMPLETED.to_string();
        lease.diagnostics.reason_code = reason_codes::WAIT_COMPLETION.to_string();
        lease.diagnostics.message = "completed lease handed off to proof cache receipt".to_string();
        lease.diagnostics.fail_closed = false;
        validate_lease_metadata(&lease)?;
        write_bytes_replace(
            &path,
            &serde_json::to_vec_pretty(&lease).map_err(|source| {
                ValidationProofCoalescerError::Json {
                    path: path.display().to_string(),
                    source,
                }
            })?,
        )?;
        Ok(lease)
    }

    pub fn fence_stale_lease(
        &self,
        request: FenceStaleLeaseRequest,
    ) -> Result<ValidationProofCoalescerOutcome, ValidationProofCoalescerError> {
        let path = self.lease_path(&request.proof_work_key);
        let relative_path = self.relative_lease_path(&request.proof_work_key);
        let Some(mut lease) = self.read_lease(&request.proof_work_key)? else {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_MALFORMED_LEASE,
                "cannot fence missing validation proof lease",
            ));
        };
        if !lease.is_expired_at(request.fenced_at) {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_STALE_LEASE,
                "only stale validation proof leases can be fenced",
            ));
        }
        lease.state = ValidationProofLeaseState::Running;
        lease.owner_agent = request.owner_agent.clone();
        lease.owner_bead_id = request.owner_bead_id.clone();
        lease.fencing_token = request.fencing_token;
        lease.updated_at = request.fenced_at;
        lease.expires_at = request.expires_at;
        lease.waiter_agents.clear();
        lease.receipt_ref = None;
        lease.diagnostics = ValidationProofCoalescerDiagnostics {
            trace_id: request.trace_id.clone(),
            event_code: event_codes::STALE_LEASE_FENCED.to_string(),
            reason_code: reason_codes::RETRY_STALE.to_string(),
            producer_agent: request.owner_agent.clone(),
            waiter_agent: None,
            message: "stale lease fenced and retried with a new owner token".to_string(),
            fail_closed: false,
        };
        validate_lease_metadata(&lease)?;
        let bytes = serde_json::to_vec_pretty(&lease).map_err(|source| {
            ValidationProofCoalescerError::Json {
                path: path.display().to_string(),
                source,
            }
        })?;
        write_bytes_replace(&path, &bytes)?;
        Ok(ValidationProofCoalescerOutcome {
            decision: coalescer_decision(DecisionInput {
                kind: ValidationProofCoalescerDecisionKind::RetryAfterStaleLease,
                reason_code: reason_codes::RETRY_STALE,
                required_action: ValidationProofCoalescerRequiredAction::RetryWithNewFence,
                event_code: event_codes::STALE_LEASE_FENCED,
                fail_closed: false,
                message: "stale lease fenced and retried with a new owner token",
                work_key: lease.proof_work_key.clone(),
                lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                    &lease,
                    relative_path,
                )),
                bead_id: request.owner_bead_id,
                agent_name: request.owner_agent,
                trace_id: request.trace_id,
                decided_at: request.fenced_at,
            }),
            lease: Some(lease),
            lease_path: path,
        })
    }

    fn create_new_lease(
        &self,
        request: CreateLeaseRequest,
        path: PathBuf,
        relative_path: String,
    ) -> Result<ValidationProofCoalescerOutcome, ValidationProofCoalescerError> {
        let lease = build_running_lease(&request);
        validate_lease_metadata(&lease)?;
        let bytes = serde_json::to_vec_pretty(&lease).map_err(|source| {
            ValidationProofCoalescerError::Json {
                path: path.display().to_string(),
                source,
            }
        })?;
        match write_bytes_create_new(&path, &bytes) {
            Ok(()) => Ok(ValidationProofCoalescerOutcome {
                decision: coalescer_decision(DecisionInput {
                    kind: ValidationProofCoalescerDecisionKind::RunLocallyViaRch,
                    reason_code: reason_codes::RUN_NO_LEASE,
                    required_action: ValidationProofCoalescerRequiredAction::StartRchValidation,
                    event_code: event_codes::PRODUCER_ADMITTED,
                    fail_closed: false,
                    message: "no active lease matched; producer admitted",
                    work_key: lease.proof_work_key.clone(),
                    lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                        &lease,
                        relative_path,
                    )),
                    bead_id: request.owner_bead_id,
                    agent_name: request.owner_agent,
                    trace_id: request.trace_id,
                    decided_at: request.created_at,
                }),
                lease: Some(lease),
                lease_path: path,
            }),
            Err(ValidationProofCoalescerError::DuplicateLease { .. }) => {
                let existing = self.read_lease(&request.proof_work_key)?;
                if let Some(lease) = existing {
                    self.join_or_wait(request, lease, path, relative_path)
                } else {
                    Err(ValidationProofCoalescerError::DuplicateLease {
                        path: path.display().to_string(),
                    })
                }
            }
            Err(error) => Err(error),
        }
    }

    fn join_or_wait(
        &self,
        request: CreateLeaseRequest,
        mut lease: ValidationProofCoalescerLease,
        path: PathBuf,
        relative_path: String,
    ) -> Result<ValidationProofCoalescerOutcome, ValidationProofCoalescerError> {
        if lease.is_expired_at(request.created_at) {
            return Ok(ValidationProofCoalescerOutcome {
                decision: coalescer_decision(DecisionInput {
                    kind: ValidationProofCoalescerDecisionKind::RetryAfterStaleLease,
                    reason_code: reason_codes::RETRY_STALE,
                    required_action: ValidationProofCoalescerRequiredAction::RetryWithNewFence,
                    event_code: event_codes::STALE_LEASE_FENCED,
                    fail_closed: true,
                    message: "existing lease is stale and must be fenced before reuse",
                    work_key: request.proof_work_key,
                    lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                        &lease,
                        relative_path,
                    )),
                    bead_id: request.owner_bead_id,
                    agent_name: request.owner_agent,
                    trace_id: request.trace_id,
                    decided_at: request.created_at,
                }),
                lease: Some(lease),
                lease_path: path,
            });
        }
        if !same_work_key(&lease.proof_work_key, &request.proof_work_key) {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_BAD_WORK_KEY,
                "stored lease work key does not match requested work key",
            ));
        }
        if matches!(lease.state, ValidationProofLeaseState::Completed) {
            return Ok(ValidationProofCoalescerOutcome {
                decision: coalescer_decision(DecisionInput {
                    kind: ValidationProofCoalescerDecisionKind::WaitForReceipt,
                    reason_code: reason_codes::WAIT_COMPLETION,
                    required_action: ValidationProofCoalescerRequiredAction::WaitForReceipt,
                    event_code: event_codes::WAIT_FOR_RECEIPT,
                    fail_closed: false,
                    message: "completed lease is ready for receipt handoff",
                    work_key: lease.proof_work_key.clone(),
                    lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                        &lease,
                        relative_path,
                    )),
                    bead_id: request.owner_bead_id,
                    agent_name: request.owner_agent,
                    trace_id: request.trace_id,
                    decided_at: request.created_at,
                }),
                lease: Some(lease),
                lease_path: path,
            });
        }
        if !lease.state.is_active() {
            return Ok(ValidationProofCoalescerOutcome {
                decision: coalescer_decision(DecisionInput {
                    kind: ValidationProofCoalescerDecisionKind::RepairState,
                    reason_code: reason_codes::REPAIR_CORRUPTED,
                    required_action: ValidationProofCoalescerRequiredAction::RepairState,
                    event_code: event_codes::CORRUPTED_STATE_REPAIR,
                    fail_closed: true,
                    message: "non-active lease state cannot be joined",
                    work_key: request.proof_work_key,
                    lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                        &lease,
                        relative_path,
                    )),
                    bead_id: request.owner_bead_id,
                    agent_name: request.owner_agent,
                    trace_id: request.trace_id,
                    decided_at: request.created_at,
                }),
                lease: Some(lease),
                lease_path: path,
            });
        }

        if !lease
            .waiter_agents
            .iter()
            .any(|agent| string_eq(agent, &request.owner_agent))
            && !string_eq(&lease.owner_agent, &request.owner_agent)
        {
            lease.waiter_agents.push(request.owner_agent.clone());
            lease.waiter_agents.sort();
            lease.waiter_agents.dedup();
        }
        lease.state = ValidationProofLeaseState::Joined;
        lease.updated_at = request.created_at;
        lease.diagnostics.event_code = event_codes::WAITER_JOINED.to_string();
        lease.diagnostics.reason_code = reason_codes::JOIN_RUNNING.to_string();
        lease.diagnostics.waiter_agent = Some(request.owner_agent.clone());
        lease.diagnostics.message = "identical work key joined the running proof".to_string();
        validate_lease_metadata(&lease)?;
        let bytes = serde_json::to_vec_pretty(&lease).map_err(|source| {
            ValidationProofCoalescerError::Json {
                path: path.display().to_string(),
                source,
            }
        })?;
        write_bytes_replace(&path, &bytes)?;
        Ok(ValidationProofCoalescerOutcome {
            decision: coalescer_decision(DecisionInput {
                kind: ValidationProofCoalescerDecisionKind::JoinExistingProof,
                reason_code: reason_codes::JOIN_RUNNING,
                required_action: ValidationProofCoalescerRequiredAction::JoinExistingLease,
                event_code: event_codes::WAITER_JOINED,
                fail_closed: false,
                message: "identical work key joined the running proof",
                work_key: lease.proof_work_key.clone(),
                lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                    &lease,
                    relative_path,
                )),
                bead_id: request.owner_bead_id,
                agent_name: request.owner_agent,
                trace_id: request.trace_id,
                decided_at: request.created_at,
            }),
            lease: Some(lease),
            lease_path: path,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationProofCoalescerError {
    #[error("{code}: {detail}")]
    ContractViolation { code: &'static str, detail: String },
    #[error("duplicate validation proof lease at {path}")]
    DuplicateLease { path: String },
    #[error("I/O error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("JSON error at {path}: {source}")]
    Json {
        path: String,
        source: serde_json::Error,
    },
}

impl ValidationProofCoalescerError {
    #[must_use]
    pub fn contract(code: &'static str, detail: impl Into<String>) -> Self {
        Self::ContractViolation {
            code,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ContractViolation { code, .. } => code,
            Self::DuplicateLease { .. } => error_codes::ERR_VPCO_DUPLICATE_LEASE,
            Self::Io { .. } | Self::Json { .. } => error_codes::ERR_VPCO_CORRUPTED_STATE,
        }
    }
}

pub fn decide_validation_proof_admission(
    policy: &ValidationProofAdmissionPolicy,
    input: &ValidationProofAdmissionInput,
) -> Result<ValidationProofAdmissionDecision, ValidationProofCoalescerError> {
    validate_admission_policy(policy)?;
    validate_admission_input(input)?;

    let effective_priority =
        effective_admission_priority(input.proof_priority, input.bead_priority);
    let threshold = policy.threshold_for(effective_priority);
    let available_worker_slots = input.capacity_snapshot.available_worker_slots();
    let observed_queue_depth = input
        .capacity_snapshot
        .observed_queue_depth()
        .saturating_add(input.current_queue_depth);

    if input.dirty_worktree && matches!(input.dirty_state_policy, DirtyStatePolicy::CleanRequired) {
        return Ok(admission_decision(AdmissionDecisionInput {
            policy_id: policy.policy_id.clone(),
            kind: ValidationProofCoalescerDecisionKind::RejectDirtyPolicy,
            reason_code: reason_codes::REJECT_DIRTY_POLICY,
            required_action: ValidationProofCoalescerRequiredAction::FailClosed,
            event_code: event_codes::DIRTY_POLICY_REJECTED,
            fail_closed: true,
            message: "dirty worktree rejected by clean-required validation admission policy",
            effective_priority,
            input,
            available_worker_slots,
            observed_queue_depth,
        }));
    }

    if observed_queue_depth >= threshold.max_queue_depth {
        return Ok(admission_decision(AdmissionDecisionInput {
            policy_id: policy.policy_id.clone(),
            kind: ValidationProofCoalescerDecisionKind::RejectCapacity,
            reason_code: reason_codes::REJECT_CAPACITY,
            required_action: ValidationProofCoalescerRequiredAction::FailClosed,
            event_code: event_codes::CAPACITY_REJECTED,
            fail_closed: true,
            message: "validation admission rejected to bound proof queue growth",
            effective_priority,
            input,
            available_worker_slots,
            observed_queue_depth,
        }));
    }

    if input.capacity_snapshot.disk_pressure_warning && threshold.reject_on_disk_pressure {
        return Ok(admission_decision(AdmissionDecisionInput {
            policy_id: policy.policy_id.clone(),
            kind: ValidationProofCoalescerDecisionKind::RejectCapacity,
            reason_code: reason_codes::REJECT_CAPACITY,
            required_action: ValidationProofCoalescerRequiredAction::FailClosed,
            event_code: event_codes::CAPACITY_REJECTED,
            fail_closed: true,
            message: "validation admission rejected because capacity snapshot reports disk pressure",
            effective_priority,
            input,
            available_worker_slots,
            observed_queue_depth,
        }));
    }

    if input
        .capacity_snapshot
        .oldest_queued_age_seconds
        .is_some_and(|age| age > threshold.max_oldest_queue_age_seconds)
    {
        return Ok(admission_decision(AdmissionDecisionInput {
            policy_id: policy.policy_id.clone(),
            kind: ValidationProofCoalescerDecisionKind::RejectCapacity,
            reason_code: reason_codes::REJECT_CAPACITY,
            required_action: ValidationProofCoalescerRequiredAction::FailClosed,
            event_code: event_codes::CAPACITY_REJECTED,
            fail_closed: true,
            message: "validation admission rejected because RCH queue age is stale",
            effective_priority,
            input,
            available_worker_slots,
            observed_queue_depth,
        }));
    }

    let capacity_is_busy = available_worker_slots < threshold.min_available_worker_slots
        || (!threshold.allow_degraded_workers && input.capacity_snapshot.has_degraded_workers())
        || input.timeout_budget_seconds < threshold.min_timeout_budget_seconds;

    if capacity_is_busy {
        match policy.capacity_mode {
            ValidationProofCapacityMode::ObserveOnly => {}
            ValidationProofCapacityMode::QueueWhenBusy => {
                return Ok(admission_decision(AdmissionDecisionInput {
                    policy_id: policy.policy_id.clone(),
                    kind: ValidationProofCoalescerDecisionKind::QueuedByPolicy,
                    reason_code: reason_codes::QUEUE_CAPACITY,
                    required_action: ValidationProofCoalescerRequiredAction::QueueValidation,
                    event_code: event_codes::QUEUED_BY_CAPACITY,
                    fail_closed: false,
                    message: "validation proof queued until RCH capacity is available",
                    effective_priority,
                    input,
                    available_worker_slots,
                    observed_queue_depth,
                }));
            }
            ValidationProofCapacityMode::RejectWhenBusy => {
                return Ok(admission_decision(AdmissionDecisionInput {
                    policy_id: policy.policy_id.clone(),
                    kind: ValidationProofCoalescerDecisionKind::RejectCapacity,
                    reason_code: reason_codes::REJECT_CAPACITY,
                    required_action: ValidationProofCoalescerRequiredAction::FailClosed,
                    event_code: event_codes::CAPACITY_REJECTED,
                    fail_closed: true,
                    message: "validation admission rejected because RCH capacity is below threshold",
                    effective_priority,
                    input,
                    available_worker_slots,
                    observed_queue_depth,
                }));
            }
        }
    }

    Ok(admission_decision(AdmissionDecisionInput {
        policy_id: policy.policy_id.clone(),
        kind: ValidationProofCoalescerDecisionKind::RunLocallyViaRch,
        reason_code: reason_codes::RUN_NO_LEASE,
        required_action: ValidationProofCoalescerRequiredAction::StartRchValidation,
        event_code: event_codes::PRODUCER_ADMITTED,
        fail_closed: false,
        message: "validation admission accepted producer for RCH execution",
        effective_priority,
        input,
        available_worker_slots,
        observed_queue_depth,
    }))
}

struct AdmissionDecisionInput<'a> {
    policy_id: String,
    kind: ValidationProofCoalescerDecisionKind,
    reason_code: &'static str,
    required_action: ValidationProofCoalescerRequiredAction,
    event_code: &'static str,
    fail_closed: bool,
    message: &'static str,
    effective_priority: ValidationProofPriority,
    input: &'a ValidationProofAdmissionInput,
    available_worker_slots: u16,
    observed_queue_depth: u16,
}

fn admission_decision(input: AdmissionDecisionInput<'_>) -> ValidationProofAdmissionDecision {
    ValidationProofAdmissionDecision {
        schema_version: ADMISSION_DECISION_SCHEMA_VERSION.to_string(),
        policy_id: input.policy_id,
        decision: input.kind,
        reason_code: input.reason_code.to_string(),
        required_action: input.required_action,
        diagnostics: ValidationProofAdmissionDiagnostics {
            trace_id: input.input.trace_id.clone(),
            message: input.message.to_string(),
            fail_closed: input.fail_closed,
            event_code: input.event_code.to_string(),
            effective_priority: input.effective_priority,
            available_worker_slots: input.available_worker_slots,
            observed_queue_depth: input.observed_queue_depth,
            oldest_queued_age_seconds: input.input.capacity_snapshot.oldest_queued_age_seconds,
            disk_pressure_warning: input.input.capacity_snapshot.disk_pressure_warning,
            target_dir_class: input.input.target_dir_class,
            timeout_budget_seconds: input.input.timeout_budget_seconds,
        },
    }
}

fn effective_admission_priority(
    proof_priority: ValidationProofPriority,
    bead_priority: u8,
) -> ValidationProofPriority {
    let inherited = match bead_priority {
        0 | 1 => ValidationProofPriority::High,
        2 => ValidationProofPriority::Normal,
        _ => ValidationProofPriority::Low,
    };
    proof_priority.max(inherited)
}

fn validate_admission_policy(
    policy: &ValidationProofAdmissionPolicy,
) -> Result<(), ValidationProofCoalescerError> {
    if !string_eq(&policy.schema_version, ADMISSION_POLICY_SCHEMA_VERSION)
        || policy.policy_id.trim().is_empty()
    {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_POLICY,
            "validation proof admission policy identity is malformed",
        ));
    }
    for threshold in [
        policy.low_priority,
        policy.normal_priority,
        policy.high_priority,
    ] {
        if threshold.max_queue_depth == 0
            || threshold.max_oldest_queue_age_seconds == 0
            || threshold.min_timeout_budget_seconds == 0
        {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_MALFORMED_POLICY,
                "validation proof admission thresholds must be non-zero where they bound growth",
            ));
        }
    }
    Ok(())
}

fn validate_admission_input(
    input: &ValidationProofAdmissionInput,
) -> Result<(), ValidationProofCoalescerError> {
    if input.trace_id.trim().is_empty()
        || !string_eq(
            &input.capacity_snapshot.schema_version,
            CAPACITY_SNAPSHOT_SCHEMA_VERSION,
        )
        || input.capacity_snapshot.workers.is_empty()
        || input.timeout_budget_seconds == 0
    {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_POLICY,
            "validation proof admission input is malformed",
        ));
    }
    if input.capacity_snapshot.workers.iter().any(|worker| {
        worker.worker_id.trim().is_empty() || worker.available_slots > worker.total_slots
    }) {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_POLICY,
            "validation proof RCH worker capacity is malformed",
        ));
    }
    Ok(())
}

struct DecisionInput {
    kind: ValidationProofCoalescerDecisionKind,
    reason_code: &'static str,
    required_action: ValidationProofCoalescerRequiredAction,
    event_code: &'static str,
    fail_closed: bool,
    message: &'static str,
    work_key: ValidationProofWorkKey,
    lease_ref: Option<ValidationProofCoalescerLeaseRef>,
    bead_id: String,
    agent_name: String,
    trace_id: String,
    decided_at: DateTime<Utc>,
}

fn build_running_lease(request: &CreateLeaseRequest) -> ValidationProofCoalescerLease {
    ValidationProofCoalescerLease {
        schema_version: LEASE_SCHEMA_VERSION.to_string(),
        lease_id: format!(
            "vpco-lease-{}",
            key_hex_prefix(&request.proof_work_key.hex, 16)
        ),
        proof_work_key: request.proof_work_key.clone(),
        state: ValidationProofLeaseState::Running,
        owner_agent: request.owner_agent.clone(),
        owner_bead_id: request.owner_bead_id.clone(),
        fencing_token: request.fencing_token.clone(),
        created_at: request.created_at,
        updated_at: request.created_at,
        expires_at: request.expires_at,
        waiter_agents: Vec::new(),
        admission_policy_id: request.admission_policy_id.clone(),
        rch_command: request.rch_command.clone(),
        target_dir_policy_id: request.proof_work_key.target_dir_policy_id.clone(),
        receipt_ref: None,
        proof_cache_key: request.proof_work_key.proof_cache_key.clone(),
        diagnostics: ValidationProofCoalescerDiagnostics {
            trace_id: request.trace_id.clone(),
            event_code: event_codes::PRODUCER_ADMITTED.to_string(),
            reason_code: reason_codes::RUN_NO_LEASE.to_string(),
            producer_agent: request.owner_agent.clone(),
            waiter_agent: None,
            message: "producer admitted for new proof work key".to_string(),
            fail_closed: false,
        },
    }
}

fn repair_state_outcome(
    request: CreateLeaseRequest,
    path: PathBuf,
    relative_path: String,
    error: &ValidationProofCoalescerError,
) -> ValidationProofCoalescerOutcome {
    ValidationProofCoalescerOutcome {
        lease: None,
        lease_path: path,
        decision: coalescer_decision(DecisionInput {
            kind: ValidationProofCoalescerDecisionKind::RepairState,
            reason_code: reason_codes::REPAIR_CORRUPTED,
            required_action: ValidationProofCoalescerRequiredAction::RepairState,
            event_code: event_codes::CORRUPTED_STATE_REPAIR,
            fail_closed: true,
            message: "stored lease metadata is corrupted and must be repaired before reuse",
            work_key: request.proof_work_key.clone(),
            lease_ref: Some(ValidationProofCoalescerLeaseRef {
                lease_id: format!(
                    "vpco-lease-{}",
                    key_hex_prefix(&request.proof_work_key.hex, 16)
                ),
                path: relative_path,
                state: ValidationProofLeaseState::FailedClosed,
                owner_agent: request.owner_agent.clone(),
                owner_bead_id: request.owner_bead_id.clone(),
                fencing_token: request.fencing_token.clone(),
            }),
            bead_id: request.owner_bead_id,
            agent_name: request.owner_agent,
            trace_id: request.trace_id,
            decided_at: request.created_at,
        })
        .with_detail(error.to_string()),
    }
}

fn coalescer_decision(input: DecisionInput) -> ValidationProofCoalescerDecision {
    ValidationProofCoalescerDecision {
        schema_version: DECISION_SCHEMA_VERSION.to_string(),
        decision_id: format!(
            "vpco-decision-{}-{}",
            input.kind.as_str(),
            key_hex_prefix(&input.work_key.hex, 16)
        ),
        proof_work_key: input.work_key,
        lease_ref: input.lease_ref,
        bead_id: input.bead_id,
        agent_name: input.agent_name,
        trace_id: input.trace_id,
        decided_at: input.decided_at,
        decision: input.kind,
        reason_code: input.reason_code.to_string(),
        required_action: input.required_action,
        diagnostics: ValidationProofCoalescerDecisionDiagnostics {
            message: input.message.to_string(),
            fail_closed: input.fail_closed,
            event_code: input.event_code.to_string(),
        },
    }
}

trait DecisionDetail {
    fn with_detail(self, detail: String) -> Self;
}

impl DecisionDetail for ValidationProofCoalescerDecision {
    fn with_detail(mut self, detail: String) -> Self {
        self.diagnostics.message = format!("{}: {detail}", self.diagnostics.message);
        self
    }
}

fn validate_lease_metadata(
    lease: &ValidationProofCoalescerLease,
) -> Result<(), ValidationProofCoalescerError> {
    if !string_eq(&lease.schema_version, LEASE_SCHEMA_VERSION) {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_INVALID_SCHEMA_VERSION,
            "unsupported validation proof lease schema version",
        ));
    }
    if !lease.proof_work_key.verifies() {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_BAD_WORK_KEY,
            "validation proof lease work key does not verify",
        ));
    }
    if !lease.proof_cache_key.verifies()
        || !constant_time::ct_eq(&lease.proof_cache_key.hex, &lease.proof_work_key.hex)
        || !constant_time::ct_eq(
            &lease.proof_cache_key.hex,
            &lease.proof_work_key.proof_cache_key.hex,
        )
    {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_BAD_WORK_KEY,
            "validation proof lease proof-cache key does not match work key",
        ));
    }
    if !lease.rch_command.command_digest.verifies()
        || !constant_time::ct_eq(
            &lease.rch_command.command_digest.hex,
            &lease.proof_work_key.command_digest.hex,
        )
    {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_COMMAND_DIGEST_MISMATCH,
            "validation proof lease RCH command digest does not match work key",
        ));
    }
    if lease.lease_id.trim().is_empty()
        || lease.owner_agent.trim().is_empty()
        || lease.owner_bead_id.trim().is_empty()
        || lease.fencing_token.trim().is_empty()
        || lease.admission_policy_id.trim().is_empty()
        || lease.diagnostics.trace_id.trim().is_empty()
    {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_LEASE,
            "validation proof lease identity fields must be present",
        ));
    }
    if lease.updated_at < lease.created_at {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_LEASE,
            "validation proof lease update timestamp predates creation",
        ));
    }
    if !string_eq(
        &lease.target_dir_policy_id,
        &lease.proof_work_key.target_dir_policy_id,
    ) {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_LEASE,
            "validation proof lease target-dir policy does not match work key",
        ));
    }
    if lease
        .waiter_agents
        .iter()
        .any(|agent| agent.trim().is_empty())
    {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_LEASE,
            "validation proof lease waiter agents must be non-empty strings",
        ));
    }
    if matches!(lease.state, ValidationProofLeaseState::Completed) {
        let Some(receipt_ref) = &lease.receipt_ref else {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_MALFORMED_LEASE,
                "completed validation proof lease requires a receipt reference",
            ));
        };
        if receipt_ref.receipt_id.trim().is_empty()
            || receipt_ref.path.trim().is_empty()
            || !constant_time::ct_eq(&receipt_ref.proof_cache_key_hex, &lease.proof_cache_key.hex)
        {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_MALFORMED_LEASE,
                "completed validation proof lease receipt reference is malformed",
            ));
        }
    }
    if lease.diagnostics.fail_closed
        || matches!(lease.state, ValidationProofLeaseState::FailedClosed)
    {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_CORRUPTED_STATE,
            "validation proof lease is explicitly fail-closed",
        ));
    }
    Ok(())
}

fn write_bytes_create_new(path: &Path, bytes: &[u8]) -> Result<(), ValidationProofCoalescerError> {
    if path.exists() {
        return Err(ValidationProofCoalescerError::DuplicateLease {
            path: path.display().to_string(),
        });
    }
    let parent = path.parent().ok_or_else(|| {
        ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_LEASE,
            "lease path has no parent directory",
        )
    })?;
    fs::create_dir_all(parent).map_err(|source| ValidationProofCoalescerError::Io {
        path: parent.display().to_string(),
        source,
    })?;
    let temp_guard = TempFileGuard::new(path);
    {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(temp_guard.path())
            .map_err(|source| ValidationProofCoalescerError::Io {
                path: temp_guard.path().display().to_string(),
                source,
            })?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| ValidationProofCoalescerError::Io {
                path: temp_guard.path().display().to_string(),
                source,
            })?;
    }
    fs::hard_link(temp_guard.path(), path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            ValidationProofCoalescerError::DuplicateLease {
                path: path.display().to_string(),
            }
        } else {
            ValidationProofCoalescerError::Io {
                path: path.display().to_string(),
                source,
            }
        }
    })?;
    sync_parent_directory(parent, path)?;
    Ok(())
}

fn write_bytes_replace(path: &Path, bytes: &[u8]) -> Result<(), ValidationProofCoalescerError> {
    let parent = path.parent().ok_or_else(|| {
        ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_LEASE,
            "lease path has no parent directory",
        )
    })?;
    fs::create_dir_all(parent).map_err(|source| ValidationProofCoalescerError::Io {
        path: parent.display().to_string(),
        source,
    })?;
    let mut temp_guard = TempFileGuard::new(path);
    {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(temp_guard.path())
            .map_err(|source| ValidationProofCoalescerError::Io {
                path: temp_guard.path().display().to_string(),
                source,
            })?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| ValidationProofCoalescerError::Io {
                path: temp_guard.path().display().to_string(),
                source,
            })?;
    }
    fs::rename(temp_guard.path(), path).map_err(|source| ValidationProofCoalescerError::Io {
        path: path.display().to_string(),
        source,
    })?;
    temp_guard.disarm();
    sync_parent_directory(parent, path)
}

fn sync_parent_directory(parent: &Path, path: &Path) -> Result<(), ValidationProofCoalescerError> {
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|source| ValidationProofCoalescerError::Io {
            path: path.display().to_string(),
            source,
        })
}

struct TempFileGuard {
    path: PathBuf,
    armed: bool,
}

impl TempFileGuard {
    fn new(path: &Path) -> Self {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("validation-proof-lease");
        let unique = format!(
            ".{file_name}.tmp-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        Self {
            path: path.with_file_name(unique),
            armed: true,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn canonical_work_key_material(
    command_digest: &CommandDigest,
    input_digests: &[InputDigest],
    git_commit: &str,
    dirty_worktree: bool,
    dirty_state_policy: DirtyStatePolicy,
    feature_flags: &[String],
    cargo_toolchain: &str,
    package: &str,
    test_target: &str,
    environment_policy_id: &str,
    target_dir_policy_id: &str,
) -> String {
    let input_material = input_digests
        .iter()
        .map(|digest| format!("{}:{}:{}", digest.path, digest.algorithm, digest.hex))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "schema={WORK_KEY_SCHEMA_VERSION}\0command_digest={}:{}\0inputs={}\0git_commit={}\0dirty={}\0dirty_policy={}\0features={}\0toolchain={}\0package={}\0test_target={}\0env_policy={}\0target_policy={}",
        command_digest.algorithm,
        command_digest.hex,
        input_material,
        git_commit,
        dirty_worktree,
        dirty_state_policy.as_str(),
        feature_flags.join(","),
        cargo_toolchain,
        package,
        test_target,
        environment_policy_id,
        target_dir_policy_id
    )
}

fn same_work_key(left: &ValidationProofWorkKey, right: &ValidationProofWorkKey) -> bool {
    constant_time::ct_eq(&left.hex, &right.hex)
        && constant_time::ct_eq(&left.canonical_material, &right.canonical_material)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn key_hex_prefix(hex_value: &str, len: usize) -> &str {
    hex_value
        .get(..len.min(hex_value.len()))
        .unwrap_or(hex_value)
}

fn string_eq(left: &str, right: &str) -> bool {
    constant_time::ct_eq(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::TempDir;

    fn ts(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 6, 2, 0, second)
            .single()
            .expect("valid timestamp")
    }

    fn command_digest(seed: &str) -> CommandDigest {
        let canonical_material = format!("cargo test --test validation_proof_coalescer -- {seed}");
        CommandDigest {
            algorithm: "sha256".to_string(),
            hex: hex::encode(Sha256::digest(canonical_material.as_bytes())),
            canonical_material,
        }
    }

    fn work_key(seed: &str) -> ValidationProofWorkKey {
        ValidationProofWorkKey::from_parts(ValidationProofWorkKeyParts {
            command_digest: command_digest(seed),
            input_digests: vec![InputDigest::new(
                format!("crates/franken-node/src/ops/validation_proof_coalescer_{seed}.rs"),
                seed.as_bytes(),
                "unit-test",
            )],
            git_commit: format!("commit-{seed}"),
            dirty_worktree: false,
            dirty_state_policy: DirtyStatePolicy::CleanRequired,
            feature_flags: vec!["external-commands".to_string(), "http-client".to_string()],
            cargo_toolchain: "nightly-2026-02-19".to_string(),
            package: "frankenengine-node".to_string(),
            test_target: "validation_proof_coalescer".to_string(),
            environment_policy_id: "validation-proof-coalescer/env-policy/v1".to_string(),
            target_dir_policy_id: "validation-proof-coalescer/target-dir/off-repo/v1".to_string(),
        })
        .expect("valid work key")
    }

    fn create_request(seed: &str, agent: &str, at: DateTime<Utc>) -> CreateLeaseRequest {
        let key = work_key(seed);
        CreateLeaseRequest {
            rch_command: ValidationProofRchCommand {
                argv: vec!["rch".to_string(), "exec".to_string(), "--".to_string()],
                command_digest: key.command_digest.clone(),
            },
            proof_work_key: key,
            owner_agent: agent.to_string(),
            owner_bead_id: "bd-y4coj".to_string(),
            trace_id: format!("trace-{seed}-{agent}"),
            fencing_token: format!("fence-{seed}-{agent}"),
            created_at: at,
            expires_at: at + chrono::Duration::minutes(30),
            admission_policy_id: "validation-proof-coalescer/admission/default/v1".to_string(),
        }
    }

    fn capacity_snapshot(
        available_slots: u16,
        queue_depth: u16,
        oldest_queued_age_seconds: Option<u64>,
        degraded: bool,
        disk_pressure_warning: bool,
    ) -> ValidationProofRchCapacitySnapshot {
        ValidationProofRchCapacitySnapshot {
            schema_version: CAPACITY_SNAPSHOT_SCHEMA_VERSION.to_string(),
            observed_at: ts(1),
            workers: vec![ValidationProofRchWorkerCapacity {
                worker_id: "vmi-test-1".to_string(),
                total_slots: 4,
                available_slots,
                queue_depth: 0,
                degraded,
            }],
            queue_depth,
            oldest_queued_age_seconds,
            disk_pressure_warning,
        }
    }

    fn admission_input(
        capacity_snapshot: ValidationProofRchCapacitySnapshot,
        proof_priority: ValidationProofPriority,
        bead_priority: u8,
        current_queue_depth: u16,
    ) -> ValidationProofAdmissionInput {
        ValidationProofAdmissionInput {
            trace_id: format!(
                "trace-admission-{}-{}",
                proof_priority.as_str(),
                bead_priority
            ),
            capacity_snapshot,
            proof_priority,
            bead_priority,
            dirty_worktree: false,
            dirty_state_policy: DirtyStatePolicy::CleanRequired,
            target_dir_class: ValidationProofTargetDirClass::OffRepo,
            timeout_budget_seconds: 900,
            current_queue_depth,
        }
    }

    fn replacement_marker() -> String {
        ["new", "lease", "marker"].join("-")
    }

    #[test]
    fn equivalent_keys_converge_to_join_decision() {
        let temp = TempDir::new().expect("tempdir");
        let store = ValidationProofCoalescerStore::new(temp.path());

        let first = store
            .create_or_join(create_request("same", "PearlLeopard", ts(1)))
            .expect("first create");
        assert_eq!(
            first.decision.decision,
            ValidationProofCoalescerDecisionKind::RunLocallyViaRch
        );

        let second = store
            .create_or_join(create_request("same", "LavenderElk", ts(2)))
            .expect("second join");
        assert_eq!(
            second.decision.decision,
            ValidationProofCoalescerDecisionKind::JoinExistingProof
        );
        let lease = second.lease.expect("lease");
        assert_eq!(lease.waiter_agents, vec!["LavenderElk".to_string()]);
        assert!(second.lease_path.exists());
    }

    #[test]
    fn divergent_keys_create_independent_leases() {
        let temp = TempDir::new().expect("tempdir");
        let store = ValidationProofCoalescerStore::new(temp.path());

        let left = store
            .create_or_join(create_request("left", "PearlLeopard", ts(1)))
            .expect("left");
        let right = store
            .create_or_join(create_request("right", "PearlLeopard", ts(2)))
            .expect("right");

        assert_ne!(left.lease_path, right.lease_path);
        assert!(left.lease_path.exists());
        assert!(right.lease_path.exists());
    }

    #[test]
    fn stale_lease_requires_fencing_before_reuse() {
        let temp = TempDir::new().expect("tempdir");
        let store = ValidationProofCoalescerStore::new(temp.path());
        let mut request = create_request("stale", "PearlLeopard", ts(1));
        request.expires_at = ts(5);
        store.create_or_join(request.clone()).expect("created");

        let stale = store
            .create_or_join(create_request("stale", "LavenderElk", ts(10)))
            .expect("stale decision");
        assert_eq!(
            stale.decision.decision,
            ValidationProofCoalescerDecisionKind::RetryAfterStaleLease
        );
        assert!(stale.decision.diagnostics.fail_closed);

        let fenced = store
            .fence_stale_lease(FenceStaleLeaseRequest {
                proof_work_key: request.proof_work_key.clone(),
                owner_agent: "LavenderElk".to_string(),
                owner_bead_id: "bd-y4coj".to_string(),
                trace_id: "trace-fenced".to_string(),
                fencing_token: replacement_marker(),
                fenced_at: ts(11),
                expires_at: ts(50),
            })
            .expect("fence stale lease");
        assert_eq!(
            fenced.decision.decision,
            ValidationProofCoalescerDecisionKind::RetryAfterStaleLease
        );

        let err = store
            .complete_lease(CompleteLeaseRequest {
                proof_work_key: request.proof_work_key,
                owner_agent: "PearlLeopard".to_string(),
                owner_bead_id: "bd-y4coj".to_string(),
                fencing_token: request.fencing_token,
                completed_at: ts(12),
                receipt_ref: receipt_ref("stale"),
            })
            .expect_err("old owner is fenced");
        assert_eq!(err.code(), error_codes::ERR_VPCO_FENCED_OWNER);
    }

    #[test]
    fn corrupted_metadata_yields_repair_decision() {
        let temp = TempDir::new().expect("tempdir");
        let store = ValidationProofCoalescerStore::new(temp.path());
        let request = create_request("corrupt", "PearlLeopard", ts(1));
        let path = store.lease_path(&request.proof_work_key);
        fs::create_dir_all(path.parent().expect("lease parent")).expect("parent");
        fs::write(&path, b"{not-json").expect("corrupt lease");

        let outcome = store.create_or_join(request).expect("repair decision");
        assert_eq!(
            outcome.decision.decision,
            ValidationProofCoalescerDecisionKind::RepairState
        );
        assert!(outcome.decision.diagnostics.fail_closed);
        assert!(outcome.lease.is_none());
    }

    #[test]
    fn completion_requires_owner_and_fencing_token() {
        let temp = TempDir::new().expect("tempdir");
        let store = ValidationProofCoalescerStore::new(temp.path());
        let request = create_request("complete", "PearlLeopard", ts(1));
        store.create_or_join(request.clone()).expect("created");

        let err = store
            .complete_lease(CompleteLeaseRequest {
                proof_work_key: request.proof_work_key.clone(),
                owner_agent: "LavenderElk".to_string(),
                owner_bead_id: "bd-y4coj".to_string(),
                fencing_token: request.fencing_token.clone(),
                completed_at: ts(2),
                receipt_ref: receipt_ref("complete"),
            })
            .expect_err("wrong owner rejected");
        assert_eq!(err.code(), error_codes::ERR_VPCO_FENCED_OWNER);

        let completed = store
            .complete_lease(CompleteLeaseRequest {
                proof_work_key: request.proof_work_key,
                owner_agent: request.owner_agent,
                owner_bead_id: request.owner_bead_id,
                fencing_token: request.fencing_token,
                completed_at: ts(3),
                receipt_ref: receipt_ref("complete"),
            })
            .expect("complete");
        assert_eq!(completed.state, ValidationProofLeaseState::Completed);
        assert_eq!(
            completed.diagnostics.event_code,
            event_codes::RECEIPT_HANDOFF_COMPLETED
        );
    }

    #[test]
    fn admission_accepts_healthy_capacity_deterministically() {
        let policy = ValidationProofAdmissionPolicy::default_policy(
            "validation-proof-coalescer/admission/default/v1",
        );
        let input = admission_input(
            capacity_snapshot(4, 0, Some(0), false, false),
            ValidationProofPriority::Normal,
            2,
            0,
        );

        let first =
            decide_validation_proof_admission(&policy, &input).expect("first admission decision");
        let second =
            decide_validation_proof_admission(&policy, &input).expect("second admission decision");

        assert_eq!(first, second);
        assert_eq!(
            first.decision,
            ValidationProofCoalescerDecisionKind::RunLocallyViaRch
        );
        assert_eq!(
            first.required_action,
            ValidationProofCoalescerRequiredAction::StartRchValidation
        );
        assert_eq!(
            first.diagnostics.effective_priority,
            ValidationProofPriority::Normal
        );
    }

    #[test]
    fn admission_queues_busy_normal_priority_without_shelling_out() {
        let policy = ValidationProofAdmissionPolicy::default_policy(
            "validation-proof-coalescer/admission/default/v1",
        );
        let probe = StaticValidationProofRchCapacityProbe::new(capacity_snapshot(
            1,
            2,
            Some(15),
            false,
            false,
        ));
        let sampled = sample_validation_proof_capacity(&probe).expect("static capacity sample");
        let input = admission_input(sampled, ValidationProofPriority::Normal, 2, 0);

        let decision =
            decide_validation_proof_admission(&policy, &input).expect("admission decision");

        assert_eq!(
            decision.decision,
            ValidationProofCoalescerDecisionKind::QueuedByPolicy
        );
        assert_eq!(decision.reason_code, reason_codes::QUEUE_CAPACITY);
        assert!(!decision.diagnostics.fail_closed);
    }

    #[test]
    fn admission_rejects_at_queue_high_watermark() {
        let policy = ValidationProofAdmissionPolicy::default_policy(
            "validation-proof-coalescer/admission/default/v1",
        );
        let input = admission_input(
            capacity_snapshot(4, 7, Some(30), false, false),
            ValidationProofPriority::Normal,
            2,
            1,
        );

        let decision =
            decide_validation_proof_admission(&policy, &input).expect("admission decision");

        assert_eq!(
            decision.decision,
            ValidationProofCoalescerDecisionKind::RejectCapacity
        );
        assert_eq!(decision.reason_code, reason_codes::REJECT_CAPACITY);
        assert!(decision.diagnostics.fail_closed);
        assert_eq!(decision.diagnostics.observed_queue_depth, 8);
    }

    #[test]
    fn admission_inherits_high_priority_from_bead_priority() {
        let policy = ValidationProofAdmissionPolicy::default_policy(
            "validation-proof-coalescer/admission/default/v1",
        );
        let input = admission_input(
            capacity_snapshot(1, 0, Some(0), false, false),
            ValidationProofPriority::Low,
            1,
            0,
        );

        let decision =
            decide_validation_proof_admission(&policy, &input).expect("admission decision");

        assert_eq!(
            decision.decision,
            ValidationProofCoalescerDecisionKind::RunLocallyViaRch
        );
        assert_eq!(
            decision.diagnostics.effective_priority,
            ValidationProofPriority::High
        );
    }

    #[test]
    fn admission_rejects_disk_pressure_for_normal_priority() {
        let policy = ValidationProofAdmissionPolicy::default_policy(
            "validation-proof-coalescer/admission/default/v1",
        );
        let input = admission_input(
            capacity_snapshot(4, 0, Some(0), false, true),
            ValidationProofPriority::Normal,
            2,
            0,
        );

        let decision =
            decide_validation_proof_admission(&policy, &input).expect("admission decision");

        assert_eq!(
            decision.decision,
            ValidationProofCoalescerDecisionKind::RejectCapacity
        );
        assert!(decision.diagnostics.disk_pressure_warning);
        assert!(decision.diagnostics.fail_closed);
    }

    fn receipt_ref(seed: &str) -> ValidationProofCoalescerReceiptRef {
        let key = work_key(seed);
        ValidationProofCoalescerReceiptRef {
            receipt_id: format!("receipt-{seed}"),
            path: format!("artifacts/validation_broker/receipts/{seed}.json"),
            bead_id: "bd-y4coj".to_string(),
            proof_cache_key_hex: key.proof_cache_key.hex,
        }
    }
}
