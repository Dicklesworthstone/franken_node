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
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

pub const WORK_KEY_SCHEMA_VERSION: &str = "franken-node/validation-proof-coalescer/work-key/v1";
pub const LEASE_SCHEMA_VERSION: &str = "franken-node/validation-proof-coalescer/lease/v1";
pub const DECISION_SCHEMA_VERSION: &str = "franken-node/validation-proof-coalescer/decision/v1";
pub const TELEMETRY_EVENT_SCHEMA_VERSION: &str =
    "franken-node/validation-proof-coalescer/telemetry-event/v1";
pub const CAPACITY_SNAPSHOT_SCHEMA_VERSION: &str =
    "franken-node/validation-proof-coalescer/rch-capacity-snapshot/v1";
pub const ADMISSION_POLICY_SCHEMA_VERSION: &str =
    "franken-node/validation-proof-coalescer/admission-policy/v1";
pub const ADMISSION_DECISION_SCHEMA_VERSION: &str =
    "franken-node/validation-proof-coalescer/admission-decision/v1";
pub const WORK_STEAL_POLICY_SCHEMA_VERSION: &str =
    "franken-node/validation-proof-coalescer/work-steal-policy/v1";
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
    pub const ERR_VPCO_INSUFFICIENT_STALE_EVIDENCE: &str = "ERR_VPCO_INSUFFICIENT_STALE_EVIDENCE";
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
    pub const WAIT_FRESH_PRODUCER: &str = "VPCO_WAIT_FRESH_PRODUCER";
    pub const INSUFFICIENT_STALE_EVIDENCE: &str = "VPCO_INSUFFICIENT_STALE_EVIDENCE";
}

pub mod swarm_scheduler_error_codes {
    pub const ERR_VSS_INVALID_SCHEMA_VERSION: &str = "ERR_VSS_INVALID_SCHEMA_VERSION";
    pub const ERR_VSS_MALFORMED_INPUT: &str = "ERR_VSS_MALFORMED_INPUT";
    pub const ERR_VSS_BAD_WORK_KEY: &str = "ERR_VSS_BAD_WORK_KEY";
    pub const ERR_VSS_COMMAND_DIGEST_MISMATCH: &str = "ERR_VSS_COMMAND_DIGEST_MISMATCH";
    pub const ERR_VSS_MALFORMED_POLICY: &str = "ERR_VSS_MALFORMED_POLICY";
    pub const ERR_VSS_PRODUCT_RETRIED_AS_INFRA: &str = "ERR_VSS_PRODUCT_RETRIED_AS_INFRA";
    pub const ERR_VSS_INVALID_ARTIFACT_ACCEPTED: &str = "ERR_VSS_INVALID_ARTIFACT_ACCEPTED";
}

pub mod swarm_scheduler_reason_codes {
    pub const RUN_READY: &str = "VSS_RUN_READY";
    pub const JOIN_IDENTICAL: &str = "VSS_JOIN_IDENTICAL";
    pub const WAIT_CAPACITY: &str = "VSS_WAIT_CAPACITY";
    pub const STEAL_STALE: &str = "VSS_STEAL_STALE";
    pub const REJECT_LOW_PRIORITY: &str = "VSS_REJECT_LOW_PRIORITY";
    pub const SOURCE_ONLY_BLOCKER: &str = "VSS_SOURCE_ONLY_BLOCKER";
    pub const FAIL_PRODUCT: &str = "VSS_FAIL_PRODUCT";
    pub const FAIL_INVALID_ARTIFACT: &str = "VSS_FAIL_INVALID_ARTIFACT";
}

pub mod swarm_scheduler_event_codes {
    pub const RUN_NOW: &str = "VSS-001";
    pub const JOIN_EXISTING: &str = "VSS-002";
    pub const WAIT_CAPACITY: &str = "VSS-003";
    pub const STEAL_STALE: &str = "VSS-004";
    pub const REJECT_LOW_PRIORITY: &str = "VSS-005";
    pub const SOURCE_ONLY_BLOCKER: &str = "VSS-006";
    pub const FAIL_PRODUCT: &str = "VSS-007";
    pub const FAIL_INVALID_ARTIFACT: &str = "VSS-008";
}

pub mod capacity_market_reason_codes {
    pub const ALLOW_SOURCE_ONLY: &str = "VCM_ALLOW_SOURCE_ONLY";
    pub const RESERVE_RCH_SLOT: &str = "VCM_RESERVE_RCH_SLOT";
    pub const WAIT_FOR_EXISTING_PROOF: &str = "VCM_WAIT_FOR_EXISTING_PROOF";
    pub const REUSE_CACHE_RECEIPT: &str = "VCM_REUSE_CACHE_RECEIPT";
    pub const QUEUE_WITH_RETRY_AFTER: &str = "VCM_QUEUE_WITH_RETRY_AFTER";
    pub const REFUSE_LOCAL_FALLBACK: &str = "VCM_REFUSE_LOCAL_FALLBACK";
    pub const FAIL_CLOSED: &str = "VCM_FAIL_CLOSED";
}

/// Process-local validation proof coalescer lease synchronization lock.
///
/// Prevents TOCTOU race conditions in lease read-modify-write paths by
/// coordinating file-based reads and writes across concurrent agents. Uses
/// advisory file locking (cross-process) plus in-process mutex (same-process
/// coordination).
fn validation_proof_coalescer_persist_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_validation_proof_coalescer_persist(
    _lease_path: &Path,
) -> Result<MutexGuard<'static, ()>, ValidationProofCoalescerError> {
    validation_proof_coalescer_persist_lock()
        .lock()
        .map_err(|_| {
            ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_MALFORMED_LEASE,
                "validation proof coalescer persist lock poisoned",
            )
        })
}

fn validation_proof_coalescer_lock_path(lease_path: &Path) -> PathBuf {
    let parent = lease_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = lease_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("validation-proof-coalescer-lease");
    parent.join(format!("{file_name}.lock"))
}

fn lock_validation_proof_coalescer_file(
    file: &File,
    lock_path: &Path,
    lease_path: &Path,
) -> Result<(), ValidationProofCoalescerError> {
    match file.try_lock_exclusive() {
        Ok(()) => return Ok(()),
        Err(err) if matches!(err.kind(), ErrorKind::WouldBlock) => {}
        Err(err) => {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_MALFORMED_LEASE,
                format!("failed acquiring flock for {}: {err}", lock_path.display()),
            ));
        }
    }

    // Retry with backoff for contested locks
    let retry_delays = [50, 100, 200, 300, 500]; // milliseconds
    for delay_millis in retry_delays {
        thread::sleep(Duration::from_millis(delay_millis));
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(()),
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock) => {}
            Err(err) => {
                return Err(ValidationProofCoalescerError::contract(
                    error_codes::ERR_VPCO_MALFORMED_LEASE,
                    format!("failed acquiring flock for {}: {err}", lock_path.display()),
                ));
            }
        }
    }

    Err(ValidationProofCoalescerError::contract(
        error_codes::ERR_VPCO_MALFORMED_LEASE,
        format!(
            "validation proof coalescer file lock timeout for {}",
            lease_path.display()
        ),
    ))
}

fn unlock_validation_proof_coalescer_file(
    file: &File,
    lock_path: &Path,
    _lease_path: &Path,
) -> Result<(), ValidationProofCoalescerError> {
    file.unlock().map_err(|err| {
        ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_LEASE,
            format!("failed releasing flock for {}: {err}", lock_path.display()),
        )
    })
}

fn with_validation_proof_coalescer_persist_lock<T>(
    lease_path: &Path,
    lease_operation: impl FnOnce() -> Result<T, ValidationProofCoalescerError>,
) -> Result<T, ValidationProofCoalescerError> {
    // Canonical lock order: file flock first, process mutex second.
    let parent = lease_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|err| {
        ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_LEASE,
            format!(
                "failed creating lease parent directory {}: {err}",
                parent.display()
            ),
        )
    })?;

    let lock_path = validation_proof_coalescer_lock_path(lease_path);
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| {
            ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_MALFORMED_LEASE,
                format!("failed opening flock file {}: {err}", lock_path.display()),
            )
        })?;

    // Step 1: Acquire file flock FIRST (cross-process synchronization)
    lock_validation_proof_coalescer_file(&lock_file, &lock_path, lease_path)?;

    // Step 2: Acquire process Mutex SECOND (in-process synchronization)
    let _process_guard = lock_validation_proof_coalescer_persist(lease_path)?;

    let work_result = lease_operation();
    let unlock_result = unlock_validation_proof_coalescer_file(&lock_file, &lock_path, lease_path);

    match (work_result, unlock_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), _) => Err(err),
        (Ok(_), Err(err)) => Err(err),
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofWorkStealPolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub min_heartbeat_stale_seconds: u64,
    pub min_progress_stale_seconds: u64,
    pub min_timeout_budget_seconds: u64,
}

impl ValidationProofWorkStealPolicy {
    #[must_use]
    pub fn default_policy(policy_id: impl Into<String>) -> Self {
        Self {
            schema_version: WORK_STEAL_POLICY_SCHEMA_VERSION.to_string(),
            policy_id: policy_id.into(),
            min_heartbeat_stale_seconds: 300,
            min_progress_stale_seconds: 300,
            min_timeout_budget_seconds: 300,
        }
    }
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

pub const SWARM_SCHEDULER_INPUT_SCHEMA_VERSION: &str =
    "franken-node/validation-swarm-scheduler/input/v1";
pub const SWARM_SCHEDULER_POLICY_SCHEMA_VERSION: &str =
    "franken-node/validation-swarm-scheduler/policy/v1";
pub const SWARM_SCHEDULER_DECISION_SCHEMA_VERSION: &str =
    "franken-node/validation-swarm-scheduler/decision/v1";
pub const VALIDATION_CAPACITY_MARKET_BID_SCHEMA_VERSION: &str =
    "franken-node/validation-capacity-market/bid/v1";
const SWARM_SCHEDULER_MAX_ID_BYTES: usize = 160;
const SWARM_SCHEDULER_MAX_FIELD_BYTES: usize = 512;
const SWARM_SCHEDULER_MAX_PATH_BYTES: usize = 2048;
const SWARM_SCHEDULER_MAX_FEATURE_FLAGS: usize = 128;
const SWARM_SCHEDULER_MAX_INPUT_DIGESTS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmSchedulerDigestRef {
    pub algorithm: String,
    pub hex: String,
    pub canonical_material: String,
}

impl ValidationSwarmSchedulerDigestRef {
    #[must_use]
    pub fn sha256_material(material: impl Into<String>) -> Self {
        let canonical_material = material.into();
        Self {
            algorithm: "sha256".to_string(),
            hex: hex::encode(Sha256::digest(canonical_material.as_bytes())),
            canonical_material,
        }
    }

    #[must_use]
    pub fn verifies(&self) -> bool {
        if !string_eq(&self.algorithm, "sha256") || !is_sha256_hex(&self.hex) {
            return false;
        }
        let expected = hex::encode(Sha256::digest(self.canonical_material.as_bytes()));
        constant_time::ct_eq(&expected, &self.hex)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ValidationSwarmSchedulerPriority {
    #[serde(rename = "P0")]
    P0,
    #[serde(rename = "P1")]
    P1,
    #[serde(rename = "P2")]
    P2,
    #[serde(rename = "P3")]
    P3,
    #[serde(rename = "P4")]
    P4,
}

impl ValidationSwarmSchedulerPriority {
    #[must_use]
    pub const fn is_low_priority(self) -> bool {
        matches!(self, Self::P3 | Self::P4)
    }

    #[must_use]
    pub const fn sort_rank(self) -> u8 {
        match self {
            Self::P0 => 0,
            Self::P1 => 1,
            Self::P2 => 2,
            Self::P3 => 3,
            Self::P4 => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSwarmSchedulerTargetDirClass {
    OffRepo,
    RepoLocalGuarded,
    RepoLocalWritable,
    Unwritable,
    Missing,
    Unknown,
}

impl From<ValidationProofTargetDirClass> for ValidationSwarmSchedulerTargetDirClass {
    fn from(value: ValidationProofTargetDirClass) -> Self {
        match value {
            ValidationProofTargetDirClass::OffRepo | ValidationProofTargetDirClass::Tmp => {
                Self::OffRepo
            }
            ValidationProofTargetDirClass::RepoLocal => Self::RepoLocalWritable,
            ValidationProofTargetDirClass::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSwarmSchedulerCoalescerState {
    None,
    Running,
    Joined,
    Completed,
    Stale,
    Fenced,
    Rejected,
    FailedClosed,
}

impl ValidationSwarmSchedulerCoalescerState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Running => "running",
            Self::Joined => "joined",
            Self::Completed => "completed",
            Self::Stale => "stale",
            Self::Fenced => "fenced",
            Self::Rejected => "rejected",
            Self::FailedClosed => "failed_closed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSwarmSchedulerFlightRecorderState {
    None,
    RemoteSuccess,
    WorkerTimeout,
    MissingToolchain,
    DiskPressure,
    ContentionDeferred,
    LocalFallbackRefused,
    SourceOnlyBlocker,
    ProductFailure,
    InvalidArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSwarmSchedulerProofDebtClass {
    None,
    WorkerInfra,
    Capacity,
    StaleProducer,
    SourceOnly,
    ProductFailure,
    InvalidArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSwarmSchedulerDecisionKind {
    RunNow,
    JoinExisting,
    WaitForCapacity,
    StealStaleWork,
    RejectLowPriority,
    RecordSourceOnlyBlocker,
    FailClosedProduct,
    FailClosedInvalidArtifact,
}

impl ValidationSwarmSchedulerDecisionKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunNow => "run_now",
            Self::JoinExisting => "join_existing",
            Self::WaitForCapacity => "wait_for_capacity",
            Self::StealStaleWork => "steal_stale_work",
            Self::RejectLowPriority => "reject_low_priority",
            Self::RecordSourceOnlyBlocker => "record_source_only_blocker",
            Self::FailClosedProduct => "fail_closed_product",
            Self::FailClosedInvalidArtifact => "fail_closed_invalid_artifact",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSwarmSchedulerRequiredAction {
    StartRchValidation,
    JoinExistingProof,
    WaitForCapacity,
    StealWithNewFence,
    DeferLowPriority,
    RecordSourceOnlyBlocker,
    SurfaceProductFailure,
    RejectArtifact,
}

impl ValidationSwarmSchedulerRequiredAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartRchValidation => "start_rch_validation",
            Self::JoinExistingProof => "join_existing_proof",
            Self::WaitForCapacity => "wait_for_capacity",
            Self::StealWithNewFence => "steal_with_new_fence",
            Self::DeferLowPriority => "defer_low_priority",
            Self::RecordSourceOnlyBlocker => "record_source_only_blocker",
            Self::SurfaceProductFailure => "surface_product_failure",
            Self::RejectArtifact => "reject_artifact",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSwarmSchedulerFairnessBucket {
    Emergency,
    High,
    Normal,
    Low,
    Aging,
    Blocked,
}

impl ValidationSwarmSchedulerFairnessBucket {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::High => "high",
            Self::Normal => "normal",
            Self::Low => "low",
            Self::Aging => "aging",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSwarmSchedulerStarvationRisk {
    None,
    Watch,
    Elevated,
    Breached,
}

impl ValidationSwarmSchedulerStarvationRisk {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Breached => "breached",
        }
    }

    #[must_use]
    pub const fn breaches_slo(self) -> bool {
        matches!(self, Self::Breached)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmSchedulerCapacitySnapshot {
    pub snapshot_id: String,
    pub captured_at: DateTime<Utc>,
    pub workers_total: u16,
    pub workers_healthy: u16,
    pub slots_total: u16,
    pub slots_available: u16,
    pub queue_depth: u16,
    pub stale_active_builds: u16,
    pub disk_pressure_workers: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmSchedulerPolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub max_running_proofs: u16,
    pub max_waiters_per_work_key: u16,
    pub queue_high_watermark: u16,
    pub starvation_after_ms: u64,
    pub aging_step_ms: u64,
    pub min_available_worker_slots: u16,
    pub allow_work_stealing: bool,
    pub fairness_buckets: Vec<ValidationSwarmSchedulerFairnessBucket>,
}

impl ValidationSwarmSchedulerPolicy {
    #[must_use]
    pub fn default_policy(policy_id: impl Into<String>) -> Self {
        Self {
            schema_version: SWARM_SCHEDULER_POLICY_SCHEMA_VERSION.to_string(),
            policy_id: policy_id.into(),
            max_running_proofs: 8,
            max_waiters_per_work_key: 32,
            queue_high_watermark: 64,
            starvation_after_ms: 900_000,
            aging_step_ms: 300_000,
            min_available_worker_slots: 2,
            allow_work_stealing: true,
            fairness_buckets: vec![
                ValidationSwarmSchedulerFairnessBucket::Emergency,
                ValidationSwarmSchedulerFairnessBucket::High,
                ValidationSwarmSchedulerFairnessBucket::Normal,
                ValidationSwarmSchedulerFairnessBucket::Low,
                ValidationSwarmSchedulerFairnessBucket::Aging,
                ValidationSwarmSchedulerFairnessBucket::Blocked,
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmSchedulerInput {
    pub schema_version: String,
    pub input_id: String,
    pub bead_id: String,
    pub agent_name: String,
    pub proof_work_key: ValidationSwarmSchedulerDigestRef,
    pub command_digest: ValidationSwarmSchedulerDigestRef,
    pub dirty_state_policy: DirtyStatePolicy,
    pub target_dir_class: ValidationSwarmSchedulerTargetDirClass,
    pub capacity_snapshot: ValidationSwarmSchedulerCapacitySnapshot,
    pub coalescer_state: ValidationSwarmSchedulerCoalescerState,
    pub flight_recorder_state: ValidationSwarmSchedulerFlightRecorderState,
    pub proof_debt_class: ValidationSwarmSchedulerProofDebtClass,
    pub queue_age_ms: u64,
    pub priority: ValidationSwarmSchedulerPriority,
    pub timeout_budget_ms: u64,
    pub source_only_allowed: bool,
    pub product_failure: bool,
    pub worker_infra_retryable: bool,
    pub artifact_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationSwarmSchedulerBuildInput {
    pub bead_id: String,
    pub agent_name: String,
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
    pub target_dir_class: ValidationSwarmSchedulerTargetDirClass,
    pub capacity_snapshot: ValidationSwarmSchedulerCapacitySnapshot,
    pub coalescer_state: ValidationSwarmSchedulerCoalescerState,
    pub flight_recorder_state: ValidationSwarmSchedulerFlightRecorderState,
    pub proof_debt_class: ValidationSwarmSchedulerProofDebtClass,
    pub queue_age_ms: u64,
    pub priority: ValidationSwarmSchedulerPriority,
    pub timeout_budget_ms: u64,
    pub source_only_allowed: bool,
    pub product_failure: bool,
    pub worker_infra_retryable: bool,
    pub artifact_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmSchedulerDiagnostics {
    pub proof_work_key_hex: String,
    pub command_digest_hex: String,
    pub capacity_snapshot_id: String,
    pub queue_age_ms: u64,
    pub slots_total: u16,
    pub slots_available: u16,
    pub worker_slots: u16,
    pub queue_depth: u16,
    pub coalescer_state: ValidationSwarmSchedulerCoalescerState,
    pub flight_recorder_state: ValidationSwarmSchedulerFlightRecorderState,
    pub proof_debt_class: ValidationSwarmSchedulerProofDebtClass,
    pub retry_after_ms: Option<u64>,
    pub fencing_token_digest: Option<String>,
    pub recorder_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSwarmSchedulerDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub input_ref: String,
    pub bead_id: String,
    pub agent_name: String,
    pub trace_id: String,
    pub decided_at: DateTime<Utc>,
    pub freshness_expires_at: DateTime<Utc>,
    pub decision: ValidationSwarmSchedulerDecisionKind,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: ValidationSwarmSchedulerRequiredAction,
    pub fairness_bucket: ValidationSwarmSchedulerFairnessBucket,
    pub starvation_risk: ValidationSwarmSchedulerStarvationRisk,
    pub retryable: bool,
    pub fail_closed: bool,
    pub green_proof_eligible: bool,
    pub operator_message: String,
    pub diagnostics: ValidationSwarmSchedulerDiagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCapacityMarketBidKind {
    AllowSourceOnly,
    ReserveRchSlot,
    WaitForExistingProof,
    ReuseCacheReceipt,
    QueueWithRetryAfter,
    RefuseLocalFallback,
    FailClosed,
}

impl ValidationCapacityMarketBidKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowSourceOnly => "allow_source_only",
            Self::ReserveRchSlot => "reserve_rch_slot",
            Self::WaitForExistingProof => "wait_for_existing_proof",
            Self::ReuseCacheReceipt => "reuse_cache_receipt",
            Self::QueueWithRetryAfter => "queue_with_retry_after",
            Self::RefuseLocalFallback => "refuse_local_fallback",
            Self::FailClosed => "fail_closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCapacityMarketBid {
    pub schema_version: String,
    pub bid_id: String,
    pub bead_id: String,
    pub agent_name: String,
    pub bid: ValidationCapacityMarketBidKind,
    pub reason_code: String,
    pub source_decision: ValidationSwarmSchedulerDecisionKind,
    pub source_reason_code: String,
    pub required_action: ValidationSwarmSchedulerRequiredAction,
    pub fairness_bucket: ValidationSwarmSchedulerFairnessBucket,
    pub starvation_risk: ValidationSwarmSchedulerStarvationRisk,
    pub command_digest_hex: String,
    pub proof_work_key_hex: String,
    pub capacity_snapshot_id: String,
    pub queue_rank: u16,
    pub queue_depth: u16,
    pub slots_available: u16,
    pub retry_after_ms: Option<u64>,
    pub fail_closed: bool,
    pub green_proof_eligible: bool,
    pub capacity_evidence_source: String,
    pub operator_message: String,
}

pub fn decide_validation_swarm_schedule(
    policy: &ValidationSwarmSchedulerPolicy,
    input: &ValidationSwarmSchedulerInput,
    decided_at: DateTime<Utc>,
) -> Result<ValidationSwarmSchedulerDecision, ValidationProofCoalescerError> {
    validate_swarm_scheduler_policy(policy)?;
    validate_swarm_scheduler_input(input)?;

    let starvation_risk = swarm_scheduler_starvation_risk(policy, input.queue_age_ms);
    let kind = if !input.artifact_valid {
        ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact
    } else if input.product_failure
        || matches!(
            input.flight_recorder_state,
            ValidationSwarmSchedulerFlightRecorderState::ProductFailure
        )
        || matches!(
            input.proof_debt_class,
            ValidationSwarmSchedulerProofDebtClass::ProductFailure
        )
    {
        ValidationSwarmSchedulerDecisionKind::FailClosedProduct
    } else if input.source_only_allowed
        || matches!(
            input.flight_recorder_state,
            ValidationSwarmSchedulerFlightRecorderState::SourceOnlyBlocker
        )
        || matches!(
            input.proof_debt_class,
            ValidationSwarmSchedulerProofDebtClass::SourceOnly
        )
    {
        ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker
    } else if matches!(
        input.coalescer_state,
        ValidationSwarmSchedulerCoalescerState::Running
            | ValidationSwarmSchedulerCoalescerState::Joined
            | ValidationSwarmSchedulerCoalescerState::Completed
    ) {
        ValidationSwarmSchedulerDecisionKind::JoinExisting
    } else if policy.allow_work_stealing
        && matches!(
            input.coalescer_state,
            ValidationSwarmSchedulerCoalescerState::Stale
                | ValidationSwarmSchedulerCoalescerState::Fenced
        )
    {
        ValidationSwarmSchedulerDecisionKind::StealStaleWork
    } else if input.priority.is_low_priority()
        && input.capacity_snapshot.queue_depth >= policy.queue_high_watermark
        && !matches!(
            starvation_risk,
            ValidationSwarmSchedulerStarvationRisk::Elevated
                | ValidationSwarmSchedulerStarvationRisk::Breached
        )
    {
        ValidationSwarmSchedulerDecisionKind::RejectLowPriority
    } else if input.capacity_snapshot.slots_available < policy.min_available_worker_slots
        || input.capacity_snapshot.queue_depth >= policy.queue_high_watermark
        || input.capacity_snapshot.stale_active_builds >= policy.max_running_proofs
        || input.capacity_snapshot.disk_pressure_workers > 0
        || input.worker_infra_retryable
    {
        ValidationSwarmSchedulerDecisionKind::WaitForCapacity
    } else {
        ValidationSwarmSchedulerDecisionKind::RunNow
    };

    Ok(build_swarm_scheduler_decision(
        policy, input, kind, decided_at,
    ))
}

pub fn build_validation_swarm_scheduler_input(
    parts: ValidationSwarmSchedulerBuildInput,
) -> Result<ValidationSwarmSchedulerInput, ValidationProofCoalescerError> {
    validate_swarm_scheduler_build_input(&parts)?;

    let ValidationSwarmSchedulerBuildInput {
        bead_id,
        agent_name,
        command_digest,
        input_digests,
        git_commit,
        dirty_worktree,
        dirty_state_policy,
        feature_flags,
        cargo_toolchain,
        package,
        test_target,
        environment_policy_id,
        target_dir_policy_id,
        target_dir_class,
        capacity_snapshot,
        coalescer_state,
        flight_recorder_state,
        proof_debt_class,
        queue_age_ms,
        priority,
        timeout_budget_ms,
        source_only_allowed,
        product_failure,
        worker_infra_retryable,
        artifact_valid,
    } = parts;

    let scheduler_command_digest = swarm_scheduler_digest_from_command(&command_digest)?;
    let proof_work_key = ValidationProofWorkKey::from_parts(ValidationProofWorkKeyParts {
        command_digest,
        input_digests,
        git_commit,
        dirty_worktree,
        dirty_state_policy,
        feature_flags,
        cargo_toolchain,
        package,
        test_target,
        environment_policy_id,
        target_dir_policy_id,
    })?;
    let scheduler_proof_work_key = swarm_scheduler_digest_from_work_key(&proof_work_key);
    let input = ValidationSwarmSchedulerInput {
        schema_version: SWARM_SCHEDULER_INPUT_SCHEMA_VERSION.to_string(),
        input_id: swarm_scheduler_input_id(
            &bead_id,
            &agent_name,
            &scheduler_proof_work_key.hex,
            &scheduler_command_digest.hex,
        ),
        bead_id,
        agent_name,
        proof_work_key: scheduler_proof_work_key,
        command_digest: scheduler_command_digest,
        dirty_state_policy,
        target_dir_class,
        capacity_snapshot,
        coalescer_state,
        flight_recorder_state,
        proof_debt_class,
        queue_age_ms,
        priority,
        timeout_budget_ms,
        source_only_allowed,
        product_failure,
        worker_infra_retryable,
        artifact_valid,
    };
    validate_swarm_scheduler_input(&input)?;
    Ok(input)
}

pub fn decide_validation_swarm_schedule_from_build_input(
    policy: &ValidationSwarmSchedulerPolicy,
    parts: ValidationSwarmSchedulerBuildInput,
    decided_at: DateTime<Utc>,
) -> Result<ValidationSwarmSchedulerDecision, ValidationProofCoalescerError> {
    let input = build_validation_swarm_scheduler_input(parts)?;
    decide_validation_swarm_schedule(policy, &input, decided_at)
}

pub fn order_validation_swarm_scheduler_inputs<'a>(
    policy: &ValidationSwarmSchedulerPolicy,
    inputs: &'a [ValidationSwarmSchedulerInput],
) -> Result<Vec<&'a ValidationSwarmSchedulerInput>, ValidationProofCoalescerError> {
    validate_swarm_scheduler_policy(policy)?;
    for input in inputs {
        validate_swarm_scheduler_input(input)?;
    }

    let mut ordered = inputs.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| swarm_scheduler_input_ordering(policy, left, right));
    Ok(ordered)
}

pub fn build_validation_capacity_market_bids(
    policy: &ValidationSwarmSchedulerPolicy,
    inputs: &[ValidationSwarmSchedulerInput],
    decided_at: DateTime<Utc>,
) -> Result<Vec<ValidationCapacityMarketBid>, ValidationProofCoalescerError> {
    let ordered = order_validation_swarm_scheduler_inputs(policy, inputs)?;
    let mut bids = Vec::with_capacity(ordered.len());
    for (index, input) in ordered.into_iter().enumerate() {
        let decision = decide_validation_swarm_schedule(policy, input, decided_at)?;
        bids.push(validation_capacity_market_bid_from_decision(
            &decision,
            queue_rank_from_index(index),
        ));
    }
    Ok(bids)
}

#[must_use]
pub fn validation_capacity_market_bid_from_decision(
    decision: &ValidationSwarmSchedulerDecision,
    queue_rank: u16,
) -> ValidationCapacityMarketBid {
    let (bid, reason_code) = validation_capacity_market_bid_rule(decision);
    ValidationCapacityMarketBid {
        schema_version: VALIDATION_CAPACITY_MARKET_BID_SCHEMA_VERSION.to_string(),
        bid_id: format!("vcm-bid-{}-{}", decision.input_ref, bid.as_str()),
        bead_id: decision.bead_id.clone(),
        agent_name: decision.agent_name.clone(),
        bid,
        reason_code: reason_code.to_string(),
        source_decision: decision.decision,
        source_reason_code: decision.reason_code.clone(),
        required_action: decision.required_action,
        fairness_bucket: decision.fairness_bucket,
        starvation_risk: decision.starvation_risk,
        command_digest_hex: decision.diagnostics.command_digest_hex.clone(),
        proof_work_key_hex: decision.diagnostics.proof_work_key_hex.clone(),
        capacity_snapshot_id: decision.diagnostics.capacity_snapshot_id.clone(),
        queue_rank,
        queue_depth: decision.diagnostics.queue_depth,
        slots_available: decision.diagnostics.slots_available,
        retry_after_ms: decision.diagnostics.retry_after_ms,
        fail_closed: decision.fail_closed
            || matches!(
                bid,
                ValidationCapacityMarketBidKind::FailClosed
                    | ValidationCapacityMarketBidKind::RefuseLocalFallback
            ),
        green_proof_eligible: bid == ValidationCapacityMarketBidKind::ReserveRchSlot
            && !decision.fail_closed,
        capacity_evidence_source: format!(
            "validation_swarm_scheduler:{}",
            decision.diagnostics.capacity_snapshot_id
        ),
        operator_message: validation_capacity_market_operator_message(bid).to_string(),
    }
}

#[must_use]
pub fn render_validation_capacity_market_bid_human(bid: &ValidationCapacityMarketBid) -> String {
    format!(
        "capacity_market_bid bead={} bid={} reason_code={} queue_rank={} retry_after_ms={} capacity_source={} action={}",
        bid.bead_id,
        bid.bid.as_str(),
        bid.reason_code,
        bid.queue_rank,
        bid.retry_after_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string()),
        bid.capacity_evidence_source,
        bid.operator_message
    )
}

pub fn render_validation_capacity_market_bid_json(
    bid: &ValidationCapacityMarketBid,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(bid)
}

fn swarm_scheduler_input_ordering(
    policy: &ValidationSwarmSchedulerPolicy,
    left: &ValidationSwarmSchedulerInput,
    right: &ValidationSwarmSchedulerInput,
) -> Ordering {
    swarm_scheduler_effective_priority_rank(policy, left)
        .cmp(&swarm_scheduler_effective_priority_rank(policy, right))
        .then_with(|| left.timeout_budget_ms.cmp(&right.timeout_budget_ms))
        .then_with(|| right.queue_age_ms.cmp(&left.queue_age_ms))
        .then_with(|| left.proof_work_key.hex.cmp(&right.proof_work_key.hex))
        .then_with(|| left.bead_id.cmp(&right.bead_id))
        .then_with(|| left.agent_name.cmp(&right.agent_name))
        .then_with(|| left.input_id.cmp(&right.input_id))
}

fn swarm_scheduler_effective_priority_rank(
    policy: &ValidationSwarmSchedulerPolicy,
    input: &ValidationSwarmSchedulerInput,
) -> u8 {
    let base_rank = input.priority.sort_rank();
    if input.product_failure
        || !input.artifact_valid
        || matches!(
            input.proof_debt_class,
            ValidationSwarmSchedulerProofDebtClass::SourceOnly
                | ValidationSwarmSchedulerProofDebtClass::ProductFailure
                | ValidationSwarmSchedulerProofDebtClass::InvalidArtifact
        )
    {
        return base_rank;
    }

    let aging_steps = input.queue_age_ms / policy.aging_step_ms;
    let aging_boost = u8::try_from(aging_steps).unwrap_or(u8::MAX).min(2);
    base_rank.saturating_sub(aging_boost)
}

fn validation_capacity_market_bid_rule(
    decision: &ValidationSwarmSchedulerDecision,
) -> (ValidationCapacityMarketBidKind, &'static str) {
    if decision.diagnostics.flight_recorder_state
        == ValidationSwarmSchedulerFlightRecorderState::LocalFallbackRefused
    {
        return (
            ValidationCapacityMarketBidKind::RefuseLocalFallback,
            capacity_market_reason_codes::REFUSE_LOCAL_FALLBACK,
        );
    }

    match decision.decision {
        ValidationSwarmSchedulerDecisionKind::RunNow
        | ValidationSwarmSchedulerDecisionKind::StealStaleWork => (
            ValidationCapacityMarketBidKind::ReserveRchSlot,
            capacity_market_reason_codes::RESERVE_RCH_SLOT,
        ),
        ValidationSwarmSchedulerDecisionKind::JoinExisting
            if decision.diagnostics.coalescer_state
                == ValidationSwarmSchedulerCoalescerState::Completed =>
        {
            (
                ValidationCapacityMarketBidKind::ReuseCacheReceipt,
                capacity_market_reason_codes::REUSE_CACHE_RECEIPT,
            )
        }
        ValidationSwarmSchedulerDecisionKind::JoinExisting => (
            ValidationCapacityMarketBidKind::WaitForExistingProof,
            capacity_market_reason_codes::WAIT_FOR_EXISTING_PROOF,
        ),
        ValidationSwarmSchedulerDecisionKind::WaitForCapacity
        | ValidationSwarmSchedulerDecisionKind::RejectLowPriority => (
            ValidationCapacityMarketBidKind::QueueWithRetryAfter,
            capacity_market_reason_codes::QUEUE_WITH_RETRY_AFTER,
        ),
        ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker => (
            ValidationCapacityMarketBidKind::AllowSourceOnly,
            capacity_market_reason_codes::ALLOW_SOURCE_ONLY,
        ),
        ValidationSwarmSchedulerDecisionKind::FailClosedProduct
        | ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact => (
            ValidationCapacityMarketBidKind::FailClosed,
            capacity_market_reason_codes::FAIL_CLOSED,
        ),
    }
}

fn validation_capacity_market_operator_message(
    bid: ValidationCapacityMarketBidKind,
) -> &'static str {
    match bid {
        ValidationCapacityMarketBidKind::AllowSourceOnly => {
            "Record source-only evidence and do not count the proof as green."
        }
        ValidationCapacityMarketBidKind::ReserveRchSlot => {
            "Reserve one RCH slot for the producer proof."
        }
        ValidationCapacityMarketBidKind::WaitForExistingProof => {
            "Wait for the matching in-flight proof instead of launching a duplicate."
        }
        ValidationCapacityMarketBidKind::ReuseCacheReceipt => {
            "Reuse the completed proof/cache receipt and avoid new cargo work."
        }
        ValidationCapacityMarketBidKind::QueueWithRetryAfter => {
            "Queue the proof and retry after the market backoff."
        }
        ValidationCapacityMarketBidKind::RefuseLocalFallback => {
            "Refuse local fallback; remote proof remains required."
        }
        ValidationCapacityMarketBidKind::FailClosed => {
            "Surface the failure as a blocker; do not retry it as capacity work."
        }
    }
}

fn queue_rank_from_index(index: usize) -> u16 {
    u16::try_from(index.saturating_add(1)).unwrap_or(u16::MAX)
}

fn validate_swarm_scheduler_policy(
    policy: &ValidationSwarmSchedulerPolicy,
) -> Result<(), ValidationProofCoalescerError> {
    if !string_eq(
        &policy.schema_version,
        SWARM_SCHEDULER_POLICY_SCHEMA_VERSION,
    ) || policy.policy_id.trim().is_empty()
        || policy.max_running_proofs == 0
        || policy.max_waiters_per_work_key == 0
        || policy.queue_high_watermark == 0
        || policy.starvation_after_ms == 0
        || policy.aging_step_ms == 0
        || policy.fairness_buckets.is_empty()
    {
        return Err(ValidationProofCoalescerError::contract(
            swarm_scheduler_error_codes::ERR_VSS_MALFORMED_POLICY,
            "validation swarm scheduler policy is malformed",
        ));
    }
    Ok(())
}

fn validate_swarm_scheduler_input(
    input: &ValidationSwarmSchedulerInput,
) -> Result<(), ValidationProofCoalescerError> {
    if !string_eq(&input.schema_version, SWARM_SCHEDULER_INPUT_SCHEMA_VERSION) {
        return Err(ValidationProofCoalescerError::contract(
            swarm_scheduler_error_codes::ERR_VSS_INVALID_SCHEMA_VERSION,
            "validation swarm scheduler input schema version is invalid",
        ));
    }
    if !swarm_scheduler_field_is_safe(&input.input_id, SWARM_SCHEDULER_MAX_ID_BYTES)
        || !swarm_scheduler_field_is_safe(&input.bead_id, SWARM_SCHEDULER_MAX_ID_BYTES)
        || !swarm_scheduler_field_is_safe(&input.agent_name, SWARM_SCHEDULER_MAX_ID_BYTES)
        || !swarm_scheduler_field_is_safe(
            &input.capacity_snapshot.snapshot_id,
            SWARM_SCHEDULER_MAX_ID_BYTES,
        )
        || input.capacity_snapshot.workers_total == 0
        || input.capacity_snapshot.workers_healthy > input.capacity_snapshot.workers_total
        || input.capacity_snapshot.slots_total == 0
        || input.capacity_snapshot.slots_available > input.capacity_snapshot.slots_total
        || input.timeout_budget_ms == 0
    {
        return Err(ValidationProofCoalescerError::contract(
            swarm_scheduler_error_codes::ERR_VSS_MALFORMED_INPUT,
            "validation swarm scheduler input identity fields are malformed",
        ));
    }
    if !input.proof_work_key.verifies() {
        return Err(ValidationProofCoalescerError::contract(
            swarm_scheduler_error_codes::ERR_VSS_BAD_WORK_KEY,
            "validation swarm scheduler proof work key digest does not verify",
        ));
    }
    if !input.command_digest.verifies() {
        return Err(ValidationProofCoalescerError::contract(
            swarm_scheduler_error_codes::ERR_VSS_COMMAND_DIGEST_MISMATCH,
            "validation swarm scheduler command digest does not verify",
        ));
    }
    if input.product_failure && input.worker_infra_retryable {
        return Err(ValidationProofCoalescerError::contract(
            swarm_scheduler_error_codes::ERR_VSS_PRODUCT_RETRIED_AS_INFRA,
            "product failure cannot be routed as retryable worker infrastructure",
        ));
    }
    if !input.artifact_valid
        && !matches!(
            input.proof_debt_class,
            ValidationSwarmSchedulerProofDebtClass::InvalidArtifact
        )
    {
        return Err(ValidationProofCoalescerError::contract(
            swarm_scheduler_error_codes::ERR_VSS_INVALID_ARTIFACT_ACCEPTED,
            "invalid scheduler artifacts must be classified as invalid_artifact debt",
        ));
    }
    Ok(())
}

fn validate_swarm_scheduler_build_input(
    parts: &ValidationSwarmSchedulerBuildInput,
) -> Result<(), ValidationProofCoalescerError> {
    if !swarm_scheduler_field_is_safe(&parts.bead_id, SWARM_SCHEDULER_MAX_ID_BYTES)
        || !swarm_scheduler_field_is_safe(&parts.agent_name, SWARM_SCHEDULER_MAX_ID_BYTES)
        || !swarm_scheduler_field_is_safe(&parts.git_commit, SWARM_SCHEDULER_MAX_FIELD_BYTES)
        || !swarm_scheduler_field_is_safe(&parts.cargo_toolchain, SWARM_SCHEDULER_MAX_FIELD_BYTES)
        || !swarm_scheduler_field_is_safe(&parts.package, SWARM_SCHEDULER_MAX_FIELD_BYTES)
        || !swarm_scheduler_field_is_safe(&parts.test_target, SWARM_SCHEDULER_MAX_FIELD_BYTES)
        || !swarm_scheduler_field_is_safe(
            &parts.environment_policy_id,
            SWARM_SCHEDULER_MAX_FIELD_BYTES,
        )
        || !swarm_scheduler_field_is_safe(
            &parts.target_dir_policy_id,
            SWARM_SCHEDULER_MAX_FIELD_BYTES,
        )
        || !swarm_scheduler_field_is_safe(
            &parts.capacity_snapshot.snapshot_id,
            SWARM_SCHEDULER_MAX_ID_BYTES,
        )
        || parts.input_digests.is_empty()
        || parts.input_digests.len() > SWARM_SCHEDULER_MAX_INPUT_DIGESTS
        || parts
            .input_digests
            .iter()
            .any(|digest| !swarm_scheduler_input_digest_is_safe(digest))
        || parts.feature_flags.len() > SWARM_SCHEDULER_MAX_FEATURE_FLAGS
        || parts
            .feature_flags
            .iter()
            .any(|feature| !swarm_scheduler_field_is_safe(feature, SWARM_SCHEDULER_MAX_FIELD_BYTES))
    {
        return Err(ValidationProofCoalescerError::contract(
            swarm_scheduler_error_codes::ERR_VSS_MALFORMED_INPUT,
            "validation swarm scheduler builder input is malformed",
        ));
    }
    Ok(())
}

fn swarm_scheduler_digest_from_command(
    command_digest: &CommandDigest,
) -> Result<ValidationSwarmSchedulerDigestRef, ValidationProofCoalescerError> {
    let digest = ValidationSwarmSchedulerDigestRef {
        algorithm: command_digest.algorithm.clone(),
        hex: command_digest.hex.clone(),
        canonical_material: command_digest.canonical_material.clone(),
    };
    if !digest.verifies() {
        return Err(ValidationProofCoalescerError::contract(
            swarm_scheduler_error_codes::ERR_VSS_COMMAND_DIGEST_MISMATCH,
            "validation swarm scheduler command digest does not verify",
        ));
    }
    Ok(digest)
}

fn swarm_scheduler_digest_from_work_key(
    work_key: &ValidationProofWorkKey,
) -> ValidationSwarmSchedulerDigestRef {
    ValidationSwarmSchedulerDigestRef {
        algorithm: work_key.algorithm.clone(),
        hex: work_key.hex.clone(),
        canonical_material: work_key.canonical_material.clone(),
    }
}

fn swarm_scheduler_input_id(
    bead_id: &str,
    agent_name: &str,
    proof_work_key_hex: &str,
    command_digest_hex: &str,
) -> String {
    format!(
        "vss-input-{}-{}-{}-{}",
        swarm_scheduler_id_component(bead_id),
        swarm_scheduler_id_component(agent_name),
        key_hex_prefix(proof_work_key_hex, 12),
        key_hex_prefix(command_digest_hex, 12)
    )
}

fn swarm_scheduler_id_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(64));
    for ch in value.trim().chars() {
        if out.len() >= 64 {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if matches!(ch, '-' | '_') {
            out.push(ch);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let component = out.trim_matches('-');
    if component.is_empty() {
        "unknown".to_string()
    } else {
        component.to_string()
    }
}

fn swarm_scheduler_input_digest_is_safe(digest: &InputDigest) -> bool {
    digest.is_valid()
        && swarm_scheduler_field_is_safe(&digest.path, SWARM_SCHEDULER_MAX_PATH_BYTES)
        && swarm_scheduler_field_is_safe(&digest.source, SWARM_SCHEDULER_MAX_FIELD_BYTES)
}

fn swarm_scheduler_field_is_safe(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes && !value.contains('\0')
}

fn build_swarm_scheduler_decision(
    policy: &ValidationSwarmSchedulerPolicy,
    input: &ValidationSwarmSchedulerInput,
    kind: ValidationSwarmSchedulerDecisionKind,
    decided_at: DateTime<Utc>,
) -> ValidationSwarmSchedulerDecision {
    let (reason_code, event_code, required_action, retryable, fail_closed, message) =
        swarm_scheduler_rule(kind);
    let freshness_expires_at = decided_at + swarm_scheduler_freshness_duration(policy);
    let starvation_risk = swarm_scheduler_starvation_risk(policy, input.queue_age_ms);
    let fairness_bucket = swarm_scheduler_fairness_bucket(kind, input.priority, starvation_risk);
    let retry_after_ms = matches!(
        kind,
        ValidationSwarmSchedulerDecisionKind::WaitForCapacity
            | ValidationSwarmSchedulerDecisionKind::RejectLowPriority
    )
    .then_some(policy.aging_step_ms.min(60_000));
    let fencing_token_digest = matches!(kind, ValidationSwarmSchedulerDecisionKind::StealStaleWork)
        .then(|| {
            hex::encode(Sha256::digest(
                format!(
                    "{}:{}:{}",
                    input.proof_work_key.hex, input.agent_name, input.queue_age_ms
                )
                .as_bytes(),
            ))
        });

    ValidationSwarmSchedulerDecision {
        schema_version: SWARM_SCHEDULER_DECISION_SCHEMA_VERSION.to_string(),
        decision_id: format!("vss-decision-{}-{}", input.input_id, kind.as_str()),
        input_ref: input.input_id.clone(),
        bead_id: input.bead_id.clone(),
        agent_name: input.agent_name.clone(),
        trace_id: format!("trace-{}-{}", input.input_id, kind.as_str()),
        decided_at,
        freshness_expires_at,
        decision: kind,
        reason_code: reason_code.to_string(),
        event_code: event_code.to_string(),
        required_action,
        fairness_bucket,
        starvation_risk,
        retryable,
        fail_closed,
        green_proof_eligible: false,
        operator_message: message.to_string(),
        diagnostics: ValidationSwarmSchedulerDiagnostics {
            proof_work_key_hex: input.proof_work_key.hex.clone(),
            command_digest_hex: input.command_digest.hex.clone(),
            capacity_snapshot_id: input.capacity_snapshot.snapshot_id.clone(),
            queue_age_ms: input.queue_age_ms,
            slots_total: input.capacity_snapshot.slots_total,
            slots_available: input.capacity_snapshot.slots_available,
            worker_slots: input.capacity_snapshot.slots_available,
            queue_depth: input.capacity_snapshot.queue_depth,
            coalescer_state: input.coalescer_state,
            flight_recorder_state: input.flight_recorder_state,
            proof_debt_class: input.proof_debt_class,
            retry_after_ms,
            fencing_token_digest,
            recorder_path: Some(format!(
                "artifacts/validation_broker/swarm_scheduler/{}.json",
                kind.as_str()
            )),
        },
    }
}

fn swarm_scheduler_rule(
    kind: ValidationSwarmSchedulerDecisionKind,
) -> (
    &'static str,
    &'static str,
    ValidationSwarmSchedulerRequiredAction,
    bool,
    bool,
    &'static str,
) {
    match kind {
        ValidationSwarmSchedulerDecisionKind::RunNow => (
            swarm_scheduler_reason_codes::RUN_READY,
            swarm_scheduler_event_codes::RUN_NOW,
            ValidationSwarmSchedulerRequiredAction::StartRchValidation,
            false,
            false,
            "Run one producer validation through RCH.",
        ),
        ValidationSwarmSchedulerDecisionKind::JoinExisting => (
            swarm_scheduler_reason_codes::JOIN_IDENTICAL,
            swarm_scheduler_event_codes::JOIN_EXISTING,
            ValidationSwarmSchedulerRequiredAction::JoinExistingProof,
            false,
            false,
            "Join the existing identical proof work key.",
        ),
        ValidationSwarmSchedulerDecisionKind::WaitForCapacity => (
            swarm_scheduler_reason_codes::WAIT_CAPACITY,
            swarm_scheduler_event_codes::WAIT_CAPACITY,
            ValidationSwarmSchedulerRequiredAction::WaitForCapacity,
            true,
            false,
            "Wait for worker capacity before starting another producer.",
        ),
        ValidationSwarmSchedulerDecisionKind::StealStaleWork => (
            swarm_scheduler_reason_codes::STEAL_STALE,
            swarm_scheduler_event_codes::STEAL_STALE,
            ValidationSwarmSchedulerRequiredAction::StealWithNewFence,
            true,
            false,
            "Fence the stale producer before retrying proof work.",
        ),
        ValidationSwarmSchedulerDecisionKind::RejectLowPriority => (
            swarm_scheduler_reason_codes::REJECT_LOW_PRIORITY,
            swarm_scheduler_event_codes::REJECT_LOW_PRIORITY,
            ValidationSwarmSchedulerRequiredAction::DeferLowPriority,
            true,
            false,
            "Defer low-priority proof work while higher-priority work is saturated.",
        ),
        ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker => (
            swarm_scheduler_reason_codes::SOURCE_ONLY_BLOCKER,
            swarm_scheduler_event_codes::SOURCE_ONLY_BLOCKER,
            ValidationSwarmSchedulerRequiredAction::RecordSourceOnlyBlocker,
            false,
            true,
            "Record source-only blocker evidence; do not count it as green proof.",
        ),
        ValidationSwarmSchedulerDecisionKind::FailClosedProduct => (
            swarm_scheduler_reason_codes::FAIL_PRODUCT,
            swarm_scheduler_event_codes::FAIL_PRODUCT,
            ValidationSwarmSchedulerRequiredAction::SurfaceProductFailure,
            false,
            true,
            "Surface product compile/test failure instead of retrying as worker infra.",
        ),
        ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact => (
            swarm_scheduler_reason_codes::FAIL_INVALID_ARTIFACT,
            swarm_scheduler_event_codes::FAIL_INVALID_ARTIFACT,
            ValidationSwarmSchedulerRequiredAction::RejectArtifact,
            false,
            true,
            "Reject malformed recorder/coalescer/debt artifacts.",
        ),
    }
}

fn swarm_scheduler_freshness_duration(policy: &ValidationSwarmSchedulerPolicy) -> chrono::Duration {
    chrono::Duration::milliseconds(i64::try_from(policy.aging_step_ms).unwrap_or(i64::MAX))
}

fn swarm_scheduler_starvation_risk(
    policy: &ValidationSwarmSchedulerPolicy,
    queue_age_ms: u64,
) -> ValidationSwarmSchedulerStarvationRisk {
    if queue_age_ms >= policy.starvation_after_ms {
        ValidationSwarmSchedulerStarvationRisk::Breached
    } else if queue_age_ms >= policy.aging_step_ms.saturating_mul(2) {
        ValidationSwarmSchedulerStarvationRisk::Elevated
    } else if queue_age_ms >= policy.aging_step_ms {
        ValidationSwarmSchedulerStarvationRisk::Watch
    } else {
        ValidationSwarmSchedulerStarvationRisk::None
    }
}

fn swarm_scheduler_fairness_bucket(
    kind: ValidationSwarmSchedulerDecisionKind,
    priority: ValidationSwarmSchedulerPriority,
    starvation_risk: ValidationSwarmSchedulerStarvationRisk,
) -> ValidationSwarmSchedulerFairnessBucket {
    if matches!(
        kind,
        ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker
            | ValidationSwarmSchedulerDecisionKind::FailClosedProduct
            | ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact
    ) {
        return ValidationSwarmSchedulerFairnessBucket::Blocked;
    }
    if matches!(
        starvation_risk,
        ValidationSwarmSchedulerStarvationRisk::Watch
            | ValidationSwarmSchedulerStarvationRisk::Elevated
            | ValidationSwarmSchedulerStarvationRisk::Breached
    ) {
        return ValidationSwarmSchedulerFairnessBucket::Aging;
    }
    match priority {
        ValidationSwarmSchedulerPriority::P0 => ValidationSwarmSchedulerFairnessBucket::Emergency,
        ValidationSwarmSchedulerPriority::P1 => ValidationSwarmSchedulerFairnessBucket::High,
        ValidationSwarmSchedulerPriority::P2 => ValidationSwarmSchedulerFairnessBucket::Normal,
        ValidationSwarmSchedulerPriority::P3 | ValidationSwarmSchedulerPriority::P4 => {
            ValidationSwarmSchedulerFairnessBucket::Low
        }
    }
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
        let canonical_material = canonical_work_key_material(CanonicalWorkKeyMaterialParts {
            command_digest: &parts.command_digest,
            input_digests: &input_digests,
            git_commit: &parts.git_commit,
            dirty_worktree: parts.dirty_worktree,
            dirty_state_policy: parts.dirty_state_policy,
            feature_flags: &feature_flags,
            cargo_toolchain: &parts.cargo_toolchain,
            package: &parts.package,
            test_target: &parts.test_target,
            environment_policy_id: &parts.environment_policy_id,
            target_dir_policy_id: &parts.target_dir_policy_id,
        });
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCoalescerTelemetryEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub proof_work_key: String,
    pub proof_cache_key: String,
    pub lease_id: String,
    pub lease_state: String,
    pub decision: String,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
    pub producer_agent: String,
    pub waiter_agent: String,
    pub bead_id: String,
    pub receipt_path: String,
    pub cache_key: String,
    pub fencing_token: String,
    pub target_dir_policy_id: String,
    pub dirty_state_policy: String,
    pub fail_closed: bool,
}

impl ValidationProofCoalescerTelemetryEvent {
    #[must_use]
    pub fn from_decision(
        decision: &ValidationProofCoalescerDecision,
        receipt_path: Option<&str>,
    ) -> Self {
        let lease_ref = decision.lease_ref.as_ref();
        let producer_agent = lease_ref
            .map(|lease| lease.owner_agent.as_str())
            .unwrap_or(decision.agent_name.as_str());
        let waiter_agent = if matches!(
            decision.decision,
            ValidationProofCoalescerDecisionKind::JoinExistingProof
                | ValidationProofCoalescerDecisionKind::WaitForReceipt
                | ValidationProofCoalescerDecisionKind::RetryAfterStaleLease
                | ValidationProofCoalescerDecisionKind::RepairState
        ) {
            decision.agent_name.as_str()
        } else {
            "none"
        };

        Self {
            schema_version: TELEMETRY_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: decision.trace_id.clone(),
            proof_work_key: decision.proof_work_key.hex.clone(),
            proof_cache_key: decision.proof_work_key.proof_cache_key.hex.clone(),
            lease_id: lease_ref
                .map(|lease| lease.lease_id.clone())
                .unwrap_or_else(|| "no-lease".to_string()),
            lease_state: lease_ref
                .map(|lease| lease.state.as_str().to_string())
                .unwrap_or_else(|| "no-lease".to_string()),
            decision: decision.decision.as_str().to_string(),
            reason_code: decision.reason_code.clone(),
            event_code: decision.diagnostics.event_code.clone(),
            required_action: decision.required_action.as_str().to_string(),
            producer_agent: producer_agent.to_string(),
            waiter_agent: waiter_agent.to_string(),
            bead_id: decision.bead_id.clone(),
            receipt_path: receipt_path.unwrap_or("none").to_string(),
            cache_key: decision.proof_work_key.proof_cache_key.hex.clone(),
            fencing_token: lease_ref
                .map(|lease| lease.fencing_token.clone())
                .unwrap_or_else(|| "no-fence".to_string()),
            target_dir_policy_id: decision.proof_work_key.target_dir_policy_id.clone(),
            dirty_state_policy: decision
                .proof_work_key
                .dirty_state_policy
                .as_str()
                .to_string(),
            fail_closed: decision.diagnostics.fail_closed,
        }
    }

    #[must_use]
    pub fn from_completed_lease(lease: &ValidationProofCoalescerLease) -> Self {
        let receipt_path = lease
            .receipt_ref
            .as_ref()
            .map(|receipt| receipt.path.as_str())
            .unwrap_or("none");
        Self {
            schema_version: TELEMETRY_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: lease.diagnostics.trace_id.clone(),
            proof_work_key: lease.proof_work_key.hex.clone(),
            proof_cache_key: lease.proof_cache_key.hex.clone(),
            lease_id: lease.lease_id.clone(),
            lease_state: lease.state.as_str().to_string(),
            decision: lease.state.as_str().to_string(),
            reason_code: lease.diagnostics.reason_code.clone(),
            event_code: lease.diagnostics.event_code.clone(),
            required_action: ValidationProofCoalescerRequiredAction::WaitForReceipt
                .as_str()
                .to_string(),
            producer_agent: lease.owner_agent.clone(),
            waiter_agent: lease
                .diagnostics
                .waiter_agent
                .clone()
                .unwrap_or_else(|| "none".to_string()),
            bead_id: lease.owner_bead_id.clone(),
            receipt_path: receipt_path.to_string(),
            cache_key: lease.proof_cache_key.hex.clone(),
            fencing_token: lease.fencing_token.clone(),
            target_dir_policy_id: lease.target_dir_policy_id.clone(),
            dirty_state_policy: lease.proof_work_key.dirty_state_policy.as_str().to_string(),
            fail_closed: lease.diagnostics.fail_closed,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofStaleProducerEvidence {
    pub recorder_attempt_id: String,
    pub recorder_path: String,
    pub producer_agent: String,
    pub producer_bead_id: String,
    pub lease_id: String,
    pub fencing_token: String,
    pub last_heartbeat_at: DateTime<Utc>,
    pub last_progress_at: DateTime<Utc>,
    pub progress_stale_observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StealStaleLeaseRequest {
    pub proof_work_key: ValidationProofWorkKey,
    pub stealer_agent: String,
    pub stealer_bead_id: String,
    pub trace_id: String,
    pub new_fencing_token: String,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub timeout_budget_seconds: u64,
    pub stale_progress_evidence: ValidationProofStaleProducerEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofWorkStealAssessment {
    pub previous_lease_ref: ValidationProofCoalescerLeaseRef,
    pub recorder_attempt_id: String,
    pub recorder_path: String,
    pub lease_expired: bool,
    pub evidence_matches_lease: bool,
    pub heartbeat_age_seconds: u64,
    pub heartbeat_stale: bool,
    pub progress_age_seconds: u64,
    pub progress_stale: bool,
    pub timeout_budget_seconds: u64,
    pub timeout_budget_sufficient: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationProofWorkStealOutcome {
    pub lease: Option<ValidationProofCoalescerLease>,
    pub lease_path: PathBuf,
    pub decision: ValidationProofCoalescerDecision,
    pub assessment: ValidationProofWorkStealAssessment,
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
        let lock_path = path.clone();
        with_validation_proof_coalescer_persist_lock(&lock_path, || {
            match self.read_lease(&request.proof_work_key) {
                Ok(None) => self.create_new_lease(request, path, relative_path),
                Ok(Some(lease)) => self.join_or_wait(request, lease, path, relative_path),
                Err(error) => Ok(repair_state_outcome(request, path, relative_path, &error)),
            }
        })
    }

    pub fn complete_lease(
        &self,
        request: CompleteLeaseRequest,
    ) -> Result<ValidationProofCoalescerLease, ValidationProofCoalescerError> {
        let path = self.lease_path(&request.proof_work_key);
        let lock_path = path.clone();
        with_validation_proof_coalescer_persist_lock(&lock_path, || {
            self.complete_lease_synchronized(request, &path)
        })
    }

    fn complete_lease_synchronized(
        &self,
        request: CompleteLeaseRequest,
        path: &Path,
    ) -> Result<ValidationProofCoalescerLease, ValidationProofCoalescerError> {
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
            path,
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
        let lock_path = path.clone();
        with_validation_proof_coalescer_persist_lock(&lock_path, || {
            self.fence_stale_lease_synchronized(request, path, relative_path)
        })
    }

    fn fence_stale_lease_synchronized(
        &self,
        request: FenceStaleLeaseRequest,
        path: PathBuf,
        relative_path: String,
    ) -> Result<ValidationProofCoalescerOutcome, ValidationProofCoalescerError> {
        let Some(mut lease) = self.read_lease(&request.proof_work_key)? else {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_MALFORMED_LEASE,
                "cannot fence missing validation proof lease",
            ));
        };
        if matches!(lease.state, ValidationProofLeaseState::Completed)
            || lease.receipt_ref.is_some()
        {
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
                    decided_at: request.fenced_at,
                }),
                lease: Some(lease),
                lease_path: path.to_path_buf(),
            });
        }
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
                bead_id: request.owner_bead_id.clone(),
                agent_name: request.owner_agent.clone(),
                trace_id: request.trace_id.clone(),
                decided_at: request.fenced_at,
            }),
            lease: Some(lease),
            lease_path: path.to_path_buf(),
        })
    }

    pub fn steal_stale_lease(
        &self,
        policy: &ValidationProofWorkStealPolicy,
        request: StealStaleLeaseRequest,
    ) -> Result<ValidationProofWorkStealOutcome, ValidationProofCoalescerError> {
        validate_work_steal_policy(policy)?;
        validate_work_steal_request(&request)?;

        let path = self.lease_path(&request.proof_work_key);

        // Wrap the entire read-assess-write sequence with advisory file locking
        // to prevent TOCTOU race conditions between concurrent steal attempts
        with_validation_proof_coalescer_persist_lock(&path, || {
            self.steal_stale_lease_synchronized(policy, &request, &path)
        })
    }

    fn steal_stale_lease_synchronized(
        &self,
        policy: &ValidationProofWorkStealPolicy,
        request: &StealStaleLeaseRequest,
        path: &Path,
    ) -> Result<ValidationProofWorkStealOutcome, ValidationProofCoalescerError> {
        let relative_path = self.relative_lease_path(&request.proof_work_key);
        let Some(mut lease) = self.read_lease(&request.proof_work_key)? else {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_MALFORMED_LEASE,
                "cannot steal missing validation proof lease",
            ));
        };
        if !same_work_key(&lease.proof_work_key, &request.proof_work_key) {
            return Err(ValidationProofCoalescerError::contract(
                error_codes::ERR_VPCO_BAD_WORK_KEY,
                "work-steal request work key does not match stored lease",
            ));
        }

        let assessment = assess_work_steal(&lease, &relative_path, policy, request)?;
        if matches!(lease.state, ValidationProofLeaseState::Completed) {
            return Ok(work_steal_outcome(WorkStealOutcomeInput {
                lease: Some(lease.clone()),
                lease_path: path.to_path_buf(),
                assessment,
                kind: ValidationProofCoalescerDecisionKind::WaitForReceipt,
                reason_code: reason_codes::WAIT_COMPLETION,
                required_action: ValidationProofCoalescerRequiredAction::WaitForReceipt,
                event_code: event_codes::WAIT_FOR_RECEIPT,
                fail_closed: false,
                message: "completed lease is ready for proof-cache receipt handoff",
                work_key: lease.proof_work_key.clone(),
                lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                    &lease,
                    relative_path,
                )),
                bead_id: request.stealer_bead_id.clone(),
                agent_name: request.stealer_agent.clone(),
                trace_id: request.trace_id.clone(),
                decided_at: request.observed_at,
            }));
        }

        if !lease.state.is_active() || !assessment.evidence_matches_lease {
            return Ok(work_steal_outcome(WorkStealOutcomeInput {
                lease: Some(lease.clone()),
                lease_path: path.to_path_buf(),
                assessment,
                kind: ValidationProofCoalescerDecisionKind::RepairState,
                reason_code: reason_codes::INSUFFICIENT_STALE_EVIDENCE,
                required_action: ValidationProofCoalescerRequiredAction::FailClosed,
                event_code: event_codes::CORRUPTED_STATE_REPAIR,
                fail_closed: true,
                message: "work-steal stale-progress evidence does not match an active lease",
                work_key: request.proof_work_key.clone(),
                lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                    &lease,
                    relative_path,
                )),
                bead_id: request.stealer_bead_id.clone(),
                agent_name: request.stealer_agent.clone(),
                trace_id: request.trace_id.clone(),
                decided_at: request.observed_at,
            }));
        }

        if !assessment.lease_expired || !assessment.heartbeat_stale || !assessment.progress_stale {
            return Ok(work_steal_outcome(WorkStealOutcomeInput {
                lease: Some(lease.clone()),
                lease_path: path.to_path_buf(),
                assessment,
                kind: ValidationProofCoalescerDecisionKind::JoinExistingProof,
                reason_code: reason_codes::WAIT_FRESH_PRODUCER,
                required_action: ValidationProofCoalescerRequiredAction::JoinExistingLease,
                event_code: event_codes::WAIT_FOR_RECEIPT,
                fail_closed: false,
                message: "active validation producer still has fresh lease, heartbeat, or progress evidence",
                work_key: request.proof_work_key.clone(),
                lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                    &lease,
                    relative_path,
                )),
                bead_id: request.stealer_bead_id.clone(),
                agent_name: request.stealer_agent.clone(),
                trace_id: request.trace_id.clone(),
                decided_at: request.observed_at,
            }));
        }

        if !assessment.timeout_budget_sufficient {
            return Ok(work_steal_outcome(WorkStealOutcomeInput {
                lease: Some(lease.clone()),
                lease_path: path.to_path_buf(),
                assessment,
                kind: ValidationProofCoalescerDecisionKind::RejectCapacity,
                reason_code: reason_codes::REJECT_CAPACITY,
                required_action: ValidationProofCoalescerRequiredAction::FailClosed,
                event_code: event_codes::CAPACITY_REJECTED,
                fail_closed: true,
                message: "stale validation lease cannot be stolen because retry timeout budget is below policy minimum",
                work_key: request.proof_work_key.clone(),
                lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                    &lease,
                    relative_path,
                )),
                bead_id: request.stealer_bead_id.clone(),
                agent_name: request.stealer_agent.clone(),
                trace_id: request.trace_id.clone(),
                decided_at: request.observed_at,
            }));
        }

        let previous_owner = lease.owner_agent.clone();
        let previous_bead = lease.owner_bead_id.clone();
        lease.state = ValidationProofLeaseState::Running;
        lease.owner_agent = request.stealer_agent.clone();
        lease.owner_bead_id = request.stealer_bead_id.clone();
        lease.fencing_token = request.new_fencing_token.clone();
        lease.updated_at = request.observed_at;
        lease.expires_at = request.expires_at;
        lease.waiter_agents.clear();
        lease.receipt_ref = None;
        lease.diagnostics = ValidationProofCoalescerDiagnostics {
            trace_id: request.trace_id.clone(),
            event_code: event_codes::STALE_LEASE_FENCED.to_string(),
            reason_code: reason_codes::RETRY_STALE.to_string(),
            producer_agent: request.stealer_agent.clone(),
            waiter_agent: None,
            message: format!(
                "stale producer {previous_owner}/{previous_bead} fenced by {} using recorder attempt {}",
                request.stealer_agent, request.stale_progress_evidence.recorder_attempt_id
            ),
            fail_closed: false,
        };
        validate_lease_metadata(&lease)?;
        let bytes = serde_json::to_vec_pretty(&lease).map_err(|source| {
            ValidationProofCoalescerError::Json {
                path: path.display().to_string(),
                source,
            }
        })?;
        write_bytes_replace(path, &bytes)?;

        Ok(work_steal_outcome(WorkStealOutcomeInput {
            lease: Some(lease.clone()),
            lease_path: path.to_path_buf(),
            assessment,
            kind: ValidationProofCoalescerDecisionKind::RetryAfterStaleLease,
            reason_code: reason_codes::RETRY_STALE,
            required_action: ValidationProofCoalescerRequiredAction::RetryWithNewFence,
            event_code: event_codes::STALE_LEASE_FENCED,
            fail_closed: false,
            message: "stale validation proof producer fenced and stolen with a fresh token",
            work_key: lease.proof_work_key.clone(),
            lease_ref: Some(ValidationProofCoalescerLeaseRef::from_lease(
                &lease,
                relative_path,
            )),
            bead_id: request.stealer_bead_id.clone(),
            agent_name: request.stealer_agent.clone(),
            trace_id: request.trace_id.clone(),
            decided_at: request.observed_at,
        }))
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
                lease_path: path.to_path_buf(),
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
                lease_path: path.to_path_buf(),
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
                lease_path: path.to_path_buf(),
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
                lease_path: path.to_path_buf(),
            });
        }

        match self.read_lease(&request.proof_work_key)? {
            Some(current) if validation_proof_leases_differ(&current, &lease) => {
                return self.join_or_wait(request, current, path, relative_path);
            }
            Some(_) => {}
            None => {
                return Err(ValidationProofCoalescerError::contract(
                    error_codes::ERR_VPCO_MALFORMED_LEASE,
                    "cannot join missing validation proof lease",
                ));
            }
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
            lease_path: path.to_path_buf(),
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

struct WorkStealOutcomeInput {
    lease: Option<ValidationProofCoalescerLease>,
    lease_path: PathBuf,
    assessment: ValidationProofWorkStealAssessment,
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

fn work_steal_outcome(input: WorkStealOutcomeInput) -> ValidationProofWorkStealOutcome {
    ValidationProofWorkStealOutcome {
        lease: input.lease,
        lease_path: input.lease_path,
        assessment: input.assessment,
        decision: coalescer_decision(DecisionInput {
            kind: input.kind,
            reason_code: input.reason_code,
            required_action: input.required_action,
            event_code: input.event_code,
            fail_closed: input.fail_closed,
            message: input.message,
            work_key: input.work_key,
            lease_ref: input.lease_ref,
            bead_id: input.bead_id,
            agent_name: input.agent_name,
            trace_id: input.trace_id,
            decided_at: input.decided_at,
        }),
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

fn validate_work_steal_policy(
    policy: &ValidationProofWorkStealPolicy,
) -> Result<(), ValidationProofCoalescerError> {
    if !string_eq(&policy.schema_version, WORK_STEAL_POLICY_SCHEMA_VERSION)
        || policy.policy_id.trim().is_empty()
        || policy.min_heartbeat_stale_seconds == 0
        || policy.min_progress_stale_seconds == 0
        || policy.min_timeout_budget_seconds == 0
    {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_POLICY,
            "validation proof work-steal policy is malformed",
        ));
    }
    Ok(())
}

fn validate_work_steal_request(
    request: &StealStaleLeaseRequest,
) -> Result<(), ValidationProofCoalescerError> {
    let evidence = &request.stale_progress_evidence;
    if request.stealer_agent.trim().is_empty()
        || request.stealer_bead_id.trim().is_empty()
        || request.trace_id.trim().is_empty()
        || request.new_fencing_token.trim().is_empty()
        || request.timeout_budget_seconds == 0
        || request.expires_at <= request.observed_at
        || evidence.recorder_attempt_id.trim().is_empty()
        || evidence.recorder_path.trim().is_empty()
        || evidence.producer_agent.trim().is_empty()
        || evidence.producer_bead_id.trim().is_empty()
        || evidence.lease_id.trim().is_empty()
        || evidence.fencing_token.trim().is_empty()
        || evidence.progress_stale_observed_at < evidence.last_progress_at
        || request.observed_at < evidence.last_heartbeat_at
        || request.observed_at < evidence.progress_stale_observed_at
        || string_eq(&request.new_fencing_token, &evidence.fencing_token)
    {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_DECISION,
            "validation proof work-steal request is malformed",
        ));
    }
    Ok(())
}

fn assess_work_steal(
    lease: &ValidationProofCoalescerLease,
    relative_path: &str,
    policy: &ValidationProofWorkStealPolicy,
    request: &StealStaleLeaseRequest,
) -> Result<ValidationProofWorkStealAssessment, ValidationProofCoalescerError> {
    let evidence = &request.stale_progress_evidence;
    let heartbeat_age_seconds = seconds_between(evidence.last_heartbeat_at, request.observed_at)?;
    let progress_age_seconds = seconds_between(
        evidence.last_progress_at,
        evidence.progress_stale_observed_at,
    )?;
    Ok(ValidationProofWorkStealAssessment {
        previous_lease_ref: ValidationProofCoalescerLeaseRef::from_lease(lease, relative_path),
        recorder_attempt_id: evidence.recorder_attempt_id.clone(),
        recorder_path: evidence.recorder_path.clone(),
        lease_expired: lease.is_expired_at(request.observed_at),
        evidence_matches_lease: string_eq(&evidence.producer_agent, &lease.owner_agent)
            && string_eq(&evidence.producer_bead_id, &lease.owner_bead_id)
            && string_eq(&evidence.lease_id, &lease.lease_id)
            && string_eq(&evidence.fencing_token, &lease.fencing_token),
        heartbeat_age_seconds,
        heartbeat_stale: heartbeat_age_seconds >= policy.min_heartbeat_stale_seconds,
        progress_age_seconds,
        progress_stale: progress_age_seconds >= policy.min_progress_stale_seconds,
        timeout_budget_seconds: request.timeout_budget_seconds,
        timeout_budget_sufficient: request.timeout_budget_seconds
            >= policy.min_timeout_budget_seconds,
    })
}

fn seconds_between(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<u64, ValidationProofCoalescerError> {
    if end < start {
        return Err(ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_DECISION,
            "validation proof timestamp order is malformed",
        ));
    }
    u64::try_from(end.signed_duration_since(start).num_seconds()).map_err(|_| {
        ValidationProofCoalescerError::contract(
            error_codes::ERR_VPCO_MALFORMED_DECISION,
            "validation proof timestamp range is malformed",
        )
    })
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
        lease_path: path.to_path_buf(),
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

struct CanonicalWorkKeyMaterialParts<'a> {
    command_digest: &'a CommandDigest,
    input_digests: &'a [InputDigest],
    git_commit: &'a str,
    dirty_worktree: bool,
    dirty_state_policy: DirtyStatePolicy,
    feature_flags: &'a [String],
    cargo_toolchain: &'a str,
    package: &'a str,
    test_target: &'a str,
    environment_policy_id: &'a str,
    target_dir_policy_id: &'a str,
}

fn canonical_work_key_material(parts: CanonicalWorkKeyMaterialParts<'_>) -> String {
    let input_material = parts
        .input_digests
        .iter()
        .map(|digest| format!("{}:{}:{}", digest.path, digest.algorithm, digest.hex))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "schema={WORK_KEY_SCHEMA_VERSION}\0command_digest={}:{}\0inputs={}\0git_commit={}\0dirty={}\0dirty_policy={}\0features={}\0toolchain={}\0package={}\0test_target={}\0env_policy={}\0target_policy={}",
        parts.command_digest.algorithm,
        parts.command_digest.hex,
        input_material,
        parts.git_commit,
        parts.dirty_worktree,
        parts.dirty_state_policy.as_str(),
        parts.feature_flags.join(","),
        parts.cargo_toolchain,
        parts.package,
        parts.test_target,
        parts.environment_policy_id,
        parts.target_dir_policy_id
    )
}

fn same_work_key(left: &ValidationProofWorkKey, right: &ValidationProofWorkKey) -> bool {
    constant_time::ct_eq(&left.hex, &right.hex)
        && constant_time::ct_eq(&left.canonical_material, &right.canonical_material)
}

fn validation_proof_leases_differ(
    left: &ValidationProofCoalescerLease,
    right: &ValidationProofCoalescerLease,
) -> bool {
    PartialEq::ne(left, right)
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

    fn scheduler_digest(material: &str) -> ValidationSwarmSchedulerDigestRef {
        ValidationSwarmSchedulerDigestRef::sha256_material(material)
    }

    fn scheduler_capacity(
        slots_available: u16,
        queue_depth: u16,
        stale_active_builds: u16,
        disk_pressure_workers: u16,
    ) -> ValidationSwarmSchedulerCapacitySnapshot {
        ValidationSwarmSchedulerCapacitySnapshot {
            snapshot_id: format!(
                "vss-capacity-{slots_available}-{queue_depth}-{stale_active_builds}-{disk_pressure_workers}"
            ),
            captured_at: ts(3),
            workers_total: 4,
            workers_healthy: 3,
            slots_total: 16,
            slots_available,
            queue_depth,
            stale_active_builds,
            disk_pressure_workers,
        }
    }

    fn scheduler_policy() -> ValidationSwarmSchedulerPolicy {
        ValidationSwarmSchedulerPolicy::default_policy(
            "validation-swarm-scheduler/policy/unit-test/v1",
        )
    }

    fn scheduler_input(seed: &str) -> ValidationSwarmSchedulerInput {
        ValidationSwarmSchedulerInput {
            schema_version: SWARM_SCHEDULER_INPUT_SCHEMA_VERSION.to_string(),
            input_id: format!("vss-input-{seed}"),
            bead_id: "bd-7d9di".to_string(),
            agent_name: "RedGlen".to_string(),
            proof_work_key: scheduler_digest(&format!("proof-work-key/{seed}")),
            command_digest: scheduler_digest(&format!("cargo test swarm_scheduler/{seed}")),
            dirty_state_policy: DirtyStatePolicy::CleanRequired,
            target_dir_class: ValidationSwarmSchedulerTargetDirClass::OffRepo,
            capacity_snapshot: scheduler_capacity(4, 0, 0, 0),
            coalescer_state: ValidationSwarmSchedulerCoalescerState::None,
            flight_recorder_state: ValidationSwarmSchedulerFlightRecorderState::None,
            proof_debt_class: ValidationSwarmSchedulerProofDebtClass::None,
            queue_age_ms: 0,
            priority: ValidationSwarmSchedulerPriority::P1,
            timeout_budget_ms: 900_000,
            source_only_allowed: false,
            product_failure: false,
            worker_infra_retryable: false,
            artifact_valid: true,
        }
    }

    fn scheduler_decision(
        policy: &ValidationSwarmSchedulerPolicy,
        input: &ValidationSwarmSchedulerInput,
    ) -> ValidationSwarmSchedulerDecision {
        decide_validation_swarm_schedule(policy, input, ts(20)).expect("scheduler decision")
    }

    fn replacement_marker() -> String {
        ["new", "lease", "marker"].join("-")
    }

    #[test]
    fn swarm_scheduler_run_now_is_deterministic() {
        let policy = scheduler_policy();
        let input = scheduler_input("run-now");

        let first = scheduler_decision(&policy, &input);
        let second = scheduler_decision(&policy, &input);

        assert_eq!(first, second);
        assert_eq!(first.decision, ValidationSwarmSchedulerDecisionKind::RunNow);
        assert_eq!(first.reason_code, swarm_scheduler_reason_codes::RUN_READY);
        assert_eq!(first.event_code, swarm_scheduler_event_codes::RUN_NOW);
        assert_eq!(
            first.required_action,
            ValidationSwarmSchedulerRequiredAction::StartRchValidation
        );
        assert_eq!(
            first.fairness_bucket,
            ValidationSwarmSchedulerFairnessBucket::High
        );
        assert_eq!(
            first.starvation_risk,
            ValidationSwarmSchedulerStarvationRisk::None
        );
        assert!(!first.green_proof_eligible);
        assert!(!first.retryable);
        assert!(!first.fail_closed);
    }

    #[test]
    fn swarm_scheduler_joins_existing_equivalent_work() {
        let policy = scheduler_policy();
        let mut input = scheduler_input("join-existing");
        input.coalescer_state = ValidationSwarmSchedulerCoalescerState::Running;

        let decision = scheduler_decision(&policy, &input);

        assert_eq!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::JoinExisting
        );
        assert_eq!(
            decision.required_action,
            ValidationSwarmSchedulerRequiredAction::JoinExistingProof
        );
        assert_eq!(
            decision.diagnostics.coalescer_state,
            ValidationSwarmSchedulerCoalescerState::Running
        );
        assert!(!decision.green_proof_eligible);
    }

    #[test]
    fn swarm_scheduler_joins_completed_proof_cache_hit() {
        let policy = scheduler_policy();
        let mut input = scheduler_input("proof-cache-hit");
        input.coalescer_state = ValidationSwarmSchedulerCoalescerState::Completed;

        let decision = scheduler_decision(&policy, &input);

        assert_eq!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::JoinExisting
        );
        assert_eq!(
            decision.reason_code,
            swarm_scheduler_reason_codes::JOIN_IDENTICAL
        );
        assert_eq!(
            decision.required_action,
            ValidationSwarmSchedulerRequiredAction::JoinExistingProof
        );
    }

    #[test]
    fn swarm_scheduler_waits_for_capacity_without_green_proof() {
        let policy = scheduler_policy();
        let mut input = scheduler_input("wait-capacity");
        input.priority = ValidationSwarmSchedulerPriority::P2;
        input.capacity_snapshot = scheduler_capacity(0, policy.queue_high_watermark + 8, 0, 0);
        input.queue_age_ms = policy.aging_step_ms;

        let decision = scheduler_decision(&policy, &input);

        assert_eq!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::WaitForCapacity
        );
        assert_eq!(
            decision.required_action,
            ValidationSwarmSchedulerRequiredAction::WaitForCapacity
        );
        assert_eq!(
            decision.fairness_bucket,
            ValidationSwarmSchedulerFairnessBucket::Aging
        );
        assert_eq!(
            decision.starvation_risk,
            ValidationSwarmSchedulerStarvationRisk::Watch
        );
        assert_eq!(decision.diagnostics.retry_after_ms, Some(60_000));
        assert!(decision.retryable);
        assert!(!decision.green_proof_eligible);
    }

    #[test]
    fn swarm_scheduler_rejects_low_priority_at_high_watermark() {
        let policy = scheduler_policy();
        let mut input = scheduler_input("reject-low-priority");
        input.priority = ValidationSwarmSchedulerPriority::P4;
        input.capacity_snapshot = scheduler_capacity(4, policy.queue_high_watermark, 0, 0);

        let decision = scheduler_decision(&policy, &input);

        assert_eq!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::RejectLowPriority
        );
        assert_eq!(
            decision.required_action,
            ValidationSwarmSchedulerRequiredAction::DeferLowPriority
        );
        assert_eq!(
            decision.fairness_bucket,
            ValidationSwarmSchedulerFairnessBucket::Low
        );
        assert_eq!(
            decision.reason_code,
            swarm_scheduler_reason_codes::REJECT_LOW_PRIORITY
        );
        assert_eq!(decision.diagnostics.retry_after_ms, Some(60_000));
        assert!(!decision.green_proof_eligible);
    }

    #[test]
    fn swarm_scheduler_ages_low_priority_to_capacity_wait() {
        let policy = scheduler_policy();
        let mut input = scheduler_input("aged-low-priority");
        input.priority = ValidationSwarmSchedulerPriority::P4;
        input.capacity_snapshot = scheduler_capacity(4, policy.queue_high_watermark, 0, 0);
        input.queue_age_ms = policy.aging_step_ms.saturating_mul(2);

        let decision = scheduler_decision(&policy, &input);

        assert_eq!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::WaitForCapacity
        );
        assert_eq!(
            decision.fairness_bucket,
            ValidationSwarmSchedulerFairnessBucket::Aging
        );
        assert_eq!(
            decision.starvation_risk,
            ValidationSwarmSchedulerStarvationRisk::Elevated
        );
        assert!(decision.retryable);
    }

    #[test]
    fn swarm_scheduler_steals_stale_work_with_fence_digest() {
        let policy = scheduler_policy();
        let mut input = scheduler_input("steal-stale");
        input.coalescer_state = ValidationSwarmSchedulerCoalescerState::Stale;

        let decision = scheduler_decision(&policy, &input);

        assert_eq!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::StealStaleWork
        );
        assert_eq!(
            decision.required_action,
            ValidationSwarmSchedulerRequiredAction::StealWithNewFence
        );
        assert_eq!(
            decision.reason_code,
            swarm_scheduler_reason_codes::STEAL_STALE
        );
        assert_eq!(
            decision
                .diagnostics
                .fencing_token_digest
                .as_deref()
                .map(str::len),
            Some(64)
        );
        assert!(decision.retryable);
        assert!(!decision.green_proof_eligible);
    }

    #[test]
    fn swarm_scheduler_records_source_only_blocker_fail_closed() {
        let policy = scheduler_policy();
        let mut input = scheduler_input("source-only");
        input.source_only_allowed = true;
        input.proof_debt_class = ValidationSwarmSchedulerProofDebtClass::SourceOnly;
        input.queue_age_ms = policy.starvation_after_ms;

        let decision = scheduler_decision(&policy, &input);

        assert_eq!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::RecordSourceOnlyBlocker
        );
        assert_eq!(
            decision.required_action,
            ValidationSwarmSchedulerRequiredAction::RecordSourceOnlyBlocker
        );
        assert_eq!(
            decision.fairness_bucket,
            ValidationSwarmSchedulerFairnessBucket::Blocked
        );
        assert!(decision.fail_closed);
        assert!(!decision.retryable);
        assert!(!decision.green_proof_eligible);
    }

    #[test]
    fn swarm_scheduler_fails_closed_for_product_failure() {
        let policy = scheduler_policy();
        let mut input = scheduler_input("product-failure");
        input.product_failure = true;
        input.proof_debt_class = ValidationSwarmSchedulerProofDebtClass::ProductFailure;
        input.flight_recorder_state = ValidationSwarmSchedulerFlightRecorderState::ProductFailure;

        let decision = scheduler_decision(&policy, &input);

        assert_eq!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::FailClosedProduct
        );
        assert_eq!(
            decision.reason_code,
            swarm_scheduler_reason_codes::FAIL_PRODUCT
        );
        assert!(decision.fail_closed);
        assert!(!decision.retryable);
        assert!(!decision.green_proof_eligible);
    }

    #[test]
    fn swarm_scheduler_fails_closed_for_invalid_artifact() {
        let policy = scheduler_policy();
        let mut input = scheduler_input("invalid-artifact");
        input.artifact_valid = false;
        input.proof_debt_class = ValidationSwarmSchedulerProofDebtClass::InvalidArtifact;
        input.flight_recorder_state = ValidationSwarmSchedulerFlightRecorderState::InvalidArtifact;

        let decision = scheduler_decision(&policy, &input);

        assert_eq!(
            decision.decision,
            ValidationSwarmSchedulerDecisionKind::FailClosedInvalidArtifact
        );
        assert_eq!(
            decision.reason_code,
            swarm_scheduler_reason_codes::FAIL_INVALID_ARTIFACT
        );
        assert_eq!(
            decision.required_action,
            ValidationSwarmSchedulerRequiredAction::RejectArtifact
        );
        assert!(decision.fail_closed);
        assert!(!decision.green_proof_eligible);
    }

    #[test]
    fn swarm_scheduler_rejects_product_failure_as_worker_infra() {
        let policy = scheduler_policy();
        let mut input = scheduler_input("product-as-infra");
        input.product_failure = true;
        input.worker_infra_retryable = true;
        input.proof_debt_class = ValidationSwarmSchedulerProofDebtClass::ProductFailure;

        let err = decide_validation_swarm_schedule(&policy, &input, ts(20))
            .expect_err("product failure cannot be worker infra");

        assert_eq!(
            err.code(),
            swarm_scheduler_error_codes::ERR_VSS_PRODUCT_RETRIED_AS_INFRA
        );
    }

    #[test]
    fn swarm_scheduler_orders_by_effective_priority_freshness_and_stable_ties() {
        let policy = scheduler_policy();
        let mut p0 = scheduler_input("rank-p0");
        p0.priority = ValidationSwarmSchedulerPriority::P0;
        p0.timeout_budget_ms = 60_000;

        let mut aged_p4 = scheduler_input("rank-aged-p4");
        aged_p4.priority = ValidationSwarmSchedulerPriority::P4;
        aged_p4.queue_age_ms = policy.aging_step_ms.saturating_mul(2);
        aged_p4.timeout_budget_ms = 120_000;

        let mut fresh_p2 = scheduler_input("rank-fresh-p2");
        fresh_p2.priority = ValidationSwarmSchedulerPriority::P2;
        fresh_p2.timeout_budget_ms = 120_000;

        let mut tie_left = scheduler_input("rank-tie-left");
        tie_left.priority = ValidationSwarmSchedulerPriority::P2;
        tie_left.timeout_budget_ms = 240_000;
        tie_left.bead_id = "bd-b".to_string();
        tie_left.agent_name = "OrangeAsh".to_string();

        let mut tie_right = scheduler_input("rank-tie-right");
        tie_right.priority = ValidationSwarmSchedulerPriority::P2;
        tie_right.timeout_budget_ms = 240_000;
        tie_right.proof_work_key = tie_left.proof_work_key.clone();
        tie_right.bead_id = "bd-a".to_string();
        tie_right.agent_name = "BlueStone".to_string();

        let inputs = vec![tie_left, fresh_p2, aged_p4, p0, tie_right];
        let ordered =
            order_validation_swarm_scheduler_inputs(&policy, &inputs).expect("ordered inputs");
        let ordered_ids = ordered
            .into_iter()
            .map(|input| input.input_id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            ordered_ids,
            vec![
                "vss-input-rank-p0",
                "vss-input-rank-aged-p4",
                "vss-input-rank-fresh-p2",
                "vss-input-rank-tie-right",
                "vss-input-rank-tie-left",
            ]
        );
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
    fn stale_join_snapshot_cannot_overwrite_completed_receipt() {
        let temp = TempDir::new().expect("tempdir");
        let store = ValidationProofCoalescerStore::new(temp.path());
        let request = create_request("stale-join", "PearlLeopard", ts(1));
        let path = store.lease_path(&request.proof_work_key);
        let relative_path = store.relative_lease_path(&request.proof_work_key);
        let stale_lease = store
            .create_or_join(request.clone())
            .expect("created")
            .lease
            .expect("lease");

        store
            .complete_lease(CompleteLeaseRequest {
                proof_work_key: request.proof_work_key.clone(),
                owner_agent: request.owner_agent.clone(),
                owner_bead_id: request.owner_bead_id.clone(),
                fencing_token: request.fencing_token.clone(),
                completed_at: ts(3),
                receipt_ref: receipt_ref("stale-join"),
            })
            .expect("completed");

        let waiter = create_request("stale-join", "LavenderElk", ts(4));
        let outcome = store
            .join_or_wait(waiter, stale_lease, path, relative_path)
            .expect("stale join snapshot handled");

        assert_eq!(
            outcome.decision.decision,
            ValidationProofCoalescerDecisionKind::WaitForReceipt
        );
        let final_lease = store
            .read_lease(&request.proof_work_key)
            .expect("read final")
            .expect("lease present");
        assert_eq!(final_lease.state, ValidationProofLeaseState::Completed);
        assert!(final_lease.receipt_ref.is_some());
        assert!(final_lease.waiter_agents.is_empty());
    }

    #[test]
    fn stale_fence_cannot_reopen_completed_receipt() {
        let temp = TempDir::new().expect("tempdir");
        let store = ValidationProofCoalescerStore::new(temp.path());
        let mut request = create_request("stale-fence", "PearlLeopard", ts(1));
        request.expires_at = ts(5);
        store.create_or_join(request.clone()).expect("created");
        store
            .complete_lease(CompleteLeaseRequest {
                proof_work_key: request.proof_work_key.clone(),
                owner_agent: request.owner_agent.clone(),
                owner_bead_id: request.owner_bead_id.clone(),
                fencing_token: request.fencing_token.clone(),
                completed_at: ts(3),
                receipt_ref: receipt_ref("stale-fence"),
            })
            .expect("completed");

        let fenced = store
            .fence_stale_lease(FenceStaleLeaseRequest {
                proof_work_key: request.proof_work_key.clone(),
                owner_agent: "LavenderElk".to_string(),
                owner_bead_id: "bd-y4coj".to_string(),
                trace_id: "trace-fence-completed".to_string(),
                fencing_token: replacement_marker(),
                fenced_at: ts(10),
                expires_at: ts(50),
            })
            .expect("completed lease is not reopened");

        assert_eq!(
            fenced.decision.decision,
            ValidationProofCoalescerDecisionKind::WaitForReceipt
        );
        let final_lease = store
            .read_lease(&request.proof_work_key)
            .expect("read final")
            .expect("lease present");
        assert_eq!(final_lease.state, ValidationProofLeaseState::Completed);
        assert_eq!(final_lease.owner_agent, "PearlLeopard");
        assert!(final_lease.receipt_ref.is_some());
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
