//! Validation broker queue, dedupe, and receipt persistence.
//!
//! This module implements the `bd-1khdi` validation broker contract for
//! cargo/RCH proof work. It keeps request admission deterministic, records the
//! exact command and input digests that define a validation attempt, and writes
//! final receipts through an atomic filesystem path.

use crate::security::constant_time;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub const REQUEST_SCHEMA_VERSION: &str = "franken-node/validation-broker/request/v1";
pub const QUEUE_SCHEMA_VERSION: &str = "franken-node/validation-broker/queue/v1";
pub const RECEIPT_SCHEMA_VERSION: &str = "franken-node/validation-broker/receipt/v1";
pub const STATUS_SCHEMA_VERSION: &str = "franken-node/validation-broker/status/v1";
pub const DEFAULT_MAX_QUEUE_DEPTH: usize = 1024;
const SHA256_HEX_LEN: usize = 64;

pub mod event_codes {
    pub const REQUEST_ACCEPTED: &str = "VB-001";
    pub const QUEUE_DEDUPLICATED: &str = "VB-002";
    pub const WORKER_OBSERVED: &str = "VB-003";
    pub const COMMAND_STARTED: &str = "VB-004";
    pub const COMMAND_COMPLETED: &str = "VB-005";
    pub const TIMEOUT_CLASSIFIED: &str = "VB-006";
    pub const SOURCE_ONLY_RECORDED: &str = "VB-007";
    pub const RECEIPT_EMITTED: &str = "VB-008";
    pub const DOCTOR_READINESS_EMITTED: &str = "VB-009";
    pub const CI_GATE_CONSUMED: &str = "VB-010";
}

pub mod error_codes {
    pub const ERR_VB_INVALID_SCHEMA_VERSION: &str = "ERR_VB_INVALID_SCHEMA_VERSION";
    pub const ERR_VB_MALFORMED_RECEIPT: &str = "ERR_VB_MALFORMED_RECEIPT";
    pub const ERR_VB_MISSING_COMMAND_DIGEST: &str = "ERR_VB_MISSING_COMMAND_DIGEST";
    pub const ERR_VB_STALE_RECEIPT: &str = "ERR_VB_STALE_RECEIPT";
    pub const ERR_VB_BEAD_MISMATCH: &str = "ERR_VB_BEAD_MISMATCH";
    pub const ERR_VB_INVALID_TIMEOUT_CLASS: &str = "ERR_VB_INVALID_TIMEOUT_CLASS";
    pub const ERR_VB_MISSING_ARTIFACT_PATH: &str = "ERR_VB_MISSING_ARTIFACT_PATH";
    pub const ERR_VB_UNDECLARED_SOURCE_ONLY: &str = "ERR_VB_UNDECLARED_SOURCE_ONLY";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationPriority {
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueState {
    Queued,
    Leased,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl QueueState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchMode {
    Remote,
    LocalFallback,
    NotUsed,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutClass {
    None,
    QueueWait,
    RchDispatch,
    SshCommand,
    CargoTestTimeout,
    ProcessIdle,
    ProcessWall,
    WorkerUnreachable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationErrorClass {
    None,
    CompileError,
    TestFailure,
    ClippyWarning,
    FormatFailure,
    TransportTimeout,
    WorkerInfra,
    EnvironmentContention,
    DiskPressure,
    SourceOnly,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceOnlyReason {
    CargoContention,
    RchUnavailable,
    SiblingDependencyBlocker,
    DiskPressure,
    ReservedSurface,
    NoCargoRequested,
    DocsOnly,
}

impl SourceOnlyReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CargoContention => "cargo_contention",
            Self::RchUnavailable => "rch_unavailable",
            Self::SiblingDependencyBlocker => "sibling_dependency_blocker",
            Self::DiskPressure => "disk_pressure",
            Self::ReservedSurface => "reserved_surface",
            Self::NoCargoRequested => "no_cargo_requested",
            Self::DocsOnly => "docs_only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationExitKind {
    Success,
    Failed,
    Timeout,
    SourceOnly,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatusKind {
    Unknown,
    Queued,
    Leased,
    Running,
    Reused,
    Failed,
    Passed,
    SourceOnly,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestRef {
    pub algorithm: String,
    pub hex: String,
}

impl DigestRef {
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        Self {
            algorithm: "sha256".to_string(),
            hex: hex::encode(Sha256::digest(bytes)),
        }
    }

    #[must_use]
    pub fn from_command_digest(digest: &CommandDigest) -> Self {
        Self {
            algorithm: digest.algorithm.clone(),
            hex: digest.hex.clone(),
        }
    }

    #[must_use]
    pub fn is_valid_sha256(&self) -> bool {
        self.algorithm == "sha256" && is_sha256_hex(&self.hex)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    pub program: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub environment_policy_id: String,
    pub target_dir_policy_id: String,
}

impl CommandSpec {
    #[must_use]
    pub fn canonical_material(&self) -> String {
        format!(
            "program={}\0argv={}\0cwd={}\0env_policy={}\0target_dir_policy={}",
            self.program,
            self.argv.join(" "),
            self.cwd,
            self.environment_policy_id,
            self.target_dir_policy_id
        )
    }

    #[must_use]
    pub fn digest(&self) -> CommandDigest {
        let material = self.canonical_material();
        CommandDigest {
            algorithm: "sha256".to_string(),
            hex: hex::encode(Sha256::digest(material.as_bytes())),
            canonical_material: material,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandDigest {
    pub algorithm: String,
    pub hex: String,
    pub canonical_material: String,
}

impl CommandDigest {
    #[must_use]
    pub fn verifies(&self) -> bool {
        if self.algorithm != "sha256" || !is_sha256_hex(&self.hex) {
            return false;
        }
        let expected = hex::encode(Sha256::digest(self.canonical_material.as_bytes()));
        constant_time::ct_eq(&expected, &self.hex)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputDigest {
    pub path: String,
    pub algorithm: String,
    pub hex: String,
    pub source: String,
}

impl InputDigest {
    #[must_use]
    pub fn new(path: impl Into<String>, bytes: &[u8], source: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            algorithm: "sha256".to_string(),
            hex: hex::encode(Sha256::digest(bytes)),
            source: source.into(),
        }
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.path.trim().is_empty() && self.algorithm == "sha256" && is_sha256_hex(&self.hex)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSet {
    pub git_commit: String,
    pub dirty_worktree: bool,
    pub changed_paths: Vec<String>,
    pub content_digests: Vec<InputDigest>,
    pub feature_flags: Vec<String>,
}

impl InputSet {
    #[must_use]
    pub fn canonical_material(&self) -> String {
        let mut changed_paths = self.changed_paths.clone();
        changed_paths.sort();
        changed_paths.dedup();

        let mut content_digests = self.content_digests.clone();
        content_digests.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then(left.algorithm.cmp(&right.algorithm))
                .then(left.hex.cmp(&right.hex))
        });

        let mut feature_flags = self.feature_flags.clone();
        feature_flags.sort();
        feature_flags.dedup();

        let digest_material = content_digests
            .iter()
            .map(|digest| format!("{}:{}:{}", digest.path, digest.algorithm, digest.hex))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "git_commit={}\0dirty={}\0changed={}\0digests={}\0features={}",
            self.git_commit,
            self.dirty_worktree,
            changed_paths.join(","),
            digest_material,
            feature_flags.join(",")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedupeKey {
    pub algorithm: String,
    pub hex: String,
    pub canonical_material: String,
}

impl DedupeKey {
    #[must_use]
    pub fn from_material(material: String) -> Self {
        Self {
            algorithm: "sha256".to_string(),
            hex: hex::encode(Sha256::digest(material.as_bytes())),
            canonical_material: material,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputPolicy {
    pub stdout_path: String,
    pub stderr_path: String,
    pub summary_path: String,
    pub receipt_path: String,
    pub retention: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackPolicy {
    pub source_only_allowed: bool,
    pub allowed_reasons: Vec<SourceOnlyReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationBrokerRequest {
    pub schema_version: String,
    pub request_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub requester_agent: String,
    pub created_at: DateTime<Utc>,
    pub priority: ValidationPriority,
    pub command: CommandSpec,
    pub inputs: InputSet,
    pub dedupe_key: DedupeKey,
    pub output_policy: OutputPolicy,
    pub fallback_policy: FallbackPolicy,
}

impl ValidationBrokerRequest {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        request_id: impl Into<String>,
        bead_id: impl Into<String>,
        thread_id: impl Into<String>,
        requester_agent: impl Into<String>,
        created_at: DateTime<Utc>,
        priority: ValidationPriority,
        command: CommandSpec,
        inputs: InputSet,
        output_policy: OutputPolicy,
        fallback_policy: FallbackPolicy,
    ) -> Self {
        let request_id = request_id.into();
        let bead_id = bead_id.into();
        let thread_id = thread_id.into();
        let requester_agent = requester_agent.into();
        let dedupe_key = Self::compute_dedupe_key(&bead_id, &thread_id, &command, &inputs);
        Self {
            schema_version: REQUEST_SCHEMA_VERSION.to_string(),
            request_id,
            bead_id,
            thread_id,
            requester_agent,
            created_at,
            priority,
            command,
            inputs,
            dedupe_key,
            output_policy,
            fallback_policy,
        }
    }

    #[must_use]
    pub fn compute_dedupe_key(
        bead_id: &str,
        thread_id: &str,
        command: &CommandSpec,
        inputs: &InputSet,
    ) -> DedupeKey {
        DedupeKey::from_material(format!(
            "schema={REQUEST_SCHEMA_VERSION}\0bead={bead_id}\0thread={thread_id}\0{}\0{}",
            command.canonical_material(),
            inputs.canonical_material()
        ))
    }

    #[must_use]
    pub fn recomputed_dedupe_key(&self) -> DedupeKey {
        Self::compute_dedupe_key(&self.bead_id, &self.thread_id, &self.command, &self.inputs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseState {
    pub holder_agent: Option<String>,
    pub leased_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub renew_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRequirements {
    pub require_rch_remote: bool,
    pub cargo_toolchain: String,
    pub feature_flags: Vec<String>,
    pub max_wall_time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCapabilityObservation {
    pub observation_id: String,
    pub worker_id: String,
    pub observed_at: DateTime<Utc>,
    pub rch_mode: RchMode,
    pub reachable: bool,
    pub capabilities: BTreeMap<String, String>,
    pub failure: Option<WorkerFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerFailure {
    pub error_class: ValidationErrorClass,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerQueueEntry {
    pub schema_version: String,
    pub queue_id: String,
    pub request: ValidationBrokerRequest,
    pub queue_state: QueueState,
    pub dedupe_key: DedupeKey,
    pub lease: LeaseState,
    pub worker_requirements: WorkerRequirements,
    pub observations: Vec<WorkerCapabilityObservation>,
    pub queued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnqueueOutcome {
    pub queue_id: String,
    pub deduplicated: bool,
    pub queue_depth: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueSnapshot {
    pub queue_depth: usize,
    pub oldest_queued_age_ms: Option<u64>,
    pub active_leases: usize,
    pub expired_leases: usize,
    pub queued_by_state: BTreeMap<QueueState, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofArtifactPaths {
    pub stdout_path: String,
    pub stderr_path: String,
    pub summary_path: String,
    pub receipt_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofStatus {
    pub schema_version: String,
    pub bead_id: String,
    pub thread_id: String,
    pub request_id: Option<String>,
    pub queue_id: Option<String>,
    pub status: ProofStatusKind,
    pub queue_state: Option<QueueState>,
    pub deduplicated: bool,
    pub queue_depth: usize,
    pub artifact_paths: Option<ProofArtifactPaths>,
    pub command_digest: Option<DigestRef>,
    pub exit: Option<ValidationExit>,
    pub reason: Option<String>,
    pub observed_at: DateTime<Utc>,
}

impl ValidationProofStatus {
    #[must_use]
    pub fn unknown(bead_id: &str, thread_id: &str, observed_at: DateTime<Utc>) -> Self {
        Self {
            schema_version: STATUS_SCHEMA_VERSION.to_string(),
            bead_id: bead_id.to_string(),
            thread_id: thread_id.to_string(),
            request_id: None,
            queue_id: None,
            status: ProofStatusKind::Unknown,
            queue_state: None,
            deduplicated: false,
            queue_depth: 0,
            artifact_paths: None,
            command_digest: None,
            exit: None,
            reason: Some("no validation broker request or receipt matched".to_string()),
            observed_at,
        }
    }

    #[must_use]
    pub fn from_queue_entry(
        entry: &BrokerQueueEntry,
        queue_depth: usize,
        deduplicated: bool,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            schema_version: STATUS_SCHEMA_VERSION.to_string(),
            bead_id: entry.request.bead_id.clone(),
            thread_id: entry.request.thread_id.clone(),
            request_id: Some(entry.request.request_id.clone()),
            queue_id: Some(entry.queue_id.clone()),
            status: proof_status_from_queue_state(entry.queue_state, deduplicated),
            queue_state: Some(entry.queue_state),
            deduplicated,
            queue_depth,
            artifact_paths: Some(ProofArtifactPaths {
                stdout_path: entry.request.output_policy.stdout_path.clone(),
                stderr_path: entry.request.output_policy.stderr_path.clone(),
                summary_path: entry.request.output_policy.summary_path.clone(),
                receipt_path: entry.request.output_policy.receipt_path.clone(),
            }),
            command_digest: Some(DigestRef::from_command_digest(
                &entry.request.command.digest(),
            )),
            exit: None,
            reason: None,
            observed_at,
        }
    }

    pub fn from_receipt(
        receipt: &ValidationReceipt,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ValidationBrokerError> {
        receipt.validate_at(observed_at)?;
        Ok(Self {
            schema_version: STATUS_SCHEMA_VERSION.to_string(),
            bead_id: receipt.bead_id.clone(),
            thread_id: receipt.thread_id.clone(),
            request_id: Some(receipt.request_id.clone()),
            queue_id: None,
            status: proof_status_from_exit(receipt.exit.kind),
            queue_state: None,
            deduplicated: false,
            queue_depth: 0,
            artifact_paths: Some(ProofArtifactPaths {
                stdout_path: receipt.artifacts.stdout_path.clone(),
                stderr_path: receipt.artifacts.stderr_path.clone(),
                summary_path: receipt.artifacts.summary_path.clone(),
                receipt_path: receipt.artifacts.receipt_path.clone(),
            }),
            command_digest: Some(DigestRef {
                algorithm: receipt.command_digest.algorithm.clone(),
                hex: receipt.command_digest.hex.clone(),
            }),
            exit: Some(receipt.exit.clone()),
            reason: receipt
                .classifications
                .source_only_reason
                .map(|reason| reason.as_str().to_string()),
            observed_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ValidationBrokerQueue {
    max_depth: usize,
    entries: VecDeque<BrokerQueueEntry>,
    dedupe_index: BTreeMap<String, String>,
}

impl Default for ValidationBrokerQueue {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_QUEUE_DEPTH)
    }
}

impl ValidationBrokerQueue {
    #[must_use]
    pub fn new(max_depth: usize) -> Self {
        Self {
            max_depth,
            entries: VecDeque::new(),
            dedupe_index: BTreeMap::new(),
        }
    }

    pub fn enqueue(
        &mut self,
        request: ValidationBrokerRequest,
        worker_requirements: WorkerRequirements,
        now: DateTime<Utc>,
    ) -> Result<EnqueueOutcome, ValidationBrokerError> {
        if self.max_depth == 0 {
            return Err(ValidationBrokerError::InvalidConfig {
                reason: "validation broker queue max_depth must be > 0".to_string(),
            });
        }

        let recomputed = request.recomputed_dedupe_key();
        if !constant_time::ct_eq(&recomputed.hex, &request.dedupe_key.hex) {
            return Err(ValidationBrokerError::InvalidDedupeKey {
                expected: recomputed.hex,
                actual: request.dedupe_key.hex,
            });
        }

        if let Some(queue_id) = self.dedupe_index.get(&request.dedupe_key.hex) {
            return Ok(EnqueueOutcome {
                queue_id: queue_id.clone(),
                deduplicated: true,
                queue_depth: self.entries.len(),
            });
        }

        if self.entries.len() >= self.max_depth {
            return Err(ValidationBrokerError::QueueFull {
                max_depth: self.max_depth,
            });
        }

        let queue_id = format!("vbq-{}", &request.dedupe_key.hex[..16]);
        let entry = BrokerQueueEntry {
            schema_version: QUEUE_SCHEMA_VERSION.to_string(),
            queue_id: queue_id.clone(),
            dedupe_key: request.dedupe_key.clone(),
            request,
            queue_state: QueueState::Queued,
            lease: LeaseState {
                holder_agent: None,
                leased_at: None,
                expires_at: None,
                renew_count: 0,
            },
            worker_requirements,
            observations: Vec::new(),
            queued_at: now,
        };
        self.dedupe_index
            .insert(entry.dedupe_key.hex.clone(), queue_id.clone());
        self.entries.push_back(entry);

        Ok(EnqueueOutcome {
            queue_id,
            deduplicated: false,
            queue_depth: self.entries.len(),
        })
    }

    pub fn lease_next(
        &mut self,
        holder_agent: impl Into<String>,
        leased_at: DateTime<Utc>,
        lease_duration_ms: u64,
    ) -> Result<Option<BrokerQueueEntry>, ValidationBrokerError> {
        if lease_duration_ms == 0 {
            return Err(ValidationBrokerError::InvalidConfig {
                reason: "validation broker lease_duration_ms must be > 0".to_string(),
            });
        }
        let lease_duration =
            chrono::Duration::milliseconds(i64::try_from(lease_duration_ms).unwrap_or(i64::MAX));
        let holder_agent = holder_agent.into();

        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.queue_state == QueueState::Queued)
        else {
            return Ok(None);
        };

        if let Some(entry) = self.entries.get_mut(index) {
            entry.queue_state = QueueState::Leased;
            entry.lease = LeaseState {
                holder_agent: Some(holder_agent),
                leased_at: Some(leased_at),
                expires_at: Some(leased_at + lease_duration),
                renew_count: entry.lease.renew_count,
            };
            return Ok(Some(entry.clone()));
        }
        Ok(None)
    }

    pub fn mark_running(&mut self, queue_id: &str) -> Result<(), ValidationBrokerError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.queue_id == queue_id)
            .ok_or_else(|| ValidationBrokerError::QueueEntryNotFound {
                queue_id: queue_id.to_string(),
            })?;
        entry.queue_state = QueueState::Running;
        Ok(())
    }

    pub fn complete(&mut self, queue_id: &str, passed: bool) -> Result<(), ValidationBrokerError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.queue_id == queue_id)
            .ok_or_else(|| ValidationBrokerError::QueueEntryNotFound {
                queue_id: queue_id.to_string(),
            })?;
        entry.queue_state = if passed {
            QueueState::Completed
        } else {
            QueueState::Failed
        };
        entry.lease.holder_agent = None;
        entry.lease.leased_at = None;
        entry.lease.expires_at = None;
        Ok(())
    }

    pub fn expire_stale_leases(&mut self, now: DateTime<Utc>) -> usize {
        let mut expired = 0;
        for entry in &mut self.entries {
            let is_expired = entry
                .lease
                .expires_at
                .is_some_and(|expires_at| expires_at <= now);
            if is_expired && matches!(entry.queue_state, QueueState::Leased | QueueState::Running) {
                entry.queue_state = QueueState::Failed;
                entry.lease.holder_agent = None;
                expired += 1;
            }
        }
        expired
    }

    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn entries(&self) -> &VecDeque<BrokerQueueEntry> {
        &self.entries
    }

    #[must_use]
    pub fn snapshot(&self, now: DateTime<Utc>) -> QueueSnapshot {
        let oldest_queued_age_ms = self.entries.front().map(|entry| {
            let millis = now
                .signed_duration_since(entry.queued_at)
                .num_milliseconds()
                .max(0);
            u64::try_from(millis).unwrap_or(u64::MAX)
        });
        let mut active_leases = 0;
        let mut expired_leases = 0;
        let mut queued_by_state = BTreeMap::new();

        for entry in &self.entries {
            *queued_by_state.entry(entry.queue_state).or_insert(0) += 1;
            if let Some(expires_at) = entry.lease.expires_at {
                if expires_at <= now {
                    expired_leases += 1;
                } else {
                    active_leases += 1;
                }
            }
        }

        QueueSnapshot {
            queue_depth: self.entries.len(),
            oldest_queued_age_ms,
            active_leases,
            expired_leases,
            queued_by_state,
        }
    }

    #[must_use]
    pub fn proof_status_for(
        &self,
        bead_id: &str,
        thread_id: &str,
        observed_at: DateTime<Utc>,
    ) -> ValidationProofStatus {
        self.entries
            .iter()
            .find(|entry| entry.request.bead_id == bead_id && entry.request.thread_id == thread_id)
            .map(|entry| {
                ValidationProofStatus::from_queue_entry(
                    entry,
                    self.entries.len(),
                    false,
                    observed_at,
                )
            })
            .unwrap_or_else(|| ValidationProofStatus::unknown(bead_id, thread_id, observed_at))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRequestRef {
    pub request_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub dedupe_key: DigestRef,
    pub cross_thread_waiver: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentPolicy {
    pub policy_id: String,
    pub allowed_env: Vec<String>,
    pub redacted_env: Vec<String>,
    pub remote_required: bool,
    pub network_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDirPolicy {
    pub policy_id: String,
    pub kind: String,
    pub path: String,
    pub path_digest: DigestRef,
    pub cleanup: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchReceipt {
    pub mode: RchMode,
    pub worker_id: Option<String>,
    pub require_remote: bool,
    pub capability_observation_id: Option<String>,
    pub worker_pool: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationTiming {
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub freshness_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationExit {
    pub kind: ValidationExitKind,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub timeout_class: TimeoutClass,
    pub error_class: ValidationErrorClass,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptArtifacts {
    pub stdout_path: String,
    pub stderr_path: String,
    pub summary_path: String,
    pub receipt_path: String,
    pub stdout_digest: DigestRef,
    pub stderr_digest: DigestRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptTrust {
    pub generated_by: String,
    pub agent_name: String,
    pub git_commit: String,
    pub dirty_worktree: bool,
    pub freshness: String,
    pub signature_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptClassifications {
    pub source_only_fallback: bool,
    pub source_only_reason: Option<SourceOnlyReason>,
    pub doctor_readiness: String,
    pub ci_consumable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub request_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub request_ref: ReceiptRequestRef,
    pub command: CommandSpec,
    pub command_digest: CommandDigest,
    pub environment_policy: EnvironmentPolicy,
    pub target_dir_policy: TargetDirPolicy,
    pub input_digests: Vec<InputDigest>,
    pub rch: RchReceipt,
    pub timing: ValidationTiming,
    pub exit: ValidationExit,
    pub artifacts: ReceiptArtifacts,
    pub trust: ReceiptTrust,
    pub classifications: ReceiptClassifications,
}

impl ValidationReceipt {
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ValidationBrokerError> {
        if self.schema_version != RECEIPT_SCHEMA_VERSION {
            return Err(ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_INVALID_SCHEMA_VERSION,
                detail: format!("unsupported schema_version={}", self.schema_version),
            });
        }

        if self.bead_id.trim().is_empty()
            || self.thread_id.trim().is_empty()
            || self.request_ref.bead_id != self.bead_id
            || self.request_ref.thread_id != self.thread_id
            || self.request_ref.request_id != self.request_id
        {
            return Err(ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_BEAD_MISMATCH,
                detail: "receipt bead/thread/request references must match".to_string(),
            });
        }

        let expected_command_digest = self.command.digest();
        if !self.command_digest.verifies()
            || !constant_time::ct_eq(&expected_command_digest.hex, &self.command_digest.hex)
        {
            return Err(ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_MISSING_COMMAND_DIGEST,
                detail: "command_digest does not match canonical command material".to_string(),
            });
        }

        if self.input_digests.is_empty()
            || self.input_digests.iter().any(|digest| !digest.is_valid())
        {
            return Err(ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_MALFORMED_RECEIPT,
                detail: "receipt must include at least one valid input digest".to_string(),
            });
        }

        if self.timing.finished_at < self.timing.started_at {
            return Err(ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_MALFORMED_RECEIPT,
                detail: "finished_at must not be before started_at".to_string(),
            });
        }
        if self.timing.freshness_expires_at < now {
            return Err(ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_STALE_RECEIPT,
                detail: "receipt freshness has expired".to_string(),
            });
        }

        if self.exit.kind == ValidationExitKind::Timeout
            && self.exit.timeout_class == TimeoutClass::None
        {
            return Err(ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_INVALID_TIMEOUT_CLASS,
                detail: "timeout exits require a concrete timeout class".to_string(),
            });
        }

        if self.artifacts.stdout_path.trim().is_empty()
            || self.artifacts.stderr_path.trim().is_empty()
            || self.artifacts.summary_path.trim().is_empty()
            || self.artifacts.receipt_path.trim().is_empty()
        {
            return Err(ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_MISSING_ARTIFACT_PATH,
                detail: "receipt artifact paths must be non-empty".to_string(),
            });
        }

        if (self.classifications.source_only_fallback
            || self.exit.kind == ValidationExitKind::SourceOnly)
            && self.classifications.source_only_reason.is_none()
        {
            return Err(ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_UNDECLARED_SOURCE_ONLY,
                detail: "source-only fallback requires an allowed reason".to_string(),
            });
        }

        Ok(())
    }
}

pub fn write_validation_receipt(
    path: &Path,
    receipt: &ValidationReceipt,
) -> Result<(), ValidationBrokerError> {
    write_validation_receipt_at(path, receipt, Utc::now())
}

pub fn write_validation_receipt_at(
    path: &Path,
    receipt: &ValidationReceipt,
    now: DateTime<Utc>,
) -> Result<(), ValidationBrokerError> {
    receipt.validate_at(now)?;
    let bytes = serde_json::to_vec_pretty(receipt).map_err(ValidationBrokerError::Json)?;
    write_bytes_atomically(path, &bytes)
}

pub fn render_validation_proof_status_json(
    status: &ValidationProofStatus,
) -> Result<String, ValidationBrokerError> {
    serde_json::to_string_pretty(status).map_err(ValidationBrokerError::Json)
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationBrokerError {
    #[error("validation broker queue is full (max_depth={max_depth})")]
    QueueFull { max_depth: usize },
    #[error("validation broker queue entry not found: {queue_id}")]
    QueueEntryNotFound { queue_id: String },
    #[error("invalid validation broker config: {reason}")]
    InvalidConfig { reason: String },
    #[error("invalid validation broker dedupe key: expected {expected}, got {actual}")]
    InvalidDedupeKey { expected: String, actual: String },
    #[error("{code}: {detail}")]
    ContractViolation { code: &'static str, detail: String },
    #[error("failed to encode validation receipt JSON: {0}")]
    Json(serde_json::Error),
    #[error("failed writing validation receipt to {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn proof_status_from_queue_state(queue_state: QueueState, deduplicated: bool) -> ProofStatusKind {
    if deduplicated {
        return ProofStatusKind::Reused;
    }
    match queue_state {
        QueueState::Queued => ProofStatusKind::Queued,
        QueueState::Leased => ProofStatusKind::Leased,
        QueueState::Running => ProofStatusKind::Running,
        QueueState::Completed => ProofStatusKind::Passed,
        QueueState::Failed => ProofStatusKind::Failed,
        QueueState::Cancelled => ProofStatusKind::Cancelled,
    }
}

fn proof_status_from_exit(exit_kind: ValidationExitKind) -> ProofStatusKind {
    match exit_kind {
        ValidationExitKind::Success => ProofStatusKind::Passed,
        ValidationExitKind::Failed | ValidationExitKind::Timeout => ProofStatusKind::Failed,
        ValidationExitKind::SourceOnly => ProofStatusKind::SourceOnly,
        ValidationExitKind::Cancelled => ProofStatusKind::Cancelled,
    }
}

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> Result<(), ValidationBrokerError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent).map_err(|source| ValidationBrokerError::Write {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let mut temp_guard = TempFileGuard::new(path);
    {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(temp_guard.path())
            .map_err(|source| ValidationBrokerError::Write {
                path: temp_guard.path().display().to_string(),
                source,
            })?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| ValidationBrokerError::Write {
                path: temp_guard.path().display().to_string(),
                source,
            })?;
    }

    fs::rename(temp_guard.path(), path).map_err(|source| ValidationBrokerError::Write {
        path: path.display().to_string(),
        source,
    })?;
    temp_guard.persist();
    sync_directory(parent)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ValidationBrokerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ValidationBrokerError::Write {
            path: path.display().to_string(),
            source,
        })
}

struct TempFileGuard {
    path: PathBuf,
    active: bool,
}

impl TempFileGuard {
    fn new(path: &Path) -> Self {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("validation-receipt");
        let temp_name = format!(
            ".{file_name}.tmp-{}-{}",
            std::process::id(),
            Utc::now().timestamp_micros()
        );
        let temp_path = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(temp_name);
        Self {
            path: temp_path,
            active: true,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&mut self) {
        self.active = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::TempDir;

    fn ts(seconds: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, seconds)
            .single()
            .expect("valid timestamp")
    }

    fn command() -> CommandSpec {
        CommandSpec {
            program: "cargo".to_string(),
            argv: vec![
                "+nightly-2026-02-19".to_string(),
                "test".to_string(),
                "-p".to_string(),
                "frankenengine-node".to_string(),
                "--test".to_string(),
                "idempotency_key_derivation".to_string(),
            ],
            cwd: "/data/projects/franken_node".to_string(),
            environment_policy_id: "validation-broker/env-policy/v1".to_string(),
            target_dir_policy_id: "validation-broker/target-dir/off-repo/v1".to_string(),
        }
    }

    fn inputs() -> InputSet {
        InputSet {
            git_commit: "af6e4745".to_string(),
            dirty_worktree: false,
            changed_paths: vec![
                "crates/franken-node/tests/idempotency_key_derivation.rs".to_string(),
            ],
            content_digests: vec![InputDigest::new(
                "crates/franken-node/tests/idempotency_key_derivation.rs",
                b"idempotency-key-derivation-test",
                "git-or-worktree",
            )],
            feature_flags: vec!["extended-surfaces".to_string()],
        }
    }

    fn request() -> ValidationBrokerRequest {
        ValidationBrokerRequest::new(
            "vbreq-bd-6efmv-1",
            "bd-6efmv",
            "bd-6efmv",
            "PinkFern",
            ts(0),
            ValidationPriority::High,
            command(),
            inputs(),
            OutputPolicy {
                stdout_path: "artifacts/validation_broker/bd-6efmv/stdout.txt".to_string(),
                stderr_path: "artifacts/validation_broker/bd-6efmv/stderr.txt".to_string(),
                summary_path: "artifacts/validation_broker/bd-6efmv/summary.md".to_string(),
                receipt_path: "artifacts/validation_broker/bd-6efmv/receipt.json".to_string(),
                retention: "keep-with-bead".to_string(),
            },
            FallbackPolicy {
                source_only_allowed: true,
                allowed_reasons: vec![SourceOnlyReason::CargoContention],
            },
        )
    }

    fn worker_requirements() -> WorkerRequirements {
        WorkerRequirements {
            require_rch_remote: true,
            cargo_toolchain: "nightly-2026-02-19".to_string(),
            feature_flags: vec!["extended-surfaces".to_string()],
            max_wall_time_ms: 1_800_000,
        }
    }

    fn receipt() -> ValidationReceipt {
        let req = request();
        ValidationReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_id: "vbrcpt-bd-6efmv-1".to_string(),
            request_id: req.request_id.clone(),
            bead_id: req.bead_id.clone(),
            thread_id: req.thread_id.clone(),
            request_ref: ReceiptRequestRef {
                request_id: req.request_id.clone(),
                bead_id: req.bead_id.clone(),
                thread_id: req.thread_id.clone(),
                dedupe_key: DigestRef {
                    algorithm: req.dedupe_key.algorithm.clone(),
                    hex: req.dedupe_key.hex.clone(),
                },
                cross_thread_waiver: None,
            },
            command_digest: req.command.digest(),
            command: req.command.clone(),
            environment_policy: EnvironmentPolicy {
                policy_id: req.command.environment_policy_id.clone(),
                allowed_env: vec![
                    "RCH_REQUIRE_REMOTE".to_string(),
                    "CARGO_TARGET_DIR".to_string(),
                ],
                redacted_env: Vec::new(),
                remote_required: true,
                network_policy: "rch-only".to_string(),
            },
            target_dir_policy: TargetDirPolicy {
                policy_id: req.command.target_dir_policy_id.clone(),
                kind: "off_repo".to_string(),
                path: "/data/tmp/franken_node-pinkfern-bd-6efmv-target".to_string(),
                path_digest: DigestRef::sha256(b"/data/tmp/franken_node-pinkfern-bd-6efmv-target"),
                cleanup: "best_effort_after_receipt".to_string(),
            },
            input_digests: req.inputs.content_digests.clone(),
            rch: RchReceipt {
                mode: RchMode::Remote,
                worker_id: Some("ts2".to_string()),
                require_remote: true,
                capability_observation_id: Some("vbobs-ts2".to_string()),
                worker_pool: "default".to_string(),
            },
            timing: ValidationTiming {
                started_at: ts(1),
                finished_at: ts(2),
                duration_ms: 1_000,
                freshness_expires_at: ts(10),
            },
            exit: ValidationExit {
                kind: ValidationExitKind::Success,
                code: Some(0),
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::None,
                retryable: false,
            },
            artifacts: ReceiptArtifacts {
                stdout_path: "artifacts/validation_broker/bd-6efmv/stdout.txt".to_string(),
                stderr_path: "artifacts/validation_broker/bd-6efmv/stderr.txt".to_string(),
                summary_path: "artifacts/validation_broker/bd-6efmv/summary.md".to_string(),
                receipt_path: "artifacts/validation_broker/bd-6efmv/receipt.json".to_string(),
                stdout_digest: DigestRef::sha256(b"stdout"),
                stderr_digest: DigestRef::sha256(b"stderr"),
            },
            trust: ReceiptTrust {
                generated_by: "validation-broker".to_string(),
                agent_name: "PinkFern".to_string(),
                git_commit: "af6e4745".to_string(),
                dirty_worktree: false,
                freshness: "fresh".to_string(),
                signature_status: "unsigned-test".to_string(),
            },
            classifications: ReceiptClassifications {
                source_only_fallback: false,
                source_only_reason: None,
                doctor_readiness: "ready".to_string(),
                ci_consumable: true,
            },
        }
    }

    #[test]
    fn dedupe_key_is_stable_across_changed_path_ordering() {
        let mut left = inputs();
        left.changed_paths = vec!["b.rs".to_string(), "a.rs".to_string(), "a.rs".to_string()];
        let mut right = left.clone();
        right.changed_paths = vec!["a.rs".to_string(), "b.rs".to_string()];

        let left_key =
            ValidationBrokerRequest::compute_dedupe_key("bd-6efmv", "bd-6efmv", &command(), &left);
        let right_key =
            ValidationBrokerRequest::compute_dedupe_key("bd-6efmv", "bd-6efmv", &command(), &right);

        assert_eq!(left_key.hex, right_key.hex);
    }

    #[test]
    fn different_input_digest_changes_dedupe_key() {
        let left = inputs();
        let mut right = inputs();
        right.content_digests = vec![InputDigest::new(
            "crates/franken-node/tests/idempotency_key_derivation.rs",
            b"different-input-content",
            "git-or-worktree",
        )];

        let left_key =
            ValidationBrokerRequest::compute_dedupe_key("bd-6efmv", "bd-6efmv", &command(), &left);
        let right_key =
            ValidationBrokerRequest::compute_dedupe_key("bd-6efmv", "bd-6efmv", &command(), &right);

        assert_ne!(left_key.hex, right_key.hex);
    }

    #[test]
    fn queue_deduplicates_same_request_without_second_entry() {
        let mut queue = ValidationBrokerQueue::new(4);
        let first = queue
            .enqueue(request(), worker_requirements(), ts(0))
            .expect("first enqueue");
        let second = queue
            .enqueue(request(), worker_requirements(), ts(1))
            .expect("duplicate enqueue");

        assert!(!first.deduplicated);
        assert!(second.deduplicated);
        assert_eq!(first.queue_id, second.queue_id);
        assert_eq!(queue.queue_depth(), 1);
    }

    #[test]
    fn queue_full_fails_without_dropping_existing_entry() {
        let mut queue = ValidationBrokerQueue::new(1);
        queue
            .enqueue(request(), worker_requirements(), ts(0))
            .expect("first enqueue");
        let mut second = request();
        second.bead_id = "bd-other".to_string();
        second.thread_id = "bd-other".to_string();
        second.dedupe_key = ValidationBrokerRequest::compute_dedupe_key(
            &second.bead_id,
            &second.thread_id,
            &second.command,
            &second.inputs,
        );

        let err = queue
            .enqueue(second, worker_requirements(), ts(1))
            .expect_err("queue should be full");
        assert!(matches!(
            err,
            ValidationBrokerError::QueueFull { max_depth: 1 }
        ));
        assert_eq!(queue.queue_depth(), 1);
    }

    #[test]
    fn snapshot_reports_oldest_age_and_lease_counts() {
        let mut queue = ValidationBrokerQueue::new(4);
        queue
            .enqueue(request(), worker_requirements(), ts(0))
            .expect("enqueue");
        let snapshot = queue.snapshot(ts(5));

        assert_eq!(snapshot.queue_depth, 1);
        assert_eq!(snapshot.oldest_queued_age_ms, Some(5_000));
        assert_eq!(snapshot.active_leases, 0);
        assert_eq!(snapshot.expired_leases, 0);
        assert_eq!(snapshot.queued_by_state.get(&QueueState::Queued), Some(&1));

        let value = serde_json::to_value(&snapshot).expect("snapshot serializes");
        let queued = value
            .get("queued_by_state")
            .and_then(serde_json::Value::as_object)
            .and_then(|states| states.get("queued"))
            .and_then(serde_json::Value::as_u64);
        assert_eq!(queued, Some(1));
    }

    #[test]
    fn stale_leases_fail_closed_and_status_json_reports_artifacts()
    -> Result<(), ValidationBrokerError> {
        let mut queue = ValidationBrokerQueue::new(4);
        let outcome = queue.enqueue(request(), worker_requirements(), ts(0))?;

        let status = queue.proof_status_for("bd-6efmv", "bd-6efmv", ts(0));
        assert_eq!(status.status, ProofStatusKind::Queued);
        let json = render_validation_proof_status_json(&status)?;
        assert!(json.contains("\"status\": \"queued\""));
        assert!(json.contains("artifacts/validation_broker/bd-6efmv/receipt.json"));

        let leased = queue.lease_next("PinkFern", ts(1), 1_000)?;
        assert!(leased.is_some());
        queue.mark_running(&outcome.queue_id)?;
        assert_eq!(
            queue.proof_status_for("bd-6efmv", "bd-6efmv", ts(1)).status,
            ProofStatusKind::Running
        );

        let expired = queue.expire_stale_leases(ts(3));
        assert_eq!(expired, 1);
        assert_eq!(
            queue.proof_status_for("bd-6efmv", "bd-6efmv", ts(3)).status,
            ProofStatusKind::Failed
        );
    }

    #[test]
    fn receipt_validates_command_digest_and_contract_fields() {
        let receipt = receipt();
        receipt.validate_at(ts(3)).expect("receipt should validate");
    }

    #[test]
    fn receipt_rejects_bad_command_digest() {
        let mut receipt = receipt();
        receipt.command_digest.hex = "0".repeat(64);

        let err = receipt
            .validate_at(ts(3))
            .expect_err("bad command digest should fail");
        assert!(matches!(
            err,
            ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_MISSING_COMMAND_DIGEST,
                ..
            }
        ));
    }

    #[test]
    fn stale_receipt_is_rejected() {
        let receipt = receipt();
        let err = receipt
            .validate_at(ts(11))
            .expect_err("stale receipt should fail");
        assert!(matches!(
            err,
            ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_STALE_RECEIPT,
                ..
            }
        ));
    }

    #[test]
    fn bead_thread_mismatch_is_rejected() {
        let mut receipt = receipt();
        receipt.request_ref.bead_id = "bd-wrong".to_string();

        let err = receipt
            .validate_at(ts(3))
            .expect_err("mismatched bead should fail");
        assert!(matches!(
            err,
            ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_BEAD_MISMATCH,
                ..
            }
        ));
    }

    #[test]
    fn timeout_exit_requires_concrete_timeout_class() {
        let mut receipt = receipt();
        receipt.exit.kind = ValidationExitKind::Timeout;
        receipt.exit.error_class = ValidationErrorClass::TransportTimeout;
        receipt.exit.timeout_class = TimeoutClass::None;

        let err = receipt
            .validate_at(ts(3))
            .expect_err("timeout without class should fail");
        assert!(matches!(
            err,
            ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_INVALID_TIMEOUT_CLASS,
                ..
            }
        ));
    }

    #[test]
    fn source_only_requires_reason() {
        let mut receipt = receipt();
        receipt.exit.kind = ValidationExitKind::SourceOnly;
        receipt.exit.error_class = ValidationErrorClass::SourceOnly;
        receipt.classifications.source_only_fallback = true;
        receipt.classifications.source_only_reason = None;

        let err = receipt
            .validate_at(ts(3))
            .expect_err("source-only without reason should fail");
        assert!(matches!(
            err,
            ValidationBrokerError::ContractViolation {
                code: error_codes::ERR_VB_UNDECLARED_SOURCE_ONLY,
                ..
            }
        ));
    }

    #[test]
    fn receipt_status_json_reports_passed_state_and_artifacts() -> Result<(), ValidationBrokerError>
    {
        let receipt = receipt();
        let status = ValidationProofStatus::from_receipt(&receipt, ts(3))?;
        let json = render_validation_proof_status_json(&status)?;

        assert_eq!(status.status, ProofStatusKind::Passed);
        assert!(json.contains("\"status\": \"passed\""));
        assert!(json.contains("artifacts/validation_broker/bd-6efmv/stdout.txt"));
        Ok(())
    }

    #[test]
    fn serde_rejects_unknown_timeout_class() {
        let mut value = serde_json::to_value(receipt()).expect("receipt serializes");
        let exit = value
            .get_mut("exit")
            .and_then(serde_json::Value::as_object_mut)
            .expect("receipt has exit object");
        exit.insert(
            "timeout_class".to_string(),
            serde_json::Value::String("made_up".to_string()),
        );

        let result = serde_json::from_value::<ValidationReceipt>(value);
        assert!(result.is_err());
    }

    #[test]
    fn receipt_writer_persists_round_trippable_json() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("receipt.json");
        let receipt = receipt();

        write_validation_receipt_at(&path, &receipt, ts(3))?;

        let raw = fs::read_to_string(&path)?;
        let parsed: ValidationReceipt = serde_json::from_str(&raw)?;
        assert_eq!(parsed.receipt_id, receipt.receipt_id);
        assert_eq!(parsed.command_digest.hex, receipt.command_digest.hex);
        Ok(())
    }
}
