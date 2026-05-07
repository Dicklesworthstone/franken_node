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
use std::path::{Component, Path, PathBuf};

pub const REQUEST_SCHEMA_VERSION: &str = "franken-node/validation-broker/request/v1";
pub const QUEUE_SCHEMA_VERSION: &str = "franken-node/validation-broker/queue/v1";
pub const RECEIPT_SCHEMA_VERSION: &str = "franken-node/validation-broker/receipt/v1";
pub const STATUS_SCHEMA_VERSION: &str = "franken-node/validation-broker/status/v1";
pub const READINESS_REF_SCHEMA_VERSION: &str = "franken-node/validation-broker/readiness-ref/v1";
pub const FLIGHT_RECORDER_ATTEMPT_SCHEMA_VERSION: &str =
    "franken-node/validation-flight-recorder/attempt/v1";
pub const FLIGHT_RECORDER_OBSERVATION_SCHEMA_VERSION: &str =
    "franken-node/validation-flight-recorder/observation/v1";
pub const FLIGHT_RECORDER_RECOVERY_SCHEMA_VERSION: &str =
    "franken-node/validation-flight-recorder/recovery/v1";
pub const DEFAULT_MAX_QUEUE_DEPTH: usize = 1024;
pub const DEFAULT_MAX_FLIGHT_RECORDER_OBSERVATIONS: usize = 256;
pub const FLIGHT_RECORDER_MAX_SNIPPET_BYTES: usize = 4_096;
pub const FLIGHT_RECORDER_REDACTED_ENV_VALUE: &str = "<redacted>";
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
    pub const ERR_VB_INVALID_READINESS_REF: &str = "ERR_VB_INVALID_READINESS_REF";
    pub const ERR_VB_STALE_READINESS_REF: &str = "ERR_VB_STALE_READINESS_REF";
    pub const ERR_VFR_INVALID_SCHEMA_VERSION: &str = "ERR_VFR_INVALID_SCHEMA_VERSION";
    pub const ERR_VFR_MALFORMED_ATTEMPT: &str = "ERR_VFR_MALFORMED_ATTEMPT";
    pub const ERR_VFR_BEAD_MISMATCH: &str = "ERR_VFR_BEAD_MISMATCH";
    pub const ERR_VFR_MISSING_COMMAND_DIGEST: &str = "ERR_VFR_MISSING_COMMAND_DIGEST";
    pub const ERR_VFR_STALE_ATTEMPT: &str = "ERR_VFR_STALE_ATTEMPT";
    pub const ERR_VFR_INVALID_OBSERVATION_ORDER: &str = "ERR_VFR_INVALID_OBSERVATION_ORDER";
    pub const ERR_VFR_INVALID_ARTIFACT_PATH: &str = "ERR_VFR_INVALID_ARTIFACT_PATH";
    pub const ERR_VFR_UNBOUNDED_SNIPPET: &str = "ERR_VFR_UNBOUNDED_SNIPPET";
    pub const ERR_VFR_UNREDACTED_ENVIRONMENT: &str = "ERR_VFR_UNREDACTED_ENVIRONMENT";
    pub const ERR_VFR_INVALID_RECOVERY_DECISION: &str = "ERR_VFR_INVALID_RECOVERY_DECISION";
    pub const ERR_VFR_INVALID_READINESS_REF: &str = "ERR_VFR_INVALID_READINESS_REF";
    pub const ERR_VFR_STALE_READINESS_REF: &str = "ERR_VFR_STALE_READINESS_REF";
}

pub mod readiness_ref_reason_codes {
    pub const WORKER_AUTH_FAILED: &str = "PLR_WORKER_AUTH_FAILED";
    pub const OVERRIDE_NOT_HONORED: &str = "PLR_OVERRIDE_NOT_HONORED";
    pub const SAME_TOOLCHAIN_MISSING: &str = "PLR_SAME_TOOLCHAIN_MISSING";
    pub const LOCAL_FALLBACK_REFUSED: &str = "PLR_LOCAL_FALLBACK_REFUSED";
}

pub mod flight_recorder_event_codes {
    pub const SUCCESS_REMOTE: &str = "VFR-001";
    pub const RETRY_SSH_TIMEOUT: &str = "VFR-002";
    pub const RETRY_MISSING_TOOLCHAIN: &str = "VFR-003";
    pub const RETRY_WORKER_FS: &str = "VFR-004";
    pub const QUEUE_CONTENTION: &str = "VFR-005";
    pub const REJECT_LOCAL_FALLBACK: &str = "VFR-006";
    pub const SOURCE_ONLY_ALLOWED: &str = "VFR-007";
    pub const PRODUCT_FAILURE: &str = "VFR-008";
    pub const STALE_PROGRESS: &str = "VFR-009";
    pub const STALE_LEASE_FENCE: &str = "VFR-010";
    pub const REUSE_RECEIPT: &str = "VFR-011";
    pub const INVALID_ARTIFACT: &str = "VFR-012";
}

pub mod flight_recorder_reason_codes {
    pub const SUCCESS_REMOTE: &str = "VFR_SUCCESS_REMOTE";
    pub const RETRY_SSH_TIMEOUT: &str = "VFR_RETRY_SSH_TIMEOUT";
    pub const RETRY_MISSING_TOOLCHAIN: &str = "VFR_RETRY_MISSING_TOOLCHAIN";
    pub const RETRY_WORKER_FS: &str = "VFR_RETRY_WORKER_FS";
    pub const QUEUE_CONTENTION: &str = "VFR_QUEUE_CONTENTION";
    pub const REJECT_LOCAL_FALLBACK: &str = "VFR_REJECT_LOCAL_FALLBACK";
    pub const SOURCE_ONLY_ALLOWED: &str = "VFR_SOURCE_ONLY_ALLOWED";
    pub const PRODUCT_FAILURE: &str = "VFR_PRODUCT_FAILURE";
    pub const STALE_PROGRESS: &str = "VFR_STALE_PROGRESS";
    pub const STALE_LEASE_FENCE: &str = "VFR_STALE_LEASE_FENCE";
    pub const REUSE_RECEIPT: &str = "VFR_REUSE_RECEIPT";
    pub const INVALID_ARTIFACT: &str = "VFR_INVALID_ARTIFACT";
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
    ProofLaneWorkerAuthFailed,
    ProofLaneOverrideNotHonored,
    ProofLaneSameToolchainMissing,
    ProofLaneLocalFallbackRefused,
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
            Self::ProofLaneWorkerAuthFailed => "proof_lane_worker_auth_failed",
            Self::ProofLaneOverrideNotHonored => "proof_lane_override_not_honored",
            Self::ProofLaneSameToolchainMissing => "proof_lane_same_toolchain_missing",
            Self::ProofLaneLocalFallbackRefused => "proof_lane_local_fallback_refused",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofEvidenceSource {
    Unknown,
    BrokerQueue,
    FreshExecution,
    SourceOnlyFallback,
    ProofCacheHit,
}

impl ProofEvidenceSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::BrokerQueue => "broker_queue",
            Self::FreshExecution => "fresh_execution",
            Self::SourceOnlyFallback => "source_only_fallback",
            Self::ProofCacheHit => "proof_cache_hit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheReuseEvidence {
    pub decision_id: String,
    pub cache_key_hex: String,
    pub entry_id: String,
    pub entry_path: String,
    pub receipt_id: String,
    pub receipt_path: String,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
    pub diagnostic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReadinessRef {
    pub schema_version: String,
    pub path: String,
    pub digest: DigestRef,
    pub generated_at: DateTime<Utc>,
    pub freshness_expires_at: DateTime<Utc>,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: String,
}

impl ValidationReadinessRef {
    pub fn validate_for_receipt_at(&self, now: DateTime<Utc>) -> Result<(), ValidationBrokerError> {
        self.validate_at(
            now,
            error_codes::ERR_VB_INVALID_READINESS_REF,
            error_codes::ERR_VB_STALE_READINESS_REF,
        )
    }

    pub fn validate_for_flight_recorder_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), ValidationBrokerError> {
        self.validate_at(
            now,
            error_codes::ERR_VFR_INVALID_READINESS_REF,
            error_codes::ERR_VFR_STALE_READINESS_REF,
        )
    }

    fn validate_at(
        &self,
        now: DateTime<Utc>,
        invalid_code: &'static str,
        stale_code: &'static str,
    ) -> Result<(), ValidationBrokerError> {
        if !constant_time::ct_eq(&self.schema_version, READINESS_REF_SCHEMA_VERSION) {
            return contract_err(
                invalid_code,
                format!(
                    "unsupported readiness_ref schema_version={}",
                    self.schema_version
                ),
            );
        }
        validate_repo_relative_path_with_code(&self.path, "readiness_ref path", invalid_code)?;
        validate_digest_with_code(&self.digest, "readiness_ref digest", invalid_code)?;
        validate_non_empty_field(&self.reason_code, "readiness_ref reason_code", invalid_code)?;
        validate_non_empty_field(&self.event_code, "readiness_ref event_code", invalid_code)?;
        validate_non_empty_field(
            &self.required_action,
            "readiness_ref required_action",
            invalid_code,
        )?;
        if self.freshness_expires_at < self.generated_at {
            return contract_err(
                invalid_code,
                "readiness_ref freshness_expires_at cannot predate generated_at",
            );
        }
        if self.freshness_expires_at < now {
            return contract_err(stale_code, "readiness_ref freshness has expired");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlightRecorderTargetDirClass {
    OffRepo,
    RepoLocalGuarded,
    RepoLocalWritable,
    Unwritable,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlightRecorderObservationPhase {
    RequestEnqueued,
    LeaseAcquired,
    CapacityObserved,
    DispatchStarted,
    WorkerSelected,
    ProgressObserved,
    ProgressStale,
    AttemptCancelled,
    AdapterClassified,
    ReceiptEmitted,
    RecoveryPlanned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlightRecorderAdapterOutcomeClass {
    Passed,
    CommandFailed,
    CompileFailed,
    TestFailed,
    WorkerTimeout,
    WorkerMissingToolchain,
    WorkerFilesystemError,
    LocalFallbackRefused,
    ContentionDeferred,
    BrokerInternalError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlightRecorderExitKind {
    Success,
    Failure,
    Timeout,
    WorkerInfra,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlightRecorderRecoveryDecision {
    AcceptSuccess,
    RetryRemoteSameWorker,
    RetryRemoteDifferentWorker,
    QueueUntilCapacity,
    DrainWorkerThenRetry,
    WaitForExistingProof,
    RetryWithNewFence,
    ReuseReceipt,
    UseSourceOnlyBlocker,
    FailClosedProduct,
    FailClosedInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlightRecorderRequiredAction {
    None,
    RetryRemote,
    WaitForCapacity,
    DrainWorker,
    WaitForExistingProof,
    RefreshLeaseFence,
    ReuseReceipt,
    RecordSourceOnlyBlocker,
    SurfaceProductFailure,
    RejectArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderCommand {
    pub program: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub command_digest: CommandDigest,
    pub environment_policy_id: String,
    pub target_dir_policy_id: String,
}

impl FlightRecorderCommand {
    #[must_use]
    pub fn from_command_spec(command: &CommandSpec) -> Self {
        Self {
            program: command.program.clone(),
            argv: command.argv.clone(),
            cwd: command.cwd.clone(),
            command_digest: command.digest(),
            environment_policy_id: command.environment_policy_id.clone(),
            target_dir_policy_id: command.target_dir_policy_id.clone(),
        }
    }

    #[must_use]
    pub fn to_command_spec(&self) -> CommandSpec {
        CommandSpec {
            program: self.program.clone(),
            argv: self.argv.clone(),
            cwd: self.cwd.clone(),
            environment_policy_id: self.environment_policy_id.clone(),
            target_dir_policy_id: self.target_dir_policy_id.clone(),
        }
    }

    #[must_use]
    pub fn digest(&self) -> CommandDigest {
        self.to_command_spec().digest()
    }

    #[must_use]
    pub fn verifies(&self) -> bool {
        let expected = self.digest();
        self.command_digest.verifies()
            && constant_time::ct_eq(&expected.hex, &self.command_digest.hex)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderEnvironment {
    pub policy_id: String,
    pub allowed_env: Vec<String>,
    pub redacted_env: Vec<String>,
    pub remote_required: bool,
    pub network_policy: String,
    #[serde(default)]
    pub captured_env: BTreeMap<String, String>,
}

impl FlightRecorderEnvironment {
    fn validate(&self) -> Result<(), ValidationBrokerError> {
        if self.policy_id.trim().is_empty() || self.network_policy.trim().is_empty() {
            return flight_recorder_err(
                error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                "environment policy_id and network_policy must be non-empty",
            );
        }

        for (key, value) in &self.captured_env {
            let allowed = self.allowed_env.iter().any(|allowed| allowed == key);
            let redacted = self.redacted_env.iter().any(|redacted| redacted == key);
            if !allowed && !redacted {
                return flight_recorder_err(
                    error_codes::ERR_VFR_UNREDACTED_ENVIRONMENT,
                    format!("captured env key `{key}` is outside allow/redact lists"),
                );
            }
            if redacted && !constant_time::ct_eq(value, FLIGHT_RECORDER_REDACTED_ENV_VALUE) {
                return flight_recorder_err(
                    error_codes::ERR_VFR_UNREDACTED_ENVIRONMENT,
                    format!("captured env key `{key}` must be redacted"),
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderTargetDir {
    pub class: FlightRecorderTargetDirClass,
    pub path: Option<String>,
    pub path_digest: Option<DigestRef>,
    pub repo_local: bool,
    pub guarded_placeholder: bool,
    pub writable_parent: Option<bool>,
    pub sync_root_digest: Option<DigestRef>,
    pub diagnostic: String,
}

impl FlightRecorderTargetDir {
    fn validate(&self) -> Result<(), ValidationBrokerError> {
        if self.diagnostic.trim().is_empty() {
            return flight_recorder_err(
                error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                "target_dir diagnostic must be non-empty",
            );
        }

        if self.guarded_placeholder && self.class != FlightRecorderTargetDirClass::RepoLocalGuarded
        {
            return flight_recorder_err(
                error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                "guarded placeholders must use repo_local_guarded target-dir class",
            );
        }

        if matches!(
            self.class,
            FlightRecorderTargetDirClass::OffRepo
                | FlightRecorderTargetDirClass::RepoLocalGuarded
                | FlightRecorderTargetDirClass::RepoLocalWritable
                | FlightRecorderTargetDirClass::Unwritable
        ) && self
            .path
            .as_deref()
            .is_none_or(|path| path.trim().is_empty())
        {
            return flight_recorder_err(
                error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                "target_dir path is required for concrete target-dir classes",
            );
        }

        if let Some(path) = &self.path {
            validate_no_nul(
                path,
                error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                "target_dir path",
            )?;
        }
        if let Some(path_digest) = &self.path_digest {
            validate_digest(path_digest, "target_dir path_digest")?;
        }
        if let Some(sync_root_digest) = &self.sync_root_digest {
            validate_digest(sync_root_digest, "target_dir sync_root_digest")?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderObservation {
    pub schema_version: String,
    pub observation_id: String,
    pub observed_at: DateTime<Utc>,
    pub phase: FlightRecorderObservationPhase,
    pub event_code: String,
    pub worker_id: Option<String>,
    pub rch_mode: RchMode,
    pub queue_state: Option<QueueState>,
    pub message: String,
    #[serde(default)]
    pub details: BTreeMap<String, String>,
}

impl FlightRecorderObservation {
    fn validate(&self) -> Result<(), ValidationBrokerError> {
        if !constant_time::ct_eq(
            &self.schema_version,
            FLIGHT_RECORDER_OBSERVATION_SCHEMA_VERSION,
        ) {
            return flight_recorder_err(
                error_codes::ERR_VFR_INVALID_SCHEMA_VERSION,
                format!(
                    "unsupported observation schema_version={}",
                    self.schema_version
                ),
            );
        }
        validate_non_empty_id(&self.observation_id, "observation_id")?;
        validate_bounded_snippet(&self.message, "observation message")?;
        validate_no_nul(
            &self.message,
            error_codes::ERR_VFR_MALFORMED_ATTEMPT,
            "observation message",
        )?;
        if !is_known_flight_recorder_event_code(&self.event_code) {
            return flight_recorder_err(
                error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                format!("unknown flight recorder event_code={}", self.event_code),
            );
        }
        if let Some(worker_id) = &self.worker_id {
            validate_non_empty_id(worker_id, "worker_id")?;
        }
        for (key, value) in &self.details {
            validate_non_empty_id(key, "observation detail key")?;
            validate_bounded_snippet(value, "observation detail value")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderAdapterOutcome {
    pub outcome: FlightRecorderAdapterOutcomeClass,
    pub execution_mode: RchMode,
    pub worker_id: Option<String>,
    pub timeout_class: TimeoutClass,
    pub exit_code: Option<i32>,
    pub retryable: bool,
    pub product_failure: bool,
    pub reason_code: String,
    pub detail: String,
}

impl FlightRecorderAdapterOutcome {
    fn validate(&self) -> Result<(), ValidationBrokerError> {
        validate_non_empty_id(&self.reason_code, "adapter outcome reason_code")?;
        validate_bounded_snippet(&self.detail, "adapter outcome detail")?;
        if let Some(worker_id) = &self.worker_id {
            validate_non_empty_id(worker_id, "adapter outcome worker_id")?;
        }

        match self.outcome {
            FlightRecorderAdapterOutcomeClass::Passed => {
                if self.execution_mode != RchMode::Remote
                    || self.timeout_class != TimeoutClass::None
                    || self.retryable
                    || self.product_failure
                {
                    return flight_recorder_err(
                        error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                        "green adapter outcomes require remote execution, no timeout, and no failure flags",
                    );
                }
            }
            FlightRecorderAdapterOutcomeClass::CommandFailed
            | FlightRecorderAdapterOutcomeClass::CompileFailed
            | FlightRecorderAdapterOutcomeClass::TestFailed => {
                if !self.product_failure || self.retryable {
                    return flight_recorder_err(
                        error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                        "product adapter failures must be non-retryable product failures",
                    );
                }
            }
            FlightRecorderAdapterOutcomeClass::WorkerTimeout => {
                if self.timeout_class == TimeoutClass::None
                    || self.product_failure
                    || !self.retryable
                {
                    return flight_recorder_err(
                        error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                        "worker timeouts require a timeout class and retryable infrastructure flags",
                    );
                }
            }
            FlightRecorderAdapterOutcomeClass::WorkerMissingToolchain
            | FlightRecorderAdapterOutcomeClass::WorkerFilesystemError
            | FlightRecorderAdapterOutcomeClass::LocalFallbackRefused
            | FlightRecorderAdapterOutcomeClass::ContentionDeferred => {
                if self.product_failure || !self.retryable {
                    return flight_recorder_err(
                        error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                        "retryable worker infrastructure outcomes must not be product failures",
                    );
                }
            }
            FlightRecorderAdapterOutcomeClass::BrokerInternalError => {
                if self.product_failure || self.retryable {
                    return flight_recorder_err(
                        error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                        "broker-internal adapter errors must fail closed without retry/product flags",
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderExit {
    pub kind: FlightRecorderExitKind,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub timeout_class: TimeoutClass,
    pub error_class: ValidationErrorClass,
    pub retryable: bool,
    pub product_failure: bool,
}

impl FlightRecorderExit {
    fn validate(&self) -> Result<(), ValidationBrokerError> {
        match self.kind {
            FlightRecorderExitKind::Success => {
                if self.timeout_class != TimeoutClass::None
                    || self.error_class != ValidationErrorClass::None
                    || self.retryable
                    || self.product_failure
                {
                    return flight_recorder_err(
                        error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                        "success exits must not carry timeout, error, retry, or product-failure flags",
                    );
                }
            }
            FlightRecorderExitKind::Timeout => {
                if self.timeout_class == TimeoutClass::None
                    || self.error_class != ValidationErrorClass::TransportTimeout
                    || !self.retryable
                    || self.product_failure
                {
                    return flight_recorder_err(
                        error_codes::ERR_VB_INVALID_TIMEOUT_CLASS,
                        "timeout exits require transport timeout class and retryable infra flags",
                    );
                }
            }
            FlightRecorderExitKind::WorkerInfra => {
                if self.error_class == ValidationErrorClass::None
                    || self.product_failure
                    || !self.retryable
                {
                    return flight_recorder_err(
                        error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                        "worker infra exits require retryable non-product error classification",
                    );
                }
            }
            FlightRecorderExitKind::Deferred => {
                if self.error_class != ValidationErrorClass::EnvironmentContention
                    || self.product_failure
                    || !self.retryable
                {
                    return flight_recorder_err(
                        error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                        "deferred exits require retryable contention classification",
                    );
                }
            }
            FlightRecorderExitKind::Failure => {
                if self.retryable || self.error_class == ValidationErrorClass::None {
                    return flight_recorder_err(
                        error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                        "failures must be terminal and carry an error classification",
                    );
                }
                if matches!(
                    self.error_class,
                    ValidationErrorClass::CompileError
                        | ValidationErrorClass::TestFailure
                        | ValidationErrorClass::ClippyWarning
                        | ValidationErrorClass::FormatFailure
                ) && !self.product_failure
                {
                    return flight_recorder_err(
                        error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                        "compile/test/lint/format failures must be product failures",
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderArtifacts {
    pub attempt_path: String,
    pub stdout_path: String,
    pub stderr_path: String,
    pub summary_path: String,
    pub recovery_path: Option<String>,
    pub stdout_digest: DigestRef,
    pub stderr_digest: DigestRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_snippet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_snippet: Option<String>,
}

impl FlightRecorderArtifacts {
    fn validate(&self) -> Result<(), ValidationBrokerError> {
        validate_repo_relative_path(&self.attempt_path, "attempt_path")?;
        validate_repo_relative_path(&self.stdout_path, "stdout_path")?;
        validate_repo_relative_path(&self.stderr_path, "stderr_path")?;
        validate_repo_relative_path(&self.summary_path, "summary_path")?;
        if let Some(recovery_path) = &self.recovery_path {
            validate_repo_relative_path(recovery_path, "recovery_path")?;
        }
        validate_digest(&self.stdout_digest, "stdout_digest")?;
        validate_digest(&self.stderr_digest, "stderr_digest")?;
        if let Some(snippet) = &self.stdout_snippet {
            validate_bounded_snippet(snippet, "stdout_snippet")?;
        }
        if let Some(snippet) = &self.stderr_snippet {
            validate_bounded_snippet(snippet, "stderr_snippet")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderRecoveryRef {
    pub decision_id: String,
    pub path: String,
    pub digest: DigestRef,
}

impl FlightRecorderRecoveryRef {
    fn validate(&self) -> Result<(), ValidationBrokerError> {
        validate_non_empty_id(&self.decision_id, "recovery decision_id")?;
        validate_repo_relative_path(&self.path, "recovery ref path")?;
        validate_digest(&self.digest, "recovery ref digest")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecorderTrust {
    pub generated_by: String,
    pub agent_name: String,
    pub git_commit: String,
    pub dirty_worktree: bool,
    pub freshness: String,
    pub signature_status: String,
}

impl FlightRecorderTrust {
    fn validate(&self) -> Result<(), ValidationBrokerError> {
        validate_non_empty_id(&self.generated_by, "trust generated_by")?;
        validate_non_empty_id(&self.agent_name, "trust agent_name")?;
        validate_non_empty_id(&self.git_commit, "trust git_commit")?;
        validate_non_empty_id(&self.freshness, "trust freshness")?;
        validate_non_empty_id(&self.signature_status, "trust signature_status")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFlightRecorderAttempt {
    pub schema_version: String,
    pub attempt_id: String,
    pub trace_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub request_id: Option<String>,
    pub queue_id: Option<String>,
    pub coalescer_lease_id: Option<String>,
    pub proof_cache_key_hex: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub freshness_expires_at: DateTime<Utc>,
    pub command: FlightRecorderCommand,
    pub environment: FlightRecorderEnvironment,
    pub target_dir: FlightRecorderTargetDir,
    pub input_digests: Vec<InputDigest>,
    pub observations: Vec<FlightRecorderObservation>,
    pub adapter_outcome: Option<FlightRecorderAdapterOutcome>,
    pub exit: FlightRecorderExit,
    pub artifacts: FlightRecorderArtifacts,
    pub recovery_ref: Option<FlightRecorderRecoveryRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_ref: Option<ValidationReadinessRef>,
    pub trust: FlightRecorderTrust,
}

impl ValidationFlightRecorderAttempt {
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ValidationBrokerError> {
        if !constant_time::ct_eq(&self.schema_version, FLIGHT_RECORDER_ATTEMPT_SCHEMA_VERSION) {
            return flight_recorder_err(
                error_codes::ERR_VFR_INVALID_SCHEMA_VERSION,
                format!("unsupported attempt schema_version={}", self.schema_version),
            );
        }

        validate_non_empty_id(&self.attempt_id, "attempt_id")?;
        validate_non_empty_id(&self.trace_id, "trace_id")?;
        validate_non_empty_id(&self.bead_id, "bead_id")?;
        validate_non_empty_id(&self.thread_id, "thread_id")?;
        validate_optional_id(self.request_id.as_deref(), "request_id")?;
        validate_optional_id(self.queue_id.as_deref(), "queue_id")?;
        validate_optional_id(self.coalescer_lease_id.as_deref(), "coalescer_lease_id")?;
        if let Some(cache_key) = &self.proof_cache_key_hex {
            if !is_sha256_hex(cache_key) {
                return flight_recorder_err(
                    error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                    "proof_cache_key_hex must be a lowercase SHA-256 digest",
                );
            }
        }

        if !self.command.verifies() {
            return flight_recorder_err(
                error_codes::ERR_VFR_MISSING_COMMAND_DIGEST,
                "flight recorder command_digest does not match command material",
            );
        }
        self.environment.validate()?;
        self.target_dir.validate()?;

        if self.input_digests.is_empty()
            || self.input_digests.iter().any(|digest| !digest.is_valid())
        {
            return flight_recorder_err(
                error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                "flight recorder attempts require at least one valid input digest",
            );
        }

        validate_attempt_timestamps(self, now)?;
        validate_observations(&self.observations)?;

        if let Some(adapter_outcome) = &self.adapter_outcome {
            adapter_outcome.validate()?;
            validate_adapter_exit_compatibility(adapter_outcome, &self.exit)?;
        }
        self.exit.validate()?;
        self.artifacts.validate()?;
        if let Some(recovery_ref) = &self.recovery_ref {
            recovery_ref.validate()?;
        }
        validate_flight_recorder_readiness_ref(self, now)?;
        self.trust.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFlightRecorderRecovery {
    pub schema_version: String,
    pub decision_id: String,
    pub attempt_id: String,
    pub bead_id: String,
    pub thread_id: String,
    pub decided_at: DateTime<Utc>,
    pub input_digest: DigestRef,
    pub decision: FlightRecorderRecoveryDecision,
    pub reason_code: String,
    pub event_code: String,
    pub required_action: FlightRecorderRequiredAction,
    pub fail_closed: bool,
    pub retryable: bool,
    pub freshness_expires_at: DateTime<Utc>,
    pub operator_message: String,
    #[serde(default)]
    pub diagnostics: BTreeMap<String, String>,
}

impl ValidationFlightRecorderRecovery {
    pub fn validate_for_attempt(
        &self,
        attempt: &ValidationFlightRecorderAttempt,
        now: DateTime<Utc>,
    ) -> Result<(), ValidationBrokerError> {
        attempt.validate_at(now)?;
        if !constant_time::ct_eq(
            &self.schema_version,
            FLIGHT_RECORDER_RECOVERY_SCHEMA_VERSION,
        ) {
            return flight_recorder_err(
                error_codes::ERR_VFR_INVALID_SCHEMA_VERSION,
                format!(
                    "unsupported recovery schema_version={}",
                    self.schema_version
                ),
            );
        }
        validate_non_empty_id(&self.decision_id, "decision_id")?;
        if !constant_time::ct_eq(&self.attempt_id, &attempt.attempt_id)
            || !constant_time::ct_eq(&self.bead_id, &attempt.bead_id)
            || !constant_time::ct_eq(&self.thread_id, &attempt.thread_id)
        {
            return flight_recorder_err(
                error_codes::ERR_VFR_BEAD_MISMATCH,
                "recovery attempt/bead/thread references must match attempt artifact",
            );
        }
        if self.decided_at < attempt.created_at {
            return flight_recorder_err(
                error_codes::ERR_VFR_INVALID_RECOVERY_DECISION,
                "recovery decision cannot predate attempt creation",
            );
        }
        if self.freshness_expires_at < now {
            return flight_recorder_err(
                error_codes::ERR_VFR_STALE_ATTEMPT,
                "recovery decision freshness has expired",
            );
        }
        validate_digest(&self.input_digest, "recovery input_digest")?;
        validate_reason_event_pair(&self.reason_code, &self.event_code)?;
        validate_recovery_policy(self)?;
        validate_bounded_snippet(&self.operator_message, "operator_message")?;
        for (key, value) in &self.diagnostics {
            validate_non_empty_id(key, "recovery diagnostic key")?;
            validate_bounded_snippet(value, "recovery diagnostic value")?;
        }
        Ok(())
    }
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
    #[serde(default = "default_proof_evidence_source")]
    pub proof_source: ProofEvidenceSource,
    pub queue_state: Option<QueueState>,
    pub deduplicated: bool,
    pub queue_depth: usize,
    pub artifact_paths: Option<ProofArtifactPaths>,
    pub command_digest: Option<DigestRef>,
    pub exit: Option<ValidationExit>,
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_cache: Option<ValidationProofCacheReuseEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_ref: Option<ValidationReadinessRef>,
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
            proof_source: ProofEvidenceSource::Unknown,
            queue_state: None,
            deduplicated: false,
            queue_depth: 0,
            artifact_paths: None,
            command_digest: None,
            exit: None,
            reason: Some("no validation broker request or receipt matched".to_string()),
            proof_cache: None,
            readiness_ref: None,
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
            proof_source: ProofEvidenceSource::BrokerQueue,
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
            proof_cache: None,
            readiness_ref: None,
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
            proof_source: proof_source_from_receipt(receipt),
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
            proof_cache: None,
            readiness_ref: receipt.readiness_ref.clone(),
            observed_at,
        })
    }

    pub fn from_cache_reuse(
        receipt: &ValidationReceipt,
        proof_cache: ValidationProofCacheReuseEvidence,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ValidationBrokerError> {
        receipt.validate_at(observed_at)?;
        Ok(Self {
            schema_version: STATUS_SCHEMA_VERSION.to_string(),
            bead_id: receipt.bead_id.clone(),
            thread_id: receipt.thread_id.clone(),
            request_id: Some(receipt.request_id.clone()),
            queue_id: None,
            status: ProofStatusKind::Reused,
            proof_source: ProofEvidenceSource::ProofCacheHit,
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
            reason: Some(format!("proof cache hit: {}", proof_cache.reason_code)),
            proof_cache: Some(proof_cache),
            readiness_ref: receipt.readiness_ref.clone(),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_ref: Option<ValidationReadinessRef>,
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
        validate_receipt_readiness_ref(self, now)?;

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

fn flight_recorder_err<T>(
    code: &'static str,
    detail: impl Into<String>,
) -> Result<T, ValidationBrokerError> {
    contract_err(code, detail)
}

fn contract_err<T>(
    code: &'static str,
    detail: impl Into<String>,
) -> Result<T, ValidationBrokerError> {
    Err(ValidationBrokerError::ContractViolation {
        code,
        detail: detail.into(),
    })
}

fn validate_non_empty_id(value: &str, field: &str) -> Result<(), ValidationBrokerError> {
    if value.trim().is_empty() || value.contains('\0') {
        return flight_recorder_err(
            error_codes::ERR_VFR_MALFORMED_ATTEMPT,
            format!("{field} must be non-empty and free of NUL bytes"),
        );
    }
    Ok(())
}

fn validate_optional_id(value: Option<&str>, field: &str) -> Result<(), ValidationBrokerError> {
    if let Some(value) = value {
        validate_non_empty_id(value, field)?;
    }
    Ok(())
}

fn validate_no_nul(
    value: &str,
    code: &'static str,
    field: &str,
) -> Result<(), ValidationBrokerError> {
    if value.contains('\0') {
        return flight_recorder_err(code, format!("{field} must be free of NUL bytes"));
    }
    Ok(())
}

fn validate_non_empty_field(
    value: &str,
    field: &str,
    code: &'static str,
) -> Result<(), ValidationBrokerError> {
    if value.trim().is_empty() || value.contains('\0') {
        return contract_err(
            code,
            format!("{field} must be non-empty and free of NUL bytes"),
        );
    }
    Ok(())
}

fn validate_digest(digest: &DigestRef, field: &str) -> Result<(), ValidationBrokerError> {
    validate_digest_with_code(digest, field, error_codes::ERR_VFR_MALFORMED_ATTEMPT)
}

fn validate_digest_with_code(
    digest: &DigestRef,
    field: &str,
    code: &'static str,
) -> Result<(), ValidationBrokerError> {
    if !digest.is_valid_sha256() {
        return contract_err(code, format!("{field} must be a SHA-256 digest"));
    }
    Ok(())
}

fn validate_repo_relative_path(path: &str, field: &str) -> Result<(), ValidationBrokerError> {
    validate_repo_relative_path_with_code(path, field, error_codes::ERR_VFR_INVALID_ARTIFACT_PATH)
}

fn validate_repo_relative_path_with_code(
    path: &str,
    field: &str,
    code: &'static str,
) -> Result<(), ValidationBrokerError> {
    validate_no_nul(path, code, field)?;
    if path.trim().is_empty() {
        return contract_err(code, format!("{field} must be non-empty"));
    }

    let parsed = Path::new(path);
    if parsed.is_absolute()
        || parsed.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return contract_err(
            code,
            format!("{field} must be repo-relative without traversal"),
        );
    }

    Ok(())
}

fn validate_receipt_readiness_ref(
    receipt: &ValidationReceipt,
    now: DateTime<Utc>,
) -> Result<(), ValidationBrokerError> {
    let requires_readiness_ref = receipt
        .classifications
        .source_only_reason
        .is_some_and(SourceOnlyReason::requires_readiness_ref);
    match (
        &receipt.readiness_ref,
        receipt.classifications.source_only_reason,
    ) {
        (Some(readiness_ref), Some(reason)) if reason.requires_readiness_ref() => {
            readiness_ref.validate_for_receipt_at(now)?;
            if receipt.exit.kind != ValidationExitKind::SourceOnly
                || !receipt.classifications.source_only_fallback
                || receipt.exit.error_class != ValidationErrorClass::SourceOnly
            {
                return contract_err(
                    error_codes::ERR_VB_INVALID_READINESS_REF,
                    "readiness_ref is only valid for source-only proof-lane blockers",
                );
            }
            if !readiness_ref_reason_matches_source_only(reason, readiness_ref) {
                return contract_err(
                    error_codes::ERR_VB_INVALID_READINESS_REF,
                    "readiness_ref reason_code does not match source_only_reason",
                );
            }
        }
        (Some(_), _) => {
            return contract_err(
                error_codes::ERR_VB_INVALID_READINESS_REF,
                "readiness_ref requires a proof-lane source_only_reason",
            );
        }
        (None, _) if requires_readiness_ref => {
            return contract_err(
                error_codes::ERR_VB_INVALID_READINESS_REF,
                "proof-lane source-only closeout requires readiness_ref",
            );
        }
        (None, _) => {}
    }
    Ok(())
}

fn validate_flight_recorder_readiness_ref(
    attempt: &ValidationFlightRecorderAttempt,
    now: DateTime<Utc>,
) -> Result<(), ValidationBrokerError> {
    if let Some(readiness_ref) = &attempt.readiness_ref {
        readiness_ref.validate_for_flight_recorder_at(now)?;
        if !matches!(
            attempt.exit.kind,
            FlightRecorderExitKind::WorkerInfra | FlightRecorderExitKind::Deferred
        ) {
            return contract_err(
                error_codes::ERR_VFR_INVALID_READINESS_REF,
                "flight recorder readiness_ref is only valid for worker-infra or deferred attempts",
            );
        }
    }
    Ok(())
}

impl SourceOnlyReason {
    const fn requires_readiness_ref(self) -> bool {
        matches!(
            self,
            Self::ProofLaneWorkerAuthFailed
                | Self::ProofLaneOverrideNotHonored
                | Self::ProofLaneSameToolchainMissing
                | Self::ProofLaneLocalFallbackRefused
        )
    }
}

fn readiness_ref_reason_matches_source_only(
    reason: SourceOnlyReason,
    readiness_ref: &ValidationReadinessRef,
) -> bool {
    match reason {
        SourceOnlyReason::ProofLaneWorkerAuthFailed => constant_time::ct_eq(
            &readiness_ref.reason_code,
            readiness_ref_reason_codes::WORKER_AUTH_FAILED,
        ),
        SourceOnlyReason::ProofLaneOverrideNotHonored => constant_time::ct_eq(
            &readiness_ref.reason_code,
            readiness_ref_reason_codes::OVERRIDE_NOT_HONORED,
        ),
        SourceOnlyReason::ProofLaneSameToolchainMissing => constant_time::ct_eq(
            &readiness_ref.reason_code,
            readiness_ref_reason_codes::SAME_TOOLCHAIN_MISSING,
        ),
        SourceOnlyReason::ProofLaneLocalFallbackRefused => constant_time::ct_eq(
            &readiness_ref.reason_code,
            readiness_ref_reason_codes::LOCAL_FALLBACK_REFUSED,
        ),
        _ => false,
    }
}

fn validate_bounded_snippet(value: &str, field: &str) -> Result<(), ValidationBrokerError> {
    if value.len() > FLIGHT_RECORDER_MAX_SNIPPET_BYTES {
        return flight_recorder_err(
            error_codes::ERR_VFR_UNBOUNDED_SNIPPET,
            format!("{field} exceeds {FLIGHT_RECORDER_MAX_SNIPPET_BYTES} bytes"),
        );
    }
    validate_no_nul(value, error_codes::ERR_VFR_MALFORMED_ATTEMPT, field)
}

fn validate_attempt_timestamps(
    attempt: &ValidationFlightRecorderAttempt,
    now: DateTime<Utc>,
) -> Result<(), ValidationBrokerError> {
    if attempt.freshness_expires_at < now {
        return flight_recorder_err(
            error_codes::ERR_VFR_STALE_ATTEMPT,
            "flight recorder attempt freshness has expired",
        );
    }
    if let Some(started_at) = attempt.started_at {
        if started_at < attempt.created_at {
            return flight_recorder_err(
                error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                "started_at cannot predate created_at",
            );
        }
    }
    if let (Some(started_at), Some(finished_at)) = (attempt.started_at, attempt.finished_at) {
        if finished_at < started_at {
            return flight_recorder_err(
                error_codes::ERR_VFR_MALFORMED_ATTEMPT,
                "finished_at cannot predate started_at",
            );
        }
    }
    Ok(())
}

fn validate_observations(
    observations: &[FlightRecorderObservation],
) -> Result<(), ValidationBrokerError> {
    if observations.is_empty() || observations.len() > DEFAULT_MAX_FLIGHT_RECORDER_OBSERVATIONS {
        return flight_recorder_err(
            error_codes::ERR_VFR_INVALID_OBSERVATION_ORDER,
            format!(
                "flight recorder observations must contain 1..={DEFAULT_MAX_FLIGHT_RECORDER_OBSERVATIONS} entries"
            ),
        );
    }

    for observation in observations {
        observation.validate()?;
    }

    for pair in observations.windows(2) {
        let [left, right] = pair else {
            continue;
        };
        if left.observed_at > right.observed_at
            || (left.observed_at == right.observed_at && left.observation_id > right.observation_id)
        {
            return flight_recorder_err(
                error_codes::ERR_VFR_INVALID_OBSERVATION_ORDER,
                "flight recorder observations must be sorted by observed_at then observation_id",
            );
        }
    }

    Ok(())
}

fn validate_adapter_exit_compatibility(
    adapter_outcome: &FlightRecorderAdapterOutcome,
    exit: &FlightRecorderExit,
) -> Result<(), ValidationBrokerError> {
    let compatible = match adapter_outcome.outcome {
        FlightRecorderAdapterOutcomeClass::Passed => {
            matches!(exit.kind, FlightRecorderExitKind::Success)
        }
        FlightRecorderAdapterOutcomeClass::CommandFailed
        | FlightRecorderAdapterOutcomeClass::CompileFailed
        | FlightRecorderAdapterOutcomeClass::TestFailed => {
            matches!(exit.kind, FlightRecorderExitKind::Failure)
                && exit.product_failure
                && !exit.retryable
        }
        FlightRecorderAdapterOutcomeClass::WorkerTimeout => {
            matches!(exit.kind, FlightRecorderExitKind::Timeout)
                && timeout_classes_match(exit.timeout_class, adapter_outcome.timeout_class)
        }
        FlightRecorderAdapterOutcomeClass::WorkerMissingToolchain
        | FlightRecorderAdapterOutcomeClass::WorkerFilesystemError
        | FlightRecorderAdapterOutcomeClass::LocalFallbackRefused => {
            matches!(exit.kind, FlightRecorderExitKind::WorkerInfra)
                && !exit.product_failure
                && exit.retryable
        }
        FlightRecorderAdapterOutcomeClass::ContentionDeferred => {
            matches!(exit.kind, FlightRecorderExitKind::Deferred)
                && matches!(
                    exit.error_class,
                    ValidationErrorClass::EnvironmentContention
                )
        }
        FlightRecorderAdapterOutcomeClass::BrokerInternalError => {
            matches!(exit.kind, FlightRecorderExitKind::Failure)
                && !exit.retryable
                && !exit.product_failure
        }
    };

    if compatible {
        Ok(())
    } else {
        flight_recorder_err(
            error_codes::ERR_VFR_MALFORMED_ATTEMPT,
            "adapter outcome and flight recorder exit classification disagree",
        )
    }
}

fn timeout_classes_match(left: TimeoutClass, right: TimeoutClass) -> bool {
    matches!(
        (left, right),
        (TimeoutClass::None, TimeoutClass::None)
            | (TimeoutClass::QueueWait, TimeoutClass::QueueWait)
            | (TimeoutClass::RchDispatch, TimeoutClass::RchDispatch)
            | (TimeoutClass::SshCommand, TimeoutClass::SshCommand)
            | (
                TimeoutClass::CargoTestTimeout,
                TimeoutClass::CargoTestTimeout
            )
            | (TimeoutClass::ProcessIdle, TimeoutClass::ProcessIdle)
            | (TimeoutClass::ProcessWall, TimeoutClass::ProcessWall)
            | (
                TimeoutClass::WorkerUnreachable,
                TimeoutClass::WorkerUnreachable
            )
            | (TimeoutClass::Unknown, TimeoutClass::Unknown)
    )
}

fn is_known_flight_recorder_event_code(event_code: &str) -> bool {
    matches!(
        event_code,
        flight_recorder_event_codes::SUCCESS_REMOTE
            | flight_recorder_event_codes::RETRY_SSH_TIMEOUT
            | flight_recorder_event_codes::RETRY_MISSING_TOOLCHAIN
            | flight_recorder_event_codes::RETRY_WORKER_FS
            | flight_recorder_event_codes::QUEUE_CONTENTION
            | flight_recorder_event_codes::REJECT_LOCAL_FALLBACK
            | flight_recorder_event_codes::SOURCE_ONLY_ALLOWED
            | flight_recorder_event_codes::PRODUCT_FAILURE
            | flight_recorder_event_codes::STALE_PROGRESS
            | flight_recorder_event_codes::STALE_LEASE_FENCE
            | flight_recorder_event_codes::REUSE_RECEIPT
            | flight_recorder_event_codes::INVALID_ARTIFACT
    )
}

fn validate_reason_event_pair(reason: &str, event: &str) -> Result<(), ValidationBrokerError> {
    let valid = matches!(
        (reason, event),
        (
            flight_recorder_reason_codes::SUCCESS_REMOTE,
            flight_recorder_event_codes::SUCCESS_REMOTE
        ) | (
            flight_recorder_reason_codes::RETRY_SSH_TIMEOUT,
            flight_recorder_event_codes::RETRY_SSH_TIMEOUT
        ) | (
            flight_recorder_reason_codes::RETRY_MISSING_TOOLCHAIN,
            flight_recorder_event_codes::RETRY_MISSING_TOOLCHAIN
        ) | (
            flight_recorder_reason_codes::RETRY_WORKER_FS,
            flight_recorder_event_codes::RETRY_WORKER_FS
        ) | (
            flight_recorder_reason_codes::QUEUE_CONTENTION,
            flight_recorder_event_codes::QUEUE_CONTENTION
        ) | (
            flight_recorder_reason_codes::REJECT_LOCAL_FALLBACK,
            flight_recorder_event_codes::REJECT_LOCAL_FALLBACK
        ) | (
            flight_recorder_reason_codes::SOURCE_ONLY_ALLOWED,
            flight_recorder_event_codes::SOURCE_ONLY_ALLOWED
        ) | (
            flight_recorder_reason_codes::PRODUCT_FAILURE,
            flight_recorder_event_codes::PRODUCT_FAILURE
        ) | (
            flight_recorder_reason_codes::STALE_PROGRESS,
            flight_recorder_event_codes::STALE_PROGRESS
        ) | (
            flight_recorder_reason_codes::STALE_LEASE_FENCE,
            flight_recorder_event_codes::STALE_LEASE_FENCE
        ) | (
            flight_recorder_reason_codes::REUSE_RECEIPT,
            flight_recorder_event_codes::REUSE_RECEIPT
        ) | (
            flight_recorder_reason_codes::INVALID_ARTIFACT,
            flight_recorder_event_codes::INVALID_ARTIFACT
        )
    );

    if valid {
        Ok(())
    } else {
        flight_recorder_err(
            error_codes::ERR_VFR_INVALID_RECOVERY_DECISION,
            format!("reason_code={reason} does not match event_code={event}"),
        )
    }
}

fn validate_recovery_policy(
    recovery: &ValidationFlightRecorderRecovery,
) -> Result<(), ValidationBrokerError> {
    if !recovery_action_matches(recovery.decision, recovery.required_action) {
        return flight_recorder_err(
            error_codes::ERR_VFR_INVALID_RECOVERY_DECISION,
            "recovery decision and required_action disagree",
        );
    }

    let should_retry = matches!(
        recovery.decision,
        FlightRecorderRecoveryDecision::RetryRemoteSameWorker
            | FlightRecorderRecoveryDecision::RetryRemoteDifferentWorker
            | FlightRecorderRecoveryDecision::QueueUntilCapacity
            | FlightRecorderRecoveryDecision::DrainWorkerThenRetry
            | FlightRecorderRecoveryDecision::WaitForExistingProof
            | FlightRecorderRecoveryDecision::RetryWithNewFence
    );
    if bools_differ(recovery.retryable, should_retry) {
        return flight_recorder_err(
            error_codes::ERR_VFR_INVALID_RECOVERY_DECISION,
            "recovery retryable flag does not match decision",
        );
    }

    let should_fail_closed = matches!(
        recovery.decision,
        FlightRecorderRecoveryDecision::FailClosedProduct
            | FlightRecorderRecoveryDecision::FailClosedInvalid
            | FlightRecorderRecoveryDecision::UseSourceOnlyBlocker
    );
    if bools_differ(recovery.fail_closed, should_fail_closed) {
        return flight_recorder_err(
            error_codes::ERR_VFR_INVALID_RECOVERY_DECISION,
            "recovery fail_closed flag does not match decision",
        );
    }

    Ok(())
}

fn recovery_action_matches(
    decision: FlightRecorderRecoveryDecision,
    required_action: FlightRecorderRequiredAction,
) -> bool {
    matches!(
        (decision, required_action),
        (
            FlightRecorderRecoveryDecision::AcceptSuccess,
            FlightRecorderRequiredAction::None
        ) | (
            FlightRecorderRecoveryDecision::RetryRemoteSameWorker
                | FlightRecorderRecoveryDecision::RetryRemoteDifferentWorker,
            FlightRecorderRequiredAction::RetryRemote
        ) | (
            FlightRecorderRecoveryDecision::QueueUntilCapacity,
            FlightRecorderRequiredAction::WaitForCapacity
        ) | (
            FlightRecorderRecoveryDecision::DrainWorkerThenRetry,
            FlightRecorderRequiredAction::DrainWorker
        ) | (
            FlightRecorderRecoveryDecision::WaitForExistingProof,
            FlightRecorderRequiredAction::WaitForExistingProof
        ) | (
            FlightRecorderRecoveryDecision::RetryWithNewFence,
            FlightRecorderRequiredAction::RefreshLeaseFence
        ) | (
            FlightRecorderRecoveryDecision::ReuseReceipt,
            FlightRecorderRequiredAction::ReuseReceipt
        ) | (
            FlightRecorderRecoveryDecision::UseSourceOnlyBlocker,
            FlightRecorderRequiredAction::RecordSourceOnlyBlocker
        ) | (
            FlightRecorderRecoveryDecision::FailClosedProduct,
            FlightRecorderRequiredAction::SurfaceProductFailure
        ) | (
            FlightRecorderRecoveryDecision::FailClosedInvalid,
            FlightRecorderRequiredAction::RejectArtifact
        )
    )
}

fn bools_differ(left: bool, right: bool) -> bool {
    (left && !right) || (!left && right)
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

const fn default_proof_evidence_source() -> ProofEvidenceSource {
    ProofEvidenceSource::Unknown
}

fn proof_source_from_receipt(receipt: &ValidationReceipt) -> ProofEvidenceSource {
    if receipt.classifications.source_only_fallback
        || receipt.exit.kind == ValidationExitKind::SourceOnly
    {
        ProofEvidenceSource::SourceOnlyFallback
    } else {
        ProofEvidenceSource::FreshExecution
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
            readiness_ref: None,
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

    fn flight_adapter_outcome(
        outcome: FlightRecorderAdapterOutcomeClass,
    ) -> FlightRecorderAdapterOutcome {
        match outcome {
            FlightRecorderAdapterOutcomeClass::Passed => FlightRecorderAdapterOutcome {
                outcome,
                execution_mode: RchMode::Remote,
                worker_id: Some("ts2".to_string()),
                timeout_class: TimeoutClass::None,
                exit_code: Some(0),
                retryable: false,
                product_failure: false,
                reason_code: "RCH-PASSED".to_string(),
                detail: "remote RCH command completed successfully".to_string(),
            },
            FlightRecorderAdapterOutcomeClass::WorkerTimeout => FlightRecorderAdapterOutcome {
                outcome,
                execution_mode: RchMode::Unavailable,
                worker_id: Some("ts2".to_string()),
                timeout_class: TimeoutClass::SshCommand,
                exit_code: None,
                retryable: true,
                product_failure: false,
                reason_code: "RCH-WORKER-TIMEOUT".to_string(),
                detail: "[RCH-E104] SSH command timed out (no local fallback)".to_string(),
            },
            FlightRecorderAdapterOutcomeClass::WorkerMissingToolchain => {
                FlightRecorderAdapterOutcome {
                    outcome,
                    execution_mode: RchMode::Remote,
                    worker_id: Some("ts3".to_string()),
                    timeout_class: TimeoutClass::None,
                    exit_code: None,
                    retryable: true,
                    product_failure: false,
                    reason_code: "RCH-WORKER-MISSING-TOOLCHAIN".to_string(),
                    detail: "requested Rust toolchain is not installed".to_string(),
                }
            }
            FlightRecorderAdapterOutcomeClass::WorkerFilesystemError => {
                FlightRecorderAdapterOutcome {
                    outcome,
                    execution_mode: RchMode::Remote,
                    worker_id: Some("ts4".to_string()),
                    timeout_class: TimeoutClass::None,
                    exit_code: None,
                    retryable: true,
                    product_failure: false,
                    reason_code: "RCH-WORKER-FILESYSTEM".to_string(),
                    detail: "No space left on device".to_string(),
                }
            }
            FlightRecorderAdapterOutcomeClass::LocalFallbackRefused => {
                FlightRecorderAdapterOutcome {
                    outcome,
                    execution_mode: RchMode::LocalFallback,
                    worker_id: Some("local".to_string()),
                    timeout_class: TimeoutClass::None,
                    exit_code: None,
                    retryable: true,
                    product_failure: false,
                    reason_code: "RCH-LOCAL-FALLBACK-REFUSED".to_string(),
                    detail: "remote proof was required but RCH fell back locally".to_string(),
                }
            }
            FlightRecorderAdapterOutcomeClass::ContentionDeferred => FlightRecorderAdapterOutcome {
                outcome,
                execution_mode: RchMode::NotUsed,
                worker_id: None,
                timeout_class: TimeoutClass::QueueWait,
                exit_code: None,
                retryable: true,
                product_failure: false,
                reason_code: "RCH-CONTENTION-DEFERRED".to_string(),
                detail: "active cargo/rustc process count exceeds threshold".to_string(),
            },
            FlightRecorderAdapterOutcomeClass::CompileFailed => FlightRecorderAdapterOutcome {
                outcome,
                execution_mode: RchMode::Remote,
                worker_id: Some("ts2".to_string()),
                timeout_class: TimeoutClass::None,
                exit_code: Some(101),
                retryable: false,
                product_failure: true,
                reason_code: "RCH-COMPILE-FAILED".to_string(),
                detail: "cargo validation failed during compilation".to_string(),
            },
            FlightRecorderAdapterOutcomeClass::TestFailed => FlightRecorderAdapterOutcome {
                outcome,
                execution_mode: RchMode::Remote,
                worker_id: Some("ts2".to_string()),
                timeout_class: TimeoutClass::None,
                exit_code: Some(101),
                retryable: false,
                product_failure: true,
                reason_code: "RCH-TEST-FAILED".to_string(),
                detail: "cargo test reported failing tests".to_string(),
            },
            FlightRecorderAdapterOutcomeClass::CommandFailed => FlightRecorderAdapterOutcome {
                outcome,
                execution_mode: RchMode::Remote,
                worker_id: Some("ts2".to_string()),
                timeout_class: TimeoutClass::None,
                exit_code: Some(1),
                retryable: false,
                product_failure: true,
                reason_code: "RCH-COMMAND-FAILED".to_string(),
                detail: "RCH command exited non-zero".to_string(),
            },
            FlightRecorderAdapterOutcomeClass::BrokerInternalError => {
                FlightRecorderAdapterOutcome {
                    outcome,
                    execution_mode: RchMode::Unavailable,
                    worker_id: None,
                    timeout_class: TimeoutClass::Unknown,
                    exit_code: None,
                    retryable: false,
                    product_failure: false,
                    reason_code: "RCH-ADAPTER-POLICY".to_string(),
                    detail: "RCH adapter rejected the command policy".to_string(),
                }
            }
        }
    }

    fn flight_exit(outcome: FlightRecorderAdapterOutcomeClass) -> FlightRecorderExit {
        match outcome {
            FlightRecorderAdapterOutcomeClass::Passed => FlightRecorderExit {
                kind: FlightRecorderExitKind::Success,
                code: Some(0),
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::None,
                retryable: false,
                product_failure: false,
            },
            FlightRecorderAdapterOutcomeClass::WorkerTimeout => FlightRecorderExit {
                kind: FlightRecorderExitKind::Timeout,
                code: None,
                signal: None,
                timeout_class: TimeoutClass::SshCommand,
                error_class: ValidationErrorClass::TransportTimeout,
                retryable: true,
                product_failure: false,
            },
            FlightRecorderAdapterOutcomeClass::WorkerMissingToolchain => FlightRecorderExit {
                kind: FlightRecorderExitKind::WorkerInfra,
                code: None,
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::WorkerInfra,
                retryable: true,
                product_failure: false,
            },
            FlightRecorderAdapterOutcomeClass::WorkerFilesystemError => FlightRecorderExit {
                kind: FlightRecorderExitKind::WorkerInfra,
                code: None,
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::DiskPressure,
                retryable: true,
                product_failure: false,
            },
            FlightRecorderAdapterOutcomeClass::LocalFallbackRefused => FlightRecorderExit {
                kind: FlightRecorderExitKind::WorkerInfra,
                code: None,
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::WorkerInfra,
                retryable: true,
                product_failure: false,
            },
            FlightRecorderAdapterOutcomeClass::ContentionDeferred => FlightRecorderExit {
                kind: FlightRecorderExitKind::Deferred,
                code: None,
                signal: None,
                timeout_class: TimeoutClass::QueueWait,
                error_class: ValidationErrorClass::EnvironmentContention,
                retryable: true,
                product_failure: false,
            },
            FlightRecorderAdapterOutcomeClass::CompileFailed => FlightRecorderExit {
                kind: FlightRecorderExitKind::Failure,
                code: Some(101),
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::CompileError,
                retryable: false,
                product_failure: true,
            },
            FlightRecorderAdapterOutcomeClass::TestFailed => FlightRecorderExit {
                kind: FlightRecorderExitKind::Failure,
                code: Some(101),
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::TestFailure,
                retryable: false,
                product_failure: true,
            },
            FlightRecorderAdapterOutcomeClass::CommandFailed => FlightRecorderExit {
                kind: FlightRecorderExitKind::Failure,
                code: Some(1),
                signal: None,
                timeout_class: TimeoutClass::None,
                error_class: ValidationErrorClass::Unknown,
                retryable: false,
                product_failure: true,
            },
            FlightRecorderAdapterOutcomeClass::BrokerInternalError => FlightRecorderExit {
                kind: FlightRecorderExitKind::Failure,
                code: None,
                signal: None,
                timeout_class: TimeoutClass::Unknown,
                error_class: ValidationErrorClass::Unknown,
                retryable: false,
                product_failure: false,
            },
        }
    }

    fn recovery_contract(
        outcome: FlightRecorderAdapterOutcomeClass,
    ) -> (
        FlightRecorderRecoveryDecision,
        &'static str,
        &'static str,
        FlightRecorderRequiredAction,
        bool,
        bool,
    ) {
        match outcome {
            FlightRecorderAdapterOutcomeClass::Passed => (
                FlightRecorderRecoveryDecision::AcceptSuccess,
                flight_recorder_reason_codes::SUCCESS_REMOTE,
                flight_recorder_event_codes::SUCCESS_REMOTE,
                FlightRecorderRequiredAction::None,
                false,
                false,
            ),
            FlightRecorderAdapterOutcomeClass::WorkerTimeout => (
                FlightRecorderRecoveryDecision::RetryRemoteDifferentWorker,
                flight_recorder_reason_codes::RETRY_SSH_TIMEOUT,
                flight_recorder_event_codes::RETRY_SSH_TIMEOUT,
                FlightRecorderRequiredAction::RetryRemote,
                false,
                true,
            ),
            FlightRecorderAdapterOutcomeClass::WorkerMissingToolchain => (
                FlightRecorderRecoveryDecision::RetryRemoteDifferentWorker,
                flight_recorder_reason_codes::RETRY_MISSING_TOOLCHAIN,
                flight_recorder_event_codes::RETRY_MISSING_TOOLCHAIN,
                FlightRecorderRequiredAction::RetryRemote,
                false,
                true,
            ),
            FlightRecorderAdapterOutcomeClass::WorkerFilesystemError => (
                FlightRecorderRecoveryDecision::DrainWorkerThenRetry,
                flight_recorder_reason_codes::RETRY_WORKER_FS,
                flight_recorder_event_codes::RETRY_WORKER_FS,
                FlightRecorderRequiredAction::DrainWorker,
                false,
                true,
            ),
            FlightRecorderAdapterOutcomeClass::LocalFallbackRefused => (
                FlightRecorderRecoveryDecision::RetryRemoteDifferentWorker,
                flight_recorder_reason_codes::REJECT_LOCAL_FALLBACK,
                flight_recorder_event_codes::REJECT_LOCAL_FALLBACK,
                FlightRecorderRequiredAction::RetryRemote,
                false,
                true,
            ),
            FlightRecorderAdapterOutcomeClass::ContentionDeferred => (
                FlightRecorderRecoveryDecision::QueueUntilCapacity,
                flight_recorder_reason_codes::QUEUE_CONTENTION,
                flight_recorder_event_codes::QUEUE_CONTENTION,
                FlightRecorderRequiredAction::WaitForCapacity,
                false,
                true,
            ),
            FlightRecorderAdapterOutcomeClass::CompileFailed
            | FlightRecorderAdapterOutcomeClass::TestFailed
            | FlightRecorderAdapterOutcomeClass::CommandFailed => (
                FlightRecorderRecoveryDecision::FailClosedProduct,
                flight_recorder_reason_codes::PRODUCT_FAILURE,
                flight_recorder_event_codes::PRODUCT_FAILURE,
                FlightRecorderRequiredAction::SurfaceProductFailure,
                true,
                false,
            ),
            FlightRecorderAdapterOutcomeClass::BrokerInternalError => (
                FlightRecorderRecoveryDecision::FailClosedInvalid,
                flight_recorder_reason_codes::INVALID_ARTIFACT,
                flight_recorder_event_codes::INVALID_ARTIFACT,
                FlightRecorderRequiredAction::RejectArtifact,
                true,
                false,
            ),
        }
    }

    fn flight_attempt(
        outcome: FlightRecorderAdapterOutcomeClass,
    ) -> ValidationFlightRecorderAttempt {
        let adapter_outcome = flight_adapter_outcome(outcome);
        let (_, _, event_code, _, _, _) = recovery_contract(outcome);
        let mut captured_env = BTreeMap::new();
        captured_env.insert("RCH_REQUIRE_REMOTE".to_string(), "1".to_string());
        captured_env.insert(
            "SECRET_TOKEN".to_string(),
            FLIGHT_RECORDER_REDACTED_ENV_VALUE.to_string(),
        );

        ValidationFlightRecorderAttempt {
            schema_version: FLIGHT_RECORDER_ATTEMPT_SCHEMA_VERSION.to_string(),
            attempt_id: format!("vfr-attempt-bd-yn4xb-{}", event_code.to_ascii_lowercase()),
            trace_id: "trace-bd-yn4xb".to_string(),
            bead_id: "bd-yn4xb".to_string(),
            thread_id: "bd-yn4xb".to_string(),
            request_id: Some("vbreq-bd-yn4xb-1".to_string()),
            queue_id: Some("vbq-bd-yn4xb-1".to_string()),
            coalescer_lease_id: Some("vpcl-bd-yn4xb-1".to_string()),
            proof_cache_key_hex: Some("a".repeat(64)),
            created_at: ts(0),
            started_at: Some(ts(1)),
            finished_at: Some(ts(2)),
            freshness_expires_at: ts(10),
            command: FlightRecorderCommand::from_command_spec(&command()),
            environment: FlightRecorderEnvironment {
                policy_id: "validation-flight-recorder/env-policy/v1".to_string(),
                allowed_env: vec!["RCH_REQUIRE_REMOTE".to_string()],
                redacted_env: vec!["SECRET_TOKEN".to_string()],
                remote_required: true,
                network_policy: "rch-only".to_string(),
                captured_env,
            },
            target_dir: FlightRecorderTargetDir {
                class: FlightRecorderTargetDirClass::OffRepo,
                path: Some("/data/tmp/franken_node-pearlleopard-bd-yn4xb-target".to_string()),
                path_digest: Some(DigestRef::sha256(
                    b"/data/tmp/franken_node-pearlleopard-bd-yn4xb-target",
                )),
                repo_local: false,
                guarded_placeholder: false,
                writable_parent: Some(true),
                sync_root_digest: Some(DigestRef::sha256(b"rch-sync-root-summary")),
                diagnostic: "off-repo target dir selected for RCH validation".to_string(),
            },
            input_digests: vec![InputDigest::new(
                "crates/franken-node/src/ops/validation_broker.rs",
                b"flight-recorder-validation-model",
                "git-or-worktree",
            )],
            observations: vec![FlightRecorderObservation {
                schema_version: FLIGHT_RECORDER_OBSERVATION_SCHEMA_VERSION.to_string(),
                observation_id: "vfr-obs-0001".to_string(),
                observed_at: ts(2),
                phase: FlightRecorderObservationPhase::AdapterClassified,
                event_code: event_code.to_string(),
                worker_id: adapter_outcome.worker_id.clone(),
                rch_mode: adapter_outcome.execution_mode,
                queue_state: Some(QueueState::Running),
                message: adapter_outcome.detail.clone(),
                details: BTreeMap::from([(
                    "adapter_reason_code".to_string(),
                    adapter_outcome.reason_code.clone(),
                )]),
            }],
            adapter_outcome: Some(adapter_outcome),
            exit: flight_exit(outcome),
            artifacts: FlightRecorderArtifacts {
                attempt_path: "artifacts/validation_broker/bd-yn4xb/flight-recorder/attempt.vfr-attempt-bd-yn4xb.json".to_string(),
                stdout_path: "artifacts/validation_broker/bd-yn4xb/flight-recorder/stdout.vfr-attempt-bd-yn4xb.txt".to_string(),
                stderr_path: "artifacts/validation_broker/bd-yn4xb/flight-recorder/stderr.vfr-attempt-bd-yn4xb.txt".to_string(),
                summary_path: "artifacts/validation_broker/bd-yn4xb/flight-recorder/summary.vfr-attempt-bd-yn4xb.md".to_string(),
                recovery_path: Some("artifacts/validation_broker/bd-yn4xb/flight-recorder/recovery.vfr-attempt-bd-yn4xb.json".to_string()),
                stdout_digest: DigestRef::sha256(b"stdout"),
                stderr_digest: DigestRef::sha256(b"stderr"),
                stdout_snippet: Some("stdout".to_string()),
                stderr_snippet: Some("stderr".to_string()),
            },
            recovery_ref: Some(FlightRecorderRecoveryRef {
                decision_id: "vfr-recovery-bd-yn4xb-1".to_string(),
                path: "artifacts/validation_broker/bd-yn4xb/flight-recorder/recovery.vfr-attempt-bd-yn4xb.json".to_string(),
                digest: DigestRef::sha256(b"recovery"),
            }),
            readiness_ref: None,
            trust: FlightRecorderTrust {
                generated_by: "validation-flight-recorder".to_string(),
                agent_name: "PearlLeopard".to_string(),
                git_commit: "af6e4745".to_string(),
                dirty_worktree: true,
                freshness: "fresh".to_string(),
                signature_status: "unsigned-test".to_string(),
            },
        }
    }

    fn flight_recovery(
        attempt: &ValidationFlightRecorderAttempt,
        outcome: FlightRecorderAdapterOutcomeClass,
    ) -> ValidationFlightRecorderRecovery {
        let (decision, reason_code, event_code, required_action, fail_closed, retryable) =
            recovery_contract(outcome);

        ValidationFlightRecorderRecovery {
            schema_version: FLIGHT_RECORDER_RECOVERY_SCHEMA_VERSION.to_string(),
            decision_id: "vfr-recovery-bd-yn4xb-1".to_string(),
            attempt_id: attempt.attempt_id.clone(),
            bead_id: attempt.bead_id.clone(),
            thread_id: attempt.thread_id.clone(),
            decided_at: ts(3),
            input_digest: DigestRef::sha256(b"attempt-plus-policy"),
            decision,
            reason_code: reason_code.to_string(),
            event_code: event_code.to_string(),
            required_action,
            fail_closed,
            retryable,
            freshness_expires_at: ts(10),
            operator_message: "deterministic recovery action selected".to_string(),
            diagnostics: BTreeMap::from([("attempt_id".to_string(), attempt.attempt_id.clone())]),
        }
    }

    fn assert_contract_code(err: ValidationBrokerError, expected: &'static str) {
        assert!(matches!(
            err,
            ValidationBrokerError::ContractViolation { code, .. } if constant_time::ct_eq(code, expected)
        ));
    }

    #[test]
    fn flight_recorder_success_attempt_round_trips_and_validates() {
        let attempt = flight_attempt(FlightRecorderAdapterOutcomeClass::Passed);
        attempt
            .validate_at(ts(3))
            .expect("success attempt should validate");

        let json = serde_json::to_string_pretty(&attempt).expect("attempt serializes");
        let parsed: ValidationFlightRecorderAttempt =
            serde_json::from_str(&json).expect("attempt deserializes");
        parsed
            .validate_at(ts(3))
            .expect("round-tripped attempt should validate");

        let recovery = flight_recovery(&parsed, FlightRecorderAdapterOutcomeClass::Passed);
        recovery
            .validate_for_attempt(&parsed, ts(3))
            .expect("success recovery should validate");
    }

    #[test]
    fn flight_recorder_examples_cover_required_rch_classes() {
        for outcome in [
            FlightRecorderAdapterOutcomeClass::Passed,
            FlightRecorderAdapterOutcomeClass::WorkerTimeout,
            FlightRecorderAdapterOutcomeClass::ContentionDeferred,
            FlightRecorderAdapterOutcomeClass::LocalFallbackRefused,
            FlightRecorderAdapterOutcomeClass::WorkerMissingToolchain,
            FlightRecorderAdapterOutcomeClass::WorkerFilesystemError,
            FlightRecorderAdapterOutcomeClass::CompileFailed,
            FlightRecorderAdapterOutcomeClass::TestFailed,
        ] {
            let attempt = flight_attempt(outcome);
            attempt
                .validate_at(ts(3))
                .expect("flight recorder example should validate");

            let recovery = flight_recovery(&attempt, outcome);
            recovery
                .validate_for_attempt(&attempt, ts(3))
                .expect("flight recorder recovery should validate");
        }
    }

    #[test]
    fn flight_recorder_rejects_bad_command_digest() {
        let mut attempt = flight_attempt(FlightRecorderAdapterOutcomeClass::Passed);
        attempt.command.command_digest.hex = "0".repeat(64);

        let err = attempt
            .validate_at(ts(3))
            .expect_err("bad command digest should fail closed");
        assert_contract_code(err, error_codes::ERR_VFR_MISSING_COMMAND_DIGEST);
    }

    #[test]
    fn flight_recorder_rejects_absolute_artifact_path() {
        let mut attempt = flight_attempt(FlightRecorderAdapterOutcomeClass::Passed);
        attempt.artifacts.stdout_path = "/tmp/stdout.txt".to_string();

        let err = attempt
            .validate_at(ts(3))
            .expect_err("absolute artifact path should fail closed");
        assert_contract_code(err, error_codes::ERR_VFR_INVALID_ARTIFACT_PATH);
    }

    #[test]
    fn flight_recorder_rejects_unredacted_environment() {
        let mut attempt = flight_attempt(FlightRecorderAdapterOutcomeClass::Passed);
        attempt
            .environment
            .captured_env
            .insert("SECRET_TOKEN".to_string(), "raw-secret".to_string());

        let err = attempt
            .validate_at(ts(3))
            .expect_err("unredacted environment should fail closed");
        assert_contract_code(err, error_codes::ERR_VFR_UNREDACTED_ENVIRONMENT);
    }

    #[test]
    fn flight_recorder_rejects_unsorted_observation_timeline() {
        let mut attempt = flight_attempt(FlightRecorderAdapterOutcomeClass::Passed);
        let mut earlier = attempt
            .observations
            .first()
            .expect("attempt has one observation")
            .clone();
        earlier.observation_id = "vfr-obs-0000".to_string();
        earlier.observed_at = ts(1);
        attempt.observations.push(earlier);

        let err = attempt
            .validate_at(ts(3))
            .expect_err("unsorted observation timeline should fail closed");
        assert_contract_code(err, error_codes::ERR_VFR_INVALID_OBSERVATION_ORDER);
    }

    #[test]
    fn flight_recorder_rejects_unbounded_output_snippet() {
        let mut attempt = flight_attempt(FlightRecorderAdapterOutcomeClass::Passed);
        attempt.artifacts.stdout_snippet = Some("x".repeat(FLIGHT_RECORDER_MAX_SNIPPET_BYTES + 1));

        let err = attempt
            .validate_at(ts(3))
            .expect_err("unbounded snippet should fail closed");
        assert_contract_code(err, error_codes::ERR_VFR_UNBOUNDED_SNIPPET);
    }

    #[test]
    fn flight_recorder_rejects_recovery_action_mismatch() {
        let attempt = flight_attempt(FlightRecorderAdapterOutcomeClass::WorkerTimeout);
        let mut recovery =
            flight_recovery(&attempt, FlightRecorderAdapterOutcomeClass::WorkerTimeout);
        recovery.required_action = FlightRecorderRequiredAction::WaitForCapacity;

        let err = recovery
            .validate_for_attempt(&attempt, ts(3))
            .expect_err("recovery action mismatch should fail closed");
        assert_contract_code(err, error_codes::ERR_VFR_INVALID_RECOVERY_DECISION);
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
