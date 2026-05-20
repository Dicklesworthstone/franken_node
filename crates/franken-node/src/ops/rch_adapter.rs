//! RCH validation adapter and outcome classifier.
//!
//! The adapter keeps RCH proof failures from being collapsed into a generic
//! product failure. It validates that a command is an explicitly allowed cargo
//! validation command, refuses local fallback when remote execution is required,
//! and classifies worker/toolchain/timeout problems separately from compile and
//! test failures.

use crate::ops::validation_broker::{
    DigestRef, FlightRecorderAdapterOutcome, FlightRecorderAdapterOutcomeClass, InputDigest,
    RchMode, TimeoutClass,
};
use crate::security::constant_time;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub const RCH_ADAPTER_SCHEMA_VERSION: &str = "franken-node/rch-adapter/outcome/v1";
pub const RCH_ATTESTED_PROOF_RECEIPT_SCHEMA_VERSION: &str =
    "franken-node/rch-attested-proof-receipt/v1";
pub const RCH_PROOF_ATTESTATION_SCHEMA_VERSION: &str = "franken-node/rch-proof-attestation/v1";
pub const RCH_QUEUE_SNAPSHOT_CLASSIFICATION_SCHEMA_VERSION: &str =
    "franken-node/rch-queue-snapshot-classification/v1";
pub const DEFAULT_MAX_ACTIVE_CARGO_PROCESSES: usize = 2;
const RCH_COMMAND_DIGEST_DOMAIN: &str = "franken-node/rch-command-digest/v1";
const RCH_ATTESTATION_DIGEST_DOMAIN: &str = "franken-node/rch-attestation-digest/v1";
const SNIPPET_MAX_BYTES: usize = 4_096;

/// Maximum entries in env_allowlist to prevent DoS via oversized deserialized input.
const MAX_ENV_ALLOWLIST_ENTRIES: usize = 256;
/// Maximum source fingerprints to prevent DoS via oversized deserialized input.
const MAX_SOURCE_FINGERPRINTS: usize = 4_096;
/// Maximum redacted env keys to prevent DoS via oversized deserialized input.
const MAX_REDACTED_ENV_KEYS: usize = 256;
/// Maximum argv elements in an RCH invocation.
const MAX_INVOCATION_ARGV: usize = 128;

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn push_len_prefixed_field(material: &mut String, label: &str, value: &str) {
    material.push_str(label);
    material.push(':');
    material.push_str(&len_to_u64(value.len()).to_string());
    material.push(':');
    material.push_str(value);
    material.push('\0');
}

fn option_str_ct_eq(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => constant_time::ct_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchValidationAction {
    Build,
    Check,
    Clippy,
    Test,
    Fmt,
}

impl RchValidationAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Check => "check",
            Self::Clippy => "clippy",
            Self::Test => "test",
            Self::Fmt => "fmt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchOutcomeClass {
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

impl RchOutcomeClass {
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Passed)
    }

    #[must_use]
    pub const fn is_product_failure(self) -> bool {
        matches!(
            self,
            Self::CommandFailed | Self::CompileFailed | Self::TestFailed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchTimeoutClass {
    None,
    SshCommand,
    CargoTestTimeout,
    ProcessIdle,
    ProcessWall,
    WorkerUnreachable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchExecutionMode {
    Remote,
    LocalFallback,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchQueueSnapshotClass {
    FreshRunning,
    ProgressStale,
    QueueSaturated,
    WorkerUnreachable,
    SiblingApiDrift,
    ArtifactRetrievalFailed,
    LocalFallbackForbidden,
    UnknownFailClosed,
}

impl RchQueueSnapshotClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FreshRunning => "fresh_running",
            Self::ProgressStale => "progress_stale",
            Self::QueueSaturated => "queue_saturated",
            Self::WorkerUnreachable => "worker_unreachable",
            Self::SiblingApiDrift => "sibling_api_drift",
            Self::ArtifactRetrievalFailed => "artifact_retrieval_failed",
            Self::LocalFallbackForbidden => "local_fallback_forbidden",
            Self::UnknownFailClosed => "unknown_fail_closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchQueueSnapshotPolicy {
    pub max_queue_depth: u16,
    pub max_oldest_queued_age_seconds: u64,
    pub min_heartbeat_stale_seconds: u64,
    pub min_progress_stale_seconds: u64,
}

impl Default for RchQueueSnapshotPolicy {
    fn default() -> Self {
        Self {
            max_queue_depth: 8,
            max_oldest_queued_age_seconds: 600,
            min_heartbeat_stale_seconds: 300,
            min_progress_stale_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchQueueSnapshotInput {
    pub command_digest: String,
    pub worker_id: Option<String>,
    pub target_dir: Option<String>,
    pub package: Option<String>,
    pub test_target: Option<String>,
    pub queue_depth: u16,
    pub oldest_queued_age_seconds: Option<u64>,
    pub heartbeat_age_seconds: Option<u64>,
    pub progress_age_seconds: Option<u64>,
    pub worker_reachable: Option<bool>,
    pub remote_required: bool,
    pub local_fallback_observed: bool,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

impl RchQueueSnapshotInput {
    #[must_use]
    pub fn for_command(command_digest: impl Into<String>) -> Self {
        Self {
            command_digest: command_digest.into(),
            worker_id: None,
            target_dir: None,
            package: None,
            test_target: None,
            queue_depth: 0,
            oldest_queued_age_seconds: None,
            heartbeat_age_seconds: None,
            progress_age_seconds: None,
            worker_reachable: Some(true),
            remote_required: true,
            local_fallback_observed: false,
            stdout_tail: String::new(),
            stderr_tail: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchQueueSnapshotClassification {
    pub schema_version: String,
    pub command_digest: String,
    pub class: RchQueueSnapshotClass,
    pub reason_code: String,
    pub retryable: bool,
    pub product_failure: bool,
    pub infrastructure_failure: bool,
    pub worker_id: Option<String>,
    pub target_dir: Option<String>,
    pub package: Option<String>,
    pub test_target: Option<String>,
    pub evidence_snippet: String,
    pub recommended_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchCommandPolicy {
    pub require_remote: bool,
    pub max_active_cargo_processes: usize,
    pub allowed_package: Option<String>,
}

impl Default for RchCommandPolicy {
    fn default() -> Self {
        Self {
            require_remote: true,
            max_active_cargo_processes: DEFAULT_MAX_ACTIVE_CARGO_PROCESSES,
            allowed_package: Some("frankenengine-node".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchInvocation {
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: String,
}

impl RchInvocation {
    #[must_use]
    pub fn cargo(argv: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            env: BTreeMap::new(),
            cwd: String::new(),
        }
    }

    #[must_use]
    pub fn canonical_command(&self) -> String {
        let mut material = String::from(RCH_COMMAND_DIGEST_DOMAIN);
        material.push('\0');

        push_len_prefixed_field(&mut material, "cwd", &self.cwd);

        material.push_str("env_count:");
        material.push_str(&len_to_u64(self.env.len()).to_string());
        material.push('\0');
        for (key, value) in &self.env {
            push_len_prefixed_field(&mut material, "env_key", key);
            push_len_prefixed_field(&mut material, "env_value", value);
        }

        material.push_str("argv_count:");
        material.push_str(&len_to_u64(self.argv.len()).to_string());
        material.push('\0');
        for arg in &self.argv {
            push_len_prefixed_field(&mut material, "argv", arg);
        }

        material
    }

    #[must_use]
    pub fn command_digest(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_command().as_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedRchCommand {
    pub action: RchValidationAction,
    pub package: Option<String>,
    pub cargo_argv: Vec<String>,
    pub target_dir: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchProcessSnapshot {
    pub active_cargo_processes: usize,
    pub active_rch_processes: usize,
}

impl RchProcessSnapshot {
    #[must_use]
    pub const fn quiet() -> Self {
        Self {
            active_cargo_processes: 0,
            active_rch_processes: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchCommandOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

impl RchCommandOutput {
    #[must_use]
    pub fn combined_output(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchArtifactDigest {
    pub algorithm: String,
    pub hex: String,
    pub snippet: String,
}

impl RchArtifactDigest {
    #[must_use]
    pub fn from_output(output: &str) -> Self {
        let snippet = bounded_snippet(output);
        Self {
            algorithm: "sha256".to_string(),
            hex: hex::encode(Sha256::digest(output.as_bytes())),
            snippet,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchToolchainFingerprintInput {
    pub cargo_version: String,
    pub rustc_version: String,
    pub toolchain_channel: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchProofAttestationInput {
    pub env_allowlist: Vec<String>,
    pub toolchain: RchToolchainFingerprintInput,
    pub sync_root: Option<String>,
    pub target_dir: Option<String>,
    pub source_fingerprints: Vec<InputDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchProofAttestation {
    pub schema_version: String,
    pub command_digest: DigestRef,
    pub env_allowlist_fingerprint: DigestRef,
    pub toolchain_fingerprint: DigestRef,
    pub worker_id: Option<String>,
    pub worker_fingerprint: Option<DigestRef>,
    pub sync_root_fingerprint: Option<DigestRef>,
    pub target_dir_fingerprint: DigestRef,
    pub source_fingerprints: Vec<InputDigest>,
    pub redacted_env_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchAttestedProofReceipt {
    pub schema_version: String,
    pub outcome: RchAdapterOutcome,
    pub attestation: RchProofAttestation,
}

impl RchAttestedProofReceipt {
    pub fn validate(&self) -> Result<(), RchAdapterError> {
        if self.schema_version != RCH_ATTESTED_PROOF_RECEIPT_SCHEMA_VERSION {
            return Err(RchAdapterError::InvalidAttestationSchema {
                schema_version: self.schema_version.clone(),
            });
        }
        self.attestation.validate()?;
        if !constant_time::ct_eq(
            &self.outcome.command_digest,
            &self.attestation.command_digest.hex,
        ) {
            return Err(RchAdapterError::AttestationMismatch {
                field: "command_digest",
            });
        }
        if !option_str_ct_eq(
            self.outcome.worker_id.as_deref(),
            self.attestation.worker_id.as_deref(),
        ) {
            return Err(RchAdapterError::AttestationMismatch { field: "worker_id" });
        }
        if self.outcome.execution_mode == RchExecutionMode::Remote
            && self.attestation.worker_fingerprint.is_none()
        {
            return Err(RchAdapterError::MissingWorkerMetadata);
        }
        Ok(())
    }
}

impl RchProofAttestation {
    fn validate(&self) -> Result<(), RchAdapterError> {
        if self.schema_version != RCH_PROOF_ATTESTATION_SCHEMA_VERSION {
            return Err(RchAdapterError::InvalidAttestationSchema {
                schema_version: self.schema_version.clone(),
            });
        }

        // Bound checks to prevent DoS via oversized deserialized input.
        if self.source_fingerprints.len() > MAX_SOURCE_FINGERPRINTS {
            return Err(RchAdapterError::CollectionTooLarge {
                field: "source_fingerprints",
                max: MAX_SOURCE_FINGERPRINTS,
                actual: self.source_fingerprints.len(),
            });
        }
        if self.redacted_env_keys.len() > MAX_REDACTED_ENV_KEYS {
            return Err(RchAdapterError::CollectionTooLarge {
                field: "redacted_env_keys",
                max: MAX_REDACTED_ENV_KEYS,
                actual: self.redacted_env_keys.len(),
            });
        }

        for (field, digest) in [
            ("command_digest", &self.command_digest),
            ("env_allowlist_fingerprint", &self.env_allowlist_fingerprint),
            ("toolchain_fingerprint", &self.toolchain_fingerprint),
            ("target_dir_fingerprint", &self.target_dir_fingerprint),
        ] {
            if !digest.is_valid_sha256() {
                return Err(RchAdapterError::InvalidAttestationDigest { field });
            }
        }
        for (field, digest) in [
            ("worker_fingerprint", self.worker_fingerprint.as_ref()),
            ("sync_root_fingerprint", self.sync_root_fingerprint.as_ref()),
        ] {
            if let Some(digest) = digest
                && !digest.is_valid_sha256()
            {
                return Err(RchAdapterError::InvalidAttestationDigest { field });
            }
        }
        if self.source_fingerprints.is_empty() {
            return Err(RchAdapterError::MissingSourceFingerprints);
        }
        for fingerprint in &self.source_fingerprints {
            if !fingerprint.is_valid() {
                return Err(RchAdapterError::InvalidSourceFingerprint {
                    path: fingerprint.path.clone(),
                });
            }
        }
        Ok(())
    }
}

pub fn build_rch_attested_proof_receipt(
    invocation: &RchInvocation,
    outcome: RchAdapterOutcome,
    input: RchProofAttestationInput,
) -> Result<RchAttestedProofReceipt, RchAdapterError> {
    if outcome.execution_mode == RchExecutionMode::Remote && outcome.worker_id.is_none() {
        return Err(RchAdapterError::MissingWorkerMetadata);
    }

    // Bound checks on input collections to prevent DoS via oversized input.
    if invocation.argv.len() > MAX_INVOCATION_ARGV {
        return Err(RchAdapterError::CollectionTooLarge {
            field: "invocation.argv",
            max: MAX_INVOCATION_ARGV,
            actual: invocation.argv.len(),
        });
    }
    if input.env_allowlist.len() > MAX_ENV_ALLOWLIST_ENTRIES {
        return Err(RchAdapterError::CollectionTooLarge {
            field: "env_allowlist",
            max: MAX_ENV_ALLOWLIST_ENTRIES,
            actual: input.env_allowlist.len(),
        });
    }
    if input.source_fingerprints.len() > MAX_SOURCE_FINGERPRINTS {
        return Err(RchAdapterError::CollectionTooLarge {
            field: "source_fingerprints",
            max: MAX_SOURCE_FINGERPRINTS,
            actual: input.source_fingerprints.len(),
        });
    }

    let (_, inferred_target_dir) = normalize_cargo_argv(invocation)?;
    let target_dir = input
        .target_dir
        .clone()
        .or(inferred_target_dir)
        .unwrap_or_else(|| "unknown".to_string());
    let (env_allowlist_fingerprint, redacted_env_keys) =
        env_allowlist_fingerprint(invocation, &input.env_allowlist);

    let mut source_fingerprints = input.source_fingerprints.clone();
    source_fingerprints.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.algorithm.cmp(&right.algorithm))
            .then(left.hex.cmp(&right.hex))
            .then(left.source.cmp(&right.source))
    });

    let attestation = RchProofAttestation {
        schema_version: RCH_PROOF_ATTESTATION_SCHEMA_VERSION.to_string(),
        command_digest: DigestRef {
            algorithm: "sha256".to_string(),
            hex: invocation.command_digest(),
        },
        env_allowlist_fingerprint,
        toolchain_fingerprint: toolchain_fingerprint(&input.toolchain),
        worker_id: outcome.worker_id.clone(),
        worker_fingerprint: outcome
            .worker_id
            .as_deref()
            .map(|worker_id| digest_fields("worker", &[("worker_id", worker_id)])),
        sync_root_fingerprint: input
            .sync_root
            .as_deref()
            .map(|sync_root| digest_fields("sync_root", &[("path", sync_root)])),
        target_dir_fingerprint: digest_fields("target_dir", &[("path", &target_dir)]),
        source_fingerprints,
        redacted_env_keys,
    };

    let receipt = RchAttestedProofReceipt {
        schema_version: RCH_ATTESTED_PROOF_RECEIPT_SCHEMA_VERSION.to_string(),
        outcome,
        attestation,
    };
    receipt.validate()?;
    Ok(receipt)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchAdapterOutcome {
    pub schema_version: String,
    pub command_digest: String,
    pub action: Option<RchValidationAction>,
    pub package: Option<String>,
    pub outcome: RchOutcomeClass,
    pub execution_mode: RchExecutionMode,
    pub worker_id: Option<String>,
    pub timeout_class: RchTimeoutClass,
    pub exit_code: Option<i32>,
    pub retryable: bool,
    pub product_failure: bool,
    pub reason_code: String,
    pub detail: String,
    pub stdout_digest: RchArtifactDigest,
    pub stderr_digest: RchArtifactDigest,
    pub duration_ms: u64,
}

impl RchAdapterOutcome {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.outcome.is_success()
            && self.execution_mode == RchExecutionMode::Remote
            && !self.product_failure
    }

    /// Convert RCH adapter outcome to flight recorder adapter outcome for replayable attempt records.
    #[must_use]
    pub fn to_flight_recorder_adapter_outcome(&self) -> FlightRecorderAdapterOutcome {
        FlightRecorderAdapterOutcome {
            outcome: self.map_outcome_class(),
            execution_mode: self.map_execution_mode(),
            worker_id: self.worker_id.clone(),
            timeout_class: self.map_timeout_class(),
            exit_code: self.exit_code,
            retryable: self.retryable,
            product_failure: self.product_failure,
            reason_code: self.reason_code.clone(),
            detail: self.detail.clone(),
        }
    }

    fn map_outcome_class(&self) -> FlightRecorderAdapterOutcomeClass {
        match self.outcome {
            RchOutcomeClass::Passed => FlightRecorderAdapterOutcomeClass::Passed,
            RchOutcomeClass::CommandFailed => FlightRecorderAdapterOutcomeClass::CommandFailed,
            RchOutcomeClass::CompileFailed => FlightRecorderAdapterOutcomeClass::CompileFailed,
            RchOutcomeClass::TestFailed => FlightRecorderAdapterOutcomeClass::TestFailed,
            RchOutcomeClass::WorkerTimeout => FlightRecorderAdapterOutcomeClass::WorkerTimeout,
            RchOutcomeClass::WorkerMissingToolchain => {
                FlightRecorderAdapterOutcomeClass::WorkerMissingToolchain
            }
            RchOutcomeClass::WorkerFilesystemError => {
                FlightRecorderAdapterOutcomeClass::WorkerFilesystemError
            }
            RchOutcomeClass::LocalFallbackRefused => {
                FlightRecorderAdapterOutcomeClass::LocalFallbackRefused
            }
            RchOutcomeClass::ContentionDeferred => {
                FlightRecorderAdapterOutcomeClass::ContentionDeferred
            }
            RchOutcomeClass::BrokerInternalError => {
                FlightRecorderAdapterOutcomeClass::BrokerInternalError
            }
        }
    }

    fn map_execution_mode(&self) -> RchMode {
        match self.execution_mode {
            RchExecutionMode::Remote => RchMode::Remote,
            RchExecutionMode::LocalFallback => RchMode::LocalFallback,
            RchExecutionMode::Unavailable => RchMode::Unavailable,
            RchExecutionMode::Unknown => RchMode::Unavailable, // Map Unknown to Unavailable as closest match
        }
    }

    fn map_timeout_class(&self) -> TimeoutClass {
        match self.timeout_class {
            RchTimeoutClass::None => TimeoutClass::None,
            RchTimeoutClass::SshCommand => TimeoutClass::SshCommand,
            RchTimeoutClass::CargoTestTimeout => TimeoutClass::CargoTestTimeout,
            RchTimeoutClass::ProcessIdle => TimeoutClass::ProcessIdle,
            RchTimeoutClass::ProcessWall => TimeoutClass::ProcessWall,
            RchTimeoutClass::WorkerUnreachable => TimeoutClass::WorkerUnreachable,
            RchTimeoutClass::Unknown => TimeoutClass::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::validation_broker::{FlightRecorderAdapterOutcomeClass, RchMode, TimeoutClass};

    #[test]
    fn test_rch_adapter_outcome_to_flight_recorder_mapping() {
        let rch_outcome = RchAdapterOutcome {
            schema_version: "test/v1".to_string(),
            command_digest: "deadbeef".to_string(),
            action: Some(RchValidationAction::Check),
            package: Some("frankenengine-node".to_string()),
            outcome: RchOutcomeClass::Passed,
            execution_mode: RchExecutionMode::Remote,
            worker_id: Some("worker-123".to_string()),
            timeout_class: RchTimeoutClass::None,
            exit_code: Some(0),
            retryable: false,
            product_failure: false,
            reason_code: "RCH-S000".to_string(),
            detail: "successful validation".to_string(),
            stdout_digest: RchArtifactDigest {
                algorithm: "sha256".to_string(),
                hex: "abcd1234".to_string(),
                snippet: "success output".to_string(),
            },
            stderr_digest: RchArtifactDigest {
                algorithm: "sha256".to_string(),
                hex: "efgh5678".to_string(),
                snippet: "".to_string(),
            },
            duration_ms: 12345,
        };

        let flight_outcome = rch_outcome.to_flight_recorder_adapter_outcome();

        assert_eq!(
            flight_outcome.outcome,
            FlightRecorderAdapterOutcomeClass::Passed
        );
        assert_eq!(flight_outcome.execution_mode, RchMode::Remote);
        assert_eq!(flight_outcome.worker_id, Some("worker-123".to_string()));
        assert_eq!(flight_outcome.timeout_class, TimeoutClass::None);
        assert_eq!(flight_outcome.exit_code, Some(0));
        assert!(!flight_outcome.retryable);
        assert!(!flight_outcome.product_failure);
        assert_eq!(flight_outcome.reason_code, "RCH-S000");
        assert_eq!(flight_outcome.detail, "successful validation");
    }

    #[test]
    fn test_rch_adapter_outcome_mapping_worker_timeout() {
        let rch_outcome = RchAdapterOutcome {
            schema_version: "test/v1".to_string(),
            command_digest: "deadbeef".to_string(),
            action: Some(RchValidationAction::Check),
            package: Some("frankenengine-node".to_string()),
            outcome: RchOutcomeClass::WorkerTimeout,
            execution_mode: RchExecutionMode::Unavailable,
            worker_id: None,
            timeout_class: RchTimeoutClass::SshCommand,
            exit_code: None,
            retryable: true,
            product_failure: false,
            reason_code: "RCH-E104".to_string(),
            detail: "worker ssh connection timeout".to_string(),
            stdout_digest: RchArtifactDigest {
                algorithm: "sha256".to_string(),
                hex: "".to_string(),
                snippet: "".to_string(),
            },
            stderr_digest: RchArtifactDigest {
                algorithm: "sha256".to_string(),
                hex: "".to_string(),
                snippet: "timeout error".to_string(),
            },
            duration_ms: 30000,
        };

        let flight_outcome = rch_outcome.to_flight_recorder_adapter_outcome();

        assert_eq!(
            flight_outcome.outcome,
            FlightRecorderAdapterOutcomeClass::WorkerTimeout
        );
        assert_eq!(flight_outcome.execution_mode, RchMode::Unavailable);
        assert_eq!(flight_outcome.worker_id, None);
        assert_eq!(flight_outcome.timeout_class, TimeoutClass::SshCommand);
        assert_eq!(flight_outcome.exit_code, None);
        assert!(flight_outcome.retryable);
        assert!(!flight_outcome.product_failure);
        assert_eq!(flight_outcome.reason_code, "RCH-E104");
        assert_eq!(flight_outcome.detail, "worker ssh connection timeout");
    }

    #[test]
    fn test_rch_adapter_outcome_mapping_unknown_execution_mode() {
        // Test that RchExecutionMode::Unknown maps to RchMode::Unavailable
        let rch_outcome = RchAdapterOutcome {
            schema_version: "test/v1".to_string(),
            command_digest: "deadbeef".to_string(),
            action: Some(RchValidationAction::Build),
            package: None,
            outcome: RchOutcomeClass::BrokerInternalError,
            execution_mode: RchExecutionMode::Unknown,
            worker_id: None,
            timeout_class: RchTimeoutClass::Unknown,
            exit_code: Some(-1),
            retryable: false,
            product_failure: false,
            reason_code: "RCH-E999".to_string(),
            detail: "internal broker error".to_string(),
            stdout_digest: RchArtifactDigest {
                algorithm: "sha256".to_string(),
                hex: "".to_string(),
                snippet: "".to_string(),
            },
            stderr_digest: RchArtifactDigest {
                algorithm: "sha256".to_string(),
                hex: "".to_string(),
                snippet: "".to_string(),
            },
            duration_ms: 100,
        };

        let flight_outcome = rch_outcome.to_flight_recorder_adapter_outcome();

        assert_eq!(flight_outcome.execution_mode, RchMode::Unavailable);
        assert_eq!(flight_outcome.timeout_class, TimeoutClass::Unknown);
    }
}

#[derive(Debug, Error)]
pub enum RchAdapterError {
    #[error("empty RCH invocation argv")]
    EmptyInvocation,
    #[error("RCH adapter only accepts cargo validation commands, got program `{program}`")]
    UnsupportedProgram { program: String },
    #[error("RCH adapter command is missing a cargo action")]
    MissingAction,
    #[error("unsupported cargo validation action `{action}`")]
    UnsupportedAction { action: String },
    #[error("RCH adapter command must target package `{expected}`")]
    MissingPackage { expected: String },
    #[error("package `{actual}` is not allowed by this RCH policy; expected `{expected}`")]
    DisallowedPackage { expected: String, actual: String },
    #[error("RCH_REQUIRE_REMOTE=1 is required for this validation command")]
    MissingRemoteRequirement,
    #[error("remote RCH attestation requires worker metadata")]
    MissingWorkerMetadata,
    #[error("invalid RCH attestation schema version `{schema_version}`")]
    InvalidAttestationSchema { schema_version: String },
    #[error("invalid RCH attestation digest field `{field}`")]
    InvalidAttestationDigest { field: &'static str },
    #[error("RCH attestation source fingerprints are required")]
    MissingSourceFingerprints,
    #[error("invalid RCH attestation source fingerprint for `{path}`")]
    InvalidSourceFingerprint { path: String },
    #[error("RCH attestation field `{field}` does not match adapter outcome")]
    AttestationMismatch { field: &'static str },
    #[error("{field} exceeds maximum size {max} (got {actual})")]
    CollectionTooLarge {
        field: &'static str,
        max: usize,
        actual: usize,
    },
}

pub fn validate_allowed_rch_command(
    invocation: &RchInvocation,
    policy: &RchCommandPolicy,
) -> Result<AllowedRchCommand, RchAdapterError> {
    // Bound check to prevent DoS via oversized argv.
    if invocation.argv.len() > MAX_INVOCATION_ARGV {
        return Err(RchAdapterError::CollectionTooLarge {
            field: "invocation.argv",
            max: MAX_INVOCATION_ARGV,
            actual: invocation.argv.len(),
        });
    }

    let (cargo_argv, target_dir) = normalize_cargo_argv(invocation)?;
    let mut cursor = cargo_argv.iter();

    let Some(program) = cursor.next() else {
        return Err(RchAdapterError::EmptyInvocation);
    };
    if program != "cargo" {
        return Err(RchAdapterError::UnsupportedProgram {
            program: program.clone(),
        });
    }

    let Some(action_token) = cursor.find(|arg| !arg.starts_with('+')) else {
        return Err(RchAdapterError::MissingAction);
    };
    let action = parse_action(action_token)?;
    let package = package_from_args(&cargo_argv);

    if let Some(expected) = &policy.allowed_package {
        match &package {
            Some(actual) if actual == expected => {}
            Some(actual) => {
                return Err(RchAdapterError::DisallowedPackage {
                    expected: expected.clone(),
                    actual: actual.clone(),
                });
            }
            None => {
                return Err(RchAdapterError::MissingPackage {
                    expected: expected.clone(),
                });
            }
        }
    }

    if policy.require_remote && !requires_remote(invocation) {
        return Err(RchAdapterError::MissingRemoteRequirement);
    }

    Ok(AllowedRchCommand {
        action,
        package,
        cargo_argv,
        target_dir,
    })
}

pub fn classify_rch_output(
    invocation: &RchInvocation,
    output: &RchCommandOutput,
    process_snapshot: &RchProcessSnapshot,
    policy: &RchCommandPolicy,
) -> RchAdapterOutcome {
    let command = validate_allowed_rch_command(invocation, policy);
    let command_digest = invocation.command_digest();
    let combined = output.combined_output();
    let normalized = combined.to_ascii_lowercase();
    let execution_mode = execution_mode_from_output(&combined);
    let worker_id = worker_id_from_output(&combined);
    let stdout_digest = RchArtifactDigest::from_output(&output.stdout);
    let stderr_digest = RchArtifactDigest::from_output(&output.stderr);

    let (action, package, validation_error) = match command {
        Ok(command) => (Some(command.action), command.package, None),
        Err(error) => (None, None, Some(error.to_string())),
    };

    let classification = if let Some(detail) = validation_error {
        ClassifiedOutcome {
            outcome: RchOutcomeClass::BrokerInternalError,
            timeout_class: RchTimeoutClass::None,
            retryable: false,
            reason_code: "RCH-ADAPTER-POLICY".to_string(),
            detail,
        }
    } else if command_was_deferred(output)
        && process_snapshot.active_cargo_processes >= policy.max_active_cargo_processes
    {
        ClassifiedOutcome {
            outcome: RchOutcomeClass::ContentionDeferred,
            timeout_class: RchTimeoutClass::None,
            retryable: true,
            reason_code: "RCH-CONTENTION-DEFERRED".to_string(),
            detail: format!(
                "active cargo/rustc process count {} exceeds threshold {}",
                process_snapshot.active_cargo_processes, policy.max_active_cargo_processes
            ),
        }
    } else if let Some(worker_failure) = classify_worker_failure(&normalized) {
        worker_failure
    } else if policy.require_remote && execution_mode != RchExecutionMode::Remote {
        ClassifiedOutcome {
            outcome: RchOutcomeClass::LocalFallbackRefused,
            timeout_class: RchTimeoutClass::None,
            retryable: true,
            reason_code: "RCH-LOCAL-FALLBACK-REFUSED".to_string(),
            detail: "remote execution was required but no remote RCH completion marker was found"
                .to_string(),
        }
    } else {
        classify_normalized_output(output.exit_code, &normalized)
    };

    RchAdapterOutcome {
        schema_version: RCH_ADAPTER_SCHEMA_VERSION.to_string(),
        command_digest,
        action,
        package,
        outcome: classification.outcome,
        execution_mode,
        worker_id,
        timeout_class: classification.timeout_class,
        exit_code: output.exit_code,
        retryable: classification.retryable,
        product_failure: classification.outcome.is_product_failure(),
        reason_code: classification.reason_code,
        detail: classification.detail,
        stdout_digest,
        stderr_digest,
        duration_ms: output.duration_ms,
    }
}

#[must_use]
pub fn classify_rch_queue_snapshot(
    input: &RchQueueSnapshotInput,
    policy: &RchQueueSnapshotPolicy,
) -> RchQueueSnapshotClassification {
    let evidence = snapshot_evidence(input);
    let normalized = evidence.to_ascii_lowercase();

    let (class, reason_code, retryable, product_failure, infrastructure_failure, action) = if input
        .command_digest
        .trim()
        .is_empty()
    {
        (
            RchQueueSnapshotClass::UnknownFailClosed,
            "RCH-SNAPSHOT-MISSING-COMMAND-DIGEST",
            false,
            false,
            false,
            "Inspect the snapshot source; command identity is required before relying on it.",
        )
    } else if input.remote_required && input.local_fallback_observed {
        (
            RchQueueSnapshotClass::LocalFallbackForbidden,
            "RCH-SNAPSHOT-LOCAL-FALLBACK-FORBIDDEN",
            true,
            false,
            true,
            "Rerun through RCH only; do not treat local fallback output as proof.",
        )
    } else if contains_any(
        &normalized,
        &[
            "no space left on device",
            "artifact retrieval failed",
            "failed to retrieve artifact",
            "could not copy artifact",
        ],
    ) {
        (
            RchQueueSnapshotClass::ArtifactRetrievalFailed,
            "RCH-SNAPSHOT-ARTIFACT-RETRIEVAL",
            true,
            false,
            true,
            "Fix or redirect the artifact/target directory path before retrying the proof.",
        )
    } else if contains_any(
        &normalized,
        &[
            "frankensqlite",
            "franken_engine",
            "sibling api drift",
            "path dependency",
            "unresolved import",
        ],
    ) {
        (
            RchQueueSnapshotClass::SiblingApiDrift,
            "RCH-SNAPSHOT-SIBLING-API-DRIFT",
            false,
            true,
            false,
            "Track the sibling dependency drift as the blocker instead of rerunning identical proof work.",
        )
    } else if input.worker_reachable == Some(false)
        || input
            .heartbeat_age_seconds
            .is_some_and(|age| age >= policy.min_heartbeat_stale_seconds)
        || contains_any(
            &normalized,
            &[
                "worker unreachable",
                "connection refused",
                "ssh command timed out",
                "worker heartbeat stale",
            ],
        )
    {
        (
            RchQueueSnapshotClass::WorkerUnreachable,
            "RCH-SNAPSHOT-WORKER-UNREACHABLE",
            true,
            false,
            true,
            "Select a healthy worker or wait for RCH recovery before retrying the proof.",
        )
    } else if input.queue_depth >= policy.max_queue_depth
        || input
            .oldest_queued_age_seconds
            .is_some_and(|age| age >= policy.max_oldest_queued_age_seconds)
    {
        (
            RchQueueSnapshotClass::QueueSaturated,
            "RCH-SNAPSHOT-QUEUE-SATURATED",
            true,
            false,
            true,
            "Queue or defer the proof; keep working on source-only tasks until capacity returns.",
        )
    } else if input
        .progress_age_seconds
        .is_some_and(|age| age >= policy.min_progress_stale_seconds)
    {
        (
            RchQueueSnapshotClass::ProgressStale,
            "RCH-SNAPSHOT-PROGRESS-STALE",
            true,
            false,
            true,
            "Do not launch duplicates; wait, inspect, or cancel only the stale proof job.",
        )
    } else if input.heartbeat_age_seconds.is_some() || input.progress_age_seconds.is_some() {
        (
            RchQueueSnapshotClass::FreshRunning,
            "RCH-SNAPSHOT-FRESH-RUNNING",
            true,
            false,
            false,
            "Wait for the active proof verdict instead of starting duplicate validation.",
        )
    } else {
        (
            RchQueueSnapshotClass::UnknownFailClosed,
            "RCH-SNAPSHOT-UNKNOWN",
            false,
            false,
            false,
            "Gather a fresher RCH status or queue snapshot before relying on this result.",
        )
    };

    RchQueueSnapshotClassification {
        schema_version: RCH_QUEUE_SNAPSHOT_CLASSIFICATION_SCHEMA_VERSION.to_string(),
        command_digest: input.command_digest.clone(),
        class,
        reason_code: reason_code.to_string(),
        retryable,
        product_failure,
        infrastructure_failure,
        worker_id: input.worker_id.clone(),
        target_dir: input.target_dir.clone(),
        package: input.package.clone(),
        test_target: input.test_target.clone(),
        evidence_snippet: redact_snapshot_evidence(&evidence),
        recommended_action: action.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassifiedOutcome {
    outcome: RchOutcomeClass,
    timeout_class: RchTimeoutClass,
    retryable: bool,
    reason_code: String,
    detail: String,
}

fn classify_normalized_output(exit_code: Option<i32>, normalized: &str) -> ClassifiedOutcome {
    if let Some(worker_failure) = classify_worker_failure(normalized) {
        return worker_failure;
    }

    if exit_code == Some(0) {
        return ClassifiedOutcome {
            outcome: RchOutcomeClass::Passed,
            timeout_class: RchTimeoutClass::None,
            retryable: false,
            reason_code: "RCH-PASSED".to_string(),
            detail: "remote RCH command completed successfully".to_string(),
        };
    }

    if normalized.contains("test result: failed") || normalized.contains("\nfailures:\n") {
        return ClassifiedOutcome {
            outcome: RchOutcomeClass::TestFailed,
            timeout_class: RchTimeoutClass::None,
            retryable: false,
            reason_code: "RCH-TEST-FAILED".to_string(),
            detail: "cargo test reached execution and reported failing tests".to_string(),
        };
    }

    if normalized.contains("error[e") || normalized.contains("could not compile") {
        return ClassifiedOutcome {
            outcome: RchOutcomeClass::CompileFailed,
            timeout_class: RchTimeoutClass::None,
            retryable: false,
            reason_code: "RCH-COMPILE-FAILED".to_string(),
            detail: "cargo validation failed during compilation".to_string(),
        };
    }

    ClassifiedOutcome {
        outcome: RchOutcomeClass::CommandFailed,
        timeout_class: RchTimeoutClass::None,
        retryable: false,
        reason_code: "RCH-COMMAND-FAILED".to_string(),
        detail: "RCH command exited non-zero without a narrower classifier".to_string(),
    }
}

fn command_was_deferred(output: &RchCommandOutput) -> bool {
    output.exit_code.is_none() && output.stdout.trim().is_empty() && output.stderr.trim().is_empty()
}

fn classify_worker_failure(normalized: &str) -> Option<ClassifiedOutcome> {
    if contains_any(
        normalized,
        &[
            "[rch-e104]",
            "ssh command timed out",
            "rch command timed out",
        ],
    ) {
        return Some(ClassifiedOutcome {
            outcome: RchOutcomeClass::WorkerTimeout,
            timeout_class: RchTimeoutClass::SshCommand,
            retryable: true,
            reason_code: "RCH-WORKER-TIMEOUT".to_string(),
            detail: "RCH remote SSH command timed out without local fallback".to_string(),
        });
    }

    if normalized.contains("toolchain")
        && contains_any(
            normalized,
            &[
                "not installed",
                "is not installed",
                "no such toolchain",
                "toolchain not found",
            ],
        )
    {
        return Some(ClassifiedOutcome {
            outcome: RchOutcomeClass::WorkerMissingToolchain,
            timeout_class: RchTimeoutClass::None,
            retryable: true,
            reason_code: "RCH-WORKER-MISSING-TOOLCHAIN".to_string(),
            detail: "RCH worker is missing the requested Rust toolchain".to_string(),
        });
    }

    if contains_any(
        normalized,
        &[
            "no space left on device",
            "read-only file system",
            "permission denied",
            "failed to create directory",
            "could not create temp dir",
            "failed to read /dp/",
            "no such file or directory (os error 2)",
        ],
    ) {
        return Some(ClassifiedOutcome {
            outcome: RchOutcomeClass::WorkerFilesystemError,
            timeout_class: RchTimeoutClass::None,
            retryable: true,
            reason_code: "RCH-WORKER-FILESYSTEM".to_string(),
            detail: "RCH worker failed before product validation due to filesystem state"
                .to_string(),
        });
    }

    None
}

fn normalize_cargo_argv(
    invocation: &RchInvocation,
) -> Result<(Vec<String>, Option<String>), RchAdapterError> {
    if invocation.argv.is_empty() {
        return Err(RchAdapterError::EmptyInvocation);
    }

    let mut index = 0;
    let mut target_dir = invocation.env.get("CARGO_TARGET_DIR").cloned();

    if invocation.argv.first().is_some_and(|arg| arg == "env") {
        index = 1;
        while let Some(arg) = invocation.argv.get(index) {
            if !looks_like_env_assignment(arg) {
                break;
            }
            if let Some(value) = arg.strip_prefix("CARGO_TARGET_DIR=") {
                target_dir = Some(value.to_string());
            }
            index += 1;
        }
    }

    let Some(cargo_slice) = invocation.argv.get(index..) else {
        return Err(RchAdapterError::EmptyInvocation);
    };
    let cargo_argv = cargo_slice.to_vec();
    if cargo_argv.is_empty() {
        return Err(RchAdapterError::EmptyInvocation);
    }
    Ok((cargo_argv, target_dir))
}

fn parse_action(action: &str) -> Result<RchValidationAction, RchAdapterError> {
    match action {
        "build" => Ok(RchValidationAction::Build),
        "check" => Ok(RchValidationAction::Check),
        "clippy" => Ok(RchValidationAction::Clippy),
        "test" => Ok(RchValidationAction::Test),
        "fmt" => Ok(RchValidationAction::Fmt),
        other => Err(RchAdapterError::UnsupportedAction {
            action: other.to_string(),
        }),
    }
}

fn package_from_args(argv: &[String]) -> Option<String> {
    argv.iter()
        .enumerate()
        .find_map(|(index, arg)| match arg.as_str() {
            "-p" | "--package" => argv.get(index + 1).cloned(),
            _ => arg
                .strip_prefix("--package=")
                .map(std::string::ToString::to_string),
        })
}

fn requires_remote(invocation: &RchInvocation) -> bool {
    invocation
        .env
        .get("RCH_REQUIRE_REMOTE")
        .is_some_and(|value| remote_required_value_enabled(value))
        || env_wrapped_remote_requirement(invocation)
}

fn env_wrapped_remote_requirement(invocation: &RchInvocation) -> bool {
    if !invocation.argv.first().is_some_and(|arg| arg == "env") {
        return false;
    }

    for arg in invocation.argv.iter().skip(1) {
        if !looks_like_env_assignment(arg) {
            return false;
        }
        if arg
            .strip_prefix("RCH_REQUIRE_REMOTE=")
            .is_some_and(remote_required_value_enabled)
        {
            return true;
        }
    }
    false
}

fn remote_required_value_enabled(value: &str) -> bool {
    value == "1" || value.eq_ignore_ascii_case("true")
}

fn execution_mode_from_output(output: &str) -> RchExecutionMode {
    let normalized = output.to_ascii_lowercase();
    if normalized.contains("[rch] remote ") {
        RchExecutionMode::Remote
    } else if normalized.contains("rch unavailable") || normalized.contains("no local fallback") {
        RchExecutionMode::Unavailable
    } else if normalized.contains("[rch] local") || normalized.contains("local fallback") {
        RchExecutionMode::LocalFallback
    } else {
        RchExecutionMode::Unknown
    }
}

fn worker_id_from_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let marker = "[RCH] remote ";
        let start = line.find(marker)? + marker.len();
        let rest = line.get(start..)?;
        let worker = rest
            .split(|ch: char| ch.is_whitespace() || ch == '(')
            .find(|token| !token.is_empty())?;
        Some(worker.to_string())
    })
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn snapshot_evidence(input: &RchQueueSnapshotInput) -> String {
    let mut evidence = String::new();
    if let Some(worker_id) = &input.worker_id {
        push_len_prefixed_field(&mut evidence, "worker_id", worker_id);
    }
    if let Some(target_dir) = &input.target_dir {
        push_len_prefixed_field(&mut evidence, "target_dir", target_dir);
    }
    if let Some(package) = &input.package {
        push_len_prefixed_field(&mut evidence, "package", package);
    }
    if let Some(test_target) = &input.test_target {
        push_len_prefixed_field(&mut evidence, "test_target", test_target);
    }
    push_len_prefixed_field(&mut evidence, "stdout_tail", &input.stdout_tail);
    push_len_prefixed_field(&mut evidence, "stderr_tail", &input.stderr_tail);
    bounded_snippet(&evidence)
}

fn redact_snapshot_evidence(evidence: &str) -> String {
    let mut redacted = Vec::new();
    let mut suppress_sensitive_continuation = false;

    for token in evidence.split_whitespace() {
        let Some((key_prefix, _value)) = token.split_once('=') else {
            if token.contains('\0') {
                suppress_sensitive_continuation = false;
            }
            if !suppress_sensitive_continuation {
                redacted.push(token.to_string());
            }
            continue;
        };

        let key = env_key_from_assignment_prefix(key_prefix);
        if is_sensitive_env_key(key) {
            redacted.push(format!("{key}=<redacted>"));
            suppress_sensitive_continuation = true;
            continue;
        }

        suppress_sensitive_continuation = false;
        redacted.push(token.to_string());
    }

    redacted.join(" ")
}

fn env_key_from_assignment_prefix(prefix: &str) -> &str {
    let key_part = prefix.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_');
    key_part
        .rsplit(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .next()
        .unwrap_or(key_part)
}

#[cfg(test)]
fn old_whitespace_token_redaction(evidence: &str) -> String {
    evidence
        .split_whitespace()
        .map(|token| {
            let key = token
                .split_once('=')
                .map_or(token, |(key, _value)| env_key_from_assignment_prefix(key));
            if is_sensitive_env_key(key) {
                format!("{key}=<redacted>")
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn digest_fields(domain: &str, fields: &[(&str, &str)]) -> DigestRef {
    let mut material = String::from(RCH_ATTESTATION_DIGEST_DOMAIN);
    material.push('\0');
    push_len_prefixed_field(&mut material, "domain", domain);
    material.push_str("field_count:");
    material.push_str(&len_to_u64(fields.len()).to_string());
    material.push('\0');
    for (key, value) in fields {
        push_len_prefixed_field(&mut material, "key", key);
        push_len_prefixed_field(&mut material, "value", value);
    }
    DigestRef::sha256(material.as_bytes())
}

fn toolchain_fingerprint(input: &RchToolchainFingerprintInput) -> DigestRef {
    digest_fields(
        "toolchain",
        &[
            ("cargo_version", &input.cargo_version),
            ("rustc_version", &input.rustc_version),
            ("toolchain_channel", &input.toolchain_channel),
        ],
    )
}

fn env_allowlist_fingerprint(
    invocation: &RchInvocation,
    allowlist: &[String],
) -> (DigestRef, Vec<String>) {
    let mut keys = allowlist.to_vec();
    keys.sort();
    keys.dedup();

    let mut material = String::from(RCH_ATTESTATION_DIGEST_DOMAIN);
    material.push('\0');
    push_len_prefixed_field(&mut material, "domain", "env_allowlist");
    material.push_str("env_count:");
    material.push_str(&len_to_u64(keys.len()).to_string());
    material.push('\0');

    let mut redacted = Vec::new();
    for key in &keys {
        push_len_prefixed_field(&mut material, "env_key", key);
        if is_sensitive_env_key(key) {
            redacted.push(key.clone());
            push_len_prefixed_field(&mut material, "env_value", "<redacted>");
        } else if let Some(value) = invocation.env.get(key) {
            push_len_prefixed_field(&mut material, "env_value", value);
        } else {
            push_len_prefixed_field(&mut material, "env_value", "<missing>");
        }
    }

    (DigestRef::sha256(material.as_bytes()), redacted)
}

fn is_sensitive_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    contains_any(
        &upper,
        &[
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "API_KEY",
            "CREDENTIAL",
            "AUTH",
        ],
    )
}

fn bounded_snippet(output: &str) -> String {
    let mut snippet = String::new();
    for ch in output.chars() {
        let next_len = snippet.len() + ch.len_utf8();
        if next_len > SNIPPET_MAX_BYTES {
            break;
        }
        snippet.push(ch);
    }
    snippet
}

fn looks_like_env_assignment(arg: &str) -> bool {
    let Some((key, _value)) = arg.split_once('=') else {
        return false;
    };
    !key.is_empty()
        && key
            .bytes()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RchCommandPolicy {
        RchCommandPolicy::default()
    }

    fn invocation(argv: &[&str]) -> RchInvocation {
        let mut env = BTreeMap::new();
        env.insert("RCH_REQUIRE_REMOTE".to_string(), "1".to_string());
        RchInvocation {
            argv: argv.iter().map(|arg| (*arg).to_string()).collect(),
            env,
            cwd: "/data/projects/franken_node".to_string(),
        }
    }

    fn output(exit_code: i32, stdout: &str, stderr: &str) -> RchCommandOutput {
        RchCommandOutput {
            exit_code: Some(exit_code),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            duration_ms: 1_234,
        }
    }

    #[test]
    fn command_digest_length_prefixes_ambiguous_env_assignments() {
        let mut left_env = BTreeMap::new();
        left_env.insert("A".to_string(), "B=C".to_string());
        let left = RchInvocation {
            argv: vec!["cargo".to_string(), "check".to_string()],
            env: left_env,
            cwd: "/repo".to_string(),
        };

        let mut right_env = BTreeMap::new();
        right_env.insert("A=B".to_string(), "C".to_string());
        let right = RchInvocation {
            argv: vec!["cargo".to_string(), "check".to_string()],
            env: right_env,
            cwd: "/repo".to_string(),
        };

        let ambiguous_left = ["A", "B=C"].join("=");
        let ambiguous_right = ["A=B", "C"].join("=");
        let left_material = left.canonical_command();
        let right_material = right.canonical_command();

        assert_eq!("A=B=C", ambiguous_left);
        assert_eq!("A=B=C", ambiguous_right);
        assert!(left_material.starts_with("franken-node/rch-command-digest/v1\0"));
        assert!(left_material.contains("env_key:1:A\0env_value:3:B=C\0"));
        assert!(right_material.contains("env_key:3:A=B\0env_value:1:C\0"));
        assert_ne!(left_material, right_material);
        assert_ne!(left.command_digest(), right.command_digest());
    }

    #[test]
    fn validates_env_wrapped_cargo_command_and_target_dir() {
        let cmd = invocation(&[
            "env",
            "CARGO_TARGET_DIR=/data/tmp/franken_node-test-target",
            "cargo",
            "+nightly-2026-02-19",
            "test",
            "-p",
            "frankenengine-node",
            "--test",
            "idempotency_key_derivation",
        ]);

        let allowed = validate_allowed_rch_command(&cmd, &policy()).expect("allowed command");

        assert_eq!(allowed.action, RchValidationAction::Test);
        assert_eq!(allowed.package.as_deref(), Some("frankenengine-node"));
        assert_eq!(
            allowed.target_dir.as_deref(),
            Some("/data/tmp/franken_node-test-target")
        );
    }

    #[test]
    fn accepts_equals_form_package_flag() {
        let cmd = invocation(&["cargo", "check", "--package=frankenengine-node"]);

        let allowed = validate_allowed_rch_command(&cmd, &policy()).expect("allowed command");

        assert_eq!(allowed.action, RchValidationAction::Check);
        assert_eq!(allowed.package.as_deref(), Some("frankenengine-node"));
    }

    #[test]
    fn accepts_case_insensitive_env_wrapped_remote_requirement() {
        let cmd = RchInvocation {
            argv: [
                "env",
                "RCH_REQUIRE_REMOTE=True",
                "cargo",
                "check",
                "-p",
                "frankenengine-node",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            env: BTreeMap::new(),
            cwd: "/data/projects/franken_node".to_string(),
        };

        let allowed =
            validate_allowed_rch_command(&cmd, &policy()).expect("argv remote env is accepted");

        assert_eq!(allowed.action, RchValidationAction::Check);
        assert_eq!(allowed.package.as_deref(), Some("frankenengine-node"));
    }

    #[test]
    fn rejects_remote_requirement_smuggled_as_cargo_argument() {
        let cmd = RchInvocation {
            argv: [
                "cargo",
                "check",
                "-p",
                "frankenengine-node",
                "RCH_REQUIRE_REMOTE=1",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            env: BTreeMap::new(),
            cwd: "/data/projects/franken_node".to_string(),
        };

        let err = validate_allowed_rch_command(&cmd, &policy())
            .expect_err("cargo argv must not satisfy remote requirement");

        assert!(matches!(err, RchAdapterError::MissingRemoteRequirement));
    }

    #[test]
    fn rejects_commands_without_remote_requirement() {
        let cmd = RchInvocation::cargo(["cargo", "check", "-p", "frankenengine-node"]);

        let err = validate_allowed_rch_command(&cmd, &policy()).expect_err("missing remote env");

        assert!(matches!(err, RchAdapterError::MissingRemoteRequirement));
    }

    #[test]
    fn rejects_missing_package_when_policy_requires_one() {
        let cmd = invocation(&["cargo", "check", "--all-targets"]);

        let err = validate_allowed_rch_command(&cmd, &policy()).expect_err("missing package");

        assert!(matches!(err, RchAdapterError::MissingPackage { .. }));
    }

    #[test]
    fn remote_success_extracts_worker_and_is_green() {
        let cmd = invocation(&[
            "cargo",
            "check",
            "-p",
            "frankenengine-node",
            "--all-targets",
        ]);
        let result = output(
            0,
            "Finished `dev` profile\n[RCH] remote vmi1293453 (803.3s)\n",
            "",
        );

        let outcome = classify_rch_output(&cmd, &result, &RchProcessSnapshot::quiet(), &policy());

        assert_eq!(outcome.outcome, RchOutcomeClass::Passed);
        assert_eq!(outcome.execution_mode, RchExecutionMode::Remote);
        assert_eq!(outcome.worker_id.as_deref(), Some("vmi1293453"));
        assert!(outcome.is_green());
    }

    #[test]
    fn ssh_timeout_is_worker_timeout_not_product_failure() {
        let cmd = invocation(&["cargo", "test", "-p", "frankenengine-node"]);
        let result = output(
            101,
            "",
            "[RCH-E104] SSH command timed out (no local fallback)\n[RCH] remote ts2 (1800.0s)",
        );

        let outcome = classify_rch_output(&cmd, &result, &RchProcessSnapshot::quiet(), &policy());

        assert_eq!(outcome.outcome, RchOutcomeClass::WorkerTimeout);
        assert_eq!(outcome.timeout_class, RchTimeoutClass::SshCommand);
        assert!(!outcome.product_failure);
        assert!(outcome.retryable);
    }

    #[test]
    fn ssh_timeout_without_remote_summary_is_still_worker_timeout() {
        let cmd = invocation(&["cargo", "test", "-p", "frankenengine-node"]);
        let result = output(
            101,
            "",
            "[RCH-E104] SSH command timed out (no local fallback)",
        );

        let outcome = classify_rch_output(&cmd, &result, &RchProcessSnapshot::quiet(), &policy());

        assert_eq!(outcome.outcome, RchOutcomeClass::WorkerTimeout);
        assert_eq!(outcome.execution_mode, RchExecutionMode::Unavailable);
        assert!(!outcome.product_failure);
    }

    #[test]
    fn missing_toolchain_is_capability_drift() {
        let cmd = invocation(&[
            "cargo",
            "+nightly-2099-01-01",
            "check",
            "-p",
            "frankenengine-node",
        ]);
        let result = output(
            1,
            "",
            "error: toolchain 'nightly-2099-01-01-x86_64-unknown-linux-gnu' is not installed\n[RCH] remote ts2 (1.2s)",
        );

        let outcome = classify_rch_output(&cmd, &result, &RchProcessSnapshot::quiet(), &policy());

        assert_eq!(outcome.outcome, RchOutcomeClass::WorkerMissingToolchain);
        assert!(!outcome.product_failure);
        assert_eq!(outcome.execution_mode, RchExecutionMode::Remote);
    }

    #[test]
    fn worker_filesystem_error_is_not_compile_failure() {
        let cmd = invocation(&["cargo", "check", "-p", "frankenengine-node"]);
        let result = output(
            101,
            "",
            "error: failed to create directory `/data/tmp/foo`: No space left on device\n[RCH] remote ts2 (0.8s)",
        );

        let outcome = classify_rch_output(&cmd, &result, &RchProcessSnapshot::quiet(), &policy());

        assert_eq!(outcome.outcome, RchOutcomeClass::WorkerFilesystemError);
        assert!(!outcome.product_failure);
        assert!(outcome.retryable);
    }

    #[test]
    fn local_fallback_never_reports_green_when_remote_required() {
        let cmd = invocation(&["cargo", "check", "-p", "frankenengine-node"]);
        let result = output(0, "[RCH] local fallback\nFinished `dev` profile\n", "");

        let outcome = classify_rch_output(&cmd, &result, &RchProcessSnapshot::quiet(), &policy());

        assert_eq!(outcome.outcome, RchOutcomeClass::LocalFallbackRefused);
        assert_eq!(outcome.execution_mode, RchExecutionMode::LocalFallback);
        assert!(!outcome.is_green());
    }

    #[test]
    fn contention_defers_before_classifying_product_output() {
        let cmd = invocation(&["cargo", "check", "-p", "frankenengine-node"]);
        let result = RchCommandOutput {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        };
        let snapshot = RchProcessSnapshot {
            active_cargo_processes: 8,
            active_rch_processes: 3,
        };

        let outcome = classify_rch_output(&cmd, &result, &snapshot, &policy());

        assert_eq!(outcome.outcome, RchOutcomeClass::ContentionDeferred);
        assert!(!outcome.product_failure);
    }

    #[test]
    fn contention_defers_at_exact_active_cargo_cap() {
        let cmd = invocation(&["cargo", "check", "-p", "frankenengine-node"]);
        let result = RchCommandOutput {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        };
        let snapshot = RchProcessSnapshot {
            active_cargo_processes: policy().max_active_cargo_processes,
            active_rch_processes: 0,
        };

        let outcome = classify_rch_output(&cmd, &result, &snapshot, &policy());

        assert_eq!(outcome.outcome, RchOutcomeClass::ContentionDeferred);
        assert!(outcome.retryable);
        assert!(!outcome.product_failure);
    }

    #[test]
    fn completed_output_is_not_overridden_by_current_contention() {
        let cmd = invocation(&["cargo", "check", "-p", "frankenengine-node"]);
        let result = output(
            101,
            "",
            "error[E0425]: cannot find value\ncould not compile\n[RCH] remote ts2 (1.0s)",
        );
        let snapshot = RchProcessSnapshot {
            active_cargo_processes: 8,
            active_rch_processes: 3,
        };

        let outcome = classify_rch_output(&cmd, &result, &snapshot, &policy());

        assert_eq!(outcome.outcome, RchOutcomeClass::CompileFailed);
        assert!(outcome.product_failure);
    }

    #[test]
    fn compile_and_test_failures_are_product_failures() {
        let check_cmd = invocation(&["cargo", "check", "-p", "frankenengine-node"]);
        let compile = output(
            101,
            "",
            "error[E0599]: no method\ncould not compile\n[RCH] remote ts2",
        );
        let compile_outcome = classify_rch_output(
            &check_cmd,
            &compile,
            &RchProcessSnapshot::quiet(),
            &policy(),
        );

        let test_cmd = invocation(&["cargo", "test", "-p", "frankenengine-node"]);
        let test = output(
            101,
            "test result: FAILED. 0 passed; 1 failed\n[RCH] remote ts2",
            "",
        );
        let test_outcome =
            classify_rch_output(&test_cmd, &test, &RchProcessSnapshot::quiet(), &policy());

        assert_eq!(compile_outcome.outcome, RchOutcomeClass::CompileFailed);
        assert!(compile_outcome.product_failure);
        assert_eq!(test_outcome.outcome, RchOutcomeClass::TestFailed);
        assert!(test_outcome.product_failure);
    }

    #[test]
    fn rejects_oversized_argv_in_validate_allowed_rch_command() {
        let oversized_argv: Vec<String> = (0..MAX_INVOCATION_ARGV + 1)
            .map(|i| format!("arg{i}"))
            .collect();
        let cmd = RchInvocation {
            argv: oversized_argv,
            env: BTreeMap::new(),
            cwd: "/repo".to_string(),
        };

        let err = validate_allowed_rch_command(&cmd, &policy()).expect_err("oversized argv");

        assert!(matches!(
            err,
            RchAdapterError::CollectionTooLarge {
                field: "invocation.argv",
                max: MAX_INVOCATION_ARGV,
                ..
            }
        ));
    }

    #[test]
    fn rejects_oversized_source_fingerprints_in_attestation_validate() {
        let oversized_fingerprints: Vec<InputDigest> = (0..MAX_SOURCE_FINGERPRINTS + 1)
            .map(|i| InputDigest {
                path: format!("file{i}.rs"),
                algorithm: "sha256".to_string(),
                hex: "a".repeat(64),
                source: "test".to_string(),
            })
            .collect();

        let attestation = RchProofAttestation {
            schema_version: RCH_PROOF_ATTESTATION_SCHEMA_VERSION.to_string(),
            command_digest: DigestRef::sha256(b"test"),
            env_allowlist_fingerprint: DigestRef::sha256(b"env"),
            toolchain_fingerprint: DigestRef::sha256(b"toolchain"),
            worker_id: Some("worker".to_string()),
            worker_fingerprint: Some(DigestRef::sha256(b"worker")),
            sync_root_fingerprint: None,
            target_dir_fingerprint: DigestRef::sha256(b"target"),
            source_fingerprints: oversized_fingerprints,
            redacted_env_keys: Vec::new(),
        };

        let err = attestation
            .validate()
            .expect_err("oversized source_fingerprints");

        assert!(matches!(
            err,
            RchAdapterError::CollectionTooLarge {
                field: "source_fingerprints",
                max: MAX_SOURCE_FINGERPRINTS,
                ..
            }
        ));
    }

    #[test]
    fn rejects_oversized_redacted_env_keys_in_attestation_validate() {
        let oversized_keys: Vec<String> = (0..MAX_REDACTED_ENV_KEYS + 1)
            .map(|i| format!("KEY{i}"))
            .collect();

        let attestation = RchProofAttestation {
            schema_version: RCH_PROOF_ATTESTATION_SCHEMA_VERSION.to_string(),
            command_digest: DigestRef::sha256(b"test"),
            env_allowlist_fingerprint: DigestRef::sha256(b"env"),
            toolchain_fingerprint: DigestRef::sha256(b"toolchain"),
            worker_id: Some("worker".to_string()),
            worker_fingerprint: Some(DigestRef::sha256(b"worker")),
            sync_root_fingerprint: None,
            target_dir_fingerprint: DigestRef::sha256(b"target"),
            source_fingerprints: vec![InputDigest {
                path: "src/main.rs".to_string(),
                algorithm: "sha256".to_string(),
                hex: "a".repeat(64),
                source: "test".to_string(),
            }],
            redacted_env_keys: oversized_keys,
        };

        let err = attestation
            .validate()
            .expect_err("oversized redacted_env_keys");

        assert!(matches!(
            err,
            RchAdapterError::CollectionTooLarge {
                field: "redacted_env_keys",
                max: MAX_REDACTED_ENV_KEYS,
                ..
            }
        ));
    }

    #[test]
    fn snapshot_redaction_suppresses_spaced_secret_continuations() {
        let mut evidence = String::new();
        push_len_prefixed_field(
            &mut evidence,
            "stdout_tail",
            "API_TOKEN=alpha beta gamma regular=value",
        );

        let old = old_whitespace_token_redaction(&evidence);
        assert!(old.contains("beta"));
        assert!(old.contains("gamma"));

        let redacted = redact_snapshot_evidence(&evidence);
        assert!(redacted.contains("API_TOKEN=<redacted>"));
        assert!(!redacted.contains("alpha"));
        assert!(!redacted.contains("beta"));
        assert!(!redacted.contains("gamma"));
        assert!(redacted.contains("regular=value"));
    }
}
