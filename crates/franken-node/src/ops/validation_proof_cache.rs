//! Content-addressed validation proof cache primitives.
//!
//! The cache is intentionally isolated from existing validation flows until the
//! downstream integration bead wires it in. A lookup only returns a hit after the
//! cache entry and its underlying validation broker receipt both validate.

use crate::ops::validation_broker::{
    self, CommandDigest, InputDigest, ValidationBrokerRequest, ValidationReceipt,
};
use crate::security::constant_time;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

pub const KEY_SCHEMA_VERSION: &str = "franken-node/validation-proof-cache/key/v1";
pub const ENTRY_SCHEMA_VERSION: &str = "franken-node/validation-proof-cache/entry/v1";
pub const DECISION_SCHEMA_VERSION: &str = "franken-node/validation-proof-cache/decision/v1";
pub const GC_REPORT_SCHEMA_VERSION: &str = "franken-node/validation-proof-cache/gc-report/v1";
const SHA256_HEX_LEN: usize = 64;

pub mod error_codes {
    pub const ERR_VPC_INVALID_SCHEMA_VERSION: &str = "ERR_VPC_INVALID_SCHEMA_VERSION";
    pub const ERR_VPC_MALFORMED_KEY: &str = "ERR_VPC_MALFORMED_KEY";
    pub const ERR_VPC_MALFORMED_ENTRY: &str = "ERR_VPC_MALFORMED_ENTRY";
    pub const ERR_VPC_MALFORMED_DECISION: &str = "ERR_VPC_MALFORMED_DECISION";
    pub const ERR_VPC_BAD_CACHE_KEY: &str = "ERR_VPC_BAD_CACHE_KEY";
    pub const ERR_VPC_RECEIPT_DIGEST_MISMATCH: &str = "ERR_VPC_RECEIPT_DIGEST_MISMATCH";
    pub const ERR_VPC_COMMAND_DIGEST_MISMATCH: &str = "ERR_VPC_COMMAND_DIGEST_MISMATCH";
    pub const ERR_VPC_INPUT_DIGEST_MISMATCH: &str = "ERR_VPC_INPUT_DIGEST_MISMATCH";
    pub const ERR_VPC_STALE_ENTRY: &str = "ERR_VPC_STALE_ENTRY";
    pub const ERR_VPC_DIRTY_STATE_MISMATCH: &str = "ERR_VPC_DIRTY_STATE_MISMATCH";
    pub const ERR_VPC_POLICY_MISMATCH: &str = "ERR_VPC_POLICY_MISMATCH";
    pub const ERR_VPC_QUOTA_BLOCKED: &str = "ERR_VPC_QUOTA_BLOCKED";
    pub const ERR_VPC_CORRUPTED_ENTRY: &str = "ERR_VPC_CORRUPTED_ENTRY";
    pub const ERR_VPC_DUPLICATE_ENTRY: &str = "ERR_VPC_DUPLICATE_ENTRY";
}

pub mod event_codes {
    pub const LOOKUP_STARTED: &str = "VPC-001";
    pub const HIT_ACCEPTED: &str = "VPC-002";
    pub const MISS_RECORDED: &str = "VPC-003";
    pub const STALE_REJECTED: &str = "VPC-004";
    pub const RECEIPT_DIGEST_REJECTED: &str = "VPC-005";
    pub const COMMAND_OR_INPUT_REJECTED: &str = "VPC-006";
    pub const POLICY_REJECTED: &str = "VPC-007";
    pub const QUOTA_REJECTED: &str = "VPC-008";
    pub const CORRUPTED_REJECTED: &str = "VPC-009";
    pub const GC_REMOVAL_RECORDED: &str = "VPC-010";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirtyStatePolicy {
    CleanRequired,
    DirtyAllowedWithDigest,
    SourceOnlyDocumented,
}

impl DirtyStatePolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CleanRequired => "clean_required",
            Self::DirtyAllowedWithDigest => "dirty_allowed_with_digest",
            Self::SourceOnlyDocumented => "source_only_documented",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheScope {
    pub dirty_state_policy: DirtyStatePolicy,
    pub cargo_toolchain: String,
    pub package: String,
    pub test_target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCacheDigest {
    pub algorithm: String,
    pub hex: String,
    pub canonical_material: String,
}

impl ProofCacheDigest {
    #[must_use]
    pub fn sha256_material(material: String) -> Self {
        Self {
            algorithm: "sha256".to_string(),
            hex: hex::encode(Sha256::digest(material.as_bytes())),
            canonical_material: material,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheKey {
    pub schema_version: String,
    pub key_id: String,
    pub algorithm: String,
    pub hex: String,
    pub canonical_material: String,
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

impl ValidationProofCacheKey {
    pub fn from_request_and_receipt(
        request: &ValidationBrokerRequest,
        receipt: &ValidationReceipt,
        scope: ValidationProofCacheScope,
    ) -> Result<Self, ValidationProofCacheError> {
        validate_request_receipt_scope(request, receipt)?;
        if matches!(scope.dirty_state_policy, DirtyStatePolicy::CleanRequired)
            && (request.inputs.dirty_worktree || receipt.trust.dirty_worktree)
        {
            return Err(ValidationProofCacheError::contract(
                error_codes::ERR_VPC_DIRTY_STATE_MISMATCH,
                "clean_required proof cache key cannot be built from dirty worktree material",
            ));
        }

        let mut input_digests = receipt.input_digests.clone();
        sort_input_digests(&mut input_digests);
        let mut feature_flags = request.inputs.feature_flags.clone();
        feature_flags.sort();
        feature_flags.dedup();

        let canonical_material = canonical_key_material(
            &receipt.command_digest,
            &input_digests,
            &request.inputs.git_commit,
            request.inputs.dirty_worktree,
            scope.dirty_state_policy,
            &feature_flags,
            &scope.cargo_toolchain,
            &scope.package,
            &scope.test_target,
            &receipt.environment_policy.policy_id,
            &receipt.target_dir_policy.policy_id,
        );
        let hex = hex::encode(Sha256::digest(canonical_material.as_bytes()));
        Ok(Self {
            schema_version: KEY_SCHEMA_VERSION.to_string(),
            key_id: format!("vpckey-{}", key_hex_prefix(&hex, 16)),
            algorithm: "sha256".to_string(),
            hex,
            canonical_material,
            command_digest: receipt.command_digest.clone(),
            input_digests,
            git_commit: request.inputs.git_commit.clone(),
            dirty_worktree: request.inputs.dirty_worktree,
            dirty_state_policy: scope.dirty_state_policy,
            feature_flags,
            cargo_toolchain: scope.cargo_toolchain,
            package: scope.package,
            test_target: scope.test_target,
            environment_policy_id: receipt.environment_policy.policy_id.clone(),
            target_dir_policy_id: receipt.target_dir_policy.policy_id.clone(),
        })
    }

    #[must_use]
    pub fn verifies(&self) -> bool {
        if !string_eq(&self.schema_version, KEY_SCHEMA_VERSION)
            || !string_eq(&self.algorithm, "sha256")
            || !is_sha256_hex(&self.hex)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheReceiptRef {
    pub receipt_id: String,
    pub path: String,
    pub bead_id: String,
    pub command_digest: CommandDigest,
    pub input_digests: Vec<InputDigest>,
    pub dirty_worktree: bool,
    pub dirty_state_policy: DirtyStatePolicy,
    pub environment_policy_id: String,
    pub target_dir_policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheTrust {
    pub state: String,
    pub git_commit: String,
    pub signature_status: String,
    pub dirty_worktree: bool,
    pub dirty_state_policy: DirtyStatePolicy,
    pub environment_policy_id: String,
    pub target_dir_policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheReuse {
    pub count: u64,
    pub last_reused_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheStorage {
    pub path: String,
    pub bytes: u64,
    pub quota_class: String,
    pub retention_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheInvalidation {
    pub active: bool,
    pub reason: Option<String>,
    pub corrupted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheEntry {
    pub schema_version: String,
    pub entry_id: String,
    pub cache_key: ValidationProofCacheKey,
    pub bead_id: String,
    pub receipt_ref: ValidationProofCacheReceiptRef,
    pub receipt_digest: ProofCacheDigest,
    pub producer_agent: String,
    pub created_at: DateTime<Utc>,
    pub freshness_expires_at: DateTime<Utc>,
    pub trust: ValidationProofCacheTrust,
    pub reuse: ValidationProofCacheReuse,
    pub storage: ValidationProofCacheStorage,
    pub invalidation: ValidationProofCacheInvalidation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofCacheDecisionKind {
    Hit,
    Miss,
    Stale,
    DigestMismatch,
    PolicyMismatch,
    DirtyStateMismatch,
    QuotaBlocked,
    CorruptedEntry,
}

impl ValidationProofCacheDecisionKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Stale => "stale",
            Self::DigestMismatch => "digest_mismatch",
            Self::PolicyMismatch => "policy_mismatch",
            Self::DirtyStateMismatch => "dirty_state_mismatch",
            Self::QuotaBlocked => "quota_blocked",
            Self::CorruptedEntry => "corrupted_entry",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProofCacheRequiredAction {
    ReuseReceipt,
    RunValidation,
    RefreshValidation,
    RepairCache,
    FreeSpace,
    SourceOnlyNotAllowed,
}

impl ValidationProofCacheRequiredAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReuseReceipt => "reuse_receipt",
            Self::RunValidation => "run_validation",
            Self::RefreshValidation => "refresh_validation",
            Self::RepairCache => "repair_cache",
            Self::FreeSpace => "free_space",
            Self::SourceOnlyNotAllowed => "source_only_not_allowed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheEntryRef {
    pub entry_id: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheDecisionDiagnostics {
    pub message: String,
    pub fail_closed: bool,
    pub event_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub cache_key: ValidationProofCacheKey,
    pub bead_id: String,
    pub trace_id: String,
    pub decided_at: DateTime<Utc>,
    pub decision: ValidationProofCacheDecisionKind,
    pub reason_code: String,
    pub entry_ref: Option<ValidationProofCacheEntryRef>,
    pub receipt_ref: Option<ValidationProofCacheReceiptRef>,
    pub required_action: ValidationProofCacheRequiredAction,
    pub diagnostics: ValidationProofCacheDecisionDiagnostics,
}

impl ValidationProofCacheDecision {
    #[must_use]
    pub fn to_broker_reuse_evidence(
        &self,
    ) -> Option<validation_broker::ValidationProofCacheReuseEvidence> {
        if !matches!(self.decision, ValidationProofCacheDecisionKind::Hit)
            || !matches!(
                self.required_action,
                ValidationProofCacheRequiredAction::ReuseReceipt
            )
        {
            return None;
        }
        let entry_ref = self.entry_ref.as_ref()?;
        let receipt_ref = self.receipt_ref.as_ref()?;
        Some(validation_broker::ValidationProofCacheReuseEvidence {
            decision_id: self.decision_id.clone(),
            cache_key_hex: self.cache_key.hex.clone(),
            entry_id: entry_ref.entry_id.clone(),
            entry_path: entry_ref.path.clone(),
            receipt_id: receipt_ref.receipt_id.clone(),
            receipt_path: receipt_ref.path.clone(),
            reason_code: self.reason_code.clone(),
            event_code: self.diagnostics.event_code.clone(),
            required_action: self.required_action.as_str().to_string(),
            diagnostic: self.diagnostics.message.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationProofCacheHit {
    pub entry: ValidationProofCacheEntry,
    pub receipt: ValidationReceipt,
    pub decision: ValidationProofCacheDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationProofCacheLookup {
    Hit(Box<ValidationProofCacheHit>),
    Miss(ValidationProofCacheDecision),
}

pub fn render_validation_proof_cache_decision_json(
    decision: &ValidationProofCacheDecision,
) -> Result<String, ValidationProofCacheError> {
    serde_json::to_string_pretty(decision).map_err(|source| ValidationProofCacheError::Json {
        path: "validation-proof-cache-decision".to_string(),
        source,
    })
}

#[must_use]
pub fn render_validation_proof_cache_decision_human(
    decision: &ValidationProofCacheDecision,
) -> String {
    let entry = decision.entry_ref.as_ref().map_or_else(
        || "none".to_string(),
        |entry| format!("{} at {}", entry.entry_id, entry.path),
    );
    let receipt = decision.receipt_ref.as_ref().map_or_else(
        || "none".to_string(),
        |receipt| format!("{} at {}", receipt.receipt_id, receipt.path),
    );
    [
        format!(
            "validation proof-cache: decision={} action={} reason_code={} event_code={} fail_closed={}",
            decision.decision.as_str(),
            decision.required_action.as_str(),
            decision.reason_code,
            decision.diagnostics.event_code,
            decision.diagnostics.fail_closed
        ),
        format!("  bead_id={}", decision.bead_id),
        format!("  trace_id={}", decision.trace_id),
        format!("  cache_key={}", decision.cache_key.hex),
        format!("  entry={entry}"),
        format!("  receipt={receipt}"),
        format!("  diagnostic={}", decision.diagnostics.message),
    ]
    .join("\n")
}

#[must_use]
pub fn validation_proof_cache_rejection_decision(
    key: ValidationProofCacheKey,
    decided_at: DateTime<Utc>,
    checked_path: impl Into<String>,
    error: &ValidationProofCacheError,
) -> ValidationProofCacheDecision {
    let checked_path = checked_path.into();
    let (decision, reason_code, required_action, event_code) = rejection_parts(error.code());
    ValidationProofCacheDecision {
        schema_version: DECISION_SCHEMA_VERSION.to_string(),
        decision_id: format!(
            "vpc-decision-reject-{}-{}",
            decision.as_str(),
            key_hex_prefix(&key.hex, 16)
        ),
        bead_id: key.package.clone(),
        trace_id: format!(
            "vpc-trace-reject-{}-{}",
            decision.as_str(),
            key_hex_prefix(&key.hex, 16)
        ),
        decided_at,
        decision,
        reason_code: reason_code.to_string(),
        entry_ref: Some(ValidationProofCacheEntryRef {
            entry_id: "unknown".to_string(),
            path: checked_path,
        }),
        receipt_ref: None,
        required_action,
        diagnostics: ValidationProofCacheDecisionDiagnostics {
            message: error.to_string(),
            fail_closed: true,
            event_code: event_code.to_string(),
        },
        cache_key: key,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheQuotaPolicy {
    pub max_total_bytes: u64,
    pub max_entries: usize,
    pub max_age_seconds: i64,
    pub min_available_bytes: u64,
    pub active_beads: Vec<String>,
    pub expected_git_commit: Option<String>,
    pub expected_input_digests: Vec<InputDigest>,
    pub expected_dirty_state_policy: Option<DirtyStatePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheDiskPressure {
    pub available_bytes: u64,
    pub minimum_required_bytes: u64,
    pub blocked: bool,
    pub reason_code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheGcEntry {
    pub entry_id: String,
    pub path: String,
    pub bead_id: String,
    pub cache_key_hex: String,
    pub bytes: u64,
    pub active_bead: bool,
    pub reason_code: String,
    pub event_code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProofCacheGcReport {
    pub schema_version: String,
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub policy: ValidationProofCacheQuotaPolicy,
    pub kept_entries: Vec<ValidationProofCacheGcEntry>,
    pub removed_entries: Vec<ValidationProofCacheGcEntry>,
    pub rejected_entries: Vec<ValidationProofCacheGcEntry>,
    pub disk_pressure: ValidationProofCacheDiskPressure,
}

struct ValidationProofCacheGcCandidate {
    entry: ValidationProofCacheEntry,
    path: String,
    bytes: u64,
    active_bead: bool,
}

#[derive(Debug, Clone)]
pub struct ValidationProofCacheStore {
    root: PathBuf,
}

impl ValidationProofCacheStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn entry_path(&self, key: &ValidationProofCacheKey) -> PathBuf {
        self.root
            .join("entries")
            .join(key_hex_prefix(&key.hex, 2))
            .join(format!("{}.json", key.hex))
    }

    #[must_use]
    pub fn relative_entry_path(&self, key: &ValidationProofCacheKey) -> String {
        format!("entries/{}/{}.json", key_hex_prefix(&key.hex, 2), key.hex)
    }

    pub fn build_entry(
        &self,
        key: ValidationProofCacheKey,
        receipt_path: impl Into<String>,
        receipt: &ValidationReceipt,
        receipt_bytes: &[u8],
        producer_agent: impl Into<String>,
        created_at: DateTime<Utc>,
    ) -> Result<ValidationProofCacheEntry, ValidationProofCacheError> {
        validate_key_receipt_match(&key, receipt)?;
        let receipt_path = receipt_path.into();
        let storage_path = self.relative_entry_path(&key);
        let receipt_digest =
            ProofCacheDigest::sha256_material(String::from_utf8_lossy(receipt_bytes).into_owned());
        let entry = ValidationProofCacheEntry {
            schema_version: ENTRY_SCHEMA_VERSION.to_string(),
            entry_id: format!("vpc-entry-{}", key_hex_prefix(&key.hex, 16)),
            cache_key: key.clone(),
            bead_id: receipt.bead_id.clone(),
            receipt_ref: ValidationProofCacheReceiptRef {
                receipt_id: receipt.receipt_id.clone(),
                path: receipt_path,
                bead_id: receipt.bead_id.clone(),
                command_digest: receipt.command_digest.clone(),
                input_digests: sorted_input_digest_clone(&receipt.input_digests),
                dirty_worktree: receipt.trust.dirty_worktree,
                dirty_state_policy: key.dirty_state_policy,
                environment_policy_id: receipt.environment_policy.policy_id.clone(),
                target_dir_policy_id: receipt.target_dir_policy.policy_id.clone(),
            },
            receipt_digest,
            producer_agent: producer_agent.into(),
            created_at,
            freshness_expires_at: receipt.timing.freshness_expires_at,
            trust: ValidationProofCacheTrust {
                state: "fresh".to_string(),
                git_commit: receipt.trust.git_commit.clone(),
                signature_status: receipt.trust.signature_status.clone(),
                dirty_worktree: receipt.trust.dirty_worktree,
                dirty_state_policy: key.dirty_state_policy,
                environment_policy_id: receipt.environment_policy.policy_id.clone(),
                target_dir_policy_id: receipt.target_dir_policy.policy_id.clone(),
            },
            reuse: ValidationProofCacheReuse {
                count: 0,
                last_reused_at: None,
            },
            storage: ValidationProofCacheStorage {
                path: storage_path,
                bytes: u64::try_from(receipt_bytes.len()).unwrap_or(u64::MAX),
                quota_class: "validation-proof-cache".to_string(),
                retention_policy: "fresh-until-expiry".to_string(),
            },
            invalidation: ValidationProofCacheInvalidation {
                active: false,
                reason: None,
                corrupted: false,
            },
        };
        validate_entry_for_receipt(&entry, &key, receipt, receipt_bytes, created_at)?;
        Ok(entry)
    }

    pub fn put_entry(
        &self,
        entry: &ValidationProofCacheEntry,
    ) -> Result<PathBuf, ValidationProofCacheError> {
        let path = self.entry_path(&entry.cache_key);
        let expected_relative = self.relative_entry_path(&entry.cache_key);
        if !constant_time::ct_eq(&entry.storage.path, &expected_relative) {
            return Err(ValidationProofCacheError::contract(
                error_codes::ERR_VPC_MALFORMED_ENTRY,
                "cache entry storage path does not match canonical key path",
            ));
        }
        let bytes =
            serde_json::to_vec_pretty(entry).map_err(|source| ValidationProofCacheError::Json {
                path: path.display().to_string(),
                source,
            })?;
        write_bytes_create_new(&path, &bytes)?;
        Ok(path)
    }

    pub fn put_entry_with_quota(
        &self,
        entry: &ValidationProofCacheEntry,
        policy: &ValidationProofCacheQuotaPolicy,
        available_bytes: u64,
        now: DateTime<Utc>,
    ) -> Result<PathBuf, ValidationProofCacheError> {
        let disk_pressure = disk_pressure_snapshot(policy, available_bytes);
        if disk_pressure.blocked {
            return Err(ValidationProofCacheError::contract(
                error_codes::ERR_VPC_QUOTA_BLOCKED,
                disk_pressure.message,
            ));
        }
        if available_bytes.saturating_sub(entry.storage.bytes) < policy.min_available_bytes {
            return Err(ValidationProofCacheError::contract(
                error_codes::ERR_VPC_QUOTA_BLOCKED,
                "proof cache write would drop available bytes below the minimum free-space policy",
            ));
        }
        if entry.storage.bytes > policy.max_total_bytes {
            return Err(ValidationProofCacheError::contract(
                error_codes::ERR_VPC_QUOTA_BLOCKED,
                "proof cache entry exceeds total byte quota",
            ));
        }

        let report = self.plan_garbage_collection(policy, now, available_bytes)?;
        let kept_bytes = report
            .kept_entries
            .iter()
            .fold(0_u64, |total, entry| total.saturating_add(entry.bytes));
        if report.kept_entries.len() >= policy.max_entries
            || kept_bytes.saturating_add(entry.storage.bytes) > policy.max_total_bytes
        {
            return Err(ValidationProofCacheError::contract(
                error_codes::ERR_VPC_QUOTA_BLOCKED,
                "proof cache quota requires garbage collection before accepting a new entry",
            ));
        }

        self.put_entry(entry)
    }

    pub fn read_entry(
        &self,
        key: &ValidationProofCacheKey,
    ) -> Result<Option<ValidationProofCacheEntry>, ValidationProofCacheError> {
        let path = self.entry_path(key);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|source| ValidationProofCacheError::Io {
            path: path.display().to_string(),
            source,
        })?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|source| ValidationProofCacheError::Json {
                path: path.display().to_string(),
                source,
            })
    }

    pub fn lookup(
        &self,
        key: &ValidationProofCacheKey,
        now: DateTime<Utc>,
    ) -> Result<ValidationProofCacheLookup, ValidationProofCacheError> {
        let Some(entry) = self.read_entry(key)? else {
            return Ok(ValidationProofCacheLookup::Miss(miss_decision(
                key.clone(),
                now,
                self.relative_entry_path(key),
            )));
        };
        let receipt_path = self.resolve_artifact_path(&entry.receipt_ref.path)?;
        let receipt_bytes =
            fs::read(&receipt_path).map_err(|source| ValidationProofCacheError::Io {
                path: receipt_path.display().to_string(),
                source,
            })?;
        let receipt: ValidationReceipt =
            serde_json::from_slice(&receipt_bytes).map_err(|source| {
                ValidationProofCacheError::Json {
                    path: receipt_path.display().to_string(),
                    source,
                }
            })?;
        validate_entry_for_receipt(&entry, key, &receipt, &receipt_bytes, now)?;
        let decision = hit_decision(key.clone(), &entry, now);
        Ok(ValidationProofCacheLookup::Hit(Box::new(
            ValidationProofCacheHit {
                entry,
                receipt,
                decision,
            },
        )))
    }

    pub fn plan_garbage_collection(
        &self,
        policy: &ValidationProofCacheQuotaPolicy,
        now: DateTime<Utc>,
        available_bytes: u64,
    ) -> Result<ValidationProofCacheGcReport, ValidationProofCacheError> {
        let mut candidates = Vec::new();
        let mut removed_entries = Vec::new();
        let mut rejected_entries = Vec::new();

        for path in self.entry_files()? {
            let relative_path = self.relative_path_or_display(&path);
            let file_bytes = fs::metadata(&path)
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            let bytes = fs::read(&path).map_err(|source| ValidationProofCacheError::Io {
                path: path.display().to_string(),
                source,
            })?;
            let Ok(entry) = serde_json::from_slice::<ValidationProofCacheEntry>(&bytes) else {
                rejected_entries.push(gc_entry_from_parts(
                    "malformed-entry",
                    relative_path,
                    "",
                    "",
                    file_bytes,
                    false,
                    error_codes::ERR_VPC_MALFORMED_ENTRY,
                    event_codes::CORRUPTED_REJECTED,
                    "proof cache entry JSON could not be parsed",
                ));
                continue;
            };
            let stored_bytes = if entry.storage.bytes == 0 {
                file_bytes
            } else {
                entry.storage.bytes
            };
            let active_bead = policy
                .active_beads
                .iter()
                .any(|bead| string_eq(bead, &entry.bead_id));

            if !string_eq(&entry.schema_version, ENTRY_SCHEMA_VERSION) {
                rejected_entries.push(gc_entry_from_entry(
                    &entry,
                    relative_path,
                    stored_bytes,
                    active_bead,
                    error_codes::ERR_VPC_INVALID_SCHEMA_VERSION,
                    event_codes::CORRUPTED_REJECTED,
                    "unsupported proof cache entry schema version",
                ));
                continue;
            }
            if !entry.cache_key.verifies() {
                rejected_entries.push(gc_entry_from_entry(
                    &entry,
                    relative_path,
                    stored_bytes,
                    active_bead,
                    error_codes::ERR_VPC_BAD_CACHE_KEY,
                    event_codes::CORRUPTED_REJECTED,
                    "proof cache key does not verify",
                ));
                continue;
            }
            if entry.invalidation.active || entry.invalidation.corrupted {
                rejected_entries.push(gc_entry_from_entry(
                    &entry,
                    relative_path,
                    stored_bytes,
                    active_bead,
                    error_codes::ERR_VPC_CORRUPTED_ENTRY,
                    event_codes::CORRUPTED_REJECTED,
                    "proof cache entry is invalidated or corrupted",
                ));
                continue;
            }
            if let Err(error) = self
                .resolve_artifact_path(&entry.receipt_ref.path)
                .and_then(|path| {
                    if path.exists() {
                        Ok(path)
                    } else {
                        Err(ValidationProofCacheError::contract(
                            error_codes::ERR_VPC_MALFORMED_ENTRY,
                            "proof cache receipt artifact is missing",
                        ))
                    }
                })
            {
                rejected_entries.push(gc_entry_from_entry(
                    &entry,
                    relative_path,
                    stored_bytes,
                    active_bead,
                    error.code(),
                    event_codes::CORRUPTED_REJECTED,
                    "proof cache receipt artifact is missing or outside the cache root",
                ));
                continue;
            }
            if entry.freshness_expires_at < now || entry_is_older_than_policy(&entry, policy, now) {
                removed_entries.push(gc_entry_from_entry(
                    &entry,
                    relative_path,
                    stored_bytes,
                    active_bead,
                    error_codes::ERR_VPC_STALE_ENTRY,
                    event_codes::STALE_REJECTED,
                    "proof cache entry exceeded freshness or max-age policy",
                ));
                continue;
            }
            if let Some(expected_git_commit) = &policy.expected_git_commit {
                if !string_eq(expected_git_commit, &entry.trust.git_commit) {
                    rejected_entries.push(gc_entry_from_entry(
                        &entry,
                        relative_path,
                        stored_bytes,
                        active_bead,
                        error_codes::ERR_VPC_STALE_ENTRY,
                        event_codes::STALE_REJECTED,
                        "proof cache entry git commit is not in the expected validation scope",
                    ));
                    continue;
                }
            }
            if !policy.expected_input_digests.is_empty()
                && !input_digest_sets_match(
                    &policy.expected_input_digests,
                    &entry.cache_key.input_digests,
                )
            {
                rejected_entries.push(gc_entry_from_entry(
                    &entry,
                    relative_path,
                    stored_bytes,
                    active_bead,
                    error_codes::ERR_VPC_INPUT_DIGEST_MISMATCH,
                    event_codes::COMMAND_OR_INPUT_REJECTED,
                    "proof cache entry input digest set drifted from the expected validation scope",
                ));
                continue;
            }
            if let Some(expected_dirty_state_policy) = policy.expected_dirty_state_policy {
                if !string_eq(
                    expected_dirty_state_policy.as_str(),
                    entry.cache_key.dirty_state_policy.as_str(),
                ) {
                    rejected_entries.push(gc_entry_from_entry(
                        &entry,
                        relative_path,
                        stored_bytes,
                        active_bead,
                        error_codes::ERR_VPC_DIRTY_STATE_MISMATCH,
                        event_codes::POLICY_REJECTED,
                        "proof cache entry dirty-state policy drifted from the expected validation scope",
                    ));
                    continue;
                }
            }
            candidates.push(ValidationProofCacheGcCandidate {
                entry,
                path: relative_path,
                bytes: stored_bytes,
                active_bead,
            });
        }

        candidates.sort_by(|left, right| {
            right
                .active_bead
                .cmp(&left.active_bead)
                .then_with(|| {
                    right
                        .entry
                        .freshness_expires_at
                        .cmp(&left.entry.freshness_expires_at)
                })
                .then_with(|| right.entry.created_at.cmp(&left.entry.created_at))
                .then_with(|| left.entry.entry_id.cmp(&right.entry.entry_id))
        });

        let mut kept_entries = Vec::new();
        let mut kept_bytes = 0_u64;
        for candidate in candidates {
            if kept_entries.len() < policy.max_entries
                && kept_bytes.saturating_add(candidate.bytes) <= policy.max_total_bytes
            {
                kept_bytes = kept_bytes.saturating_add(candidate.bytes);
                kept_entries.push(gc_entry_from_entry(
                    &candidate.entry,
                    candidate.path,
                    candidate.bytes,
                    candidate.active_bead,
                    "VPC_KEEP_FRESH",
                    event_codes::HIT_ACCEPTED,
                    "proof cache entry is fresh and within quota",
                ));
            } else {
                removed_entries.push(gc_entry_from_entry(
                    &candidate.entry,
                    candidate.path,
                    candidate.bytes,
                    candidate.active_bead,
                    error_codes::ERR_VPC_QUOTA_BLOCKED,
                    event_codes::QUOTA_REJECTED,
                    "proof cache entry is outside the quota-retained set",
                ));
            }
        }

        let report_id = format!(
            "vpc-gc-{}-{}-{}-{}",
            now.timestamp(),
            kept_entries.len(),
            removed_entries.len(),
            rejected_entries.len()
        );
        Ok(ValidationProofCacheGcReport {
            schema_version: GC_REPORT_SCHEMA_VERSION.to_string(),
            report_id,
            generated_at: now,
            policy: policy.clone(),
            kept_entries,
            removed_entries,
            rejected_entries,
            disk_pressure: disk_pressure_snapshot(policy, available_bytes),
        })
    }

    fn resolve_artifact_path(
        &self,
        relative_path: &str,
    ) -> Result<PathBuf, ValidationProofCacheError> {
        let path = Path::new(relative_path);
        if path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(ValidationProofCacheError::contract(
                error_codes::ERR_VPC_MALFORMED_ENTRY,
                "proof cache receipt path must be a relative path inside the cache root",
            ));
        }
        let mut resolved = self.root.clone();
        for component in path.components() {
            let Component::Normal(segment) = component else {
                return Err(ValidationProofCacheError::contract(
                    error_codes::ERR_VPC_MALFORMED_ENTRY,
                    "proof cache receipt path must contain only normal path components",
                ));
            };
            resolved.push(segment);
        }
        Ok(resolved)
    }

    fn entry_files(&self) -> Result<Vec<PathBuf>, ValidationProofCacheError> {
        let entries_root = self.root.join("entries");
        if !entries_root.exists() {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        collect_entry_files(&entries_root, &mut files)?;
        files.sort();
        Ok(files)
    }

    fn relative_path_or_display(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .map(|relative| relative.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| path.display().to_string())
    }
}

fn disk_pressure_snapshot(
    policy: &ValidationProofCacheQuotaPolicy,
    available_bytes: u64,
) -> ValidationProofCacheDiskPressure {
    let blocked = available_bytes < policy.min_available_bytes;
    let reason_code = blocked.then(|| error_codes::ERR_VPC_QUOTA_BLOCKED.to_string());
    let message = if blocked {
        "available bytes are below the proof cache minimum free-space policy".to_string()
    } else {
        "available bytes satisfy the proof cache minimum free-space policy".to_string()
    };
    ValidationProofCacheDiskPressure {
        available_bytes,
        minimum_required_bytes: policy.min_available_bytes,
        blocked,
        reason_code,
        message,
    }
}

fn collect_entry_files(
    root: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), ValidationProofCacheError> {
    for entry in fs::read_dir(root).map_err(|source| ValidationProofCacheError::Io {
        path: root.display().to_string(),
        source,
    })? {
        let entry = entry.map_err(|source| ValidationProofCacheError::Io {
            path: root.display().to_string(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|source| ValidationProofCacheError::Io {
                path: path.display().to_string(),
                source,
            })?;
        if file_type.is_dir() {
            collect_entry_files(&path, files)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq("json"))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn entry_is_older_than_policy(
    entry: &ValidationProofCacheEntry,
    policy: &ValidationProofCacheQuotaPolicy,
    now: DateTime<Utc>,
) -> bool {
    policy.max_age_seconds >= 0
        && now.signed_duration_since(entry.created_at).num_seconds() > policy.max_age_seconds
}

#[allow(clippy::too_many_arguments)]
fn gc_entry_from_parts(
    entry_id: impl Into<String>,
    path: impl Into<String>,
    bead_id: impl Into<String>,
    cache_key_hex: impl Into<String>,
    bytes: u64,
    active_bead: bool,
    reason_code: impl Into<String>,
    event_code: impl Into<String>,
    message: impl Into<String>,
) -> ValidationProofCacheGcEntry {
    ValidationProofCacheGcEntry {
        entry_id: entry_id.into(),
        path: path.into(),
        bead_id: bead_id.into(),
        cache_key_hex: cache_key_hex.into(),
        bytes,
        active_bead,
        reason_code: reason_code.into(),
        event_code: event_code.into(),
        message: message.into(),
    }
}

fn gc_entry_from_entry(
    entry: &ValidationProofCacheEntry,
    path: impl Into<String>,
    bytes: u64,
    active_bead: bool,
    reason_code: impl Into<String>,
    event_code: impl Into<String>,
    message: impl Into<String>,
) -> ValidationProofCacheGcEntry {
    gc_entry_from_parts(
        entry.entry_id.clone(),
        path,
        entry.bead_id.clone(),
        entry.cache_key.hex.clone(),
        bytes,
        active_bead,
        reason_code,
        event_code,
        message,
    )
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationProofCacheError {
    #[error("{code}: {detail}")]
    ContractViolation { code: &'static str, detail: String },
    #[error("duplicate proof cache entry at {path}")]
    DuplicateEntry { path: String },
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

impl ValidationProofCacheError {
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
            Self::DuplicateEntry { .. } => error_codes::ERR_VPC_DUPLICATE_ENTRY,
            Self::Io { .. } | Self::Json { .. } => error_codes::ERR_VPC_MALFORMED_ENTRY,
        }
    }
}

fn validate_request_receipt_scope(
    request: &ValidationBrokerRequest,
    receipt: &ValidationReceipt,
) -> Result<(), ValidationProofCacheError> {
    if !string_eq(&request.bead_id, &receipt.bead_id)
        || !string_eq(&request.thread_id, &receipt.thread_id)
        || !string_eq(&request.request_id, &receipt.request_id)
    {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_MALFORMED_ENTRY,
            "request and receipt bead/thread/request identifiers must match",
        ));
    }
    let request_command_digest = request.command.digest();
    if !request_command_digest.verifies()
        || !receipt.command_digest.verifies()
        || !constant_time::ct_eq(&request_command_digest.hex, &receipt.command_digest.hex)
    {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_COMMAND_DIGEST_MISMATCH,
            "request command digest must match receipt command digest",
        ));
    }
    if !input_digest_sets_match(&request.inputs.content_digests, &receipt.input_digests) {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_INPUT_DIGEST_MISMATCH,
            "request input digest set must match receipt input digest set",
        ));
    }
    Ok(())
}

fn validate_key_receipt_match(
    key: &ValidationProofCacheKey,
    receipt: &ValidationReceipt,
) -> Result<(), ValidationProofCacheError> {
    if !key.verifies() {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_BAD_CACHE_KEY,
            "cache key digest does not verify",
        ));
    }
    if !constant_time::ct_eq(&key.command_digest.hex, &receipt.command_digest.hex) {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_COMMAND_DIGEST_MISMATCH,
            "cache key command digest does not match receipt command digest",
        ));
    }
    if !input_digest_sets_match(&key.input_digests, &receipt.input_digests) {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_INPUT_DIGEST_MISMATCH,
            "cache key input digests do not match receipt input digests",
        ));
    }
    if (key.dirty_worktree ^ receipt.trust.dirty_worktree)
        || (matches!(key.dirty_state_policy, DirtyStatePolicy::CleanRequired)
            && receipt.trust.dirty_worktree)
    {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_DIRTY_STATE_MISMATCH,
            "cache key dirty-state policy does not match receipt trust state",
        ));
    }
    if !string_eq(
        &key.environment_policy_id,
        &receipt.environment_policy.policy_id,
    ) || !string_eq(
        &key.target_dir_policy_id,
        &receipt.target_dir_policy.policy_id,
    ) {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_POLICY_MISMATCH,
            "cache key policies do not match receipt policies",
        ));
    }
    Ok(())
}

fn validate_entry_for_receipt(
    entry: &ValidationProofCacheEntry,
    requested_key: &ValidationProofCacheKey,
    receipt: &ValidationReceipt,
    receipt_bytes: &[u8],
    now: DateTime<Utc>,
) -> Result<(), ValidationProofCacheError> {
    if !string_eq(&entry.schema_version, ENTRY_SCHEMA_VERSION) {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_INVALID_SCHEMA_VERSION,
            "unsupported proof cache entry schema version",
        ));
    }
    if !constant_time::ct_eq(&entry.cache_key.hex, &requested_key.hex) {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_BAD_CACHE_KEY,
            "cache entry key does not match requested key",
        ));
    }
    validate_key_receipt_match(&entry.cache_key, receipt)?;
    validate_key_receipt_match(requested_key, receipt)?;
    map_receipt_error(receipt.validate_at(now))?;
    if entry.freshness_expires_at < now {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_STALE_ENTRY,
            "proof cache entry freshness has expired",
        ));
    }
    if !entry.receipt_digest.verifies() {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_RECEIPT_DIGEST_MISMATCH,
            "stored receipt digest does not verify its canonical material",
        ));
    }
    let observed_receipt_digest =
        ProofCacheDigest::sha256_material(String::from_utf8_lossy(receipt_bytes).into_owned());
    if !constant_time::ct_eq(&observed_receipt_digest.hex, &entry.receipt_digest.hex) {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_RECEIPT_DIGEST_MISMATCH,
            "receipt bytes do not match proof cache receipt digest",
        ));
    }
    if !string_eq(&entry.receipt_ref.receipt_id, &receipt.receipt_id)
        || !string_eq(&entry.receipt_ref.bead_id, &receipt.bead_id)
    {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_MALFORMED_ENTRY,
            "entry receipt reference does not match loaded receipt",
        ));
    }
    if !constant_time::ct_eq(
        &entry.receipt_ref.command_digest.hex,
        &receipt.command_digest.hex,
    ) || !constant_time::ct_eq(
        &entry.receipt_ref.command_digest.hex,
        &entry.cache_key.command_digest.hex,
    ) {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_COMMAND_DIGEST_MISMATCH,
            "entry command digest does not match loaded receipt",
        ));
    }
    if !input_digest_sets_match(&entry.receipt_ref.input_digests, &receipt.input_digests) {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_INPUT_DIGEST_MISMATCH,
            "entry input digests do not match loaded receipt",
        ));
    }
    if (entry.receipt_ref.dirty_worktree ^ receipt.trust.dirty_worktree)
        || (entry.trust.dirty_worktree ^ receipt.trust.dirty_worktree)
        || !string_eq(
            entry.trust.dirty_state_policy.as_str(),
            entry.cache_key.dirty_state_policy.as_str(),
        )
    {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_DIRTY_STATE_MISMATCH,
            "entry dirty-state fields do not match loaded receipt",
        ));
    }
    if !string_eq(
        &entry.receipt_ref.environment_policy_id,
        &receipt.environment_policy.policy_id,
    ) || !string_eq(
        &entry.receipt_ref.target_dir_policy_id,
        &receipt.target_dir_policy.policy_id,
    ) || !string_eq(
        &entry.trust.environment_policy_id,
        &receipt.environment_policy.policy_id,
    ) || !string_eq(
        &entry.trust.target_dir_policy_id,
        &receipt.target_dir_policy.policy_id,
    ) {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_POLICY_MISMATCH,
            "entry policy fields do not match loaded receipt",
        ));
    }
    if entry.invalidation.active || entry.invalidation.corrupted {
        return Err(ValidationProofCacheError::contract(
            error_codes::ERR_VPC_CORRUPTED_ENTRY,
            "proof cache entry is invalidated or corrupted",
        ));
    }
    Ok(())
}

fn map_receipt_error(
    result: Result<(), validation_broker::ValidationBrokerError>,
) -> Result<(), ValidationProofCacheError> {
    result.map_err(|error| match error {
        validation_broker::ValidationBrokerError::ContractViolation { code, detail } => {
            let mapped = match code {
                validation_broker::error_codes::ERR_VB_STALE_RECEIPT => {
                    error_codes::ERR_VPC_STALE_ENTRY
                }
                validation_broker::error_codes::ERR_VB_MISSING_COMMAND_DIGEST => {
                    error_codes::ERR_VPC_COMMAND_DIGEST_MISMATCH
                }
                validation_broker::error_codes::ERR_VB_MALFORMED_RECEIPT => {
                    error_codes::ERR_VPC_INPUT_DIGEST_MISMATCH
                }
                validation_broker::error_codes::ERR_VB_INVALID_SCHEMA_VERSION => {
                    error_codes::ERR_VPC_INVALID_SCHEMA_VERSION
                }
                _ => error_codes::ERR_VPC_MALFORMED_ENTRY,
            };
            ValidationProofCacheError::contract(mapped, detail)
        }
        other => ValidationProofCacheError::contract(
            error_codes::ERR_VPC_MALFORMED_ENTRY,
            other.to_string(),
        ),
    })
}

fn canonical_key_material(
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
        "schema={KEY_SCHEMA_VERSION}\0command={}:{}\0inputs={}\0git_commit={}\0dirty={}\0dirty_policy={}\0features={}\0toolchain={}\0package={}\0test_target={}\0env_policy={}\0target_policy={}",
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

fn hit_decision(
    key: ValidationProofCacheKey,
    entry: &ValidationProofCacheEntry,
    decided_at: DateTime<Utc>,
) -> ValidationProofCacheDecision {
    ValidationProofCacheDecision {
        schema_version: DECISION_SCHEMA_VERSION.to_string(),
        decision_id: format!("vpc-decision-hit-{}", key_hex_prefix(&key.hex, 16)),
        cache_key: key,
        bead_id: entry.bead_id.clone(),
        trace_id: format!("vpc-trace-hit-{}", entry.entry_id),
        decided_at,
        decision: ValidationProofCacheDecisionKind::Hit,
        reason_code: "VPC_HIT_FRESH".to_string(),
        entry_ref: Some(ValidationProofCacheEntryRef {
            entry_id: entry.entry_id.clone(),
            path: entry.storage.path.clone(),
        }),
        receipt_ref: Some(entry.receipt_ref.clone()),
        required_action: ValidationProofCacheRequiredAction::ReuseReceipt,
        diagnostics: ValidationProofCacheDecisionDiagnostics {
            message: "fresh proof cache entry accepted".to_string(),
            fail_closed: false,
            event_code: event_codes::HIT_ACCEPTED.to_string(),
        },
    }
}

fn miss_decision(
    key: ValidationProofCacheKey,
    decided_at: DateTime<Utc>,
    checked_path: String,
) -> ValidationProofCacheDecision {
    ValidationProofCacheDecision {
        schema_version: DECISION_SCHEMA_VERSION.to_string(),
        decision_id: format!("vpc-decision-miss-{}", key_hex_prefix(&key.hex, 16)),
        bead_id: key.package.clone(),
        trace_id: format!("vpc-trace-miss-{}", key_hex_prefix(&key.hex, 16)),
        decided_at,
        decision: ValidationProofCacheDecisionKind::Miss,
        reason_code: "VPC_MISS_NO_ENTRY".to_string(),
        entry_ref: Some(ValidationProofCacheEntryRef {
            entry_id: "none".to_string(),
            path: checked_path,
        }),
        receipt_ref: None,
        required_action: ValidationProofCacheRequiredAction::RunValidation,
        diagnostics: ValidationProofCacheDecisionDiagnostics {
            message: "no proof cache entry found for key".to_string(),
            fail_closed: true,
            event_code: event_codes::MISS_RECORDED.to_string(),
        },
        cache_key: key,
    }
}

fn rejection_parts(
    code: &str,
) -> (
    ValidationProofCacheDecisionKind,
    &'static str,
    ValidationProofCacheRequiredAction,
    &'static str,
) {
    match code {
        error_codes::ERR_VPC_STALE_ENTRY => (
            ValidationProofCacheDecisionKind::Stale,
            "VPC_REJECT_STALE",
            ValidationProofCacheRequiredAction::RefreshValidation,
            event_codes::STALE_REJECTED,
        ),
        error_codes::ERR_VPC_RECEIPT_DIGEST_MISMATCH => (
            ValidationProofCacheDecisionKind::DigestMismatch,
            "VPC_REJECT_RECEIPT_DIGEST",
            ValidationProofCacheRequiredAction::RepairCache,
            event_codes::RECEIPT_DIGEST_REJECTED,
        ),
        error_codes::ERR_VPC_COMMAND_DIGEST_MISMATCH => (
            ValidationProofCacheDecisionKind::DigestMismatch,
            "VPC_REJECT_COMMAND_DIGEST",
            ValidationProofCacheRequiredAction::RepairCache,
            event_codes::COMMAND_OR_INPUT_REJECTED,
        ),
        error_codes::ERR_VPC_INPUT_DIGEST_MISMATCH => (
            ValidationProofCacheDecisionKind::DigestMismatch,
            "VPC_REJECT_INPUT_DIGEST",
            ValidationProofCacheRequiredAction::RepairCache,
            event_codes::COMMAND_OR_INPUT_REJECTED,
        ),
        error_codes::ERR_VPC_POLICY_MISMATCH => (
            ValidationProofCacheDecisionKind::PolicyMismatch,
            "VPC_REJECT_POLICY",
            ValidationProofCacheRequiredAction::RunValidation,
            event_codes::POLICY_REJECTED,
        ),
        error_codes::ERR_VPC_DIRTY_STATE_MISMATCH => (
            ValidationProofCacheDecisionKind::DirtyStateMismatch,
            "VPC_REJECT_DIRTY_STATE",
            ValidationProofCacheRequiredAction::RunValidation,
            event_codes::POLICY_REJECTED,
        ),
        error_codes::ERR_VPC_QUOTA_BLOCKED => (
            ValidationProofCacheDecisionKind::QuotaBlocked,
            "VPC_REJECT_QUOTA",
            ValidationProofCacheRequiredAction::FreeSpace,
            event_codes::QUOTA_REJECTED,
        ),
        error_codes::ERR_VPC_CORRUPTED_ENTRY => (
            ValidationProofCacheDecisionKind::CorruptedEntry,
            "VPC_REJECT_CORRUPTED",
            ValidationProofCacheRequiredAction::RepairCache,
            event_codes::CORRUPTED_REJECTED,
        ),
        _ => (
            ValidationProofCacheDecisionKind::CorruptedEntry,
            "VPC_REJECT_CORRUPTED",
            ValidationProofCacheRequiredAction::RepairCache,
            event_codes::CORRUPTED_REJECTED,
        ),
    }
}

fn write_bytes_create_new(path: &Path, bytes: &[u8]) -> Result<(), ValidationProofCacheError> {
    if path.exists() {
        return Err(ValidationProofCacheError::DuplicateEntry {
            path: path.display().to_string(),
        });
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent).map_err(|source| ValidationProofCacheError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let temp_guard = TempFileGuard::new(path);
    {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(temp_guard.path())
            .map_err(|source| ValidationProofCacheError::Io {
                path: temp_guard.path().display().to_string(),
                source,
            })?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| ValidationProofCacheError::Io {
                path: temp_guard.path().display().to_string(),
                source,
            })?;
    }
    fs::hard_link(temp_guard.path(), path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            ValidationProofCacheError::DuplicateEntry {
                path: path.display().to_string(),
            }
        } else {
            ValidationProofCacheError::Io {
                path: path.display().to_string(),
                source,
            }
        }
    })?;
    sync_directory(parent)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ValidationProofCacheError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ValidationProofCacheError::Io {
            path: path.display().to_string(),
            source,
        })
}

fn sorted_input_digest_clone(input_digests: &[InputDigest]) -> Vec<InputDigest> {
    let mut cloned = input_digests.to_vec();
    sort_input_digests(&mut cloned);
    cloned
}

fn sort_input_digests(input_digests: &mut [InputDigest]) {
    input_digests.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.algorithm.cmp(&right.algorithm))
            .then(left.hex.cmp(&right.hex))
    });
}

fn input_digest_set(input_digests: &[InputDigest]) -> BTreeSet<(String, String, String)> {
    input_digests
        .iter()
        .map(|digest| {
            (
                digest.path.clone(),
                digest.algorithm.clone(),
                digest.hex.clone(),
            )
        })
        .collect()
}

fn input_digest_sets_match(left: &[InputDigest], right: &[InputDigest]) -> bool {
    let left_set = input_digest_set(left);
    let right_set = input_digest_set(right);
    if left_set.len() != right_set.len() {
        return false;
    }
    left_set
        .iter()
        .all(|(left_path, left_algorithm, left_hex)| {
            right_set
                .iter()
                .any(|(right_path, right_algorithm, right_hex)| {
                    constant_time::ct_eq(left_path, right_path)
                        && constant_time::ct_eq(left_algorithm, right_algorithm)
                        && constant_time::ct_eq(left_hex, right_hex)
                })
        })
}

fn key_hex_prefix(hex: &str, len: usize) -> &str {
    hex.get(..len).unwrap_or("invalid")
}

fn string_eq(left: &str, right: &str) -> bool {
    constant_time::ct_eq(left, right)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

struct TempFileGuard {
    path: PathBuf,
}

impl TempFileGuard {
    fn new(path: &Path) -> Self {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("validation-proof-cache-entry");
        let temp_name = format!(
            ".{file_name}.tmp-{}-{}",
            std::process::id(),
            Utc::now().timestamp_micros()
        );
        Self {
            path: path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(temp_name),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::validation_broker::{
        EnvironmentPolicy, FallbackPolicy, OutputPolicy, RchMode, RchReceipt, ReceiptArtifacts,
        ReceiptClassifications, ReceiptRequestRef, ReceiptTrust, SourceOnlyReason, TargetDirPolicy,
        TimeoutClass, ValidationErrorClass, ValidationExit, ValidationExitKind, ValidationPriority,
        ValidationTiming,
    };
    use chrono::TimeZone;
    use tempfile::TempDir;

    const FIXTURE_JSON: &str = include_str!(
        "../../../../artifacts/validation_broker/proof_cache/validation_proof_cache_fixtures.v1.json"
    );

    fn ts(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, second)
            .single()
            .expect("valid timestamp")
    }

    fn command() -> validation_broker::CommandSpec {
        validation_broker::CommandSpec {
            program: "cargo".to_string(),
            argv: vec![
                "+nightly-2026-02-19".to_string(),
                "test".to_string(),
                "-p".to_string(),
                "frankenengine-node".to_string(),
                "validation_proof_cache".to_string(),
            ],
            cwd: "/data/projects/franken_node".to_string(),
            environment_policy_id: "validation-broker/env-policy/v1".to_string(),
            target_dir_policy_id: "validation-broker/target-dir/off-repo/v1".to_string(),
        }
    }

    fn inputs() -> validation_broker::InputSet {
        validation_broker::InputSet {
            git_commit: "0c77f679".to_string(),
            dirty_worktree: false,
            changed_paths: vec![
                "crates/franken-node/src/ops/validation_proof_cache.rs".to_string(),
            ],
            content_digests: vec![InputDigest::new(
                "crates/franken-node/src/ops/validation_proof_cache.rs",
                b"validation-proof-cache-fixture",
                "fixture",
            )],
            feature_flags: vec!["http-client".to_string(), "external-commands".to_string()],
        }
    }

    fn request() -> ValidationBrokerRequest {
        ValidationBrokerRequest::new(
            "vbreq-bd-8j9au-1",
            "bd-8j9au",
            "bd-8j9au",
            "LavenderElk",
            ts(0),
            ValidationPriority::High,
            command(),
            inputs(),
            OutputPolicy {
                stdout_path: "artifacts/validation_broker/bd-8j9au/stdout.txt".to_string(),
                stderr_path: "artifacts/validation_broker/bd-8j9au/stderr.txt".to_string(),
                summary_path: "artifacts/validation_broker/bd-8j9au/summary.md".to_string(),
                receipt_path: "receipts/bd-8j9au.json".to_string(),
                retention: "until-closeout".to_string(),
            },
            FallbackPolicy {
                source_only_allowed: false,
                allowed_reasons: vec![SourceOnlyReason::DocsOnly],
            },
        )
    }

    fn receipt_with_expiry(freshness_expires_at: DateTime<Utc>) -> ValidationReceipt {
        let request = request();
        let command = request.command.clone();
        let command_digest = command.digest();
        ValidationReceipt {
            schema_version: validation_broker::RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_id: "vbrcpt-bd-8j9au-1".to_string(),
            request_id: request.request_id.clone(),
            bead_id: request.bead_id.clone(),
            thread_id: request.thread_id.clone(),
            request_ref: ReceiptRequestRef {
                request_id: request.request_id.clone(),
                bead_id: request.bead_id.clone(),
                thread_id: request.thread_id.clone(),
                dedupe_key: DigestRef {
                    algorithm: request.dedupe_key.algorithm.clone(),
                    hex: request.dedupe_key.hex.clone(),
                },
                cross_thread_waiver: None,
            },
            command,
            command_digest,
            environment_policy: EnvironmentPolicy {
                policy_id: "validation-broker/env-policy/v1".to_string(),
                allowed_env: vec!["CARGO_TARGET_DIR".to_string()],
                redacted_env: vec![],
                remote_required: true,
                network_policy: "rch-only".to_string(),
            },
            target_dir_policy: TargetDirPolicy {
                policy_id: "validation-broker/target-dir/off-repo/v1".to_string(),
                kind: "off-repo".to_string(),
                path: "/data/tmp/franken_node_validation_proof_cache".to_string(),
                path_digest: DigestRef::sha256(b"/data/tmp/franken_node_validation_proof_cache"),
                cleanup: "caller-owned".to_string(),
            },
            input_digests: request.inputs.content_digests.clone(),
            rch: RchReceipt {
                mode: RchMode::Remote,
                worker_id: Some("ts-test".to_string()),
                require_remote: true,
                capability_observation_id: None,
                worker_pool: "test".to_string(),
            },
            timing: ValidationTiming {
                started_at: ts(1),
                finished_at: ts(2),
                duration_ms: 1_000,
                freshness_expires_at,
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
                stdout_path: "artifacts/validation_broker/bd-8j9au/stdout.txt".to_string(),
                stderr_path: "artifacts/validation_broker/bd-8j9au/stderr.txt".to_string(),
                summary_path: "artifacts/validation_broker/bd-8j9au/summary.md".to_string(),
                receipt_path: "receipts/bd-8j9au.json".to_string(),
                stdout_digest: DigestRef::sha256(b"stdout"),
                stderr_digest: DigestRef::sha256(b"stderr"),
            },
            trust: ReceiptTrust {
                generated_by: "validation-broker".to_string(),
                agent_name: "LavenderElk".to_string(),
                git_commit: "0c77f679".to_string(),
                dirty_worktree: false,
                freshness: "fresh".to_string(),
                signature_status: "unsigned-test".to_string(),
            },
            classifications: ReceiptClassifications {
                source_only_fallback: false,
                source_only_reason: None,
                doctor_readiness: "green".to_string(),
                ci_consumable: true,
            },
        }
    }

    fn fresh_receipt() -> ValidationReceipt {
        receipt_with_expiry(ts(50))
    }

    fn scope() -> ValidationProofCacheScope {
        ValidationProofCacheScope {
            dirty_state_policy: DirtyStatePolicy::CleanRequired,
            cargo_toolchain: "nightly-2026-02-19".to_string(),
            package: "frankenengine-node".to_string(),
            test_target: "validation_proof_cache".to_string(),
        }
    }

    fn write_receipt(root: &Path, receipt: &ValidationReceipt) -> (String, Vec<u8>) {
        let relative_path = "receipts/bd-8j9au.json".to_string();
        let path = root.join(&relative_path);
        fs::create_dir_all(path.parent().expect("receipt parent")).expect("receipt parent");
        let bytes = serde_json::to_vec_pretty(receipt).expect("receipt json");
        fs::write(&path, &bytes).expect("receipt written");
        (relative_path, bytes)
    }

    fn populated_store(
        mutate_entry: impl FnOnce(&mut ValidationProofCacheEntry),
    ) -> (
        TempDir,
        ValidationProofCacheStore,
        ValidationProofCacheKey,
        ValidationProofCacheEntry,
    ) {
        let dir = TempDir::new().expect("tempdir");
        let store = ValidationProofCacheStore::new(dir.path());
        let request = request();
        let receipt = fresh_receipt();
        let (receipt_path, receipt_bytes) = write_receipt(dir.path(), &receipt);
        let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
            .expect("key");
        let mut entry = store
            .build_entry(
                key.clone(),
                receipt_path,
                &receipt,
                &receipt_bytes,
                "LavenderElk",
                ts(3),
            )
            .expect("entry");
        mutate_entry(&mut entry);
        store.put_entry(&entry).expect("entry persisted");
        (dir, store, key, entry)
    }

    #[test]
    fn cache_lookup_returns_hit_only_with_valid_receipt() {
        let (_dir, store, key, _entry) = populated_store(|_| {});

        let lookup = store.lookup(&key, ts(4)).expect("lookup");

        match lookup {
            ValidationProofCacheLookup::Hit(hit) => {
                assert_eq!(hit.receipt.receipt_id, "vbrcpt-bd-8j9au-1");
                assert_eq!(hit.decision.decision, ValidationProofCacheDecisionKind::Hit);
                assert_eq!(
                    hit.decision.required_action,
                    ValidationProofCacheRequiredAction::ReuseReceipt
                );
            }
            ValidationProofCacheLookup::Miss(decision) => {
                assert_eq!(decision.decision, ValidationProofCacheDecisionKind::Hit);
            }
        }
    }

    #[test]
    fn cache_lookup_misses_without_entry() {
        let dir = TempDir::new().expect("tempdir");
        let store = ValidationProofCacheStore::new(dir.path());
        let request = request();
        let receipt = fresh_receipt();
        let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
            .expect("key");

        let lookup = store.lookup(&key, ts(4)).expect("lookup");

        match lookup {
            ValidationProofCacheLookup::Miss(decision) => {
                assert_eq!(decision.decision, ValidationProofCacheDecisionKind::Miss);
                assert!(decision.diagnostics.fail_closed);
            }
            ValidationProofCacheLookup::Hit(hit) => {
                assert_eq!(
                    hit.decision.decision,
                    ValidationProofCacheDecisionKind::Miss
                );
            }
        }
    }

    #[test]
    fn stale_receipt_fails_closed() {
        let dir = TempDir::new().expect("tempdir");
        let store = ValidationProofCacheStore::new(dir.path());
        let request = request();
        let receipt = receipt_with_expiry(ts(3));
        let (receipt_path, receipt_bytes) = write_receipt(dir.path(), &receipt);
        let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
            .expect("key");
        let entry = store
            .build_entry(
                key.clone(),
                receipt_path,
                &receipt,
                &receipt_bytes,
                "LavenderElk",
                ts(2),
            )
            .expect("entry");
        store.put_entry(&entry).expect("entry persisted");

        let err = store.lookup(&key, ts(4)).expect_err("stale entry rejects");

        assert_eq!(err.code(), error_codes::ERR_VPC_STALE_ENTRY);
    }

    #[test]
    fn receipt_digest_mismatch_fails_closed() {
        let (dir, store, key, _entry) = populated_store(|_| {});
        let receipt_path = dir.path().join("receipts/bd-8j9au.json");
        fs::write(receipt_path, b"{\"tampered\": true}").expect("tampered receipt");

        let err = store
            .lookup(&key, ts(4))
            .expect_err("digest mismatch rejects");

        assert_eq!(err.code(), error_codes::ERR_VPC_RECEIPT_DIGEST_MISMATCH);
    }

    #[test]
    fn command_digest_mismatch_fails_closed() {
        let (_dir, store, key, _entry) = populated_store(|entry| {
            entry.receipt_ref.command_digest.hex = "0".repeat(64);
        });

        let err = store
            .lookup(&key, ts(4))
            .expect_err("command mismatch rejects");

        assert_eq!(err.code(), error_codes::ERR_VPC_COMMAND_DIGEST_MISMATCH);
    }

    #[test]
    fn input_digest_mismatch_fails_closed() {
        let (_dir, store, key, _entry) = populated_store(|entry| {
            let Some(input_digest) = entry.receipt_ref.input_digests.first_mut() else {
                assert!(!entry.receipt_ref.input_digests.is_empty());
                return;
            };
            input_digest.hex = "1".repeat(64);
        });

        let err = store
            .lookup(&key, ts(4))
            .expect_err("input mismatch rejects");

        assert_eq!(err.code(), error_codes::ERR_VPC_INPUT_DIGEST_MISMATCH);
    }

    #[test]
    fn policy_mismatch_fails_closed() {
        let (_dir, store, key, _entry) = populated_store(|entry| {
            entry.trust.target_dir_policy_id =
                "validation-broker/target-dir/repo-local/v1".to_string();
        });

        let err = store
            .lookup(&key, ts(4))
            .expect_err("policy mismatch rejects");

        assert_eq!(err.code(), error_codes::ERR_VPC_POLICY_MISMATCH);
    }

    #[test]
    fn corrupted_entry_fails_closed() {
        let (_dir, store, key, _entry) = populated_store(|entry| {
            entry.invalidation.active = true;
            entry.invalidation.corrupted = true;
            entry.invalidation.reason = Some("fixture corruption".to_string());
        });

        let err = store
            .lookup(&key, ts(4))
            .expect_err("corrupted entry rejects");

        assert_eq!(err.code(), error_codes::ERR_VPC_CORRUPTED_ENTRY);
    }

    #[test]
    fn duplicate_entry_does_not_overwrite_existing_file() {
        let (_dir, store, _key, entry) = populated_store(|_| {});
        let path = store.entry_path(&entry.cache_key);
        let original = fs::read(&path).expect("original entry");

        let err = store.put_entry(&entry).expect_err("duplicate rejects");
        let after = fs::read(&path).expect("entry after duplicate attempt");

        assert_eq!(err.code(), error_codes::ERR_VPC_DUPLICATE_ENTRY);
        assert_eq!(original, after);
    }

    #[test]
    fn preexisting_unrelated_entry_file_is_not_overwritten() {
        let dir = TempDir::new().expect("tempdir");
        let store = ValidationProofCacheStore::new(dir.path());
        let request = request();
        let receipt = fresh_receipt();
        let (receipt_path, receipt_bytes) = write_receipt(dir.path(), &receipt);
        let key = ValidationProofCacheKey::from_request_and_receipt(&request, &receipt, scope())
            .expect("key");
        let entry = store
            .build_entry(
                key.clone(),
                receipt_path,
                &receipt,
                &receipt_bytes,
                "LavenderElk",
                ts(3),
            )
            .expect("entry");
        let path = store.entry_path(&key);
        fs::create_dir_all(path.parent().expect("entry parent")).expect("entry parent");
        fs::write(&path, b"unrelated").expect("preexisting unrelated file");

        let err = store
            .put_entry(&entry)
            .expect_err("preexisting file rejects");
        let after = fs::read(&path).expect("preexisting after put");

        assert_eq!(err.code(), error_codes::ERR_VPC_DUPLICATE_ENTRY);
        assert_eq!(after, b"unrelated");
    }

    #[test]
    fn deterministic_contract_fixture_loads() {
        let fixture: serde_json::Value = serde_json::from_str(FIXTURE_JSON).expect("fixture json");

        assert_eq!(
            fixture["schema_version"],
            "franken-node/validation-proof-cache/fixtures/v1"
        );
        assert_eq!(
            fixture["valid_cache_keys"].as_array().expect("keys").len(),
            1
        );
        assert_eq!(
            fixture["valid_entries"].as_array().expect("entries").len(),
            1
        );
    }
}
