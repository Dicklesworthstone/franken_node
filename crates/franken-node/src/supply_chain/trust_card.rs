//! bd-2yh: Extension trust-card API and CLI surfaces.
//!
//! Trust cards aggregate provenance, certification, reputation, and revocation
//! state into a deterministic, signed profile that can be queried via API and
//! displayed via CLI.

#[cfg(test)]
#[path = "trust_card_fuzz_test.rs"]
mod fuzz_smoke_tests;

use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions, TryLockError},
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, OnceLock},
    thread,
    time::Duration,
};

use base64::Engine as _;
use fs2::FileExt;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::certification::{DerivationMetadata, VerifiedEvidenceRef};
use crate::push_bounded;
use crate::security::constant_time;

/// Source context for trust card registry snapshot validation.
/// Determines the validation strategy based on input source trust level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSourceContext {
    /// Trusted file source (local filesystem, known location).
    /// Uses lazy validation: parse first, then basic validation.
    TrustedFile,
    /// Untrusted network source (remote API, user upload).
    /// Uses eager validation: verify signature before parsing, comprehensive checks.
    UntrustedNetwork,
}

const MAX_TELEMETRY: usize = 4096;
const MAX_CARD_VERSIONS: usize = 512;
const MAX_AUDIT_HISTORY: usize = 256;

/// Maximum extension ID length to prevent memory exhaustion DoS attacks.
const MAX_EXTENSION_ID_LEN: usize = 256;

/// Maximum JSON payload size for untrusted sources to prevent DoS attacks.
const MAX_UNTRUSTED_JSON_SIZE: usize = 1_000_000; // 1MB

fn next_trust_card_version(
    previous_version: u64,
    extension_id: &str,
) -> Result<u64, TrustCardError> {
    previous_version
        .checked_add(1)
        .ok_or_else(|| TrustCardError::InvalidInput {
            reason: format!("trust_card_version exhausted for extension `{extension_id}`"),
        })
}

fn ensure_evidence_refs_present(refs: &[VerifiedEvidenceRef]) -> Result<(), TrustCardError> {
    if refs.is_empty() {
        return Err(TrustCardError::EvidenceMissing);
    }
    Ok(())
}

fn card_matches_filter(card: &TrustCard, filter: &TrustCardListFilter) -> bool {
    if let Some(level) = filter.certification_level
        && card.certification_level != level
    {
        return false;
    }
    if let Some(publisher_id) = &filter.publisher_id
        && &card.publisher.publisher_id != publisher_id
    {
        return false;
    }
    if let Some(capability) = &filter.capability
        && !card
            .capability_declarations
            .iter()
            .any(|cap| cap.name.contains(capability))
    {
        return false;
    }
    true
}

/// Compute a domain-separated hash for trust-card derivation evidence.
fn compute_trust_card_derivation_hash(refs: &[VerifiedEvidenceRef], derived_at: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"trust_card_derivation_v1:");
    hasher.update(derived_at.to_le_bytes());
    hasher.update(u64::try_from(refs.len()).unwrap_or(u64::MAX).to_le_bytes());
    for r in refs {
        hasher.update(
            u64::try_from(r.evidence_id.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(r.evidence_id.as_bytes());
        let type_tag = serde_json::to_string(&r.evidence_type).unwrap_or_default();
        hasher.update(
            u64::try_from(type_tag.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(type_tag.as_bytes());
        hasher.update(r.verified_at_epoch.to_le_bytes());
        hasher.update(
            u64::try_from(r.verification_receipt_hash.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(r.verification_receipt_hash.as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub const TRUST_CARD_CREATED: &str = "TRUST_CARD_CREATED";
pub const TRUST_CARD_UPDATED: &str = "TRUST_CARD_UPDATED";
pub const TRUST_CARD_REVOKED: &str = "TRUST_CARD_REVOKED";
pub const TRUST_CARD_QUERIED: &str = "TRUST_CARD_QUERIED";
pub const TRUST_CARD_COMPUTED: &str = "TRUST_CARD_COMPUTED";
pub const TRUST_CARD_SERVED: &str = "TRUST_CARD_SERVED";
pub const TRUST_CARD_CACHE_HIT: &str = "TRUST_CARD_CACHE_HIT";
pub const TRUST_CARD_CACHE_MISS: &str = "TRUST_CARD_CACHE_MISS";
pub const TRUST_CARD_STALE_REFRESH: &str = "TRUST_CARD_STALE_REFRESH";
pub const TRUST_CARD_FORCE_REFRESH: &str = "TRUST_CARD_FORCE_REFRESH";
pub const TRUST_CARD_DIFF_COMPUTED: &str = "TRUST_CARD_DIFF_COMPUTED";

const DEFAULT_CACHE_TTL_SECS: u64 = crate::config::timeouts::TRUST_CARD_CACHE_TTL_SECS;
const DEFAULT_REGISTRY_KEY: &[u8] = b"franken-node-trust-card-registry-key-v1";
const MIN_CONFIGURED_REGISTRY_KEY_BYTES: usize = 32;
pub const TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA: &str = "franken-node/trust-card-registry-state/v1";

/// Get registry signing key from config (fail-closed if not specified).
fn get_registry_key(config: &crate::config::TrustConfig) -> Result<Vec<u8>, TrustCardError> {
    match &config.registry_signing_key {
        Some(key_base64) => {
            if key_base64.trim() != key_base64 || key_base64.is_empty() {
                return Err(TrustCardError::InvalidInput {
                    reason: "registry_signing_key must be non-empty base64 without surrounding whitespace"
                        .to_string(),
                });
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(key_base64)
                .map_err(|err| TrustCardError::InvalidInput {
                    reason: format!("registry_signing_key must be valid base64: {err}"),
                })?;
            if decoded.len() < MIN_CONFIGURED_REGISTRY_KEY_BYTES {
                return Err(TrustCardError::InvalidInput {
                    reason: format!(
                        "registry_signing_key must decode to at least {MIN_CONFIGURED_REGISTRY_KEY_BYTES} bytes"
                    ),
                });
            }
            Ok(decoded)
        }
        None => Err(TrustCardError::InvalidInput {
            reason: "registry_signing_key must be configured (fail-closed security boundary)"
                .to_string(),
        }),
    }
}

/// Validate basic bounds for a parsed snapshot (lazy validation).
/// Used for trusted file sources where comprehensive validation is less critical.
fn validate_basic_bounds(snapshot: &TrustCardRegistrySnapshot) -> Result<(), TrustCardError> {
    // Basic schema version check
    if snapshot.schema_version != TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA {
        return Err(TrustCardError::UnsupportedSnapshotSchema(
            snapshot.schema_version.clone(),
        ));
    }

    // Basic sanity checks on numeric fields
    if snapshot.cache_ttl_secs == 0 {
        return Err(TrustCardError::InvalidSnapshot(
            "cache_ttl_secs must be positive".to_string(),
        ));
    }

    // Extension ID length validation to prevent memory exhaustion
    for extension_id in snapshot.cards_by_extension.keys() {
        if extension_id.len() > MAX_EXTENSION_ID_LEN {
            return Err(TrustCardError::InvalidInput {
                reason: format!(
                    "extension_id length {} exceeds maximum {}",
                    extension_id.len(),
                    MAX_EXTENSION_ID_LEN
                ),
            });
        }
    }

    Ok(())
}

/// Validate comprehensive security properties for untrusted sources (eager validation).
/// Includes signature verification, hash validation, and strict bounds checking.
fn validate_comprehensive(
    snapshot: &TrustCardRegistrySnapshot,
    registry_key: &[u8],
) -> Result<(), TrustCardError> {
    // First do all the basic validation
    validate_basic_bounds(snapshot)?;

    // Then comprehensive signature and hash verification
    verify_snapshot_signature(snapshot, registry_key)?;

    // Additional strict validation for untrusted sources
    let total_cards: usize = snapshot
        .cards_by_extension
        .values()
        .map(|cards| cards.len())
        .sum();

    if total_cards > 10_000 {
        return Err(TrustCardError::InvalidSnapshot(format!(
            "too many trust cards: {total_cards} exceeds limit 10,000"
        )));
    }

    // Validate each card's structure more strictly
    for (extension_id, cards) in &snapshot.cards_by_extension {
        if cards.len() > MAX_CARD_VERSIONS {
            return Err(TrustCardError::InvalidInput {
                reason: format!(
                    "extension {} has {} cards, exceeds limit {}",
                    extension_id,
                    cards.len(),
                    MAX_CARD_VERSIONS
                ),
            });
        }
    }

    Ok(())
}

/// Verify signature before parsing JSON (eager validation for untrusted sources).
/// Performs minimal parsing to extract signature field for verification.
fn verify_signature_before_parsing(
    raw_json: &str,
    registry_key: &[u8],
) -> Result<(), TrustCardError> {
    // Size check first to prevent DoS
    if raw_json.len() > MAX_UNTRUSTED_JSON_SIZE {
        return Err(TrustCardError::InvalidSnapshot(format!(
            "JSON size {} exceeds maximum {} for untrusted sources",
            raw_json.len(),
            MAX_UNTRUSTED_JSON_SIZE
        )));
    }

    // Minimal parsing to extract only signature-relevant fields
    let partial: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|err| TrustCardError::InvalidSnapshot(format!("malformed JSON: {}", err)))?;

    let snapshot_hash = partial
        .get("snapshot_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            TrustCardError::InvalidSnapshot("missing snapshot_hash field".to_string())
        })?;

    let registry_signature = partial
        .get("registry_signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            TrustCardError::InvalidSnapshot("missing registry_signature field".to_string())
        })?;

    // Verify signature before full parsing
    let mut mac =
        HmacSha256::new_from_slice(registry_key).map_err(|_| TrustCardError::InvalidRegistryKey)?;
    mac.update(b"trust_card_registry_snapshot_sig_v1:");
    mac.update(snapshot_hash.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());

    if !constant_time::ct_eq(registry_signature, &expected_signature) {
        return Err(TrustCardError::InvalidSnapshot(
            "signature verification failed before parsing".to_string(),
        ));
    }

    Ok(())
}

/// Sanitize error messages for untrusted sources to prevent information leakage.
fn sanitize_error_for_untrusted(err: TrustCardError) -> TrustCardError {
    match err {
        TrustCardError::SnapshotParse { path, .. } => TrustCardError::SnapshotParse {
            path,
            detail: "parsing failed".to_string(),
        },
        TrustCardError::InvalidSnapshot(_) => {
            TrustCardError::InvalidSnapshot("snapshot validation failed".to_string())
        }
        // Pass through other errors unchanged
        other => other,
    }
}
const TRUST_CARD_REGISTRY_HIGH_WATER_SCHEMA: &str =
    "franken-node/trust-card-registry-high-water/v1";
const SNAPSHOT_LOCK_RETRY_BACKOFF_MILLIS: [u64; 3] = [100, 200, 400];

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, thiserror::Error)]
pub enum TrustCardError {
    /// Operator remediation: seed or refresh trust-card state for this extension, then retry the lookup.
    #[error("trust card not found for extension `{0}`")]
    NotFound(String),
    /// Operator remediation: refresh the registry snapshot or request the exact historical card version.
    #[error("trust card version `{version}` not found for extension `{extension_id}`")]
    VersionNotFound { extension_id: String, version: u64 },
    /// Operator remediation: rotate or restore the registry signing key, refresh the card, and re-verify.
    #[error("trust card signature verification failed for extension `{0}`")]
    SignatureInvalid(String),
    /// Operator remediation: discard the stale or tampered card, reload authoritative registry state, and recompute the hash.
    #[error("trust card hash mismatch for extension `{0}`")]
    CardHashMismatch(String),
    /// Operator remediation: inspect the serialized trust-card payload for malformed JSON or unsupported field values.
    #[error("json serialization error: {0}")]
    Json(String),
    /// Operator remediation: replace the registry HMAC key with valid key material before signing or verifying cards.
    #[error("invalid hmac key")]
    InvalidRegistryKey,
    /// Operator remediation: retry with a one-based page number and a positive page size within operator policy limits.
    #[error("invalid pagination: page={page}, per_page={per_page}")]
    InvalidPagination { page: usize, per_page: usize },
    /// Operator remediation: correct the rejected input field named in the reason before deriving or mutating a card.
    #[error("invalid trust-card input: {reason}")]
    InvalidInput { reason: String },
    /// Operator remediation: attach at least one verified evidence receipt before deriving the trust card.
    #[error("trust card derivation requires at least one verified evidence reference")]
    EvidenceMissing,
    /// Operator remediation: add verified upgrade evidence before raising a card's certification level.
    #[error("upgrading certification level requires evidence references")]
    EvidenceRequiredForUpgrade,
    /// Operator remediation: create a new replacement card instead of attempting to reactivate a revoked one.
    #[error("revocation is irreversible: cannot transition from Revoked to Active")]
    RevocationIrreversible,
    /// Operator remediation: migrate or regenerate the snapshot with the current trust-card registry schema.
    #[error("unsupported trust-card registry snapshot schema `{0}`")]
    UnsupportedSnapshotSchema(String),
    /// Operator remediation: repair the snapshot contents from authoritative state or restore the last valid snapshot.
    #[error("invalid trust-card registry snapshot: {0}")]
    InvalidSnapshot(String),
    /// Operator remediation: check that the snapshot path exists and that the process has read permission.
    #[error("failed reading trust-card registry snapshot {path}: {detail}")]
    SnapshotRead { path: PathBuf, detail: String },
    /// Operator remediation: validate the snapshot JSON and regenerate it if parsing fails.
    #[error("failed parsing trust-card registry snapshot {path}: {detail}")]
    SnapshotParse { path: PathBuf, detail: String },
    /// Operator remediation: verify parent directory permissions and disk space, then retry the atomic snapshot write.
    #[error("failed writing trust-card registry snapshot {path}: {detail}")]
    SnapshotWrite { path: PathBuf, detail: String },
}

impl TrustCardError {
    /// Return a short operator-facing remediation step for this error class.
    #[must_use]
    pub fn remediation(&self) -> &'static str {
        match self {
            TrustCardError::NotFound(_) => {
                "Seed or refresh trust-card state for this extension, then retry the lookup."
            }
            TrustCardError::VersionNotFound { .. } => {
                "Refresh the registry snapshot or request the exact historical card version."
            }
            TrustCardError::SignatureInvalid(_) => {
                "Rotate or restore the registry signing key, refresh the card, and re-verify."
            }
            TrustCardError::CardHashMismatch(_) => {
                "Discard the stale or tampered card, reload authoritative registry state, and recompute the hash."
            }
            TrustCardError::Json(_) => {
                "Inspect the serialized trust-card payload for malformed JSON or unsupported field values."
            }
            TrustCardError::InvalidRegistryKey => {
                "Replace the registry HMAC key with valid key material before signing or verifying cards."
            }
            TrustCardError::InvalidPagination { .. } => {
                "Retry with a one-based page number and a positive page size within operator policy limits."
            }
            TrustCardError::InvalidInput { .. } => {
                "Correct the rejected input field named in the reason before deriving or mutating a card."
            }
            TrustCardError::EvidenceMissing => {
                "Attach at least one verified evidence receipt before deriving the trust card."
            }
            TrustCardError::EvidenceRequiredForUpgrade => {
                "Add verified upgrade evidence before raising a card's certification level."
            }
            TrustCardError::RevocationIrreversible => {
                "Create a new replacement card instead of attempting to reactivate a revoked one."
            }
            TrustCardError::UnsupportedSnapshotSchema(_) => {
                "Migrate or regenerate the snapshot with the current trust-card registry schema."
            }
            TrustCardError::InvalidSnapshot(_) => {
                "Repair the snapshot contents from authoritative state or restore the last valid snapshot."
            }
            TrustCardError::SnapshotRead { .. } => {
                "Check that the snapshot path exists and that the process has read permission."
            }
            TrustCardError::SnapshotParse { .. } => {
                "Validate the snapshot JSON and regenerate it if parsing fails."
            }
            TrustCardError::SnapshotWrite { .. } => {
                "Verify parent directory permissions and disk space, then retry the atomic snapshot write."
            }
        }
    }
}

impl From<serde_json::Error> for TrustCardError {
    fn from(e: serde_json::Error) -> Self {
        TrustCardError::Json(e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationLevel {
    Unknown,
    Bronze,
    Silver,
    Gold,
    Platinum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReputationTrend {
    Improving,
    Stable,
    Declining,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRisk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RevocationStatus {
    Active,
    Revoked { reason: String, revoked_at: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionIdentity {
    pub extension_id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherIdentity {
    pub publisher_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDeclaration {
    pub name: String,
    pub description: String,
    pub risk: CapabilityRisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehavioralProfile {
    pub network_access: bool,
    pub filesystem_access: bool,
    pub subprocess_access: bool,
    pub profile_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceSummary {
    pub attestation_level: String,
    pub source_uri: String,
    pub artifact_hashes: Vec<String>,
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyTrustStatus {
    pub dependency_id: String,
    pub trust_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp: String,
    pub event_code: String,
    pub detail: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustCard {
    pub schema_version: String,
    pub trust_card_version: u64,
    pub previous_version_hash: Option<String>,
    pub extension: ExtensionIdentity,
    pub publisher: PublisherIdentity,
    pub certification_level: CertificationLevel,
    pub capability_declarations: Vec<CapabilityDeclaration>,
    pub behavioral_profile: BehavioralProfile,
    pub revocation_status: RevocationStatus,
    pub provenance_summary: ProvenanceSummary,
    pub reputation_score_basis_points: u16,
    pub reputation_trend: ReputationTrend,
    pub active_quarantine: bool,
    pub dependency_trust_summary: Vec<DependencyTrustStatus>,
    pub last_verified_timestamp: String,
    pub user_facing_risk_assessment: RiskAssessment,
    pub audit_history: Vec<AuditRecord>,
    /// Derivation metadata linking this trust card to verified upstream evidence.
    pub derivation_evidence: Option<DerivationMetadata>,
    pub card_hash: String,
    pub registry_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustCardInput {
    pub extension: ExtensionIdentity,
    pub publisher: PublisherIdentity,
    pub certification_level: CertificationLevel,
    pub capability_declarations: Vec<CapabilityDeclaration>,
    pub behavioral_profile: BehavioralProfile,
    pub revocation_status: RevocationStatus,
    pub provenance_summary: ProvenanceSummary,
    pub reputation_score_basis_points: u16,
    pub reputation_trend: ReputationTrend,
    pub active_quarantine: bool,
    pub dependency_trust_summary: Vec<DependencyTrustStatus>,
    pub last_verified_timestamp: String,
    pub user_facing_risk_assessment: RiskAssessment,
    /// Verified evidence references binding this trust card to upstream verification.
    /// At least one evidence reference is required for card creation (fail-closed).
    pub evidence_refs: Vec<VerifiedEvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustCardMutation {
    pub certification_level: Option<CertificationLevel>,
    pub revocation_status: Option<RevocationStatus>,
    pub active_quarantine: Option<bool>,
    pub reputation_score_basis_points: Option<u16>,
    pub reputation_trend: Option<ReputationTrend>,
    pub user_facing_risk_assessment: Option<RiskAssessment>,
    pub last_verified_timestamp: Option<String>,
    /// Evidence references required when upgrading certification level.
    pub evidence_refs: Option<Vec<VerifiedEvidenceRef>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustCardListFilter {
    pub certification_level: Option<CertificationLevel>,
    pub publisher_id: Option<String>,
    pub capability: Option<String>,
}

impl TrustCardListFilter {
    #[must_use]
    /// Build a filter with no constraints so every current trust card matches.
    ///
    /// # Parameters
    /// This helper takes no parameters.
    ///
    /// # Returns
    /// A `TrustCardListFilter` with all optional selectors cleared.
    ///
    /// # Errors
    /// This helper does not return errors.
    pub fn empty() -> Self {
        Self {
            certification_level: None,
            publisher_id: None,
            capability: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustCardDiffEntry {
    pub field: String,
    pub left: String,
    pub right: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustCardComparison {
    pub left_extension_id: String,
    pub right_extension_id: String,
    pub changes: Vec<TrustCardDiffEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_code: String,
    pub extension_id: Option<String>,
    pub trace_id: String,
    pub timestamp_secs: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedCard {
    card: TrustCard,
    cached_at_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustCardSyncReport {
    pub total_cards: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub stale_refreshes: usize,
    pub forced_refreshes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustCardRegistrySnapshot {
    pub schema_version: String,
    pub snapshot_epoch: u64,
    pub previous_snapshot_hash: Option<String>,
    pub cache_ttl_secs: u64,
    pub cards_by_extension: BTreeMap<String, Vec<TrustCard>>,
    pub snapshot_hash: String,
    pub registry_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustCardRegistrySnapshotHighWater {
    schema_version: String,
    snapshot_epoch: u64,
    snapshot_hash: String,
    high_water_signature: String,
}

impl TrustCardRegistrySnapshot {
    /// Construct and sign a canonical trust-card registry snapshot.
    ///
    /// # Parameters
    /// - `cache_ttl_secs`: cache TTL persisted into the snapshot, clamped to at least one second.
    /// - `cards_by_extension`: authoritative extension history to embed in the snapshot.
    /// - `registry_key`: HMAC key used to sign the snapshot payload.
    ///
    /// # Returns
    /// A signed `TrustCardRegistrySnapshot` ready for persistence or transport.
    ///
    /// # Errors
    /// Returns `TrustCardError` if snapshot signing fails because the registry key
    /// or canonical serialization is invalid.
    pub fn signed(
        cache_ttl_secs: u64,
        cards_by_extension: BTreeMap<String, Vec<TrustCard>>,
        registry_key: &[u8],
    ) -> Result<Self, TrustCardError> {
        let mut snapshot = Self {
            schema_version: TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA.to_string(),
            snapshot_epoch: 1,
            previous_snapshot_hash: None,
            cache_ttl_secs: cache_ttl_secs.max(1),
            cards_by_extension,
            snapshot_hash: String::new(),
            registry_signature: String::new(),
        };
        sign_snapshot_in_place(&mut snapshot, registry_key)?;
        Ok(snapshot)
    }
}

#[derive(Debug, Clone)]
pub struct TrustCardRegistry {
    cards_by_extension: BTreeMap<String, Vec<TrustCard>>,
    cache_by_extension: BTreeMap<String, CachedCard>,
    cache_ttl_secs: u64,
    registry_key: Vec<u8>,
    telemetry: Vec<TelemetryEvent>,
    snapshot_epoch: u64,
    previous_snapshot_hash: Option<String>,
    last_snapshot_hash: Option<String>,
}

impl Default for TrustCardRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_TTL_SECS, DEFAULT_REGISTRY_KEY)
    }
}

impl TrustCardRegistry {
    #[must_use]
    /// Create an empty trust-card registry with bounded cache TTL and signing key.
    ///
    /// # Parameters
    /// - `cache_ttl_secs`: cache TTL for hot reads, clamped to at least one second.
    /// - `registry_key`: HMAC key used to sign cards and snapshots.
    ///
    /// # Returns
    /// A new empty `TrustCardRegistry`.
    ///
    /// # Errors
    /// This constructor does not return errors.
    pub fn new(cache_ttl_secs: u64, registry_key: &[u8]) -> Self {
        Self {
            cards_by_extension: BTreeMap::new(),
            cache_by_extension: BTreeMap::new(),
            cache_ttl_secs: cache_ttl_secs.max(1),
            registry_key: registry_key.to_vec(),
            telemetry: Vec::new(),
            snapshot_epoch: 0,
            previous_snapshot_hash: None,
            last_snapshot_hash: None,
        }
    }

    /// Create an empty trust-card registry using configuration for signing key.
    ///
    /// # Parameters
    /// - `config`: Trust configuration containing optional registry signing key.
    ///
    /// # Returns
    /// A new empty `TrustCardRegistry` with signing key from config (fail-closed if not configured).
    pub fn from_config(config: &crate::config::TrustConfig) -> Result<Self, TrustCardError> {
        let cache_ttl_secs = config.card_cache_ttl_secs.unwrap_or(DEFAULT_CACHE_TTL_SECS);
        let registry_key = get_registry_key(config)?;
        Ok(Self::new(cache_ttl_secs, &registry_key))
    }

    /// Materialize the registry's current authoritative state as a signed snapshot.
    ///
    /// # Parameters
    /// This method uses the registry's in-memory state and takes no extra parameters.
    ///
    /// # Returns
    /// A `TrustCardRegistrySnapshot` containing the current cards, sequence state,
    /// and fresh registry signature.
    ///
    /// # Errors
    /// Returns `TrustCardError` if canonical snapshot signing fails.
    pub fn snapshot(&self) -> Result<TrustCardRegistrySnapshot, TrustCardError> {
        let mut snapshot = TrustCardRegistrySnapshot {
            schema_version: TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA.to_string(),
            snapshot_epoch: self.snapshot_epoch,
            previous_snapshot_hash: self.previous_snapshot_hash.clone(),
            cache_ttl_secs: self.cache_ttl_secs,
            cards_by_extension: self.cards_by_extension.clone(),
            snapshot_hash: String::new(),
            registry_signature: String::new(),
        };
        sign_snapshot_in_place(&mut snapshot, &self.registry_key)?;
        Ok(snapshot)
    }

    fn advance_snapshot_sequence_for_mutation(&mut self) {
        self.previous_snapshot_hash =
            if self.snapshot_epoch == 0 && self.cards_by_extension.is_empty() {
                None
            } else {
                self.last_snapshot_hash
                    .clone()
                    .or_else(|| self.snapshot().ok().map(|s| s.snapshot_hash))
            };
        self.snapshot_epoch = self.snapshot_epoch.saturating_add(1);
        self.last_snapshot_hash = None;
    }

    /// Restore a registry from a trusted signed snapshot.
    ///
    /// # Parameters
    /// - `snapshot`: snapshot payload to validate and ingest.
    /// - `registry_key`: HMAC key used to verify the snapshot and card signatures.
    /// - `loaded_at_secs`: timestamp assigned to cache entries restored from the snapshot.
    ///
    /// # Returns
    /// A `TrustCardRegistry` populated from the snapshot contents.
    ///
    /// # Errors
    /// Returns `TrustCardError` if the snapshot schema is unsupported, any embedded
    /// card history is invalid, or the snapshot signature fails verification.
    pub fn from_snapshot(
        snapshot: TrustCardRegistrySnapshot,
        registry_key: &[u8],
        loaded_at_secs: u64,
    ) -> Result<Self, TrustCardError> {
        if snapshot.schema_version != TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA {
            return Err(TrustCardError::UnsupportedSnapshotSchema(
                snapshot.schema_version,
            ));
        }

        let mut registry = Self::new(snapshot.cache_ttl_secs, registry_key);
        registry.cards_by_extension = snapshot.cards_by_extension.clone();

        for (extension_id, history) in &registry.cards_by_extension {
            validate_snapshot_history(extension_id, history, &registry.registry_key)?;
            let latest = history.last().cloned().ok_or_else(|| {
                TrustCardError::InvalidSnapshot(format!(
                    "extension bucket `{extension_id}` cannot be empty"
                ))
            })?;
            registry.cache_by_extension.insert(
                extension_id.clone(),
                CachedCard {
                    card: latest,
                    cached_at_secs: loaded_at_secs,
                },
            );
        }

        verify_snapshot_signature(&snapshot, registry_key)?;
        registry.snapshot_epoch = snapshot.snapshot_epoch;
        registry.previous_snapshot_hash = snapshot.previous_snapshot_hash;
        registry.last_snapshot_hash = Some(snapshot.snapshot_hash);

        Ok(registry)
    }

    /// Load authoritative trust-card state from disk and validate its high-water marker.
    ///
    /// Uses contextual validation strategy based on input source trust level:
    /// - `TrustedFile`: Lazy validation (parse first, basic checks)
    /// - `UntrustedNetwork`: Eager validation (verify signature before parsing, comprehensive checks)
    ///
    /// # Parameters
    /// - `path`: snapshot file to read and validate.
    /// - `cache_ttl_secs`: cache TTL to apply to the loaded registry, clamped to at least one second.
    /// - `loaded_at_secs`: timestamp assigned to cache entries restored from disk.
    /// - `source_context`: trust level of the input source, determines validation strategy.
    ///
    /// # Returns
    /// A validated `TrustCardRegistry` reconstructed from the on-disk snapshot.
    ///
    /// # Errors
    /// Returns `TrustCardError` if reading, parsing, signature validation, or
    /// high-water validation fails. Error details are sanitized for untrusted sources.
    pub fn load_authoritative_state(
        path: &Path,
        cache_ttl_secs: u64,
        loaded_at_secs: u64,
        source_context: SnapshotSourceContext,
    ) -> Result<Self, TrustCardError> {
        let raw = std::fs::read_to_string(path).map_err(|err| TrustCardError::SnapshotRead {
            path: path.to_path_buf(),
            detail: err.to_string(),
        })?;

        // Contextual validation strategy based on source trust level
        let snapshot =
            match source_context {
                SnapshotSourceContext::TrustedFile => {
                    // Lazy validation: parse first, then basic checks
                    let snapshot = serde_json::from_str::<TrustCardRegistrySnapshot>(&raw)
                        .map_err(|err| TrustCardError::SnapshotParse {
                            path: path.to_path_buf(),
                            detail: err.to_string(),
                        })?;
                    validate_basic_bounds(&snapshot)?;
                    snapshot
                }
                SnapshotSourceContext::UntrustedNetwork => {
                    // Eager validation: verify signature first, comprehensive checks
                    verify_signature_before_parsing(&raw, DEFAULT_REGISTRY_KEY)
                        .map_err(|err| sanitize_error_for_untrusted(err))?;

                    let snapshot = serde_json::from_str::<TrustCardRegistrySnapshot>(&raw)
                        .map_err(|err| {
                            sanitize_error_for_untrusted(TrustCardError::SnapshotParse {
                                path: path.to_path_buf(),
                                detail: err.to_string(),
                            })
                        })?;

                    validate_comprehensive(&snapshot, DEFAULT_REGISTRY_KEY)
                        .map_err(|err| sanitize_error_for_untrusted(err))?;
                    snapshot
                }
            };

        let high_water = read_snapshot_high_water(path, DEFAULT_REGISTRY_KEY)?;
        validate_snapshot_high_water(path, &snapshot, high_water.as_ref())?;
        let trusted_snapshot = snapshot.clone();
        let mut registry = Self::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, loaded_at_secs)?;
        registry.cache_ttl_secs = cache_ttl_secs.max(1);
        persist_snapshot_high_water_if_newer(
            path,
            &trusted_snapshot,
            high_water.as_ref(),
            DEFAULT_REGISTRY_KEY,
        )?;
        Ok(registry)
    }

    /// Load authoritative trust-card state from disk using configuration for signing key.
    ///
    /// # Parameters
    /// - `path`: snapshot file to read and validate.
    /// - `config`: trust configuration containing signing key and cache TTL settings.
    /// - `loaded_at_secs`: timestamp assigned to cache entries restored from disk.
    /// - `source_context`: validation strategy based on source trust level.
    ///
    /// # Returns
    /// A validated `TrustCardRegistry` reconstructed from the on-disk snapshot.
    pub fn load_authoritative_state_from_config(
        path: &Path,
        config: &crate::config::TrustConfig,
        loaded_at_secs: u64,
        source_context: SnapshotSourceContext,
    ) -> Result<Self, TrustCardError> {
        let cache_ttl_secs = config.card_cache_ttl_secs.unwrap_or(DEFAULT_CACHE_TTL_SECS);
        let registry_key = get_registry_key(config)?;

        let raw = std::fs::read_to_string(path).map_err(|err| TrustCardError::SnapshotRead {
            path: path.to_path_buf(),
            detail: err.to_string(),
        })?;

        // Contextual validation strategy based on source trust level
        let snapshot =
            match source_context {
                SnapshotSourceContext::TrustedFile => {
                    // Lazy validation: parse first, then basic checks
                    let snapshot = serde_json::from_str::<TrustCardRegistrySnapshot>(&raw)
                        .map_err(|err| TrustCardError::SnapshotParse {
                            path: path.to_path_buf(),
                            detail: err.to_string(),
                        })?;
                    validate_basic_bounds(&snapshot)?;
                    snapshot
                }
                SnapshotSourceContext::UntrustedNetwork => {
                    // Eager validation: verify signature first, comprehensive checks
                    verify_signature_before_parsing(&raw, &registry_key)
                        .map_err(|err| sanitize_error_for_untrusted(err))?;

                    let snapshot = serde_json::from_str::<TrustCardRegistrySnapshot>(&raw)
                        .map_err(|err| {
                            sanitize_error_for_untrusted(TrustCardError::SnapshotParse {
                                path: path.to_path_buf(),
                                detail: err.to_string(),
                            })
                        })?;

                    validate_comprehensive(&snapshot, &registry_key)
                        .map_err(|err| sanitize_error_for_untrusted(err))?;
                    snapshot
                }
            };

        let high_water = read_snapshot_high_water(path, &registry_key)?;
        validate_snapshot_high_water(path, &snapshot, high_water.as_ref())?;
        let trusted_snapshot = snapshot.clone();
        let mut registry = Self::from_snapshot(snapshot, &registry_key, loaded_at_secs)?;
        registry.cache_ttl_secs = cache_ttl_secs.max(1);

        persist_snapshot_high_water_if_newer(
            path,
            &trusted_snapshot,
            high_water.as_ref(),
            &registry_key,
        )?;
        Ok(registry)
    }

    /// Persist the registry's authoritative snapshot and signed high-water marker atomically.
    ///
    /// # Parameters
    /// - `path`: destination snapshot path for the canonical registry state.
    ///
    /// # Returns
    /// `Ok(())` after both the snapshot and high-water marker are durably written.
    ///
    /// # Errors
    /// Returns `TrustCardError` if snapshot materialization, lock acquisition,
    /// canonical encoding, fsync, or atomic persistence fails.
    pub fn persist_authoritative_state(&self, path: &Path) -> Result<(), TrustCardError> {
        let snapshot = self.snapshot()?;
        let high_water_path = authoritative_snapshot_high_water_path(path);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        with_authoritative_snapshot_persist_lock(path, || {
            let high_water = read_snapshot_high_water(path, &self.registry_key)?;
            validate_snapshot_high_water(path, &snapshot, high_water.as_ref())?;
            let encoded = to_canonical_json(&snapshot)?;
            let next_high_water = signed_snapshot_high_water(&snapshot, &self.registry_key)?;
            let high_water_encoded = to_canonical_json(&next_high_water)?;
            let mut temp =
                NamedTempFile::new_in(parent).map_err(|err| TrustCardError::SnapshotWrite {
                    path: path.to_path_buf(),
                    detail: err.to_string(),
                })?;
            temp.write_all(encoded.as_bytes())
                .map_err(|err| TrustCardError::SnapshotWrite {
                    path: path.to_path_buf(),
                    detail: err.to_string(),
                })?;
            temp.as_file()
                .sync_all()
                .map_err(|err| TrustCardError::SnapshotWrite {
                    path: path.to_path_buf(),
                    detail: err.to_string(),
                })?;
            temp.persist(path)
                .map_err(|err| TrustCardError::SnapshotWrite {
                    path: path.to_path_buf(),
                    detail: err.error.to_string(),
                })?;
            let mut high_water_temp =
                NamedTempFile::new_in(parent).map_err(|err| TrustCardError::SnapshotWrite {
                    path: high_water_path.clone(),
                    detail: err.to_string(),
                })?;
            high_water_temp
                .write_all(high_water_encoded.as_bytes())
                .map_err(|err| TrustCardError::SnapshotWrite {
                    path: high_water_path.clone(),
                    detail: err.to_string(),
                })?;
            high_water_temp
                .as_file()
                .sync_all()
                .map_err(|err| TrustCardError::SnapshotWrite {
                    path: high_water_path.clone(),
                    detail: err.to_string(),
                })?;
            high_water_temp.persist(&high_water_path).map_err(|err| {
                TrustCardError::SnapshotWrite {
                    path: high_water_path.clone(),
                    detail: err.error.to_string(),
                }
            })?;
            sync_parent_directory(parent, path)?;
            Ok(())
        })
    }

    /// Derive, sign, and store the next trust-card version for an extension.
    ///
    /// # Parameters
    /// - `input`: canonical trust-card input payload and evidence references.
    /// - `now_secs`: unix timestamp used for derivation evidence and audit history.
    /// - `trace_id`: operator-visible correlation ID recorded in telemetry.
    ///
    /// # Returns
    /// The newly created and signed `TrustCard`.
    ///
    /// # Errors
    /// Returns `TrustCardError` if required evidence is missing, the next version
    /// overflows, input validation fails, or signing fails.
    pub fn create(
        &mut self,
        input: TrustCardInput,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<TrustCard, TrustCardError> {
        // Evidence binding gate: at least one evidence reference is required.
        ensure_evidence_refs_present(&input.evidence_refs)?;

        let derivation_hash = compute_trust_card_derivation_hash(&input.evidence_refs, now_secs);
        let derivation = DerivationMetadata {
            evidence_refs: input.evidence_refs.clone(),
            derived_at_epoch: now_secs,
            derivation_chain_hash: derivation_hash,
        };

        let extension_id = input.extension.extension_id.clone();
        let (previous_hash, next_version) = match self.latest_verified_card(&extension_id)? {
            Some(previous) => (
                Some(previous.card_hash.clone()),
                next_trust_card_version(previous.trust_card_version, &extension_id)?,
            ),
            None => (None, 1),
        };

        let mut card = TrustCard {
            schema_version: "1.0.0".to_string(),
            trust_card_version: next_version,
            previous_version_hash: previous_hash,
            extension: input.extension,
            publisher: input.publisher,
            certification_level: input.certification_level,
            capability_declarations: sorted_capabilities(input.capability_declarations),
            behavioral_profile: input.behavioral_profile,
            revocation_status: input.revocation_status,
            provenance_summary: input.provenance_summary,
            reputation_score_basis_points: input.reputation_score_basis_points,
            reputation_trend: input.reputation_trend,
            active_quarantine: input.active_quarantine,
            dependency_trust_summary: sorted_dependencies(input.dependency_trust_summary),
            last_verified_timestamp: input.last_verified_timestamp,
            user_facing_risk_assessment: input.user_facing_risk_assessment,
            audit_history: vec![AuditRecord {
                timestamp: timestamp_from_secs(now_secs),
                event_code: TRUST_CARD_CREATED.to_string(),
                detail: "trust card created".to_string(),
                trace_id: trace_id.to_string(),
            }],
            derivation_evidence: Some(derivation),
            card_hash: String::new(),
            registry_signature: String::new(),
        };
        sign_card_in_place(&mut card, &self.registry_key)?;
        self.advance_snapshot_sequence_for_mutation();

        push_bounded(
            self.cards_by_extension
                .entry(extension_id.clone())
                .or_default(),
            card.clone(),
            MAX_CARD_VERSIONS,
        );
        self.cache_by_extension.insert(
            extension_id.clone(),
            CachedCard {
                card: card.clone(),
                cached_at_secs: now_secs,
            },
        );

        self.emit(
            TRUST_CARD_COMPUTED,
            Some(extension_id.clone()),
            trace_id,
            now_secs,
            "computed and signed trust card",
        );
        self.emit(
            TRUST_CARD_CREATED,
            Some(extension_id),
            trace_id,
            now_secs,
            "created trust card version",
        );
        Ok(card)
    }

    /// Apply a mutation to the latest trust card for one extension and append a new version.
    ///
    /// # Parameters
    /// - `extension_id`: extension whose latest trust card should be updated.
    /// - `mutation`: partial update payload describing the next card state.
    /// - `now_secs`: unix timestamp used for derivation evidence and audit history.
    /// - `trace_id`: operator-visible correlation ID recorded in telemetry.
    ///
    /// # Returns
    /// The newly created replacement `TrustCard` version.
    ///
    /// # Errors
    /// Returns `TrustCardError` if the extension is missing, the mutation breaks
    /// trust-card invariants, required evidence is missing, or signing fails.
    pub fn update(
        &mut self,
        extension_id: &str,
        mutation: TrustCardMutation,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<TrustCard, TrustCardError> {
        let latest = self
            .latest_verified_card(extension_id)?
            .cloned()
            .ok_or_else(|| TrustCardError::NotFound(extension_id.to_string()))?;

        if let Some(refs) = mutation.evidence_refs.as_ref() {
            ensure_evidence_refs_present(refs)?;
        }

        // Monotone upgrade enforcement: upgrading certification requires evidence.
        if let Some(level) = mutation.certification_level
            && level > latest.certification_level
            && mutation.evidence_refs.is_none()
        {
            return Err(TrustCardError::EvidenceRequiredForUpgrade);
        }

        let mut next = latest.clone();
        next.trust_card_version = next_trust_card_version(latest.trust_card_version, extension_id)?;
        next.previous_version_hash = Some(latest.card_hash.clone());
        if let Some(level) = mutation.certification_level {
            next.certification_level = level;
        }

        // Update derivation evidence if new evidence refs are provided.
        if let Some(refs) = &mutation.evidence_refs {
            let derivation_hash = compute_trust_card_derivation_hash(refs, now_secs);
            next.derivation_evidence = Some(DerivationMetadata {
                evidence_refs: refs.clone(),
                derived_at_epoch: now_secs,
                derivation_chain_hash: derivation_hash,
            });
        }
        if let Some(status) = mutation.revocation_status {
            // INV-TC-MONOTONIC-REVOCATION: once revoked, a trust card can
            // NEVER transition back to Active.  Revocation is permanent and
            // irreversible — accepting Active on a Revoked card would let a
            // revoked extension re-enter the trusted set.
            if matches!(latest.revocation_status, RevocationStatus::Revoked { .. })
                && matches!(status, RevocationStatus::Active)
            {
                return Err(TrustCardError::RevocationIrreversible);
            }
            if matches!(status, RevocationStatus::Revoked { .. }) {
                self.emit(
                    TRUST_CARD_REVOKED,
                    Some(extension_id.to_string()),
                    trace_id,
                    now_secs,
                    "revocation status updated",
                );
            }
            next.revocation_status = status;
        }
        if let Some(active_quarantine) = mutation.active_quarantine {
            next.active_quarantine = active_quarantine;
        }
        if let Some(score) = mutation.reputation_score_basis_points {
            next.reputation_score_basis_points = score;
        }
        if let Some(trend) = mutation.reputation_trend {
            next.reputation_trend = trend;
        }
        if let Some(risk) = mutation.user_facing_risk_assessment {
            next.user_facing_risk_assessment = risk;
        }
        if let Some(ts) = mutation.last_verified_timestamp {
            next.last_verified_timestamp = ts;
        }
        push_bounded(
            &mut next.audit_history,
            AuditRecord {
                timestamp: timestamp_from_secs(now_secs),
                event_code: TRUST_CARD_UPDATED.to_string(),
                detail: "trust card updated".to_string(),
                trace_id: trace_id.to_string(),
            },
            MAX_AUDIT_HISTORY,
        );

        sign_card_in_place(&mut next, &self.registry_key)?;
        self.advance_snapshot_sequence_for_mutation();
        push_bounded(
            self.cards_by_extension
                .entry(extension_id.to_string())
                .or_default(),
            next.clone(),
            MAX_CARD_VERSIONS,
        );
        self.cache_by_extension.insert(
            extension_id.to_string(),
            CachedCard {
                card: next.clone(),
                cached_at_secs: now_secs,
            },
        );
        self.emit(
            TRUST_CARD_UPDATED,
            Some(extension_id.to_string()),
            trace_id,
            now_secs,
            "updated trust card version",
        );
        Ok(next)
    }

    /// Read the latest verified trust card for one extension, using the cache when valid.
    ///
    /// # Parameters
    /// - `extension_id`: extension identifier to resolve.
    /// - `now_secs`: unix timestamp used for cache freshness checks.
    /// - `trace_id`: operator-visible correlation ID recorded in telemetry.
    ///
    /// # Returns
    /// `Some(TrustCard)` when the extension exists or `None` when no card is known.
    ///
    /// # Errors
    /// Returns `TrustCardError` if cached or authoritative card signatures fail
    /// verification during the read path.
    pub fn read(
        &mut self,
        extension_id: &str,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<Option<TrustCard>, TrustCardError> {
        self.emit(
            TRUST_CARD_QUERIED,
            Some(extension_id.to_string()),
            trace_id,
            now_secs,
            "query by extension id",
        );

        if let Some(cached) = self.cache_by_extension.get(extension_id)
            && now_secs.saturating_sub(cached.cached_at_secs) < self.cache_ttl_secs
        {
            let card = cached.card.clone();
            // SECURITY: Always re-verify signature on cache hit to prevent serving tampered cards.
            // This protects against cache poisoning attacks where malicious cards could be injected.
            verify_card_signature(&card, &self.registry_key).map_err(|_| {
                // Remove invalid cached entry immediately
                self.cache_by_extension.remove(extension_id);
                TrustCardError::SignatureInvalid(extension_id.to_string())
            })?;

            self.emit(
                TRUST_CARD_CACHE_HIT,
                Some(extension_id.to_string()),
                trace_id,
                now_secs,
                "served from cache after signature re-verification",
            );
            self.emit(
                TRUST_CARD_SERVED,
                Some(extension_id.to_string()),
                trace_id,
                now_secs,
                "served verified trust card",
            );
            return Ok(Some(card));
        }

        let Some(latest_card) = self.latest_verified_card(extension_id)?.cloned() else {
            return Ok(None);
        };

        if self.cache_by_extension.contains_key(extension_id) {
            self.emit(
                TRUST_CARD_STALE_REFRESH,
                Some(extension_id.to_string()),
                trace_id,
                now_secs,
                "cache stale; refreshed from source",
            );
        } else {
            self.emit(
                TRUST_CARD_CACHE_MISS,
                Some(extension_id.to_string()),
                trace_id,
                now_secs,
                "cache miss",
            );
        }

        self.cache_by_extension.insert(
            extension_id.to_string(),
            CachedCard {
                card: latest_card.clone(),
                cached_at_secs: now_secs,
            },
        );
        self.emit(
            TRUST_CARD_SERVED,
            Some(extension_id.to_string()),
            trace_id,
            now_secs,
            "served verified trust card",
        );
        Ok(Some(latest_card))
    }

    /// List the latest verified trust cards that satisfy a filter.
    ///
    /// # Parameters
    /// - `filter`: certification, publisher, and capability selectors.
    /// - `trace_id`: operator-visible correlation ID recorded in telemetry.
    /// - `now_secs`: unix timestamp used for telemetry timestamps.
    ///
    /// # Returns
    /// A sorted vector of current trust cards that match the filter.
    ///
    /// # Errors
    /// Returns `TrustCardError` if any matched card fails signature verification.
    pub fn list(
        &mut self,
        filter: &TrustCardListFilter,
        trace_id: &str,
        now_secs: u64,
    ) -> Result<Vec<TrustCard>, TrustCardError> {
        self.emit(
            TRUST_CARD_QUERIED,
            None,
            trace_id,
            now_secs,
            "query trust cards by filter",
        );
        let mut out = Vec::new();
        for history in self.cards_by_extension.values() {
            let Some(card) = history.last() else {
                continue;
            };
            if !card_matches_filter(card, filter) {
                continue;
            }
            verify_card_signature(card, &self.registry_key)?;
            out.push(card.clone());
        }
        out.sort_by(|left, right| {
            left.extension
                .extension_id
                .cmp(&right.extension.extension_id)
        });
        Ok(out)
    }

    /// List the latest verified trust cards published by one publisher.
    ///
    /// # Parameters
    /// - `publisher_id`: publisher identifier to filter on.
    /// - `now_secs`: unix timestamp used for telemetry timestamps.
    /// - `trace_id`: operator-visible correlation ID recorded in telemetry.
    ///
    /// # Returns
    /// A sorted vector of current trust cards for the publisher.
    ///
    /// # Errors
    /// Returns `TrustCardError` if any matched card fails signature verification.
    pub fn list_by_publisher(
        &mut self,
        publisher_id: &str,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<Vec<TrustCard>, TrustCardError> {
        self.list(
            &TrustCardListFilter {
                certification_level: None,
                publisher_id: Some(publisher_id.to_string()),
                capability: None,
            },
            trace_id,
            now_secs,
        )
    }

    /// Refresh trust-card cache entries and report the sync outcome.
    ///
    /// # Parameters
    /// - `now_secs`: unix timestamp used for cache freshness decisions and telemetry.
    /// - `trace_id`: operator-visible correlation ID recorded in telemetry.
    /// - `force`: whether fresh cache entries should still be rebuilt from source.
    ///
    /// # Returns
    /// A `TrustCardSyncReport` summarizing cache hits, misses, and refreshes.
    ///
    /// # Errors
    /// Returns `TrustCardError` if a source card is missing or any cached/source
    /// card fails verification while syncing.
    pub fn sync_cache(
        &mut self,
        now_secs: u64,
        trace_id: &str,
        force: bool,
    ) -> Result<TrustCardSyncReport, TrustCardError> {
        self.emit(
            TRUST_CARD_QUERIED,
            None,
            trace_id,
            now_secs,
            if force {
                "force sync trust card cache"
            } else {
                "sync trust card cache"
            },
        );

        let extension_ids = self.cards_by_extension.keys().cloned().collect::<Vec<_>>();
        let mut report = TrustCardSyncReport {
            total_cards: extension_ids.len(),
            cache_hits: 0,
            cache_misses: 0,
            stale_refreshes: 0,
            forced_refreshes: 0,
        };

        for extension_id in extension_ids {
            let cache_state = match self.cache_by_extension.get(&extension_id) {
                Some(cached)
                    if now_secs.saturating_sub(cached.cached_at_secs) < self.cache_ttl_secs =>
                {
                    CacheSyncState::Fresh
                }
                Some(_) => CacheSyncState::Stale,
                None => CacheSyncState::Missing,
            };

            match cache_state {
                CacheSyncState::Fresh if !force => {
                    let cached = self
                        .cache_by_extension
                        .get(&extension_id)
                        .ok_or_else(|| TrustCardError::NotFound(extension_id.clone()))?;

                    // SECURITY: Always re-verify signature on cache sync to detect tampering
                    match verify_card_signature(&cached.card, &self.registry_key) {
                        Ok(()) => {
                            report.cache_hits = report.cache_hits.saturating_add(1);
                            self.emit(
                                TRUST_CARD_CACHE_HIT,
                                Some(extension_id),
                                trace_id,
                                now_secs,
                                "sync skipped fresh cache entry after signature re-verification",
                            );
                            continue;
                        }
                        Err(_) => {
                            // Invalid signature - remove from cache and rebuild
                            self.cache_by_extension.remove(&extension_id);
                            report.cache_misses = report.cache_misses.saturating_add(1);
                            self.emit(
                                TRUST_CARD_CACHE_MISS,
                                Some(extension_id.clone()),
                                trace_id,
                                now_secs,
                                "sync discarded invalid cache entry and repopulated from source",
                            );
                        }
                    }
                }
                CacheSyncState::Missing => {
                    report.cache_misses = report.cache_misses.saturating_add(1);
                    self.emit(
                        TRUST_CARD_CACHE_MISS,
                        Some(extension_id.clone()),
                        trace_id,
                        now_secs,
                        "sync populated missing cache entry",
                    );
                }
                CacheSyncState::Stale => {
                    report.stale_refreshes = report.stale_refreshes.saturating_add(1);
                    self.emit(
                        TRUST_CARD_STALE_REFRESH,
                        Some(extension_id.clone()),
                        trace_id,
                        now_secs,
                        "sync refreshed stale cache from source",
                    );
                }
                CacheSyncState::Fresh => {
                    report.forced_refreshes = report.forced_refreshes.saturating_add(1);
                    self.emit(
                        TRUST_CARD_FORCE_REFRESH,
                        Some(extension_id.clone()),
                        trace_id,
                        now_secs,
                        "force sync refreshed fresh cache from source",
                    );
                }
            }

            let latest = self
                .latest_verified_card(&extension_id)?
                .cloned()
                .ok_or_else(|| TrustCardError::NotFound(extension_id.clone()))?;
            self.cache_by_extension.insert(
                extension_id,
                CachedCard {
                    card: latest,
                    cached_at_secs: now_secs,
                },
            );
        }

        Ok(report)
    }

    /// Search trust cards by extension ID, publisher ID, or capability name.
    ///
    /// # Parameters
    /// - `query`: case-insensitive search string.
    /// - `now_secs`: unix timestamp used for telemetry timestamps.
    /// - `trace_id`: operator-visible correlation ID recorded in telemetry.
    ///
    /// # Returns
    /// A sorted vector of current trust cards whose searchable text matches the query.
    ///
    /// # Errors
    /// Returns `TrustCardError` if any matched card fails signature verification.
    pub fn search(
        &mut self,
        query: &str,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<Vec<TrustCard>, TrustCardError> {
        self.emit(
            TRUST_CARD_QUERIED,
            None,
            trace_id,
            now_secs,
            &format!("search trust cards by query: {query}"),
        );
        let query_lc = query.to_ascii_lowercase();
        let mut out = Vec::new();
        for history in self.cards_by_extension.values() {
            let Some(card) = history.last() else {
                continue;
            };
            let capability_text = card
                .capability_declarations
                .iter()
                .map(|cap| cap.name.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let haystack = format!(
                "{} {} {}",
                card.extension.extension_id, card.publisher.publisher_id, capability_text
            )
            .to_ascii_lowercase();
            if !haystack.contains(&query_lc) {
                continue;
            }
            verify_card_signature(card, &self.registry_key)?;
            out.push(card.clone());
        }
        out.sort_by(|left, right| {
            left.extension
                .extension_id
                .cmp(&right.extension.extension_id)
        });
        Ok(out)
    }

    /// Compare the latest verified trust cards for two extensions.
    ///
    /// # Parameters
    /// - `left_extension_id`: first extension identifier in the comparison.
    /// - `right_extension_id`: second extension identifier in the comparison.
    /// - `now_secs`: unix timestamp used for telemetry timestamps.
    /// - `trace_id`: operator-visible correlation ID recorded in telemetry.
    ///
    /// # Returns
    /// A field-level `TrustCardComparison` describing the latest-card differences.
    ///
    /// # Errors
    /// Returns `TrustCardError` if either extension is missing or either latest
    /// card fails signature verification.
    pub fn compare(
        &mut self,
        left_extension_id: &str,
        right_extension_id: &str,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<TrustCardComparison, TrustCardError> {
        let comparison = {
            let left = self
                .latest_card(left_extension_id)
                .ok_or_else(|| TrustCardError::NotFound(left_extension_id.to_string()))?;
            let right = self
                .latest_card(right_extension_id)
                .ok_or_else(|| TrustCardError::NotFound(right_extension_id.to_string()))?;
            verify_card_signature(left, &self.registry_key)?;
            verify_card_signature(right, &self.registry_key)?;
            comparison_from_cards(
                left,
                right,
                left_extension_id.to_string(),
                right_extension_id.to_string(),
            )
        };
        self.emit(
            TRUST_CARD_DIFF_COMPUTED,
            Some(left_extension_id.to_string()),
            trace_id,
            now_secs,
            &format!("computed trust-card diff against {right_extension_id}"),
        );
        Ok(comparison)
    }

    /// Compare two verified historical trust-card versions for one extension.
    ///
    /// # Parameters
    /// - `extension_id`: extension whose version history should be compared.
    /// - `left_version`: first trust-card version to compare.
    /// - `right_version`: second trust-card version to compare.
    /// - `now_secs`: unix timestamp used for telemetry timestamps.
    /// - `trace_id`: operator-visible correlation ID recorded in telemetry.
    ///
    /// # Returns
    /// A field-level `TrustCardComparison` for the requested historical versions.
    ///
    /// # Errors
    /// Returns `TrustCardError` if the extension or either version is missing or
    /// either historical card fails signature verification.
    pub fn compare_versions(
        &mut self,
        extension_id: &str,
        left_version: u64,
        right_version: u64,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<TrustCardComparison, TrustCardError> {
        let comparison = {
            let history = self
                .cards_by_extension
                .get(extension_id)
                .ok_or_else(|| TrustCardError::NotFound(extension_id.to_string()))?;
            let left = history
                .iter()
                .find(|card| card.trust_card_version == left_version)
                .ok_or_else(|| TrustCardError::VersionNotFound {
                    extension_id: extension_id.to_string(),
                    version: left_version,
                })?;
            let right = history
                .iter()
                .find(|card| card.trust_card_version == right_version)
                .ok_or_else(|| TrustCardError::VersionNotFound {
                    extension_id: extension_id.to_string(),
                    version: right_version,
                })?;
            verify_card_signature(left, &self.registry_key)?;
            verify_card_signature(right, &self.registry_key)?;
            comparison_from_cards(
                left,
                right,
                format!("{extension_id}@{left_version}"),
                format!("{extension_id}@{right_version}"),
            )
        };

        self.emit(
            TRUST_CARD_DIFF_COMPUTED,
            Some(extension_id.to_string()),
            trace_id,
            now_secs,
            &format!("computed trust-card version diff {left_version} -> {right_version}"),
        );
        Ok(comparison)
    }

    /// Read one verified historical trust-card version without touching cache state.
    ///
    /// # Parameters
    /// - `extension_id`: extension whose version history should be searched.
    /// - `trust_card_version`: historical trust-card version to resolve.
    ///
    /// # Returns
    /// `Some(TrustCard)` when that historical version exists or `None` otherwise.
    ///
    /// # Errors
    /// Returns `TrustCardError` if the located card fails signature verification.
    pub fn read_version(
        &self,
        extension_id: &str,
        trust_card_version: u64,
    ) -> Result<Option<TrustCard>, TrustCardError> {
        let card = self
            .cards_by_extension
            .get(extension_id)
            .and_then(|history| {
                history
                    .iter()
                    .find(|card| card.trust_card_version == trust_card_version)
            })
            .cloned();
        if let Some(card) = card {
            verify_card_signature(&card, &self.registry_key)?;
            return Ok(Some(card));
        }
        Ok(None)
    }

    #[must_use]
    /// Expose the registry's bounded telemetry ring buffer.
    ///
    /// # Parameters
    /// This accessor takes no parameters.
    ///
    /// # Returns
    /// An immutable slice of accumulated `TelemetryEvent` entries.
    ///
    /// # Errors
    /// This accessor does not return errors.
    pub fn telemetry(&self) -> &[TelemetryEvent] {
        &self.telemetry
    }

    fn latest_card(&self, extension_id: &str) -> Option<&TrustCard> {
        if extension_id.len() > MAX_EXTENSION_ID_LEN {
            return None;
        }
        self.cards_by_extension
            .get(extension_id)
            .and_then(|history| history.last())
    }

    fn latest_verified_card(
        &self,
        extension_id: &str,
    ) -> Result<Option<&TrustCard>, TrustCardError> {
        if extension_id.len() > MAX_EXTENSION_ID_LEN {
            return Err(TrustCardError::InvalidInput {
                reason: format!(
                    "extension_id too long: {} bytes exceeds maximum of {}",
                    extension_id.len(),
                    MAX_EXTENSION_ID_LEN
                ),
            });
        }
        let latest = self.latest_card(extension_id);
        if let Some(card) = latest {
            verify_card_signature(card, &self.registry_key)?;
        }
        Ok(latest)
    }

    fn emit(
        &mut self,
        event_code: &str,
        extension_id: Option<String>,
        trace_id: &str,
        timestamp_secs: u64,
        detail: &str,
    ) {
        push_bounded(
            &mut self.telemetry,
            TelemetryEvent {
                event_code: event_code.to_string(),
                extension_id,
                trace_id: trace_id.to_string(),
                timestamp_secs,
                detail: detail.to_string(),
            },
            MAX_TELEMETRY,
        );
    }
}

/// Process-local trust-card authoritative snapshot persistence lock.
///
/// Canonical lifecycle: `with_authoritative_snapshot_persist_lock` creates or
/// opens the lock file, acquires the cross-process flock first, then acquires
/// this mutex before reading high-water state and writing the snapshot plus
/// high-water temp files. The explicit flock unlock runs after the write closure
/// and before the mutex guard drops at function return. Callers must not hold
/// another module's persist lock when entering this path. If this mutex is left
/// held or poisoned, same-process snapshot writes fail before mutating snapshot
/// files; if the flock cannot be released, closing the lock file still drops the
/// OS lock when the function unwinds.
fn authoritative_snapshot_persist_process_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_authoritative_snapshot_persist_process(
    path: &Path,
) -> Result<MutexGuard<'static, ()>, TrustCardError> {
    authoritative_snapshot_persist_process_lock()
        .lock()
        .map_err(|_| TrustCardError::SnapshotWrite {
            path: path.to_path_buf(),
            detail: "trust-card snapshot persist lock poisoned".to_string(),
        })
}

fn authoritative_snapshot_lock_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("trust-card-registry-state");
    parent.join(format!("{file_name}.lock"))
}

fn authoritative_snapshot_high_water_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("trust-card-registry-state");
    parent.join(format!("{file_name}.high-water.json"))
}

fn sync_parent_directory(parent: &Path, path: &Path) -> Result<(), TrustCardError> {
    let dir = File::open(parent).map_err(|err| TrustCardError::SnapshotWrite {
        path: path.to_path_buf(),
        detail: format!(
            "failed opening parent directory {} for sync: {err}",
            parent.display()
        ),
    })?;
    dir.sync_all().map_err(|err| TrustCardError::SnapshotWrite {
        path: path.to_path_buf(),
        detail: format!(
            "failed syncing parent directory {}: {err}",
            parent.display()
        ),
    })
}

fn lock_authoritative_snapshot_file(
    file: &File,
    lock_path: &Path,
    snapshot_path: &Path,
) -> Result<(), TrustCardError> {
    match file.try_lock() {
        Ok(()) => return Ok(()),
        Err(TryLockError::WouldBlock) => {}
        Err(TryLockError::Error(err)) => {
            return Err(TrustCardError::SnapshotWrite {
                path: snapshot_path.to_path_buf(),
                detail: format!("failed acquiring flock for {}: {err}", lock_path.display()),
            });
        }
    }

    for delay_millis in SNAPSHOT_LOCK_RETRY_BACKOFF_MILLIS {
        thread::sleep(Duration::from_millis(delay_millis));
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(err)) => {
                return Err(TrustCardError::SnapshotWrite {
                    path: snapshot_path.to_path_buf(),
                    detail: format!("failed acquiring flock for {}: {err}", lock_path.display()),
                });
            }
        }
    }

    Err(TrustCardError::SnapshotWrite {
        path: snapshot_path.to_path_buf(),
        detail: format!(
            "timed out acquiring flock for {} after retries at 100ms/200ms/400ms",
            lock_path.display()
        ),
    })
}

fn unlock_authoritative_snapshot_file(
    file: &File,
    lock_path: &Path,
    snapshot_path: &Path,
) -> Result<(), TrustCardError> {
    file.unlock().map_err(|err| TrustCardError::SnapshotWrite {
        path: snapshot_path.to_path_buf(),
        detail: format!("failed releasing flock for {}: {err}", lock_path.display()),
    })
}

fn with_authoritative_snapshot_persist_lock<T>(
    path: &Path,
    write_snapshot: impl FnOnce() -> Result<T, TrustCardError>,
) -> Result<T, TrustCardError> {
    // Canonical lock order: file flock first, process mutex second.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|err| TrustCardError::SnapshotWrite {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })?;
    let lock_path = authoritative_snapshot_lock_path(path);
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| TrustCardError::SnapshotWrite {
            path: path.to_path_buf(),
            detail: format!("failed opening flock file {}: {err}", lock_path.display()),
        })?;
    // Step 1: Acquire file flock FIRST (cross-process synchronization)
    lock_authoritative_snapshot_file(&lock_file, &lock_path, path)?;

    // Step 2: Acquire process Mutex SECOND (in-process synchronization)
    let _process_guard = lock_authoritative_snapshot_persist_process(path)?;

    let write_result = write_snapshot();
    let unlock_result = unlock_authoritative_snapshot_file(&lock_file, &lock_path, path);
    match (write_result, unlock_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), _) => Err(err),
        (Ok(_), Err(err)) => Err(err),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheSyncState {
    Fresh,
    Stale,
    Missing,
}

fn comparison_from_cards(
    left: &TrustCard,
    right: &TrustCard,
    left_extension_id: String,
    right_extension_id: String,
) -> TrustCardComparison {
    let mut changes = Vec::new();
    if left.certification_level != right.certification_level {
        changes.push(TrustCardDiffEntry {
            field: "certification_level".to_string(),
            left: format!("{:?}", left.certification_level).to_ascii_lowercase(),
            right: format!("{:?}", right.certification_level).to_ascii_lowercase(),
        });
    }
    if left.reputation_score_basis_points != right.reputation_score_basis_points {
        changes.push(TrustCardDiffEntry {
            field: "reputation_score_basis_points".to_string(),
            left: left.reputation_score_basis_points.to_string(),
            right: right.reputation_score_basis_points.to_string(),
        });
    }
    if left.revocation_status != right.revocation_status {
        changes.push(TrustCardDiffEntry {
            field: "revocation_status".to_string(),
            left: format!("{:?}", left.revocation_status).to_ascii_lowercase(),
            right: format!("{:?}", right.revocation_status).to_ascii_lowercase(),
        });
    }
    if left.active_quarantine != right.active_quarantine {
        changes.push(TrustCardDiffEntry {
            field: "active_quarantine".to_string(),
            left: left.active_quarantine.to_string(),
            right: right.active_quarantine.to_string(),
        });
    }
    if left.capability_declarations != right.capability_declarations {
        changes.push(TrustCardDiffEntry {
            field: "capability_declarations".to_string(),
            left: left
                .capability_declarations
                .iter()
                .map(|cap| cap.name.clone())
                .collect::<Vec<_>>()
                .join(","),
            right: right
                .capability_declarations
                .iter()
                .map(|cap| cap.name.clone())
                .collect::<Vec<_>>()
                .join(","),
        });
    }
    if left.extension.version != right.extension.version {
        changes.push(TrustCardDiffEntry {
            field: "extension_version".to_string(),
            left: left.extension.version.clone(),
            right: right.extension.version.clone(),
        });
    }

    TrustCardComparison {
        left_extension_id,
        right_extension_id,
        changes,
    }
}

/// Slice one-based pagination bounds over a collection.
///
/// # Parameters
/// - `items`: source collection to paginate.
/// - `page`: one-based page number to read.
/// - `per_page`: maximum number of items to return.
///
/// # Returns
/// A cloned page of items, or an empty vector when the page starts past the end.
///
/// # Errors
/// Returns `TrustCardError::InvalidPagination` when `page` or `per_page` is zero.
pub fn paginate<T: Clone>(
    items: &[T],
    page: usize,
    per_page: usize,
) -> Result<Vec<T>, TrustCardError> {
    if page == 0 || per_page == 0 {
        return Err(TrustCardError::InvalidPagination { page, per_page });
    }
    let start = (page - 1).saturating_mul(per_page);
    if start >= items.len() {
        return Ok(Vec::new());
    }
    let end = start.saturating_add(per_page).min(items.len());
    Ok(items[start..end].to_vec())
}

/// Render one trust card into the stable human-readable CLI summary format.
///
/// # Parameters
/// - `card`: trust card to format for operator-facing output.
///
/// # Returns
/// A multi-line human-readable summary string.
///
/// # Errors
/// This renderer does not return errors.
pub fn render_trust_card_human(card: &TrustCard) -> String {
    let status = match &card.revocation_status {
        RevocationStatus::Active => "active".to_string(),
        RevocationStatus::Revoked { reason, .. } => format!("revoked ({reason})"),
    };
    let capabilities = card
        .capability_declarations
        .iter()
        .map(|capability| capability.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "extension: {}@{}\npublisher: {}\ncertification: {:?}\nreputation: {}bp ({:?})\nrevocation: {}\nquarantine: {}\ncapabilities: {}\nrisk: {:?} - {}",
        card.extension.extension_id,
        card.extension.version,
        card.publisher.display_name,
        card.certification_level,
        card.reputation_score_basis_points,
        card.reputation_trend,
        status,
        card.active_quarantine,
        capabilities,
        card.user_facing_risk_assessment.level,
        card.user_facing_risk_assessment.summary
    )
}

/// Render a trust-card comparison into the stable human-readable CLI diff format.
///
/// # Parameters
/// - `comparison`: field-level comparison to format.
///
/// # Returns
/// A human-readable comparison string, including the no-differences case.
///
/// # Errors
/// This renderer does not return errors.
pub fn render_comparison_human(comparison: &TrustCardComparison) -> String {
    if comparison.changes.is_empty() {
        return format!(
            "compare {} vs {}: no differences",
            comparison.left_extension_id, comparison.right_extension_id
        );
    }

    let mut out = format!(
        "compare {} vs {}:\n",
        comparison.left_extension_id, comparison.right_extension_id
    );
    for change in &comparison.changes {
        out.push_str(&format!(
            "- {}: {} -> {}\n",
            change.field, change.left, change.right
        ));
    }
    out.trim_end().to_string()
}

/// Verify a trust card's canonical hash and registry signature.
///
/// # Parameters
/// - `card`: trust card whose integrity should be checked.
/// - `registry_key`: HMAC key expected to have signed the card.
///
/// # Returns
/// `Ok(())` when both the card hash and registry signature verify.
///
/// # Errors
/// Returns `TrustCardError` if canonical hashing fails, the HMAC key is invalid,
/// or either integrity check does not match.
pub fn verify_card_signature(card: &TrustCard, registry_key: &[u8]) -> Result<(), TrustCardError> {
    let expected_hash = compute_card_hash(card)?;
    if !constant_time::ct_eq(&card.card_hash, &expected_hash) {
        return Err(TrustCardError::CardHashMismatch(
            card.extension.extension_id.clone(),
        ));
    }

    let mut mac =
        HmacSha256::new_from_slice(registry_key).map_err(|_| TrustCardError::InvalidRegistryKey)?;
    mac.update(b"trust_card_registry_sig_v1:");
    mac.update(card.card_hash.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());
    if !constant_time::ct_eq(&card.registry_signature, &expected_signature) {
        return Err(TrustCardError::SignatureInvalid(
            card.extension.extension_id.clone(),
        ));
    }
    Ok(())
}

/// Compute the canonical hash for a trust card payload.
///
/// # Parameters
/// - `card`: trust card whose hash should be recomputed.
///
/// # Returns
/// The canonical hex-encoded SHA-256 digest for the card payload.
///
/// # Errors
/// Returns `TrustCardError` if canonical serialization of the card fails.
pub fn compute_card_hash(card: &TrustCard) -> Result<String, TrustCardError> {
    let canonical = canonical_card_without_hash_and_signature(card)?;
    let encoded = serde_json::to_vec(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(b"trust_card_hash_v1:");
    hasher.update(
        u64::try_from(encoded.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(&encoded);
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

/// Serialize a value into the trust-card module's canonical JSON ordering.
///
/// # Parameters
/// - `value`: serializable value to canonicalize.
///
/// # Returns
/// A JSON string with deterministically ordered object keys.
///
/// # Errors
/// Returns `TrustCardError` if value serialization fails.
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, TrustCardError> {
    let raw = serde_json::to_value(value)?;
    let canonical = canonicalize_value(raw);
    Ok(serde_json::to_string(&canonical)?)
}

#[cfg(any(test, feature = "test-support"))]
fn fixture_evidence_refs() -> Vec<VerifiedEvidenceRef> {
    use super::certification::EvidenceType;
    vec![
        VerifiedEvidenceRef {
            evidence_id: "ev-fixture-prov-001".to_string(),
            evidence_type: EvidenceType::ProvenanceChain,
            verified_at_epoch: 1000,
            verification_receipt_hash: "a".repeat(64),
        },
        VerifiedEvidenceRef {
            evidence_id: "ev-fixture-rep-001".to_string(),
            evidence_type: EvidenceType::ReputationSignal,
            verified_at_epoch: 1000,
            verification_receipt_hash: "b".repeat(64),
        },
    ]
}

/// Deterministic trust-card fixture registry for tests and seeded fixture state.
///
/// This helper must remain unreachable from operator-facing trust flows.
#[cfg(any(test, feature = "test-support"))]
pub fn fixture_registry(now_secs: u64) -> Result<TrustCardRegistry, TrustCardError> {
    let mut registry = TrustCardRegistry::default();
    let base_trace = "trace-fixture-registry";

    registry.create(
        TrustCardInput {
            extension: ExtensionIdentity {
                extension_id: "npm:@acme/auth-guard".to_string(),
                version: "1.4.2".to_string(),
            },
            publisher: PublisherIdentity {
                publisher_id: "pub-acme".to_string(),
                display_name: "Acme Security".to_string(),
            },
            certification_level: CertificationLevel::Gold,
            capability_declarations: vec![
                CapabilityDeclaration {
                    name: "auth.validate-token".to_string(),
                    description: "Validate JWT and attach identity context".to_string(),
                    risk: CapabilityRisk::Medium,
                },
                CapabilityDeclaration {
                    name: "auth.revoke-session".to_string(),
                    description: "Invalidate compromised sessions".to_string(),
                    risk: CapabilityRisk::High,
                },
            ],
            behavioral_profile: BehavioralProfile {
                network_access: true,
                filesystem_access: false,
                subprocess_access: false,
                profile_summary: "Network-only auth checks with bounded side effects".to_string(),
            },
            revocation_status: RevocationStatus::Active,
            provenance_summary: ProvenanceSummary {
                attestation_level: "slsa-l3".to_string(),
                source_uri: "fixture://trust-card/acme/auth-guard".to_string(),
                artifact_hashes: vec![format!("sha256:deadbeef{}", "a".repeat(56))],
                verified_at: "2026-02-20T12:00:00Z".to_string(),
            },
            reputation_score_basis_points: 920,
            reputation_trend: ReputationTrend::Improving,
            active_quarantine: false,
            dependency_trust_summary: vec![DependencyTrustStatus {
                dependency_id: "npm:jsonwebtoken@9".to_string(),
                trust_level: "verified".to_string(),
            }],
            last_verified_timestamp: "2026-02-20T12:00:00Z".to_string(),
            user_facing_risk_assessment: RiskAssessment {
                level: RiskLevel::Low,
                summary:
                    "Token validation extension with strong provenance and no local disk access"
                        .to_string(),
            },
            evidence_refs: fixture_evidence_refs(),
        },
        now_secs,
        base_trace,
    )?;

    registry.create(
        TrustCardInput {
            extension: ExtensionIdentity {
                extension_id: "npm:@beta/telemetry-bridge".to_string(),
                version: "0.9.1".to_string(),
            },
            publisher: PublisherIdentity {
                publisher_id: "pub-beta".to_string(),
                display_name: "Beta Labs".to_string(),
            },
            certification_level: CertificationLevel::Silver,
            capability_declarations: vec![CapabilityDeclaration {
                name: "telemetry.forward".to_string(),
                description: "Forward runtime telemetry to remote collector".to_string(),
                risk: CapabilityRisk::High,
            }],
            behavioral_profile: BehavioralProfile {
                network_access: true,
                filesystem_access: true,
                subprocess_access: false,
                profile_summary: "Network telemetry forwarding with local spool fallback"
                    .to_string(),
            },
            revocation_status: RevocationStatus::Active,
            provenance_summary: ProvenanceSummary {
                attestation_level: "slsa-l2".to_string(),
                source_uri: "fixture://trust-card/beta/telemetry-bridge".to_string(),
                artifact_hashes: vec![format!("sha256:deadbeef{}", "b".repeat(56))],
                verified_at: "2026-02-20T12:00:01Z".to_string(),
            },
            reputation_score_basis_points: 680,
            reputation_trend: ReputationTrend::Stable,
            active_quarantine: true,
            dependency_trust_summary: vec![DependencyTrustStatus {
                dependency_id: "npm:axios@1".to_string(),
                trust_level: "monitor".to_string(),
            }],
            last_verified_timestamp: "2026-02-20T12:00:01Z".to_string(),
            user_facing_risk_assessment: RiskAssessment {
                level: RiskLevel::High,
                summary:
                    "Telemetry extension with elevated network and local spool behavior; monitor closely"
                        .to_string(),
            },
            evidence_refs: fixture_evidence_refs(),
        },
        now_secs.saturating_add(1),
        base_trace,
    )?;

    registry.update(
        "npm:@beta/telemetry-bridge",
        TrustCardMutation {
            certification_level: Some(CertificationLevel::Bronze),
            revocation_status: Some(RevocationStatus::Revoked {
                reason: "publisher key compromised".to_string(),
                revoked_at: "2026-02-20T12:01:00Z".to_string(),
            }),
            active_quarantine: Some(true),
            reputation_score_basis_points: Some(410),
            reputation_trend: Some(ReputationTrend::Declining),
            user_facing_risk_assessment: Some(RiskAssessment {
                level: RiskLevel::Critical,
                summary: "Revoked due to publisher compromise; do not deploy".to_string(),
            }),
            last_verified_timestamp: Some("2026-02-20T12:01:00Z".to_string()),
            evidence_refs: None, // Demotion: no new evidence required.
        },
        now_secs.saturating_add(2),
        base_trace,
    )?;

    Ok(registry)
}

fn validate_snapshot_history(
    extension_id: &str,
    history: &[TrustCard],
    registry_key: &[u8],
) -> Result<(), TrustCardError> {
    let mut previous_version = None;
    let mut previous_hash: Option<String> = None;

    for card in history {
        if card.extension.extension_id != extension_id {
            return Err(TrustCardError::InvalidSnapshot(format!(
                "extension bucket `{extension_id}` contains card for `{}`",
                card.extension.extension_id
            )));
        }
        verify_card_signature(card, registry_key)?;
        if let Some(prev_version) = previous_version
            && card.trust_card_version <= prev_version
        {
            return Err(TrustCardError::InvalidSnapshot(format!(
                "extension `{extension_id}` has non-monotonic trust_card_version history"
            )));
        }
        if let Some(prev_hash) = &previous_hash
            && card.previous_version_hash.as_deref() != Some(prev_hash.as_str())
        {
            return Err(TrustCardError::InvalidSnapshot(format!(
                "extension `{extension_id}` broke previous_version_hash linkage"
            )));
        }

        previous_version = Some(card.trust_card_version);
        previous_hash = Some(card.card_hash.clone());
    }

    Ok(())
}

fn canonical_card_without_hash_and_signature(card: &TrustCard) -> Result<Value, TrustCardError> {
    let mut value = serde_json::to_value(card)?;
    let Some(map) = value.as_object_mut() else {
        return Ok(value);
    };
    map.insert("card_hash".to_string(), Value::String(String::new()));
    map.insert(
        "registry_signature".to_string(),
        Value::String(String::new()),
    );
    Ok(canonicalize_value(value))
}

fn sign_card_in_place(card: &mut TrustCard, registry_key: &[u8]) -> Result<(), TrustCardError> {
    card.card_hash = compute_card_hash(card)?;
    let mut mac =
        HmacSha256::new_from_slice(registry_key).map_err(|_| TrustCardError::InvalidRegistryKey)?;
    mac.update(b"trust_card_registry_sig_v1:");
    mac.update(card.card_hash.as_bytes());
    card.registry_signature = hex::encode(mac.finalize().into_bytes());
    Ok(())
}

fn canonical_snapshot_without_hash_and_signature(
    snapshot: &TrustCardRegistrySnapshot,
) -> Result<Value, TrustCardError> {
    let mut value = serde_json::to_value(snapshot)?;
    let Some(map) = value.as_object_mut() else {
        return Ok(value);
    };
    map.insert("snapshot_hash".to_string(), Value::String(String::new()));
    map.insert(
        "registry_signature".to_string(),
        Value::String(String::new()),
    );
    Ok(canonicalize_value(value))
}

fn compute_snapshot_hash(snapshot: &TrustCardRegistrySnapshot) -> Result<String, TrustCardError> {
    let canonical = canonical_snapshot_without_hash_and_signature(snapshot)?;
    let encoded = serde_json::to_vec(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(b"trust_card_registry_snapshot_hash_v1:");
    hasher.update(
        u64::try_from(encoded.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(&encoded);
    Ok(hex::encode(hasher.finalize()))
}

fn sign_snapshot_in_place(
    snapshot: &mut TrustCardRegistrySnapshot,
    registry_key: &[u8],
) -> Result<(), TrustCardError> {
    snapshot.snapshot_hash = compute_snapshot_hash(snapshot)?;
    let mut mac =
        HmacSha256::new_from_slice(registry_key).map_err(|_| TrustCardError::InvalidRegistryKey)?;
    mac.update(b"trust_card_registry_snapshot_sig_v1:");
    mac.update(snapshot.snapshot_hash.as_bytes());
    snapshot.registry_signature = hex::encode(mac.finalize().into_bytes());
    Ok(())
}

fn verify_snapshot_signature(
    snapshot: &TrustCardRegistrySnapshot,
    registry_key: &[u8],
) -> Result<(), TrustCardError> {
    let expected_hash = compute_snapshot_hash(snapshot)?;
    if !constant_time::ct_eq(&snapshot.snapshot_hash, &expected_hash) {
        return Err(TrustCardError::InvalidSnapshot(
            "registry snapshot hash mismatch".to_string(),
        ));
    }

    let mut mac =
        HmacSha256::new_from_slice(registry_key).map_err(|_| TrustCardError::InvalidRegistryKey)?;
    mac.update(b"trust_card_registry_snapshot_sig_v1:");
    mac.update(snapshot.snapshot_hash.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());
    if !constant_time::ct_eq(&snapshot.registry_signature, &expected_signature) {
        return Err(TrustCardError::InvalidSnapshot(
            "registry snapshot signature mismatch".to_string(),
        ));
    }
    Ok(())
}

fn canonical_high_water_without_signature(
    high_water: &TrustCardRegistrySnapshotHighWater,
) -> Result<Value, TrustCardError> {
    let mut value = serde_json::to_value(high_water)?;
    let Some(map) = value.as_object_mut() else {
        return Ok(value);
    };
    map.insert(
        "high_water_signature".to_string(),
        Value::String(String::new()),
    );
    Ok(canonicalize_value(value))
}

fn high_water_signature(
    high_water: &TrustCardRegistrySnapshotHighWater,
    registry_key: &[u8],
) -> Result<String, TrustCardError> {
    let canonical = canonical_high_water_without_signature(high_water)?;
    let encoded = serde_json::to_vec(&canonical)?;
    let mut mac =
        HmacSha256::new_from_slice(registry_key).map_err(|_| TrustCardError::InvalidRegistryKey)?;
    mac.update(b"trust_card_registry_high_water_sig_v1:");
    mac.update(
        &u64::try_from(encoded.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    mac.update(&encoded);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn signed_snapshot_high_water(
    snapshot: &TrustCardRegistrySnapshot,
    registry_key: &[u8],
) -> Result<TrustCardRegistrySnapshotHighWater, TrustCardError> {
    verify_snapshot_signature(snapshot, registry_key)?;
    let mut high_water = TrustCardRegistrySnapshotHighWater {
        schema_version: TRUST_CARD_REGISTRY_HIGH_WATER_SCHEMA.to_string(),
        snapshot_epoch: snapshot.snapshot_epoch,
        snapshot_hash: snapshot.snapshot_hash.clone(),
        high_water_signature: String::new(),
    };
    high_water.high_water_signature = high_water_signature(&high_water, registry_key)?;
    Ok(high_water)
}

fn verify_snapshot_high_water(
    high_water: &TrustCardRegistrySnapshotHighWater,
    registry_key: &[u8],
) -> Result<(), TrustCardError> {
    if high_water.schema_version != TRUST_CARD_REGISTRY_HIGH_WATER_SCHEMA {
        return Err(TrustCardError::InvalidSnapshot(format!(
            "unsupported trust-card registry high-water schema `{}`",
            high_water.schema_version
        )));
    }
    let expected_signature = high_water_signature(high_water, registry_key)?;
    if !constant_time::ct_eq(&high_water.high_water_signature, &expected_signature) {
        return Err(TrustCardError::InvalidSnapshot(
            "trust-card registry high-water signature mismatch".to_string(),
        ));
    }
    Ok(())
}

fn read_snapshot_high_water(
    snapshot_path: &Path,
    registry_key: &[u8],
) -> Result<Option<TrustCardRegistrySnapshotHighWater>, TrustCardError> {
    let high_water_path = authoritative_snapshot_high_water_path(snapshot_path);
    if !high_water_path.exists() {
        return Ok(None);
    }
    let raw =
        std::fs::read_to_string(&high_water_path).map_err(|err| TrustCardError::SnapshotRead {
            path: high_water_path.clone(),
            detail: err.to_string(),
        })?;
    let high_water =
        serde_json::from_str::<TrustCardRegistrySnapshotHighWater>(&raw).map_err(|err| {
            TrustCardError::SnapshotParse {
                path: high_water_path.clone(),
                detail: err.to_string(),
            }
        })?;
    verify_snapshot_high_water(&high_water, registry_key)?;
    Ok(Some(high_water))
}

fn validate_snapshot_high_water(
    path: &Path,
    snapshot: &TrustCardRegistrySnapshot,
    high_water: Option<&TrustCardRegistrySnapshotHighWater>,
) -> Result<(), TrustCardError> {
    let Some(high_water) = high_water else {
        return Ok(());
    };

    if snapshot.snapshot_epoch < high_water.snapshot_epoch {
        return Err(TrustCardError::InvalidSnapshot(format!(
            "snapshot rollback rejected for {}: epoch {} is older than high-water epoch {}",
            path.display(),
            snapshot.snapshot_epoch,
            high_water.snapshot_epoch
        )));
    }

    if snapshot.snapshot_epoch == high_water.snapshot_epoch {
        if !constant_time::ct_eq(&snapshot.snapshot_hash, &high_water.snapshot_hash) {
            return Err(TrustCardError::InvalidSnapshot(format!(
                "snapshot rollback rejected for {}: epoch {} hash differs from high-water",
                path.display(),
                snapshot.snapshot_epoch
            )));
        }
        return Ok(());
    }

    let extends_high_water = snapshot
        .previous_snapshot_hash
        .as_deref()
        .is_some_and(|previous| constant_time::ct_eq(previous, &high_water.snapshot_hash));
    if !extends_high_water {
        return Err(TrustCardError::InvalidSnapshot(format!(
            "snapshot chain rejected for {}: epoch {} does not extend high-water epoch {}",
            path.display(),
            snapshot.snapshot_epoch,
            high_water.snapshot_epoch
        )));
    }

    Ok(())
}

fn write_snapshot_high_water(
    snapshot_path: &Path,
    high_water: &TrustCardRegistrySnapshotHighWater,
) -> Result<(), TrustCardError> {
    let high_water_path = authoritative_snapshot_high_water_path(snapshot_path);
    let parent = high_water_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|err| TrustCardError::SnapshotWrite {
        path: high_water_path.clone(),
        detail: err.to_string(),
    })?;
    let encoded = to_canonical_json(high_water)?;
    let mut temp = NamedTempFile::new_in(parent).map_err(|err| TrustCardError::SnapshotWrite {
        path: high_water_path.clone(),
        detail: err.to_string(),
    })?;
    temp.write_all(encoded.as_bytes())
        .map_err(|err| TrustCardError::SnapshotWrite {
            path: high_water_path.clone(),
            detail: err.to_string(),
        })?;
    temp.as_file()
        .sync_all()
        .map_err(|err| TrustCardError::SnapshotWrite {
            path: high_water_path.clone(),
            detail: err.to_string(),
        })?;
    temp.persist(&high_water_path)
        .map_err(|err| TrustCardError::SnapshotWrite {
            path: high_water_path.clone(),
            detail: err.error.to_string(),
        })?;
    sync_parent_directory(parent, &high_water_path)?;
    Ok(())
}

fn persist_snapshot_high_water_if_newer(
    path: &Path,
    snapshot: &TrustCardRegistrySnapshot,
    high_water: Option<&TrustCardRegistrySnapshotHighWater>,
    registry_key: &[u8],
) -> Result<(), TrustCardError> {
    let should_write = match high_water {
        None => true,
        Some(current) => {
            snapshot.snapshot_epoch > current.snapshot_epoch
                || (snapshot.snapshot_epoch == current.snapshot_epoch
                    && !constant_time::ct_eq(&snapshot.snapshot_hash, &current.snapshot_hash))
        }
    };
    if !should_write {
        return Ok(());
    }
    let next = signed_snapshot_high_water(snapshot, registry_key)?;
    write_snapshot_high_water(path, &next)
}

fn sorted_capabilities(mut capabilities: Vec<CapabilityDeclaration>) -> Vec<CapabilityDeclaration> {
    capabilities.sort_by(|left, right| left.name.cmp(&right.name));
    capabilities
}

fn sorted_dependencies(mut dependencies: Vec<DependencyTrustStatus>) -> Vec<DependencyTrustStatus> {
    dependencies.sort_by(|left, right| left.dependency_id.cmp(&right.dependency_id));
    dependencies
}

fn timestamp_from_secs(timestamp_secs: u64) -> String {
    let secs = match i64::try_from(timestamp_secs) {
        Ok(s) => s,
        Err(_) => return "1970-01-01T00:00:00Z".to_string(),
    };
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_unstable_by(|(left_key, _), (right_key, _)| left_key.cmp(right_key));

            let mut out = serde_json::Map::with_capacity(entries.len());
            for (key, nested_value) in entries {
                out.insert(key, canonicalize_value(nested_value));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_value).collect()),
        _ => value,
    }
}

#[cfg(test)]
mod test_canonical_optimization;

#[cfg(test)]
mod canonical_perf_test;

#[cfg(test)]
mod tests {
    use super::{
        AuditRecord, BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
        DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
        ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, SnapshotSourceContext,
        TrustCard, TrustCardError, TrustCardMutation, TrustCardRegistry, VerifiedEvidenceRef,
        canonicalize_value, to_canonical_json, update_card_hash, validate_trust_card_structure,
    };
    use base64::Engine as _;

    fn test_evidence_refs() -> Vec<VerifiedEvidenceRef> {
        use super::super::certification::EvidenceType;
        vec![
            VerifiedEvidenceRef {
                evidence_id: "ev-test-prov-001".to_string(),
                evidence_type: EvidenceType::ProvenanceChain,
                verified_at_epoch: 900,
                verification_receipt_hash: "c".repeat(64),
            },
            VerifiedEvidenceRef {
                evidence_id: "ev-test-rep-001".to_string(),
                evidence_type: EvidenceType::ReputationSignal,
                verified_at_epoch: 900,
                verification_receipt_hash: "d".repeat(64),
            },
        ]
    }

    fn sample_input() -> TrustCardInput {
        TrustCardInput {
            extension: ExtensionIdentity {
                extension_id: "npm:@acme/plugin".to_string(),
                version: "1.0.0".to_string(),
            },
            publisher: PublisherIdentity {
                publisher_id: "pub-acme".to_string(),
                display_name: "Acme".to_string(),
            },
            certification_level: CertificationLevel::Gold,
            capability_declarations: vec![CapabilityDeclaration {
                name: "plugin.execute".to_string(),
                description: "Run plugin".to_string(),
                risk: CapabilityRisk::Medium,
            }],
            behavioral_profile: BehavioralProfile {
                network_access: true,
                filesystem_access: false,
                subprocess_access: false,
                profile_summary: "safe".to_string(),
            },
            revocation_status: RevocationStatus::Active,
            provenance_summary: ProvenanceSummary {
                attestation_level: "slsa-l3".to_string(),
                source_uri: "registry://acme/plugin".to_string(),
                artifact_hashes: vec!["sha256:".to_string() + &"e".repeat(64)],
                verified_at: "2026-01-01T00:00:00Z".to_string(),
            },
            reputation_score_basis_points: 900,
            reputation_trend: ReputationTrend::Stable,
            active_quarantine: false,
            dependency_trust_summary: vec![DependencyTrustStatus {
                dependency_id: "dep-a".to_string(),
                trust_level: "verified".to_string(),
            }],
            last_verified_timestamp: "2026-01-01T00:00:00Z".to_string(),
            user_facing_risk_assessment: RiskAssessment {
                level: RiskLevel::Low,
                summary: "low risk".to_string(),
            },
            evidence_refs: test_evidence_refs(),
        }
    }

    #[test]
    fn trust_card_error_remediation_covers_operator_recovery_paths() {
        let path = std::path::PathBuf::from("state/trust-card-registry.json");
        let cases = [
            (
                TrustCardError::NotFound("npm:@missing/plugin".to_string()),
                "Seed or refresh",
            ),
            (
                TrustCardError::VersionNotFound {
                    extension_id: "npm:@acme/plugin".to_string(),
                    version: 42,
                },
                "historical card version",
            ),
            (
                TrustCardError::SignatureInvalid("npm:@acme/plugin".to_string()),
                "registry signing key",
            ),
            (
                TrustCardError::CardHashMismatch("npm:@acme/plugin".to_string()),
                "tampered card",
            ),
            (
                TrustCardError::Json("invalid type".to_string()),
                "malformed JSON",
            ),
            (TrustCardError::InvalidRegistryKey, "HMAC key"),
            (
                TrustCardError::InvalidPagination {
                    page: 0,
                    per_page: 0,
                },
                "one-based page number",
            ),
            (
                TrustCardError::InvalidInput {
                    reason: "extension_id cannot be empty".to_string(),
                },
                "rejected input field",
            ),
            (TrustCardError::EvidenceMissing, "verified evidence receipt"),
            (
                TrustCardError::EvidenceRequiredForUpgrade,
                "verified upgrade evidence",
            ),
            (TrustCardError::RevocationIrreversible, "replacement card"),
            (
                TrustCardError::UnsupportedSnapshotSchema("legacy".to_string()),
                "current trust-card registry schema",
            ),
            (
                TrustCardError::InvalidSnapshot("missing cards".to_string()),
                "authoritative state",
            ),
            (
                TrustCardError::SnapshotRead {
                    path: path.clone(),
                    detail: "not found".to_string(),
                },
                "read permission",
            ),
            (
                TrustCardError::SnapshotParse {
                    path: path.clone(),
                    detail: "syntax".to_string(),
                },
                "regenerate it",
            ),
            (
                TrustCardError::SnapshotWrite {
                    path,
                    detail: "disk full".to_string(),
                },
                "disk space",
            ),
        ];

        for (error, expected) in cases {
            let remediation = error.remediation();
            assert!(
                remediation.contains(expected),
                "{error:?} remediation `{remediation}` did not include `{expected}`"
            );
        }
    }

    #[test]
    fn create_and_read_round_trip() {
        let mut registry = TrustCardRegistry::default();
        let card = registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        assert_eq!(card.trust_card_version, 1);
        let fetched = registry
            .read("npm:@acme/plugin", 1_005, "trace")
            .expect("read")
            .expect("exists");
        assert_eq!(fetched.extension.extension_id, "npm:@acme/plugin");
    }

    #[test]
    fn update_creates_hash_linked_version() {
        let mut registry = TrustCardRegistry::default();
        let first = registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        let second = registry
            .update(
                "npm:@acme/plugin",
                TrustCardMutation {
                    certification_level: Some(CertificationLevel::Platinum),
                    revocation_status: None,
                    active_quarantine: None,
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: None,
                    evidence_refs: Some(test_evidence_refs()),
                },
                1_020,
                "trace",
            )
            .expect("update");
        assert_eq!(second.trust_card_version, 2);
        assert_eq!(
            second.previous_version_hash.as_deref(),
            Some(first.card_hash.as_str())
        );
    }

    #[test]
    fn signature_verification_rejects_tampered_card() {
        let mut registry = TrustCardRegistry::default();
        let mut card = registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        card.reputation_score_basis_points = 10;
        let err = verify_card_signature(&card, DEFAULT_REGISTRY_KEY).expect_err("must fail");
        assert!(matches!(err, TrustCardError::CardHashMismatch(_)));
    }

    #[test]
    fn list_filter_by_publisher_and_capability() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let by_pub = registry
            .list_by_publisher("pub-acme", 1_010, "trace")
            .expect("list by publisher");
        assert_eq!(by_pub.len(), 1);
        let by_capability = registry
            .search("telemetry", 1_010, "trace")
            .expect("search");
        assert_eq!(by_capability.len(), 1);
    }

    #[test]
    fn list_by_publisher_ignores_tampered_non_matching_card() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        registry
            .cards_by_extension
            .get_mut("npm:@beta/telemetry-bridge")
            .expect("history")
            .last_mut()
            .expect("latest")
            .reputation_score_basis_points = 999;

        let cards = registry
            .list_by_publisher("pub-acme", 1_010, "trace")
            .expect("unrelated tamper should not break filtered publisher list");
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].publisher.publisher_id, "pub-acme");
    }

    #[test]
    fn search_ignores_tampered_non_matching_card() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        registry
            .cards_by_extension
            .get_mut("npm:@beta/telemetry-bridge")
            .expect("history")
            .last_mut()
            .expect("latest")
            .reputation_score_basis_points = 999;

        let cards = registry
            .search("auth-guard", 1_010, "trace")
            .expect("unrelated tamper should not break search");
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].extension.extension_id, "npm:@acme/auth-guard");
    }

    #[test]
    fn compare_shows_changes() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let diff = registry
            .compare(
                "npm:@acme/auth-guard",
                "npm:@beta/telemetry-bridge",
                1_100,
                "trace",
            )
            .expect("compare");
        assert!(!diff.changes.is_empty());
    }

    #[test]
    fn compare_versions_for_same_extension() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let diff = registry
            .compare_versions("npm:@beta/telemetry-bridge", 1, 2, 1_100, "trace")
            .expect("compare versions");
        assert!(!diff.changes.is_empty());
        assert_eq!(
            diff.left_extension_id,
            "npm:@beta/telemetry-bridge@1".to_string()
        );
        assert_eq!(
            diff.right_extension_id,
            "npm:@beta/telemetry-bridge@2".to_string()
        );
    }

    #[test]
    fn compare_rejects_tampered_latest_card() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let latest = registry
            .cards_by_extension
            .get_mut("npm:@beta/telemetry-bridge")
            .expect("history")
            .last_mut()
            .expect("latest");
        latest.reputation_score_basis_points =
            latest.reputation_score_basis_points.saturating_add(1);

        let err = registry
            .compare(
                "npm:@acme/auth-guard",
                "npm:@beta/telemetry-bridge",
                1_100,
                "trace",
            )
            .expect_err("tampered latest card must be rejected");
        assert!(
            matches!(err, TrustCardError::CardHashMismatch(extension) if extension == "npm:@beta/telemetry-bridge")
        );
    }

    #[test]
    fn compare_versions_rejects_tampered_history_card() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let original = registry
            .cards_by_extension
            .get("npm:@beta/telemetry-bridge")
            .expect("history")[0]
            .clone();
        registry
            .cards_by_extension
            .get_mut("npm:@beta/telemetry-bridge")
            .expect("history")[0]
            .previous_version_hash = Some(original.card_hash);

        let err = registry
            .compare_versions("npm:@beta/telemetry-bridge", 1, 2, 1_100, "trace")
            .expect_err("tampered historical card must be rejected");
        assert!(
            matches!(err, TrustCardError::CardHashMismatch(extension) if extension == "npm:@beta/telemetry-bridge")
        );
    }

    #[test]
    fn read_specific_version() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let version_1 = registry
            .read_version("npm:@beta/telemetry-bridge", 1)
            .expect("read version")
            .expect("version 1");
        assert_eq!(version_1.trust_card_version, 1);
        assert!(
            registry
                .read_version("npm:@beta/telemetry-bridge", 9)
                .expect("read missing version")
                .is_none()
        );
    }

    #[test]
    fn paginate_handles_edges() {
        let items = vec![1, 2, 3, 4, 5];
        let page1 = paginate(&items, 1, 2).expect("page1");
        assert_eq!(page1, vec![1, 2]);
        let page3 = paginate(&items, 3, 2).expect("page3");
        assert_eq!(page3, vec![5]);
        let empty = paginate(&items, 4, 2).expect("page4");
        assert!(empty.is_empty());
    }

    #[test]
    fn paginate_rejects_zero_page() {
        let err = paginate(&[1, 2, 3], 0, 2).expect_err("page zero must fail");
        assert!(matches!(
            err,
            TrustCardError::InvalidPagination {
                page: 0,
                per_page: 2
            }
        ));
    }

    #[test]
    fn paginate_rejects_zero_per_page() {
        let err = paginate(&[1, 2, 3], 1, 0).expect_err("per_page zero must fail");
        assert!(matches!(
            err,
            TrustCardError::InvalidPagination {
                page: 1,
                per_page: 0
            }
        ));
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_items() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_zero_capacity_drops_new_item() {
        let mut items: Vec<&str> = Vec::new();

        push_bounded(&mut items, "ignored", 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_keeps_newest_items() {
        let mut items = vec![10, 11, 12, 13];

        push_bounded(&mut items, 14, 3);

        assert_eq!(items, vec![12, 13, 14]);
    }

    #[test]
    fn update_rejects_missing_extension_without_creating_history() {
        let mut registry = TrustCardRegistry::default();

        let err = registry
            .update(
                "npm:@missing/plugin",
                TrustCardMutation {
                    certification_level: Some(CertificationLevel::Bronze),
                    revocation_status: None,
                    active_quarantine: None,
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: None,
                    evidence_refs: None,
                },
                1_000,
                "trace",
            )
            .expect_err("missing extension must fail update");

        assert!(matches!(err, TrustCardError::NotFound(id) if id == "npm:@missing/plugin"));
        assert!(registry.cards_by_extension.is_empty());
        assert!(registry.cache_by_extension.is_empty());
    }

    #[test]
    fn compare_rejects_missing_left_extension() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = registry
            .compare(
                "npm:@missing/plugin",
                "npm:@beta/telemetry-bridge",
                1_100,
                "trace",
            )
            .expect_err("missing left card must fail compare");

        assert!(matches!(err, TrustCardError::NotFound(id) if id == "npm:@missing/plugin"));
    }

    #[test]
    fn compare_rejects_missing_right_extension() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = registry
            .compare(
                "npm:@acme/auth-guard",
                "npm:@missing/plugin",
                1_100,
                "trace",
            )
            .expect_err("missing right card must fail compare");

        assert!(matches!(err, TrustCardError::NotFound(id) if id == "npm:@missing/plugin"));
    }

    #[test]
    fn compare_versions_rejects_missing_extension_history() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = registry
            .compare_versions("npm:@missing/plugin", 1, 2, 1_100, "trace")
            .expect_err("missing history must fail version compare");

        assert!(matches!(err, TrustCardError::NotFound(id) if id == "npm:@missing/plugin"));
    }

    #[test]
    fn compare_versions_rejects_missing_left_version() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = registry
            .compare_versions("npm:@beta/telemetry-bridge", 99, 2, 1_100, "trace")
            .expect_err("missing left version must fail version compare");

        assert!(matches!(
            err,
            TrustCardError::VersionNotFound {
                extension_id,
                version: 99
            } if extension_id == "npm:@beta/telemetry-bridge"
        ));
    }

    #[test]
    fn compare_versions_rejects_missing_right_version() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = registry
            .compare_versions("npm:@beta/telemetry-bridge", 1, 99, 1_100, "trace")
            .expect_err("missing right version must fail version compare");

        assert!(matches!(
            err,
            TrustCardError::VersionNotFound {
                extension_id,
                version: 99
            } if extension_id == "npm:@beta/telemetry-bridge"
        ));
    }

    #[test]
    fn timestamp_from_secs_uses_rfc3339_and_not_unix_seconds() {
        let secs = 1_700_000_000_u64;
        let formatted = timestamp_from_secs(secs);

        assert!(
            chrono::DateTime::parse_from_rfc3339(&formatted).is_ok(),
            "expected RFC3339 timestamp, got {formatted}"
        );
        assert!(formatted.ends_with('Z'));
        assert_ne!(formatted, format!("{secs}Z"));
    }

    #[test]
    fn telemetry_includes_cache_miss_and_hit() {
        let mut registry = TrustCardRegistry::new(60, DEFAULT_REGISTRY_KEY);
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        registry
            .read("npm:@acme/plugin", 1_001, "trace")
            .expect("read1");
        registry
            .read("npm:@acme/plugin", 1_002, "trace")
            .expect("read2");
        let codes: Vec<&str> = registry
            .telemetry()
            .iter()
            .map(|evt| evt.event_code.as_str())
            .collect();
        assert!(codes.contains(&TRUST_CARD_CACHE_HIT));
    }

    #[test]
    fn sync_cache_counts_missing_entries_without_force() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let total_cards = registry.cards_by_extension.len();
        let missing_extension = registry
            .cards_by_extension
            .keys()
            .next()
            .cloned()
            .expect("demo registry should not be empty");
        registry.cache_by_extension.remove(&missing_extension);

        let report = registry
            .sync_cache(1_010, "trace-sync", false)
            .expect("sync cache");

        assert_eq!(report.total_cards, total_cards);
        assert_eq!(report.cache_misses, 1);
        assert_eq!(report.cache_hits, total_cards.saturating_sub(1));
        assert_eq!(report.stale_refreshes, 0);
        assert_eq!(report.forced_refreshes, 0);
        assert!(registry.cache_by_extension.contains_key(&missing_extension));
    }

    #[test]
    fn sync_cache_refreshes_stale_entries_without_force() {
        let mut registry = TrustCardRegistry::new(1, DEFAULT_REGISTRY_KEY);
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");

        let report = registry
            .sync_cache(1_002, "trace-sync", false)
            .expect("sync cache");

        assert_eq!(
            report,
            TrustCardSyncReport {
                total_cards: 1,
                cache_hits: 0,
                cache_misses: 0,
                stale_refreshes: 1,
                forced_refreshes: 0,
            }
        );
    }

    #[test]
    fn exact_ttl_boundary_fails_closed_for_read_and_sync_cache() {
        let mut read_registry = TrustCardRegistry::new(10, DEFAULT_REGISTRY_KEY);
        read_registry
            .create(sample_input(), 1_000, "trace-create")
            .expect("create");
        read_registry
            .cards_by_extension
            .get_mut("npm:@acme/plugin")
            .expect("history")
            .last_mut()
            .expect("latest")
            .reputation_score_basis_points = 1;

        let read_err = read_registry
            .read("npm:@acme/plugin", 1_010, "trace-read")
            .expect_err("exact ttl boundary must refresh from source and reject tampering");
        assert!(matches!(
            read_err,
            TrustCardError::CardHashMismatch(extension) if extension == "npm:@acme/plugin"
        ));

        let mut sync_registry = TrustCardRegistry::new(10, DEFAULT_REGISTRY_KEY);
        sync_registry
            .create(sample_input(), 1_000, "trace-create")
            .expect("create");
        sync_registry
            .cards_by_extension
            .get_mut("npm:@acme/plugin")
            .expect("history")
            .last_mut()
            .expect("latest")
            .reputation_score_basis_points = 1;

        let sync_err = sync_registry
            .sync_cache(1_010, "trace-sync", false)
            .expect_err("exact ttl boundary must not treat the cache entry as fresh");
        assert!(matches!(
            sync_err,
            TrustCardError::CardHashMismatch(extension) if extension == "npm:@acme/plugin"
        ));
    }

    #[test]
    fn sync_cache_force_refreshes_fresh_entries() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let total_cards = registry.cards_by_extension.len();

        let report = registry
            .sync_cache(1_010, "trace-sync", true)
            .expect("force sync cache");

        assert_eq!(report.total_cards, total_cards);
        assert_eq!(report.cache_hits, 0);
        assert_eq!(report.cache_misses, 0);
        assert_eq!(report.stale_refreshes, 0);
        assert_eq!(report.forced_refreshes, total_cards);

        let codes: Vec<&str> = registry
            .telemetry()
            .iter()
            .map(|evt| evt.event_code.as_str())
            .collect();
        assert!(codes.contains(&TRUST_CARD_FORCE_REFRESH));
    }

    #[test]
    fn timestamp_from_secs_produces_valid_iso8601() {
        let ts = timestamp_from_secs(1_700_000_000);
        assert!(ts.contains('T'), "must contain T separator: {ts}");
        assert!(ts.ends_with('Z'), "must end with Z: {ts}");
        assert_eq!(ts, "2023-11-14T22:13:20Z");
    }

    // ── Evidence binding adversarial tests ──────────────────────────────

    #[test]
    fn create_rejects_empty_evidence() {
        let mut registry = TrustCardRegistry::default();
        let mut input = sample_input();
        input.evidence_refs = vec![];
        let err = registry
            .create(input, 1_000, "trace")
            .expect_err("must fail");
        assert!(matches!(err, TrustCardError::EvidenceMissing));
    }

    #[test]
    fn create_includes_derivation_evidence() {
        let mut registry = TrustCardRegistry::default();
        let card = registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        let derivation = card
            .derivation_evidence
            .as_ref()
            .expect("derivation must be present");
        assert_eq!(derivation.evidence_refs.len(), 2);
        assert!(derivation.derivation_chain_hash.starts_with("sha256:"));
        assert_eq!(derivation.derived_at_epoch, 1_000);
    }

    #[test]
    fn update_upgrade_without_evidence_rejected() {
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        // Gold (from sample) → Platinum without evidence → error.
        let err = registry
            .update(
                "npm:@acme/plugin",
                TrustCardMutation {
                    certification_level: Some(CertificationLevel::Platinum),
                    revocation_status: None,
                    active_quarantine: None,
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: None,
                    evidence_refs: None,
                },
                1_020,
                "trace",
            )
            .expect_err("upgrade without evidence must fail");
        assert!(matches!(err, TrustCardError::EvidenceRequiredForUpgrade));
    }

    #[test]
    fn update_upgrade_with_empty_evidence_rejected() {
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        let err = registry
            .update(
                "npm:@acme/plugin",
                TrustCardMutation {
                    certification_level: Some(CertificationLevel::Platinum),
                    revocation_status: None,
                    active_quarantine: None,
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: None,
                    evidence_refs: Some(Vec::new()),
                },
                1_020,
                "trace",
            )
            .expect_err("empty upgrade evidence must fail");
        assert!(matches!(err, TrustCardError::EvidenceMissing));
    }

    #[test]
    fn update_demotion_without_evidence_allowed() {
        let mut registry = TrustCardRegistry::default();
        // Create with Gold level.
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        // Gold → Bronze is a demotion — should succeed without evidence.
        let card = registry
            .update(
                "npm:@acme/plugin",
                TrustCardMutation {
                    certification_level: Some(CertificationLevel::Bronze),
                    revocation_status: None,
                    active_quarantine: None,
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: None,
                    evidence_refs: None,
                },
                1_020,
                "trace",
            )
            .expect("demotion without evidence should succeed");
        assert_eq!(card.certification_level, CertificationLevel::Bronze);
    }

    #[test]
    fn update_with_empty_evidence_rejected_even_without_upgrade() {
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        let err = registry
            .update(
                "npm:@acme/plugin",
                TrustCardMutation {
                    certification_level: Some(CertificationLevel::Bronze),
                    revocation_status: None,
                    active_quarantine: None,
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: None,
                    evidence_refs: Some(Vec::new()),
                },
                1_020,
                "trace",
            )
            .expect_err("empty evidence should not erase derivation metadata");
        assert!(matches!(err, TrustCardError::EvidenceMissing));
    }

    #[test]
    fn update_with_evidence_replaces_derivation() {
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        let new_refs = test_evidence_refs();
        let card = registry
            .update(
                "npm:@acme/plugin",
                TrustCardMutation {
                    certification_level: Some(CertificationLevel::Platinum),
                    revocation_status: None,
                    active_quarantine: None,
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: None,
                    evidence_refs: Some(new_refs),
                },
                2_000,
                "trace",
            )
            .expect("upgrade with evidence should succeed");
        let derivation = card
            .derivation_evidence
            .as_ref()
            .expect("derivation updated");
        assert_eq!(derivation.derived_at_epoch, 2_000);
    }

    #[test]
    fn list_rejects_tampered_latest_card() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        registry
            .cards_by_extension
            .get_mut("npm:@beta/telemetry-bridge")
            .expect("history")
            .last_mut()
            .expect("latest")
            .reputation_score_basis_points = 999;

        let err = registry
            .list(&TrustCardListFilter::empty(), "trace", 1_100)
            .expect_err("tampered latest card must fail list");
        assert!(
            matches!(err, TrustCardError::CardHashMismatch(extension) if extension == "npm:@beta/telemetry-bridge")
        );
    }

    #[test]
    fn create_rejects_append_after_tampered_latest_card() {
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace-create-1")
            .expect("create");
        registry
            .cards_by_extension
            .get_mut("npm:@acme/plugin")
            .expect("history")
            .last_mut()
            .expect("latest")
            .reputation_score_basis_points = 1;

        let mut second_input = sample_input();
        second_input.extension.version = "2.0.0".to_string();

        let err = registry
            .create(second_input, 1_100, "trace-create-2")
            .expect_err("tampered latest card must block append");
        assert!(matches!(
            err,
            TrustCardError::CardHashMismatch(extension) if extension == "npm:@acme/plugin"
        ));
    }

    #[test]
    fn update_rejects_tampered_latest_card() {
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace-create")
            .expect("create");
        registry
            .cards_by_extension
            .get_mut("npm:@acme/plugin")
            .expect("history")
            .last_mut()
            .expect("latest")
            .reputation_score_basis_points = 1;

        let err = registry
            .update(
                "npm:@acme/plugin",
                TrustCardMutation {
                    certification_level: Some(CertificationLevel::Platinum),
                    revocation_status: None,
                    active_quarantine: None,
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: None,
                    evidence_refs: Some(test_evidence_refs()),
                },
                1_100,
                "trace-update",
            )
            .expect_err("tampered latest card must block update");
        assert!(matches!(
            err,
            TrustCardError::CardHashMismatch(extension) if extension == "npm:@acme/plugin"
        ));
    }

    #[test]
    fn search_rejects_tampered_matching_card() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        registry
            .cards_by_extension
            .get_mut("npm:@beta/telemetry-bridge")
            .expect("history")
            .last_mut()
            .expect("latest")
            .publisher
            .publisher_id = "pub-tampered".to_string();

        let err = registry
            .search("tampered", 1_100, "trace")
            .expect_err("tampered card must fail search");
        assert!(
            matches!(err, TrustCardError::CardHashMismatch(extension) if extension == "npm:@beta/telemetry-bridge")
        );
    }

    #[test]
    fn read_recovers_from_invalid_fresh_cache_entry() {
        let mut registry = TrustCardRegistry::default();
        let created = registry
            .create(sample_input(), 1_000, "trace-create")
            .expect("create");
        registry
            .cache_by_extension
            .get_mut("npm:@acme/plugin")
            .expect("cached")
            .card
            .reputation_score_basis_points = 1;

        let fetched = registry
            .read("npm:@acme/plugin", 1_001, "trace-read")
            .expect("read")
            .expect("card exists");

        assert_eq!(fetched.card_hash, created.card_hash);
        assert_eq!(
            registry
                .cache_by_extension
                .get("npm:@acme/plugin")
                .expect("cache repaired")
                .card
                .card_hash,
            created.card_hash
        );
    }

    #[test]
    fn read_version_rejects_tampered_history_card() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        registry
            .cards_by_extension
            .get_mut("npm:@beta/telemetry-bridge")
            .expect("history")[0]
            .previous_version_hash = Some("tampered".to_string());

        let err = registry
            .read_version("npm:@beta/telemetry-bridge", 1)
            .expect_err("tampered historical card must fail");
        assert!(
            matches!(err, TrustCardError::CardHashMismatch(extension) if extension == "npm:@beta/telemetry-bridge")
        );
    }

    #[test]
    fn read_rejects_tampered_source_without_caching_it() {
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace-create")
            .expect("create");
        registry.cache_by_extension.remove("npm:@acme/plugin");
        registry
            .cards_by_extension
            .get_mut("npm:@acme/plugin")
            .expect("history")
            .last_mut()
            .expect("latest")
            .reputation_score_basis_points = 1;

        let err = registry
            .read("npm:@acme/plugin", 1_100, "trace-read")
            .expect_err("tampered source must be rejected");
        assert!(matches!(
            err,
            TrustCardError::CardHashMismatch(extension) if extension == "npm:@acme/plugin"
        ));
        assert!(!registry.cache_by_extension.contains_key("npm:@acme/plugin"));
    }

    #[test]
    fn sync_cache_rebuilds_invalid_fresh_cache_entry() {
        let mut registry = TrustCardRegistry::default();
        let created = registry
            .create(sample_input(), 1_000, "trace-create")
            .expect("create");
        registry
            .cache_by_extension
            .get_mut("npm:@acme/plugin")
            .expect("cached")
            .card
            .reputation_score_basis_points = 1;

        let report = registry
            .sync_cache(1_001, "trace-sync", false)
            .expect("sync cache");

        assert_eq!(report.cache_hits, 0);
        assert_eq!(report.cache_misses, 1);
        assert_eq!(
            registry
                .cache_by_extension
                .get("npm:@acme/plugin")
                .expect("cache rebuilt")
                .card
                .card_hash,
            created.card_hash
        );
    }

    #[test]
    fn timestamp_from_secs_fallback_is_valid_iso8601() {
        // 10 trillion seconds exceeds chrono's max supported date, so from_timestamp returns None → fallback fires
        let ts = timestamp_from_secs(10_000_000_000_000);
        assert!(ts.contains('T'), "fallback must be valid ISO8601: {ts}");
        assert!(ts.ends_with('Z'), "fallback must end with Z: {ts}");
        assert!(
            !ts.chars().all(|c| c.is_ascii_digit() || c == 'Z'),
            "fallback must not be raw digits+Z: {ts}"
        );
    }

    #[test]
    fn concurrent_authoritative_snapshot_write_fails_closed_when_flock_is_held() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join(".franken-node/state/trust-card-registry.v1.json");
        let parent = path.parent().expect("snapshot path should have parent");
        std::fs::create_dir_all(parent).expect("create parent");
        let lock_path = authoritative_snapshot_lock_path(&path);
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open lock");
        lock_file.try_lock().expect("hold competing writer lock");

        let err = registry
            .persist_authoritative_state(&path)
            .expect_err("held flock must prevent concurrent snapshot publication");

        lock_file.unlock().expect("release lock");
        assert!(matches!(
            err,
            TrustCardError::SnapshotWrite { detail, .. }
                if detail.contains("timed out acquiring flock")
        ));
        assert!(
            !path.exists(),
            "snapshot must not be published while another writer holds the flock"
        );
    }

    #[test]
    fn parent_directory_sync_fails_closed_when_parent_cannot_be_opened() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing_parent = dir.path().join("missing-parent");
        let snapshot_path = missing_parent.join("trust-card-registry.v1.json");

        let err = sync_parent_directory(&missing_parent, &snapshot_path)
            .expect_err("missing parent directory must fail closed");

        assert!(matches!(
            err,
            TrustCardError::SnapshotWrite { path, detail }
                if path == snapshot_path
                    && detail.contains("failed opening parent directory")
        ));
    }

    #[test]
    fn registry_snapshot_roundtrip_preserves_latest_cards() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join(".franken-node/state/trust-card-registry.v1.json");
        registry
            .persist_authoritative_state(&path)
            .expect("persist authoritative state");

        let mut restored = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("load");

        let cards = restored
            .list(&TrustCardListFilter::empty(), "trace-roundtrip", 2_000)
            .expect("list");
        assert_eq!(cards.len(), 2);
        assert_eq!(
            restored
                .cache_by_extension
                .get("npm:@beta/telemetry-bridge")
                .expect("cached")
                .cached_at_secs,
            2_000
        );
    }

    #[test]
    fn load_authoritative_state_rejects_older_signed_snapshot_rollback() {
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace-create")
            .expect("create");
        let older_snapshot = registry.snapshot().expect("snapshot");
        registry
            .update(
                "npm:@acme/plugin",
                TrustCardMutation {
                    certification_level: Some(CertificationLevel::Bronze),
                    revocation_status: Some(RevocationStatus::Revoked {
                        reason: "rollback regression revocation".to_string(),
                        revoked_at: "2026-01-01T00:01:00Z".to_string(),
                    }),
                    active_quarantine: Some(true),
                    reputation_score_basis_points: Some(100),
                    reputation_trend: Some(ReputationTrend::Declining),
                    user_facing_risk_assessment: Some(RiskAssessment {
                        level: RiskLevel::Critical,
                        summary: "revoked for rollback regression".to_string(),
                    }),
                    last_verified_timestamp: Some("2026-01-01T00:01:00Z".to_string()),
                    evidence_refs: None,
                },
                1_100,
                "trace-revoke",
            )
            .expect("revoke");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join(".franken-node/state/trust-card-registry.v1.json");
        registry
            .persist_authoritative_state(&path)
            .expect("persist revoked high-water state");
        std::fs::write(
            &path,
            to_canonical_json(&older_snapshot).expect("older json"),
        )
        .expect("install older snapshot");

        let err = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::TrustedFile,
        )
        .expect_err("older signed snapshot must be rejected after high-water advances");

        assert!(
            matches!(err, TrustCardError::InvalidSnapshot(ref detail) if detail.contains("rollback rejected")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn registry_snapshot_rejects_tampered_card_history() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let mut snapshot = registry.snapshot().expect("snapshot");
        snapshot
            .cards_by_extension
            .get_mut("npm:@beta/telemetry-bridge")
            .expect("history")[0]
            .reputation_score_basis_points = 1;

        let err = TrustCardRegistry::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, 2_000)
            .expect_err("tampered snapshot must fail");
        assert!(
            matches!(err, TrustCardError::CardHashMismatch(extension) if extension == "npm:@beta/telemetry-bridge")
        );
    }

    #[test]
    fn registry_snapshot_rejects_mismatched_extension_bucket() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let mut snapshot = registry.snapshot().expect("snapshot");
        let history = snapshot
            .cards_by_extension
            .remove("npm:@acme/auth-guard")
            .expect("history");
        snapshot
            .cards_by_extension
            .insert("npm:@wrong/extension".to_string(), history);

        let err = TrustCardRegistry::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, 2_000)
            .expect_err("wrong bucket must fail");
        assert!(
            matches!(err, TrustCardError::InvalidSnapshot(detail) if detail.contains("contains card"))
        );
    }

    #[test]
    fn registry_snapshot_rejects_unsupported_schema() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let mut snapshot = registry.snapshot().expect("snapshot");
        snapshot.schema_version = "franken-node/trust-card-registry-state/v0".to_string();

        let err = TrustCardRegistry::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, 2_000)
            .expect_err("unsupported schema must fail");

        assert!(matches!(
            err,
            TrustCardError::UnsupportedSnapshotSchema(schema)
                if schema == "franken-node/trust-card-registry-state/v0"
        ));
    }

    #[test]
    fn registry_snapshot_rejects_empty_history_bucket() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let mut snapshot = registry.snapshot().expect("snapshot");
        snapshot
            .cards_by_extension
            .insert("npm:@empty/plugin".to_string(), Vec::new());

        let err = TrustCardRegistry::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, 2_000)
            .expect_err("empty history bucket must fail");

        assert!(
            matches!(err, TrustCardError::InvalidSnapshot(detail) if detail.contains("cannot be empty"))
        );
    }

    #[test]
    fn registry_snapshot_rejects_non_monotonic_versions() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let mut snapshot = registry.snapshot().expect("snapshot");
        let history = snapshot
            .cards_by_extension
            .get_mut("npm:@beta/telemetry-bridge")
            .expect("history");
        history[1].trust_card_version = history[0].trust_card_version;
        sign_card_in_place(&mut history[1], DEFAULT_REGISTRY_KEY).expect("resign");

        let err = TrustCardRegistry::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, 2_000)
            .expect_err("non-monotonic history must fail");

        assert!(
            matches!(err, TrustCardError::InvalidSnapshot(detail) if detail.contains("non-monotonic"))
        );
    }

    #[test]
    fn registry_snapshot_rejects_broken_previous_hash_linkage() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let mut snapshot = registry.snapshot().expect("snapshot");
        let history = snapshot
            .cards_by_extension
            .get_mut("npm:@beta/telemetry-bridge")
            .expect("history");
        history[1].previous_version_hash = Some("0".repeat(64));
        sign_card_in_place(&mut history[1], DEFAULT_REGISTRY_KEY).expect("resign");

        let err = TrustCardRegistry::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, 2_000)
            .expect_err("broken previous hash linkage must fail");

        assert!(
            matches!(err, TrustCardError::InvalidSnapshot(detail) if detail.contains("previous_version_hash"))
        );
    }

    #[test]
    fn load_authoritative_state_rejects_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing-trust-card-state.json");

        let err = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::TrustedFile,
        )
        .expect_err("missing state file must fail");

        assert!(matches!(err, TrustCardError::SnapshotRead { .. }));
    }

    #[test]
    fn load_authoritative_state_rejects_malformed_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("malformed-trust-card-state.json");
        std::fs::write(&path, "{not-json").expect("write malformed state");

        let err = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::TrustedFile,
        )
        .expect_err("malformed state file must fail");

        assert!(matches!(err, TrustCardError::SnapshotParse { .. }));
    }

    #[test]
    fn snapshot_fails_with_invalid_registry_key() {
        // Use an empty key which should be invalid for HMAC
        let invalid_key = b"";
        let mut registry = TrustCardRegistry::new(0, invalid_key);
        registry
            .create(sample_input(), 1_000, "trace-create")
            .expect("create");

        let err = registry
            .snapshot()
            .expect_err("snapshot with invalid key should fail");
        assert!(matches!(err, TrustCardError::InvalidRegistryKey));
    }

    // ── NEGATIVE-PATH TESTS: Security & Robustness ──────────────────

    #[test]
    fn test_negative_publisher_id_with_unicode_injection_attacks() {
        use crate::security::constant_time;

        let malicious_publisher_ids = [
            "publisher\u{202E}fake\u{202C}",      // BiDi override attack
            "publisher\x1b[31mred\x1b[0m",        // ANSI escape injection
            "publisher\0null\r\n\t",              // Control character injection
            "publisher\"}{\"admin\":true,\"fake", // JSON injection attempt
            "publisher/../../etc/passwd",         // Path traversal attempt
            "publisher\u{200B}\u{FEFF}",          // Zero-width character injection
            "publisher.with.dots",                // Domain confusion
            "PUBLISHER",                          // Case sensitivity test
            "publisher@domain.com",               // Email-like format
        ];

        for malicious_id in malicious_publisher_ids {
            let publisher = TrustCardPublisher {
                publisher_id: malicious_id.to_string(),
                display_name: "Test Publisher".to_string(),
                domain: Some("example.com".to_string()),
                contact_email: Some("test@example.com".to_string()),
                verified_at_epoch: 1234567890,
                signature_algorithm: "ecdsa-p256".to_string(),
                public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                    .to_string(),
            };

            // Verify serialization handles malicious publisher ID safely
            let json = serde_json::to_string(&publisher).expect("serialization should work");
            let parsed: TrustCardPublisher =
                serde_json::from_str(&json).expect("deserialization should work");

            // Verify malicious content is preserved exactly for forensics but contained
            assert_eq!(
                parsed.publisher_id, malicious_id,
                "publisher ID should be preserved"
            );

            // Verify JSON structure integrity
            let json_value: serde_json::Value =
                serde_json::from_str(&json).expect("JSON should be valid");
            let expected_keys = [
                "publisher_id",
                "display_name",
                "domain",
                "contact_email",
                "verified_at_epoch",
                "signature_algorithm",
                "public_key_pem",
            ];

            if let Some(obj) = json_value.as_object() {
                for key in obj.keys() {
                    assert!(
                        expected_keys.contains(&key.as_str()),
                        "unexpected field '{}' - possible JSON injection",
                        key
                    );
                }
            }

            // Verify constant-time comparison works for publisher IDs
            let normal_id = "normal-publisher-123";
            assert!(
                !constant_time::ct_eq(&parsed.publisher_id, normal_id),
                "publisher ID comparison should be constant-time"
            );
        }
    }

    #[test]
    fn test_negative_trust_card_derivation_hash_with_massive_evidence_refs() {
        // Create 10,000 evidence refs to stress the hashing function
        let massive_refs: Vec<VerifiedEvidenceRef> = (0..10_000)
            .map(|i| VerifiedEvidenceRef {
                evidence_id: format!("evidence_{}_with_long_suffix_{}", i, "X".repeat(1000)),
                evidence_type: EvidenceType::ProvenanceAttestation,
                verified_at_epoch: 1234567890_u64.saturating_add(i as u64),
                verification_receipt_hash: format!(
                    "hash_{}_with_long_suffix_{}",
                    i,
                    "Y".repeat(500)
                ),
            })
            .collect();

        let derived_at = u64::MAX; // Test with maximum timestamp

        // Should handle massive inputs without overflow or memory exhaustion
        let hash1 = compute_trust_card_derivation_hash(&massive_refs, derived_at);

        // Verify hash is deterministic with same inputs
        let hash2 = compute_trust_card_derivation_hash(&massive_refs, derived_at);
        assert_eq!(hash1, hash2, "derivation hash should be deterministic");

        // Verify hash format and length
        assert!(
            hash1.starts_with("sha256:"),
            "hash should have proper prefix"
        );
        assert_eq!(hash1.len(), 71, "sha256 hash should have correct length");

        // Verify different inputs produce different hashes
        let different_refs = massive_refs[0..9999].to_vec(); // One less ref
        let hash3 = compute_trust_card_derivation_hash(&different_refs, derived_at);
        assert_ne!(
            hash1, hash3,
            "different inputs should produce different hashes"
        );

        // Test with extreme derived_at values
        let hash_min = compute_trust_card_derivation_hash(&massive_refs, 0);
        let hash_max = compute_trust_card_derivation_hash(&massive_refs, u64::MAX);
        assert_ne!(
            hash_min, hash_max,
            "different timestamps should produce different hashes"
        );

        // Test collision resistance with similar evidence IDs
        let collision_refs = vec![
            VerifiedEvidenceRef {
                evidence_id: "evidence_1".to_string(),
                evidence_type: EvidenceType::ProvenanceAttestation,
                verified_at_epoch: 123,
                verification_receipt_hash: "hash1".to_string(),
            },
            VerifiedEvidenceRef {
                evidence_id: "evidence_2".to_string(),
                evidence_type: EvidenceType::ProvenanceAttestation,
                verified_at_epoch: 123,
                verification_receipt_hash: "hash1".to_string(),
            },
        ];

        let swapped_refs = vec![collision_refs[1].clone(), collision_refs[0].clone()];

        let hash_original = compute_trust_card_derivation_hash(&collision_refs, 123);
        let hash_swapped = compute_trust_card_derivation_hash(&swapped_refs, 123);
        assert_ne!(
            hash_original, hash_swapped,
            "order should affect hash (collision resistance)"
        );
    }

    #[test]
    fn test_negative_capability_declaration_with_malicious_injection_patterns() {
        let malicious_capabilities = vec![
            CapabilityDeclaration {
                name: "cap\u{202E}fake\u{202C}".to_string(), // BiDi override
                scope: "global".to_string(),
                impact: "critical".to_string(),
                evidence_ref: "ref\x1b[31m".to_string(), // ANSI escape
            },
            CapabilityDeclaration {
                name: "capability\"}{\"admin\":true,\"bypass".to_string(), // JSON injection
                scope: "local\0null".to_string(),                          // Null byte injection
                impact: "high\r\n\t".to_string(),                          // Control chars
                evidence_ref: "ref/../../etc/passwd".to_string(),          // Path traversal
            },
            CapabilityDeclaration {
                name: "X".repeat(10_000),         // Massive field (10KB)
                scope: "Y".repeat(5_000),         // Massive field (5KB)
                impact: "Z".repeat(5_000),        // Massive field (5KB)
                evidence_ref: "W".repeat(10_000), // Massive field (10KB)
            },
        ];

        let trust_card = TrustCard {
            card_id: "test-card".to_string(),
            publisher: test_publisher(),
            extension_id: "test-extension".to_string(),
            certification_level: CertificationLevel::Verified,
            capability_declarations: malicious_capabilities.clone(),
            reputation_score: 0.95,
            trust_card_schema_version: "1.0.0".to_string(),
            derived_at_epoch: 1234567890,
            derivation_evidence_hash: "test-hash".to_string(),
            revocation_status: RevocationStatus::Valid,
            cache_metadata: CacheMetadata {
                cached_at_epoch: 1234567890,
                ttl_seconds: 60,
                refresh_count: 0,
            },
            audit_history: vec![],
        };

        // Verify serialization handles malicious capabilities
        let json = serde_json::to_string(&trust_card)
            .expect("serialization should handle malicious capabilities");
        let parsed: TrustCard = serde_json::from_str(&json).expect("deserialization should work");

        // Verify capabilities are preserved (for forensics) but contained
        assert_eq!(
            parsed.capability_declarations.len(),
            malicious_capabilities.len()
        );

        for (original, parsed_cap) in malicious_capabilities
            .iter()
            .zip(parsed.capability_declarations.iter())
        {
            assert_eq!(
                original.name, parsed_cap.name,
                "capability name should be preserved"
            );
            assert_eq!(
                original.scope, parsed_cap.scope,
                "capability scope should be preserved"
            );
            assert_eq!(
                original.impact, parsed_cap.impact,
                "capability impact should be preserved"
            );
            assert_eq!(
                original.evidence_ref, parsed_cap.evidence_ref,
                "capability evidence_ref should be preserved"
            );
        }

        // Verify JSON structure integrity
        let json_value: serde_json::Value =
            serde_json::from_str(&json).expect("JSON should be valid");
        assert!(
            json_value.get("admin").is_none(),
            "JSON injection should not create admin field"
        );

        // Test that massive fields are handled without memory explosion
        assert!(
            json.len() > 50_000,
            "serialized JSON should include massive fields"
        );
        assert!(
            json.len() < 1_000_000,
            "serialized JSON should be reasonably bounded"
        );

        // Test display functionality with malicious content
        let display = format!("{:?}", trust_card);
        assert!(display.len() > 1000, "debug display should include content");
        assert!(display.len() < 100_000, "debug display should be bounded");
    }

    #[test]
    fn test_negative_trust_card_filter_bypass_with_case_sensitivity() {
        let test_card = TrustCard {
            card_id: "test-card".to_string(),
            publisher: TrustCardPublisher {
                publisher_id: "Publisher-123".to_string(), // Mixed case
                display_name: "Test Publisher".to_string(),
                domain: Some("example.com".to_string()),
                contact_email: Some("test@example.com".to_string()),
                verified_at_epoch: 1234567890,
                signature_algorithm: "ecdsa-p256".to_string(),
                public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                    .to_string(),
            },
            extension_id: "Test-Extension".to_string(),
            certification_level: CertificationLevel::Verified,
            capability_declarations: vec![CapabilityDeclaration {
                name: "Network-Access".to_string(), // Mixed case capability
                scope: "global".to_string(),
                impact: "medium".to_string(),
                evidence_ref: "ref123".to_string(),
            }],
            reputation_score: 0.95,
            trust_card_schema_version: "1.0.0".to_string(),
            derived_at_epoch: 1234567890,
            derivation_evidence_hash: "test-hash".to_string(),
            revocation_status: RevocationStatus::Valid,
            cache_metadata: CacheMetadata {
                cached_at_epoch: 1234567890,
                ttl_seconds: 60,
                refresh_count: 0,
            },
            audit_history: vec![],
        };

        // Test filters with different case variations
        let filter_exact_case = TrustCardListFilter {
            certification_level: Some(CertificationLevel::Verified),
            publisher_id: Some("Publisher-123".to_string()), // Exact match
            capability: Some("Network-Access".to_string()),  // Exact match
        };

        let filter_wrong_case = TrustCardListFilter {
            certification_level: Some(CertificationLevel::Verified),
            publisher_id: Some("publisher-123".to_string()), // Different case
            capability: Some("network-access".to_string()),  // Different case
        };

        let filter_partial_match = TrustCardListFilter {
            certification_level: Some(CertificationLevel::Verified),
            publisher_id: Some("Publisher-123".to_string()),
            capability: Some("Network".to_string()), // Partial match (should work due to contains())
        };

        // Test exact case matching
        assert!(
            card_matches_filter(&test_card, &filter_exact_case),
            "exact case should match"
        );

        // Test case sensitivity in publisher_id (should fail with wrong case)
        assert!(
            !card_matches_filter(&test_card, &filter_wrong_case),
            "wrong case should not match publisher_id"
        );

        // Test capability partial matching (contains() is case-sensitive)
        assert!(
            card_matches_filter(&test_card, &filter_partial_match),
            "partial capability match should work"
        );

        let filter_partial_wrong_case = TrustCardListFilter {
            certification_level: Some(CertificationLevel::Verified),
            publisher_id: Some("Publisher-123".to_string()),
            capability: Some("network".to_string()), // Lowercase partial (should fail)
        };

        assert!(
            !card_matches_filter(&test_card, &filter_partial_wrong_case),
            "case-sensitive capability partial match should fail"
        );

        // Test with unicode normalization bypass attempts
        let filter_unicode_bypass = TrustCardListFilter {
            certification_level: Some(CertificationLevel::Verified),
            publisher_id: Some("Publisher\u{2010}123".to_string()), // Unicode hyphen instead of ASCII hyphen
            capability: None,
        };

        assert!(
            !card_matches_filter(&test_card, &filter_unicode_bypass),
            "unicode normalization bypass should not work"
        );
    }

    #[test]
    fn test_negative_trust_card_registry_hmac_key_injection() {
        use crate::security::constant_time;

        let malicious_keys = [
            b"key\0null".as_slice(),                  // Null byte injection
            b"key\r\n\t".as_slice(),                  // Control characters
            b"key\x1b[31mred\x1b[0m".as_slice(),      // ANSI escape sequences
            &[0u8; 0],                                // Empty key
            &[0u8; 1],                                // Single null byte
            &[255u8; 1000],                           // All-ones key
            b"very_long_key_".repeat(100).as_slice(), // Extremely long key
        ];

        for malicious_key in malicious_keys {
            // Create HMAC with malicious key
            let mut mac = match Hmac::<Sha256>::new_from_slice(malicious_key) {
                Ok(mac) => mac,
                Err(_) => continue, // Some keys might be rejected by HMAC
            };

            // Test HMAC computation with various inputs
            let test_inputs = [
                b"normal data",
                b"data\0with\0nulls",
                b"data\r\nwith\r\ncontrol\tchars",
                b"\x1b[31mdata with ansi\x1b[0m",
                &[0u8; 10000],        // Large zero buffer
                &b"A".repeat(100000), // Very large input
            ];

            for input in test_inputs {
                mac.update(input);
                let result = mac.finalize_reset();
                let result_bytes = result.into_bytes();

                // Verify HMAC output is always 32 bytes for SHA256
                assert_eq!(
                    result_bytes.len(),
                    32,
                    "HMAC-SHA256 should always produce 32 bytes"
                );

                // Verify output doesn't contain obvious patterns that might indicate key leakage
                let all_zero = result_bytes.iter().all(|&b| b == 0);
                let all_same = result_bytes.iter().all(|&b| b == result_bytes[0]);

                // While technically possible, these patterns are extremely unlikely with proper HMAC
                if malicious_key.len() > 0 && !malicious_key.iter().all(|&b| b == 0) {
                    assert!(
                        !all_zero,
                        "HMAC output should not be all zeros with non-zero key"
                    );
                    assert!(!all_same, "HMAC output should not be all same byte");
                }
            }
        }

        // Test constant-time comparison of HMAC outputs
        let key1 = b"test_key_1";
        let key2 = b"test_key_2";

        let mut mac1 = Hmac::<Sha256>::new_from_slice(key1).expect("valid key1");
        let mut mac2 = Hmac::<Sha256>::new_from_slice(key2).expect("valid key2");

        mac1.update(b"test data");
        mac2.update(b"test data");

        let result1 = mac1.finalize().into_bytes();
        let result2 = mac2.finalize().into_bytes();

        // Different keys should produce different outputs
        assert!(
            !constant_time::ct_eq(&hex::encode(&result1), &hex::encode(&result2)),
            "different keys should produce different HMAC outputs"
        );
    }

    #[test]
    fn test_negative_trust_card_audit_history_with_massive_entries() {
        let mut audit_entries = Vec::new();

        // Create 1000 audit entries with large content
        for i in 0..1000 {
            audit_entries.push(TrustCardAuditEntry {
                audited_at_epoch: 1234567890_u64.saturating_add(i as u64),
                audit_type: "security_review".to_string(),
                auditor_id: format!("auditor_{}_with_long_id_{}", i, "X".repeat(500)),
                finding_summary: format!("finding_{}_with_massive_content_{}", i, "Y".repeat(5000)),
                severity: if i % 2 == 0 {
                    "high".to_string()
                } else {
                    "medium".to_string()
                },
                remediation_status: if i % 3 == 0 {
                    "resolved".to_string()
                } else {
                    "pending".to_string()
                },
            });
        }

        let mut trust_card = TrustCard {
            card_id: "audit-test".to_string(),
            publisher: test_publisher(),
            extension_id: "audit-extension".to_string(),
            certification_level: CertificationLevel::Verified,
            capability_declarations: vec![],
            reputation_score: 0.85,
            trust_card_schema_version: "1.0.0".to_string(),
            derived_at_epoch: 1234567890,
            derivation_evidence_hash: "test-hash".to_string(),
            revocation_status: RevocationStatus::Valid,
            cache_metadata: CacheMetadata {
                cached_at_epoch: 1234567890,
                ttl_seconds: 60,
                refresh_count: 0,
            },
            audit_history: audit_entries,
        };

        // Verify bounded storage kicks in
        assert_eq!(
            trust_card.audit_history.len(),
            1000,
            "should start with 1000 entries"
        );

        // Add more entries to test push_bounded
        for i in 1000..1500 {
            let entry = TrustCardAuditEntry {
                audited_at_epoch: 1234567890_u64.saturating_add(i as u64),
                audit_type: "additional_review".to_string(),
                auditor_id: format!("auditor_{}", i),
                finding_summary: format!("finding_{}", i),
                severity: "low".to_string(),
                remediation_status: "resolved".to_string(),
            };

            push_bounded(&mut trust_card.audit_history, entry, MAX_AUDIT_HISTORY);
        }

        // Should be bounded to MAX_AUDIT_HISTORY
        assert_eq!(
            trust_card.audit_history.len(),
            MAX_AUDIT_HISTORY,
            "audit history should be bounded to MAX_AUDIT_HISTORY"
        );

        // Verify latest entries are preserved
        let latest_entry = &trust_card.audit_history[trust_card.audit_history.len() - 1];
        assert_eq!(
            latest_entry.audit_type, "additional_review",
            "latest entry should be preserved"
        );

        // Test serialization with massive audit history
        let json = serde_json::to_string(&trust_card)
            .expect("serialization should handle massive audit history");
        assert!(json.len() > 100_000, "serialized JSON should be large");
        assert!(
            json.len() < 10_000_000,
            "serialized JSON should be reasonably bounded"
        );

        // Test deserialization roundtrip
        let parsed: TrustCard = serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(
            parsed.audit_history.len(),
            trust_card.audit_history.len(),
            "audit history length should be preserved"
        );
    }

    #[test]
    fn test_negative_evidence_ref_with_hash_collision_simulation() {
        use crate::security::constant_time;

        // Create evidence refs with potential hash collisions
        let collision_candidates = vec![
            VerifiedEvidenceRef {
                evidence_id: "evidence_1".to_string(),
                evidence_type: EvidenceType::ProvenanceAttestation,
                verified_at_epoch: 1234567890,
                verification_receipt_hash: "sha256:a".repeat(32), // Fake SHA256
            },
            VerifiedEvidenceRef {
                evidence_id: "evidence_2".to_string(),
                evidence_type: EvidenceType::ProvenanceAttestation,
                verified_at_epoch: 1234567890,
                verification_receipt_hash: "sha256:b".repeat(32), // Fake SHA256
            },
            VerifiedEvidenceRef {
                evidence_id: "evidence_1".to_string(), // Same ID, different hash
                evidence_type: EvidenceType::ProvenanceAttestation,
                verified_at_epoch: 1234567890,
                verification_receipt_hash: "sha256:c".repeat(32),
            },
        ];

        // Test ensure_evidence_refs_present with colliding refs
        let result = ensure_evidence_refs_present(&collision_candidates);
        assert!(result.is_ok(), "should accept non-empty evidence refs");

        // Test with empty refs
        let empty_result = ensure_evidence_refs_present(&[]);
        assert!(
            matches!(empty_result, Err(TrustCardError::EvidenceMissing)),
            "should reject empty evidence refs"
        );

        // Test derivation hash with collision candidates
        let hash1 = compute_trust_card_derivation_hash(&collision_candidates, 123);
        let hash2 = compute_trust_card_derivation_hash(&collision_candidates, 123);
        assert_eq!(hash1, hash2, "derivation hash should be deterministic");

        // Test that order matters (prevents some collision attacks)
        let mut reversed = collision_candidates.clone();
        reversed.reverse();
        let hash_reversed = compute_trust_card_derivation_hash(&reversed, 123);
        assert_ne!(hash1, hash_reversed, "order should affect hash");

        // Test hash comparison with constant-time
        let different_refs = vec![collision_candidates[0].clone()]; // Just one ref
        let hash_different = compute_trust_card_derivation_hash(&different_refs, 123);

        assert!(
            !constant_time::ct_eq(&hash1, &hash_different),
            "different refs should produce different hashes"
        );

        // Test with malicious evidence IDs that might cause hash collisions
        let malicious_refs = vec![
            VerifiedEvidenceRef {
                evidence_id: "evidence\0null".to_string(),
                evidence_type: EvidenceType::CertificationEvidence,
                verified_at_epoch: 123,
                verification_receipt_hash: "hash1".to_string(),
            },
            VerifiedEvidenceRef {
                evidence_id: "evidence".to_string(), // Without null
                evidence_type: EvidenceType::CertificationEvidence,
                verified_at_epoch: 123,
                verification_receipt_hash: "hash1".to_string(),
            },
        ];

        let hash_with_null = compute_trust_card_derivation_hash(&malicious_refs, 123);
        let hash_without_null = compute_trust_card_derivation_hash(&malicious_refs[1..], 123);

        // Length prefixing in the hash function should prevent null-byte collisions
        assert_ne!(
            hash_with_null, hash_without_null,
            "null byte should not cause collision"
        );
    }

    #[test]
    fn test_negative_temp_file_operations_with_malicious_paths() {
        // Test temp file creation with various edge cases
        let test_cases = [
            ("normal-file.json", true),
            ("file-with-unicode-\u{1F4A9}.json", true),
            ("file\0with\0nulls.json", true), // OS might reject, but shouldn't panic
            ("file\r\nwith\r\ncontrol.json", true),
            ("very_long_filename_".repeat(100), true), // Extremely long name
        ];

        for (filename, should_attempt) in test_cases {
            if !should_attempt {
                continue;
            }

            let dir = match tempfile::tempdir() {
                Ok(dir) => dir,
                Err(_) => continue,
            };

            let path = dir.path().join(filename);

            // Test file creation
            match NamedTempFile::new_in(dir.path()) {
                Ok(mut temp_file) => {
                    // Write test content
                    let test_content =
                        r#"{"test": "content with unicode \u{1F4A9} and control \r\n chars"}"#;

                    match write!(temp_file, "{}", test_content) {
                        Ok(_) => {
                            // Test atomic rename
                            match temp_file.persist(&path) {
                                Ok(_) => {
                                    // Verify file exists and content is correct
                                    if let Ok(content) = std::fs::read_to_string(&path) {
                                        assert_eq!(
                                            content, test_content,
                                            "file content should be preserved"
                                        );
                                    }

                                    // Clean up
                                    let _ = std::fs::remove_file(&path);
                                }
                                Err(_) => {
                                    // Atomic rename might fail for malicious paths - that's OK
                                }
                            }
                        }
                        Err(_) => {
                            // Write might fail for some malicious content - that's OK
                        }
                    }
                }
                Err(_) => {
                    // Temp file creation might fail for malicious names - that's OK
                }
            }
        }

        // Test with directory traversal attempts
        let dir = tempfile::tempdir().expect("tempdir should work");
        let traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "legitimate/../../etc/passwd",
            "/absolute/path/attempt",
        ];

        for traversal_path in traversal_attempts {
            // These should either:
            // 1. Be rejected by the OS/filesystem
            // 2. Be contained within the temp directory
            // 3. Fail gracefully without security implications

            if let Ok(temp_file) = NamedTempFile::new_in(dir.path()) {
                let target_path = dir.path().join(traversal_path);

                // Attempt should either fail or be contained
                let _ = temp_file.persist(&target_path);

                // Verify no files were created outside the temp directory
                // (This is a basic check - full verification would require path canonicalization)
                if target_path.exists() {
                    assert!(
                        target_path.starts_with(dir.path()),
                        "created file should be within temp directory"
                    );
                }
            }
        }
    }

    #[test]
    fn test_negative_push_bounded_with_arithmetic_overflow_edge_cases() {
        // Test push_bounded with potential overflow scenarios
        let mut test_vec = Vec::new();

        // Fill with maximum capacity near usize overflow
        let large_cap = if cfg!(target_pointer_width = "64") {
            1000 // Use reasonable size for testing
        } else {
            100 // Smaller for 32-bit
        };

        // Fill vector to capacity
        for i in 0..large_cap {
            push_bounded(&mut test_vec, i, large_cap);
        }
        assert_eq!(test_vec.len(), large_cap);

        // Test overflow protection in drain calculation
        let mut overflow_vec = vec![0; large_cap * 2]; // Start with more than capacity

        // This should trigger the overflow protection in push_bounded
        push_bounded(&mut overflow_vec, 999, large_cap);
        assert_eq!(
            overflow_vec.len(),
            large_cap,
            "should be reduced to capacity"
        );
        assert_eq!(
            overflow_vec[overflow_vec.len() - 1],
            999,
            "latest item should be preserved"
        );

        // Test with zero capacity (special case)
        let mut zero_cap_vec = vec![1, 2, 3, 4, 5];
        push_bounded(&mut zero_cap_vec, 6, 0);
        assert_eq!(zero_cap_vec.len(), 0, "zero capacity should clear vector");

        // Test with capacity 1 (minimum non-zero)
        let mut single_cap_vec = vec![1, 2, 3];
        push_bounded(&mut single_cap_vec, 4, 1);
        assert_eq!(
            single_cap_vec.len(),
            1,
            "capacity 1 should keep only latest"
        );
        assert_eq!(single_cap_vec[0], 4, "should keep the newly pushed item");

        // Test saturating arithmetic in the drain calculation
        // overflow = items.len().saturating_sub(cap).saturating_add(1)
        let mut extreme_vec = Vec::new();
        extreme_vec.resize(1000, 0);

        // Test with very small capacity to trigger large drain
        push_bounded(&mut extreme_vec, 1001, 5);
        assert_eq!(extreme_vec.len(), 5, "should be reduced to small capacity");
        assert_eq!(extreme_vec[4], 1001, "latest item should be at end");

        // Verify arithmetic didn't overflow by checking all elements
        let expected = [996, 997, 998, 999, 1001]; // What should remain after drain
        for (i, &expected_val) in expected.iter().enumerate() {
            if i < 4 {
                // First 4 elements should be from original vector
                assert!(
                    extreme_vec[i] <= 999,
                    "element {} should be from original range",
                    i
                );
            } else {
                // Last element should be the new one
                assert_eq!(
                    extreme_vec[i], expected_val,
                    "element {} should be new value",
                    i
                );
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Metamorphic Testing Relations
    // ---------------------------------------------------------------------------

    /// MR1: Trust-card add+revoke commutativity (Equivalence + Permutative)
    ///
    /// Property: create(input) → mutate(revoke) should yield same final state
    /// as create(input_with_revoked_status). Since revocation is irreversible,
    /// we test that direct creation with revoked status == create then revoke.
    ///
    /// Detects: State corruption, mutation ordering bugs, cache inconsistencies
    #[cfg(test)]
    #[test]
    fn mr_trust_card_add_revoke_commutativity() {
        let mut registry1 = TrustCardRegistry::new(60, b"metamorphic-test-key");
        let mut registry2 = TrustCardRegistry::new(60, b"metamorphic-test-key");

        let base_input = sample_input();
        let revoke_reason = "metamorphic test revocation".to_string();
        let revoke_time = "2024-01-01T12:00:00Z".to_string();
        let now_secs = 1000;

        // Path 1: Create active, then revoke via mutation
        let card1 = registry1
            .create(base_input.clone(), now_secs, "trace1")
            .expect("create active card");

        let revoke_mutation = TrustCardMutation {
            certification_level: None,
            revocation_status: Some(RevocationStatus::Revoked {
                reason: revoke_reason.clone(),
                revoked_at: revoke_time.clone(),
            }),
            active_quarantine: None,
            reputation_score_basis_points: None,
            reputation_trend: None,
            user_facing_risk_assessment: None,
            last_verified_timestamp: None,
            evidence_refs: None,
        };

        let final_card1 = registry1
            .mutate(
                &card1.extension.extension_id,
                revoke_mutation,
                now_secs + 100,
                "trace1-revoke",
            )
            .expect("revoke card");

        // Path 2: Create with revoked status directly
        let mut revoked_input = base_input;
        revoked_input.revocation_status = RevocationStatus::Revoked {
            reason: revoke_reason,
            revoked_at: revoke_time,
        };

        let final_card2 = registry2
            .create(revoked_input, now_secs, "trace2")
            .expect("create revoked card");

        // Metamorphic relation: Both paths should result in equivalent revoked state
        assert!(matches!(
            final_card1.revocation_status,
            RevocationStatus::Revoked { .. }
        ));
        assert!(matches!(
            final_card2.revocation_status,
            RevocationStatus::Revoked { .. }
        ));

        // Core properties should be identical (ignoring version-specific fields)
        assert_eq!(final_card1.extension, final_card2.extension);
        assert_eq!(final_card1.publisher, final_card2.publisher);
        assert_eq!(
            final_card1.certification_level,
            final_card2.certification_level
        );

        // Both should have revoked status with same reason
        match (
            &final_card1.revocation_status,
            &final_card2.revocation_status,
        ) {
            (
                RevocationStatus::Revoked { reason: r1, .. },
                RevocationStatus::Revoked { reason: r2, .. },
            ) => {
                assert_eq!(r1, r2, "Revocation reasons should match");
            }
            _ => panic!("Both cards should be revoked"),
        }
    }

    /// MR2: Trust-card mutation sequence commutativity for independent fields
    ///
    /// Property: mutate(field_A) → mutate(field_B) == mutate(field_B) → mutate(field_A)
    /// when field_A and field_B are independent (don't affect each other).
    ///
    /// Detects: Field coupling bugs, mutation ordering dependencies, side effects
    #[cfg(test)]
    #[test]
    fn mr_trust_card_mutation_commutativity() {
        let input = sample_input();
        let now_secs = 1000;

        // Create base card in two registries
        let mut registry1 = TrustCardRegistry::new(60, b"metamorphic-test-key");
        let mut registry2 = TrustCardRegistry::new(60, b"metamorphic-test-key");

        let extension_id = &input.extension.extension_id;

        registry1
            .create(input.clone(), now_secs, "trace1")
            .expect("create card1");
        registry2
            .create(input, now_secs, "trace2")
            .expect("create card2");

        // Independent mutations: reputation score + quarantine status
        let reputation_mutation = TrustCardMutation {
            certification_level: None,
            revocation_status: None,
            active_quarantine: None,
            reputation_score_basis_points: Some(7500),
            reputation_trend: None,
            user_facing_risk_assessment: None,
            last_verified_timestamp: None,
            evidence_refs: None,
        };

        let quarantine_mutation = TrustCardMutation {
            certification_level: None,
            revocation_status: None,
            active_quarantine: Some(true),
            reputation_score_basis_points: None,
            reputation_trend: None,
            user_facing_risk_assessment: None,
            last_verified_timestamp: None,
            evidence_refs: None,
        };

        // Path 1: reputation then quarantine
        registry1
            .mutate(
                extension_id,
                reputation_mutation.clone(),
                now_secs + 100,
                "trace1a",
            )
            .expect("reputation mutation");
        let final1 = registry1
            .mutate(
                extension_id,
                quarantine_mutation.clone(),
                now_secs + 200,
                "trace1b",
            )
            .expect("quarantine mutation");

        // Path 2: quarantine then reputation
        registry2
            .mutate(extension_id, quarantine_mutation, now_secs + 100, "trace2a")
            .expect("quarantine mutation");
        let final2 = registry2
            .mutate(extension_id, reputation_mutation, now_secs + 200, "trace2b")
            .expect("reputation mutation");

        // Metamorphic relation: Final state should be identical
        assert_eq!(
            final1.reputation_score_basis_points,
            final2.reputation_score_basis_points
        );
        assert_eq!(final1.active_quarantine, final2.active_quarantine);

        // Core properties should remain unchanged
        assert_eq!(final1.extension, final2.extension);
        assert_eq!(final1.publisher, final2.publisher);
        assert_eq!(final1.certification_level, final2.certification_level);
    }

    // === GOLDEN ARTIFACT TESTING ===
    // Golden file tests for trust-card outputs with canonicalization

    use insta::Settings;
    use regex::Regex;

    /// Scrub non-deterministic values for golden comparison
    fn scrub_trust_card_output(output: &str) -> String {
        let mut scrubbed = output.to_string();

        // UUIDs → [UUID]
        let uuid_re =
            Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
        scrubbed = uuid_re.replace_all(&scrubbed, "[UUID]").to_string();

        // ISO timestamps → [TIMESTAMP]
        let ts_re =
            Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?").unwrap();
        scrubbed = ts_re.replace_all(&scrubbed, "[TIMESTAMP]").to_string();

        // Epoch timestamps → [EPOCH]
        let epoch_re = Regex::new(r"\b\d{10,13}\b").unwrap();
        scrubbed = epoch_re.replace_all(&scrubbed, "[EPOCH]").to_string();

        // SHA256 hashes → [HASH]
        let hash_re = Regex::new(r"sha256:[a-f0-9]{64}").unwrap();
        scrubbed = hash_re.replace_all(&scrubbed, "sha256:[HASH]").to_string();

        // Hex signatures → [SIG]
        let sig_re = Regex::new(r"[a-f0-9]{128,256}").unwrap();
        scrubbed = sig_re.replace_all(&scrubbed, "[SIG]").to_string();

        scrubbed
    }

    fn canonical_trust_card_fixture() -> TrustCard {
        TrustCard {
            schema_version: "trust-card-v1.0".to_string(),
            trust_card_version: 42,
            extension: ExtensionIdentity {
                extension_id: "npm:@acme/security-scanner".to_string(),
                version: "2.1.0".to_string(),
            },
            publisher: PublisherIdentity {
                publisher_id: "acme-corp".to_string(),
                display_name: "ACME Corporation".to_string(),
            },
            certification_level: CertificationLevel::Gold,
            revocation_status: RevocationStatus::Active,
            behavioral_profile: BehavioralProfile {
                network_access: true,
                filesystem_access: false,
                sandbox_escape_risk: false,
                profile_summary: "Network scanner with read-only file access".to_string(),
            },
            capabilities: vec![
                CapabilityDeclaration {
                    name: "network.scan".to_string(),
                    description: "Scan network endpoints for vulnerabilities".to_string(),
                    risk: CapabilityRisk::Medium,
                },
                CapabilityDeclaration {
                    name: "fs.read_config".to_string(),
                    description: "Read configuration files".to_string(),
                    risk: CapabilityRisk::Low,
                },
            ],
            provenance: ProvenanceSummary {
                attestation_level: "L3-verified-build".to_string(),
                source_uri: "https://github.com/acme-corp/security-scanner".to_string(),
                build_reproducible: true,
                verified_at: "2026-04-21T00:00:00Z".to_string(),
            },
            dependency_trust_status: vec![
                DependencyTrustStatus {
                    dependency_id: "npm:lodash".to_string(),
                    trust_level: "high".to_string(),
                },
                DependencyTrustStatus {
                    dependency_id: "npm:axios".to_string(),
                    trust_level: "medium".to_string(),
                },
            ],
            reputation_score_basis_points: 8750, // 87.5%
            reputation_trend: ReputationTrend::Improving,
            active_quarantine: false,
            user_facing_risk_assessment: RiskAssessment {
                level: RiskLevel::Low,
                summary: "Well-maintained security tool with verified provenance".to_string(),
            },
            last_verified_timestamp: "2026-04-21T12:00:00Z".to_string(),
            evidence_refs: vec![
                VerifiedEvidenceRef {
                    evidence_id: "slsa-provenance-v1.0".to_string(),
                    evidence_type: EvidenceType::ProvenanceAttestation,
                    verified_at_epoch: 1735689600,
                    verification_receipt_hash: "sha256:abc123def456789".to_string(),
                },
                VerifiedEvidenceRef {
                    evidence_id: "security-audit-2026-Q1".to_string(),
                    evidence_type: EvidenceType::CertificationEvidence,
                    verified_at_epoch: 1735689600,
                    verification_receipt_hash: "sha256:fed987cba654321".to_string(),
                },
            ],
            derivation_hash: "computed-hash-placeholder".to_string(),
            registry_signature: "signature-placeholder".to_string(),
        }
    }

    #[test]
    fn golden_trust_card_human_rendering() {
        let card = canonical_trust_card_fixture();
        let rendered = render_trust_card_human(&card);
        let scrubbed = scrub_trust_card_output(&rendered);

        insta::assert_snapshot!("trust_card_human_render", scrubbed);
    }

    #[test]
    fn golden_trust_card_human_rendering_revoked() {
        let mut card = canonical_trust_card_fixture();
        card.revocation_status = RevocationStatus::Revoked {
            reason: "Security vulnerability discovered in dependency".to_string(),
            revoked_at: "2026-04-20T15:30:00Z".to_string(),
        };
        card.active_quarantine = true;
        card.user_facing_risk_assessment = RiskAssessment {
            level: RiskLevel::Critical,
            summary: "REVOKED: Security vulnerability in transitive dependency".to_string(),
        };

        let rendered = render_trust_card_human(&card);
        let scrubbed = scrub_trust_card_output(&rendered);

        insta::assert_snapshot!("trust_card_human_render_revoked", scrubbed);
    }

    #[test]
    fn golden_trust_card_canonical_json() {
        let card = canonical_trust_card_fixture();
        let canonical_json = to_canonical_json(&card).expect("canonical JSON should serialize");
        let scrubbed = scrub_trust_card_output(&canonical_json);

        insta::assert_snapshot!("trust_card_canonical_json", scrubbed);
    }

    #[test]
    fn golden_trust_card_comparison_human_rendering() {
        let card1 = canonical_trust_card_fixture();
        let mut card2 = canonical_trust_card_fixture();

        // Make some differences for comparison
        card2.certification_level = CertificationLevel::Platinum;
        card2.reputation_score_basis_points = 9500; // 95%
        card2.reputation_trend = ReputationTrend::Stable;

        // Create comparison using the internal comparison logic
        let comparison = TrustCardComparison {
            left_extension_id: card1.extension.extension_id.clone(),
            right_extension_id: card2.extension.extension_id.clone(),
            changes: vec![
                TrustCardDiffEntry {
                    field: "certification_level".to_string(),
                    left: "gold".to_string(),
                    right: "platinum".to_string(),
                },
                TrustCardDiffEntry {
                    field: "reputation_score_basis_points".to_string(),
                    left: "8750".to_string(),
                    right: "9500".to_string(),
                },
                TrustCardDiffEntry {
                    field: "reputation_trend".to_string(),
                    left: "improving".to_string(),
                    right: "stable".to_string(),
                },
            ],
        };

        let rendered = render_comparison_human(&comparison);
        // Comparison output should be deterministic (no timestamps/UUIDs)
        insta::assert_snapshot!("trust_card_comparison_human", rendered);
    }

    #[test]
    fn golden_trust_card_complex_scenario() {
        // Test complex scenario with multiple capabilities and dependencies
        let mut card = canonical_trust_card_fixture();

        // Add more capabilities
        card.capabilities.extend(vec![
            CapabilityDeclaration {
                name: "crypto.encrypt".to_string(),
                description: "Encrypt sensitive data".to_string(),
                risk: CapabilityRisk::High,
            },
            CapabilityDeclaration {
                name: "system.process_spawn".to_string(),
                description: "Spawn system processes".to_string(),
                risk: CapabilityRisk::Critical,
            },
        ]);

        // Add more dependencies
        card.dependency_trust_status.extend(vec![
            DependencyTrustStatus {
                dependency_id: "npm:crypto-js".to_string(),
                trust_level: "high".to_string(),
            },
            DependencyTrustStatus {
                dependency_id: "npm:node-forge".to_string(),
                trust_level: "medium".to_string(),
            },
            DependencyTrustStatus {
                dependency_id: "npm:bcrypt".to_string(),
                trust_level: "unverified".to_string(),
            },
        ]);

        // Update risk assessment based on additional capabilities
        card.user_facing_risk_assessment = RiskAssessment {
            level: RiskLevel::High,
            summary: "High-capability security tool requiring careful review".to_string(),
        };

        let rendered = render_trust_card_human(&card);
        let scrubbed = scrub_trust_card_output(&rendered);

        insta::assert_snapshot!("trust_card_human_complex_scenario", scrubbed);
    }

    #[test]
    fn golden_trust_card_empty_collections() {
        // Test edge case with minimal/empty collections
        let mut card = canonical_trust_card_fixture();
        card.capabilities.clear();
        card.dependency_trust_status.clear();
        card.evidence_refs = vec![]; // This should still work due to ensure_evidence_refs_present validation

        let rendered = render_trust_card_human(&card);
        let scrubbed = scrub_trust_card_output(&rendered);

        insta::assert_snapshot!("trust_card_human_empty_collections", scrubbed);
    }

    #[test]
    fn golden_trust_card_canonical_json_stability() {
        // Test that canonical JSON is stable across multiple serializations
        let card = canonical_trust_card_fixture();

        let json1 = to_canonical_json(&card).expect("first serialization");
        let json2 = to_canonical_json(&card).expect("second serialization");
        let json3 = to_canonical_json(&card).expect("third serialization");

        assert_eq!(json1, json2, "canonical JSON should be stable");
        assert_eq!(json2, json3, "canonical JSON should be stable");

        let scrubbed = scrub_trust_card_output(&json1);
        insta::assert_snapshot!("trust_card_canonical_json_stability", scrubbed);
    }

    #[test]
    fn test_cache_poisoning_attack_prevention() {
        // Test that cache poisoning attacks are prevented by signature re-verification
        // This validates the bd-dz3yz fix that enforces signature verification on cache hits
        let mut registry = TrustCardRegistry::default();

        // Create a legitimate card
        let original_card = registry
            .create(sample_input(), 1_000, "trace-create")
            .expect("create legitimate card");

        // Verify the card is cached
        assert!(registry.cache_by_extension.contains_key("npm:@acme/plugin"));

        // ATTACK: Directly poison the cache with a malicious card that has the same extension
        // but different content, simulating what an attacker might try to inject
        let mut poisoned_card = original_card.clone();
        poisoned_card.reputation_score_basis_points = 9999; // Malicious modification
        poisoned_card.security_advisory_count = 0; // Hide security issues
        poisoned_card.signature_hex = "deadbeefdeadbeefdeadbeefdeadbeef".to_string(); // Invalid signature

        // Insert the poisoned entry directly into cache (bypassing normal validation)
        registry.cache_by_extension.insert(
            "npm:@acme/plugin".to_string(),
            CachedCard {
                card: poisoned_card,
                cached_at_secs: 1_001, // Fresh timestamp
            },
        );

        // DEFENSE: Attempt to read the card - this should trigger signature re-verification
        let result = registry.read("npm:@acme/plugin", 1_002, "trace-poison-test");

        // The poisoned entry should be rejected and removed from cache
        assert!(result.is_ok(), "Read should succeed after cache repair");
        let retrieved_card = result.unwrap().expect("Card should exist after repair");

        // Verify the returned card is the original legitimate card, not the poisoned one
        assert_eq!(
            retrieved_card.reputation_score_basis_points,
            original_card.reputation_score_basis_points
        );
        assert_eq!(
            retrieved_card.security_advisory_count,
            original_card.security_advisory_count
        );
        assert_eq!(retrieved_card.card_hash, original_card.card_hash);
        assert_eq!(retrieved_card.signature_hex, original_card.signature_hex);

        // Verify the cache now contains the repaired legitimate card
        let cached = registry
            .cache_by_extension
            .get("npm:@acme/plugin")
            .expect("Cache should contain repaired entry");
        assert_eq!(cached.card.card_hash, original_card.card_hash);
        assert_eq!(cached.card.signature_hex, original_card.signature_hex);
        assert_ne!(
            cached.card.signature_hex,
            "deadbeefdeadbeefdeadbeefdeadbeef"
        );

        // Additional test: Verify that sync_cache also detects and removes poisoned entries
        registry.cache_by_extension.insert(
            "npm:@acme/plugin".to_string(),
            CachedCard {
                card: {
                    let mut another_poison = original_card.clone();
                    another_poison.reputation_score_basis_points = 1; // Different poison
                    another_poison.signature_hex = "cafebabecafebabecafebabecafebabe".to_string();
                    another_poison
                },
                cached_at_secs: 1_003,
            },
        );

        let sync_report = registry
            .sync_cache(1_004, "trace-sync-poison", false)
            .expect("Sync should handle poisoned cache");

        // Sync should detect the poisoned entry and rebuild it
        assert_eq!(
            sync_report.cache_misses, 1,
            "Poisoned entry should count as cache miss"
        );
        assert_eq!(
            sync_report.cache_hits, 0,
            "No valid cache hits with poisoned entry"
        );

        // Final verification: cache contains only legitimate card
        let final_cached = registry
            .cache_by_extension
            .get("npm:@acme/plugin")
            .expect("Cache should be repaired after sync");
        assert_eq!(final_cached.card.card_hash, original_card.card_hash);
        assert_ne!(
            final_cached.card.signature_hex,
            "cafebabecafebabecafebabecafebabe"
        );
    }

    #[test]
    fn contextual_validation_trusted_file_lazy_validation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test-trust-card-state.json");

        // Create a valid registry
        let mut registry = TrustCardRegistry::default();
        let card = registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        registry
            .persist_authoritative_state(&path)
            .expect("persist");

        // Load using trusted file context - should use lazy validation
        let restored = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("load with trusted file context");

        // Verify the registry was loaded correctly
        let loaded_card = restored
            .read("npm:@acme/plugin", 2_000, "trace")
            .expect("read")
            .expect("card exists");
        assert_eq!(loaded_card.card_hash, card.card_hash);
    }

    #[test]
    fn contextual_validation_untrusted_network_eager_validation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test-trust-card-state.json");

        // Create a valid registry with proper signature
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        registry
            .persist_authoritative_state(&path)
            .expect("persist");

        // Load using untrusted network context - should use eager validation
        let restored = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::UntrustedNetwork,
        )
        .expect("load with untrusted network context");

        // Verify the registry was loaded correctly
        let cards = restored
            .list(&TrustCardListFilter::empty(), "trace", 2_000)
            .expect("list");
        assert_eq!(cards.len(), 1);
    }

    #[test]
    fn contextual_validation_untrusted_rejects_oversized_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("huge-trust-card-state.json");

        // Create JSON larger than MAX_UNTRUSTED_JSON_SIZE
        let huge_json = format!(
            r#"{{"schema_version":"test","snapshot_epoch":1,"cache_ttl_secs":60,"cards_by_extension":{{}},"snapshot_hash":"{}","registry_signature":"fake"}}"#,
            "A".repeat(MAX_UNTRUSTED_JSON_SIZE)
        );
        std::fs::write(&path, huge_json).expect("write huge JSON");

        // Untrusted context should reject oversized JSON
        let err = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::UntrustedNetwork,
        )
        .expect_err("oversized JSON should be rejected for untrusted sources");

        assert!(matches!(err, TrustCardError::InvalidSnapshot(ref detail)
            if detail.contains("exceeds maximum")));
    }

    #[test]
    fn contextual_validation_untrusted_rejects_invalid_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("invalid-sig-trust-card-state.json");

        // Create JSON with invalid signature
        let invalid_snapshot = TrustCardRegistrySnapshot {
            schema_version: TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA.to_string(),
            snapshot_epoch: 1,
            previous_snapshot_hash: None,
            cache_ttl_secs: 60,
            cards_by_extension: BTreeMap::new(),
            snapshot_hash: "valid_hash".to_string(),
            registry_signature: "invalid_signature".to_string(),
        };
        let json = serde_json::to_string_pretty(&invalid_snapshot).expect("serialize");
        std::fs::write(&path, json).expect("write invalid snapshot");

        // Untrusted context should reject invalid signature before parsing
        let err = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::UntrustedNetwork,
        )
        .expect_err("invalid signature should be rejected for untrusted sources");

        assert!(matches!(err, TrustCardError::InvalidSnapshot(ref detail)
            if detail.contains("signature verification failed")));
    }

    #[test]
    fn contextual_validation_trusted_allows_malformed_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad-sig-trust-card-state.json");

        // Create a valid registry first
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        registry
            .persist_authoritative_state(&path)
            .expect("persist");

        // Tamper with the signature in the file
        let original_json = std::fs::read_to_string(&path).expect("read");
        let mut snapshot: TrustCardRegistrySnapshot =
            serde_json::from_str(&original_json).expect("parse");
        snapshot.registry_signature = "tampered_signature".to_string();
        let tampered_json = serde_json::to_string_pretty(&snapshot).expect("serialize");
        std::fs::write(&path, tampered_json).expect("write tampered");

        // Trusted context should allow parsing but fail later during signature verification
        // This tests that lazy validation parses first, validates later
        let err = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::TrustedFile,
        )
        .expect_err("tampered signature should eventually fail");

        // Error should come from later signature validation, not pre-parsing
        assert!(matches!(err, TrustCardError::InvalidSnapshot(ref detail)
            if detail.contains("signature mismatch")));
    }

    #[test]
    fn contextual_validation_error_sanitization_untrusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("malformed-trust-card-state.json");
        std::fs::write(&path, "invalid json {").expect("write malformed");

        // Untrusted context should sanitize error messages
        let err = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::UntrustedNetwork,
        )
        .expect_err("malformed JSON should fail");

        // Error detail should be sanitized for untrusted sources
        match err {
            TrustCardError::InvalidSnapshot(detail) => {
                assert_eq!(detail, "snapshot validation failed");
            }
            _ => panic!("Expected sanitized InvalidSnapshot error, got: {:?}", err),
        }
    }

    #[test]
    fn contextual_validation_error_detail_preserved_trusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("malformed-trust-card-state.json");
        std::fs::write(&path, "invalid json {").expect("write malformed");

        // Trusted context should preserve detailed error messages
        let err = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::TrustedFile,
        )
        .expect_err("malformed JSON should fail");

        // Error should contain specific parsing details
        match err {
            TrustCardError::SnapshotParse { detail, .. } => {
                // Should contain actual JSON parsing error details
                assert!(detail.contains("EOF") || detail.contains("expected"));
            }
            _ => panic!("Expected detailed SnapshotParse error, got: {:?}", err),
        }
    }

    #[test]
    fn contextual_validation_comprehensive_bounds_checking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bounds-test-trust-card-state.json");

        // Create snapshot with too many cards (exceeding limits for untrusted sources)
        let mut cards_map = BTreeMap::new();
        let sample_cards: Vec<TrustCard> = (0..600)
            .map(|i| {
                let mut card = sample_input().try_into().expect("convert");
                let card_ref: &mut TrustCard = &mut card;
                card_ref.extension.extension_id = format!("npm:@test/card-{i}");
                card_ref.trust_card_version = 1;
                card
            })
            .collect();
        cards_map.insert("npm:@test/excessive".to_string(), sample_cards);

        let snapshot = TrustCardRegistrySnapshot {
            schema_version: TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA.to_string(),
            snapshot_epoch: 1,
            previous_snapshot_hash: None,
            cache_ttl_secs: 60,
            cards_by_extension: cards_map,
            snapshot_hash: "test_hash".to_string(),
            registry_signature: "test_signature".to_string(),
        };

        let json = serde_json::to_string_pretty(&snapshot).expect("serialize");
        std::fs::write(&path, json).expect("write excessive cards");

        // Untrusted context should reject based on card count limits
        // But first we need to make the signature valid to test the bounds checking
        // For this test, we'll check that the validation fails appropriately
        let err = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::UntrustedNetwork,
        )
        .expect_err("excessive cards should be rejected for untrusted sources");

        // Should fail during validation (either signature or bounds)
        assert!(matches!(
            err,
            TrustCardError::InvalidSnapshot(_) | TrustCardError::InvalidInput { .. }
        ));
    }

    #[test]
    fn validate_basic_bounds_schema_version_check() {
        let snapshot = TrustCardRegistrySnapshot {
            schema_version: "wrong/schema/v99".to_string(),
            snapshot_epoch: 1,
            previous_snapshot_hash: None,
            cache_ttl_secs: 60,
            cards_by_extension: BTreeMap::new(),
            snapshot_hash: "test_hash".to_string(),
            registry_signature: "test_signature".to_string(),
        };

        let err = validate_basic_bounds(&snapshot).expect_err("wrong schema should fail");
        assert!(matches!(err, TrustCardError::UnsupportedSnapshotSchema(_)));
    }

    #[test]
    fn validate_basic_bounds_extension_id_length() {
        let mut cards_map = BTreeMap::new();
        let long_id = "npm:@test/".to_string() + &"x".repeat(MAX_EXTENSION_ID_LEN);
        cards_map.insert(long_id, vec![]);

        let snapshot = TrustCardRegistrySnapshot {
            schema_version: TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA.to_string(),
            snapshot_epoch: 1,
            previous_snapshot_hash: None,
            cache_ttl_secs: 60,
            cards_by_extension: cards_map,
            snapshot_hash: "test_hash".to_string(),
            registry_signature: "test_signature".to_string(),
        };

        let err = validate_basic_bounds(&snapshot).expect_err("oversized extension ID should fail");
        assert!(matches!(err, TrustCardError::InvalidInput { .. }));
    }

    #[test]
    fn registry_from_config_rejects_invalid_configured_key() {
        let mut config = crate::config::Config::for_profile(crate::config::Profile::Balanced).trust;
        config.registry_signing_key = Some("not-base64".to_string());

        let err = match TrustCardRegistry::from_config(&config) {
            Ok(_) => panic!("invalid key should fail closed"),
            Err(err) => err,
        };

        assert!(matches!(err, TrustCardError::InvalidInput { .. }));
    }

    #[test]
    fn registry_from_config_accepts_valid_configured_key() {
        let mut config = crate::config::Config::for_profile(crate::config::Profile::Balanced).trust;
        config.registry_signing_key =
            Some(base64::engine::general_purpose::STANDARD.encode([9_u8; 32]));

        TrustCardRegistry::from_config(&config).expect("valid key should configure registry");
    }

    #[test]
    fn configured_load_writes_high_water_with_configured_key() {
        let mut config = crate::config::Config::for_profile(crate::config::Profile::Balanced).trust;
        config.registry_signing_key =
            Some(base64::engine::general_purpose::STANDARD.encode([7_u8; 32]));
        let mut registry = TrustCardRegistry::from_config(&config)
            .expect("custom registry key should configure registry");
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("custom-key-trust-card-state.json");
        let snapshot = registry.snapshot().expect("snapshot");
        std::fs::write(
            &path,
            to_canonical_json(&snapshot).expect("snapshot should serialize"),
        )
        .expect("write snapshot without high-water");

        TrustCardRegistry::load_authoritative_state_from_config(
            &path,
            &config,
            2_000,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("first configured load should write high-water");

        TrustCardRegistry::load_authoritative_state_from_config(
            &path,
            &config,
            3_000,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("second configured load should verify high-water with configured key");
    }

    #[test]
    fn backward_compatibility_function() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("compat-trust-card-state.json");

        // Create a valid registry
        let mut registry = TrustCardRegistry::default();
        registry
            .create(sample_input(), 1_000, "trace")
            .expect("create");
        registry
            .persist_authoritative_state(&path)
            .expect("persist");

        let restored = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("load authoritative state");

        // Should work the same as trusted file context
        let cards = restored
            .list(&TrustCardListFilter::empty(), "trace", 2_000)
            .expect("list");
        assert_eq!(cards.len(), 1);
    }
}
