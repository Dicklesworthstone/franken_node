//! bd-2yh: Extension trust-card API and CLI surfaces.
//!
//! Trust cards aggregate provenance, certification, reputation, and revocation
//! state into a deterministic, signed profile that can be queried via API and
//! displayed via CLI.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::certification::{DerivationMetadata, VerifiedEvidenceRef};

const MAX_TELEMETRY: usize = 4096;
const MAX_CARD_VERSIONS: usize = 512;
const MAX_AUDIT_HISTORY: usize = 256;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
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
    hasher.update((refs.len() as u64).to_le_bytes());
    for r in refs {
        hasher.update((r.evidence_id.len() as u64).to_le_bytes());
        hasher.update(r.evidence_id.as_bytes());
        let type_tag = serde_json::to_string(&r.evidence_type).unwrap_or_default();
        hasher.update((type_tag.len() as u64).to_le_bytes());
        hasher.update(type_tag.as_bytes());
        hasher.update(r.verified_at_epoch.to_le_bytes());
        hasher.update((r.verification_receipt_hash.len() as u64).to_le_bytes());
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

const DEFAULT_CACHE_TTL_SECS: u64 = 60;
const DEFAULT_REGISTRY_KEY: &[u8] = b"franken-node-trust-card-registry-key-v1";
pub const TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA: &str = "franken-node/trust-card-registry-state/v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, thiserror::Error)]
pub enum TrustCardError {
    #[error("trust card not found for extension `{0}`")]
    NotFound(String),
    #[error("trust card version `{version}` not found for extension `{extension_id}`")]
    VersionNotFound { extension_id: String, version: u64 },
    #[error("trust card signature verification failed for extension `{0}`")]
    SignatureInvalid(String),
    #[error("trust card hash mismatch for extension `{0}`")]
    CardHashMismatch(String),
    #[error("json serialization error: {0}")]
    Json(String),
    #[error("invalid hmac key")]
    InvalidRegistryKey,
    #[error("invalid pagination: page={page}, per_page={per_page}")]
    InvalidPagination { page: usize, per_page: usize },
    #[error("trust card derivation requires at least one verified evidence reference")]
    EvidenceMissing,
    #[error("upgrading certification level requires evidence references")]
    EvidenceRequiredForUpgrade,
    #[error("revocation is irreversible: cannot transition from Revoked to Active")]
    RevocationIrreversible,
    #[error("unsupported trust-card registry snapshot schema `{0}`")]
    UnsupportedSnapshotSchema(String),
    #[error("invalid trust-card registry snapshot: {0}")]
    InvalidSnapshot(String),
    #[error("failed reading trust-card registry snapshot {path}: {detail}")]
    SnapshotRead { path: PathBuf, detail: String },
    #[error("failed parsing trust-card registry snapshot {path}: {detail}")]
    SnapshotParse { path: PathBuf, detail: String },
    #[error("failed writing trust-card registry snapshot {path}: {detail}")]
    SnapshotWrite { path: PathBuf, detail: String },
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
    pub cache_ttl_secs: u64,
    pub cards_by_extension: BTreeMap<String, Vec<TrustCard>>,
}

#[derive(Debug, Clone)]
pub struct TrustCardRegistry {
    cards_by_extension: BTreeMap<String, Vec<TrustCard>>,
    cache_by_extension: BTreeMap<String, CachedCard>,
    cache_ttl_secs: u64,
    registry_key: Vec<u8>,
    telemetry: Vec<TelemetryEvent>,
}

impl Default for TrustCardRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_CACHE_TTL_SECS, DEFAULT_REGISTRY_KEY)
    }
}

impl TrustCardRegistry {
    #[must_use]
    pub fn new(cache_ttl_secs: u64, registry_key: &[u8]) -> Self {
        Self {
            cards_by_extension: BTreeMap::new(),
            cache_by_extension: BTreeMap::new(),
            cache_ttl_secs: cache_ttl_secs.max(1),
            registry_key: registry_key.to_vec(),
            telemetry: Vec::new(),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> TrustCardRegistrySnapshot {
        TrustCardRegistrySnapshot {
            schema_version: TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA.to_string(),
            cache_ttl_secs: self.cache_ttl_secs,
            cards_by_extension: self.cards_by_extension.clone(),
        }
    }

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
        registry.cards_by_extension = snapshot.cards_by_extension;

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

        Ok(registry)
    }

    pub fn load_authoritative_state(
        path: &Path,
        cache_ttl_secs: u64,
        loaded_at_secs: u64,
    ) -> Result<Self, TrustCardError> {
        let raw = std::fs::read_to_string(path).map_err(|err| TrustCardError::SnapshotRead {
            path: path.to_path_buf(),
            detail: err.to_string(),
        })?;
        let snapshot = serde_json::from_str::<TrustCardRegistrySnapshot>(&raw).map_err(|err| {
            TrustCardError::SnapshotParse {
                path: path.to_path_buf(),
                detail: err.to_string(),
            }
        })?;
        let mut registry = Self::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, loaded_at_secs)?;
        registry.cache_ttl_secs = cache_ttl_secs.max(1);
        Ok(registry)
    }

    pub fn persist_authoritative_state(&self, path: &Path) -> Result<(), TrustCardError> {
        let encoded = to_canonical_json(&self.snapshot())?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|err| TrustCardError::SnapshotWrite {
            path: path.to_path_buf(),
            detail: err.to_string(),
        })?;
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
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

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
                previous.trust_card_version.saturating_add(1),
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
        next.trust_card_version = latest.trust_card_version.saturating_add(1);
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
            && now_secs.saturating_sub(cached.cached_at_secs) <= self.cache_ttl_secs
        {
            let card = cached.card.clone();
            if verify_card_signature(&card, &self.registry_key).is_ok() {
                self.emit(
                    TRUST_CARD_CACHE_HIT,
                    Some(extension_id.to_string()),
                    trace_id,
                    now_secs,
                    "served from cache",
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

            self.cache_by_extension.remove(extension_id);
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
                    if now_secs.saturating_sub(cached.cached_at_secs) <= self.cache_ttl_secs =>
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
                    if verify_card_signature(&cached.card, &self.registry_key).is_ok() {
                        report.cache_hits = report.cache_hits.saturating_add(1);
                        self.emit(
                            TRUST_CARD_CACHE_HIT,
                            Some(extension_id),
                            trace_id,
                            now_secs,
                            "sync skipped fresh cache entry",
                        );
                        continue;
                    }

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
    pub fn telemetry(&self) -> &[TelemetryEvent] {
        &self.telemetry
    }

    fn latest_card(&self, extension_id: &str) -> Option<&TrustCard> {
        self.cards_by_extension
            .get(extension_id)
            .and_then(|history| history.last())
    }

    fn latest_verified_card(
        &self,
        extension_id: &str,
    ) -> Result<Option<&TrustCard>, TrustCardError> {
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

pub fn verify_card_signature(card: &TrustCard, registry_key: &[u8]) -> Result<(), TrustCardError> {
    let expected_hash = compute_card_hash(card)?;
    if !crate::security::constant_time::ct_eq(&card.card_hash, &expected_hash) {
        return Err(TrustCardError::CardHashMismatch(
            card.extension.extension_id.clone(),
        ));
    }

    let mut mac =
        HmacSha256::new_from_slice(registry_key).map_err(|_| TrustCardError::InvalidRegistryKey)?;
    mac.update(b"trust_card_registry_sig_v1:");
    mac.update(card.card_hash.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());
    if !crate::security::constant_time::ct_eq(&card.registry_signature, &expected_signature) {
        return Err(TrustCardError::SignatureInvalid(
            card.extension.extension_id.clone(),
        ));
    }
    Ok(())
}

pub fn compute_card_hash(card: &TrustCard) -> Result<String, TrustCardError> {
    let canonical = canonical_card_without_hash_and_signature(card)?;
    let encoded = serde_json::to_vec(&canonical)?;
    let digest = Sha256::digest([b"trust_card_hash_v1:" as &[u8], &encoded].concat());
    Ok(hex::encode(digest))
}

pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, TrustCardError> {
    let raw = serde_json::to_value(value)?;
    let canonical = canonicalize_value(raw);
    Ok(serde_json::to_string(&canonical)?)
}

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
    Ok(canonicalize_value(Value::Object(map.clone())))
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
            let mut keys: BTreeSet<String> = BTreeSet::new();
            for key in map.keys() {
                keys.insert(key.clone());
            }
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(val) = map.get(&key) {
                    out.insert(key, canonicalize_value(val.clone()));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_value).collect()),
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn registry_snapshot_roundtrip_preserves_latest_cards() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join(".franken-node/state/trust-card-registry.v1.json");
        registry
            .persist_authoritative_state(&path)
            .expect("persist authoritative state");

        let mut restored =
            TrustCardRegistry::load_authoritative_state(&path, 60, 2_000).expect("load");

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
    fn registry_snapshot_rejects_tampered_card_history() {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let mut snapshot = registry.snapshot();
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
        let mut snapshot = registry.snapshot();
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
}
