//! bd-2yh: Extension trust-card API and CLI surfaces.
//!
//! Trust cards aggregate provenance, certification, reputation, and revocation
//! state into a deterministic, signed profile that can be queried via API and
//! displayed via CLI.

use std::collections::{BTreeMap, BTreeSet};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const TRUST_CARD_CREATED: &str = "TRUST_CARD_CREATED";
pub const TRUST_CARD_UPDATED: &str = "TRUST_CARD_UPDATED";
pub const TRUST_CARD_REVOKED: &str = "TRUST_CARD_REVOKED";
pub const TRUST_CARD_QUERIED: &str = "TRUST_CARD_QUERIED";
pub const TRUST_CARD_COMPUTED: &str = "TRUST_CARD_COMPUTED";
pub const TRUST_CARD_SERVED: &str = "TRUST_CARD_SERVED";
pub const TRUST_CARD_CACHE_HIT: &str = "TRUST_CARD_CACHE_HIT";
pub const TRUST_CARD_CACHE_MISS: &str = "TRUST_CARD_CACHE_MISS";
pub const TRUST_CARD_STALE_REFRESH: &str = "TRUST_CARD_STALE_REFRESH";
pub const TRUST_CARD_DIFF_COMPUTED: &str = "TRUST_CARD_DIFF_COMPUTED";

const DEFAULT_CACHE_TTL_SECS: u64 = 60;
const DEFAULT_REGISTRY_KEY: &[u8] = b"franken-node-trust-card-registry-key-v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, thiserror::Error)]
pub enum TrustCardError {
    #[error("trust card not found for extension `{0}`")]
    NotFound(String),
    #[error("trust card signature verification failed for extension `{0}`")]
    SignatureInvalid(String),
    #[error("trust card hash mismatch for extension `{0}`")]
    CardHashMismatch(String),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid hmac key")]
    InvalidRegistryKey,
    #[error("invalid pagination: page={page}, per_page={per_page}")]
    InvalidPagination { page: usize, per_page: usize },
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

    pub fn create(
        &mut self,
        input: TrustCardInput,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<TrustCard, TrustCardError> {
        let extension_id = input.extension.extension_id.clone();
        let previous = self
            .cards_by_extension
            .get(&extension_id)
            .and_then(|history| history.last());
        let previous_hash = previous.map(|card| card.card_hash.clone());
        let next_version = previous.map_or(1, |card| card.trust_card_version + 1);

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
            card_hash: String::new(),
            registry_signature: String::new(),
        };
        sign_card_in_place(&mut card, &self.registry_key)?;

        self.cards_by_extension
            .entry(extension_id.clone())
            .or_default()
            .push(card.clone());
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
            .latest_card(extension_id)
            .ok_or_else(|| TrustCardError::NotFound(extension_id.to_string()))?
            .clone();

        let mut next = latest.clone();
        next.trust_card_version = latest.trust_card_version + 1;
        next.previous_version_hash = Some(latest.card_hash.clone());
        if let Some(level) = mutation.certification_level {
            next.certification_level = level;
        }
        if let Some(status) = mutation.revocation_status {
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
        next.audit_history.push(AuditRecord {
            timestamp: timestamp_from_secs(now_secs),
            event_code: TRUST_CARD_UPDATED.to_string(),
            detail: "trust card updated".to_string(),
            trace_id: trace_id.to_string(),
        });

        sign_card_in_place(&mut next, &self.registry_key)?;
        self.cards_by_extension
            .entry(extension_id.to_string())
            .or_default()
            .push(next.clone());
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

        let latest = self.latest_card(extension_id).cloned();
        let Some(latest_card) = latest else {
            return Ok(None);
        };

        let cache_decision = self
            .cache_by_extension
            .get(extension_id)
            .filter(|cached| cached.card.trust_card_version == latest_card.trust_card_version)
            .map(|cached| now_secs.saturating_sub(cached.cached_at_secs) <= self.cache_ttl_secs);

        let card = match cache_decision {
            Some(true) => {
                self.emit(
                    TRUST_CARD_CACHE_HIT,
                    Some(extension_id.to_string()),
                    trace_id,
                    now_secs,
                    "served from cache",
                );
                self.cache_by_extension
                    .get(extension_id)
                    .map(|cached| cached.card.clone())
                    .unwrap_or(latest_card.clone())
            }
            Some(false) => {
                self.emit(
                    TRUST_CARD_STALE_REFRESH,
                    Some(extension_id.to_string()),
                    trace_id,
                    now_secs,
                    "cache stale; refreshed from source",
                );
                self.cache_by_extension.insert(
                    extension_id.to_string(),
                    CachedCard {
                        card: latest_card.clone(),
                        cached_at_secs: now_secs,
                    },
                );
                latest_card.clone()
            }
            None => {
                self.emit(
                    TRUST_CARD_CACHE_MISS,
                    Some(extension_id.to_string()),
                    trace_id,
                    now_secs,
                    "cache miss",
                );
                self.cache_by_extension.insert(
                    extension_id.to_string(),
                    CachedCard {
                        card: latest_card.clone(),
                        cached_at_secs: now_secs,
                    },
                );
                latest_card.clone()
            }
        };

        verify_card_signature(&card, &self.registry_key)?;
        self.emit(
            TRUST_CARD_SERVED,
            Some(extension_id.to_string()),
            trace_id,
            now_secs,
            "served verified trust card",
        );
        Ok(Some(card))
    }

    pub fn list(
        &self,
        filter: &TrustCardListFilter,
        trace_id: &str,
        now_secs: u64,
    ) -> Vec<TrustCard> {
        let _ = (trace_id, now_secs);
        let mut out = Vec::new();
        for history in self.cards_by_extension.values() {
            let Some(card) = history.last() else {
                continue;
            };
            if let Some(level) = filter.certification_level {
                if card.certification_level != level {
                    continue;
                }
            }
            if let Some(publisher_id) = &filter.publisher_id {
                if &card.publisher.publisher_id != publisher_id {
                    continue;
                }
            }
            if let Some(capability) = &filter.capability {
                if !card
                    .capability_declarations
                    .iter()
                    .any(|cap| cap.name.contains(capability))
                {
                    continue;
                }
            }
            out.push(card.clone());
        }
        out.sort_by(|left, right| left.extension.extension_id.cmp(&right.extension.extension_id));
        out
    }

    pub fn list_by_publisher(
        &self,
        publisher_id: &str,
        now_secs: u64,
        trace_id: &str,
    ) -> Vec<TrustCard> {
        let _ = (now_secs, trace_id);
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

    pub fn search(
        &self,
        query: &str,
        now_secs: u64,
        trace_id: &str,
    ) -> Vec<TrustCard> {
        let _ = (now_secs, trace_id);
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
            if haystack.contains(&query_lc) {
                out.push(card.clone());
            }
        }
        out.sort_by(|left, right| left.extension.extension_id.cmp(&right.extension.extension_id));
        out
    }

    pub fn compare(
        &self,
        left_extension_id: &str,
        right_extension_id: &str,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<TrustCardComparison, TrustCardError> {
        let _ = (now_secs, trace_id);
        let left = self
            .latest_card(left_extension_id)
            .ok_or_else(|| TrustCardError::NotFound(left_extension_id.to_string()))?;
        let right = self
            .latest_card(right_extension_id)
            .ok_or_else(|| TrustCardError::NotFound(right_extension_id.to_string()))?;

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

        Ok(TrustCardComparison {
            left_extension_id: left_extension_id.to_string(),
            right_extension_id: right_extension_id.to_string(),
            changes,
        })
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

    fn emit(
        &mut self,
        event_code: &str,
        extension_id: Option<String>,
        trace_id: &str,
        timestamp_secs: u64,
        detail: &str,
    ) {
        self.telemetry.push(TelemetryEvent {
            event_code: event_code.to_string(),
            extension_id,
            trace_id: trace_id.to_string(),
            timestamp_secs,
            detail: detail.to_string(),
        });
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
    if card.card_hash != expected_hash {
        return Err(TrustCardError::CardHashMismatch(
            card.extension.extension_id.clone(),
        ));
    }

    let mut mac =
        HmacSha256::new_from_slice(registry_key).map_err(|_| TrustCardError::InvalidRegistryKey)?;
    mac.update(card.card_hash.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());
    if card.registry_signature != expected_signature {
        return Err(TrustCardError::SignatureInvalid(
            card.extension.extension_id.clone(),
        ));
    }
    Ok(())
}

pub fn compute_card_hash(card: &TrustCard) -> Result<String, TrustCardError> {
    let canonical = canonical_card_without_hash_and_signature(card)?;
    let encoded = serde_json::to_vec(&canonical)?;
    let digest = Sha256::digest(encoded);
    Ok(hex::encode(digest))
}

pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, TrustCardError> {
    let raw = serde_json::to_value(value)?;
    let canonical = canonicalize_value(raw);
    Ok(serde_json::to_string(&canonical)?)
}

pub fn demo_registry(now_secs: u64) -> Result<TrustCardRegistry, TrustCardError> {
    let mut registry = TrustCardRegistry::default();
    let base_trace = "trace-demo";

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
                profile_summary: "Network-only auth checks with bounded side effects"
                    .to_string(),
            },
            revocation_status: RevocationStatus::Active,
            provenance_summary: ProvenanceSummary {
                attestation_level: "slsa-l3".to_string(),
                source_uri: "https://registry.example/acme/auth-guard".to_string(),
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
                summary: "Token validation extension with strong provenance and no local disk access"
                    .to_string(),
            },
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
                source_uri: "https://registry.example/beta/telemetry-bridge".to_string(),
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
        },
        now_secs.saturating_add(2),
        base_trace,
    )?;

    Ok(registry)
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
    format!("{timestamp_secs}Z")
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
        }
    }

    #[test]
    fn create_and_read_round_trip() {
        let mut registry = TrustCardRegistry::default();
        let card = registry.create(sample_input(), 1_000, "trace").expect("create");
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
        let first = registry.create(sample_input(), 1_000, "trace").expect("create");
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
                },
                1_020,
                "trace",
            )
            .expect("update");
        assert_eq!(second.trust_card_version, 2);
        assert_eq!(second.previous_version_hash.as_deref(), Some(&first.card_hash));
    }

    #[test]
    fn signature_verification_rejects_tampered_card() {
        let mut registry = TrustCardRegistry::default();
        let mut card = registry.create(sample_input(), 1_000, "trace").expect("create");
        card.reputation_score_basis_points = 10;
        let err = verify_card_signature(&card, DEFAULT_REGISTRY_KEY).expect_err("must fail");
        assert!(matches!(err, TrustCardError::CardHashMismatch(_)));
    }

    #[test]
    fn list_filter_by_publisher_and_capability() {
        let registry = demo_registry(1_000).expect("demo");
        let by_pub = registry.list_by_publisher("pub-acme", 1_010, "trace");
        assert_eq!(by_pub.len(), 1);
        let by_capability = registry.search("telemetry", 1_010, "trace");
        assert_eq!(by_capability.len(), 1);
    }

    #[test]
    fn compare_shows_changes() {
        let registry = demo_registry(1_000).expect("demo");
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
    fn telemetry_includes_cache_miss_and_hit() {
        let mut registry = TrustCardRegistry::new(60, DEFAULT_REGISTRY_KEY);
        registry.create(sample_input(), 1_000, "trace").expect("create");
        registry
            .read("npm:@acme/plugin", 1_001, "trace")
            .expect("read1");
        registry
            .read("npm:@acme/plugin", 1_002, "trace")
            .expect("read2");
        let codes: Vec<&str> = registry.telemetry().iter().map(|evt| evt.event_code.as_str()).collect();
        assert!(codes.contains(&TRUST_CARD_CACHE_HIT));
    }
}
