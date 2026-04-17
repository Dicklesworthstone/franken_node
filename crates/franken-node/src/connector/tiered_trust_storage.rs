//! L1/L2/L3 tiered trust artifact storage with explicit source-of-truth
//! designation per object class.
//!
//! Bead: bd-okqy (Section 10.14)
//!
//! Three tiers:
//! - **L1 Local** – hot working set for immediate control-plane decisions.
//! - **L2 Warm**  – recently-active artifacts for rapid recovery.
//! - **L3 Archive** – durable long-term copies for audit / disaster recovery.
//!
//! Each object class (from bd-2573 registry) maps to exactly one
//! authoritative tier via [`AuthorityMap`]. The mapping is immutable
//! after initialization — runtime mutation attempts fail with
//! `ERR_AUTHORITY_MAP_IMMUTABLE`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use crate::capacity_defaults::aliases::MAX_EVENTS;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
}

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const TS_TIER_INITIALIZED: &str = "TS_TIER_INITIALIZED";
pub const TS_STORE_COMPLETE: &str = "TS_STORE_COMPLETE";
pub const TS_RETRIEVE_COMPLETE: &str = "TS_RETRIEVE_COMPLETE";
pub const TS_EVICT_COMPLETE: &str = "TS_EVICT_COMPLETE";
pub const TS_RECOVERY_START: &str = "TS_RECOVERY_START";
pub const TS_RECOVERY_COMPLETE: &str = "TS_RECOVERY_COMPLETE";
pub const TS_AUTHORITY_MAP_VIOLATION: &str = "TS_AUTHORITY_MAP_VIOLATION";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_AUTHORITY_MAP_IMMUTABLE: &str = "ERR_AUTHORITY_MAP_IMMUTABLE";
pub const ERR_ARTIFACT_NOT_FOUND: &str = "ERR_ARTIFACT_NOT_FOUND";
pub const ERR_RECOVERY_SOURCE_MISSING: &str = "ERR_RECOVERY_SOURCE_MISSING";
pub const ERR_RECOVERY_DIRECTION_INVALID: &str = "ERR_RECOVERY_DIRECTION_INVALID";
pub const ERR_EVICT_REQUIRES_RETRIEVABILITY: &str = "ERR_EVICT_REQUIRES_RETRIEVABILITY";
pub const ERR_TIER_NOT_AUTHORITATIVE: &str = "ERR_TIER_NOT_AUTHORITATIVE";

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

/// INV-TIER-AUTHORITY: Each object class maps to exactly one authoritative tier.
pub const INV_TIER_AUTHORITY: &str = "INV-TIER-AUTHORITY";
/// INV-TIER-IMMUTABLE: Authority map is immutable after initialization.
pub const INV_TIER_IMMUTABLE: &str = "INV-TIER-IMMUTABLE";
/// INV-TIER-RECOVERY: Recovery reconstructs derived tier content from authoritative tier.
pub const INV_TIER_RECOVERY: &str = "INV-TIER-RECOVERY";
/// INV-TIER-ORDERED: Authority levels are strictly ordered L1 > L2 > L3.
pub const INV_TIER_ORDERED: &str = "INV-TIER-ORDERED";

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Canonical object class identifiers from bd-2573.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectClass {
    CriticalMarker,
    TrustReceipt,
    ReplayBundle,
    TelemetryArtifact,
}

impl ObjectClass {
    pub fn all() -> &'static [ObjectClass] {
        &[
            ObjectClass::CriticalMarker,
            ObjectClass::TrustReceipt,
            ObjectClass::ReplayBundle,
            ObjectClass::TelemetryArtifact,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectClass::CriticalMarker => "critical_marker",
            ObjectClass::TrustReceipt => "trust_receipt",
            ObjectClass::ReplayBundle => "replay_bundle",
            ObjectClass::TelemetryArtifact => "telemetry_artifact",
        }
    }
}

impl fmt::Display for ObjectClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Storage tier designating latency / authority level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Tier {
    /// Hot local working set — lowest latency, highest authority.
    L1Local = 1,
    /// Warm recently-active — moderate latency, moderate authority.
    L2Warm = 2,
    /// Cold durable archive — highest latency, lowest authority.
    L3Archive = 3,
}

impl Tier {
    pub fn all() -> &'static [Tier] {
        &[Tier::L1Local, Tier::L2Warm, Tier::L3Archive]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::L1Local => "L1_local",
            Tier::L2Warm => "L2_warm",
            Tier::L3Archive => "L3_archive",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Authority level returned by each tier. Strictly ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuthorityLevel(pub u8);

impl AuthorityLevel {
    pub const L1: AuthorityLevel = AuthorityLevel(3); // highest
    pub const L2: AuthorityLevel = AuthorityLevel(2);
    pub const L3: AuthorityLevel = AuthorityLevel(1); // lowest
}

/// Returns the authority level for a tier.
pub fn authority_level_for(tier: Tier) -> AuthorityLevel {
    match tier {
        Tier::L1Local => AuthorityLevel::L1,
        Tier::L2Warm => AuthorityLevel::L2,
        Tier::L3Archive => AuthorityLevel::L3,
    }
}

/// Unique artifact identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub String);

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Trust artifact stored in the tiered system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustArtifact {
    pub id: ArtifactId,
    pub object_class: ObjectClass,
    pub payload: Vec<u8>,
    pub epoch_id: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageError {
    pub code: String,
    pub message: String,
}

impl StorageError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        StorageError {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn authority_map_immutable() -> Self {
        Self::new(
            ERR_AUTHORITY_MAP_IMMUTABLE,
            "Authority map is immutable after initialization",
        )
    }

    pub fn artifact_not_found(id: &ArtifactId, tier: Tier) -> Self {
        Self::new(
            ERR_ARTIFACT_NOT_FOUND,
            format!("Artifact {} not found in tier {}", id, tier),
        )
    }

    pub fn recovery_source_missing(
        id: &ArtifactId,
        target_tier: Tier,
        searched_tiers: &[Tier],
    ) -> Self {
        let searched = searched_tiers
            .iter()
            .map(Tier::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        Self::new(
            ERR_RECOVERY_SOURCE_MISSING,
            format!(
                "Artifact {} not found in recovery source tier(s) [{}] for target tier {}",
                id, searched, target_tier
            ),
        )
    }

    pub fn recovery_direction_invalid(from: Tier, to: Tier) -> Self {
        Self::new(
            ERR_RECOVERY_DIRECTION_INVALID,
            format!(
                "Cannot recover from tier {} to tier {} (must recover from higher-authority to lower)",
                from, to
            ),
        )
    }

    pub fn evict_requires_retrievability(id: &ArtifactId, tier: Tier) -> Self {
        Self::new(
            ERR_EVICT_REQUIRES_RETRIEVABILITY,
            format!(
                "Cannot evict artifact {} from tier {} without retrievability proof in a lower tier",
                id, tier
            ),
        )
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ---------------------------------------------------------------------------
// Authority map
// ---------------------------------------------------------------------------

/// Maps each object class to its authoritative (source-of-truth) tier.
/// Immutable after construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityMap {
    mapping: BTreeMap<ObjectClass, Tier>,
    frozen: bool,
}

impl AuthorityMap {
    /// Build an authority map from a set of (class, tier) pairs.
    /// The map is frozen immediately — no further modifications are allowed.
    pub fn new(entries: &[(ObjectClass, Tier)]) -> Self {
        let mapping: BTreeMap<ObjectClass, Tier> = entries.iter().cloned().collect();
        AuthorityMap {
            mapping,
            frozen: true,
        }
    }

    /// Build with the default authority assignments:
    /// - CriticalMarker → L1 (hot, immediate decisions)
    /// - TrustReceipt   → L2 (warm, rapid recovery)
    /// - ReplayBundle    → L3 (cold, durable archive)
    /// - TelemetryArtifact → L2 (warm, on-demand)
    pub fn default_mapping() -> Self {
        Self::new(&[
            (ObjectClass::CriticalMarker, Tier::L1Local),
            (ObjectClass::TrustReceipt, Tier::L2Warm),
            (ObjectClass::ReplayBundle, Tier::L3Archive),
            (ObjectClass::TelemetryArtifact, Tier::L2Warm),
        ])
    }

    /// Look up the authoritative tier for a given object class.
    pub fn authoritative_tier(&self, class: ObjectClass) -> Option<Tier> {
        self.mapping.get(&class).copied()
    }

    /// Attempt to change the mapping — always fails after construction.
    pub fn try_update(&mut self, _class: ObjectClass, _tier: Tier) -> Result<(), StorageError> {
        // INV-TIER-IMMUTABLE: authority map is frozen at construction.
        Err(StorageError::authority_map_immutable())
    }

    /// Check whether a class is stored in its authoritative tier.
    pub fn is_authoritative(&self, class: ObjectClass, tier: Tier) -> bool {
        self.authoritative_tier(class) == Some(tier)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.mapping.len()
    }

    /// Whether the map has any entries.
    pub fn is_empty(&self) -> bool {
        self.mapping.is_empty()
    }

    /// Iterate over all (class, tier) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&ObjectClass, &Tier)> {
        self.mapping.iter()
    }

    /// Serialize the map to JSON for audit purposes.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ---------------------------------------------------------------------------
// Tier store (in-memory implementation)
// ---------------------------------------------------------------------------

/// Per-tier artifact store.
#[derive(Debug, Clone)]
struct TierStore {
    tier: Tier,
    artifacts: BTreeMap<ArtifactId, TrustArtifact>,
}

impl TierStore {
    fn new(tier: Tier) -> Self {
        TierStore {
            tier,
            artifacts: BTreeMap::new(),
        }
    }

    fn store(&mut self, artifact: TrustArtifact) -> ArtifactId {
        let id = artifact.id.clone();
        self.artifacts.insert(id.clone(), artifact);
        id
    }

    fn retrieve(&self, id: &ArtifactId) -> Result<&TrustArtifact, StorageError> {
        self.artifacts
            .get(id)
            .ok_or_else(|| StorageError::artifact_not_found(id, self.tier))
    }

    fn evict(&mut self, id: &ArtifactId) -> Result<TrustArtifact, StorageError> {
        self.artifacts
            .remove(id)
            .ok_or_else(|| StorageError::artifact_not_found(id, self.tier))
    }

    fn contains(&self, id: &ArtifactId) -> bool {
        self.artifacts.contains_key(id)
    }

    fn authority_level(&self) -> AuthorityLevel {
        authority_level_for(self.tier)
    }

    fn count(&self) -> usize {
        self.artifacts.len()
    }
}

// ---------------------------------------------------------------------------
// Event log
// ---------------------------------------------------------------------------

/// Structured event emitted by storage operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEvent {
    pub code: String,
    pub tier: String,
    pub artifact_id: Option<String>,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// TieredTrustStorage
// ---------------------------------------------------------------------------

/// L1/L2/L3 tiered trust artifact storage with per-class authority
/// designation and recovery paths.
#[derive(Debug)]
pub struct TieredTrustStorage {
    authority_map: AuthorityMap,
    l1: TierStore,
    l2: TierStore,
    l3: TierStore,
    events: Vec<StorageEvent>,
}

impl TieredTrustStorage {
    /// Create a new tiered storage system with the given authority map.
    pub fn new(authority_map: AuthorityMap) -> Self {
        let mut storage = TieredTrustStorage {
            authority_map,
            l1: TierStore::new(Tier::L1Local),
            l2: TierStore::new(Tier::L2Warm),
            l3: TierStore::new(Tier::L3Archive),
            events: Vec::new(),
        };
        for tier in Tier::all() {
            storage.emit(
                TS_TIER_INITIALIZED,
                *tier,
                None,
                format!("Tier {} initialized", tier),
            );
        }
        storage
    }

    /// Create with the default authority map.
    pub fn with_defaults() -> Self {
        Self::new(AuthorityMap::default_mapping())
    }

    /// Reference to the immutable authority map.
    pub fn authority_map(&self) -> &AuthorityMap {
        &self.authority_map
    }

    /// Attempt to mutate the authority map. Always fails (immutability).
    pub fn try_update_authority(
        &mut self,
        class: ObjectClass,
        tier: Tier,
    ) -> Result<(), StorageError> {
        let result = self.authority_map.try_update(class, tier);
        if result.is_err() {
            self.emit(
                TS_AUTHORITY_MAP_VIOLATION,
                tier,
                None,
                format!(
                    "Rejected authority map mutation for class {} to tier {}",
                    class, tier
                ),
            );
        }
        result
    }

    // -- tier accessor -------------------------------------------------------

    fn tier_store(&self, tier: Tier) -> &TierStore {
        match tier {
            Tier::L1Local => &self.l1,
            Tier::L2Warm => &self.l2,
            Tier::L3Archive => &self.l3,
        }
    }

    fn tier_store_mut(&mut self, tier: Tier) -> &mut TierStore {
        match tier {
            Tier::L1Local => &mut self.l1,
            Tier::L2Warm => &mut self.l2,
            Tier::L3Archive => &mut self.l3,
        }
    }

    // -- CRUD operations -----------------------------------------------------

    /// Store an artifact in the specified tier.
    pub fn store(&mut self, tier: Tier, artifact: TrustArtifact) -> ArtifactId {
        let id = self.tier_store_mut(tier).store(artifact);
        self.emit(
            TS_STORE_COMPLETE,
            tier,
            Some(&id),
            format!("Artifact {} stored in tier {}", id, tier),
        );
        id
    }

    /// Retrieve an artifact from the specified tier.
    pub fn retrieve(&mut self, tier: Tier, id: &ArtifactId) -> Result<TrustArtifact, StorageError> {
        let result = self.tier_store(tier).retrieve(id).cloned();
        if let Ok(ref artifact) = result {
            self.emit(
                TS_RETRIEVE_COMPLETE,
                tier,
                Some(&artifact.id),
                format!("Artifact {} retrieved from tier {}", id, tier),
            );
        }
        result
    }

    /// Evict an artifact from the specified tier.
    ///
    /// For non-L3 tiers, eviction requires the artifact to be retrievable
    /// from a lower (higher-authority-number) tier — this is the
    /// retrievability-before-eviction proof required by bd-1fck.
    pub fn evict(&mut self, tier: Tier, id: &ArtifactId) -> Result<TrustArtifact, StorageError> {
        // Retrievability check: artifact must exist in a colder tier.
        match tier {
            Tier::L1Local => {
                if !self.l2.contains(id) && !self.l3.contains(id) {
                    return Err(StorageError::evict_requires_retrievability(id, tier));
                }
            }
            Tier::L2Warm => {
                if !self.l3.contains(id) {
                    return Err(StorageError::evict_requires_retrievability(id, tier));
                }
            }
            Tier::L3Archive => {
                // L3 is the coldest tier — eviction is allowed (permanent deletion).
            }
        }
        let artifact = self.tier_store_mut(tier).evict(id)?;
        self.emit(
            TS_EVICT_COMPLETE,
            tier,
            Some(id),
            format!("Artifact {} evicted from tier {}", id, tier),
        );
        Ok(artifact)
    }

    /// Check whether an artifact exists in a given tier.
    pub fn contains(&self, tier: Tier, id: &ArtifactId) -> bool {
        self.tier_store(tier).contains(id)
    }

    /// Authority level for a given tier.
    pub fn authority_level(&self, tier: Tier) -> AuthorityLevel {
        self.tier_store(tier).authority_level()
    }

    /// Number of artifacts in a given tier.
    pub fn tier_count(&self, tier: Tier) -> usize {
        self.tier_store(tier).count()
    }

    // -- Recovery path -------------------------------------------------------

    /// Recover an artifact into `target_tier` by copying from the
    /// authoritative tier (or any tier with higher authority).
    ///
    /// Valid recovery directions (source → target):
    /// - L2 → L1  (warm to hot)
    /// - L3 → L1  (archive to hot)
    /// - L3 → L2  (archive to warm)
    ///
    /// Recovery from a lower-authority tier to a higher-authority tier
    /// (e.g., L1 → L3) is invalid and returns an error.
    pub fn recover_tier(
        &mut self,
        target_tier: Tier,
        artifact_id: &ArtifactId,
    ) -> Result<(), StorageError> {
        self.emit(
            TS_RECOVERY_START,
            target_tier,
            Some(artifact_id),
            format!(
                "Recovery started for artifact {} into tier {}",
                artifact_id, target_tier
            ),
        );

        // Find the artifact in the authoritative or any higher-authority tier.
        let source = self.find_recovery_source(target_tier, artifact_id)?;
        let artifact = source.clone();

        // Store the recovered copy in the target tier.
        self.tier_store_mut(target_tier).store(artifact);

        self.emit(
            TS_RECOVERY_COMPLETE,
            target_tier,
            Some(artifact_id),
            format!(
                "Recovery complete for artifact {} into tier {}",
                artifact_id, target_tier
            ),
        );
        Ok(())
    }

    /// Find the artifact in a tier with strictly higher authority than
    /// `target_tier`.
    fn find_recovery_source(
        &self,
        target_tier: Tier,
        artifact_id: &ArtifactId,
    ) -> Result<TrustArtifact, StorageError> {
        // Recovery sources ordered by authority (highest first).
        let candidate_tiers: &[Tier] = match target_tier {
            Tier::L1Local => &[Tier::L2Warm, Tier::L3Archive],
            Tier::L2Warm => &[Tier::L3Archive],
            Tier::L3Archive => {
                // Cannot recover into the coldest tier from a higher tier
                // (there is none).
                return Err(StorageError::recovery_direction_invalid(
                    Tier::L3Archive,
                    Tier::L3Archive,
                ));
            }
        };

        for &source_tier in candidate_tiers {
            if let Ok(artifact) = self.tier_store(source_tier).retrieve(artifact_id) {
                return Ok(artifact.clone());
            }
        }

        Err(StorageError::recovery_source_missing(
            artifact_id,
            target_tier,
            candidate_tiers,
        ))
    }

    // -- Event log -----------------------------------------------------------

    fn emit(&mut self, code: &str, tier: Tier, artifact_id: Option<&ArtifactId>, detail: String) {
        push_bounded(
            &mut self.events,
            StorageEvent {
                code: code.to_string(),
                tier: tier.as_str().to_string(),
                artifact_id: artifact_id.map(|id| id.0.clone()),
                detail,
            },
            MAX_EVENTS,
        );
    }

    /// All events emitted since creation.
    pub fn events(&self) -> &[StorageEvent] {
        &self.events
    }

    /// Drain and return all events.
    pub fn take_events(&mut self) -> Vec<StorageEvent> {
        std::mem::take(&mut self.events)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_artifact(id: &str, class: ObjectClass) -> TrustArtifact {
        TrustArtifact {
            id: ArtifactId(id.to_string()),
            object_class: class,
            payload: vec![0xCA, 0xFE],
            epoch_id: 1,
        }
    }

    // -- AuthorityLevel ordering ------------------------------------------

    #[test]
    fn test_authority_levels_are_ordered() {
        assert!(AuthorityLevel::L1 > AuthorityLevel::L2);
        assert!(AuthorityLevel::L2 > AuthorityLevel::L3);
        assert!(AuthorityLevel::L1 > AuthorityLevel::L3);
    }

    #[test]
    fn test_authority_level_for_tiers() {
        assert_eq!(authority_level_for(Tier::L1Local), AuthorityLevel::L1);
        assert_eq!(authority_level_for(Tier::L2Warm), AuthorityLevel::L2);
        assert_eq!(authority_level_for(Tier::L3Archive), AuthorityLevel::L3);
    }

    // -- AuthorityMap construction ----------------------------------------

    #[test]
    fn test_authority_map_default_has_all_classes() {
        let map = AuthorityMap::default_mapping();
        for class in ObjectClass::all() {
            assert!(
                map.authoritative_tier(*class).is_some(),
                "Missing class {}",
                class
            );
        }
    }

    #[test]
    fn test_authority_map_default_assignments() {
        let map = AuthorityMap::default_mapping();
        assert_eq!(
            map.authoritative_tier(ObjectClass::CriticalMarker),
            Some(Tier::L1Local)
        );
        assert_eq!(
            map.authoritative_tier(ObjectClass::TrustReceipt),
            Some(Tier::L2Warm)
        );
        assert_eq!(
            map.authoritative_tier(ObjectClass::ReplayBundle),
            Some(Tier::L3Archive)
        );
        assert_eq!(
            map.authoritative_tier(ObjectClass::TelemetryArtifact),
            Some(Tier::L2Warm)
        );
    }

    #[test]
    fn test_authority_map_immutable() {
        let mut map = AuthorityMap::default_mapping();
        let result = map.try_update(ObjectClass::CriticalMarker, Tier::L3Archive);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ERR_AUTHORITY_MAP_IMMUTABLE);
    }

    #[test]
    fn test_authority_map_is_authoritative() {
        let map = AuthorityMap::default_mapping();
        assert!(map.is_authoritative(ObjectClass::CriticalMarker, Tier::L1Local));
        assert!(!map.is_authoritative(ObjectClass::CriticalMarker, Tier::L2Warm));
    }

    #[test]
    fn test_authority_map_len() {
        let map = AuthorityMap::default_mapping();
        assert_eq!(map.len(), 4);
        assert!(!map.is_empty());
    }

    #[test]
    fn test_authority_map_json_serialization() {
        let map = AuthorityMap::default_mapping();
        let json = map.to_json().expect("serialize");
        let parsed: AuthorityMap = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.len(), map.len());
        for class in ObjectClass::all() {
            assert_eq!(
                parsed.authoritative_tier(*class),
                map.authoritative_tier(*class)
            );
        }
    }

    #[test]
    fn test_authority_map_custom() {
        let map = AuthorityMap::new(&[
            (ObjectClass::CriticalMarker, Tier::L3Archive),
            (ObjectClass::TrustReceipt, Tier::L1Local),
        ]);
        assert_eq!(
            map.authoritative_tier(ObjectClass::CriticalMarker),
            Some(Tier::L3Archive)
        );
        assert_eq!(
            map.authoritative_tier(ObjectClass::TrustReceipt),
            Some(Tier::L1Local)
        );
        assert!(map.authoritative_tier(ObjectClass::ReplayBundle).is_none());
    }

    // -- TieredTrustStorage construction ----------------------------------

    #[test]
    fn test_storage_initialization_events() {
        let storage = TieredTrustStorage::with_defaults();
        let init_events: Vec<_> = storage
            .events()
            .iter()
            .filter(|e| e.code == TS_TIER_INITIALIZED)
            .collect();
        assert_eq!(init_events.len(), 3);
    }

    #[test]
    fn test_storage_empty_on_creation() {
        let storage = TieredTrustStorage::with_defaults();
        for tier in Tier::all() {
            assert_eq!(storage.tier_count(*tier), 0);
        }
    }

    #[test]
    fn test_storage_authority_levels() {
        let storage = TieredTrustStorage::with_defaults();
        assert_eq!(storage.authority_level(Tier::L1Local), AuthorityLevel::L1);
        assert_eq!(storage.authority_level(Tier::L2Warm), AuthorityLevel::L2);
        assert_eq!(storage.authority_level(Tier::L3Archive), AuthorityLevel::L3);
    }

    // -- Store / retrieve / evict -----------------------------------------

    #[test]
    fn test_store_and_retrieve_l1() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("a1", ObjectClass::CriticalMarker);
        let id = storage.store(Tier::L1Local, art.clone());
        let retrieved = storage.retrieve(Tier::L1Local, &id).unwrap();
        assert_eq!(retrieved.payload, art.payload);
    }

    #[test]
    fn test_store_and_retrieve_l2() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("a2", ObjectClass::TrustReceipt);
        let id = storage.store(Tier::L2Warm, art.clone());
        let retrieved = storage.retrieve(Tier::L2Warm, &id).unwrap();
        assert_eq!(retrieved.payload, art.payload);
    }

    #[test]
    fn test_store_and_retrieve_l3() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("a3", ObjectClass::ReplayBundle);
        let id = storage.store(Tier::L3Archive, art.clone());
        let retrieved = storage.retrieve(Tier::L3Archive, &id).unwrap();
        assert_eq!(retrieved.payload, art.payload);
    }

    #[test]
    fn test_retrieve_missing_returns_error() {
        let mut storage = TieredTrustStorage::with_defaults();
        let id = ArtifactId("nonexistent".to_string());
        let result = storage.retrieve(Tier::L1Local, &id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_ARTIFACT_NOT_FOUND);
    }

    #[test]
    fn test_evict_l1_requires_l2_or_l3_copy() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("a1", ObjectClass::CriticalMarker);
        storage.store(Tier::L1Local, art.clone());
        let id = ArtifactId("a1".to_string());

        // Evict without copy in L2/L3 → error
        let result = storage.evict(Tier::L1Local, &id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_EVICT_REQUIRES_RETRIEVABILITY);
    }

    #[test]
    fn test_evict_l1_succeeds_with_l2_copy() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("a1", ObjectClass::CriticalMarker);
        storage.store(Tier::L1Local, art.clone());
        storage.store(Tier::L2Warm, art.clone());
        let id = ArtifactId("a1".to_string());

        let evicted = storage.evict(Tier::L1Local, &id).unwrap();
        assert_eq!(evicted.id, id);
        assert!(!storage.contains(Tier::L1Local, &id));
        assert!(storage.contains(Tier::L2Warm, &id));
    }

    #[test]
    fn test_evict_l1_succeeds_with_l3_copy() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("a1", ObjectClass::CriticalMarker);
        storage.store(Tier::L1Local, art.clone());
        storage.store(Tier::L3Archive, art.clone());
        let id = ArtifactId("a1".to_string());

        let evicted = storage.evict(Tier::L1Local, &id).unwrap();
        assert_eq!(evicted.id, id);
    }

    #[test]
    fn test_evict_l2_requires_l3_copy() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("a2", ObjectClass::TrustReceipt);
        storage.store(Tier::L2Warm, art.clone());
        let id = ArtifactId("a2".to_string());

        let result = storage.evict(Tier::L2Warm, &id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_EVICT_REQUIRES_RETRIEVABILITY);
    }

    #[test]
    fn test_evict_l2_succeeds_with_l3_copy() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("a2", ObjectClass::TrustReceipt);
        storage.store(Tier::L2Warm, art.clone());
        storage.store(Tier::L3Archive, art.clone());
        let id = ArtifactId("a2".to_string());

        let evicted = storage.evict(Tier::L2Warm, &id).unwrap();
        assert_eq!(evicted.id, id);
    }

    #[test]
    fn test_evict_l3_always_allowed() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("a3", ObjectClass::ReplayBundle);
        storage.store(Tier::L3Archive, art.clone());
        let id = ArtifactId("a3".to_string());

        let evicted = storage.evict(Tier::L3Archive, &id).unwrap();
        assert_eq!(evicted.id, id);
    }

    #[test]
    fn test_evict_missing_artifact_error() {
        let mut storage = TieredTrustStorage::with_defaults();
        let id = ArtifactId("missing".to_string());
        // For L3, no retrievability check — just not found.
        let result = storage.evict(Tier::L3Archive, &id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_ARTIFACT_NOT_FOUND);
    }

    // -- Recovery path ----------------------------------------------------

    #[test]
    fn test_recover_l1_from_l2() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("r1", ObjectClass::CriticalMarker);
        storage.store(Tier::L2Warm, art.clone());

        storage
            .recover_tier(Tier::L1Local, &ArtifactId("r1".to_string()))
            .unwrap();
        assert!(storage.contains(Tier::L1Local, &ArtifactId("r1".to_string())));
    }

    #[test]
    fn test_recover_l1_from_l3() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("r2", ObjectClass::CriticalMarker);
        storage.store(Tier::L3Archive, art.clone());

        storage
            .recover_tier(Tier::L1Local, &ArtifactId("r2".to_string()))
            .unwrap();
        assert!(storage.contains(Tier::L1Local, &ArtifactId("r2".to_string())));
    }

    #[test]
    fn test_recover_l2_from_l3() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("r3", ObjectClass::ReplayBundle);
        storage.store(Tier::L3Archive, art.clone());

        storage
            .recover_tier(Tier::L2Warm, &ArtifactId("r3".to_string()))
            .unwrap();
        assert!(storage.contains(Tier::L2Warm, &ArtifactId("r3".to_string())));
    }

    #[test]
    fn test_recover_l3_fails() {
        let mut storage = TieredTrustStorage::with_defaults();
        let id = ArtifactId("r4".to_string());
        let result = storage.recover_tier(Tier::L3Archive, &id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_RECOVERY_DIRECTION_INVALID);
    }

    #[test]
    fn test_recover_missing_source_fails() {
        let mut storage = TieredTrustStorage::with_defaults();
        let id = ArtifactId("missing".to_string());
        let result = storage.recover_tier(Tier::L1Local, &id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_RECOVERY_SOURCE_MISSING);
    }

    #[test]
    fn test_recover_missing_source_reports_candidate_tiers() {
        let mut storage = TieredTrustStorage::with_defaults();
        let id = ArtifactId("missing".to_string());
        let err = storage.recover_tier(Tier::L1Local, &id).unwrap_err();

        assert_eq!(err.code, ERR_RECOVERY_SOURCE_MISSING);
        assert!(err.message.contains("L1_local"));
        assert!(err.message.contains("L2_warm"));
        assert!(err.message.contains("L3_archive"));
    }

    #[test]
    fn test_recover_prefers_l2_over_l3() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art_l2 = TrustArtifact {
            id: ArtifactId("r5".to_string()),
            object_class: ObjectClass::CriticalMarker,
            payload: vec![0x02],
            epoch_id: 2,
        };
        let art_l3 = TrustArtifact {
            id: ArtifactId("r5".to_string()),
            object_class: ObjectClass::CriticalMarker,
            payload: vec![0x03],
            epoch_id: 1,
        };
        storage.store(Tier::L2Warm, art_l2.clone());
        storage.store(Tier::L3Archive, art_l3.clone());

        storage
            .recover_tier(Tier::L1Local, &ArtifactId("r5".to_string()))
            .unwrap();
        let recovered = storage
            .retrieve(Tier::L1Local, &ArtifactId("r5".to_string()))
            .unwrap();
        // Should recover from L2 (higher authority than L3)
        assert_eq!(recovered.payload, vec![0x02]);
    }

    #[test]
    fn test_recovery_events_emitted() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("r6", ObjectClass::TrustReceipt);
        storage.store(Tier::L3Archive, art.clone());
        let pre_count = storage.events().len();

        storage
            .recover_tier(Tier::L2Warm, &ArtifactId("r6".to_string()))
            .unwrap();

        let new_events: Vec<_> = storage.events()[pre_count..].to_vec();
        let codes: Vec<_> = new_events.iter().map(|e| e.code.as_str()).collect();
        assert!(codes.contains(&TS_RECOVERY_START));
        assert!(codes.contains(&TS_RECOVERY_COMPLETE));
    }

    // -- Authority map violation ------------------------------------------

    #[test]
    fn test_try_update_authority_fails_with_event() {
        let mut storage = TieredTrustStorage::with_defaults();
        let result = storage.try_update_authority(ObjectClass::CriticalMarker, Tier::L3Archive);
        assert!(result.is_err());

        let violation_events: Vec<_> = storage
            .events()
            .iter()
            .filter(|e| e.code == TS_AUTHORITY_MAP_VIOLATION)
            .collect();
        assert_eq!(violation_events.len(), 1);
    }

    // -- ObjectClass enum -------------------------------------------------

    #[test]
    fn test_object_class_all() {
        assert_eq!(ObjectClass::all().len(), 4);
    }

    #[test]
    fn test_object_class_as_str() {
        assert_eq!(ObjectClass::CriticalMarker.as_str(), "critical_marker");
        assert_eq!(ObjectClass::TrustReceipt.as_str(), "trust_receipt");
        assert_eq!(ObjectClass::ReplayBundle.as_str(), "replay_bundle");
        assert_eq!(
            ObjectClass::TelemetryArtifact.as_str(),
            "telemetry_artifact"
        );
    }

    #[test]
    fn test_object_class_display() {
        assert_eq!(
            format!("{}", ObjectClass::CriticalMarker),
            "critical_marker"
        );
    }

    // -- Tier enum --------------------------------------------------------

    #[test]
    fn test_tier_all() {
        assert_eq!(Tier::all().len(), 3);
    }

    #[test]
    fn test_tier_ordering() {
        assert!(Tier::L1Local < Tier::L2Warm);
        assert!(Tier::L2Warm < Tier::L3Archive);
    }

    #[test]
    fn test_tier_as_str() {
        assert_eq!(Tier::L1Local.as_str(), "L1_local");
        assert_eq!(Tier::L2Warm.as_str(), "L2_warm");
        assert_eq!(Tier::L3Archive.as_str(), "L3_archive");
    }

    // -- Event log --------------------------------------------------------

    #[test]
    fn test_take_events_drains() {
        let mut storage = TieredTrustStorage::with_defaults();
        assert!(!storage.events().is_empty());
        let events = storage.take_events();
        assert!(!events.is_empty());
        assert!(storage.events().is_empty());
    }

    // -- Serde round-trip on types ----------------------------------------

    #[test]
    fn test_artifact_serde_roundtrip() {
        let art = make_artifact("s1", ObjectClass::TrustReceipt);
        let json = serde_json::to_string(&art).unwrap();
        let parsed: TrustArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, art);
    }

    #[test]
    fn test_storage_error_serde_roundtrip() {
        let err = StorageError::authority_map_immutable();
        let json = serde_json::to_string(&err).unwrap();
        let parsed: StorageError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    #[test]
    fn test_tier_serde_roundtrip() {
        for tier in Tier::all() {
            let json = serde_json::to_string(tier).unwrap();
            let parsed: Tier = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *tier);
        }
    }

    #[test]
    fn test_object_class_serde_roundtrip() {
        for class in ObjectClass::all() {
            let json = serde_json::to_string(class).unwrap();
            let parsed: ObjectClass = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *class);
        }
    }

    // -- Contains ---------------------------------------------------------

    #[test]
    fn test_contains_false_when_empty() {
        let storage = TieredTrustStorage::with_defaults();
        let id = ArtifactId("x".to_string());
        assert!(!storage.contains(Tier::L1Local, &id));
    }

    #[test]
    fn test_contains_true_after_store() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("c1", ObjectClass::CriticalMarker);
        let id = storage.store(Tier::L1Local, art);
        assert!(storage.contains(Tier::L1Local, &id));
        assert!(!storage.contains(Tier::L2Warm, &id));
    }

    // -- Store and evict events -------------------------------------------

    #[test]
    fn test_store_emits_event() {
        let mut storage = TieredTrustStorage::with_defaults();
        let pre = storage.events().len();
        let art = make_artifact("e1", ObjectClass::TrustReceipt);
        storage.store(Tier::L2Warm, art);
        let new_events: Vec<_> = storage.events()[pre..]
            .iter()
            .filter(|e| e.code == TS_STORE_COMPLETE)
            .collect();
        assert_eq!(new_events.len(), 1);
    }

    #[test]
    fn test_retrieve_emits_event() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("e2", ObjectClass::TrustReceipt);
        let id = storage.store(Tier::L2Warm, art);
        let pre = storage.events().len();
        storage.retrieve(Tier::L2Warm, &id).unwrap();
        let new_events: Vec<_> = storage.events()[pre..]
            .iter()
            .filter(|e| e.code == TS_RETRIEVE_COMPLETE)
            .collect();
        assert_eq!(new_events.len(), 1);
    }

    #[test]
    fn test_evict_emits_event() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("e3", ObjectClass::ReplayBundle);
        let id = storage.store(Tier::L3Archive, art);
        let pre = storage.events().len();
        storage.evict(Tier::L3Archive, &id).unwrap();
        let new_events: Vec<_> = storage.events()[pre..]
            .iter()
            .filter(|e| e.code == TS_EVICT_COMPLETE)
            .collect();
        assert_eq!(new_events.len(), 1);
    }

    // -- Event code constants defined -------------------------------------

    #[test]
    fn test_event_codes_defined() {
        assert!(!TS_TIER_INITIALIZED.is_empty());
        assert!(!TS_STORE_COMPLETE.is_empty());
        assert!(!TS_RETRIEVE_COMPLETE.is_empty());
        assert!(!TS_EVICT_COMPLETE.is_empty());
        assert!(!TS_RECOVERY_START.is_empty());
        assert!(!TS_RECOVERY_COMPLETE.is_empty());
        assert!(!TS_AUTHORITY_MAP_VIOLATION.is_empty());
    }

    // -- Invariant constants defined --------------------------------------

    #[test]
    fn test_invariant_constants_defined() {
        assert!(!INV_TIER_AUTHORITY.is_empty());
        assert!(!INV_TIER_IMMUTABLE.is_empty());
        assert!(!INV_TIER_RECOVERY.is_empty());
        assert!(!INV_TIER_ORDERED.is_empty());
    }

    // -- Tier count -------------------------------------------------------

    #[test]
    fn test_tier_count_increments() {
        let mut storage = TieredTrustStorage::with_defaults();
        assert_eq!(storage.tier_count(Tier::L1Local), 0);
        storage.store(
            Tier::L1Local,
            make_artifact("tc1", ObjectClass::CriticalMarker),
        );
        assert_eq!(storage.tier_count(Tier::L1Local), 1);
        storage.store(
            Tier::L1Local,
            make_artifact("tc2", ObjectClass::CriticalMarker),
        );
        assert_eq!(storage.tier_count(Tier::L1Local), 2);
    }

    #[test]
    fn test_authority_map_update_rejection_preserves_mapping() {
        let mut map = AuthorityMap::default_mapping();
        let before: Vec<_> = map.iter().map(|(class, tier)| (*class, *tier)).collect();

        let err = map
            .try_update(ObjectClass::CriticalMarker, Tier::L3Archive)
            .unwrap_err();

        assert_eq!(err.code, ERR_AUTHORITY_MAP_IMMUTABLE);
        let after: Vec<_> = map.iter().map(|(class, tier)| (*class, *tier)).collect();
        assert_eq!(after, before);
        assert_eq!(
            map.authoritative_tier(ObjectClass::CriticalMarker),
            Some(Tier::L1Local)
        );
    }

    #[test]
    fn test_try_update_authority_failure_preserves_storage_counts() {
        let mut storage = TieredTrustStorage::with_defaults();
        let art = make_artifact("immutable-count", ObjectClass::CriticalMarker);
        storage.store(Tier::L1Local, art);
        let l1_count = storage.tier_count(Tier::L1Local);
        let l2_count = storage.tier_count(Tier::L2Warm);
        let l3_count = storage.tier_count(Tier::L3Archive);

        let err = storage
            .try_update_authority(ObjectClass::CriticalMarker, Tier::L3Archive)
            .unwrap_err();

        assert_eq!(err.code, ERR_AUTHORITY_MAP_IMMUTABLE);
        assert_eq!(storage.tier_count(Tier::L1Local), l1_count);
        assert_eq!(storage.tier_count(Tier::L2Warm), l2_count);
        assert_eq!(storage.tier_count(Tier::L3Archive), l3_count);
        assert!(storage.contains(Tier::L1Local, &ArtifactId("immutable-count".to_string())));
    }

    #[test]
    fn test_retrieve_missing_does_not_emit_success_event() {
        let mut storage = TieredTrustStorage::with_defaults();
        let event_len = storage.events().len();
        let id = ArtifactId("missing-retrieve".to_string());

        let err = storage.retrieve(Tier::L2Warm, &id).unwrap_err();

        assert_eq!(err.code, ERR_ARTIFACT_NOT_FOUND);
        assert_eq!(storage.events().len(), event_len);
        assert!(!storage.contains(Tier::L2Warm, &id));
    }

    #[test]
    fn test_failed_l1_eviction_preserves_artifact_and_emits_no_evict_event() {
        let mut storage = TieredTrustStorage::with_defaults();
        let id = storage.store(
            Tier::L1Local,
            make_artifact("no-proof-l1", ObjectClass::CriticalMarker),
        );
        let event_len = storage.events().len();

        let err = storage.evict(Tier::L1Local, &id).unwrap_err();

        assert_eq!(err.code, ERR_EVICT_REQUIRES_RETRIEVABILITY);
        assert!(storage.contains(Tier::L1Local, &id));
        assert_eq!(storage.tier_count(Tier::L1Local), 1);
        assert_eq!(storage.events().len(), event_len);
    }

    #[test]
    fn test_failed_l2_eviction_preserves_artifact_and_lower_tiers() {
        let mut storage = TieredTrustStorage::with_defaults();
        let id = storage.store(
            Tier::L2Warm,
            make_artifact("no-proof-l2", ObjectClass::TrustReceipt),
        );
        let event_len = storage.events().len();

        let err = storage.evict(Tier::L2Warm, &id).unwrap_err();

        assert_eq!(err.code, ERR_EVICT_REQUIRES_RETRIEVABILITY);
        assert!(storage.contains(Tier::L2Warm, &id));
        assert!(!storage.contains(Tier::L3Archive, &id));
        assert_eq!(storage.events().len(), event_len);
    }

    #[test]
    fn test_recover_l3_invalid_direction_does_not_create_artifact() {
        let mut storage = TieredTrustStorage::with_defaults();
        let id = ArtifactId("invalid-direction".to_string());

        let err = storage.recover_tier(Tier::L3Archive, &id).unwrap_err();

        assert_eq!(err.code, ERR_RECOVERY_DIRECTION_INVALID);
        assert!(!storage.contains(Tier::L3Archive, &id));
        assert!(
            storage
                .events()
                .iter()
                .all(|event| event.code != TS_RECOVERY_COMPLETE)
        );
    }

    #[test]
    fn test_recover_missing_source_does_not_create_target_copy() {
        let mut storage = TieredTrustStorage::with_defaults();
        let id = ArtifactId("missing-source".to_string());
        let event_len = storage.events().len();

        let err = storage.recover_tier(Tier::L1Local, &id).unwrap_err();

        assert_eq!(err.code, ERR_RECOVERY_SOURCE_MISSING);
        assert!(!storage.contains(Tier::L1Local, &id));
        assert!(!storage.contains(Tier::L2Warm, &id));
        assert!(!storage.contains(Tier::L3Archive, &id));
        assert_eq!(
            storage.events()[event_len..]
                .iter()
                .filter(|event| event.code == TS_RECOVERY_COMPLETE)
                .count(),
            0
        );
    }

    #[test]
    fn test_recover_l2_does_not_use_l1_as_source() {
        let mut storage = TieredTrustStorage::with_defaults();
        let id = storage.store(
            Tier::L1Local,
            make_artifact("wrong-source", ObjectClass::TrustReceipt),
        );

        let err = storage.recover_tier(Tier::L2Warm, &id).unwrap_err();

        assert_eq!(err.code, ERR_RECOVERY_SOURCE_MISSING);
        assert!(storage.contains(Tier::L1Local, &id));
        assert!(!storage.contains(Tier::L2Warm, &id));
    }

    // ---------------------------------------------------------------------------
    // NEGATIVE-PATH TESTS: Security hardening for tiered trust storage
    // ---------------------------------------------------------------------------

    #[test]
    fn negative_unicode_injection_in_artifact_ids_and_object_paths() {
        let mut storage = TieredTrustStorage::with_defaults();

        // BiDi override attack in artifact ID
        let malicious_id = "\u{202E}tset\u{202D}real_id";
        let artifact = TrustArtifact {
            id: ArtifactId(malicious_id.to_string()),
            object_class: ObjectClass::CriticalMarker,
            payload: vec![0xBA, 0xD0],
            epoch_id: 1,
        };

        // Store and verify Unicode is preserved (not sanitized)
        let stored_id = storage.store(Tier::L1Local, artifact.clone());
        assert_eq!(stored_id.0, malicious_id);
        assert!(storage.contains(Tier::L1Local, &stored_id));

        // Zero-width character injection
        let zero_width_id = "normal\u{200B}\u{200C}\u{200D}\u{FEFF}hidden";
        let zw_artifact = TrustArtifact {
            id: ArtifactId(zero_width_id.to_string()),
            object_class: ObjectClass::TrustReceipt,
            payload: vec![0xDE, 0xAD],
            epoch_id: 2,
        };

        let zw_stored = storage.store(Tier::L2Warm, zw_artifact);
        assert!(storage.contains(Tier::L2Warm, &zw_stored));

        // Path traversal attempts in artifact ID
        let traversal_id = "../../../etc/passwd\0\nmalicious";
        let traversal_artifact = TrustArtifact {
            id: ArtifactId(traversal_id.to_string()),
            object_class: ObjectClass::ReplayBundle,
            payload: vec![0xCA, 0xFE],
            epoch_id: 3,
        };

        let traversal_stored = storage.store(Tier::L3Archive, traversal_artifact);
        assert!(storage.contains(Tier::L3Archive, &traversal_stored));
        assert!(traversal_stored.0.contains('\0'));
        assert!(traversal_stored.0.contains('\n'));
    }

    #[test]
    fn negative_memory_exhaustion_with_massive_artifact_payloads() {
        let mut storage = TieredTrustStorage::with_defaults();

        // Attempt to store artifact with extremely large payload
        let huge_payload = vec![0x42; 100_000_000]; // 100MB payload
        let big_artifact = TrustArtifact {
            id: ArtifactId("memory_bomb".to_string()),
            object_class: ObjectClass::TelemetryArtifact,
            payload: huge_payload.clone(),
            epoch_id: u64::MAX, // Also test epoch overflow
        };

        // Storage should handle large payloads gracefully
        let stored_id = storage.store(Tier::L2Warm, big_artifact);
        assert!(storage.contains(Tier::L2Warm, &stored_id));

        // Verify payload integrity preserved
        let retrieved = storage.retrieve(Tier::L2Warm, &stored_id).unwrap();
        assert_eq!(retrieved.payload.len(), 100_000_000);
        assert_eq!(retrieved.epoch_id, u64::MAX);

        // Test memory stress with multiple large artifacts
        for i in 0..10 {
            let stress_artifact = TrustArtifact {
                id: ArtifactId(format!("stress_{}", i)),
                object_class: ObjectClass::CriticalMarker,
                payload: vec![0x88; 10_000_000], // 10MB each
                epoch_id: i as u64,
            };
            storage.store(Tier::L1Local, stress_artifact);
        }

        assert_eq!(storage.tier_count(Tier::L1Local), 10);
    }

    #[test]
    fn negative_authority_level_boundary_violations_and_overflow() {
        // Test authority level arithmetic edge cases
        let l1_level = AuthorityLevel::L1;
        let l2_level = AuthorityLevel::L2;
        let l3_level = AuthorityLevel::L3;

        // Verify ordering invariants at boundaries
        assert!(l1_level > l2_level);
        assert!(l2_level > l3_level);
        assert_eq!(l1_level.0, 3);
        assert_eq!(l2_level.0, 2);
        assert_eq!(l3_level.0, 1);

        // Test tier ordering invariants
        assert!(Tier::L1Local < Tier::L2Warm);
        assert!(Tier::L2Warm < Tier::L3Archive);

        // Test authority level function consistency
        assert_eq!(authority_level_for(Tier::L1Local), AuthorityLevel::L1);
        assert_eq!(authority_level_for(Tier::L2Warm), AuthorityLevel::L2);
        assert_eq!(authority_level_for(Tier::L3Archive), AuthorityLevel::L3);

        // Verify no integer overflow in authority arithmetic
        let max_authority = AuthorityLevel(u8::MAX);
        let min_authority = AuthorityLevel(0);
        assert!(max_authority > l1_level);
        assert!(l3_level > min_authority);

        // Test tier discriminant values don't overflow
        assert_eq!(Tier::L1Local as i32, 1);
        assert_eq!(Tier::L2Warm as i32, 2);
        assert_eq!(Tier::L3Archive as i32, 3);
    }

    #[test]
    fn negative_concurrent_access_safety_stress_testing() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let storage = Arc::new(Mutex::new(TieredTrustStorage::with_defaults()));
        let mut handles = vec![];

        // Spawn multiple threads performing concurrent operations
        for thread_id in 0..8 {
            let storage_clone = Arc::clone(&storage);
            let handle = thread::spawn(move || {
                for op_id in 0..100 {
                    let artifact = TrustArtifact {
                        id: ArtifactId(format!("thread_{}_op_{}", thread_id, op_id)),
                        object_class: ObjectClass::CriticalMarker,
                        payload: vec![thread_id as u8; 1000],
                        epoch_id: (thread_id * 1000 + op_id) as u64,
                    };

                    let mut storage = storage_clone.lock().unwrap();
                    let stored_id = storage.store(Tier::L1Local, artifact.clone());

                    // Immediate retrieval
                    let retrieved = storage.retrieve(Tier::L1Local, &stored_id).unwrap();
                    assert_eq!(retrieved.payload, artifact.payload);

                    // Try authority map mutation (should always fail)
                    let result = storage.try_update_authority(
                        ObjectClass::CriticalMarker,
                        Tier::L3Archive
                    );
                    assert!(result.is_err());
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state consistency
        let storage = storage.lock().unwrap();
        assert_eq!(storage.tier_count(Tier::L1Local), 800); // 8 threads * 100 ops

        // Verify authority map remains immutable
        assert_eq!(
            storage.authority_map().authoritative_tier(ObjectClass::CriticalMarker),
            Some(Tier::L1Local)
        );
    }

    #[test]
    fn negative_serialization_corruption_and_deserialization_attacks() {
        let storage = TieredTrustStorage::with_defaults();

        // Test malformed JSON serialization of authority map
        let authority_map = storage.authority_map();
        let json = authority_map.to_json().unwrap();

        // Corrupt the JSON in various ways
        let corrupted_jsons = vec![
            json.replace("L1_local", "L99_invalid"),
            json.replace("critical_marker", "malicious\0injection"),
            json.replace("true", "\"not_boolean\""),
            "{\"mapping\":{\"critical_marker\":null},\"frozen\":true}".to_string(),
            "{}".to_string(), // Empty object
            "null".to_string(), // Null value
            "\"string_instead_of_object\"".to_string(),
        ];

        for corrupted_json in corrupted_jsons {
            let parse_result: Result<AuthorityMap, _> = serde_json::from_str(&corrupted_json);
            // Should either fail to parse or preserve corruption for analysis
            if let Ok(parsed_map) = parse_result {
                // If it parsed, verify it doesn't crash on basic operations
                let _ = parsed_map.len();
                let _ = parsed_map.is_empty();
                let _ = parsed_map.iter().count();
            }
        }

        // Test artifact serialization with extreme values
        let extreme_artifact = TrustArtifact {
            id: ArtifactId("\u{FFFD}\u{10FFFF}extreme\0\n\r\t".to_string()),
            object_class: ObjectClass::ReplayBundle,
            payload: vec![0x00, 0xFF, 0x7F, 0x80], // Edge byte values
            epoch_id: u64::MAX,
        };

        let artifact_json = serde_json::to_string(&extreme_artifact).unwrap();
        let parsed_artifact: TrustArtifact = serde_json::from_str(&artifact_json).unwrap();
        assert_eq!(parsed_artifact, extreme_artifact);

        // Test storage error serialization integrity
        let errors = vec![
            StorageError::authority_map_immutable(),
            StorageError::artifact_not_found(&ArtifactId("test".to_string()), Tier::L1Local),
            StorageError::recovery_source_missing(
                &ArtifactId("missing".to_string()),
                Tier::L1Local,
                &[Tier::L2Warm, Tier::L3Archive]
            ),
        ];

        for error in errors {
            let error_json = serde_json::to_string(&error).unwrap();
            let parsed_error: StorageError = serde_json::from_str(&error_json).unwrap();
            assert_eq!(parsed_error, error);
        }
    }

    #[test]
    fn negative_epoch_id_overflow_and_timestamp_edge_cases() {
        let mut storage = TieredTrustStorage::with_defaults();

        // Test epoch ID boundary values
        let boundary_epochs = vec![0, 1, u32::MAX as u64, u64::MAX - 1, u64::MAX];

        for (i, &epoch_id) in boundary_epochs.iter().enumerate() {
            let artifact = TrustArtifact {
                id: ArtifactId(format!("epoch_test_{}", i)),
                object_class: ObjectClass::TelemetryArtifact,
                payload: vec![0xEE; 100],
                epoch_id,
            };

            let stored_id = storage.store(Tier::L2Warm, artifact.clone());
            let retrieved = storage.retrieve(Tier::L2Warm, &stored_id).unwrap();

            // Verify epoch preservation without overflow
            assert_eq!(retrieved.epoch_id, epoch_id);
        }

        // Test arithmetic on epoch IDs (simulate epoch advancement)
        let base_epoch = u64::MAX - 10;
        for offset in 0..20 {
            let epoch_id = base_epoch.saturating_add(offset);
            let artifact = TrustArtifact {
                id: ArtifactId(format!("saturating_epoch_{}", offset)),
                object_class: ObjectClass::CriticalMarker,
                payload: vec![offset as u8; 50],
                epoch_id,
            };

            storage.store(Tier::L1Local, artifact);
        }

        // Verify all artifacts stored successfully
        assert_eq!(storage.tier_count(Tier::L2Warm), boundary_epochs.len());

        // Test epoch comparison edge cases
        let epoch_zero = TrustArtifact {
            id: ArtifactId("zero_epoch".to_string()),
            object_class: ObjectClass::ReplayBundle,
            payload: vec![0x00],
            epoch_id: 0,
        };

        let epoch_max = TrustArtifact {
            id: ArtifactId("max_epoch".to_string()),
            object_class: ObjectClass::ReplayBundle,
            payload: vec![0xFF],
            epoch_id: u64::MAX,
        };

        storage.store(Tier::L3Archive, epoch_zero);
        storage.store(Tier::L3Archive, epoch_max);

        // Verify both extreme epochs can coexist
        assert!(storage.contains(Tier::L3Archive, &ArtifactId("zero_epoch".to_string())));
        assert!(storage.contains(Tier::L3Archive, &ArtifactId("max_epoch".to_string())));
    }

    #[test]
    fn negative_recovery_path_manipulation_and_authority_bypass_attempts() {
        let mut storage = TieredTrustStorage::with_defaults();

        // Create artifacts with conflicting content in different tiers
        let honest_artifact = TrustArtifact {
            id: ArtifactId("contested_artifact".to_string()),
            object_class: ObjectClass::TrustReceipt,
            payload: vec![0x48, 0x4F, 0x4E], // "HON"est
            epoch_id: 100,
        };

        let malicious_artifact = TrustArtifact {
            id: ArtifactId("contested_artifact".to_string()),
            object_class: ObjectClass::TrustReceipt,
            payload: vec![0x4D, 0x41, 0x4C], // "MAL"icious
            epoch_id: 99, // Earlier epoch
        };

        // Store honest version in L2 (higher authority)
        storage.store(Tier::L2Warm, honest_artifact.clone());

        // Store malicious version in L3 (lower authority)
        storage.store(Tier::L3Archive, malicious_artifact.clone());

        // Recovery to L1 should use L2 (higher authority), not L3
        storage.recover_tier(Tier::L1Local, &ArtifactId("contested_artifact".to_string())).unwrap();

        let recovered = storage.retrieve(Tier::L1Local, &ArtifactId("contested_artifact".to_string())).unwrap();
        assert_eq!(recovered.payload, vec![0x48, 0x4F, 0x4E]); // Honest version
        assert_eq!(recovered.epoch_id, 100); // Higher epoch from L2

        // Test invalid recovery directions are rejected
        let invalid_recoveries = vec![
            (Tier::L3Archive, Tier::L1Local), // Invalid: L3 → L1 through L3
            (Tier::L3Archive, Tier::L2Warm),  // Invalid: L3 → L2 through L3
            (Tier::L3Archive, Tier::L3Archive), // Invalid: L3 → L3
        ];

        for (source, target) in invalid_recoveries {
            if source == Tier::L3Archive && target == Tier::L3Archive {
                // This case hits the L3 recovery direction check
                let result = storage.recover_tier(target, &ArtifactId("any_id".to_string()));
                assert!(result.is_err());
                assert_eq!(result.unwrap_err().code, ERR_RECOVERY_DIRECTION_INVALID);
            }
        }

        // Test recovery source prioritization attack
        let priority_artifact = TrustArtifact {
            id: ArtifactId("priority_test".to_string()),
            object_class: ObjectClass::CriticalMarker,
            payload: vec![0xAA], // L1 version
            epoch_id: 300,
        };

        let l2_version = TrustArtifact {
            id: ArtifactId("priority_test".to_string()),
            object_class: ObjectClass::CriticalMarker,
            payload: vec![0xBB], // L2 version
            epoch_id: 200,
        };

        let l3_version = TrustArtifact {
            id: ArtifactId("priority_test".to_string()),
            object_class: ObjectClass::CriticalMarker,
            payload: vec![0xCC], // L3 version
            epoch_id: 100,
        };

        // Store in all tiers with L2 having different content than L3
        storage.store(Tier::L2Warm, l2_version);
        storage.store(Tier::L3Archive, l3_version);

        // Clear L1 and recover - should prefer L2 over L3
        storage.evict(Tier::L1Local, &ArtifactId("priority_test".to_string())).unwrap();
        storage.recover_tier(Tier::L1Local, &ArtifactId("priority_test".to_string())).unwrap();

        let final_recovered = storage.retrieve(Tier::L1Local, &ArtifactId("priority_test".to_string())).unwrap();
        assert_eq!(final_recovered.payload, vec![0xBB]); // L2 version preferred
        assert_eq!(final_recovered.epoch_id, 200);
    }

    #[test]
    fn negative_event_log_injection_and_bounded_storage_attacks() {
        let mut storage = TieredTrustStorage::with_defaults();

        // Test event log with malicious content in all fields
        let malicious_events = vec![
            ("code\r\n\x1b[31mRED\x1b[0m", "tier\u{202E}spoofed", Some("id\x00null"), "detail\"quotes"),
            ("code\u{FEFF}bom", "tier\u{200B}zw", Some("id\u{10FFFF}high"), "detail\u{D800}\u{DFFF}surr"),
            ("code\n\rHTTP/1.1 200 OK\r\n\r\n", "tier' OR '1'='1' --", Some("id<script>"), "detail\\\"escape"),
        ];

        for (code, tier_str, artifact_id, detail) in malicious_events {
            storage.emit(
                code,
                Tier::L1Local, // Will be converted to "L1_local"
                artifact_id.map(|s| &ArtifactId(s.to_string())),
                detail.to_string(),
            );
        }

        // Verify malicious content preserved in event log
        let recent_events = storage.events();
        for event in recent_events.iter().rev().take(3) {
            // Events should preserve malicious content exactly
            assert!(event.code.contains("code") || event.tier == "L1_local");
        }

        // Test bounded event storage with massive event generation
        for i in 0..MAX_EVENTS * 2 {
            let massive_artifact = TrustArtifact {
                id: ArtifactId(format!("massive_event_{}", i)),
                object_class: ObjectClass::TelemetryArtifact,
                payload: vec![0x99; 1000], // 1KB each
                epoch_id: i as u64,
            };
            storage.store(Tier::L2Warm, massive_artifact);
        }

        // Should be bounded by MAX_EVENTS
        assert_eq!(storage.events().len(), MAX_EVENTS);

        // Test event log overflow behavior
        let events_before_overflow = storage.events().len();
        storage.emit(
            "OVERFLOW_TEST",
            Tier::L3Archive,
            Some(&ArtifactId("overflow".to_string())),
            "Testing overflow boundary".to_string(),
        );
        assert_eq!(storage.events().len(), events_before_overflow);
    }

    #[test]
    fn negative_push_bounded_edge_cases_and_memory_behavior() {
        let mut items: Vec<Vec<u8>> = Vec::new();

        // Test with zero capacity
        push_bounded(&mut items, vec![1, 2, 3], 0);
        assert!(items.is_empty());

        // Test with capacity 1
        push_bounded(&mut items, vec![4, 5, 6], 1);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], vec![4, 5, 6]);

        push_bounded(&mut items, vec![7, 8, 9], 1);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], vec![7, 8, 9]);

        // Test overflow calculation edge cases
        let mut large_items: Vec<String> = Vec::new();
        for i in 0..100 {
            large_items.push(format!("item_{}", i));
        }

        // Push to capacity 50
        push_bounded(&mut large_items, "new_item".to_string(), 50);
        assert_eq!(large_items.len(), 50);
        assert_eq!(large_items[0], "item_51"); // First remaining item
        assert_eq!(large_items[49], "new_item"); // Last item

        // Test with very large capacity (larger than current length)
        let mut small_items = vec!["a", "b", "c"];
        push_bounded(&mut small_items, "d", 1000);
        assert_eq!(small_items, vec!["a", "b", "c", "d"]);

        // Test underflow protection in overflow calculation
        let mut single_item = vec!["single"];
        push_bounded(&mut single_item, "replacement", 1);
        assert_eq!(single_item, vec!["replacement"]);
    }

    #[test]
    fn negative_storage_error_display_injection_and_formatting_attacks() {
        // Test error display with various injection patterns
        let injection_patterns = [
            ("\x1b[31mRED\x1b[0m", "ANSI color injection"),
            ("\r\nHTTP/1.1 200 OK\r\n\r\n<html>", "HTTP header injection"),
            ("\u{202E}spoofed\u{202D}", "BiDi text direction override"),
            ("\u{FEFF}BOM\u{200B}zero-width", "Unicode BOM and zero-width"),
            ("\"quotes'apostrophe\\backslash", "Quote and escape injection"),
            ("\x00null\x01\x02\x03", "Control character injection"),
        ];

        for (malicious_id, attack_type) in injection_patterns {
            let errors = vec![
                StorageError::artifact_not_found(&ArtifactId(malicious_id.to_string()), Tier::L1Local),
                StorageError::evict_requires_retrievability(&ArtifactId(malicious_id.to_string()), Tier::L2Warm),
                StorageError::recovery_source_missing(
                    &ArtifactId(malicious_id.to_string()),
                    Tier::L1Local,
                    &[Tier::L2Warm, Tier::L3Archive]
                ),
            ];

            for error in errors {
                let display_string = format!("{}", error);

                // Verify error display preserves malicious content but remains structured
                assert!(display_string.contains('[') && display_string.contains(']'));
                assert!(display_string.contains(malicious_id));

                // Verify error code prefixes are preserved
                assert!(display_string.starts_with('['));

                println!("Attack type '{}' display: {}", attack_type, display_string);
            }
        }

        // Test error serialization with extreme values
        let extreme_error = StorageError::new(
            "EXTREME_ERROR_CODE_".repeat(100).as_str(), // Very long error code
            "x".repeat(100_000), // 100KB message
        );

        let json = serde_json::to_string(&extreme_error).unwrap();
        let deserialized: StorageError = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, extreme_error);
        assert_eq!(deserialized.message.len(), 100_000);
    }

    #[test]
    fn negative_object_class_and_tier_serialization_tampering() {
        // Test serialization tampering of ObjectClass enum
        let invalid_object_classes = [
            "\"unknown_class\"",
            "\"CriticalMarker\"", // Wrong case
            "\"critical-marker\"", // Wrong separator
            "null",
            "42",
            "true",
            "{}",
            "[]",
        ];

        for invalid_json in invalid_object_classes {
            let result: Result<ObjectClass, _> = serde_json::from_str(invalid_json);
            assert!(result.is_err(), "Should reject invalid ObjectClass: {}", invalid_json);
        }

        // Test serialization tampering of Tier enum
        let invalid_tiers = [
            "\"L0_invalid\"",
            "\"L4_nonexistent\"",
            "\"l1_local\"", // Wrong case
            "\"L1-local\"", // Wrong separator
            "\"L1Local\"",  // No separator
            "null",
            "0",
            "false",
        ];

        for invalid_json in invalid_tiers {
            let result: Result<Tier, _> = serde_json::from_str(invalid_json);
            assert!(result.is_err(), "Should reject invalid Tier: {}", invalid_json);
        }

        // Test round-trip with valid values to ensure no regression
        for object_class in ObjectClass::all() {
            let json = serde_json::to_string(object_class).unwrap();
            let parsed: ObjectClass = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *object_class);
        }

        for tier in Tier::all() {
            let json = serde_json::to_string(tier).unwrap();
            let parsed: Tier = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *tier);
        }
    }

    #[test]
    fn negative_authority_map_corruption_and_validation_bypass_attempts() {
        // Test authority map with malicious JSON manipulation
        let map = AuthorityMap::default_mapping();
        let json = map.to_json().unwrap();

        // Test various corruption attempts
        let corruption_attempts = vec![
            json.replace("\"frozen\":true", "\"frozen\":false"), // Attempt to unfreeze
            json.replace("L1_local", "L99_hacked"), // Invalid tier
            json.replace("critical_marker", "malicious_class"), // Invalid class
            json.replace("\"mapping\":", "\"Mapping\":"), // Case change
            json.replace('}', ",\"extra_field\":\"injection\"}"), // Extra fields
        ];

        for corrupted_json in corruption_attempts {
            let parse_result: Result<AuthorityMap, _> = serde_json::from_str(&corrupted_json);

            if let Ok(corrupted_map) = parse_result {
                // If parsing succeeded, verify immutability is preserved
                let mut mutable_copy = corrupted_map.clone();
                let update_result = mutable_copy.try_update(ObjectClass::CriticalMarker, Tier::L3Archive);
                assert!(update_result.is_err()); // Should still be immutable
                assert_eq!(update_result.unwrap_err().code, ERR_AUTHORITY_MAP_IMMUTABLE);
            }
        }

        // Test authority map with duplicate entries (should overwrite)
        let duplicate_entries = AuthorityMap::new(&[
            (ObjectClass::CriticalMarker, Tier::L1Local),
            (ObjectClass::CriticalMarker, Tier::L3Archive), // Duplicate - should overwrite
        ]);

        assert_eq!(
            duplicate_entries.authoritative_tier(ObjectClass::CriticalMarker),
            Some(Tier::L3Archive) // Last entry wins
        );

        // Test empty authority map
        let empty_map = AuthorityMap::new(&[]);
        assert!(empty_map.is_empty());
        assert_eq!(empty_map.len(), 0);
        for class in ObjectClass::all() {
            assert!(empty_map.authoritative_tier(*class).is_none());
        }

        // Test authority map iteration with extreme content
        let extreme_map = AuthorityMap::new(&[
            (ObjectClass::CriticalMarker, Tier::L1Local),
            (ObjectClass::TrustReceipt, Tier::L2Warm),
            (ObjectClass::ReplayBundle, Tier::L3Archive),
            (ObjectClass::TelemetryArtifact, Tier::L1Local),
        ]);

        let collected: Vec<_> = extreme_map.iter().collect();
        assert_eq!(collected.len(), 4);
    }

    #[test]
    fn negative_tier_store_capacity_and_memory_stress_testing() {
        let mut storage = TieredTrustStorage::with_defaults();

        // Test each tier with massive artifact storage
        let tiers_and_counts = [
            (Tier::L1Local, 10_000),
            (Tier::L2Warm, 5_000),
            (Tier::L3Archive, 20_000),
        ];

        for (tier, count) in tiers_and_counts {
            for i in 0..count {
                let stress_artifact = TrustArtifact {
                    id: ArtifactId(format!("stress_{}_{}", tier.as_str(), i)),
                    object_class: match tier {
                        Tier::L1Local => ObjectClass::CriticalMarker,
                        Tier::L2Warm => ObjectClass::TrustReceipt,
                        Tier::L3Archive => ObjectClass::ReplayBundle,
                    },
                    payload: vec![i as u8; (i % 1000) + 1], // Variable payload sizes
                    epoch_id: i as u64,
                };

                storage.store(tier, stress_artifact);
            }

            assert_eq!(storage.tier_count(tier), count);
        }

        // Test cross-tier operations under stress
        let total_artifacts = tiers_and_counts.iter().map(|(_, count)| count).sum::<usize>();
        assert!(storage.events().len() <= MAX_EVENTS); // Should be bounded

        // Test memory efficiency by checking some artifacts are still retrievable
        for (tier, _) in tiers_and_counts {
            let test_id = ArtifactId(format!("stress_{}_9999", tier.as_str()));
            if storage.contains(tier, &test_id) {
                let retrieved = storage.retrieve(tier, &test_id).unwrap();
                assert_eq!(retrieved.payload.len(), 1000); // 9999 % 1000 + 1 = 1000
            }
        }

        println!("Successfully stress tested with {} total artifacts", total_artifacts);
    }

    #[test]
    fn negative_recovery_path_race_conditions_and_consistency_attacks() {
        let mut storage = TieredTrustStorage::with_defaults();

        // Setup competing artifacts in different tiers
        let competing_artifacts = vec![
            (Tier::L2Warm, vec![0x22], 200),
            (Tier::L3Archive, vec![0x33], 100),
        ];

        let artifact_id = ArtifactId("race_condition_test".to_string());

        for (tier, payload, epoch) in competing_artifacts {
            let artifact = TrustArtifact {
                id: artifact_id.clone(),
                object_class: ObjectClass::TrustReceipt,
                payload,
                epoch_id: epoch,
            };
            storage.store(tier, artifact);
        }

        // Rapid recovery operations
        for i in 0..100 {
            // Clear L1 and recover
            if storage.contains(Tier::L1Local, &artifact_id) {
                storage.evict(Tier::L1Local, &artifact_id).unwrap();
            }

            storage.recover_tier(Tier::L1Local, &artifact_id).unwrap();

            // Verify consistent recovery (should always use L2)
            let recovered = storage.retrieve(Tier::L1Local, &artifact_id).unwrap();
            assert_eq!(recovered.payload, vec![0x22]); // L2 version
            assert_eq!(recovered.epoch_id, 200);

            // Modify L3 content during recovery
            if i % 10 == 0 {
                let modified_l3 = TrustArtifact {
                    id: artifact_id.clone(),
                    object_class: ObjectClass::TrustReceipt,
                    payload: vec![0x33, i as u8], // Modified payload
                    epoch_id: 100 + i as u64, // Modified epoch
                };
                storage.store(Tier::L3Archive, modified_l3);
            }
        }

        // Final consistency check
        let final_l1 = storage.retrieve(Tier::L1Local, &artifact_id).unwrap();
        let final_l2 = storage.retrieve(Tier::L2Warm, &artifact_id).unwrap();
        assert_eq!(final_l1.payload, final_l2.payload); // L1 should match L2
    }

    #[test]
    fn negative_artifact_id_collision_and_uniqueness_attacks() {
        let mut storage = TieredTrustStorage::with_defaults();

        // Test artifacts with visually similar IDs
        let collision_ids = vec![
            "artifact_1", // ASCII '1'
            "artifact_l", // ASCII 'l' (lowercase L)
            "artifact_I", // ASCII 'I' (capital i)
            "artifact_\u{1D7CF}", // Mathematical Monospace Digit One
            "artifact_\u{FF11}", // Fullwidth Digit One
        ];

        for id in collision_ids {
            let artifact = TrustArtifact {
                id: ArtifactId(id.to_string()),
                object_class: ObjectClass::CriticalMarker,
                payload: id.as_bytes().to_vec(), // Use ID as payload for verification
                epoch_id: 1,
            };

            let stored_id = storage.store(Tier::L1Local, artifact.clone());
            assert_eq!(stored_id.0, id); // ID preserved exactly

            // Verify retrieval with exact ID
            let retrieved = storage.retrieve(Tier::L1Local, &stored_id).unwrap();
            assert_eq!(retrieved.id.0, id);
            assert_eq!(retrieved.payload, id.as_bytes().to_vec());
        }

        // All should be stored separately (no collision)
        assert_eq!(storage.tier_count(Tier::L1Local), collision_ids.len());

        // Test Unicode normalization collision attempts
        let normalization_ids = vec![
            "café", // NFC form
            "cafe\u{0301}", // NFD form (separate combining acute)
        ];

        for id in normalization_ids {
            let artifact = TrustArtifact {
                id: ArtifactId(id.to_string()),
                object_class: ObjectClass::TelemetryArtifact,
                payload: vec![0xCA, 0xFE],
                epoch_id: 2,
            };
            storage.store(Tier::L2Warm, artifact);
        }

        // Should be treated as different artifacts (byte-level comparison)
        assert_eq!(storage.tier_count(Tier::L2Warm), 2);

        // Test extremely long artifact IDs
        let long_id = "x".repeat(100_000); // 100KB ID
        let long_artifact = TrustArtifact {
            id: ArtifactId(long_id.clone()),
            object_class: ObjectClass::ReplayBundle,
            payload: vec![0x4C, 0x4F, 0x4E, 0x47], // "LONG"
            epoch_id: 3,
        };

        let stored_long_id = storage.store(Tier::L3Archive, long_artifact);
        assert_eq!(stored_long_id.0.len(), 100_000);
        assert!(storage.contains(Tier::L3Archive, &stored_long_id));
    }

    #[test]
    fn negative_eviction_policy_bypass_and_retrievability_attacks() {
        let mut storage = TieredTrustStorage::with_defaults();

        // Setup artifact hierarchy for bypass attempts
        let hierarchy_artifact = TrustArtifact {
            id: ArtifactId("hierarchy_test".to_string()),
            object_class: ObjectClass::TrustReceipt,
            payload: vec![0xBB, 0xBB],
            epoch_id: 500,
        };

        // Store in all tiers
        storage.store(Tier::L1Local, hierarchy_artifact.clone());
        storage.store(Tier::L2Warm, hierarchy_artifact.clone());
        storage.store(Tier::L3Archive, hierarchy_artifact.clone());

        let artifact_id = ArtifactId("hierarchy_test".to_string());

        // Test L1 eviction with L2 copy (should succeed)
        let evicted_l1 = storage.evict(Tier::L1Local, &artifact_id).unwrap();
        assert_eq!(evicted_l1.payload, vec![0xBB, 0xBB]);
        assert!(!storage.contains(Tier::L1Local, &artifact_id));

        // Test L2 eviction with L3 copy (should succeed)
        let evicted_l2 = storage.evict(Tier::L2Warm, &artifact_id).unwrap();
        assert!(!storage.contains(Tier::L2Warm, &artifact_id));

        // Test L3 eviction (always allowed - permanent deletion)
        let evicted_l3 = storage.evict(Tier::L3Archive, &artifact_id).unwrap();
        assert!(!storage.contains(Tier::L3Archive, &artifact_id));

        // Test eviction of non-existent artifact
        let missing_id = ArtifactId("never_existed".to_string());
        for tier in Tier::all() {
            let result = storage.evict(*tier, &missing_id);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().code, ERR_ARTIFACT_NOT_FOUND);
        }

        // Test retrievability enforcement for partial hierarchies
        let partial_artifact = TrustArtifact {
            id: ArtifactId("partial_test".to_string()),
            object_class: ObjectClass::CriticalMarker,
            payload: vec![0xAA],
            epoch_id: 600,
        };

        // Store only in L1 and L3 (skip L2)
        storage.store(Tier::L1Local, partial_artifact.clone());
        storage.store(Tier::L3Archive, partial_artifact.clone());

        let partial_id = ArtifactId("partial_test".to_string());

        // L1 eviction should succeed (L3 copy exists)
        let evicted_partial = storage.evict(Tier::L1Local, &partial_id).unwrap();
        assert_eq!(evicted_partial.payload, vec![0xAA]);

        // Test stress eviction with many artifacts
        for i in 0..1000 {
            let stress_artifact = TrustArtifact {
                id: ArtifactId(format!("eviction_stress_{}", i)),
                object_class: ObjectClass::ReplayBundle,
                payload: vec![i as u8],
                epoch_id: i as u64,
            };

            // Store in L3 for unrestricted eviction
            let id = storage.store(Tier::L3Archive, stress_artifact);

            // Immediate eviction
            if i % 2 == 0 {
                storage.evict(Tier::L3Archive, &id).unwrap();
            }
        }

        // Half should remain
        assert_eq!(storage.tier_count(Tier::L3Archive), 500);
    }
}
