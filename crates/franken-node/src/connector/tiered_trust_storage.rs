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
        self.events.push(StorageEvent {
            code: code.to_string(),
            tier: tier.as_str().to_string(),
            artifact_id: artifact_id.map(|id| id.0.clone()),
            detail,
        });
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
}
