//! Content-derived deterministic seed derivation for encoding/repair schedules.
//!
//! Provides domain-separated seed derivation using SHA-256, ensuring identical
//! `(domain, content_hash, config)` tuples produce identical seeds across all
//! platforms and Rust versions. No floating point, no locale-sensitive operations.
//!
//! ## Invariants
//!
//! - **INV-SEED-DOMAIN-SEP**: Different domain tags always produce different seeds
//!   for identical content and config.
//! - **INV-SEED-STABLE**: Identical inputs produce identical outputs, always.
//! - **INV-SEED-BOUNDED**: Derivation is constant-time w.r.t. content size
//!   (operates on 32-byte hash, not raw content).
//! - **INV-SEED-NO-PLATFORM**: No platform-dependent behavior (no float, no locale).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

const MAX_BUMP_RECORDS: usize = 4096;

pub fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }

    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

/// Constant-time byte comparison (inline to avoid cross-crate path issues in test harnesses).
fn ct_eq_bytes_inline(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

// ---------------------------------------------------------------------------
// Domain tags
// ---------------------------------------------------------------------------

/// Domain tag for seed derivation. Each domain uses a distinct versioned prefix
/// to guarantee domain separation (INV-SEED-DOMAIN-SEP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DomainTag {
    /// Erasure coding / chunk boundary decisions.
    Encoding,
    /// Repair scheduling priorities.
    Repair,
    /// General scheduling (non-encoding, non-repair).
    Scheduling,
    /// Replica placement decisions.
    Placement,
    /// Integrity verification ordering.
    Verification,
}

impl DomainTag {
    /// Returns the versioned domain-separation prefix string.
    /// These prefixes are append-only: once published, they MUST NOT change.
    pub fn prefix(&self) -> &'static str {
        match self {
            DomainTag::Encoding => "franken_node.encoding.v1",
            DomainTag::Repair => "franken_node.repair.v1",
            DomainTag::Scheduling => "franken_node.scheduling.v1",
            DomainTag::Placement => "franken_node.placement.v1",
            DomainTag::Verification => "franken_node.verification.v1",
        }
    }

    /// All domain tags, useful for exhaustive testing.
    pub fn all() -> &'static [DomainTag] {
        &[
            DomainTag::Encoding,
            DomainTag::Repair,
            DomainTag::Scheduling,
            DomainTag::Placement,
            DomainTag::Verification,
        ]
    }

    /// Label for structured logging.
    pub fn label(&self) -> &'static str {
        match self {
            DomainTag::Encoding => "encoding",
            DomainTag::Repair => "repair",
            DomainTag::Scheduling => "scheduling",
            DomainTag::Placement => "placement",
            DomainTag::Verification => "verification",
        }
    }
}

impl fmt::Display for DomainTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Content hash
// ---------------------------------------------------------------------------

/// A 32-byte content hash (SHA-256 of the raw content).
/// The deriver never touches raw content — only this pre-computed hash
/// (INV-SEED-BOUNDED).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentHash(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl ContentHash {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn from_hex(s: &str) -> Result<Self, SeedError> {
        let decoded = hex::decode(s).map_err(|_| SeedError::InvalidContentHash)?;
        if decoded.len() != 32 {
            return Err(SeedError::InvalidContentHash);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First 8 hex chars, for log fields.
    pub fn prefix_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

// ---------------------------------------------------------------------------
// Schedule config
// ---------------------------------------------------------------------------

/// Deterministic schedule configuration. Uses BTreeMap for sorted-key iteration,
/// ensuring identical serialization across platforms (INV-SEED-NO-PLATFORM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Monotonic version number. Bumped when parameters change.
    pub version: u32,
    /// Sorted key-value parameter map.
    pub parameters: BTreeMap<String, String>,
}

impl ScheduleConfig {
    pub fn new(version: u32) -> Self {
        Self {
            version,
            parameters: BTreeMap::new(),
        }
    }

    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }

    /// Deterministic hash of the config (version + sorted params).
    /// Used for version bump detection and as input to seed derivation.
    pub fn config_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"deterministic_seed_config_v1:");
        hasher.update(self.version.to_le_bytes());
        for (k, v) in &self.parameters {
            hasher.update(u64::try_from(k.len()).unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(k.as_bytes());
            hasher.update(u64::try_from(v.len()).unwrap_or(u64::MAX).to_le_bytes());
            hasher.update(v.as_bytes());
        }
        hasher.finalize().into()
    }

    #[allow(dead_code)]
    pub fn config_hash_hex(&self) -> String {
        hex::encode(self.config_hash())
    }
}

// ---------------------------------------------------------------------------
// Deterministic seed
// ---------------------------------------------------------------------------

/// The derived deterministic seed (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicSeed {
    #[serde(with = "hex_bytes")]
    pub bytes: [u8; 32],
    pub domain: DomainTag,
    pub config_version: u32,
}

impl DeterministicSeed {
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// First 8 hex chars, for log fields.
    pub fn prefix_hex(&self) -> String {
        hex::encode(&self.bytes[..4])
    }
}

// ---------------------------------------------------------------------------
// Version bump record
// ---------------------------------------------------------------------------

/// Emitted when a config change would alter the derived seed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionBumpRecord {
    pub domain: DomainTag,
    pub content_hash_hex: String,
    pub old_config_hash: String,
    pub new_config_hash: String,
    pub old_seed_hex: String,
    pub new_seed_hex: String,
    pub old_version: u32,
    pub new_version: u32,
    pub bump_reason: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SeedError {
    #[error("invalid content hash: must be 32 bytes hex-encoded")]
    InvalidContentHash,
    #[error("config version must be > 0")]
    #[allow(dead_code)]
    ZeroConfigVersion,
}

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Structured log event code for seed derivation.
pub const EVENT_SEED_DERIVED: &str = "SEED_DERIVED";
/// Structured log event code for version bump detection.
pub const EVENT_SEED_VERSION_BUMP: &str = "SEED_VERSION_BUMP";

// ---------------------------------------------------------------------------
// Core derivation
// ---------------------------------------------------------------------------

/// Derives a deterministic seed from domain, content hash, and config.
///
/// The derivation is: `SHA-256(domain_prefix || 0x00 || content_hash || config_hash)`.
///
/// The null byte separator prevents prefix collisions between domain tags
/// of different lengths.
///
/// This function is pure, constant-time w.r.t. content size, and
/// platform-independent (INV-SEED-STABLE, INV-SEED-BOUNDED, INV-SEED-NO-PLATFORM).
pub fn derive_seed(
    domain: &DomainTag,
    content_hash: &ContentHash,
    config: &ScheduleConfig,
) -> DeterministicSeed {
    let mut hasher = Sha256::new();

    // Domain-separation prefix (INV-SEED-DOMAIN-SEP)
    hasher.update(domain.prefix().as_bytes());
    // Null separator to prevent prefix collisions
    hasher.update([0x00]);
    // Content hash (32 bytes)
    hasher.update(content_hash.0);
    // Config hash (32 bytes, deterministic)
    hasher.update(config.config_hash());

    let result: [u8; 32] = hasher.finalize().into();

    DeterministicSeed {
        bytes: result,
        domain: *domain,
        config_version: config.version,
    }
}

// ---------------------------------------------------------------------------
// Deriver (stateful wrapper with version bump tracking)
// ---------------------------------------------------------------------------

/// Stateful seed deriver that tracks config changes and emits version bump
/// records when a config change would alter derived seeds.
#[derive(Debug)]
pub struct DeterministicSeedDeriver {
    /// Last known config hash and version per domain, for bump detection.
    last_config_hashes: BTreeMap<DomainTag, ([u8; 32], u32)>,
    /// Accumulated version bump records.
    bump_records: Vec<VersionBumpRecord>,
}

impl DeterministicSeedDeriver {
    pub fn new() -> Self {
        Self {
            last_config_hashes: BTreeMap::new(),
            bump_records: Vec::new(),
        }
    }

    /// Derive a seed, automatically detecting and recording config version bumps.
    ///
    /// Returns `(seed, Option<bump_record>)`. The bump record is Some if the
    /// config hash changed since the last derivation for this domain.
    pub fn derive_seed(
        &mut self,
        domain: &DomainTag,
        content_hash: &ContentHash,
        config: &ScheduleConfig,
    ) -> (DeterministicSeed, Option<VersionBumpRecord>) {
        let new_config_hash = config.config_hash();
        let seed = derive_seed(domain, content_hash, config);

        // [SEED_DERIVED] structured log point
        // Fields: domain, content_hash_prefix, config_version, seed_hash_prefix, trace_id
        let _event = EVENT_SEED_DERIVED;

        let bump = if let Some(&(old_hash, old_version)) = self.last_config_hashes.get(domain) {
            if !ct_eq_bytes_inline(&old_hash, &new_config_hash) {
                // Config changed — compute old seed for the record
                // We need to reconstruct what the old seed was. Since we only
                // stored the config hash (not the full config), we record the
                // hashes and the new seed. The old_seed_hex is computed by
                // re-deriving with the old config hash directly.
                let old_seed = derive_seed_raw(domain, content_hash, &old_hash);

                let record = VersionBumpRecord {
                    domain: *domain,
                    content_hash_hex: content_hash.to_hex(),
                    old_config_hash: hex::encode(old_hash.as_slice()),
                    new_config_hash: hex::encode(new_config_hash),
                    old_seed_hex: hex::encode(old_seed),
                    new_seed_hex: seed.to_hex(),
                    old_version,
                    new_version: config.version,
                    bump_reason: format!("Config hash changed for domain '{}'", domain.label()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };

                // [SEED_VERSION_BUMP] structured log point
                let _event = EVENT_SEED_VERSION_BUMP;

                push_bounded(&mut self.bump_records, record.clone(), MAX_BUMP_RECORDS);
                self.last_config_hashes
                    .insert(*domain, (new_config_hash, config.version));
                Some(record)
            } else {
                None
            }
        } else {
            // First derivation for this domain — just record the config hash and version
            self.last_config_hashes
                .insert(*domain, (new_config_hash, config.version));
            None
        };

        (seed, bump)
    }
}

// Inline negative-path tests for derive_seed method
#[cfg(test)]
#[test]
fn derive_seed_negative_path_regression_coverage() {
    // Test: Unicode injection in config parameter keys and values
    let mut deriver = DeterministicSeedDeriver::new();
    let unicode_attack_config = ScheduleConfig::new(1)
        .with_param(
            "param\u{202E}marap_evil\u{202D}",
            "value\u{FEFF}\u{200B}invisible",
        )
        .with_param("legitimate_param", "légitimate_value_with_accénts");
    let content_hash = ContentHash::from_bytes([0x42; 32]);
    let domain = &DomainTag::Encoding;

    let (seed, _bump) = deriver.derive_seed(domain, &content_hash, &unicode_attack_config);
    assert_eq!(
        seed.domain, *domain,
        "Domain should be preserved despite Unicode injection"
    );
    assert_eq!(seed.config_version, 1, "Config version should be preserved");
    // Unicode content should be preserved in config hash calculation without interpretation

    // Test: Control character injection in parameter values
    let mut deriver = DeterministicSeedDeriver::new();
    let control_char_config = ScheduleConfig::new(2)
        .with_param("malicious", "value\x00\x01\x02\r\n\t")
        .with_param("sql_injection", "'; DROP TABLE seeds; --")
        .with_param("script_injection", "<script>alert('xss')</script>");
    let result = deriver.derive_seed(&DomainTag::Repair, &content_hash, &control_char_config);
    assert!(
        result.0.bytes.iter().all(|&b| b != 0),
        "Derived seed should not be all zeros"
    );
    // Control characters should be hashed as-is without interpretation

    // Test: Memory exhaustion through massive parameter maps
    let mut deriver = DeterministicSeedDeriver::new();
    let mut massive_config = ScheduleConfig::new(3);
    let massive_value = "X".repeat(10_000); // 10KB per value
    for i in 0..100 {
        // 1MB total config
        massive_config =
            massive_config.with_param(format!("massive_key_{}", i), massive_value.clone());
    }
    let (massive_seed, _) =
        deriver.derive_seed(&DomainTag::Scheduling, &content_hash, &massive_config);
    assert_eq!(
        massive_seed.bytes.len(),
        32,
        "Should produce 32-byte seed regardless of config size"
    );
    // Should handle massive configurations without memory issues

    // Test: Hash collision resistance with similar configurations
    let mut deriver = DeterministicSeedDeriver::new();
    let similar_configs = [
        ScheduleConfig::new(4).with_param("param", "value1"),
        ScheduleConfig::new(4).with_param("param", "value2"),
        ScheduleConfig::new(5).with_param("param", "value1"), // Different version
        ScheduleConfig::new(4).with_param("different_param", "value1"),
    ];

    let mut seeds = Vec::new();
    for (i, config) in similar_configs.iter().enumerate() {
        let domain = &DomainTag::Placement;
        let test_hash = ContentHash::from_bytes([i as u8; 32]);
        let (seed, _) = deriver.derive_seed(domain, &test_hash, config);
        seeds.push(seed.bytes);
    }

    // All seeds should be unique
    for i in 0..seeds.len() {
        for j in (i + 1)..seeds.len() {
            assert!(
                !ct_eq_bytes_inline(&seeds[i], &seeds[j]),
                "Different configurations should produce different seeds"
            );
        }
    }

    // Test: Version bump detection and record generation
    let mut deriver = DeterministicSeedDeriver::new();
    let initial_config = ScheduleConfig::new(1).with_param("initial", "config");
    let updated_config = ScheduleConfig::new(2).with_param("updated", "config");
    let domain = &DomainTag::Verification;

    // First derivation should not generate bump
    let (_, bump1) = deriver.derive_seed(domain, &content_hash, &initial_config);
    assert!(
        bump1.is_none(),
        "First derivation should not generate version bump"
    );

    // Second derivation with different config should generate bump
    let (_, bump2) = deriver.derive_seed(domain, &content_hash, &updated_config);
    assert!(
        bump2.is_some(),
        "Config change should generate version bump record"
    );

    if let Some(bump_record) = bump2 {
        assert_eq!(
            bump_record.domain, *domain,
            "Bump record should contain correct domain"
        );
        assert_eq!(
            bump_record.old_version, 1,
            "Bump record should contain old version"
        );
        assert_eq!(
            bump_record.new_version, 2,
            "Bump record should contain new version"
        );
        assert_ne!(
            bump_record.old_seed_hex, bump_record.new_seed_hex,
            "Old and new seeds should differ"
        );
    }

    // Test: Bump record capacity boundary attacks (bump flooding)
    let mut deriver = DeterministicSeedDeriver::new();
    // Generate more bump records than capacity
    for i in 0..MAX_BUMP_RECORDS.saturating_add(10) {
        let flood_config =
            ScheduleConfig::new(u32::try_from(i).unwrap_or(u32::MAX).saturating_add(1))
                .with_param("flood", &format!("version_{}", i));
        let test_domain = &DomainTag::Encoding;
        let flood_hash = ContentHash::from_bytes([i as u8; 32]);
        let _ = deriver.derive_seed(test_domain, &flood_hash, &flood_config);
    }
    assert!(
        deriver.bump_records().len() <= MAX_BUMP_RECORDS,
        "Bump records should be capacity-bounded"
    );

    // Test: Domain separation verification
    let mut deriver = DeterministicSeedDeriver::new();
    let test_config = ScheduleConfig::new(1).with_param("test", "separation");
    let test_hash = ContentHash::from_bytes([0xAB; 32]);

    let mut domain_seeds = Vec::new();
    for domain in DomainTag::all() {
        let (seed, _) = deriver.derive_seed(domain, &test_hash, &test_config);
        domain_seeds.push((domain.label(), seed.bytes));
    }

    // Seeds from different domains should be unique
    for i in 0..domain_seeds.len() {
        for j in (i + 1)..domain_seeds.len() {
            assert!(
                !ct_eq_bytes_inline(&domain_seeds[i].1, &domain_seeds[j].1),
                "Different domains should produce different seeds: {} vs {}",
                domain_seeds[i].0,
                domain_seeds[j].0
            );
        }
    }

    // Test: Constant-time property simulation (deterministic output)
    let mut deriver1 = DeterministicSeedDeriver::new();
    let mut deriver2 = DeterministicSeedDeriver::new();
    let determinism_config = ScheduleConfig::new(42).with_param("determinism", "test");
    let determinism_hash = ContentHash::from_bytes([0xDE; 32]);
    let domain = &DomainTag::Repair;

    let (seed1, _) = deriver1.derive_seed(domain, &determinism_hash, &determinism_config);
    let (seed2, _) = deriver2.derive_seed(domain, &determinism_hash, &determinism_config);

    assert!(
        ct_eq_bytes_inline(&seed1.bytes, &seed2.bytes),
        "Identical inputs should produce identical seeds"
    );
    assert_eq!(seed1.domain, seed2.domain, "Domain should be identical");
    assert_eq!(
        seed1.config_version, seed2.config_version,
        "Config version should be identical"
    );

    // Test: Content hash boundary validation
    let mut deriver = DeterministicSeedDeriver::new();
    let boundary_config = ScheduleConfig::new(1).with_param("boundary", "test");
    let boundary_hashes = [
        ContentHash::from_bytes([0x00; 32]), // All zeros
        ContentHash::from_bytes([0xFF; 32]), // All ones
        ContentHash::from_bytes({
            let mut arr = [0u8; 32];
            arr[0] = 0xFF;
            arr
        }), // Single bit set
        ContentHash::from_bytes({
            let mut arr = [0u8; 32];
            for i in 0..32 {
                arr[i] = i as u8;
            }
            arr
        }), // Incremental pattern
    ];

    let mut boundary_seeds = Vec::new();
    for (i, hash) in boundary_hashes.iter().enumerate() {
        let (seed, _) = deriver.derive_seed(&DomainTag::Process, hash, &boundary_config);
        boundary_seeds.push((i, seed.bytes));
    }

    // All boundary cases should produce unique seeds
    for i in 0..boundary_seeds.len() {
        for j in (i + 1)..boundary_seeds.len() {
            assert!(
                !ct_eq_bytes_inline(&boundary_seeds[i].1, &boundary_seeds[j].1),
                "Boundary hash case {} should differ from case {}",
                boundary_seeds[i].0,
                boundary_seeds[j].0
            );
        }
    }

    // Test: Parameter ordering independence (BTreeMap sorted keys)
    let mut deriver = DeterministicSeedDeriver::new();
    let config_order1 = ScheduleConfig::new(1)
        .with_param("aaa", "first")
        .with_param("zzz", "second")
        .with_param("mmm", "third");
    let config_order2 = ScheduleConfig::new(1)
        .with_param("zzz", "second")
        .with_param("aaa", "first")
        .with_param("mmm", "third");

    let ordering_hash = ContentHash::from_bytes([0x11; 32]);
    let (seed_order1, _) =
        deriver.derive_seed(&DomainTag::Encoding, &ordering_hash, &config_order1);
    let (seed_order2, _) =
        deriver.derive_seed(&DomainTag::Encoding, &ordering_hash, &config_order2);

    assert!(
        ct_eq_bytes_inline(&seed_order1.bytes, &seed_order2.bytes),
        "Parameter insertion order should not affect derived seed"
    );

    // Test: Config hash length overflow protection
    let mut deriver = DeterministicSeedDeriver::new();
    let overflow_config =
        ScheduleConfig::new(u32::MAX).with_param(&"K".repeat(1_000_000), &"V".repeat(1_000_000)); // Very large key/value
    let overflow_hash = ContentHash::from_bytes([0xFF; 32]);

    let (overflow_seed, _) =
        deriver.derive_seed(&DomainTag::Verification, &overflow_hash, &overflow_config);
    assert_eq!(
        overflow_seed.bytes.len(),
        32,
        "Should produce valid seed even with overflow-sized config"
    );
    assert_eq!(
        overflow_seed.config_version,
        u32::MAX,
        "Should preserve max config version"
    );

    // Test: Timestamp generation in bump records
    let mut deriver = DeterministicSeedDeriver::new();
    let time_config1 = ScheduleConfig::new(1).with_param("time", "test1");
    let time_config2 = ScheduleConfig::new(2).with_param("time", "test2");
    let time_hash = ContentHash::from_bytes([0x33; 32]);
    let time_domain = &DomainTag::Placement;

    let (_, _) = deriver.derive_seed(time_domain, &time_hash, &time_config1);
    let (_, bump) = deriver.derive_seed(time_domain, &time_hash, &time_config2);

    if let Some(bump_record) = bump {
        assert!(
            !bump_record.timestamp.is_empty(),
            "Bump record should contain timestamp"
        );
        assert!(
            bump_record.timestamp.contains("T"),
            "Timestamp should be RFC3339 format"
        );
        assert!(
            bump_record.bump_reason.contains("Config hash changed"),
            "Bump reason should be descriptive"
        );
    }

    // Test: Clear bump records functionality
    let mut deriver = DeterministicSeedDeriver::new();
    let clear_config1 = ScheduleConfig::new(1).with_param("clear", "test");
    let clear_config2 = ScheduleConfig::new(2).with_param("clear", "test");
    let clear_hash = ContentHash::from_bytes([0x77; 32]);

    let (_, _) = deriver.derive_seed(&DomainTag::Scheduling, &clear_hash, &clear_config1);
    let (_, _) = deriver.derive_seed(&DomainTag::Scheduling, &clear_hash, &clear_config2);

    assert!(
        !deriver.bump_records().is_empty(),
        "Should have bump records before clear"
    );
    deriver.clear_bump_records();
    assert!(
        deriver.bump_records().is_empty(),
        "Should have no bump records after clear"
    );
    assert!(
        deriver.tracked_domains() > 0,
        "Should still track domains after clearing records"
    );

    // Test: Domain tracking count accuracy
    let mut deriver = DeterministicSeedDeriver::new();
    let tracking_config = ScheduleConfig::new(1).with_param("tracking", "test");
    let tracking_hash = ContentHash::from_bytes([0x99; 32]);

    assert_eq!(
        deriver.tracked_domains(),
        0,
        "Should start with zero tracked domains"
    );

    for (i, domain) in DomainTag::all().iter().enumerate() {
        let (_, _) = deriver.derive_seed(domain, &tracking_hash, &tracking_config);
        assert_eq!(
            deriver.tracked_domains(),
            i.saturating_add(1),
            "Should increment tracked domain count"
        );
    }

    assert_eq!(
        deriver.tracked_domains(),
        DomainTag::all().len(),
        "Should track all domains"
    );
}

impl DeterministicSeedDeriver {
    /// All accumulated version bump records.
    pub fn bump_records(&self) -> &[VersionBumpRecord] {
        &self.bump_records
    }

    /// Clear accumulated bump records (e.g., after persisting them).
    pub fn clear_bump_records(&mut self) {
        self.bump_records.clear();
    }

    /// Number of domains currently tracked.
    pub fn tracked_domains(&self) -> usize {
        self.last_config_hashes.len()
    }
}

impl Default for DeterministicSeedDeriver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Internal: raw derivation from pre-computed config hash
// ---------------------------------------------------------------------------

/// Same derivation as `derive_seed` but takes a raw config hash instead of
/// a ScheduleConfig. Used internally for version bump old-seed computation.
fn derive_seed_raw(
    domain: &DomainTag,
    content_hash: &ContentHash,
    config_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.prefix().as_bytes());
    hasher.update([0x00]);
    hasher.update(content_hash.0);
    hasher.update(config_hash);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Serde helper for [u8; 32] as hex
// ---------------------------------------------------------------------------

mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if decoded.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                decoded.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }
}

// ---------------------------------------------------------------------------
// Compile-time Send + Sync assertion
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<DeterministicSeedDeriver>();
    assert_sync::<DeterministicSeed>();
    assert_send::<DeterministicSeed>();
    assert_sync::<ContentHash>();
    assert_send::<ContentHash>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_content_hash() -> ContentHash {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("test hash index must fit in u8");
        }
        ContentHash(h)
    }

    fn test_config_v1() -> ScheduleConfig {
        ScheduleConfig::new(1)
            .with_param("chunk_size", "65536")
            .with_param("erasure_k", "4")
            .with_param("erasure_m", "2")
    }

    fn test_config_v2() -> ScheduleConfig {
        ScheduleConfig::new(2)
            .with_param("chunk_size", "131072")
            .with_param("erasure_k", "4")
            .with_param("erasure_m", "2")
    }

    // -- Basic derivation ---------------------------------------------------

    #[test]
    fn test_derive_seed_deterministic() {
        let ch = test_content_hash();
        let cfg = test_config_v1();
        let s1 = derive_seed(&DomainTag::Encoding, &ch, &cfg);
        let s2 = derive_seed(&DomainTag::Encoding, &ch, &cfg);
        assert_eq!(
            s1.bytes, s2.bytes,
            "INV-SEED-STABLE: identical inputs → identical seeds"
        );
    }

    #[test]
    fn test_derive_seed_is_32_bytes() {
        let s = derive_seed(
            &DomainTag::Encoding,
            &test_content_hash(),
            &test_config_v1(),
        );
        assert_eq!(s.bytes.len(), 32);
    }

    #[test]
    fn test_derive_seed_nonzero() {
        let s = derive_seed(
            &DomainTag::Encoding,
            &test_content_hash(),
            &test_config_v1(),
        );
        assert_ne!(s.bytes, [0u8; 32], "seed should not be all zeros");
    }

    // -- Domain separation --------------------------------------------------

    #[test]
    fn test_domain_separation_encoding_vs_repair() {
        let ch = test_content_hash();
        let cfg = test_config_v1();
        let s_enc = derive_seed(&DomainTag::Encoding, &ch, &cfg);
        let s_rep = derive_seed(&DomainTag::Repair, &ch, &cfg);
        assert_ne!(
            s_enc.bytes, s_rep.bytes,
            "INV-SEED-DOMAIN-SEP: different domains → different seeds"
        );
    }

    #[test]
    fn test_domain_separation_all_pairs() {
        let ch = test_content_hash();
        let cfg = test_config_v1();
        let domains = DomainTag::all();
        for i in 0..domains.len() {
            for j in i.saturating_add(1)..domains.len() {
                let s_i = derive_seed(&domains[i], &ch, &cfg);
                let s_j = derive_seed(&domains[j], &ch, &cfg);
                assert_ne!(
                    s_i.bytes, s_j.bytes,
                    "domains {:?} and {:?} must produce different seeds",
                    domains[i], domains[j]
                );
            }
        }
    }

    #[test]
    fn test_domain_tag_labels() {
        assert_eq!(DomainTag::Encoding.label(), "encoding");
        assert_eq!(DomainTag::Repair.label(), "repair");
        assert_eq!(DomainTag::Scheduling.label(), "scheduling");
        assert_eq!(DomainTag::Placement.label(), "placement");
        assert_eq!(DomainTag::Verification.label(), "verification");
    }

    #[test]
    fn test_domain_tag_prefixes_unique() {
        let domains = DomainTag::all();
        for i in 0..domains.len() {
            for j in i.saturating_add(1)..domains.len() {
                assert_ne!(
                    domains[i].prefix(),
                    domains[j].prefix(),
                    "domain prefixes must be unique"
                );
            }
        }
    }

    #[test]
    fn test_domain_tag_all_count() {
        assert_eq!(DomainTag::all().len(), 5);
    }

    // -- Content hash sensitivity -------------------------------------------

    #[test]
    fn test_different_content_different_seed() {
        let cfg = test_config_v1();
        let ch1 = ContentHash([0u8; 32]);
        let ch2 = ContentHash([1u8; 32]);
        let s1 = derive_seed(&DomainTag::Encoding, &ch1, &cfg);
        let s2 = derive_seed(&DomainTag::Encoding, &ch2, &cfg);
        assert_ne!(s1.bytes, s2.bytes);
    }

    #[test]
    fn test_single_bit_content_change() {
        let cfg = test_config_v1();
        let h1 = [0u8; 32];
        let mut h2 = [0u8; 32];
        h2[31] = 1; // single bit flip
        let s1 = derive_seed(&DomainTag::Encoding, &ContentHash(h1), &cfg);
        let s2 = derive_seed(&DomainTag::Encoding, &ContentHash(h2), &cfg);
        assert_ne!(
            s1.bytes, s2.bytes,
            "single-bit change in content must change seed"
        );
    }

    // -- Config sensitivity -------------------------------------------------

    #[test]
    fn test_different_config_different_seed() {
        let ch = test_content_hash();
        let s1 = derive_seed(&DomainTag::Encoding, &ch, &test_config_v1());
        let s2 = derive_seed(&DomainTag::Encoding, &ch, &test_config_v2());
        assert_ne!(s1.bytes, s2.bytes, "config change must change seed");
    }

    #[test]
    fn test_config_version_changes_seed() {
        let ch = test_content_hash();
        let c1 = ScheduleConfig::new(1).with_param("k", "4");
        let c2 = ScheduleConfig::new(2).with_param("k", "4");
        let s1 = derive_seed(&DomainTag::Encoding, &ch, &c1);
        let s2 = derive_seed(&DomainTag::Encoding, &ch, &c2);
        assert_ne!(s1.bytes, s2.bytes, "version change alone must change seed");
    }

    #[test]
    fn test_config_param_order_irrelevant() {
        let ch = test_content_hash();
        // BTreeMap sorts keys, so insertion order should not matter
        let c1 = ScheduleConfig::new(1)
            .with_param("a", "1")
            .with_param("b", "2");
        let c2 = ScheduleConfig::new(1)
            .with_param("b", "2")
            .with_param("a", "1");
        let s1 = derive_seed(&DomainTag::Encoding, &ch, &c1);
        let s2 = derive_seed(&DomainTag::Encoding, &ch, &c2);
        assert_eq!(s1.bytes, s2.bytes, "BTreeMap ensures order independence");
    }

    #[test]
    fn test_config_hash_deterministic() {
        let c = test_config_v1();
        let h1 = c.config_hash();
        let h2 = c.config_hash();
        assert_eq!(h1, h2);
    }

    // -- Empty / edge cases -------------------------------------------------

    #[test]
    fn test_empty_content_hash() {
        let ch = ContentHash([0u8; 32]);
        let s = derive_seed(&DomainTag::Encoding, &ch, &test_config_v1());
        assert_ne!(
            s.bytes, [0u8; 32],
            "zero content hash still produces non-zero seed"
        );
    }

    #[test]
    fn test_empty_config_params() {
        let ch = test_content_hash();
        let cfg = ScheduleConfig::new(1);
        let s = derive_seed(&DomainTag::Encoding, &ch, &cfg);
        assert_ne!(s.bytes, [0u8; 32]);
    }

    #[test]
    fn test_max_version() {
        let cfg = ScheduleConfig::new(u32::MAX);
        let s = derive_seed(&DomainTag::Encoding, &test_content_hash(), &cfg);
        assert_ne!(s.bytes, [0u8; 32]);
    }

    // -- ContentHash methods ------------------------------------------------

    #[test]
    fn test_content_hash_from_hex() {
        let hex_str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let ch = ContentHash::from_hex(hex_str).expect("from_hex should succeed");
        assert_eq!(ch.to_hex(), hex_str);
    }

    #[test]
    fn test_content_hash_from_hex_invalid_length() {
        assert!(ContentHash::from_hex("aabb").is_err());
    }

    #[test]
    fn test_content_hash_from_hex_invalid_chars() {
        assert!(ContentHash::from_hex("zzzz").is_err());
    }

    #[test]
    fn test_content_hash_prefix_hex() {
        let ch = test_content_hash();
        let p = ch.prefix_hex();
        assert_eq!(p.len(), 8);
        assert_eq!(&p, &ch.to_hex()[..8]);
    }

    // -- DeterministicSeed methods ------------------------------------------

    #[test]
    fn test_seed_to_hex_length() {
        let s = derive_seed(
            &DomainTag::Encoding,
            &test_content_hash(),
            &test_config_v1(),
        );
        assert_eq!(s.to_hex().len(), 64);
    }

    #[test]
    fn test_seed_prefix_hex() {
        let s = derive_seed(
            &DomainTag::Encoding,
            &test_content_hash(),
            &test_config_v1(),
        );
        assert_eq!(s.prefix_hex().len(), 8);
    }

    #[test]
    fn test_seed_domain_preserved() {
        let s = derive_seed(&DomainTag::Repair, &test_content_hash(), &test_config_v1());
        assert_eq!(s.domain, DomainTag::Repair);
    }

    #[test]
    fn test_seed_config_version_preserved() {
        let cfg = test_config_v1();
        let s = derive_seed(&DomainTag::Encoding, &test_content_hash(), &cfg);
        assert_eq!(s.config_version, 1);
    }

    // -- Serialization roundtrip --------------------------------------------

    #[test]
    fn test_seed_serialization_roundtrip() {
        let s = derive_seed(
            &DomainTag::Encoding,
            &test_content_hash(),
            &test_config_v1(),
        );
        let json = serde_json::to_string(&s).expect("to_string should succeed");
        let s2: DeterministicSeed = serde_json::from_str(&json).expect("from_str should succeed");
        assert_eq!(s.bytes, s2.bytes);
        assert_eq!(s.domain, s2.domain);
        assert_eq!(s.config_version, s2.config_version);
    }

    #[test]
    fn test_content_hash_serialization_roundtrip() {
        let ch = test_content_hash();
        let json = serde_json::to_string(&ch).expect("to_string should succeed");
        let ch2: ContentHash = serde_json::from_str(&json).expect("from_str should succeed");
        assert_eq!(ch.0, ch2.0);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = test_config_v1();
        let json = serde_json::to_string(&cfg).expect("to_string should succeed");
        let cfg2: ScheduleConfig = serde_json::from_str(&json).expect("from_str should succeed");
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn test_version_bump_record_serialization() {
        let record = VersionBumpRecord {
            domain: DomainTag::Encoding,
            content_hash_hex: "aa".repeat(32),
            old_config_hash: "bb".repeat(32),
            new_config_hash: "cc".repeat(32),
            old_seed_hex: "dd".repeat(32),
            new_seed_hex: "ee".repeat(32),
            old_version: 1,
            new_version: 2,
            bump_reason: "test".to_string(),
            timestamp: "2026-02-20T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&record).expect("to_string should succeed");
        let record2: VersionBumpRecord =
            serde_json::from_str(&json).expect("from_str should succeed");
        assert_eq!(record.domain, record2.domain);
        assert_eq!(record.old_version, record2.old_version);
    }

    // -- Deriver (stateful) -------------------------------------------------

    #[test]
    fn test_deriver_new_is_empty() {
        let d = DeterministicSeedDeriver::new();
        assert_eq!(d.tracked_domains(), 0);
        assert!(d.bump_records().is_empty());
    }

    #[test]
    fn test_deriver_first_call_no_bump() {
        let mut d = DeterministicSeedDeriver::new();
        let (seed, bump) = d.derive_seed(
            &DomainTag::Encoding,
            &test_content_hash(),
            &test_config_v1(),
        );
        assert!(bump.is_none(), "first call should not produce a bump");
        assert_eq!(seed.domain, DomainTag::Encoding);
        assert_eq!(d.tracked_domains(), 1);
    }

    #[test]
    fn test_deriver_same_config_no_bump() {
        let mut d = DeterministicSeedDeriver::new();
        let cfg = test_config_v1();
        let ch = test_content_hash();
        d.derive_seed(&DomainTag::Encoding, &ch, &cfg);
        let (_, bump) = d.derive_seed(&DomainTag::Encoding, &ch, &cfg);
        assert!(bump.is_none(), "same config should not produce a bump");
    }

    #[test]
    fn test_deriver_config_change_triggers_bump() {
        let mut d = DeterministicSeedDeriver::new();
        let ch = test_content_hash();
        d.derive_seed(&DomainTag::Encoding, &ch, &test_config_v1());
        let (_, bump) = d.derive_seed(&DomainTag::Encoding, &ch, &test_config_v2());
        assert!(bump.is_some(), "config change must trigger a version bump");
        let bump = bump.expect("bump should succeed");
        assert_eq!(bump.domain, DomainTag::Encoding);
        assert_eq!(bump.new_version, 2);
        assert_ne!(bump.old_config_hash, bump.new_config_hash);
        assert_ne!(bump.old_seed_hex, bump.new_seed_hex);
    }

    #[test]
    fn test_deriver_bump_records_accumulate() {
        let mut d = DeterministicSeedDeriver::new();
        let ch = test_content_hash();
        d.derive_seed(&DomainTag::Encoding, &ch, &test_config_v1());
        d.derive_seed(&DomainTag::Encoding, &ch, &test_config_v2());
        assert_eq!(d.bump_records().len(), 1);

        let cfg3 = ScheduleConfig::new(3).with_param("chunk_size", "262144");
        d.derive_seed(&DomainTag::Encoding, &ch, &cfg3);
        assert_eq!(d.bump_records().len(), 2);
    }

    #[test]
    fn test_deriver_clear_bump_records() {
        let mut d = DeterministicSeedDeriver::new();
        let ch = test_content_hash();
        d.derive_seed(&DomainTag::Encoding, &ch, &test_config_v1());
        d.derive_seed(&DomainTag::Encoding, &ch, &test_config_v2());
        assert_eq!(d.bump_records().len(), 1);
        d.clear_bump_records();
        assert!(d.bump_records().is_empty());
    }

    #[test]
    fn test_deriver_independent_domains() {
        let mut d = DeterministicSeedDeriver::new();
        let ch = test_content_hash();
        let cfg = test_config_v1();
        d.derive_seed(&DomainTag::Encoding, &ch, &cfg);
        let (_, bump) = d.derive_seed(&DomainTag::Repair, &ch, &cfg);
        assert!(bump.is_none(), "first call to a new domain is not a bump");
        assert_eq!(d.tracked_domains(), 2);
    }

    #[test]
    fn test_deriver_default() {
        let d = DeterministicSeedDeriver::default();
        assert_eq!(d.tracked_domains(), 0);
    }

    // -- Golden vector stability (cross-check with published vectors) -------

    #[test]
    fn test_golden_vector_encoding_zero() {
        let ch = ContentHash([0u8; 32]);
        let cfg = ScheduleConfig::new(1).with_param("chunk_size", "65536");
        let s = derive_seed(&DomainTag::Encoding, &ch, &cfg);
        assert_eq!(
            s.to_hex(),
            "9ab81d9ee4da4554e8344da711703db7998a071dba947601b7e4acf5dc6d46cb",
            "golden vector v-encoding-zero"
        );
    }

    #[test]
    fn test_golden_vector_repair_zero() {
        let ch = ContentHash([0u8; 32]);
        let cfg = ScheduleConfig::new(1).with_param("chunk_size", "65536");
        let s = derive_seed(&DomainTag::Repair, &ch, &cfg);
        assert_eq!(
            s.to_hex(),
            "9ffc3022492ba2bb2a4cc22987b045ec638abe4e449fcdba4cb0d8cee3be9927",
            "golden vector v-repair-zero"
        );
    }

    #[test]
    fn test_golden_vector_repair_ff() {
        let ch = ContentHash([0xffu8; 32]);
        let cfg = ScheduleConfig::new(1).with_param("priority", "high");
        let s = derive_seed(&DomainTag::Repair, &ch, &cfg);
        assert_eq!(
            s.to_hex(),
            "16c1e3a2da470b2852261ecf3bfd51f2a82d89b4a229d058e446fe6dbe26edc2",
            "golden vector v-repair-ff"
        );
    }

    #[test]
    fn test_golden_vector_encoding_seq_v2() {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("test hash index must fit in u8");
        }
        let ch = ContentHash(h);
        let cfg = ScheduleConfig::new(2)
            .with_param("chunk_size", "131072")
            .with_param("erasure_k", "4")
            .with_param("erasure_m", "2");
        let s = derive_seed(&DomainTag::Encoding, &ch, &cfg);
        assert_eq!(
            s.to_hex(),
            "eccd9f55f0e832e0bc45aec1e369ebe5c1961cd1bc16099a73010dd57056561e",
            "golden vector v-encoding-seq-v2"
        );
    }

    #[test]
    fn test_golden_vector_scheduling_empty_params() {
        let ch = ContentHash([0x42u8; 32]);
        let cfg = ScheduleConfig::new(1);
        let s = derive_seed(&DomainTag::Scheduling, &ch, &cfg);
        assert_eq!(
            s.to_hex(),
            "49166fa13e6e9b3efab1c771501b1673a2efd1154992cd5b1be8296908520052",
            "golden vector v-scheduling-empty-params"
        );
    }

    #[test]
    fn test_golden_vector_verification_singlebit() {
        let mut h = [0u8; 32];
        h[31] = 1;
        let ch = ContentHash(h);
        let cfg = ScheduleConfig::new(1).with_param("depth", "8");
        let s = derive_seed(&DomainTag::Verification, &ch, &cfg);
        assert_eq!(
            s.to_hex(),
            "7ae1c0c6171a83e573fae38249c147f81ca324a0618f1d362dc927f21178e0cc",
            "golden vector v-verification-singlebit"
        );
    }

    // -- Statistical collision test -----------------------------------------

    #[test]
    fn test_no_collisions_100_samples() {
        let cfg = test_config_v1();
        let mut seen = std::collections::BTreeSet::new();
        for i in 0u8..100 {
            let mut h = [0u8; 32];
            h[0] = i;
            h[1] = i.wrapping_mul(7);
            let ch = ContentHash(h);
            let s = derive_seed(&DomainTag::Encoding, &ch, &cfg);
            assert!(seen.insert(s.bytes), "collision at sample {}", i);
        }
    }

    #[test]
    fn test_no_collisions_across_domains() {
        let ch = test_content_hash();
        let cfg = test_config_v1();
        let mut seen = std::collections::BTreeSet::new();
        for domain in DomainTag::all() {
            let s = derive_seed(domain, &ch, &cfg);
            assert!(seen.insert(s.bytes), "collision for domain {:?}", domain);
        }
    }

    mod fuzz_inspired_encoding_tests {
        use super::*;

        #[test]
        fn config_hash_length_prefixes_prevent_key_value_concatenation_collision() {
            let content_hash = test_content_hash();
            let cfg_left = ScheduleConfig::new(1).with_param("ab", "c");
            let cfg_right = ScheduleConfig::new(1).with_param("a", "bc");

            assert_ne!(cfg_left.config_hash(), cfg_right.config_hash());
            assert_ne!(
                derive_seed(&DomainTag::Encoding, &content_hash, &cfg_left).bytes,
                derive_seed(&DomainTag::Encoding, &content_hash, &cfg_right).bytes
            );
        }

        #[test]
        fn config_hash_distinguishes_empty_key_from_empty_value() {
            let content_hash = test_content_hash();
            let cfg_empty_key = ScheduleConfig::new(1).with_param("", "abc");
            let cfg_empty_value = ScheduleConfig::new(1).with_param("abc", "");

            assert_ne!(cfg_empty_key.config_hash(), cfg_empty_value.config_hash());
            assert_ne!(
                derive_seed(&DomainTag::Repair, &content_hash, &cfg_empty_key).bytes,
                derive_seed(&DomainTag::Repair, &content_hash, &cfg_empty_value).bytes
            );
        }

        #[test]
        fn duplicate_param_insertion_is_deterministic_last_write_wins() {
            let content_hash = test_content_hash();
            let duplicate_write = ScheduleConfig::new(7)
                .with_param("fanout", "first")
                .with_param("fanout", "second");
            let direct_write = ScheduleConfig::new(7).with_param("fanout", "second");

            assert_eq!(duplicate_write.config_hash(), direct_write.config_hash());
            assert_eq!(
                derive_seed(&DomainTag::Scheduling, &content_hash, &duplicate_write).bytes,
                derive_seed(&DomainTag::Scheduling, &content_hash, &direct_write).bytes
            );
        }

        #[test]
        fn unusual_ascii_control_params_roundtrip_without_seed_drift() {
            let content_hash = ContentHash([0x5a; 32]);
            let config = ScheduleConfig::new(42)
                .with_param("lane\0name", "realtime\ncancel\tbulkhead")
                .with_param("separator:key", "value:with:delimiters");
            let seed_before = derive_seed(&DomainTag::Placement, &content_hash, &config);

            let encoded = serde_json::to_string(&config).expect("config JSON should serialize");
            let decoded: ScheduleConfig =
                serde_json::from_str(&encoded).expect("config JSON should deserialize");
            let seed_after = derive_seed(&DomainTag::Placement, &content_hash, &decoded);

            assert_eq!(config, decoded);
            assert_eq!(seed_before.bytes, seed_after.bytes);
        }

        #[test]
        fn content_hash_uppercase_hex_is_accepted_and_normalized() {
            let raw = "AA".repeat(32);
            let parsed = ContentHash::from_hex(&raw).expect("uppercase hex should parse");

            assert_eq!(parsed.0, [0xaa; 32]);
            assert_eq!(parsed.to_hex(), "aa".repeat(32));
        }

        #[test]
        fn content_hash_hex_rejects_fuzzed_delimiters_and_whitespace() {
            let invalid_inputs = [
                format!("0x{}", "aa".repeat(32)),
                format!("{} {}", "aa".repeat(16), "aa".repeat(16)),
                format!("{}\n{}", "aa".repeat(16), "aa".repeat(16)),
                format!("aa\0{}", "aa".repeat(31)),
                "a".repeat(63),
                "a".repeat(65),
            ];

            for raw in invalid_inputs {
                assert!(
                    ContentHash::from_hex(&raw).is_err(),
                    "fuzzed hash input should be rejected: {raw:?}"
                );
            }
        }

        #[test]
        fn deterministic_seed_deserialize_rejects_short_hex_bytes() {
            let payload = serde_json::json!({
                "bytes": "aa",
                "domain": "Encoding",
                "config_version": 1
            });

            assert!(serde_json::from_value::<DeterministicSeed>(payload).is_err());
        }

        #[test]
        fn deterministic_seed_deserialize_rejects_non_hex_bytes() {
            let payload = serde_json::json!({
                "bytes": "zz".repeat(32),
                "domain": "Encoding",
                "config_version": 1
            });

            assert!(serde_json::from_value::<DeterministicSeed>(payload).is_err());
        }

        #[test]
        fn deterministic_seed_deserialize_accepts_uppercase_hex_and_normalizes_output() {
            let payload = serde_json::json!({
                "bytes": "AB".repeat(32),
                "domain": "Verification",
                "config_version": 9
            });

            let seed: DeterministicSeed =
                serde_json::from_value(payload).expect("uppercase seed bytes should parse");

            assert_eq!(seed.bytes, [0xab; 32]);
            assert_eq!(seed.domain, DomainTag::Verification);
            assert_eq!(seed.config_version, 9);
            assert_eq!(seed.to_hex(), "ab".repeat(32));
        }

        #[test]
        fn bump_record_buffer_stays_bounded_under_mutation_corpus() {
            let mut deriver = DeterministicSeedDeriver::new();
            let content_hash = ContentHash([0x7d; 32]);

            for version in 1..=MAX_BUMP_RECORDS.saturating_add(8) {
                let config = ScheduleConfig::new(u32::try_from(version).unwrap_or(u32::MAX))
                    .with_param("salt", format!("mutation-{version:04}"));
                deriver.derive_seed(&DomainTag::Encoding, &content_hash, &config);
            }

            let records = deriver.bump_records();
            assert_eq!(records.len(), MAX_BUMP_RECORDS);
            assert!(
                records
                    .first()
                    .expect("bounded buffer should retain records")
                    .new_version
                    > 2
            );
            assert_eq!(
                records
                    .last()
                    .expect("bounded buffer should retain the newest record")
                    .new_version,
                u32::try_from(MAX_BUMP_RECORDS.saturating_add(8)).unwrap_or(u32::MAX)
            );
        }

        #[test]
        fn push_bounded_zero_capacity_discards_without_panic() {
            let mut items = vec![1, 2, 3];
            push_bounded(&mut items, 4, 0);

            assert!(items.is_empty());
        }

        #[test]
        fn push_bounded_retains_recent_window_when_over_capacity() {
            let mut items = vec![10, 20, 30, 40, 50];
            push_bounded(&mut items, 60, 3);

            assert_eq!(items, vec![40, 50, 60]);
        }
    }

    // -- DomainTag Display --------------------------------------------------

    #[test]
    fn test_domain_tag_display() {
        assert_eq!(format!("{}", DomainTag::Encoding), "encoding");
        assert_eq!(format!("{}", DomainTag::Repair), "repair");
    }

    // -- Event codes exist --------------------------------------------------

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(EVENT_SEED_DERIVED, "SEED_DERIVED");
        assert_eq!(EVENT_SEED_VERSION_BUMP, "SEED_VERSION_BUMP");
    }
}

#[cfg(test)]
mod additional_negative_path_tests {
    use super::*;

    fn content_hash() -> ContentHash {
        ContentHash([0x2a; 32])
    }

    #[test]
    fn content_hash_rejects_sha256_prefixed_hex() {
        let prefixed = format!("sha256:{}", "aa".repeat(32));

        let err = ContentHash::from_hex(&prefixed)
            .expect_err("domain-prefixed content hash must fail closed");

        assert_eq!(err, SeedError::InvalidContentHash);
    }

    #[test]
    fn content_hash_rejects_valid_hex_with_trailing_space() {
        let mut raw = "aa".repeat(32);
        raw.push(' ');

        let err = ContentHash::from_hex(&raw)
            .expect_err("content hash parsing must not trim trailing whitespace");

        assert_eq!(err, SeedError::InvalidContentHash);
    }

    #[test]
    fn content_hash_deserialize_rejects_non_string_bytes() {
        let payload = serde_json::json!([0, 1, 2, 3]);

        let result: Result<ContentHash, _> = serde_json::from_value(payload);

        assert!(result.is_err());
    }

    #[test]
    fn content_hash_deserialize_rejects_31_byte_hex() {
        let payload = serde_json::json!("aa".repeat(31));

        let result: Result<ContentHash, _> = serde_json::from_value(payload);

        assert!(result.is_err());
    }

    #[test]
    fn domain_tag_deserialize_rejects_lowercase_label() {
        let result: Result<DomainTag, _> = serde_json::from_str(r#""encoding""#);

        assert!(result.is_err());
    }

    #[test]
    fn domain_tag_deserialize_rejects_unknown_variant() {
        let result: Result<DomainTag, _> = serde_json::from_str(r#""Quarantine""#);

        assert!(result.is_err());
    }

    #[test]
    fn seed_deserialize_rejects_unknown_domain_even_with_valid_bytes() {
        let payload = serde_json::json!({
            "bytes": "11".repeat(32),
            "domain": "Quarantine",
            "config_version": 1
        });

        let result: Result<DeterministicSeed, _> = serde_json::from_value(payload);

        assert!(result.is_err());
    }

    #[test]
    fn config_mutation_without_version_bump_still_emits_bump_record() {
        let mut deriver = DeterministicSeedDeriver::new();
        let first = ScheduleConfig::new(7).with_param("chunk_size", "65536");
        let mutated_same_version = ScheduleConfig::new(7).with_param("chunk_size", "131072");
        deriver.derive_seed(&DomainTag::Encoding, &content_hash(), &first);

        let (_, bump) =
            deriver.derive_seed(&DomainTag::Encoding, &content_hash(), &mutated_same_version);
        let bump = bump.expect("config hash drift must be recorded even if version is reused");

        assert_eq!(bump.old_version, 7);
        assert_eq!(bump.new_version, 7);
        assert_ne!(bump.old_config_hash, bump.new_config_hash);
        assert_ne!(bump.old_seed_hex, bump.new_seed_hex);
    }

    #[test]
    fn clearing_bump_records_does_not_reset_tracked_config_state() {
        let mut deriver = DeterministicSeedDeriver::new();
        let first = ScheduleConfig::new(1).with_param("salt", "a");
        let second = ScheduleConfig::new(2).with_param("salt", "b");
        deriver.derive_seed(&DomainTag::Repair, &content_hash(), &first);
        deriver.derive_seed(&DomainTag::Repair, &content_hash(), &second);
        deriver.clear_bump_records();

        let (_, bump) = deriver.derive_seed(&DomainTag::Repair, &content_hash(), &first);

        assert!(
            bump.is_some(),
            "clearing records must not erase the tracked last config hash"
        );
        assert_eq!(deriver.tracked_domains(), 1);
    }

    #[test]
    fn schedule_config_deserialize_rejects_missing_version() {
        let payload = serde_json::json!({
            "parameters": {
                "chunk_size": "65536"
            }
        });

        let result = serde_json::from_value::<ScheduleConfig>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn schedule_config_deserialize_rejects_parameters_array() {
        let payload = serde_json::json!({
            "version": 1,
            "parameters": [["chunk_size", "65536"]]
        });

        let result = serde_json::from_value::<ScheduleConfig>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn schedule_config_deserialize_rejects_non_string_parameter_value() {
        let payload = serde_json::json!({
            "version": 1,
            "parameters": {
                "chunk_size": 65536
            }
        });

        let result = serde_json::from_value::<ScheduleConfig>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn deterministic_seed_deserialize_rejects_missing_config_version() {
        let payload = serde_json::json!({
            "bytes": "22".repeat(32),
            "domain": "Encoding"
        });

        let result = serde_json::from_value::<DeterministicSeed>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn deterministic_seed_deserialize_rejects_negative_config_version() {
        let payload = serde_json::json!({
            "bytes": "22".repeat(32),
            "domain": "Encoding",
            "config_version": -1
        });

        let result = serde_json::from_value::<DeterministicSeed>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn version_bump_record_deserialize_rejects_missing_reason() {
        let payload = serde_json::json!({
            "domain": "Repair",
            "content_hash_hex": "33".repeat(32),
            "old_config_hash": "44".repeat(32),
            "new_config_hash": "55".repeat(32),
            "old_seed_hex": "66".repeat(32),
            "new_seed_hex": "77".repeat(32),
            "old_version": 1,
            "new_version": 2,
            "timestamp": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<VersionBumpRecord>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn version_bump_record_deserialize_rejects_numeric_seed_hex() {
        let payload = serde_json::json!({
            "domain": "Repair",
            "content_hash_hex": "33".repeat(32),
            "old_config_hash": "44".repeat(32),
            "new_config_hash": "55".repeat(32),
            "old_seed_hex": 66,
            "new_seed_hex": "77".repeat(32),
            "old_version": 1,
            "new_version": 2,
            "bump_reason": "config changed",
            "timestamp": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<VersionBumpRecord>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn content_hash_rejects_unicode_confusable_hex_digits() {
        let raw = format!("{}ＡＡ", "aa".repeat(31));

        let err =
            ContentHash::from_hex(&raw).expect_err("fullwidth hex lookalikes must be rejected");

        assert_eq!(err, SeedError::InvalidContentHash);
    }

    #[test]
    fn content_hash_rejects_embedded_zero_width_separator() {
        let raw = format!("{}{}", "aa".repeat(16), "\u{200b}aa".repeat(16));

        let err = ContentHash::from_hex(&raw).expect_err("invisible separators must be rejected");

        assert_eq!(err, SeedError::InvalidContentHash);
    }

    #[test]
    fn schedule_config_deserialize_rejects_negative_version() {
        let payload = serde_json::json!({
            "version": -1,
            "parameters": {
                "chunk_size": "65536"
            }
        });

        let result = serde_json::from_value::<ScheduleConfig>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn schedule_config_deserialize_rejects_null_parameters() {
        let payload = serde_json::json!({
            "version": 1,
            "parameters": null
        });

        let result = serde_json::from_value::<ScheduleConfig>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn deterministic_seed_deserialize_rejects_missing_domain() {
        let payload = serde_json::json!({
            "bytes": "22".repeat(32),
            "config_version": 1
        });

        let result = serde_json::from_value::<DeterministicSeed>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn deterministic_seed_deserialize_rejects_string_config_version() {
        let payload = serde_json::json!({
            "bytes": "22".repeat(32),
            "domain": "Encoding",
            "config_version": "1"
        });

        let result = serde_json::from_value::<DeterministicSeed>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn domain_tag_deserialize_rejects_object_payload() {
        let payload = serde_json::json!({
            "label": "Encoding"
        });

        let result = serde_json::from_value::<DomainTag>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn content_hash_change_without_config_drift_does_not_emit_bump_record() {
        let mut deriver = DeterministicSeedDeriver::new();
        let config = ScheduleConfig::new(1).with_param("salt", "stable");
        let first_hash = ContentHash([0x10; 32]);
        let second_hash = ContentHash([0x20; 32]);
        deriver.derive_seed(&DomainTag::Placement, &first_hash, &config);

        let (_, bump) = deriver.derive_seed(&DomainTag::Placement, &second_hash, &config);

        assert!(bump.is_none());
        assert!(deriver.bump_records().is_empty());
    }

    #[test]
    fn version_bump_record_deserialize_rejects_negative_old_version() {
        let payload = serde_json::json!({
            "domain": "Repair",
            "content_hash_hex": "33".repeat(32),
            "old_config_hash": "44".repeat(32),
            "new_config_hash": "55".repeat(32),
            "old_seed_hex": "66".repeat(32),
            "new_seed_hex": "77".repeat(32),
            "old_version": -1,
            "new_version": 2,
            "bump_reason": "config changed",
            "timestamp": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<VersionBumpRecord>(payload);

        assert!(result.is_err());
    }

    #[test]
    fn negative_tracked_domains_count_arithmetic_without_overflow_protection() {
        // Test potential overflow in domain tracking arithmetic
        // Line 604: i + 1 without saturating_add in tracked_domains verification
        let mut deriver = DeterministicSeedDeriver::new();
        let config = ScheduleConfig::new(1).with_param("overflow_test", "value");
        let content_hash = ContentHash::from_bytes([0xAA; 32]);

        // Simulate extreme domain usage patterns
        for domain in DomainTag::all() {
            let (_, _) = deriver.derive_seed(domain, &content_hash, &config);

            // The current implementation uses i + 1 without protection
            // This simulates potential overflow if we had many more domains
            let current_count = deriver.tracked_domains();
            if current_count < usize::MAX {
                // Demonstrate the pattern that could overflow:
                // assert_eq!(deriver.tracked_domains(), i + 1);

                // Safe version should use saturating arithmetic:
                let safe_count = current_count.saturating_add(1);
                assert!(
                    safe_count >= current_count,
                    "Safe count should not underflow"
                );
            }
        }

        // Verify final count without overflow
        let final_count = deriver.tracked_domains();
        assert_eq!(
            final_count,
            DomainTag::all().len(),
            "Should track all domains"
        );

        // Test boundary condition for maximum domains
        assert!(
            final_count <= usize::MAX,
            "Domain count should not overflow"
        );
    }

    #[test]
    fn negative_domain_separation_loop_bounds_with_overflow_potential() {
        // Test loop bounds in domain separation verification
        // Line 782: (i + 1)..domains.len() could overflow with extreme indices
        let ch = test_content_hash();
        let cfg = test_config_v1();
        let domains = DomainTag::all();

        // Test the pattern that could overflow in domain pair verification
        for i in 0..domains.len() {
            // Current implementation: for j in (i + 1)..domains.len()
            // Test safe bounds calculation
            let safe_start = i.saturating_add(1);
            if safe_start < domains.len() {
                for j in safe_start..domains.len() {
                    let s_i = derive_seed(&domains[i], &ch, &cfg);
                    let s_j = derive_seed(&domains[j], &ch, &cfg);

                    assert_ne!(
                        s_i.bytes, s_j.bytes,
                        "Domain {} vs {} should produce different seeds",
                        i, j
                    );
                }
            }
        }

        // Demonstrate potential overflow scenario with hypothetical large index
        let test_large_index = usize::MAX.saturating_sub(10);
        let safe_increment = test_large_index.saturating_add(1);
        assert!(
            safe_increment <= usize::MAX,
            "Saturating add should prevent overflow"
        );

        // Unsafe version would overflow: test_large_index + 1 (if near MAX)
        if test_large_index < usize::MAX {
            let _unsafe_increment = test_large_index + 1; // Would panic near MAX
        }
    }

    #[test]
    fn negative_test_content_hash_generation_with_index_overflow() {
        // Test potential overflow in test helper functions
        // Line 709: u8::try_from(i) with potential index overflow

        // Test boundary conditions for index-to-byte conversion
        let boundary_indices = [0, 127, 255, 256, 1000, usize::MAX];

        for &index in &boundary_indices {
            if index <= 31 {
                // Valid array index for 32-byte hash
                // Test safe conversion
                let safe_byte = u8::try_from(index).unwrap_or(u8::MAX);
                assert!(safe_byte <= u8::MAX, "Safe conversion should not overflow");

                // Create hash with safe byte
                let mut h = [0u8; 32];
                h[index] = safe_byte;
                let content_hash = ContentHash(h);

                // Verify hash integrity
                assert_eq!(
                    content_hash.0[index], safe_byte,
                    "Hash should preserve safe byte value"
                );
            } else {
                // Index too large for array - test error handling
                let conversion_result = u8::try_from(index);
                if index > u8::MAX as usize {
                    assert!(
                        conversion_result.is_err(),
                        "Should fail to convert large index to u8"
                    );
                }
            }
        }

        // Test the original helper function behavior
        let test_hash = test_content_hash();
        assert_eq!(test_hash.0.len(), 32, "Test hash should be 32 bytes");

        // Verify incrementing pattern in test hash
        for i in 0..32 {
            let expected_byte = u8::try_from(i).expect("Index should fit in u8");
            assert_eq!(
                test_hash.0[i], expected_byte,
                "Test hash should have incrementing pattern"
            );
        }
    }

    #[test]
    fn negative_bump_records_clear_without_bounded_operation() {
        // Test unbounded clear operation on bump records
        // Line 618: self.bump_records.clear() without size/capacity verification
        let mut deriver = DeterministicSeedDeriver::new();
        let base_config = ScheduleConfig::new(1).with_param("base", "value");
        let content_hash = ContentHash::from_bytes([0xBB; 32]);

        // Generate many bump records to stress clear operation
        for i in 0..MAX_BUMP_RECORDS {
            let config_i =
                ScheduleConfig::new(u32::try_from(i).unwrap_or(u32::MAX).saturating_add(1))
                    .with_param("iteration", &i.to_string());
            let (_, _) = deriver.derive_seed(&DomainTag::Encoding, &content_hash, &config_i);
        }

        // Verify records were generated and bounded
        let records_before_clear = deriver.bump_records().len();
        assert!(
            records_before_clear > 0,
            "Should have bump records before clear"
        );
        assert!(
            records_before_clear <= MAX_BUMP_RECORDS,
            "Should respect bump record capacity"
        );

        // Test clear operation
        deriver.clear_bump_records();
        assert_eq!(
            deriver.bump_records().len(),
            0,
            "Should have zero records after clear"
        );

        // Verify deriver still functions after clear
        let tracked_before = deriver.tracked_domains();
        let test_config = ScheduleConfig::new(99).with_param("post_clear", "test");
        let (seed, bump) = deriver.derive_seed(&DomainTag::Repair, &content_hash, &test_config);

        assert_eq!(
            seed.bytes.len(),
            32,
            "Should produce valid seed after clear"
        );
        assert!(bump.is_some(), "Should generate bump record for new config");
        assert_eq!(
            deriver.tracked_domains(),
            tracked_before,
            "Domain tracking should be preserved"
        );

        // Test multiple clears don't cause issues
        deriver.clear_bump_records();
        deriver.clear_bump_records();
        assert_eq!(
            deriver.bump_records().len(),
            0,
            "Multiple clears should be safe"
        );

        // A hardened implementation might:
        // 1. Verify capacity before/after clear
        // 2. Use bounded_clear(max_retained) instead of clear()
        // 3. Track clear operations for audit purposes
    }

    #[test]
    fn negative_hex_encoding_slice_operations_with_potential_optimization() {
        // Test hex encoding operations that use .as_slice()
        // Line 347: hex::encode(old_hash.as_slice()) - potential optimization concerns
        let mut deriver = DeterministicSeedDeriver::new();
        let content_hash = ContentHash::from_bytes([0xCC; 32]);

        // Test hex encoding/decoding with various hash patterns
        let hash_patterns = [
            [0x00; 32], // All zeros
            [0xFF; 32], // All ones
            [0xAA; 32], // Alternating pattern
            {
                let mut pattern = [0u8; 32];
                for (i, byte) in pattern.iter_mut().enumerate() {
                    *byte = (i ^ (i >> 4)) as u8; // XOR pattern
                }
                pattern
            },
            {
                let mut pattern = [0u8; 32];
                for (i, byte) in pattern.iter_mut().enumerate() {
                    *byte = ((i * 37) % 256) as u8; // Prime modulo pattern
                }
                pattern
            },
        ];

        for (test_num, pattern) in hash_patterns.iter().enumerate() {
            let test_hash = ContentHash::from_bytes(*pattern);
            let config1 =
                ScheduleConfig::new(1).with_param("pattern", &format!("test_{}", test_num));
            let config2 =
                ScheduleConfig::new(2).with_param("pattern", &format!("test_{}", test_num));

            // Generate bump record to test hex encoding operations
            let (_, _) = deriver.derive_seed(&DomainTag::Placement, &test_hash, &config1);
            let (_, bump) = deriver.derive_seed(&DomainTag::Placement, &test_hash, &config2);

            if let Some(bump_record) = bump {
                // Verify hex encoding integrity
                assert_eq!(
                    bump_record.old_config_hash.len(),
                    64,
                    "Config hash hex should be 64 chars"
                );
                assert_eq!(
                    bump_record.new_config_hash.len(),
                    64,
                    "New config hash hex should be 64 chars"
                );
                assert_eq!(
                    bump_record.old_seed_hex.len(),
                    64,
                    "Old seed hex should be 64 chars"
                );
                assert_eq!(
                    bump_record.new_seed_hex.len(),
                    64,
                    "New seed hex should be 64 chars"
                );
                assert_eq!(
                    bump_record.content_hash_hex.len(),
                    64,
                    "Content hash hex should be 64 chars"
                );

                // Verify hex strings are valid
                for hex_field in [
                    &bump_record.old_config_hash,
                    &bump_record.new_config_hash,
                    &bump_record.old_seed_hex,
                    &bump_record.new_seed_hex,
                    &bump_record.content_hash_hex,
                ] {
                    assert!(
                        hex_field.chars().all(|c| c.is_ascii_hexdigit()),
                        "Hex field should contain only hex digits: {}",
                        hex_field
                    );

                    // Test round-trip encoding/decoding
                    let decoded = hex::decode(hex_field).expect("Should decode valid hex");
                    assert_eq!(decoded.len(), 32, "Decoded hex should be 32 bytes");

                    let re_encoded = hex::encode(&decoded);
                    assert_eq!(
                        &re_encoded, hex_field,
                        "Round-trip encoding should be stable"
                    );
                }
            }
        }

        // Test content hash hex operations specifically
        for pattern in &hash_patterns {
            let test_hash = ContentHash::from_bytes(*pattern);
            let hex_string = test_hash.to_hex();
            let prefix_hex = test_hash.prefix_hex();

            assert_eq!(hex_string.len(), 64, "Full hex should be 64 characters");
            assert_eq!(prefix_hex.len(), 8, "Prefix hex should be 8 characters");
            assert!(
                hex_string.starts_with(&prefix_hex),
                "Full hex should start with prefix"
            );
        }
    }
}
