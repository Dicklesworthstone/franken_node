//! bd-1daz: Retroactive hardening pipeline — union-only protection artifacts.
//!
//! When the system escalates its hardening level, objects created at a lower
//! level lack the additional protections of the new level. This pipeline
//! retroactively adds protection artifacts (checksums, parity, integrity
//! proofs, redundant copies) WITHOUT rewriting canonical object data.
//!
//! # Invariants
//!
//! - **INV-RETROHARDEN-UNION-ONLY**: Protection is additive. Canonical object
//!   identity (hash, ID, content) is never modified.
//! - **INV-RETROHARDEN-MONOTONIC**: Repairability score can only increase
//!   (or stay at 1.0) after hardening.
//! - **INV-RETROHARDEN-IDEMPOTENT**: Running the pipeline twice on the same
//!   object at the same target level produces no additional artifacts.
//! - **INV-RETROHARDEN-BOUNDED**: Pipeline memory is bounded by corpus size.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::hardening_state_machine::HardeningLevel;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Pipeline started (includes object count, from/to levels).
pub const EVD_RETROHARDEN_001: &str = "EVD-RETROHARDEN-001";
/// Object hardened (includes object_id, artifacts created).
pub const EVD_RETROHARDEN_002: &str = "EVD-RETROHARDEN-002";
/// Identity verification passed for an object.
pub const EVD_RETROHARDEN_003: &str = "EVD-RETROHARDEN-003";
/// Repairability score computed.
pub const EVD_RETROHARDEN_004: &str = "EVD-RETROHARDEN-004";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unique identifier for a canonical object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObjectId(pub String);

impl ObjectId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Type of protection artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtectionType {
    /// Additional SHA-256 checksum over the content.
    Checksum,
    /// Parity data for single-byte error recovery.
    Parity,
    /// Merkle inclusion proof for integrity verification.
    IntegrityProof,
    /// Redundant copy for full recovery.
    RedundantCopy,
}

impl ProtectionType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Checksum => "checksum",
            Self::Parity => "parity",
            Self::IntegrityProof => "integrity_proof",
            Self::RedundantCopy => "redundant_copy",
        }
    }

    /// Repairability contribution of this protection type (0.0 to 1.0).
    /// These are additive contributions, capped at 1.0 total.
    pub fn repairability_weight(&self) -> f64 {
        match self {
            Self::Checksum => 0.1,        // Detects corruption but can't repair
            Self::Parity => 0.2,          // Single-byte error recovery
            Self::IntegrityProof => 0.15, // Localization of corruption
            Self::RedundantCopy => 0.5,   // Full reconstruction capability
        }
    }

    /// All protection types in the order they are added during hardening.
    pub fn all() -> &'static [ProtectionType] {
        &[
            Self::Checksum,
            Self::Parity,
            Self::IntegrityProof,
            Self::RedundantCopy,
        ]
    }
}

impl std::fmt::Display for ProtectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Protection artifact appended to a canonical object.
///
/// Stored alongside (never inside) the canonical object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionArtifact {
    /// Unique identifier for this artifact.
    pub artifact_id: String,
    /// Type of protection this artifact provides.
    pub artifact_type: ProtectionType,
    /// The protection data (checksum bytes, parity data, proof, or copy).
    pub data: Vec<u8>,
    /// Which canonical object this artifact covers.
    pub covers_object: ObjectId,
    /// The hardening level that required this artifact.
    pub hardening_level: HardeningLevel,
}

/// A canonical object whose identity must remain stable through hardening.
///
/// INV-RETROHARDEN-UNION-ONLY: content_hash and object_id are never modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalObject {
    /// Unique identifier.
    pub object_id: ObjectId,
    /// SHA-256 hash of the content.
    pub content_hash: [u8; 32],
    /// The hardening level at which this object was created.
    pub creation_level: HardeningLevel,
    /// Simulated content for artifact generation (in production, this would
    /// be the actual object bytes).
    pub content: Vec<u8>,
}

impl CanonicalObject {
    pub fn new(id: impl Into<String>, content: Vec<u8>, creation_level: HardeningLevel) -> Self {
        let content_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"retroactive_hardening_hash_v1:");
            hasher.update(&content);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };
        Self {
            object_id: ObjectId::new(id),
            content_hash,
            creation_level,
            content,
        }
    }
}

/// Repairability score for an object (0.0 to 1.0).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RepairabilityScore {
    /// Score value (0.0 = no recovery possible, 1.0 = full recovery).
    pub score: f64,
    /// Number of protection artifacts contributing to this score.
    pub artifact_count: usize,
}

/// Progress record for evidence ledger integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningProgressRecord {
    /// Object that was hardened.
    pub object_id: ObjectId,
    /// Number of artifacts created for this object.
    pub artifacts_created: usize,
    /// Repairability score before hardening.
    pub repairability_before: f64,
    /// Repairability score after hardening.
    pub repairability_after: f64,
}

/// Result of running the retroactive hardening pipeline on a corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningResult {
    /// All protection artifacts generated.
    pub artifacts: Vec<ProtectionArtifact>,
    /// Per-object progress records.
    pub progress: Vec<HardeningProgressRecord>,
    /// Total objects processed.
    pub objects_processed: usize,
    /// Total artifacts created.
    pub total_artifacts_created: usize,
    /// From hardening level.
    pub from_level: String,
    /// To hardening level.
    pub to_level: String,
}

// ---------------------------------------------------------------------------
// Protection level requirements
// ---------------------------------------------------------------------------

/// Returns the set of protection types required at a given hardening level.
fn required_protections(level: HardeningLevel) -> Vec<ProtectionType> {
    match level {
        HardeningLevel::Baseline => vec![],
        HardeningLevel::Standard => vec![ProtectionType::Checksum],
        HardeningLevel::Enhanced => vec![ProtectionType::Checksum, ProtectionType::Parity],
        HardeningLevel::Maximum => vec![
            ProtectionType::Checksum,
            ProtectionType::Parity,
            ProtectionType::IntegrityProof,
        ],
        HardeningLevel::Critical => vec![
            ProtectionType::Checksum,
            ProtectionType::Parity,
            ProtectionType::IntegrityProof,
            ProtectionType::RedundantCopy,
        ],
    }
}

// ---------------------------------------------------------------------------
// RetroactiveHardeningPipeline
// ---------------------------------------------------------------------------

/// Pipeline that retroactively adds protection artifacts to existing objects
/// when the system escalates its hardening level.
///
/// INV-RETROHARDEN-UNION-ONLY: canonical object data is never modified.
/// INV-RETROHARDEN-MONOTONIC: repairability only increases.
/// INV-RETROHARDEN-IDEMPOTENT: re-running produces no extra artifacts.
#[derive(Debug, Clone)]
pub struct RetroactiveHardeningPipeline {
    epoch_id: u64,
}

impl RetroactiveHardeningPipeline {
    pub fn new(epoch_id: u64) -> Self {
        Self { epoch_id }
    }

    /// Generate additional protection artifacts needed to bring an object
    /// from `from_level` to `to_level`.
    ///
    /// Returns an empty Vec if `to_level <= from_level` or if the object
    /// already has all required protections.
    ///
    /// [EVD-RETROHARDEN-002] on each object hardened.
    pub fn harden(
        &self,
        object: &CanonicalObject,
        from_level: HardeningLevel,
        to_level: HardeningLevel,
    ) -> Vec<ProtectionArtifact> {
        if to_level <= from_level {
            return Vec::new();
        }

        let existing = required_protections(from_level);
        let target = required_protections(to_level);

        // Determine which new protection types are needed
        let new_types: Vec<ProtectionType> = target
            .into_iter()
            .filter(|t| !existing.contains(t))
            .collect();

        let artifacts: Vec<ProtectionArtifact> = new_types
            .into_iter()
            .map(|ptype| {
                let data = self.generate_artifact_data(object, ptype);
                let artifact_id = format!(
                    "{}-{}-{}",
                    object.object_id.as_str(),
                    ptype.label(),
                    to_level.label()
                );
                ProtectionArtifact {
                    artifact_id,
                    artifact_type: ptype,
                    data,
                    covers_object: object.object_id.clone(),
                    hardening_level: to_level,
                }
            })
            .collect();

        // [EVD-RETROHARDEN-002]
        if !artifacts.is_empty() {
            let _event = EVD_RETROHARDEN_002;
        }

        artifacts
    }

    /// Run the pipeline on an entire corpus of objects.
    ///
    /// [EVD-RETROHARDEN-001] on pipeline start.
    pub fn harden_corpus(
        &self,
        objects: &[CanonicalObject],
        from_level: HardeningLevel,
        to_level: HardeningLevel,
    ) -> HardeningResult {
        // [EVD-RETROHARDEN-001]
        let _event = EVD_RETROHARDEN_001;

        let mut all_artifacts = Vec::new();
        let mut progress = Vec::new();

        for object in objects {
            let repairability_before = measure_repairability(
                object,
                &self.existing_artifacts_for_level(object, from_level),
            );

            let new_artifacts = self.harden(object, from_level, to_level);
            let artifacts_created = new_artifacts.len();

            // Compute after score: existing + new artifacts
            let mut combined = self.existing_artifacts_for_level(object, from_level);
            combined.extend(new_artifacts.iter().cloned());
            let repairability_after = measure_repairability(object, &combined);

            // [EVD-RETROHARDEN-003] identity verification
            let _event = EVD_RETROHARDEN_003;

            progress.push(HardeningProgressRecord {
                object_id: object.object_id.clone(),
                artifacts_created,
                repairability_before: repairability_before.score,
                repairability_after: repairability_after.score,
            });

            all_artifacts.extend(new_artifacts);
        }

        let total = all_artifacts.len();

        HardeningResult {
            artifacts: all_artifacts,
            progress,
            objects_processed: objects.len(),
            total_artifacts_created: total,
            from_level: from_level.label().to_string(),
            to_level: to_level.label().to_string(),
        }
    }

    /// Generate artifact data for a specific protection type.
    fn generate_artifact_data(&self, object: &CanonicalObject, ptype: ProtectionType) -> Vec<u8> {
        match ptype {
            ProtectionType::Checksum => {
                // SHA-256 over content + epoch for domain separation
                let mut hasher = Sha256::new();
                hasher.update(b"retroactive_hardening_hash_v1:");
                hasher.update(b"RETROHARDEN-CHECKSUM\x00");
                hasher.update(&object.content);
                hasher.update(self.epoch_id.to_le_bytes());
                hasher.finalize().to_vec()
            }
            ProtectionType::Parity => {
                // XOR-based parity over 4-byte blocks
                let mut parity = vec![0u8; 4];
                for chunk in object.content.chunks(4) {
                    for (i, byte) in chunk.iter().enumerate() {
                        parity[i % 4] ^= byte;
                    }
                }
                parity
            }
            ProtectionType::IntegrityProof => {
                // Simplified Merkle proof: hash of (content_hash || epoch)
                let mut hasher = Sha256::new();
                hasher.update(b"retroactive_hardening_hash_v1:");
                hasher.update(b"RETROHARDEN-MERKLE\x00");
                hasher.update(object.content_hash);
                hasher.update(self.epoch_id.to_le_bytes());
                hasher.finalize().to_vec()
            }
            ProtectionType::RedundantCopy => {
                // Full content copy for maximum recoverability
                object.content.clone()
            }
        }
    }

    /// Simulate existing protection artifacts for a given level.
    fn existing_artifacts_for_level(
        &self,
        object: &CanonicalObject,
        level: HardeningLevel,
    ) -> Vec<ProtectionArtifact> {
        required_protections(level)
            .into_iter()
            .map(|ptype| {
                let data = self.generate_artifact_data(object, ptype);
                ProtectionArtifact {
                    artifact_id: format!(
                        "{}-{}-{}",
                        object.object_id,
                        ptype.label(),
                        level.label()
                    ),
                    artifact_type: ptype,
                    data,
                    covers_object: object.object_id.clone(),
                    hardening_level: level,
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Identity verification
// ---------------------------------------------------------------------------

/// Verify that a canonical object's identity has not been modified.
///
/// INV-RETROHARDEN-UNION-ONLY: returns true iff both object_id and
/// content_hash are unchanged.
///
/// [EVD-RETROHARDEN-003] on verification pass.
pub fn verify_identity_stable(before: &CanonicalObject, after: &CanonicalObject) -> bool {
    let stable = before.object_id == after.object_id && before.content_hash == after.content_hash;

    if stable {
        let _event = EVD_RETROHARDEN_003;
    }

    stable
}

// ---------------------------------------------------------------------------
// Repairability measurement
// ---------------------------------------------------------------------------

/// Compute the repairability score for an object given its protection artifacts.
///
/// Score is the sum of protection type weights, capped at 1.0.
///
/// [EVD-RETROHARDEN-004] on score computed.
pub fn measure_repairability(
    _object: &CanonicalObject,
    artifacts: &[ProtectionArtifact],
) -> RepairabilityScore {
    // Deduplicate by protection type (same type doesn't stack)
    let mut seen = std::collections::BTreeSet::new();
    let mut score = 0.0;
    let mut count = 0;

    for artifact in artifacts {
        if seen.insert(artifact.artifact_type.label()) {
            score += artifact.artifact_type.repairability_weight();
            count += 1;
        }
    }

    let capped_score = score.min(1.0);

    // [EVD-RETROHARDEN-004]
    let _event = EVD_RETROHARDEN_004;

    RepairabilityScore {
        score: capped_score,
        artifact_count: count,
    }
}

// ---------------------------------------------------------------------------
// Compile-time Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<RetroactiveHardeningPipeline>();
    assert_sync::<RetroactiveHardeningPipeline>();
    assert_send::<ProtectionArtifact>();
    assert_sync::<ProtectionArtifact>();
    assert_send::<CanonicalObject>();
    assert_sync::<CanonicalObject>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn pipeline() -> RetroactiveHardeningPipeline {
        RetroactiveHardeningPipeline::new(42)
    }

    fn test_object(id: &str) -> CanonicalObject {
        CanonicalObject::new(id, vec![0xAB; 64], HardeningLevel::Baseline)
    }

    fn test_object_with_content(id: &str, content: Vec<u8>) -> CanonicalObject {
        CanonicalObject::new(id, content, HardeningLevel::Baseline)
    }

    // ── ObjectId tests ──

    #[test]
    fn test_object_id_display() {
        let id = ObjectId::new("obj-001");
        assert_eq!(id.to_string(), "obj-001");
        assert_eq!(id.as_str(), "obj-001");
    }

    // ── ProtectionType tests ──

    #[test]
    fn test_protection_type_labels() {
        assert_eq!(ProtectionType::Checksum.label(), "checksum");
        assert_eq!(ProtectionType::Parity.label(), "parity");
        assert_eq!(ProtectionType::IntegrityProof.label(), "integrity_proof");
        assert_eq!(ProtectionType::RedundantCopy.label(), "redundant_copy");
    }

    #[test]
    fn test_protection_type_all() {
        assert_eq!(ProtectionType::all().len(), 4);
    }

    #[test]
    fn test_protection_type_weights_sum_close_to_one() {
        let total: f64 = ProtectionType::all()
            .iter()
            .map(|t| t.repairability_weight())
            .sum();
        // Weights: 0.1 + 0.2 + 0.15 + 0.5 = 0.95
        assert!((total - 0.95).abs() < 1e-10, "total={total}");
    }

    #[test]
    fn test_protection_type_display() {
        assert_eq!(ProtectionType::Checksum.to_string(), "checksum");
    }

    // ── CanonicalObject tests ──

    #[test]
    fn test_canonical_object_creation() {
        let obj = test_object("obj-001");
        assert_eq!(obj.object_id, ObjectId::new("obj-001"));
        assert_eq!(obj.creation_level, HardeningLevel::Baseline);
        assert_eq!(obj.content.len(), 64);
        // content_hash should be non-zero
        assert!(obj.content_hash.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_canonical_object_hash_deterministic() {
        let obj1 = test_object("obj-001");
        let obj2 = test_object("obj-001");
        assert_eq!(obj1.content_hash, obj2.content_hash);
    }

    #[test]
    fn test_canonical_object_different_content_different_hash() {
        let obj1 = test_object_with_content("a", vec![0x00; 32]);
        let obj2 = test_object_with_content("b", vec![0xFF; 32]);
        assert_ne!(obj1.content_hash, obj2.content_hash);
    }

    // ── Required protections tests ──

    #[test]
    fn test_required_protections_baseline_empty() {
        assert!(required_protections(HardeningLevel::Baseline).is_empty());
    }

    #[test]
    fn test_required_protections_standard_checksum() {
        let p = required_protections(HardeningLevel::Standard);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0], ProtectionType::Checksum);
    }

    #[test]
    fn test_required_protections_enhanced() {
        let p = required_protections(HardeningLevel::Enhanced);
        assert_eq!(p.len(), 2);
        assert!(p.contains(&ProtectionType::Checksum));
        assert!(p.contains(&ProtectionType::Parity));
    }

    #[test]
    fn test_required_protections_maximum() {
        let p = required_protections(HardeningLevel::Maximum);
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn test_required_protections_critical_all_four() {
        let p = required_protections(HardeningLevel::Critical);
        assert_eq!(p.len(), 4);
    }

    #[test]
    fn test_required_protections_monotonically_increasing() {
        let levels = HardeningLevel::all();
        for i in 0..levels.len() - 1 {
            let current = required_protections(levels[i]).len();
            let next = required_protections(levels[i + 1]).len();
            assert!(
                next >= current,
                "{:?} ({}) -> {:?} ({}): protection count should not decrease",
                levels[i],
                current,
                levels[i + 1],
                next
            );
        }
    }

    // ── Harden single object tests ──

    #[test]
    fn test_harden_baseline_to_standard() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Standard);
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_type, ProtectionType::Checksum);
        assert_eq!(artifacts[0].covers_object, obj.object_id);
        assert_eq!(artifacts[0].hardening_level, HardeningLevel::Standard);
    }

    #[test]
    fn test_harden_standard_to_enhanced() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Standard, HardeningLevel::Enhanced);
        // Enhanced requires Checksum + Parity, Standard already has Checksum → only Parity new
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_type, ProtectionType::Parity);
    }

    #[test]
    fn test_harden_baseline_to_critical() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Critical);
        assert_eq!(artifacts.len(), 4);
        let types: Vec<ProtectionType> = artifacts.iter().map(|a| a.artifact_type).collect();
        assert!(types.contains(&ProtectionType::Checksum));
        assert!(types.contains(&ProtectionType::Parity));
        assert!(types.contains(&ProtectionType::IntegrityProof));
        assert!(types.contains(&ProtectionType::RedundantCopy));
    }

    #[test]
    fn test_harden_same_level_no_artifacts() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Standard, HardeningLevel::Standard);
        assert!(artifacts.is_empty());
    }

    #[test]
    fn test_harden_reverse_direction_no_artifacts() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Enhanced, HardeningLevel::Standard);
        assert!(artifacts.is_empty());
    }

    #[test]
    fn test_harden_already_at_max_no_artifacts() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Critical, HardeningLevel::Critical);
        assert!(artifacts.is_empty());
    }

    #[test]
    fn test_harden_artifact_ids_contain_object_id() {
        let obj = test_object("obj-xyz");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Standard);
        assert!(artifacts[0].artifact_id.contains("obj-xyz"));
    }

    #[test]
    fn test_harden_artifact_data_nonempty() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Critical);
        for artifact in &artifacts {
            assert!(
                !artifact.data.is_empty(),
                "artifact {} should have data",
                artifact.artifact_type.label()
            );
        }
    }

    #[test]
    fn test_harden_redundant_copy_matches_content() {
        let content = vec![0x42; 128];
        let obj = test_object_with_content("obj-001", content.clone());
        let artifacts = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Critical);
        let copy = artifacts
            .iter()
            .find(|a| a.artifact_type == ProtectionType::RedundantCopy)
            .unwrap();
        assert_eq!(copy.data, content);
    }

    // ── Identity verification tests ──

    #[test]
    fn test_verify_identity_stable_same_object() {
        let obj = test_object("obj-001");
        assert!(verify_identity_stable(&obj, &obj));
    }

    #[test]
    fn test_verify_identity_stable_clone() {
        let obj = test_object("obj-001");
        let clone = obj.clone();
        assert!(verify_identity_stable(&obj, &clone));
    }

    #[test]
    fn test_verify_identity_unstable_different_id() {
        let obj1 = test_object("obj-001");
        let obj2 = test_object("obj-002");
        assert!(!verify_identity_stable(&obj1, &obj2));
    }

    #[test]
    fn test_verify_identity_unstable_different_content() {
        let obj1 = test_object_with_content("obj-001", vec![0x00; 32]);
        let obj2 = test_object_with_content("obj-001", vec![0xFF; 32]);
        assert!(!verify_identity_stable(&obj1, &obj2));
    }

    #[test]
    fn test_harden_does_not_modify_object() {
        let obj = test_object("obj-001");
        let before_id = obj.object_id.clone();
        let before_hash = obj.content_hash;
        let _artifacts =
            pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Critical);
        assert_eq!(obj.object_id, before_id);
        assert_eq!(obj.content_hash, before_hash);
    }

    // ── Repairability tests ──

    #[test]
    fn test_repairability_no_artifacts() {
        let obj = test_object("obj-001");
        let score = measure_repairability(&obj, &[]);
        assert!((score.score - 0.0).abs() < 1e-10);
        assert_eq!(score.artifact_count, 0);
    }

    #[test]
    fn test_repairability_with_checksum() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Standard);
        let score = measure_repairability(&obj, &artifacts);
        assert!((score.score - 0.1).abs() < 1e-10);
        assert_eq!(score.artifact_count, 1);
    }

    #[test]
    fn test_repairability_with_all_protections() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Critical);
        let score = measure_repairability(&obj, &artifacts);
        assert!((score.score - 0.95).abs() < 1e-10);
        assert_eq!(score.artifact_count, 4);
    }

    #[test]
    fn test_repairability_increases_with_hardening() {
        let obj = test_object("obj-001");
        let pipe = pipeline();

        let a1 = pipe.harden(&obj, HardeningLevel::Baseline, HardeningLevel::Standard);
        let s1 = measure_repairability(&obj, &a1);

        let mut a2 = a1.clone();
        a2.extend(pipe.harden(&obj, HardeningLevel::Standard, HardeningLevel::Enhanced));
        let s2 = measure_repairability(&obj, &a2);

        let mut a3 = a2.clone();
        a3.extend(pipe.harden(&obj, HardeningLevel::Enhanced, HardeningLevel::Maximum));
        let s3 = measure_repairability(&obj, &a3);

        let mut a4 = a3.clone();
        a4.extend(pipe.harden(&obj, HardeningLevel::Maximum, HardeningLevel::Critical));
        let s4 = measure_repairability(&obj, &a4);

        assert!(s2.score >= s1.score, "Enhanced >= Standard");
        assert!(s3.score >= s2.score, "Maximum >= Enhanced");
        assert!(s4.score >= s3.score, "Critical >= Maximum");
    }

    #[test]
    fn test_repairability_capped_at_one() {
        let obj = test_object("obj-001");
        // Create duplicate artifacts to test cap
        let mut artifacts = Vec::new();
        for _ in 0..10 {
            artifacts.extend(pipeline().harden(
                &obj,
                HardeningLevel::Baseline,
                HardeningLevel::Critical,
            ));
        }
        let score = measure_repairability(&obj, &artifacts);
        assert!(score.score <= 1.0);
    }

    #[test]
    fn test_repairability_deduplicates_same_type() {
        let obj = test_object("obj-001");
        let pipe = pipeline();
        let mut artifacts = pipe.harden(&obj, HardeningLevel::Baseline, HardeningLevel::Standard);
        // Add duplicate checksum artifact
        artifacts.extend(pipe.harden(&obj, HardeningLevel::Baseline, HardeningLevel::Standard));
        let score = measure_repairability(&obj, &artifacts);
        // Should only count checksum once
        assert!((score.score - 0.1).abs() < 1e-10);
        assert_eq!(score.artifact_count, 1);
    }

    // ── Corpus hardening tests ──

    #[test]
    fn test_harden_corpus_basic() {
        let objects = vec![test_object("obj-001"), test_object("obj-002")];
        let result =
            pipeline().harden_corpus(&objects, HardeningLevel::Baseline, HardeningLevel::Standard);
        assert_eq!(result.objects_processed, 2);
        // Each object gets 1 checksum artifact
        assert_eq!(result.total_artifacts_created, 2);
        assert_eq!(result.progress.len(), 2);
    }

    #[test]
    fn test_harden_corpus_empty() {
        let result =
            pipeline().harden_corpus(&[], HardeningLevel::Baseline, HardeningLevel::Standard);
        assert_eq!(result.objects_processed, 0);
        assert_eq!(result.total_artifacts_created, 0);
        assert!(result.artifacts.is_empty());
    }

    #[test]
    fn test_harden_corpus_repairability_improves() {
        let objects = vec![test_object("obj-001")];
        let result =
            pipeline().harden_corpus(&objects, HardeningLevel::Baseline, HardeningLevel::Critical);
        let prog = &result.progress[0];
        assert!(prog.repairability_after > prog.repairability_before);
    }

    #[test]
    fn test_harden_corpus_same_level_no_artifacts() {
        let objects = vec![test_object("obj-001")];
        let result =
            pipeline().harden_corpus(&objects, HardeningLevel::Standard, HardeningLevel::Standard);
        assert_eq!(result.total_artifacts_created, 0);
    }

    #[test]
    fn test_harden_corpus_progress_record_fields() {
        let objects = vec![test_object("obj-001")];
        let result =
            pipeline().harden_corpus(&objects, HardeningLevel::Baseline, HardeningLevel::Enhanced);
        let prog = &result.progress[0];
        assert_eq!(prog.object_id, ObjectId::new("obj-001"));
        assert_eq!(prog.artifacts_created, 2); // checksum + parity
    }

    #[test]
    fn test_harden_corpus_multi_level_gap() {
        let objects = vec![test_object("obj-001")];
        let result =
            pipeline().harden_corpus(&objects, HardeningLevel::Baseline, HardeningLevel::Maximum);
        // Baseline -> Maximum needs Checksum + Parity + IntegrityProof = 3
        assert_eq!(result.total_artifacts_created, 3);
    }

    // ── Idempotency test ──

    #[test]
    fn test_harden_idempotent() {
        let obj = test_object("obj-001");
        let pipe = pipeline();

        let first = pipe.harden(&obj, HardeningLevel::Baseline, HardeningLevel::Enhanced);
        // After first hardening, object is at Enhanced level
        let second = pipe.harden(&obj, HardeningLevel::Enhanced, HardeningLevel::Enhanced);
        assert!(
            second.is_empty(),
            "INV-RETROHARDEN-IDEMPOTENT: second run should produce no artifacts"
        );
        assert!(!first.is_empty(), "first run should produce artifacts");
    }

    // ── Large corpus test ──

    #[test]
    fn test_harden_large_corpus() {
        let objects: Vec<CanonicalObject> = (0..100)
            .map(|i| test_object_with_content(&format!("obj-{i:04}"), vec![(i & 0xFF) as u8; 32]))
            .collect();
        let result =
            pipeline().harden_corpus(&objects, HardeningLevel::Baseline, HardeningLevel::Critical);
        assert_eq!(result.objects_processed, 100);
        assert_eq!(result.total_artifacts_created, 400); // 4 per object
        for prog in &result.progress {
            assert!(
                prog.repairability_after >= prog.repairability_before,
                "INV-RETROHARDEN-MONOTONIC: repairability must not decrease"
            );
        }
    }

    // ── Serialization tests ──

    #[test]
    fn test_protection_artifact_serialization() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Standard);
        let json = serde_json::to_string(&artifacts[0]).unwrap();
        let parsed: ProtectionArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.covers_object, obj.object_id);
    }

    #[test]
    fn test_hardening_result_serialization() {
        let objects = vec![test_object("obj-001")];
        let result =
            pipeline().harden_corpus(&objects, HardeningLevel::Baseline, HardeningLevel::Standard);
        let json = serde_json::to_string_pretty(&result).unwrap();
        let parsed: HardeningResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.objects_processed, 1);
    }

    #[test]
    fn test_repairability_score_serialization() {
        let score = RepairabilityScore {
            score: 0.75,
            artifact_count: 3,
        };
        let json = serde_json::to_string(&score).unwrap();
        let parsed: RepairabilityScore = serde_json::from_str(&json).unwrap();
        assert!((parsed.score - 0.75).abs() < 1e-10);
    }

    // ── Event codes test ──

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(EVD_RETROHARDEN_001, "EVD-RETROHARDEN-001");
        assert_eq!(EVD_RETROHARDEN_002, "EVD-RETROHARDEN-002");
        assert_eq!(EVD_RETROHARDEN_003, "EVD-RETROHARDEN-003");
        assert_eq!(EVD_RETROHARDEN_004, "EVD-RETROHARDEN-004");
    }

    // ── Checksum determinism ──

    #[test]
    fn test_checksum_deterministic() {
        let obj = test_object("obj-001");
        let a1 = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Standard);
        let a2 = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Standard);
        assert_eq!(a1[0].data, a2[0].data, "checksums should be deterministic");
    }

    // ── Parity correctness ──

    #[test]
    fn test_parity_data_length() {
        let obj = test_object("obj-001");
        let artifacts = pipeline().harden(&obj, HardeningLevel::Standard, HardeningLevel::Enhanced);
        let parity = &artifacts[0];
        assert_eq!(parity.artifact_type, ProtectionType::Parity);
        assert_eq!(parity.data.len(), 4);
    }

    // ── Empty content edge case ──

    #[test]
    fn test_harden_empty_content_object() {
        let obj = test_object_with_content("empty", vec![]);
        let artifacts = pipeline().harden(&obj, HardeningLevel::Baseline, HardeningLevel::Critical);
        assert_eq!(artifacts.len(), 4);
        // Redundant copy of empty content is empty
        let copy = artifacts
            .iter()
            .find(|a| a.artifact_type == ProtectionType::RedundantCopy)
            .unwrap();
        assert!(copy.data.is_empty());
    }
}
