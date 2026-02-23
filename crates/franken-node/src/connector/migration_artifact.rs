//! bd-3hm: Migration singularity artifact contract and verifier format (Section 10.12).
//!
//! Defines the artifact contract for migration singularity: a structured, versioned
//! format for migration outputs including rollback receipts, confidence intervals,
//! precondition proofs, and verifier-friendly validation metadata. This bridges the
//! migration system (10.3) and the verifier economy (10.17).
//!
//! # Capabilities
//!
//! - Structured, versioned migration artifact format
//! - Rollback receipts with signer identity and procedure hash
//! - Confidence intervals with dry-run success rate and historical similarity
//! - Verifier metadata with replay capsule refs and assertion schemas
//! - Deterministic serialization via BTreeMap
//! - Reference artifact generator for testing and validation
//!
//! # Invariants
//!
//! - **INV-MA-SIGNED**: Every artifact carries a non-empty signature field.
//! - **INV-MA-ROLLBACK-PRESENT**: Every artifact includes a rollback receipt.
//! - **INV-MA-CONFIDENCE-CALIBRATED**: Confidence probability in [0.0, 1.0].
//! - **INV-MA-VERSIONED**: Every artifact carries a schema version string.
//! - **INV-MA-VERIFIER-COMPLETE**: Verifier metadata includes at least one replay
//!   capsule ref and one expected state hash.
//! - **INV-MA-DETERMINISTIC**: Same inputs produce byte-identical serialized output.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Migration artifact generated.
    pub const MA_GENERATED: &str = "MA-001";
    /// Migration artifact signed.
    pub const MA_SIGNED: &str = "MA-002";
    /// Migration artifact validated successfully.
    pub const MA_VALIDATED: &str = "MA-003";
    /// Migration artifact schema violation detected.
    pub const MA_SCHEMA_VIOLATION: &str = "MA-004";
    /// Migration artifact signature invalid.
    pub const MA_SIGNATURE_INVALID: &str = "MA-005";
    /// Migration artifact rollback receipt verified.
    pub const MA_ROLLBACK_VERIFIED: &str = "MA-006";
    /// Migration artifact confidence check passed.
    pub const MA_CONFIDENCE_CHECK: &str = "MA-007";
    /// Migration artifact version negotiated.
    pub const MA_VERSION_NEGOTIATED: &str = "MA-008";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_MA_INVALID_SCHEMA: &str = "ERR_MA_INVALID_SCHEMA";
    pub const ERR_MA_SIGNATURE_INVALID: &str = "ERR_MA_SIGNATURE_INVALID";
    pub const ERR_MA_MISSING_ROLLBACK: &str = "ERR_MA_MISSING_ROLLBACK";
    pub const ERR_MA_CONFIDENCE_LOW: &str = "ERR_MA_CONFIDENCE_LOW";
    pub const ERR_MA_VERSION_UNSUPPORTED: &str = "ERR_MA_VERSION_UNSUPPORTED";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_MA_SIGNED: &str = "INV-MA-SIGNED";
    pub const INV_MA_ROLLBACK_PRESENT: &str = "INV-MA-ROLLBACK-PRESENT";
    pub const INV_MA_CONFIDENCE_CALIBRATED: &str = "INV-MA-CONFIDENCE-CALIBRATED";
    pub const INV_MA_VERSIONED: &str = "INV-MA-VERSIONED";
    pub const INV_MA_VERIFIER_COMPLETE: &str = "INV-MA-VERIFIER-COMPLETE";
    pub const INV_MA_DETERMINISTIC: &str = "INV-MA-DETERMINISTIC";
}

/// Schema version for the current migration artifact format.
pub const SCHEMA_VERSION: &str = "ma-v1.0";

// ---------------------------------------------------------------------------
// ArtifactVersion
// ---------------------------------------------------------------------------

/// Supported artifact schema versions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactVersion {
    /// Current schema version: ma-v1.0
    V1_0,
}

impl ArtifactVersion {
    /// The canonical string representation.
    pub fn label(&self) -> &'static str {
        match self {
            Self::V1_0 => "ma-v1.0",
        }
    }

    /// Parse from string.
    pub fn from_str_version(s: &str) -> Option<Self> {
        match s {
            "ma-v1.0" => Some(Self::V1_0),
            _ => None,
        }
    }

    /// All supported versions.
    pub fn all() -> &'static [ArtifactVersion] {
        &[Self::V1_0]
    }
}

// ---------------------------------------------------------------------------
// MigrationStep
// ---------------------------------------------------------------------------

/// A single step within a migration plan.
///
/// Each step captures the action to perform, the target resource, pre/post
/// state hashes for verification, a rollback action, and an estimated duration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationStep {
    /// The type of action (e.g. "schema_upgrade", "data_migration", "config_update").
    pub action_type: String,
    /// The resource being modified.
    pub target_resource: String,
    /// SHA-256 hash of the pre-migration state.
    pub pre_state_hash: String,
    /// SHA-256 hash of the expected post-migration state.
    pub post_state_hash: String,
    /// Description of the rollback action for this step.
    pub rollback_action: String,
    /// Estimated duration of this step in milliseconds.
    pub estimated_duration_ms: u64,
}

// ---------------------------------------------------------------------------
// RollbackReceipt
// ---------------------------------------------------------------------------

/// Receipt proving that a rollback path exists and has been validated.
///
/// # INV-MA-ROLLBACK-PRESENT
/// Every migration artifact must include a rollback receipt with non-empty fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RollbackReceipt {
    /// Reference to the original state snapshot.
    pub original_state_ref: String,
    /// SHA-256 hash of the rollback procedure.
    pub rollback_procedure_hash: String,
    /// Maximum time allowed for rollback in milliseconds.
    pub max_rollback_time_ms: u64,
    /// Identity of the signer who certified the rollback path.
    pub signer_identity: String,
    /// Signature over the rollback receipt fields.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// ConfidenceInterval
// ---------------------------------------------------------------------------

/// Confidence metrics for a migration plan.
///
/// # INV-MA-CONFIDENCE-CALIBRATED
/// The probability field must be in [0.0, 1.0].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    /// Overall success probability in [0.0, 1.0].
    pub probability: f64,
    /// Success rate from dry-run executions in [0.0, 1.0].
    pub dry_run_success_rate: f64,
    /// Similarity score to historically successful migrations in [0.0, 1.0].
    pub historical_similarity: f64,
    /// Fraction of preconditions verified in [0.0, 1.0].
    pub precondition_coverage: f64,
    /// Whether rollback was validated end-to-end.
    pub rollback_validation: bool,
}

// ---------------------------------------------------------------------------
// VerifierMetadata
// ---------------------------------------------------------------------------

/// Metadata for external verifiers to independently validate the migration.
///
/// # INV-MA-VERIFIER-COMPLETE
/// Must include at least one replay capsule ref and one expected state hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifierMetadata {
    /// References to replay capsules that can reproduce the migration.
    pub replay_capsule_refs: Vec<String>,
    /// Expected state hashes at each verification checkpoint.
    pub expected_state_hashes: BTreeMap<String, String>,
    /// JSON Schema URIs for assertion validation.
    pub assertion_schemas: Vec<String>,
    /// Descriptions of verification procedures.
    pub verification_procedures: Vec<String>,
}

// ---------------------------------------------------------------------------
// MigrationArtifact
// ---------------------------------------------------------------------------

/// The top-level migration singularity artifact.
///
/// This is the canonical, versioned output of a migration plan that bridges
/// the migration system (10.3) and the verifier economy (10.17).
///
/// # Invariants
///
/// - INV-MA-SIGNED: `signature` is non-empty.
/// - INV-MA-ROLLBACK-PRESENT: `rollback_receipt` is present.
/// - INV-MA-CONFIDENCE-CALIBRATED: `confidence_interval.probability` in [0.0, 1.0].
/// - INV-MA-VERSIONED: `schema_version` matches a supported version string.
/// - INV-MA-VERIFIER-COMPLETE: verifier metadata has >= 1 replay ref and >= 1 state hash.
/// - INV-MA-DETERMINISTIC: deterministic serialization via BTreeMap + sorted fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationArtifact {
    /// Schema version (e.g. "ma-v1.0").
    pub schema_version: String,
    /// Unique plan identifier.
    pub plan_id: String,
    /// Plan version number.
    pub plan_version: u64,
    /// Precondition assertions that must hold before migration.
    pub preconditions: Vec<String>,
    /// Ordered migration steps.
    pub steps: Vec<MigrationStep>,
    /// Rollback receipt proving rollback path is validated.
    pub rollback_receipt: RollbackReceipt,
    /// Confidence interval for the migration.
    pub confidence_interval: ConfidenceInterval,
    /// Verifier-friendly metadata for independent validation.
    pub verifier_metadata: VerifierMetadata,
    /// Cryptographic signature over the artifact.
    pub signature: String,
    /// Content hash for determinism verification.
    pub content_hash: String,
    /// Timestamp of artifact creation (RFC 3339).
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validation result for a migration artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validate a migration artifact against all invariants.
///
/// Returns a `ValidationResult` with details on any violations.
pub fn validate_artifact(artifact: &MigrationArtifact) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // INV-MA-SIGNED
    if artifact.signature.is_empty() {
        errors.push(format!(
            "{}: artifact signature is empty",
            error_codes::ERR_MA_SIGNATURE_INVALID
        ));
    }

    // INV-MA-ROLLBACK-PRESENT
    if artifact.rollback_receipt.original_state_ref.is_empty()
        || artifact.rollback_receipt.rollback_procedure_hash.is_empty()
        || artifact.rollback_receipt.signer_identity.is_empty()
        || artifact.rollback_receipt.signature.is_empty()
    {
        errors.push(format!(
            "{}: rollback receipt has empty required fields",
            error_codes::ERR_MA_MISSING_ROLLBACK
        ));
    }

    // INV-MA-CONFIDENCE-CALIBRATED
    let ci = &artifact.confidence_interval;
    if !(0.0..=1.0).contains(&ci.probability) {
        errors.push(format!(
            "{}: probability {} out of [0.0, 1.0]",
            error_codes::ERR_MA_CONFIDENCE_LOW,
            ci.probability
        ));
    }
    if !(0.0..=1.0).contains(&ci.dry_run_success_rate) {
        warnings.push(format!(
            "dry_run_success_rate {} out of [0.0, 1.0]",
            ci.dry_run_success_rate
        ));
    }
    if !(0.0..=1.0).contains(&ci.historical_similarity) {
        warnings.push(format!(
            "historical_similarity {} out of [0.0, 1.0]",
            ci.historical_similarity
        ));
    }
    if !(0.0..=1.0).contains(&ci.precondition_coverage) {
        warnings.push(format!(
            "precondition_coverage {} out of [0.0, 1.0]",
            ci.precondition_coverage
        ));
    }

    // INV-MA-VERSIONED
    if ArtifactVersion::from_str_version(&artifact.schema_version).is_none() {
        errors.push(format!(
            "{}: unsupported schema version '{}'",
            error_codes::ERR_MA_VERSION_UNSUPPORTED,
            artifact.schema_version
        ));
    }

    // INV-MA-VERIFIER-COMPLETE
    if artifact.verifier_metadata.replay_capsule_refs.is_empty() {
        errors.push(format!(
            "{}: verifier metadata has no replay capsule refs",
            error_codes::ERR_MA_INVALID_SCHEMA
        ));
    }
    if artifact.verifier_metadata.expected_state_hashes.is_empty() {
        errors.push(format!(
            "{}: verifier metadata has no expected state hashes",
            error_codes::ERR_MA_INVALID_SCHEMA
        ));
    }

    ValidationResult {
        valid: errors.is_empty(),
        errors,
        warnings,
    }
}

/// Compute the content hash for a migration artifact.
///
/// # INV-MA-DETERMINISTIC
/// Uses BTreeMap-based serialization for deterministic output.
pub fn compute_content_hash(artifact: &MigrationArtifact) -> String {
    let canonical = serde_json::json!({
        "schema_version": artifact.schema_version,
        "plan_id": artifact.plan_id,
        "plan_version": artifact.plan_version,
        "preconditions": artifact.preconditions,
        "steps": artifact.steps,
        "rollback_receipt": artifact.rollback_receipt,
        "confidence_interval": {
            "probability": artifact.confidence_interval.probability,
            "dry_run_success_rate": artifact.confidence_interval.dry_run_success_rate,
            "historical_similarity": artifact.confidence_interval.historical_similarity,
            "precondition_coverage": artifact.confidence_interval.precondition_coverage,
            "rollback_validation": artifact.confidence_interval.rollback_validation,
        },
        "verifier_metadata": artifact.verifier_metadata,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    hex::encode(Sha256::digest(
        [b"migration_artifact_hash_v1:" as &[u8], bytes.as_slice()].concat(),
    ))
}

// ---------------------------------------------------------------------------
// Reference artifact generator
// ---------------------------------------------------------------------------

/// Generate a reference migration artifact for testing and validation.
///
/// The reference artifact satisfies all invariants and can be used as a
/// golden vector for schema validation and verifier integration tests.
pub fn generate_reference_artifact() -> MigrationArtifact {
    let mut expected_state_hashes = BTreeMap::new();
    expected_state_hashes.insert(
        "checkpoint_0".to_string(),
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
    );
    expected_state_hashes.insert(
        "checkpoint_1".to_string(),
        "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3".to_string(),
    );

    let mut artifact = MigrationArtifact {
        schema_version: SCHEMA_VERSION.to_string(),
        plan_id: "plan-ref-001".to_string(),
        plan_version: 1,
        preconditions: vec![
            "database_schema_v2_exists".to_string(),
            "backup_snapshot_valid".to_string(),
            "no_active_transactions".to_string(),
        ],
        steps: vec![
            MigrationStep {
                action_type: "schema_upgrade".to_string(),
                target_resource: "trust_store.db".to_string(),
                pre_state_hash: "aaaa".repeat(16),
                post_state_hash: "bbbb".repeat(16),
                rollback_action: "restore_schema_v1".to_string(),
                estimated_duration_ms: 5000,
            },
            MigrationStep {
                action_type: "data_migration".to_string(),
                target_resource: "trust_cards_table".to_string(),
                pre_state_hash: "cccc".repeat(16),
                post_state_hash: "dddd".repeat(16),
                rollback_action: "restore_trust_cards_backup".to_string(),
                estimated_duration_ms: 30000,
            },
            MigrationStep {
                action_type: "config_update".to_string(),
                target_resource: "node_config.toml".to_string(),
                pre_state_hash: "eeee".repeat(16),
                post_state_hash: "ffff".repeat(16),
                rollback_action: "restore_config_backup".to_string(),
                estimated_duration_ms: 1000,
            },
        ],
        rollback_receipt: RollbackReceipt {
            original_state_ref: "snapshot://trust_store/2026-02-21T00:00:00Z".to_string(),
            rollback_procedure_hash: "1234abcd".repeat(8),
            max_rollback_time_ms: 60000,
            signer_identity: "operator://fleet-admin@example.com".to_string(),
            signature: "sig_rollback_".to_string() + &"ab".repeat(32),
        },
        confidence_interval: ConfidenceInterval {
            probability: 0.95,
            dry_run_success_rate: 0.98,
            historical_similarity: 0.90,
            precondition_coverage: 1.0,
            rollback_validation: true,
        },
        verifier_metadata: VerifierMetadata {
            replay_capsule_refs: vec![
                "capsule://migration/plan-ref-001/run-1".to_string(),
                "capsule://migration/plan-ref-001/run-2".to_string(),
            ],
            expected_state_hashes,
            assertion_schemas: vec!["schema://migration-artifact/ma-v1.0".to_string()],
            verification_procedures: vec![
                "Replay capsule run-1 and compare post-state hashes".to_string(),
                "Verify rollback receipt signature against operator key".to_string(),
            ],
        },
        signature: "sig_artifact_".to_string() + &"cd".repeat(32),
        content_hash: String::new(),
        created_at: "2026-02-21T00:00:00Z".to_string(),
    };

    artifact.content_hash = compute_content_hash(&artifact);
    artifact
}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// Structured audit event for migration artifact operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationArtifactEvent {
    pub event_code: String,
    pub plan_id: String,
    pub detail: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Reference artifact ────────────────────────────────────────────

    #[test]
    fn test_generate_reference_artifact() {
        let artifact = generate_reference_artifact();
        assert_eq!(artifact.schema_version, SCHEMA_VERSION);
        assert_eq!(artifact.plan_id, "plan-ref-001");
        assert_eq!(artifact.plan_version, 1);
    }

    #[test]
    fn test_reference_artifact_has_steps() {
        let artifact = generate_reference_artifact();
        assert_eq!(artifact.steps.len(), 3);
    }

    #[test]
    fn test_reference_artifact_has_preconditions() {
        let artifact = generate_reference_artifact();
        assert_eq!(artifact.preconditions.len(), 3);
    }

    #[test]
    fn test_reference_artifact_has_signature() {
        let artifact = generate_reference_artifact();
        assert!(!artifact.signature.is_empty());
    }

    #[test]
    fn test_reference_artifact_has_content_hash() {
        let artifact = generate_reference_artifact();
        assert_eq!(artifact.content_hash.len(), 64);
    }

    #[test]
    fn test_reference_artifact_has_rollback_receipt() {
        let artifact = generate_reference_artifact();
        assert!(!artifact.rollback_receipt.original_state_ref.is_empty());
        assert!(!artifact.rollback_receipt.rollback_procedure_hash.is_empty());
        assert!(!artifact.rollback_receipt.signer_identity.is_empty());
        assert!(!artifact.rollback_receipt.signature.is_empty());
    }

    #[test]
    fn test_reference_artifact_has_verifier_metadata() {
        let artifact = generate_reference_artifact();
        assert!(!artifact.verifier_metadata.replay_capsule_refs.is_empty());
        assert!(!artifact.verifier_metadata.expected_state_hashes.is_empty());
    }

    #[test]
    fn test_reference_artifact_confidence_calibrated() {
        let artifact = generate_reference_artifact();
        let ci = &artifact.confidence_interval;
        assert!((0.0..=1.0).contains(&ci.probability));
        assert!((0.0..=1.0).contains(&ci.dry_run_success_rate));
        assert!((0.0..=1.0).contains(&ci.historical_similarity));
        assert!((0.0..=1.0).contains(&ci.precondition_coverage));
    }

    // ── Validation ────────────────────────────────────────────────────

    #[test]
    fn test_validate_reference_artifact_passes() {
        let artifact = generate_reference_artifact();
        let result = validate_artifact(&artifact);
        assert!(result.valid, "errors: {:?}", result.errors);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_empty_signature_fails() {
        let mut artifact = generate_reference_artifact();
        artifact.signature = String::new();
        let result = validate_artifact(&artifact);
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("ERR_MA_SIGNATURE_INVALID"))
        );
    }

    #[test]
    fn test_validate_missing_rollback_fields_fails() {
        let mut artifact = generate_reference_artifact();
        artifact.rollback_receipt.original_state_ref = String::new();
        let result = validate_artifact(&artifact);
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("ERR_MA_MISSING_ROLLBACK"))
        );
    }

    #[test]
    fn test_validate_confidence_out_of_range_fails() {
        let mut artifact = generate_reference_artifact();
        artifact.confidence_interval.probability = 1.5;
        let result = validate_artifact(&artifact);
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("ERR_MA_CONFIDENCE_LOW"))
        );
    }

    #[test]
    fn test_validate_unsupported_version_fails() {
        let mut artifact = generate_reference_artifact();
        artifact.schema_version = "ma-v99.0".to_string();
        let result = validate_artifact(&artifact);
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("ERR_MA_VERSION_UNSUPPORTED"))
        );
    }

    #[test]
    fn test_validate_no_replay_refs_fails() {
        let mut artifact = generate_reference_artifact();
        artifact.verifier_metadata.replay_capsule_refs.clear();
        let result = validate_artifact(&artifact);
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("ERR_MA_INVALID_SCHEMA"))
        );
    }

    #[test]
    fn test_validate_no_expected_hashes_fails() {
        let mut artifact = generate_reference_artifact();
        artifact.verifier_metadata.expected_state_hashes.clear();
        let result = validate_artifact(&artifact);
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("ERR_MA_INVALID_SCHEMA"))
        );
    }

    // ── Determinism ───────────────────────────────────────────────────

    #[test]
    fn test_content_hash_deterministic() {
        let a1 = generate_reference_artifact();
        let a2 = generate_reference_artifact();
        assert_eq!(a1.content_hash, a2.content_hash);
    }

    #[test]
    fn test_content_hash_changes_with_plan_id() {
        let a1 = generate_reference_artifact();
        let mut a2 = generate_reference_artifact();
        a2.plan_id = "plan-ref-002".to_string();
        a2.content_hash = compute_content_hash(&a2);
        assert_ne!(a1.content_hash, a2.content_hash);
    }

    #[test]
    fn test_content_hash_length() {
        let artifact = generate_reference_artifact();
        assert_eq!(artifact.content_hash.len(), 64);
    }

    // ── ArtifactVersion ───────────────────────────────────────────────

    #[test]
    fn test_artifact_version_label() {
        assert_eq!(ArtifactVersion::V1_0.label(), "ma-v1.0");
    }

    #[test]
    fn test_artifact_version_parse() {
        assert_eq!(
            ArtifactVersion::from_str_version("ma-v1.0"),
            Some(ArtifactVersion::V1_0)
        );
    }

    #[test]
    fn test_artifact_version_parse_invalid() {
        assert_eq!(ArtifactVersion::from_str_version("bogus"), None);
    }

    #[test]
    fn test_artifact_version_all() {
        assert_eq!(ArtifactVersion::all().len(), 1);
    }

    // ── MigrationStep ─────────────────────────────────────────────────

    #[test]
    fn test_migration_step_fields() {
        let step = MigrationStep {
            action_type: "schema_upgrade".to_string(),
            target_resource: "db".to_string(),
            pre_state_hash: "aa".repeat(32),
            post_state_hash: "bb".repeat(32),
            rollback_action: "rollback".to_string(),
            estimated_duration_ms: 1000,
        };
        assert_eq!(step.action_type, "schema_upgrade");
        assert_eq!(step.estimated_duration_ms, 1000);
    }

    // ── RollbackReceipt ───────────────────────────────────────────────

    #[test]
    fn test_rollback_receipt_fields() {
        let receipt = RollbackReceipt {
            original_state_ref: "ref".to_string(),
            rollback_procedure_hash: "hash".to_string(),
            max_rollback_time_ms: 5000,
            signer_identity: "signer".to_string(),
            signature: "sig".to_string(),
        };
        assert_eq!(receipt.max_rollback_time_ms, 5000);
    }

    // ── ConfidenceInterval ────────────────────────────────────────────

    #[test]
    fn test_confidence_interval_range() {
        let ci = ConfidenceInterval {
            probability: 0.5,
            dry_run_success_rate: 0.7,
            historical_similarity: 0.8,
            precondition_coverage: 0.9,
            rollback_validation: true,
        };
        assert!((0.0..=1.0).contains(&ci.probability));
    }

    #[test]
    fn test_confidence_interval_boundary_zero() {
        let ci = ConfidenceInterval {
            probability: 0.0,
            dry_run_success_rate: 0.0,
            historical_similarity: 0.0,
            precondition_coverage: 0.0,
            rollback_validation: false,
        };
        assert!((0.0..=1.0).contains(&ci.probability));
    }

    #[test]
    fn test_confidence_interval_boundary_one() {
        let ci = ConfidenceInterval {
            probability: 1.0,
            dry_run_success_rate: 1.0,
            historical_similarity: 1.0,
            precondition_coverage: 1.0,
            rollback_validation: true,
        };
        assert!((0.0..=1.0).contains(&ci.probability));
    }

    // ── VerifierMetadata ──────────────────────────────────────────────

    #[test]
    fn test_verifier_metadata_btreemap() {
        let mut hashes = BTreeMap::new();
        hashes.insert("ck_0".to_string(), "hash_0".to_string());
        hashes.insert("ck_1".to_string(), "hash_1".to_string());
        let vm = VerifierMetadata {
            replay_capsule_refs: vec!["ref_1".to_string()],
            expected_state_hashes: hashes,
            assertion_schemas: vec![],
            verification_procedures: vec![],
        };
        assert_eq!(vm.expected_state_hashes.len(), 2);
        // BTreeMap iterates in sorted order
        let keys: Vec<_> = vm.expected_state_hashes.keys().collect();
        assert_eq!(keys, vec!["ck_0", "ck_1"]);
    }

    // ── Serde round-trip ──────────────────────────────────────────────

    #[test]
    fn test_migration_artifact_serde_roundtrip() {
        let artifact = generate_reference_artifact();
        let json = serde_json::to_string(&artifact).unwrap();
        let parsed: MigrationArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, parsed);
    }

    #[test]
    fn test_migration_step_serde_roundtrip() {
        let step = MigrationStep {
            action_type: "test".to_string(),
            target_resource: "res".to_string(),
            pre_state_hash: "aa".repeat(32),
            post_state_hash: "bb".repeat(32),
            rollback_action: "rb".to_string(),
            estimated_duration_ms: 100,
        };
        let json = serde_json::to_string(&step).unwrap();
        let parsed: MigrationStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, parsed);
    }

    #[test]
    fn test_rollback_receipt_serde_roundtrip() {
        let receipt = RollbackReceipt {
            original_state_ref: "ref".to_string(),
            rollback_procedure_hash: "hash".to_string(),
            max_rollback_time_ms: 1000,
            signer_identity: "id".to_string(),
            signature: "sig".to_string(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: RollbackReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn test_confidence_interval_serde_roundtrip() {
        let ci = ConfidenceInterval {
            probability: 0.95,
            dry_run_success_rate: 0.99,
            historical_similarity: 0.85,
            precondition_coverage: 1.0,
            rollback_validation: true,
        };
        let json = serde_json::to_string(&ci).unwrap();
        let parsed: ConfidenceInterval = serde_json::from_str(&json).unwrap();
        assert_eq!(ci, parsed);
    }

    #[test]
    fn test_verifier_metadata_serde_roundtrip() {
        let mut hashes = BTreeMap::new();
        hashes.insert("ck".to_string(), "h".to_string());
        let vm = VerifierMetadata {
            replay_capsule_refs: vec!["ref".to_string()],
            expected_state_hashes: hashes,
            assertion_schemas: vec!["schema".to_string()],
            verification_procedures: vec!["proc".to_string()],
        };
        let json = serde_json::to_string(&vm).unwrap();
        let parsed: VerifierMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(vm, parsed);
    }

    #[test]
    fn test_artifact_version_serde_roundtrip() {
        let v = ArtifactVersion::V1_0;
        let json = serde_json::to_string(&v).unwrap();
        let parsed: ArtifactVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn test_artifact_event_serde_roundtrip() {
        let evt = MigrationArtifactEvent {
            event_code: event_codes::MA_GENERATED.to_string(),
            plan_id: "plan-1".to_string(),
            detail: "generated".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let parsed: MigrationArtifactEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "MA-001");
    }

    // ── Event codes ───────────────────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::MA_GENERATED, "MA-001");
        assert_eq!(event_codes::MA_SIGNED, "MA-002");
        assert_eq!(event_codes::MA_VALIDATED, "MA-003");
        assert_eq!(event_codes::MA_SCHEMA_VIOLATION, "MA-004");
        assert_eq!(event_codes::MA_SIGNATURE_INVALID, "MA-005");
        assert_eq!(event_codes::MA_ROLLBACK_VERIFIED, "MA-006");
        assert_eq!(event_codes::MA_CONFIDENCE_CHECK, "MA-007");
        assert_eq!(event_codes::MA_VERSION_NEGOTIATED, "MA-008");
    }

    // ── Error codes ───────────────────────────────────────────────────

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(error_codes::ERR_MA_INVALID_SCHEMA, "ERR_MA_INVALID_SCHEMA");
        assert_eq!(
            error_codes::ERR_MA_SIGNATURE_INVALID,
            "ERR_MA_SIGNATURE_INVALID"
        );
        assert_eq!(
            error_codes::ERR_MA_MISSING_ROLLBACK,
            "ERR_MA_MISSING_ROLLBACK"
        );
        assert_eq!(error_codes::ERR_MA_CONFIDENCE_LOW, "ERR_MA_CONFIDENCE_LOW");
        assert_eq!(
            error_codes::ERR_MA_VERSION_UNSUPPORTED,
            "ERR_MA_VERSION_UNSUPPORTED"
        );
    }

    // ── Invariants ────────────────────────────────────────────────────

    #[test]
    fn test_invariants_defined() {
        assert_eq!(invariants::INV_MA_SIGNED, "INV-MA-SIGNED");
        assert_eq!(
            invariants::INV_MA_ROLLBACK_PRESENT,
            "INV-MA-ROLLBACK-PRESENT"
        );
        assert_eq!(
            invariants::INV_MA_CONFIDENCE_CALIBRATED,
            "INV-MA-CONFIDENCE-CALIBRATED"
        );
        assert_eq!(invariants::INV_MA_VERSIONED, "INV-MA-VERSIONED");
        assert_eq!(
            invariants::INV_MA_VERIFIER_COMPLETE,
            "INV-MA-VERIFIER-COMPLETE"
        );
        assert_eq!(invariants::INV_MA_DETERMINISTIC, "INV-MA-DETERMINISTIC");
    }

    // ── Schema version ────────────────────────────────────────────────

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "ma-v1.0");
    }

    // ── Send + Sync ───────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<MigrationArtifact>();
        assert_sync::<MigrationArtifact>();
        assert_send::<MigrationStep>();
        assert_sync::<MigrationStep>();
        assert_send::<RollbackReceipt>();
        assert_sync::<RollbackReceipt>();
        assert_send::<ConfidenceInterval>();
        assert_sync::<ConfidenceInterval>();
        assert_send::<VerifierMetadata>();
        assert_sync::<VerifierMetadata>();
        assert_send::<ArtifactVersion>();
        assert_sync::<ArtifactVersion>();
        assert_send::<ValidationResult>();
        assert_sync::<ValidationResult>();
        assert_send::<MigrationArtifactEvent>();
        assert_sync::<MigrationArtifactEvent>();
    }

    // ── ValidationResult ──────────────────────────────────────────────

    #[test]
    fn test_validation_result_serde() {
        let vr = ValidationResult {
            valid: true,
            errors: vec![],
            warnings: vec!["warn".to_string()],
        };
        let json = serde_json::to_string(&vr).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(vr, parsed);
    }

    // ── Multiple validation errors ────────────────────────────────────

    #[test]
    fn test_multiple_validation_errors() {
        let mut artifact = generate_reference_artifact();
        artifact.signature = String::new();
        artifact.rollback_receipt.original_state_ref = String::new();
        artifact.confidence_interval.probability = 2.0;
        artifact.schema_version = "bogus".to_string();
        artifact.verifier_metadata.replay_capsule_refs.clear();
        artifact.verifier_metadata.expected_state_hashes.clear();
        let result = validate_artifact(&artifact);
        assert!(!result.valid);
        // Should have multiple errors
        assert_eq!(result.errors.len(), 6);
    }
}
