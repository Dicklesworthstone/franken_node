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
//! - Behavioral conformance certificates with machine-readable bounded coverage
//! - Ledger-chain bindings for certificate audit continuity
//! - Differential witnesses binding fixture, proptest, and effect-receipt equivalence evidence
//! - Deterministic serialization via BTreeMap
//! - Reference artifact generator for testing and validation
//!
//! # Invariants
//!
//! - **INV-MA-SIGNED**: Every artifact carries a non-empty signature field.
//! - **INV-MA-ROLLBACK-PRESENT**: Every artifact includes a rollback receipt.
//! - **INV-MA-CONFIDENCE-CALIBRATED**: All confidence interval metrics are finite
//!   and remain in [0.0, 1.0].
//! - **INV-MA-VERSIONED**: Every artifact carries a schema version string.
//! - **INV-MA-VERIFIER-COMPLETE**: Verifier metadata includes at least one replay
//!   capsule ref and one expected state hash.
//! - **INV-MA-DETERMINISTIC**: Same inputs produce byte-identical serialized output.
//! - **INV-MA-BOUND-FIRST-CLASS**: Behavioral certificates expose their bounded
//!   input, property, and coverage scope as structured fields.
//! - **INV-MA-LEDGER-CHAINED**: Behavioral certificates bind to evidence ledger
//!   entry hashes and prior certificate hashes.
//! - **INV-MA-DIFFERENTIAL-WITNESS-BOUND**: Behavioral certificates bind their
//!   lockstep verdict hash to a structured zero-divergence differential witness.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const ROLLBACK_RECEIPT_SIGNING_KEY: &[u8] =
    b"franken_node.connector.migration_artifact.rollback_receipt_sign_v1";
const MIGRATION_ARTIFACT_SIGNING_KEY: &[u8] = b"franken_node.connector.migration_artifact.sign_v1";
const BEHAVIORAL_CONFORMANCE_CERTIFICATE_SIGNING_KEY: &[u8] =
    b"franken_node.connector.migration_artifact.behavioral_conformance_certificate.sign_v1";

type HmacSha256 = Hmac<Sha256>;

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
    /// Bounded migration certificate emitted with first-class scope metadata.
    pub const FN_MIGCERT_GENERATED: &str = "FN-MIGCERT-001";
    /// Certificate bound, coverage, and ledger-chain invariants verified.
    pub const FN_MIGCERT_BOUND_VERIFIED: &str = "FN-MIGCERT-002";
    /// Differential witness bound to the migration certificate verified.
    pub const FN_MIGCERT_DIFFERENTIAL_WITNESS_VERIFIED: &str = "FN-MIGCERT-003";
    /// Offline verifier SDK migration-equivalence certification completed.
    pub const FN_MIGCERT_SDK_CERTIFIED: &str = "FN-MIGCERT-004";
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
    pub const ERR_MA_BOUND_INVALID: &str = "ERR_MA_BOUND_INVALID";
    pub const ERR_MA_LEDGER_CHAIN_INVALID: &str = "ERR_MA_LEDGER_CHAIN_INVALID";
    pub const ERR_MA_DIFFERENTIAL_WITNESS_INVALID: &str = "ERR_MA_DIFFERENTIAL_WITNESS_INVALID";
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
    pub const INV_MA_BOUND_FIRST_CLASS: &str = "INV-MA-BOUND-FIRST-CLASS";
    pub const INV_MA_LEDGER_CHAINED: &str = "INV-MA-LEDGER-CHAINED";
    pub const INV_MA_DIFFERENTIAL_WITNESS_BOUND: &str = "INV-MA-DIFFERENTIAL-WITNESS-BOUND";
}

/// Schema version for the current migration artifact format.
pub const SCHEMA_VERSION: &str = "ma-v1.0";

/// Schema version for bounded behavioral conformance certificates.
pub const BEHAVIORAL_CONFORMANCE_CERTIFICATE_SCHEMA_VERSION: &str = "bcc-v1.0";

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

#[derive(Debug, Serialize)]
struct UnsignedRollbackReceipt<'a> {
    original_state_ref: &'a str,
    rollback_procedure_hash: &'a str,
    max_rollback_time_ms: u64,
    signer_identity: &'a str,
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
// BehavioralConformanceCertificate
// ---------------------------------------------------------------------------

/// The concrete input slice covered by a behavioral conformance certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundedInputScope {
    /// Human-stable input class name, such as "commonjs-module".
    pub input_class: String,
    /// Deterministic selector for the covered corpus slice.
    pub selector: String,
    /// Number of concrete inputs covered by this scope.
    pub count: u64,
    /// SHA-256 digest over the ordered covered input identifiers.
    pub digest: String,
}

/// Property classes that a behavioral conformance certificate can bind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformancePropertyClass {
    SyntaxEquivalence,
    ObservableOutput,
    ErrorBehavior,
    SideEffectBoundary,
    TemporalBehavior,
    ResourceUse,
    Custom(String),
}

/// Coverage statement for the certificate's bounded behavioral claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundCoverage {
    /// Number of covered lockstep cases.
    pub covered_cases: u64,
    /// Total cases in the declared bounded scope.
    pub total_cases: u64,
    /// Covered fraction in [0.0, 1.0].
    pub coverage_ratio: f64,
    /// Deterministic method used to derive the coverage statement.
    pub measurement_method: String,
}

/// First-class machine-readable BOUND for a behavioral conformance certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralConformanceBound {
    /// Which inputs are in scope.
    pub input_scope: Vec<BoundedInputScope>,
    /// Which behavioral property classes are in scope.
    pub property_classes: Vec<ConformancePropertyClass>,
    /// Coverage over the declared scope.
    pub coverage: BoundCoverage,
}

/// Result of the differential witness run bound into a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialWitnessVerdict {
    Pass,
    Fail,
}

/// Structured differential witness behind a bounded lockstep verdict.
///
/// This is intentionally a summary witness, not an unbounded equivalence claim:
/// it names the lockstep oracle, binds the fixture/proptest/effect-receipt
/// case counts, and records zero divergences for the covered input scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialWitness {
    /// Stable lockstep oracle implementation identifier.
    pub lockstep_oracle_id: String,
    /// SHA-256 digest over the ordered fixture corpus case identifiers.
    pub fixture_corpus_digest: String,
    /// Deterministic seed material for proptest-generated inputs.
    pub proptest_seed: String,
    /// Number of fixture-corpus cases exercised by the oracle.
    pub fixture_cases: u64,
    /// Number of proptest-generated cases exercised by the oracle.
    pub proptest_cases: u64,
    /// Number of effect-receipt equivalence cases exercised.
    pub effect_receipt_equivalence_cases: u64,
    /// Number of observed behavioral divergences.
    pub divergence_count: u64,
    /// Pass/fail verdict over the bounded differential run.
    pub verdict: DifferentialWitnessVerdict,
    /// SHA-256 digest over the structured witness fields above.
    pub witness_hash: String,
}

impl DifferentialWitness {
    pub fn total_cases(&self) -> u64 {
        self.fixture_cases
            .saturating_add(self.proptest_cases)
            .saturating_add(self.effect_receipt_equivalence_cases)
    }
}

/// Evidence-ledger chain binding for a behavioral conformance certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateLedgerChain {
    /// Prior certificate content hash, or None for the genesis certificate.
    pub previous_certificate_hash: Option<String>,
    /// Evidence ledger entry hash that records this certificate.
    pub evidence_ledger_entry_hash: String,
    /// Monotonic sequence within the certificate ledger domain.
    pub certificate_sequence: u64,
    /// Stable ledger domain identifier, e.g. "observability:evidence-ledger-v2".
    pub ledger_domain: String,
}

/// Bounded certificate for verifier-certified behavioral migration claims.
///
/// The certificate intentionally avoids claiming global equivalence. Its
/// `bound` field names the concrete inputs, property classes, and coverage
/// for which `lockstep_verdict_hash` applies, while `differential_witness`
/// explains the zero-divergence oracle run behind that hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralConformanceCertificate {
    /// Schema version (e.g. "bcc-v1.0").
    pub schema_version: String,
    /// SHA-256 hash of the pre-migration source.
    pub source_hash: String,
    /// SHA-256 hash of the post-migration target.
    pub target_hash: String,
    /// Stable migration rule identifier.
    pub rule_id: String,
    /// Version of the migration rule.
    pub rule_version: String,
    /// Structured proof that the rule preconditions held.
    pub precondition_proof: BTreeMap<String, serde_json::Value>,
    /// SHA-256 hash of the bounded lockstep verdict.
    pub lockstep_verdict_hash: String,
    /// Structured zero-divergence differential witness bound to the verdict hash.
    pub differential_witness: DifferentialWitness,
    /// First-class bounded claim metadata.
    pub bound: BehavioralConformanceBound,
    /// Evidence-ledger chain binding.
    pub ledger_chain: CertificateLedgerChain,
    /// Deterministic content hash over unsigned certificate fields.
    pub content_hash: String,
    /// Timestamp of certificate creation (RFC 3339).
    pub created_at: String,
    /// Signature over the canonical certificate payload.
    pub signature: String,
}

#[derive(Debug, Serialize)]
struct UnsignedBehavioralConformanceCertificate<'a> {
    schema_version: &'a str,
    source_hash: &'a str,
    target_hash: &'a str,
    rule_id: &'a str,
    rule_version: &'a str,
    precondition_proof: &'a BTreeMap<String, serde_json::Value>,
    lockstep_verdict_hash: &'a str,
    differential_witness: &'a DifferentialWitness,
    bound: &'a BehavioralConformanceBound,
    ledger_chain: &'a CertificateLedgerChain,
    content_hash: &'a str,
    created_at: &'a str,
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
/// - INV-MA-CONFIDENCE-CALIBRATED: all `confidence_interval` metrics are finite
///   and remain in [0.0, 1.0].
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

#[derive(Debug, Serialize)]
struct UnsignedMigrationArtifact<'a> {
    schema_version: &'a str,
    plan_id: &'a str,
    plan_version: u64,
    preconditions: &'a [String],
    steps: &'a [MigrationStep],
    rollback_receipt: &'a RollbackReceipt,
    confidence_interval: &'a ConfidenceInterval,
    verifier_metadata: &'a VerifierMetadata,
    content_hash: &'a str,
    created_at: &'a str,
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
    let warnings = Vec::new();

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
    for (field, value) in [
        ("probability", ci.probability),
        ("dry_run_success_rate", ci.dry_run_success_rate),
        ("historical_similarity", ci.historical_similarity),
        ("precondition_coverage", ci.precondition_coverage),
    ] {
        if !(0.0..=1.0).contains(&value) {
            errors.push(format!(
                "{}: {field} {value} out of [0.0, 1.0]",
                error_codes::ERR_MA_CONFIDENCE_LOW
            ));
        }
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

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn push_hash_error(errors: &mut Vec<String>, field: &str, value: &str) {
    errors.push(format!(
        "{}: {field} must be a 64-character SHA-256 hex digest, got '{value}'",
        error_codes::ERR_MA_INVALID_SCHEMA
    ));
}

/// Validate a bounded behavioral conformance certificate against its schema.
pub fn validate_behavioral_conformance_certificate(
    certificate: &BehavioralConformanceCertificate,
) -> ValidationResult {
    let mut errors = Vec::new();
    let warnings = Vec::new();

    if certificate.signature.is_empty() {
        errors.push(format!(
            "{}: certificate signature is empty",
            error_codes::ERR_MA_SIGNATURE_INVALID
        ));
    }

    if certificate.schema_version != BEHAVIORAL_CONFORMANCE_CERTIFICATE_SCHEMA_VERSION {
        errors.push(format!(
            "{}: unsupported certificate schema version '{}'",
            error_codes::ERR_MA_VERSION_UNSUPPORTED,
            certificate.schema_version
        ));
    }

    for (field, value) in [
        ("source_hash", certificate.source_hash.as_str()),
        ("target_hash", certificate.target_hash.as_str()),
        (
            "lockstep_verdict_hash",
            certificate.lockstep_verdict_hash.as_str(),
        ),
        ("content_hash", certificate.content_hash.as_str()),
        (
            "ledger_chain.evidence_ledger_entry_hash",
            certificate.ledger_chain.evidence_ledger_entry_hash.as_str(),
        ),
        (
            "differential_witness.fixture_corpus_digest",
            certificate
                .differential_witness
                .fixture_corpus_digest
                .as_str(),
        ),
        (
            "differential_witness.witness_hash",
            certificate.differential_witness.witness_hash.as_str(),
        ),
    ] {
        if !is_sha256_hex(value) {
            push_hash_error(&mut errors, field, value);
        }
    }

    if let Some(previous_hash) = &certificate.ledger_chain.previous_certificate_hash
        && !is_sha256_hex(previous_hash)
    {
        push_hash_error(
            &mut errors,
            "ledger_chain.previous_certificate_hash",
            previous_hash,
        );
    }

    if certificate.rule_id.trim().is_empty() {
        errors.push(format!(
            "{}: rule_id is required",
            error_codes::ERR_MA_INVALID_SCHEMA
        ));
    }
    if certificate.rule_version.trim().is_empty() {
        errors.push(format!(
            "{}: rule_version is required",
            error_codes::ERR_MA_INVALID_SCHEMA
        ));
    }
    if certificate.precondition_proof.is_empty() {
        errors.push(format!(
            "{}: precondition_proof is required",
            error_codes::ERR_MA_INVALID_SCHEMA
        ));
    }

    if certificate.bound.input_scope.is_empty() {
        errors.push(format!(
            "{}: bound.input_scope must name at least one input scope",
            error_codes::ERR_MA_BOUND_INVALID
        ));
    }
    for (index, scope) in certificate.bound.input_scope.iter().enumerate() {
        if scope.input_class.trim().is_empty()
            || scope.selector.trim().is_empty()
            || scope.count == 0
            || !is_sha256_hex(&scope.digest)
        {
            errors.push(format!(
                "{}: bound.input_scope[{index}] has invalid class, selector, count, or digest",
                error_codes::ERR_MA_BOUND_INVALID
            ));
        }
    }

    if certificate.bound.property_classes.is_empty() {
        errors.push(format!(
            "{}: bound.property_classes must name at least one property class",
            error_codes::ERR_MA_BOUND_INVALID
        ));
    }

    let coverage = &certificate.bound.coverage;
    if coverage.total_cases == 0
        || coverage.covered_cases > coverage.total_cases
        || !(0.0..=1.0).contains(&coverage.coverage_ratio)
        || coverage.measurement_method.trim().is_empty()
    {
        errors.push(format!(
            "{}: bound.coverage must have nonzero total cases, covered<=total, ratio in [0.0, 1.0], and a measurement method",
            error_codes::ERR_MA_BOUND_INVALID
        ));
    }

    let differential_witness = &certificate.differential_witness;
    if differential_witness.lockstep_oracle_id.trim().is_empty()
        || differential_witness.proptest_seed.trim().is_empty()
        || differential_witness.fixture_cases == 0
        || differential_witness.proptest_cases == 0
        || differential_witness.effect_receipt_equivalence_cases == 0
    {
        errors.push(format!(
            "{}: differential_witness must name an oracle and include fixture, proptest, and effect-receipt cases",
            error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID
        ));
    }
    if !matches!(
        differential_witness.verdict,
        DifferentialWitnessVerdict::Pass
    ) || differential_witness.divergence_count != 0
    {
        errors.push(format!(
            "{}: differential_witness must be a zero-divergence pass verdict",
            error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID
        ));
    }
    let witness_total_cases = differential_witness.total_cases();
    if witness_total_cases != coverage.covered_cases || witness_total_cases != coverage.total_cases
    {
        errors.push(format!(
            "{}: differential_witness case total must equal bound.coverage covered and total cases",
            error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID
        ));
    }
    let expected_witness_hash = compute_differential_witness_hash(differential_witness);
    if !crate::security::constant_time::ct_eq(
        &differential_witness.witness_hash,
        &expected_witness_hash,
    ) {
        errors.push(format!(
            "{}: differential_witness.witness_hash does not match witness payload",
            error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID
        ));
    }
    if !crate::security::constant_time::ct_eq(
        &certificate.lockstep_verdict_hash,
        &differential_witness.witness_hash,
    ) {
        errors.push(format!(
            "{}: lockstep_verdict_hash must equal differential_witness.witness_hash",
            error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID
        ));
    }

    if certificate.ledger_chain.ledger_domain.trim().is_empty() {
        errors.push(format!(
            "{}: ledger_chain.ledger_domain is required",
            error_codes::ERR_MA_LEDGER_CHAIN_INVALID
        ));
    }

    let expected_content_hash = compute_behavioral_conformance_certificate_hash(certificate);
    if !crate::security::constant_time::ct_eq(&certificate.content_hash, &expected_content_hash) {
        errors.push(format!(
            "{}: content_hash does not match certificate payload",
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
///
/// # Panics
/// None — non-finite f64 values produce a sentinel error hash rather than
/// silently collapsing to `null` in JSON (which causes hash collisions).
pub fn compute_content_hash(artifact: &MigrationArtifact) -> String {
    // Guard: reject NaN/Inf in confidence_interval f64 fields.
    // JSON serializes non-finite f64 as null, causing materially different
    // artifacts to alias to the same content_hash.
    let ci = &artifact.confidence_interval;
    if !ci.probability.is_finite()
        || !ci.dry_run_success_rate.is_finite()
        || !ci.historical_similarity.is_finite()
        || !ci.precondition_coverage.is_finite()
    {
        return hex::encode(Sha256::digest(
            b"migration_artifact_hash_v1:__non_finite_confidence_interval__",
        ));
    }

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
    let bytes =
        serde_json::to_vec(&canonical).unwrap_or_else(|e| format!("__serde_err:{e}").into_bytes());
    hex::encode(Sha256::digest(
        [b"migration_artifact_hash_v1:" as &[u8], bytes.as_slice()].concat(),
    ))
}

/// Compute the digest for a differential witness, excluding its self-hash field.
pub fn compute_differential_witness_hash(witness: &DifferentialWitness) -> String {
    let canonical = serde_json::json!({
        "lockstep_oracle_id": witness.lockstep_oracle_id,
        "fixture_corpus_digest": witness.fixture_corpus_digest,
        "proptest_seed": witness.proptest_seed,
        "fixture_cases": witness.fixture_cases,
        "proptest_cases": witness.proptest_cases,
        "effect_receipt_equivalence_cases": witness.effect_receipt_equivalence_cases,
        "divergence_count": witness.divergence_count,
        "verdict": witness.verdict,
    });
    let bytes =
        serde_json::to_vec(&canonical).unwrap_or_else(|e| format!("__serde_err:{e}").into_bytes());
    hex::encode(Sha256::digest(
        [
            b"migration_differential_witness_hash_v1:" as &[u8],
            bytes.as_slice(),
        ]
        .concat(),
    ))
}

/// Compute the content hash for a behavioral conformance certificate.
pub fn compute_behavioral_conformance_certificate_hash(
    certificate: &BehavioralConformanceCertificate,
) -> String {
    if !certificate.bound.coverage.coverage_ratio.is_finite() {
        return hex::encode(Sha256::digest(
            b"behavioral_conformance_certificate_hash_v1:__non_finite_coverage_ratio__",
        ));
    }

    let canonical = serde_json::json!({
        "schema_version": certificate.schema_version,
        "source_hash": certificate.source_hash,
        "target_hash": certificate.target_hash,
        "rule_id": certificate.rule_id,
        "rule_version": certificate.rule_version,
        "precondition_proof": certificate.precondition_proof,
        "lockstep_verdict_hash": certificate.lockstep_verdict_hash,
        "differential_witness": certificate.differential_witness,
        "bound": certificate.bound,
        "ledger_chain": certificate.ledger_chain,
    });
    let bytes =
        serde_json::to_vec(&canonical).unwrap_or_else(|e| format!("__serde_err:{e}").into_bytes());
    hex::encode(Sha256::digest(
        [
            b"behavioral_conformance_certificate_hash_v1:" as &[u8],
            bytes.as_slice(),
        ]
        .concat(),
    ))
}

fn canonical_rollback_receipt_payload(receipt: &RollbackReceipt) -> Vec<u8> {
    serde_json::to_vec(&UnsignedRollbackReceipt {
        original_state_ref: &receipt.original_state_ref,
        rollback_procedure_hash: &receipt.rollback_procedure_hash,
        max_rollback_time_ms: receipt.max_rollback_time_ms,
        signer_identity: &receipt.signer_identity,
    })
    .unwrap_or_else(|error| format!("__rollback_receipt_serde_error:{error}").into_bytes())
}

fn sign_rollback_receipt(receipt: &RollbackReceipt) -> String {
    let mut mac = HmacSha256::new_from_slice(ROLLBACK_RECEIPT_SIGNING_KEY)
        .expect("rollback receipt signing key is valid");
    mac.update(b"migration_artifact_rollback_receipt_sign_v1:");
    mac.update(&canonical_rollback_receipt_payload(receipt));
    hex::encode(mac.finalize().into_bytes())
}

fn canonical_artifact_payload(artifact: &MigrationArtifact) -> Vec<u8> {
    serde_json::to_vec(&UnsignedMigrationArtifact {
        schema_version: &artifact.schema_version,
        plan_id: &artifact.plan_id,
        plan_version: artifact.plan_version,
        preconditions: &artifact.preconditions,
        steps: &artifact.steps,
        rollback_receipt: &artifact.rollback_receipt,
        confidence_interval: &artifact.confidence_interval,
        verifier_metadata: &artifact.verifier_metadata,
        content_hash: &artifact.content_hash,
        created_at: &artifact.created_at,
    })
    .unwrap_or_else(|error| format!("__migration_artifact_serde_error:{error}").into_bytes())
}

fn sign_artifact(artifact: &MigrationArtifact) -> String {
    let mut mac = HmacSha256::new_from_slice(MIGRATION_ARTIFACT_SIGNING_KEY)
        .expect("migration artifact signing key is valid");
    mac.update(b"migration_artifact_sign_v1:");
    mac.update(&canonical_artifact_payload(artifact));
    hex::encode(mac.finalize().into_bytes())
}

fn canonical_behavioral_conformance_certificate_payload(
    certificate: &BehavioralConformanceCertificate,
) -> Vec<u8> {
    serde_json::to_vec(&UnsignedBehavioralConformanceCertificate {
        schema_version: &certificate.schema_version,
        source_hash: &certificate.source_hash,
        target_hash: &certificate.target_hash,
        rule_id: &certificate.rule_id,
        rule_version: &certificate.rule_version,
        precondition_proof: &certificate.precondition_proof,
        lockstep_verdict_hash: &certificate.lockstep_verdict_hash,
        differential_witness: &certificate.differential_witness,
        bound: &certificate.bound,
        ledger_chain: &certificate.ledger_chain,
        content_hash: &certificate.content_hash,
        created_at: &certificate.created_at,
    })
    .unwrap_or_else(|error| {
        format!("__behavioral_conformance_certificate_serde_error:{error}").into_bytes()
    })
}

fn sign_behavioral_conformance_certificate(
    certificate: &BehavioralConformanceCertificate,
) -> String {
    let mut mac = HmacSha256::new_from_slice(BEHAVIORAL_CONFORMANCE_CERTIFICATE_SIGNING_KEY)
        .expect("behavioral conformance certificate signing key is valid");
    mac.update(b"behavioral_conformance_certificate_sign_v1:");
    mac.update(&canonical_behavioral_conformance_certificate_payload(
        certificate,
    ));
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_artifact_signatures(artifact: &MigrationArtifact) -> bool {
    let expected_rollback_signature = sign_rollback_receipt(&artifact.rollback_receipt);
    if !crate::security::constant_time::ct_eq(
        &artifact.rollback_receipt.signature,
        &expected_rollback_signature,
    ) {
        return false;
    }

    let expected_artifact_signature = sign_artifact(artifact);
    crate::security::constant_time::ct_eq(&artifact.signature, &expected_artifact_signature)
}

pub fn verify_behavioral_conformance_certificate_signature(
    certificate: &BehavioralConformanceCertificate,
) -> bool {
    let expected_signature = sign_behavioral_conformance_certificate(certificate);
    crate::security::constant_time::ct_eq(&certificate.signature, &expected_signature)
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
            signature: String::new(),
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
        signature: String::new(),
        content_hash: String::new(),
        created_at: "2026-02-21T00:00:00Z".to_string(),
    };

    artifact.rollback_receipt.signature = sign_rollback_receipt(&artifact.rollback_receipt);
    artifact.content_hash = compute_content_hash(&artifact);
    artifact.signature = sign_artifact(&artifact);
    artifact
}

/// Generate a reference bounded behavioral conformance certificate.
pub fn generate_reference_behavioral_conformance_certificate() -> BehavioralConformanceCertificate {
    let mut precondition_proof = BTreeMap::new();
    precondition_proof.insert(
        "rule".to_string(),
        serde_json::json!("rewrite:cjs-require-to-esm@1.0.0"),
    );
    precondition_proof.insert("require_cache_absent".to_string(), serde_json::json!(true));
    precondition_proof.insert(
        "source_ast_hash".to_string(),
        serde_json::json!("1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"),
    );

    let mut differential_witness = DifferentialWitness {
        lockstep_oracle_id: "compat-lockstep-oracle-v1".to_string(),
        fixture_corpus_digest: "cc33".repeat(16),
        proptest_seed: "proptest-seed:cjs-esm:0000000000000001".to_string(),
        fixture_cases: 64,
        proptest_cases: 32,
        effect_receipt_equivalence_cases: 32,
        divergence_count: 0,
        verdict: DifferentialWitnessVerdict::Pass,
        witness_hash: String::new(),
    };
    differential_witness.witness_hash = compute_differential_witness_hash(&differential_witness);

    let mut certificate = BehavioralConformanceCertificate {
        schema_version: BEHAVIORAL_CONFORMANCE_CERTIFICATE_SCHEMA_VERSION.to_string(),
        source_hash: "aa11".repeat(16),
        target_hash: "bb22".repeat(16),
        rule_id: "rewrite:cjs-require-to-esm".to_string(),
        rule_version: "1.0.0".to_string(),
        precondition_proof,
        lockstep_verdict_hash: differential_witness.witness_hash.clone(),
        differential_witness,
        bound: BehavioralConformanceBound {
            input_scope: vec![BoundedInputScope {
                input_class: "commonjs-module".to_string(),
                selector: "fixtures/migration/commonjs/*.js".to_string(),
                count: 128,
                digest: "dd44".repeat(16),
            }],
            property_classes: vec![
                ConformancePropertyClass::SyntaxEquivalence,
                ConformancePropertyClass::ObservableOutput,
                ConformancePropertyClass::ErrorBehavior,
            ],
            coverage: BoundCoverage {
                covered_cases: 128,
                total_cases: 128,
                coverage_ratio: 1.0,
                measurement_method: "deterministic-lockstep-corpus-v1".to_string(),
            },
        },
        ledger_chain: CertificateLedgerChain {
            previous_certificate_hash: None,
            evidence_ledger_entry_hash: "ee55".repeat(16),
            certificate_sequence: 0,
            ledger_domain: "observability:evidence-ledger-v2".to_string(),
        },
        content_hash: String::new(),
        created_at: "2026-02-21T00:00:00Z".to_string(),
        signature: String::new(),
    };

    certificate.content_hash = compute_behavioral_conformance_certificate_hash(&certificate);
    certificate.signature = sign_behavioral_conformance_certificate(&certificate);
    certificate
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
    use crate::security::constant_time;

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
        assert_eq!(artifact.signature.len(), 64);
        assert!(verify_artifact_signatures(&artifact));
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
        assert_eq!(artifact.rollback_receipt.signature.len(), 64);
    }

    #[test]
    fn test_reference_artifact_has_verifier_metadata() {
        let artifact = generate_reference_artifact();
        assert!(!artifact.verifier_metadata.replay_capsule_refs.is_empty());
        assert!(!artifact.verifier_metadata.expected_state_hashes.is_empty());
    }

    #[test]
    fn test_reference_behavioral_conformance_certificate_has_first_class_bound() {
        let certificate = generate_reference_behavioral_conformance_certificate();

        assert_eq!(
            certificate.schema_version,
            BEHAVIORAL_CONFORMANCE_CERTIFICATE_SCHEMA_VERSION
        );
        assert_eq!(certificate.bound.input_scope.len(), 1);
        assert_eq!(
            certificate.bound.property_classes,
            vec![
                ConformancePropertyClass::SyntaxEquivalence,
                ConformancePropertyClass::ObservableOutput,
                ConformancePropertyClass::ErrorBehavior,
            ]
        );
        assert_eq!(certificate.bound.coverage.covered_cases, 128);
        assert_eq!(certificate.bound.coverage.total_cases, 128);
        assert_eq!(certificate.differential_witness.fixture_cases, 64);
        assert_eq!(certificate.differential_witness.proptest_cases, 32);
        assert_eq!(
            certificate
                .differential_witness
                .effect_receipt_equivalence_cases,
            32
        );
        assert_eq!(certificate.differential_witness.divergence_count, 0);
        assert_eq!(
            certificate.differential_witness.verdict,
            DifferentialWitnessVerdict::Pass
        );
        assert_eq!(
            certificate.lockstep_verdict_hash,
            certificate.differential_witness.witness_hash
        );

        let value = serde_json::to_value(&certificate).unwrap();
        assert!(value.get("bound").is_some());
        assert!(value.get("differential_witness").is_some());
        assert_eq!(
            value["bound"]["input_scope"][0]["input_class"],
            "commonjs-module"
        );
        assert_eq!(value["bound"]["property_classes"][0], "syntax_equivalence");
        assert_eq!(value["bound"]["coverage"]["coverage_ratio"], 1.0);
        assert_eq!(
            value["differential_witness"]["lockstep_oracle_id"],
            "compat-lockstep-oracle-v1"
        );
        assert_eq!(value["differential_witness"]["verdict"], "pass");
    }

    #[test]
    fn test_reference_behavioral_conformance_certificate_is_ledger_chained() {
        let certificate = generate_reference_behavioral_conformance_certificate();

        assert_eq!(
            certificate.ledger_chain.ledger_domain,
            "observability:evidence-ledger-v2"
        );
        assert!(certificate.ledger_chain.previous_certificate_hash.is_none());
        assert!(is_sha256_hex(
            &certificate.ledger_chain.evidence_ledger_entry_hash
        ));
        assert_eq!(certificate.ledger_chain.certificate_sequence, 0);
    }

    #[test]
    fn test_reference_behavioral_conformance_certificate_has_bound_differential_witness() {
        let certificate = generate_reference_behavioral_conformance_certificate();
        let witness = &certificate.differential_witness;

        assert_eq!(witness.lockstep_oracle_id, "compat-lockstep-oracle-v1");
        assert_eq!(witness.fixture_cases + witness.proptest_cases, 96);
        assert_eq!(witness.effect_receipt_equivalence_cases, 32);
        assert_eq!(
            witness.total_cases(),
            certificate.bound.coverage.covered_cases
        );
        assert_eq!(
            witness.total_cases(),
            certificate.bound.coverage.total_cases
        );
        assert_eq!(witness.witness_hash.len(), 64);
        assert_eq!(witness.witness_hash, certificate.lockstep_verdict_hash);
        assert_eq!(
            witness.witness_hash,
            compute_differential_witness_hash(witness)
        );
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
    fn test_validate_reference_behavioral_conformance_certificate_passes() {
        let certificate = generate_reference_behavioral_conformance_certificate();

        let result = validate_behavioral_conformance_certificate(&certificate);

        assert!(result.valid, "errors: {:?}", result.errors);
        assert!(verify_behavioral_conformance_certificate_signature(
            &certificate
        ));
    }

    #[test]
    fn test_reference_artifact_signature_detects_tampering() {
        let mut artifact = generate_reference_artifact();
        assert!(verify_artifact_signatures(&artifact));
        artifact.steps[0].rollback_action.push_str("_tampered");
        assert!(!verify_artifact_signatures(&artifact));
    }

    #[test]
    fn test_behavioral_conformance_certificate_signature_detects_bound_tampering() {
        let mut certificate = generate_reference_behavioral_conformance_certificate();
        assert!(verify_behavioral_conformance_certificate_signature(
            &certificate
        ));

        certificate.bound.coverage.covered_cases = 127;

        assert!(!verify_behavioral_conformance_certificate_signature(
            &certificate
        ));
    }

    #[test]
    fn test_behavioral_conformance_certificate_validation_rejects_stale_content_hash() {
        let mut certificate = generate_reference_behavioral_conformance_certificate();
        certificate.bound.input_scope[0].selector = "fixtures/other/*.js".to_string();
        certificate.signature = sign_behavioral_conformance_certificate(&certificate);

        let result = validate_behavioral_conformance_certificate(&certificate);

        assert!(!result.valid);
        assert!(result.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_INVALID_SCHEMA)
                && error.contains("content_hash does not match")
        }));
    }

    #[test]
    fn test_behavioral_conformance_certificate_hash_changes_with_bound() {
        let certificate = generate_reference_behavioral_conformance_certificate();
        let mut changed = certificate.clone();
        changed
            .bound
            .property_classes
            .push(ConformancePropertyClass::SideEffectBoundary);

        assert_ne!(
            certificate.content_hash,
            compute_behavioral_conformance_certificate_hash(&changed)
        );
    }

    #[test]
    fn test_behavioral_conformance_certificate_hash_changes_with_differential_witness() {
        let certificate = generate_reference_behavioral_conformance_certificate();
        let mut changed = certificate.clone();
        changed.differential_witness.proptest_seed =
            "proptest-seed:cjs-esm:0000000000000002".to_string();
        changed.differential_witness.witness_hash =
            compute_differential_witness_hash(&changed.differential_witness);
        changed.lockstep_verdict_hash = changed.differential_witness.witness_hash.clone();

        assert_ne!(
            certificate.content_hash,
            compute_behavioral_conformance_certificate_hash(&changed)
        );
    }

    #[test]
    fn test_validate_certificate_rejects_differential_witness_divergence() {
        let mut certificate = generate_reference_behavioral_conformance_certificate();
        certificate.differential_witness.divergence_count = 1;
        certificate.differential_witness.verdict = DifferentialWitnessVerdict::Fail;
        certificate.differential_witness.witness_hash =
            compute_differential_witness_hash(&certificate.differential_witness);
        certificate.lockstep_verdict_hash = certificate.differential_witness.witness_hash.clone();
        certificate.content_hash = compute_behavioral_conformance_certificate_hash(&certificate);
        certificate.signature = sign_behavioral_conformance_certificate(&certificate);

        let result = validate_behavioral_conformance_certificate(&certificate);

        assert!(!result.valid);
        assert!(result.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID)
                && error.contains("zero-divergence")
        }));
    }

    #[test]
    fn test_validate_certificate_rejects_unbound_differential_witness_hash() {
        let mut certificate = generate_reference_behavioral_conformance_certificate();
        certificate.differential_witness.proptest_cases = 31;
        certificate.content_hash = compute_behavioral_conformance_certificate_hash(&certificate);
        certificate.signature = sign_behavioral_conformance_certificate(&certificate);

        let result = validate_behavioral_conformance_certificate(&certificate);

        assert!(!result.valid);
        assert!(result.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID)
                && error.contains("witness_hash")
        }));
    }

    #[test]
    fn test_reference_artifact_signatures_are_not_placeholder_prefixed() {
        let artifact = generate_reference_artifact();
        assert!(!artifact.signature.starts_with("sig_"));
        assert!(!artifact.rollback_receipt.signature.starts_with("sig_"));
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

    #[test]
    fn test_validate_certificate_missing_bound_inputs_fails() {
        let mut certificate = generate_reference_behavioral_conformance_certificate();
        certificate.bound.input_scope.clear();
        certificate.content_hash = compute_behavioral_conformance_certificate_hash(&certificate);
        certificate.signature = sign_behavioral_conformance_certificate(&certificate);

        let result = validate_behavioral_conformance_certificate(&certificate);

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(error_codes::ERR_MA_BOUND_INVALID))
        );
    }

    #[test]
    fn test_validate_certificate_bad_coverage_fails() {
        let mut certificate = generate_reference_behavioral_conformance_certificate();
        certificate.bound.coverage.covered_cases = 129;
        certificate.content_hash = compute_behavioral_conformance_certificate_hash(&certificate);
        certificate.signature = sign_behavioral_conformance_certificate(&certificate);

        let result = validate_behavioral_conformance_certificate(&certificate);

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(error_codes::ERR_MA_BOUND_INVALID))
        );
    }

    #[test]
    fn test_validate_certificate_bad_ledger_hash_fails() {
        let mut certificate = generate_reference_behavioral_conformance_certificate();
        certificate.ledger_chain.evidence_ledger_entry_hash = "not-a-hash".to_string();
        certificate.content_hash = compute_behavioral_conformance_certificate_hash(&certificate);
        certificate.signature = sign_behavioral_conformance_certificate(&certificate);

        let result = validate_behavioral_conformance_certificate(&certificate);

        assert!(!result.valid);
        assert!(result.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_INVALID_SCHEMA)
                && error.contains("ledger_chain.evidence_ledger_entry_hash")
        }));
    }

    #[test]
    fn test_validate_certificate_bad_previous_hash_fails() {
        let mut certificate = generate_reference_behavioral_conformance_certificate();
        certificate.ledger_chain.previous_certificate_hash = Some("short".to_string());
        certificate.content_hash = compute_behavioral_conformance_certificate_hash(&certificate);
        certificate.signature = sign_behavioral_conformance_certificate(&certificate);

        let result = validate_behavioral_conformance_certificate(&certificate);

        assert!(!result.valid);
        assert!(result.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_INVALID_SCHEMA)
                && error.contains("ledger_chain.previous_certificate_hash")
        }));
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

    // bd-i8z4r: NaN/Inf in confidence_interval must not cause hash collisions
    #[test]
    fn test_content_hash_nan_probability_produces_sentinel() {
        let mut a = generate_reference_artifact();
        a.confidence_interval.probability = f64::NAN;
        let hash = compute_content_hash(&a);
        // Must produce a deterministic sentinel hash, not collide with valid artifacts
        assert_ne!(hash, generate_reference_artifact().content_hash);
    }

    #[test]
    fn test_content_hash_inf_dry_run_produces_sentinel() {
        let mut a = generate_reference_artifact();
        a.confidence_interval.dry_run_success_rate = f64::INFINITY;
        let hash = compute_content_hash(&a);
        assert_ne!(hash, generate_reference_artifact().content_hash);
    }

    #[test]
    fn test_content_hash_nan_sentinel_is_deterministic() {
        let mut a1 = generate_reference_artifact();
        let mut a2 = generate_reference_artifact();
        a1.confidence_interval.probability = f64::NAN;
        a2.confidence_interval.probability = f64::NAN;
        // All non-finite artifacts map to the same sentinel
        assert_eq!(compute_content_hash(&a1), compute_content_hash(&a2));
    }

    #[test]
    fn test_content_hash_neg_inf_precondition_produces_sentinel() {
        let mut a = generate_reference_artifact();
        a.confidence_interval.precondition_coverage = f64::NEG_INFINITY;
        let hash = compute_content_hash(&a);
        assert_ne!(hash, generate_reference_artifact().content_hash);
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
    fn test_behavioral_conformance_certificate_serde_roundtrip() {
        let certificate = generate_reference_behavioral_conformance_certificate();
        let json = serde_json::to_string(&certificate).unwrap();
        let parsed: BehavioralConformanceCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(certificate, parsed);
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
        assert_eq!(error_codes::ERR_MA_BOUND_INVALID, "ERR_MA_BOUND_INVALID");
        assert_eq!(
            error_codes::ERR_MA_LEDGER_CHAIN_INVALID,
            "ERR_MA_LEDGER_CHAIN_INVALID"
        );
        assert_eq!(
            error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID,
            "ERR_MA_DIFFERENTIAL_WITNESS_INVALID"
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
        assert_eq!(
            invariants::INV_MA_BOUND_FIRST_CLASS,
            "INV-MA-BOUND-FIRST-CLASS"
        );
        assert_eq!(invariants::INV_MA_LEDGER_CHAINED, "INV-MA-LEDGER-CHAINED");
        assert_eq!(
            invariants::INV_MA_DIFFERENTIAL_WITNESS_BOUND,
            "INV-MA-DIFFERENTIAL-WITNESS-BOUND"
        );
    }

    // ── Schema version ────────────────────────────────────────────────

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "ma-v1.0");
        assert_eq!(
            BEHAVIORAL_CONFORMANCE_CERTIFICATE_SCHEMA_VERSION,
            "bcc-v1.0"
        );
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
        assert_send::<BoundedInputScope>();
        assert_sync::<BoundedInputScope>();
        assert_send::<ConformancePropertyClass>();
        assert_sync::<ConformancePropertyClass>();
        assert_send::<BoundCoverage>();
        assert_sync::<BoundCoverage>();
        assert_send::<BehavioralConformanceBound>();
        assert_sync::<BehavioralConformanceBound>();
        assert_send::<CertificateLedgerChain>();
        assert_sync::<CertificateLedgerChain>();
        assert_send::<DifferentialWitnessVerdict>();
        assert_sync::<DifferentialWitnessVerdict>();
        assert_send::<DifferentialWitness>();
        assert_sync::<DifferentialWitness>();
        assert_send::<BehavioralConformanceCertificate>();
        assert_sync::<BehavioralConformanceCertificate>();
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

    #[test]
    fn test_verify_signatures_timing_safe_near_match() {
        // Regression: HMAC comparisons must use ct_eq, not ==.
        // Forge a signature that differs only in the last byte.
        let mut artifact = generate_reference_artifact();
        assert!(verify_artifact_signatures(&artifact));

        // Mutate last byte of artifact signature
        let mut forged = artifact.signature.clone();
        let last = forged.pop().unwrap();
        let replacement = if last == 'a' { 'b' } else { 'a' };
        forged.push(replacement);
        artifact.signature = forged;
        assert!(!verify_artifact_signatures(&artifact));

        // Mutate last byte of rollback receipt signature
        let mut artifact2 = generate_reference_artifact();
        let mut forged_rb = artifact2.rollback_receipt.signature.clone();
        let last_rb = forged_rb.pop().unwrap();
        let replacement_rb = if last_rb == 'a' { 'b' } else { 'a' };
        forged_rb.push(replacement_rb);
        artifact2.rollback_receipt.signature = forged_rb;
        assert!(!verify_artifact_signatures(&artifact2));
    }

    #[test]
    fn test_validate_missing_rollback_procedure_hash_fails_precisely() {
        let mut artifact = generate_reference_artifact();
        artifact.rollback_receipt.rollback_procedure_hash.clear();

        let result = validate_artifact(&artifact);

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(error_codes::ERR_MA_MISSING_ROLLBACK))
        );
    }

    #[test]
    fn test_validate_missing_rollback_signer_fails_precisely() {
        let mut artifact = generate_reference_artifact();
        artifact.rollback_receipt.signer_identity.clear();

        let result = validate_artifact(&artifact);

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(error_codes::ERR_MA_MISSING_ROLLBACK))
        );
    }

    #[test]
    fn test_validate_missing_rollback_signature_fails_precisely() {
        let mut artifact = generate_reference_artifact();
        artifact.rollback_receipt.signature.clear();

        let result = validate_artifact(&artifact);

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(error_codes::ERR_MA_MISSING_ROLLBACK))
        );
    }

    #[test]
    fn test_validate_nan_probability_fails_closed() {
        let mut artifact = generate_reference_artifact();
        artifact.confidence_interval.probability = f64::NAN;

        let result = validate_artifact(&artifact);

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(error_codes::ERR_MA_CONFIDENCE_LOW))
        );
    }

    #[test]
    fn test_validate_negative_probability_fails_closed() {
        let mut artifact = generate_reference_artifact();
        artifact.confidence_interval.probability = -0.01;

        let result = validate_artifact(&artifact);

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("probability -0.01 out of [0.0, 1.0]"))
        );
    }

    #[test]
    fn test_validate_confidence_fields_fail_closed() {
        let mut artifact = generate_reference_artifact();
        artifact.confidence_interval.dry_run_success_rate = -0.1;
        artifact.confidence_interval.historical_similarity = 1.1;
        artifact.confidence_interval.precondition_coverage = f64::INFINITY;

        let result = validate_artifact(&artifact);

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 3);
        assert!(result.warnings.is_empty());
        assert!(result.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_CONFIDENCE_LOW)
                && error.contains("dry_run_success_rate")
        }));
        assert!(result.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_CONFIDENCE_LOW)
                && error.contains("historical_similarity")
        }));
        assert!(result.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_CONFIDENCE_LOW)
                && error.contains("precondition_coverage")
        }));
    }

    #[test]
    fn test_verify_artifact_signature_rejects_content_hash_tamper() {
        let mut artifact = generate_reference_artifact();
        assert!(verify_artifact_signatures(&artifact));

        artifact.content_hash.replace_range(0..1, "0");

        assert!(!verify_artifact_signatures(&artifact));
    }

    #[test]
    fn test_verify_rollback_signature_rejects_max_time_tamper() {
        let mut artifact = generate_reference_artifact();
        assert!(verify_artifact_signatures(&artifact));

        artifact.rollback_receipt.max_rollback_time_ms = artifact
            .rollback_receipt
            .max_rollback_time_ms
            .saturating_add(1);

        assert!(!verify_artifact_signatures(&artifact));
    }

    #[test]
    fn test_verify_artifact_signature_rejects_created_at_tamper() {
        let mut artifact = generate_reference_artifact();
        assert!(verify_artifact_signatures(&artifact));

        artifact.created_at = "2026-02-22T00:00:00Z".to_string();

        assert!(!verify_artifact_signatures(&artifact));
    }

    #[test]
    fn negative_validate_trailing_space_schema_version_fails_closed() {
        let mut artifact = generate_reference_artifact();
        artifact.schema_version = format!("{SCHEMA_VERSION} ");

        let result = validate_artifact(&artifact);

        assert!(!result.valid);
        assert!(result.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_VERSION_UNSUPPORTED) && error.contains("ma-v1.0 ")
        }));
    }

    #[test]
    fn negative_validate_empty_schema_version_fails_closed() {
        let mut artifact = generate_reference_artifact();
        artifact.schema_version.clear();

        let result = validate_artifact(&artifact);

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(error_codes::ERR_MA_VERSION_UNSUPPORTED))
        );
    }

    #[test]
    fn negative_validate_infinite_probability_fails_closed() {
        let mut artifact = generate_reference_artifact();
        artifact.confidence_interval.probability = f64::INFINITY;

        let result = validate_artifact(&artifact);

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(error_codes::ERR_MA_CONFIDENCE_LOW))
        );
    }

    #[test]
    fn negative_validate_negative_infinite_probability_fails_closed() {
        let mut artifact = generate_reference_artifact();
        artifact.confidence_interval.probability = f64::NEG_INFINITY;

        let result = validate_artifact(&artifact);

        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains(error_codes::ERR_MA_CONFIDENCE_LOW))
        );
    }

    #[test]
    fn negative_rollback_original_state_tamper_rejects_signatures() {
        let mut artifact = generate_reference_artifact();
        assert!(verify_artifact_signatures(&artifact));

        artifact
            .rollback_receipt
            .original_state_ref
            .push_str("#tampered");

        assert!(!verify_artifact_signatures(&artifact));
    }

    #[test]
    fn negative_empty_rollback_signature_rejects_signature_verification() {
        let mut artifact = generate_reference_artifact();
        artifact.rollback_receipt.signature.clear();

        assert!(!verify_artifact_signatures(&artifact));
    }

    #[test]
    fn negative_empty_artifact_signature_rejects_signature_verification() {
        let mut artifact = generate_reference_artifact();
        artifact.signature.clear();

        assert!(!verify_artifact_signatures(&artifact));
    }

    #[test]
    fn negative_deserialize_artifact_rejects_missing_plan_id() {
        let mut value = serde_json::to_value(generate_reference_artifact()).unwrap();
        value.as_object_mut().unwrap().remove("plan_id");

        let result = serde_json::from_value::<MigrationArtifact>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_deserialize_artifact_rejects_string_plan_version() {
        let mut value = serde_json::to_value(generate_reference_artifact()).unwrap();
        value.as_object_mut().unwrap().insert(
            "plan_version".to_string(),
            serde_json::Value::String("1".to_string()),
        );

        let result = serde_json::from_value::<MigrationArtifact>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_deserialize_confidence_rejects_string_probability() {
        let raw = serde_json::json!({
            "probability": "0.95",
            "dry_run_success_rate": 0.98,
            "historical_similarity": 0.90,
            "precondition_coverage": 1.0,
            "rollback_validation": true
        });

        let result = serde_json::from_value::<ConfidenceInterval>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn negative_deserialize_step_rejects_missing_rollback_action() {
        let raw = serde_json::json!({
            "action_type": "schema_upgrade",
            "target_resource": "trust_store.db",
            "pre_state_hash": "aaaa",
            "post_state_hash": "bbbb",
            "estimated_duration_ms": 5000
        });

        let result = serde_json::from_value::<MigrationStep>(raw);

        assert!(result.is_err());
    }
}
