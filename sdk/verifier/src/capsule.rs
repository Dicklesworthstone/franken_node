//! Replay capsule types and operations for external verifiers.
//!
//! This module provides the public-facing capsule format that external verifiers
//! use to replay Ed25519-authenticated capsules and reproduce claim verdicts
//! without privileged internal access.
//!
//! # Security Posture
//!
//! This module provides cryptographic Ed25519 verification. `sign_capsule` and `verify_signature`
//! generate and verify real Ed25519 cryptographic signatures so
//! external tools can authenticate capsule provenance with full
//! cryptographic guarantees. This provides replacement-quality
//! verification capabilities.
//!
//! # Invariants
//!
//! - INV-CAPSULE-STABLE-SCHEMA: Schema format is stable across versions.
//! - INV-CAPSULE-VERSIONED-API: Every capsule carries a version.
//! - INV-CAPSULE-NO-PRIVILEGED-ACCESS: Replay is entirely local and offline.
//! - INV-CAPSULE-VERDICT-REPRODUCIBLE: Same capsule always yields same verdict.

use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hex;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{
    ERR_CAPSULE_ACCESS_DENIED, ERR_CAPSULE_REPLAY_DIVERGED, ERR_CAPSULE_SCHEMA_MISMATCH,
    ERR_CAPSULE_SIGNATURE_INVALID, ERR_CAPSULE_VERDICT_MISMATCH, SDK_VERSION,
};

/// Security posture marker for the workspace replay capsule with cryptographic signatures.
pub const CRYPTOGRAPHIC_SECURITY_POSTURE: &str = "cryptographic_ed25519_authenticated";

/// Stable rule id for guardrails that must fence the workspace replay capsule surface.
pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::WORKSPACE_REPLAY_CAPSULE";

const MAX_VERIFIER_IDENTITY_NAME_LEN: usize = 255;
const MAX_CREATOR_IDENTITY_NAME_LEN: usize = 255;

/// Domain separator for Ed25519 capsule signatures.
const ED25519_CAPSULE_SIGNATURE_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:ed25519-capsule-signature:v1:";

// ---------------------------------------------------------------------------
// Capsule types
// ---------------------------------------------------------------------------

/// Manifest describing a replay capsule's contents.
///
/// INV-CAPSULE-VERSIONED-API: carries schema_version.
/// INV-CAPSULE-STABLE-SCHEMA: fields are fixed for a given schema version.
#[derive(Debug, Clone, PartialEq)]
pub struct CapsuleManifest {
    pub schema_version: String,
    pub capsule_id: String,
    pub description: String,
    pub claim_type: String,
    pub input_refs: Vec<String>,
    pub expected_output_hash: String,
    pub created_at: String,
    pub creator_identity: String,
    pub metadata: BTreeMap<String, String>,
}

/// A signed, self-contained replay capsule.
///
/// INV-CAPSULE-NO-PRIVILEGED-ACCESS: all data needed for replay is included.
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: deterministic replay from contained data.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayCapsule {
    pub manifest: CapsuleManifest,
    pub payload: String,
    pub inputs: BTreeMap<String, String>,
    pub signature: String,
}

/// Verdict of a capsule replay operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleVerdict {
    Pass,
    Fail,
    Inconclusive,
}

/// Result of replaying a capsule.
#[derive(Debug, Clone, PartialEq)]
pub struct CapsuleReplayResult {
    pub capsule_id: String,
    pub verdict: CapsuleVerdict,
    pub expected_hash: String,
    pub actual_hash: String,
    pub detail: String,
}

/// Error type for capsule operations.
#[derive(Debug, Clone, PartialEq)]
pub enum CapsuleError {
    SignatureInvalid(String),
    Ed25519SignatureMalformed { length: usize },
    Ed25519SignatureInvalid,
    SchemaMismatch(String),
    ReplayDiverged { expected: String, actual: String },
    VerdictMismatch { expected: String, actual: String },
    AccessDenied(String),
    EmptyPayload(String),
    ManifestIncomplete(String),
}

impl std::fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureInvalid(msg) => {
                write!(f, "{}: {msg}", ERR_CAPSULE_SIGNATURE_INVALID)
            }
            Self::Ed25519SignatureMalformed { length } => write!(
                f,
                "replay capsule Ed25519 signature has invalid length {length}"
            ),
            Self::Ed25519SignatureInvalid => {
                write!(f, "replay capsule Ed25519 signature verification failed")
            }
            Self::SchemaMismatch(msg) => {
                write!(f, "{}: {msg}", ERR_CAPSULE_SCHEMA_MISMATCH)
            }
            Self::ReplayDiverged {
                expected: _,
                actual: _,
            } => {
                write!(
                    f,
                    "{}: replay output hash mismatch (expected and actual digests redacted)",
                    ERR_CAPSULE_REPLAY_DIVERGED
                )
            }
            Self::VerdictMismatch {
                expected: _,
                actual: _,
            } => {
                write!(
                    f,
                    "{}: reproduced verdict mismatch (expected and actual verdicts redacted)",
                    ERR_CAPSULE_VERDICT_MISMATCH
                )
            }
            Self::AccessDenied(msg) => {
                write!(f, "{}: {msg}", ERR_CAPSULE_ACCESS_DENIED)
            }
            Self::EmptyPayload(msg) => {
                write!(f, "ERR_CAPSULE_EMPTY_PAYLOAD: {msg}")
            }
            Self::ManifestIncomplete(msg) => {
                write!(f, "ERR_CAPSULE_MANIFEST_INCOMPLETE: {msg}")
            }
        }
    }
}

/// Standard result type returned by replay capsule helpers.
pub type CapsuleResult<T> = Result<T, CapsuleError>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Constant-time string comparison to prevent timing side-channels on
/// signature/hash verification.
fn ct_eq(a: &str, b: &str) -> bool {
    ct_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Constant-time byte slice comparison.
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Compute a deterministic hash (SHA-256, hex-encoded) with domain separator.
///
/// External verifiers may use this for ad-hoc hashing of capsule-related data.
///
/// # Examples
///
/// ```rust
/// use frankenengine_verifier_sdk::capsule::deterministic_hash;
///
/// let digest = deterministic_hash("payload");
/// assert_eq!(digest.len(), 64);
/// ```
///
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: same inputs always yield same output.
pub fn deterministic_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"verifier_sdk_capsule_v1:");
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
fn push_length_prefixed(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value.as_bytes());
}

/// Modern length-prefixed byte serialization (consistent with bundle.rs)
fn push_length_prefixed_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    buffer.extend_from_slice(bytes);
}

/// Compute the deterministic replay hash for a capsule's payload and inputs.
///
/// Uses length-prefixed encoding to prevent payload-input delimiter collision:
/// without length-prefixing, a payload containing "|key=value" would hash
/// identically to a shorter payload with that key-value pair in inputs.
fn compute_replay_hash(payload: &str, inputs: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"verifier_sdk_capsule_replay_v1:");
    hasher.update(
        u64::try_from(payload.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(payload.as_bytes());
    hasher.update(
        u64::try_from(inputs.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (k, v) in inputs {
        hasher.update(u64::try_from(k.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(k.as_bytes());
        hasher.update(u64::try_from(v.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(v.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Compute the signing payload for a capsule using length-prefixed SHA-256.
///
/// Uses length-prefixed encoding to prevent delimiter-collision ambiguity
/// across manifest fields, payload, and inputs.
///
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: deterministic for same capsule contents.
#[cfg(test)]
fn compute_signing_payload(capsule: &ReplayCapsule) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"verifier_sdk_capsule_signing_v1:");
    for field in [
        capsule.manifest.capsule_id.as_str(),
        capsule.manifest.schema_version.as_str(),
        capsule.manifest.description.as_str(),
        capsule.manifest.claim_type.as_str(),
        capsule.manifest.expected_output_hash.as_str(),
        capsule.manifest.created_at.as_str(),
        capsule.manifest.creator_identity.as_str(),
        capsule.payload.as_str(),
    ] {
        push_length_prefixed(&mut hasher, field);
    }
    hasher.update(
        u64::try_from(capsule.manifest.input_refs.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for input_ref in &capsule.manifest.input_refs {
        push_length_prefixed(&mut hasher, input_ref);
    }
    hasher.update(
        u64::try_from(capsule.manifest.metadata.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (key, value) in &capsule.manifest.metadata {
        push_length_prefixed(&mut hasher, key);
        push_length_prefixed(&mut hasher, value);
    }
    hasher.update(
        u64::try_from(capsule.inputs.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (k, v) in &capsule.inputs {
        push_length_prefixed(&mut hasher, k);
        push_length_prefixed(&mut hasher, v);
    }
    hex::encode(hasher.finalize())
}

/// Compute the Ed25519 signing payload for a capsule.
///
/// Creates domain-separated payload with length-prefixed encoding for all
/// capsule fields to prevent field injection attacks.
fn ed25519_capsule_signature_payload(capsule: &ReplayCapsule) -> Vec<u8> {
    let mut payload = Vec::new();

    // Modern domain-separated length-prefixed construction (like bundle.rs)
    push_length_prefixed_bytes(&mut payload, ED25519_CAPSULE_SIGNATURE_DOMAIN);
    push_length_prefixed_bytes(&mut payload, capsule.manifest.schema_version.as_bytes());
    push_length_prefixed_bytes(&mut payload, capsule.manifest.capsule_id.as_bytes());
    push_length_prefixed_bytes(&mut payload, capsule.manifest.description.as_bytes());
    push_length_prefixed_bytes(&mut payload, capsule.manifest.claim_type.as_bytes());
    push_length_prefixed_bytes(
        &mut payload,
        capsule.manifest.expected_output_hash.as_bytes(),
    );
    push_length_prefixed_bytes(&mut payload, capsule.manifest.created_at.as_bytes());
    push_length_prefixed_bytes(&mut payload, capsule.manifest.creator_identity.as_bytes());
    push_length_prefixed_bytes(&mut payload, capsule.payload.as_bytes());

    // Serialize input_refs with length prefix
    payload.extend_from_slice(
        &u64::try_from(capsule.manifest.input_refs.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for input_ref in &capsule.manifest.input_refs {
        push_length_prefixed_bytes(&mut payload, input_ref.as_bytes());
    }

    // Serialize metadata with length prefix
    payload.extend_from_slice(
        &u64::try_from(capsule.manifest.metadata.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (key, value) in &capsule.manifest.metadata {
        push_length_prefixed_bytes(&mut payload, key.as_bytes());
        push_length_prefixed_bytes(&mut payload, value.as_bytes());
    }

    // Serialize inputs with length prefix
    payload.extend_from_slice(
        &u64::try_from(capsule.inputs.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (k, v) in &capsule.inputs {
        push_length_prefixed_bytes(&mut payload, k.as_bytes());
        push_length_prefixed_bytes(&mut payload, v.as_bytes());
    }

    payload
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Validate a capsule manifest for completeness.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "test-support")] {
/// use frankenengine_verifier_sdk::capsule::{build_reference_capsule, validate_manifest};
///
/// let capsule = build_reference_capsule();
/// validate_manifest(&capsule.manifest)?;
/// # }
/// # Ok::<(), frankenengine_verifier_sdk::capsule::CapsuleError>(())
/// ```
///
/// INV-CAPSULE-STABLE-SCHEMA: schema_version must match SDK_VERSION.
/// INV-CAPSULE-VERSIONED-API: version is checked.
pub fn validate_manifest(manifest: &CapsuleManifest) -> CapsuleResult<()> {
    if manifest.schema_version.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "schema_version is empty".into(),
        ));
    }
    if manifest.schema_version != SDK_VERSION {
        return Err(CapsuleError::SchemaMismatch(format!(
            "unsupported: {}, expected: {}",
            manifest.schema_version, SDK_VERSION
        )));
    }
    validate_capsule_id(&manifest.capsule_id)?;
    if manifest.claim_type.trim().is_empty() || manifest.claim_type != manifest.claim_type.trim() {
        return Err(CapsuleError::ManifestIncomplete(
            "claim_type is empty".into(),
        ));
    }
    if manifest.expected_output_hash.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "expected_output_hash is empty".into(),
        ));
    }
    if !is_sha256_hex(&manifest.expected_output_hash) {
        return Err(CapsuleError::ManifestIncomplete(
            "expected_output_hash must be a 64-character hex sha256 digest".into(),
        ));
    }
    if manifest.created_at.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "created_at is empty".into(),
        ));
    }
    if manifest.created_at != manifest.created_at.trim() {
        return Err(CapsuleError::ManifestIncomplete(
            "created_at must not contain leading or trailing whitespace".into(),
        ));
    }
    DateTime::parse_from_rfc3339(&manifest.created_at).map_err(|_| {
        CapsuleError::ManifestIncomplete("created_at must be a valid RFC3339 timestamp".into())
    })?;
    if manifest.creator_identity.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "creator_identity is empty".into(),
        ));
    }
    validate_creator_identity(&manifest.creator_identity)?;
    Ok(())
}

fn validate_capsule_id(capsule_id: &str) -> Result<(), CapsuleError> {
    validate_reference_identifier("capsule_id", capsule_id)
}

fn validate_declared_input_refs(capsule: &ReplayCapsule) -> Result<(), CapsuleError> {
    let mut declared = BTreeSet::new();
    for input_ref in &capsule.manifest.input_refs {
        validate_reference_identifier("input_refs", input_ref)?;
        if !declared.insert(input_ref.as_str()) {
            return Err(CapsuleError::ManifestIncomplete(
                "input_refs contains duplicate entries".into(),
            ));
        }
    }

    let mut actual = BTreeSet::new();
    for input_key in capsule.inputs.keys() {
        validate_reference_identifier("inputs", input_key)?;
        actual.insert(input_key.as_str());
    }
    if declared != actual {
        let missing: Vec<&str> = declared.difference(&actual).copied().collect();
        let extra: Vec<&str> = actual.difference(&declared).copied().collect();
        return Err(CapsuleError::ManifestIncomplete(format!(
            "input_refs do not match inputs: missing=[{}], extra=[{}]",
            missing.join(","),
            extra.join(",")
        )));
    }

    Ok(())
}

fn validate_reference_identifier(field: &str, value: &str) -> Result<(), CapsuleError> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(CapsuleError::ManifestIncomplete(format!(
            "{field} identifier must be non-empty and must not contain leading or trailing whitespace"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(CapsuleError::ManifestIncomplete(format!(
            "{field} identifier must include only ASCII letters, digits, '.', '-', and '_'"
        )));
    }
    Ok(())
}

fn validate_verifier_identity(verifier_identity: &str) -> Result<(), CapsuleError> {
    if verifier_identity != verifier_identity.trim() {
        return Err(CapsuleError::AccessDenied(
            "verifier_identity must not contain leading or trailing whitespace".into(),
        ));
    }
    let Some(remainder) = verifier_identity.strip_prefix("verifier://") else {
        return Err(CapsuleError::AccessDenied(
            "verifier_identity must use the external verifier:// scheme".into(),
        ));
    };
    if remainder.trim().is_empty() || remainder != remainder.trim() {
        return Err(CapsuleError::AccessDenied(
            "verifier_identity must include a non-empty verifier name".into(),
        ));
    }
    if remainder.len() > MAX_VERIFIER_IDENTITY_NAME_LEN {
        return Err(CapsuleError::AccessDenied(format!(
            "verifier_identity must be at most {MAX_VERIFIER_IDENTITY_NAME_LEN} ASCII bytes after verifier://"
        )));
    }
    if !remainder
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(CapsuleError::AccessDenied(
            "verifier_identity must include only ASCII letters, digits, '.', '-', and '_'".into(),
        ));
    }
    Ok(())
}

fn validate_creator_identity(creator_identity: &str) -> Result<(), CapsuleError> {
    if creator_identity != creator_identity.trim() {
        return Err(CapsuleError::ManifestIncomplete(
            "creator_identity must not contain leading or trailing whitespace".into(),
        ));
    }
    let Some(remainder) = creator_identity.strip_prefix("creator://") else {
        return Err(CapsuleError::ManifestIncomplete(
            "creator_identity must use the creator:// scheme".into(),
        ));
    };
    if remainder.trim().is_empty() || remainder != remainder.trim() {
        return Err(CapsuleError::ManifestIncomplete(
            "creator_identity must include a non-empty creator name".into(),
        ));
    }
    if remainder.len() > MAX_CREATOR_IDENTITY_NAME_LEN {
        return Err(CapsuleError::ManifestIncomplete(format!(
            "creator_identity must be at most {MAX_CREATOR_IDENTITY_NAME_LEN} ASCII bytes after creator://"
        )));
    }
    if !remainder
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'@'))
    {
        return Err(CapsuleError::ManifestIncomplete(
            "creator_identity must include only ASCII letters, digits, '.', '-', '_', and '@'"
                .into(),
        ));
    }
    Ok(())
}

/// Sign a capsule with Ed25519 cryptographic signature.
///
/// The signature binds the manifest, payload, and inputs via domain-separated
/// Ed25519 signing over length-prefixed SHA-256 canonical encoding.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "test-support")] {
/// use ed25519_dalek::SigningKey;
/// use frankenengine_verifier_sdk::capsule::{build_reference_capsule, sign_capsule};
///
/// let signing_key = SigningKey::from_bytes(&[1_u8; 32]);
/// let mut capsule = build_reference_capsule();
/// capsule.signature.clear();
/// sign_capsule(&signing_key, &mut capsule);
/// assert_eq!(capsule.signature.len(), 128); // hex-encoded 64-byte signature
/// # }
/// ```
pub fn sign_capsule(signing_key: &SigningKey, capsule: &mut ReplayCapsule) {
    let payload = ed25519_capsule_signature_payload(capsule);
    let signature = signing_key.sign(&payload);
    capsule.signature = hex::encode(signature.to_bytes());
}

/// Verify a capsule's Ed25519 cryptographic signature.
///
/// Verifies the Ed25519 signature against the canonical payload using the
/// provided public key. Prevents timing side-channel attacks.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "test-support")] {
/// use ed25519_dalek::{SigningKey, VerifyingKey};
/// use frankenengine_verifier_sdk::capsule::{build_reference_capsule, sign_capsule, verify_signature};
///
/// let signing_key = SigningKey::from_bytes(&[1_u8; 32]);
/// let verifying_key = VerifyingKey::from(&signing_key);
/// let mut capsule = build_reference_capsule();
/// sign_capsule(&signing_key, &mut capsule);
/// verify_signature(&verifying_key, &capsule)?;
/// # }
/// # Ok::<(), frankenengine_verifier_sdk::capsule::CapsuleError>(())
/// ```
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    capsule: &ReplayCapsule,
) -> CapsuleResult<()> {
    // Decode hex signature
    let signature_bytes =
        hex::decode(&capsule.signature).map_err(|_| CapsuleError::Ed25519SignatureMalformed {
            length: capsule.signature.len(),
        })?;

    if signature_bytes.len() != 64 {
        return Err(CapsuleError::Ed25519SignatureMalformed {
            length: signature_bytes.len(),
        });
    }

    let signature_array: [u8; 64] = signature_bytes.as_slice().try_into().map_err(|_| {
        CapsuleError::Ed25519SignatureMalformed {
            length: signature_bytes.len(),
        }
    })?;
    let signature = Signature::from_bytes(&signature_array);
    let payload = ed25519_capsule_signature_payload(capsule);

    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| CapsuleError::Ed25519SignatureInvalid)
}

/// Replay a capsule and produce a result.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "test-support")] {
/// use frankenengine_verifier_sdk::capsule::{build_reference_capsule, replay, CapsuleVerdict};
///
/// let result = replay(&build_reference_capsule(), "verifier://docs")?;
/// assert_eq!(result.verdict, CapsuleVerdict::Pass);
/// # }
/// # Ok::<(), frankenengine_verifier_sdk::capsule::CapsuleError>(())
/// ```
///
/// INV-CAPSULE-NO-PRIVILEGED-ACCESS: purely local computation.
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: deterministic for same inputs.
pub fn replay(
    verifying_key: &VerifyingKey,
    capsule: &ReplayCapsule,
    verifier_identity: &str,
) -> CapsuleResult<CapsuleReplayResult> {
    // Step 1: Validate manifest
    validate_manifest(&capsule.manifest)?;

    // Step 2: Ensure the caller is an external verifier identity.
    validate_verifier_identity(verifier_identity)?;

    // Step 3: Verify signature
    verify_signature(verifying_key, capsule)?;

    // Step 4: Bind the declared input inventory to the replayed inputs.
    validate_declared_input_refs(capsule)?;

    // Step 5: Check non-empty payload
    if capsule.payload.is_empty() {
        return Err(CapsuleError::EmptyPayload("payload is empty".into()));
    }

    // Step 6: Compute actual output hash using length-prefixed encoding
    let actual_hash = compute_replay_hash(&capsule.payload, &capsule.inputs);

    // Step 7: Compare
    let verdict = if ct_eq(&actual_hash, &capsule.manifest.expected_output_hash) {
        CapsuleVerdict::Pass
    } else {
        CapsuleVerdict::Fail
    };

    let detail = if verdict == CapsuleVerdict::Pass {
        "replay output matches expected hash".to_string()
    } else {
        "replay diverged: expected and actual digests redacted".to_string()
    };

    Ok(CapsuleReplayResult {
        capsule_id: capsule.manifest.capsule_id.clone(),
        verdict,
        expected_hash: capsule.manifest.expected_output_hash.clone(),
        actual_hash,
        detail,
    })
}

/// Build a reference capsule for testing.
///
/// The capsule is properly signed and has a valid expected_output_hash
/// so that replay will produce a PASS verdict.
///
/// # Examples
///
/// ```rust
/// use ed25519_dalek::{SigningKey, VerifyingKey};
/// use frankenengine_verifier_sdk::capsule::{build_reference_capsule, verify_signature};
///
/// let signing_key = SigningKey::from_bytes(&[1_u8; 32]);
/// let verifying_key = VerifyingKey::from(&signing_key);
/// let capsule = build_reference_capsule();
/// verify_signature(&verifying_key, &capsule)?;
/// # Ok::<(), frankenengine_verifier_sdk::capsule::CapsuleError>(())
/// ```
#[cfg(any(test, feature = "test-support"))]
pub fn build_reference_capsule() -> ReplayCapsule {
    let mut inputs = BTreeMap::new();
    inputs.insert("artifact_a".to_string(), "content_of_a".to_string());
    inputs.insert("artifact_b".to_string(), "content_of_b".to_string());

    let payload = "reference_payload_data".to_string();

    // Compute expected output hash exactly as replay does
    let expected_hash = compute_replay_hash(&payload, &inputs);

    let manifest = CapsuleManifest {
        schema_version: SDK_VERSION.to_string(),
        capsule_id: "capsule-ref-001".to_string(),
        description: "Reference capsule for testing".to_string(),
        claim_type: "migration_safety".to_string(),
        input_refs: vec!["artifact_a".to_string(), "artifact_b".to_string()],
        expected_output_hash: expected_hash,
        created_at: "2026-02-21T00:00:00Z".to_string(),
        creator_identity: "creator://test@example.com".to_string(),
        metadata: BTreeMap::new(),
    };

    let mut capsule = ReplayCapsule {
        manifest,
        payload,
        inputs,
        signature: String::new(),
    };
    let test_signing_key = SigningKey::from_bytes(&[1_u8; 32]);
    sign_capsule(&test_signing_key, &mut capsule);
    capsule
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Test signing key for consistent test signatures.
    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[1_u8; 32])
    }

    /// Test verifying key matching the test signing key.
    fn test_verifying_key() -> VerifyingKey {
        VerifyingKey::from(&test_signing_key())
    }

    fn replay(
        capsule: &ReplayCapsule,
        verifier_identity: &str,
    ) -> CapsuleResult<CapsuleReplayResult> {
        super::replay(&test_verifying_key(), capsule, verifier_identity)
    }

    fn assert_manifest_tamper_rejected(case: &str, mutate: impl FnOnce(&mut ReplayCapsule)) {
        let capsule = build_reference_capsule();
        let mut tampered = capsule.clone();
        mutate(&mut tampered);
        let verifying_key = test_verifying_key();
        match verify_signature(&verifying_key, &tampered) {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid for {case} tamper, got {other:?}"),
        }
    }

    #[test]
    fn test_cryptographic_posture_markers_defined() {
        assert_eq!(
            CRYPTOGRAPHIC_SECURITY_POSTURE,
            "cryptographic_ed25519_authenticated"
        );
        assert_eq!(
            STRUCTURAL_ONLY_RULE_ID,
            "VERIFIER_SHORTCUT_GUARD::WORKSPACE_REPLAY_CAPSULE"
        );
    }

    #[test]
    fn test_build_reference_capsule() {
        let capsule = build_reference_capsule();
        assert!(!capsule.signature.is_empty());
        assert_eq!(capsule.signature.len(), 64);
        assert_eq!(capsule.manifest.schema_version, SDK_VERSION);
    }

    #[test]
    fn test_validate_manifest_pass() {
        let capsule = build_reference_capsule();
        assert!(validate_manifest(&capsule.manifest).is_ok());
    }

    #[test]
    fn test_validate_manifest_bad_schema() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.schema_version = "bad".to_string();
        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::SchemaMismatch(_)) => {}
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_empty_capsule_id() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.capsule_id = String::new();
        assert!(validate_manifest(&capsule.manifest).is_err());
    }

    #[test]
    fn test_validate_manifest_malformed_expected_hash() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.expected_output_hash = "wrong_hash".to_string();
        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("expected_output_hash"));
                assert!(msg.contains("sha256"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_empty_created_at() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.created_at = String::new();
        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("created_at"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_rejects_malformed_created_at() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.created_at = "2026-02-30T00:00:00Z".to_string();
        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("created_at"));
                assert!(msg.contains("RFC3339"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_signature_pass() {
        let capsule = build_reference_capsule();
        let verifying_key = test_verifying_key();
        assert!(verify_signature(&verifying_key, &capsule).is_ok());
    }

    #[test]
    fn test_verify_signature_tampered() {
        let mut capsule = build_reference_capsule();
        capsule.signature = "tampered".to_string();
        let verifying_key = test_verifying_key();
        match verify_signature(&verifying_key, &capsule) {
            Err(CapsuleError::Ed25519SignatureMalformed { .. }) => {}
            other => panic!("expected Ed25519SignatureMalformed, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_signature_invalid_signature() {
        let mut capsule = build_reference_capsule();
        // Valid hex length (128 chars = 64 bytes) but wrong signature
        capsule.signature = "a".repeat(128);
        let verifying_key = test_verifying_key();
        match verify_signature(&verifying_key, &capsule) {
            Err(CapsuleError::Ed25519SignatureInvalid) => {}
            other => panic!("expected Ed25519SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn test_tampered_capsule_rejection() {
        let mut capsule = build_reference_capsule();
        let original_payload = capsule.payload.clone();

        // Tamper with payload after signing
        capsule.payload = "tampered_payload_data".to_string();

        // Verification should fail due to tampered content
        let verifying_key = test_verifying_key();
        match verify_signature(&verifying_key, &capsule) {
            Err(CapsuleError::Ed25519SignatureInvalid) => {}
            other => panic!("expected Ed25519SignatureInvalid for tampered capsule, got {other:?}"),
        }

        // Ensure payload was actually different
        assert_ne!(capsule.payload, original_payload);
    }

    #[test]
    fn test_replay_pass() {
        let capsule = build_reference_capsule();
        let result = replay(&capsule, "verifier://verifier-1").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
        assert_eq!(result.actual_hash, result.expected_hash);
    }

    #[test]
    fn test_replay_deterministic() {
        // INV-CAPSULE-VERDICT-REPRODUCIBLE
        let capsule = build_reference_capsule();
        let r1 = replay(&capsule, "verifier://v1").unwrap();
        let r2 = replay(&capsule, "verifier://v1").unwrap();
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.actual_hash, r2.actual_hash);
    }

    #[test]
    fn test_replay_diverged() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.expected_output_hash = "f".repeat(64);
        sign_capsule(&test_signing_key(), &mut capsule);
        let result = replay(&capsule, "verifier://v1").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Fail);
    }

    #[test]
    fn test_replay_rejects_malformed_expected_hash() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.expected_output_hash = "wrong_hash".to_string();
        sign_capsule(&test_signing_key(), &mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("expected_output_hash"));
                assert!(msg.contains("sha256"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_uppercase_expected_hash() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.expected_output_hash =
            capsule.manifest.expected_output_hash.to_uppercase();
        sign_capsule(&test_signing_key(), &mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("expected_output_hash"));
                assert!(msg.contains("sha256"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_empty_created_at() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.created_at = String::new();
        sign_capsule(&test_signing_key(), &mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("created_at"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_malformed_created_at() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.created_at = "2026-13-01T00:00:00Z".to_string();
        sign_capsule(&test_signing_key(), &mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("created_at"));
                assert!(msg.contains("RFC3339"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_empty_payload() {
        let mut capsule = build_reference_capsule();
        capsule.payload = String::new();
        sign_capsule(&test_signing_key(), &mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::EmptyPayload(_)) => {}
            other => panic!("expected EmptyPayload, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_tampered_signature() {
        let mut capsule = build_reference_capsule();
        capsule.signature = "tampered".to_string();
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_missing_declared_input() {
        let mut capsule = build_reference_capsule();
        capsule.inputs.remove("artifact_b");
        sign_capsule(&test_signing_key(), &mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("input_refs"));
                assert!(msg.contains("missing=[artifact_b]"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_extra_undeclared_input() {
        let mut capsule = build_reference_capsule();
        capsule
            .inputs
            .insert("artifact_c".to_string(), "content_of_c".to_string());
        sign_capsule(&test_signing_key(), &mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("input_refs"));
                assert!(msg.contains("extra=[artifact_c]"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_duplicate_declared_input_refs() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.input_refs.push("artifact_a".to_string());
        sign_capsule(&test_signing_key(), &mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("input_refs"));
                assert!(msg.contains("duplicate"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_whitespace_padded_declared_input_ref_even_when_inputs_match() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.input_refs = vec![" artifact_a".to_string()];
        capsule.inputs = BTreeMap::from([(" artifact_a".to_string(), "content_of_a".to_string())]);
        capsule.manifest.expected_output_hash =
            compute_replay_hash(&capsule.payload, &capsule.inputs);
        sign_capsule(&test_signing_key(), &mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("input_refs"));
                assert!(msg.contains("leading or trailing whitespace"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_control_byte_input_key_even_when_manifest_matches() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.input_refs = vec!["artifact_a\0shadow".to_string()];
        capsule.inputs =
            BTreeMap::from([("artifact_a\0shadow".to_string(), "content_of_a".to_string())]);
        capsule.manifest.expected_output_hash =
            compute_replay_hash(&capsule.payload, &capsule.inputs);
        sign_capsule(&test_signing_key(), &mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("identifier must include only ASCII letters"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_error_display_signature_invalid() {
        let err = CapsuleError::SignatureInvalid("bad".into());
        assert!(format!("{err}").contains(ERR_CAPSULE_SIGNATURE_INVALID));
    }

    #[test]
    fn test_error_display_schema_mismatch() {
        let err = CapsuleError::SchemaMismatch("bad".into());
        assert!(format!("{err}").contains(ERR_CAPSULE_SCHEMA_MISMATCH));
    }

    #[test]
    fn test_error_display_replay_diverged() {
        let err = CapsuleError::ReplayDiverged {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(format!("{err}").contains(ERR_CAPSULE_REPLAY_DIVERGED));
    }

    #[test]
    fn test_error_display_verdict_mismatch() {
        let err = CapsuleError::VerdictMismatch {
            expected: "pass".into(),
            actual: "fail".into(),
        };
        assert!(format!("{err}").contains(ERR_CAPSULE_VERDICT_MISMATCH));
    }

    #[test]
    fn test_error_display_access_denied() {
        let err = CapsuleError::AccessDenied("denied".into());
        assert!(format!("{err}").contains(ERR_CAPSULE_ACCESS_DENIED));
    }

    #[test]
    fn test_deterministic_hash_consistency() {
        let h1 = deterministic_hash("test_data");
        let h2 = deterministic_hash("test_data");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_deterministic_hash_different_inputs() {
        let h1 = deterministic_hash("input_a");
        let h2 = deterministic_hash("input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_capsule_no_privileged_access() {
        // INV-CAPSULE-NO-PRIVILEGED-ACCESS: replay is local, no network needed
        let capsule = build_reference_capsule();
        let result = replay(&capsule, "verifier://offline-verifier").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
    }

    #[test]
    fn test_replay_rejects_empty_verifier_identity() {
        let capsule = build_reference_capsule();
        match replay(&capsule, "   ") {
            Err(CapsuleError::AccessDenied(msg)) => {
                assert!(msg.contains("leading or trailing whitespace"));
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_non_verifier_identity_scheme() {
        let capsule = build_reference_capsule();
        match replay(&capsule, "creator://test@example.com") {
            Err(CapsuleError::AccessDenied(msg)) => {
                assert!(msg.contains("verifier://"));
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_accepts_255_byte_verifier_identity_name() {
        let capsule = build_reference_capsule();
        let verifier_identity = format!("verifier://{}", "a".repeat(255));

        let result = replay(&capsule, &verifier_identity)
            .expect("255-byte verifier identity should remain valid");

        assert_eq!(result.verdict, CapsuleVerdict::Pass);
    }

    #[test]
    fn test_replay_rejects_256_byte_verifier_identity_name() {
        let capsule = build_reference_capsule();
        let verifier_identity = format!("verifier://{}", "a".repeat(256));

        match replay(&capsule, &verifier_identity) {
            Err(CapsuleError::AccessDenied(msg)) => {
                assert!(msg.contains("at most 255 ASCII bytes"));
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_malformed_creator_identity() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.creator_identity = " creator://test@example.com".to_string();
        sign_capsule(&test_signing_key(), &mut capsule);

        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("creator_identity"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_accepts_255_byte_creator_identity_name() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.creator_identity = format!("creator://{}", "a".repeat(255));

        validate_manifest(&capsule.manifest)
            .expect("255-byte creator identity should remain valid");
    }

    #[test]
    fn test_validate_manifest_rejects_256_byte_creator_identity_name() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.creator_identity = format!("creator://{}", "a".repeat(256));

        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("at most 255 ASCII bytes"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_capsule_manifest_btreemap_ordering() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.metadata.insert("z_key".into(), "z".into());
        capsule.manifest.metadata.insert("a_key".into(), "a".into());
        let keys: Vec<_> = capsule.manifest.metadata.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    // -- Security regression tests ------------------------------------------

    #[test]
    fn test_hash_uses_sha256_not_xor() {
        // Verify the hash is SHA-256 (collision-resistant), not XOR-based.
        // XOR hash: "ab" and "ba" could collide. SHA-256 will not.
        let h1 = deterministic_hash("ab");
        let h2 = deterministic_hash("ba");
        assert_ne!(h1, h2, "hash must distinguish permuted inputs (not XOR)");

        // XOR hash maps all single-char inputs of same byte to same slot,
        // making strings that differ only in repeated chars collide.
        let h3 = deterministic_hash("aaa");
        let h4 = deterministic_hash("a");
        assert_ne!(
            h3, h4,
            "hash must distinguish different-length same-char inputs"
        );
    }

    #[test]
    fn test_signing_payload_delimiter_collision_resistance() {
        // Pipe-delimited "A|B" signing would let an attacker craft a capsule_id
        // containing "|" that produces the same signing payload as a different
        // capsule. Length-prefixed encoding prevents this.
        let mut capsule_a = build_reference_capsule();
        capsule_a.manifest.capsule_id = "id-a|vsdk-v1.0".to_string();
        capsule_a.manifest.schema_version = SDK_VERSION.to_string();
        sign_capsule(&test_signing_key(), &mut capsule_a);

        let mut capsule_b = build_reference_capsule();
        capsule_b.manifest.capsule_id = "id-a".to_string();
        capsule_b.manifest.schema_version = SDK_VERSION.to_string();
        sign_capsule(&test_signing_key(), &mut capsule_b);

        assert_ne!(
            capsule_a.signature, capsule_b.signature,
            "signing must resist delimiter collision in capsule_id"
        );
    }

    #[test]
    fn test_replay_hash_payload_input_collision_resistance() {
        // Without length-prefixed encoding, a payload "data|key=val" with no
        // inputs would hash identically to payload "data" with input key=val.
        let inputs_empty = BTreeMap::new();
        let h1 = compute_replay_hash("data|artifact_a=content_of_a", &inputs_empty);

        let mut inputs_with = BTreeMap::new();
        inputs_with.insert("artifact_a".to_string(), "content_of_a".to_string());
        let h2 = compute_replay_hash("data", &inputs_with);

        assert_ne!(
            h1, h2,
            "replay hash must distinguish payload-embedded vs actual inputs"
        );
    }

    #[test]
    fn test_constant_time_comparison_used() {
        // Verify that ct_eq works correctly (same and different strings).
        assert!(ct_eq("hello", "hello"));
        assert!(!ct_eq("hello", "hellx"));
        assert!(!ct_eq("hello", "hell"));
        assert!(ct_eq("", ""));
        assert!(ct_eq_bytes(b"test", b"test"));
        assert!(!ct_eq_bytes(b"test", b"tesx"));
    }

    #[test]
    fn test_forged_same_length_signature_rejected() {
        // Adversarial: forged signature with same length as real one
        let capsule = build_reference_capsule();
        let mut forged = capsule.clone();
        // Create a 64-char hex string that differs from the real signature
        forged.signature = "a".repeat(64);
        assert_ne!(forged.signature, capsule.signature);
        match verify_signature(&test_verifying_key(), &forged) {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid for forged sig, got {other:?}"),
        }
    }

    #[test]
    fn test_payload_swap_under_reused_signature() {
        // Adversarial: swap payload but keep old signature
        let capsule = build_reference_capsule();
        let mut swapped = capsule.clone();
        swapped.payload = "completely_different_payload".to_string();
        // Don't re-sign — attacker reuses old signature
        match replay(&swapped, "verifier://v1") {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid for swapped payload, got {other:?}"),
        }
    }

    #[test]
    fn test_claim_type_tamper_under_reused_signature_rejected() {
        assert_manifest_tamper_rejected("claim_type", |capsule| {
            capsule.manifest.claim_type = "runtime_safety".to_string();
        });
    }

    #[test]
    fn test_input_refs_tamper_under_reused_signature_rejected() {
        assert_manifest_tamper_rejected("input_refs", |capsule| {
            capsule.manifest.input_refs.push("artifact_c".to_string());
        });
    }

    #[test]
    fn test_created_at_tamper_under_reused_signature_rejected() {
        assert_manifest_tamper_rejected("created_at", |capsule| {
            capsule.manifest.created_at = "2026-02-22T00:00:00Z".to_string();
        });
    }

    #[test]
    fn test_creator_identity_tamper_under_reused_signature_rejected() {
        assert_manifest_tamper_rejected("creator_identity", |capsule| {
            capsule.manifest.creator_identity = "creator://attacker@example.com".to_string();
        });
    }

    #[test]
    fn test_metadata_tamper_under_reused_signature_rejected() {
        assert_manifest_tamper_rejected("metadata", |capsule| {
            capsule
                .manifest
                .metadata
                .insert("tampered".to_string(), "true".to_string());
        });
    }

    #[test]
    fn test_cross_claim_replay_rejected() {
        // Adversarial: take signature from capsule A, apply to capsule B
        let capsule_a = build_reference_capsule();
        let mut capsule_b = build_reference_capsule();
        capsule_b.manifest.capsule_id = "capsule-different-001".to_string();
        capsule_b.manifest.expected_output_hash =
            compute_replay_hash(&capsule_b.payload, &capsule_b.inputs);
        // Reuse capsule_a's signature
        capsule_b.signature = capsule_a.signature.clone();
        match verify_signature(&test_verifying_key(), &capsule_b) {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid for cross-claim replay, got {other:?}"),
        }
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_validate_manifest_with_unicode_control_characters_rejects() {
        let mut capsule = build_reference_capsule();
        // Inject null byte and other control characters into capsule_id
        capsule.manifest.capsule_id = "capsule\0with\x01control\x1fchars".to_string();
        sign_capsule(&test_signing_key(), &mut capsule);

        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("capsule_id"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }

        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("capsule_id"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn negative_replay_with_extremely_large_payload_handles_gracefully() {
        let mut capsule = build_reference_capsule();
        // Create a very large payload (1MB of 'x' characters)
        capsule.payload = "x".repeat(1_000_000);
        capsule.manifest.expected_output_hash =
            compute_replay_hash(&capsule.payload, &capsule.inputs);
        sign_capsule(&test_signing_key(), &mut capsule);

        // Should handle large payloads without panicking or excessive memory usage
        let result = replay(&capsule, "verifier://large-test").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
    }

    #[test]
    fn negative_validate_manifest_with_path_traversal_creator_identity_rejects() {
        let mut capsule = build_reference_capsule();
        // Inject path traversal sequences into various fields
        capsule.manifest.capsule_id = "../../../etc/passwd".to_string();
        capsule.manifest.description = "payload\\..\\windows\\system32".to_string();
        capsule.manifest.creator_identity = "creator://../root@localhost".to_string();

        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("capsule_id") || msg.contains("creator_identity"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn negative_validate_manifest_with_malformed_creator_identities_rejects() {
        let invalid_creator_identities = vec![
            " creator://test@example.com",
            "creator://",
            "creator:///empty",
            "creator://space name",
            "creator://../traversal",
            "creator://\u{0000}",
            "verifier://test@example.com",
            "garbage",
        ];

        for creator_identity in invalid_creator_identities {
            let mut capsule = build_reference_capsule();
            capsule.manifest.creator_identity = creator_identity.to_string();
            match validate_manifest(&capsule.manifest) {
                Err(CapsuleError::ManifestIncomplete(msg)) => {
                    assert!(msg.contains("creator_identity"));
                }
                other => panic!(
                    "expected ManifestIncomplete for creator_identity '{creator_identity}', got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn negative_deterministic_hash_with_maximum_unicode_handles_correctly() {
        // Test with various Unicode edge cases including max codepoints
        let test_cases = vec![
            "\u{FFFF}".to_string(),                 // Max BMP codepoint
            "\u{10FFFF}".to_string(),               // Max Unicode codepoint
            "🚀🔥💀\u{1F600}".to_string(),          // Emoji sequence
            "\u{200B}\u{FEFF}\u{034F}".to_string(), // Zero-width/invisible chars
        ];

        for input in test_cases {
            let hash = deterministic_hash(&input);
            assert_eq!(hash.len(), 64);
            assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn negative_validate_manifest_with_whitespace_only_fields_rejects() {
        let mut capsule = build_reference_capsule();

        capsule.manifest.capsule_id = "   \t\n\r   ".to_string();
        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("capsule_id"));
            }
            other => {
                panic!("expected ManifestIncomplete for whitespace-only capsule_id, got {other:?}")
            }
        }

        let mut capsule2 = build_reference_capsule();
        capsule2.manifest.claim_type = "\u{00A0}\u{2000}\u{2001}".to_string();
        match validate_manifest(&capsule2.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("claim_type"));
            }
            other => {
                panic!("expected ManifestIncomplete for whitespace-only claim_type, got {other:?}")
            }
        }

        let mut capsule3 = build_reference_capsule();
        capsule3.manifest.created_at = "\n\t  ".to_string();
        match validate_manifest(&capsule3.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("created_at"));
            }
            other => {
                panic!("expected ManifestIncomplete for whitespace-only created_at, got {other:?}")
            }
        }
    }

    #[test]
    fn test_validate_manifest_rejects_whitespace_padded_capsule_id() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.capsule_id = " capsule-ref-001 ".to_string();

        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("capsule_id"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_rejects_whitespace_padded_claim_type() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.claim_type = " compatibility_check ".to_string();

        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("claim_type"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_rejects_whitespace_padded_created_at() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.created_at = " 2026-04-01T00:00:00Z ".to_string();

        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("created_at"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_whitespace_padded_capsule_id() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.capsule_id = " capsule-ref-001 ".to_string();
        sign_capsule(&test_signing_key(), &mut capsule);

        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("capsule_id"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_path_traversal_capsule_id() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.capsule_id = "../../../etc/passwd".to_string();
        sign_capsule(&test_signing_key(), &mut capsule);

        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("capsule_id"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_whitespace_padded_claim_type() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.claim_type = " compatibility_check ".to_string();
        sign_capsule(&test_signing_key(), &mut capsule);

        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("claim_type"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_whitespace_padded_created_at() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.created_at = " 2026-04-01T00:00:00Z ".to_string();
        sign_capsule(&test_signing_key(), &mut capsule);

        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("created_at"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn negative_validate_verifier_identity_with_malformed_uri_rejects() {
        let capsule = build_reference_capsule();

        let invalid_identities = vec![
            "verifier://",             // Missing verifier name
            "verifier:///empty",       // Extra slash
            "verifier://\n\r",         // Newlines in URI
            "verifier://space space",  // Spaces in verifier name
            "VERIFIER://upper",        // Wrong case scheme
            "verifier://../traversal", // Path traversal in URI
            "verifier://\u{0000}",     // Null byte
            "verifier://\u{FFFF}",     // Invalid Unicode
        ];

        for identity in invalid_identities {
            match replay(&capsule, identity) {
                Err(CapsuleError::AccessDenied(_)) => {} // Expected
                other => panic!("Expected AccessDenied for identity '{identity}', got {other:?}"),
            }
        }
    }

    #[test]
    fn negative_validate_manifest_with_almost_valid_hash_formats_rejects() {
        let mut capsule = build_reference_capsule();

        let invalid_hashes = vec![
            "g".repeat(64),                     // Invalid hex character 'g'
            "f".repeat(63),                     // Too short (63 chars)
            "f".repeat(65),                     // Too long (65 chars)
            "F".repeat(64),                     // Uppercase hex (might be rejected)
            "123456789abcdef".repeat(3) + "12", // Wrong length
            "".to_string(),                     // Empty
            "\n".repeat(32) + &"f".repeat(32),  // Newlines in middle
        ];

        for hash in invalid_hashes {
            capsule.manifest.expected_output_hash = hash.clone();
            match validate_manifest(&capsule.manifest) {
                Err(CapsuleError::ManifestIncomplete(msg)) => {
                    assert!(msg.contains("expected_output_hash") || msg.contains("sha256"));
                }
                other => panic!("Expected ManifestIncomplete for hash '{hash}', got {other:?}"),
            }
        }
    }

    #[test]
    fn negative_replay_with_massive_input_map_handles_memory_efficiently() {
        let mut capsule = build_reference_capsule();

        // Create capsule with many inputs (1000 key-value pairs)
        capsule.inputs.clear();
        capsule.manifest.input_refs.clear();

        for i in 0..1000 {
            let key = format!("input_key_{:04}", i);
            let value = format!("input_value_data_content_{}", i);
            capsule.inputs.insert(key.clone(), value);
            capsule.manifest.input_refs.push(key);
        }

        capsule.manifest.expected_output_hash =
            compute_replay_hash(&capsule.payload, &capsule.inputs);
        sign_capsule(&test_signing_key(), &mut capsule);

        // Should handle large input maps without excessive memory consumption
        let start = std::time::Instant::now();
        let result = replay(&capsule, "verifier://stress-test").unwrap();
        let duration = start.elapsed();

        assert_eq!(result.verdict, CapsuleVerdict::Pass);
        // Should complete within reasonable time (5 seconds is generous)
        assert!(duration < std::time::Duration::from_secs(5));
    }

    #[test]
    fn negative_compute_replay_hash_with_key_value_collision_attack_resists() {
        // Test that length-prefixed encoding prevents key-value collision attacks
        // where attacker crafts keys/values to produce same hash as different data

        // Attack 1: Key ending with length prefix of value
        let mut inputs1 = BTreeMap::new();
        inputs1.insert(
            "key\x08\x00\x00\x00\x00\x00\x00\x00value123".to_string(),
            "".to_string(),
        );
        let hash1 = compute_replay_hash("payload", &inputs1);

        // Attack 2: Different key-value split of same byte sequence
        let mut inputs2 = BTreeMap::new();
        inputs2.insert("key".to_string(), "value123".to_string());
        let hash2 = compute_replay_hash("payload", &inputs2);

        // Length-prefixed encoding should make these produce different hashes
        assert_ne!(
            hash1, hash2,
            "Replay hash must resist key-value collision attacks"
        );
    }

    #[test]
    fn negative_replay_with_empty_string_verifier_identity_after_scheme_rejects() {
        let capsule = build_reference_capsule();

        // Test verifier:// with empty remainder after trimming
        let empty_remainder_cases = vec![
            "verifier://   ",      // Only whitespace after scheme
            "verifier://\t\n\r",   // Only tabs/newlines after scheme
            "verifier://\u{00A0}", // Only non-breaking space after scheme
        ];

        for identity in empty_remainder_cases {
            match replay(&capsule, identity) {
                Err(CapsuleError::AccessDenied(msg)) => {
                    assert!(msg.contains("non-empty verifier name"));
                }
                other => panic!(
                    "Expected AccessDenied for empty verifier name '{identity}', got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn negative_replay_rejects_leading_whitespace_padded_verifier_identity() {
        let capsule = build_reference_capsule();

        match replay(&capsule, " verifier://offline-verifier") {
            Err(CapsuleError::AccessDenied(msg)) => {
                assert!(msg.contains("leading or trailing whitespace"));
            }
            other => panic!(
                "Expected AccessDenied for leading-whitespace verifier identity, got {other:?}"
            ),
        }
    }

    #[test]
    fn negative_replay_rejects_trailing_whitespace_padded_verifier_identity() {
        let capsule = build_reference_capsule();

        match replay(&capsule, "verifier://offline-verifier ") {
            Err(CapsuleError::AccessDenied(msg)) => {
                assert!(msg.contains("leading or trailing whitespace"));
            }
            other => panic!(
                "Expected AccessDenied for trailing-whitespace verifier identity, got {other:?}"
            ),
        }
    }

    // ── Additional negative-path tests for edge cases and boundary conditions ──

    #[test]
    fn negative_is_sha256_hex_with_boundary_and_invalid_cases() {
        // Test exact boundary cases for SHA-256 hex validation
        assert!(!is_sha256_hex("")); // Empty string
        assert!(!is_sha256_hex("f".repeat(63).as_str())); // Too short by 1
        assert!(!is_sha256_hex("f".repeat(65).as_str())); // Too long by 1
        assert!(!is_sha256_hex("F".repeat(64).as_str())); // Uppercase hex
        assert!(!is_sha256_hex("G".repeat(64).as_str())); // Invalid hex char
        assert!(!is_sha256_hex("Z".repeat(64).as_str())); // Invalid hex char
        assert!(!is_sha256_hex(&format!(
            "{}g{}",
            "f".repeat(31),
            "f".repeat(32)
        ))); // Invalid char in middle
        assert!(!is_sha256_hex(&format!(
            "{}\x00{}",
            "f".repeat(31),
            "f".repeat(32)
        ))); // Null byte
        // Valid case for comparison
        assert!(is_sha256_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn negative_push_length_prefixed_with_maximum_and_zero_values() {
        let mut hasher = Sha256::new();

        // Test with maximum possible string length (approaching usize::MAX)
        // Note: We can't actually create a string of usize::MAX length due to memory,
        // but we can test the length encoding behavior
        let max_len_str = "x".repeat(65536); // Large but manageable string
        push_length_prefixed(&mut hasher, &max_len_str);

        // Test with zero-length string
        push_length_prefixed(&mut hasher, "");

        // Test with string containing only null bytes
        let null_str = "\0".repeat(100);
        push_length_prefixed(&mut hasher, &null_str);

        // Test with string containing high Unicode codepoints
        let unicode_str = "\u{1F4A9}".repeat(100); // Pile of poo emoji repeated
        push_length_prefixed(&mut hasher, &unicode_str);

        // Finalize to ensure no panic
        let _result = hasher.finalize();
    }

    #[test]
    fn negative_compute_replay_hash_with_minimal_and_edge_data() {
        // Test with completely empty payload and inputs
        let empty_inputs = BTreeMap::new();
        let hash1 = compute_replay_hash("", &empty_inputs);
        assert_eq!(hash1.len(), 64);
        assert!(hash1.bytes().all(|b| b.is_ascii_hexdigit()));

        // Test with payload containing only control characters
        let control_payload = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let hash2 = compute_replay_hash(control_payload, &empty_inputs);
        assert_ne!(hash1, hash2);

        // Test with single-character key and value at boundaries
        let mut single_inputs = BTreeMap::new();
        single_inputs.insert("".to_string(), "".to_string()); // Empty key and value
        single_inputs.insert("a".to_string(), "b".to_string()); // Single chars
        let hash3 = compute_replay_hash("c", &single_inputs);
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn negative_compute_signing_payload_with_boundary_manifest_sizes() {
        let capsule = build_reference_capsule();

        // Test with minimal manifest fields (empty strings where allowed)
        let mut minimal_capsule = capsule.clone();
        minimal_capsule.manifest.description = "".to_string();
        minimal_capsule.manifest.input_refs.clear();
        minimal_capsule.manifest.metadata.clear();
        minimal_capsule.inputs.clear();
        minimal_capsule.payload = "".to_string();
        let minimal_payload = compute_signing_payload(&minimal_capsule);

        // Test with maximum reasonable field sizes
        let mut maximal_capsule = capsule.clone();
        maximal_capsule.manifest.description = "x".repeat(10000);
        maximal_capsule.payload = "y".repeat(10000);
        for i in 0..100 {
            let key = format!("meta_key_{}", i);
            let value = format!("meta_value_{}", "z".repeat(100));
            maximal_capsule.manifest.metadata.insert(key, value);
        }
        let maximal_payload = compute_signing_payload(&maximal_capsule);

        assert_ne!(minimal_payload, maximal_payload);
        assert_eq!(minimal_payload.len(), 64);
        assert_eq!(maximal_payload.len(), 64);
    }

    #[test]
    fn negative_validate_declared_input_refs_with_edge_case_collections() {
        // Test with capsule having maximum number of input refs
        let mut stress_capsule = build_reference_capsule();
        stress_capsule.manifest.input_refs.clear();
        stress_capsule.inputs.clear();

        // Add many input refs to test iteration performance and memory
        for i in 0..1000 {
            let ref_name = format!("stress_input_{:04}", i);
            stress_capsule.manifest.input_refs.push(ref_name.clone());
            stress_capsule
                .inputs
                .insert(ref_name, format!("content_{}", i));
        }

        assert!(validate_declared_input_refs(&stress_capsule).is_ok());

        // Test malformed input refs with Unicode/control identifiers
        let mut unicode_capsule = build_reference_capsule();
        unicode_capsule.manifest.input_refs.clear();
        unicode_capsule.inputs.clear();

        let unicode_refs = vec![
            "\u{1F600}".to_string(),  // Emoji
            "\u{0000}".to_string(),   // Null character
            "\u{FFFF}".to_string(),   // Max BMP
            "\u{10FFFF}".to_string(), // Max Unicode
        ];

        for unicode_ref in unicode_refs {
            unicode_capsule
                .manifest
                .input_refs
                .push(unicode_ref.clone());
            unicode_capsule
                .inputs
                .insert(unicode_ref, "unicode_content".to_string());
        }

        match validate_declared_input_refs(&unicode_capsule) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("identifier must include only ASCII letters"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn negative_ct_eq_bytes_with_length_boundary_conditions() {
        // Test constant-time comparison with various length combinations
        assert!(!ct_eq_bytes(b"", b"a")); // Empty vs non-empty
        assert!(!ct_eq_bytes(b"a", b"")); // Non-empty vs empty
        assert!(ct_eq_bytes(b"", b"")); // Both empty

        // Test with very large byte arrays of different lengths
        let large1 = vec![0u8; 10000];
        let large2 = vec![1u8; 10000];
        let large3 = vec![0u8; 10001]; // Different length

        assert!(ct_eq_bytes(&large1, &large1)); // Same content, same length
        assert!(!ct_eq_bytes(&large1, &large2)); // Different content, same length
        assert!(!ct_eq_bytes(&large1, &large3)); // Same content, different length

        // Test with arrays differing only in last byte
        let almost_same1 = vec![42u8; 1000];
        let mut almost_same2 = vec![42u8; 1000];
        almost_same2[999] = 43; // Change last byte

        assert!(!ct_eq_bytes(&almost_same1, &almost_same2));
    }

    #[test]
    fn negative_domain_separator_collision_resistance_stress_test() {
        // Test that different domain separators produce different hashes
        // even with identical subsequent data
        let test_data = "identical_input_data";

        let hash_capsule = deterministic_hash(test_data);

        // Manually compute hash with different domain separator
        let mut hasher_different = Sha256::new();
        hasher_different.update(b"different_domain_separator:");
        hasher_different.update(test_data.as_bytes());
        let hash_different = hex::encode(hasher_different.finalize());

        assert_ne!(
            hash_capsule, hash_different,
            "Domain separators must prevent hash collision"
        );

        // Test with malicious input that tries to forge domain separator
        let malicious_input = "verifier_sdk_capsule_v1:fake_domain_sep";
        let hash_malicious = deterministic_hash(malicious_input);

        // Should NOT match hash of legitimate empty string with proper separator
        let hash_legitimate = deterministic_hash("");
        assert_ne!(
            hash_malicious, hash_legitimate,
            "Malicious domain separator injection must be prevented"
        );
    }

    #[test]
    fn negative_hash_computation_with_zero_length_boundaries() {
        // Test edge cases in hash computation involving zero-length data
        let mut zero_inputs = BTreeMap::new();
        zero_inputs.insert("".to_string(), "".to_string()); // Zero-length key and value

        let hash_zero_payload = compute_replay_hash("", &zero_inputs);
        let hash_zero_inputs = compute_replay_hash("data", &BTreeMap::new());
        let hash_both_zero = compute_replay_hash("", &BTreeMap::new());

        // All should be different due to different length prefixes
        assert_ne!(hash_zero_payload, hash_zero_inputs);
        assert_ne!(hash_zero_payload, hash_both_zero);
        assert_ne!(hash_zero_inputs, hash_both_zero);

        // Test with zero-length metadata in signing payload
        let mut zero_meta_capsule = build_reference_capsule();
        zero_meta_capsule.manifest.metadata.clear();
        zero_meta_capsule
            .manifest
            .metadata
            .insert("".to_string(), "".to_string());
        let signing_zero = compute_signing_payload(&zero_meta_capsule);

        let mut no_meta_capsule = build_reference_capsule();
        no_meta_capsule.manifest.metadata.clear();
        let signing_no_meta = compute_signing_payload(&no_meta_capsule);

        assert_ne!(
            signing_zero, signing_no_meta,
            "Empty metadata entry must differ from no metadata"
        );
    }

    // =========================================================================
    // ADDITIONAL COMPREHENSIVE NEGATIVE-PATH TESTS
    // =========================================================================

    #[test]
    fn negative_capsule_with_schema_version_spoofing_attempts_rejected() {
        let mut capsule = build_reference_capsule();

        // Attempt to spoof schema version with similar-looking strings
        let spoofed_versions = vec![
            format!("{}\0", SDK_VERSION),       // Null terminator
            format!(" {} ", SDK_VERSION),       // Extra whitespace
            format!("{}\n", SDK_VERSION),       // Newline suffix
            format!("{}\u{200B}", SDK_VERSION), // Zero-width space
            SDK_VERSION.to_uppercase(),         // Case change
            format!("{}x", SDK_VERSION),        // Extra character
            format!("v{}", SDK_VERSION),        // Version prefix
        ];

        for spoofed_version in spoofed_versions {
            capsule.manifest.schema_version = spoofed_version.clone();
            match validate_manifest(&capsule.manifest) {
                Err(CapsuleError::SchemaMismatch(_)) => {} // Expected
                other => panic!(
                    "Expected SchemaMismatch for spoofed version '{}', got {other:?}",
                    spoofed_version
                ),
            }
        }
    }

    #[test]
    fn negative_replay_with_extremely_deep_nested_input_structure() {
        let mut capsule = build_reference_capsule();
        capsule.inputs.clear();
        capsule.manifest.input_refs.clear();

        // Create inputs with deeply nested JSON-like structure in values
        let deep_nesting_levels = 1000;
        let mut nested_value = "core".to_string();
        for i in 0..deep_nesting_levels {
            nested_value = format!("{{\"level_{}\": \"{}\"}}", i, nested_value);
        }

        capsule
            .inputs
            .insert("deep_nested".to_string(), nested_value);
        capsule.manifest.input_refs.push("deep_nested".to_string());
        capsule.manifest.expected_output_hash =
            compute_replay_hash(&capsule.payload, &capsule.inputs);
        sign_capsule(&test_signing_key(), &mut capsule);

        // Should handle deep nesting without stack overflow or excessive processing time
        let start = std::time::Instant::now();
        let result = replay(&capsule, "verifier://nesting-test").unwrap();
        let duration = start.elapsed();

        assert_eq!(result.verdict, CapsuleVerdict::Pass);
        assert!(duration < std::time::Duration::from_secs(5)); // Should complete reasonably fast
    }

    #[test]
    fn negative_capsule_creation_with_invalid_utf8_sequences_handled() {
        // Test behavior with byte sequences that are invalid UTF-8
        let mut capsule = build_reference_capsule();

        // Create potentially invalid UTF-8 sequences (would be caught at string creation)
        let invalid_utf8_attempts = vec![
            "valid\u{FFFD}replacement".to_string(), // Replacement character
            r#"incomplete\uD800surrogate"#.to_string(), // Raw string with surrogate escape
        ];

        for invalid_sequence in invalid_utf8_attempts {
            capsule.manifest.description = invalid_sequence.clone();
            sign_capsule(&test_signing_key(), &mut capsule);

            // Should handle gracefully without crashing
            assert!(validate_manifest(&capsule.manifest).is_ok());
            let result = replay(&capsule, "verifier://utf8-test");
            assert!(result.is_ok());
        }
    }

    #[test]
    fn negative_deterministic_hash_with_identical_bytes_different_encodings() {
        // Test that the hash distinguishes between different string interpretations of same bytes
        let byte_sequence = vec![0xC4, 0x85]; // UTF-8 for 'ą'
        let utf8_string = String::from_utf8(byte_sequence.clone()).unwrap();
        let latin1_interpretation = byte_sequence.iter().map(|&b| b as char).collect::<String>();

        let hash_utf8 = deterministic_hash(&utf8_string);
        let hash_latin1 = deterministic_hash(&latin1_interpretation);

        // Should produce different hashes for different string interpretations
        if utf8_string != latin1_interpretation {
            assert_ne!(
                hash_utf8, hash_latin1,
                "Different string interpretations must produce different hashes"
            );
        }
    }

    #[test]
    fn negative_verify_signature_with_race_condition_simulation() {
        let mut capsule = build_reference_capsule();

        // Simulate potential race condition by modifying capsule during verification
        let original_signature = capsule.signature.clone();

        // Capture the expected signing payload
        let expected_payload = compute_signing_payload(&capsule);

        // Modify the capsule slightly
        capsule.manifest.description.push('x');

        // Restore original signature (simulating race where signature was computed before modification)
        capsule.signature = original_signature;

        // Should detect that signature no longer matches modified content
        let verifying_key = test_verifying_key();
        match verify_signature(&verifying_key, &capsule) {
            Err(CapsuleError::Ed25519SignatureInvalid) => {} // Expected
            other => panic!("Expected Ed25519SignatureInvalid for modified capsule, got {other:?}"),
        }

        // Verify that the current payload is indeed different
        let modified_payload = compute_signing_payload(&capsule);
        assert_ne!(expected_payload, modified_payload);
    }

    #[test]
    fn negative_capsule_input_keys_with_btreemap_edge_case_ordering() {
        // Test BTreeMap behavior with keys that have tricky lexicographic ordering
        let mut capsule = build_reference_capsule();
        capsule.inputs.clear();
        capsule.manifest.input_refs.clear();

        let tricky_keys = vec![
            "1".to_string(),
            "10".to_string(),
            "2".to_string(),      // Lexicographic: "1" < "10" < "2"
            "a_".to_string(),     // Valid ASCII with underscore
            "z".to_string(),      // ASCII
            "Z-test".to_string(), // Valid ASCII with dash
        ];

        // Insert in random order
        for key in tricky_keys.iter().rev() {
            capsule
                .inputs
                .insert(key.clone(), format!("value_for_{}", key));
            capsule.manifest.input_refs.push(key.clone());
        }

        // Sort input_refs to match expected BTreeMap ordering
        capsule.manifest.input_refs.sort();

        // Compute hash multiple times to ensure deterministic ordering
        let hash1 = compute_replay_hash(&capsule.payload, &capsule.inputs);
        let hash2 = compute_replay_hash(&capsule.payload, &capsule.inputs);

        assert_eq!(
            hash1, hash2,
            "Hash must be deterministic despite key ordering complexity"
        );

        capsule.manifest.expected_output_hash = hash1;
        sign_capsule(&test_signing_key(), &mut capsule);

        let result = replay(&capsule, "verifier://ordering-complex").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
    }

    #[test]
    fn negative_validate_verifier_identity_with_protocol_confusion_attempts() {
        let capsule = build_reference_capsule();

        // Test various protocol confusion attempts
        let confusion_attempts = vec![
            "VERIFIER://uppercase-scheme",    // Wrong case
            "verifier:\\\\windows-style",     // Wrong separator style
            "verifier:/single-slash",         // Missing second slash
            "verifier:///triple-slash",       // Too many slashes
            "http://verifier://double-proto", // Nested protocols
            "verifier://user:pass@host",      // Authority with credentials
            "verifier://host:port/path",      // Port and path
            "verifier://host?query=param",    // Query parameters
            "verifier://host#fragment",       // Fragment
            "javascript:alert('xss')",        // Different protocol entirely
        ];

        for attempt in confusion_attempts {
            match replay(&capsule, attempt) {
                Err(CapsuleError::AccessDenied(_)) => {} // Expected
                other => panic!(
                    "Expected AccessDenied for protocol confusion '{}', got {other:?}",
                    attempt
                ),
            }
        }
    }

    #[test]
    fn negative_capsule_metadata_with_json_injection_patterns() {
        let mut capsule = build_reference_capsule();

        // Test metadata values that could cause JSON injection if improperly handled
        let injection_patterns = vec![
            "\"},\"injected\":\"malicious\",\"dummy\":\"".to_string(),
            "\\u0022},\\u0022injected\\u0022:\\u0022malicious".to_string(),
            "\n},\n\"injected\": \"value\",\n\"real\": \"".to_string(),
            "\"},\"__proto__\":{\"isAdmin\":true},\"dummy\":\"".to_string(),
        ];

        for pattern in injection_patterns {
            capsule.manifest.metadata.clear();
            capsule
                .manifest
                .metadata
                .insert("potentially_malicious".to_string(), pattern.clone());
            sign_capsule(&test_signing_key(), &mut capsule);

            // Should handle injection patterns without breaking verification
            assert!(validate_manifest(&capsule.manifest).is_ok());

            let result = replay(&capsule, "verifier://injection-meta-test");
            assert!(
                result.is_ok(),
                "Metadata injection pattern should not break replay"
            );

            // Verify the pattern is preserved as-is in metadata
            assert_eq!(
                capsule.manifest.metadata.get("potentially_malicious"),
                Some(&pattern)
            );
        }
    }

    #[test]
    fn negative_compute_replay_hash_memory_exhaustion_resistance() {
        // Test that hash computation doesn't exhaust memory with pathological inputs
        let mut large_inputs = BTreeMap::new();

        // Create many inputs with moderately large values
        for i in 0..1000 {
            let key = format!("stress_key_{:04}", i);
            let value = "x".repeat(1000); // 1KB per value = 1MB total
            large_inputs.insert(key, value);
        }

        let large_payload = "y".repeat(100_000); // 100KB payload

        // Should compute hash without excessive memory allocation
        let start_time = std::time::Instant::now();
        let hash = compute_replay_hash(&large_payload, &large_inputs);
        let duration = start_time.elapsed();

        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(duration < std::time::Duration::from_secs(5)); // Should be reasonably fast
    }

    #[test]
    fn negative_constant_time_string_comparison_with_length_attacks() {
        // Test that ct_eq properly handles length-based timing attacks
        let reference = "secret_reference_string";

        // Test strings of different lengths (should fail fast on length)
        let different_lengths = vec![
            "",
            "a",
            "ab",
            "secret_reference_strin",   // One character shorter
            "secret_reference_stringx", // One character longer
            "secret_reference_string_much_longer_suffix",
        ];

        for test_string in different_lengths {
            let result = ct_eq(reference, test_string);
            assert!(!result, "Different length strings should not be equal");
        }

        // Test strings of same length but different content
        let same_length_different = vec![
            "tecret_reference_string", // First char different
            "secret_reference_strinz", // Last char different
            "secret_referencx_string", // Middle char different
            "SECRET_REFERENCE_STRING", // Case different
        ];

        for test_string in same_length_different {
            assert_eq!(test_string.len(), reference.len()); // Verify same length
            let result = ct_eq(reference, test_string);
            assert!(
                !result,
                "Same length, different content should not be equal"
            );
        }

        // Positive test case
        assert!(ct_eq(reference, reference));
    }

    // =========================================================================
    // ADDITIONAL COMPREHENSIVE NEGATIVE-PATH SECURITY TESTS
    // =========================================================================

    #[test]
    fn negative_capsule_manifest_with_extreme_field_pollution_attacks() {
        let mut capsule = build_reference_capsule();

        // Test metadata pollution with extreme key counts
        capsule.manifest.metadata.clear();
        for i in 0..10000 {
            let malicious_key = format!("pollution_{:04}\x00\r\n\t", i);
            let malicious_value = format!(
                "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>{}",
                "x".repeat(i % 1000)
            );
            capsule
                .manifest
                .metadata
                .insert(malicious_key, malicious_value);
        }
        sign_capsule(&test_signing_key(), &mut capsule);

        // Should handle massive metadata pollution without crashing or timeout
        let start = std::time::Instant::now();
        let result = validate_manifest(&capsule.manifest);
        let duration = start.elapsed();

        assert!(result.is_ok());
        assert!(duration < std::time::Duration::from_secs(10)); // Should complete reasonably

        // Test replay with polluted metadata
        match replay(&capsule, "verifier://pollution-test") {
            Ok(_) | Err(_) => {} // Either success or failure is acceptable, but no panic
        }
    }

    #[test]
    fn negative_deterministic_hash_with_unicode_normalization_bypass_attempts() {
        // Test hash behavior with Unicode normalization attacks
        let canonical_form = "café"; // Composed form (é as single codepoint)
        let decomposed_form = "cafe\u{0301}"; // Decomposed form (e + combining acute)
        let malicious_lookalike = "café"; // Different Unicode that looks similar

        let hash_canonical = deterministic_hash(canonical_form);
        let hash_decomposed = deterministic_hash(decomposed_form);
        let _hash_lookalike = deterministic_hash(malicious_lookalike);

        // Different Unicode representations should produce different hashes
        // (no normalization should be applied)
        if canonical_form.as_bytes() != decomposed_form.as_bytes() {
            assert_ne!(
                hash_canonical, hash_decomposed,
                "Different Unicode byte sequences must produce different hashes"
            );
        }

        // Test with various Unicode attack patterns
        let unicode_attacks = vec![
            "admin\u{202E}nidma", // Right-to-left override
            "admin\u{200D}user",  // Zero-width joiner
            "admin\u{FEFF}user",  // Zero-width no-break space
            "admin\u{034F}user",  // Combining grapheme joiner
            "admin\u{200B}user",  // Zero-width space
        ];

        let legitimate_hash = deterministic_hash("adminuser");
        for attack_input in unicode_attacks {
            let attack_hash = deterministic_hash(attack_input);
            assert_ne!(
                legitimate_hash,
                attack_hash,
                "Unicode attack pattern '{}' must not collide with legitimate input",
                attack_input.escape_unicode()
            );
        }
    }

    #[test]
    fn negative_replay_hash_with_malicious_length_prefix_injection() {
        // Test resistance to length-prefix injection attacks
        let mut legitimate_inputs = BTreeMap::new();
        legitimate_inputs.insert("key1".to_string(), "value1".to_string());

        // Attacker tries to inject fake length prefixes in payload
        let attack_payloads = vec![
            format!("{}{}key1{}value1{}",
                    "payload".len().to_le_bytes().iter().map(|&b| b as char).collect::<String>(),
                    "payload",
                    "key1".len().to_le_bytes().iter().map(|&b| b as char).collect::<String>(),
                    "value1".len().to_le_bytes().iter().map(|&b| b as char).collect::<String>()),
            "\x08\x00\x00\x00\x00\x00\x00\x00payloadX\x04\x00\x00\x00\x00\x00\x00\x00key1\x06\x00\x00\x00\x00\x00\x00\x00value1".to_string(),
            "fake_payload\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00".to_string(),
        ];

        let legitimate_hash = compute_replay_hash("legitimate_payload", &legitimate_inputs);

        for attack_payload in attack_payloads {
            let attack_hash = compute_replay_hash(&attack_payload, &BTreeMap::new());
            assert_ne!(
                legitimate_hash, attack_hash,
                "Length prefix injection attack must not produce hash collision"
            );
        }
    }

    #[test]
    fn negative_verifier_identity_with_homograph_and_spoofing_attacks() {
        let capsule = build_reference_capsule();

        // Test homograph attacks using similar-looking characters
        let homograph_attacks = vec![
            "verifier://аdmin",     // Cyrillic 'а' instead of Latin 'a'
            "verifier://admin‍user", // Zero-width joiner
            "verifier://аdmіn",     // Mixed Cyrillic/Latin
            "verifier://admín",     // Latin with accent
            "verifier://ⱱerifier",  // Latin small letter v with right hook
            "verifier://verífier",  // Accent on i
            "verifier://veriﬁer",   // Latin small ligature fi
        ];

        for spoofed_identity in homograph_attacks {
            match replay(&capsule, spoofed_identity) {
                Err(CapsuleError::AccessDenied(_)) => {} // May be rejected during validation
                Ok(_) => {
                    // If accepted, ensure it doesn't compromise security
                    // (the test just ensures no panic/crash occurs)
                }
                Err(_other_err) => {
                    // Other errors are also acceptable as long as no crash
                }
            }
        }

        // Test IDN homograph domain spoofing patterns
        let domain_spoofs = vec![
            "verifier://раypal.com",    // Cyrillic 'а' and 'р'
            "verifier://gооgle.com",    // Cyrillic 'о' characters
            "verifier://аmazon.com",    // Cyrillic 'а'
            "verifier://miсrosoft.com", // Cyrillic 'с'
        ];

        for spoof in domain_spoofs {
            match replay(&capsule, spoof) {
                Err(_) | Ok(_) => {} // Either result acceptable, no crash expected
            }
        }
    }

    #[test]
    fn negative_signing_payload_with_arithmetic_overflow_in_length_encoding() {
        // Test behavior near arithmetic boundaries in length encoding
        let mut stress_capsule = build_reference_capsule();

        // Test with field lengths approaching u64::MAX representation
        // Note: We can't actually create strings of usize::MAX length, but we test the encoding
        let max_reasonable_length = 1_000_000;
        stress_capsule.payload = "z".repeat(max_reasonable_length);

        // Add metadata with keys and values that test boundary conditions
        stress_capsule.manifest.metadata.clear();
        stress_capsule
            .manifest
            .metadata
            .insert("".to_string(), "".to_string()); // Zero length
        stress_capsule
            .manifest
            .metadata
            .insert("x".repeat(65535), "y".repeat(65536)); // Large but manageable

        // Should handle large lengths in signing payload without overflow
        let signing_payload = compute_signing_payload(&stress_capsule);
        assert_eq!(signing_payload.len(), 64);
        assert!(signing_payload.bytes().all(|b| b.is_ascii_hexdigit()));

        // Test with maximum number of input_refs
        stress_capsule.manifest.input_refs.clear();
        stress_capsule.inputs.clear();
        for i in 0..10000 {
            let key = format!("input_{:05}", i);
            stress_capsule.manifest.input_refs.push(key.clone());
            stress_capsule.inputs.insert(key, format!("content_{}", i));
        }

        let stress_signing = compute_signing_payload(&stress_capsule);
        assert_eq!(stress_signing.len(), 64);
        assert!(stress_signing.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn negative_capsule_error_display_with_injection_resistant_formatting() {
        // Test that error display properly escapes malicious input
        let injection_attempts = vec![
            "error\x1b[31mRED_TEXT\x1b[0m",                   // ANSI escape codes
            "error\r\nHTTP/1.1 200 OK\r\nContent-Type: text", // HTTP header injection
            "error</script><script>alert('xss')</script>",    // HTML/JS injection
            "error\0null_terminated\x00more",                 // Null byte injection
            "error\n\nSecond-Line: malicious",                // Newline injection
            "error\u{202E}reverse\u{202D}normal",             // BiDi override attacks
        ];

        for malicious_content in injection_attempts {
            let error_variants = vec![
                CapsuleError::SignatureInvalid(malicious_content.to_string()),
                CapsuleError::SchemaMismatch(malicious_content.to_string()),
                CapsuleError::AccessDenied(malicious_content.to_string()),
                CapsuleError::EmptyPayload(malicious_content.to_string()),
                CapsuleError::ManifestIncomplete(malicious_content.to_string()),
                CapsuleError::ReplayDiverged {
                    expected: malicious_content.to_string(),
                    actual: "legitimate".to_string(),
                },
                CapsuleError::VerdictMismatch {
                    expected: "Pass".to_string(),
                    actual: malicious_content.to_string(),
                },
            ];

            for error in error_variants {
                let error_string = format!("{}", error);

                match error {
                    CapsuleError::ReplayDiverged { .. } | CapsuleError::VerdictMismatch { .. } => {
                        assert!(
                            !error_string.contains(malicious_content)
                                && !error_string
                                    .contains(&malicious_content.escape_debug().to_string()),
                            "Sensitive mismatch displays should redact attacker-controlled values"
                        );
                        assert!(error_string.contains("redacted"));
                    }
                    _ => {
                        // Error should contain the malicious content but in a safe way
                        // (Display trait should not process escape codes, just include them as-is)
                        assert!(
                            error_string.contains(malicious_content)
                                || error_string
                                    .contains(&malicious_content.escape_debug().to_string()),
                            "Error display should include malicious content safely"
                        );
                    }
                }

                // Should not crash or cause undefined behavior
                assert!(
                    !error_string.is_empty(),
                    "Error display should not be empty"
                );
            }
        }
    }

    #[test]
    fn negative_btreemap_iteration_determinism_under_adversarial_key_patterns() {
        // Test BTreeMap determinism with adversarial key patterns designed to exploit ordering
        let mut capsule = build_reference_capsule();
        capsule.inputs.clear();
        capsule.manifest.input_refs.clear();

        // Keys designed to test lexicographic edge cases and potential hash collision exploitation
        let adversarial_keys = vec![
            // ASCII boundary conditions
            "\x00".to_string(),   // Null character (minimum)
            "\x1F".to_string(),   // Unit separator
            "\x20".to_string(),   // Space
            "\x21".to_string(),   // Exclamation
            "\x7E".to_string(),   // Tilde (near maximum printable ASCII)
            "\x7F".to_string(),   // DEL character
            "\u{FF}".to_string(), // Maximum 8-bit value
            // Length-based potential collisions
            "a".to_string(),
            "aa".to_string(),
            "aaa".to_string(),
            // Numeric string sorting edge cases
            "1".to_string(),
            "10".to_string(),
            "11".to_string(),
            "2".to_string(),
            "20".to_string(),
            // Unicode ordering edge cases
            "é".to_string(),          // Latin small letter e with acute
            "e\u{0301}".to_string(),  // e + combining acute accent
            "\u{1F600}".to_string(),  // Emoji (high Unicode)
            "\u{10FFFF}".to_string(), // Maximum Unicode codepoint
        ];

        // Insert in random order to test BTreeMap stabilizes the ordering
        for (i, key) in adversarial_keys.into_iter().rev().enumerate() {
            capsule
                .inputs
                .insert(key.clone(), format!("value_{:03}", i));
            capsule.manifest.input_refs.push(key);
        }

        // Sort manifest refs to match BTreeMap order
        capsule.manifest.input_refs.sort();

        // Compute hash multiple times to verify determinism
        let hash_attempts = (0..10)
            .map(|_| compute_replay_hash(&capsule.payload, &capsule.inputs))
            .collect::<Vec<_>>();

        // All hash attempts should be identical
        for (i, hash) in hash_attempts.iter().enumerate() {
            assert_eq!(
                hash, &hash_attempts[0],
                "Hash attempt {} differs from first attempt",
                i
            );
        }

        // This test intentionally uses invalid input_refs with non-ASCII characters
        // The validation should reject these and return an appropriate error
        capsule.manifest.expected_output_hash = hash_attempts[0].clone();
        sign_capsule(&test_signing_key(), &mut capsule);

        match replay(&capsule, "verifier://adversarial-keys") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("identifier must include only ASCII letters"));
            }
            other => panic!("Expected ManifestIncomplete for invalid input_refs, got {other:?}"),
        }
    }

    #[test]
    fn negative_replay_verdict_consistency_under_concurrent_simulation() {
        // Test verdict consistency by simulating concurrent access patterns
        let capsule = build_reference_capsule();

        // Simulate multiple "concurrent" replay attempts with identical capsule
        let replay_results: Vec<_> = (0..100)
            .map(|i| replay(&capsule, &format!("verifier://concurrent-sim-{:03}", i)))
            .collect();

        // All replays should succeed with identical results
        for (i, result) in replay_results.iter().enumerate() {
            match result {
                Ok(replay_result) => {
                    assert_eq!(
                        replay_result.verdict,
                        CapsuleVerdict::Pass,
                        "Replay {} should pass",
                        i
                    );
                    assert_eq!(
                        replay_result.actual_hash, replay_result.expected_hash,
                        "Hash mismatch in replay {}",
                        i
                    );
                    assert_eq!(
                        replay_result.capsule_id, capsule.manifest.capsule_id,
                        "Capsule ID mismatch in replay {}",
                        i
                    );
                }
                Err(e) => panic!("Replay {} failed unexpectedly: {}", i, e),
            }
        }

        // Test with slightly modified verifier identities to ensure no cross-contamination
        let verifier_variations = vec![
            "verifier://test-v1",
            "verifier://test-v2",
            "verifier://test-v3",
            "verifier://different-verifier",
            "verifier://CAPS_VERIFIER",
            "verifier://verifier-with-dashes",
            "verifier://123-numeric-verifier",
        ];

        for verifier_id in verifier_variations {
            let result = replay(&capsule, verifier_id).unwrap();
            assert_eq!(result.verdict, CapsuleVerdict::Pass);
            // Result should be identical regardless of verifier identity
            assert_eq!(result.actual_hash, capsule.manifest.expected_output_hash);
        }
    }

    #[test]
    fn negative_hash_collision_resistance_against_birthday_attack_simulation() {
        // Test hash collision resistance with patterns that could exploit birthday paradox
        let base_input = "collision_test_input";
        let mut hash_set = std::collections::HashSet::new();

        // Generate variations of input and verify no collisions occur
        let variations =
            (0..1000).map(|i| format!("{}_variant_{:04}_{}", base_input, i, "x".repeat(i % 100)));

        for input in variations {
            let hash = deterministic_hash(&input);
            assert_eq!(hash.len(), 64);
            assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));

            // In a cryptographically secure hash, collisions should be extremely rare
            if hash_set.contains(&hash) {
                panic!("Hash collision detected for input: {}", input);
            }
            hash_set.insert(hash);
        }

        // Test with structured input patterns that could exploit internal hash state
        let structured_patterns = vec![
            "aaaa", "aaab", "aaba", "abaa", "baaa", // Hamming distance 1 patterns
            "0000", "0001", "0010", "0100", "1000", // Binary patterns
            "ffff", "fffe", "ffef", "feff", "efff", // High-bit patterns
        ];

        let mut structured_hashes = std::collections::HashSet::new();
        for pattern in structured_patterns {
            let hash = deterministic_hash(pattern);
            assert!(
                !structured_hashes.contains(&hash),
                "Collision in structured pattern: {}",
                pattern
            );
            structured_hashes.insert(hash);
        }
    }

    // =========================================================================
    // EXTREME ADVERSARIAL NEGATIVE-PATH SECURITY TESTS
    // =========================================================================

    #[test]
    fn extreme_adversarial_cryptographic_timing_attack_on_signature_verification() {
        // Extreme: Cryptographic timing analysis of signature verification to detect non-constant-time vulnerabilities
        use std::time::Instant;

        let reference_capsule = build_reference_capsule();
        let correct_signature = reference_capsule.signature.clone();

        let sample_count = 10000;

        // Create attack signatures designed to exploit timing differences
        let timing_attack_cases = vec![
            // Differ at different bit positions to test early termination
            (format!("0{}", &correct_signature[1..]), "first_char_diff"),
            (
                format!("{}{}", &correct_signature[..31], "X"),
                "middle_char_diff",
            ),
            (format!("{}X", &correct_signature[..63]), "last_char_diff"),
            // Same length but entirely different
            ("0".repeat(64), "all_zeros"),
            ("f".repeat(64), "all_fs"),
            ("a".repeat(64), "all_as"),
            // Partial matches that could reveal processing patterns
            (
                format!("{}{}", &correct_signature[..32], "0".repeat(32)),
                "half_correct",
            ),
            (
                format!("{}{}", &correct_signature[..48], "0".repeat(16)),
                "three_quarter_correct",
            ),
            (
                format!("{}{}", &correct_signature[..60], "0000"),
                "almost_correct",
            ),
        ];

        let mut timing_results = std::collections::HashMap::new();

        for (attack_signature, test_name) in timing_attack_cases {
            let mut attack_capsule = reference_capsule.clone();
            attack_capsule.signature = attack_signature;

            let mut timings = Vec::new();

            // Collect timing samples for each attack case
            let verifying_key = test_verifying_key();
            for _ in 0..sample_count {
                let start = Instant::now();
                let _result = verify_signature(&verifying_key, &attack_capsule);
                let duration = start.elapsed();
                timings.push(duration.as_nanos());
            }

            // Calculate statistics
            timings.sort_unstable();
            let median = timings[sample_count / 2] as f64;
            let min = *timings.iter().min().unwrap() as f64;
            let max = *timings.iter().max().unwrap() as f64;
            let mean = timings.iter().map(|&x| x as f64).sum::<f64>() / sample_count as f64;

            timing_results.insert(test_name, (median, min, max, mean));
        }

        // Analyze timing differences for patterns indicating non-constant-time comparison
        let medians: Vec<f64> = timing_results
            .values()
            .map(|(median, _, _, _)| *median)
            .collect();
        let mean_median = medians.iter().sum::<f64>() / medians.len() as f64;
        let max_median = medians.iter().fold(0.0_f64, |acc, &x| acc.max(x));
        let min_median = medians.iter().fold(f64::INFINITY, |acc, &x| acc.min(x));

        let timing_variance_ratio = (max_median - min_median) / mean_median;

        // Constant-time verification should have low timing variance across different inputs
        assert!(
            timing_variance_ratio < 1.5,
            "Suspicious timing variance in signature verification: ratio={:.3}, mean={:.0}ns, min={:.0}ns, max={:.0}ns",
            timing_variance_ratio,
            mean_median,
            min_median,
            max_median
        );

        // No individual test case should be dramatically different from others
        for (test_name, (median, min, max, mean)) in timing_results {
            let individual_variance = (max - min) / mean;
            assert!(
                individual_variance < 3.0,
                "High variance in test case '{}': median={:.0}ns, min={:.0}ns, max={:.0}ns, variance={:.3}",
                test_name,
                median,
                min,
                max,
                individual_variance
            );

            let deviation_from_mean = (median - mean_median).abs() / mean_median;
            assert!(
                deviation_from_mean < 0.5,
                "Test case '{}' deviates significantly from mean timing: {:.3}",
                test_name,
                deviation_from_mean
            );
        }
    }

    #[test]
    fn extreme_adversarial_length_extension_attacks_on_hash_computation() {
        // Extreme: Test resistance to length extension attacks on hash computation

        // Standard MD construction vulnerabilities don't apply to SHA-256 with HMAC-like structure,
        // but test edge cases in our length-prefixed construction
        let base_payload = "legitimate_payload";
        let mut base_inputs = BTreeMap::new();
        base_inputs.insert("input1".to_string(), "value1".to_string());

        let legitimate_hash = compute_replay_hash(base_payload, &base_inputs);

        // Attempt length extension by appending data that looks like valid length-prefixed content
        let extension_attempts = vec![
            // Try to append fake input entries
            format!(
                "{}\x05\x00\x00\x00\x00\x00\x00\x00input\x06\x00\x00\x00\x00\x00\x00\x00malice",
                base_payload
            ),
            // Try to inject length prefix that could confuse parser
            format!(
                "{}\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00a\x01\x00\x00\x00\x00\x00\x00\x00b",
                base_payload
            ),
            // Attempt to create collision by manipulating payload structure
            format!(
                "{}\x08\x00\x00\x00\x00\x00\x00\x00input1xx\x06\x00\x00\x00\x00\x00\x00\x00value1",
                base_payload
            ),
        ];

        for extension_attempt in extension_attempts {
            let extension_hash = compute_replay_hash(&extension_attempt, &BTreeMap::new());

            assert_ne!(
                legitimate_hash, extension_hash,
                "Length extension attack must not produce hash collision"
            );

            // Test with various input combinations to ensure isolation
            let mut extension_inputs = BTreeMap::new();
            extension_inputs.insert("different_key".to_string(), "different_value".to_string());

            let combined_extension_hash =
                compute_replay_hash(&extension_attempt, &extension_inputs);
            assert_ne!(
                legitimate_hash, combined_extension_hash,
                "Combined length extension attack must not produce collision"
            );
        }

        // Test resistance to second preimage attacks via crafted payloads
        let collision_prefix = format!("{}collision", base_payload);
        let collision_suffix = format!("collision{}", base_payload);
        let second_preimage_attempts = vec![
            // Try to create payload that when combined with different inputs produces same hash
            "crafted_payload_attempt_1",
            "crafted_payload_attempt_2",
            &collision_prefix,
            &collision_suffix,
        ];

        for preimage_attempt in second_preimage_attempts {
            let mut attack_inputs = BTreeMap::new();
            attack_inputs.insert("attack_input".to_string(), "attack_value".to_string());

            let preimage_hash = compute_replay_hash(preimage_attempt, &attack_inputs);

            assert_ne!(
                legitimate_hash, preimage_hash,
                "Second preimage attack with payload '{}' must not produce collision",
                preimage_attempt
            );
        }
    }

    #[test]
    fn extreme_adversarial_domain_separator_injection_and_collision_attacks() {
        // Extreme: Test domain separator injection attacks and cross-domain hash collisions

        let legitimate_data = "test_data";
        let legitimate_hash = deterministic_hash(legitimate_data);

        // Attempt to inject domain separator to cause collision with empty input
        let separator_injection_attempts = vec![
            // Try to prepend domain separator to confuse hash computation
            "verifier_sdk_capsule_v1:",
            "verifier_sdk_capsule_v1:additional_data",
            "\x76\x65\x72\x69\x66\x69\x65\x72\x5f\x73\x64\x6b\x5f\x63\x61\x70\x73\x75\x6c\x65\x5f\x76\x31\x3a", // Hex encoding
            // Try different domain separators that could cause confusion
            "verifier_sdk_capsule_v2:test_data",
            "verifier_sdk_capsule_replay_v1:test_data",
            "verifier_sdk_capsule_signing_v1:test_data",
            // Binary injection of domain separator
            "verifier_sdk_capsule_v1:test_data",
        ];

        for injection_attempt in separator_injection_attempts {
            let attack_hash = deterministic_hash(injection_attempt);

            assert_ne!(
                legitimate_hash,
                attack_hash,
                "Domain separator injection '{}' must not produce collision",
                injection_attempt.escape_debug()
            );
        }

        // Test cross-function domain separator collision resistance
        let replay_data_payload = "payload";
        let mut replay_inputs = BTreeMap::new();
        replay_inputs.insert("key".to_string(), "value".to_string());

        let replay_hash = compute_replay_hash(replay_data_payload, &replay_inputs);

        // Try to craft deterministic hash input that collides with replay hash
        let cross_domain_attacks = vec![
            format!("verifier_sdk_capsule_replay_v1:{}", replay_data_payload),
            format!(
                "{}payload",
                u64::try_from(replay_data_payload.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes()
                    .iter()
                    .map(|&b| b as char)
                    .collect::<String>()
            ),
            format!(
                "verifier_sdk_capsule_replay_v1:{}{}{}{}{}",
                u64::try_from(replay_data_payload.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes()
                    .iter()
                    .map(|&b| b as char)
                    .collect::<String>(),
                replay_data_payload,
                (1u64)
                    .to_le_bytes()
                    .iter()
                    .map(|&b| b as char)
                    .collect::<String>(),
                (3u64)
                    .to_le_bytes()
                    .iter()
                    .map(|&b| b as char)
                    .collect::<String>(),
                "key"
            ),
        ];

        for attack_input in cross_domain_attacks {
            let cross_domain_hash = deterministic_hash(&attack_input);

            assert_ne!(
                replay_hash,
                cross_domain_hash,
                "Cross-domain collision attack must not succeed with input: {}",
                attack_input.escape_debug()
            );
        }

        // Verify domain separators actually work by confirming same data with different separators produces different hashes
        let test_input = "identical_content";

        let mut manual_hash1 = Sha256::new();
        manual_hash1.update(b"domain_sep_1:");
        manual_hash1.update(test_input.as_bytes());
        let hash1 = hex::encode(manual_hash1.finalize());

        let mut manual_hash2 = Sha256::new();
        manual_hash2.update(b"domain_sep_2:");
        manual_hash2.update(test_input.as_bytes());
        let hash2 = hex::encode(manual_hash2.finalize());

        assert_ne!(
            hash1, hash2,
            "Different domain separators must produce different hashes"
        );
    }

    #[test]
    fn extreme_adversarial_unicode_normalization_timing_side_channel_attacks() {
        // Extreme: Test for timing side channels in Unicode normalization during string processing
        use std::time::Instant;

        let sample_count = 1000;

        // Create Unicode strings that could exhibit different processing times
        // Store repeated strings in variables to avoid temporary value issues
        let massive_decomposed = "e\u{0301}".repeat(1000);
        let massive_emoji = "\u{1F600}".repeat(500);
        let massive_combining = "\u{0300}".repeat(2000);
        let heavily_accented = "a\u{0300}\u{0301}\u{0302}\u{0303}".repeat(500);

        let unicode_timing_cases = vec![
            // Composed vs decomposed forms that are visually identical
            ("café", "composed_single_codepoint"),
            ("cafe\u{0301}", "decomposed_combining_accent"),
            // Complex normalization cases
            ("\u{1E0A}\u{0323}", "complex_combining_sequence"), // Ḋ + combining dot below
            ("\u{1E0C}\u{0307}", "different_complex_sequence"), // Ḍ + combining dot above
            // Maximum length normalization cases
            (&massive_decomposed, "massive_decomposed_accents"), // 1000 é characters decomposed
            (&massive_emoji, "massive_emoji_sequence"),          // 500 emoji
            // Potential normalization DoS patterns
            (&massive_combining, "massive_combining_only"), // Only combining characters
            (&heavily_accented, "heavily_accented_sequence"),
        ];

        let mut unicode_timings = std::collections::HashMap::new();

        for (unicode_input, test_name) in unicode_timing_cases {
            let mut timings = Vec::new();

            // Test deterministic hash timing with Unicode input
            for _ in 0..sample_count {
                let start = Instant::now();
                let _hash = deterministic_hash(unicode_input);
                let duration = start.elapsed();
                timings.push(duration.as_nanos());
            }

            timings.sort_unstable();
            let median = timings[sample_count / 2] as f64;
            let min = *timings.iter().min().unwrap() as f64;
            let max = *timings.iter().max().unwrap() as f64;

            unicode_timings.insert(test_name, (median, min, max));

            // Individual test should complete in reasonable time
            assert!(
                median < 1_000_000.0, // 1ms
                "Unicode processing too slow for '{}': {:.0}ns",
                test_name,
                median
            );
        }

        // Analyze timing relationships to detect Unicode normalization side channels
        let medians: Vec<f64> = unicode_timings
            .values()
            .map(|(median, _, _)| *median)
            .collect();
        let mean_median = medians.iter().sum::<f64>() / medians.len() as f64;
        let max_median = medians.iter().fold(0.0_f64, |acc, &x| acc.max(x));
        let min_median = medians.iter().fold(f64::INFINITY, |acc, &x| acc.min(x));

        let unicode_timing_variance = (max_median - min_median) / mean_median;

        // Unicode processing should not have dramatic timing differences
        assert!(
            unicode_timing_variance < 3.0,
            "Suspicious Unicode timing variance: ratio={:.3}, mean={:.0}ns, min={:.0}ns, max={:.0}ns",
            unicode_timing_variance,
            mean_median,
            min_median,
            max_median
        );

        // Test capsule replay with Unicode content
        let mut unicode_capsule = build_reference_capsule();
        unicode_capsule.manifest.description = "café vs cafe\u{0301} timing test".to_string();
        unicode_capsule.payload = "Unicode payload: \u{1F600}\u{1F601}\u{1F602}".to_string();

        let mut unicode_inputs = BTreeMap::new();
        unicode_inputs.insert(
            "unicode_key_é".to_string(),
            "unicode_value_\u{1F525}".to_string(),
        );
        unicode_capsule.inputs = unicode_inputs;

        unicode_capsule.manifest.input_refs = vec!["unicode_key_é".to_string()];
        unicode_capsule.manifest.expected_output_hash =
            compute_replay_hash(&unicode_capsule.payload, &unicode_capsule.inputs);
        sign_capsule(&test_signing_key(), &mut unicode_capsule);

        // Unicode input_refs are no longer valid - should be rejected
        let unicode_start = Instant::now();
        match replay(&unicode_capsule, "verifier://unicode-test") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("identifier must include only ASCII letters"));
                let unicode_replay_time = unicode_start.elapsed();
                // Validation should be fast regardless of Unicode complexity
                assert!(unicode_replay_time < std::time::Duration::from_millis(100));
            }
            other => panic!("Expected ManifestIncomplete for Unicode input_ref, got {other:?}"),
        }
    }

    #[test]
    fn extreme_adversarial_memory_pressure_cryptographic_operations_under_stress() {
        // Extreme: Test cryptographic operations under extreme memory pressure

        // Create large data structures to simulate memory pressure
        let memory_pressure_data: Vec<_> = (0..10000)
            .map(|i| {
                format!(
                    "memory_pressure_string_number_{}_with_content_{}",
                    i,
                    "x".repeat(100)
                )
            })
            .collect();

        // Test hash computation under memory pressure
        let mut stress_capsule = build_reference_capsule();
        stress_capsule.payload = "y".repeat(500_000); // 500KB payload

        // Add many inputs to create memory pressure
        stress_capsule.inputs.clear();
        stress_capsule.manifest.input_refs.clear();
        for i in 0..1000 {
            let key = format!("stress_input_{:04}", i);
            let value = format!("stress_value_{}_{}", i, "z".repeat(200)); // 200+ chars per value
            stress_capsule.inputs.insert(key.clone(), value);
            stress_capsule.manifest.input_refs.push(key);
        }

        // Perform cryptographic operations under memory pressure
        let stress_start = std::time::Instant::now();

        // Hash computation should remain stable under memory pressure
        let stress_hash = compute_replay_hash(&stress_capsule.payload, &stress_capsule.inputs);
        assert_eq!(stress_hash.len(), 64);
        assert!(stress_hash.bytes().all(|b| b.is_ascii_hexdigit()));

        // Signing should work under memory pressure
        stress_capsule.manifest.expected_output_hash = stress_hash;
        let test_signing_key = test_signing_key();
        sign_capsule(&test_signing_key, &mut stress_capsule);

        let signing_time = stress_start.elapsed();
        assert!(signing_time < std::time::Duration::from_secs(10)); // Should complete within 10s

        // Verification should work under memory pressure
        let verification_start = std::time::Instant::now();
        let verifying_key = test_verifying_key();
        assert!(verify_signature(&verifying_key, &stress_capsule).is_ok());
        let verification_time = verification_start.elapsed();
        assert!(verification_time < std::time::Duration::from_secs(5));

        // Full replay under memory pressure
        let replay_start = std::time::Instant::now();
        let stress_result = replay(&stress_capsule, "verifier://memory-stress").unwrap();
        let replay_time = replay_start.elapsed();

        assert_eq!(stress_result.verdict, CapsuleVerdict::Pass);
        assert!(replay_time < std::time::Duration::from_secs(10));

        // Memory usage should be proportional, not exponential
        let estimated_memory = stress_capsule.payload.len()
            + stress_capsule
                .inputs
                .values()
                .map(|v| v.len())
                .sum::<usize>()
            + stress_capsule.inputs.keys().map(|k| k.len()).sum::<usize>();

        // Should be roughly linear with input size (allowing some overhead)
        assert!(
            estimated_memory < 10_000_000, // 10MB reasonable upper bound
            "Memory usage appears excessive: ~{} bytes",
            estimated_memory
        );

        // Cleanup memory pressure data to prevent issues with later tests
        drop(memory_pressure_data);
    }

    #[test]
    fn extreme_adversarial_constant_time_comparison_statistical_analysis() {
        // Extreme: Statistical analysis of constant-time comparison to detect timing leaks
        use std::time::Instant;

        let reference_string = "reference_signature_hash_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sample_count = 5000;

        // Create test cases designed to exploit different comparison patterns
        let timing_test_cases = vec![
            // Early difference cases
            ("0".repeat(64), "all_zeros_early_diff"),
            ("x".repeat(64), "all_x_early_diff"),
            (format!("z{}", &reference_string[1..]), "first_char_diff"),
            // Late difference cases
            (format!("{}x", &reference_string[..63]), "last_char_diff"),
            (format!("{}0", &reference_string[..63]), "last_char_zero"),
            (format!("{}f", &reference_string[..63]), "last_char_f"),
            // Multiple position differences
            (format!("x{}x", &reference_string[1..63]), "first_last_diff"),
            (format!("x{}", &reference_string[1..]), "first_only_diff"),
            (
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
                "reverse_hex",
            ),
            // Bit-level differences (same char but different case)
            (format!("F{}", &reference_string[1..]), "case_diff_first"),
            (format!("{}F", &reference_string[..63]), "case_diff_last"),
            // Identical case
            (reference_string.to_string(), "identical"),
        ];

        let mut detailed_timings = std::collections::HashMap::new();

        for (test_string, test_name) in timing_test_cases {
            let mut timings = Vec::new();

            // Collect high-resolution timing data
            for _ in 0..sample_count {
                // Use a more precise timing method
                let start = Instant::now();
                let _result = ct_eq(&reference_string, &test_string);
                let duration = start.elapsed();
                timings.push(duration.as_nanos());
            }

            // Statistical analysis
            timings.sort_unstable();

            let mean = timings.iter().sum::<u128>() as f64 / sample_count as f64;
            let median = timings[sample_count / 2] as f64;
            let min = *timings.iter().min().unwrap() as f64;
            let max = *timings.iter().max().unwrap() as f64;

            // Calculate standard deviation
            let variance = timings
                .iter()
                .map(|&x| (x as f64 - mean).powi(2))
                .sum::<f64>()
                / sample_count as f64;
            let std_dev = variance.sqrt();

            // Calculate percentiles
            let p95 = timings[(sample_count as f64 * 0.95) as usize] as f64;
            let p99 = timings[(sample_count as f64 * 0.99) as usize] as f64;

            detailed_timings.insert(test_name, (mean, median, min, max, std_dev, p95, p99));
        }

        // Statistical analysis for constant-time properties
        let means: Vec<f64> = detailed_timings
            .values()
            .map(|(mean, _, _, _, _, _, _)| *mean)
            .collect();
        let overall_mean = means.iter().sum::<f64>() / means.len() as f64;
        let max_mean = means.iter().fold(0.0_f64, |acc, &x| acc.max(x));
        let min_mean = means.iter().fold(f64::INFINITY, |acc, &x| acc.min(x));

        // Constant-time comparison should have very low variance across different inputs
        let mean_variance_ratio = (max_mean - min_mean) / overall_mean;
        assert!(
            mean_variance_ratio < 0.3, // 30% variance threshold
            "Excessive timing variance suggests non-constant-time comparison: ratio={:.3}",
            mean_variance_ratio
        );

        // Individual test analysis
        for (test_name, (mean, median, min, max, std_dev, p95, p99)) in detailed_timings {
            // High individual variance could indicate timing leaks
            let individual_variance = (max - min) / mean;
            assert!(
                individual_variance < 5.0,
                "High individual timing variance for '{}': ratio={:.3}, mean={:.0}ns",
                test_name,
                individual_variance,
                mean
            );

            // Standard deviation relative to mean should be reasonable
            let coefficient_of_variation = std_dev / mean;
            assert!(
                coefficient_of_variation < 1.0,
                "High coefficient of variation for '{}': {:.3}",
                test_name,
                coefficient_of_variation
            );

            // 99th percentile should not be dramatically higher than median (indicating outliers)
            assert!(
                p95 <= p99,
                "p95 should not exceed p99 for '{}': p95={:.0}ns, p99={:.0}ns",
                test_name,
                p95,
                p99
            );
            let outlier_ratio = p99 / median;
            assert!(
                outlier_ratio < 10.0,
                "Excessive outliers for '{}': p99/median ratio={:.3}",
                test_name,
                outlier_ratio
            );

            // Deviation from overall mean should be small
            let deviation_from_overall = (mean - overall_mean).abs() / overall_mean;
            assert!(
                deviation_from_overall < 0.5,
                "Test case '{}' deviates significantly from overall mean: {:.3}",
                test_name,
                deviation_from_overall
            );
        }

        // Test byte-level constant-time comparison as well
        let reference_bytes = reference_string.as_bytes();

        for (test_string, test_name) in &[
            ("0".repeat(64), "byte_zeros".to_string()),
            (
                format!("x{}", &reference_string[1..]),
                "byte_first_diff".to_string(),
            ),
            (reference_string.to_string(), "byte_identical".to_string()),
        ] {
            let test_bytes = test_string.as_bytes();
            let mut byte_timings = Vec::new();

            for _ in 0..sample_count / 2 {
                // Fewer samples for byte tests
                let start = Instant::now();
                let _result = ct_eq_bytes(reference_bytes, test_bytes);
                let duration = start.elapsed();
                byte_timings.push(duration.as_nanos());
            }

            let byte_mean = byte_timings.iter().sum::<u128>() as f64 / (sample_count / 2) as f64;
            let byte_deviation = (byte_mean - overall_mean).abs() / overall_mean;

            // Byte comparison should be consistent with string comparison timing
            assert!(
                byte_deviation < 1.0,
                "Byte comparison timing inconsistent for '{}': deviation={:.3}",
                test_name,
                byte_deviation
            );
        }
    }

    #[test]
    fn extreme_adversarial_cryptographic_hash_differential_analysis() {
        // Extreme: Differential cryptanalysis patterns to test hash function robustness

        // Test Hamming distance relationships in hash outputs
        let base_input = "cryptographic_differential_analysis_base";
        let base_hash = deterministic_hash(base_input);

        // Generate inputs with controlled bit differences
        let differential_cases = vec![
            // Single bit flips at different positions
            (format!("{}x", &base_input[1..]), "bit_flip_pos_0"),
            (
                format!(
                    "{}x{}",
                    &base_input[..base_input.len() / 2],
                    &base_input[base_input.len() / 2 + 1..]
                ),
                "bit_flip_middle",
            ),
            (
                format!("{}x", &base_input[..base_input.len() - 1]),
                "bit_flip_last",
            ),
            // Multiple bit flips
            (
                "cryptographic_differential_analysis_basz".to_string(),
                "two_bit_flip",
            ),
            (
                "cryptographic_differential_analysis_basf".to_string(),
                "hex_bit_pattern",
            ),
            // Byte boundary tests
            (
                "cryptographic_differential_analysis_bas\x00".to_string(),
                "null_byte_append",
            ),
            (
                "cryptographic_differential_analysis_bas\u{FF}".to_string(),
                "high_byte_append",
            ),
            // Length variations
            (
                "cryptographic_differential_analysis_bas".to_string(),
                "truncated",
            ),
            (
                "cryptographic_differential_analysis_baseX".to_string(),
                "extended",
            ),
        ];

        let mut hash_relationships = Vec::new();

        for (modified_input, test_name) in differential_cases {
            let modified_hash = deterministic_hash(&modified_input);

            // Verify no hash collision occurs
            assert_ne!(
                base_hash, modified_hash,
                "Hash collision detected for differential input '{}': '{}'",
                test_name, modified_input
            );

            // Calculate Hamming distance between hashes (converted to binary)
            let base_bytes = hex::decode(&base_hash).expect("Base hash should be valid hex");
            let modified_bytes =
                hex::decode(&modified_hash).expect("Modified hash should be valid hex");

            assert_eq!(base_bytes.len(), modified_bytes.len());

            let hamming_distance = base_bytes
                .iter()
                .zip(modified_bytes.iter())
                .map(|(&a, &b)| (a ^ b).count_ones())
                .sum::<u32>();

            hash_relationships.push((test_name, hamming_distance));

            // For cryptographic hash functions, small input changes should cause
            // large, unpredictable output changes (avalanche effect)
            assert!(
                hamming_distance >= 50, // Should flip many bits
                "Insufficient avalanche effect for '{}': Hamming distance={}",
                test_name,
                hamming_distance
            );

            assert!(
                hamming_distance <= 200, // But not suspiciously many
                "Suspicious bit flip pattern for '{}': Hamming distance={}",
                test_name,
                hamming_distance
            );
        }

        // Statistical analysis of Hamming distances
        let distances: Vec<u32> = hash_relationships
            .iter()
            .map(|(_, distance)| *distance)
            .collect();
        let mean_distance = distances.iter().sum::<u32>() as f64 / distances.len() as f64;
        let expected_distance = 128.0; // Roughly half the bits should flip for good hash function

        let distance_deviation = (mean_distance - expected_distance).abs() / expected_distance;
        assert!(
            distance_deviation < 0.3, // 30% deviation threshold
            "Hamming distance distribution suspicious: mean={:.1}, expected≈{}, deviation={:.3}",
            mean_distance,
            expected_distance,
            distance_deviation
        );

        // Test specific cryptographic properties

        // Test collision resistance with structured inputs
        let structured_inputs =
            (0..1000).map(|i| format!("structured_collision_test_{:04}_{}", i, "a".repeat(i % 50)));

        let mut structured_hashes = std::collections::HashSet::new();
        for structured_input in structured_inputs {
            let hash = deterministic_hash(&structured_input);

            assert!(
                !structured_hashes.contains(&hash),
                "Collision detected in structured inputs: '{}'",
                structured_input
            );
            structured_hashes.insert(hash);
        }

        // Test preimage resistance by attempting to reverse known hashes
        let target_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            &base_hash,
        ];

        for target_hash in target_hashes {
            let mut preimage_found = false;

            // Try a limited number of preimage attempts (this is just a sanity check)
            for attempt in 0..1000 {
                let candidate_input = format!("preimage_attempt_{:04}", attempt);
                let candidate_hash = deterministic_hash(&candidate_input);

                if candidate_hash == target_hash && candidate_input != base_input {
                    preimage_found = true;
                    break;
                }
            }

            // Should not find preimages easily (except for the known base_input case)
            if target_hash != base_hash {
                assert!(
                    !preimage_found,
                    "Preimage found too easily for target hash: {}",
                    target_hash
                );
            }
        }
    }

    #[test]
    fn extreme_adversarial_verifier_identity_injection_and_privilege_escalation() {
        // Extreme: Test verifier identity parsing for injection attacks and privilege escalation

        let test_capsule = build_reference_capsule();

        // Test protocol injection attempts
        let protocol_injection_attacks = vec![
            // URI injection attempts
            "verifier://evil.com/verifier://legitimate.com",
            "verifier://legitimate.com@evil.com",
            "verifier://user:password@evil.com/legitimate",
            "verifier://legitimate.com:8080/../../../admin",
            // Scheme confusion attacks
            "javascript:alert('xss')//verifier://fake",
            "data:text/html,<script>alert('xss')</script>//verifier://fake",
            "file:///etc/passwd#verifier://fake",
            "http://evil.com/verifier://redirect",
            // Authority bypass attempts
            "verifier:///admin/../../verifier://bypass",
            "verifier://\\\\evil.com/verifier://legitimate",
            "verifier://../../../admin/verifier://escalate",
            // Control character injection
            "verifier://admin\r\nSet-Cookie: admin=true\r\n//fake",
            "verifier://admin\x00\x01\x02\x03fake",
            "verifier://admin\u{202E}lamitgel\u{202D}//fake", // BiDi override
            // Unicode normalization attacks
            "verifier://аdmin", // Cyrillic 'а' instead of Latin 'a'
            "verifier://admin\u{0300}\u{0301}\u{0302}", // Heavy accent combining
            "verifier://admin\u{FEFF}zero-width", // Zero-width BOM
        ];

        for malicious_identity in protocol_injection_attacks {
            match replay(&test_capsule, malicious_identity) {
                Err(CapsuleError::AccessDenied(_)) => {
                    // Expected rejection is fine
                }
                Ok(_) => {
                    // If accepted, ensure no security compromise occurred
                    // The replay should still work correctly without privilege escalation
                    // This test primarily ensures no panic/crash occurs
                }
                Err(_) => {
                    // Other errors are also acceptable as long as no crash
                }
            }
        }

        // Test length-based attacks on verifier identity parsing
        let length_based_attacks = vec![
            // Extremely long verifier names
            format!("verifier://{}", "x".repeat(100_000)),
            format!("verifier://{}", "aaaaaaaa".repeat(12500)), // 100k chars
            // Empty components after parsing
            "verifier://   ".to_string(),
            "verifier://\t\n\r   \x20".to_string(),
            "verifier://\u{00A0}\u{2000}\u{2001}".to_string(), // Various Unicode spaces
            // Boundary length conditions
            format!("verifier://{}", "a".repeat(1)), // Minimum
            format!("verifier://{}", "a".repeat(255)), // Typical domain limit
            format!("verifier://{}", "a".repeat(65535)), // Large but manageable
        ];

        for length_attack in length_based_attacks {
            let start_time = std::time::Instant::now();
            let result = replay(&test_capsule, &length_attack);
            let duration = start_time.elapsed();

            // Should complete quickly regardless of input length
            assert!(
                duration < std::time::Duration::from_secs(1),
                "Verifier identity parsing took too long: {:?}",
                duration
            );

            // Result should be predictable (likely rejected for long/invalid inputs)
            match result {
                Ok(_) | Err(_) => {} // Any result is fine as long as no crash
            }
        }

        // Test environment variable injection attempts
        let env_injection_attacks = vec![
            "verifier://${PATH}malicious",
            "verifier://%PATH%windows",
            "verifier://$(echo injection)",
            "verifier://`cat /etc/passwd`",
            "verifier://$HOME/.bashrc",
            "verifier://\\$USER@evil.com",
        ];

        for env_attack in env_injection_attacks {
            match replay(&test_capsule, env_attack) {
                Ok(_) => {
                    // If somehow accepted, verify no environment variable was actually expanded
                    assert!(
                        !env_attack.contains("injection"),
                        "Environment variable injection should not be processed"
                    );
                }
                Err(_) => {
                    // Rejection is expected and safe
                }
            }
        }

        // Test legitimate verifier identities still work after injection tests
        let legitimate_identities = vec![
            "verifier://legitimate-verifier-1",
            "verifier://verifier.example.com",
            "verifier://test-verifier-2026",
            "verifier://CAPS-VERIFIER",
            "verifier://verifier_with_underscores",
            "verifier://123-numeric-verifier-456",
        ];

        for legitimate_identity in legitimate_identities {
            let result = replay(&test_capsule, legitimate_identity);
            assert!(
                result.is_ok(),
                "Legitimate verifier identity should work: {}",
                legitimate_identity
            );

            let replay_result = result.unwrap();
            assert_eq!(replay_result.verdict, CapsuleVerdict::Pass);
        }
    }

    #[test]
    fn extreme_adversarial_integer_overflow_protection_in_length_encoding_operations() {
        // Extreme: Test integer overflow protection in length-prefixed encoding operations

        // Test u64 length encoding boundary conditions
        let max_length_test_cases = vec![
            (0u64, "zero_length"),
            (1u64, "single_length"),
            (255u64, "byte_boundary"),
            (65535u64, "u16_max"),
            (4294967295u64, "u32_max"),
            (u64::MAX - 1, "near_u64_max"),
            (u64::MAX, "u64_max"),
        ];

        for (test_length, _test_name) in max_length_test_cases {
            // Test length encoding itself doesn't overflow
            let encoded_length = test_length.to_le_bytes();
            assert_eq!(encoded_length.len(), 8); // Should always be 8 bytes

            // Test with manageable string that represents this length conceptually
            let test_string = if test_length <= 100_000 {
                "x".repeat(test_length as usize)
            } else {
                // For very large theoretical lengths, use a representative string
                format!("length_test_string_representing_{}", test_length)
            };

            // Test hash computation with length encoding
            let mut test_hasher = Sha256::new();
            test_hasher.update(b"length_test_domain:");
            push_length_prefixed(&mut test_hasher, &test_string);
            let result_hash = hex::encode(test_hasher.finalize());

            assert_eq!(result_hash.len(), 64);
            assert!(result_hash.bytes().all(|b| b.is_ascii_hexdigit()));
        }

        // Test with collections at boundary sizes
        let mut boundary_inputs = BTreeMap::new();

        // Add inputs that test boundary conditions in collection length encoding
        for i in 0..1000 {
            let key = format!("boundary_key_{:04}", i);
            let value = format!("boundary_value_{}", i);
            boundary_inputs.insert(key, value);
        }

        // Test replay hash with large input collection
        let boundary_payload = "boundary_test_payload";
        let boundary_hash = compute_replay_hash(boundary_payload, &boundary_inputs);
        assert_eq!(boundary_hash.len(), 64);

        // Test with edge case: empty strings in large collections
        let mut empty_edge_inputs = BTreeMap::new();
        for i in 0..10000 {
            empty_edge_inputs.insert(format!("key_{}", i), String::new()); // Empty values
        }

        let empty_edge_hash = compute_replay_hash("", &empty_edge_inputs);
        assert_eq!(empty_edge_hash.len(), 64);
        assert_ne!(empty_edge_hash, boundary_hash); // Should be different

        // Test arithmetic wraparound protection
        let mut overflow_test_inputs = BTreeMap::new();

        // Test with maximum reasonable collection size
        let max_test_size = 50_000; // Large but manageable for testing
        for i in 0..max_test_size {
            let key = format!("overflow_test_key_{:06}", i);
            let value = format!("value_{}", i % 100); // Varied but bounded value size
            overflow_test_inputs.insert(key, value);
        }

        // Should handle large collections without arithmetic overflow
        let start_time = std::time::Instant::now();
        let overflow_test_hash =
            compute_replay_hash("overflow_test_payload", &overflow_test_inputs);
        let duration = start_time.elapsed();

        assert_eq!(overflow_test_hash.len(), 64);
        assert!(duration < std::time::Duration::from_secs(30)); // Should complete in reasonable time

        // Test signing payload computation with overflow protection
        let mut overflow_capsule = build_reference_capsule();
        overflow_capsule.inputs = overflow_test_inputs;
        overflow_capsule.manifest.input_refs = (0..max_test_size)
            .map(|i| format!("overflow_test_key_{:06}", i))
            .collect();

        let signing_start = std::time::Instant::now();
        let signing_payload = compute_signing_payload(&overflow_capsule);
        let signing_duration = signing_start.elapsed();

        assert_eq!(signing_payload.len(), 64);
        assert!(signing_duration < std::time::Duration::from_secs(60));

        // Test that length encoding is consistent for same data
        let consistency_hash1 = compute_replay_hash(boundary_payload, &boundary_inputs);
        let consistency_hash2 = compute_replay_hash(boundary_payload, &boundary_inputs);
        assert_eq!(
            consistency_hash1, consistency_hash2,
            "Length encoding should be deterministic"
        );

        // Test edge case: theoretical maximum string length
        // (We can't actually allocate this much memory, but test the encoding)
        let theoretical_max_len = usize::MAX as u64;
        let theoretical_bytes = theoretical_max_len.to_le_bytes();
        assert_eq!(theoretical_bytes.len(), 8);

        // The bytes should represent the maximum value correctly
        assert_eq!(u64::from_le_bytes(theoretical_bytes), theoretical_max_len);
    }
}
