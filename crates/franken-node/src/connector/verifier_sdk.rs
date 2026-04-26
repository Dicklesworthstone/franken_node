//! bd-3c2: Verifier-economy SDK with independent validation workflows (Section 10.12).
//!
//! Implements a verifier SDK that enables independent third parties to verify
//! claims, migration artifacts, trust state, and replay capsules. The SDK is
//! the bridge to the verifier economy, making independent verification easy
//! and reliable.
//!
//! # Capabilities
//!
//! - Verify claims against evidence bundles
//! - Verify migration artifacts (signature, schema, preconditions, rollback)
//! - Verify trust state against anchors (chain of trust)
//! - Replay capsules and compare outputs
//! - Self-contained evidence bundles for offline verification
//! - Transparency log entries with merkle proofs
//! - Validation workflows for release, incident, and compliance contexts
//!
//! # Invariants
//!
//! - **INV-VER-DETERMINISTIC**: Same inputs always produce the same verification result.
//! - **INV-VER-OFFLINE-CAPABLE**: All core verification operations work without network.
//! - **INV-VER-EVIDENCE-BOUND**: A verification result is cryptographically bound to its evidence.
//! - **INV-VER-RESULT-SIGNED**: Every verification result carries a verifier signature.
//! - **INV-VER-TRANSPARENCY-APPEND**: Transparency log entries are append-only and hash-chained.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Maximum transparency log entries before oldest are evicted.
const MAX_TRANSPARENCY_LOG_ENTRIES: usize = 8192;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Claim verified successfully.
    pub const VER_CLAIM_VERIFIED: &str = "VER-001";
    /// Claim verification failed.
    pub const VER_CLAIM_FAILED: &str = "VER-002";
    /// Migration artifact verified.
    pub const VER_MIGRATION_VERIFIED: &str = "VER-003";
    /// Trust state verified.
    pub const VER_TRUST_STATE_VERIFIED: &str = "VER-004";
    /// Replay completed.
    pub const VER_REPLAY_COMPLETED: &str = "VER-005";
    /// Verification result signed.
    pub const VER_RESULT_SIGNED: &str = "VER-006";
    /// Transparency log entry appended.
    pub const VER_TRANSPARENCY_LOG_APPENDED: &str = "VER-007";
    /// Evidence bundle validated.
    pub const VER_BUNDLE_VALIDATED: &str = "VER-008";
    /// Offline verification check performed.
    pub const VER_OFFLINE_CHECK: &str = "VER-009";
    /// Validation workflow completed.
    pub const VER_WORKFLOW_COMPLETED: &str = "VER-010";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_VER_INVALID_CLAIM: &str = "ERR_VER_INVALID_CLAIM";
    pub const ERR_VER_EVIDENCE_MISSING: &str = "ERR_VER_EVIDENCE_MISSING";
    pub const ERR_VER_SIGNATURE_INVALID: &str = "ERR_VER_SIGNATURE_INVALID";
    pub const ERR_VER_HASH_MISMATCH: &str = "ERR_VER_HASH_MISMATCH";
    pub const ERR_VER_REPLAY_DIVERGED: &str = "ERR_VER_REPLAY_DIVERGED";
    pub const ERR_VER_ANCHOR_UNKNOWN: &str = "ERR_VER_ANCHOR_UNKNOWN";
    pub const ERR_VER_BUNDLE_INCOMPLETE: &str = "ERR_VER_BUNDLE_INCOMPLETE";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_VER_DETERMINISTIC: &str = "INV-VER-DETERMINISTIC";
    pub const INV_VER_OFFLINE_CAPABLE: &str = "INV-VER-OFFLINE-CAPABLE";
    pub const INV_VER_EVIDENCE_BOUND: &str = "INV-VER-EVIDENCE-BOUND";
    pub const INV_VER_RESULT_SIGNED: &str = "INV-VER-RESULT-SIGNED";
    pub const INV_VER_TRANSPARENCY_APPEND: &str = "INV-VER-TRANSPARENCY-APPEND";
}

/// Schema version for the verifier SDK format.
pub const SCHEMA_VERSION: &str = "ver-v1.0";

/// Stable posture marker for the hash-only replay helper in this module.
///
/// Replacement-critical signed capsule verification must use the stronger
/// `connector::universal_verifier_sdk` and verifier-economy paths instead.
pub const STRUCTURAL_ONLY_REPLAY_HELPER_POSTURE: &str =
    "structural_only_helper_not_replacement_critical";

/// Stable rule id used by shortcut-regression guardrails.
pub const STRUCTURAL_ONLY_REPLAY_HELPER_RULE_ID: &str =
    "VERIFIER_SHORTCUT_GUARD::CONNECTOR_REPLAY_HELPER";

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// Verification verdict.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

/// A verifiable claim about a subject.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub claim_id: String,
    pub claim_type: String,
    pub subject: String,
    pub assertion: String,
    pub evidence_refs: Vec<String>,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// A single piece of evidence supporting a claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_id: String,
    pub claim_ref: String,
    pub artifacts: BTreeMap<String, String>,
    pub verification_procedure: String,
}

// ---------------------------------------------------------------------------
// EvidenceBundle
// ---------------------------------------------------------------------------

/// A self-contained bundle of a claim and its supporting evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub claim: Claim,
    pub evidence_items: Vec<Evidence>,
    pub self_contained: bool,
}

// ---------------------------------------------------------------------------
// AssertionResult
// ---------------------------------------------------------------------------

/// Result of a single assertion check within a verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssertionResult {
    pub assertion: String,
    pub passed: bool,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Verifier signer
// ---------------------------------------------------------------------------

/// Signing identity used to bind verification results to a concrete verifier key.
#[derive(Clone)]
pub struct VerifierSigner {
    verifier_identity: String,
    signing_key: SigningKey,
}

impl VerifierSigner {
    pub fn from_signing_key(verifier_identity: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            verifier_identity: verifier_identity.into(),
            signing_key,
        }
    }

    pub fn verifier_identity(&self) -> &str {
        &self.verifier_identity
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    fn sign(&self, payload: &[u8]) -> String {
        hex::encode(self.signing_key.sign(payload).to_bytes())
    }
}

// ---------------------------------------------------------------------------
// VerificationResult
// ---------------------------------------------------------------------------

/// The outcome of a verification operation.
///
/// # INV-VER-RESULT-SIGNED
/// Every result carries a non-empty `verifier_signature`.
///
/// # INV-VER-EVIDENCE-BOUND
/// The `artifact_binding_hash` binds the result to the evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verdict: Verdict,
    pub confidence_score: f64,
    pub checked_assertions: Vec<AssertionResult>,
    pub execution_timestamp: String,
    pub verifier_identity: String,
    pub signature_algorithm: String,
    pub verifier_public_key: String,
    pub artifact_binding_hash: String,
    pub verifier_signature: String,
}

// ---------------------------------------------------------------------------
// ReplayResult
// ---------------------------------------------------------------------------

/// The outcome of replaying a capsule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayResult {
    pub verdict: Verdict,
    pub expected_output_hash: String,
    pub actual_output_hash: String,
    pub replay_duration_ms: u64,
}

// ---------------------------------------------------------------------------
// ValidationWorkflow
// ---------------------------------------------------------------------------

/// Workflow context for structured validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationWorkflow {
    ReleaseValidation,
    IncidentValidation,
    ComplianceAudit,
}

// ---------------------------------------------------------------------------
// TransparencyLogEntry
// ---------------------------------------------------------------------------

/// An append-only transparency log entry.
///
/// # INV-VER-TRANSPARENCY-APPEND
/// Entries are hash-chained; each `result_hash` covers the verification result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    pub result_hash: String,
    pub timestamp: String,
    pub verifier_id: String,
    pub merkle_proof: Vec<String>,
}

// ---------------------------------------------------------------------------
// VerifierSdkEvent
// ---------------------------------------------------------------------------

/// Structured audit event for verifier SDK operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierSdkEvent {
    pub event_code: String,
    pub detail: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// VerifierSdkError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum VerifierSdkError {
    InvalidClaim(String),
    EvidenceMissing(String),
    SignatureInvalid(String),
    HashMismatch { expected: String, actual: String },
    ReplayDiverged { expected: String, actual: String },
    AnchorUnknown(String),
    BundleIncomplete(String),
}

impl std::fmt::Display for VerifierSdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidClaim(msg) => write!(f, "{}: {msg}", error_codes::ERR_VER_INVALID_CLAIM),
            Self::EvidenceMissing(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VER_EVIDENCE_MISSING)
            }
            Self::SignatureInvalid(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VER_SIGNATURE_INVALID)
            }
            Self::HashMismatch { expected, actual } => {
                write!(
                    f,
                    "{}: expected={expected}, actual={actual}",
                    error_codes::ERR_VER_HASH_MISMATCH
                )
            }
            Self::ReplayDiverged { expected, actual } => {
                write!(
                    f,
                    "{}: expected={expected}, actual={actual}",
                    error_codes::ERR_VER_REPLAY_DIVERGED
                )
            }
            Self::AnchorUnknown(msg) => write!(f, "{}: {msg}", error_codes::ERR_VER_ANCHOR_UNKNOWN),
            Self::BundleIncomplete(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VER_BUNDLE_INCOMPLETE)
            }
        }
    }
}

impl std::error::Error for VerifierSdkError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a deterministic hash over a string (hex-encoded SHA-256).
/// INV-VER-DETERMINISTIC: same inputs always produce the same output.
fn deterministic_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"connector_verifier_sdk_v1:");
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn append_length_prefixed(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn strip_ed25519_prefix(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed
        .as_bytes()
        .get(0..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"ed25519:"))
    {
        &trimmed[8..]
    } else {
        trimmed
    }
}

fn hex_blob(raw: &str, expected_len: usize) -> Result<Vec<u8>, VerifierSdkError> {
    let normalized = strip_ed25519_prefix(raw);
    let decoded = hex::decode(normalized).map_err(|_| {
        VerifierSdkError::SignatureInvalid("signature or public key is not valid hex".to_string())
    })?;
    if decoded.len() != expected_len {
        return Err(VerifierSdkError::SignatureInvalid(format!(
            "signature or public key has invalid length {} (expected {expected_len})",
            decoded.len()
        )));
    }
    Ok(decoded)
}

fn canonicalize_ed25519_public_key_hex(public_key: &str) -> Result<String, VerifierSdkError> {
    Ok(hex::encode(hex_blob(public_key, 32)?))
}

fn is_sha256_hex(value: &str) -> bool {
    let normalized = value.strip_prefix("sha256:").unwrap_or(value);
    normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn normalize_sha256_prefixed(value: &str) -> Option<String> {
    if !is_sha256_hex(value) {
        return None;
    }
    Some(match value.strip_prefix("sha256:") {
        Some(normalized) => format!("sha256:{normalized}"),
        None => format!("sha256:{value}"),
    })
}

fn hash_trace_commitment_pair(left: &str, right: &str) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"connector_trace_commitment_v1:");
    append_length_prefixed(&mut payload, left);
    append_length_prefixed(&mut payload, right);
    format!("sha256:{}", hex::encode(Sha256::digest(payload)))
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TraceCommitmentProofStep {
    pub sibling_hash: String,
    pub sibling_on_left: bool,
}

pub(crate) fn compute_trace_commitment_root(trace_chunk_hashes: &[String]) -> Option<String> {
    if trace_chunk_hashes.is_empty() {
        return None;
    }

    let mut level = trace_chunk_hashes
        .iter()
        .map(|hash| normalize_sha256_prefixed(hash))
        .collect::<Option<Vec<_>>>()?;

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        let mut index = 0;
        while index < level.len() {
            let left = &level[index];
            let right = level.get(index + 1).unwrap_or(left);
            next_level.push(hash_trace_commitment_pair(left, right));
            index += 2;
        }
        level = next_level;
    }

    level.into_iter().next()
}

#[cfg(test)]
pub(crate) fn build_trace_commitment_proof(
    trace_chunk_hashes: &[String],
    leaf_index: usize,
) -> Option<Vec<TraceCommitmentProofStep>> {
    if trace_chunk_hashes.is_empty() || leaf_index >= trace_chunk_hashes.len() {
        return None;
    }

    let mut level = trace_chunk_hashes
        .iter()
        .map(|hash| normalize_sha256_prefixed(hash))
        .collect::<Option<Vec<_>>>()?;
    let mut proof = Vec::new();
    let mut index = leaf_index;

    while level.len() > 1 {
        let sibling_index = if index.is_multiple_of(2) {
            (index + 1).min(level.len() - 1)
        } else {
            index - 1
        };
        proof.push(TraceCommitmentProofStep {
            sibling_hash: level[sibling_index].clone(),
            sibling_on_left: sibling_index < index,
        });

        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        let mut pair_index = 0;
        while pair_index < level.len() {
            let left = &level[pair_index];
            let right = level.get(pair_index + 1).unwrap_or(left);
            next_level.push(hash_trace_commitment_pair(left, right));
            pair_index += 2;
        }
        index /= 2;
        level = next_level;
    }

    Some(proof)
}

#[cfg(test)]
pub(crate) fn verify_trace_commitment_proof(
    trace_chunk_hash: &str,
    proof: &[TraceCommitmentProofStep],
    expected_root: &str,
) -> bool {
    let mut current = match normalize_sha256_prefixed(trace_chunk_hash) {
        Some(hash) => hash,
        None => return false,
    };
    let expected_root = match normalize_sha256_prefixed(expected_root) {
        Some(hash) => hash,
        None => return false,
    };

    for step in proof {
        let sibling_hash = match normalize_sha256_prefixed(&step.sibling_hash) {
            Some(hash) => hash,
            None => return false,
        };
        current = if step.sibling_on_left {
            hash_trace_commitment_pair(&sibling_hash, &current)
        } else {
            hash_trace_commitment_pair(&current, &sibling_hash)
        };
    }

    crate::security::constant_time::ct_eq(&current, &expected_root)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_capsule_integrity_hash(
    capsule_id: &str,
    schema_version: &str,
    attestation_id: &str,
    verifier_id: &str,
    claim_metadata_hash: &str,
    issued_at: &str,
    expires_at: &str,
    input_state_hash: &str,
    trace_commitment_root: &str,
    output_state_hash: &str,
    expected_result_hash: &str,
) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"connector_signed_capsule_integrity_v2:");
    for field in [
        capsule_id,
        schema_version,
        attestation_id,
        verifier_id,
        claim_metadata_hash,
        issued_at,
        expires_at,
        input_state_hash,
        trace_commitment_root,
        output_state_hash,
        expected_result_hash,
    ] {
        append_length_prefixed(&mut payload, field);
    }

    format!("sha256:{}", hex::encode(Sha256::digest(payload)))
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn replay_capsule_signature_payload(
    capsule_id: &str,
    schema_version: &str,
    attestation_id: &str,
    verifier_id: &str,
    claim_metadata_hash: &str,
    issued_at: &str,
    expires_at: &str,
    input_state_hash: &str,
    trace_chunk_hashes: &[String],
    trace_commitment_root: &str,
    output_state_hash: &str,
    expected_result_hash: &str,
    integrity_hash: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"connector_signed_capsule_signature_v1:");
    for field in [
        capsule_id,
        schema_version,
        attestation_id,
        verifier_id,
        claim_metadata_hash,
        issued_at,
        expires_at,
        input_state_hash,
        trace_commitment_root,
        output_state_hash,
        expected_result_hash,
        integrity_hash,
    ] {
        append_length_prefixed(&mut payload, field);
    }
    payload.extend_from_slice(
        &u64::try_from(trace_chunk_hashes.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for hash in trace_chunk_hashes {
        append_length_prefixed(&mut payload, hash);
    }
    payload
}

pub(crate) fn parse_ed25519_verifying_key_hex(
    public_key: &str,
) -> Result<VerifyingKey, VerifierSdkError> {
    let key_bytes = hex_blob(public_key, 32)?;
    VerifyingKey::from_bytes(
        &key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifierSdkError::SignatureInvalid("invalid verifying key".to_string()))?,
    )
    .map_err(|_| VerifierSdkError::SignatureInvalid("invalid verifying key".to_string()))
}

fn parse_ed25519_signature_hex(signature: &str) -> Result<Signature, VerifierSdkError> {
    let signature_bytes = hex_blob(signature, 64)?;
    Ok(Signature::from_bytes(
        &signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifierSdkError::SignatureInvalid("invalid signature".to_string()))?,
    ))
}

pub(crate) fn verify_ed25519_signature_with_key_hex(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature: &str,
) -> Result<(), VerifierSdkError> {
    let signature = parse_ed25519_signature_hex(signature)?;
    verifying_key.verify(payload, &signature).map_err(|_| {
        VerifierSdkError::SignatureInvalid("signature verification failed".to_string())
    })
}

pub(crate) fn verify_ed25519_signature_hex(
    public_key: &str,
    payload: &[u8],
    signature: &str,
) -> Result<(), VerifierSdkError> {
    let verifying_key = parse_ed25519_verifying_key_hex(public_key)?;
    verify_ed25519_signature_with_key_hex(&verifying_key, payload, signature)
}

fn canonical_migration_artifact_payload(
    artifact: &BTreeMap<String, serde_json::Value>,
) -> Result<Vec<u8>, VerifierSdkError> {
    let mut canonical = artifact.clone();
    canonical.remove("signature");
    canonical.remove("signature_algorithm");
    canonical.remove("signer_public_key");
    serde_json::to_vec(&canonical).map_err(|err| {
        VerifierSdkError::InvalidClaim(format!("artifact canonicalization failed: {err}"))
    })
}

fn migration_artifact_binding_hash(
    canonical_payload: &[u8],
    expected_signer_public_key: &str,
) -> String {
    let canonical_signer_public_key =
        canonicalize_ed25519_public_key_hex(expected_signer_public_key)
            .unwrap_or_else(|_| expected_signer_public_key.trim().to_string());
    let mut hasher = Sha256::new();
    hasher.update(b"connector_verifier_sdk_migration_binding_v2:");
    hasher.update(
        u64::try_from(canonical_payload.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(canonical_payload);
    hasher.update(
        u64::try_from(canonical_signer_public_key.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(canonical_signer_public_key.as_bytes());
    hex::encode(hasher.finalize())
}

struct VerificationResultSignatureView<'a> {
    verdict: &'a Verdict,
    confidence_score: f64,
    checked_assertions: &'a [AssertionResult],
    execution_timestamp: &'a str,
    verifier_identity: &'a str,
    signature_algorithm: &'a str,
    verifier_public_key: &'a str,
    artifact_binding_hash: &'a str,
}

fn verification_result_signature_payload(view: &VerificationResultSignatureView<'_>) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"connector_verifier_sdk_result_v1:");
    append_length_prefixed(
        &mut payload,
        match view.verdict {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Inconclusive => "inconclusive",
        },
    );
    payload.extend_from_slice(&view.confidence_score.to_bits().to_le_bytes());
    payload.extend_from_slice(
        &u64::try_from(view.checked_assertions.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for assertion in view.checked_assertions {
        append_length_prefixed(&mut payload, &assertion.assertion);
        payload.push(u8::from(assertion.passed));
        append_length_prefixed(&mut payload, &assertion.detail);
    }
    for field in [
        view.execution_timestamp,
        view.verifier_identity,
        view.signature_algorithm,
        view.verifier_public_key,
        view.artifact_binding_hash,
    ] {
        append_length_prefixed(&mut payload, field);
    }
    payload
}

fn build_signed_verification_result(
    verdict: Verdict,
    confidence_score: f64,
    checked_assertions: Vec<AssertionResult>,
    artifact_binding_hash: String,
    signer: &VerifierSigner,
) -> VerificationResult {
    // Defense in depth: NaN/Inf confidence is nonsensical — clamp to 0.0.
    let confidence_score = if confidence_score.is_finite() {
        confidence_score
    } else {
        0.0
    };
    let execution_timestamp = now_timestamp();
    let signature_algorithm = "ed25519".to_string();
    let verifier_public_key = signer.public_key_hex();
    let payload = verification_result_signature_payload(&VerificationResultSignatureView {
        verdict: &verdict,
        confidence_score,
        checked_assertions: &checked_assertions,
        execution_timestamp: &execution_timestamp,
        verifier_identity: signer.verifier_identity(),
        signature_algorithm: &signature_algorithm,
        verifier_public_key: &verifier_public_key,
        artifact_binding_hash: &artifact_binding_hash,
    });
    let verifier_signature = signer.sign(&payload);

    VerificationResult {
        verdict,
        confidence_score,
        checked_assertions,
        execution_timestamp,
        verifier_identity: signer.verifier_identity().to_string(),
        signature_algorithm,
        verifier_public_key,
        artifact_binding_hash,
        verifier_signature,
    }
}

pub fn verify_verification_result_signature(
    result: &VerificationResult,
) -> Result<(), VerifierSdkError> {
    if !result.signature_algorithm.eq_ignore_ascii_case("ed25519") {
        return Err(VerifierSdkError::SignatureInvalid(format!(
            "unsupported signature algorithm {}",
            result.signature_algorithm
        )));
    }

    let payload = verification_result_signature_payload(&VerificationResultSignatureView {
        verdict: &result.verdict,
        confidence_score: result.confidence_score,
        checked_assertions: &result.checked_assertions,
        execution_timestamp: &result.execution_timestamp,
        verifier_identity: &result.verifier_identity,
        signature_algorithm: &result.signature_algorithm,
        verifier_public_key: &result.verifier_public_key,
        artifact_binding_hash: &result.artifact_binding_hash,
    });
    verify_ed25519_signature_hex(
        &result.verifier_public_key,
        &payload,
        &result.verifier_signature,
    )
}

/// Compute the binding hash for a claim and its evidence items.
/// INV-VER-EVIDENCE-BOUND: result is bound to evidence.
fn compute_binding_hash(claim: &Claim, evidence: &[Evidence]) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"connector_verifier_sdk_binding_v2:");
    // Bind the full claim/evidence surface so a signed verification result
    // cannot be replayed onto a materially different claim.
    for field in [
        claim.claim_id.as_str(),
        claim.claim_type.as_str(),
        claim.subject.as_str(),
        claim.assertion.as_str(),
        claim.timestamp.as_str(),
    ] {
        append_length_prefixed(&mut payload, field);
    }
    payload.extend_from_slice(
        &u64::try_from(claim.evidence_refs.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for evidence_ref in &claim.evidence_refs {
        append_length_prefixed(&mut payload, evidence_ref);
    }
    payload.extend_from_slice(
        &u64::try_from(evidence.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for ev in evidence {
        for field in [
            ev.evidence_id.as_str(),
            ev.claim_ref.as_str(),
            ev.verification_procedure.as_str(),
        ] {
            append_length_prefixed(&mut payload, field);
        }
        payload.extend_from_slice(
            &u64::try_from(ev.artifacts.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        for (k, v) in &ev.artifacts {
            append_length_prefixed(&mut payload, k);
            append_length_prefixed(&mut payload, v);
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    hex::encode(hasher.finalize())
}

fn now_timestamp() -> String {
    "2026-02-21T00:00:00Z".to_string()
}

// ---------------------------------------------------------------------------
// Core verification operations
// ---------------------------------------------------------------------------

/// Verify a claim against its evidence.
///
/// Checks that:
/// 1. The claim has a non-empty claim_id, assertion, and subject.
/// 2. Evidence is non-empty and references the claim.
/// 3. Each evidence item has artifacts.
///
/// INV-VER-OFFLINE-CAPABLE: no network required.
/// INV-VER-DETERMINISTIC: same inputs produce the same result.
/// INV-VER-EVIDENCE-BOUND: result carries artifact_binding_hash.
/// INV-VER-RESULT-SIGNED: result carries verifier_signature.
pub fn verify_claim(
    claim: &Claim,
    evidence: &[Evidence],
    signer: &VerifierSigner,
) -> Result<VerificationResult, VerifierSdkError> {
    let mut assertions = Vec::new();

    // Check claim validity
    let claim_valid =
        !claim.claim_id.is_empty() && !claim.assertion.is_empty() && !claim.subject.is_empty();
    assertions.push(AssertionResult {
        assertion: "claim_fields_present".to_string(),
        passed: claim_valid,
        detail: if claim_valid {
            "claim has required fields".to_string()
        } else {
            "claim missing required fields".to_string()
        },
    });

    if !claim_valid {
        return Err(VerifierSdkError::InvalidClaim(
            "claim missing required fields".to_string(),
        ));
    }

    // Check evidence non-empty
    if evidence.is_empty() {
        return Err(VerifierSdkError::EvidenceMissing(
            "no evidence provided".to_string(),
        ));
    }

    assertions.push(AssertionResult {
        assertion: "evidence_present".to_string(),
        passed: true,
        detail: format!("{} evidence items", evidence.len()),
    });

    // INV-VER-EVIDENCE-BOUND: Bind claim.evidence_refs to actual evidence_ids.
    // Every declared evidence_ref must have a matching evidence item, and every
    // evidence item must be declared in evidence_refs.
    {
        let declared: std::collections::BTreeSet<&str> =
            claim.evidence_refs.iter().map(|s| s.as_str()).collect();
        let provided: std::collections::BTreeSet<&str> =
            evidence.iter().map(|e| e.evidence_id.as_str()).collect();

        let undeclared: Vec<&str> = provided.difference(&declared).copied().collect();
        let missing: Vec<&str> = declared.difference(&provided).copied().collect();

        let refs_bound = undeclared.is_empty() && missing.is_empty();
        assertions.push(AssertionResult {
            assertion: "evidence_refs_binding".to_string(),
            passed: refs_bound,
            detail: if refs_bound {
                "all evidence_refs match provided evidence_ids".to_string()
            } else {
                format!("evidence_refs mismatch: undeclared={undeclared:?}, missing={missing:?}")
            },
        });

        if !refs_bound {
            return Err(VerifierSdkError::EvidenceMissing(format!(
                "evidence_refs binding failed: undeclared={undeclared:?}, missing={missing:?}"
            )));
        }
    }

    // Check each evidence item
    let mut all_pass = true;
    for ev in evidence {
        let refs_match = ev.claim_ref == claim.claim_id;
        assertions.push(AssertionResult {
            assertion: format!("evidence_{}_refs_claim", ev.evidence_id),
            passed: refs_match,
            detail: if refs_match {
                "references correct claim".to_string()
            } else {
                format!("claim_ref={} != claim_id={}", ev.claim_ref, claim.claim_id)
            },
        });
        if !refs_match {
            all_pass = false;
        }

        let has_artifacts = !ev.artifacts.is_empty();
        assertions.push(AssertionResult {
            assertion: format!("evidence_{}_has_artifacts", ev.evidence_id),
            passed: has_artifacts,
            detail: if has_artifacts {
                format!("{} artifacts", ev.artifacts.len())
            } else {
                "no artifacts".to_string()
            },
        });
        if !has_artifacts {
            all_pass = false;
        }

        let has_procedure = !ev.verification_procedure.is_empty();
        assertions.push(AssertionResult {
            assertion: format!("evidence_{}_has_procedure", ev.evidence_id),
            passed: has_procedure,
            detail: if has_procedure {
                "procedure defined".to_string()
            } else {
                "no procedure".to_string()
            },
        });
        if !has_procedure {
            all_pass = false;
        }
    }

    let verdict = if all_pass {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    let confidence = if all_pass { 1.0 } else { 0.0 };
    let binding_hash = compute_binding_hash(claim, evidence);
    Ok(build_signed_verification_result(
        verdict,
        confidence,
        assertions,
        binding_hash,
        signer,
    ))
}

/// Verify a migration artifact: signature, schema, preconditions, rollback receipt.
///
/// INV-VER-OFFLINE-CAPABLE: no network required.
/// INV-VER-DETERMINISTIC: same inputs produce the same result.
pub fn verify_migration_artifact(
    artifact: &BTreeMap<String, serde_json::Value>,
    expected_signer_public_key: &str,
    signer: &VerifierSigner,
) -> Result<VerificationResult, VerifierSdkError> {
    let mut assertions = Vec::new();

    // Check schema_version
    let sv = artifact
        .get("schema_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sv_ok = !sv.is_empty();
    assertions.push(AssertionResult {
        assertion: "schema_version_present".to_string(),
        passed: sv_ok,
        detail: if sv_ok {
            format!("schema_version={sv}")
        } else {
            "missing".to_string()
        },
    });

    // Check signature
    let sig = artifact
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let signature_algorithm = artifact
        .get("signature_algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let signer_public_key = artifact
        .get("signer_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let signature_payload = canonical_migration_artifact_payload(artifact)?;
    let canonical_expected_signer_public_key =
        canonicalize_ed25519_public_key_hex(expected_signer_public_key).ok();
    let canonical_signer_public_key = canonicalize_ed25519_public_key_hex(signer_public_key).ok();
    let signer_key_matches_expected = !expected_signer_public_key.is_empty()
        && canonical_expected_signer_public_key
            .as_deref()
            .zip(canonical_signer_public_key.as_deref())
            .is_some_and(|(expected, actual)| {
                crate::security::constant_time::ct_eq(actual, expected)
            });
    let sig_ok = signature_algorithm.eq_ignore_ascii_case("ed25519")
        && signer_key_matches_expected
        && verify_ed25519_signature_hex(signer_public_key, &signature_payload, sig).is_ok();
    assertions.push(AssertionResult {
        assertion: "signer_public_key_matches_expected".to_string(),
        passed: signer_key_matches_expected,
        detail: if signer_key_matches_expected {
            "artifact signer matches trusted key".to_string()
        } else {
            format!(
                "trusted signer mismatch: expected={}, actual={}",
                canonical_expected_signer_public_key
                    .as_deref()
                    .unwrap_or(expected_signer_public_key),
                canonical_signer_public_key
                    .as_deref()
                    .unwrap_or(signer_public_key)
            )
        },
    });
    assertions.push(AssertionResult {
        assertion: "signature_valid".to_string(),
        passed: sig_ok,
        detail: if sig_ok {
            "ed25519 signature verified".to_string()
        } else {
            "signature missing or invalid".to_string()
        },
    });

    // Check content_hash
    let ch = artifact
        .get("content_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let ch_ok = is_sha256_hex(ch);
    assertions.push(AssertionResult {
        assertion: "content_hash_valid".to_string(),
        passed: ch_ok,
        detail: if ch_ok {
            "sha256 digest shape valid".to_string()
        } else {
            format!("invalid hash shape: {ch}")
        },
    });

    // Check rollback_receipt
    let rb = artifact.get("rollback_receipt");
    let rb_ok = rb.is_some_and(|v| v.is_object());
    assertions.push(AssertionResult {
        assertion: "rollback_receipt_present".to_string(),
        passed: rb_ok,
        detail: if rb_ok {
            "rollback receipt present".to_string()
        } else {
            "missing".to_string()
        },
    });

    // Check preconditions
    let pre = artifact.get("preconditions");
    let pre_ok = pre.is_some_and(|v| v.is_array());
    assertions.push(AssertionResult {
        assertion: "preconditions_present".to_string(),
        passed: pre_ok,
        detail: if pre_ok {
            "preconditions present".to_string()
        } else {
            "missing".to_string()
        },
    });

    let all_pass = assertions.iter().all(|a| a.passed);
    let verdict = if all_pass {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    let confidence = if all_pass { 1.0 } else { 0.0 };
    let binding_hash =
        migration_artifact_binding_hash(&signature_payload, expected_signer_public_key);
    Ok(build_signed_verification_result(
        verdict,
        confidence,
        assertions,
        binding_hash,
        signer,
    ))
}

/// Verify trust state against a trust anchor.
///
/// INV-VER-OFFLINE-CAPABLE: no network required.
/// INV-VER-DETERMINISTIC: same inputs produce the same result.
pub fn verify_trust_state(
    state: &BTreeMap<String, String>,
    anchor: &BTreeMap<String, String>,
    signer: &VerifierSigner,
) -> Result<VerificationResult, VerifierSdkError> {
    let mut assertions = Vec::new();

    // Check anchor is non-empty
    if anchor.is_empty() {
        return Err(VerifierSdkError::AnchorUnknown(
            "trust anchor is empty".to_string(),
        ));
    }

    assertions.push(AssertionResult {
        assertion: "anchor_present".to_string(),
        passed: true,
        detail: format!("{} anchor entries", anchor.len()),
    });

    // Check state is non-empty
    let state_ok = !state.is_empty();
    assertions.push(AssertionResult {
        assertion: "state_present".to_string(),
        passed: state_ok,
        detail: if state_ok {
            format!("{} state entries", state.len())
        } else {
            "state is empty".to_string()
        },
    });

    // Chain-of-trust: verify that each anchor key present in state matches
    let mut chain_ok = true;
    for (key, expected) in anchor {
        let actual = state.get(key).map(|s| s.as_str()).unwrap_or("");
        let matches = crate::security::constant_time::ct_eq(actual, expected);
        assertions.push(AssertionResult {
            assertion: format!("chain_trust_{key}"),
            passed: matches,
            detail: if matches {
                format!("{key} matches anchor")
            } else {
                format!("{key}: expected={expected}, actual={actual}")
            },
        });
        if !matches {
            chain_ok = false;
        }
    }

    let all_pass = state_ok && chain_ok;
    let verdict = if all_pass {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    let confidence = if all_pass { 1.0 } else { 0.0 };

    let mut hasher = Sha256::new();
    hasher.update(b"connector_verifier_sdk_state_binding_v1:");
    hasher.update(u64::try_from(state.len()).unwrap_or(u64::MAX).to_le_bytes());
    for (k, v) in state {
        hasher.update(u64::try_from(k.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(k.as_bytes());
        hasher.update(u64::try_from(v.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(v.as_bytes());
    }
    hasher.update(
        u64::try_from(anchor.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (k, v) in anchor {
        hasher.update(u64::try_from(k.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(k.as_bytes());
        hasher.update(u64::try_from(v.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(v.as_bytes());
    }
    let binding_hash = hex::encode(hasher.finalize());
    Ok(build_signed_verification_result(
        verdict,
        confidence,
        assertions,
        binding_hash,
        signer,
    ))
}

/// Replay a capsule and compare outputs.
///
/// INV-VER-OFFLINE-CAPABLE: replay is local.
/// INV-VER-DETERMINISTIC: same capsule produces the same result.
/// `STRUCTURAL_ONLY_REPLAY_HELPER_POSTURE` applies here: this helper is a
/// deterministic smoke-check, not a signed replacement-critical verifier.
pub fn replay_capsule(capsule_data: &str, expected_output_hash: &str) -> ReplayResult {
    // Compute deterministic hash of capsule data as actual output
    let actual_hash = deterministic_hash(capsule_data);
    let matches = crate::security::constant_time::ct_eq(&actual_hash, expected_output_hash);

    ReplayResult {
        verdict: if matches {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        expected_output_hash: expected_output_hash.to_string(),
        actual_output_hash: actual_hash,
        replay_duration_ms: 0,
    }
}

// ---------------------------------------------------------------------------
// Bundle validation
// ---------------------------------------------------------------------------

/// Validate an evidence bundle for completeness.
///
/// INV-VER-OFFLINE-CAPABLE: purely local check.
pub fn validate_bundle(bundle: &EvidenceBundle) -> Result<(), VerifierSdkError> {
    if bundle.claim.claim_id.is_empty() {
        return Err(VerifierSdkError::BundleIncomplete(
            "bundle claim has no claim_id".to_string(),
        ));
    }
    if bundle.evidence_items.is_empty() {
        return Err(VerifierSdkError::BundleIncomplete(
            "bundle has no evidence items".to_string(),
        ));
    }
    for ev in &bundle.evidence_items {
        if ev.claim_ref != bundle.claim.claim_id {
            return Err(VerifierSdkError::BundleIncomplete(format!(
                "evidence {} references {} but claim is {}",
                ev.evidence_id, ev.claim_ref, bundle.claim.claim_id
            )));
        }
    }
    // INV-VER-EVIDENCE-BOUND: every declared evidence_ref must have a matching
    // evidence item, and every evidence item must appear in evidence_refs.
    let declared: std::collections::BTreeSet<&str> = bundle
        .claim
        .evidence_refs
        .iter()
        .map(|s| s.as_str())
        .collect();
    let provided: std::collections::BTreeSet<&str> = bundle
        .evidence_items
        .iter()
        .map(|e| e.evidence_id.as_str())
        .collect();
    if declared != provided {
        let undeclared: Vec<&str> = provided.difference(&declared).copied().collect();
        let missing: Vec<&str> = declared.difference(&provided).copied().collect();
        return Err(VerifierSdkError::BundleIncomplete(format!(
            "evidence_refs binding failed: undeclared={undeclared:?}, missing={missing:?}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Transparency log
// ---------------------------------------------------------------------------

/// Append a verification result to the transparency log.
///
/// INV-VER-TRANSPARENCY-APPEND: entries are append-only.
pub fn append_transparency_log(
    log: &mut Vec<TransparencyLogEntry>,
    result: &VerificationResult,
) -> Result<TransparencyLogEntry, VerifierSdkError> {
    verify_verification_result_signature(result)?;
    let result_hash = deterministic_hash(
        &serde_json::to_string(result).unwrap_or_else(|e| format!("__serde_err:{e}")),
    );
    let prev_hash = log
        .last()
        .map(|e| e.result_hash.clone())
        .unwrap_or_else(|| "0".repeat(64));
    let merkle_proof = vec![prev_hash, result_hash.clone()];

    let entry = TransparencyLogEntry {
        result_hash,
        timestamp: now_timestamp(),
        verifier_id: result.verifier_identity.clone(),
        merkle_proof,
    };
    push_bounded(log, entry.clone(), MAX_TRANSPARENCY_LOG_ENTRIES);
    Ok(entry)
}

// ---------------------------------------------------------------------------
// Workflow execution
// ---------------------------------------------------------------------------

/// Execute a validation workflow on a bundle.
///
/// INV-VER-OFFLINE-CAPABLE: works without network.
pub fn execute_workflow(
    workflow: &ValidationWorkflow,
    bundle: &EvidenceBundle,
    signer: &VerifierSigner,
) -> Result<VerificationResult, VerifierSdkError> {
    validate_bundle(bundle)?;

    let result = verify_claim(&bundle.claim, &bundle.evidence_items, signer)?;

    // Workflow-specific checks add assertion context but same core logic
    let mut assertions = result.checked_assertions.clone();
    let workflow_name = match workflow {
        ValidationWorkflow::ReleaseValidation => "release_validation",
        ValidationWorkflow::IncidentValidation => "incident_validation",
        ValidationWorkflow::ComplianceAudit => "compliance_audit",
    };
    assertions.push(AssertionResult {
        assertion: format!("workflow_{workflow_name}"),
        passed: true,
        detail: format!("workflow {workflow_name} executed"),
    });

    Ok(build_signed_verification_result(
        result.verdict,
        result.confidence_score,
        assertions,
        result.artifact_binding_hash,
        signer,
    ))
}

// ---------------------------------------------------------------------------
// Reference generators
// ---------------------------------------------------------------------------

/// Generate a reference claim for testing.
pub fn generate_reference_claim() -> Claim {
    Claim {
        claim_id: "claim-ref-001".to_string(),
        claim_type: "migration_safety".to_string(),
        subject: "plan-ref-001".to_string(),
        assertion: "Migration plan satisfies rollback safety invariants".to_string(),
        evidence_refs: vec!["ev-ref-001".to_string(), "ev-ref-002".to_string()],
        timestamp: "2026-02-21T00:00:00Z".to_string(),
    }
}

/// Generate reference evidence for testing.
pub fn generate_reference_evidence() -> Vec<Evidence> {
    let mut artifacts_1 = BTreeMap::new();
    artifacts_1.insert("signature".to_string(), "sig_abc123".to_string());
    artifacts_1.insert("hash".to_string(), "aa".repeat(32));
    artifacts_1.insert("timestamp".to_string(), "2026-02-21T00:00:00Z".to_string());

    let mut artifacts_2 = BTreeMap::new();
    artifacts_2.insert("signature".to_string(), "sig_def456".to_string());
    artifacts_2.insert("hash".to_string(), "bb".repeat(32));
    artifacts_2.insert("timestamp".to_string(), "2026-02-21T00:00:00Z".to_string());

    vec![
        Evidence {
            evidence_id: "ev-ref-001".to_string(),
            claim_ref: "claim-ref-001".to_string(),
            artifacts: artifacts_1,
            verification_procedure: "Check signature against operator key and compare hash"
                .to_string(),
        },
        Evidence {
            evidence_id: "ev-ref-002".to_string(),
            claim_ref: "claim-ref-001".to_string(),
            artifacts: artifacts_2,
            verification_procedure: "Verify rollback receipt and replay capsule output".to_string(),
        },
    ]
}

/// Generate a reference evidence bundle for testing.
pub fn generate_reference_bundle() -> EvidenceBundle {
    EvidenceBundle {
        claim: generate_reference_claim(),
        evidence_items: generate_reference_evidence(),
        self_contained: true,
    }
}

/// Generate a reference verification result for testing.
pub fn generate_reference_verification_result() -> Result<VerificationResult, VerifierSdkError> {
    let claim = generate_reference_claim();
    let evidence = generate_reference_evidence();
    let signer = VerifierSigner::from_signing_key(
        "verifier://test@example.com",
        SigningKey::from_bytes(&[42; 32]),
    );
    verify_claim(&claim, &evidence, &signer)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::constant_time;
    use ed25519_dalek::{Signer, SigningKey};

    // ── Reference generators ────────────────────────────────────────

    #[test]
    fn test_generate_reference_claim() {
        let claim = generate_reference_claim();
        assert_eq!(claim.claim_id, "claim-ref-001");
        assert!(!claim.assertion.is_empty());
        assert!(!claim.subject.is_empty());
        assert_eq!(claim.evidence_refs.len(), 2);
    }

    #[test]
    fn test_generate_reference_evidence() {
        let evidence = generate_reference_evidence();
        assert_eq!(evidence.len(), 2);
        for ev in &evidence {
            assert!(!ev.artifacts.is_empty());
            assert!(!ev.verification_procedure.is_empty());
        }
    }

    #[test]
    fn test_generate_reference_bundle() {
        let bundle = generate_reference_bundle();
        assert!(bundle.self_contained);
        assert_eq!(bundle.evidence_items.len(), 2);
        assert_eq!(bundle.claim.claim_id, "claim-ref-001");
    }

    #[test]
    fn test_generate_reference_verification_result() {
        let result = generate_reference_verification_result().unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
        assert!(!result.verifier_signature.is_empty());
        assert!(!result.artifact_binding_hash.is_empty());
    }

    // ── verify_claim ────────────────────────────────────────────────

    #[test]
    fn test_verify_claim_pass() {
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let signer = test_verifier_signer("verifier-1", 1);
        let result = verify_claim(&claim, &evidence, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.confidence_score, 1.0);
    }

    #[test]
    fn test_verify_claim_empty_claim_id_fails() {
        let mut claim = generate_reference_claim();
        claim.claim_id = String::new();
        let evidence = generate_reference_evidence();
        let signer = test_verifier_signer("v1", 1);
        let err = verify_claim(&claim, &evidence, &signer);
        assert!(err.is_err());
        match err.unwrap_err() {
            VerifierSdkError::InvalidClaim(_) => {}
            other => unreachable!("expected InvalidClaim, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_claim_empty_assertion_fails() {
        let mut claim = generate_reference_claim();
        claim.assertion = String::new();
        let evidence = generate_reference_evidence();
        let signer = test_verifier_signer("v1", 1);
        let err = verify_claim(&claim, &evidence, &signer);
        assert!(err.is_err());
    }

    #[test]
    fn test_verify_claim_empty_subject_fails() {
        let mut claim = generate_reference_claim();
        claim.subject = String::new();
        let evidence = generate_reference_evidence();
        let signer = test_verifier_signer("v1", 1);
        let err = verify_claim(&claim, &evidence, &signer);
        assert!(err.is_err());
    }

    #[test]
    fn test_verify_claim_no_evidence_fails() {
        let claim = generate_reference_claim();
        let signer = test_verifier_signer("v1", 1);
        let err = verify_claim(&claim, &[], &signer);
        assert!(err.is_err());
        match err.unwrap_err() {
            VerifierSdkError::EvidenceMissing(_) => {}
            other => unreachable!("expected EvidenceMissing, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_claim_mismatched_ref_fails() {
        let claim = generate_reference_claim();
        let mut evidence = generate_reference_evidence();
        evidence[0].claim_ref = "wrong-ref".to_string();
        let signer = test_verifier_signer("v1", 1);
        let result = verify_claim(&claim, &evidence, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
    }

    #[test]
    fn test_verify_claim_empty_artifacts_fails() {
        let claim = generate_reference_claim();
        let mut evidence = generate_reference_evidence();
        evidence[0].artifacts.clear();
        let signer = test_verifier_signer("v1", 1);
        let result = verify_claim(&claim, &evidence, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
    }

    #[test]
    fn test_verify_claim_result_signed() {
        // INV-VER-RESULT-SIGNED
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let signer = test_verifier_signer("v1", 1);
        let result = verify_claim(&claim, &evidence, &signer).unwrap();
        assert!(!result.verifier_signature.is_empty());
        assert_eq!(result.signature_algorithm, "ed25519");
        assert_eq!(result.verifier_public_key, signer.public_key_hex());
        assert_eq!(result.verifier_identity, "v1");
        verify_verification_result_signature(&result).expect("signature must verify");
    }

    #[test]
    fn test_verify_claim_evidence_bound() {
        // INV-VER-EVIDENCE-BOUND
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let signer = test_verifier_signer("v1", 1);
        let result = verify_claim(&claim, &evidence, &signer).unwrap();
        assert!(!result.artifact_binding_hash.is_empty());
        assert_eq!(result.artifact_binding_hash.len(), 64);
    }

    #[test]
    fn test_verify_claim_deterministic() {
        // INV-VER-DETERMINISTIC
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let signer = test_verifier_signer("v1", 1);
        let r1 = verify_claim(&claim, &evidence, &signer).unwrap();
        let r2 = verify_claim(&claim, &evidence, &signer).unwrap();
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.artifact_binding_hash, r2.artifact_binding_hash);
        assert_eq!(r1.verifier_signature, r2.verifier_signature);
        assert_eq!(r1.checked_assertions.len(), r2.checked_assertions.len());
    }

    #[test]
    fn test_verify_claim_binding_hash_changes_with_subject() {
        let claim = generate_reference_claim();
        let mut other_claim = claim.clone();
        other_claim.subject = "plan-ref-002".to_string();
        let evidence = generate_reference_evidence();
        let signer = test_verifier_signer("v1", 1);

        let r1 = verify_claim(&claim, &evidence, &signer).unwrap();
        let r2 = verify_claim(&other_claim, &evidence, &signer).unwrap();

        assert_ne!(r1.artifact_binding_hash, r2.artifact_binding_hash);
        assert_ne!(r1.verifier_signature, r2.verifier_signature);
    }

    #[test]
    fn test_verify_claim_binding_hash_changes_with_verification_procedure() {
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let mut other_evidence = evidence.clone();
        other_evidence[0].verification_procedure =
            "Recompute hash against a different validation recipe".to_string();
        let signer = test_verifier_signer("v1", 1);

        let r1 = verify_claim(&claim, &evidence, &signer).unwrap();
        let r2 = verify_claim(&claim, &other_evidence, &signer).unwrap();

        assert_ne!(r1.artifact_binding_hash, r2.artifact_binding_hash);
        assert_ne!(r1.verifier_signature, r2.verifier_signature);
    }

    // ── verify_migration_artifact ──────────────────────────────────

    #[test]
    fn test_verify_migration_artifact_pass() {
        let signing_key = test_signing_key(7);
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert(
            "rollback_receipt".to_string(),
            serde_json::json!({"key": "val"}),
        );
        artifact.insert("preconditions".to_string(), serde_json::json!(["pre1"]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!(format!("sha256:{}", "aa".repeat(32))),
        );
        sign_migration_artifact(&mut artifact, &signing_key);
        let signer = test_verifier_signer("v1", 1);
        let result = verify_migration_artifact(
            &artifact,
            &hex::encode(signing_key.verifying_key().to_bytes()),
            &signer,
        )
        .unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
        verify_verification_result_signature(&result).expect("signature must verify");
    }

    #[test]
    fn test_verify_migration_artifact_missing_signature() {
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert(
            "rollback_receipt".to_string(),
            serde_json::json!({"key": "val"}),
        );
        artifact.insert("preconditions".to_string(), serde_json::json!(["pre1"]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!(format!("sha256:{}", "aa".repeat(32))),
        );
        let signer = test_verifier_signer("v1", 1);
        let result = verify_migration_artifact(
            &artifact,
            &hex::encode(test_signing_key(7).verifying_key().to_bytes()),
            &signer,
        )
        .unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
    }

    #[test]
    fn test_verify_migration_artifact_deterministic() {
        // INV-VER-DETERMINISTIC
        let signing_key = test_signing_key(9);
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert("rollback_receipt".to_string(), serde_json::json!({}));
        artifact.insert("preconditions".to_string(), serde_json::json!([]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!(format!("sha256:{}", "cc".repeat(32))),
        );
        sign_migration_artifact(&mut artifact, &signing_key);
        let signer = test_verifier_signer("v1", 1);
        let trusted_key = hex::encode(signing_key.verifying_key().to_bytes());
        let r1 = verify_migration_artifact(&artifact, &trusted_key, &signer).unwrap();
        let r2 = verify_migration_artifact(&artifact, &trusted_key, &signer).unwrap();
        assert_eq!(r1.artifact_binding_hash, r2.artifact_binding_hash);
    }

    #[test]
    fn test_verify_migration_artifact_tampered_signature_fails() {
        let signing_key = test_signing_key(11);
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert("rollback_receipt".to_string(), serde_json::json!({}));
        artifact.insert("preconditions".to_string(), serde_json::json!(["pre1"]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!(format!("sha256:{}", "dd".repeat(32))),
        );
        sign_migration_artifact(&mut artifact, &signing_key);
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!(format!("sha256:{}", "ee".repeat(32))),
        );

        let signer = test_verifier_signer("v1", 1);
        let result = verify_migration_artifact(
            &artifact,
            &hex::encode(signing_key.verifying_key().to_bytes()),
            &signer,
        )
        .unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
        assert!(
            result
                .checked_assertions
                .iter()
                .any(|assertion| assertion.assertion == "signature_valid" && !assertion.passed)
        );
    }

    #[test]
    fn test_verify_migration_artifact_accepts_uppercase_embedded_signer_key() {
        let signing_key = test_signing_key(12);
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert("rollback_receipt".to_string(), serde_json::json!({}));
        artifact.insert("preconditions".to_string(), serde_json::json!(["pre1"]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!(format!("sha256:{}", "ef".repeat(32))),
        );
        sign_migration_artifact(&mut artifact, &signing_key);
        artifact.insert(
            "signer_public_key".to_string(),
            serde_json::json!(hex::encode(signing_key.verifying_key().to_bytes()).to_uppercase()),
        );

        let signer = test_verifier_signer("v1", 1);
        let trusted_key = hex::encode(signing_key.verifying_key().to_bytes());
        let result = verify_migration_artifact(&artifact, &trusted_key, &signer).unwrap();

        assert_eq!(result.verdict, Verdict::Pass);
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "signer_public_key_matches_expected" && assertion.passed
        }));
    }

    #[test]
    fn test_verify_migration_artifact_untrusted_embedded_key_fails() {
        let signing_key = test_signing_key(13);
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert("rollback_receipt".to_string(), serde_json::json!({}));
        artifact.insert("preconditions".to_string(), serde_json::json!(["pre1"]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!(format!("sha256:{}", "ef".repeat(32))),
        );
        sign_migration_artifact(&mut artifact, &signing_key);

        let signer = test_verifier_signer("v1", 1);
        let untrusted_key = hex::encode(test_signing_key(99).verifying_key().to_bytes());
        let result = verify_migration_artifact(&artifact, &untrusted_key, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
        assert!(result.checked_assertions.iter().any(|assertion| {
            assertion.assertion == "signer_public_key_matches_expected" && !assertion.passed
        }));
    }

    #[test]
    fn test_migration_artifact_binding_hash_canonicalizes_equivalent_key_encodings() {
        let signing_key = test_signing_key(14);
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert("rollback_receipt".to_string(), serde_json::json!({}));
        artifact.insert("preconditions".to_string(), serde_json::json!(["pre1"]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!(format!("sha256:{}", "f0".repeat(32))),
        );
        sign_migration_artifact(&mut artifact, &signing_key);

        let signature_payload = canonical_migration_artifact_payload(&artifact).unwrap();
        let trusted_key = hex::encode(signing_key.verifying_key().to_bytes());
        let uppercase_key = trusted_key.to_uppercase();
        let prefixed_uppercase_key = format!("ED25519:{uppercase_key}");

        let canonical_hash = migration_artifact_binding_hash(&signature_payload, &trusted_key);
        let uppercase_hash = migration_artifact_binding_hash(&signature_payload, &uppercase_key);
        let prefixed_hash =
            migration_artifact_binding_hash(&signature_payload, &prefixed_uppercase_key);

        assert_eq!(canonical_hash, uppercase_hash);
        assert_eq!(canonical_hash, prefixed_hash);
    }

    #[test]
    fn test_verify_migration_artifact_binding_hash_depends_on_trusted_key_bytes() {
        let signing_key = test_signing_key(15);
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert("rollback_receipt".to_string(), serde_json::json!({}));
        artifact.insert("preconditions".to_string(), serde_json::json!(["pre1"]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!(format!("sha256:{}", "f1".repeat(32))),
        );
        sign_migration_artifact(&mut artifact, &signing_key);

        let signer = test_verifier_signer("v1", 1);
        let trusted_key = hex::encode(signing_key.verifying_key().to_bytes());
        let other_key = format!(
            "ed25519:{}",
            hex::encode(test_signing_key(16).verifying_key().to_bytes()).to_uppercase()
        );
        let trusted = verify_migration_artifact(&artifact, &trusted_key, &signer).unwrap();
        let other = verify_migration_artifact(&artifact, &other_key, &signer).unwrap();

        assert_ne!(trusted.artifact_binding_hash, other.artifact_binding_hash);
        assert_eq!(other.verdict, Verdict::Fail);
    }

    // ── verify_trust_state ────────────────────────────────────────

    #[test]
    fn test_verify_trust_state_pass() {
        let mut state = BTreeMap::new();
        state.insert("root_key".to_string(), "abc123".to_string());
        state.insert("policy_epoch".to_string(), "42".to_string());
        let mut anchor = BTreeMap::new();
        anchor.insert("root_key".to_string(), "abc123".to_string());
        let signer = test_verifier_signer("v1", 1);
        let result = verify_trust_state(&state, &anchor, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn test_verify_trust_state_mismatch() {
        let mut state = BTreeMap::new();
        state.insert("root_key".to_string(), "wrong".to_string());
        let mut anchor = BTreeMap::new();
        anchor.insert("root_key".to_string(), "abc123".to_string());
        let signer = test_verifier_signer("v1", 1);
        let result = verify_trust_state(&state, &anchor, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
    }

    #[test]
    fn test_verify_trust_state_empty_anchor_fails() {
        let mut state = BTreeMap::new();
        state.insert("key".to_string(), "val".to_string());
        let anchor = BTreeMap::new();
        let signer = test_verifier_signer("v1", 1);
        let err = verify_trust_state(&state, &anchor, &signer);
        assert!(err.is_err());
        match err.unwrap_err() {
            VerifierSdkError::AnchorUnknown(_) => {}
            other => unreachable!("expected AnchorUnknown, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_trust_state_deterministic() {
        // INV-VER-DETERMINISTIC
        let mut state = BTreeMap::new();
        state.insert("k".to_string(), "v".to_string());
        let mut anchor = BTreeMap::new();
        anchor.insert("k".to_string(), "v".to_string());
        let signer = test_verifier_signer("v1", 1);
        let r1 = verify_trust_state(&state, &anchor, &signer).unwrap();
        let r2 = verify_trust_state(&state, &anchor, &signer).unwrap();
        assert_eq!(r1.artifact_binding_hash, r2.artifact_binding_hash);
    }

    // ── replay_capsule ─────────────────────────────────────────────

    #[test]
    fn test_replay_capsule_match() {
        let data = "capsule_data_123";
        let expected = deterministic_hash(data);
        let result = replay_capsule(data, &expected);
        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.actual_output_hash, result.expected_output_hash);
    }

    #[test]
    fn test_replay_capsule_diverged() {
        let result = replay_capsule("data", "wrong_hash");
        assert_eq!(result.verdict, Verdict::Fail);
        assert_ne!(result.actual_output_hash, result.expected_output_hash);
    }

    #[test]
    fn test_replay_capsule_deterministic() {
        // INV-VER-DETERMINISTIC
        let r1 = replay_capsule("data", "hash");
        let r2 = replay_capsule("data", "hash");
        assert_eq!(r1.actual_output_hash, r2.actual_output_hash);
        assert_eq!(r1.verdict, r2.verdict);
    }

    // ── validate_bundle ─────────────────────────────────────────────

    #[test]
    fn test_validate_bundle_pass() {
        let bundle = generate_reference_bundle();
        assert!(validate_bundle(&bundle).is_ok());
    }

    #[test]
    fn test_validate_bundle_empty_claim_id() {
        let mut bundle = generate_reference_bundle();
        bundle.claim.claim_id = String::new();
        assert!(validate_bundle(&bundle).is_err());
    }

    #[test]
    fn test_validate_bundle_no_evidence() {
        let mut bundle = generate_reference_bundle();
        bundle.evidence_items.clear();
        assert!(validate_bundle(&bundle).is_err());
    }

    #[test]
    fn test_validate_bundle_wrong_ref() {
        let mut bundle = generate_reference_bundle();
        bundle.evidence_items[0].claim_ref = "wrong".to_string();
        assert!(validate_bundle(&bundle).is_err());
    }

    // ── transparency log ────────────────────────────────────────────

    #[test]
    fn test_transparency_log_append() {
        // INV-VER-TRANSPARENCY-APPEND
        let mut log = Vec::new();
        let result = generate_reference_verification_result().unwrap();
        let entry = append_transparency_log(&mut log, &result).unwrap();
        assert_eq!(log.len(), 1);
        assert!(!entry.result_hash.is_empty());
        assert!(!entry.merkle_proof.is_empty());
    }

    #[test]
    fn test_transparency_log_chain() {
        let mut log = Vec::new();
        let r1 = generate_reference_verification_result().unwrap();
        let e1 = append_transparency_log(&mut log, &r1).unwrap();
        let e2 = append_transparency_log(&mut log, &r1).unwrap();
        assert_eq!(log.len(), 2);
        // Second entry's merkle_proof should reference first entry's hash
        assert!(e2.merkle_proof.contains(&e1.result_hash));
    }

    #[test]
    fn test_transparency_log_first_entry_zeros() {
        let mut log = Vec::new();
        let result = generate_reference_verification_result().unwrap();
        let entry = append_transparency_log(&mut log, &result).unwrap();
        assert!(entry.merkle_proof[0] == "0".repeat(64));
    }

    // ── workflow execution ──────────────────────────────────────────

    #[test]
    fn test_execute_workflow_release() {
        let bundle = generate_reference_bundle();
        let signer = test_verifier_signer("v1", 1);
        let result =
            execute_workflow(&ValidationWorkflow::ReleaseValidation, &bundle, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
        let workflow_assertion = result
            .checked_assertions
            .iter()
            .any(|a| a.assertion.contains("release_validation"));
        assert!(workflow_assertion);
    }

    #[test]
    fn test_execute_workflow_incident() {
        let bundle = generate_reference_bundle();
        let signer = test_verifier_signer("v1", 1);
        let result =
            execute_workflow(&ValidationWorkflow::IncidentValidation, &bundle, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn test_execute_workflow_compliance() {
        let bundle = generate_reference_bundle();
        let signer = test_verifier_signer("v1", 1);
        let result =
            execute_workflow(&ValidationWorkflow::ComplianceAudit, &bundle, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn test_execute_workflow_invalid_bundle_fails() {
        let mut bundle = generate_reference_bundle();
        bundle.evidence_items.clear();
        let signer = test_verifier_signer("v1", 1);
        let err = execute_workflow(&ValidationWorkflow::ReleaseValidation, &bundle, &signer);
        assert!(err.is_err());
    }

    // ── serde round-trips ───────────────────────────────────────────

    #[test]
    fn test_claim_serde_roundtrip() {
        let claim = generate_reference_claim();
        let json = serde_json::to_string(&claim).unwrap();
        let parsed: Claim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim, parsed);
    }

    #[test]
    fn test_evidence_serde_roundtrip() {
        let evidence = &generate_reference_evidence()[0];
        let json = serde_json::to_string(evidence).unwrap();
        let parsed: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(*evidence, parsed);
    }

    #[test]
    fn test_evidence_bundle_serde_roundtrip() {
        let bundle = generate_reference_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: EvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, parsed);
    }

    #[test]
    fn test_verification_result_serde_roundtrip() {
        let result = generate_reference_verification_result().unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let parsed: VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, parsed);
    }

    #[test]
    fn test_replay_result_serde_roundtrip() {
        let rr = ReplayResult {
            verdict: Verdict::Pass,
            expected_output_hash: "aabb".to_string(),
            actual_output_hash: "aabb".to_string(),
            replay_duration_ms: 42,
        };
        let json = serde_json::to_string(&rr).unwrap();
        let parsed: ReplayResult = serde_json::from_str(&json).unwrap();
        assert_eq!(rr, parsed);
    }

    #[test]
    fn test_validation_workflow_serde_roundtrip() {
        let wf = ValidationWorkflow::ReleaseValidation;
        let json = serde_json::to_string(&wf).unwrap();
        let parsed: ValidationWorkflow = serde_json::from_str(&json).unwrap();
        assert_eq!(wf, parsed);
    }

    #[test]
    fn test_transparency_log_entry_serde_roundtrip() {
        let entry = TransparencyLogEntry {
            result_hash: "aabb".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verifier_id: "v1".to_string(),
            merkle_proof: vec!["proof1".to_string()],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: TransparencyLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn test_verdict_serde_roundtrip() {
        for v in [Verdict::Pass, Verdict::Fail, Verdict::Inconclusive] {
            let json = serde_json::to_string(&v).unwrap();
            let parsed: Verdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, parsed);
        }
    }

    #[test]
    fn test_verdict_deserialize_rejects_unknown_variant() {
        let result: Result<Verdict, _> = serde_json::from_str(r#""unknown""#);

        assert!(result.is_err());
    }

    #[test]
    fn test_validation_workflow_deserialize_rejects_unknown_variant() {
        let result: Result<ValidationWorkflow, _> = serde_json::from_str(r#""dry_run""#);

        assert!(result.is_err());
    }

    #[test]
    fn test_verification_result_deserialize_rejects_missing_signature() {
        let json = r#"{
            "verdict": "pass",
            "confidence_score": 1.0,
            "checked_assertions": [],
            "execution_timestamp": "2026-02-21T00:00:00Z",
            "verifier_identity": "v1",
            "signature_algorithm": "ed25519",
            "verifier_public_key": "00",
            "artifact_binding_hash": "binding"
        }"#;

        let result: Result<VerificationResult, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_claim_deserialize_rejects_missing_claim_id() {
        let json = r#"{
            "claim_type": "migration_safety",
            "subject": "plan-ref-001",
            "assertion": "claim is safe",
            "evidence_refs": ["ev-ref-001"],
            "timestamp": "2026-02-21T00:00:00Z"
        }"#;

        let result: Result<Claim, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_claim_deserialize_rejects_evidence_refs_type_confusion() {
        let json = r#"{
            "claim_id": "claim-ref-001",
            "claim_type": "migration_safety",
            "subject": "plan-ref-001",
            "assertion": "claim is safe",
            "evidence_refs": {"ev-ref-001": true},
            "timestamp": "2026-02-21T00:00:00Z"
        }"#;

        let result: Result<Claim, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_evidence_deserialize_rejects_artifacts_type_confusion() {
        let json = r#"{
            "evidence_id": "ev-ref-001",
            "claim_ref": "claim-ref-001",
            "artifacts": ["not", "a", "map"],
            "verification_procedure": "verify hash"
        }"#;

        let result: Result<Evidence, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_evidence_bundle_deserialize_rejects_items_type_confusion() {
        let json = r#"{
            "claim": {
                "claim_id": "claim-ref-001",
                "claim_type": "migration_safety",
                "subject": "plan-ref-001",
                "assertion": "claim is safe",
                "evidence_refs": ["ev-ref-001"],
                "timestamp": "2026-02-21T00:00:00Z"
            },
            "evidence_items": {"ev-ref-001": true},
            "self_contained": true
        }"#;

        let result: Result<EvidenceBundle, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_assertion_result_deserialize_rejects_passed_type_confusion() {
        let json = r#"{
            "assertion": "claim_fields_present",
            "passed": "true",
            "detail": "claim has required fields"
        }"#;

        let result: Result<AssertionResult, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_replay_result_deserialize_rejects_negative_duration() {
        let json = r#"{
            "verdict": "fail",
            "expected_output_hash": "aa",
            "actual_output_hash": "bb",
            "replay_duration_ms": -1
        }"#;

        let result: Result<ReplayResult, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_verifier_sdk_event_deserialize_rejects_missing_timestamp() {
        let json = r#"{
            "event_code": "VER-001",
            "detail": "claim verified"
        }"#;

        let result: Result<VerifierSdkEvent, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn test_transparency_log_entry_deserialize_rejects_merkle_proof_type_confusion() {
        let json = r#"{
            "result_hash": "aabb",
            "timestamp": "2026-02-21T00:00:00Z",
            "verifier_id": "v1",
            "merkle_proof": {"previous": "00"}
        }"#;

        let result: Result<TransparencyLogEntry, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    // ── event codes ─────────────────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::VER_CLAIM_VERIFIED, "VER-001");
        assert_eq!(event_codes::VER_CLAIM_FAILED, "VER-002");
        assert_eq!(event_codes::VER_MIGRATION_VERIFIED, "VER-003");
        assert_eq!(event_codes::VER_TRUST_STATE_VERIFIED, "VER-004");
        assert_eq!(event_codes::VER_REPLAY_COMPLETED, "VER-005");
        assert_eq!(event_codes::VER_RESULT_SIGNED, "VER-006");
        assert_eq!(event_codes::VER_TRANSPARENCY_LOG_APPENDED, "VER-007");
        assert_eq!(event_codes::VER_BUNDLE_VALIDATED, "VER-008");
        assert_eq!(event_codes::VER_OFFLINE_CHECK, "VER-009");
        assert_eq!(event_codes::VER_WORKFLOW_COMPLETED, "VER-010");
    }

    // ── error codes ─────────────────────────────────────────────────

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(error_codes::ERR_VER_INVALID_CLAIM, "ERR_VER_INVALID_CLAIM");
        assert_eq!(
            error_codes::ERR_VER_EVIDENCE_MISSING,
            "ERR_VER_EVIDENCE_MISSING"
        );
        assert_eq!(
            error_codes::ERR_VER_SIGNATURE_INVALID,
            "ERR_VER_SIGNATURE_INVALID"
        );
        assert_eq!(error_codes::ERR_VER_HASH_MISMATCH, "ERR_VER_HASH_MISMATCH");
        assert_eq!(
            error_codes::ERR_VER_REPLAY_DIVERGED,
            "ERR_VER_REPLAY_DIVERGED"
        );
        assert_eq!(
            error_codes::ERR_VER_ANCHOR_UNKNOWN,
            "ERR_VER_ANCHOR_UNKNOWN"
        );
        assert_eq!(
            error_codes::ERR_VER_BUNDLE_INCOMPLETE,
            "ERR_VER_BUNDLE_INCOMPLETE"
        );
    }

    // ── invariants ──────────────────────────────────────────────────

    #[test]
    fn test_invariants_defined() {
        assert_eq!(invariants::INV_VER_DETERMINISTIC, "INV-VER-DETERMINISTIC");
        assert_eq!(
            invariants::INV_VER_OFFLINE_CAPABLE,
            "INV-VER-OFFLINE-CAPABLE"
        );
        assert_eq!(invariants::INV_VER_EVIDENCE_BOUND, "INV-VER-EVIDENCE-BOUND");
        assert_eq!(invariants::INV_VER_RESULT_SIGNED, "INV-VER-RESULT-SIGNED");
        assert_eq!(
            invariants::INV_VER_TRANSPARENCY_APPEND,
            "INV-VER-TRANSPARENCY-APPEND"
        );
    }

    // ── schema version ──────────────────────────────────────────────

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "ver-v1.0");
    }

    // ── error display ───────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let err = VerifierSdkError::InvalidClaim("bad".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VER_INVALID_CLAIM));

        let err = VerifierSdkError::EvidenceMissing("none".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VER_EVIDENCE_MISSING));

        let err = VerifierSdkError::SignatureInvalid("bad".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VER_SIGNATURE_INVALID));

        let err = VerifierSdkError::HashMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        assert!(format!("{err}").contains(error_codes::ERR_VER_HASH_MISMATCH));

        let err = VerifierSdkError::ReplayDiverged {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        assert!(format!("{err}").contains(error_codes::ERR_VER_REPLAY_DIVERGED));

        let err = VerifierSdkError::AnchorUnknown("x".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VER_ANCHOR_UNKNOWN));

        let err = VerifierSdkError::BundleIncomplete("x".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VER_BUNDLE_INCOMPLETE));
    }

    // ── Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Claim>();
        assert_sync::<Claim>();
        assert_send::<Evidence>();
        assert_sync::<Evidence>();
        assert_send::<EvidenceBundle>();
        assert_sync::<EvidenceBundle>();
        assert_send::<VerificationResult>();
        assert_sync::<VerificationResult>();
        assert_send::<ReplayResult>();
        assert_sync::<ReplayResult>();
        assert_send::<ValidationWorkflow>();
        assert_sync::<ValidationWorkflow>();
        assert_send::<TransparencyLogEntry>();
        assert_sync::<TransparencyLogEntry>();
        assert_send::<Verdict>();
        assert_sync::<Verdict>();
        assert_send::<VerifierSdkEvent>();
        assert_sync::<VerifierSdkEvent>();
        assert_send::<VerifierSdkError>();
        assert_sync::<VerifierSdkError>();
    }

    // ── offline-capable ─────────────────────────────────────────────

    #[test]
    fn test_offline_capable_claim_verification() {
        // INV-VER-OFFLINE-CAPABLE: no network calls
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let signer = test_verifier_signer("offline-verifier", 9);
        let result = verify_claim(&claim, &evidence, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn test_offline_capable_bundle_validation() {
        // INV-VER-OFFLINE-CAPABLE
        let bundle = generate_reference_bundle();
        assert!(validate_bundle(&bundle).is_ok());
    }

    // ── deterministic hash helper ───────────────────────────────────

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

    // ── verifier sdk event ──────────────────────────────────────────

    #[test]
    fn test_verifier_sdk_event_serde() {
        let evt = VerifierSdkEvent {
            event_code: event_codes::VER_CLAIM_VERIFIED.to_string(),
            detail: "claim verified".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let parsed: VerifierSdkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "VER-001");
    }

    // ── assertion result ────────────────────────────────────────────

    #[test]
    fn test_assertion_result_serde() {
        let ar = AssertionResult {
            assertion: "test".to_string(),
            passed: true,
            detail: "ok".to_string(),
        };
        let json = serde_json::to_string(&ar).unwrap();
        let parsed: AssertionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(ar, parsed);
    }

    // ── evidence BTreeMap ordering ──────────────────────────────────

    #[test]
    fn test_evidence_btreemap_ordering() {
        let evidence = &generate_reference_evidence()[0];
        let keys: Vec<_> = evidence.artifacts.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeMap should iterate in sorted order");
    }

    // ── verify_claim empty procedure ────────────────────────────────

    #[test]
    fn test_verify_claim_empty_procedure_fails() {
        let claim = generate_reference_claim();
        let mut evidence = generate_reference_evidence();
        evidence[0].verification_procedure = String::new();
        let signer = test_verifier_signer("v1", 1);
        let result = verify_claim(&claim, &evidence, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
    }

    #[test]
    fn test_verify_trust_state_timing_safe_anchor_comparison() {
        // Regression: anchor comparison must use ct_eq, not ==.
        // A near-match anchor must still fail (timing-safe comparison
        // prevents byte-by-byte leakage).
        let mut state = BTreeMap::new();
        state.insert("root_key".to_string(), "abcdef0123456789".to_string());
        let mut anchor = BTreeMap::new();
        // Off-by-one in last byte
        anchor.insert("root_key".to_string(), "abcdef012345678a".to_string());
        let signer = test_verifier_signer("v1", 1);
        let result = verify_trust_state(&state, &anchor, &signer).unwrap();
        assert_eq!(result.verdict, Verdict::Fail);

        // Same-length, completely different values
        let mut anchor2 = BTreeMap::new();
        anchor2.insert("root_key".to_string(), "xxxxxxxxxxxxxxxx".to_string());
        let result2 = verify_trust_state(&state, &anchor2, &signer).unwrap();
        assert_eq!(result2.verdict, Verdict::Fail);
    }

    #[test]
    fn test_verify_claim_signature_rejects_tampered_binding_hash() {
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let signer = test_verifier_signer("v1", 1);
        let mut result = verify_claim(&claim, &evidence, &signer).unwrap();
        result.artifact_binding_hash = "0".repeat(64);
        let err =
            verify_verification_result_signature(&result).expect_err("tampered result must fail");
        assert!(matches!(err, VerifierSdkError::SignatureInvalid(_)));
    }

    #[test]
    fn test_append_transparency_log_rejects_invalid_signature() {
        let mut log = Vec::new();
        let mut result = generate_reference_verification_result().unwrap();
        result.verifier_signature = "ff".repeat(64);
        let err = append_transparency_log(&mut log, &result)
            .expect_err("invalid signature must be rejected");
        assert!(matches!(err, VerifierSdkError::SignatureInvalid(_)));
        assert!(log.is_empty());
    }

    #[test]
    fn test_verify_result_rejects_unsupported_signature_algorithm() {
        let mut result = generate_reference_verification_result().unwrap();
        result.signature_algorithm = "rsa".to_string();

        let err = verify_verification_result_signature(&result).unwrap_err();

        assert!(matches!(err, VerifierSdkError::SignatureInvalid(_)));
    }

    #[test]
    fn test_verify_result_rejects_malformed_public_key() {
        let mut result = generate_reference_verification_result().unwrap();
        result.verifier_public_key = "not-hex".to_string();

        let err = verify_verification_result_signature(&result).unwrap_err();

        assert!(matches!(err, VerifierSdkError::SignatureInvalid(_)));
    }

    #[test]
    fn test_verify_result_rejects_truncated_signature() {
        let mut result = generate_reference_verification_result().unwrap();
        result.verifier_signature = "aa".repeat(63);

        let err = verify_verification_result_signature(&result).unwrap_err();

        assert!(matches!(err, VerifierSdkError::SignatureInvalid(_)));
    }

    #[test]
    fn test_append_transparency_log_rejects_unsupported_algorithm_without_append() {
        let mut log = Vec::new();
        let mut result = generate_reference_verification_result().unwrap();
        result.signature_algorithm = "rsa".to_string();

        let err = append_transparency_log(&mut log, &result).unwrap_err();

        assert!(matches!(err, VerifierSdkError::SignatureInvalid(_)));
        assert!(log.is_empty());
    }

    #[test]
    fn test_compute_trace_commitment_root_rejects_empty_input() {
        assert!(compute_trace_commitment_root(&[]).is_none());
    }

    #[test]
    fn test_compute_trace_commitment_root_rejects_malformed_leaf() {
        let leaves = vec!["not-a-sha256-digest".to_string()];

        assert!(compute_trace_commitment_root(&leaves).is_none());
    }

    #[test]
    fn test_build_trace_commitment_proof_rejects_out_of_bounds_leaf() {
        let leaves = vec![
            "sha256:".to_string() + &"11".repeat(32),
            "sha256:".to_string() + &"22".repeat(32),
        ];

        assert!(build_trace_commitment_proof(&leaves, 2).is_none());
    }

    #[test]
    fn test_verify_trace_commitment_proof_rejects_malformed_expected_root() {
        let leaves = vec![
            "sha256:".to_string() + &"11".repeat(32),
            "sha256:".to_string() + &"22".repeat(32),
        ];
        let proof = build_trace_commitment_proof(&leaves, 0).unwrap();

        assert!(!verify_trace_commitment_proof(
            &leaves[0],
            &proof,
            "not-a-root"
        ));
    }

    #[test]
    fn test_verify_trace_commitment_proof_rejects_malformed_sibling() {
        let leaves = vec![
            "sha256:".to_string() + &"11".repeat(32),
            "sha256:".to_string() + &"22".repeat(32),
        ];
        let root = compute_trace_commitment_root(&leaves).unwrap();
        let proof = vec![TraceCommitmentProofStep {
            sibling_hash: "not-a-sibling".to_string(),
            sibling_on_left: false,
        }];

        assert!(!verify_trace_commitment_proof(&leaves[0], &proof, &root));
    }

    #[test]
    fn test_trace_commitment_proof_roundtrip() {
        let trace_chunk_hashes = vec![
            "sha256:".to_string() + &"11".repeat(32),
            "sha256:".to_string() + &"22".repeat(32),
            "sha256:".to_string() + &"33".repeat(32),
        ];
        let root = compute_trace_commitment_root(&trace_chunk_hashes).unwrap();
        let proof = build_trace_commitment_proof(&trace_chunk_hashes, 1).unwrap();
        assert!(verify_trace_commitment_proof(
            &trace_chunk_hashes[1],
            &proof,
            &root
        ));
        assert!(!verify_trace_commitment_proof(
            &trace_chunk_hashes[0],
            &proof,
            &root
        ));
    }

    #[test]
    fn test_compute_capsule_integrity_hash_binds_metadata_fields() {
        let trace_chunk_hashes = vec![
            "sha256:".to_string() + &"44".repeat(32),
            "sha256:".to_string() + &"55".repeat(32),
        ];
        let trace_commitment_root = compute_trace_commitment_root(&trace_chunk_hashes).unwrap();
        let baseline = compute_capsule_integrity_hash(
            "cap-1",
            "vep-replay-capsule-v2",
            "att-1",
            "ver-1",
            &("sha256:".to_string() + &"66".repeat(32)),
            "2026-03-10T00:00:00Z",
            "2026-03-10T01:00:00Z",
            &("sha256:".to_string() + &"77".repeat(32)),
            &trace_commitment_root,
            &("sha256:".to_string() + &"88".repeat(32)),
            &("sha256:".to_string() + &"99".repeat(32)),
        );
        let changed_verifier = compute_capsule_integrity_hash(
            "cap-1",
            "vep-replay-capsule-v2",
            "att-1",
            "ver-2",
            &("sha256:".to_string() + &"66".repeat(32)),
            "2026-03-10T00:00:00Z",
            "2026-03-10T01:00:00Z",
            &("sha256:".to_string() + &"77".repeat(32)),
            &trace_commitment_root,
            &("sha256:".to_string() + &"88".repeat(32)),
            &("sha256:".to_string() + &"99".repeat(32)),
        );
        let changed_trace_root = compute_capsule_integrity_hash(
            "cap-1",
            "vep-replay-capsule-v2",
            "att-1",
            "ver-1",
            &("sha256:".to_string() + &"66".repeat(32)),
            "2026-03-10T00:00:00Z",
            "2026-03-10T01:00:00Z",
            &("sha256:".to_string() + &"77".repeat(32)),
            &("sha256:".to_string() + &"aa".repeat(32)),
            &("sha256:".to_string() + &"88".repeat(32)),
            &("sha256:".to_string() + &"99".repeat(32)),
        );
        assert_ne!(baseline, changed_verifier);
        assert_ne!(baseline, changed_trace_root);
    }

    fn test_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn test_verifier_signer(verifier_identity: &str, seed: u8) -> VerifierSigner {
        VerifierSigner::from_signing_key(verifier_identity, test_signing_key(seed))
    }

    fn sign_migration_artifact(
        artifact: &mut BTreeMap<String, serde_json::Value>,
        signing_key: &SigningKey,
    ) {
        artifact.insert(
            "signature_algorithm".to_string(),
            serde_json::json!("ed25519"),
        );
        artifact.insert(
            "signer_public_key".to_string(),
            serde_json::json!(hex::encode(signing_key.verifying_key().to_bytes())),
        );
        let payload = canonical_migration_artifact_payload(artifact).unwrap();
        let signature = signing_key.sign(&payload);
        artifact.insert(
            "signature".to_string(),
            serde_json::json!(hex::encode(signature.to_bytes())),
        );
    }

    #[test]
    fn nan_confidence_score_clamped_to_zero() {
        let signer = test_verifier_signer("verifier-nan", 42);
        let result = build_signed_verification_result(
            Verdict::Pass,
            f64::NAN,
            vec![],
            "binding-hash".to_string(),
            &signer,
        );
        assert_eq!(result.confidence_score, 0.0);
        // Signature must verify cleanly with the clamped value.
        assert!(verify_verification_result_signature(&result).is_ok());
    }

    #[test]
    fn infinity_confidence_score_clamped_to_zero() {
        let signer = test_verifier_signer("verifier-inf", 43);
        let result = build_signed_verification_result(
            Verdict::Fail,
            f64::INFINITY,
            vec![],
            "binding-hash".to_string(),
            &signer,
        );
        assert_eq!(result.confidence_score, 0.0);
        assert!(verify_verification_result_signature(&result).is_ok());
    }

    #[test]
    fn neg_infinity_confidence_score_clamped_to_zero() {
        let signer = test_verifier_signer("verifier-neginf", 44);
        let result = build_signed_verification_result(
            Verdict::Inconclusive,
            f64::NEG_INFINITY,
            vec![],
            "binding-hash".to_string(),
            &signer,
        );
        assert_eq!(result.confidence_score, 0.0);
        assert!(verify_verification_result_signature(&result).is_ok());
    }

    // ── evidence_refs binding regression (bd-1z5a.21) ───────────────

    /// verify_claim rejects when evidence_refs declares refs not in evidence.
    #[test]
    fn test_verify_claim_rejects_undeclared_evidence() {
        let mut claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        // Add a phantom ref not backed by evidence.
        claim.evidence_refs.push("ev-phantom".to_string());
        let signer = test_verifier_signer("v1", 1);
        let err = verify_claim(&claim, &evidence, &signer);
        assert!(
            err.is_err(),
            "should reject missing evidence for declared ref"
        );
    }

    /// verify_claim rejects when evidence item is not declared in evidence_refs.
    #[test]
    fn test_verify_claim_rejects_extra_evidence() {
        let claim = generate_reference_claim();
        let mut evidence = generate_reference_evidence();
        // Add an evidence item not declared in evidence_refs.
        evidence.push(Evidence {
            evidence_id: "ev-extra".to_string(),
            claim_ref: claim.claim_id.clone(),
            artifacts: BTreeMap::from([("hash".to_string(), "aa".repeat(32))]),
            verification_procedure: "extra check".to_string(),
        });
        let signer = test_verifier_signer("v1", 1);
        let err = verify_claim(&claim, &evidence, &signer);
        assert!(err.is_err(), "should reject undeclared evidence item");
    }

    /// validate_bundle rejects mismatched evidence_refs.
    #[test]
    fn test_validate_bundle_rejects_evidence_refs_mismatch() {
        let mut bundle = generate_reference_bundle();
        bundle.claim.evidence_refs = vec!["ev-ref-001".to_string()];
        // Bundle still has 2 evidence items but claim only declares 1 ref.
        let err = validate_bundle(&bundle);
        assert!(
            err.is_err(),
            "should reject when evidence_refs subset of evidence items"
        );
    }

    #[test]
    fn negative_claim_rejects_numeric_timestamp() {
        let json = r#"{
            "claim_id": "claim-ref-001",
            "claim_type": "migration_safety",
            "subject": "plan-ref-001",
            "assertion": "claim is safe",
            "evidence_refs": ["ev-ref-001"],
            "timestamp": 1708473600
        }"#;

        let result: Result<Claim, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn negative_evidence_rejects_missing_verification_procedure() {
        let json = r#"{
            "evidence_id": "ev-ref-001",
            "claim_ref": "claim-ref-001",
            "artifacts": {"digest": "aa"}
        }"#;

        let result: Result<Evidence, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn negative_evidence_rejects_non_string_artifact_value() {
        let json = r#"{
            "evidence_id": "ev-ref-001",
            "claim_ref": "claim-ref-001",
            "artifacts": {"digest": 7},
            "verification_procedure": "verify digest"
        }"#;

        let result: Result<Evidence, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn negative_evidence_bundle_rejects_numeric_self_contained_flag() {
        let json = r#"{
            "claim": {
                "claim_id": "claim-ref-001",
                "claim_type": "migration_safety",
                "subject": "plan-ref-001",
                "assertion": "claim is safe",
                "evidence_refs": ["ev-ref-001"],
                "timestamp": "2026-02-21T00:00:00Z"
            },
            "evidence_items": [],
            "self_contained": 1
        }"#;

        let result: Result<EvidenceBundle, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn negative_verification_result_rejects_object_checked_assertions() {
        let json = r#"{
            "verdict": "pass",
            "confidence_score": 1.0,
            "checked_assertions": {"assertion": "present"},
            "execution_timestamp": "2026-02-21T00:00:00Z",
            "verifier_identity": "v1",
            "signature_algorithm": "ed25519",
            "verifier_public_key": "00",
            "artifact_binding_hash": "binding",
            "verifier_signature": "00"
        }"#;

        let result: Result<VerificationResult, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn negative_verification_result_rejects_string_confidence_score() {
        let json = r#"{
            "verdict": "pass",
            "confidence_score": "1.0",
            "checked_assertions": [],
            "execution_timestamp": "2026-02-21T00:00:00Z",
            "verifier_identity": "v1",
            "signature_algorithm": "ed25519",
            "verifier_public_key": "00",
            "artifact_binding_hash": "binding",
            "verifier_signature": "00"
        }"#;

        let result: Result<VerificationResult, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn negative_replay_result_rejects_string_duration() {
        let json = r#"{
            "verdict": "fail",
            "expected_output_hash": "aa",
            "actual_output_hash": "bb",
            "replay_duration_ms": "42"
        }"#;

        let result: Result<ReplayResult, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn negative_transparency_log_entry_rejects_numeric_proof_member() {
        let json = r#"{
            "result_hash": "aabb",
            "timestamp": "2026-02-21T00:00:00Z",
            "verifier_id": "v1",
            "merkle_proof": ["proof1", 7]
        }"#;

        let result: Result<TransparencyLogEntry, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn negative_verifier_sdk_event_rejects_numeric_event_code() {
        let json = r#"{
            "event_code": 7,
            "detail": "claim verified",
            "timestamp": "2026-02-21T00:00:00Z"
        }"#;

        let result: Result<VerifierSdkEvent, _> = serde_json::from_str(json);

        assert!(result.is_err());
    }

    #[test]
    fn negative_push_bounded_zero_capacity_clears_without_insert() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn negative_push_bounded_eviction_handles_exact_capacity() {
        let mut items = vec![1, 2];

        push_bounded(&mut items, 3, 2);

        assert_eq!(items, vec![2, 3]);
    }
}
