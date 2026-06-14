//! Canonical replay bundle serialization and verification helpers.
//!
//! The verifier SDK verifies deterministic bytes, stable hashes, in-bundle
//! artifact integrity, and detached Ed25519 signatures over sealed bundle
//! identity.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, FixedOffset};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::SDK_VERSION;

/// Stable schema marker for SDK replay bundles.
pub const REPLAY_BUNDLE_SCHEMA_VERSION: &str = "vsdk-replay-bundle-v1.0";

/// Hash algorithm tag accepted by the verifier SDK bundle surface.
pub const REPLAY_BUNDLE_HASH_ALGORITHM: &str = "sha256";
/// Timeline event type that carries one proof-carrying host-effect receipt.
pub const EFFECT_RECEIPT_EVENT_TYPE: &str = "effect_receipt";
/// Stable schema marker for effect receipts embedded in verifier SDK bundles.
pub const EFFECT_RECEIPT_SCHEMA_VERSION: &str = "effect-receipt-v1.1";
/// Event code emitted when offline effect-chain verification starts.
pub const FN_VSDK_EFFECT_CHAIN_START: &str = "FN-VSDK-EFFECT-CHAIN-START";
/// Event code emitted for each verified effect receipt.
pub const FN_VSDK_EFFECT_VERIFIED: &str = "FN-VSDK-EFFECT-VERIFIED";
/// Event code emitted when offline effect-chain verification succeeds.
pub const FN_VSDK_EFFECT_CHAIN_PASS: &str = "FN-VSDK-EFFECT-CHAIN-PASS";

const HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:canonical-hash:v1:";
const SIGNATURE_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:structural-signature:v1:";
const ED25519_BUNDLE_SIGNATURE_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:ed25519-bundle-signature:v1:";
const CAS_HASH_DOMAIN: &[u8] = b"storage_cas_content_hash_v1:";
const EFFECT_RECEIPT_HASH_DOMAIN: &[u8] = b"runtime_effect_receipt_canonical_v1:";
const EFFECT_RECEIPT_CHAIN_HASH_DOMAIN: &[u8] = b"runtime_effect_receipt_chain_v1:";
const CONTENT_HASH_PREFIX: &str = "sha256:";
const EFFECT_RECEIPT_CHAIN_GENESIS: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// A deterministic replay bundle that external verifiers can serialize, hash,
/// and verify without depending on privileged product internals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundle {
    pub header: BundleHeader,
    pub schema_version: String,
    pub sdk_version: String,
    pub bundle_id: String,
    pub incident_id: String,
    pub created_at: String,
    pub policy_version: String,
    pub verifier_identity: String,
    pub timeline: Vec<TimelineEvent>,
    pub initial_state_snapshot: Value,
    pub evidence_refs: Vec<String>,
    pub artifacts: BTreeMap<String, BundleArtifact>,
    pub chunks: Vec<BundleChunk>,
    pub metadata: BTreeMap<String, String>,
    pub integrity_hash: String,
    pub signature: BundleSignature,
}

/// Versioned replay bundle header checked before payload integrity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BundleHeader {
    pub hash_algorithm: String,
    pub payload_length_bytes: u64,
    pub chunk_count: u32,
}

/// A single event in replay order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub sequence_number: u64,
    pub event_id: String,
    pub timestamp: String,
    pub event_type: String,
    pub payload: Value,
    pub state_snapshot: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_parent: Option<u64>,
    pub policy_version: String,
}

/// Manifest entry describing one payload chunk in deterministic order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BundleChunk {
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub artifact_path: String,
    pub payload_length_bytes: u64,
    pub payload_digest: String,
}

/// Opaque bundle artifact bytes plus their SDK hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BundleArtifact {
    pub media_type: String,
    pub digest: String,
    pub bytes_hex: String,
}

/// Structural signature over a sealed bundle's integrity hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BundleSignature {
    pub algorithm: String,
    pub signature_hex: String,
}

/// Class of host effect described by an embedded proof-carrying receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    FsRead,
    FsWrite,
    NetConnect,
    HttpRequest,
    Spawn,
    ModuleResolve,
}

impl EffectKind {
    const fn tag(self) -> u8 {
        match self {
            Self::FsRead => 1,
            Self::FsWrite => 2,
            Self::NetConnect => 3,
            Self::HttpRequest => 4,
            Self::Spawn => 5,
            Self::ModuleResolve => 6,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::NetConnect => "net_connect",
            Self::HttpRequest => "http_request",
            Self::Spawn => "spawn",
            Self::ModuleResolve => "module_resolve",
        }
    }
}

/// Pre-execution policy decision bound into an effect receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum EffectPolicyOutcome {
    Allowed { capability_ref: String },
    Denied { reason: String },
}

impl EffectPolicyOutcome {
    const fn tag(&self) -> u8 {
        match self {
            Self::Allowed { .. } => 1,
            Self::Denied { .. } => 2,
        }
    }

    const fn label(&self) -> &'static str {
        match self {
            Self::Allowed { .. } => "allowed",
            Self::Denied { .. } => "denied",
        }
    }

    fn capability_ref(&self) -> Option<&str> {
        match self {
            Self::Allowed { capability_ref } => Some(capability_ref),
            Self::Denied { .. } => None,
        }
    }
}

/// Information-flow verdict bound into an effect receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowPolicyVerdict {
    LabelClean,
    Declassified,
    Blocked,
}

impl FlowPolicyVerdict {
    const fn tag(self) -> u8 {
        match self {
            Self::LabelClean => 1,
            Self::Declassified => 2,
            Self::Blocked => 3,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::LabelClean => "label_clean",
            Self::Declassified => "declassified",
            Self::Blocked => "blocked",
        }
    }
}

/// Effect receipt wire shape accepted by offline SDK verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceipt {
    pub schema_version: String,
    pub seq: u64,
    pub trace_id: String,
    pub effect_kind: EffectKind,
    pub policy_outcome: EffectPolicyOutcome,
    pub pre_state_hash: String,
    pub args_hash: String,
    pub result_hash: Option<String>,
    pub post_state_hash: Option<String>,
    pub input_lineage_hash: String,
    pub output_lineage_hash: Option<String>,
    pub label_set_commitment: String,
    pub declassification_ref: Option<String>,
    pub flow_policy_verdict: FlowPolicyVerdict,
    pub recorded_at_millis: u64,
}

/// One append-only effect receipt chain entry embedded in a replay bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceiptChainEntry {
    pub index: u64,
    pub prev_chain_hash: String,
    pub receipt_hash: String,
    pub chain_hash: String,
    pub receipt: EffectReceipt,
}

/// One receipt field proven against a CAS byte artifact in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCasBinding {
    pub field: String,
    pub hash: String,
    pub artifact_path: String,
    pub byte_length: u64,
}

/// Effect receipt summary after offline chain and CAS-byte verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedEffect {
    pub index: u64,
    pub seq: u64,
    pub trace_id: String,
    pub effect_kind: String,
    pub outcome: String,
    pub capability_ref: Option<String>,
    pub result_hash: Option<String>,
    pub input_lineage_hash: String,
    pub output_lineage_hash: Option<String>,
    pub label_set_commitment: String,
    pub declassification_ref: Option<String>,
    pub flow_policy_verdict: String,
    pub cas_bindings: Vec<VerifiedCasBinding>,
}

/// Offline verification report for an effect-chain-bearing replay bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectChainVerification {
    pub bundle_id: String,
    pub verifier_identity: String,
    pub effect_count: usize,
    pub head_chain_hash: String,
    pub verified_effects: Vec<VerifiedEffect>,
    pub event_codes: Vec<String>,
}

/// Errors returned by replay bundle serialization and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    Json(String),
    UnsupportedSchema {
        expected: String,
        actual: String,
    },
    UnsupportedSdk {
        expected: String,
        actual: String,
    },
    UnsupportedHashAlgorithm {
        expected: String,
        actual: String,
    },
    MissingField {
        field: &'static str,
    },
    EmptyTimeline,
    EmptyArtifacts,
    EmptyChunks,
    NonCanonicalEncoding,
    NonDeterministicFloat {
        path: String,
    },
    PayloadLengthMismatch {
        expected: u64,
        actual: u64,
    },
    ChunkCountMismatch {
        expected: u32,
        actual: u32,
    },
    ChunkIndexMismatch {
        expected: u32,
        actual: u32,
    },
    ChunkArtifactMissing {
        path: String,
    },
    InvalidArtifactPath {
        path: String,
    },
    NonCanonicalField {
        field: &'static str,
        actual: String,
    },
    ChunkPayloadLengthMismatch {
        artifact_path: String,
        expected: u64,
        actual: u64,
    },
    ChunkDigestMismatch {
        artifact_path: String,
        expected: String,
        actual: String,
    },
    InvalidTimestamp {
        field: &'static str,
        actual: String,
    },
    NonMonotonicTimestamp {
        previous: String,
        current: String,
        event_id: String,
    },
    InvalidArtifactHex {
        path: String,
        source: String,
    },
    ArtifactDigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    IntegrityMismatch {
        expected: String,
        actual: String,
    },
    SignatureMismatch {
        expected: String,
        actual: String,
    },
    InvalidVerifierIdentity {
        actual: String,
    },
    EventPolicyVersionMismatch {
        bundle_policy_version: String,
        event_id: String,
        event_policy_version: String,
    },
    Ed25519SignatureMalformed {
        length: usize,
    },
    Ed25519SignatureInvalid,
    EmptyEffectChain,
    InvalidEffectReceiptPayload {
        event_id: String,
        source: String,
    },
    UnsupportedEffectReceiptSchema {
        index: u64,
        expected: String,
        actual: String,
    },
    MalformedEffectContentHash {
        index: u64,
        field: &'static str,
        value: String,
    },
    MalformedEffectLineageHash {
        index: u64,
        field: &'static str,
        value: String,
    },
    EffectReceiptLineagePolicy {
        index: u64,
        detail: String,
    },
    EffectReceiptAllowedMissingHash {
        index: u64,
        field: &'static str,
    },
    EffectReceiptDeniedHasHash {
        index: u64,
        field: &'static str,
    },
    EffectReceiptMissingCasBytes {
        index: u64,
        field: &'static str,
        hash: String,
    },
    EffectChainIntegrity {
        index: u64,
        detail: String,
    },
}

impl fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message) => write!(formatter, "replay bundle JSON error: {message}"),
            Self::UnsupportedSchema { expected, actual } => write!(
                formatter,
                "replay bundle schema mismatch: expected {expected}, got {actual}"
            ),
            Self::UnsupportedSdk { expected, actual } => write!(
                formatter,
                "replay bundle SDK mismatch: expected {expected}, got {actual}"
            ),
            Self::UnsupportedHashAlgorithm { expected, actual } => write!(
                formatter,
                "replay bundle hash algorithm mismatch: expected {expected}, got {actual}"
            ),
            Self::MissingField { field } => {
                write!(formatter, "replay bundle field is empty: {field}")
            }
            Self::EmptyTimeline => write!(formatter, "replay bundle timeline is empty"),
            Self::EmptyArtifacts => write!(formatter, "replay bundle artifacts are empty"),
            Self::EmptyChunks => write!(formatter, "replay bundle chunks are empty"),
            Self::NonCanonicalEncoding => {
                write!(formatter, "replay bundle bytes are not canonical")
            }
            Self::NonDeterministicFloat { path } => {
                write!(
                    formatter,
                    "replay bundle contains non-deterministic float at {path}"
                )
            }
            Self::PayloadLengthMismatch { expected, actual } => write!(
                formatter,
                "replay bundle payload length mismatch: expected {expected}, got {actual}"
            ),
            Self::ChunkCountMismatch { expected, actual } => write!(
                formatter,
                "replay bundle chunk count mismatch: expected {expected}, got {actual}"
            ),
            Self::ChunkIndexMismatch { expected, actual } => write!(
                formatter,
                "replay bundle chunk index mismatch: expected {expected}, got {actual}"
            ),
            Self::ChunkArtifactMissing { path } => {
                write!(
                    formatter,
                    "replay bundle chunk references missing artifact {path}"
                )
            }
            Self::InvalidArtifactPath { path } => {
                write!(formatter, "replay bundle artifact path is invalid: {path}")
            }
            Self::NonCanonicalField { field, actual: _ } => write!(
                formatter,
                "replay bundle field {field} must not contain surrounding whitespace"
            ),
            Self::ChunkPayloadLengthMismatch {
                artifact_path,
                expected,
                actual,
            } => write!(
                formatter,
                "replay bundle chunk {artifact_path} payload length mismatch: expected {expected}, got {actual}"
            ),
            Self::ChunkDigestMismatch {
                artifact_path,
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "replay bundle chunk {artifact_path} digest mismatch (expected and actual digests redacted)"
            ),
            Self::InvalidTimestamp { field, actual: _ } => {
                write!(formatter, "replay bundle field {field} must be RFC3339")
            }
            Self::NonMonotonicTimestamp {
                previous,
                current,
                event_id,
            } => write!(
                formatter,
                "replay bundle timestamp for {event_id} is non-monotonic: previous {previous}, current {current}"
            ),
            Self::InvalidArtifactHex { path, source } => {
                write!(
                    formatter,
                    "replay bundle artifact {path} has invalid hex: {source}"
                )
            }
            Self::ArtifactDigestMismatch {
                path,
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "replay bundle artifact {path} digest mismatch (expected and actual digests redacted)"
            ),
            Self::IntegrityMismatch {
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "replay bundle integrity mismatch (expected and actual digests redacted)"
            ),
            Self::SignatureMismatch {
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "replay bundle signature mismatch (expected and actual signatures redacted)"
            ),
            Self::InvalidVerifierIdentity { actual: _ } => write!(
                formatter,
                "replay bundle verifier identity must use external verifier:// scheme with non-empty name"
            ),
            Self::EventPolicyVersionMismatch {
                bundle_policy_version,
                event_id,
                event_policy_version,
            } => write!(
                formatter,
                "replay bundle event {event_id} policy_version mismatch: bundle={bundle_policy_version}, event={event_policy_version}"
            ),
            Self::Ed25519SignatureMalformed { length } => write!(
                formatter,
                "replay bundle Ed25519 signature has invalid length {length}"
            ),
            Self::Ed25519SignatureInvalid => {
                write!(
                    formatter,
                    "replay bundle Ed25519 signature verification failed"
                )
            }
            Self::EmptyEffectChain => {
                write!(formatter, "replay bundle carries no effect_receipt events")
            }
            Self::InvalidEffectReceiptPayload { event_id, source } => write!(
                formatter,
                "replay bundle effect receipt payload for {event_id} is invalid: {source}"
            ),
            Self::UnsupportedEffectReceiptSchema {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "effect receipt {index} schema mismatch: expected {expected}, got {actual}"
            ),
            Self::MalformedEffectContentHash {
                index,
                field,
                value: _,
            } => write!(
                formatter,
                "effect receipt {index} field {field} is not a canonical sha256:<hex> content hash"
            ),
            Self::MalformedEffectLineageHash {
                index,
                field,
                value: _,
            } => write!(
                formatter,
                "effect receipt {index} lineage field {field} is not a canonical sha256:<hex> hash"
            ),
            Self::EffectReceiptLineagePolicy { index, detail } => write!(
                formatter,
                "effect receipt {index} lineage policy invalid: {detail}"
            ),
            Self::EffectReceiptAllowedMissingHash { index, field } => write!(
                formatter,
                "allowed effect receipt {index} is missing {field}"
            ),
            Self::EffectReceiptDeniedHasHash { index, field } => write!(
                formatter,
                "denied effect receipt {index} must not carry {field}"
            ),
            Self::EffectReceiptMissingCasBytes {
                index,
                field,
                hash: _,
            } => write!(
                formatter,
                "effect receipt {index} field {field} references CAS bytes not bundled"
            ),
            Self::EffectChainIntegrity { index, detail } => write!(
                formatter,
                "effect receipt chain integrity violation at index {index}: {detail}"
            ),
        }
    }
}

impl std::error::Error for BundleError {}

/// Standard result type returned by replay bundle helpers.
pub type BundleResult<T> = Result<T, BundleError>;

#[derive(Serialize)]
struct ReplayBundleIntegrityView<'a> {
    header: &'a BundleHeader,
    schema_version: &'a str,
    sdk_version: &'a str,
    bundle_id: &'a str,
    incident_id: &'a str,
    created_at: &'a str,
    policy_version: &'a str,
    verifier_identity: &'a str,
    timeline: &'a [TimelineEvent],
    initial_state_snapshot: &'a Value,
    evidence_refs: &'a [String],
    artifacts: &'a BTreeMap<String, BundleArtifact>,
    chunks: &'a [BundleChunk],
    metadata: &'a BTreeMap<String, String>,
}

/// Serialize a replay bundle to canonical JSON bytes.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// let bytes = bundle::serialize(&sealed_bundle)?;
/// ```
pub fn serialize(bundle: &ReplayBundle) -> BundleResult<Vec<u8>> {
    canonical_bytes(bundle)
}

/// Deserialize replay bundle bytes without performing integrity verification.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// let bundle = bundle::deserialize(&canonical_bytes)?;
/// ```
pub fn deserialize(bytes: &[u8]) -> BundleResult<ReplayBundle> {
    serde_json::from_slice(bytes).map_err(|source| BundleError::Json(source.to_string()))
}

/// Compute the SDK's domain-separated SHA-256 hash for canonical bytes.
///
/// # Examples
///
/// ```rust
/// use frankenengine_verifier_sdk::bundle;
///
/// let digest = bundle::hash(b"payload");
/// assert_eq!(digest.len(), 64);
/// ```
#[must_use]
pub fn hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Compute the integrity hash over all replay bundle fields except
/// `integrity_hash`.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// let digest = bundle::integrity_hash(&bundle)?;
/// ```
pub fn integrity_hash(bundle: &ReplayBundle) -> BundleResult<String> {
    let view = ReplayBundleIntegrityView {
        header: &bundle.header,
        schema_version: &bundle.schema_version,
        sdk_version: &bundle.sdk_version,
        bundle_id: &bundle.bundle_id,
        incident_id: &bundle.incident_id,
        created_at: &bundle.created_at,
        policy_version: &bundle.policy_version,
        verifier_identity: &bundle.verifier_identity,
        timeline: &bundle.timeline,
        initial_state_snapshot: &bundle.initial_state_snapshot,
        evidence_refs: &bundle.evidence_refs,
        artifacts: &bundle.artifacts,
        chunks: &bundle.chunks,
        metadata: &bundle.metadata,
    };
    Ok(hash(&canonical_bytes(&view)?))
}

/// Populate `integrity_hash` from the current replay bundle contents.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// bundle::seal(&mut bundle)?;
/// ```
pub fn seal(bundle: &mut ReplayBundle) -> BundleResult<()> {
    bundle.integrity_hash = integrity_hash(bundle)?;
    bundle.signature = BundleSignature {
        algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
        signature_hex: compute_signature_hex(&bundle.integrity_hash),
    };
    Ok(())
}

/// Sign a sealed replay bundle with Ed25519.
///
/// The signature preimage is domain-separated and binds the public bundle
/// schema, SDK version, bundle id, incident id, creation timestamp, and
/// structural `integrity_hash`. Callers should `seal` the bundle before
/// signing; `verify_signed_bundle` enforces that structural seal before
/// checking the detached Ed25519 signature.
///
/// # Examples
///
/// ```rust,ignore
/// use ed25519_dalek::SigningKey;
/// use frankenengine_verifier_sdk::bundle;
///
/// let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
/// let signature = bundle::sign_bundle(&signing_key, &sealed_bundle);
/// ```
#[must_use]
pub fn sign_bundle(signing_key: &SigningKey, bundle: &ReplayBundle) -> Signature {
    signing_key.sign(&ed25519_bundle_signature_payload(bundle))
}

/// Verify a detached Ed25519 signature over caller-supplied bytes.
///
/// This is intentionally payload-agnostic so downstream verifiers can check
/// registry entries and other public signed artifacts without depending on
/// privileged `franken-node` internals.
///
/// # Examples
///
/// ```rust
/// use ed25519_dalek::{Signer, SigningKey};
/// use frankenengine_verifier_sdk::bundle;
///
/// let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
/// let payload = b"registry-entry";
/// let signature = signing_key.sign(payload);
/// bundle::verify_ed25519_signature(
///     &signing_key.verifying_key(),
///     payload,
///     &signature.to_bytes(),
/// )?;
/// # Ok::<(), frankenengine_verifier_sdk::bundle::BundleError>(())
/// ```
pub fn verify_ed25519_signature(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature_bytes: &[u8],
) -> BundleResult<()> {
    let signature = Signature::from_slice(signature_bytes).map_err(|_| {
        BundleError::Ed25519SignatureMalformed {
            length: signature_bytes.len(),
        }
    })?;
    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|_| BundleError::Ed25519SignatureInvalid)
}

/// Verify a detached Ed25519 signature over a sealed replay bundle.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// bundle::verify_signed_bundle(&verifying_key, &sealed_bundle, &signature_bytes)?;
/// ```
pub fn verify_signed_bundle(
    verifying_key: &VerifyingKey,
    bundle: &ReplayBundle,
    signature_bytes: &[u8],
) -> BundleResult<()> {
    let canonical = serialize(bundle)?;
    verify(&canonical)?;
    verify_ed25519_signature(
        verifying_key,
        &ed25519_bundle_signature_payload(bundle),
        signature_bytes,
    )
}

/// Verify canonical encoding, schema, artifact hashes, and bundle integrity.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// let bundle = bundle::verify(&canonical_bytes)?;
/// ```
pub fn verify(bytes: &[u8]) -> BundleResult<ReplayBundle> {
    let bundle = deserialize(bytes)?;
    let canonical = serialize(&bundle)?;
    if canonical != bytes {
        return Err(BundleError::NonCanonicalEncoding);
    }
    validate_structure(&bundle)?;
    validate_artifacts(&bundle)?;
    validate_header(&bundle)?;
    validate_chunks(&bundle)?;
    let actual = integrity_hash(&bundle)?;
    if !constant_time_eq(&bundle.integrity_hash, &actual) {
        return Err(BundleError::IntegrityMismatch {
            expected: bundle.integrity_hash,
            actual,
        });
    }
    validate_signature(&bundle)?;
    Ok(bundle)
}

/// Verify a replay bundle and then independently verify its embedded
/// proof-carrying effect receipt chain against bundled CAS bytes.
///
/// The SDK recomputes each receipt hash, chain hash, and referenced CAS content
/// hash without consulting privileged runtime internals. Structural bundle
/// verification runs first, so unsupported bundle schema/sdk versions and
/// non-canonical bytes fail closed before effect-chain parsing.
pub fn verify_effect_chain(bytes: &[u8]) -> BundleResult<EffectChainVerification> {
    let bundle = verify(bytes)?;
    verify_effect_chain_in_bundle(&bundle)
}

/// Verify effect receipt chain events in an already structurally verified
/// replay bundle.
pub fn verify_effect_chain_in_bundle(
    bundle: &ReplayBundle,
) -> BundleResult<EffectChainVerification> {
    let cas_lookup = cas_artifact_lookup(bundle)?;
    let entries = effect_chain_entries(bundle)?;
    if entries.is_empty() {
        return Err(BundleError::EmptyEffectChain);
    }

    let mut expected_prev = EFFECT_RECEIPT_CHAIN_GENESIS.to_string();
    let mut verified_effects = Vec::with_capacity(entries.len());
    for (position, entry) in entries.iter().enumerate() {
        let expected_index = u64::try_from(position).unwrap_or(u64::MAX);
        if entry.index != expected_index {
            return Err(BundleError::EffectChainIntegrity {
                index: expected_index,
                detail: format!(
                    "index field {} does not match effect event position {expected_index}",
                    entry.index
                ),
            });
        }
        if !constant_time_eq(&entry.prev_chain_hash, &expected_prev) {
            return Err(BundleError::EffectChainIntegrity {
                index: expected_index,
                detail: "prev_chain_hash does not match prior effect entry".to_string(),
            });
        }

        validate_effect_receipt(expected_index, &entry.receipt)?;
        let recomputed_receipt = effect_receipt_hash(&entry.receipt);
        if !constant_time_eq(&recomputed_receipt, &entry.receipt_hash) {
            return Err(BundleError::EffectChainIntegrity {
                index: expected_index,
                detail: "receipt_hash does not match receipt contents".to_string(),
            });
        }
        let recomputed_chain =
            effect_chain_hash(entry.index, &entry.prev_chain_hash, &entry.receipt_hash);
        if !constant_time_eq(&recomputed_chain, &entry.chain_hash) {
            return Err(BundleError::EffectChainIntegrity {
                index: expected_index,
                detail: "chain_hash does not match index, prev_chain_hash, and receipt_hash"
                    .to_string(),
            });
        }

        let cas_bindings =
            verify_receipt_cas_bindings(expected_index, &entry.receipt, &cas_lookup)?;
        verified_effects.push(VerifiedEffect {
            index: entry.index,
            seq: entry.receipt.seq,
            trace_id: entry.receipt.trace_id.clone(),
            effect_kind: entry.receipt.effect_kind.label().to_string(),
            outcome: entry.receipt.policy_outcome.label().to_string(),
            capability_ref: entry
                .receipt
                .policy_outcome
                .capability_ref()
                .map(str::to_string),
            result_hash: entry.receipt.result_hash.clone(),
            input_lineage_hash: entry.receipt.input_lineage_hash.clone(),
            output_lineage_hash: entry.receipt.output_lineage_hash.clone(),
            label_set_commitment: entry.receipt.label_set_commitment.clone(),
            declassification_ref: entry.receipt.declassification_ref.clone(),
            flow_policy_verdict: entry.receipt.flow_policy_verdict.label().to_string(),
            cas_bindings,
        });

        expected_prev = entry.chain_hash.clone();
    }

    Ok(EffectChainVerification {
        bundle_id: bundle.bundle_id.clone(),
        verifier_identity: bundle.verifier_identity.clone(),
        effect_count: verified_effects.len(),
        head_chain_hash: expected_prev,
        verified_effects,
        event_codes: vec![
            FN_VSDK_EFFECT_CHAIN_START.to_string(),
            FN_VSDK_EFFECT_VERIFIED.to_string(),
            FN_VSDK_EFFECT_CHAIN_PASS.to_string(),
        ],
    })
}

/// Render a deterministic operator transcript for a verified effect chain.
#[must_use]
pub fn render_effect_chain_transcript(report: &EffectChainVerification) -> String {
    let mut transcript = String::new();
    transcript.push_str(&format!(
        "{FN_VSDK_EFFECT_CHAIN_START} bundle_id={} effect_count={}\n",
        report.bundle_id, report.effect_count
    ));
    for effect in &report.verified_effects {
        let capability = effect.capability_ref.as_deref().unwrap_or("none");
        let result_hash = effect.result_hash.as_deref().unwrap_or("none");
        let output_lineage_hash = effect.output_lineage_hash.as_deref().unwrap_or("none");
        let declassification_ref = effect.declassification_ref.as_deref().unwrap_or("none");
        transcript.push_str(&format!(
            "{FN_VSDK_EFFECT_VERIFIED} index={} seq={} kind={} outcome={} capability_ref={} result_hash={} flow_policy_verdict={} input_lineage_hash={} output_lineage_hash={} label_set_commitment={} declassification_ref={} cas_bindings={}\n",
            effect.index,
            effect.seq,
            effect.effect_kind,
            effect.outcome,
            capability,
            result_hash,
            effect.flow_policy_verdict,
            effect.input_lineage_hash,
            output_lineage_hash,
            effect.label_set_commitment,
            declassification_ref,
            effect.cas_bindings.len()
        ));
    }
    transcript.push_str(&format!(
        "{FN_VSDK_EFFECT_CHAIN_PASS} bundle_id={} head_chain_hash={}\n",
        report.bundle_id, report.head_chain_hash
    ));
    transcript
}

#[derive(Debug, Clone)]
struct CasArtifactBinding {
    artifact_path: String,
    byte_length: u64,
}

fn cas_artifact_lookup(
    bundle: &ReplayBundle,
) -> BundleResult<BTreeMap<String, CasArtifactBinding>> {
    let mut lookup = BTreeMap::new();
    for (path, artifact) in &bundle.artifacts {
        let bytes = decode_canonical_artifact_hex(path, &artifact.bytes_hex)?;
        let content_hash = cas_content_hash(&bytes);
        lookup.entry(content_hash).or_insert_with(|| {
            let byte_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            CasArtifactBinding {
                artifact_path: path.clone(),
                byte_length,
            }
        });
    }
    Ok(lookup)
}

fn effect_chain_entries(bundle: &ReplayBundle) -> BundleResult<Vec<EffectReceiptChainEntry>> {
    bundle
        .timeline
        .iter()
        .filter(|event| event.event_type == EFFECT_RECEIPT_EVENT_TYPE)
        .map(|event| {
            serde_json::from_value(event.payload.clone()).map_err(|source| {
                BundleError::InvalidEffectReceiptPayload {
                    event_id: event.event_id.clone(),
                    source: source.to_string(),
                }
            })
        })
        .collect()
}

fn validate_effect_receipt(index: u64, receipt: &EffectReceipt) -> BundleResult<()> {
    if receipt.schema_version != EFFECT_RECEIPT_SCHEMA_VERSION {
        return Err(BundleError::UnsupportedEffectReceiptSchema {
            index,
            expected: EFFECT_RECEIPT_SCHEMA_VERSION.to_string(),
            actual: receipt.schema_version.clone(),
        });
    }
    validate_effect_content_hash(index, "pre_state_hash", &receipt.pre_state_hash)?;
    validate_effect_content_hash(index, "args_hash", &receipt.args_hash)?;
    validate_effect_lineage_hash(index, "input_lineage_hash", &receipt.input_lineage_hash)?;
    validate_effect_lineage_hash(index, "label_set_commitment", &receipt.label_set_commitment)?;
    if let Some(output_lineage_hash) = &receipt.output_lineage_hash {
        validate_effect_lineage_hash(index, "output_lineage_hash", output_lineage_hash)?;
    }
    if receipt
        .declassification_ref
        .as_ref()
        .is_some_and(|declassification_ref| declassification_ref.trim().is_empty())
    {
        return Err(BundleError::EffectReceiptLineagePolicy {
            index,
            detail: "declassification_ref must not be empty".to_string(),
        });
    }
    let is_allowed = matches!(&receipt.policy_outcome, EffectPolicyOutcome::Allowed { .. });
    match &receipt.policy_outcome {
        EffectPolicyOutcome::Allowed { .. } => {
            if receipt.result_hash.is_none() {
                return Err(BundleError::EffectReceiptAllowedMissingHash {
                    index,
                    field: "result_hash",
                });
            }
            if receipt.post_state_hash.is_none() {
                return Err(BundleError::EffectReceiptAllowedMissingHash {
                    index,
                    field: "post_state_hash",
                });
            }
            if receipt.output_lineage_hash.is_none() {
                return Err(BundleError::EffectReceiptAllowedMissingHash {
                    index,
                    field: "output_lineage_hash",
                });
            }
        }
        EffectPolicyOutcome::Denied { .. } => {
            if receipt.result_hash.is_some() {
                return Err(BundleError::EffectReceiptDeniedHasHash {
                    index,
                    field: "result_hash",
                });
            }
            if receipt.post_state_hash.is_some() {
                return Err(BundleError::EffectReceiptDeniedHasHash {
                    index,
                    field: "post_state_hash",
                });
            }
            if receipt.output_lineage_hash.is_some() {
                return Err(BundleError::EffectReceiptDeniedHasHash {
                    index,
                    field: "output_lineage_hash",
                });
            }
        }
    }
    match receipt.flow_policy_verdict {
        FlowPolicyVerdict::LabelClean => {
            if receipt.declassification_ref.is_some() {
                return Err(BundleError::EffectReceiptLineagePolicy {
                    index,
                    detail: "label-clean effects must not carry declassification_ref".to_string(),
                });
            }
        }
        FlowPolicyVerdict::Declassified => {
            if !is_allowed {
                return Err(BundleError::EffectReceiptLineagePolicy {
                    index,
                    detail: "declassified flow verdict requires an allowed effect".to_string(),
                });
            }
            if receipt.declassification_ref.is_none() {
                return Err(BundleError::EffectReceiptLineagePolicy {
                    index,
                    detail: "declassified flow verdict requires declassification_ref".to_string(),
                });
            }
        }
        FlowPolicyVerdict::Blocked => {
            if is_allowed {
                return Err(BundleError::EffectReceiptLineagePolicy {
                    index,
                    detail: "blocked flow verdict requires a denied effect".to_string(),
                });
            }
            if receipt.declassification_ref.is_some() {
                return Err(BundleError::EffectReceiptLineagePolicy {
                    index,
                    detail: "blocked flow verdict must not carry declassification_ref".to_string(),
                });
            }
        }
    }
    if let Some(hash) = &receipt.result_hash {
        validate_effect_content_hash(index, "result_hash", hash)?;
    }
    if let Some(hash) = &receipt.post_state_hash {
        validate_effect_content_hash(index, "post_state_hash", hash)?;
    }
    Ok(())
}

fn validate_effect_lineage_hash(index: u64, field: &'static str, value: &str) -> BundleResult<()> {
    let Some(hex) = value.strip_prefix(CONTENT_HASH_PREFIX) else {
        return Err(BundleError::MalformedEffectLineageHash {
            index,
            field,
            value: value.to_string(),
        });
    };
    if hex.len() != 64 || !is_canonical_lower_hex(hex) {
        return Err(BundleError::MalformedEffectLineageHash {
            index,
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_effect_content_hash(index: u64, field: &'static str, value: &str) -> BundleResult<()> {
    let Some(hex) = value.strip_prefix(CONTENT_HASH_PREFIX) else {
        return Err(BundleError::MalformedEffectContentHash {
            index,
            field,
            value: value.to_string(),
        });
    };
    if hex.len() != 64 || !is_canonical_lower_hex(hex) {
        return Err(BundleError::MalformedEffectContentHash {
            index,
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn verify_receipt_cas_bindings(
    index: u64,
    receipt: &EffectReceipt,
    cas_lookup: &BTreeMap<String, CasArtifactBinding>,
) -> BundleResult<Vec<VerifiedCasBinding>> {
    let mut bindings = Vec::new();
    push_verified_cas_binding(
        &mut bindings,
        index,
        "pre_state_hash",
        &receipt.pre_state_hash,
        cas_lookup,
    )?;
    push_verified_cas_binding(
        &mut bindings,
        index,
        "args_hash",
        &receipt.args_hash,
        cas_lookup,
    )?;
    if let Some(hash) = &receipt.result_hash {
        push_verified_cas_binding(&mut bindings, index, "result_hash", hash, cas_lookup)?;
    }
    if let Some(hash) = &receipt.post_state_hash {
        push_verified_cas_binding(&mut bindings, index, "post_state_hash", hash, cas_lookup)?;
    }
    Ok(bindings)
}

fn push_verified_cas_binding(
    bindings: &mut Vec<VerifiedCasBinding>,
    index: u64,
    field: &'static str,
    hash: &str,
    cas_lookup: &BTreeMap<String, CasArtifactBinding>,
) -> BundleResult<()> {
    let artifact =
        cas_lookup
            .get(hash)
            .ok_or_else(|| BundleError::EffectReceiptMissingCasBytes {
                index,
                field,
                hash: hash.to_string(),
            })?;
    bindings.push(VerifiedCasBinding {
        field: field.to_string(),
        hash: hash.to_string(),
        artifact_path: artifact.artifact_path.clone(),
        byte_length: artifact.byte_length,
    });
    Ok(())
}

fn cas_content_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CAS_HASH_DOMAIN);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
    format!("{CONTENT_HASH_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn effect_receipt_hash(receipt: &EffectReceipt) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EFFECT_RECEIPT_HASH_DOMAIN);
    update_hash_str(&mut hasher, &receipt.schema_version);
    hasher.update(receipt.seq.to_le_bytes());
    update_hash_str(&mut hasher, &receipt.trace_id);
    hasher.update([receipt.effect_kind.tag()]);
    hasher.update([receipt.policy_outcome.tag()]);
    match &receipt.policy_outcome {
        EffectPolicyOutcome::Allowed { capability_ref } => {
            update_hash_str(&mut hasher, capability_ref);
        }
        EffectPolicyOutcome::Denied { reason } => {
            update_hash_str(&mut hasher, reason);
        }
    }
    update_hash_str(&mut hasher, &receipt.pre_state_hash);
    update_hash_str(&mut hasher, &receipt.args_hash);
    update_optional_hash_str(&mut hasher, receipt.result_hash.as_deref());
    update_optional_hash_str(&mut hasher, receipt.post_state_hash.as_deref());
    update_hash_str(&mut hasher, &receipt.input_lineage_hash);
    update_optional_hash_str(&mut hasher, receipt.output_lineage_hash.as_deref());
    update_hash_str(&mut hasher, &receipt.label_set_commitment);
    update_optional_hash_str(&mut hasher, receipt.declassification_ref.as_deref());
    hasher.update([receipt.flow_policy_verdict.tag()]);
    hasher.update(receipt.recorded_at_millis.to_le_bytes());
    format!("{CONTENT_HASH_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn update_hash_str(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn update_optional_hash_str(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(hash) => {
            hasher.update([1_u8]);
            update_hash_str(hasher, hash);
        }
        None => hasher.update([0_u8]),
    }
}

fn effect_chain_hash(index: u64, prev_chain_hash: &str, receipt_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EFFECT_RECEIPT_CHAIN_HASH_DOMAIN);
    hasher.update(index.to_le_bytes());
    update_hash_str(&mut hasher, prev_chain_hash);
    update_hash_str(&mut hasher, receipt_hash);
    format!("{CONTENT_HASH_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn validate_structure(bundle: &ReplayBundle) -> Result<(), BundleError> {
    if bundle.schema_version != REPLAY_BUNDLE_SCHEMA_VERSION {
        return Err(BundleError::UnsupportedSchema {
            expected: REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
            actual: bundle.schema_version.clone(),
        });
    }
    if bundle.sdk_version != SDK_VERSION {
        return Err(BundleError::UnsupportedSdk {
            expected: SDK_VERSION.to_string(),
            actual: bundle.sdk_version.clone(),
        });
    }
    validate_hash_algorithm(&bundle.header.hash_algorithm)?;
    validate_hash_algorithm(&bundle.signature.algorithm)?;
    validate_canonical_text("bundle_id", &bundle.bundle_id)?;
    validate_canonical_text("incident_id", &bundle.incident_id)?;
    validate_nonempty("created_at", &bundle.created_at)?;
    parse_rfc3339_timestamp("created_at", &bundle.created_at)?;
    validate_canonical_text("policy_version", &bundle.policy_version)?;
    validate_nonempty("verifier_identity", &bundle.verifier_identity)?;
    validate_verifier_identity(&bundle.verifier_identity)?;
    validate_nonempty("integrity_hash", &bundle.integrity_hash)?;
    validate_nonempty("signature.signature_hex", &bundle.signature.signature_hex)?;
    if bundle.timeline.is_empty() {
        return Err(BundleError::EmptyTimeline);
    }
    if bundle.artifacts.is_empty() {
        return Err(BundleError::EmptyArtifacts);
    }
    if bundle.chunks.is_empty() {
        return Err(BundleError::EmptyChunks);
    }

    let mut previous_sequence = None;
    let mut previous_timestamp: Option<(DateTime<FixedOffset>, &str)> = None;
    for event in &bundle.timeline {
        validate_canonical_text("timeline.event_id", &event.event_id)?;
        validate_nonempty("timeline.timestamp", &event.timestamp)?;
        let parsed_timestamp = parse_rfc3339_timestamp("timeline.timestamp", &event.timestamp)?;
        validate_canonical_text("timeline.event_type", &event.event_type)?;
        validate_canonical_text("timeline.policy_version", &event.policy_version)?;
        if event.policy_version != bundle.policy_version {
            return Err(BundleError::EventPolicyVersionMismatch {
                bundle_policy_version: bundle.policy_version.clone(),
                event_id: event.event_id.clone(),
                event_policy_version: event.policy_version.clone(),
            });
        }
        if let Some(previous) = previous_sequence
            && event.sequence_number <= previous
        {
            return Err(BundleError::MissingField {
                field: "timeline.sequence_number",
            });
        }
        previous_sequence = Some(event.sequence_number);
        if let Some((previous, previous_raw)) = previous_timestamp
            && parsed_timestamp <= previous
        {
            return Err(BundleError::NonMonotonicTimestamp {
                previous: previous_raw.to_string(),
                current: event.timestamp.clone(),
                event_id: event.event_id.clone(),
            });
        }
        previous_timestamp = Some((parsed_timestamp, event.timestamp.as_str()));
    }
    Ok(())
}

fn validate_hash_algorithm(actual: &str) -> Result<(), BundleError> {
    if actual != REPLAY_BUNDLE_HASH_ALGORITHM {
        Err(BundleError::UnsupportedHashAlgorithm {
            expected: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            actual: actual.to_string(),
        })
    } else {
        Ok(())
    }
}

fn validate_verifier_identity(verifier_identity: &str) -> Result<(), BundleError> {
    if verifier_identity != verifier_identity.trim() {
        return Err(BundleError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
        });
    }
    let Some(remainder) = verifier_identity.strip_prefix("verifier://") else {
        return Err(BundleError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
        });
    };
    if remainder.trim().is_empty() || remainder != remainder.trim() {
        return Err(BundleError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
        });
    }
    if !remainder
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(BundleError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
        });
    }
    Ok(())
}

fn validate_artifacts(bundle: &ReplayBundle) -> Result<(), BundleError> {
    for (path, artifact) in &bundle.artifacts {
        validate_artifact_path(path)?;
        validate_nonempty("artifacts.media_type", &artifact.media_type)?;
        validate_nonempty("artifacts.digest", &artifact.digest)?;
        validate_nonempty("artifacts.bytes_hex", &artifact.bytes_hex)?;
        let bytes = decode_canonical_artifact_hex(path, &artifact.bytes_hex)?;
        let actual = hash(&bytes);
        if !constant_time_eq(&artifact.digest, &actual) {
            return Err(BundleError::ArtifactDigestMismatch {
                path: path.clone(),
                expected: artifact.digest.clone(),
                actual,
            });
        }
    }
    Ok(())
}

fn validate_header(bundle: &ReplayBundle) -> Result<(), BundleError> {
    let actual_payload_length = payload_length_bytes(&bundle.artifacts)?;
    if bundle.header.payload_length_bytes != actual_payload_length {
        return Err(BundleError::PayloadLengthMismatch {
            expected: bundle.header.payload_length_bytes,
            actual: actual_payload_length,
        });
    }

    let actual_chunk_count =
        u32::try_from(bundle.chunks.len()).map_err(|_| BundleError::ChunkCountMismatch {
            expected: bundle.header.chunk_count,
            actual: u32::MAX,
        })?;
    if bundle.header.chunk_count != actual_chunk_count {
        return Err(BundleError::ChunkCountMismatch {
            expected: bundle.header.chunk_count,
            actual: actual_chunk_count,
        });
    }
    Ok(())
}

fn validate_chunks(bundle: &ReplayBundle) -> Result<(), BundleError> {
    let total_chunks =
        u32::try_from(bundle.chunks.len()).map_err(|_| BundleError::ChunkCountMismatch {
            expected: bundle.header.chunk_count,
            actual: u32::MAX,
        })?;

    for (index, chunk) in bundle.chunks.iter().enumerate() {
        let expected_index = u32::try_from(index).map_err(|_| BundleError::ChunkIndexMismatch {
            expected: u32::MAX,
            actual: chunk.chunk_index,
        })?;
        if chunk.chunk_index != expected_index {
            return Err(BundleError::ChunkIndexMismatch {
                expected: expected_index,
                actual: chunk.chunk_index,
            });
        }
        if chunk.total_chunks != total_chunks {
            return Err(BundleError::ChunkCountMismatch {
                expected: total_chunks,
                actual: chunk.total_chunks,
            });
        }
        validate_artifact_path(&chunk.artifact_path)?;

        let artifact = bundle.artifacts.get(&chunk.artifact_path).ok_or_else(|| {
            BundleError::ChunkArtifactMissing {
                path: chunk.artifact_path.clone(),
            }
        })?;
        let bytes = decode_canonical_artifact_hex(&chunk.artifact_path, &artifact.bytes_hex)?;
        let actual_payload_length =
            u64::try_from(bytes.len()).map_err(|_| BundleError::ChunkPayloadLengthMismatch {
                artifact_path: chunk.artifact_path.clone(),
                expected: chunk.payload_length_bytes,
                actual: u64::MAX,
            })?;
        if chunk.payload_length_bytes != actual_payload_length {
            return Err(BundleError::ChunkPayloadLengthMismatch {
                artifact_path: chunk.artifact_path.clone(),
                expected: chunk.payload_length_bytes,
                actual: actual_payload_length,
            });
        }
        if !constant_time_eq(&chunk.payload_digest, &artifact.digest) {
            return Err(BundleError::ChunkDigestMismatch {
                artifact_path: chunk.artifact_path.clone(),
                expected: artifact.digest.clone(),
                actual: chunk.payload_digest.clone(),
            });
        }
    }
    Ok(())
}

fn payload_length_bytes(artifacts: &BTreeMap<String, BundleArtifact>) -> Result<u64, BundleError> {
    let mut total = 0_u64;
    for (path, artifact) in artifacts {
        let bytes = decode_canonical_artifact_hex(path, &artifact.bytes_hex)?;
        let length =
            u64::try_from(bytes.len()).map_err(|_| BundleError::PayloadLengthMismatch {
                expected: u64::MAX,
                actual: u64::MAX,
            })?;
        total = total
            .checked_add(length)
            .ok_or(BundleError::PayloadLengthMismatch {
                expected: u64::MAX,
                actual: u64::MAX,
            })?;
    }
    Ok(total)
}

fn validate_signature(bundle: &ReplayBundle) -> Result<(), BundleError> {
    let expected = compute_signature_hex(&bundle.integrity_hash);
    if !constant_time_eq(&bundle.signature.signature_hex, &expected) {
        return Err(BundleError::SignatureMismatch {
            expected,
            actual: bundle.signature.signature_hex.clone(),
        });
    }
    Ok(())
}

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), BundleError> {
    if value.trim().is_empty() {
        Err(BundleError::MissingField { field })
    } else {
        Ok(())
    }
}

fn decode_canonical_artifact_hex(path: &str, bytes_hex: &str) -> Result<Vec<u8>, BundleError> {
    if !is_canonical_lower_hex(bytes_hex) {
        return Err(BundleError::InvalidArtifactHex {
            path: path.to_string(),
            source: "artifact bytes_hex must use canonical lowercase hex".to_string(),
        });
    }
    hex::decode(bytes_hex).map_err(|source| BundleError::InvalidArtifactHex {
        path: path.to_string(),
        source: source.to_string(),
    })
}

fn is_canonical_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_artifact_path(path: &str) -> Result<(), BundleError> {
    if path.trim().is_empty()
        || path.trim() != path
        || path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|byte| {
            byte == b'\0'
                || byte.is_ascii_control()
                || !matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'/')
        })
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(BundleError::InvalidArtifactPath {
            path: path.to_string(),
        });
    }
    Ok(())
}

fn validate_canonical_text(field: &'static str, value: &str) -> Result<(), BundleError> {
    validate_nonempty(field, value)?;
    if value.trim() != value {
        return Err(BundleError::NonCanonicalField {
            field,
            actual: value.to_string(),
        });
    }
    Ok(())
}

fn parse_rfc3339_timestamp(
    field: &'static str,
    value: &str,
) -> Result<DateTime<FixedOffset>, BundleError> {
    DateTime::parse_from_rfc3339(value).map_err(|_| BundleError::InvalidTimestamp {
        field,
        actual: value.to_string(),
    })
}

fn compute_signature_hex(integrity_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SIGNATURE_DOMAIN);
    hasher.update(integrity_hash.as_bytes());
    hex::encode(hasher.finalize())
}

fn ed25519_bundle_signature_payload(bundle: &ReplayBundle) -> Vec<u8> {
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, ED25519_BUNDLE_SIGNATURE_DOMAIN);
    push_length_prefixed(&mut payload, bundle.schema_version.as_bytes());
    push_length_prefixed(&mut payload, bundle.sdk_version.as_bytes());
    push_length_prefixed(&mut payload, bundle.bundle_id.as_bytes());
    push_length_prefixed(&mut payload, bundle.incident_id.as_bytes());
    push_length_prefixed(&mut payload, bundle.created_at.as_bytes());
    push_length_prefixed(&mut payload, bundle.integrity_hash.as_bytes());
    payload
}

fn push_length_prefixed(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    buffer.extend_from_slice(bytes);
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, BundleError> {
    let value =
        serde_json::to_value(value).map_err(|source| BundleError::Json(source.to_string()))?;
    let canonical = canonicalize_value(value, "$")?;
    serde_json::to_vec(&canonical).map_err(|source| BundleError::Json(source.to_string()))
}

fn canonicalize_value(value: Value, path: &str) -> Result<Value, BundleError> {
    match value {
        Value::Array(items) => items
            .into_iter()
            .enumerate()
            .map(|(index, item)| canonicalize_value(item, &format!("{path}[{index}]")))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(map) => {
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

            let mut canonical = serde_json::Map::with_capacity(entries.len());
            for (key, item) in entries {
                canonical.insert(
                    key.clone(),
                    canonicalize_value(item, &format!("{path}.{key}"))?,
                );
            }
            Ok(Value::Object(canonical))
        }
        Value::Number(number) if number.is_f64() => Err(BundleError::NonDeterministicFloat {
            path: path.to_string(),
        }),
        other => Ok(other),
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_test_bundle(verifier_identity: &str) -> ReplayBundle {
        let artifact_bytes = b"bundle-artifact";
        let artifact_path = "artifacts/replay.json".to_string();
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            artifact_path.clone(),
            BundleArtifact {
                media_type: "application/json".to_string(),
                digest: hash(artifact_bytes),
                bytes_hex: hex::encode(artifact_bytes),
            },
        );
        let mut bundle = ReplayBundle {
            header: BundleHeader {
                hash_algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
                payload_length_bytes: u64::try_from(artifact_bytes.len())
                    .expect("artifact length should fit in u64"),
                chunk_count: 1,
            },
            schema_version: REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
            sdk_version: SDK_VERSION.to_string(),
            bundle_id: "bundle-alpha".to_string(),
            incident_id: "incident-alpha".to_string(),
            created_at: "2026-02-21T00:00:00Z".to_string(),
            policy_version: "policy.v1".to_string(),
            verifier_identity: verifier_identity.to_string(),
            timeline: vec![TimelineEvent {
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
            chunks: vec![BundleChunk {
                chunk_index: 0,
                total_chunks: 1,
                artifact_path,
                payload_length_bytes: u64::try_from(artifact_bytes.len())
                    .expect("artifact length should fit in u64"),
                payload_digest: hash(artifact_bytes),
            }],
            metadata: BTreeMap::new(),
            integrity_hash: String::new(),
            signature: BundleSignature {
                algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
                signature_hex: String::new(),
            },
        };
        seal(&mut bundle).expect("test bundle should seal");
        bundle
    }

    #[test]
    fn verify_accepts_external_verifier_identity() {
        let bundle = make_test_bundle("verifier://alpha");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let verified = verify(&bytes).expect("external verifier identity should verify");

        assert_eq!(verified.verifier_identity, "verifier://alpha");
    }

    #[test]
    fn verify_rejects_non_verifier_identity_scheme() {
        let bundle = make_test_bundle("operator://alpha");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("non-verifier identity must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_empty_verifier_identity_after_scheme() {
        let bundle = make_test_bundle("verifier://");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("empty verifier name must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_whitespace_only_verifier_identity_after_scheme() {
        let bundle = make_test_bundle("verifier://   ");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("whitespace-only verifier name must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_leading_whitespace_padded_verifier_identity() {
        let bundle = make_test_bundle(" verifier://alpha");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes)
            .expect_err("leading-whitespace-padded verifier identity must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_trailing_whitespace_padded_verifier_identity() {
        let bundle = make_test_bundle("verifier://alpha ");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes)
            .expect_err("trailing-whitespace-padded verifier identity must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_verifier_identity_with_embedded_spaces() {
        let bundle = make_test_bundle("verifier://alpha beta");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("embedded spaces must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_verifier_identity_with_path_like_suffix() {
        let bundle = make_test_bundle("verifier://alpha/beta");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("path-like verifier names must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_verifier_identity_with_null_byte() {
        let bundle = make_test_bundle("verifier://alpha\u{0000}");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("null-byte verifier names must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_whitespace_padded_artifact_map_key() {
        let mut bundle = make_test_bundle("verifier://alpha");
        let artifact = bundle
            .artifacts
            .remove("artifacts/replay.json")
            .expect("fixture artifact must exist");
        bundle
            .artifacts
            .insert(" artifacts/replay.json".to_string(), artifact);
        bundle.chunks[0].artifact_path = " artifacts/replay.json".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("padded artifact map key must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == " artifacts/replay.json"
        ));
    }

    #[test]
    fn verify_rejects_whitespace_padded_chunk_artifact_path() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.chunks[0].artifact_path = "artifacts/replay.json ".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("padded chunk artifact path must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == "artifacts/replay.json "
        ));
    }

    #[test]
    fn verify_rejects_path_traversal_artifact_map_key() {
        let mut bundle = make_test_bundle("verifier://alpha");
        let artifact = bundle
            .artifacts
            .remove("artifacts/replay.json")
            .expect("fixture artifact must exist");
        bundle
            .artifacts
            .insert("../escape.json".to_string(), artifact);
        bundle.chunks[0].artifact_path = "../escape.json".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("path traversal artifact path must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == "../escape.json"
        ));
    }

    #[test]
    fn verify_rejects_absolute_chunk_artifact_path() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.chunks[0].artifact_path = "/absolute/replay.json".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("absolute chunk artifact path must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == "/absolute/replay.json"
        ));
    }

    #[test]
    fn verify_rejects_backslash_artifact_map_key() {
        let mut bundle = make_test_bundle("verifier://alpha");
        let artifact = bundle
            .artifacts
            .remove("artifacts/replay.json")
            .expect("fixture artifact must exist");
        bundle
            .artifacts
            .insert("artifacts\\replay.json".to_string(), artifact);
        bundle.chunks[0].artifact_path = "artifacts\\replay.json".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("backslash artifact path must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == "artifacts\\replay.json"
        ));
    }

    #[test]
    fn verify_rejects_null_byte_chunk_artifact_path() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.chunks[0].artifact_path = "artifacts/\u{0000}replay.json".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("null-byte chunk artifact path must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == "artifacts/\u{0000}replay.json"
        ));
    }

    #[test]
    fn verify_rejects_uppercase_artifact_bytes_hex() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle
            .artifacts
            .get_mut("artifacts/replay.json")
            .expect("fixture artifact must exist")
            .bytes_hex = "62756E646C652D4152544946414354".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("uppercase artifact bytes_hex must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactHex { path, source }
                if path == "artifacts/replay.json"
                    && source.contains("canonical lowercase hex")
        ));
    }

    #[test]
    fn verify_rejects_malformed_created_at_timestamp() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.created_at = "not-a-timestamp".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("malformed created_at must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidTimestamp { field, actual }
                if field == "created_at" && actual == "not-a-timestamp"
        ));
    }

    #[test]
    fn verify_rejects_whitespace_padded_created_at_timestamp() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.created_at = " 2026-02-21T00:00:00Z ".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("whitespace-padded created_at must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidTimestamp { field, actual }
                if field == "created_at" && actual == " 2026-02-21T00:00:00Z "
        ));
    }

    #[test]
    fn verify_rejects_malformed_timeline_timestamp() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.timeline[0].timestamp = "tomorrow-ish".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("malformed timeline timestamp must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidTimestamp { field, actual }
                if field == "timeline.timestamp" && actual == "tomorrow-ish"
        ));
    }

    #[test]
    fn verify_rejects_whitespace_padded_bundle_id() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.bundle_id = " bundle-alpha ".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("whitespace-padded bundle_id must fail closed");

        assert!(matches!(
            err,
            BundleError::NonCanonicalField { field, actual }
                if field == "bundle_id" && actual == " bundle-alpha "
        ));
    }

    #[test]
    fn verify_rejects_whitespace_padded_timeline_event_id() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.timeline[0].event_id = " evt-1 ".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("whitespace-padded timeline.event_id must fail closed");

        assert!(matches!(
            err,
            BundleError::NonCanonicalField { field, actual }
                if field == "timeline.event_id" && actual == " evt-1 "
        ));
    }

    #[test]
    fn verify_rejects_whitespace_padded_timeline_event_type() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.timeline[0].event_type = " verification.started ".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err =
            verify(&bytes).expect_err("whitespace-padded timeline.event_type must fail closed");

        assert!(matches!(
            err,
            BundleError::NonCanonicalField { field, actual }
                if field == "timeline.event_type" && actual == " verification.started "
        ));
    }

    #[test]
    fn bundle_error_display_redacts_verifier_and_digest_values() {
        let verifier_error = BundleError::InvalidVerifierIdentity {
            actual: "verifier://evil\nspoof".to_string(),
        };
        let field_error = BundleError::NonCanonicalField {
            field: "bundle_id",
            actual: " bundle-alpha ".to_string(),
        };
        let timestamp_error = BundleError::InvalidTimestamp {
            field: "created_at",
            actual: "not-a-timestamp".to_string(),
        };
        let digest_error = BundleError::IntegrityMismatch {
            expected: "expected-digest".to_string(),
            actual: "actual-digest".to_string(),
        };
        let signature_error = BundleError::SignatureMismatch {
            expected: "expected-signature".to_string(),
            actual: "actual-signature".to_string(),
        };

        let verifier_display = verifier_error.to_string();
        assert!(!verifier_display.contains("verifier://evil"));
        assert!(!verifier_display.contains("spoof"));

        let field_display = field_error.to_string();
        assert!(field_display.contains("bundle_id"));
        assert!(!field_display.contains(" bundle-alpha "));

        let timestamp_display = timestamp_error.to_string();
        assert!(timestamp_display.contains("created_at"));
        assert!(!timestamp_display.contains("not-a-timestamp"));

        let digest_display = digest_error.to_string();
        assert!(digest_display.contains("redacted"));
        assert!(!digest_display.contains("expected-digest"));
        assert!(!digest_display.contains("actual-digest"));

        let signature_display = signature_error.to_string();
        assert!(signature_display.contains("redacted"));
        assert!(!signature_display.contains("expected-signature"));
        assert!(!signature_display.contains("actual-signature"));
    }

    #[test]
    fn verify_accepts_uniform_event_policy_versions() {
        let bundle = make_test_bundle("verifier://alpha");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let verified = verify(&bytes).expect("uniform policy_version should verify");

        assert_eq!(verified.policy_version, "policy.v1");
        assert_eq!(verified.timeline[0].policy_version, "policy.v1");
    }

    #[test]
    fn verify_rejects_mixed_event_policy_versions() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.timeline[0].policy_version = "policy.v2".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("mixed event policy_version must fail closed");

        assert!(matches!(
            err,
            BundleError::EventPolicyVersionMismatch {
                bundle_policy_version,
                event_id,
                event_policy_version,
            } if bundle_policy_version == "policy.v1"
                && event_id == "evt-1"
                && event_policy_version == "policy.v2"
        ));
    }
}
