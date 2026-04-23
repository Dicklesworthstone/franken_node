//! Canonical replay bundle serialization and verification helpers.
//!
//! The verifier SDK verifies deterministic bytes, stable hashes, in-bundle
//! artifact integrity, and detached Ed25519 signatures over sealed bundle
//! identity.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, FixedOffset};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::SDK_VERSION;

/// Stable schema marker for SDK replay bundles.
pub const REPLAY_BUNDLE_SCHEMA_VERSION: &str = "vsdk-replay-bundle-v1.0";

/// Hash algorithm tag accepted by the verifier SDK bundle surface.
pub const REPLAY_BUNDLE_HASH_ALGORITHM: &str = "sha256";

const HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:canonical-hash:v1:";
const SIGNATURE_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:structural-signature:v1:";
const ED25519_BUNDLE_SIGNATURE_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:ed25519-bundle-signature:v1:";

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
            Self::NonCanonicalField { field, actual } => write!(
                formatter,
                "replay bundle field {field} must not contain surrounding whitespace: got {actual}"
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
                expected,
                actual,
            } => write!(
                formatter,
                "replay bundle chunk {artifact_path} digest mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidTimestamp { field, actual } => write!(
                formatter,
                "replay bundle field {field} must be RFC3339: got {actual}"
            ),
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
                expected,
                actual,
            } => write!(
                formatter,
                "replay bundle artifact {path} digest mismatch: expected {expected}, got {actual}"
            ),
            Self::IntegrityMismatch { expected, actual } => write!(
                formatter,
                "replay bundle integrity mismatch: expected {expected}, got {actual}"
            ),
            Self::SignatureMismatch { expected, actual } => write!(
                formatter,
                "replay bundle signature mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidVerifierIdentity { actual } => write!(
                formatter,
                "replay bundle verifier identity must use external verifier:// scheme with non-empty name: got {actual}"
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
        }
    }
}

impl std::error::Error for BundleError {}

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
pub fn serialize(bundle: &ReplayBundle) -> Result<Vec<u8>, BundleError> {
    canonical_bytes(bundle)
}

/// Deserialize replay bundle bytes without performing integrity verification.
pub fn deserialize(bytes: &[u8]) -> Result<ReplayBundle, BundleError> {
    serde_json::from_slice(bytes).map_err(|source| BundleError::Json(source.to_string()))
}

/// Compute the SDK's domain-separated SHA-256 hash for canonical bytes.
#[must_use]
pub fn hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Compute the integrity hash over all replay bundle fields except
/// `integrity_hash`.
pub fn integrity_hash(bundle: &ReplayBundle) -> Result<String, BundleError> {
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
pub fn seal(bundle: &mut ReplayBundle) -> Result<(), BundleError> {
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
#[must_use]
pub fn sign_bundle(signing_key: &SigningKey, bundle: &ReplayBundle) -> Signature {
    signing_key.sign(&ed25519_bundle_signature_payload(bundle))
}

/// Verify a detached Ed25519 signature over caller-supplied bytes.
///
/// This is intentionally payload-agnostic so downstream verifiers can check
/// registry entries and other public signed artifacts without depending on
/// privileged `franken-node` internals.
pub fn verify_ed25519_signature(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature_bytes: &[u8],
) -> Result<(), BundleError> {
    let signature = Signature::from_slice(signature_bytes).map_err(|_| {
        BundleError::Ed25519SignatureMalformed {
            length: signature_bytes.len(),
        }
    })?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| BundleError::Ed25519SignatureInvalid)
}

/// Verify a detached Ed25519 signature over a sealed replay bundle.
pub fn verify_signed_bundle(
    verifying_key: &VerifyingKey,
    bundle: &ReplayBundle,
    signature_bytes: &[u8],
) -> Result<(), BundleError> {
    let canonical = serialize(bundle)?;
    verify(&canonical)?;
    verify_ed25519_signature(
        verifying_key,
        &ed25519_bundle_signature_payload(bundle),
        signature_bytes,
    )
}

/// Verify canonical encoding, schema, artifact hashes, and bundle integrity.
pub fn verify(bytes: &[u8]) -> Result<ReplayBundle, BundleError> {
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
    buffer.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
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
        bundle.artifacts.insert("../escape.json".to_string(), artifact);
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
        bundle.artifacts.insert("artifacts\\replay.json".to_string(), artifact);
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
        bundle.artifacts.get_mut("artifacts/replay.json").expect("fixture artifact must exist").bytes_hex =
            "62756E646C652D4152544946414354".to_string();
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
