//! Canonical replay bundle serialization and verification helpers.
//!
//! The verifier SDK verifies deterministic bytes, stable hashes, in-bundle
//! artifact integrity, and detached Ed25519 signatures over sealed bundle
//! identity.

use std::collections::BTreeMap;
use std::fmt;

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
pub struct BundleChunk {
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub artifact_path: String,
    pub payload_length_bytes: u64,
    pub payload_digest: String,
}

/// Opaque bundle artifact bytes plus their SDK hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleArtifact {
    pub media_type: String,
    pub digest: String,
    pub bytes_hex: String,
}

/// Structural signature over a sealed bundle's integrity hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Verify a detached Ed25519 signature over a sealed replay bundle.
pub fn verify_signed_bundle(
    verifying_key: &VerifyingKey,
    bundle: &ReplayBundle,
    signature_bytes: &[u8],
) -> Result<(), BundleError> {
    let canonical = serialize(bundle)?;
    verify(&canonical)?;
    let signature = Signature::from_slice(signature_bytes).map_err(|_| {
        BundleError::Ed25519SignatureMalformed {
            length: signature_bytes.len(),
        }
    })?;
    verifying_key
        .verify(&ed25519_bundle_signature_payload(bundle), &signature)
        .map_err(|_| BundleError::Ed25519SignatureInvalid)
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
    validate_nonempty("bundle_id", &bundle.bundle_id)?;
    validate_nonempty("incident_id", &bundle.incident_id)?;
    validate_nonempty("created_at", &bundle.created_at)?;
    validate_nonempty("policy_version", &bundle.policy_version)?;
    validate_nonempty("verifier_identity", &bundle.verifier_identity)?;
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
    let mut previous_timestamp = None;
    for event in &bundle.timeline {
        validate_nonempty("timeline.event_id", &event.event_id)?;
        validate_nonempty("timeline.timestamp", &event.timestamp)?;
        validate_nonempty("timeline.event_type", &event.event_type)?;
        validate_nonempty("timeline.policy_version", &event.policy_version)?;
        if let Some(previous) = previous_sequence
            && event.sequence_number <= previous
        {
            return Err(BundleError::MissingField {
                field: "timeline.sequence_number",
            });
        }
        previous_sequence = Some(event.sequence_number);
        if let Some(previous) = previous_timestamp
            && event.timestamp.as_str() <= previous
        {
            return Err(BundleError::NonMonotonicTimestamp {
                previous: previous.to_string(),
                current: event.timestamp.clone(),
                event_id: event.event_id.clone(),
            });
        }
        previous_timestamp = Some(event.timestamp.as_str());
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

fn validate_artifacts(bundle: &ReplayBundle) -> Result<(), BundleError> {
    for (path, artifact) in &bundle.artifacts {
        if path.trim().is_empty() {
            return Err(BundleError::MissingField {
                field: "artifacts.path",
            });
        }
        validate_nonempty("artifacts.media_type", &artifact.media_type)?;
        validate_nonempty("artifacts.digest", &artifact.digest)?;
        validate_nonempty("artifacts.bytes_hex", &artifact.bytes_hex)?;
        let bytes =
            hex::decode(&artifact.bytes_hex).map_err(|source| BundleError::InvalidArtifactHex {
                path: path.clone(),
                source: source.to_string(),
            })?;
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

        let artifact = bundle.artifacts.get(&chunk.artifact_path).ok_or_else(|| {
            BundleError::ChunkArtifactMissing {
                path: chunk.artifact_path.clone(),
            }
        })?;
        let bytes =
            hex::decode(&artifact.bytes_hex).map_err(|source| BundleError::InvalidArtifactHex {
                path: chunk.artifact_path.clone(),
                source: source.to_string(),
            })?;
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
        let bytes =
            hex::decode(&artifact.bytes_hex).map_err(|source| BundleError::InvalidArtifactHex {
                path: path.clone(),
                source: source.to_string(),
            })?;
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
            entries.sort_by(|left, right| left.0.cmp(&right.0));

            let mut canonical = serde_json::Map::new();
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
