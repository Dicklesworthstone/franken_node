//! Canonical replay bundle serialization and verification helpers.
//!
//! The verifier SDK intentionally keeps this surface structural-only: it
//! verifies deterministic bytes, stable hashes, and in-bundle artifact
//! integrity without claiming detached cryptographic authority.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::SDK_VERSION;

/// Stable schema marker for SDK replay bundles.
pub const REPLAY_BUNDLE_SCHEMA_VERSION: &str = "vsdk-replay-bundle-v1.0";

const HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:canonical-hash:v1:";

/// A deterministic replay bundle that external verifiers can serialize, hash,
/// and verify without depending on privileged product internals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundle {
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
    pub metadata: BTreeMap<String, String>,
    pub integrity_hash: String,
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

/// Opaque bundle artifact bytes plus their SDK hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleArtifact {
    pub media_type: String,
    pub digest: String,
    pub bytes_hex: String,
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
    MissingField {
        field: &'static str,
    },
    EmptyTimeline,
    EmptyArtifacts,
    NonCanonicalEncoding,
    NonDeterministicFloat {
        path: String,
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
            Self::MissingField { field } => {
                write!(formatter, "replay bundle field is empty: {field}")
            }
            Self::EmptyTimeline => write!(formatter, "replay bundle timeline is empty"),
            Self::EmptyArtifacts => write!(formatter, "replay bundle artifacts are empty"),
            Self::NonCanonicalEncoding => {
                write!(formatter, "replay bundle bytes are not canonical")
            }
            Self::NonDeterministicFloat { path } => {
                write!(
                    formatter,
                    "replay bundle contains non-deterministic float at {path}"
                )
            }
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
        }
    }
}

impl std::error::Error for BundleError {}

#[derive(Serialize)]
struct ReplayBundleIntegrityView<'a> {
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
        metadata: &bundle.metadata,
    };
    Ok(hash(&canonical_bytes(&view)?))
}

/// Populate `integrity_hash` from the current replay bundle contents.
pub fn seal(bundle: &mut ReplayBundle) -> Result<(), BundleError> {
    bundle.integrity_hash = integrity_hash(bundle)?;
    Ok(())
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
    let actual = integrity_hash(&bundle)?;
    if !constant_time_eq(&bundle.integrity_hash, &actual) {
        return Err(BundleError::IntegrityMismatch {
            expected: bundle.integrity_hash,
            actual,
        });
    }
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
    validate_nonempty("bundle_id", &bundle.bundle_id)?;
    validate_nonempty("incident_id", &bundle.incident_id)?;
    validate_nonempty("created_at", &bundle.created_at)?;
    validate_nonempty("policy_version", &bundle.policy_version)?;
    validate_nonempty("verifier_identity", &bundle.verifier_identity)?;
    validate_nonempty("integrity_hash", &bundle.integrity_hash)?;
    if bundle.timeline.is_empty() {
        return Err(BundleError::EmptyTimeline);
    }
    if bundle.artifacts.is_empty() {
        return Err(BundleError::EmptyArtifacts);
    }

    let mut previous_sequence = None;
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
    }
    Ok(())
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

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), BundleError> {
    if value.trim().is_empty() {
        Err(BundleError::MissingField { field })
    } else {
        Ok(())
    }
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
