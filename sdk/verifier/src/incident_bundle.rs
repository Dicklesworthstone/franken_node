//! Independent verification of `franken-node incident bundle` output
//! (`.fnbundle`, the product's signed incident replay bundle).
//!
//! This module re-derives everything a third party needs to trust a CLI
//! incident bundle WITHOUT depending on the producing `frankenengine-node`
//! crate:
//!
//! 1. the canonical integrity view (the bundle object minus `integrity_hash`
//!    and `signature`, keys sorted, floats rejected, compact JSON) hashes to the
//!    recorded `integrity_hash`;
//! 2. the manifest's `decision_sequence_hash` re-derives from the timeline,
//!    initial state snapshot and policy version (the "replay" re-derivation);
//! 3. the Ed25519 signature over
//!    `b"replay_bundle_sig_v1:" || u64_le(len) || integrity_hash` verifies
//!    strictly under a public key the VERIFIER supplies — the key embedded in
//!    the bundle is only accepted when it equals that trust anchor.
//!
//! Unknown top-level fields are rejected so no unsigned data can ride along.
//! The chunk layout (gzip sizing) is covered by the integrity hash but is not
//! independently re-derived here.

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Domain separator of the product's bundle signature payload.
pub const INCIDENT_BUNDLE_SIGNATURE_DOMAIN: &[u8] = b"replay_bundle_sig_v1:";
/// Signature algorithm the product records.
pub const INCIDENT_BUNDLE_SIGNATURE_ALGORITHM: &str = "ed25519";
/// Trust scope the product records for incident bundles.
pub const INCIDENT_BUNDLE_TRUST_SCOPE: &str = "incident_replay_bundle";
/// Upper bound on a bundle accepted for verification.
pub const MAX_INCIDENT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

const REQUIRED_FIELDS: [&str; 10] = [
    "bundle_id",
    "incident_id",
    "created_at",
    "timeline",
    "initial_state_snapshot",
    "policy_version",
    "manifest",
    "chunks",
    "integrity_hash",
    "signature",
];
const OPTIONAL_FIELDS: [&str; 2] = ["evidence_refs", "trust_artifact_refs"];

/// Facts established by a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIncidentBundle {
    pub bundle_id: String,
    pub incident_id: String,
    pub created_at: String,
    pub policy_version: String,
    pub event_count: usize,
    pub integrity_hash: String,
    pub decision_sequence_hash: String,
    pub signer_public_key_hex: String,
    pub signing_identity: String,
}

/// Why a bundle failed independent verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentBundleError {
    TooLarge { bytes: usize },
    Json(String),
    NotAnObject,
    MissingField { field: &'static str },
    UnknownField { field: String },
    WrongType { field: &'static str },
    NonDeterministicFloat { path: String },
    IntegrityMismatch { expected: String, actual: String },
    DecisionSequenceMismatch { expected: String, actual: String },
    EventCountMismatch { manifest: u64, timeline: usize },
    SignatureAlgorithmUnsupported { algorithm: String },
    SignatureTrustScopeMismatch { actual: String },
    SignatureKeySourceUntrusted,
    SignerNotTrusted,
    SignaturePayloadHashMismatch,
    SignatureMalformed,
    SignatureInvalid,
}

impl std::fmt::Display for IncidentBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { bytes } => write!(f, "incident bundle exceeds size limit ({bytes} bytes)"),
            Self::Json(detail) => write!(f, "incident bundle is not valid JSON: {detail}"),
            Self::NotAnObject => write!(f, "incident bundle must be a JSON object"),
            Self::MissingField { field } => write!(f, "incident bundle missing field `{field}`"),
            Self::UnknownField { field } => {
                write!(f, "incident bundle carries unsigned unknown field `{field}`")
            }
            Self::WrongType { field } => write!(f, "incident bundle field `{field}` has the wrong type"),
            Self::NonDeterministicFloat { path } => {
                write!(f, "incident bundle contains a float at {path}")
            }
            Self::IntegrityMismatch { expected, actual } => {
                write!(f, "integrity hash mismatch: recorded {expected}, recomputed {actual}")
            }
            Self::DecisionSequenceMismatch { expected, actual } => write!(
                f,
                "decision sequence hash mismatch: recorded {expected}, recomputed {actual}"
            ),
            Self::EventCountMismatch { manifest, timeline } => write!(
                f,
                "manifest event_count {manifest} does not match timeline length {timeline}"
            ),
            Self::SignatureAlgorithmUnsupported { algorithm } => {
                write!(f, "unsupported bundle signature algorithm `{algorithm}`")
            }
            Self::SignatureTrustScopeMismatch { actual } => {
                write!(f, "bundle signature trust scope `{actual}` is not `{INCIDENT_BUNDLE_TRUST_SCOPE}`")
            }
            Self::SignatureKeySourceUntrusted => {
                write!(f, "bundle was signed with an untrusted `local` key source")
            }
            Self::SignerNotTrusted => {
                write!(f, "bundle signer is not the verifier-supplied trust anchor")
            }
            Self::SignaturePayloadHashMismatch => {
                write!(f, "recorded signed_payload_sha256 does not match the signature payload")
            }
            Self::SignatureMalformed => write!(f, "bundle signature is malformed"),
            Self::SignatureInvalid => write!(f, "bundle signature does not verify"),
        }
    }
}

impl std::error::Error for IncidentBundleError {}

fn canonicalize(value: &Value, path: &str) -> Result<Value, IncidentBundleError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(value.clone()),
        Value::Number(number) => {
            if number.is_f64() {
                Err(IncidentBundleError::NonDeterministicFloat { path: path.to_string() })
            } else {
                Ok(value.clone())
            }
        }
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(idx, item)| canonicalize(item, &format!("{path}[{idx}]")))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key], &format!("{path}.{key}"))?);
            }
            Ok(Value::Object(out))
        }
    }
}

fn canonical_sha256_hex(value: &Value, path: &str) -> Result<String, IncidentBundleError> {
    let canonical = canonicalize(value, path)?;
    let bytes =
        serde_json::to_vec(&canonical).map_err(|err| IncidentBundleError::Json(err.to_string()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn ct_str_eq(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn string_field<'a>(object: &'a Map<String, Value>, field: &'static str) -> Result<&'a str, IncidentBundleError> {
    object
        .get(field)
        .ok_or(IncidentBundleError::MissingField { field })?
        .as_str()
        .ok_or(IncidentBundleError::WrongType { field })
}

/// The exact bytes the product signs for a bundle with `integrity_hash`.
#[must_use]
pub fn incident_bundle_signature_payload(integrity_hash: &str) -> Vec<u8> {
    let hash = integrity_hash.as_bytes();
    let mut payload = Vec::with_capacity(INCIDENT_BUNDLE_SIGNATURE_DOMAIN.len() + 8 + hash.len());
    payload.extend_from_slice(INCIDENT_BUNDLE_SIGNATURE_DOMAIN);
    payload.extend_from_slice(&(hash.len() as u64).to_le_bytes());
    payload.extend_from_slice(hash);
    payload
}

/// Independently verify a `franken-node incident bundle` `.fnbundle` against
/// the verifier's own trust anchor.
///
/// # Errors
///
/// Returns the first failed check as an [`IncidentBundleError`]; nothing is
/// accepted partially.
pub fn verify_incident_bundle(
    bytes: &[u8],
    trusted_signer: &VerifyingKey,
) -> Result<VerifiedIncidentBundle, IncidentBundleError> {
    if bytes.len() > MAX_INCIDENT_BUNDLE_BYTES {
        return Err(IncidentBundleError::TooLarge { bytes: bytes.len() });
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|err| IncidentBundleError::Json(err.to_string()))?;
    let Value::Object(object) = value else {
        return Err(IncidentBundleError::NotAnObject);
    };
    for field in REQUIRED_FIELDS {
        if !object.contains_key(field) {
            return Err(IncidentBundleError::MissingField { field });
        }
    }
    if let Some(unknown) = object
        .keys()
        .find(|key| !REQUIRED_FIELDS.contains(&key.as_str()) && !OPTIONAL_FIELDS.contains(&key.as_str()))
    {
        return Err(IncidentBundleError::UnknownField { field: unknown.clone() });
    }

    // 1. Integrity: canonical view = bundle minus integrity_hash and signature.
    let recorded_integrity = string_field(&object, "integrity_hash")?.to_string();
    let mut view = object.clone();
    view.remove("integrity_hash");
    view.remove("signature");
    let recomputed_integrity = canonical_sha256_hex(&Value::Object(view), "$.integrity_view")?;
    if !ct_str_eq(&recorded_integrity, &recomputed_integrity) {
        return Err(IncidentBundleError::IntegrityMismatch {
            expected: recorded_integrity,
            actual: recomputed_integrity,
        });
    }

    // 2. Replay re-derivation of the decision sequence.
    let timeline = object
        .get("timeline")
        .and_then(Value::as_array)
        .ok_or(IncidentBundleError::WrongType { field: "timeline" })?;
    let policy_version = string_field(&object, "policy_version")?;
    let manifest = object
        .get("manifest")
        .and_then(Value::as_object)
        .ok_or(IncidentBundleError::WrongType { field: "manifest" })?;
    let recorded_sequence = manifest
        .get("decision_sequence_hash")
        .and_then(Value::as_str)
        .ok_or(IncidentBundleError::MissingField { field: "manifest.decision_sequence_hash" })?;
    let recomputed_sequence = canonical_sha256_hex(
        &serde_json::json!({
            "timeline": timeline,
            "initial_state_snapshot": object["initial_state_snapshot"],
            "policy_version": policy_version,
        }),
        "$.decision_sequence",
    )?;
    if !ct_str_eq(recorded_sequence, &recomputed_sequence) {
        return Err(IncidentBundleError::DecisionSequenceMismatch {
            expected: recorded_sequence.to_string(),
            actual: recomputed_sequence,
        });
    }
    let manifest_count = manifest
        .get("event_count")
        .and_then(Value::as_u64)
        .ok_or(IncidentBundleError::MissingField { field: "manifest.event_count" })?;
    if usize::try_from(manifest_count).ok() != Some(timeline.len()) {
        return Err(IncidentBundleError::EventCountMismatch {
            manifest: manifest_count,
            timeline: timeline.len(),
        });
    }

    // 3. Signature under the verifier's trust anchor.
    let signature = object
        .get("signature")
        .and_then(Value::as_object)
        .ok_or(IncidentBundleError::WrongType { field: "signature" })?;
    let sig_str = |field: &'static str| -> Result<&str, IncidentBundleError> {
        signature
            .get(field)
            .and_then(Value::as_str)
            .ok_or(IncidentBundleError::MissingField { field })
    };
    let algorithm = sig_str("algorithm")?;
    if !ct_str_eq(algorithm, INCIDENT_BUNDLE_SIGNATURE_ALGORITHM) {
        return Err(IncidentBundleError::SignatureAlgorithmUnsupported {
            algorithm: algorithm.to_string(),
        });
    }
    let trust_scope = sig_str("trust_scope")?;
    if !ct_str_eq(trust_scope, INCIDENT_BUNDLE_TRUST_SCOPE) {
        return Err(IncidentBundleError::SignatureTrustScopeMismatch {
            actual: trust_scope.to_string(),
        });
    }
    if ct_str_eq(sig_str("key_source")?, "local") {
        return Err(IncidentBundleError::SignatureKeySourceUntrusted);
    }
    let public_key_hex = sig_str("public_key_hex")?;
    let anchor_hex = hex::encode(trusted_signer.as_bytes());
    if !ct_str_eq(&public_key_hex.to_ascii_lowercase(), &anchor_hex) {
        return Err(IncidentBundleError::SignerNotTrusted);
    }
    let payload = incident_bundle_signature_payload(&recorded_integrity);
    if !ct_str_eq(sig_str("signed_payload_sha256")?, &hex::encode(Sha256::digest(&payload))) {
        return Err(IncidentBundleError::SignaturePayloadHashMismatch);
    }
    let signature_bytes =
        hex::decode(sig_str("signature_hex")?).map_err(|_| IncidentBundleError::SignatureMalformed)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| IncidentBundleError::SignatureMalformed)?;
    trusted_signer
        .verify_strict(&payload, &signature)
        .map_err(|_| IncidentBundleError::SignatureInvalid)?;

    Ok(VerifiedIncidentBundle {
        bundle_id: string_field(&object, "bundle_id")?.to_string(),
        incident_id: string_field(&object, "incident_id")?.to_string(),
        created_at: string_field(&object, "created_at")?.to_string(),
        policy_version: policy_version.to_string(),
        event_count: timeline.len(),
        integrity_hash: recorded_integrity,
        decision_sequence_hash: recomputed_sequence,
        signer_public_key_hex: anchor_hex,
        signing_identity: sig_str("signing_identity")?.to_string(),
    })
}
