//! Independent verification of `franken-node incident bundle` output
//! (`.fnbundle`, the product's signed incident replay bundle).
//!
//! This module re-derives everything a third party needs to trust a CLI
//! incident bundle WITHOUT depending on the producing `frankenengine-node`
//! crate:
//!
//! 1. the canonical integrity view (the bundle object minus `integrity_hash`
//!    and `signature`, keys sorted, floats rejected, compact JSON) hashes —
//!    `SHA-256(b"replay_bundle_hash_v1:" || canonical_json)` — to the recorded
//!    `integrity_hash`;
//! 2. the manifest's `decision_sequence_hash` re-derives from the timeline,
//!    initial state snapshot and policy version (the "replay" re-derivation);
//! 3. the Ed25519 signature over
//!    `b"replay_bundle_sig_v1:" || u64_le(len) || integrity_hash` verifies
//!    strictly under a public key the VERIFIER supplies — the key embedded in
//!    the bundle and its derived key ID must match that trust anchor;
//! 4. timeline sequencing, timestamps, causal parents, deterministic bundle ID,
//!    manifest endpoints and spans, canonical chunk boundaries and chunk hashes
//!    are independently checked against the authenticated events.
//!
//! The signature envelope's human-readable `signing_identity` label is outside
//! the signed integrity view. Verified signer identity is therefore the
//! canonical key ID derived from the verifier's trust anchor.
//!
//! Duplicate object members are rejected before canonicalization, including
//! escaped spellings of the same member name. A signature must not authenticate
//! different evidence depending on a consumer's first/last-member convention.
//! Unknown top-level fields are rejected so no unsigned data can ride along.
//! Gzip byte counts remain signed producer assertions: compression is optional
//! in the product. This verifier checks replay structure, not guest execution.

#[path = "incident_bundle_structure.rs"]
mod structure;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Domain separator of the product's bundle signature payload.
pub const INCIDENT_BUNDLE_SIGNATURE_DOMAIN: &[u8] = b"replay_bundle_sig_v1:";
/// Domain prefix of every product bundle digest (integrity and decision
/// sequence): `SHA-256(domain || canonical_json)`.
pub const INCIDENT_BUNDLE_HASH_DOMAIN: &[u8] = b"replay_bundle_hash_v1:";
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
    /// Lowercase hexadecimal encoding of the verifier-supplied trusted public key.
    pub signer_public_key_hex: String,
    /// Canonical artifact-signing key ID derived from the trusted public key.
    ///
    /// For authenticated attribution, this field contains the key ID instead of
    /// the bundle's unsigned `signature.signing_identity` label. Applications
    /// needing a human-readable name must use their own trusted key-to-name mapping.
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
    Structure { path: String, reason: &'static str },
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
            Self::TooLarge { bytes } => {
                write!(f, "incident bundle exceeds size limit ({bytes} bytes)")
            }
            Self::Json(detail) => write!(f, "incident bundle is not valid JSON: {detail}"),
            Self::NotAnObject => write!(f, "incident bundle must be a JSON object"),
            Self::MissingField { field } => write!(f, "incident bundle missing field `{field}`"),
            Self::UnknownField { field } => {
                write!(
                    f,
                    "incident bundle carries unsigned unknown field `{field}`"
                )
            }
            Self::WrongType { field } => {
                write!(f, "incident bundle field `{field}` has the wrong type")
            }
            Self::NonDeterministicFloat { path } => {
                write!(f, "incident bundle contains a float at {path}")
            }
            Self::IntegrityMismatch { expected, actual } => {
                write!(
                    f,
                    "integrity hash mismatch: recorded {expected}, recomputed {actual}"
                )
            }
            Self::DecisionSequenceMismatch { expected, actual } => write!(
                f,
                "decision sequence hash mismatch: recorded {expected}, recomputed {actual}"
            ),
            Self::EventCountMismatch { manifest, timeline } => write!(
                f,
                "manifest event_count {manifest} does not match timeline length {timeline}"
            ),
            Self::Structure { path, reason } => {
                write!(f, "incident bundle structure invalid at {path}: {reason}")
            }
            Self::SignatureAlgorithmUnsupported { algorithm } => {
                write!(f, "unsupported bundle signature algorithm `{algorithm}`")
            }
            Self::SignatureTrustScopeMismatch { actual } => {
                write!(
                    f,
                    "bundle signature trust scope `{actual}` is not `{INCIDENT_BUNDLE_TRUST_SCOPE}`"
                )
            }
            Self::SignatureKeySourceUntrusted => {
                write!(f, "bundle was signed with an untrusted `local` key source")
            }
            Self::SignerNotTrusted => {
                write!(f, "bundle signer is not the verifier-supplied trust anchor")
            }
            Self::SignaturePayloadHashMismatch => {
                write!(
                    f,
                    "recorded signed_payload_sha256 does not match the signature payload"
                )
            }
            Self::SignatureMalformed => write!(f, "bundle signature is malformed"),
            Self::SignatureInvalid => write!(f, "bundle signature does not verify"),
        }
    }
}

impl std::error::Error for IncidentBundleError {}

/// Preserve the JSON value model without Value's last-member-wins parsing.
/// Checking after deserialization is too late: duplicate evidence has already
/// disappeared from the value that gets hashed. This visitor checks every
/// object, including objects inside arrays and the unsigned signature envelope.
/// serde_json's normal recursion limit and end-of-input check remain enabled.
struct UnambiguousJson(Value);

impl<'de> Deserialize<'de> for UnambiguousJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;

        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = UnambiguousJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object members")
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UnambiguousJson(Value::Null))
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UnambiguousJson(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UnambiguousJson(Value::Number(value.into())))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UnambiguousJson(Value::Number(value.into())))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| UnambiguousJson(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                self.visit_string(value.to_owned())
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UnambiguousJson(Value::String(value)))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UnambiguousJson(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(UnambiguousJson(Value::Array(values)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = object.next_key::<String>()? {
                    // Keys are decoded before comparison, so e.g. "id" and
                    // "\u0069d" cannot smuggle two interpretations of a field.
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON object member"));
                    }
                    let UnambiguousJson(value) = object.next_value()?;
                    values.insert(key, value);
                }
                Ok(UnambiguousJson(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(JsonVisitor)
    }
}

fn canonicalize(value: &Value, path: &str) -> Result<Value, IncidentBundleError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(value.clone()),
        Value::Number(number) => {
            if number.is_f64() {
                Err(IncidentBundleError::NonDeterministicFloat {
                    path: path.to_string(),
                })
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
                out.insert(
                    key.clone(),
                    canonicalize(&map[key], &format!("{path}.{key}"))?,
                );
            }
            Ok(Value::Object(out))
        }
    }
}

/// Domain-separated digest of the canonical JSON form of `value`.
///
/// # Errors
///
/// Rejects floats (non-deterministic encodings) and serialization failures.
pub fn incident_bundle_canonical_digest(
    value: &Value,
    path: &str,
) -> Result<String, IncidentBundleError> {
    let canonical = canonicalize(value, path)?;
    let bytes =
        serde_json::to_vec(&canonical).map_err(|err| IncidentBundleError::Json(err.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(INCIDENT_BUNDLE_HASH_DOMAIN);
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn ct_str_eq(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn trusted_signer_key_id(trusted_signer: &VerifyingKey) -> String {
    // Match the product's artifact_signing::KeyId::from_verifying_key exactly.
    let public_key = trusted_signer.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"artifact_signing_keyid_v1:");
    hasher.update((public_key.len() as u64).to_le_bytes());
    hasher.update(public_key);
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, IncidentBundleError> {
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
///
/// # Example
///
/// The README's "Verifier SDK" example, run against a bundle the real CLI
/// wrote (`tests/fixtures/cli_incident_bundle/INC-SDK-FIXTURE-1.fnbundle`,
/// signed with the RFC 8032 section 7.1 TEST 1 key):
///
/// ```
/// use ed25519_dalek::VerifyingKey;
/// use frankenengine_verifier_sdk::incident_bundle::verify_incident_bundle;
///
/// /// Verify a `franken-node incident bundle` output against a signer key the
/// /// auditor obtained independently (never the key embedded in the bundle).
/// fn audit(
///     bundle_path: &std::path::Path,
///     trusted_signer: &VerifyingKey,
/// ) -> Result<(), Box<dyn std::error::Error>> {
///     let bytes = std::fs::read(bundle_path)?;
///     let verified = verify_incident_bundle(&bytes, trusted_signer)?;
///     println!(
///         "verified incident {} ({} events, integrity {})",
///         verified.incident_id, verified.event_count, verified.integrity_hash
///     );
///     Ok(())
/// }
///
/// let mut anchor = [0_u8; 32];
/// hex::decode_to_slice(
///     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
///     &mut anchor,
/// )?;
/// let bundle = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
///     .join("tests/fixtures/cli_incident_bundle/INC-SDK-FIXTURE-1.fnbundle");
/// audit(&bundle, &VerifyingKey::from_bytes(&anchor)?)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn verify_incident_bundle(
    bytes: &[u8],
    trusted_signer: &VerifyingKey,
) -> Result<VerifiedIncidentBundle, IncidentBundleError> {
    if bytes.len() > MAX_INCIDENT_BUNDLE_BYTES {
        return Err(IncidentBundleError::TooLarge { bytes: bytes.len() });
    }
    let UnambiguousJson(value) =
        serde_json::from_slice(bytes).map_err(|err| IncidentBundleError::Json(err.to_string()))?;
    let Value::Object(object) = value else {
        return Err(IncidentBundleError::NotAnObject);
    };
    for field in REQUIRED_FIELDS {
        if !object.contains_key(field) {
            return Err(IncidentBundleError::MissingField { field });
        }
    }
    if let Some(unknown) = object.keys().find(|key| {
        !REQUIRED_FIELDS.contains(&key.as_str()) && !OPTIONAL_FIELDS.contains(&key.as_str())
    }) {
        return Err(IncidentBundleError::UnknownField {
            field: unknown.clone(),
        });
    }

    // 1. Integrity: canonical view = bundle minus integrity_hash and signature.
    let recorded_integrity = string_field(&object, "integrity_hash")?.to_string();
    let mut view = object.clone();
    view.remove("integrity_hash");
    view.remove("signature");
    let recomputed_integrity =
        incident_bundle_canonical_digest(&Value::Object(view), "$.integrity_view")?;
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
        .ok_or(IncidentBundleError::MissingField {
            field: "manifest.decision_sequence_hash",
        })?;
    let recomputed_sequence = incident_bundle_canonical_digest(
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
    let manifest_count = manifest.get("event_count").and_then(Value::as_u64).ok_or(
        IncidentBundleError::MissingField {
            field: "manifest.event_count",
        },
    )?;
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
    let anchor_key_id = trusted_signer_key_id(trusted_signer);
    if !ct_str_eq(sig_str("key_id")?, &anchor_key_id) {
        return Err(IncidentBundleError::SignerNotTrusted);
    }
    let payload = incident_bundle_signature_payload(&recorded_integrity);
    if !ct_str_eq(
        sig_str("signed_payload_sha256")?,
        &hex::encode(Sha256::digest(&payload)),
    ) {
        return Err(IncidentBundleError::SignaturePayloadHashMismatch);
    }
    let signature_bytes = hex::decode(sig_str("signature_hex")?)
        .map_err(|_| IncidentBundleError::SignatureMalformed)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| IncidentBundleError::SignatureMalformed)?;
    trusted_signer
        .verify_strict(&payload, &signature)
        .map_err(|_| IncidentBundleError::SignatureInvalid)?;

    // Preserve the envelope's required-string validation without promoting its
    // unsigned human-readable label to an authenticated signer identity.
    sig_str("signing_identity")?;

    // A valid signer can still produce inconsistent evidence. Do not promote
    // hashes and counts to a verified replay until their structure is checked.
    structure::verify_structure(&object)?;

    Ok(VerifiedIncidentBundle {
        bundle_id: string_field(&object, "bundle_id")?.to_string(),
        incident_id: string_field(&object, "incident_id")?.to_string(),
        created_at: string_field(&object, "created_at")?.to_string(),
        policy_version: policy_version.to_string(),
        event_count: timeline.len(),
        integrity_hash: recorded_integrity,
        decision_sequence_hash: recomputed_sequence,
        signer_public_key_hex: anchor_hex,
        signing_identity: anchor_key_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLI_BUNDLE: &str =
        include_str!("../tests/fixtures/cli_incident_bundle/INC-SDK-FIXTURE-1.fnbundle");

    fn trusted_key() -> VerifyingKey {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            &mut bytes,
        )
        .unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn real_cli_bundle_remains_verifiable_with_unambiguous_json() {
        let verified = verify_incident_bundle(CLI_BUNDLE.as_bytes(), &trusted_key()).unwrap();
        assert_eq!(verified.incident_id, "INC-SDK-FIXTURE-1");
        assert_eq!(verified.event_count, 3);
        assert_eq!(verified.signing_identity, "339eefa3a988f613");
    }

    #[test]
    fn duplicate_members_cannot_hide_behind_an_unchanged_valid_signature() {
        let original: Value = serde_json::from_str(CLI_BUNDLE).unwrap();
        verify_incident_bundle(CLI_BUNDLE.as_bytes(), &trusted_key()).unwrap();
        for (needle, replacement) in [
            (
                r#""incident_id":"#,
                r#""incident_id":"OTHER","incident_id":"#,
            ),
            (
                r#""incident_id":"#,
                r#""incident\u005fid":"OTHER","incident_id":"#,
            ),
            (r#""timeline":"#, r#""timeline":[],"timeline":"#),
            (r#""event_count":3"#, r#""event_count":0,"event_count":3"#),
            (
                r#""signal":"anomaly""#,
                r#""signal":"benign","signal":"anomaly""#,
            ),
            (
                r#""signal":"anomaly""#,
                r#""signal":"anomaly","signal":"anomaly""#,
            ),
            (
                r#""public_key_hex":"#,
                r#""public_key_hex":"untrusted","public_key_hex":"#,
            ),
            (
                r#""key_source":"cli""#,
                r#""key_source":"local","key_source":"cli""#,
            ),
        ] {
            assert!(CLI_BUNDLE.contains(needle), "fixture must exercise {needle}");
            let ambiguous = CLI_BUNDLE.replacen(needle, replacement, 1);
            // The old parser erases the injected member, leaving exactly the
            // original authenticated value and its still-valid signature.
            assert_eq!(serde_json::from_str::<Value>(&ambiguous).unwrap(), original);
            let error = verify_incident_bundle(ambiguous.as_bytes(), &trusted_key()).unwrap_err();
            assert!(
                matches!(error, IncidentBundleError::Json(ref detail)
                    if detail.contains("duplicate JSON object member")),
                "{needle}: {error}"
            );
        }
    }

    #[test]
    fn duplicate_checks_reach_nested_timeline_and_manifest_objects() {
        // The first signal occurs in chunks. Mutate only the last occurrence
        // here so a chunk failure cannot mask acceptance of a timeline duplicate.
        for (needle, replacement) in [
            (
                r#""signal":"anomaly""#,
                r#""signal":null,"signal":"anomaly""#,
            ),
            (
                r#""decision_sequence_hash":"#,
                r#""decision_sequence_hash":"","decision_sequence_hash":"#,
            ),
        ] {
            let (before, after) = CLI_BUNDLE.rsplit_once(needle).unwrap();
            let ambiguous = format!("{before}{replacement}{after}");
            assert_ne!(ambiguous, CLI_BUNDLE);
            assert_eq!(
                serde_json::from_str::<Value>(&ambiguous).unwrap(),
                serde_json::from_str::<Value>(CLI_BUNDLE).unwrap()
            );
            assert!(matches!(
                verify_incident_bundle(ambiguous.as_bytes(), &trusted_key()),
                Err(IncidentBundleError::Json(_))
            ));
        }
    }

    #[test]
    fn strict_parser_preserves_json_types_and_full_integer_precision() {
        let input = br#"{"min":-9223372036854775808,"max":18446744073709551615,"items":[null,true,false,"\u0061",{},[]],"siblings":[{"id":1},{"id":2}]}"#;
        let parsed: UnambiguousJson = serde_json::from_slice(input).unwrap();
        assert_eq!(parsed.0, serde_json::from_slice::<Value>(input).unwrap());
        assert_eq!(parsed.0["min"].as_i64(), Some(i64::MIN));
        assert_eq!(parsed.0["max"].as_u64(), Some(u64::MAX));
    }

    #[test]
    fn strict_parser_retains_float_rejection_at_the_canonical_boundary() {
        let parsed: UnambiguousJson = serde_json::from_slice(br#"{"x":1.5}"#).unwrap();
        assert!(matches!(
            incident_bundle_canonical_digest(&parsed.0, "$"),
            Err(IncidentBundleError::NonDeterministicFloat { path }) if path == "$.x"
        ));
    }

    #[test]
    fn strict_parser_keeps_recursion_utf8_and_trailing_data_checks() {
        let nested = format!("{}0{}", "[".repeat(256), "]".repeat(256));
        assert!(serde_json::from_str::<UnambiguousJson>(&nested).is_err());
        assert!(serde_json::from_slice::<UnambiguousJson>(b"{\"x\":\"\xff\"}").is_err());
        let trailing = format!("{CLI_BUNDLE} {{}}");
        assert!(matches!(
            verify_incident_bundle(trailing.as_bytes(), &trusted_key()),
            Err(IncidentBundleError::Json(_))
        ));
        let whitespace = format!("{CLI_BUNDLE}\n\t ");
        assert!(verify_incident_bundle(whitespace.as_bytes(), &trusted_key()).is_ok());
    }
}
