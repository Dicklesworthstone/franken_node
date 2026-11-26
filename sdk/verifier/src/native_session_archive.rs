//! Offline verification of product-root-signed native session cold archives.
//!
//! The v1 archive authenticates a compaction-time snapshot. It does not carry
//! the original admission/outcome signatures, source bytes, or effect ledger.
//! Verification therefore cannot certify original receipts, replay, cleanup,
//! freshness, or complete history. Private paths and operator text stay inside
//! the input and are never opened or returned.

use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Timelike as _, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    Admission, EffectObservation, MAX_ADMISSION_BYTES, MAX_OUTCOME_BYTES, Outcome, OutcomeKind,
    ProcessObservation, digest_valid, lowercase_hex, validate_admission, validate_outcome,
};
use crate::incident_bundle::decode_evidence_json;

pub const NATIVE_SESSION_COLD_ARCHIVE_SCHEMA: &str = "franken-node/native-session-cold-archive/v1";
/// Oversized archives must be produced in smaller compaction batches.
pub const MAX_NATIVE_SESSION_COLD_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_NATIVE_SESSION_COLD_ARCHIVE_SESSIONS: usize = 16_384;

const LEAF_DOMAIN: &[u8] = b"franken-node/native-session-cold-archive-leaf/v1\0";
const NODE_DOMAIN: &[u8] = b"franken-node/native-session-cold-archive-node/v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"franken-node/native-session-cold-archive-sig/v1\0";

/// Privacy-preserving facts authenticated at compaction time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedNativeSessionColdArchive {
    pub schema_version: &'static str,
    pub scope: &'static str,
    pub archive_sha256: String,
    pub signer_public_key_hex: String,
    pub product_root_key_id: String,
    pub archived_at: String,
    pub session_count: usize,
    pub source_bound_sessions: usize,
    pub merkle_root_sha256: String,
    pub original_receipt_signatures_verified: bool,
    pub replay_certified: bool,
    pub quiescence_certified: bool,
    pub historical_completeness: bool,
}

/// Stable errors contain no private or attacker-controlled record values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSessionColdArchiveError {
    ExpectedRootInvalid,
    ExpectedRootMismatch,
    InputTooLarge,
    JsonInvalid,
    SchemaUnsupported,
    SignerUntrusted,
    SignatureMalformed,
    SignatureInvalid,
    ArchiveInvalid,
    SessionInvalid,
    LeafMismatch,
    MerkleRootMismatch,
}

impl NativeSessionColdArchiveError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExpectedRootInvalid => "EXPECTED_ARCHIVE_ROOT_INVALID",
            Self::ExpectedRootMismatch => "EXPECTED_ARCHIVE_ROOT_MISMATCH",
            Self::InputTooLarge => "INPUT_TOO_LARGE",
            Self::JsonInvalid => "JSON_INVALID",
            Self::SchemaUnsupported => "SCHEMA_UNSUPPORTED",
            Self::SignerUntrusted => "SIGNER_UNTRUSTED",
            Self::SignatureMalformed => "SIGNATURE_MALFORMED",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::ArchiveInvalid => "ARCHIVE_INVALID",
            Self::SessionInvalid => "ARCHIVE_SESSION_INVALID",
            Self::LeafMismatch => "ARCHIVE_LEAF_MISMATCH",
            Self::MerkleRootMismatch => "ARCHIVE_ROOT_MISMATCH",
        }
    }
}

impl fmt::Display for NativeSessionColdArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExpectedRootInvalid => "expected native archive root is invalid",
            Self::ExpectedRootMismatch => {
                "authenticated native archive does not match the expected root"
            }
            Self::InputTooLarge => "native session cold archive exceeds its bound",
            Self::JsonInvalid => "native session cold archive has invalid or ambiguous JSON",
            Self::SchemaUnsupported => "native session cold archive schema is unsupported",
            Self::SignerUntrusted => {
                "native session cold archive signer is not the trusted product root"
            }
            Self::SignatureMalformed => "native session cold archive signature encoding is invalid",
            Self::SignatureInvalid => "native session cold archive signature is invalid",
            Self::ArchiveInvalid => "native session cold archive metadata is inconsistent",
            Self::SessionInvalid => "native session cold archive contains an invalid session",
            Self::LeafMismatch => "native session cold archive leaf commitment does not match",
            Self::MerkleRootMismatch => "native session cold archive Merkle root does not match",
        })
    }
}

impl std::error::Error for NativeSessionColdArchiveError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    schema_version: String,
    archived_at: DateTime<Utc>,
    operator_id: String,
    reason: String,
    session_count: usize,
    merkle_root_sha256: String,
    signing_public_key_hex: String,
    signature_hex: String,
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    session_nonce: String,
    leaf_sha256: String,
    admission: Admission,
    outcome: Outcome,
}

// Field order and optional-field omission are part of the producer's protocol.
// Do not hash serde_json::Value's sorted map order or the supplied JSON spelling.
#[derive(Serialize)]
struct CanonicalAdmission<'a> {
    session_nonce: &'a str,
    product_root_key_id: &'a str,
    identity_capture_path: &'a str,
    security_epoch: u64,
    admitted_at: DateTime<Utc>,
    project_root: &'a str,
    entrypoint: &'a str,
    dependency_ids: &'a [String],
    configured_node_id: &'a Option<String>,
    fleet_zone_id: &'a Option<String>,
    fleet_policy_sha256: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_spawn_authority_granted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    control_scopes: Option<Vec<CanonicalControlScope<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_capsule: Option<CanonicalSourceBinding<'a>>,
}

#[derive(Serialize)]
struct CanonicalControlScope<'a> {
    project_root: &'a str,
    admission_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    fleet_policy_sha256: &'a Option<String>,
}

#[derive(Serialize)]
struct CanonicalSourceBinding<'a> {
    capsule_digest: &'a str,
    graph_input_hash: &'a str,
    capsule_bytes: usize,
}

#[derive(Serialize)]
struct CanonicalOutcome<'a> {
    observed_at: DateTime<Utc>,
    kind: &'static str,
    process: &'static str,
    containment_empty_observed: bool,
    effects: CanonicalEffects<'a>,
}

#[derive(Serialize)]
struct CanonicalEffects<'a> {
    kind: &'static str,
    effect_count: usize,
    allowed_count: usize,
    denied_count: usize,
    failed_count: usize,
    chain_head_hash: &'a str,
    ledger_sha256: &'a str,
}

fn utc_time(value: &str) -> Result<DateTime<Utc>, NativeSessionColdArchiveError> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| NativeSessionColdArchiveError::SessionInvalid)
}

fn bounded_json<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, NativeSessionColdArchiveError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| NativeSessionColdArchiveError::JsonInvalid)?;
    if bytes.len() > maximum {
        return Err(NativeSessionColdArchiveError::InputTooLarge);
    }
    Ok(bytes)
}

fn admission_bytes(admission: &Admission) -> Result<Vec<u8>, NativeSessionColdArchiveError> {
    bounded_json(
        &CanonicalAdmission {
            session_nonce: &admission.session_nonce,
            product_root_key_id: &admission.product_root_key_id,
            identity_capture_path: &admission.identity_capture_path,
            security_epoch: admission.security_epoch,
            admitted_at: utc_time(&admission.admitted_at)?,
            project_root: &admission.project_root,
            entrypoint: &admission.entrypoint,
            dependency_ids: &admission.dependency_ids,
            configured_node_id: &admission.configured_node_id,
            fleet_zone_id: &admission.fleet_zone_id,
            fleet_policy_sha256: &admission.fleet_policy_sha256,
            process_spawn_authority_granted: admission.process_spawn_authority_granted,
            control_scopes: admission.control_scopes.as_ref().map(|scopes| {
                scopes
                    .iter()
                    .map(|scope| CanonicalControlScope {
                        project_root: &scope.project_root,
                        admission_generation: scope.admission_generation,
                        fleet_policy_sha256: &scope.fleet_policy_sha256,
                    })
                    .collect()
            }),
            source_capsule: admission.source_capsule.as_ref().map(|source| {
                CanonicalSourceBinding {
                    capsule_digest: &source.capsule_digest,
                    graph_input_hash: &source.graph_input_hash,
                    capsule_bytes: source.capsule_bytes,
                }
            }),
        },
        MAX_ADMISSION_BYTES,
    )
}

fn outcome_bytes(outcome: &Outcome) -> Result<Vec<u8>, NativeSessionColdArchiveError> {
    if outcome.kind != OutcomeKind::Completed
        || outcome.process != ProcessObservation::WorkerReaped
        || outcome.panic_evidence.is_some()
    {
        return Err(NativeSessionColdArchiveError::SessionInvalid);
    }
    let EffectObservation::FinalLedgerObserved {
        effect_count,
        allowed_count,
        denied_count,
        failed_count,
        chain_head_hash,
        ledger_sha256,
    } = &outcome.effects
    else {
        return Err(NativeSessionColdArchiveError::SessionInvalid);
    };
    if *denied_count != 0 || *failed_count != 0 {
        return Err(NativeSessionColdArchiveError::SessionInvalid);
    }
    bounded_json(
        &CanonicalOutcome {
            observed_at: utc_time(&outcome.observed_at)?,
            kind: "completed",
            process: "worker_reaped",
            containment_empty_observed: outcome.containment_empty_observed,
            effects: CanonicalEffects {
                kind: "final_ledger_observed",
                effect_count: *effect_count,
                allowed_count: *allowed_count,
                denied_count: *denied_count,
                failed_count: *failed_count,
                chain_head_hash,
                ledger_sha256,
            },
        },
        MAX_OUTCOME_BYTES,
    )
}

fn leaf_hash(entry: &Entry) -> Result<String, NativeSessionColdArchiveError> {
    let admission = admission_bytes(&entry.admission)?;
    let outcome = outcome_bytes(&entry.outcome)?;
    let mut hash = Sha256::new();
    hash.update(LEAF_DOMAIN);
    for part in [
        entry.session_nonce.as_bytes(),
        admission.as_slice(),
        outcome.as_slice(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Ok(hex::encode(hash.finalize()))
}

fn merkle_root(mut level: Vec<String>) -> String {
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let left = &pair[0];
                let right = pair.get(1).unwrap_or(left);
                let mut hash = Sha256::new();
                hash.update(NODE_DOMAIN);
                hash.update(left.as_bytes());
                hash.update(b":");
                hash.update(right.as_bytes());
                hex::encode(hash.finalize())
            })
            .collect();
    }
    // Empty archives are refused before computing the root.
    level.pop().unwrap_or_default()
}

fn signature_preimage(archive: &Archive) -> Result<Vec<u8>, NativeSessionColdArchiveError> {
    #[derive(Serialize)]
    struct Signable<'a> {
        schema_version: &'a str,
        archived_at: &'a DateTime<Utc>,
        operator_id: &'a str,
        reason: &'a str,
        session_count: usize,
        merkle_root_sha256: &'a str,
        signing_public_key_hex: &'a str,
    }
    let payload = bounded_json(
        &Signable {
            schema_version: &archive.schema_version,
            archived_at: &archive.archived_at,
            operator_id: &archive.operator_id,
            reason: &archive.reason,
            session_count: archive.session_count,
            merkle_root_sha256: &archive.merkle_root_sha256,
            signing_public_key_hex: &archive.signing_public_key_hex,
        },
        MAX_NATIVE_SESSION_COLD_ARCHIVE_BYTES,
    )?;
    // Unlike the per-session receipt protocols, this v1 domain has no length prefix.
    let mut preimage = SIGNATURE_DOMAIN.to_vec();
    preimage.extend_from_slice(&payload);
    Ok(preimage)
}

/// Authenticate a cold archive using an independently enrolled product root.
///
/// Recomputes every ordered, length-framed session leaf and the Merkle tree,
/// verifies the strict Ed25519 metadata signature, and refuses non-clean or
/// cross-root entries. This verifies the archive-time statement only.
pub fn verify_native_session_cold_archive(
    input: &[u8],
    trusted_root: &VerifyingKey,
) -> Result<VerifiedNativeSessionColdArchive, NativeSessionColdArchiveError> {
    verify_archive(input, trusted_root, None)
}

/// Additionally require a particular Merkle root retained by the caller.
///
/// Obtain the expected raw lowercase SHA-256 from a trusted archival record,
/// independently of this candidate. This pins the ordered session population;
/// it does not pin archive metadata, which the root may re-attest separately.
/// The returned archive SHA-256 identifies the exact supplied artifact bytes.
pub fn verify_native_session_cold_archive_with_expected_root(
    input: &[u8],
    trusted_root: &VerifyingKey,
    expected_merkle_root_sha256: &str,
) -> Result<VerifiedNativeSessionColdArchive, NativeSessionColdArchiveError> {
    if !digest_valid(expected_merkle_root_sha256) {
        return Err(NativeSessionColdArchiveError::ExpectedRootInvalid);
    }
    verify_archive(input, trusted_root, Some(expected_merkle_root_sha256))
}

fn verify_archive(
    input: &[u8],
    trusted_root: &VerifyingKey,
    expected_root: Option<&str>,
) -> Result<VerifiedNativeSessionColdArchive, NativeSessionColdArchiveError> {
    if input.len() > MAX_NATIVE_SESSION_COLD_ARCHIVE_BYTES {
        return Err(NativeSessionColdArchiveError::InputTooLarge);
    }
    let value =
        decode_evidence_json(input).map_err(|_| NativeSessionColdArchiveError::JsonInvalid)?;
    let archive: Archive =
        serde_json::from_value(value).map_err(|_| NativeSessionColdArchiveError::JsonInvalid)?;
    if archive.schema_version != NATIVE_SESSION_COLD_ARCHIVE_SCHEMA {
        return Err(NativeSessionColdArchiveError::SchemaUnsupported);
    }
    if archive.entries.is_empty()
        || archive.session_count != archive.entries.len()
        || archive.entries.len() > MAX_NATIVE_SESSION_COLD_ARCHIVE_SESSIONS
        || archive.operator_id.trim().is_empty()
        || archive.reason.trim().is_empty()
        || archive.archived_at.nanosecond() >= 1_000_000_000
        || !digest_valid(&archive.merkle_root_sha256)
    {
        return Err(NativeSessionColdArchiveError::ArchiveInvalid);
    }
    let key_hex = hex::encode(trusted_root.as_bytes());
    if trusted_root.is_weak() || archive.signing_public_key_hex != key_hex {
        return Err(NativeSessionColdArchiveError::SignerUntrusted);
    }
    if !lowercase_hex(&archive.signature_hex, 128) {
        return Err(NativeSessionColdArchiveError::SignatureMalformed);
    }
    let mut signature_bytes = [0_u8; 64];
    hex::decode_to_slice(&archive.signature_hex, &mut signature_bytes)
        .map_err(|_| NativeSessionColdArchiveError::SignatureMalformed)?;
    trusted_root
        .verify_strict(
            &signature_preimage(&archive)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| NativeSessionColdArchiveError::SignatureInvalid)?;

    let product_root_key_id = format!("ed25519:{key_hex}");
    let mut seen = BTreeSet::new();
    let mut leaves = Vec::with_capacity(archive.entries.len());
    let mut source_bound_sessions = 0;
    for entry in &archive.entries {
        if entry.session_nonce != entry.admission.session_nonce
            || entry.admission.product_root_key_id != product_root_key_id
            || !seen.insert(&entry.session_nonce)
        {
            return Err(NativeSessionColdArchiveError::SessionInvalid);
        }
        validate_admission(&entry.admission)
            .and_then(|()| validate_outcome(&entry.admission, &entry.outcome))
            .map_err(|_| NativeSessionColdArchiveError::SessionInvalid)?;
        let leaf = leaf_hash(entry)?;
        if entry.leaf_sha256 != leaf {
            return Err(NativeSessionColdArchiveError::LeafMismatch);
        }
        source_bound_sessions += usize::from(entry.admission.source_capsule.is_some());
        leaves.push(leaf);
    }
    let root = merkle_root(leaves);
    if archive.merkle_root_sha256 != root {
        return Err(NativeSessionColdArchiveError::MerkleRootMismatch);
    }
    if expected_root.is_some_and(|expected| expected != root) {
        return Err(NativeSessionColdArchiveError::ExpectedRootMismatch);
    }
    Ok(VerifiedNativeSessionColdArchive {
        schema_version: NATIVE_SESSION_COLD_ARCHIVE_SCHEMA,
        scope: "authenticated_archived_supervisor_observations",
        archive_sha256: hex::encode(Sha256::digest(input)),
        signer_public_key_hex: key_hex,
        product_root_key_id,
        archived_at: archive
            .archived_at
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        session_count: archive.session_count,
        source_bound_sessions,
        merkle_root_sha256: root,
        original_receipt_signatures_verified: false,
        replay_certified: false,
        quiescence_certified: false,
        historical_completeness: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixtures() -> (VerifyingKey, Value) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/native_session_cold_archives.json"
        ))
        .unwrap();
        let mut key = [0_u8; 32];
        hex::decode_to_slice(fixture["trusted_key_hex"].as_str().unwrap(), &mut key).unwrap();
        (VerifyingKey::from_bytes(&key).unwrap(), fixture)
    }

    fn candidate(name: &str) -> (VerifyingKey, Value) {
        let (key, fixture) = fixtures();
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        (key, case["archive"].clone())
    }

    fn verify_value(
        key: &VerifyingKey,
        value: &Value,
    ) -> Result<VerifiedNativeSessionColdArchive, NativeSessionColdArchiveError> {
        verify_native_session_cold_archive(&serde_json::to_vec(value).unwrap(), key)
    }

    #[test]
    fn cold_archive_matches_independent_python_protocol_vectors() {
        let (key, fixture) = fixtures();
        for case in fixture["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let input = serde_json::to_vec(&case["archive"]).unwrap();
            let archive: Archive = serde_json::from_slice(&input).unwrap();
            assert_eq!(
                hex::encode(signature_preimage(&archive).unwrap()),
                case["expected"]["signature_preimage_hex"].as_str().unwrap(),
                "{name}"
            );
            // These signatures and byte encodings were produced independently
            // with Python/hashlib/cryptography, not this verifier's helpers.
            if case["valid"] == true {
                let verified = verify_native_session_cold_archive(&input, &key).unwrap();
                assert_eq!(
                    verified.merkle_root_sha256,
                    case["expected"]["merkle_root_sha256"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    verified.session_count as u64,
                    case["expected"]["session_count"].as_u64().unwrap()
                );
                assert_eq!(
                    verified.source_bound_sessions,
                    usize::from(name != "single")
                );
                assert!(!verified.original_receipt_signatures_verified);
                assert!(!verified.replay_certified);
                assert!(!verified.quiescence_certified);
                assert!(!verified.historical_completeness);
                let summary = serde_json::to_string(&verified).unwrap();
                for private in [
                    "/project",
                    "operator:test",
                    "capacity recovery",
                    "package://",
                ] {
                    assert!(!summary.contains(private), "{name}: {private}");
                }
                for (index, entry) in archive.entries.iter().enumerate() {
                    let expected = &case["expected"]["entries"][index];
                    assert_eq!(
                        String::from_utf8(admission_bytes(&entry.admission).unwrap()).unwrap(),
                        expected["canonical_admission_json"].as_str().unwrap()
                    );
                    assert_eq!(
                        String::from_utf8(outcome_bytes(&entry.outcome).unwrap()).unwrap(),
                        expected["canonical_outcome_json"].as_str().unwrap()
                    );
                    assert_eq!(
                        leaf_hash(entry).unwrap(),
                        case["expected"]["leaf_sha256"][index].as_str().unwrap()
                    );
                }
            } else {
                let expected = if name == "empty_archive" {
                    NativeSessionColdArchiveError::ArchiveInvalid
                } else {
                    NativeSessionColdArchiveError::SessionInvalid
                };
                assert_eq!(
                    verify_native_session_cold_archive(&input, &key).unwrap_err(),
                    expected,
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn cold_archive_rejects_content_order_and_signature_tampering() {
        let (key, original) = candidate("triple");
        let mut changed = original.clone();
        changed["entries"][0]["admission"]["dependency_ids"] = json!(["different-package"]);
        assert_eq!(
            verify_value(&key, &changed).unwrap_err(),
            NativeSessionColdArchiveError::LeafMismatch
        );
        changed = original.clone();
        changed["entries"].as_array_mut().unwrap().swap(0, 1);
        assert_eq!(
            verify_value(&key, &changed).unwrap_err(),
            NativeSessionColdArchiveError::MerkleRootMismatch
        );
        changed = original.clone();
        changed["entries"].as_array_mut().unwrap().pop();
        assert_eq!(
            verify_value(&key, &changed).unwrap_err(),
            NativeSessionColdArchiveError::ArchiveInvalid
        );
        changed = original.clone();
        changed["reason"] = json!("substituted operator assertion");
        assert_eq!(
            verify_value(&key, &changed).unwrap_err(),
            NativeSessionColdArchiveError::SignatureInvalid
        );
        changed = original.clone();
        changed["signature_hex"] = json!("00");
        assert_eq!(
            verify_value(&key, &changed).unwrap_err(),
            NativeSessionColdArchiveError::SignatureMalformed
        );
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[0x12; 32]);
        assert_eq!(
            verify_value(&stranger.verifying_key(), &original).unwrap_err(),
            NativeSessionColdArchiveError::SignerUntrusted
        );
    }

    #[test]
    fn cold_archive_requires_unambiguous_bounded_supported_records() {
        let (key, original) = candidate("single");
        let raw = serde_json::to_string(&original).unwrap();
        for duplicate in [
            raw.replacen(
                "\"session_count\":1",
                "\"session_count\":1,\"session_count\":1",
                1,
            ),
            raw.replacen(
                "\"security_epoch\":7",
                "\"security_epoch\":7,\"security_epoch\":7",
                1,
            ),
        ] {
            assert_ne!(duplicate, raw);
            assert_eq!(
                verify_native_session_cold_archive(duplicate.as_bytes(), &key).unwrap_err(),
                NativeSessionColdArchiveError::JsonInvalid
            );
        }
        for pointer in [
            "/entries/0/admission",
            "/entries/0/outcome",
            "/entries/0/outcome/effects",
        ] {
            let mut changed = original.clone();
            changed.pointer_mut(pointer).unwrap()["unknown"] = json!(true);
            assert_eq!(
                verify_value(&key, &changed).unwrap_err(),
                NativeSessionColdArchiveError::JsonInvalid
            );
        }
        let mut changed = original.clone();
        changed["entries"][0]["outcome"]["panic_evidence"] = Value::Null;
        assert_eq!(
            verify_value(&key, &changed).unwrap_err(),
            NativeSessionColdArchiveError::JsonInvalid
        );
        changed = original.clone();
        changed["entries"][0]["admission"]
            .as_object_mut()
            .unwrap()
            .remove("configured_node_id");
        assert_eq!(
            verify_value(&key, &changed).unwrap_err(),
            NativeSessionColdArchiveError::JsonInvalid
        );
        changed = original.clone();
        changed["schema_version"] = json!("franken-node/native-session-cold-archive/v2");
        assert_eq!(
            verify_value(&key, &changed).unwrap_err(),
            NativeSessionColdArchiveError::SchemaUnsupported
        );
        changed = original;
        changed["entries"][0]["admission"]["dependency_ids"] =
            json!(["x".repeat(MAX_ADMISSION_BYTES)]);
        assert_eq!(
            verify_value(&key, &changed).unwrap_err(),
            NativeSessionColdArchiveError::InputTooLarge
        );
        assert_eq!(
            verify_native_session_cold_archive(
                &vec![b' '; MAX_NATIVE_SESSION_COLD_ARCHIVE_BYTES + 1],
                &key
            )
            .unwrap_err(),
            NativeSessionColdArchiveError::InputTooLarge
        );
    }

    #[test]
    fn cold_archive_expected_root_pins_the_selected_population() {
        let (key, original) = candidate("triple");
        let input = serde_json::to_vec(&original).unwrap();
        let root = original["merkle_root_sha256"].as_str().unwrap();
        verify_native_session_cold_archive_with_expected_root(&input, &key, root).unwrap();
        assert_eq!(
            verify_native_session_cold_archive_with_expected_root(&input, &key, &"0".repeat(64))
                .unwrap_err(),
            NativeSessionColdArchiveError::ExpectedRootMismatch
        );
        assert_eq!(
            verify_native_session_cold_archive_with_expected_root(b"unread", &key, "bad")
                .unwrap_err(),
            NativeSessionColdArchiveError::ExpectedRootInvalid
        );
    }
}
