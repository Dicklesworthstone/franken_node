//! Cross-implementation conformance: the independent verifier SDK verifies a
//! bundle produced by the real `franken-node incident bundle` CLI.
//!
//! Fixture provenance (`fixtures/cli_incident_bundle/INC-SDK-FIXTURE-1.fnbundle`):
//! produced by `franken-node incident bundle --id INC-SDK-FIXTURE-1 --verify
//! --receipt-signing-key <seed>` (release build of franken_node 8b8b45311)
//! where `<seed>` is the RFC 8032 section 7.1 TEST 1 secret key. The trust
//! anchor below is that test vector's published public key, so the anchor is
//! independent of anything embedded in the bundle.

use ed25519_dalek::VerifyingKey;
use frankenengine_verifier_sdk::incident_bundle::{
    IncidentBundleError, incident_bundle_canonical_digest, incident_bundle_signature_payload,
    verify_incident_bundle,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/cli_incident_bundle/INC-SDK-FIXTURE-1.fnbundle");
/// RFC 8032 section 7.1 TEST 1 public key.
const RFC8032_TEST1_PUBLIC_KEY_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn anchor() -> VerifyingKey {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(RFC8032_TEST1_PUBLIC_KEY_HEX, &mut bytes).unwrap();
    VerifyingKey::from_bytes(&bytes).unwrap()
}

fn fixture_value() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}

/// Recompute the integrity hash of a (tampered) bundle the way an attacker
/// without the signing key would, so later checks are reached.
fn reseal_integrity(value: &mut Value) {
    let mut view = value.as_object().unwrap().clone();
    view.remove("integrity_hash");
    view.remove("signature");
    value["integrity_hash"] = Value::String(
        incident_bundle_canonical_digest(&Value::Object(view), "$.integrity_view").unwrap(),
    );
}

#[test]
fn sdk_verifies_real_cli_incident_bundle_under_independent_anchor() {
    let verified = verify_incident_bundle(FIXTURE, &anchor()).expect("CLI bundle must verify");
    assert_eq!(verified.incident_id, "INC-SDK-FIXTURE-1");
    assert_eq!(verified.event_count, 2);
    assert_eq!(verified.signer_public_key_hex, RFC8032_TEST1_PUBLIC_KEY_HEX);
    assert_eq!(
        verified.integrity_hash,
        fixture_value()["integrity_hash"].as_str().unwrap()
    );
}

#[test]
fn foreign_trust_anchor_is_rejected() {
    let other = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]).verifying_key();
    assert_eq!(
        verify_incident_bundle(FIXTURE, &other),
        Err(IncidentBundleError::SignerNotTrusted)
    );
}

#[test]
fn tampered_timeline_fails_integrity() {
    let mut value = fixture_value();
    value["timeline"][1]["payload"]["risk"] = Value::from(10);
    let err = verify_incident_bundle(&serde_json::to_vec(&value).unwrap(), &anchor()).unwrap_err();
    assert!(
        matches!(err, IncidentBundleError::IntegrityMismatch { .. }),
        "{err}"
    );
}

#[test]
fn resealed_tamper_without_key_fails_signature() {
    let mut value = fixture_value();
    value["timeline"][1]["payload"]["risk"] = Value::from(10);
    value["chunks"][0]["events"][1]["payload"]["risk"] = Value::from(10);
    // Keep the decision-sequence re-derivation consistent so the signature
    // is the check under test.
    let sequence = serde_json::json!({
        "timeline": value["timeline"],
        "initial_state_snapshot": value["initial_state_snapshot"],
        "policy_version": value["policy_version"],
    });
    value["manifest"]["decision_sequence_hash"] =
        Value::String(incident_bundle_canonical_digest(&sequence, "$.decision_sequence").unwrap());
    reseal_integrity(&mut value);
    let payload = incident_bundle_signature_payload(value["integrity_hash"].as_str().unwrap());
    value["signature"]["signed_payload_sha256"] =
        Value::String(hex::encode(Sha256::digest(&payload)));
    assert_eq!(
        verify_incident_bundle(&serde_json::to_vec(&value).unwrap(), &anchor()),
        Err(IncidentBundleError::SignatureInvalid)
    );
}

#[test]
fn decision_sequence_rederivation_is_load_bearing() {
    let mut value = fixture_value();
    value["manifest"]["decision_sequence_hash"] = Value::String("0".repeat(64));
    reseal_integrity(&mut value);
    let err = verify_incident_bundle(&serde_json::to_vec(&value).unwrap(), &anchor()).unwrap_err();
    assert!(
        matches!(err, IncidentBundleError::DecisionSequenceMismatch { .. }),
        "{err}"
    );
}

#[test]
fn unsigned_extra_field_is_rejected() {
    let mut value = fixture_value();
    value["operator_note"] = Value::String("trust me".into());
    assert_eq!(
        verify_incident_bundle(&serde_json::to_vec(&value).unwrap(), &anchor()),
        Err(IncidentBundleError::UnknownField {
            field: "operator_note".into()
        })
    );
}
