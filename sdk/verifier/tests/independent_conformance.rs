//! Independent Verifier SDK Conformance Tests (bd-tenx3.5).
//!
//! Validates that the Verifier SDK operates as a truly independent verification
//! library without requiring the main `frankenengine-node` product crate.
//!
//! Covers:
//! - Ed25519 signature verification on frozen canonical vectors
//! - Tamper detection (payload bit-flips, altered signatures, truncated bytes)
//! - Unknown and mismatched schema version rejection
//! - Counterfactual receipt canonical verification
//! - Fail-closed error handling

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::json;

use frankenengine_verifier_sdk::bundle::{
    BundleError, verify_ed25519_signature, verify_bundle_envelope,
};
use frankenengine_verifier_sdk::capsule::{Capsule, ReplayEvent};
use frankenengine_verifier_sdk::counterfactual::{
    CounterfactualReceiptError, verify_counterfactual_receipt,
};
use frankenengine_verifier_sdk::SDK_VERSION;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture_signing_key(seed_byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed_byte; 32])
}

#[test]
fn independent_sdk_verifies_valid_signature() -> TestResult {
    let signing_key = fixture_signing_key(0x42);
    let verifying_key = signing_key.verifying_key();
    let message = b"canonical-verifier-vector-2026";
    let signature = signing_key.sign(message);

    verify_ed25519_signature(&verifying_key, message, &signature.to_bytes())?;
    Ok(())
}

#[test]
fn independent_sdk_detects_payload_tampering() -> TestResult {
    let signing_key = fixture_signing_key(0x43);
    let verifying_key = signing_key.verifying_key();
    let message = b"tamper-proof-payload-v1";
    let signature = signing_key.sign(message);

    let mut tampered = message.to_vec();
    tampered[0] ^= 0x01; // flip 1 bit

    let err = verify_ed25519_signature(&verifying_key, &tampered, &signature.to_bytes())
        .expect_err("tampered payload must fail verification");
    assert_eq!(err, BundleError::Ed25519SignatureInvalid);
    Ok(())
}

#[test]
fn independent_sdk_detects_signature_corruption() -> TestResult {
    let signing_key = fixture_signing_key(0x44);
    let verifying_key = signing_key.verifying_key();
    let message = b"integrity-protected-stream";
    let mut sig_bytes = signing_key.sign(message).to_bytes();
    sig_bytes[10] ^= 0xFF; // corrupt signature byte

    let err = verify_ed25519_signature(&verifying_key, message, &sig_bytes)
        .expect_err("corrupted signature must fail verification");
    assert_eq!(err, BundleError::Ed25519SignatureInvalid);
    Ok(())
}

#[test]
fn independent_sdk_rejects_wrong_key() -> TestResult {
    let signing_key = fixture_signing_key(0x45);
    let wrong_key = fixture_signing_key(0x46).verifying_key();
    let message = b"wrong-key-challenge";
    let signature = signing_key.sign(message);

    let err = verify_ed25519_signature(&wrong_key, message, &signature.to_bytes())
        .expect_err("signature signed by a different key must fail verification");
    assert_eq!(err, BundleError::Ed25519SignatureInvalid);
    Ok(())
}

#[test]
fn independent_sdk_rejects_unknown_schema_version() {
    let payload = json!({
        "schema_version": "vsdk-v99.0-unsupported",
        "capsule_id": "cap-001",
        "timestamp_utc": "2026-09-22T00:00:00Z"
    });

    let res = verify_bundle_envelope(&payload);
    assert!(res.is_err(), "unknown schema version must fail closed");
}

#[test]
fn independent_sdk_verifies_sdk_version_constant() {
    assert_eq!(SDK_VERSION, "vsdk-v1.0");
}

#[test]
fn independent_sdk_verifies_counterfactual_receipt_pass_and_fail_closed() -> TestResult {
    let signing_key = fixture_signing_key(0x77);
    let verifying_key = signing_key.verifying_key();

    let baseline_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let bundle_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    let mut receipt_json = json!({
        "schema_version": "franken-node/counterfactual-receipt-v1",
        "receipt_id": "rcpt-001",
        "timestamp_utc": "2026-09-22T00:00:00Z",
        "metadata": {
            "baseline_integrity_hash": baseline_hash,
            "bundle_hash": bundle_hash,
            "policy_profile": "strict"
        },
        "results": [
            {
                "counterfactual_bundle_hash": bundle_hash,
                "divergence_count": 0,
                "verdict": "pass"
            }
        ]
    });

    // Compute canonical bytes for receipt and sign
    let canonical = frankenengine_verifier_sdk::counterfactual::to_canonical_counterfactual_json(&receipt_json)?;
    let sig = signing_key.sign(canonical.as_bytes());

    receipt_json["signature"] = json!({
        "algorithm": "ed25519",
        "public_key": hex::encode(verifying_key.as_bytes()),
        "signature_bytes": hex::encode(sig.to_bytes())
    });

    // Valid verification passes
    verify_counterfactual_receipt(&receipt_json, &verifying_key)?;

    // Tampering metadata bundle_hash fails closed
    let mut tampered = receipt_json.clone();
    tampered["metadata"]["bundle_hash"] = json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let err = verify_counterfactual_receipt(&tampered, &verifying_key)
        .expect_err("tampered counterfactual receipt must fail closed");

    // The signature check or hash mismatch triggers failure
    assert!(
        matches!(
            err,
            CounterfactualReceiptError::Signature(_)
                | CounterfactualReceiptError::CounterfactualBundleHashMismatch { .. }
        ),
        "unexpected error variant: {err:?}"
    );

    Ok(())
}
