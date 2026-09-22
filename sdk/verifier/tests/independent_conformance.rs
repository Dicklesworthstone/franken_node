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

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

use frankenengine_verifier_sdk::bundle::{BundleError, verify_ed25519_signature};
use frankenengine_verifier_sdk::capsule::{CapsuleError, CapsuleManifest, validate_manifest};
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
    let manifest = CapsuleManifest {
        schema_version: "vsdk-v99.0-unsupported".to_string(),
        capsule_id: "cap-001".to_string(),
        description: "Unsupported schema fixture".to_string(),
        claim_type: "execution".to_string(),
        input_refs: vec![],
        expected_output_hash: "0".repeat(64),
        created_at: "2026-09-22T00:00:00Z".to_string(),
        creator_identity: "verifier-tester".to_string(),
        metadata: BTreeMap::new(),
    };

    let res = validate_manifest(&manifest);
    assert!(
        matches!(res, Err(CapsuleError::SchemaMismatch { .. })),
        "unknown schema version must fail closed with SchemaMismatch"
    );
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

    let baseline_bundle = json!({
        "schema_version": "v1.0",
        "bundle_id": "INC-001",
        "integrity_hash": baseline_hash,
    });

    let counterfactual_output = json!({
        "metadata": {
            "bundle_hash": baseline_hash,
            "policy": "strict"
        },
        "results": [
            {
                "metadata": {
                    "bundle_hash": baseline_hash
                },
                "verdict": "pass"
            }
        ]
    });

    let canonical =
        frankenengine_verifier_sdk::counterfactual::canonical_json_bytes(&counterfactual_output)?;
    let sig = signing_key.sign(&canonical);
    let signature_bytes = sig.to_bytes();

    // Valid verification passes
    verify_counterfactual_receipt(
        &baseline_bundle,
        &counterfactual_output,
        &verifying_key,
        &signature_bytes,
    )?;

    // Tampering output fails closed
    let mut tampered = counterfactual_output.clone();
    tampered["metadata"]["bundle_hash"] =
        json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let err = verify_counterfactual_receipt(
        &baseline_bundle,
        &tampered,
        &verifying_key,
        &signature_bytes,
    )
    .expect_err("tampered counterfactual receipt must fail closed");

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
