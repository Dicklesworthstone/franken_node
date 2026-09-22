//! Verifier SDK independent registry signature verification tests.
//!
//! Validates that the SDK can independently verify Ed25519 signatures on
//! canonical extension registry manifest structures without depending on the
//! runtime crate.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use frankenengine_verifier_sdk::bundle::{BundleError, verify_ed25519_signature};
use serde::{Deserialize, Serialize};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryManifestEntry {
    name: String,
    publisher_id: String,
    version: String,
    content_hash: String,
    tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExtensionSignatureWire {
    key_id: String,
    algorithm: String,
    signature_bytes: Vec<u8>,
    signed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedRegistryRecord {
    entry: RegistryManifestEntry,
    signature: ExtensionSignatureWire,
    manifest_bytes: Vec<u8>,
}

#[test]
fn sdk_independently_verifies_registry_manifest_signature() -> TestResult {
    let (record, public_key) = create_signed_registry_record()?;

    assert_eq!(record.signature.algorithm, "ed25519");

    // Valid signature verifies successfully
    verify_ed25519_signature(
        &public_key,
        &record.manifest_bytes,
        &record.signature.signature_bytes,
    )?;

    // Bit-flipped manifest payload fails verification
    let mut mutated_manifest = record.manifest_bytes.clone();
    if let Some(first_byte) = mutated_manifest.first_mut() {
        *first_byte ^= 0x01;
    }

    let err = verify_ed25519_signature(
        &public_key,
        &mutated_manifest,
        &record.signature.signature_bytes,
    )
    .expect_err("mutated registry manifest unexpectedly verified");
    assert_eq!(err, BundleError::Ed25519SignatureInvalid);

    // Corrupted signature bytes fail verification
    let mut mutated_sig = record.signature.signature_bytes.clone();
    if let Some(last_byte) = mutated_sig.last_mut() {
        *last_byte ^= 0xff;
    }
    let err2 = verify_ed25519_signature(&public_key, &record.manifest_bytes, &mutated_sig)
        .expect_err("corrupted signature unexpectedly verified");
    assert_eq!(err2, BundleError::Ed25519SignatureInvalid);

    // Wrong public key fails verification
    let other_key = SigningKey::from_bytes(&[99_u8; 32]).verifying_key();
    let err3 = verify_ed25519_signature(
        &other_key,
        &record.manifest_bytes,
        &record.signature.signature_bytes,
    )
    .expect_err("wrong key unexpectedly verified");
    assert_eq!(err3, BundleError::Ed25519SignatureInvalid);

    Ok(())
}

fn create_signed_registry_record() -> TestResult<(SignedRegistryRecord, VerifyingKey)> {
    let signing_key = SigningKey::from_bytes(&[42_u8; 32]);
    let verifying_key = signing_key.verifying_key();

    let entry = RegistryManifestEntry {
        name: "chain-verify-registry".to_string(),
        publisher_id: "pub-001".to_string(),
        version: "1.0.0".to_string(),
        content_hash: "c".repeat(64),
        tags: vec!["sdk-verifier".to_string(), "registry".to_string()],
    };

    let manifest_bytes = serde_json::to_vec(&entry)?;
    let signature = signing_key.sign(&manifest_bytes);

    let record = SignedRegistryRecord {
        entry,
        signature: ExtensionSignatureWire {
            key_id: hex::encode(verifying_key.as_bytes()),
            algorithm: "ed25519".to_string(),
            signature_bytes: signature.to_bytes().to_vec(),
            signed_at: "2023-11-14T22:13:20Z".to_string(),
        },
        manifest_bytes,
    };

    Ok((record, verifying_key))
}
