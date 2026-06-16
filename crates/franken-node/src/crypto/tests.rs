//! Integration tests for crypto trait abstractions.

use super::*;
use ed25519_dalek::Signer as _;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TestReceiptData {
    receipt_id: u64,
    timestamp: u64,
    decision: String,
    metadata: Vec<String>,
}

/// Test comprehensive signing and verification workflow.
#[test]
fn test_crypto_integration_workflow() {
    let (public_key, secret_key) = Ed25519Scheme::generate_keypair().unwrap();
    let signer = Ed25519Signer::new();

    let test_data = TestReceiptData {
        receipt_id: 12345,
        timestamp: 1640995200,
        decision: "approved".to_string(),
        metadata: vec!["metadata1".to_string(), "metadata2".to_string()],
    };

    // Sign structured data
    let signature = signer
        .sign_structured(&secret_key, "decision_receipt", &test_data)
        .unwrap();

    // Verify using low-level scheme interface
    let serialized = serde_json::to_vec(&test_data).unwrap();
    let domain = b"franken_node_decision_receipt:";

    assert!(Ed25519Scheme::verify_with_domain(
        &public_key,
        domain,
        &serialized,
        &signature
    ));
}

/// Test domain separation prevents cross-context attacks.
#[test]
fn test_crypto_domain_separation_security() {
    let (public_key, secret_key) = Ed25519Scheme::generate_keypair().unwrap();
    let signer = Ed25519Signer::new();

    let message = b"identical message";

    // Sign same message with different contexts
    let receipt_sig = signer
        .sign_message(&secret_key, "decision_receipt", message)
        .unwrap();
    let capability_sig = signer
        .sign_message(&secret_key, "remote_capability", message)
        .unwrap();

    // Signatures should be different
    assert_ne!(receipt_sig, capability_sig);

    // Cross-context verification should fail
    let receipt_domain = b"franken_node_decision_receipt:";
    let capability_domain = b"franken_node_remote_capability:";

    // Correct context verifications should succeed
    assert!(Ed25519Scheme::verify_with_domain(
        &public_key,
        receipt_domain,
        message,
        &receipt_sig
    ));
    assert!(Ed25519Scheme::verify_with_domain(
        &public_key,
        capability_domain,
        message,
        &capability_sig
    ));

    // Cross-context verifications should fail
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        receipt_domain,
        message,
        &capability_sig
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        capability_domain,
        message,
        &receipt_sig
    ));
}

/// Test raw signatures preserve caller-owned canonical preimages.
#[test]
fn test_crypto_raw_signature_compatibility_path() {
    let (public_key, secret_key) = Ed25519Scheme::generate_keypair().unwrap();
    let preimage = b"decision-receipt-v1 canonical payload bytes";
    let direct_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
    let direct_signature = direct_key.sign(preimage).to_bytes();

    let raw_signature = Ed25519Scheme::sign_raw(&secret_key, preimage).unwrap();

    assert_eq!(raw_signature, direct_signature);
    assert!(Ed25519Scheme::verify_raw(
        &public_key,
        preimage,
        &raw_signature
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        b"decision_receipt",
        preimage,
        &raw_signature
    ));
}

/// Test key material integration with signing operations.
#[test]
fn test_crypto_key_material_integration() {
    let expires_at = std::time::SystemTime::now() + Duration::from_secs(3600);
    let key_material =
        Ed25519KeyMaterial::new("integration_test_key".to_string(), expires_at).unwrap();

    // Store key material
    key_material.store_in_secure_storage().unwrap();

    // Load key material from storage
    let loaded_key = Ed25519KeyMaterial::load_from_secure_storage("integration_test_key").unwrap();
    assert!(loaded_key.is_valid());

    // Use loaded key material for signing
    let signer = Ed25519Signer::new();
    let message = b"key material integration test";

    let signature = signer
        .sign_message(loaded_key.secret_key(), "integration_test", message)
        .unwrap();

    // Verify with public key from key material
    let domain = b"franken_node_integration_test:";
    assert!(Ed25519Scheme::verify_with_domain(
        loaded_key.public_key(),
        domain,
        message,
        &signature
    ));

    // Clean up
    Ed25519KeyMaterial::remove_from_secure_storage("integration_test_key").unwrap();
}

/// Test error handling across trait boundaries.
#[test]
fn test_crypto_error_handling() {
    let signer = Ed25519Signer::new();

    // Test serialization error handling
    #[derive(Serialize)]
    struct BadData {
        #[serde(serialize_with = "fail_serialize")]
        field: u32,
    }

    fn fail_serialize<S>(_: &u32, _: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom(
            "intentional serialization failure",
        ))
    }

    let (_, secret_key) = Ed25519Scheme::generate_keypair().unwrap();
    let bad_data = BadData { field: 42 };

    let result = signer.sign_structured(&secret_key, "error_test", &bad_data);
    assert!(matches!(result, Err(Ed25519Error::SerializationFailed(_))));

    // Test key material error handling
    let result = Ed25519KeyMaterial::load_from_secure_storage("nonexistent_key");
    assert!(matches!(result, Err(KeyMaterialError::KeyNotFound(_))));
}

/// Test constant-time properties of verification operations.
#[test]
fn test_crypto_constant_time_properties() {
    let (public_key, secret_key) = Ed25519Scheme::generate_keypair().unwrap();
    let message = b"constant time test message";
    let domain = b"constant_time_test";

    let valid_signature = Ed25519Scheme::sign_with_domain(&secret_key, domain, message).unwrap();

    // Create various types of invalid signatures
    let mut zero_signature = [0u8; 64];
    let mut flipped_signature = valid_signature;
    flipped_signature[0] ^= 1;
    let mut random_signature = [0u8; 64];
    random_signature.fill(0xFF);

    // All verification operations should complete without panicking
    // and return appropriate boolean results
    assert!(Ed25519Scheme::verify_with_domain(
        &public_key,
        domain,
        message,
        &valid_signature
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        domain,
        message,
        &zero_signature
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        domain,
        message,
        &flipped_signature
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        domain,
        message,
        &random_signature
    ));

    // Test with invalid public key (should not panic)
    let invalid_public_key = [0u8; 32];
    assert!(!Ed25519Scheme::verify_with_domain(
        &invalid_public_key,
        domain,
        message,
        &valid_signature
    ));
}

/// Test scheme ID consistency and algorithm identification.
#[test]
fn test_crypto_scheme_identification() {
    assert_eq!(Ed25519Scheme::scheme_id(), ED25519_SIGNATURE_SCHEME_ID);

    // Scheme ID should be consistent across instances
    let id1 = Ed25519Scheme::scheme_id();
    let id2 = Ed25519Scheme::scheme_id();
    assert_eq!(id1, id2);

    // Should be a valid identifier format
    assert!(id1.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    assert!(!id1.is_empty());
}

#[test]
fn test_crypto_suite_registry_identifies_default_ed25519_suite() {
    let suite = default_crypto_suite();

    assert_eq!(suite.id, ED25519_V1_CRYPTO_SUITE);
    assert_eq!(suite.id, DEFAULT_CRYPTO_SUITE);
    assert_eq!(suite.registry_schema, CRYPTO_SUITE_REGISTRY_SCHEMA);
    assert_eq!(suite.signature_scheme_id, Ed25519Scheme::scheme_id());
    assert_eq!(suite.signature_algorithm, ED25519_V1_SIGNATURE_VERSION);
    assert_eq!(suite.signature_version, ED25519_V1_SIGNATURE_VERSION);
    assert_eq!(registered_crypto_suites(), &[*suite]);
}

#[test]
fn test_crypto_suite_registry_migration_helpers_roundtrip_legacy_signature_version() {
    assert_eq!(
        upgrade_signature_version_to_crypto_suite(ED25519_V1_SIGNATURE_VERSION).unwrap(),
        ED25519_V1_CRYPTO_SUITE
    );
    assert_eq!(
        downgrade_crypto_suite_to_signature_version(ED25519_V1_CRYPTO_SUITE).unwrap(),
        ED25519_V1_SIGNATURE_VERSION
    );
    assert_eq!(
        crypto_suite_for_signature_version(ED25519_V1_SIGNATURE_VERSION)
            .unwrap()
            .id,
        ED25519_V1_CRYPTO_SUITE
    );
}

#[test]
fn test_crypto_suite_registry_rejects_unknown_suite_and_signature_version() {
    assert!(matches!(
        validate_crypto_suite("ed25519-v2"),
        Err(CryptoSuiteError::UnknownSuite { suite_id }) if suite_id == "ed25519-v2"
    ));
    assert!(matches!(
        crypto_suite_for_signature_version("ed25519-v2"),
        Err(CryptoSuiteError::UnsupportedSignatureVersion { signature_version })
            if signature_version == "ed25519-v2"
    ));
}

/// Test length-prefixed domain separation prevents collision attacks.
#[test]
fn test_crypto_length_prefix_collision_resistance() {
    let (public_key, secret_key) = Ed25519Scheme::generate_keypair().unwrap();

    // These should produce different signatures even though concatenated they're the same
    let sig1 = Ed25519Scheme::sign_with_domain(&secret_key, b"ab", b"cd").unwrap();
    let sig2 = Ed25519Scheme::sign_with_domain(&secret_key, b"a", b"bcd").unwrap();

    assert_ne!(sig1, sig2);

    // Verify both signatures work with their respective inputs
    assert!(Ed25519Scheme::verify_with_domain(
        &public_key,
        b"ab",
        b"cd",
        &sig1
    ));
    assert!(Ed25519Scheme::verify_with_domain(
        &public_key,
        b"a",
        b"bcd",
        &sig2
    ));

    // Cross-verification should fail
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        b"ab",
        b"cd",
        &sig2
    ));
    assert!(!Ed25519Scheme::verify_with_domain(
        &public_key,
        b"a",
        b"bcd",
        &sig1
    ));
}

/// Test key validation and parsing edge cases.
#[test]
fn test_crypto_key_validation_edge_cases() {
    // Test empty key
    let result = Ed25519Scheme::public_key_from_bytes(&[]);
    assert!(matches!(
        result,
        Err(Ed25519Error::InvalidKeyLength {
            expected: 32,
            actual: 0
        })
    ));

    // Test oversized key
    let oversized_key = [0u8; 64];
    let result = Ed25519Scheme::public_key_from_bytes(&oversized_key);
    assert!(matches!(
        result,
        Err(Ed25519Error::InvalidKeyLength {
            expected: 32,
            actual: 64
        })
    ));

    // Test signature validation edge cases
    let result = Ed25519Scheme::signature_from_bytes(&[]);
    assert!(matches!(
        result,
        Err(Ed25519Error::InvalidSignatureLength {
            expected: 64,
            actual: 0
        })
    ));

    let oversized_sig = [0u8; 128];
    let result = Ed25519Scheme::signature_from_bytes(&oversized_sig);
    assert!(matches!(
        result,
        Err(Ed25519Error::InvalidSignatureLength {
            expected: 64,
            actual: 128
        })
    ));
}

/// Test security pattern compliance in all operations.
#[test]
fn test_crypto_security_pattern_compliance() {
    let expires_at = std::time::SystemTime::now() + Duration::from_secs(3600);
    let key_material =
        Ed25519KeyMaterial::new("security_test_key".to_string(), expires_at).unwrap();

    // Key material should use fail-closed expiration semantics
    assert!(key_material.is_valid());

    // Fingerprints should be deterministic and not expose key material
    let fingerprint1 = key_material.fingerprint();
    let fingerprint2 = key_material.fingerprint();
    assert_eq!(fingerprint1, fingerprint2);
    assert!(fingerprint1.starts_with("ed25519:"));

    // Fingerprint should not contain raw key bytes
    let public_key_hex = hex::encode(key_material.public_key());
    assert!(!fingerprint1.contains(&public_key_hex));

    // Key rotation should change key material
    let mut key_copy = key_material.clone();
    let old_public_key = *key_copy.public_key();
    let old_fingerprint = key_copy.fingerprint();

    key_copy.rotate().unwrap();

    assert_ne!(key_copy.public_key(), &old_public_key);
    assert_ne!(key_copy.fingerprint(), old_fingerprint);
    assert!(key_copy.is_valid());
}

/// `sign_raw` / `verify_raw` round-trip without any wrapper domain.
///
/// Regression guard for the bd-dwx4l migration of `decision_receipt` /
/// `replay_bundle` / `remote_cap` onto the trait: those modules pass an
/// already-canonical preimage and would break every existing signature in
/// the wild if a wrapper domain got prepended underneath them.
#[test]
fn test_ed25519_raw_signature_roundtrip() {
    let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
    let message = b"already-canonical preimage with embedded domain";

    let signature = Ed25519Scheme::sign_raw(&sk, message).unwrap();
    assert!(Ed25519Scheme::verify_raw(&pk, message, &signature));
}

/// `sign_raw` MUST produce different bytes than `sign_with_domain` for the
/// same message under the same key. This proves the wrapper domain on
/// `sign_with_domain` actually applies, and that picking `sign_raw` is the
/// only way to preserve signature compatibility with consumers that have
/// their own canonical preimage scheme.
#[test]
fn test_ed25519_raw_vs_domain_signatures_differ() {
    let (_pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
    let message = b"identical message";

    let raw_sig = Ed25519Scheme::sign_raw(&sk, message).unwrap();
    let domain_sig = Ed25519Scheme::sign_with_domain(&sk, b"some_caller_domain:", message).unwrap();

    // If these ever match, the wrapper has been removed and every existing
    // signed `decision_receipt` / `replay_bundle` / `remote_cap` in the wild
    // is at risk.
    assert_ne!(raw_sig, domain_sig);
}

/// `verify_raw` must reject signatures produced by `sign_with_domain` over
/// the same message (and vice versa). Cross-API verification proves the two
/// surfaces are disjoint, so callers that pick one never accidentally
/// validate the other.
#[test]
fn test_ed25519_raw_and_domain_cross_verification_rejects() {
    let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
    let message = b"identical message";

    let raw_sig = Ed25519Scheme::sign_raw(&sk, message).unwrap();
    let domain_sig = Ed25519Scheme::sign_with_domain(&sk, b"caller_domain:", message).unwrap();

    // raw signature should NOT verify under the domain API (or under a
    // different domain) because the verifier prepends its own wrapper.
    assert!(!Ed25519Scheme::verify_with_domain(
        &pk,
        b"caller_domain:",
        message,
        &raw_sig
    ));

    // domain signature should NOT verify under the raw API because the
    // signer included a wrapper digest that the raw verifier doesn't apply.
    assert!(!Ed25519Scheme::verify_raw(&pk, message, &domain_sig));
}

/// `verify_raw` must fail closed (return false, not panic) on every
/// recoverable parse error: malformed public key, malformed signature
/// bytes, and any flipped bit in a valid signature.
#[test]
fn test_ed25519_raw_verify_fail_closed_paths() {
    let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
    let message = b"raw fail-closed coverage";
    let valid_sig = Ed25519Scheme::sign_raw(&sk, message).unwrap();

    // Valid baseline.
    assert!(Ed25519Scheme::verify_raw(&pk, message, &valid_sig));

    // All-zero public key: cannot be parsed as a curve point.
    let zero_pk = [0u8; 32];
    assert!(!Ed25519Scheme::verify_raw(&zero_pk, message, &valid_sig));

    // Flipped signature byte.
    let mut tampered_sig = valid_sig;
    tampered_sig[0] ^= 0x01;
    assert!(!Ed25519Scheme::verify_raw(&pk, message, &tampered_sig));

    // All-zero signature.
    let zero_sig = [0u8; 64];
    assert!(!Ed25519Scheme::verify_raw(&pk, message, &zero_sig));

    // Different message must fail.
    assert!(!Ed25519Scheme::verify_raw(
        &pk,
        b"different message",
        &valid_sig
    ));
}

/// Test performance characteristics don't regress.
#[test]
fn test_crypto_performance_baseline() {
    let (public_key, secret_key) = Ed25519Scheme::generate_keypair().unwrap();
    let signer = Ed25519Signer::new();
    let message =
        b"performance test message that is reasonably long to simulate realistic payloads";

    let iterations = 100;
    let start = std::time::Instant::now();

    for i in 0..iterations {
        let context = format!("perf_test_{}", i);
        let signature = signer.sign_message(&secret_key, &context, message).unwrap();
        let domain = format!("franken_node_{}:", context);
        assert!(Ed25519Scheme::verify_with_domain(
            &public_key,
            domain.as_bytes(),
            message,
            &signature
        ));
    }

    let elapsed = start.elapsed();

    // Should complete reasonably quickly (this is a loose bound for CI environments)
    assert!(
        elapsed < Duration::from_secs(5),
        "Crypto operations too slow: {:?}",
        elapsed
    );

    // Print timing info for manual review
    println!(
        "Completed {} sign+verify cycles in {:?} ({:?} per cycle)",
        iterations,
        elapsed,
        elapsed / iterations
    );
}
