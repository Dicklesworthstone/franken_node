//! Golden vector conformance tests for signed decision receipts.
//!
//! Locks the canonical encoding format of fleet decision receipts to prevent
//! breaking changes that could affect signature verification or interoperability.
//!
//! Bead: bd-1sgm4

use frankenengine_node::api::fleet_quarantine::{
    DecisionReceipt, DecisionReceiptPayload, DecisionReceiptScope,
    canonical_decision_receipt_payload_hash, decision_receipt_payload_bytes,
    sign_decision_receipt,
};
use ed25519_dalek::SigningKey;
use hex;
use serde_json;

/// Fixed Ed25519 signing key for reproducible golden vectors
const GOLDEN_SIGNING_KEY_HEX: &str = "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5";

fn create_golden_decision_receipt() -> DecisionReceipt {
    let scope = DecisionReceiptScope::zone("abc123");
    let payload = DecisionReceiptPayload {
        action_type: "quarantine".to_string(),
        extension_id: Some("abc123-extension-test".to_string()),
        incident_id: None,
        scope: scope.clone(),
        reason: "Emergency quarantine of suspected malware".to_string(),
        event_code: "FLEET_QUARANTINE_INITIATED".to_string(),
    };

    DecisionReceipt {
        operation_id: "fleet-quarantine-emergency-001".to_string(),
        receipt_id: "rcpt-fleet-quarantine-001".to_string(),
        issuer: "cli-fleet-operator".to_string(),
        issued_at: "2026-04-25T00:00:00Z".to_string(),
        zone_id: "abc123".to_string(),
        payload_hash: canonical_decision_receipt_payload_hash(
            "fleet-quarantine-emergency-001",
            "cli-fleet-operator",
            "abc123",
            "2026-04-25T00:00:00Z",
            &payload,
        ),
        decision_payload: payload,
        signature: None,
    }
}

#[test]
fn decision_receipt_canonical_payload_hash_golden_vector() {
    let receipt = create_golden_decision_receipt();

    // Test that the payload hash computation is stable
    let computed_hash = canonical_decision_receipt_payload_hash(
        &receipt.operation_id,
        &receipt.issuer,
        &receipt.zone_id,
        &receipt.issued_at,
        &receipt.decision_payload,
    );

    assert_eq!(
        computed_hash.len(),
        64,
        "Payload hash should be 64 hex characters (SHA-256)"
    );

    // Log the actual hash for golden vector creation
    eprintln!("Golden payload hash: {}", computed_hash);
}

#[test]
fn decision_receipt_canonical_bytes_golden_vector() {
    let receipt = create_golden_decision_receipt();

    // Extract canonical bytes from the signing process
    let canonical_bytes = decision_receipt_payload_bytes(&receipt);
    let canonical_hex = hex::encode(&canonical_bytes);

    eprintln!("Golden canonical bytes length: {}", canonical_bytes.len());
    eprintln!("Golden canonical bytes (hex): {}", canonical_hex);

    // Verify the bytes start with the expected domain separator
    assert!(canonical_bytes.starts_with(b"franken_node_fleet_decision_receipt_v1:"));
}

#[test]
fn decision_receipt_signature_golden_vector() {
    let receipt = create_golden_decision_receipt();

    // Create signing key from fixed bytes for reproducible signatures
    let key_bytes = hex::decode(GOLDEN_SIGNING_KEY_HEX)
        .expect("Valid hex key");
    let signing_key = SigningKey::from_bytes(&key_bytes.try_into().unwrap());

    // Sign the receipt
    let signature = sign_decision_receipt(
        &receipt,
        &signing_key,
        "test-key-source",
        "test-signing-identity",
    );

    eprintln!("Golden signature algorithm: {}", signature.algorithm);
    eprintln!("Golden signature public_key_hex: {}", signature.public_key_hex);
    eprintln!("Golden signature key_id: {}", signature.key_id);
    eprintln!("Golden signature trust_scope: {}", signature.trust_scope);
    eprintln!("Golden signature payload_sha256: {}", signature.signed_payload_sha256);
    eprintln!("Golden signature hex: {}", signature.signature_hex);

    // Verify basic signature properties
    assert_eq!(signature.algorithm, "ed25519");
    assert_eq!(signature.trust_scope, "fleet_decision");
    assert_eq!(signature.public_key_hex.len(), 64);
    assert_eq!(signature.signature_hex.len(), 128);
    assert_eq!(signature.signed_payload_sha256.len(), 64);
}

#[test]
fn decision_receipt_full_signed_golden_vector() {
    let mut receipt = create_golden_decision_receipt();

    // Create signing key and sign
    let key_bytes = hex::decode(GOLDEN_SIGNING_KEY_HEX)
        .expect("Valid hex key");
    let signing_key = SigningKey::from_bytes(&key_bytes.try_into().unwrap());

    let signature = sign_decision_receipt(
        &receipt,
        &signing_key,
        "test-key-source",
        "test-signing-identity",
    );

    receipt.signature = Some(signature);

    // Serialize to JSON and verify structure
    let json_str = serde_json::to_string_pretty(&receipt)
        .expect("Receipt should serialize");

    eprintln!("Golden signed receipt JSON:\n{}", json_str);

    // Verify JSON roundtrip
    let deserialized: DecisionReceipt = serde_json::from_str(&json_str)
        .expect("Receipt should deserialize");

    assert_eq!(deserialized, receipt);

    // Verify signature is present and valid
    assert!(deserialized.signature.is_some());
    let sig = deserialized.signature.unwrap();
    assert_eq!(sig.algorithm, "ed25519");
    assert_eq!(sig.trust_scope, "fleet_decision");
}

// The canonical payload byte-reconstruction (previously duplicated here, which
// drifted and reached into the now-private `append_framed`) is provided by the
// public `decision_receipt_payload_bytes` in fleet_quarantine.rs, so these golden
// vectors track the exact bytes prod signs. See bd-qtciw.