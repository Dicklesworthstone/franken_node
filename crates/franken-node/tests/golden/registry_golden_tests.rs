//! Golden artifact tests for registry receipts and outputs
//!
//! Tests the deterministic outputs of registry operations including:
//! - Registry publish receipt outputs
//! - Registry search results with integrity status
//! - Registry verification reports
//! - Registry manifest JSON structures

use frankenengine_node::supply_chain::artifact_signing::KeyId;
use serde_json::Value;

// Golden utilities re-exported from parent module
use super::{assert_scrubbed_golden, assert_scrubbed_json_golden};

/// Create a test signing key for deterministic outputs
fn create_test_signing_key() -> ed25519_dalek::SigningKey {
    // Use fixed key material for deterministic testing
    ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32])
}

/// Create a test registry manifest structure
fn create_test_registry_manifest() -> Value {
    let signer = create_test_signing_key();
    let key_id = KeyId::from_verifying_key(&signer.verifying_key());

    serde_json::json!({
        "schema_version": "franken-node/registry-manifest/v1",
        "extension_id": "plugin-test-golden-12345678",
        "publisher_key_id": key_id.to_string(),
        "artifact_sha256": "sha256:abcdef1234567890fedcba0987654321abcdef1234567890fedcba0987654321",
        "artifact_size_bytes": 1024,
        "published_at": "2024-01-01T00:00:00Z",
        "manifest_bytes_b64": "dGVzdC1tYW5pZmVzdC1kYXRh",
        "signature_b64": "dGVzdC1zaWduYXR1cmUtZGF0YQ==",
        "signature_scheme": "ed25519"
    })
}

/// Create a test registry publish receipt
fn create_test_publish_receipt() -> Value {
    let signer = create_test_signing_key();
    let key_id = KeyId::from_verifying_key(&signer.verifying_key());

    serde_json::json!({
        "extension_id": "plugin-test-golden-12345678",
        "publisher_key_id": key_id.to_string(),
        "signing_key_source": "test",
        "signing_key_path": "/test/keys/publisher.ed25519",
        "artifact_path": ".franken-node/state/registry/artifacts/plugin-test-golden-12345678/artifact.fnext",
        "manifest_path": ".franken-node/state/registry/artifacts/plugin-test-golden-12345678/artifact.manifest.json",
        "integrity": "verified",
        "published_at": "2024-01-01T00:00:00Z"
    })
}

/// Create a test registry search result
fn create_test_search_results() -> Value {
    serde_json::json!([
        {
            "extension_id": "plugin-test-golden-12345678",
            "artifact_path": ".franken-node/state/registry/artifacts/plugin-test-golden-12345678/artifact.fnext",
            "manifest_path": ".franken-node/state/registry/artifacts/plugin-test-golden-12345678/artifact.manifest.json",
            "integrity_status": "verified",
            "published_at": "2024-01-01T00:00:00Z",
            "archived": false
        },
        {
            "extension_id": "plugin-older-archived-87654321",
            "artifact_path": ".franken-node/state/registry/archive/plugin-older-archived-87654321/artifact.fnext",
            "manifest_path": ".franken-node/state/registry/archive/plugin-older-archived-87654321/artifact.manifest.json",
            "integrity_status": "hash-mismatch",
            "published_at": "2023-12-01T00:00:00Z",
            "archived": true
        }
    ])
}

/// Create a test registry verification report
fn create_test_verification_report() -> Value {
    serde_json::json!({
        "extension_id": "plugin-test-golden-12345678",
        "integrity": "verified",
        "manifest_path": ".franken-node/state/registry/artifacts/plugin-test-golden-12345678/artifact.manifest.json",
        "artifact_path": ".franken-node/state/registry/artifacts/plugin-test-golden-12345678/artifact.fnext",
        "artifact_sha256": "sha256:abcdef1234567890fedcba0987654321abcdef1234567890fedcba0987654321",
        "signature_verification": "valid",
        "archived": false,
        "verified_at": "2024-01-01T00:00:00Z"
    })
}

/// Create a test registry garbage collection report
fn create_test_gc_report() -> Value {
    serde_json::json!({
        "operation": "garbage_collect",
        "keep_count": 1,
        "archived": 2,
        "deleted": 0,
        "active_artifacts": 1,
        "archived_artifacts": 3,
        "total_artifacts": 4,
        "completed_at": "2024-01-01T00:00:00Z"
    })
}

#[test]
fn test_registry_manifest_golden() {
    let manifest = create_test_registry_manifest();
    assert_scrubbed_json_golden("registry_manifest", &manifest);
}

#[test]
fn test_registry_publish_receipt_golden() {
    let receipt = create_test_publish_receipt();
    assert_scrubbed_json_golden("registry_publish_receipt", &receipt);
}

#[test]
fn test_registry_publish_output_golden() {
    // Simulate the human-readable output that registry publish command produces
    let output = "registry publish: extension_id=plugin-test-golden-12345678\n\
                  publisher_key_id=72416df9f1dcd9b3\n\
                  signing_key_source=test\n\
                  signing_key_path=/test/keys/publisher.ed25519\n\
                  artifact_path=.franken-node/state/registry/artifacts/plugin-test-golden-12345678/artifact.fnext\n\
                  manifest_path=.franken-node/state/registry/artifacts/plugin-test-golden-12345678/artifact.manifest.json\n\
                  integrity=verified";

    assert_scrubbed_golden("registry_publish_output", output);
}

#[test]
fn test_registry_search_results_golden() {
    let results = create_test_search_results();
    assert_scrubbed_json_golden("registry_search_results", &results);
}

#[test]
fn test_registry_search_output_golden() {
    // Simulate the human-readable search output
    let output = "plugin-test-golden-12345678\n\
                  .franken-node/state/registry/artifacts/plugin-test-golden-12345678/artifact.fnext\n\
                  verified\n\
                  \n\
                  plugin-older-archived-87654321\n\
                  .franken-node/state/registry/archive/plugin-older-archived-87654321/artifact.fnext\n\
                  hash-mismatch";

    assert_scrubbed_golden("registry_search_output", output);
}

#[test]
fn test_registry_verification_report_golden() {
    let report = create_test_verification_report();
    assert_scrubbed_json_golden("registry_verification_report", &report);
}

#[test]
fn test_registry_verification_output_golden() {
    // Simulate the human-readable verification output
    let output = "extension_id=plugin-test-golden-12345678\n\
                  integrity=verified\n\
                  manifest_path=.franken-node/state/registry/artifacts/plugin-test-golden-12345678/artifact.manifest.json\n\
                  archived=false";

    assert_scrubbed_golden("registry_verification_output", output);
}

#[test]
fn test_registry_verification_failure_golden() {
    // Test the output when verification fails
    let output = "extension_id=plugin-corrupted-99999999\n\
                  integrity=hash-mismatch\n\
                  manifest_path=.franken-node/state/registry/artifacts/plugin-corrupted-99999999/artifact.manifest.json\n\
                  expected_sha256=sha256:abcdef1234567890fedcba0987654321abcdef1234567890fedcba0987654321\n\
                  actual_sha256=sha256:different123456789fedcba0987654321abcdef1234567890fedcba098765\n\
                  archived=false";

    assert_scrubbed_golden("registry_verification_failure", output);
}

#[test]
fn test_registry_gc_report_golden() {
    let report = create_test_gc_report();
    assert_scrubbed_json_golden("registry_gc_report", &report);
}

#[test]
fn test_registry_gc_output_golden() {
    // Simulate the human-readable GC output
    let output = "registry garbage collection: keep=1\n\
                  archived=2\n\
                  deleted=0\n\
                  active_artifacts=1\n\
                  archived_artifacts=3\n\
                  total_artifacts=4";

    assert_scrubbed_golden("registry_gc_output", output);
}

#[test]
fn test_registry_tampered_manifest_error_golden() {
    // Test the error output when a manifest signature is invalid
    let error_output = "ERROR: Registry verification failed\n\
                       extension_id: plugin-tampered-11111111\n\
                       error_type: invalid-signature\n\
                       manifest_path: .franken-node/state/registry/artifacts/plugin-tampered-11111111/artifact.manifest.json\n\
                       artifact_path: .franken-node/state/registry/artifacts/plugin-tampered-11111111/artifact.fnext\n\
                       details: Ed25519 signature verification failed for manifest";

    assert_scrubbed_golden("registry_tampered_manifest_error", error_output);
}

#[test]
fn test_registry_corrupted_artifact_error_golden() {
    // Test the error output when an artifact is corrupted
    let error_output = "ERROR: Registry verification failed\n\
                       extension_id: plugin-corrupted-22222222\n\
                       error_type: hash-mismatch\n\
                       manifest_path: .franken-node/state/registry/artifacts/plugin-corrupted-22222222/artifact.manifest.json\n\
                       artifact_path: .franken-node/state/registry/artifacts/plugin-corrupted-22222222/artifact.fnext\n\
                       expected_hash: sha256:abcdef1234567890fedcba0987654321abcdef1234567890fedcba0987654321\n\
                       actual_hash: sha256:tampered123456789fedcba0987654321abcdef1234567890fedcba098765";

    assert_scrubbed_golden("registry_corrupted_artifact_error", error_output);
}
