//! VEF Receipt Schema Conformance Harness
//!
//! Tests canonical ExecutionReceipt serialization against reference vectors.
//! Validates INV-VEF-RECEIPT-* invariants using artifacts/10.18/vef_receipt_schema_vectors.json.
//!
//! Coverage:
//! - Round-trip serialization/deserialization
//! - Canonical witness reference ordering (sort + dedup)
//! - Deterministic hash computation
//! - Schema version validation

use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Load reference vectors from embedded artifact file.
const VEF_RECEIPT_VECTORS_JSON: &str =
    include_str!("../../../artifacts/10.18/vef_receipt_schema_vectors.json");

#[derive(Debug, Deserialize)]
struct VefReceiptConformanceVectors {
    #[allow(dead_code)]
    bead_id: String,
    schema_version: String,
    receipt_schema_version: String,
    #[allow(dead_code)]
    description: String,
    vectors: Vec<VefReceiptVector>,
}

#[derive(Debug, Deserialize)]
struct VefReceiptVector {
    name: String,
    input_receipt: RawExecutionReceipt,
    expected_hash: String,
    expected_canonical_witnesses: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RawExecutionReceipt {
    schema_version: String,
    action_type: String,
    capability_context: BTreeMap<String, String>,
    actor_identity: String,
    artifact_identity: String,
    policy_snapshot_hash: String,
    timestamp_millis: u64,
    sequence_number: u64,
    witness_references: Vec<String>,
    trace_id: String,
}

impl From<RawExecutionReceipt> for ExecutionReceipt {
    fn from(raw: RawExecutionReceipt) -> Self {
        let action_type = match raw.action_type.as_str() {
            "network_access" => ExecutionActionType::NetworkAccess,
            "filesystem_operation" => ExecutionActionType::FilesystemOperation,
            "process_spawn" => ExecutionActionType::ProcessSpawn,
            "secret_access" => ExecutionActionType::SecretAccess,
            "policy_transition" => ExecutionActionType::PolicyTransition,
            "artifact_promotion" => ExecutionActionType::ArtifactPromotion,
            _ => panic!("Unknown action type: {}", raw.action_type),
        };

        Self {
            schema_version: raw.schema_version,
            action_type,
            capability_context: raw.capability_context,
            actor_identity: raw.actor_identity,
            artifact_identity: raw.artifact_identity,
            policy_snapshot_hash: raw.policy_snapshot_hash,
            timestamp_millis: raw.timestamp_millis,
            sequence_number: raw.sequence_number,
            witness_references: raw.witness_references,
            trace_id: raw.trace_id,
        }
    }
}

/// Compute canonical hash for ExecutionReceipt using domain-separated SHA256.
fn compute_canonical_hash(receipt: &ExecutionReceipt) -> String {
    let canonical = receipt.canonicalized();
    let canonical_json = serde_json::to_string(&canonical)
        .expect("receipt should serialize to JSON");

    let mut hasher = Sha256::new();
    hasher.update(b"vef_execution_receipt_v1:");
    hasher.update(canonical_json.as_bytes());
    let hash = hasher.finalize();

    format!("sha256:{}", hex::encode(hash))
}

/// Load and parse conformance vectors from embedded artifact.
fn load_conformance_vectors() -> VefReceiptConformanceVectors {
    serde_json::from_str(VEF_RECEIPT_VECTORS_JSON)
        .expect("VEF receipt vectors should be valid JSON")
}

#[test]
fn vef_receipt_schema_version_matches_vectors() {
    let vectors = load_conformance_vectors();
    assert_eq!(
        vectors.receipt_schema_version,
        RECEIPT_SCHEMA_VERSION,
        "Receipt schema version in vectors should match implementation constant"
    );
}

#[test]
fn vef_receipt_round_trip_conformance() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        // Test round-trip: RawExecutionReceipt → ExecutionReceipt → JSON → ExecutionReceipt
        let receipt: ExecutionReceipt = vector.input_receipt.clone().into();

        // Serialize to JSON
        let receipt_json = serde_json::to_string(&receipt)
            .unwrap_or_else(|e| panic!(
                "Vector '{}' failed to serialize: {}", vector.name, e
            ));

        // Deserialize back from JSON
        let receipt_roundtrip: ExecutionReceipt = serde_json::from_str(&receipt_json)
            .unwrap_or_else(|e| panic!(
                "Vector '{}' failed to deserialize: {}", vector.name, e
            ));

        // Round-trip should preserve all fields
        assert_eq!(
            receipt, receipt_roundtrip,
            "Vector '{}' failed round-trip test", vector.name
        );
    }
}

#[test]
fn vef_receipt_witness_canonicalization_conformance() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: ExecutionReceipt = vector.input_receipt.clone().into();
        let canonical = receipt.canonicalized();

        // Witnesses should be sorted and deduplicated
        assert_eq!(
            canonical.witness_references,
            vector.expected_canonical_witnesses,
            "Vector '{}' witness canonicalization mismatch", vector.name
        );

        // Canonical witnesses should be sorted
        let mut expected_sorted = vector.expected_canonical_witnesses.clone();
        expected_sorted.sort();
        assert_eq!(
            canonical.witness_references, expected_sorted,
            "Vector '{}' canonical witnesses not properly sorted", vector.name
        );
    }
}

#[test]
fn vef_receipt_canonical_hash_conformance() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: ExecutionReceipt = vector.input_receipt.clone().into();
        let computed_hash = compute_canonical_hash(&receipt);

        assert_eq!(
            computed_hash,
            vector.expected_hash,
            "Vector '{}' canonical hash mismatch.\n\
             Expected: {}\n\
             Computed: {}",
            vector.name, vector.expected_hash, computed_hash
        );
    }
}

#[test]
fn vef_receipt_deterministic_serialization_conformance() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: ExecutionReceipt = vector.input_receipt.clone().into();

        // Same receipt should serialize identically multiple times
        let json1 = serde_json::to_string(&receipt.canonicalized()).unwrap();
        let json2 = serde_json::to_string(&receipt.canonicalized()).unwrap();

        assert_eq!(
            json1, json2,
            "Vector '{}' produced non-deterministic serialization", vector.name
        );

        // Hash should also be deterministic
        let hash1 = compute_canonical_hash(&receipt);
        let hash2 = compute_canonical_hash(&receipt);

        assert_eq!(
            hash1, hash2,
            "Vector '{}' produced non-deterministic hash", vector.name
        );
    }
}

#[test]
fn vef_receipt_schema_version_validation() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: ExecutionReceipt = vector.input_receipt.clone().into();

        // Schema version should match expected constant
        assert_eq!(
            receipt.schema_version,
            RECEIPT_SCHEMA_VERSION,
            "Vector '{}' has wrong schema version", vector.name
        );
    }
}

#[test]
fn vef_receipt_semantic_invariants() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: ExecutionReceipt = vector.input_receipt.clone().into();

        // Trace ID should not be empty
        assert!(
            !receipt.trace_id.is_empty(),
            "Vector '{}' has empty trace_id", vector.name
        );

        // Actor identity should not be empty
        assert!(
            !receipt.actor_identity.is_empty(),
            "Vector '{}' has empty actor_identity", vector.name
        );

        // Policy snapshot hash should be SHA256-prefixed
        assert!(
            receipt.policy_snapshot_hash.starts_with("sha256:"),
            "Vector '{}' policy_snapshot_hash missing sha256 prefix", vector.name
        );

        // Timestamp should be reasonable (not zero, not far future)
        assert!(
            receipt.timestamp_millis > 1_600_000_000_000, // After 2020
            "Vector '{}' timestamp_millis too old", vector.name
        );

        assert!(
            receipt.timestamp_millis < 2_000_000_000_000, // Before 2033
            "Vector '{}' timestamp_millis too far in future", vector.name
        );
    }
}