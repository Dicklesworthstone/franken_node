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

use frankenengine_node::capacity_defaults::aliases::MAX_CHECKPOINTS;
use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION, receipt_hash_sha256,
};
use frankenengine_node::vef::receipt_chain::{ReceiptChain, ReceiptChainConfig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Load reference vectors from embedded artifact file.
const VEF_RECEIPT_VECTORS_JSON: &str =
    include_str!("../../../artifacts/10.18/vef_receipt_schema_vectors.json");

#[derive(Debug, Deserialize)]
struct VefReceiptConformanceVectors {
    #[allow(dead_code)]
    bead_id: String,
    #[allow(dead_code)]
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

type TestResult = Result<(), String>;

fn execution_receipt_from_raw(raw: RawExecutionReceipt) -> Result<ExecutionReceipt, String> {
    let action_type = match raw.action_type.as_str() {
        "network_access" => ExecutionActionType::NetworkAccess,
        "filesystem_operation" => ExecutionActionType::FilesystemOperation,
        "process_spawn" => ExecutionActionType::ProcessSpawn,
        "secret_access" => ExecutionActionType::SecretAccess,
        "policy_transition" => ExecutionActionType::PolicyTransition,
        "artifact_promotion" => ExecutionActionType::ArtifactPromotion,
        _ => return Err(format!("unknown action type: {}", raw.action_type)),
    };

    Ok(ExecutionReceipt {
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
    })
}

/// Compute canonical hash for ExecutionReceipt using canonical JSON bytes only.
fn compute_canonical_hash(receipt: &ExecutionReceipt) -> Result<String, String> {
    receipt_hash_sha256(receipt).map_err(|err| format!("receipt should hash canonically: {err:?}"))
}

/// Load and parse conformance vectors from embedded artifact.
fn load_conformance_vectors() -> Result<VefReceiptConformanceVectors, String> {
    serde_json::from_str(VEF_RECEIPT_VECTORS_JSON)
        .map_err(|err| format!("VEF receipt vectors should be valid JSON: {err}"))
}

fn chain_receipt(sequence_number: u64, action_type: ExecutionActionType) -> ExecutionReceipt {
    let mut capability_context = BTreeMap::new();
    capability_context.insert("capability".to_string(), format!("cap-{sequence_number}"));
    capability_context.insert("scope".to_string(), "vef-receipt-chain".to_string());

    ExecutionReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        action_type,
        capability_context,
        actor_identity: format!("actor-{sequence_number}"),
        artifact_identity: format!("artifact-{sequence_number}"),
        policy_snapshot_hash: format!("sha256:{sequence_number:064x}"),
        timestamp_millis: 1_700_002_000_000_u64.saturating_add(sequence_number),
        sequence_number,
        witness_references: vec![format!("witness-{sequence_number}")],
        trace_id: "trace-checkpoint-capacity".to_string(),
    }
}

#[test]
fn vef_receipt_schema_version_matches_vectors() -> TestResult {
    let vectors = load_conformance_vectors()?;
    assert_eq!(
        vectors.receipt_schema_version, RECEIPT_SCHEMA_VERSION,
        "Receipt schema version in vectors should match implementation constant"
    );
    Ok(())
}

#[test]
fn vef_receipt_round_trip_conformance() -> TestResult {
    let vectors = load_conformance_vectors()?;

    for vector in &vectors.vectors {
        // Test round-trip: RawExecutionReceipt → ExecutionReceipt → JSON → ExecutionReceipt
        let receipt = execution_receipt_from_raw(vector.input_receipt.clone())?;

        // Serialize to JSON
        let receipt_json = serde_json::to_string(&receipt)
            .map_err(|e| format!("Vector '{}' failed to serialize: {e}", vector.name))?;

        // Deserialize back from JSON
        let receipt_roundtrip: ExecutionReceipt = serde_json::from_str(&receipt_json)
            .map_err(|e| format!("Vector '{}' failed to deserialize: {e}", vector.name))?;

        // Round-trip should preserve all fields
        assert_eq!(
            receipt, receipt_roundtrip,
            "Vector '{}' failed round-trip test",
            vector.name
        );
    }
    Ok(())
}

#[test]
fn vef_receipt_witness_canonicalization_conformance() -> TestResult {
    let vectors = load_conformance_vectors()?;

    for vector in &vectors.vectors {
        let receipt = execution_receipt_from_raw(vector.input_receipt.clone())?;
        let canonical = receipt.canonicalized();

        // Witnesses should be sorted and deduplicated
        assert_eq!(
            canonical.witness_references, vector.expected_canonical_witnesses,
            "Vector '{}' witness canonicalization mismatch",
            vector.name
        );

        // Canonical witnesses should be sorted
        let mut expected_sorted = vector.expected_canonical_witnesses.clone();
        expected_sorted.sort();
        assert_eq!(
            canonical.witness_references, expected_sorted,
            "Vector '{}' canonical witnesses not properly sorted",
            vector.name
        );
    }
    Ok(())
}

#[test]
fn vef_receipt_canonical_hash_conformance() -> TestResult {
    let vectors = load_conformance_vectors()?;

    for vector in &vectors.vectors {
        let receipt = execution_receipt_from_raw(vector.input_receipt.clone())?;
        let computed_hash = compute_canonical_hash(&receipt)?;

        assert_eq!(
            computed_hash, vector.expected_hash,
            "Vector '{}' canonical hash mismatch.\n\
             Expected: {}\n\
             Computed: {}",
            vector.name, vector.expected_hash, computed_hash
        );
    }
    Ok(())
}

#[test]
fn vef_receipt_deterministic_serialization_conformance() -> TestResult {
    let vectors = load_conformance_vectors()?;

    for vector in &vectors.vectors {
        let receipt = execution_receipt_from_raw(vector.input_receipt.clone())?;

        // Same receipt should serialize identically multiple times
        let json1 = serde_json::to_string(&receipt.canonicalized())
            .map_err(|e| format!("Vector '{}' failed to serialize: {e}", vector.name))?;
        let json2 = serde_json::to_string(&receipt.canonicalized())
            .map_err(|e| format!("Vector '{}' failed to serialize: {e}", vector.name))?;

        assert_eq!(
            json1, json2,
            "Vector '{}' produced non-deterministic serialization",
            vector.name
        );

        // Hash should also be deterministic
        let hash1 = compute_canonical_hash(&receipt)?;
        let hash2 = compute_canonical_hash(&receipt)?;

        assert_eq!(
            hash1, hash2,
            "Vector '{}' produced non-deterministic hash",
            vector.name
        );
    }
    Ok(())
}

#[test]
fn vef_receipt_schema_version_validation() -> TestResult {
    let vectors = load_conformance_vectors()?;

    for vector in &vectors.vectors {
        let receipt = execution_receipt_from_raw(vector.input_receipt.clone())?;

        // Schema version should match expected constant
        assert_eq!(
            receipt.schema_version, RECEIPT_SCHEMA_VERSION,
            "Vector '{}' has wrong schema version",
            vector.name
        );
    }
    Ok(())
}

#[test]
fn vef_receipt_semantic_invariants() -> TestResult {
    let vectors = load_conformance_vectors()?;

    for vector in &vectors.vectors {
        let receipt = execution_receipt_from_raw(vector.input_receipt.clone())?;

        // Trace ID should not be empty
        assert!(
            !receipt.trace_id.is_empty(),
            "Vector '{}' has empty trace_id",
            vector.name
        );

        // Actor identity should not be empty
        assert!(
            !receipt.actor_identity.is_empty(),
            "Vector '{}' has empty actor_identity",
            vector.name
        );

        // Policy snapshot hash should be SHA256-prefixed
        assert!(
            receipt.policy_snapshot_hash.starts_with("sha256:"),
            "Vector '{}' policy_snapshot_hash missing sha256 prefix",
            vector.name
        );

        // Timestamp should be present. Some adversarial vectors intentionally
        // exercise maximum timestamp values.
        assert!(
            receipt.timestamp_millis > 1_600_000_000_000, // After 2020
            "Vector '{}' timestamp_millis too old",
            vector.name
        );

        assert_ne!(
            receipt.timestamp_millis, 0,
            "Vector '{}' timestamp_millis is zero",
            vector.name
        );
    }
    Ok(())
}

#[test]
fn vef_receipt_chain_checkpoint_capacity_fails_closed_without_eviction() -> TestResult {
    let mut chain = ReceiptChain::new(ReceiptChainConfig {
        checkpoint_every_entries: 1,
        checkpoint_every_millis: 0,
    });

    for seq in 0..MAX_CHECKPOINTS {
        let seq_u64 = u64::try_from(seq).unwrap_or({
            // This should never happen with MAX_CHECKPOINTS=1024, but handle gracefully
            seq as u64 // Use saturating conversion as fallback
        });
        chain
            .append(
                chain_receipt(seq_u64, ExecutionActionType::NetworkAccess),
                1_700_002_100_000_u64.saturating_add(seq_u64),
                "trace-checkpoint-capacity",
            )
            .map_err(|err| format!("append within checkpoint capacity should succeed: {err:?}"))?;
    }

    chain
        .verify_integrity()
        .map_err(|err| format!("full checkpoint set should remain verifiable: {err:?}"))?;
    assert_eq!(chain.entries().len(), MAX_CHECKPOINTS);
    assert_eq!(chain.checkpoints().len(), MAX_CHECKPOINTS);
    assert_eq!(chain.checkpoints()[0].checkpoint_id, 0);

    let err = match chain.append(
        chain_receipt(9_999, ExecutionActionType::SecretAccess),
        1_700_002_200_000,
        "trace-checkpoint-capacity-overflow",
    ) {
        Ok(_) => return Err("checkpoint overflow should fail closed".to_string()),
        Err(err) => err,
    };

    assert_eq!(err.code, "ERR-VEF-CHAIN-CHECKPOINT");
    assert!(err.message.contains("checkpoint capacity exhausted"));
    assert_eq!(chain.entries().len(), MAX_CHECKPOINTS);
    assert_eq!(chain.checkpoints().len(), MAX_CHECKPOINTS);
    assert_eq!(chain.checkpoints()[0].checkpoint_id, 0);
    chain
        .verify_integrity()
        .map_err(|err| format!("failed overflow append must not corrupt chain: {err:?}"))?;
    Ok(())
}

/// Golden test for VEF execution receipt binary format
///
/// Tests that VEF execution receipt canonical binary serialization remains stable
/// across versions. Execution receipts are cryptographically signed audit records
/// and any format change would break signature validation and compliance tooling.
#[test]
fn vef_execution_receipt_binary_format_golden() -> TestResult {
    use frankenengine_node::connector::vef_execution_receipt::serialize_canonical;
    use std::{fs, path::Path};

    // Create deterministic execution receipt for golden testing
    let mut capability_context = BTreeMap::new();
    capability_context.insert("capability".to_string(), "network.egress".to_string());
    capability_context.insert("domain".to_string(), "extensions".to_string());
    capability_context.insert("scope".to_string(), "runtime".to_string());

    let receipt = ExecutionReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        action_type: ExecutionActionType::NetworkAccess,
        capability_context,
        actor_identity: "agent:golden-test-actor".to_string(),
        artifact_identity: "artifact:ext:franken-node-core-v1.0.0".to_string(),
        policy_snapshot_hash:
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        timestamp_millis: 1704067200000, // Fixed timestamp: 2024-01-01T00:00:00Z
        sequence_number: 1000,
        witness_references: vec![
            "witness:alpha".to_string(),
            "witness:beta".to_string(),
            "witness:gamma".to_string(),
        ],
        trace_id: "trace-golden-vef-001".to_string(),
    };

    // Serialize to canonical binary format
    let binary_output = serialize_canonical(&receipt)
        .map_err(|err| format!("VEF execution receipt failed to serialize: {err}"))?;

    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/golden/vef_execution_receipt.bin");

    // Check if we're in update mode
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        let parent = golden_path
            .parent()
            .ok_or_else(|| format!("golden path has no parent: {}", golden_path.display()))?;
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create golden dir {}: {err}", parent.display()))?;
        fs::write(&golden_path, &binary_output)
            .map_err(|err| format!("failed to update golden {}: {err}", golden_path.display()))?;
        return Ok(());
    }

    // Read expected golden output
    let expected_binary = fs::read(&golden_path).map_err(|err| {
        format!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff artifacts/golden/\n\
             Read error: {err}",
            golden_path.display()
        )
    })?;

    // Compare byte-for-byte
    if !binary_output
        .as_slice()
        .cmp(expected_binary.as_slice())
        .is_eq()
    {
        let actual_path = golden_path.with_file_name("vef_execution_receipt.actual.bin");
        fs::write(&actual_path, &binary_output).map_err(|err| {
            format!(
                "failed to write actual golden {}: {err}",
                actual_path.display()
            )
        })?;

        return Err(format!(
            "GOLDEN MISMATCH: VEF execution receipt binary format changed\n\n\
             This indicates a breaking change to canonical binary serialization\n\
             that could invalidate existing signatures and break audit compliance.\n\n\
             To update: UPDATE_GOLDENS=1 cargo test vef_execution_receipt_binary_format_golden\n\
             To review: xxd {} | head -20 && echo '---' && xxd {} | head -20",
            golden_path.display(),
            actual_path.display(),
        ));
    }
    Ok(())
}
