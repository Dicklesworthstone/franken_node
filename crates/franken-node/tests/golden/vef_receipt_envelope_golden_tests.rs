//! Golden artifact tests for VEF receipt envelope canonical forms
//!
//! Tests the deterministic serialization and chain integrity for:
//! - ExecutionReceipt structures with canonicalization
//! - ReceiptChainEntry with hash chain validation
//! - ReceiptCheckpoint with commitment verification
//! - Receipt chain integrity and tamper detection patterns

use crate::golden;
use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionActionType, ExecutionReceipt, receipt_hash_sha256,
};
use frankenengine_node::vef::receipt_chain::{
    ChainError, GENESIS_PREV_HASH, RECEIPT_CHAIN_SCHEMA_VERSION, ReceiptChainConfig,
    ReceiptChainEntry, ReceiptCheckpoint, error_codes, event_codes,
};
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn test_execution_receipt_basic_structure() {
    // Test basic ExecutionReceipt structure serialization
    let receipt = ExecutionReceipt {
        schema_version: RECEIPT_CHAIN_SCHEMA_VERSION.to_string(),
        action_type: ExecutionActionType::NetworkAccess,
        capability_context: {
            let mut context = BTreeMap::new();
            context.insert("capability_type".to_string(), "network_egress".to_string());
            context.insert(
                "endpoint".to_string(),
                "https://api.example.com".to_string(),
            );
            context
        },
        actor_identity: "verifier-001".to_string(),
        artifact_identity: "artifact-12345".to_string(),
        policy_snapshot_hash: "sha256:abcd1234567890ef".to_string(),
        timestamp_millis: 1234567890123, // Fixed timestamp for determinism
        sequence_number: 42,
        witness_references: vec!["witness-001".to_string(), "witness-002".to_string()],
        trace_id: "trace-vef-001".to_string(),
    };

    let receipt_json = serde_json::to_value(&receipt).expect("Should serialize ExecutionReceipt");
    golden::assert_scrubbed_json_golden(
        "vef_receipt_envelope/execution_receipt_basic",
        &receipt_json,
    );
}

#[test]
fn test_execution_receipt_canonicalization() {
    // Test that canonicalization produces deterministic output
    let base_receipt = ExecutionReceipt {
        schema_version: RECEIPT_CHAIN_SCHEMA_VERSION.to_string(),
        action_type: ExecutionActionType::PolicyTransition,
        capability_context: {
            let mut context = BTreeMap::new();
            context.insert("decision_type".to_string(), "allow".to_string());
            context.insert("policy_id".to_string(), "policy-123".to_string());
            context
        },
        actor_identity: "decision-engine".to_string(),
        artifact_identity: "artifact-999".to_string(),
        policy_snapshot_hash: "sha256:fedcba0987654321".to_string(),
        timestamp_millis: 1234567890000,
        sequence_number: 1,
        witness_references: vec![
            "witness-beta".to_string(),  // Out of order
            "witness-alpha".to_string(), // Out of order
            "witness-beta".to_string(),  // Duplicate
            "witness-gamma".to_string(),
        ],
        trace_id: "trace-canon-001".to_string(),
    };

    // Test both original and canonicalized forms
    let original_json = serde_json::to_value(&base_receipt).expect("Should serialize original");
    let canonicalized = base_receipt.canonicalized();
    let canonical_json = serde_json::to_value(&canonicalized).expect("Should serialize canonical");

    let comparison = json!({
        "original": original_json,
        "canonicalized": canonical_json,
        "witness_references_changed": base_receipt.witness_references != canonicalized.witness_references,
        "original_witness_count": base_receipt.witness_references.len(),
        "canonical_witness_count": canonicalized.witness_references.len(),
    });

    golden::assert_scrubbed_json_golden(
        "vef_receipt_envelope/canonicalization_comparison",
        &comparison,
    );

    // Test that canonicalization is idempotent
    let double_canonical = canonicalized.canonicalized();
    assert_eq!(canonicalized, double_canonical);

    let idempotency_test = json!({
        "canonical_receipt": serde_json::to_value(&canonicalized).unwrap(),
        "double_canonical_receipt": serde_json::to_value(&double_canonical).unwrap(),
        "idempotent": canonicalized == double_canonical,
    });

    golden::assert_scrubbed_json_golden(
        "vef_receipt_envelope/canonicalization_idempotent",
        &idempotency_test,
    );
}

#[test]
fn test_execution_receipt_action_types() {
    // Test every ExecutionActionType variant. Iterate the prod-provided
    // `ExecutionActionType::all()` slice rather than a hard-coded list so this
    // golden cannot silently drift out of sync if the enum gains/loses variants.
    let base_receipt_template = |action_type| ExecutionReceipt {
        schema_version: RECEIPT_CHAIN_SCHEMA_VERSION.to_string(),
        action_type,
        capability_context: BTreeMap::new(),
        actor_identity: "test-actor".to_string(),
        artifact_identity: "test-artifact".to_string(),
        policy_snapshot_hash: "sha256:0123456789abcdef".to_string(),
        timestamp_millis: 1234567890000,
        sequence_number: 1,
        witness_references: vec!["witness-1".to_string()],
        trace_id: "trace-action-type".to_string(),
    };

    for &action_type in ExecutionActionType::all() {
        let receipt = base_receipt_template(action_type);
        let receipt_json = serde_json::to_value(&receipt).expect("Should serialize receipt");

        golden::assert_scrubbed_json_golden(
            &format!("vef_receipt_envelope/action_types/{action_type:?}"),
            &receipt_json,
        );
    }
}

#[test]
fn test_receipt_hash_consistency() {
    // Test that receipt hashing is deterministic and consistent
    let receipt = ExecutionReceipt {
        schema_version: RECEIPT_CHAIN_SCHEMA_VERSION.to_string(),
        action_type: ExecutionActionType::PolicyTransition,
        capability_context: {
            let mut context = BTreeMap::new();
            context.insert("test_key".to_string(), "test_value".to_string());
            context
        },
        actor_identity: "hash-test-actor".to_string(),
        artifact_identity: "hash-test-artifact".to_string(),
        policy_snapshot_hash: "sha256:hashtest123456".to_string(),
        timestamp_millis: 1234567890000,
        sequence_number: 100,
        witness_references: vec!["hash-witness-1".to_string(), "hash-witness-2".to_string()],
        trace_id: "trace-hash-test".to_string(),
    };

    // Test hash computation
    match receipt_hash_sha256(&receipt) {
        Ok(hash1) => {
            // Compute hash again to test determinism
            match receipt_hash_sha256(&receipt) {
                Ok(hash2) => {
                    // Test that canonicalized receipt produces same hash
                    let canonical_receipt = receipt.canonicalized();
                    let canonical_hash = receipt_hash_sha256(&canonical_receipt)
                        .unwrap_or_else(|_| "ERROR".to_string());

                    let hash_test = json!({
                        "receipt": serde_json::to_value(&receipt).unwrap(),
                        "hash_1": hash1,
                        "hash_2": hash2,
                        "canonical_hash": canonical_hash,
                        "deterministic": hash1 == hash2,
                        "canonical_matches": hash1 == canonical_hash,
                        "hash_format_valid": hash1.starts_with("sha256:") && hash1.len() == 71,
                    });

                    golden::assert_scrubbed_json_golden(
                        "vef_receipt_envelope/hash_consistency",
                        &hash_test,
                    );
                }
                Err(err) => {
                    let error_json = json!({
                        "error": "second_hash_failed",
                        "message": format!("{}", err),
                    });
                    golden::assert_scrubbed_json_golden(
                        "vef_receipt_envelope/hash_consistency_error",
                        &error_json,
                    );
                }
            }
        }
        Err(err) => {
            let error_json = json!({
                "error": "initial_hash_failed",
                "message": format!("{}", err),
            });
            golden::assert_scrubbed_json_golden(
                "vef_receipt_envelope/hash_consistency_error",
                &error_json,
            );
        }
    }
}

#[test]
fn test_receipt_chain_entry_structure() {
    // Test ReceiptChainEntry structure
    let receipt = ExecutionReceipt {
        schema_version: RECEIPT_CHAIN_SCHEMA_VERSION.to_string(),
        action_type: ExecutionActionType::ArtifactPromotion,
        capability_context: {
            let mut context = BTreeMap::new();
            context.insert("evidence_type".to_string(), "signature".to_string());
            context
        },
        actor_identity: "chain-test-actor".to_string(),
        artifact_identity: "chain-test-artifact".to_string(),
        policy_snapshot_hash: "sha256:chaintest987654".to_string(),
        timestamp_millis: 1234567890000,
        sequence_number: 5,
        witness_references: vec!["chain-witness".to_string()],
        trace_id: "trace-chain-001".to_string(),
    };

    let chain_entry = ReceiptChainEntry {
        index: 0, // Genesis entry
        prev_chain_hash: GENESIS_PREV_HASH.to_string(),
        receipt_hash: "sha256:1234567890abcdef1234567890abcdef12345678".to_string(),
        chain_hash: "sha256:fedcba0987654321fedcba0987654321fedcba09".to_string(),
        receipt,
        appended_at_millis: 1234567890100, // Slightly after receipt timestamp
        trace_id: "trace-chain-append-001".to_string(),
    };

    let entry_json = serde_json::to_value(&chain_entry).expect("Should serialize chain entry");
    golden::assert_scrubbed_json_golden("vef_receipt_envelope/chain_entry_basic", &entry_json);
}

#[test]
fn test_receipt_chain_progression() {
    // Test chain progression with multiple entries
    let base_receipt = ExecutionReceipt {
        schema_version: RECEIPT_CHAIN_SCHEMA_VERSION.to_string(),
        action_type: ExecutionActionType::PolicyTransition,
        capability_context: BTreeMap::new(),
        actor_identity: "progression-actor".to_string(),
        artifact_identity: "progression-artifact".to_string(),
        policy_snapshot_hash: "sha256:progression123".to_string(),
        timestamp_millis: 1234567890000,
        sequence_number: 1,
        witness_references: vec![],
        trace_id: "trace-progression".to_string(),
    };

    // Create a chain of 3 entries
    let chain_entries = vec![
        ReceiptChainEntry {
            index: 0,
            prev_chain_hash: GENESIS_PREV_HASH.to_string(),
            receipt_hash: "sha256:hash000".to_string(),
            chain_hash: "sha256:chain000".to_string(),
            receipt: {
                let mut receipt = base_receipt.clone();
                receipt.sequence_number = 0;
                receipt.trace_id = "trace-progression-0".to_string();
                receipt
            },
            appended_at_millis: 1234567890000,
            trace_id: "trace-progression-0".to_string(),
        },
        ReceiptChainEntry {
            index: 1,
            prev_chain_hash: "sha256:chain000".to_string(), // Links to previous
            receipt_hash: "sha256:hash001".to_string(),
            chain_hash: "sha256:chain001".to_string(),
            receipt: {
                let mut receipt = base_receipt.clone();
                receipt.sequence_number = 1;
                receipt.trace_id = "trace-progression-1".to_string();
                receipt
            },
            appended_at_millis: 1234567890100,
            trace_id: "trace-progression-1".to_string(),
        },
        ReceiptChainEntry {
            index: 2,
            prev_chain_hash: "sha256:chain001".to_string(), // Links to previous
            receipt_hash: "sha256:hash002".to_string(),
            chain_hash: "sha256:chain002".to_string(),
            receipt: {
                let mut receipt = base_receipt.clone();
                receipt.sequence_number = 2;
                receipt.trace_id = "trace-progression-2".to_string();
                receipt
            },
            appended_at_millis: 1234567890200,
            trace_id: "trace-progression-2".to_string(),
        },
    ];

    let chain_json = serde_json::to_value(&chain_entries).expect("Should serialize chain");
    golden::assert_scrubbed_json_golden("vef_receipt_envelope/chain_progression", &chain_json);
}

#[test]
fn test_receipt_checkpoint_structure() {
    // Test ReceiptCheckpoint structure
    let checkpoint = ReceiptCheckpoint {
        checkpoint_id: 1,
        start_index: 0,
        end_index: 63,
        entry_count: 64,
        chain_head_hash: "sha256:checkpoint_head_hash_123456".to_string(),
        commitment_hash: "sha256:checkpoint_commitment_654321".to_string(),
        created_at_millis: 1234567890000,
        trace_id: "trace-checkpoint-001".to_string(),
    };

    let checkpoint_json = serde_json::to_value(&checkpoint).expect("Should serialize checkpoint");
    golden::assert_scrubbed_json_golden("vef_receipt_envelope/checkpoint_basic", &checkpoint_json);
}

#[test]
fn test_receipt_checkpoint_boundary_conditions() {
    // Test checkpoint boundary conditions
    let checkpoint_test_cases = vec![
        (
            "empty_checkpoint",
            ReceiptCheckpoint {
                checkpoint_id: 0,
                start_index: 0,
                end_index: 0,
                entry_count: 0,
                chain_head_hash: "".to_string(),
                commitment_hash: "".to_string(),
                created_at_millis: 0,
                trace_id: "".to_string(),
            },
        ),
        (
            "single_entry_checkpoint",
            ReceiptCheckpoint {
                checkpoint_id: 1,
                start_index: 0,
                end_index: 0,
                entry_count: 1,
                chain_head_hash: "sha256:single_entry_head".to_string(),
                commitment_hash: "sha256:single_entry_commit".to_string(),
                created_at_millis: 1234567890000,
                trace_id: "trace-single".to_string(),
            },
        ),
        (
            "large_range_checkpoint",
            ReceiptCheckpoint {
                checkpoint_id: 999,
                start_index: 1000000,
                end_index: 1999999,
                entry_count: 1000000,
                chain_head_hash: "sha256:large_range_head_hash".to_string(),
                commitment_hash: "sha256:large_range_commit_hash".to_string(),
                created_at_millis: 1234567890000,
                trace_id: "trace-large-range".to_string(),
            },
        ),
        (
            "max_values_checkpoint",
            ReceiptCheckpoint {
                checkpoint_id: u64::MAX,
                start_index: u64::MAX - 1,
                end_index: u64::MAX,
                entry_count: 1,
                chain_head_hash: "sha256:max_values_head".to_string(),
                commitment_hash: "sha256:max_values_commit".to_string(),
                created_at_millis: u64::MAX,
                trace_id: "trace-max-values".to_string(),
            },
        ),
    ];

    for (test_name, checkpoint) in checkpoint_test_cases {
        let checkpoint_json =
            serde_json::to_value(&checkpoint).expect("Should serialize checkpoint");

        golden::assert_scrubbed_json_golden(
            &format!("vef_receipt_envelope/checkpoint_boundaries/{}", test_name),
            &checkpoint_json,
        );
    }
}

#[test]
fn test_receipt_chain_config_variations() {
    // Test ReceiptChainConfig variations
    let config_test_cases = vec![
        ("default_config", ReceiptChainConfig::default()),
        (
            "frequent_checkpoints",
            ReceiptChainConfig {
                checkpoint_every_entries: 10,
                checkpoint_every_millis: 1000,
            },
        ),
        (
            "rare_checkpoints",
            ReceiptChainConfig {
                checkpoint_every_entries: 10000,
                checkpoint_every_millis: 3600000, // 1 hour
            },
        ),
        (
            "entry_only_checkpoints",
            ReceiptChainConfig {
                checkpoint_every_entries: 100,
                checkpoint_every_millis: 0, // Disabled
            },
        ),
        (
            "time_only_checkpoints",
            ReceiptChainConfig {
                checkpoint_every_entries: 0,    // Disabled
                checkpoint_every_millis: 60000, // 1 minute
            },
        ),
        (
            "disabled_checkpoints",
            ReceiptChainConfig {
                checkpoint_every_entries: 0,
                checkpoint_every_millis: 0,
            },
        ),
    ];

    for (test_name, config) in config_test_cases {
        let config_json = serde_json::to_value(&config).expect("Should serialize config");

        golden::assert_scrubbed_json_golden(
            &format!("vef_receipt_envelope/chain_config/{}", test_name),
            &config_json,
        );
    }
}

#[test]
fn test_chain_error_patterns() {
    // Test ChainError patterns for fail-closed semantics. The `tamper` /
    // `checkpoint` / `sequence` / `internal` constructors are private to the
    // receipt_chain module (internal fail-closed helpers), so we build the
    // public `ChainError` struct directly from the public `error_codes` /
    // `event_codes` constants — the exact pairing prod uses — to keep this
    // golden faithful without widening the prod API surface.
    let error_test_cases = vec![
        (
            "tamper_error",
            ChainError {
                code: error_codes::ERR_VEF_CHAIN_TAMPER.to_string(),
                event_code: event_codes::VEF_CHAIN_ERR_001_TAMPER.to_string(),
                message: "Hash mismatch detected in chain entry 42".to_string(),
            },
        ),
        (
            "checkpoint_error",
            ChainError {
                code: error_codes::ERR_VEF_CHAIN_CHECKPOINT.to_string(),
                event_code: event_codes::VEF_CHAIN_ERR_002_CHECKPOINT.to_string(),
                message: "Invalid checkpoint commitment hash".to_string(),
            },
        ),
        (
            "sequence_error",
            ChainError {
                code: error_codes::ERR_VEF_CHAIN_SEQUENCE.to_string(),
                event_code: event_codes::VEF_CHAIN_ERR_003_SEQUENCE.to_string(),
                message: "Gap in chain sequence: expected index 10, got 12".to_string(),
            },
        ),
        (
            "internal_error",
            ChainError {
                code: error_codes::ERR_VEF_CHAIN_INTERNAL.to_string(),
                event_code: event_codes::VEF_CHAIN_ERR_004_INTERNAL.to_string(),
                message: "Serialization failure during hash computation".to_string(),
            },
        ),
    ];

    for (test_name, error) in error_test_cases {
        let error_json = serde_json::to_value(&error).expect("Should serialize error");

        golden::assert_scrubbed_json_golden(
            &format!("vef_receipt_envelope/chain_errors/{}", test_name),
            &error_json,
        );
    }
}

#[test]
fn test_schema_version_consistency() {
    // Test that schema version is consistently applied
    let receipt_with_schema = ExecutionReceipt {
        schema_version: RECEIPT_CHAIN_SCHEMA_VERSION.to_string(),
        action_type: ExecutionActionType::ArtifactPromotion,
        capability_context: BTreeMap::new(),
        actor_identity: "schema-test-actor".to_string(),
        artifact_identity: "schema-test-artifact".to_string(),
        policy_snapshot_hash: "sha256:schema123".to_string(),
        timestamp_millis: 1234567890000,
        sequence_number: 1,
        witness_references: vec![],
        trace_id: "trace-schema".to_string(),
    };

    let schema_test = json!({
        "schema_version": RECEIPT_CHAIN_SCHEMA_VERSION,
        "receipt": serde_json::to_value(&receipt_with_schema).unwrap(),
        "genesis_prev_hash": GENESIS_PREV_HASH,
        "schema_length": RECEIPT_CHAIN_SCHEMA_VERSION.len(),
        "schema_format": "vef-receipt-chain-v*",
    });

    golden::assert_scrubbed_json_golden("vef_receipt_envelope/schema_consistency", &schema_test);
}

// NOTE (bd-08com): the former `test_verification_context_variations` golden was
// removed here. Its subject type `VerificationContext { domain, constraints }`
// was deleted from `connector::vef_execution_receipt` and has no successor type,
// so there is nothing left to snapshot. If a replacement verification-context
// surface is later introduced, add fresh golden coverage under a new bead rather
// than resurrecting this one against a type that no longer exists.
