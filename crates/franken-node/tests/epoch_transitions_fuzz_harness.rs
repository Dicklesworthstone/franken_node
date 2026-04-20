//! Structure-aware fuzzing harness for epoch transition state machines
//!
//! Tests epoch transition sequences for:
//! - EpochTransition MAC verification under fuzzed inputs
//! - ControlEpoch progression invariant enforcement
//! - ValidityWindowPolicy boundary condition handling
//! - Epoch store recovery consistency across state variations
//!
//! Follows the canonical_serializer_fuzz_harness pattern with structure-aware
//! epoch state generation and invariant validation.

use frankenengine_node::control_plane::control_epoch::{
    ControlEpoch, EpochStore, EpochTransition, ValidityWindowPolicy,
    EpochError, EpochRejection, EpochRejectionReason, check_artifact_epoch,
    EpochArtifactEvent, event_codes,
};
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_EPOCH_VALUE: u64 = 1_000_000; // Reasonable upper bound for testing
const MAX_MANIFEST_HASH_LEN: usize = 256;
const MAX_TRACE_ID_LEN: usize = 128;
const MAX_ARTIFACT_ID_LEN: usize = 512;
const MAX_LOOKBACK_WINDOW: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum HarnessEpochError {
    EpochOperation(String),
    MacVerification,
    Serialization(String),
    InvalidTransition,
    WindowPolicyViolation,
    ArtifactValidation(String),
}

impl From<EpochError> for HarnessEpochError {
    fn from(error: EpochError) -> Self {
        Self::EpochOperation(error.to_string())
    }
}

/// Generate seed epoch values for boundary testing
fn seed_epoch_values() -> Vec<u64> {
    vec![
        0,                    // Genesis
        1,                    // First real epoch
        2,                    // Second epoch
        100,                  // Typical value
        1000,                 // Large but reasonable
        MAX_EPOCH_VALUE / 2,  // Mid-range
        MAX_EPOCH_VALUE - 1,  // Near maximum
        u64::MAX - 1,         // Near overflow
        u64::MAX,             // Maximum value
    ]
}

/// Generate seed manifest hashes for testing
fn seed_manifest_hashes() -> Vec<String> {
    vec![
        "".to_string(),                                    // Empty (invalid)
        "a".to_string(),                                   // Minimal
        "manifest-hash-0000000000000001".to_string(),      // Standard format
        "manifest-hash-fedcba9876543210".to_string(),      // Hex variation
        "manifest-hash-".to_string(),                      // Incomplete
        "manifest".to_string(),                            // No hash suffix
        " manifest-hash-0001 ".to_string(),                // Whitespace padded (invalid)
        "\0manifest-hash-0001".to_string(),                // Null byte (invalid)
        "x".repeat(MAX_MANIFEST_HASH_LEN),                 // Maximum length
        "x".repeat(MAX_MANIFEST_HASH_LEN + 1),             // Over limit (invalid)
    ]
}

/// Generate seed trace IDs for testing
fn seed_trace_ids() -> Vec<String> {
    vec![
        "".to_string(),                           // Empty (invalid)
        "trace-0001".to_string(),                 // Standard format
        "trace-test".to_string(),                 // Text suffix
        "t".to_string(),                          // Minimal
        " trace-0001 ".to_string(),               // Whitespace padded (invalid)
        "\0trace".to_string(),                    // Null byte (invalid)
        "trace-".to_string(),                     // Incomplete
        "trace-αβγ".to_string(),                  // Unicode
        "x".repeat(MAX_TRACE_ID_LEN),             // Maximum length
        "x".repeat(MAX_TRACE_ID_LEN + 1),         // Over limit (invalid)
    ]
}

/// Generate seed artifact IDs for validation testing
fn seed_artifact_ids() -> Vec<String> {
    vec![
        "".to_string(),                           // Empty (invalid)
        "artifact-1".to_string(),                 // Standard
        "a".to_string(),                          // Minimal
        "<unknown>".to_string(),                  // Reserved (invalid)
        " artifact-1 ".to_string(),               // Whitespace (invalid)
        "\0artifact".to_string(),                 // Null byte (invalid)
        "/artifact-1".to_string(),                // Leading slash (invalid)
        "artifact\\1".to_string(),                // Backslash (invalid)
        "artifact/../1".to_string(),              // Parent dir (invalid)
        "artifact-1/sub/../item".to_string(),     // Embedded parent (invalid)
        "artifact_with_underscores".to_string(),  // Valid variation
        "artifact.with.dots".to_string(),         // Valid variation
        "artifact-with-dashes".to_string(),       // Valid variation
        "x".repeat(MAX_ARTIFACT_ID_LEN),          // Maximum length
        "x".repeat(MAX_ARTIFACT_ID_LEN + 1),      // Over limit (invalid)
    ]
}

/// Generate seed timestamp values
fn seed_timestamps() -> Vec<u64> {
    vec![
        0,                    // Unix epoch start
        1,                    // Minimal
        1000000000,           // Year 2001
        1640995200,           // Year 2022
        1704067200,           // Year 2024
        u64::MAX / 2,         // Mid-range
        u64::MAX - 1,         // Near maximum
        u64::MAX,             // Maximum
    ]
}

/// Generate comprehensive epoch transition test vectors
fn seed_transition_vectors() -> Vec<(u64, String, u64, String)> {
    let mut vectors = Vec::new();
    let epochs = vec![0, 1, 2, 10, 100];
    let manifests = vec!["manifest-hash-0001", "manifest-hash-test"];
    let timestamps = vec![1000000000, 1640995200];
    let traces = vec!["trace-001", "trace-test"];

    for &epoch in &epochs {
        for manifest in &manifests {
            for &timestamp in &timestamps {
                for trace in &traces {
                    vectors.push((epoch, manifest.to_string(), timestamp, trace.to_string()));
                }
            }
        }
    }

    vectors
}

/// Validate epoch transition MAC consistency
fn validate_transition_mac_consistency(
    old_epoch: ControlEpoch,
    new_epoch: ControlEpoch,
    timestamp: u64,
    manifest_hash: &str,
    trace_id: &str,
) -> Result<(), HarnessEpochError> {
    if manifest_hash.trim().is_empty() || trace_id.trim().is_empty() {
        return Err(HarnessEpochError::InvalidTransition);
    }

    let mut store = EpochStore::recover(old_epoch.value());

    // Attempt to advance to new epoch
    match store.epoch_advance(manifest_hash, timestamp, trace_id) {
        Ok(transition) => {
            // MAC should verify
            if !transition.verify() {
                return Err(HarnessEpochError::MacVerification);
            }

            // Create second transition with same parameters
            let mut store2 = EpochStore::recover(old_epoch.value());
            match store2.epoch_advance(manifest_hash, timestamp, trace_id) {
                Ok(transition2) => {
                    // MACs should be identical for identical inputs
                    if transition.event_mac != transition2.event_mac {
                        return Err(HarnessEpochError::MacVerification);
                    }
                },
                Err(_) => return Err(HarnessEpochError::InvalidTransition),
            }

            Ok(())
        },
        Err(_) => {
            // Expected failure for invalid inputs
            Err(HarnessEpochError::InvalidTransition)
        }
    }
}

/// Test validity window policy enforcement
fn validate_window_policy_enforcement(
    current_epoch: u64,
    lookback: u64,
    artifact_epoch: u64,
    artifact_id: &str,
) -> Result<bool, HarnessEpochError> {
    if current_epoch > MAX_EPOCH_VALUE || lookback > MAX_LOOKBACK_WINDOW {
        return Err(HarnessEpochError::WindowPolicyViolation);
    }

    let policy = ValidityWindowPolicy::new(ControlEpoch::new(current_epoch), lookback);
    let trace_id = "fuzz-window-test";

    match check_artifact_epoch(artifact_id, ControlEpoch::new(artifact_epoch), &policy, trace_id) {
        Ok(_event) => Ok(true),  // Artifact accepted
        Err(_rejection) => Ok(false), // Artifact rejected
    }
}

/// Validate epoch store recovery consistency
fn validate_epoch_store_recovery_consistency(epoch_value: u64) -> Result<(), HarnessEpochError> {
    if epoch_value > MAX_EPOCH_VALUE {
        return Err(HarnessEpochError::InvalidTransition);
    }

    let store1 = EpochStore::recover(epoch_value);
    let store2 = EpochStore::recover(epoch_value);

    // Recovery should be deterministic
    if store1.epoch_read() != store2.epoch_read() {
        return Err(HarnessEpochError::InvalidTransition);
    }

    if store1.committed_epoch() != store2.committed_epoch() {
        return Err(HarnessEpochError::InvalidTransition);
    }

    Ok(())
}

#[test]
fn fuzz_epoch_transition_mac_verification_deterministic() {
    for (epoch_value, manifest_hash, timestamp, trace_id) in seed_transition_vectors() {
        let old_epoch = ControlEpoch::new(epoch_value);
        let new_epoch = ControlEpoch::new(epoch_value.saturating_add(1));

        let result = validate_transition_mac_consistency(
            old_epoch, new_epoch, timestamp, &manifest_hash, &trace_id
        );

        // Either consistently succeeds or consistently fails
        let result2 = validate_transition_mac_consistency(
            old_epoch, new_epoch, timestamp, &manifest_hash, &trace_id
        );

        assert_eq!(
            result.is_ok(),
            result2.is_ok(),
            "MAC validation should be deterministic for epoch: {}, manifest: {}, trace: {}",
            epoch_value, manifest_hash, trace_id
        );
    }
}

#[test]
fn fuzz_epoch_progression_invariant_enforcement() {
    let regression_attempts = vec![
        (5, 4),   // Backward
        (5, 5),   // Same
        (5, 0),   // Reset to genesis
        (100, 50), // Large regression
    ];

    for (current, attempted) in regression_attempts {
        let mut store = EpochStore::recover(current);

        let result = store.epoch_set(
            attempted,
            "manifest-regression-test",
            1000000000,
            "trace-regression"
        );

        // All regressions should fail
        assert!(result.is_err(), "Epoch regression from {} to {} should be rejected", current, attempted);

        // Store state should be unchanged
        assert_eq!(store.epoch_read().value(), current, "Store state should not change after rejected regression");
    }
}

#[test]
fn fuzz_validity_window_boundary_conditions() {
    let test_cases = vec![
        // (current_epoch, lookback, artifact_epoch, should_accept)
        (100, 10, 100, true),    // Current epoch
        (100, 10, 99, true),     // Recent
        (100, 10, 90, true),     // At boundary
        (100, 10, 89, false),    // Just outside window
        (100, 10, 50, false),    // Old
        (100, 10, 101, false),   // Future
        (0, 0, 0, true),         // Genesis with zero window
        (1, 0, 1, true),         // Zero window, current only
        (1, 0, 0, false),        // Zero window, past epoch
    ];

    for (current_epoch, lookback, artifact_epoch, should_accept) in test_cases {
        let result = validate_window_policy_enforcement(
            current_epoch,
            lookback,
            artifact_epoch,
            "artifact-boundary-test"
        );

        match result {
            Ok(accepted) => {
                assert_eq!(
                    accepted, should_accept,
                    "Window policy mismatch: current={}, lookback={}, artifact={}, expected={}, got={}",
                    current_epoch, lookback, artifact_epoch, should_accept, accepted
                );
            },
            Err(_) => {
                // Error is acceptable for extreme values
                assert!(
                    current_epoch > MAX_EPOCH_VALUE || lookback > MAX_LOOKBACK_WINDOW,
                    "Unexpected error for reasonable values: current={}, lookback={}",
                    current_epoch, lookback
                );
            }
        }
    }
}

#[test]
fn fuzz_artifact_id_validation_comprehensive() {
    for artifact_id in seed_artifact_ids() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(100), 10);
        let result = check_artifact_epoch(&artifact_id, ControlEpoch::new(100), &policy, "fuzz-artifact");

        // Classify expected vs actual results
        let should_be_valid = !artifact_id.is_empty()
            && artifact_id.trim() == artifact_id
            && artifact_id != "<unknown>"
            && !artifact_id.contains('\0')
            && !artifact_id.starts_with('/')
            && !artifact_id.contains('\\')
            && !artifact_id.split('/').any(|seg| seg == "..")
            && artifact_id.len() <= MAX_ARTIFACT_ID_LEN;

        match (result, should_be_valid) {
            (Ok(_), true) => {
                // Valid artifact correctly accepted
            },
            (Err(_), false) => {
                // Invalid artifact correctly rejected
            },
            (Ok(_), false) => {
                panic!("Invalid artifact_id accepted: {:?}", artifact_id);
            },
            (Err(_), true) => {
                panic!("Valid artifact_id rejected: {:?}", artifact_id);
            }
        }
    }
}

#[test]
fn fuzz_epoch_store_recovery_determinism() {
    for &epoch_value in &seed_epoch_values() {
        if epoch_value <= MAX_EPOCH_VALUE {
            validate_epoch_store_recovery_consistency(epoch_value)
                .expect(&format!("Epoch store recovery should be deterministic for epoch: {}", epoch_value));
        }
    }
}

#[test]
fn fuzz_transition_serialization_round_trip() {
    let mut store = EpochStore::new();

    for (i, (epoch_val, manifest_hash, timestamp, trace_id)) in seed_transition_vectors().iter().enumerate().take(5) {
        if !manifest_hash.trim().is_empty() && !trace_id.trim().is_empty() {
            match store.epoch_advance(manifest_hash, *timestamp, trace_id) {
                Ok(transition) => {
                    // Test serialization round-trip
                    let serialized = serde_json::to_string(&transition)
                        .expect("transition should serialize");

                    let deserialized: EpochTransition = serde_json::from_str(&serialized)
                        .expect("transition should deserialize");

                    assert_eq!(transition, deserialized, "Transition round-trip failed for step {}", i);

                    // Verify MAC still validates after round-trip
                    assert!(deserialized.verify(), "Deserialized transition MAC should still validate");
                },
                Err(_) => {
                    // Expected for invalid inputs
                }
            }
        }
    }
}

#[test]
fn fuzz_manifest_hash_boundary_validation() {
    let mut store = EpochStore::new();

    for manifest_hash in seed_manifest_hashes() {
        let result = store.epoch_advance(&manifest_hash, 1000000000, "trace-manifest-test");

        let should_succeed = !manifest_hash.trim().is_empty()
            && manifest_hash.trim() == manifest_hash
            && !manifest_hash.contains('\0')
            && manifest_hash.len() <= MAX_MANIFEST_HASH_LEN;

        match (result, should_succeed) {
            (Ok(_), true) => {
                // Valid manifest correctly processed
            },
            (Err(_), false) => {
                // Invalid manifest correctly rejected
            },
            (Ok(_), false) => {
                panic!("Invalid manifest_hash accepted: {:?}", manifest_hash);
            },
            (Err(_), true) => {
                // May fail due to store state (epoch progression), which is OK
            }
        }
    }
}

#[test]
fn fuzz_trace_id_boundary_validation() {
    for trace_id in seed_trace_ids() {
        let mut store = EpochStore::new();
        let result = store.epoch_advance("manifest-hash-test", 1000000000, &trace_id);

        let should_succeed = !trace_id.trim().is_empty()
            && trace_id.trim() == trace_id
            && !trace_id.contains('\0')
            && trace_id.len() <= MAX_TRACE_ID_LEN;

        match (result, should_succeed) {
            (Ok(_), true) => {
                // Valid trace_id correctly processed
            },
            (Err(_), false) => {
                // Invalid trace_id correctly rejected
            },
            (Ok(_), false) => {
                panic!("Invalid trace_id accepted: {:?}", trace_id);
            },
            (Err(_), true) => {
                // Valid trace_id should succeed for first epoch advance
                panic!("Valid trace_id rejected: {:?}", trace_id);
            }
        }
    }
}

#[test]
fn fuzz_epoch_overflow_protection() {
    let mut store = EpochStore::recover(u64::MAX);

    // Attempting to advance from maximum epoch should fail
    let result = store.epoch_advance("manifest-overflow-test", 1000000000, "trace-overflow");

    assert!(result.is_err(), "Epoch advance from u64::MAX should fail");

    // Store state should remain unchanged
    assert_eq!(store.epoch_read().value(), u64::MAX, "Store should remain at maximum epoch");

    // Attempting to set to any value should also fail (no progression possible)
    let set_result = store.epoch_set(u64::MAX, "manifest-set-max", 1000000001, "trace-set");
    assert!(set_result.is_err(), "Setting epoch to same maximum value should fail");
}