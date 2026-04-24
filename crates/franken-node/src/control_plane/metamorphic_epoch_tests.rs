//! Metamorphic tests for epoch validity under permutations
//!
//! Tests that epoch system maintains monotonic progression and signing
//! invariants regardless of concurrent operation ordering.

use super::control_epoch::{ControlEpoch, EpochStore, invalid_artifact_id_reason};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
enum EpochOperation {
    Advance { reason: String },
    ReadCurrent,
    ValidateArtifact { artifact_id: String },
}

/// Generate test epoch operations
fn generate_epoch_operations() -> Vec<EpochOperation> {
    vec![
        EpochOperation::Advance {
            reason: "test_advance_1".to_string(),
        },
        EpochOperation::ReadCurrent,
        EpochOperation::Advance {
            reason: "test_advance_2".to_string(),
        },
        EpochOperation::ValidateArtifact {
            artifact_id: "valid/path/file.txt".to_string(),
        },
        EpochOperation::Advance {
            reason: "test_advance_3".to_string(),
        },
        EpochOperation::ValidateArtifact {
            artifact_id: "../invalid/path".to_string(),
        },
        EpochOperation::ReadCurrent,
    ]
}

/// MR1: Epoch Monotonic Ordering (Equivalence)
/// Epoch advances should maintain monotonic progression regardless of operation ordering
#[cfg(test)]
mod mr_epoch_monotonic_ordering {
    use super::{EpochStore, is_gap_free, is_monotonic};

    #[test]
    fn monotonic_progression_under_reorder() {
        // Test advance operations in original order
        let mut store1 = EpochStore::recover(0);
        let advances = vec![
            "reason1".to_string(),
            "reason2".to_string(),
            "reason3".to_string(),
        ];
        let mut original_epochs = vec![store1.epoch_read()];

        for reason in &advances {
            match store1.epoch_advance(reason, "sig") {
                Ok(_) => original_epochs.push(store1.epoch_read()),
                Err(_) => break,
            }
        }

        // Test same advances in reverse order
        let mut store2 = EpochStore::recover(0);
        let mut reversed_advances = advances.clone();
        reversed_advances.reverse();
        let mut reordered_epochs = vec![store2.epoch_read()];

        for reason in &reversed_advances {
            match store2.epoch_advance(reason, "sig") {
                Ok(_) => reordered_epochs.push(store2.epoch_read()),
                Err(_) => break,
            }
        }

        // INV-EPOCH-MONOTONIC: Both sequences should be strictly monotonic
        assert!(
            is_monotonic(&original_epochs),
            "Original epoch sequence not monotonic: {:?}",
            original_epochs
        );
        assert!(
            is_monotonic(&reordered_epochs),
            "Reordered epoch sequence not monotonic: {:?}",
            reordered_epochs
        );

        // INV-EPOCH-NO-GAP: Both should advance by exactly 1 per operation
        assert!(
            is_gap_free(&original_epochs),
            "Original sequence has gaps: {:?}",
            original_epochs
        );
        assert!(
            is_gap_free(&reordered_epochs),
            "Reordered sequence has gaps: {:?}",
            reordered_epochs
        );

        // Final epochs should be the same (same number of advances)
        assert_eq!(
            original_epochs.last(),
            reordered_epochs.last(),
            "Final epochs differ: original={:?}, reordered={:?}",
            original_epochs.last(),
            reordered_epochs.last()
        );
    }
}

/// MR2: Artifact Validation Consistency (Equivalence)
/// Artifact validation should be deterministic regardless of operation ordering
#[cfg(test)]
mod mr_artifact_validation_consistency {
    use super::{BTreeMap, invalid_artifact_id_reason};

    #[test]
    fn artifact_decisions_consistent_under_reorder() {
        let artifacts = vec![
            "valid/path/file.txt",
            "../invalid/path",   // Should be rejected
            "/absolute/invalid", // Should be rejected
            "another/valid/file.dat",
        ];

        // Test validation in original order
        let mut original_results = BTreeMap::new();
        for artifact in &artifacts {
            let result = invalid_artifact_id_reason(artifact);
            original_results.insert(artifact.to_string(), result);
        }

        // Test validation in reverse order
        let mut reversed_artifacts = artifacts.clone();
        reversed_artifacts.reverse();
        let mut reordered_results = BTreeMap::new();
        for artifact in &reversed_artifacts {
            let result = invalid_artifact_id_reason(artifact);
            reordered_results.insert(artifact.to_string(), result);
        }

        // Validation results should be identical regardless of ordering
        for (artifact_id, original_result) in &original_results {
            if let Some(reordered_result) = reordered_results.get(artifact_id) {
                assert_eq!(
                    original_result, reordered_result,
                    "Artifact {} validation changed: {:?} -> {:?}",
                    artifact_id, original_result, reordered_result
                );
            }
        }
    }
}

// Helper functions for testing
fn is_monotonic(epochs: &[ControlEpoch]) -> bool {
    epochs.windows(2).all(|w| w[0] < w[1])
}

fn is_gap_free(epochs: &[ControlEpoch]) -> bool {
    epochs.windows(2).all(|w| w[1].value() == w[0].value() + 1)
}

#[cfg(test)]
mod tests {
    use super::{ControlEpoch, is_gap_free, is_monotonic};

    #[test]
    fn test_monotonic_detection() {
        let epochs = vec![
            ControlEpoch::new(0),
            ControlEpoch::new(1),
            ControlEpoch::new(2),
            ControlEpoch::new(3),
        ];
        assert!(is_monotonic(&epochs));

        let non_monotonic = vec![
            ControlEpoch::new(0),
            ControlEpoch::new(2),
            ControlEpoch::new(1),
        ];
        assert!(!is_monotonic(&non_monotonic));
    }

    #[test]
    fn test_gap_free_detection() {
        let gap_free = vec![
            ControlEpoch::new(0),
            ControlEpoch::new(1),
            ControlEpoch::new(2),
        ];
        assert!(is_gap_free(&gap_free));

        let with_gap = vec![
            ControlEpoch::new(0),
            ControlEpoch::new(1),
            ControlEpoch::new(3), // Gap at 2
        ];
        assert!(!is_gap_free(&with_gap));
    }
}
