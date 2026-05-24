#![no_main]

//! Comprehensive fuzz harness for
//! `frankenengine_node::control_plane::fork_detection::DivergenceDetector::compare`
//! at `crates/franken-node/src/control_plane/fork_detection.rs:358`.
//!
//! Background: The `compare` method implements complex state validation logic
//! for detecting forks, rollbacks, gaps, and convergence across distributed
//! control-plane replicas. It handles multiple comparison scenarios with string
//! field validations but currently has ZERO fuzz coverage.
//!
//! The method classifies state vector pairs into:
//! - CONVERGED: same epoch + same state_hash + same parent_hash
//! - FORKED: same epoch + different state_hash
//! - GAP_DETECTED: epoch difference > 1
//! - ROLLBACK_DETECTED: broken parent hash chain
//!
//! A regression in the epoch comparison, hash validation, or state machine
//! logic could let an attacker mask a rollback as convergence or cause
//! false positive fork detection under normal operation.
//!
//! Existing fuzz coverage: **ZERO** (only compute_state_hash is covered).
//!
//! Eight invariants tested per call:
//!
//!   (A) **INV-FDC-PANIC-FREE** — arbitrary StateVectors MUST NOT
//!       panic the compare method regardless of string content.
//!
//!   (B) **INV-FDC-DETERMINISTIC** — same StateVector pair compared
//!       multiple times produces identical DetectionResult.
//!
//!   (C) **INV-FDC-CONVERGENCE-SYMMETRY** — if compare(A,B) returns
//!       Converged, then compare(B,A) MUST also return Converged.
//!
//!   (D) **INV-FDC-FORK-SYMMETRY** — if compare(A,B) returns Forked,
//!       then compare(B,A) MUST also return Forked.
//!
//!   (E) **INV-FDC-IDENTICAL-VECTORS** — compare(A,A) with identical
//!       StateVectors MUST return Converged (never Forked).
//!
//!   (F) **INV-FDC-EPOCH-GAP-BOUNDARY** — vectors with epoch difference
//!       exactly 1 MUST NOT return GapDetected.
//!
//!   (G) **INV-FDC-ROLLBACK-PARENT-CHAIN** — when epoch_newer = epoch_older + 1
//!       and newer.parent_state_hash != older.state_hash, MUST return
//!       RollbackDetected.
//!
//!   (H) **INV-FDC-HALT-ON-CRITICAL** — Forked and RollbackDetected
//!       results MUST set detector.is_halted() to true.

use arbitrary::Arbitrary;
use frankenengine_node::control_plane::fork_detection::{
    DetectionResult, DivergenceDetector, StateVector,
};
use libfuzzer_sys::fuzz_target;

const MAX_STRING_LEN: usize = 2048;
const MAX_NODE_ID_LEN: usize = 256;

#[derive(Debug, Arbitrary)]
struct ForkDetectionCompareFuzzCase {
    local_state: StateVectorFuzzInput,
    remote_state: StateVectorFuzzInput,
    // Additional test scenarios
    scenario: FuzzScenario,
    string_poison: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
struct StateVectorFuzzInput {
    epoch: u64,
    marker_id_raw: Vec<u8>,
    state_hash_raw: Vec<u8>,
    parent_state_hash_raw: Vec<u8>,
    timestamp: u64,
    node_id_raw: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzScenario {
    /// Test arbitrary state vectors
    Arbitrary,
    /// Force identical epochs for fork testing
    SameEpoch,
    /// Force adjacent epochs (gap boundary)
    AdjacentEpochs,
    /// Force large epoch gap
    LargeEpochGap,
    /// Force identical state vectors
    Identical,
    /// Force potential rollback scenario
    PotentialRollback,
}

impl StateVectorFuzzInput {
    fn to_state_vector(&self, poison: &[u8]) -> StateVector {
        StateVector {
            epoch: self.epoch,
            marker_id: bounded_string_with_poison(&self.marker_id_raw, poison, MAX_STRING_LEN),
            state_hash: bounded_hex_string(&self.state_hash_raw, MAX_STRING_LEN),
            parent_state_hash: bounded_hex_string(&self.parent_state_hash_raw, MAX_STRING_LEN),
            timestamp: self.timestamp,
            node_id: bounded_string_with_poison(&self.node_id_raw, &[], MAX_NODE_ID_LEN),
        }
    }
}

fuzz_target!(|case: ForkDetectionCompareFuzzCase| {
    let mut local = case.local_state.to_state_vector(&case.string_poison);
    let mut remote = case.remote_state.to_state_vector(&case.string_poison);

    // Apply scenario transformations to create specific test conditions
    apply_scenario_transforms(&mut local, &mut remote, case.scenario);

    // Create fresh detector instances for each test to ensure clean state
    let mut detector = DivergenceDetector::new();
    let mut detector2 = DivergenceDetector::new();

    // ── (A) Panic-free ─────────────────────────────────────────────────
    let result = std::panic::catch_unwind(|| {
        detector.compare(&local, &remote)
    });
    assert!(
        result.is_ok(),
        "INV-FDC-PANIC-FREE violated: compare panicked on arbitrary StateVectors"
    );

    let (detection_result, proof) = result.unwrap();

    // ── (B) Deterministic ──────────────────────────────────────────────
    let (second_result, second_proof) = detector2.compare(&local, &remote);
    assert_eq!(
        detection_result, second_result,
        "INV-FDC-DETERMINISTIC violated: same StateVectors produced different results"
    );

    // Proof consistency (both present or both absent)
    assert_eq!(
        proof.is_some(), second_proof.is_some(),
        "INV-FDC-DETERMINISTIC violated: proof presence inconsistent"
    );

    // ── (C) Convergence symmetry ───────────────────────────────────────
    if detection_result == DetectionResult::Converged {
        let mut detector_rev = DivergenceDetector::new();
        let (reverse_result, _) = detector_rev.compare(&remote, &local);
        assert_eq!(
            reverse_result,
            DetectionResult::Converged,
            "INV-FDC-CONVERGENCE-SYMMETRY violated: compare(A,B)=Converged but compare(B,A)={:?}",
            reverse_result
        );
    }

    // ── (D) Fork symmetry ──────────────────────────────────────────────
    if detection_result == DetectionResult::Forked {
        let mut detector_rev = DivergenceDetector::new();
        let (reverse_result, _) = detector_rev.compare(&remote, &local);
        assert_eq!(
            reverse_result,
            DetectionResult::Forked,
            "INV-FDC-FORK-SYMMETRY violated: compare(A,B)=Forked but compare(B,A)={:?}",
            reverse_result
        );
    }

    // ── (E) Identical vectors ──────────────────────────────────────────
    let mut detector_self = DivergenceDetector::new();
    let (self_result, _) = detector_self.compare(&local, &local);
    assert_eq!(
        self_result,
        DetectionResult::Converged,
        "INV-FDC-IDENTICAL-VECTORS violated: compare(A,A) returned {:?} instead of Converged",
        self_result
    );

    // ── (F) Epoch gap boundary ─────────────────────────────────────────
    let epoch_diff = local.epoch.abs_diff(remote.epoch);
    if epoch_diff <= 1 {
        assert_ne!(
            detection_result,
            DetectionResult::GapDetected,
            "INV-FDC-EPOCH-GAP-BOUNDARY violated: GapDetected with epoch diff {} <= 1",
            epoch_diff
        );
    }

    // ── (G) Rollback parent chain ──────────────────────────────────────
    // When epochs are adjacent and parent chain is broken, must detect rollback
    if epoch_diff == 1 {
        let (older, newer) = if local.epoch < remote.epoch {
            (&local, &remote)
        } else {
            (&remote, &local)
        };

        // If parent chain is broken, must detect rollback
        if newer.parent_state_hash != older.state_hash {
            assert_eq!(
                detection_result,
                DetectionResult::RollbackDetected,
                "INV-FDC-ROLLBACK-PARENT-CHAIN violated: broken parent chain not detected \
                 (older.state_hash={:?}, newer.parent_state_hash={:?})",
                older.state_hash,
                newer.parent_state_hash
            );
        }
    }

    // ── (H) Halt on critical ───────────────────────────────────────────
    match detection_result {
        DetectionResult::Forked | DetectionResult::RollbackDetected => {
            assert!(
                detector.is_halted(),
                "INV-FDC-HALT-ON-CRITICAL violated: detector not halted after {:?}",
                detection_result
            );

            // Critical results must include a proof
            assert!(
                proof.is_some(),
                "INV-FDC-HALT-ON-CRITICAL violated: no proof for critical result {:?}",
                detection_result
            );
        }
        DetectionResult::Converged | DetectionResult::GapDetected => {
            // Non-critical results should not halt for gaps, but convergence
            // after a previous halt should not reset halt state (only operator can)
            // This is implementation-dependent, so we don't assert halt state here
        }
    }

    // Additional validation: result classification logic
    if local.epoch == remote.epoch {
        match detection_result {
            DetectionResult::GapDetected => {
                panic!(
                    "Logic error: same epoch ({}) returned GapDetected",
                    local.epoch
                );
            }
            DetectionResult::Converged => {
                // Must have same state_hash for convergence
                assert_eq!(
                    local.state_hash, remote.state_hash,
                    "Converged result with different state hashes: {:?} vs {:?}",
                    local.state_hash, remote.state_hash
                );
            }
            DetectionResult::Forked => {
                // Must have different state_hash for fork
                assert_ne!(
                    local.state_hash, remote.state_hash,
                    "Forked result with identical state hashes: {:?}",
                    local.state_hash
                );
            }
            DetectionResult::RollbackDetected => {
                // Same epoch rollback requires same state_hash but different parent_hash
                assert_eq!(
                    local.state_hash, remote.state_hash,
                    "Same-epoch rollback with different state hashes"
                );
                assert_ne!(
                    local.parent_state_hash, remote.parent_state_hash,
                    "Same-epoch rollback with identical parent hashes"
                );
            }
        }
    } else if epoch_diff > 1 {
        assert_eq!(
            detection_result,
            DetectionResult::GapDetected,
            "Large epoch gap ({}) did not return GapDetected: {:?}",
            epoch_diff,
            detection_result
        );
    }
});

fn apply_scenario_transforms(local: &mut StateVector, remote: &mut StateVector, scenario: FuzzScenario) {
    match scenario {
        FuzzScenario::Arbitrary => {
            // No transforms - use as-is
        }
        FuzzScenario::SameEpoch => {
            remote.epoch = local.epoch;
        }
        FuzzScenario::AdjacentEpochs => {
            remote.epoch = local.epoch.saturating_add(1);
        }
        FuzzScenario::LargeEpochGap => {
            remote.epoch = local.epoch.saturating_add(10);
        }
        FuzzScenario::Identical => {
            remote.epoch = local.epoch;
            remote.marker_id = local.marker_id.clone();
            remote.state_hash = local.state_hash.clone();
            remote.parent_state_hash = local.parent_state_hash.clone();
            remote.timestamp = local.timestamp;
            remote.node_id = local.node_id.clone();
        }
        FuzzScenario::PotentialRollback => {
            // Set up adjacent epochs with different parent hashes
            remote.epoch = local.epoch.saturating_add(1);
            remote.parent_state_hash = format!("{}X", local.state_hash); // Ensure different
        }
    }
}

fn bounded_string_with_poison(input: &[u8], poison: &[u8], max_len: usize) -> String {
    let mut combined = Vec::new();

    // Add original input
    for &byte in input.iter().take(max_len / 2) {
        if let Ok(s) = std::str::from_utf8(&[byte]) {
            combined.extend_from_slice(s.as_bytes());
        }
    }

    // Add poison for control character / injection testing
    for &byte in poison.iter().take(max_len / 4) {
        if combined.len() >= max_len {
            break;
        }
        combined.push(byte);
    }

    // Ensure we have a valid UTF-8 string and truncate to max_len
    String::from_utf8_lossy(&combined[..combined.len().min(max_len)]).into_owned()
}

fn bounded_hex_string(input: &[u8], max_len: usize) -> String {
    // Generate hex-like strings for state_hash and parent_state_hash fields
    let hex_chars = b"0123456789abcdef";
    let mut result = String::new();

    for (i, &byte) in input.iter().enumerate() {
        if result.len() >= max_len {
            break;
        }
        let char_idx = (byte as usize) % hex_chars.len();
        result.push(hex_chars[char_idx] as char);

        // Occasionally inject non-hex characters for validation testing
        if i % 17 == 0 && result.len() < max_len {
            result.push('G'); // Invalid hex character
        }
    }

    // Ensure minimum length for hash-like appearance
    while result.len() < 8 && result.len() < max_len {
        result.push('0');
    }

    result
}