//! Metamorphic tests for the security replay window.
//!
//! The replay window is exercised through `RevocationFreshnessGate` nonce
//! consumption: adding duplicate nonce observations must be idempotent with
//! respect to final window state, and capacity overflow must retain the most
//! recent suffix without growing beyond the configured maximum.

use frankenengine_node::capacity_defaults::aliases::MAX_CONSUMED_NONCES;
use frankenengine_node::security::revocation_freshness_gate::{
    FreshnessError, FreshnessProof, RevocationFreshnessGate, SafetyTier,
};

const CURRENT_EPOCH: u64 = 1_000;
const ACTION_ID: &str = "telemetry_config";

fn test_sig(proof: &FreshnessProof) -> String {
    format!("sig-{}-{}", proof.nonce, proof.epoch)
}

fn gate() -> RevocationFreshnessGate {
    RevocationFreshnessGate::new(
        Box::new(test_sig),
        vec![(ACTION_ID.to_string(), SafetyTier::Advisory)],
    )
}

fn proof_for(nonce: &str) -> FreshnessProof {
    let mut proof = FreshnessProof {
        timestamp: 1_700_000_000,
        credentials_checked: vec![
            "credential-alpha".to_string(),
            "credential-beta".to_string(),
        ],
        nonce: nonce.to_string(),
        signature: String::new(),
        tier: SafetyTier::Advisory,
        epoch: CURRENT_EPOCH,
    };
    proof.signature = test_sig(&proof);
    proof
}

fn insert_nonce(gate: &mut RevocationFreshnessGate, nonce: &str, trace_id: &str) {
    let proof = proof_for(nonce);
    let result = gate.check(&proof, CURRENT_EPOCH, true, false, ACTION_ID, trace_id);
    assert!(
        result.as_ref().is_ok_and(|decision| decision.allowed),
        "fresh nonce {nonce} should be accepted, got {result:?}"
    );
}

#[test]
fn duplicate_augmented_replay_stream_preserves_window_state_and_fifo_capacity() {
    let seed_nonces: Vec<String> = (0..32)
        .map(|idx| format!("rwmm-idempotent-{idx:03}"))
        .collect();

    let mut unique_only = gate();
    let mut duplicate_augmented = gate();

    for nonce in &seed_nonces {
        insert_nonce(&mut unique_only, nonce, "trace-rwmm-unique");

        insert_nonce(
            &mut duplicate_augmented,
            nonce,
            "trace-rwmm-augmented-first",
        );
        let count_after_first_insert = duplicate_augmented.consumed_nonce_count();
        let duplicate = proof_for(nonce);
        let duplicate_result = duplicate_augmented.check(
            &duplicate,
            CURRENT_EPOCH,
            true,
            false,
            ACTION_ID,
            "trace-rwmm-augmented-duplicate",
        );

        assert!(
            matches!(
                duplicate_result,
                Err(FreshnessError::ReplayDetected { nonce: replayed_nonce })
                    if replayed_nonce == *nonce
            ),
            "second insertion of {nonce} must be a typed replay rejection"
        );
        assert_eq!(
            duplicate_augmented.consumed_nonce_count(),
            count_after_first_insert,
            "duplicate insertion must not grow the replay window"
        );
    }

    assert_eq!(
        duplicate_augmented.consumed_nonce_count(),
        unique_only.consumed_nonce_count(),
        "duplicate-augmented stream should converge to unique-only window size"
    );
    for nonce in &seed_nonces {
        assert_eq!(
            duplicate_augmented.is_nonce_consumed(nonce),
            unique_only.is_nonce_consumed(nonce),
            "duplicate augmentation changed membership for nonce {nonce}"
        );
    }

    let overflow = 17_usize;
    let total_insertions = MAX_CONSUMED_NONCES.saturating_add(overflow);
    let mut saturated = gate();

    for idx in 0..total_insertions {
        let nonce = format!("rwmm-capacity-{idx:06}");
        let trace_id = format!("trace-rwmm-capacity-{idx:06}");
        insert_nonce(&mut saturated, &nonce, &trace_id);
        assert!(
            saturated.consumed_nonce_count() <= MAX_CONSUMED_NONCES,
            "replay window grew beyond MAX_CONSUMED_NONCES after insertion {idx}"
        );
    }

    assert_eq!(
        saturated.consumed_nonce_count(),
        MAX_CONSUMED_NONCES,
        "saturated replay window should stop at exactly MAX_CONSUMED_NONCES"
    );

    for idx in 0..overflow {
        let evicted = format!("rwmm-capacity-{idx:06}");
        assert!(
            !saturated.is_nonce_consumed(&evicted),
            "FIFO replay window should evict oldest nonce {evicted}"
        );
    }

    for idx in overflow..total_insertions {
        let retained = format!("rwmm-capacity-{idx:06}");
        assert!(
            saturated.is_nonce_consumed(&retained),
            "FIFO replay window should retain recent nonce {retained}"
        );
    }
}
