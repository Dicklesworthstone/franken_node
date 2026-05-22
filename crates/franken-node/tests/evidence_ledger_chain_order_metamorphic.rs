//! Metamorphic test: hash chain order-sensitivity for the evidence ledger.
//!
//! For distinct entries E1 != E2, appending [E1, E2] vs [E2, E1] MUST produce
//! different chain bindings on the second slot's `prev_entry_hash`. If this
//! property failed, the hash chain would not bind append order — an attacker
//! could reorder evidence without detection.
//!
//! Bead: bd-1p8y3

use frankenengine_node::observability::evidence_ledger::{
    DecisionKind, EvidenceEntry, EvidenceLedger, LedgerCapacity, test_entry,
};
use frankenengine_node::test_strategies;
use proptest::prelude::*;

fn build_ledger() -> EvidenceLedger {
    EvidenceLedger::new(LedgerCapacity::new(64, 64 * 1024))
}

fn mk_entry(decision_id: &str, epoch_id: u64, kind: DecisionKind) -> EvidenceEntry {
    let mut e = test_entry(decision_id, epoch_id);
    e.decision_kind = kind;
    e
}

fn append_all(entries: &[EvidenceEntry]) -> Vec<EvidenceEntry> {
    let mut ledger = build_ledger();
    for entry in entries {
        ledger
            .append(entry.clone())
            .expect("append must succeed for in-budget test entries");
    }
    ledger
        .snapshot()
        .entries
        .into_iter()
        .map(|(_, e)| e)
        .collect()
}

/// MR1 (permutative, order-sensitive): swapping append order MUST change the
/// chain head binding when the two entries are distinct.
#[test]
fn mr_chain_head_changes_under_swap_of_distinct_entries() {
    let e1 = mk_entry("DEC-001", 1, DecisionKind::Admit);
    let e2 = mk_entry("DEC-002", 2, DecisionKind::Deny);

    let forward = append_all(&[e1.clone(), e2.clone()]);
    let reversed = append_all(&[e2.clone(), e1.clone()]);

    // Both ledgers retain two entries.
    assert_eq!(forward.len(), 2);
    assert_eq!(reversed.len(), 2);

    // The first entry in each ledger has empty prev_entry_hash (chain root).
    assert!(
        forward[0].prev_entry_hash.is_empty(),
        "first appended entry must have empty prev_entry_hash, got {:?}",
        forward[0].prev_entry_hash
    );
    assert!(
        reversed[0].prev_entry_hash.is_empty(),
        "first appended entry must have empty prev_entry_hash, got {:?}",
        reversed[0].prev_entry_hash
    );

    // The second-slot prev_entry_hash differs because each binds to a
    // different first-slot entry.
    assert_ne!(
        forward[1].prev_entry_hash, reversed[1].prev_entry_hash,
        "hash chain failed order-sensitivity: swapping append order produced the \
         same prev_entry_hash on the second slot — chain provides no tamper \
         detection across reorder.\n forward[1].prev = {:?}\n reversed[1].prev = {:?}",
        forward[1].prev_entry_hash, reversed[1].prev_entry_hash
    );
}

/// MR2 (inclusive, multiset commutativity): the multiset of (decision_id,
/// epoch_id) pairs is invariant under append-order permutation. The ledger
/// must retain every appended payload regardless of insertion order — only
/// the chain bindings change, never membership.
#[test]
fn mr_membership_is_commutative_under_reorder() {
    let e1 = mk_entry("DEC-A", 10, DecisionKind::Quarantine);
    let e2 = mk_entry("DEC-B", 20, DecisionKind::Release);
    let e3 = mk_entry("DEC-C", 30, DecisionKind::Throttle);

    let forward = append_all(&[e1.clone(), e2.clone(), e3.clone()]);
    let reversed = append_all(&[e3, e2, e1]);

    let mut forward_keys: Vec<(String, u64)> = forward
        .iter()
        .map(|e| (e.decision_id.clone(), e.epoch_id))
        .collect();
    let mut reversed_keys: Vec<(String, u64)> = reversed
        .iter()
        .map(|e| (e.decision_id.clone(), e.epoch_id))
        .collect();
    forward_keys.sort();
    reversed_keys.sort();

    assert_eq!(
        forward_keys, reversed_keys,
        "ledger membership multiset must be permutation-invariant; got \
         forward={forward_keys:?} reversed={reversed_keys:?}"
    );
}

/// MR3 (compound: order-sensitivity + composition under length-3 reorders):
/// the ordered tuple of `prev_entry_hash` values across all retained entries
/// must be unique per append-order permutation. Note that `compute_entry_hash`
/// intentionally excludes `prev_entry_hash` to avoid a circular dependency, so
/// chain order-sensitivity surfaces in the *sequence* of prev bindings, not in
/// any single tail hash. If two distinct permutations produced the same prev
/// sequence, the chain would not distinguish those append histories — the
/// tamper-detection guarantee would be lost.
#[test]
fn mr_three_entry_reorders_all_produce_distinct_prev_hash_sequences() {
    let entries = [
        mk_entry("DEC-1", 1, DecisionKind::Admit),
        mk_entry("DEC-2", 2, DecisionKind::Deny),
        mk_entry("DEC-3", 3, DecisionKind::Escalate),
    ];

    // All 6 permutations of indices (0,1,2).
    let perms: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];

    let mut prev_sequences: Vec<(Vec<String>, [usize; 3])> = perms
        .iter()
        .map(|perm| {
            let ordered = [
                entries[perm[0]].clone(),
                entries[perm[1]].clone(),
                entries[perm[2]].clone(),
            ];
            let snap = append_all(&ordered);
            let seq: Vec<String> = snap.iter().map(|e| e.prev_entry_hash.clone()).collect();
            (seq, *perm)
        })
        .collect();

    let total = prev_sequences.len();
    prev_sequences.sort_by(|a, b| a.0.cmp(&b.0));
    prev_sequences.dedup_by(|a, b| a.0 == b.0);

    assert_eq!(
        prev_sequences.len(),
        total,
        "expected {total} distinct prev_entry_hash sequences across all 6 \
         permutations of 3 distinct entries; got {} unique sequences — chain \
         is collapsing distinct append histories",
        prev_sequences.len()
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// MR4 (property-based order-sensitivity): for any two distinct entries
    /// drawn from a small space, the second-slot prev_entry_hash differs
    /// between forward and reversed append orders.
    #[test]
    fn mr_pbt_chain_head_changes_under_swap(
        e1 in test_strategies::evidence_ledger_entries(),
        e2 in test_strategies::evidence_ledger_entries(),
    ) {
        prop_assume!(e1 != e2);

        let forward = append_all(&[e1.clone(), e2.clone()]);
        let reversed = append_all(&[e2, e1]);

        prop_assert_ne!(
            &forward[1].prev_entry_hash,
            &reversed[1].prev_entry_hash,
            "hash chain order-sensitivity violated for distinct entries",
        );
    }

    /// MR5 (property-based determinism, r7-cc_4-2204): for ANY append
    /// sequence, two independent ledger constructions over the same input
    /// MUST produce bit-identical `(entry_hash, prev_entry_hash)` pairs at
    /// every slot. This pins three load-bearing invariants the T12.4
    /// profiling-feature wrapper at
    /// `crates/franken-node/src/observability/evidence_ledger.rs::EvidenceLedger::append`
    /// (shipped under bd-98xo5.12.4 commit 8d6adee7 + fresh-eyes r3
    /// schema fix 8869165a) MUST preserve:
    ///   1. No clock-dependent fields land in the canonical hash preimage
    ///      (otherwise two builds would diverge across the build wall-clock).
    ///   2. No RNG nondeterminism in the replay-signature derivation
    ///      (the replay-signing key is deterministic from the seed; the
    ///      signature itself is RFC 8032 Ed25519 which is deterministic).
    ///   3. The instrumentation `cfg(feature = "profiling")` wrapper at
    ///      evidence_ledger.rs:1589-1602 cannot perturb byte output —
    ///      the timing-recorder block is structurally a no-op on every
    ///      return value path; this MR catches a hypothetical regression
    ///      where someone moves logic INTO the wrapper.
    ///
    /// A failure here invalidates every downstream consumer that signs or
    /// HMAC's the canonical evidence-bundle bytes (replay bundles, audit
    /// receipts, federation roll-ups).
    #[test]
    fn mr_pbt_append_is_deterministic_across_independent_builds(
        entries in proptest::collection::vec(
            test_strategies::evidence_ledger_entries(),
            1..=8,
        ),
    ) {
        let first_build = append_all(&entries);
        let second_build = append_all(&entries);

        prop_assert_eq!(
            first_build.len(),
            second_build.len(),
            "independent builds must produce same snapshot length"
        );

        for (idx, (a, b)) in first_build.iter().zip(second_build.iter()).enumerate() {
            prop_assert_eq!(
                &a.prev_entry_hash,
                &b.prev_entry_hash,
                "slot {} prev_entry_hash diverged across independent builds — \
                 a clock or RNG leak in the canonical hash preimage would \
                 invalidate replay-bundle and federation roll-up signatures",
                idx,
            );
            prop_assert_eq!(
                &a.decision_id,
                &b.decision_id,
                "slot {} decision_id diverged — input was the same, output \
                 must be the same",
                idx,
            );
            prop_assert_eq!(
                a.epoch_id,
                b.epoch_id,
                "slot {} epoch_id diverged",
                idx,
            );
            prop_assert_eq!(
                a.decision_kind,
                b.decision_kind,
                "slot {} decision_kind diverged",
                idx,
            );
        }
    }
}
