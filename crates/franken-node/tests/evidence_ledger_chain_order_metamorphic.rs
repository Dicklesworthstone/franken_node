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
    ledger.snapshot().entries.into_iter().map(|(_, e)| e).collect()
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
/// any non-trivial permutation of three distinct entries must produce a
/// different chain head than the canonical order. Equality with the
/// canonical chain head would mean ≥2 distinct orderings collide on the
/// final prev binding — a hash chain weakness.
#[test]
fn mr_three_entry_reorders_all_produce_distinct_tail_bindings() {
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

    let mut tails: Vec<(String, [usize; 3])> = perms
        .iter()
        .map(|perm| {
            let ordered = [
                entries[perm[0]].clone(),
                entries[perm[1]].clone(),
                entries[perm[2]].clone(),
            ];
            let snap = append_all(&ordered);
            // The tail prev_entry_hash binds to the (n-1)-th appended entry's
            // hash — distinct orderings yield distinct prefixes and so must
            // yield distinct tail bindings.
            (snap[2].prev_entry_hash.clone(), *perm)
        })
        .collect();

    let total = tails.len();
    tails.sort_by(|a, b| a.0.cmp(&b.0));
    tails.dedup_by(|a, b| a.0 == b.0);

    assert_eq!(
        tails.len(),
        total,
        "expected {total} distinct tail prev_entry_hashes across all 6 \
         permutations of 3 distinct entries; got {} unique values — hash chain \
         is collapsing distinct prefixes",
        tails.len()
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
        id_a in "[A-Z]{3}-[0-9]{2}",
        id_b in "[A-Z]{3}-[0-9]{2}",
        epoch_a in 1u64..1_000,
        epoch_b in 1u64..1_000,
        kind_a in 0usize..7,
        kind_b in 0usize..7,
    ) {
        // Skip the degenerate equal-entry case — the MR only asserts
        // sensitivity when inputs differ.
        let kinds = [
            DecisionKind::Admit,
            DecisionKind::Deny,
            DecisionKind::Quarantine,
            DecisionKind::Release,
            DecisionKind::Rollback,
            DecisionKind::Throttle,
            DecisionKind::Escalate,
        ];
        let e1 = mk_entry(&id_a, epoch_a, kinds[kind_a]);
        let e2 = mk_entry(&id_b, epoch_b, kinds[kind_b]);
        prop_assume!((id_a.as_str(), epoch_a, kind_a) != (id_b.as_str(), epoch_b, kind_b));

        let forward = append_all(&[e1.clone(), e2.clone()]);
        let reversed = append_all(&[e2, e1]);

        prop_assert_ne!(
            &forward[1].prev_entry_hash,
            &reversed[1].prev_entry_hash,
            "hash chain order-sensitivity violated for distinct entries",
        );
    }
}
