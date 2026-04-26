//! Metamorphic test for trust card canonical hash invariance under field reordering.
//!
//! Property: Reorder non-semantic JSON fields → same canonical hash
//! This tests that the canonicalization process correctly normalizes field ordering
//! and produces deterministic hashes regardless of input field ordering.

use frankenengine_node::supply_chain::trust_card::{
    TrustCard, compute_card_hash, to_canonical_json,
};
use frankenengine_node::test_strategies;
use proptest::prelude::*;
use serde_json::{Map, Value};

/// Reorders fields in a JSON object by shuffling the key order
fn reorder_json_fields(mut value: Value, seed: u64) -> Value {
    match &mut value {
        Value::Object(map) => {
            // Extract all key-value pairs
            let mut pairs: Vec<(String, Value)> = map
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        reorder_json_fields(v.clone(), seed.wrapping_mul(31)),
                    )
                })
                .collect();

            // Deterministic shuffle based on seed
            let mut rng_state = seed;
            for i in (1..pairs.len()).rev() {
                rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                let j = (rng_state as usize) % (i + 1);
                pairs.swap(i, j);
            }

            // Rebuild map with shuffled order
            let mut new_map = Map::new();
            for (key, val) in pairs {
                new_map.insert(key, val);
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| reorder_json_fields(v.clone(), seed.wrapping_mul(37)))
                .collect(),
        ),
        other => other.clone(),
    }
}

proptest! {
    /// Metamorphic Property: Field reordering invariance
    ///
    /// Given a TrustCard, if we:
    /// 1. Serialize it to JSON and reorder all field keys
    /// 2. Deserialize back to TrustCard
    /// 3. Compute canonical hash
    ///
    /// Then: canonical_hash(original) == canonical_hash(reordered)
    ///
    /// This tests that canonicalization correctly normalizes field ordering.
    #[test]
    fn mr_trust_card_field_reorder_invariant_canonical_hash(
        card in test_strategies::trust_cards(),
        shuffle_seed in any::<u64>()
    ) {
        // Step 1: Compute hash of original card
        let original_hash = compute_card_hash(&card)
            .expect("original card should compute valid hash");

        // Step 2: Serialize to JSON and reorder all fields deterministically
        let original_json = serde_json::to_value(&card)
            .expect("card should serialize to JSON");

        let reordered_json = reorder_json_fields(original_json, shuffle_seed);

        // Step 3: Deserialize reordered JSON back to TrustCard
        let reordered_card: TrustCard = serde_json::from_value(reordered_json)
            .expect("reordered JSON should deserialize to valid TrustCard");

        // Step 4: Compute hash of reordered card
        let reordered_hash = compute_card_hash(&reordered_card)
            .expect("reordered card should compute valid hash");

        // Metamorphic invariant: hashes must be identical
        prop_assert_eq!(
            original_hash,
            reordered_hash,
            "Field reordering changed canonical hash - canonicalization is not deterministic"
        );
    }

    /// Metamorphic Property: Canonical JSON stability under reordering
    ///
    /// Given a TrustCard, if we:
    /// 1. Reorder its JSON representation multiple times
    /// 2. Compute canonical JSON for each
    ///
    /// Then: All canonical JSON outputs must be identical
    ///
    /// This tests canonical JSON normalization more directly.
    #[test]
    fn mr_trust_card_canonical_json_reorder_stable(
        card in test_strategies::trust_cards(),
        seeds in prop::collection::vec(any::<u64>(), 2..5)
    ) {
        // Compute canonical JSON of original
        let original_canonical = to_canonical_json(&card)
            .expect("original card should produce canonical JSON");

        // Apply multiple different field reorderings
        for seed in seeds {
            let original_json = serde_json::to_value(&card)
                .expect("card should serialize");

            let reordered_json = reorder_json_fields(original_json, seed);

            let reordered_card: TrustCard = serde_json::from_value(reordered_json)
                .expect("reordered JSON should deserialize");

            let reordered_canonical = to_canonical_json(&reordered_card)
                .expect("reordered card should produce canonical JSON");

            // Metamorphic invariant: canonical JSON must be identical
            prop_assert_eq!(
                original_canonical,
                reordered_canonical,
                "Canonical JSON changed after field reordering with seed {}", seed
            );
        }
    }

    /// Metamorphic Property: Hash-signature separation under reordering
    ///
    /// Given a TrustCard with placeholder hash/signature, if we:
    /// 1. Reorder fields and compute hash
    /// 2. Set that hash in the card and reorder again
    ///
    /// Then: The hash computation should be stable (not depend on hash field order)
    #[test]
    fn mr_trust_card_hash_computation_reorder_independent(
        mut card in test_strategies::trust_cards(),
        reorder_seed in any::<u64>()
    ) {
        // Ensure we start with empty hash/signature for deterministic test
        card.card_hash = String::new();
        card.registry_signature = String::new();

        // Compute hash via normal path
        let hash1 = compute_card_hash(&card)
            .expect("card should compute hash");

        // Serialize, reorder, deserialize
        let json = serde_json::to_value(&card)
            .expect("card should serialize");
        let reordered_json = reorder_json_fields(json, reorder_seed);
        let mut reordered_card: TrustCard = serde_json::from_value(reordered_json)
            .expect("reordered JSON should deserialize");

        // Ensure hash/signature are still empty after reordering
        reordered_card.card_hash = String::new();
        reordered_card.registry_signature = String::new();

        // Compute hash of reordered card
        let hash2 = compute_card_hash(&reordered_card)
            .expect("reordered card should compute hash");

        // Metamorphic invariant: hash computation is reorder-independent
        prop_assert_eq!(
            hash1,
            hash2,
            "Hash computation changed after field reordering - not deterministic"
        );
    }
}
