//! Metamorphic test for replay bundle event reordering invariance.
//!
//! Property: Reorder concurrent events (same timestamp) → same canonical bundle
//! This tests that the bundle generation process correctly handles event ordering
//! for events that occur at the same timestamp and are logically commutative.

use frankenengine_node::test_strategies;
use frankenengine_node::tools::replay_bundle::{
    RawEvent, generate_replay_bundle, to_canonical_json,
};
use proptest::prelude::*;
use serde_json::{Value, json};
use std::collections::HashMap;

/// Reorders events that have the same timestamp
fn reorder_concurrent_events(mut events: Vec<RawEvent>, seed: u64) -> Vec<RawEvent> {
    // Group events by timestamp
    let mut timestamp_groups: HashMap<String, Vec<(usize, RawEvent)>> = HashMap::new();

    for (idx, event) in events.into_iter().enumerate() {
        timestamp_groups
            .entry(event.timestamp.clone())
            .or_insert_with(Vec::new)
            .push((idx, event));
    }

    // Shuffle events within each timestamp group using deterministic seed
    let mut result = Vec::new();
    let mut sorted_timestamps: Vec<_> = timestamp_groups.keys().cloned().collect();
    sorted_timestamps.sort();

    for timestamp in sorted_timestamps {
        let mut group = timestamp_groups.remove(&timestamp).unwrap();

        // Only reorder if there are multiple events with same timestamp
        if group.len() > 1 {
            // Deterministic shuffle based on seed
            let mut rng_state = seed.wrapping_mul(timestamp.len() as u64);
            for i in (1..group.len()).rev() {
                rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                let j = (rng_state as usize) % (i + 1);
                group.swap(i, j);
            }
        }

        // Add reordered events to result
        for (_, event) in group {
            result.push(event);
        }
    }

    result
}

proptest! {
    /// Metamorphic Property: Event reordering invariance for concurrent events
    ///
    /// Given a set of events, if we:
    /// 1. Generate a replay bundle from the original event order
    /// 2. Reorder events that have the same timestamp (concurrent events)
    /// 3. Generate a replay bundle from the reordered events
    ///
    /// Then: canonical_json(original_bundle) == canonical_json(reordered_bundle)
    ///
    /// This tests that replay bundle generation is invariant to the ordering
    /// of logically concurrent events (same timestamp).
    #[test]
    fn mr_replay_bundle_concurrent_event_reorder_invariance(
        events in prop::collection::vec(test_strategies::replay_bundle_entries(), 2..8),
        reorder_seed in any::<u64>()
    ) {
        let incident_id = "test-incident-metamorphic";

        // Step 1: Generate bundle from original event order
        let original_bundle = generate_replay_bundle(incident_id, &events)
            .expect("original events should generate valid bundle");

        let original_canonical = to_canonical_json(&original_bundle)
            .expect("original bundle should produce canonical JSON");

        // Step 2: Reorder events that share the same timestamp
        let reordered_events = reorder_concurrent_events(events, reorder_seed);

        // Step 3: Generate bundle from reordered events
        let reordered_bundle = generate_replay_bundle(incident_id, &reordered_events)
            .expect("reordered events should generate valid bundle");

        let reordered_canonical = to_canonical_json(&reordered_bundle)
            .expect("reordered bundle should produce canonical JSON");

        // Metamorphic invariant: canonical JSON should be identical for concurrent event reordering
        prop_assert_eq!(
            original_canonical,
            reordered_canonical,
            "Reordering concurrent events changed canonical bundle representation - determinism violated"
        );
    }

    /// Metamorphic Property: Identical incident ID with identical events → identical bundles
    ///
    /// Given the same incident ID and event list, if we:
    /// 1. Generate a bundle twice with identical inputs
    ///
    /// Then: The bundles should be byte-for-byte identical
    ///
    /// This tests the INV-RB-DETERMINISTIC invariant directly.
    #[test]
    fn mr_replay_bundle_deterministic_generation(
        events in prop::collection::vec(test_strategies::replay_bundle_entries(), 1..5)
    ) {
        let incident_id = "deterministic-test";

        // Generate bundle twice with identical inputs
        let bundle1 = generate_replay_bundle(incident_id, &events)
            .expect("first bundle generation should succeed");

        let bundle2 = generate_replay_bundle(incident_id, &events)
            .expect("second bundle generation should succeed");

        let canonical1 = to_canonical_json(&bundle1)
            .expect("first bundle should canonicalize");

        let canonical2 = to_canonical_json(&bundle2)
            .expect("second bundle should canonicalize");

        // Metamorphic invariant: identical inputs produce identical outputs
        prop_assert_eq!(
            canonical1,
            canonical2,
            "Identical inputs produced different bundles - INV-RB-DETERMINISTIC violated"
        );
    }

    /// Metamorphic Property: Event payload field reordering → same bundle hash
    ///
    /// Given events with JSON payloads, if we:
    /// 1. Generate a bundle from events with original JSON field ordering
    /// 2. Reorder JSON fields in event payloads (keeping same data)
    /// 3. Generate a bundle from events with reordered JSON fields
    ///
    /// Then: The bundle canonical representations should be identical
    ///
    /// This tests that JSON canonicalization correctly normalizes field ordering.
    #[test]
    fn mr_replay_bundle_payload_field_reorder_invariance(
        mut events in prop::collection::vec(test_strategies::replay_bundle_entries(), 1..4),
        field_seed in any::<u64>()
    ) {
        let incident_id = "field-reorder-test";

        // Generate original bundle
        let original_bundle = generate_replay_bundle(incident_id, &events)
            .expect("original bundle should generate");

        let original_canonical = to_canonical_json(&original_bundle)
            .expect("original bundle should canonicalize");

        // Reorder JSON fields in event payloads
        for event in &mut events {
            if let Value::Object(ref mut map) = event.payload {
                // Convert to vector, shuffle, rebuild map
                let mut pairs: Vec<_> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

                // Deterministic shuffle
                let mut rng_state = field_seed;
                for i in (1..pairs.len()).rev() {
                    rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                    let j = (rng_state as usize) % (i + 1);
                    pairs.swap(i, j);
                }

                map.clear();
                for (key, value) in pairs {
                    map.insert(key, value);
                }
            }
        }

        // Generate bundle with reordered JSON fields
        let reordered_bundle = generate_replay_bundle(incident_id, &events)
            .expect("reordered field bundle should generate");

        let reordered_canonical = to_canonical_json(&reordered_bundle)
            .expect("reordered field bundle should canonicalize");

        // Metamorphic invariant: JSON field reordering should not affect canonical representation
        prop_assert_eq!(
            original_canonical,
            reordered_canonical,
            "JSON field reordering changed canonical bundle - canonicalization failed"
        );
    }
}
