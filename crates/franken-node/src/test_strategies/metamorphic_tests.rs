//! Metamorphic tests for proptest strategy generators.
//!
//! These tests verify metamorphic relations for test data generation strategies,
//! ensuring the generators produce well-formed outputs with expected properties.

#[cfg(test)]
mod tests {
    use super::super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    /// Derive a deterministic 32-byte ChaCha seed from a `u64`.
    ///
    /// `TestRng::set_seed` is `pub(crate)` in proptest, so seeding now goes
    /// through the public `TestRng::from_seed`, which requires a 32-byte seed
    /// for `RngAlgorithm::ChaCha`. Encoding the `u64` into the low 8 bytes keeps
    /// the metamorphic invariant intact: equal `u64` seeds yield equal seed
    /// bytes (so identical RNG streams), and distinct seeds stay distinct.
    fn chacha_seed_bytes(seed: u64) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[..8].copy_from_slice(&seed.to_le_bytes());
        buf
    }

    /// Build a deterministic `TestRunner` seeded from a `u64`.
    ///
    /// `Strategy::new_tree` takes a `&mut TestRunner` (not a bare `TestRng`), so we
    /// wrap the ChaCha-seeded `TestRng` in a runner with default config. Equal seeds
    /// yield equal runners → identical generation streams (the metamorphic invariant).
    fn seeded_runner(seed: u64) -> proptest::test_runner::TestRunner {
        proptest::test_runner::TestRunner::new_with_rng(
            proptest::test_runner::Config::default(),
            proptest::test_runner::TestRng::from_seed(
                proptest::test_runner::RngAlgorithm::ChaCha,
                &chacha_seed_bytes(seed),
            ),
        )
    }

    #[test]
    fn mr_equivalence_generator_determinism() {
        // MR1: Same seed should produce same generated values across runs
        // Generate `max_len` directly in-range (1..1000); a bare `usize` param
        // spans the full integer range so a `prop_assume!(max_len < 1000)` filter
        // rejects ~every case and aborts on too-many-global-rejects.
        proptest!(|(seed: u64, max_len in 1usize..1000)| {
            let mut rng1 = seeded_runner(seed);
            let mut rng2 = seeded_runner(seed);

            let strategy = bounded_text(max_len);
            let val1 = strategy.new_tree(&mut rng1).unwrap().current();
            let val2 = strategy.new_tree(&mut rng2).unwrap().current();

            prop_assert_eq!(val1, val2, "Same seed should produce identical values");
        });
    }

    #[test]
    fn mr_inclusive_length_bound_containment() {
        // MR2: Smaller max_len generators should produce subset of larger ones
        // Generate both lengths in-range (see MR1) rather than filtering full-range usize.
        proptest!(|(max_len_small in 1usize..100, extra_len in 1usize..50)| {
            let max_len_large = max_len_small.saturating_add(extra_len);

            let small_strategy = bounded_text(max_len_small);
            let large_strategy = bounded_text(max_len_large);

            // Generate samples from both strategies
            let mut small_samples = Vec::new();
            let mut large_samples = Vec::new();

            for seed in 0..20u64 {
                let mut rng_small = seeded_runner(seed);
                let mut rng_large = seeded_runner(seed);

                if let Ok(tree) = small_strategy.new_tree(&mut rng_small) {
                    small_samples.push(tree.current());
                }
                if let Ok(tree) = large_strategy.new_tree(&mut rng_large) {
                    large_samples.push(tree.current());
                }
            }

            // Every sample from small generator should be valid for large generator.
            // `bounded_text` caps the number of *input bytes* at `max_len`, then runs
            // `String::from_utf8_lossy`, which replaces each invalid byte with U+FFFD
            // (3 output bytes) — so the output *byte* length can exceed `max_len`.
            // The character count, however, is bounded by the input byte budget
            // (each source byte yields at most one char), so that is the invariant
            // that actually encodes the small-subset-of-large containment relation.
            for small_sample in &small_samples {
                prop_assert!(
                    small_sample.chars().count() <= max_len_large,
                    "Small generator sample exceeds large generator's bound: {} > {}",
                    small_sample.chars().count(),
                    max_len_large
                );
            }
        });
    }

    #[test]
    fn mr_multiplicative_size_scaling() {
        // MR3: Doubling max_len should expand the potential output space
        // Generate `base_len` in-range (see MR1) rather than filtering full-range usize.
        proptest!(|(base_len in 1usize..50)| {
            let doubled_len = base_len.saturating_mul(2);

            let base_strategy = bounded_text(base_len);
            let doubled_strategy = bounded_text(doubled_len);

            // Collect unique outputs from both strategies
            let mut base_outputs = HashSet::new();
            let mut doubled_outputs = HashSet::new();

            for seed in 0..100u64 {
                let mut rng_base = seeded_runner(seed);
                let mut rng_doubled = seeded_runner(seed);

                if let Ok(tree) = base_strategy.new_tree(&mut rng_base) {
                    base_outputs.insert(tree.current());
                }
                if let Ok(tree) = doubled_strategy.new_tree(&mut rng_doubled) {
                    doubled_outputs.insert(tree.current());
                }
            }

            // Doubled generator should explore at least as large a space as base
            // (This is probabilistic but should hold with high confidence)
            prop_assert!(
                doubled_outputs.len() >= base_outputs.len() || doubled_outputs.len() > 80,
                "Doubled max_len should not reduce output diversity: base={}, doubled={}",
                base_outputs.len(),
                doubled_outputs.len()
            );
        });
    }

    #[test]
    fn mr_equivalence_identifier_format_invariants() {
        // MR4: Generated identifiers should always match their expected format
        // Generate `max_len` in-range (see MR1) rather than filtering full-range usize.
        proptest!(|(max_len in 1usize..100)| {
            let strategy = ascii_identifier(max_len);

            // Test multiple generations
            for seed in 0..50u64 {
                let mut rng = seeded_runner(seed);

                if let Ok(tree) = strategy.new_tree(&mut rng) {
                    let identifier = tree.current();

                    prop_assert!(!identifier.is_empty(), "Identifier should not be empty");
                    prop_assert!(
                        identifier.len() <= max_len,
                        "Identifier length {} exceeds max {}",
                        identifier.len(),
                        max_len
                    );

                    // Should only contain allowed characters
                    for ch in identifier.chars() {
                        prop_assert!(
                            ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == ':' || ch == '-',
                            "Invalid character '{}' in identifier '{}'",
                            ch,
                            identifier
                        );
                    }
                }
            }
        });
    }

    #[test]
    fn mr_permutation_timestamp_format_validity() {
        // MR5: All generated timestamps should be valid RFC3339 format
        let strategy = rfc3339_timestamp();

        // Test multiple timestamp generations
        for seed in 0..30u64 {
            let mut rng = seeded_runner(seed);

            if let Ok(tree) = strategy.new_tree(&mut rng) {
                let timestamp = tree.current();

                // Should match RFC3339 basic pattern
                assert!(
                    timestamp.starts_with("2026-") && timestamp.ends_with('Z'),
                    "Timestamp should be 2026 year with Z suffix: '{}'",
                    timestamp
                );

                // Should have correct length (YYYY-MM-DDTHH:MM:SS.sssZ = 24 chars)
                assert_eq!(
                    timestamp.len(),
                    24,
                    "Timestamp should be 24 characters: '{}'",
                    timestamp
                );

                // Check basic format components
                let parts: Vec<&str> = timestamp.split(&['T', '-', ':', '.', 'Z'][..]).collect();
                assert!(
                    parts.len() >= 6,
                    "Timestamp should have all components: '{}'",
                    timestamp
                );
            }
        }
    }

    #[test]
    fn mr_additive_hash_format_consistency() {
        // MR6: SHA256 hashes should always have consistent format
        let strategy = sha256_hash();

        for seed in 0..20u64 {
            let mut rng = seeded_runner(seed);

            if let Ok(tree) = strategy.new_tree(&mut rng) {
                let hash = tree.current();

                assert!(
                    hash.starts_with("sha256:"),
                    "Hash should start with sha256: prefix: '{}'",
                    hash
                );

                let hex_part = &hash[7..]; // Skip "sha256:" prefix
                assert_eq!(
                    hex_part.len(),
                    64,
                    "SHA256 hex should be 64 characters: '{}'",
                    hex_part
                );

                // Should be valid hex
                for ch in hex_part.chars() {
                    assert!(
                        ch.is_ascii_hexdigit(),
                        "Invalid hex character '{}' in hash '{}'",
                        ch,
                        hash
                    );
                }
            }
        }
    }

    #[test]
    fn mr_inclusive_hex_length_scaling() {
        // MR7: hex_bytes generator should produce exact length outputs
        // Generate `target_len` in-range (see MR1) rather than filtering full-range usize.
        proptest!(|(target_len in 1usize..100)| {
            let strategy = hex_bytes(target_len);

            for seed in 0..10u64 {
                let mut rng = seeded_runner(seed);

                if let Ok(tree) = strategy.new_tree(&mut rng) {
                    let hex_string = tree.current();

                    prop_assert_eq!(
                        hex_string.len(),
                        target_len * 2, // Each byte becomes 2 hex chars
                        "Hex string length should be exactly 2x target length"
                    );

                    // Should be valid hex
                    for ch in hex_string.chars() {
                        prop_assert!(
                            ch.is_ascii_hexdigit(),
                            "Invalid hex character '{}' in hex_bytes output",
                            ch
                        );
                    }
                }
            }
        });
    }
}
