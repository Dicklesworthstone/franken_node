//! Metamorphic tests for proptest strategy generators.
//!
//! These tests verify metamorphic relations for test data generation strategies,
//! ensuring the generators produce well-formed outputs with expected properties.

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    #[test]
    fn mr_equivalence_generator_determinism() {
        // MR1: Same seed should produce same generated values across runs
        proptest!(|(seed: u64, max_len: usize)| {
            prop_assume!(max_len > 0 && max_len < 1000);

            let mut rng1 = proptest::test_runner::TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha);
            let mut rng2 = proptest::test_runner::TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha);

            rng1.set_seed(seed);
            rng2.set_seed(seed);

            let strategy = bounded_text(max_len);
            let val1 = strategy.new_tree(&mut rng1).unwrap().current();
            let val2 = strategy.new_tree(&mut rng2).unwrap().current();

            prop_assert_eq!(val1, val2, "Same seed should produce identical values");
        });
    }

    #[test]
    fn mr_inclusive_length_bound_containment() {
        // MR2: Smaller max_len generators should produce subset of larger ones
        proptest!(|(max_len_small: usize, extra_len: usize)| {
            prop_assume!(max_len_small > 0 && max_len_small < 100);
            prop_assume!(extra_len > 0 && extra_len < 50);

            let max_len_large = max_len_small.saturating_add(extra_len);

            let small_strategy = bounded_text(max_len_small);
            let large_strategy = bounded_text(max_len_large);

            // Generate samples from both strategies
            let mut small_samples = Vec::new();
            let mut large_samples = Vec::new();

            for seed in 0..20u64 {
                let mut rng_small = proptest::test_runner::TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha);
                let mut rng_large = proptest::test_runner::TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha);

                rng_small.set_seed(seed);
                rng_large.set_seed(seed);

                if let Ok(tree) = small_strategy.new_tree(&mut rng_small) {
                    small_samples.push(tree.current());
                }
                if let Ok(tree) = large_strategy.new_tree(&mut rng_large) {
                    large_samples.push(tree.current());
                }
            }

            // Every sample from small generator should be valid for large generator
            for small_sample in &small_samples {
                prop_assert!(
                    small_sample.len() <= max_len_large,
                    "Small generator sample exceeds large generator's bound: {} > {}",
                    small_sample.len(),
                    max_len_large
                );
            }
        });
    }

    #[test]
    fn mr_multiplicative_size_scaling() {
        // MR3: Doubling max_len should expand the potential output space
        proptest!(|(base_len: usize)| {
            prop_assume!(base_len > 0 && base_len < 50);

            let doubled_len = base_len.saturating_mul(2);

            let base_strategy = bounded_text(base_len);
            let doubled_strategy = bounded_text(doubled_len);

            // Collect unique outputs from both strategies
            let mut base_outputs = HashSet::new();
            let mut doubled_outputs = HashSet::new();

            for seed in 0..100u64 {
                let mut rng_base = proptest::test_runner::TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha);
                let mut rng_doubled = proptest::test_runner::TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha);

                rng_base.set_seed(seed);
                rng_doubled.set_seed(seed);

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
        proptest!(|(max_len: usize)| {
            prop_assume!(max_len > 0 && max_len < 100);

            let strategy = ascii_identifier(max_len);

            // Test multiple generations
            for seed in 0..50u64 {
                let mut rng = proptest::test_runner::TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha);
                rng.set_seed(seed);

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
        proptest!(|()| {
            let strategy = rfc3339_timestamp();

            // Test multiple timestamp generations
            for seed in 0..30u64 {
                let mut rng = proptest::test_runner::TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha);
                rng.set_seed(seed);

                if let Ok(tree) = strategy.new_tree(&mut rng) {
                    let timestamp = tree.current();

                    // Should match RFC3339 basic pattern
                    prop_assert!(
                        timestamp.starts_with("2026-") && timestamp.ends_with('Z'),
                        "Timestamp should be 2026 year with Z suffix: '{}'",
                        timestamp
                    );

                    // Should have correct length (YYYY-MM-DDTHH:MM:SS.sssZ = 24 chars)
                    prop_assert_eq!(
                        timestamp.len(),
                        24,
                        "Timestamp should be 24 characters: '{}'",
                        timestamp
                    );

                    // Check basic format components
                    let parts: Vec<&str> = timestamp.split(&['T', '-', ':', '.', 'Z'][..]).collect();
                    prop_assert!(parts.len() >= 6, "Timestamp should have all components: '{}'", timestamp);
                }
            }
        });
    }

    #[test]
    fn mr_additive_hash_format_consistency() {
        // MR6: SHA256 hashes should always have consistent format
        proptest!(|()| {
            let strategy = sha256_hash();

            for seed in 0..20u64 {
                let mut rng = proptest::test_runner::TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha);
                rng.set_seed(seed);

                if let Ok(tree) = strategy.new_tree(&mut rng) {
                    let hash = tree.current();

                    prop_assert!(
                        hash.starts_with("sha256:"),
                        "Hash should start with sha256: prefix: '{}'",
                        hash
                    );

                    let hex_part = &hash[7..]; // Skip "sha256:" prefix
                    prop_assert_eq!(
                        hex_part.len(),
                        64,
                        "SHA256 hex should be 64 characters: '{}'",
                        hex_part
                    );

                    // Should be valid hex
                    for ch in hex_part.chars() {
                        prop_assert!(
                            ch.is_ascii_hexdigit(),
                            "Invalid hex character '{}' in hash '{}'",
                            ch,
                            hash
                        );
                    }
                }
            }
        });
    }

    #[test]
    fn mr_inclusive_hex_length_scaling() {
        // MR7: hex_bytes generator should produce exact length outputs
        proptest!(|(target_len: usize)| {
            prop_assume!(target_len > 0 && target_len < 100);

            let strategy = hex_bytes(target_len);

            for seed in 0..10u64 {
                let mut rng = proptest::test_runner::TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha);
                rng.set_seed(seed);

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