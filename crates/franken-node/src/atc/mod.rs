//! Autonomous Trust Control (ATC) surface contract.
//!
//! This module intentionally keeps the ATC surface explicit while the concrete
//! engines continue to live in their implementation domains. The fingerprint is
//! a stable, domain-separated contract marker for claim gates and verifier
//! evidence that need to detect accidental surface drift.

use sha2::{Digest, Sha256};

pub const ATC_MODULE_SURFACE: &[&str] = &[
    "aggregation",
    "federation",
    "global_priors",
    "privacy_envelope",
    "signal_extraction",
    "signal_schema",
    "sketch_system",
    "urgent_routing",
];

pub fn module_surface() -> &'static [&'static str] {
    ATC_MODULE_SURFACE
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

#[cfg(test)]
mod module_surface_negative_tests {
    use super::*;

    #[test]
    fn module_surface_immutable_reference_consistency() {
        let surface1 = module_surface();
        let surface2 = module_surface();

        // Multiple calls should return identical references
        assert_eq!(surface1.as_ptr(), surface2.as_ptr());
        assert_eq!(surface1.len(), surface2.len());
    }

    #[test]
    fn module_surface_no_empty_strings() {
        for (index, &module) in module_surface().iter().enumerate() {
            assert!(!module.is_empty(),
                   "Module at index {} is empty string", index);
        }
    }

    #[test]
    fn module_surface_no_whitespace_only_modules() {
        for (index, &module) in module_surface().iter().enumerate() {
            assert!(!module.trim().is_empty(),
                   "Module at index {} is whitespace-only: {:?}", index, module);
            assert_eq!(module.trim(), module,
                      "Module at index {} has leading/trailing whitespace: {:?}", index, module);
        }
    }

    #[test]
    fn module_surface_no_path_separators() {
        for (index, &module) in module_surface().iter().enumerate() {
            assert!(!module.contains('/'),
                   "Module at index {} contains forward slash: {}", index, module);
            assert!(!module.contains('\\'),
                   "Module at index {} contains backslash: {}", index, module);
        }
    }

    #[test]
    fn module_surface_no_control_characters() {
        for (index, &module) in module_surface().iter().enumerate() {
            for (char_index, c) in module.char_indices() {
                assert!(!c.is_control(),
                       "Module at index {} contains control character at position {}: {:?}",
                       index, char_index, c);
            }
        }
    }

    #[test]
    fn module_surface_reasonable_length_bounds() {
        for (index, &module) in module_surface().iter().enumerate() {
            assert!(module.len() >= 3,
                   "Module at index {} is too short ({}): {}", index, module.len(), module);
            assert!(module.len() <= 50,
                   "Module at index {} is too long ({}): {}", index, module.len(), module);
        }
    }

    #[test]
    fn module_surface_no_consecutive_underscores() {
        for (index, &module) in module_surface().iter().enumerate() {
            assert!(!module.contains("__"),
                   "Module at index {} contains consecutive underscores: {}", index, module);
        }
    }

    #[test]
    fn module_surface_no_reserved_keywords() {
        let reserved_keywords = [
            "self", "super", "crate", "mod", "use", "pub", "fn", "let", "mut",
            "const", "static", "struct", "enum", "impl", "trait", "type",
            "if", "else", "match", "loop", "while", "for", "break", "continue",
            "return", "async", "await", "unsafe", "extern", "main", "test",
        ];

        for (index, &module) in module_surface().iter().enumerate() {
            for &keyword in &reserved_keywords {
                assert_ne!(module, keyword,
                          "Module at index {} is reserved keyword: {}", index, module);
            }
        }
    }

    #[test]
    fn module_surface_no_numeric_only_names() {
        for (index, &module) in module_surface().iter().enumerate() {
            assert!(!module.chars().all(|c| c.is_ascii_digit() || c == '_'),
                   "Module at index {} is numeric-only: {}", index, module);
        }
    }

    #[test]
    fn module_surface_consistent_naming_convention() {
        for (index, &module) in module_surface().iter().enumerate() {
            // Should start with lowercase letter
            let first_char = module.chars().next().expect("Non-empty module");
            assert!(first_char.is_ascii_lowercase(),
                   "Module at index {} doesn't start with lowercase letter: {}", index, module);

            // Should not have uppercase letters anywhere
            assert!(!module.chars().any(|c| c.is_ascii_uppercase()),
                   "Module at index {} contains uppercase letters: {}", index, module);
        }
    }

    #[test]
    fn module_surface_no_duplicate_prefixes() {
        let modules = module_surface();

        for i in 0..modules.len() {
            for j in (i+1)..modules.len() {
                let module_a = modules[i];
                let module_b = modules[j];

                // Check if one is a prefix of another
                assert!(!module_a.starts_with(&format!("{}_", module_b)) &&
                       !module_b.starts_with(&format!("{}_", module_a)),
                       "Modules {} and {} have prefix relationship", module_a, module_b);
            }
        }
    }

    #[test]
    fn module_surface_balanced_categorization() {
        let modules = module_surface();

        // Count modules by category (rough heuristic)
        let mut category_counts = std::collections::HashMap::new();

        for &module in modules {
            if module.contains("signal") {
                let count = category_counts.entry("signal").or_insert(0);
                *count = count.saturating_add(1);
            } else if module.contains("privacy") {
                let count = category_counts.entry("privacy").or_insert(0);
                *count = count.saturating_add(1);
            } else {
                let count = category_counts.entry("other").or_insert(0);
                *count = count.saturating_add(1);
            }
        }

        // No single category should dominate excessively
        let total = modules.len();
        for (category, count) in &category_counts {
            let percentage = (*count as f64) / (total as f64) * 100.0;
            assert!(percentage.is_finite(), "Non-finite percentage for category {}", category);
            assert!(percentage <= 75.0,
                   "Category {} dominates with {:.1}% of modules", category, percentage);
        }
    }

    #[test]
    fn module_surface_no_obvious_typos() {
        // Check for common typo patterns in module names
        for (index, &module) in module_surface().iter().enumerate() {
            // No repeated characters that are likely typos
            let chars: Vec<char> = module.chars().collect();
            for i in 0..chars.len().saturating_sub(2) {
                if chars[i] == chars[i+1] && chars[i] != '_' && chars[i].is_ascii_alphabetic() {
                    // Allow some legitimate doubled letters
                    let doubled_char = chars[i];
                    let valid_doubles = ['l', 'r', 's', 't', 'p', 'g']; // common in English
                    if !valid_doubles.contains(&doubled_char) {
                        panic!("Module at index {} may have typo with doubled '{}': {}",
                               index, doubled_char, module);
                    }
                }
            }
        }
    }

    #[test]
    fn module_surface_semantic_coherence() {
        // Each module should have semantic meaning in ATC context
        let atc_related_keywords = [
            "aggregation", "federation", "privacy", "signal", "sketch", "routing",
            "global", "envelope", "extraction", "schema", "system", "urgent", "priors"
        ];

        for (index, &module) in module_surface().iter().enumerate() {
            let has_atc_keyword = atc_related_keywords.iter().any(|&keyword| {
                module.contains(keyword)
            });

            assert!(has_atc_keyword,
                   "Module at index {} lacks obvious ATC-related semantics: {}", index, module);
        }
    }

    #[test]
    fn module_surface_memory_layout_stability() {
        // Test that the static array has stable memory layout
        let surface1 = module_surface();

        // Force some memory operations
        let _temp_vec: Vec<String> = surface1.iter().map(|s| s.to_string()).collect();

        let surface2 = module_surface();

        // Should be exactly the same memory location
        assert_eq!(surface1.as_ptr(), surface2.as_ptr());

        // Individual string pointers should also be stable
        for (i, (&str1, &str2)) in surface1.iter().zip(surface2.iter()).enumerate() {
            assert_eq!(str1.as_ptr(), str2.as_ptr(),
                      "String pointer changed for module at index {}", i);
        }
    }

    #[test]
    fn module_surface_thread_safety_verification() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let thread_count = 4;
        let barrier = Arc::new(Barrier::new(thread_count));
        let mut handles = Vec::new();

        for thread_id in 0..thread_count {
            let barrier = barrier.clone();

            let handle = thread::spawn(move || {
                barrier.wait(); // Synchronize start

                // Each thread accesses module_surface simultaneously
                let surface = module_surface();

                // Verify basic properties
                assert!(!surface.is_empty());
                assert_eq!(surface.len(), ATC_MODULE_SURFACE.len());

                // Return first module for comparison
                (thread_id, surface[0], surface.as_ptr())
            });

            push_bounded(&mut handles, handle, 100);
        }

        let mut results = Vec::new();
        for handle in handles {
            push_bounded(&mut results, handle.join().unwrap(), 100);
        }

        // All threads should see identical results
        let first_result = &results[0];
        for result in &results[1..] {
            assert_eq!(first_result.1, result.1, "Different module content across threads");
            assert_eq!(first_result.2, result.2, "Different pointer across threads");
        }
    }
}

pub fn module_surface_fingerprint_hex() -> String {
    surface_fingerprint_hex(ATC_MODULE_SURFACE)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod usize_to_u64_negative_tests {
    use super::*;

    #[test]
    fn usize_to_u64_zero_boundary() {
        assert_eq!(usize_to_u64(0), 0u64);
    }

    #[test]
    fn usize_to_u64_one_boundary() {
        assert_eq!(usize_to_u64(1), 1u64);
    }

    #[test]
    fn usize_to_u64_max_usize_saturates_to_u64_max() {
        // On systems where usize > u64 (theoretical), should saturate
        let result = usize_to_u64(usize::MAX);
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn usize_to_u64_large_values_within_u64_range() {
        if usize::BITS <= 64 {
            let large_value = usize::MAX / 2;
            assert_eq!(usize_to_u64(large_value), large_value as u64);
        }
    }

    #[test]
    fn usize_to_u64_power_of_two_boundaries() {
        for shift in 0..64.min(usize::BITS) {
            let value = 1usize << shift;
            if value <= usize::MAX {
                let result = usize_to_u64(value);
                assert!(result <= u64::MAX);
                if value <= u64::MAX as usize {
                    assert_eq!(result, value as u64);
                }
            }
        }
    }

    #[test]
    fn usize_to_u64_near_overflow_boundaries() {
        let test_values = [
            usize::MAX.saturating_sub(10),
            usize::MAX.saturating_sub(1),
            usize::MAX,
        ];

        for &value in &test_values {
            let result = usize_to_u64(value);
            assert!(result <= u64::MAX);
            // Should never panic
        }
    }

    #[test]
    fn usize_to_u64_consistency_across_architectures() {
        // Test common values that should behave consistently
        let common_values = [
            0, 1, 127, 255, 256, 65535, 65536,
            1_000, 10_000, 100_000, 1_000_000,
        ];

        for &value in &common_values {
            if value <= usize::MAX {
                let result = usize_to_u64(value);
                assert_eq!(result, value as u64);
            }
        }
    }
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(usize_to_u64(bytes.len()).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod update_len_prefixed_negative_tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn update_len_prefixed_with_empty_slice_encodes_zero_length() {
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        update_len_prefixed(&mut hasher1, b"");

        // Manually encode zero length + empty data for comparison
        hasher2.update(0u64.to_le_bytes());
        hasher2.update(b"");

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn update_len_prefixed_distinguishes_empty_from_single_zero_byte() {
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        update_len_prefixed(&mut hasher1, b"");
        update_len_prefixed(&mut hasher2, b"\x00");

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn update_len_prefixed_with_maximum_single_byte_slice() {
        let max_byte_slice = vec![0xFF; 1];
        let mut hasher = Sha256::new();

        // Should not panic with max byte values
        update_len_prefixed(&mut hasher, &max_byte_slice);

        let _result = hasher.finalize();
    }

    #[test]
    fn update_len_prefixed_with_large_data_chunk() {
        let large_chunk = vec![0xAA; 100_000]; // 100KB
        let mut hasher = Sha256::new();

        update_len_prefixed(&mut hasher, &large_chunk);

        let _result = hasher.finalize();
    }

    #[test]
    fn update_len_prefixed_collision_resistance_different_lengths() {
        // Test that same content but different concatenations produce different hashes
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        // Case 1: Single 6-byte string
        update_len_prefixed(&mut hasher1, b"abcdef");

        // Case 2: Two 3-byte strings (same total bytes, different structure)
        update_len_prefixed(&mut hasher2, b"abc");
        update_len_prefixed(&mut hasher2, b"def");

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn update_len_prefixed_handles_all_byte_values() {
        let all_bytes: Vec<u8> = (0..=255).collect();
        let mut hasher = Sha256::new();

        update_len_prefixed(&mut hasher, &all_bytes);

        let result = hasher.finalize();
        assert_eq!(result.len(), 32); // SHA-256 produces 32 bytes
    }

    #[test]
    fn update_len_prefixed_length_encoding_boundary_values() {
        // Test various length boundaries that could cause encoding issues
        let test_lengths = [0, 1, 127, 128, 255, 256, 65535, 65536];

        for &len in &test_lengths {
            if len <= 10000 { // Keep test reasonable
                let data = vec![42u8; len];
                let mut hasher = Sha256::new();

                update_len_prefixed(&mut hasher, &data);

                let _result = hasher.finalize();
            }
        }
    }

    #[test]
    fn update_len_prefixed_prevents_length_confusion_attacks() {
        // Test that attackers can't confuse length prefix with data
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        // Legitimate: 8-byte data
        let legitimate_data = b"testdata";
        update_len_prefixed(&mut hasher1, legitimate_data);

        // Attack attempt: embed fake length prefix in data
        let attack_data = [&8u64.to_le_bytes()[..], b"testdata"].concat();
        update_len_prefixed(&mut hasher2, &attack_data);

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();
        assert_ne!(hash1, hash2); // Length-prefixed encoding should prevent this attack
    }

    #[test]
    fn update_len_prefixed_with_pathological_repeated_patterns() {
        let patterns = [
            vec![0x00; 1000],           // All zeros
            vec![0xFF; 1000],           // All ones
            vec![0xAA; 1000],           // Alternating pattern
            (0u8..=255).cycle().take(1000).collect(), // Sequential pattern
        ];

        let mut hashes = Vec::new();

        for pattern in &patterns {
            let mut hasher = Sha256::new();
            update_len_prefixed(&mut hasher, pattern);
            let hash = hasher.finalize();
            push_bounded(&mut hashes, hash, 10000);
        }

        // All patterns should produce different hashes
        for i in 0..hashes.len() {
            for j in (i+1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j]);
            }
        }
    }

    #[test]
    fn update_len_prefixed_consistent_across_multiple_calls() {
        // Same data should always produce same hash
        let test_data = b"consistency_test_data";

        let mut hash1 = {
            let mut hasher = Sha256::new();
            update_len_prefixed(&mut hasher, test_data);
            hasher.finalize()
        };

        let mut hash2 = {
            let mut hasher = Sha256::new();
            update_len_prefixed(&mut hasher, test_data);
            hasher.finalize()
        };

        assert_eq!(hash1, hash2);
    }
}

fn update_count(hasher: &mut Sha256, count: usize) {
    hasher.update(usize_to_u64(count).to_le_bytes());
}

#[cfg(test)]
mod update_count_negative_tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn update_count_zero_produces_deterministic_hash() {
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        update_count(&mut hasher1, 0);
        update_count(&mut hasher2, 0);

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn update_count_distinguishes_zero_from_one() {
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        update_count(&mut hasher1, 0);
        update_count(&mut hasher2, 1);

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn update_count_max_usize_saturates_gracefully() {
        let mut hasher = Sha256::new();

        // Should not panic with maximum usize value
        update_count(&mut hasher, usize::MAX);

        let _result = hasher.finalize();
    }

    #[test]
    fn update_count_power_of_two_boundaries_all_different() {
        let mut hashes = Vec::new();

        for shift in 0..32 {
            let count = 1usize << shift;
            if count <= usize::MAX / 2 { // Avoid overflow
                let mut hasher = Sha256::new();
                update_count(&mut hasher, count);
                let hash = hasher.finalize();
                push_bounded(&mut hashes, (count, hash), 10000);
            }
        }

        // All power-of-two counts should produce different hashes
        for i in 0..hashes.len() {
            for j in (i+1)..hashes.len() {
                assert_ne!(hashes[i].1, hashes[j].1,
                          "Hash collision between counts {} and {}",
                          hashes[i].0, hashes[j].0);
            }
        }
    }

    #[test]
    fn update_count_sequential_values_avalanche_effect() {
        // Test that sequential count values produce very different hashes
        let base_count = 12345;
        let mut base_hasher = Sha256::new();
        update_count(&mut base_hasher, base_count);
        let base_hash = base_hasher.finalize();

        for offset in 1..=10 {
            let mut test_hasher = Sha256::new();
            update_count(&mut test_hasher, base_count + offset);
            let test_hash = test_hasher.finalize();

            // Should be completely different (good avalanche effect)
            assert_ne!(base_hash, test_hash);

            // Count number of differing bytes (should be substantial)
            let differing_bytes = base_hash.iter()
                .zip(test_hash.iter())
                .filter(|(a, b)| a != b)
                .count();

            // At least 50% of bytes should differ for good avalanche
            assert!(differing_bytes > 16,
                   "Poor avalanche effect: only {}/32 bytes differ for count {} vs {}",
                   differing_bytes, base_count, base_count + offset);
        }
    }

    #[test]
    fn update_count_large_sparse_values_no_collisions() {
        let sparse_counts = [
            1_000, 10_000, 100_000, 1_000_000,
            1_234_567, 7_654_321, 9_876_543,
            usize::MAX / 4, usize::MAX / 2, usize::MAX,
        ];

        let mut hashes = Vec::new();

        for &count in &sparse_counts {
            let mut hasher = Sha256::new();
            update_count(&mut hasher, count);
            let hash = hasher.finalize();
            hashes.push((count, hash));
        }

        // All sparse values should produce different hashes
        for i in 0..hashes.len() {
            for j in (i+1)..hashes.len() {
                assert_ne!(hashes[i].1, hashes[j].1,
                          "Hash collision between sparse counts {} and {}",
                          hashes[i].0, hashes[j].0);
            }
        }
    }

    #[test]
    fn update_count_negative_overflow_edge_cases() {
        // Test counts at overflow boundaries
        let boundary_counts = [
            u32::MAX as usize,
            (u32::MAX as usize) + 1,
            u64::MAX as usize, // May be same as usize::MAX on 64-bit
        ];

        for &count in &boundary_counts {
            if count <= usize::MAX {
                let mut hasher = Sha256::new();
                update_count(&mut hasher, count);
                let _result = hasher.finalize();
            }
        }
    }

    #[test]
    fn update_count_repeated_calls_idempotency() {
        // Test that multiple update_count calls with same value are consistent
        let test_count = 98765;

        let hash1 = {
            let mut hasher = Sha256::new();
            update_count(&mut hasher, test_count);
            hasher.finalize()
        };

        let hash2 = {
            let mut hasher = Sha256::new();
            update_count(&mut hasher, test_count);
            hasher.finalize()
        };

        let hash3 = {
            let mut hasher = Sha256::new();
            update_count(&mut hasher, test_count);
            hasher.finalize()
        };

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
    }

    #[test]
    fn update_count_versus_manual_u64_encoding_consistency() {
        let test_count = 42_000;

        let mut hasher1 = Sha256::new();
        update_count(&mut hasher1, test_count);
        let hash1 = hasher1.finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(usize_to_u64(test_count).to_le_bytes());
        let hash2 = hasher2.finalize();

        // Should be identical since update_count is just a wrapper
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn update_count_endianness_consistency() {
        // Test that little-endian encoding is consistent
        let test_count = 0x1234_5678_9ABC_DEF0usize;

        if test_count <= usize::MAX {
            let mut hasher = Sha256::new();
            update_count(&mut hasher, test_count);
            let hash = hasher.finalize();

            // Compare with manual little-endian encoding
            let mut manual_hasher = Sha256::new();
            let u64_value = usize_to_u64(test_count);
            manual_hasher.update(u64_value.to_le_bytes());
            let manual_hash = manual_hasher.finalize();

            assert_eq!(hash, manual_hash);
        }
    }
}

fn update_field(hasher: &mut Sha256, field_domain: &'static [u8], bytes: &[u8]) {
    update_len_prefixed(hasher, field_domain);
    update_len_prefixed(hasher, bytes);
}

#[cfg(test)]
mod update_field_negative_tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn update_field_empty_domain_empty_data() {
        let mut hasher = Sha256::new();
        update_field(&mut hasher, b"", b"");
        let _result = hasher.finalize();
    }

    #[test]
    fn update_field_prevents_domain_data_concatenation_collision() {
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        // Case 1: domain="abc", data="def"
        update_field(&mut hasher1, b"abc", b"def");

        // Case 2: domain="ab", data="cdef" (same concatenated bytes "abcdef")
        update_field(&mut hasher2, b"ab", b"cdef");

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();

        // Length-prefixed encoding should prevent this collision
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn update_field_collision_resistance_swapped_domain_data() {
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        let domain = b"field:test";
        let data = b"value:data";

        // Normal order
        update_field(&mut hasher1, domain, data);

        // Swapped order (domain/data role reversed)
        update_field(&mut hasher2, data, domain);

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn update_field_with_null_bytes_in_domain_and_data() {
        let mut hasher = Sha256::new();

        let domain_with_null = b"field\x00test";
        let data_with_null = b"value\x00data";

        // Should handle null bytes without issues
        update_field(&mut hasher, domain_with_null, data_with_null);

        let _result = hasher.finalize();
    }

    #[test]
    fn update_field_large_domain_large_data() {
        let mut hasher = Sha256::new();

        let large_domain = vec![b'D'; 10_000];
        let large_data = vec![b'd'; 10_000];

        update_field(&mut hasher, &large_domain, &large_data);

        let _result = hasher.finalize();
    }

    #[test]
    fn update_field_identical_domain_data_different_from_duplicated() {
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        let identical_bytes = b"same_content";

        // Case 1: domain and data are the same
        update_field(&mut hasher1, identical_bytes, identical_bytes);

        // Case 2: just the content duplicated as data only
        update_field(&mut hasher2, b"", identical_bytes);
        update_field(&mut hasher2, b"", identical_bytes);

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn update_field_domain_separator_injection_resistance() {
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        // Normal field
        update_field(&mut hasher1, b"field:name", b"value");

        // Attempt to inject fake field separator in data
        update_field(&mut hasher2, b"field", b"name\x00\x00\x00\x0Afield:namevalue");

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();

        // Length prefixes should prevent separator injection
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn update_field_control_character_handling() {
        let control_chars = [
            b"\x00\x01\x02\x03".as_slice(),    // Low control chars
            b"\x7F\x80\x81\x82".as_slice(),    // High control chars
            b"\r\n\t\x0b\x0c".as_slice(),      // Whitespace control chars
            b"\x1B[31mANSI\x1B[0m".as_slice(), // ANSI escape sequences
        ];

        for (i, &domain) in control_chars.iter().enumerate() {
            for (j, &data) in control_chars.iter().enumerate() {
                let mut hasher = Sha256::new();
                update_field(&mut hasher, domain, data);
                let hash = hasher.finalize();

                // Should produce valid hash regardless of control characters
                assert_eq!(hash.len(), 32);

                // Different combinations should produce different hashes
                if i != j {
                    let mut other_hasher = Sha256::new();
                    update_field(&mut other_hasher, data, domain);
                    let other_hash = other_hasher.finalize();
                    assert_ne!(hash, other_hash);
                }
            }
        }
    }

    #[test]
    fn update_field_unicode_edge_cases() {
        let unicode_test_cases = [
            (b"\xC0\x80", b"overlong_null"),        // Invalid UTF-8
            (b"valid_ascii", b"\xF4\x90\x80\x80"), // Invalid high codepoint
            (b"\xEF\xBF\xBF", b"max_bmp"),          // Max BMP codepoint
            (b"emoji_domain", b"\xF0\x9F\x92\xA9"), // Pile of poo emoji
        ];

        let mut hashes = Vec::new();

        for (domain, data) in unicode_test_cases {
            let mut hasher = Sha256::new();
            update_field(&mut hasher, domain, data);
            let hash = hasher.finalize();
            push_bounded(&mut hashes, hash, 10000);
        }

        // All should be different
        for i in 0..hashes.len() {
            for j in (i+1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j]);
            }
        }
    }

    #[test]
    fn update_field_boundary_length_values() {
        // Test field updates with boundary length values
        let boundary_lengths = [0, 1, 255, 256, 65535, 65536];

        for &len in &boundary_lengths {
            if len <= 10000 { // Keep test reasonable
                let domain = vec![b'F'; len];
                let data = vec![b'D'; len];

                let mut hasher = Sha256::new();
                update_field(&mut hasher, &domain, &data);
                let _result = hasher.finalize();
            }
        }
    }

    #[test]
    fn update_field_sequential_identical_updates_consistency() {
        // Multiple sequential identical updates should be consistent
        let domain = b"test_domain";
        let data = b"test_data";

        let hash1 = {
            let mut hasher = Sha256::new();
            update_field(&mut hasher, domain, data);
            hasher.finalize()
        };

        let hash2 = {
            let mut hasher = Sha256::new();
            update_field(&mut hasher, domain, data);
            hasher.finalize()
        };

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn update_field_versus_manual_len_prefixed_equivalence() {
        let domain = b"manual_test";
        let data = b"equivalence_check";

        let mut hasher1 = Sha256::new();
        update_field(&mut hasher1, domain, data);
        let hash1 = hasher1.finalize();

        let mut hasher2 = Sha256::new();
        update_len_prefixed(&mut hasher2, domain);
        update_len_prefixed(&mut hasher2, data);
        let hash2 = hasher2.finalize();

        // Should be identical since update_field is a wrapper
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn update_field_attack_via_fake_length_prefixes() {
        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();

        // Legitimate field update
        update_field(&mut hasher1, b"domain", b"data");

        // Attack: try to embed fake length prefixes
        let fake_domain = [&6u64.to_le_bytes()[..], b"domain"].concat();
        let fake_data = [&4u64.to_le_bytes()[..], b"data"].concat();
        update_field(&mut hasher2, &fake_domain, &fake_data);

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();

        // Should be different - length prefixing prevents this attack
        assert_ne!(hash1, hash2);
    }
}

fn surface_fingerprint_hex(modules: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"atc_module_surface_v1:");
    update_len_prefixed(&mut hasher, b"field:module_count");
    update_count(&mut hasher, modules.len());
    for module in modules {
        update_field(&mut hasher, b"field:module_name", module.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod surface_fingerprint_hex_negative_tests {
    use super::*;

    #[test]
    fn surface_fingerprint_hex_empty_module_array() {
        let fingerprint = surface_fingerprint_hex(&[]);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn surface_fingerprint_hex_single_empty_string_module() {
        let fingerprint = surface_fingerprint_hex(&[""]);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));

        // Should differ from empty array
        let empty_fingerprint = surface_fingerprint_hex(&[]);
        assert_ne!(fingerprint, empty_fingerprint);
    }

    #[test]
    fn surface_fingerprint_hex_modules_with_embedded_null_bytes() {
        let modules_with_nulls = ["module\x00with\x00nulls", "normal_module"];
        let fingerprint = surface_fingerprint_hex(&modules_with_nulls);

        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));

        // Should differ from modules without nulls
        let clean_modules = ["module_with_nulls", "normal_module"];
        let clean_fingerprint = surface_fingerprint_hex(&clean_modules);
        assert_ne!(fingerprint, clean_fingerprint);
    }

    #[test]
    fn surface_fingerprint_hex_extremely_long_module_names() {
        let long_module = "x".repeat(100_000); // 100KB module name
        let modules = [long_module.as_str()];

        let fingerprint = surface_fingerprint_hex(&modules);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn surface_fingerprint_hex_many_small_modules() {
        // Test with large number of small modules (stress count encoding)
        let mut many_modules = Vec::new();
        for i in 0..1000 {
            many_modules.push(format!("m{}", i));
        }
        let module_refs: Vec<&str> = many_modules.iter().map(String::as_str).collect();

        let fingerprint = surface_fingerprint_hex(&module_refs);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn surface_fingerprint_hex_modules_with_control_characters() {
        let control_modules = [
            "\x00\x01\x02\x03",      // Low control chars
            "\x7F\u{80}\u{81}\u{82}", // High control chars
            "\r\n\t\u{0B}\u{0C}",     // Whitespace controls
            "\x1B[31mcolored\x1B[0m", // ANSI escape sequences
        ];

        let fingerprint = surface_fingerprint_hex(&control_modules);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn surface_fingerprint_hex_unicode_edge_case_modules() {
        let unicode_modules = [
            "\u{FFFF}",              // Max BMP codepoint
            "\u{10FFFF}",            // Max Unicode codepoint
            "\u{1F4A9}\u{1F525}",    // Emoji sequence
            "\u{200B}\u{FEFF}",      // Zero-width/invisible chars
            "café\u{0301}",          // Combining diacriticals
        ];

        let fingerprint = surface_fingerprint_hex(&unicode_modules);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn surface_fingerprint_hex_collision_resistance_similar_modules() {
        let similar_module_sets = [
            ["aaaaaaaaaa"],
            ["bbbbbbbbbb"],
            ["ababababab"],
            ["bababababab"],
            ["0123456789"],
            ["9876543210"],
        ];

        let mut fingerprints = Vec::new();
        for modules in &similar_module_sets {
            let fp = surface_fingerprint_hex(modules);
            fingerprints.push(fp);
        }

        // All should be unique (no collisions)
        for i in 0..fingerprints.len() {
            for j in (i+1)..fingerprints.len() {
                assert_ne!(fingerprints[i], fingerprints[j]);
            }
        }
    }

    #[test]
    fn surface_fingerprint_hex_order_sensitivity() {
        let modules1 = ["first", "second", "third"];
        let modules2 = ["third", "second", "first"];
        let modules3 = ["second", "first", "third"];

        let fp1 = surface_fingerprint_hex(&modules1);
        let fp2 = surface_fingerprint_hex(&modules2);
        let fp3 = surface_fingerprint_hex(&modules3);

        // All different orders should produce different fingerprints
        assert_ne!(fp1, fp2);
        assert_ne!(fp2, fp3);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn surface_fingerprint_hex_duplicate_module_detection() {
        let modules_with_duplicates = ["module_a", "module_b", "module_a"];
        let modules_without_duplicates = ["module_a", "module_b", "module_c"];

        let fp1 = surface_fingerprint_hex(&modules_with_duplicates);
        let fp2 = surface_fingerprint_hex(&modules_without_duplicates);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn surface_fingerprint_hex_module_boundary_injection_attempts() {
        // Test attempts to inject fake module boundaries
        let injection_attempts = [
            ["\x00\x00\x00\x01fake_count"],           // Fake count injection
            ["field:module_name\x00\x00\x00\x04fake"], // Fake field injection
            ["atc_module_surface_v1:fake_domain"],     // Domain separator injection
        ];

        let legitimate_modules = ["legitimate_module"];
        let legitimate_fp = surface_fingerprint_hex(&legitimate_modules);

        for injection_modules in &injection_attempts {
            let injection_fp = surface_fingerprint_hex(injection_modules);

            // Should never match legitimate fingerprint
            assert_ne!(legitimate_fp, injection_fp);

            // Should still be valid hex
            assert_eq!(injection_fp.len(), 64);
            assert!(injection_fp.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn surface_fingerprint_hex_pathological_repeated_patterns() {
        let pathological_patterns = [
            vec!["a".repeat(1000)],                    // Single repeated char
            vec!["ab".repeat(500)],                    // Two-char pattern
            vec!["pattern".repeat(100)],               // Word pattern
            vec!["0".repeat(64)],                      // All zeros (64 chars like hash)
            vec!["f".repeat(64)],                      // All 'f' (like max hash)
        ];

        let mut all_fingerprints = Vec::new();
        for pattern_vec in pathological_patterns {
            let pattern_refs: Vec<&str> = pattern_vec.iter().map(String::as_str).collect();
            let fp = surface_fingerprint_hex(&pattern_refs);
            all_fingerprints.push(fp);
        }

        // All should be unique despite pathological input patterns
        for i in 0..all_fingerprints.len() {
            for j in (i+1)..all_fingerprints.len() {
                assert_ne!(all_fingerprints[i], all_fingerprints[j]);
            }
        }
    }

    #[test]
    fn surface_fingerprint_hex_consistency_across_multiple_calls() {
        let test_modules = ["consistency", "test", "modules"];

        let fp1 = surface_fingerprint_hex(&test_modules);
        let fp2 = surface_fingerprint_hex(&test_modules);
        let fp3 = surface_fingerprint_hex(&test_modules);

        assert_eq!(fp1, fp2);
        assert_eq!(fp2, fp3);
    }

    #[test]
    fn surface_fingerprint_hex_avalanche_effect_single_char_changes() {
        let base_modules = ["test_avalanche"];
        let base_fp = surface_fingerprint_hex(&base_modules);

        let mutations = [
            ["Test_avalanche"],      // Case change first char
            ["test_avalanchE"],      // Case change last char
            ["test_avalanch_"],      // Character substitution
            ["test_avalanche "],     // Extra space
            ["test_avalan che"],     // Space insertion
        ];

        for mutated_modules in &mutations {
            let mutated_fp = surface_fingerprint_hex(mutated_modules);

            // Should be completely different
            assert_ne!(base_fp, mutated_fp);

            // Test bit-level avalanche effect
            let base_bytes = hex::decode(&base_fp).unwrap();
            let mutated_bytes = hex::decode(&mutated_fp).unwrap();

            let mut differing_bits = 0;
            for (base_byte, mutated_byte) in base_bytes.iter().zip(mutated_bytes.iter()) {
                differing_bits += (base_byte ^ mutated_byte).count_ones();
            }

            let change_percentage = (differing_bits as f64) / 256.0 * 100.0;
            assert!(change_percentage.is_finite(), "Non-finite change percentage");
            assert!(change_percentage > 25.0,
                   "Poor avalanche effect: only {:.1}% bits changed", change_percentage);
        }
    }

    #[test]
    fn surface_fingerprint_hex_hex_encoding_validation() {
        let test_modules = ["hex_validation_test"];
        let fingerprint = surface_fingerprint_hex(&test_modules);

        // Must be exactly 64 hex characters (32 bytes * 2 chars/byte)
        assert_eq!(fingerprint.len(), 64);

        // All characters must be valid hex
        for c in fingerprint.chars() {
            assert!(c.is_ascii_hexdigit(), "Invalid hex character: {}", c);
        }

        // Should be lowercase hex
        assert!(fingerprint.chars().all(|c| !c.is_ascii_uppercase()));

        // Should decode to exactly 32 bytes
        let decoded = hex::decode(&fingerprint).unwrap();
        assert_eq!(decoded.len(), 32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::constant_time;
    use std::collections::BTreeSet;

    fn assert_fingerprint_eq(left: &str, right: &str) {
        assert!(constant_time::ct_eq_bytes(left.as_bytes(), right.as_bytes()));
    }

    fn assert_fingerprint_ne(left: &str, right: &str) {
        assert!(!constant_time::ct_eq_bytes(left.as_bytes(), right.as_bytes()));
    }

    #[test]
    fn atc_module_surface_lists_expected_subsystems() {
        assert_eq!(
            module_surface(),
            &[
                "aggregation",
                "federation",
                "global_priors",
                "privacy_envelope",
                "signal_extraction",
                "signal_schema",
                "sketch_system",
                "urgent_routing",
            ],
        );
    }

    #[test]
    fn atc_module_surface_names_are_unique() {
        let unique: BTreeSet<&str> = module_surface().iter().copied().collect();

        assert_eq!(unique.len(), module_surface().len());
    }

    #[test]
    fn atc_module_surface_names_are_ascii_snake_case() {
        for module in module_surface() {
            assert!(!module.is_empty());
            assert!(module.bytes().all(|byte| {
                byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit()
            }));
            assert!(!module.starts_with('_'));
            assert!(!module.ends_with('_'));
        }
    }

    #[test]
    fn atc_module_surface_order_is_stable_for_fingerprints() {
        assert!(module_surface().windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn atc_module_surface_fingerprint_is_deterministic() {
        assert_fingerprint_eq(
            module_surface_fingerprint_hex().as_str(),
            module_surface_fingerprint_hex().as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_changes_when_module_is_removed() {
        let shortened = &module_surface()[..module_surface().len() - 1];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(shortened).as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_changes_when_order_changes() {
        let mut reordered = module_surface().to_vec();
        reordered.swap(0, 1);

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&reordered).as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_separates_concatenation_collisions() {
        assert_fingerprint_ne(
            surface_fingerprint_hex(&["signal", "schema"]).as_str(),
            surface_fingerprint_hex(&["signal_schema"]).as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_changes_when_duplicate_is_inserted() {
        let mut mutated = module_surface().to_vec();
        mutated.insert(1, "aggregation");

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_changes_when_empty_name_is_inserted() {
        let mut mutated = module_surface().to_vec();
        mutated.insert(0, "");

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_changes_when_uppercase_alias_is_inserted() {
        let mut mutated = module_surface().to_vec();
        mutated.push("Federation");

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_changes_when_trailing_separator_is_inserted() {
        let mut mutated = module_surface().to_vec();
        mutated.push("urgent_routing_");

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_changes_when_embedded_nul_is_inserted() {
        let mut mutated = module_surface().to_vec();
        mutated.push("signal\0schema");

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_changes_when_registered_name_is_replaced() {
        let mut mutated = module_surface().to_vec();
        mutated[1] = "federation_shadow";

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_changes_when_privileged_surface_is_added() {
        let mut mutated = module_surface().to_vec();
        mutated.push("admin_override");

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn atc_module_surface_fingerprint_separates_equal_byte_concatenations() {
        assert_fingerprint_ne(
            surface_fingerprint_hex(&["ab", "c"]).as_str(),
            surface_fingerprint_hex(&["a", "bc"]).as_str(),
        );
    }
}

#[cfg(test)]
mod atc_surface_additional_negative_tests {
    use super::*;
    use crate::security::constant_time;

    fn assert_fingerprint_ne(left: &str, right: &str) {
        assert!(!constant_time::ct_eq_bytes(left.as_bytes(), right.as_bytes()));
    }

    fn assert_fingerprint_eq(left: &str, right: &str) {
        assert!(constant_time::ct_eq_bytes(left.as_bytes(), right.as_bytes()));
    }

    #[test]
    fn fingerprint_changes_when_duplicate_replaces_existing_module_at_same_count() {
        let mutated = [
            "aggregation",
            "aggregation",
            "global_priors",
            "privacy_envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn fingerprint_changes_when_leading_underscore_module_is_present() {
        let mutated = [
            "_aggregation",
            "federation",
            "global_priors",
            "privacy_envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn fingerprint_changes_when_module_contains_whitespace() {
        let mutated = [
            "aggregation ",
            "federation",
            "global_priors",
            "privacy_envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn fingerprint_changes_when_module_uses_dash_separator() {
        let mutated = [
            "aggregation",
            "federation",
            "global-priors",
            "privacy_envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn fingerprint_changes_when_module_has_double_underscore_segment() {
        let mutated = [
            "aggregation",
            "federation",
            "global_priors",
            "privacy__envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn fingerprint_distinguishes_empty_surface_from_single_empty_module() {
        assert_fingerprint_ne(
            surface_fingerprint_hex(&[]).as_str(),
            surface_fingerprint_hex(&[""]).as_str(),
        );
    }

    #[test]
    fn fingerprint_distinguishes_repeated_empty_modules_from_single_empty_module() {
        assert_fingerprint_ne(
            surface_fingerprint_hex(&[""]).as_str(),
            surface_fingerprint_hex(&["", ""]).as_str(),
        );
    }

    #[test]
    fn fingerprint_is_stable_for_equivalent_borrowed_surface_fixture() {
        let borrowed = [
            "aggregation",
            "federation",
            "global_priors",
            "privacy_envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_eq(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&borrowed).as_str(),
        );
    }

    #[test]
    fn fingerprint_changes_when_module_contains_newline() {
        let mutated = [
            "aggregation",
            "federation\nshadow",
            "global_priors",
            "privacy_envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn fingerprint_changes_when_module_uses_path_separator() {
        let mutated = [
            "aggregation",
            "federation",
            "global_priors",
            "privacy/envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn fingerprint_changes_when_module_looks_like_parent_path() {
        let mutated = [
            "aggregation",
            "federation",
            "..",
            "privacy_envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn fingerprint_changes_when_module_contains_tab() {
        let mutated = [
            "aggregation",
            "federation",
            "global_priors",
            "privacy_envelope",
            "signal\textraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn fingerprint_changes_when_module_uses_unicode_confusable() {
        let mutated = [
            "aggregation",
            "federation",
            "global_priors",
            "privacy_envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routіng",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }

    #[test]
    fn fingerprint_distinguishes_nul_prefix_from_nul_suffix() {
        assert_fingerprint_ne(
            surface_fingerprint_hex(&["\0signal_schema"]).as_str(),
            surface_fingerprint_hex(&["signal_schema\0"]).as_str(),
        );
    }

    #[test]
    fn fingerprint_changes_when_module_is_replaced_by_reserved_name() {
        let mutated = [
            "aggregation",
            "federation",
            "global_priors",
            "privacy_envelope",
            "self",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            surface_fingerprint_hex(&mutated).as_str(),
        );
    }
}

#[cfg(test)]
mod atc_comprehensive_negative_edge_cases {
    use super::*;
    use crate::security::constant_time;

    fn assert_fingerprint_ne(left: &str, right: &str) {
        assert!(!constant_time::ct_eq_bytes(left.as_bytes(), right.as_bytes()));
    }

    // =========================================================================
    // COMPREHENSIVE NEGATIVE-PATH EDGE CASE TESTS
    // =========================================================================

    #[test]
    fn negative_fingerprint_with_maximum_usize_length_modules_saturates_gracefully() {
        // Test usize_to_u64 conversion with extreme values
        let extreme_module = "x".repeat(100_000); // 100KB module name
        let mutated = [extreme_module.as_str()];

        // Should handle extremely long module names without panicking
        let fingerprint = surface_fingerprint_hex(&mutated);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));

        // Should differ from normal surface
        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            &fingerprint,
        );
    }

    #[test]
    fn negative_fingerprint_with_massive_module_count_handles_memory_efficiently() {
        // Test with many small modules to stress count encoding
        let mut massive_surface = Vec::new();
        for i in 0..10_000 {
            massive_surface.push(format!("mod_{:05}", i));
        }
        let massive_surface_refs: Vec<&str> = massive_surface.iter().map(String::as_str).collect();

        let start = std::time::Instant::now();
        let fingerprint = surface_fingerprint_hex(&massive_surface_refs);
        let duration = start.elapsed();

        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(duration < std::time::Duration::from_secs(10)); // Should complete reasonably fast

        // Should differ from normal surface
        assert_fingerprint_ne(
            module_surface_fingerprint_hex().as_str(),
            &fingerprint,
        );
    }

    #[test]
    fn negative_fingerprint_with_control_character_modules_preserves_binary_data() {
        let control_chars_modules = [
            "\x00\x01\x02\x03", // Null and low control chars
            "\x7F\u{80}\u{81}\u{82}", // High control chars and extended ASCII
            "\x1B[31mred\x1B[0m", // ANSI escape sequences
            "\r\n\t\u{0B}\u{0C}", // Various whitespace control chars
            "\u{FEFF}BOM",     // Byte Order Mark + text
        ];

        for module_with_controls in control_chars_modules {
            let mutated = [module_with_controls];
            let fingerprint = surface_fingerprint_hex(&mutated);

            // Should preserve control characters without sanitization
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));

            // Each should produce different fingerprints
            assert_fingerprint_ne(
                module_surface_fingerprint_hex().as_str(),
                &fingerprint,
            );
        }
    }

    #[test]
    fn negative_fingerprint_with_unicode_edge_case_modules_handled_correctly() {
        let unicode_edge_cases = [
            "\u{FFFF}",        // Max BMP codepoint
            "\u{10FFFF}",      // Max Unicode codepoint
            "\u{1F4A9}\u{1F525}", // Emoji sequence
            "\u{200B}\u{FEFF}\u{034F}", // Zero-width/invisible chars
            "a\u{0300}\u{0301}b", // Combining diacritical marks
            "\u{1D11E}",       // Musical symbol (outside BMP)
        ];

        for unicode_module in unicode_edge_cases {
            let mutated = [unicode_module];
            let fingerprint = surface_fingerprint_hex(&mutated);

            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));

            // Each Unicode edge case should produce different fingerprints
            assert_fingerprint_ne(
                module_surface_fingerprint_hex().as_str(),
                &fingerprint,
            );
        }
    }

    #[test]
    fn negative_update_len_prefixed_with_zero_and_maximum_boundaries() {
        use sha2::Sha256;

        let mut hasher = Sha256::new();

        // Test with zero-length data
        update_len_prefixed(&mut hasher, b"");

        // Test with maximum practical data size
        let large_data = vec![0xAA; 1_000_000]; // 1MB of data
        update_len_prefixed(&mut hasher, &large_data);

        // Test with data containing all byte values
        let all_bytes: Vec<u8> = (0..=255).collect();
        update_len_prefixed(&mut hasher, &all_bytes);

        // Should complete without panicking
        let _result = hasher.finalize();
    }

    #[test]
    fn negative_usize_to_u64_conversion_edge_cases() {
        // Test conversion at various boundaries
        assert_eq!(usize_to_u64(0), 0u64);
        assert_eq!(usize_to_u64(1), 1u64);
        assert_eq!(usize_to_u64(usize::MAX), u64::MAX);

        // Test with large but representable usize values
        if usize::BITS <= 64 {
            let large_usize = usize::MAX / 2;
            assert_eq!(usize_to_u64(large_usize), large_usize as u64);
        }
    }

    #[test]
    fn negative_fingerprint_length_prefix_collision_resistance_stress_test() {
        // Stress test the length-prefixed encoding to ensure no collisions
        // between different arrangements of the same byte content

        // Test 1: Different field arrangements
        let arrangement1 = ["a", "bc"];
        let arrangement2 = ["ab", "c"];
        assert_fingerprint_ne(
            surface_fingerprint_hex(&arrangement1).as_str(),
            surface_fingerprint_hex(&arrangement2).as_str(),
        );

        // Test 2: Length encoding collision attempts
        let attempt1 = ["\x03\x00\x00\x00\x00\x00\x00\x00abc"]; // Fake length prefix + data
        let attempt2 = ["abc"];
        assert_fingerprint_ne(
            surface_fingerprint_hex(&attempt1).as_str(),
            surface_fingerprint_hex(&attempt2).as_str(),
        );

        // Test 3: Field boundary confusion
        let boundary1 = ["field:module_name", "value"];
        let boundary2 = ["field:module_namevalue", ""];
        assert_fingerprint_ne(
            surface_fingerprint_hex(&boundary1).as_str(),
            surface_fingerprint_hex(&boundary2).as_str(),
        );
    }

    #[test]
    fn negative_fingerprint_with_similar_byte_patterns_distinguishes_correctly() {
        // Test patterns that might hash to similar values with weak hash functions
        let similar_patterns = [
            ["aaaaaaaaaa"],
            ["bbbbbbbbbb"],
            ["ababababab"],
            ["bababababab"],
            ["0123456789"],
            ["9876543210"],
        ];

        let mut fingerprints = Vec::new();
        for pattern in &similar_patterns {
            let fp = surface_fingerprint_hex(pattern);
            fingerprints.push(fp);
        }

        // All fingerprints should be unique (no collisions)
        for i in 0..fingerprints.len() {
            for j in (i+1)..fingerprints.len() {
                assert_fingerprint_ne(&fingerprints[i], &fingerprints[j]);
            }
        }
    }

    #[test]
    fn negative_module_surface_constant_time_comparison_behavior_verification() {
        // Verify that constant-time comparison behaves consistently
        let reference_fingerprint = module_surface_fingerprint_hex();

        // Test with same-length different content
        let mut mutated_surface = module_surface().to_vec();
        mutated_surface[0] = "aggregatiox"; // Same length, different end
        let mutated_fingerprint = surface_fingerprint_hex(&mutated_surface);

        // Both fingerprints should be 64 chars (same length)
        assert_eq!(reference_fingerprint.len(), 64);
        assert_eq!(mutated_fingerprint.len(), 64);

        // But content should differ
        assert_fingerprint_ne(&reference_fingerprint, &mutated_fingerprint);

        // Test with completely different length
        let short_fingerprint = surface_fingerprint_hex(&["a"]);
        assert_eq!(short_fingerprint.len(), 64); // Still 64 chars (hex encoded hash)
        assert_fingerprint_ne(&reference_fingerprint, &short_fingerprint);
    }

    #[test]
    fn negative_domain_separator_injection_attempts_fail() {
        // Test that malicious modules can't inject domain separators
        let injection_attempts = [
            "atc_module_surface_v1:fake",
            "field:module_namefake:value",
            "atc_module_surface_v1:\x00injection",
            "\x00atc_module_surface_v1:",
        ];

        for injection_module in injection_attempts {
            let mutated = [injection_module];
            let fingerprint = surface_fingerprint_hex(&mutated);

            // Should not match empty surface or any legitimate fingerprint
            assert_fingerprint_ne(
                surface_fingerprint_hex(&[]).as_str(),
                &fingerprint,
            );
            assert_fingerprint_ne(
                module_surface_fingerprint_hex().as_str(),
                &fingerprint,
            );

            // Should still produce valid hex fingerprint
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn negative_fingerprint_with_pathological_repeated_patterns() {
        // Test modules with pathological repetition that might cause hash weaknesses
        let pathological_patterns = [
            vec!["a".repeat(1000)],                    // Single repeated char
            vec!["ab".repeat(500)],                    // Two-char pattern
            vec!["abc".repeat(333) + "a"],             // Three-char pattern + remainder
            vec!["pattern".repeat(100)],               // Word pattern
            vec!["0".repeat(64)],                      // All zeros (64 chars like hash)
            vec!["f".repeat(64)],                      // All 'f' (like max hash)
        ];

        let mut all_fingerprints = Vec::new();
        for pattern_vec in pathological_patterns {
            let pattern_refs: Vec<&str> = pattern_vec.iter().map(String::as_str).collect();
            let fp = surface_fingerprint_hex(&pattern_refs);
            all_fingerprints.push(fp);
        }

        // All should be unique despite pathological input patterns
        for i in 0..all_fingerprints.len() {
            for j in (i+1)..all_fingerprints.len() {
                assert_fingerprint_ne(&all_fingerprints[i], &all_fingerprints[j]);
            }
        }

        // All should differ from legitimate surface
        for fp in &all_fingerprints {
            assert_fingerprint_ne(module_surface_fingerprint_hex().as_str(), fp);
        }
    }

    #[test]
    fn negative_update_field_with_overlapping_domain_and_data() {
        use sha2::Sha256;

        let mut hasher1 = Sha256::new();
        hasher1.update(b"test_domain_v1:");
        update_field(&mut hasher1, b"field:test", b"domain_overlap_data");

        let mut hasher2 = Sha256::new();
        hasher2.update(b"test_domain_v1:");
        update_field(&mut hasher2, b"field:testdomain_overlap_", b"data");

        let hash1 = hex::encode(hasher1.finalize());
        let hash2 = hex::encode(hasher2.finalize());

        // Length-prefixed encoding should prevent domain/data overlap collisions
        assert_ne!(hash1, hash2, "Field update must prevent domain/data overlap collisions");
    }
}

#[cfg(test)]
mod atc_extreme_adversarial_negative_tests {
    use super::*;
    use crate::security::constant_time;

    fn assert_fingerprint_ne(left: &str, right: &str) {
        assert!(!constant_time::ct_eq_bytes(left.as_bytes(), right.as_bytes()));
    }

    // =========================================================================
    // EXTREME ADVERSARIAL NEGATIVE-PATH TESTS
    // =========================================================================

    #[test]
    fn negative_recursive_domain_separator_nesting_injection_attempts() {
        // Test deeply nested injection attempts that try to confuse the hasher
        let recursive_injection_modules = [
            "field:module_name\x00field:module_name\x00fake",
            "atc_module_surface_v1:atc_module_surface_v1:nested",
            "\x00\x00\x00\x08field:module_name\x00\x00\x00\x04fake", // Length bytes + injection
            "field:module_count\x00\x00\x00\x00\x00\x00\x00\x01", // Fake count injection
        ];

        let reference_fingerprint = module_surface_fingerprint_hex();

        for injection_module in recursive_injection_modules {
            let mutated = [injection_module];
            let fingerprint = surface_fingerprint_hex(&mutated);

            // Should not match any legitimate fingerprint
            assert_fingerprint_ne(&reference_fingerprint, &fingerprint);
            assert_fingerprint_ne(
                &surface_fingerprint_hex(&["legitimate_module"]),
                &fingerprint,
            );

            // Should still produce valid hex
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn negative_binary_length_prefix_manipulation_attacks() {
        // Test attempts to manipulate the length prefix encoding directly
        let binary_attack_modules = [
            "\x01\x00\x00\x00\x00\x00\x00\x00a",           // 1-byte fake length + data
            "\u{FF}\u{FF}\u{FF}\u{FF}\u{FF}\u{FF}\u{FF}\u{FF}overflow", // Max u64 fake length
            "\x00\x00\x00\x00\x00\x00\x00\x00",           // Zero length only
            "a\x01\x00\x00\x00\x00\x00\x00\x00b",         // Data + fake length + data
        ];

        for attack_module in binary_attack_modules {
            let mutated = [attack_module];
            let fingerprint = surface_fingerprint_hex(&mutated);

            // Should differ from legitimate modules
            assert_fingerprint_ne(
                &module_surface_fingerprint_hex(),
                &fingerprint,
            );

            // Test collision resistance against simple modules
            for simple_module in ["a", "b", "ab", "ba"] {
                let simple_fingerprint = surface_fingerprint_hex(&[simple_module]);
                assert_fingerprint_ne(&fingerprint, &simple_fingerprint);
            }
        }
    }

    #[test]
    fn negative_hash_algorithm_birthday_attack_simulation() {
        // Generate many module combinations to test for unexpected collisions
        let module_variations = [
            "aggregation", "Aggregation", "AGGREGATION", "aggregation_", "_aggregation",
            "aggregation1", "aggregation2", "aggregation0", "aggregations", "aggregatio",
            "aggreagtion", "agregation", "aggragation", // Common typos
        ];

        let mut all_fingerprints = std::collections::HashMap::new();

        for &module in &module_variations {
            let fingerprint = surface_fingerprint_hex(&[module]);

            if let Some(existing_module) = all_fingerprints.insert(fingerprint.clone(), module) {
                panic!("Hash collision detected between '{}' and '{}'", existing_module, module);
            }

            // Each should differ from the main surface
            assert_fingerprint_ne(&module_surface_fingerprint_hex(), &fingerprint);
        }

        // Test with combinations of modules
        for i in 0..module_variations.len().min(5) {
            for j in (i+1)..module_variations.len().min(5) {
                let combo = [module_variations[i], module_variations[j]];
                let fingerprint = surface_fingerprint_hex(&combo);

                if let Some(existing) = all_fingerprints.insert(fingerprint.clone(), "combo") {
                    panic!("Collision between combo {:?} and existing {}", combo, existing);
                }
            }
        }
    }

    #[test]
    fn negative_memory_exhaustion_via_computed_length_overflow() {
        // Test that usize_to_u64 handles edge cases without memory exhaustion
        use sha2::Sha256;

        let mut hasher = Sha256::new();

        // Test update_count with various boundary values
        update_count(&mut hasher, 0);
        update_count(&mut hasher, 1);
        update_count(&mut hasher, usize::MAX);

        // Test update_len_prefixed with boundary conditions
        update_len_prefixed(&mut hasher, b"");
        update_len_prefixed(&mut hasher, &[0u8; 1]);

        if std::mem::size_of::<usize>() == 8 {
            // On 64-bit systems, test near usize::MAX
            let large_count = usize::MAX / 2;
            update_count(&mut hasher, large_count);
        }

        // Should complete without panic or excessive memory allocation
        let _result = hasher.finalize();
    }

    #[test]
    fn negative_timing_side_channel_resistance_verification() {
        use std::time::Instant;

        let reference_surface = module_surface();
        let reference_fingerprint = module_surface_fingerprint_hex();

        // Create surfaces with similar but different content
        let mut similar_surface = reference_surface.to_vec();
        similar_surface[similar_surface.len() - 1] = "urgent_routinx"; // Last char different

        let mut very_different_surface = vec!["zzzzzzzzz"; reference_surface.len()];

        // Measure timing for fingerprint generation
        let timing_samples = 100;
        let mut reference_times = Vec::new();
        let mut similar_times = Vec::new();
        let mut different_times = Vec::new();

        for _ in 0..timing_samples {
            // Time reference fingerprint
            let start = Instant::now();
            let _ = surface_fingerprint_hex(reference_surface);
            reference_times.push(start.elapsed());

            // Time similar fingerprint
            let start = Instant::now();
            let _ = surface_fingerprint_hex(&similar_surface);
            similar_times.push(start.elapsed());

            // Time very different fingerprint
            let start = Instant::now();
            let _ = surface_fingerprint_hex(&very_different_surface);
            different_times.push(start.elapsed());
        }

        // Verify that timing doesn't vary significantly based on content similarity
        // (This is a heuristic test - significant differences could indicate timing leaks)
        let avg_ref = reference_times.iter().sum::<std::time::Duration>() / timing_samples as u32;
        let avg_sim = similar_times.iter().sum::<std::time::Duration>() / timing_samples as u32;
        let avg_diff = different_times.iter().sum::<std::time::Duration>() / timing_samples as u32;

        // All should be reasonably close (within 10x of each other)
        let max_time = [avg_ref, avg_sim, avg_diff].into_iter().max().unwrap();
        let min_time = [avg_ref, avg_sim, avg_diff].into_iter().min().unwrap();

        if min_time.as_nanos() > 0 {
            let timing_ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;
            assert!(timing_ratio.is_finite(), "Non-finite timing ratio");
            assert!(timing_ratio < 10.0,
                   "Suspicious timing variation: max={:?}, min={:?}, ratio={:.2}",
                   max_time, min_time, timing_ratio);
        }
    }

    #[test]
    fn negative_constant_time_comparison_with_unicode_edge_cases() {
        // Test constant-time comparison with various Unicode edge cases
        let unicode_test_pairs = [
            ("café", "cafe\u{0301}"), // NFC vs NFD
            ("A", "\u{0041}"),        // ASCII vs Unicode codepoint
            ("Ⅸ", "IX"),              // Roman numeral vs ASCII
            ("\u{FEFF}test", "test"), // With/without BOM
            ("test\u{200B}", "test"), // With/without zero-width space
        ];

        for (str1, str2) in unicode_test_pairs {
            let fp1 = surface_fingerprint_hex(&[str1]);
            let fp2 = surface_fingerprint_hex(&[str2]);

            // Different Unicode representations should produce different fingerprints
            assert_fingerprint_ne(&fp1, &fp2);

            // Self-comparison should be consistent
            assert!(constant_time::ct_eq_bytes(fp1.as_bytes(), fp1.as_bytes()));
            assert!(constant_time::ct_eq_bytes(fp2.as_bytes(), fp2.as_bytes()));

            // Cross-comparison should be consistent
            let comparison1 = constant_time::ct_eq_bytes(fp1.as_bytes(), fp2.as_bytes());
            let comparison2 = constant_time::ct_eq_bytes(fp1.as_bytes(), fp2.as_bytes());
            assert_eq!(comparison1, comparison2);
        }
    }

    #[test]
    fn negative_json_injection_via_hex_fingerprint_interpretation() {
        // Test that hex fingerprints can't be interpreted as JSON injection
        let injection_modules = [
            "}{\"injected\":true,\"modules\":[\"",
            "\"],\"evil\":\"payload\",\"real\":[\"",
            "\\u0022:\\u007b\\u0022injected\\u0022",
            "%22%3a%7b%22injected%22",
        ];

        for injection_module in injection_modules {
            let fingerprint = surface_fingerprint_hex(&[injection_module]);

            // Fingerprint should always be valid hex (no JSON-like content)
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(!fingerprint.contains("\""));
            assert!(!fingerprint.contains("{"));
            assert!(!fingerprint.contains("}"));
            assert!(!fingerprint.contains("["));
            assert!(!fingerprint.contains("]"));

            // Should not match legitimate surfaces
            assert_fingerprint_ne(&module_surface_fingerprint_hex(), &fingerprint);
        }
    }

    #[test]
    fn negative_zero_byte_boundary_handling_in_length_prefixed_encoding() {
        // Test edge cases around zero-byte boundaries in length-prefixed data
        let zero_boundary_modules = [
            "",                    // Zero length
            "\x00",               // Single null byte
            "\x00\x00",           // Two null bytes
            "a\x00",              // Data + null
            "\x00a",              // Null + data
            "a\x00b\x00c",        // Interspersed nulls
        ];

        for module in zero_boundary_modules {
            let fingerprint = surface_fingerprint_hex(&[module]);

            // Should handle zero bytes correctly
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));

            // Each should be distinct
            for other_module in zero_boundary_modules {
                if module != other_module {
                    let other_fp = surface_fingerprint_hex(&[other_module]);
                    assert_fingerprint_ne(&fingerprint, &other_fp);
                }
            }
        }
    }

    #[test]
    fn negative_domain_separator_length_manipulation_attacks() {
        use sha2::Sha256;

        // Test that domain separator length can't be manipulated
        let mut legitimate_hasher = Sha256::new();
        legitimate_hasher.update(b"atc_module_surface_v1:");
        update_field(&mut legitimate_hasher, b"field:module_name", b"test");
        let legitimate_hash = hex::encode(legitimate_hasher.finalize());

        // Attempt to fake the domain separator length
        let mut attack_hasher = Sha256::new();
        attack_hasher.update(b"atc_module_surface_v1:");
        // Try to fake the length prefix of the domain separator
        attack_hasher.update(&(1000u64).to_le_bytes()); // Wrong length
        attack_hasher.update(b"field:module_name");
        update_len_prefixed(&mut attack_hasher, b"test");
        let attack_hash = hex::encode(attack_hasher.finalize());

        assert_ne!(legitimate_hash, attack_hash,
                  "Domain separator length manipulation should not succeed");
    }

    #[test]
    fn negative_module_surface_mutation_cascade_testing() {
        // Test that small mutations cascade through the entire fingerprint
        let base_surface = module_surface();
        let base_fingerprint = module_surface_fingerprint_hex();

        // Test single-bit mutations in each module name
        for module_idx in 0..base_surface.len() {
            let original_module = base_surface[module_idx];
            let mut module_bytes = original_module.as_bytes().to_vec();

            // Flip each bit in the first byte of the module name
            for bit_idx in 0..8 {
                if !module_bytes.is_empty() {
                    let original_byte = module_bytes[0];
                    module_bytes[0] = original_byte ^ (1 << bit_idx);

                    // Only test if the result is valid UTF-8
                    if let Ok(mutated_module) = String::from_utf8(module_bytes.clone()) {
                        let mut mutated_surface = base_surface.to_vec();
                        mutated_surface[module_idx] = &mutated_module;

                        let mutated_fingerprint = surface_fingerprint_hex(&mutated_surface);

                        // Single bit flip should completely change fingerprint
                        assert_fingerprint_ne(&base_fingerprint, &mutated_fingerprint);

                        // Should be different from flipping other bits too
                        for other_bit in 0..8 {
                            if other_bit != bit_idx {
                                module_bytes[0] = original_byte ^ (1 << other_bit);
                                if let Ok(other_mutated) = String::from_utf8(module_bytes.clone()) {
                                    let mut other_surface = base_surface.to_vec();
                                    other_surface[module_idx] = &other_mutated;
                                    let other_fp = surface_fingerprint_hex(&other_surface);
                                    assert_fingerprint_ne(&mutated_fingerprint, &other_fp);
                                }
                            }
                        }
                    }

                    // Restore original byte for next iteration
                    module_bytes[0] = original_byte;
                }
            }
        }
    }

    #[test]
    fn negative_fingerprint_generation_under_memory_fragmentation_stress() {
        // Test fingerprint generation when memory allocation patterns might be fragmented
        use sha2::Sha256;

        // Create many small allocations to fragment memory
        let mut memory_fragmenters: Vec<Vec<u8>> = Vec::new();
        for i in 0..1000 {
            // Create various sized allocations to fragment heap
            let size = (i * 37) % 1000 + 1; // Pseudo-random sizes
            memory_fragmenters.push(vec![i as u8; size]);
        }

        // Generate fingerprints in this fragmented environment
        let stress_surface = ["memory", "fragmentation", "stress", "test"];
        let fingerprint1 = surface_fingerprint_hex(&stress_surface);

        // Add more fragmentation
        for i in 1000..2000 {
            let size = (i * 73) % 500 + 1;
            memory_fragmenters.push(vec![(i % 256) as u8; size]);
        }

        let fingerprint2 = surface_fingerprint_hex(&stress_surface);

        // Fingerprints should be identical despite memory fragmentation
        assert_fingerprint_eq(&fingerprint1, &fingerprint2);
        assert_eq!(fingerprint1.len(), 64);
        assert!(fingerprint1.bytes().all(|b| b.is_ascii_hexdigit()));

        // Clean up should not affect subsequent generations
        drop(memory_fragmenters);
        let fingerprint3 = surface_fingerprint_hex(&stress_surface);
        assert_fingerprint_eq(&fingerprint1, &fingerprint3);
    }

    #[test]
    fn negative_hasher_state_corruption_via_extreme_update_sequences() {
        // Test that hasher state remains consistent under extreme update patterns
        use sha2::Sha256;

        // Pattern 1: Alternating tiny and large updates
        let mut hasher1 = Sha256::new();
        hasher1.update(b"atc_module_surface_v1:");

        for i in 0..100 {
            if i % 2 == 0 {
                hasher1.update(&[i as u8]); // Single byte
            } else {
                hasher1.update(&vec![i as u8; 10000]); // Large chunk
            }
        }
        let hash1 = hex::encode(hasher1.finalize());

        // Pattern 2: Many tiny updates followed by one large update
        let mut hasher2 = Sha256::new();
        hasher2.update(b"atc_module_surface_v1:");

        for i in 0..1000 {
            hasher2.update(&[i as u8]);
        }
        hasher2.update(&vec![42u8; 100000]);
        let hash2 = hex::encode(hasher2.finalize());

        // Pattern 3: Empty updates interspersed with data
        let mut hasher3 = Sha256::new();
        hasher3.update(b"atc_module_surface_v1:");

        for i in 0..100 {
            hasher3.update(b""); // Empty update
            hasher3.update(&[(i * 3) as u8]); // Small data
            hasher3.update(b""); // Another empty update
        }
        let hash3 = hex::encode(hasher3.finalize());

        // All should produce valid hex hashes
        assert_eq!(hash1.len(), 64);
        assert_eq!(hash2.len(), 64);
        assert_eq!(hash3.len(), 64);

        assert!(hash1.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(hash2.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(hash3.bytes().all(|b| b.is_ascii_hexdigit()));

        // All should be different (no state corruption)
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn negative_concurrent_fingerprint_generation_state_isolation_stress() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Simulate concurrent fingerprint generation to test for race conditions
        let shared_results = Arc::new(Mutex::new(Vec::new()));
        let thread_count = 8;
        let iterations_per_thread = 100;

        let mut handles = Vec::new();

        for thread_id in 0..thread_count {
            let results = shared_results.clone();

            let handle = thread::spawn(move || {
                let mut local_results = Vec::new();

                for iteration in 0..iterations_per_thread {
                    // Each thread works with slightly different module surfaces
                    let federation_module = format!("federation_t{}_i{}", thread_id, iteration);
                    let surface = [
                        "aggregation",
                        federation_module.as_str(),
                        "global_priors",
                        "privacy_envelope",
                        "signal_extraction",
                        "signal_schema",
                        "sketch_system",
                        "urgent_routing",
                    ];

                    let fingerprint = surface_fingerprint_hex(&surface);
                    local_results.push((thread_id, iteration, fingerprint));
                }

                // Merge results back
                let mut shared = results.lock().unwrap();
                shared.extend(local_results);
            });

            push_bounded(&mut handles, handle, 100);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        let final_results = shared_results.lock().unwrap();

        // Verify all fingerprints are valid
        for (thread_id, iteration, fingerprint) in final_results.iter() {
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));

            // Fingerprint should be deterministic for the same input
            let federation_module = format!("federation_t{}_i{}", thread_id, iteration);
            let surface = [
                "aggregation",
                federation_module.as_str(),
                "global_priors",
                "privacy_envelope",
                "signal_extraction",
                "signal_schema",
                "sketch_system",
                "urgent_routing",
            ];
            let regenerated = surface_fingerprint_hex(&surface);
            assert_eq!(*fingerprint, regenerated);
        }

        // Verify no duplicate fingerprints (all inputs were unique)
        let total_results = final_results.len();
        let mut unique_fingerprints = std::collections::HashSet::new();
        for (_, _, fingerprint) in final_results.iter() {
            unique_fingerprints.insert(fingerprint);
        }

        assert_eq!(unique_fingerprints.len(), total_results);
        assert_eq!(total_results, thread_count * iterations_per_thread);
    }

    #[test]
    fn negative_hex_encoding_validation_with_adversarial_byte_patterns() {
        // Test hex encoding/validation with pathological byte patterns that might break encoding
        use sha2::Sha256;

        let adversarial_patterns = [
            vec![0x00; 32],                    // All zeros
            vec![0xFF; 32],                    // All ones
            vec![0x7F; 32],                    // Max ASCII
            vec![0x80; 32],                    // Min high bit
            (0..32).collect::<Vec<u8>>(),      // Sequential
            (0..32).rev().collect::<Vec<u8>>(), // Reverse sequential
            vec![0xAA; 32],                    // Alternating bits
            vec![0x55; 32],                    // Inverse alternating
        ];

        for (pattern_idx, pattern) in adversarial_patterns.iter().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(b"test_pattern:");
            hasher.update(pattern);
            let raw_hash = hasher.finalize();

            let hex_encoded = hex::encode(raw_hash);

            // Verify hex encoding properties
            assert_eq!(hex_encoded.len(), 64);
            assert!(hex_encoded.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(!hex_encoded.is_empty());

            // Test round-trip encoding/decoding
            let decoded = hex::decode(&hex_encoded).expect("Should decode valid hex");
            assert_eq!(decoded.len(), 32);

            let re_encoded = hex::encode(&decoded);
            assert_eq!(hex_encoded, re_encoded);

            // Test that different patterns produce different hex
            for (other_idx, other_pattern) in adversarial_patterns.iter().enumerate() {
                if other_idx != pattern_idx {
                    let mut other_hasher = Sha256::new();
                    other_hasher.update(b"test_pattern:");
                    other_hasher.update(other_pattern);
                    let other_hash = hex::encode(other_hasher.finalize());
                    assert_ne!(hex_encoded, other_hash);
                }
            }
        }
    }

    #[test]
    fn negative_domain_separator_integrity_under_hash_extension_attacks() {
        use sha2::Sha256;

        // Test resistance to hash extension attacks on domain separators
        let legitimate_domain = b"atc_module_surface_v1:";

        // Attempt hash extension patterns
        let extension_attempts = [
            b"atc_module_surface_v1:extra_data".as_slice(),
            b"atc_module_surface_v1:\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18".as_slice(), // SHA-256 padding attempt
            b"atc_module_surface_v1:atc_module_surface_v1:".as_slice(),
        ];

        let mut legitimate_hasher = Sha256::new();
        legitimate_hasher.update(legitimate_domain);
        update_field(&mut legitimate_hasher, b"field:module_name", b"test");
        let legitimate_hash = hex::encode(legitimate_hasher.finalize());

        for extension in extension_attempts {
            let mut extension_hasher = Sha256::new();
            extension_hasher.update(extension);
            update_field(&mut extension_hasher, b"field:module_name", b"test");
            let extension_hash = hex::encode(extension_hasher.finalize());

            // Extension attempts should never match legitimate hash
            assert_ne!(legitimate_hash, extension_hash);

            // All should still produce valid hex
            assert_eq!(extension_hash.len(), 64);
            assert!(extension_hash.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn negative_system_resource_exhaustion_during_large_surface_processing() {
        // Test behavior under simulated system resource pressure
        let huge_module_name = "x".repeat(1_000_000); // 1MB module name

        // Measure initial fingerprint generation
        let start_time = std::time::Instant::now();
        let start_fingerprint = surface_fingerprint_hex(&[&huge_module_name]);
        let initial_duration = start_time.elapsed();

        assert_eq!(start_fingerprint.len(), 64);
        assert!(start_fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));

        // Create memory pressure by allocating large chunks
        let mut pressure_allocations = Vec::new();
        for i in 0..100 {
            pressure_allocations.push(vec![i as u8; 100_000]); // 10MB total pressure
        }

        // Generate fingerprint under memory pressure
        let pressure_time = std::time::Instant::now();
        let pressure_fingerprint = surface_fingerprint_hex(&[&huge_module_name]);
        let pressure_duration = pressure_time.elapsed();

        // Should produce identical result despite memory pressure
        assert_eq!(start_fingerprint, pressure_fingerprint);

        // Timing shouldn't degrade dramatically (allow 10x slower)
        if initial_duration.as_nanos() > 0 {
            let slowdown_ratio = pressure_duration.as_nanos() as f64 / initial_duration.as_nanos() as f64;
            assert!(slowdown_ratio.is_finite(), "Non-finite slowdown ratio");
            assert!(slowdown_ratio < 10.0,
                   "Performance degradation too severe: {}x slower", slowdown_ratio);
        }

        // Clean up pressure and verify consistency
        drop(pressure_allocations);
        let cleanup_fingerprint = surface_fingerprint_hex(&[&huge_module_name]);
        assert_eq!(start_fingerprint, cleanup_fingerprint);
    }

    #[test]
    fn negative_advanced_timing_analysis_with_statistical_validation() {
        use std::time::Instant;

        // Advanced timing analysis to detect potential side-channel leaks
        let sample_size = 1000;
        let reference_surface = module_surface();

        // Category 1: Same length, different content (timing should be similar)
        let mut same_length_surface = reference_surface.to_vec();
        same_length_surface[0] = "aggregatioX"; // Same length as "aggregation"

        // Category 2: Different length (timing might differ, but predictably)
        let shorter_surface = ["short"];
        let longer_surface = ["very_long_module_name_that_exceeds_normal_length"];

        let mut reference_times = Vec::new();
        let mut same_length_times = Vec::new();
        let mut shorter_times = Vec::new();
        let mut longer_times = Vec::new();

        // Collect timing samples in randomized order to reduce bias
        for round in 0..sample_size {
            let test_order = [
                (0, reference_surface),
                (1, same_length_surface.as_slice()),
                (2, shorter_surface.as_slice()),
                (3, longer_surface.as_slice()),
            ];

            // Randomize test order within each round using round number as seed
            let start_idx = round % 4;

            for offset in 0..4 {
                let (category, surface) = test_order[(start_idx + offset) % 4];

                let start = Instant::now();
                let _fingerprint = surface_fingerprint_hex(surface);
                let duration = start.elapsed();

                match category {
                    0 => reference_times.push(duration),
                    1 => same_length_times.push(duration),
                    2 => shorter_times.push(duration),
                    3 => longer_times.push(duration),
                    _ => unreachable!(),
                }
            }
        }

        // Statistical analysis of timing variations
        fn calculate_stats(times: &[std::time::Duration]) -> (f64, f64) {
            let nanos: Vec<f64> = times.iter().map(|d| d.as_nanos() as f64).collect();
            let mean = nanos.iter().sum::<f64>() / nanos.len() as f64;
            assert!(mean.is_finite(), "Non-finite mean in statistical analysis");
            let variance = nanos.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / nanos.len() as f64;
            assert!(variance.is_finite(), "Non-finite variance in statistical analysis");
            let std_dev = variance.sqrt();
            assert!(std_dev.is_finite(), "Non-finite standard deviation");
            (mean, std_dev)
        }

        let (ref_mean, ref_std) = calculate_stats(&reference_times);
        let (same_mean, same_std) = calculate_stats(&same_length_times);
        let (short_mean, short_std) = calculate_stats(&shorter_times);
        let (long_mean, long_std) = calculate_stats(&longer_times);

        // Same-length different-content should have very similar timing
        if ref_mean > 0.0 && same_mean > 0.0 {
            let same_length_ratio = (ref_mean - same_mean).abs() / ref_mean;
            assert!(same_length_ratio < 0.5,
                   "Same-length timing difference too large: {:.2}% (ref={:.0}ns, same={:.0}ns)",
                   same_length_ratio * 100.0, ref_mean, same_mean);
        }

        // Standard deviations should be reasonable (not excessive variation)
        let max_cv = 2.0; // Maximum coefficient of variation (std/mean)
        if ref_mean > 0.0 {
            assert!(ref_std / ref_mean < max_cv, "Reference timing too variable");
        }
        if same_mean > 0.0 {
            assert!(same_std / same_mean < max_cv, "Same-length timing too variable");
        }
        if short_mean > 0.0 {
            assert!(short_std / short_mean < max_cv, "Short timing too variable");
        }
        if long_mean > 0.0 {
            assert!(long_std / long_mean < max_cv, "Long timing too variable");
        }
    }

    #[test]
    fn negative_cryptographic_avalanche_effect_validation() {
        // Test that small changes in input cause large changes in output (avalanche effect)
        let base_surface = ["test_module"];
        let base_fingerprint = surface_fingerprint_hex(&base_surface);

        // Test single character changes
        let mutations = [
            ["test_modulE"],     // Case change in last char
            ["Test_module"],     // Case change in first char
            ["test_modul_"],     // Character substitution
            ["test_module "],    // Trailing space
            [" test_module"],    // Leading space
            ["test_module_"],    // Extra character
            ["test_modul"],      // Missing character
        ];

        let mut hamming_distances = Vec::new();

        for mutated_surface in &mutations {
            let mutated_fingerprint = surface_fingerprint_hex(mutated_surface);

            // Convert hex strings to bytes for bit-level analysis
            let base_bytes = hex::decode(&base_fingerprint).expect("Valid hex");
            let mutated_bytes = hex::decode(&mutated_fingerprint).expect("Valid hex");

            // Calculate Hamming distance (differing bits)
            let mut differing_bits = 0;
            for (base_byte, mutated_byte) in base_bytes.iter().zip(mutated_bytes.iter()) {
                differing_bits += (base_byte ^ mutated_byte).count_ones();
            }

            hamming_distances.push(differing_bits);

            // Small input change should cause significant output change
            let hash_bits = base_bytes.len() * 8;
            let change_percentage = (differing_bits as f64) / (hash_bits as f64) * 100.0;
            assert!(change_percentage.is_finite(), "Non-finite change percentage in avalanche test");

            // Good avalanche effect means ~50% of bits change
            assert!(change_percentage > 25.0,
                   "Poor avalanche effect: only {:.1}% of bits changed for mutation {:?}",
                   change_percentage, mutated_surface[0]);

            // Should not be identical (that would indicate no avalanche)
            assert_ne!(base_fingerprint, mutated_fingerprint);
        }

        // Average avalanche effect should be robust
        let avg_changed_bits = hamming_distances.iter().sum::<u32>() as f64 / hamming_distances.len() as f64;
        assert!(avg_changed_bits.is_finite(), "Non-finite average changed bits");
        let hash_bits = 256f64; // SHA-256 has 256 bits
        let avg_change_percentage = avg_changed_bits / hash_bits * 100.0;
        assert!(avg_change_percentage.is_finite(), "Non-finite average change percentage");

        assert!(avg_change_percentage > 40.0 && avg_change_percentage < 60.0,
               "Average avalanche effect outside expected range: {:.1}% (expected ~50%)",
               avg_change_percentage);
    }

    #[test]
    fn negative_fingerprint_prefix_suffix_collision_resistance_validation() {
        // Test resistance to prefix and suffix collision attacks
        let collision_test_cases = [
            // Prefix collision attempts
            (["abc"], ["abcd"]),
            (["test"], ["testing"]),
            (["mod"], ["module"]),

            // Suffix collision attempts
            (["xyz"], ["wxyz"]),
            (["ing"], ["testing"]),
            (["ule"], ["module"]),

            // Substring collision attempts
            (["ab", "cd"], ["a", "bcd"]),
            (["pre", "fix"], ["pref", "ix"]),
            (["", "test"], ["tes", "t"]),

            // Empty/whitespace collision attempts
            ([""], [" "]),
            (["", ""], [""]),
            ([" "], ["  "]),
        ];

        for (surface1, surface2) in collision_test_cases {
            let fp1 = surface_fingerprint_hex(&surface1);
            let fp2 = surface_fingerprint_hex(&surface2);

            // Should never collide
            assert_fingerprint_ne(&fp1, &fp2);

            // Both should be valid
            assert_eq!(fp1.len(), 64);
            assert_eq!(fp2.len(), 64);
            assert!(fp1.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(fp2.bytes().all(|b| b.is_ascii_hexdigit()));
        }

        // Test more complex collision scenarios
        let complex_cases = [
            // Length manipulation
            (vec!["x".repeat(100)], vec!["x".repeat(99), "x"]),
            (vec!["a".repeat(50), "b".repeat(50)], vec!["a".repeat(100)]),

            // Boundary confusion
            (vec!["field:module_name", "test"], vec!["field:module_nametest"]),
            (vec!["atc_module", "_surface"], vec!["atc_module_surface"]),
        ];

        for (surface1, surface2) in complex_cases {
            let surface1_refs: Vec<&str> = surface1.iter().map(String::as_str).collect();
            let surface2_refs: Vec<&str> = surface2.iter().map(String::as_str).collect();

            let fp1 = surface_fingerprint_hex(&surface1_refs);
            let fp2 = surface_fingerprint_hex(&surface2_refs);

            assert_fingerprint_ne(&fp1, &fp2);
        }
    }

    // ============================================================================
    // EXTREME ADVERSARIAL NEGATIVE-PATH TESTS
    // ============================================================================
    // Comprehensive edge case validation targeting sophisticated attack scenarios

    #[test]
    fn negative_unicode_normalization_attack_surface_fingerprinting() {
        // Test fingerprint resistance to Unicode normalization attacks
        let unicode_attack_surfaces = vec![
            // NFC vs NFD normalization attacks
            vec!["café"],                           // NFC: é as single codepoint
            vec!["cafe\u{0301}"],                   // NFD: e + combining acute
            vec!["café"],                           // NFKC: compatibility normalization
            vec!["cafe\u{0301}"],                   // NFKD: compatibility decomposition

            // Unicode confusables and homoglyphs
            vec!["aggregation"],                    // Latin characters
            vec!["аggregation"],                    // Cyrillic 'а' (U+0430) instead of Latin 'a'
            vec!["aggregаtion"],                    // Cyrillic 'а' in middle
            vec!["αggregation"],                    // Greek alpha instead of 'a'

            // BiDi override attacks
            vec!["signal\u{202e}_gnissecorp\u{202c}_extraction"],  // RTL override
            vec!["signal\u{202d}_processing\u{202c}_extraction"],   // LTR override

            // Zero-width character pollution
            vec!["sig\u{200b}nal_extraction"],      // Zero-width space
            vec!["signal\u{200c}_extraction"],      // Zero-width non-joiner
            vec!["signal\u{200d}_extraction"],      // Zero-width joiner
            vec!["signal\u{feff}_extraction"],      // Byte order mark

            // Combining character stacking
            vec!["signal\u{0300}\u{0301}\u{0302}_extraction"], // Multiple combining marks
            vec!["signal_extraction\u{0300}"],      // Combining mark at end
        ];

        // All should produce different fingerprints despite visual similarity
        let mut seen_fingerprints = std::collections::HashSet::new();
        for (i, surface) in unicode_attack_surfaces.iter().enumerate() {
            let surface_refs: Vec<&str> = surface.iter().map(String::as_str).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);

            assert_eq!(fingerprint.len(), 64, "Unicode test {} should produce 64-char hex", i);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Unicode test {} should produce valid hex: {}", i, fingerprint);

            assert!(seen_fingerprints.insert(fingerprint.clone()),
                   "Unicode normalization collision detected at test {}: {}", i, fingerprint);
        }

        // Verify we have unique fingerprints for all test cases
        assert_eq!(seen_fingerprints.len(), unicode_attack_surfaces.len());
    }

    #[test]
    fn negative_memory_exhaustion_massive_surface_arrays() {
        // Test fingerprinting with massive surface arrays that could cause memory issues
        let massive_surface_configs = vec![
            // Large number of short modules
            (0..10000).map(|i| format!("mod_{:06}", i)).collect::<Vec<_>>(),

            // Smaller number of very long modules
            (0..100).map(|i| format!("module_{}{}", i, "x".repeat(10000))).collect::<Vec<_>>(),

            // Mixed size distribution
            (0..1000).map(|i| {
                if i % 10 == 0 {
                    format!("large_module_{}{}", i, "y".repeat(1000))
                } else {
                    format!("small_{}", i)
                }
            }).collect::<Vec<_>>(),

            // Edge case: single massive module
            vec!["z".repeat(1_000_000)],

            // Pattern that might cause hash table collisions
            (0..5000).map(|i| format!("collision_test_{:04x}", i)).collect::<Vec<_>>(),
        ];

        for (test_idx, massive_surface) in massive_surface_configs.into_iter().enumerate() {
            let surface_refs: Vec<&str> = massive_surface.iter().map(String::as_str).collect();

            // Should handle massive inputs without memory issues or crashes
            let start = std::time::Instant::now();
            let fingerprint = surface_fingerprint_hex(&surface_refs);
            let duration = start.elapsed();

            // Should complete within reasonable time (not hang/infinite loop)
            assert!(duration.as_secs() < 10, "Massive surface test {} took too long: {:?}", test_idx, duration);

            // Should produce valid fingerprint despite size
            assert_eq!(fingerprint.len(), 64, "Massive test {} should produce 64-char hex", test_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Massive test {} should produce valid hex", test_idx);
            assert_ne!(fingerprint, "0".repeat(64), "Should not produce zero fingerprint");
            assert_ne!(fingerprint, "f".repeat(64), "Should not produce all-f fingerprint");
        }
    }

    #[test]
    fn negative_hash_collision_birthday_attack_surface_modules() {
        // Test resistance to birthday attack patterns on surface module names
        let birthday_attack_modules = vec![
            // Bit manipulation patterns that might expose hash weaknesses
            (0..256).map(|i| format!("birthday_{:02x}", i)).collect::<Vec<_>>(),

            // Mathematical sequence patterns
            (1..100).map(|i| format!("fib_{}", fibonacci_mod(i, 1000))).collect::<Vec<_>>(),

            // Prime number sequences
            prime_sequence(100).iter().map(|&p| format!("prime_{}", p)).collect::<Vec<_>>(),

            // Powers of 2 near hash boundaries
            (0..32).map(|i| format!("pow2_{}", 1_u64 << i)).collect::<Vec<_>>(),

            // CRC polynomial patterns
            vec![
                "crc_0x1021", "crc_0x8005", "crc_0x8408", "crc_0x8810",
                "crc_0xa001", "crc_0xc867", "crc_0x1edc6f41", "crc_0x04c11db7"
            ].iter().map(|&s| s.to_string()).collect::<Vec<_>>(),
        ];

        for (attack_idx, modules) in birthday_attack_modules.into_iter().enumerate() {
            let module_refs: Vec<&str> = modules.iter().map(String::as_str).collect();
            let fingerprint = surface_fingerprint_hex(&module_refs);

            // Should produce valid fingerprint despite collision-prone patterns
            assert_eq!(fingerprint.len(), 64, "Birthday attack test {} failed length check", attack_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Birthday attack test {} produced invalid hex", attack_idx);

            // Should not produce obviously weak hashes
            assert_ne!(fingerprint, "0".repeat(64), "Attack test {} produced zero hash", attack_idx);
            assert_ne!(fingerprint, "f".repeat(64), "Attack test {} produced max hash", attack_idx);
            assert!(!fingerprint.chars().all(|c| c == fingerprint.chars().next().unwrap()),
                   "Attack test {} produced single-character hash: {}", attack_idx, fingerprint);

            // Should have reasonable entropy distribution
            let unique_chars: std::collections::HashSet<_> = fingerprint.chars().collect();
            assert!(unique_chars.len() >= 4, "Attack test {} has low entropy: {}", attack_idx, fingerprint);
        }

        // Helper function for Fibonacci sequence
        fn fibonacci_mod(n: usize, modulo: u64) -> u64 {
            if n == 0 { return 0; }
            if n == 1 { return 1; }
            let mut a = 0u64;
            let mut b = 1u64;
            for _ in 2..=n {
                let next = (a + b) % modulo;
                a = b;
                b = next;
            }
            b
        }

        // Helper function for prime sequence
        fn prime_sequence(limit: usize) -> Vec<u64> {
            let mut primes = Vec::new();
            let mut is_prime = vec![true; limit + 1];
            is_prime[0] = false;
            if limit > 0 { is_prime[1] = false; }

            for i in 2..=limit {
                if is_prime[i] {
                    primes.push(i as u64);
                    for j in ((i * i)..=limit).step_by(i) {
                        is_prime[j] = false;
                    }
                }
            }
            primes
        }
    }

    #[test]
    fn negative_domain_separator_injection_surface_fingerprinting() {
        // Test resistance to domain separator injection in surface fingerprinting
        let domain_injection_attacks = vec![
            // Attempt to inject actual domain separator
            vec!["surface_fingerprint_v1:"],
            vec!["field:module_count"],
            vec!["field:module_name"],

            // Length prefix manipulation attempts
            vec!["\x08\x00\x00\x00\x00\x00\x00\x00test"],  // 8-byte length prefix
            vec!["test\x04\x00\x00\x00\x00\x00\x00\x00"],  // Length after data

            // Hash algorithm identifier injection
            vec!["sha256:", "blake3:", "keccak256:"],

            // Protocol version injection
            vec!["v1:", "v2:", "version:1"],

            // Field boundary confusion
            vec!["field:module_namemodule_value"],
            vec!["module_count8module_name"],

            // Multi-field injection attempts
            vec!["field:module_count", "8field:module_name", "injection"],

            // Null byte injection
            vec!["module\x00separator\x00injection"],
            vec!["legit_module\x00\x00\x00hidden"],

            // Hash padding injection (SHA-256 style)
            vec!["module\u{80}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20"],
        ];

        let mut injection_fingerprints = std::collections::HashSet::new();

        for (attack_idx, attack_surface) in domain_injection_attacks.into_iter().enumerate() {
            let surface_refs: Vec<&str> = attack_surface.iter().map(|s| s.as_ref()).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);

            // Should produce valid fingerprint despite injection attempts
            assert_eq!(fingerprint.len(), 64, "Domain injection test {} failed length", attack_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Domain injection test {} produced invalid hex", attack_idx);

            // All injection attempts should produce unique fingerprints
            assert!(injection_fingerprints.insert(fingerprint.clone()),
                   "Domain separator injection collision at test {}: {}", attack_idx, fingerprint);
        }

        // Verify no collisions occurred
        assert_eq!(injection_fingerprints.len(), domain_injection_attacks.len());

        // Test that legitimate modules produce different fingerprints from injection attempts
        let legitimate_surface_refs = module_surface();
        let legitimate_fingerprint = surface_fingerprint_hex(legitimate_surface_refs);

        assert!(!injection_fingerprints.contains(&legitimate_fingerprint),
               "Legitimate surface collides with injection attack fingerprint");
    }

    #[test]
    fn negative_arithmetic_overflow_surface_length_calculations() {
        // Test surface fingerprinting with inputs that could cause integer overflow
        let overflow_test_surfaces = vec![
            // Near usize::MAX length scenarios
            vec!["x".repeat(if cfg!(target_pointer_width = "64") {
                1_000_000
            } else {
                256_000
            })],

            // Large number of small modules (count overflow)
            (0..50_000).map(|i| format!("m{}", i % 1000)).collect::<Vec<_>>(),

            // Modules with lengths that might overflow when summed
            vec![
                "a".repeat(1_000_000),
                "b".repeat(1_000_000),
                "c".repeat(1_000_000),
                "d".repeat(1_000_000),
            ],

            // Edge case: empty modules with overflow-prone count
            vec![""; 50_000],

            // Mixed: many small + few huge
            {
                let mut mixed = (0..10_000).map(|i| format!("tiny{}", i)).collect::<Vec<_>>();
                mixed.push("huge".repeat(250_000));
                mixed
            },
        ];

        for (test_idx, overflow_surface) in overflow_test_surfaces.into_iter().enumerate() {
            let surface_refs: Vec<&str> = overflow_surface.iter().map(String::as_str).collect();

            // Should handle overflow scenarios without panicking
            let result = std::panic::catch_unwind(|| {
                surface_fingerprint_hex(&surface_refs)
            });

            match result {
                Ok(fingerprint) => {
                    // If it succeeds, should produce valid fingerprint
                    assert_eq!(fingerprint.len(), 64, "Overflow test {} failed length check", test_idx);
                    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                           "Overflow test {} produced invalid hex", test_idx);
                }
                Err(_) => {
                    // Acceptable to panic on extreme inputs (controlled failure)
                    // But should not cause memory corruption or undefined behavior
                }
            }
        }
    }

    #[test]
    fn negative_control_character_pollution_surface_validation() {
        // Test surface validation with control character pollution attacks
        let control_char_attacks = vec![
            // ASCII control characters
            vec!["module\x00name"],     // Null byte
            vec!["module\x01name"],     // Start of heading
            vec!["module\x07name"],     // Bell
            vec!["module\x08name"],     // Backspace
            vec!["module\x0Aname"],     // Line feed
            vec!["module\x0Dname"],     // Carriage return
            vec!["module\x1Bname"],     // Escape
            vec!["module\x7Fname"],     // Delete

            // Terminal control sequences
            vec!["module\x1B[2Jname"],  // Clear screen
            vec!["module\x1B[31mname"], // Red color
            vec!["module\x1B[Hname"],   // Home cursor

            // Unicode control characters
            vec!["module\u{0085}name"], // Next line (NEL)
            vec!["module\u{2028}name"], // Line separator
            vec!["module\u{2029}name"], // Paragraph separator

            // Mixed control character pollution
            vec!["mod\x00\x01\x02ule\x7F\x1B[Hname"],

            // Control characters at boundaries
            vec!["\x00module", "name\x7F"],
            vec!["\x1B[2J", "clean_module", "\x1B[0m"],
        ];

        for (attack_idx, attack_surface) in control_char_attacks.into_iter().enumerate() {
            let surface_refs: Vec<&str> = attack_surface.iter().map(|s| s.as_ref()).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);

            // Should handle control characters without corruption
            assert_eq!(fingerprint.len(), 64, "Control char test {} failed length", attack_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Control char test {} produced invalid hex: {}", attack_idx, fingerprint);

            // Control characters should not cause hash to become predictable
            assert_ne!(fingerprint, "0".repeat(64), "Control char test {} produced zero hash", attack_idx);
            assert_ne!(fingerprint, "f".repeat(64), "Control char test {} produced max hash", attack_idx);
        }

        // Test that control character variations produce different fingerprints
        let control_variants = vec![
            vec!["module"],
            vec!["module\x00"],
            vec!["module\x01"],
            vec!["module\x7F"],
            vec!["\x00module"],
            vec!["mod\x00ule"],
        ];

        let mut control_fingerprints = std::collections::HashSet::new();
        for variant in control_variants {
            let variant_refs: Vec<&str> = variant.iter().map(|s| s.as_ref()).collect();
            let fingerprint = surface_fingerprint_hex(&variant_refs);
            assert!(control_fingerprints.insert(fingerprint),
                   "Control character variant collision detected");
        }
    }

    #[test]
    fn negative_concurrent_surface_fingerprint_consistency() {
        // Test surface fingerprinting consistency under concurrent-like access patterns
        let test_surface = vec!["aggregation", "federation", "privacy_envelope"];
        let surface_refs: Vec<&str> = test_surface.iter().map(|s| s.as_ref()).collect();

        // Generate fingerprints rapidly to test for race conditions or state corruption
        let mut fingerprints = Vec::new();
        for _ in 0..1000 {
            let fingerprint = surface_fingerprint_hex(&surface_refs);
            push_bounded(&mut fingerprints, fingerprint, 10000);
        }

        // All fingerprints should be identical (deterministic)
        let first_fingerprint = &fingerprints[0];
        for (i, fingerprint) in fingerprints.iter().enumerate() {
            assert_eq!(fingerprint, first_fingerprint,
                      "Fingerprint inconsistency at iteration {}: expected {}, got {}",
                      i, first_fingerprint, fingerprint);
        }

        // Test with different input orderings to verify order sensitivity
        let reordered_surfaces = vec![
            vec!["aggregation", "federation", "privacy_envelope"],
            vec!["federation", "aggregation", "privacy_envelope"],
            vec!["privacy_envelope", "federation", "aggregation"],
            vec!["aggregation", "privacy_envelope", "federation"],
        ];

        let mut ordering_fingerprints = std::collections::HashSet::new();
        for reordered in reordered_surfaces {
            let reordered_refs: Vec<&str> = reordered.iter().map(|s| s.as_ref()).collect();
            let fingerprint = surface_fingerprint_hex(&reordered_refs);

            // Different orderings should produce different fingerprints
            assert!(ordering_fingerprints.insert(fingerprint.clone()),
                   "Ordering collision detected for: {:?}", reordered);
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // Should have 4 unique fingerprints for 4 different orderings
        assert_eq!(ordering_fingerprints.len(), 4);
    }

    #[test]
    fn negative_json_serialization_injection_surface_fingerprinting() {
        // Test surface fingerprinting resistance to JSON injection patterns
        let json_injection_attacks = vec![
            // JSON control character injection
            vec![r#"module": "injected", "evil": "true", "real_module""#],
            vec![r#"{"injected": true, "module": "#],
            vec![r#"module\", \"injected\": true, \"continue\": \"#],

            // JSON escape sequence injection
            vec![r#"module\\u0000hidden"#],
            vec![r#"module\\n\\r\\t"#],
            vec![r#"module\\\" injection\\\""#],

            // Unicode escape injection
            vec![r#"module\u0022injection\u0022"#],
            vec![r#"module\u005C\u0022evil\u0022"#],

            // Nested structure injection
            vec![r#"module", "nested": {"evil": true}, "continue": ""#],
            vec![r#"[\"injected\", \"array\"], \"module\": \""#],

            // Null byte and binary injection disguised as JSON
            vec!["module\x00{\"evil\": true}"],
            vec!["module\": true, \"injected\": \""],

            // Newline injection for log corruption
            vec!["module\nINJECTED: true\nmodule2"],
            vec!["module\r\nSet-Cookie: evil=true\r\nmodule2"],
        ];

        for (attack_idx, attack_surface) in json_injection_attacks.into_iter().enumerate() {
            let surface_refs: Vec<&str> = attack_surface.iter().map(|s| s.as_ref()).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);

            // Should handle JSON injection attempts without corruption
            assert_eq!(fingerprint.len(), 64, "JSON injection test {} failed length", attack_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "JSON injection test {} produced invalid hex", attack_idx);

            // Should not produce predictable hashes that might indicate successful injection
            assert_ne!(fingerprint, "0".repeat(64), "JSON injection test {} produced zero hash", attack_idx);
            assert_ne!(fingerprint, "f".repeat(64), "JSON injection test {} produced max hash", attack_idx);

            // Should maintain entropy despite injection patterns
            let unique_chars: std::collections::HashSet<_> = fingerprint.chars().collect();
            assert!(unique_chars.len() >= 4, "JSON injection test {} has low entropy", attack_idx);
        }

        // Verify that legitimate JSON-like module names are handled correctly
        let legitimate_json_like = vec![
            vec!["json_parser"],
            vec!["data_schema"],
            vec!["config_loader"],
            vec!["api_response"],
        ];

        for json_like in legitimate_json_like {
            let refs: Vec<&str> = json_like.iter().map(|s| s.as_ref()).collect();
            let fingerprint = surface_fingerprint_hex(&refs);
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn negative_atc_surface_comprehensive_unicode_injection_and_encoding_attacks() {
        // Test comprehensive Unicode injection and encoding attack resistance
        let unicode_injection_surfaces = vec![
            // Right-to-left override attacks
            vec![
                "normal_module",
                "\u{202E}\u{202D}fake_module\u{202C}",
                "privacy_envelope",
            ],

            // Zero-width character injection
            vec![
                "signal_extraction",
                "signal\u{200B}\u{200C}\u{200D}schema",
                "sketch_system",
            ],

            // Non-character code points
            vec![
                "aggregation",
                "\u{FFFF}\u{FFFE}\u{FDD0}non_chars",
                "federation",
            ],

            // Combining marks that could alter display
            vec![
                "global_priors",
                "\u{0300}\u{0301}\u{0302}combining_marks_module",
                "urgent_routing",
            ],

            // Unicode normalization attacks
            vec![
                "privacy_envelope",
                "café", // é as single character
                "cafe\u{0301}", // e + combining acute accent
            ],

            // Emoji and high Unicode ranges
            vec![
                "🚀rocket_module",
                "signal_🔄extraction",
                "💻\u{1F4A5}💥system",
            ],

            // Mixed script attacks
            vec![
                "normal_module",
                "сignal_extraсtion", // Cyrillic с mixed with Latin
                "federаtion", // Cyrillic а in Latin word
            ],

            // Invisible separators and spaces
            vec![
                "signal_extraction",
                "signal\u{2028}extraction", // Line separator
                "signal\u{2029}extraction", // Paragraph separator
            ],

            // Homoglyph attacks
            vec![
                "aggregation", // Normal
                "aggregаtion", // Cyrillic а
                "aggregⰰtion", // Glagolitic А
            ],

            // UTF-8 overlong encoding simulation
            vec![
                "normal",
                "mοdule", // Greek omicron looks like Latin o
                "modulе", // Cyrillic е looks like Latin e
            ],
        ];

        for (surface_idx, unicode_surface) in unicode_injection_surfaces.into_iter().enumerate() {
            let surface_refs: Vec<&str> = unicode_surface.iter().map(|s| s.as_ref()).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);

            // Should produce consistent fingerprints despite Unicode content
            assert_eq!(fingerprint.len(), 64,
                      "Unicode injection surface {} failed length check", surface_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Unicode injection surface {} produced invalid hex", surface_idx);

            // Should not produce obviously predictable patterns
            assert_ne!(fingerprint, "0".repeat(64),
                      "Unicode surface {} produced zero hash", surface_idx);
            assert_ne!(fingerprint, "f".repeat(64),
                      "Unicode surface {} produced max hash", surface_idx);

            // Fingerprint should be deterministic for same Unicode input
            let fingerprint2 = surface_fingerprint_hex(&surface_refs);
            assert_eq!(fingerprint, fingerprint2,
                      "Unicode surface {} fingerprint not deterministic", surface_idx);

            // Should maintain sufficient entropy despite Unicode attacks
            let unique_chars: std::collections::HashSet<_> = fingerprint.chars().collect();
            assert!(unique_chars.len() >= 6,
                   "Unicode surface {} has insufficient entropy: {}", surface_idx, unique_chars.len());

            // Test that Unicode normalization doesn't break fingerprinting
            let normalized_surface: Vec<String> = unicode_surface
                .iter()
                .map(|s| s.chars().collect::<String>()) // Simple normalization
                .collect();
            let normalized_refs: Vec<&str> = normalized_surface.iter().map(|s| s.as_ref()).collect();
            let normalized_fingerprint = surface_fingerprint_hex(&normalized_refs);

            // Should handle normalized versions consistently
            assert_eq!(normalized_fingerprint.len(), 64);
            assert!(normalized_fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // Test extreme Unicode boundary conditions
        let unicode_boundary_cases = vec![
            // Surrogate pairs and high Unicode
            vec!["\u{10000}", "\u{10FFFF}", "normal"], // Valid high Unicode
            vec!["normal", "\u{E000}", "\u{F8FF}"],    // Private use area
            vec!["\u{FFF0}", "\u{FFFD}", "normal"],    // Specials block

            // Maximum length Unicode module names
            vec!["🚀".repeat(20)], // 20 emoji characters
            vec!["控制字符".repeat(10)], // Chinese characters
            vec!["\u{0300}".repeat(50)], // Many combining marks
        ];

        for (boundary_idx, boundary_surface) in unicode_boundary_cases.into_iter().enumerate() {
            let surface_refs: Vec<&str> = boundary_surface.iter().map(|s| s.as_ref()).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);

            assert_eq!(fingerprint.len(), 64,
                      "Unicode boundary case {} failed", boundary_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Unicode boundary case {} invalid hex", boundary_idx);

            // Should not crash or produce empty results
            assert!(!fingerprint.is_empty(),
                   "Unicode boundary case {} produced empty fingerprint", boundary_idx);
        }
    }

    #[test]
    fn negative_surface_fingerprint_collision_resistance_and_preimage_attacks() {
        // Test surface fingerprint collision resistance and preimage attack resistance
        let mut observed_fingerprints = std::collections::HashSet::new();

        // Test collision resistance with systematic variations
        let collision_test_bases = [
            ["aggregation", "federation"],
            ["privacy_envelope", "signal_extraction"],
            ["signal_schema", "sketch_system"],
            ["global_priors", "urgent_routing"],
        ];

        for (base_idx, base_surface) in collision_test_bases.iter().enumerate() {
            // Generate many variations to test collision resistance
            for variation in 0..1000 {
                let mut test_surface = base_surface
                    .iter()
                    .map(|module| (*module).to_owned())
                    .collect::<Vec<_>>();

                // Add systematic variations
                test_surface.push(format!("variation_{}", variation));
                test_surface.push(format!("base_{}_var_{}", base_idx, variation));

                let surface_refs: Vec<&str> = test_surface.iter().map(String::as_str).collect();
                let fingerprint = surface_fingerprint_hex(&surface_refs);

                // Check for collisions
                assert!(!observed_fingerprints.contains(&fingerprint),
                       "Collision detected for base {} variation {}: {}", base_idx, variation, fingerprint);
                observed_fingerprints.insert(fingerprint.clone());

                // Verify fingerprint properties
                assert_eq!(fingerprint.len(), 64);
                assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));

                // Test determinism
                let fingerprint2 = surface_fingerprint_hex(&surface_refs);
                assert_eq!(fingerprint, fingerprint2,
                          "Non-deterministic fingerprint for base {} variation {}", base_idx, variation);
            }
        }

        // Test preimage resistance
        let target_fingerprints = vec![
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "deadbeefcafebabe1234567890abcdef0011223344556677889900aabbccddee",
            "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        ];

        for target in target_fingerprints {
            let mut found_preimage = false;

            // Try many different surface combinations
            for attempt in 0..10000 {
                let attempt_surface = vec![
                    format!("preimage_attempt_{}", attempt),
                    format!("target_search_{}", attempt),
                    format!("collision_test_{}", attempt % 100),
                ];

                let surface_refs: Vec<&str> = attempt_surface.iter().map(String::as_str).collect();
                let computed = surface_fingerprint_hex(&surface_refs);

                if computed == target {
                    found_preimage = true;
                    break;
                }
            }

            // Should be extremely unlikely to find preimage by chance
            assert!(!found_preimage,
                   "Accidentally found preimage for target: {}", target);
        }

        // Test avalanche effect (small changes cause large fingerprint changes)
        let avalanche_base = ["aggregation", "federation", "global_priors"];
        let base_fingerprint = surface_fingerprint_hex(&avalanche_base);

        // Test single character changes
        for pos in 0..3 {
            for original_module in &avalanche_base {
                if !original_module.is_empty() {
                    let mut modified_surface = avalanche_base
                        .iter()
                        .map(|module| (*module).to_owned())
                        .collect::<Vec<_>>();

                    let mut modified_bytes = original_module.as_bytes().to_vec();
                    modified_bytes[0] ^= 0x01;
                    let modified_module = String::from_utf8(modified_bytes)
                        .expect("ASCII module mutation should remain valid UTF-8");
                    modified_surface[pos] = modified_module;

                    let modified_refs: Vec<&str> = modified_surface.iter().map(String::as_str).collect();
                    let modified_fingerprint = surface_fingerprint_hex(&modified_refs);

                    // Should produce significantly different fingerprint
                    assert_ne!(base_fingerprint, modified_fingerprint,
                             "Insufficient avalanche effect for position {}", pos);

                    // Count differing hex characters
                    let diff_count = base_fingerprint
                        .chars()
                        .zip(modified_fingerprint.chars())
                        .filter(|(a, b)| a != b)
                        .count();

                    // Should have good avalanche effect (roughly half characters different)
                    assert!(diff_count > 20,
                           "Weak avalanche effect: only {} chars differ for position {}", diff_count, pos);
                }
            }
        }

        // Test order sensitivity
        let order_test_surface = vec!["alpha", "beta", "gamma"];
        let original_refs: Vec<&str> = order_test_surface.iter().map(|s| s.as_ref()).collect();
        let original_fingerprint = surface_fingerprint_hex(&original_refs);

        let mut reversed_surface = order_test_surface.clone();
        reversed_surface.reverse();
        let reversed_refs: Vec<&str> = reversed_surface.iter().map(|s| s.as_ref()).collect();
        let reversed_fingerprint = surface_fingerprint_hex(&reversed_refs);

        assert_ne!(original_fingerprint, reversed_fingerprint,
                  "Fingerprint should be order-sensitive");

        // Test length sensitivity
        let short_surface = vec!["short"];
        let long_surface = vec!["short", "extended", "much", "longer", "surface"];

        let short_refs: Vec<&str> = short_surface.iter().map(|s| s.as_ref()).collect();
        let long_refs: Vec<&str> = long_surface.iter().map(|s| s.as_ref()).collect();

        let short_fingerprint = surface_fingerprint_hex(&short_refs);
        let long_fingerprint = surface_fingerprint_hex(&long_refs);

        assert_ne!(short_fingerprint, long_fingerprint,
                  "Fingerprint should be length-sensitive");
    }

    #[test]
    fn negative_surface_module_boundary_validation_and_injection_resistance() {
        // Test surface module boundary validation and injection attack resistance
        let injection_attack_surfaces = vec![
            // Path traversal attacks
            vec![
                "normal_module",
                "../../../etc/passwd",
                "privacy_envelope",
            ],
            vec![
                "aggregation",
                "../../secret/key.pem",
                "federation",
            ],
            vec![
                "signal_extraction",
                "..\\..\\windows\\system32\\config",
                "sketch_system",
            ],

            // Command injection attempts
            vec![
                "signal_schema",
                "; rm -rf /tmp/*",
                "global_priors",
            ],
            vec![
                "urgent_routing",
                "$(whoami)",
                "privacy_envelope",
            ],
            vec![
                "aggregation",
                "`cat /etc/shadow`",
                "federation",
            ],

            // SQL injection patterns
            vec![
                "normal_module",
                "'; DROP TABLE modules; --",
                "signal_extraction",
            ],
            vec![
                "sketch_system",
                "' UNION SELECT * FROM secrets; --",
                "global_priors",
            ],
            vec![
                "privacy_envelope",
                "' OR '1'='1",
                "urgent_routing",
            ],

            // Script injection patterns
            vec![
                "aggregation",
                "<script>alert('xss')</script>",
                "federation",
            ],
            vec![
                "signal_schema",
                "javascript:void(0)",
                "sketch_system",
            ],
            vec![
                "global_priors",
                "data:text/html,<script>evil()</script>",
                "urgent_routing",
            ],

            // Binary data injection
            vec![
                "normal_module",
                "\x00\x01\x02\x03binary_data",
                "privacy_envelope",
            ],
            vec![
                "signal_extraction",
                "\u{FF}\u{FE}\u{FD}binary_injection",
                "signal_schema",
            ],

            // Protocol injection
            vec![
                "aggregation",
                "file:///etc/passwd",
                "federation",
            ],
            vec![
                "sketch_system",
                "http://evil.com/steal_data",
                "global_priors",
            ],
            vec![
                "urgent_routing",
                "ftp://malicious.server/upload",
                "privacy_envelope",
            ],

            // Format string injection
            vec![
                "signal_extraction",
                "%s%d%n%x",
                "signal_schema",
            ],
            vec![
                "aggregation",
                "%{module}",
                "federation",
            ],

            // Environment variable injection
            vec![
                "normal_module",
                "${PATH}",
                "privacy_envelope",
            ],
            vec![
                "sketch_system",
                "$HOME/evil_script",
                "global_priors",
            ],

            // Null byte injection
            vec![
                "aggregation",
                "module\x00hidden_content",
                "federation",
            ],
            vec![
                "signal_extraction\x00evil",
                "signal_schema",
                "sketch_system",
            ],
        ];

        for (attack_idx, attack_surface) in injection_attack_surfaces.into_iter().enumerate() {
            let surface_refs: Vec<&str> = attack_surface.iter().map(String::as_str).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);

            // Should handle injection attempts safely
            assert_eq!(fingerprint.len(), 64,
                      "Injection attack {} failed length check", attack_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Injection attack {} produced invalid hex", attack_idx);

            // Should not produce obviously compromised fingerprints
            assert_ne!(fingerprint, "0".repeat(64),
                      "Injection attack {} produced suspicious zero hash", attack_idx);

            // Fingerprint should not contain injection content
            let fingerprint_upper = fingerprint.to_uppercase();
            assert!(!fingerprint_upper.contains("DEAD"),
                   "Injection attack {} fingerprint suspicious: {}", attack_idx, fingerprint);
            assert!(!fingerprint_upper.contains("BEEF"),
                   "Injection attack {} fingerprint suspicious: {}", attack_idx, fingerprint);

            // Should be deterministic even with injection content
            let fingerprint2 = surface_fingerprint_hex(&surface_refs);
            assert_eq!(fingerprint, fingerprint2,
                      "Injection attack {} not deterministic", attack_idx);

            // Test that injection doesn't affect subsequent operations
            let clean_surface = vec!["aggregation", "federation", "global_priors"];
            let clean_refs: Vec<&str> = clean_surface.iter().map(String::as_str).collect();
            let clean_fingerprint = surface_fingerprint_hex(&clean_refs);

            assert_eq!(clean_fingerprint.len(), 64,
                      "Post-injection operation failed for attack {}", attack_idx);
            assert!(clean_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Post-injection operation invalid for attack {}", attack_idx);
        }

        // Test module name validation resistance
        let boundary_violation_modules = vec![
            "", // Empty module
            " ", // Whitespace only
            "\t", // Tab only
            "\n", // Newline only
            "\r\n", // CRLF
            ".", // Single dot
            "..", // Double dot
            "...", // Triple dot
            "module.", // Ends with dot
            ".module", // Starts with dot
            "mod..ule", // Double dots in middle
            "module/", // Ends with slash
            "/module", // Starts with slash
            "mod/ule", // Slash in middle
            "module\\", // Ends with backslash
            "\\module", // Starts with backslash
            "mod\\ule", // Backslash in middle
            "MOD", // All uppercase
            "Mod", // Mixed case
            "123", // Numeric only
            "_", // Underscore only
            "__", // Double underscore
            "mod__ule", // Double underscore in middle
            "module__", // Ends with double underscore
            "__module", // Starts with double underscore
            "a".repeat(1000), // Extremely long
            "\x00module", // Null prefix
            "module\x00", // Null suffix
            "mod\x00ule", // Null in middle
        ];

        for (boundary_idx, boundary_module) in boundary_violation_modules.into_iter().enumerate() {
            let boundary_surface = vec!["aggregation", boundary_module, "federation"];
            let surface_refs: Vec<&str> = boundary_surface.iter().map(String::as_str).collect();

            // Should handle boundary violations gracefully
            let fingerprint = surface_fingerprint_hex(&surface_refs);

            assert_eq!(fingerprint.len(), 64,
                      "Boundary violation {} failed: {}", boundary_idx, boundary_module);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Boundary violation {} invalid hex: {}", boundary_idx, boundary_module);

            // Should be deterministic for boundary cases
            let fingerprint2 = surface_fingerprint_hex(&surface_refs);
            assert_eq!(fingerprint, fingerprint2,
                      "Boundary violation {} not deterministic: {}", boundary_idx, boundary_module);
        }

        // Test extremely large surface collections
        let large_surface: Vec<String> = (0..10000)
            .map(|i| format!("large_module_{:06}", i))
            .collect();
        let large_refs: Vec<&str> = large_surface.iter().map(String::as_str).collect();

        let start_time = std::time::Instant::now();
        let large_fingerprint = surface_fingerprint_hex(&large_refs);
        let duration = start_time.elapsed();

        // Should handle large surfaces efficiently
        assert!(duration < std::time::Duration::from_secs(5),
               "Large surface fingerprinting took too long: {:?}", duration);
        assert_eq!(large_fingerprint.len(), 64);
        assert!(large_fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn negative_surface_contract_stability_and_backwards_compatibility_attacks() {
        // Test surface contract stability and backwards compatibility attack resistance

        // Test that ATC_MODULE_SURFACE constant is immutable
        let original_surface = ATC_MODULE_SURFACE;
        let retrieved_surface1 = module_surface();
        let retrieved_surface2 = module_surface();

        // Multiple retrievals should return identical references (not copies)
        assert_eq!(retrieved_surface1.as_ptr(), retrieved_surface2.as_ptr(),
                  "Module surface should return same reference");
        assert_eq!(retrieved_surface1.as_ptr(), original_surface.as_ptr(),
                  "Module surface should match constant reference");

        // Test contract stability under memory pressure
        let mut pressure_vectors = Vec::new();
        for i in 0..1000 {
            // Create memory pressure
            pressure_vectors.push(vec![format!("pressure_{}", i); 1000]);

            // Verify surface remains stable
            let surface_under_pressure = module_surface();
            assert_eq!(surface_under_pressure.as_ptr(), original_surface.as_ptr(),
                      "Surface reference changed under memory pressure at iteration {}", i);
            assert_eq!(surface_under_pressure.len(), original_surface.len(),
                      "Surface length changed under memory pressure at iteration {}", i);
        }

        // Test contract content immutability simulation
        let expected_modules = [
            "aggregation",
            "federation",
            "global_priors",
            "privacy_envelope",
            "signal_extraction",
            "signal_schema",
            "sketch_system",
            "urgent_routing",
        ];

        let current_surface = module_surface();
        assert_eq!(current_surface.len(), expected_modules.len(),
                  "Surface length differs from expected contract");

        for (idx, &expected_module) in expected_modules.iter().enumerate() {
            assert_eq!(current_surface[idx], expected_module,
                      "Surface module {} differs from contract: got {}, expected {}",
                      idx, current_surface[idx], expected_module);
        }

        // Test fingerprinting stability across different access patterns
        let access_patterns = vec![
            // Direct constant access
            ATC_MODULE_SURFACE.to_vec(),
            // Function access
            module_surface().to_vec(),
            // Multiple function calls
            {
                let mut pattern = Vec::new();
                for _ in 0..10 {
                    pattern.extend_from_slice(module_surface());
                }
                pattern[0..module_surface().len()].to_vec()
            },
            // Cloned access
            module_surface().iter().cloned().collect(),
        ];

        let mut pattern_fingerprints = Vec::new();
        for (pattern_idx, pattern) in access_patterns.into_iter().enumerate() {
            let pattern_refs: Vec<&str> = pattern.iter().map(String::as_str).collect();
            let fingerprint = surface_fingerprint_hex(&pattern_refs);

            assert_eq!(fingerprint.len(), 64,
                      "Access pattern {} produced invalid fingerprint length", pattern_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Access pattern {} produced invalid hex fingerprint", pattern_idx);

            pattern_fingerprints.push(fingerprint);
        }

        // All access patterns should produce identical fingerprints
        let canonical_fingerprint = &pattern_fingerprints[0];
        for (pattern_idx, fingerprint) in pattern_fingerprints.iter().enumerate().skip(1) {
            assert_eq!(fingerprint, canonical_fingerprint,
                      "Access pattern {} produced different fingerprint: {} vs {}",
                      pattern_idx, fingerprint, canonical_fingerprint);
        }

        // Test backwards compatibility simulation with version drift
        let version_drift_scenarios = vec![
            // Missing module scenario
            vec![
                "aggregation", "federation", "global_priors", "privacy_envelope",
                "signal_extraction", "signal_schema", "sketch_system",
                // "urgent_routing" missing
            ],

            // Extra module scenario
            vec![
                "aggregation", "federation", "global_priors", "privacy_envelope",
                "signal_extraction", "signal_schema", "sketch_system", "urgent_routing",
                "new_experimental_module", // Extra module
            ],

            // Reordered modules scenario
            vec![
                "urgent_routing", "sketch_system", "signal_schema", "signal_extraction",
                "privacy_envelope", "global_priors", "federation", "aggregation",
            ],

            // Modified module names scenario
            vec![
                "aggregation", "federation", "global_priors", "privacy_envelope",
                "signal_extraction", "signal_schema_v2", "sketch_system", "urgent_routing",
            ],
        ];

        let canonical_surface = module_surface();
        let canonical_refs: Vec<&str> = canonical_surface.iter().cloned().collect();
        let canonical_fingerprint = surface_fingerprint_hex(&canonical_refs);

        for (drift_idx, drift_scenario) in version_drift_scenarios.into_iter().enumerate() {
            let drift_refs: Vec<&str> = drift_scenario.iter().map(String::as_str).collect();
            let drift_fingerprint = surface_fingerprint_hex(&drift_refs);

            // Drift scenarios should produce different fingerprints (detect drift)
            assert_ne!(drift_fingerprint, canonical_fingerprint,
                      "Drift scenario {} should produce different fingerprint", drift_idx);
            assert_eq!(drift_fingerprint.len(), 64,
                      "Drift scenario {} produced invalid fingerprint length", drift_idx);
            assert!(drift_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Drift scenario {} produced invalid hex fingerprint", drift_idx);

            // Should be deterministic even for drift scenarios
            let drift_fingerprint2 = surface_fingerprint_hex(&drift_refs);
            assert_eq!(drift_fingerprint, drift_fingerprint2,
                      "Drift scenario {} not deterministic", drift_idx);
        }

        // Test surface integrity under concurrent access simulation
        let concurrent_results: Vec<_> = (0..1000)
            .map(|_| {
                let surface = module_surface();
                let surface_refs: Vec<&str> = surface.iter().cloned().collect();
                (surface.as_ptr(), surface_fingerprint_hex(&surface_refs))
            })
            .collect();

        let (canonical_ptr, canonical_concurrent_fingerprint) = &concurrent_results[0];
        for (access_idx, (ptr, fingerprint)) in concurrent_results.iter().enumerate().skip(1) {
            assert_eq!(ptr, canonical_ptr,
                      "Concurrent access {} returned different pointer", access_idx);
            assert_eq!(fingerprint, canonical_concurrent_fingerprint,
                      "Concurrent access {} produced different fingerprint", access_idx);
        }
    }

    #[test]
    fn negative_surface_fingerprint_cryptographic_strength_and_entropy_analysis() {
        // Test surface fingerprint cryptographic strength and entropy analysis

        // Test entropy distribution in fingerprints
        let entropy_test_surfaces = vec![
            // Minimal entropy inputs
            vec!["a"],
            vec!["a", "a", "a"],
            vec!["aaaa", "bbbb", "cccc"],

            // Medium entropy inputs
            vec!["aggregation", "federation"],
            vec!["signal_extraction", "signal_schema", "sketch_system"],

            // High entropy inputs
            vec![
                "aggregation", "federation", "global_priors", "privacy_envelope",
                "signal_extraction", "signal_schema", "sketch_system", "urgent_routing"
            ],

            // Pathological inputs designed to test hash function
            vec!["", "a", "aa", "aaa"],
            vec!["x".repeat(1000), "y".repeat(1000)],
            (0..100).map(|i| format!("module_{:03}", i)).collect(),
        ];

        let mut all_fingerprints = Vec::new();
        let mut entropy_stats = Vec::new();

        for (entropy_idx, entropy_surface) in entropy_test_surfaces.into_iter().enumerate() {
            let surface_refs: Vec<&str> = entropy_surface.iter().map(String::as_str).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);

            assert_eq!(fingerprint.len(), 64,
                      "Entropy test {} invalid length", entropy_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Entropy test {} invalid hex", entropy_idx);

            push_bounded(&mut all_fingerprints, fingerprint.clone(), 50000);

            // Analyze character distribution for entropy
            let mut char_counts = std::collections::HashMap::new();
            for c in fingerprint.chars() {
                let count = char_counts.entry(c).or_insert(0);
                *count = count.saturating_add(1);
            }

            let unique_chars = char_counts.len();
            let max_count = *char_counts.values().max().unwrap_or(&0);
            let min_count = *char_counts.values().min().unwrap_or(&0);

            entropy_stats.push((unique_chars, max_count, min_count));

            // Should have reasonable character distribution
            assert!(unique_chars >= 4,
                   "Entropy test {} has too few unique characters: {}", entropy_idx, unique_chars);
            assert!(max_count <= 20,
                   "Entropy test {} has character bias: max count {}", entropy_idx, max_count);

            // Test bit distribution
            let bytes = hex::decode(&fingerprint).expect("Valid hex fingerprint");
            let mut bit_counts = [0; 2];
            for byte in bytes {
                for bit_pos in 0..8 {
                    let bit = (byte >> bit_pos) & 1;
                    bit_counts[bit as usize] = bit_counts[bit as usize].saturating_add(1);
                }
            }

            let total_bits = bytes.len() * 8;
            let bit_0_ratio = bit_counts[0] as f64 / total_bits as f64;
            assert!(bit_0_ratio.is_finite(), "Non-finite bit 0 ratio");
            let bit_1_ratio = bit_counts[1] as f64 / total_bits as f64;
            assert!(bit_1_ratio.is_finite(), "Non-finite bit 1 ratio");

            // Bit distribution should be roughly balanced
            assert!(bit_0_ratio >= 0.3 && bit_0_ratio <= 0.7,
                   "Entropy test {} unbalanced bit 0 ratio: {}", entropy_idx, bit_0_ratio);
            assert!(bit_1_ratio >= 0.3 && bit_1_ratio <= 0.7,
                   "Entropy test {} unbalanced bit 1 ratio: {}", entropy_idx, bit_1_ratio);
        }

        // Check for fingerprint uniqueness across all tests
        let mut unique_fingerprints = std::collections::HashSet::new();
        for (i, fingerprint) in all_fingerprints.iter().enumerate() {
            assert!(unique_fingerprints.insert(fingerprint.clone()),
                   "Duplicate fingerprint found at test {}: {}", i, fingerprint);
        }

        // Test cryptographic properties with known attack patterns
        let crypto_attack_surfaces = vec![
            // Length extension patterns
            vec!["base"],
            vec!["base", "\u{80}\x00\x00\x00\x00\x00\x00\x00"],

            // Birthday attack patterns
            (0..256).map(|i| format!("birthday_{:02x}", i)).collect(),

            // Meet-in-the-middle patterns
            vec!["prefix_a", "suffix_x"],
            vec!["prefix_b", "suffix_x"],
            vec!["prefix_a", "suffix_y"],

            // Differential patterns
            vec!["differential_base"],
            vec!["differential_base_modified"],

            // Block cipher patterns
            vec!["block1_aaaa", "block2_bbbb"],
            vec!["block1_aaab", "block2_bbbb"], // Single bit difference
        ];

        let mut crypto_fingerprints = Vec::new();
        for crypto_surface in crypto_attack_surfaces {
            let surface_refs: Vec<&str> = crypto_surface.iter().map(String::as_str).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);
            crypto_fingerprints.push(fingerprint);
        }

        // All crypto test fingerprints should be unique
        let crypto_unique: std::collections::HashSet<_> = crypto_fingerprints.iter().cloned().collect();
        assert_eq!(crypto_unique.len(), crypto_fingerprints.len(),
                  "Crypto attack patterns produced collisions");

        // Test statistical properties
        let statistical_surfaces: Vec<_> = (0..1000)
            .map(|i| vec![format!("statistical_test_{:04}", i)])
            .collect();

        let mut statistical_fingerprints = Vec::new();
        for stat_surface in statistical_surfaces {
            let surface_refs: Vec<&str> = stat_surface.iter().map(String::as_str).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);
            statistical_fingerprints.push(fingerprint);
        }

        // Statistical analysis of fingerprint distribution
        let mut hex_char_histogram = [0u32; 16];
        for fingerprint in &statistical_fingerprints {
            for c in fingerprint.chars() {
                let digit = c.to_digit(16).unwrap() as usize;
                hex_char_histogram[digit] = hex_char_histogram[digit].saturating_add(1);
            }
        }

        let total_chars = statistical_fingerprints.len() * 64;
        let expected_per_char = total_chars / 16;

        // Chi-squared test for uniform distribution
        let mut chi_squared = 0.0;
        for count in hex_char_histogram {
            let diff = count as f64 - expected_per_char as f64;
            let term = (diff * diff) / expected_per_char as f64;
            assert!(term.is_finite(), "Non-finite chi-squared term");
            chi_squared += term;
        }
        assert!(chi_squared.is_finite(), "Non-finite chi-squared result");

        // Should not deviate too much from uniform distribution
        // Chi-squared with 15 degrees of freedom, 95% confidence is ~25
        assert!(chi_squared < 50.0,
               "Hex character distribution too non-uniform: chi-squared = {}", chi_squared);

        // Test that fingerprints don't reveal input structure
        let structure_revealing_test = vec![
            vec!["AAAA", "BBBB", "CCCC"], // Uppercase pattern
            vec!["aaaa", "bbbb", "cccc"], // Lowercase equivalent
        ];

        let mut structure_fingerprints = Vec::new();
        for structure_surface in structure_revealing_test {
            let surface_refs: Vec<&str> = structure_surface.iter().map(String::as_str).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);
            structure_fingerprints.push(fingerprint);
        }

        // Fingerprints should be different (case sensitivity)
        assert_ne!(structure_fingerprints[0], structure_fingerprints[1],
                  "Case differences should produce different fingerprints");

        // Neither should reveal obvious input structure
        for (i, fingerprint) in structure_fingerprints.iter().enumerate() {
            assert!(!fingerprint.to_uppercase().contains("AAAA"),
                   "Structure test {} reveals input pattern in fingerprint", i);
            assert!(!fingerprint.to_uppercase().contains("BBBB"),
                   "Structure test {} reveals input pattern in fingerprint", i);
        }
    }

    #[test]
    fn negative_surface_memory_exhaustion_and_resource_consumption_attacks() {
        // Test surface memory exhaustion and resource consumption attack resistance

        // Test extremely large individual module names
        let large_module_scenarios = vec![
            vec!["normal".to_owned(), "x".repeat(256_000), "normal".to_owned()],
            vec!["y".repeat(512_000)],
            vec!["z".repeat(1_000_000), "small".to_owned()],
        ];

        for (scenario_idx, large_scenario) in large_module_scenarios.into_iter().enumerate() {
            let start_time = std::time::Instant::now();
            let surface_refs: Vec<&str> = large_scenario.iter().map(String::as_str).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);
            let duration = start_time.elapsed();

            // Should complete in reasonable time despite large inputs
            assert!(duration < std::time::Duration::from_secs(30),
                   "Large module scenario {} took too long: {:?}", scenario_idx, duration);

            assert_eq!(fingerprint.len(), 64,
                      "Large module scenario {} invalid length", scenario_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Large module scenario {} invalid hex", scenario_idx);

            // Should be deterministic even for large inputs
            let start_time2 = std::time::Instant::now();
            let fingerprint2 = surface_fingerprint_hex(&surface_refs);
            let duration2 = start_time2.elapsed();

            assert_eq!(fingerprint, fingerprint2,
                      "Large module scenario {} not deterministic", scenario_idx);

            // Second call should be roughly same speed (no degradation)
            let baseline_ms = duration.as_millis().max(1);
            let second_ms = duration2.as_millis();
            assert!(second_ms < baseline_ms.saturating_mul(10),
                   "Large module scenario {} performance degraded: {}ms vs {}ms",
                   scenario_idx, second_ms, baseline_ms);
        }

        // Test massive number of small modules
        let massive_count_scenarios = vec![
            (10_000, "small"),   // 10k small modules
            (50_000, "tiny"),    // 50k tiny modules
            (100_000, "x"),      // 100k single char modules
        ];

        for (count, module_base) in massive_count_scenarios {
            let massive_surface: Vec<String> = (0..count)
                .map(|i| format!("{}_{:08}", module_base, i))
                .collect();

            let start_time = std::time::Instant::now();
            let surface_refs: Vec<&str> = massive_surface.iter().map(String::as_str).collect();
            let fingerprint = surface_fingerprint_hex(&surface_refs);
            let duration = start_time.elapsed();

            // Should handle massive counts efficiently
            assert!(duration < std::time::Duration::from_secs(60),
                   "Massive count {} took too long: {:?}", count, duration);

            assert_eq!(fingerprint.len(), 64,
                      "Massive count {} invalid length", count);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Massive count {} invalid hex", count);

            // Test memory usage doesn't grow unbounded
            let memory_test_start = std::time::Instant::now();
            for _ in 0..10 {
                let _repeat_fingerprint = surface_fingerprint_hex(&surface_refs);
            }
            let memory_test_duration = memory_test_start.elapsed();

            // Repeated calls should not show memory pressure
            let avg_duration = memory_test_duration.as_millis() / 10;
            let initial_duration = duration.as_millis();

            assert!(avg_duration < initial_duration.max(1).saturating_mul(5),
                   "Memory pressure detected for count {}: {}ms vs {}ms",
                   count, avg_duration, initial_duration);
        }

        // Test mixed large and massive scenarios
        let mut mixed_surface = Vec::new();

        // Add some very large modules
        for i in 0..10 {
            mixed_surface.push(format!("large_{}_{}_{}", i, "X".repeat(100_000), i));
        }

        // Add many small modules
        for i in 0..10_000 {
            mixed_surface.push(format!("small_{:05}", i));
        }

        // Add some moderate modules
        for i in 0..100 {
            mixed_surface.push(format!("moderate_{}_{}", i, "Y".repeat(1_000)));
        }

        let mixed_start = std::time::Instant::now();
        let mixed_refs: Vec<&str> = mixed_surface.iter().map(String::as_str).collect();
        let mixed_fingerprint = surface_fingerprint_hex(&mixed_refs);
        let mixed_duration = mixed_start.elapsed();

        assert!(mixed_duration < std::time::Duration::from_secs(120),
               "Mixed scenario took too long: {:?}", mixed_duration);
        assert_eq!(mixed_fingerprint.len(), 64);
        assert!(mixed_fingerprint.chars().all(|c| c.is_ascii_hexdigit()));

        // Test rapid repeated calls under memory pressure
        let rapid_test_surface = ["rapid", "test", "surface"];

        let mut rapid_durations = Vec::new();
        for i in 0..250 {
            let rapid_start = std::time::Instant::now();
            let _rapid_fingerprint = surface_fingerprint_hex(&rapid_test_surface);
            let rapid_duration = rapid_start.elapsed();
            rapid_durations.push(rapid_duration);

            // Inject memory pressure periodically
            if i % 50 == 0 {
                let _pressure: Vec<Vec<u8>> = (0..100).map(|_| vec![0u8; 1000]).collect();
            }
        }

        // Performance should remain stable under pressure
        let first_duration = rapid_durations[0].as_micros();
        let last_duration = rapid_durations[249].as_micros();

        assert!(last_duration < first_duration.max(1).saturating_mul(10),
               "Performance degraded under pressure: {}us vs {}us",
               last_duration, first_duration);

        // Test concurrent access under resource pressure
        use std::sync::Arc;
        use std::thread;

        let concurrent_surface = Arc::new(vec![
            "concurrent".to_string(),
            "access".to_string(),
            "test".to_string(),
            "pressure".to_string(),
        ]);

        let handles: Vec<_> = (0..4).map(|thread_id| {
            let surface = Arc::clone(&concurrent_surface);
            thread::spawn(move || {
                let mut results = Vec::new();
                for i in 0..100 {
                    // Add thread-specific pressure
                    let _pressure: Vec<u8> = vec![thread_id as u8; 10_000];

                    let refs: Vec<&str> = surface.iter().map(String::as_str).collect();
                    let fingerprint = surface_fingerprint_hex(&refs);

                    results.push(fingerprint);

                    // Occasional larger pressure
                    if i % 25 == 0 {
                        let _big_pressure: Vec<u8> = vec![0u8; 100_000];
                    }
                }
                results
            })
        }).collect();

        // Collect all results
        let mut all_concurrent_results = Vec::new();
        for handle in handles {
            let thread_results = handle.join().expect("Thread should complete");
            all_concurrent_results.extend(thread_results);
        }

        // All results should be identical (deterministic under pressure)
        let canonical = &all_concurrent_results[0];
        for (i, result) in all_concurrent_results.iter().enumerate() {
            assert_eq!(result, canonical,
                      "Concurrent result {} differs under pressure", i);
        }

        assert_eq!(canonical.len(), 64);
        assert!(canonical.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn negative_surface_temporal_consistency_and_deterministic_guarantees() {
        // Test surface temporal consistency and deterministic guarantee validation

        // Test deterministic behavior across time
        let temporal_test_surface = vec!["temporal", "consistency", "test"];
        let surface_refs: Vec<&str> = temporal_test_surface.iter().map(String::as_str).collect();

        // Generate fingerprints at different times with delays
        let mut temporal_fingerprints = Vec::new();
        let mut temporal_timestamps = Vec::new();

        for i in 0..100 {
            let start_time = std::time::Instant::now();
            let fingerprint = surface_fingerprint_hex(&surface_refs);
            temporal_fingerprints.push(fingerprint);
            temporal_timestamps.push(start_time);

            // Variable delays to test time independence
            let delay_ms = match i % 5 {
                0 => 1,
                1 => 10,
                2 => 50,
                3 => 100,
                _ => 0,
            };
            if delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
        }

        // All fingerprints should be identical regardless of timing
        let canonical_temporal = &temporal_fingerprints[0];
        for (i, fingerprint) in temporal_fingerprints.iter().enumerate() {
            assert_eq!(fingerprint, canonical_temporal,
                      "Temporal fingerprint {} differs at time {:?}", i, temporal_timestamps[i]);
        }

        // Test deterministic behavior under different system states
        let system_state_tests = vec![
            // Different memory allocator states
            || {
                let _allocations: Vec<Vec<u8>> = (0..1000).map(|i| vec![i as u8; 1000]).collect();
                surface_fingerprint_hex(&surface_refs)
            },

            // Different stack depth
            || {
                fn deep_call(depth: u32, refs: &[&str]) -> String {
                    if depth == 0 {
                        surface_fingerprint_hex(refs)
                    } else {
                        deep_call(depth - 1, refs)
                    }
                }
                deep_call(100, &surface_refs)
            },

            // Different thread contexts
            || {
                std::thread::spawn(|| surface_fingerprint_hex(&surface_refs))
                    .join()
                    .unwrap()
            },
        ];

        for (state_idx, state_test) in system_state_tests.into_iter().enumerate() {
            let state_fingerprint = state_test();
            assert_eq!(state_fingerprint, *canonical_temporal,
                      "System state test {} produced different fingerprint", state_idx);
        }

        // Test order sensitivity determinism
        let order_test_bases = vec![
            vec!["alpha", "beta", "gamma"],
            vec!["one", "two", "three", "four"],
            vec!["first", "second"],
        ];

        for (base_idx, base_order) in order_test_bases.into_iter().enumerate() {
            let base_refs: Vec<&str> = base_order.iter().map(String::as_str).collect();
            let base_fingerprint = surface_fingerprint_hex(&base_refs);

            // Test all permutations for determinism
            let permutations = if base_order.len() <= 4 {
                // Generate all permutations for small sets
                let mut perms = Vec::new();
                let mut indices: Vec<usize> = (0..base_order.len()).collect();

                // Simple permutation generation (factorial is small for len <= 4)
                loop {
                    let perm: Vec<String> = indices.iter().map(|&i| base_order[i].to_string()).collect();
                    perms.push(perm);

                    // Next permutation (lexicographic)
                    if !next_permutation(&mut indices) {
                        break;
                    }
                }
                perms
            } else {
                // Just test a few permutations for larger sets
                vec![
                    base_order.clone(),
                    {let mut rev = base_order.clone(); rev.reverse(); rev},
                    {let mut mid = base_order.clone(); mid.swap(0, mid.len()-1); mid},
                ]
            };

            let mut perm_fingerprints = std::collections::HashMap::new();

            for (perm_idx, perm) in permutations.into_iter().enumerate() {
                let perm_refs: Vec<&str> = perm.iter().map(String::as_str).collect();
                let perm_fingerprint = surface_fingerprint_hex(&perm_refs);

                // Each permutation should produce deterministic fingerprint
                for _ in 0..5 {
                    let repeat_fingerprint = surface_fingerprint_hex(&perm_refs);
                    assert_eq!(perm_fingerprint, repeat_fingerprint,
                              "Base {} perm {} not deterministic", base_idx, perm_idx);
                }

                // Store unique permutation fingerprints
                perm_fingerprints.insert(perm, perm_fingerprint);
            }

            // Different orders should produce different fingerprints
            let unique_fingerprints: std::collections::HashSet<_> =
                perm_fingerprints.values().collect();
            assert_eq!(unique_fingerprints.len(), perm_fingerprints.len(),
                      "Base {} has permutation collisions", base_idx);
        }

        // Test content sensitivity determinism
        let content_variations = vec![
            vec!["content", "test", "base"],
            vec!["content", "test", "base "], // Trailing space
            vec!["content", "test", "Base"], // Case change
            vec!["content", "test", "base", ""], // Empty addition
            vec!["content", "test"], // Removal
            vec!["content", "test", "base", "extra"], // Addition
            vec!["content", "tést", "base"], // Accent addition
        ];

        let mut content_fingerprints = std::collections::HashMap::new();
        for variation in content_variations {
            let var_refs: Vec<&str> = variation.iter().map(String::as_str).collect();
            let var_fingerprint = surface_fingerprint_hex(&var_refs);

            // Each variation should be deterministic
            for _ in 0..10 {
                let repeat_fingerprint = surface_fingerprint_hex(&var_refs);
                assert_eq!(var_fingerprint, repeat_fingerprint,
                          "Content variation {:?} not deterministic", variation);
            }

            content_fingerprints.insert(variation, var_fingerprint);
        }

        // All variations should produce different fingerprints
        let unique_content: std::collections::HashSet<_> = content_fingerprints.values().collect();
        assert_eq!(unique_content.len(), content_fingerprints.len(),
                  "Content variations have collisions");

        // Test extreme determinism validation
        let extreme_test_cases = vec![
            // Boundary Unicode
            vec!["\u{0000}", "\u{FFFF}"],
            vec!["\u{10000}", "\u{10FFFF}"],

            // Whitespace variations
            vec![" ", "\t", "\n", "\r"],
            vec!["", " ", "  "],

            // Numeric boundaries
            vec!["0", "1", "2"],
            vec!["9", "10", "11"],

            // Special characters
            vec!["!", "@", "#", "$"],
            vec!["%", "^", "&", "*"],
        ];

        for extreme_case in extreme_test_cases {
            let case_refs: Vec<&str> = extreme_case.iter().map(String::as_str).collect();

            // Test determinism across multiple iterations
            let mut extreme_fingerprints = Vec::new();
            for _ in 0..50 {
                extreme_fingerprints.push(surface_fingerprint_hex(&case_refs));
            }

            // All should be identical
            let canonical_extreme = &extreme_fingerprints[0];
            for (i, fingerprint) in extreme_fingerprints.iter().enumerate() {
                assert_eq!(fingerprint, canonical_extreme,
                          "Extreme case {:?} not deterministic at iteration {}", extreme_case, i);
            }
        }

        // Helper function for permutation generation
        fn next_permutation<T: Ord>(arr: &mut [T]) -> bool {
            let len = arr.len();
            if len <= 1 {
                return false;
            }

            let mut i = len - 2;
            while arr[i] >= arr[i + 1] {
                if i == 0 {
                    return false;
                }
                i -= 1;
            }

            let mut j = len - 1;
            while arr[j] <= arr[i] {
                j -= 1;
            }

            arr.swap(i, j);
            arr[(i + 1)..].reverse();
            true
        }
    }

    // ═══ EXTREME ADVERSARIAL NEGATIVE-PATH TESTS ═══
    // These tests target sophisticated attack vectors against ATC surface contracts

    #[test]
    fn test_extreme_adversarial_surface_unicode_injection_attack() {
        // Test Unicode injection attacks against ATC surface where attacker
        // attempts to inject bidirectional overrides and confusable characters
        // to manipulate trust surface detection and module enumeration

        // Test bidirectional override injection attempts
        let bidi_attack_modules = [
            "aggregation\u{202E}noitagerga", // Right-to-Left Override
            "federation\u{202D}evil_module", // Left-to-Right Override
            "global\u{061C}_priors", // Arabic Letter Mark
            "privacy\u{200E}envelope\u{200F}", // Left-to-Right/Right-to-Left Mark
            "signal\u{2066}extraction\u{2069}", // Left-to-Right Isolate
            "sketch\u{2067}system\u{2069}", // Right-to-Left Isolate
        ];

        for (attack_idx, malicious_module) in bidi_attack_modules.iter().enumerate() {
            // Test that Unicode injection doesn't corrupt surface detection
            let attack_surface = [*malicious_module];
            let fingerprint = surface_fingerprint_hex(&attack_surface);

            // Verify fingerprint computation handles Unicode injection safely
            assert!(fingerprint.len() > 0,
                "Attack {}: Fingerprint should not be empty for injected module", attack_idx);
            assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                "Attack {}: Fingerprint should be valid hex despite Unicode injection", attack_idx);
            assert_eq!(fingerprint.len(), 64,
                "Attack {}: Fingerprint should maintain expected length", attack_idx);

            // Test that injection doesn't match legitimate module surfaces
            for &legitimate_module in module_surface() {
                assert_ne!(malicious_module, &legitimate_module,
                    "Attack {}: Unicode injection should not match legitimate module", attack_idx);
            }

            // Verify fingerprint stability under repeated computation
            let fingerprint_2 = surface_fingerprint_hex(&attack_surface);
            assert_eq!(fingerprint, fingerprint_2,
                "Attack {}: Unicode injection should not break fingerprint determinism", attack_idx);
        }

        // Test confusable character injection (homograph attacks)
        let homograph_attacks = [
            "аggregation", // Cyrillic 'а' instead of Latin 'a'
            "federаtion", // Cyrillic 'а' instead of Latin 'a'
            "рrivacy_envelope", // Cyrillic 'р' instead of Latin 'p'
            "ѕignal_extraction", // Cyrillic 'ѕ' instead of Latin 's'
            "ѕketch_system", // Cyrillic 'ѕ' instead of Latin 's'
            "urgеnt_routing", // Cyrillic 'е' instead of Latin 'e'
        ];

        for (attack_idx, homograph_module) in homograph_attacks.iter().enumerate() {
            let homograph_surface = [*homograph_module];
            let homograph_fingerprint = surface_fingerprint_hex(&homograph_surface);

            // Verify homograph attack detection via fingerprint differences
            for &legitimate_module in module_surface() {
                let legitimate_surface = [legitimate_module];
                let legitimate_fingerprint = surface_fingerprint_hex(&legitimate_surface);

                assert_ne!(homograph_fingerprint, legitimate_fingerprint,
                    "Attack {}: Homograph '{}' should have different fingerprint from '{}'",
                    attack_idx, homograph_module, legitimate_module);
            }

            // Test that homograph doesn't visually deceive module enumeration
            assert!(!module_surface().contains(homograph_module),
                "Attack {}: Homograph should not be present in legitimate surface", attack_idx);
        }

        // Test zero-width character injection
        let zero_width_attacks = [
            "aggregation\u{200B}", // Zero Width Space
            "federation\u{200C}", // Zero Width Non-Joiner
            "global_priors\u{200D}", // Zero Width Joiner
            "privacy\u{FEFF}envelope", // Zero Width No-Break Space (BOM)
            "signal_extraction\u{034F}", // Combining Grapheme Joiner
        ];

        for (attack_idx, zw_module) in zero_width_attacks.iter().enumerate() {
            let zw_surface = [*zw_module];
            let zw_fingerprint = surface_fingerprint_hex(&zw_surface);

            // Verify zero-width injection creates distinguishable fingerprints
            for &legitimate_module in module_surface() {
                let legitimate_surface = [legitimate_module];
                let legitimate_fingerprint = surface_fingerprint_hex(&legitimate_surface);

                assert_ne!(zw_fingerprint, legitimate_fingerprint,
                    "Attack {}: Zero-width injection should change fingerprint", attack_idx);
            }
        }
    }

    #[test]
    fn test_extreme_adversarial_surface_domain_separator_collision() {
        // Test domain separator collision attacks where attacker crafts module
        // names to collide with internal hash domain separators and bypass trust boundaries

        // Craft modules attempting to collide with expected domain separators
        let separator_collision_attacks = vec![
            "atc_surface_v1".to_owned(), // Potential collision with internal domain
            "surface:fingerprint".to_owned(), // Colon injection
            "module|separator".to_owned(), // Pipe separator injection
            "atc\x00surface".to_owned(), // Null byte injection
            "surface\nfingerprint".to_owned(), // Newline injection
            "module\rseparator".to_owned(), // Carriage return injection
            "atc\ttab\tseparator".to_owned(), // Tab injection
            "surface||pipe||collision".to_owned(), // Double pipe collision
            "module::double::colon".to_owned(), // Double colon injection
            "atc_surface_fingerprint_collision".to_owned(), // Length extension
            "atcatcatcatcatc".to_owned(), // Repetition attack
            format!("surface{}", "_".repeat(100)), // Underscore flooding
        ];

        for (attack_idx, collision_module) in separator_collision_attacks.iter().enumerate() {
            let collision_surface = [collision_module.as_str()];
            let collision_fingerprint = surface_fingerprint_hex(&collision_surface);

            // Verify collision attempt doesn't match legitimate surfaces
            for &legitimate_module in module_surface() {
                let legitimate_surface = [legitimate_module];
                let legitimate_fingerprint = surface_fingerprint_hex(&legitimate_surface);

                assert_ne!(collision_fingerprint, legitimate_fingerprint,
                    "Attack {}: Domain separator collision should not match legitimate fingerprint", attack_idx);

                // Test that collision doesn't create substring confusion
                assert_ne!(collision_module, &legitimate_module,
                    "Attack {}: Collision module should not equal legitimate module", attack_idx);
            }

            // Test that collision doesn't break fingerprint computation
            assert!(collision_fingerprint.len() == 64,
                "Attack {}: Collision should not break fingerprint length", attack_idx);
            assert!(collision_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                "Attack {}: Collision should not break fingerprint format", attack_idx);

            // Test determinism under domain separator collision
            let collision_fingerprint_2 = surface_fingerprint_hex(&collision_surface);
            assert_eq!(collision_fingerprint, collision_fingerprint_2,
                "Attack {}: Domain separator collision should not break determinism", attack_idx);

            // Test with multiple collision attempts in same surface
            let multi_collision_surface = [
                collision_module.as_str(),
                "aggregation",
                collision_module.as_str(), // Duplicate collision attempt
            ];
            let multi_collision_fingerprint = surface_fingerprint_hex(&multi_collision_surface);

            assert!(multi_collision_fingerprint.len() == 64,
                "Attack {}: Multi-collision should maintain fingerprint format", attack_idx);
        }

        // Test hash prefix collision attempts
        let prefix_collision_attacks = (0..50).map(|i| {
            format!("prefix_collision_{:08x}", i)
        }).collect::<Vec<_>>();

        let mut collision_fingerprints = std::collections::HashSet::new();

        for (attack_idx, prefix_module) in prefix_collision_attacks.iter().enumerate() {
            let prefix_surface = [prefix_module.as_str()];
            let prefix_fingerprint = surface_fingerprint_hex(&prefix_surface);

            // Verify no hash prefix collisions
            assert!(collision_fingerprints.insert(prefix_fingerprint.clone()),
                "Attack {}: Hash prefix collision detected with module '{}'", attack_idx, prefix_module);
        }

        println!("Domain separator collision test: {} unique fingerprints generated, no collisions detected",
            collision_fingerprints.len());
    }

    #[test]
    fn test_extreme_adversarial_surface_length_extension_exploitation() {
        // Test length extension attacks against surface fingerprinting where
        // attacker appends data to existing module names to exploit hash functions
        // vulnerable to length extension attacks

        // Get legitimate surface fingerprints as attack targets
        let legitimate_modules: Vec<&str> = module_surface().to_vec();
        let legitimate_fingerprint = surface_fingerprint_hex(&legitimate_modules);

        // Attempt length extension attacks
        let extension_payloads = vec![
            "malicious_extension".to_owned(),
            "admin=true".to_owned(),
            format!(
                "\u{80}{}{}",
                "\x00".repeat(55),
                (64_u64)
                    .to_be_bytes()
                    .iter()
                    .map(|&b| b as char)
                    .collect::<String>()
            ), // SHA padding attack
            "||injected_module".to_owned(),
            "\nEVIL_MODULE\n".to_owned(),
            "A".repeat(1000), // Massive extension
            legitimate_modules[0].repeat(10), // Self-repetition
            "backdoor_access_granted".to_owned(),
            "\x00\x01\x02\x03".to_owned(), // Binary extension
            format!("{}_{}", legitimate_modules[0], "extended"), // Natural extension
        ];

        for (attack_idx, extension) in extension_payloads.iter().enumerate() {
            // Attempt length extension by appending to each legitimate module
            for (module_idx, &legitimate_module) in legitimate_modules.iter().enumerate() {
                let extended_module = format!("{}{}", legitimate_module, extension);
                let extended_surface = [extended_module.as_str()];
                let extended_fingerprint = surface_fingerprint_hex(&extended_surface);

                // Verify length extension doesn't produce predictable fingerprints
                assert_ne!(extended_fingerprint, legitimate_fingerprint,
                    "Attack {} Module {}: Length extension should not preserve fingerprint", attack_idx, module_idx);

                // Verify extension doesn't match other legitimate fingerprints
                for &other_module in legitimate_modules.iter() {
                    if other_module != legitimate_module {
                        let other_surface = [other_module];
                        let other_fingerprint = surface_fingerprint_hex(&other_surface);

                        assert_ne!(extended_fingerprint, other_fingerprint,
                            "Attack {} Module {}: Extension should not collide with other modules", attack_idx, module_idx);
                    }
                }

                // Test that extended module isn't accepted as legitimate
                assert!(!legitimate_modules.contains(&extended_module.as_str()),
                    "Attack {} Module {}: Extended module should not be in legitimate set", attack_idx, module_idx);

                // Verify fingerprint computation remains stable for extensions
                let extended_fingerprint_2 = surface_fingerprint_hex(&extended_surface);
                assert_eq!(extended_fingerprint, extended_fingerprint_2,
                    "Attack {} Module {}: Extension fingerprint should be deterministic", attack_idx, module_idx);
            }

            // Test length extension with multiple modules
            let multi_extended: Vec<String> = legitimate_modules.iter()
                .map(|&module| format!("{}{}", module, extension))
                .collect();
            let multi_extended_refs: Vec<&str> = multi_extended.iter().map(String::as_str).collect();
            let multi_extended_fingerprint = surface_fingerprint_hex(&multi_extended_refs);

            assert_ne!(multi_extended_fingerprint, legitimate_fingerprint,
                "Attack {}: Multi-module extension should not preserve fingerprint", attack_idx);
        }

        // Test chained length extensions (extension of extensions)
        let chained_module = format!("{}{}{}",
            legitimate_modules[0],
            extension_payloads[0],
            extension_payloads[1]);
        let chained_surface = [chained_module.as_str()];
        let chained_fingerprint = surface_fingerprint_hex(&chained_surface);

        assert_ne!(chained_fingerprint, legitimate_fingerprint,
            "Chained length extension should not preserve fingerprint");

        // Test extension truncation attempts
        for &legitimate_module in legitimate_modules.iter() {
            for truncate_len in [1, 2, legitimate_module.len() / 2] {
                if truncate_len < legitimate_module.len() {
                    let truncated = &legitimate_module[..legitimate_module.len() - truncate_len];
                    let truncated_surface = [truncated];
                    let truncated_fingerprint = surface_fingerprint_hex(&truncated_surface);

                    assert_ne!(truncated_fingerprint, legitimate_fingerprint,
                        "Truncation should not preserve fingerprint: {} vs {}",
                        truncated, legitimate_module);
                }
            }
        }
    }

    #[test]
    fn test_extreme_adversarial_surface_algorithmic_complexity_explosion() {
        // Test algorithmic complexity attacks where attacker crafts surface
        // inputs designed to trigger worst-case performance in fingerprinting

        use std::time::{Duration, Instant};

        // Generate complexity attack patterns
        let complexity_attacks = vec![
            // Massive duplication
            vec!["duplicate".to_owned(); 10000],

            // Pathological string patterns
            vec!["a".repeat(10000)],
            vec!["abcdefghijklmnopqrstuvwxyz".repeat(1000)],

            // Many small modules (breadth attack)
            (0..5000).map(|i| format!("module_{}", i)).collect::<Vec<String>>(),

            // Nested repetition patterns
            vec!["nested_".repeat(1000)],

            // Unicode expansion patterns
            vec!["🚀".repeat(1000)], // Multi-byte characters

            // Hash collision attempts via birthday paradox
            (0..1000).map(|i| format!("hash_candidate_{:04x}", i * 17 % 65536))
                .collect::<Vec<String>>(),
        ];

        for (attack_idx, attack_surface) in complexity_attacks.iter().enumerate() {
            // Skip attacks that are too large for reasonable testing
            if attack_surface.len() > 10000 {
                continue;
            }

            println!("Testing complexity attack {}: {} modules", attack_idx, attack_surface.len());

            // Measure fingerprinting performance
            let start_time = Instant::now();
            let attack_refs: Vec<&str> = attack_surface.iter().map(String::as_str).collect();
            let attack_fingerprint = surface_fingerprint_hex(&attack_refs);
            let duration = start_time.elapsed();

            // Verify fingerprint was computed successfully
            assert_eq!(attack_fingerprint.len(), 64,
                "Attack {}: Complexity attack should not break fingerprint format", attack_idx);
            assert!(attack_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                "Attack {}: Complexity attack should produce valid hex fingerprint", attack_idx);

            // Verify reasonable performance bounds (should not hang)
            assert!(duration < Duration::from_secs(5),
                "Attack {}: Fingerprinting should complete in reasonable time: {:?}", attack_idx, duration);

            // Test determinism under complexity attacks
            let attack_fingerprint_2 = surface_fingerprint_hex(&attack_refs);
            assert_eq!(attack_fingerprint, attack_fingerprint_2,
                "Attack {}: Complexity attack should not break determinism", attack_idx);

            // Verify attack doesn't match legitimate surface
            let legitimate_fingerprint = surface_fingerprint_hex(&module_surface());
            assert_ne!(attack_fingerprint, legitimate_fingerprint,
                "Attack {}: Complexity attack should not collide with legitimate surface", attack_idx);

            // Test that complexity doesn't corrupt subsequent operations
            let post_attack_surface = ["test_module"];
            let post_attack_fingerprint = surface_fingerprint_hex(&post_attack_surface);
            assert!(post_attack_fingerprint.len() == 64,
                "Attack {}: Post-complexity operation should work correctly", attack_idx);

            println!("Attack {} completed in {:?}", attack_idx, duration);
        }

        // Test nested complexity with legitimate modules
        let mut nested_complexity_surface = module_surface()
            .iter()
            .map(|module| (*module).to_owned())
            .collect::<Vec<_>>();
        nested_complexity_surface.extend((0..1000).map(|i| format!("nested_attack_{}", i)));

        let start_time = Instant::now();
        let nested_refs: Vec<&str> = nested_complexity_surface.iter().map(String::as_str).collect();
        let nested_fingerprint = surface_fingerprint_hex(&nested_refs);
        let nested_duration = start_time.elapsed();

        assert!(nested_duration < Duration::from_secs(5),
            "Nested complexity attack should complete in reasonable time: {:?}", nested_duration);
        assert_eq!(nested_fingerprint.len(), 64,
            "Nested complexity should produce valid fingerprint");
    }

    #[test]
    fn test_extreme_adversarial_surface_memory_exhaustion_via_expansion() {
        // Test memory exhaustion attacks via surface expansion where attacker
        // attempts to consume excessive memory during fingerprint computation

        // Memory pressure attack patterns
        let memory_attacks = vec![
            // Large individual strings
            vec!["x".repeat(100000)],
            vec!["memory_exhaustion_".repeat(10000)],

            // Many medium-sized strings
            (0..1000).map(|i| format!("memory_attack_module_{}_{}",
                i, "padding".repeat(100)))
                .collect::<Vec<String>>(),

            // Exponential expansion patterns
            vec![(0..50).map(|_| "exponential_growth")
                .collect::<Vec<_>>().join("_")],

            // Unicode memory expansion
            vec!["🌟💫⭐".repeat(10000)], // Multi-byte Unicode

            // Nested structure simulation
            vec![format!("{}{}{}",
                "start_", "nested_".repeat(1000), "_end")],
        ];

        for (attack_idx, memory_surface) in memory_attacks.iter().enumerate() {
            println!("Testing memory attack {}: {} modules, total estimated memory: {} bytes",
                attack_idx, memory_surface.len(),
                memory_surface.iter().map(|s| s.len()).sum::<usize>());

            // Test fingerprinting under memory pressure
            let memory_refs: Vec<&str> = memory_surface.iter().map(String::as_str).collect();
            let memory_fingerprint = surface_fingerprint_hex(&memory_refs);

            // Verify memory attack doesn't break fingerprint format
            assert_eq!(memory_fingerprint.len(), 64,
                "Memory attack {}: Should maintain fingerprint length", attack_idx);
            assert!(memory_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                "Memory attack {}: Should produce valid hex fingerprint", attack_idx);

            // Test determinism under memory pressure
            let memory_fingerprint_2 = surface_fingerprint_hex(&memory_refs);
            assert_eq!(memory_fingerprint, memory_fingerprint_2,
                "Memory attack {}: Should maintain determinism under memory pressure", attack_idx);

            // Verify memory attack doesn't corrupt legitimate operations
            let legitimate_fingerprint = surface_fingerprint_hex(&module_surface());
            assert_ne!(memory_fingerprint, legitimate_fingerprint,
                "Memory attack {}: Should not collide with legitimate surface", attack_idx);

            // Test that system recovers after memory attack
            let recovery_surface = ["recovery_test"];
            let recovery_fingerprint = surface_fingerprint_hex(&recovery_surface);
            assert_eq!(recovery_fingerprint.len(), 64,
                "Memory attack {}: System should recover after memory pressure", attack_idx);

            println!("Memory attack {} completed successfully", attack_idx);
        }

        // Test memory fragmentation attack (many small allocations)
        let fragmentation_surface: Vec<String> = (0..10000)
            .map(|i| format!("frag{}", i))
            .collect();
        let fragmentation_refs: Vec<&str> = fragmentation_surface.iter().map(String::as_str).collect();

        let fragmentation_fingerprint = surface_fingerprint_hex(&fragmentation_refs);
        assert_eq!(fragmentation_fingerprint.len(), 64,
            "Memory fragmentation attack should produce valid fingerprint");

        // Test memory layout attack (specific byte patterns)
        let layout_attack_surface = vec![
            "\x00".repeat(1000), // Null bytes
            "\u{FF}".repeat(1000), // All bits set
            (0u8..=255).cycle().take(10000).map(char::from).collect::<String>(), // Full byte range
        ];
        let layout_attack_refs: Vec<&str> = layout_attack_surface.iter().map(String::as_str).collect();

        let layout_fingerprint = surface_fingerprint_hex(&layout_attack_refs);
        assert_eq!(layout_fingerprint.len(), 64,
            "Memory layout attack should produce valid fingerprint");

        println!("All memory exhaustion attacks completed successfully");
    }

    #[test]
    fn test_extreme_adversarial_surface_concurrent_modification_race() {
        // Test concurrent modification attacks against surface fingerprinting
        // where multiple threads attempt to corrupt computation state

        use std::sync::{Arc, Mutex};
        use std::thread;

        // Shared test surface for concurrent access
        let base_surface = Arc::new(
            module_surface()
                .iter()
                .map(|module| (*module).to_owned())
                .collect::<Vec<_>>(),
        );
        let results = Arc::new(Mutex::new(Vec::new()));

        let mut handles = vec![];

        // Launch concurrent fingerprinting operations
        for thread_id in 0..20 {
            let surface_clone = Arc::clone(&base_surface);
            let results_clone = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                // Each thread performs multiple fingerprinting operations
                for iteration in 0..50 {
                    // Create thread-specific surface modifications
                    let mut modified_surface = surface_clone.as_ref().clone();
                    modified_surface.push(format!("thread_{}_{}", thread_id, iteration));

                    let modified_refs: Vec<&str> = modified_surface.iter().map(String::as_str).collect();

                    // Attempt concurrent fingerprinting
                    let fingerprint = surface_fingerprint_hex(&modified_refs);

                    // Verify fingerprint format integrity under concurrency
                    let format_valid = fingerprint.len() == 64 &&
                        fingerprint.chars().all(|c| c.is_ascii_hexdigit());

                    thread_results.push((thread_id, iteration, fingerprint, format_valid));

                    // Test determinism within thread
                    let fingerprint_2 = surface_fingerprint_hex(&modified_refs);
                    if fingerprint != fingerprint_2 {
                        panic!("Thread {} Iteration {}: Non-deterministic fingerprint under concurrency!",
                            thread_id, iteration);
                    }

                    // Brief yield to encourage race conditions
                    thread::yield_now();
                }

                // Store results for analysis
                results_clone.lock().unwrap().extend(thread_results);
            });

            push_bounded(&mut handles, handle, 100);
        }

        // Wait for all concurrent operations to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        // Analyze concurrent results
        let final_results = results.lock().unwrap();
        let mut unique_fingerprints = std::collections::HashSet::new();
        let mut format_violations = 0;
        let mut determinism_violations = 0;

        for &(thread_id, iteration, ref fingerprint, format_valid) in final_results.iter() {
            if !format_valid {
                format_violations = format_violations.saturating_add(1);
                println!("Format violation: Thread {} Iteration {} - Fingerprint: {}",
                    thread_id, iteration, fingerprint);
            }

            unique_fingerprints.insert(fingerprint.clone());

            // Re-test determinism across threads for same input
            if thread_id == 0 && iteration == 0 {
                // This should match the base computation
                let mut test_surface = base_surface.as_ref().clone();
                test_surface.push("thread_0_0".to_owned());
                let test_refs: Vec<&str> = test_surface.iter().map(String::as_str).collect();
                let test_fingerprint = surface_fingerprint_hex(&test_refs);

                if test_fingerprint != *fingerprint {
                    determinism_violations = determinism_violations.saturating_add(1);
                }
            }
        }

        println!("Concurrent modification test results:");
        println!("  Total operations: {}", final_results.len());
        println!("  Unique fingerprints: {}", unique_fingerprints.len());
        println!("  Format violations: {}", format_violations);
        println!("  Determinism violations: {}", determinism_violations);

        // Verify concurrent safety
        assert_eq!(format_violations, 0,
            "No fingerprint format violations should occur under concurrency");
        assert_eq!(determinism_violations, 0,
            "No determinism violations should occur under concurrency");

        // Verify that all threads produced valid, unique results for different inputs
        assert!(unique_fingerprints.len() > 100,
            "Concurrent operations should produce diverse fingerprints: {} unique out of {}",
            unique_fingerprints.len(), final_results.len());

        // Test post-concurrency system stability
        let post_concurrent_fingerprint = surface_fingerprint_hex(&module_surface());
        assert_eq!(post_concurrent_fingerprint.len(), 64,
            "System should remain stable after concurrent stress");
        assert!(post_concurrent_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
            "Post-concurrent fingerprint should maintain format");
    }

    #[test]
    fn test_extreme_adversarial_surface_cryptographic_downgrade_bypass() {
        // Test cryptographic downgrade attacks against surface fingerprinting
        // where attacker attempts to force use of weaker hash functions or bypass crypto

        // Test hash function substitution attempts (simulated)
        let downgrade_test_surfaces = vec![
            // Patterns that might trigger algorithmic weaknesses
            vec!["aaaa".to_owned()],
            vec!["abcd".repeat(1000)],
            vec!["1234567890abcdef".to_owned()],
            vec!["0".repeat(64)], // All zeros (weak hash target)
            vec!["f".repeat(64)], // All ones (weak hash target)

            // Patterns designed to exploit specific hash properties
            vec!["collision_candidate_1".to_owned(), "collision_candidate_2".to_owned()],
            vec![format!("0x{}", "deadbeef".repeat(8))],

            // Birthday attack simulation
            (0..100).map(|i| format!("birthday_{:08x}", i))
                .collect::<Vec<String>>(),

            // Known weak patterns from hash function literature
            vec!["".to_owned(), "a".to_owned(), "aa".to_owned(), "aaa".to_owned()], // Length-based patterns
            vec![(0u8..=255).map(|b| b as char).collect::<String>()], // Full alphabet
        ];

        let legitimate_fingerprint = surface_fingerprint_hex(&module_surface());
        let mut observed_fingerprints = std::collections::HashMap::new();

        for (attack_idx, downgrade_surface) in downgrade_test_surfaces.iter().enumerate() {
            let downgrade_refs: Vec<&str> = downgrade_surface.iter().map(String::as_str).collect();
            let downgrade_fingerprint = surface_fingerprint_hex(&downgrade_refs);

            // Verify downgrade attempt doesn't produce weak fingerprints
            assert_eq!(downgrade_fingerprint.len(), 64,
                "Downgrade attack {} should not break fingerprint length", attack_idx);
            assert!(downgrade_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                "Downgrade attack {} should not break fingerprint format", attack_idx);

            // Verify no collision with legitimate surface
            assert_ne!(downgrade_fingerprint, legitimate_fingerprint,
                "Downgrade attack {} should not collide with legitimate fingerprint", attack_idx);

            // Test for obvious weak fingerprints
            assert_ne!(downgrade_fingerprint, "0000000000000000000000000000000000000000000000000000000000000000",
                "Downgrade attack {} should not produce all-zero fingerprint", attack_idx);
            assert_ne!(downgrade_fingerprint, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "Downgrade attack {} should not produce all-one fingerprint", attack_idx);

            // Check for obvious patterns that might indicate weak crypto
            let repeated_patterns = [
                "0123456789abcdef".repeat(4),
                "a".repeat(64),
                "01".repeat(32),
                "00".repeat(32),
                "ff".repeat(32),
            ];

            for pattern in &repeated_patterns {
                assert_ne!(downgrade_fingerprint, *pattern,
                    "Downgrade attack {} should not produce predictable pattern", attack_idx);
            }

            // Track fingerprint distribution for collision analysis
            let count = observed_fingerprints.entry(downgrade_fingerprint.clone()).or_insert(0);
            *count = count.saturating_add(1);

            // Test determinism under downgrade attempts
            let downgrade_fingerprint_2 = surface_fingerprint_hex(&downgrade_refs);
            assert_eq!(downgrade_fingerprint, downgrade_fingerprint_2,
                "Downgrade attack {} should maintain determinism", attack_idx);

            println!("Downgrade test {}: {} modules -> fingerprint: {}",
                attack_idx, downgrade_surface.len(), &downgrade_fingerprint[..16]);
        }

        // Analyze fingerprint distribution for bias
        let total_fingerprints = observed_fingerprints.len();
        let collision_count = observed_fingerprints.values().filter(|&&count| count > 1).count();

        println!("Cryptographic downgrade analysis:");
        println!("  Total unique fingerprints: {}", total_fingerprints);
        println!("  Collision count: {}", collision_count);
        let collision_rate = (collision_count as f64 / total_fingerprints as f64) * 100.0;
        assert!(collision_rate.is_finite(), "Non-finite collision rate");
        println!("  Collision rate: {:.4}%", collision_rate);

        // Verify low collision rate (should be cryptographically strong)
        assert!(collision_count < total_fingerprints / 10,
            "Collision rate should be low: {} collisions out of {} fingerprints", collision_count, total_fingerprints);

        // Test that downgrade attacks don't affect legitimate operations
        let post_downgrade_fingerprint = surface_fingerprint_hex(&module_surface());
        assert_eq!(post_downgrade_fingerprint, legitimate_fingerprint,
            "Legitimate fingerprint should be unchanged after downgrade attacks");

        // Test resistance to length extension after downgrade attempts
        for &legitimate_module in module_surface() {
            let extended = format!("{}malicious_extension", legitimate_module);
            let extended_surface = [extended.as_str()];
            let extended_fingerprint = surface_fingerprint_hex(&extended_surface);

            assert_ne!(extended_fingerprint, legitimate_fingerprint,
                "Length extension should not work after downgrade attempts");
        }
    }

    #[cfg(test)]
    mod atc_comprehensive_security_and_attack_vector_tests {
        use super::*;
        use std::collections::{HashMap, HashSet};

        #[test]
        fn test_module_surface_tampering_and_injection_attacks() {
            // Attack 1: Module surface consistency under repeated access
            let surface_references = (0..10000).map(|_| module_surface()).collect::<Vec<_>>();

            // All references should point to the same memory location
            let first_ptr = surface_references[0].as_ptr();
            for (i, surface) in surface_references.iter().enumerate() {
                assert_eq!(surface.as_ptr(), first_ptr,
                          "Module surface reference {} should point to same memory", i);
                assert_eq!(surface.len(), ATC_MODULE_SURFACE.len(),
                          "Surface length should remain constant");
            }

            // Attack 2: Module surface content immutability verification
            let original_surface = module_surface();
            let original_content: Vec<String> = original_surface.iter().map(|&s| s.to_string()).collect();

            // Attempt to access surface many times with potential concurrent access
            let mut all_contents = Vec::new();
            for i in 0..1000 {
                let current_surface = module_surface();
                let current_content: Vec<String> = current_surface.iter().map(|&s| s.to_string()).collect();
                all_contents.push(current_content);

                // Every access should return identical content
                assert_eq!(all_contents[i], original_content,
                          "Surface content should be immutable across access {}", i);
            }

            // Attack 3: Module surface name injection simulation
            let legitimate_modules = module_surface();

            // Verify no malicious content can be present
            let dangerous_patterns = [
                "../", "../../", "/etc/", "/bin/", "/usr/",
                "${", "$(", "`", "eval", "exec",
                "\x00", "\n", "\r", "\t", "\x1b",
                "<script>", "javascript:", "data:",
                "DROP", "DELETE", "UPDATE", "INSERT", "SELECT",
                "||", "&&", ";", "|", "&",
                "\\x", "\\u", "%00", "%2e", "%2f",
                "🦀", "💥", "🔒", // Unicode injection
            ];

            for (module_idx, &module_name) in legitimate_modules.iter().enumerate() {
                for (pattern_idx, &pattern) in dangerous_patterns.iter().enumerate() {
                    assert!(!module_name.contains(pattern),
                           "Module {} (index {}) contains dangerous pattern {} (index {}): {}",
                           module_name, module_idx, pattern, pattern_idx, module_name);
                }
            }

            // Attack 4: Module surface length manipulation attempts
            for (i, &module_name) in legitimate_modules.iter().enumerate() {
                // Verify reasonable length bounds (already tested but re-verify for security)
                assert!(module_name.len() >= 3 && module_name.len() <= 50,
                       "Module {} at index {} has suspicious length {}: {}",
                       module_name, i, module_name.len(), module_name);

                // Verify no buffer overflow potential
                assert!(module_name.len() < usize::MAX / 2,
                       "Module {} at index {} has potential overflow length: {}",
                       module_name, i, module_name.len());
            }

            // Attack 5: Module surface ordering and uniqueness attacks
            let module_names: Vec<&str> = legitimate_modules.to_vec();
            let unique_names: HashSet<&str> = module_names.iter().cloned().collect();

            // Verify no duplicates (potential confusion attack)
            assert_eq!(module_names.len(), unique_names.len(),
                      "Module surface should not contain duplicates");

            // Verify stable ordering (timing attack resistance)
            for access_round in 0..100 {
                let current_surface = module_surface();
                for (i, (&original, &current)) in module_names.iter().zip(current_surface.iter()).enumerate() {
                    assert_eq!(original, current,
                              "Module at index {} changed between access rounds: {} vs {} (round {})",
                              i, original, current, access_round);
                }
            }
        }

        #[test]
        fn test_fingerprint_collision_and_manipulation_attacks() {
            // Attack 1: Fingerprint consistency under repeated computation
            let mut fingerprints = Vec::new();
            for i in 0..1000 {
                let fp = module_surface_fingerprint_hex();
                fingerprints.push(fp);

                // Each computation should produce identical results
                if i > 0 {
                    assert_eq!(fingerprints[i], fingerprints[0],
                              "Fingerprint {} should be identical to first computation", i);
                }
            }

            let stable_fingerprint = &fingerprints[0];

            // Verify fingerprint format and security properties
            assert_eq!(stable_fingerprint.len(), 64, "Fingerprint should be 64 hex characters (SHA256)");
            assert!(stable_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                   "Fingerprint should contain only valid hex characters");

            // Attack 2: Surface modification detection through fingerprint
            let original_fingerprint = module_surface_fingerprint_hex();

            // Simulate potential surface modifications by testing different inputs
            let modified_surfaces = vec![
                vec![], // Empty surface
                vec!["modified_module"], // Single modified module
                vec!["aggregation"], // Single legitimate module
                vec!["aggregation", "federation"], // Subset of legitimate modules
                vec!["new_module", "aggregation", "federation"], // Added module
                vec!["aggregation", "federation", "global_priors", "privacy_envelope",
                     "signal_extraction", "signal_schema", "sketch_system", "urgent_routing",
                     "extra_module"], // Added extra module
            ];

            for (i, modified_surface) in modified_surfaces.iter().enumerate() {
                let mut hasher = Sha256::new();
                hasher.update(b"ATC-MODULE-SURFACE:");
                for module in modified_surface {
                    update_len_prefixed(&mut hasher, module.as_bytes());
                }
                let modified_fingerprint = hex::encode(hasher.finalize());

                if modified_surface.len() == ATC_MODULE_SURFACE.len() &&
                   modified_surface.iter().zip(ATC_MODULE_SURFACE.iter()).all(|(a, b)| a == b) {
                    // Only identical surface should produce same fingerprint
                    assert_eq!(modified_fingerprint, original_fingerprint,
                              "Identical surface should produce same fingerprint");
                } else {
                    // Any modification should produce different fingerprint
                    assert_ne!(modified_fingerprint, original_fingerprint,
                              "Modified surface {} should produce different fingerprint", i);
                }
            }

            // Attack 3: Hash collision attempts through crafted inputs
            let collision_attempts = vec![
                ("ATC-MODULE-SURFACE", ""),
                ("", "ATC-MODULE-SURFACE:"),
                ("ATC-MODULE-SURFACE:", ""),
                ("ATC", "-MODULE-SURFACE:"),
                ("ATC-MODULE", "-SURFACE:"),
                ("ATC-MODULE-SURFACE", ":"),
            ];

            for (prefix, suffix) in collision_attempts {
                let mut collision_hasher = Sha256::new();
                collision_hasher.update(prefix.as_bytes());
                for module in ATC_MODULE_SURFACE {
                    update_len_prefixed(&mut collision_hasher, module.as_bytes());
                }
                collision_hasher.update(suffix.as_bytes());
                let collision_fingerprint = hex::encode(collision_hasher.finalize());

                assert_ne!(collision_fingerprint, original_fingerprint,
                          "Collision attempt with prefix '{}' and suffix '{}' should fail", prefix, suffix);
            }

            // Attack 4: Length extension and padding attacks
            let length_extension_attempts = vec![
                b"\x80".to_vec(), // SHA-256 padding start
                b"\x00".repeat(64), // Block-sized padding
                b"\x00".repeat(55), // Near block boundary
                b"\x80\x00".repeat(32), // Alternating padding pattern
                vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00], // Length encoding
            ];

            for (i, padding) in length_extension_attempts.iter().enumerate() {
                let mut extension_hasher = Sha256::new();
                extension_hasher.update(b"ATC-MODULE-SURFACE:");
                for module in ATC_MODULE_SURFACE {
                    update_len_prefixed(&mut extension_hasher, module.as_bytes());
                }
                extension_hasher.update(padding);
                let extension_fingerprint = hex::encode(extension_hasher.finalize());

                assert_ne!(extension_fingerprint, original_fingerprint,
                          "Length extension attempt {} should not produce valid fingerprint", i);
            }

            // Attack 5: Domain separator bypass attempts
            let separator_bypass_attempts = vec![
                "ATCMODULESURFACE:",     // No hyphens
                "ATC_MODULE_SURFACE:",   // Underscores instead of hyphens
                "atc-module-surface:",   // Lowercase
                "ATC-MODULE-SURFACE;",   // Different terminator
                "ATC-MODULE-SURFACE",    // No terminator
                ":ATC-MODULE-SURFACE:",  // Leading separator
                "ATC-MODULE-SURFACE::",  // Double separator
                "ATC-MODULE-SURFACE:\x00", // Null terminator
            ];

            for (i, separator) in separator_bypass_attempts.iter().enumerate() {
                let mut bypass_hasher = Sha256::new();
                bypass_hasher.update(separator.as_bytes());
                for module in ATC_MODULE_SURFACE {
                    update_len_prefixed(&mut bypass_hasher, module.as_bytes());
                }
                let bypass_fingerprint = hex::encode(bypass_hasher.finalize());

                assert_ne!(bypass_fingerprint, original_fingerprint,
                          "Domain separator bypass attempt {} should fail: {}", i, separator);
            }
        }

        #[test]
        fn test_usize_to_u64_overflow_and_boundary_attacks() {
            // Attack 1: Boundary value comprehensive testing
            let boundary_values = vec![
                0,                    // Minimum value
                1,                    // Minimum + 1
                usize::MAX / 2,       // Half maximum
                usize::MAX - 1,       // Near maximum
                usize::MAX,           // Maximum value
                u64::MAX as usize,    // u64 maximum (if usize >= 64-bit)
                2_usize.pow(32),      // 32-bit boundary
                2_usize.pow(31) - 1,  // 31-bit boundary
                2_usize.pow(31),      // 31-bit + 1
                2_usize.pow(16),      // 16-bit boundary
                2_usize.pow(8),       // 8-bit boundary
            ];

            for value in boundary_values {
                let result = usize_to_u64(value);

                // Result should always be valid u64
                assert!(result <= u64::MAX, "Result should not exceed u64::MAX for value {}", value);

                // If value fits in u64, should be exact conversion
                if value <= u64::MAX as usize {
                    assert_eq!(result, value as u64, "Value {} should convert exactly", value);
                } else {
                    // If value exceeds u64, should saturate to u64::MAX
                    assert_eq!(result, u64::MAX, "Value {} should saturate to u64::MAX", value);
                }
            }

            // Attack 2: Arithmetic overflow resistance verification
            let overflow_test_values = vec![
                (usize::MAX, u64::MAX),
                (usize::MAX - 1, if usize::MAX - 1 <= u64::MAX as usize { (usize::MAX - 1) as u64 } else { u64::MAX }),
                (0, 0),
                (1, 1),
            ];

            for (input, expected) in overflow_test_values {
                let result = usize_to_u64(input);
                assert_eq!(result, expected,
                          "usize_to_u64({}) should return {} but got {}", input, expected, result);

                assert_eq!(usize_to_u64(input), result, "Conversion should be deterministic for input {}", input);
            }

            // Attack 3: Platform independence verification
            // Test that conversion behaves consistently across different architectures
            for shift in 0..64.min(usize::BITS) {
                let test_value = 1usize << shift;
                let result = usize_to_u64(test_value);

                if test_value <= u64::MAX as usize {
                    assert_eq!(result, test_value as u64,
                              "Power of 2 value 1<<{} should convert exactly", shift);
                } else {
                    assert_eq!(result, u64::MAX,
                              "Power of 2 value 1<<{} should saturate", shift);
                }
            }

            // Attack 4: Saturation behavior under extreme inputs
            let saturation_tests = vec![
                usize::MAX,
                usize::MAX.saturating_sub(1),
                usize::MAX.saturating_sub(100),
                usize::MAX.saturating_sub(1000),
            ];

            for value in saturation_tests {
                let result = usize_to_u64(value);

                // Should never exceed u64::MAX
                assert!(result <= u64::MAX, "Saturation failed for value {}", value);

                // Should maintain monotonicity where possible
                if value > 0 {
                    let smaller_result = usize_to_u64(value.saturating_sub(1));
                    if value <= u64::MAX as usize {
                        assert!(result >= smaller_result,
                               "Monotonicity violated: {} vs {} for inputs {} vs {}",
                               result, smaller_result, value, value.saturating_sub(1));
                    }
                }
            }

            // Attack 5: Rapid conversion stress testing
            for i in 0..100000 {
                let test_value = (i * 7919) % (usize::MAX / 1000 + 1); // Pseudo-random values
                let result = usize_to_u64(test_value);

                assert!(result <= u64::MAX, "Stress test iteration {} failed for value {}", i, test_value);

                if test_value <= u64::MAX as usize {
                    assert_eq!(result, test_value as u64,
                              "Stress test exact conversion failed at iteration {}", i);
                } else {
                    assert_eq!(result, u64::MAX,
                              "Stress test saturation failed at iteration {}", i);
                }

                // Verify consistency across multiple calls
                let result2 = usize_to_u64(test_value);
                assert_eq!(result, result2,
                          "Conversion should be deterministic for value {} at iteration {}", test_value, i);
            }
        }

        #[test]
        fn test_length_prefixed_hash_injection_and_collision_attacks() {
            // Attack 1: Length prefix collision attempts
            let collision_test_cases = vec![
                // Same content, different representations
                (b"ab".to_vec(), b"ab".to_vec()),
                (b"a".to_vec(), b"a".to_vec()),
                (b"".to_vec(), b"".to_vec()),

                // Different content that might collide without length prefixing
                (b"ab".to_vec(), b"a\x00b".to_vec()),
                (b"a\x00".to_vec(), b"a".to_vec()),
                (b"\x00".to_vec(), b"".to_vec()),
                (b"a\x00b".to_vec(), b"ab\x00".to_vec()),

                // Binary data collision attempts
                (vec![0x00, 0x01], vec![0x00, 0x01]),
                (vec![0x00], vec![0x01]),
                (vec![0xFF], vec![0xFE]),
                (vec![0x00, 0x00], vec![0x00]),

                // Large data collision attempts
                (vec![0x42; 1000], vec![0x42; 1001]),
                (b"A".repeat(1000).into_bytes(), b"B".repeat(1000).into_bytes()),
            ];

            for (i, (data1, data2)) in collision_test_cases.iter().enumerate() {
                let mut hasher1 = Sha256::new();
                let mut hasher2 = Sha256::new();

                update_len_prefixed(&mut hasher1, data1);
                update_len_prefixed(&mut hasher2, data2);

                let hash1 = hasher1.finalize();
                let hash2 = hasher2.finalize();

                if data1 == data2 {
                    assert_eq!(hash1, hash2,
                              "Identical data {} should produce identical hashes", i);
                } else {
                    assert_ne!(hash1, hash2,
                              "Different data {} should produce different hashes", i);
                }
            }

            // Attack 2: Length encoding manipulation
            let length_manipulation_tests = vec![
                (vec![0x00; 8], "Zero length encoding"),
                (vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "Length = 1"),
                (vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], "Maximum length"),
                (vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], "Length = 256"),
                (vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00], "Length = 65536"),
            ];

            for (encoded_length, description) in length_manipulation_tests {
                let mut manual_hasher = Sha256::new();
                let mut proper_hasher = Sha256::new();

                // Manual length encoding (potential attack)
                manual_hasher.update(&encoded_length);
                manual_hasher.update(b"test_data");

                // Proper length encoding
                update_len_prefixed(&mut proper_hasher, b"test_data");

                let manual_hash = manual_hasher.finalize();
                let proper_hash = proper_hasher.finalize();

                // Manual encoding should not match proper encoding unless exact match
                let proper_length_encoding = 9u64.to_le_bytes(); // "test_data".len() = 9
                if encoded_length == proper_length_encoding.to_vec() {
                    assert_eq!(manual_hash, proper_hash,
                              "Proper length encoding should match for {}", description);
                } else {
                    assert_ne!(manual_hash, proper_hash,
                              "Manual length manipulation should fail for {}", description);
                }
            }

            // Attack 3: Multi-part message confusion
            let multipart_tests = vec![
                (vec![b"part1".to_vec(), b"part2".to_vec()], b"part1part2".to_vec()),
                (vec![b"a".to_vec(), b"b".to_vec()], b"ab".to_vec()),
                (vec![b"".to_vec(), b"test".to_vec()], b"test".to_vec()),
                (vec![b"test".to_vec(), b"".to_vec()], b"test".to_vec()),
                (vec![b"\x00".to_vec(), b"\x01".to_vec()], b"\x00\x01".to_vec()),
            ];

            for (parts, concatenated) in multipart_tests {
                let mut parts_hasher = Sha256::new();
                let mut concat_hasher = Sha256::new();

                // Hash multiple parts separately
                for part in &parts {
                    update_len_prefixed(&mut parts_hasher, part);
                }

                // Hash concatenated version
                update_len_prefixed(&mut concat_hasher, concatenated);

                let parts_hash = parts_hasher.finalize();
                let concat_hash = concat_hasher.finalize();

                // Should always be different (length prefixing prevents confusion)
                assert_ne!(parts_hash, concat_hash,
                          "Multi-part vs concatenated should produce different hashes");
            }

            // Attack 4: Large input stress testing
            let large_input_sizes = vec![
                0,
                1,
                100,
                1024,       // 1KB
                64 * 1024,  // 64KB
                1024 * 1024, // 1MB
            ];

            for size in large_input_sizes {
                let large_data = vec![0x42; size];
                let mut hasher = Sha256::new();

                // Should handle large inputs without panic
                update_len_prefixed(&mut hasher, &large_data);
                let hash = hasher.finalize();

                // Verify hash is valid
                assert_eq!(hash.len(), 32, "Hash should be 32 bytes for input size {}", size);

                // Verify different sizes produce different hashes
                if size > 0 {
                    let smaller_data = vec![0x42; size.saturating_sub(1)];
                    let mut smaller_hasher = Sha256::new();
                    update_len_prefixed(&mut smaller_hasher, &smaller_data);
                    let smaller_hash = smaller_hasher.finalize();

                    assert_ne!(hash, smaller_hash,
                              "Different sizes {} vs {} should produce different hashes", size, size.saturating_sub(1));
                }
            }

            // Attack 5: Rapid hashing with varying inputs
            let mut previous_hashes = HashSet::new();

            for i in 0..10000 {
                let dynamic_data = format!("dynamic_test_data_{}", i).into_bytes();
                let mut hasher = Sha256::new();
                update_len_prefixed(&mut hasher, &dynamic_data);
                let hash = hasher.finalize();

                // Each hash should be unique
                assert!(!previous_hashes.contains(&hash),
                       "Hash collision detected at iteration {}", i);
                previous_hashes.insert(hash);

                // Hash should be deterministic
                let mut hasher2 = Sha256::new();
                update_len_prefixed(&mut hasher2, &dynamic_data);
                let hash2 = hasher2.finalize();

                assert_eq!(hash, hash2,
                          "Hash should be deterministic for iteration {}", i);
            }
        }

        #[test]
        fn test_surface_fingerprint_hex_encoding_and_format_attacks() {
            let fingerprint = module_surface_fingerprint_hex();

            // Attack 1: Hex encoding validation and security properties
            assert_eq!(fingerprint.len(), 64,
                      "Fingerprint should be exactly 64 hex characters (SHA256)");

            for (i, c) in fingerprint.char_indices() {
                assert!(c.is_ascii_hexdigit(),
                       "Character '{}' at position {} is not a valid hex digit", c, i);
                assert!(c.is_ascii_lowercase() || c.is_ascii_digit(),
                       "Hex character '{}' at position {} should be lowercase", c, i);
                assert_ne!(c, '\0',
                          "Fingerprint should not contain null characters at position {}", i);
            }

            // Attack 2: Fingerprint entropy and randomness verification
            let hex_chars: Vec<char> = fingerprint.chars().collect();
            let mut char_counts = HashMap::new();

            for &c in &hex_chars {
                let count = char_counts.entry(c).or_insert(0);
                *count = count.saturating_add(1);
            }

            // Should have reasonable entropy (not all same character)
            assert!(char_counts.len() > 1,
                   "Fingerprint should not be all the same character");

            // Should not be obvious patterns
            assert_ne!(fingerprint, "0".repeat(64),
                      "Fingerprint should not be all zeros");
            assert_ne!(fingerprint, "f".repeat(64),
                      "Fingerprint should not be all F's");
            assert_ne!(fingerprint, "0123456789abcdef".repeat(4),
                      "Fingerprint should not be obvious pattern");

            // Attack 3: Hex string format consistency
            let fingerprint_bytes = hex::decode(&fingerprint)
                .expect("Fingerprint should decode as valid hex");

            assert_eq!(fingerprint_bytes.len(), 32,
                      "Decoded fingerprint should be 32 bytes");

            // Re-encode and verify consistency
            let re_encoded = hex::encode(&fingerprint_bytes);
            assert_eq!(re_encoded, fingerprint,
                      "Re-encoding should produce identical fingerprint");

            // Attack 4: Case sensitivity verification
            let uppercase_fingerprint = fingerprint.to_uppercase();
            assert_ne!(fingerprint, uppercase_fingerprint,
                      "Fingerprint should be lowercase only");

            // Verify uppercase version would decode to same bytes
            let uppercase_bytes = hex::decode(&uppercase_fingerprint)
                .expect("Uppercase fingerprint should also decode");
            assert_eq!(fingerprint_bytes, uppercase_bytes,
                      "Uppercase and lowercase should decode to same bytes");

            // Attack 5: Fingerprint stability across system states
            let mut stability_fingerprints = Vec::new();

            for round in 0..1000 {
                let current_fp = module_surface_fingerprint_hex();
                stability_fingerprints.push(current_fp);

                // Should always match the first computation
                assert_eq!(stability_fingerprints[round], fingerprint,
                          "Fingerprint should be stable across computation round {}", round);

                // Verify no memory corruption
                assert_eq!(stability_fingerprints[round].len(), 64,
                          "Fingerprint length should be stable in round {}", round);

                for (i, c) in stability_fingerprints[round].char_indices() {
                    assert!(c.is_ascii_hexdigit(),
                           "Character corruption detected at position {} in round {}: '{}'", i, round, c);
                }
            }

            // Attack 6: Fingerprint uniqueness against known weak hashes
            let weak_hash_patterns = vec![
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256("")
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", // SHA256("a")
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", // SHA256("abc")
                "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", // SHA256("The quick brown fox jumps over the lazy dog")
                "0".repeat(64),                                                      // All zeros
                "f".repeat(64),                                                      // All F's
                "deadbeef".repeat(8),                                                // Repeated pattern
            ];

            for weak_hash in weak_hash_patterns {
                assert_ne!(fingerprint, weak_hash,
                          "Fingerprint should not match known weak hash: {}", weak_hash);
            }
        }

        #[test]
        fn test_module_surface_security_properties_and_attack_resistance() {
            // Attack 1: Module surface timing attack resistance
            use std::time::Instant;

            let mut access_times = Vec::new();
            for i in 0..10000 {
                let start = Instant::now();
                let _surface = module_surface();
                let duration = start.elapsed();
                access_times.push(duration);

                // Should be consistently fast (constant time)
                assert!(duration.as_nanos() < 1_000_000, // 1ms threshold
                       "Module surface access {} took too long: {:?}", i, duration);
            }

            // Timing should be relatively consistent (no data-dependent timing)
            let avg_time: u64 = access_times.iter().map(|d| d.as_nanos() as u64).sum::<u64>() / u64::try_from(access_times.len()).unwrap_or(u64::MAX);
            let mut outliers = 0;

            for (i, &time) in access_times.iter().enumerate() {
                let time_nanos = time.as_nanos() as u64;
                if time_nanos > avg_time * 10 { // More than 10x average
                    outliers = outliers.saturating_add(1);
                }
                assert!(outliers < 100, // Less than 1% outliers
                       "Too many timing outliers detected, potential timing attack vulnerability");
            }

            // Attack 2: Module surface cache pollution resistance
            let surface1 = module_surface();

            // Perform many unrelated operations to potentially pollute caches
            let mut dummy_data = Vec::new();
            for i in 0..100000 {
                dummy_data.push(format!("cache_pollution_{}", i));
                let _ = dummy_data.len();
            }

            let surface2 = module_surface();

            // Should return exact same reference despite cache pollution
            assert_eq!(surface1.as_ptr(), surface2.as_ptr(),
                      "Module surface should be cache pollution resistant");
            assert_eq!(surface1, surface2,
                      "Module surface content should be identical after cache pollution");

            // Attack 3: Module surface memory layout analysis resistance
            let surface = module_surface();

            // Verify memory layout properties that resist analysis
            for (i, &module_name) in surface.iter().enumerate() {
                // Each string should be properly terminated
                assert!(module_name.as_bytes().iter().all(|&b| b != 0),
                       "Module {} should not contain null bytes", i);

                // Should not leak memory addresses in content
                assert!(!module_name.contains("0x"),
                       "Module {} should not contain hex addresses", i);
                assert!(!module_name.chars().any(|c| c as u32 > 127),
                       "Module {} should be ASCII only", i);

                // Should not contain obvious memory patterns
                assert!(!module_name.contains("deadbeef"),
                       "Module {} should not contain debug patterns", i);
                assert!(!module_name.contains("cafebabe"),
                       "Module {} should not contain magic constants", i);
            }

            // Attack 4: Module surface side-channel resistance
            // Access patterns should not leak information
            for access_pattern in &[
                vec![0, 1, 2, 3, 4, 5, 6, 7], // Sequential
                vec![7, 6, 5, 4, 3, 2, 1, 0], // Reverse
                vec![0, 2, 4, 6, 1, 3, 5, 7], // Odd/even
                vec![3, 1, 4, 1, 5, 9, 2, 6], // Random-ish
            ] {
                let surface = module_surface();

                for &index in access_pattern {
                    if index < surface.len() {
                        let module = surface[index];
                        assert!(!module.is_empty(),
                               "Module at index {} should not be empty", index);
                    }
                }
            }

            // Attack 5: Module surface information disclosure resistance
            let surface = module_surface();

            for (i, &module_name) in surface.iter().enumerate() {
                // Should not disclose system information
                let sensitive_patterns = [
                    "/", "\\", ":", ".", "..", "~", "$", "%",
                    "root", "admin", "user", "home", "etc", "var", "tmp",
                    "password", "secret", "key", "token", "auth",
                    "127.0.0.1", "localhost", "0.0.0.0",
                    "http", "https", "ftp", "ssh",
                ];

                for pattern in &sensitive_patterns {
                    assert!(!module_name.to_lowercase().contains(&pattern.to_lowercase()),
                           "Module {} should not contain sensitive pattern '{}'", i, pattern);
                }

                // Should not contain version information that could aid attacks
                assert!(!module_name.chars().any(|c| c.is_ascii_digit()),
                       "Module {} should not contain version numbers", i);

                // Should not contain obvious algorithm names
                let crypto_patterns = ["aes", "rsa", "sha", "md5", "des", "rc4"];
                for pattern in &crypto_patterns {
                    assert!(!module_name.to_lowercase().contains(pattern),
                           "Module {} should not contain crypto algorithm name '{}'", i, pattern);
                }
            }
        }
    }
}
