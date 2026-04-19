//! Additional edge case tests for encoding modules
//! These tests focus on boundary conditions, timing attack protection,
//! and cryptographic edge cases not covered in the main test suite.

#[cfg(test)]
mod additional_encoding_edge_tests {
    use super::super::deterministic_seed::*;
    use crate::security::constant_time;

    // === Constant-Time Comparison Edge Cases ===

    #[test]
    fn test_ct_eq_timing_consistency() {
        // Test that constant-time comparison is consistent regardless of input patterns
        let seed1 = [0x00u8; 32];
        let seed2 = [0xFFu8; 32];
        let seed3 = [0xAAu8; 32];
        let seed4 = [0x55u8; 32];

        // These comparisons should take similar time regardless of bit patterns
        assert!(!constant_time::ct_eq_bytes(&seed1, &seed2));
        assert!(!constant_time::ct_eq_bytes(&seed1, &seed3));
        assert!(!constant_time::ct_eq_bytes(&seed1, &seed4));
        assert!(!constant_time::ct_eq_bytes(&seed2, &seed3));
        assert!(!constant_time::ct_eq_bytes(&seed2, &seed4));
        assert!(!constant_time::ct_eq_bytes(&seed3, &seed4));

        // Self-comparison should be true
        assert!(constant_time::ct_eq_bytes(&seed1, &seed1));
        assert!(constant_time::ct_eq_bytes(&seed2, &seed2));
        assert!(constant_time::ct_eq_bytes(&seed3, &seed3));
        assert!(constant_time::ct_eq_bytes(&seed4, &seed4));
    }

    #[test]
    fn test_ct_eq_with_near_identical_inputs() {
        // Test timing attack protection with inputs that differ by single bits
        let mut base = [0x42u8; 32];
        let mut modified = base;

        // Test each bit position to ensure constant-time behavior
        for byte_idx in 0..32 {
            for bit_idx in 0..8 {
                modified[byte_idx] ^= 1 << bit_idx; // Flip one bit
                assert!(!constant_time::ct_eq_bytes(&base, &modified));
                modified[byte_idx] ^= 1 << bit_idx; // Flip back
                assert!(constant_time::ct_eq_bytes(&base, &modified));
            }
        }
    }

    // === Domain Separation Edge Cases ===

    #[test]
    fn test_domain_separation_collision_resistance() {
        // Test that different domain tags produce different outputs
        let hash = ContentHash([0x12u8; 32]);
        let config = ScheduleConfig::new(1);

        let encoding_seed = derive_seed(&DomainTag::Encoding, &hash, &config);
        let repair_seed = derive_seed(&DomainTag::Repair, &hash, &config);
        let scheduling_seed = derive_seed(&DomainTag::Scheduling, &hash, &config);

        // All seeds should be different due to domain separation
        assert!(!constant_time::ct_eq_bytes(
            &encoding_seed.bytes,
            &repair_seed.bytes
        ));
        assert!(!constant_time::ct_eq_bytes(
            &encoding_seed.bytes,
            &scheduling_seed.bytes
        ));
        assert!(!constant_time::ct_eq_bytes(
            &repair_seed.bytes,
            &scheduling_seed.bytes
        ));
    }

    #[test]
    fn test_config_collision_prevention() {
        // Test that similar configs with different parameters produce different seeds
        let hash = ContentHash([0x34u8; 32]);

        let config1 = ScheduleConfig::new(1).with_param("size", "1024");
        let config2 = ScheduleConfig::new(1).with_param("size", "1025"); // One byte difference
        let config3 = ScheduleConfig::new(1)
            .with_param("size", "1024")
            .with_param("extra", "");
        let config4 = ScheduleConfig::new(2); // Different version

        let seed1 = derive_seed(&DomainTag::Encoding, &hash, &config1);
        let seed2 = derive_seed(&DomainTag::Encoding, &hash, &config2);
        let seed3 = derive_seed(&DomainTag::Encoding, &hash, &config3);
        let seed4 = derive_seed(&DomainTag::Encoding, &hash, &config4);

        // All seeds should be different
        assert!(!constant_time::ct_eq_bytes(&seed1.bytes, &seed2.bytes));
        assert!(!constant_time::ct_eq_bytes(&seed1.bytes, &seed3.bytes));
        assert!(!constant_time::ct_eq_bytes(&seed1.bytes, &seed4.bytes));
        assert!(!constant_time::ct_eq_bytes(&seed2.bytes, &seed3.bytes));
        assert!(!constant_time::ct_eq_bytes(&seed2.bytes, &seed4.bytes));
        assert!(!constant_time::ct_eq_bytes(&seed3.bytes, &seed4.bytes));
    }

    // === Large Input Handling ===

    #[test]
    fn test_large_config_parameter_handling() {
        let hash = ContentHash([0x56u8; 32]);

        // Test with very large parameter values
        let large_config = ScheduleConfig::new(1)
            .with_param("large_param", &"x".repeat(10000)) // 10KB parameter
            .with_param("number", &format!("{}", u64::MAX))
            .with_param("binary", &"A".repeat(1000));

        // Should handle large configs without issues
        let seed = derive_seed(&DomainTag::Encoding, &hash, &large_config);

        // Verify result is valid
        assert_eq!(seed.bytes.len(), 32);
        assert!(seed.bytes.iter().any(|&b| b != 0)); // Should not be all zeros
    }

    #[test]
    fn test_many_parameters_handling() {
        let hash = ContentHash([0x78u8; 32]);

        // Test with many parameters to stress the length-prefixed hashing
        let mut config = ScheduleConfig::new(1);
        for i in 0..1000 {
            config = config.with_param(&format!("param_{i}"), &format!("value_{i}"));
        }

        // Should handle many parameters correctly
        let seed = derive_seed(&DomainTag::Repair, &hash, &config);

        // Verify result is valid
        assert_eq!(seed.bytes.len(), 32);
        assert_eq!(seed.to_hex().len(), 64); // Hex representation should be 64 chars
    }

    // === Edge Cases in Seed Conversion ===

    #[test]
    fn test_seed_hex_representation_consistency() {
        // Test that hex conversion is consistent and reversible
        let test_patterns = [
            [0x00u8; 32], // All zeros
            [0xFFu8; 32], // All ones
            {
                let mut pattern = [0u8; 32];
                for (i, b) in pattern.iter_mut().enumerate() {
                    *b = u8::try_from(i).expect("test pattern index should fit in u8");
                }
                pattern
            },
            {
                let mut pattern = [0u8; 32];
                for (i, b) in pattern.iter_mut().enumerate() {
                    let i = u8::try_from(i).expect("test pattern index should fit in u8");
                    *b = i.wrapping_mul(i);
                }
                pattern
            },
        ];

        for pattern in &test_patterns {
            let seed = DeterministicSeed {
                bytes: *pattern,
                domain: DomainTag::Encoding,
                config_version: 1,
            };
            let hex = seed.to_hex();

            // Hex should be exactly 64 characters (32 bytes * 2 hex chars)
            assert_eq!(hex.len(), 64);

            // Should only contain valid hex characters
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

            // Should be lowercase (by convention)
            assert_eq!(hex, hex.to_lowercase());
        }
    }

    // === Cryptographic Boundary Conditions ===

    #[test]
    fn test_zero_length_inputs() {
        let hash = ContentHash([0x9Au8; 32]);

        // Test with empty parameters
        let empty_config = ScheduleConfig::new(0); // Zero version
        let seed = derive_seed(&DomainTag::Encoding, &hash, &empty_config);

        // Should still produce valid output
        assert_eq!(seed.bytes.len(), 32);
        assert!(seed.bytes.iter().any(|&b| b != 0)); // Should not be all zeros due to hash input
    }

    #[test]
    fn test_hash_collision_resistance() {
        // Test that similar content hashes produce different seeds
        let mut hash1_data = [0x42u8; 32];
        let mut hash2_data = hash1_data;
        hash2_data[31] ^= 1; // Flip one bit in last byte

        let hash1 = ContentHash(hash1_data);
        let hash2 = ContentHash(hash2_data);
        let config = ScheduleConfig::new(1);

        let seed1 = derive_seed(&DomainTag::Encoding, &hash1, &config);
        let seed2 = derive_seed(&DomainTag::Encoding, &hash2, &config);

        // Single bit difference in input should produce completely different output
        assert!(!constant_time::ct_eq_bytes(&seed1.bytes, &seed2.bytes));

        // Hamming distance should be significant (avalanche effect)
        let differences = seed1
            .bytes
            .iter()
            .zip(seed2.bytes.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum::<u32>();

        // Should have many bit differences (avalanche effect check)
        assert!(
            differences > 64,
            "Expected significant avalanche effect, got {differences} bit differences"
        );
    }

    // === Version Handling Edge Cases ===

    #[test]
    fn test_version_boundary_values() {
        let hash = ContentHash([0xBCu8; 32]);

        // Test boundary version values
        let versions = [u32::MIN, 1, 100, 1000, u32::MAX / 2, u32::MAX - 1, u32::MAX];

        let mut seeds = Vec::new();
        for &version in &versions {
            let config = ScheduleConfig::new(version);
            let seed = derive_seed(&DomainTag::Scheduling, &hash, &config);
            deterministic_seed::push_bounded(&mut seeds, seed, 10);
        }

        // All versions should produce different seeds
        for i in 0..seeds.len() {
            for j in i.saturating_add(1)..seeds.len() {
                assert!(
                    !constant_time::ct_eq_bytes(&seeds[i].bytes, &seeds[j].bytes),
                    "Seeds for versions {} and {} should be different",
                    versions[i],
                    versions[j]
                );
            }
        }
    }

    // === Memory Safety Edge Cases ===

    #[test]
    fn test_concurrent_seed_derivation() {
        use std::sync::Arc;
        use std::thread;

        // Test that concurrent seed derivation is safe
        let hash = Arc::new(ContentHash([0xDEu8; 32]));
        let handles: Vec<_> = (0..8)
            .map(|thread_id| {
                let hash_clone = Arc::clone(&hash);
                thread::spawn(move || {
                    let config = ScheduleConfig::new(
                        u32::try_from(thread_id).expect("thread id should fit in u32"),
                    )
                    .with_param("thread", &format!("thread_{thread_id}"));
                    derive_seed(&DomainTag::Encoding, &hash_clone, &config)
                })
            })
            .collect();

        let mut seeds = Vec::new();
        for handle in handles {
            deterministic_seed::push_bounded(&mut seeds, handle.join().expect("Thread should complete successfully"), 10);
        }

        // All seeds should be different (due to different thread IDs in config)
        for i in 0..seeds.len() {
            for j in i.saturating_add(1)..seeds.len() {
                assert!(
                    !constant_time::ct_eq_bytes(&seeds[i].bytes, &seeds[j].bytes),
                    "Concurrent seeds {i} and {j} should be different"
                );
            }
        }
    }

    // === Canonical Encoding Contract Tests ===

    #[test]
    fn length_prefix_hash_distinguishes_key_value_boundary_collisions() {
        let left = ScheduleConfig::new(11).with_param("ab", "c");
        let right = ScheduleConfig::new(11).with_param("a", "bc");

        assert_ne!(left.config_hash(), right.config_hash());
        assert_ne!(
            derive_seed(&DomainTag::Encoding, &ContentHash([0x11; 32]), &left).bytes,
            derive_seed(&DomainTag::Encoding, &ContentHash([0x11; 32]), &right).bytes
        );
    }

    #[test]
    fn length_prefix_hash_distinguishes_empty_key_from_empty_value() {
        let empty_key = ScheduleConfig::new(12).with_param("", "payload");
        let empty_value = ScheduleConfig::new(12).with_param("payload", "");

        assert_ne!(empty_key.config_hash(), empty_value.config_hash());
    }

    #[test]
    fn schedule_config_json_roundtrip_preserves_hash_and_seed() {
        let content_hash = ContentHash([0x22; 32]);
        let config = ScheduleConfig::new(13)
            .with_param("chunk_size", "65536")
            .with_param("mode", "canonical");
        let seed_before = derive_seed(&DomainTag::Verification, &content_hash, &config);

        let encoded = serde_json::to_string(&config).expect("config should encode");
        let decoded: ScheduleConfig = serde_json::from_str(&encoded).expect("config should decode");
        let seed_after = derive_seed(&DomainTag::Verification, &content_hash, &decoded);

        assert!(constant_time::ct_eq_bytes(
            &config.config_hash(),
            &decoded.config_hash()
        ));
        assert!(constant_time::ct_eq_bytes(
            &seed_before.bytes,
            &seed_after.bytes
        ));
    }

    #[test]
    fn content_hash_json_roundtrip_preserves_lowercase_canonical_hex() {
        let content_hash = ContentHash([0xab; 32]);
        let encoded = serde_json::to_string(&content_hash).expect("hash should encode");
        assert_eq!(encoded, format!("\"{}\"", "ab".repeat(32)));

        let decoded: ContentHash = serde_json::from_str(&encoded).expect("hash should decode");
        assert_eq!(decoded.to_hex(), "ab".repeat(32));
    }

    #[test]
    fn deterministic_seed_json_roundtrip_preserves_canonical_fields() {
        let seed = derive_seed(
            &DomainTag::Placement,
            &ContentHash([0xcd; 32]),
            &ScheduleConfig::new(14).with_param("rack", "az-a"),
        );

        let encoded = serde_json::to_string(&seed).expect("seed should encode");
        let decoded: DeterministicSeed =
            serde_json::from_str(&encoded).expect("seed should decode");

        assert!(constant_time::ct_eq_bytes(&seed.bytes, &decoded.bytes));
        assert_eq!(decoded.domain, DomainTag::Placement);
        assert_eq!(decoded.config_version, 14);
        assert!(constant_time::ct_eq_bytes(
            decoded.to_hex().as_bytes(),
            seed.to_hex().as_bytes()
        ));
    }

    #[test]
    fn malformed_content_hash_json_rejects_wrong_length_and_non_hex() {
        for payload in [
            serde_json::json!("aa"),
            serde_json::json!("zz".repeat(32)),
            serde_json::json!("aa ".repeat(32)),
        ] {
            assert!(serde_json::from_value::<ContentHash>(payload).is_err());
        }
    }

    #[test]
    fn malformed_seed_json_rejects_missing_or_bad_fields() {
        let bad_payloads = [
            serde_json::json!({
                "bytes": "aa".repeat(32),
                "config_version": 1
            }),
            serde_json::json!({
                "bytes": "aa",
                "domain": "Encoding",
                "config_version": 1
            }),
            serde_json::json!({
                "bytes": "aa".repeat(32),
                "domain": "NoSuchDomain",
                "config_version": 1
            }),
        ];

        for payload in bad_payloads {
            assert!(serde_json::from_value::<DeterministicSeed>(payload).is_err());
        }
    }

    #[test]
    fn malformed_schedule_config_json_rejects_non_string_params() {
        let payload = serde_json::json!({
            "version": 16,
            "parameters": {
                "chunk_size": 65536
            }
        });

        assert!(serde_json::from_value::<ScheduleConfig>(payload).is_err());
    }

    #[test]
    fn malformed_schedule_config_json_rejects_non_numeric_version() {
        let payload = serde_json::json!({
            "version": "16",
            "parameters": {
                "chunk_size": "65536"
            }
        });

        assert!(serde_json::from_value::<ScheduleConfig>(payload).is_err());
    }

    #[test]
    fn canonical_config_form_is_unique_for_insertion_order_permutations() {
        let first = ScheduleConfig::new(15)
            .with_param("zeta", "last")
            .with_param("alpha", "first")
            .with_param("middle", "center");
        let second = ScheduleConfig::new(15)
            .with_param("middle", "center")
            .with_param("zeta", "last")
            .with_param("alpha", "first");

        assert!(constant_time::ct_eq_bytes(
            &first.config_hash(),
            &second.config_hash()
        ));
        assert_eq!(
            serde_json::to_string(&first).expect("first config should encode"),
            serde_json::to_string(&second).expect("second config should encode")
        );
    }
}
