//! Metamorphic test suite for deterministic seed derivation.
//!
//! Tests metamorphic relations that must hold for correct implementation:
//! - Hex roundtrip identity (invertive)
//! - Domain separation (exclusive)
//! - Content sensitivity (exclusive)
//! - Derivation determinism (equivalence)
//!
//! Uses property-based testing with 100 random inputs to detect:
//! - Serialization corruption
//! - Hash collisions
//! - Platform dependencies
//! - Domain leakage vulnerabilities

use frankenengine_node::encoding::deterministic_seed::{
    ContentHash, DeterministicSeed, DeterministicSeedDeriver, DomainTag, ScheduleConfig,
    derive_seed, SeedError,
};
use std::collections::HashSet;

const PROPERTY_TEST_ITERATIONS: usize = 100;

/// Generate random 32-byte array for content hash testing
fn random_content_bytes(seed: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let mut state = seed;
    for i in 0..32 {
        state = state.wrapping_mul(1103515245).wrapping_add(12345); // Linear congruential generator
        bytes[i] = (state >> 16) as u8;
    }
    bytes
}

/// Generate random schedule config for testing
fn random_schedule_config(seed: u64, param_count: usize) -> ScheduleConfig {
    let mut config = ScheduleConfig::new(seed as u32);
    let mut param_seed = seed;

    for i in 0..param_count {
        param_seed = param_seed.wrapping_mul(69069).wrapping_add(1);
        let key = format!("param_{:03}", i);
        let value = format!("value_{:06x}", param_seed);
        config = config.with_param(&key, &value);
    }

    config
}

/// MR1: Hex Roundtrip Identity (Invertive)
/// For all valid content hashes: from_hex(to_hex(x)) = x
#[test]
fn mr_hex_roundtrip_content_hash() {
    let mut roundtrip_failures = Vec::new();

    for i in 0..PROPERTY_TEST_ITERATIONS {
        let seed = i as u64;
        let original_bytes = random_content_bytes(seed);
        let content_hash = ContentHash::from_bytes(original_bytes);

        // MR: from_hex(to_hex(x)) = x
        let hex_string = content_hash.to_hex();
        let roundtrip_result = ContentHash::from_hex(&hex_string);

        match roundtrip_result {
            Ok(roundtrip_hash) => {
                if content_hash != roundtrip_hash {
                    roundtrip_failures.push(format!(
                        "Iteration {}: Original {:?} != Roundtrip {:?} (hex: {})",
                        i, content_hash, roundtrip_hash, hex_string
                    ));
                }
            }
            Err(e) => {
                roundtrip_failures.push(format!(
                    "Iteration {}: Roundtrip parsing failed: {:?} (hex: {})",
                    i, e, hex_string
                ));
            }
        }

        // Additional check: hex string should be exactly 64 characters
        assert_eq!(hex_string.len(), 64,
            "Hex string should be 64 characters at iteration {}: '{}'", i, hex_string);
    }

    assert!(roundtrip_failures.is_empty(),
        "Hex roundtrip failures:\n{}", roundtrip_failures.join("\n"));
}

/// MR2: Hex Roundtrip Identity for DeterministicSeed
/// For all derived seeds: seed bytes should roundtrip through hex
#[test]
fn mr_hex_roundtrip_deterministic_seed() {
    let mut seed_failures = Vec::new();

    for i in 0..PROPERTY_TEST_ITERATIONS {
        let iteration_seed = i as u64;
        let content_bytes = random_content_bytes(iteration_seed);
        let content_hash = ContentHash::from_bytes(content_bytes);
        let config = random_schedule_config(iteration_seed, 3);
        let domain = &DomainTag::all()[i % DomainTag::all().len()];

        let derived_seed = derive_seed(domain, &content_hash, &config);

        // MR: seed.to_hex() should produce valid hex that represents the seed bytes
        let seed_hex = derived_seed.to_hex();
        let expected_hex = hex::encode(derived_seed.bytes);

        if seed_hex != expected_hex {
            seed_failures.push(format!(
                "Iteration {}: Seed hex mismatch - to_hex(): '{}', expected: '{}'",
                i, seed_hex, expected_hex
            ));
        }

        // Verify hex string properties
        assert_eq!(seed_hex.len(), 64,
            "Seed hex should be 64 characters at iteration {}: '{}'", i, seed_hex);
        assert!(seed_hex.chars().all(|c| c.is_ascii_hexdigit()),
            "Seed hex should contain only hex digits at iteration {}: '{}'", i, seed_hex);
    }

    assert!(seed_failures.is_empty(),
        "Seed hex roundtrip failures:\n{}", seed_failures.join("\n"));
}

/// MR3: Domain Separation (Exclusive)
/// For different domains with identical content and config: seeds must be different
#[test]
fn mr_domain_separation() {
    let mut separation_failures = Vec::new();

    for i in 0..(PROPERTY_TEST_ITERATIONS / 2) {
        let iteration_seed = i as u64;
        let content_bytes = random_content_bytes(iteration_seed);
        let content_hash = ContentHash::from_bytes(content_bytes);
        let config = random_schedule_config(iteration_seed, 2);

        let all_domains = DomainTag::all();

        // Test all pairs of different domains
        for j in 0..all_domains.len() {
            for k in (j + 1)..all_domains.len() {
                let domain1 = &all_domains[j];
                let domain2 = &all_domains[k];

                // MR: derive_seed(domain1, content, config) ≠ derive_seed(domain2, content, config)
                let seed1 = derive_seed(domain1, &content_hash, &config);
                let seed2 = derive_seed(domain2, &content_hash, &config);

                if seed1.bytes == seed2.bytes {
                    separation_failures.push(format!(
                        "Iteration {}: Domain separation failed - {:?} and {:?} produced identical seeds: {}",
                        i, domain1, domain2, seed1.to_hex()
                    ));
                }

                if seed1.domain == seed2.domain {
                    separation_failures.push(format!(
                        "Iteration {}: Domain metadata not preserved - both seeds report domain {:?}",
                        i, seed1.domain
                    ));
                }
            }
        }
    }

    assert!(separation_failures.is_empty(),
        "Domain separation failures:\n{}", separation_failures.join("\n"));
}

/// MR4: Content Sensitivity (Exclusive)
/// For different content with identical domain and config: seeds must be different
#[test]
fn mr_content_sensitivity() {
    let mut sensitivity_failures = Vec::new();

    for i in 0..(PROPERTY_TEST_ITERATIONS / 2) {
        let iteration_seed = i as u64;
        let config = random_schedule_config(iteration_seed, 2);
        let domain = &DomainTag::Encoding; // Use fixed domain

        // Generate two different content hashes
        let content1_bytes = random_content_bytes(iteration_seed);
        let content2_bytes = random_content_bytes(iteration_seed + 1);

        // Ensure content is actually different
        if content1_bytes == content2_bytes {
            continue; // Skip if random generator produced identical content
        }

        let content1 = ContentHash::from_bytes(content1_bytes);
        let content2 = ContentHash::from_bytes(content2_bytes);

        // MR: derive_seed(domain, content1, config) ≠ derive_seed(domain, content2, config)
        let seed1 = derive_seed(domain, &content1, &config);
        let seed2 = derive_seed(domain, &content2, &config);

        if seed1.bytes == seed2.bytes {
            sensitivity_failures.push(format!(
                "Iteration {}: Content sensitivity failed - different content produced identical seeds: {}",
                i, seed1.to_hex()
            ));
        }
    }

    assert!(sensitivity_failures.is_empty(),
        "Content sensitivity failures:\n{}", sensitivity_failures.join("\n"));
}

/// MR5: Configuration Sensitivity (Exclusive)
/// For different configs with identical domain and content: seeds must be different
#[test]
fn mr_config_sensitivity() {
    let mut config_failures = Vec::new();

    for i in 0..(PROPERTY_TEST_ITERATIONS / 2) {
        let iteration_seed = i as u64;
        let content_bytes = random_content_bytes(iteration_seed);
        let content_hash = ContentHash::from_bytes(content_bytes);
        let domain = &DomainTag::Encoding;

        // Generate two different configs
        let config1 = random_schedule_config(iteration_seed, 2);
        let config2 = random_schedule_config(iteration_seed + 100, 3); // Different seed + param count

        // MR: derive_seed(domain, content, config1) ≠ derive_seed(domain, content, config2)
        let seed1 = derive_seed(domain, &content_hash, &config1);
        let seed2 = derive_seed(domain, &content_hash, &config2);

        if seed1.bytes == seed2.bytes {
            config_failures.push(format!(
                "Iteration {}: Config sensitivity failed - different configs produced identical seeds: {}",
                i, seed1.to_hex()
            ));
        }

        // Verify config version is preserved
        if seed1.config_version != config1.version {
            config_failures.push(format!(
                "Iteration {}: Config version not preserved - seed reports {}, config was {}",
                i, seed1.config_version, config1.version
            ));
        }
    }

    assert!(config_failures.is_empty(),
        "Configuration sensitivity failures:\n{}", config_failures.join("\n"));
}

/// MR6: Derivation Determinism (Equivalence)
/// Identical inputs must always produce identical outputs
#[test]
fn mr_derivation_determinism() {
    let mut determinism_failures = Vec::new();

    for i in 0..PROPERTY_TEST_ITERATIONS {
        let iteration_seed = i as u64;
        let content_bytes = random_content_bytes(iteration_seed);
        let content_hash = ContentHash::from_bytes(content_bytes);
        let config = random_schedule_config(iteration_seed, 2);
        let domain = &DomainTag::all()[i % DomainTag::all().len()];

        // MR: derive_seed(domain, content, config) = derive_seed(domain, content, config)
        let seed1 = derive_seed(domain, &content_hash, &config);
        let seed2 = derive_seed(domain, &content_hash, &config);

        if seed1.bytes != seed2.bytes {
            determinism_failures.push(format!(
                "Iteration {}: Determinism failed - identical inputs produced different seeds: {} vs {}",
                i, seed1.to_hex(), seed2.to_hex()
            ));
        }

        if seed1.domain != seed2.domain {
            determinism_failures.push(format!(
                "Iteration {}: Domain metadata inconsistent between identical calls",
                i
            ));
        }

        if seed1.config_version != seed2.config_version {
            determinism_failures.push(format!(
                "Iteration {}: Config version inconsistent between identical calls",
                i
            ));
        }
    }

    assert!(determinism_failures.is_empty(),
        "Derivation determinism failures:\n{}", determinism_failures.join("\n"));
}

/// MR7: Stateful Deriver Consistency
/// DeterministicSeedDeriver should produce same seeds as stateless derive_seed
#[test]
fn mr_stateful_deriver_consistency() {
    let mut consistency_failures = Vec::new();

    for i in 0..PROPERTY_TEST_ITERATIONS {
        let iteration_seed = i as u64;
        let content_bytes = random_content_bytes(iteration_seed);
        let content_hash = ContentHash::from_bytes(content_bytes);
        let config = random_schedule_config(iteration_seed, 1);
        let domain = &DomainTag::all()[i % DomainTag::all().len()];

        // Stateless derivation
        let stateless_seed = derive_seed(domain, &content_hash, &config);

        // Stateful derivation
        let mut deriver = DeterministicSeedDeriver::new();
        let (stateful_seed, _bump) = deriver.derive_seed(domain, &content_hash, &config);

        // MR: stateful_derive_seed(args) = stateless_derive_seed(args)
        if stateless_seed.bytes != stateful_seed.bytes {
            consistency_failures.push(format!(
                "Iteration {}: Stateful/stateless inconsistency - stateless: {}, stateful: {}",
                i, stateless_seed.to_hex(), stateful_seed.to_hex()
            ));
        }

        if stateless_seed.domain != stateful_seed.domain {
            consistency_failures.push(format!(
                "Iteration {}: Domain metadata inconsistency between stateful/stateless",
                i
            ));
        }
    }

    assert!(consistency_failures.is_empty(),
        "Stateful deriver consistency failures:\n{}", consistency_failures.join("\n"));
}

/// MR8: Collision Resistance (Statistical)
/// Different inputs should produce different seeds (with high probability)
#[test]
fn mr_collision_resistance() {
    let mut all_seeds = HashSet::new();
    let mut collision_count = 0;

    for i in 0..PROPERTY_TEST_ITERATIONS {
        let iteration_seed = i as u64;
        let content_bytes = random_content_bytes(iteration_seed);
        let content_hash = ContentHash::from_bytes(content_bytes);
        let config = random_schedule_config(iteration_seed, i % 5);
        let domain = &DomainTag::all()[i % DomainTag::all().len()];

        let derived_seed = derive_seed(domain, &content_hash, &config);
        let seed_bytes = derived_seed.bytes.to_vec();

        // MR: Different inputs should (almost always) produce different outputs
        if all_seeds.contains(&seed_bytes) {
            collision_count += 1;
        } else {
            all_seeds.insert(seed_bytes);
        }
    }

    // With 100 iterations and 256-bit seeds, collisions should be extremely rare
    // Allow at most 1 collision (could be legitimate with random chance)
    assert!(collision_count <= 1,
        "Too many seed collisions detected: {} out of {} iterations",
        collision_count, PROPERTY_TEST_ITERATIONS);

    // Verify we generated a reasonable number of unique seeds
    assert!(all_seeds.len() >= PROPERTY_TEST_ITERATIONS - 1,
        "Not enough unique seeds generated: {} unique out of {} iterations",
        all_seeds.len(), PROPERTY_TEST_ITERATIONS);
}

/// MR9: Hex Encoding Validation (Format Consistency)
/// All hex outputs should be well-formed lowercase hex
#[test]
fn mr_hex_encoding_format() {
    let mut format_failures = Vec::new();

    for i in 0..PROPERTY_TEST_ITERATIONS {
        let iteration_seed = i as u64;
        let content_bytes = random_content_bytes(iteration_seed);
        let content_hash = ContentHash::from_bytes(content_bytes);
        let config = random_schedule_config(iteration_seed, 1);
        let domain = &DomainTag::Encoding;

        let derived_seed = derive_seed(domain, &content_hash, &config);

        // Check ContentHash hex format
        let content_hex = content_hash.to_hex();
        if content_hex.len() != 64 {
            format_failures.push(format!("Iteration {}: ContentHash hex wrong length: {}", i, content_hex.len()));
        }
        if !content_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            format_failures.push(format!("Iteration {}: ContentHash hex contains non-hex: '{}'", i, content_hex));
        }
        if content_hex != content_hex.to_lowercase() {
            format_failures.push(format!("Iteration {}: ContentHash hex not lowercase: '{}'", i, content_hex));
        }

        // Check DeterministicSeed hex format
        let seed_hex = derived_seed.to_hex();
        if seed_hex.len() != 64 {
            format_failures.push(format!("Iteration {}: Seed hex wrong length: {}", i, seed_hex.len()));
        }
        if !seed_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            format_failures.push(format!("Iteration {}: Seed hex contains non-hex: '{}'", i, seed_hex));
        }
        if seed_hex != seed_hex.to_lowercase() {
            format_failures.push(format!("Iteration {}: Seed hex not lowercase: '{}'", i, seed_hex));
        }

        // Check prefix hex format
        let prefix_hex = derived_seed.prefix_hex();
        if prefix_hex.len() != 8 {  // First 4 bytes = 8 hex chars (see DeterministicSeed::prefix_hex)
            format_failures.push(format!("Iteration {}: Prefix hex wrong length: {}", i, prefix_hex.len()));
        }
        if !seed_hex.starts_with(&prefix_hex) {
            format_failures.push(format!("Iteration {}: Prefix hex not a prefix of full hex", i));
        }
    }

    assert!(format_failures.is_empty(),
        "Hex format validation failures:\n{}", format_failures.join("\n"));
}

/// Comprehensive metamorphic test combining multiple relations
/// This composite test exercises multiple metamorphic properties together
#[test]
fn mr_comprehensive_composite() {
    let test_seed = 12345u64;

    // Generate test data
    let content1_bytes = random_content_bytes(test_seed);
    let content2_bytes = random_content_bytes(test_seed + 1);
    let content1 = ContentHash::from_bytes(content1_bytes);
    let content2 = ContentHash::from_bytes(content2_bytes);

    let config1 = random_schedule_config(test_seed, 2);
    let config2 = random_schedule_config(test_seed + 100, 3);

    let domain1 = &DomainTag::Encoding;
    let domain2 = &DomainTag::Repair;

    // Derive seeds for all combinations
    let seed_d1_c1_cfg1 = derive_seed(domain1, &content1, &config1);
    let seed_d1_c1_cfg2 = derive_seed(domain1, &content1, &config2);
    let seed_d1_c2_cfg1 = derive_seed(domain1, &content2, &config1);
    let seed_d2_c1_cfg1 = derive_seed(domain2, &content1, &config1);

    // Composite MR: All seeds should be different when any input differs
    let all_seeds = vec![
        &seed_d1_c1_cfg1,
        &seed_d1_c1_cfg2,
        &seed_d1_c2_cfg1,
        &seed_d2_c1_cfg1,
    ];

    for i in 0..all_seeds.len() {
        for j in (i + 1)..all_seeds.len() {
            assert_ne!(all_seeds[i].bytes, all_seeds[j].bytes,
                "Seeds {} and {} should be different but are identical: {}",
                i, j, all_seeds[i].to_hex());
        }
    }

    // Verify hex roundtrip for all seeds
    for (idx, seed) in all_seeds.iter().enumerate() {
        let hex = seed.to_hex();
        let parsed_hash = ContentHash::from_hex(&hex);
        assert!(parsed_hash.is_ok(), "Seed {} hex should be parseable: '{}'", idx, hex);
    }

    // Verify determinism by re-deriving
    let seed_d1_c1_cfg1_repeat = derive_seed(domain1, &content1, &config1);
    assert_eq!(seed_d1_c1_cfg1.bytes, seed_d1_c1_cfg1_repeat.bytes,
        "Repeated derivation should be identical");
}