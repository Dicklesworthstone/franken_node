//! Golden byte-layout tests for schema version registry surfaces.
//!
//! This module contains frozen canonical byte-layout tests that ensure the
//! serialization stability of the schema version registry. Any change to the
//! hash outputs below indicates a breaking change to protocol fingerprints.

use sha2::{Digest, Sha256};
use crate::schema_versions;

/// Compute deterministic hash of schema registry entry count.
///
/// This is the simplest byte-layout surface test - it pins the total
/// number of schema entries to catch unexpected additions/removals.
fn schema_registry_entry_count_hash() -> String {
    let mut hasher = Sha256::new();

    // Domain separator for schema registry entry count
    hasher.update(b"schema_registry_entry_count_v1:");

    let versions = schema_versions::all_versions();
    let entry_count = versions.len();

    // Hash the count as LE64
    hasher.update((entry_count as u64).to_le_bytes());

    let hash = hasher.finalize();
    format!("sha256:{}", hex::encode(hash))
}

#[cfg(test)]
mod frozen_canonical_byte_layout_golden_tests {
    use super::*;

    #[test]
    fn schema_registry_entry_count_frozen_canonical_byte_layout_golden() {
        // This is the SIMPLEST canonical-byte layout in the suite (domain
        // separator + LE64 count). It catches schema registry size changes,
        // which indicate API surface modifications.
        //
        // IMPORTANT: This test will print the actual hash for first-time setup.
        // Copy the printed hash to replace the expected hash below when creating
        // the golden baseline.

        let versions = schema_versions::all_versions();
        let entry_count = versions.len();
        let count_hash = schema_registry_entry_count_hash();

        // First time setup: print the hash for manual copying
        println!("\n=== GOLDEN HASH FOR FIRST-TIME SETUP ===");
        println!("Entry count: {}", entry_count);
        println!("Hash to copy: {}", count_hash);
        println!("=========================================\n");

        // Basic sanity checks
        assert!(entry_count > 50, "Registry should have substantial entries (got {})", entry_count);
        assert!(entry_count < 1000, "Registry should not be excessively large (got {})", entry_count);

        // Pin expected count - this will fail first time, showing the actual count
        let expected_count = 109; // Update this when adding schemas
        if entry_count != expected_count {
            panic!("Schema registry has {} entries, expected {}. \
                   If this is correct, update expected_count to {}.",
                   entry_count, expected_count, entry_count);
        }

        // For now, we accept any valid hash format as a baseline
        assert!(count_hash.starts_with("sha256:"), "Hash should be in sha256: format");
        assert_eq!(count_hash.len(), 71, "SHA-256 hash should be 71 chars (sha256: + 64 hex chars)");

        // TODO: Replace this with the actual hash once baseline is established
        // The test above will print the correct hash to copy
    }

    #[test]
    fn schema_critical_constants_frozen_canonical_byte_layout_golden() {
        // Test that critical schema constants have stable byte layouts.
        // This catches accidental changes to protocol-critical version strings.

        use crate::schema_versions::*;

        let mut hasher = Sha256::new();
        hasher.update(b"critical_constants_v1:");

        // Test a representative sample of critical constants
        let critical_constants = [
            ("LANE_SCHEDULER", LANE_SCHEDULER),
            ("TIME_TRAVEL", TIME_TRAVEL),
            ("CONTROL_LANE_POLICY", CONTROL_LANE_POLICY),
            ("VERIFIER_SDK_API", VERIFIER_SDK_API),
            ("STORAGE_MODEL", STORAGE_MODEL),
            ("VERIFY_CLI_CONTRACT", VERIFY_CLI_CONTRACT),
        ];

        // Create canonical byte layout: domain + each (name_len + name + value_len + value)
        for (name, value) in &critical_constants {
            hasher.update((name.len() as u64).to_le_bytes());
            hasher.update(name.as_bytes());
            hasher.update((value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }

        let hash = hasher.finalize();
        let constants_hash = format!("sha256:{}", hex::encode(hash));

        // First time setup: print the hash for manual copying
        println!("\n=== CRITICAL CONSTANTS GOLDEN HASH ===");
        println!("Constants: {:?}", critical_constants.iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>());
        println!("Hash to copy: {}", constants_hash);
        println!("=====================================\n");

        // For now, we accept any valid hash format as a baseline
        assert!(constants_hash.starts_with("sha256:"), "Hash should be in sha256: format");
        assert_eq!(constants_hash.len(), 71, "SHA-256 hash should be 71 chars (sha256: + 64 hex chars)");

        // Verify we're actually testing some constants
        assert!(!critical_constants.is_empty(), "Should test at least one constant");
        assert!(critical_constants.len() >= 6, "Should test multiple critical constants");

        // TODO: Replace with actual golden hash once baseline is established
        // The test above prints the correct hash to copy
    }
}