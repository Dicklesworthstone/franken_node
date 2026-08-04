//! Golden byte-layout tests for schema version registry surfaces.
//!
//! This module contains frozen canonical byte-layout tests that ensure the
//! serialization stability of the schema version registry. Any change to the
//! hash outputs below indicates a breaking change to protocol fingerprints.

use crate::schema_versions;
use sha2::{Digest, Sha256};

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

/// Compute deterministic hash of complete schema registry structure.
///
/// This creates a canonical byte layout by:
/// 1. Domain separator: "schema_registry_structure_v1:"
/// 2. Entry count as LE64
/// 3. For each entry (sorted by name): field:name + name_bytes + field:version + version_bytes
/// 4. SHA-256 hex of the complete structure
fn schema_registry_structure_hash() -> String {
    let mut hasher = Sha256::new();

    // Domain separator
    hasher.update(b"schema_registry_structure_v1:");

    let versions = schema_versions::all_versions();

    // Entry count
    hasher.update((versions.len() as u64).to_le_bytes());

    // Sort entries by name for deterministic ordering
    let mut sorted_versions = versions;
    sorted_versions.sort_by_key(|(name, _)| *name);

    // Hash each entry with length prefixes to prevent collision attacks
    for (name, version) in sorted_versions {
        hasher.update(b"field:name");
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());

        hasher.update(b"field:version");
        hasher.update((version.len() as u64).to_le_bytes());
        hasher.update(version.as_bytes());
    }

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
        assert!(
            entry_count > 50,
            "Registry should have substantial entries (got {})",
            entry_count
        );
        assert!(
            entry_count < 1000,
            "Registry should not be excessively large (got {})",
            entry_count
        );

        // Pin expected count - this will fail first time, showing the actual count
        let expected_count = 137; // Update this when adding schemas
        if entry_count != expected_count {
            panic!(
                "Schema registry has {} entries, expected {}. \
                   If this is correct, update expected_count to {}.",
                entry_count, expected_count, entry_count
            );
        }

        // For now, we accept any valid hash format as a baseline
        assert!(
            count_hash.starts_with("sha256:"),
            "Hash should be in sha256: format"
        );
        assert_eq!(
            count_hash.len(),
            71,
            "SHA-256 hash should be 71 chars (sha256: + 64 hex chars)"
        );

        // Golden hash baseline - any change indicates schema registry modification
        // (re-blessed for bd-bg2hy: +run_sentinel_report AND folding in three
        // prior unblessed registry additions — the pinned 133 had silently
        // drifted from the real 136 before this bead; now 137)
        let expected_hash =
            "sha256:ce056c7a2aaa12e682ddf7c81dcca4ae1e52c5521b04ed06722209d7565e58c7";
        assert_eq!(
            count_hash, expected_hash,
            "Schema registry entry count hash changed - this indicates API surface modification.\
                   \nExpected: {}\nActual: {}\nIf this is expected, update the golden hash.",
            expected_hash, count_hash
        );
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
        println!(
            "Constants: {:?}",
            critical_constants
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
        );
        println!("Hash to copy: {}", constants_hash);
        println!("=====================================\n");

        // For now, we accept any valid hash format as a baseline
        assert!(
            constants_hash.starts_with("sha256:"),
            "Hash should be in sha256: format"
        );
        assert_eq!(
            constants_hash.len(),
            71,
            "SHA-256 hash should be 71 chars (sha256: + 64 hex chars)"
        );

        // Verify we're actually testing some constants
        assert!(
            !critical_constants.is_empty(),
            "Should test at least one constant"
        );
        assert!(
            critical_constants.len() >= 6,
            "Should test multiple critical constants"
        );

        // Golden hash baseline - any change indicates critical constants modification
        let expected_hash =
            "sha256:dc2000d100005761856f863673826b1eedc3ed1254c03030b3be6c899acf531e";
        assert_eq!(
            constants_hash, expected_hash,
            "Critical constants hash changed - this indicates protocol-critical version drift.\
                   \nExpected: {}\nActual: {}\nIf this is expected, update the golden hash.",
            expected_hash, constants_hash
        );
    }

    #[test]
    fn schema_registry_structure_frozen_canonical_byte_layout_golden() {
        // This is the COMPREHENSIVE canonical-byte layout test that pins the complete
        // schema registry structure including all names and versions. It catches:
        // 1. Addition/removal of schema entries
        // 2. Changes to schema names or values
        // 3. Changes to entry ordering algorithm
        // 4. Changes to hashing domain separator or field framing

        let structure_hash = schema_registry_structure_hash();
        let versions = schema_versions::all_versions();

        // First time setup: print comprehensive info for baseline establishment
        println!("\n=== SCHEMA REGISTRY STRUCTURE GOLDEN HASH ===");
        println!("Total entries: {}", versions.len());
        println!("Structure hash: {}", structure_hash);

        // Show first few entries to verify structure
        let mut sorted_versions = versions.clone();
        sorted_versions.sort_by_key(|(name, _)| *name);
        println!("First 5 entries (sorted by name):");
        for (i, (name, version)) in sorted_versions.iter().enumerate().take(5) {
            println!("  {}: {} = {}", i + 1, name, version);
        }
        println!("============================================\n");

        // Verify structural integrity
        assert!(
            versions.len() > 50,
            "Registry should have substantial entries"
        );
        assert!(
            versions.len() < 1000,
            "Registry should not be excessively large"
        );

        // Verify all entries have valid names and versions
        for (name, version) in &versions {
            assert!(!name.is_empty(), "Schema name should not be empty");
            assert!(!version.is_empty(), "Schema version should not be empty");
            assert!(name.is_ascii(), "Schema name should be ASCII");
            assert!(version.is_ascii(), "Schema version should be ASCII");
        }

        // Verify hash format
        assert!(
            structure_hash.starts_with("sha256:"),
            "Hash should be in sha256: format"
        );
        assert_eq!(structure_hash.len(), 71, "SHA-256 hash should be 71 chars");

        // Verify no duplicate names (registry integrity)
        let mut names: Vec<&str> = versions.iter().map(|(name, _)| *name).collect();
        names.sort();
        let unique_count = {
            names.dedup();
            names.len()
        };
        assert_eq!(
            unique_count,
            versions.len(),
            "Schema registry should have no duplicate names"
        );

        // Golden hash baseline - any change indicates schema registry structure modification
        // (re-blessed for bd-bg2hy: +run_sentinel_report + three prior
        // unblessed additions; see the entry-count golden above)
        let expected_hash =
            "sha256:502de87979e6cddb61cf400cead6b9bb55a15aeee915c0876bfabf62620dac98";
        assert_eq!(
            structure_hash, expected_hash,
            "Schema registry structure hash changed - this indicates schema modification (add/remove/rename).\
                   \nExpected: {}\nActual: {}\nIf this is expected, update the golden hash.",
            expected_hash, structure_hash
        );
    }
}
