#!/usr/bin/env cargo +nightly --quiet -Zscript
```toml
[dependencies]
sha2 = "0.10"
hex = "0.4"
```

use sha2::{Digest, Sha256};

// Mock all_versions function for testing
fn mock_all_versions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("lane_scheduler", "ls-v1.0"),
        ("time_travel", "ttr-v1.0"),
        ("control_lane_policy", "clp-v1.0"),
        ("verifier_sdk_api", "1.0.0"),
        ("storage_model", "1.0.0"),
        ("verify_cli_contract", "3.0.0"),
        // Add more entries as needed
    ]
}

fn schema_registry_structure_hash() -> String {
    let mut hasher = Sha256::new();

    // Domain separator
    hasher.update(b"schema_registry_v1:");

    let versions = mock_all_versions();

    // Entry count
    hasher.update((versions.len() as u64).to_le_bytes());

    // Sort entries by name for deterministic ordering
    let mut sorted_versions = versions;
    sorted_versions.sort_by_key(|(name, _)| *name);

    // Hash each entry with length prefixes
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

fn main() {
    println!("Schema registry structure hash:");
    println!("{}", schema_registry_structure_hash());

    // Generate a sample entry count hash
    let mut hasher = Sha256::new();
    hasher.update(b"registry_count_v1:");
    hasher.update((6u64).to_le_bytes()); // Sample count
    let count_hash = hasher.finalize();
    println!("Registry count hash (sample for 6 entries):");
    println!("sha256:{}", hex::encode(count_hash));
}