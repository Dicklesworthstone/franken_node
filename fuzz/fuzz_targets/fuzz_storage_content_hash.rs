#![no_main]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::storage::retrievability_gate::content_hash;

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs to avoid OOM
    if data.len() > 10_000_000 {
        return;
    }

    // Test content hashing function with arbitrary byte inputs
    let hash = content_hash(data);

    // Invariants that must hold for any input:
    // 1. Hash is always 64 characters (SHA-256 hex encoded)
    assert_eq!(hash.len(), 64, "Hash length must always be 64 chars");

    // 2. Hash contains only valid hex characters
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "Hash must be valid hex");

    // 3. Same input produces same hash (deterministic)
    let hash2 = content_hash(data);
    assert_eq!(hash, hash2, "Hashing must be deterministic");

    // 4. Different inputs (when possible) should produce different hashes
    if !data.is_empty() {
        let mut modified = data.to_vec();
        modified[0] = modified[0].wrapping_add(1);
        let hash_modified = content_hash(&modified);
        assert_ne!(hash, hash_modified, "Different inputs should produce different hashes");
    }
});