#![no_main]

use libfuzzer_sys::fuzz_target;
use sha2::{Sha256, Digest};

// Import the private function for testing
// Note: This requires making the function pub for fuzzing
// For now, we'll create our own copy with same logic for fuzzing
fn update_hash_json_bytes_len_prefixed(hasher: &mut Sha256, json_bytes: &[u8]) {
    let len = u64::try_from(json_bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(json_bytes);
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs to prevent OOM
    if data.len() > 10_000_000 {
        return;
    }

    // Test length-prefixed hash update function
    let mut hasher1 = Sha256::new();
    update_hash_json_bytes_len_prefixed(&mut hasher1, data);
    let hash1 = hasher1.finalize();

    // Test deterministic behavior - same input should produce same hash state
    let mut hasher2 = Sha256::new();
    update_hash_json_bytes_len_prefixed(&mut hasher2, data);
    let hash2 = hasher2.finalize();
    assert_eq!(hash1, hash2, "Hash update must be deterministic");

    // Test that length prefixing prevents collision between different inputs
    // that concatenate to the same bytes
    if data.len() >= 2 {
        // Split data into two parts and test that order matters
        let mid = data.len() / 2;
        let part1 = &data[..mid];
        let part2 = &data[mid..];

        // Hash with single update
        let mut hasher_single = Sha256::new();
        update_hash_json_bytes_len_prefixed(&mut hasher_single, data);
        let hash_single = hasher_single.finalize();

        // Hash with two separate updates
        let mut hasher_split = Sha256::new();
        update_hash_json_bytes_len_prefixed(&mut hasher_split, part1);
        update_hash_json_bytes_len_prefixed(&mut hasher_split, part2);
        let hash_split = hasher_split.finalize();

        // These should be different due to length prefixing
        assert_ne!(hash_single, hash_split,
                  "Length prefixing should prevent collision between single and split inputs");
    }

    // Test edge cases
    if data.is_empty() {
        let mut hasher_empty = Sha256::new();
        update_hash_json_bytes_len_prefixed(&mut hasher_empty, &[]);
        let _ = hasher_empty.finalize(); // Should not panic
    }

    // Test with maximum safe length
    if data.len() as u64 == u64::MAX {
        // This is an edge case that should handle gracefully
        let mut hasher_max = Sha256::new();
        update_hash_json_bytes_len_prefixed(&mut hasher_max, data);
        let _ = hasher_max.finalize(); // Should not panic
    }

    // Invariant: length encoding should be little-endian consistent
    let expected_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let len_bytes = expected_len.to_le_bytes();

    // Manual hash construction for verification
    let mut hasher_manual = Sha256::new();
    hasher_manual.update(&len_bytes);
    hasher_manual.update(data);
    let hash_manual = hasher_manual.finalize();

    // Should match our function
    let mut hasher_func = Sha256::new();
    update_hash_json_bytes_len_prefixed(&mut hasher_func, data);
    let hash_func = hasher_func.finalize();

    assert_eq!(hash_manual, hash_func, "Manual construction should match function");
});