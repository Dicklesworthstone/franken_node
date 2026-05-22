#![no_main]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::migration::{
    migration_runtime_smoke_stdout_sha256_hex,
    migration_runtime_smoke_stderr_sha256_hex
};

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > 5_000_000 {
        return;
    }

    // Test both stdout and stderr smoke test hash functions
    let stdout_hash = migration_runtime_smoke_stdout_sha256_hex(data);
    let stderr_hash = migration_runtime_smoke_stderr_sha256_hex(data);

    // Invariants for both hash functions:
    // 1. Hashes are always 64 characters (SHA-256 hex)
    assert_eq!(stdout_hash.len(), 64, "Stdout hash length must be 64 chars");
    assert_eq!(stderr_hash.len(), 64, "Stderr hash length must be 64 chars");

    // 2. Hashes contain only valid hex characters
    assert!(stdout_hash.chars().all(|c| c.is_ascii_hexdigit()), "Stdout hash must be valid hex");
    assert!(stderr_hash.chars().all(|c| c.is_ascii_hexdigit()), "Stderr hash must be valid hex");

    // 3. Same input produces same hash (deterministic)
    let stdout_hash2 = migration_runtime_smoke_stdout_sha256_hex(data);
    let stderr_hash2 = migration_runtime_smoke_stderr_sha256_hex(data);
    assert_eq!(stdout_hash, stdout_hash2, "Stdout hashing must be deterministic");
    assert_eq!(stderr_hash, stderr_hash2, "Stderr hashing must be deterministic");

    // 4. Different domain separators should produce different results for same input
    assert_ne!(stdout_hash, stderr_hash, "Different domain separators must produce different hashes");

    // 5. Test with empty input - should not panic
    if data.is_empty() {
        let _ = migration_runtime_smoke_stdout_sha256_hex(data);
        let _ = migration_runtime_smoke_stderr_sha256_hex(data);
    }
});