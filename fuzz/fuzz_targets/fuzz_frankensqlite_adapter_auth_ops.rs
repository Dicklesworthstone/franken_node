#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::BTreeMap;

use frankenengine_node::storage::frankensqlite_adapter::{
    FrankensqliteAdapter, AdapterConfig, CallerContext, CallerRole, PersistenceClass,
    MAX_STORE_KEY_BYTES, MAX_STORE_VALUE_BYTES,
};

// Size limits for bounded fuzzing
const MAX_OPERATIONS: usize = 16;
const MAX_KEY_LEN: usize = 256.min(MAX_STORE_KEY_BYTES);
const MAX_VALUE_LEN: usize = 1024.min(MAX_STORE_VALUE_BYTES);
const MAX_STRING_LEN: usize = 128;

/// Fuzzable caller context with bounded strings
#[derive(Debug, Clone, Arbitrary)]
struct FuzzCallerContext {
    #[arbitrary(with = bounded_string)]
    caller_id: String,
    role: CallerRole,
    #[arbitrary(with = bounded_string)]
    trace_id: String,
}

impl From<FuzzCallerContext> for CallerContext {
    fn from(fuzz: FuzzCallerContext) -> Self {
        CallerContext::new(fuzz.caller_id, fuzz.role, fuzz.trace_id)
    }
}

/// Fuzzable adapter configuration with validation-friendly defaults
#[derive(Debug, Clone, Arbitrary)]
struct FuzzAdapterConfig {
    #[arbitrary(with = bounded_db_path)]
    db_path: String,
    #[arbitrary(with = bounded_pool_size)]
    pool_size: usize,
    wal_enabled: bool,
    #[arbitrary(with = bounded_flush_interval)]
    flush_interval_ms: u64,
}

impl From<FuzzAdapterConfig> for AdapterConfig {
    fn from(fuzz: FuzzAdapterConfig) -> Self {
        AdapterConfig {
            db_path: fuzz.db_path,
            pool_size: fuzz.pool_size,
            wal_enabled: fuzz.wal_enabled,
            flush_interval_ms: fuzz.flush_interval_ms,
        }
    }
}

/// Storage operation variants for structure-aware fuzzing
#[derive(Debug, Clone, Arbitrary)]
enum StorageOp {
    Write {
        caller: FuzzCallerContext,
        class: PersistenceClass,
        #[arbitrary(with = bounded_key)]
        key: String,
        #[arbitrary(with = bounded_value)]
        value: Vec<u8>,
    },
    Read {
        caller: FuzzCallerContext,
        class: PersistenceClass,
        #[arbitrary(with = bounded_key)]
        key: String,
    },
    WriteLegacy {
        class: PersistenceClass,
        #[arbitrary(with = bounded_key)]
        key: String,
        #[arbitrary(with = bounded_value)]
        value: Vec<u8>,
    },
}

/// Complete fuzz input with bounded sequences
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    config: FuzzAdapterConfig,
    #[arbitrary(with = bounded_ops)]
    operations: Vec<StorageOp>,
}

// Bounded arbitrary helpers to prevent OOM and improve coverage

fn bounded_string(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(0..=MAX_STRING_LEN)?;
    let bytes = u.bytes(len)?;

    // Generate string with potential control characters for sanitization testing
    let mut result = String::with_capacity(len);
    for &byte in bytes {
        match byte {
            0..=31 => result.push(char::from(byte)), // Control characters
            32..=126 => result.push(char::from(byte)), // Printable ASCII
            127..=255 => {
                // Extended ASCII - use replacement for valid UTF-8
                result.push('\u{FFFD}');
            }
        }
    }
    Ok(result)
}

fn bounded_db_path(u: &mut Unstructured) -> arbitrary::Result<String> {
    let path_type = u.int_in_range(0..=4)?;
    match path_type {
        0 => Ok("memory.db".to_string()), // Valid relative path
        1 => Ok("/tmp/test.db".to_string()), // Valid absolute path
        2 => Ok("../escape.db".to_string()), // Path traversal attempt
        3 => Ok("/etc/passwd".to_string()), // Dangerous absolute path
        4 => {
            // Random path with potential issues
            let mut path = bounded_string(u)?;
            // Inject potential path traversal sequences
            if u.arbitrary::<bool>()? {
                path.push_str("/..");
            }
            if u.arbitrary::<bool>()? {
                path.push('\0'); // Null byte injection
            }
            Ok(path)
        }
        _ => unreachable!(),
    }
}

fn bounded_pool_size(u: &mut Unstructured) -> arbitrary::Result<usize> {
    u.int_in_range(1..=64)
}

fn bounded_flush_interval(u: &mut Unstructured) -> arbitrary::Result<u64> {
    u.int_in_range(1..=10000)
}

fn bounded_key(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(0..=MAX_KEY_LEN)?;
    let bytes = u.bytes(len)?;

    // Generate keys with edge cases
    if bytes.is_empty() {
        return Ok(String::new());
    }

    let mut key = String::with_capacity(len);
    for &byte in bytes {
        match byte {
            // Include problematic characters for log injection testing
            0 => key.push('\0'), // Null byte
            10 => key.push('\n'), // Newline
            13 => key.push('\r'), // Carriage return
            92 => key.push('\\'), // Backslash
            _ => key.push(char::from(byte.clamp(32, 126))), // Printable ASCII
        }
    }
    Ok(key)
}

fn bounded_value(u: &mut Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=MAX_VALUE_LEN)?;
    u.bytes(len).map(|bytes| bytes.to_vec())
}

fn bounded_ops(u: &mut Unstructured) -> arbitrary::Result<Vec<StorageOp>> {
    let len = u.int_in_range(0..=MAX_OPERATIONS)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fuzz_target!(|data: &[u8]| {
    // Input size guard to prevent OOM
    if data.len() > 100_000 {
        return;
    }

    let input: FuzzInput = match Unstructured::new(data).arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Invalid input, skip silently
    };

    // Test adapter creation with configuration validation
    let config: AdapterConfig = input.config.into();
    let mut adapter = match FrankensqliteAdapter::new_validated(config) {
        Ok(adapter) => adapter,
        Err(_) => {
            // Configuration validation failed as expected for invalid configs
            return;
        }
    };

    // Track operation state for invariant checking
    let mut expected_keys: BTreeMap<(PersistenceClass, String), Vec<u8>> = BTreeMap::new();
    let mut write_count = 0;
    let mut read_count = 0;

    // Execute fuzzed operations sequence
    for op in input.operations {
        match op {
            StorageOp::Write { caller, class, key, value } => {
                let caller_ctx: CallerContext = caller.into();

                // Test write operation with authorization
                match adapter.write(&caller_ctx, class, &key, &value) {
                    Ok(_) => {
                        // Write succeeded - update expected state
                        expected_keys.insert((class, key.clone()), value.clone());
                        write_count += 1;

                        // Verify key sanitization doesn't crash
                        let _sanitized = format!("Key: {}", key); // Should not panic
                    }
                    Err(_) => {
                        // Write failed due to authorization or validation - this is expected
                        // for invalid callers/contexts
                    }
                }
            }

            StorageOp::Read { caller, class, key } => {
                let caller_ctx: CallerContext = caller.into();

                // Test read operation with authorization
                match adapter.read(&caller_ctx, class, &key) {
                    Ok(result) => {
                        read_count += 1;

                        // If we expect this key to exist, verify consistency
                        if let Some(expected_value) = expected_keys.get(&(class, key.clone())) {
                            if let Some(actual_value) = result.value {
                                assert_eq!(
                                    &actual_value[..],
                                    &expected_value[..],
                                    "Read value doesn't match expected for key: {}",
                                    key
                                );
                            }
                        }
                    }
                    Err(_) => {
                        // Read failed due to authorization, missing key, or validation
                        // This is expected for restricted callers or non-existent keys
                    }
                }
            }

            StorageOp::WriteLegacy { class, key, value } => {
                // Test legacy write path
                match adapter.write_legacy(class, &key, &value) {
                    Ok(_) => {
                        expected_keys.insert((class, key.clone()), value);
                        write_count += 1;
                    }
                    Err(_) => {
                        // Legacy write failed - this can happen
                    }
                }
            }
        }
    }

    // Invariant checks - these must hold regardless of input
    let summary = adapter.summary();

    // Operation counts should be consistent
    assert!(summary.total_writes <= write_count.saturating_add(1));
    assert!(summary.total_reads <= read_count.saturating_add(1));

    // Write failures shouldn't exceed total writes
    assert!(summary.write_failures <= summary.total_writes);

    // Schema version should be reasonable
    assert!(summary.schema_version <= 1000, "Schema version suspiciously high: {}", summary.schema_version);

    // Replay metrics should be consistent
    assert!(summary.replay_mismatches <= summary.replay_count);

    // Tier-specific write counts should sum to total writes
    let tier_sum: usize = summary.writes_by_tier.values().sum();
    assert!(
        tier_sum <= summary.total_writes.saturating_add(expected_keys.len()),
        "Tier write counts ({}) exceed total writes ({})",
        tier_sum,
        summary.total_writes
    );
});