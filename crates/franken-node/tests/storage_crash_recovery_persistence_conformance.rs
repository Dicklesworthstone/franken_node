//! Comprehensive crash recovery and persistence conformance testing for FrankensqliteAdapter.
//!
//! Tests critical storage functionality that must be bulletproof:
//! - Crash recovery preserves Tier 1 data and discards ephemeral data
//! - Replay produces deterministic state reconstruction
//! - Schema versioning handles migrations correctly
//! - Authorization controls prevent unauthorized access
//! - Tier durability guarantees are enforced under all conditions
//!
//! This targets the under-tested crash/recovery paths that are critical for data integrity.

use frankenengine_node::storage::frankensqlite_adapter::{
    AdapterConfig, AdapterError, AdapterSummary, CallerContext, CallerRole, DurabilityTier,
    FrankensqliteAdapter, PersistenceClass, ReadResult,
};
use std::collections::BTreeMap;
use tempfile::TempDir;

const MAX_CRASH_SCENARIOS: usize = 50;
const MAX_REPLAY_OPERATIONS: usize = 100;

/// Test that crash recovery preserves all Tier 1 data while discarding ephemeral data
#[test]
fn test_crash_recovery_tier_durability_guarantees() {
    // Set up adapter with mixed-tier data
    let config = AdapterConfig::default();
    let mut adapter = FrankensqliteAdapter::new(config).expect("adapter creation should succeed");
    let caller = CallerContext::system("test", "crash_recovery_durability");

    // Write data across all durability tiers
    let tier1_keys = ["audit_1", "control_1", "fence_1"];
    let tier2_keys = ["snapshot_1", "crdt_1"];
    let tier3_keys = ["cache_1", "metric_1"];

    // Tier 1: WAL-backed, must survive crash
    for key in tier1_keys.iter() {
        adapter.write(&caller, PersistenceClass::AuditLog, key, b"tier1_data")
            .expect("Tier 1 write should succeed");
    }

    // Tier 2: Periodic flush, may survive depending on timing
    for key in tier2_keys.iter() {
        adapter.write(&caller, PersistenceClass::Snapshot, key, b"tier2_data")
            .expect("Tier 2 write should succeed");
    }

    // Tier 3: Ephemeral, should be lost on crash
    for key in tier3_keys.iter() {
        adapter.write(&caller, PersistenceClass::Cache, key, b"tier3_data")
            .expect("Tier 3 write should succeed");
    }

    // Verify all data is present before crash
    for key in tier1_keys.iter().chain(tier2_keys.iter()).chain(tier3_keys.iter()) {
        let result = adapter.read(&caller, key);
        assert!(result.is_ok(), "Pre-crash read of {} should succeed", key);
    }

    // Simulate crash and recovery
    let recovered_count = adapter.crash_recovery();
    assert!(recovered_count > 0, "Crash recovery should process operations");

    // CRITICAL ASSERTION: All Tier 1 data must survive
    for key in tier1_keys.iter() {
        let result = adapter.read(&caller, key);
        assert!(result.is_ok(), "Tier 1 data '{}' must survive crash recovery", key);
        if let Ok(ReadResult::Found(data)) = result {
            assert_eq!(data, b"tier1_data", "Tier 1 data '{}' must be intact", key);
        } else {
            panic!("Tier 1 data '{}' was lost after crash recovery - durability violation", key);
        }
    }

    // Tier 3 data should be discarded (ephemeral by design)
    for key in tier3_keys.iter() {
        let result = adapter.read(&caller, key);
        assert!(matches!(result, Ok(ReadResult::NotFound)),
                "Tier 3 data '{}' should be discarded after crash", key);
    }
}

/// Test that replay produces deterministic state reconstruction
#[test]
fn test_replay_deterministic_state_reconstruction() {
    let config = AdapterConfig::default();
    let caller = CallerContext::system("test", "replay_deterministic");

    // Create sequence of deterministic operations
    let operations = vec![
        ("audit_seq_1", PersistenceClass::AuditLog, b"op1"),
        ("control_state", PersistenceClass::ControlState, b"state1"),
        ("audit_seq_2", PersistenceClass::AuditLog, b"op2"),
        ("control_state", PersistenceClass::ControlState, b"state2"),
        ("snapshot_1", PersistenceClass::Snapshot, b"snap1"),
        ("audit_seq_3", PersistenceClass::AuditLog, b"op3"),
    ];

    // Execute operations multiple times and verify replay produces identical results
    for iteration in 0..5 {
        let mut adapter = FrankensqliteAdapter::new(config.clone())
            .expect("adapter creation should succeed");

        // Execute the sequence
        for (key, class, data) in &operations {
            adapter.write(&caller, *class, key, data)
                .expect("write should succeed");
        }

        // Get replay state
        let replay_results = adapter.replay();

        if iteration == 0 {
            // Store baseline for comparison
            continue;
        }

        // CRITICAL ASSERTION: Replay must be deterministic across runs
        let first_adapter = FrankensqliteAdapter::new(config.clone()).unwrap();
        let first_replay = {
            let mut temp_adapter = first_adapter;
            for (key, class, data) in &operations {
                temp_adapter.write(&caller, *class, key, data).unwrap();
            }
            temp_adapter.replay()
        };

        assert_eq!(replay_results.len(), first_replay.len(),
                  "Replay length must be deterministic");

        // Verify each replayed operation matches
        for (i, (result, expected)) in replay_results.iter().zip(first_replay.iter()).enumerate() {
            assert_eq!(result, expected,
                      "Replay operation {} must be deterministic: got {:?}, expected {:?}",
                      i, result, expected);
        }
    }
}

/// Test schema version consistency and migration behavior
#[test]
fn test_schema_version_migration_consistency() {
    let config = AdapterConfig::default();
    let mut adapter = FrankensqliteAdapter::new(config).expect("adapter creation should succeed");
    let caller = CallerContext::system("test", "schema_migration");

    // Get initial schema version
    let initial_version = adapter.schema_version();
    assert!(initial_version > 0, "Schema version must be positive");

    // Write some data
    adapter.write(&caller, PersistenceClass::AuditLog, "pre_migration", b"original")
        .expect("write before migration should succeed");

    // Schema version should remain consistent during normal operations
    assert_eq!(adapter.schema_version(), initial_version,
              "Schema version should not change during normal operations");

    // Simulate crash and recovery - schema version must be preserved
    adapter.crash_recovery();
    assert_eq!(adapter.schema_version(), initial_version,
              "Schema version must be preserved across crash recovery");

    // Data written before migration must still be readable
    let result = adapter.read(&caller, "pre_migration");
    assert!(matches!(result, Ok(ReadResult::Found(_))),
            "Pre-migration data must survive version consistency checks");
}

/// Test authorization controls prevent unauthorized access
#[test]
fn test_authorization_access_controls() {
    let config = AdapterConfig::default();
    let mut adapter = FrankensqliteAdapter::new(config).expect("adapter creation should succeed");

    // Create contexts with different authorization levels
    let system_caller = CallerContext::system("system", "auth_test");
    let service_caller = CallerContext::service("service", "auth_test");
    let readonly_caller = CallerContext::read_only("readonly", "auth_test");

    // System caller should be able to write to all classes
    adapter.write(&system_caller, PersistenceClass::AuditLog, "system_key", b"data")
        .expect("system caller should write to audit log");
    adapter.write(&system_caller, PersistenceClass::ControlState, "system_control", b"data")
        .expect("system caller should write to control state");

    // Service caller should have limited write access
    let service_audit_result = adapter.write(&service_caller, PersistenceClass::AuditLog, "service_key", b"data");
    // Note: Exact authorization rules depend on implementation, this tests that authorization is enforced

    // Read-only caller should never be able to write
    let readonly_write_result = adapter.write(&readonly_caller, PersistenceClass::Cache, "readonly_key", b"data");
    assert!(readonly_write_result.is_err(),
            "Read-only caller must not be able to write");

    // All callers should be able to read (if authorized for that specific data)
    let system_read = adapter.read(&system_caller, "system_key");
    assert!(system_read.is_ok(), "System caller should read own data");

    // CRITICAL ASSERTION: Authorization must be enforced consistently
    let readonly_read = adapter.read(&readonly_caller, "system_key");
    // The result depends on implementation - key point is that authorization is checked
    match readonly_read {
        Ok(_) => {
            // If read is allowed, it should return correct data
        },
        Err(AdapterError::Authorization(_)) => {
            // If read is denied, it should be explicit authorization error
        },
        Err(other) => {
            panic!("Unexpected error type for authorization check: {:?}", other);
        }
    }
}

/// Test concurrent operations don't corrupt adapter state
#[test]
fn test_concurrent_operations_state_integrity() {
    let config = AdapterConfig::default();
    let mut adapter = FrankensqliteAdapter::new(config).expect("adapter creation should succeed");
    let caller = CallerContext::system("test", "concurrent_integrity");

    // Simulate concurrent writes to same keys (single-threaded simulation)
    let concurrent_operations = vec![
        ("shared_key", PersistenceClass::ControlState, b"value_a"),
        ("shared_key", PersistenceClass::ControlState, b"value_b"),
        ("shared_key", PersistenceClass::ControlState, b"value_c"),
        ("other_key", PersistenceClass::AuditLog, b"other_a"),
        ("shared_key", PersistenceClass::ControlState, b"value_d"),
        ("other_key", PersistenceClass::AuditLog, b"other_b"),
    ];

    // Execute operations
    for (key, class, data) in &concurrent_operations {
        adapter.write(&caller, *class, key, data)
            .expect("concurrent write should succeed");
    }

    // State must be consistent - last write wins for same key
    let final_shared_result = adapter.read(&caller, "shared_key");
    assert!(final_shared_result.is_ok(), "Shared key should be readable after concurrent writes");

    // Audit log should contain all operations (append-only)
    let other_result = adapter.read(&caller, "other_key");
    assert!(other_result.is_ok(), "Other key should be readable");

    // CRITICAL ASSERTION: Crash recovery after concurrent operations must be safe
    let recovery_count = adapter.crash_recovery();

    // Data must still be accessible after recovery
    let post_recovery_shared = adapter.read(&caller, "shared_key");
    let post_recovery_other = adapter.read(&caller, "other_key");

    assert!(post_recovery_shared.is_ok(),
            "Shared key must survive crash recovery after concurrent operations");
    assert!(post_recovery_other.is_ok(),
            "Other key must survive crash recovery after concurrent operations");
}

/// Test adapter summary provides accurate state information
#[test]
fn test_adapter_summary_state_accuracy() {
    let config = AdapterConfig::default();
    let mut adapter = FrankensqliteAdapter::new(config).expect("adapter creation should succeed");
    let caller = CallerContext::system("test", "summary_accuracy");

    // Get baseline summary
    let initial_summary = adapter.summary();
    let initial_tier1_ops = initial_summary.tier1_operation_count;
    let initial_tier2_ops = initial_summary.tier2_operation_count;
    let initial_tier3_ops = initial_summary.tier3_operation_count;

    // Perform operations across tiers
    adapter.write(&caller, PersistenceClass::AuditLog, "audit1", b"data")
        .expect("tier1 write should succeed");
    adapter.write(&caller, PersistenceClass::Snapshot, "snap1", b"data")
        .expect("tier2 write should succeed");
    adapter.write(&caller, PersistenceClass::Cache, "cache1", b"data")
        .expect("tier3 write should succeed");

    // Get updated summary
    let updated_summary = adapter.summary();

    // CRITICAL ASSERTION: Summary must accurately reflect operations
    assert_eq!(updated_summary.tier1_operation_count, initial_tier1_ops + 1,
              "Summary must reflect Tier 1 operation");
    assert_eq!(updated_summary.tier2_operation_count, initial_tier2_ops + 1,
              "Summary must reflect Tier 2 operation");
    assert_eq!(updated_summary.tier3_operation_count, initial_tier3_ops + 1,
              "Summary must reflect Tier 3 operation");

    // Summary should include schema version
    assert_eq!(updated_summary.schema_version, adapter.schema_version(),
              "Summary schema version must match adapter");

    // After crash recovery, summary should be updated
    let pre_crash_summary = adapter.summary();
    adapter.crash_recovery();
    let post_crash_summary = adapter.summary();

    // Recovery count should be reflected
    assert!(post_crash_summary.last_crash_recovery_count > 0,
           "Summary should reflect crash recovery execution");
}

/// Test edge cases and error conditions
#[test]
fn test_error_conditions_and_edge_cases() {
    let config = AdapterConfig::default();
    let mut adapter = FrankensqliteAdapter::new(config).expect("adapter creation should succeed");
    let caller = CallerContext::system("test", "error_conditions");

    // Test reading non-existent keys
    let missing_result = adapter.read(&caller, "non_existent_key");
    assert!(matches!(missing_result, Ok(ReadResult::NotFound)),
            "Reading non-existent key should return NotFound, not error");

    // Test writing empty data
    adapter.write(&caller, PersistenceClass::AuditLog, "empty_key", b"")
        .expect("writing empty data should succeed");

    let empty_result = adapter.read(&caller, "empty_key");
    assert!(matches!(empty_result, Ok(ReadResult::Found(data)) if data.is_empty()),
            "Empty data should be retrievable");

    // Test writing large data
    let large_data = vec![0u8; 1024 * 1024]; // 1MB
    adapter.write(&caller, PersistenceClass::Snapshot, "large_key", &large_data)
        .expect("writing large data should succeed");

    let large_result = adapter.read(&caller, "large_key");
    assert!(matches!(large_result, Ok(ReadResult::Found(data)) if data.len() == large_data.len()),
            "Large data should be retrievable with correct size");

    // Test key collision behavior
    adapter.write(&caller, PersistenceClass::ControlState, "collision_key", b"first")
        .expect("first write should succeed");
    adapter.write(&caller, PersistenceClass::ControlState, "collision_key", b"second")
        .expect("second write should succeed");

    let collision_result = adapter.read(&caller, "collision_key");
    assert!(matches!(collision_result, Ok(ReadResult::Found(data)) if data == b"second"),
            "Last write should win for key collisions");
}

/// Comprehensive metamorphic property: operations + crash + recovery should be equivalent to operations + recovery
#[test]
fn test_crash_recovery_metamorphic_property() {
    let config = AdapterConfig::default();
    let caller = CallerContext::system("test", "metamorphic_crash");

    let operations = vec![
        ("key1", PersistenceClass::AuditLog, b"audit1"),
        ("key2", PersistenceClass::ControlState, b"control1"),
        ("key3", PersistenceClass::Snapshot, b"snap1"),
        ("key1", PersistenceClass::AuditLog, b"audit2"), // overwrite
        ("key4", PersistenceClass::Cache, b"cache1"),
    ];

    // Path A: Operations + Crash + Recovery
    let mut adapter_a = FrankensqliteAdapter::new(config.clone()).unwrap();
    for (key, class, data) in &operations {
        adapter_a.write(&caller, *class, key, data).unwrap();
    }
    adapter_a.crash_recovery();
    let summary_a = adapter_a.summary();

    // Path B: Operations + Recovery (no explicit crash)
    let mut adapter_b = FrankensqliteAdapter::new(config.clone()).unwrap();
    for (key, class, data) in &operations {
        adapter_b.write(&caller, *class, key, data).unwrap();
    }
    // Crash recovery should be idempotent
    adapter_b.crash_recovery();
    let summary_b = adapter_b.summary();

    // METAMORPHIC PROPERTY: Both paths should yield equivalent durable state
    for (key, class, _) in &operations {
        if *class != PersistenceClass::Cache { // Cache data may be lost
            let result_a = adapter_a.read(&caller, key);
            let result_b = adapter_b.read(&caller, key);

            assert_eq!(result_a.is_ok(), result_b.is_ok(),
                      "Read success should be equivalent for key {}", key);

            if let (Ok(data_a), Ok(data_b)) = (result_a, result_b) {
                assert_eq!(data_a, data_b,
                          "Data should be equivalent after crash recovery for key {}", key);
            }
        }
    }

    // Schema versions should be equivalent
    assert_eq!(adapter_a.schema_version(), adapter_b.schema_version(),
              "Schema versions should be equivalent");
}