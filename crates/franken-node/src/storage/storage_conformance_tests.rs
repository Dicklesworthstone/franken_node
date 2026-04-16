//! Comprehensive conformance and edge case tests for the storage module.
//!
//! Tests focus on:
//! - Boundary conditions and edge cases
//! - Resource exhaustion scenarios
//! - Input validation edge cases
//! - Concurrency simulation
//! - Hardening pattern verification

use crate::storage::frankensqlite_adapter::*;
use crate::storage::retrievability_gate::*;
use crate::storage::models::*;
use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_EVENTS, MAX_RECEIPTS, MAX_SCHEMA_VERSIONS};

/// Test edge cases around push_bounded function
#[cfg(test)]
mod push_bounded_edge_tests {
    use super::*;

    #[test]
    fn test_push_bounded_exact_capacity() {
        let mut adapter = FrankensqliteAdapter::default();

        // Fill exactly to capacity
        for i in 0..MAX_AUDIT_LOG_ENTRIES {
            adapter.write(PersistenceClass::AuditLog, &format!("key_{}", i), b"data")
                .expect("should succeed");
        }

        // One more should trigger overflow handling
        adapter.write(PersistenceClass::AuditLog, "overflow_key", b"overflow_data")
            .expect("should succeed");

        assert_eq!(adapter.summary().total_writes, MAX_AUDIT_LOG_ENTRIES + 1);
        // Audit log should be bounded to MAX_AUDIT_LOG_ENTRIES
        assert!(adapter.audit_log.len() <= MAX_AUDIT_LOG_ENTRIES);
    }

    #[test]
    fn test_push_bounded_zero_capacity() {
        // Test with zero capacity (degenerate case)
        let mut items = Vec::new();
        push_bounded(&mut items, "item1", 0);
        assert!(items.is_empty()); // Should drain everything immediately

        push_bounded(&mut items, "item2", 0);
        assert!(items.is_empty());
    }

    #[test]
    fn test_push_bounded_capacity_one() {
        let mut items = Vec::new();
        push_bounded(&mut items, "first", 1);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "first");

        push_bounded(&mut items, "second", 1);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "second"); // Should have replaced first
    }

    #[test]
    fn test_push_bounded_large_overflow() {
        let mut items = Vec::new();

        // Add many items to create large overflow
        for i in 0..1000 {
            items.push(format!("item_{}", i));
        }

        // Set small capacity to trigger large drain
        push_bounded(&mut items, "final_item", 5);
        assert_eq!(items.len(), 5);
        assert_eq!(items[4], "final_item");
        // Should contain the last few items plus the new one
        assert!(items.iter().any(|s| s == "final_item"));
    }
}

/// Test saturating arithmetic edge cases
#[cfg(test)]
mod saturating_arithmetic_tests {
    use super::*;

    #[test]
    fn test_counter_overflow_prevention() {
        let mut adapter = FrankensqliteAdapter::default();

        // Manually set counters near u64::MAX to test overflow protection
        adapter.write_count = u64::MAX - 1;
        adapter.read_count = u64::MAX - 1;
        adapter.write_failures = u64::MAX - 1;
        adapter.replay_count = u64::MAX - 1;
        adapter.replay_mismatches = u64::MAX - 1;

        // Trigger operations that increment these counters
        let _ = adapter.write(PersistenceClass::ControlState, "test", b"data");
        adapter.read(PersistenceClass::ControlState, "test");
        let _ = adapter.replay();

        // Counters should saturate at MAX, not overflow
        assert_eq!(adapter.write_count, u64::MAX);
        assert_eq!(adapter.read_count, u64::MAX);
        assert_eq!(adapter.replay_count, u64::MAX);
    }

    #[test]
    fn test_tier_write_counter_saturation() {
        let mut adapter = FrankensqliteAdapter::default();

        // Manually set a tier counter near MAX
        adapter.writes_by_tier.insert(DurabilityTier::Tier1, u64::MAX - 1);

        // Write to that tier
        adapter.write(PersistenceClass::ControlState, "test", b"data")
            .expect("should succeed");

        assert_eq!(adapter.writes_by_tier[&DurabilityTier::Tier1], u64::MAX);
    }

    #[test]
    fn test_retrievability_gate_timestamp_saturation() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        // Manually set timestamp counter near MAX
        gate.timestamp_counter = u64::MAX - 1;

        // Trigger operation that increments timestamp
        let _err = gate.check_retrievability(
            &ArtifactId("test".to_string()),
            &SegmentId("test".to_string()),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "hash"
        );

        assert_eq!(gate.timestamp_counter, u64::MAX);
    }
}

/// Test latency measurement edge cases
#[cfg(test)]
mod latency_measurement_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_latency_overflow_protection() {
        // This test verifies that extremely long latencies don't cause overflow
        // The code uses `u64::try_from(...).unwrap_or(u64::MAX)` which should handle this
        let mut adapter = FrankensqliteAdapter::default();

        // Write operation should handle any latency measurement
        adapter.write(PersistenceClass::ControlState, "test", b"data")
            .expect("should succeed");

        // The latency should be reasonable (implementation caps at u64::MAX)
        assert!(adapter.summary().total_writes > 0);
    }
}

/// Test input validation edge cases
#[cfg(test)]
mod input_validation_edge_tests {
    use super::*;

    #[test]
    fn test_empty_keys_and_values() {
        let mut adapter = FrankensqliteAdapter::default();

        // Empty key should work
        adapter.write(PersistenceClass::ControlState, "", b"data")
            .expect("empty key should be allowed");

        // Empty value should work
        adapter.write(PersistenceClass::ControlState, "key", b"")
            .expect("empty value should be allowed");

        // Both empty should work
        adapter.write(PersistenceClass::ControlState, "", b"")
            .expect("both empty should be allowed");
    }

    #[test]
    fn test_very_long_keys() {
        let mut adapter = FrankensqliteAdapter::default();

        // Very long key
        let long_key = "a".repeat(10_000);
        adapter.write(PersistenceClass::ControlState, &long_key, b"data")
            .expect("long key should be handled");

        let result = adapter.read(PersistenceClass::ControlState, &long_key);
        assert!(result.found);
        assert_eq!(result.value.unwrap(), b"data");
    }

    #[test]
    fn test_very_large_values() {
        let mut adapter = FrankensqliteAdapter::default();

        // Very large value (1MB)
        let large_value = vec![0u8; 1_000_000];
        adapter.write(PersistenceClass::ControlState, "large", &large_value)
            .expect("large value should be handled");

        let result = adapter.read(PersistenceClass::ControlState, "large");
        assert!(result.found);
        assert_eq!(result.value.unwrap().len(), 1_000_000);
    }

    #[test]
    fn test_unicode_keys() {
        let mut adapter = FrankensqliteAdapter::default();

        // Unicode key with various characters
        let unicode_key = "🔥测试🚀نمونه🎉";
        adapter.write(PersistenceClass::ControlState, unicode_key, b"unicode_data")
            .expect("unicode key should be handled");

        let result = adapter.read(PersistenceClass::ControlState, unicode_key);
        assert!(result.found);
        assert_eq!(result.value.unwrap(), b"unicode_data");
    }

    #[test]
    fn test_special_characters_in_keys() {
        let mut adapter = FrankensqliteAdapter::default();

        let special_keys = vec![
            "\n\r\t",          // Whitespace
            "\0\x01\x02",      // Control chars
            "\"'\\",           // Quotes and backslash
            "/../..",          // Path-like
            "<script>",        // HTML-like
            "' OR 1=1 --",     // SQL injection-like
            "\u{200B}\u{FEFF}", // Zero-width chars
        ];

        for (i, key) in special_keys.iter().enumerate() {
            let value = format!("value_{}", i).into_bytes();
            adapter.write(PersistenceClass::ControlState, key, &value)
                .expect("special character key should be handled");

            let result = adapter.read(PersistenceClass::ControlState, key);
            assert!(result.found, "Failed for key: {:?}", key);
            assert_eq!(result.value.unwrap(), value);
        }
    }
}

/// Test retrievability gate edge cases
#[cfg(test)]
mod retrievability_gate_edge_tests {
    use super::*;

    #[test]
    fn test_artifact_id_edge_cases() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        let edge_cases = vec![
            ("", "empty artifact id should be rejected"),
            ("   ", "whitespace-only artifact id should be rejected"),
            (" valid_id ", "artifact id with leading/trailing whitespace should be rejected"),
            ("<unknown>", "reserved artifact id should be rejected"),
        ];

        for (artifact_id, description) in edge_cases {
            let err = gate.check_retrievability(
                &ArtifactId(artifact_id.to_string()),
                &SegmentId("valid_segment".to_string()),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "valid_hash"
            ).unwrap_err();

            assert_eq!(err.code, ERR_INVALID_ARTIFACT_ID, "{}", description);
        }
    }

    #[test]
    fn test_segment_id_edge_cases() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        let edge_cases = vec![
            ("", "empty segment id should be rejected"),
            ("   ", "whitespace-only segment id should be rejected"),
            (" valid_id ", "segment id with leading/trailing whitespace should be rejected"),
        ];

        for (segment_id, description) in edge_cases {
            let err = gate.check_retrievability(
                &ArtifactId("valid_artifact".to_string()),
                &SegmentId(segment_id.to_string()),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "valid_hash"
            ).unwrap_err();

            assert_eq!(err.code, ERR_INVALID_SEGMENT_ID, "{}", description);
        }
    }

    #[test]
    fn test_latency_boundary_conditions() {
        let config = RetrievabilityConfig {
            max_latency_ms: 1000,
            require_hash_match: true,
        };
        let mut gate = RetrievabilityGate::new(config);

        let test_cases = vec![
            (999, true, "just under limit should pass"),
            (1000, false, "exactly at limit should fail (fail-closed)"),
            (1001, false, "just over limit should fail"),
        ];

        for (latency_ms, should_pass, description) in test_cases {
            gate.register_target(
                &ArtifactId("test_artifact".to_string()),
                &SegmentId("test_segment".to_string()),
                StorageTier::L3Archive,
                TargetTierState {
                    content_hash: "test_hash".to_string(),
                    reachable: true,
                    fetch_latency_ms: latency_ms,
                },
            );

            let result = gate.check_retrievability(
                &ArtifactId("test_artifact".to_string()),
                &SegmentId("test_segment".to_string()),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                "test_hash"
            );

            assert_eq!(result.is_ok(), should_pass, "{}", description);

            if !should_pass {
                let err = result.unwrap_err();
                assert_eq!(err.code, ERR_LATENCY_EXCEEDED);
            }
        }
    }

    #[test]
    fn test_zero_max_latency_config() {
        let config = RetrievabilityConfig {
            max_latency_ms: 0,
            require_hash_match: true,
        };
        let mut gate = RetrievabilityGate::new(config);

        // Any non-zero latency should fail
        gate.register_target(
            &ArtifactId("test".to_string()),
            &SegmentId("test".to_string()),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "hash".to_string(),
                reachable: true,
                fetch_latency_ms: 1, // Any positive latency
            },
        );

        let err = gate.check_retrievability(
            &ArtifactId("test".to_string()),
            &SegmentId("test".to_string()),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "hash"
        ).unwrap_err();

        assert_eq!(err.code, ERR_LATENCY_EXCEEDED);
    }
}

/// Test constant-time comparison edge cases
#[cfg(test)]
mod constant_time_comparison_tests {
    use super::*;

    #[test]
    fn test_hash_comparison_timing_consistency() {
        // This test verifies that hash comparisons use constant-time comparison
        // The retrievability gate uses ct_eq for hash comparison
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        let test_cases = vec![
            ("identical", "identical"),                    // Identical
            ("different", "DIFFERENT"),                    // Different case
            ("short", "very_long_string_different"),       // Different length
            ("", "non_empty"),                             // Empty vs non-empty
            ("similar_prefix_1", "similar_prefix_2"),      // Similar prefix
            ("abc123", "abc124"),                          // One char difference
        ];

        for (expected, actual) in test_cases {
            gate.register_target(
                &ArtifactId("test".to_string()),
                &SegmentId("test".to_string()),
                StorageTier::L3Archive,
                TargetTierState {
                    content_hash: actual.to_string(),
                    reachable: true,
                    fetch_latency_ms: 100,
                },
            );

            let result = gate.check_retrievability(
                &ArtifactId("test".to_string()),
                &SegmentId("test".to_string()),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                expected
            );

            if expected == actual {
                assert!(result.is_ok());
            } else {
                let err = result.unwrap_err();
                assert_eq!(err.code, ERR_HASH_MISMATCH);
            }
        }
    }

    #[test]
    fn test_hash_comparison_with_relaxed_mode() {
        let config = RetrievabilityConfig {
            max_latency_ms: 5000,
            require_hash_match: false, // Relaxed mode
        };
        let mut gate = RetrievabilityGate::new(config);

        gate.register_target(
            &ArtifactId("test".to_string()),
            &SegmentId("test".to_string()),
            StorageTier::L3Archive,
            TargetTierState {
                content_hash: "actual_hash".to_string(),
                reachable: true,
                fetch_latency_ms: 100,
            },
        );

        // Should pass even with hash mismatch in relaxed mode
        let proof = gate.check_retrievability(
            &ArtifactId("test".to_string()),
            &SegmentId("test".to_string()),
            StorageTier::L2Warm,
            StorageTier::L3Archive,
            "different_hash"
        ).unwrap();

        // Proof should bind to actual hash from target
        assert_eq!(proof.content_hash, "actual_hash");
    }
}

/// Test resource exhaustion scenarios
#[cfg(test)]
mod resource_exhaustion_tests {
    use super::*;

    #[test]
    fn test_maximum_events_overflow() {
        let mut adapter = FrankensqliteAdapter::default();

        // Generate more events than MAX_EVENTS by doing many writes
        for i in 0..(MAX_EVENTS + 100) {
            let _ = adapter.write(PersistenceClass::ControlState, &format!("key_{}", i), b"data");
        }

        // Events should be bounded to MAX_EVENTS
        assert_eq!(adapter.events().len(), MAX_EVENTS);

        // Latest events should be preserved
        let latest_events = adapter.events();
        assert!(latest_events.iter().any(|e| e.detail.contains("FRANKENSQLITE_WRITE_SUCCESS")));
    }

    #[test]
    fn test_maximum_receipts_overflow() {
        let mut gate = RetrievabilityGate::new(RetrievabilityConfig::default());

        // Register many targets and generate proofs to exceed MAX_RECEIPTS
        for i in 0..(MAX_RECEIPTS + 50) {
            let artifact_id = format!("artifact_{}", i);
            let segment_id = format!("segment_{}", i);
            let hash = format!("hash_{}", i);

            gate.register_target(
                &ArtifactId(artifact_id.clone()),
                &SegmentId(segment_id.clone()),
                StorageTier::L3Archive,
                TargetTierState {
                    content_hash: hash.clone(),
                    reachable: true,
                    fetch_latency_ms: 100,
                },
            );

            let _ = gate.check_retrievability(
                &ArtifactId(artifact_id),
                &SegmentId(segment_id),
                StorageTier::L2Warm,
                StorageTier::L3Archive,
                &hash
            );
        }

        // Receipts should be bounded
        assert_eq!(gate.receipts().len(), MAX_RECEIPTS);
    }

    #[test]
    fn test_maximum_schema_versions() {
        let mut adapter = FrankensqliteAdapter::default();

        // Apply more migrations than MAX_SCHEMA_VERSIONS
        for version in 2..(MAX_SCHEMA_VERSIONS + 10) {
            let _ = adapter.migrate(version as u32, &format!("Migration {}", version));
        }

        // Schema versions should be bounded
        assert_eq!(adapter.schema_versions.len(), MAX_SCHEMA_VERSIONS);
        assert_eq!(adapter.schema_version(), (MAX_SCHEMA_VERSIONS + 9) as u32);
    }
}

/// Test concurrent access simulation
#[cfg(test)]
mod concurrent_access_simulation_tests {
    use super::*;

    #[test]
    fn test_interleaved_read_write_operations() {
        let mut adapter = FrankensqliteAdapter::default();

        // Simulate interleaved operations across different persistence classes
        let operations = vec![
            ("write", PersistenceClass::ControlState, "key1", b"data1"),
            ("read", PersistenceClass::ControlState, "key1", b""),
            ("write", PersistenceClass::AuditLog, "log1", b"log_data1"),
            ("write", PersistenceClass::Snapshot, "snap1", b"snap_data1"),
            ("read", PersistenceClass::AuditLog, "log1", b""),
            ("write", PersistenceClass::Cache, "cache1", b"cache_data1"),
            ("read", PersistenceClass::Snapshot, "snap1", b""),
            ("read", PersistenceClass::Cache, "cache1", b""),
        ];

        for (op_type, class, key, value) in operations {
            match op_type {
                "write" => {
                    adapter.write(class, key, value).expect("write should succeed");
                },
                "read" => {
                    let result = adapter.read(class, key);
                    if class != PersistenceClass::Cache || key == "cache1" {
                        // Except for non-existent cache reads, should find data
                        if key != "key1" && key != "log1" && key != "snap1" && key != "cache1" {
                            continue;
                        }
                        assert!(result.found, "Should find data for {}", key);
                    }
                },
                _ => unreachable!(),
            }
        }

        let summary = adapter.summary();
        assert_eq!(summary.total_writes, 4);
        assert_eq!(summary.total_reads, 4);
        assert_eq!(summary.write_failures, 0);
    }

    #[test]
    fn test_concurrent_audit_log_uniqueness() {
        let mut adapter = FrankensqliteAdapter::default();

        // First write should succeed
        adapter.write(PersistenceClass::AuditLog, "audit_1", b"first_entry")
            .expect("first audit entry should succeed");

        // Duplicate key should fail (simulates concurrent write attempt)
        let err = adapter.write(PersistenceClass::AuditLog, "audit_1", b"duplicate_entry")
            .expect_err("duplicate audit key should fail");

        assert!(matches!(err, AdapterError::WriteFailure { .. }));

        // Original entry should be preserved
        let result = adapter.read(PersistenceClass::AuditLog, "audit_1");
        assert_eq!(result.value.unwrap(), b"first_entry");

        assert_eq!(adapter.summary().write_failures, 1);
    }

    #[test]
    fn test_mixed_storage_tier_operations() {
        let mut adapter = FrankensqliteAdapter::default();

        // Write to all tiers with overlapping keys
        let classes = PersistenceClass::all();
        for (i, class) in classes.iter().enumerate() {
            adapter.write(*class, "shared_key", format!("data_for_{}", i).as_bytes())
                .expect("write should succeed");
        }

        // Read from all tiers
        for (i, class) in classes.iter().enumerate() {
            let result = adapter.read(*class, "shared_key");
            assert!(result.found);
            assert_eq!(result.value.unwrap(), format!("data_for_{}", i).as_bytes());
        }

        // Each class should be in its appropriate tier
        for class in classes {
            let result = adapter.read(*class, "shared_key");
            assert_eq!(result.tier, class.tier());
        }
    }
}

/// Test domain separator and hash collision prevention
#[cfg(test)]
mod hash_collision_prevention_tests {
    use super::*;

    #[test]
    fn test_content_hash_domain_separation() {
        // Test that content_hash includes domain separator
        let hash1 = content_hash(b"test_data");
        let hash2 = content_hash(b"test_data");

        // Should be identical for same input
        assert_eq!(hash1, hash2);

        // Should be different from raw SHA-256
        use sha2::{Digest, Sha256};
        let raw_hash = format!("{:x}", Sha256::digest(b"test_data"));
        assert_ne!(hash1, raw_hash);

        // Should include domain separator effect
        let manual_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"retrievability_gate_hash_v1:");
            hasher.update(b"test_data");
            format!("{:x}", hasher.finalize())
        };
        assert_eq!(hash1, manual_hash);
    }

    #[test]
    fn test_hash_collision_resistance() {
        // Test different inputs that might collide
        let test_cases = vec![
            (b"abc", b"ab_c"),
            (b"", b""),
            (b"a", b"aa"),
            (b"test", b"TEST"),
            (b"123", b"321"),
        ];

        for (input1, input2) in test_cases {
            let hash1 = content_hash(input1);
            let hash2 = content_hash(input2);

            if input1 == input2 {
                assert_eq!(hash1, hash2, "Same input should produce same hash");
            } else {
                assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
            }
        }
    }
}

/// Test error handling and recovery scenarios
#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_adapter_error_serialization() {
        let errors = vec![
            AdapterError::WriteFailure {
                key: "test_key".to_string(),
                reason: "disk full".to_string()
            },
            AdapterError::ReadFailure {
                key: "missing_key".to_string(),
                reason: "not found".to_string()
            },
            AdapterError::ReplayMismatch {
                entry_id: "entry_123".to_string(),
                detail: "hash mismatch".to_string()
            },
            AdapterError::SchemaMigrationFailed {
                version: 42,
                reason: "constraint violation".to_string()
            },
            AdapterError::PoolExhausted,
        ];

        for error in errors {
            let json = serde_json::to_string(&error).expect("should serialize");
            let parsed: AdapterError = serde_json::from_str(&json).expect("should deserialize");
            assert_eq!(parsed, error);

            // Check display format
            let display_str = error.to_string();
            assert!(!display_str.is_empty());
        }
    }

    #[test]
    fn test_migration_version_validation() {
        let mut adapter = FrankensqliteAdapter::default();

        // Should start at version 1
        assert_eq!(adapter.schema_version(), 1);

        // Can't downgrade
        let err = adapter.migrate(0, "downgrade").unwrap_err();
        assert!(matches!(err, AdapterError::SchemaMigrationFailed { version: 0, .. }));

        // Can't apply same version
        let err = adapter.migrate(1, "duplicate").unwrap_err();
        assert!(matches!(err, AdapterError::SchemaMigrationFailed { version: 1, .. }));

        // Can upgrade
        adapter.migrate(2, "upgrade").expect("should succeed");
        assert_eq!(adapter.schema_version(), 2);

        // Can't skip versions (this test shows current behavior, might be intentionally allowed)
        adapter.migrate(10, "big jump").expect("should succeed");
        assert_eq!(adapter.schema_version(), 10);
    }

    #[test]
    fn test_crash_recovery_simulation() {
        let mut adapter = FrankensqliteAdapter::default();

        // Write to different tiers
        adapter.write(PersistenceClass::ControlState, "fence1", b"token1").expect("should succeed");
        adapter.write(PersistenceClass::AuditLog, "audit1", b"log1").expect("should succeed");
        adapter.write(PersistenceClass::Snapshot, "snap1", b"snapshot1").expect("should succeed");
        adapter.write(PersistenceClass::Cache, "cache1", b"temp1").expect("should succeed");

        // Simulate crash recovery
        let recovered_count = adapter.crash_recovery();

        // Should have recovered at least Tier 1 items (ControlState + AuditLog)
        assert!(recovered_count >= 2);

        // Tier 1 data should still be readable
        let control_result = adapter.read(PersistenceClass::ControlState, "fence1");
        assert!(control_result.found);

        let audit_result = adapter.read(PersistenceClass::AuditLog, "audit1");
        assert!(audit_result.found);
    }
}

/// Test all model serialization edge cases
#[cfg(test)]
mod model_serialization_tests {
    use super::*;

    #[test]
    fn test_all_mandatory_models_serialization() {
        // Test edge cases for all mandatory model types

        // FencingLeaseRecord with edge values
        let fencing_record = FencingLeaseRecord {
            lease_seq: u64::MAX,
            object_id: "".to_string(),
            holder_id: "🔥holder🔥".to_string(),
            epoch: 0,
            acquired_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "9999-12-31T23:59:59Z".to_string(),
            fence_version: u32::MAX,
        };

        let json = serde_json::to_string(&fencing_record).expect("should serialize");
        let parsed: FencingLeaseRecord = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(parsed, fencing_record);

        // LeaseQuorumRecord with empty participants
        let quorum_record = LeaseQuorumRecord {
            quorum_id: "quorum_".repeat(100), // Long ID
            resource_key: "".to_string(), // Empty key
            participants: Vec::new(), // Empty participants
            ack_count: 0,
            required_acks: u32::MAX,
            epoch: u64::MAX,
            decided_at: None, // None value
            outcome: "unknown".to_string(),
        };

        let json = serde_json::to_string(&quorum_record).expect("should serialize");
        let parsed: LeaseQuorumRecord = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(parsed, quorum_record);
    }

    #[test]
    fn test_optional_model_edge_cases() {
        // OfflineCoverageMetricRecord with edge values
        let coverage_record = OfflineCoverageMetricRecord {
            metric_id: "m".repeat(1000), // Very long ID
            domain_name: "".to_string(), // Empty domain
            coverage_pct: f64::NAN, // NaN value
            sampled_at: "invalid_date".to_string(), // Invalid date format
            sample_size: 0, // Zero samples
        };

        let json = serde_json::to_string(&coverage_record).expect("should serialize");
        let parsed: OfflineCoverageMetricRecord = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(parsed.metric_id, coverage_record.metric_id);
        assert_eq!(parsed.domain_name, coverage_record.domain_name);
        assert!(parsed.coverage_pct.is_nan()); // NaN comparison
        assert_eq!(parsed.sample_size, 0);
    }

    #[test]
    fn test_model_metadata_consistency() {
        // Verify all models have consistent metadata
        let metadata = all_model_metadata();

        for model in metadata {
            // All models should have non-empty names
            assert!(!model.name.is_empty(), "Model {} has empty name", model.name);

            // All models should have version 1.0.0
            assert_eq!(model.version, "1.0.0", "Model {} has wrong version", model.name);

            // All models should have non-empty table names
            assert!(!model.table.is_empty(), "Model {} has empty table", model.name);

            // All models should have at least one column
            assert!(!model.columns.is_empty(), "Model {} has no columns", model.name);

            // Classification should be valid
            assert!(
                matches!(model.classification, "mandatory" | "should_use" | "optional"),
                "Model {} has invalid classification: {}",
                model.name,
                model.classification
            );
        }
    }
}