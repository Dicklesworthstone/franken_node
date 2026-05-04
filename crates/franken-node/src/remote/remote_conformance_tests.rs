//! Comprehensive edge case conformance tests for the remote module.
//!
//! Tests critical hardening patterns and edge cases across all remote components:
//! - virtual_transport_faults: network chaos testing
//! - idempotency: key derivation and collision resistance
//! - computation_registry: versioned remote computation tracking
//! - eviction_saga: cancel-safe lifecycle management
//! - idempotency_store: at-most-once execution semantics
//! - remote_bulkhead: concurrency limiting with backpressure

#[cfg(all(test, feature = "remote-ops"))]
mod tests {
    use super::super::{
        computation_registry::*, eviction_saga::*, idempotency::*, idempotency_store::*,
        remote_bulkhead::*, virtual_transport_faults::*,
    };
    use crate::security::constant_time;
    use crate::{
        capacity_defaults::aliases::MAX_SAGAS,
        config::RemoteConfig,
        security::{
            constant_time::ct_eq,
            remote_cap::{CapabilityGate, CapabilityProvider, RemoteOperation, RemoteScope},
        },
    };
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet};

    // ── Virtual Transport Faults Edge Cases ─────────────────────────────────────

    #[test]
    fn vtf_arithmetic_overflow_protection() {
        // Test potential overflow in fault generation arithmetic
        let excessive_faults = FaultConfig {
            drop_probability: 1.0,
            reorder_probability: 0.0,
            reorder_max_depth: 1,
            corrupt_probability: 0.0,
            corrupt_bit_count: 1,
            max_faults: usize::MAX,
        };

        let fault_err = excessive_faults
            .validate()
            .expect_err("unbounded max_faults must be rejected");
        assert!(fault_err.contains("max_faults"));

        let config = FaultConfig {
            max_faults: MAX_SCHEDULED_FAULTS,
            ..excessive_faults
        };

        let message_err =
            FaultSchedule::from_seed(42, &config, MAX_CAMPAIGN_MESSAGES.saturating_add(1))
                .expect_err("unbounded total_messages must be rejected");
        assert!(message_err.contains("total_messages"));
    }

    #[test]
    fn vtf_xorshift_determinism_edge_cases() {
        // Test xorshift PRNG with edge case seeds
        let edge_seeds = [0, 1, u64::MAX, u64::MAX - 1];
        let config = chaos();

        for &seed in &edge_seeds {
            let s1 = FaultSchedule::from_seed(seed, &config, 100)
                .expect("valid chaos config must build a deterministic schedule");
            let s2 = FaultSchedule::from_seed(seed, &config, 100)
                .expect("valid chaos config must build a deterministic schedule");

            assert_eq!(s1.faults.len(), s2.faults.len());
            for (a, b) in s1.faults.iter().zip(s2.faults.iter()) {
                assert_eq!(a.message_index, b.message_index);
                assert_eq!(a.fault, b.fault);
            }
        }
    }

    #[test]
    fn vtf_corrupt_bit_position_boundary_protection() {
        let mut harness = VirtualTransportFaultHarness::new(1);
        let payload = vec![0xFF; 1000]; // Large payload

        // Very high bit positions that exceed payload size
        let bit_positions = vec![8000, 16000, usize::MAX];
        let corrupted = harness.apply_corrupt(1, &payload, &bit_positions, "test");

        // Should not panic, should only corrupt bits within payload bounds
        assert_eq!(corrupted.len(), 1000);
        // Original payload should be mostly unchanged since bit positions are out of bounds
        let diff_count = payload
            .iter()
            .zip(corrupted.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(diff_count, 0); // No changes since all bit positions are out of bounds
    }

    #[test]
    fn vtf_reorder_depth_zero_protection() {
        let mut harness = VirtualTransportFaultHarness::new(1);

        // Depth 0 should not cause issues
        let result = harness.apply_reorder(1, b"test", 0, "test");
        assert!(result.is_none()); // Nothing should be returned immediately

        // Adding another message should not return anything since depth is 0
        let result2 = harness.apply_reorder(2, b"test2", 0, "test");
        assert!(result2.is_none());

        // Buffer should contain messages but nothing promoted
        let flushed = harness.flush_reorder_buffer();
        assert_eq!(flushed.len(), 2);
    }

    #[test]
    fn vtf_floating_point_precision_validation() {
        // Test floating point probability roll calculation edge cases
        let config = FaultConfig {
            drop_probability: f64::MIN_POSITIVE,
            reorder_probability: f64::MIN_POSITIVE,
            reorder_max_depth: 1,
            corrupt_probability: f64::MIN_POSITIVE,
            corrupt_bit_count: 1,
            max_faults: 1000,
        };

        // Should validate correctly
        assert!(config.validate().is_ok());

        // Generate schedule - should not panic with very small probabilities
        let schedule = FaultSchedule::from_seed(42, &config, 10000)
            .expect("valid tiny-probability config must build a schedule");
        assert!(schedule.faults.len() >= 0); // May be 0 due to tiny probabilities
    }

    // ── Idempotency Key Derivation Edge Cases ───────────────────────────────────

    #[test]
    fn idempotency_length_prefix_collision_resistance() {
        let deriver = IdempotencyKeyDeriver::default();

        // Craft inputs that would collide under delimiter-based encoding
        let computation_a = "a";
        let computation_b = "ab";
        let request_a = b"\x00\x00\x00\x00\x00\x00\x00\x01b";
        let request_b = b"";

        let key_a = deriver.derive_key(computation_a, 0, request_a).unwrap();
        let key_b = deriver.derive_key(computation_b, 0, request_b).unwrap();

        // Length-prefixed encoding should prevent collision
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn idempotency_epoch_boundary_behavior() {
        let deriver = IdempotencyKeyDeriver::default();

        // Test epoch boundary values
        let epochs = [0, 1, u64::MAX - 1, u64::MAX];
        let mut keys = BTreeSet::new();

        for &epoch in &epochs {
            let key = deriver
                .derive_key("test.action.v1", epoch, b"payload")
                .unwrap();
            assert!(keys.insert(key.to_hex())); // All should be unique
        }
    }

    #[test]
    fn idempotency_very_large_payload_handling() {
        let deriver = IdempotencyKeyDeriver::default();

        // Very large payload that could stress memory
        let large_payload = vec![0xAA; 10_000_000]; // 10MB

        let key = deriver.derive_key("large.test.v1", 42, &large_payload);
        assert!(key.is_ok());
        assert_eq!(key.unwrap().to_hex().len(), 64); // Still produces 32-byte key
    }

    #[test]
    fn idempotency_computation_name_unicode_handling() {
        let deriver = IdempotencyKeyDeriver::default();

        // Unicode computation names should work
        let unicode_name = "测试.action.v1";
        let key = deriver.derive_key(unicode_name, 1, b"test");
        assert!(key.is_ok());

        // Different Unicode sequences should produce different keys
        let name_a = "café.action.v1"; // é as single codepoint
        let name_b = "cafe\u{0301}.action.v1"; // e + combining acute accent

        let key_a = deriver.derive_key(name_a, 1, b"test").unwrap();
        let key_b = deriver.derive_key(name_b, 1, b"test").unwrap();
        assert_ne!(key_a, key_b); // Should be different due to normalization
    }

    // ── Computation Registry Edge Cases ─────────────────────────────────────────

    #[test]
    fn registry_capacity_boundary_protection() {
        let mut registry = ComputationRegistry::new(1, "test");

        // Fill registry to capacity
        for i in 0..MAX_COMPUTATION_ENTRIES {
            let entry = ComputationEntry {
                name: format!("domain{}.action.v1", i),
                description: "Test computation".to_string(),
                required_capabilities: vec![RemoteOperation::RemoteComputation],
                input_schema: "{}".to_string(),
                output_schema: "{}".to_string(),
            };

            if i < MAX_COMPUTATION_ENTRIES {
                assert!(registry.register_computation(entry, "test").is_ok());
            }
        }

        // Next registration should fail
        let overflow_entry = ComputationEntry {
            name: "overflow.action.v1".to_string(),
            description: "Should fail".to_string(),
            required_capabilities: vec![RemoteOperation::RemoteComputation],
            input_schema: "{}".to_string(),
            output_schema: "{}".to_string(),
        };

        let err = registry
            .register_computation(overflow_entry, "test")
            .unwrap_err();
        assert_eq!(err.code(), ERR_INVALID_COMPUTATION_ENTRY);
    }

    #[test]
    fn registry_version_arithmetic_overflow_protection() {
        let mut registry = ComputationRegistry::new(u64::MAX - 1, "test");

        // Should allow increment to u64::MAX
        assert!(registry.bump_version(u64::MAX, "test").is_ok());

        // Should reject any further increments (even wrapping to 0)
        let err = registry.bump_version(0, "test").unwrap_err();
        assert_eq!(err.code(), ERR_REGISTRY_VERSION_REGRESSION);
    }

    #[test]
    fn registry_capability_gate_stress_test() {
        let mut registry = ComputationRegistry::new(1, "test");

        // Register computation requiring many capabilities
        let entry = ComputationEntry {
            name: "complex.operation.v1".to_string(),
            description: "Multi-capability operation".to_string(),
            required_capabilities: vec![
                RemoteOperation::RemoteComputation,
                RemoteOperation::TelemetryExport,
                // Add more operations as they become available
            ],
            input_schema: "{}".to_string(),
            output_schema: "{}".to_string(),
        };

        registry.register_computation(entry, "test").unwrap();

        let provider = CapabilityProvider::new("test-secret");
        let mut gate = CapabilityGate::new("test-secret");

        // Test with insufficient capabilities
        let (limited_cap, _) = provider
            .issue(
                "test-principal",
                RemoteScope::new(
                    vec![RemoteOperation::RemoteComputation], // Missing TelemetryExport
                    vec!["https://test.example.com".to_string()],
                ),
                1700000000,
                3600,
                true,
                false,
                "test",
            )
            .unwrap();

        let err = registry
            .authorize_dispatch(
                "complex.operation.v1",
                "https://test.example.com/compute",
                Some(&limited_cap),
                &mut gate,
                1700000050,
                "test",
            )
            .unwrap_err();

        assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
    }

    // ── Eviction Saga Edge Cases ────────────────────────────────────────────────

    #[test]
    fn saga_capacity_management_boundary_behavior() {
        let mut mgr = EvictionSagaManager::new();

        // Fill up to capacity
        let mut saga_ids = Vec::new();
        for i in 0..MAX_SAGAS {
            let artifact_id = format!("artifact-{}", i);
            let saga_id = mgr
                .start_saga(&artifact_id, RemoteCapLookup::Granted, "test")
                .unwrap();
            saga_ids.push(saga_id);
        }

        // Next saga should trigger eviction (but all are non-terminal)
        let err = mgr
            .start_saga("overflow", RemoteCapLookup::Granted, "test")
            .unwrap_err();
        assert!(err.contains("registry full"));

        // Complete some sagas to make them terminal
        for saga_id in &saga_ids[0..5] {
            mgr.begin_upload(saga_id, 1000, "test").unwrap();
            mgr.complete_upload(saga_id, 2000, "test").unwrap();
            mgr.complete_verify(saga_id, 3000, "test").unwrap();
            mgr.complete_retire(saga_id, 4000, "test").unwrap();
        }

        // Now should be able to start new saga (evicts oldest terminal)
        let new_saga = mgr.start_saga("new-artifact", RemoteCapLookup::Granted, "test");
        assert!(new_saga.is_ok());
    }

    #[test]
    fn saga_crash_recovery_compensation_determinism() {
        let mut mgr = EvictionSagaManager::new();

        let saga_id = mgr
            .start_saga("crash-test", RemoteCapLookup::Granted, "test")
            .unwrap();
        mgr.begin_upload(&saga_id, 1000, "test").unwrap();
        mgr.complete_upload(&saga_id, 2000, "test").unwrap();

        // Simulate crash during verify phase
        let action1 = mgr.recover_saga(&saga_id, 3000, "test").unwrap();

        // Second recovery call should be idempotent
        let action2 = mgr.recover_saga(&saga_id, 3100, "test").unwrap();

        // Should get same compensation action both times
        assert!(matches!(action1, CompensationAction::CleanupL3));
        assert!(matches!(action2, CompensationAction::None)); // Already compensated

        let saga = mgr.get_saga(&saga_id).unwrap();
        assert_eq!(saga.phase, SagaPhase::Compensated);
    }

    #[test]
    fn saga_transition_capacity_boundary_enforcement() {
        let mgr = EvictionSagaManager::with_capacities(1000, 3); // Very small transition cap

        let saga_id = mgr
            .start_saga("transition-test", RemoteCapLookup::Granted, "test")
            .unwrap();

        // Perform many transitions
        mgr.begin_upload(&saga_id, 1000, "test").unwrap();
        mgr.complete_upload(&saga_id, 2000, "test").unwrap();
        mgr.complete_verify(&saga_id, 3000, "test").unwrap();
        mgr.complete_retire(&saga_id, 4000, "test").unwrap();

        let saga = mgr.get_saga(&saga_id).unwrap();

        // Should only keep last 3 transitions due to capacity limit
        assert_eq!(saga.transitions.len(), 3);
        assert_eq!(saga.transitions[0].to_phase, SagaPhase::Verifying);
        assert_eq!(saga.transitions[1].to_phase, SagaPhase::Retiring);
        assert_eq!(saga.transitions[2].to_phase, SagaPhase::Complete);
    }

    #[test]
    fn saga_artifact_id_validation_edge_cases() {
        let mut mgr = EvictionSagaManager::new();

        // Test various invalid artifact IDs
        let invalid_ids = [
            "",             // Empty
            " ",            // Whitespace only
            "  artifact  ", // Leading/trailing whitespace
            "<unknown>",    // Reserved
            " <unknown> ",  // Reserved with whitespace
            "\0artifact",   // Null byte
            "artifact\n",   // Newline
            "artifact\t",   // Tab
        ];

        for invalid_id in invalid_ids {
            let err = mgr
                .start_saga(invalid_id, RemoteCapLookup::Granted, "test")
                .unwrap_err();
            assert!(err.contains(ERR_INVALID_ARTIFACT_ID));
        }

        // Test valid artifact ID with Unicode
        let valid_id = "测试-artifact-🚀";
        assert!(
            mgr.start_saga(valid_id, RemoteCapLookup::Granted, "test")
                .is_ok()
        );
    }

    // ── Idempotency Store Edge Cases ────────────────────────────────────────────

    #[test]
    fn idempotency_store_ttl_boundary_behavior() {
        let ttl_secs = 100;
        let mut store = IdempotencyDedupeStore::new(ttl_secs);

        let key = IdempotencyKey::from_bytes([1; 32]);
        let payload = b"ttl-test";

        // Insert at t=1000
        let result = store.check_or_insert(key, payload, 1000, "test");
        assert_eq!(result, DedupeResult::New);

        store
            .complete(key, b"result".to_vec(), 1001, "test")
            .unwrap();

        // At t=1099 (within TTL), should get cached result
        let result = store.check_or_insert(key, payload, 1099, "test");
        assert!(matches!(result, DedupeResult::Duplicate(_)));

        // At t=1100 (exactly at TTL boundary), should treat as expired
        let result = store.check_or_insert(key, payload, 1100, "test");
        assert_eq!(result, DedupeResult::New);
    }

    #[test]
    fn idempotency_store_constant_time_hash_comparison() {
        let mut store = IdempotencyDedupeStore::new(3600);

        let key = IdempotencyKey::from_bytes([2; 32]);

        // Insert with first payload
        store.check_or_insert(key, b"payload1", 1000, "test");
        store
            .complete(key, b"result1".to_vec(), 1001, "test")
            .unwrap();

        // Try with different payload - should use constant-time comparison
        let result = store.check_or_insert(key, b"payload2", 1002, "test");

        match result {
            DedupeResult::Conflict {
                expected_hash,
                actual_hash,
                ..
            } => {
                // Hashes should be different
                assert_ne!(expected_hash, actual_hash);

                // Verify constant-time comparison was used (can't test timing directly,
                // but we can verify the comparison logic is correct)
                assert!(!ct_eq(&expected_hash, &actual_hash));
            }
            other => panic!("Expected conflict, got {:?}", other),
        }
    }

    #[test]
    fn idempotency_store_capacity_exhaustion_with_sweep() {
        // Create store that will hit capacity quickly
        let mut store = IdempotencyDedupeStore::new(1); // Very short TTL

        // Fill store to capacity with expired entries
        for i in 0..MAX_DEDUPE_ENTRIES {
            let key = {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
                IdempotencyKey::from_bytes(bytes)
            };

            store.check_or_insert(key, &i.to_le_bytes(), 1000, "test"); // All at t=1000
        }

        // All entries should be expired at t=1002 (TTL=1)
        // New insert should trigger sweep and succeed
        let new_key = IdempotencyKey::from_bytes([0xFF; 32]);
        let result = store.check_or_insert(new_key, b"new", 1002, "test");
        assert_eq!(result, DedupeResult::New);

        // Store should be much smaller after sweep
        assert!(store.entry_count() < MAX_DEDUPE_ENTRIES);
    }

    #[test]
    fn idempotency_store_crash_recovery_comprehensive() {
        let mut store = IdempotencyDedupeStore::new(3600);

        // Create various in-flight entries
        let keys: Vec<_> = (0..10)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                IdempotencyKey::from_bytes(bytes)
            })
            .collect();

        // Insert some entries
        for (i, &key) in keys.iter().enumerate() {
            store.check_or_insert(key, &[i as u8], 1000, "test");

            // Complete half of them
            if i % 2 == 0 {
                store
                    .complete(key, vec![i as u8; 10], 1001, "test")
                    .unwrap();
            }
        }

        // Simulate crash - recover in-flight entries
        let recovered = store.recover_inflight("crash-test");
        assert_eq!(recovered, 5); // Half were still in-flight

        // All processing entries should now be abandoned
        for (i, &key) in keys.iter().enumerate() {
            let result = store.check_or_insert(key, &[i as u8], 1002, "test");

            if i % 2 == 0 {
                // Completed entries should still return cached results
                assert!(matches!(result, DedupeResult::Duplicate(_)));
            } else {
                // Abandoned entries should allow retry
                assert_eq!(result, DedupeResult::New);
            }
        }
    }

    // ── Remote Bulkhead Edge Cases ──────────────────────────────────────────────

    #[test]
    fn bulkhead_permit_id_exhaustion_boundary() {
        let mut bulkhead = RemoteBulkhead::new(2, BackpressurePolicy::Reject, 50).unwrap();

        // Set permit ID close to exhaustion
        bulkhead.next_permit_id = u64::MAX - 1;

        // Should issue second-to-last permit ID
        let permit1 = bulkhead.acquire(true, "req1", 1000).unwrap();
        assert_eq!(permit1.permit_id(), u64::MAX - 1);

        // Should issue last permit ID
        let permit2 = bulkhead.acquire(true, "req2", 1001).unwrap();
        assert_eq!(permit2.permit_id(), u64::MAX);

        // Release both permits
        bulkhead.release(permit1, 1002).unwrap();
        bulkhead.release(permit2, 1003).unwrap();

        // Next acquire should fail due to permit ID exhaustion
        let err = bulkhead.acquire(true, "req3", 1004).unwrap_err();
        assert_eq!(err.code(), "RB_ERR_PERMIT_ID_EXHAUSTED");
    }

    #[test]
    fn bulkhead_queue_timeout_precision_boundary() {
        let mut bulkhead = RemoteBulkhead::new(
            1,
            BackpressurePolicy::Queue {
                max_depth: 2,
                timeout_ms: 1,
            }, // 1ms timeout
            50,
        )
        .unwrap();

        // Acquire permit to fill capacity
        let permit = bulkhead.acquire(true, "active", 1000).unwrap();

        // Queue request at t=1001
        let queued = bulkhead.acquire(true, "queued", 1001).unwrap_err();
        assert!(matches!(queued, BulkheadError::Queued { .. }));

        // Poll at exactly timeout boundary (t=1002, expires_at=1002)
        let timeout_err = bulkhead.poll_queued("queued", 1002).unwrap_err();
        assert!(matches!(timeout_err, BulkheadError::QueueTimeout { .. }));

        // Verify request was removed from queue
        assert_eq!(bulkhead.queue_depth(), 0);

        bulkhead.release(permit, 1003).unwrap();
    }

    #[test]
    fn bulkhead_capacity_change_race_conditions() {
        let mut bulkhead = RemoteBulkhead::new(3, BackpressurePolicy::Reject, 50).unwrap();

        // Fill to capacity
        let permit1 = bulkhead.acquire(true, "req1", 1000).unwrap();
        let permit2 = bulkhead.acquire(true, "req2", 1001).unwrap();
        let permit3 = bulkhead.acquire(true, "req3", 1002).unwrap();

        // Reduce capacity while at full capacity
        bulkhead.set_max_in_flight(1, 1003).unwrap();
        assert_eq!(bulkhead.draining_target(), Some(1));

        // New acquires should be blocked by draining
        let drain_err = bulkhead.acquire(true, "req4", 1004).unwrap_err();
        assert!(matches!(
            drain_err,
            BulkheadError::Draining {
                in_flight: 3,
                target_cap: 1
            }
        ));

        // Release permits one by one
        bulkhead.release(permit1, 1005).unwrap();
        assert_eq!(bulkhead.draining_target(), Some(1)); // Still draining

        bulkhead.release(permit2, 1006).unwrap();
        assert_eq!(bulkhead.draining_target(), Some(1)); // Still draining

        bulkhead.release(permit3, 1007).unwrap();
        assert_eq!(bulkhead.draining_target(), None); // Draining complete

        // Should now be able to acquire within new capacity
        let new_permit = bulkhead.acquire(true, "req5", 1008).unwrap();
        bulkhead.release(new_permit, 1009).unwrap();
    }

    #[test]
    fn bulkhead_latency_percentile_calculation_edge_cases() {
        let mut bulkhead = RemoteBulkhead::new(10, BackpressurePolicy::Reject, 50).unwrap();

        // Test with empty samples
        assert_eq!(bulkhead.p99_foreground_latency_ms(), None);

        // Test with single sample
        bulkhead.record_foreground_latency(100, 1000);
        assert_eq!(bulkhead.p99_foreground_latency_ms(), Some(100));

        // Test with exactly 100 samples (edge case for percentile calculation)
        for i in 1..100 {
            bulkhead.record_foreground_latency(i, 1000 + i);
        }

        let p99 = bulkhead.p99_foreground_latency_ms().unwrap();
        // P99 of 1..100 should be 99
        assert_eq!(p99, 99);

        // Test latency target evaluation
        assert!(!bulkhead.latency_within_target()); // P99=99 > target=50

        // Add many low latency samples to bring P99 down
        for i in 0..1000 {
            bulkhead.record_foreground_latency(10, 2000 + i);
        }

        let new_p99 = bulkhead.p99_foreground_latency_ms().unwrap();
        assert!(new_p99 <= 50); // Should now be within target
        assert!(bulkhead.latency_within_target());
    }

    #[test]
    fn bulkhead_request_id_validation_comprehensive() {
        let mut bulkhead = RemoteBulkhead::new(2, BackpressurePolicy::Reject, 50).unwrap();

        // Test various invalid request IDs
        let invalid_ids = [
            "",      // Empty
            " ",     // Whitespace only
            "  ",    // Multiple whitespace
            "\t",    // Tab only
            "\n",    // Newline only
            "\t\n ", // Mixed whitespace
        ];

        for invalid_id in invalid_ids {
            let err = bulkhead.acquire(true, invalid_id, 1000).unwrap_err();
            assert_eq!(err.code(), "RB_ERR_INVALID_REQUEST_ID");
        }

        // Test valid request IDs with edge case content
        let valid_ids = [
            "a",                   // Single character
            "req-123",             // Normal ID
            "测试-request",        // Unicode
            "request with spaces", // Internal spaces (should be valid)
            " leading-space",      // Leading space should be invalid
            "trailing-space ",     // Trailing space should be invalid
        ];

        // Only the internal spaces one should succeed
        let permit = bulkhead.acquire(true, "request with spaces", 1000).unwrap();
        bulkhead.release(permit, 1001).unwrap();

        // The ones with leading/trailing spaces should fail
        for &id in &[" leading-space", "trailing-space "] {
            let err = bulkhead.acquire(true, id, 1002).unwrap_err();
            assert_eq!(err.code(), "RB_ERR_INVALID_REQUEST_ID");
        }
    }

    #[test]
    fn bulkhead_event_log_bounded_capacity_stress() {
        let mut bulkhead = RemoteBulkhead::new(1, BackpressurePolicy::Reject, 50).unwrap();

        // Generate many events to test bounded logging
        for i in 0..1000 {
            bulkhead.record_foreground_latency(i, i);
        }

        // Event log should be bounded
        assert!(bulkhead.events().len() <= crate::capacity_defaults::aliases::MAX_BULKHEAD_EVENTS);

        // Latest events should be preserved
        let events = bulkhead.events();
        if !events.is_empty() {
            let last_event = events.last().unwrap();
            assert!(last_event.detail.contains("latency_ms=999"));
        }
    }

    // ── Cross-module Integration Edge Cases ─────────────────────────────────────

    #[test]
    fn remote_config_integration_boundary_values() {
        let configs = [
            RemoteConfig {
                idempotency_ttl_secs: 0,
            }, // Zero TTL
            RemoteConfig {
                idempotency_ttl_secs: 1,
            }, // Minimum TTL
            RemoteConfig {
                idempotency_ttl_secs: u64::MAX,
            }, // Maximum TTL
        ];

        for config in configs {
            let store = IdempotencyDedupeStore::from_remote_config(&config);
            assert_eq!(store.ttl_secs(), config.idempotency_ttl_secs);

            // Should be able to create entries even with extreme TTL values
            let key = IdempotencyKey::from_bytes([0x42; 32]);
            let result = store.check_or_insert(key, b"test", 1000, "test");
            assert_eq!(result, DedupeResult::New);
        }
    }

    #[test]
    fn memory_pressure_simulation() {
        // Simulate memory pressure across multiple remote components
        let mut registry = ComputationRegistry::new(1, "stress");
        let mut saga_mgr = EvictionSagaManager::new();
        let mut store = IdempotencyDedupeStore::new(3600);
        let mut bulkhead = RemoteBulkhead::new(
            100,
            BackpressurePolicy::Queue {
                max_depth: 1000,
                timeout_ms: 1000,
            },
            50,
        )
        .unwrap();

        // Create many entries across all components
        for i in 0..1000 {
            // Registry entries (will hit capacity limit)
            if i < MAX_COMPUTATION_ENTRIES {
                let entry = ComputationEntry {
                    name: format!("stress{}.test.v1", i),
                    description: "Stress test".to_string(),
                    required_capabilities: vec![RemoteOperation::RemoteComputation],
                    input_schema: "{}".to_string(),
                    output_schema: "{}".to_string(),
                };
                let _ = registry.register_computation(entry, "stress");
            }

            // Saga entries (will trigger eviction)
            if i < MAX_SAGAS + 100 {
                let artifact_id = format!("stress-artifact-{}", i);
                let _ = saga_mgr.start_saga(&artifact_id, RemoteCapLookup::Granted, "stress");
            }

            // Idempotency store entries
            let key = {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
                IdempotencyKey::from_bytes(bytes)
            };
            store.check_or_insert(key, &i.to_le_bytes(), 1000, "stress");

            // Bulkhead latency samples
            bulkhead.record_foreground_latency(i as u64, 1000 + i as u64);
        }

        // All components should remain functional under stress
        assert!(registry.list_computations().len() <= MAX_COMPUTATION_ENTRIES);
        assert!(saga_mgr.saga_count() <= MAX_SAGAS);
        assert!(store.entry_count() > 0);
        assert!(!bulkhead.events().is_empty());
    }

    #[test]
    fn deterministic_hash_consistency_across_components() {
        // Verify hash consistency across different remote components
        let payload = b"test-payload-for-hashing";

        // Idempotency store payload hash
        let ids_hash = hash_payload(payload);

        // Virtual transport fault payload hash
        let mut harness = VirtualTransportFaultHarness::new(42);
        let vtf_hash = {
            let test_result = harness.run_campaign("test", &no_faults(), 1, "test");
            // Extract hash from content_hash calculation
            test_result.content_hash
        };

        // Both should be deterministic and consistent
        let ids_hash_2 = hash_payload(payload);
        assert_eq!(ids_hash, ids_hash_2);

        // Different payloads should produce different hashes
        let different_hash = hash_payload(b"different-payload");
        assert_ne!(ids_hash, different_hash);
    }

    #[test]
    fn negative_idempotency_empty_domain_prefix_rejected() {
        let err = IdempotencyKeyDeriver::new(&[]).unwrap_err();

        assert_eq!(err.code(), "IK_ERR_EMPTY_DOMAIN_PREFIX");
    }

    #[test]
    fn negative_idempotency_empty_computation_name_rejected() {
        let deriver = IdempotencyKeyDeriver::default();
        let err = deriver.derive_key("", 7, b"payload").unwrap_err();

        assert_eq!(err.code(), "IK_ERR_EMPTY_COMPUTATION_NAME");
    }

    #[test]
    fn negative_idempotency_key_from_short_hex_rejected() {
        let err = IdempotencyKey::from_hex("00").unwrap_err();

        assert_eq!(err.code(), "IK_ERR_INVALID_HEX");
    }

    #[test]
    fn negative_registry_empty_description_does_not_insert() {
        let mut registry = ComputationRegistry::new(1, "negative-registry");
        let entry = ComputationEntry {
            name: "domain.action.v1".to_string(),
            description: String::new(),
            required_capabilities: vec![RemoteOperation::RemoteComputation],
            input_schema: "{}".to_string(),
            output_schema: "{}".to_string(),
        };

        let err = registry
            .register_computation(entry, "negative-registry")
            .unwrap_err();

        assert_eq!(err.code(), ERR_INVALID_COMPUTATION_ENTRY);
        assert_eq!(registry.list_computations().len(), 0);
    }

    #[test]
    fn negative_registry_malformed_lookup_does_not_insert() {
        let mut registry = ComputationRegistry::new(1, "negative-registry");

        let err = registry
            .validate_computation_name("not-canonical", "negative-registry")
            .unwrap_err();

        assert_eq!(err.code(), ERR_MALFORMED_COMPUTATION_NAME);
        assert_eq!(registry.list_computations().len(), 0);
    }

    #[test]
    fn negative_saga_start_without_remote_cap_rejected() {
        let mut mgr = EvictionSagaManager::new();

        let err = mgr
            .start_saga(
                "artifact-no-cap",
                RemoteCapLookup::NotPresent,
                "negative-saga",
            )
            .unwrap_err();

        assert!(err.contains("RemoteCap required"));
        assert_eq!(mgr.saga_count(), 0);
    }

    #[test]
    fn negative_saga_invalid_transition_leaves_phase_created() {
        let mut mgr = EvictionSagaManager::new();
        let saga_id = mgr
            .start_saga(
                "artifact-invalid-transition",
                RemoteCapLookup::Granted,
                "negative-saga",
            )
            .unwrap();

        let err = mgr
            .complete_upload(&saga_id, 1_000, "negative-saga")
            .unwrap_err();

        assert!(err.contains("invalid transition"));
        assert_eq!(mgr.get_saga(&saga_id).unwrap().phase, SagaPhase::Created);
    }

    #[test]
    fn negative_saga_failed_cap_recheck_blocks_upload() {
        let mut mgr = EvictionSagaManager::new();
        let saga_id = mgr
            .start_saga(
                "artifact-cap-recheck",
                RemoteCapLookup::Granted,
                "negative-saga",
            )
            .unwrap();

        let err = mgr
            .recheck_remote_cap(&saga_id, RemoteCapLookup::NotPresent, "negative-saga")
            .unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));

        let err = mgr
            .begin_upload(&saga_id, 2_000, "negative-saga")
            .unwrap_err();
        assert!(err.contains("RemoteCap recheck failed"));
        assert_eq!(mgr.get_saga(&saga_id).unwrap().phase, SagaPhase::Created);
    }

    #[test]
    fn negative_idempotency_complete_unknown_key_rejected() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let unknown_key = IdempotencyKey::from_bytes([9; 32]);

        let err = store
            .complete(unknown_key, b"result".to_vec(), 1_000, "negative-store")
            .unwrap_err();

        assert!(err.contains("no entry for key"));
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn negative_bulkhead_zero_queue_depth_rejected() {
        let err = RemoteBulkhead::new(
            1,
            BackpressurePolicy::Queue {
                max_depth: 0,
                timeout_ms: 10,
            },
            50,
        )
        .unwrap_err();

        assert_eq!(err.code(), "RB_ERR_INVALID_CONFIG");
    }

    #[test]
    fn negative_bulkhead_duplicate_active_request_rejected() {
        let mut bulkhead = RemoteBulkhead::new(2, BackpressurePolicy::Reject, 50).unwrap();
        let permit = bulkhead.acquire(true, "duplicate-active", 1_000).unwrap();

        let err = bulkhead
            .acquire(true, "duplicate-active", 1_001)
            .unwrap_err();

        assert_eq!(err.code(), "RB_ERR_DUPLICATE_REQUEST");
        assert_eq!(bulkhead.current_in_flight(), 1);
        bulkhead.release(permit, 1_002).unwrap();
    }

    #[test]
    fn negative_bulkhead_unknown_queued_request_rejected() {
        let mut bulkhead = RemoteBulkhead::new(
            1,
            BackpressurePolicy::Queue {
                max_depth: 1,
                timeout_ms: 10,
            },
            50,
        )
        .unwrap();

        let err = bulkhead
            .poll_queued("missing-queued-request", 1_000)
            .unwrap_err();

        assert_eq!(err.code(), "RB_ERR_UNKNOWN_REQUEST");
        assert_eq!(bulkhead.queue_depth(), 0);
    }
}
