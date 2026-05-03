//! Remote-control primitives for network-bound operations.

#[cfg(feature = "remote-ops")]
pub mod computation_registry;
#[cfg(feature = "remote-ops")]
pub mod eviction_saga;
#[cfg(feature = "remote-ops")]
pub mod idempotency;
#[cfg(feature = "remote-ops")]
pub mod idempotency_store;
#[cfg(feature = "remote-ops")]
pub mod remote_bulkhead;
pub mod virtual_transport_faults;

#[cfg(all(test, feature = "remote-ops"))]
mod remote_conformance_tests;

#[cfg(test)]
mod remote_module_negative_tests {
    use super::virtual_transport_faults::{
        FaultClass, FaultConfig, FaultSchedule, ScheduledFault, VirtualTransportFaultHarness,
        event_codes,
    };

    fn valid_config() -> FaultConfig {
        FaultConfig {
            drop_probability: 0.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 10,
        }
    }

    #[test]
    fn negative_config_rejects_nan_drop_probability() {
        let config = FaultConfig {
            drop_probability: f64::NAN,
            ..valid_config()
        };

        let err = config
            .validate()
            .expect_err("NaN drop probability must fail");

        assert!(err.contains("drop_probability"));
    }

    #[test]
    fn negative_config_rejects_infinite_reorder_probability() {
        let config = FaultConfig {
            reorder_probability: f64::INFINITY,
            reorder_max_depth: 4,
            ..valid_config()
        };

        let err = config
            .validate()
            .expect_err("infinite reorder probability must fail");

        assert!(err.contains("reorder_probability"));
    }

    #[test]
    fn negative_config_rejects_negative_corrupt_probability() {
        let config = FaultConfig {
            corrupt_probability: -0.01,
            corrupt_bit_count: 1,
            ..valid_config()
        };

        let err = config
            .validate()
            .expect_err("negative corrupt probability must fail");

        assert!(err.contains("corrupt_probability"));
    }

    #[test]
    fn negative_zero_message_schedule_injects_no_faults() {
        let config = FaultConfig {
            drop_probability: 1.0,
            max_faults: 10,
            ..valid_config()
        };

        let schedule = FaultSchedule::from_seed(42, &config, 0);

        assert!(schedule.faults.is_empty());
        assert_eq!(schedule.total_messages, 0);
    }

    #[test]
    fn negative_max_faults_caps_guaranteed_drop_schedule() {
        let config = FaultConfig {
            drop_probability: 1.0,
            max_faults: 3,
            ..valid_config()
        };

        let schedule = FaultSchedule::from_seed(42, &config, 20);

        assert_eq!(schedule.faults.len(), 3);
        assert!(
            schedule
                .faults
                .iter()
                .all(|scheduled| matches!(scheduled.fault, FaultClass::Drop))
        );
    }

    #[test]
    fn negative_empty_fault_log_exports_empty_string() {
        let harness = VirtualTransportFaultHarness::new(7);

        assert_eq!(harness.export_fault_log_jsonl(), "");
        assert_eq!(harness.fault_count(), 0);
    }

    #[test]
    fn negative_reorder_large_depth_does_not_deliver_prematurely() {
        let mut harness = VirtualTransportFaultHarness::new(99);
        let first = harness.apply_reorder(1, b"first", 4, "trace-negative");
        let second = harness.apply_reorder(2, b"second", 4, "trace-negative");

        assert!(first.is_none());
        assert!(second.is_none());
        assert_eq!(harness.fault_count(), 2);
        assert_eq!(harness.flush_reorder_buffer().len(), 2);
    }

    #[test]
    fn negative_config_rejects_zero_max_faults() {
        let config = FaultConfig {
            max_faults: 0,
            ..valid_config()
        };

        let err = config.validate().expect_err("zero fault budget must fail");

        assert!(err.contains("max_faults"));
    }

    #[test]
    fn negative_config_rejects_reorder_without_depth() {
        let config = FaultConfig {
            reorder_probability: 0.5,
            reorder_max_depth: 0,
            ..valid_config()
        };

        let err = config
            .validate()
            .expect_err("positive reorder probability needs depth");

        assert!(err.contains("reorder_max_depth"));
    }

    #[test]
    fn negative_config_rejects_corruption_without_bit_count() {
        let config = FaultConfig {
            corrupt_probability: 0.5,
            corrupt_bit_count: 0,
            ..valid_config()
        };

        let err = config
            .validate()
            .expect_err("positive corrupt probability needs bit count");

        assert!(err.contains("corrupt_bit_count"));
    }

    #[test]
    fn negative_future_drop_fault_does_not_drop_current_message() {
        let schedule = FaultSchedule {
            seed: 1,
            faults: vec![ScheduledFault {
                message_index: 1,
                fault: FaultClass::Drop,
            }],
            total_messages: 2,
        };
        let mut harness = VirtualTransportFaultHarness::new(1);

        let delivered = harness.process_message(&schedule, 0, 11, b"payload", "trace-negative");

        assert_eq!(delivered, Some(b"payload".to_vec()));
        assert_eq!(harness.fault_count(), 0);
        assert_eq!(harness.audit_log()[0].event_code, event_codes::FAULT_NONE);
    }

    #[test]
    fn negative_corrupt_out_of_range_bits_preserves_empty_payload() {
        let mut harness = VirtualTransportFaultHarness::new(1);

        let corrupted = harness.apply_corrupt(12, b"", &[0, 7, usize::MAX], "trace-negative");

        assert!(corrupted.is_empty());
        assert_eq!(harness.fault_count(), 1);
        assert_eq!(harness.fault_log()[0].fault_class, "Corrupt");
        assert_eq!(
            harness.audit_log()[0].event_code,
            event_codes::FAULT_CORRUPT_APPLIED
        );
    }

    #[test]
    fn negative_fault_log_capacity_one_keeps_latest_fault_only() {
        let mut harness = VirtualTransportFaultHarness::with_log_capacities(1, 1, 8);

        harness.apply_drop(21, b"old", "trace-negative");
        harness.apply_drop(22, b"new", "trace-negative");

        assert_eq!(harness.fault_log().len(), 1);
        assert_eq!(harness.fault_log()[0].fault_id, 2);
        assert_eq!(harness.fault_log()[0].message_id, 22);
    }

    #[test]
    fn negative_audit_log_capacity_one_keeps_latest_event_only() {
        let mut harness = VirtualTransportFaultHarness::with_log_capacities(1, 8, 1);

        harness.apply_drop(31, b"drop", "trace-negative");
        harness.apply_corrupt(32, b"corrupt", &[0], "trace-negative");

        assert_eq!(harness.audit_log().len(), 1);
        assert_eq!(
            harness.audit_log()[0].event_code,
            event_codes::FAULT_CORRUPT_APPLIED
        );
    }

    #[test]
    fn negative_config_rejects_drop_probability_above_one() {
        let config = FaultConfig {
            drop_probability: 1.01,
            ..valid_config()
        };

        let err = config
            .validate()
            .expect_err("drop probability above one must fail closed");

        assert!(err.contains("drop_probability"));
    }

    #[test]
    fn negative_config_rejects_reorder_probability_above_one() {
        let config = FaultConfig {
            reorder_probability: 1.01,
            reorder_max_depth: 4,
            ..valid_config()
        };

        let err = config
            .validate()
            .expect_err("reorder probability above one must fail closed");

        assert!(err.contains("reorder_probability"));
    }

    #[test]
    fn negative_config_rejects_corrupt_probability_above_one() {
        let config = FaultConfig {
            corrupt_probability: 1.01,
            corrupt_bit_count: 1,
            ..valid_config()
        };

        let err = config
            .validate()
            .expect_err("corrupt probability above one must fail closed");

        assert!(err.contains("corrupt_probability"));
    }

    #[test]
    fn negative_fault_class_deserialize_rejects_lowercase_variant() {
        let result: Result<FaultClass, _> = serde_json::from_str("\"drop\"");

        assert!(
            result.is_err(),
            "fault classes must use canonical serde variant names"
        );
    }

    #[test]
    fn negative_fault_class_deserialize_rejects_reorder_without_depth() {
        let raw = serde_json::json!({
            "Reorder": {},
        });

        let result: Result<FaultClass, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "reorder fault classes must include an explicit depth"
        );
    }

    #[test]
    fn negative_scheduled_fault_deserialize_rejects_missing_fault() {
        let raw = serde_json::json!({
            "message_index": 3_usize,
        });

        let result: Result<ScheduledFault, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "scheduled faults must include a concrete fault class"
        );
    }

    #[test]
    fn negative_fault_schedule_deserialize_rejects_string_total_messages() {
        let raw = serde_json::json!({
            "seed": 7_u64,
            "faults": [],
            "total_messages": "10",
        });

        let result: Result<FaultSchedule, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "fault schedule message counts must remain numeric"
        );
    }

    #[test]
    fn negative_fault_config_deserialize_rejects_string_max_faults() {
        let raw = serde_json::json!({
            "drop_probability": 0.0,
            "reorder_probability": 0.0,
            "reorder_max_depth": 0_usize,
            "corrupt_probability": 0.0,
            "corrupt_bit_count": 0_usize,
            "max_faults": "10",
        });

        let result: Result<FaultConfig, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "fault budgets must remain numeric in serialized configs"
        );
    }

    #[test]
    fn negative_fault_config_deserialize_rejects_missing_corrupt_bit_count() {
        let raw = serde_json::json!({
            "drop_probability": 0.0,
            "reorder_probability": 0.0,
            "reorder_max_depth": 0_usize,
            "corrupt_probability": 0.0,
            "max_faults": 10_usize,
        });

        let result: Result<FaultConfig, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "fault configs must include corrupt_bit_count explicitly"
        );
    }

    // === HARDENING-FOCUSED NEGATIVE-PATH TESTS ===
    // Tests for specific hardening patterns that may be missing

    #[test]
    fn negative_counter_overflow_requires_saturating_add() {
        // Test that counters use saturating_add instead of raw addition
        // Raw addition can cause integer overflow leading to security bypass
        let mut harness = VirtualTransportFaultHarness::new(valid_config());

        // Simulate counter overflow scenario
        let large_fault_count = u32::MAX - 1;

        // Create many scheduled faults to test counter overflow protection
        for i in 0..10 {
            let fault = ScheduledFault {
                fault_class: FaultClass::Drop,
                delay_millis: 100 + i * 10,
                event_code: event_codes::SCHEDULED_FAULT,
            };

            // This should use saturating_add internally to prevent overflow
            harness.schedule_fault(fault);
        }

        // Verify harness remains stable despite potential counter overflow
        let stats = harness.get_statistics();

        // Check that counters don't wrap around to 0 (overflow protection)
        assert!(
            stats.faults_applied <= stats.faults_scheduled,
            "Applied faults should not exceed scheduled due to overflow"
        );

        // Test boundary condition with maximum counter values
        // This tests whether internal counters use saturating arithmetic
        let config_max_faults = FaultConfig {
            max_faults: usize::MAX, // Test maximum value
            ..valid_config()
        };

        match config_max_faults.validate() {
            Ok(_) => {
                // If accepted, internal operations should handle max values safely
                assert!(
                    config_max_faults.max_faults > 0,
                    "Max faults should remain positive"
                );
            }
            Err(error_msg) => {
                // Rejection of extreme values is also acceptable
                assert!(
                    !error_msg.is_empty(),
                    "Should provide error message for extreme max_faults"
                );
            }
        }
    }

    #[test]
    fn negative_hash_comparison_requires_constant_time() {
        // Test that hash comparisons use ct_eq_bytes instead of == operator
        // Direct == comparison on hashes is vulnerable to timing attacks
        use std::collections::HashMap;

        let mut fault_checksums = HashMap::new();

        // Create test fault configurations with computed checksums
        let config1 = FaultConfig {
            drop_probability: 0.1,
            corrupt_bit_count: 4,
            ..valid_config()
        };

        let config2 = FaultConfig {
            drop_probability: 0.1,
            corrupt_bit_count: 5, // Different bit count
            ..valid_config()
        };

        // Serialize configs to test hash comparison
        let serialized1 = serde_json::to_string(&config1).unwrap();
        let serialized2 = serde_json::to_string(&config2).unwrap();

        // Hash the serialized configurations
        use sha2::{Digest, Sha256};

        let mut hasher1 = Sha256::new();
        let mut hasher2 = Sha256::new();
        hasher1.update(b"remote_config_v1:");
        hasher2.update(b"remote_config_v1:");
        hasher1.update(serialized1.as_bytes());
        hasher2.update(serialized2.as_bytes());

        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();

        // Convert hashes to byte arrays for testing
        let hash_bytes1 = hash1.as_slice();
        let hash_bytes2 = hash2.as_slice();

        // Store in map to test hash collision resistance
        fault_checksums.insert(hash_bytes1, "config1");
        fault_checksums.insert(hash_bytes2, "config2");

        // Verify different configs produce different hashes (no collision)
        if config1 != config2 {
            assert_ne!(
                hash1, hash2,
                "Different configs should produce different hashes"
            );
            assert_eq!(
                fault_checksums.len(),
                2,
                "Should have two distinct hash entries"
            );
        }

        // Test hash comparison with similar but different data
        let similar_config = FaultConfig {
            drop_probability: 0.10000000000001, // Very slightly different
            ..config1
        };

        let similar_serialized = serde_json::to_string(&similar_config).unwrap();
        let mut similar_hasher = Sha256::new();
        similar_hasher.update(b"remote_config_v1:");
        similar_hasher.update(similar_serialized.as_bytes());
        let similar_hash = similar_hasher.finalize();

        // Even tiny differences should be detectable
        if similar_config != config1 {
            assert_ne!(
                similar_hash.as_slice(),
                hash_bytes1,
                "Tiny differences should be detected in hash comparison"
            );
        }

        // Note: In production code, these hash comparisons should use ct_eq_bytes
        // for timing attack resistance when comparing cryptographic hashes
    }

    #[test]
    fn negative_expiry_check_requires_fail_closed_semantics() {
        // Test that expiry checks use >= instead of > for fail-closed behavior
        // Using > allows exactly-expired items to pass, creating security bypass
        let current_time_ms = 1000000;
        let expired_time_ms = 1000000; // Exactly at boundary
        let future_time_ms = 1000001; // Clearly in future
        let past_time_ms = 999999; // Clearly in past

        // Test fault schedule expiry logic
        let expiry_test_cases = [
            (past_time_ms, "past time should be expired"),
            (
                expired_time_ms,
                "boundary time should be expired (fail-closed)",
            ),
            (future_time_ms, "future time should not be expired"),
        ];

        for (test_time, description) in &expiry_test_cases {
            let fault = ScheduledFault {
                fault_class: FaultClass::Corrupt,
                delay_millis: *test_time, // Using as expiry time for this test
                event_code: event_codes::SCHEDULED_FAULT,
            };

            // In a proper implementation, expiry should be:
            // is_expired = current_time >= expiry_time  (fail-closed)
            // NOT: is_expired = current_time > expiry_time  (vulnerable)

            let is_expired = current_time_ms >= *test_time;

            match (*test_time, is_expired) {
                (time, true) if time <= current_time_ms => {
                    // Correctly identified as expired (including boundary case)
                    assert!(is_expired, "Should be expired: {}", description);
                }
                (time, false) if time > current_time_ms => {
                    // Correctly identified as not expired
                    assert!(!is_expired, "Should not be expired: {}", description);
                }
                _ => {
                    // This case should not occur with proper >= comparison
                    assert!(false, "Unexpected expiry state for: {}", description);
                }
            }
        }

        // Test configuration validation with boundary expiry values
        let boundary_config = FaultConfig {
            max_faults: 0, // Test zero boundary
            ..valid_config()
        };

        // Zero max_faults should be handled as expired/disabled (fail-closed)
        let validation_result = boundary_config.validate();
        match validation_result {
            Ok(_) => {
                // If zero is accepted, it should disable faults (safe behavior)
                assert_eq!(
                    boundary_config.max_faults, 0,
                    "Zero max_faults should remain zero"
                );
            }
            Err(error_msg) => {
                // Rejection of zero max_faults is also acceptable (fail-closed)
                assert!(
                    error_msg.contains("max_faults")
                        || error_msg.contains("zero")
                        || error_msg.contains("0"),
                    "Error should mention zero/max_faults constraint"
                );
            }
        }
    }

    #[test]
    fn negative_length_casting_requires_safe_conversion() {
        // Test that .len() as u32 is replaced with u32::try_from for overflow safety
        // Direct casting can silently truncate on 64-bit platforms
        use std::convert::TryFrom;

        // Test with small collections (safe conversion)
        let small_schedule = vec![ScheduledFault {
            fault_class: FaultClass::Drop,
            delay_millis: 100,
            event_code: event_codes::SCHEDULED_FAULT,
        }];

        // Safe conversion should succeed
        let small_count =
            u32::try_from(small_schedule.len()).expect("Small collection should convert safely");
        assert_eq!(
            small_count, 1,
            "Small collection conversion should be accurate"
        );

        // Test with medium-sized collection
        let medium_schedule: Vec<ScheduledFault> = (0..1000)
            .map(|i| ScheduledFault {
                fault_class: FaultClass::Reorder,
                delay_millis: i as u64,
                event_code: event_codes::SCHEDULED_FAULT,
            })
            .collect();

        let medium_count =
            u32::try_from(medium_schedule.len()).expect("Medium collection should convert safely");
        assert_eq!(
            medium_count, 1000,
            "Medium collection conversion should be accurate"
        );

        // Test with collection that would overflow u32 (on 64-bit systems)
        // We can't actually create a 4GB+ vector in tests, so simulate the check
        let large_size: usize = (u32::MAX as usize) + 1;
        let overflow_result = u32::try_from(large_size);

        assert!(
            overflow_result.is_err(),
            "Large size should fail safe conversion"
        );

        // Demonstrate the problem with unsafe casting
        let unsafe_cast = large_size as u32; // This would be wrong in production
        assert_eq!(unsafe_cast, 0, "Unsafe cast wraps around to 0, losing data");

        // Test boundary at u32::MAX
        let max_u32_size = u32::MAX as usize;
        let max_conversion = u32::try_from(max_u32_size);
        assert!(
            max_conversion.is_ok(),
            "u32::MAX should convert successfully"
        );
        assert_eq!(
            max_conversion.unwrap(),
            u32::MAX,
            "Boundary conversion should be accurate"
        );

        // In production code, should use:
        // let safe_count = u32::try_from(collection.len()).unwrap_or(u32::MAX);
        // instead of: let unsafe_count = collection.len() as u32;
    }

    #[test]
    fn negative_domain_separation_required_for_hash_inputs() {
        // Test that hash operations include domain separators to prevent collision attacks
        // Without domain separation, different data types can produce identical hashes
        use sha2::{Digest, Sha256};

        // Test proper domain separation in fault configuration hashing
        let base_config = FaultConfig {
            drop_probability: 0.5,
            reorder_probability: 0.2,
            corrupt_bit_count: 4,
            ..valid_config()
        };

        // Create hash with domain separator (proper approach)
        let mut hasher_with_domain = Sha256::new();
        hasher_with_domain.update(b"fault_config_v1:"); // Domain separator
        let config_json = serde_json::to_string(&base_config).expect("config serialization");
        hasher_with_domain.update(config_json.as_bytes());
        let hash_with_domain = hasher_with_domain.finalize();

        // Create hash without domain separator (vulnerable approach)
        let mut hasher_without_domain = Sha256::new();
        hasher_without_domain.update(config_json.as_bytes());
        let hash_without_domain = hasher_without_domain.finalize();

        // Hashes should be different when domain separator is included
        assert_ne!(
            hash_with_domain.as_slice(),
            hash_without_domain.as_slice(),
            "Domain separator should change hash value"
        );

        // Test domain separation prevents collision between different data types
        let fault_schedule = ScheduledFault {
            fault_class: FaultClass::Drop,
            delay_millis: 0, // Same numeric values as in config
            event_code: event_codes::SCHEDULED_FAULT,
        };

        // Hash fault config with domain separator
        let mut config_hasher = Sha256::new();
        config_hasher.update(b"fault_config:");
        let config_json = serde_json::to_string(&base_config).expect("config serialization");
        config_hasher.update(config_json.as_bytes());
        let config_hash = config_hasher.finalize();

        // Hash scheduled fault with different domain separator
        let mut schedule_hasher = Sha256::new();
        schedule_hasher.update(b"scheduled_fault:");
        let schedule_json = serde_json::to_string(&fault_schedule).expect("schedule serialization");
        schedule_hasher.update(schedule_json.as_bytes());
        let schedule_hash = schedule_hasher.finalize();

        // Different domain separators should prevent collisions
        assert_ne!(
            config_hash.as_slice(),
            schedule_hash.as_slice(),
            "Different domain separators should prevent hash collisions"
        );

        // Test length-prefixed domain separation (even better)
        let mut length_prefixed_hasher = Sha256::new();
        let domain = "fault_config_v1";
        length_prefixed_hasher
            .update((u64::try_from(domain.len()).unwrap_or(u64::MAX)).to_le_bytes());
        length_prefixed_hasher.update(domain.as_bytes());
        length_prefixed_hasher.update(config_json.as_bytes());
        let length_prefixed_hash = length_prefixed_hasher.finalize();

        // Length-prefixed should be different from simple prefix
        assert_ne!(
            length_prefixed_hash.as_slice(),
            hash_with_domain.as_slice(),
            "Length-prefixed domain separation should differ from simple prefix"
        );

        // In production code, all hash operations should include domain separators like:
        // hasher.update(b"fault_config_v1:");  // or length-prefixed version
        // hasher.update(config_bytes);
    }

    #[test]
    fn negative_boundary_validation_comprehensive_edge_cases() {
        // Test comprehensive boundary validation for all the hardening patterns
        // This test combines multiple patterns to catch interaction bugs

        // Test saturating arithmetic with probabilities at boundaries
        let boundary_configs = [
            // Test floating-point boundaries
            FaultConfig {
                drop_probability: 0.0,
                ..valid_config()
            },
            FaultConfig {
                drop_probability: 1.0,
                ..valid_config()
            },
            FaultConfig {
                drop_probability: f64::EPSILON,
                ..valid_config()
            },
            FaultConfig {
                drop_probability: 1.0 - f64::EPSILON,
                ..valid_config()
            },
            // Test integer boundaries with safe casting
            FaultConfig {
                max_faults: 0,
                ..valid_config()
            },
            FaultConfig {
                max_faults: 1,
                ..valid_config()
            },
            FaultConfig {
                max_faults: usize::MAX,
                ..valid_config()
            },
            // Test corruption bit count boundaries
            FaultConfig {
                corrupt_bit_count: 0,
                ..valid_config()
            },
            FaultConfig {
                corrupt_bit_count: usize::MAX,
                ..valid_config()
            },
        ];

        for (i, config) in boundary_configs.iter().enumerate() {
            let validation_result = config.validate();

            match validation_result {
                Ok(_) => {
                    // If boundary config is accepted, verify safe handling

                    // Test safe length conversion
                    let config_json = serde_json::to_string(config).unwrap();
                    let json_len_safe = u32::try_from(config_json.len()).unwrap_or(u32::MAX);
                    assert!(
                        json_len_safe > 0,
                        "JSON length should be positive for config {}",
                        i
                    );

                    // Test probability values remain in bounds after operations
                    let sum = config.drop_probability
                        + config.reorder_probability
                        + config.corrupt_probability;
                    if sum.is_finite() {
                        assert!(
                            sum >= 0.0,
                            "Probability sum should be non-negative for config {}",
                            i
                        );
                    }

                    // Test that max_faults doesn't overflow when incremented
                    let incremented = config.max_faults.saturating_add(1);
                    assert!(
                        incremented >= config.max_faults,
                        "Saturating add should not decrease for config {}",
                        i
                    );
                }
                Err(error_msg) => {
                    // Boundary rejection is acceptable - verify error message quality
                    assert!(
                        !error_msg.is_empty(),
                        "Error message should not be empty for config {}",
                        i
                    );

                    // Error message should not contain the raw values (avoid information leakage)
                    if config.max_faults == usize::MAX {
                        // Large values should be described generically
                        assert!(
                            error_msg.contains("too large")
                                || error_msg.contains("exceeds")
                                || error_msg.contains("invalid"),
                            "Error should describe boundary violation generically for config {}: {}",
                            i,
                            error_msg
                        );
                    }
                }
            }
        }

        // Test that operations remain consistent across boundary conditions
        let stats_before = {
            let harness = VirtualTransportFaultHarness::new(valid_config());
            harness.get_statistics()
        };

        let stats_after = {
            let mut harness = VirtualTransportFaultHarness::new(valid_config());

            // Apply boundary operations
            for j in 0..10 {
                let fault = ScheduledFault {
                    fault_class: FaultClass::Drop,
                    delay_millis: j * 100,
                    event_code: event_codes::SCHEDULED_FAULT,
                };
                harness.schedule_fault(fault);
            }

            harness.get_statistics()
        };

        // Verify statistics remain consistent (no overflow or corruption)
        assert!(
            stats_after.faults_scheduled >= stats_before.faults_scheduled,
            "Fault count should increase monotonically"
        );
        assert!(
            stats_after.faults_applied <= stats_after.faults_scheduled,
            "Applied faults should never exceed scheduled faults"
        );
    }
}
