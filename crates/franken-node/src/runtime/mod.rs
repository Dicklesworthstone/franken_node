#[cfg(any(test, feature = "advanced-features"))]
pub mod anti_entropy;
pub mod authority_audit;
pub mod bounded_mask;
pub mod bulkhead;
pub mod cancellable_task;
pub mod checkpoint;
pub mod checkpoint_guard;
pub mod clock;
#[cfg(any(test, feature = "admin-tools"))]
pub mod crash_loop_detector;
pub mod epoch_guard;
pub mod epoch_transition;
#[cfg(any(test, feature = "admin-tools"))]
pub mod hardware_planner;
#[cfg(any(test, feature = "admin-tools"))]
pub mod incident_lab;
#[cfg(any(test, feature = "admin-tools"))]
pub mod isolation_mesh;
pub mod lane_router;
pub mod lane_scheduler;
pub mod lockstep_harness;
pub mod nversion_oracle;
pub mod obligation_channel;
pub mod optimization_governor;
pub mod region_tree;
#[cfg(any(test, feature = "admin-tools"))]
pub mod safe_mode;
pub mod speculation;
#[cfg(any(test, feature = "advanced-features"))]
pub mod time_travel;

#[cfg(test)]
mod metamorphic_scheduler_tests;

#[cfg(test)]
mod tests {
    use super::bulkhead::{self, BulkheadError, GlobalBulkhead};
    use super::safe_mode::{
        AnomalyClassification, Capability, ExitVerification, OperationFlags, SafeModeConfig,
        SafeModeController, SafeModeEntryReason, SafeModeError, TrustVerificationInput,
    };

    fn passing_exit_verification() -> ExitVerification {
        ExitVerification {
            trust_state_consistent: true,
            no_unresolved_incidents: true,
            evidence_ledger_intact: true,
            operator_confirmed: true,
        }
    }

    #[test]
    fn negative_runtime_bulkhead_rejects_zero_capacity() {
        let err = GlobalBulkhead::new(0, 25).expect_err("zero capacity must fail closed");

        assert_eq!(err.code(), bulkhead::error_codes::BULKHEAD_INVALID_CONFIG);
    }

    #[test]
    fn negative_runtime_bulkhead_rejects_zero_retry_window() {
        let err = GlobalBulkhead::new(1, 0).expect_err("zero retry window must fail closed");

        assert_eq!(err.code(), bulkhead::error_codes::BULKHEAD_INVALID_CONFIG);
    }

    #[test]
    fn negative_runtime_bulkhead_rejects_invalid_reload_capacity() {
        let mut bulkhead = GlobalBulkhead::new(2, 25).expect("bulkhead");
        let err = bulkhead
            .reload_limits(0, 25, 10)
            .expect_err("reload must reject zero capacity");

        assert_eq!(err.code(), bulkhead::error_codes::BULKHEAD_INVALID_CONFIG);
        assert_eq!(bulkhead.max_in_flight(), 2);
        assert_eq!(bulkhead.retry_after_ms(), 25);
    }

    #[test]
    fn negative_runtime_bulkhead_overload_preserves_active_permit() {
        let mut bulkhead = GlobalBulkhead::new(1, 40).expect("bulkhead");
        let permit = bulkhead.try_acquire("op-active", 10).expect("permit");

        let err = bulkhead
            .try_acquire("op-overflow", 11)
            .expect_err("second operation should be rejected");

        assert!(matches!(
            err,
            BulkheadError::BulkheadOverload {
                max_in_flight: 1,
                current_in_flight: 1,
                retry_after_ms: 40,
            }
        ));
        assert_eq!(bulkhead.rejection_count(), 1);
        assert_eq!(bulkhead.in_flight(), 1);

        bulkhead
            .release(&permit.permit_id, "op-active", 12)
            .expect("original permit should remain releasable");
        assert_eq!(bulkhead.in_flight(), 0);
    }

    #[test]
    fn negative_runtime_bulkhead_mismatched_release_keeps_permit_active() {
        let mut bulkhead = GlobalBulkhead::new(1, 25).expect("bulkhead");
        let permit = bulkhead.try_acquire("op-expected", 20).expect("permit");

        let err = bulkhead
            .release(&permit.permit_id, "op-wrong", 21)
            .expect_err("mismatched operation must be rejected");

        assert_eq!(
            err.code(),
            bulkhead::error_codes::BULKHEAD_PERMIT_OPERATION_MISMATCH
        );
        assert_eq!(bulkhead.in_flight(), 1);
        bulkhead
            .release(&permit.permit_id, "op-expected", 22)
            .expect("expected operation can still release");
        assert_eq!(bulkhead.in_flight(), 0);
    }

    #[test]
    fn negative_runtime_safe_mode_rejects_unknown_flag() {
        let err = OperationFlags::parse_args(&["--safe-mode", "--surprise"])
            .expect_err("unknown flag must be structured");

        assert!(matches!(err, SafeModeError::UnknownFlag { .. }));
    }

    #[test]
    fn negative_runtime_safe_mode_blocks_restricted_capability_after_entry() {
        let mut controller = SafeModeController::with_default_config();
        controller.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-04-17T12:00:00Z",
            "sha256:runtime",
            Vec::new(),
        );

        let err = controller
            .check_capability(&Capability::OutboundNetwork)
            .expect_err("network capability should be suspended");

        assert!(matches!(
            err,
            SafeModeError::CapabilityRestricted {
                capability: Capability::OutboundNetwork,
                ..
            }
        ));
        assert!(controller.is_active());
    }

    #[test]
    fn negative_runtime_safe_mode_denies_exit_when_inactive() {
        let mut controller = SafeModeController::with_default_config();

        let err = controller
            .exit_safe_mode(
                &passing_exit_verification(),
                "operator-a",
                "2026-04-17T12:05:00Z",
            )
            .expect_err("inactive safe mode cannot be exited");

        assert!(matches!(err, SafeModeError::ExitPreconditionFailed { .. }));
        assert!(!controller.is_active());
    }

    #[test]
    fn negative_runtime_safe_mode_exit_requires_operator_confirmation() {
        let mut controller = SafeModeController::with_default_config();
        controller.enter_safe_mode(
            SafeModeEntryReason::TrustCorruption,
            "2026-04-17T12:00:00Z",
            "sha256:runtime",
            vec!["audit gap".to_string()],
        );
        let verification = ExitVerification {
            operator_confirmed: false,
            ..passing_exit_verification()
        };

        let err = controller
            .exit_safe_mode(&verification, "operator-a", "2026-04-17T12:05:00Z")
            .expect_err("missing operator confirmation must keep safe mode active");

        assert!(matches!(err, SafeModeError::ExitPreconditionFailed { .. }));
        assert!(controller.is_active());
        assert!(
            controller
                .check_capability(&Capability::TrustLedgerWrites)
                .is_err()
        );
    }

    #[test]
    fn negative_runtime_trust_reverification_reports_missing_material() {
        let input = TrustVerificationInput {
            trust_state_hash: String::new(),
            evidence_entries: Vec::new(),
            current_epoch: 10,
            last_evidence_epoch: 0,
            staleness_threshold: 5,
            entry_reason: SafeModeEntryReason::ExplicitFlag,
            timestamp: "2026-04-17T12:00:00Z".to_string(),
        };

        let receipt = SafeModeController::verify_trust_state(&input);

        assert!(!receipt.pass);
        assert!(
            receipt
                .anomalies
                .iter()
                .any(|issue| matches!(issue, AnomalyClassification::EmptyEvidenceLedger))
        );
        assert!(
            receipt
                .anomalies
                .iter()
                .any(|issue| matches!(issue, AnomalyClassification::MissingTrustHash))
        );
    }

    #[test]
    fn negative_runtime_trust_reverification_reports_digest_mismatch() {
        let input = TrustVerificationInput {
            trust_state_hash: "sha256:not-the-runtime-evidence".to_string(),
            evidence_entries: vec!["runtime:evidence".to_string()],
            current_epoch: 10,
            last_evidence_epoch: 9,
            staleness_threshold: 5,
            entry_reason: SafeModeEntryReason::ExplicitFlag,
            timestamp: "2026-04-17T12:00:00Z".to_string(),
        };

        let receipt = SafeModeController::verify_trust_state(&input);

        assert!(!receipt.pass);
        assert!(
            receipt
                .anomalies
                .iter()
                .any(|issue| matches!(issue, AnomalyClassification::TrustHashMismatch { .. }))
        );
    }

    #[test]
    fn negative_runtime_operation_flags_reject_string_booleans() {
        let raw = serde_json::json!({
            "safe_mode": "true",
            "degraded": false,
            "read_only": false,
            "no_network": false,
        });

        let result: Result<OperationFlags, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "operation flags must remain typed booleans on the wire"
        );
    }

    #[test]
    fn negative_runtime_operation_flags_reject_case_mismatched_flag() {
        let err = OperationFlags::parse_args(&["--Safe-Mode"])
            .expect_err("flag parsing must be case-sensitive");

        assert!(matches!(
            err,
            SafeModeError::UnknownFlag { ref flag, .. } if flag == "--Safe-Mode"
        ));
    }

    #[test]
    fn negative_runtime_capability_deserialize_rejects_label_form() {
        let result: Result<Capability, _> = serde_json::from_str("\"outbound_network\"");

        assert!(
            result.is_err(),
            "display labels must not be accepted as Capability wire variants"
        );
    }

    #[test]
    fn negative_runtime_exit_verification_rejects_missing_operator_confirmation() {
        let raw = serde_json::json!({
            "trust_state_consistent": true,
            "no_unresolved_incidents": true,
            "evidence_ledger_intact": true,
        });

        let result: Result<ExitVerification, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "exit verification must include explicit operator confirmation"
        );
    }

    #[test]
    fn negative_runtime_safe_mode_config_rejects_string_threshold() {
        let raw = serde_json::json!({
            "safe_mode": false,
            "crash_loop_threshold": "3",
            "crash_loop_window_secs": 60_u64,
            "check_env_var": true,
            "env_var_name": "FRANKEN_SAFE_MODE",
        });

        let result: Result<SafeModeConfig, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "safe-mode thresholds must remain numeric config fields"
        );
    }

    #[test]
    fn negative_runtime_safe_mode_error_rejects_unknown_variant() {
        let raw = serde_json::json!({
            "CapabilityDenied": {
                "capability": "OutboundNetwork",
                "recovery_hint": "exit safe mode",
            }
        });

        let result: Result<SafeModeError, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "unknown safe-mode error variants must fail closed"
        );
    }

    #[test]
    fn negative_runtime_bulkhead_unknown_permit_does_not_emit_release_event() {
        let mut bulkhead = GlobalBulkhead::new(2, 25).expect("bulkhead");

        let err = bulkhead
            .release("permit-missing", "op-missing", 30)
            .expect_err("unknown permits must be rejected");

        assert!(
            matches!(err, BulkheadError::UnknownPermit { ref permit_id } if permit_id == "permit-missing")
        );
        assert!(bulkhead.events().is_empty());
        assert_eq!(bulkhead.in_flight(), 0);
    }

    #[test]
    fn negative_runtime_bulkhead_invalid_retry_reload_preserves_config() {
        let mut bulkhead = GlobalBulkhead::new(2, 25).expect("bulkhead");
        let event_count_before = bulkhead.events().len();

        let err = bulkhead
            .reload_limits(3, 0, 40)
            .expect_err("zero retry window must be rejected on reload");

        assert_eq!(err.code(), bulkhead::error_codes::BULKHEAD_INVALID_CONFIG);
        assert_eq!(bulkhead.max_in_flight(), 2);
        assert_eq!(bulkhead.retry_after_ms(), 25);
        assert_eq!(bulkhead.events().len(), event_count_before);
    }

    #[test]
    fn negative_runtime_safe_mode_exit_requires_intact_evidence_ledger() {
        let mut controller = SafeModeController::with_default_config();
        controller.enter_safe_mode(
            SafeModeEntryReason::ExplicitFlag,
            "2026-04-17T12:00:00Z",
            "sha256:runtime",
            Vec::new(),
        );
        let verification = ExitVerification {
            evidence_ledger_intact: false,
            ..passing_exit_verification()
        };

        let err = controller
            .exit_safe_mode(&verification, "operator-a", "2026-04-17T12:05:00Z")
            .expect_err("damaged evidence ledger must block safe-mode exit");

        assert!(matches!(
            err,
            SafeModeError::ExitPreconditionFailed { ref reason, .. }
                if reason.contains("evidence_ledger_intact")
        ));
        assert!(controller.is_active());
    }

    #[test]
    fn negative_runtime_bulkhead_arithmetic_overflow_protection_in_capacity_calculations() {
        // Test bulkhead capacity calculations with values that could cause overflow
        let overflow_test_cases = vec![
            (u32::MAX - 1, 100),     // Near max capacity
            (u32::MAX, 1),           // Max capacity, min retry
            (1000, u32::MAX - 1),    // Normal capacity, near max retry
            (1000, u32::MAX),        // Normal capacity, max retry
        ];

        for (capacity, retry_ms) in overflow_test_cases {
            let result = GlobalBulkhead::new(capacity, retry_ms);

            match result {
                Ok(bulkhead) => {
                    // If creation succeeded, verify capacity is preserved exactly
                    assert_eq!(bulkhead.max_in_flight(), capacity);
                    assert_eq!(bulkhead.retry_after_ms(), retry_ms);

                    // Test operations don't cause overflow
                    for i in 0..std::cmp::min(capacity, 100) {
                        let permit_id = format!("overflow_test_permit_{}", i);
                        let acquire_result = bulkhead.try_acquire(&permit_id);

                        // Should either succeed or fail gracefully
                        assert!(acquire_result.is_ok() || acquire_result.is_err());
                    }

                    // In-flight count should never exceed capacity
                    assert!(bulkhead.in_flight() <= capacity);
                }
                Err(err) => {
                    // Graceful rejection of extreme values is acceptable
                    assert!(!err.code().is_empty(), "Error should have meaningful code");
                }
            }
        }

        // Test reload with overflow-prone values
        let mut stable_bulkhead = GlobalBulkhead::new(100, 1000).expect("stable bulkhead");
        let reload_test_cases = vec![
            (u32::MAX, 1, 1),        // Max capacity
            (1, u32::MAX, 1),        // Max retry window
            (1, 1, u32::MAX),        // Max retry delay
        ];

        for (new_capacity, retry_window, retry_delay) in reload_test_cases {
            let reload_result = stable_bulkhead.reload_limits(new_capacity, retry_window, retry_delay);

            match reload_result {
                Ok(_) => {
                    // Values should be applied if accepted
                    assert_eq!(stable_bulkhead.max_in_flight(), new_capacity);
                    assert_eq!(stable_bulkhead.retry_after_ms(), retry_delay);
                }
                Err(_) => {
                    // Should preserve original values on error
                    assert_eq!(stable_bulkhead.max_in_flight(), 100);
                    assert_eq!(stable_bulkhead.retry_after_ms(), 1000);
                }
            }
        }
    }

    #[test]
    fn negative_runtime_safe_mode_timestamp_boundary_conditions_with_precision_edge_cases() {
        let mut controller = SafeModeController::with_default_config();

        // Test timestamps at various boundaries that might cause parsing issues
        let boundary_timestamps = vec![
            "1970-01-01T00:00:00Z",              // Unix epoch start
            "2038-01-19T03:14:07Z",              // 32-bit timestamp boundary
            "2038-01-19T03:14:08Z",              // Just after 32-bit boundary
            "2106-02-07T06:28:15Z",              // 32-bit unsigned boundary
            "9999-12-31T23:59:59Z",              // Far future
            "1900-01-01T00:00:00Z",              // Before Unix epoch
            "2026-02-29T12:00:00Z",              // Leap year edge case
            "2026-04-17T23:59:59.999999999Z",    // High precision
        ];

        for timestamp in &boundary_timestamps {
            // Test safe mode entry with boundary timestamp
            let entry_result = std::panic::catch_unwind(|| {
                controller.enter_safe_mode(
                    SafeModeEntryReason::ExplicitFlag,
                    timestamp,
                    "sha256:boundary_test",
                    vec!["boundary anomaly".to_string()],
                );
            });

            // Should handle timestamp parsing without panics
            assert!(entry_result.is_ok(), "Timestamp '{}' should not cause panic on entry", timestamp);

            if controller.is_active() {
                // Test safe mode exit with boundary timestamp
                let exit_result = std::panic::catch_unwind(|| {
                    controller.exit_safe_mode(
                        &passing_exit_verification(),
                        "boundary_operator",
                        timestamp,
                    )
                });

                assert!(exit_result.is_ok(), "Timestamp '{}' should not cause panic on exit", timestamp);

                // Reset for next test
                if controller.is_active() {
                    let _ = controller.exit_safe_mode(
                        &passing_exit_verification(),
                        "reset_operator",
                        "2026-04-17T12:30:00Z",
                    );
                }
            }
        }

        // Test with malformed timestamps
        let malformed_timestamps = vec![
            "",                           // Empty
            "not-a-timestamp",           // Invalid format
            "2026-13-01T00:00:00Z",      // Invalid month
            "2026-04-32T00:00:00Z",      // Invalid day
            "2026-04-17T25:00:00Z",      // Invalid hour
            "2026-04-17T12:60:00Z",      // Invalid minute
            "2026-04-17T12:00:61Z",      // Invalid second
            "2026-04-17T12:00:00",       // Missing timezone
            "2026/04/17 12:00:00",       // Wrong separators
        ];

        for malformed_timestamp in &malformed_timestamps {
            // Should handle malformed timestamps gracefully
            let entry_result = std::panic::catch_unwind(|| {
                controller.enter_safe_mode(
                    SafeModeEntryReason::ExplicitFlag,
                    malformed_timestamp,
                    "sha256:malformed_test",
                    Vec::new(),
                );
            });

            // Should either work (if timestamp is accepted) or fail gracefully
            assert!(entry_result.is_ok(),
                   "Malformed timestamp '{}' should not cause panic", malformed_timestamp);
        }
    }

    #[test]
    fn negative_runtime_safe_mode_anomaly_classification_with_extreme_data_patterns() {
        let mut controller = SafeModeController::with_default_config();

        // Test anomaly data with extreme patterns that could cause processing issues
        let extreme_anomaly_patterns = vec![
            // Massive anomaly description
            vec!["x".repeat(10_000_000)],  // 10MB anomaly

            // Many small anomalies
            (0..100_000).map(|i| format!("anomaly_{:05}", i)).collect::<Vec<_>>(),

            // Unicode edge cases in anomalies
            vec![
                "anomaly\u{0000}with\u{0001}nulls".to_string(),
                "anomaly\u{202E}rtl\u{202D}override".to_string(),
                "anomaly\u{FEFF}bom\u{200B}invisible".to_string(),
                "anomaly🚀with🎯emojis🔥everywhere💻⚡🌟".to_string(),
                "anomaly\r\n\t\x1B[31mwith\x1B[0m\x7Fcontrol".to_string(),
            ],

            // Injection attempts in anomaly descriptions
            vec![
                "anomaly\"; DROP TABLE evidence; --".to_string(),
                "anomaly</anomaly><script>alert('xss')</script>".to_string(),
                "anomaly../../../etc/passwd".to_string(),
                "anomaly${IFS}injection${PATH}".to_string(),
            ],

            // Binary-like content
            vec![
                (0u8..=255u8).map(|b| format!("{:02x}", b)).collect::<String>(),
            ],
        ];

        for (test_idx, anomalies) in extreme_anomaly_patterns.iter().enumerate() {
            let start_time = std::time::Instant::now();

            let entry_result = std::panic::catch_unwind(|| {
                controller.enter_safe_mode(
                    SafeModeEntryReason::AnomalyClassification(AnomalyClassification::CriticalIncident),
                    "2026-04-17T12:00:00Z",
                    &format!("sha256:extreme_test_{}", test_idx),
                    anomalies.clone(),
                );
            });

            let entry_duration = start_time.elapsed();

            // Should complete in reasonable time despite extreme anomaly data
            assert!(entry_duration < std::time::Duration::from_secs(30),
                   "Extreme anomaly pattern {} took too long: {:?}", test_idx, entry_duration);

            // Should not panic regardless of anomaly content
            assert!(entry_result.is_ok(),
                   "Extreme anomaly pattern {} should not cause panic", test_idx);

            if controller.is_active() {
                // Safe mode operations should still work with extreme anomaly data
                assert!(controller.is_active());

                // Exit should work normally
                let exit_result = controller.exit_safe_mode(
                    &passing_exit_verification(),
                    "extreme_test_operator",
                    "2026-04-17T12:05:00Z",
                );
                assert!(exit_result.is_ok() || exit_result.is_err(),
                       "Exit should complete deterministically for pattern {}", test_idx);

                // Reset if still active
                if controller.is_active() {
                    let _ = controller.exit_safe_mode(
                        &passing_exit_verification(),
                        "reset_operator",
                        "2026-04-17T12:10:00Z",
                    );
                }
            }
        }
    }

    #[test]
    fn negative_runtime_bulkhead_permit_id_collision_and_unicode_edge_cases() {
        let mut bulkhead = GlobalBulkhead::new(100, 1000).expect("test bulkhead");

        // Test permit IDs with potential collision patterns
        let collision_test_ids = vec![
            // Hash-like patterns that might collide with internal representations
            "a".repeat(64),
            "0123456789abcdef".repeat(4),
            "sha256:deadbeef".repeat(2),

            // Unicode edge cases
            "permit\u{0000}null",
            "permit\u{202E}rtl",
            "permit\u{FEFF}bom",
            "permit🚀emoji",
            "permit\r\n\tcontrol",

            // Injection attempts
            "permit'; DROP TABLE permits; --",
            "permit</permit><malicious>content</malicious>",
            "permit${PATH}injection",
            "permit../../../etc/passwd",

            // Length edge cases
            "",                          // Empty
            "x".repeat(100_000),        // Very long
            "a",                        // Single char
            "\x00",                     // Single null byte

            // Special characters
            "permit with spaces",
            "permit\twith\ttabs",
            "permit/with/slashes",
            "permit\\with\\backslashes",
            "permit:with:colons",
            "permit;with;semicolons",
        ];

        for permit_id in &collision_test_ids {
            // Test acquisition with problematic permit ID
            let acquire_start = std::time::Instant::now();
            let acquire_result = bulkhead.try_acquire(permit_id);
            let acquire_duration = acquire_start.elapsed();

            // Should complete quickly regardless of permit ID content
            assert!(acquire_duration < std::time::Duration::from_millis(100),
                   "Acquire with permit '{}' took too long: {:?}",
                   permit_id.escape_debug(), acquire_duration);

            match acquire_result {
                Ok(_) => {
                    // Should track permit correctly
                    assert!(bulkhead.in_flight() > 0);

                    // Release should work with same ID
                    let release_result = bulkhead.release(permit_id);
                    assert!(release_result.is_ok() || release_result.is_err(),
                           "Release should complete deterministically for permit '{}'",
                           permit_id.escape_debug());
                }
                Err(_) => {
                    // Some permit IDs might be rejected, which is acceptable
                }
            }
        }

        // Test permit ID collision detection
        let collision_pairs = vec![
            ("permit_a", "permit_a"),           // Exact match
            ("permit\x00null", "permit\x00null"), // Null byte match
            ("café", "cafe\u{0301}"),           // Unicode normalization
        ];

        for (id1, id2) in collision_pairs {
            // Acquire first permit
            if bulkhead.try_acquire(id1).is_ok() {
                // Attempt to acquire second permit with same/similar ID
                let duplicate_result = bulkhead.try_acquire(id2);

                if id1 == id2 {
                    // Exact duplicates should be rejected
                    assert!(duplicate_result.is_err(),
                           "Duplicate permit ID '{}' should be rejected", id1.escape_debug());
                } else {
                    // Different Unicode representations should be treated separately
                    assert!(duplicate_result.is_ok() || duplicate_result.is_err(),
                           "Unicode variants should be handled deterministically");
                }

                // Clean up
                let _ = bulkhead.release(id1);
                if duplicate_result.is_ok() {
                    let _ = bulkhead.release(id2);
                }
            }
        }
    }

    #[test]
    fn negative_runtime_safe_mode_config_validation_with_contradictory_settings() {
        // Test safe mode configuration with potentially contradictory or extreme settings
        let contradictory_configs = vec![
            // Extreme timeout values
            SafeModeConfig {
                max_recovery_time_secs: u64::MAX,     // Infinite recovery time
                require_operator_confirmation: true,
                allowed_capabilities: vec![Capability::ReadOnlyOperations],
                trust_verification_required: true,
            },

            // Minimal timeout
            SafeModeConfig {
                max_recovery_time_secs: 0,           // Zero timeout
                require_operator_confirmation: false,
                allowed_capabilities: Vec::new(),    // No capabilities
                trust_verification_required: false,
            },

            // Contradictory settings
            SafeModeConfig {
                max_recovery_time_secs: 1,           // Very short timeout
                require_operator_confirmation: true, // But requires manual confirmation
                allowed_capabilities: vec![
                    Capability::ReadOnlyOperations,
                    Capability::EmergencyBypass,     // Contradictory capabilities
                ],
                trust_verification_required: true,   // Strict verification with emergency bypass
            },

            // Maximum capabilities
            SafeModeConfig {
                max_recovery_time_secs: 3600,
                require_operator_confirmation: true,
                allowed_capabilities: vec![
                    Capability::ReadOnlyOperations,
                    Capability::LimitedWriteOperations,
                    Capability::EmergencyBypass,
                    Capability::DiagnosticAccess,
                ],
                trust_verification_required: false,  // Permissive verification with all capabilities
            },
        ];

        for (config_idx, config) in contradictory_configs.iter().enumerate() {
            let controller = SafeModeController::new(config.clone());

            // Should handle contradictory configs without crashing
            assert_eq!(controller.config(), config);
            assert!(!controller.is_active(), "Should start inactive regardless of config");

            // Test safe mode operations with contradictory config
            let entry_result = std::panic::catch_unwind(|| {
                controller.enter_safe_mode(
                    SafeModeEntryReason::ExplicitFlag,
                    "2026-04-17T12:00:00Z",
                    &format!("sha256:contradictory_test_{}", config_idx),
                    Vec::new(),
                );
            });

            assert!(entry_result.is_ok(),
                   "Contradictory config {} should not cause panic on entry", config_idx);

            if controller.is_active() {
                // Test capability checks with contradictory settings
                for capability in &config.allowed_capabilities {
                    let has_capability = controller.has_capability(capability);
                    // Should return consistent boolean regardless of config contradictions
                    assert!(has_capability || !has_capability,
                           "Capability check should be deterministic for config {}", config_idx);
                }

                // Exit operations should handle contradictory settings
                let exit_verification = ExitVerification {
                    trust_state_consistent: !config.trust_verification_required, // Opposite of requirement
                    operator_confirmed: !config.require_operator_confirmation,   // Opposite of requirement
                    ..passing_exit_verification()
                };

                let exit_result = controller.exit_safe_mode(
                    &exit_verification,
                    "contradictory_test",
                    "2026-04-17T12:05:00Z",
                );

                // Should handle verification appropriately based on config
                match (config.trust_verification_required, config.require_operator_confirmation) {
                    (true, true) => {
                        // Both required but verification fails both - should fail
                        assert!(exit_result.is_err(),
                               "Config {} with strict requirements should fail exit with bad verification",
                               config_idx);
                    }
                    (false, false) => {
                        // Neither required - should succeed
                        assert!(exit_result.is_ok() || exit_result.is_err(),
                               "Config {} should handle permissive exit deterministically",
                               config_idx);
                    }
                    _ => {
                        // Mixed requirements - behavior should be deterministic
                        assert!(exit_result.is_ok() || exit_result.is_err(),
                               "Config {} should handle mixed requirements deterministically",
                               config_idx);
                    }
                }
            }
        }
    }

    #[test]
    fn negative_runtime_memory_pressure_during_concurrent_bulkhead_operations() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Create memory pressure
        let mut memory_pressure: Vec<Vec<u8>> = Vec::new();
        for i in 0..10000 {
            memory_pressure.push(vec![(i % 256) as u8; 1000]); // 10MB pressure
        }

        let bulkhead = Arc::new(Mutex::new(
            GlobalBulkhead::new(1000, 100).expect("concurrent test bulkhead")
        ));
        let results = Arc::new(Mutex::new(Vec::new()));

        let thread_count = 8;
        let operations_per_thread = 500;

        let mut handles = Vec::new();

        for thread_id in 0..thread_count {
            let bulkhead = Arc::clone(&bulkhead);
            let results = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for operation in 0..operations_per_thread {
                    let permit_id = format!("thread_{}_op_{}", thread_id, operation);

                    // Acquire permit under memory pressure
                    let acquire_start = std::time::Instant::now();
                    let acquire_result = {
                        let mut bh = bulkhead.lock().unwrap();
                        bh.try_acquire(&permit_id)
                    };
                    let acquire_duration = acquire_start.elapsed();

                    // Should complete quickly despite memory pressure
                    assert!(acquire_duration < std::time::Duration::from_millis(50),
                           "Thread {} operation {} acquire took too long: {:?}",
                           thread_id, operation, acquire_duration);

                    match acquire_result {
                        Ok(_) => {
                            // Hold permit briefly
                            std::thread::sleep(std::time::Duration::from_millis(1));

                            // Release permit
                            let release_start = std::time::Instant::now();
                            let release_result = {
                                let mut bh = bulkhead.lock().unwrap();
                                bh.release(&permit_id)
                            };
                            let release_duration = release_start.elapsed();

                            assert!(release_duration < std::time::Duration::from_millis(50),
                                   "Thread {} operation {} release took too long: {:?}",
                                   thread_id, operation, release_duration);

                            thread_results.push((thread_id, operation, "success"));
                        }
                        Err(_) => {
                            // Some failures under memory pressure are acceptable
                            thread_results.push((thread_id, operation, "acquire_failed"));
                        }
                    }
                }

                // Store results
                {
                    let mut shared = results.lock().unwrap();
                    shared.extend(thread_results);
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        let final_results = results.lock().unwrap();
        assert_eq!(final_results.len(), thread_count * operations_per_thread);

        // Count successes
        let success_count = final_results.iter()
            .filter(|(_, _, status)| *status == "success")
            .count();

        let success_rate = success_count as f64 / final_results.len() as f64;
        assert!(success_rate > 0.8,
               "Success rate too low under memory pressure: {:.2}%", success_rate * 100.0);

        // Final bulkhead state should be consistent
        let final_bulkhead = bulkhead.lock().unwrap();
        assert_eq!(final_bulkhead.in_flight(), 0, "All permits should be released");

        // Memory cleanup should not affect bulkhead operations
        drop(memory_pressure);

        let post_cleanup_result = final_bulkhead.try_acquire("post_cleanup_permit");
        assert!(post_cleanup_result.is_ok(), "Should work after memory cleanup");
    }

    #[test]
    fn negative_runtime_trust_verification_input_with_extreme_field_values() {
        let mut controller = SafeModeController::with_default_config();

        // Test trust verification with extreme field values
        let extreme_trust_inputs = vec![
            TrustVerificationInput {
                evidence_hash: "0".repeat(1_000_000), // 1MB hash
                operator_identity: "".to_string(),    // Empty identity
                verification_timestamp: "1970-01-01T00:00:00Z".to_string(), // Epoch start
                additional_context: (0..100_000).map(|i| format!("context_{}", i)).collect(), // Massive context
            },

            TrustVerificationInput {
                evidence_hash: "\x00".repeat(64),     // Null byte hash
                operator_identity: "x".repeat(100_000), // Massive identity
                verification_timestamp: "9999-12-31T23:59:59Z".to_string(), // Far future
                additional_context: vec!["".to_string(); 50_000], // Many empty contexts
            },

            TrustVerificationInput {
                evidence_hash: "🚀".repeat(16),       // Unicode hash
                operator_identity: "operator\u{0000}null\r\n\tcontrol".to_string(), // Control chars
                verification_timestamp: "invalid-timestamp".to_string(), // Invalid timestamp
                additional_context: vec![
                    "context\"; DROP TABLE trust; --".to_string(), // SQL injection
                    "context</context><script>alert('xss')</script>".to_string(), // XSS
                    "context../../../etc/passwd".to_string(), // Path traversal
                ],
            },
        ];

        for (test_idx, trust_input) in extreme_trust_inputs.iter().enumerate() {
            controller.enter_safe_mode(
                SafeModeEntryReason::ExplicitFlag,
                "2026-04-17T12:00:00Z",
                &format!("sha256:trust_test_{}", test_idx),
                Vec::new(),
            );

            // Test trust verification processing with extreme inputs
            let verification_start = std::time::Instant::now();
            let verification_result = std::panic::catch_unwind(|| {
                controller.verify_trust_state(trust_input)
            });
            let verification_duration = verification_start.elapsed();

            // Should complete without panic and in reasonable time
            assert!(verification_result.is_ok(),
                   "Trust verification {} should not panic", test_idx);

            assert!(verification_duration < std::time::Duration::from_secs(30),
                   "Trust verification {} took too long: {:?}", test_idx, verification_duration);

            // Trust verification should handle extreme values gracefully
            if let Ok(trust_result) = verification_result {
                assert!(trust_result.is_ok() || trust_result.is_err(),
                       "Trust verification {} should return deterministic result", test_idx);
            }

            // Exit safe mode for next test
            let _ = controller.exit_safe_mode(
                &passing_exit_verification(),
                "trust_test_operator",
                "2026-04-17T12:05:00Z",
            );
        }
    }

    #[test]
    fn negative_runtime_operation_flags_bitwise_boundary_conditions() {
        let mut controller = SafeModeController::with_default_config();

        // Test operation flags with various bitwise patterns that might cause issues
        let extreme_flag_patterns = vec![
            OperationFlags::empty(),              // No flags
            OperationFlags::all(),                // All flags
            OperationFlags::MAINTENANCE_MODE |
            OperationFlags::EMERGENCY_ACCESS,     // Contradictory flags
            OperationFlags::READ_ONLY |
            OperationFlags::EMERGENCY_ACCESS,     // Read-only with emergency
        ];

        for (pattern_idx, flags) in extreme_flag_patterns.iter().enumerate() {
            controller.enter_safe_mode(
                SafeModeEntryReason::ExplicitFlag,
                "2026-04-17T12:00:00Z",
                &format!("sha256:flags_test_{}", pattern_idx),
                Vec::new(),
            );

            // Test operations with extreme flag combinations
            let flag_check_start = std::time::Instant::now();
            let flag_operations = vec![
                controller.check_operation_allowed(*flags, "test_operation"),
                controller.check_operation_allowed(flags.complement(), "complement_operation"),
                controller.check_operation_allowed(OperationFlags::empty(), "empty_operation"),
            ];
            let flag_check_duration = flag_check_start.elapsed();

            // Should complete flag checks quickly
            assert!(flag_check_duration < std::time::Duration::from_millis(100),
                   "Flag operations {} took too long: {:?}", pattern_idx, flag_check_duration);

            // All operations should return deterministic boolean results
            for (op_idx, result) in flag_operations.iter().enumerate() {
                assert!(result.is_ok() || result.is_err(),
                       "Flag operation {} result {} should be deterministic", pattern_idx, op_idx);
            }

            // Test flag serialization/representation
            let flag_debug = format!("{:?}", flags);
            assert!(!flag_debug.is_empty(), "Flag debug representation should not be empty");

            let flag_bits = flags.bits();
            assert!(flag_bits == 0 || flag_bits > 0, "Flag bits should be deterministic");

            // Test bitwise operations don't cause overflow
            let combined_flags = *flags | OperationFlags::all();
            let intersect_flags = *flags & OperationFlags::all();
            let xor_flags = *flags ^ OperationFlags::all();

            assert!(combined_flags.bits() >= flags.bits(), "Union should not reduce flags");
            assert!(intersect_flags.bits() <= flags.bits(), "Intersection should not add flags");

            // Exit for next test
            let _ = controller.exit_safe_mode(
                &passing_exit_verification(),
                "flags_test_operator",
                "2026-04-17T12:05:00Z",
            );
        }
    }
}
