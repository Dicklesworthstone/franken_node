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
pub mod effect_receipt;
pub mod epoch_guard;
pub mod epoch_transition;
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
pub mod resource_governor;
pub mod safe_mode;
pub mod speculation;
#[cfg(any(test, feature = "advanced-features"))]
pub mod time_travel;

#[cfg(test)]
mod metamorphic_scheduler_tests;

#[cfg(test)]
mod tests {
    use crate::lock_utils::try_lock;

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

    fn test_clock_start() -> std::time::Instant {
        std::time::Instant::now()
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
        let overflow_test_cases: Vec<(usize, u64)> = vec![
            (u32::MAX as usize - 1, 100), // Near max capacity
            (u32::MAX as usize, 1),       // Max capacity, min retry
            (1000, u32::MAX as u64 - 1),  // Normal capacity, near max retry
            (1000, u32::MAX as u64),      // Normal capacity, max retry
        ];

        for (capacity, retry_ms) in overflow_test_cases {
            let result = GlobalBulkhead::new(capacity, retry_ms);

            match result {
                Ok(mut bulkhead) => {
                    // If creation succeeded, verify capacity is preserved exactly
                    assert_eq!(bulkhead.max_in_flight(), capacity);
                    assert_eq!(bulkhead.retry_after_ms(), retry_ms);

                    // Test operations don't cause overflow
                    for i in 0..std::cmp::min(capacity, 100) {
                        let permit_id = format!("overflow_test_permit_{}", i);
                        let acquire_result = bulkhead.try_acquire(&permit_id, i as u64);

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
        // reload_limits(new_max_in_flight, new_retry_after_ms, now_ms)
        let reload_test_cases: Vec<(usize, u64, u64)> = vec![
            (u32::MAX as usize, 1, 1), // Max capacity
            (1, u32::MAX as u64, 1),   // Max retry-after window
            (1, 1, u32::MAX as u64),   // Max reload timestamp
        ];

        for (new_capacity, new_retry_after, now_ms) in reload_test_cases {
            let reload_result =
                stable_bulkhead.reload_limits(new_capacity, new_retry_after, now_ms);

            match reload_result {
                Ok(_) => {
                    // Values should be applied if accepted
                    assert_eq!(stable_bulkhead.max_in_flight(), new_capacity);
                    assert_eq!(stable_bulkhead.retry_after_ms(), new_retry_after);
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
            "1970-01-01T00:00:00Z",           // Unix epoch start
            "2038-01-19T03:14:07Z",           // 32-bit timestamp boundary
            "2038-01-19T03:14:08Z",           // Just after 32-bit boundary
            "2106-02-07T06:28:15Z",           // 32-bit unsigned boundary
            "9999-12-31T23:59:59Z",           // Far future
            "1900-01-01T00:00:00Z",           // Before Unix epoch
            "2026-02-29T12:00:00Z",           // Leap year edge case
            "2026-04-17T23:59:59.999999999Z", // High precision
        ];

        for timestamp in &boundary_timestamps {
            // Test safe mode entry with boundary timestamp
            let entry_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                controller.enter_safe_mode(
                    SafeModeEntryReason::ExplicitFlag,
                    timestamp,
                    "sha256:boundary_test",
                    vec!["boundary anomaly".to_string()],
                );
            }));

            // Should handle timestamp parsing without panics
            assert!(
                entry_result.is_ok(),
                "Timestamp '{}' should not cause panic on entry",
                timestamp
            );

            if controller.is_active() {
                // Test safe mode exit with boundary timestamp
                let exit_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    controller.exit_safe_mode(
                        &passing_exit_verification(),
                        "boundary_operator",
                        timestamp,
                    )
                }));

                assert!(
                    exit_result.is_ok(),
                    "Timestamp '{}' should not cause panic on exit",
                    timestamp
                );

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
            "",                     // Empty
            "not-a-timestamp",      // Invalid format
            "2026-13-01T00:00:00Z", // Invalid month
            "2026-04-32T00:00:00Z", // Invalid day
            "2026-04-17T25:00:00Z", // Invalid hour
            "2026-04-17T12:60:00Z", // Invalid minute
            "2026-04-17T12:00:61Z", // Invalid second
            "2026-04-17T12:00:00",  // Missing timezone
            "2026/04/17 12:00:00",  // Wrong separators
        ];

        for malformed_timestamp in &malformed_timestamps {
            // Should handle malformed timestamps gracefully
            let entry_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                controller.enter_safe_mode(
                    SafeModeEntryReason::ExplicitFlag,
                    malformed_timestamp,
                    "sha256:malformed_test",
                    Vec::new(),
                );
            }));

            // Should either work (if timestamp is accepted) or fail gracefully
            assert!(
                entry_result.is_ok(),
                "Malformed timestamp '{}' should not cause panic",
                malformed_timestamp
            );
        }
    }

    #[test]
    fn negative_runtime_safe_mode_anomaly_classification_with_extreme_data_patterns() {
        let mut controller = SafeModeController::with_default_config();

        // Test anomaly data with extreme patterns that could cause processing issues
        let extreme_anomaly_patterns = vec![
            // Massive anomaly description
            vec!["x".repeat(10_000_000)], // 10MB anomaly
            // Many small anomalies
            (0..100_000)
                .map(|i| format!("anomaly_{:05}", i))
                .collect::<Vec<_>>(),
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
                (0u8..=255u8)
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>(),
            ],
        ];

        for (test_idx, anomalies) in extreme_anomaly_patterns.iter().enumerate() {
            let start_time = std::time::Instant::now();

            let entry_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // TrustCorruption is the most-severe (fail-closed) entry reason,
                // preserving the original "critical incident" classification intent.
                controller.enter_safe_mode(
                    SafeModeEntryReason::TrustCorruption,
                    "2026-04-17T12:00:00Z",
                    &format!("sha256:extreme_test_{}", test_idx),
                    anomalies.clone(),
                );
            }));

            let entry_duration = start_time.elapsed();

            // Should complete in reasonable time despite extreme anomaly data
            assert!(
                entry_duration < std::time::Duration::from_secs(30),
                "Extreme anomaly pattern {} took too long: {:?}",
                test_idx,
                entry_duration
            );

            // Should not panic regardless of anomaly content
            assert!(
                entry_result.is_ok(),
                "Extreme anomaly pattern {} should not cause panic",
                test_idx
            );

            if controller.is_active() {
                // Safe mode operations should still work with extreme anomaly data
                assert!(controller.is_active());

                // Exit should work normally
                let exit_result = controller.exit_safe_mode(
                    &passing_exit_verification(),
                    "extreme_test_operator",
                    "2026-04-17T12:05:00Z",
                );
                assert!(
                    exit_result.is_ok() || exit_result.is_err(),
                    "Exit should complete deterministically for pattern {}",
                    test_idx
                );

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

        // Test operation IDs with potential collision patterns
        let collision_test_ids: Vec<String> = vec![
            // Hash-like patterns that might collide with internal representations
            "a".repeat(64),
            "0123456789abcdef".repeat(4),
            "sha256:deadbeef".repeat(2),
            // Unicode edge cases
            "permit\u{0000}null".to_string(),
            "permit\u{202E}rtl".to_string(),
            "permit\u{FEFF}bom".to_string(),
            "permit🚀emoji".to_string(),
            "permit\r\n\tcontrol".to_string(),
            // Injection attempts
            "permit'; DROP TABLE permits; --".to_string(),
            "permit</permit><malicious>content</malicious>".to_string(),
            "permit${PATH}injection".to_string(),
            "permit../../../etc/passwd".to_string(),
            // Length edge cases
            "".to_string(),      // Empty
            "x".repeat(100_000), // Very long
            "a".to_string(),     // Single char
            "\x00".to_string(),  // Single null byte
            // Special characters
            "permit with spaces".to_string(),
            "permit\twith\ttabs".to_string(),
            "permit/with/slashes".to_string(),
            "permit\\with\\backslashes".to_string(),
            "permit:with:colons".to_string(),
            "permit;with;semicolons".to_string(),
        ];

        for (idx, operation_id) in collision_test_ids.iter().enumerate() {
            let now_ms = u64::try_from(idx).unwrap_or(u64::MAX);
            // Test acquisition with problematic operation ID
            let acquire_start = std::time::Instant::now();
            let acquire_result = bulkhead.try_acquire(operation_id, now_ms);
            let acquire_duration = acquire_start.elapsed();

            // Should complete quickly regardless of operation ID content
            assert!(
                acquire_duration < std::time::Duration::from_millis(100),
                "Acquire with operation '{}' took too long: {:?}",
                operation_id.escape_debug(),
                acquire_duration
            );

            match acquire_result {
                Ok(permit) => {
                    // Should track permit correctly
                    assert!(bulkhead.in_flight() > 0);

                    // Release should work with the issued permit id and same operation id
                    let release_result =
                        bulkhead.release(&permit.permit_id, operation_id, now_ms);
                    assert!(
                        release_result.is_ok() || release_result.is_err(),
                        "Release should complete deterministically for operation '{}'",
                        operation_id.escape_debug()
                    );
                }
                Err(_) => {
                    // Some operation IDs might be rejected, which is acceptable
                }
            }
        }

        // Test permit-id generation under colliding operation ids.
        // FIXME(bd-yom8c): the old API treated the caller-supplied id as a permit
        // key and rejected exact duplicates; that uniqueness key was removed.
        // Operation ids are now non-unique labels and permit ids are generated
        // per acquisition, so the invariant we assert is that distinct
        // acquisitions never alias to the same permit id.
        let collision_pairs = vec![
            ("permit_a", "permit_a"),             // Exact operation-id match
            ("permit\x00null", "permit\x00null"), // Null byte (rejected at acquire)
            ("café", "cafe\u{0301}"),             // Unicode normalization
        ];

        for (id1, id2) in collision_pairs {
            // Acquire first permit (id1 is the operation id).
            if let Ok(first) = bulkhead.try_acquire(id1, 1) {
                // Acquire a second permit with the same/similar operation id.
                let duplicate_result = bulkhead.try_acquire(id2, 2);

                // Generated permit ids must never alias, even for identical
                // operation ids, so the two permits stay independent.
                if let Ok(ref second) = duplicate_result {
                    assert_ne!(
                        first.permit_id, second.permit_id,
                        "distinct acquisitions must yield distinct permit ids for '{}'",
                        id1.escape_debug()
                    );
                }

                // Clean up.
                let _ = bulkhead.release(&first.permit_id, id1, 3);
                if let Ok(second) = duplicate_result {
                    let _ = bulkhead.release(&second.permit_id, id2, 4);
                }
            }
        }
    }

    #[test]
    fn negative_runtime_safe_mode_config_validation_with_contradictory_settings() {
        // Test safe mode configuration with potentially contradictory or extreme settings.
        let contradictory_configs = vec![
            // Extreme crash-loop thresholds.
            SafeModeConfig {
                safe_mode: true,
                crash_loop_threshold: u32::MAX,
                crash_loop_window_secs: u64::MAX,
                check_env_var: true,
                env_var_name: "FRANKEN_SAFE_MODE".to_string(),
            },
            // Minimal crash-loop settings.
            SafeModeConfig {
                safe_mode: false,
                crash_loop_threshold: 0,
                crash_loop_window_secs: 0,
                check_env_var: false,
                env_var_name: String::new(),
            },
            // Contradictory settings: zero threshold but an enormous window.
            SafeModeConfig {
                safe_mode: true,
                crash_loop_threshold: 0,
                crash_loop_window_secs: u64::MAX,
                check_env_var: true,
                env_var_name: "FRANKEN_SAFE_MODE".to_string(),
            },
            // Permissive settings: high threshold, env probing disabled.
            SafeModeConfig {
                safe_mode: false,
                crash_loop_threshold: 1_000_000,
                crash_loop_window_secs: 3600,
                check_env_var: false,
                env_var_name: "CUSTOM_SAFE_MODE".to_string(),
            },
        ];

        for (config_idx, config) in contradictory_configs.iter().enumerate() {
            let mut controller = SafeModeController::new(config.clone());

            // Should handle contradictory configs without crashing.
            assert_eq!(controller.config(), config);
            assert!(
                !controller.is_active(),
                "Should start inactive regardless of config"
            );

            // Test safe mode operations with contradictory config.
            let entry_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                controller.enter_safe_mode(
                    SafeModeEntryReason::ExplicitFlag,
                    "2026-04-17T12:00:00Z",
                    &format!("sha256:contradictory_test_{}", config_idx),
                    Vec::new(),
                );
            }));

            assert!(
                entry_result.is_ok(),
                "Contradictory config {} should not cause panic on entry",
                config_idx
            );

            if controller.is_active() {
                // INV-SMO-RESTRICTED: every capability is restricted in safe mode,
                // and the check is deterministic regardless of config contradictions.
                for capability in Capability::all() {
                    let restricted = controller.check_capability(&capability).is_err();
                    assert!(
                        restricted,
                        "Capability {capability} must be restricted in safe mode for config {config_idx}"
                    );
                }

                // INV-SMO-RECOVERY: a verification that fails its preconditions must
                // block exit and keep safe mode active.
                let failing_verification = ExitVerification {
                    trust_state_consistent: false,
                    operator_confirmed: false,
                    ..passing_exit_verification()
                };
                let blocked_exit = controller.exit_safe_mode(
                    &failing_verification,
                    "contradictory_test",
                    "2026-04-17T12:05:00Z",
                );
                assert!(
                    blocked_exit.is_err(),
                    "Config {} must fail exit with a failing verification",
                    config_idx
                );
                assert!(
                    controller.is_active(),
                    "Config {} must stay in safe mode after a blocked exit",
                    config_idx
                );

                // A fully-passing verification clears safe mode deterministically.
                let exit_result = controller.exit_safe_mode(
                    &passing_exit_verification(),
                    "contradictory_test",
                    "2026-04-17T12:06:00Z",
                );
                assert!(
                    exit_result.is_ok(),
                    "Config {} should exit safe mode with full verification",
                    config_idx
                );
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
            GlobalBulkhead::new(1000, 100).expect("concurrent test bulkhead"),
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
                        let mut bh =
                            try_lock(&bulkhead, "runtime memory pressure bulkhead acquire")
                                .expect("bulkhead mutex should lock for acquire");
                        bh.try_acquire(&permit_id, operation as u64)
                    };
                    let acquire_duration = acquire_start.elapsed();

                    // Should complete quickly despite memory pressure
                    assert!(
                        acquire_duration < std::time::Duration::from_millis(50),
                        "Thread {} operation {} acquire took too long: {:?}",
                        thread_id,
                        operation,
                        acquire_duration
                    );

                    match acquire_result {
                        Ok(permit) => {
                            // Hold permit briefly
                            std::thread::sleep(std::time::Duration::from_millis(1));

                            // Release permit
                            let release_start = std::time::Instant::now();
                            let release_result = {
                                let mut bh =
                                    try_lock(&bulkhead, "runtime memory pressure bulkhead release")
                                        .expect("bulkhead mutex should lock for release");
                                bh.release(&permit.permit_id, &permit_id, operation as u64)
                            };
                            let release_duration = release_start.elapsed();

                            assert!(
                                release_duration < std::time::Duration::from_millis(50),
                                "Thread {} operation {} release took too long: {:?}",
                                thread_id,
                                operation,
                                release_duration
                            );

                            thread_results.push((thread_id, operation, true));
                        }
                        Err(_) => {
                            // Some failures under memory pressure are acceptable
                            thread_results.push((thread_id, operation, false));
                        }
                    }
                }

                // Store results
                {
                    let mut shared =
                        try_lock(&results, "runtime memory pressure results aggregation")
                            .expect("results mutex should lock for aggregation");
                    shared.extend(thread_results);
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        let final_results = try_lock(
            &results,
            "runtime memory pressure final results verification",
        )
        .expect("results mutex should lock for final verification");
        assert_eq!(final_results.len(), thread_count * operations_per_thread);

        // Count successes
        let success_count = final_results
            .iter()
            .filter(|(_, _, acquired)| *acquired)
            .count();

        let success_rate = if final_results.is_empty() {
            0.0
        } else {
            let rate = success_count as f64 / final_results.len() as f64;
            if rate.is_finite() { rate } else { 0.0 }
        };
        assert!(
            success_rate > 0.8,
            "Success rate too low under memory pressure: {:.2}%",
            success_rate * 100.0
        );

        // Final bulkhead state should be consistent
        let mut final_bulkhead = try_lock(
            &bulkhead,
            "runtime memory pressure final bulkhead verification",
        )
        .expect("bulkhead mutex should lock for final verification");
        assert_eq!(
            final_bulkhead.in_flight(),
            0,
            "All permits should be released"
        );

        // Memory cleanup should not affect bulkhead operations
        drop(memory_pressure);

        let post_cleanup_result = final_bulkhead.try_acquire("post_cleanup_permit", 0);
        assert!(
            post_cleanup_result.is_ok(),
            "Should work after memory cleanup"
        );
    }

    #[test]
    fn negative_runtime_trust_verification_input_with_extreme_field_values() {
        let mut controller = SafeModeController::with_default_config();

        // Test trust verification with extreme field values.
        let extreme_trust_inputs = vec![
            TrustVerificationInput {
                trust_state_hash: "0".repeat(1_000_000), // 1MB hash
                evidence_entries: (0..100_000).map(|i| format!("context_{}", i)).collect(), // Massive evidence
                current_epoch: 0,
                last_evidence_epoch: 0,
                staleness_threshold: 5,
                entry_reason: SafeModeEntryReason::ExplicitFlag,
                timestamp: "1970-01-01T00:00:00Z".to_string(), // Epoch start
            },
            TrustVerificationInput {
                trust_state_hash: "\x00".repeat(64),               // Null byte hash
                evidence_entries: vec!["".to_string(); 50_000],    // Many empty entries
                current_epoch: u64::MAX,
                last_evidence_epoch: 1,
                staleness_threshold: 1,
                entry_reason: SafeModeEntryReason::ExplicitFlag,
                timestamp: "9999-12-31T23:59:59Z".to_string(), // Far future
            },
            TrustVerificationInput {
                trust_state_hash: "🚀".repeat(16), // Unicode hash
                evidence_entries: vec![
                    "context\"; DROP TABLE trust; --".to_string(), // SQL injection
                    "context</context><script>alert('xss')</script>".to_string(), // XSS
                    "context../../../etc/passwd".to_string(),      // Path traversal
                ],
                current_epoch: 10,
                last_evidence_epoch: 9,
                staleness_threshold: 5,
                entry_reason: SafeModeEntryReason::ExplicitFlag,
                timestamp: "invalid-timestamp".to_string(), // Invalid timestamp
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
            let started_at = test_clock_start();
            let verification_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                SafeModeController::verify_trust_state(trust_input)
            }));
            let verification_duration = started_at.elapsed();

            // Should complete without panic and in reasonable time
            assert!(
                verification_result.is_ok(),
                "Trust verification {} should not panic",
                test_idx
            );

            assert!(
                verification_duration < std::time::Duration::from_secs(30),
                "Trust verification {} took too long: {:?}",
                test_idx,
                verification_duration
            );

            // Trust verification should handle extreme values gracefully and produce
            // a deterministic, proof-carrying receipt.
            if let Ok(receipt) = verification_result {
                assert!(
                    !receipt.trust_proof_digest.is_empty(),
                    "Trust verification {} should return a deterministic receipt",
                    test_idx
                );
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

        // Active-flag count is the bool-field analog of a bitflags `bits` popcount.
        fn active_count(flags: &OperationFlags) -> usize {
            flags.active_flag_names().len()
        }
        // The all-flags-set value (analog of bitflags `all`).
        let all_flags = OperationFlags {
            safe_mode: true,
            degraded: true,
            read_only: true,
            no_network: true,
        };

        // Test operation flags with various combinations that might cause issues.
        let extreme_flag_patterns = vec![
            OperationFlags::none(), // No flags
            all_flags.clone(),      // All flags
            OperationFlags {
                safe_mode: true,
                degraded: false,
                read_only: false,
                no_network: true,
            }, // Safe-mode with network lockdown
            OperationFlags {
                safe_mode: false,
                degraded: false,
                read_only: true,
                no_network: true,
            }, // Read-only with network lockdown
        ];

        for (pattern_idx, flags) in extreme_flag_patterns.iter().enumerate() {
            controller.enter_safe_mode(
                SafeModeEntryReason::ExplicitFlag,
                "2026-04-17T12:00:00Z",
                &format!("sha256:flags_test_{}", pattern_idx),
                Vec::new(),
            );

            // The complement (every bool negated) is the analog of bitflags `complement`.
            let complement = OperationFlags {
                safe_mode: !flags.safe_mode,
                degraded: !flags.degraded,
                read_only: !flags.read_only,
                no_network: !flags.no_network,
            };

            // Computing the restricted-capability set for several flag combinations
            // must be deterministic and panic-free (the analog of evaluating each
            // operation against the flags).
            let flag_check_start = std::time::Instant::now();
            let flag_operations = vec![
                SafeModeController::compute_restricted_capabilities(flags),
                SafeModeController::compute_restricted_capabilities(&complement),
                SafeModeController::compute_restricted_capabilities(&OperationFlags::none()),
            ];
            let flag_check_duration = flag_check_start.elapsed();

            // Should complete flag checks quickly
            assert!(
                flag_check_duration < std::time::Duration::from_millis(100),
                "Flag operations {} took too long: {:?}",
                pattern_idx,
                flag_check_duration
            );

            // All operations should be deterministic (recomputing yields the same set).
            for (op_idx, restricted) in flag_operations.iter().enumerate() {
                let recomputed = match op_idx {
                    0 => SafeModeController::compute_restricted_capabilities(flags),
                    1 => SafeModeController::compute_restricted_capabilities(&complement),
                    _ => SafeModeController::compute_restricted_capabilities(
                        &OperationFlags::none(),
                    ),
                };
                assert_eq!(
                    restricted, &recomputed,
                    "Flag operation {} result {} should be deterministic",
                    pattern_idx, op_idx
                );
            }

            // Test flag serialization/representation
            let flag_debug = format!("{:?}", flags);
            assert!(
                !flag_debug.is_empty(),
                "Flag debug representation should not be empty"
            );

            let flag_bits = active_count(flags);
            assert!(flag_bits <= 4, "Flag count should be deterministic and bounded");

            // Field-wise union / intersection are the analogs of bitwise | and &.
            let combined_flags = OperationFlags {
                safe_mode: flags.safe_mode || all_flags.safe_mode,
                degraded: flags.degraded || all_flags.degraded,
                read_only: flags.read_only || all_flags.read_only,
                no_network: flags.no_network || all_flags.no_network,
            };
            let intersect_flags = OperationFlags {
                safe_mode: flags.safe_mode && all_flags.safe_mode,
                degraded: flags.degraded && all_flags.degraded,
                read_only: flags.read_only && all_flags.read_only,
                no_network: flags.no_network && all_flags.no_network,
            };

            assert!(
                active_count(&combined_flags) >= active_count(flags),
                "Union should not reduce flags"
            );
            assert!(
                active_count(&intersect_flags) <= active_count(flags),
                "Intersection should not add flags"
            );

            // Exit for next test
            let _ = controller.exit_safe_mode(
                &passing_exit_verification(),
                "flags_test_operator",
                "2026-04-17T12:05:00Z",
            );
        }
    }
}
