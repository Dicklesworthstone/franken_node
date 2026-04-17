//! Remote-control primitives for network-bound operations.

#[cfg(feature = "extended-surfaces")]
pub mod computation_registry;
#[cfg(feature = "extended-surfaces")]
pub mod eviction_saga;
#[cfg(feature = "extended-surfaces")]
pub mod idempotency;
#[cfg(feature = "extended-surfaces")]
pub mod idempotency_store;
#[cfg(feature = "extended-surfaces")]
pub mod remote_bulkhead;
pub mod virtual_transport_faults;

#[cfg(test)]
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
}
