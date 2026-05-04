use frankenengine_node::remote::virtual_transport_faults::{
    FaultClass, FaultConfig, FaultSchedule, MAX_CAMPAIGN_MESSAGES, MAX_SCHEDULED_FAULTS,
    ScheduledFault, VirtualTransportFaultHarness, chaos, event_codes,
};

#[test]
fn process_message_applies_unsorted_manual_schedule() {
    let mut harness = VirtualTransportFaultHarness::new(1);
    let schedule = FaultSchedule {
        seed: 1,
        faults: vec![
            ScheduledFault {
                message_index: 2,
                fault: FaultClass::Drop,
            },
            ScheduledFault {
                message_index: 0,
                fault: FaultClass::Corrupt {
                    bit_positions: vec![0],
                },
            },
        ],
        total_messages: 3,
    };

    let result = harness.process_message(&schedule, 0, 1, &[0], "t-unsorted");

    assert_eq!(result, Some(vec![1]));
    assert_eq!(harness.fault_count(), 1);
    assert_eq!(harness.fault_log()[0].fault_class, "Corrupt");
}

#[test]
fn fault_config_rejects_cumulative_probability_above_one() {
    let invalid = FaultConfig {
        drop_probability: 0.6,
        reorder_probability: 0.3,
        reorder_max_depth: 1,
        corrupt_probability: 0.2,
        corrupt_bit_count: 1,
        max_faults: 10,
    };

    assert_eq!(
        invalid.validate(),
        Err("fault probabilities must sum to <= 1".to_string())
    );
}

#[test]
fn fault_config_rejects_unbounded_fault_budget() {
    let invalid = FaultConfig {
        drop_probability: 1.0,
        reorder_probability: 0.0,
        reorder_max_depth: 0,
        corrupt_probability: 0.0,
        corrupt_bit_count: 0,
        max_faults: MAX_SCHEDULED_FAULTS.saturating_add(1),
    };

    let err = invalid
        .validate()
        .expect_err("fault budgets above the schedule cap must fail closed");

    assert!(err.contains("max_faults"));
}

#[test]
fn fault_schedule_rejects_unbounded_message_count() {
    let err = FaultSchedule::from_seed(42, &chaos(), MAX_CAMPAIGN_MESSAGES.saturating_add(1))
        .expect_err("message counts above the campaign cap must fail closed");

    assert!(err.contains("total_messages"));
}

#[test]
fn oversized_campaign_rejects_without_processing_messages() {
    let mut harness = VirtualTransportFaultHarness::new(42);

    let result = harness.run_campaign(
        "oversized",
        &chaos(),
        MAX_CAMPAIGN_MESSAGES.saturating_add(1),
        "t-oversized",
    );

    assert_eq!(
        result.total_messages,
        MAX_CAMPAIGN_MESSAGES.saturating_add(1)
    );
    assert_eq!(result.total_faults, 0);
    assert_eq!(result.drops, 0);
    assert_eq!(result.reorders, 0);
    assert_eq!(result.corruptions, 0);
    assert_eq!(harness.fault_count(), 0);
    assert!(!result.content_hash.is_empty());
    assert!(harness.audit_log().iter().any(|record| {
        record
            .detail
            .get("rejected")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    }));
}

fn assert_campaign_rejects_invalid_config(config: FaultConfig, expected_reason: &str) {
    let mut harness = VirtualTransportFaultHarness::new(42);

    let result = harness.run_campaign("invalid", &config, 10, "t-invalid");

    assert_eq!(result.total_messages, 10);
    assert_eq!(result.total_faults, 0);
    assert_eq!(result.drops, 0);
    assert_eq!(result.reorders, 0);
    assert_eq!(result.corruptions, 0);
    assert_eq!(harness.fault_count(), 0);
    assert!(
        !harness
            .audit_log()
            .iter()
            .any(|record| record.event_code == event_codes::FAULT_SCHEDULE_CREATED)
    );
    assert!(harness.audit_log().iter().any(|record| {
        record.event_code == event_codes::FAULT_SCENARIO_END
            && record
                .detail
                .get("rejected")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            && record
                .detail
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|reason| reason.contains(expected_reason))
    }));
}

#[test]
fn invalid_campaign_configs_reject_instead_of_no_fault_schedule() {
    assert_campaign_rejects_invalid_config(
        FaultConfig {
            drop_probability: f64::NAN,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 1,
        },
        "drop_probability",
    );
    assert_campaign_rejects_invalid_config(
        FaultConfig {
            drop_probability: 0.6,
            reorder_probability: 0.3,
            reorder_max_depth: 1,
            corrupt_probability: 0.2,
            corrupt_bit_count: 1,
            max_faults: 10,
        },
        "sum",
    );
    assert_campaign_rejects_invalid_config(
        FaultConfig {
            drop_probability: 1.0,
            reorder_probability: 0.0,
            reorder_max_depth: 0,
            corrupt_probability: 0.0,
            corrupt_bit_count: 0,
            max_faults: 0,
        },
        "max_faults",
    );
}
