//! Golden artifact tests for lane scheduler telemetry snapshots
//!
//! Tests deterministic output format stability for:
//! - LaneTelemetrySnapshot serialization across policy variations
//! - Schedule plan outputs under different epoch conditions
//! - Policy validation error messages
//!
//! Complements runtime_lane_scheduler_conformance.rs by focusing on output format
//! validation rather than behavioral correctness testing.

use frankenengine_node::runtime::lane_scheduler::{
    LaneConfig, LaneMappingPolicy, LaneScheduler, LaneSchedulerError,
    SchedulerLane, TaskClass, task_classes,
};
use insta::Settings;

/// Helper to create a minimal policy for deterministic testing
fn minimal_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    policy
        .add_lane(LaneConfig::new(SchedulerLane::Background, 10, 2))
        .expect("minimal policy creation should succeed");
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy
}

/// Helper to create a multi-lane policy for complex scheduling scenarios
fn multi_lane_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();

    // Control critical lane - high priority, low concurrency
    policy.add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 100, 1)).unwrap();
    policy.add_rule(&task_classes::epoch_transition(), SchedulerLane::ControlCritical);

    // Remote effect lane - medium priority, medium concurrency
    policy.add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, 50, 4)).unwrap();
    policy.add_rule(&task_classes::remote_computation(), SchedulerLane::RemoteEffect);

    // Background lane - low priority, high concurrency
    policy.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 8)).unwrap();
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy.add_rule(&task_classes::garbage_collection(), SchedulerLane::Background);

    policy
}

#[test]
fn golden_telemetry_snapshot_minimal_scheduler() {
    let mut settings = Settings::clone_current();

    // Scrub dynamic values for deterministic golden comparison
    settings.add_filter(r"\d{13,}", "[TIMESTAMP]");
    settings.add_filter(r"golden-test-\d+", "[TASK_ID]");
    settings.add_filter(r#"trace_id[":]?\s*["'][^"']+["']"#, "trace_id: \"[TRACE_ID]\"");

    settings.bind(|| {
        let mut scheduler = LaneScheduler::new(minimal_policy()).unwrap();

        // Admit a single task for deterministic state
        let _assignment = scheduler
            .assign_task(&task_classes::log_rotation(), 1000000, "golden-test-1")
            .unwrap();

        // Mark task as completed for deterministic telemetry
        scheduler.mark_task_completed("golden-test-1", 1000100).unwrap();

        let snapshot = scheduler.telemetry_snapshot(1000200);
        insta::assert_json_snapshot!(snapshot);
    });
}

#[test]
fn golden_telemetry_snapshot_multi_lane_scheduler() {
    let mut settings = Settings::clone_current();

    // Scrub dynamic values
    settings.add_filter(r"\d{13,}", "[TIMESTAMP]");
    settings.add_filter(r"(epoch|remote|log)-task-\d+", "[TASK_ID]");
    settings.add_filter(r#"trace_id[":]?\s*["'][^"']+["']"#, "trace_id: \"[TRACE_ID]\"");

    settings.bind(|| {
        let mut scheduler = LaneScheduler::new(multi_lane_policy()).unwrap();

        // Admit tasks across different lanes for comprehensive telemetry
        let _assignment1 = scheduler
            .assign_task(&task_classes::epoch_transition(), 2000000, "epoch-task-1")
            .unwrap();

        let _assignment2 = scheduler
            .assign_task(&task_classes::remote_computation(), 2000100, "remote-task-1")
            .unwrap();

        let _assignment3 = scheduler
            .assign_task(&task_classes::log_rotation(), 2000200, "log-task-1")
            .unwrap();

        // Complete some tasks to show different lane states
        scheduler.mark_task_completed("epoch-task-1", 2000300).unwrap();
        scheduler.mark_task_completed("log-task-1", 2000400).unwrap();

        let snapshot = scheduler.telemetry_snapshot(2000500);
        insta::assert_json_snapshot!(snapshot);
    });
}

#[test]
fn golden_telemetry_snapshot_capacity_enforcement() {
    let mut settings = Settings::clone_current();

    settings.add_filter(r"\d{13,}", "[TIMESTAMP]");
    settings.add_filter(r"cap-test-\d+", "[TASK_ID]");

    settings.bind(|| {
        // Create policy with capacity of 1 to test cap enforcement
        let mut policy = LaneMappingPolicy::new();
        policy.add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, 50, 1)).unwrap();
        policy.add_rule(&task_classes::remote_computation(), SchedulerLane::RemoteEffect);

        let mut scheduler = LaneScheduler::new(policy).unwrap();

        // First admission should succeed
        let _assignment1 = scheduler
            .assign_task(&task_classes::remote_computation(), 3000000, "cap-test-1")
            .unwrap();

        // Second admission should fail due to capacity
        let assignment2_result = scheduler
            .assign_task(&task_classes::remote_computation(), 3000100, "cap-test-2");

        let snapshot = scheduler.telemetry_snapshot(3000200);

        // Verify assignment failure was due to capacity
        assert!(assignment2_result.is_err());
        assert!(matches!(assignment2_result.unwrap_err(), LaneSchedulerError::CapExceeded { .. }));

        insta::assert_json_snapshot!(snapshot);
    });
}

#[test]
fn golden_scheduler_policy_serialization() {
    let policy = multi_lane_policy();
    insta::assert_json_snapshot!(policy);
}

#[test]
fn golden_scheduler_policy_validation_errors() {
    // Test various invalid policy configurations
    let mut invalid_policies = Vec::new();

    // Empty policy
    let empty_policy = LaneMappingPolicy::new();
    invalid_policies.push(("empty_policy", empty_policy.validate()));

    // Policy with lane but no rules
    let mut no_rules_policy = LaneMappingPolicy::new();
    no_rules_policy.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 2)).unwrap();
    invalid_policies.push(("no_rules_policy", no_rules_policy.validate()));

    // Policy with zero priority weight
    let mut zero_priority_policy = LaneMappingPolicy::new();
    let mut config = LaneConfig::new(SchedulerLane::Background, 10, 2);
    config.priority_weight = 0;
    let _ = zero_priority_policy.add_lane(config);
    invalid_policies.push(("zero_priority_policy", zero_priority_policy.validate()));

    // Collect all validation results
    let mut validation_results = Vec::new();
    for (name, result) in invalid_policies {
        validation_results.push(serde_json::json!({
            "policy_type": name,
            "validation_result": result.map(|_| "valid").unwrap_or_else(|e| e.as_str()),
            "is_valid": result.is_ok()
        }));
    }

    let json_value = serde_json::json!({
        "validation_results": validation_results
    });

    insta::assert_json_snapshot!(json_value);
}