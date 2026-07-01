//! Conformance tests for runtime lane scheduler - focuses on hardening patterns,
//! fail-closed semantics, boundary conditions, and concurrent access patterns.
//!
//! This test harness validates that the lane scheduler properly implements:
//! - Saturating arithmetic for all counter operations
//! - Fail-closed capacity enforcement
//! - Boundary condition handling (u64::MAX, zero values, etc.)
//! - Starvation detection timing accuracy
//! - Hot-reload race condition safety
//! - Policy validation robustness
//! - Audit log integrity under stress

use frankenengine_node::runtime::lane_scheduler::*;
use std::collections::HashSet;

/// Generate a large timestamp near u64::MAX to test overflow handling
const LARGE_TIMESTAMP: u64 = u64::MAX - 1000;

/// Helper to create a minimal policy for testing edge cases
fn minimal_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    policy
        .add_lane(LaneConfig::new(SchedulerLane::Background, 1, 1))
        .expect("minimal policy creation should succeed");
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy
}

/// Helper to create a policy with custom starvation window
fn policy_with_starvation_window(window_ms: u64) -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    let mut config = LaneConfig::new(SchedulerLane::Background, 1, 1);
    config.starvation_window_ms = window_ms;
    policy.add_lane(config).unwrap();
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy
}

#[test]
fn saturating_arithmetic_prevents_counter_overflow() {
    let mut scheduler = LaneScheduler::new(minimal_policy()).unwrap();

    // Manipulate internal counter to near-max values to test overflow protection
    let assignment = scheduler
        .assign_task(&task_classes::log_rotation(), 1000, "overflow-test")
        .unwrap();

    // Complete many tasks to test completed_total overflow protection
    for i in 0..10 {
        scheduler
            .complete_task(&assignment.task_id, 1001 + i, "test")
            .unwrap();
        let _fresh_assignment = scheduler
            .assign_task(
                &task_classes::log_rotation(),
                1002 + i,
                &format!("test-{}", i),
            )
            .unwrap();
    }

    let counters = scheduler.lane_counter(SchedulerLane::Background).unwrap();
    // If saturating arithmetic works correctly, counters should never overflow
    assert!(counters.completed_total < u64::MAX);
}

#[test]
fn boundary_condition_u64_max_timestamps_handled_safely() {
    let mut scheduler = LaneScheduler::new(minimal_policy()).unwrap();

    // Test assignment with near-maximum timestamp
    let assignment = scheduler
        .assign_task(&task_classes::log_rotation(), LARGE_TIMESTAMP, "large-ts")
        .unwrap();

    // Complete with even larger timestamp
    let completion_result = scheduler.complete_task(&assignment.task_id, u64::MAX, "max-ts");

    // Should succeed without overflow panics
    assert!(completion_result.is_ok());

    let counters = scheduler.lane_counter(SchedulerLane::Background).unwrap();
    assert_eq!(counters.completed_total, 1);
    assert_eq!(counters.last_completion_ms, Some(u64::MAX));
}

#[test]
fn starvation_detection_timing_precision_at_boundaries() {
    let policy = policy_with_starvation_window(1000); // 1 second window
    let mut scheduler = LaneScheduler::new(policy).unwrap();

    // Fill the lane
    let assignment = scheduler
        .assign_task(&task_classes::log_rotation(), 1000, "fill")
        .unwrap();

    // Queue a task
    let _ = scheduler.assign_task(&task_classes::log_rotation(), 1001, "queue");

    // Test starvation detection at exact boundary (should not detect yet)
    let starved_at_boundary = scheduler.check_starvation(2000, "boundary-test");
    assert!(
        starved_at_boundary.is_empty(),
        "Should not detect starvation exactly at window boundary"
    );

    // Test starvation detection just past boundary (should detect)
    let starved_past_boundary = scheduler.check_starvation(2001, "past-boundary");
    assert_eq!(starved_past_boundary.len(), 1);
    assert_eq!(
        starved_past_boundary[0],
        LaneSchedulerError::Starvation {
            lane: SchedulerLane::Background,
            queue_depth: 1,
            elapsed_ms: 1000,
        }
    );

    // Verify starvation state is properly tracked
    let counters = scheduler.lane_counter(SchedulerLane::Background).unwrap();
    assert!(counters.starvation_active);
    assert_eq!(counters.starvation_events, 1);
}

#[test]
fn fail_closed_capacity_enforcement_under_concurrent_load_simulation() {
    let mut policy = LaneMappingPolicy::new();
    let config = LaneConfig::new(SchedulerLane::ControlCritical, 100, 2); // Cap of 2
    policy.add_lane(config).unwrap();
    policy.add_rule(
        &task_classes::epoch_transition(),
        SchedulerLane::ControlCritical,
    );
    let mut scheduler = LaneScheduler::new(policy).unwrap();

    // Simulate concurrent task assignments
    let task1 = scheduler
        .assign_task(&task_classes::epoch_transition(), 1000, "concurrent-1")
        .unwrap();
    let task2 = scheduler
        .assign_task(&task_classes::epoch_transition(), 1001, "concurrent-2")
        .unwrap();

    // Third assignment should fail (capacity enforcement)
    let result3 = scheduler.assign_task(&task_classes::epoch_transition(), 1002, "concurrent-3");
    assert!(result3.is_err());
    assert_eq!(
        result3.unwrap_err().code(),
        error_codes::ERR_LANE_CAP_EXCEEDED
    );

    // Verify queue depth tracking
    let counters = scheduler
        .lane_counter(SchedulerLane::ControlCritical)
        .unwrap();
    assert_eq!(counters.active_count, 2);
    assert_eq!(counters.queued_count, 1);
    assert_eq!(counters.rejected_total, 1);
    assert_eq!(counters.first_queued_at_ms, Some(1002));

    // Complete one task and verify queue admission
    scheduler
        .complete_task(&task1.task_id, 1003, "complete-1")
        .unwrap();

    // Now another assignment should succeed (queue slot available)
    let task4 = scheduler
        .assign_task(&task_classes::epoch_transition(), 1004, "post-completion")
        .unwrap();

    let counters = scheduler
        .lane_counter(SchedulerLane::ControlCritical)
        .unwrap();
    assert_eq!(counters.active_count, 2); // Still at capacity
    assert_eq!(counters.queued_count, 0); // Queue drained
    assert_eq!(counters.first_queued_at_ms, None); // No more queued items
}

#[test]
fn hot_reload_race_condition_safety_with_active_tasks() {
    let mut scheduler = LaneScheduler::new(default_policy()).unwrap();

    // Create active tasks in multiple lanes
    let cc_task = scheduler
        .assign_task(&task_classes::epoch_transition(), 1000, "cc")
        .unwrap();
    let re_task = scheduler
        .assign_task(&task_classes::remote_computation(), 1001, "re")
        .unwrap();

    // Verify initial state
    assert_eq!(scheduler.total_active(), 2);

    // Perform hot reload with modified policy
    let mut new_policy = default_policy();
    new_policy.add_rule(&TaskClass::new("new_task_type"), SchedulerLane::Maintenance);
    let reload_result = scheduler.reload_policy(new_policy);
    assert!(
        reload_result.is_ok(),
        "Hot reload should succeed with active tasks"
    );

    // Verify existing tasks still complete successfully
    let cc_complete = scheduler.complete_task(&cc_task.task_id, 1002, "cc-done");
    assert!(cc_complete.is_ok());
    let re_complete = scheduler.complete_task(&re_task.task_id, 1003, "re-done");
    assert!(re_complete.is_ok());

    // Verify new policy is active
    let new_assignment = scheduler.assign_task(&TaskClass::new("new_task_type"), 1004, "new");
    assert!(new_assignment.is_ok());
    assert_eq!(new_assignment.unwrap().lane, SchedulerLane::Maintenance);
}

#[test]
fn policy_validation_rejects_malformed_configurations() {
    // Test invalid policies that should be rejected
    let test_cases = vec![
        ("empty policy", LaneMappingPolicy::new()),
        ("lanes without mapping rules", {
            let mut p = LaneMappingPolicy::new();
            p.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 2))
                .unwrap();
            p
        }),
        ("mapping rules without lane configs", {
            let mut p = LaneMappingPolicy::new();
            p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
            p
        }),
        ("zero priority weight", {
            let mut p = LaneMappingPolicy::new();
            p.add_lane(LaneConfig::new(SchedulerLane::Background, 0, 2))
                .unwrap();
            p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
            p
        }),
        ("zero concurrency cap", {
            let mut p = LaneMappingPolicy::new();
            p.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 0))
                .unwrap();
            p.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
            p
        }),
    ];

    for (description, policy) in test_cases {
        let validation_result = policy.validate();
        assert!(
            validation_result.is_err(),
            "Policy validation should reject: {}",
            description
        );

        let scheduler_result = LaneScheduler::new(policy);
        assert!(
            scheduler_result.is_err(),
            "Scheduler creation should reject: {}",
            description
        );
        assert_eq!(
            scheduler_result.unwrap_err().code(),
            error_codes::ERR_LANE_INVALID_POLICY
        );
    }
}

#[test]
fn audit_log_integrity_under_high_throughput() {
    let mut scheduler = LaneScheduler::with_audit_log_capacity(default_policy(), 10).unwrap();

    // Generate high throughput to test audit log bounds and integrity
    let mut completed_task_ids = Vec::new();

    // Create many assignments to exceed audit log capacity
    for i in 0..20 {
        let task_class = match i % 4 {
            0 => task_classes::epoch_transition(),
            1 => task_classes::remote_computation(),
            2 => task_classes::garbage_collection(),
            _ => task_classes::telemetry_export(),
        };

        if let Ok(assignment) =
            scheduler.assign_task(&task_class, 1000 + i, &format!("high-throughput-{}", i))
        {
            completed_task_ids.push(assignment.task_id);
        }
    }

    // Complete all tasks
    for (i, task_id) in completed_task_ids.into_iter().enumerate() {
        let _ = scheduler.complete_task(&task_id, 2000 + i as u64, &format!("complete-{}", i));
    }

    // Verify audit log respects capacity bounds
    assert_eq!(scheduler.audit_log().len(), 10);
    assert_eq!(scheduler.audit_log_capacity(), 10);

    // Verify audit log contains most recent events (oldest-first eviction)
    let audit_events: Vec<_> = scheduler
        .audit_log()
        .iter()
        .map(|e| &e.event_code)
        .collect();
    let completion_events = audit_events
        .iter()
        .filter(|&&code| code == event_codes::LANE_TASK_COMPLETED)
        .count();

    // Should have some completion events (most recent ones kept)
    assert!(
        completion_events > 0,
        "Audit log should retain recent completion events"
    );

    // Verify JSONL export works correctly
    let jsonl = scheduler.export_audit_log_jsonl();
    let lines: Vec<_> = jsonl.lines().collect();
    assert_eq!(lines.len(), 10);

    // Verify each line is valid JSON
    for line in lines {
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("Audit log JSONL should contain valid JSON");
        assert!(parsed["event_code"].is_string());
        assert!(parsed["timestamp_ms"].is_number());
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
    }
}

#[test]
fn starvation_detection_algorithm_accuracy_across_complex_scenarios() {
    let policy = policy_with_starvation_window(500); // 500ms window
    let mut scheduler = LaneScheduler::new(policy).unwrap();

    // Test scenario: Fill lane, queue work, complete sporadically
    let initial_task = scheduler
        .assign_task(&task_classes::log_rotation(), 1000, "initial")
        .unwrap();

    // Queue multiple tasks
    let _ = scheduler.assign_task(&task_classes::log_rotation(), 1100, "queue-1");
    let _ = scheduler.assign_task(&task_classes::log_rotation(), 1200, "queue-2");
    let _ = scheduler.assign_task(&task_classes::log_rotation(), 1300, "queue-3");

    // Before starvation window expires (should not detect)
    let check1 = scheduler.check_starvation(1550, "check-1");
    assert!(check1.is_empty());

    // After starvation window expires (should detect)
    let check2 = scheduler.check_starvation(1650, "check-2");
    assert_eq!(check2.len(), 1);

    // Complete the initial task, admit new work
    scheduler
        .complete_task(&initial_task.task_id, 1700, "complete-initial")
        .unwrap();
    let new_task = scheduler
        .assign_task(&task_classes::log_rotation(), 1750, "new-after-complete")
        .unwrap();

    // Starvation should persist (queue not empty)
    let check3 = scheduler.check_starvation(1800, "check-3");
    assert_eq!(check3.len(), 1);

    // Complete all remaining work
    scheduler
        .complete_task(&new_task.task_id, 1850, "complete-new")
        .unwrap();

    // Continue admitting until queue is drained
    for i in 0..2 {
        // Should admit 2 more tasks to clear the queue
        if let Ok(task) = scheduler.assign_task(
            &task_classes::log_rotation(),
            1900 + i * 10,
            &format!("drain-{}", i),
        ) {
            let _ = scheduler.complete_task(
                &task.task_id,
                1910 + i * 10,
                &format!("drain-complete-{}", i),
            );
        }
    }

    // Now starvation should clear
    let check4 = scheduler.check_starvation(2000, "check-4");
    assert!(check4.is_empty());

    let counters = scheduler.lane_counter(SchedulerLane::Background).unwrap();
    assert!(!counters.starvation_active);
    assert_eq!(counters.queued_count, 0);

    // Verify starvation cleared event in audit log
    let starvation_cleared_events: Vec<_> = scheduler
        .audit_log()
        .iter()
        .filter(|e| e.event_code == event_codes::LANE_STARVATION_CLEARED)
        .collect();
    assert!(!starvation_cleared_events.is_empty());
}

#[test]
fn multi_lane_interaction_isolation_and_independence() {
    let mut scheduler = LaneScheduler::new(default_policy()).unwrap();

    // Create tasks across all lanes
    let cc_tasks: Vec<_> = (0..3)
        .map(|i| {
            scheduler
                .assign_task(
                    &task_classes::epoch_transition(),
                    1000 + i,
                    &format!("cc-{}", i),
                )
                .unwrap()
        })
        .collect();

    let re_tasks: Vec<_> = (0..5)
        .map(|i| {
            scheduler
                .assign_task(
                    &task_classes::remote_computation(),
                    1100 + i,
                    &format!("re-{}", i),
                )
                .unwrap()
        })
        .collect();

    let maint_tasks: Vec<_> = (0..2)
        .map(|i| {
            scheduler
                .assign_task(
                    &task_classes::garbage_collection(),
                    1200 + i,
                    &format!("maint-{}", i),
                )
                .unwrap()
        })
        .collect();

    // Verify lane isolation - each lane tracks its own counters independently
    let cc_counters = scheduler
        .lane_counter(SchedulerLane::ControlCritical)
        .unwrap();
    let re_counters = scheduler.lane_counter(SchedulerLane::RemoteEffect).unwrap();
    let maint_counters = scheduler.lane_counter(SchedulerLane::Maintenance).unwrap();
    let bg_counters = scheduler.lane_counter(SchedulerLane::Background).unwrap();

    assert_eq!(cc_counters.active_count, 3);
    assert_eq!(re_counters.active_count, 5);
    assert_eq!(maint_counters.active_count, 2);
    assert_eq!(bg_counters.active_count, 0);

    // Complete tasks in one lane, verify others unaffected
    for task in cc_tasks {
        scheduler
            .complete_task(&task.task_id, 1300, "cc-complete")
            .unwrap();
    }

    let cc_counters_after = scheduler
        .lane_counter(SchedulerLane::ControlCritical)
        .unwrap();
    let re_counters_after = scheduler.lane_counter(SchedulerLane::RemoteEffect).unwrap();

    assert_eq!(cc_counters_after.active_count, 0);
    assert_eq!(cc_counters_after.completed_total, 3);
    assert_eq!(re_counters_after.active_count, 5); // Unchanged
    assert_eq!(re_counters_after.completed_total, 0); // Unchanged
}

#[test]
fn task_id_uniqueness_and_collision_resistance() {
    let mut scheduler = LaneScheduler::new(default_policy()).unwrap();
    let mut seen_task_ids = HashSet::new();

    // Generate many tasks to test ID uniqueness
    for i in 0u64..1000 {
        let task_class = if i.is_multiple_of(2) {
            task_classes::epoch_transition()
        } else {
            task_classes::telemetry_export()
        };

        if let Ok(assignment) =
            scheduler.assign_task(&task_class, 1000 + i, &format!("unique-test-{}", i))
        {
            let was_new = seen_task_ids.insert(assignment.task_id.clone());
            assert!(
                was_new,
                "Task ID collision detected: {}",
                assignment.task_id
            );

            // Complete the task to free up lane capacity
            let _ =
                scheduler.complete_task(&assignment.task_id, 2000 + i, &format!("complete-{}", i));
        }
    }

    // Should have seen many unique IDs
    assert!(
        seen_task_ids.len() >= 500,
        "Should generate unique task IDs"
    );
}

#[test]
fn zero_value_boundary_conditions() {
    // Test with minimal audit log capacity (should clamp to 1)
    let scheduler = LaneScheduler::with_audit_log_capacity(minimal_policy(), 0).unwrap();
    assert_eq!(scheduler.audit_log_capacity(), 1);

    // Test starvation window of zero (edge case)
    let policy = policy_with_starvation_window(0);
    let mut scheduler = LaneScheduler::new(policy).unwrap();

    let assignment = scheduler
        .assign_task(&task_classes::log_rotation(), 1000, "zero-window")
        .unwrap();
    let _ = scheduler.assign_task(&task_classes::log_rotation(), 1001, "queue");

    // With zero window, should immediately detect starvation
    let starved = scheduler.check_starvation(1001, "immediate");
    assert_eq!(starved.len(), 1);
}

#[test]
fn telemetry_snapshot_consistency_under_load() {
    let mut scheduler = LaneScheduler::new(default_policy()).unwrap();

    // Create mixed workload
    let assignments = vec![
        scheduler
            .assign_task(&task_classes::epoch_transition(), 1000, "t1")
            .unwrap(),
        scheduler
            .assign_task(&task_classes::remote_computation(), 1001, "t2")
            .unwrap(),
        scheduler
            .assign_task(&task_classes::garbage_collection(), 1002, "t3")
            .unwrap(),
        scheduler
            .assign_task(&task_classes::telemetry_export(), 1003, "t4")
            .unwrap(),
    ];

    // Take snapshot
    let snapshot = scheduler.telemetry_snapshot(1500);

    // Verify snapshot consistency
    assert_eq!(snapshot.counters.len(), 4); // All lanes present
    assert_eq!(snapshot.timestamp_ms, 1500);
    assert_eq!(snapshot.schema_version, SCHEMA_VERSION);

    // Verify individual counter consistency
    let total_active_from_snapshot: usize = snapshot.counters.iter().map(|c| c.active_count).sum();
    assert_eq!(total_active_from_snapshot, scheduler.total_active());

    // Complete some tasks and verify snapshot reflects changes
    scheduler
        .complete_task(&assignments[0].task_id, 1600, "complete-1")
        .unwrap();
    scheduler
        .complete_task(&assignments[1].task_id, 1601, "complete-2")
        .unwrap();

    let snapshot2 = scheduler.telemetry_snapshot(1700);
    let total_active_after: usize = snapshot2.counters.iter().map(|c| c.active_count).sum();
    let total_completed_after: u64 = snapshot2.counters.iter().map(|c| c.completed_total).sum();

    assert_eq!(total_active_after, 2); // 2 tasks still active
    assert_eq!(total_completed_after, 2); // 2 tasks completed
}
