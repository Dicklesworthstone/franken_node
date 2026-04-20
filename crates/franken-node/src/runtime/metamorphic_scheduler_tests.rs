//! Metamorphic tests for scheduler reorder invariance
//!
//! Tests that scheduler behavior is invariant under task reordering
//! within the same priority class, validating core scheduling properties.

use super::lane_scheduler::*;
use std::collections::HashMap;

#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate test task sequences for metamorphic testing
fn generate_test_tasks() -> Vec<(TaskClass, String)> {
    vec![
        (task_classes::epoch_transition(), "task_1".to_string()),
        (task_classes::barrier_coordination(), "task_2".to_string()),
        (task_classes::marker_write(), "task_3".to_string()),
        (task_classes::remote_computation(), "task_4".to_string()),
        (task_classes::artifact_upload(), "task_5".to_string()),
        (task_classes::garbage_collection(), "task_6".to_string()),
        (task_classes::telemetry_export(), "task_7".to_string()),
    ]
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// MR1: Scheduler Reorder Invariance (Permutative)
/// Reordering tasks within same priority class should not change lane assignments
#[cfg(test)]
mod mr_scheduler_reorder_invariance {
    use super::*;

    #[test]
    fn task_to_lane_mapping_invariant_under_reorder() {
        let policy = create_test_policy();
        let mut tasks = generate_test_tasks();

        // Record original assignments
        let mut scheduler = LaneScheduler::new(policy.clone()).unwrap();
        let mut original_assignments = HashMap::new();
        let timestamp = current_timestamp();

        for (task_class, task_id) in &tasks {
            if let Ok(assignment) = scheduler.assign_task(task_class, timestamp, "trace1") {
                original_assignments.insert(task_id.clone(), assignment.lane);
            }
        }

        // Shuffle the same tasks
        tasks.reverse(); // Simple reordering for deterministic test

        // Create fresh scheduler with same policy
        let mut reordered_scheduler = LaneScheduler::new(policy).unwrap();
        let mut reordered_assignments = HashMap::new();

        for (task_class, task_id) in &tasks {
            if let Ok(assignment) = reordered_scheduler.assign_task(task_class, timestamp, "trace2") {
                reordered_assignments.insert(task_id.clone(), assignment.lane);
            }
        }

        // INV-LANE-EXACT-MAP: Same task class always maps to same lane
        for (task_id, original_lane) in original_assignments {
            if let Some(&reordered_lane) = reordered_assignments.get(&task_id) {
                assert_eq!(original_lane, reordered_lane,
                    "Task {} lane assignment changed: {:?} -> {:?}",
                    task_id, original_lane, reordered_lane);
            }
        }
    }

    #[test]
    fn concurrency_cap_preserved_under_reorder() {
        let policy = create_test_policy();
        let tasks = generate_test_tasks();
        let timestamp = current_timestamp();

        // Process in original order
        let mut scheduler = LaneScheduler::new(policy.clone()).unwrap();
        let mut assignment_count = 0;

        for (task_class, task_id) in &tasks {
            if scheduler.assign_task(task_class, timestamp, "trace").is_ok() {
                assignment_count += 1;
                // Complete every other task to test cap enforcement
                if assignment_count % 2 == 0 {
                    let _ = scheduler.complete_task(task_id, timestamp + 1, "trace");
                }
            }
        }

        // Reprocess in reverse order
        let mut reordered_scheduler = LaneScheduler::new(policy).unwrap();
        let mut reordered_assignment_count = 0;
        let mut reversed_tasks = tasks.clone();
        reversed_tasks.reverse();

        for (task_class, task_id) in &reversed_tasks {
            if reordered_scheduler.assign_task(task_class, timestamp, "trace").is_ok() {
                reordered_assignment_count += 1;
                if reordered_assignment_count % 2 == 0 {
                    let _ = reordered_scheduler.complete_task(task_id, timestamp + 1, "trace");
                }
            }
        }

        // INV-LANE-CAP-ENFORCE: Should handle same number of assignments regardless of order
        // Since we're using same policy and same tasks, assignment behavior should be consistent
        assert_eq!(assignment_count, reordered_assignment_count,
            "Different assignment counts: original={}, reordered={}",
            assignment_count, reordered_assignment_count);
    }
}

/// MR2: Telemetry Accuracy Under Reorder (Additive)
#[cfg(test)]
mod mr_telemetry_accuracy {
    use super::*;

    #[test]
    fn event_counts_consistent_under_reorder() {
        let policy = create_test_policy();
        let tasks = generate_test_tasks();

        // Count events in original order
        let original_counts = process_tasks_count_events(&tasks, &policy);

        // Count events in reverse order
        let mut reversed_tasks = tasks.clone();
        reversed_tasks.reverse();
        let reordered_counts = process_tasks_count_events(&reversed_tasks, &policy);

        // INV-LANE-TELEMETRY-ACCURATE: Total event counts should be identical
        for event_type in &["ASSIGN", "COMPLETE"] {
            let orig = original_counts.get(event_type).unwrap_or(&0);
            let reord = reordered_counts.get(event_type).unwrap_or(&0);
            assert_eq!(orig, reord,
                "Event count mismatch for {}: original={}, reordered={}",
                event_type, orig, reord);
        }
    }
}

// Helper functions for test setup
fn create_test_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();

    // Add lane configs with realistic concurrency caps
    policy.add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 100, 2)).unwrap();
    policy.add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, 50, 8)).unwrap();
    policy.add_lane(LaneConfig::new(SchedulerLane::Maintenance, 20, 4)).unwrap();
    policy.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 16)).unwrap();

    // Add mapping rules
    policy.add_rule(&task_classes::epoch_transition(), SchedulerLane::ControlCritical);
    policy.add_rule(&task_classes::barrier_coordination(), SchedulerLane::ControlCritical);
    policy.add_rule(&task_classes::marker_write(), SchedulerLane::ControlCritical);
    policy.add_rule(&task_classes::remote_computation(), SchedulerLane::RemoteEffect);
    policy.add_rule(&task_classes::artifact_upload(), SchedulerLane::RemoteEffect);
    policy.add_rule(&task_classes::garbage_collection(), SchedulerLane::Maintenance);
    policy.add_rule(&task_classes::telemetry_export(), SchedulerLane::Background);

    policy
}

fn _get_policy_caps(policy: &LaneMappingPolicy) -> HashMap<SchedulerLane, usize> {
    policy.lane_configs.iter()
        .map(|(_, config)| (config.lane, config.concurrency_cap))
        .collect()
}

fn process_tasks_count_events(
    tasks: &[(TaskClass, String)],
    policy: &LaneMappingPolicy
) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    let mut scheduler = LaneScheduler::new(policy.clone()).unwrap();
    let timestamp = current_timestamp();

    for (i, (task_class, task_id)) in tasks.iter().enumerate() {
        if scheduler.assign_task(task_class, timestamp, "trace").is_ok() {
            *counts.entry("ASSIGN".to_string()).or_insert(0) += 1;

            if i % 2 == 0 {
                if scheduler.complete_task(task_id, timestamp + 1, "trace").is_ok() {
                    *counts.entry("COMPLETE".to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_test_policy() {
        let policy = create_test_policy();
        assert!(policy.validate().is_ok(), "Test policy should be valid");
    }
}