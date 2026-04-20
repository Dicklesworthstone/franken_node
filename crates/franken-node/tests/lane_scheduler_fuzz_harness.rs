//! Structure-aware fuzzing harness for lane scheduler inputs
//!
//! Tests policy+epoch+lane tuple combinations for:
//! - LaneMappingPolicy serialization/deserialization
//! - Task assignment determinism across policy variations
//! - Concurrency cap enforcement under fuzzed parameters
//! - Policy validation boundary conditions
//!
//! Follows the canonical_serializer_fuzz_harness pattern with structure-aware
//! input generation and round-trip validation.

use frankenengine_node::runtime::lane_scheduler::{
    LaneScheduler, LaneMappingPolicy, LaneConfig, SchedulerLane, TaskClass,
    task_classes, LaneSchedulerError, LaneTelemetrySnapshot,
};
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_LANES_PER_POLICY: usize = 16;
const MAX_MAPPING_RULES: usize = 32;
const MAX_CONCURRENCY_CAP: usize = 256;
const MAX_PRIORITY_WEIGHT: u32 = 1000;
const MAX_STARVATION_WINDOW_MS: u64 = 300_000; // 5 minutes

#[derive(Debug, Clone, PartialEq, Eq)]
enum HarnessPolicyError {
    PolicyValidation(String),
    SchedulerCreation(String),
    TaskAdmission(String),
    Serialization(String),
    CapExceeded,
    InvalidConfiguration,
}

impl From<LaneSchedulerError> for HarnessPolicyError {
    fn from(error: LaneSchedulerError) -> Self {
        match error {
            LaneSchedulerError::CapExceeded { .. } => Self::CapExceeded,
            _ => Self::TaskAdmission(error.to_string()),
        }
    }
}

/// Generate seed lane configurations for boundary testing
fn seed_lane_configs() -> Vec<LaneConfig> {
    vec![
        // Minimal valid config
        LaneConfig::new(SchedulerLane::ControlCritical, 1, 1),
        // High-priority, low-concurrency (control plane)
        LaneConfig::new(SchedulerLane::ControlCritical, 100, 4),
        // Medium-priority, medium-concurrency (remote effects)
        LaneConfig::new(SchedulerLane::RemoteEffect, 50, 16),
        // Low-priority, high-concurrency (maintenance)
        LaneConfig::new(SchedulerLane::Maintenance, 25, 64),
        // Background processing
        LaneConfig::new(SchedulerLane::Background, 10, 8),
        // Boundary: maximum values
        LaneConfig::new(SchedulerLane::RemoteEffect, MAX_PRIORITY_WEIGHT, MAX_CONCURRENCY_CAP),
        // Boundary: minimum priority, maximum concurrency
        LaneConfig::new(SchedulerLane::Background, 1, MAX_CONCURRENCY_CAP),
        // Boundary: maximum priority, minimum concurrency
        LaneConfig::new(SchedulerLane::ControlCritical, MAX_PRIORITY_WEIGHT, 1),
    ]
}

/// Generate seed task classes for mapping rule testing
fn seed_task_classes() -> Vec<TaskClass> {
    vec![
        task_classes::epoch_transition(),
        task_classes::barrier_coordination(),
        task_classes::marker_write(),
        task_classes::remote_computation(),
        task_classes::artifact_upload(),
        task_classes::garbage_collection(),
        task_classes::telemetry_export(),
        TaskClass::new("custom_task_class"),
        TaskClass::new("boundary_task"),
        TaskClass::new("stress_test_class"),
    ]
}

/// Generate seed lane mapping policies for fuzzing
fn seed_policies() -> Vec<LaneMappingPolicy> {
    let mut policies = Vec::new();

    // Empty policy (invalid)
    policies.push(LaneMappingPolicy::new());

    // Single lane policy
    let mut single_lane = LaneMappingPolicy::new();
    single_lane.add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 100, 4)).unwrap();
    single_lane.add_rule(&task_classes::epoch_transition(), SchedulerLane::ControlCritical);
    policies.push(single_lane);

    // Full policy with all lanes
    let mut full_policy = LaneMappingPolicy::new();
    for lane_config in seed_lane_configs() {
        if !full_policy.lane_configs.contains_key(lane_config.lane.as_str()) {
            let _ = full_policy.add_lane(lane_config);
        }
    }
    for (i, task_class) in seed_task_classes().iter().enumerate() {
        let lane = SchedulerLane::all()[i % SchedulerLane::all().len()];
        full_policy.add_rule(task_class, lane);
    }
    policies.push(full_policy);

    // Unbalanced policy (many rules, few lanes)
    let mut unbalanced = LaneMappingPolicy::new();
    unbalanced.add_lane(LaneConfig::new(SchedulerLane::Background, 1, 1)).unwrap();
    for task_class in seed_task_classes() {
        unbalanced.add_rule(&task_class, SchedulerLane::Background);
    }
    policies.push(unbalanced);

    // Boundary capacity policy
    let mut boundary = LaneMappingPolicy::new();
    boundary.add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, MAX_PRIORITY_WEIGHT, MAX_CONCURRENCY_CAP)).unwrap();
    boundary.add_rule(&task_classes::remote_computation(), SchedulerLane::RemoteEffect);
    policies.push(boundary);

    policies
}

/// Generate policy+epoch+lane tuples for comprehensive fuzzing
fn seed_policy_epoch_lane_tuples() -> Vec<(LaneMappingPolicy, u64, SchedulerLane)> {
    let mut tuples = Vec::new();
    let policies = seed_policies();
    let epochs = vec![0, 1, 100, 1000, u64::MAX / 2, u64::MAX - 1];

    for policy in policies {
        for epoch in &epochs {
            for lane in SchedulerLane::all() {
                tuples.push((policy.clone(), *epoch, *lane));
            }
        }
    }

    tuples
}

/// Validate policy round-trip serialization consistency
fn validate_policy_round_trip(policy: &LaneMappingPolicy) -> Result<(), HarnessPolicyError> {
    let serialized = serde_json::to_string(policy)
        .map_err(|e| HarnessPolicyError::Serialization(e.to_string()))?;

    let deserialized: LaneMappingPolicy = serde_json::from_str(&serialized)
        .map_err(|e| HarnessPolicyError::Serialization(e.to_string()))?;

    if policy != &deserialized {
        return Err(HarnessPolicyError::Serialization("round-trip inequality".to_string()));
    }

    Ok(())
}

/// Test scheduler behavior with fuzzed policy under deterministic inputs
fn validate_scheduler_determinism(
    policy: &LaneMappingPolicy,
    epoch_hint: u64,
    target_lane: SchedulerLane,
) -> Result<LaneTelemetrySnapshot, HarnessPolicyError> {
    if policy.validate().is_err() {
        return Err(HarnessPolicyError::InvalidConfiguration);
    }

    let mut scheduler = LaneScheduler::new(policy.clone())
        .map_err(|e| HarnessPolicyError::SchedulerCreation(e.to_string()))?;

    // Deterministic task admission sequence
    let base_timestamp = 1000000 + epoch_hint;
    let test_tasks = vec![
        task_classes::epoch_transition(),
        task_classes::remote_computation(),
        task_classes::garbage_collection(),
    ];

    for (i, task_class) in test_tasks.iter().enumerate() {
        let timestamp = base_timestamp + (i as u64) * 100;
        let trace_id = format!("fuzz-trace-{}-{}", epoch_hint, i);

        // Admission may fail due to capacity - that's valid behavior to test
        let _result = scheduler.admit_task(task_class, timestamp, &trace_id);
    }

    let snapshot_timestamp = base_timestamp + 1000;
    Ok(scheduler.telemetry_snapshot(snapshot_timestamp))
}

#[test]
fn fuzz_policy_round_trip_serialization_deterministic() {
    for policy in seed_policies() {
        validate_policy_round_trip(&policy)
            .expect("seed policies should round-trip serialize deterministically");
    }
}

#[test]
fn fuzz_policy_validation_boundary_conditions() {
    let test_cases = vec![
        // Empty policy
        (LaneMappingPolicy::new(), false),

        // No lanes configured
        {
            let mut policy = LaneMappingPolicy::new();
            policy.add_rule(&task_classes::epoch_transition(), SchedulerLane::ControlCritical);
            (policy, false)
        },

        // Zero priority weight
        {
            let mut policy = LaneMappingPolicy::new();
            let mut config = LaneConfig::new(SchedulerLane::ControlCritical, 1, 1);
            config.priority_weight = 0;
            let _ = policy.add_lane(config);
            (policy, false)
        },

        // Zero concurrency cap
        {
            let mut policy = LaneMappingPolicy::new();
            let mut config = LaneConfig::new(SchedulerLane::ControlCritical, 100, 1);
            config.concurrency_cap = 0;
            let _ = policy.add_lane(config);
            (policy, false)
        },

        // Valid minimal policy
        {
            let mut policy = LaneMappingPolicy::new();
            policy.add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 1, 1)).unwrap();
            policy.add_rule(&task_classes::epoch_transition(), SchedulerLane::ControlCritical);
            (policy, true)
        },
    ];

    for (policy, should_be_valid) in test_cases {
        let validation_result = policy.validate();
        assert_eq!(
            validation_result.is_ok(),
            should_be_valid,
            "Policy validation mismatch for policy: {:?}, validation: {:?}",
            policy,
            validation_result
        );
    }
}

#[test]
fn fuzz_scheduler_creation_from_policy_variations() {
    for policy in seed_policies() {
        let scheduler_result = LaneScheduler::new(policy.clone());
        let policy_valid = policy.validate().is_ok();

        assert_eq!(
            scheduler_result.is_ok(),
            policy_valid,
            "Scheduler creation should match policy validation for policy: {:?}",
            policy
        );
    }
}

#[test]
fn fuzz_policy_epoch_lane_tuple_determinism() {
    for (policy, epoch_hint, target_lane) in seed_policy_epoch_lane_tuples() {
        if policy.validate().is_ok() {
            let result1 = validate_scheduler_determinism(&policy, epoch_hint, target_lane);
            let result2 = validate_scheduler_determinism(&policy, epoch_hint, target_lane);

            match (result1, result2) {
                (Ok(snapshot1), Ok(snapshot2)) => {
                    // Snapshots should be deterministic for same inputs
                    assert_eq!(
                        snapshot1.schema_version,
                        snapshot2.schema_version,
                        "Schema version should be deterministic"
                    );
                    assert_eq!(
                        snapshot1.counters.len(),
                        snapshot2.counters.len(),
                        "Counter length should be deterministic for policy: {:?}",
                        policy
                    );
                },
                (Err(_), Err(_)) => {
                    // Both failing consistently is acceptable
                },
                (result1, result2) => {
                    panic!("Inconsistent scheduler behavior: {:?} vs {:?} for policy: {:?}, epoch: {}, lane: {:?}",
                           result1, result2, policy, epoch_hint, target_lane);
                }
            }
        }
    }
}

#[test]
fn fuzz_policy_serialization_byte_stability() {
    for policy in seed_policies() {
        if policy.validate().is_ok() {
            let serialized1 = serde_json::to_string_pretty(&policy)
                .expect("valid policy should serialize");
            let serialized2 = serde_json::to_string_pretty(&policy)
                .expect("valid policy should serialize consistently");

            assert_eq!(
                serialized1, serialized2,
                "Policy serialization should be byte-stable for policy: {:?}",
                policy
            );
        }
    }
}

#[test]
fn fuzz_lane_config_boundary_values() {
    let boundary_configs = vec![
        // Minimal valid values
        LaneConfig::new(SchedulerLane::Background, 1, 1),
        // Maximum practical values
        LaneConfig::new(SchedulerLane::ControlCritical, MAX_PRIORITY_WEIGHT, MAX_CONCURRENCY_CAP),
        // Asymmetric configurations
        LaneConfig::new(SchedulerLane::RemoteEffect, 1, MAX_CONCURRENCY_CAP),
        LaneConfig::new(SchedulerLane::Maintenance, MAX_PRIORITY_WEIGHT, 1),
    ];

    for config in boundary_configs {
        // Config creation should succeed
        assert!(config.priority_weight > 0);
        assert!(config.concurrency_cap > 0);

        // Should be serializable
        let serialized = serde_json::to_string(&config)
            .expect("lane config should serialize");
        let _deserialized: LaneConfig = serde_json::from_str(&serialized)
            .expect("lane config should deserialize");
    }
}

#[test]
fn fuzz_task_class_mapping_edge_cases() {
    let edge_task_classes = vec![
        TaskClass::new(""),  // Empty name
        TaskClass::new("a"), // Single character
        TaskClass::new(&"x".repeat(1000)), // Long name
        TaskClass::new("task-with-special-chars!@#$%^&*()"),
        TaskClass::new("unicode_task_名前"),
    ];

    let mut policy = LaneMappingPolicy::new();
    policy.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 4)).unwrap();

    for task_class in edge_task_classes {
        // Mapping should succeed regardless of task class name
        policy.add_rule(&task_class, SchedulerLane::Background);

        // Should be retrievable
        let resolved = policy.resolve(&task_class);
        assert_eq!(resolved, Some(SchedulerLane::Background));
    }
}

#[test]
fn fuzz_concurrency_cap_enforcement() {
    let mut policy = LaneMappingPolicy::new();
    // Create lane with capacity of exactly 2
    policy.add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, 50, 2)).unwrap();
    policy.add_rule(&task_classes::remote_computation(), SchedulerLane::RemoteEffect);

    let mut scheduler = LaneScheduler::new(policy).unwrap();

    // Should admit exactly 2 tasks, then start rejecting
    let task_class = task_classes::remote_computation();

    // First admission: should succeed
    let result1 = scheduler.admit_task(&task_class, 1000, "trace-1");
    assert!(result1.is_ok(), "First task admission should succeed");

    // Second admission: should succeed
    let result2 = scheduler.admit_task(&task_class, 1001, "trace-2");
    assert!(result2.is_ok(), "Second task admission should succeed");

    // Third admission: should fail (capacity exceeded)
    let result3 = scheduler.admit_task(&task_class, 1002, "trace-3");
    assert!(result3.is_err(), "Third task admission should fail due to capacity");

    // Verify the error is capacity-related
    match result3 {
        Err(LaneSchedulerError::CapExceeded { cap, current, .. }) => {
            assert_eq!(cap, 2);
            assert_eq!(current, 2);
        },
        _ => panic!("Expected CapExceeded error, got: {:?}", result3),
    }
}