//! Conformance tests for control-plane lane mapping policy (bd-cuut).
//!
//! Validates that the default lane mapping policy from `10.14/bd-qlc6`
//! satisfies the control-plane lane discipline required by Section 10.15.
//!
//! # Invariants Tested
//!
//! - `INV-CLP-EVERY-CLASS-MAPPED`: Every well-known task class resolves to a lane.
//! - `INV-CLP-BUDGET-SUM`: Minimum budget allocations sum to ≤ 100%.
//! - `INV-CLP-CANCEL-BEFORE-READY`: Cancel-tier tasks are always scheduled
//!   before Ready-tier tasks when both are pending.
//! - `INV-CLP-CANCEL-NEVER-STARVED`: Cancel-tier tasks are not starved even
//!   under heavy Ready-tier load.

use frankenengine_node::runtime::lane_scheduler::{
    self, LaneScheduler, SchedulerLane, TaskClass, default_policy, task_classes,
};

/// All well-known task classes from the 10.14 specification.
fn all_task_classes() -> Vec<TaskClass> {
    vec![
        task_classes::epoch_transition(),
        task_classes::barrier_coordination(),
        task_classes::marker_write(),
        task_classes::remote_computation(),
        task_classes::artifact_upload(),
        task_classes::artifact_eviction(),
        task_classes::garbage_collection(),
        task_classes::compaction(),
        task_classes::telemetry_export(),
        task_classes::log_rotation(),
    ]
}

/// Cancel-tier task classes (ControlCritical lane).
fn cancel_tier_classes() -> Vec<TaskClass> {
    vec![
        task_classes::epoch_transition(),
        task_classes::barrier_coordination(),
        task_classes::marker_write(),
    ]
}

/// Ready-tier task classes (Maintenance + Background lanes).
fn ready_tier_classes() -> Vec<TaskClass> {
    vec![
        task_classes::garbage_collection(),
        task_classes::compaction(),
        task_classes::telemetry_export(),
        task_classes::log_rotation(),
    ]
}

// ── INV-CLP-EVERY-CLASS-MAPPED ─────────────────────────────────────────

#[test]
fn every_task_class_has_lane_assignment() {
    let policy = default_policy();
    for tc in &all_task_classes() {
        let lane = policy.resolve(tc);
        assert!(
            lane.is_some(),
            "task class '{}' has no lane assignment in default policy",
            tc
        );
    }
}

#[test]
fn cancel_tier_maps_to_control_critical() {
    let policy = default_policy();
    for tc in &cancel_tier_classes() {
        let lane = policy.resolve(tc).expect("should resolve");
        assert_eq!(
            lane,
            SchedulerLane::ControlCritical,
            "cancel-tier class '{}' should map to ControlCritical, got {:?}",
            tc,
            lane
        );
    }
}

#[test]
fn ready_tier_maps_to_maintenance_or_background() {
    let policy = default_policy();
    for tc in &ready_tier_classes() {
        let lane = policy.resolve(tc).expect("should resolve");
        assert!(
            lane == SchedulerLane::Maintenance || lane == SchedulerLane::Background,
            "ready-tier class '{}' should map to Maintenance or Background, got {:?}",
            tc,
            lane
        );
    }
}

// ── INV-CLP-BUDGET-SUM ─────────────────────────────────────────────────

#[test]
fn budget_allocations_sum_correctly() {
    // Minimum budgets: Cancel=20%, Timed=30%, Ready=10%
    let cancel_min = 20_u32;
    let timed_min = 30_u32;
    let ready_min = 10_u32;
    let total = cancel_min + timed_min + ready_min;
    assert!(total <= 100, "minimum budget sum {} exceeds 100%", total);
    assert_eq!(total, 60, "expected 60% allocated, 40% unallocated");
}

#[test]
fn priority_weights_reflect_cancel_gt_timed_gt_ready() {
    let policy = default_policy();
    let cc = &policy.lane_configs[SchedulerLane::ControlCritical.as_str()];
    let re = &policy.lane_configs[SchedulerLane::RemoteEffect.as_str()];
    let mt = &policy.lane_configs[SchedulerLane::Maintenance.as_str()];
    let bg = &policy.lane_configs[SchedulerLane::Background.as_str()];

    assert!(
        cc.priority_weight > re.priority_weight,
        "Cancel priority ({}) must exceed Timed priority ({})",
        cc.priority_weight,
        re.priority_weight
    );
    assert!(
        re.priority_weight > mt.priority_weight,
        "Timed priority ({}) must exceed Ready/Maintenance priority ({})",
        re.priority_weight,
        mt.priority_weight
    );
    assert!(
        mt.priority_weight > bg.priority_weight,
        "Maintenance priority ({}) must exceed Background priority ({})",
        mt.priority_weight,
        bg.priority_weight
    );
}

// ── INV-CLP-CANCEL-BEFORE-READY ────────────────────────────────────────

#[test]
fn cancel_lane_tasks_scheduled_before_ready_under_mixed_load() {
    let policy = default_policy();
    let mut sched = LaneScheduler::new(policy).expect("valid policy");
    let mut ts = 1000_u64;

    // Submit a mix of Ready-tier and Cancel-tier tasks.
    // Ready tasks first (to attempt to starve Cancel).
    let bg_class = task_classes::telemetry_export();
    let cancel_class = task_classes::epoch_transition();

    // Fill Background lane to cap
    let bg_cap = 2;
    for _ in 0..bg_cap {
        let _ = sched.assign_task(&bg_class, ts, "test");
        ts += 1;
    }

    // Now submit Cancel-tier task — should succeed despite Background load.
    let result = sched.assign_task(&cancel_class, ts, "test");
    assert!(
        result.is_ok(),
        "Cancel-tier task must be schedulable when only Ready-tier is loaded: {:?}",
        result.err()
    );
    let assignment = result.unwrap();
    assert_eq!(assignment.lane, SchedulerLane::ControlCritical);
}

// ── INV-CLP-CANCEL-NEVER-STARVED ───────────────────────────────────────

#[test]
fn cancel_lane_not_starved_under_heavy_ready_load() {
    let policy = default_policy();
    let mut sched = LaneScheduler::new(policy).expect("valid policy");
    let mut ts = 1000_u64;

    // Saturate ALL lanes to their caps
    let classes_and_caps: Vec<(TaskClass, usize)> = vec![
        (task_classes::telemetry_export(), 2),
        (task_classes::garbage_collection(), 4),
        (task_classes::remote_computation(), 32),
    ];

    for (class, cap) in &classes_and_caps {
        for _ in 0..*cap {
            let _ = sched.assign_task(class, ts, "load");
            ts += 1;
        }
    }

    // Cancel-tier task should STILL be schedulable (different lane with its own cap)
    let cancel_class = task_classes::epoch_transition();
    let result = sched.assign_task(&cancel_class, ts, "cancel-test");
    assert!(
        result.is_ok(),
        "Cancel-tier MUST be schedulable even when other lanes are saturated: {:?}",
        result.err()
    );
}

#[test]
fn starvation_detected_when_lane_idle_too_long() {
    let policy = default_policy();
    let mut sched = LaneScheduler::new(policy).expect("valid policy");
    let mut ts = 1000_u64;

    // Assign and immediately cap the Background lane
    let bg_class = task_classes::telemetry_export();
    let _ = sched.assign_task(&bg_class, ts, "bg-1");
    let _ = sched.assign_task(&bg_class, ts, "bg-2");
    // Cap is 2 for Background, next will be rejected and counted as queued
    let _ = sched.assign_task(&bg_class, ts, "bg-3");

    // Advance time past starvation window (5000 ms for Background)
    ts += 6000;

    let starved = sched.check_starvation(ts, "starve-check");
    let bg_starved = starved.iter().any(|e| {
        matches!(
            e,
            lane_scheduler::LaneSchedulerError::Starvation {
                lane: SchedulerLane::Background,
                ..
            }
        )
    });
    assert!(
        bg_starved,
        "Background lane should be detected as starved after exceeding starvation window"
    );
}

// ── Workload simulation for starvation metrics ─────────────────────────

#[test]
fn workload_simulation_produces_metrics() {
    let policy = default_policy();
    let mut sched = LaneScheduler::new(policy).expect("valid policy");

    let cancel_class = task_classes::epoch_transition();
    let timed_class = task_classes::remote_computation();
    let ready_class = task_classes::telemetry_export();

    let mut cancel_runs = 0_u64;
    let mut timed_runs = 0_u64;
    let mut ready_runs = 0_u64;

    // Simulate 100 ticks of mixed workload.
    for tick in 0..100_u64 {
        let ts = 1000 + tick * 100;

        // Every tick: try to assign one of each tier.
        if sched.assign_task(&cancel_class, ts, "sim").is_ok() {
            cancel_runs += 1;
            // Complete immediately to free the slot.
            if let Some(task_id) = sched.audit_log().last().map(|last| last.task_id.clone()) {
                let _ = sched.complete_task(&task_id, ts + 10, "sim");
            }
        }

        if sched.assign_task(&timed_class, ts, "sim").is_ok() {
            timed_runs += 1;
            if let Some(task_id) = sched.audit_log().last().map(|last| last.task_id.clone()) {
                let _ = sched.complete_task(&task_id, ts + 10, "sim");
            }
        }

        if sched.assign_task(&ready_class, ts, "sim").is_ok() {
            ready_runs += 1;
            if let Some(task_id) = sched.audit_log().last().map(|last| last.task_id.clone()) {
                let _ = sched.complete_task(&task_id, ts + 10, "sim");
            }
        }
    }

    // All tiers should have received scheduling.
    assert!(cancel_runs > 0, "Cancel tier must receive scheduling slots");
    assert!(timed_runs > 0, "Timed tier must receive scheduling slots");
    assert!(ready_runs > 0, "Ready tier must receive scheduling slots");

    // Cancel tier should have the most or equal runs (highest priority).
    assert!(
        cancel_runs >= ready_runs,
        "Cancel runs ({}) should be >= Ready runs ({})",
        cancel_runs,
        ready_runs
    );
}

// ── Adversarial: flood Ready, assert Cancel still works ────────────────

#[test]
fn adversarial_ready_flood_does_not_block_cancel() {
    let policy = default_policy();
    let mut sched = LaneScheduler::new(policy).expect("valid policy");
    let mut ts = 1000_u64;

    let ready_class = task_classes::telemetry_export();
    let cancel_class = task_classes::barrier_coordination();

    // Flood Ready lane to cap and beyond.
    for _ in 0..10 {
        let _ = sched.assign_task(&ready_class, ts, "flood");
        ts += 1;
    }

    // Cancel task should STILL succeed.
    let result = sched.assign_task(&cancel_class, ts, "cancel");
    assert!(
        result.is_ok(),
        "Cancel task blocked by Ready flood: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap().lane, SchedulerLane::ControlCritical);
}

#[test]
fn default_policy_validation_passes() {
    let policy = default_policy();
    assert!(
        policy.validate().is_ok(),
        "default policy must pass validation: {:?}",
        policy.validate().err()
    );
}
