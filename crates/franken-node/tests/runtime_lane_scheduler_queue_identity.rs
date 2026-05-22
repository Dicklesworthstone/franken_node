use frankenengine_node::runtime::lane_scheduler::{
    LaneConfig, LaneMappingPolicy, LaneScheduler, LaneSchedulerError, SchedulerLane, TaskClass,
    default_policy, error_codes, event_codes, task_classes,
};

fn single_background_lane_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    policy
        .add_lane(LaneConfig::new(SchedulerLane::Background, 10, 1))
        .expect("test lane should be unique");
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy
}

fn single_control_critical_lane_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    policy
        .add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 100, 1))
        .expect("test lane should be unique");
    policy.add_rule(
        &task_classes::epoch_transition(),
        SchedulerLane::ControlCritical,
    );
    policy
}

fn two_slot_background_lane_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    let mut config = LaneConfig::new(SchedulerLane::Background, 10, 2);
    config.starvation_window_ms = 1_000;
    policy.add_lane(config).expect("test lane should be unique");
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy
}

fn queued_task_id_from(error: LaneSchedulerError) -> Option<String> {
    match error {
        LaneSchedulerError::CapExceeded { queued_task_id, .. } => queued_task_id,
        _ => None,
    }
}

struct DefaultPolicyRequirement {
    name: &'static str,
    task_class: TaskClass,
    expected_lane: SchedulerLane,
}

fn default_policy_requirements() -> Vec<DefaultPolicyRequirement> {
    vec![
        DefaultPolicyRequirement {
            name: "INV-LANE-EXACT-MAP/control/epoch-transition",
            task_class: task_classes::epoch_transition(),
            expected_lane: SchedulerLane::ControlCritical,
        },
        DefaultPolicyRequirement {
            name: "INV-LANE-EXACT-MAP/control/barrier-coordination",
            task_class: task_classes::barrier_coordination(),
            expected_lane: SchedulerLane::ControlCritical,
        },
        DefaultPolicyRequirement {
            name: "INV-LANE-EXACT-MAP/control/marker-write",
            task_class: task_classes::marker_write(),
            expected_lane: SchedulerLane::ControlCritical,
        },
        DefaultPolicyRequirement {
            name: "INV-LANE-EXACT-MAP/remote/computation",
            task_class: task_classes::remote_computation(),
            expected_lane: SchedulerLane::RemoteEffect,
        },
        DefaultPolicyRequirement {
            name: "INV-LANE-EXACT-MAP/remote/artifact-upload",
            task_class: task_classes::artifact_upload(),
            expected_lane: SchedulerLane::RemoteEffect,
        },
        DefaultPolicyRequirement {
            name: "INV-LANE-EXACT-MAP/remote/artifact-eviction",
            task_class: task_classes::artifact_eviction(),
            expected_lane: SchedulerLane::RemoteEffect,
        },
        DefaultPolicyRequirement {
            name: "INV-LANE-EXACT-MAP/maintenance/garbage-collection",
            task_class: task_classes::garbage_collection(),
            expected_lane: SchedulerLane::Maintenance,
        },
        DefaultPolicyRequirement {
            name: "INV-LANE-EXACT-MAP/maintenance/compaction",
            task_class: task_classes::compaction(),
            expected_lane: SchedulerLane::Maintenance,
        },
        DefaultPolicyRequirement {
            name: "INV-LANE-EXACT-MAP/background/telemetry-export",
            task_class: task_classes::telemetry_export(),
            expected_lane: SchedulerLane::Background,
        },
        DefaultPolicyRequirement {
            name: "INV-LANE-EXACT-MAP/background/log-rotation",
            task_class: task_classes::log_rotation(),
            expected_lane: SchedulerLane::Background,
        },
    ]
}

#[derive(Debug, PartialEq, Eq)]
struct QueueDrainOutcome {
    front_queued_id: String,
    promoted_task_id: String,
    active_task_ids: Vec<String>,
    queued_task_ids: Vec<String>,
    active_count: usize,
    queued_count: usize,
    first_queued_at_ms: Option<u64>,
    completed_total: u64,
}

fn drain_front_queue_after_optional_tail_abort(abort_tail: bool) -> QueueDrainOutcome {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");
    let active = scheduler
        .assign_task(&task_classes::log_rotation(), 3_000, "trace-active")
        .expect("first task should occupy the lane");
    let front_queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 3_001, "trace-front-queued")
            .expect_err("front queued task should surface cap pressure"),
    )
    .expect("front cap error must include queued task id");

    if abort_tail {
        let tail_queued = queued_task_id_from(
            scheduler
                .assign_task(&task_classes::log_rotation(), 3_002, "trace-tail-queued")
                .expect_err("tail queued task should surface cap pressure"),
        )
        .expect("tail cap error must include queued task id");
        scheduler
            .abort_queued_task_id(&tail_queued, 3_003, "trace-tail-abort")
            .expect("tail queued task should abort cleanly");
    }

    scheduler
        .complete_task(&active.task_id.to_string(), 3_010, "trace-complete-active")
        .expect("completion should promote the front queued task");

    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters after drain");
    let promoted_task_id = scheduler
        .audit_log()
        .iter()
        .rev()
        .find(|record| record.event_code == event_codes::LANE_TASK_PROMOTED)
        .expect("promotion audit record")
        .task_id
        .clone();

    QueueDrainOutcome {
        front_queued_id: front_queued,
        promoted_task_id,
        active_task_ids: scheduler.active_task_ids(SchedulerLane::Background),
        queued_task_ids: scheduler.queued_task_ids(SchedulerLane::Background),
        active_count: counters.active_count,
        queued_count: counters.queued_count,
        first_queued_at_ms: counters.first_queued_at_ms,
        completed_total: counters.completed_total,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct QueueLifecycleDigest {
    active_task_ids: Vec<String>,
    queued_task_ids: Vec<String>,
    active_count: usize,
    queued_count: usize,
    first_queued_at_ms: Option<u64>,
    completed_total: u64,
    rejected_total: u64,
    starvation_events: u64,
    audit_codes: Vec<String>,
}

fn queue_lifecycle_digest(scheduler: &LaneScheduler) -> QueueLifecycleDigest {
    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters");
    QueueLifecycleDigest {
        active_task_ids: scheduler.active_task_ids(SchedulerLane::Background),
        queued_task_ids: scheduler.queued_task_ids(SchedulerLane::Background),
        active_count: counters.active_count,
        queued_count: counters.queued_count,
        first_queued_at_ms: counters.first_queued_at_ms,
        completed_total: counters.completed_total,
        rejected_total: counters.rejected_total,
        starvation_events: counters.starvation_events,
        audit_codes: scheduler
            .audit_log()
            .iter()
            .map(|record| record.event_code.clone())
            .collect(),
    }
}

fn observe_scheduler_without_lane_mutation(scheduler: &mut LaneScheduler, timestamp_ms: u64) {
    let before = queue_lifecycle_digest(scheduler);
    let audit_len = scheduler.audit_log().len();

    assert_eq!(
        scheduler
            .telemetry_snapshot(timestamp_ms)
            .schema_version
            .as_str(),
        "ls-v1.0"
    );
    assert!(
        scheduler
            .assign_task(
                &task_classes::compaction(),
                timestamp_ms,
                "metamorphic-observe-unknown",
            )
            .is_err(),
        "unknown-class probes must fail without mutating lane state"
    );
    assert!(
        scheduler
            .check_starvation(timestamp_ms, "metamorphic-observe-starvation")
            .is_empty(),
        "observation timestamps stay below the starvation window"
    );

    assert_eq!(scheduler.audit_log().len(), audit_len);
    assert_eq!(queue_lifecycle_digest(scheduler), before);
}

fn run_queue_lifecycle(with_observation_interleavings: bool) -> QueueLifecycleDigest {
    let mut scheduler = LaneScheduler::new(two_slot_background_lane_policy())
        .expect("test policy should construct scheduler");

    let first = scheduler
        .assign_task(&task_classes::log_rotation(), 1_000, "meta-active-1")
        .expect("first task should start");
    let second = scheduler
        .assign_task(&task_classes::log_rotation(), 1_001, "meta-active-2")
        .expect("second task should start");
    let first_queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 1_002, "meta-queued-1")
            .expect_err("third task should queue at cap"),
    )
    .expect("first queued task id");
    let second_queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 1_003, "meta-queued-2")
            .expect_err("fourth task should queue at cap"),
    )
    .expect("second queued task id");

    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background),
        vec![first.task_id.to_string(), second.task_id.to_string()]
    );
    assert_eq!(
        scheduler.queued_task_ids(SchedulerLane::Background),
        vec![first_queued.clone(), second_queued.clone()]
    );

    if with_observation_interleavings {
        observe_scheduler_without_lane_mutation(&mut scheduler, 1_004);
    }

    scheduler
        .complete_task(&first.task_id, 1_010, "meta-complete-1")
        .expect("first completion should promote front queued task");
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background),
        vec![second.task_id.to_string(), first_queued.clone()]
    );
    assert_eq!(
        scheduler.queued_task_ids(SchedulerLane::Background),
        vec![second_queued.clone()]
    );

    if with_observation_interleavings {
        observe_scheduler_without_lane_mutation(&mut scheduler, 1_011);
    }

    scheduler
        .complete_task(&second.task_id, 1_020, "meta-complete-2")
        .expect("second completion should promote tail queued task");
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background),
        vec![first_queued.clone(), second_queued.clone()]
    );
    assert!(
        scheduler
            .queued_task_ids(SchedulerLane::Background)
            .is_empty()
    );

    if with_observation_interleavings {
        observe_scheduler_without_lane_mutation(&mut scheduler, 1_021);
    }

    for (offset, task_id) in scheduler
        .active_task_ids(SchedulerLane::Background)
        .into_iter()
        .enumerate()
    {
        scheduler
            .complete_task(
                &task_id,
                1_030 + u64::try_from(offset).expect("small offset fits in u64"),
                "meta-drain",
            )
            .expect("remaining active task should complete");
    }

    queue_lifecycle_digest(&scheduler)
}

fn run_head_abort_promotion(with_observation_interleavings: bool) -> QueueLifecycleDigest {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(&task_classes::log_rotation(), 5_000, "meta-head-active")
        .expect("first task should occupy the lane");
    let aborted_head = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 5_001, "meta-head-aborted")
            .expect_err("head queued task should surface cap pressure"),
    )
    .expect("head queued task id");
    let promoted_tail = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 5_002, "meta-tail-promoted")
            .expect_err("tail queued task should surface cap pressure"),
    )
    .expect("tail queued task id");

    assert_eq!(
        scheduler.queued_task_ids(SchedulerLane::Background),
        vec![aborted_head.clone(), promoted_tail.clone()]
    );

    if with_observation_interleavings {
        observe_scheduler_without_lane_mutation(&mut scheduler, 5_003);
    }

    let aborted = scheduler
        .abort_queued_task_id(&aborted_head, 5_004, "meta-abort-head")
        .expect("head queued task should abort cleanly");
    assert_eq!(aborted.task_id.to_string(), aborted_head);
    assert_eq!(
        scheduler.queued_task_ids(SchedulerLane::Background),
        vec![promoted_tail.clone()]
    );
    assert_eq!(
        scheduler
            .lane_counter(SchedulerLane::Background)
            .expect("background counters after head abort")
            .first_queued_at_ms,
        Some(5_002)
    );

    if with_observation_interleavings {
        observe_scheduler_without_lane_mutation(&mut scheduler, 5_005);
    }

    scheduler
        .complete_task(&active.task_id.to_string(), 5_010, "meta-complete-active")
        .expect("completion should promote replacement queued task");
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background),
        vec![promoted_tail.clone()]
    );
    assert!(
        scheduler
            .queued_task_ids(SchedulerLane::Background)
            .is_empty()
    );

    if with_observation_interleavings {
        observe_scheduler_without_lane_mutation(&mut scheduler, 5_011);
    }

    scheduler
        .complete_task(&promoted_tail, 5_020, "meta-complete-promoted")
        .expect("promoted replacement task should complete cleanly");

    queue_lifecycle_digest(&scheduler)
}

#[test]
fn metamorphic_queue_lifecycle_invariants_survive_observation_interleavings() {
    let baseline = run_queue_lifecycle(false);
    let observed = run_queue_lifecycle(true);

    assert_eq!(observed, baseline);
    assert_eq!(observed.active_count, 0);
    assert_eq!(observed.queued_count, 0);
    assert_eq!(observed.completed_total, 4);
    assert_eq!(observed.rejected_total, 2);
    assert_eq!(observed.starvation_events, 0);
}

#[test]
fn metamorphic_head_queue_abort_rebases_front_and_survives_observation_interleavings() {
    let baseline = run_head_abort_promotion(false);
    let observed = run_head_abort_promotion(true);

    assert_eq!(observed, baseline);
    assert_eq!(observed.active_count, 0);
    assert_eq!(observed.queued_count, 0);
    assert_eq!(observed.first_queued_at_ms, None);
    assert_eq!(observed.completed_total, 2);
    assert_eq!(observed.rejected_total, 2);
    assert_eq!(observed.starvation_events, 0);
    assert!(
        observed
            .audit_codes
            .contains(&event_codes::LANE_TASK_ABORTED.to_string())
    );
    assert!(
        observed
            .audit_codes
            .contains(&event_codes::LANE_TASK_PROMOTED.to_string())
    );
}

#[test]
fn hot_reload_removes_idle_stale_lane_counters() {
    let mut scheduler =
        LaneScheduler::new(default_policy()).expect("default policy should construct scheduler");

    scheduler
        .reload_policy(single_background_lane_policy())
        .expect("idle removed lanes should reload cleanly");

    assert!(
        scheduler
            .lane_counter(SchedulerLane::ControlCritical)
            .is_none(),
        "removed control lane counter must not remain visible"
    );
    assert!(
        scheduler
            .lane_counter(SchedulerLane::RemoteEffect)
            .is_none(),
        "removed remote lane counter must not remain visible"
    );
    assert!(
        scheduler.lane_counter(SchedulerLane::Maintenance).is_none(),
        "removed maintenance lane counter must not remain visible"
    );
    assert!(
        scheduler.lane_counter(SchedulerLane::Background).is_some(),
        "surviving background lane counter must remain visible"
    );
    assert_eq!(scheduler.lane_counters().len(), 1);
    assert_eq!(scheduler.total_active(), 0);
}

#[test]
fn hot_reload_rejects_removed_lane_with_active_work() {
    let mut scheduler =
        LaneScheduler::new(default_policy()).expect("default policy should construct scheduler");
    let active = scheduler
        .assign_task(&task_classes::epoch_transition(), 1_000, "trace-active")
        .expect("control-critical task should start");

    let error = scheduler
        .reload_policy(single_background_lane_policy())
        .expect_err("removing a lane with active work must fail closed");
    assert_eq!(error.code(), error_codes::ERR_LANE_INVALID_POLICY);
    let detail = match error {
        LaneSchedulerError::InvalidPolicy { detail } => detail,
        _ => String::new(),
    };
    assert!(detail.contains("control_critical"));
    assert!(detail.contains("active="));

    assert_eq!(
        scheduler
            .policy()
            .resolve(&task_classes::epoch_transition())
            .expect("old policy should remain active after rejected reload"),
        SchedulerLane::ControlCritical
    );
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::ControlCritical),
        vec![active.task_id.to_string()]
    );
    assert!(
        scheduler
            .lane_counter(SchedulerLane::ControlCritical)
            .is_some(),
        "rejected reload must keep existing lane counters"
    );
}

#[test]
fn lane_scheduler_keeps_capped_task_identity_and_promotes_fifo() {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(&task_classes::log_rotation(), 1_000, "trace-active")
        .expect("first task should occupy the lane");
    let cap_error = scheduler
        .assign_task(&task_classes::log_rotation(), 1_001, "trace-queued")
        .expect_err("second task should queue and surface cap pressure");

    let queued_task_id = queued_task_id_from(cap_error);
    assert!(
        queued_task_id.is_some(),
        "cap error must include queued task id"
    );
    let queued_task_id = queued_task_id.unwrap_or_default();
    assert_eq!(
        scheduler.queued_task_ids(SchedulerLane::Background),
        vec![queued_task_id.clone()]
    );
    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters");
    assert_eq!(counters.queued_count, 1);
    assert_eq!(counters.first_queued_at_ms, Some(1_001));
    assert_eq!(counters.rejected_total, 1);

    scheduler
        .complete_task(&active.task_id.to_string(), 1_010, "trace-complete")
        .expect("completion should promote queued task");

    assert!(
        scheduler
            .queued_task_ids(SchedulerLane::Background)
            .is_empty()
    );
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background),
        vec![queued_task_id.clone()]
    );
    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters after promotion");
    assert_eq!(counters.active_count, 1);
    assert_eq!(counters.queued_count, 0);
    assert_eq!(counters.first_queued_at_ms, None);

    let queued_record = scheduler
        .audit_log()
        .iter()
        .find(|record| record.event_code == event_codes::LANE_TASK_QUEUED)
        .expect("queue audit record");
    assert_eq!(queued_record.task_id, queued_task_id);
    assert_eq!(queued_record.trace_id, "trace-queued");
    let promoted_record = scheduler
        .audit_log()
        .iter()
        .find(|record| record.event_code == event_codes::LANE_TASK_PROMOTED)
        .expect("promotion audit record");
    assert_eq!(promoted_record.task_id, queued_task_id);
    assert_eq!(promoted_record.trace_id, "trace-queued");
    assert_ne!(promoted_record.trace_id, "trace-complete");
}

#[test]
fn lane_scheduler_aborts_specific_queued_task_without_dropping_neighbors() {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    scheduler
        .assign_task(&task_classes::log_rotation(), 2_000, "trace-active")
        .expect("first task should occupy the lane");
    let first_queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 2_001, "trace-queued-1")
            .expect_err("first queued task should surface cap pressure"),
    );
    assert!(
        first_queued.is_some(),
        "first cap error must include queued task id"
    );
    let first_queued = first_queued.unwrap_or_default();
    let second_queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 2_002, "trace-queued-2")
            .expect_err("second queued task should surface cap pressure"),
    );
    assert!(
        second_queued.is_some(),
        "second cap error must include queued task id"
    );
    let second_queued = second_queued.unwrap_or_default();

    let aborted = scheduler
        .abort_queued_task_id(&second_queued, 2_003, "trace-abort")
        .expect("specific queued task should abort");

    assert_eq!(aborted.task_id.to_string(), second_queued);
    assert_eq!(
        scheduler.queued_task_ids(SchedulerLane::Background),
        vec![first_queued]
    );
    assert_eq!(
        scheduler
            .abort_queued_task_id("missing-task", 2_004, "trace-missing")
            .expect_err("missing queued task must fail")
            .code(),
        error_codes::ERR_LANE_TASK_NOT_FOUND
    );
    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters");
    assert_eq!(counters.active_count, 1);
    assert_eq!(counters.queued_count, 1);
    assert_eq!(counters.first_queued_at_ms, Some(2_001));
}

#[test]
fn metamorphic_tail_queue_abort_preserves_front_promotion() {
    let baseline = drain_front_queue_after_optional_tail_abort(false);
    let transformed = drain_front_queue_after_optional_tail_abort(true);

    assert_eq!(
        transformed, baseline,
        "adding and aborting a non-front queued task must not alter front-queue promotion"
    );
    assert_eq!(baseline.promoted_task_id, baseline.front_queued_id);
    assert_eq!(baseline.active_task_ids, vec![baseline.front_queued_id]);
    assert!(baseline.queued_task_ids.is_empty());
}

#[test]
fn metamorphic_tail_abort_commutes_with_head_completion_lifecycle() {
    fn build_seed() -> (LaneScheduler, String, String, String) {
        let mut scheduler = LaneScheduler::new(single_background_lane_policy())
            .expect("test policy should construct scheduler");

        let active = scheduler
            .assign_task(&task_classes::log_rotation(), 4_000, "trace-active")
            .expect("first task should occupy the lane");
        let promoted = queued_task_id_from(
            scheduler
                .assign_task(&task_classes::log_rotation(), 4_001, "trace-promoted")
                .expect_err("second task should queue at cap"),
        )
        .expect("promoted queued task id");
        let aborted = queued_task_id_from(
            scheduler
                .assign_task(&task_classes::log_rotation(), 4_002, "trace-aborted")
                .expect_err("third task should queue at cap"),
        )
        .expect("aborted queued task id");

        (scheduler, active.task_id.to_string(), promoted, aborted)
    }

    let (mut abort_then_complete, active_a, promoted_a, aborted_a) = build_seed();
    let (mut complete_then_abort, active_b, promoted_b, aborted_b) = build_seed();
    assert_eq!(
        (active_a.as_str(), promoted_a.as_str(), aborted_a.as_str()),
        (active_b.as_str(), promoted_b.as_str(), aborted_b.as_str())
    );

    let aborted_first = abort_then_complete
        .abort_queued_task_id(&aborted_a, 4_003, "trace-abort-tail")
        .expect("tail queued task should abort before completion");
    assert_eq!(aborted_first.task_id.to_string(), aborted_a);
    abort_then_complete
        .complete_task(&active_a, 4_004, "trace-complete-head")
        .expect("head completion should promote front queued task");

    complete_then_abort
        .complete_task(&active_b, 4_004, "trace-complete-head")
        .expect("head completion should promote front queued task");
    let aborted_second = complete_then_abort
        .abort_queued_task_id(&aborted_b, 4_003, "trace-abort-tail")
        .expect("tail queued task should abort after completion");
    assert_eq!(aborted_second.task_id.to_string(), aborted_b);

    assert_eq!(
        abort_then_complete.active_task_ids(SchedulerLane::Background),
        vec![promoted_a.clone()]
    );
    assert_eq!(
        complete_then_abort.active_task_ids(SchedulerLane::Background),
        vec![promoted_b]
    );
    assert!(
        abort_then_complete
            .queued_task_ids(SchedulerLane::Background)
            .is_empty()
    );
    assert!(
        complete_then_abort
            .queued_task_ids(SchedulerLane::Background)
            .is_empty()
    );
    assert_eq!(
        abort_then_complete
            .lane_counter(SchedulerLane::Background)
            .expect("abort-first background counters"),
        complete_then_abort
            .lane_counter(SchedulerLane::Background)
            .expect("completion-first background counters")
    );
}

#[test]
fn conformance_default_policy_exactly_maps_canonical_task_classes() {
    let requirements = default_policy_requirements();
    let policy = default_policy();
    policy
        .validate()
        .expect("default lane policy must validate");

    assert_eq!(policy.lane_configs.len(), SchedulerLane::all().len());
    assert_eq!(
        policy.mapping_rules.len(),
        requirements.len(),
        "default policy must not contain unaccounted task-class rules"
    );

    let mut seen_task_classes = Vec::new();
    for requirement in &requirements {
        assert!(
            seen_task_classes
                .iter()
                .all(|seen: &String| seen.as_str() != requirement.task_class.as_str()),
            "duplicate conformance requirement for {}",
            requirement.task_class
        );
        seen_task_classes.push(requirement.task_class.as_str().to_string());

        assert_eq!(
            policy.resolve(&requirement.task_class),
            Some(requirement.expected_lane),
            "{}",
            requirement.name
        );
    }

    for lane in SchedulerLane::all() {
        let config = policy
            .lane_configs
            .get(lane.as_str())
            .expect("every declared lane must have a config");
        assert!(config.priority_weight > 0, "{} priority", lane);
        assert!(config.concurrency_cap > 0, "{} cap", lane);
    }

    let mut scheduler = LaneScheduler::new(policy).expect("default policy should construct");
    for (offset, requirement) in requirements.iter().enumerate() {
        let assignment = scheduler
            .assign_task(
                &requirement.task_class,
                10_000 + u64::try_from(offset).expect("small offset fits"),
                requirement.name,
            )
            .expect("canonical class should assign without queueing");
        assert_eq!(assignment.lane, requirement.expected_lane);
    }

    let expected_active = [
        (SchedulerLane::ControlCritical, 3usize),
        (SchedulerLane::RemoteEffect, 3usize),
        (SchedulerLane::Maintenance, 2usize),
        (SchedulerLane::Background, 2usize),
    ];
    for (lane, expected_count) in expected_active {
        let counters = scheduler.lane_counter(lane).expect("lane counters");
        assert_eq!(counters.active_count, expected_count, "{lane}");
        assert_eq!(counters.queued_count, 0, "{lane}");
        assert_eq!(counters.rejected_total, 0, "{lane}");
    }
    assert_eq!(scheduler.total_active(), requirements.len());
    assert!(
        scheduler
            .audit_log()
            .iter()
            .all(|record| record.event_code == event_codes::LANE_ASSIGN),
        "canonical policy conformance should only emit assignment audit records"
    );
}

#[test]
fn conformance_hot_reload_rejects_removed_lane_with_queued_work_without_losing_queue() {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");
    let active = scheduler
        .assign_task(&task_classes::log_rotation(), 4_000, "trace-active")
        .expect("first task should occupy the lane");
    let queued_task_id = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 4_001, "trace-queued")
            .expect_err("second task should queue at cap"),
    )
    .expect("cap pressure must expose queued task id");

    let error = scheduler
        .reload_policy(single_control_critical_lane_policy())
        .expect_err("removing a lane with queued work must fail closed");
    assert_eq!(error.code(), error_codes::ERR_LANE_INVALID_POLICY);
    let detail = match error {
        LaneSchedulerError::InvalidPolicy { detail } => detail,
        _ => String::new(),
    };
    assert!(detail.contains("background"));
    assert!(detail.contains("active=1"));
    assert!(detail.contains("queued=1"));

    assert_eq!(
        scheduler
            .policy()
            .resolve(&task_classes::log_rotation())
            .expect("rejected reload must preserve old mapping"),
        SchedulerLane::Background
    );
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background),
        vec![active.task_id.to_string()]
    );
    assert_eq!(
        scheduler.queued_task_ids(SchedulerLane::Background),
        vec![queued_task_id]
    );
    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters");
    assert_eq!(counters.active_count, 1);
    assert_eq!(counters.queued_count, 1);
    assert_eq!(counters.first_queued_at_ms, Some(4_001));
}
