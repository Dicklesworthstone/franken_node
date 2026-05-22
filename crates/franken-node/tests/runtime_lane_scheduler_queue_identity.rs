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

fn reweighted_single_background_lane_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    let mut config = LaneConfig::new(SchedulerLane::Background, 25, 1);
    config.starvation_window_ms = 2_000;
    policy.add_lane(config).expect("test lane should be unique");
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy
}

fn fast_starving_background_lane_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    let mut config = LaneConfig::new(SchedulerLane::Background, 10, 1);
    config.starvation_window_ms = 100;
    policy.add_lane(config).expect("test lane should be unique");
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy
}

fn expanded_background_with_idle_maintenance_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    policy
        .add_lane(LaneConfig::new(SchedulerLane::Background, 10, 1))
        .expect("background lane should be unique");
    policy
        .add_lane(LaneConfig::new(SchedulerLane::Maintenance, 20, 2))
        .expect("maintenance lane should be unique");
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy.add_rule(
        &task_classes::garbage_collection(),
        SchedulerLane::Maintenance,
    );
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

fn zero_cap_background_lane_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    policy
        .add_lane(LaneConfig::new(SchedulerLane::Background, 10, 0))
        .expect("test lane should be unique");
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
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

#[derive(Debug, PartialEq, Eq)]
struct QueueStateDigest {
    active_task_ids: Vec<String>,
    queued_task_ids: Vec<String>,
    active_count: usize,
    queued_count: usize,
    first_queued_at_ms: Option<u64>,
    completed_total: u64,
    rejected_total: u64,
    starvation_events: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct AuditCapacityLifecycleDigest {
    state: QueueStateDigest,
    audit_capacity: usize,
    audit_len: usize,
    audit_codes: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct BackgroundLaneIsolationDigest {
    active_count: usize,
    queued_count: usize,
    first_queued_at_ms: Option<u64>,
    completed_total: u64,
    rejected_total: u64,
    starvation_events: u64,
    background_audit_events: Vec<(String, String)>,
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

fn queue_state_digest(scheduler: &LaneScheduler) -> QueueStateDigest {
    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters");
    QueueStateDigest {
        active_task_ids: scheduler.active_task_ids(SchedulerLane::Background),
        queued_task_ids: scheduler.queued_task_ids(SchedulerLane::Background),
        active_count: counters.active_count,
        queued_count: counters.queued_count,
        first_queued_at_ms: counters.first_queued_at_ms,
        completed_total: counters.completed_total,
        rejected_total: counters.rejected_total,
        starvation_events: counters.starvation_events,
    }
}

fn background_lane_isolation_digest(scheduler: &LaneScheduler) -> BackgroundLaneIsolationDigest {
    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters");
    BackgroundLaneIsolationDigest {
        active_count: counters.active_count,
        queued_count: counters.queued_count,
        first_queued_at_ms: counters.first_queued_at_ms,
        completed_total: counters.completed_total,
        rejected_total: counters.rejected_total,
        starvation_events: counters.starvation_events,
        background_audit_events: scheduler
            .audit_log()
            .iter()
            .filter(|record| record.lane == SchedulerLane::Background.as_str())
            .map(|record| (record.event_code.clone(), record.trace_id.clone()))
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

fn run_background_queue_with_optional_independent_lane_work(
    with_independent_lane_work: bool,
) -> BackgroundLaneIsolationDigest {
    let mut scheduler =
        LaneScheduler::new(default_policy()).expect("default policy should construct scheduler");

    let first_background = scheduler
        .assign_task(&task_classes::log_rotation(), 6_000, "meta-bg-active-1")
        .expect("first background task should occupy the lane");
    let second_background = scheduler
        .assign_task(&task_classes::telemetry_export(), 6_001, "meta-bg-active-2")
        .expect("second background task should occupy the lane");
    let queued_background = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 6_002, "meta-bg-queued")
            .expect_err("third background task should queue at cap"),
    )
    .expect("background cap error must include queued task id");

    assert_eq!(
        scheduler
            .lane_counter(SchedulerLane::Background)
            .expect("background counters before independent work")
            .first_queued_at_ms,
        Some(6_002)
    );

    if with_independent_lane_work {
        let control = scheduler
            .assign_task(
                &task_classes::epoch_transition(),
                6_003,
                "meta-control-active",
            )
            .expect("control task should assign independently");
        let remote = scheduler
            .assign_task(
                &task_classes::remote_computation(),
                6_004,
                "meta-remote-active",
            )
            .expect("remote task should assign independently");
        let maintenance = scheduler
            .assign_task(
                &task_classes::garbage_collection(),
                6_005,
                "meta-maintenance-active",
            )
            .expect("maintenance task should assign independently");

        assert_eq!(
            scheduler
                .lane_counter(SchedulerLane::Background)
                .expect("background counters after independent assignment")
                .queued_count,
            1
        );

        scheduler
            .complete_task(&control.task_id.to_string(), 6_006, "meta-control-complete")
            .expect("control completion should not mutate background queue");
        scheduler
            .complete_task(&remote.task_id.to_string(), 6_007, "meta-remote-complete")
            .expect("remote completion should not mutate background queue");
        scheduler
            .complete_task(
                &maintenance.task_id.to_string(),
                6_008,
                "meta-maintenance-complete",
            )
            .expect("maintenance completion should not mutate background queue");

        assert_eq!(
            scheduler
                .lane_counter(SchedulerLane::Background)
                .expect("background counters after independent completion")
                .first_queued_at_ms,
            Some(6_002)
        );
    }

    scheduler
        .complete_task(
            &first_background.task_id.to_string(),
            6_010,
            "meta-bg-complete-1",
        )
        .expect("background completion should promote queued background task");
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background).len(),
        2
    );
    assert!(
        scheduler
            .queued_task_ids(SchedulerLane::Background)
            .is_empty()
    );

    scheduler
        .complete_task(
            &second_background.task_id.to_string(),
            6_020,
            "meta-bg-complete-2",
        )
        .expect("second background task should complete");
    scheduler
        .complete_task(&queued_background, 6_021, "meta-bg-complete-promoted")
        .expect("promoted background task should complete");

    background_lane_isolation_digest(&scheduler)
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

fn run_queue_lifecycle_after_optional_preserving_reload(
    with_preserving_reload: bool,
) -> QueueLifecycleDigest {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(&task_classes::log_rotation(), 7_000, "meta-reload-active")
        .expect("first task should occupy the lane");
    let queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 7_001, "meta-reload-queued")
            .expect_err("second task should queue at cap"),
    )
    .expect("cap pressure must expose queued task id");

    if with_preserving_reload {
        scheduler
            .reload_policy(reweighted_single_background_lane_policy())
            .expect("reload preserving queued lane should succeed");
        assert_eq!(
            scheduler
                .policy()
                .lane_configs
                .get(SchedulerLane::Background.as_str())
                .expect("background lane must survive reload")
                .priority_weight,
            25
        );
        assert_eq!(
            scheduler.queued_task_ids(SchedulerLane::Background),
            vec![queued.clone()]
        );
    }

    scheduler
        .complete_task(
            &active.task_id.to_string(),
            7_010,
            "meta-reload-complete-active",
        )
        .expect("completion should promote queued task after reload");
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background),
        vec![queued.clone()]
    );
    assert!(
        scheduler
            .queued_task_ids(SchedulerLane::Background)
            .is_empty()
    );

    scheduler
        .complete_task(&queued, 7_020, "meta-reload-complete-promoted")
        .expect("promoted task should complete after reload");

    queue_lifecycle_digest(&scheduler)
}

fn run_starvation_latch_lifecycle(with_duplicate_starvation_check: bool) -> QueueLifecycleDigest {
    let mut scheduler = LaneScheduler::new(fast_starving_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(&task_classes::log_rotation(), 8_000, "meta-starve-active")
        .expect("first task should occupy the lane");
    let queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 8_001, "meta-starve-queued")
            .expect_err("second task should queue at cap"),
    )
    .expect("cap pressure must expose queued task id");

    let starved = scheduler.check_starvation(8_101, "meta-starve-first");
    assert_eq!(starved.len(), 1);
    assert_eq!(starved[0].code(), error_codes::ERR_LANE_STARVATION);
    {
        let counters = scheduler
            .lane_counter(SchedulerLane::Background)
            .expect("background counters after starvation");
        assert_eq!(counters.starvation_events, 1);
        assert!(counters.starvation_active);
    }

    if with_duplicate_starvation_check {
        let audit_len = scheduler.audit_log().len();
        let duplicate = scheduler.check_starvation(8_150, "meta-starve-duplicate");
        assert_eq!(duplicate.len(), 1);
        assert_eq!(scheduler.audit_log().len(), audit_len);
        let counters = scheduler
            .lane_counter(SchedulerLane::Background)
            .expect("background counters after duplicate starvation");
        assert_eq!(counters.starvation_events, 1);
        assert!(counters.starvation_active);
    }

    scheduler
        .complete_task(
            &active.task_id.to_string(),
            8_200,
            "meta-starve-complete-active",
        )
        .expect("completion should promote queued task after starvation");
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background),
        vec![queued.clone()]
    );
    assert!(
        scheduler
            .queued_task_ids(SchedulerLane::Background)
            .is_empty()
    );

    let cleared = scheduler.check_starvation(8_201, "meta-starve-clear");
    assert!(cleared.is_empty());
    {
        let counters = scheduler
            .lane_counter(SchedulerLane::Background)
            .expect("background counters after starvation clears");
        assert_eq!(counters.starvation_events, 1);
        assert!(!counters.starvation_active);
    }

    scheduler
        .complete_task(&queued, 8_210, "meta-starve-complete-promoted")
        .expect("promoted task should complete after starvation clears");

    queue_lifecycle_digest(&scheduler)
}

fn run_queue_lifecycle_after_optional_expanding_reload(
    with_expanding_reload: bool,
) -> QueueLifecycleDigest {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(&task_classes::log_rotation(), 9_000, "meta-expand-active")
        .expect("first task should occupy the lane");
    let queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 9_001, "meta-expand-queued")
            .expect_err("second task should queue at cap"),
    )
    .expect("cap pressure must expose queued task id");

    if with_expanding_reload {
        scheduler
            .reload_policy(expanded_background_with_idle_maintenance_policy())
            .expect("expanding reload should preserve active background lane");
        assert_eq!(
            scheduler
                .policy()
                .resolve(&task_classes::garbage_collection()),
            Some(SchedulerLane::Maintenance)
        );
        assert_eq!(
            scheduler.queued_task_ids(SchedulerLane::Background),
            vec![queued.clone()]
        );
        let maintenance_counters = scheduler
            .lane_counter(SchedulerLane::Maintenance)
            .expect("expanded policy should initialize maintenance counters");
        assert_eq!(maintenance_counters.active_count, 0);
        assert_eq!(maintenance_counters.queued_count, 0);
        assert_eq!(maintenance_counters.completed_total, 0);
        assert_eq!(maintenance_counters.rejected_total, 0);
    }

    scheduler
        .complete_task(
            &active.task_id.to_string(),
            9_010,
            "meta-expand-complete-active",
        )
        .expect("completion should promote queued task after expanding reload");
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background),
        vec![queued.clone()]
    );
    assert!(
        scheduler
            .queued_task_ids(SchedulerLane::Background)
            .is_empty()
    );

    scheduler
        .complete_task(&queued, 9_020, "meta-expand-complete-promoted")
        .expect("promoted task should complete after expanding reload");

    queue_lifecycle_digest(&scheduler)
}

fn run_queue_lifecycle_after_optional_expand_reduce_churn(
    with_expand_reduce_churn: bool,
) -> QueueLifecycleDigest {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(&task_classes::log_rotation(), 9_500, "meta-churn-active")
        .expect("first task should occupy the lane");
    let queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 9_501, "meta-churn-queued")
            .expect_err("second task should queue at cap"),
    )
    .expect("cap pressure must expose queued task id");

    if with_expand_reduce_churn {
        scheduler
            .reload_policy(expanded_background_with_idle_maintenance_policy())
            .expect("idle lane expansion should preserve queued background work");
        assert_eq!(
            scheduler.queued_task_ids(SchedulerLane::Background),
            vec![queued.clone()]
        );
        assert!(
            scheduler.lane_counter(SchedulerLane::Maintenance).is_some(),
            "expanded idle maintenance counter should be visible before reduction"
        );
    }

    scheduler
        .complete_task(
            &active.task_id.to_string(),
            9_510,
            "meta-churn-complete-active",
        )
        .expect("completion should promote queued task after optional expansion");
    scheduler
        .complete_task(&queued, 9_520, "meta-churn-complete-promoted")
        .expect("promoted task should complete before optional reduction");

    if with_expand_reduce_churn {
        scheduler
            .reload_policy(single_background_lane_policy())
            .expect("idle expanded lane should be removable after background drain");
        assert!(
            scheduler.lane_counter(SchedulerLane::Maintenance).is_none(),
            "idle maintenance counter should be removed after reduction"
        );
        assert_eq!(scheduler.lane_counters().len(), 1);
        assert_eq!(
            scheduler
                .policy()
                .resolve(&task_classes::garbage_collection()),
            None
        );
        assert_eq!(
            scheduler.policy().resolve(&task_classes::log_rotation()),
            Some(SchedulerLane::Background)
        );
    }

    queue_lifecycle_digest(&scheduler)
}

fn run_queue_lifecycle_after_optional_rejected_lane_removal(
    with_rejected_reload: bool,
) -> QueueLifecycleDigest {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(
            &task_classes::log_rotation(),
            9_700,
            "meta-reject-reload-active",
        )
        .expect("first task should occupy the lane");
    let queued = queued_task_id_from(
        scheduler
            .assign_task(
                &task_classes::log_rotation(),
                9_701,
                "meta-reject-reload-queued",
            )
            .expect_err("second task should queue at cap"),
    )
    .expect("cap pressure must expose queued task id");

    if with_rejected_reload {
        let before_rejected_reload = queue_lifecycle_digest(&scheduler);
        let error = scheduler
            .reload_policy(single_control_critical_lane_policy())
            .expect_err("removing a lane with active and queued work must fail closed");
        assert_eq!(error.code(), error_codes::ERR_LANE_INVALID_POLICY);
        let detail = match error {
            LaneSchedulerError::InvalidPolicy { detail } => detail,
            _ => String::new(),
        };
        assert!(detail.contains("background"));
        assert!(detail.contains("active=1"));
        assert!(detail.contains("queued=1"));
        assert_eq!(
            scheduler.policy().resolve(&task_classes::log_rotation()),
            Some(SchedulerLane::Background)
        );
        assert_eq!(
            scheduler
                .policy()
                .resolve(&task_classes::epoch_transition()),
            None
        );
        assert_eq!(
            scheduler.queued_task_ids(SchedulerLane::Background),
            vec![queued.clone()]
        );
        assert_eq!(queue_lifecycle_digest(&scheduler), before_rejected_reload);
    }

    scheduler
        .complete_task(
            &active.task_id.to_string(),
            9_710,
            "meta-reject-reload-complete-active",
        )
        .expect("completion should promote queued task after rejected reload");
    scheduler
        .complete_task(&queued, 9_720, "meta-reject-reload-complete-promoted")
        .expect("promoted task should complete after rejected reload");

    queue_lifecycle_digest(&scheduler)
}

fn run_queue_lifecycle_after_optional_invalid_policy_reload(
    with_invalid_reload: bool,
) -> QueueLifecycleDigest {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(
            &task_classes::log_rotation(),
            9_900,
            "meta-invalid-reload-active",
        )
        .expect("first task should occupy the lane");
    let queued = queued_task_id_from(
        scheduler
            .assign_task(
                &task_classes::log_rotation(),
                9_901,
                "meta-invalid-reload-queued",
            )
            .expect_err("second task should queue at cap"),
    )
    .expect("cap pressure must expose queued task id");

    if with_invalid_reload {
        let before_invalid_reload = queue_lifecycle_digest(&scheduler);
        let error = scheduler
            .reload_policy(zero_cap_background_lane_policy())
            .expect_err("invalid replacement policy must fail closed");
        assert_eq!(error.code(), error_codes::ERR_LANE_INVALID_POLICY);
        let detail = match error {
            LaneSchedulerError::InvalidPolicy { detail } => detail,
            _ => String::new(),
        };
        assert!(detail.contains("zero concurrency cap"));
        assert_eq!(
            scheduler
                .policy()
                .lane_configs
                .get(SchedulerLane::Background.as_str())
                .expect("background lane must remain configured")
                .concurrency_cap,
            1
        );
        assert_eq!(
            scheduler.policy().resolve(&task_classes::log_rotation()),
            Some(SchedulerLane::Background)
        );
        assert_eq!(
            scheduler.queued_task_ids(SchedulerLane::Background),
            vec![queued.clone()]
        );
        assert_eq!(queue_lifecycle_digest(&scheduler), before_invalid_reload);
    }

    scheduler
        .complete_task(
            &active.task_id.to_string(),
            9_910,
            "meta-invalid-reload-complete-active",
        )
        .expect("completion should promote queued task after invalid reload");
    scheduler
        .complete_task(&queued, 9_920, "meta-invalid-reload-complete-promoted")
        .expect("promoted task should complete after invalid reload");

    queue_lifecycle_digest(&scheduler)
}

fn run_queue_lifecycle_after_optional_missing_task_probes(
    with_missing_task_probes: bool,
) -> QueueLifecycleDigest {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(
            &task_classes::log_rotation(),
            10_100,
            "meta-missing-probe-active",
        )
        .expect("first task should occupy the lane");
    let queued = queued_task_id_from(
        scheduler
            .assign_task(
                &task_classes::log_rotation(),
                10_101,
                "meta-missing-probe-queued",
            )
            .expect_err("second task should queue at cap"),
    )
    .expect("cap pressure must expose queued task id");

    if with_missing_task_probes {
        let before_missing_probes = queue_lifecycle_digest(&scheduler);
        assert_eq!(
            scheduler
                .complete_task(
                    "task-99999999",
                    10_102,
                    "meta-missing-probe-complete-missing"
                )
                .expect_err("missing active task must fail without mutation")
                .code(),
            error_codes::ERR_LANE_TASK_NOT_FOUND
        );
        assert_eq!(
            scheduler
                .abort_queued_task_id("task-99999999", 10_103, "meta-missing-probe-abort-missing")
                .expect_err("missing queued task must fail without mutation")
                .code(),
            error_codes::ERR_LANE_TASK_NOT_FOUND
        );
        assert_eq!(
            scheduler.active_task_ids(SchedulerLane::Background),
            vec![active.task_id.to_string()]
        );
        assert_eq!(
            scheduler.queued_task_ids(SchedulerLane::Background),
            vec![queued.clone()]
        );
        assert_eq!(queue_lifecycle_digest(&scheduler), before_missing_probes);
    }

    scheduler
        .complete_task(
            &active.task_id.to_string(),
            10_110,
            "meta-missing-probe-complete-active",
        )
        .expect("completion should promote queued task after missing probes");
    scheduler
        .complete_task(&queued, 10_120, "meta-missing-probe-complete-promoted")
        .expect("promoted task should complete after missing probes");

    queue_lifecycle_digest(&scheduler)
}

fn run_queue_lifecycle_after_optional_telemetry_export_probes(
    with_export_probes: bool,
) -> QueueLifecycleDigest {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(
            &task_classes::log_rotation(),
            10_300,
            "meta-export-probe-active",
        )
        .expect("first task should occupy the lane");
    let queued = queued_task_id_from(
        scheduler
            .assign_task(
                &task_classes::log_rotation(),
                10_301,
                "meta-export-probe-queued",
            )
            .expect_err("second task should queue at cap"),
    )
    .expect("cap pressure must expose queued task id");

    if with_export_probes {
        let before_export_probes = queue_lifecycle_digest(&scheduler);
        let audit_len = scheduler.audit_log().len();

        let snapshot = scheduler.telemetry_snapshot(10_302);
        assert_eq!(snapshot.schema_version.as_str(), "ls-v1.0");
        assert_eq!(snapshot.timestamp_ms, 10_302);
        let background = snapshot
            .counters
            .iter()
            .find(|counters| counters.lane == SchedulerLane::Background)
            .expect("background counters must be present in telemetry");
        assert_eq!(background.active_count, 1);
        assert_eq!(background.queued_count, 1);
        assert_eq!(background.first_queued_at_ms, Some(10_301));
        assert_eq!(background.rejected_total, 1);
        assert_eq!(background.starvation_events, 0);

        let exported = scheduler.export_audit_log_jsonl();
        let exported_lines: Vec<&str> = exported.lines().collect();
        assert_eq!(exported_lines.len(), audit_len);
        assert!(
            exported_lines.iter().any(|line| {
                line.contains(event_codes::LANE_ASSIGN) && line.contains("meta-export-probe-active")
            }),
            "audit export must include the active assignment record"
        );
        assert!(
            exported_lines.iter().any(|line| {
                line.contains(event_codes::LANE_TASK_QUEUED)
                    && line.contains("meta-export-probe-queued")
                    && line.contains(&queued)
            }),
            "audit export must include the queued task identity record"
        );
        assert_eq!(scheduler.audit_log().len(), audit_len);
        assert_eq!(
            scheduler.active_task_ids(SchedulerLane::Background),
            vec![active.task_id.to_string()]
        );
        assert_eq!(
            scheduler.queued_task_ids(SchedulerLane::Background),
            vec![queued.clone()]
        );
        assert_eq!(queue_lifecycle_digest(&scheduler), before_export_probes);
    }

    scheduler
        .complete_task(
            &active.task_id.to_string(),
            10_310,
            "meta-export-probe-complete-active",
        )
        .expect("completion should promote queued task after export probes");
    scheduler
        .complete_task(&queued, 10_320, "meta-export-probe-complete-promoted")
        .expect("promoted task should complete after export probes");

    queue_lifecycle_digest(&scheduler)
}

fn run_queue_lifecycle_with_optional_bounded_audit_capacity(
    bounded_capacity: Option<usize>,
) -> AuditCapacityLifecycleDigest {
    let mut scheduler = match bounded_capacity {
        Some(capacity) => {
            LaneScheduler::with_audit_log_capacity(single_background_lane_policy(), capacity)
        }
        None => LaneScheduler::new(single_background_lane_policy()),
    }
    .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(
            &task_classes::log_rotation(),
            10_500,
            "meta-audit-cap-active",
        )
        .expect("first task should occupy the lane");
    let queued = queued_task_id_from(
        scheduler
            .assign_task(
                &task_classes::log_rotation(),
                10_501,
                "meta-audit-cap-queued",
            )
            .expect_err("second task should queue at cap"),
    )
    .expect("cap pressure must expose queued task id");

    scheduler
        .complete_task(
            &active.task_id.to_string(),
            10_510,
            "meta-audit-cap-complete-active",
        )
        .expect("completion should promote queued task under audit capacity");
    scheduler
        .complete_task(&queued, 10_520, "meta-audit-cap-complete-promoted")
        .expect("promoted task should complete under audit capacity");

    AuditCapacityLifecycleDigest {
        state: queue_state_digest(&scheduler),
        audit_capacity: scheduler.audit_log_capacity(),
        audit_len: scheduler.audit_log().len(),
        audit_codes: scheduler
            .audit_log()
            .iter()
            .map(|record| record.event_code.clone())
            .collect(),
    }
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
fn metamorphic_independent_lane_work_commutes_with_background_queue_lifecycle() {
    let baseline = run_background_queue_with_optional_independent_lane_work(false);
    let transformed = run_background_queue_with_optional_independent_lane_work(true);

    assert_eq!(transformed, baseline);
    assert_eq!(transformed.active_count, 0);
    assert_eq!(transformed.queued_count, 0);
    assert_eq!(transformed.first_queued_at_ms, None);
    assert_eq!(transformed.completed_total, 3);
    assert_eq!(transformed.rejected_total, 1);
    assert_eq!(transformed.starvation_events, 0);
    assert_eq!(
        transformed
            .background_audit_events
            .iter()
            .filter(|(event_code, _)| event_code == event_codes::LANE_TASK_PROMOTED)
            .count(),
        1
    );
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
fn metamorphic_preserving_hot_reload_keeps_background_queue_identity_and_promotion() {
    let baseline = run_queue_lifecycle_after_optional_preserving_reload(false);
    let reloaded = run_queue_lifecycle_after_optional_preserving_reload(true);

    assert_eq!(reloaded, baseline);
    assert_eq!(reloaded.active_count, 0);
    assert_eq!(reloaded.queued_count, 0);
    assert_eq!(reloaded.first_queued_at_ms, None);
    assert_eq!(reloaded.completed_total, 2);
    assert_eq!(reloaded.rejected_total, 1);
    assert_eq!(reloaded.starvation_events, 0);
    assert_eq!(
        reloaded
            .audit_codes
            .iter()
            .filter(|event_code| *event_code == event_codes::LANE_TASK_PROMOTED)
            .count(),
        1
    );
}

#[test]
fn metamorphic_repeated_starvation_checks_are_lifecycle_idempotent() {
    let baseline = run_starvation_latch_lifecycle(false);
    let repeated = run_starvation_latch_lifecycle(true);

    assert_eq!(repeated, baseline);
    assert_eq!(repeated.active_count, 0);
    assert_eq!(repeated.queued_count, 0);
    assert_eq!(repeated.first_queued_at_ms, None);
    assert_eq!(repeated.completed_total, 2);
    assert_eq!(repeated.rejected_total, 1);
    assert_eq!(repeated.starvation_events, 1);
    assert_eq!(
        repeated
            .audit_codes
            .iter()
            .filter(|event_code| *event_code == event_codes::LANE_STARVED)
            .count(),
        1
    );
    assert_eq!(
        repeated
            .audit_codes
            .iter()
            .filter(|event_code| *event_code == event_codes::LANE_STARVATION_CLEARED)
            .count(),
        1
    );
    assert_eq!(
        repeated
            .audit_codes
            .iter()
            .filter(|event_code| *event_code == event_codes::LANE_TASK_PROMOTED)
            .count(),
        1
    );
}

#[test]
fn metamorphic_expanding_hot_reload_preserves_existing_queue_lifecycle() {
    let baseline = run_queue_lifecycle_after_optional_expanding_reload(false);
    let expanded = run_queue_lifecycle_after_optional_expanding_reload(true);

    assert_eq!(expanded, baseline);
    assert_eq!(expanded.active_count, 0);
    assert_eq!(expanded.queued_count, 0);
    assert_eq!(expanded.first_queued_at_ms, None);
    assert_eq!(expanded.completed_total, 2);
    assert_eq!(expanded.rejected_total, 1);
    assert_eq!(expanded.starvation_events, 0);
    assert_eq!(
        expanded
            .audit_codes
            .iter()
            .filter(|event_code| *event_code == event_codes::LANE_TASK_PROMOTED)
            .count(),
        1
    );
}

#[test]
fn metamorphic_expand_then_reduce_policy_churn_preserves_queue_lifecycle() {
    let baseline = run_queue_lifecycle_after_optional_expand_reduce_churn(false);
    let churned = run_queue_lifecycle_after_optional_expand_reduce_churn(true);

    assert_eq!(churned, baseline);
    assert_eq!(churned.active_count, 0);
    assert_eq!(churned.queued_count, 0);
    assert_eq!(churned.first_queued_at_ms, None);
    assert_eq!(churned.completed_total, 2);
    assert_eq!(churned.rejected_total, 1);
    assert_eq!(churned.starvation_events, 0);
    assert_eq!(
        churned
            .audit_codes
            .iter()
            .filter(|event_code| *event_code == event_codes::LANE_TASK_PROMOTED)
            .count(),
        1
    );
}

#[test]
fn metamorphic_rejected_hot_reload_is_queue_lifecycle_idempotent() {
    let baseline = run_queue_lifecycle_after_optional_rejected_lane_removal(false);
    let rejected = run_queue_lifecycle_after_optional_rejected_lane_removal(true);

    assert_eq!(rejected, baseline);
    assert_eq!(rejected.active_count, 0);
    assert_eq!(rejected.queued_count, 0);
    assert_eq!(rejected.first_queued_at_ms, None);
    assert_eq!(rejected.completed_total, 2);
    assert_eq!(rejected.rejected_total, 1);
    assert_eq!(rejected.starvation_events, 0);
    assert_eq!(
        rejected
            .audit_codes
            .iter()
            .filter(|event_code| *event_code == event_codes::LANE_TASK_PROMOTED)
            .count(),
        1
    );
}

#[test]
fn metamorphic_invalid_policy_reload_is_queue_lifecycle_idempotent() {
    let baseline = run_queue_lifecycle_after_optional_invalid_policy_reload(false);
    let rejected = run_queue_lifecycle_after_optional_invalid_policy_reload(true);

    assert_eq!(rejected, baseline);
    assert_eq!(rejected.active_count, 0);
    assert_eq!(rejected.queued_count, 0);
    assert_eq!(rejected.first_queued_at_ms, None);
    assert_eq!(rejected.completed_total, 2);
    assert_eq!(rejected.rejected_total, 1);
    assert_eq!(rejected.starvation_events, 0);
    assert_eq!(
        rejected
            .audit_codes
            .iter()
            .filter(|event_code| *event_code == event_codes::LANE_TASK_PROMOTED)
            .count(),
        1
    );
}

#[test]
fn metamorphic_missing_task_probes_are_queue_lifecycle_idempotent() {
    let baseline = run_queue_lifecycle_after_optional_missing_task_probes(false);
    let probed = run_queue_lifecycle_after_optional_missing_task_probes(true);

    assert_eq!(probed, baseline);
    assert_eq!(probed.active_count, 0);
    assert_eq!(probed.queued_count, 0);
    assert_eq!(probed.first_queued_at_ms, None);
    assert_eq!(probed.completed_total, 2);
    assert_eq!(probed.rejected_total, 1);
    assert_eq!(probed.starvation_events, 0);
    assert_eq!(
        probed
            .audit_codes
            .iter()
            .filter(|event_code| *event_code == event_codes::LANE_TASK_PROMOTED)
            .count(),
        1
    );
}

#[test]
fn metamorphic_telemetry_and_audit_exports_preserve_queue_lifecycle() {
    let baseline = run_queue_lifecycle_after_optional_telemetry_export_probes(false);
    let probed = run_queue_lifecycle_after_optional_telemetry_export_probes(true);

    assert_eq!(probed, baseline);
    assert_eq!(probed.active_count, 0);
    assert_eq!(probed.queued_count, 0);
    assert_eq!(probed.first_queued_at_ms, None);
    assert_eq!(probed.completed_total, 2);
    assert_eq!(probed.rejected_total, 1);
    assert_eq!(probed.starvation_events, 0);
    assert_eq!(
        probed
            .audit_codes
            .iter()
            .filter(|event_code| *event_code == event_codes::LANE_TASK_PROMOTED)
            .count(),
        1
    );
}

#[test]
fn metamorphic_bounded_audit_capacity_preserves_queue_lifecycle() {
    let baseline = run_queue_lifecycle_with_optional_bounded_audit_capacity(None);
    let bounded = run_queue_lifecycle_with_optional_bounded_audit_capacity(Some(3));

    assert_eq!(bounded.state, baseline.state);
    assert_eq!(bounded.state.active_count, 0);
    assert_eq!(bounded.state.queued_count, 0);
    assert_eq!(bounded.state.first_queued_at_ms, None);
    assert_eq!(bounded.state.completed_total, 2);
    assert_eq!(bounded.state.rejected_total, 1);
    assert_eq!(bounded.state.starvation_events, 0);
    assert_eq!(baseline.audit_len, 5);
    assert_eq!(bounded.audit_capacity, 3);
    assert_eq!(bounded.audit_len, 3);
    assert!(bounded.audit_len <= bounded.audit_capacity);
    assert_eq!(
        bounded.audit_codes,
        vec![
            event_codes::LANE_TASK_COMPLETED.to_string(),
            event_codes::LANE_TASK_PROMOTED.to_string(),
            event_codes::LANE_TASK_COMPLETED.to_string(),
        ]
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
