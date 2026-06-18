use frankenengine_node::ops::swarm_validation_admission::{
    SwarmValidationAdmissionDecision, SwarmValidationAdmissionFixtureKind,
    SwarmValidationAdmissionInputFixture, SwarmValidationAdmissionPriority,
    SwarmValidationRequestedAction, SwarmValidationTargetDirStrategy,
    SwarmValidationWorkerRequirement, deterministic_swarm_validation_admission_fixtures,
    plan_swarm_validation_admission,
};
use frankenengine_node::ops::validation_planner::ValidationShardRchQueueState;
use frankenengine_node::ops::validation_readiness::{
    VALIDATION_SWARM_ADMISSION_READINESS_SCHEMA_VERSION, ValidationReadinessInput,
    ValidationReadinessStatus, build_validation_readiness_report,
    render_validation_readiness_human, render_validation_readiness_json,
};
use serde_json::Value;

const DEFAULT_RETRY_AFTER_MS: u64 = 30_000;

fn fixture_input(
    kind: SwarmValidationAdmissionFixtureKind,
) -> SwarmValidationAdmissionInputFixture {
    deterministic_swarm_validation_admission_fixtures()
        .fixture(kind)
        .expect("fixture exists")
        .input
        .clone()
}

#[test]
fn high_memory_headroom_emits_worker_priority_and_lane_budget_hints() {
    let mut input = fixture_input(SwarmValidationAdmissionFixtureKind::SingleAgent);
    input.rch.queue.workers_available = 4;

    let decision = plan_swarm_validation_admission(&input);
    let hints = &decision.execution_hints;

    assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Run);
    assert_eq!(
        hints.worker_requirement,
        SwarmValidationWorkerRequirement::PreferHighMemoryRemote
    );
    assert_eq!(
        hints.target_dir_strategy,
        SwarmValidationTargetDirStrategy::ReuseIsolated
    );
    assert_eq!(
        hints.target_dir.as_deref(),
        Some("/tmp/rch_target_navyturtle_sva")
    );
    assert_eq!(
        hints.build_slot_name.as_deref(),
        Some("rch-sva-bd-0x4fy-4-cargo-test")
    );
    assert_eq!(
        hints.rch_priority,
        Some(SwarmValidationAdmissionPriority::P1)
    );
    assert_eq!(hints.lane_budget.max_parallel_rch_jobs, 4);
    assert_eq!(hints.lane_budget.cargo_build_jobs, 1);
    assert_eq!(hints.lane_budget.expected_build_slots, 1);
    assert!(
        hints
            .advisory_notes
            .iter()
            .any(|note| note.contains("rch exec --"))
    );
    assert!(
        hints
            .advisory_notes
            .iter()
            .any(|note| note.contains("CARGO_BUILD_JOBS=1"))
    );
}

#[test]
fn disk_pressure_defers_target_dir_churn() {
    let mut input = fixture_input(SwarmValidationAdmissionFixtureKind::SingleAgent);
    input.workspace.free_disk_bytes = 16 * 1024 * 1024 * 1024;
    input.target_dir.target_dir_bytes = 24 * 1024 * 1024 * 1024;

    let decision = plan_swarm_validation_admission(&input);
    let hints = &decision.execution_hints;

    assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Defer);
    assert_eq!(decision.reason_code, "SVA_DEFER_TARGET_DIR_DISK_PRESSURE");
    assert_eq!(
        hints.target_dir_strategy,
        SwarmValidationTargetDirStrategy::DeferForDiskPressure
    );
    assert_eq!(
        hints.worker_requirement,
        SwarmValidationWorkerRequirement::PreferHighMemoryRemote
    );
    assert_eq!(hints.lane_budget.max_parallel_rch_jobs, 0);
    assert_eq!(
        hints.lane_budget.retry_after_ms,
        Some(DEFAULT_RETRY_AFTER_MS)
    );
    assert!(
        hints
            .advisory_notes
            .iter()
            .any(|note| note.contains("free disk"))
    );
}

#[test]
fn saturated_rch_queue_hints_wait_without_new_jobs() {
    let mut input = fixture_input(SwarmValidationAdmissionFixtureKind::SaturatedRchQueue);
    input.rch.queue = ValidationShardRchQueueState::saturated(24, 12);

    let decision = plan_swarm_validation_admission(&input);
    let hints = &decision.execution_hints;

    assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Defer);
    assert_eq!(
        hints.worker_requirement,
        SwarmValidationWorkerRequirement::WaitForRchCapacity
    );
    assert_eq!(hints.lane_budget.max_parallel_rch_jobs, 0);
    assert_eq!(
        hints.lane_budget.retry_after_ms,
        Some(DEFAULT_RETRY_AFTER_MS)
    );
    assert!(
        hints
            .advisory_notes
            .iter()
            .any(|note| note.contains("RCH queue is saturated"))
    );
}

#[test]
fn narrow_diagnostic_probe_uses_unique_target_dir_hint() {
    let mut input = fixture_input(SwarmValidationAdmissionFixtureKind::SingleAgent);
    input.requested_action = SwarmValidationRequestedAction::CargoCheck;
    input.target_dir.isolated_target_dir = None;
    input.host.memory_bytes = 64 * 1024 * 1024 * 1024;

    let decision = plan_swarm_validation_admission(&input);
    let hints = &decision.execution_hints;
    let expected_target_dir = "/tmp/rch_target_franken_node_bd-0x4fy-4_cargo-check";

    assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Run);
    assert_eq!(
        hints.target_dir_strategy,
        SwarmValidationTargetDirStrategy::CreateUniqueTemp
    );
    assert_eq!(hints.target_dir.as_deref(), Some(expected_target_dir));
    assert_eq!(
        hints.build_slot_name.as_deref(),
        Some("rch-sva-bd-0x4fy-4-cargo-check")
    );
    assert_eq!(
        decision.safe_command_shape.as_deref(),
        Some(
            "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_node_bd-0x4fy-4_cargo-check cargo check -p frankenengine-node --lib --no-default-features"
        )
    );
    assert!(
        hints
            .advisory_notes
            .iter()
            .any(|note| note.contains("narrow diagnostic probe"))
    );
}

#[test]
fn coalesced_proof_hints_include_key_and_zero_new_rch_jobs() {
    let input = fixture_input(SwarmValidationAdmissionFixtureKind::DuplicateProofRequest);

    let decision = plan_swarm_validation_admission(&input);
    let hints = &decision.execution_hints;

    assert_eq!(
        decision.decision,
        SwarmValidationAdmissionDecision::Coalesce
    );
    assert_eq!(
        hints.coalescing_key.as_deref(),
        Some("sha256:proof-work-key-duplicate")
    );
    assert_eq!(
        hints.target_dir_strategy,
        SwarmValidationTargetDirStrategy::JoinExistingProofLease
    );
    assert_eq!(hints.lane_budget.max_parallel_rch_jobs, 0);
    assert!(
        hints
            .advisory_notes
            .iter()
            .any(|note| note.contains("join by coalescing key"))
    );
}

#[test]
fn readiness_summary_surfaces_swarm_admission_states_in_json_and_human_output()
-> Result<(), Box<dyn std::error::Error>> {
    let mut stale_input = fixture_input(SwarmValidationAdmissionFixtureKind::SingleAgent);
    stale_input.freshness_expires_at = stale_input.observed_at;
    let decisions = vec![
        plan_swarm_validation_admission(&fixture_input(
            SwarmValidationAdmissionFixtureKind::SingleAgent,
        )),
        plan_swarm_validation_admission(&fixture_input(
            SwarmValidationAdmissionFixtureKind::DuplicateProofRequest,
        )),
        plan_swarm_validation_admission(&fixture_input(
            SwarmValidationAdmissionFixtureKind::SaturatedRchQueue,
        )),
        plan_swarm_validation_admission(&fixture_input(
            SwarmValidationAdmissionFixtureKind::OwnerDeadStaleLease,
        )),
        plan_swarm_validation_admission(&fixture_input(
            SwarmValidationAdmissionFixtureKind::IncompatibleProofRequest,
        )),
        plan_swarm_validation_admission(&stale_input),
    ];
    let input = ValidationReadinessInput {
        swarm_admission_decisions: decisions,
        ..ValidationReadinessInput::default()
    };

    let report = build_validation_readiness_report(
        &input,
        "sva-readiness-all-states",
        stale_input.observed_at,
    );
    let admission = &report.summary.swarm_admission;

    assert_eq!(
        admission.schema_version,
        VALIDATION_SWARM_ADMISSION_READINESS_SCHEMA_VERSION
    );
    assert_eq!(admission.decisions, 6);
    assert_eq!(admission.run, 1);
    assert_eq!(admission.coalesce, 1);
    assert_eq!(admission.defer, 1);
    assert_eq!(admission.handoff, 1);
    assert_eq!(admission.blocked, 2);
    assert_eq!(admission.stale_inputs, 1);
    assert_eq!(admission.fail_closed, 2);
    assert!(admission.green_proof_eligible >= 2);
    assert!(admission.rch_jobs_budgeted > 0);

    let check = report
        .checks
        .iter()
        .find(|check| check.code == "VR-SWARM-ADMISSION-011")
        .expect("swarm admission readiness check");
    assert_eq!(check.status, ValidationReadinessStatus::Fail);
    assert_eq!(check.event_code, "SVA-017");
    assert!(check.message.contains("SWARM-INCOMPATIBLE-PROOF"));
    assert!(
        check
            .message
            .contains("SVA_BLOCKED_STALE_OR_INVALID_ARTIFACT")
    );

    let report_json = render_validation_readiness_json(&report)?;
    let value: Value = serde_json::from_str(&report_json)?;
    assert_eq!(
        value["summary"]["swarm_admission"]["schema_version"],
        VALIDATION_SWARM_ADMISSION_READINESS_SCHEMA_VERSION
    );
    assert_eq!(value["summary"]["swarm_admission"]["blocked"], 2);
    assert!(
        value["summary"]["swarm_admission"]["decision_details"]
            .as_array()
            .expect("decision details array")
            .iter()
            .any(|detail| detail["decision"] == "handoff"
                && detail["owner_agent"] == "ScarletSeal"
                && detail["event_code"] == "SVA-009")
    );
    assert!(
        value["summary"]["swarm_admission"]["decision_details"]
            .as_array()
            .expect("decision details array")
            .iter()
            .any(|detail| detail["decision"] == "defer"
                && detail["worker_requirement"] == "wait_for_rch_capacity"
                && detail["max_parallel_rch_jobs"] == 0)
    );

    let human = render_validation_readiness_human(&report);
    assert!(human.contains(
        "swarm_admission=decisions:6 run:1 coalesce:1 defer:1 handoff:1 blocked:2 stale_inputs:1 fail_closed:2"
    ));
    assert!(human.contains("swarm_admission bead=bd-0x4fy.4"));
    assert!(human.contains("reason_code=SWARM-INCOMPATIBLE-PROOF"));
    assert!(human.contains("reason_code=SVA_BLOCKED_STALE_OR_INVALID_ARTIFACT"));
    assert!(!human.contains("safe_command=cargo "));

    Ok(())
}

#[test]
fn readiness_swarm_admission_run_and_coalesce_pass_without_local_cargo_recommendations()
-> Result<(), Box<dyn std::error::Error>> {
    let decisions = vec![
        plan_swarm_validation_admission(&fixture_input(
            SwarmValidationAdmissionFixtureKind::SingleAgent,
        )),
        plan_swarm_validation_admission(&fixture_input(
            SwarmValidationAdmissionFixtureKind::DuplicateProofRequest,
        )),
    ];
    let input = ValidationReadinessInput {
        swarm_admission_decisions: decisions,
        ..ValidationReadinessInput::default()
    };

    let report = build_validation_readiness_report(
        &input,
        "sva-readiness-run-coalesce",
        fixture_input(SwarmValidationAdmissionFixtureKind::SingleAgent).observed_at,
    );
    let check = report
        .checks
        .iter()
        .find(|check| check.code == "VR-SWARM-ADMISSION-011")
        .expect("swarm admission readiness check");

    assert_eq!(check.status, ValidationReadinessStatus::Pass);
    assert_eq!(check.event_code, "SVA-001");
    assert!(check.message.contains("run=1"));
    assert!(check.message.contains("coalesce=1"));

    let report_json = render_validation_readiness_json(&report)?;
    let value: Value = serde_json::from_str(&report_json)?;
    let details = value["summary"]["swarm_admission"]["decision_details"]
        .as_array()
        .expect("decision details array");
    assert!(details.iter().any(|detail| {
        detail["decision"] == "run"
            && detail["safe_command_shape"]
                .as_str()
                .is_some_and(|command| command.starts_with("rch exec -- env CARGO_TARGET_DIR="))
    }));
    assert!(details.iter().any(|detail| detail["decision"] == "coalesce"
        && detail["proof_work_key"] == "sha256:proof-work-key-duplicate"
        && detail["max_parallel_rch_jobs"] == 0));

    Ok(())
}
