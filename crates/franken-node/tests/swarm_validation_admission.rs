use frankenengine_node::ops::swarm_validation_admission::{
    SwarmValidationAdmissionDecision, SwarmValidationAdmissionFixtureKind,
    SwarmValidationAdmissionInputFixture, SwarmValidationAdmissionPriority,
    SwarmValidationRequestedAction, SwarmValidationTargetDirStrategy,
    SwarmValidationWorkerRequirement, deterministic_swarm_validation_admission_fixtures,
    plan_swarm_validation_admission,
};
use frankenengine_node::ops::validation_planner::ValidationShardRchQueueState;

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
