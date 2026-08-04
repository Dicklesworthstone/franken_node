use chrono::TimeDelta;
use frankenengine_node::ops::swarm_validation_admission::{
    MAX_SWARM_ADMISSION_AGENTS, MAX_SWARM_ADMISSION_BUILD_SLOTS,
    MAX_SWARM_ADMISSION_COMPATIBILITY_BLOCKERS, MAX_SWARM_ADMISSION_RESERVATIONS,
    MAX_SWARM_ADMISSION_WAITERS, SwarmValidationAdmissionDecision,
    SwarmValidationAdmissionDecisionRecord, SwarmValidationAdmissionFixtureKind,
    SwarmValidationAdmissionInputFixture, SwarmValidationAdmissionPriority,
    SwarmValidationAgentSnapshot, SwarmValidationBuildSlotSnapshot, SwarmValidationBuildSlotState,
    SwarmValidationProofCompatibility, SwarmValidationRequestedAction,
    SwarmValidationReservationMode, SwarmValidationReservationSnapshot,
    SwarmValidationTargetDirStrategy, SwarmValidationUnavailableSignal,
    SwarmValidationWorkerRequirement, deterministic_swarm_validation_admission_fixtures,
    plan_swarm_validation_admission,
};
use frankenengine_node::ops::validation_planner::ValidationShardRchQueueState;
use frankenengine_node::ops::validation_readiness::{
    VALIDATION_SWARM_ADMISSION_READINESS_SCHEMA_VERSION, ValidationReadinessInput,
    ValidationReadinessStatus, build_validation_readiness_report,
    render_validation_readiness_human, render_validation_readiness_json,
};
use proptest::prelude::*;
use serde_json::{Value, json};

const DEFAULT_RETRY_AFTER_MS: u64 = 30_000;
const TRANSCRIPT_SCHEMA_VERSION: &str = "franken-node/swarm-validation-admission/transcript/v1";

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
fn mock_free_e2e_swarm_validation_transcript_emits_stable_jsonl()
-> Result<(), Box<dyn std::error::Error>> {
    let mut producer = fixture_input(SwarmValidationAdmissionFixtureKind::SingleAgent);
    set_scenario_identity(&mut producer, "producer-run", "NavyTurtle");
    producer.proof.proof_work_key = Some("sha256:proof-work-key-e2e".to_string());
    producer.proof.command_digest = Some("sha256:command-digest-e2e".to_string());

    let mut waiter = fixture_input(SwarmValidationAdmissionFixtureKind::DuplicateProofRequest);
    set_scenario_identity(&mut waiter, "coalesce-waiter", "SilentGrove");
    waiter.proof.proof_work_key = Some("sha256:proof-work-key-e2e".to_string());
    waiter.proof.command_digest = Some("sha256:command-digest-e2e".to_string());
    waiter.proof.owner_agent = Some("NavyTurtle".to_string());
    let waiter_coalescing = waiter
        .proof
        .coalescing
        .as_mut()
        .expect("waiter fixture has coalescing state");
    waiter_coalescing.proof_work_key = Some("sha256:proof-work-key-e2e".to_string());
    waiter_coalescing.command_digest = Some("sha256:command-digest-e2e".to_string());
    waiter_coalescing.owner_agent = Some("NavyTurtle".to_string());
    waiter_coalescing.owner_bead_id = Some("bd-0x4fy.9".to_string());
    waiter_coalescing.lease_id = Some("vpco-lease-bd-0x4fy-9".to_string());

    let mut reservation_block = fixture_input(SwarmValidationAdmissionFixtureKind::SingleAgent);
    set_scenario_identity(&mut reservation_block, "reservation-block", "CrimsonOrchid");
    reservation_block
        .coordination
        .reservations
        .push(SwarmValidationReservationSnapshot {
            holder_agent: "ScarletSeal".to_string(),
            path_pattern: "crates/franken-node/src/ops/swarm_validation_admission.rs".to_string(),
            mode: SwarmValidationReservationMode::Exclusive,
            reason: Some("bd-0x4fy.9-peer".to_string()),
            expires_at: reservation_block.observed_at + TimeDelta::minutes(30),
        });

    let mut stale_handoff = fixture_input(SwarmValidationAdmissionFixtureKind::StaleLease);
    set_scenario_identity(&mut stale_handoff, "stale-handoff", "YellowSparrow");

    let mut saturated_queue = fixture_input(SwarmValidationAdmissionFixtureKind::SaturatedRchQueue);
    set_scenario_identity(&mut saturated_queue, "rch-saturated", "SunnyIvy");

    let decisions = [
        (
            "agent_a_start_rch_lane",
            plan_swarm_validation_admission(&producer),
        ),
        (
            "agent_b_join_same_proof",
            plan_swarm_validation_admission(&waiter),
        ),
        (
            "agent_c_reservation_conflict",
            plan_swarm_validation_admission(&reservation_block),
        ),
        (
            "agent_d_stale_lease_handoff",
            plan_swarm_validation_admission(&stale_handoff),
        ),
        (
            "agent_e_rch_saturated_defer",
            plan_swarm_validation_admission(&saturated_queue),
        ),
    ];
    let transcript = decisions
        .iter()
        .map(|(step, decision)| transcript_entry(step, decision))
        .collect::<Vec<_>>();
    let jsonl = render_transcript_jsonl(&transcript)?;

    eprintln!("{jsonl}");
    assert_eq!(jsonl, render_transcript_jsonl(&transcript)?);
    assert_eq!(jsonl.lines().count(), 5);
    assert!(!jsonl.contains("\"command\":\"cargo "));

    let rows = jsonl
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;

    assert!(rows.iter().all(|row| {
        row["schema_version"] == TRANSCRIPT_SCHEMA_VERSION
            && row["bead_id"] == "bd-0x4fy.9"
            && row["thread_id"] == "bd-0x4fy.9"
            && row["trace_id"]
                .as_str()
                .is_some_and(|trace| trace.starts_with("trace-sva-bd-0x4fy-9-"))
            && row["closeout_recommendation"].as_str().is_some()
    }));
    let [
        producer_row,
        waiter_row,
        reservation_row,
        handoff_row,
        saturated_row,
    ] = rows.as_slice()
    else {
        return Err(format!("expected five transcript rows, got {}", rows.len()).into());
    };

    assert_eq!(producer_row["decision"], "run");
    assert_eq!(producer_row["reason_code"], "SVA_RUN_RCH_READY");
    assert_eq!(producer_row["proof_key"], "sha256:proof-work-key-e2e");
    assert_eq!(producer_row["rch_status_class"], "rch_ready");
    assert!(
        producer_row["command"]
            .as_str()
            .is_some_and(|command| command.starts_with("rch exec --"))
    );

    assert_eq!(waiter_row["decision"], "coalesce");
    assert_eq!(waiter_row["proof_key"], "sha256:proof-work-key-e2e");
    assert_eq!(waiter_row["coalescing_owner_agent"], "NavyTurtle");
    assert_eq!(waiter_row["max_parallel_rch_jobs"], 0);

    assert_eq!(reservation_row["decision"], "blocked");
    assert_eq!(
        reservation_row["reason_code"],
        "SVA_BLOCKED_ACTIVE_RESERVATION"
    );
    assert!(
        reservation_row["reservation_evidence"]
            .as_array()
            .expect("reservation evidence array")
            .iter()
            .any(|evidence| evidence
                .as_str()
                .is_some_and(|value| value.contains("ScarletSeal")))
    );

    assert_eq!(handoff_row["decision"], "handoff");
    assert_eq!(handoff_row["reason_code"], "SWARM-STALE-LEASE");
    assert!(
        handoff_row["build_slot_evidence"]
            .as_array()
            .expect("build slot evidence array")
            .iter()
            .any(|evidence| evidence
                .as_str()
                .is_some_and(|value| value.contains("rch-proof-bd-0x4fy-2")))
    );

    assert_eq!(saturated_row["decision"], "defer");
    assert_eq!(saturated_row["reason_code"], "SVA_DEFER_RCH_QUEUE");
    assert_eq!(saturated_row["rch_status_class"], "rch_saturated");
    assert_eq!(saturated_row["command"], Value::Null);
    assert_eq!(
        saturated_row["closeout_recommendation"],
        "refresh_admission_after_retry_no_local_cargo"
    );

    Ok(())
}

#[test]
fn missing_required_input_fields_fail_closed_with_explicit_reason() {
    let mut input = fixture_input(SwarmValidationAdmissionFixtureKind::SingleAgent);
    input.input_id.clear();
    input.trace_id.clear();
    input.bead.bead_id.clear();
    input.bead.thread_id.clear();
    input.agent_name.clear();
    input.policy.profile_id.clear();

    let decision = plan_swarm_validation_admission(&input);

    eprintln!(
        "fixture=missing_required_input decision={} reason_code={} coalescing_key={} action={}",
        decision.decision.as_str(),
        decision.reason_code,
        decision
            .execution_hints
            .coalescing_key
            .as_deref()
            .unwrap_or("none"),
        decision.required_action
    );
    assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Blocked);
    assert_eq!(decision.reason_code, "SVA_BLOCKED_MISSING_INPUT");
    assert_eq!(decision.event_code, "SVA-011");
    assert_eq!(decision.required_action, "repair_admission_input");
    assert!(decision.fail_closed);
    assert!(
        decision.diagnostics.blocked_by.iter().any(|blocker| {
            blocker.contains("input_id") && blocker.contains("policy.profile_id")
        }),
        "missing field list should name empty fields: {:?}",
        decision.diagnostics.blocked_by
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn proof_key_or_command_digest_mismatch_never_coalesces(
        proof_suffix in "[a-z0-9]{1,16}",
        command_suffix in "[a-z0-9]{1,16}",
    ) {
        let mut proof_key_input =
            fixture_input(SwarmValidationAdmissionFixtureKind::DuplicateProofRequest);
        proof_key_input
            .proof
            .coalescing
            .as_mut()
            .expect("duplicate fixture has coalescing state")
            .proof_work_key = Some(format!("sha256:other-proof-{proof_suffix}"));

        let proof_key_decision = plan_swarm_validation_admission(&proof_key_input);

        prop_assert_eq!(
            proof_key_decision.decision,
            SwarmValidationAdmissionDecision::Blocked
        );
        prop_assert_eq!(
            proof_key_decision.reason_code.as_str(),
            "SWARM-INCOMPATIBLE-PROOF"
        );
        prop_assert!(proof_key_decision.fail_closed);
        prop_assert!(proof_key_decision
            .diagnostics
            .blocked_by
            .iter()
            .any(|blocker| blocker.contains("proof work key mismatch")));

        let mut command_digest_input =
            fixture_input(SwarmValidationAdmissionFixtureKind::DuplicateProofRequest);
        command_digest_input
            .proof
            .coalescing
            .as_mut()
            .expect("duplicate fixture has coalescing state")
            .command_digest = Some(format!("sha256:other-command-{command_suffix}"));

        let command_digest_decision = plan_swarm_validation_admission(&command_digest_input);

        prop_assert_eq!(
            command_digest_decision.decision,
            SwarmValidationAdmissionDecision::Blocked
        );
        prop_assert_eq!(
            command_digest_decision.reason_code.as_str(),
            "SWARM-INCOMPATIBLE-PROOF"
        );
        prop_assert!(command_digest_decision.fail_closed);
        prop_assert!(command_digest_decision
            .diagnostics
            .blocked_by
            .iter()
            .any(|blocker| blocker.contains("command digest mismatch")));
    }
}

#[test]
fn profile_incompatibility_blocks_instead_of_reusing_equivalent_hashes() {
    let mut input = fixture_input(SwarmValidationAdmissionFixtureKind::DuplicateProofRequest);
    let coalescing = input
        .proof
        .coalescing
        .as_mut()
        .expect("duplicate fixture has coalescing state");
    coalescing.compatibility = SwarmValidationProofCompatibility::DifferentProfile;
    coalescing
        .compatibility_blockers
        .push("feature/profile hash changed".to_string());

    let decision = plan_swarm_validation_admission(&input);

    assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Blocked);
    assert_eq!(decision.reason_code, "SWARM-INCOMPATIBLE-PROOF");
    assert!(decision.fail_closed);
    assert!(
        decision
            .diagnostics
            .blocked_by
            .iter()
            .any(|blocker| blocker.contains("different_profile"))
    );
    assert!(
        decision
            .diagnostics
            .blocked_by
            .iter()
            .any(|blocker| blocker.contains("feature/profile hash changed"))
    );
}

#[test]
fn stale_lease_handoff_preserves_owner_and_slot_evidence() {
    let input = fixture_input(SwarmValidationAdmissionFixtureKind::StaleLease);

    let decision = plan_swarm_validation_admission(&input);

    assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Handoff);
    assert_eq!(decision.reason_code, "SWARM-STALE-LEASE");
    assert_eq!(decision.required_action, "request_agent_handoff");
    assert!(
        decision
            .diagnostics
            .blocked_by
            .iter()
            .any(|blocker| blocker.contains("stale owner RainyFrog"))
    );
    assert!(
        decision
            .evidence_refs
            .iter()
            .any(|evidence| { evidence == "rch-build-slot:RainyFrog:rch-proof-bd-0x4fy-2" })
    );
}

#[test]
fn agent_mail_reservation_conflict_blocks_with_holder_details() {
    let mut input = fixture_input(SwarmValidationAdmissionFixtureKind::SingleAgent);
    input
        .coordination
        .reservations
        .push(SwarmValidationReservationSnapshot {
            holder_agent: "ScarletSeal".to_string(),
            path_pattern: "crates/franken-node/src/ops/swarm_validation_admission.rs".to_string(),
            mode: SwarmValidationReservationMode::Exclusive,
            reason: Some("bd-other".to_string()),
            expires_at: input.observed_at + TimeDelta::minutes(30),
        });

    let decision = plan_swarm_validation_admission(&input);

    assert_eq!(decision.decision, SwarmValidationAdmissionDecision::Blocked);
    assert_eq!(decision.reason_code, "SVA_BLOCKED_ACTIVE_RESERVATION");
    assert_eq!(
        decision.required_action,
        "coordinate_with_reservation_holder"
    );
    assert!(decision.fail_closed);
    assert!(
        decision
            .diagnostics
            .blocked_by
            .iter()
            .any(|blocker| blocker.contains("ScarletSeal"))
    );
    assert!(decision.evidence_refs.iter().any(|evidence| {
        evidence
            == "agent-mail-reservation:ScarletSeal:crates/franken-node/src/ops/swarm_validation_admission.rs"
    }));
}

#[test]
fn normalization_caps_and_orders_large_coordination_inputs_deterministically() {
    let mut input = fixture_input(SwarmValidationAdmissionFixtureKind::SingleAgent);
    input.coordination.active_agents = (0..(MAX_SWARM_ADMISSION_AGENTS + 8))
        .rev()
        .map(|index| SwarmValidationAgentSnapshot {
            agent_name: format!("Agent{index:04}"),
            project_key: "/data/projects/franken_node".to_string(),
            last_active_age_secs: u64::try_from(index).expect("test index fits u64"),
            ack_required_count: 0,
        })
        .collect();
    input.coordination.reservations = (0..(MAX_SWARM_ADMISSION_RESERVATIONS + 8))
        .rev()
        .map(|index| SwarmValidationReservationSnapshot {
            holder_agent: format!("Holder{index:04}"),
            path_pattern: format!("crates/franken-node/src/path_{index:04}.rs"),
            mode: SwarmValidationReservationMode::Exclusive,
            reason: Some(format!("bd-cap-{index:04}")),
            expires_at: input.observed_at + TimeDelta::minutes(30),
        })
        .collect();
    input.coordination.build_slots = (0..(MAX_SWARM_ADMISSION_BUILD_SLOTS + 8))
        .rev()
        .map(|index| SwarmValidationBuildSlotSnapshot {
            slot: format!("rch-slot-{index:04}"),
            holder_agent: format!("Holder{index:04}"),
            state: SwarmValidationBuildSlotState::Running,
            command_digest: Some(format!("sha256:command-{index:04}")),
            last_progress_age_secs: u64::try_from(index).expect("test index fits u64"),
        })
        .collect();
    input.missing_signals = vec![
        SwarmValidationUnavailableSignal::Rch,
        SwarmValidationUnavailableSignal::AgentMail,
        SwarmValidationUnavailableSignal::Rch,
        SwarmValidationUnavailableSignal::Beads,
        SwarmValidationUnavailableSignal::AgentMail,
    ];

    let normalized = input.normalize();
    let agent_names = normalized
        .coordination
        .active_agents
        .iter()
        .map(|agent| agent.agent_name.clone())
        .collect::<Vec<_>>();
    let reservation_paths = normalized
        .coordination
        .reservations
        .iter()
        .map(|reservation| reservation.path_pattern.clone())
        .collect::<Vec<_>>();
    let build_slots = normalized
        .coordination
        .build_slots
        .iter()
        .map(|slot| slot.slot.clone())
        .collect::<Vec<_>>();

    assert_eq!(agent_names.len(), MAX_SWARM_ADMISSION_AGENTS);
    assert_eq!(reservation_paths.len(), MAX_SWARM_ADMISSION_RESERVATIONS);
    assert_eq!(build_slots.len(), MAX_SWARM_ADMISSION_BUILD_SLOTS);
    assert_sorted(&agent_names);
    assert_sorted(&reservation_paths);
    assert_sorted(&build_slots);
    assert_eq!(
        normalized.missing_signals,
        vec![
            SwarmValidationUnavailableSignal::AgentMail,
            SwarmValidationUnavailableSignal::Beads,
            SwarmValidationUnavailableSignal::Rch,
        ]
    );
}

#[test]
fn proof_coalescing_waiters_and_blockers_are_capped_and_sorted() {
    let mut input = fixture_input(SwarmValidationAdmissionFixtureKind::DuplicateProofRequest);
    let coalescing = input
        .proof
        .coalescing
        .as_mut()
        .expect("duplicate fixture has coalescing state");
    coalescing.waiter_agents = (0..(MAX_SWARM_ADMISSION_WAITERS + 8))
        .rev()
        .map(|index| format!("Waiter{index:04}"))
        .collect();
    coalescing.compatibility_blockers = (0..(MAX_SWARM_ADMISSION_COMPATIBILITY_BLOCKERS + 8))
        .rev()
        .map(|index| format!("blocker-{index:04}"))
        .collect();

    let normalized = input.normalize();
    let coalescing = normalized
        .proof
        .coalescing
        .as_ref()
        .expect("coalescing state survives normalization");

    assert_eq!(coalescing.waiter_agents.len(), MAX_SWARM_ADMISSION_WAITERS);
    assert_eq!(
        coalescing.compatibility_blockers.len(),
        MAX_SWARM_ADMISSION_COMPATIBILITY_BLOCKERS
    );
    assert_sorted(&coalescing.waiter_agents);
    assert_sorted(&coalescing.compatibility_blockers);
}

#[test]
fn fixture_matrix_logs_decision_reason_key_and_action_for_nocapture() {
    let catalog = deterministic_swarm_validation_admission_fixtures();

    for fixture in catalog.fixtures {
        let decision = plan_swarm_validation_admission(&fixture.input);
        let coalescing_key = decision
            .execution_hints
            .coalescing_key
            .as_deref()
            .unwrap_or("none");

        eprintln!(
            "fixture={} decision={} reason_code={} coalescing_key={} action={}",
            fixture.fixture_kind.as_str(),
            decision.decision.as_str(),
            decision.reason_code,
            coalescing_key,
            decision.required_action
        );
        assert_eq!(decision.decision, fixture.expectation.decision);
        assert_eq!(decision.reason_code, fixture.expectation.reason_code);
        assert_eq!(
            decision.required_action,
            fixture.expectation.required_action
        );
        assert!(
            !decision
                .safe_command_shape
                .as_deref()
                .unwrap_or_default()
                .starts_with("cargo "),
            "fixture {} must not recommend local cargo",
            fixture.fixture_kind.as_str()
        );
    }
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

fn assert_sorted(values: &[String]) {
    assert!(
        values.windows(2).all(|pair| pair[0] <= pair[1]),
        "values should be sorted deterministically: {values:?}"
    );
}

fn set_scenario_identity(
    input: &mut SwarmValidationAdmissionInputFixture,
    step_suffix: &str,
    agent_name: &str,
) {
    input.input_id = format!("sva-input-bd-0x4fy-9-{step_suffix}");
    input.trace_id = format!("trace-sva-bd-0x4fy-9-{step_suffix}");
    input.bead.bead_id = "bd-0x4fy.9".to_string();
    input.bead.thread_id = "bd-0x4fy.9".to_string();
    input.bead.assignee = Some(agent_name.to_string());
    input.agent_name = agent_name.to_string();
}

fn transcript_entry(step: &str, decision: &SwarmValidationAdmissionDecisionRecord) -> Value {
    let reservation_evidence = prefixed_evidence(decision, "agent-mail-reservation:");
    let build_slot_evidence = prefixed_evidence(decision, "rch-build-slot:");
    let coalescing_owner_agent = decision
        .coalescing_target
        .as_ref()
        .and_then(|target| target.owner_agent.clone());

    json!({
        "schema_version": TRANSCRIPT_SCHEMA_VERSION,
        "step": step,
        "command": decision.safe_command_shape.as_deref(),
        "bead_id": &decision.bead_id,
        "thread_id": &decision.thread_id,
        "trace_id": &decision.trace_id,
        "agent_name": &decision.agent_name,
        "decision": decision.decision.as_str(),
        "reason_code": &decision.reason_code,
        "event_code": &decision.event_code,
        "required_action": &decision.required_action,
        "proof_key": decision.execution_hints.coalescing_key.as_deref(),
        "proof_source": decision.proof_source.as_str(),
        "coalescing_owner_agent": coalescing_owner_agent,
        "reservation_evidence": reservation_evidence,
        "build_slot_evidence": build_slot_evidence,
        "rch_status_class": rch_status_class(decision),
        "target_dir_strategy": decision.execution_hints.target_dir_strategy,
        "worker_requirement": decision.execution_hints.worker_requirement,
        "max_parallel_rch_jobs": decision.execution_hints.lane_budget.max_parallel_rch_jobs,
        "retry_after_ms": decision.retry_after_ms,
        "closeout_recommendation": closeout_recommendation(decision),
    })
}

fn prefixed_evidence(
    decision: &SwarmValidationAdmissionDecisionRecord,
    prefix: &str,
) -> Vec<String> {
    decision
        .evidence_refs
        .iter()
        .filter(|evidence| evidence.starts_with(prefix))
        .cloned()
        .collect()
}

fn rch_status_class(decision: &SwarmValidationAdmissionDecisionRecord) -> &'static str {
    if !decision.diagnostics.rch_available {
        return "rch_unavailable";
    }

    if decision.execution_hints.worker_requirement
        == SwarmValidationWorkerRequirement::WaitForRchCapacity
    {
        return "rch_saturated";
    }

    match decision.decision {
        SwarmValidationAdmissionDecision::Run => {
            if decision
                .safe_command_shape
                .as_deref()
                .is_some_and(|command| command.starts_with("rch exec --"))
            {
                "rch_ready"
            } else {
                "source_only"
            }
        }
        SwarmValidationAdmissionDecision::Coalesce => "proof_reuse",
        SwarmValidationAdmissionDecision::Defer => "defer",
        SwarmValidationAdmissionDecision::Handoff => "handoff_required",
        SwarmValidationAdmissionDecision::Blocked => "blocked",
    }
}

fn closeout_recommendation(decision: &SwarmValidationAdmissionDecisionRecord) -> &'static str {
    match decision.decision {
        SwarmValidationAdmissionDecision::Run if decision.green_proof_eligible => {
            "run_rch_command_then_attach_receipt"
        }
        SwarmValidationAdmissionDecision::Run => "run_source_checks_then_close",
        SwarmValidationAdmissionDecision::Coalesce if decision.green_proof_eligible => {
            "wait_for_or_reuse_receipt_before_closeout"
        }
        SwarmValidationAdmissionDecision::Coalesce => "wait_for_matching_proof_state",
        SwarmValidationAdmissionDecision::Defer => "refresh_admission_after_retry_no_local_cargo",
        SwarmValidationAdmissionDecision::Handoff => "request_handoff_before_claiming",
        SwarmValidationAdmissionDecision::Blocked => "record_blocker_and_do_not_close",
    }
}

fn render_transcript_jsonl(entries: &[Value]) -> Result<String, serde_json::Error> {
    entries
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map(|lines| format!("{}\n", lines.join("\n")))
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
