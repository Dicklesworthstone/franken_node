use assert_cmd::Command;
use frankenengine_node::ops::doctor::{
    AgentMailCoordinationSummary, AgentMailHealthState, WorkspacePressureDoctor,
};
use frankenengine_node::ops::workspace_pressure_policy::{
    AGENT_COMMAND_LEDGER_SCHEMA_VERSION, AdmissionDecision, AgentCommandBudgetEntry,
    AgentCommandBudgetLedger, AgentCommandCostClass, AgentCommandExecutionPolicy,
    AgentCommandFamily, AgentCommandLedgerError, AgentCommandPolicyViolation,
    AgentCommandValidationOutcome, CROSS_REPO_BLOCKER_ENVELOPE_SCHEMA_VERSION,
    CrossRepoBlockerEnvelopeInput, MAX_AGENT_COMMAND_LEDGER_ENTRIES,
    NO_READY_AUTOPILOT_SCHEMA_VERSION, NoReadyAutopilotAction, NoReadyAutopilotInput,
    NoReadyAutopilotRejectedAlternative, NoReadyBlockedBeadEvidence, NoReadyBlockerOrigin,
    NoReadyInProgressBead, OPERATOR_WHAT_IF_SCHEMA_VERSION, OperatorWhatIfAction,
    OperatorWhatIfArtifact, OperatorWhatIfArtifactSafetyClass, OperatorWhatIfInput,
    OperatorWhatIfRchBuildState, OperatorWhatIfRchQueueState, PolicyDecision,
    TARGET_DIR_LEASE_PLAN_SCHEMA_VERSION, TargetDirLeaseArtifactClass, TargetDirLeaseCommandFamily,
    TargetDirLeasePlanInput, TargetDirLeaseRoot, TargetDirLeaseRootKind, WorkCostClass,
    WorkspaceHardwareTopologySnapshot, WorkspacePressureInputs, WorkspacePressurePolicy,
    count_active_reservations_in_dir, render_agent_command_ledger_human,
    render_target_dir_lease_plan_human, target_dir_lease_reason_codes,
};
use frankenengine_node::runtime::resource_governor::{
    ResourceArtifactInventory, ResourceArtifactInventoryEntry, ResourceArtifactKind,
    ResourceArtifactOpenFileStatus, ResourceArtifactPin, ResourceArtifactSafetyClass,
    ResourceGovernorSnapshotInput, SnapshotProcessInput, reason_codes,
};
use fsqlite::compat::TransactionExt;
use fsqlite::{Connection, SqliteValue};
use proptest::test_runner::Config as ProptestConfig;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const GOLDEN: &str =
    include_str!("../../../artifacts/golden/workspace_pressure_governance_e2e.json");
const OPERATOR_WHAT_IF_FIXTURES: &str =
    include_str!("../../../artifacts/validation_broker/bd-38hez.6/operator_what_if_fixtures.json");
const REPO_KEY: &str = "/data/projects/franken_node";
const POLICY_DECISION_GOLDEN_RELATIVE_PATH: &str =
    "../../tests/golden/workspace_pressure_policy_decisions.json";
const POLICY_DECISION_GOLDEN_SCHEMA_VERSION: &str = "bd-p9mpd.4/v1";
const MAX_POLICY_DIAGNOSTIC_REASONS_WITH_TRUNCATION: usize = 33;
const SPARSE_EIGHT_GIB: u64 = 8 * 1024 * 1024 * 1024;
const SPARSE_FOUR_GIB: u64 = 4 * 1024 * 1024 * 1024;
const SPARSE_ONE_GIB: u64 = 1024 * 1024 * 1024;

#[test]
fn agent_mail_reservation_counter_uses_active_unreleased_unexpired_leases() {
    let dir = TempDir::new().expect("create tempdir");
    let reservations_dir = dir.path().join("file_reservations");
    fs::create_dir_all(&reservations_dir).expect("create reservations dir");

    let future = (chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339();
    let past = (chrono::Utc::now() - chrono::Duration::minutes(30)).to_rfc3339();
    let released = chrono::Utc::now().to_rfc3339();

    write_reservation_fixture(&reservations_dir, "active", &future, None);
    write_reservation_fixture(&reservations_dir, "expired", &past, None);
    write_reservation_fixture(&reservations_dir, "released", &future, Some(&released));
    fs::write(
        reservations_dir.join("missing_expiry.json"),
        br#"{"released_ts":null}"#,
    )
    .expect("write missing expiry fixture");
    fs::write(reservations_dir.join("malformed.json"), b"{").expect("write malformed fixture");
    fs::write(reservations_dir.join("ignored.txt"), b"{}").expect("write ignored fixture");

    assert_eq!(count_active_reservations_in_dir(&reservations_dir), Some(1));
    assert_eq!(
        count_active_reservations_in_dir(&dir.path().join("missing")),
        None
    );
}

#[test]
fn agent_mail_coordination_summary_reports_archive_ahead_and_lock_owner() {
    let payload = json!({
        "status": "error",
        "recovery_mode": "degraded_read_only",
        "next_action": "am doctor repair",
        "archive_inventory": {
            "messages": 17_017_u64,
            "agents": 1_760_u64
        },
        "database_inventory": {
            "messages": 0_u64,
            "agents": 0_u64
        },
        "lock_owner": {
            "pid": 4_134_220_u64,
            "command": "am"
        }
    });

    let summary = AgentMailCoordinationSummary::from_health_payload(&payload);

    assert_eq!(summary.health_state, AgentMailHealthState::LockOwnerActive);
    assert!(!summary.healthy);
    assert!(
        summary
            .signals
            .iter()
            .any(|signal| signal == "archive_ahead_index")
    );
    assert!(
        summary
            .signals
            .iter()
            .any(|signal| signal == "lock_owner_active")
    );
    assert_eq!(summary.archive_message_count, Some(17_017));
    assert_eq!(summary.index_message_count, Some(0));
    assert_eq!(summary.lock_owner_pid, Some(4_134_220));
    assert_eq!(summary.lock_owner_command.as_deref(), Some("am"));
    assert!(
        summary
            .safe_next_action
            .contains("am doctor repair --dry-run")
    );
}

#[test]
fn workspace_pressure_doctor_exposes_agent_mail_coordination_json_and_human() {
    let inputs = WorkspacePressureInputs {
        free_disk_bytes: 2_000_000_000,
        target_dir_bytes: 3_000_000_000,
        active_build_count: 2,
        rch_available_slots: Some(4),
        memory_pressure: 0.4,
        active_reservations: 2,
        coordination_healthy: false,
    };
    let coordination = AgentMailCoordinationSummary::from_health_payload(&json!({
        "status": "error",
        "recovery_mode": "degraded_read_only",
        "archive_inventory": {"messages": 9_u64, "agents": 3_u64},
        "database_inventory": {"messages": 1_u64, "agents": 1_u64},
        "next_action": "am doctor repair"
    }));

    let doctor = WorkspacePressureDoctor::new();
    let report = doctor.generate_report_with_agent_mail_coordination(&inputs, coordination);
    let rendered = serde_json::to_value(&report).expect("workspace pressure report serializes");
    let human = doctor.format_human_report(&report);

    assert_eq!(
        rendered["resources"]["agent_mail_coordination"]["health_state"],
        "archive_ahead_index"
    );
    assert_eq!(
        rendered["resources"]["agent_mail_coordination"]["archive_message_count"],
        9
    );
    assert_eq!(
        rendered["resources"]["agent_mail_coordination"]["index_message_count"],
        1
    );
    assert!(
        rendered["resources"]["agent_mail_coordination"]["safe_next_action"]
            .as_str()
            .is_some_and(|action| action.contains("am doctor repair"))
    );
    assert!(human.contains("Coordination: Degraded (archive_ahead_index)"));
    assert!(human.contains("Coordination Action:"));
}

#[derive(Debug, Deserialize)]
struct GoldenFixture {
    schema_version: String,
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    work_class: String,
    priority: u32,
    free_disk_bytes: u64,
    active_build_count: u32,
    rch_available_slots: Option<u32>,
    memory_pressure: f32,
    active_reservations: u32,
    coordination_healthy: bool,
    expected_admission: String,
    expected_reason_code: String,
    minimum_cleanup_candidates: usize,
}

#[derive(Debug, Deserialize)]
struct OperatorWhatIfFixture {
    schema_version: String,
    scenarios: Vec<OperatorWhatIfScenario>,
}

#[derive(Debug, Deserialize)]
struct OperatorWhatIfScenario {
    name: String,
    bead_id: String,
    work_class: WorkCostClass,
    bead_priority: u32,
    requested_command: String,
    workspace: WorkspacePressureInputs,
    rch_queue: OperatorWhatIfRchQueueState,
    artifacts: Vec<OperatorWhatIfArtifact>,
    ledger_kind: Option<String>,
    stale_sibling_blocker: Option<String>,
    expected_action: OperatorWhatIfAction,
    expected_reason_code: String,
    expected_command_prefix: Option<String>,
    expected_cleanup_actions: usize,
    expected_pinned_artifacts: usize,
    expected_protected_artifacts: usize,
    expected_log_event: String,
}

#[test]
fn fixture_replay_uses_real_workspace_artifacts_and_structured_logs() {
    let fixture: GoldenFixture = serde_json::from_str(GOLDEN).expect("golden fixture should parse");
    assert_eq!(fixture.schema_version, "bd-p9mpd.6/v1");
    assert_eq!(fixture.scenarios.len(), 8);

    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let mut scenario_names = BTreeSet::new();

    for scenario in &fixture.scenarios {
        assert!(scenario_names.insert(scenario.name.as_str()));
        let workspace = RealWorkspace::materialize(&scenario.name);
        let inventory = ResourceArtifactInventory::try_new(workspace.inventory_entries())
            .expect("real artifact inventory should validate");
        let cleanup_candidates = inventory.cleanup_candidates().collect::<Vec<_>>();

        assert!(
            cleanup_candidates.len() >= scenario.minimum_cleanup_candidates,
            "{} should expose enough cleanup candidates",
            scenario.name
        );
        assert_cleanup_candidates_are_safe(&cleanup_candidates);
        assert_protected_paths_remain_non_cleanup(&inventory);

        let inputs = WorkspacePressureInputs {
            free_disk_bytes: scenario.free_disk_bytes,
            target_dir_bytes: workspace.target_dir_bytes(),
            active_build_count: scenario.active_build_count,
            rch_available_slots: scenario.rch_available_slots,
            memory_pressure: scenario.memory_pressure,
            active_reservations: scenario.active_reservations,
            coordination_healthy: scenario.coordination_healthy,
        };
        let work_class = match parse_work_class(&scenario.work_class) {
            Some(work_class) => work_class,
            None => {
                assert!(
                    matches!(
                        scenario.work_class.as_str(),
                        "Validation"
                            | "Fuzzing"
                            | "Benchmark"
                            | "DocsGate"
                            | "SourceOnly"
                            | "Cleanup"
                    ),
                    "unknown work class: {}",
                    scenario.work_class
                );
                WorkCostClass::SourceOnly
            }
        };
        let decision = policy.decide_admission(work_class, scenario.priority, &inputs);

        assert_eq!(
            admission_name(&decision.admission),
            scenario.expected_admission,
            "{} admission drifted",
            scenario.name
        );
        assert_eq!(
            decision.reason_code, scenario.expected_reason_code,
            "{} reason code drifted",
            scenario.name
        );

        workspace.append_assertion_log(json!({
            "schema_version": "bd-p9mpd.6/assertion-log/v1",
            "trace_id": format!("bd-p9mpd.6-{}", scenario.name),
            "scenario": scenario.name,
            "phase": "fixture_replay",
            "assertion": "policy_decision_and_cleanup_safety",
            "admission": admission_name(&decision.admission),
            "reason_code": decision.reason_code,
            "cleanup_candidate_count": cleanup_candidates.len(),
            "cleanup_candidate_bytes": cleanup_candidates
                .iter()
                .filter_map(|entry| entry.bytes)
                .sum::<u64>(),
            "target_dir_bytes": inputs.target_dir_bytes,
            "artifact_root": workspace.root().display().to_string(),
            "coordination_db": workspace.coordination_db_path.display().to_string()
        }));
        workspace.assert_assertion_log_is_jsonl();
    }
}

#[test]
fn cli_subprocess_reads_real_snapshot_artifact_inventory() {
    let workspace = RealWorkspace::materialize("cli_subprocess");
    let snapshot_path = workspace.root().join("snapshots/resource-governor.json");
    fs::create_dir_all(snapshot_path.parent().expect("snapshot parent"))
        .expect("create snapshot dir");

    let snapshot = ResourceGovernorSnapshotInput {
        source: Some("bd-p9mpd.6-real-snapshot".to_string()),
        processes: vec![
            SnapshotProcessInput {
                pid: Some(7001),
                command: "cargo test -p frankenengine-node workspace_pressure_governance_e2e"
                    .to_string(),
                kind: None,
            },
            SnapshotProcessInput {
                pid: Some(7002),
                command: "rustc --crate-name frankenengine_node".to_string(),
                kind: None,
            },
            SnapshotProcessInput {
                pid: Some(7003),
                command: "rch exec -- cargo test".to_string(),
                kind: None,
            },
        ],
        rch_queue_depth: Some(4),
        active_proof_classes: vec!["workspace-pressure-e2e".to_string()],
        target_dir_usage_mb: Some(bytes_to_mib(workspace.target_dir_bytes())),
        artifact_inventory: workspace.inventory_entries(),
        ..ResourceGovernorSnapshotInput::default()
    };

    fs::write(
        &snapshot_path,
        serde_json::to_string_pretty(&snapshot).expect("serialize snapshot"),
    )
    .expect("write real snapshot");

    let mut command = franken_node();
    command.args([
        "ops",
        "resource-governor",
        "--process-snapshot",
        &relative_cli_path(&snapshot_path),
        "--requested-proof-class",
        "workspace-pressure-e2e",
        "--trace-id",
        "bd-p9mpd.6-cli",
        "--json",
    ]);

    let output = command.assert().success().get_output().stdout.clone();
    let payload: Value = serde_json::from_slice(&output).expect("resource-governor output is json");

    assert_eq!(payload["command"], "ops resource-governor");
    assert_eq!(payload["trace_id"], "bd-p9mpd.6-cli");
    assert_eq!(payload["structured_log"]["event_code"], "RG-002");
    assert_eq!(
        payload["decision"]["reason_code"],
        reason_codes::DEDUPE_ACTIVE_PROOF_CLASS
    );

    let entries = payload["observation"]["artifact_inventory"]["entries"]
        .as_array()
        .expect("artifact inventory entries");
    assert!(entries.len() >= 7);
    assert!(
        entries
            .iter()
            .any(|entry| entry["cleanup_eligible"].as_bool() == Some(true))
    );
    assert!(
        entries
            .iter()
            .filter(|entry| entry["cleanup_eligible"].as_bool() == Some(true))
            .all(|entry| !is_protected_path(entry["path"].as_str().expect("entry path")))
    );

    workspace.append_assertion_log(json!({
        "schema_version": "bd-p9mpd.6/assertion-log/v1",
        "trace_id": "bd-p9mpd.6-cli",
        "scenario": "cli_subprocess",
        "phase": "real_subprocess",
        "assertion": "resource_governor_preserves_artifact_inventory",
        "reason_code": payload["decision"]["reason_code"],
        "entry_count": entries.len(),
        "cleanup_candidate_count": entries
            .iter()
            .filter(|entry| entry["cleanup_eligible"].as_bool() == Some(true))
            .count(),
        "snapshot_path": snapshot_path.display().to_string()
    }));
    workspace.assert_assertion_log_is_jsonl();
}

#[test]
fn workspace_pressure_policy_decision_golden_matches_real_policy() -> std::io::Result<()> {
    let actual = build_policy_decision_golden();
    let mut actual_text =
        serde_json::to_string_pretty(&actual).expect("policy golden should serialize");
    actual_text.push('\n');
    let golden_path = policy_decision_golden_path();

    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::write(&golden_path, actual_text)?;
        return Ok(());
    }

    let expected_text = fs::read_to_string(&golden_path).map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!(
                "failed to read workspace pressure policy golden at {}: {err}. \
             Run with UPDATE_GOLDENS=1 to create it.",
                golden_path.display()
            ),
        )
    });
    let expected_text = expected_text?;
    assert_eq!(
        expected_text, actual_text,
        "workspace pressure policy golden drifted from the real policy implementation; \
         rerun this test with UPDATE_GOLDENS=1 only after reviewing the diff"
    );
    Ok(())
}

#[test]
fn target_dir_lease_plan_golden_ranks_roots_without_cleanup_commands() {
    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let input = TargetDirLeasePlanInput {
        plan_id: "bd-c9hho.2-golden".to_string(),
        workspace_root: REPO_KEY.to_string(),
        bead_id: "bd-c9hho.2".to_string(),
        command_family: TargetDirLeaseCommandFamily::RchCargo,
        expected_artifact_class: TargetDirLeaseArtifactClass::BuildOutput,
        roots: vec![
            TargetDirLeaseRoot {
                path: "/data/projects/franken_node/target".to_string(),
                kind: TargetDirLeaseRootKind::RepoLocal,
                total_bytes: 512 * 1024 * 1024 * 1024,
                free_bytes: 300 * 1024 * 1024 * 1024,
                numa_node: Some(0),
                stable_owner: true,
                existing_lease_count: 0,
                stale: false,
            },
            TargetDirLeaseRoot {
                path: "/data/tmp/franken-node-targets-a".to_string(),
                kind: TargetDirLeaseRootKind::OffRepo,
                total_bytes: 512 * 1024 * 1024 * 1024,
                free_bytes: 80 * 1024 * 1024 * 1024,
                numa_node: Some(1),
                stable_owner: true,
                existing_lease_count: 2,
                stale: false,
            },
            TargetDirLeaseRoot {
                path: "/data/tmp/franken-node-targets-b".to_string(),
                kind: TargetDirLeaseRootKind::OffRepo,
                total_bytes: 512 * 1024 * 1024 * 1024,
                free_bytes: 96 * 1024 * 1024 * 1024,
                numa_node: Some(2),
                stable_owner: true,
                existing_lease_count: 0,
                stale: false,
            },
        ],
        topology: Some(WorkspaceHardwareTopologySnapshot {
            snapshot_id: "topology-96c-256g".to_string(),
            cpu_cores: 96,
            memory_bytes: 256 * 1024 * 1024 * 1024,
            numa_nodes: Some(4),
            stale: false,
        }),
        memory_pressure: 0.42,
        active_reservation_hints: Vec::new(),
        rch_required: true,
        lease_ttl_ms: 3_600_000,
    };

    let plan = policy.plan_target_dir_lease(input);
    let rendered = serde_json::to_value(&plan).expect("target-dir lease plan serializes");

    assert_eq!(
        rendered["schema_version"],
        TARGET_DIR_LEASE_PLAN_SCHEMA_VERSION
    );
    assert_eq!(
        rendered["selected_reason_code"],
        target_dir_lease_reason_codes::SELECT_OFF_REPO_RCH
    );
    assert_eq!(
        plan.selected_path.as_deref(),
        Some("/data/tmp/franken-node-targets-b/franken-node-bd-c9hho-2-rch_cargo-build-output")
    );
    assert!(!plan.fail_closed);
    assert_eq!(plan.candidates.len(), 3);
    assert!(plan.diagnostics.len() <= MAX_POLICY_DIAGNOSTIC_REASONS_WITH_TRUNCATION);
    assert!(
        plan.candidates
            .iter()
            .all(|candidate| candidate.diagnostics.len()
                <= MAX_POLICY_DIAGNOSTIC_REASONS_WITH_TRUNCATION)
    );
    assert!(plan.candidates.iter().any(|candidate| candidate.reason_code
        == target_dir_lease_reason_codes::REJECT_REPO_LOCAL_HEAVY
        && candidate.requires_approval));
    assert!(
        plan.cleanup_recommendations
            .iter()
            .all(|recommendation| recommendation.requires_approval)
    );

    let human = render_target_dir_lease_plan_human(&plan);
    assert!(human.contains("target_dir_lease"));
    assert!(human.contains("bd-c9hho.2"));
    assert!(human.contains(
        "/data/tmp/franken-node-targets-b/franken-node-bd-c9hho-2-rch_cargo-build-output"
    ));
    assert!(!human.contains("rm -rf"));
    assert!(!human.contains("git clean"));
}

proptest::proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn proptest_workspace_pressure_admission_is_bounded(
        free_disk_bytes in 0_u64..20_000_000_000,
        target_dir_bytes in 0_u64..80_000_000_000,
        active_build_count in 0_u32..64,
        rch_available_slots in proptest::option::of(0_u32..32),
        memory_pressure in 0.0_f32..1.25,
        active_reservations in 0_u32..256,
        priority in 0_u32..5,
        work_class_idx in 0_usize..6,
    ) {
        let work_classes = [
            WorkCostClass::Validation,
            WorkCostClass::Fuzzing,
            WorkCostClass::Benchmark,
            WorkCostClass::DocsGate,
            WorkCostClass::SourceOnly,
            WorkCostClass::Cleanup,
        ];
        let work_class = *work_classes
            .get(work_class_idx)
            .expect("generated work class index stays in range");
        let inputs = WorkspacePressureInputs {
            free_disk_bytes,
            target_dir_bytes,
            active_build_count,
            rch_available_slots,
            memory_pressure,
            active_reservations,
            coordination_healthy: active_reservations < 128,
        };

        let decision =
            WorkspacePressurePolicy::with_balanced_defaults().decide_admission(
                work_class,
                priority,
                &inputs,
            );

        proptest::prop_assert!(decision.confidence.is_finite());
        proptest::prop_assert!((0.0..=1.0).contains(&decision.confidence));
        proptest::prop_assert!(!decision.reason_code.trim().is_empty());
        proptest::prop_assert!(!decision.summary.trim().is_empty());
        proptest::prop_assert!(
            decision.diagnostic_reasons.len() <= MAX_POLICY_DIAGNOSTIC_REASONS_WITH_TRUNCATION
        );
        proptest::prop_assert!(decision.cleanup_candidates.len() <= 2);

        if work_class.prefers_rch()
            && work_class.cost_weight() > 7
            && inputs.rch_available_slots.is_none()
        {
            let queued_or_refused = matches!(
                decision.admission,
                AdmissionDecision::Queue { .. } | AdmissionDecision::RefuseLocalFallback
            );
            proptest::prop_assert!(queued_or_refused);
        }
    }
}

#[test]
fn agent_command_budget_ledger_empty_and_entry_cap_are_stable() {
    let empty = AgentCommandBudgetLedger::try_new(
        "session-empty",
        "CalmSnow",
        Some("bd-38hez.4".to_string()),
        Vec::new(),
    )
    .expect("empty ledger should validate");

    assert_eq!(empty.schema_version, AGENT_COMMAND_LEDGER_SCHEMA_VERSION);
    assert_eq!(empty.summary.command_count, 0);
    assert_eq!(empty.summary.policy_violation_count, 0);

    let encoded = serde_json::to_value(&empty).expect("ledger should serialize");
    assert_eq!(
        encoded["schema_version"],
        "franken-node/agent-command-ledger/v1"
    );
    assert_eq!(encoded["summary"]["command_count"], 0);

    let entries = (0..=MAX_AGENT_COMMAND_LEDGER_ENTRIES)
        .map(|idx| {
            AgentCommandBudgetEntry::new(
                format!("cmd-{idx}"),
                AgentCommandFamily::SourceOnly,
                AgentCommandCostClass::SourceOnly,
                AgentCommandExecutionPolicy::SourceOnly,
                "ubs crates/franken-node/src/ops/workspace_pressure_policy.rs",
            )
        })
        .collect();

    let err = AgentCommandBudgetLedger::try_new("session-cap", "CalmSnow", None, entries)
        .expect_err("entry cap should fail closed");

    assert_eq!(
        err,
        AgentCommandLedgerError::TooManyEntries {
            count: MAX_AGENT_COMMAND_LEDGER_ENTRIES + 1,
            max: MAX_AGENT_COMMAND_LEDGER_ENTRIES
        }
    );
}

#[test]
fn agent_command_budget_ledger_flags_bare_cargo_and_preserves_rch_proof() {
    let bare_cargo = AgentCommandBudgetEntry::new(
        "cmd-bare-cargo",
        AgentCommandFamily::Cargo,
        AgentCommandCostClass::LocalCpuSensitive,
        AgentCommandExecutionPolicy::LocalAllowed,
        "cargo test -p frankenengine-node",
    )
    .with_touched_paths(["crates/franken-node/src/lib.rs"]);

    let bare_ledger = AgentCommandBudgetLedger::try_new(
        "session-bare-cargo",
        "CalmSnow",
        Some("bd-38hez.4".to_string()),
        vec![bare_cargo],
    )
    .expect("bare cargo ledger should validate with derived violations");

    let bare_entry = bare_ledger.entries.first().expect("bare cargo entry");
    assert!(
        bare_entry
            .violations
            .contains(&AgentCommandPolicyViolation::BareCargo)
    );
    assert!(
        bare_entry
            .violations
            .contains(&AgentCommandPolicyViolation::MissingRchForCargo)
    );
    assert!(
        bare_entry
            .violations
            .contains(&AgentCommandPolicyViolation::UnreservedCodeEdit)
    );
    assert_eq!(bare_ledger.summary.commands_with_violations, 1);
    assert_eq!(bare_ledger.summary.policy_violation_count, 3);

    let rch_proof = AgentCommandBudgetEntry::new(
        "cmd-rch-cargo",
        AgentCommandFamily::Cargo,
        AgentCommandCostClass::RchRemote,
        AgentCommandExecutionPolicy::RchRequired,
        "rch exec -- cargo test -p frankenengine-node validation_planner",
    )
    .with_elapsed_ms(42_000)
    .with_target_dir(".rch-target-vmi1167313-job")
    .with_touched_paths(["crates/franken-node/src/ops/workspace_pressure_policy.rs"])
    .with_reservation_refs(["agent-mail-reservation-17248"])
    .with_evidence_links(["rch://29833915539653001"])
    .with_validation_outcome(AgentCommandValidationOutcome::Passed);

    let rch_ledger = AgentCommandBudgetLedger::try_new(
        "session-rch",
        "CalmSnow",
        Some("bd-38hez.4".to_string()),
        vec![rch_proof],
    )
    .expect("rch proof ledger should validate");

    assert!(
        rch_ledger
            .entries
            .first()
            .expect("rch entry")
            .violations
            .is_empty()
    );
    assert_eq!(rch_ledger.summary.rch_submissions, 1);
    assert_eq!(rch_ledger.summary.validation_passed, 1);
    assert_eq!(rch_ledger.summary.policy_violation_count, 0);
}

#[test]
fn agent_command_budget_ledger_allows_source_only_and_redacts_protected_values() {
    let source_only = AgentCommandBudgetEntry::new(
        "cmd-ubs",
        AgentCommandFamily::Ubs,
        AgentCommandCostClass::SourceOnly,
        AgentCommandExecutionPolicy::SourceOnly,
        "UBS_SKIP_RUST_BUILD=1 ubs crates/franken-node/src/ops/workspace_pressure_policy.rs",
    )
    .with_touched_paths(["docs/specs/validation_closeout.md"])
    .with_validation_outcome(AgentCommandValidationOutcome::Passed);

    let source_ledger =
        AgentCommandBudgetLedger::try_new("session-source", "CalmSnow", None, vec![source_only])
            .expect("source-only ledger should validate");

    assert!(
        source_ledger
            .entries
            .first()
            .expect("source-only entry")
            .violations
            .is_empty()
    );
    assert_eq!(source_ledger.summary.command_count, 1);
    assert_eq!(source_ledger.summary.validation_passed, 1);

    let secret_command = AgentCommandBudgetEntry::new(
        "cmd-redact",
        AgentCommandFamily::AgentMail,
        AgentCommandCostClass::Coordination,
        AgentCommandExecutionPolicy::CoordinationOnly,
        "send_message SECRET_TOKEN=raw --password hunter2 --api-key=abcdef",
    );

    let redacted =
        AgentCommandBudgetLedger::try_new("session-redact", "CalmSnow", None, vec![secret_command])
            .expect("redacted ledger should validate");
    let summary = &redacted
        .entries
        .first()
        .expect("redacted entry")
        .command_summary;

    assert!(!summary.contains("raw"));
    assert!(!summary.contains("hunter2"));
    assert!(!summary.contains("abcdef"));
    assert!(summary.contains("SECRET_TOKEN=<redacted>"));
    assert!(summary.contains("--password <redacted>"));
    assert!(summary.contains("--api-key=<redacted>"));
}

#[test]
fn agent_command_budget_ledger_human_summary_is_stable() {
    let ledger = AgentCommandBudgetLedger::try_new(
        "session-human",
        "CalmSnow",
        Some("bd-38hez.4".to_string()),
        vec![
            AgentCommandBudgetEntry::new(
                "cmd-human",
                AgentCommandFamily::Cargo,
                AgentCommandCostClass::LocalCpuSensitive,
                AgentCommandExecutionPolicy::LocalAllowed,
                "cargo test -p frankenengine-node",
            )
            .with_touched_paths(["crates/franken-node/src/lib.rs"]),
        ],
    )
    .expect("ledger should validate");

    let rendered = render_agent_command_ledger_human(&ledger);

    assert!(rendered.contains("session=session-human"));
    assert!(rendered.contains("agent=CalmSnow"));
    assert!(rendered.contains("bead=bd-38hez.4"));
    assert!(rendered.contains("commands=1"));
    assert!(rendered.contains("policy_violations=3"));
}

#[test]
fn operator_what_if_fixture_replay_is_deterministic_and_safe() -> Result<(), String> {
    let fixture: OperatorWhatIfFixture = serde_json::from_str(OPERATOR_WHAT_IF_FIXTURES)
        .map_err(|err| format!("what-if fixtures should parse: {err}"))?;
    assert_eq!(
        fixture.schema_version,
        "franken-node/operator-what-if-fixtures/v1"
    );
    assert_eq!(fixture.scenarios.len(), 9);

    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let mut names = BTreeSet::new();

    for scenario in &fixture.scenarios {
        assert!(names.insert(scenario.name.as_str()));
        let input = OperatorWhatIfInput {
            scenario_id: scenario.name.clone(),
            bead_id: Some(scenario.bead_id.clone()),
            work_class: scenario.work_class,
            bead_priority: scenario.bead_priority,
            requested_command: Some(scenario.requested_command.clone()),
            workspace: scenario.workspace.clone(),
            rch_queue: scenario.rch_queue.clone(),
            artifacts: scenario.artifacts.clone(),
            command_ledger: scenario
                .ledger_kind
                .as_deref()
                .map(operator_what_if_fixture_ledger)
                .transpose()?,
            stale_sibling_blocker: scenario.stale_sibling_blocker.clone(),
        };

        let report = policy.simulate_operator_what_if(input);
        assert_eq!(report.schema_version, OPERATOR_WHAT_IF_SCHEMA_VERSION);
        assert_eq!(
            report.action, scenario.expected_action,
            "{} action drifted",
            scenario.name
        );
        assert_eq!(
            report.reason_code, scenario.expected_reason_code,
            "{} reason code drifted",
            scenario.name
        );
        if let Some(prefix) = &scenario.expected_command_prefix {
            let command = report
                .simulated_command
                .as_deref()
                .expect("scenario expected simulated command");
            assert!(
                command.starts_with(prefix),
                "{} simulated command should start with `{}` but got `{}`",
                scenario.name,
                prefix,
                command
            );
        }
        assert_eq!(
            report.cleanup_actions.len(),
            scenario.expected_cleanup_actions,
            "{} cleanup action count drifted",
            scenario.name
        );
        assert_eq!(
            report.pinned_artifact_count, scenario.expected_pinned_artifacts,
            "{} pinned count drifted",
            scenario.name
        );
        assert_eq!(
            report.protected_artifact_count, scenario.expected_protected_artifacts,
            "{} protected count drifted",
            scenario.name
        );

        let blocked_paths = scenario
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.safety_class != OperatorWhatIfArtifactSafetyClass::CleanupEligible
            })
            .map(|artifact| artifact.path.as_str())
            .collect::<BTreeSet<_>>();
        assert!(
            report
                .cleanup_actions
                .iter()
                .all(|action| !blocked_paths.contains(action.path.as_str())),
            "{} protected or pinned artifact became a cleanup action",
            scenario.name
        );
        assert!(
            report
                .logs
                .iter()
                .any(|log| log.event_code == scenario.expected_log_event),
            "{} did not emit expected event {}",
            scenario.name,
            scenario.expected_log_event
        );
        assert!(report.human_summary.contains(&scenario.name));
        if scenario.expected_reason_code == "VAL_DEFER_RCH_STALE" {
            let stale_progress = report
                .rch_stale_progress
                .as_ref()
                .expect("stale-progress scenario should carry RCH build evidence");
            assert_eq!(stale_progress.active_builds.len(), 1);
            let build = &stale_progress.active_builds[0];
            assert_eq!(build.build_id, "29893806476230668");
            assert_eq!(build.worker_id, "vmi1152480");
            assert!(build.heartbeat_fresh);
            assert!(build.progress_stale);
            assert!(
                report
                    .human_summary
                    .contains("29893806476230668@vmi1152480")
            );
            assert!(
                report
                    .human_summary
                    .contains("Do not enqueue additional heavy cargo work")
            );
            assert!(
                stale_progress
                    .safe_next_action
                    .contains("cancel only a build you own")
            );
        } else {
            assert!(
                report.rch_stale_progress.is_none(),
                "{} unexpectedly carried stale RCH progress",
                scenario.name
            );
        }
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("what-if report should serialize: {err}"))?;
    }

    Ok(())
}

#[test]
fn no_ready_autopilot_creates_planning_bead_when_ready_empty_clean() {
    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let receipt = policy.plan_no_ready_autopilot(no_ready_base_input("no-ready-clean"));

    assert_eq!(receipt.schema_version, NO_READY_AUTOPILOT_SCHEMA_VERSION);
    assert_eq!(
        receipt.selected_action,
        NoReadyAutopilotAction::CreatePlanningBead
    );
    assert_eq!(receipt.reason_code, "NO_READY_CREATE_PLANNING_BEAD");
    assert_eq!(receipt.ready_issue_count, 0);
    assert!(receipt.human_summary.contains("ready=0"));
    assert!(
        receipt
            .pasteable_beads_note
            .contains("last_ready_command=br ready --json")
    );
    assert!(no_ready_rejected_contains(
        &receipt.rejected_alternatives,
        NoReadyAutopilotAction::UseReadyWork
    ));

    let encoded = serde_json::to_value(&receipt).expect("no-ready receipt serializes");
    assert_eq!(
        encoded["selected_action"],
        json!(NoReadyAutopilotAction::CreatePlanningBead)
    );
}

#[test]
fn no_ready_autopilot_refreshes_stale_in_progress_before_new_work() {
    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let mut input = no_ready_base_input("no-ready-stale-in-progress");
    input.in_progress_beads.push(NoReadyInProgressBead {
        bead_id: "bd-stale.1".to_string(),
        assignee: "NavyTurtle".to_string(),
        updated_age_secs: 7_200,
        status_summary: "claimed without validation update".to_string(),
        reserved_paths: vec!["crates/franken-node/src/lib.rs".to_string()],
    });

    let receipt = policy.plan_no_ready_autopilot(input);

    assert_eq!(
        receipt.selected_action,
        NoReadyAutopilotAction::RefreshStaleInProgress
    );
    assert_eq!(receipt.reason_code, "NO_READY_REFRESH_STALE_IN_PROGRESS");
    assert_eq!(receipt.stale_in_progress_beads.len(), 1);
    assert!(receipt.safe_next_action.contains("br show"));
    assert!(receipt.pasteable_beads_note.contains("bd-stale.1"));
    assert!(receipt.pasteable_beads_note.contains("NavyTurtle"));
    assert!(no_ready_rejected_contains(
        &receipt.rejected_alternatives,
        NoReadyAutopilotAction::CreatePlanningBead
    ));
}

#[test]
fn no_ready_autopilot_defers_for_rch_pressure_and_preserves_blocker_text() {
    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let mut input = no_ready_base_input("no-ready-rch-pressure");
    input
        .rch_queue
        .active_builds
        .push(OperatorWhatIfRchBuildState {
            build_id: "29893806476230671".to_string(),
            worker_id: "vmi1152480".to_string(),
            command: "cargo test -p frankenengine-node workspace_pressure_governance_e2e"
                .to_string(),
            heartbeat_fresh: true,
            progress_stale: true,
            progress_age_secs: Some(172),
        });
    input.blocked_beads.push(NoReadyBlockedBeadEvidence {
        bead_id: "bd-bf06i.2".to_string(),
        origin: NoReadyBlockerOrigin::BuildInfrastructure,
        owner: Some("LavenderTower".to_string()),
        sibling_project: None,
        blocker_command:
            "rch exec -- cargo test -p frankenengine-node workspace_pressure_governance_e2e"
                .to_string(),
        first_blocker_line: "detector_progress_stale=true progress_age_secs=172".to_string(),
        notes: "RCH heartbeat remained fresh while progress stayed stale".to_string(),
    });

    let receipt = policy.plan_no_ready_autopilot(input);

    assert_eq!(
        receipt.selected_action,
        NoReadyAutopilotAction::DeferForRchPressure
    );
    assert_eq!(receipt.reason_code, "NO_READY_DEFER_RCH_STALE");
    assert!(
        receipt
            .rch_stale_progress
            .as_ref()
            .is_some_and(|progress| progress.active_builds.len() == 1)
    );
    assert!(
        receipt
            .human_summary
            .contains("29893806476230671@vmi1152480")
    );
    assert!(
        receipt
            .pasteable_beads_note
            .contains("rch exec -- cargo test -p frankenengine-node")
    );
    assert!(
        receipt
            .pasteable_beads_note
            .contains("detector_progress_stale=true progress_age_secs=172")
    );
    assert!(no_ready_rejected_contains(
        &receipt.rejected_alternatives,
        NoReadyAutopilotAction::RefreshBlockedEvidence
    ));
}

#[test]
fn no_ready_autopilot_handoffs_cross_repo_blockers_without_optimism() {
    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let mut input = no_ready_base_input("no-ready-cross-repo");
    input.blocked_beads.push(NoReadyBlockedBeadEvidence {
        bead_id: "bd-f5b04.2.6".to_string(),
        origin: NoReadyBlockerOrigin::SiblingRepository,
        owner: Some("NavyTurtle".to_string()),
        sibling_project: Some("/data/projects/franken_engine".to_string()),
        blocker_command: "rch exec -- cargo test -p frankenengine-engine data_contract".to_string(),
        first_blocker_line: "HostIoProvider proof missing from committed franken_engine head"
            .to_string(),
        notes: "franken_node must wait for a committed sibling revision".to_string(),
    });

    let receipt = policy.plan_no_ready_autopilot(input);

    assert_eq!(
        receipt.selected_action,
        NoReadyAutopilotAction::HandoffCrossRepoBlocker
    );
    assert_eq!(receipt.reason_code, "NO_READY_HANDOFF_CROSS_REPO");
    assert!(
        receipt
            .safe_next_action
            .contains("/data/projects/franken_engine")
    );
    assert!(receipt.pasteable_beads_note.contains("bd-f5b04.2.6"));
    assert!(
        receipt
            .pasteable_beads_note
            .contains("HostIoProvider proof missing")
    );
    assert!(no_ready_rejected_contains(
        &receipt.rejected_alternatives,
        NoReadyAutopilotAction::CreatePlanningBead
    ));
}

#[test]
fn cross_repo_blocker_envelope_allows_retry_only_after_required_commit() {
    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let input = host_io_provider_blocker_input(true, Some("fe-hostio-2026-06-18T21-commit-a1"));

    let envelope = policy.build_cross_repo_blocker_envelope(input);
    let rendered = serde_json::to_value(&envelope).expect("envelope serializes");

    assert_eq!(
        envelope.schema_version,
        CROSS_REPO_BLOCKER_ENVELOPE_SCHEMA_VERSION
    );
    assert_eq!(envelope.reason_code, "XREPO_BLOCKER_COMMITTED_READY");
    assert!(envelope.retry_validation_allowed);
    assert!(envelope.sufficient_to_unblock);
    assert!(!envelope.beads_status_change_allowed);
    assert_eq!(rendered["sibling_project"], "/data/projects/franken_engine");
    assert_eq!(rendered["sibling_bead_id"], "bd-f5b04.2.6");
    assert_eq!(rendered["agent_mail_thread_id"], "bd-f5b04.2.6");
    assert_eq!(rendered["agent_mail_message_id"], "37");
    assert_eq!(rendered["rch_build_id"], "29893806476230674");
    assert_eq!(
        rendered["required_committed_revision"],
        "fe-hostio-2026-06-18T21-commit-a1"
    );
    assert!(
        envelope
            .safe_next_action
            .contains("do not close or unblock until validation passes")
    );
    assert!(
        envelope
            .pasteable_beads_note
            .contains("beads_status_change_allowed=false")
    );
    assert!(
        envelope
            .agent_mail_handoff_body
            .contains("HostIoProvider proof missing")
    );
    assert!(envelope.human_summary.contains("NavyTurtle"));
    assert!(
        envelope
            .human_summary
            .contains("/data/projects/franken_engine")
    );
}

#[test]
fn cross_repo_blocker_envelope_rejects_uncommitted_evidence_as_unblock_proof() {
    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let input = host_io_provider_blocker_input(false, Some("working-tree-hostio-proof"));

    let envelope = policy.build_cross_repo_blocker_envelope(input);

    assert_eq!(envelope.reason_code, "XREPO_BLOCKER_UNCOMMITTED_EVIDENCE");
    assert!(!envelope.retry_validation_allowed);
    assert!(!envelope.sufficient_to_unblock);
    assert!(!envelope.beads_status_change_allowed);
    assert!(
        envelope
            .safe_next_action
            .contains("commit the required evidence revision")
    );
    assert!(
        envelope
            .pasteable_beads_note
            .contains("observed_revision_committed=false")
    );
    assert!(
        envelope
            .pasteable_beads_note
            .contains("sufficient_to_unblock=false")
    );
    assert!(
        envelope
            .agent_mail_handoff_body
            .contains("retry_validation_allowed=false")
    );
    assert!(
        envelope
            .human_summary
            .contains("beads_status_change_allowed=false")
    );
}

#[test]
fn cross_repo_blocker_envelope_preserves_external_rch_blocker_metadata() {
    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let input = CrossRepoBlockerEnvelopeInput {
        envelope_id: "xrepo-rch-stale-29893806476230674".to_string(),
        franken_node_bead_id: "bd-bf06i.3".to_string(),
        blocker_origin: NoReadyBlockerOrigin::BuildInfrastructure,
        next_owner: "LavenderTower".to_string(),
        sibling_project: None,
        sibling_bead_id: None,
        agent_mail_thread_id: Some("bd-bf06i.3".to_string()),
        agent_mail_message_id: None,
        rch_build_id: Some("29893806476230674".to_string()),
        required_committed_revision: "rch-worker-progress-fresh".to_string(),
        observed_revision: Some("rch-worker-progress-fresh".to_string()),
        observed_revision_committed: true,
        validation_command:
            "rch exec -- cargo test -p frankenengine-node --test workspace_pressure_governance_e2e no_ready_autopilot"
                .to_string(),
        first_blocker_line:
            "detector_progress_stale=true progress_age_secs=209 heartbeat_age_secs=4"
                .to_string(),
    };

    let envelope = policy.build_cross_repo_blocker_envelope(input);

    assert_eq!(envelope.reason_code, "XREPO_BLOCKER_BUILD_READY");
    assert!(envelope.retry_validation_allowed);
    assert_eq!(envelope.rch_build_id.as_deref(), Some("29893806476230674"));
    assert!(
        envelope
            .pasteable_beads_note
            .contains("rch_build_id=29893806476230674")
    );
    assert!(
        envelope
            .agent_mail_handoff_body
            .contains("detector_progress_stale=true")
    );
}

fn host_io_provider_blocker_input(
    observed_revision_committed: bool,
    observed_revision: Option<&str>,
) -> CrossRepoBlockerEnvelopeInput {
    CrossRepoBlockerEnvelopeInput {
        envelope_id: "xrepo-bd-f5b04-2-6-hostio-provider".to_string(),
        franken_node_bead_id: "bd-bf06i.4".to_string(),
        blocker_origin: NoReadyBlockerOrigin::SiblingRepository,
        next_owner: "NavyTurtle".to_string(),
        sibling_project: Some("/data/projects/franken_engine".to_string()),
        sibling_bead_id: Some("bd-f5b04.2.6".to_string()),
        agent_mail_thread_id: Some("bd-f5b04.2.6".to_string()),
        agent_mail_message_id: Some("37".to_string()),
        rch_build_id: Some("29893806476230674".to_string()),
        required_committed_revision: "fe-hostio-2026-06-18T21-commit-a1".to_string(),
        observed_revision: observed_revision.map(str::to_string),
        observed_revision_committed,
        validation_command:
            "rch exec -- cargo test -p frankenengine-node --test workspace_pressure_governance_e2e cross_repo_blocker"
                .to_string(),
        first_blocker_line:
            "HostIoProvider proof missing from committed franken_engine head".to_string(),
    }
}

fn no_ready_base_input(receipt_id: &str) -> NoReadyAutopilotInput {
    NoReadyAutopilotInput {
        receipt_id: receipt_id.to_string(),
        workspace_root: REPO_KEY.to_string(),
        ready_issue_count: 0,
        open_issue_count: 5,
        blocked_issue_count: 2,
        in_progress_beads: Vec::new(),
        blocked_beads: Vec::new(),
        rch_queue: OperatorWhatIfRchQueueState {
            available_slots: Some(8),
            queued_jobs: 0,
            degraded_workers: 0,
            local_fallback_allowed: false,
            active_builds: Vec::new(),
        },
        last_ready_command: Some("br ready --json".to_string()),
        idea_wizard_allowed: true,
    }
}

fn no_ready_rejected_contains(
    alternatives: &[NoReadyAutopilotRejectedAlternative],
    action: NoReadyAutopilotAction,
) -> bool {
    alternatives
        .iter()
        .any(|alternative| alternative.action == action)
}

fn operator_what_if_fixture_ledger(kind: &str) -> Result<AgentCommandBudgetLedger, String> {
    match kind {
        "clean_rch" => AgentCommandBudgetLedger::try_new(
            "session-what-if-rch",
            "CalmSnow",
            Some("bd-38hez.6".to_string()),
            vec![
                AgentCommandBudgetEntry::new(
                    "cmd-rch-proof",
                    AgentCommandFamily::Cargo,
                    AgentCommandCostClass::RchRemote,
                    AgentCommandExecutionPolicy::RchRequired,
                    "rch exec -- cargo test -p frankenengine-node workspace_pressure_governance_e2e",
                )
                .with_target_dir("/data/tmp/franken_node-what-if-target")
                .with_touched_paths(["crates/franken-node/tests/workspace_pressure_governance_e2e.rs"])
                .with_reservation_refs(["agent-mail-reservation-17314"])
                .with_validation_outcome(AgentCommandValidationOutcome::Passed),
            ],
        )
        .map_err(|err| format!("clean rch ledger should validate: {err}")),
        "bare_cargo" => AgentCommandBudgetLedger::try_new(
            "session-what-if-bare",
            "CalmSnow",
            Some("bd-38hez.6".to_string()),
            vec![AgentCommandBudgetEntry::new(
                "cmd-bare-cargo",
                AgentCommandFamily::Cargo,
                AgentCommandCostClass::LocalCpuSensitive,
                AgentCommandExecutionPolicy::LocalAllowed,
                "cargo test -p frankenengine-node workspace_pressure_governance_e2e",
            )
            .with_touched_paths(["crates/franken-node/tests/workspace_pressure_governance_e2e.rs"])],
        )
        .map_err(|err| format!("bare cargo ledger should validate: {err}")),
        other => Err(format!("unknown what-if ledger kind: {other}")),
    }
}

struct RealWorkspace {
    root: TempDir,
    coordination_db_path: PathBuf,
    eligible_paths: Vec<PathBuf>,
    pinned_paths: Vec<PathBuf>,
    protected_paths: Vec<PathBuf>,
}

impl RealWorkspace {
    fn materialize(name: &str) -> Self {
        let root = TempDir::new_in(".").expect("create real workspace tempdir");
        let root_path = root.path();
        let coordination_db_path =
            create_real_coordination_db(root_path.join(".beads/beads.db"), name);

        let protected_paths = vec![
            write_bytes(root_path.join("src/lib.rs"), b"pub fn real_source() {}\n"),
            write_bytes(root_path.join("docs/spec.md"), b"# operator docs\n"),
            write_bytes(root_path.join("scripts/check.sh"), b"#!/bin/sh\nexit 0\n"),
            coordination_db_path.clone(),
            write_bytes(root_path.join("agents/RedGlen/inbox.json"), b"[]\n"),
            write_bytes(
                root_path.join("logs/session.log"),
                b"build log must remain protected\n",
            ),
            write_bytes(
                root_path.join("memory/session.jsonl"),
                b"{\"kind\":\"session\"}\n",
            ),
        ];

        let eligible_paths = vec![
            write_sparse(
                root_path.join("target/debug/incremental/stale-object.o"),
                SPARSE_EIGHT_GIB,
            ),
            write_sparse(
                root_path.join("target-rch-stale/debug/build/out.bin"),
                SPARSE_ONE_GIB,
            ),
        ];
        let pinned_paths = vec![write_sparse(
            root_path.join("target/pinned/do-not-clean.rlib"),
            SPARSE_FOUR_GIB,
        )];
        write_bytes(
            root_path.join(".franken-node/pins/workspace-pressure-pin.json"),
            format!(
                "{{\"scenario\":\"{}\",\"path\":\"{}\"}}\n",
                name,
                pinned_paths[0].display()
            )
            .as_bytes(),
        );

        Self {
            root,
            coordination_db_path,
            eligible_paths,
            pinned_paths,
            protected_paths,
        }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn target_dir_bytes(&self) -> u64 {
        self.eligible_paths
            .iter()
            .chain(self.pinned_paths.iter())
            .filter_map(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .sum()
    }

    fn inventory_entries(&self) -> Vec<ResourceArtifactInventoryEntry> {
        let mut entries = Vec::new();
        for path in &self.eligible_paths {
            entries.push(
                ResourceArtifactInventoryEntry::new(
                    path.display().to_string(),
                    REPO_KEY,
                    artifact_kind_for_path(path),
                    ResourceArtifactSafetyClass::RebuildableBuildOutput,
                    file_len(path),
                )
                .with_open_file_status(ResourceArtifactOpenFileStatus::NotOpen),
            );
        }
        for path in &self.pinned_paths {
            entries.push(
                ResourceArtifactInventoryEntry::new(
                    path.display().to_string(),
                    REPO_KEY,
                    ResourceArtifactKind::CargoTargetDir,
                    ResourceArtifactSafetyClass::RebuildableBuildOutput,
                    file_len(path),
                )
                .with_open_file_status(ResourceArtifactOpenFileStatus::NotOpen)
                .with_pin(ResourceArtifactPin {
                    reason: "active validation proof still owns artifact".to_string(),
                    owner_agent: Some("RedGlen".to_string()),
                    bead_id: Some("bd-p9mpd.6".to_string()),
                    expires_at: None,
                }),
            );
        }
        for path in &self.protected_paths {
            entries.push(ResourceArtifactInventoryEntry::new(
                path.display().to_string(),
                REPO_KEY,
                ResourceArtifactKind::Unknown,
                safety_class_for_path(path),
                file_len(path),
            ));
        }
        entries
    }

    fn append_assertion_log(&self, payload: Value) {
        let path = self.root().join("logs/bd-p9mpd.6.assertions.jsonl");
        fs::create_dir_all(path.parent().expect("log parent")).expect("create log parent");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open assertion log");
        writeln!(
            file,
            "{}",
            serde_json::to_string(&payload).expect("serialize log")
        )
        .expect("write assertion log");
    }

    fn assert_assertion_log_is_jsonl(&self) {
        let path = self.root().join("logs/bd-p9mpd.6.assertions.jsonl");
        let raw = fs::read_to_string(path).expect("read assertion log");
        assert!(!raw.trim().is_empty());
        for line in raw.lines() {
            let event: Value = serde_json::from_str(line).expect("assertion log line is json");
            assert_eq!(event["schema_version"], "bd-p9mpd.6/assertion-log/v1");
            assert!(event["trace_id"].as_str().is_some());
            assert!(event["phase"].as_str().is_some());
            assert!(event["assertion"].as_str().is_some());
        }
    }
}

fn assert_cleanup_candidates_are_safe(candidates: &[&ResourceArtifactInventoryEntry]) {
    for candidate in candidates {
        assert!(
            !is_protected_path(&candidate.path),
            "cleanup candidate must not be protected: {}",
            candidate.path
        );
        assert!(
            candidate.pin.is_none(),
            "pinned artifact was cleanup eligible"
        );
        assert_eq!(
            candidate.open_file_status,
            ResourceArtifactOpenFileStatus::NotOpen
        );
    }
}

fn assert_protected_paths_remain_non_cleanup(inventory: &ResourceArtifactInventory) {
    for entry in &inventory.entries {
        if is_protected_path(&entry.path) || entry.pin.is_some() {
            assert!(
                !entry.cleanup_eligible,
                "protected or pinned path became cleanup eligible: {}",
                entry.path
            );
        }
    }
}

fn is_protected_path(path: &str) -> bool {
    path.contains("/src/")
        || path.contains("/docs/")
        || path.contains("/scripts/")
        || path.contains("/.beads/")
        || path.contains("/agents/")
        || path.contains("/logs/")
        || path.contains("/memory/")
        || path.contains("/memories/")
        || path.contains("/sessions/")
}

fn write_bytes(path: PathBuf, contents: &[u8]) -> PathBuf {
    fs::create_dir_all(path.parent().expect("file parent")).expect("create parent");
    fs::write(&path, contents).expect("write file");
    path
}

fn write_reservation_fixture(dir: &Path, name: &str, expires_ts: &str, released_ts: Option<&str>) {
    let payload = json!({
        "id": name,
        "project": REPO_KEY,
        "agent": "TestAgent",
        "path_pattern": "crates/franken-node/src/main.rs",
        "exclusive": true,
        "reason": "test",
        "created_ts": chrono::Utc::now().to_rfc3339(),
        "expires_ts": expires_ts,
        "released_ts": released_ts,
    });

    fs::write(
        dir.join(format!("{name}.json")),
        serde_json::to_vec_pretty(&payload).expect("serialize reservation fixture"),
    )
    .expect("write reservation fixture");
}

fn write_sparse(path: PathBuf, len: u64) -> PathBuf {
    fs::create_dir_all(path.parent().expect("sparse parent")).expect("create sparse parent");
    let file = fs::File::create(&path).expect("create sparse artifact");
    file.set_len(len).expect("size sparse artifact");
    path
}

fn create_real_coordination_db(path: PathBuf, scenario: &str) -> PathBuf {
    fs::create_dir_all(path.parent().expect("db parent")).expect("create db parent");
    let db_path = path.to_string_lossy().into_owned();
    let connection = Connection::open(&db_path).expect("open real coordination db");
    connection
        .execute(
            "CREATE TABLE pressure_governance_events (
                id INTEGER PRIMARY KEY,
                scenario TEXT NOT NULL,
                phase TEXT NOT NULL
            );",
        )
        .expect("create pressure governance table");
    connection
        .execute_with_params(
            "INSERT INTO pressure_governance_events (scenario, phase) VALUES (?1, ?2);",
            &[
                SqliteValue::Text(scenario.to_string().into()),
                SqliteValue::Text("committed".into()),
            ],
        )
        .expect("insert committed coordination state");
    assert_eq!(query_coordination_event_count(&connection), Some(1));

    let mut transaction = connection
        .transaction()
        .expect("begin rollback transaction");
    transaction
        .execute_with_params(
            "INSERT INTO pressure_governance_events (scenario, phase) VALUES (?1, ?2);",
            &[
                SqliteValue::Text(scenario.to_string().into()),
                SqliteValue::Text("transient-validation".into()),
            ],
        )
        .expect("insert transient coordination state");
    let in_transaction_row = transaction
        .query_row("SELECT COUNT(*) FROM pressure_governance_events;")
        .expect("query count inside rollback transaction");
    assert_eq!(
        single_integer(in_transaction_row.values()),
        Some(2),
        "transaction event count should include transient row"
    );
    transaction
        .rollback()
        .expect("rollback transient coordination state");

    assert_eq!(query_coordination_event_count(&connection), Some(1));
    path
}

fn query_coordination_event_count(connection: &Connection) -> Option<i64> {
    let row = connection
        .query_row("SELECT COUNT(*) FROM pressure_governance_events;")
        .expect("query coordination event count");
    single_integer(row.values())
}

fn single_integer(values: &[SqliteValue]) -> Option<i64> {
    match values {
        [SqliteValue::Integer(value)] => Some(*value),
        _ => None,
    }
}

fn file_len(path: &Path) -> Option<u64> {
    fs::metadata(path).ok().map(|metadata| metadata.len())
}

fn artifact_kind_for_path(path: &Path) -> ResourceArtifactKind {
    if path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|part| part.contains("rch"))
    }) {
        ResourceArtifactKind::RchTargetDir
    } else {
        ResourceArtifactKind::CargoTargetDir
    }
}

fn safety_class_for_path(path: &Path) -> ResourceArtifactSafetyClass {
    let path = path.to_string_lossy();
    if path.contains("/.beads/") || path.contains("/agents/") {
        ResourceArtifactSafetyClass::BeadsMailNeverDelete
    } else if path.contains("/logs/") || path.contains("/memory/") {
        ResourceArtifactSafetyClass::LogsSessionHistoryNeverDelete
    } else {
        ResourceArtifactSafetyClass::SourceNeverDelete
    }
}

fn parse_work_class(name: &str) -> Option<WorkCostClass> {
    match name {
        "Validation" => Some(WorkCostClass::Validation),
        "Fuzzing" => Some(WorkCostClass::Fuzzing),
        "Benchmark" => Some(WorkCostClass::Benchmark),
        "DocsGate" => Some(WorkCostClass::DocsGate),
        "SourceOnly" => Some(WorkCostClass::SourceOnly),
        "Cleanup" => Some(WorkCostClass::Cleanup),
        _ => None,
    }
}

fn admission_name(admission: &AdmissionDecision) -> &'static str {
    match admission {
        AdmissionDecision::AllowLocal => "AllowLocal",
        AdmissionDecision::RequireRch => "RequireRch",
        AdmissionDecision::Queue { .. } => "Queue",
        AdmissionDecision::Wait { .. } => "Wait",
        AdmissionDecision::RefuseLocalFallback => "RefuseLocalFallback",
    }
}

fn bytes_to_mib(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

fn policy_decision_golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(POLICY_DECISION_GOLDEN_RELATIVE_PATH)
}

fn build_policy_decision_golden() -> Value {
    let policy = WorkspacePressurePolicy::with_balanced_defaults();
    let work_types = policy_decision_work_types();
    let mut scenario_values = BTreeMap::new();
    let mut decision_matrix = Vec::new();

    for (scenario_name, inputs) in policy_decision_scenarios() {
        let mut work_decisions = BTreeMap::new();

        for (work_class, work_class_name, priority) in &work_types {
            let decision = policy.decide_admission(*work_class, *priority, &inputs);
            let cleanup_candidates = stable_cleanup_candidates(&decision);
            let has_cleanup_candidates = !cleanup_candidates.is_empty();
            let decision_value = json!({
                "admission": admission_name(&decision.admission),
                "cleanup_candidates": cleanup_candidates,
                "confidence": stable_f32_value(decision.confidence),
                "reason_code": decision.reason_code.as_str(),
            });

            decision_matrix.push(json!({
                "decision": admission_name(&decision.admission),
                "has_cleanup_candidates": has_cleanup_candidates,
                "priority": priority,
                "reason_code": decision.reason_code.as_str(),
                "scenario": scenario_name,
                "work_class": work_class_name,
            }));
            work_decisions.insert((*work_class_name).to_string(), decision_value);
        }

        scenario_values.insert(
            scenario_name.to_string(),
            json!({
                "inputs": stable_policy_inputs(&inputs),
                "work_decisions": work_decisions,
            }),
        );
    }

    json!({
        "decision_matrix": decision_matrix,
        "description": "Workspace pressure policy decision golden artifacts",
        "scenarios": scenario_values,
        "schema_version": POLICY_DECISION_GOLDEN_SCHEMA_VERSION,
    })
}

fn stable_policy_inputs(inputs: &WorkspacePressureInputs) -> BTreeMap<String, Value> {
    let mut value = BTreeMap::new();
    value.insert(
        "active_build_count".to_string(),
        json!(inputs.active_build_count),
    );
    value.insert(
        "active_reservations".to_string(),
        json!(inputs.active_reservations),
    );
    value.insert(
        "coordination_healthy".to_string(),
        json!(inputs.coordination_healthy),
    );
    value.insert("free_disk_bytes".to_string(), json!(inputs.free_disk_bytes));
    value.insert(
        "memory_pressure".to_string(),
        stable_f32_value(inputs.memory_pressure),
    );
    value.insert(
        "rch_available_slots".to_string(),
        json!(inputs.rch_available_slots),
    );
    value.insert(
        "target_dir_bytes".to_string(),
        json!(inputs.target_dir_bytes),
    );
    value
}

fn stable_f32_value(value: f32) -> Value {
    json!(((value as f64) * 100.0).round() / 100.0)
}

fn policy_decision_work_types() -> Vec<(WorkCostClass, &'static str, u32)> {
    vec![
        (WorkCostClass::SourceOnly, "SourceOnly", 2),
        (WorkCostClass::DocsGate, "DocsGate", 2),
        (WorkCostClass::Validation, "Validation", 1),
        (WorkCostClass::Benchmark, "Benchmark", 1),
        (WorkCostClass::Fuzzing, "Fuzzing", 1),
        (WorkCostClass::Cleanup, "Cleanup", 3),
    ]
}

fn policy_decision_scenarios() -> Vec<(&'static str, WorkspacePressureInputs)> {
    vec![
        (
            "healthy",
            WorkspacePressureInputs {
                free_disk_bytes: 5_000_000_000,
                target_dir_bytes: 1_000_000_000,
                active_build_count: 1,
                rch_available_slots: Some(8),
                memory_pressure: 0.3,
                active_reservations: 5,
                coordination_healthy: true,
            },
        ),
        (
            "disk_pressure",
            WorkspacePressureInputs {
                free_disk_bytes: 200_000_000,
                target_dir_bytes: 12_000_000_000,
                active_build_count: 2,
                rch_available_slots: Some(5),
                memory_pressure: 0.4,
                active_reservations: 10,
                coordination_healthy: true,
            },
        ),
        (
            "build_pressure",
            WorkspacePressureInputs {
                free_disk_bytes: 2_000_000_000,
                target_dir_bytes: 3_000_000_000,
                active_build_count: 8,
                rch_available_slots: Some(2),
                memory_pressure: 0.7,
                active_reservations: 15,
                coordination_healthy: true,
            },
        ),
        (
            "rch_unavailable",
            WorkspacePressureInputs {
                free_disk_bytes: 1_500_000_000,
                target_dir_bytes: 2_000_000_000,
                active_build_count: 3,
                rch_available_slots: None,
                memory_pressure: 0.6,
                active_reservations: 20,
                coordination_healthy: true,
            },
        ),
        (
            "coordination_degraded",
            WorkspacePressureInputs {
                free_disk_bytes: 1_000_000_000,
                target_dir_bytes: 4_000_000_000,
                active_build_count: 2,
                rch_available_slots: None,
                memory_pressure: 0.5,
                active_reservations: 60,
                coordination_healthy: false,
            },
        ),
        (
            "critical",
            WorkspacePressureInputs {
                free_disk_bytes: 50_000_000,
                target_dir_bytes: 15_000_000_000,
                active_build_count: 10,
                rch_available_slots: Some(0),
                memory_pressure: 0.95,
                active_reservations: 100,
                coordination_healthy: false,
            },
        ),
    ]
}

fn stable_cleanup_candidates(decision: &PolicyDecision) -> Vec<Value> {
    decision
        .cleanup_candidates
        .iter()
        .filter(|candidate| candidate.path == Path::new("target"))
        .map(|candidate| {
            json!({
                "path": candidate.path.display().to_string(),
                "reason": candidate.reason.as_str(),
                "size_bytes": candidate.size_bytes,
            })
        })
        .collect()
}

fn franken_node() -> Command {
    Command::cargo_bin("franken-node").expect("franken-node test binary")
}

fn relative_cli_path(path: &Path) -> String {
    let cwd = std::env::current_dir().expect("current dir");
    path.strip_prefix(&cwd)
        .unwrap_or(path)
        .to_str()
        .expect("utf8 path")
        .to_string()
}
