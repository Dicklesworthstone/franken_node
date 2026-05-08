use assert_cmd::Command;
use frankenengine_node::ops::workspace_pressure_policy::{
    AdmissionDecision, WorkCostClass, WorkspacePressureInputs, WorkspacePressurePolicy,
};
use frankenengine_node::runtime::resource_governor::{
    ResourceArtifactInventory, ResourceArtifactInventoryEntry, ResourceArtifactKind,
    ResourceArtifactOpenFileStatus, ResourceArtifactPin, ResourceArtifactSafetyClass,
    ResourceGovernorSnapshotInput, SnapshotProcessInput, reason_codes,
};
use fsqlite::compat::TransactionExt;
use fsqlite::{Connection, SqliteValue};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const GOLDEN: &str =
    include_str!("../../../artifacts/golden/workspace_pressure_governance_e2e.json");
const REPO_KEY: &str = "/data/projects/franken_node";
const SPARSE_EIGHT_GIB: u64 = 8 * 1024 * 1024 * 1024;
const SPARSE_FOUR_GIB: u64 = 4 * 1024 * 1024 * 1024;
const SPARSE_ONE_GIB: u64 = 1024 * 1024 * 1024;

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
        let Some(work_class) = parse_work_class(&scenario.work_class) else {
            assert!(false, "unknown work class: {}", scenario.work_class);
            continue;
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
