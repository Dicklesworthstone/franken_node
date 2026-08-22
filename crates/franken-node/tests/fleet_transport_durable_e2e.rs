//! Integration coverage for the durable frankensqlite fleet transport
//! (bd-reality-20260820-w0fc6.3).
//!
//! These tests live in a wired `[[test]]` target because `[lib] test = false`
//! keeps inline `#[cfg(test)]` suites out of `cargo test` (bd-rjc2m.21); the
//! durable transport is public API, so an integration target exercises it
//! without losing coverage.
//!
//! Durability model under test: `journal_mode=WAL` + `synchronous=FULL` means
//! every COMMITTED transaction survives process death. The crash scenario is
//! exercised as reopen-after-drop plus the cross-process abort case in
//! `crash_child_commits_survive_sigkill_style_abort`.

use std::time::Duration;

use chrono::Utc;
use frankenengine_node::control_plane::fleet_transport::{
    FleetAction, FleetActionRecord, FleetTargetKind, FleetTransport, NodeHealth, NodeStatus,
};
use frankenengine_node::control_plane::fleet_transport_durable::{
    DurableFleetTransport, count_active_quarantine_actions,
};

const FLEET_DB_FILE: &str = "fleet-state.db";
const FLEET_ACTION_LOG_FILE: &str = "actions.jsonl";

fn sample_action(action_id: &str, incident_id: &str) -> FleetActionRecord {
    FleetActionRecord {
        action_id: action_id.to_string(),
        emitted_at: Utc::now(),
        action: FleetAction::Quarantine {
            zone_id: "zone-a".to_string(),
            incident_id: incident_id.to_string(),
            target_id: "ext-1".to_string(),
            target_kind: FleetTargetKind::Extension,
            reason: "test".to_string(),
            quarantine_version: 1,
        },
    }
}

fn release_action(action_id: &str, incident_id: &str) -> FleetActionRecord {
    FleetActionRecord {
        action_id: action_id.to_string(),
        emitted_at: Utc::now(),
        action: FleetAction::Release {
            zone_id: "zone-a".to_string(),
            incident_id: incident_id.to_string(),
            reason: Some("test".to_string()),
        },
    }
}

fn sample_node(node_id: &str) -> NodeStatus {
    NodeStatus {
        zone_id: "zone-a".to_string(),
        node_id: node_id.to_string(),
        last_seen: Utc::now(),
        quarantine_version: 0,
        health: NodeHealth::Healthy,
    }
}

#[test]
fn writes_survive_reopen_and_read_back_in_contract_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("fleet");
    {
        let mut transport = DurableFleetTransport::new(&state_dir).expect("open");
        transport.initialize().expect("initialize");
        // Explicit distinct timestamps: the sort contract is chronological
        // (emitted_at, then action_id), so a-1 precedes a-2 by construction.
        let base = Utc::now();
        let mut first = sample_action("a-1", "inc-1");
        first.emitted_at = base;
        let mut second = sample_action("a-2", "inc-2");
        second.emitted_at = base + chrono::TimeDelta::try_seconds(1).expect("1s delta");
        transport.publish_action(&second).expect("publish a-2");
        transport.publish_action(&first).expect("publish a-1");
        transport
            .upsert_node_status(&sample_node("node-1"))
            .expect("upsert node");
    }

    let mut reopened = DurableFleetTransport::new(&state_dir).expect("reopen");
    reopened.initialize().expect("re-initialize is idempotent");
    let actions = reopened.list_actions().expect("list actions");
    assert_eq!(actions.len(), 2, "both actions survive reopen");
    assert_eq!(
        actions[0].action_id, "a-1",
        "chronological order: a-1 precedes a-2"
    );
    let nodes = reopened.list_node_statuses().expect("list nodes");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].node_id, "node-1");
    let state = reopened.read_shared_state().expect("shared state");
    assert_eq!(state.actions.len(), 2);
    assert_eq!(state.nodes.len(), 1);
}

#[test]
fn republishing_same_action_id_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
    transport.initialize().expect("initialize");
    transport
        .publish_action(&sample_action("a-1", "inc-1"))
        .expect("publish first");
    transport
        .publish_action(&sample_action("a-1", "inc-1"))
        .expect("republish same id");
    assert_eq!(transport.list_actions().expect("list").len(), 1);
}

#[test]
fn reads_fail_closed_before_initialize() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transport = DurableFleetTransport::new(dir.path()).expect("open");
    let err = transport
        .list_actions()
        .expect_err("uninitialized transport must fail closed");
    assert!(
        matches!(
            err,
            frankenengine_node::control_plane::fleet_transport::FleetTransportError::NotInitialized {
                ..
            }
        ),
        "expected NotInitialized, got {err:?}"
    );
}

#[test]
fn list_stale_nodes_filters_and_sorts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
    transport.initialize().expect("initialize");

    let mut stale_node = sample_node("node-stale");
    stale_node.last_seen = Utc::now() - chrono::TimeDelta::try_hours(2).expect("2h");
    let fresh_node = sample_node("node-fresh");
    transport
        .upsert_node_status(&stale_node)
        .expect("stale upsert");
    transport
        .upsert_node_status(&fresh_node)
        .expect("fresh upsert");

    let stale = transport
        .list_stale_nodes(Utc::now(), Duration::from_secs(3_600))
        .expect("stale list");
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].node_id, "node-stale");
}

#[test]
fn legacy_jsonl_layout_imports_once_and_rollback_restores_import() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("fleet");
    std::fs::create_dir_all(state_dir.join("nodes")).expect("nodes dir");

    let record = sample_action("legacy-1", "inc-legacy");
    std::fs::write(
        state_dir.join(FLEET_ACTION_LOG_FILE),
        format!("{}\n", serde_json::to_string(&record).expect("serialize")),
    )
    .expect("write legacy actions.jsonl");
    let node = sample_node("legacy-node");
    std::fs::write(
        state_dir.join("nodes").join("node-legacy-node.json"),
        serde_json::to_string_pretty(&node).expect("serialize node"),
    )
    .expect("write legacy node file");

    let mut transport = DurableFleetTransport::new(&state_dir).expect("open");
    transport.initialize().expect("initialize imports legacy");
    assert_eq!(transport.list_actions().expect("list").len(), 1);
    assert_eq!(transport.list_node_statuses().expect("nodes").len(), 1);

    // Re-initializing the SAME database must not double-import.
    transport.initialize().expect("second initialize");
    assert_eq!(transport.list_actions().expect("list").len(), 1);
    drop(transport);

    // Rollback = delete the database; the importer re-runs from JSONL.
    std::fs::remove_file(state_dir.join(FLEET_DB_FILE)).expect("remove db");
    let _ = std::fs::remove_file(state_dir.join(format!("{FLEET_DB_FILE}-wal")));
    let _ = std::fs::remove_file(state_dir.join(format!("{FLEET_DB_FILE}-shm")));
    let mut rolled_back = DurableFleetTransport::new(&state_dir).expect("reopen");
    rolled_back.initialize().expect("re-import after rollback");
    let actions = rolled_back.list_actions().expect("list");
    assert_eq!(actions.len(), 1, "legacy record restored exactly once");
    assert_eq!(actions[0].action_id, "legacy-1");
}

#[test]
fn quarantine_incident_count_matches_file_reader_semantics() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
    transport.initialize().expect("initialize");
    transport
        .publish_action(&sample_action("q-1", "inc-1"))
        .expect("quarantine inc-1");
    transport
        .publish_action(&sample_action("q-2", "inc-2"))
        .expect("quarantine inc-2");
    transport
        .publish_action(&release_action("r-1", "inc-1"))
        .expect("release inc-1");

    let count = count_active_quarantine_actions(dir.path()).expect("count from durable store");
    assert_eq!(count, 1, "only inc-2 remains active");

    // Missing database behaves like the missing actions.jsonl case: zero.
    let empty = tempfile::tempdir().expect("empty tempdir");
    assert_eq!(
        count_active_quarantine_actions(empty.path()).expect("missing db"),
        0
    );
}

/// Env-var guard so the spawned child runs ONLY the child routine.
const CRASH_CHILD_ENV: &str = "FLEET_DURABLE_CRASH_CHILD_DB";

fn crash_child_routine(state_dir: &std::path::Path) -> ! {
    let mut transport = DurableFleetTransport::new(state_dir).expect("child open");
    transport.initialize().expect("child initialize");
    transport
        .publish_action(&sample_action("committed-before-abort", "inc-crash"))
        .expect("child commit");
    // Committed under WAL+FULL: the fsync happened at COMMIT, so dying here
    // without closing the connection must not lose it.
    eprintln!("crash-child: committed, aborting");
    std::process::abort();
}

#[test]
fn committed_writes_survive_child_process_abort() {
    if let Ok(db_path) = std::env::var(CRASH_CHILD_ENV) {
        let state_dir = std::path::Path::new(&db_path)
            .parent()
            .expect("child state dir")
            .to_path_buf();
        crash_child_routine(&state_dir);
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("fleet");
    std::fs::create_dir_all(&state_dir).expect("state dir");

    let exe = std::env::current_exe().expect("current test binary");
    let output = std::process::Command::new(exe)
        .arg("--exact")
        .arg("committed_writes_survive_child_process_abort")
        .env(CRASH_CHILD_ENV, state_dir.join(FLEET_DB_FILE))
        .output()
        .expect("spawn crash child");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(
        output.status.signal(),
        Some(6),
        "child must die from SIGABRT; status={:?} stderr={stderr}",
        output.status
    );

    // Parent side: reopen the store the child died against and prove the
    // pre-abort commit survived without any graceful shutdown step.
    let mut reopened = DurableFleetTransport::new(&state_dir).expect("reopen after abort");
    reopened.initialize().expect("initialize after abort");
    let actions = reopened.list_actions().expect("list after abort");
    assert_eq!(actions.len(), 1, "committed action must survive the abort");
    assert_eq!(actions[0].action_id, "committed-before-abort");
}
