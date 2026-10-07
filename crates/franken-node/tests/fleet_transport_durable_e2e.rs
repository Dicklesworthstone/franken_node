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
    FileFleetTransport, FleetAction, FleetActionRecord, FleetTargetKind, FleetTransport,
    FleetTransportError, NodeHealth, NodeStatus,
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
    let original = sample_action("a-1", "inc-1");
    transport.publish_action(&original).expect("publish first");
    transport
        .publish_action(&original)
        .expect("retry exact record");
    assert_eq!(
        transport.list_actions().expect("list"),
        vec![original.clone()]
    );
    drop(transport);

    let mut reopened = DurableFleetTransport::new(dir.path()).expect("reopen");
    reopened.initialize().expect("initialize again");
    reopened
        .publish_action(&original)
        .expect("retry after restart");
    assert_eq!(
        reopened.list_actions().expect("list after restart"),
        vec![original]
    );
}

#[test]
fn conflicting_action_id_cannot_replace_quarantine_or_reorder_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
    transport.initialize().expect("initialize");
    let original = sample_action("immutable-id", "inc-protected");
    transport.publish_action(&original).expect("quarantine");

    let mut changed_time = original.clone();
    changed_time.emitted_at += chrono::TimeDelta::seconds(1);
    let mut changed_target = original.clone();
    if let FleetAction::Quarantine { target_id, .. } = &mut changed_target.action {
        *target_id = "different-extension".into();
    }
    let mut changed_kind = original.clone();
    changed_kind.action = FleetAction::Release {
        zone_id: "zone-a".into(),
        incident_id: "inc-protected".into(),
        reason: Some("must use a new action ID".into()),
    };

    for conflicting in [changed_time, changed_target, changed_kind] {
        let err = transport
            .publish_action(&conflicting)
            .expect_err("conflicting retry");
        assert!(
            matches!(err, FleetTransportError::ActionConflict { .. }),
            "{err:?}"
        );
        assert_eq!(
            transport.list_actions().expect("unchanged history"),
            vec![original.clone()]
        );
    }
    // A rejected transaction must release its lock and leave the connection
    // usable. An exact retry still works before the process restarts.
    transport
        .publish_action(&original)
        .expect("retry following conflicts");
    drop(transport);

    let mut reopened = DurableFleetTransport::new(dir.path()).expect("reopen");
    reopened.initialize().expect("initialize after conflicts");
    assert_eq!(
        reopened.list_actions().expect("persisted history"),
        vec![original]
    );
    assert_eq!(
        count_active_quarantine_actions(dir.path()).expect("active quarantine"),
        1
    );
}

#[test]
fn concurrent_publishers_choose_one_immutable_action() {
    use std::sync::{Arc, Barrier};

    let dir = tempfile::tempdir().expect("tempdir");
    let mut seeded = DurableFleetTransport::new(dir.path()).expect("open");
    seeded.initialize().expect("initialize");
    drop(seeded);

    let original = sample_action("raced-id", "inc-race");
    let mut competing = original.clone();
    competing.action = FleetAction::Release {
        zone_id: "zone-a".into(),
        incident_id: "inc-race".into(),
        reason: Some("competing operation with the same ID".into()),
    };
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let spawn = |record: FleetActionRecord| {
            let barrier = Arc::clone(&barrier);
            let path = dir.path();
            scope.spawn(move || {
                // Each writer owns an independent database connection. The
                // transport's per-connection mutex cannot serialize this race.
                let mut transport = DurableFleetTransport::new(path).expect("writer open");
                barrier.wait();
                transport.publish_action(&record)
            })
        };
        let first = spawn(original.clone());
        let second = spawn(competing.clone());
        [
            first.join().expect("first writer"),
            second.join().expect("second writer"),
        ]
    });
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "{results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(FleetTransportError::ActionConflict { .. })))
            .count(),
        1,
        "the losing writer must report a semantic conflict: {results:?}"
    );
    let winner = if results[0].is_ok() {
        original
    } else {
        competing
    };
    let mut reopened = DurableFleetTransport::new(dir.path()).expect("reopen after race");
    reopened.initialize().expect("initialize after race");
    assert_eq!(
        reopened.list_actions().expect("one winner"),
        vec![winner.clone()]
    );
    reopened
        .publish_action(&winner)
        .expect("winner can retry after restart");
    assert_eq!(
        reopened.list_actions().expect("still one winner"),
        vec![winner]
    );
}

#[test]
fn invalid_actions_and_node_statuses_never_enter_the_durable_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
    transport.initialize().expect("initialize");
    let mut blank_reason = sample_action("blank-reason", "inc-invalid");
    if let FleetAction::Quarantine { reason, .. } = &mut blank_reason.action {
        *reason = " ".into();
    }
    let mut oversized = sample_action("oversized", "inc-invalid");
    if let FleetAction::Quarantine { reason, .. } = &mut oversized.action {
        *reason = "x".repeat(4096);
    }
    for record in [
        sample_action("../invalid", "inc-invalid"),
        blank_reason,
        oversized,
    ] {
        assert!(matches!(
            transport.publish_action(&record),
            Err(FleetTransportError::SerializationError { .. })
        ));
    }
    let mut node = sample_node("../invalid-node");
    assert!(matches!(
        transport.upsert_node_status(&node),
        Err(FleetTransportError::SerializationError { .. })
    ));
    node.node_id = "valid-node".into();
    node.zone_id = "invalid/zone".into();
    assert!(matches!(
        transport.upsert_node_status(&node),
        Err(FleetTransportError::SerializationError { .. })
    ));
    let state = transport.read_shared_state().expect("empty valid state");
    assert!(state.actions.is_empty());
    assert!(state.nodes.is_empty());
}

#[test]
fn file_transport_retries_do_not_duplicate_or_replace_actions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = FileFleetTransport::new(dir.path());
    transport.initialize().expect("initialize");
    let original = sample_action("file-id", "inc-file");
    transport.publish_action(&original).expect("publish");
    let before = std::fs::read(dir.path().join(FLEET_ACTION_LOG_FILE)).expect("read log");
    transport.publish_action(&original).expect("exact retry");
    let mut conflicting = original.clone();
    conflicting.emitted_at += chrono::TimeDelta::seconds(1);
    assert!(matches!(
        transport.publish_action(&conflicting),
        Err(FleetTransportError::ActionConflict { .. })
    ));
    assert_eq!(
        std::fs::read(dir.path().join(FLEET_ACTION_LOG_FILE)).expect("unchanged log"),
        before
    );
    drop(transport);

    let mut reopened = FileFleetTransport::new(dir.path());
    reopened.initialize().expect("reopen");
    reopened
        .publish_action(&original)
        .expect("exact retry after reopen");
    assert_eq!(
        reopened.list_actions().expect("one retained action"),
        vec![original]
    );
}

#[test]
fn file_transport_preserves_a_complete_record_without_its_final_newline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = FileFleetTransport::new(dir.path());
    transport.initialize().expect("initialize");
    let original = sample_action("unterminated-id", "inc-unterminated");
    let payload = serde_json::to_vec(&original).expect("serialize complete record");
    let log = dir.path().join(FLEET_ACTION_LOG_FILE);
    std::fs::write(&log, &payload).expect("simulate complete record before delimiter write");

    transport
        .publish_action(&original)
        .expect("retry syncs the existing complete record");
    assert_eq!(std::fs::read(&log).expect("retained bytes"), payload);
    let mut next = sample_action("following-id", "inc-following");
    next.emitted_at = original.emitted_at + chrono::TimeDelta::seconds(1);
    transport
        .publish_action(&next)
        .expect("append after the unterminated complete record");
    drop(transport);

    let mut reopened = FileFleetTransport::new(dir.path());
    reopened.initialize().expect("reopen appended log");
    assert_eq!(
        reopened.list_actions().expect("two complete records"),
        vec![original, next]
    );
    let bytes = std::fs::read(&log).expect("read delimited log");
    assert!(bytes.starts_with(&payload));
    assert_eq!(bytes.iter().filter(|&&byte| byte == b'\n').count(), 2);
}

#[test]
fn file_transport_rejects_a_torn_record_without_appending_or_rewriting_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = FileFleetTransport::new(dir.path());
    transport.initialize().expect("initialize");
    transport
        .publish_action(&sample_action("complete-id", "inc-complete"))
        .expect("publish complete record");
    let log = dir.path().join(FLEET_ACTION_LOG_FILE);
    let mut damaged = std::fs::read(&log).expect("read complete record");
    damaged.extend_from_slice(br#"{"action_id":"torn-id","emitted_at":"#);
    std::fs::write(&log, &damaged).expect("simulate a torn append");

    assert!(matches!(
        transport.publish_action(&sample_action("next-id", "inc-next")),
        Err(FleetTransportError::SerializationError { .. })
    ));
    assert_eq!(
        std::fs::read(&log).expect("no mutation of damaged history"),
        damaged
    );
}

#[cfg(feature = "fleet-control-plane-server")]
#[test]
fn live_http_conflict_is_nonretryable_and_preserves_the_durable_action() {
    use frankenengine_node::control_plane::fleet_http_server::{
        FleetControlPlaneService, FleetHttpEventSink, FleetHttpServerConfig,
        FleetHttpServerControl, serve_fleet_control_plane,
    };
    use frankenengine_node::control_plane::fleet_transport_http::HttpFleetTransport;
    use std::sync::{Arc, mpsc};

    struct StopOnDrop(Arc<FleetHttpServerControl>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.request_shutdown();
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let token = "fleet-test-0123456789abcdef0123456789abcdef";
    let service = Arc::new(
        FleetControlPlaneService::open(dir.path().to_path_buf(), token).expect("open service"),
    );
    let control = FleetHttpServerControl::new();
    let stop = StopOnDrop(Arc::clone(&control));
    let (ready, bound) = mpsc::channel();
    let sink: FleetHttpEventSink = Arc::new(move |event| {
        if let Some(address) = &event.bound_addr {
            let _ = ready.send(address.clone());
        }
    });
    let server = std::thread::spawn(move || {
        serve_fleet_control_plane(
            service,
            &FleetHttpServerConfig {
                bind: "127.0.0.1:0".into(),
                max_requests: None,
            },
            control,
            sink,
        )
    });
    let address = bound
        .recv_timeout(Duration::from_secs(10))
        .expect("listener ready");
    let mut client =
        HttpFleetTransport::new(&format!("http://{address}"), token, Duration::from_secs(5))
            .expect("client");
    client
        .initialize()
        .expect("authenticated HTTP initialization");
    let original = sample_action("http-immutable", "inc-http");
    client
        .publish_action(&original)
        .expect("publish over socket");
    client
        .publish_action(&original)
        .expect("exact retry over socket");

    let mut conflicting = original.clone();
    conflicting.action = FleetAction::Release {
        zone_id: "zone-a".into(),
        incident_id: "inc-http".into(),
        reason: Some("cannot replace the original quarantine".into()),
    };
    let error = client
        .publish_action(&conflicting)
        .expect_err("HTTP action conflict");
    assert!(
        matches!(&error, FleetTransportError::ActionConflict { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("FLEET_HTTP_ACTION_CONFLICT"));
    assert!(error.to_string().contains("HTTP 409"));
    assert_eq!(
        client.list_actions().expect("read over socket"),
        vec![original.clone()]
    );

    stop.0.request_shutdown();
    server
        .join()
        .expect("server thread")
        .expect("server drained");
    let mut reopened = DurableFleetTransport::new(dir.path()).expect("reopen coordinator store");
    reopened.initialize().expect("initialize store");
    assert_eq!(
        reopened.list_actions().expect("unchanged durable record"),
        vec![original]
    );
}

#[test]
fn legacy_import_rejects_conflicting_action_ids_without_replacing_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = sample_action("legacy-conflict", "inc-original");
    let mut conflicting = original.clone();
    conflicting.action = FleetAction::Release {
        zone_id: "zone-a".into(),
        incident_id: "inc-original".into(),
        reason: Some("conflicting legacy record".into()),
    };
    std::fs::write(
        dir.path().join(FLEET_ACTION_LOG_FILE),
        format!(
            "{}\n{}\n",
            serde_json::to_string(&original).expect("encode original"),
            serde_json::to_string(&conflicting).expect("encode conflict")
        ),
    )
    .expect("write legacy log");
    let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
    assert!(matches!(
        transport.initialize(),
        Err(FleetTransportError::ActionConflict { .. })
    ));
    assert!(matches!(
        transport.list_actions(),
        Err(FleetTransportError::NotInitialized { .. })
    ));
    drop(transport);

    // The first accepted row stays intact even though import could not finish.
    // Correcting the legacy source to that original record allows a resumable,
    // idempotent import; the conflicting release was never authoritative.
    std::fs::write(
        dir.path().join(FLEET_ACTION_LOG_FILE),
        format!("{}\n", serde_json::to_string(&original).expect("encode")),
    )
    .expect("correct legacy source");
    let mut reopened = DurableFleetTransport::new(dir.path()).expect("reopen");
    reopened.initialize().expect("resume valid import");
    assert_eq!(
        reopened.list_actions().expect("original retained"),
        vec![original]
    );
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
