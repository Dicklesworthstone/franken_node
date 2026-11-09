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
use frankenengine_node::capacity_defaults::aliases::{MAX_ACTION_LOG_ENTRIES, MAX_NODES_CAP};
use frankenengine_node::control_plane::fleet_transport::{
    FileFleetTransport, FleetAction, FleetActionRecord, FleetTargetKind, FleetTransport,
    FleetTransportError, NodeHealth, NodeStatus, fleet_application_checkpoint,
};
use frankenengine_node::control_plane::fleet_transport_durable::{
    DurableFleetTransport, count_active_quarantine_actions,
};
use fsqlite::compat::TransactionExt;
use fsqlite::{Connection, SqliteValue};

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
        applied_actions: None,
    }
}

/// Populate the actual canonical capacity efficiently. Raw SQL is fixture
/// setup only: the final admissions, retries, reads and reopen all use the
/// product transport. Batching avoids tens of thousands of individual fsyncs.
fn seed_durable_inventory(
    transport: &DurableFleetTransport,
    action_count: usize,
    node_count: usize,
) {
    let connection = Connection::open(transport.db_path().to_string_lossy().as_ref())
        .expect("open fixture connection");
    connection.query("PRAGMA journal_mode=WAL;").expect("WAL");
    connection.query("PRAGMA synchronous=FULL;").expect("FULL");
    let mut tx = connection.transaction().expect("fixture transaction");
    const BATCH_SIZE: usize = 128;
    for first in (0..action_count).step_by(BATCH_SIZE) {
        let batch_len = (action_count - first).min(BATCH_SIZE);
        let placeholders = (0..batch_len)
            .map(|index| {
                format!(
                    "(?{}, ?{}, ?{})",
                    index * 3 + 1,
                    index * 3 + 2,
                    index * 3 + 3
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let mut parameters = Vec::with_capacity(batch_len * 3);
        for index in first..first + batch_len {
            let record = sample_action(&format!("seed-action-{index:05}"), "seed-incident");
            parameters.extend([
                SqliteValue::Text(record.action_id.clone().into()),
                SqliteValue::Text(record.emitted_at.to_rfc3339().into()),
                SqliteValue::Text(
                    serde_json::to_string(&record)
                        .expect("encode action")
                        .into(),
                ),
            ]);
        }
        tx.execute_with_params(
            &format!(
                "INSERT INTO fleet_actions(action_id, emitted_at, action_json) VALUES {placeholders};"
            ),
            &parameters,
        )
        .expect("seed action batch");
    }
    for first in (0..node_count).step_by(BATCH_SIZE) {
        let batch_len = (node_count - first).min(BATCH_SIZE);
        let placeholders = (0..batch_len)
            .map(|index| {
                format!(
                    "(?{}, ?{}, ?{})",
                    index * 3 + 1,
                    index * 3 + 2,
                    index * 3 + 3
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let mut parameters = Vec::with_capacity(batch_len * 3);
        for index in first..first + batch_len {
            let node = sample_node(&format!("seed-node-{index:05}"));
            parameters.extend([
                SqliteValue::Text(node.zone_id.clone().into()),
                SqliteValue::Text(node.node_id.clone().into()),
                SqliteValue::Text(serde_json::to_string(&node).expect("encode node").into()),
            ]);
        }
        tx.execute_with_params(
            &format!(
                "INSERT INTO fleet_nodes(zone_id, node_id, status_json) VALUES {placeholders};"
            ),
            &parameters,
        )
        .expect("seed node batch");
    }
    tx.commit().expect("commit fixture inventory");
}

#[test]
fn durable_capacity_keeps_retries_and_existing_heartbeats_operational() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
    transport.initialize().expect("initialize");
    seed_durable_inventory(&transport, MAX_ACTION_LOG_ENTRIES - 1, MAX_NODES_CAP - 1);

    let action = sample_action("last-action-slot", "retained-incident");
    transport.publish_action(&action).expect("last action slot");
    let mut node = sample_node("last-node-slot");
    transport.upsert_node_status(&node).expect("last node slot");
    transport
        .publish_action(&action)
        .expect("exact retry at capacity");

    let mut conflict = action.clone();
    conflict.action = release_action("unused-id", "retained-incident").action;
    assert!(matches!(
        transport.publish_action(&conflict),
        Err(FleetTransportError::ActionConflict { .. })
    ));
    assert!(matches!(
        transport.publish_action(&release_action(
            "over-capacity-release",
            "retained-incident"
        )),
        Err(FleetTransportError::SerializationError { .. })
    ));
    assert!(matches!(
        transport.upsert_node_status(&sample_node("over-capacity-node")),
        Err(FleetTransportError::SerializationError { .. })
    ));
    let mut another_zone = node.clone();
    another_zone.zone_id = "zone-b".to_string();
    assert!(matches!(
        transport.upsert_node_status(&another_zone),
        Err(FleetTransportError::SerializationError { .. })
    ));

    let actions = transport.list_actions().expect("retained actions readable");
    assert_eq!(actions.len(), MAX_ACTION_LOG_ENTRIES);
    assert!(actions.contains(&action), "containment is never evicted");
    assert!(
        !actions
            .iter()
            .any(|row| row.action_id == "over-capacity-release")
    );
    node.applied_actions = Some(
        fleet_application_checkpoint(&actions, "zone-a").expect("full snapshot remains applicable"),
    );
    transport
        .upsert_node_status(&node)
        .expect("existing node can still acknowledge application");
    drop(transport);

    let mut reopened = DurableFleetTransport::new(dir.path()).expect("reopen");
    reopened.initialize().expect("reinitialize");
    reopened
        .publish_action(&action)
        .expect("retry after reopen");
    let state = reopened
        .read_shared_state()
        .expect("coherent retained snapshot");
    assert_eq!(state.actions, actions);
    assert_eq!(state.nodes.len(), MAX_NODES_CAP);
    assert!(state.nodes.contains(&node));
    assert_eq!(
        node.applied_actions,
        Some(fleet_application_checkpoint(&state.actions, "zone-a").expect("checkpoint"))
    );
    node.health = NodeHealth::Degraded;
    node.applied_actions = None;
    reopened
        .upsert_node_status(&node)
        .expect("failure can still clear the previous checkpoint at capacity");
    assert!(
        reopened
            .list_node_statuses()
            .expect("latest heartbeats")
            .contains(&node)
    );
}

#[test]
fn durable_readers_refuse_oversized_existing_inventory_without_truncating() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
    transport.initialize().expect("initialize");
    // A store written by an older version must not silently hide its last
    // action or node to manufacture an in-bounds convergence snapshot.
    seed_durable_inventory(&transport, MAX_ACTION_LOG_ENTRIES + 1, MAX_NODES_CAP + 1);
    for result in [
        transport.list_actions().map(|_| ()),
        transport.list_node_statuses().map(|_| ()),
        transport.read_shared_state().map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(FleetTransportError::SerializationError { .. })
        ));
    }
    let connection = Connection::open(transport.db_path().to_string_lossy().as_ref())
        .expect("inspect retained inventory");
    for (table, expected) in [
        ("fleet_actions", MAX_ACTION_LOG_ENTRIES + 1),
        ("fleet_nodes", MAX_NODES_CAP + 1),
    ] {
        let rows = connection
            .query(&format!("SELECT COUNT(*) FROM {table};"))
            .expect("count");
        assert_eq!(
            rows[0].values()[0],
            SqliteValue::Integer(i64::try_from(expected).expect("capacity fits i64"))
        );
    }
}

#[test]
fn concurrent_durable_publishers_cannot_overbook_the_last_inventory_slots() {
    use std::sync::{Arc, Barrier};

    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
    transport.initialize().expect("initialize");
    seed_durable_inventory(&transport, MAX_ACTION_LOG_ENTRIES - 1, MAX_NODES_CAP - 1);
    let barrier = Arc::new(Barrier::new(3));
    let publishers = (0..2)
        .map(|index| {
            let root = dir.path().to_path_buf();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut writer = DurableFleetTransport::new(root).expect("independent writer");
                writer.initialize().expect("writer initialize");
                barrier.wait();
                let action = writer.publish_action(&sample_action(
                    &format!("racing-action-{index}"),
                    &format!("racing-incident-{index}"),
                ));
                barrier.wait();
                let node = writer.upsert_node_status(&sample_node(&format!("racing-node-{index}")));
                (action, node)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    barrier.wait();
    let results = publishers
        .into_iter()
        .map(|writer| writer.join().expect("writer completed"))
        .collect::<Vec<_>>();
    assert_eq!(
        results.iter().filter(|(action, _)| action.is_ok()).count(),
        1
    );
    assert_eq!(results.iter().filter(|(_, node)| node.is_ok()).count(), 1);
    for result in results
        .into_iter()
        .flat_map(|(action, node)| [action, node])
    {
        if let Err(error) = result {
            assert!(
                matches!(error, FleetTransportError::SerializationError { .. }),
                "{error}"
            );
        }
    }
    let state = transport
        .read_shared_state()
        .expect("bounded snapshot after races");
    assert_eq!(state.actions.len(), MAX_ACTION_LOG_ENTRIES);
    assert_eq!(state.nodes.len(), MAX_NODES_CAP);
    assert_eq!(
        state
            .actions
            .iter()
            .filter(|row| row.action_id.starts_with("seed-action-"))
            .count(),
        MAX_ACTION_LOG_ENTRIES - 1
    );
    assert_eq!(
        state
            .nodes
            .iter()
            .filter(|row| row.node_id.starts_with("seed-node-"))
            .count(),
        MAX_NODES_CAP - 1
    );
}

#[test]
fn durable_shared_state_does_not_mix_action_and_checkpoint_generations() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};

    let dir = tempfile::tempdir().expect("tempdir");
    let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
    transport.initialize().expect("initialize");
    seed_durable_inventory(&transport, 256, 0);
    let mut actions = transport.list_actions().expect("initial actions");
    let mut node = sample_node("generation-node");
    node.applied_actions =
        Some(fleet_application_checkpoint(&actions, "zone-a").expect("checkpoint"));
    transport.upsert_node_status(&node).expect("initial node");

    let barrier = Arc::new(Barrier::new(2));
    let finished = Arc::new(AtomicBool::new(false));
    let writer_barrier = Arc::clone(&barrier);
    let writer_finished = Arc::clone(&finished);
    let db_path = transport.db_path().to_path_buf();
    let writer = std::thread::spawn(move || {
        let connection =
            Connection::open(db_path.to_string_lossy().as_ref()).expect("writer connection");
        connection
            .query("PRAGMA journal_mode=WAL;")
            .expect("writer WAL");
        connection
            .query("PRAGMA synchronous=FULL;")
            .expect("writer FULL");
        connection
            .query("PRAGMA busy_timeout=5000;")
            .expect("writer timeout");
        writer_barrier.wait();
        for generation in 0..64 {
            let action = sample_action(
                &format!("generation-{generation:03}"),
                "generation-incident",
            );
            actions.push(action.clone());
            node.applied_actions =
                Some(fleet_application_checkpoint(&actions, "zone-a").expect("next checkpoint"));
            let mut tx = connection.transaction().expect("generation transaction");
            tx.execute_with_params(
                "INSERT INTO fleet_actions(action_id, emitted_at, action_json) VALUES (?1, ?2, ?3);",
                &[
                    SqliteValue::Text(action.action_id.into()),
                    SqliteValue::Text(action.emitted_at.to_rfc3339().into()),
                    SqliteValue::Text(serde_json::to_string(actions.last().expect("appended action")).expect("encode action").into()),
                ],
            ).expect("generation action");
            tx.execute_with_params(
                "UPDATE fleet_nodes SET status_json = ?1 WHERE zone_id = ?2 AND node_id = ?3;",
                &[
                    SqliteValue::Text(serde_json::to_string(&node).expect("encode node").into()),
                    SqliteValue::Text(node.zone_id.clone().into()),
                    SqliteValue::Text(node.node_id.clone().into()),
                ],
            )
            .expect("generation node");
            // Both records become visible together. Every valid snapshot must
            // therefore pair the action set with exactly its own checkpoint.
            tx.commit().expect("commit generation");
        }
        writer_finished.store(true, Ordering::Release);
    });
    barrier.wait();
    for sample in 0..128 {
        let state = transport.read_shared_state().expect("shared snapshot");
        assert_eq!(state.nodes.len(), 1);
        assert_eq!(
            state.nodes[0].applied_actions,
            Some(
                fleet_application_checkpoint(&state.actions, "zone-a")
                    .expect("snapshot checkpoint")
            ),
            "reader combined actions and heartbeat from different committed snapshots"
        );
        if sample >= 31 && finished.load(Ordering::Acquire) {
            break;
        }
    }
    writer.join().expect("generation writer completed");
    assert_eq!(transport.list_actions().expect("final actions").len(), 320);
}

#[test]
fn application_checkpoints_bind_zone_wildcards_and_complete_immutable_records() {
    let first = sample_action("checkpoint-a", "incident-a");
    let mut wildcard = sample_action("checkpoint-global", "incident-global");
    if let FleetAction::Quarantine { zone_id, .. } = &mut wildcard.action {
        *zone_id = "all".to_string();
    }
    let mut other_zone = sample_action("checkpoint-b", "incident-b");
    if let FleetAction::Quarantine { zone_id, .. } = &mut other_zone.action {
        *zone_id = "zone-b".to_string();
    }
    let actions = vec![first.clone(), wildcard.clone(), other_zone.clone()];
    let expected = fleet_application_checkpoint(&actions, "zone-a").expect("checkpoint");
    assert_eq!(expected.action_count, 2);
    assert_ne!(
        expected,
        fleet_application_checkpoint(
            &[other_zone.clone(), wildcard.clone(), first.clone()],
            "zone-a"
        )
        .expect("reordered relevant history has a different checkpoint")
    );
    assert_eq!(
        expected,
        fleet_application_checkpoint(
            &[other_zone.clone(), first.clone(), wildcard.clone()],
            "zone-a"
        )
        .expect("unrelated zone order does not change the relevant sequence")
    );
    assert_eq!(
        expected,
        fleet_application_checkpoint(&[first.clone(), wildcard.clone()], "zone-a")
            .expect("unrelated zone excluded")
    );
    assert_ne!(
        expected,
        fleet_application_checkpoint(&actions, "zone-b").expect("other zone")
    );
    let mut changed_time = first.clone();
    changed_time.emitted_at -= chrono::TimeDelta::seconds(1);
    assert_ne!(
        expected,
        fleet_application_checkpoint(&[changed_time, wildcard.clone()], "zone-a")
            .expect("timestamp is immutable evidence")
    );
    let mut changed_target = first.clone();
    if let FleetAction::Quarantine { target_id, .. } = &mut changed_target.action {
        *target_id = "another-extension".to_string();
    }
    assert_ne!(
        expected,
        fleet_application_checkpoint(&[changed_target, wildcard], "zone-a")
            .expect("target is immutable evidence")
    );
    assert!(
        fleet_application_checkpoint(&[first.clone(), first], "zone-a").is_err(),
        "ambiguous duplicate IDs cannot yield an application checkpoint"
    );
}

#[test]
fn application_checkpoints_survive_file_and_sql_storage_and_failed_poll_clears_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let action = sample_action("checkpoint-persist", "checkpoint-incident");
    let expected =
        fleet_application_checkpoint(std::slice::from_ref(&action), "zone-a").expect("checkpoint");
    for durable in [false, true] {
        let root = dir.path().join(if durable { "sql" } else { "file" });
        let mut transport: Box<dyn FleetTransport> = if durable {
            Box::new(DurableFleetTransport::new(&root).expect("durable transport"))
        } else {
            Box::new(FileFleetTransport::new(&root))
        };
        transport.initialize().expect("initialize");
        transport.publish_action(&action).expect("publish");
        let mut node = sample_node("checkpoint-node");
        transport
            .upsert_node_status(&node)
            .expect("historical heartbeat");
        assert!(
            transport.list_node_statuses().expect("nodes")[0]
                .applied_actions
                .is_none()
        );
        node.applied_actions = Some(expected.clone());
        transport
            .upsert_node_status(&node)
            .expect("applied heartbeat");
        assert_eq!(
            transport.read_shared_state().expect("state").nodes[0].applied_actions,
            Some(expected.clone())
        );
        let mut invalid = node.clone();
        invalid.health = NodeHealth::Degraded;
        assert!(
            transport.upsert_node_status(&invalid).is_err(),
            "a degraded node must clear its earlier application checkpoint"
        );
        assert_eq!(
            transport.list_node_statuses().expect("unchanged node")[0],
            node
        );
        invalid
            .applied_actions
            .as_mut()
            .expect("checkpoint")
            .actions_sha256 = "Z".repeat(64);
        invalid.health = NodeHealth::Healthy;
        assert!(
            transport.upsert_node_status(&invalid).is_err(),
            "invalid digest rejected"
        );
        node.health = NodeHealth::Degraded;
        node.applied_actions = None;
        transport
            .upsert_node_status(&node)
            .expect("failed poll clears proof");
        drop(transport);
        let mut reopened: Box<dyn FleetTransport> = if durable {
            Box::new(DurableFleetTransport::new(&root).expect("reopen SQL"))
        } else {
            Box::new(FileFleetTransport::new(&root))
        };
        reopened.initialize().expect("reinitialize");
        assert_eq!(
            reopened.list_node_statuses().expect("reopened nodes"),
            vec![node]
        );
    }
    let historical = serde_json::json!({
        "zone_id":"zone-a", "node_id":"legacy-node", "last_seen":Utc::now(),
        "quarantine_version":u64::MAX, "health":"healthy"
    });
    let decoded: NodeStatus = serde_json::from_value(historical.clone()).expect("legacy heartbeat");
    assert!(decoded.applied_actions.is_none());
    assert_eq!(
        serde_json::to_value(decoded).expect("same historical bytes"),
        historical
    );
}

#[test]
fn writes_survive_reopen_and_read_back_in_contract_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("fleet");
    {
        let mut transport = DurableFleetTransport::new(&state_dir).expect("open");
        transport.initialize().expect("initialize");
        // The second issuer has a slower clock and a lower action ID. Neither
        // can move its committed action ahead of the first accepted action.
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
        actions[0].action_id, "a-2",
        "the first committed action remains first despite issuer clock skew"
    );
    assert_eq!(actions[1].action_id, "a-1");
    let nodes = reopened.list_node_statuses().expect("list nodes");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].node_id, "node-1");
    let state = reopened.read_shared_state().expect("shared state");
    assert_eq!(state.actions, actions);
    assert_eq!(state.nodes.len(), 1);
}

#[test]
fn file_and_durable_transports_preserve_requarantine_order_through_retry_and_reopen() {
    use std::io::Write as _;

    let compact_on_reopen = |transport: &mut FileFleetTransport| {
        // Exercise initialize()'s real 10 MiB compaction threshold. Empty
        // JSONL lines are valid fixture padding and add no action records.
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(transport.layout().actions_path())
            .expect("open action log for compaction fixture");
        let mut writer = std::io::BufWriter::new(file);
        let mut padding = [b' '; 4_096];
        padding[4_095] = b'\n';
        for _ in 0..2_560 {
            writer.write_all(&padding).expect("write padding");
        }
        writer.flush().expect("flush padding");
        drop(writer);
        transport.initialize().expect("compact on reopen");
        assert!(
            std::fs::metadata(transport.layout().actions_path())
                .expect("compacted log metadata")
                .len()
                < 10 * 1_024 * 1_024,
            "normal initialization must actually compact the oversized log"
        );
    };
    let directory = tempfile::tempdir().expect("tempdir");
    let now = Utc::now() - chrono::TimeDelta::days(60);
    let mut original = sample_action("z-original", "same-incident");
    original.emitted_at = now;
    let mut release = release_action("m-release", "same-incident");
    release.emitted_at = now + chrono::TimeDelta::seconds(1);
    let mut repeat = sample_action("a-repeat", "same-incident");
    repeat.emitted_at = now - chrono::TimeDelta::hours(1);
    let expected = vec![original, release.clone(), repeat];

    for durable in [false, true] {
        let root = directory.path().join(if durable { "sql" } else { "file" });
        let open = || -> Box<dyn FleetTransport> {
            if durable {
                Box::new(DurableFleetTransport::new(&root).expect("durable transport"))
            } else {
                Box::new(FileFleetTransport::new(&root))
            }
        };
        {
            let mut transport = open();
            transport.initialize().expect("initialize");
            for action in &expected {
                transport.publish_action(action).expect("publish");
            }
            transport
                .publish_action(&release)
                .expect("retry must not move the release after the new quarantine");
            assert_eq!(transport.list_actions().expect("listed actions"), expected);
            assert_eq!(
                transport.read_shared_state().expect("shared state").actions,
                expected
            );
        }
        let mut reopened = open();
        reopened.initialize().expect("reinitialize");
        assert_eq!(reopened.list_actions().expect("reopened history"), expected);
        assert_eq!(
            reopened
                .read_shared_state()
                .expect("reopened shared state")
                .actions,
            expected
        );
        if durable {
            assert_eq!(
                count_active_quarantine_actions(&root).expect("active metric"),
                1
            );
        }
    }
    let file_root = directory.path().join("file");
    let mut file = FileFleetTransport::new(&file_root);
    compact_on_reopen(&mut file);
    assert_eq!(
        file.list_actions().expect("compacted file history"),
        expected
    );
    let mut imported = DurableFleetTransport::new(&file_root).expect("import file store");
    imported.initialize().expect("initialize imported store");
    assert_eq!(
        imported
            .read_shared_state()
            .expect("imported snapshot")
            .actions,
        expected,
        "migration to the durable store must preserve active containment order"
    );
    let mut released = FileFleetTransport::new(directory.path().join("released-file"));
    released.initialize().expect("initialize released fixture");
    for action in &expected {
        released.publish_action(action).expect("publish fixture");
    }
    let mut final_release = release;
    final_release.action_id = "0-final-release".to_string();
    final_release.emitted_at = now - chrono::TimeDelta::hours(2);
    released
        .publish_action(&final_release)
        .expect("publish backdated final release");
    compact_on_reopen(&mut released);
    assert!(
        released
            .list_actions()
            .expect("released history")
            .is_empty(),
        "a subsequently committed release permits expired incident history to retire"
    );
    let reordered = vec![
        expected[0].clone(),
        expected[2].clone(),
        expected[1].clone(),
    ];
    assert_ne!(
        fleet_application_checkpoint(&expected, "zone-a").expect("quarantined checkpoint"),
        fleet_application_checkpoint(&reordered, "zone-a").expect("released checkpoint"),
        "opposite containment outcomes must never share an application checkpoint"
    );
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
fn live_http_conflicts_and_legacy_routes_preserve_durable_actions_and_checkpoints() {
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

    let mut node = sample_node("http-applied-node");
    node.applied_actions = Some(
        fleet_application_checkpoint(std::slice::from_ref(&original), "zone-a")
            .expect("application checkpoint"),
    );
    client
        .upsert_node_status(&node)
        .expect("checkpoint heartbeat over socket");
    let received = client
        .read_shared_state()
        .expect("checkpoint state over socket");
    assert_eq!(received.nodes.len(), 1);
    assert_eq!(received.nodes[0].applied_actions, node.applied_actions);

    // Version negotiation must happen before mutation. A v1 client checks
    // response schemas only after POST, so v2 must not expose writable v1
    // routes even when a legacy client presents the correct bearer token.
    let legacy_client = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(5)))
            .max_redirects(0)
            .http_status_as_error(false)
            .build(),
    );
    let mut legacy_node = node.clone();
    legacy_node
        .applied_actions
        .as_mut()
        .expect("checkpoint")
        .actions_sha256 = "0".repeat(64);
    for (path, payload) in [
        (
            "/v1/fleet/actions",
            serde_json::to_vec(&release_action("legacy-release", "inc-http"))
                .expect("legacy action"),
        ),
        (
            "/v1/fleet/nodes",
            serde_json::to_vec(&legacy_node).expect("legacy heartbeat"),
        ),
    ] {
        let response = legacy_client
            .post(format!("http://{address}{path}"))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .send(&payload[..])
            .expect("legacy request reaches coordinator");
        assert_eq!(response.status().as_u16(), 404, "legacy route {path}");
    }
    assert_eq!(
        client
            .read_shared_state()
            .expect("state after legacy writes"),
        received,
        "old action and checkpoint submissions must not mutate the coordinator"
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
    assert_eq!(
        reopened
            .list_node_statuses()
            .expect("durable HTTP acknowledgement")[0]
            .applied_actions,
        node.applied_actions
    );
}

#[cfg(feature = "fleet-control-plane-server")]
#[test]
fn live_http_enrollment_binds_identities_scopes_reads_and_requires_fresh_checkpoints() {
    use frankenengine_node::control_plane::fleet_http_server::{
        FLEET_NODE_CREDENTIALS_SCHEMA, FleetControlPlaneService, FleetHttpEventSink,
        FleetHttpServerConfig, FleetHttpServerControl, FleetNodeCredentials,
        serve_fleet_control_plane,
    };
    use frankenengine_node::control_plane::fleet_transport_http::HttpFleetTransport;
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, mpsc};

    struct StopOnDrop(Arc<FleetHttpServerControl>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.request_shutdown();
        }
    }

    let dir = tempfile::tempdir().expect("coordinator directory");
    let operator_token = "operator-0123456789abcdef0123456789abcdef";
    let first_a_token = "node-a-first-0123456789abcdef0123456789abcdef";
    let rotated_a_token = "node-a-rotated-0123456789abcdef0123456789abcdef";
    let node_b_token = "node-b-0123456789abcdef0123456789abcdef";
    let action_a = sample_action("enrolled-a", "inc-a");
    let mut action_b = sample_action("enrolled-b", "inc-b");
    if let FleetAction::Quarantine { zone_id, .. } = &mut action_b.action {
        *zone_id = "zone-b".into();
    }
    let mut action_all = sample_action("enrolled-all", "inc-all");
    if let FleetAction::Quarantine { zone_id, .. } = &mut action_all.action {
        *zone_id = "all".into();
    }
    let all_actions = vec![action_a.clone(), action_b.clone(), action_all.clone()];
    let mut node_a = sample_node("enrolled-node-a");
    node_a.applied_actions =
        Some(fleet_application_checkpoint(&all_actions, "zone-a").expect("node-a checkpoint"));
    let mut node_b = sample_node("enrolled-node-b");
    node_b.zone_id = "zone-b".into();
    node_b.applied_actions =
        Some(fleet_application_checkpoint(&all_actions, "zone-b").expect("node-b checkpoint"));
    {
        let mut store = DurableFleetTransport::new(dir.path()).expect("legacy store");
        store.initialize().expect("initialize legacy store");
        for action in &all_actions {
            store.publish_action(action).expect("retained action");
        }
        for node in [&node_a, &node_b] {
            store.upsert_node_status(node).expect("legacy checkpoint");
        }
    }

    // The second coordinator incarnation rotates one node credential and
    // retains the durable store. Neither prior shared-bearer nor previously
    // authenticated checkpoints may acquire fresh authority after restart.
    for node_a_token in [first_a_token, rotated_a_token] {
        let enrollment_path = dir.path().join("node-credentials.json");
        std::fs::write(
            &enrollment_path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": FLEET_NODE_CREDENTIALS_SCHEMA,
                "nodes": [
                    {"zone_id": "zone-a", "node_id": "enrolled-node-a",
                     "token_sha256": hex::encode(Sha256::digest(node_a_token.as_bytes()))},
                    {"zone_id": "zone-b", "node_id": "enrolled-node-b",
                     "token_sha256": hex::encode(Sha256::digest(node_b_token.as_bytes()))},
                    {"zone_id": "zone-a", "node_id": "enrolled-node-missing",
                     "token_sha256": hex::encode(Sha256::digest(b"missing-node-0123456789abcdef0123456789abcdef"))}
                ]
            }))
            .expect("encode enrollment"),
        )
        .expect("write enrollment");
        let service = FleetControlPlaneService::open(dir.path().to_path_buf(), operator_token)
            .expect("open enrolled service")
            .with_node_credentials(
                FleetNodeCredentials::load(&enrollment_path).expect("enrollment"),
            )
            .expect("distinct operator and node identities");
        assert_eq!(service.enrolled_node_count(), 3);
        let service = Arc::new(service);
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
        let url = format!("http://{address}");
        let client = |token: &str| {
            HttpFleetTransport::new(&url, token, Duration::from_secs(5)).expect("HTTP client")
        };
        let mut operator = client(operator_token);
        let mut agent_a = client(node_a_token);
        let mut agent_b = client(node_b_token);
        operator.initialize().expect("operator initialization");
        agent_a.initialize().expect("node-a initialization");
        agent_b.initialize().expect("node-b initialization");
        let initial = operator.read_shared_state().expect("operator inventory");
        assert_eq!(initial.actions, all_actions);
        assert_eq!(initial.nodes.len(), 3);
        assert!(
            initial
                .nodes
                .iter()
                .all(|node| node.applied_actions.is_none())
        );

        assert_eq!(
            agent_a.list_actions().expect("zone-a actions"),
            vec![action_a.clone(), action_all.clone()]
        );
        assert_eq!(
            agent_b.list_actions().expect("zone-b actions"),
            vec![action_b.clone(), action_all.clone()]
        );
        let own = agent_a.list_node_statuses().expect("node-a identity probe");
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].node_id, node_a.node_id);
        assert_eq!(own[0].zone_id, node_a.zone_id);
        assert!(
            agent_a
                .read_shared_state()
                .expect_err("no whole-fleet disclosure")
                .to_string()
                .contains("HTTP 403")
        );
        assert!(
            agent_a
                .publish_action(&release_action("node-release", "inc-a"))
                .expect_err("agent has no control-action authority")
                .to_string()
                .contains("HTTP 403")
        );
        assert!(
            operator
                .upsert_node_status(&node_a)
                .expect_err("operator cannot authenticate node acknowledgement")
                .to_string()
                .contains("HTTP 403")
        );
        let mut renamed_node = node_a.clone();
        renamed_node.node_id = "renamed-node-a".into();
        let mut changed_zone = node_a.clone();
        changed_zone.zone_id = "zone-b".into();
        for forged in [node_b.clone(), renamed_node, changed_zone] {
            assert!(
                agent_a
                    .upsert_node_status(&forged)
                    .expect_err("node identity substitution refused")
                    .to_string()
                    .contains("HTTP 403")
            );
        }
        if node_a_token == rotated_a_token {
            assert!(
                client(first_a_token)
                    .list_actions()
                    .expect_err("rotated credential refused")
                    .to_string()
                    .contains("HTTP 401")
            );
        }
        agent_a
            .upsert_node_status(&node_a)
            .expect("authenticated node-a checkpoint");
        let partial = operator
            .read_shared_state()
            .expect("partial fresh inventory");
        assert_eq!(
            partial
                .nodes
                .iter()
                .filter(|node| node.applied_actions.is_some())
                .count(),
            1
        );
        agent_b
            .upsert_node_status(&node_b)
            .expect("authenticated node-b checkpoint");
        let complete = operator.read_shared_state().expect("fresh inventory");
        assert_eq!(
            complete.actions, all_actions,
            "forbidden writes changed no action"
        );
        assert_eq!(
            complete.nodes.len(),
            3,
            "forged identities were never stored"
        );
        for node in &complete.nodes {
            if node.node_id == "enrolled-node-missing" {
                assert_eq!(node.health, NodeHealth::Stale);
                assert!(node.applied_actions.is_none());
                assert_eq!(node.last_seen, chrono::DateTime::<Utc>::UNIX_EPOCH);
                continue;
            }
            assert_eq!(
                node.applied_actions,
                Some(
                    fleet_application_checkpoint(&all_actions, &node.zone_id)
                        .expect("exact checkpoint")
                )
            );
        }
        // Another coordinator or local durable transport may share the store.
        // An unauthenticated replacement must not inherit the genuine node's
        // previously observed authority, even under the same node/zone key.
        let mut replaced = complete
            .nodes
            .iter()
            .find(|node| node.node_id == node_a.node_id)
            .expect("authenticated node-a row")
            .clone();
        replaced
            .applied_actions
            .as_mut()
            .expect("checkpoint")
            .actions_sha256 = "0".repeat(64);
        {
            let mut other_writer = DurableFleetTransport::new(dir.path()).expect("second writer");
            other_writer.initialize().expect("initialize second writer");
            other_writer
                .upsert_node_status(&replaced)
                .expect("replace durable row outside enrolled HTTP authority");
        }
        let replaced_view = operator
            .read_shared_state()
            .expect("inventory after concurrent durable replacement");
        assert!(
            replaced_view
                .nodes
                .iter()
                .find(|node| node.node_id == node_a.node_id)
                .expect("retained node-a identity")
                .applied_actions
                .is_none()
        );
        assert_eq!(
            replaced_view
                .nodes
                .iter()
                .find(|node| node.node_id == node_b.node_id)
                .expect("unchanged node-b acknowledgement")
                .applied_actions,
            node_b.applied_actions
        );
        agent_a
            .upsert_node_status(&node_a)
            .expect("only a new authenticated heartbeat restores the checkpoint");
        assert_eq!(
            agent_a.list_node_statuses().expect("restored node-a view")[0].applied_actions,
            node_a.applied_actions
        );
        stop.0.request_shutdown();
        server
            .join()
            .expect("server thread")
            .expect("server drained");
    }
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

#[cfg(feature = "http-client")]
mod http_origin_boundary {
    use super::{release_action, sample_action, sample_node};
    use frankenengine_node::capacity_defaults::aliases::{MAX_ACTION_LOG_ENTRIES, MAX_NODES_CAP};
    use frankenengine_node::control_plane::fleet_transport::{
        FLEET_SHARED_STATE_SCHEMA, FleetActionRecord, FleetApplicationCheckpoint, FleetTransport,
        FleetTransportError, NodeHealth,
    };
    use frankenengine_node::control_plane::fleet_transport_http::{
        FLEET_HTTP_ACTIONS_PATH, FLEET_HTTP_API_SCHEMA, FLEET_HTTP_HEALTH_PATH,
        FLEET_HTTP_NODES_PATH, FLEET_HTTP_STATE_PATH, HttpFleetTransport,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    const TOKEN: &str = "fleet-origin-test-0123456789abcdef0123456789abcdef";

    /// A real HTTP peer with bounded accept/read/write operations for each
    /// scripted response. Return every complete request to check actual I/O.
    fn serve_responses<const N: usize>(
        responses: [String; N],
    ) -> (String, JoinHandle<[String; N]>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP peer");
        let origin = format!("http://{}", listener.local_addr().expect("peer address"));
        listener.set_nonblocking(true).expect("nonblocking accept");
        let peer = std::thread::spawn(move || {
            responses.map(|response| {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "HTTP peer was never contacted");
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept HTTP peer: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .expect("write timeout");
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(request.len() < 64 * 1024, "HTTP request headers too large");
                    let mut byte = [0_u8; 1];
                    stream.read_exact(&mut byte).expect("request header byte");
                    request.push(byte[0]);
                }
                let headers = std::str::from_utf8(&request).expect("ASCII request headers");
                let content_length = headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map_or(0, |(_, value)| {
                        value.trim().parse::<usize>().expect("body length")
                    });
                assert!(content_length <= 64 * 1024, "HTTP request body too large");
                let header_bytes = request.len();
                request.resize(header_bytes + content_length, 0);
                stream
                    .read_exact(&mut request[header_bytes..])
                    .expect("complete request body");
                stream
                    .write_all(response.as_bytes())
                    .expect("send response");
                String::from_utf8(request).expect("UTF-8 request")
            })
        });
        (origin, peer)
    }

    fn json_response(body: &serde_json::Value) -> String {
        let body = serde_json::to_string(body).expect("encode response");
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn fleet_http_redirects_never_contact_another_origin() {
        for (status, body_length) in [301, 302, 303, 307, 308]
            .into_iter()
            .flat_map(|status| [0, 1_048_576].map(|body_length| (status, body_length)))
        {
            for operation in ["health", "actions", "publish", "heartbeat"] {
                let target = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
                target
                    .set_nonblocking(true)
                    .expect("inspect pending contacts");
                let destination = format!(
                    "http://{}/untrusted-fleet",
                    target.local_addr().expect("redirect address")
                );
                // A complete empty body permits automatic redirects; a
                // truncated nonempty body proves refusal precedes body reads.
                let (origin, peer) = serve_responses([format!(
                    "HTTP/1.1 {status} Redirect\r\nLocation: {destination}\r\nContent-Length: {body_length}\r\nConnection: close\r\n\r\n"
                )]);
                let mut client = HttpFleetTransport::new(&origin, TOKEN, Duration::from_secs(2))
                    .expect("client");
                let result = match operation {
                    "health" => client.health().map(|_| ()),
                    "actions" => client.list_actions().map(|_| ()),
                    "publish" => {
                        client.publish_action(&sample_action("origin-action", "origin-inc"))
                    }
                    "heartbeat" => client.upsert_node_status(&sample_node("origin-node")),
                    _ => unreachable!("fixed operation table"),
                };
                let [request] = peer.join().expect("HTTP peer finished");
                let contact = target
                    .accept()
                    .expect_err("redirect target must never be contacted");
                assert_eq!(contact.kind(), std::io::ErrorKind::WouldBlock);
                let error = result.expect_err("redirect must not succeed");
                assert!(
                    matches!(&error, FleetTransportError::IoError { .. }),
                    "{error}"
                );
                assert!(
                    error
                        .to_string()
                        .contains(&format!("HTTP {status}; redirects are refused")),
                    "{operation}: {error}"
                );
                assert!(
                    !error.to_string().contains(&destination),
                    "untrusted redirect target must not be promoted into diagnostics"
                );
                let has_token = request.contains(TOKEN);
                assert_eq!(has_token, operation != "health", "{operation}");
                if operation == "publish" || operation == "heartbeat" {
                    assert!(request.starts_with("POST "), "{operation}");
                } else {
                    assert!(request.starts_with("GET "), "{operation}");
                }
            }
        }
    }

    #[test]
    fn fleet_http_direct_reads_and_mutations_keep_their_wire_contract() {
        let action = sample_action("origin-positive", "origin-positive-inc");
        let (origin, peer) = serve_responses([json_response(&serde_json::json!({
            "schema_version": FLEET_HTTP_API_SCHEMA,
            "actions": [action.clone()]
        }))]);
        let client =
            HttpFleetTransport::new(&origin, TOKEN, Duration::from_secs(2)).expect("read client");
        let result = client.list_actions();
        let [request] = peer.join().expect("read peer finished");
        assert_eq!(result.expect("direct list succeeds"), vec![action.clone()]);
        assert!(request.starts_with("GET /v2/fleet/actions HTTP/1.1\r\n"));
        assert!(request.contains(&format!("Bearer {TOKEN}")));

        let (origin, peer) = serve_responses([json_response(&serde_json::json!({
            "schema_version": FLEET_HTTP_API_SCHEMA,
            "accepted": action.action_id
        }))]);
        let mut client = HttpFleetTransport::new(&origin, TOKEN, Duration::from_secs(2))
            .expect("publish client");
        let result = client.publish_action(&action);
        let [request] = peer.join().expect("publish peer finished");
        result.expect("direct publication succeeds");
        assert!(request.starts_with("POST /v2/fleet/actions HTTP/1.1\r\n"));
        assert!(request.contains(&format!("Bearer {TOKEN}")));
        let (_, body) = request.split_once("\r\n\r\n").expect("request body");
        assert_eq!(
            serde_json::from_str::<FleetActionRecord>(body).expect("actual transmitted action"),
            action
        );
    }

    fn assert_snapshot_refused(path: &str, body: &serde_json::Value, expected: &str) {
        let (origin, peer) = serve_responses([json_response(body)]);
        let client = HttpFleetTransport::new(&origin, TOKEN, Duration::from_secs(5))
            .expect("snapshot client");
        let result = match path {
            FLEET_HTTP_ACTIONS_PATH => client.list_actions().map(|_| ()),
            FLEET_HTTP_NODES_PATH => client.list_node_statuses().map(|_| ()),
            FLEET_HTTP_STATE_PATH => client.read_shared_state().map(|_| ()),
            _ => unreachable!("fixed snapshot route table"),
        };
        let [request] = peer.join().expect("snapshot peer finished");
        let error = result.expect_err("malformed snapshot must fail closed");
        assert!(
            matches!(&error, FleetTransportError::SerializationError { .. }),
            "{path}: {error}"
        );
        assert!(error.to_string().contains(expected), "{path}: {error}");
        assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
        assert!(request.contains(&format!("Bearer {TOKEN}")));
    }

    fn initialization_result(nodes: &serde_json::Value) -> Result<(), FleetTransportError> {
        let (origin, peer) = serve_responses([
            json_response(&serde_json::json!({
                "schema_version": FLEET_HTTP_API_SCHEMA,
                "status": "ok",
                "service": "franken-node",
                "store": "durable"
            })),
            json_response(nodes),
        ]);
        let mut client = HttpFleetTransport::new(&origin, TOKEN, Duration::from_secs(5))
            .expect("initialization client");
        let result = client.initialize();
        let [health_request, nodes_request] = peer.join().expect("initialization peer finished");
        assert!(health_request.starts_with(&format!("GET {FLEET_HTTP_HEALTH_PATH} HTTP/1.1\r\n")));
        assert!(!health_request.contains(TOKEN));
        assert!(nodes_request.starts_with(&format!("GET {FLEET_HTTP_NODES_PATH} HTTP/1.1\r\n")));
        assert!(nodes_request.contains(&format!("Bearer {TOKEN}")));
        result
    }

    #[test]
    fn fleet_http_initialization_validates_the_authenticated_node_snapshot() {
        let node = sample_node("initialization-node");
        let mut invalid_id = node.clone();
        invalid_id.node_id = "../escape".to_string();
        let mut invalid_checkpoint = node.clone();
        invalid_checkpoint.applied_actions = Some(FleetApplicationCheckpoint {
            action_count: 0,
            actions_sha256: "not-a-sha256-digest".to_string(),
        });
        for (nodes, expected) in [
            (vec![invalid_id], "node_id"),
            (vec![invalid_checkpoint], "checkpoint"),
            (vec![node.clone(), node.clone()], "repeats node"),
        ] {
            let error = initialization_result(&serde_json::json!({
                "schema_version": FLEET_HTTP_API_SCHEMA,
                "nodes": nodes
            }))
            .expect_err("authenticated invalid nodes must not initialize");
            assert!(
                matches!(&error, FleetTransportError::SerializationError { .. }),
                "{error}"
            );
            assert!(error.to_string().contains(expected), "{error}");
        }
        for nodes in [vec![], vec![node]] {
            initialization_result(&serde_json::json!({
                "schema_version": FLEET_HTTP_API_SCHEMA,
                "nodes": nodes
            }))
            .expect("valid empty and populated coordinators initialize");
        }
    }

    #[test]
    fn fleet_http_action_snapshots_reject_repeated_ids_and_invalid_records() {
        let action = sample_action("snapshot-action", "snapshot-incident");
        let conflict = release_action("snapshot-action", "snapshot-incident");
        let mut invalid_id = action.clone();
        invalid_id.action_id = "../escape".to_string();
        for (actions, expected) in [
            (vec![action.clone(), action], "repeats action_id"),
            (
                vec![
                    sample_action("snapshot-action", "snapshot-incident"),
                    conflict,
                ],
                "repeats action_id",
            ),
            (vec![invalid_id], "action_id"),
        ] {
            assert_snapshot_refused(
                FLEET_HTTP_ACTIONS_PATH,
                &serde_json::json!({
                    "schema_version": FLEET_HTTP_API_SCHEMA,
                    "actions": actions
                }),
                expected,
            );
            assert_snapshot_refused(
                FLEET_HTTP_STATE_PATH,
                &serde_json::json!({
                    "schema_version": FLEET_HTTP_API_SCHEMA,
                    "state": {
                        "schema_version": FLEET_SHARED_STATE_SCHEMA,
                        "actions": actions,
                        "nodes": []
                    }
                }),
                expected,
            );
        }
    }

    #[test]
    fn fleet_http_node_snapshots_reject_repeated_scoped_ids_and_invalid_records() {
        let node = sample_node("snapshot-node");
        let mut conflict = node.clone();
        conflict.health = NodeHealth::Quarantined;
        conflict.quarantine_version = 99;
        let mut invalid_id = node.clone();
        invalid_id.node_id = "../escape".to_string();
        let mut invalid_checkpoint = node.clone();
        invalid_checkpoint.applied_actions = Some(FleetApplicationCheckpoint {
            action_count: 0,
            actions_sha256: "A".repeat(64),
        });
        for (nodes, expected) in [
            (vec![node.clone(), node.clone()], "repeats node"),
            (vec![node, conflict], "repeats node"),
            (vec![invalid_id], "node_id"),
            (vec![invalid_checkpoint], "checkpoint"),
        ] {
            assert_snapshot_refused(
                FLEET_HTTP_NODES_PATH,
                &serde_json::json!({
                    "schema_version": FLEET_HTTP_API_SCHEMA,
                    "nodes": nodes
                }),
                expected,
            );
            assert_snapshot_refused(
                FLEET_HTTP_STATE_PATH,
                &serde_json::json!({
                    "schema_version": FLEET_HTTP_API_SCHEMA,
                    "state": {
                        "schema_version": FLEET_SHARED_STATE_SCHEMA,
                        "actions": [],
                        "nodes": nodes
                    }
                }),
                expected,
            );
        }
    }

    #[test]
    fn fleet_http_snapshots_require_both_http_and_shared_state_schemas() {
        let mut actions = serde_json::json!({
            "schema_version": FLEET_HTTP_API_SCHEMA,
            "actions": []
        });
        let mut nodes = serde_json::json!({
            "schema_version": FLEET_HTTP_API_SCHEMA,
            "nodes": []
        });
        let mut state = serde_json::json!({
            "schema_version": FLEET_HTTP_API_SCHEMA,
            "state": {
                "schema_version": FLEET_SHARED_STATE_SCHEMA,
                "actions": [],
                "nodes": []
            }
        });
        for (path, body) in [
            (FLEET_HTTP_ACTIONS_PATH, &mut actions),
            (FLEET_HTTP_NODES_PATH, &mut nodes),
            (FLEET_HTTP_STATE_PATH, &mut state),
        ] {
            for schema in ["franken-node/fleet-http-api/v1", "future-http-schema"] {
                body["schema_version"] = schema.into();
                assert_snapshot_refused(path, body, FLEET_HTTP_API_SCHEMA);
            }
        }
        let error = initialization_result(&nodes).expect_err("unknown initialization schema");
        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        state["schema_version"] = FLEET_HTTP_API_SCHEMA.into();
        for schema in [
            "franken-node/fleet-transport-state/v1",
            "future-shared-state-schema",
        ] {
            state["state"]["schema_version"] = schema.into();
            assert_snapshot_refused(FLEET_HTTP_STATE_PATH, &state, FLEET_SHARED_STATE_SCHEMA);
        }
    }

    #[test]
    fn fleet_http_snapshots_preserve_action_order_and_sort_node_identity() {
        let timestamp =
            chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("fixed timestamp");
        let mut early = sample_action("action-z", "early-incident");
        early.emitted_at = timestamp - chrono::TimeDelta::seconds(1);
        let mut first = sample_action("action-a", "first-incident");
        first.emitted_at = timestamp;
        let mut second = sample_action("action-b", "second-incident");
        second.emitted_at = timestamp;
        let actions = vec![second, early, first];
        let expected_actions = actions.clone();
        let first_node = sample_node("node-a");
        let second_node = sample_node("node-b");
        let mut other_zone = first_node.clone();
        other_zone.zone_id = "zone-b".to_string();
        let expected_nodes = vec![first_node.clone(), second_node.clone(), other_zone.clone()];
        let nodes = vec![other_zone, second_node, first_node];
        let (origin, peer) = serve_responses([
            json_response(&serde_json::json!({
                "schema_version": FLEET_HTTP_API_SCHEMA,
                "actions": actions
            })),
            json_response(&serde_json::json!({
                "schema_version": FLEET_HTTP_API_SCHEMA,
                "nodes": nodes
            })),
            json_response(&serde_json::json!({
                "schema_version": FLEET_HTTP_API_SCHEMA,
                "state": {
                    "schema_version": FLEET_SHARED_STATE_SCHEMA,
                    "actions": actions,
                    "nodes": nodes
                }
            })),
        ]);
        let client = HttpFleetTransport::new(&origin, TOKEN, Duration::from_secs(5))
            .expect("ordered snapshot client");
        let listed_actions = client.list_actions();
        let listed_nodes = client.list_node_statuses();
        let shared = client.read_shared_state();
        let requests = peer.join().expect("ordered snapshot peer finished");
        assert_eq!(listed_actions.expect("unique actions"), expected_actions);
        assert_eq!(listed_nodes.expect("zone-scoped nodes"), expected_nodes);
        let shared = shared.expect("valid shared state");
        assert_eq!(shared.schema_version, FLEET_SHARED_STATE_SCHEMA);
        assert_eq!(shared.actions, expected_actions);
        assert_eq!(shared.nodes, expected_nodes);
        for (request, path) in requests.iter().zip([
            FLEET_HTTP_ACTIONS_PATH,
            FLEET_HTTP_NODES_PATH,
            FLEET_HTTP_STATE_PATH,
        ]) {
            assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
            assert!(request.contains(&format!("Bearer {TOKEN}")));
        }
    }

    #[test]
    fn fleet_http_snapshot_count_limits_refuse_overflow_without_truncation() {
        // Use distinct valid identities: duplicate or record validation must
        // not accidentally stand in for the count boundary being tested.
        let timestamp =
            chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("fixed timestamp");
        let mut actions: Vec<_> = (0..MAX_ACTION_LOG_ENTRIES)
            .map(|index| {
                let mut action =
                    sample_action(&format!("bounded-action-{index:05}"), "bounded-inc");
                action.emitted_at = timestamp;
                action
            })
            .collect();
        let mut nodes: Vec<_> = (0..MAX_NODES_CAP)
            .map(|index| sample_node(&format!("bounded-node-{index:05}")))
            .collect();
        let (origin, peer) = serve_responses([json_response(&serde_json::json!({
            "schema_version": FLEET_HTTP_API_SCHEMA,
            "state": {
                "schema_version": FLEET_SHARED_STATE_SCHEMA,
                "actions": actions,
                "nodes": nodes
            }
        }))]);
        let client = HttpFleetTransport::new(&origin, TOKEN, Duration::from_secs(5))
            .expect("bounded snapshot client");
        let result = client.read_shared_state();
        peer.join().expect("bounded snapshot peer finished");
        let shared = result.expect("inclusive limits preserve the complete snapshot");
        assert_eq!(shared.actions, actions);
        assert_eq!(shared.nodes, nodes);

        actions.push(sample_action("bounded-action-extra", "bounded-inc-extra"));
        assert_snapshot_refused(
            FLEET_HTTP_ACTIONS_PATH,
            &serde_json::json!({
                "schema_version": FLEET_HTTP_API_SCHEMA,
                "actions": actions
            }),
            "action snapshot exceeds",
        );
        assert_snapshot_refused(
            FLEET_HTTP_STATE_PATH,
            &serde_json::json!({
                "schema_version": FLEET_HTTP_API_SCHEMA,
                "state": {
                    "schema_version": FLEET_SHARED_STATE_SCHEMA,
                    "actions": actions,
                    "nodes": []
                }
            }),
            "action snapshot exceeds",
        );

        nodes.push(sample_node("bounded-node-extra"));
        let node_body = serde_json::json!({
            "schema_version": FLEET_HTTP_API_SCHEMA,
            "nodes": nodes
        });
        assert_snapshot_refused(FLEET_HTTP_NODES_PATH, &node_body, "node snapshot exceeds");
        assert_snapshot_refused(
            FLEET_HTTP_STATE_PATH,
            &serde_json::json!({
                "schema_version": FLEET_HTTP_API_SCHEMA,
                "state": {
                    "schema_version": FLEET_SHARED_STATE_SCHEMA,
                    "actions": [],
                    "nodes": nodes
                }
            }),
            "node snapshot exceeds",
        );
        let error =
            initialization_result(&node_body).expect_err("oversized initialization snapshot");
        assert!(
            matches!(&error, FleetTransportError::SerializationError { .. }),
            "{error}"
        );
        assert!(
            error.to_string().contains("node snapshot exceeds"),
            "{error}"
        );
    }
}
