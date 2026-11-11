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

use std::{collections::BTreeSet, time::Duration};

use chrono::{DateTime, Utc};
use frankenengine_node::capacity_defaults::aliases::{MAX_ACTION_LOG_ENTRIES, MAX_NODES_CAP};
use frankenengine_node::control_plane::fleet_transport::{
    FLEET_SHARED_STATE_SCHEMA, FileFleetTransport, FleetAction, FleetActionRecord,
    FleetNativeDrainEvidence, FleetNativeDrainReadiness, FleetNativeSessionHoldTarget,
    FleetGuardedPolicyObservationScope, FleetGuardedPolicyReceipt, FleetPolicyArtifact,
    FleetPolicyMaintenanceGuard, FleetRuntimePolicy, FleetSharedState, FleetTargetKind,
    FleetTransport, FleetTransportError, GuardedFleetPolicyPublication,
    FLEET_GUARDED_POLICY_RECEIPT_SCHEMA,
    MAX_NATIVE_SESSION_MAINTENANCE_HOLDS, NativeSessionDrainCheckpoint, NativeSessionDrainState,
    NodeHealth, NodeStatus, fleet_action_log_checkpoint, fleet_action_snapshot_prefix,
    fleet_application_checkpoint,
    fleet_native_drain_evidence, fleet_native_session_hold_evidence, fleet_native_session_holds,
    validate_guarded_fleet_policy_publication, validate_node_status,
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
        native_session_drain: None,
    }
}

fn completed_drain(node: &NodeStatus) -> NativeSessionDrainCheckpoint {
    NativeSessionDrainCheckpoint {
        applied_actions: node.applied_actions.clone().expect("applied snapshot"),
        session_set_sha256: "a3".repeat(32),
        admitted_sessions: 2,
        terminal_sessions: 2,
        pending_sessions: 0,
        indeterminate_sessions: 0,
        fence_held: false,
        supervisor_attestation: None,
    }
}

fn maintenance_action(id: &str, zone: &str, resume: Option<&str>) -> FleetActionRecord {
    FleetActionRecord {
        action_id: id.to_owned(),
        emitted_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        action: match resume {
            None => FleetAction::NativeSessionHold {
                zone_id: zone.to_owned(),
                reason: "operator maintenance".to_owned(),
            },
            Some(owner) => FleetAction::NativeSessionResume {
                zone_id: zone.to_owned(),
                hold_action_id: owner.to_owned(),
                reason: None,
            },
        },
    }
}

fn acknowledge_maintenance(state: &mut FleetSharedState, now: DateTime<Utc>) {
    for node in &mut state.nodes {
        if node.zone_id != "zone-a" {
            continue;
        }
        let holds = fleet_native_session_holds(&state.actions, &node.zone_id).unwrap();
        node.last_seen = now;
        node.applied_actions =
            Some(fleet_application_checkpoint(&state.actions, &node.zone_id).unwrap());
        node.health = if holds.is_empty() {
            NodeHealth::Healthy
        } else {
            NodeHealth::Maintenance
        };
        let mut drain = completed_drain(node);
        drain.fence_held = !holds.is_empty();
        node.native_session_drain = Some(drain);
    }
}

fn maintenance_state() -> (FleetSharedState, DateTime<Utc>) {
    let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut unrelated = sample_action("outside-action", "outside-incident");
    if let FleetAction::Quarantine { zone_id, .. } = &mut unrelated.action {
        *zone_id = "zone-b".to_owned();
    }
    let mut outside = sample_node("outside-node");
    outside.zone_id = "zone-b".to_owned();
    outside.health = NodeHealth::Degraded;
    outside.last_seen = now - chrono::TimeDelta::hours(1);
    let mut state = FleetSharedState {
        schema_version: FLEET_SHARED_STATE_SCHEMA.to_owned(),
        actions: vec![
            maintenance_action("hold-a", "zone-a", None),
            maintenance_action("hold-b", "zone-a", None),
            unrelated,
        ],
        nodes: vec![sample_node("node-b"), sample_node("node-a"), outside],
    };
    acknowledge_maintenance(&mut state, now);
    (state, now)
}

fn guarded_policy_request(state: &FleetSharedState, id: &str) -> GuardedFleetPolicyPublication {
    let artifact = FleetPolicyArtifact::new(
        1,
        FleetRuntimePolicy {
            block_private_network: true,
            ..FleetRuntimePolicy::default()
        },
    )
    .unwrap();
    GuardedFleetPolicyPublication {
        action: FleetActionRecord {
            action_id: id.to_owned(),
            emitted_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            action: FleetAction::PolicyUpdate {
                zone_id: "zone-a".to_owned(),
                policy_version: "guarded-revision-1".to_owned(),
                changed_fields: vec!["block_private_network".to_owned()],
                artifact: Some(artifact),
            },
        },
        guard: FleetPolicyMaintenanceGuard {
            hold_action_id: "hold-a".to_owned(),
            expected_action_log: fleet_action_log_checkpoint(&state.actions).unwrap(),
            required_nodes: state
                .nodes
                .iter()
                .filter(|node| node.zone_id == "zone-a")
                .map(|node| (node.zone_id.clone(), node.node_id.clone()))
                .collect(),
            stale_after: Duration::from_secs(30),
        },
    }
}

#[test]
fn guarded_policy_full_log_checkpoint_covers_concrete_zones_and_append_order() {
    let (state, now) = maintenance_state();
    let request = guarded_policy_request(&state, "guarded-policy");
    assert_eq!(request.guard.expected_action_log.action_count, 3);
    assert_eq!(fleet_application_checkpoint(&state.actions, "all").unwrap().action_count, 0);
    let evidence = validate_guarded_fleet_policy_publication(
        &request, &state, now, Duration::from_secs(30),
    ).unwrap();
    assert!(evidence.complete);
    assert_eq!(evidence.nodes.len(), 2);
    let mut changed = state.clone();
    if let FleetAction::Quarantine { reason, .. } = &mut changed.actions[2].action {
        *reason = "different concrete-zone history".to_owned();
    }
    assert_eq!(
        fleet_application_checkpoint(&changed.actions, "all").unwrap(),
        fleet_application_checkpoint(&state.actions, "all").unwrap(),
    );
    assert_ne!(fleet_action_log_checkpoint(&changed.actions).unwrap(), request.guard.expected_action_log);
    assert!(validate_guarded_fleet_policy_publication(&request, &changed, now, Duration::from_secs(30)).is_err());
    changed.actions.swap(0, 1);
    assert_ne!(fleet_action_log_checkpoint(&changed.actions).unwrap(), request.guard.expected_action_log);
    changed.actions.push(changed.actions[0].clone());
    assert!(fleet_action_log_checkpoint(&changed.actions).is_err());
}

#[test]
fn guarded_policy_requires_exact_held_scope_and_current_fresh_participants() {
    let (state, now) = maintenance_state();
    let request = guarded_policy_request(&state, "guarded-policy");
    for invalid in [
        {
            let mut changed = state.clone();
            changed.nodes.retain(|node| node.node_id != "node-a");
            changed
        },
        {
            let mut changed = state.clone();
            changed.nodes[0].last_seen = now + chrono::TimeDelta::nanoseconds(1);
            changed
        },
        {
            let mut changed = state.clone();
            changed.nodes[0].last_seen = now - chrono::TimeDelta::seconds(30);
            changed
        },
        {
            let mut changed = state.clone();
            let node = &mut changed.nodes[0];
            node.health = NodeHealth::Degraded;
            node.applied_actions = None;
            let drain = node.native_session_drain.as_mut().unwrap();
            drain.terminal_sessions -= 1;
            drain.pending_sessions = 1;
            changed
        },
        {
            let mut changed = state.clone();
            let node = &mut changed.nodes[0];
            node.health = NodeHealth::Degraded;
            node.applied_actions = None;
            let drain = node.native_session_drain.as_mut().unwrap();
            drain.terminal_sessions -= 1;
            drain.indeterminate_sessions = 1;
            changed
        },
    ] {
        assert!(validate_guarded_fleet_policy_publication(&request, &invalid, now, Duration::from_secs(30)).is_err());
    }
    let mut stale_under_server_policy = state.clone();
    stale_under_server_policy.nodes[0].last_seen = now - chrono::TimeDelta::seconds(10);
    assert!(validate_guarded_fleet_policy_publication(&request, &stale_under_server_policy, now, Duration::from_secs(10)).is_err());
    assert!(validate_guarded_fleet_policy_publication(&request, &state, now, Duration::ZERO).is_err());

    let mut wrong_scope = request.clone();
    if let FleetAction::PolicyUpdate { zone_id, .. } = &mut wrong_scope.action.action {
        *zone_id = "all".to_owned();
    }
    assert!(validate_guarded_fleet_policy_publication(&wrong_scope, &state, now, Duration::from_secs(30)).is_err());
    let mut resumed = state.clone();
    resumed.actions.push(maintenance_action("resume-a", "zone-a", Some("hold-a")));
    acknowledge_maintenance(&mut resumed, now);
    let request = guarded_policy_request(&resumed, "guarded-policy");
    assert!(validate_guarded_fleet_policy_publication(&request, &resumed, now, Duration::from_secs(30)).is_err(),
        "another owner's held fence cannot substitute for the requested owner");
}

#[test]
fn guarded_policy_receipt_rejects_contradictory_evidence_and_bounded_payload_overflow() {
    let (state, now) = maintenance_state();
    let request = guarded_policy_request(&state, "guarded-policy");
    let receipt = FleetGuardedPolicyReceipt {
        schema_version: FLEET_GUARDED_POLICY_RECEIPT_SCHEMA.to_owned(),
        action: request.action.clone(),
        guard: request.guard.clone(),
        evidence: validate_guarded_fleet_policy_publication(&request, &state, now, Duration::from_secs(20)).unwrap(),
        accepted_at: now,
        observation_scope: FleetGuardedPolicyObservationScope::LocalSupervisorObservations,
        already_published: false,
        fleet_quiescence_certified: false,
    };
    receipt.validate().unwrap();
    assert_eq!(receipt.evidence.stale_after, Duration::from_secs(20));
    let encoded = serde_json::to_vec(&receipt).unwrap();
    assert_eq!(serde_json::from_slice::<FleetGuardedPolicyReceipt>(&encoded).unwrap(), receipt);
    for invalid in [
        { let mut value = receipt.clone(); value.evidence.nodes.pop(); value },
        { let mut value = receipt.clone(); value.evidence.nodes[0].native_session_drain.as_mut().unwrap().fence_held = false; value },
        { let mut value = receipt.clone(); value.evidence.nodes[0].active_hold_ids = vec!["hold-b".into()]; value },
        { let mut value = receipt.clone(); value.evidence.nodes[0].last_seen = Some(now + chrono::TimeDelta::nanoseconds(1)); value },
        { let mut value = receipt.clone(); value.evidence.action_count += 1; value },
        { let mut value = receipt.clone(); value.evidence.target = FleetNativeSessionHoldTarget::Resumed; value },
        { let mut value = receipt.clone(); value.fleet_quiescence_certified = true; value },
    ] {
        assert!(invalid.validate().is_err());
    }
    for threshold in [Duration::ZERO, Duration::from_secs(301)] {
        let mut invalid = request.clone();
        invalid.guard.stale_after = threshold;
        assert!(invalid.validate().is_err());
    }
    let mut oversized_request = request.clone();
    let long_zone = "z".repeat(128);
    if let FleetAction::PolicyUpdate { zone_id, .. } = &mut oversized_request.action.action {
        *zone_id = long_zone.clone();
    }
    oversized_request.guard.required_nodes = (0..2_500)
        .map(|n| (long_zone.clone(), format!("{n:05}{}", "n".repeat(123))))
        .collect();
    assert!(oversized_request.validate().unwrap_err().to_string().contains("byte bound"));

    let mut oversized_receipt = receipt;
    oversized_receipt.guard.required_nodes.clear();
    let mut node = oversized_receipt.evidence.nodes[0].clone();
    node.active_hold_ids = (0..63)
        .map(|n| format!("{n:03}{}", "h".repeat(125)))
        .chain(std::iter::once("hold-a".to_owned()))
        .collect();
    oversized_receipt.evidence.nodes = (0..1_200)
        .map(|n| { let mut node = node.clone(); node.node_id = format!("node-{n:05}"); node })
        .collect();
    assert!(oversized_receipt.validate().unwrap_err().to_string().contains("byte bound"));
}

fn seed_guarded_policy_transport(
    path: &std::path::Path,
    state: &FleetSharedState,
) -> DurableFleetTransport {
    let mut transport = DurableFleetTransport::new(path).unwrap();
    transport.initialize().unwrap();
    for action in &state.actions {
        transport.publish_action(action).unwrap();
    }
    for node in &state.nodes {
        transport.upsert_node_status(node).unwrap();
    }
    transport
}

#[test]
fn guarded_policy_durable_retry_preserves_original_admission_after_resume_and_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let (state, now) = maintenance_state();
    let request = guarded_policy_request(&state, "guarded-policy");
    let mut transport = seed_guarded_policy_transport(temp.path(), &state);
    let receipt = transport.publish_policy_with_maintenance_guard_projected(
        &request,
        FleetGuardedPolicyObservationScope::LocalSupervisorObservations,
        Duration::from_secs(20),
        || now,
        |_| Ok(()),
    ).unwrap();
    receipt.validate().unwrap();
    assert!(!receipt.already_published);
    assert_eq!(receipt.guard, request.guard);
    assert_eq!(receipt.evidence.stale_after, Duration::from_secs(20));
    assert_eq!(transport.list_actions().unwrap().last(), Some(&request.action));
    drop(transport);

    let mut transport = DurableFleetTransport::new(temp.path()).unwrap();
    transport.initialize().unwrap();
    transport.publish_action(&maintenance_action("resume-a", "zone-a", Some("hold-a"))).unwrap();
    let mut retry = request.clone();
    retry.guard.expected_action_log = fleet_action_log_checkpoint(&transport.list_actions().unwrap()).unwrap();
    retry.guard.stale_after = Duration::from_secs(1);
    retry.guard.required_nodes.insert(("zone-a".to_owned(), "newly-missing".to_owned()));
    let repeated = transport.publish_policy_with_maintenance_guard_projected(
        &retry,
        FleetGuardedPolicyObservationScope::LocalSupervisorObservations,
        Duration::from_secs(1),
        || panic!("a retry must not manufacture a new observation"),
        |_| panic!("a retry must use its original persisted evidence"),
    ).unwrap();
    let mut expected = receipt;
    expected.already_published = true;
    assert_eq!(repeated, expected);
    assert_eq!(transport.list_actions().unwrap().len(), state.actions.len() + 2);
    for conflict in [
        { let mut changed = retry.clone(); changed.action.emitted_at += chrono::TimeDelta::seconds(1); changed },
        { let mut changed = retry.clone(); changed.guard.hold_action_id = "hold-b".to_owned(); changed },
    ] {
        assert!(matches!(transport.publish_policy_with_maintenance_guard(&conflict), Err(FleetTransportError::ActionConflict { .. })));
    }
}

#[test]
fn guarded_policy_durable_refusals_leave_actions_and_receipts_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let (state, now) = maintenance_state();
    let request = guarded_policy_request(&state, "guarded-policy");
    let mut transport = seed_guarded_policy_transport(temp.path(), &state);
    let result = transport.publish_policy_with_maintenance_guard_projected(
        &request,
        FleetGuardedPolicyObservationScope::EnrolledNodeObservations,
        Duration::from_secs(30),
        || now,
        |nodes| {
            let mut unseen = sample_node("enrolled-but-unseen");
            unseen.last_seen = DateTime::<Utc>::UNIX_EPOCH;
            unseen.health = NodeHealth::Stale;
            nodes.push(unseen);
            Ok(())
        },
    );
    assert!(result.is_err(), "an unobserved enrolled participant must block publication");
    assert_eq!(transport.list_actions().unwrap(), state.actions);
    let connection = Connection::open(temp.path().join(FLEET_DB_FILE).to_string_lossy().as_ref()).unwrap();
    let rows = connection.query("SELECT COUNT(*) FROM fleet_guarded_policy_publications;").unwrap();
    assert_eq!(rows[0].values(), &[SqliteValue::Integer(0)]);
    drop(connection);

    let mut changed = sample_action("concurrent-other-zone", "outside-two");
    if let FleetAction::Quarantine { zone_id, .. } = &mut changed.action {
        *zone_id = "zone-b".to_owned();
    }
    transport.publish_action(&changed).unwrap();
    assert!(transport.publish_policy_with_maintenance_guard_projected(
        &request,
        FleetGuardedPolicyObservationScope::LocalSupervisorObservations,
        Duration::from_secs(30),
        || now,
        |_| Ok(()),
    ).is_err());
    assert_eq!(transport.list_actions().unwrap().len(), state.actions.len() + 1);

    // A formerly unguarded action cannot acquire a fabricated historical guard.
    transport.publish_action(&request.action).unwrap();
    let mut existing = request;
    existing.guard.expected_action_log = fleet_action_log_checkpoint(&transport.list_actions().unwrap()).unwrap();
    assert!(matches!(transport.publish_policy_with_maintenance_guard_projected(
        &existing,
        FleetGuardedPolicyObservationScope::LocalSupervisorObservations,
        Duration::from_secs(30),
        || now,
        |_| Ok(()),
    ), Err(FleetTransportError::ActionConflict { .. })));
    let connection = Connection::open(temp.path().join(FLEET_DB_FILE).to_string_lossy().as_ref()).unwrap();
    let rows = connection.query("SELECT COUNT(*) FROM fleet_guarded_policy_publications;").unwrap();
    assert_eq!(rows[0].values(), &[SqliteValue::Integer(0)]);
}

#[test]
fn guarded_policy_serializes_concurrent_node_and_action_mutations() {
    use std::sync::mpsc;
    for action_mutation in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (mut state, _) = maintenance_state();
        acknowledge_maintenance(&mut state, Utc::now());
        let request = guarded_policy_request(&state, "guarded-policy");
        drop(seed_guarded_policy_transport(temp.path(), &state));
        let (guard_ready_tx, guard_ready_rx) = mpsc::channel();
        let (writer_ready_tx, writer_ready_rx) = mpsc::channel();
        let (guard_start_tx, guard_start_rx) = mpsc::channel();
        let (writer_start_tx, writer_start_rx) = mpsc::channel();
        let (snapshot_tx, snapshot_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (writer_result_tx, writer_result_rx) = mpsc::channel();
        let guard_path = temp.path().to_owned();
        let request_for_guard = request.clone();
        let guard = std::thread::spawn(move || {
            let mut transport = DurableFleetTransport::new(guard_path).unwrap();
            transport.initialize().unwrap();
            guard_ready_tx.send(()).unwrap();
            guard_start_rx.recv().unwrap();
            let first = std::cell::Cell::new(true);
            transport.publish_policy_with_maintenance_guard_projected(
                &request_for_guard,
                FleetGuardedPolicyObservationScope::LocalSupervisorObservations,
                Duration::from_secs(30),
                Utc::now,
                |_| {
                    if first.replace(false) {
                        snapshot_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    }
                    Ok(())
                },
            )
        });
        let writer_path = temp.path().to_owned();
        let mut degraded = state.nodes[0].clone();
        degraded.health = NodeHealth::Degraded;
        degraded.applied_actions = None;
        let writer = std::thread::spawn(move || {
            let mut transport = DurableFleetTransport::new(writer_path).unwrap();
            transport.initialize().unwrap();
            writer_ready_tx.send(()).unwrap();
            writer_start_rx.recv().unwrap();
            let result = if action_mutation {
                let mut action = sample_action("racing-other-zone", "racing-incident");
                if let FleetAction::Quarantine { zone_id, .. } = &mut action.action {
                    *zone_id = "zone-b".to_owned();
                }
                transport.publish_action(&action)
            } else {
                transport.upsert_node_status(&degraded)
            };
            writer_result_tx.send(result.is_ok()).unwrap();
            result
        });
        guard_ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        writer_ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        guard_start_tx.send(()).unwrap();
        snapshot_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        writer_start_tx.send(()).unwrap();
        // Both legitimate storage models are accepted: the common row can
        // block the second writer, or let it win and abort the older snapshot.
        // It must never let that older snapshot commit after the writer wins.
        let writer_won_before_guard_commit = writer_result_rx
            .recv_timeout(Duration::from_millis(200))
            .unwrap_or(false);
        release_tx.send(()).unwrap();
        let guarded = guard.join().unwrap();
        writer.join().unwrap().expect("concurrent mutation eventually commits");
        let mut transport = DurableFleetTransport::new(temp.path()).unwrap();
        transport.initialize().unwrap();
        let published = transport.list_actions().unwrap().iter().any(|action| action.action_id == request.action.action_id);
        if writer_won_before_guard_commit {
            assert!(guarded.is_err(), "a stale snapshot committed after a conflicting node/action mutation");
            assert!(!published);
        } else {
            assert_eq!(published, guarded.is_ok());
        }
        if let Ok(receipt) = guarded {
            receipt.validate().unwrap();
            assert_eq!(receipt.guard, request.guard);
        }
    }
}

#[test]
fn native_session_hold_owners_compose_and_require_a_known_exact_prior_zone() {
    let mut actions = vec![
        maintenance_action("global", "all", None),
        maintenance_action("east", "zone-a", None),
    ];
    assert_eq!(
        fleet_native_session_holds(&actions, "zone-a").unwrap(),
        BTreeSet::from(["east".to_owned(), "global".to_owned()])
    );
    assert_eq!(
        fleet_native_session_holds(&actions, "zone-b").unwrap(),
        BTreeSet::from(["global".to_owned()])
    );
    actions.push(maintenance_action("resume-global", "all", Some("global")));
    actions.push(maintenance_action(
        "resume-global-again",
        "all",
        Some("global"),
    ));
    assert_eq!(
        fleet_native_session_holds(&actions, "zone-a").unwrap(),
        BTreeSet::from(["east".to_owned()])
    );
    assert!(
        fleet_native_session_holds(&actions, "zone-b")
            .unwrap()
            .is_empty()
    );
    for bad in [
        maintenance_action("future", "zone-a", Some("not-yet-held")),
        maintenance_action("wrong-zone", "zone-a", Some("global")),
        maintenance_action("not-a-hold", "all", Some("resume-global")),
    ] {
        let mut invalid = actions.clone();
        invalid.push(bad);
        assert!(fleet_native_session_holds(&invalid, "zone-b").is_err());
        assert!(
            fleet_application_checkpoint(&invalid, "zone-b").is_err(),
            "unrelated scopes do not hide malformed history"
        );
    }
    let forward = vec![
        maintenance_action("resume-first", "zone-a", Some("future-hold")),
        maintenance_action("future-hold", "zone-a", None),
    ];
    assert!(fleet_native_session_holds(&forward, "zone-a").is_err());
    let mut bounded: Vec<_> = (0..MAX_NATIVE_SESSION_MAINTENANCE_HOLDS)
        .map(|n| maintenance_action(&format!("owner-{n}"), "all", None))
        .collect();
    assert_eq!(
        fleet_native_session_holds(&bounded, "zone-a")
            .unwrap()
            .len(),
        MAX_NATIVE_SESSION_MAINTENANCE_HOLDS
    );
    bounded.push(maintenance_action("one-too-many", "zone-a", None));
    assert!(fleet_native_session_holds(&bounded, "zone-a").is_err());
    bounded.pop();
    bounded.push(maintenance_action("release-slot", "all", Some("owner-0")));
    bounded.push(maintenance_action("replacement-owner", "zone-a", None));
    assert_eq!(
        fleet_native_session_holds(&bounded, "zone-a")
            .unwrap()
            .len(),
        MAX_NATIVE_SESSION_MAINTENANCE_HOLDS
    );
}

#[test]
fn native_session_hold_publication_rejects_invalid_resume_without_mutating_either_store() {
    for durable in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut transport: Box<dyn FleetTransport> = if durable {
            Box::new(DurableFleetTransport::new(directory.path()).unwrap())
        } else {
            Box::new(FileFleetTransport::new(directory.path()))
        };
        transport.initialize().unwrap();
        assert!(
            transport
                .publish_action(&maintenance_action("forward", "zone-a", Some("hold")))
                .is_err()
        );
        assert!(transport.list_actions().unwrap().is_empty());
        let hold = maintenance_action("hold", "all", None);
        transport.publish_action(&hold).unwrap();
        transport.publish_action(&hold).unwrap();
        assert!(
            transport
                .publish_action(&maintenance_action("wrong-zone", "zone-a", Some("hold")))
                .is_err()
        );
        assert_eq!(transport.list_actions().unwrap(), vec![hold.clone()]);
        let resume = maintenance_action("resume", "all", Some("hold"));
        transport.publish_action(&resume).unwrap();
        transport.publish_action(&resume).unwrap();
        assert_eq!(transport.list_actions().unwrap(), vec![hold, resume]);
        assert!(
            fleet_native_session_holds(&transport.list_actions().unwrap(), "zone-a")
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn native_session_maintenance_acknowledgement_requires_exact_held_terminal_population() {
    let (state, _) = maintenance_state();
    let valid = state.nodes[0].clone();
    validate_node_status(&valid).unwrap();
    let mut invalid = Vec::new();
    let mut missing = valid.clone();
    missing.applied_actions = None;
    invalid.push(missing);
    let mut missing = valid.clone();
    missing.native_session_drain = None;
    invalid.push(missing);
    let mut opened = valid.clone();
    opened.native_session_drain.as_mut().unwrap().fence_held = false;
    invalid.push(opened);
    let mut healthy = valid.clone();
    healthy.health = NodeHealth::Healthy;
    invalid.push(healthy);
    let mut pending = valid.clone();
    pending
        .native_session_drain
        .as_mut()
        .unwrap()
        .terminal_sessions = 1;
    pending
        .native_session_drain
        .as_mut()
        .unwrap()
        .pending_sessions = 1;
    invalid.push(pending);
    let mut unknown = valid.clone();
    unknown
        .native_session_drain
        .as_mut()
        .unwrap()
        .terminal_sessions = 1;
    unknown
        .native_session_drain
        .as_mut()
        .unwrap()
        .indeterminate_sessions = 1;
    invalid.push(unknown);
    for node in invalid {
        assert!(validate_node_status(&node).is_err());
    }
}

#[test]
fn native_session_hold_evidence_scopes_exact_owners_and_preserves_other_holds_on_resume() {
    let (mut state, now) = maintenance_state();
    let observe = |state: &FleetSharedState, target| {
        fleet_native_session_hold_evidence(
            state,
            "hold-a",
            target,
            &BTreeSet::new(),
            now,
            Duration::from_secs(30),
        )
        .unwrap()
    };
    let held = observe(&state, FleetNativeSessionHoldTarget::Held);
    assert!(held.complete);
    assert!(!held.admission_resumed);
    assert!(!held.fleet_quiescence_certified);
    assert_eq!(held.hold_zone_id, "zone-a");
    assert_eq!(
        held.nodes.len(),
        2,
        "unrelated stale zone does not block this hold"
    );
    assert_eq!(held.nodes[0].node_id, "node-a");
    assert_eq!(held.nodes[0].active_hold_ids, vec!["hold-a", "hold-b"]);
    assert!(
        held.nodes
            .iter()
            .all(|node| node.ready && !node.admission_resumed)
    );
    assert!(!observe(&state, FleetNativeSessionHoldTarget::Resumed).complete);
    assert!(
        !fleet_native_drain_evidence(&state, &BTreeSet::new(), now, Duration::from_secs(30))
            .unwrap()
            .complete
    );

    state
        .actions
        .push(maintenance_action("resume-a", "zone-a", Some("hold-a")));
    assert!(
        !observe(&state, FleetNativeSessionHoldTarget::Resumed).complete,
        "older checkpoints cannot confirm a new resume"
    );
    acknowledge_maintenance(&mut state, now);
    let remaining = observe(&state, FleetNativeSessionHoldTarget::Resumed);
    assert!(remaining.complete);
    assert!(!remaining.admission_resumed);
    assert_eq!(remaining.nodes[0].active_hold_ids, vec!["hold-b"]);
    assert_eq!(remaining.nodes[0].health, Some(NodeHealth::Maintenance));
    assert!(!observe(&state, FleetNativeSessionHoldTarget::Held).complete);

    state
        .actions
        .push(maintenance_action("resume-b", "zone-a", Some("hold-b")));
    acknowledge_maintenance(&mut state, now);
    let resumed = observe(&state, FleetNativeSessionHoldTarget::Resumed);
    assert!(resumed.complete);
    assert!(resumed.admission_resumed);
    assert!(
        resumed
            .nodes
            .iter()
            .all(|node| node.active_hold_ids.is_empty() && node.admission_resumed)
    );
    let encoded = serde_json::to_value(&resumed).unwrap();
    assert_eq!(encoded["target"], "resumed");
    assert_eq!(
        encoded["stale_after"],
        serde_json::json!({"secs":30,"nanos":0})
    );
}

#[test]
fn native_session_hold_evidence_retains_missing_identities_and_refuses_incomplete_observations() {
    let (base, now) = maintenance_state();
    let required: BTreeSet<_> = base
        .nodes
        .iter()
        .filter(|node| node.zone_id == "zone-a")
        .map(|node| (node.zone_id.clone(), node.node_id.clone()))
        .collect();
    let observe = |state: &FleetSharedState| {
        fleet_native_session_hold_evidence(
            state,
            "hold-a",
            FleetNativeSessionHoldTarget::Held,
            &required,
            now,
            Duration::from_secs(30),
        )
        .unwrap()
    };
    let mut renamed = base.clone();
    renamed.nodes[0].node_id = "replacement".to_owned();
    let lost = observe(&renamed);
    assert!(!lost.complete);
    assert!(
        lost.nodes
            .iter()
            .any(|node| node.reason == FleetNativeDrainReadiness::MissingNode)
    );
    assert_eq!(lost.nodes.len(), 3);
    for (last_seen, reason) in [
        (
            now - chrono::TimeDelta::seconds(30),
            FleetNativeDrainReadiness::StaleHeartbeat,
        ),
        (
            now + chrono::TimeDelta::nanoseconds(1),
            FleetNativeDrainReadiness::FutureHeartbeat,
        ),
    ] {
        let mut state = base.clone();
        state.nodes[0].last_seen = last_seen;
        let evidence = observe(&state);
        assert!(!evidence.complete);
        assert!(evidence.nodes.iter().any(|node| node.reason == reason));
    }
    for indeterminate in [false, true] {
        let mut state = base.clone();
        let node = &mut state.nodes[0];
        node.health = NodeHealth::Degraded;
        node.applied_actions = None;
        let drain = node.native_session_drain.as_mut().unwrap();
        drain.terminal_sessions = 1;
        drain.pending_sessions = u64::from(!indeterminate);
        drain.indeterminate_sessions = u64::from(indeterminate);
        assert!(!observe(&state).complete);
    }
    let mut opened = base.clone();
    opened.nodes[0].health = NodeHealth::Healthy;
    opened.nodes[0]
        .native_session_drain
        .as_mut()
        .unwrap()
        .fence_held = false;
    assert!(
        observe(&opened)
            .nodes
            .iter()
            .any(|node| node.reason == FleetNativeDrainReadiness::MaintenanceFenceMissing)
    );
    let mut empty = base.clone();
    empty.nodes.clear();
    assert!(!observe(&empty).complete);
    let no_nodes = fleet_native_session_hold_evidence(
        &empty,
        "hold-a",
        FleetNativeSessionHoldTarget::Held,
        &BTreeSet::new(),
        now,
        Duration::from_secs(30),
    )
    .unwrap();
    assert!(!no_nodes.complete);
    assert_eq!(no_nodes.uncovered_zones, vec!["zone-a"]);
    assert!(
        fleet_native_session_hold_evidence(
            &base,
            "outside-action",
            FleetNativeSessionHoldTarget::Held,
            &BTreeSet::new(),
            now,
            Duration::from_secs(30)
        )
        .is_err()
    );
    assert!(
        fleet_native_session_hold_evidence(
            &base,
            "hold-a",
            FleetNativeSessionHoldTarget::Held,
            &BTreeSet::from([("zone-b".to_owned(), "wrong-audience".to_owned())]),
            now,
            Duration::from_secs(30)
        )
        .is_err()
    );
}

fn complete_native_drain_state() -> (FleetSharedState, DateTime<Utc>) {
    let now = DateTime::from_timestamp(1_800_000_000, 0).expect("fixed observation time");
    let mut wildcard = sample_action("drain-all", "drain-all-incident");
    wildcard.emitted_at = now - chrono::TimeDelta::seconds(10);
    if let FleetAction::Quarantine { zone_id, .. } = &mut wildcard.action {
        *zone_id = "all".to_string();
    }
    let mut scoped = sample_action("drain-scoped", "drain-scoped-incident");
    scoped.emitted_at = now - chrono::TimeDelta::seconds(5);
    let actions = vec![wildcard, scoped];
    // The same node ID in two concrete zones is two distinct participants.
    // Reverse input order so the report must establish canonical ordering.
    let nodes = ["zone-b", "zone-a"]
        .into_iter()
        .map(|zone| {
            let mut node = sample_node("shared-node");
            node.zone_id = zone.to_string();
            node.last_seen = now - chrono::TimeDelta::seconds(1);
            node.applied_actions =
                Some(fleet_application_checkpoint(&actions, zone).expect("checkpoint"));
            node.native_session_drain = Some(completed_drain(&node));
            node
        })
        .collect();
    (
        FleetSharedState {
            schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions,
            nodes,
        },
        now,
    )
}

#[test]
fn native_drain_evidence_requires_current_populations_and_preserves_observation_scope() {
    let (state, now) = complete_native_drain_state();
    let original = state.clone();
    let evidence =
        fleet_native_drain_evidence(&state, &BTreeSet::new(), now, Duration::from_secs(30))
            .expect("complete native drain observations");
    assert!(evidence.complete);
    assert!(!evidence.fleet_quiescence_certified);
    assert_eq!(
        evidence.schema_version,
        "franken-node/fleet-native-drain-evidence/v1"
    );
    assert_eq!(evidence.scope, "local_supervisor_drain_observations");
    assert_eq!(evidence.observed_at, now);
    assert_eq!(evidence.action_count, 2);
    assert!(evidence.uncovered_zones.is_empty());
    assert_eq!(
        evidence
            .nodes
            .iter()
            .map(|node| (node.zone_id.as_str(), node.node_id.as_str()))
            .collect::<Vec<_>>(),
        vec![("zone-a", "shared-node"), ("zone-b", "shared-node")]
    );
    assert_eq!(evidence.nodes[0].expected_actions.action_count, 2);
    assert_eq!(evidence.nodes[1].expected_actions.action_count, 1);
    for node in &evidence.nodes {
        assert!(node.ready);
        assert_eq!(node.reason, FleetNativeDrainReadiness::Ready);
        assert_eq!(node.applied_actions.as_ref(), Some(&node.expected_actions));
        assert!(node.native_session_drain.as_ref().unwrap().is_complete());
    }
    let json = serde_json::to_value(&evidence).expect("serialize complete evidence");
    assert_eq!(
        json["stale_after"],
        serde_json::json!({"secs": 30, "nanos": 0})
    );
    let restored: FleetNativeDrainEvidence =
        serde_json::from_value(json).expect("restore the exact evidence");
    assert_eq!(restored, evidence);
    assert_eq!(
        state, original,
        "observing the gate never mutates fleet state"
    );
}

#[test]
fn native_drain_evidence_keeps_legacy_pending_and_indeterminate_nodes_unready() {
    let (base, now) = complete_native_drain_state();
    let mut cases = Vec::new();

    let mut legacy = base.nodes[0].clone();
    legacy.native_session_drain = None;
    cases.push((
        legacy.clone(),
        FleetNativeDrainReadiness::MissingNativeDrain,
    ));
    legacy.applied_actions = None;
    cases.push((
        legacy.clone(),
        FleetNativeDrainReadiness::MissingApplicationCheckpoint,
    ));
    legacy.health = NodeHealth::Degraded;
    cases.push((legacy, FleetNativeDrainReadiness::NodeUnhealthy));

    let mut pending = base.nodes[0].clone();
    pending.health = NodeHealth::Degraded;
    pending.applied_actions = None;
    let drain = pending.native_session_drain.as_mut().unwrap();
    drain.terminal_sessions = 1;
    drain.pending_sessions = 1;
    drain.fence_held = true;
    cases.push((pending.clone(), FleetNativeDrainReadiness::PendingSessions));

    let mut indeterminate = pending.clone();
    let drain = indeterminate.native_session_drain.as_mut().unwrap();
    drain.pending_sessions = 0;
    drain.indeterminate_sessions = 1;
    cases.push((
        indeterminate,
        FleetNativeDrainReadiness::IndeterminateSessions,
    ));

    let mut fenced = pending;
    let drain = fenced.native_session_drain.as_mut().unwrap();
    drain.terminal_sessions = 2;
    drain.pending_sessions = 0;
    cases.push((fenced, FleetNativeDrainReadiness::AdmissionFenced));

    for (node, expected_reason) in cases {
        let mut state = base.clone();
        state.nodes[0] = node;
        let evidence =
            fleet_native_drain_evidence(&state, &BTreeSet::new(), now, Duration::from_secs(30))
                .expect("valid incomplete local observations");
        assert!(!evidence.complete, "{expected_reason:?}");
        assert!(
            evidence.nodes[0].ready,
            "the independent node is still accounted for"
        );
        assert!(!evidence.nodes[1].ready);
        assert_eq!(evidence.nodes[1].reason, expected_reason);
        assert_eq!(
            evidence.nodes[1].native_session_drain,
            state.nodes[0].native_session_drain
        );
    }
}

#[test]
fn native_drain_evidence_rejects_stale_and_future_heartbeats_at_exact_boundaries() {
    let (base, now) = complete_native_drain_state();
    for (last_seen, expected) in [
        (now, FleetNativeDrainReadiness::Ready),
        (
            now - chrono::TimeDelta::milliseconds(29_999),
            FleetNativeDrainReadiness::Ready,
        ),
        (
            now - chrono::TimeDelta::seconds(30),
            FleetNativeDrainReadiness::StaleHeartbeat,
        ),
        (
            now + chrono::TimeDelta::nanoseconds(1),
            FleetNativeDrainReadiness::FutureHeartbeat,
        ),
    ] {
        let mut state = base.clone();
        state.nodes[0].last_seen = last_seen;
        let evidence =
            fleet_native_drain_evidence(&state, &BTreeSet::new(), now, Duration::from_secs(30))
                .expect("bounded heartbeat observation");
        assert_eq!(evidence.nodes[1].reason, expected);
        assert_eq!(
            evidence.complete,
            expected == FleetNativeDrainReadiness::Ready
        );
    }
    for threshold in [Duration::ZERO, Duration::MAX] {
        assert!(fleet_native_drain_evidence(&base, &BTreeSet::new(), now, threshold).is_err());
    }
}

#[test]
fn native_drain_evidence_requires_new_acknowledgements_after_action_changes() {
    let (base, now) = complete_native_drain_state();
    let mut appended = base.clone();
    let mut next = sample_action("drain-new", "drain-new-incident");
    next.emitted_at = now - chrono::TimeDelta::seconds(60);
    if let FleetAction::Quarantine { zone_id, .. } = &mut next.action {
        *zone_id = "all".to_string();
    }
    appended.actions.push(next);

    let mut rewritten = base.clone();
    if let FleetAction::Quarantine { reason, .. } = &mut rewritten.actions[0].action {
        *reason = "different operator instruction".to_string();
    }
    let mut reordered = base.clone();
    reordered.actions.swap(0, 1);
    for state in [&appended, &rewritten, &reordered] {
        let evidence =
            fleet_native_drain_evidence(state, &BTreeSet::new(), now, Duration::from_secs(30))
                .expect("old acknowledgements remain visible");
        assert!(!evidence.complete);
        assert!(
            evidence
                .nodes
                .iter()
                .any(|node| { node.reason == FleetNativeDrainReadiness::DrainSnapshotMismatch })
        );
    }

    let mut application_only = appended.clone();
    application_only.nodes[0].native_session_drain = None;
    let evidence = fleet_native_drain_evidence(
        &application_only,
        &BTreeSet::new(),
        now,
        Duration::from_secs(30),
    )
    .expect("old application-only acknowledgement");
    assert_eq!(
        evidence.nodes[1].reason,
        FleetNativeDrainReadiness::ApplicationSnapshotMismatch
    );

    for node in &mut appended.nodes {
        node.applied_actions =
            Some(fleet_application_checkpoint(&appended.actions, &node.zone_id).unwrap());
        node.native_session_drain = Some(completed_drain(node));
    }
    assert!(
        fleet_native_drain_evidence(&appended, &BTreeSet::new(), now, Duration::from_secs(30),)
            .expect("fresh complete observations satisfy the new action snapshot")
            .complete
    );
}

#[test]
fn native_drain_evidence_refuses_empty_history_and_uncovered_action_scopes() {
    let (base, now) = complete_native_drain_state();
    let mut no_actions = base.clone();
    no_actions.actions.clear();
    let mut no_nodes = base.clone();
    no_nodes.nodes.clear();
    for state in [&no_actions, &no_nodes] {
        assert!(
            !fleet_native_drain_evidence(state, &BTreeSet::new(), now, Duration::from_secs(30),)
                .expect("empty population is a non-complete observation")
                .complete
        );
    }

    let mut uncovered = base;
    let mut third_zone = sample_action("drain-third-zone", "drain-third-incident");
    if let FleetAction::Quarantine { zone_id, .. } = &mut third_zone.action {
        *zone_id = "zone-c".to_string();
    }
    uncovered.actions.push(third_zone);
    let evidence =
        fleet_native_drain_evidence(&uncovered, &BTreeSet::new(), now, Duration::from_secs(30))
            .expect("uncovered scope");
    assert!(!evidence.complete);
    assert!(evidence.nodes.iter().all(|node| node.ready));
    assert_eq!(evidence.uncovered_zones, vec!["zone-c"]);

    let mut third = sample_node("new-node");
    third.zone_id = "zone-c".to_string();
    third.last_seen = now;
    third.applied_actions =
        Some(fleet_application_checkpoint(&uncovered.actions, "zone-c").unwrap());
    third.native_session_drain = Some(completed_drain(&third));
    uncovered.nodes.push(third);
    assert!(
        fleet_native_drain_evidence(&uncovered, &BTreeSet::new(), now, Duration::from_secs(30),)
            .expect("all targeted scopes now have complete observations")
            .complete
    );
}

#[test]
fn native_drain_evidence_retains_missing_and_renamed_required_identities() {
    let (base, now) = complete_native_drain_state();
    let required: BTreeSet<_> = base
        .nodes
        .iter()
        .map(|node| (node.zone_id.clone(), node.node_id.clone()))
        .collect();
    let mut state = base.clone();
    let original = state.nodes.remove(0);
    let mut replacement = original.clone();
    replacement.node_id = "replacement-node".to_string();
    state.nodes.push(replacement);
    let evidence = fleet_native_drain_evidence(&state, &required, now, Duration::from_secs(30))
        .expect("missing original node remains an obligation");
    assert!(!evidence.complete);
    assert_eq!(evidence.nodes.len(), 3);
    let missing = evidence
        .nodes
        .iter()
        .find(|node| node.zone_id == original.zone_id && node.node_id == original.node_id)
        .unwrap();
    assert_eq!(missing.reason, FleetNativeDrainReadiness::MissingNode);
    assert!(!missing.ready);
    assert!(missing.last_seen.is_none());
    assert!(missing.health.is_none());
    assert!(missing.applied_actions.is_none());
    assert!(missing.native_session_drain.is_none());

    state.nodes.push(original);
    assert!(
        fleet_native_drain_evidence(&state, &required, now, Duration::from_secs(30))
            .expect("the retained identity returns with its exact observation")
            .complete
    );

    state.actions.remove(0);
    for node in &mut state.nodes {
        node.applied_actions =
            Some(fleet_application_checkpoint(&state.actions, &node.zone_id).unwrap());
        node.native_session_drain = Some(completed_drain(node));
    }
    let evidence = fleet_native_drain_evidence(&state, &required, now, Duration::from_secs(30))
        .expect("retained participant must still have an applicable action");
    assert!(!evidence.complete);
    assert!(
        evidence
            .nodes
            .iter()
            .any(|node| { node.reason == FleetNativeDrainReadiness::NoApplicableActions })
    );
}

#[test]
fn native_drain_evidence_rejects_malformed_duplicate_and_oversized_snapshots() {
    let (base, now) = complete_native_drain_state();
    let mut candidates = Vec::new();
    let mut duplicate_node = base.clone();
    duplicate_node.nodes.push(duplicate_node.nodes[0].clone());
    candidates.push(duplicate_node);
    let mut duplicate_action = base.clone();
    duplicate_action
        .actions
        .push(duplicate_action.actions[0].clone());
    candidates.push(duplicate_action);
    let mut wrong_schema = base.clone();
    wrong_schema.schema_version = "unrecognized-state".to_string();
    candidates.push(wrong_schema);
    let mut unknown_session = base.clone();
    unknown_session.nodes[0]
        .native_session_drain
        .as_mut()
        .unwrap()
        .admitted_sessions += 1;
    candidates.push(unknown_session);
    let mut bad_digest = base.clone();
    bad_digest.nodes[0]
        .native_session_drain
        .as_mut()
        .unwrap()
        .session_set_sha256 = "INVALID".to_string();
    candidates.push(bad_digest);
    let mut ambiguous_zone = base.clone();
    ambiguous_zone.nodes[0].zone_id = "all".to_string();
    candidates.push(ambiguous_zone);
    let mut unrelated_bad_status = base.clone();
    unrelated_bad_status.actions.remove(0);
    let mut outside_scope = sample_node("bad/node");
    outside_scope.zone_id = "zone-outside".to_string();
    unrelated_bad_status.nodes.push(outside_scope);
    candidates.push(unrelated_bad_status);
    let mut too_many_nodes = base.clone();
    too_many_nodes
        .nodes
        .resize(MAX_NODES_CAP + 1, base.nodes[0].clone());
    candidates.push(too_many_nodes);
    let mut too_many_actions = base.clone();
    too_many_actions
        .actions
        .resize(MAX_ACTION_LOG_ENTRIES + 1, base.actions[0].clone());
    candidates.push(too_many_actions);
    for state in candidates {
        assert!(
            fleet_native_drain_evidence(&state, &BTreeSet::new(), now, Duration::from_secs(30),)
                .is_err(),
            "invalid snapshot must fail before producing an aggregate"
        );
    }

    for identity in [
        ("all".to_string(), "node".to_string()),
        ("zone-a".to_string(), "../node".to_string()),
    ] {
        assert!(
            fleet_native_drain_evidence(
                &base,
                &BTreeSet::from([identity]),
                now,
                Duration::from_secs(30),
            )
            .is_err()
        );
    }
    let full_required = (0..MAX_NODES_CAP)
        .map(|index| ("zone-a".to_string(), format!("retained-{index}")))
        .collect();
    assert!(
        fleet_native_drain_evidence(&base, &full_required, now, Duration::from_secs(30),).is_err(),
        "the union of current and retained identities is bounded too"
    );
}

#[test]
fn native_session_drain_rejects_unaccounted_sessions_and_unapplied_completion() {
    let action = sample_action("drain-contract", "drain-incident");
    let checkpoint = fleet_application_checkpoint(&[action], "zone-a").expect("checkpoint");
    let mut node = sample_node("drain-node");
    node.applied_actions = Some(checkpoint.clone());
    let completed = completed_drain(&node);
    node.native_session_drain = Some(completed.clone());
    validate_node_status(&node).expect("applied and completed");
    assert!(completed.is_complete());
    assert_eq!(completed.state(), NativeSessionDrainState::Completed);

    let mut missing_application = node.clone();
    missing_application.applied_actions = None;
    assert!(validate_node_status(&missing_application).is_err());
    let mut wrong_actions = node.clone();
    wrong_actions.applied_actions =
        Some(fleet_application_checkpoint(&[], "zone-a").expect("different action snapshot"));
    assert!(validate_node_status(&wrong_actions).is_err());

    let mut pending = completed.clone();
    pending.terminal_sessions = 1;
    pending.pending_sessions = 1;
    pending.fence_held = true;
    node.health = NodeHealth::Degraded;
    node.applied_actions = None;
    node.native_session_drain = Some(pending.clone());
    validate_node_status(&node).expect("retained pending obligation after failed application");
    assert_eq!(pending.state(), NativeSessionDrainState::Pending);
    assert!(!pending.is_complete());
    let mut premature_healthy = node.clone();
    premature_healthy.health = NodeHealth::Healthy;
    premature_healthy.applied_actions = Some(checkpoint);
    assert!(validate_node_status(&premature_healthy).is_err());

    let mut unknown = pending.clone();
    unknown.pending_sessions = 0;
    unknown.indeterminate_sessions = 1;
    node.native_session_drain = Some(unknown.clone());
    validate_node_status(&node).expect("unknown effects remain represented");
    assert_eq!(unknown.state(), NativeSessionDrainState::Indeterminate);
    assert!(!unknown.is_complete());

    let mut unfenced_pending = pending.clone();
    unfenced_pending.fence_held = false;
    let mut unfenced_unknown = unknown;
    unfenced_unknown.fence_held = false;
    let mut unaccounted = pending.clone();
    unaccounted.admitted_sessions = 3;
    let mut overflow = pending.clone();
    overflow.terminal_sessions = u64::MAX;
    overflow.admitted_sessions = 0;
    let mut bad_session_digest = completed.clone();
    bad_session_digest.session_set_sha256 = "A".repeat(64);
    let mut bad_actions_digest = completed.clone();
    bad_actions_digest.applied_actions.actions_sha256 = "a".repeat(63);
    for invalid in [
        unfenced_pending,
        unfenced_unknown,
        unaccounted,
        overflow,
        bad_session_digest,
        bad_actions_digest,
    ] {
        assert!(
            invalid.validate().is_err(),
            "accepted invalid drain {invalid:?}"
        );
    }

    let mut held = completed;
    held.fence_held = true;
    held.validate()
        .expect("terminal census still awaits policy application");
    assert_eq!(held.state(), NativeSessionDrainState::Pending);
    assert!(!held.is_complete());
    let mut malformed = serde_json::to_value(&held).expect("encode");
    malformed["quiescence_certified"] = true.into();
    assert!(serde_json::from_value::<NativeSessionDrainCheckpoint>(malformed).is_err());
}

#[test]
fn native_session_drain_survives_file_and_sql_reopen_without_discarding_unknowns() {
    let directory = tempfile::tempdir().expect("tempdir");
    let action = sample_action("drain-retained", "drain-incident");
    let checkpoint =
        fleet_application_checkpoint(std::slice::from_ref(&action), "zone-a").expect("checkpoint");
    for durable in [false, true] {
        let root = directory.path().join(if durable { "sql" } else { "file" });
        let open = || -> Box<dyn FleetTransport> {
            if durable {
                Box::new(DurableFleetTransport::new(&root).expect("SQL store"))
            } else {
                Box::new(FileFleetTransport::new(&root))
            }
        };
        let mut transport = open();
        transport.initialize().expect("initialize");
        transport.publish_action(&action).expect("action");
        let mut node = sample_node("retained-drain-node");
        node.applied_actions = Some(checkpoint.clone());
        node.native_session_drain = Some(completed_drain(&node));
        transport.upsert_node_status(&node).expect("complete drain");
        drop(transport);
        let mut reopened = open();
        reopened.initialize().expect("reopen");
        assert_eq!(
            reopened.list_node_statuses().expect("read"),
            vec![node.clone()]
        );

        node.applied_actions = None;
        node.health = NodeHealth::Degraded;
        let drain = node.native_session_drain.as_mut().expect("drain");
        drain.terminal_sessions = 0;
        drain.pending_sessions = 1;
        drain.indeterminate_sessions = 1;
        drain.fence_held = true;
        reopened
            .upsert_node_status(&node)
            .expect("retain unknown outcomes");
        let mut forged_complete = node.clone();
        forged_complete
            .native_session_drain
            .as_mut()
            .expect("drain")
            .fence_held = false;
        assert!(reopened.upsert_node_status(&forged_complete).is_err());
        drop(reopened);
        let mut reopened = open();
        reopened.initialize().expect("reopen pending drain");
        assert_eq!(
            reopened.list_node_statuses().expect("retained unknowns"),
            vec![node]
        );
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
fn retained_action_prefix_preserves_zone_and_wildcard_order_across_appends() {
    let first = sample_action("prefix-zone", "prefix-incident");
    let mut foreign = sample_action("prefix-foreign", "foreign-incident");
    if let FleetAction::Quarantine { zone_id, .. } = &mut foreign.action {
        *zone_id = "zone-b".to_string();
    }
    let mut wildcard = sample_action("prefix-wildcard", "global-incident");
    if let FleetAction::Quarantine { zone_id, .. } = &mut wildcard.action {
        *zone_id = "all".to_string();
    }
    let retained_actions = vec![first.clone(), foreign.clone(), wildcard.clone()];
    let retained = fleet_application_checkpoint(&retained_actions, "zone-a").expect("retained");
    let appended = release_action("prefix-release", "prefix-incident");
    let expanded = vec![
        foreign.clone(),
        first.clone(),
        wildcard.clone(),
        appended.clone(),
    ];
    assert_eq!(
        fleet_action_snapshot_prefix(&expanded, "zone-a", &retained).expect("retained prefix"),
        vec![first.clone(), wildcard.clone()],
        "new actions wait and unrelated-zone records do not change relevant order"
    );
    let current = fleet_application_checkpoint(&expanded, "zone-a").expect("current");
    assert_eq!(
        fleet_action_snapshot_prefix(&expanded, "zone-a", &current).expect("full relevant history"),
        vec![first, wildcard, appended]
    );
    let empty = fleet_application_checkpoint(&[], "zone-a").expect("empty retained prefix");
    assert!(
        fleet_action_snapshot_prefix(&expanded, "zone-a", &empty)
            .expect("empty prefix remains valid after appends")
            .is_empty()
    );
    let foreign_checkpoint =
        fleet_application_checkpoint(&[foreign], "zone-b").expect("other zone checkpoint");
    assert!(matches!(
        fleet_action_snapshot_prefix(&expanded, "zone-a", &foreign_checkpoint),
        Err(FleetTransportError::StaleState { .. })
    ));
}

#[test]
fn retained_action_prefix_rejects_missing_rewritten_reordered_and_inflated_history() {
    let first = sample_action("retained-first", "retained-incident");
    let release = release_action("retained-release", "retained-incident");
    let actions = vec![first.clone(), release.clone()];
    let retained = fleet_application_checkpoint(&actions, "zone-a").expect("retained");
    let mut changed = first.clone();
    changed.emitted_at -= chrono::TimeDelta::seconds(1);
    let rewritten = vec![changed, release.clone()];
    let reordered = vec![release.clone(), first.clone()];
    let replaced = vec![
        release.clone(),
        sample_action("retained-replacement", "new-incident"),
    ];
    let missing = vec![release];
    for history in [&rewritten, &reordered, &replaced, &missing] {
        assert!(matches!(
            fleet_action_snapshot_prefix(history, "zone-a", &retained),
            Err(FleetTransportError::StaleState { .. })
        ));
    }
    let mut inflated = retained.clone();
    inflated.action_count += 1;
    assert!(matches!(
        fleet_action_snapshot_prefix(&actions, "zone-a", &inflated),
        Err(FleetTransportError::StaleState { .. })
    ));
    inflated.action_count = u64::MAX;
    assert!(matches!(
        fleet_action_snapshot_prefix(&actions, "zone-a", &inflated),
        Err(FleetTransportError::SerializationError { .. })
    ));
    let mut malformed = retained;
    malformed.actions_sha256 = "AB".repeat(32);
    assert!(matches!(
        fleet_action_snapshot_prefix(&actions, "zone-a", &malformed),
        Err(FleetTransportError::SerializationError { .. })
    ));
}

#[test]
fn retained_action_prefix_validates_the_entire_bounded_source_history() {
    let first = sample_action("bounded-first", "bounded-incident");
    let retained =
        fleet_application_checkpoint(std::slice::from_ref(&first), "zone-a").expect("retained");
    let mut invalid_foreign = sample_action("invalid-foreign", "foreign-incident");
    if let FleetAction::Quarantine { zone_id, .. } = &mut invalid_foreign.action {
        *zone_id = "zone-b".to_string();
    }
    invalid_foreign.action_id.clear();
    let malformed_tail = vec![first.clone(), invalid_foreign];
    let duplicate_tail = vec![first.clone(), first.clone()];
    let oversized = vec![first; MAX_ACTION_LOG_ENTRIES + 1];
    let empty = fleet_application_checkpoint(&[], "zone-a").expect("empty prefix");
    for checkpoint in [&retained, &empty] {
        for history in [&malformed_tail, &duplicate_tail, &oversized] {
            assert!(matches!(
                fleet_action_snapshot_prefix(history, "zone-a", checkpoint),
                Err(FleetTransportError::SerializationError { .. })
            ));
        }
    }
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
    assert!(decoded.native_session_drain.is_none());
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
    node.native_session_drain = Some(completed_drain(&node));
    client
        .upsert_node_status(&node)
        .expect("checkpoint heartbeat over socket");
    let received = client
        .read_shared_state()
        .expect("checkpoint state over socket");
    assert_eq!(received.nodes.len(), 1);
    assert_eq!(received.nodes[0].applied_actions, node.applied_actions);
    assert_eq!(
        received.nodes[0].native_session_drain,
        node.native_session_drain
    );

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
    assert_eq!(
        reopened
            .list_node_statuses()
            .expect("durable drain checkpoint")[0]
            .native_session_drain,
        node.native_session_drain
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
    node_a.native_session_drain = Some(completed_drain(&node_a));
    let mut node_b = sample_node("enrolled-node-b");
    node_b.zone_id = "zone-b".into();
    node_b.applied_actions =
        Some(fleet_application_checkpoint(&all_actions, "zone-b").expect("node-b checkpoint"));
    node_b.native_session_drain = Some(completed_drain(&node_b));
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
        assert!(
            initial
                .nodes
                .iter()
                .all(|node| node.native_session_drain.is_none())
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
        assert_eq!(
            partial
                .nodes
                .iter()
                .filter(|node| node.native_session_drain.is_some())
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
                assert!(node.native_session_drain.is_none());
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
            assert_eq!(node.native_session_drain, Some(completed_drain(node)));
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
        replaced
            .native_session_drain
            .as_mut()
            .expect("drain")
            .applied_actions = replaced
            .applied_actions
            .clone()
            .expect("replaced application");
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
        assert!(
            replaced_view
                .nodes
                .iter()
                .find(|node| node.node_id == node_a.node_id)
                .expect("retained node-a identity")
                .native_session_drain
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
        assert_eq!(
            agent_a.list_node_statuses().expect("restored node-a drain")[0].native_session_drain,
            node_a.native_session_drain
        );
        // Changing only the retained population must also invalidate the
        // authentication of a row: a matching application ACK is insufficient.
        let mut altered_population = operator
            .read_shared_state()
            .expect("fresh state")
            .nodes
            .into_iter()
            .find(|node| node.node_id == node_a.node_id)
            .expect("node-a");
        altered_population
            .native_session_drain
            .as_mut()
            .expect("drain")
            .session_set_sha256 = "d4".repeat(32);
        {
            let mut other_writer =
                DurableFleetTransport::new(dir.path()).expect("population writer");
            other_writer
                .initialize()
                .expect("initialize population writer");
            other_writer
                .upsert_node_status(&altered_population)
                .expect("write changed census");
        }
        let view = agent_a
            .list_node_statuses()
            .expect("changed population view");
        assert!(view[0].applied_actions.is_none());
        assert!(view[0].native_session_drain.is_none());
        agent_a
            .upsert_node_status(&node_a)
            .expect("reauthenticate exact census");
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
