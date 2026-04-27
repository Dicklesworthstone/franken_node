//! Full fleet quarantine E2E coverage with real in-process state.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::Utc;
use frankenengine_node::api::fleet_quarantine::{
    FLEET_INTERNAL, FLEET_QUARANTINE_INITIATED, FLEET_RECONCILE_COMPLETED, FLEET_RELEASED,
    FleetActionResult, FleetControlManager, QuarantineRequest, QuarantineScope,
    handle_quarantine, replace_shared_fleet_control_manager_for_tests,
    reset_shared_fleet_control_manager_for_tests,
};
use frankenengine_node::api::error::ApiError;
use frankenengine_node::api::middleware::{AuthIdentity, AuthMethod, TraceContext};
use frankenengine_node::control_plane::fleet_transport::{
    FileFleetTransport, FleetAction as PersistedFleetAction, FleetActionRecord, FleetTargetKind,
    FleetTransport, NodeHealth, NodeStatus,
};
use serde_json::{Value, json};
use tempfile::tempdir;

const SUITE: &str = "fleet_quarantine_e2e_full";
static HANDLER_TEST_LOCK: Mutex<()> = Mutex::new(());

struct JsonLineLog {
    path: PathBuf,
    test_name: &'static str,
}

impl JsonLineLog {
    fn new(path: PathBuf, test_name: &'static str) -> Self {
        Self { path, test_name }
    }

    fn emit(&self, phase: &str, event: &str, data: Value) {
        let entry = json!({
            "ts": Utc::now().to_rfc3339(),
            "suite": SUITE,
            "test": self.test_name,
            "phase": phase,
            "event": event,
            "data": data,
        });
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .expect("open structured E2E log");
        let payload = serde_json::to_vec(&entry).expect("serialize structured E2E log entry");
        file.write_all(&payload)
            .expect("write structured E2E log entry");
        file.write_all(b"\n")
            .expect("write structured E2E log delimiter");
        file.sync_all().expect("sync structured E2E log entry");
    }

    fn assert_json_eq(&self, phase: &str, field: &str, expected: Value, actual: Value) {
        let matched = expected == actual;
        self.emit(
            phase,
            "assertion",
            json!({
                "field": field,
                "expected": expected,
                "actual": actual,
                "match": matched,
            }),
        );
        assert!(matched, "{field} mismatch");
    }

    fn entries(&self) -> Vec<Value> {
        let contents = fs::read_to_string(&self.path).expect("read structured E2E log");
        assert!(
            contents.ends_with('\n'),
            "structured E2E log must be newline-delimited"
        );
        contents
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse structured E2E log line"))
            .collect()
    }
}

fn e2e_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "fleet-e2e-admin".to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string()],
    }
}

fn e2e_trace(phase: &str) -> TraceContext {
    TraceContext {
        trace_id: format!("fleet-e2e-{phase}-{}", uuid::Uuid::now_v7()),
        span_id: "0000000000000001".to_string(),
        trace_flags: 1,
    }
}

fn activated_manager() -> FleetControlManager {
    let mut manager = FleetControlManager::with_decision_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&[83_u8; 32]),
        "fleet-quarantine-e2e-full",
        "fleet-quarantine-e2e",
    );
    manager.activate();
    manager
}

fn seed_transport_nodes(transport: &mut FileFleetTransport, zone_id: &str) {
    for (node_id, health) in [
        ("node-e2e-primary", NodeHealth::Healthy),
        ("node-e2e-secondary", NodeHealth::Healthy),
    ] {
        transport
            .upsert_node_status(&NodeStatus {
                zone_id: zone_id.to_string(),
                node_id: node_id.to_string(),
                last_seen: Utc::now(),
                quarantine_version: 0,
                health,
            })
            .expect("upsert real fleet node status");
    }
}

fn active_incidents_from_actions(actions: &[FleetActionRecord]) -> BTreeSet<String> {
    let mut active_incidents = BTreeSet::new();
    for record in actions {
        match &record.action {
            PersistedFleetAction::Quarantine { incident_id, .. } => {
                active_incidents.insert(incident_id.clone());
            }
            PersistedFleetAction::Release { incident_id, .. } => {
                active_incidents.remove(incident_id);
            }
            PersistedFleetAction::PolicyUpdate { .. } => {}
        }
    }
    active_incidents
}

fn action_log_line_count(transport: &FileFleetTransport) -> usize {
    fs::read_to_string(transport.layout().actions_path())
        .expect("read real fleet action JSONL log")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

fn log_current_state(
    logger: &JsonLineLog,
    phase: &str,
    manager: &FleetControlManager,
    transport: &FileFleetTransport,
    zone_id: &str,
    result: Option<&FleetActionResult>,
) {
    let zone_status = manager.status(zone_id).expect("read manager zone status");
    let shared_state = transport
        .read_shared_state()
        .expect("read real file-backed fleet state");
    let active_transport_incidents = active_incidents_from_actions(&shared_state.actions);
    let event_codes = manager
        .events()
        .iter()
        .map(|event| event.event_code.as_str())
        .collect::<Vec<_>>();

    logger.emit(
        phase,
        "state_snapshot",
        json!({
            "zone_id": zone_id,
            "manager": {
                "incident_count": manager.incident_count(),
                "active_incidents": manager.active_incidents().len(),
                "active_quarantines": zone_status.active_quarantines,
                "active_revocations": zone_status.active_revocations,
                "pending_convergences": zone_status.pending_convergences.len(),
            },
            "transport": {
                "actions": shared_state.actions.len(),
                "nodes": shared_state.nodes.len(),
                "active_incidents": active_transport_incidents.len(),
                "raw_action_log_lines": action_log_line_count(transport),
            },
            "result": result.map(|result| json!({
                "operation_id": result.operation_id,
                "action_type": result.action_type,
                "event_code": result.event_code,
                "receipt_verified": manager.verify_decision_receipt_signature(&result.receipt),
            })),
            "events": event_codes,
        }),
    );
}

fn persist_quarantine(
    transport: &mut FileFleetTransport,
    result: &FleetActionResult,
    extension_id: &str,
    scope: &QuarantineScope,
    quarantine_version: u64,
) -> String {
    let incident_id = format!("inc-{}", result.operation_id);
    transport
        .publish_action(&FleetActionRecord {
            action_id: result.operation_id.clone(),
            emitted_at: Utc::now(),
            action: PersistedFleetAction::Quarantine {
                zone_id: scope.zone_id.clone(),
                incident_id: incident_id.clone(),
                target_id: extension_id.to_string(),
                target_kind: FleetTargetKind::Extension,
                reason: scope.reason.clone(),
                quarantine_version,
            },
        })
        .expect("persist real quarantine action");
    incident_id
}

fn persist_release(
    transport: &mut FileFleetTransport,
    result: &FleetActionResult,
    zone_id: &str,
    incident_id: &str,
) {
    transport
        .publish_action(&FleetActionRecord {
            action_id: result.operation_id.clone(),
            emitted_at: Utc::now(),
            action: PersistedFleetAction::Release {
                zone_id: zone_id.to_string(),
                incident_id: incident_id.to_string(),
                reason: Some("E2E release after quarantine verification".to_string()),
            },
        })
        .expect("persist real release action");
}

fn assert_logged_state(
    logger: &JsonLineLog,
    entry: &Value,
    phase: &str,
    action_count: usize,
    manager_incident_count: usize,
    active_transport_incidents: usize,
    active_quarantines: u64,
) {
    logger.assert_json_eq(phase, "phase", json!(phase), entry["phase"].clone());
    logger.assert_json_eq(
        phase,
        "transport action count",
        json!(action_count),
        entry["data"]["transport"]["actions"].clone(),
    );
    logger.assert_json_eq(
        phase,
        "raw action log lines",
        json!(action_count),
        entry["data"]["transport"]["raw_action_log_lines"].clone(),
    );
    logger.assert_json_eq(
        phase,
        "transport node count",
        json!(2),
        entry["data"]["transport"]["nodes"].clone(),
    );
    logger.assert_json_eq(
        phase,
        "transport active incidents",
        json!(active_transport_incidents),
        entry["data"]["transport"]["active_incidents"].clone(),
    );
    logger.assert_json_eq(
        phase,
        "manager incident count",
        json!(manager_incident_count),
        entry["data"]["manager"]["incident_count"].clone(),
    );
    logger.assert_json_eq(
        phase,
        "manager active quarantines",
        json!(active_quarantines),
        entry["data"]["manager"]["active_quarantines"].clone(),
    );
}

#[test]
fn quarantine_release_reconcile_e2e_persists_real_state_and_jsonl_evidence() {
    let tempdir = tempdir().expect("create isolated fleet E2E tempdir");
    let state_root = tempdir.path().join("fleet-state");
    let log_path = tempdir.path().join("fleet-e2e.jsonl");
    let logger = JsonLineLog::new(
        log_path,
        "quarantine_release_reconcile_e2e_persists_real_state_and_jsonl_evidence",
    );
    let mut transport = FileFleetTransport::new(&state_root);
    transport.initialize().expect("initialize real fleet state");

    let zone_id = "zone-e2e-full";
    let extension_id = "extension-e2e-full";
    let scope = QuarantineScope {
        zone_id: zone_id.to_string(),
        tenant_id: Some("tenant-e2e".to_string()),
        affected_nodes: 2,
        reason: "real E2E quarantine path".to_string(),
    };
    let identity = e2e_identity();
    let mut manager = activated_manager();
    seed_transport_nodes(&mut transport, zone_id);

    log_current_state(&logger, "setup", &manager, &transport, zone_id, None);

    let quarantine_result = manager
        .quarantine(extension_id, &scope, &identity, &e2e_trace("quarantine"))
        .expect("quarantine should succeed through real manager state");
    logger.assert_json_eq(
        "quarantine",
        "quarantine event code",
        json!(FLEET_QUARANTINE_INITIATED),
        json!(&quarantine_result.event_code),
    );
    logger.assert_json_eq(
        "quarantine",
        "quarantine receipt signature",
        json!(true),
        json!(manager.verify_decision_receipt_signature(&quarantine_result.receipt)),
    );
    let incident_id =
        persist_quarantine(&mut transport, &quarantine_result, extension_id, &scope, 1);
    log_current_state(
        &logger,
        "quarantine",
        &manager,
        &transport,
        zone_id,
        Some(&quarantine_result),
    );

    let release_result = manager
        .release(&incident_id, &identity, &e2e_trace("release"))
        .expect("release should succeed through real manager state");
    logger.assert_json_eq(
        "release",
        "release event code",
        json!(FLEET_RELEASED),
        json!(&release_result.event_code),
    );
    logger.assert_json_eq(
        "release",
        "release receipt signature",
        json!(true),
        json!(manager.verify_decision_receipt_signature(&release_result.receipt)),
    );
    persist_release(&mut transport, &release_result, zone_id, &incident_id);
    log_current_state(
        &logger,
        "release",
        &manager,
        &transport,
        zone_id,
        Some(&release_result),
    );

    let reconcile_result = manager
        .reconcile(&identity, &e2e_trace("reconcile"))
        .expect("reconcile should succeed through real manager state");
    logger.assert_json_eq(
        "reconcile",
        "reconcile event code",
        json!(FLEET_RECONCILE_COMPLETED),
        json!(&reconcile_result.event_code),
    );
    logger.assert_json_eq(
        "reconcile",
        "reconcile receipt signature",
        json!(true),
        json!(manager.verify_decision_receipt_signature(&reconcile_result.receipt)),
    );
    log_current_state(
        &logger,
        "reconcile",
        &manager,
        &transport,
        zone_id,
        Some(&reconcile_result),
    );

    let shared_state = transport
        .read_shared_state()
        .expect("read real fleet state after full E2E sequence");
    logger.assert_json_eq(
        "assert",
        "persisted action count",
        json!(2),
        json!(shared_state.actions.len()),
    );
    logger.assert_json_eq(
        "assert",
        "persisted node count",
        json!(2),
        json!(shared_state.nodes.len()),
    );
    logger.assert_json_eq(
        "assert",
        "transport active incidents after release",
        json!(0),
        json!(active_incidents_from_actions(&shared_state.actions).len()),
    );
    logger.assert_json_eq(
        "assert",
        "manager incident count after reconcile",
        json!(0),
        json!(manager.incident_count()),
    );
    logger.assert_json_eq(
        "assert",
        "manager active incident count after reconcile",
        json!(0),
        json!(manager.active_incidents().len()),
    );
    logger.assert_json_eq(
        "assert",
        "manager active quarantines after reconcile",
        json!(0),
        json!(
            manager
                .status(zone_id)
                .expect("read final zone status")
                .active_quarantines
        ),
    );

    let entries = logger.entries();
    let state_entries = entries
        .iter()
        .filter(|entry| entry["event"] == "state_snapshot")
        .collect::<Vec<_>>();
    let phases = state_entries
        .iter()
        .map(|entry| entry["phase"].as_str().expect("phase is string"))
        .collect::<Vec<_>>();
    assert_eq!(phases, ["setup", "quarantine", "release", "reconcile"]);
    assert_logged_state(&logger, state_entries[0], "setup", 0, 0, 0, 0);
    assert_logged_state(&logger, state_entries[1], "quarantine", 1, 1, 1, 1);
    assert_logged_state(&logger, state_entries[2], "release", 2, 0, 0, 0);
    assert_logged_state(&logger, state_entries[3], "reconcile", 2, 0, 0, 0);

    let final_entries = logger.entries();
    assert!(
        final_entries
            .iter()
            .any(|entry| entry["event"] == "assertion"),
        "structured E2E log must include assertion records"
    );
    assert!(
        final_entries
            .iter()
            .filter(|entry| entry["event"] == "assertion")
            .all(|entry| entry["data"]["match"] == true),
        "every structured assertion record must pass"
    );
}

#[test]
fn quarantine_handler_reports_internal_error_for_broken_transport_persistence() {
    let _guard = HANDLER_TEST_LOCK.lock().expect("handler test lock");
    reset_shared_fleet_control_manager_for_tests();

    let temp_dir = tempdir().expect("tempdir");
    let state_root = temp_dir.path().join("broken-handler-transport");
    let transport = FileFleetTransport::new(&state_root);
    let mut manager = FleetControlManager::with_file_transport_and_signing_key_for_tests(
        transport,
        ed25519_dalek::SigningKey::from_bytes(&[61_u8; 32]),
        "fleet-quarantine-e2e-full",
        "fleet-handler-e2e",
    )
    .expect("create manager with file transport");
    manager.activate();
    fs::remove_file(state_root.join("actions.jsonl")).expect("remove transport action log");
    replace_shared_fleet_control_manager_for_tests(manager);

    let err = handle_quarantine(
        &e2e_identity(),
        &e2e_trace("broken-transport"),
        &QuarantineRequest {
            extension_id: "ext-broken-handler".to_string(),
            scope: QuarantineScope {
                zone_id: "zone-handler".to_string(),
                tenant_id: None,
                affected_nodes: 1,
                reason: "transport persistence failure".to_string(),
            },
        },
    )
    .expect_err("broken transport must map to internal API failure");

    match err {
        ApiError::Internal { detail, .. } => assert!(detail.contains(FLEET_INTERNAL)),
        other => panic!("unexpected error: {other:?}"),
    }

    reset_shared_fleet_control_manager_for_tests();
}
