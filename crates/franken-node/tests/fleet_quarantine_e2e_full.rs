//! Full fleet quarantine E2E coverage with real in-process state.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, mpsc};
use std::time::Duration;

use chrono::Utc;
use frankenengine_node::api::error::ApiError;
use frankenengine_node::api::fleet_quarantine::{
    FLEET_INTERNAL, FLEET_QUARANTINE_INITIATED, FLEET_RECONCILE_COMPLETED,
    FLEET_RELEASE_VALIDATION_INVALID, FLEET_RELEASED, FLEET_ROLLBACK_UNVERIFIED,
    FLEET_VALIDATOR_EQUIVOCATION, FleetActionResult, FleetControlManager, PositiveValidation,
    QuarantineRequest, QuarantineScope, ReleaseValidationPolicy, handle_quarantine,
    replace_shared_fleet_control_manager_for_tests, reset_shared_fleet_control_manager_for_tests,
    sign_positive_validation,
};
use frankenengine_node::api::middleware::{AuthIdentity, AuthMethod, TraceContext};
use frankenengine_node::control_plane::fleet_transport::{
    FileFleetTransport, FleetAction as PersistedFleetAction, FleetActionRecord, FleetTargetKind,
    FleetTransport, FleetTransportError, NodeHealth, NodeStatus,
    fleet_action_compaction_root_key_for_test, lock_fleet_action_compaction_process_for_test,
};
use frankenengine_node::control_plane::mmr_proofs::{
    MmrCheckpoint, mmr_prefix_proof, verify_prefix,
};
use serde_json::{Value, json};
use tempfile::tempdir;

const SUITE: &str = "fleet_quarantine_e2e_full";
const FN_FLEETLOG_MMR_ROOT_COMMITTED: &str = "FN-FLEETLOG-MMR-ROOT-COMMITTED";
const FN_FLEETLOG_PREFIX_PROOF_VERIFIED: &str = "FN-FLEETLOG-PREFIX-PROOF-VERIFIED";
const FN_FLEETLOG_VALIDATION_ACCEPTED: &str = "FN-FLEETLOG-VALIDATION-ACCEPTED";
const FN_FLEETLOG_QUORUM_CERT_ACCEPTED: &str = "FN-FLEETLOG-QUORUM-CERT-ACCEPTED";
const FN_FLEETLOG_QUORUM_MISSING: &str = "FN-FLEETLOG-QUORUM-MISSING";
const FN_FLEETLOG_VALIDATION_REJECTED: &str = "FN-FLEETLOG-VALIDATION-REJECTED";
const FN_FLEETLOG_EQUIVOCATION_FAULT: &str = "FN-FLEETLOG-EQUIVOCATION-FAULT";
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

fn release_validator_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn configure_release_validation_policy(
    manager: &mut FleetControlManager,
    quorum: usize,
) -> Vec<ed25519_dalek::SigningKey> {
    let validators = vec![
        release_validator_key(91),
        release_validator_key(92),
        release_validator_key(93),
    ];
    let verifying_keys = validators
        .iter()
        .map(ed25519_dalek::SigningKey::verifying_key)
        .collect::<Vec<_>>();
    manager.configure_release_validation(
        ReleaseValidationPolicy::from_validator_keys(&verifying_keys).with_quorum(quorum),
    );
    validators
}

fn control_epoch_for_incident(incident_id: &str) -> u64 {
    let Some(raw_operation) = incident_id.strip_prefix("inc-fleet-op-") else {
        return 0;
    };
    raw_operation
        .split_once('-')
        .and_then(|(epoch, _sequence)| u64::from_str_radix(epoch, 16).ok())
        .unwrap_or(0)
}

fn validation_for_incident(
    key: &ed25519_dalek::SigningKey,
    incident_id: &str,
    extension_id: &str,
    action_type: &str,
    zone_id: &str,
    resolved: bool,
    issued_at: &str,
) -> PositiveValidation {
    sign_positive_validation(
        key,
        incident_id,
        extension_id,
        action_type,
        zone_id,
        control_epoch_for_incident(incident_id),
        resolved,
        issued_at,
    )
}

fn append_fleet_log_marker(
    checkpoint: &mut MmrCheckpoint,
    node_id: &str,
    event_code: &str,
    incident_id: &str,
    operation_id: &str,
) -> frankenengine_node::control_plane::mmr_proofs::MmrRoot {
    checkpoint
        .append_marker_hash(&format!(
            "{node_id}|{event_code}|{incident_id}|{operation_id}"
        ))
        .expect("append fleet action marker to MMR checkpoint")
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
            PersistedFleetAction::Revoke { .. } => {}
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

#[test]
fn fleet_transport_rejects_oversized_action_log_line_before_parsing() {
    let tempdir = tempdir().expect("tempdir");
    let state_root = tempdir.path().join("fleet-state");
    let mut transport = FileFleetTransport::new(&state_root);
    transport
        .initialize()
        .expect("initialize real fleet transport");

    fs::write(transport.layout().actions_path(), vec![b'A'; 8 * 1024])
        .expect("write oversized action log line");

    let error = transport
        .list_actions()
        .expect_err("oversized action log line should be rejected");
    let rendered = error.to_string();

    assert!(matches!(
        error,
        FleetTransportError::SerializationError { .. }
    ));
    assert!(
        rendered.contains("JSONL line 1"),
        "error should name offending line: {rendered}"
    );
    assert!(
        rendered.contains("exceeds"),
        "error should report the bounded-line rejection: {rendered}"
    );
}

#[test]
fn fleet_transport_compaction_guard_serializes_equivalent_root_spellings() {
    let tempdir = tempdir().expect("tempdir");
    let state_root = tempdir.path().join("fleet-state");
    let equivalent_parent = state_root.join("nested");
    fs::create_dir_all(&equivalent_parent).expect("create equivalent parent");
    let equivalent_root = equivalent_parent.join("..");
    let mut transport = FileFleetTransport::new(&state_root);
    transport
        .initialize()
        .expect("initialize real fleet transport");

    assert_eq!(
        fleet_action_compaction_root_key_for_test(transport.layout().root_dir())
            .expect("canonical root key"),
        fleet_action_compaction_root_key_for_test(&equivalent_root).expect("equivalent root key"),
        "equivalent fleet roots must share one process-lock registry key"
    );

    let guard = lock_fleet_action_compaction_process_for_test(transport.layout().root_dir())
        .expect("take first process guard");
    let (sender, receiver) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let _guard = lock_fleet_action_compaction_process_for_test(&equivalent_root)
            .expect("equivalent process guard waits then acquires");
        sender.send(()).expect("send acquisition");
    });

    assert!(
        matches!(
            receiver.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "equivalent root spelling must wait behind the existing process guard"
    );

    drop(guard);
    receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("equivalent root guard should acquire after release");
    waiter.join().expect("equivalent root waiter join");
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
    let validators = configure_release_validation_policy(&mut manager, 2);
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

    for validator in validators.iter().take(2) {
        let validation = validation_for_incident(
            validator,
            &incident_id,
            extension_id,
            "quarantine",
            zone_id,
            true,
            &Utc::now().to_rfc3339(),
        );
        manager
            .submit_release_validation(validation)
            .expect("positive release validation should be accepted");
    }
    logger.emit(
        "release",
        "fleet_log_event",
        json!({
            "code": FN_FLEETLOG_QUORUM_CERT_ACCEPTED,
            "incident_id": &incident_id,
            "threshold": 2,
            "valid_signatures": 2,
            "control_epoch": control_epoch_for_incident(&incident_id),
        }),
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
fn fleet_log_quorum_equivocation_and_mmr_prefix_proof_e2e() {
    let tempdir = tempdir().expect("create isolated fleet-log E2E tempdir");
    let state_root = tempdir.path().join("fleet-state");
    let log_path = tempdir.path().join("fleet-log-e2e.jsonl");
    let logger = JsonLineLog::new(
        log_path,
        "fleet_log_quorum_equivocation_and_mmr_prefix_proof_e2e",
    );
    let mut transport = FileFleetTransport::new(&state_root);
    transport.initialize().expect("initialize real fleet state");

    let zone_id = "zone-fleet-log";
    let extension_id = "extension-fleet-log";
    let scope = QuarantineScope {
        zone_id: zone_id.to_string(),
        tenant_id: Some("tenant-fleet-log".to_string()),
        affected_nodes: 2,
        reason: "accountable fleet log E2E quarantine".to_string(),
    };
    let identity = e2e_identity();
    let mut manager = activated_manager();
    let validators = configure_release_validation_policy(&mut manager, 2);
    seed_transport_nodes(&mut transport, zone_id);

    log_current_state(&logger, "setup", &manager, &transport, zone_id, None);

    let quarantine_result = manager
        .quarantine(
            extension_id,
            &scope,
            &identity,
            &e2e_trace("fleet-log-quarantine"),
        )
        .expect("quarantine should succeed before release validation");
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

    let mut primary_checkpoint = MmrCheckpoint::enabled();
    let mut secondary_checkpoint = MmrCheckpoint::enabled();
    let primary_quarantine_root = append_fleet_log_marker(
        &mut primary_checkpoint,
        "node-e2e-primary",
        FLEET_QUARANTINE_INITIATED,
        &incident_id,
        &quarantine_result.operation_id,
    );
    let secondary_quarantine_root = append_fleet_log_marker(
        &mut secondary_checkpoint,
        "node-e2e-secondary",
        FLEET_QUARANTINE_INITIATED,
        &incident_id,
        &quarantine_result.operation_id,
    );
    let primary_catch_up_checkpoint = primary_checkpoint.clone();
    let secondary_catch_up_checkpoint = secondary_checkpoint.clone();
    logger.emit(
        "quarantine",
        "fleet_log_event",
        json!({
            "code": FN_FLEETLOG_MMR_ROOT_COMMITTED,
            "incident_id": &incident_id,
            "node_roots": [
                {
                    "node_id": "node-e2e-primary",
                    "tree_size": primary_quarantine_root.tree_size,
                    "root_hash": primary_quarantine_root.root_hash,
                },
                {
                    "node_id": "node-e2e-secondary",
                    "tree_size": secondary_quarantine_root.tree_size,
                    "root_hash": secondary_quarantine_root.root_hash,
                },
            ],
        }),
    );

    let missing_quorum = manager
        .release(&incident_id, &identity, &e2e_trace("release-no-quorum"))
        .expect_err("release must be denied before quorum is collected");
    assert_eq!(missing_quorum.error_code(), FLEET_ROLLBACK_UNVERIFIED);
    logger.emit(
        "release-denied",
        "fleet_log_event",
        json!({
            "code": FN_FLEETLOG_QUORUM_MISSING,
            "incident_id": &incident_id,
            "error_code": missing_quorum.error_code(),
            "threshold": 2,
            "valid_signatures": 0,
        }),
    );

    let issued_at = Utc::now().to_rfc3339();
    let v0 = validation_for_incident(
        &validators[0],
        &incident_id,
        extension_id,
        "quarantine",
        zone_id,
        true,
        &issued_at,
    );
    assert_eq!(v0.incident_id, incident_id);
    assert_eq!(v0.extension_id, extension_id);
    assert_eq!(v0.action_type, "quarantine");
    assert_eq!(v0.zone_id, zone_id);
    assert_eq!(v0.control_epoch, control_epoch_for_incident(&incident_id));
    manager
        .submit_release_validation(v0.clone())
        .expect("first validator signature should be accepted");
    logger.emit(
        "quorum",
        "fleet_log_event",
        json!({
            "code": FN_FLEETLOG_VALIDATION_ACCEPTED,
            "incident_id": &incident_id,
            "validator_key_id": &v0.validator_key_id,
            "threshold": 2,
            "valid_signatures": 1,
            "control_epoch": v0.control_epoch,
            "signature_hex_len": v0.signature_hex.len(),
        }),
    );

    let duplicate = validation_for_incident(
        &validators[0],
        &incident_id,
        extension_id,
        "quarantine",
        zone_id,
        true,
        &Utc::now().to_rfc3339(),
    );
    manager
        .submit_release_validation(duplicate)
        .expect("duplicate same-verdict validation refreshes but does not double-count");
    let duplicate_shortfall = manager
        .release(
            &incident_id,
            &identity,
            &e2e_trace("release-duplicate-only"),
        )
        .expect_err("one validator plus a duplicate cannot satisfy 2-of-3");
    assert_eq!(duplicate_shortfall.error_code(), FLEET_ROLLBACK_UNVERIFIED);

    let mut forged = validation_for_incident(
        &validators[1],
        &incident_id,
        extension_id,
        "quarantine",
        zone_id,
        true,
        &Utc::now().to_rfc3339(),
    );
    forged.signature_hex = hex::encode([17_u8; 64]);
    let forged_err = manager
        .submit_release_validation(forged)
        .expect_err("forged validation must be rejected");
    assert_eq!(forged_err.error_code(), FLEET_RELEASE_VALIDATION_INVALID);
    logger.emit(
        "quorum",
        "fleet_log_event",
        json!({
            "code": FN_FLEETLOG_VALIDATION_REJECTED,
            "incident_id": &incident_id,
            "reason": "forged",
            "error_code": forged_err.error_code(),
        }),
    );

    let stale_ts = (Utc::now() - chrono::Duration::seconds(7200)).to_rfc3339();
    let stale = validation_for_incident(
        &validators[1],
        &incident_id,
        extension_id,
        "quarantine",
        zone_id,
        true,
        &stale_ts,
    );
    let stale_err = manager
        .submit_release_validation(stale)
        .expect_err("back-dated validation must be rejected");
    assert_eq!(stale_err.error_code(), FLEET_RELEASE_VALIDATION_INVALID);
    logger.emit(
        "quorum",
        "fleet_log_event",
        json!({
            "code": FN_FLEETLOG_VALIDATION_REJECTED,
            "incident_id": &incident_id,
            "reason": "backdated",
            "error_code": stale_err.error_code(),
        }),
    );

    let contradiction = validation_for_incident(
        &validators[0],
        &incident_id,
        extension_id,
        "quarantine",
        zone_id,
        false,
        &Utc::now().to_rfc3339(),
    );
    let equivocation = manager
        .submit_release_validation(contradiction)
        .expect_err("conflicting validator statement must produce a fault receipt");
    assert_eq!(equivocation.error_code(), FLEET_VALIDATOR_EQUIVOCATION);
    let fault = manager
        .validator_fault_receipts()
        .first()
        .expect("equivocation fault receipt should be recorded");
    assert_eq!(fault.fault_type, "validator_equivocation");
    assert_eq!(fault.incident_id, incident_id);
    assert_eq!(
        fault.control_epoch,
        control_epoch_for_incident(&incident_id)
    );
    assert_eq!(fault.conflicting.len(), 2);
    assert_ne!(fault.conflicting[0].resolved, fault.conflicting[1].resolved);
    assert!(
        fault
            .conflicting
            .iter()
            .all(|proof| !proof.signature_hex.is_empty()),
        "fault receipt must embed signed conflicting validations"
    );
    logger.assert_json_eq(
        "equivocation",
        "quarantine remains active after equivocation",
        json!(1),
        json!(
            manager
                .status(zone_id)
                .expect("zone status after equivocation")
                .active_quarantines
        ),
    );
    logger.emit(
        "equivocation",
        "fleet_log_event",
        json!({
            "code": FN_FLEETLOG_EQUIVOCATION_FAULT,
            "error_code": equivocation.error_code(),
            "incident_id": &incident_id,
            "validator_key_id": &fault.validator_key_id,
            "control_epoch": fault.control_epoch,
            "conflicting_signatures": fault.conflicting.len(),
            "quarantine_scope": "fleet-wide",
        }),
    );
    let primary_fault_root = append_fleet_log_marker(
        &mut primary_checkpoint,
        "node-e2e-primary",
        FLEET_VALIDATOR_EQUIVOCATION,
        &incident_id,
        &quarantine_result.operation_id,
    );
    let secondary_fault_root = append_fleet_log_marker(
        &mut secondary_checkpoint,
        "node-e2e-secondary",
        FLEET_VALIDATOR_EQUIVOCATION,
        &incident_id,
        &quarantine_result.operation_id,
    );

    let v1 = validation_for_incident(
        &validators[1],
        &incident_id,
        extension_id,
        "quarantine",
        zone_id,
        true,
        &Utc::now().to_rfc3339(),
    );
    assert_eq!(v1.control_epoch, v0.control_epoch);
    assert_eq!(v1.incident_id, v0.incident_id);
    manager
        .submit_release_validation(v1.clone())
        .expect("second distinct validator reaches quorum");
    let primary_quorum_root = append_fleet_log_marker(
        &mut primary_checkpoint,
        "node-e2e-primary",
        FN_FLEETLOG_QUORUM_CERT_ACCEPTED,
        &incident_id,
        &quarantine_result.operation_id,
    );
    let secondary_quorum_root = append_fleet_log_marker(
        &mut secondary_checkpoint,
        "node-e2e-secondary",
        FN_FLEETLOG_QUORUM_CERT_ACCEPTED,
        &incident_id,
        &quarantine_result.operation_id,
    );
    logger.emit(
        "quorum",
        "fleet_log_event",
        json!({
            "code": FN_FLEETLOG_QUORUM_CERT_ACCEPTED,
            "incident_id": &incident_id,
            "threshold": 2,
            "valid_signatures": 2,
            "control_epoch": v1.control_epoch,
            "validator_key_ids": [&v0.validator_key_id, &v1.validator_key_id],
            "node_roots": [
                {
                    "node_id": "node-e2e-primary",
                    "fault_root": primary_fault_root.root_hash,
                    "quorum_root": primary_quorum_root.root_hash,
                    "tree_size": primary_quorum_root.tree_size,
                },
                {
                    "node_id": "node-e2e-secondary",
                    "fault_root": secondary_fault_root.root_hash,
                    "quorum_root": secondary_quorum_root.root_hash,
                    "tree_size": secondary_quorum_root.tree_size,
                },
            ],
        }),
    );

    let primary_prefix = mmr_prefix_proof(&primary_catch_up_checkpoint, &primary_checkpoint)
        .expect("primary node catch-up prefix proof");
    let secondary_prefix = mmr_prefix_proof(&secondary_catch_up_checkpoint, &secondary_checkpoint)
        .expect("secondary node catch-up prefix proof");
    let primary_old_root = primary_catch_up_checkpoint
        .root()
        .expect("primary catch-up root")
        .clone();
    let primary_new_root = primary_checkpoint.root().expect("primary new root").clone();
    let secondary_old_root = secondary_catch_up_checkpoint
        .root()
        .expect("secondary catch-up root")
        .clone();
    let secondary_new_root = secondary_checkpoint
        .root()
        .expect("secondary new root")
        .clone();
    verify_prefix(&primary_prefix, &primary_old_root, &primary_new_root)
        .expect("primary node prefix proof verifies");
    verify_prefix(&secondary_prefix, &secondary_old_root, &secondary_new_root)
        .expect("secondary node prefix proof verifies");
    logger.emit(
        "catch-up",
        "fleet_log_event",
        json!({
            "code": FN_FLEETLOG_PREFIX_PROOF_VERIFIED,
            "incident_id": &incident_id,
            "nodes_verified": 2,
            "prefix_sizes": [primary_prefix.prefix_size, secondary_prefix.prefix_size],
            "super_tree_sizes": [primary_prefix.super_tree_size, secondary_prefix.super_tree_size],
        }),
    );

    let release_result = manager
        .release(&incident_id, &identity, &e2e_trace("release-with-quorum"))
        .expect("release should succeed after k distinct valid signatures");
    assert_eq!(release_result.event_code, FLEET_RELEASED);
    persist_release(&mut transport, &release_result, zone_id, &incident_id);
    log_current_state(
        &logger,
        "release",
        &manager,
        &transport,
        zone_id,
        Some(&release_result),
    );

    let shared_state = transport
        .read_shared_state()
        .expect("read fleet state after quorum release");
    logger.assert_json_eq(
        "release",
        "transport active incidents after quorum release",
        json!(0),
        json!(active_incidents_from_actions(&shared_state.actions).len()),
    );
    logger.assert_json_eq(
        "release",
        "manager active quarantines after quorum release",
        json!(0),
        json!(
            manager
                .status(zone_id)
                .expect("final zone status")
                .active_quarantines
        ),
    );

    let entries = logger.entries();
    for expected_code in [
        FN_FLEETLOG_MMR_ROOT_COMMITTED,
        FN_FLEETLOG_QUORUM_MISSING,
        FN_FLEETLOG_VALIDATION_ACCEPTED,
        FN_FLEETLOG_VALIDATION_REJECTED,
        FN_FLEETLOG_EQUIVOCATION_FAULT,
        FN_FLEETLOG_QUORUM_CERT_ACCEPTED,
        FN_FLEETLOG_PREFIX_PROOF_VERIFIED,
    ] {
        assert!(
            entries.iter().any(|entry| {
                entry["event"] == "fleet_log_event" && entry["data"]["code"] == expected_code
            }),
            "structured fleet-log transcript missing event code {expected_code}"
        );
    }
    assert!(
        entries
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

    assert!(
        matches!(&err, ApiError::Internal { detail, .. } if detail.contains(FLEET_INTERNAL)),
        "broken transport should map to internal API failure: {err:?}"
    );

    reset_shared_fleet_control_manager_for_tests();
}
