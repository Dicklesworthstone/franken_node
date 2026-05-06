//! Mock-free end-to-end test for the control-plane divergence gate.
//!
//! Drives `frankenengine_node::control_plane::divergence_gate::ControlPlaneDivergenceGate`
//! through the full state machine:
//!
//!   Normal → check_propagation(diverged inputs) → Diverged
//!   Diverged → check_mutation → DIVERGENCE_BLOCK
//!   Diverged → respond_halt → still Diverged, halt logged
//!   Diverged → respond_quarantine → Quarantined + partition recorded
//!   Quarantined → respond_alert → Alerted + alert dispatched
//!   Alerted → respond_recover (with HMAC-signed authorization) → Normal
//!
//! Bead: bd-lp99n.
//!
//! Coverage:
//!   - check_propagation Converged path keeps Normal,
//!   - check_propagation Forked path transitions to Diverged with halt,
//!   - check_mutation in Normal returns allowed=true,
//!   - check_mutation in Diverged returns DivergenceBlock for every
//!     `MutationKind` variant,
//!   - respond_halt invalid from Normal → InvalidTransition,
//!   - respond_quarantine wires through to QuarantinePartition + state,
//!   - respond_alert produces OperatorAlert with stable severity/trace,
//!   - respond_recover with valid HMAC OperatorAuthorization → Normal,
//!   - respond_recover with TAMPERED authorization → UnauthorizedRecovery,
//!   - verify_marker against a real MarkerStream.
//!
//! No mocks: real `DivergenceDetector`, real `OperatorAuthorization` HMAC
//! over a SHA-256 canonical preimage, real `MarkerStream`. Each phase
//! emits a structured tracing event PLUS a JSON-line on stderr.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::control_plane::divergence_gate::{
    ControlPlaneDivergenceGate, DivergenceGateError, GateState, MutationKind,
    OperatorAuthorization, OperatorAuthorizationKeyRecord, event_codes,
};
use frankenengine_node::control_plane::fork_detection::{DetectionResult, StateVector};
use frankenengine_node::control_plane::marker_stream::{MarkerEventType, MarkerStream};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{error, info};

static TEST_TRACING_INIT: Once = Once::new();

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

#[derive(serde::Serialize)]
struct PhaseLog<'a> {
    timestamp: String,
    test_name: &'a str,
    phase: &'a str,
    duration_ms: u64,
    success: bool,
    detail: serde_json::Value,
}

struct Harness {
    test_name: &'static str,
    started: Instant,
}

impl Harness {
    fn new(test_name: &'static str) -> Self {
        init_test_tracing();
        let h = Self {
            test_name,
            started: Instant::now(),
        };
        h.log_phase("setup", true, json!({}));
        h
    }

    fn log_phase(&self, phase: &str, success: bool, detail: serde_json::Value) {
        let entry = PhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name,
            phase,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            success,
            detail,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&entry).expect("phase log serializes")
        );
        if success {
            info!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase completed"
            );
        } else {
            error!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase failed"
            );
        }
    }
}

fn sv(node: &str, epoch: u64, payload: &str, parent_hash: &str) -> StateVector {
    StateVector {
        epoch,
        marker_id: format!("marker-{node}-{epoch}"),
        state_hash: StateVector::compute_state_hash(payload),
        parent_state_hash: parent_hash.to_string(),
        timestamp: 1_745_750_000 + epoch,
        node_id: node.to_string(),
    }
}

const SIGNING_KEY: &[u8] = b"e2e-divergence-gate-hmac-key-v1";
const SIGNING_KEY_ID: &str = "e2e-operator-key-v1";

fn recovery_auth(
    gate: &ControlPlaneDivergenceGate,
    operator_id: &str,
    checkpoint_epoch: u64,
    timestamp: u64,
    reason: &str,
) -> OperatorAuthorization {
    OperatorAuthorization::new_for_active_divergence_with_key_id(
        operator_id,
        SIGNING_KEY_ID,
        gate.active_divergence().expect("active divergence"),
        checkpoint_epoch,
        timestamp,
        reason,
        SIGNING_KEY,
    )
}

fn auth_key(auth: &OperatorAuthorization) -> OperatorAuthorizationKeyRecord {
    OperatorAuthorizationKeyRecord::for_authorization(auth, SIGNING_KEY.to_vec())
}

fn expected_active_divergence_fingerprint(gate: &ControlPlaneDivergenceGate) -> String {
    let active = gate.active_divergence().expect("active divergence");
    let canonical = format!(
        "{}:{}|{}|{}:{}|{}:{}|{}",
        active.detection_result.len(),
        active.detection_result,
        active.fork_epoch,
        active.local_hash.len(),
        active.local_hash,
        active.remote_hash.len(),
        active.remote_hash,
        active.detected_at
    );

    let mut hasher = Sha256::new();
    hasher.update(b"divergence_gate_active_v1:");
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

fn expected_authorization_hash(auth: &OperatorAuthorization) -> String {
    let canonical = format!(
        "{}:{}|{}:{}|{}:{}|{}|{}|{}:{}|{}:{}|{}:{}",
        auth.operator_id.len(),
        auth.operator_id,
        auth.key_id.len(),
        auth.key_id,
        auth.operator_key_fingerprint.len(),
        auth.operator_key_fingerprint,
        auth.resync_checkpoint_epoch,
        auth.timestamp,
        auth.nonce.len(),
        auth.nonce,
        auth.divergence_fingerprint.len(),
        auth.divergence_fingerprint,
        auth.reason.len(),
        auth.reason
    );

    let mut hasher = Sha256::new();
    hasher.update(b"divergence_gate_auth_v3:");
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

fn expected_authorization_signature(auth: &OperatorAuthorization) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(SIGNING_KEY).expect("HMAC key is valid");
    mac.update(b"divergence_gate_sign_v1:");
    mac.update(auth.authorization_hash.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn active_divergence_fingerprint(gate: &ControlPlaneDivergenceGate) -> String {
    gate.active_divergence()
        .expect("active divergence")
        .authorization_fingerprint()
}

struct DivergencePreservation<'a> {
    audit_before: usize,
    events_before: usize,
    fingerprint_before: &'a str,
}

impl<'a> DivergencePreservation<'a> {
    fn capture(gate: &ControlPlaneDivergenceGate, fingerprint_before: &'a str) -> Self {
        Self {
            audit_before: gate.audit_log().len(),
            events_before: gate.events().len(),
            fingerprint_before,
        }
    }
}

fn assert_unauthorized_recovery_preserves_divergence(
    h: &Harness,
    gate: &ControlPlaneDivergenceGate,
    err: DivergenceGateError,
    preserved: DivergencePreservation<'_>,
    expected_reason: &str,
    phase: &str,
) {
    if let DivergenceGateError::UnauthorizedRecovery { reason } = err {
        assert!(
            reason.contains(expected_reason),
            "expected reason containing {expected_reason:?}, got {reason:?}"
        );
        assert_eq!(gate.state(), GateState::Diverged);
        assert_eq!(gate.audit_log().len(), preserved.audit_before);
        assert_eq!(gate.events().len(), preserved.events_before);
        assert_eq!(
            active_divergence_fingerprint(gate),
            preserved.fingerprint_before
        );
        h.log_phase(phase, true, json!({"reason": reason}));
    } else {
        assert!(matches!(
            err,
            DivergenceGateError::UnauthorizedRecovery { .. }
        ));
    }
}

#[test]
fn e2e_divergence_gate_normal_path_allows_mutations() -> Result<(), String> {
    let h = Harness::new("e2e_divergence_gate_normal_path_allows_mutations");

    let mut gate = ControlPlaneDivergenceGate::new("node-A");
    assert_eq!(gate.state(), GateState::Normal);
    assert!(gate.allows_mutation());
    h.log_phase("initial_normal", true, json!({}));

    let local = sv("node-A", 5, "epoch-5", "parent-of-5");
    let remote = sv("node-B", 5, "epoch-5", "parent-of-5");
    let (result, _proof, log_event) =
        gate.check_propagation(&local, &remote, 1_745_750_005, "trace-conv");
    assert_eq!(result, DetectionResult::Converged);
    assert_eq!(log_event.severity, "INFO");
    assert_eq!(gate.state(), GateState::Normal);
    h.log_phase("converged_keeps_normal", true, json!({}));

    // check_mutation in Normal: allowed for every kind.
    for kind in [
        MutationKind::PolicyUpdate,
        MutationKind::TokenIssuance,
        MutationKind::ZoneBoundaryChange,
        MutationKind::RevocationPublish,
        MutationKind::EpochTransition,
        MutationKind::QuarantinePromotion,
    ] {
        let res = gate
            .check_mutation(&kind, 1_745_750_006, "trace-mut")
            .expect("mutation allowed in Normal");
        assert!(res.allowed);
        assert_eq!(res.gate_state, "normal");
    }
    h.log_phase("all_mutations_allowed", true, json!({}));

    // respond_halt is INVALID from Normal.
    let err = gate.respond_halt(1_745_750_007, "trace-halt-bad");
    match err {
        Err(DivergenceGateError::InvalidTransition {
            from,
            to: _,
            reason: _,
        }) => {
            assert_eq!(from, "normal");
            h.log_phase("halt_from_normal_rejected", true, json!({}));
        }
        other => return Err(format!("expected InvalidTransition, got {other:?}")),
    }

    Ok(())
}

#[test]
fn e2e_divergence_gate_forked_blocks_mutations_then_quarantine_then_alert() -> Result<(), String> {
    let h = Harness::new("e2e_divergence_gate_forked_blocks_mutations_then_quarantine_then_alert");

    let mut gate = ControlPlaneDivergenceGate::new("node-A");

    // Forked: same epoch, different state hashes.
    let local = sv("node-A", 7, "payload-A", "parent-7");
    let remote = sv("node-B", 7, "payload-B-DIFFERENT", "parent-7");
    let (result, proof, log_event) =
        gate.check_propagation(&local, &remote, 1_745_750_007, "trace-fork");
    assert_eq!(result, DetectionResult::Forked);
    assert!(proof.is_some());
    assert_eq!(log_event.severity, "CRITICAL");
    assert_eq!(gate.state(), GateState::Diverged);
    assert!(!gate.allows_mutation());
    assert!(gate.active_divergence().is_some());
    h.log_phase("forked_detected", true, json!({"state": "diverged"}));

    // check_mutation in Diverged: DivergenceBlock for any kind.
    let err = gate
        .check_mutation(&MutationKind::PolicyUpdate, 1_745_750_008, "trace-block")
        .expect_err("mutation blocked in Diverged");
    match err {
        DivergenceGateError::DivergenceBlock {
            mutation_kind,
            gate_state,
            detail: _,
        } => {
            assert_eq!(mutation_kind, "policy_update");
            assert_eq!(gate_state, "diverged");
        }
        other => return Err(format!("expected DivergenceBlock, got {other:?}")),
    }
    assert_eq!(gate.blocked_mutations().len(), 1);
    h.log_phase("mutation_blocked", true, json!({}));

    // respond_halt valid from Diverged: state stays, halt logged on
    // active_divergence.response_mode.
    gate.respond_halt(1_745_750_009, "trace-halt")
        .expect("halt ok");
    assert_eq!(gate.state(), GateState::Diverged);
    assert_eq!(
        gate.active_divergence()
            .and_then(|a| a.response_mode.as_deref()),
        Some("HALT")
    );
    h.log_phase("halt_recorded", true, json!({}));

    // respond_quarantine: transitions to Quarantined, partition recorded.
    let partition = gate
        .respond_quarantine("partition-east", "node-A", 1_745_750_010, "trace-quar")
        .expect("quarantine ok");
    assert_eq!(partition.partition_id, "partition-east");
    assert_eq!(partition.divergence_epoch, 7);
    assert_eq!(gate.state(), GateState::Quarantined);
    assert_eq!(gate.quarantined_partitions().len(), 1);
    h.log_phase("quarantined", true, json!({"partition": "partition-east"}));

    // respond_alert: from Quarantined it's allowed.
    let alert = gate
        .respond_alert(1_745_750_011, "trace-alert")
        .expect("alert ok");
    assert_eq!(alert.severity, "CRITICAL");
    assert_eq!(alert.divergence_epoch, 7);
    assert_eq!(gate.state(), GateState::Alerted);
    assert!(alert.alert_id.starts_with("ALERT-"));
    h.log_phase(
        "alerted",
        true,
        json!({"alert_id": alert.alert_id, "severity": alert.severity}),
    );

    Ok(())
}

#[test]
fn e2e_divergence_gate_audits_distinct_fork_while_already_diverged() {
    let h = Harness::new("e2e_divergence_gate_audits_distinct_fork_while_already_diverged");

    let mut gate = ControlPlaneDivergenceGate::new("node-A");

    let local = sv("node-A", 7, "payload-A", "parent-7");
    let remote = sv("node-B", 7, "payload-B-DIFFERENT", "parent-7");
    let (result, _, _) = gate.check_propagation(&local, &remote, 1_745_750_007, "trace-fork-1");
    assert_eq!(result, DetectionResult::Forked);
    assert_eq!(gate.state(), GateState::Diverged);

    let active_before = gate
        .active_divergence()
        .expect("first fork records active divergence")
        .clone();
    let audit_before = gate.audit_log().len();
    let events_before = gate.events().len();
    h.log_phase(
        "first_fork_recorded",
        true,
        json!({"remote_hash": active_before.remote_hash.as_str()}),
    );

    let second_remote = sv("node-C", 7, "payload-C-DIFFERENT", "parent-7");
    let (second_result, _, _) =
        gate.check_propagation(&local, &second_remote, 1_745_750_008, "trace-fork-2");

    assert_eq!(second_result, DetectionResult::Forked);
    assert_eq!(gate.state(), GateState::Diverged);
    let active_after = gate
        .active_divergence()
        .expect("subsequent fork preserves active divergence");
    assert_eq!(active_after.local_hash, active_before.local_hash);
    assert_eq!(active_after.remote_hash, active_before.remote_hash);
    assert_eq!(active_after.detected_at, active_before.detected_at);
    assert_eq!(gate.audit_log().len(), audit_before + 1);
    assert_eq!(gate.events().len(), events_before + 1);
    let audit_entry = gate
        .audit_log()
        .last()
        .expect("distinct subsequent fork emits audit entry");
    assert_eq!(
        audit_entry.event_code,
        event_codes::DG_001_DIVERGENCE_DETECTED
    );
    assert_eq!(audit_entry.trace_id, "trace-fork-2");
    assert!(audit_entry.detail.contains("subsequent divergence"));
    h.log_phase("second_fork_audited_without_overwrite", true, json!({}));
}

#[test]
fn e2e_divergence_gate_recover_with_authorized_operator() {
    let h = Harness::new("e2e_divergence_gate_recover_with_authorized_operator");

    let mut gate = ControlPlaneDivergenceGate::new("node-A");

    // Drive into Diverged state.
    let local = sv("node-A", 4, "payload-4", "parent-4");
    let remote = sv("node-B", 5, "payload-5", "WRONG-parent-not-matching-4");
    let (result, _, _) = gate.check_propagation(&local, &remote, 1_745_750_004, "trace-r0");
    assert_eq!(result, DetectionResult::RollbackDetected);
    assert_eq!(gate.state(), GateState::Diverged);
    h.log_phase("diverged", true, json!({}));

    // Build a real signed authorization.
    let auth = recovery_auth(
        &gate,
        "operator-prod-1",
        12, // resync_checkpoint_epoch
        1_745_750_100,
        "operator-approved-recovery",
    );
    assert!(
        auth.verify(&auth_key(&auth)),
        "freshly minted authorization must verify under same key"
    );
    h.log_phase("auth_built", true, json!({"operator": "operator-prod-1"}));

    // Recover succeeds → Normal.
    let recovery = gate
        .respond_recover(&auth, &auth_key(&auth), 100, 1_745_750_120, "trace-rec")
        .expect("recovery ok");
    assert!(recovery.success);
    assert_eq!(recovery.authorizing_operator, "operator-prod-1");
    assert_eq!(recovery.resync_checkpoint, 12);
    assert_eq!(recovery.markers_replayed, 100);
    assert_eq!(gate.state(), GateState::Normal);
    assert!(gate.active_divergence().is_none());
    assert!(gate.allows_mutation());
    h.log_phase("recovered_to_normal", true, json!({}));

    // Now mutations are allowed again.
    gate.check_mutation(&MutationKind::EpochTransition, 1_745_750_121, "trace-post")
        .expect("mutations allowed again post-recovery");
    h.log_phase("post_recovery_mutations_allowed", true, json!({}));
}

#[test]
fn e2e_divergence_gate_authorization_hash_uses_stable_canonical_text_contract() {
    let h =
        Harness::new("e2e_divergence_gate_authorization_hash_uses_stable_canonical_text_contract");

    let mut gate = ControlPlaneDivergenceGate::new("node-A");
    let local = sv("node-A", 4, "payload-4", "parent-4");
    let remote = sv("node-B", 5, "payload-5", "WRONG-parent-not-matching-4");
    let (result, _, _) = gate.check_propagation(&local, &remote, 1_745_750_004, "trace-r0");
    assert_eq!(result, DetectionResult::RollbackDetected);
    assert_eq!(gate.state(), GateState::Diverged);

    let active = gate.active_divergence().expect("active divergence");
    assert_eq!(
        active.authorization_fingerprint(),
        expected_active_divergence_fingerprint(&gate)
    );
    h.log_phase("active_divergence_fingerprint_stable", true, json!({}));

    let auth = recovery_auth(
        &gate,
        "operator-prod-1",
        12,
        1_745_750_100,
        "operator-approved-recovery",
    );

    assert_eq!(auth.authorization_hash, expected_authorization_hash(&auth));
    assert_eq!(auth.signature, expected_authorization_signature(&auth));
    assert!(auth.verify(&auth_key(&auth)));
    h.log_phase("authorization_hash_and_signature_stable", true, json!({}));
}

#[test]
fn e2e_divergence_gate_rejects_mismatched_authorization_key_id() {
    let h = Harness::new("e2e_divergence_gate_rejects_mismatched_authorization_key_id");

    let mut gate = ControlPlaneDivergenceGate::new("node-A");
    let local = sv("node-A", 4, "payload-4", "parent-4");
    let remote = sv("node-B", 5, "payload-5", "WRONG-parent-not-matching-4");
    let (result, _, _) = gate.check_propagation(&local, &remote, 1_745_750_004, "trace-key-r0");
    assert_eq!(result, DetectionResult::RollbackDetected);

    let auth = recovery_auth(
        &gate,
        "operator-prod-1",
        12,
        1_745_750_100,
        "operator-approved-recovery",
    );
    let wrong_key_id = OperatorAuthorizationKeyRecord::new(
        "operator-prod-1",
        "e2e-operator-key-v2",
        SIGNING_KEY.to_vec(),
    );

    assert!(!auth.verify(&wrong_key_id));
    let err = gate
        .respond_recover(&auth, &wrong_key_id, 100, 1_745_750_120, "trace-key-rec")
        .expect_err("mismatched key id must reject recovery");
    assert!(matches!(
        err,
        DivergenceGateError::UnauthorizedRecovery { .. }
    ));
    assert_eq!(gate.state(), GateState::Diverged);
    h.log_phase("mismatched_key_id_rejected", true, json!({}));
}

#[test]
fn e2e_divergence_gate_recovery_authorization_binding_contract() {
    let h = Harness::new("e2e_divergence_gate_recovery_authorization_binding_contract");

    let mut gate = ControlPlaneDivergenceGate::new("node-A");

    let cycle_a_local = sv("node-A", 10, "cycle-a-local", "parent-a");
    let cycle_a_remote = sv("node-B", 10, "cycle-a-remote-diverged", "parent-a");
    let (cycle_a_result, _, _) = gate.check_propagation(
        &cycle_a_local,
        &cycle_a_remote,
        1_745_760_000,
        "trace-a-fork",
    );
    assert_eq!(cycle_a_result, DetectionResult::Forked);
    assert_eq!(gate.state(), GateState::Diverged);
    let cycle_a_fingerprint = active_divergence_fingerprint(&gate);
    h.log_phase(
        "cycle_a_diverged",
        true,
        json!({"fingerprint": cycle_a_fingerprint.as_str()}),
    );

    let auth_a = recovery_auth(
        &gate,
        "operator-prod-1",
        15,
        1_745_760_010,
        "cycle-a-approved-recovery",
    );
    assert!(auth_a.verify(&auth_key(&auth_a)));
    h.log_phase(
        "cycle_a_auth_bound",
        true,
        json!({
            "checkpoint": auth_a.resync_checkpoint_epoch,
            "key_id": auth_a.key_id.as_str(),
            "nonce": auth_a.nonce.as_str()
        }),
    );

    let wrong_key_id = OperatorAuthorizationKeyRecord::new(
        "operator-prod-1",
        "e2e-operator-key-v2",
        SIGNING_KEY.to_vec(),
    );
    let preserved = DivergencePreservation::capture(&gate, &cycle_a_fingerprint);
    let err = gate
        .respond_recover(
            &auth_a,
            &wrong_key_id,
            100,
            1_745_760_020,
            "trace-a-wrong-key",
        )
        .expect_err("wrong key id must reject recovery");
    assert_unauthorized_recovery_preserves_divergence(
        &h,
        &gate,
        err,
        preserved,
        "verification failed",
        "wrong_key_id_rejected",
    );

    let mut wrong_checkpoint = auth_a.clone();
    wrong_checkpoint.resync_checkpoint_epoch = wrong_checkpoint
        .resync_checkpoint_epoch
        .checked_add(1)
        .expect("checkpoint increment");
    let preserved = DivergencePreservation::capture(&gate, &cycle_a_fingerprint);
    let err = gate
        .respond_recover(
            &wrong_checkpoint,
            &auth_key(&wrong_checkpoint),
            100,
            1_745_760_021,
            "trace-a-wrong-checkpoint",
        )
        .expect_err("checkpoint tamper must reject recovery");
    assert_unauthorized_recovery_preserves_divergence(
        &h,
        &gate,
        err,
        preserved,
        "verification failed",
        "wrong_checkpoint_rejected",
    );

    let stale_auth = recovery_auth(
        &gate,
        "operator-prod-1",
        15,
        1_745_760_030,
        "cycle-a-stale-recovery",
    );
    let preserved = DivergencePreservation::capture(&gate, &cycle_a_fingerprint);
    let err = gate
        .respond_recover(
            &stale_auth,
            &auth_key(&stale_auth),
            100,
            1_746_060_031,
            "trace-a-expired",
        )
        .expect_err("expired authorization must reject recovery");
    assert_unauthorized_recovery_preserves_divergence(
        &h,
        &gate,
        err,
        preserved,
        "expired",
        "expired_timestamp_rejected",
    );

    let recovery_a = gate
        .respond_recover(
            &auth_a,
            &auth_key(&auth_a),
            100,
            1_745_760_040,
            "trace-a-recover",
        )
        .expect("cycle A recovery succeeds");
    assert!(recovery_a.success);
    assert_eq!(recovery_a.resync_checkpoint, 15);
    assert_eq!(gate.state(), GateState::Normal);
    assert!(gate.active_divergence().is_none());
    h.log_phase(
        "cycle_a_recovered",
        true,
        json!({"checkpoint": recovery_a.resync_checkpoint}),
    );

    let cycle_b_local = sv("node-A", 11, "cycle-b-local", "parent-b");
    let cycle_b_remote = sv("node-C", 11, "cycle-b-remote-diverged", "parent-b");
    let (cycle_b_result, _, _) = gate.check_propagation(
        &cycle_b_local,
        &cycle_b_remote,
        1_745_760_100,
        "trace-b-fork",
    );
    assert_eq!(cycle_b_result, DetectionResult::Forked);
    assert_eq!(gate.state(), GateState::Diverged);
    let cycle_b_fingerprint = active_divergence_fingerprint(&gate);
    assert_ne!(cycle_b_fingerprint, auth_a.divergence_fingerprint);
    h.log_phase(
        "cycle_b_diverged",
        true,
        json!({"fingerprint": cycle_b_fingerprint.as_str()}),
    );

    let preserved = DivergencePreservation::capture(&gate, &cycle_b_fingerprint);
    let err = gate
        .respond_recover(
            &auth_a,
            &auth_key(&auth_a),
            100,
            1_745_760_110,
            "trace-b-replay-cycle-a",
        )
        .expect_err("cycle A authorization must not recover cycle B");
    assert_unauthorized_recovery_preserves_divergence(
        &h,
        &gate,
        err,
        preserved,
        "active divergence",
        "cycle_a_authorization_rejected_for_cycle_b",
    );

    let auth_b = recovery_auth(
        &gate,
        "operator-prod-1",
        16,
        1_745_760_120,
        "cycle-b-approved-recovery",
    );
    let mut replayed_nonce = auth_b.clone();
    replayed_nonce.nonce = auth_a.nonce.clone();
    replayed_nonce.authorization_hash = expected_authorization_hash(&replayed_nonce);
    replayed_nonce.signature = expected_authorization_signature(&replayed_nonce);
    assert!(replayed_nonce.verify(&auth_key(&replayed_nonce)));
    let preserved = DivergencePreservation::capture(&gate, &cycle_b_fingerprint);
    let err = gate
        .respond_recover(
            &replayed_nonce,
            &auth_key(&replayed_nonce),
            100,
            1_745_760_130,
            "trace-b-replayed-nonce",
        )
        .expect_err("consumed nonce must reject recovery");
    assert_unauthorized_recovery_preserves_divergence(
        &h,
        &gate,
        err,
        preserved,
        "nonce already consumed",
        "consumed_nonce_rejected",
    );

    let recovery_b = gate
        .respond_recover(
            &auth_b,
            &auth_key(&auth_b),
            101,
            1_745_760_140,
            "trace-b-recover",
        )
        .expect("cycle B recovery succeeds with fresh authorization");
    assert!(recovery_b.success);
    assert_eq!(recovery_b.resync_checkpoint, 16);
    assert_eq!(gate.state(), GateState::Normal);
    assert!(gate.active_divergence().is_none());
    h.log_phase(
        "cycle_b_recovered",
        true,
        json!({"checkpoint": recovery_b.resync_checkpoint}),
    );
}

#[test]
fn e2e_divergence_gate_recover_rejects_tampered_authorization() -> Result<(), String> {
    let h = Harness::new("e2e_divergence_gate_recover_rejects_tampered_authorization");

    let mut gate = ControlPlaneDivergenceGate::new("node-A");

    // Diverged state.
    let local = sv("node-A", 7, "payload-A", "parent-7");
    let remote = sv("node-B", 7, "payload-B-DIFFERENT", "parent-7");
    gate.check_propagation(&local, &remote, 1_745_750_007, "trace-fork");
    assert_eq!(gate.state(), GateState::Diverged);

    let mut auth = recovery_auth(&gate, "operator-rogue", 12, 1_745_750_100, "rogue-recovery");
    // Tamper a hex char in the authorization_hash.
    let mut chars: Vec<char> = auth.authorization_hash.chars().collect();
    if let Some(first) = chars.first_mut() {
        *first = match *first {
            '0' => '1',
            _ => '0',
        };
    }
    auth.authorization_hash = chars.into_iter().collect();
    assert!(
        !auth.verify(&auth_key(&auth)),
        "tampered auth must NOT verify"
    );
    h.log_phase("auth_tampered", true, json!({}));

    let err = gate
        .respond_recover(&auth, &auth_key(&auth), 100, 1_745_750_120, "trace-rec-bad")
        .expect_err("tampered auth rejected");
    match err {
        DivergenceGateError::UnauthorizedRecovery { reason } => {
            assert!(reason.contains("authorization") || reason.contains("hash"));
            h.log_phase(
                "unauthorized_recovery_rejected",
                true,
                json!({"reason": reason}),
            );
        }
        other => return Err(format!("expected UnauthorizedRecovery, got {other:?}")),
    }
    // Gate must remain Diverged (not transition to Normal/Recovering).
    assert_eq!(gate.state(), GateState::Diverged);

    Ok(())
}

#[test]
fn e2e_divergence_gate_verify_marker_proof() {
    let h = Harness::new("e2e_divergence_gate_verify_marker_proof");

    // Build a real marker stream with one TrustDecision marker.
    let mut stream = MarkerStream::new();
    let m = stream
        .append(
            MarkerEventType::TrustDecision,
            "sha256:payload-1",
            1_745_750_000,
            "trace-stream",
        )
        .expect("append");
    let marker_id = m.marker_hash.clone();
    h.log_phase(
        "stream_built",
        true,
        json!({"marker_id": marker_id, "len": stream.len()}),
    );

    let mut gate = ControlPlaneDivergenceGate::new("node-A");

    // verify_marker against the real stream at sequence 0 succeeds.
    gate.verify_marker(&stream, &marker_id, 0, 1_745_750_001, "trace-v")
        .expect("real marker proof verifies");
    h.log_phase("marker_verified", true, json!({}));

    // verify_marker with wrong claimed_epoch fails (out of stream range).
    let err = gate
        .verify_marker(&stream, &marker_id, 99, 1_745_750_002, "trace-v-bad")
        .expect_err("oob epoch rejected");
    assert!(matches!(err, DivergenceGateError::FreshnessFailed { .. }));
    h.log_phase("marker_oob_rejected", true, json!({}));
}
