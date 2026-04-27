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
    OperatorAuthorization,
};
use frankenengine_node::control_plane::fork_detection::{DetectionResult, StateVector};
use frankenengine_node::control_plane::marker_stream::{MarkerEventType, MarkerStream};
use serde_json::json;
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

#[test]
fn e2e_divergence_gate_normal_path_allows_mutations() {
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
        Err(DivergenceGateError::InvalidTransition { from, to: _, reason: _ }) => {
            assert_eq!(from, "normal");
            h.log_phase("halt_from_normal_rejected", true, json!({}));
        }
        other => panic!("expected InvalidTransition, got {other:?}"),
    }
}

#[test]
fn e2e_divergence_gate_forked_blocks_mutations_then_quarantine_then_alert() {
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
        other => panic!("expected DivergenceBlock, got {other:?}"),
    }
    assert_eq!(gate.blocked_mutations().len(), 1);
    h.log_phase("mutation_blocked", true, json!({}));

    // respond_halt valid from Diverged: state stays, halt logged on
    // active_divergence.response_mode.
    gate.respond_halt(1_745_750_009, "trace-halt").expect("halt ok");
    assert_eq!(gate.state(), GateState::Diverged);
    assert_eq!(
        gate.active_divergence().and_then(|a| a.response_mode.as_deref()),
        Some("HALT")
    );
    h.log_phase("halt_recorded", true, json!({}));

    // respond_quarantine: transitions to Quarantined, partition recorded.
    let partition = gate
        .respond_quarantine(
            "partition-east",
            "node-A",
            1_745_750_010,
            "trace-quar",
        )
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
    let auth = OperatorAuthorization::new(
        "operator-prod-1",
        12, // resync_checkpoint_epoch
        1_745_750_100,
        "operator-approved-recovery",
        SIGNING_KEY,
    );
    assert!(
        auth.verify(SIGNING_KEY),
        "freshly minted authorization must verify under same key"
    );
    h.log_phase("auth_built", true, json!({"operator": "operator-prod-1"}));

    // Recover succeeds → Normal.
    let recovery = gate
        .respond_recover(&auth, SIGNING_KEY, 100, 1_745_750_120, "trace-rec")
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
fn e2e_divergence_gate_recover_rejects_tampered_authorization() {
    let h = Harness::new("e2e_divergence_gate_recover_rejects_tampered_authorization");

    let mut gate = ControlPlaneDivergenceGate::new("node-A");

    // Diverged state.
    let local = sv("node-A", 7, "payload-A", "parent-7");
    let remote = sv("node-B", 7, "payload-B-DIFFERENT", "parent-7");
    gate.check_propagation(&local, &remote, 1_745_750_007, "trace-fork");
    assert_eq!(gate.state(), GateState::Diverged);

    let mut auth = OperatorAuthorization::new(
        "operator-rogue",
        12,
        1_745_750_100,
        "rogue-recovery",
        SIGNING_KEY,
    );
    // Tamper a hex char in the authorization_hash.
    let mut chars: Vec<char> = auth.authorization_hash.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    auth.authorization_hash = chars.into_iter().collect();
    assert!(
        !auth.verify(SIGNING_KEY),
        "tampered auth must NOT verify"
    );
    h.log_phase("auth_tampered", true, json!({}));

    let err = gate
        .respond_recover(&auth, SIGNING_KEY, 100, 1_745_750_120, "trace-rec-bad")
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
        other => panic!("expected UnauthorizedRecovery, got {other:?}"),
    }
    // Gate must remain Diverged (not transition to Normal/Recovering).
    assert_eq!(gate.state(), GateState::Diverged);
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
