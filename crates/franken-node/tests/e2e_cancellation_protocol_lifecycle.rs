//! Mock-free end-to-end test for the control-plane cancellation protocol FSM.
//!
//! Drives `frankenengine_node::control_plane::cancellation_protocol::CancellationProtocol`
//! through the canonical six-phase lifecycle:
//!
//!   Idle → CancelRequested → Draining → DrainComplete →
//!   Finalizing → Finalized
//!
//! Coverage:
//!   - happy path advances every legal transition with audit events,
//!   - INV-CANP-IDEMPOTENT: duplicate `request_cancel` for an already
//!     CancelRequested workflow is absorbed,
//!   - INV-CANP-DRAIN-BOUNDED: drain timeout exceeded with
//!     `force_on_timeout=true` advances to `DrainComplete` with the
//!     `drain_timed_out` flag set; with `force_on_timeout=false` the
//!     transition is rejected with `DrainTimeout`,
//!   - INV-CANP-FINALIZE-CLEAN: a non-clean `ResourceTracker` rejects
//!     finalize with `ResourceLeak` and the FSM stays in `Finalizing`,
//!   - INV-CANP-AUDIT-COMPLETE: each phase transition writes a
//!     `CancelAuditEvent` with the right `event_code` and from/to
//!     phases,
//!   - illegal transitions are rejected with `InvalidPhase`,
//!   - operations on unknown workflow_ids return `WorkflowNotFound`,
//!   - `AlreadyFinal` rejection on attempts to re-cancel a finalized
//!     workflow.
//!
//! Bead: bd-3bpbs.
//!
//! No mocks: real `CancellationProtocol`, real `DrainConfig`, real
//! `ResourceTracker`, real audit log. Each phase emits a structured
//! tracing event PLUS a JSON-line on stderr.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::control_plane::cancellation_protocol::{
    CancelPhase, CancelProtocolError, CancellationProtocol, DrainConfig, ResourceTracker,
};
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

fn clean_resources() -> ResourceTracker {
    ResourceTracker::empty()
}

#[test]
fn e2e_cancellation_protocol_happy_path_six_phases() {
    let h = Harness::new("e2e_cancellation_protocol_happy_path_six_phases");

    let mut proto = CancellationProtocol::new(DrainConfig::new(60_000, true));

    // Phase 1: REQUEST.
    let rec = proto
        .request_cancel("wf-1", 3, 1_000, "trace-req")
        .expect("request_cancel");
    assert_eq!(rec.current_phase, CancelPhase::CancelRequested);
    assert_eq!(rec.in_flight_count, 3);
    h.log_phase("requested", true, json!({"in_flight": 3}));

    // INV-CANP-IDEMPOTENT: a second request on CancelRequested is absorbed.
    proto
        .request_cancel("wf-1", 5, 1_010, "trace-req-dup")
        .expect("idempotent request");
    let rec = proto.get_record("wf-1").expect("rec");
    assert_eq!(rec.current_phase, CancelPhase::CancelRequested);
    h.log_phase("idempotent_request", true, json!({}));

    // Phase 2a: DRAIN start.
    proto
        .start_drain("wf-1", 1_100, "trace-drain-start")
        .expect("start_drain");
    assert_eq!(
        proto.current_phase("wf-1"),
        Some(CancelPhase::Draining)
    );
    h.log_phase("draining", true, json!({}));

    // Phase 2b: DRAIN complete.
    proto
        .complete_drain("wf-1", 1_200, "trace-drain-complete")
        .expect("complete_drain");
    assert_eq!(
        proto.current_phase("wf-1"),
        Some(CancelPhase::DrainComplete)
    );
    h.log_phase("drain_complete", true, json!({}));

    // Phase 3: FINALIZE with clean resources.
    proto
        .finalize("wf-1", &clean_resources(), 1_300, "trace-final")
        .expect("finalize");
    assert_eq!(
        proto.current_phase("wf-1"),
        Some(CancelPhase::Finalized)
    );
    h.log_phase("finalized", true, json!({}));

    // INV-CANP-AUDIT-COMPLETE: every phase logged.
    let log = proto.audit_log();
    let event_codes: Vec<_> = log.iter().map(|e| e.event_code.as_str()).collect();
    assert!(event_codes.iter().any(|c| *c == "CAN-001"), "request logged");
    assert!(event_codes.iter().any(|c| *c == "CAN-002"), "drain start logged");
    assert!(event_codes.iter().any(|c| *c == "CAN-003"), "drain complete logged");
    assert!(event_codes.iter().any(|c| *c == "CAN-005"), "finalize logged");
    h.log_phase("audit_complete", true, json!({"events": log.len()}));

    // Re-finalizing a Finalized workflow returns AlreadyFinal.
    let err = proto
        .finalize("wf-1", &clean_resources(), 1_400, "trace-refinal")
        .expect_err("re-finalize rejected");
    assert!(matches!(err, CancelProtocolError::AlreadyFinal { .. }));
    assert_eq!(err.code(), "ERR_CANCEL_ALREADY_FINAL");
    h.log_phase("already_final_rejected", true, json!({"code": err.code()}));
}

#[test]
fn e2e_cancellation_protocol_drain_timeout_force_vs_reject() {
    let h = Harness::new("e2e_cancellation_protocol_drain_timeout_force_vs_reject");

    // force_on_timeout = true: timeout exceeded → advances anyway,
    // `drain_timed_out` flag set.
    let mut proto = CancellationProtocol::new(DrainConfig::new(100, true));
    proto
        .request_cancel("wf-force", 1, 1_000, "trace-r")
        .expect("request");
    proto.start_drain("wf-force", 1_010, "trace-s").expect("start");
    // 5_000 - 1_010 = 3_990ms elapsed >> 100ms timeout.
    proto
        .complete_drain("wf-force", 5_000, "trace-c")
        .expect("complete with force");
    let rec = proto.get_record("wf-force").expect("rec");
    assert_eq!(rec.current_phase, CancelPhase::DrainComplete);
    assert!(rec.drain_timed_out, "drain_timed_out flag should be set");
    h.log_phase("force_advanced_with_flag", true, json!({}));

    // force_on_timeout = false: timeout exceeded → rejected with DrainTimeout.
    let mut proto_strict = CancellationProtocol::new(DrainConfig::new(100, false));
    proto_strict
        .request_cancel("wf-strict", 1, 1_000, "trace-r")
        .expect("request");
    proto_strict
        .start_drain("wf-strict", 1_010, "trace-s")
        .expect("start");
    let err = proto_strict
        .complete_drain("wf-strict", 5_000, "trace-c")
        .expect_err("timeout rejects in strict mode");
    match err {
        CancelProtocolError::DrainTimeout {
            workflow_id,
            elapsed_ms,
            timeout_ms,
        } => {
            assert_eq!(workflow_id, "wf-strict");
            assert!(elapsed_ms >= timeout_ms);
            h.log_phase(
                "strict_timeout_rejected",
                true,
                json!({"elapsed_ms": elapsed_ms, "timeout_ms": timeout_ms}),
            );
        }
        other => panic!("expected DrainTimeout, got {other:?}"),
    }
    // FSM stays in Draining when strict timeout fires.
    let rec = proto_strict.get_record("wf-strict").expect("rec");
    assert_eq!(rec.current_phase, CancelPhase::Draining);
    h.log_phase(
        "strict_phase_stayed_draining",
        true,
        json!({"phase": "draining"}),
    );
}

#[test]
fn e2e_cancellation_protocol_finalize_resource_leak_rejected() {
    let h = Harness::new("e2e_cancellation_protocol_finalize_resource_leak_rejected");

    let mut proto = CancellationProtocol::new(DrainConfig::new(60_000, true));
    proto
        .request_cancel("wf-leak", 0, 1_000, "trace-r")
        .expect("request");
    proto.start_drain("wf-leak", 1_010, "trace-s").expect("start");
    proto
        .complete_drain("wf-leak", 1_020, "trace-c")
        .expect("complete");

    // INV-CANP-FINALIZE-CLEAN: leaked open handle + held lock + pending write.
    let leaky = ResourceTracker {
        open_handles: vec!["fd:42".to_string()],
        pending_writes: 3,
        held_locks: vec!["lock:registry".to_string()],
    };
    assert!(!leaky.is_clean());
    let leaks = leaky.leaked_resources();
    assert!(leaks.iter().any(|s| s.contains("handle:")));

    let err = proto
        .finalize("wf-leak", &leaky, 1_030, "trace-final")
        .expect_err("leak rejected");
    match err {
        CancelProtocolError::ResourceLeak {
            workflow_id,
            leaked_resources,
        } => {
            assert_eq!(workflow_id, "wf-leak");
            assert!(!leaked_resources.is_empty());
            h.log_phase(
                "leak_rejected",
                true,
                json!({"leaks": leaked_resources.len()}),
            );
        }
        other => panic!("expected ResourceLeak, got {other:?}"),
    }
    // FSM stays in Finalizing (operator can intervene).
    let rec = proto.get_record("wf-leak").expect("rec");
    assert_eq!(rec.current_phase, CancelPhase::Finalizing);
    assert!(!rec.resource_leaks.is_empty());
    h.log_phase(
        "phase_stuck_in_finalizing",
        true,
        json!({"leaks": rec.resource_leaks.len()}),
    );
}

#[test]
fn e2e_cancellation_protocol_illegal_transitions_and_unknown_workflow() {
    let h = Harness::new("e2e_cancellation_protocol_illegal_transitions_and_unknown_workflow");

    let mut proto = CancellationProtocol::new(DrainConfig::default());

    // start_drain on unknown workflow → WorkflowNotFound.
    let err = proto
        .start_drain("wf-ghost", 1_000, "trace-ghost")
        .expect_err("unknown rejected");
    assert!(matches!(
        err,
        CancelProtocolError::WorkflowNotFound { .. }
    ));
    assert_eq!(err.code(), "ERR_CANCEL_NOT_FOUND");
    h.log_phase("unknown_workflow_rejected", true, json!({"code": err.code()}));

    // Request → start_drain → finalize WITHOUT complete_drain in between
    // (illegal transition Draining → Finalizing).
    proto
        .request_cancel("wf-illegal", 0, 1_000, "trace-r")
        .expect("request");
    proto
        .start_drain("wf-illegal", 1_010, "trace-s")
        .expect("start");
    let err = proto
        .finalize("wf-illegal", &clean_resources(), 1_020, "trace-skip")
        .expect_err("skip-drain-complete rejected");
    assert!(matches!(err, CancelProtocolError::InvalidPhase { .. }));
    assert_eq!(err.code(), "ERR_CANCEL_INVALID_PHASE");
    h.log_phase("invalid_transition_rejected", true, json!({"code": err.code()}));

    // can_transition_to: Idle → DrainComplete is illegal.
    assert!(!CancelPhase::Idle.can_transition_to(&CancelPhase::DrainComplete));
    // Finalized has no legal targets.
    assert!(CancelPhase::Finalized.legal_targets().is_empty());
    h.log_phase("transition_table_correct", true, json!({}));
}
