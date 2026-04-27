//! Mock-free end-to-end test for the epoch transition barrier coordinator.
//!
//! Drives `frankenengine_node::control_plane::epoch_transition_barrier::EpochTransitionBarrier`
//! through the canonical four-phase FSM: Proposed → Draining →
//! (Committed | Aborted).
//!
//! Coverage:
//!   - register_participant + propose moves to Draining,
//!   - per-participant drain ACKs are collected; try_commit while ACKs
//!     missing returns NotAllAcked,
//!   - all ACKs received → try_commit returns
//!     `BarrierCommitOutcome::Committed { target_epoch }`,
//!   - try_commit past `global_timeout_ms` with missing ACKs auto-aborts
//!     and returns `BarrierCommitOutcome::Aborted { reason: Timeout }`,
//!   - explicit `abort` succeeds and the system stays at the current
//!     epoch (INV-BARRIER-ABORT-SAFE),
//!   - INV-BARRIER-SERIALIZED: a second `propose` while one is active
//!     returns `ConcurrentBarrier`,
//!   - EpochMismatch: target epoch != current+1 rejected,
//!   - EpochOverflow at u64::MAX rejected,
//!   - BarrierIdMismatch: ACK with wrong barrier_id rejected,
//!   - UnknownParticipant: ACK from non-registered participant rejected,
//!   - record_drain_failure aborts with `DrainFailed` reason,
//!   - terminal barriers retain transcript/audit evidence but still allow
//!     participant unregister once no barrier is active.
//!
//! Bead: bd-2gj4n.
//!
//! No mocks: real `EpochTransitionBarrier`, real `BarrierConfig`, real
//! BTreeSet-backed participant registry, real audit history. Each phase
//! emits a structured tracing event PLUS a JSON-line on stderr.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::control_plane::epoch_transition_barrier::{
    AbortReason, BarrierCommitOutcome, BarrierConfig, BarrierError, BarrierPhase, DrainAck,
    EpochTransitionBarrier,
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

fn build_barrier(global_timeout_ms: u64, drain_timeout_ms: u64) -> EpochTransitionBarrier {
    EpochTransitionBarrier::new(BarrierConfig::new(global_timeout_ms, drain_timeout_ms))
}

#[test]
fn e2e_barrier_happy_path_commit_with_all_acks() {
    let h = Harness::new("e2e_barrier_happy_path_commit_with_all_acks");

    let mut barrier = build_barrier(60_000, 30_000);
    for pid in ["node-A", "node-B", "node-C"] {
        barrier.register_participant(pid);
    }
    assert_eq!(barrier.registered_participants().len(), 3);
    h.log_phase("registered", true, json!({"count": 3}));

    let inst = barrier
        .propose(7, 8, 1_000, "trace-prop")
        .expect("propose ok");
    let barrier_id = inst.barrier_id.clone();
    assert!(barrier.is_barrier_active());
    let active = barrier.active_barrier().expect("active");
    assert_eq!(active.phase, BarrierPhase::Draining);
    assert_eq!(active.target_epoch, 8);
    h.log_phase(
        "proposed_into_draining",
        true,
        json!({"barrier_id": barrier_id, "target": 8}),
    );

    // Try commit before any ACKs → NotAllAcked.
    let err = barrier
        .try_commit(1_100, "trace-early-commit")
        .expect_err("not all acked");
    match err {
        BarrierError::NotAllAcked { missing } => {
            assert_eq!(missing.len(), 3);
            h.log_phase("not_all_acked", true, json!({"missing": missing.len()}));
        }
        other => panic!("expected NotAllAcked, got {other:?}"),
    }

    // Send all 3 ACKs.
    for (i, pid) in ["node-A", "node-B", "node-C"].iter().enumerate() {
        barrier
            .record_drain_ack(DrainAck {
                participant_id: pid.to_string(),
                barrier_id: barrier_id.clone(),
                drained_items: 100u64.saturating_add(i as u64),
                elapsed_ms: 50 + i as u64 * 10,
                trace_id: format!("trace-ack-{i}"),
            })
            .expect("ack ok");
    }
    let active = barrier.active_barrier().expect("active");
    assert_eq!(active.ack_count(), 3);
    assert!(active.all_acked());
    h.log_phase("all_acked", true, json!({}));

    let outcome = barrier
        .try_commit(1_500, "trace-commit")
        .expect("commit ok");
    assert_eq!(outcome, BarrierCommitOutcome::Committed { target_epoch: 8 });
    let active = barrier.active_barrier().expect("active");
    assert_eq!(active.phase, BarrierPhase::Committed);
    assert_eq!(barrier.completed_barrier_count(), 1);
    h.log_phase("committed", true, json!({"target_epoch": 8}));
}

#[test]
fn e2e_barrier_timeout_auto_aborts() {
    let h = Harness::new("e2e_barrier_timeout_auto_aborts");

    // Tight global timeout (100ms), drain timeout 50ms.
    let mut barrier = build_barrier(100, 50);
    barrier.register_participant("node-A");
    barrier.register_participant("node-B");

    barrier.propose(0, 1, 1_000, "trace-prop").expect("propose");

    // Only node-A acks; node-B is missing.
    barrier
        .record_drain_ack(DrainAck {
            participant_id: "node-A".to_string(),
            barrier_id: "barrier-000001".to_string(),
            drained_items: 5,
            elapsed_ms: 30,
            trace_id: "trace-ack-A".to_string(),
        })
        .expect("ack A");

    // Try commit AFTER global timeout — should auto-abort.
    let outcome = barrier
        .try_commit(1_200, "trace-late-commit")
        .expect("commit returns Aborted");
    match outcome {
        BarrierCommitOutcome::Aborted {
            current_epoch,
            reason,
        } => {
            assert_eq!(current_epoch, 0, "INV-BARRIER-ABORT-SAFE: epoch unchanged");
            match reason {
                AbortReason::Timeout {
                    missing_participants,
                } => {
                    assert_eq!(missing_participants, vec!["node-B".to_string()]);
                    h.log_phase("timeout_auto_aborted", true, json!({"missing": "node-B"}));
                }
                other => panic!("expected Timeout reason, got {other:?}"),
            }
        }
        other => panic!("expected Aborted, got {other:?}"),
    }

    let active = barrier.active_barrier().expect("active still references");
    assert_eq!(active.phase, BarrierPhase::Aborted);
}

#[test]
fn e2e_barrier_invariant_serialized_rejects_concurrent_propose() {
    let h = Harness::new("e2e_barrier_invariant_serialized_rejects_concurrent_propose");

    let mut barrier = build_barrier(60_000, 30_000);
    barrier.register_participant("node-A");

    barrier.propose(5, 6, 1_000, "trace-1").expect("propose 1");
    let err = barrier
        .propose(5, 6, 1_010, "trace-2")
        .expect_err("concurrent rejected");
    assert!(matches!(err, BarrierError::ConcurrentBarrier { .. }));
    assert_eq!(err.code(), "ERR_BARRIER_CONCURRENT");
    h.log_phase("concurrent_rejected", true, json!({"code": err.code()}));
}

#[test]
fn e2e_barrier_epoch_validation() {
    let h = Harness::new("e2e_barrier_epoch_validation");

    let mut barrier = build_barrier(60_000, 30_000);
    barrier.register_participant("node-A");

    // EpochMismatch: target != current+1.
    let err = barrier
        .propose(5, 7, 1_000, "trace-jump")
        .expect_err("non-consecutive rejected");
    assert!(matches!(err, BarrierError::EpochMismatch { .. }));
    assert_eq!(err.code(), "ERR_BARRIER_EPOCH_MISMATCH");
    h.log_phase("epoch_mismatch", true, json!({"code": err.code()}));

    // EpochOverflow at u64::MAX.
    let err = barrier
        .propose(u64::MAX, 0, 1_001, "trace-overflow")
        .expect_err("overflow rejected");
    assert!(matches!(err, BarrierError::EpochOverflow { .. }));
    assert_eq!(err.code(), "ERR_BARRIER_EPOCH_OVERFLOW");
    h.log_phase("epoch_overflow", true, json!({"code": err.code()}));

    // No participants → NoParticipants.
    let mut empty = build_barrier(60_000, 30_000);
    let err = empty
        .propose(0, 1, 1_002, "trace-empty")
        .expect_err("no participants rejected");
    assert!(matches!(err, BarrierError::NoParticipants));
    assert_eq!(err.code(), "ERR_BARRIER_NO_PARTICIPANTS");
    h.log_phase("no_participants", true, json!({"code": err.code()}));
}

#[test]
fn e2e_barrier_ack_validation_rejects_mismatch_and_unknown() {
    let h = Harness::new("e2e_barrier_ack_validation_rejects_mismatch_and_unknown");

    let mut barrier = build_barrier(60_000, 30_000);
    barrier.register_participant("node-A");
    barrier.propose(0, 1, 1_000, "trace-prop").expect("propose");

    // BarrierIdMismatch.
    let err = barrier
        .record_drain_ack(DrainAck {
            participant_id: "node-A".to_string(),
            barrier_id: "barrier-WRONG".to_string(),
            drained_items: 1,
            elapsed_ms: 10,
            trace_id: "trace-bad-id".to_string(),
        })
        .expect_err("wrong barrier_id rejected");
    assert!(matches!(err, BarrierError::BarrierIdMismatch { .. }));
    assert_eq!(err.code(), "ERR_BARRIER_ID_MISMATCH");
    h.log_phase("barrier_id_mismatch", true, json!({"code": err.code()}));

    // UnknownParticipant.
    let err = barrier
        .record_drain_ack(DrainAck {
            participant_id: "node-GHOST".to_string(),
            barrier_id: "barrier-000001".to_string(),
            drained_items: 1,
            elapsed_ms: 10,
            trace_id: "trace-ghost".to_string(),
        })
        .expect_err("ghost rejected");
    assert!(matches!(err, BarrierError::UnknownParticipant { .. }));
    assert_eq!(err.code(), "ERR_BARRIER_UNKNOWN_PARTICIPANT");
    h.log_phase("unknown_participant", true, json!({"code": err.code()}));
}

#[test]
fn e2e_barrier_drain_failure_aborts() {
    let h = Harness::new("e2e_barrier_drain_failure_aborts");

    let mut barrier = build_barrier(60_000, 30_000);
    barrier.register_participant("node-A");
    barrier.register_participant("node-B");
    barrier.propose(3, 4, 1_000, "trace-prop").expect("propose");

    let current = barrier
        .record_drain_failure("node-B", "disk full", 1_050, "trace-fail")
        .expect("record drain failure");
    assert_eq!(current, 3, "INV-BARRIER-ABORT-SAFE: epoch unchanged");
    let active = barrier.active_barrier().expect("active");
    assert_eq!(active.phase, BarrierPhase::Aborted);
    if let Some(AbortReason::DrainFailed {
        participant_id,
        detail,
    }) = &active.abort_reason
    {
        assert_eq!(participant_id, "node-B");
        assert_eq!(detail, "disk full");
        h.log_phase("drain_failed_abort", true, json!({"participant": "node-B"}));
    } else {
        panic!("expected DrainFailed abort reason");
    }
    assert_eq!(barrier.completed_barrier_count(), 1);
}

#[test]
fn e2e_barrier_unregister_blocked_during_active_barrier() {
    let h = Harness::new("e2e_barrier_unregister_blocked_during_active_barrier");

    let mut barrier = build_barrier(60_000, 30_000);
    barrier.register_participant("node-A");

    // Before propose: unregister succeeds.
    barrier
        .unregister_participant("node-A")
        .expect("unregister allowed when no barrier active");
    assert_eq!(barrier.registered_participants().len(), 0);
    h.log_phase("unregister_when_idle", true, json!({}));

    // Re-register and propose.
    barrier.register_participant("node-A");
    barrier.propose(0, 1, 1_000, "trace-prop").expect("propose");

    // Unregister during active barrier → ConcurrentBarrier.
    let err = barrier
        .unregister_participant("node-A")
        .expect_err("unregister blocked");
    assert!(matches!(err, BarrierError::ConcurrentBarrier { .. }));
    h.log_phase("unregister_blocked_during_active", true, json!({}));

    barrier
        .record_drain_ack(DrainAck {
            participant_id: "node-A".to_string(),
            barrier_id: "barrier-000001".to_string(),
            drained_items: 2,
            elapsed_ms: 25,
            trace_id: "trace-ack".to_string(),
        })
        .expect("ack ok before explicit abort");
    let current_epoch = barrier
        .abort(
            AbortReason::Cancelled {
                detail: "operator cancelled".to_string(),
            },
            1_050,
            "trace-abort",
        )
        .expect("explicit abort");
    assert_eq!(current_epoch, 0, "INV-BARRIER-ABORT-SAFE: epoch unchanged");

    let transcript = barrier
        .transcript()
        .expect("transcript retained after abort");
    assert_eq!(transcript.phase, BarrierPhase::Aborted);
    let abort_sent_count = transcript
        .entries
        .iter()
        .filter(|entry| entry.event_code == "BARRIER_ABORT_SENT")
        .count();
    assert_eq!(abort_sent_count, 1);
    assert!(
        transcript
            .entries
            .iter()
            .any(|entry| entry.event_code == "BARRIER_ABORTED"),
        "explicit abort should be present in transcript"
    );
    let transcript_lines: Vec<_> = transcript.export_jsonl().lines().collect();
    assert_eq!(transcript_lines.len(), transcript.entries.len());
    for line in transcript_lines {
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("transcript line should parse as JSON");
        assert_eq!(parsed["barrier_id"], "barrier-000001");
    }

    let audit = barrier.audit_history();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].outcome, "ABORTED");
    assert_eq!(audit[0].acks_received, 1);
    assert_eq!(
        audit[0].abort_reason.as_deref(),
        Some("cancelled: operator cancelled")
    );
    h.log_phase(
        "explicit_abort_retains_audit",
        true,
        json!({"abort_sent_count": abort_sent_count}),
    );

    barrier
        .unregister_participant("node-A")
        .expect("terminal barrier should not block unregister");
    assert_eq!(barrier.registered_participants().len(), 0);
    h.log_phase("unregister_after_terminal_barrier", true, json!({}));
}
