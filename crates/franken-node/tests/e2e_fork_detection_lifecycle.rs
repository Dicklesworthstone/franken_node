//! Mock-free end-to-end test for the fork-detection state machine.
//!
//! Drives the public surface of
//! `frankenengine_node::control_plane::fork_detection` through the full
//! divergence taxonomy:
//!
//! - `DivergenceDetector::compare`: Converged / Forked / GapDetected /
//!   RollbackDetected.
//! - `compare_and_log`: structured `DivergenceLogEvent` severity matrix
//!   (INFO / WARN / CRITICAL).
//! - `suggest_reconciliation`: per-result actionable guidance
//!   (NoAction / FillGap / ResolveConflict / InvestigateRollback).
//! - `RollbackDetector::feed`: chain validation across a forward sequence,
//!   same-epoch rollback rejection, gap detection, and parent-hash chain break.
//! - `operator_reset`: clears the halted bit set by INV-RFD-HALT-ON-DIVERGENCE.
//!
//! Bead: bd-19l5s.
//!
//! No mocks: real `StateVector` instances, real SHA-256-backed state hashes
//! via `StateVector::compute_state_hash`, real `RollbackProof` objects, real
//! constant-time hash comparisons. Each phase emits a structured tracing
//! event PLUS a JSON-line on stderr so a CI failure can be reconstructed
//! from the test transcript alone.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::control_plane::fork_detection::{
    DetectionResult, DivergenceDetector, ForkDetectionError, ReconciliationSuggestion,
    RollbackDetector, StateVector,
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

#[test]
fn e2e_divergence_detector_converged_path() {
    let h = Harness::new("e2e_divergence_detector_converged_path");

    let mut det = DivergenceDetector::new();
    assert!(!det.is_halted());
    assert_eq!(det.history_len(), 0);
    assert!(det.last_result().is_none());

    // Identical state on both nodes at the same epoch → Converged.
    let local = sv("node-A", 5, "epoch-5-payload", "parent-of-5");
    let remote = sv("node-B", 5, "epoch-5-payload", "parent-of-5");
    let (result, proof) = det.compare(&local, &remote);
    assert_eq!(result, DetectionResult::Converged);
    assert!(proof.is_none(), "Converged path must produce no proof");
    assert!(!det.is_halted(), "Converged must not halt");
    assert_eq!(det.last_result(), Some(&DetectionResult::Converged));
    h.log_phase(
        "converged",
        true,
        json!({"history_len": det.history_len(), "halted": det.is_halted()}),
    );

    // Reconciliation suggestion: NoAction.
    let suggestion = DivergenceDetector::suggest_reconciliation(&local, &remote, &result, proof);
    assert!(matches!(suggestion, ReconciliationSuggestion::NoAction));
    h.log_phase("suggestion_no_action", true, json!({}));
}

#[test]
fn e2e_divergence_detector_forked_path_halts() {
    let h = Harness::new("e2e_divergence_detector_forked_path_halts");

    let mut det = DivergenceDetector::new();
    let local = sv("node-A", 7, "payload-A", "parent-of-7");
    let remote = sv("node-B", 7, "payload-B-DIFFERENT", "parent-of-7");
    let (result, proof, log_event) = det.compare_and_log(&local, &remote);

    assert_eq!(result, DetectionResult::Forked);
    let proof = proof.expect("Forked path emits a RollbackProof");
    assert_eq!(proof.detection_result, DetectionResult::Forked);
    assert!(det.is_halted(), "INV-RFD-HALT-ON-DIVERGENCE not enforced");
    assert_eq!(log_event.severity, "CRITICAL");
    h.log_phase(
        "forked_halt",
        true,
        json!({"event_code": log_event.event_code, "severity": log_event.severity}),
    );

    // Reconciliation suggestion: ResolveConflict carries both hashes.
    let suggestion =
        DivergenceDetector::suggest_reconciliation(&local, &remote, &result, Some(proof));
    match suggestion {
        ReconciliationSuggestion::ResolveConflict {
            epoch,
            local_hash,
            remote_hash,
        } => {
            assert_eq!(epoch, 7);
            assert_ne!(local_hash, remote_hash);
            h.log_phase("suggestion_resolve_conflict", true, json!({"epoch": epoch}));
        }
        other => panic!("expected ResolveConflict, got {other:?}"),
    }

    // operator_reset clears halt.
    det.operator_reset();
    assert!(!det.is_halted(), "operator_reset must clear halt");
    assert!(det.last_result().is_none());
    assert_eq!(det.history_len(), 0);
    h.log_phase("operator_reset", true, json!({}));
}

#[test]
fn e2e_divergence_detector_gap_path_warns_without_halt() {
    let h = Harness::new("e2e_divergence_detector_gap_path_warns_without_halt");

    let mut det = DivergenceDetector::new();
    let local = sv("node-A", 10, "payload-10", "parent-of-10");
    let remote = sv("node-B", 100, "payload-100", "parent-of-100");
    let (result, proof, log_event) = det.compare_and_log(&local, &remote);

    assert_eq!(result, DetectionResult::GapDetected);
    assert!(proof.is_none(), "Gap path produces no rollback proof");
    assert!(!det.is_halted(), "Gap is a WARN, not CRITICAL");
    assert_eq!(log_event.severity, "WARN");
    h.log_phase("gap_warn", true, json!({"severity": log_event.severity}));

    let suggestion = DivergenceDetector::suggest_reconciliation(&local, &remote, &result, None);
    match suggestion {
        ReconciliationSuggestion::FillGap {
            missing_start,
            missing_end,
        } => {
            assert_eq!(missing_start, 11);
            assert_eq!(missing_end, 100);
            h.log_phase(
                "suggestion_fill_gap",
                true,
                json!({"start": missing_start, "end": missing_end}),
            );
        }
        other => panic!("expected FillGap, got {other:?}"),
    }
}

#[test]
fn e2e_divergence_detector_rollback_via_parent_chain_break() {
    let h = Harness::new("e2e_divergence_detector_rollback_via_parent_chain_break");

    let mut det = DivergenceDetector::new();
    // Adjacent epochs (4 → 5) but the newer's parent_state_hash does NOT match
    // the older's state_hash → rollback detected.
    let older = sv("node-A", 4, "payload-4", "parent-of-4");
    let newer = sv(
        "node-B",
        5,
        "payload-5",
        "WRONG-parent-hash-not-matching-older-state",
    );
    let (result, proof) = det.compare(&older, &newer);
    assert_eq!(result, DetectionResult::RollbackDetected);
    let proof = proof.expect("rollback path emits a proof");
    assert_eq!(proof.detection_result, DetectionResult::RollbackDetected);
    assert_eq!(proof.expected_parent_hash, older.state_hash);
    assert_eq!(proof.actual_parent_hash, newer.parent_state_hash);
    assert!(det.is_halted(), "rollback must halt the detector");
    h.log_phase("rollback_detected", true, json!({"halted": true}));

    let suggestion =
        DivergenceDetector::suggest_reconciliation(&older, &newer, &result, Some(proof));
    match suggestion {
        ReconciliationSuggestion::InvestigateRollback { proof } => {
            assert_eq!(proof.detection_result, DetectionResult::RollbackDetected);
            h.log_phase("suggestion_investigate_rollback", true, json!({}));
        }
        other => panic!("expected InvestigateRollback, got {other:?}"),
    }
}

#[test]
fn e2e_rollback_detector_feed_chain_lifecycle() {
    let h = Harness::new("e2e_rollback_detector_feed_chain_lifecycle");

    let mut rd = RollbackDetector::new();
    assert!(rd.last_known().is_none());
    assert_eq!(rd.proof_count(), 0);

    // ── ACT: feed a forward chain with valid parent hashes ─────────
    let s1 = sv("node-A", 1, "payload-1", "");
    rd.feed(s1.clone()).expect("first feed accepted");
    let s2 = sv("node-A", 2, "payload-2", &s1.state_hash);
    rd.feed(s2.clone()).expect("second feed: parent matches");
    let s3 = sv("node-A", 3, "payload-3", &s2.state_hash);
    rd.feed(s3.clone()).expect("third feed: chain still valid");
    assert_eq!(rd.last_known().map(|k| k.epoch), Some(3));
    assert_eq!(rd.proof_count(), 0);
    h.log_phase("forward_chain", true, json!({"epoch": 3}));

    // ── ASSERT: same-epoch rollback rejected ────────────────────────
    let stale = sv("node-A", 3, "payload-replay", &s2.state_hash);
    let err = rd.feed(stale).expect_err("same-epoch feed rejected");
    match err {
        ForkDetectionError::RfdRollbackDetected {
            epoch,
            expected_parent,
            actual_parent,
        } => {
            assert_eq!(epoch, 3);
            assert_eq!(expected_parent, s3.state_hash);
            assert_eq!(actual_parent, s2.state_hash);
            h.log_phase(
                "same_epoch_rollback_rejected",
                true,
                json!({"epoch": epoch}),
            );
        }
        other => panic!("expected RfdRollbackDetected, got {other:?}"),
    }
    assert_eq!(rd.proof_count(), 1);

    // ── ASSERT: gap detection (epoch 3 → epoch 5) ──────────────────
    let gap = sv("node-A", 5, "payload-5", &s3.state_hash);
    let gap_err = rd.feed(gap).expect_err("gap rejected");
    assert!(
        matches!(
            gap_err,
            ForkDetectionError::RfdGapDetected {
                local_epoch: 3,
                remote_epoch: 5,
            }
        ),
        "expected RfdGapDetected{{local=3, remote=5}}, got {gap_err:?}"
    );
    // Even on gap, RollbackDetector promotes the new SV to last_known so
    // forward progress can resume (gap was returned for operator visibility).
    assert_eq!(rd.last_known().map(|k| k.epoch), Some(5));
    h.log_phase("gap_detected", true, json!({"new_epoch": 5}));

    // ── ASSERT: parent-hash chain break detected ────────────────────
    let mut wrong_parent = sv(
        "node-A",
        6,
        "payload-6",
        "deadbeef-not-the-real-parent-hash",
    );
    // Force adjacent so we test the parent-hash branch (not the gap branch).
    wrong_parent.epoch = 6;
    let chain_err = rd
        .feed(wrong_parent.clone())
        .expect_err("chain break rejected");
    match chain_err {
        ForkDetectionError::RfdRollbackDetected {
            epoch,
            actual_parent,
            ..
        } => {
            assert_eq!(epoch, 6);
            assert_eq!(actual_parent, wrong_parent.parent_state_hash);
            h.log_phase("chain_break_rejected", true, json!({"epoch": 6}));
        }
        other => panic!("expected RfdRollbackDetected (chain break), got {other:?}"),
    }
    // The proofs vec accumulates: first same-epoch + this chain break.
    assert_eq!(rd.proof_count(), 2);
    assert!(
        rd.proofs()
            .iter()
            .all(|p| matches!(p.detection_result, DetectionResult::RollbackDetected))
    );
    h.log_phase(
        "proofs_serializable",
        true,
        json!({"count": rd.proof_count()}),
    );
}
