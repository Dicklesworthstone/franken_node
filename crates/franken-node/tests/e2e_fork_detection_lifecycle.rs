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
//! - `MarkerProofVerifier::verify`: exact marker/epoch acceptance and
//!   fail-closed handling for wrong hashes or claimed epochs.
//! - `operator_reset`: clears the halted bit set by INV-RFD-HALT-ON-DIVERGENCE.
//! - Halt stickiness: later Converged comparisons never clear halt without
//!   explicit operator reset.
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
    DetectionResult, DivergenceDetector, ForkDetectionError, MarkerProofVerifier,
    ReconciliationSuggestion, RollbackDetector, StateVector,
};
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
        match serde_json::to_string(&entry) {
            Ok(line) => eprintln!("{line}"),
            Err(error) => eprintln!(
                "{{\"test_name\":\"{}\",\"phase\":\"{}\",\"success\":false,\"detail\":\"phase log serialization failed: {error}\"}}",
                self.test_name, phase
            ),
        }
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

fn marker_stream(entries: &[(MarkerEventType, &str, u64, &str)]) -> MarkerStream {
    let mut stream = MarkerStream::new();
    for (event_type, payload, timestamp, trace_id) in entries {
        let appended = stream.append(*event_type, payload, *timestamp, trace_id);
        assert!(
            appended.is_ok(),
            "marker stream append succeeds: {appended:?}"
        );
    }
    stream
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
    assert!(proof.is_some(), "Forked path emits a RollbackProof");
    let Some(proof) = proof else {
        return;
    };
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
    assert!(
        matches!(suggestion, ReconciliationSuggestion::ResolveConflict { .. }),
        "expected ResolveConflict, got {suggestion:?}"
    );
    if let ReconciliationSuggestion::ResolveConflict {
        epoch,
        local_hash,
        remote_hash,
    } = suggestion
    {
        assert_eq!(epoch, 7);
        assert_ne!(local_hash, remote_hash);
        h.log_phase("suggestion_resolve_conflict", true, json!({"epoch": epoch}));
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
    assert!(
        matches!(suggestion, ReconciliationSuggestion::FillGap { .. }),
        "expected FillGap, got {suggestion:?}"
    );
    if let ReconciliationSuggestion::FillGap {
        missing_start,
        missing_end,
    } = suggestion
    {
        assert_eq!(missing_start, 11);
        assert_eq!(missing_end, 100);
        h.log_phase(
            "suggestion_fill_gap",
            true,
            json!({"start": missing_start, "end": missing_end}),
        );
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
    assert!(proof.is_some(), "rollback path emits a proof");
    let Some(proof) = proof else {
        return;
    };
    assert_eq!(proof.detection_result, DetectionResult::RollbackDetected);
    assert_eq!(proof.expected_parent_hash, older.state_hash);
    assert_eq!(proof.actual_parent_hash, newer.parent_state_hash);
    assert_eq!(proof.local_state, older);
    assert_eq!(proof.remote_state, newer);
    assert!(
        proof.trace_id.starts_with("rfd-node-A-node-B-4"),
        "rollback proof trace id should bind the compared nodes and local epoch"
    );
    assert!(
        proof.detection_timestamp >= older.timestamp,
        "rollback proof must carry an audit timestamp"
    );
    assert!(det.is_halted(), "rollback must halt the detector");
    h.log_phase(
        "rollback_detected",
        true,
        json!({
            "halted": true,
            "trace_id": proof.trace_id.clone(),
            "expected_parent_hash": proof.expected_parent_hash.clone(),
            "actual_parent_hash": proof.actual_parent_hash.clone(),
        }),
    );

    let suggestion =
        DivergenceDetector::suggest_reconciliation(&older, &newer, &result, Some(proof));
    assert!(
        matches!(
            suggestion,
            ReconciliationSuggestion::InvestigateRollback { .. }
        ),
        "expected InvestigateRollback, got {suggestion:?}"
    );
    if let ReconciliationSuggestion::InvestigateRollback { proof } = suggestion {
        assert_eq!(proof.detection_result, DetectionResult::RollbackDetected);
        assert_eq!(proof.expected_parent_hash, proof.local_state.state_hash);
        assert_eq!(
            proof.actual_parent_hash,
            proof.remote_state.parent_state_hash
        );
        h.log_phase(
            "suggestion_investigate_rollback",
            true,
            json!({"trace_id": proof.trace_id}),
        );
    }
}

#[test]
fn e2e_marker_proof_verifier_accepts_exact_epoch_and_fails_closed() {
    let h = Harness::new("e2e_marker_proof_verifier_accepts_exact_epoch_and_fails_closed");

    let stream = marker_stream(&[
        (
            MarkerEventType::PolicyChange,
            "sha256:policy-0",
            1_745_760_000,
            "trace-policy-0",
        ),
        (
            MarkerEventType::EpochTransition,
            "sha256:epoch-1",
            1_745_760_010,
            "trace-epoch-1",
        ),
    ]);
    assert_eq!(stream.len(), 2, "second marker exists");
    let Some(accepted_marker) = stream.get(1) else {
        unreachable!("stream length assertion guarantees the second marker exists");
    };
    let accepted_hash = accepted_marker.marker_hash.clone();

    let exact_epoch = MarkerProofVerifier::verify(&stream, &accepted_hash, 1);
    assert!(
        exact_epoch.is_ok(),
        "exact marker hash at claimed epoch must verify: {exact_epoch:?}"
    );
    h.log_phase(
        "marker_exact_epoch_verified",
        true,
        json!({"claimed_epoch": 1}),
    );

    let wrong_epoch = MarkerProofVerifier::verify(&stream, &accepted_hash, 0);
    assert!(
        wrong_epoch.is_err(),
        "valid marker at the wrong epoch must fail closed"
    );
    let Err(wrong_epoch) = wrong_epoch else {
        return;
    };
    assert!(
        matches!(wrong_epoch, ForkDetectionError::RfdMarkerNotFound { .. }),
        "expected RfdMarkerNotFound for wrong epoch, got {wrong_epoch:?}"
    );
    if let ForkDetectionError::RfdMarkerNotFound {
        marker_id,
        claimed_epoch,
    } = wrong_epoch
    {
        assert_eq!(marker_id, accepted_hash);
        assert_eq!(claimed_epoch, 0);
        h.log_phase(
            "marker_wrong_epoch_rejected",
            true,
            json!({"claimed_epoch": 0}),
        );
    }

    let wrong_hash = MarkerProofVerifier::verify(&stream, "wrong-marker-hash", 1);
    assert!(wrong_hash.is_err(), "wrong marker hash must fail closed");
    let Err(wrong_hash) = wrong_hash else {
        return;
    };
    assert_eq!(wrong_hash.code(), "RFD_MARKER_NOT_FOUND");
    h.log_phase("marker_wrong_hash_rejected", true, json!({}));
}

#[test]
fn e2e_divergence_detector_halt_is_sticky_until_operator_reset() {
    let h = Harness::new("e2e_divergence_detector_halt_is_sticky_until_operator_reset");

    let mut det = DivergenceDetector::new();
    let fork_a = sv("node-A", 8, "fork-a", "parent-of-8");
    let fork_b = sv("node-B", 8, "fork-b", "parent-of-8");
    let (fork_result, fork_proof, fork_event) = det.compare_and_log(&fork_a, &fork_b);
    assert_eq!(fork_result, DetectionResult::Forked);
    assert!(fork_proof.is_some());
    assert_eq!(fork_event.severity, "CRITICAL");
    assert!(det.is_halted(), "fork must set halted");
    h.log_phase(
        "fork_halted",
        true,
        json!({"severity": fork_event.severity}),
    );

    let converged_a = sv("node-A", 9, "same-after-fork", "parent-of-9");
    let converged_b = sv("node-B", 9, "same-after-fork", "parent-of-9");
    let (converged_result, converged_proof, converged_event) =
        det.compare_and_log(&converged_a, &converged_b);
    assert_eq!(converged_result, DetectionResult::Converged);
    assert!(converged_proof.is_none());
    assert_eq!(converged_event.severity, "INFO");
    assert!(
        det.is_halted(),
        "Converged comparison must not clear a prior divergence halt"
    );
    assert_eq!(det.last_result(), Some(&DetectionResult::Converged));
    h.log_phase(
        "converged_does_not_clear_halt",
        true,
        json!({"halted": det.is_halted()}),
    );

    det.operator_reset();
    assert!(
        !det.is_halted(),
        "operator_reset is the only halt clear path"
    );
    assert!(det.last_result().is_none());
    h.log_phase("operator_reset_cleared_halt", true, json!({}));
}

#[test]
fn e2e_gap_detected_reconciliation_is_warn_fill_gap_without_proof() {
    let h = Harness::new("e2e_gap_detected_reconciliation_is_warn_fill_gap_without_proof");

    let mut det = DivergenceDetector::new();
    let local = sv("node-A", 10, "payload-10", "parent-of-10");
    let remote = sv("node-B", 14, "payload-14", "parent-of-14");
    let (result, proof, event) = det.compare_and_log(&local, &remote);

    assert_eq!(result, DetectionResult::GapDetected);
    assert!(proof.is_none(), "GapDetected must not emit rollback proof");
    assert_eq!(event.severity, "WARN");
    assert_eq!(event.local_epoch, 10);
    assert_eq!(event.remote_epoch, 14);
    assert!(!det.is_halted(), "GapDetected must not halt mutations");
    h.log_phase(
        "gap_detected_warn",
        true,
        json!({"severity": event.severity, "local_epoch": 10, "remote_epoch": 14}),
    );

    let suggestion = DivergenceDetector::suggest_reconciliation(&local, &remote, &result, None);
    assert!(
        matches!(suggestion, ReconciliationSuggestion::FillGap { .. }),
        "expected FillGap for GapDetected, got {suggestion:?}"
    );
    if let ReconciliationSuggestion::FillGap {
        missing_start,
        missing_end,
    } = suggestion
    {
        assert_eq!(missing_start, 11);
        assert_eq!(missing_end, 14);
        h.log_phase(
            "gap_fill_range",
            true,
            json!({"missing_start": missing_start, "missing_end": missing_end}),
        );
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
    let first_feed = rd.feed(s1.clone());
    assert!(first_feed.is_ok(), "first feed accepted: {first_feed:?}");
    let s2 = sv("node-A", 2, "payload-2", &s1.state_hash);
    let second_feed = rd.feed(s2.clone());
    assert!(
        second_feed.is_ok(),
        "second feed: parent matches: {second_feed:?}"
    );
    let s3 = sv("node-A", 3, "payload-3", &s2.state_hash);
    let third_feed = rd.feed(s3.clone());
    assert!(
        third_feed.is_ok(),
        "third feed: chain still valid: {third_feed:?}"
    );
    assert_eq!(rd.last_known().map(|k| k.epoch), Some(3));
    assert_eq!(rd.proof_count(), 0);
    h.log_phase("forward_chain", true, json!({"epoch": 3}));

    // ── ASSERT: same-epoch rollback rejected ────────────────────────
    let stale = sv("node-A", 3, "payload-replay", &s2.state_hash);
    let err = rd.feed(stale);
    assert!(err.is_err(), "same-epoch feed rejected");
    let Err(err) = err else {
        return;
    };
    assert!(
        matches!(err, ForkDetectionError::RfdRollbackDetected { .. }),
        "expected RfdRollbackDetected, got {err:?}"
    );
    if let ForkDetectionError::RfdRollbackDetected {
        epoch,
        expected_parent,
        actual_parent,
    } = err
    {
        assert_eq!(epoch, 3);
        assert_eq!(expected_parent, s3.state_hash);
        assert_eq!(actual_parent, s2.state_hash);
        h.log_phase(
            "same_epoch_rollback_rejected",
            true,
            json!({"epoch": epoch}),
        );
    }
    assert_eq!(rd.proof_count(), 1);

    // ── ASSERT: gap detection (epoch 3 → epoch 5) ──────────────────
    let gap = sv("node-A", 5, "payload-5", &s3.state_hash);
    let gap_err = rd.feed(gap);
    assert!(gap_err.is_err(), "gap rejected");
    let Err(gap_err) = gap_err else {
        return;
    };
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
    let chain_err = rd.feed(wrong_parent.clone());
    assert!(chain_err.is_err(), "chain break rejected");
    let Err(chain_err) = chain_err else {
        return;
    };
    assert!(
        matches!(chain_err, ForkDetectionError::RfdRollbackDetected { .. }),
        "expected RfdRollbackDetected (chain break), got {chain_err:?}"
    );
    if let ForkDetectionError::RfdRollbackDetected {
        epoch,
        actual_parent,
        ..
    } = chain_err
    {
        assert_eq!(epoch, 6);
        assert_eq!(actual_parent, wrong_parent.parent_state_hash);
        h.log_phase("chain_break_rejected", true, json!({"epoch": 6}));
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
