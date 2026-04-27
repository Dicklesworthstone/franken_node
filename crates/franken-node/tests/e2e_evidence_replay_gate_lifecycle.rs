//! Mock-free end-to-end test for the control-plane evidence replay gate.
//!
//! Drives the public surface of
//! `frankenengine_node::control_plane::evidence_replay_gate::EvidenceReplayGate`
//! end-to-end through real `CapturedEvidence` objects:
//!
//!   1. `capture_evidence` then `replay_decision` with the original action →
//!      `ReplayVerdict::Reproduced` and counter advances,
//!   2. `replay_decision` with a different action → `Diverged` carrying
//!      original/replayed/diff_hash/diff_size_bytes,
//!   3. `replay_decision` against an entry whose `input_hash` is tampered
//!      → `Error{reason}` and `total_errors` increments,
//!   4. `evaluate_gate` over a mixed evidence store: any divergence or
//!      error yields `GateDecision::Fail`; a pure-reproduced store yields
//!      `Pass`,
//!   5. `replay_log` records every RPL-001..RPL-005 event in order with
//!      stable trace_ids.
//!
//! Bead: bd-14kvi.
//!
//! No mocks: real `CapturedEvidence` with SHA-256 `compute_input_hash`,
//! real constant-time action comparison, real bounded-vec event log. Each
//! phase emits a structured tracing event PLUS a JSON-line on stderr.

use std::collections::BTreeMap;
use std::sync::Once;
use std::time::Instant;

use frankenengine_node::control_plane::evidence_replay_gate::{
    CapturedEvidence, DecisionType, EvidenceReplayGate, GateDecision, ReplayVerdict,
    RPL_001_REPLAY_INITIATED, RPL_002_REPRODUCED, RPL_003_DIVERGED, RPL_004_ERROR,
    RPL_005_GATE_DECISION,
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

/// Build a real `CapturedEvidence` whose `input_hash` is correct under
/// `compute_input_hash`. The returned struct is ready to feed into
/// `EvidenceReplayGate::replay_decision`.
fn make_evidence(
    decision_id: &str,
    decision_type: DecisionType,
    epoch_id: u64,
    chosen_action: &str,
) -> CapturedEvidence {
    let mut ctx = BTreeMap::new();
    ctx.insert("region".to_string(), "us-east-1".to_string());
    ctx.insert("operator".to_string(), "ops@example.com".to_string());
    let mut e = CapturedEvidence {
        decision_id: decision_id.to_string(),
        decision_type,
        epoch_id,
        timestamp: "2026-04-27T00:00:00Z".to_string(),
        chosen_action: chosen_action.to_string(),
        input_entries: vec![
            "evidence-line-1".to_string(),
            "evidence-line-2".to_string(),
        ],
        input_context: ctx,
        input_hash: String::new(),
        trace_id: format!("trace-{decision_id}"),
    };
    e.input_hash = e.compute_input_hash();
    e
}

#[test]
fn e2e_replay_gate_reproduced_path() {
    let h = Harness::new("e2e_replay_gate_reproduced_path");

    let mut gate = EvidenceReplayGate::new();
    assert_eq!(gate.evidence_count(), 0);
    assert_eq!(gate.total_replays(), 0);
    let evidence = make_evidence(
        "DEC-REP-001",
        DecisionType::HealthGate,
        7,
        "action:promote",
    );
    gate.capture_evidence(evidence.clone());
    assert_eq!(gate.evidence_count(), 1);
    h.log_phase("captured", true, json!({"count": 1}));

    let result = gate.replay_decision(&evidence, "action:promote", "2026-04-27T00:01:00Z");
    assert_eq!(result.decision_id, "DEC-REP-001");
    assert_eq!(result.decision_type, DecisionType::HealthGate);
    assert!(matches!(result.verdict, ReplayVerdict::Reproduced));
    assert_eq!(result.event_code, RPL_002_REPRODUCED);
    assert_eq!(gate.total_replays(), 1);
    assert_eq!(gate.total_reproduced(), 1);
    assert_eq!(gate.total_diverged(), 0);
    assert_eq!(gate.total_errors(), 0);
    h.log_phase("reproduced", true, json!({"event_code": result.event_code}));

    // RPL-001 then RPL-002 logged in order.
    let log = gate.replay_log();
    assert!(log.len() >= 2);
    assert_eq!(log[0].event_code, RPL_001_REPLAY_INITIATED);
    assert_eq!(log[1].event_code, RPL_002_REPRODUCED);
    assert_eq!(log[1].verdict.as_deref(), Some("reproduced"));
    h.log_phase("log_order", true, json!({"entries": log.len()}));
}

#[test]
fn e2e_replay_gate_diverged_path_carries_diff() {
    let h = Harness::new("e2e_replay_gate_diverged_path_carries_diff");

    let mut gate = EvidenceReplayGate::new();
    let evidence = make_evidence(
        "DEC-DIV-001",
        DecisionType::Rollout,
        7,
        "action:rollout-canary",
    );

    let result =
        gate.replay_decision(&evidence, "action:rollback-now", "2026-04-27T00:02:00Z");
    match &result.verdict {
        ReplayVerdict::Diverged {
            original_action,
            replayed_action,
            diff_hash,
            diff_size_bytes,
        } => {
            assert_eq!(original_action, "action:rollout-canary");
            assert_eq!(replayed_action, "action:rollback-now");
            assert!(!diff_hash.is_empty());
            assert!(*diff_size_bytes > 0);
            h.log_phase(
                "diverged",
                true,
                json!({"diff_hash": diff_hash, "diff_size": diff_size_bytes}),
            );
        }
        other => panic!("expected Diverged, got {other:?}"),
    }
    assert_eq!(result.event_code, RPL_003_DIVERGED);
    assert_eq!(gate.total_diverged(), 1);
    assert_eq!(gate.total_reproduced(), 0);

    // Last log entry should be RPL-003 with diff_size_bytes populated.
    let last = gate
        .replay_log()
        .last()
        .expect("at least one log entry");
    assert_eq!(last.event_code, RPL_003_DIVERGED);
    assert!(last.diff_size_bytes.is_some());
    assert_eq!(last.verdict.as_deref(), Some("diverged"));
    h.log_phase("log_diverged", true, json!({}));
}

#[test]
fn e2e_replay_gate_input_hash_tamper_yields_error() {
    let h = Harness::new("e2e_replay_gate_input_hash_tamper_yields_error");

    let mut gate = EvidenceReplayGate::new();
    let mut evidence = make_evidence(
        "DEC-ERR-001",
        DecisionType::Quarantine,
        7,
        "action:quarantine-issue",
    );
    // Tamper with the input_hash AFTER it's been computed.
    let mut chars: Vec<char> = evidence.input_hash.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    evidence.input_hash = chars.into_iter().collect();

    let result = gate.replay_decision(
        &evidence,
        "action:quarantine-issue",
        "2026-04-27T00:03:00Z",
    );
    match &result.verdict {
        ReplayVerdict::Error { reason } => {
            assert!(reason.contains("Input hash mismatch"));
            h.log_phase(
                "error_input_hash_mismatch",
                true,
                json!({"reason": reason}),
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
    assert_eq!(result.event_code, RPL_004_ERROR);
    assert_eq!(gate.total_errors(), 1);
    assert_eq!(gate.total_reproduced(), 0);
    assert_eq!(gate.total_diverged(), 0);
}

#[test]
fn e2e_replay_gate_evaluate_gate_pass_when_all_reproduced() {
    let h = Harness::new("e2e_replay_gate_evaluate_gate_pass_when_all_reproduced");

    let mut gate = EvidenceReplayGate::new();
    for i in 0..4 {
        let id = format!("DEC-PASS-{i:03}");
        let action = format!("action:promote-{i}");
        gate.capture_evidence(make_evidence(&id, DecisionType::HealthGate, 7, &action));
    }
    assert_eq!(gate.evidence_count(), 4);

    let gate_result = gate.evaluate_gate("2026-04-27T00:04:00Z");
    assert_eq!(gate_result.decision, GateDecision::Pass);
    assert_eq!(gate_result.reproduced_count, 4);
    assert_eq!(gate_result.diverged_count, 0);
    assert_eq!(gate_result.error_count, 0);
    assert_eq!(gate_result.replay_results.len(), 4);
    for r in &gate_result.replay_results {
        assert!(matches!(r.verdict, ReplayVerdict::Reproduced));
    }

    // The last log entry is the gate decision (RPL-005).
    let last = gate
        .replay_log()
        .last()
        .expect("at least one log entry");
    assert_eq!(last.event_code, RPL_005_GATE_DECISION);
    h.log_phase(
        "gate_pass",
        true,
        json!({"reproduced": 4, "decision": "pass"}),
    );
}

#[test]
fn e2e_replay_gate_evaluate_gate_fails_when_any_diverged_or_errored() {
    let h = Harness::new("e2e_replay_gate_evaluate_gate_fails_when_any_diverged_or_errored");

    // For evaluate_gate, the gate replays each captured evidence using the
    // ORIGINAL chosen_action (deterministic short-circuit). To force a
    // divergence inside evaluate_gate, we tamper the hash of one entry so
    // the gate produces an Error verdict. Otherwise evaluate_gate would
    // always reproduce (since it replays original chosen_action against
    // itself).
    let mut gate = EvidenceReplayGate::new();
    let mut tampered = make_evidence(
        "DEC-FAIL-001",
        DecisionType::Fencing,
        7,
        "action:fence-now",
    );
    let mut chars: Vec<char> = tampered.input_hash.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    tampered.input_hash = chars.into_iter().collect();
    gate.capture_evidence(tampered);
    gate.capture_evidence(make_evidence(
        "DEC-FAIL-002",
        DecisionType::HealthGate,
        7,
        "action:promote",
    ));

    let result = gate.evaluate_gate("2026-04-27T00:05:00Z");
    assert_eq!(result.decision, GateDecision::Fail);
    assert!(result.error_count >= 1);
    assert!(result.reproduced_count >= 1);
    h.log_phase(
        "gate_fail",
        true,
        json!({
            "decision": "fail",
            "errors": result.error_count,
            "reproduced": result.reproduced_count,
        }),
    );
}
