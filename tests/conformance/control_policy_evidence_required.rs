//! Conformance tests for bd-15j6 mandatory control-policy evidence.
//!
//! The `policy_evidence_required` sentinel is intentionally stable because
//! audit tooling greps for the contract by name.

use frankenengine_node::connector::control_evidence::{
    ConformanceError, ControlEvidenceEmitter, ControlEvidenceEntry, DecisionOutcome, DecisionType,
    EVD_001_ENTRY_EMITTED, EVD_002_ENTRY_MISSING, EVD_003_SCHEMA_VALID, EVD_004_SCHEMA_INVALID,
    EVD_005_ORDERING_VIOLATION, map_decision_kind,
};

const POLICY_EVIDENCE_REQUIRED_SENTINEL: &str = "policy_evidence_required";

const POLICY_INFLUENCED_DECISIONS: &[(DecisionType, DecisionOutcome, &str, u64)] = &[
    (
        DecisionType::HealthGateEval,
        DecisionOutcome::Pass,
        "health-gate-pass",
        1_000,
    ),
    (
        DecisionType::RolloutTransition,
        DecisionOutcome::Proceed,
        "rollout-proceed",
        2_000,
    ),
    (
        DecisionType::QuarantineAction,
        DecisionOutcome::Promote,
        "quarantine-promote",
        3_000,
    ),
    (
        DecisionType::FencingDecision,
        DecisionOutcome::Grant,
        "fencing-grant",
        4_000,
    ),
    (
        DecisionType::MigrationDecision,
        DecisionOutcome::Abort,
        "migration-abort",
        5_000,
    ),
];

fn make_entry(
    decision_type: DecisionType,
    outcome: DecisionOutcome,
    decision_id: &str,
    timestamp_ms: u64,
) -> ControlEvidenceEntry {
    ControlEvidenceEntry {
        schema_version: "1.0".to_string(),
        decision_id: decision_id.to_string(),
        decision_type,
        decision_kind: map_decision_kind(decision_type, outcome),
        policy_inputs: vec![
            "policy=mandatory-evidence".to_string(),
            "source=control-plane".to_string(),
        ],
        candidates_considered: vec!["admit".to_string(), "deny".to_string()],
        chosen_action: format!("{outcome:?}"),
        rejection_reasons: vec!["lower-ranked alternative rejected".to_string()],
        epoch: 42,
        trace_id: format!("trace-{decision_id}"),
        timestamp_ms,
    }
}

fn run_policy_decisions() -> ControlEvidenceEmitter {
    let mut emitter = ControlEvidenceEmitter::new();
    for (decision_type, outcome, decision_id, timestamp_ms) in POLICY_INFLUENCED_DECISIONS {
        let entry = make_entry(*decision_type, *outcome, decision_id, *timestamp_ms);
        let expected_kind = entry.decision_kind;
        let emitted = emitter
            .execute_with_evidence(*decision_type, Some(entry))
            .expect("policy-influenced decision must accept valid evidence");
        assert_eq!(emitted.decision_type, *decision_type);
        assert_eq!(emitted.decision_kind, expected_kind);
    }
    emitter
}

#[test]
fn policy_evidence_required_sentinel_is_stable() {
    assert_eq!(
        POLICY_EVIDENCE_REQUIRED_SENTINEL,
        "policy_evidence_required"
    );
}

#[test]
fn policy_evidence_required_for_every_policy_influenced_decision() {
    let emitter = run_policy_decisions();

    assert_eq!(emitter.entries().len(), POLICY_INFLUENCED_DECISIONS.len());
    assert!(emitter.uncovered_types().is_empty());

    for (entry, (decision_type, outcome, _, _)) in
        emitter.entries().iter().zip(POLICY_INFLUENCED_DECISIONS)
    {
        entry
            .validate()
            .expect("emitted policy evidence must match canonical schema");
        assert_eq!(entry.decision_type, *decision_type);
        assert_eq!(
            entry.decision_kind,
            map_decision_kind(*decision_type, *outcome)
        );
    }

    let emitted_events = emitter
        .events()
        .iter()
        .filter(|event| event.code == EVD_001_ENTRY_EMITTED)
        .count();
    let schema_events = emitter
        .events()
        .iter()
        .filter(|event| event.code == EVD_003_SCHEMA_VALID)
        .count();

    assert_eq!(emitted_events, POLICY_INFLUENCED_DECISIONS.len());
    assert_eq!(schema_events, POLICY_INFLUENCED_DECISIONS.len());
}

#[test]
fn policy_evidence_required_missing_entry_fails_closed() {
    let mut emitter = ControlEvidenceEmitter::new();

    let err = emitter
        .execute_with_evidence(DecisionType::HealthGateEval, None)
        .expect_err("missing policy evidence must be a conformance failure");

    assert!(matches!(err, ConformanceError::MissingEvidence(_)));
    assert!(emitter.entries().is_empty());
    assert!(
        emitter
            .events()
            .iter()
            .any(|event| event.code == EVD_002_ENTRY_MISSING)
    );
}

#[test]
fn policy_evidence_required_rejects_malformed_schema() {
    let mut emitter = ControlEvidenceEmitter::new();
    let mut entry = make_entry(
        DecisionType::FencingDecision,
        DecisionOutcome::Grant,
        "bad-schema",
        1_000,
    );
    entry.schema_version = "2.0".to_string();

    let err = emitter
        .execute_with_evidence(DecisionType::FencingDecision, Some(entry))
        .expect_err("malformed evidence must be rejected");

    assert!(matches!(err, ConformanceError::SchemaInvalid(_)));
    assert!(emitter.entries().is_empty());
    assert!(
        emitter
            .events()
            .iter()
            .any(|event| event.code == EVD_004_SCHEMA_INVALID)
    );
}

#[test]
fn policy_evidence_required_ordering_is_deterministic() {
    let first = run_policy_decisions().to_jsonl();
    let second = run_policy_decisions().to_jsonl();

    assert_eq!(first, second);
}

#[test]
fn policy_evidence_required_detects_ordering_violation() {
    let mut emitter = ControlEvidenceEmitter::new();
    emitter
        .emit_evidence(make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "same-decision",
            2_000,
        ))
        .expect("first evidence entry should be valid");
    emitter
        .emit_evidence(make_entry(
            DecisionType::HealthGateEval,
            DecisionOutcome::Pass,
            "same-decision",
            1_000,
        ))
        .expect("second evidence entry should be valid before ordering check");

    let err = emitter
        .verify_ordering()
        .expect_err("out-of-order policy evidence must fail conformance");

    assert!(matches!(err, ConformanceError::OrderingViolation(_)));
    assert!(
        emitter
            .events()
            .iter()
            .any(|event| event.code == EVD_005_ORDERING_VIOLATION)
    );
}
