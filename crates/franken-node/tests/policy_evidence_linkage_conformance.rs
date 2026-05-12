#![cfg(feature = "policy-engine")]

//! Conformance coverage for policy action evidence decision-ID linkage.
//!
//! Bead: bd-uzoyf.1. The product contract requires a policy action to execute
//! only when the evidence entry's decision_id exactly matches the action ID.

use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity};
use frankenengine_node::policy::evidence_emission::{
    ActionId, ConformanceError, EvidenceConformanceChecker, PolicyAction, PolicyActionOutcome,
    build_evidence_entry,
};
use serde_json::json;

type TestResult = Result<(), String>;

fn make_ledger() -> EvidenceLedger {
    EvidenceLedger::new(LedgerCapacity::new(32, 128_000))
}

fn evidence(
    action: PolicyAction,
    decision_id: &ActionId,
) -> frankenengine_node::observability::evidence_ledger::EvidenceEntry {
    build_evidence_entry(
        action,
        decision_id,
        "trace-policy-linkage-conformance",
        20260512,
        json!({
            "suite": "policy_evidence_linkage_conformance",
            "action": action.label(),
        }),
    )
}

fn assert_action_id_mismatch(
    outcome: PolicyActionOutcome,
    action: PolicyAction,
    expected: &ActionId,
    actual: &ActionId,
) -> TestResult {
    match outcome {
        PolicyActionOutcome::Rejected {
            action: actual_action,
            error:
                ConformanceError::ActionIdMismatch {
                    expected: expected_id,
                    actual: actual_id,
                },
        } => {
            assert_eq!(actual_action, action);
            assert_eq!(&expected_id, expected);
            assert_eq!(actual_id, actual.as_str());
            Ok(())
        }
        other => Err(format!(
            "expected ActionIdMismatch rejection, got {other:?}"
        )),
    }
}

#[test]
fn policy_evidence_linkage_accepts_exact_decision_id_for_all_actions() -> TestResult {
    let mut checker = EvidenceConformanceChecker::new();
    let mut ledger = make_ledger();

    for action in PolicyAction::all() {
        let action_id = ActionId::new(format!("{}-decision-linkage-exact", action.label()));
        let evidence = evidence(*action, &action_id);
        let before_len = ledger.len();

        let outcome = checker.verify_and_execute(*action, &action_id, Some(&evidence), &mut ledger);

        match outcome {
            PolicyActionOutcome::Executed {
                action: actual_action,
                action_id: actual_id,
                evidence_decision_id,
            } => {
                assert_eq!(actual_action, *action);
                assert_eq!(actual_id, action_id);
                assert_eq!(evidence_decision_id, action_id.as_str());
            }
            other => return Err(format!("expected executed policy action, got {other:?}")),
        }
        assert_eq!(ledger.len(), before_len + 1);
    }

    assert_eq!(checker.executed_count(), PolicyAction::all().len() as u64);
    assert_eq!(checker.rejected_count(), 0);
    assert_eq!(ledger.len(), PolicyAction::all().len());
    Ok(())
}

#[test]
fn policy_evidence_linkage_rejects_prefix_suffix_and_same_length_mismatches() -> TestResult {
    let mismatch_cases = [
        (
            "prefix-extension",
            "policy-action-001",
            "policy-action-001-shadow",
        ),
        (
            "prefix-injection",
            "policy-action-001",
            "shadow-policy-action-001",
        ),
        ("same-length-tail", "policy-action-001", "policy-action-002"),
    ];

    for action in PolicyAction::all() {
        for (case, expected_raw, actual_raw) in mismatch_cases {
            let expected = ActionId::new(format!("{}-{expected_raw}", action.label()));
            let actual = ActionId::new(format!("{}-{actual_raw}", action.label()));
            let mismatched_evidence = evidence(*action, &actual);
            let mut checker = EvidenceConformanceChecker::new();
            let mut ledger = make_ledger();

            let outcome = checker.verify_and_execute(
                *action,
                &expected,
                Some(&mismatched_evidence),
                &mut ledger,
            );

            assert_action_id_mismatch(outcome, *action, &expected, &actual)
                .map_err(|err| format!("{case}: {err}"))?;
            assert_eq!(checker.executed_count(), 0, "{case}");
            assert_eq!(checker.rejected_count(), 1, "{case}");
            assert_eq!(ledger.len(), 0, "{case}");
        }
    }

    Ok(())
}
