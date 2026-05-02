#![cfg(feature = "policy-engine")]

//! Mock-free E2E checks for policy evidence emission contracts.
//!
//! The suite loads the checked-in evidence matrix and drives the actual
//! `EvidenceConformanceChecker` against a real `EvidenceLedger`.

use std::{fs, path::PathBuf};

use frankenengine_node::observability::evidence_ledger::{
    EvidenceLedger, LabSpillMode, LedgerCapacity,
};
use frankenengine_node::policy::evidence_emission::{
    ActionId, ConformanceError, EvidenceConformanceChecker, PolicyAction, PolicyActionOutcome,
    build_evidence_entry,
};
use serde::Deserialize;
use serde_json::json;

const MATRIX_PATH: &str = "artifacts/10.14/policy_decision_evidence_matrix.json";

#[derive(Debug, Deserialize)]
struct MatrixDoc {
    bead_id: String,
    matrix: Vec<MatrixRow>,
}

#[derive(Debug, Deserialize)]
struct MatrixRow {
    action: String,
    decision_kind: String,
    evidence_required: bool,
    rejection_on_missing: bool,
    test_coverage: Vec<String>,
}

fn log_phase(test_name: &str, phase: &str, detail: serde_json::Value) {
    eprintln!(
        "{}",
        serde_json::to_string(&json!({
            "suite": "policy_e2e_evidence_matrix",
            "test": test_name,
            "phase": phase,
            "detail": detail,
        }))
        .expect("structured test log serializes")
    );
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir must have workspace parent")
        .parent()
        .expect("workspace parent must have repository parent")
        .to_path_buf()
}

fn load_artifact(path: &str) -> String {
    fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|err| panic!("{path} must be readable from the checkout: {err}"))
}

fn parse_action(action: &str) -> PolicyAction {
    match action {
        "commit" => PolicyAction::Commit,
        "abort" => PolicyAction::Abort,
        "quarantine" => PolicyAction::Quarantine,
        "release" => PolicyAction::Release,
        other => panic!("unsupported policy action in matrix: {other}"),
    }
}

fn assert_executed(outcome: &PolicyActionOutcome, action: PolicyAction, action_id: &ActionId) {
    match outcome {
        PolicyActionOutcome::Executed {
            action: actual_action,
            action_id: actual_id,
            evidence_decision_id,
        } => {
            assert_eq!(*actual_action, action);
            assert_eq!(actual_id, action_id);
            assert_eq!(evidence_decision_id, action_id.as_str());
        }
        other => panic!("expected executed outcome, got {other:?}"),
    }
}

fn assert_missing_rejected(
    outcome: &PolicyActionOutcome,
    action: PolicyAction,
    action_id: &ActionId,
) {
    match outcome {
        PolicyActionOutcome::Rejected {
            action: actual_action,
            error:
                ConformanceError::MissingEvidence {
                    action: error_action,
                    action_id: error_id,
                },
        } => {
            assert_eq!(*actual_action, action);
            assert_eq!(*error_action, action);
            assert_eq!(error_id, action_id);
        }
        other => panic!("expected missing-evidence rejection, got {other:?}"),
    }
}

fn assert_linkage_rejected(
    outcome: &PolicyActionOutcome,
    action: PolicyAction,
    expected: &ActionId,
    actual: &ActionId,
) {
    match outcome {
        PolicyActionOutcome::Rejected {
            action: actual_action,
            error:
                ConformanceError::ActionIdMismatch {
                    expected: expected_id,
                    actual: actual_id,
                },
        } => {
            assert_eq!(*actual_action, action);
            assert_eq!(expected_id, expected);
            assert_eq!(actual_id, actual.as_str());
        }
        other => panic!("expected linkage rejection, got {other:?}"),
    }
}

#[test]
fn policy_evidence_matrix_drives_real_checker_and_ledger() {
    let test_name = "policy_evidence_matrix_drives_real_checker_and_ledger";
    let matrix_json = load_artifact(MATRIX_PATH);
    let matrix: MatrixDoc =
        serde_json::from_str(&matrix_json).expect("policy evidence matrix must parse");
    assert_eq!(matrix.bead_id, "bd-oolt");
    let output_dir = tempfile::tempdir().expect("temp output dir must be created");
    let spill_path = output_dir.path().join("policy_evidence_spill.jsonl");
    log_phase(
        test_name,
        "artifact_loaded",
        json!({
            "path": MATRIX_PATH,
            "rows": matrix.matrix.len(),
            "spill_path": spill_path.display().to_string(),
        }),
    );

    let mut checker = EvidenceConformanceChecker::new();
    let mut ledger = EvidenceLedger::new(LedgerCapacity::new(64, 256_000));
    let mut spill = LabSpillMode::with_file(LedgerCapacity::new(64, 256_000), &spill_path)
        .expect("file-backed spill ledger opens in tempdir");

    for row in &matrix.matrix {
        let action = parse_action(&row.action);
        assert!(
            row.evidence_required,
            "{} must require evidence",
            row.action
        );
        assert!(
            row.rejection_on_missing,
            "{} must reject missing evidence",
            row.action
        );
        assert_eq!(action.expected_decision_kind().label(), row.decision_kind);
        assert!(
            row.test_coverage
                .iter()
                .any(|name| name == &format!("{}_with_evidence_executes", row.action)),
            "{} matrix row must name with-evidence coverage",
            row.action
        );
        assert!(
            row.test_coverage
                .iter()
                .any(|name| name == &format!("{}_without_evidence_rejected", row.action)),
            "{} matrix row must name missing-evidence coverage",
            row.action
        );

        let action_id = ActionId::new(format!("{}-matrix-action", row.action));
        let evidence = build_evidence_entry(
            action,
            &action_id,
            "trace-policy-e2e-matrix",
            20260502,
            json!({"artifact": MATRIX_PATH, "action": row.action}),
        );
        let ledger_len_before = ledger.len();
        let executed = checker.verify_and_execute(action, &action_id, Some(&evidence), &mut ledger);
        assert_executed(&executed, action, &action_id);
        assert_eq!(ledger.len(), ledger_len_before + 1);
        spill
            .append(evidence.clone())
            .expect("accepted evidence appends to file-backed spill ledger");

        let missing_id = ActionId::new(format!("{}-missing-evidence", row.action));
        let ledger_len_before_missing = ledger.len();
        let missing = checker.verify_and_execute(action, &missing_id, None, &mut ledger);
        assert_missing_rejected(&missing, action, &missing_id);
        assert_eq!(ledger.len(), ledger_len_before_missing);

        let expected_id = ActionId::new(format!("{}-expected-linkage", row.action));
        let actual_id = ActionId::new(format!("{}-actual-linkage", row.action));
        let mismatched_evidence = build_evidence_entry(
            action,
            &actual_id,
            "trace-policy-e2e-linkage",
            20260502,
            json!({"artifact": MATRIX_PATH, "action": row.action, "linkage": "mismatch"}),
        );
        let ledger_len_before_mismatch = ledger.len();
        let mismatch = checker.verify_and_execute(
            action,
            &expected_id,
            Some(&mismatched_evidence),
            &mut ledger,
        );
        assert_linkage_rejected(&mismatch, action, &expected_id, &actual_id);
        assert_eq!(ledger.len(), ledger_len_before_mismatch);

        log_phase(
            test_name,
            "row_asserted",
            json!({
                "action": row.action,
                "decision_kind": row.decision_kind,
                "ledger_len": ledger.len(),
            }),
        );
    }

    assert_eq!(checker.executed_count(), matrix.matrix.len() as u64);
    assert_eq!(checker.rejected_count(), (matrix.matrix.len() * 2) as u64);
    assert_eq!(ledger.len(), matrix.matrix.len());
    assert_eq!(ledger.total_appended(), matrix.matrix.len() as u64);
    assert_eq!(spill.len(), matrix.matrix.len());
    spill
        .sync_evidence_durability()
        .expect("spill ledger syncs to tempfile");
    let spill_contents =
        fs::read_to_string(&spill_path).expect("spill ledger JSONL reads back from tempfile");
    assert_eq!(spill_contents.lines().count(), matrix.matrix.len());
    log_phase(
        test_name,
        "assert",
        json!({
            "executed_count": checker.executed_count(),
            "rejected_count": checker.rejected_count(),
            "ledger_len": ledger.len(),
            "spill_lines": spill_contents.lines().count(),
        }),
    );
}
