//! Integration tests for bd-2d17 DGIS migration admission/progression gate.
//!
//! These tests validate end-to-end gate behavior with deterministic outcomes:
//! - admission rejection with structured reasons,
//! - progression re-check semantics,
//! - auto-replan generation with lower-risk alternatives.

#[path = "../../crates/franken-node/src/migration/dgis_migration_gate.rs"]
mod gate_impl;

use gate_impl::{
    GateVerdict, GraphHealthSnapshot, MigrationGateThresholds, MigrationPathCandidate,
    build_migration_health_report, evaluate_admission, evaluate_progression_phase,
};

fn baseline() -> GraphHealthSnapshot {
    GraphHealthSnapshot {
        cascade_risk: 0.20,
        fragility_findings: 3,
        articulation_points: 2,
    }
}

#[test]
fn admission_gate_rejects_high_risk_plan_with_structured_reasons() {
    let thresholds = MigrationGateThresholds {
        max_cascade_risk_delta: 0.08,
        max_new_fragility_findings: 1,
        max_new_articulation_points: 1,
    };
    let projected = GraphHealthSnapshot {
        cascade_risk: 0.39,
        fragility_findings: 6,
        articulation_points: 4,
    };

    let evaluation = evaluate_admission("trace-int-1", baseline(), projected, thresholds, &[]);
    assert_eq!(evaluation.verdict, GateVerdict::Block);
    assert_eq!(evaluation.rejection_reasons.len(), 3);
    assert!(
        evaluation
            .rejection_reasons
            .iter()
            .any(|reason| reason.code == "DGIS-MIGRATE-RISK-DELTA")
    );
}

#[test]
fn progression_gate_rechecks_per_phase_and_allows_when_within_budget() {
    let thresholds = MigrationGateThresholds {
        max_cascade_risk_delta: 0.08,
        max_new_fragility_findings: 2,
        max_new_articulation_points: 2,
    };
    let canary_projected = GraphHealthSnapshot {
        cascade_risk: 0.24,
        fragility_findings: 4,
        articulation_points: 3,
    };

    let phase_eval = evaluate_progression_phase(
        "trace-int-2",
        "phase-canary",
        baseline(),
        canary_projected,
        thresholds,
        &[],
    );

    assert_eq!(phase_eval.verdict, GateVerdict::Allow);
    assert_eq!(phase_eval.phase, "phase-canary");
}

#[test]
fn auto_replan_returns_lower_risk_alternative() {
    let thresholds = MigrationGateThresholds::default();
    let blocked_projected = GraphHealthSnapshot {
        cascade_risk: 0.42,
        fragility_findings: 8,
        articulation_points: 5,
    };
    let candidates = vec![
        MigrationPathCandidate {
            path_id: "path-safe".to_string(),
            projected: GraphHealthSnapshot {
                cascade_risk: 0.26,
                fragility_findings: 4,
                articulation_points: 2,
            },
            notes: "two-phase rollout with quarantine".to_string(),
        },
        MigrationPathCandidate {
            path_id: "path-risky".to_string(),
            projected: GraphHealthSnapshot {
                cascade_risk: 0.41,
                fragility_findings: 8,
                articulation_points: 5,
            },
            notes: "small change only".to_string(),
        },
    ];

    let evaluation = evaluate_admission(
        "trace-int-3",
        baseline(),
        blocked_projected,
        thresholds,
        &candidates,
    );
    assert_eq!(evaluation.verdict, GateVerdict::ReplanRequired);
    assert!(!evaluation.replan_suggestions.is_empty());

    let first = &evaluation.replan_suggestions[0];
    assert_eq!(first.path_id, "path-safe");
    assert!(first.projected_delta.cascade_risk_delta < evaluation.delta.cascade_risk_delta);
}

#[test]
fn health_report_is_machine_readable_with_gate_verdict() {
    let evaluation = evaluate_admission(
        "trace-int-4",
        baseline(),
        GraphHealthSnapshot {
            cascade_risk: 0.24,
            fragility_findings: 4,
            articulation_points: 2,
        },
        MigrationGateThresholds::default(),
        &[],
    );
    let report = build_migration_health_report("plan-int-4", evaluation);
    let json = serde_json::to_string_pretty(&report).expect("report should serialize");
    assert!(json.contains("\"plan_id\": \"plan-int-4\""));
    assert!(json.contains("\"verdict\": \"allow\""));
}
