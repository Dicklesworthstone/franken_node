//! Integration tests for bd-aoq6 BPET migration stability gate.
//!
//! Verifies migration admission constraints and automated fallback behavior.

use frankenengine_node::migration::bpet_migration_gate::{
    GateVerdict, RolloutHealthSnapshot, RolloutPhase, StabilityThresholds, TrajectorySnapshot,
    build_migration_report, evaluate_admission, evaluate_rollout_health,
};

fn baseline() -> TrajectorySnapshot {
    TrajectorySnapshot {
        instability_score: 0.20,
        drift_score: 0.16,
        regime_shift_probability: 0.11,
    }
}

#[test]
fn admission_requires_additional_evidence_for_moderate_instability_jump() {
    let projected = TrajectorySnapshot {
        instability_score: 0.34,
        drift_score: 0.28,
        regime_shift_probability: 0.24,
    };
    let decision = evaluate_admission(
        "trace-aoq6-1",
        baseline(),
        projected,
        StabilityThresholds::default(),
        "v3.2.1",
    );
    assert_eq!(decision.verdict, GateVerdict::RequireAdditionalEvidence);
    assert!(
        decision
            .additional_evidence_required
            .contains(&"bpet.calibration_report".to_string())
    );
}

#[test]
fn severe_risk_forces_staged_rollout_with_fallback_plan() {
    let projected = TrajectorySnapshot {
        instability_score: 0.71,
        drift_score: 0.42,
        regime_shift_probability: 0.55,
    };
    let decision = evaluate_admission(
        "trace-aoq6-2",
        baseline(),
        projected,
        StabilityThresholds::default(),
        "v3.2.1",
    );
    assert_eq!(decision.verdict, GateVerdict::StagedRolloutRequired);
    let rollout = decision.staged_rollout.as_ref().expect("staged rollout");
    assert_eq!(rollout.steps.len(), 4);
    assert!(rollout.fallback.rollback_to_version.ends_with("-previous"));
}

#[test]
fn rollout_health_violation_triggers_automatic_rollback() {
    let projected = TrajectorySnapshot {
        instability_score: 0.71,
        drift_score: 0.42,
        regime_shift_probability: 0.55,
    };
    let decision = evaluate_admission(
        "trace-aoq6-3",
        baseline(),
        projected,
        StabilityThresholds::default(),
        "v3.2.1",
    );
    let rollout = decision.staged_rollout.as_ref().expect("staged rollout");
    let health = RolloutHealthSnapshot {
        phase: RolloutPhase::Canary,
        observed: TrajectorySnapshot {
            instability_score: 0.82,
            drift_score: 0.50,
            regime_shift_probability: 0.61,
        },
    };
    let rollback = evaluate_rollout_health("trace-aoq6-3", rollout, &health);
    assert!(rollback.should_rollback);
}

#[test]
fn migration_report_serializes_with_admission_verdict() {
    let projected = TrajectorySnapshot {
        instability_score: 0.24,
        drift_score: 0.19,
        regime_shift_probability: 0.14,
    };
    let admission = evaluate_admission(
        "trace-aoq6-4",
        baseline(),
        projected,
        StabilityThresholds::default(),
        "v3.2.1",
    );
    let report = build_migration_report("migration-aoq6-4", admission);
    let json = serde_json::to_string_pretty(&report).expect("report should serialize");
    assert!(json.contains("\"migration_id\": \"migration-aoq6-4\""));
    assert!(json.contains("\"verdict\": \"allow\""));
}
