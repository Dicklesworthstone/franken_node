//! BPET migration stability gate (bd-aoq6).
//!
//! Integrates trajectory-stability constraints into migration admission and
//! rollout rollback decisions.

use serde::{Deserialize, Serialize};

const MAX_EVENTS: usize = 4096;

/// Stable event codes for BPET migration stability gates.
pub mod event_codes {
    pub const BASELINE_CAPTURED: &str = "BPET-MIGRATE-001";
    pub const ADMISSION_ALLOWED: &str = "BPET-MIGRATE-002";
    pub const EVIDENCE_REQUIRED: &str = "BPET-MIGRATE-003";
    pub const STAGED_ROLLOUT_REQUIRED: &str = "BPET-MIGRATE-004";
    pub const ROLLBACK_TRIGGERED: &str = "BPET-MIGRATE-005";
    pub const PHASE_ADVANCED: &str = "BPET-MIGRATE-006";
    pub const FALLBACK_PLAN_GENERATED: &str = "BPET-MIGRATE-007";
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TrajectorySnapshot {
    /// Higher values indicate lower evolutionary stability.
    pub instability_score: f64,
    /// Drift intensity in the current epoch window.
    pub drift_score: f64,
    /// Estimated probability of a regime shift.
    pub regime_shift_probability: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TrajectoryDelta {
    pub instability_delta: f64,
    pub drift_delta: f64,
    pub regime_shift_delta: f64,
}

impl TrajectoryDelta {
    pub fn between(baseline: TrajectorySnapshot, projected: TrajectorySnapshot) -> Self {
        Self {
            instability_delta: projected.instability_score - baseline.instability_score,
            drift_delta: projected.drift_score - baseline.drift_score,
            regime_shift_delta: projected.regime_shift_probability
                - baseline.regime_shift_probability,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct StabilityThresholds {
    pub max_instability_delta_for_direct_admit: f64,
    pub max_drift_score_for_direct_admit: f64,
    pub max_regime_shift_probability_for_direct_admit: f64,
    pub max_instability_score_for_staged_rollout: f64,
    pub max_regime_shift_probability_for_staged_rollout: f64,
}

impl Default for StabilityThresholds {
    fn default() -> Self {
        Self {
            max_instability_delta_for_direct_admit: 0.08,
            max_drift_score_for_direct_admit: 0.30,
            max_regime_shift_probability_for_direct_admit: 0.22,
            max_instability_score_for_staged_rollout: 0.62,
            max_regime_shift_probability_for_staged_rollout: 0.45,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    Allow,
    RequireAdditionalEvidence,
    StagedRolloutRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvent {
    pub code: String,
    pub level: String,
    pub trace_id: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutPhase {
    Canary,
    Limited,
    Progressive,
    General,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RolloutStep {
    pub phase: RolloutPhase,
    pub max_instability_score: f64,
    pub max_regime_shift_probability: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FallbackPlan {
    pub rollback_to_version: String,
    pub quarantine_window_minutes: u32,
    pub required_artifacts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StagedRolloutPlan {
    pub steps: Vec<RolloutStep>,
    pub fallback: FallbackPlan,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdmissionDecision {
    pub verdict: GateVerdict,
    pub baseline: TrajectorySnapshot,
    pub projected: TrajectorySnapshot,
    pub delta: TrajectoryDelta,
    pub thresholds: StabilityThresholds,
    pub additional_evidence_required: Vec<String>,
    pub staged_rollout: Option<StagedRolloutPlan>,
    pub events: Vec<GateEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RolloutHealthSnapshot {
    pub phase: RolloutPhase,
    pub observed: TrajectorySnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackDecision {
    pub should_rollback: bool,
    pub reason: String,
    pub event: GateEvent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetMigrationReport {
    pub migration_id: String,
    pub admission: AdmissionDecision,
}

fn gate_event(code: &str, level: &str, trace_id: &str, message: String) -> GateEvent {
    GateEvent {
        code: code.to_string(),
        level: level.to_string(),
        trace_id: trace_id.to_string(),
        message,
    }
}

fn derive_evidence_requirements(
    baseline: TrajectorySnapshot,
    projected: TrajectorySnapshot,
    thresholds: StabilityThresholds,
) -> Vec<String> {
    let mut requirements = Vec::new();

    let instability_delta = projected.instability_score - baseline.instability_score;
    if !instability_delta.is_finite()
        || instability_delta >= thresholds.max_instability_delta_for_direct_admit
    {
        requirements.push("bpet.calibration_report".to_string());
        requirements.push("bpet.drift_explainer".to_string());
    }
    if !projected.drift_score.is_finite()
        || projected.drift_score >= thresholds.max_drift_score_for_direct_admit
    {
        requirements.push("bpet.longitudinal_drift_trace".to_string());
    }
    if !projected.regime_shift_probability.is_finite()
        || projected.regime_shift_probability
            >= thresholds.max_regime_shift_probability_for_direct_admit
    {
        requirements.push("bpet.regime_shift_counterfactuals".to_string());
        requirements.push("ops.signoff.two_person_rule".to_string());
    }

    requirements.sort();
    requirements.dedup();
    requirements
}

fn build_staged_rollout_plan(
    target_version: &str,
    projected: TrajectorySnapshot,
) -> StagedRolloutPlan {
    let safe_instability = if projected.instability_score.is_finite() {
        projected.instability_score
    } else {
        0.0
    };
    let safe_regime = if projected.regime_shift_probability.is_finite() {
        projected.regime_shift_probability
    } else {
        0.0
    };
    let step = |phase: RolloutPhase, instability_factor: f64, regime_factor: f64| RolloutStep {
        phase,
        max_instability_score: safe_instability * instability_factor,
        max_regime_shift_probability: safe_regime * regime_factor,
    };

    StagedRolloutPlan {
        steps: vec![
            step(RolloutPhase::Canary, 0.88, 0.88),
            step(RolloutPhase::Limited, 0.92, 0.92),
            step(RolloutPhase::Progressive, 0.96, 0.96),
            step(RolloutPhase::General, 1.00, 1.00),
        ],
        fallback: FallbackPlan {
            rollback_to_version: format!("{target_version}-previous"),
            quarantine_window_minutes: 90,
            required_artifacts: vec![
                "artifacts/10.21/bpet_migration_gate_results.json".to_string(),
                "artifacts/10.21/bpet_trajectory_replay.json".to_string(),
                "artifacts/10.21/bpet_fallback_receipt.json".to_string(),
            ],
        },
    }
}

pub fn evaluate_admission(
    trace_id: &str,
    baseline: TrajectorySnapshot,
    projected: TrajectorySnapshot,
    thresholds: StabilityThresholds,
    target_version: &str,
) -> AdmissionDecision {
    let delta = TrajectoryDelta::between(baseline, projected);
    let mut events = vec![gate_event(
        event_codes::BASELINE_CAPTURED,
        "info",
        trace_id,
        format!(
            "captured baseline instability={:.4}, drift={:.4}, regime_prob={:.4}",
            baseline.instability_score, baseline.drift_score, baseline.regime_shift_probability
        ),
    )];

    // NaN/Inf fail-closed: non-finite values must trigger the most restrictive path
    let needs_evidence = !delta.instability_delta.is_finite()
        || delta.instability_delta > thresholds.max_instability_delta_for_direct_admit
        || !projected.drift_score.is_finite()
        || projected.drift_score > thresholds.max_drift_score_for_direct_admit
        || !projected.regime_shift_probability.is_finite()
        || projected.regime_shift_probability
            > thresholds.max_regime_shift_probability_for_direct_admit;

    let severe = !projected.instability_score.is_finite()
        || projected.instability_score > thresholds.max_instability_score_for_staged_rollout
        || !projected.regime_shift_probability.is_finite()
        || projected.regime_shift_probability
            > thresholds.max_regime_shift_probability_for_staged_rollout;

    if !needs_evidence {
        events.push(gate_event(
            event_codes::ADMISSION_ALLOWED,
            "info",
            trace_id,
            "admission accepted without additional constraints".to_string(),
        ));
        if events.len() > MAX_EVENTS {
            let overflow = events.len() - MAX_EVENTS;
            events.drain(0..overflow);
        }
        return AdmissionDecision {
            verdict: GateVerdict::Allow,
            baseline,
            projected,
            delta,
            thresholds,
            additional_evidence_required: Vec::new(),
            staged_rollout: None,
            events,
        };
    }

    if severe {
        let rollout = build_staged_rollout_plan(target_version, projected);
        events.push(gate_event(
            event_codes::STAGED_ROLLOUT_REQUIRED,
            "warn",
            trace_id,
            "trajectory risk exceeds direct-admit limits; staged rollout required".to_string(),
        ));
        if events.len() > MAX_EVENTS {
            let overflow = events.len() - MAX_EVENTS;
            events.drain(0..overflow);
        }
        events.push(gate_event(
            event_codes::FALLBACK_PLAN_GENERATED,
            "info",
            trace_id,
            format!(
                "generated fallback rollback target={}",
                rollout.fallback.rollback_to_version
            ),
        ));
        if events.len() > MAX_EVENTS {
            let overflow = events.len() - MAX_EVENTS;
            events.drain(0..overflow);
        }
        return AdmissionDecision {
            verdict: GateVerdict::StagedRolloutRequired,
            baseline,
            projected,
            delta,
            thresholds,
            additional_evidence_required: derive_evidence_requirements(
                baseline, projected, thresholds,
            ),
            staged_rollout: Some(rollout),
            events,
        };
    }

    let evidence = derive_evidence_requirements(baseline, projected, thresholds);
    events.push(gate_event(
        event_codes::EVIDENCE_REQUIRED,
        "warn",
        trace_id,
        format!(
            "additional evidence required before admit ({} item(s))",
            evidence.len()
        ),
    ));

    AdmissionDecision {
        verdict: GateVerdict::RequireAdditionalEvidence,
        baseline,
        projected,
        delta,
        thresholds,
        additional_evidence_required: evidence,
        staged_rollout: None,
        events,
    }
}

pub fn evaluate_rollout_health(
    trace_id: &str,
    rollout: &StagedRolloutPlan,
    health: &RolloutHealthSnapshot,
) -> RollbackDecision {
    let step = match rollout.steps.iter().find(|step| step.phase == health.phase) {
        Some(s) => s,
        None => {
            let reason = format!("rollback triggered: unknown phase {:?}", health.phase);
            return RollbackDecision {
                should_rollback: true,
                reason: reason.clone(),
                event: gate_event(event_codes::ROLLBACK_TRIGGERED, "error", trace_id, reason),
            };
        }
    };

    // NaN/Inf fail-closed: non-finite observed values trigger rollback
    let instability_violation = !health.observed.instability_score.is_finite()
        || health.observed.instability_score >= step.max_instability_score;
    let regime_violation = !health.observed.regime_shift_probability.is_finite()
        || health.observed.regime_shift_probability >= step.max_regime_shift_probability;

    if instability_violation || regime_violation {
        let reason = format!(
            "rollback triggered at phase={:?}: observed instability={:.4}/{:.4}, regime_prob={:.4}/{:.4}",
            health.phase,
            health.observed.instability_score,
            step.max_instability_score,
            health.observed.regime_shift_probability,
            step.max_regime_shift_probability,
        );
        return RollbackDecision {
            should_rollback: true,
            reason: reason.clone(),
            event: gate_event(event_codes::ROLLBACK_TRIGGERED, "error", trace_id, reason),
        };
    }

    let reason = format!(
        "phase {:?} healthy: observed instability={:.4}, regime_prob={:.4}",
        health.phase, health.observed.instability_score, health.observed.regime_shift_probability
    );
    RollbackDecision {
        should_rollback: false,
        reason: reason.clone(),
        event: gate_event(event_codes::PHASE_ADVANCED, "info", trace_id, reason),
    }
}

pub fn build_migration_report(
    migration_id: &str,
    admission: AdmissionDecision,
) -> BpetMigrationReport {
    BpetMigrationReport {
        migration_id: migration_id.to_string(),
        admission,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> TrajectorySnapshot {
        TrajectorySnapshot {
            instability_score: 0.20,
            drift_score: 0.18,
            regime_shift_probability: 0.10,
        }
    }

    #[test]
    fn allows_stable_admission() {
        let projected = TrajectorySnapshot {
            instability_score: 0.23,
            drift_score: 0.20,
            regime_shift_probability: 0.14,
        };
        let decision = evaluate_admission(
            "trace-bpet-allow",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.3.0",
        );
        assert_eq!(decision.verdict, GateVerdict::Allow);
        assert!(decision.additional_evidence_required.is_empty());
        assert!(decision.staged_rollout.is_none());
    }

    #[test]
    fn requires_evidence_for_moderate_threshold_crossing() {
        let projected = TrajectorySnapshot {
            instability_score: 0.33,
            drift_score: 0.29,
            regime_shift_probability: 0.26,
        };
        let decision = evaluate_admission(
            "trace-bpet-evidence",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.3.0",
        );
        assert_eq!(decision.verdict, GateVerdict::RequireAdditionalEvidence);
        assert!(!decision.additional_evidence_required.is_empty());
        assert!(decision.staged_rollout.is_none());
    }

    #[test]
    fn mandates_staged_rollout_for_severe_risk() {
        let projected = TrajectorySnapshot {
            instability_score: 0.70,
            drift_score: 0.40,
            regime_shift_probability: 0.53,
        };
        let decision = evaluate_admission(
            "trace-bpet-staged",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.3.0",
        );
        assert_eq!(decision.verdict, GateVerdict::StagedRolloutRequired);
        let rollout = decision
            .staged_rollout
            .as_ref()
            .expect("staged rollout should be present");
        assert_eq!(rollout.steps.len(), 4);
        assert!(rollout.fallback.rollback_to_version.contains("previous"));
    }

    #[test]
    fn rollback_triggers_when_phase_limits_breached() {
        let projected = TrajectorySnapshot {
            instability_score: 0.70,
            drift_score: 0.40,
            regime_shift_probability: 0.53,
        };
        let decision = evaluate_admission(
            "trace-bpet-rollout",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.3.0",
        );
        let rollout = decision.staged_rollout.expect("staged rollout");
        let health = RolloutHealthSnapshot {
            phase: RolloutPhase::Canary,
            observed: TrajectorySnapshot {
                instability_score: 0.72,
                drift_score: 0.41,
                regime_shift_probability: 0.60,
            },
        };
        let rollback = evaluate_rollout_health("trace-bpet-rollout", &rollout, &health);
        assert!(rollback.should_rollback);
        assert_eq!(rollback.event.code, event_codes::ROLLBACK_TRIGGERED);
    }

    #[test]
    fn rollout_advances_when_within_limits() {
        let projected = TrajectorySnapshot {
            instability_score: 0.70,
            drift_score: 0.40,
            regime_shift_probability: 0.53,
        };
        let decision = evaluate_admission(
            "trace-bpet-advance",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.3.0",
        );
        let rollout = decision.staged_rollout.expect("staged rollout");
        let health = RolloutHealthSnapshot {
            phase: RolloutPhase::Canary,
            observed: TrajectorySnapshot {
                instability_score: 0.58,
                drift_score: 0.32,
                regime_shift_probability: 0.41,
            },
        };
        let rollback = evaluate_rollout_health("trace-bpet-advance", &rollout, &health);
        assert!(!rollback.should_rollback);
        assert_eq!(rollback.event.code, event_codes::PHASE_ADVANCED);
    }

    #[test]
    fn default_thresholds_are_reasonable() {
        let t = StabilityThresholds::default();
        assert!(t.max_instability_delta_for_direct_admit > 0.0);
        assert!(
            t.max_instability_score_for_staged_rollout > t.max_instability_delta_for_direct_admit
        );
        assert!(t.max_drift_score_for_direct_admit > 0.0);
        assert!(t.max_regime_shift_probability_for_direct_admit > 0.0);
        assert!(
            t.max_regime_shift_probability_for_staged_rollout
                > t.max_regime_shift_probability_for_direct_admit
        );
    }

    #[test]
    fn trajectory_delta_between_computes_correctly() {
        let base = TrajectorySnapshot {
            instability_score: 0.10,
            drift_score: 0.20,
            regime_shift_probability: 0.05,
        };
        let proj = TrajectorySnapshot {
            instability_score: 0.30,
            drift_score: 0.25,
            regime_shift_probability: 0.15,
        };
        let delta = TrajectoryDelta::between(base, proj);
        assert!((delta.instability_delta - 0.20).abs() < 1e-9);
        assert!((delta.drift_delta - 0.05).abs() < 1e-9);
        assert!((delta.regime_shift_delta - 0.10).abs() < 1e-9);
    }

    #[test]
    fn zero_delta_trajectory_allows() {
        let snap = baseline();
        let decision = evaluate_admission(
            "trace-zero",
            snap,
            snap,
            StabilityThresholds::default(),
            "v1.0.0",
        );
        assert_eq!(decision.verdict, GateVerdict::Allow);
    }

    #[test]
    fn event_codes_are_distinct() {
        let codes = [
            event_codes::BASELINE_CAPTURED,
            event_codes::ADMISSION_ALLOWED,
            event_codes::EVIDENCE_REQUIRED,
            event_codes::STAGED_ROLLOUT_REQUIRED,
            event_codes::ROLLBACK_TRIGGERED,
            event_codes::PHASE_ADVANCED,
            event_codes::FALLBACK_PLAN_GENERATED,
        ];
        let set: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(set.len(), codes.len());
    }

    #[test]
    fn severe_instability_triggers_staged_rollout() {
        let projected = TrajectorySnapshot {
            instability_score: 0.80,
            drift_score: 0.70,
            regime_shift_probability: 0.60,
        };
        let decision = evaluate_admission(
            "trace-severe",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.0.0",
        );
        assert_eq!(decision.verdict, GateVerdict::StagedRolloutRequired);
        assert!(decision.staged_rollout.is_some());
        let plan = decision.staged_rollout.expect("should have rollout");
        assert!(!plan.steps.is_empty());
    }

    #[test]
    fn migration_report_has_migration_id() {
        let decision = evaluate_admission(
            "trace-report",
            baseline(),
            baseline(),
            StabilityThresholds::default(),
            "v1.0.0",
        );
        let report = BpetMigrationReport {
            migration_id: "mig-report-001".to_string(),
            admission: decision,
        };
        assert!(!report.migration_id.is_empty());
        assert_eq!(report.admission.verdict, GateVerdict::Allow);
    }

    #[test]
    fn rollback_decision_carries_event() {
        let projected = TrajectorySnapshot {
            instability_score: 0.80,
            drift_score: 0.70,
            regime_shift_probability: 0.60,
        };
        let decision = evaluate_admission(
            "trace-rb",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.0.0",
        );
        let rollout = decision.staged_rollout.expect("should have staged rollout");
        let health = RolloutHealthSnapshot {
            phase: RolloutPhase::General,
            observed: TrajectorySnapshot {
                instability_score: 0.95,
                drift_score: 0.80,
                regime_shift_probability: 0.70,
            },
        };
        let rollback = evaluate_rollout_health("trace-rb-eval", &rollout, &health);
        assert!(!rollback.event.code.is_empty());
    }

    #[test]
    fn gate_verdict_serde_roundtrip() {
        let v = GateVerdict::RequireAdditionalEvidence;
        let json = serde_json::to_string(&v).expect("serialize");
        let parsed: GateVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, v);
    }

    #[test]
    fn evidence_requirements_are_deterministic() {
        let projected = TrajectorySnapshot {
            instability_score: 0.33,
            drift_score: 0.29,
            regime_shift_probability: 0.26,
        };
        let first = evaluate_admission(
            "trace-bpet-det-a",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.3.0",
        );
        let second = evaluate_admission(
            "trace-bpet-det-b",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.3.0",
        );
        assert_eq!(
            first.additional_evidence_required,
            second.additional_evidence_required
        );
    }

    #[test]
    fn nan_instability_score_blocks_admission() {
        let projected = TrajectorySnapshot {
            instability_score: f64::NAN,
            drift_score: 0.20,
            regime_shift_probability: 0.10,
        };
        let decision = evaluate_admission(
            "trace-nan",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v1.0.0",
        );
        assert_ne!(decision.verdict, GateVerdict::Allow);
    }

    #[test]
    fn nan_drift_score_blocks_admission() {
        let projected = TrajectorySnapshot {
            instability_score: 0.20,
            drift_score: f64::NAN,
            regime_shift_probability: 0.10,
        };
        let decision = evaluate_admission(
            "trace-nan-drift",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v1.0.0",
        );
        assert_ne!(decision.verdict, GateVerdict::Allow);
    }

    #[test]
    fn nan_regime_shift_blocks_admission() {
        let projected = TrajectorySnapshot {
            instability_score: 0.20,
            drift_score: 0.20,
            regime_shift_probability: f64::NAN,
        };
        let decision = evaluate_admission(
            "trace-nan-regime",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v1.0.0",
        );
        assert_ne!(decision.verdict, GateVerdict::Allow);
    }

    #[test]
    fn inf_instability_triggers_staged_rollout() {
        let projected = TrajectorySnapshot {
            instability_score: f64::INFINITY,
            drift_score: 0.20,
            regime_shift_probability: 0.10,
        };
        let decision = evaluate_admission(
            "trace-inf",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v1.0.0",
        );
        assert_eq!(decision.verdict, GateVerdict::StagedRolloutRequired);
    }

    #[test]
    fn nan_observed_instability_triggers_rollback() {
        let projected = TrajectorySnapshot {
            instability_score: 0.70,
            drift_score: 0.40,
            regime_shift_probability: 0.53,
        };
        let decision = evaluate_admission(
            "trace-rb-nan",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.0.0",
        );
        let rollout = decision.staged_rollout.expect("staged rollout");
        let health = RolloutHealthSnapshot {
            phase: RolloutPhase::Canary,
            observed: TrajectorySnapshot {
                instability_score: f64::NAN,
                drift_score: 0.20,
                regime_shift_probability: 0.10,
            },
        };
        let rollback = evaluate_rollout_health("trace-rb-nan", &rollout, &health);
        assert!(
            rollback.should_rollback,
            "NaN observed instability must trigger rollback"
        );
    }

    #[test]
    fn nan_observed_regime_shift_triggers_rollback() {
        let projected = TrajectorySnapshot {
            instability_score: 0.70,
            drift_score: 0.40,
            regime_shift_probability: 0.53,
        };
        let decision = evaluate_admission(
            "trace-rb-nan-regime",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.0.0",
        );
        let rollout = decision.staged_rollout.expect("staged rollout");
        let health = RolloutHealthSnapshot {
            phase: RolloutPhase::Canary,
            observed: TrajectorySnapshot {
                instability_score: 0.10,
                drift_score: 0.20,
                regime_shift_probability: f64::NAN,
            },
        };
        let rollback = evaluate_rollout_health("trace-rb-nan-regime", &rollout, &health);
        assert!(
            rollback.should_rollback,
            "NaN observed regime_shift must trigger rollback"
        );
    }

    #[test]
    fn builds_migration_report() {
        let projected = TrajectorySnapshot {
            instability_score: 0.23,
            drift_score: 0.20,
            regime_shift_probability: 0.14,
        };
        let decision = evaluate_admission(
            "trace-bpet-report",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.0.0",
        );

        let report = build_migration_report("migration-001", decision.clone());
        assert_eq!(report.migration_id, "migration-001");
        assert_eq!(report.admission, decision);
    }
}
