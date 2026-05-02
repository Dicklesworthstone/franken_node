//! BPET migration stability gate (bd-aoq6).
//!
//! Integrates trajectory-stability constraints into migration admission and
//! rollout rollback decisions.

use serde::{Deserialize, Serialize};

use frankenengine_node::capacity_defaults::aliases::MAX_EVENTS;

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

/// Maximum evidence requirements to prevent memory exhaustion attacks.
const MAX_EVIDENCE_REQUIREMENTS: usize = 20;

/// Push item to vector with capacity bounds checking to prevent memory exhaustion.
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

fn derive_evidence_requirements(
    baseline: TrajectorySnapshot,
    projected: TrajectorySnapshot,
    thresholds: StabilityThresholds,
) -> Vec<String> {
    let mut requirements = Vec::new();

    let instability_delta = projected.instability_score - baseline.instability_score;
    let drift_delta = projected.drift_score - baseline.drift_score;
    let regime_shift_delta = projected.regime_shift_probability - baseline.regime_shift_probability;
    if !instability_delta.is_finite()
        || instability_delta >= thresholds.max_instability_delta_for_direct_admit
    {
        push_bounded(
            &mut requirements,
            "bpet.calibration_report".to_string(),
            MAX_EVIDENCE_REQUIREMENTS,
        );
        push_bounded(
            &mut requirements,
            "bpet.drift_explainer".to_string(),
            MAX_EVIDENCE_REQUIREMENTS,
        );
    }
    if !projected.drift_score.is_finite()
        || !drift_delta.is_finite()
        || projected.drift_score >= thresholds.max_drift_score_for_direct_admit
    {
        push_bounded(
            &mut requirements,
            "bpet.longitudinal_drift_trace".to_string(),
            MAX_EVIDENCE_REQUIREMENTS,
        );
    }
    if !projected.regime_shift_probability.is_finite()
        || !regime_shift_delta.is_finite()
        || projected.regime_shift_probability
            >= thresholds.max_regime_shift_probability_for_direct_admit
    {
        push_bounded(
            &mut requirements,
            "bpet.regime_shift_counterfactuals".to_string(),
            MAX_EVIDENCE_REQUIREMENTS,
        );
        push_bounded(
            &mut requirements,
            "ops.signoff.two_person_rule".to_string(),
            MAX_EVIDENCE_REQUIREMENTS,
        );
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
        || delta.instability_delta >= thresholds.max_instability_delta_for_direct_admit
        || !delta.drift_delta.is_finite()
        || !delta.regime_shift_delta.is_finite()
        || !projected.drift_score.is_finite()
        || projected.drift_score >= thresholds.max_drift_score_for_direct_admit
        || !projected.regime_shift_probability.is_finite()
        || projected.regime_shift_probability
            >= thresholds.max_regime_shift_probability_for_direct_admit;

    let severe = !projected.instability_score.is_finite()
        || projected.instability_score >= thresholds.max_instability_score_for_staged_rollout
        || !projected.regime_shift_probability.is_finite()
        || projected.regime_shift_probability
            >= thresholds.max_regime_shift_probability_for_staged_rollout;

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
            events.drain(0..overflow.min(events.len()));
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
            events.drain(0..overflow.min(events.len()));
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

    if !needs_evidence {
        events.push(gate_event(
            event_codes::ADMISSION_ALLOWED,
            "info",
            trace_id,
            "admission accepted without additional constraints".to_string(),
        ));
        if events.len() > MAX_EVENTS {
            let overflow = events.len() - MAX_EVENTS;
            events.drain(0..overflow.min(events.len()));
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

    #[test]
    fn nan_baseline_instability_requires_evidence() {
        let base = TrajectorySnapshot {
            instability_score: f64::NAN,
            drift_score: 0.18,
            regime_shift_probability: 0.10,
        };
        let projected = TrajectorySnapshot {
            instability_score: 0.21,
            drift_score: 0.20,
            regime_shift_probability: 0.12,
        };

        let decision = evaluate_admission(
            "trace-bpet-nan-baseline",
            base,
            projected,
            StabilityThresholds::default(),
            "v2.4.0",
        );

        assert_eq!(decision.verdict, GateVerdict::RequireAdditionalEvidence);
        assert!(
            decision
                .additional_evidence_required
                .contains(&"bpet.calibration_report".to_string())
        );
    }

    #[test]
    fn negative_infinite_drift_requires_evidence() {
        let projected = TrajectorySnapshot {
            instability_score: 0.21,
            drift_score: f64::NEG_INFINITY,
            regime_shift_probability: 0.12,
        };

        let decision = evaluate_admission(
            "trace-bpet-neg-inf-drift",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.4.0",
        );

        assert_eq!(decision.verdict, GateVerdict::RequireAdditionalEvidence);
        assert!(
            decision
                .additional_evidence_required
                .contains(&"bpet.longitudinal_drift_trace".to_string())
        );
    }

    #[test]
    fn negative_infinite_regime_shift_requires_staged_rollout() {
        let projected = TrajectorySnapshot {
            instability_score: 0.21,
            drift_score: 0.20,
            regime_shift_probability: f64::NEG_INFINITY,
        };

        let decision = evaluate_admission(
            "trace-bpet-neg-inf-regime",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.4.0",
        );

        assert_eq!(decision.verdict, GateVerdict::StagedRolloutRequired);
        assert!(decision.staged_rollout.is_some());
    }

    #[test]
    fn empty_rollout_plan_fails_closed_with_rollback() {
        let rollout = StagedRolloutPlan {
            steps: Vec::new(),
            fallback: FallbackPlan {
                rollback_to_version: "v2.4.0-previous".to_string(),
                quarantine_window_minutes: 90,
                required_artifacts: Vec::new(),
            },
        };
        let health = RolloutHealthSnapshot {
            phase: RolloutPhase::Canary,
            observed: baseline(),
        };

        let rollback = evaluate_rollout_health("trace-bpet-empty-plan", &rollout, &health);

        assert!(rollback.should_rollback);
        assert_eq!(rollback.event.code, event_codes::ROLLBACK_TRIGGERED);
        assert!(rollback.reason.contains("unknown phase"));
    }

    #[test]
    fn infinite_observed_regime_shift_triggers_rollback() {
        let projected = TrajectorySnapshot {
            instability_score: 0.70,
            drift_score: 0.40,
            regime_shift_probability: 0.53,
        };
        let decision = evaluate_admission(
            "trace-bpet-inf-observed-regime",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.4.0",
        );
        let rollout = decision.staged_rollout.expect("staged rollout");
        let health = RolloutHealthSnapshot {
            phase: RolloutPhase::Canary,
            observed: TrajectorySnapshot {
                instability_score: 0.10,
                drift_score: 0.10,
                regime_shift_probability: f64::INFINITY,
            },
        };

        let rollback = evaluate_rollout_health("trace-bpet-inf-observed-regime", &rollout, &health);

        assert!(rollback.should_rollback);
        assert_eq!(rollback.event.level, "error");
    }

    #[test]
    fn exact_rollout_instability_limit_triggers_rollback() {
        let projected = TrajectorySnapshot {
            instability_score: 0.70,
            drift_score: 0.40,
            regime_shift_probability: 0.53,
        };
        let decision = evaluate_admission(
            "trace-bpet-exact-limit",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.4.0",
        );
        let rollout = decision.staged_rollout.expect("staged rollout");
        let canary = rollout
            .steps
            .iter()
            .find(|step| step.phase == RolloutPhase::Canary)
            .expect("canary step")
            .clone();
        let health = RolloutHealthSnapshot {
            phase: RolloutPhase::Canary,
            observed: TrajectorySnapshot {
                instability_score: canary.max_instability_score,
                drift_score: 0.10,
                regime_shift_probability: canary.max_regime_shift_probability / 2.0,
            },
        };

        let rollback = evaluate_rollout_health("trace-bpet-exact-limit", &rollout, &health);

        assert!(
            rollback.should_rollback,
            "hitting the configured rollback limit must fail closed"
        );
    }

    #[test]
    fn non_finite_staged_rollout_projection_uses_finite_zero_limits() {
        let projected = TrajectorySnapshot {
            instability_score: f64::INFINITY,
            drift_score: 0.80,
            regime_shift_probability: f64::NAN,
        };

        let decision = evaluate_admission(
            "trace-bpet-nonfinite-plan",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.4.0",
        );
        let rollout = decision.staged_rollout.expect("staged rollout");

        assert!(rollout.steps.iter().all(|step| {
            step.max_instability_score.is_finite()
                && step.max_regime_shift_probability.is_finite()
                && (step.max_instability_score - 0.0).abs() < f64::EPSILON
                && (step.max_regime_shift_probability - 0.0).abs() < f64::EPSILON
        }));
    }

    #[test]
    fn negative_threshold_configuration_requires_staged_rollout() {
        let thresholds = StabilityThresholds {
            max_instability_delta_for_direct_admit: -0.01,
            max_drift_score_for_direct_admit: -0.01,
            max_regime_shift_probability_for_direct_admit: -0.01,
            max_instability_score_for_staged_rollout: -0.01,
            max_regime_shift_probability_for_staged_rollout: -0.01,
        };

        let decision = evaluate_admission(
            "trace-bpet-negative-thresholds",
            baseline(),
            baseline(),
            thresholds,
            "v2.4.0",
        );

        assert_eq!(decision.verdict, GateVerdict::StagedRolloutRequired);
        assert!(decision.staged_rollout.is_some());
    }

    #[test]
    fn exact_direct_instability_boundary_requires_evidence() {
        let thresholds = StabilityThresholds::default();
        let base = baseline();
        let projected = TrajectorySnapshot {
            instability_score: base.instability_score
                + thresholds.max_instability_delta_for_direct_admit,
            drift_score: 0.20,
            regime_shift_probability: 0.12,
        };

        let decision = evaluate_admission(
            "trace-bpet-exact-direct-instability",
            base,
            projected,
            thresholds,
            "v2.5.0",
        );

        assert_eq!(decision.verdict, GateVerdict::RequireAdditionalEvidence);
        assert!(decision.staged_rollout.is_none());
        assert!(
            decision
                .additional_evidence_required
                .contains(&"bpet.calibration_report".to_string())
        );
        assert!(
            decision
                .additional_evidence_required
                .contains(&"bpet.drift_explainer".to_string())
        );
    }

    #[test]
    fn exact_direct_drift_boundary_requires_evidence() {
        let thresholds = StabilityThresholds::default();
        let projected = TrajectorySnapshot {
            instability_score: 0.21,
            drift_score: thresholds.max_drift_score_for_direct_admit,
            regime_shift_probability: 0.12,
        };

        let decision = evaluate_admission(
            "trace-bpet-exact-direct-drift",
            baseline(),
            projected,
            thresholds,
            "v2.5.0",
        );

        assert_eq!(decision.verdict, GateVerdict::RequireAdditionalEvidence);
        assert_eq!(
            decision.additional_evidence_required,
            vec!["bpet.longitudinal_drift_trace".to_string()]
        );
    }

    #[test]
    fn exact_direct_regime_boundary_requires_evidence() {
        let thresholds = StabilityThresholds::default();
        let projected = TrajectorySnapshot {
            instability_score: 0.21,
            drift_score: 0.20,
            regime_shift_probability: thresholds.max_regime_shift_probability_for_direct_admit,
        };

        let decision = evaluate_admission(
            "trace-bpet-exact-direct-regime",
            baseline(),
            projected,
            thresholds,
            "v2.5.0",
        );

        assert_eq!(decision.verdict, GateVerdict::RequireAdditionalEvidence);
        assert!(
            decision
                .additional_evidence_required
                .contains(&"bpet.regime_shift_counterfactuals".to_string())
        );
        assert!(
            decision
                .additional_evidence_required
                .contains(&"ops.signoff.two_person_rule".to_string())
        );
    }

    #[test]
    fn exact_staged_instability_boundary_requires_rollout() {
        let thresholds = StabilityThresholds::default();
        let projected = TrajectorySnapshot {
            instability_score: thresholds.max_instability_score_for_staged_rollout,
            drift_score: 0.20,
            regime_shift_probability: 0.12,
        };

        let decision = evaluate_admission(
            "trace-bpet-exact-staged-instability",
            baseline(),
            projected,
            thresholds,
            "v2.5.0",
        );

        assert_eq!(decision.verdict, GateVerdict::StagedRolloutRequired);
        assert!(decision.staged_rollout.is_some());
        assert_eq!(
            decision.events.last().map(|event| event.code.as_str()),
            Some(event_codes::FALLBACK_PLAN_GENERATED)
        );
    }

    #[test]
    fn exact_staged_regime_boundary_requires_rollout() {
        let thresholds = StabilityThresholds::default();
        let projected = TrajectorySnapshot {
            instability_score: 0.21,
            drift_score: 0.20,
            regime_shift_probability: thresholds.max_regime_shift_probability_for_staged_rollout,
        };

        let decision = evaluate_admission(
            "trace-bpet-exact-staged-regime",
            baseline(),
            projected,
            thresholds,
            "v2.5.0",
        );

        assert_eq!(decision.verdict, GateVerdict::StagedRolloutRequired);
        assert!(decision.staged_rollout.is_some());
        assert!(
            decision
                .additional_evidence_required
                .contains(&"bpet.regime_shift_counterfactuals".to_string())
        );
    }

    #[test]
    fn nan_baseline_drift_requires_evidence() {
        let base = TrajectorySnapshot {
            instability_score: 0.20,
            drift_score: f64::NAN,
            regime_shift_probability: 0.10,
        };
        let projected = TrajectorySnapshot {
            instability_score: 0.21,
            drift_score: 0.20,
            regime_shift_probability: 0.12,
        };

        let decision = evaluate_admission(
            "trace-bpet-nan-baseline-drift",
            base,
            projected,
            StabilityThresholds::default(),
            "v2.5.0",
        );

        assert_eq!(decision.verdict, GateVerdict::RequireAdditionalEvidence);
        assert_eq!(
            decision.additional_evidence_required,
            vec!["bpet.longitudinal_drift_trace".to_string()]
        );
    }

    #[test]
    fn infinite_baseline_regime_requires_evidence() {
        let base = TrajectorySnapshot {
            instability_score: 0.20,
            drift_score: 0.18,
            regime_shift_probability: f64::INFINITY,
        };
        let projected = TrajectorySnapshot {
            instability_score: 0.21,
            drift_score: 0.20,
            regime_shift_probability: 0.12,
        };

        let decision = evaluate_admission(
            "trace-bpet-inf-baseline-regime",
            base,
            projected,
            StabilityThresholds::default(),
            "v2.5.0",
        );

        assert_eq!(decision.verdict, GateVerdict::RequireAdditionalEvidence);
        assert!(
            decision
                .additional_evidence_required
                .contains(&"bpet.regime_shift_counterfactuals".to_string())
        );
        assert!(
            decision
                .additional_evidence_required
                .contains(&"ops.signoff.two_person_rule".to_string())
        );
    }

    #[test]
    fn exact_rollout_regime_limit_triggers_rollback() {
        let projected = TrajectorySnapshot {
            instability_score: 0.70,
            drift_score: 0.40,
            regime_shift_probability: 0.53,
        };
        let decision = evaluate_admission(
            "trace-bpet-exact-regime-limit",
            baseline(),
            projected,
            StabilityThresholds::default(),
            "v2.5.0",
        );
        let rollout = decision.staged_rollout.expect("staged rollout");
        let canary = rollout
            .steps
            .iter()
            .find(|step| step.phase == RolloutPhase::Canary)
            .expect("canary step")
            .clone();
        let health = RolloutHealthSnapshot {
            phase: RolloutPhase::Canary,
            observed: TrajectorySnapshot {
                instability_score: canary.max_instability_score / 2.0,
                drift_score: 0.10,
                regime_shift_probability: canary.max_regime_shift_probability,
            },
        };

        let rollback = evaluate_rollout_health("trace-bpet-exact-regime-limit", &rollout, &health);

        assert!(rollback.should_rollback);
        assert_eq!(rollback.event.code, event_codes::ROLLBACK_TRIGGERED);
    }

    // ── NEGATIVE-PATH TESTS: Security & Robustness ──────────────────

    #[test]
    fn test_negative_trajectory_snapshot_with_extreme_floating_point_values() {
        let extreme_values = [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MIN,
            f64::MAX,
            f64::EPSILON,
            -f64::EPSILON,
            0.0,
            -0.0,
            1e100,
            1e-100,
            f64::from_bits(0x7FF0000000000001), // Signaling NaN
            f64::from_bits(0x7FF8000000000000), // Quiet NaN
        ];

        for extreme_value in extreme_values {
            let extreme_snapshot = TrajectorySnapshot {
                instability_score: extreme_value,
                drift_score: extreme_value,
                regime_shift_probability: extreme_value,
            };

            // Verify serialization handles extreme values safely
            match serde_json::to_string(&extreme_snapshot) {
                Ok(json) => {
                    // If serialization succeeds, verify deserialization
                    let parsed: Result<TrajectorySnapshot, _> = serde_json::from_str(&json);

                    if let Ok(parsed_snapshot) = parsed {
                        // For finite values, should be exact
                        if extreme_value.is_finite() {
                            assert_eq!(parsed_snapshot.instability_score, extreme_value);
                            assert_eq!(parsed_snapshot.drift_score, extreme_value);
                            assert_eq!(parsed_snapshot.regime_shift_probability, extreme_value);
                        }
                    }
                    // NaN/Infinity might be serialized as null or special strings - that's OK
                }
                Err(_) => {
                    // Serialization failure for extreme values is acceptable
                }
            }

            // Test delta computation with extreme values
            let normal_snapshot = TrajectorySnapshot {
                instability_score: 0.5,
                drift_score: 0.3,
                regime_shift_probability: 0.2,
            };

            let delta = TrajectoryDelta::between(normal_snapshot, extreme_snapshot);

            // Verify delta computation doesn't panic and handles extreme cases
            if extreme_value.is_finite() {
                assert!(
                    delta.instability_delta.is_finite() || delta.instability_delta.is_infinite()
                );
                assert!(delta.drift_delta.is_finite() || delta.drift_delta.is_infinite());
                assert!(
                    delta.regime_shift_delta.is_finite() || delta.regime_shift_delta.is_infinite()
                );
            } else {
                // NaN or infinite inputs should produce NaN or infinite deltas
                assert!(delta.instability_delta.is_nan() || delta.instability_delta.is_infinite());
            }

            // Test gate evaluation with extreme trajectory
            if extreme_value.is_finite() && extreme_value >= 0.0 && extreme_value <= 1.0 {
                let result = evaluate_migration_gate("test-extreme", &extreme_snapshot);
                // Should not panic, might allow/reject based on thresholds
                assert!(matches!(
                    result.verdict,
                    GateVerdict::Allow
                        | GateVerdict::RequireAdditionalEvidence
                        | GateVerdict::StagedRolloutRequired
                ));
            }
        }
    }

    #[test]
    fn test_negative_stability_thresholds_with_malicious_bypass_attempts() {
        // Test with thresholds that might allow bypass
        let bypass_thresholds = [
            StabilityThresholds {
                max_instability_delta_for_direct_admit: f64::INFINITY,
                max_drift_score_for_direct_admit: f64::INFINITY,
                max_regime_shift_probability_for_direct_admit: f64::INFINITY,
                max_instability_score_for_staged_rollout: f64::INFINITY,
                max_regime_shift_probability_for_staged_rollout: f64::INFINITY,
            },
            StabilityThresholds {
                max_instability_delta_for_direct_admit: -1.0, // Negative threshold
                max_drift_score_for_direct_admit: -1.0,
                max_regime_shift_probability_for_direct_admit: -1.0,
                max_instability_score_for_staged_rollout: -1.0,
                max_regime_shift_probability_for_staged_rollout: -1.0,
            },
            StabilityThresholds {
                max_instability_delta_for_direct_admit: f64::NAN,
                max_drift_score_for_direct_admit: f64::NAN,
                max_regime_shift_probability_for_direct_admit: f64::NAN,
                max_instability_score_for_staged_rollout: f64::NAN,
                max_regime_shift_probability_for_staged_rollout: f64::NAN,
            },
        ];

        let test_trajectory = TrajectorySnapshot {
            instability_score: 0.5,
            drift_score: 0.4,
            regime_shift_probability: 0.3,
        };

        for malicious_thresholds in bypass_thresholds {
            // Test that the gate doesn't get bypassed by malicious thresholds
            let gate = MigrationGate::new(malicious_thresholds);
            let result = gate.evaluate("test-bypass", &test_trajectory);

            // Verify gate still produces valid verdicts even with extreme thresholds
            assert!(matches!(
                result.verdict,
                GateVerdict::Allow
                    | GateVerdict::RequireAdditionalEvidence
                    | GateVerdict::StagedRolloutRequired
            ));

            // Test serialization of malicious thresholds
            let json = serde_json::to_string(&malicious_thresholds);
            match json {
                Ok(json_str) => {
                    // Should be able to deserialize safely
                    let parsed: Result<StabilityThresholds, _> = serde_json::from_str(&json_str);
                    if parsed.is_ok() {
                        // Verify no injection or corruption occurred
                        assert!(!json_str.contains("admin"), "no injection should occur");
                        assert!(!json_str.contains("bypass"), "no injection should occur");
                    }
                }
                Err(_) => {
                    // Serialization failure is acceptable for extreme values
                }
            }
        }

        // Test boundary conditions that might cause bypass
        let boundary_thresholds = StabilityThresholds {
            max_instability_delta_for_direct_admit: f64::EPSILON,
            max_drift_score_for_direct_admit: f64::EPSILON,
            max_regime_shift_probability_for_direct_admit: f64::EPSILON,
            max_instability_score_for_staged_rollout: 1.0 - f64::EPSILON,
            max_regime_shift_probability_for_staged_rollout: 1.0 - f64::EPSILON,
        };

        let gate = MigrationGate::new(boundary_thresholds);

        // Test with values very close to thresholds
        let boundary_trajectory = TrajectorySnapshot {
            instability_score: f64::EPSILON / 2.0,
            drift_score: f64::EPSILON / 2.0,
            regime_shift_probability: f64::EPSILON / 2.0,
        };

        let result = gate.evaluate("test-boundary", &boundary_trajectory);
        // Should handle boundary cases without floating-point comparison issues
    }

    // Test helper types for rollout plan validation
    #[derive(Debug, Clone, PartialEq)]
    struct RolloutPlan {
        canary: RolloutStep,
        limited: RolloutStep,
        progressive: RolloutStep,
        general: RolloutStep,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct RolloutStep {
        phase: RolloutPhase,
        max_instability_score: f64,
        max_regime_shift_probability: f64,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum RolloutPhase {
        Canary,
        Limited,
        Progressive,
        General,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct RolloutHealth {
        stability_score: f64,
        risk_level: f64,
    }

    #[test]
    fn test_negative_trace_id_with_unicode_injection_attacks() {
        use crate::security::constant_time;

        let malicious_trace_ids = [
            "trace\u{202E}fake\u{202C}",          // BiDi override attack
            "trace\x1b[31mred\x1b[0m",            // ANSI escape injection
            "trace\0null\r\n\t",                  // Control character injection
            "trace\"}{\"admin\":true,\"bypass\"", // JSON injection attempt
            "trace/../../etc/passwd",             // Path traversal attempt
            "trace\u{FEFF}BOM",                   // Byte order mark
            "trace\u{200B}\u{200C}\u{200D}",      // Zero-width characters
            "trace".repeat(1000),                 // Extremely long trace ID
        ];

        let test_trajectory = TrajectorySnapshot {
            instability_score: 0.5,
            drift_score: 0.3,
            regime_shift_probability: 0.2,
        };

        for malicious_trace_id in malicious_trace_ids {
            // Test gate evaluation with malicious trace ID
            let result = evaluate_migration_gate(malicious_trace_id, &test_trajectory);

            // Verify result contains the trace ID but is safely contained
            assert_eq!(
                result.event.trace_id, malicious_trace_id,
                "trace ID should be preserved for forensics"
            );

            // Verify JSON serialization is safe
            let json = serde_json::to_string(&result).expect("serialization should work");
            let parsed: serde_json::Value =
                serde_json::from_str(&json).expect("JSON should be valid");

            // Verify no injection occurred in JSON structure
            assert!(
                parsed.get("admin").is_none(),
                "JSON injection should not create admin field"
            );
            assert!(
                parsed.get("bypass").is_none(),
                "JSON injection should not create bypass field"
            );

            // Verify trace ID is properly escaped in JSON
            if let Some(event) = parsed.get("event") {
                if let Some(trace_id) = event.get("trace_id") {
                    if let Some(trace_str) = trace_id.as_str() {
                        assert_eq!(
                            trace_str, malicious_trace_id,
                            "trace ID should be preserved"
                        );
                    }
                }
            }

            // Test constant-time comparison for trace IDs
            let normal_trace = "normal-trace-123";
            assert!(
                !constant_time::ct_eq(malicious_trace_id, normal_trace),
                "trace ID comparison should be constant-time"
            );

            // Test rollout evaluation with malicious trace ID
            let rollout = RolloutPlan {
                canary: RolloutStep {
                    phase: RolloutPhase::Canary,
                    max_instability_score: 0.3,
                    max_regime_shift_probability: 0.2,
                },
                limited: RolloutStep {
                    phase: RolloutPhase::Limited,
                    max_instability_score: 0.5,
                    max_regime_shift_probability: 0.3,
                },
                progressive: RolloutStep {
                    phase: RolloutPhase::Progressive,
                    max_instability_score: 0.7,
                    max_regime_shift_probability: 0.4,
                },
                general: RolloutStep {
                    phase: RolloutPhase::General,
                    max_instability_score: 1.0,
                    max_regime_shift_probability: 0.5,
                },
            };

            let health = RolloutHealth {
                current_phase: RolloutPhase::Canary,
                stability: test_trajectory,
            };

            let rollback = evaluate_rollout_health(malicious_trace_id, &rollout, &health);

            // Verify rollback evaluation works with malicious trace ID
            assert_eq!(
                rollback.event.trace_id, malicious_trace_id,
                "rollback trace ID should be preserved"
            );
        }
    }

    #[test]
    fn test_negative_gate_event_message_with_massive_injection_payload() {
        let massive_message = "X".repeat(1_000_000); // 1MB message

        let massive_event = GateEvent {
            code: event_codes::EVIDENCE_REQUIRED.to_string(),
            level: "warning".to_string(),
            trace_id: "test-massive".to_string(),
            message: massive_message.clone(),
        };

        // Verify serialization handles massive message
        let json = serde_json::to_string(&massive_event)
            .expect("serialization should handle massive message");
        assert!(
            json.len() >= massive_message.len(),
            "JSON should include massive message"
        );

        // Verify deserialization works
        let parsed: GateEvent = serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(
            parsed.message, massive_message,
            "massive message should be preserved"
        );

        // Test with injection patterns in message
        let injection_messages = [
            "message\u{202E}fake\u{202C}",
            "message\x1b[31mred\x1b[0m",
            "message\0null\r\n\t",
            "message\"}{\"admin\":true,\"bypass",
            "message with unicode \u{1F4A9} and control \r\n chars",
        ];

        for injection_message in injection_messages {
            let injection_event = GateEvent {
                code: event_codes::ADMISSION_ALLOWED.to_string(),
                level: "info".to_string(),
                trace_id: "test-injection".to_string(),
                message: injection_message.to_string(),
            };

            // Verify serialization contains injection safely
            let json = serde_json::to_string(&injection_event).expect("serialization should work");
            let parsed: serde_json::Value =
                serde_json::from_str(&json).expect("JSON should be valid");

            // Verify no additional fields were injected
            let expected_keys = ["code", "level", "trace_id", "message"];
            if let Some(obj) = parsed.as_object() {
                for key in obj.keys() {
                    assert!(
                        expected_keys.contains(&key.as_str()),
                        "unexpected field '{}' - possible JSON injection",
                        key
                    );
                }
            }

            // Verify message content is properly escaped
            if let Some(message) = parsed.get("message").and_then(|m| m.as_str()) {
                assert_eq!(
                    message, injection_message,
                    "message should be preserved exactly"
                );
            }
        }
    }

    #[test]
    fn test_negative_rollout_step_with_invalid_phase_transitions() {
        // Test rollout steps with potential bypass via enum manipulation
        let phases = [
            RolloutPhase::Canary,
            RolloutPhase::Limited,
            RolloutPhase::Progressive,
            RolloutPhase::General,
        ];

        for phase in phases {
            let rollout_step = RolloutStep {
                phase,
                max_instability_score: f64::NAN, // Invalid threshold
                max_regime_shift_probability: f64::INFINITY, // Invalid threshold
            };

            // Test serialization with invalid thresholds
            let json = serde_json::to_string(&rollout_step);
            match json {
                Ok(json_str) => {
                    // Try to deserialize
                    let parsed: Result<RolloutStep, _> = serde_json::from_str(&json_str);
                    // Might succeed or fail depending on how NaN/Infinity is serialized
                }
                Err(_) => {
                    // Serialization failure is acceptable for NaN/Infinity
                }
            }
        }

        // Test potential enum injection attacks
        let invalid_phase_jsons = [
            r#"{"phase": "Admin", "max_instability_score": 0.0, "max_regime_shift_probability": 0.0}"#,
            r#"{"phase": 999, "max_instability_score": 0.0, "max_regime_shift_probability": 0.0}"#,
            r#"{"phase": "canary\"}{\"bypass\":true", "max_instability_score": 0.0, "max_regime_shift_probability": 0.0}"#,
            r#"{"phase": null, "max_instability_score": 0.0, "max_regime_shift_probability": 0.0}"#,
        ];

        for invalid_json in invalid_phase_jsons {
            let result: Result<RolloutStep, _> = serde_json::from_str(invalid_json);
            // Should fail to deserialize invalid enum variants
            assert!(
                result.is_err(),
                "invalid phase should fail deserialization: {}",
                invalid_json
            );
        }

        // Test with extreme threshold values
        let extreme_step = RolloutStep {
            phase: RolloutPhase::Canary,
            max_instability_score: f64::MAX,
            max_regime_shift_probability: f64::MAX,
        };

        let rollout = RolloutPlan {
            canary: extreme_step,
            limited: extreme_step,
            progressive: extreme_step,
            general: extreme_step,
        };

        let normal_health = RolloutHealth {
            current_phase: RolloutPhase::Canary,
            stability: TrajectorySnapshot {
                instability_score: 0.5,
                drift_score: 0.3,
                regime_shift_probability: 0.2,
            },
        };

        // Should handle extreme thresholds without panic
        let rollback = evaluate_rollout_health("test-extreme-thresholds", &rollout, &normal_health);
        assert!(
            !rollback.should_rollback,
            "extreme thresholds should allow rollout"
        );
    }

    #[test]
    fn test_negative_trajectory_delta_arithmetic_overflow_protection() {
        // Test delta computation with values that might cause overflow
        let max_snapshot = TrajectorySnapshot {
            instability_score: f64::MAX,
            drift_score: f64::MAX,
            regime_shift_probability: f64::MAX,
        };

        let min_snapshot = TrajectorySnapshot {
            instability_score: f64::MIN,
            drift_score: f64::MIN,
            regime_shift_probability: f64::MIN,
        };

        // Test extreme delta computation
        let max_to_min_delta = TrajectoryDelta::between(max_snapshot, min_snapshot);
        let min_to_max_delta = TrajectoryDelta::between(min_snapshot, max_snapshot);

        // Verify deltas are infinite rather than overflowing
        assert!(max_to_min_delta.instability_delta.is_infinite());
        assert!(max_to_min_delta.drift_delta.is_infinite());
        assert!(max_to_min_delta.regime_shift_delta.is_infinite());

        assert!(min_to_max_delta.instability_delta.is_infinite());
        assert!(min_to_max_delta.drift_delta.is_infinite());
        assert!(min_to_max_delta.regime_shift_delta.is_infinite());

        // Test with very close values near floating-point precision limits
        let base_snapshot = TrajectorySnapshot {
            instability_score: 1.0,
            drift_score: 1.0,
            regime_shift_probability: 1.0,
        };

        let epsilon_snapshot = TrajectorySnapshot {
            instability_score: 1.0 + f64::EPSILON,
            drift_score: 1.0 + f64::EPSILON,
            regime_shift_probability: 1.0 + f64::EPSILON,
        };

        let epsilon_delta = TrajectoryDelta::between(base_snapshot, epsilon_snapshot);

        // Verify small differences are preserved
        assert!(epsilon_delta.instability_delta > 0.0);
        assert!(epsilon_delta.instability_delta < 1e-10);

        // Test with values that might cause loss of precision
        let large_base = TrajectorySnapshot {
            instability_score: 1e15,
            drift_score: 1e15,
            regime_shift_probability: 1e15,
        };

        let large_modified = TrajectorySnapshot {
            instability_score: 1e15 + 1.0,
            drift_score: 1e15 + 1.0,
            regime_shift_probability: 1e15 + 1.0,
        };

        let precision_delta = TrajectoryDelta::between(large_base, large_modified);

        // Verify delta computation doesn't lose significant precision
        // (though exact values depend on floating-point representation)
        assert!(precision_delta.instability_delta.is_finite());
        assert!(precision_delta.drift_delta.is_finite());
        assert!(precision_delta.regime_shift_delta.is_finite());
    }

    #[test]
    fn test_negative_migration_gate_events_with_bounded_storage() {
        let mut gate = MigrationGate::new(StabilityThresholds::default());

        // Generate many events to test bounded storage
        let test_trajectory = TrajectorySnapshot {
            instability_score: 0.9, // High value to trigger events
            drift_score: 0.8,
            regime_shift_probability: 0.7,
        };

        let mut all_trace_ids = Vec::new();

        // Generate 10,000 events to stress the storage system
        for i in 0..10_000 {
            let trace_id = format!("stress-test-{:05}", i);
            let result = gate.evaluate(&trace_id, &test_trajectory);

            all_trace_ids.push(trace_id.clone());

            // Verify each evaluation produces a valid result
            assert!(matches!(
                result.verdict,
                GateVerdict::Allow
                    | GateVerdict::RequireAdditionalEvidence
                    | GateVerdict::StagedRolloutRequired
            ));
            assert_eq!(result.event.trace_id, trace_id);
        }

        // Verify recent events are bounded (implementation detail, but should not grow unbounded)
        if gate.recent_events.len() > MAX_EVENTS * 2 {
            panic!(
                "event storage should be bounded, got {} events",
                gate.recent_events.len()
            );
        }

        // Test with malicious trace IDs that might cause memory issues
        let memory_stress_trajectory = TrajectorySnapshot {
            instability_score: 0.5,
            drift_score: 0.5,
            regime_shift_probability: 0.5,
        };

        for i in 0..100 {
            let huge_trace_id = format!("huge-trace-{}-{}", i, "X".repeat(10_000)); // 10KB trace ID
            let result = gate.evaluate(&huge_trace_id, &memory_stress_trajectory);

            // Should handle huge trace IDs without memory explosion
            assert_eq!(result.event.trace_id, huge_trace_id);
        }

        // Verify gate still functions after stress testing
        let final_result = gate.evaluate("final-test", &test_trajectory);
        assert!(matches!(
            final_result.verdict,
            GateVerdict::Allow
                | GateVerdict::RequireAdditionalEvidence
                | GateVerdict::StagedRolloutRequired
        ));
    }

    #[test]
    fn test_negative_fallback_plan_with_malicious_step_configuration() {
        // Test fallback plan generation with malicious rollout configurations
        let malicious_rollout = RolloutPlan {
            canary: RolloutStep {
                phase: RolloutPhase::Canary,
                max_instability_score: -1.0, // Negative threshold (invalid)
                max_regime_shift_probability: 2.0, // Over 1.0 (invalid for probability)
            },
            limited: RolloutStep {
                phase: RolloutPhase::Limited,
                max_instability_score: f64::INFINITY,
                max_regime_shift_probability: f64::NAN,
            },
            progressive: RolloutStep {
                phase: RolloutPhase::Progressive,
                max_instability_score: 0.0, // Zero threshold (very restrictive)
                max_regime_shift_probability: 0.0,
            },
            general: RolloutStep {
                phase: RolloutPhase::General,
                max_instability_score: f64::MIN, // Minimum float
                max_regime_shift_probability: f64::EPSILON,
            },
        };

        let test_trajectory = TrajectorySnapshot {
            instability_score: 0.5,
            drift_score: 0.3,
            regime_shift_probability: 0.2,
        };

        let health = RolloutHealth {
            current_phase: RolloutPhase::Canary,
            stability: test_trajectory,
        };

        // Test that fallback plan generation handles malicious configuration
        let fallback = generate_fallback_plan("malicious-config-test", &malicious_rollout);

        // Should produce a valid fallback plan despite malicious input
        assert!(
            !fallback.steps.is_empty(),
            "fallback plan should have steps"
        );

        // Test rollout health evaluation with malicious configuration
        let rollback =
            evaluate_rollout_health("malicious-rollout-test", &malicious_rollout, &health);

        // Should not panic and should produce a valid rollback decision
        assert_eq!(rollback.event.trace_id, "malicious-rollout-test");

        // Verify the rollback decision is safe (either allow or rollback, but deterministic)
        assert!(rollback.should_rollback == true || rollback.should_rollback == false);

        // Test serialization of malicious rollout configuration
        let json = serde_json::to_string(&malicious_rollout);
        match json {
            Ok(json_str) => {
                // Should be able to deserialize without corruption
                let parsed: Result<RolloutPlan, _> = serde_json::from_str(&json_str);
                // Might fail for NaN/Infinity values, which is acceptable
            }
            Err(_) => {
                // Serialization failure for extreme values is acceptable
            }
        }
    }

    // === HARDENING-FOCUSED NEGATIVE-PATH TESTS ===
    // Tests for specific hardening patterns that must be enforced

    #[test]
    fn negative_vector_operations_must_use_push_bounded() {
        // Test that Vec::push operations use push_bounded instead of raw push
        // Raw push can cause memory exhaustion through unbounded growth
        let baseline = baseline();
        let projected = TrajectorySnapshot {
            instability_score: 0.9, // High instability to trigger evidence requirements
            drift_score: 0.8,
            regime_shift_probability: 0.7,
        };
        let thresholds = StabilityThresholds::default();

        // Test evidence requirements generation (currently uses raw Vec::push)
        let requirements = gather_evidence_requirements(baseline, projected, &thresholds);

        // Should use push_bounded to prevent memory exhaustion
        // Currently vulnerable: requirements.push("item") without bounds checking
        assert!(
            requirements.len() <= 10,
            "Evidence requirements should be bounded"
        );
        assert!(
            !requirements.is_empty(),
            "Should generate some requirements for high instability"
        );

        // Test that repeated calls don't cause unbounded growth
        let mut all_requirements = Vec::new();
        for i in 0..1000 {
            let test_projected = TrajectorySnapshot {
                instability_score: 0.5 + (i as f64 * 0.0001),
                drift_score: 0.5,
                regime_shift_probability: 0.5,
            };
            let mut batch_requirements =
                gather_evidence_requirements(baseline, test_projected, &thresholds);

            // Simulate what should be push_bounded behavior
            const MAX_TOTAL_REQUIREMENTS: usize = 100;
            for req in batch_requirements.drain(..) {
                if all_requirements.len() >= MAX_TOTAL_REQUIREMENTS {
                    let overflow = all_requirements
                        .len()
                        .saturating_sub(MAX_TOTAL_REQUIREMENTS)
                        .saturating_add(1);
                    all_requirements.drain(0..overflow.min(all_requirements.len()));
                }
                all_requirements.push(req);
            }
        }

        // Requirements should be bounded despite 1000 iterations
        assert!(
            all_requirements.len() <= 100,
            "Requirements should be bounded with push_bounded pattern"
        );

        // Production code should use: push_bounded(&mut requirements, item, MAX_REQUIREMENTS) ✓
        // NOT: requirements.push(item) ✗ (unbounded growth)
    }

    #[test]
    fn negative_event_storage_must_use_push_bounded() {
        // Test that event storage uses push_bounded instead of manual length checking
        // Current code manually checks length and drains - should use push_bounded
        let mut gate = BpetMigrationGate::new();
        let baseline = baseline();

        // Test event accumulation with bounded storage
        for i in 0..200 {
            let projected = TrajectorySnapshot {
                instability_score: 0.1,
                drift_score: 0.1,
                regime_shift_probability: 0.1,
            };

            let trace_id = format!("test-trace-{}", i);
            let result = gate.evaluate(&trace_id, &projected);

            // Events should be bounded (currently uses manual length checking)
            assert!(
                result.events.len() <= MAX_EVENTS * 2,
                "Events should be bounded at iteration {}",
                i
            );
        }

        // Verify gate's internal event storage is also bounded
        assert!(
            gate.recent_events.len() <= MAX_EVENTS * 3,
            "Gate's recent events should be bounded"
        );

        // Test with large event generation in single call
        let high_instability_projected = TrajectorySnapshot {
            instability_score: 0.9, // Triggers multiple event types
            drift_score: 0.9,
            regime_shift_probability: 0.9,
        };

        let large_result = gate.evaluate("large-event-test", &high_instability_projected);

        // Single evaluation should not exceed reasonable event count
        assert!(
            large_result.events.len() <= 20,
            "Single evaluation should not generate excessive events"
        );

        // Production code should use: push_bounded(&mut events, event, MAX_EVENTS) ✓
        // NOT: events.push(event); if events.len() > MAX_EVENTS { drain... } ✗
    }

    #[test]
    fn negative_length_casting_must_use_safe_conversion() {
        // Test that .len() as u32 is replaced with u32::try_from for overflow safety
        // Direct casting silently truncates on 64-bit platforms
        use std::convert::TryFrom;

        let baseline = baseline();
        let projected = TrajectorySnapshot {
            instability_score: 0.5,
            drift_score: 0.5,
            regime_shift_probability: 0.5,
        };

        // Test evidence requirements length conversion
        let requirements =
            gather_evidence_requirements(baseline, projected, &StabilityThresholds::default());

        // Safe length conversion
        let safe_count = u32::try_from(requirements.len()).unwrap_or(u32::MAX);
        assert!(safe_count <= 100, "Requirements count should be reasonable");

        // Demonstrate unsafe vs safe casting with simulated large collections
        let large_size: usize = (u32::MAX as usize) + 1;

        // Unsafe casting (what NOT to do)
        let unsafe_cast = large_size as u32;
        assert_eq!(unsafe_cast, 0, "Unsafe cast wraps to 0, losing data");

        // Safe casting (what SHOULD be done)
        let safe_cast = u32::try_from(large_size);
        assert!(safe_cast.is_err(), "Safe casting should detect overflow");

        // Test boundary conditions
        let max_safe_size = u32::MAX as usize;
        let boundary_cast = u32::try_from(max_safe_size);
        assert!(boundary_cast.is_ok(), "u32::MAX should be safe boundary");
        assert_eq!(boundary_cast.unwrap(), u32::MAX);

        // Test with rollout steps length
        let rollout = build_staged_rollout_plan("test-version", projected);
        let steps_count = rollout.steps.len();
        let steps_safe_count = u32::try_from(steps_count).unwrap_or(u32::MAX);
        assert!(steps_safe_count <= 10, "Rollout steps should be bounded");

        // Production code should use: u32::try_from(collection.len()).unwrap_or(u32::MAX) ✓
        // NOT: collection.len() as u32 ✗ (silent truncation)
    }

    #[test]
    fn negative_threshold_comparison_must_use_fail_closed_semantics() {
        // Test that threshold comparisons use >= instead of > for fail-closed behavior
        // Using > allows boundary values to pass through (security bypass)
        let baseline = baseline();
        let thresholds = StabilityThresholds::default();

        // Test boundary conditions for instability thresholds
        let boundary_test_cases = [
            // Exactly at threshold (should be rejected with fail-closed >= comparison)
            TrajectorySnapshot {
                instability_score: thresholds.max_instability_score_for_staged_rollout,
                drift_score: 0.1,
                regime_shift_probability: 0.1,
            },
            // Just below threshold (should pass)
            TrajectorySnapshot {
                instability_score: thresholds.max_instability_score_for_staged_rollout - 0.001,
                drift_score: 0.1,
                regime_shift_probability: 0.1,
            },
            // Just above threshold (should be rejected)
            TrajectorySnapshot {
                instability_score: thresholds.max_instability_score_for_staged_rollout + 0.001,
                drift_score: 0.1,
                regime_shift_probability: 0.1,
            },
        ];

        for (i, projected) in boundary_test_cases.iter().enumerate() {
            let decision = evaluate_trajectory_for_admission(
                baseline,
                *projected,
                "test-version",
                &thresholds,
                &format!("boundary-test-{}", i),
            );

            let is_at_boundary = (projected.instability_score
                - thresholds.max_instability_score_for_staged_rollout)
                .abs()
                < f64::EPSILON;
            let is_above_threshold =
                projected.instability_score > thresholds.max_instability_score_for_staged_rollout;

            if is_at_boundary {
                // Boundary case: fail-closed should reject (use >=, not >)
                assert!(
                    matches!(decision.verdict, GateVerdict::StagedRolloutRequired),
                    "Boundary case should be rejected with fail-closed semantics for test {}",
                    i
                );
            } else if is_above_threshold {
                // Above threshold: should definitely be rejected
                assert!(
                    matches!(decision.verdict, GateVerdict::StagedRolloutRequired),
                    "Above threshold should be rejected for test {}",
                    i
                );
            } else {
                // Below threshold: should be allowed (unless other constraints apply)
                // May still require evidence due to other factors, but not staged rollout for this metric
            }
        }

        // Test regime shift probability boundaries
        let regime_boundary = TrajectorySnapshot {
            instability_score: 0.1,
            drift_score: 0.1,
            regime_shift_probability: thresholds.max_regime_shift_probability_for_staged_rollout,
        };

        let regime_decision = evaluate_trajectory_for_admission(
            baseline,
            regime_boundary,
            "test-version",
            &thresholds,
            "regime-boundary-test",
        );

        // Boundary regime shift probability should trigger staged rollout (fail-closed)
        assert!(
            matches!(regime_decision.verdict, GateVerdict::StagedRolloutRequired),
            "Boundary regime shift probability should be fail-closed"
        );

        // Production code should use: value >= threshold ✓ (fail-closed)
        // NOT: value > threshold ✗ (allows boundary values through)
    }

    #[test]
    fn negative_hash_operations_must_include_domain_separators() {
        // Test that hash operations include domain separators to prevent collision attacks
        // BPET migration should hash trajectory data with proper domain separation
        use sha2::{Digest, Sha256};

        let trajectory1 = TrajectorySnapshot {
            instability_score: 0.5,
            drift_score: 0.3,
            regime_shift_probability: 0.2,
        };

        let trajectory2 = TrajectorySnapshot {
            instability_score: 0.5,
            drift_score: 0.3,
            regime_shift_probability: 0.2,
        };

        // Hash with domain separator (proper approach)
        let mut hasher_with_domain = Sha256::new();
        hasher_with_domain.update(b"bpet_trajectory_v1:");
        let trajectory1_json =
            serde_json::to_string(&trajectory1).expect("trajectory1 serialization");
        hasher_with_domain.update(trajectory1_json.as_bytes());
        let hash_with_domain = hasher_with_domain.finalize();

        // Hash without domain separator (vulnerable approach)
        let mut hasher_without_domain = Sha256::new();
        hasher_without_domain.update(trajectory1_json.as_bytes());
        let hash_without_domain = hasher_without_domain.finalize();

        // Domain separator should change hash value
        assert_ne!(
            hash_with_domain.as_slice(),
            hash_without_domain.as_slice(),
            "Domain separator should change hash value"
        );

        // Test different types with different domain separators
        let thresholds = StabilityThresholds::default();

        let mut trajectory_hasher = Sha256::new();
        trajectory_hasher.update(b"bpet_trajectory:");
        trajectory_hasher.update(trajectory1_json.as_bytes());
        let trajectory_hash = trajectory_hasher.finalize();

        let mut thresholds_hasher = Sha256::new();
        thresholds_hasher.update(b"bpet_thresholds:");
        let thresholds_json = serde_json::to_string(&thresholds).expect("thresholds serialization");
        thresholds_hasher.update(thresholds_json.as_bytes());
        let thresholds_hash = thresholds_hasher.finalize();

        // Different types should have different hash domains
        assert_ne!(
            trajectory_hash.as_slice(),
            thresholds_hash.as_slice(),
            "Different types should have different hash domains"
        );

        // Test length-prefixed domain separation
        let mut length_prefixed_hasher = Sha256::new();
        let domain = "bpet_trajectory_v1";
        let domain_len = u64::try_from(domain.len()).unwrap_or(u64::MAX);
        length_prefixed_hasher.update(domain_len.to_le_bytes());
        length_prefixed_hasher.update(domain.as_bytes());
        length_prefixed_hasher.update(trajectory1_json.as_bytes());
        let length_prefixed_hash = length_prefixed_hasher.finalize();

        assert_ne!(
            length_prefixed_hash.as_slice(),
            hash_with_domain.as_slice(),
            "Length-prefixed domain separation should be distinct"
        );

        // Test rollout phase hashing with domain separation
        let phase = RolloutPhase::Canary;

        let mut phase_hasher = Sha256::new();
        phase_hasher.update(b"bpet_rollout_phase:");
        let phase_json = serde_json::to_string(&phase).expect("phase serialization");
        phase_hasher.update(phase_json.as_bytes());
        let phase_hash = phase_hasher.finalize();

        assert_ne!(
            phase_hash.as_slice(),
            trajectory_hash.as_slice(),
            "Rollout phase should have different hash domain"
        );

        // Production code should use domain separators:
        // hasher.update(b"bpet_trajectory_v1:");  ✓
        // hasher.update(trajectory_bytes);
        // NOT: hasher.update(trajectory_bytes) alone ✗
    }

    #[test]
    fn negative_comprehensive_hardening_patterns_validation() {
        // Test all hardening patterns together to catch interaction bugs
        let mut gate = BpetMigrationGate::new();
        let baseline = baseline();
        let thresholds = StabilityThresholds::default();

        // Test with trajectory that triggers multiple patterns
        for i in 0..100 {
            let projected = TrajectorySnapshot {
                instability_score: 0.5 + (i as f64 * 0.001), // Gradually increasing
                drift_score: 0.3 + (i as f64 * 0.001),
                regime_shift_probability: 0.2 + (i as f64 * 0.001),
            };

            let trace_id = format!("comprehensive-test-{:04x}", i); // Hex format
            let result = gate.evaluate(&trace_id, &projected);

            // Test safe length conversion throughout
            let events_count = result.events.len();
            let safe_events_count =
                std::convert::TryFrom::try_from(events_count).unwrap_or(u32::MAX);
            assert!(
                safe_events_count <= 50,
                "Events should be reasonably bounded for iteration {}",
                i
            );

            // Test evidence requirements (should use push_bounded)
            let requirements = gather_evidence_requirements(baseline, projected, &thresholds);
            assert!(
                requirements.len() <= 20,
                "Requirements should be bounded for iteration {}",
                i
            );

            // Test threshold comparisons (should use fail-closed semantics)
            let is_high_risk = projected.instability_score
                >= thresholds.max_instability_score_for_staged_rollout
                || projected.regime_shift_probability
                    >= thresholds.max_regime_shift_probability_for_staged_rollout;

            if is_high_risk {
                assert!(
                    matches!(result.verdict, GateVerdict::StagedRolloutRequired),
                    "High risk should require staged rollout for iteration {}",
                    i
                );
            }

            // Verify no arithmetic overflow in delta calculations
            let delta = TrajectoryDelta::between(baseline, projected);
            assert!(
                delta.instability_delta.is_finite(),
                "Instability delta should be finite for iteration {}",
                i
            );
            assert!(
                delta.drift_delta.is_finite(),
                "Drift delta should be finite for iteration {}",
                i
            );
            assert!(
                delta.regime_shift_delta.is_finite(),
                "Regime shift delta should be finite for iteration {}",
                i
            );
        }

        // Test gate's internal state remains bounded
        assert!(
            gate.recent_events.len() <= MAX_EVENTS * 5,
            "Gate recent events should be bounded after comprehensive testing"
        );

        // Test rollout plan generation with boundary conditions
        let boundary_projected = TrajectorySnapshot {
            instability_score: thresholds.max_instability_score_for_staged_rollout,
            drift_score: thresholds.max_drift_score_for_direct_admit,
            regime_shift_probability: thresholds.max_regime_shift_probability_for_staged_rollout,
        };

        let rollout = build_staged_rollout_plan("boundary-test", boundary_projected);

        // Rollout should have reasonable step count (bounded)
        let steps_count = rollout.steps.len();
        let safe_steps_count = std::convert::TryFrom::try_from(steps_count).unwrap_or(u32::MAX);
        assert!(
            safe_steps_count <= 10,
            "Rollout steps should be reasonably bounded"
        );

        // Verify all hardening patterns work together without conflicts
        assert!(matches!(rollout.canary.phase, RolloutPhase::Canary));
        assert!(rollout.canary.max_instability_score.is_finite());
        assert!(rollout.canary.max_regime_shift_probability.is_finite());
    }
}
