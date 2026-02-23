//! DGIS migration admission/progression gate (bd-2d17).
//!
//! This gate connects migration autopilot decisions to dependency-topology
//! health deltas, with deterministic rejection reasons and replan suggestions.

use serde::{Deserialize, Serialize};

/// Stable event codes for gate telemetry.
pub mod event_codes {
    pub const BASELINE_CAPTURED: &str = "DGIS-MIGRATE-001";
    pub const ADMISSION_ALLOWED: &str = "DGIS-MIGRATE-002";
    pub const ADMISSION_BLOCKED: &str = "DGIS-MIGRATE-003";
    pub const PHASE_ALLOWED: &str = "DGIS-MIGRATE-004";
    pub const PHASE_BLOCKED: &str = "DGIS-MIGRATE-005";
    pub const REPLAN_SUGGESTED: &str = "DGIS-MIGRATE-006";
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GraphHealthSnapshot {
    /// Aggregated cascade-risk score from DGIS (0.0..=1.0 in current policy).
    pub cascade_risk: f64,
    /// Count of fragility findings.
    pub fragility_findings: u32,
    /// Count of articulation points/chokepoints.
    pub articulation_points: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HealthDelta {
    /// Positive values indicate increased risk relative to baseline.
    pub cascade_risk_delta: f64,
    pub new_fragility_findings: i32,
    pub new_articulation_points: i32,
}

impl HealthDelta {
    pub fn between(baseline: GraphHealthSnapshot, projected: GraphHealthSnapshot) -> Self {
        Self {
            cascade_risk_delta: projected.cascade_risk - baseline.cascade_risk,
            new_fragility_findings: projected.fragility_findings as i32
                - baseline.fragility_findings as i32,
            new_articulation_points: projected.articulation_points as i32
                - baseline.articulation_points as i32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MigrationGateThresholds {
    pub max_cascade_risk_delta: f64,
    pub max_new_fragility_findings: u32,
    pub max_new_articulation_points: u32,
}

impl Default for MigrationGateThresholds {
    fn default() -> Self {
        Self {
            max_cascade_risk_delta: 0.12,
            max_new_fragility_findings: 2,
            max_new_articulation_points: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationPathCandidate {
    pub path_id: String,
    pub projected: GraphHealthSnapshot,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplanSuggestion {
    pub path_id: String,
    pub projected_delta: HealthDelta,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectionReason {
    pub code: String,
    pub detail: String,
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
pub enum GateVerdict {
    Allow,
    Block,
    ReplanRequired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateEvaluation {
    pub phase: String,
    pub verdict: GateVerdict,
    pub baseline: GraphHealthSnapshot,
    pub projected: GraphHealthSnapshot,
    pub delta: HealthDelta,
    pub thresholds: MigrationGateThresholds,
    pub rejection_reasons: Vec<RejectionReason>,
    pub replan_suggestions: Vec<ReplanSuggestion>,
    pub events: Vec<GateEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationHealthReport {
    pub plan_id: String,
    pub evaluation: GateEvaluation,
}

fn evaluate_policy(
    delta: HealthDelta,
    thresholds: MigrationGateThresholds,
) -> Vec<RejectionReason> {
    let mut reasons = Vec::new();

    if delta.cascade_risk_delta > thresholds.max_cascade_risk_delta {
        reasons.push(RejectionReason {
            code: "DGIS-MIGRATE-RISK-DELTA".to_string(),
            detail: format!(
                "cascade risk delta {:.4} exceeds max {:.4}",
                delta.cascade_risk_delta, thresholds.max_cascade_risk_delta
            ),
        });
    }

    if delta.new_fragility_findings > thresholds.max_new_fragility_findings as i32 {
        reasons.push(RejectionReason {
            code: "DGIS-MIGRATE-FRAGILITY-DELTA".to_string(),
            detail: format!(
                "new fragility findings {} exceed max {}",
                delta.new_fragility_findings, thresholds.max_new_fragility_findings
            ),
        });
    }

    if delta.new_articulation_points > thresholds.max_new_articulation_points as i32 {
        reasons.push(RejectionReason {
            code: "DGIS-MIGRATE-ARTICULATION-DELTA".to_string(),
            detail: format!(
                "new articulation points {} exceed max {}",
                delta.new_articulation_points, thresholds.max_new_articulation_points
            ),
        });
    }

    reasons
}

fn gate_event(code: &str, level: &str, trace_id: &str, message: String) -> GateEvent {
    GateEvent {
        code: code.to_string(),
        level: level.to_string(),
        trace_id: trace_id.to_string(),
        message,
    }
}

fn lower_risk_than_blocked(blocked: HealthDelta, candidate: HealthDelta) -> bool {
    candidate.cascade_risk_delta < blocked.cascade_risk_delta
        && candidate.new_fragility_findings < blocked.new_fragility_findings
        && candidate.new_articulation_points < blocked.new_articulation_points
}

pub fn suggest_replans(
    baseline: GraphHealthSnapshot,
    blocked_delta: HealthDelta,
    candidates: &[MigrationPathCandidate],
    thresholds: MigrationGateThresholds,
) -> Vec<ReplanSuggestion> {
    let mut scored: Vec<(bool, HealthDelta, &MigrationPathCandidate)> = candidates
        .iter()
        .map(|candidate| {
            let delta = HealthDelta::between(baseline, candidate.projected);
            let passes = evaluate_policy(delta, thresholds).is_empty();
            (passes, delta, candidate)
        })
        .filter(|(_, delta, _)| lower_risk_than_blocked(blocked_delta, *delta))
        .collect();

    scored.sort_by(|(passes_a, delta_a, cand_a), (passes_b, delta_b, cand_b)| {
        passes_b
            .cmp(passes_a)
            .then_with(|| {
                delta_a
                    .cascade_risk_delta
                    .total_cmp(&delta_b.cascade_risk_delta)
            })
            .then_with(|| {
                delta_a
                    .new_fragility_findings
                    .cmp(&delta_b.new_fragility_findings)
            })
            .then_with(|| {
                delta_a
                    .new_articulation_points
                    .cmp(&delta_b.new_articulation_points)
            })
            .then_with(|| cand_a.path_id.cmp(&cand_b.path_id))
    });

    scored
        .into_iter()
        .take(3)
        .map(|(passes, delta, candidate)| ReplanSuggestion {
            path_id: candidate.path_id.clone(),
            projected_delta: delta,
            rationale: if passes {
                format!(
                    "candidate reduces topology risk while staying within policy budget ({})",
                    candidate.notes
                )
            } else {
                format!(
                    "candidate reduces risk relative to blocked plan but still exceeds one or more thresholds ({})",
                    candidate.notes
                )
            },
        })
        .collect()
}

fn evaluate(
    trace_id: &str,
    phase: &str,
    baseline: GraphHealthSnapshot,
    projected: GraphHealthSnapshot,
    thresholds: MigrationGateThresholds,
    candidates: &[MigrationPathCandidate],
) -> GateEvaluation {
    let delta = HealthDelta::between(baseline, projected);
    let rejection_reasons = evaluate_policy(delta, thresholds);
    let replan_suggestions = if rejection_reasons.is_empty() {
        Vec::new()
    } else {
        suggest_replans(baseline, delta, candidates, thresholds)
    };

    let verdict = if rejection_reasons.is_empty() {
        GateVerdict::Allow
    } else if replan_suggestions.is_empty() {
        GateVerdict::Block
    } else {
        GateVerdict::ReplanRequired
    };

    let mut events = vec![gate_event(
        event_codes::BASELINE_CAPTURED,
        "info",
        trace_id,
        format!(
            "phase={phase}: captured baseline risk={:.4}, fragility={}, articulation={}",
            baseline.cascade_risk, baseline.fragility_findings, baseline.articulation_points
        ),
    )];

    match verdict {
        GateVerdict::Allow => {
            let event_code = if phase == "admission" {
                event_codes::ADMISSION_ALLOWED
            } else {
                event_codes::PHASE_ALLOWED
            };
            events.push(gate_event(
                event_code,
                "info",
                trace_id,
                format!("phase={phase}: migration gate passed"),
            ));
        }
        GateVerdict::Block | GateVerdict::ReplanRequired => {
            let event_code = if phase == "admission" {
                event_codes::ADMISSION_BLOCKED
            } else {
                event_codes::PHASE_BLOCKED
            };
            events.push(gate_event(
                event_code,
                "warn",
                trace_id,
                format!(
                    "phase={phase}: migration gate rejected with {} violation(s)",
                    rejection_reasons.len()
                ),
            ));
            for suggestion in &replan_suggestions {
                events.push(gate_event(
                    event_codes::REPLAN_SUGGESTED,
                    "info",
                    trace_id,
                    format!("phase={phase}: suggested path={}", suggestion.path_id),
                ));
            }
        }
    }

    GateEvaluation {
        phase: phase.to_string(),
        verdict,
        baseline,
        projected,
        delta,
        thresholds,
        rejection_reasons,
        replan_suggestions,
        events,
    }
}

pub fn evaluate_admission(
    trace_id: &str,
    baseline: GraphHealthSnapshot,
    projected: GraphHealthSnapshot,
    thresholds: MigrationGateThresholds,
    candidates: &[MigrationPathCandidate],
) -> GateEvaluation {
    evaluate(
        trace_id,
        "admission",
        baseline,
        projected,
        thresholds,
        candidates,
    )
}

pub fn evaluate_progression_phase(
    trace_id: &str,
    phase_name: &str,
    baseline: GraphHealthSnapshot,
    projected: GraphHealthSnapshot,
    thresholds: MigrationGateThresholds,
    candidates: &[MigrationPathCandidate],
) -> GateEvaluation {
    evaluate(
        trace_id, phase_name, baseline, projected, thresholds, candidates,
    )
}

pub fn build_migration_health_report(
    plan_id: &str,
    evaluation: GateEvaluation,
) -> MigrationHealthReport {
    MigrationHealthReport {
        plan_id: plan_id.to_string(),
        evaluation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> GraphHealthSnapshot {
        GraphHealthSnapshot {
            cascade_risk: 0.21,
            fragility_findings: 4,
            articulation_points: 2,
        }
    }

    #[test]
    fn computes_health_delta() {
        let projected = GraphHealthSnapshot {
            cascade_risk: 0.33,
            fragility_findings: 6,
            articulation_points: 3,
        };

        let delta = HealthDelta::between(baseline(), projected);
        assert!((delta.cascade_risk_delta - 0.12).abs() < 1e-9);
        assert_eq!(delta.new_fragility_findings, 2);
        assert_eq!(delta.new_articulation_points, 1);
    }

    #[test]
    fn allows_admission_within_thresholds() {
        let projected = GraphHealthSnapshot {
            cascade_risk: 0.28,
            fragility_findings: 5,
            articulation_points: 3,
        };
        let evaluation = evaluate_admission(
            "trace-allow",
            baseline(),
            projected,
            MigrationGateThresholds::default(),
            &[],
        );
        assert_eq!(evaluation.verdict, GateVerdict::Allow);
        assert!(evaluation.rejection_reasons.is_empty());
        assert!(
            evaluation
                .events
                .iter()
                .any(|event| event.code == event_codes::ADMISSION_ALLOWED)
        );
    }

    #[test]
    fn blocks_when_thresholds_violated_without_replan() {
        let projected = GraphHealthSnapshot {
            cascade_risk: 0.55,
            fragility_findings: 9,
            articulation_points: 7,
        };
        let evaluation = evaluate_admission(
            "trace-block",
            baseline(),
            projected,
            MigrationGateThresholds::default(),
            &[],
        );
        assert_eq!(evaluation.verdict, GateVerdict::Block);
        assert_eq!(evaluation.rejection_reasons.len(), 3);
        assert!(evaluation.replan_suggestions.is_empty());
    }

    #[test]
    fn suggests_replan_when_lower_risk_path_exists() {
        let projected = GraphHealthSnapshot {
            cascade_risk: 0.45,
            fragility_findings: 8,
            articulation_points: 6,
        };
        let candidates = vec![
            MigrationPathCandidate {
                path_id: "path-a".to_string(),
                projected: GraphHealthSnapshot {
                    cascade_risk: 0.26,
                    fragility_findings: 5,
                    articulation_points: 2,
                },
                notes: "stage patch first".to_string(),
            },
            MigrationPathCandidate {
                path_id: "path-b".to_string(),
                projected: GraphHealthSnapshot {
                    cascade_risk: 0.41,
                    fragility_findings: 8,
                    articulation_points: 5,
                },
                notes: "delay edge component".to_string(),
            },
        ];
        let evaluation = evaluate_admission(
            "trace-replan",
            baseline(),
            projected,
            MigrationGateThresholds::default(),
            &candidates,
        );
        assert_eq!(evaluation.verdict, GateVerdict::ReplanRequired);
        assert!(!evaluation.replan_suggestions.is_empty());
        assert_eq!(evaluation.replan_suggestions[0].path_id, "path-a");
        assert!(
            evaluation
                .events
                .iter()
                .any(|event| event.code == event_codes::REPLAN_SUGGESTED)
        );
    }

    #[test]
    fn progression_phase_reports_phase_specific_event_code() {
        let evaluation = evaluate_progression_phase(
            "trace-phase",
            "phase-canary",
            baseline(),
            GraphHealthSnapshot {
                cascade_risk: 0.29,
                fragility_findings: 5,
                articulation_points: 3,
            },
            MigrationGateThresholds::default(),
            &[],
        );
        assert_eq!(evaluation.phase, "phase-canary");
        assert_eq!(evaluation.verdict, GateVerdict::Allow);
        assert!(
            evaluation
                .events
                .iter()
                .any(|event| event.code == event_codes::PHASE_ALLOWED)
        );
    }

    #[test]
    fn replan_suggestions_are_deterministic() {
        let candidates = vec![
            MigrationPathCandidate {
                path_id: "path-z".to_string(),
                projected: GraphHealthSnapshot {
                    cascade_risk: 0.36,
                    fragility_findings: 6,
                    articulation_points: 5,
                },
                notes: "z".to_string(),
            },
            MigrationPathCandidate {
                path_id: "path-a".to_string(),
                projected: GraphHealthSnapshot {
                    cascade_risk: 0.31,
                    fragility_findings: 5,
                    articulation_points: 3,
                },
                notes: "a".to_string(),
            },
        ];
        let blocked_delta = HealthDelta {
            cascade_risk_delta: 0.25,
            new_fragility_findings: 6,
            new_articulation_points: 4,
        };
        let first = suggest_replans(
            baseline(),
            blocked_delta,
            &candidates,
            MigrationGateThresholds::default(),
        );
        let second = suggest_replans(
            baseline(),
            blocked_delta,
            &candidates,
            MigrationGateThresholds::default(),
        );
        assert_eq!(first, second);
        assert_eq!(first[0].path_id, "path-a");
    }

    #[test]
    fn health_report_wraps_evaluation() {
        let evaluation = evaluate_admission(
            "trace-report",
            baseline(),
            GraphHealthSnapshot {
                cascade_risk: 0.28,
                fragility_findings: 5,
                articulation_points: 3,
            },
            MigrationGateThresholds::default(),
            &[],
        );
        let report = build_migration_health_report("plan-42", evaluation.clone());
        assert_eq!(report.plan_id, "plan-42");
        assert_eq!(report.evaluation, evaluation);
    }
}
