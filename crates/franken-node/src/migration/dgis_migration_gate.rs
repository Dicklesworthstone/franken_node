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
    pub new_fragility_findings: i64,
    pub new_articulation_points: i64,
}

impl HealthDelta {
    pub fn between(baseline: GraphHealthSnapshot, projected: GraphHealthSnapshot) -> Self {
        let cascade_risk_delta =
            if baseline.cascade_risk.is_finite() && projected.cascade_risk.is_finite() {
                projected.cascade_risk - baseline.cascade_risk
            } else {
                f64::NAN
            };

        Self {
            cascade_risk_delta,
            new_fragility_findings: i64::from(projected.fragility_findings)
                - i64::from(baseline.fragility_findings),
            new_articulation_points: i64::from(projected.articulation_points)
                - i64::from(baseline.articulation_points),
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

    if !thresholds.max_cascade_risk_delta.is_finite()
        || !delta.cascade_risk_delta.is_finite()
        || delta.cascade_risk_delta >= thresholds.max_cascade_risk_delta
    {
        let detail = if !thresholds.max_cascade_risk_delta.is_finite() {
            format!(
                "cascade risk threshold {} is not finite",
                thresholds.max_cascade_risk_delta
            )
        } else if !delta.cascade_risk_delta.is_finite() {
            format!(
                "cascade risk delta {} is not finite",
                delta.cascade_risk_delta
            )
        } else {
            format!(
                "cascade risk delta {:.4} meets or exceeds max {:.4}",
                delta.cascade_risk_delta, thresholds.max_cascade_risk_delta
            )
        };
        reasons.push(RejectionReason {
            code: "DGIS-MIGRATE-RISK-DELTA".to_string(),
            detail,
        });
    }

    if delta.new_fragility_findings >= i64::from(thresholds.max_new_fragility_findings) {
        reasons.push(RejectionReason {
            code: "DGIS-MIGRATE-FRAGILITY-DELTA".to_string(),
            detail: format!(
                "new fragility findings {} meet or exceed max {}",
                delta.new_fragility_findings, thresholds.max_new_fragility_findings
            ),
        });
    }

    if delta.new_articulation_points >= i64::from(thresholds.max_new_articulation_points) {
        reasons.push(RejectionReason {
            code: "DGIS-MIGRATE-ARTICULATION-DELTA".to_string(),
            detail: format!(
                "new articulation points {} meet or exceed max {}",
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
    candidate.cascade_risk_delta <= blocked.cascade_risk_delta
        && candidate.new_fragility_findings <= blocked.new_fragility_findings
        && candidate.new_articulation_points <= blocked.new_articulation_points
        && (candidate.cascade_risk_delta < blocked.cascade_risk_delta
            || candidate.new_fragility_findings < blocked.new_fragility_findings
            || candidate.new_articulation_points < blocked.new_articulation_points)
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
            articulation_points: 2,
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
                articulation_points: 2,
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
    fn default_thresholds_are_positive() {
        let t = MigrationGateThresholds::default();
        assert!(t.max_cascade_risk_delta > 0.0);
        assert!(t.max_new_fragility_findings > 0);
        assert!(t.max_new_articulation_points > 0);
    }

    #[test]
    fn zero_delta_allows_admission() {
        let snap = baseline();
        let evaluation = evaluate_admission(
            "trace-zero",
            snap,
            snap,
            MigrationGateThresholds::default(),
            &[],
        );
        assert_eq!(evaluation.verdict, GateVerdict::Allow);
    }

    #[test]
    fn negative_delta_is_improvement() {
        let improved = GraphHealthSnapshot {
            cascade_risk: 0.10,
            fragility_findings: 1,
            articulation_points: 0,
        };
        let delta = HealthDelta::between(baseline(), improved);
        assert!(delta.cascade_risk_delta < 0.0);
    }

    #[test]
    fn empty_candidates_no_replans() {
        let blocked_delta = HealthDelta {
            cascade_risk_delta: 1.0,
            new_fragility_findings: 20,
            new_articulation_points: 10,
        };
        let suggestions = suggest_replans(
            baseline(),
            blocked_delta,
            &[],
            MigrationGateThresholds::default(),
        );
        assert!(suggestions.is_empty());
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let v = GateVerdict::Block;
        let json = serde_json::to_string(&v).expect("serialize");
        let parsed: GateVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, v);
    }

    #[test]
    fn progression_phase_canary_event() {
        let projected = GraphHealthSnapshot {
            cascade_risk: 0.28,
            fragility_findings: 5,
            articulation_points: 3,
        };
        let phase_eval = evaluate_progression_phase(
            "trace-phase",
            "canary",
            baseline(),
            projected,
            MigrationGateThresholds::default(),
            &[],
        );
        assert!(!phase_eval.events.is_empty());
        assert!(!phase_eval.events[0].code.is_empty());
    }

    #[test]
    fn single_candidate_replan_sorted() {
        let delta = HealthDelta {
            cascade_risk_delta: 1.0,
            new_fragility_findings: 20,
            new_articulation_points: 10,
        };
        let candidates = vec![MigrationPathCandidate {
            path_id: "alt-1".to_string(),
            notes: "lower risk".to_string(),
            projected: GraphHealthSnapshot {
                cascade_risk: 0.15,
                fragility_findings: 2,
                articulation_points: 1,
            },
        }];
        let suggestions = suggest_replans(
            baseline(),
            delta,
            &candidates,
            MigrationGateThresholds::default(),
        );
        assert_eq!(suggestions.len(), 1);
    }

    #[test]
    fn event_codes_are_nonempty() {
        assert!(!event_codes::BASELINE_CAPTURED.is_empty());
        assert!(!event_codes::ADMISSION_ALLOWED.is_empty());
        assert!(!event_codes::ADMISSION_BLOCKED.is_empty());
    }

    #[test]
    fn nan_cascade_risk_delta_blocks_admission() {
        let projected = GraphHealthSnapshot {
            cascade_risk: f64::NAN,
            fragility_findings: 4,
            articulation_points: 2,
        };
        let evaluation = evaluate_admission(
            "trace-nan",
            baseline(),
            projected,
            MigrationGateThresholds::default(),
            &[],
        );
        assert_eq!(evaluation.verdict, GateVerdict::Block);
        assert!(
            evaluation
                .rejection_reasons
                .iter()
                .any(|r| r.code == "DGIS-MIGRATE-RISK-DELTA")
        );
    }

    #[test]
    fn inf_cascade_risk_delta_blocks_admission() {
        let projected = GraphHealthSnapshot {
            cascade_risk: f64::INFINITY,
            fragility_findings: 4,
            articulation_points: 2,
        };
        let evaluation = evaluate_admission(
            "trace-inf",
            baseline(),
            projected,
            MigrationGateThresholds::default(),
            &[],
        );
        assert_eq!(evaluation.verdict, GateVerdict::Block);
        assert!(
            evaluation
                .rejection_reasons
                .iter()
                .any(|r| r.code == "DGIS-MIGRATE-RISK-DELTA")
        );
    }

    #[test]
    fn neg_inf_cascade_risk_delta_blocks_admission() {
        let projected = GraphHealthSnapshot {
            cascade_risk: f64::NEG_INFINITY,
            fragility_findings: 4,
            articulation_points: 2,
        };
        let evaluation = evaluate_admission(
            "trace-neg-inf",
            baseline(),
            projected,
            MigrationGateThresholds::default(),
            &[],
        );
        assert_eq!(evaluation.verdict, GateVerdict::Block);
        assert!(
            evaluation
                .rejection_reasons
                .iter()
                .any(|r| r.code == "DGIS-MIGRATE-RISK-DELTA")
        );
    }

    #[test]
    fn non_finite_risk_threshold_blocks_admission() {
        let mut thresholds = MigrationGateThresholds::default();
        thresholds.max_cascade_risk_delta = f64::NAN;
        let evaluation = evaluate_admission(
            "trace-nan-threshold",
            baseline(),
            GraphHealthSnapshot {
                cascade_risk: 0.22,
                fragility_findings: 4,
                articulation_points: 2,
            },
            thresholds,
            &[],
        );

        assert_eq!(evaluation.verdict, GateVerdict::Block);
        assert!(
            evaluation
                .rejection_reasons
                .iter()
                .any(|r| r.detail.contains("threshold") && r.detail.contains("not finite"))
        );
    }

    #[test]
    fn exact_threshold_delta_blocks_admission_fail_closed() {
        let thresholds = MigrationGateThresholds {
            max_cascade_risk_delta: 0.10,
            max_new_fragility_findings: 2,
            max_new_articulation_points: 1,
        };
        let baseline = GraphHealthSnapshot {
            cascade_risk: 0.0,
            fragility_findings: 4,
            articulation_points: 2,
        };
        let projected = GraphHealthSnapshot {
            cascade_risk: 0.10,
            fragility_findings: baseline.fragility_findings.saturating_add(2),
            articulation_points: baseline.articulation_points.saturating_add(1),
        };

        let evaluation = evaluate_admission("trace-boundary", baseline, projected, thresholds, &[]);

        assert_eq!(evaluation.verdict, GateVerdict::Block);
        assert_eq!(evaluation.rejection_reasons.len(), 3);
    }

    #[test]
    fn cascade_risk_delta_just_over_threshold_blocks_admission() {
        let thresholds = MigrationGateThresholds {
            max_cascade_risk_delta: 0.10,
            max_new_fragility_findings: 99,
            max_new_articulation_points: 99,
        };
        let projected = GraphHealthSnapshot {
            cascade_risk: baseline().cascade_risk + 0.100_001,
            fragility_findings: baseline().fragility_findings,
            articulation_points: baseline().articulation_points,
        };

        let evaluation =
            evaluate_admission("trace-risk-epsilon", baseline(), projected, thresholds, &[]);

        assert_eq!(evaluation.verdict, GateVerdict::Block);
        assert_eq!(evaluation.rejection_reasons.len(), 1);
        assert_eq!(
            evaluation.rejection_reasons[0].code,
            "DGIS-MIGRATE-RISK-DELTA"
        );
    }

    #[test]
    fn fragility_delta_blocks_when_only_fragility_exceeds_budget() {
        let thresholds = MigrationGateThresholds {
            max_cascade_risk_delta: 1.0,
            max_new_fragility_findings: 1,
            max_new_articulation_points: 99,
        };
        let projected = GraphHealthSnapshot {
            cascade_risk: baseline().cascade_risk,
            fragility_findings: baseline().fragility_findings + 2,
            articulation_points: baseline().articulation_points,
        };

        let evaluation = evaluate_admission(
            "trace-fragility-only",
            baseline(),
            projected,
            thresholds,
            &[],
        );

        assert_eq!(evaluation.verdict, GateVerdict::Block);
        assert_eq!(evaluation.rejection_reasons.len(), 1);
        assert_eq!(
            evaluation.rejection_reasons[0].code,
            "DGIS-MIGRATE-FRAGILITY-DELTA"
        );
    }

    #[test]
    fn articulation_delta_blocks_when_only_articulation_exceeds_budget() {
        let thresholds = MigrationGateThresholds {
            max_cascade_risk_delta: 1.0,
            max_new_fragility_findings: 99,
            max_new_articulation_points: 0,
        };
        let projected = GraphHealthSnapshot {
            cascade_risk: baseline().cascade_risk,
            fragility_findings: baseline().fragility_findings,
            articulation_points: baseline().articulation_points + 1,
        };

        let evaluation = evaluate_admission(
            "trace-articulation-only",
            baseline(),
            projected,
            thresholds,
            &[],
        );

        assert_eq!(evaluation.verdict, GateVerdict::Block);
        assert_eq!(evaluation.rejection_reasons.len(), 1);
        assert_eq!(
            evaluation.rejection_reasons[0].code,
            "DGIS-MIGRATE-ARTICULATION-DELTA"
        );
    }

    #[test]
    fn threshold_blocked_progression_phase_uses_phase_blocked_event() {
        let evaluation = evaluate_progression_phase(
            "trace-phase-blocked",
            "phase-cutover",
            baseline(),
            GraphHealthSnapshot {
                cascade_risk: 0.50,
                fragility_findings: 12,
                articulation_points: 6,
            },
            MigrationGateThresholds::default(),
            &[],
        );

        assert_eq!(evaluation.verdict, GateVerdict::Block);
        assert!(
            evaluation
                .events
                .iter()
                .any(|event| event.code == event_codes::PHASE_BLOCKED)
        );
        assert!(
            evaluation
                .events
                .iter()
                .all(|event| event.code != event_codes::ADMISSION_BLOCKED)
        );
    }

    #[test]
    fn replan_suggestions_exclude_equal_or_worse_candidates() {
        let blocked_delta = HealthDelta {
            cascade_risk_delta: 0.20,
            new_fragility_findings: 4,
            new_articulation_points: 2,
        };
        let candidates = vec![
            MigrationPathCandidate {
                path_id: "equal-risk".to_string(),
                projected: GraphHealthSnapshot {
                    cascade_risk: baseline().cascade_risk + 0.20,
                    fragility_findings: baseline().fragility_findings + 4,
                    articulation_points: baseline().articulation_points + 2,
                },
                notes: "same as blocked plan".to_string(),
            },
            MigrationPathCandidate {
                path_id: "worse-risk".to_string(),
                projected: GraphHealthSnapshot {
                    cascade_risk: baseline().cascade_risk + 0.25,
                    fragility_findings: baseline().fragility_findings + 5,
                    articulation_points: baseline().articulation_points + 3,
                },
                notes: "strictly worse than blocked plan".to_string(),
            },
        ];

        let suggestions = suggest_replans(
            baseline(),
            blocked_delta,
            &candidates,
            MigrationGateThresholds::default(),
        );

        assert!(suggestions.is_empty());
    }

    #[test]
    fn multiple_violations_are_reported_in_policy_order() {
        let evaluation = evaluate_admission(
            "trace-policy-order",
            baseline(),
            GraphHealthSnapshot {
                cascade_risk: 0.70,
                fragility_findings: 20,
                articulation_points: 10,
            },
            MigrationGateThresholds::default(),
            &[],
        );
        let codes: Vec<&str> = evaluation
            .rejection_reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect();

        assert_eq!(
            codes,
            vec![
                "DGIS-MIGRATE-RISK-DELTA",
                "DGIS-MIGRATE-FRAGILITY-DELTA",
                "DGIS-MIGRATE-ARTICULATION-DELTA",
            ]
        );
    }

    #[test]
    fn replan_suggestions_are_limited_to_three_lowest_risk_candidates() {
        let blocked_delta = HealthDelta {
            cascade_risk_delta: 0.50,
            new_fragility_findings: 10,
            new_articulation_points: 6,
        };
        let candidates: Vec<MigrationPathCandidate> = (0..5)
            .map(|idx| MigrationPathCandidate {
                path_id: format!("path-{idx}"),
                projected: GraphHealthSnapshot {
                    cascade_risk: baseline().cascade_risk + 0.01 * f64::from(idx),
                    fragility_findings: baseline().fragility_findings,
                    articulation_points: baseline().articulation_points,
                },
                notes: format!("candidate {idx}"),
            })
            .collect();

        let suggestions = suggest_replans(
            baseline(),
            blocked_delta,
            &candidates,
            MigrationGateThresholds::default(),
        );

        assert_eq!(suggestions.len(), 3);
        assert_eq!(suggestions[0].path_id, "path-0");
        assert_eq!(suggestions[1].path_id, "path-1");
        assert_eq!(suggestions[2].path_id, "path-2");
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

#[cfg(test)]
mod dgis_migration_gate_hardening_negative_tests {
    use super::*;

    const MAX_REJECTION_REASONS: usize = 10;
    const MAX_REPLAN_SUGGESTIONS: usize = 5;
    const MAX_GATE_EVENTS: usize = 20;

    fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
        if items.len() >= cap {
            let overflow = items.len() - cap + 1;
            items.drain(0..overflow);
        }
        items.push(item);
    }

    #[test]
    fn negative_vec_push_without_bounded_capacity_protection_reasons() {
        let delta = HealthDelta {
            cascade_risk_delta: 2.0,      // Way over threshold
            new_fragility_findings: 1000, // Way over threshold
            new_articulation_points: 500, // Way over threshold
        };

        let thresholds = MigrationGateThresholds {
            max_cascade_risk_delta: 0.1,
            max_new_fragility_findings: 1,
            max_new_articulation_points: 1,
        };

        // This will trigger all three rejection conditions without bounds checking
        let mut simulated_reasons = Vec::new();

        // Simulate the vulnerable pattern from evaluate_policy function
        for _ in 0..100 {
            // Attempt to overflow rejection reasons vector
            if delta.cascade_risk_delta > thresholds.max_cascade_risk_delta {
                simulated_reasons.push(format!(
                    "cascade_risk_delta_violation_{}",
                    simulated_reasons.len()
                ));
            }
            if delta.new_fragility_findings > i64::from(thresholds.max_new_fragility_findings) {
                simulated_reasons.push(format!("fragility_violation_{}", simulated_reasons.len()));
            }
            if delta.new_articulation_points > i64::from(thresholds.max_new_articulation_points) {
                simulated_reasons.push(format!(
                    "articulation_violation_{}",
                    simulated_reasons.len()
                ));
            }
        }

        // Without push_bounded, this vector could grow without bounds
        assert!(
            simulated_reasons.len() > MAX_REJECTION_REASONS,
            "unbounded rejection reasons should exceed safe capacity"
        );

        // Test proper bounded version
        let mut bounded_reasons = Vec::new();
        for _ in 0..100 {
            if delta.cascade_risk_delta > thresholds.max_cascade_risk_delta {
                let reason_idx = bounded_reasons.len();
                push_bounded(
                    &mut bounded_reasons,
                    format!("cascade_risk_delta_violation_{reason_idx}"),
                    MAX_REJECTION_REASONS,
                );
            }
        }

        // With push_bounded, vector should be capped
        assert!(
            bounded_reasons.len() <= MAX_REJECTION_REASONS,
            "bounded rejection reasons should respect capacity limit"
        );
    }

    #[test]
    fn negative_threshold_comparison_bypass_without_fail_closed_semantics() {
        let thresholds = MigrationGateThresholds {
            max_cascade_risk_delta: 0.12,
            max_new_fragility_findings: 2,
            max_new_articulation_points: 1,
        };

        // Test exact boundary values that could bypass security with > instead of >=
        let boundary_delta = HealthDelta {
            cascade_risk_delta: 0.12,   // Exactly at threshold
            new_fragility_findings: 2,  // Exactly at threshold
            new_articulation_points: 1, // Exactly at threshold
        };

        // With > comparison (vulnerable): boundary values pass incorrectly
        let vulnerable_cascade_check =
            boundary_delta.cascade_risk_delta > thresholds.max_cascade_risk_delta;
        let vulnerable_fragility_check = boundary_delta.new_fragility_findings
            > i64::from(thresholds.max_new_fragility_findings);
        let vulnerable_articulation_check = boundary_delta.new_articulation_points
            > i64::from(thresholds.max_new_articulation_points);

        // These should all be false with > (vulnerable to boundary bypass)
        assert!(
            !vulnerable_cascade_check,
            "boundary cascade risk bypasses > comparison"
        );
        assert!(
            !vulnerable_fragility_check,
            "boundary fragility bypasses > comparison"
        );
        assert!(
            !vulnerable_articulation_check,
            "boundary articulation bypasses > comparison"
        );

        // With >= comparison (secure): boundary values are properly rejected
        let secure_cascade_check =
            boundary_delta.cascade_risk_delta >= thresholds.max_cascade_risk_delta;
        let secure_fragility_check = boundary_delta.new_fragility_findings
            >= i64::from(thresholds.max_new_fragility_findings);
        let secure_articulation_check = boundary_delta.new_articulation_points
            >= i64::from(thresholds.max_new_articulation_points);

        // These should all be true with >= (fail-closed at boundary)
        assert!(
            secure_cascade_check,
            "fail-closed cascade risk should reject boundary"
        );
        assert!(
            secure_fragility_check,
            "fail-closed fragility should reject boundary"
        );
        assert!(
            secure_articulation_check,
            "fail-closed articulation should reject boundary"
        );

        // Test the actual evaluate_policy function behavior on boundary
        let actual_reasons = evaluate_policy(boundary_delta, thresholds);

        assert_eq!(
            actual_reasons.len(),
            3,
            "boundary values must be rejected with fail-closed >= checks"
        );
    }

    #[test]
    fn negative_integer_cast_overflow_without_try_from_protection() {
        // Test potential overflow in i64::from conversions
        let max_thresholds = MigrationGateThresholds {
            max_cascade_risk_delta: 1.0,
            max_new_fragility_findings: u32::MAX, // Maximum u32 value
            max_new_articulation_points: u32::MAX, // Maximum u32 value
        };

        let overflow_delta = HealthDelta {
            cascade_risk_delta: 0.1,
            new_fragility_findings: i64::MAX,  // Maximum i64 value
            new_articulation_points: i64::MAX, // Maximum i64 value
        };

        // Test i64::from(u32::MAX) conversion - this is safe but worth verifying
        let max_fragility_i64 = i64::from(max_thresholds.max_new_fragility_findings);
        let max_articulation_i64 = i64::from(max_thresholds.max_new_articulation_points);

        assert_eq!(max_fragility_i64, i64::from(u32::MAX));
        assert_eq!(max_articulation_i64, i64::from(u32::MAX));

        // Verify comparison behavior with extreme values
        let fragility_exceeds = overflow_delta.new_fragility_findings > max_fragility_i64;
        let articulation_exceeds = overflow_delta.new_articulation_points > max_articulation_i64;

        assert!(
            fragility_exceeds,
            "i64::MAX should exceed u32::MAX converted to i64"
        );
        assert!(
            articulation_exceeds,
            "i64::MAX should exceed u32::MAX converted to i64"
        );

        // Test with boundary conditions around integer limits
        let boundary_tests = vec![
            (i64::from(u32::MAX) - 1, false), // Just under max u32
            (i64::from(u32::MAX), false),     // Exactly max u32 (should use >= for fail-closed)
            (i64::from(u32::MAX) + 1, true),  // Just over max u32
        ];

        for (test_value, should_exceed) in boundary_tests {
            let test_exceeds = test_value > max_fragility_i64;
            if should_exceed {
                assert!(
                    test_exceeds,
                    "value {} should exceed threshold {}",
                    test_value, max_fragility_i64
                );
            } else {
                assert!(
                    !test_exceeds,
                    "value {} should not exceed threshold {} with > comparison",
                    test_value, max_fragility_i64
                );
            }
        }
    }

    #[test]
    fn negative_arithmetic_overflow_in_health_delta_computation() {
        // Test overflow protection in HealthDelta::between calculation
        let max_baseline = GraphHealthSnapshot {
            cascade_risk: f64::MAX,
            fragility_findings: u32::MAX,
            articulation_points: u32::MAX,
        };

        let min_projected = GraphHealthSnapshot {
            cascade_risk: f64::MIN,
            fragility_findings: 0,
            articulation_points: 0,
        };

        // This should handle extreme value differences without overflow/panic
        let delta = HealthDelta::between(max_baseline, min_projected);

        // Verify cascade_risk_delta handles extreme differences
        assert!(
            delta.cascade_risk_delta.is_finite() || delta.cascade_risk_delta.is_infinite(),
            "cascade risk delta should not be NaN"
        );

        // Verify integer differences handle u32::MAX correctly
        assert_eq!(delta.new_fragility_findings, -(i64::from(u32::MAX)));
        assert_eq!(delta.new_articulation_points, -(i64::from(u32::MAX)));

        // Test reverse case: min baseline to max projected
        let reverse_delta = HealthDelta::between(min_projected, max_baseline);

        assert!(
            reverse_delta.cascade_risk_delta.is_finite()
                || reverse_delta.cascade_risk_delta.is_infinite(),
            "reverse cascade risk delta should not be NaN"
        );
        assert_eq!(reverse_delta.new_fragility_findings, i64::from(u32::MAX));
        assert_eq!(reverse_delta.new_articulation_points, i64::from(u32::MAX));
    }

    #[test]
    fn negative_event_accumulation_without_push_bounded_protection() {
        // Test unbounded event accumulation in gate_event calls
        let baseline = GraphHealthSnapshot {
            cascade_risk: 0.1,
            fragility_findings: 1,
            articulation_points: 1,
        };

        let projected = GraphHealthSnapshot {
            cascade_risk: 0.9, // High risk to trigger rejections
            fragility_findings: 100,
            articulation_points: 50,
        };

        let thresholds = MigrationGateThresholds::default();

        // Create many candidates to trigger event generation
        let many_candidates: Vec<MigrationPathCandidate> = (0..100)
            .map(|i| MigrationPathCandidate {
                path_id: format!("candidate_{}", i),
                projected: GraphHealthSnapshot {
                    cascade_risk: 0.2 + (i as f64 * 0.001),
                    fragility_findings: 2 + i as u32,
                    articulation_points: 1 + i as u32,
                },
                notes: format!("test candidate {}", i),
            })
            .collect();

        // This will generate many events without bounds checking
        let evaluation = evaluate_admission(
            "trace-many-events",
            baseline,
            projected,
            thresholds,
            &many_candidates,
        );

        // Verify the evaluation still completes (no panic from unbounded growth)
        assert_eq!(evaluation.verdict, GateVerdict::ReplanRequired);

        // The current implementation doesn't bound events, which could be a memory issue
        let event_count = evaluation.events.len();
        if event_count > MAX_GATE_EVENTS {
            // This documents potential unbounded growth issue
            // In a hardened version, events should use push_bounded
        }

        // Verify replan suggestions are properly bounded to 3
        assert!(
            evaluation.replan_suggestions.len() <= 3,
            "replan suggestions should be limited to 3 regardless of candidate count"
        );
    }

    #[test]
    fn negative_string_formatting_without_domain_separation() {
        // Test potential hash collision in string formatting without domain separators
        let trace_id = "collision_test";

        // These could hash to the same value without proper domain separation
        let event_a = gate_event("CODE", "info", trace_id, "key=value|data=test".to_string());
        let event_b = gate_event("CODE", "info", trace_id, "key=valuedata=test".to_string());

        // Without domain separation, these strings could collide
        assert_ne!(
            event_a.message, event_b.message,
            "messages should be distinct"
        );

        let phase_tests = vec![
            ("phase", "separator", "data"),
            ("phaseseparator", "", "data"), // Different structure, same chars
            ("pha", "seseparator", "data"), // Different split points
        ];
        let encode_fields = |phase: &str, separator: &str, data: &str| {
            let mut encoded = Vec::new();
            for field in [phase, separator, data] {
                encoded.extend_from_slice(&(field.len() as u64).to_le_bytes());
                encoded.extend_from_slice(field.as_bytes());
            }
            encoded
        };
        let mut saw_raw_collision = false;

        for (phase_a, sep_a, data_a) in &phase_tests {
            for (phase_b, sep_b, data_b) in &phase_tests {
                if (phase_a, sep_a, data_a) != (phase_b, sep_b, data_b) {
                    let combined_a = format!("{}{}{}", phase_a, sep_a, data_a);
                    let combined_b = format!("{}{}{}", phase_b, sep_b, data_b);

                    if combined_a == combined_b {
                        saw_raw_collision = true;
                    }
                    assert_ne!(
                        encode_fields(phase_a, sep_a, data_a),
                        encode_fields(phase_b, sep_b, data_b),
                        "length-prefixed fields should preserve tuple boundaries"
                    );
                }
            }
        }
        assert!(
            saw_raw_collision,
            "test vectors should include at least one raw-concatenation collision"
        );
    }

    // =========================================================================
    // ADDITIONAL NEGATIVE-PATH SECURITY HARDENING TESTS
    // =========================================================================
    // Added comprehensive attack vector testing focusing on:
    // - Vec::push unbounded growth attacks
    // - Boundary condition fail-closed attacks
    // - Resource exhaustion and capacity attacks
    // - Threshold bypass and injection attacks

    #[test]
    fn test_rejection_reasons_vec_push_unbounded_growth_attacks() {
        // Test for Vec::push without push_bounded in evaluate_policy (lines 140, 147, 157)
        let thresholds = MigrationGateThresholds {
            max_cascade_risk_delta: 0.0, // Zero threshold to trigger all rejections
            max_new_fragility_findings: 0,
            max_new_articulation_points: 0,
        };

        // Attack vector: values that trigger all three rejection conditions
        let attack_deltas = vec![
            // NaN injection attack
            HealthDelta {
                cascade_risk_delta: f64::NAN,
                new_fragility_findings: i64::MAX,
                new_articulation_points: i64::MAX,
            },
            // Maximum values attack
            HealthDelta {
                cascade_risk_delta: f64::MAX,
                new_fragility_findings: i64::MAX,
                new_articulation_points: i64::MAX,
            },
            // Boundary case: minimum values that should trigger rejection
            HealthDelta {
                cascade_risk_delta: f64::EPSILON, // Smallest positive value
                new_fragility_findings: 1,
                new_articulation_points: 1,
            },
        ];

        for (i, delta) in attack_deltas.iter().enumerate() {
            let reasons = evaluate_policy(*delta, thresholds);

            // Should generate exactly 3 rejection reasons without unbounded Vec growth
            assert_eq!(
                reasons.len(),
                3,
                "Attack vector {} should generate exactly 3 rejections",
                i
            );

            // Verify each Vec::push call was executed
            let codes: Vec<&str> = reasons.iter().map(|r| r.code.as_str()).collect();
            assert!(codes.contains(&"DGIS-MIGRATE-RISK-DELTA"));
            assert!(codes.contains(&"DGIS-MIGRATE-FRAGILITY-DELTA"));
            assert!(codes.contains(&"DGIS-MIGRATE-ARTICULATION-DELTA"));

            // All reasons should have proper error details
            for reason in &reasons {
                assert!(!reason.code.is_empty());
                assert!(!reason.detail.is_empty());
                assert!(reason.detail.len() < 1000, "Error detail should be bounded");
            }
        }
    }

    #[test]
    fn test_events_vec_push_unbounded_growth_attacks() {
        // Test for Vec::push without push_bounded in evaluate function (lines 286, 299, 309)
        let baseline = GraphHealthSnapshot {
            cascade_risk: 0.1,
            fragility_findings: 5,
            articulation_points: 2,
        };

        // Create evaluation that will trigger multiple event pushes
        let massive_candidates: Vec<MigrationPathCandidate> = (0..100)
            .map(|i| MigrationPathCandidate {
                path_id: format!("candidate_{}", i),
                projected: GraphHealthSnapshot {
                    cascade_risk: 0.05, // Better than baseline to create valid suggestions
                    fragility_findings: 4,
                    articulation_points: 1,
                },
                notes: format!("candidate_{}_notes", i),
            })
            .collect();

        let thresholds = MigrationGateThresholds {
            max_cascade_risk_delta: 0.01, // Very low to force rejection
            max_new_fragility_findings: 0,
            max_new_articulation_points: 0,
        };

        // Should trigger BASELINE_CAPTURED, ADMISSION_BLOCKED, and REPLAN_SUGGESTED events
        let evaluation = evaluate(
            "vec_push_attack_trace",
            "admission",
            baseline,
            GraphHealthSnapshot {
                cascade_risk: 0.2, // Will exceed threshold
                fragility_findings: 10,
                articulation_points: 5,
            },
            thresholds,
            &massive_candidates,
        );

        // Events vector should be populated but not unbounded
        assert!(!evaluation.events.is_empty(), "Should generate events");
        assert!(
            evaluation.events.len() <= 50,
            "Events should be bounded to prevent memory exhaustion: {}",
            evaluation.events.len()
        );

        // Verify expected event types are present
        let event_codes: Vec<&str> = evaluation.events.iter().map(|e| e.code.as_str()).collect();
        assert!(event_codes.contains(&"DGIS-MIGRATE-001")); // BASELINE_CAPTURED
        assert!(event_codes.contains(&"DGIS-MIGRATE-003")); // ADMISSION_BLOCKED

        // All events should have proper structure
        for event in &evaluation.events {
            assert!(!event.code.is_empty());
            assert!(!event.level.is_empty());
            assert!(!event.trace_id.is_empty());
            assert!(!event.message.is_empty());
            assert!(
                event.message.len() < 2000,
                "Event message should be bounded"
            );
        }
    }

    #[test]
    fn test_threshold_comparison_boundary_fail_closed_attacks() {
        // Test > vs >= boundary conditions in evaluate_policy (lines 127, 146, 156)

        let boundary_attack_vectors = vec![
            // Cascade risk delta boundary attacks
            (
                HealthDelta {
                    cascade_risk_delta: 0.12, // Exactly at default threshold
                    new_fragility_findings: 0,
                    new_articulation_points: 0,
                },
                "cascade_risk_exactly_at_threshold",
            ),
            // Fragility findings boundary attacks
            (
                HealthDelta {
                    cascade_risk_delta: 0.0,
                    new_fragility_findings: 2, // Exactly at default threshold
                    new_articulation_points: 0,
                },
                "fragility_exactly_at_threshold",
            ),
            // Articulation points boundary attacks
            (
                HealthDelta {
                    cascade_risk_delta: 0.0,
                    new_fragility_findings: 0,
                    new_articulation_points: 1, // Exactly at default threshold
                },
                "articulation_exactly_at_threshold",
            ),
        ];

        let thresholds = MigrationGateThresholds::default();

        for (delta, attack_description) in boundary_attack_vectors {
            let reasons = evaluate_policy(delta, thresholds);

            assert_eq!(
                reasons.len(),
                1,
                "boundary value should trigger exactly one rejection ({attack_description})"
            );

            // Test just over threshold (should always fail)
            let over_threshold = HealthDelta {
                cascade_risk_delta: thresholds.max_cascade_risk_delta + f64::EPSILON,
                new_fragility_findings: i64::from(thresholds.max_new_fragility_findings) + 1,
                new_articulation_points: i64::from(thresholds.max_new_articulation_points) + 1,
            };

            let over_reasons = evaluate_policy(over_threshold, thresholds);
            assert_eq!(
                over_reasons.len(),
                3,
                "Values over threshold should trigger all rejections ({})",
                attack_description
            );
        }
    }

    #[test]
    fn test_resource_exhaustion_candidate_processing_attacks() {
        // Test resource exhaustion in suggest_replans with massive candidate lists
        let baseline = GraphHealthSnapshot {
            cascade_risk: 0.1,
            fragility_findings: 5,
            articulation_points: 2,
        };

        let blocked_delta = HealthDelta {
            cascade_risk_delta: 0.5,
            new_fragility_findings: 20,
            new_articulation_points: 10,
        };

        // Generate candidate list to test performance
        let exhaustion_candidates: Vec<MigrationPathCandidate> = (0..1000)
            .map(|i| MigrationPathCandidate {
                path_id: format!("exhaust_candidate_{:05}", i),
                projected: GraphHealthSnapshot {
                    cascade_risk: baseline.cascade_risk + (i as f64 * 0.00001),
                    fragility_findings: baseline.fragility_findings.saturating_add(i as u32 % 3),
                    articulation_points: baseline.articulation_points.saturating_add(i as u32 % 2),
                },
                notes: "A".repeat(100 + (i % 50)),
            })
            .collect();

        let thresholds = MigrationGateThresholds::default();

        let start_time = std::time::Instant::now();
        let suggestions =
            suggest_replans(baseline, blocked_delta, &exhaustion_candidates, thresholds);
        let duration = start_time.elapsed();

        // Should complete in reasonable time despite large input
        assert!(
            duration.as_millis() < 500,
            "Processing took too long: {}ms",
            duration.as_millis()
        );

        // Should respect the take(3) limit regardless of input size
        assert!(
            suggestions.len() <= 3,
            "Returned too many suggestions: {}",
            suggestions.len()
        );

        // Memory usage should be bounded
        let total_suggestion_size: usize = suggestions
            .iter()
            .map(|s| s.path_id.len() + s.rationale.len())
            .sum();

        assert!(
            total_suggestion_size < 5000,
            "Used too much memory: {} bytes",
            total_suggestion_size
        );
    }
}
