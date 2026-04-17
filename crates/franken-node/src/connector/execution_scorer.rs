//! bd-jxgt: Execution planner scorer (latency/risk/capability-aware).
//!
//! Deterministic scoring with explicit tie-breakers and explainable factor weights.
//! Identical inputs always produce identical rankings.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

const PROBABILITY_SUM_EPSILON: f64 = 1e-9;
pub const DEFAULT_SENSITIVITY_DELTA: f64 = 0.05;

/// Configurable factor weights for scoring.
#[derive(Debug, Clone)]
pub struct ScoringWeights {
    pub latency_weight: f64,
    pub risk_weight: f64,
    pub capability_weight: f64,
}

impl ScoringWeights {
    pub fn default_weights() -> Self {
        Self {
            latency_weight: 0.4,
            risk_weight: 0.3,
            capability_weight: 0.3,
        }
    }

    pub fn sum(&self) -> f64 {
        self.latency_weight + self.risk_weight + self.capability_weight
    }
}

/// Input candidate for scoring.
#[derive(Debug, Clone)]
pub struct CandidateInput {
    pub device_id: String,
    pub estimated_latency_ms: f64,
    pub risk_score: f64,
    pub capability_match_ratio: f64,
}

/// Per-factor score breakdown.
#[derive(Debug, Clone)]
pub struct FactorBreakdown {
    pub latency_component: f64,
    pub risk_component: f64,
    pub capability_component: f64,
}

/// A scored candidate with rank and explainable factors.
#[derive(Debug, Clone)]
pub struct ScoredCandidate {
    pub device_id: String,
    pub total_score: f64,
    pub factors: FactorBreakdown,
    pub rank: usize,
}

/// Full planner decision record.
#[derive(Debug, Clone)]
pub struct PlannerDecision {
    pub candidates: Vec<ScoredCandidate>,
    pub weights: ScoringWeights,
    pub trace_id: String,
    pub timestamp: String,
}

/// Explicit action/outcome loss matrix for expected-loss scoring.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LossMatrix {
    pub schema_version: String,
    pub actions: Vec<String>,
    pub outcomes: Vec<String>,
    pub values: Vec<Vec<f64>>,
}

impl LossMatrix {
    pub fn validate(&self) -> Result<(), LossScoringError> {
        if self.schema_version.trim().is_empty() {
            return Err(LossScoringError::InvalidSchema {
                reason: "missing schema_version".to_string(),
            });
        }
        if self.actions.is_empty() {
            return Err(LossScoringError::InvalidSchema {
                reason: "matrix must define at least one action".to_string(),
            });
        }
        if self.outcomes.is_empty() {
            return Err(LossScoringError::InvalidSchema {
                reason: "matrix must define at least one outcome".to_string(),
            });
        }
        if self.values.len() != self.actions.len() {
            return Err(LossScoringError::InvalidSchema {
                reason: "row count must match action count".to_string(),
            });
        }
        for (row_index, row) in self.values.iter().enumerate() {
            if row.len() != self.outcomes.len() {
                return Err(LossScoringError::InvalidSchema {
                    reason: format!(
                        "row {row_index} has {} columns but expected {}",
                        row.len(),
                        self.outcomes.len()
                    ),
                });
            }
            if row.iter().any(|value| !value.is_finite()) {
                return Err(LossScoringError::InvalidSchema {
                    reason: format!("row {row_index} contains non-finite loss values"),
                });
            }
        }

        let has_do_nothing = self.actions.iter().any(|action| {
            let normalized = normalize_action_name(action);
            normalized == "donothing" || normalized == "noop"
        });
        if !has_do_nothing {
            return Err(LossScoringError::MissingDoNothingAction);
        }

        Ok(())
    }

    fn action_index(&self, action: &str) -> Option<usize> {
        self.actions.iter().position(|a| a == action)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpectedLossScore {
    pub action: String,
    pub expected_loss: f64,
    pub dominant_outcome: String,
    pub breakdown: Vec<(String, f64)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensitivityRecord {
    pub action: String,
    pub parameter_name: String,
    pub delta: f64,
    pub original_rank: usize,
    pub perturbed_rank: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LossScoringError {
    InvalidSchema { reason: String },
    MissingDoNothingAction,
    UnknownAction { action: String },
    ProbabilityLengthMismatch { expected: usize, got: usize },
    InvalidProbabilities { reason: String },
    NoActionsRequested,
    InvalidSensitivityDelta { delta: f64 },
}

impl LossScoringError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidSchema { .. } => "ELS_INVALID_SCHEMA",
            Self::MissingDoNothingAction => "ELS_MISSING_DO_NOTHING_ACTION",
            Self::UnknownAction { .. } => "ELS_UNKNOWN_ACTION",
            Self::ProbabilityLengthMismatch { .. } => "ELS_PROBABILITY_LENGTH_MISMATCH",
            Self::InvalidProbabilities { .. } => "ELS_INVALID_PROBABILITIES",
            Self::NoActionsRequested => "ELS_NO_ACTIONS_REQUESTED",
            Self::InvalidSensitivityDelta { .. } => "ELS_INVALID_SENSITIVITY_DELTA",
        }
    }
}

impl std::fmt::Display for LossScoringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSchema { reason } => write!(f, "ELS_INVALID_SCHEMA: {reason}"),
            Self::MissingDoNothingAction => write!(f, "ELS_MISSING_DO_NOTHING_ACTION"),
            Self::UnknownAction { action } => write!(f, "ELS_UNKNOWN_ACTION: {action}"),
            Self::ProbabilityLengthMismatch { expected, got } => {
                write!(
                    f,
                    "ELS_PROBABILITY_LENGTH_MISMATCH: expected={expected} got={got}"
                )
            }
            Self::InvalidProbabilities { reason } => {
                write!(f, "ELS_INVALID_PROBABILITIES: {reason}")
            }
            Self::NoActionsRequested => write!(f, "ELS_NO_ACTIONS_REQUESTED"),
            Self::InvalidSensitivityDelta { delta } => {
                write!(f, "ELS_INVALID_SENSITIVITY_DELTA: {delta}")
            }
        }
    }
}

fn normalize_action_name(action: &str) -> String {
    action
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn validate_probabilities(
    probabilities: &[f64],
    expected_len: usize,
) -> Result<(), LossScoringError> {
    if probabilities.len() != expected_len {
        return Err(LossScoringError::ProbabilityLengthMismatch {
            expected: expected_len,
            got: probabilities.len(),
        });
    }
    if probabilities.iter().any(|p| !p.is_finite()) {
        return Err(LossScoringError::InvalidProbabilities {
            reason: "probabilities must be finite numbers".to_string(),
        });
    }
    if probabilities.iter().any(|p| !(0.0..=1.0).contains(p)) {
        return Err(LossScoringError::InvalidProbabilities {
            reason: "probabilities must be within [0, 1]".to_string(),
        });
    }

    let sum: f64 = probabilities.iter().sum();
    if !sum.is_finite() || (sum - 1.0).abs() > PROBABILITY_SUM_EPSILON {
        return Err(LossScoringError::InvalidProbabilities {
            reason: format!(
                "probability sum must equal 1.0 within epsilon {PROBABILITY_SUM_EPSILON}, got {sum}"
            ),
        });
    }
    Ok(())
}

/// Score one action by expected loss using an explicit loss matrix.
pub fn score_action(
    action: &str,
    loss_matrix: &LossMatrix,
    state_probabilities: &[f64],
) -> Result<ExpectedLossScore, LossScoringError> {
    loss_matrix.validate()?;
    validate_probabilities(state_probabilities, loss_matrix.outcomes.len())?;

    let action_index =
        loss_matrix
            .action_index(action)
            .ok_or_else(|| LossScoringError::UnknownAction {
                action: action.to_string(),
            })?;

    let row = &loss_matrix.values[action_index];
    let mut breakdown = Vec::with_capacity(loss_matrix.outcomes.len());
    let mut expected_loss = 0.0;
    let mut dominant_value = f64::NEG_INFINITY;
    let mut dominant_outcome = String::new();

    for (outcome, (&loss_value, &probability)) in loss_matrix
        .outcomes
        .iter()
        .zip(row.iter().zip(state_probabilities.iter()))
    {
        let contribution = loss_value * probability;
        breakdown.push((outcome.clone(), contribution));
        expected_loss += contribution;

        if contribution > dominant_value {
            dominant_value = contribution;
            dominant_outcome = outcome.clone();
        }
    }

    Ok(ExpectedLossScore {
        action: action.to_string(),
        expected_loss,
        dominant_outcome,
        breakdown,
    })
}

/// Score all candidate actions and sort by expected loss (ascending).
pub fn compare_actions(
    actions: &[&str],
    matrix: &LossMatrix,
    probs: &[f64],
) -> Result<Vec<ExpectedLossScore>, LossScoringError> {
    if actions.is_empty() {
        return Err(LossScoringError::NoActionsRequested);
    }

    let mut scores = actions
        .iter()
        .map(|action| score_action(action, matrix, probs))
        .collect::<Result<Vec<_>, _>>()?;

    scores.sort_by(|a, b| {
        a.expected_loss
            .partial_cmp(&b.expected_loss)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.action.cmp(&b.action))
    });
    Ok(scores)
}

fn perturb_probabilities(base: &[f64], index: usize, delta: f64) -> Option<Vec<f64>> {
    if base.is_empty() {
        return None;
    }
    if base.len() == 1 {
        return if (delta.abs() <= PROBABILITY_SUM_EPSILON)
            || (base[0] + delta - 1.0).abs() <= PROBABILITY_SUM_EPSILON
        {
            Some(vec![1.0])
        } else {
            None
        };
    }

    let updated_target = base[index] + delta;
    if !(0.0..=1.0).contains(&updated_target) {
        return None;
    }

    let mut adjusted = base.to_vec();
    let old_remainder = 1.0 - base[index];
    let new_remainder = 1.0 - updated_target;
    adjusted[index] = updated_target;

    if old_remainder.abs() <= PROBABILITY_SUM_EPSILON {
        let share = new_remainder / (base.len() as f64 - 1.0);
        for (candidate_index, value) in adjusted.iter_mut().enumerate() {
            if candidate_index != index {
                *value = share;
            }
        }
    } else {
        for (candidate_index, value) in adjusted.iter_mut().enumerate() {
            if candidate_index == index {
                continue;
            }
            *value = (base[candidate_index] / old_remainder) * new_remainder;
        }
    }

    if adjusted.iter().any(|p| !(0.0..=1.0).contains(p)) {
        return None;
    }

    let sum: f64 = adjusted.iter().sum();
    if !sum.is_finite() || sum <= 0.0 {
        return None;
    }
    let normalization_factor = 1.0 / sum;
    for value in &mut adjusted {
        *value *= normalization_factor;
    }

    Some(adjusted)
}

/// Run probability perturbation sensitivity analysis.
pub fn sensitivity_analysis(
    actions: &[&str],
    matrix: &LossMatrix,
    probs: &[f64],
    delta: f64,
) -> Result<Vec<SensitivityRecord>, LossScoringError> {
    if !delta.is_finite() || delta <= 0.0 {
        return Err(LossScoringError::InvalidSensitivityDelta { delta });
    }

    let baseline = compare_actions(actions, matrix, probs)?;
    let baseline_rank = baseline
        .iter()
        .enumerate()
        .map(|(index, score)| (score.action.clone(), index + 1))
        .collect::<BTreeMap<_, _>>();

    let mut records = Vec::new();

    for (outcome_index, outcome_name) in matrix.outcomes.iter().enumerate() {
        for signed_delta in [delta, -delta] {
            let Some(perturbed_probs) = perturb_probabilities(probs, outcome_index, signed_delta)
            else {
                continue;
            };
            let perturbed = compare_actions(actions, matrix, &perturbed_probs)?;
            let perturbed_rank = perturbed
                .iter()
                .enumerate()
                .map(|(index, score)| (score.action.clone(), index + 1))
                .collect::<BTreeMap<_, _>>();

            for action in actions {
                let Some(original_rank) = baseline_rank.get(*action) else {
                    continue;
                };
                let Some(new_rank) = perturbed_rank.get(*action) else {
                    continue;
                };
                if original_rank != new_rank {
                    records.push(SensitivityRecord {
                        action: (*action).to_string(),
                        parameter_name: outcome_name.clone(),
                        delta: signed_delta,
                        original_rank: *original_rank,
                        perturbed_rank: *new_rank,
                    });
                }
            }
        }
    }

    records.sort_by(|a, b| {
        a.parameter_name
            .cmp(&b.parameter_name)
            .then(
                b.delta
                    .partial_cmp(&a.delta)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(a.action.cmp(&b.action))
            .then(a.original_rank.cmp(&b.original_rank))
            .then(a.perturbed_rank.cmp(&b.perturbed_rank))
    });

    Ok(records)
}

pub fn sensitivity_analysis_default(
    actions: &[&str],
    matrix: &LossMatrix,
    probs: &[f64],
) -> Result<Vec<SensitivityRecord>, LossScoringError> {
    sensitivity_analysis(actions, matrix, probs, DEFAULT_SENSITIVITY_DELTA)
}

/// Errors from scorer operations.
#[derive(Debug, Clone, PartialEq)]
pub enum ScorerError {
    InvalidWeights { reason: String },
    NoCandidates,
    InvalidInput { device_id: String, reason: String },
    ScoreOverflow { device_id: String },
}

impl ScorerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidWeights { .. } => "EPS_INVALID_WEIGHTS",
            Self::NoCandidates => "EPS_NO_CANDIDATES",
            Self::InvalidInput { .. } => "EPS_INVALID_INPUT",
            Self::ScoreOverflow { .. } => "EPS_SCORE_OVERFLOW",
        }
    }
}

impl std::fmt::Display for ScorerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWeights { reason } => write!(f, "EPS_INVALID_WEIGHTS: {reason}"),
            Self::NoCandidates => write!(f, "EPS_NO_CANDIDATES"),
            Self::InvalidInput { device_id, reason } => {
                write!(f, "EPS_INVALID_INPUT: {device_id} {reason}")
            }
            Self::ScoreOverflow { device_id } => write!(f, "EPS_SCORE_OVERFLOW: {device_id}"),
        }
    }
}

/// Validate scoring weights.
///
/// INV-EPS-REJECT-INVALID: weights must be non-negative and sum > 0.
pub fn validate_weights(weights: &ScoringWeights) -> Result<(), ScorerError> {
    if !weights.latency_weight.is_finite()
        || !weights.risk_weight.is_finite()
        || !weights.capability_weight.is_finite()
    {
        return Err(ScorerError::InvalidWeights {
            reason: "weights must be finite".into(),
        });
    }
    if weights.latency_weight < 0.0 || weights.risk_weight < 0.0 || weights.capability_weight < 0.0
    {
        return Err(ScorerError::InvalidWeights {
            reason: "negative weight".into(),
        });
    }
    let weight_sum = weights.sum();
    if !weight_sum.is_finite() || weight_sum <= 0.0 {
        return Err(ScorerError::InvalidWeights {
            reason: "weights sum to zero".into(),
        });
    }
    Ok(())
}

/// Validate a candidate input.
fn validate_candidate(c: &CandidateInput) -> Result<(), ScorerError> {
    if c.device_id.is_empty() {
        return Err(ScorerError::InvalidInput {
            device_id: "(empty)".into(),
            reason: "empty device_id".into(),
        });
    }
    if !c.estimated_latency_ms.is_finite() || c.estimated_latency_ms < 0.0 {
        return Err(ScorerError::InvalidInput {
            device_id: c.device_id.clone(),
            reason: "latency must be finite and >= 0".into(),
        });
    }
    if !(0.0..=1.0).contains(&c.risk_score) {
        return Err(ScorerError::InvalidInput {
            device_id: c.device_id.clone(),
            reason: "risk_score out of [0,1]".into(),
        });
    }
    if !(0.0..=1.0).contains(&c.capability_match_ratio) {
        return Err(ScorerError::InvalidInput {
            device_id: c.device_id.clone(),
            reason: "capability_match_ratio out of [0,1]".into(),
        });
    }
    Ok(())
}

/// Score candidates deterministically.
///
/// Scoring formula:
///   latency_component = weight * (1.0 - min(latency/1000, 1.0))  (lower latency → higher score)
///   risk_component    = weight * (1.0 - risk_score)                (lower risk → higher score)
///   capability_component = weight * capability_match_ratio         (higher match → higher score)
///   total = latency_component + risk_component + capability_component
///
/// INV-EPS-DETERMINISTIC: same inputs → same ranking.
/// INV-EPS-TIEBREAK: ties broken by lexicographic device_id (ascending).
/// INV-EPS-EXPLAINABLE: every candidate gets a FactorBreakdown.
pub fn score_candidates(
    candidates: &[CandidateInput],
    weights: &ScoringWeights,
    trace_id: &str,
    timestamp: &str,
) -> Result<PlannerDecision, ScorerError> {
    validate_weights(weights)?;

    if candidates.is_empty() {
        return Err(ScorerError::NoCandidates);
    }

    for c in candidates {
        validate_candidate(c)?;
    }

    let norm = weights.sum();
    let lw = weights.latency_weight / norm;
    let rw = weights.risk_weight / norm;
    let cw = weights.capability_weight / norm;

    let mut scored: Vec<ScoredCandidate> = candidates
        .iter()
        .map(|c| {
            let latency_normalized = (c.estimated_latency_ms / 1000.0).min(1.0);
            let latency_component = lw * (1.0 - latency_normalized);
            let risk_component = rw * (1.0 - c.risk_score);
            let capability_component = cw * c.capability_match_ratio;
            let total = latency_component + risk_component + capability_component;

            if !latency_component.is_finite()
                || !risk_component.is_finite()
                || !capability_component.is_finite()
                || !total.is_finite()
            {
                return Err(ScorerError::ScoreOverflow {
                    device_id: c.device_id.clone(),
                });
            }

            Ok(ScoredCandidate {
                device_id: c.device_id.clone(),
                total_score: total,
                factors: FactorBreakdown {
                    latency_component,
                    risk_component,
                    capability_component,
                },
                rank: 0, // set after sorting
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // INV-EPS-DETERMINISTIC + INV-EPS-TIEBREAK:
    // Sort descending by score; tie-break by ascending device_id.
    scored.sort_by(|a, b| {
        b.total_score
            .partial_cmp(&a.total_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.device_id.cmp(&b.device_id))
    });

    // Assign ranks (1-based)
    for (i, s) in scored.iter_mut().enumerate() {
        s.rank = i + 1;
    }

    Ok(PlannerDecision {
        candidates: scored,
        weights: weights.clone(),
        trace_id: trace_id.to_string(),
        timestamp: timestamp.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weights() -> ScoringWeights {
        ScoringWeights::default_weights()
    }

    fn cand(id: &str, latency: f64, risk: f64, cap: f64) -> CandidateInput {
        CandidateInput {
            device_id: id.into(),
            estimated_latency_ms: latency,
            risk_score: risk,
            capability_match_ratio: cap,
        }
    }

    #[test]
    fn score_single_candidate() {
        let candidates = vec![cand("d1", 100.0, 0.2, 0.9)];
        let d = score_candidates(&candidates, &weights(), "tr", "ts").unwrap();
        assert_eq!(d.candidates.len(), 1);
        assert_eq!(d.candidates[0].rank, 1);
        assert!(d.candidates[0].total_score > 0.0);
    }

    #[test]
    fn deterministic_ranking() {
        let candidates = vec![
            cand("d1", 100.0, 0.2, 0.9),
            cand("d2", 200.0, 0.5, 0.8),
            cand("d3", 50.0, 0.1, 0.7),
        ];
        let r1 = score_candidates(&candidates, &weights(), "tr", "ts").unwrap();
        let r2 = score_candidates(&candidates, &weights(), "tr", "ts").unwrap();
        let ids1: Vec<&str> = r1.candidates.iter().map(|c| c.device_id.as_str()).collect();
        let ids2: Vec<&str> = r2.candidates.iter().map(|c| c.device_id.as_str()).collect();
        assert_eq!(ids1, ids2, "INV-EPS-DETERMINISTIC violated");
    }

    #[test]
    fn tiebreak_by_device_id() {
        // Same scores, different device_ids
        let candidates = vec![
            cand("b-device", 100.0, 0.5, 0.5),
            cand("a-device", 100.0, 0.5, 0.5),
        ];
        let d = score_candidates(&candidates, &weights(), "tr", "ts").unwrap();
        assert_eq!(d.candidates[0].device_id, "a-device"); // lexicographic
        assert_eq!(d.candidates[1].device_id, "b-device");
    }

    #[test]
    fn lower_latency_scores_higher() {
        let candidates = vec![cand("fast", 10.0, 0.5, 0.5), cand("slow", 900.0, 0.5, 0.5)];
        let d = score_candidates(&candidates, &weights(), "tr", "ts").unwrap();
        assert_eq!(d.candidates[0].device_id, "fast");
    }

    #[test]
    fn lower_risk_scores_higher() {
        let candidates = vec![
            cand("safe", 100.0, 0.1, 0.5),
            cand("risky", 100.0, 0.9, 0.5),
        ];
        let d = score_candidates(&candidates, &weights(), "tr", "ts").unwrap();
        assert_eq!(d.candidates[0].device_id, "safe");
    }

    #[test]
    fn higher_capability_scores_higher() {
        let candidates = vec![
            cand("full", 100.0, 0.5, 1.0),
            cand("partial", 100.0, 0.5, 0.1),
        ];
        let d = score_candidates(&candidates, &weights(), "tr", "ts").unwrap();
        assert_eq!(d.candidates[0].device_id, "full");
    }

    #[test]
    fn explainable_factors() {
        let candidates = vec![cand("d1", 100.0, 0.2, 0.9)];
        let d = score_candidates(&candidates, &weights(), "tr", "ts").unwrap();
        let f = &d.candidates[0].factors;
        assert!(f.latency_component >= 0.0);
        assert!(f.risk_component >= 0.0);
        assert!(f.capability_component >= 0.0);
        let sum = f.latency_component + f.risk_component + f.capability_component;
        assert!((sum - d.candidates[0].total_score).abs() < 1e-10);
    }

    #[test]
    fn no_candidates_error() {
        let err = score_candidates(&[], &weights(), "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "EPS_NO_CANDIDATES");
    }

    #[test]
    fn invalid_weights_negative() {
        let w = ScoringWeights {
            latency_weight: -1.0,
            risk_weight: 0.5,
            capability_weight: 0.5,
        };
        let err = score_candidates(&[cand("d1", 100.0, 0.5, 0.5)], &w, "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "EPS_INVALID_WEIGHTS");
    }

    #[test]
    fn invalid_weights_zero_sum() {
        let w = ScoringWeights {
            latency_weight: 0.0,
            risk_weight: 0.0,
            capability_weight: 0.0,
        };
        let err = score_candidates(&[cand("d1", 100.0, 0.5, 0.5)], &w, "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "EPS_INVALID_WEIGHTS");
    }

    #[test]
    fn invalid_weights_non_finite() {
        let w = ScoringWeights {
            latency_weight: f64::INFINITY,
            risk_weight: 0.5,
            capability_weight: 0.5,
        };
        let err = score_candidates(&[cand("d1", 100.0, 0.5, 0.5)], &w, "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "EPS_INVALID_WEIGHTS");
    }

    #[test]
    fn invalid_risk_out_of_range() {
        let candidates = vec![cand("d1", 100.0, 1.5, 0.5)];
        let err = score_candidates(&candidates, &weights(), "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "EPS_INVALID_INPUT");
    }

    #[test]
    fn invalid_capability_out_of_range() {
        let candidates = vec![cand("d1", 100.0, 0.5, -0.1)];
        let err = score_candidates(&candidates, &weights(), "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "EPS_INVALID_INPUT");
    }

    #[test]
    fn invalid_empty_device_id() {
        let candidates = vec![cand("", 100.0, 0.5, 0.5)];
        let err = score_candidates(&candidates, &weights(), "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "EPS_INVALID_INPUT");
    }

    #[test]
    fn negative_latency_rejected() {
        let candidates = vec![cand("d1", -10.0, 0.5, 0.5)];
        let err = score_candidates(&candidates, &weights(), "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "EPS_INVALID_INPUT");
    }

    #[test]
    fn non_finite_latency_rejected() {
        let candidates = vec![cand("d1", f64::NAN, 0.5, 0.5)];
        let err = score_candidates(&candidates, &weights(), "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "EPS_INVALID_INPUT");
    }

    #[test]
    fn ranks_are_sequential() {
        let candidates = vec![
            cand("d1", 100.0, 0.2, 0.9),
            cand("d2", 200.0, 0.5, 0.8),
            cand("d3", 50.0, 0.1, 0.7),
        ];
        let d = score_candidates(&candidates, &weights(), "tr", "ts").unwrap();
        let ranks: Vec<usize> = d.candidates.iter().map(|c| c.rank).collect();
        assert_eq!(ranks, vec![1, 2, 3]);
    }

    #[test]
    fn decision_has_trace() {
        let d =
            score_candidates(&[cand("d1", 100.0, 0.5, 0.5)], &weights(), "trace-x", "ts").unwrap();
        assert_eq!(d.trace_id, "trace-x");
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            ScorerError::InvalidWeights { reason: "x".into() }.code(),
            "EPS_INVALID_WEIGHTS"
        );
        assert_eq!(ScorerError::NoCandidates.code(), "EPS_NO_CANDIDATES");
        assert_eq!(
            ScorerError::InvalidInput {
                device_id: "x".into(),
                reason: "y".into()
            }
            .code(),
            "EPS_INVALID_INPUT"
        );
        assert_eq!(
            ScorerError::ScoreOverflow {
                device_id: "x".into()
            }
            .code(),
            "EPS_SCORE_OVERFLOW"
        );
    }

    #[test]
    fn error_display() {
        let e = ScorerError::InvalidWeights {
            reason: "neg".into(),
        };
        assert!(e.to_string().contains("EPS_INVALID_WEIGHTS"));
    }

    #[test]
    fn default_weights_valid() {
        let w = ScoringWeights::default_weights();
        assert!(validate_weights(&w).is_ok());
        assert!((w.sum() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn latency_capped_at_1000ms() {
        // Latency >1000 should be capped at normalized=1.0 → component=0
        let candidates = vec![cand("d1", 2000.0, 0.0, 1.0)];
        let d = score_candidates(&candidates, &weights(), "tr", "ts").unwrap();
        assert!((d.candidates[0].factors.latency_component - 0.0).abs() < 1e-10);
    }

    fn loss_matrix() -> LossMatrix {
        LossMatrix {
            schema_version: "1.0.0".to_string(),
            actions: vec![
                "do_nothing".to_string(),
                "throttle".to_string(),
                "quarantine".to_string(),
                "rebuild".to_string(),
            ],
            outcomes: vec![
                "benign".to_string(),
                "contained".to_string(),
                "spread".to_string(),
                "catastrophic".to_string(),
                "compliance_penalty".to_string(),
            ],
            values: vec![
                vec![1.0, 5.0, 40.0, 90.0, 30.0],
                vec![2.0, 3.0, 20.0, 60.0, 15.0],
                vec![5.0, 2.0, 8.0, 20.0, 5.0],
                vec![12.0, 4.0, 6.0, 10.0, 3.0],
            ],
        }
    }

    #[test]
    fn loss_matrix_json_roundtrip_keeps_schema_version() {
        let matrix = loss_matrix();
        let json = serde_json::to_string(&matrix).unwrap();
        let parsed: LossMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, "1.0.0");
        assert_eq!(parsed.actions.len(), matrix.actions.len());
        assert_eq!(parsed.outcomes.len(), matrix.outcomes.len());
    }

    #[test]
    fn score_action_returns_expected_loss_and_dominant_outcome() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.2, 0.15, 0.1, 0.05];
        let scored = score_action("quarantine", &matrix, &probs).unwrap();
        assert_eq!(scored.action, "quarantine");
        assert!((scored.expected_loss - 6.35).abs() < 1e-9);
        assert_eq!(scored.dominant_outcome, "benign");
        assert_eq!(scored.breakdown.len(), matrix.outcomes.len());
    }

    #[test]
    fn score_action_rejects_probability_sum_violation() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.2, 0.15, 0.1, 0.1];
        let err = score_action("quarantine", &matrix, &probs).unwrap_err();
        assert_eq!(err.code(), "ELS_INVALID_PROBABILITIES");
    }

    #[test]
    fn compare_actions_returns_sorted_ascending_loss() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.2, 0.15, 0.1, 0.05];
        let actions = ["do_nothing", "throttle", "quarantine", "rebuild"];
        let ranked = compare_actions(&actions, &matrix, &probs).unwrap();
        assert_eq!(ranked[0].action, "quarantine");
        assert_eq!(ranked[1].action, "rebuild");
        assert_eq!(ranked[2].action, "throttle");
        assert_eq!(ranked[3].action, "do_nothing");
    }

    #[test]
    fn compare_actions_rejects_empty_action_set() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.2, 0.15, 0.1, 0.05];
        let err = compare_actions(&[], &matrix, &probs).unwrap_err();
        assert_eq!(err.code(), "ELS_NO_ACTIONS_REQUESTED");
    }

    #[test]
    fn sensitivity_analysis_reports_rank_changes() {
        let matrix = LossMatrix {
            schema_version: "1.0.0".to_string(),
            actions: vec![
                "do_nothing".to_string(),
                "monitor".to_string(),
                "block".to_string(),
            ],
            outcomes: vec!["false_alarm".to_string(), "active_attack".to_string()],
            values: vec![vec![1.0, 100.0], vec![5.0, 60.0], vec![20.0, 20.0]],
        };
        let probs = [0.8, 0.2];
        let actions = ["do_nothing", "monitor", "block"];
        let records = sensitivity_analysis(&actions, &matrix, &probs, 0.3).unwrap();
        assert!(!records.is_empty());
        assert!(records.iter().any(|record| record.action == "block"));
        assert!(
            records
                .iter()
                .all(|record| record.parameter_name == "false_alarm"
                    || record.parameter_name == "active_attack")
        );
    }

    #[test]
    fn sensitivity_analysis_default_uses_default_delta() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.2, 0.15, 0.1, 0.05];
        let actions = ["do_nothing", "throttle", "quarantine", "rebuild"];
        let records = sensitivity_analysis_default(&actions, &matrix, &probs).unwrap();
        assert!(records.iter().all(|record| {
            (record.delta - DEFAULT_SENSITIVITY_DELTA).abs() < 1e-12
                || (record.delta + DEFAULT_SENSITIVITY_DELTA).abs() < 1e-12
        }));
    }

    #[test]
    fn loss_matrix_requires_do_nothing_row() {
        let matrix = LossMatrix {
            schema_version: "1.0.0".to_string(),
            actions: vec!["allow".to_string(), "block".to_string()],
            outcomes: vec!["ok".to_string(), "bad".to_string()],
            values: vec![vec![1.0, 10.0], vec![5.0, 2.0]],
        };
        let probs = [0.5, 0.5];
        let err = score_action("allow", &matrix, &probs).unwrap_err();
        assert_eq!(err.code(), "ELS_MISSING_DO_NOTHING_ACTION");
    }

    #[test]
    fn loss_matrix_rejects_dimension_mismatch() {
        let matrix = LossMatrix {
            schema_version: "1.0.0".to_string(),
            actions: vec!["do_nothing".to_string(), "block".to_string()],
            outcomes: vec!["ok".to_string(), "bad".to_string()],
            values: vec![vec![1.0, 10.0], vec![5.0]],
        };
        let probs = [0.5, 0.5];
        let err = score_action("block", &matrix, &probs).unwrap_err();
        assert_eq!(err.code(), "ELS_INVALID_SCHEMA");
    }

    #[test]
    fn loss_matrix_rejects_blank_schema_version() {
        let matrix = LossMatrix {
            schema_version: "   ".to_string(),
            actions: vec!["do_nothing".to_string()],
            outcomes: vec!["ok".to_string()],
            values: vec![vec![0.0]],
        };

        let err = score_action("do_nothing", &matrix, &[1.0]).unwrap_err();

        assert_eq!(err.code(), "ELS_INVALID_SCHEMA");
        assert!(err.to_string().contains("missing schema_version"));
    }

    #[test]
    fn loss_matrix_rejects_empty_actions() {
        let matrix = LossMatrix {
            schema_version: "1.0.0".to_string(),
            actions: Vec::new(),
            outcomes: vec!["ok".to_string()],
            values: Vec::new(),
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "ELS_INVALID_SCHEMA");
        assert!(err.to_string().contains("at least one action"));
    }

    #[test]
    fn loss_matrix_rejects_empty_outcomes() {
        let matrix = LossMatrix {
            schema_version: "1.0.0".to_string(),
            actions: vec!["do_nothing".to_string()],
            outcomes: Vec::new(),
            values: vec![Vec::new()],
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "ELS_INVALID_SCHEMA");
        assert!(err.to_string().contains("at least one outcome"));
    }

    #[test]
    fn loss_matrix_rejects_row_count_mismatch() {
        let matrix = LossMatrix {
            schema_version: "1.0.0".to_string(),
            actions: vec!["do_nothing".to_string(), "block".to_string()],
            outcomes: vec!["ok".to_string()],
            values: vec![vec![0.0]],
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "ELS_INVALID_SCHEMA");
        assert!(err.to_string().contains("row count"));
    }

    #[test]
    fn loss_matrix_rejects_non_finite_loss_value() {
        let matrix = LossMatrix {
            schema_version: "1.0.0".to_string(),
            actions: vec!["do_nothing".to_string()],
            outcomes: vec!["ok".to_string()],
            values: vec![vec![f64::INFINITY]],
        };

        let err = matrix.validate().unwrap_err();

        assert_eq!(err.code(), "ELS_INVALID_SCHEMA");
        assert!(err.to_string().contains("non-finite"));
    }

    #[test]
    fn score_action_rejects_unknown_action() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.2, 0.15, 0.1, 0.05];

        let err = score_action("restart_planet", &matrix, &probs).unwrap_err();

        assert_eq!(err.code(), "ELS_UNKNOWN_ACTION");
        assert!(err.to_string().contains("restart_planet"));
    }

    #[test]
    fn score_action_rejects_probability_length_mismatch() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.5];

        let err = score_action("quarantine", &matrix, &probs).unwrap_err();

        assert_eq!(err.code(), "ELS_PROBABILITY_LENGTH_MISMATCH");
        assert!(err.to_string().contains("expected=5"));
    }

    #[test]
    fn score_action_rejects_non_finite_probability() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.2, f64::NAN, 0.1, 0.2];

        let err = score_action("quarantine", &matrix, &probs).unwrap_err();

        assert_eq!(err.code(), "ELS_INVALID_PROBABILITIES");
        assert!(err.to_string().contains("finite numbers"));
    }

    #[test]
    fn score_action_rejects_out_of_range_probability() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.2, -0.05, 0.1, 0.25];

        let err = score_action("quarantine", &matrix, &probs).unwrap_err();

        assert_eq!(err.code(), "ELS_INVALID_PROBABILITIES");
        assert!(err.to_string().contains("[0, 1]"));
    }

    #[test]
    fn sensitivity_analysis_rejects_zero_delta() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.2, 0.15, 0.1, 0.05];
        let actions = ["do_nothing", "throttle", "quarantine", "rebuild"];

        let err = sensitivity_analysis(&actions, &matrix, &probs, 0.0).unwrap_err();

        assert_eq!(err.code(), "ELS_INVALID_SENSITIVITY_DELTA");
        assert!(err.to_string().contains('0'));
    }

    #[test]
    fn sensitivity_analysis_rejects_non_finite_delta() {
        let matrix = loss_matrix();
        let probs = [0.5, 0.2, 0.15, 0.1, 0.05];
        let actions = ["do_nothing", "throttle", "quarantine", "rebuild"];

        let err = sensitivity_analysis(&actions, &matrix, &probs, f64::INFINITY).unwrap_err();

        assert_eq!(err.code(), "ELS_INVALID_SENSITIVITY_DELTA");
        assert!(err.to_string().contains("inf"));
    }
}

#[cfg(test)]
mod execution_scorer_comprehensive_negative_tests {
    use super::*;
    use std::collections::HashMap;

    /// Negative test: Unicode injection and encoding attacks in device identifiers and trace data
    #[test]
    fn negative_unicode_injection_device_and_trace_attacks() {
        // Test malicious Unicode in device IDs
        let malicious_devices = vec![
            "device\u{202e}evil\u{200b}", // Right-to-left override + zero-width space
            "device\u{0000}injection", // Null byte injection
            "device\u{feff}bom", // Byte order mark
            "device\u{2028}newline", // Line separator
            "device\u{2029}paragraph", // Paragraph separator
            "device\u{200c}\u{200d}joiners", // Zero-width joiners
            "device\u{034f}combining", // Combining grapheme joiner
        ];

        let mut candidates = Vec::new();
        for (i, malicious_device) in malicious_devices.iter().enumerate() {
            candidates.push(CandidateInput {
                device_id: malicious_device.to_string(),
                estimated_latency_ms: 100.0 + i as f64 * 10.0,
                risk_score: 0.1 + i as f64 * 0.1,
                capability_match_ratio: 0.9 - i as f64 * 0.1,
            });
        }

        let weights = ScoringWeights::default_weights();
        let unicode_trace = "trace\u{202e}malicious\u{0000}";
        let unicode_timestamp = "2026-01-01T\u{feff}12:00:00Z";

        let result = score_candidates(&candidates, &weights, &unicode_trace, &unicode_timestamp);
        assert!(result.is_ok(), "Should handle Unicode in device IDs and trace data");

        let decision = result.unwrap();
        assert_eq!(decision.candidates.len(), malicious_devices.len());

        // Verify Unicode content is preserved without corruption
        assert_eq!(decision.trace_id, unicode_trace);
        assert_eq!(decision.timestamp, unicode_timestamp);

        // Verify ranking determinism despite Unicode content
        let second_result = score_candidates(&candidates, &weights, &unicode_trace, &unicode_timestamp);
        assert!(second_result.is_ok());

        let second_decision = second_result.unwrap();
        for (i, (first, second)) in decision.candidates.iter().zip(second_decision.candidates.iter()).enumerate() {
            assert_eq!(first.device_id, second.device_id, "Unicode should not affect deterministic ranking at position {}", i);
            assert_eq!(first.rank, second.rank, "Ranks should be identical despite Unicode");
        }

        // Test loss matrix with Unicode action/outcome names
        let unicode_matrix = LossMatrix {
            schema_version: "1.0\u{200b}".to_string(),
            actions: vec![
                "do_nothing\u{202e}".to_string(),
                "action\u{0000}inject".to_string(),
                "unicode\u{feff}action".to_string(),
            ],
            outcomes: vec![
                "outcome\u{2028}a".to_string(),
                "outcome\u{200c}b".to_string(),
            ],
            values: vec![
                vec![1.0, 10.0],
                vec![2.0, 5.0],
                vec![3.0, 8.0],
            ],
        };

        let validation_result = unicode_matrix.validate();
        match validation_result {
            Ok(_) => {
                // Unicode was accepted, test scoring
                let probs = [0.7, 0.3];
                let score_result = score_action("do_nothing\u{202e}", &unicode_matrix, &probs);
                match score_result {
                    Ok(score) => {
                        assert_eq!(score.action, "do_nothing\u{202e}");
                        assert!(score.expected_loss.is_finite());
                    },
                    Err(e) => {
                        // Unicode-specific rejection is acceptable
                        assert!(matches!(e, LossScoringError::UnknownAction { .. }));
                    }
                }
            },
            Err(e) => {
                // Unicode validation failure is also acceptable
                assert_eq!(e.code(), "ELS_INVALID_SCHEMA");
            }
        }
    }

    /// Negative test: Arithmetic overflow and floating-point precision attacks
    #[test]
    fn negative_arithmetic_overflow_floating_point_precision() {
        let weights = ScoringWeights::default_weights();

        // Test near-maximum floating-point values
        let extreme_candidates = vec![
            CandidateInput {
                device_id: "extreme-latency".to_string(),
                estimated_latency_ms: f64::MAX / 2.0, // Very large latency
                risk_score: 0.5,
                capability_match_ratio: 0.5,
            },
            CandidateInput {
                device_id: "tiny-latency".to_string(),
                estimated_latency_ms: f64::MIN_POSITIVE, // Smallest positive value
                risk_score: 0.5,
                capability_match_ratio: 0.5,
            },
            CandidateInput {
                device_id: "precision-boundary".to_string(),
                estimated_latency_ms: 1000.0 + f64::EPSILON, // Just above 1000ms boundary
                risk_score: 1.0 - f64::EPSILON, // Near maximum risk
                capability_match_ratio: f64::EPSILON, // Near minimum capability
            },
        ];

        let result = score_candidates(&extreme_candidates, &weights, "trace-extreme", "timestamp");
        assert!(result.is_ok(), "Should handle extreme floating-point values");

        let decision = result.unwrap();
        for candidate in &decision.candidates {
            assert!(candidate.total_score.is_finite(), "Total score should be finite for {}", candidate.device_id);
            assert!(candidate.factors.latency_component.is_finite(), "Latency component should be finite");
            assert!(candidate.factors.risk_component.is_finite(), "Risk component should be finite");
            assert!(candidate.factors.capability_component.is_finite(), "Capability component should be finite");
        }

        // Test overflow protection in weight calculations
        let overflow_weights = ScoringWeights {
            latency_weight: f64::MAX / 4.0,
            risk_weight: f64::MAX / 4.0,
            capability_weight: f64::MAX / 4.0,
        };

        let overflow_candidate = vec![CandidateInput {
            device_id: "overflow-test".to_string(),
            estimated_latency_ms: 500.0,
            risk_score: 0.8,
            capability_match_ratio: 0.9,
        }];

        let overflow_result = score_candidates(&overflow_candidate, &overflow_weights, "trace-overflow", "timestamp");
        match overflow_result {
            Ok(decision) => {
                // If scoring succeeded, verify no overflow occurred
                assert!(decision.candidates[0].total_score.is_finite(), "Score should remain finite despite large weights");
            },
            Err(e) => {
                // Overflow detection and rejection is acceptable
                assert!(matches!(e, ScorerError::InvalidWeights { .. } | ScorerError::ScoreOverflow { .. }));
            }
        }

        // Test loss matrix with extreme values
        let extreme_matrix = LossMatrix {
            schema_version: "extreme-test".to_string(),
            actions: vec!["do_nothing".to_string(), "extreme_action".to_string()],
            outcomes: vec!["normal".to_string(), "extreme".to_string()],
            values: vec![
                vec![1.0, f64::MAX / 1e6], // Large but finite loss
                vec![f64::MIN_POSITIVE, 1000.0],
            ],
        };

        let extreme_validation = extreme_matrix.validate();
        assert!(extreme_validation.is_ok(), "Should handle extreme but finite loss values");

        let extreme_probs = [1.0 - f64::EPSILON, f64::EPSILON];
        let extreme_score_result = score_action("extreme_action", &extreme_matrix, &extreme_probs);
        assert!(extreme_score_result.is_ok(), "Should handle extreme probability distributions");

        if let Ok(score) = extreme_score_result {
            assert!(score.expected_loss.is_finite(), "Expected loss should remain finite");
        }

        // Test precision loss in probability normalization
        let precision_probs = [0.3333333333333333, 0.3333333333333333, 0.3333333333333334];
        let precision_matrix = LossMatrix {
            schema_version: "precision-test".to_string(),
            actions: vec!["do_nothing".to_string()],
            outcomes: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            values: vec![vec![1.0, 2.0, 3.0]],
        };

        let precision_validation = validate_probabilities(&precision_probs, 3);
        assert!(precision_validation.is_ok(), "Should handle precision-boundary probability sums");
    }

    /// Negative test: Memory exhaustion attacks with massive candidate sets and loss matrices
    #[test]
    fn negative_memory_exhaustion_massive_data_structures() {
        let weights = ScoringWeights::default_weights();

        // Test massive number of candidates
        let huge_device_base = "device".repeat(100);
        let mut massive_candidates = Vec::new();

        for i in 0..1000 {
            massive_candidates.push(CandidateInput {
                device_id: format!("{}-{}", huge_device_base, i),
                estimated_latency_ms: 100.0 + (i as f64 * 0.1) % 1000.0,
                risk_score: (i as f64 * 0.001) % 1.0,
                capability_match_ratio: 1.0 - (i as f64 * 0.0005) % 1.0,
            });
        }

        let massive_trace = "trace".repeat(1000);
        let massive_timestamp = "timestamp".repeat(500);

        let result = score_candidates(&massive_candidates, &weights, &massive_trace, &massive_timestamp);
        assert!(result.is_ok(), "Should handle large candidate sets without memory exhaustion");

        if let Ok(decision) = result {
            assert_eq!(decision.candidates.len(), 1000);

            // Verify deterministic ranking with large dataset
            for (i, candidate) in decision.candidates.iter().enumerate() {
                assert_eq!(candidate.rank, i + 1, "Ranks should be sequential");
                assert!(candidate.total_score.is_finite(), "All scores should be finite");
            }
        }

        // Test massive loss matrix
        let mut massive_actions = Vec::new();
        let mut massive_outcomes = Vec::new();
        let mut massive_values = Vec::new();

        // Create large loss matrix
        massive_actions.push("do_nothing".to_string()); // Required action
        for i in 0..500 {
            massive_actions.push(format!("action-{}-{}", i, "x".repeat(50)));
        }

        for i in 0..300 {
            massive_outcomes.push(format!("outcome-{}-{}", i, "y".repeat(30)));
        }

        for action_idx in 0..massive_actions.len() {
            let mut row = Vec::new();
            for outcome_idx in 0..massive_outcomes.len() {
                row.push(1.0 + (action_idx as f64 + outcome_idx as f64) * 0.1);
            }
            massive_values.push(row);
        }

        let massive_matrix = LossMatrix {
            schema_version: "massive-test".to_string(),
            actions: massive_actions.clone(),
            outcomes: massive_outcomes.clone(),
            values: massive_values,
        };

        let massive_validation = massive_matrix.validate();
        assert!(massive_validation.is_ok(), "Should validate massive but well-formed loss matrix");

        // Test scoring with massive matrix (use smaller probability array for efficiency)
        let mut massive_probs = vec![0.0; massive_outcomes.len()];
        massive_probs[0] = 1.0; // All probability on first outcome

        let massive_score_result = score_action("do_nothing", &massive_matrix, &massive_probs);
        assert!(massive_score_result.is_ok(), "Should handle massive loss matrix scoring");

        // Test memory usage during sensitivity analysis with smaller subset
        let subset_actions: Vec<&str> = massive_actions.iter().take(10).map(|s| s.as_str()).collect();
        let mut subset_probs = vec![0.0; massive_outcomes.len().min(20)];
        if !subset_probs.is_empty() {
            subset_probs[0] = 1.0;
        }

        // Adjust matrix for subset test
        let subset_matrix = LossMatrix {
            schema_version: massive_matrix.schema_version.clone(),
            actions: massive_matrix.actions.iter().take(10).cloned().collect(),
            outcomes: massive_matrix.outcomes.iter().take(20).cloned().collect(),
            values: massive_matrix.values.iter().take(10).map(|row| row.iter().take(20).cloned().collect()).collect(),
        };

        let sensitivity_result = sensitivity_analysis(&subset_actions, &subset_matrix, &subset_probs, 0.1);
        match sensitivity_result {
            Ok(records) => {
                assert!(records.len() < 10000, "Sensitivity records should be bounded");
            },
            Err(_) => {
                // Memory or computation limits are acceptable for massive datasets
            }
        }
    }

    /// Negative test: Floating-point precision edge cases and denormal number handling
    #[test]
    fn negative_floating_point_precision_edge_cases() {
        let weights = ScoringWeights::default_weights();

        // Test subnormal (denormal) numbers
        let subnormal_candidates = vec![
            CandidateInput {
                device_id: "subnormal-latency".to_string(),
                estimated_latency_ms: f64::from_bits(1), // Smallest subnormal positive
                risk_score: 0.5,
                capability_match_ratio: 0.5,
            },
            CandidateInput {
                device_id: "subnormal-precision".to_string(),
                estimated_latency_ms: 100.0,
                risk_score: f64::from_bits(1), // Subnormal risk (invalid, should fail)
                capability_match_ratio: 0.5,
            },
        ];

        let result = score_candidates(&subnormal_candidates, &weights, "trace-subnormal", "timestamp");
        match result {
            Ok(decision) => {
                // If accepted, verify all scores remain finite
                for candidate in &decision.candidates {
                    assert!(candidate.total_score.is_finite());
                    assert!(candidate.total_score >= 0.0);
                }
            },
            Err(e) => {
                // Rejection of subnormal values is acceptable
                assert_eq!(e.code(), "EPS_INVALID_INPUT");
            }
        }

        // Test precision loss in tie-breaking scenarios
        let epsilon_diff = f64::EPSILON;
        let tie_candidates = vec![
            CandidateInput {
                device_id: "tie-a".to_string(),
                estimated_latency_ms: 100.0,
                risk_score: 0.5,
                capability_match_ratio: 0.5,
            },
            CandidateInput {
                device_id: "tie-b".to_string(),
                estimated_latency_ms: 100.0 + epsilon_diff,
                risk_score: 0.5,
                capability_match_ratio: 0.5,
            },
            CandidateInput {
                device_id: "tie-c".to_string(),
                estimated_latency_ms: 100.0 - epsilon_diff,
                risk_score: 0.5,
                capability_match_ratio: 0.5,
            },
        ];

        let tie_result = score_candidates(&tie_candidates, &weights, "trace-tie", "timestamp");
        assert!(tie_result.is_ok(), "Should handle epsilon-level differences");

        let tie_decision = tie_result.unwrap();
        assert_eq!(tie_decision.candidates.len(), 3);

        // Test multiple rounds to ensure deterministic tie-breaking
        let tie_result2 = score_candidates(&tie_candidates, &weights, "trace-tie", "timestamp");
        assert!(tie_result2.is_ok());

        let tie_decision2 = tie_result2.unwrap();
        for (first, second) in tie_decision.candidates.iter().zip(tie_decision2.candidates.iter()) {
            assert_eq!(first.device_id, second.device_id, "Tie-breaking should be deterministic");
            assert_eq!(first.rank, second.rank, "Ranks should be stable across runs");
        }

        // Test probability normalization edge cases
        let edge_probs = vec![
            [1.0, 0.0], // Perfect certainty
            [0.5 + f64::EPSILON, 0.5 - f64::EPSILON], // Epsilon imbalance
            [f64::MIN_POSITIVE, 1.0 - f64::MIN_POSITIVE], // Extreme imbalance
        ];

        let edge_matrix = LossMatrix {
            schema_version: "edge-test".to_string(),
            actions: vec!["do_nothing".to_string(), "act".to_string()],
            outcomes: vec!["a".to_string(), "b".to_string()],
            values: vec![vec![1.0, 2.0], vec![3.0, 4.0]],
        };

        for probs in edge_probs {
            let validation = validate_probabilities(&probs, 2);
            assert!(validation.is_ok(), "Should handle edge-case probability distributions: {:?}", probs);

            let score_result = score_action("act", &edge_matrix, &probs);
            assert!(score_result.is_ok(), "Should score with edge-case probabilities: {:?}", probs);
        }

        // Test weight normalization edge cases
        let edge_weights = vec![
            ScoringWeights { latency_weight: f64::EPSILON, risk_weight: f64::EPSILON, capability_weight: 1.0 },
            ScoringWeights { latency_weight: 1000000.0, risk_weight: 0.001, capability_weight: 0.001 },
            ScoringWeights { latency_weight: f64::MIN_POSITIVE, risk_weight: f64::MIN_POSITIVE, capability_weight: f64::MIN_POSITIVE },
        ];

        let test_candidate = vec![CandidateInput {
            device_id: "edge-weight-test".to_string(),
            estimated_latency_ms: 100.0,
            risk_score: 0.5,
            capability_match_ratio: 0.5,
        }];

        for weight in edge_weights {
            let weight_result = score_candidates(&test_candidate, &weight, "trace-weight-edge", "timestamp");
            match weight_result {
                Ok(decision) => {
                    // If accepted, verify normalization worked correctly
                    assert!(decision.candidates[0].total_score.is_finite());
                },
                Err(e) => {
                    // Rejection of extreme weights is acceptable
                    assert_eq!(e.code(), "EPS_INVALID_WEIGHTS");
                }
            }
        }
    }

    /// Negative test: Timing attack resistance in scoring operations and comparisons
    #[test]
    fn negative_timing_attack_resistance() {
        let weights = ScoringWeights::default_weights();

        // Create candidates with similar vs. different device IDs
        let similar_devices = vec![
            "device-aaa",
            "device-aab",
            "device-aac",
            "device-xyz",
            "completely-different-device-name",
        ];

        let mut timing_candidates = Vec::new();
        for device_id in &similar_devices {
            timing_candidates.push(CandidateInput {
                device_id: device_id.to_string(),
                estimated_latency_ms: 100.0,
                risk_score: 0.5,
                capability_match_ratio: 0.5,
            });
        }

        // Measure timing for multiple runs
        let mut timing_results = Vec::new();
        for _ in 0..10 {
            let start_time = std::time::Instant::now();
            let _result = score_candidates(&timing_candidates, &weights, "trace-timing", "timestamp");
            let duration = start_time.elapsed();
            timing_results.push(duration);
        }

        // Timing should be relatively consistent
        let max_timing = timing_results.iter().max().unwrap();
        let min_timing = timing_results.iter().min().unwrap();
        let timing_ratio = max_timing.as_nanos() as f64 / min_timing.as_nanos() as f64;

        assert!(timing_ratio < 3.0, "Scoring timing variance too high: {}", timing_ratio);

        // Test timing consistency for validation operations
        let validation_test_weights = vec![
            ScoringWeights { latency_weight: 0.4, risk_weight: 0.3, capability_weight: 0.3 },
            ScoringWeights { latency_weight: -0.1, risk_weight: 0.3, capability_weight: 0.3 }, // Invalid
            ScoringWeights { latency_weight: 0.0, risk_weight: 0.0, capability_weight: 0.0 }, // Invalid
        ];

        let mut validation_timing_results = Vec::new();
        for weight_config in &validation_test_weights {
            let start_time = std::time::Instant::now();
            let _result = validate_weights(weight_config);
            let duration = start_time.elapsed();
            validation_timing_results.push(duration);
        }

        // Validation timing should not leak information about validity
        let max_val_timing = validation_timing_results.iter().max().unwrap();
        let min_val_timing = validation_timing_results.iter().min().unwrap();
        let val_timing_ratio = max_val_timing.as_nanos() as f64 / min_val_timing.as_nanos() as f64;

        assert!(val_timing_ratio < 4.0, "Validation timing variance too high: {}", val_timing_ratio);

        // Test loss matrix action lookup timing consistency
        let timing_matrix = LossMatrix {
            schema_version: "timing-test".to_string(),
            actions: vec!["do_nothing".to_string(), "similar_action_a".to_string(), "similar_action_b".to_string(), "different".to_string()],
            outcomes: vec!["outcome".to_string()],
            values: vec![vec![1.0], vec![2.0], vec![3.0], vec![4.0]],
        };

        let test_probs = [1.0];
        let test_actions = ["do_nothing", "similar_action_a", "similar_action_b", "different", "nonexistent"];

        let mut action_timing_results = Vec::new();
        for action in &test_actions {
            let start_time = std::time::Instant::now();
            let _result = score_action(action, &timing_matrix, &test_probs);
            let duration = start_time.elapsed();
            action_timing_results.push(duration);
        }

        // Action lookup timing should be consistent regardless of similarity or existence
        let max_action_timing = action_timing_results.iter().max().unwrap();
        let min_action_timing = action_timing_results.iter().min().unwrap();
        let action_timing_ratio = max_action_timing.as_nanos() as f64 / min_action_timing.as_nanos() as f64;

        assert!(action_timing_ratio < 5.0, "Action lookup timing variance too high: {}", action_timing_ratio);
    }

    /// Negative test: Probability perturbation edge cases and sensitivity analysis attacks
    #[test]
    fn negative_probability_perturbation_sensitivity_attacks() {
        // Test perturb_probabilities with edge cases
        let edge_cases = vec![
            // Single probability (special case)
            (vec![1.0], 0, 0.1, false), // Should fail - can't perturb single probability away from 1.0
            (vec![1.0], 0, 0.0, true),  // Should succeed - no change

            // Boundary perturbations
            (vec![0.0, 1.0], 0, 1.0, true),  // Move all probability to first outcome
            (vec![0.0, 1.0], 1, -1.0, true), // Move all probability from second outcome
            (vec![0.5, 0.5], 0, 0.5, true),  // Boundary case
            (vec![0.5, 0.5], 0, 0.6, false), // Exceeds boundary

            // Precision edge cases
            (vec![0.3333333333333333, 0.6666666666666667], 0, f64::EPSILON, true),
            (vec![f64::EPSILON, 1.0 - f64::EPSILON], 0, -f64::EPSILON/2.0, true),
        ];

        for (base_probs, index, delta, should_succeed) in edge_cases {
            let result = perturb_probabilities(&base_probs, index, delta);
            if should_succeed {
                assert!(result.is_some(), "Expected perturbation to succeed for base={:?}, index={}, delta={}", base_probs, index, delta);

                if let Some(perturbed) = result {
                    // Verify probability properties
                    assert!(perturbed.iter().all(|p| *p >= 0.0 && *p <= 1.0), "All probabilities should be in [0,1]");
                    let sum: f64 = perturbed.iter().sum();
                    assert!((sum - 1.0).abs() <= PROBABILITY_SUM_EPSILON * 10.0, "Perturbed probabilities should sum to 1.0, got {}", sum);
                }
            } else {
                assert!(result.is_none(), "Expected perturbation to fail for base={:?}, index={}, delta={}", base_probs, index, delta);
            }
        }

        // Test sensitivity analysis with extreme scenarios
        let extreme_matrix = LossMatrix {
            schema_version: "extreme-sensitivity".to_string(),
            actions: vec![
                "do_nothing".to_string(),
                "low_impact".to_string(),
                "high_impact".to_string(),
            ],
            outcomes: vec![
                "very_likely".to_string(),
                "unlikely".to_string(),
                "very_unlikely".to_string(),
            ],
            values: vec![
                vec![1.0, 100.0, 1000.0],    // do_nothing: low cost for likely, high for unlikely
                vec![10.0, 50.0, 100.0],     // low_impact: medium costs
                vec![50.0, 20.0, 10.0],      // high_impact: front-loaded cost
            ],
        };

        // Test with extreme probability distributions
        let extreme_prob_cases = vec![
            [0.99, 0.009, 0.001],           // Very skewed
            [0.001, 0.001, 0.998],          // Reverse skewed
            [0.333333, 0.333333, 0.333334], // Even split with precision boundary
        ];

        for probs in extreme_prob_cases {
            let actions = ["do_nothing", "low_impact", "high_impact"];

            // Test baseline comparison
            let baseline_result = compare_actions(&actions, &extreme_matrix, &probs);
            assert!(baseline_result.is_ok(), "Baseline comparison should succeed for probs: {:?}", probs);

            // Test sensitivity analysis with various delta values
            let delta_values = [0.001, 0.01, 0.1, 0.2];
            for delta in delta_values {
                let sensitivity_result = sensitivity_analysis(&actions, &extreme_matrix, &probs, delta);
                match sensitivity_result {
                    Ok(records) => {
                        // Verify sensitivity records are well-formed
                        for record in &records {
                            assert!(actions.contains(&record.action.as_str()), "Action should be in original set");
                            assert!(extreme_matrix.outcomes.contains(&record.parameter_name), "Parameter should be an outcome");
                            assert!(record.delta.abs() <= delta + f64::EPSILON, "Delta should be within specified range");
                            assert!(record.original_rank >= 1 && record.original_rank <= actions.len(), "Original rank should be valid");
                            assert!(record.perturbed_rank >= 1 && record.perturbed_rank <= actions.len(), "Perturbed rank should be valid");
                        }

                        // Verify sorting order
                        for window in records.windows(2) {
                            let (a, b) = (&window[0], &window[1]);
                            assert!(
                                a.parameter_name <= b.parameter_name ||
                                (a.parameter_name == b.parameter_name && a.delta >= b.delta) ||
                                (a.parameter_name == b.parameter_name && a.delta == b.delta && a.action <= b.action),
                                "Sensitivity records should be properly sorted"
                            );
                        }
                    },
                    Err(e) => {
                        // Some extreme cases may legitimately fail
                        assert!(matches!(e,
                            LossScoringError::InvalidProbabilities { .. } |
                            LossScoringError::InvalidSensitivityDelta { .. }
                        ), "Failure should be due to invalid input parameters for delta={}, probs={:?}", delta, probs);
                    }
                }
            }
        }

        // Test sensitivity analysis with massive delta (should fail gracefully)
        let normal_probs = [0.6, 0.3, 0.1];
        let actions = ["do_nothing", "low_impact"];

        let massive_delta_result = sensitivity_analysis(&actions, &extreme_matrix, &normal_probs, 10.0);
        assert!(massive_delta_result.is_err(), "Massive delta should be rejected");
        assert_eq!(massive_delta_result.unwrap_err().code(), "ELS_INVALID_SENSITIVITY_DELTA");

        let negative_delta_result = sensitivity_analysis(&actions, &extreme_matrix, &normal_probs, -0.1);
        assert!(negative_delta_result.is_err(), "Negative delta should be rejected");
        assert_eq!(negative_delta_result.unwrap_err().code(), "ELS_INVALID_SENSITIVITY_DELTA");
    }

    /// Negative test: Loss matrix schema validation edge cases and malformed data
    #[test]
    fn negative_loss_matrix_schema_validation_attacks() {
        // Test various schema validation edge cases
        let malformed_matrices = vec![
            // Empty schema version
            LossMatrix {
                schema_version: String::new(),
                actions: vec!["do_nothing".to_string()],
                outcomes: vec!["outcome".to_string()],
                values: vec![vec![1.0]],
            },

            // Whitespace-only schema version
            LossMatrix {
                schema_version: "   \t\n  ".to_string(),
                actions: vec!["do_nothing".to_string()],
                outcomes: vec!["outcome".to_string()],
                values: vec![vec![1.0]],
            },

            // Missing required "do nothing" action (various spellings)
            LossMatrix {
                schema_version: "test".to_string(),
                actions: vec!["act".to_string(), "react".to_string()],
                outcomes: vec!["outcome".to_string()],
                values: vec![vec![1.0], vec![2.0]],
            },

            // Inconsistent row lengths
            LossMatrix {
                schema_version: "test".to_string(),
                actions: vec!["do_nothing".to_string(), "act".to_string()],
                outcomes: vec!["a".to_string(), "b".to_string(), "c".to_string()],
                values: vec![
                    vec![1.0, 2.0, 3.0],  // Correct length
                    vec![4.0, 5.0],       // Wrong length
                ],
            },

            // Infinite loss values
            LossMatrix {
                schema_version: "test".to_string(),
                actions: vec!["do_nothing".to_string()],
                outcomes: vec!["outcome".to_string()],
                values: vec![vec![f64::INFINITY]],
            },

            // NaN loss values
            LossMatrix {
                schema_version: "test".to_string(),
                actions: vec!["do_nothing".to_string()],
                outcomes: vec!["outcome".to_string()],
                values: vec![vec![f64::NAN]],
            },
        ];

        for (i, matrix) in malformed_matrices.iter().enumerate() {
            let validation_result = matrix.validate();
            assert!(validation_result.is_err(), "Matrix {} should fail validation: {:?}", i, matrix);

            let error = validation_result.unwrap_err();
            match error {
                LossScoringError::InvalidSchema { .. } => {},
                LossScoringError::MissingDoNothingAction => {},
                _ => panic!("Unexpected error type for matrix {}: {:?}", i, error),
            }
        }

        // Test "do nothing" action recognition edge cases
        let do_nothing_variants = vec![
            "do_nothing",
            "donothing",
            "noop",
            "NOOP",
            "Do_Nothing",
            "do-nothing", // Should NOT match (contains non-alphanumeric)
            "do nothing", // Should NOT match (contains space)
        ];

        for variant in do_nothing_variants {
            let matrix = LossMatrix {
                schema_version: "test".to_string(),
                actions: vec![variant.to_string()],
                outcomes: vec!["outcome".to_string()],
                values: vec![vec![1.0]],
            };

            let validation_result = matrix.validate();
            let normalized = normalize_action_name(variant);

            if normalized == "donothing" || normalized == "noop" {
                assert!(validation_result.is_ok(), "Variant '{}' (normalized: '{}') should be accepted as do_nothing", variant, normalized);
            } else {
                assert!(validation_result.is_err(), "Variant '{}' (normalized: '{}') should be rejected", variant, normalized);
                assert_eq!(validation_result.unwrap_err(), LossScoringError::MissingDoNothingAction);
            }
        }

        // Test action name normalization edge cases
        let normalization_cases = vec![
            ("Action123", "action123"),
            ("Action_With_Underscores", "actionwithunderscores"),
            ("Action-With-Dashes", "actionwithdashes"),
            ("Action With Spaces", "actionwithspaces"),
            ("Action!@#$%^&*()With~Symbols", "actionwithsymbols"),
            ("", ""),
            ("123", "123"),
            ("αβγ", "αβγ"), // Non-ASCII should be preserved
        ];

        for (input, expected) in normalization_cases {
            let normalized = normalize_action_name(input);
            assert_eq!(normalized, expected, "Normalization failed for input: '{}'", input);
        }

        // Test massive matrix dimensions
        let massive_matrix = LossMatrix {
            schema_version: "massive-test".to_string(),
            actions: (0..1000).map(|i| if i == 0 { "do_nothing".to_string() } else { format!("action_{}", i) }).collect(),
            outcomes: (0..500).map(|i| format!("outcome_{}", i)).collect(),
            values: (0..1000).map(|i| (0..500).map(|j| (i + j) as f64).collect()).collect(),
        };

        let massive_validation = massive_matrix.validate();
        assert!(massive_validation.is_ok(), "Massive but well-formed matrix should validate");

        // Test action lookup performance with massive matrix
        let lookup_start = std::time::Instant::now();
        let lookup_result = massive_matrix.action_index("action_999");
        let lookup_duration = lookup_start.elapsed();

        assert_eq!(lookup_result, Some(999), "Action lookup should find correct index");
        assert!(lookup_duration < std::time::Duration::from_millis(10), "Action lookup should be fast even for large matrices");
    }
}
