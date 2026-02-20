//! bd-jxgt: Execution planner scorer (latency/risk/capability-aware).
//!
//! Deterministic scoring with explicit tie-breakers and explainable factor weights.
//! Identical inputs always produce identical rankings.

use std::collections::HashMap;

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
    if (sum - 1.0).abs() > PROBABILITY_SUM_EPSILON {
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
    if base.len() <= 1 {
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
    if sum <= 0.0 {
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
        .collect::<HashMap<_, _>>();

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
                .collect::<HashMap<_, _>>();

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
    if weights.latency_weight < 0.0 || weights.risk_weight < 0.0 || weights.capability_weight < 0.0
    {
        return Err(ScorerError::InvalidWeights {
            reason: "negative weight".into(),
        });
    }
    if weights.sum() <= 0.0 {
        return Err(ScorerError::InvalidWeights {
            reason: "weights sum to zero".into(),
        });
    }
    if weights.latency_weight.is_nan()
        || weights.risk_weight.is_nan()
        || weights.capability_weight.is_nan()
    {
        return Err(ScorerError::InvalidWeights {
            reason: "NaN weight".into(),
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
    if c.estimated_latency_ms < 0.0 {
        return Err(ScorerError::InvalidInput {
            device_id: c.device_id.clone(),
            reason: "negative latency".into(),
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

            ScoredCandidate {
                device_id: c.device_id.clone(),
                total_score: total,
                factors: FactorBreakdown {
                    latency_component,
                    risk_component,
                    capability_component,
                },
                rank: 0, // set after sorting
            }
        })
        .collect();

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
}
