//! bd-jxgt: Execution planner scorer (latency/risk/capability-aware).
//!
//! Deterministic scoring with explicit tie-breakers and explainable factor weights.
//! Identical inputs always produce identical rankings.

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
        let candidates = vec![
            cand("fast", 10.0, 0.5, 0.5),
            cand("slow", 900.0, 0.5, 0.5),
        ];
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
        let d = score_candidates(&[cand("d1", 100.0, 0.5, 0.5)], &weights(), "trace-x", "ts")
            .unwrap();
        assert_eq!(d.trace_id, "trace-x");
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(ScorerError::InvalidWeights { reason: "x".into() }.code(), "EPS_INVALID_WEIGHTS");
        assert_eq!(ScorerError::NoCandidates.code(), "EPS_NO_CANDIDATES");
        assert_eq!(ScorerError::InvalidInput { device_id: "x".into(), reason: "y".into() }.code(), "EPS_INVALID_INPUT");
        assert_eq!(ScorerError::ScoreOverflow { device_id: "x".into() }.code(), "EPS_SCORE_OVERFLOW");
    }

    #[test]
    fn error_display() {
        let e = ScorerError::InvalidWeights { reason: "neg".into() };
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
}
