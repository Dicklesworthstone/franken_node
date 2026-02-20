//! bd-2t5u: Predictive pre-staging engine for high-probability offline artifacts.
//!
//! Budget-limited pre-staging with measured prediction quality.
//! Deterministic: same candidates + config → same decisions.

/// Configuration for pre-staging budget and thresholds.
#[derive(Debug, Clone)]
pub struct PrestageConfig {
    pub max_bytes: u64,
    pub probability_threshold: f64,
    pub max_artifacts_per_cycle: usize,
}

impl PrestageConfig {
    pub fn default_config() -> Self {
        Self {
            max_bytes: 100_000_000, // 100MB
            probability_threshold: 0.5,
            max_artifacts_per_cycle: 50,
        }
    }
}

/// An artifact candidate for pre-staging.
#[derive(Debug, Clone)]
pub struct ArtifactCandidate {
    pub artifact_id: String,
    pub size_bytes: u64,
    pub predicted_probability: f64,
}

/// Decision record for a single artifact.
#[derive(Debug, Clone)]
pub struct PrestageDecision {
    pub artifact_id: String,
    pub staged: bool,
    pub reason: String,
    pub budget_remaining: u64,
}

/// Quality metrics for prediction accuracy.
#[derive(Debug, Clone)]
pub struct QualityMetrics {
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
}

/// Coverage report for a pre-staging cycle.
#[derive(Debug, Clone)]
pub struct PrestageReport {
    pub total_candidates: usize,
    pub staged_count: usize,
    pub skipped_count: usize,
    pub budget_used: u64,
    pub budget_total: u64,
    pub trace_id: String,
    pub timestamp: String,
}

/// Errors from pre-staging operations.
#[derive(Debug, Clone, PartialEq)]
pub enum PrestageError {
    BudgetExceeded { used: u64, limit: u64 },
    InvalidConfig { reason: String },
    NoCandidates,
    ThresholdInvalid { value: f64 },
}

impl PrestageError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BudgetExceeded { .. } => "PSE_BUDGET_EXCEEDED",
            Self::InvalidConfig { .. } => "PSE_INVALID_CONFIG",
            Self::NoCandidates => "PSE_NO_CANDIDATES",
            Self::ThresholdInvalid { .. } => "PSE_THRESHOLD_INVALID",
        }
    }
}

impl std::fmt::Display for PrestageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BudgetExceeded { used, limit } => {
                write!(f, "PSE_BUDGET_EXCEEDED: {used}/{limit}")
            }
            Self::InvalidConfig { reason } => write!(f, "PSE_INVALID_CONFIG: {reason}"),
            Self::NoCandidates => write!(f, "PSE_NO_CANDIDATES"),
            Self::ThresholdInvalid { value } => write!(f, "PSE_THRESHOLD_INVALID: {value}"),
        }
    }
}

/// Validate pre-staging configuration.
pub fn validate_config(config: &PrestageConfig) -> Result<(), PrestageError> {
    if config.max_bytes == 0 {
        return Err(PrestageError::InvalidConfig {
            reason: "max_bytes must be > 0".into(),
        });
    }
    if config.max_artifacts_per_cycle == 0 {
        return Err(PrestageError::InvalidConfig {
            reason: "max_artifacts_per_cycle must be > 0".into(),
        });
    }
    if !(0.0..=1.0).contains(&config.probability_threshold) {
        return Err(PrestageError::ThresholdInvalid {
            value: config.probability_threshold,
        });
    }
    Ok(())
}

/// Evaluate candidates for pre-staging within budget.
///
/// INV-PSE-BUDGET: total staged bytes <= max_bytes.
/// INV-PSE-DETERMINISTIC: candidates are sorted by probability descending,
/// then by artifact_id for determinism.
pub fn evaluate_candidates(
    candidates: &[ArtifactCandidate],
    config: &PrestageConfig,
    trace_id: &str,
    timestamp: &str,
) -> Result<(Vec<PrestageDecision>, PrestageReport), PrestageError> {
    validate_config(config)?;

    if candidates.is_empty() {
        return Err(PrestageError::NoCandidates);
    }

    // Sort deterministically: probability descending, then artifact_id ascending
    let mut sorted: Vec<&ArtifactCandidate> = candidates.iter().collect();
    sorted.sort_by(|a, b| {
        b.predicted_probability
            .partial_cmp(&a.predicted_probability)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.artifact_id.cmp(&b.artifact_id))
    });

    let mut decisions = Vec::new();
    let mut budget_used: u64 = 0;
    let mut staged_count: usize = 0;

    for candidate in &sorted {
        // Below threshold
        if candidate.predicted_probability < config.probability_threshold {
            decisions.push(PrestageDecision {
                artifact_id: candidate.artifact_id.clone(),
                staged: false,
                reason: format!(
                    "probability {:.2} < threshold {:.2}",
                    candidate.predicted_probability, config.probability_threshold
                ),
                budget_remaining: config.max_bytes - budget_used,
            });
            continue;
        }

        // Max artifacts per cycle reached
        if staged_count >= config.max_artifacts_per_cycle {
            decisions.push(PrestageDecision {
                artifact_id: candidate.artifact_id.clone(),
                staged: false,
                reason: "max_artifacts_per_cycle reached".into(),
                budget_remaining: config.max_bytes - budget_used,
            });
            continue;
        }

        // INV-PSE-BUDGET: check budget
        if budget_used + candidate.size_bytes > config.max_bytes {
            decisions.push(PrestageDecision {
                artifact_id: candidate.artifact_id.clone(),
                staged: false,
                reason: format!(
                    "budget exceeded: {} + {} > {}",
                    budget_used, candidate.size_bytes, config.max_bytes
                ),
                budget_remaining: config.max_bytes - budget_used,
            });
            continue;
        }

        // Stage this artifact
        budget_used += candidate.size_bytes;
        staged_count += 1;
        decisions.push(PrestageDecision {
            artifact_id: candidate.artifact_id.clone(),
            staged: true,
            reason: format!(
                "probability {:.2} >= threshold",
                candidate.predicted_probability
            ),
            budget_remaining: config.max_bytes - budget_used,
        });
    }

    let report = PrestageReport {
        total_candidates: candidates.len(),
        staged_count,
        skipped_count: candidates.len() - staged_count,
        budget_used,
        budget_total: config.max_bytes,
        trace_id: trace_id.to_string(),
        timestamp: timestamp.to_string(),
    };

    Ok((decisions, report))
}

/// Measure prediction quality against actual needed artifacts.
///
/// INV-PSE-QUALITY: precision and recall are computed and reported.
pub fn measure_quality(decisions: &[PrestageDecision], actual_needed: &[String]) -> QualityMetrics {
    let staged: Vec<&str> = decisions
        .iter()
        .filter(|d| d.staged)
        .map(|d| d.artifact_id.as_str())
        .collect();

    if staged.is_empty() && actual_needed.is_empty() {
        return QualityMetrics {
            precision: 1.0,
            recall: 1.0,
            f1_score: 1.0,
        };
    }

    let true_positives = staged
        .iter()
        .filter(|id| actual_needed.contains(&id.to_string()))
        .count() as f64;

    let precision = if staged.is_empty() {
        0.0
    } else {
        true_positives / staged.len() as f64
    };

    let recall = if actual_needed.is_empty() {
        1.0
    } else {
        true_positives / actual_needed.len() as f64
    };

    let f1_score = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    QualityMetrics {
        precision,
        recall,
        f1_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PrestageConfig {
        PrestageConfig {
            max_bytes: 1000,
            probability_threshold: 0.5,
            max_artifacts_per_cycle: 10,
        }
    }

    fn cand(id: &str, size: u64, prob: f64) -> ArtifactCandidate {
        ArtifactCandidate {
            artifact_id: id.into(),
            size_bytes: size,
            predicted_probability: prob,
        }
    }

    #[test]
    fn stage_high_probability() {
        let candidates = vec![cand("a1", 100, 0.9)];
        let (decisions, report) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
        assert!(decisions[0].staged);
        assert_eq!(report.staged_count, 1);
    }

    #[test]
    fn skip_low_probability() {
        let candidates = vec![cand("a1", 100, 0.3)];
        let (decisions, _) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
        assert!(!decisions[0].staged);
    }

    #[test]
    fn budget_limit_respected() {
        let candidates = vec![cand("a1", 600, 0.9), cand("a2", 600, 0.8)];
        let (decisions, report) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
        assert!(decisions[0].staged);
        assert!(!decisions[1].staged);
        assert!(report.budget_used <= config().max_bytes);
    }

    #[test]
    fn max_artifacts_limit() {
        let mut cfg = config();
        cfg.max_artifacts_per_cycle = 2;
        let candidates = vec![
            cand("a1", 10, 0.9),
            cand("a2", 10, 0.8),
            cand("a3", 10, 0.7),
        ];
        let (_, report) = evaluate_candidates(&candidates, &cfg, "tr", "ts").unwrap();
        assert_eq!(report.staged_count, 2);
    }

    #[test]
    fn deterministic_order() {
        let candidates = vec![
            cand("c", 100, 0.7),
            cand("a", 100, 0.9),
            cand("b", 100, 0.7),
        ];
        let (d1, _) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
        let (d2, _) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
        let ids1: Vec<&str> = d1.iter().map(|d| d.artifact_id.as_str()).collect();
        let ids2: Vec<&str> = d2.iter().map(|d| d.artifact_id.as_str()).collect();
        assert_eq!(ids1, ids2);
    }

    #[test]
    fn sorted_by_probability_desc() {
        let candidates = vec![
            cand("low", 100, 0.6),
            cand("high", 100, 0.95),
            cand("mid", 100, 0.8),
        ];
        let (decisions, _) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
        // First staged should be the highest probability
        let staged: Vec<&str> = decisions
            .iter()
            .filter(|d| d.staged)
            .map(|d| d.artifact_id.as_str())
            .collect();
        assert_eq!(staged[0], "high");
    }

    #[test]
    fn no_candidates_error() {
        let err = evaluate_candidates(&[], &config(), "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "PSE_NO_CANDIDATES");
    }

    #[test]
    fn invalid_config_zero_budget() {
        let cfg = PrestageConfig {
            max_bytes: 0,
            ..config()
        };
        let err = evaluate_candidates(&[cand("a", 10, 0.9)], &cfg, "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "PSE_INVALID_CONFIG");
    }

    #[test]
    fn invalid_config_zero_max_artifacts() {
        let cfg = PrestageConfig {
            max_artifacts_per_cycle: 0,
            ..config()
        };
        let err = evaluate_candidates(&[cand("a", 10, 0.9)], &cfg, "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "PSE_INVALID_CONFIG");
    }

    #[test]
    fn threshold_out_of_range() {
        let cfg = PrestageConfig {
            probability_threshold: 1.5,
            ..config()
        };
        let err = evaluate_candidates(&[cand("a", 10, 0.9)], &cfg, "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "PSE_THRESHOLD_INVALID");
    }

    #[test]
    fn quality_perfect() {
        let decisions = vec![PrestageDecision {
            artifact_id: "a1".into(),
            staged: true,
            reason: "".into(),
            budget_remaining: 0,
        }];
        let actual = vec!["a1".to_string()];
        let q = measure_quality(&decisions, &actual);
        assert!((q.precision - 1.0).abs() < 1e-10);
        assert!((q.recall - 1.0).abs() < 1e-10);
    }

    #[test]
    fn quality_no_overlap() {
        let decisions = vec![PrestageDecision {
            artifact_id: "a1".into(),
            staged: true,
            reason: "".into(),
            budget_remaining: 0,
        }];
        let actual = vec!["a2".to_string()];
        let q = measure_quality(&decisions, &actual);
        assert!((q.precision - 0.0).abs() < 1e-10);
        assert!((q.recall - 0.0).abs() < 1e-10);
    }

    #[test]
    fn quality_partial() {
        let decisions = vec![
            PrestageDecision {
                artifact_id: "a1".into(),
                staged: true,
                reason: "".into(),
                budget_remaining: 0,
            },
            PrestageDecision {
                artifact_id: "a2".into(),
                staged: true,
                reason: "".into(),
                budget_remaining: 0,
            },
        ];
        let actual = vec!["a1".to_string(), "a3".to_string()];
        let q = measure_quality(&decisions, &actual);
        assert!((q.precision - 0.5).abs() < 1e-10); // 1/2 staged were needed
        assert!((q.recall - 0.5).abs() < 1e-10); // 1/2 needed were staged
    }

    #[test]
    fn report_has_trace() {
        let candidates = vec![cand("a1", 100, 0.9)];
        let (_, report) = evaluate_candidates(&candidates, &config(), "trace-x", "ts").unwrap();
        assert_eq!(report.trace_id, "trace-x");
    }

    #[test]
    fn budget_remaining_tracked() {
        let candidates = vec![cand("a1", 300, 0.9), cand("a2", 200, 0.8)];
        let (decisions, _) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
        assert_eq!(decisions[0].budget_remaining, 700); // 1000 - 300
        assert_eq!(decisions[1].budget_remaining, 500); // 1000 - 300 - 200
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            PrestageError::BudgetExceeded { used: 0, limit: 0 }.code(),
            "PSE_BUDGET_EXCEEDED"
        );
        assert_eq!(
            PrestageError::InvalidConfig { reason: "".into() }.code(),
            "PSE_INVALID_CONFIG"
        );
        assert_eq!(PrestageError::NoCandidates.code(), "PSE_NO_CANDIDATES");
        assert_eq!(
            PrestageError::ThresholdInvalid { value: 0.0 }.code(),
            "PSE_THRESHOLD_INVALID"
        );
    }

    #[test]
    fn error_display() {
        let e = PrestageError::BudgetExceeded {
            used: 100,
            limit: 50,
        };
        assert!(e.to_string().contains("PSE_BUDGET_EXCEEDED"));
    }

    #[test]
    fn default_config_valid() {
        assert!(validate_config(&PrestageConfig::default_config()).is_ok());
    }

    #[test]
    fn coverage_improvement() {
        // Baseline: no pre-staging → 0 staged
        // With pre-staging: some staged
        let candidates = vec![
            cand("a1", 100, 0.9),
            cand("a2", 100, 0.8),
            cand("a3", 100, 0.3),
        ];
        let (_, report) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
        assert!(
            report.staged_count > 0,
            "INV-PSE-COVERAGE: must stage something"
        );
        assert!(
            report.staged_count < report.total_candidates,
            "Not all staged (threshold filters)"
        );
    }
}
