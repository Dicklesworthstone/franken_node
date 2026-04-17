//! bd-mwvn: Policy action explainer distinguishing diagnostic vs guarantee confidence.
//!
//! Produces structured explanations for policy decisions that explicitly separate
//! two types of confidence:
//! - **Diagnostic confidence**: Bayesian posterior probability — heuristic, data-driven.
//! - **Guarantee confidence**: Guardrail verification — provable, invariant-backed.
//!
//! # Invariants
//!
//! - **INV-EXPLAIN-SEPARATION**: Every explanation has distinct diagnostic and
//!   guarantee sections with ambiguity-free wording.
//! - **INV-EXPLAIN-WORDING**: Diagnostic section never uses guarantee-language;
//!   guarantee section never uses diagnostic-language.
//! - **INV-EXPLAIN-COMPLETE**: Every explanation includes both sections, even
//!   when one has no data (e.g. zero observations still produces diagnostic section).

use serde::{Deserialize, Serialize};

use super::bayesian_diagnostics::{BayesianDiagnostics, CandidateRef, DiagnosticConfidence};
use super::decision_engine::{DecisionOutcome, DecisionReason, GuardrailId};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Explanation generated.
pub const EVD_EXPLAIN_001: &str = "EVD-EXPLAIN-001";
/// Wording validation passed.
pub const EVD_EXPLAIN_002: &str = "EVD-EXPLAIN-002";
/// Wording validation failed (includes offending terms).
pub const EVD_EXPLAIN_003: &str = "EVD-EXPLAIN-003";
/// Explanation serialized for API.
#[cfg(any(test, feature = "extended-surfaces"))]
pub const EVD_EXPLAIN_004: &str = "EVD-EXPLAIN-004";

// ---------------------------------------------------------------------------
// Wording vocabulary
// ---------------------------------------------------------------------------

/// Terms reserved for guarantee sections — forbidden in diagnostic text.
const GUARANTEE_VOCABULARY: &[&str] = &[
    "verified by guardrail",
    "proven within bounds",
    "guaranteed by invariant",
    "provably safe",
    "formally verified",
    "invariant-backed",
    "hard guarantee",
];

/// Terms reserved for diagnostic sections — forbidden in guarantee text.
const DIAGNOSTIC_VOCABULARY: &[&str] = &[
    "statistically suggested",
    "data indicates",
    "heuristic estimate",
    "posterior probability",
    "bayesian ranking",
    "observation-based",
    "data-driven estimate",
];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Diagnostic (Bayesian, heuristic) confidence section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticSection {
    /// Posterior probability of the chosen candidate.
    pub posterior_prob: Option<f64>,
    /// Number of observations that informed the ranking.
    pub observation_count: u64,
    /// 95% confidence interval on the posterior, if available.
    pub confidence_interval: Option<(f64, f64)>,
    /// Overall diagnostic confidence level.
    pub confidence_level: String,
    /// Natural-language summary using diagnostic vocabulary.
    pub summary: String,
}

/// Guarantee (guardrail, invariant-backed) confidence section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuaranteeSection {
    /// Whether all applicable guardrails passed for the chosen action.
    pub all_guardrails_passed: bool,
    /// List of guardrails that were checked.
    pub guardrails_checked: Vec<String>,
    /// List of invariants that back this guarantee.
    pub invariants_verified: Vec<String>,
    /// Natural-language summary using guarantee vocabulary.
    pub summary: String,
}

/// Explanation for why a higher-ranked alternative was blocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedExplanation {
    /// The candidate that was blocked.
    pub candidate: CandidateRef,
    /// Its Bayesian rank (0-indexed).
    pub bayesian_rank: usize,
    /// Which guardrails blocked it.
    pub blocked_by: Vec<GuardrailId>,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Complete policy explanation for a decision.
///
/// INV-EXPLAIN-SEPARATION: diagnostic and guarantee sections are always present
/// and use distinct vocabulary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExplanation {
    /// Diagnostic (heuristic, data-driven) confidence assessment.
    pub diagnostic_confidence: DiagnosticSection,
    /// Guarantee (provable, guardrail-backed) confidence assessment.
    pub guarantee_confidence: GuaranteeSection,
    /// Human-readable one-liner of what action was taken and why.
    pub action_summary: String,
    /// Explanations for why higher-ranked alternatives were blocked.
    pub blocked_alternatives: Vec<BlockedExplanation>,
    /// Epoch in which this explanation was generated.
    pub epoch_id: u64,
}

// ---------------------------------------------------------------------------
// Wording validation
// ---------------------------------------------------------------------------

/// Result of wording validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WordingValidation {
    pub valid: bool,
    pub violations: Vec<String>,
}

/// Validate that diagnostic text does not use guarantee vocabulary
/// and guarantee text does not use diagnostic vocabulary.
///
/// [EVD-EXPLAIN-002] on pass, [EVD-EXPLAIN-003] on failure.
pub fn validate_wording(explanation: &PolicyExplanation) -> WordingValidation {
    let mut violations = Vec::new();
    let diag_text = explanation.diagnostic_confidence.summary.to_lowercase();
    let guar_text = explanation.guarantee_confidence.summary.to_lowercase();

    // Diagnostic section must not use guarantee vocabulary.
    for term in GUARANTEE_VOCABULARY {
        if diag_text.contains(&term.to_lowercase()) {
            violations.push(format!(
                "diagnostic section contains guarantee term: '{term}'"
            ));
        }
    }

    // Guarantee section must not use diagnostic vocabulary.
    for term in DIAGNOSTIC_VOCABULARY {
        if guar_text.contains(&term.to_lowercase()) {
            violations.push(format!(
                "guarantee section contains diagnostic term: '{term}'"
            ));
        }
    }

    let valid = violations.is_empty();

    if valid {
        let _event = EVD_EXPLAIN_002;
    } else {
        let _event = EVD_EXPLAIN_003;
    }

    WordingValidation { valid, violations }
}

// ---------------------------------------------------------------------------
// PolicyExplainer
// ---------------------------------------------------------------------------

/// Generates structured explanations for policy decisions.
///
/// Separates diagnostic (Bayesian, heuristic) confidence from guarantee
/// (guardrail, invariant-backed) confidence so operators never confuse
/// a strong recommendation with a hard safety guarantee.
pub struct PolicyExplainer;

impl PolicyExplainer {
    /// Produce a structured explanation for a decision outcome.
    ///
    /// [EVD-EXPLAIN-001] explanation generated.
    pub fn explain(
        outcome: &DecisionOutcome,
        diagnostics: &BayesianDiagnostics,
    ) -> PolicyExplanation {
        let diagnostic_section = Self::build_diagnostic_section(outcome, diagnostics);
        let guarantee_section = Self::build_guarantee_section(outcome);
        let action_summary = Self::build_action_summary(outcome);
        let blocked_alternatives = Self::build_blocked_explanations(outcome);

        // [EVD-EXPLAIN-001]
        let _event = EVD_EXPLAIN_001;

        PolicyExplanation {
            diagnostic_confidence: diagnostic_section,
            guarantee_confidence: guarantee_section,
            action_summary,
            blocked_alternatives,
            epoch_id: outcome.epoch_id,
        }
    }

    fn build_diagnostic_section(
        outcome: &DecisionOutcome,
        diagnostics: &BayesianDiagnostics,
    ) -> DiagnosticSection {
        let obs_count = diagnostics.total_observations();
        let confidence = diagnostics.overall_confidence();
        let confidence_str = match confidence {
            DiagnosticConfidence::Low => "low",
            DiagnosticConfidence::Medium => "medium",
            DiagnosticConfidence::High => "high",
        };

        if let Some(ref chosen) = outcome.chosen {
            let candidates: Vec<CandidateRef> = std::iter::once(chosen.clone())
                .chain(outcome.blocked.iter().map(|b| b.candidate.clone()))
                .collect();
            let ranked = diagnostics.rank_candidates(&candidates, &[]);
            let chosen_ranked = ranked.iter().find(|r| &r.candidate_ref == chosen);

            let (posterior, ci) = match chosen_ranked {
                Some(r) => (Some(r.posterior_prob), Some(r.confidence_interval)),
                None => (None, None),
            };

            let summary = if obs_count == 0 {
                "Insufficient data for diagnostic ranking. This is a heuristic estimate based on uniform priors.".to_string()
            } else {
                format!(
                    "Data indicates the chosen action is statistically suggested with {confidence_str} diagnostic confidence based on {obs_count} observations. This is a heuristic estimate, not a safety guarantee."
                )
            };

            DiagnosticSection {
                posterior_prob: posterior,
                observation_count: obs_count,
                confidence_interval: ci,
                confidence_level: confidence_str.to_string(),
                summary,
            }
        } else {
            let summary = if obs_count == 0 {
                "No observations available. Diagnostic ranking produced no actionable recommendation.".to_string()
            } else {
                format!(
                    "Data indicates {obs_count} observations were processed with {confidence_str} diagnostic confidence, but no candidate was eligible for selection. This is an observation-based assessment."
                )
            };

            DiagnosticSection {
                posterior_prob: None,
                observation_count: obs_count,
                confidence_interval: None,
                confidence_level: confidence_str.to_string(),
                summary,
            }
        }
    }

    fn build_guarantee_section(outcome: &DecisionOutcome) -> GuaranteeSection {
        let has_chosen = outcome.chosen.is_some();
        let has_blocked = !outcome.blocked.is_empty();

        let guardrails_checked: Vec<String> = outcome
            .blocked
            .iter()
            .flat_map(|b| b.blocked_by.iter().map(|g| g.as_str().to_string()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        let invariants = if has_chosen {
            vec![
                "INV-DECIDE-PRECEDENCE".to_string(),
                "INV-GUARD-ANYTIME".to_string(),
            ]
        } else {
            vec![
                "INV-DECIDE-PRECEDENCE".to_string(),
                "INV-DECIDE-NO-PANIC".to_string(),
                "INV-GUARD-ANYTIME".to_string(),
            ]
        };

        let summary = if has_chosen && !has_blocked {
            "All guardrails passed. The chosen action is verified by guardrail checks and proven within bounds of all monitored invariants.".to_string()
        } else if has_chosen && has_blocked {
            format!(
                "The chosen action is verified by guardrail checks. {} higher-ranked alternative(s) were blocked, guaranteed by invariant enforcement.",
                outcome.blocked.len()
            )
        } else {
            "No action could be verified by guardrail checks. All candidates were blocked, guaranteed by invariant enforcement to prevent unsafe operations.".to_string()
        };

        GuaranteeSection {
            all_guardrails_passed: has_chosen && !has_blocked,
            guardrails_checked,
            invariants_verified: invariants,
            summary,
        }
    }

    fn build_action_summary(outcome: &DecisionOutcome) -> String {
        match &outcome.reason {
            DecisionReason::TopCandidateAccepted => {
                format!(
                    "Action '{}' selected: top-ranked candidate passed all guardrails.",
                    outcome.chosen.as_ref().map_or("unknown", |c| &c.0)
                )
            }
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank } => {
                format!(
                    "Action '{}' selected: top candidate blocked, fell back to rank {}.",
                    outcome.chosen.as_ref().map_or("unknown", |c| &c.0),
                    fallback_rank
                )
            }
            DecisionReason::AllCandidatesBlocked => {
                format!(
                    "No action selected: all {} candidate(s) blocked by guardrails.",
                    outcome.blocked.len()
                )
            }
            DecisionReason::NoCandidates => {
                "No action selected: no candidates were provided.".to_string()
            }
        }
    }

    fn build_blocked_explanations(outcome: &DecisionOutcome) -> Vec<BlockedExplanation> {
        outcome
            .blocked
            .iter()
            .map(|b| {
                let guardrail_names: Vec<String> = b
                    .blocked_by
                    .iter()
                    .map(|g| g.as_str().to_string())
                    .collect();
                let explanation = format!(
                    "Candidate '{}' (rank {}) was blocked by guardrail(s): {}. Reasons: {}",
                    b.candidate.0,
                    b.bayesian_rank,
                    guardrail_names.join(", "),
                    b.reasons.join("; "),
                );
                BlockedExplanation {
                    candidate: b.candidate.clone(),
                    bayesian_rank: b.bayesian_rank,
                    blocked_by: b.blocked_by.clone(),
                    explanation,
                }
            })
            .collect()
    }

    /// Serialize explanation to JSON.
    ///
    /// [EVD-EXPLAIN-004] explanation serialized.
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn to_json(explanation: &PolicyExplanation) -> Result<String, serde_json::Error> {
        let _event = EVD_EXPLAIN_004;
        serde_json::to_string_pretty(explanation)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::bayesian_diagnostics::{BayesianDiagnostics, CandidateRef, Observation};
    use crate::policy::decision_engine::{
        BlockedCandidate, DecisionOutcome, DecisionReason, GuardrailId,
    };

    fn c(id: &str) -> CandidateRef {
        CandidateRef::new(id)
    }

    fn obs(id: &str, success: bool) -> Observation {
        Observation::new(c(id), success, 1)
    }

    fn top_accepted_outcome() -> DecisionOutcome {
        DecisionOutcome {
            chosen: Some(c("repair-A")),
            blocked: Vec::new(),
            reason: DecisionReason::TopCandidateAccepted,
            epoch_id: 42,
        }
    }

    fn fallback_outcome() -> DecisionOutcome {
        DecisionOutcome {
            chosen: Some(c("conservative")),
            blocked: vec![BlockedCandidate {
                candidate: c("aggressive"),
                blocked_by: vec![GuardrailId::new("memory_budget")],
                bayesian_rank: 0,
                reasons: vec!["memory utilization 96% exceeds threshold".to_string()],
            }],
            reason: DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 1 },
            epoch_id: 42,
        }
    }

    fn all_blocked_outcome() -> DecisionOutcome {
        DecisionOutcome {
            chosen: None,
            blocked: vec![
                BlockedCandidate {
                    candidate: c("A"),
                    blocked_by: vec![GuardrailId::new("durability_budget")],
                    bayesian_rank: 0,
                    reasons: vec!["durability below minimum".to_string()],
                },
                BlockedCandidate {
                    candidate: c("B"),
                    blocked_by: vec![GuardrailId::new("durability_budget")],
                    bayesian_rank: 1,
                    reasons: vec!["durability below minimum".to_string()],
                },
            ],
            reason: DecisionReason::AllCandidatesBlocked,
            epoch_id: 42,
        }
    }

    fn no_candidates_outcome() -> DecisionOutcome {
        DecisionOutcome {
            chosen: None,
            blocked: Vec::new(),
            reason: DecisionReason::NoCandidates,
            epoch_id: 42,
        }
    }

    fn diagnostics_with_observations() -> BayesianDiagnostics {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..15 {
            d.update(&obs("repair-A", true));
            d.update(&obs("conservative", true));
            d.update(&obs("aggressive", false));
        }
        d
    }

    fn empty_diagnostics() -> BayesianDiagnostics {
        BayesianDiagnostics::new()
    }

    // -- Basic construction --

    #[test]
    fn test_explain_top_accepted() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        assert!(explanation.action_summary.contains("repair-A"));
        assert!(explanation.action_summary.contains("top-ranked"));
    }

    #[test]
    fn test_explain_fallback() {
        let explanation =
            PolicyExplainer::explain(&fallback_outcome(), &diagnostics_with_observations());
        assert!(explanation.action_summary.contains("conservative"));
        assert!(explanation.action_summary.contains("fell back"));
    }

    #[test]
    fn test_explain_all_blocked() {
        let explanation =
            PolicyExplainer::explain(&all_blocked_outcome(), &diagnostics_with_observations());
        assert!(explanation.action_summary.contains("No action"));
        assert!(explanation.action_summary.contains("blocked"));
    }

    #[test]
    fn test_explain_no_candidates() {
        let explanation = PolicyExplainer::explain(&no_candidates_outcome(), &empty_diagnostics());
        assert!(explanation.action_summary.contains("no candidates"));
    }

    // -- Diagnostic section always present --

    #[test]
    fn test_diagnostic_section_present_with_observations() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        assert!(explanation.diagnostic_confidence.observation_count > 0);
        assert!(!explanation.diagnostic_confidence.summary.is_empty());
    }

    #[test]
    fn test_diagnostic_section_present_without_observations() {
        let explanation = PolicyExplainer::explain(&top_accepted_outcome(), &empty_diagnostics());
        assert_eq!(explanation.diagnostic_confidence.observation_count, 0);
        assert!(!explanation.diagnostic_confidence.summary.is_empty());
        assert!(
            explanation
                .diagnostic_confidence
                .summary
                .contains("Insufficient data")
        );
    }

    #[test]
    fn test_diagnostic_section_present_all_blocked() {
        let explanation =
            PolicyExplainer::explain(&all_blocked_outcome(), &diagnostics_with_observations());
        assert!(!explanation.diagnostic_confidence.summary.is_empty());
    }

    // -- Guarantee section always present --

    #[test]
    fn test_guarantee_section_present_accepted() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        assert!(explanation.guarantee_confidence.all_guardrails_passed);
        assert!(!explanation.guarantee_confidence.summary.is_empty());
    }

    #[test]
    fn test_guarantee_section_present_fallback() {
        let explanation =
            PolicyExplainer::explain(&fallback_outcome(), &diagnostics_with_observations());
        assert!(!explanation.guarantee_confidence.all_guardrails_passed);
        assert!(!explanation.guarantee_confidence.summary.is_empty());
    }

    #[test]
    fn test_guarantee_section_present_all_blocked() {
        let explanation =
            PolicyExplainer::explain(&all_blocked_outcome(), &diagnostics_with_observations());
        assert!(!explanation.guarantee_confidence.all_guardrails_passed);
        assert!(
            explanation
                .guarantee_confidence
                .summary
                .contains("No action")
        );
    }

    // -- Wording validation --

    #[test]
    fn test_wording_valid_top_accepted() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        let validation = validate_wording(&explanation);
        assert!(validation.valid, "Violations: {:?}", validation.violations);
    }

    #[test]
    fn test_wording_valid_fallback() {
        let explanation =
            PolicyExplainer::explain(&fallback_outcome(), &diagnostics_with_observations());
        let validation = validate_wording(&explanation);
        assert!(validation.valid, "Violations: {:?}", validation.violations);
    }

    #[test]
    fn test_wording_valid_all_blocked() {
        let explanation =
            PolicyExplainer::explain(&all_blocked_outcome(), &diagnostics_with_observations());
        let validation = validate_wording(&explanation);
        assert!(validation.valid, "Violations: {:?}", validation.violations);
    }

    #[test]
    fn test_wording_valid_no_candidates() {
        let explanation = PolicyExplainer::explain(&no_candidates_outcome(), &empty_diagnostics());
        let validation = validate_wording(&explanation);
        assert!(validation.valid, "Violations: {:?}", validation.violations);
    }

    #[test]
    fn test_wording_valid_empty_diagnostics() {
        let explanation = PolicyExplainer::explain(&top_accepted_outcome(), &empty_diagnostics());
        let validation = validate_wording(&explanation);
        assert!(validation.valid, "Violations: {:?}", validation.violations);
    }

    #[test]
    fn test_wording_rejects_guarantee_term_in_diagnostic() {
        let mut explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        explanation.diagnostic_confidence.summary =
            "This is verified by guardrail and statistically suggested.".to_string();
        let validation = validate_wording(&explanation);
        assert!(!validation.valid);
        assert!(!validation.violations.is_empty());
    }

    #[test]
    fn test_wording_rejects_diagnostic_term_in_guarantee() {
        let mut explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        explanation.guarantee_confidence.summary =
            "Data indicates this is safe and proven within bounds.".to_string();
        let validation = validate_wording(&explanation);
        assert!(!validation.valid);
    }

    #[test]
    fn test_wording_rejects_provably_safe_in_diagnostic() {
        let mut explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        explanation.diagnostic_confidence.summary =
            "The policy is provably safe according to the diagnostic section.".to_string();

        let validation = validate_wording(&explanation);

        assert!(!validation.valid);
        assert!(validation.violations.iter().any(|violation| {
            violation.contains("diagnostic section contains guarantee term")
                && violation.contains("provably safe")
        }));
    }

    #[test]
    fn test_wording_rejects_hard_guarantee_in_diagnostic_case_insensitive() {
        let mut explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        explanation.diagnostic_confidence.summary =
            "This diagnostic result is a HARD GUARANTEE for operators.".to_string();

        let validation = validate_wording(&explanation);

        assert!(!validation.valid);
        assert!(
            validation
                .violations
                .iter()
                .any(|violation| violation.contains("hard guarantee"))
        );
    }

    #[test]
    fn test_wording_rejects_posterior_probability_in_guarantee() {
        let mut explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        explanation.guarantee_confidence.summary =
            "The guardrail guarantee is based on posterior probability.".to_string();

        let validation = validate_wording(&explanation);

        assert!(!validation.valid);
        assert!(validation.violations.iter().any(|violation| {
            violation.contains("guarantee section contains diagnostic term")
                && violation.contains("posterior probability")
        }));
    }

    #[test]
    fn test_wording_rejects_bayesian_ranking_in_guarantee_case_insensitive() {
        let mut explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        explanation.guarantee_confidence.summary =
            "The invariant section relies on BAYESIAN RANKING evidence.".to_string();

        let validation = validate_wording(&explanation);

        assert!(!validation.valid);
        assert!(
            validation
                .violations
                .iter()
                .any(|violation| violation.contains("bayesian ranking"))
        );
    }

    #[test]
    fn test_wording_reports_both_section_violations() {
        let mut explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        explanation.diagnostic_confidence.summary =
            "Diagnostic text claims it is formally verified.".to_string();
        explanation.guarantee_confidence.summary =
            "Guarantee text claims it is statistically suggested.".to_string();

        let validation = validate_wording(&explanation);

        assert!(!validation.valid);
        assert_eq!(validation.violations.len(), 2);
        assert!(
            validation
                .violations
                .iter()
                .any(|violation| violation.contains("formally verified"))
        );
        assert!(
            validation
                .violations
                .iter()
                .any(|violation| violation.contains("statistically suggested"))
        );
    }

    #[test]
    fn test_wording_reports_multiple_terms_from_one_section() {
        let mut explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        explanation.diagnostic_confidence.summary =
            "This is verified by guardrail and guaranteed by invariant.".to_string();

        let validation = validate_wording(&explanation);

        assert!(!validation.valid);
        assert_eq!(validation.violations.len(), 2);
        assert!(
            validation
                .violations
                .iter()
                .any(|violation| violation.contains("verified by guardrail"))
        );
        assert!(
            validation
                .violations
                .iter()
                .any(|violation| violation.contains("guaranteed by invariant"))
        );
    }

    #[test]
    fn test_wording_rejects_observation_based_in_guarantee() {
        let mut explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        explanation.guarantee_confidence.summary =
            "This guarantee is an observation-based safety statement.".to_string();

        let validation = validate_wording(&explanation);

        assert!(!validation.valid);
        assert!(
            validation
                .violations
                .iter()
                .any(|violation| violation.contains("observation-based"))
        );
    }

    // -- Blocked alternatives --

    #[test]
    fn test_blocked_alternatives_empty_when_top_accepted() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        assert!(explanation.blocked_alternatives.is_empty());
    }

    #[test]
    fn test_blocked_alternatives_present_on_fallback() {
        let explanation =
            PolicyExplainer::explain(&fallback_outcome(), &diagnostics_with_observations());
        assert_eq!(explanation.blocked_alternatives.len(), 1);
        assert_eq!(
            explanation.blocked_alternatives[0].candidate,
            c("aggressive")
        );
        assert!(!explanation.blocked_alternatives[0].blocked_by.is_empty());
    }

    #[test]
    fn test_blocked_alternatives_present_on_all_blocked() {
        let explanation =
            PolicyExplainer::explain(&all_blocked_outcome(), &diagnostics_with_observations());
        assert_eq!(explanation.blocked_alternatives.len(), 2);
    }

    #[test]
    fn test_blocked_explanation_has_guardrail_ids() {
        let explanation =
            PolicyExplainer::explain(&fallback_outcome(), &diagnostics_with_observations());
        let blocked = &explanation.blocked_alternatives[0];
        assert!(
            blocked
                .blocked_by
                .iter()
                .any(|g| g.as_str() == "memory_budget")
        );
    }

    // -- Serialization --

    #[test]
    fn test_serialization_roundtrip() {
        let explanation =
            PolicyExplainer::explain(&fallback_outcome(), &diagnostics_with_observations());
        let json = PolicyExplainer::to_json(&explanation).unwrap();
        let parsed: PolicyExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.epoch_id, explanation.epoch_id);
        assert_eq!(parsed.action_summary, explanation.action_summary);
    }

    #[test]
    fn test_json_has_both_top_level_sections() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        let json = PolicyExplainer::to_json(&explanation).unwrap();
        assert!(json.contains("diagnostic_confidence"));
        assert!(json.contains("guarantee_confidence"));
    }

    // -- Epoch propagation --

    #[test]
    fn test_epoch_propagated() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        assert_eq!(explanation.epoch_id, 42);
    }

    // -- Event codes --

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(EVD_EXPLAIN_001, "EVD-EXPLAIN-001");
        assert_eq!(EVD_EXPLAIN_002, "EVD-EXPLAIN-002");
        assert_eq!(EVD_EXPLAIN_003, "EVD-EXPLAIN-003");
        assert_eq!(EVD_EXPLAIN_004, "EVD-EXPLAIN-004");
    }

    // -- Vocabulary constants --

    #[test]
    fn test_guarantee_vocabulary_non_empty() {
        assert!(!GUARANTEE_VOCABULARY.is_empty());
    }

    #[test]
    fn test_diagnostic_vocabulary_non_empty() {
        assert!(!DIAGNOSTIC_VOCABULARY.is_empty());
    }

    #[test]
    fn test_vocabularies_are_disjoint() {
        for gt in GUARANTEE_VOCABULARY {
            for dt in DIAGNOSTIC_VOCABULARY {
                assert_ne!(
                    gt.to_lowercase(),
                    dt.to_lowercase(),
                    "vocabularies must be disjoint"
                );
            }
        }
    }

    // -- Confidence level strings --

    #[test]
    fn test_confidence_level_low_with_no_observations() {
        let explanation = PolicyExplainer::explain(&top_accepted_outcome(), &empty_diagnostics());
        assert_eq!(explanation.diagnostic_confidence.confidence_level, "low");
    }

    #[test]
    fn test_confidence_level_with_many_observations() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        assert!(
            explanation.diagnostic_confidence.confidence_level == "medium"
                || explanation.diagnostic_confidence.confidence_level == "high"
        );
    }

    // -- Invariants in guarantee section --

    #[test]
    fn test_invariants_verified_present() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        assert!(
            !explanation
                .guarantee_confidence
                .invariants_verified
                .is_empty()
        );
        assert!(
            explanation
                .guarantee_confidence
                .invariants_verified
                .contains(&"INV-DECIDE-PRECEDENCE".to_string())
        );
    }

    #[test]
    fn test_all_blocked_has_no_panic_invariant() {
        let explanation =
            PolicyExplainer::explain(&all_blocked_outcome(), &diagnostics_with_observations());
        assert!(
            explanation
                .guarantee_confidence
                .invariants_verified
                .contains(&"INV-DECIDE-NO-PANIC".to_string())
        );
    }

    // -- WordingValidation serialization --

    #[test]
    fn test_wording_validation_serialization() {
        let wv = WordingValidation {
            valid: true,
            violations: Vec::new(),
        };
        let json = serde_json::to_string(&wv).unwrap();
        let parsed: WordingValidation = serde_json::from_str(&json).unwrap();
        assert!(parsed.valid);
    }

    // -- Diagnostic section uses correct language --

    #[test]
    fn test_diagnostic_summary_uses_heuristic_language() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        let summary = &explanation.diagnostic_confidence.summary;
        let has_diag_term = DIAGNOSTIC_VOCABULARY
            .iter()
            .any(|term| summary.to_lowercase().contains(&term.to_lowercase()));
        assert!(
            has_diag_term,
            "Diagnostic summary should use diagnostic vocabulary: {summary}"
        );
    }

    // -- Guarantee section uses correct language --

    #[test]
    fn test_guarantee_summary_uses_guarantee_language() {
        let explanation =
            PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        let summary = &explanation.guarantee_confidence.summary;
        let has_guar_term = GUARANTEE_VOCABULARY
            .iter()
            .any(|term| summary.to_lowercase().contains(&term.to_lowercase()));
        assert!(
            has_guar_term,
            "Guarantee summary should use guarantee vocabulary: {summary}"
        );
    }

    // ---------------------------------------------------------------------------
    // NEGATIVE-PATH TESTS: Security hardening for policy explanation
    // ---------------------------------------------------------------------------

    #[test]
    fn negative_unicode_injection_in_explanations_and_identifiers() {
        // Create outcome with Unicode injection in candidate IDs
        let malicious_outcome = DecisionOutcome {
            chosen: Some(CandidateRef::new("\u{202E}suoicilam\u{202D}legitimate_action")),
            blocked: vec![
                BlockedCandidate {
                    candidate: CandidateRef::new("normal\u{200B}\u{200C}hidden\u{FEFF}candidate"),
                    blocked_by: vec![GuardrailId::new("guardrail\u{0000}\ninjection\r\t")],
                    bayesian_rank: 0,
                    reasons: vec![
                        "reason with\u{202E}attack\u{202D} and path traversal: ../../../etc/passwd\0".to_string(),
                        "another reason\nwith\rcontrol\tchars".to_string(),
                    ],
                },
                BlockedCandidate {
                    candidate: CandidateRef::new("candidate_2"),
                    blocked_by: vec![
                        GuardrailId::new("memory\u{2028}budget"),
                        GuardrailId::new("durability\u{2029}budget"),
                    ],
                    bayesian_rank: 1,
                    reasons: vec!["multi\u{0085}line\u{000C}injection".to_string()],
                },
            ],
            reason: DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 0 },
            epoch_id: u64::MAX, // Also test epoch overflow
        };

        // Create diagnostics with Unicode injection
        let mut unicode_diagnostics = BayesianDiagnostics::new();
        for _ in 0..10 {
            unicode_diagnostics.update(&Observation::new(
                CandidateRef::new("\u{202E}suoicilam\u{202D}legitimate_action"),
                true,
                1,
            ));
            unicode_diagnostics.update(&Observation::new(
                CandidateRef::new("normal\u{200B}\u{200C}hidden\u{FEFF}candidate"),
                false,
                1,
            ));
        }

        let explanation = PolicyExplainer::explain(&malicious_outcome, &unicode_diagnostics);

        // Verify Unicode is preserved in explanations for analysis
        assert!(explanation.action_summary.contains('\u{202E}'));
        assert_eq!(explanation.epoch_id, u64::MAX);

        // Check blocked alternatives preserve Unicode injection
        assert_eq!(explanation.blocked_alternatives.len(), 2);
        assert!(explanation.blocked_alternatives[0].candidate.0.contains('\u{200B}'));
        assert!(explanation.blocked_alternatives[0].explanation.contains('\u{202E}'));
        assert!(explanation.blocked_alternatives[0].explanation.contains('\0'));

        // Check guardrail names preserve injection
        let guardrail_names: Vec<String> = explanation.blocked_alternatives
            .iter()
            .flat_map(|b| b.blocked_by.iter())
            .map(|g| g.as_str().to_string())
            .collect();
        assert!(guardrail_names.iter().any(|name| name.contains('\u{0000}')));

        // Test JSON serialization preserves Unicode for analysis
        let json = PolicyExplainer::to_json(&explanation).unwrap();
        let parsed: PolicyExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action_summary, explanation.action_summary);
        assert_eq!(parsed.epoch_id, u64::MAX);
    }

    #[test]
    fn negative_wording_validation_bypass_and_vocabulary_confusion_attacks() {
        // Test case-insensitive validation bypass attempts
        let mut bypass_explanation = PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());

        // Attempt to bypass validation with case variations
        bypass_explanation.diagnostic_confidence.summary = "This is VERIFIED BY GUARDRAIL with alternating case.".to_string();
        bypass_explanation.guarantee_confidence.summary = "This guarantee uses DATA INDICATES for confusion.".to_string();

        let validation = validate_wording(&bypass_explanation);
        assert!(!validation.valid);
        assert_eq!(validation.violations.len(), 2);

        // Test Unicode homoglyph attacks in vocabulary
        let mut homoglyph_explanation = PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        homoglyph_explanation.diagnostic_confidence.summary = "This is veriﬁed by guardrail with unicode fi ligature.".to_string(); // \u{FB01}

        let homoglyph_validation = validate_wording(&homoglyph_explanation);
        // Current validation should miss homoglyph, but this tests the edge case
        assert!(homoglyph_validation.valid); // Demonstrates potential vulnerability

        // Test partial term matching edge cases
        let mut partial_explanation = PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        partial_explanation.diagnostic_confidence.summary = "verified by guardrail suffix".to_string();
        partial_explanation.guarantee_confidence.summary = "prefix data indicates approach".to_string();

        let partial_validation = validate_wording(&partial_explanation);
        assert!(!partial_validation.valid);
        assert_eq!(partial_validation.violations.len(), 2);

        // Test vocabulary injection via embedded terms
        let mut embedded_explanation = PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        embedded_explanation.diagnostic_confidence.summary = "not_verified by guardrail_but_close".to_string();
        embedded_explanation.guarantee_confidence.summary = "no_data indicates_anything".to_string();

        let embedded_validation = validate_wording(&embedded_explanation);
        // Should still catch because contains() finds substrings
        assert!(!embedded_validation.valid);

        // Test maximum violations (all terms at once)
        let mut max_violation_explanation = PolicyExplainer::explain(&top_accepted_outcome(), &diagnostics_with_observations());
        max_violation_explanation.diagnostic_confidence.summary = GUARANTEE_VOCABULARY.join(" ") + " mixed with diagnostic terms";
        max_violation_explanation.guarantee_confidence.summary = DIAGNOSTIC_VOCABULARY.join(" ") + " mixed with guarantee terms";

        let max_validation = validate_wording(&max_violation_explanation);
        assert!(!max_validation.valid);
        assert!(max_validation.violations.len() >= GUARANTEE_VOCABULARY.len() + DIAGNOSTIC_VOCABULARY.len());
    }

    #[test]
    fn negative_confidence_manipulation_and_floating_point_attacks() {
        // Create diagnostics with extreme floating point values
        let mut extreme_diagnostics = BayesianDiagnostics::new();

        // Add some valid observations first
        for _ in 0..5 {
            extreme_diagnostics.update(&obs("normal", true));
        }

        let mut floating_outcome = top_accepted_outcome();
        floating_outcome.chosen = Some(c("extreme_float_test"));

        let explanation = PolicyExplainer::explain(&floating_outcome, &extreme_diagnostics);

        // Test confidence interval edge cases
        let mut manual_explanation = explanation.clone();
        manual_explanation.diagnostic_confidence.posterior_prob = Some(f64::NAN);
        manual_explanation.diagnostic_confidence.confidence_interval = Some((f64::NEG_INFINITY, f64::INFINITY));

        // JSON serialization should handle extreme values
        let json_result = PolicyExplainer::to_json(&manual_explanation);
        assert!(json_result.is_ok());

        // Test confidence level manipulation
        let confidence_levels = vec!["low", "medium", "high", "invalid", "", "\0", "extremely_high"];
        for level in confidence_levels {
            let mut conf_explanation = explanation.clone();
            conf_explanation.diagnostic_confidence.confidence_level = level.to_string();

            let conf_json = PolicyExplainer::to_json(&conf_explanation);
            assert!(conf_json.is_ok());

            if let Ok(json_str) = conf_json {
                let parsed_result: Result<PolicyExplanation, _> = serde_json::from_str(&json_str);
                assert!(parsed_result.is_ok());
            }
        }

        // Test observation count overflow
        let mut overflow_explanation = explanation.clone();
        overflow_explanation.diagnostic_confidence.observation_count = u64::MAX;

        let overflow_json = PolicyExplainer::to_json(&overflow_explanation);
        assert!(overflow_json.is_ok());

        // Test negative probabilities and out-of-bounds intervals
        let mut bounds_explanation = explanation.clone();
        bounds_explanation.diagnostic_confidence.posterior_prob = Some(-0.5);
        bounds_explanation.diagnostic_confidence.confidence_interval = Some((-1.0, 2.0));

        let bounds_json = PolicyExplainer::to_json(&bounds_explanation);
        assert!(bounds_json.is_ok());

        // Test very small and very large floating point values
        let extreme_values = vec![
            f64::MIN, f64::MAX, f64::EPSILON, -f64::EPSILON,
            1e-100, 1e100, -1e-100, -1e100
        ];

        for value in extreme_values {
            let mut extreme_explanation = explanation.clone();
            extreme_explanation.diagnostic_confidence.posterior_prob = Some(value);
            extreme_explanation.diagnostic_confidence.confidence_interval = Some((value, value + 0.01));

            let extreme_json = PolicyExplainer::to_json(&extreme_explanation);
            assert!(extreme_json.is_ok());
        }
    }

    #[test]
    fn negative_json_serialization_injection_and_corruption_attacks() {
        let base_explanation = PolicyExplainer::explain(&fallback_outcome(), &diagnostics_with_observations());

        // Test JSON injection in string fields
        let json_injection_fields = vec![
            (r#"injection","malicious":"payload"#, "action_summary"),
            (r#"escape\"sequence\"attack"#, "summary"),
            ("line\nbreak\rattack\ttabs", "explanation"),
            ("\u{0008}\u{000C}\u{0085}\u{2028}\u{2029}", "control_chars"), // Various unicode control chars
        ];

        for (injection_str, field_type) in json_injection_fields {
            let mut inject_explanation = base_explanation.clone();

            match field_type {
                "action_summary" => inject_explanation.action_summary = injection_str.to_string(),
                "summary" => {
                    inject_explanation.diagnostic_confidence.summary = injection_str.to_string();
                    inject_explanation.guarantee_confidence.summary = injection_str.to_string();
                },
                "explanation" => {
                    if let Some(blocked) = inject_explanation.blocked_alternatives.get_mut(0) {
                        blocked.explanation = injection_str.to_string();
                    }
                },
                "control_chars" => {
                    inject_explanation.diagnostic_confidence.confidence_level = injection_str.to_string();
                },
                _ => {}
            }

            // JSON serialization should escape properly
            let json_result = PolicyExplainer::to_json(&inject_explanation);
            assert!(json_result.is_ok(), "JSON serialization failed for field: {}", field_type);

            if let Ok(json_str) = json_result {
                // Verify JSON is parseable
                let parse_result: Result<PolicyExplanation, _> = serde_json::from_str(&json_str);
                assert!(parse_result.is_ok(), "JSON parsing failed for field: {}", field_type);

                // Verify no unescaped injection in final JSON
                assert!(!json_str.contains(r#""malicious""#));
                assert!(!json_str.contains(r#""payload""#));

                // Verify proper escaping of quotes and control characters
                if injection_str.contains('"') {
                    assert!(json_str.contains(r#"\""#)); // Should be escaped
                }
            }
        }

        // Test massive string field attacks
        let huge_strings = vec![
            ("huge_summary", "A".repeat(1_000_000)),
            ("huge_explanation", "B".repeat(500_000)),
            ("huge_confidence_level", "C".repeat(100_000)),
        ];

        for (field_name, huge_str) in huge_strings {
            let mut huge_explanation = base_explanation.clone();

            match field_name {
                "huge_summary" => huge_explanation.diagnostic_confidence.summary = huge_str,
                "huge_explanation" => {
                    if let Some(blocked) = huge_explanation.blocked_alternatives.get_mut(0) {
                        blocked.explanation = huge_str;
                    }
                },
                "huge_confidence_level" => huge_explanation.diagnostic_confidence.confidence_level = huge_str,
                _ => {}
            }

            let huge_json = PolicyExplainer::to_json(&huge_explanation);
            assert!(huge_json.is_ok(), "Failed to serialize huge string in field: {}", field_name);
        }

        // Test empty string edge cases
        let mut empty_explanation = base_explanation.clone();
        empty_explanation.action_summary = "".to_string();
        empty_explanation.diagnostic_confidence.summary = "".to_string();
        empty_explanation.guarantee_confidence.summary = "".to_string();
        empty_explanation.diagnostic_confidence.confidence_level = "".to_string();

        let empty_json = PolicyExplainer::to_json(&empty_explanation);
        assert!(empty_json.is_ok());
    }

    #[test]
    fn negative_memory_exhaustion_with_massive_blocked_alternatives() {
        // Create outcome with massive number of blocked candidates
        let massive_blocked: Vec<BlockedCandidate> = (0..10_000)
            .map(|i| BlockedCandidate {
                candidate: CandidateRef::new(&format!("massive_candidate_{}", i)),
                blocked_by: vec![
                    GuardrailId::new(&format!("guardrail_a_{}", i)),
                    GuardrailId::new(&format!("guardrail_b_{}", i)),
                    GuardrailId::new(&format!("guardrail_c_{}", i)),
                ],
                bayesian_rank: i,
                reasons: vec![
                    format!("reason_1_{}: memory exhaustion attempt with very long reason text repeated many times {}", i, "x".repeat(1000)),
                    format!("reason_2_{}: another massive reason with large content {}", i, "y".repeat(1000)),
                    format!("reason_3_{}: third reason to increase memory pressure {}", i, "z".repeat(1000)),
                ],
            })
            .collect();

        let massive_outcome = DecisionOutcome {
            chosen: Some(c("survivor")),
            blocked: massive_blocked,
            reason: DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 9999 },
            epoch_id: 12345,
        };

        let massive_diagnostics = diagnostics_with_observations();
        let explanation = PolicyExplainer::explain(&massive_outcome, &massive_diagnostics);

        // Should handle large number of blocked alternatives
        assert_eq!(explanation.blocked_alternatives.len(), 10_000);

        // Each blocked explanation should be properly formed
        for (i, blocked) in explanation.blocked_alternatives.iter().enumerate() {
            assert_eq!(blocked.bayesian_rank, i);
            assert_eq!(blocked.blocked_by.len(), 3);
            assert!(!blocked.explanation.is_empty());
            assert!(blocked.explanation.contains(&format!("massive_candidate_{}", i)));
        }

        // Test serialization with massive data
        let json_result = PolicyExplainer::to_json(&explanation);
        assert!(json_result.is_ok(), "Failed to serialize massive blocked alternatives");

        // Test guarantee section with massive guardrails list
        assert!(explanation.guarantee_confidence.guardrails_checked.len() <= 30_000); // Should be manageable

        // Test that memory growth is predictable
        let json_size = json_result.unwrap().len();
        assert!(json_size > 1_000_000, "JSON should be large but manageable");

        // Test deserialization of massive JSON
        let parse_start = std::time::Instant::now();
        let json_str = PolicyExplainer::to_json(&explanation).unwrap();
        let parsed: Result<PolicyExplanation, _> = serde_json::from_str(&json_str);
        let parse_duration = parse_start.elapsed();

        assert!(parsed.is_ok(), "Failed to parse massive JSON");
        assert!(parse_duration.as_secs() < 10, "Parsing took too long: {:?}", parse_duration);
    }

    #[test]
    fn negative_guardrail_and_invariant_manipulation_attacks() {
        // Test duplicate guardrail IDs in blocked candidates
        let duplicate_blocked = vec![
            BlockedCandidate {
                candidate: c("dup_test_1"),
                blocked_by: vec![
                    GuardrailId::new("memory_budget"),
                    GuardrailId::new("memory_budget"), // Duplicate
                    GuardrailId::new("memory_budget"), // Triplicate
                ],
                bayesian_rank: 0,
                reasons: vec!["duplicate guardrail test".to_string()],
            },
            BlockedCandidate {
                candidate: c("dup_test_2"),
                blocked_by: vec![
                    GuardrailId::new("memory_budget"), // Same as above
                    GuardrailId::new("durability_budget"),
                ],
                bayesian_rank: 1,
                reasons: vec!["another duplicate test".to_string()],
            },
        ];

        let dup_outcome = DecisionOutcome {
            chosen: Some(c("chosen_with_dups")),
            blocked: duplicate_blocked,
            reason: DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 0 },
            epoch_id: 999,
        };

        let dup_explanation = PolicyExplainer::explain(&dup_outcome, &diagnostics_with_observations());

        // Verify guardrails_checked deduplicates (BTreeSet behavior)
        let guardrails = &dup_explanation.guarantee_confidence.guardrails_checked;
        assert!(guardrails.len() <= 2); // Should deduplicate "memory_budget"

        // Test empty guardrail IDs
        let empty_guardrail_blocked = vec![
            BlockedCandidate {
                candidate: c("empty_guardrail_test"),
                blocked_by: vec![
                    GuardrailId::new(""),
                    GuardrailId::new("valid_guardrail"),
                    GuardrailId::new("\0"),
                ],
                bayesian_rank: 0,
                reasons: vec!["testing empty guardrail IDs".to_string()],
            },
        ];

        let empty_guardrail_outcome = DecisionOutcome {
            chosen: None,
            blocked: empty_guardrail_blocked,
            reason: DecisionReason::AllCandidatesBlocked,
            epoch_id: 888,
        };

        let empty_explanation = PolicyExplainer::explain(&empty_guardrail_outcome, &empty_diagnostics());

        // Should handle empty guardrail IDs gracefully
        assert!(!empty_explanation.guarantee_confidence.guardrails_checked.is_empty());

        // Test invariant verification consistency
        let invariants = &empty_explanation.guarantee_confidence.invariants_verified;
        assert!(invariants.contains(&"INV-DECIDE-NO-PANIC".to_string())); // Should be present for all-blocked case

        // Test massive guardrail ID attacks
        let massive_guardrail_blocked = vec![
            BlockedCandidate {
                candidate: c("massive_guardrails"),
                blocked_by: (0..1000)
                    .map(|i| GuardrailId::new(&format!("guardrail_mass_{}", i)))
                    .collect(),
                bayesian_rank: 0,
                reasons: vec!["massive guardrail attack".to_string()],
            },
        ];

        let massive_guardrail_outcome = DecisionOutcome {
            chosen: None,
            blocked: massive_guardrail_blocked,
            reason: DecisionReason::AllCandidatesBlocked,
            epoch_id: 777,
        };

        let massive_guardrail_explanation = PolicyExplainer::explain(&massive_guardrail_outcome, &diagnostics_with_observations());

        // Should handle massive guardrail lists
        assert_eq!(massive_guardrail_explanation.guarantee_confidence.guardrails_checked.len(), 1000);

        // JSON serialization should still work
        let massive_json = PolicyExplainer::to_json(&massive_guardrail_explanation);
        assert!(massive_json.is_ok());
    }

    #[test]
    fn negative_epoch_boundary_and_overflow_edge_cases() {
        let epoch_boundary_tests = vec![
            (0, "zero_epoch"),
            (1, "min_epoch"),
            (u64::MAX - 1, "near_max_epoch"),
            (u64::MAX, "max_epoch"),
        ];

        for (epoch_value, test_name) in epoch_boundary_tests {
            let mut epoch_outcome = top_accepted_outcome();
            epoch_outcome.epoch_id = epoch_value;
            epoch_outcome.chosen = Some(c(test_name));

            let explanation = PolicyExplainer::explain(&epoch_outcome, &diagnostics_with_observations());

            // Verify epoch is preserved correctly
            assert_eq!(explanation.epoch_id, epoch_value);

            // Serialization should handle all epoch values
            let json_result = PolicyExplainer::to_json(&explanation);
            assert!(json_result.is_ok(), "Failed to serialize epoch: {}", epoch_value);

            if let Ok(json_str) = json_result {
                let parsed: Result<PolicyExplanation, _> = serde_json::from_str(&json_str);
                assert!(parsed.is_ok(), "Failed to parse epoch: {}", epoch_value);

                if let Ok(parsed_explanation) = parsed {
                    assert_eq!(parsed_explanation.epoch_id, epoch_value);
                }
            }
        }

        // Test epoch arithmetic edge cases in build methods
        let mut arithmetic_outcome = top_accepted_outcome();
        arithmetic_outcome.epoch_id = u64::MAX;

        // Add large epoch ID to blocked candidates to test arithmetic
        let arithmetic_blocked = vec![
            BlockedCandidate {
                candidate: c("arithmetic_test"),
                blocked_by: vec![GuardrailId::new("test_guardrail")],
                bayesian_rank: usize::MAX, // Also test rank overflow
                reasons: vec!["arithmetic boundary test".to_string()],
            },
        ];

        arithmetic_outcome.blocked = arithmetic_blocked;

        let arithmetic_explanation = PolicyExplainer::explain(&arithmetic_outcome, &diagnostics_with_observations());

        // Verify all fields handle extreme values
        assert_eq!(arithmetic_explanation.epoch_id, u64::MAX);
        assert_eq!(arithmetic_explanation.blocked_alternatives[0].bayesian_rank, usize::MAX);

        // Test serialization with extreme values
        let extreme_json = PolicyExplainer::to_json(&arithmetic_explanation);
        assert!(extreme_json.is_ok());
    }

    #[test]
    fn negative_concurrent_explanation_generation_safety() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let shared_diagnostics = Arc::new(Mutex::new(diagnostics_with_observations()));
        let mut handles = vec![];

        // Spawn multiple threads generating explanations concurrently
        for thread_id in 0..8 {
            let diagnostics_clone = Arc::clone(&shared_diagnostics);
            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for op_id in 0..50 {
                    let diagnostics = diagnostics_clone.lock().unwrap();

                    // Create different outcomes for each thread
                    let outcome = match thread_id % 4 {
                        0 => top_accepted_outcome(),
                        1 => fallback_outcome(),
                        2 => all_blocked_outcome(),
                        _ => no_candidates_outcome(),
                    };

                    let mut thread_outcome = outcome;
                    thread_outcome.epoch_id = (thread_id * 1000 + op_id) as u64;

                    if let Some(ref mut chosen) = thread_outcome.chosen {
                        chosen.0 = format!("thread_{}_op_{}", thread_id, op_id);
                    }

                    // Generate explanation
                    let explanation = PolicyExplainer::explain(&thread_outcome, &diagnostics);

                    // Test wording validation concurrently
                    let validation = validate_wording(&explanation);

                    // Test JSON serialization concurrently
                    let json_result = PolicyExplainer::to_json(&explanation);

                    thread_results.push((explanation, validation, json_result));
                }

                thread_results
            });
            handles.push(handle);
        }

        // Collect all results
        let mut all_results = Vec::new();
        for handle in handles {
            let thread_results = handle.join().unwrap();
            all_results.extend(thread_results);
        }

        // Verify all results are valid
        assert_eq!(all_results.len(), 8 * 50); // 8 threads * 50 operations each

        for (explanation, validation, json_result) in all_results {
            // All explanations should be well-formed
            assert!(!explanation.action_summary.is_empty());
            assert!(!explanation.diagnostic_confidence.summary.is_empty());
            assert!(!explanation.guarantee_confidence.summary.is_empty());

            // Wording validation should pass for generated explanations
            assert!(validation.valid, "Wording validation failed: {:?}", validation.violations);

            // JSON serialization should succeed
            assert!(json_result.is_ok(), "JSON serialization failed");

            // Verify JSON is parseable
            if let Ok(json_str) = json_result {
                let parsed: Result<PolicyExplanation, _> = serde_json::from_str(&json_str);
                assert!(parsed.is_ok(), "JSON parsing failed");
            }
        }

        // Verify vocabulary constants remain consistent after concurrent access
        assert!(!GUARANTEE_VOCABULARY.is_empty());
        assert!(!DIAGNOSTIC_VOCABULARY.is_empty());

        for gt in GUARANTEE_VOCABULARY {
            for dt in DIAGNOSTIC_VOCABULARY {
                assert_ne!(gt.to_lowercase(), dt.to_lowercase());
            }
        }
    }
}
