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
}
