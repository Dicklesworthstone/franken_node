//! Bayesian posterior diagnostics for explainable policy ranking (bd-2igi).
//!
//! Provides a transparent, data-driven ranking of candidate actions using
//! Bayesian posterior probabilities. The diagnostics layer is purely advisory —
//! it produces rankings but never directly triggers actions.
//!
//! ## Invariants
//!
//! - **INV-BAYES-ADVISORY**: Diagnostics never directly execute actions.
//! - **INV-BAYES-REPRODUCIBLE**: `replay_from` with identical observations
//!   produces bit-identical rankings (deterministic reduction order).
//! - **INV-BAYES-NORMALIZED**: Posterior probabilities sum to 1.0 within
//!   floating-point tolerance.
//! - **INV-BAYES-TRANSPARENT**: Every ranking includes full posterior, prior,
//!   observation count, and confidence interval.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Type alias for a raw candidate score tuple:
/// `(candidate_ref, posterior_mean, prior, observation_count, (ci_lower, ci_upper))`.
#[allow(dead_code)]
type RawCandidateScore = (CandidateRef, f64, f64, u64, (f64, f64));

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Posterior updated with new observation.
pub const EVD_BAYES_001: &str = "EVD-BAYES-001";
/// Ranking produced (includes top candidate and confidence).
pub const EVD_BAYES_002: &str = "EVD-BAYES-002";
/// Guardrail conflict detected on top-ranked candidate.
pub const EVD_BAYES_003: &str = "EVD-BAYES-003";
/// Replay from stored observations completed.
pub const EVD_BAYES_004: &str = "EVD-BAYES-004";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Reference to a candidate action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CandidateRef(pub String);

impl CandidateRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// An observation about a candidate's outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// Which candidate this observation is about.
    pub candidate: CandidateRef,
    /// Whether the outcome was successful (true) or not (false).
    pub success: bool,
    /// Epoch in which the observation was made.
    pub epoch_id: u64,
}

impl Observation {
    pub fn new(candidate: CandidateRef, success: bool, epoch_id: u64) -> Self {
        Self {
            candidate,
            success,
            epoch_id,
        }
    }
}

/// Confidence level of the diagnostic ranking (distinct from GuaranteeConfidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticConfidence {
    /// Too few observations to be meaningful.
    Low,
    /// Some observations but not yet converged.
    Medium,
    /// Sufficient observations for reliable ranking.
    High,
}

/// A candidate ranked by posterior probability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedCandidate {
    pub candidate_ref: CandidateRef,
    pub posterior_prob: f64,
    pub prior_prob: f64,
    pub observation_count: u64,
    pub confidence_interval: (f64, f64),
    /// True if a guardrail would block this candidate.
    pub guardrail_filtered: bool,
}

/// Internal beta distribution state for conjugate Bayesian update.
/// Beta(alpha, beta) where alpha = successes + 1, beta = failures + 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BetaState {
    alpha: f64,
    beta: f64,
    observation_count: u64,
}

impl BetaState {
    fn new() -> Self {
        // Uniform prior: Beta(1, 1)
        Self {
            alpha: 1.0,
            beta: 1.0,
            observation_count: 0,
        }
    }

    fn update(&mut self, success: bool) {
        if success {
            self.alpha += 1.0;
        } else {
            self.beta += 1.0;
        }
        self.observation_count = self.observation_count.saturating_add(1);
    }

    /// Mean of the beta distribution = alpha / (alpha + beta).
    fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// 95% credible interval using the normal approximation for beta distribution.
    fn confidence_interval_95(&self) -> (f64, f64) {
        let n = self.alpha + self.beta;
        let mean = self.mean();
        let variance = (self.alpha * self.beta) / (n * n * (n + 1.0));
        let std = variance.sqrt();
        let z = 1.96; // 95% CI
        let lo = (mean - z * std).max(0.0);
        let hi = (mean + z * std).min(1.0);
        (lo, hi)
    }

    #[allow(dead_code)]
    fn diagnostic_confidence(&self) -> DiagnosticConfidence {
        match self.observation_count {
            0..=2 => DiagnosticConfidence::Low,
            3..=9 => DiagnosticConfidence::Medium,
            _ => DiagnosticConfidence::High,
        }
    }
}

/// Bayesian diagnostics engine for explainable policy ranking.
///
/// Purely advisory — produces rankings but never directly executes actions
/// (INV-BAYES-ADVISORY).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesianDiagnostics {
    /// Per-candidate beta distribution state.
    states: BTreeMap<CandidateRef, BetaState>,
    /// Total observation count across all candidates.
    total_observations: u64,
    /// Current epoch for logging.
    epoch_id: u64,
}

impl BayesianDiagnostics {
    pub fn new() -> Self {
        Self {
            states: BTreeMap::new(),
            total_observations: 0,
            epoch_id: 0,
        }
    }

    pub fn with_epoch(mut self, epoch_id: u64) -> Self {
        self.epoch_id = epoch_id;
        self
    }

    /// Incorporate a new observation into the posterior.
    /// Returns &mut Self for chaining.
    ///
    /// [EVD-BAYES-001] Posterior update event.
    pub fn update(&mut self, observation: &Observation) -> &mut Self {
        let state = self
            .states
            .entry(observation.candidate.clone())
            .or_insert_with(BetaState::new);
        state.update(observation.success);
        self.total_observations += 1;
        self.epoch_id = observation.epoch_id;

        // [EVD-BAYES-001] structured log point
        let _event = EVD_BAYES_001;

        self
    }

    /// Rank candidates by posterior probability (descending).
    ///
    /// Candidates not seen in observations get the uniform prior (0.5).
    /// `guardrail_blocked` contains candidate refs that would be blocked.
    ///
    /// [EVD-BAYES-002] Ranking produced event.
    /// [EVD-BAYES-003] Guardrail conflict event (if top candidate blocked).
    pub fn rank_candidates(
        &self,
        candidates: &[CandidateRef],
        guardrail_blocked: &[CandidateRef],
    ) -> Vec<RankedCandidate> {
        if candidates.is_empty() {
            return Vec::new();
        }

        // Compute raw posterior means
        let mut raw_scores: Vec<RawCandidateScore> = candidates
            .iter()
            .map(|c| {
                let (posterior, prior, count, ci) = if let Some(state) = self.states.get(c) {
                    (
                        state.mean(),
                        1.0 / candidates.len() as f64,
                        state.observation_count,
                        state.confidence_interval_95(),
                    )
                } else {
                    // No observations — uniform prior
                    let prior = 1.0 / candidates.len() as f64;
                    (0.5, prior, 0, (0.0, 1.0))
                };
                (c.clone(), posterior, prior, count, ci)
            })
            .collect();

        // Normalize posterior probabilities so they sum to 1.0
        // (INV-BAYES-NORMALIZED)
        let total: f64 = raw_scores.iter().map(|(_, p, _, _, _)| *p).sum();
        if total > 0.0 {
            for entry in &mut raw_scores {
                entry.1 /= total;
            }
        }

        // Sort by posterior descending (stable sort for determinism)
        // Use BTreeMap ordering as tiebreaker for identical posteriors
        raw_scores.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

        let blocked_set: std::collections::BTreeSet<&CandidateRef> =
            guardrail_blocked.iter().collect();

        let ranked: Vec<RankedCandidate> = raw_scores
            .into_iter()
            .map(|(cref, posterior, prior, count, ci)| RankedCandidate {
                guardrail_filtered: blocked_set.contains(&cref),
                candidate_ref: cref,
                posterior_prob: posterior,
                prior_prob: prior,
                observation_count: count,
                confidence_interval: ci,
            })
            .collect();

        // [EVD-BAYES-002] structured log point
        let _event = EVD_BAYES_002;

        // [EVD-BAYES-003] guardrail conflict on top candidate
        if let Some(top) = ranked.first()
            && top.guardrail_filtered
        {
            let _event = EVD_BAYES_003;
        }

        ranked
    }

    /// Reconstruct state from an observation sequence (INV-BAYES-REPRODUCIBLE).
    ///
    /// Two calls with identical observations produce bit-identical rankings
    /// because we use deterministic iteration order (BTreeMap) and process
    /// observations in sequence.
    ///
    /// [EVD-BAYES-004] Replay completed event.
    pub fn replay_from(observations: &[Observation]) -> Self {
        let mut diag = Self::new();
        for obs in observations {
            diag.update(obs);
        }

        // [EVD-BAYES-004] structured log point
        let _event = EVD_BAYES_004;

        diag
    }

    /// Total observations processed.
    pub fn total_observations(&self) -> u64 {
        self.total_observations
    }

    /// Number of unique candidates seen.
    pub fn candidates_seen(&self) -> usize {
        self.states.len()
    }

    /// Overall diagnostic confidence based on observation volume.
    pub fn overall_confidence(&self) -> DiagnosticConfidence {
        match self.total_observations {
            0..=5 => DiagnosticConfidence::Low,
            6..=19 => DiagnosticConfidence::Medium,
            _ => DiagnosticConfidence::High,
        }
    }

    /// Serialize the full diagnostics state to JSON for persistence.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl Default for BayesianDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Compile-time Send + Sync
// ---------------------------------------------------------------------------

fn _assert_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<BayesianDiagnostics>();
    assert_sync::<BayesianDiagnostics>();
    assert_send::<RankedCandidate>();
    assert_sync::<RankedCandidate>();
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn c(id: &str) -> CandidateRef {
        CandidateRef::new(id)
    }

    fn obs(id: &str, success: bool) -> Observation {
        Observation::new(c(id), success, 1)
    }

    #[test]
    fn test_new_is_empty() {
        let d = BayesianDiagnostics::new();
        assert_eq!(d.total_observations(), 0);
        assert_eq!(d.candidates_seen(), 0);
    }

    #[test]
    fn test_default_is_empty() {
        let d = BayesianDiagnostics::default();
        assert_eq!(d.total_observations(), 0);
    }

    #[test]
    fn test_with_epoch() {
        let d = BayesianDiagnostics::new().with_epoch(42);
        assert_eq!(d.epoch_id, 42);
    }

    #[test]
    fn test_update_single_success() {
        let mut d = BayesianDiagnostics::new();
        d.update(&obs("A", true));
        assert_eq!(d.total_observations(), 1);
        assert_eq!(d.candidates_seen(), 1);
    }

    #[test]
    fn test_update_single_failure() {
        let mut d = BayesianDiagnostics::new();
        d.update(&obs("A", false));
        assert_eq!(d.total_observations(), 1);
    }

    #[test]
    fn test_update_chaining() {
        let mut d = BayesianDiagnostics::new();
        d.update(&obs("A", true)).update(&obs("B", false));
        assert_eq!(d.total_observations(), 2);
        assert_eq!(d.candidates_seen(), 2);
    }

    #[test]
    fn test_rank_empty_candidates() {
        let d = BayesianDiagnostics::new();
        let ranked = d.rank_candidates(&[], &[]);
        assert!(ranked.is_empty());
    }

    #[test]
    fn test_rank_no_observations_uniform() {
        let d = BayesianDiagnostics::new();
        let candidates = vec![c("A"), c("B")];
        let ranked = d.rank_candidates(&candidates, &[]);
        assert_eq!(ranked.len(), 2);
        let diff = (ranked[0].posterior_prob - ranked[1].posterior_prob).abs();
        assert!(diff < 1e-10, "uniform prior should give equal posteriors");
    }

    #[test]
    fn test_rank_with_observations() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..5 {
            d.update(&obs("A", true));
            d.update(&obs("B", false));
        }
        let ranked = d.rank_candidates(&[c("A"), c("B")], &[]);
        assert_eq!(ranked[0].candidate_ref, c("A"));
        assert!(ranked[0].posterior_prob > ranked[1].posterior_prob);
    }

    #[test]
    fn test_rank_posterior_sums_to_one() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..10 {
            d.update(&obs("A", true));
            d.update(&obs("B", true));
            d.update(&obs("C", false));
        }
        let ranked = d.rank_candidates(&[c("A"), c("B"), c("C")], &[]);
        let total: f64 = ranked.iter().map(|r| r.posterior_prob).sum();
        assert!(
            (total - 1.0).abs() < 1e-10,
            "INV-BAYES-NORMALIZED: sum={}",
            total
        );
    }

    #[test]
    fn test_rank_descending_order() {
        let mut d = BayesianDiagnostics::new();
        d.update(&obs("A", true));
        d.update(&obs("A", true));
        d.update(&obs("B", true));
        d.update(&obs("C", false));
        let ranked = d.rank_candidates(&[c("A"), c("B"), c("C")], &[]);
        for i in 0..ranked.len() - 1 {
            assert!(ranked[i].posterior_prob >= ranked[i + 1].posterior_prob);
        }
    }

    #[test]
    fn test_confidence_interval_bounds() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..20 {
            d.update(&obs("A", true));
        }
        let ranked = d.rank_candidates(&[c("A")], &[]);
        let (lo, hi) = ranked[0].confidence_interval;
        assert!((0.0..=1.0).contains(&lo));
        assert!((0.0..=1.0).contains(&hi));
        assert!(lo <= hi);
    }

    #[test]
    fn test_confidence_interval_narrows() {
        let mut d = BayesianDiagnostics::new();
        d.update(&obs("A", true));
        let r1 = d.rank_candidates(&[c("A")], &[]);
        let w1 = r1[0].confidence_interval.1 - r1[0].confidence_interval.0;
        for _ in 0..50 {
            d.update(&obs("A", true));
        }
        let r2 = d.rank_candidates(&[c("A")], &[]);
        let w2 = r2[0].confidence_interval.1 - r2[0].confidence_interval.0;
        assert!(w2 < w1, "CI should narrow with more observations");
    }

    #[test]
    fn test_guardrail_filtered_flag() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..10 {
            d.update(&obs("A", true));
        }
        let ranked = d.rank_candidates(&[c("A"), c("B")], &[c("A")]);
        let a = ranked.iter().find(|r| r.candidate_ref == c("A")).unwrap();
        assert!(a.guardrail_filtered);
        let b = ranked.iter().find(|r| r.candidate_ref == c("B")).unwrap();
        assert!(!b.guardrail_filtered);
    }

    #[test]
    fn test_guardrail_does_not_reorder() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..10 {
            d.update(&obs("A", true));
        }
        let without = d.rank_candidates(&[c("A"), c("B")], &[]);
        let with = d.rank_candidates(&[c("A"), c("B")], &[c("A")]);
        assert_eq!(without[0].candidate_ref, with[0].candidate_ref);
    }

    #[test]
    fn test_replay_from_reproducible() {
        let observations: Vec<Observation> = (0..100)
            .map(|i| Observation::new(c(if i % 2 == 0 { "A" } else { "B" }), i % 3 != 0, i as u64))
            .collect();
        let d1 = BayesianDiagnostics::replay_from(&observations);
        let d2 = BayesianDiagnostics::replay_from(&observations);
        let r1 = d1.rank_candidates(&[c("A"), c("B")], &[]);
        let r2 = d2.rank_candidates(&[c("A"), c("B")], &[]);
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(
                a.posterior_prob.to_bits(),
                b.posterior_prob.to_bits(),
                "INV-BAYES-REPRODUCIBLE"
            );
        }
    }

    #[test]
    fn test_replay_from_empty() {
        let d = BayesianDiagnostics::replay_from(&[]);
        assert_eq!(d.total_observations(), 0);
    }

    #[test]
    fn test_replay_matches_incremental() {
        let observations = vec![
            obs("A", true),
            obs("B", false),
            obs("A", true),
            obs("C", true),
        ];
        let replayed = BayesianDiagnostics::replay_from(&observations);
        let mut incremental = BayesianDiagnostics::new();
        for o in &observations {
            incremental.update(o);
        }
        let r1 = replayed.rank_candidates(&[c("A"), c("B"), c("C")], &[]);
        let r2 = incremental.rank_candidates(&[c("A"), c("B"), c("C")], &[]);
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.posterior_prob.to_bits(), b.posterior_prob.to_bits());
        }
    }

    #[test]
    fn test_uniform_prior_converges() {
        let mut d = BayesianDiagnostics::new();
        for i in 0..100 {
            d.update(&obs("A", i % 5 != 0));
            d.update(&obs("B", i % 5 == 0));
        }
        let ranked = d.rank_candidates(&[c("A"), c("B")], &[]);
        assert_eq!(ranked[0].candidate_ref, c("A"));
        assert!(ranked[0].posterior_prob > 0.6);
    }

    #[test]
    fn test_contradictory_observations() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..20 {
            d.update(&obs("A", true));
        }
        let r1 = d.rank_candidates(&[c("A"), c("B")], &[]);
        let a_before = r1[0].posterior_prob;
        for _ in 0..20 {
            d.update(&obs("A", false));
            d.update(&obs("B", true));
        }
        let r2 = d.rank_candidates(&[c("A"), c("B")], &[]);
        let a_entry = r2.iter().find(|r| r.candidate_ref == c("A")).unwrap();
        assert!(a_entry.posterior_prob < a_before);
    }

    #[test]
    fn test_overall_confidence_low() {
        assert_eq!(
            BayesianDiagnostics::new().overall_confidence(),
            DiagnosticConfidence::Low
        );
    }

    #[test]
    fn test_overall_confidence_medium() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..10 {
            d.update(&obs("A", true));
        }
        assert_eq!(d.overall_confidence(), DiagnosticConfidence::Medium);
    }

    #[test]
    fn test_overall_confidence_high() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..30 {
            d.update(&obs("A", true));
        }
        assert_eq!(d.overall_confidence(), DiagnosticConfidence::High);
    }

    #[test]
    fn test_single_candidate() {
        let mut d = BayesianDiagnostics::new();
        d.update(&obs("A", true));
        let ranked = d.rank_candidates(&[c("A")], &[]);
        assert_eq!(ranked.len(), 1);
        assert!((ranked[0].posterior_prob - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_many_candidates() {
        let d = BayesianDiagnostics::new();
        let candidates: Vec<CandidateRef> = (0..100).map(|i| c(&format!("C{}", i))).collect();
        let ranked = d.rank_candidates(&candidates, &[]);
        assert_eq!(ranked.len(), 100);
        let total: f64 = ranked.iter().map(|r| r.posterior_prob).sum();
        assert!((total - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_unobserved_candidate() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..10 {
            d.update(&obs("A", true));
        }
        let ranked = d.rank_candidates(&[c("A"), c("B")], &[]);
        let b = ranked.iter().find(|r| r.candidate_ref == c("B")).unwrap();
        assert_eq!(b.observation_count, 0);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut d = BayesianDiagnostics::new();
        d.update(&obs("A", true)).update(&obs("B", false));
        let json = d.to_json().unwrap();
        let d2: BayesianDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(d.total_observations(), d2.total_observations());
    }

    #[test]
    fn test_ranked_candidate_serialization() {
        let rc = RankedCandidate {
            candidate_ref: c("test"),
            posterior_prob: 0.75,
            prior_prob: 0.5,
            observation_count: 10,
            confidence_interval: (0.6, 0.9),
            guardrail_filtered: false,
        };
        let json = serde_json::to_string(&rc).unwrap();
        let rc2: RankedCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(rc.candidate_ref, rc2.candidate_ref);
    }

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(EVD_BAYES_001, "EVD-BAYES-001");
        assert_eq!(EVD_BAYES_002, "EVD-BAYES-002");
        assert_eq!(EVD_BAYES_003, "EVD-BAYES-003");
        assert_eq!(EVD_BAYES_004, "EVD-BAYES-004");
    }

    #[test]
    fn test_prior_prob_reflects_candidate_count() {
        let d = BayesianDiagnostics::new();
        let ranked = d.rank_candidates(&[c("A"), c("B"), c("C"), c("D")], &[]);
        for r in &ranked {
            assert!((r.prior_prob - 0.25).abs() < 1e-10);
        }
    }

    #[test]
    fn test_observation_count_per_candidate() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..5 {
            d.update(&obs("A", true));
        }
        for _ in 0..3 {
            d.update(&obs("B", false));
        }
        let ranked = d.rank_candidates(&[c("A"), c("B")], &[]);
        let a = ranked.iter().find(|r| r.candidate_ref == c("A")).unwrap();
        let b = ranked.iter().find(|r| r.candidate_ref == c("B")).unwrap();
        assert_eq!(a.observation_count, 5);
        assert_eq!(b.observation_count, 3);
    }
}
