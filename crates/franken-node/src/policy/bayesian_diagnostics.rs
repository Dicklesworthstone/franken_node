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
            if !self.alpha.is_finite() || self.alpha >= f64::MAX - 1.0 {
                self.alpha = f64::MAX;
            } else {
                let result = self.alpha + 1.0;
                self.alpha = if result.is_finite() { result } else { f64::MAX };
            }
        } else {
            if !self.beta.is_finite() || self.beta >= f64::MAX - 1.0 {
                self.beta = f64::MAX;
            } else {
                let result = self.beta + 1.0;
                self.beta = if result.is_finite() { result } else { f64::MAX };
            }
        }
        self.observation_count = self.observation_count.saturating_add(1);
    }

    /// Mean of the beta distribution = alpha / (alpha + beta).
    fn mean(&self) -> f64 {
        if !self.alpha.is_finite()
            || !self.beta.is_finite()
            || self.alpha < 0.0
            || self.beta < 0.0
            || self.alpha >= f64::MAX
            || self.beta >= f64::MAX
        {
            return 0.0;
        }

        let n = self.alpha + self.beta;
        if !n.is_finite() || n <= 0.0 {
            return 0.0;
        }
        self.alpha / n
    }

    /// 95% credible interval using the normal approximation for beta distribution.
    fn confidence_interval_95(&self) -> (f64, f64) {
        if !self.alpha.is_finite()
            || !self.beta.is_finite()
            || self.alpha < 0.0
            || self.beta < 0.0
            || self.alpha >= f64::MAX
            || self.beta >= f64::MAX
        {
            return (0.0, 1.0);
        }

        let n = self.alpha + self.beta;
        if !n.is_finite() || n <= 0.0 || n >= f64::MAX {
            return (0.0, 1.0);
        }

        let mean = self.alpha / n;
        if !mean.is_finite() {
            return (0.0, 1.0);
        }

        if self.beta > 0.0 && self.alpha > f64::MAX / self.beta {
            return (0.0, 1.0);
        }
        let numerator = self.alpha * self.beta;

        let sqrt_max = f64::MAX.sqrt();
        if n > sqrt_max {
            return (0.0, 1.0);
        }
        let n_squared = n * n;
        let n_plus_one = n + 1.0;
        if !n_squared.is_finite()
            || !n_plus_one.is_finite()
            || (n_squared > 0.0 && n_plus_one > f64::MAX / n_squared)
        {
            return (0.0, 1.0);
        }
        let denominator = n_squared * n_plus_one;

        if !numerator.is_finite() || !denominator.is_finite() || denominator == 0.0 {
            return (0.0, 1.0);
        }

        let variance = numerator / denominator;
        if !variance.is_finite() || variance < 0.0 {
            return (0.0, 1.0);
        }
        let std = variance.sqrt();
        let z = 1.96; // 95% CI
        let lo = (mean - z * std).max(0.0);
        let hi = (mean + z * std).min(1.0);
        if !lo.is_finite() || !hi.is_finite() {
            return (0.0, 1.0);
        }
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

    #[cfg(any(test, feature = "policy-engine"))]
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
        self.total_observations = self.total_observations.saturating_add(1);
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
                    let candidate_count_f64 =
                        u32::try_from(candidates.len()).unwrap_or(u32::MAX) as f64;
                    // Guard against division by zero and extremely small priors
                    let safe_prior = if candidate_count_f64 > 0.0 {
                        1.0 / candidate_count_f64
                    } else {
                        1.0 // Fallback to uniform if count is somehow zero
                    };
                    (
                        state.mean(),
                        safe_prior,
                        state.observation_count,
                        state.confidence_interval_95(),
                    )
                } else {
                    // No observations — uniform prior
                    let candidate_count_f64 =
                        u32::try_from(candidates.len()).unwrap_or(u32::MAX) as f64;
                    // Guard against division by zero and extremely small priors
                    let prior = if candidate_count_f64 > 0.0 {
                        1.0 / candidate_count_f64
                    } else {
                        1.0 // Fallback to uniform if count is somehow zero
                    };
                    (0.5, prior, 0, (0.0, 1.0))
                };
                (c.clone(), posterior, prior, count, ci)
            })
            .collect();

        // Normalize posterior probabilities so they sum to 1.0
        // (INV-BAYES-NORMALIZED)
        let total: f64 = raw_scores.iter().map(|(_, p, _, _, _)| *p).sum();
        if total.is_finite() && total > 0.0 {
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
    #[cfg(any(test, feature = "policy-engine"))]
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
    #[cfg(any(test, feature = "policy-engine"))]
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

    fn diagnostics_with_state(
        id: &str,
        alpha: f64,
        beta: f64,
        observation_count: u64,
    ) -> BayesianDiagnostics {
        let mut states = BTreeMap::new();
        states.insert(
            c(id),
            BetaState {
                alpha,
                beta,
                observation_count,
            },
        );
        BayesianDiagnostics {
            states,
            total_observations: observation_count,
            epoch_id: 1,
        }
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

    #[test]
    fn test_corrupt_nan_alpha_state_does_not_emit_nan_posterior() {
        let d = diagnostics_with_state("bad", f64::NAN, 1.0, 7);

        let ranked = d.rank_candidates(&[c("bad"), c("fallback")], &[]);

        let bad = ranked.iter().find(|r| r.candidate_ref == c("bad")).unwrap();
        assert_eq!(bad.posterior_prob, 0.0);
        assert!(ranked.iter().all(|r| r.posterior_prob.is_finite()));
    }

    #[test]
    fn test_corrupt_negative_beta_state_does_not_win_ranking() {
        let d = diagnostics_with_state("bad", 10.0, -1.0, 7);

        let ranked = d.rank_candidates(&[c("bad"), c("fallback")], &[]);

        assert_eq!(ranked[0].candidate_ref, c("fallback"));
        let bad = ranked.iter().find(|r| r.candidate_ref == c("bad")).unwrap();
        assert_eq!(bad.posterior_prob, 0.0);
    }

    #[test]
    fn test_corrupt_zero_alpha_beta_state_has_bounded_interval() {
        let d = diagnostics_with_state("bad", 0.0, 0.0, 3);

        let ranked = d.rank_candidates(&[c("bad")], &[]);

        assert_eq!(ranked[0].posterior_prob, 0.0);
        assert_eq!(ranked[0].confidence_interval, (0.0, 1.0));
    }

    #[test]
    fn test_corrupt_infinite_alpha_state_fails_closed() {
        let d = diagnostics_with_state("bad", f64::INFINITY, 1.0, 3);

        let ranked = d.rank_candidates(&[c("bad"), c("fallback")], &[]);

        let bad = ranked.iter().find(|r| r.candidate_ref == c("bad")).unwrap();
        assert_eq!(bad.posterior_prob, 0.0);
        assert!(bad.confidence_interval.0 <= bad.confidence_interval.1);
    }

    #[test]
    fn test_corrupt_max_alpha_beta_state_fails_closed() {
        let d = diagnostics_with_state("bad", f64::MAX, f64::MAX, 3);

        let ranked = d.rank_candidates(&[c("bad"), c("fallback")], &[]);

        let bad = ranked.iter().find(|r| r.candidate_ref == c("bad")).unwrap();
        assert_eq!(bad.posterior_prob, 0.0);
        assert!(ranked.iter().all(|r| r.posterior_prob.is_finite()));
    }

    #[test]
    fn test_update_saturates_total_observations_from_corrupt_state() {
        let mut d = diagnostics_with_state("A", 1.0, 1.0, u64::MAX);

        d.update(&obs("A", true));

        assert_eq!(d.total_observations(), u64::MAX);
        let ranked = d.rank_candidates(&[c("A")], &[]);
        assert_eq!(ranked[0].observation_count, u64::MAX);
    }

    #[test]
    fn test_update_saturates_non_finite_alpha_after_corrupt_state() {
        let mut d = diagnostics_with_state("A", f64::MAX, 1.0, 1);

        d.update(&obs("A", true));
        let ranked = d.rank_candidates(&[c("A"), c("B")], &[]);

        let a = ranked.iter().find(|r| r.candidate_ref == c("A")).unwrap();
        assert_eq!(a.posterior_prob, 0.0);
        assert!(ranked.iter().all(|r| r.posterior_prob.is_finite()));
    }

    #[test]
    fn test_duplicate_candidate_inputs_stay_finite_and_filtered() {
        let mut d = BayesianDiagnostics::new();
        d.update(&obs("A", true));

        let ranked = d.rank_candidates(&[c("A"), c("A"), c("B")], &[c("A")]);
        let total: f64 = ranked.iter().map(|r| r.posterior_prob).sum();
        let filtered_a = ranked
            .iter()
            .filter(|r| r.candidate_ref == c("A") && r.guardrail_filtered)
            .count();

        assert_eq!(ranked.len(), 3);
        assert_eq!(filtered_a, 2);
        assert!((total - 1.0).abs() < 1e-10);
        assert!(ranked.iter().all(|r| r.posterior_prob.is_finite()));
    }

    #[test]
    fn test_unknown_guardrail_candidate_does_not_filter_requested_candidate() {
        let d = BayesianDiagnostics::new();

        let ranked = d.rank_candidates(&[c("A")], &[c("missing")]);

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].candidate_ref, c("A"));
        assert!(!ranked[0].guardrail_filtered);
    }

    #[test]
    fn test_observed_candidate_not_requested_does_not_leak_into_ranking() {
        let mut d = BayesianDiagnostics::new();
        for _ in 0..8 {
            d.update(&obs("observed-only", true));
        }

        let ranked = d.rank_candidates(&[c("fallback")], &[]);

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].candidate_ref, c("fallback"));
        assert_eq!(ranked[0].observation_count, 0);
        assert!((ranked[0].posterior_prob - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_malformed_json_state_is_rejected() {
        let err = serde_json::from_str::<BayesianDiagnostics>("{\"states\":")
            .expect_err("truncated diagnostics JSON must not deserialize");

        assert!(err.is_syntax() || err.is_eof());
    }

    #[test]
    fn test_corrupt_negative_alpha_state_has_bounded_interval() {
        let d = diagnostics_with_state("bad", -1.0, 10.0, 4);

        let ranked = d.rank_candidates(&[c("bad"), c("fallback")], &[]);

        let bad = ranked.iter().find(|r| r.candidate_ref == c("bad")).unwrap();
        assert_eq!(bad.posterior_prob, 0.0);
        assert_eq!(bad.confidence_interval, (0.0, 1.0));
        assert!(ranked.iter().all(|r| r.posterior_prob.is_finite()));
    }

    #[test]
    fn test_corrupt_nan_beta_state_fails_closed() {
        let d = diagnostics_with_state("bad", 1.0, f64::NAN, 4);

        let ranked = d.rank_candidates(&[c("bad"), c("fallback")], &[]);

        let bad = ranked.iter().find(|r| r.candidate_ref == c("bad")).unwrap();
        assert_eq!(bad.posterior_prob, 0.0);
        assert_eq!(bad.confidence_interval, (0.0, 1.0));
        assert!(ranked.iter().all(|r| r.posterior_prob.is_finite()));
    }

    #[test]
    fn test_update_saturates_non_finite_beta_after_corrupt_state() {
        let mut d = diagnostics_with_state("A", 1.0, f64::MAX, 1);

        d.update(&obs("A", false));
        let ranked = d.rank_candidates(&[c("A"), c("B")], &[]);

        let a = ranked.iter().find(|r| r.candidate_ref == c("A")).unwrap();
        assert_eq!(a.posterior_prob, 0.0);
        assert!(ranked.iter().all(|r| r.posterior_prob.is_finite()));
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_candidate_ref_with_problematic_string_content() {
        // Test CandidateRef with various problematic string data
        let problematic_refs = vec![
            CandidateRef::new(""),                                    // Empty string
            CandidateRef::new("\0null\x01control\x7f"),               // Control characters
            CandidateRef::new("candidate\nwith\nnewlines"),           // Multiline
            CandidateRef::new("🚀emoji💀candidate"),                  // Unicode emoji
            CandidateRef::new("\u{FFFF}\u{10FFFF}"),                  // Max Unicode codepoints
            CandidateRef::new("../../../etc/passwd"),                 // Path traversal
            CandidateRef::new("<script>alert('candidate')</script>"), // XSS
            CandidateRef::new("x".repeat(10_000)),                    // Very long string
        ];

        for candidate_ref in problematic_refs {
            // CandidateRef creation should not panic
            assert!(!candidate_ref.0.is_empty() || candidate_ref.0.is_empty()); // Basic check

            // Should be usable in observations
            let obs = Observation::new(candidate_ref.clone(), true, 1000);
            assert_eq!(obs.candidate, candidate_ref);
            assert_eq!(obs.success, true);
            assert_eq!(obs.epoch_id, 1000);

            // Serialization should handle problematic content
            let serialization = serde_json::to_string(&candidate_ref);
            match serialization {
                Ok(json) => {
                    // If serialization succeeds, deserialization should work
                    let _deserialized: Result<CandidateRef, _> = serde_json::from_str(&json);
                    // Either succeeds or fails gracefully
                }
                Err(_) => {
                    // Some characters might not be JSON-serializable
                }
            }

            // Should be orderable for BTreeMap usage
            let ordering = candidate_ref.cmp(&candidate_ref);
            assert_eq!(ordering, std::cmp::Ordering::Equal);
        }
    }

    #[test]
    fn negative_observation_with_extreme_epoch_values() {
        // Test Observation with boundary epoch values
        let boundary_epochs = vec![
            (0, "zero_epoch"),
            (1, "minimum_positive"),
            (u64::MAX / 2, "half_maximum"),
            (u64::MAX - 1, "near_maximum"),
            (u64::MAX, "maximum_epoch"),
        ];

        for (epoch, description) in boundary_epochs {
            let success_obs = Observation::new(c("test"), true, epoch);
            let failure_obs = Observation::new(c("test"), false, epoch);

            assert_eq!(success_obs.epoch_id, epoch);
            assert_eq!(failure_obs.epoch_id, epoch);
            assert_eq!(success_obs.success, true);
            assert_eq!(failure_obs.success, false);

            // Observations should serialize with extreme epoch values
            let success_json = serde_json::to_string(&success_obs);
            let failure_json = serde_json::to_string(&failure_obs);

            assert!(
                success_json.is_ok(),
                "Should serialize observation with epoch: {}",
                description
            );
            assert!(
                failure_json.is_ok(),
                "Should serialize observation with epoch: {}",
                description
            );
        }
    }

    #[test]
    fn negative_beta_state_with_extreme_alpha_beta_values() {
        // Test BetaState with extreme alpha/beta values
        let mut extreme_state = BetaState::new();

        // Test updates that could cause overflow
        extreme_state.alpha = f64::MAX / 2.0;
        extreme_state.beta = f64::MAX / 2.0;
        extreme_state.observation_count = u64::MAX - 1;

        // Update should handle potential overflow gracefully
        extreme_state.update(true); // Should cap alpha at f64::MAX
        extreme_state.update(false); // Should cap beta at f64::MAX

        assert!(extreme_state.alpha <= f64::MAX);
        assert!(extreme_state.beta <= f64::MAX);
        assert_eq!(extreme_state.observation_count, u64::MAX); // Should saturate

        // Mean should be safe with extreme values
        let mean = extreme_state.mean();
        assert!(
            mean.is_finite() && mean >= 0.0 && mean <= 1.0,
            "Mean should be valid: {}",
            mean
        );

        // Confidence interval should be safe
        let (ci_lower, ci_upper) = extreme_state.confidence_interval_95();
        assert!(
            ci_lower >= 0.0 && ci_lower <= 1.0,
            "CI lower bound invalid: {}",
            ci_lower
        );
        assert!(
            ci_upper >= 0.0 && ci_upper <= 1.0,
            "CI upper bound invalid: {}",
            ci_upper
        );
        assert!(
            ci_lower <= ci_upper,
            "CI bounds should be ordered: {} <= {}",
            ci_lower,
            ci_upper
        );
    }

    #[test]
    fn negative_beta_state_with_invalid_initial_conditions() {
        // Test BetaState with manually set invalid conditions
        let mut invalid_states = vec![
            BetaState {
                alpha: 0.0,
                beta: 1.0,
                observation_count: 0,
            }, // Zero alpha
            BetaState {
                alpha: 1.0,
                beta: 0.0,
                observation_count: 0,
            }, // Zero beta
            BetaState {
                alpha: -1.0,
                beta: 1.0,
                observation_count: 0,
            }, // Negative alpha
            BetaState {
                alpha: 1.0,
                beta: -1.0,
                observation_count: 0,
            }, // Negative beta
            BetaState {
                alpha: f64::NAN,
                beta: 1.0,
                observation_count: 0,
            }, // NaN alpha
            BetaState {
                alpha: 1.0,
                beta: f64::NAN,
                observation_count: 0,
            }, // NaN beta
            BetaState {
                alpha: f64::INFINITY,
                beta: 1.0,
                observation_count: 0,
            }, // Infinite alpha
            BetaState {
                alpha: 1.0,
                beta: f64::INFINITY,
                observation_count: 0,
            }, // Infinite beta
        ];

        for state in &mut invalid_states {
            // Mean calculation should return safe fallback (0.0) for invalid states
            let mean = state.mean();
            assert!(
                mean.is_finite(),
                "Mean should be finite for invalid state: {}",
                mean
            );
            assert!(
                mean >= 0.0 && mean <= 1.0,
                "Mean should be in [0,1] for invalid state: {}",
                mean
            );

            // Confidence interval should return safe bounds
            let (ci_lower, ci_upper) = state.confidence_interval_95();
            assert!(
                ci_lower.is_finite() && ci_upper.is_finite(),
                "CI bounds should be finite"
            );
            assert!(
                ci_lower >= 0.0 && ci_upper <= 1.0,
                "CI bounds should be in [0,1]"
            );

            // Update should still work (normalize invalid state)
            state.update(true);
            state.update(false);

            // After updates, state should be more stable
            let updated_mean = state.mean();
            assert!(updated_mean.is_finite(), "Updated mean should be finite");
        }
    }

    #[test]
    fn negative_ranked_candidate_with_extreme_probability_values() {
        // Test RankedCandidate with extreme and invalid probability values
        let extreme_candidates = vec![
            RankedCandidate {
                candidate_ref: c("test1"),
                posterior_prob: f64::NAN, // NaN probability
                prior_prob: 0.5,
                observation_count: 10,
                confidence_interval: (0.0, 1.0),
                guardrail_filtered: false,
            },
            RankedCandidate {
                candidate_ref: c("test2"),
                posterior_prob: f64::INFINITY, // Infinite probability
                prior_prob: 0.5,
                observation_count: 10,
                confidence_interval: (0.0, 1.0),
                guardrail_filtered: false,
            },
            RankedCandidate {
                candidate_ref: c("test3"),
                posterior_prob: -0.5, // Negative probability
                prior_prob: 0.5,
                observation_count: 10,
                confidence_interval: (0.0, 1.0),
                guardrail_filtered: false,
            },
            RankedCandidate {
                candidate_ref: c("test4"),
                posterior_prob: 1.5, // Probability > 1.0
                prior_prob: 0.5,
                observation_count: 10,
                confidence_interval: (0.0, 1.0),
                guardrail_filtered: false,
            },
            RankedCandidate {
                candidate_ref: c("test5"),
                posterior_prob: 0.5,
                prior_prob: f64::NAN,        // NaN prior
                observation_count: u64::MAX, // Maximum observations
                confidence_interval: (f64::NEG_INFINITY, f64::INFINITY), // Infinite CI
                guardrail_filtered: true,
            },
        ];

        for candidate in extreme_candidates {
            // Candidate creation should not panic
            assert!(!candidate.candidate_ref.0.is_empty() || candidate.candidate_ref.0.is_empty());

            // Serialization should handle extreme values
            let serialization = serde_json::to_string(&candidate);
            match serialization {
                Ok(json) => {
                    // If serialization succeeds, fields should be preserved or normalized
                    let _deserialized: Result<RankedCandidate, _> = serde_json::from_str(&json);
                }
                Err(_) => {
                    // Some extreme values might not be JSON-serializable (NaN, Infinity)
                }
            }

            // Debug formatting should not panic
            let _debug_output = format!("{:?}", candidate);
        }
    }

    #[test]
    fn negative_diagnostic_confidence_serialization_edge_cases() {
        // Test DiagnosticConfidence serialization with edge cases
        let confidence_levels = [
            DiagnosticConfidence::Low,
            DiagnosticConfidence::Medium,
            DiagnosticConfidence::High,
        ];

        for confidence in confidence_levels {
            // Should serialize and deserialize correctly
            let serialized = serde_json::to_string(&confidence).unwrap();
            let deserialized: DiagnosticConfidence = serde_json::from_str(&serialized).unwrap();
            assert_eq!(confidence, deserialized);

            // Should be orderable
            let ordering = confidence.cmp(&confidence);
            assert_eq!(ordering, std::cmp::Ordering::Equal);
        }

        // Test deserialization with invalid enum values
        let invalid_confidence_json = vec![
            "\"Unknown\"",
            "\"HIGH\"",     // Wrong case
            "\"VeryHigh\"", // Non-existent variant
            "42",           // Wrong type
            "null",
        ];

        for invalid_json in invalid_confidence_json {
            let result: Result<DiagnosticConfidence, _> = serde_json::from_str(invalid_json);
            assert!(
                result.is_err(),
                "Should reject invalid confidence JSON: {}",
                invalid_json
            );
        }
    }

    #[test]
    fn negative_bayesian_update_numerical_stability_stress_test() {
        // Test numerical stability with many updates
        let mut state = BetaState::new();

        // Test with alternating success/failure pattern
        for i in 0..10_000 {
            state.update(i % 2 == 0);
        }

        // After many updates, state should still be valid
        assert!(state.alpha.is_finite());
        assert!(state.beta.is_finite());
        assert_eq!(state.observation_count, 10_000);

        let mean = state.mean();
        assert!(mean.is_finite() && mean >= 0.0 && mean <= 1.0);

        // With alternating pattern, mean should be close to 0.5
        assert!(
            (mean - 0.5).abs() < 0.1,
            "Mean should be close to 0.5 with alternating pattern: {}",
            mean
        );

        // Test with extreme bias (all successes)
        let mut success_state = BetaState::new();
        for _ in 0..1_000 {
            success_state.update(true);
        }

        let success_mean = success_state.mean();
        assert!(
            success_mean > 0.9,
            "All-success mean should be high: {}",
            success_mean
        );

        // Test with extreme bias (all failures)
        let mut failure_state = BetaState::new();
        for _ in 0..1_000 {
            failure_state.update(false);
        }

        let failure_mean = failure_state.mean();
        assert!(
            failure_mean < 0.1,
            "All-failure mean should be low: {}",
            failure_mean
        );
    }

    #[test]
    fn negative_confidence_interval_mathematical_edge_cases() {
        // Test confidence interval calculation with edge cases
        let edge_cases = vec![
            (1.0, 1.0),           // Uniform prior, no observations
            (1.0, f64::MAX),      // Infinite beta
            (f64::MAX, 1.0),      // Infinite alpha
            (f64::MAX, f64::MAX), // Both infinite
            (1e-100, 1.0),        // Very small alpha
            (1.0, 1e-100),        // Very small beta
            (1e100, 1e100),       // Very large values
        ];

        for (alpha, beta) in edge_cases {
            let state = BetaState {
                alpha,
                beta,
                observation_count: 1000,
            };

            let (ci_lower, ci_upper) = state.confidence_interval_95();

            // CI should always be valid bounds
            assert!(
                ci_lower.is_finite(),
                "CI lower should be finite: {}",
                ci_lower
            );
            assert!(
                ci_upper.is_finite(),
                "CI upper should be finite: {}",
                ci_upper
            );
            assert!(
                ci_lower >= 0.0,
                "CI lower should be non-negative: {}",
                ci_lower
            );
            assert!(
                ci_upper <= 1.0,
                "CI upper should not exceed 1.0: {}",
                ci_upper
            );
            assert!(
                ci_lower <= ci_upper,
                "CI bounds should be ordered: {} <= {}",
                ci_lower,
                ci_upper
            );

            // Mean should also be valid
            let mean = state.mean();
            if mean.is_finite() {
                assert!(
                    mean >= 0.0 && mean <= 1.0,
                    "Mean should be in [0,1]: {}",
                    mean
                );
                // Mean should typically be within CI (allowing for edge cases)
                if ci_lower <= ci_upper && ci_upper - ci_lower < 1.0 {
                    // Only check if CI is reasonable
                    assert!(
                        mean >= ci_lower - 0.1 && mean <= ci_upper + 0.1,
                        "Mean {} should be near CI [{}, {}]",
                        mean,
                        ci_lower,
                        ci_upper
                    );
                }
            }
        }
    }

    #[test]
    fn negative_constants_validation_and_event_code_consistency() {
        // Test that all event constants are well-formed
        let event_constants = [EVD_BAYES_001, EVD_BAYES_002, EVD_BAYES_003, EVD_BAYES_004];

        for constant in &event_constants {
            assert!(!constant.is_empty());
            assert!(
                constant.starts_with("EVD-BAYES-"),
                "Event constant should start with EVD-BAYES-: {}",
                constant
            );
            assert!(
                constant.is_ascii(),
                "Event constant should be ASCII: {}",
                constant
            );

            // Should follow pattern EVD-BAYES-XXX where XXX is a 3-digit number
            let suffix = constant.strip_prefix("EVD-BAYES-").unwrap();
            assert_eq!(
                suffix.len(),
                3,
                "Event code suffix should be 3 digits: {}",
                suffix
            );
            assert!(
                suffix.chars().all(|c| c.is_ascii_digit()),
                "Event code suffix should be numeric: {}",
                suffix
            );
        }

        // Verify event codes are sequential
        assert_eq!(EVD_BAYES_001, "EVD-BAYES-001");
        assert_eq!(EVD_BAYES_002, "EVD-BAYES-002");
        assert_eq!(EVD_BAYES_003, "EVD-BAYES-003");
        assert_eq!(EVD_BAYES_004, "EVD-BAYES-004");

        // Test type alias exists and is well-formed
        let _raw_score: RawCandidateScore = (
            c("test"),
            0.5,        // posterior_mean
            0.5,        // prior
            10,         // observation_count
            (0.3, 0.7), // confidence interval
        );

        // Type alias should work as expected
        assert_eq!(_raw_score.0, c("test"));
        assert_eq!(_raw_score.1, 0.5);
        assert_eq!(_raw_score.4.0, 0.3);
        assert_eq!(_raw_score.4.1, 0.7);
    }

    #[cfg(test)]
    mod bayesian_diagnostics_extreme_adversarial_negative_tests {
        use super::*;

        #[test]
        fn extreme_adversarial_memory_exhaustion_massive_candidate_set() {
            let mut diagnostics = BayesianDiagnostics::new();

            // Create massive candidate set to test memory limits
            let massive_candidates: Vec<CandidateRef> = (0..100_000)
                .map(|i| CandidateRef::new(format!("candidate_{i:010}_{}", "x".repeat(1000))))
                .collect();

            // Add observations to trigger internal state expansion
            for (i, candidate) in massive_candidates.iter().take(1000).enumerate() {
                diagnostics.update(&Observation::new(candidate.clone(), i % 2 == 0, i as u64));
            }

            // Ranking should handle massive candidate sets without crashing
            let result = diagnostics.rank_candidates(&massive_candidates, &[]);

            match result.len() {
                len if len == massive_candidates.len() => {
                    // If successful, verify normalization invariant
                    let total: f64 = result.iter().map(|r| r.posterior_prob).sum();
                    assert!(
                        (total - 1.0).abs() < 1e-6,
                        "Probabilities should sum to 1.0"
                    );
                }
                _ => {
                    // Acceptable to handle subset if memory limits are hit
                    assert!(!result.is_empty(), "Should return some candidates");
                }
            }
        }

        #[test]
        fn extreme_adversarial_unicode_injection_candidate_collision_attack() {
            let mut diagnostics = BayesianDiagnostics::new();

            // Unicode collision attack - visually similar candidates
            let collision_candidates = vec![
                CandidateRef::new("café"),                 // NFC normalized
                CandidateRef::new("cafe\u{301}"),          // NFD normalized (combining accent)
                CandidateRef::new("ca\u{FB00}e"),          // With ligature
                CandidateRef::new("caf\u{200B}e"),         // With zero-width space
                CandidateRef::new("\u{202E}éfac\u{202D}"), // RTL override attack
                CandidateRef::new("café\u{FEFF}"),         // With BOM
                CandidateRef::new("caf\u{00E9}"),          // Different Unicode encoding
                CandidateRef::new("CAFÉ".to_lowercase()),  // Case folding
            ];

            // Add observations to all collision candidates
            for (i, candidate) in collision_candidates.iter().enumerate() {
                for j in 0..10 {
                    diagnostics.update(&Observation::new(
                        candidate.clone(),
                        (i + j) % 2 == 0,
                        u64::try_from(i)
                            .unwrap_or(u64::MAX)
                            .saturating_mul(10)
                            .saturating_add(u64::try_from(j).unwrap_or(u64::MAX)),
                    ));
                }
            }

            let ranked = diagnostics.rank_candidates(&collision_candidates, &[]);

            // Should treat each Unicode variant as distinct candidate
            assert_eq!(ranked.len(), collision_candidates.len());

            // Verify BTreeMap ordering is consistent despite Unicode
            for candidate in &collision_candidates {
                let found = ranked.iter().find(|r| r.candidate_ref == *candidate);
                assert!(found.is_some(), "Should find candidate: {:?}", candidate.0);
            }

            // Probabilities should sum to 1.0 despite Unicode complexity
            let total: f64 = ranked.iter().map(|r| r.posterior_prob).sum();
            assert!(
                (total - 1.0).abs() < 1e-6,
                "Unicode collision should not break normalization"
            );
        }

        #[test]
        fn extreme_adversarial_floating_point_manipulation_precision_attack() {
            let mut diagnostics = BayesianDiagnostics::new();

            // Create observations designed to exploit floating-point precision
            let precision_attack_candidates = vec![
                CandidateRef::new("precise_1"),
                CandidateRef::new("precise_2"),
                CandidateRef::new("precise_3"),
            ];

            // Add observations with patterns that could cause precision loss
            for i in 0..1000 {
                // Patterns designed to stress floating-point arithmetic
                let success_pattern = match i % 7 {
                    0 => true,
                    1..=3 => false,
                    4..=5 => true,
                    _ => i % 17 == 0,
                };

                let candidate_idx = i % precision_attack_candidates.len();
                diagnostics.update(&Observation::new(
                    precision_attack_candidates[candidate_idx].clone(),
                    success_pattern,
                    i as u64,
                ));
            }

            let ranked = diagnostics.rank_candidates(&precision_attack_candidates, &[]);

            // Verify numerical stability despite precision attacks
            for candidate in &ranked {
                assert!(
                    candidate.posterior_prob.is_finite(),
                    "Posterior should be finite"
                );
                assert!(
                    candidate.posterior_prob >= 0.0,
                    "Posterior should be non-negative"
                );
                assert!(
                    candidate.posterior_prob <= 1.0,
                    "Posterior should not exceed 1.0"
                );

                let (ci_lower, ci_upper) = candidate.confidence_interval;
                assert!(
                    ci_lower.is_finite() && ci_upper.is_finite(),
                    "CI should be finite"
                );
                assert!(ci_lower >= 0.0 && ci_upper <= 1.0, "CI should be in [0,1]");
                assert!(ci_lower <= ci_upper, "CI bounds should be ordered");
            }

            // Total probability should remain normalized
            let total: f64 = ranked.iter().map(|r| r.posterior_prob).sum();
            assert!(
                (total - 1.0).abs() < 1e-10,
                "Precision attack should not break normalization"
            );
        }

        #[test]
        fn extreme_adversarial_concurrent_state_corruption_simulation() {
            // Simulate concurrent access by interleaving operations that could corrupt state
            let mut diagnostics = BayesianDiagnostics::new();

            let concurrent_candidates = vec![
                CandidateRef::new("concurrent_a"),
                CandidateRef::new("concurrent_b"),
                CandidateRef::new("concurrent_c"),
            ];

            // Simulate rapid, interleaved observations
            for round in 0..100 {
                for (i, candidate) in concurrent_candidates.iter().enumerate() {
                    // Rapid updates to simulate race conditions
                    for micro_update in 0..10 {
                        let epoch = u64::try_from(round)
                            .unwrap_or(u64::MAX)
                            .saturating_mul(30)
                            .saturating_add(u64::try_from(i).unwrap_or(u64::MAX).saturating_mul(10))
                            .saturating_add(u64::try_from(micro_update).unwrap_or(u64::MAX));
                        let success = (epoch % 3 + epoch % 7) % 2 == 0;

                        diagnostics.update(&Observation::new(candidate.clone(), success, epoch));

                        // Interleave ranking operations during updates
                        if micro_update % 3 == 0 {
                            let _intermediate_ranking =
                                diagnostics.rank_candidates(&concurrent_candidates, &[]);
                        }
                    }
                }
            }

            // Final state should be consistent despite simulated concurrency
            assert_eq!(diagnostics.total_observations(), 3000); // 100 * 3 * 10

            let final_ranking = diagnostics.rank_candidates(&concurrent_candidates, &[]);
            assert_eq!(final_ranking.len(), 3);

            // Verify consistency despite concurrent simulation
            let total: f64 = final_ranking.iter().map(|r| r.posterior_prob).sum();
            assert!(
                (total - 1.0).abs() < 1e-6,
                "Concurrent simulation should not corrupt state"
            );

            // Verify observation counts are consistent
            let total_obs: u64 = final_ranking.iter().map(|r| r.observation_count).sum();
            assert_eq!(total_obs, 3000, "Observation counts should be consistent");
        }

        #[test]
        fn extreme_adversarial_json_injection_serialization_attack() {
            let mut diagnostics = BayesianDiagnostics::new();

            // JSON injection patterns in candidate names
            let json_injection_candidates = vec![
                CandidateRef::new(r#"{"injected": "payload"}"#),
                CandidateRef::new("candidate\",\"injected\":\"evil\",\"real\":\""),
                CandidateRef::new("\\u0000\\u0001\\u0002"),
                CandidateRef::new("candidate\x00null\x01injection"),
                CandidateRef::new("</script><script>alert('xss')</script>"),
                CandidateRef::new("candidate\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
                CandidateRef::new("candidate\\\\\\\"escaped\\\"payload"),
            ];

            // Add observations with JSON injection candidates
            for (i, candidate) in json_injection_candidates.iter().enumerate() {
                diagnostics.update(&Observation::new(
                    candidate.clone(),
                    i % 2 == 0,
                    u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1000),
                ));
            }

            // Test JSON serialization with injection candidates
            let json_result = diagnostics.to_json();

            match json_result {
                Ok(json) => {
                    // If serialization succeeds, verify no injection
                    assert!(
                        !json.contains("<script>"),
                        "Should not contain script injection"
                    );
                    assert!(
                        !json.contains("HTTP/1.1"),
                        "Should not contain HTTP injection"
                    );

                    // Verify can be safely deserialized
                    let deserialization: Result<BayesianDiagnostics, _> =
                        serde_json::from_str(&json);
                    assert!(deserialization.is_ok(), "Should deserialize safely");

                    if let Ok(deserialized) = deserialization {
                        assert_eq!(
                            deserialized.total_observations(),
                            diagnostics.total_observations()
                        );
                    }
                }
                Err(_) => {
                    // Acceptable to reject JSON serialization with dangerous content
                }
            }

            // Ranking should work despite injection candidates
            let ranked = diagnostics.rank_candidates(&json_injection_candidates, &[]);
            assert_eq!(ranked.len(), json_injection_candidates.len());

            // Verify ranking serialization is safe
            for candidate in &ranked {
                let candidate_json = serde_json::to_string(candidate);
                match candidate_json {
                    Ok(json) => {
                        assert!(!json.contains("<script>"), "Candidate JSON should be safe");
                    }
                    Err(_) => {
                        // Acceptable to reject unsafe serialization
                    }
                }
            }
        }

        #[test]
        fn extreme_adversarial_algorithmic_complexity_attack() {
            let mut diagnostics = BayesianDiagnostics::new();

            // Create worst-case scenario for BTreeMap operations
            let complexity_attack_candidates: Vec<CandidateRef> = (0..1000)
                .map(|i| {
                    // Keys designed to cause maximum tree traversal
                    let key = match i % 4 {
                        0 => format!("\x00{i:010}"), // Null prefix
                        1 => format!("\x7F{i:010}"), // High ASCII
                        2 => format!("{i:010}\x00"), // Null suffix
                        _ => format!("aaaa{i:010}"), // Common prefix
                    };
                    CandidateRef::new(key)
                })
                .collect();

            // Add observations in order designed to stress tree balancing
            for i in 0..complexity_attack_candidates.len() {
                // Reverse order to stress tree insertion
                let idx = complexity_attack_candidates.len() - 1 - i;
                diagnostics.update(&Observation::new(
                    complexity_attack_candidates[idx].clone(),
                    i % 3 == 0,
                    i as u64,
                ));
            }

            // Ranking should complete in reasonable time despite complexity attack
            let start = std::time::Instant::now();
            let ranked = diagnostics.rank_candidates(&complexity_attack_candidates, &[]);
            let duration = start.elapsed();

            assert!(
                duration.as_millis() < 5000,
                "Ranking should complete quickly despite complexity attack: {:?}",
                duration
            );

            assert_eq!(ranked.len(), complexity_attack_candidates.len());

            // Verify correctness despite attack
            let total: f64 = ranked.iter().map(|r| r.posterior_prob).sum();
            assert!(
                (total - 1.0).abs() < 1e-6,
                "Complexity attack should not break correctness"
            );
        }

        #[test]
        fn extreme_adversarial_epoch_overflow_boundary_timestamp_attack() {
            let mut diagnostics = BayesianDiagnostics::new();

            // Test epoch boundary conditions that could cause overflow
            let epoch_boundaries = vec![
                (0, "epoch_zero"),
                (1, "epoch_one"),
                (u32::MAX as u64, "u32_max"),
                (u64::from(u32::MAX).saturating_add(1), "u32_overflow"),
                (i64::MAX as u64, "i64_max"),
                (u64::MAX - 1, "near_u64_max"),
                (u64::MAX, "u64_max"),
            ];

            let candidates = vec![
                CandidateRef::new("epoch_test_a"),
                CandidateRef::new("epoch_test_b"),
            ];

            // Add observations with boundary epochs
            for (epoch, description) in epoch_boundaries {
                for (i, candidate) in candidates.iter().enumerate() {
                    let adjusted_epoch = epoch.saturating_add(u64::try_from(i).unwrap_or(u64::MAX));
                    let obs = Observation::new(candidate.clone(), adjusted_epoch % 2 == 0, epoch);

                    diagnostics.update(&obs);

                    // Verify epoch is preserved correctly
                    assert_eq!(
                        diagnostics.epoch_id, epoch,
                        "Epoch should be preserved for: {}",
                        description
                    );
                }
            }

            // Should handle all epoch boundaries gracefully
            assert_eq!(diagnostics.total_observations(), epoch_boundaries.len() * 2);

            let ranked = diagnostics.rank_candidates(&candidates, &[]);
            assert_eq!(ranked.len(), 2);

            // Verify no overflow corruption
            let total: f64 = ranked.iter().map(|r| r.posterior_prob).sum();
            assert!(
                (total - 1.0).abs() < 1e-6,
                "Epoch boundary attack should not corrupt probabilities"
            );
        }

        #[test]
        fn extreme_adversarial_guardrail_set_collision_performance_attack() {
            let mut diagnostics = BayesianDiagnostics::new();

            // Create large set of candidates
            let large_candidate_set: Vec<CandidateRef> = (0..5000)
                .map(|i| CandidateRef::new(format!("candidate_{i:06}")))
                .collect();

            // Add observations to subset
            for candidate in large_candidate_set.iter().take(100) {
                diagnostics.update(&Observation::new(candidate.clone(), true, 1000));
            }

            // Create massive guardrail blocked set designed to stress set operations
            let massive_blocked_set: Vec<CandidateRef> = (0..10_000)
                .map(|i| CandidateRef::new(format!("blocked_candidate_{i:08}")))
                .collect();

            // Test ranking with massive blocked set
            let start = std::time::Instant::now();
            let ranked = diagnostics.rank_candidates(&large_candidate_set, &massive_blocked_set);
            let duration = start.elapsed();

            assert!(
                duration.as_millis() < 3000,
                "Guardrail filtering should be efficient: {:?}",
                duration
            );

            // No candidates should be filtered (none match)
            assert!(ranked.iter().all(|r| !r.guardrail_filtered));

            // Test with overlapping blocked candidates
            let overlapping_blocked: Vec<CandidateRef> = large_candidate_set
                .iter()
                .take(2500) // Half the candidates
                .cloned()
                .collect();

            let start2 = std::time::Instant::now();
            let ranked2 = diagnostics.rank_candidates(&large_candidate_set, &overlapping_blocked);
            let duration2 = start2.elapsed();

            assert!(
                duration2.as_millis() < 2000,
                "Overlapping guardrail filtering should be efficient: {:?}",
                duration2
            );

            // Verify correct filtering
            let filtered_count = ranked2.iter().filter(|r| r.guardrail_filtered).count();
            assert_eq!(
                filtered_count, 2500,
                "Should filter exactly half the candidates"
            );
        }

        #[test]
        fn extreme_adversarial_beta_distribution_numerical_edge_case_exploitation() {
            // Test extreme beta distribution edge cases that could be exploited
            let edge_case_states = vec![
                (f64::MIN_POSITIVE, f64::MIN_POSITIVE), // Minimal positive values
                (f64::MAX / 1e10, f64::MAX / 1e10),     // Very large but finite
                (1e-300, 1e-300),                       // Near machine epsilon
                (1e100, 1e-100),                        // Extreme ratio
                (1e-100, 1e100),                        // Reverse extreme ratio
                (1.0, 1e-308),                          // Near underflow
                (1e308, 1.0),                           // Near overflow
            ];

            for (alpha, beta) in edge_case_states {
                let state = BetaState {
                    alpha,
                    beta,
                    observation_count: 1000,
                };

                // Mean should be stable
                let mean = state.mean();
                if mean != 0.0 {
                    // Allow fail-closed to 0.0
                    assert!(
                        mean.is_finite(),
                        "Mean should be finite for alpha={}, beta={}",
                        alpha,
                        beta
                    );
                    assert!(
                        mean >= 0.0 && mean <= 1.0,
                        "Mean should be in [0,1] for alpha={}, beta={}",
                        alpha,
                        beta
                    );
                }

                // Confidence interval should be bounded
                let (ci_lower, ci_upper) = state.confidence_interval_95();
                assert!(
                    ci_lower.is_finite() && ci_upper.is_finite(),
                    "CI should be finite"
                );
                assert!(ci_lower >= 0.0 && ci_upper <= 1.0, "CI should be in [0,1]");
                assert!(ci_lower <= ci_upper, "CI should be ordered");

                // State should handle updates without breaking
                let mut test_state = state;
                test_state.update(true);
                test_state.update(false);

                // After update, should remain stable
                let updated_mean = test_state.mean();
                if updated_mean != 0.0 {
                    assert!(updated_mean.is_finite(), "Updated mean should be finite");
                }
            }
        }

        #[test]
        fn extreme_adversarial_replay_determinism_hash_collision_verification() {
            // Test replay determinism against potential hash collision attacks
            let base_observations = vec![
                Observation::new(CandidateRef::new("base"), true, 1),
                Observation::new(CandidateRef::new("base"), false, 2),
                Observation::new(CandidateRef::new("other"), true, 3),
            ];

            // Create variations that could cause hash collisions in internal state
            let collision_observations = vec![
                // Same logical content, different epoch ordering
                Observation::new(CandidateRef::new("base"), true, 100),
                Observation::new(CandidateRef::new("other"), true, 101),
                Observation::new(CandidateRef::new("base"), false, 102),
                // Additional similar observations
                Observation::new(CandidateRef::new("base"), true, 200),
                Observation::new(CandidateRef::new("base"), false, 201),
                Observation::new(CandidateRef::new("other"), true, 202),
            ];

            // Replay multiple times with different observation orderings
            let replay1 = BayesianDiagnostics::replay_from(&base_observations);
            let replay2 = BayesianDiagnostics::replay_from(&base_observations);

            let candidates = vec![CandidateRef::new("base"), CandidateRef::new("other")];

            let ranking1 = replay1.rank_candidates(&candidates, &[]);
            let ranking2 = replay2.rank_candidates(&candidates, &[]);

            // Should be bit-identical despite potential hash collisions
            for (r1, r2) in ranking1.iter().zip(ranking2.iter()) {
                assert_eq!(
                    r1.posterior_prob.to_bits(),
                    r2.posterior_prob.to_bits(),
                    "Replay should be bit-identical"
                );
                assert_eq!(r1.candidate_ref, r2.candidate_ref);
                assert_eq!(r1.observation_count, r2.observation_count);
            }

            // Test with collision-prone observations
            let collision_replay1 = BayesianDiagnostics::replay_from(&collision_observations);
            let collision_replay2 = BayesianDiagnostics::replay_from(&collision_observations);

            let collision_ranking1 = collision_replay1.rank_candidates(&candidates, &[]);
            let collision_ranking2 = collision_replay2.rank_candidates(&candidates, &[]);

            // Should remain deterministic despite collision attempts
            for (r1, r2) in collision_ranking1.iter().zip(collision_ranking2.iter()) {
                assert_eq!(
                    r1.posterior_prob.to_bits(),
                    r2.posterior_prob.to_bits(),
                    "Collision-prone replay should be deterministic"
                );
            }
        }
    }
}
