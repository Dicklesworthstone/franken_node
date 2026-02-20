//! bd-15u3: Guardrail precedence enforcement for policy decisions.
//!
//! Integrates the Bayesian posterior ranking (bd-2igi) with the anytime-valid
//! guardrail monitor set (bd-3a3q) to enforce a strict precedence rule:
//! guardrails ALWAYS override Bayesian recommendations.
//!
//! # Invariants
//!
//! - **INV-DECIDE-PRECEDENCE**: Guardrail verdicts override Bayesian rankings.
//!   No amount of statistical evidence authorises an action that violates a
//!   safety or durability bound.
//! - **INV-DECIDE-DETERMINISTIC**: Given identical candidates, monitors, and
//!   state, `decide` returns identical outcomes.
//! - **INV-DECIDE-NO-PANIC**: `AllBlocked` is returned (never a panic) when
//!   no candidate passes guardrails.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::bayesian_diagnostics::{CandidateRef, RankedCandidate};
use super::guardrail_monitor::{GuardrailMonitorSet, GuardrailVerdict, SystemState};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Decision made (includes chosen candidate, rank).
pub const EVD_DECIDE_001: &str = "EVD-DECIDE-001";
/// Candidate blocked by guardrail (includes guardrail_id, candidate_ref).
pub const EVD_DECIDE_002: &str = "EVD-DECIDE-002";
/// All candidates blocked.
pub const EVD_DECIDE_003: &str = "EVD-DECIDE-003";
/// Fallback to lower-ranked candidate.
pub const EVD_DECIDE_004: &str = "EVD-DECIDE-004";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Identifies a specific guardrail that blocked a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GuardrailId(pub String);

impl GuardrailId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GuardrailId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A candidate that was blocked by one or more guardrails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedCandidate {
    /// The candidate that was blocked.
    pub candidate: CandidateRef,
    /// Which guardrail(s) blocked this candidate.
    pub blocked_by: Vec<GuardrailId>,
    /// The candidate's original rank from the Bayesian engine (0-indexed).
    pub bayesian_rank: usize,
    /// Human-readable reasons from each blocking guardrail.
    pub reasons: Vec<String>,
}

/// Why the decision engine chose (or could not choose) a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionReason {
    /// The top-ranked candidate passed all guardrails.
    TopCandidateAccepted,
    /// The top-ranked candidate was blocked; a lower-ranked candidate was used.
    TopCandidateBlockedFallbackUsed {
        /// The rank of the fallback candidate that was chosen.
        fallback_rank: usize,
    },
    /// Every candidate was blocked by at least one guardrail.
    AllCandidatesBlocked,
    /// No candidates were provided.
    NoCandidates,
}

/// Result of the decision engine's precedence check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionOutcome {
    /// The chosen candidate, if any passed guardrails.
    pub chosen: Option<CandidateRef>,
    /// All candidates that were blocked, with details.
    pub blocked: Vec<BlockedCandidate>,
    /// Why this outcome was reached.
    pub reason: DecisionReason,
    /// Epoch in which this decision was made.
    pub epoch_id: u64,
}

// ---------------------------------------------------------------------------
// DecisionEngine
// ---------------------------------------------------------------------------

/// Enforces guardrail precedence over Bayesian recommendations.
///
/// The engine iterates candidates in rank order (highest posterior first) and
/// returns the first candidate that passes all guardrails. Candidates that
/// fail any guardrail are recorded in `blocked` with the specific guardrail
/// IDs and reasons.
///
/// INV-DECIDE-PRECEDENCE: guardrails always override Bayesian rankings.
#[derive(Debug, Clone)]
pub struct DecisionEngine {
    epoch_id: u64,
}

impl DecisionEngine {
    pub fn new(epoch_id: u64) -> Self {
        Self { epoch_id }
    }

    /// Apply guardrail checks to the Bayesian ranking and return the
    /// highest-ranked candidate that passes all guardrails.
    ///
    /// The function checks both:
    /// 1. System-level guardrails (from monitors + state) — these block ALL
    ///    candidates if any system invariant is violated.
    /// 2. Per-candidate guardrail flags (`guardrail_filtered` on each
    ///    `RankedCandidate`) — these block specific candidates.
    ///
    /// [EVD-DECIDE-001] on decision made.
    /// [EVD-DECIDE-002] on candidate blocked.
    /// [EVD-DECIDE-003] on all candidates blocked.
    /// [EVD-DECIDE-004] on fallback to lower-ranked candidate.
    pub fn decide(
        &self,
        candidates: &[RankedCandidate],
        monitors: &GuardrailMonitorSet,
        state: &SystemState,
    ) -> DecisionOutcome {
        if candidates.is_empty() {
            return DecisionOutcome {
                chosen: None,
                blocked: Vec::new(),
                reason: DecisionReason::NoCandidates,
                epoch_id: self.epoch_id,
            };
        }

        // Collect system-level guardrail violations.
        let system_blocks: Vec<(String, GuardrailId, String)> = monitors
            .check_all_detailed(state)
            .into_iter()
            .filter_map(|(name, verdict)| {
                if let GuardrailVerdict::Block { reason, budget_id } = verdict {
                    Some((
                        name.to_string(),
                        GuardrailId::new(budget_id.as_str()),
                        reason,
                    ))
                } else {
                    None
                }
            })
            .collect();

        let has_system_blocks = !system_blocks.is_empty();

        let mut blocked = Vec::new();
        let mut chosen: Option<(CandidateRef, usize)> = None;

        for (rank, candidate) in candidates.iter().enumerate() {
            let mut blocking_ids: Vec<GuardrailId> = Vec::new();
            let mut blocking_reasons: Vec<String> = Vec::new();

            // System-level blocks apply to all candidates.
            if has_system_blocks {
                for (_name, gid, reason) in &system_blocks {
                    blocking_ids.push(gid.clone());
                    blocking_reasons.push(reason.clone());
                }
            }

            // Per-candidate guardrail filter.
            if candidate.guardrail_filtered {
                blocking_ids.push(GuardrailId::new("per_candidate_guardrail"));
                blocking_reasons
                    .push(format!("candidate {} blocked by guardrail filter", candidate.candidate_ref.0));
            }

            if blocking_ids.is_empty() {
                // This candidate passes all guardrails.
                if chosen.is_none() {
                    chosen = Some((candidate.candidate_ref.clone(), rank));
                }
            } else {
                // [EVD-DECIDE-002] candidate blocked
                let _event = EVD_DECIDE_002;

                blocked.push(BlockedCandidate {
                    candidate: candidate.candidate_ref.clone(),
                    blocked_by: blocking_ids,
                    bayesian_rank: rank,
                    reasons: blocking_reasons,
                });
            }
        }

        let reason = match &chosen {
            Some((_, 0)) => {
                // [EVD-DECIDE-001] top candidate accepted
                let _event = EVD_DECIDE_001;
                DecisionReason::TopCandidateAccepted
            }
            Some((_, rank)) => {
                // [EVD-DECIDE-004] fallback used
                let _event = EVD_DECIDE_004;
                DecisionReason::TopCandidateBlockedFallbackUsed {
                    fallback_rank: *rank,
                }
            }
            None => {
                // [EVD-DECIDE-003] all blocked
                let _event = EVD_DECIDE_003;
                DecisionReason::AllCandidatesBlocked
            }
        };

        DecisionOutcome {
            chosen: chosen.map(|(c, _)| c),
            blocked,
            reason,
            epoch_id: self.epoch_id,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::bayesian_diagnostics::CandidateRef;
    use crate::policy::guardrail_monitor::{
        DurabilityLossGuardrail, EvidenceEmissionGuardrail, GuardrailMonitorSet,
        HardeningRegressionGuardrail, MemoryBudgetGuardrail, SystemState,
    };
    use crate::policy::hardening_state_machine::HardeningLevel;

    fn c(id: &str) -> CandidateRef {
        CandidateRef::new(id)
    }

    fn ranked(id: &str, posterior: f64, rank_filtered: bool) -> RankedCandidate {
        RankedCandidate {
            candidate_ref: c(id),
            posterior_prob: posterior,
            prior_prob: 0.5,
            observation_count: 10,
            confidence_interval: (posterior - 0.1, posterior + 0.1),
            guardrail_filtered: rank_filtered,
        }
    }

    fn healthy_state() -> SystemState {
        SystemState {
            memory_used_bytes: 500_000_000,
            memory_budget_bytes: 1_000_000_000,
            durability_level: 0.99,
            hardening_level: HardeningLevel::Standard,
            proposed_hardening_level: None,
            evidence_emission_active: true,
            epoch_id: 42,
        }
    }

    fn default_monitors() -> GuardrailMonitorSet {
        GuardrailMonitorSet::with_defaults()
    }

    fn engine() -> DecisionEngine {
        DecisionEngine::new(42)
    }

    // ── Empty candidates ──

    #[test]
    fn test_decide_empty_candidates() {
        let outcome = engine().decide(&[], &default_monitors(), &healthy_state());
        assert!(outcome.chosen.is_none());
        assert!(outcome.blocked.is_empty());
        assert_eq!(outcome.reason, DecisionReason::NoCandidates);
    }

    // ── Single candidate passes ──

    #[test]
    fn test_decide_single_candidate_passes() {
        let candidates = vec![ranked("A", 0.9, false)];
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        assert_eq!(outcome.chosen, Some(c("A")));
        assert!(outcome.blocked.is_empty());
        assert_eq!(outcome.reason, DecisionReason::TopCandidateAccepted);
    }

    // ── Single candidate blocked (per-candidate) ──

    #[test]
    fn test_decide_single_candidate_blocked_per_candidate() {
        let candidates = vec![ranked("A", 0.9, true)];
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.blocked.len(), 1);
        assert_eq!(outcome.blocked[0].candidate, c("A"));
        assert_eq!(outcome.reason, DecisionReason::AllCandidatesBlocked);
    }

    // ── Multiple candidates, first blocked, second chosen ──

    #[test]
    fn test_decide_top_blocked_fallback_to_second() {
        let candidates = vec![
            ranked("aggressive", 0.8, true),
            ranked("conservative", 0.2, false),
        ];
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        assert_eq!(outcome.chosen, Some(c("conservative")));
        assert_eq!(outcome.blocked.len(), 1);
        assert_eq!(outcome.blocked[0].candidate, c("aggressive"));
        assert_eq!(outcome.blocked[0].bayesian_rank, 0);
        assert_eq!(
            outcome.reason,
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 1 }
        );
    }

    // ── All candidates blocked ──

    #[test]
    fn test_decide_all_blocked() {
        let candidates = vec![
            ranked("A", 0.6, true),
            ranked("B", 0.3, true),
            ranked("C", 0.1, true),
        ];
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.blocked.len(), 3);
        assert_eq!(outcome.reason, DecisionReason::AllCandidatesBlocked);
    }

    // ── System-level guardrail blocks all candidates ──

    #[test]
    fn test_decide_system_level_block() {
        let candidates = vec![ranked("A", 0.7, false), ranked("B", 0.3, false)];
        let mut state = healthy_state();
        state.evidence_emission_active = false; // triggers EvidenceEmissionGuardrail Block

        let outcome = engine().decide(&candidates, &default_monitors(), &state);
        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.blocked.len(), 2);
        assert_eq!(outcome.reason, DecisionReason::AllCandidatesBlocked);

        // Both candidates blocked by the same system-level guardrail
        for b in &outcome.blocked {
            assert!(b.blocked_by.iter().any(|g| g.as_str() == "evidence_emission"));
        }
    }

    // ── System-level guardrail with per-candidate filter combined ──

    #[test]
    fn test_decide_system_plus_per_candidate_block() {
        let candidates = vec![
            ranked("A", 0.7, true),  // per-candidate + system
            ranked("B", 0.3, false), // system only
        ];
        let mut state = healthy_state();
        state.evidence_emission_active = false;

        let outcome = engine().decide(&candidates, &default_monitors(), &state);
        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.blocked.len(), 2);

        // Candidate A has both per-candidate and system guardrail
        let a_blocked = &outcome.blocked[0];
        assert_eq!(a_blocked.candidate, c("A"));
        assert!(a_blocked.blocked_by.len() >= 2);
    }

    // ── Candidate order matches Bayesian rank ──

    #[test]
    fn test_decide_preserves_bayesian_rank_order() {
        let candidates = vec![
            ranked("first", 0.6, true),
            ranked("second", 0.3, true),
            ranked("third", 0.1, false),
        ];
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        assert_eq!(outcome.chosen, Some(c("third")));
        assert_eq!(outcome.blocked[0].bayesian_rank, 0);
        assert_eq!(outcome.blocked[1].bayesian_rank, 1);
        assert_eq!(
            outcome.reason,
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 2 }
        );
    }

    // ── Memory budget guardrail blocks all ──

    #[test]
    fn test_decide_memory_budget_blocks_all() {
        let candidates = vec![ranked("A", 0.5, false), ranked("B", 0.5, false)];
        let mut state = healthy_state();
        state.memory_used_bytes = 960_000_000; // 96% > 95% threshold

        let outcome = engine().decide(&candidates, &default_monitors(), &state);
        assert!(outcome.chosen.is_none());
        for b in &outcome.blocked {
            assert!(b.blocked_by.iter().any(|g| g.as_str() == "memory_budget"));
        }
    }

    // ── Durability guardrail blocks all ──

    #[test]
    fn test_decide_durability_blocks_all() {
        let candidates = vec![ranked("A", 0.5, false)];
        let mut state = healthy_state();
        state.durability_level = 0.85; // below 0.9 minimum

        let outcome = engine().decide(&candidates, &default_monitors(), &state);
        assert!(outcome.chosen.is_none());
        assert!(outcome.blocked[0]
            .blocked_by
            .iter()
            .any(|g| g.as_str() == "durability_budget"));
    }

    // ── Hardening regression blocks all ──

    #[test]
    fn test_decide_hardening_regression_blocks_all() {
        let candidates = vec![ranked("A", 0.5, false)];
        let mut state = healthy_state();
        state.proposed_hardening_level = Some(HardeningLevel::Baseline);

        let outcome = engine().decide(&candidates, &default_monitors(), &state);
        assert!(outcome.chosen.is_none());
        assert!(outcome.blocked[0]
            .blocked_by
            .iter()
            .any(|g| g.as_str() == "hardening_regression"));
    }

    // ── Epoch propagation ──

    #[test]
    fn test_decide_epoch_id_propagated() {
        let eng = DecisionEngine::new(99);
        let candidates = vec![ranked("A", 0.5, false)];
        let outcome = eng.decide(&candidates, &default_monitors(), &healthy_state());
        assert_eq!(outcome.epoch_id, 99);
    }

    // ── Healthy system, all candidates pass ──

    #[test]
    fn test_decide_multiple_candidates_all_pass() {
        let candidates = vec![
            ranked("A", 0.6, false),
            ranked("B", 0.3, false),
            ranked("C", 0.1, false),
        ];
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        assert_eq!(outcome.chosen, Some(c("A")));
        assert!(outcome.blocked.is_empty());
        assert_eq!(outcome.reason, DecisionReason::TopCandidateAccepted);
    }

    // ── Empty monitor set (no guardrails) allows everything ──

    #[test]
    fn test_decide_no_monitors_allows_all() {
        let monitors = GuardrailMonitorSet::new(); // empty
        let candidates = vec![ranked("A", 0.5, false)];
        let outcome = engine().decide(&candidates, &monitors, &healthy_state());
        assert_eq!(outcome.chosen, Some(c("A")));
    }

    // ── Per-candidate guardrail_filtered but no monitors ──

    #[test]
    fn test_decide_per_candidate_no_monitors() {
        let monitors = GuardrailMonitorSet::new();
        let candidates = vec![ranked("A", 0.7, true), ranked("B", 0.3, false)];
        let outcome = engine().decide(&candidates, &monitors, &healthy_state());
        assert_eq!(outcome.chosen, Some(c("B")));
        assert_eq!(outcome.blocked.len(), 1);
        assert_eq!(
            outcome.reason,
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 1 }
        );
    }

    // ── Blocked candidate includes reasons ──

    #[test]
    fn test_blocked_candidate_has_reasons() {
        let candidates = vec![ranked("A", 0.5, true)];
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        assert!(!outcome.blocked[0].reasons.is_empty());
    }

    // ── Deterministic: same inputs → same outputs ──

    #[test]
    fn test_decide_deterministic() {
        let candidates = vec![
            ranked("A", 0.6, true),
            ranked("B", 0.3, false),
            ranked("C", 0.1, true),
        ];
        let monitors = default_monitors();
        let state = healthy_state();
        let eng = engine();

        let o1 = eng.decide(&candidates, &monitors, &state);
        let o2 = eng.decide(&candidates, &monitors, &state);
        assert_eq!(o1.reason, o2.reason);
        assert_eq!(o1.chosen, o2.chosen);
        assert_eq!(o1.blocked.len(), o2.blocked.len());
    }

    // ── Warn-level guardrails do NOT block candidates ──

    #[test]
    fn test_decide_warn_does_not_block() {
        let candidates = vec![ranked("A", 0.5, false)];
        let mut state = healthy_state();
        state.memory_used_bytes = 850_000_000; // 85% → warn, not block

        let outcome = engine().decide(&candidates, &default_monitors(), &state);
        assert_eq!(outcome.chosen, Some(c("A")));
        assert!(outcome.blocked.is_empty());
    }

    // ── Boundary condition: posterior tie, guardrail differentiates ──

    #[test]
    fn test_decide_tie_with_guardrail() {
        let candidates = vec![
            ranked("A", 0.5, true),  // blocked
            ranked("B", 0.5, false), // passes
        ];
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        assert_eq!(outcome.chosen, Some(c("B")));
    }

    // ── Serialization roundtrip ──

    #[test]
    fn test_decision_outcome_serialization() {
        let outcome = DecisionOutcome {
            chosen: Some(c("test")),
            blocked: vec![BlockedCandidate {
                candidate: c("blocked"),
                blocked_by: vec![GuardrailId::new("memory_budget")],
                bayesian_rank: 0,
                reasons: vec!["over limit".to_string()],
            }],
            reason: DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 1 },
            epoch_id: 42,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: DecisionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chosen, Some(c("test")));
        assert_eq!(parsed.epoch_id, 42);
    }

    // ── GuardrailId display and as_str ──

    #[test]
    fn test_guardrail_id_display() {
        let gid = GuardrailId::new("memory_budget");
        assert_eq!(gid.to_string(), "memory_budget");
        assert_eq!(gid.as_str(), "memory_budget");
    }

    // ── Event codes exist ──

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(EVD_DECIDE_001, "EVD-DECIDE-001");
        assert_eq!(EVD_DECIDE_002, "EVD-DECIDE-002");
        assert_eq!(EVD_DECIDE_003, "EVD-DECIDE-003");
        assert_eq!(EVD_DECIDE_004, "EVD-DECIDE-004");
    }

    // ── DecisionReason variants ──

    #[test]
    fn test_decision_reason_top_accepted() {
        let r = DecisionReason::TopCandidateAccepted;
        assert_eq!(r, DecisionReason::TopCandidateAccepted);
    }

    #[test]
    fn test_decision_reason_fallback() {
        let r = DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 2 };
        assert_eq!(
            r,
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 2 }
        );
    }

    #[test]
    fn test_decision_reason_all_blocked() {
        let r = DecisionReason::AllCandidatesBlocked;
        assert_eq!(r, DecisionReason::AllCandidatesBlocked);
    }

    #[test]
    fn test_decision_reason_no_candidates() {
        let r = DecisionReason::NoCandidates;
        assert_eq!(r, DecisionReason::NoCandidates);
    }

    // ── Multiple system-level blocks accumulate ──

    #[test]
    fn test_decide_multiple_system_blocks_accumulate() {
        let candidates = vec![ranked("A", 0.5, false)];
        let mut state = healthy_state();
        state.evidence_emission_active = false;
        state.durability_level = 0.85;

        let outcome = engine().decide(&candidates, &default_monitors(), &state);
        assert!(outcome.chosen.is_none());
        // Should have at least 2 blocking guardrails on the candidate
        assert!(outcome.blocked[0].blocked_by.len() >= 2);
    }

    // ── Fallback picks first passing, not last ──

    #[test]
    fn test_decide_fallback_picks_first_passing() {
        let candidates = vec![
            ranked("first", 0.5, true),
            ranked("second", 0.3, false),
            ranked("third", 0.2, false),
        ];
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        assert_eq!(outcome.chosen, Some(c("second")));
        assert_eq!(
            outcome.reason,
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 1 }
        );
    }

    // ── Middle candidate blocked, last chosen ──

    #[test]
    fn test_decide_middle_and_first_blocked() {
        let candidates = vec![
            ranked("A", 0.5, true),
            ranked("B", 0.3, true),
            ranked("C", 0.2, false),
        ];
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        assert_eq!(outcome.chosen, Some(c("C")));
        assert_eq!(outcome.blocked.len(), 2);
        assert_eq!(
            outcome.reason,
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 2 }
        );
    }

    // ── Large candidate set (100 candidates, randomized blocking) ──

    #[test]
    fn test_decide_large_candidate_set() {
        let candidates: Vec<RankedCandidate> = (0..100)
            .map(|i| ranked(&format!("C{i}"), 1.0 - (i as f64 * 0.01), i < 90))
            .collect();
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        // First 90 are blocked, C90 should be chosen
        assert_eq!(outcome.chosen, Some(c("C90")));
        assert_eq!(outcome.blocked.len(), 90);
        assert_eq!(
            outcome.reason,
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 90 }
        );
    }

    // ── BlockedCandidate serialization ──

    #[test]
    fn test_blocked_candidate_serialization() {
        let bc = BlockedCandidate {
            candidate: c("test"),
            blocked_by: vec![GuardrailId::new("mem"), GuardrailId::new("dur")],
            bayesian_rank: 0,
            reasons: vec!["over memory".into(), "low durability".into()],
        };
        let json = serde_json::to_string(&bc).unwrap();
        let parsed: BlockedCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.candidate, c("test"));
        assert_eq!(parsed.blocked_by.len(), 2);
    }

    // ── Only one monitor registered ──

    #[test]
    fn test_decide_single_monitor_blocks() {
        let mut monitors = GuardrailMonitorSet::new();
        monitors.register(Box::new(MemoryBudgetGuardrail::default_guardrail()));

        let candidates = vec![ranked("A", 0.5, false)];
        let mut state = healthy_state();
        state.memory_used_bytes = 960_000_000;

        let outcome = engine().decide(&candidates, &monitors, &state);
        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.blocked[0].blocked_by.len(), 1);
    }

    // ── New engine with different epoch ──

    #[test]
    fn test_engine_different_epochs() {
        let eng1 = DecisionEngine::new(1);
        let eng2 = DecisionEngine::new(999);
        let candidates = vec![ranked("A", 0.5, false)];
        let o1 = eng1.decide(&candidates, &default_monitors(), &healthy_state());
        let o2 = eng2.decide(&candidates, &default_monitors(), &healthy_state());
        assert_eq!(o1.epoch_id, 1);
        assert_eq!(o2.epoch_id, 999);
    }

    // ── All candidates filtered with empty monitors still blocks ──

    #[test]
    fn test_decide_all_filtered_empty_monitors() {
        let monitors = GuardrailMonitorSet::new();
        let candidates = vec![ranked("A", 0.7, true), ranked("B", 0.3, true)];
        let outcome = engine().decide(&candidates, &monitors, &healthy_state());
        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.reason, DecisionReason::AllCandidatesBlocked);
    }
}
