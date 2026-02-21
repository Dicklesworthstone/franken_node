//! bd-kiqr: Trust-system complexity risk controls.
//!
//! Detects and mitigates trust-system complexity by enforcing:
//! 1. Deterministic trust decision replay (INV-RTC-REPLAY)
//! 2. Degraded-mode trust contracts (INV-RTC-DEGRADED)
//! 3. Trust complexity budgets (INV-RTC-BUDGET)
//! 4. Trust decision audit tracking (INV-RTC-AUDIT)
//!
//! # Event Codes
//!
//! - `RTC-001`: Trust decision replay verified — deterministic
//! - `RTC-002`: Trust decision replay diverged — non-determinism detected
//! - `RTC-003`: Degraded-mode trust decision — subsystem unavailable
//! - `RTC-004`: Trust complexity budget exceeded — decision chain too deep
//!
//! # Invariants
//!
//! - **INV-RTC-REPLAY**: Every trust decision is deterministically replayable
//! - **INV-RTC-DEGRADED**: Degraded-mode has explicit contract with max duration
//! - **INV-RTC-BUDGET**: Decision chain depth does not exceed complexity budget
//! - **INV-RTC-AUDIT**: Trust decision outcomes are tracked with dashboard visibility

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const RTC_001_REPLAY_VERIFIED: &str = "RTC-001";
    pub const RTC_002_REPLAY_DIVERGED: &str = "RTC-002";
    pub const RTC_003_DEGRADED_MODE: &str = "RTC-003";
    pub const RTC_004_BUDGET_EXCEEDED: &str = "RTC-004";
}

use event_codes::*;

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_RTC_REPLAY: &str = "INV-RTC-REPLAY";
pub const INV_RTC_DEGRADED: &str = "INV-RTC-DEGRADED";
pub const INV_RTC_BUDGET: &str = "INV-RTC-BUDGET";
pub const INV_RTC_AUDIT: &str = "INV-RTC-AUDIT";

// ---------------------------------------------------------------------------
// Trust decision outcome
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustOutcome {
    Grant,
    Deny,
    Escalate,
    Degraded,
}

impl TrustOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Deny => "deny",
            Self::Escalate => "escalate",
            Self::Degraded => "degraded",
        }
    }
}

impl fmt::Display for TrustOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Trust decision context — captures all inputs for replay
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustDecisionContext {
    pub decision_id: String,
    pub endpoint_group: String,
    pub token: String,
    pub epoch: u64,
    pub capability_set: Vec<String>,
    pub clock_value: String,
    pub chain_depth: u32,
}

// ---------------------------------------------------------------------------
// Trust decision record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustDecision {
    pub context: TrustDecisionContext,
    pub outcome: TrustOutcome,
    pub reason: String,
    pub decided_at: String,
}

// ---------------------------------------------------------------------------
// Replay result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayResult {
    pub decision_id: String,
    pub original_outcome: TrustOutcome,
    pub replayed_outcome: TrustOutcome,
    pub deterministic: bool,
}

// ---------------------------------------------------------------------------
// Degraded mode state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DegradedModeState {
    pub active: bool,
    pub reason: String,
    pub cached_capabilities: Vec<String>,
    pub activated_at: Option<String>,
    pub max_duration_seconds: u64,
    pub elapsed_seconds: u64,
}

impl DegradedModeState {
    pub fn new(max_duration_seconds: u64) -> Self {
        Self {
            active: false,
            reason: String::new(),
            cached_capabilities: Vec::new(),
            activated_at: None,
            max_duration_seconds,
            elapsed_seconds: 0,
        }
    }

    pub fn activate(&mut self, reason: &str, cached_caps: Vec<String>, timestamp: &str) {
        self.active = true;
        self.reason = reason.to_string();
        self.cached_capabilities = cached_caps;
        self.activated_at = Some(timestamp.to_string());
        self.elapsed_seconds = 0;
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        self.reason.clear();
        self.cached_capabilities.clear();
        self.activated_at = None;
        self.elapsed_seconds = 0;
    }

    pub fn is_expired(&self) -> bool {
        self.active && self.elapsed_seconds > self.max_duration_seconds
    }

    pub fn is_capability_cached(&self, cap: &str) -> bool {
        self.cached_capabilities.iter().any(|c| c == cap)
    }
}

// ---------------------------------------------------------------------------
// Trust complexity budget
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplexityBudget {
    pub default_max_depth: u32,
    pub endpoint_overrides: HashMap<String, u32>,
}

impl ComplexityBudget {
    pub fn new(default_max_depth: u32) -> Self {
        Self {
            default_max_depth,
            endpoint_overrides: HashMap::new(),
        }
    }

    pub fn max_depth_for(&self, endpoint_group: &str) -> u32 {
        self.endpoint_overrides
            .get(endpoint_group)
            .copied()
            .unwrap_or(self.default_max_depth)
    }

    pub fn set_override(&mut self, endpoint_group: &str, max_depth: u32) {
        self.endpoint_overrides
            .insert(endpoint_group.to_string(), max_depth);
    }

    pub fn exceeds_budget(&self, endpoint_group: &str, chain_depth: u32) -> bool {
        chain_depth > self.max_depth_for(endpoint_group)
    }
}

impl Default for ComplexityBudget {
    fn default() -> Self {
        Self::new(5)
    }
}

// ---------------------------------------------------------------------------
// Trust audit event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustAuditEvent {
    pub code: String,
    pub decision_id: String,
    pub endpoint_group: String,
    pub outcome: TrustOutcome,
    pub chain_depth: u32,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Trust audit summary — dashboard snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustAuditSummary {
    pub total_decisions: u64,
    pub grants: u64,
    pub denials: u64,
    pub escalations: u64,
    pub degraded: u64,
    pub replay_verified: u64,
    pub replay_diverged: u64,
    pub budget_exceeded: u64,
    pub avg_chain_depth: f64,
    pub replay_success_rate_pct: f64,
    pub degraded_mode_activations: u64,
}

// ---------------------------------------------------------------------------
// Trust complexity gate
// ---------------------------------------------------------------------------

pub struct TrustComplexityGate {
    decisions: Vec<TrustDecision>,
    replay_results: Vec<ReplayResult>,
    degraded_state: DegradedModeState,
    budget: ComplexityBudget,
    events: Vec<TrustAuditEvent>,
}

impl TrustComplexityGate {
    pub fn new(budget: ComplexityBudget, max_degraded_duration_seconds: u64) -> Self {
        Self {
            decisions: Vec::new(),
            replay_results: Vec::new(),
            degraded_state: DegradedModeState::new(max_degraded_duration_seconds),
            budget,
            events: Vec::new(),
        }
    }

    /// Record a trust decision and enforce complexity budget.
    pub fn record_decision(&mut self, decision: TrustDecision) -> Result<(), TrustOutcome> {
        let chain_depth = decision.context.chain_depth;
        let endpoint = decision.context.endpoint_group.clone();

        // Check complexity budget
        if self.budget.exceeds_budget(&endpoint, chain_depth) {
            self.emit_event(
                RTC_004_BUDGET_EXCEEDED,
                &decision.context.decision_id,
                &endpoint,
                TrustOutcome::Deny,
                chain_depth,
                format!(
                    "chain depth {} exceeds budget {} for endpoint group '{}'",
                    chain_depth,
                    self.budget.max_depth_for(&endpoint),
                    endpoint
                ),
            );
            return Err(TrustOutcome::Deny);
        }

        // Record degraded-mode event if applicable
        if decision.outcome == TrustOutcome::Degraded {
            self.emit_event(
                RTC_003_DEGRADED_MODE,
                &decision.context.decision_id,
                &endpoint,
                TrustOutcome::Degraded,
                chain_depth,
                format!("degraded-mode decision: {}", decision.reason),
            );
        }

        self.decisions.push(decision);
        Ok(())
    }

    /// Replay a decision and verify determinism.
    pub fn verify_replay(
        &mut self,
        context: &TrustDecisionContext,
        replay_fn: impl FnOnce(&TrustDecisionContext) -> TrustOutcome,
    ) -> ReplayResult {
        let original = self
            .decisions
            .iter()
            .find(|d| d.context.decision_id == context.decision_id)
            .map(|d| d.outcome);

        let replayed_outcome = replay_fn(context);
        let original_outcome = original.unwrap_or(replayed_outcome);
        let deterministic = original_outcome == replayed_outcome;

        let event_code = if deterministic {
            RTC_001_REPLAY_VERIFIED
        } else {
            RTC_002_REPLAY_DIVERGED
        };

        self.emit_event(
            event_code,
            &context.decision_id,
            &context.endpoint_group,
            replayed_outcome,
            context.chain_depth,
            if deterministic {
                "replay verified: deterministic".to_string()
            } else {
                format!(
                    "replay diverged: original={}, replayed={}",
                    original_outcome, replayed_outcome
                )
            },
        );

        let result = ReplayResult {
            decision_id: context.decision_id.clone(),
            original_outcome,
            replayed_outcome,
            deterministic,
        };

        self.replay_results.push(result.clone());
        result
    }

    /// Enter degraded mode.
    pub fn enter_degraded_mode(
        &mut self,
        reason: &str,
        cached_caps: Vec<String>,
        timestamp: &str,
    ) {
        self.degraded_state.activate(reason, cached_caps, timestamp);
    }

    /// Exit degraded mode.
    pub fn exit_degraded_mode(&mut self) {
        self.degraded_state.deactivate();
    }

    /// Check if degraded mode has expired.
    pub fn is_degraded_expired(&self) -> bool {
        self.degraded_state.is_expired()
    }

    /// Update degraded mode elapsed time.
    pub fn update_degraded_elapsed(&mut self, elapsed_seconds: u64) {
        self.degraded_state.elapsed_seconds = elapsed_seconds;
    }

    /// Check if a capability is available in degraded mode.
    pub fn is_degraded_capability_cached(&self, cap: &str) -> bool {
        self.degraded_state.is_capability_cached(cap)
    }

    /// Gate pass: all invariants satisfied.
    pub fn gate_pass(&self) -> bool {
        // INV-RTC-REPLAY: no replay divergences
        let no_divergence = !self.replay_results.iter().any(|r| !r.deterministic);

        // INV-RTC-DEGRADED: degraded mode not expired
        let degraded_ok = !self.degraded_state.is_expired();

        // INV-RTC-BUDGET: no budget exceeded events
        let no_budget_exceeded = !self
            .events
            .iter()
            .any(|e| e.code == RTC_004_BUDGET_EXCEEDED);

        // INV-RTC-AUDIT: at least some decisions recorded (non-empty)
        let has_audit = !self.decisions.is_empty() || !self.events.is_empty();

        no_divergence && degraded_ok && no_budget_exceeded && has_audit
    }

    pub fn summary(&self) -> TrustAuditSummary {
        let total = self.decisions.len() as u64;
        let grants = self
            .decisions
            .iter()
            .filter(|d| d.outcome == TrustOutcome::Grant)
            .count() as u64;
        let denials = self
            .decisions
            .iter()
            .filter(|d| d.outcome == TrustOutcome::Deny)
            .count() as u64;
        let escalations = self
            .decisions
            .iter()
            .filter(|d| d.outcome == TrustOutcome::Escalate)
            .count() as u64;
        let degraded = self
            .decisions
            .iter()
            .filter(|d| d.outcome == TrustOutcome::Degraded)
            .count() as u64;

        let replay_verified = self.replay_results.iter().filter(|r| r.deterministic).count() as u64;
        let replay_diverged = self
            .replay_results
            .iter()
            .filter(|r| !r.deterministic)
            .count() as u64;
        let budget_exceeded = self
            .events
            .iter()
            .filter(|e| e.code == RTC_004_BUDGET_EXCEEDED)
            .count() as u64;

        let total_depth: u64 = self
            .decisions
            .iter()
            .map(|d| u64::from(d.context.chain_depth))
            .sum();
        let avg_chain_depth = if total > 0 {
            total_depth as f64 / total as f64
        } else {
            0.0
        };

        let replay_total = replay_verified + replay_diverged;
        let replay_success_rate_pct = if replay_total > 0 {
            replay_verified as f64 / replay_total as f64 * 100.0
        } else {
            100.0
        };

        let degraded_activations = self
            .events
            .iter()
            .filter(|e| e.code == RTC_003_DEGRADED_MODE)
            .count() as u64;

        TrustAuditSummary {
            total_decisions: total,
            grants,
            denials,
            escalations,
            degraded,
            replay_verified,
            replay_diverged,
            budget_exceeded,
            avg_chain_depth,
            replay_success_rate_pct,
            degraded_mode_activations: degraded_activations,
        }
    }

    pub fn to_report(&self) -> serde_json::Value {
        let summary = self.summary();
        let verdict = if self.gate_pass() { "PASS" } else { "FAIL" };
        serde_json::json!({
            "bead_id": "bd-kiqr",
            "section": "12",
            "gate_verdict": verdict,
            "summary": summary,
            "invariants": {
                INV_RTC_REPLAY: !self.replay_results.iter().any(|r| !r.deterministic),
                INV_RTC_DEGRADED: !self.degraded_state.is_expired(),
                INV_RTC_BUDGET: !self.events.iter().any(|e| e.code == RTC_004_BUDGET_EXCEEDED),
                INV_RTC_AUDIT: !self.decisions.is_empty() || !self.events.is_empty(),
            },
        })
    }

    pub fn decisions(&self) -> &[TrustDecision] {
        &self.decisions
    }

    pub fn replay_results(&self) -> &[ReplayResult] {
        &self.replay_results
    }

    pub fn events(&self) -> &[TrustAuditEvent] {
        &self.events
    }

    pub fn take_events(&mut self) -> Vec<TrustAuditEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn degraded_state(&self) -> &DegradedModeState {
        &self.degraded_state
    }

    fn emit_event(
        &mut self,
        code: &str,
        decision_id: &str,
        endpoint_group: &str,
        outcome: TrustOutcome,
        chain_depth: u32,
        detail: String,
    ) {
        self.events.push(TrustAuditEvent {
            code: code.to_string(),
            decision_id: decision_id.to_string(),
            endpoint_group: endpoint_group.to_string(),
            outcome,
            chain_depth,
            detail,
        });
    }
}

impl Default for TrustComplexityGate {
    fn default() -> Self {
        Self::new(ComplexityBudget::default(), 300)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context(id: &str, depth: u32) -> TrustDecisionContext {
        TrustDecisionContext {
            decision_id: id.to_string(),
            endpoint_group: "default".to_string(),
            token: "tok-abc".to_string(),
            epoch: 1,
            capability_set: vec!["read".to_string(), "write".to_string()],
            clock_value: "2026-01-01T00:00:00Z".to_string(),
            chain_depth: depth,
        }
    }

    fn make_decision(id: &str, outcome: TrustOutcome, depth: u32) -> TrustDecision {
        TrustDecision {
            context: make_context(id, depth),
            outcome,
            reason: "test".to_string(),
            decided_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    // ── Event codes defined ───────────────────────────────────────────────

    #[test]
    fn event_code_rtc_001_defined() {
        assert_eq!(RTC_001_REPLAY_VERIFIED, "RTC-001");
    }

    #[test]
    fn event_code_rtc_002_defined() {
        assert_eq!(RTC_002_REPLAY_DIVERGED, "RTC-002");
    }

    #[test]
    fn event_code_rtc_003_defined() {
        assert_eq!(RTC_003_DEGRADED_MODE, "RTC-003");
    }

    #[test]
    fn event_code_rtc_004_defined() {
        assert_eq!(RTC_004_BUDGET_EXCEEDED, "RTC-004");
    }

    // ── Invariant constants ───────────────────────────────────────────────

    #[test]
    fn invariant_replay_defined() {
        assert_eq!(INV_RTC_REPLAY, "INV-RTC-REPLAY");
    }

    #[test]
    fn invariant_degraded_defined() {
        assert_eq!(INV_RTC_DEGRADED, "INV-RTC-DEGRADED");
    }

    #[test]
    fn invariant_budget_defined() {
        assert_eq!(INV_RTC_BUDGET, "INV-RTC-BUDGET");
    }

    #[test]
    fn invariant_audit_defined() {
        assert_eq!(INV_RTC_AUDIT, "INV-RTC-AUDIT");
    }

    // ── TrustOutcome ──────────────────────────────────────────────────────

    #[test]
    fn outcome_labels_correct() {
        assert_eq!(TrustOutcome::Grant.label(), "grant");
        assert_eq!(TrustOutcome::Deny.label(), "deny");
        assert_eq!(TrustOutcome::Escalate.label(), "escalate");
        assert_eq!(TrustOutcome::Degraded.label(), "degraded");
    }

    #[test]
    fn outcome_display_matches_label() {
        for outcome in [
            TrustOutcome::Grant,
            TrustOutcome::Deny,
            TrustOutcome::Escalate,
            TrustOutcome::Degraded,
        ] {
            assert_eq!(format!("{outcome}"), outcome.label());
        }
    }

    #[test]
    fn outcome_serde_roundtrip() {
        for outcome in [
            TrustOutcome::Grant,
            TrustOutcome::Deny,
            TrustOutcome::Escalate,
            TrustOutcome::Degraded,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let parsed: TrustOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, outcome);
        }
    }

    // ── Complexity budget ─────────────────────────────────────────────────

    #[test]
    fn budget_default_max_depth_is_5() {
        let budget = ComplexityBudget::default();
        assert_eq!(budget.default_max_depth, 5);
    }

    #[test]
    fn budget_returns_default_for_unknown_endpoint() {
        let budget = ComplexityBudget::new(7);
        assert_eq!(budget.max_depth_for("unknown"), 7);
    }

    #[test]
    fn budget_override_takes_precedence() {
        let mut budget = ComplexityBudget::new(5);
        budget.set_override("admin", 10);
        assert_eq!(budget.max_depth_for("admin"), 10);
        assert_eq!(budget.max_depth_for("default"), 5);
    }

    #[test]
    fn budget_exceeds_when_over() {
        let budget = ComplexityBudget::new(3);
        assert!(budget.exceeds_budget("default", 4));
        assert!(!budget.exceeds_budget("default", 3));
        assert!(!budget.exceeds_budget("default", 2));
    }

    // ── Degraded mode ─────────────────────────────────────────────────────

    #[test]
    fn degraded_mode_initially_inactive() {
        let state = DegradedModeState::new(300);
        assert!(!state.active);
        assert!(!state.is_expired());
    }

    #[test]
    fn degraded_mode_activate_sets_fields() {
        let mut state = DegradedModeState::new(300);
        state.activate("epoch service down", vec!["read".into()], "2026-01-01T00:00:00Z");
        assert!(state.active);
        assert_eq!(state.reason, "epoch service down");
        assert!(state.is_capability_cached("read"));
        assert!(!state.is_capability_cached("write"));
    }

    #[test]
    fn degraded_mode_deactivate_clears() {
        let mut state = DegradedModeState::new(300);
        state.activate("test", vec!["cap".into()], "ts");
        state.deactivate();
        assert!(!state.active);
        assert!(state.reason.is_empty());
    }

    #[test]
    fn degraded_mode_expires_after_max_duration() {
        let mut state = DegradedModeState::new(300);
        state.activate("test", vec![], "ts");
        state.elapsed_seconds = 301;
        assert!(state.is_expired());
    }

    #[test]
    fn degraded_mode_not_expired_within_duration() {
        let mut state = DegradedModeState::new(300);
        state.activate("test", vec![], "ts");
        state.elapsed_seconds = 299;
        assert!(!state.is_expired());
    }

    // ── Gate: record decision ─────────────────────────────────────────────

    #[test]
    fn record_decision_within_budget_succeeds() {
        let mut gate = TrustComplexityGate::default();
        let decision = make_decision("d1", TrustOutcome::Grant, 3);
        assert!(gate.record_decision(decision).is_ok());
        assert_eq!(gate.decisions().len(), 1);
    }

    #[test]
    fn record_decision_exceeding_budget_fails() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(3), 300);
        let decision = make_decision("d1", TrustOutcome::Grant, 4);
        assert!(gate.record_decision(decision).is_err());
        assert!(gate.decisions().is_empty());
    }

    #[test]
    fn record_decision_emits_budget_exceeded_event() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(2), 300);
        let decision = make_decision("d1", TrustOutcome::Grant, 3);
        let _ = gate.record_decision(decision);
        assert!(gate.events().iter().any(|e| e.code == RTC_004_BUDGET_EXCEEDED));
    }

    #[test]
    fn record_degraded_decision_emits_rtc_003() {
        let mut gate = TrustComplexityGate::default();
        let decision = make_decision("d1", TrustOutcome::Degraded, 1);
        gate.record_decision(decision).unwrap();
        assert!(gate.events().iter().any(|e| e.code == RTC_003_DEGRADED_MODE));
    }

    // ── Gate: replay verification ─────────────────────────────────────────

    #[test]
    fn replay_deterministic_emits_rtc_001() {
        let mut gate = TrustComplexityGate::default();
        let decision = make_decision("d1", TrustOutcome::Grant, 2);
        gate.record_decision(decision).unwrap();

        let ctx = make_context("d1", 2);
        let result = gate.verify_replay(&ctx, |_| TrustOutcome::Grant);
        assert!(result.deterministic);
        assert!(gate.events().iter().any(|e| e.code == RTC_001_REPLAY_VERIFIED));
    }

    #[test]
    fn replay_divergence_emits_rtc_002() {
        let mut gate = TrustComplexityGate::default();
        let decision = make_decision("d1", TrustOutcome::Grant, 2);
        gate.record_decision(decision).unwrap();

        let ctx = make_context("d1", 2);
        let result = gate.verify_replay(&ctx, |_| TrustOutcome::Deny);
        assert!(!result.deterministic);
        assert!(gate.events().iter().any(|e| e.code == RTC_002_REPLAY_DIVERGED));
    }

    // ── Gate: gate_pass ───────────────────────────────────────────────────

    #[test]
    fn gate_passes_with_clean_state() {
        let mut gate = TrustComplexityGate::default();
        let decision = make_decision("d1", TrustOutcome::Grant, 2);
        gate.record_decision(decision).unwrap();

        let ctx = make_context("d1", 2);
        gate.verify_replay(&ctx, |_| TrustOutcome::Grant);
        assert!(gate.gate_pass());
    }

    #[test]
    fn gate_fails_on_replay_divergence() {
        let mut gate = TrustComplexityGate::default();
        let decision = make_decision("d1", TrustOutcome::Grant, 2);
        gate.record_decision(decision).unwrap();

        let ctx = make_context("d1", 2);
        gate.verify_replay(&ctx, |_| TrustOutcome::Deny);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn gate_fails_on_budget_exceeded() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(2), 300);
        let decision = make_decision("d1", TrustOutcome::Grant, 3);
        let _ = gate.record_decision(decision);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn gate_fails_on_degraded_expired() {
        let mut gate = TrustComplexityGate::default();
        let decision = make_decision("d1", TrustOutcome::Grant, 1);
        gate.record_decision(decision).unwrap();
        gate.enter_degraded_mode("test", vec![], "ts");
        gate.update_degraded_elapsed(301);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn gate_fails_when_empty() {
        let gate = TrustComplexityGate::default();
        assert!(!gate.gate_pass());
    }

    // ── Summary ───────────────────────────────────────────────────────────

    #[test]
    fn summary_counts_outcomes_correctly() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 1)).unwrap();
        gate.record_decision(make_decision("d2", TrustOutcome::Deny, 1)).unwrap();
        gate.record_decision(make_decision("d3", TrustOutcome::Escalate, 1)).unwrap();
        gate.record_decision(make_decision("d4", TrustOutcome::Degraded, 1)).unwrap();

        let s = gate.summary();
        assert_eq!(s.total_decisions, 4);
        assert_eq!(s.grants, 1);
        assert_eq!(s.denials, 1);
        assert_eq!(s.escalations, 1);
        assert_eq!(s.degraded, 1);
    }

    #[test]
    fn summary_avg_chain_depth_correct() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 2)).unwrap();
        gate.record_decision(make_decision("d2", TrustOutcome::Grant, 4)).unwrap();
        let s = gate.summary();
        assert!((s.avg_chain_depth - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn summary_replay_rate_100_when_all_deterministic() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 1)).unwrap();
        let ctx = make_context("d1", 1);
        gate.verify_replay(&ctx, |_| TrustOutcome::Grant);
        let s = gate.summary();
        assert!((s.replay_success_rate_pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn summary_replay_rate_0_when_all_diverged() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 1)).unwrap();
        let ctx = make_context("d1", 1);
        gate.verify_replay(&ctx, |_| TrustOutcome::Deny);
        let s = gate.summary();
        assert!(s.replay_success_rate_pct < 1.0);
    }

    // ── Report ────────────────────────────────────────────────────────────

    #[test]
    fn report_has_bead_id() {
        let gate = TrustComplexityGate::default();
        let report = gate.to_report();
        assert_eq!(report["bead_id"], "bd-kiqr");
    }

    #[test]
    fn report_has_invariants() {
        let gate = TrustComplexityGate::default();
        let report = gate.to_report();
        assert!(report.get("invariants").is_some());
    }

    #[test]
    fn report_verdict_pass_when_clean() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 1)).unwrap();
        let ctx = make_context("d1", 1);
        gate.verify_replay(&ctx, |_| TrustOutcome::Grant);
        let report = gate.to_report();
        assert_eq!(report["gate_verdict"], "PASS");
    }

    #[test]
    fn report_verdict_fail_when_divergence() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 1)).unwrap();
        let ctx = make_context("d1", 1);
        gate.verify_replay(&ctx, |_| TrustOutcome::Deny);
        let report = gate.to_report();
        assert_eq!(report["gate_verdict"], "FAIL");
    }

    // ── take_events ───────────────────────────────────────────────────────

    #[test]
    fn take_events_drains() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Degraded, 1)).unwrap();
        let events = gate.take_events();
        assert!(!events.is_empty());
        assert!(gate.events().is_empty());
    }

    // ── Serde roundtrips ──────────────────────────────────────────────────

    #[test]
    fn trust_decision_context_serde_roundtrip() {
        let ctx = make_context("serde-test", 3);
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: TrustDecisionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ctx);
    }

    #[test]
    fn trust_decision_serde_roundtrip() {
        let decision = make_decision("serde-d", TrustOutcome::Grant, 2);
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: TrustDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, decision);
    }

    #[test]
    fn replay_result_serde_roundtrip() {
        let result = ReplayResult {
            decision_id: "r1".into(),
            original_outcome: TrustOutcome::Grant,
            replayed_outcome: TrustOutcome::Grant,
            deterministic: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ReplayResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, result);
    }

    #[test]
    fn degraded_state_serde_roundtrip() {
        let state = DegradedModeState::new(300);
        let json = serde_json::to_string(&state).unwrap();
        let parsed: DegradedModeState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, state);
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let event = TrustAuditEvent {
            code: "RTC-001".into(),
            decision_id: "d1".into(),
            endpoint_group: "default".into(),
            outcome: TrustOutcome::Grant,
            chain_depth: 2,
            detail: "verified".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: TrustAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }

    // ── Determinism ───────────────────────────────────────────────────────

    #[test]
    fn determinism_same_input_same_report() {
        let build = || {
            let mut gate = TrustComplexityGate::default();
            gate.record_decision(make_decision("det", TrustOutcome::Grant, 2)).unwrap();
            let ctx = make_context("det", 2);
            gate.verify_replay(&ctx, |_| TrustOutcome::Grant);
            gate
        };

        let a = serde_json::to_string(&build().to_report()).unwrap();
        let b = serde_json::to_string(&build().to_report()).unwrap();
        assert_eq!(a, b, "report must be deterministic");
    }
}
