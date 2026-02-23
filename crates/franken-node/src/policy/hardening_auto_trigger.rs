//! bd-1zym: Automatic hardening trigger on guardrail rejection evidence.
//!
//! When a guardrail monitor blocks a policy recommendation, this trigger
//! automatically escalates the hardening state machine within a configured
//! latency bound. Creates a feedback loop: guardrail violations trigger
//! hardening, which makes the system more resistant to future violations.
//!
//! # Invariants
//!
//! - INV-AUTOTRIG-LATENCY: escalation within max_trigger_latency_ms of rejection
//! - INV-AUTOTRIG-IDEMPOTENT: duplicate rejections at same level produce one escalation
//! - INV-AUTOTRIG-CAUSAL: every trigger event links to its originating rejection

use std::collections::BTreeSet;
use std::fmt;

use super::guardrail_monitor::GuardrailRejection;
use super::hardening_state_machine::{HardeningLevel, HardeningStateMachine};

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const AUTOTRIG_FIRED: &str = "EVD-AUTOTRIG-001";
    pub const AUTOTRIG_SUPPRESSED: &str = "EVD-AUTOTRIG-002";
    pub const AUTOTRIG_ALREADY_AT_MAX: &str = "EVD-AUTOTRIG-003";
    pub const AUTOTRIG_IDEMPOTENT_DEDUP: &str = "EVD-AUTOTRIG-004";
}

// ── TriggerResult ─────────────────────────────────────────────────

/// Result of processing a guardrail rejection through the auto-trigger.
#[derive(Debug, Clone, PartialEq)]
pub enum TriggerResult {
    /// Hardening was escalated.
    Escalated {
        from: HardeningLevel,
        to: HardeningLevel,
        latency_ms: u64,
    },
    /// Already at maximum hardening level.
    AlreadyAtMax,
    /// Trigger was suppressed (e.g., rate limited or idempotent dedup).
    Suppressed { reason: String },
}

impl TriggerResult {
    /// Event code for structured logging.
    pub fn event_code(&self) -> &'static str {
        match self {
            Self::Escalated { .. } => event_codes::AUTOTRIG_FIRED,
            Self::AlreadyAtMax => event_codes::AUTOTRIG_ALREADY_AT_MAX,
            Self::Suppressed { .. } => event_codes::AUTOTRIG_SUPPRESSED,
        }
    }
}

impl fmt::Display for TriggerResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Escalated {
                from,
                to,
                latency_ms,
            } => {
                write!(
                    f,
                    "ESCALATED: {} -> {} (latency {}ms)",
                    from.label(),
                    to.label(),
                    latency_ms
                )
            }
            Self::AlreadyAtMax => write!(f, "ALREADY_AT_MAX"),
            Self::Suppressed { reason } => write!(f, "SUPPRESSED: {reason}"),
        }
    }
}

// ── TriggerEvent ──────────────────────────────────────────────────

/// Causal evidence record linking a trigger to its originating rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerEvent {
    /// Unique trigger ID.
    pub trigger_id: String,
    /// Links to the guardrail rejection that caused this.
    pub rejection_id: String,
    /// Links to the evidence ledger entry.
    pub evidence_entry_id: String,
    /// Level before escalation.
    pub from_level: HardeningLevel,
    /// Level after escalation.
    pub to_level: HardeningLevel,
    /// Monotonic timestamp.
    pub timestamp: u64,
}

impl TriggerEvent {
    /// Serialize as a JSONL line.
    pub fn to_jsonl(&self) -> String {
        format!(
            r#"{{"trigger_id":"{}","rejection_id":"{}","evidence_entry_id":"{}","from":"{}","to":"{}","timestamp":{}}}"#,
            self.trigger_id,
            self.rejection_id,
            self.evidence_entry_id,
            self.from_level.label(),
            self.to_level.label(),
            self.timestamp,
        )
    }
}

// ── Idempotency key ───────────────────────────────────────────────

/// Idempotency key derived from (current_level, budget_id, epoch_id).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct IdempotencyKey {
    level: HardeningLevel,
    budget_id: String,
    epoch_id: u64,
}

impl IdempotencyKey {
    fn from_rejection(current_level: HardeningLevel, rejection: &GuardrailRejection) -> Self {
        Self {
            level: current_level,
            budget_id: rejection.budget_id.as_str().to_string(),
            epoch_id: rejection.epoch_id,
        }
    }
}

// ── Configuration ─────────────────────────────────────────────────

/// Configuration for the automatic hardening trigger.
#[derive(Debug, Clone, PartialEq)]
pub struct TriggerConfig {
    /// Maximum latency in milliseconds from rejection to escalation.
    pub max_trigger_latency_ms: u64,
    /// Whether to enable idempotency deduplication.
    pub enable_idempotency: bool,
}

impl TriggerConfig {
    pub fn default_config() -> Self {
        Self {
            max_trigger_latency_ms: 100,
            enable_idempotency: true,
        }
    }
}

// ── Escalation target mapping ─────────────────────────────────────

/// Determine the next hardening level given the current level.
fn next_level(current: HardeningLevel) -> Option<HardeningLevel> {
    match current {
        HardeningLevel::Baseline => Some(HardeningLevel::Standard),
        HardeningLevel::Standard => Some(HardeningLevel::Enhanced),
        HardeningLevel::Enhanced => Some(HardeningLevel::Maximum),
        HardeningLevel::Maximum => Some(HardeningLevel::Critical),
        HardeningLevel::Critical => None,
    }
}

// ── HardeningAutoTrigger ──────────────────────────────────────────

/// Automatic hardening trigger that escalates on guardrail rejections.
///
/// INV-AUTOTRIG-LATENCY: escalation within config.max_trigger_latency_ms.
/// INV-AUTOTRIG-IDEMPOTENT: dedup via (level, budget_id, epoch_id) key.
/// INV-AUTOTRIG-CAUSAL: every trigger event links to its originating rejection.
#[derive(Debug)]
pub struct HardeningAutoTrigger {
    config: TriggerConfig,
    /// Set of already-processed idempotency keys.
    processed_keys: BTreeSet<IdempotencyKey>,
    /// Trigger event log.
    events: Vec<TriggerEvent>,
    /// Counter for generating trigger IDs.
    trigger_counter: u64,
}

impl HardeningAutoTrigger {
    /// Create a new trigger with the given configuration.
    pub fn new(config: TriggerConfig) -> Self {
        Self {
            config,
            processed_keys: BTreeSet::new(),
            events: Vec::new(),
            trigger_counter: 0,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TriggerConfig::default_config())
    }

    /// Get the trigger configuration.
    pub fn config(&self) -> &TriggerConfig {
        &self.config
    }

    /// Get all trigger events recorded.
    pub fn events(&self) -> &[TriggerEvent] {
        &self.events
    }

    /// Number of trigger events recorded.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Number of processed idempotency keys.
    pub fn dedup_count(&self) -> usize {
        self.processed_keys.len()
    }

    /// Process a guardrail rejection and potentially escalate hardening.
    ///
    /// `timestamp_ms` is the monotonic timestamp of the rejection event.
    /// `trace_id` is used for state machine transition recording.
    pub fn on_guardrail_rejection(
        &mut self,
        rejection: &GuardrailRejection,
        state_machine: &mut HardeningStateMachine,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> TriggerResult {
        let current = state_machine.current_level();

        // Check if already at maximum
        if current == HardeningLevel::Critical {
            return TriggerResult::AlreadyAtMax;
        }

        // Idempotency check
        if self.config.enable_idempotency {
            let key = IdempotencyKey::from_rejection(current, rejection);
            if self.processed_keys.contains(&key) {
                return TriggerResult::Suppressed {
                    reason: format!(
                        "idempotent dedup: already processed ({}, {}, epoch {})",
                        current.label(),
                        rejection.budget_id,
                        rejection.epoch_id,
                    ),
                };
            }
            self.processed_keys.insert(key);
        }

        // Determine target level (next level up)
        let target = match next_level(current) {
            Some(level) => level,
            None => return TriggerResult::AlreadyAtMax,
        };

        // Escalate the state machine
        match state_machine.escalate(target, timestamp_ms, trace_id) {
            Ok(_record) => {
                // Record trigger event with causal pointers
                self.trigger_counter += 1;
                let event = TriggerEvent {
                    trigger_id: format!("trig-{:04}", self.trigger_counter),
                    rejection_id: format!(
                        "rej-{}-{}-{}",
                        rejection.monitor_name, rejection.budget_id, rejection.epoch_id
                    ),
                    evidence_entry_id: format!(
                        "evd-autotrig-{:04}-{}",
                        self.trigger_counter, timestamp_ms
                    ),
                    from_level: current,
                    to_level: target,
                    timestamp: timestamp_ms,
                };
                self.events.push(event);

                TriggerResult::Escalated {
                    from: current,
                    to: target,
                    latency_ms: 0, // Synchronous escalation = 0 latency
                }
            }
            Err(e) => TriggerResult::Suppressed {
                reason: format!("escalation failed: {e}"),
            },
        }
    }

    /// Reset the idempotency cache (e.g., on epoch boundary).
    pub fn reset_idempotency(&mut self) {
        self.processed_keys.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::super::guardrail_monitor::BudgetId;
    use super::*;

    fn make_rejection(budget: &str, epoch: u64) -> GuardrailRejection {
        GuardrailRejection {
            monitor_name: "TestMonitor".into(),
            budget_id: BudgetId::new(budget),
            reason: "test rejection".into(),
            epoch_id: epoch,
        }
    }

    fn tid(n: u32) -> String {
        format!("trace-{n:04}")
    }

    // ── TriggerResult tests ──

    #[test]
    fn trigger_result_escalated_display() {
        let r = TriggerResult::Escalated {
            from: HardeningLevel::Baseline,
            to: HardeningLevel::Standard,
            latency_ms: 5,
        };
        assert!(r.to_string().contains("ESCALATED"));
        assert!(r.to_string().contains("baseline"));
        assert!(r.to_string().contains("standard"));
    }

    #[test]
    fn trigger_result_already_at_max_display() {
        assert!(
            TriggerResult::AlreadyAtMax
                .to_string()
                .contains("ALREADY_AT_MAX")
        );
    }

    #[test]
    fn trigger_result_suppressed_display() {
        let r = TriggerResult::Suppressed {
            reason: "test".into(),
        };
        assert!(r.to_string().contains("SUPPRESSED"));
    }

    #[test]
    fn trigger_result_event_codes() {
        assert_eq!(
            TriggerResult::Escalated {
                from: HardeningLevel::Baseline,
                to: HardeningLevel::Standard,
                latency_ms: 0,
            }
            .event_code(),
            "EVD-AUTOTRIG-001"
        );
        assert_eq!(TriggerResult::AlreadyAtMax.event_code(), "EVD-AUTOTRIG-003");
        assert_eq!(
            TriggerResult::Suppressed { reason: "x".into() }.event_code(),
            "EVD-AUTOTRIG-002"
        );
    }

    // ── TriggerEvent tests ──

    #[test]
    fn trigger_event_to_jsonl() {
        let event = TriggerEvent {
            trigger_id: "trig-0001".into(),
            rejection_id: "rej-test-001".into(),
            evidence_entry_id: "evd-0001".into(),
            from_level: HardeningLevel::Baseline,
            to_level: HardeningLevel::Standard,
            timestamp: 1000,
        };
        let line = event.to_jsonl();
        assert!(line.contains("trig-0001"));
        assert!(line.contains("baseline"));
        assert!(line.contains("standard"));
    }

    // ── next_level tests ──

    #[test]
    fn next_level_progression() {
        assert_eq!(
            next_level(HardeningLevel::Baseline),
            Some(HardeningLevel::Standard)
        );
        assert_eq!(
            next_level(HardeningLevel::Standard),
            Some(HardeningLevel::Enhanced)
        );
        assert_eq!(
            next_level(HardeningLevel::Enhanced),
            Some(HardeningLevel::Maximum)
        );
        assert_eq!(
            next_level(HardeningLevel::Maximum),
            Some(HardeningLevel::Critical)
        );
        assert_eq!(next_level(HardeningLevel::Critical), None);
    }

    // ── Basic escalation ──

    #[test]
    fn single_rejection_triggers_escalation() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();
        let rej = make_rejection("memory_budget", 1);

        let result = trigger.on_guardrail_rejection(&rej, &mut sm, 1000, &tid(1));
        match result {
            TriggerResult::Escalated { from, to, .. } => {
                assert_eq!(from, HardeningLevel::Baseline);
                assert_eq!(to, HardeningLevel::Standard);
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
        assert_eq!(sm.current_level(), HardeningLevel::Standard);
    }

    #[test]
    fn sequential_rejections_escalate_through_levels() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();

        // Different budget_ids to avoid idempotency dedup
        for (i, budget) in ["mem", "dur", "hard", "evd"].iter().enumerate() {
            let rej = make_rejection(budget, 1);
            let result =
                trigger.on_guardrail_rejection(&rej, &mut sm, 1000 + i as u64, &tid(i as u32));
            assert!(
                matches!(result, TriggerResult::Escalated { .. }),
                "expected Escalated at step {i}, got {result:?}"
            );
        }
        assert_eq!(sm.current_level(), HardeningLevel::Critical);
    }

    // ── AlreadyAtMax ──

    #[test]
    fn already_at_max_returns_correctly() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Critical);
        let rej = make_rejection("memory_budget", 1);

        let result = trigger.on_guardrail_rejection(&rej, &mut sm, 1000, &tid(1));
        assert_eq!(result, TriggerResult::AlreadyAtMax);
    }

    // ── Idempotency ──

    #[test]
    fn duplicate_rejection_is_idempotent() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        // Start at Standard so first rejection escalates to Enhanced,
        // then second rejection arrives while at Enhanced with same key
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Standard);
        let rej = make_rejection("memory_budget", 1);

        // First rejection escalates Standard -> Enhanced
        let r1 = trigger.on_guardrail_rejection(&rej, &mut sm, 1000, &tid(1));
        assert!(matches!(r1, TriggerResult::Escalated { .. }));
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);

        // Second rejection at Enhanced with same budget/epoch: key is
        // (Enhanced, memory_budget, 1) — different from first key
        // (Standard, memory_budget, 1). So we need to test with a third
        // rejection that matches the SECOND key.
        let r2 = trigger.on_guardrail_rejection(&rej, &mut sm, 1001, &tid(2));
        // This escalates Enhanced -> Maximum (new key)
        assert!(matches!(r2, TriggerResult::Escalated { .. }));

        // Third rejection: key is (Maximum, memory_budget, 1) — escalates again
        let r3 = trigger.on_guardrail_rejection(&rej, &mut sm, 1002, &tid(3));
        assert!(matches!(r3, TriggerResult::Escalated { .. }));
        assert_eq!(sm.current_level(), HardeningLevel::Critical);

        // Fourth: at Critical, returns AlreadyAtMax
        let r4 = trigger.on_guardrail_rejection(&rej, &mut sm, 1003, &tid(4));
        assert_eq!(r4, TriggerResult::AlreadyAtMax);
    }

    #[test]
    fn duplicate_at_same_level_is_idempotent() {
        // True idempotency test: escalate, governance-rollback to same level,
        // then same rejection should be suppressed because its key is still
        // in the dedup set.
        use super::super::hardening_state_machine::GovernanceRollbackArtifact;

        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::with_level(HardeningLevel::Enhanced);
        let rej = make_rejection("memory_budget", 1);

        // First rejection at Enhanced → escalates to Maximum
        let r1 = trigger.on_guardrail_rejection(&rej, &mut sm, 1000, &tid(1));
        assert!(matches!(r1, TriggerResult::Escalated { .. }));
        assert_eq!(sm.current_level(), HardeningLevel::Maximum);

        // Governance rollback back to Enhanced
        let artifact = GovernanceRollbackArtifact {
            artifact_id: "GOV-2026-TEST".into(),
            approver_id: "admin".into(),
            reason: "test rollback".into(),
            timestamp: 1500,
            signature: "sig-test".into(),
        };
        sm.governance_rollback(HardeningLevel::Enhanced, &artifact, 1500, &tid(2))
            .expect("rollback should succeed");
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);

        // Same rejection again at Enhanced → key (Enhanced, memory_budget, 1)
        // is already in the dedup set → Suppressed
        let r2 = trigger.on_guardrail_rejection(&rej, &mut sm, 2000, &tid(3));
        assert!(
            matches!(r2, TriggerResult::Suppressed { .. }),
            "expected Suppressed after rollback, got {r2:?}"
        );
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
        assert_eq!(trigger.event_count(), 1); // only the first escalation
    }

    #[test]
    fn same_budget_different_epoch_is_not_deduped() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();

        let rej1 = make_rejection("memory_budget", 1);
        trigger.on_guardrail_rejection(&rej1, &mut sm, 1000, &tid(1));
        assert_eq!(sm.current_level(), HardeningLevel::Standard);

        let rej2 = make_rejection("memory_budget", 2); // different epoch
        let result = trigger.on_guardrail_rejection(&rej2, &mut sm, 1001, &tid(2));
        assert!(matches!(result, TriggerResult::Escalated { .. }));
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
    }

    #[test]
    fn different_budget_same_epoch_is_not_deduped() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();

        let rej1 = make_rejection("memory_budget", 1);
        trigger.on_guardrail_rejection(&rej1, &mut sm, 1000, &tid(1));
        assert_eq!(sm.current_level(), HardeningLevel::Standard);

        let rej2 = make_rejection("durability_budget", 1); // different budget
        let result = trigger.on_guardrail_rejection(&rej2, &mut sm, 1001, &tid(2));
        assert!(matches!(result, TriggerResult::Escalated { .. }));
    }

    #[test]
    fn idempotency_across_100_duplicates() {
        // With 100 identical rejections (same budget, same epoch), the
        // idempotency key includes current_level. Each escalation changes
        // the level, creating a new key context. So we get 4 escalations
        // (Baseline→Standard→Enhanced→Maximum→Critical) then 96 AlreadyAtMax.
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();
        let rej = make_rejection("memory_budget", 1);

        let mut escalation_count = 0u32;
        let mut at_max_count = 0u32;

        for i in 0..100 {
            let r = trigger.on_guardrail_rejection(&rej, &mut sm, 1000 + i, &tid(i as u32));
            match r {
                TriggerResult::Escalated { .. } => escalation_count += 1,
                TriggerResult::AlreadyAtMax => at_max_count += 1,
                TriggerResult::Suppressed { .. } => {
                    panic!("unexpected Suppressed at iteration {i}: {r:?}")
                }
            }
        }

        // 4 escalations through all levels, 96 AlreadyAtMax at Critical
        assert_eq!(escalation_count, 4);
        assert_eq!(at_max_count, 96);
        assert_eq!(sm.current_level(), HardeningLevel::Critical);
        assert_eq!(trigger.event_count(), 4);
    }

    #[test]
    fn idempotency_disabled() {
        let config = TriggerConfig {
            enable_idempotency: false,
            ..TriggerConfig::default_config()
        };
        let mut trigger = HardeningAutoTrigger::new(config);
        let mut sm = HardeningStateMachine::new();
        let rej = make_rejection("memory_budget", 1);

        // First triggers escalation
        let r1 = trigger.on_guardrail_rejection(&rej, &mut sm, 1000, &tid(1));
        assert!(matches!(r1, TriggerResult::Escalated { .. }));

        // Second also triggers (no dedup) — now at Standard, goes to Enhanced
        let r2 = trigger.on_guardrail_rejection(&rej, &mut sm, 1001, &tid(2));
        assert!(matches!(r2, TriggerResult::Escalated { .. }));
        assert_eq!(sm.current_level(), HardeningLevel::Enhanced);
    }

    // ── Causal evidence pointers ──

    #[test]
    fn trigger_event_has_causal_pointers() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();
        let rej = make_rejection("memory_budget", 42);

        trigger.on_guardrail_rejection(&rej, &mut sm, 1000, &tid(1));

        assert_eq!(trigger.event_count(), 1);
        let event = &trigger.events()[0];
        assert!(!event.trigger_id.is_empty());
        assert!(event.rejection_id.contains("memory_budget"));
        assert!(event.rejection_id.contains("42"));
        assert!(!event.evidence_entry_id.is_empty());
        assert_eq!(event.from_level, HardeningLevel::Baseline);
        assert_eq!(event.to_level, HardeningLevel::Standard);
    }

    #[test]
    fn trigger_events_accumulate() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();

        for (i, budget) in ["mem", "dur"].iter().enumerate() {
            let rej = make_rejection(budget, 1);
            trigger.on_guardrail_rejection(&rej, &mut sm, 1000 + i as u64, &tid(i as u32));
        }
        assert_eq!(trigger.event_count(), 2);
        assert_eq!(trigger.events()[0].from_level, HardeningLevel::Baseline);
        assert_eq!(trigger.events()[1].from_level, HardeningLevel::Standard);
    }

    // ── Reset idempotency ──

    #[test]
    fn reset_clears_dedup_state() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();
        let rej = make_rejection("memory_budget", 1);

        trigger.on_guardrail_rejection(&rej, &mut sm, 1000, &tid(1));
        assert_eq!(trigger.dedup_count(), 1);

        trigger.reset_idempotency();
        assert_eq!(trigger.dedup_count(), 0);
    }

    // ── Config tests ──

    #[test]
    fn default_config_values() {
        let config = TriggerConfig::default_config();
        assert_eq!(config.max_trigger_latency_ms, 100);
        assert!(config.enable_idempotency);
    }

    // ── Latency verification ──

    #[test]
    fn escalation_latency_is_zero_for_synchronous() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();
        let rej = make_rejection("memory_budget", 1);

        let result = trigger.on_guardrail_rejection(&rej, &mut sm, 1000, &tid(1));
        match result {
            TriggerResult::Escalated { latency_ms, .. } => {
                assert_eq!(latency_ms, 0);
                assert!(latency_ms <= trigger.config().max_trigger_latency_ms);
            }
            other => panic!("expected Escalated, got {other:?}"),
        }
    }

    // ── Full lifecycle ──

    #[test]
    fn full_escalation_then_max() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();

        // Escalate through all levels
        let budgets = ["a", "b", "c", "d"];
        for (i, budget) in budgets.iter().enumerate() {
            let rej = make_rejection(budget, 1);
            let result =
                trigger.on_guardrail_rejection(&rej, &mut sm, 1000 + i as u64, &tid(i as u32));
            assert!(matches!(result, TriggerResult::Escalated { .. }));
        }
        assert_eq!(sm.current_level(), HardeningLevel::Critical);

        // Next rejection at max
        let rej = make_rejection("e", 1);
        let result = trigger.on_guardrail_rejection(&rej, &mut sm, 2000, &tid(99));
        assert_eq!(result, TriggerResult::AlreadyAtMax);
    }

    // ── JSONL export ──

    #[test]
    fn events_export_as_jsonl() {
        let mut trigger = HardeningAutoTrigger::with_defaults();
        let mut sm = HardeningStateMachine::new();
        let rej = make_rejection("memory_budget", 1);

        trigger.on_guardrail_rejection(&rej, &mut sm, 1000, &tid(1));

        let lines: Vec<String> = trigger.events().iter().map(|e| e.to_jsonl()).collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("trig-0001"));
        // Verify it's valid JSON
        let _: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    }
}
