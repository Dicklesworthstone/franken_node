//! bd-3a3q: Anytime-valid guardrail monitor set for security/durability-critical budgets.
//!
//! Guardrail monitors provide always-on, anytime-valid bounds that prevent the
//! system from taking dangerous actions regardless of what the Bayesian engine
//! recommends. "Anytime-valid" means monitors produce valid conclusions at any
//! stopping point (not just at pre-planned sample sizes).
//!
//! # Invariants
//!
//! - INV-GUARD-ANYTIME: every monitor is valid at any stopping point
//! - INV-GUARD-PRECEDENCE: guardrail verdicts override Bayesian recommendations
//! - INV-GUARD-RESTRICTIVE: the set returns the most restrictive verdict
//! - INV-GUARD-CONFIGURABLE: thresholds are configurable above envelope minimums

use std::fmt;

use super::correctness_envelope::CorrectnessEnvelope;
use super::hardening_state_machine::HardeningLevel;

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const GUARD_PASS: &str = "EVD-GUARD-001";
    pub const GUARD_BLOCK: &str = "EVD-GUARD-002";
    pub const GUARD_WARN: &str = "EVD-GUARD-003";
    pub const GUARD_THRESHOLD_RECONFIGURED: &str = "EVD-GUARD-004";
}

// ── Budget identification ─────────────────────────────────────────

/// Identifies a specific budget that a guardrail protects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BudgetId(pub String);

impl BudgetId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BudgetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Verdict ───────────────────────────────────────────────────────

/// Result of a guardrail monitor check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardrailVerdict {
    /// Action is within budget — proceed.
    Allow,
    /// Action exceeds budget — block immediately.
    Block { reason: String, budget_id: BudgetId },
    /// Action is approaching budget — warn but allow.
    Warn { reason: String },
}

impl GuardrailVerdict {
    /// Event code for structured logging.
    pub fn event_code(&self) -> &'static str {
        match self {
            Self::Allow => event_codes::GUARD_PASS,
            Self::Block { .. } => event_codes::GUARD_BLOCK,
            Self::Warn { .. } => event_codes::GUARD_WARN,
        }
    }

    /// Severity rank for comparing restrictiveness (higher = more restrictive).
    pub fn severity(&self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Warn { .. } => 1,
            Self::Block { .. } => 2,
        }
    }

    /// True if this verdict blocks the action.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block { .. })
    }
}

impl fmt::Display for GuardrailVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Block { reason, budget_id } => {
                write!(f, "BLOCK [{}]: {}", budget_id, reason)
            }
            Self::Warn { reason } => write!(f, "WARN: {reason}"),
        }
    }
}

// ── System state for monitors ─────────────────────────────────────

/// Snapshot of relevant system state that monitors inspect.
#[derive(Debug, Clone)]
pub struct SystemState {
    /// Current memory usage in bytes.
    pub memory_used_bytes: u64,
    /// Memory budget limit in bytes.
    pub memory_budget_bytes: u64,
    /// Current durability level (0.0 to 1.0).
    pub durability_level: f64,
    /// Current hardening level.
    pub hardening_level: HardeningLevel,
    /// Proposed hardening level (for regression detection).
    pub proposed_hardening_level: Option<HardeningLevel>,
    /// Whether evidence emission is active.
    pub evidence_emission_active: bool,
    /// Current epoch ID.
    pub epoch_id: u64,
}

impl SystemState {
    /// Memory utilization as a fraction (0.0 to 1.0).
    pub fn memory_utilization(&self) -> f64 {
        if self.memory_budget_bytes == 0 {
            return 1.0; // No budget = fully consumed
        }
        self.memory_used_bytes as f64 / self.memory_budget_bytes as f64
    }
}

// ── GuardrailMonitor trait ────────────────────────────────────────

/// A guardrail monitor that checks system state against a budget.
///
/// INV-GUARD-ANYTIME: every implementation must be valid at any stopping point.
pub trait GuardrailMonitor: fmt::Debug {
    /// Check the current system state against this monitor's budget.
    fn check(&self, state: &SystemState) -> GuardrailVerdict;

    /// Returns true — required for all monitors. The anytime-valid property
    /// means conclusions are valid at any prefix of the observation sequence.
    fn is_valid_at_any_stopping_point(&self) -> bool {
        true
    }

    /// Human-readable name for this monitor.
    fn name(&self) -> &str;

    /// The budget this monitor protects.
    fn budget_id(&self) -> &BudgetId;
}

// ── Concrete monitors ─────────────────────────────────────────────

/// Blocks actions that would exceed the memory budget.
#[derive(Debug, Clone)]
pub struct MemoryBudgetGuardrail {
    budget_id: BudgetId,
    /// Threshold (0.0-1.0): block when utilization exceeds this.
    block_threshold: f64,
    /// Warn threshold (0.0-1.0): warn when utilization exceeds this.
    warn_threshold: f64,
    /// Minimum block threshold enforced by correctness envelope.
    min_block_threshold: f64,
}

impl MemoryBudgetGuardrail {
    /// Correctness envelope minimum: memory block threshold cannot be below 0.5.
    const ENVELOPE_MIN_BLOCK_THRESHOLD: f64 = 0.5;

    pub fn new(block_threshold: f64, warn_threshold: f64) -> Self {
        let effective_block = block_threshold.max(Self::ENVELOPE_MIN_BLOCK_THRESHOLD);
        let effective_warn = warn_threshold.min(effective_block);
        Self {
            budget_id: BudgetId::new("memory_budget"),
            block_threshold: effective_block,
            warn_threshold: effective_warn,
            min_block_threshold: Self::ENVELOPE_MIN_BLOCK_THRESHOLD,
        }
    }

    pub fn default_guardrail() -> Self {
        Self::new(0.95, 0.80)
    }
}

impl GuardrailMonitor for MemoryBudgetGuardrail {
    fn check(&self, state: &SystemState) -> GuardrailVerdict {
        let util = state.memory_utilization();
        if util >= self.block_threshold {
            GuardrailVerdict::Block {
                reason: format!(
                    "memory utilization {:.1}% exceeds block threshold {:.1}%",
                    util * 100.0,
                    self.block_threshold * 100.0,
                ),
                budget_id: self.budget_id.clone(),
            }
        } else if util >= self.warn_threshold {
            GuardrailVerdict::Warn {
                reason: format!(
                    "memory utilization {:.1}% exceeds warn threshold {:.1}%",
                    util * 100.0,
                    self.warn_threshold * 100.0,
                ),
            }
        } else {
            GuardrailVerdict::Allow
        }
    }

    fn name(&self) -> &str {
        "MemoryBudgetGuardrail"
    }

    fn budget_id(&self) -> &BudgetId {
        &self.budget_id
    }
}

/// Blocks actions that would reduce durability below threshold.
#[derive(Debug, Clone)]
pub struct DurabilityLossGuardrail {
    budget_id: BudgetId,
    /// Minimum required durability level (0.0-1.0).
    min_durability: f64,
    /// Warn when durability is within this margin of min.
    warn_margin: f64,
    /// Correctness envelope minimum durability.
    min_allowed_durability: f64,
}

impl DurabilityLossGuardrail {
    /// Correctness envelope minimum: durability cannot be set below 0.5.
    const ENVELOPE_MIN_DURABILITY: f64 = 0.5;

    pub fn new(min_durability: f64, warn_margin: f64) -> Self {
        let effective_min = min_durability.max(Self::ENVELOPE_MIN_DURABILITY);
        Self {
            budget_id: BudgetId::new("durability_budget"),
            min_durability: effective_min,
            warn_margin,
            min_allowed_durability: Self::ENVELOPE_MIN_DURABILITY,
        }
    }

    pub fn default_guardrail() -> Self {
        Self::new(0.9, 0.05)
    }
}

impl GuardrailMonitor for DurabilityLossGuardrail {
    fn check(&self, state: &SystemState) -> GuardrailVerdict {
        if state.durability_level < self.min_durability {
            GuardrailVerdict::Block {
                reason: format!(
                    "durability {:.2} below minimum {:.2}",
                    state.durability_level, self.min_durability,
                ),
                budget_id: self.budget_id.clone(),
            }
        } else if state.durability_level < self.min_durability + self.warn_margin {
            GuardrailVerdict::Warn {
                reason: format!(
                    "durability {:.2} approaching minimum {:.2} (margin {:.2})",
                    state.durability_level, self.min_durability, self.warn_margin,
                ),
            }
        } else {
            GuardrailVerdict::Allow
        }
    }

    fn name(&self) -> &str {
        "DurabilityLossGuardrail"
    }

    fn budget_id(&self) -> &BudgetId {
        &self.budget_id
    }
}

/// Blocks actions that would regress the hardening level (references INV-001).
#[derive(Debug, Clone)]
pub struct HardeningRegressionGuardrail {
    budget_id: BudgetId,
}

impl HardeningRegressionGuardrail {
    pub fn new() -> Self {
        Self {
            budget_id: BudgetId::new("hardening_regression"),
        }
    }
}

impl Default for HardeningRegressionGuardrail {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardrailMonitor for HardeningRegressionGuardrail {
    fn check(&self, state: &SystemState) -> GuardrailVerdict {
        if let Some(proposed) = state.proposed_hardening_level {
            if proposed < state.hardening_level {
                return GuardrailVerdict::Block {
                    reason: format!(
                        "hardening regression from {} to {} (INV-001-MONOTONIC-HARDENING)",
                        state.hardening_level.label(),
                        proposed.label(),
                    ),
                    budget_id: self.budget_id.clone(),
                };
            }
        }
        GuardrailVerdict::Allow
    }

    fn name(&self) -> &str {
        "HardeningRegressionGuardrail"
    }

    fn budget_id(&self) -> &BudgetId {
        &self.budget_id
    }
}

/// Blocks actions that bypass mandatory evidence emission (references INV-002).
#[derive(Debug, Clone)]
pub struct EvidenceEmissionGuardrail {
    budget_id: BudgetId,
}

impl EvidenceEmissionGuardrail {
    pub fn new() -> Self {
        Self {
            budget_id: BudgetId::new("evidence_emission"),
        }
    }
}

impl Default for EvidenceEmissionGuardrail {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardrailMonitor for EvidenceEmissionGuardrail {
    fn check(&self, state: &SystemState) -> GuardrailVerdict {
        if !state.evidence_emission_active {
            GuardrailVerdict::Block {
                reason: "evidence emission is disabled (INV-002-EVIDENCE-EMISSION)".into(),
                budget_id: self.budget_id.clone(),
            }
        } else {
            GuardrailVerdict::Allow
        }
    }

    fn name(&self) -> &str {
        "EvidenceEmissionGuardrail"
    }

    fn budget_id(&self) -> &BudgetId {
        &self.budget_id
    }
}

// ── GuardrailMonitorSet ───────────────────────────────────────────

/// Rejection event from a guardrail monitor (used by downstream consumers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardrailRejection {
    pub monitor_name: String,
    pub budget_id: BudgetId,
    pub reason: String,
    pub epoch_id: u64,
}

/// Runs all registered monitors and returns the most restrictive verdict.
///
/// INV-GUARD-RESTRICTIVE: when multiple monitors fire, the most restrictive
/// verdict wins. Block > Warn > Allow.
#[derive(Debug)]
pub struct GuardrailMonitorSet {
    monitors: Vec<Box<dyn GuardrailMonitor>>,
}

impl GuardrailMonitorSet {
    /// Create an empty monitor set.
    pub fn new() -> Self {
        Self {
            monitors: Vec::new(),
        }
    }

    /// Create a monitor set with all default monitors registered.
    pub fn with_defaults() -> Self {
        let mut set = Self::new();
        set.register(Box::new(MemoryBudgetGuardrail::default_guardrail()));
        set.register(Box::new(DurabilityLossGuardrail::default_guardrail()));
        set.register(Box::new(HardeningRegressionGuardrail::new()));
        set.register(Box::new(EvidenceEmissionGuardrail::new()));
        set
    }

    /// Register a monitor.
    pub fn register(&mut self, monitor: Box<dyn GuardrailMonitor>) {
        self.monitors.push(monitor);
    }

    /// Number of registered monitors.
    pub fn monitor_count(&self) -> usize {
        self.monitors.len()
    }

    /// Run all monitors and return the most restrictive verdict.
    pub fn check_all(&self, state: &SystemState) -> GuardrailVerdict {
        let mut most_restrictive = GuardrailVerdict::Allow;

        for monitor in &self.monitors {
            let verdict = monitor.check(state);
            if verdict.severity() > most_restrictive.severity() {
                most_restrictive = verdict;
            }
        }

        most_restrictive
    }

    /// Run all monitors and return all individual verdicts.
    pub fn check_all_detailed(&self, state: &SystemState) -> Vec<(&str, GuardrailVerdict)> {
        self.monitors
            .iter()
            .map(|m| (m.name(), m.check(state)))
            .collect()
    }

    /// Check if the proposed action is allowed and produce rejection if not.
    pub fn evaluate(
        &self,
        state: &SystemState,
    ) -> Result<(), GuardrailRejection> {
        for monitor in &self.monitors {
            let verdict = monitor.check(state);
            if let GuardrailVerdict::Block { reason, budget_id } = verdict {
                return Err(GuardrailRejection {
                    monitor_name: monitor.name().to_string(),
                    budget_id,
                    reason,
                    epoch_id: state.epoch_id,
                });
            }
        }
        Ok(())
    }
}

impl Default for GuardrailMonitorSet {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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

    // ── BudgetId tests ──

    #[test]
    fn budget_id_display() {
        let id = BudgetId::new("memory_budget");
        assert_eq!(id.to_string(), "memory_budget");
        assert_eq!(id.as_str(), "memory_budget");
    }

    // ── GuardrailVerdict tests ──

    #[test]
    fn verdict_allow_severity() {
        assert_eq!(GuardrailVerdict::Allow.severity(), 0);
    }

    #[test]
    fn verdict_warn_severity() {
        let v = GuardrailVerdict::Warn {
            reason: "test".into(),
        };
        assert_eq!(v.severity(), 1);
    }

    #[test]
    fn verdict_block_severity() {
        let v = GuardrailVerdict::Block {
            reason: "test".into(),
            budget_id: BudgetId::new("test"),
        };
        assert_eq!(v.severity(), 2);
    }

    #[test]
    fn verdict_event_codes() {
        assert_eq!(GuardrailVerdict::Allow.event_code(), "EVD-GUARD-001");
        assert_eq!(
            GuardrailVerdict::Block {
                reason: "x".into(),
                budget_id: BudgetId::new("x"),
            }
            .event_code(),
            "EVD-GUARD-002"
        );
        assert_eq!(
            GuardrailVerdict::Warn {
                reason: "x".into(),
            }
            .event_code(),
            "EVD-GUARD-003"
        );
    }

    #[test]
    fn verdict_display() {
        assert_eq!(GuardrailVerdict::Allow.to_string(), "ALLOW");
        let block = GuardrailVerdict::Block {
            reason: "test".into(),
            budget_id: BudgetId::new("mem"),
        };
        assert!(block.to_string().contains("BLOCK"));
        assert!(block.to_string().contains("mem"));
    }

    #[test]
    fn verdict_is_blocked() {
        assert!(!GuardrailVerdict::Allow.is_blocked());
        assert!(!GuardrailVerdict::Warn {
            reason: "x".into()
        }
        .is_blocked());
        assert!(GuardrailVerdict::Block {
            reason: "x".into(),
            budget_id: BudgetId::new("x"),
        }
        .is_blocked());
    }

    // ── SystemState tests ──

    #[test]
    fn memory_utilization_calculation() {
        let state = healthy_state();
        assert!((state.memory_utilization() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn memory_utilization_zero_budget() {
        let mut state = healthy_state();
        state.memory_budget_bytes = 0;
        assert!((state.memory_utilization() - 1.0).abs() < f64::EPSILON);
    }

    // ── MemoryBudgetGuardrail tests ──

    #[test]
    fn memory_guard_allows_within_budget() {
        let guard = MemoryBudgetGuardrail::default_guardrail();
        let state = healthy_state(); // 50% util
        assert_eq!(guard.check(&state), GuardrailVerdict::Allow);
    }

    #[test]
    fn memory_guard_warns_near_limit() {
        let guard = MemoryBudgetGuardrail::default_guardrail();
        let mut state = healthy_state();
        state.memory_used_bytes = 850_000_000; // 85% > warn(80%) < block(95%)
        match guard.check(&state) {
            GuardrailVerdict::Warn { .. } => {}
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn memory_guard_blocks_over_limit() {
        let guard = MemoryBudgetGuardrail::default_guardrail();
        let mut state = healthy_state();
        state.memory_used_bytes = 960_000_000; // 96% > block(95%)
        match guard.check(&state) {
            GuardrailVerdict::Block { budget_id, .. } => {
                assert_eq!(budget_id.as_str(), "memory_budget");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn memory_guard_respects_envelope_minimum() {
        // Try to set threshold below 0.5 — should be clamped to 0.5
        let guard = MemoryBudgetGuardrail::new(0.3, 0.2);
        assert!((guard.block_threshold - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn memory_guard_exact_threshold() {
        let guard = MemoryBudgetGuardrail::new(0.95, 0.80);
        let mut state = healthy_state();
        state.memory_used_bytes = 950_000_000; // exactly 95%
        assert!(guard.check(&state).is_blocked());
    }

    #[test]
    fn memory_guard_anytime_valid() {
        let guard = MemoryBudgetGuardrail::default_guardrail();
        assert!(guard.is_valid_at_any_stopping_point());
    }

    #[test]
    fn memory_guard_name() {
        let guard = MemoryBudgetGuardrail::default_guardrail();
        assert_eq!(guard.name(), "MemoryBudgetGuardrail");
    }

    // ── DurabilityLossGuardrail tests ──

    #[test]
    fn durability_guard_allows_above_minimum() {
        let guard = DurabilityLossGuardrail::default_guardrail();
        let state = healthy_state(); // durability 0.99
        assert_eq!(guard.check(&state), GuardrailVerdict::Allow);
    }

    #[test]
    fn durability_guard_warns_near_minimum() {
        let guard = DurabilityLossGuardrail::default_guardrail();
        let mut state = healthy_state();
        state.durability_level = 0.92; // Above 0.9 min, within 0.05 margin
        match guard.check(&state) {
            GuardrailVerdict::Warn { .. } => {}
            other => panic!("expected Warn, got {other:?}"),
        }
    }

    #[test]
    fn durability_guard_blocks_below_minimum() {
        let guard = DurabilityLossGuardrail::default_guardrail();
        let mut state = healthy_state();
        state.durability_level = 0.85; // Below 0.9 min
        match guard.check(&state) {
            GuardrailVerdict::Block { budget_id, .. } => {
                assert_eq!(budget_id.as_str(), "durability_budget");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn durability_guard_respects_envelope_minimum() {
        // Try to set min below 0.5 — should be clamped to 0.5
        let guard = DurabilityLossGuardrail::new(0.3, 0.05);
        assert!((guard.min_durability - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn durability_guard_anytime_valid() {
        let guard = DurabilityLossGuardrail::default_guardrail();
        assert!(guard.is_valid_at_any_stopping_point());
    }

    // ── HardeningRegressionGuardrail tests ──

    #[test]
    fn hardening_guard_allows_escalation() {
        let guard = HardeningRegressionGuardrail::new();
        let mut state = healthy_state();
        state.proposed_hardening_level = Some(HardeningLevel::Enhanced);
        assert_eq!(guard.check(&state), GuardrailVerdict::Allow);
    }

    #[test]
    fn hardening_guard_allows_no_proposal() {
        let guard = HardeningRegressionGuardrail::new();
        let state = healthy_state(); // proposed = None
        assert_eq!(guard.check(&state), GuardrailVerdict::Allow);
    }

    #[test]
    fn hardening_guard_blocks_regression() {
        let guard = HardeningRegressionGuardrail::new();
        let mut state = healthy_state();
        state.proposed_hardening_level = Some(HardeningLevel::Baseline);
        match guard.check(&state) {
            GuardrailVerdict::Block { reason, budget_id } => {
                assert!(reason.contains("INV-001"));
                assert_eq!(budget_id.as_str(), "hardening_regression");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn hardening_guard_blocks_same_level() {
        // Same level is not a regression (proposed == current), should allow
        let guard = HardeningRegressionGuardrail::new();
        let mut state = healthy_state();
        state.proposed_hardening_level = Some(HardeningLevel::Standard);
        assert_eq!(guard.check(&state), GuardrailVerdict::Allow);
    }

    #[test]
    fn hardening_guard_default() {
        let guard = HardeningRegressionGuardrail::default();
        assert_eq!(guard.name(), "HardeningRegressionGuardrail");
    }

    // ── EvidenceEmissionGuardrail tests ──

    #[test]
    fn evidence_guard_allows_when_active() {
        let guard = EvidenceEmissionGuardrail::new();
        let state = healthy_state(); // evidence_emission_active = true
        assert_eq!(guard.check(&state), GuardrailVerdict::Allow);
    }

    #[test]
    fn evidence_guard_blocks_when_disabled() {
        let guard = EvidenceEmissionGuardrail::new();
        let mut state = healthy_state();
        state.evidence_emission_active = false;
        match guard.check(&state) {
            GuardrailVerdict::Block { reason, budget_id } => {
                assert!(reason.contains("INV-002"));
                assert_eq!(budget_id.as_str(), "evidence_emission");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn evidence_guard_default() {
        let guard = EvidenceEmissionGuardrail::default();
        assert_eq!(guard.name(), "EvidenceEmissionGuardrail");
    }

    // ── GuardrailMonitorSet tests ──

    #[test]
    fn set_with_defaults_has_four_monitors() {
        let set = GuardrailMonitorSet::with_defaults();
        assert_eq!(set.monitor_count(), 4);
    }

    #[test]
    fn set_allows_healthy_state() {
        let set = GuardrailMonitorSet::with_defaults();
        let state = healthy_state();
        assert_eq!(set.check_all(&state), GuardrailVerdict::Allow);
    }

    #[test]
    fn set_returns_most_restrictive_block_over_warn() {
        let set = GuardrailMonitorSet::with_defaults();
        let mut state = healthy_state();
        state.memory_used_bytes = 850_000_000; // Warn
        state.evidence_emission_active = false; // Block

        let verdict = set.check_all(&state);
        assert!(verdict.is_blocked(), "expected Block, got {verdict:?}");
    }

    #[test]
    fn set_returns_warn_when_no_block() {
        let set = GuardrailMonitorSet::with_defaults();
        let mut state = healthy_state();
        state.memory_used_bytes = 850_000_000; // memory Warn, others Allow

        let verdict = set.check_all(&state);
        assert_eq!(verdict.severity(), 1);
    }

    #[test]
    fn set_detailed_returns_all_verdicts() {
        let set = GuardrailMonitorSet::with_defaults();
        let state = healthy_state();
        let detailed = set.check_all_detailed(&state);
        assert_eq!(detailed.len(), 4);
    }

    #[test]
    fn set_evaluate_returns_rejection_on_block() {
        let set = GuardrailMonitorSet::with_defaults();
        let mut state = healthy_state();
        state.evidence_emission_active = false;

        let rejection = set.evaluate(&state).unwrap_err();
        assert_eq!(rejection.budget_id.as_str(), "evidence_emission");
        assert_eq!(rejection.epoch_id, 42);
    }

    #[test]
    fn set_evaluate_returns_ok_when_allowed() {
        let set = GuardrailMonitorSet::with_defaults();
        let state = healthy_state();
        assert!(set.evaluate(&state).is_ok());
    }

    #[test]
    fn set_empty_allows_everything() {
        let set = GuardrailMonitorSet::new();
        let state = healthy_state();
        assert_eq!(set.check_all(&state), GuardrailVerdict::Allow);
    }

    #[test]
    fn set_default_is_with_defaults() {
        let set = GuardrailMonitorSet::default();
        assert_eq!(set.monitor_count(), 4);
    }

    // ── Optional stopping / anytime-valid tests ──

    #[test]
    fn anytime_valid_memory_varies_with_observation() {
        // At any observation point, the monitor gives a valid conclusion
        let guard = MemoryBudgetGuardrail::default_guardrail();
        let mut state = healthy_state();

        // Observation sequence of increasing memory usage
        for pct in [10, 50, 75, 85, 96] {
            state.memory_used_bytes = state.memory_budget_bytes * pct / 100;
            let verdict = guard.check(&state);
            // At each point, the verdict is consistent with the observed state
            if pct >= 95 {
                assert!(verdict.is_blocked());
            } else if pct >= 80 {
                assert_eq!(verdict.severity(), 1); // Warn
            } else {
                assert_eq!(verdict, GuardrailVerdict::Allow);
            }
        }
    }

    #[test]
    fn anytime_valid_durability_varies_with_observation() {
        let guard = DurabilityLossGuardrail::default_guardrail();
        let mut state = healthy_state();

        for dur in [99, 96, 92, 89, 50] {
            state.durability_level = dur as f64 / 100.0;
            let verdict = guard.check(&state);
            if dur < 90 {
                assert!(verdict.is_blocked());
            } else if dur < 96 {
                assert_eq!(verdict.severity(), 1, "dur={dur}");
            } else {
                assert_eq!(verdict, GuardrailVerdict::Allow, "dur={dur}");
            }
        }
    }

    // ── Threshold reconfiguration tests ──

    #[test]
    fn memory_threshold_configurable_above_minimum() {
        let guard = MemoryBudgetGuardrail::new(0.8, 0.7);
        assert!((guard.block_threshold - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn durability_threshold_configurable_above_minimum() {
        let guard = DurabilityLossGuardrail::new(0.8, 0.1);
        assert!((guard.min_durability - 0.8).abs() < f64::EPSILON);
    }

    // ── Combined scenario ──

    #[test]
    fn full_lifecycle_healthy_to_critical() {
        let set = GuardrailMonitorSet::with_defaults();
        let mut state = healthy_state();

        // Step 1: healthy
        assert!(set.evaluate(&state).is_ok());

        // Step 2: memory pressure (warn)
        state.memory_used_bytes = 850_000_000;
        assert!(set.evaluate(&state).is_ok()); // warn but still ok

        // Step 3: evidence disabled (block)
        state.evidence_emission_active = false;
        let rej = set.evaluate(&state).unwrap_err();
        assert_eq!(rej.budget_id.as_str(), "evidence_emission");

        // Step 4: fix evidence, add hardening regression
        state.evidence_emission_active = true;
        state.proposed_hardening_level = Some(HardeningLevel::Baseline);
        let rej = set.evaluate(&state).unwrap_err();
        assert_eq!(rej.budget_id.as_str(), "hardening_regression");
    }
}
