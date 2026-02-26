//! bd-1ayu: Overhead/rate clamp policy for hardening escalations.
//!
//! Prevents "escalation storms" by enforcing deterministic ceilings on how fast
//! and how much the system can harden within a given time window and resource
//! budget. Supports Section 8.5 Invariant #9 (bounded resource consumption).
//!
//! # Invariants
//!
//! - INV-CLAMP-RATE: no more than `max_escalations_per_window` in any window
//! - INV-CLAMP-OVERHEAD: estimated overhead cannot exceed `max_overhead_pct`
//! - INV-CLAMP-BOUNDS: escalation stays within [min_level, max_level]
//! - INV-CLAMP-DETERMINISTIC: same inputs always produce same output

use std::fmt;

use super::hardening_state_machine::HardeningLevel;

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const CLAMP_ALLOWED: &str = "EVD-CLAMP-001";
    pub const CLAMP_CLAMPED: &str = "EVD-CLAMP-002";
    pub const CLAMP_DENIED: &str = "EVD-CLAMP-003";
    pub const CLAMP_BUDGET_RECALCULATED: &str = "EVD-CLAMP-004";
}

/// Estimated overhead percentage for each hardening level.
///
/// These are fixed, deterministic values used for clamp decisions.
pub fn estimated_overhead_pct(level: HardeningLevel) -> f64 {
    match level {
        HardeningLevel::Baseline => 0.0,
        HardeningLevel::Standard => 5.0,
        HardeningLevel::Enhanced => 15.0,
        HardeningLevel::Maximum => 35.0,
        HardeningLevel::Critical => 60.0,
    }
}

/// Budget configuration for escalation rate and overhead limits.
#[derive(Debug, Clone, PartialEq)]
pub struct EscalationBudget {
    /// Maximum escalations allowed within one window.
    pub max_escalations_per_window: u32,
    /// Rolling window duration in milliseconds (monotonic counter units).
    pub window_duration_ms: u64,
    /// Maximum additional CPU/memory overhead from hardening (percentage, 0.0-100.0).
    pub max_overhead_pct: f64,
    /// Policy floor: escalation cannot go below this level.
    pub min_level: HardeningLevel,
    /// Policy ceiling: escalation cannot go above this level.
    pub max_level: HardeningLevel,
}

impl EscalationBudget {
    /// Create a budget with sensible defaults.
    pub fn default_budget() -> Self {
        Self {
            max_escalations_per_window: 3,
            window_duration_ms: 60_000,
            max_overhead_pct: 40.0,
            min_level: HardeningLevel::Baseline,
            max_level: HardeningLevel::Critical,
        }
    }
}

/// A record of a past escalation for rate-limiting purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationRecord {
    /// Monotonic timestamp (milliseconds).
    pub timestamp_ms: u64,
    /// The level that was escalated to.
    pub to_level: HardeningLevel,
}

/// Result of a clamp evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum ClampResult {
    /// Escalation proceeds as proposed.
    Allowed,
    /// Escalation proceeds but at a lower effective level.
    Clamped {
        effective_level: HardeningLevel,
        reason: String,
    },
    /// Escalation blocked entirely.
    Denied { reason: String },
}

impl ClampResult {
    /// Event code for structured logging.
    pub fn event_code(&self) -> &'static str {
        match self {
            Self::Allowed => event_codes::CLAMP_ALLOWED,
            Self::Clamped { .. } => event_codes::CLAMP_CLAMPED,
            Self::Denied { .. } => event_codes::CLAMP_DENIED,
        }
    }

    /// Whether the escalation was allowed (possibly clamped).
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed | Self::Clamped { .. })
    }
}

impl fmt::Display for ClampResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => write!(f, "ALLOWED"),
            Self::Clamped {
                effective_level,
                reason,
            } => {
                write!(f, "CLAMPED to {}: {}", effective_level.label(), reason)
            }
            Self::Denied { reason } => write!(f, "DENIED: {reason}"),
        }
    }
}

/// Telemetry event emitted on every clamp evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct ClampEvent {
    /// Monotonic timestamp.
    pub timestamp: u64,
    /// Level that was requested.
    pub proposed_level: HardeningLevel,
    /// Level that was applied (or current if denied).
    pub effective_level: HardeningLevel,
    /// Human-readable explanation.
    pub reason: String,
    /// Fraction of rate budget consumed (0.0-1.0).
    pub budget_utilization_pct: f64,
}

impl ClampEvent {
    /// CSV header for metrics output.
    pub fn csv_header() -> &'static str {
        "timestamp,proposed_level,effective_level,clamp_reason,budget_utilization_pct,rate_count"
    }

    /// Format as CSV row.
    pub fn to_csv_row(&self, rate_count: u32) -> String {
        format!(
            "{},{},{},{},{:.4},{}",
            self.timestamp,
            self.proposed_level.label(),
            self.effective_level.label(),
            self.reason.replace(',', ";"),
            self.budget_utilization_pct,
            rate_count,
        )
    }
}

/// Error type for clamp policy operations.
#[derive(Debug, Clone, PartialEq)]
pub enum ClampError {
    /// Budget has invalid configuration.
    InvalidBudget { reason: String },
}

impl fmt::Display for ClampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBudget { reason } => write!(f, "CLAMP_INVALID_BUDGET: {reason}"),
        }
    }
}

/// Hardening clamp policy engine.
///
/// INV-CLAMP-DETERMINISTIC: identical inputs always produce identical outputs.
/// INV-CLAMP-RATE: rate limit enforced per window.
/// INV-CLAMP-OVERHEAD: overhead ceiling enforced.
/// INV-CLAMP-BOUNDS: min/max level bounds enforced.
#[derive(Debug)]
pub struct HardeningClampPolicy {
    budget: EscalationBudget,
    escalation_history: Vec<EscalationRecord>,
}

impl HardeningClampPolicy {
    /// Create a new clamp policy with the given budget.
    pub fn new(budget: EscalationBudget) -> Self {
        Self {
            budget,
            escalation_history: Vec::new(),
        }
    }

    /// Get the current budget.
    pub fn budget(&self) -> &EscalationBudget {
        &self.budget
    }

    /// Update the budget configuration.
    pub fn set_budget(&mut self, budget: EscalationBudget) {
        self.budget = budget;
    }

    /// Get the escalation history.
    pub fn history(&self) -> &[EscalationRecord] {
        &self.escalation_history
    }

    /// Record an escalation that occurred.
    pub fn record_escalation(&mut self, timestamp_ms: u64, to_level: HardeningLevel) {
        self.escalation_history.push(EscalationRecord {
            timestamp_ms,
            to_level,
        });
    }

    /// Count escalations within the current window.
    fn count_in_window(&self, now_ms: u64) -> u32 {
        // Protect against zero window duration (would mean "instant window")
        if self.budget.window_duration_ms == 0 {
            // With zero window, all historical escalations are outside the window
            return 0;
        }

        let window_start = now_ms.saturating_sub(self.budget.window_duration_ms);
        self.escalation_history
            .iter()
            .filter(|r| r.timestamp_ms >= window_start)
            .count() as u32
    }

    /// Find the highest level whose overhead is within budget.
    fn highest_level_within_overhead(&self) -> HardeningLevel {
        let mut best = HardeningLevel::Baseline;
        for level in HardeningLevel::all() {
            if estimated_overhead_pct(*level) <= self.budget.max_overhead_pct
                && *level <= self.budget.max_level
                && *level >= self.budget.min_level
            {
                best = *level;
            }
        }
        best
    }

    /// Evaluate whether a proposed escalation is within rate and overhead bounds.
    ///
    /// INV-CLAMP-DETERMINISTIC: same (proposed, current, budget, history, now_ms)
    /// always produces the same result.
    pub fn check_escalation(
        &self,
        proposed: HardeningLevel,
        current: HardeningLevel,
        now_ms: u64,
    ) -> (ClampResult, ClampEvent) {
        let rate_count = self.count_in_window(now_ms);
        let max = self.budget.max_escalations_per_window;
        let utilization = if max > 0 {
            rate_count as f64 / max as f64
        } else {
            // max_escalations_per_window = 0 means no escalations allowed
            if rate_count > 0 {
                1.0
            } else {
                // No escalations yet, but also none allowed
                1.0
            }
        };

        // Not an escalation
        if proposed <= current {
            let result = ClampResult::Denied {
                reason: format!(
                    "proposed {} is not above current {}",
                    proposed.label(),
                    current.label()
                ),
            };
            let event = ClampEvent {
                timestamp: now_ms,
                proposed_level: proposed,
                effective_level: current,
                reason: "not an escalation".into(),
                budget_utilization_pct: utilization,
            };
            return (result, event);
        }

        // Rate limit check — deny if at or above limit
        if max == 0 || rate_count >= max {
            let reason = if max == 0 {
                "rate limit: max_escalations_per_window is 0".into()
            } else {
                format!("rate limit: {rate_count}/{max} escalations in window")
            };
            let result = ClampResult::Denied {
                reason: reason.clone(),
            };
            let event = ClampEvent {
                timestamp: now_ms,
                proposed_level: proposed,
                effective_level: current,
                reason,
                budget_utilization_pct: utilization.min(1.0),
            };
            return (result, event);
        }

        // Apply max_level ceiling
        let mut effective = proposed;
        let mut clamped_reason: Option<String> = None;

        if effective > self.budget.max_level {
            effective = self.budget.max_level;
            clamped_reason = Some(format!(
                "capped at max_level {}",
                self.budget.max_level.label()
            ));
        }

        // Apply min_level floor (effective must be at least min_level)
        if effective < self.budget.min_level {
            effective = self.budget.min_level;
            let reason = format!("raised to min_level {}", self.budget.min_level.label());
            clamped_reason = Some(match clamped_reason {
                Some(prev) => format!("{prev}; {reason}"),
                None => reason,
            });
        }

        // Apply overhead limit
        let overhead = estimated_overhead_pct(effective);
        if overhead > self.budget.max_overhead_pct {
            let best = self.highest_level_within_overhead();
            if best <= current {
                let reason = format!(
                    "overhead limit: {} overhead {overhead:.1}% exceeds budget {:.1}%; best within budget ({}) not above current ({})",
                    effective.label(),
                    self.budget.max_overhead_pct,
                    best.label(),
                    current.label(),
                );
                let result = ClampResult::Denied {
                    reason: reason.clone(),
                };
                let event = ClampEvent {
                    timestamp: now_ms,
                    proposed_level: proposed,
                    effective_level: current,
                    reason,
                    budget_utilization_pct: utilization,
                };
                return (result, event);
            }
            effective = best;
            let reason = format!(
                "overhead clamped: {:.1}% exceeds budget {:.1}%, effective {}",
                estimated_overhead_pct(proposed),
                self.budget.max_overhead_pct,
                effective.label(),
            );
            clamped_reason = Some(match clamped_reason {
                Some(prev) => format!("{prev}; {reason}"),
                None => reason,
            });
        }

        // After all adjustments, verify effective is still above current
        if effective <= current {
            let reason = format!(
                "effective level {} not above current {} after clamping",
                effective.label(),
                current.label(),
            );
            let result = ClampResult::Denied {
                reason: reason.clone(),
            };
            let event = ClampEvent {
                timestamp: now_ms,
                proposed_level: proposed,
                effective_level: current,
                reason,
                budget_utilization_pct: utilization,
            };
            return (result, event);
        }

        // Build result
        let result = match clamped_reason {
            Some(reason) => ClampResult::Clamped {
                effective_level: effective,
                reason: reason.clone(),
            },
            None => ClampResult::Allowed,
        };

        let reason_str = match &result {
            ClampResult::Allowed => "allowed".to_string(),
            ClampResult::Clamped { reason, .. } => reason.clone(),
            ClampResult::Denied { reason } => reason.clone(),
        };

        let event = ClampEvent {
            timestamp: now_ms,
            proposed_level: proposed,
            effective_level: effective,
            reason: reason_str,
            budget_utilization_pct: utilization,
        };

        (result, event)
    }

    /// Convenience: check and auto-record if allowed.
    pub fn check_and_record(
        &mut self,
        proposed: HardeningLevel,
        current: HardeningLevel,
        now_ms: u64,
    ) -> (ClampResult, ClampEvent) {
        let (result, event) = self.check_escalation(proposed, current, now_ms);
        if result.is_allowed() {
            let effective = match &result {
                ClampResult::Clamped {
                    effective_level, ..
                } => *effective_level,
                _ => proposed,
            };
            self.record_escalation(now_ms, effective);
        }
        (result, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_budget() -> EscalationBudget {
        EscalationBudget::default_budget()
    }

    // ---- EscalationBudget tests ----

    #[test]
    fn default_budget_values() {
        let b = EscalationBudget::default_budget();
        assert_eq!(b.max_escalations_per_window, 3);
        assert_eq!(b.window_duration_ms, 60_000);
        assert!((b.max_overhead_pct - 40.0).abs() < f64::EPSILON);
        assert_eq!(b.min_level, HardeningLevel::Baseline);
        assert_eq!(b.max_level, HardeningLevel::Critical);
    }

    // ---- Overhead estimation tests ----

    #[test]
    fn overhead_monotonically_increases() {
        let levels = HardeningLevel::all();
        for i in 0..levels.len() - 1 {
            assert!(
                estimated_overhead_pct(levels[i]) < estimated_overhead_pct(levels[i + 1]),
                "overhead for {} should be less than {}",
                levels[i].label(),
                levels[i + 1].label()
            );
        }
    }

    #[test]
    fn overhead_baseline_is_zero() {
        assert!((estimated_overhead_pct(HardeningLevel::Baseline)).abs() < f64::EPSILON);
    }

    #[test]
    fn overhead_critical_is_60() {
        assert!((estimated_overhead_pct(HardeningLevel::Critical) - 60.0).abs() < f64::EPSILON);
    }

    // ---- Basic allowed escalation ----

    #[test]
    fn escalation_allowed_within_budget() {
        let policy = HardeningClampPolicy::new(default_budget());
        let (result, event) =
            policy.check_escalation(HardeningLevel::Standard, HardeningLevel::Baseline, 1000);
        assert_eq!(result, ClampResult::Allowed);
        assert_eq!(result.event_code(), event_codes::CLAMP_ALLOWED);
        assert_eq!(event.effective_level, HardeningLevel::Standard);
    }

    #[test]
    fn escalation_allowed_skip_levels() {
        let policy = HardeningClampPolicy::new(default_budget());
        let (result, _) =
            policy.check_escalation(HardeningLevel::Maximum, HardeningLevel::Baseline, 1000);
        assert_eq!(result, ClampResult::Allowed);
    }

    // ---- Rate limit tests ----

    #[test]
    fn rate_limit_at_boundary() {
        let budget = EscalationBudget {
            max_escalations_per_window: 2,
            window_duration_ms: 60_000,
            ..default_budget()
        };
        let mut policy = HardeningClampPolicy::new(budget);
        policy.record_escalation(1000, HardeningLevel::Standard);
        policy.record_escalation(2000, HardeningLevel::Enhanced);

        // Third escalation should be denied
        let (result, _) =
            policy.check_escalation(HardeningLevel::Maximum, HardeningLevel::Enhanced, 3000);
        assert!(matches!(result, ClampResult::Denied { .. }));
    }

    #[test]
    fn rate_limit_exactly_at_max() {
        let budget = EscalationBudget {
            max_escalations_per_window: 2,
            window_duration_ms: 60_000,
            ..default_budget()
        };
        let mut policy = HardeningClampPolicy::new(budget);
        // One escalation — should still be allowed
        policy.record_escalation(1000, HardeningLevel::Standard);

        let (result, _) =
            policy.check_escalation(HardeningLevel::Enhanced, HardeningLevel::Standard, 2000);
        assert_eq!(result, ClampResult::Allowed);
    }

    #[test]
    fn rate_limit_window_rollover() {
        let budget = EscalationBudget {
            max_escalations_per_window: 2,
            window_duration_ms: 10_000,
            ..default_budget()
        };
        let mut policy = HardeningClampPolicy::new(budget);
        policy.record_escalation(1000, HardeningLevel::Standard);
        policy.record_escalation(2000, HardeningLevel::Enhanced);

        // At 3000, within window — should be denied
        let (result, _) =
            policy.check_escalation(HardeningLevel::Maximum, HardeningLevel::Enhanced, 3000);
        assert!(matches!(result, ClampResult::Denied { .. }));

        // At 12001, outside window — old escalations expired
        let (result, _) =
            policy.check_escalation(HardeningLevel::Maximum, HardeningLevel::Enhanced, 12001);
        assert_eq!(result, ClampResult::Allowed);
    }

    #[test]
    fn rate_limit_zero_max_escalations() {
        let budget = EscalationBudget {
            max_escalations_per_window: 0,
            ..default_budget()
        };
        let policy = HardeningClampPolicy::new(budget);
        let (result, _) =
            policy.check_escalation(HardeningLevel::Standard, HardeningLevel::Baseline, 1000);
        assert!(matches!(result, ClampResult::Denied { .. }));
    }

    // ---- Max/min level bound tests ----

    #[test]
    fn max_level_clamps_proposed() {
        let budget = EscalationBudget {
            max_level: HardeningLevel::Enhanced,
            ..default_budget()
        };
        let policy = HardeningClampPolicy::new(budget);
        let (result, event) =
            policy.check_escalation(HardeningLevel::Critical, HardeningLevel::Baseline, 1000);
        match &result {
            ClampResult::Clamped {
                effective_level, ..
            } => {
                assert_eq!(*effective_level, HardeningLevel::Enhanced);
            }
            other => panic!("expected Clamped, got {other:?}"),
        }
        assert_eq!(event.effective_level, HardeningLevel::Enhanced);
    }

    #[test]
    fn max_level_below_current_denies() {
        let budget = EscalationBudget {
            max_level: HardeningLevel::Standard,
            ..default_budget()
        };
        let policy = HardeningClampPolicy::new(budget);
        // Current is Standard, max is Standard, proposed is Enhanced
        // After clamping, effective = Standard which is not above current
        let (result, _) =
            policy.check_escalation(HardeningLevel::Enhanced, HardeningLevel::Standard, 1000);
        assert!(matches!(result, ClampResult::Denied { .. }));
    }

    // ---- Overhead limit tests ----

    #[test]
    fn overhead_limit_clamps_to_lower_level() {
        let budget = EscalationBudget {
            max_overhead_pct: 20.0, // Enhanced is 15%, Maximum is 35%
            ..default_budget()
        };
        let policy = HardeningClampPolicy::new(budget);
        let (result, _) =
            policy.check_escalation(HardeningLevel::Maximum, HardeningLevel::Baseline, 1000);
        match &result {
            ClampResult::Clamped {
                effective_level, ..
            } => {
                assert_eq!(*effective_level, HardeningLevel::Enhanced);
            }
            other => panic!("expected Clamped, got {other:?}"),
        }
    }

    #[test]
    fn overhead_limit_zero_denies_all_above_baseline() {
        let budget = EscalationBudget {
            max_overhead_pct: 0.0,
            ..default_budget()
        };
        let policy = HardeningClampPolicy::new(budget);
        let (result, _) =
            policy.check_escalation(HardeningLevel::Standard, HardeningLevel::Baseline, 1000);
        assert!(matches!(result, ClampResult::Denied { .. }));
    }

    #[test]
    fn overhead_limit_allows_within_budget() {
        let budget = EscalationBudget {
            max_overhead_pct: 10.0, // Standard is 5%, so allowed
            ..default_budget()
        };
        let policy = HardeningClampPolicy::new(budget);
        let (result, _) =
            policy.check_escalation(HardeningLevel::Standard, HardeningLevel::Baseline, 1000);
        assert_eq!(result, ClampResult::Allowed);
    }

    // ---- Not-an-escalation tests ----

    #[test]
    fn same_level_denied() {
        let policy = HardeningClampPolicy::new(default_budget());
        let (result, _) =
            policy.check_escalation(HardeningLevel::Standard, HardeningLevel::Standard, 1000);
        assert!(matches!(result, ClampResult::Denied { .. }));
    }

    #[test]
    fn lower_level_denied() {
        let policy = HardeningClampPolicy::new(default_budget());
        let (result, _) =
            policy.check_escalation(HardeningLevel::Baseline, HardeningLevel::Standard, 1000);
        assert!(matches!(result, ClampResult::Denied { .. }));
    }

    // ---- Determinism tests ----

    #[test]
    fn deterministic_across_1000_runs() {
        let budget = EscalationBudget {
            max_escalations_per_window: 5,
            window_duration_ms: 30_000,
            max_overhead_pct: 40.0,
            min_level: HardeningLevel::Baseline,
            max_level: HardeningLevel::Maximum,
        };

        let first_result;
        {
            let mut policy = HardeningClampPolicy::new(budget.clone());
            policy.record_escalation(500, HardeningLevel::Standard);
            policy.record_escalation(1000, HardeningLevel::Enhanced);
            let (r, _) =
                policy.check_escalation(HardeningLevel::Critical, HardeningLevel::Enhanced, 2000);
            first_result = r;
        }

        for _ in 0..1000 {
            let mut policy = HardeningClampPolicy::new(budget.clone());
            policy.record_escalation(500, HardeningLevel::Standard);
            policy.record_escalation(1000, HardeningLevel::Enhanced);
            let (r, _) =
                policy.check_escalation(HardeningLevel::Critical, HardeningLevel::Enhanced, 2000);
            assert_eq!(r, first_result, "determinism violated on iteration");
        }
    }

    // ---- check_and_record tests ----

    #[test]
    fn check_and_record_updates_history() {
        let mut policy = HardeningClampPolicy::new(default_budget());
        assert_eq!(policy.history().len(), 0);

        let (result, _) =
            policy.check_and_record(HardeningLevel::Standard, HardeningLevel::Baseline, 1000);
        assert_eq!(result, ClampResult::Allowed);
        assert_eq!(policy.history().len(), 1);
        assert_eq!(policy.history()[0].to_level, HardeningLevel::Standard);
    }

    #[test]
    fn check_and_record_denied_no_history() {
        let budget = EscalationBudget {
            max_escalations_per_window: 0,
            ..default_budget()
        };
        let mut policy = HardeningClampPolicy::new(budget);

        let (result, _) =
            policy.check_and_record(HardeningLevel::Standard, HardeningLevel::Baseline, 1000);
        assert!(matches!(result, ClampResult::Denied { .. }));
        assert_eq!(policy.history().len(), 0);
    }

    #[test]
    fn check_and_record_clamped_records_effective() {
        let budget = EscalationBudget {
            max_level: HardeningLevel::Enhanced,
            ..default_budget()
        };
        let mut policy = HardeningClampPolicy::new(budget);

        let (result, _) =
            policy.check_and_record(HardeningLevel::Critical, HardeningLevel::Baseline, 1000);
        match &result {
            ClampResult::Clamped {
                effective_level, ..
            } => {
                assert_eq!(*effective_level, HardeningLevel::Enhanced);
            }
            other => panic!("expected Clamped, got {other:?}"),
        }
        assert_eq!(policy.history().len(), 1);
        assert_eq!(policy.history()[0].to_level, HardeningLevel::Enhanced);
    }

    // ---- ClampResult display and event_code tests ----

    #[test]
    fn clamp_result_display() {
        let allowed = ClampResult::Allowed;
        assert!(allowed.to_string().contains("ALLOWED"));

        let clamped = ClampResult::Clamped {
            effective_level: HardeningLevel::Enhanced,
            reason: "test".into(),
        };
        assert!(clamped.to_string().contains("CLAMPED"));

        let denied = ClampResult::Denied {
            reason: "test".into(),
        };
        assert!(denied.to_string().contains("DENIED"));
    }

    #[test]
    fn clamp_result_event_codes() {
        assert_eq!(ClampResult::Allowed.event_code(), "EVD-CLAMP-001");
        assert_eq!(
            ClampResult::Clamped {
                effective_level: HardeningLevel::Standard,
                reason: "test".into()
            }
            .event_code(),
            "EVD-CLAMP-002"
        );
        assert_eq!(
            ClampResult::Denied {
                reason: "test".into()
            }
            .event_code(),
            "EVD-CLAMP-003"
        );
    }

    #[test]
    fn clamp_result_is_allowed() {
        assert!(ClampResult::Allowed.is_allowed());
        assert!(
            ClampResult::Clamped {
                effective_level: HardeningLevel::Standard,
                reason: "test".into()
            }
            .is_allowed()
        );
        assert!(
            !ClampResult::Denied {
                reason: "test".into()
            }
            .is_allowed()
        );
    }

    // ---- ClampEvent CSV tests ----

    #[test]
    fn clamp_event_csv_header() {
        let header = ClampEvent::csv_header();
        assert!(header.contains("timestamp"));
        assert!(header.contains("proposed_level"));
        assert!(header.contains("effective_level"));
        assert!(header.contains("budget_utilization_pct"));
    }

    #[test]
    fn clamp_event_csv_row() {
        let event = ClampEvent {
            timestamp: 1000,
            proposed_level: HardeningLevel::Maximum,
            effective_level: HardeningLevel::Enhanced,
            reason: "overhead clamped".into(),
            budget_utilization_pct: 0.5,
        };
        let row = event.to_csv_row(2);
        assert!(row.contains("1000"));
        assert!(row.contains("maximum"));
        assert!(row.contains("enhanced"));
        assert!(row.contains("0.5000"));
    }

    // ---- Budget utilization tests ----

    #[test]
    fn budget_utilization_zero_when_empty() {
        let policy = HardeningClampPolicy::new(default_budget());
        let (_, event) =
            policy.check_escalation(HardeningLevel::Standard, HardeningLevel::Baseline, 1000);
        assert!((event.budget_utilization_pct).abs() < f64::EPSILON);
    }

    #[test]
    fn budget_utilization_increases_with_history() {
        let budget = EscalationBudget {
            max_escalations_per_window: 4,
            ..default_budget()
        };
        let mut policy = HardeningClampPolicy::new(budget);
        policy.record_escalation(500, HardeningLevel::Standard);
        policy.record_escalation(600, HardeningLevel::Enhanced);

        let (_, event) =
            policy.check_escalation(HardeningLevel::Maximum, HardeningLevel::Enhanced, 700);
        assert!((event.budget_utilization_pct - 0.5).abs() < f64::EPSILON);
    }

    // ---- Zero window duration test ----

    #[test]
    fn zero_window_duration_allows_escalation() {
        let budget = EscalationBudget {
            window_duration_ms: 0,
            ..default_budget()
        };
        let mut policy = HardeningClampPolicy::new(budget);
        // Even with history, zero window means nothing is "in window"
        policy.record_escalation(500, HardeningLevel::Standard);
        policy.record_escalation(600, HardeningLevel::Enhanced);

        let (result, _) =
            policy.check_escalation(HardeningLevel::Maximum, HardeningLevel::Enhanced, 700);
        assert_eq!(result, ClampResult::Allowed);
    }

    // ---- Combined constraint tests ----

    #[test]
    fn rate_and_overhead_combined() {
        let budget = EscalationBudget {
            max_escalations_per_window: 2,
            window_duration_ms: 60_000,
            max_overhead_pct: 20.0,
            min_level: HardeningLevel::Baseline,
            max_level: HardeningLevel::Critical,
        };
        let mut policy = HardeningClampPolicy::new(budget);
        policy.record_escalation(1000, HardeningLevel::Standard);

        // Propose Critical (60% overhead) — should be clamped to Enhanced (15%)
        let (result, _) =
            policy.check_escalation(HardeningLevel::Critical, HardeningLevel::Standard, 2000);
        match &result {
            ClampResult::Clamped {
                effective_level, ..
            } => {
                assert_eq!(*effective_level, HardeningLevel::Enhanced);
            }
            other => panic!("expected Clamped, got {other:?}"),
        }
    }

    // ---- Sustained escalation test ----

    #[test]
    fn sustained_escalation_blocked_after_limit() {
        let budget = EscalationBudget {
            max_escalations_per_window: 3,
            window_duration_ms: 60_000,
            ..default_budget()
        };
        let mut policy = HardeningClampPolicy::new(budget);

        // Three allowed escalations
        for i in 0..3 {
            policy.record_escalation(1000 + i * 100, HardeningLevel::Standard);
        }

        // Fourth should be denied
        let (result, _) =
            policy.check_escalation(HardeningLevel::Enhanced, HardeningLevel::Standard, 1500);
        assert!(matches!(result, ClampResult::Denied { .. }));
    }

    // ---- Error display ----

    #[test]
    fn clamp_error_display() {
        let err = ClampError::InvalidBudget {
            reason: "negative window".into(),
        };
        assert!(err.to_string().contains("negative window"));
    }

    // Regression: escalation at exact window boundary must be counted (fail-closed).
    // Before fix: `>` excluded boundary events, allowing one extra escalation.
    #[test]
    fn escalation_at_exact_window_boundary_is_counted() {
        let budget = EscalationBudget {
            max_escalations_per_window: 1,
            window_duration_ms: 1000,
            max_level: HardeningLevel::Maximum,
            min_level: HardeningLevel::Baseline,
            max_overhead_pct: 50.0,
        };
        let mut policy = HardeningClampPolicy::new(budget);
        // Record one escalation at t=500
        policy.record_escalation(500, HardeningLevel::Standard);
        // At t=1500, window_start = 1500 - 1000 = 500.
        // The escalation at t=500 is exactly at the boundary.
        // Fail-closed: must count it, so budget is exhausted (1/1).
        // Attempting another escalation at t=1500 should be rate-limited.
        let (result, _) =
            policy.check_escalation(HardeningLevel::Enhanced, HardeningLevel::Standard, 1500);
        assert!(
            matches!(result, ClampResult::Denied { .. }),
            "boundary event must count toward rate limit (fail-closed)"
        );
    }
}
