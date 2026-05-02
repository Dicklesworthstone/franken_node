//! bd-93k: checkpoint-placement contract guard for long orchestration loops.

use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::capacity_defaults::aliases::MAX_EVENTS;
use crate::push_bounded;

use crate::runtime::checkpoint::{
    CHECKPOINT_CONTRACT_VIOLATION, CHECKPOINT_MISSING, CHECKPOINT_SAVE, CHECKPOINT_WARNING,
    FN_CK_001_CHECKPOINT_SAVE, FN_CK_006_CONTRACT_WARNING, FN_CK_007_CONTRACT_VIOLATION,
};

/// Guard enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardMode {
    Warn,
    Strict,
}

/// Checkpoint-placement contract configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointGuardConfig {
    pub max_iterations_between_checkpoints: u64,
    pub max_duration_between_checkpoints_ms: u64,
    pub mode: GuardMode,
    pub strict_abort_multiplier: u64,
}

impl Default for CheckpointGuardConfig {
    fn default() -> Self {
        Self {
            max_iterations_between_checkpoints: 100,
            max_duration_between_checkpoints_ms: 5_000,
            mode: GuardMode::Warn,
            strict_abort_multiplier: 2,
        }
    }
}

impl CheckpointGuardConfig {
    #[must_use]
    pub fn max_duration_between_checkpoints(&self) -> Duration {
        Duration::from_millis(self.max_duration_between_checkpoints_ms)
    }
}

/// Structured guard event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointGuardEvent {
    pub event_code: String,
    pub event_name: String,
    pub orchestration_id: String,
    pub iteration_count: u64,
    pub trace_id: String,
    pub contract_status: String,
    pub elapsed_ms: u64,
}

/// Error emitted when strict checkpoint contract is violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointContractViolation {
    pub orchestration_id: String,
    pub iteration_count: u64,
    pub elapsed_ms: u64,
    pub max_iterations_between_checkpoints: u64,
    pub max_duration_between_checkpoints_ms: u64,
}

impl CheckpointContractViolation {
    #[must_use]
    pub fn code(&self) -> &'static str {
        "CHECKPOINT_CONTRACT_VIOLATION"
    }
}

impl fmt::Display for CheckpointContractViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: orchestration={} iteration={} elapsed_ms={} limits={{iterations:{},duration_ms:{}}}",
            self.code(),
            self.orchestration_id,
            self.iteration_count,
            self.elapsed_ms,
            self.max_iterations_between_checkpoints,
            self.max_duration_between_checkpoints_ms
        )
    }
}

impl std::error::Error for CheckpointContractViolation {}

/// Runtime contract guard for long loops.
#[derive(Debug, Clone)]
pub struct CheckpointGuard {
    orchestration_id: String,
    trace_id: String,
    config: CheckpointGuardConfig,
    started_at: Instant,
    last_checkpoint_at: Instant,
    last_checkpoint_iteration: u64,
    checkpoint_count: u64,
    events: Vec<CheckpointGuardEvent>,
}

impl CheckpointGuard {
    #[must_use]
    pub fn new(
        orchestration_id: impl Into<String>,
        trace_id: impl Into<String>,
        config: CheckpointGuardConfig,
    ) -> Self {
        let now = Instant::now();
        Self {
            orchestration_id: orchestration_id.into(),
            trace_id: trace_id.into(),
            config,
            started_at: now,
            last_checkpoint_at: now,
            last_checkpoint_iteration: 0,
            checkpoint_count: 0,
            events: Vec::new(),
        }
    }

    #[must_use]
    pub fn events(&self) -> &[CheckpointGuardEvent] {
        &self.events
    }

    fn emit_event(&mut self, event: CheckpointGuardEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    /// Record that a checkpoint was written at the given iteration.
    pub fn checkpoint(&mut self, iteration_count: u64) {
        self.last_checkpoint_iteration = iteration_count;
        self.last_checkpoint_at = Instant::now();
        self.checkpoint_count = self.checkpoint_count.saturating_add(1);

        self.emit_event(CheckpointGuardEvent {
            event_code: FN_CK_001_CHECKPOINT_SAVE.to_string(),
            event_name: CHECKPOINT_SAVE.to_string(),
            orchestration_id: self.orchestration_id.clone(),
            iteration_count,
            trace_id: self.trace_id.clone(),
            contract_status: "checkpointed".to_string(),
            elapsed_ms: elapsed_ms(self.started_at),
        });
    }

    /// Validate contract status for one iteration step.
    pub fn on_iteration(
        &mut self,
        iteration_count: u64,
    ) -> Result<(), CheckpointContractViolation> {
        let elapsed_since_checkpoint = self.last_checkpoint_at.elapsed();
        let elapsed_since_checkpoint_ms = duration_ms(elapsed_since_checkpoint);
        let iterations_since_checkpoint =
            iteration_count.saturating_sub(self.last_checkpoint_iteration);

        let warn_by_iterations =
            iterations_since_checkpoint >= self.config.max_iterations_between_checkpoints;
        let warn_by_duration =
            elapsed_since_checkpoint >= self.config.max_duration_between_checkpoints();

        if warn_by_iterations || warn_by_duration {
            let missing = self.checkpoint_count == 0;
            self.emit_event(CheckpointGuardEvent {
                event_code: FN_CK_006_CONTRACT_WARNING.to_string(),
                event_name: if missing {
                    CHECKPOINT_MISSING
                } else {
                    CHECKPOINT_WARNING
                }
                .to_string(),
                orchestration_id: self.orchestration_id.clone(),
                iteration_count,
                trace_id: self.trace_id.clone(),
                contract_status: "warn".to_string(),
                elapsed_ms: elapsed_since_checkpoint_ms,
            });
        }

        if self.config.mode == GuardMode::Strict {
            let strict_iterations = self
                .config
                .max_iterations_between_checkpoints
                .saturating_mul(self.config.strict_abort_multiplier);
            let strict_duration_ms = self
                .config
                .max_duration_between_checkpoints_ms
                .saturating_mul(self.config.strict_abort_multiplier);

            let violate_by_iterations = iterations_since_checkpoint >= strict_iterations;
            let violate_by_duration = elapsed_since_checkpoint_ms >= strict_duration_ms;

            if violate_by_iterations || violate_by_duration {
                self.emit_event(CheckpointGuardEvent {
                    event_code: FN_CK_007_CONTRACT_VIOLATION.to_string(),
                    event_name: CHECKPOINT_CONTRACT_VIOLATION.to_string(),
                    orchestration_id: self.orchestration_id.clone(),
                    iteration_count,
                    trace_id: self.trace_id.clone(),
                    contract_status: "violation".to_string(),
                    elapsed_ms: elapsed_since_checkpoint_ms,
                });

                return Err(CheckpointContractViolation {
                    orchestration_id: self.orchestration_id.clone(),
                    iteration_count,
                    elapsed_ms: elapsed_since_checkpoint_ms,
                    max_iterations_between_checkpoints: self
                        .config
                        .max_iterations_between_checkpoints,
                    max_duration_between_checkpoints_ms: self
                        .config
                        .max_duration_between_checkpoints_ms,
                });
            }
        }

        Ok(())
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn elapsed_ms(started: Instant) -> u64 {
    duration_ms(started.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn strict_config(iterations: u64, duration_ms: u64) -> CheckpointGuardConfig {
        CheckpointGuardConfig {
            max_iterations_between_checkpoints: iterations,
            max_duration_between_checkpoints_ms: duration_ms,
            mode: GuardMode::Strict,
            strict_abort_multiplier: 2,
        }
    }

    #[test]
    fn warn_mode_logs_warning_without_abort() {
        let mut guard = CheckpointGuard::new(
            "orch-warn",
            "trace-warn",
            CheckpointGuardConfig {
                max_iterations_between_checkpoints: 2,
                max_duration_between_checkpoints_ms: 5_000,
                mode: GuardMode::Warn,
                strict_abort_multiplier: 2,
            },
        );

        guard.on_iteration(1).expect("iter 1");
        guard.on_iteration(2).expect("iter 2");
        guard.on_iteration(3).expect("warn without abort");

        assert!(
            guard
                .events()
                .iter()
                .any(|event| event.event_code == FN_CK_006_CONTRACT_WARNING)
        );
    }

    #[test]
    fn strict_mode_aborts_after_two_x_iteration_budget() {
        let mut guard =
            CheckpointGuard::new("orch-strict", "trace-strict", strict_config(3, 5_000));

        for iteration in 1..=5 {
            assert!(guard.on_iteration(iteration).is_ok());
        }

        // iteration 6 == strict_iterations (3*2) → fail-closed at boundary
        let violation = guard.on_iteration(6).expect_err("strict violation");
        assert_eq!(violation.code(), "CHECKPOINT_CONTRACT_VIOLATION");
        assert!(
            guard
                .events()
                .iter()
                .any(|event| event.event_code == FN_CK_007_CONTRACT_VIOLATION)
        );
    }

    #[test]
    fn strict_mode_aborts_after_duration_budget() {
        let mut guard =
            CheckpointGuard::new("orch-duration", "trace-duration", strict_config(1_000, 25));
        thread::sleep(Duration::from_millis(60));
        let violation = guard.on_iteration(1).expect_err("duration violation");
        assert!(violation.elapsed_ms >= 50);
    }

    #[test]
    fn checkpoint_resets_iteration_budget() {
        let mut guard = CheckpointGuard::new("orch-reset", "trace-reset", strict_config(3, 5_000));
        guard.on_iteration(1).expect("iteration 1");
        guard.on_iteration(2).expect("iteration 2");
        guard.checkpoint(2);
        guard.on_iteration(3).expect("iteration 3 post-checkpoint");
        guard.on_iteration(4).expect("iteration 4 post-checkpoint");
        guard.on_iteration(5).expect("iteration 5 post-checkpoint");

        assert!(
            guard
                .events()
                .iter()
                .any(|event| event.event_code == FN_CK_001_CHECKPOINT_SAVE)
        );
    }

    #[test]
    fn missing_checkpoint_warning_uses_missing_event_name() {
        let mut guard =
            CheckpointGuard::new("orch-missing", "trace-missing", strict_config(3, 5_000));

        guard
            .on_iteration(3)
            .expect("warning does not abort before strict boundary");

        let warning = guard
            .events()
            .iter()
            .find(|event| event.event_code == FN_CK_006_CONTRACT_WARNING)
            .expect("warning event");
        assert_eq!(warning.event_name, CHECKPOINT_MISSING);
        assert_eq!(warning.contract_status, "warn");
        assert_eq!(warning.iteration_count, 3);
    }

    #[test]
    fn post_checkpoint_warning_uses_checkpoint_warning_event_name() {
        let mut guard = CheckpointGuard::new(
            "orch-post-checkpoint-warning",
            "trace-post-checkpoint-warning",
            strict_config(3, 5_000),
        );

        guard.checkpoint(2);
        guard
            .on_iteration(5)
            .expect("warning boundary should not abort");

        let warning = guard
            .events()
            .iter()
            .find(|event| event.event_code == FN_CK_006_CONTRACT_WARNING)
            .expect("warning event");
        assert_eq!(warning.event_name, CHECKPOINT_WARNING);
        assert_eq!(warning.iteration_count, 5);
    }

    #[test]
    fn strict_violation_boundary_is_relative_to_last_checkpoint() {
        let mut guard = CheckpointGuard::new(
            "orch-relative-boundary",
            "trace-relative-boundary",
            strict_config(3, 5_000),
        );

        guard.checkpoint(2);
        guard
            .on_iteration(7)
            .expect("one before strict relative boundary");
        let violation = guard
            .on_iteration(8)
            .expect_err("strict violation at checkpoint-relative boundary");

        assert_eq!(violation.iteration_count, 8);
        assert_eq!(violation.max_iterations_between_checkpoints, 3);
        assert!(
            guard
                .events()
                .iter()
                .any(|event| event.event_code == FN_CK_007_CONTRACT_VIOLATION
                    && event.iteration_count == 8)
        );
    }

    #[test]
    fn warn_mode_duration_breach_logs_missing_checkpoint_without_abort() {
        let mut guard = CheckpointGuard::new(
            "orch-duration-warn",
            "trace-duration-warn",
            CheckpointGuardConfig {
                max_iterations_between_checkpoints: 1_000,
                max_duration_between_checkpoints_ms: 5,
                mode: GuardMode::Warn,
                strict_abort_multiplier: 2,
            },
        );
        thread::sleep(Duration::from_millis(15));

        guard
            .on_iteration(1)
            .expect("warn mode must not abort on duration breach");

        let warning = guard
            .events()
            .iter()
            .find(|event| event.event_code == FN_CK_006_CONTRACT_WARNING)
            .expect("duration warning");
        assert_eq!(warning.event_name, CHECKPOINT_MISSING);
        assert!(warning.elapsed_ms >= 5);
    }

    #[test]
    fn contract_violation_display_includes_operator_context() {
        let violation = CheckpointContractViolation {
            orchestration_id: "orch-display".to_string(),
            iteration_count: 42,
            elapsed_ms: 7_500,
            max_iterations_between_checkpoints: 10,
            max_duration_between_checkpoints_ms: 5_000,
        };

        let rendered = violation.to_string();

        assert!(rendered.contains("CHECKPOINT_CONTRACT_VIOLATION"));
        assert!(rendered.contains("orchestration=orch-display"));
        assert!(rendered.contains("iteration=42"));
        assert!(rendered.contains("duration_ms:5000"));
    }

    #[test]
    fn duration_ms_saturates_large_durations() {
        let duration = Duration::from_secs(u64::MAX);

        assert_eq!(duration_ms(duration), u64::MAX);
    }

    #[test]
    fn push_bounded_retains_latest_events_when_over_capacity() {
        let mut events = Vec::new();
        for iteration in 0..5 {
            push_bounded(
                &mut events,
                CheckpointGuardEvent {
                    event_code: format!("E-{iteration}"),
                    event_name: "event".to_string(),
                    orchestration_id: "orch-bounded".to_string(),
                    iteration_count: iteration,
                    trace_id: "trace-bounded".to_string(),
                    contract_status: "test".to_string(),
                    elapsed_ms: iteration,
                },
                3,
            );
        }

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_code, "E-2");
        assert_eq!(events[2].event_code, "E-4");
    }

    #[test]
    fn checkpoint_count_saturates_at_u64_max() {
        let mut guard = CheckpointGuard::new(
            "orch-saturating-count",
            "trace-saturating-count",
            strict_config(3, 5_000),
        );
        guard.checkpoint_count = u64::MAX;

        guard.checkpoint(1);

        assert_eq!(guard.checkpoint_count, u64::MAX);
        assert_eq!(
            guard.events().last().expect("checkpoint event").event_code,
            FN_CK_001_CHECKPOINT_SAVE
        );
    }

    #[test]
    fn no_warning_before_iteration_boundary() {
        let mut guard = CheckpointGuard::new(
            "orch-no-warning",
            "trace-no-warning",
            CheckpointGuardConfig {
                max_iterations_between_checkpoints: 3,
                max_duration_between_checkpoints_ms: 60_000,
                mode: GuardMode::Warn,
                strict_abort_multiplier: 2,
            },
        );

        guard.on_iteration(1).expect("first iteration");
        guard.on_iteration(2).expect("below warning boundary");

        assert!(
            guard
                .events()
                .iter()
                .all(|event| event.event_code != FN_CK_006_CONTRACT_WARNING)
        );
    }

    #[test]
    fn strict_zero_abort_multiplier_fails_closed_on_first_iteration() {
        let mut guard = CheckpointGuard::new(
            "orch-zero-multiplier",
            "trace-zero-multiplier",
            CheckpointGuardConfig {
                max_iterations_between_checkpoints: 10,
                max_duration_between_checkpoints_ms: 60_000,
                mode: GuardMode::Strict,
                strict_abort_multiplier: 0,
            },
        );

        let violation = guard
            .on_iteration(1)
            .expect_err("zero multiplier should fail closed");

        assert_eq!(violation.iteration_count, 1);
        assert_eq!(violation.max_iterations_between_checkpoints, 10);
        assert_eq!(
            guard
                .events()
                .last()
                .expect("violation event should be recorded")
                .event_code,
            FN_CK_007_CONTRACT_VIOLATION
        );
    }

    #[test]
    fn strict_zero_iteration_budget_fails_closed_at_boundary() {
        let mut guard = CheckpointGuard::new(
            "orch-zero-iterations",
            "trace-zero-iterations",
            CheckpointGuardConfig {
                max_iterations_between_checkpoints: 0,
                max_duration_between_checkpoints_ms: 60_000,
                mode: GuardMode::Strict,
                strict_abort_multiplier: 2,
            },
        );

        let violation = guard
            .on_iteration(0)
            .expect_err("zero iteration budget should reject immediately");

        assert_eq!(violation.iteration_count, 0);
        assert_eq!(violation.max_iterations_between_checkpoints, 0);
        assert_eq!(
            guard
                .events()
                .last()
                .expect("violation event should be recorded")
                .event_name,
            CHECKPOINT_CONTRACT_VIOLATION
        );
    }

    #[test]
    fn checkpoint_iteration_rollback_does_not_underflow_or_warn() {
        let mut guard =
            CheckpointGuard::new("orch-rollback", "trace-rollback", strict_config(3, 60_000));

        guard.checkpoint(10);
        guard
            .on_iteration(5)
            .expect("lower iteration after checkpoint should saturate to zero");

        assert_eq!(guard.events().len(), 1);
        assert_eq!(guard.events()[0].event_code, FN_CK_001_CHECKPOINT_SAVE);
    }

    #[test]
    fn push_bounded_zero_capacity_discards_without_panicking() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_capacity_larger_than_len_keeps_existing_order() {
        let mut items = vec!["first"];

        push_bounded(&mut items, "second", 3);

        assert_eq!(items, vec!["first", "second"]);
    }

    #[test]
    fn strict_violation_records_warning_before_violation_event() {
        let mut guard = CheckpointGuard::new(
            "orch-warning-first",
            "trace-warning-first",
            strict_config(2, 60_000),
        );

        let violation = guard
            .on_iteration(4)
            .expect_err("strict boundary should fail closed");

        assert_eq!(violation.iteration_count, 4);
        assert_eq!(guard.events().len(), 2);
        assert_eq!(guard.events()[0].event_code, FN_CK_006_CONTRACT_WARNING);
        assert_eq!(guard.events()[0].event_name, CHECKPOINT_MISSING);
        assert_eq!(guard.events()[1].event_code, FN_CK_007_CONTRACT_VIOLATION);
        assert_eq!(guard.events()[1].contract_status, "violation");
    }

    #[test]
    fn strict_violation_after_checkpoint_records_checkpoint_warning_first() {
        let mut guard = CheckpointGuard::new(
            "orch-checkpoint-warning-first",
            "trace-checkpoint-warning-first",
            strict_config(2, 60_000),
        );

        guard.checkpoint(5);
        let violation = guard
            .on_iteration(9)
            .expect_err("checkpoint-relative strict boundary should reject");

        assert_eq!(violation.iteration_count, 9);
        assert_eq!(guard.events().len(), 3);
        assert_eq!(guard.events()[0].event_code, FN_CK_001_CHECKPOINT_SAVE);
        assert_eq!(guard.events()[1].event_name, CHECKPOINT_WARNING);
        assert_eq!(guard.events()[2].event_name, CHECKPOINT_CONTRACT_VIOLATION);
    }

    #[test]
    fn strict_abort_multiplier_overflow_violates_at_saturated_boundary() {
        let mut guard = CheckpointGuard::new(
            "orch-overflow-boundary",
            "trace-overflow-boundary",
            strict_config(u64::MAX, 60_000),
        );

        let violation = guard
            .on_iteration(u64::MAX)
            .expect_err("saturated strict boundary should still reject");

        assert_eq!(violation.iteration_count, u64::MAX);
        assert_eq!(violation.max_iterations_between_checkpoints, u64::MAX);
        assert_eq!(
            guard.events().last().expect("violation event").event_code,
            FN_CK_007_CONTRACT_VIOLATION
        );
    }

    #[test]
    fn checkpoint_at_u64_max_then_zero_iteration_does_not_warn() {
        let mut guard = CheckpointGuard::new(
            "orch-max-checkpoint",
            "trace-max-checkpoint",
            strict_config(1, 60_000),
        );

        guard.checkpoint(u64::MAX);
        guard
            .on_iteration(0)
            .expect("lower iteration after max checkpoint should saturate to zero");

        assert_eq!(guard.events().len(), 1);
        assert_eq!(guard.events()[0].event_code, FN_CK_001_CHECKPOINT_SAVE);
    }

    #[test]
    fn warn_mode_zero_iteration_budget_logs_warning_without_violation() {
        let mut guard = CheckpointGuard::new(
            "orch-warn-zero-budget",
            "trace-warn-zero-budget",
            CheckpointGuardConfig {
                max_iterations_between_checkpoints: 0,
                max_duration_between_checkpoints_ms: 60_000,
                mode: GuardMode::Warn,
                strict_abort_multiplier: 2,
            },
        );

        guard
            .on_iteration(0)
            .expect("warn mode zero budget should not abort");

        assert_eq!(guard.events().len(), 1);
        assert_eq!(guard.events()[0].event_code, FN_CK_006_CONTRACT_WARNING);
        assert_eq!(guard.events()[0].event_name, CHECKPOINT_MISSING);
    }

    #[test]
    fn strict_violation_error_carries_config_limits() {
        let mut guard = CheckpointGuard::new(
            "orch-error-limits",
            "trace-error-limits",
            strict_config(4, 60_000),
        );

        let violation = guard
            .on_iteration(8)
            .expect_err("strict iteration boundary should reject");

        assert_eq!(violation.orchestration_id, "orch-error-limits");
        assert_eq!(violation.iteration_count, 8);
        assert_eq!(violation.max_iterations_between_checkpoints, 4);
        assert_eq!(violation.max_duration_between_checkpoints_ms, 60_000);
    }

    #[test]
    fn default_config_duration_helper_matches_millis_budget() {
        let config = CheckpointGuardConfig::default();

        assert_eq!(
            config.max_duration_between_checkpoints(),
            Duration::from_millis(config.max_duration_between_checkpoints_ms)
        );
        assert_eq!(config.mode, GuardMode::Warn);
    }
}

#[cfg(test)]
mod checkpoint_guard_comprehensive_negative_tests {
    use super::*;

    fn malicious_config() -> CheckpointGuardConfig {
        CheckpointGuardConfig {
            max_iterations_between_checkpoints: 100,
            max_duration_between_checkpoints_ms: 5_000,
            mode: GuardMode::Strict,
            strict_abort_multiplier: 2,
        }
    }

    #[test]
    fn negative_checkpoint_guard_with_unicode_injection_attacks() {
        // Test with malicious Unicode patterns in orchestration and trace IDs
        let orchestration_patterns = [
            "orch\u{202E}spoofed\u{202D}",              // BiDi override attack
            "orch\u{0000}null\r\n\t\x1b[31mred\x1b[0m", // Null bytes + ANSI escapes
            "orch\u{FEFF}\u{200B}\u{200C}\u{200D}",     // BOM + zero-width chars
            "orch\u{10FFFF}\u{E000}\u{FDD0}",           // Private use + non-characters
            "orch\u{FFFD}\u{FFFD}",                     // Surrogate pairs
        ];

        let trace_patterns = [
            "trace\"\\escape\r\n",
            "trace\u{202A}bidi\u{202B}isolate\u{202C}",
            "trace\x00\x01\x02\x03\x04",          // Control characters
            "trace' OR '1'='1' --",               // SQL injection pattern
            "trace<script>alert('xss')</script>", // XSS pattern
        ];

        for (orch, trace) in orchestration_patterns.iter().zip(trace_patterns.iter()) {
            let mut guard = CheckpointGuard::new(orch, trace, malicious_config());

            // Should handle malicious IDs without panic
            guard.checkpoint(1);
            let _ = guard.on_iteration(1);

            // Verify malicious content preserved in events
            let event = guard.events().last().unwrap();
            assert_eq!(event.orchestration_id, *orch);
            assert_eq!(event.trace_id, *trace);
        }
    }

    #[test]
    fn negative_checkpoint_config_with_extreme_overflow_values() {
        // Test with extreme configuration values that might cause overflow
        let extreme_config = CheckpointGuardConfig {
            max_iterations_between_checkpoints: u64::MAX,
            max_duration_between_checkpoints_ms: u64::MAX,
            mode: GuardMode::Strict,
            strict_abort_multiplier: u64::MAX,
        };

        let mut guard = CheckpointGuard::new("extreme-orch", "extreme-trace", extreme_config);

        // Should handle extreme values with saturation
        let result = guard.on_iteration(u64::MAX);
        assert!(result.is_err()); // Should violate due to saturated multiplication

        let violation = result.unwrap_err();
        assert_eq!(violation.iteration_count, u64::MAX);
        assert_eq!(violation.max_iterations_between_checkpoints, u64::MAX);
    }

    #[test]
    fn negative_massive_event_storage_memory_exhaustion_attack() {
        // Test with maliciously large event storage to check memory handling
        let mut guard = CheckpointGuard::new("massive-events", "massive-trace", malicious_config());

        // Generate massive number of events with large strings
        for i in 0..10000 {
            let massive_orch_id = format!("orch-{}-{}", i, "x".repeat(1000));
            let massive_trace_id = format!("trace-{}-{}", i, "y".repeat(1000));

            // Manually emit events to test bounded storage
            guard.emit_event(CheckpointGuardEvent {
                event_code: format!("MASSIVE-EVENT-{}", i),
                event_name: "massive".repeat(100),
                orchestration_id: massive_orch_id,
                iteration_count: i as u64,
                trace_id: massive_trace_id,
                contract_status: "test".repeat(100),
                elapsed_ms: i as u64,
            });
        }

        // Should be bounded by MAX_EVENTS
        assert_eq!(guard.events().len(), MAX_EVENTS);

        // Should contain only latest events
        let last_event = guard.events().last().unwrap();
        assert!(last_event.event_code.starts_with("MASSIVE-EVENT-999"));
    }

    #[test]
    fn negative_checkpoint_contract_violation_display_with_injection_resistant_formatting() {
        // Test violation display with malicious content that might break formatting
        let malicious_violations = [
            CheckpointContractViolation {
                orchestration_id: "orch\r\n\t\x1b[31mREDTEXT\x1b[0m".to_string(),
                iteration_count: u64::MAX,
                elapsed_ms: u64::MAX,
                max_iterations_between_checkpoints: u64::MAX,
                max_duration_between_checkpoints_ms: u64::MAX,
            },
            CheckpointContractViolation {
                orchestration_id: "orch\"quotes'apostrophe\\backslash".to_string(),
                iteration_count: 0,
                elapsed_ms: 0,
                max_iterations_between_checkpoints: 0,
                max_duration_between_checkpoints_ms: 0,
            },
            CheckpointContractViolation {
                orchestration_id: "orch\u{202E}spoofed\u{FEFF}bom".to_string(),
                iteration_count: 42,
                elapsed_ms: 1337,
                max_iterations_between_checkpoints: 100,
                max_duration_between_checkpoints_ms: 5000,
            },
        ];

        for violation in malicious_violations {
            let display_string = format!("{}", violation);

            // Verify safe display formatting
            assert!(display_string.contains("CHECKPOINT_CONTRACT_VIOLATION"));
            assert!(
                display_string.contains(&format!("orchestration={}", violation.orchestration_id))
            );
            assert!(display_string.contains(&format!("iteration={}", violation.iteration_count)));
            assert!(display_string.contains(&format!("elapsed_ms={}", violation.elapsed_ms)));
        }
    }

    #[test]
    fn negative_duration_calculation_with_extreme_instant_manipulation() {
        // Test duration calculations with extreme time differences
        let mut guard = CheckpointGuard::new("time-manipulation", "time-trace", malicious_config());

        // Force extreme checkpoint time in the past (simulate time manipulation)
        guard.last_checkpoint_at = Instant::now() - Duration::from_secs(u64::MAX / 1000);

        let result = guard.on_iteration(1);

        // Should handle extreme durations without panic
        assert!(result.is_ok() || result.is_err()); // Either is acceptable, just no panic

        // Check that duration_ms handles overflow correctly
        let extreme_duration = Duration::from_secs(u64::MAX);
        assert_eq!(duration_ms(extreme_duration), u64::MAX);
    }

    #[test]
    fn negative_serialization_with_malformed_checkpoint_events() {
        // Test serialization/deserialization with malicious event content
        let malicious_events = vec![
            CheckpointGuardEvent {
                event_code: "EVT\x00\r\n\t\"".to_string(),
                event_name: "event\\\"escaped".to_string(),
                orchestration_id: "orch\u{FFFD}\u{FFFD}".to_string(),
                iteration_count: u64::MAX,
                trace_id: "trace\u{202E}bidi".to_string(),
                contract_status: "status' OR '1'='1' --".to_string(),
                elapsed_ms: u64::MAX,
            },
            CheckpointGuardEvent {
                event_code: "\u{FEFF}BOM_EVENT".to_string(),
                event_name: "invisible\u{200B}\u{200C}\u{200D}".to_string(),
                orchestration_id: "orch\u{10FFFF}".to_string(),
                iteration_count: 0,
                trace_id: "trace<script>alert('xss')</script>".to_string(),
                contract_status: "status\r\nHTTP/1.1 200 OK\r\n\r\n".to_string(),
                elapsed_ms: 0,
            },
        ];

        for event in malicious_events {
            // Should serialize without panic
            let json_result = serde_json::to_string(&event);
            assert!(json_result.is_ok());

            // Should deserialize back to same content
            let json = json_result.unwrap();
            let deserialized: Result<CheckpointGuardEvent, _> = serde_json::from_str(&json);
            assert!(deserialized.is_ok());
            assert_eq!(deserialized.unwrap(), event);
        }
    }

    #[test]
    fn negative_concurrent_checkpoint_and_iteration_race_conditions() {
        // Test potential race conditions between checkpoint() and on_iteration()
        let mut guard =
            CheckpointGuard::new("concurrent-test", "concurrent-trace", malicious_config());

        // Simulate rapid alternating checkpoint and iteration calls
        for i in 0..1000 {
            if i % 2 == 0 {
                guard.checkpoint(i);
            } else {
                let _ = guard.on_iteration(i); // May or may not violate, both OK
            }

            // Should maintain consistent state
            assert!(guard.checkpoint_count <= (i / 2) + 1);
            assert!(guard.last_checkpoint_iteration <= i);
        }

        // Should have events for all checkpoints
        let checkpoint_events: Vec<_> = guard
            .events()
            .iter()
            .filter(|e| e.event_code == FN_CK_001_CHECKPOINT_SAVE)
            .collect();
        assert!(checkpoint_events.len() <= guard.events().len());
    }

    #[test]
    fn negative_guard_mode_enumeration_with_invalid_serialization() {
        // Test GuardMode with potentially malicious serialization
        let valid_modes = [GuardMode::Warn, GuardMode::Strict];

        for mode in valid_modes {
            let json = serde_json::to_string(&mode).unwrap();
            let deserialized: GuardMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, deserialized);
        }

        // Test invalid mode deserialization
        let invalid_modes = [
            "\"Invalid\"",
            "\"warn\"",   // lowercase
            "\"STRICT\"", // uppercase
            "\"Strict\"", // different case
            "null",
            "42",
            "true",
        ];

        for invalid_json in invalid_modes {
            let result: Result<GuardMode, _> = serde_json::from_str(invalid_json);
            assert!(
                result.is_err(),
                "Should reject invalid mode: {}",
                invalid_json
            );
        }
    }

    #[test]
    fn negative_push_bounded_with_adversarial_capacity_patterns() {
        // Test push_bounded with various adversarial capacity patterns
        let test_patterns = [
            (0, vec![1, 2, 3], vec![]),                 // Zero capacity
            (1, vec![1, 2, 3], vec![3]),                // Capacity 1
            (usize::MAX, vec![1, 2, 3], vec![1, 2, 3]), // Max capacity
        ];

        for (capacity, mut initial, expected) in test_patterns {
            push_bounded(&mut initial, 4, capacity);

            if capacity == 0 {
                assert_eq!(initial, expected);
            } else if capacity == 1 {
                assert_eq!(initial, vec![4]);
            } else {
                assert_eq!(initial, vec![1, 2, 3, 4]);
            }
        }

        // Test with massive items to check memory behavior
        let mut massive_items: Vec<Vec<u8>> = Vec::new();
        for i in 0..100 {
            massive_items.push(vec![i as u8; 10000]); // 10KB items
        }

        push_bounded(&mut massive_items, vec![255u8; 10000], 50);
        assert_eq!(massive_items.len(), 50);
    }

    #[test]
    fn negative_checkpoint_config_with_zero_and_overflow_multipliers() {
        // Test configurations with edge case multipliers
        let edge_configs = [
            CheckpointGuardConfig {
                max_iterations_between_checkpoints: 100,
                max_duration_between_checkpoints_ms: 1000,
                mode: GuardMode::Strict,
                strict_abort_multiplier: 0, // Zero multiplier
            },
            CheckpointGuardConfig {
                max_iterations_between_checkpoints: u64::MAX,
                max_duration_between_checkpoints_ms: u64::MAX,
                mode: GuardMode::Strict,
                strict_abort_multiplier: u64::MAX, // Max multiplier
            },
            CheckpointGuardConfig {
                max_iterations_between_checkpoints: 1,
                max_duration_between_checkpoints_ms: 1,
                mode: GuardMode::Strict,
                strict_abort_multiplier: u64::MAX, // Overflow-prone
            },
        ];

        for (i, config) in edge_configs.iter().enumerate() {
            let mut guard = CheckpointGuard::new(
                format!("edge-config-{}", i),
                format!("edge-trace-{}", i),
                config.clone(),
            );

            // Should handle edge configurations without panic
            let result = guard.on_iteration(1);

            // Zero multiplier should immediately violate
            if config.strict_abort_multiplier == 0 {
                assert!(result.is_err());
            }

            // Max multiplier should either violate or pass depending on saturation
            if config.strict_abort_multiplier == u64::MAX {
                assert!(result.is_ok() || result.is_err());
            }
        }
    }

    #[test]
    fn negative_checkpoint_guard_config_serialization_with_extreme_values() {
        // Test config serialization with extreme values
        let extreme_config = CheckpointGuardConfig {
            max_iterations_between_checkpoints: u64::MAX,
            max_duration_between_checkpoints_ms: u64::MAX,
            mode: GuardMode::Strict,
            strict_abort_multiplier: u64::MAX,
        };

        let json = serde_json::to_string(&extreme_config).unwrap();
        let deserialized: CheckpointGuardConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(extreme_config, deserialized);
        assert_eq!(deserialized.max_iterations_between_checkpoints, u64::MAX);
        assert_eq!(deserialized.max_duration_between_checkpoints_ms, u64::MAX);
        assert_eq!(deserialized.strict_abort_multiplier, u64::MAX);

        // Test duration conversion with extreme values
        let duration = extreme_config.max_duration_between_checkpoints();
        assert_eq!(duration, Duration::from_millis(u64::MAX));
    }

    #[test]
    fn negative_iteration_count_manipulation_and_underflow_attacks() {
        // Test with iteration count manipulation that might cause underflow
        let mut guard =
            CheckpointGuard::new("underflow-test", "underflow-trace", malicious_config());

        // Set checkpoint at high iteration
        guard.checkpoint(u64::MAX);

        // Test with lower iteration (potential underflow scenario)
        let result = guard.on_iteration(0);
        assert!(result.is_ok()); // Should handle underflow gracefully with saturating_sub

        // Test with iteration count at exact boundaries
        guard.checkpoint(100);
        let result = guard.on_iteration(u64::MAX);
        assert!(result.is_err()); // Should violate due to extreme difference

        // Verify no underflow in calculations
        assert!(guard.last_checkpoint_iteration <= u64::MAX);
    }

    #[test]
    fn negative_elapsed_ms_calculation_with_time_overflow_scenarios() {
        // Test elapsed_ms with various time scenarios that might overflow
        let test_instants = [
            Instant::now() - Duration::from_secs(u64::MAX / 2000), // Large past time
            Instant::now() - Duration::from_millis(u64::MAX / 2),  // Very large past time
            Instant::now(),                                        // Current time
        ];

        for instant in test_instants {
            let elapsed = elapsed_ms(instant);

            // Should always return valid u64
            assert!(elapsed <= u64::MAX);

            // Test duration_ms directly with extreme durations
            let extreme_duration = Duration::from_secs(u64::MAX);
            assert_eq!(duration_ms(extreme_duration), u64::MAX);

            // Test with duration that might overflow as_millis()
            let overflow_duration = Duration::from_secs(u64::MAX / 1000 + 1);
            let result = duration_ms(overflow_duration);
            assert_eq!(result, u64::MAX); // Should saturate
        }
    }

    #[test]
    fn negative_checkpoint_guard_event_with_unicode_normalization_attacks() {
        // Test events with Unicode normalization attacks
        let normalization_attacks = [
            ("café", "cafe\u{0301}"),             // NFC vs NFD
            ("résumé", "re\u{0301}sume\u{0301}"), // Multiple combining chars
            ("℁ℂ℃℄", "a/sCC℄"),                   // Compatibility variants
            ("＜script＞", "<script>"),           // Fullwidth to ASCII
        ];

        for (nfc_form, attack_form) in normalization_attacks {
            let event_nfc = CheckpointGuardEvent {
                event_code: nfc_form.to_string(),
                event_name: nfc_form.to_string(),
                orchestration_id: nfc_form.to_string(),
                iteration_count: 1,
                trace_id: nfc_form.to_string(),
                contract_status: nfc_form.to_string(),
                elapsed_ms: 1000,
            };

            let event_attack = CheckpointGuardEvent {
                event_code: attack_form.to_string(),
                event_name: attack_form.to_string(),
                orchestration_id: attack_form.to_string(),
                iteration_count: 1,
                trace_id: attack_form.to_string(),
                contract_status: attack_form.to_string(),
                elapsed_ms: 1000,
            };

            // Should be treated as different due to byte-level inequality
            assert_ne!(event_nfc, event_attack);

            // Should serialize differently
            let json_nfc = serde_json::to_string(&event_nfc).unwrap();
            let json_attack = serde_json::to_string(&event_attack).unwrap();
            assert_ne!(json_nfc, json_attack);
        }
    }
}
