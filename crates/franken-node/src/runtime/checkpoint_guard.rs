//! bd-93k: checkpoint-placement contract guard for long orchestration loops.

use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

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

    /// Record that a checkpoint was written at the given iteration.
    pub fn checkpoint(&mut self, iteration_count: u64) {
        self.last_checkpoint_iteration = iteration_count;
        self.last_checkpoint_at = Instant::now();
        self.checkpoint_count = self.checkpoint_count.saturating_add(1);

        self.events.push(CheckpointGuardEvent {
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
            iterations_since_checkpoint > self.config.max_iterations_between_checkpoints;
        let warn_by_duration =
            elapsed_since_checkpoint > self.config.max_duration_between_checkpoints();

        if warn_by_iterations || warn_by_duration {
            let missing = self.checkpoint_count == 0;
            self.events.push(CheckpointGuardEvent {
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

            let violate_by_iterations = iterations_since_checkpoint > strict_iterations;
            let violate_by_duration = elapsed_since_checkpoint_ms > strict_duration_ms;

            if violate_by_iterations || violate_by_duration {
                self.events.push(CheckpointGuardEvent {
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

        for iteration in 1..=6 {
            assert!(guard.on_iteration(iteration).is_ok());
        }

        let violation = guard.on_iteration(7).expect_err("strict violation");
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
}
