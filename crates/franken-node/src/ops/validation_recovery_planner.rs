//! Deterministic validation recovery planner for RCH failures.
//!
//! This module implements `bd-8yjv9` to turn a classified failed or stalled
//! validation attempt into a deterministic next action so agents do not improvise
//! inconsistent retries.
//!
//! The recovery planner takes inputs including recorder timeline, RchAdapterOutcome,
//! validation broker request/receipt/status, proof priority, bead priority, capacity
//! snapshot, dirty-state policy, and timeout budget, then emits stable decisions
//! that are deterministic for identical inputs.

use crate::ops::rch_adapter::{
    RchAdapterOutcome, RchExecutionMode, RchOutcomeClass, RchTimeoutClass,
};
use crate::ops::validation_broker::{
    FlightRecorderAdapterOutcome, FlightRecorderAdapterOutcomeClass, FlightRecorderObservation,
};
use crate::security::constant_time;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const RECOVERY_PLANNER_SCHEMA_VERSION: &str = "franken-node/validation-recovery-planner/v1";
pub const DEFAULT_MAX_RETRY_ATTEMPTS: u32 = 3;
pub const DEFAULT_MAX_WORKER_DIVERSITY: u32 = 2;
pub const DEFAULT_TIMEOUT_BUDGET_MS: u64 = 1_800_000; // 30 minutes
pub const DEFAULT_MAX_QUEUE_AGE_MS: u64 = 3_600_000; // 1 hour

pub mod event_codes {
    pub const RECOVERY_PLAN_GENERATED: &str = "VRP-001";
    pub const RECOVERY_PLAN_RETRY_SCHEDULED: &str = "VRP-002";
    pub const RECOVERY_PLAN_QUEUE_DEFERRED: &str = "VRP-003";
    pub const RECOVERY_PLAN_FAIL_CLOSED: &str = "VRP-004";
    pub const RECOVERY_PLAN_SOURCE_ONLY_BLOCKER: &str = "VRP-005";
}

pub mod reason_codes {
    pub const RETRY_REMOTE_SAME_WORKER: &str = "RETRY_REMOTE_SAME_WORKER";
    pub const RETRY_REMOTE_DIFFERENT_WORKER: &str = "RETRY_REMOTE_DIFFERENT_WORKER";
    pub const QUEUE_UNTIL_CAPACITY: &str = "QUEUE_UNTIL_CAPACITY";
    pub const DRAIN_WORKER_THEN_RETRY: &str = "DRAIN_WORKER_THEN_RETRY";
    pub const WAIT_FOR_EXISTING_PROOF: &str = "WAIT_FOR_EXISTING_PROOF";
    pub const USE_SOURCE_ONLY_BLOCKER: &str = "USE_SOURCE_ONLY_BLOCKER";
    pub const FAIL_CLOSED: &str = "FAIL_CLOSED";
    pub const NO_RECOVERY_NEEDED: &str = "NO_RECOVERY_NEEDED";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// Retry on the same worker (transient failure)
    RetryRemoteSameWorker,
    /// Retry on a different worker (worker-specific issue)
    RetryRemoteDifferentWorker,
    /// Queue until capacity becomes available
    QueueUntilCapacity,
    /// Drain the problematic worker then retry
    DrainWorkerThenRetry,
    /// Wait for existing equivalent proof to complete
    WaitForExistingProof,
    /// Use source-only blocker (no remote validation possible)
    UseSourceOnlyBlocker,
    /// Fail closed (unrecoverable failure)
    FailClosed,
    /// No recovery needed (success case)
    NoRecoveryNeeded,
}

impl RecoveryAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetryRemoteSameWorker => "retry_remote_same_worker",
            Self::RetryRemoteDifferentWorker => "retry_remote_different_worker",
            Self::QueueUntilCapacity => "queue_until_capacity",
            Self::DrainWorkerThenRetry => "drain_worker_then_retry",
            Self::WaitForExistingProof => "wait_for_existing_proof",
            Self::UseSourceOnlyBlocker => "use_source_only_blocker",
            Self::FailClosed => "fail_closed",
            Self::NoRecoveryNeeded => "no_recovery_needed",
        }
    }

    #[must_use]
    pub const fn is_retry(self) -> bool {
        matches!(
            self,
            Self::RetryRemoteSameWorker | Self::RetryRemoteDifferentWorker
        )
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::FailClosed | Self::NoRecoveryNeeded | Self::UseSourceOnlyBlocker
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofPriority {
    pub bead_priority: u8,
    pub proof_priority: u8,
}

impl ProofPriority {
    #[must_use]
    pub const fn is_high_priority(self) -> bool {
        self.bead_priority <= 1 || self.proof_priority <= 1
    }

    #[must_use]
    pub fn combined_score(self) -> u16 {
        u16::from(self.bead_priority).saturating_add(u16::from(self.proof_priority))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacitySnapshot {
    pub available_workers: u32,
    pub active_cargo_processes: u32,
    pub max_cargo_processes: u32,
    pub rch_queue_depth: u32,
    pub max_queue_depth: u32,
}

impl CapacitySnapshot {
    #[must_use]
    pub fn has_worker_capacity(&self) -> bool {
        self.available_workers > 0
    }

    #[must_use]
    pub fn has_cargo_capacity(&self) -> bool {
        self.active_cargo_processes < self.max_cargo_processes
    }

    #[must_use]
    pub fn has_queue_capacity(&self) -> bool {
        self.rch_queue_depth < self.max_queue_depth
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPlannerInput {
    pub schema_version: String,
    pub request_id: String,
    pub trace_id: String,
    pub rch_outcome: RchAdapterOutcome,
    pub flight_recorder_observations: Vec<FlightRecorderObservation>,
    pub proof_priority: ProofPriority,
    pub capacity_snapshot: Option<CapacitySnapshot>,
    pub attempt_count: u32,
    pub worker_diversity_count: u32,
    pub timeout_budget_remaining_ms: u64,
    pub queue_age_ms: u64,
    pub dirty_state_policy: DirtyStatePolicy,
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirtyStatePolicy {
    /// Allow local fallback for dirty working directories
    AllowLocalFallback,
    /// Require clean state for all validation
    RequireCleanState,
    /// Source-only validation for dirty state
    SourceOnlyForDirty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryDecision {
    pub schema_version: String,
    pub request_id: String,
    pub trace_id: String,
    pub action: RecoveryAction,
    pub reason_code: String,
    pub event_code: String,
    pub operator_message: String,
    pub required_action: String,
    pub fail_closed: bool,
    pub freshness_timestamp_ms: u64,
    pub retry_after_ms: Option<u64>,
    pub worker_preference: Option<String>,
    pub decision_digest: String,
}

impl RecoveryDecision {
    fn new(
        input: &RecoveryPlannerInput,
        action: RecoveryAction,
        reason_code: &str,
        operator_message: String,
        required_action: String,
        retry_after_ms: Option<u64>,
        worker_preference: Option<String>,
    ) -> Result<Self, RecoveryPlannerError> {
        let event_code = match action {
            RecoveryAction::NoRecoveryNeeded => event_codes::RECOVERY_PLAN_GENERATED,
            RecoveryAction::RetryRemoteSameWorker | RecoveryAction::RetryRemoteDifferentWorker => {
                event_codes::RECOVERY_PLAN_RETRY_SCHEDULED
            }
            RecoveryAction::QueueUntilCapacity | RecoveryAction::WaitForExistingProof => {
                event_codes::RECOVERY_PLAN_QUEUE_DEFERRED
            }
            RecoveryAction::FailClosed => event_codes::RECOVERY_PLAN_FAIL_CLOSED,
            RecoveryAction::UseSourceOnlyBlocker => event_codes::RECOVERY_PLAN_SOURCE_ONLY_BLOCKER,
            RecoveryAction::DrainWorkerThenRetry => event_codes::RECOVERY_PLAN_RETRY_SCHEDULED,
        };

        let fail_closed = matches!(action, RecoveryAction::FailClosed);

        let decision_digest = compute_decision_digest(
            &input.request_id,
            &action,
            reason_code,
            &operator_message,
            retry_after_ms,
            &worker_preference,
        )?;

        Ok(Self {
            schema_version: RECOVERY_PLANNER_SCHEMA_VERSION.to_string(),
            request_id: input.request_id.clone(),
            trace_id: input.trace_id.clone(),
            action,
            reason_code: reason_code.to_string(),
            event_code: event_code.to_string(),
            operator_message,
            required_action,
            fail_closed,
            freshness_timestamp_ms: input.now_ms,
            retry_after_ms,
            worker_preference,
            decision_digest,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryPlannerError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Digest computation failed: {0}")]
    DigestError(String),
}

pub struct ValidationRecoveryPlanner {
    config: RecoveryPlannerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPlannerConfig {
    pub max_retry_attempts: u32,
    pub max_worker_diversity: u32,
    pub timeout_budget_ms: u64,
    pub max_queue_age_ms: u64,
    pub enable_priority_preemption: bool,
}

impl Default for RecoveryPlannerConfig {
    fn default() -> Self {
        Self {
            max_retry_attempts: DEFAULT_MAX_RETRY_ATTEMPTS,
            max_worker_diversity: DEFAULT_MAX_WORKER_DIVERSITY,
            timeout_budget_ms: DEFAULT_TIMEOUT_BUDGET_MS,
            max_queue_age_ms: DEFAULT_MAX_QUEUE_AGE_MS,
            enable_priority_preemption: true,
        }
    }
}

impl ValidationRecoveryPlanner {
    #[must_use]
    pub fn new(config: RecoveryPlannerConfig) -> Self {
        Self { config }
    }

    /// Generate a deterministic recovery decision for a failed validation attempt.
    pub fn plan_recovery(
        &self,
        input: &RecoveryPlannerInput,
    ) -> Result<RecoveryDecision, RecoveryPlannerError> {
        self.validate_input(input)?;

        // Success case - no recovery needed
        if input.rch_outcome.is_green() {
            return RecoveryDecision::new(
                input,
                RecoveryAction::NoRecoveryNeeded,
                reason_codes::NO_RECOVERY_NEEDED,
                "Validation completed successfully".to_string(),
                "Continue with proof verification".to_string(),
                None,
                None,
            );
        }

        // Check bounds first - fail closed if exceeded
        if self.should_fail_closed_on_bounds(input) {
            return self.create_fail_closed_decision(input, "Retry bounds exceeded");
        }

        // Handle different failure classes
        match input.rch_outcome.outcome {
            RchOutcomeClass::Passed => RecoveryDecision::new(
                input,
                RecoveryAction::NoRecoveryNeeded,
                reason_codes::NO_RECOVERY_NEEDED,
                "Validation passed".to_string(),
                "Continue processing".to_string(),
                None,
                None,
            ),
            RchOutcomeClass::CommandFailed
            | RchOutcomeClass::CompileFailed
            | RchOutcomeClass::TestFailed => {
                // Product failures should not be retried
                self.create_fail_closed_decision(
                    input,
                    "Product failure - compilation or test error",
                )
            }
            RchOutcomeClass::WorkerTimeout => self.handle_worker_timeout(input),
            RchOutcomeClass::WorkerMissingToolchain => self.handle_missing_toolchain(input),
            RchOutcomeClass::WorkerFilesystemError => self.handle_filesystem_error(input),
            RchOutcomeClass::LocalFallbackRefused => self.handle_local_fallback_refused(input),
            RchOutcomeClass::ContentionDeferred => self.handle_contention_deferred(input),
            RchOutcomeClass::BrokerInternalError => self.handle_broker_error(input),
        }
    }

    fn validate_input(&self, input: &RecoveryPlannerInput) -> Result<(), RecoveryPlannerError> {
        if input.request_id.is_empty() {
            return Err(RecoveryPlannerError::InvalidInput(
                "request_id cannot be empty".to_string(),
            ));
        }

        if input.trace_id.is_empty() {
            return Err(RecoveryPlannerError::InvalidInput(
                "trace_id cannot be empty".to_string(),
            ));
        }

        Ok(())
    }

    fn should_fail_closed_on_bounds(&self, input: &RecoveryPlannerInput) -> bool {
        input.attempt_count >= self.config.max_retry_attempts
            || input.worker_diversity_count >= self.config.max_worker_diversity
            || input.timeout_budget_remaining_ms == 0
            || input.queue_age_ms > self.config.max_queue_age_ms
    }

    fn create_fail_closed_decision(
        &self,
        input: &RecoveryPlannerInput,
        reason: &str,
    ) -> Result<RecoveryDecision, RecoveryPlannerError> {
        RecoveryDecision::new(
            input,
            RecoveryAction::FailClosed,
            reason_codes::FAIL_CLOSED,
            format!("Recovery failed: {}", reason),
            "Manual intervention required".to_string(),
            None,
            None,
        )
    }

    fn handle_worker_timeout(
        &self,
        input: &RecoveryPlannerInput,
    ) -> Result<RecoveryDecision, RecoveryPlannerError> {
        match input.rch_outcome.timeout_class {
            RchTimeoutClass::SshCommand | RchTimeoutClass::WorkerUnreachable => {
                // Worker connectivity issues - try different worker
                RecoveryDecision::new(
                    input,
                    RecoveryAction::RetryRemoteDifferentWorker,
                    reason_codes::RETRY_REMOTE_DIFFERENT_WORKER,
                    "Worker connectivity timeout - switching workers".to_string(),
                    "Retry on different worker".to_string(),
                    Some(30_000), // 30 second backoff
                    None,
                )
            }
            RchTimeoutClass::CargoTestTimeout | RchTimeoutClass::ProcessWall => {
                // Test or process timeout - might be transient, same worker okay
                RecoveryDecision::new(
                    input,
                    RecoveryAction::RetryRemoteSameWorker,
                    reason_codes::RETRY_REMOTE_SAME_WORKER,
                    "Test or process timeout - retrying".to_string(),
                    "Retry same validation".to_string(),
                    Some(60_000), // 1 minute backoff
                    input.rch_outcome.worker_id.clone(),
                )
            }
            RchTimeoutClass::ProcessIdle => {
                // Process went idle - likely worker issue
                RecoveryDecision::new(
                    input,
                    RecoveryAction::DrainWorkerThenRetry,
                    reason_codes::DRAIN_WORKER_THEN_RETRY,
                    "Process idle timeout - draining worker".to_string(),
                    "Drain worker and retry".to_string(),
                    Some(120_000), // 2 minute backoff
                    None,
                )
            }
            RchTimeoutClass::Unknown | RchTimeoutClass::None => {
                // Unknown timeout - conservative retry with different worker
                RecoveryDecision::new(
                    input,
                    RecoveryAction::RetryRemoteDifferentWorker,
                    reason_codes::RETRY_REMOTE_DIFFERENT_WORKER,
                    "Unknown timeout class - switching workers".to_string(),
                    "Retry on different worker".to_string(),
                    Some(45_000), // 45 second backoff
                    None,
                )
            }
        }
    }

    fn handle_missing_toolchain(
        &self,
        input: &RecoveryPlannerInput,
    ) -> Result<RecoveryDecision, RecoveryPlannerError> {
        // Missing toolchain is a worker configuration issue - try different worker
        RecoveryDecision::new(
            input,
            RecoveryAction::RetryRemoteDifferentWorker,
            reason_codes::RETRY_REMOTE_DIFFERENT_WORKER,
            "Worker missing required toolchain".to_string(),
            "Retry on worker with correct toolchain".to_string(),
            Some(15_000), // 15 second backoff
            None,
        )
    }

    fn handle_filesystem_error(
        &self,
        input: &RecoveryPlannerInput,
    ) -> Result<RecoveryDecision, RecoveryPlannerError> {
        // Filesystem errors could be worker-specific or systemic
        if input.attempt_count == 0 {
            // First attempt - try different worker
            RecoveryDecision::new(
                input,
                RecoveryAction::RetryRemoteDifferentWorker,
                reason_codes::RETRY_REMOTE_DIFFERENT_WORKER,
                "Filesystem error - trying different worker".to_string(),
                "Retry on different worker".to_string(),
                Some(30_000), // 30 second backoff
                None,
            )
        } else {
            // Multiple filesystem errors suggest systemic issue
            self.create_fail_closed_decision(input, "Persistent filesystem errors")
        }
    }

    fn handle_local_fallback_refused(
        &self,
        input: &RecoveryPlannerInput,
    ) -> Result<RecoveryDecision, RecoveryPlannerError> {
        match input.dirty_state_policy {
            DirtyStatePolicy::SourceOnlyForDirty => RecoveryDecision::new(
                input,
                RecoveryAction::UseSourceOnlyBlocker,
                reason_codes::USE_SOURCE_ONLY_BLOCKER,
                "Local fallback refused - using source-only validation".to_string(),
                "Switch to source-only validation mode".to_string(),
                None,
                None,
            ),
            DirtyStatePolicy::RequireCleanState => self.create_fail_closed_decision(
                input,
                "Local fallback refused and clean state required",
            ),
            DirtyStatePolicy::AllowLocalFallback => {
                // Policy conflict - local fallback should have been allowed
                RecoveryDecision::new(
                    input,
                    RecoveryAction::RetryRemoteSameWorker,
                    reason_codes::RETRY_REMOTE_SAME_WORKER,
                    "Local fallback unexpectedly refused - retrying remote".to_string(),
                    "Retry remote execution".to_string(),
                    Some(45_000), // 45 second backoff
                    input.rch_outcome.worker_id.clone(),
                )
            }
        }
    }

    fn handle_contention_deferred(
        &self,
        input: &RecoveryPlannerInput,
    ) -> Result<RecoveryDecision, RecoveryPlannerError> {
        // Check if we can queue or should use source-only blocker for lower priority
        if input.proof_priority.is_high_priority() && self.config.enable_priority_preemption {
            RecoveryDecision::new(
                input,
                RecoveryAction::RetryRemoteSameWorker,
                reason_codes::RETRY_REMOTE_SAME_WORKER,
                "High priority proof - retrying despite contention".to_string(),
                "Retry with priority elevation".to_string(),
                Some(10_000), // 10 second backoff for priority work
                input.rch_outcome.worker_id.clone(),
            )
        } else if let Some(capacity) = &input.capacity_snapshot {
            if capacity.has_queue_capacity() {
                RecoveryDecision::new(
                    input,
                    RecoveryAction::QueueUntilCapacity,
                    reason_codes::QUEUE_UNTIL_CAPACITY,
                    "Contention detected - queueing until capacity available".to_string(),
                    "Queue validation until worker capacity available".to_string(),
                    Some(120_000), // 2 minute queue backoff
                    None,
                )
            } else {
                RecoveryDecision::new(
                    input,
                    RecoveryAction::UseSourceOnlyBlocker,
                    reason_codes::USE_SOURCE_ONLY_BLOCKER,
                    "Queue full and contention high - using source-only validation".to_string(),
                    "Switch to source-only validation".to_string(),
                    None,
                    None,
                )
            }
        } else {
            // No capacity info - conservative queue
            RecoveryDecision::new(
                input,
                RecoveryAction::QueueUntilCapacity,
                reason_codes::QUEUE_UNTIL_CAPACITY,
                "Contention detected - queueing (capacity unknown)".to_string(),
                "Queue validation".to_string(),
                Some(180_000), // 3 minute backoff when no capacity info
                None,
            )
        }
    }

    fn handle_broker_error(
        &self,
        input: &RecoveryPlannerInput,
    ) -> Result<RecoveryDecision, RecoveryPlannerError> {
        // Broker internal errors suggest infrastructure issues
        if input.attempt_count == 0 {
            // First attempt - try once more with backoff
            RecoveryDecision::new(
                input,
                RecoveryAction::RetryRemoteSameWorker,
                reason_codes::RETRY_REMOTE_SAME_WORKER,
                "Broker internal error - retrying once".to_string(),
                "Retry validation request".to_string(),
                Some(60_000), // 1 minute backoff
                input.rch_outcome.worker_id.clone(),
            )
        } else {
            // Multiple broker errors - fail closed
            self.create_fail_closed_decision(input, "Persistent broker internal errors")
        }
    }
}

fn compute_decision_digest(
    request_id: &str,
    action: &RecoveryAction,
    reason_code: &str,
    operator_message: &str,
    retry_after_ms: &Option<u64>,
    worker_preference: &Option<String>,
) -> Result<String, RecoveryPlannerError> {
    #[derive(Serialize)]
    struct DigestMaterial<'a> {
        schema_version: &'a str,
        request_id: &'a str,
        action: &'a str,
        reason_code: &'a str,
        operator_message: &'a str,
        retry_after_ms: Option<u64>,
        worker_preference: Option<&'a str>,
    }

    let material = DigestMaterial {
        schema_version: RECOVERY_PLANNER_SCHEMA_VERSION,
        request_id,
        action: action.as_str(),
        reason_code,
        operator_message,
        retry_after_ms: *retry_after_ms,
        worker_preference: worker_preference.as_deref(),
    };

    let bytes = serde_json::to_vec(&material).map_err(|err| {
        RecoveryPlannerError::DigestError(format!("failed to serialize digest material: {err}"))
    })?;

    let mut hasher = Sha256::new();
    hasher.update(b"validation_recovery_planner_v1:");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Ok(format!("sha256:{}", hex::encode(digest)))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::rch_adapter::{RchArtifactDigest, RchValidationAction};

    const NOW_MS: u64 = 1_701_000_000_000;

    fn default_input() -> RecoveryPlannerInput {
        RecoveryPlannerInput {
            schema_version: RECOVERY_PLANNER_SCHEMA_VERSION.to_string(),
            request_id: "req-test-001".to_string(),
            trace_id: "trace-test-001".to_string(),
            rch_outcome: successful_rch_outcome(),
            flight_recorder_observations: vec![],
            proof_priority: ProofPriority {
                bead_priority: 2,
                proof_priority: 2,
            },
            capacity_snapshot: Some(CapacitySnapshot {
                available_workers: 3,
                active_cargo_processes: 1,
                max_cargo_processes: 4,
                rch_queue_depth: 2,
                max_queue_depth: 10,
            }),
            attempt_count: 0,
            worker_diversity_count: 0,
            timeout_budget_remaining_ms: DEFAULT_TIMEOUT_BUDGET_MS,
            queue_age_ms: 0,
            dirty_state_policy: DirtyStatePolicy::AllowLocalFallback,
            now_ms: NOW_MS,
        }
    }

    fn successful_rch_outcome() -> RchAdapterOutcome {
        RchAdapterOutcome {
            schema_version: "test".to_string(),
            command_digest: "abc123".to_string(),
            action: Some(RchValidationAction::Test),
            package: Some("frankenengine-node".to_string()),
            outcome: RchOutcomeClass::Passed,
            execution_mode: RchExecutionMode::Remote,
            worker_id: Some("worker-001".to_string()),
            timeout_class: RchTimeoutClass::None,
            exit_code: Some(0),
            retryable: false,
            product_failure: false,
            reason_code: "SUCCESS".to_string(),
            detail: "Test passed".to_string(),
            stdout_digest: RchArtifactDigest {
                algorithm: "sha256".to_string(),
                hex: "abc123".to_string(),
                snippet: "output".to_string(),
            },
            stderr_digest: RchArtifactDigest {
                algorithm: "sha256".to_string(),
                hex: "def456".to_string(),
                snippet: "".to_string(),
            },
            duration_ms: 1000,
        }
    }

    #[test]
    fn successful_validation_needs_no_recovery() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let input = default_input();
        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::NoRecoveryNeeded);
        assert_eq!(decision.reason_code, reason_codes::NO_RECOVERY_NEEDED);
        assert!(!decision.fail_closed);
        assert!(decision.retry_after_ms.is_none());
    }

    #[test]
    fn worker_timeout_ssh_retries_different_worker() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.rch_outcome.timeout_class = RchTimeoutClass::SshCommand;

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::RetryRemoteDifferentWorker);
        assert_eq!(
            decision.reason_code,
            reason_codes::RETRY_REMOTE_DIFFERENT_WORKER
        );
        assert!(!decision.fail_closed);
        assert_eq!(decision.retry_after_ms, Some(30_000));
        assert!(decision.worker_preference.is_none());
    }

    #[test]
    fn cargo_test_timeout_retries_same_worker() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.rch_outcome.timeout_class = RchTimeoutClass::CargoTestTimeout;

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::RetryRemoteSameWorker);
        assert_eq!(decision.reason_code, reason_codes::RETRY_REMOTE_SAME_WORKER);
        assert_eq!(decision.retry_after_ms, Some(60_000));
        assert_eq!(decision.worker_preference, input.rch_outcome.worker_id);
    }

    #[test]
    fn missing_toolchain_retries_different_worker() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerMissingToolchain;

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::RetryRemoteDifferentWorker);
        assert_eq!(
            decision.reason_code,
            reason_codes::RETRY_REMOTE_DIFFERENT_WORKER
        );
        assert_eq!(decision.retry_after_ms, Some(15_000));
    }

    #[test]
    fn product_failure_fails_closed() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::CompileFailed;
        input.rch_outcome.product_failure = true;

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::FailClosed);
        assert_eq!(decision.reason_code, reason_codes::FAIL_CLOSED);
        assert!(decision.fail_closed);
        assert!(decision.retry_after_ms.is_none());
    }

    #[test]
    fn max_attempts_exceeded_fails_closed() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.attempt_count = DEFAULT_MAX_RETRY_ATTEMPTS; // Exceeds limit

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::FailClosed);
        assert_eq!(decision.reason_code, reason_codes::FAIL_CLOSED);
        assert!(decision.fail_closed);
    }

    #[test]
    fn high_priority_contention_retries_with_preemption() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::ContentionDeferred;
        input.proof_priority = ProofPriority {
            bead_priority: 0, // High priority
            proof_priority: 1,
        };

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::RetryRemoteSameWorker);
        assert_eq!(decision.retry_after_ms, Some(10_000)); // Short backoff for priority
        assert!(decision.operator_message.contains("High priority"));
    }

    #[test]
    fn low_priority_contention_with_queue_capacity_queues() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::ContentionDeferred;
        input.proof_priority = ProofPriority {
            bead_priority: 3, // Low priority
            proof_priority: 3,
        };

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::QueueUntilCapacity);
        assert_eq!(decision.reason_code, reason_codes::QUEUE_UNTIL_CAPACITY);
        assert_eq!(decision.retry_after_ms, Some(120_000));
    }

    #[test]
    fn contention_with_full_queue_uses_source_only() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::ContentionDeferred;
        input.proof_priority = ProofPriority {
            bead_priority: 3, // Low priority
            proof_priority: 3,
        };
        // Set queue at capacity
        input.capacity_snapshot.as_mut().unwrap().rch_queue_depth = 10;
        input.capacity_snapshot.as_mut().unwrap().max_queue_depth = 10;

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::UseSourceOnlyBlocker);
        assert_eq!(decision.reason_code, reason_codes::USE_SOURCE_ONLY_BLOCKER);
    }

    #[test]
    fn local_fallback_refused_with_source_only_policy_uses_source_only() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::LocalFallbackRefused;
        input.dirty_state_policy = DirtyStatePolicy::SourceOnlyForDirty;

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::UseSourceOnlyBlocker);
        assert_eq!(decision.reason_code, reason_codes::USE_SOURCE_ONLY_BLOCKER);
    }

    #[test]
    fn filesystem_error_first_attempt_retries_different_worker() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerFilesystemError;
        input.attempt_count = 0; // First attempt

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::RetryRemoteDifferentWorker);
        assert_eq!(decision.retry_after_ms, Some(30_000));
    }

    #[test]
    fn filesystem_error_multiple_attempts_fails_closed() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerFilesystemError;
        input.attempt_count = 1; // Multiple attempts

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::FailClosed);
        assert!(decision.fail_closed);
        assert!(
            decision
                .operator_message
                .contains("Persistent filesystem errors")
        );
    }

    #[test]
    fn broker_error_first_attempt_retries_same_worker() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::BrokerInternalError;
        input.attempt_count = 0;

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::RetryRemoteSameWorker);
        assert_eq!(decision.retry_after_ms, Some(60_000));
        assert_eq!(decision.worker_preference, input.rch_outcome.worker_id);
    }

    #[test]
    fn broker_error_multiple_attempts_fails_closed() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::BrokerInternalError;
        input.attempt_count = 1;

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::FailClosed);
        assert!(decision.fail_closed);
    }

    #[test]
    fn decision_digest_is_deterministic() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let input = default_input();

        let decision1 = planner.plan_recovery(&input).unwrap();
        let decision2 = planner.plan_recovery(&input).unwrap();

        assert_eq!(decision1.decision_digest, decision2.decision_digest);
        assert!(decision1.decision_digest.starts_with("sha256:"));
    }

    #[test]
    fn decision_digest_changes_with_different_inputs() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let input1 = default_input();
        let mut input2 = default_input();
        input2.request_id = "different-request".to_string();

        let decision1 = planner.plan_recovery(&input1).unwrap();
        let decision2 = planner.plan_recovery(&input2).unwrap();

        assert_ne!(decision1.decision_digest, decision2.decision_digest);
    }

    #[test]
    fn timeout_budget_exhausted_fails_closed() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.timeout_budget_remaining_ms = 0; // Budget exhausted

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::FailClosed);
        assert!(decision.fail_closed);
    }

    #[test]
    fn queue_age_exceeded_fails_closed() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.queue_age_ms = DEFAULT_MAX_QUEUE_AGE_MS + 1; // Exceeds max age

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::FailClosed);
        assert!(decision.fail_closed);
    }

    #[test]
    fn worker_diversity_exceeded_fails_closed() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.worker_diversity_count = DEFAULT_MAX_WORKER_DIVERSITY; // Exceeds limit

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::FailClosed);
        assert!(decision.fail_closed);
    }

    #[test]
    fn empty_request_id_returns_error() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.request_id = String::new(); // Invalid

        let result = planner.plan_recovery(&input);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("request_id cannot be empty")
        );
    }

    #[test]
    fn empty_trace_id_returns_error() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.trace_id = String::new(); // Invalid

        let result = planner.plan_recovery(&input);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("trace_id cannot be empty")
        );
    }

    #[test]
    fn process_idle_timeout_drains_worker() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.rch_outcome.timeout_class = RchTimeoutClass::ProcessIdle;

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::DrainWorkerThenRetry);
        assert_eq!(decision.reason_code, reason_codes::DRAIN_WORKER_THEN_RETRY);
        assert_eq!(decision.retry_after_ms, Some(120_000)); // 2 minute backoff
    }
}
