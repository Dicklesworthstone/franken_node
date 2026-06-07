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

use crate::ops::rch_adapter::{RchAdapterOutcome, RchOutcomeClass, RchTimeoutClass};
use crate::ops::validation_broker::{
    FlightRecorderObservation, ProofEvidenceSource, ValidationProofCacheReuseEvidence,
    ValidationProofCoalescerEvidence,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const RECOVERY_PLANNER_SCHEMA_VERSION: &str = "franken-node/validation-recovery-planner/v1";
pub const BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION: &str =
    "franken-node/blocked-proof-rehydration/v1";
pub const DEFAULT_MAX_RETRY_ATTEMPTS: u32 = 3;
pub const DEFAULT_MAX_WORKER_DIVERSITY: u32 = 2;
pub const DEFAULT_TIMEOUT_BUDGET_MS: u64 = 1_800_000; // 30 minutes
pub const DEFAULT_MAX_QUEUE_AGE_MS: u64 = 3_600_000; // 1 hour
pub const DEFAULT_REHYDRATION_MAX_BLOCKER_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const DEFAULT_REHYDRATION_RETRY_AFTER_MS: u64 = 60_000;

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

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
    pub const RETRY_WITH_NEW_FENCE: &str = "RETRY_WITH_NEW_FENCE";
    pub const REUSE_RECEIPT: &str = "REUSE_RECEIPT";
    pub const USE_SOURCE_ONLY_BLOCKER: &str = "USE_SOURCE_ONLY_BLOCKER";
    pub const FAIL_CLOSED: &str = "FAIL_CLOSED";
    pub const NO_RECOVERY_NEEDED: &str = "NO_RECOVERY_NEEDED";
}

pub mod rehydration_reason_codes {
    pub const READY_FOR_REPROOF: &str = "REHYDRATE_READY_FOR_REPROOF";
    pub const WAIT_FOR_CAPACITY: &str = "REHYDRATE_WAIT_FOR_CAPACITY";
    pub const WAIT_FOR_EXISTING_PROOF: &str = "REHYDRATE_WAIT_FOR_EXISTING_PROOF";
    pub const REUSE_CACHE_RECEIPT: &str = "REHYDRATE_REUSE_CACHE_RECEIPT";
    pub const SOURCE_ONLY_DURING_PRESSURE: &str = "REHYDRATE_SOURCE_ONLY_DURING_PRESSURE";
    pub const STALE_COMMAND_MISSING_PATH: &str = "REHYDRATE_STALE_COMMAND_MISSING_PATH";
    pub const STALE_CLOSED_BLOCKER: &str = "REHYDRATE_STALE_CLOSED_BLOCKER";
    pub const STALE_BLOCKER_EVIDENCE: &str = "REHYDRATE_STALE_BLOCKER_EVIDENCE";
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
    /// Retry stale proof work with a fresh coalescer fencing token
    RetryWithNewFence,
    /// Reuse a completed proof receipt instead of executing duplicate work
    ReuseReceipt,
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
            Self::RetryWithNewFence => "retry_with_new_fence",
            Self::ReuseReceipt => "reuse_receipt",
            Self::UseSourceOnlyBlocker => "use_source_only_blocker",
            Self::FailClosed => "fail_closed",
            Self::NoRecoveryNeeded => "no_recovery_needed",
        }
    }

    #[must_use]
    pub const fn is_retry(self) -> bool {
        matches!(
            self,
            Self::RetryRemoteSameWorker
                | Self::RetryRemoteDifferentWorker
                | Self::RetryWithNewFence
        )
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::FailClosed
                | Self::NoRecoveryNeeded
                | Self::ReuseReceipt
                | Self::UseSourceOnlyBlocker
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
    pub proof_source: ProofEvidenceSource,
    pub proof_coalescer: Option<ValidationProofCoalescerEvidence>,
    pub proof_cache: Option<ValidationProofCacheReuseEvidence>,
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
            RecoveryAction::RetryRemoteSameWorker
            | RecoveryAction::RetryRemoteDifferentWorker
            | RecoveryAction::RetryWithNewFence => event_codes::RECOVERY_PLAN_RETRY_SCHEDULED,
            RecoveryAction::QueueUntilCapacity | RecoveryAction::WaitForExistingProof => {
                event_codes::RECOVERY_PLAN_QUEUE_DEFERRED
            }
            RecoveryAction::FailClosed => event_codes::RECOVERY_PLAN_FAIL_CLOSED,
            RecoveryAction::UseSourceOnlyBlocker => event_codes::RECOVERY_PLAN_SOURCE_ONLY_BLOCKER,
            RecoveryAction::DrainWorkerThenRetry => event_codes::RECOVERY_PLAN_RETRY_SCHEDULED,
            RecoveryAction::ReuseReceipt => event_codes::RECOVERY_PLAN_GENERATED,
        };

        let fail_closed = matches!(action, RecoveryAction::FailClosed);

        let decision_digest = compute_decision_digest(
            &input.request_id,
            &action,
            reason_code,
            &operator_message,
            &retry_after_ms,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedProofBeadState {
    Open,
    Blocked,
    InProgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RehydrationBlockerStatus {
    Open,
    Blocked,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehydrationPathRef {
    pub path: String,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehydrationBlockerRef {
    pub bead_id: String,
    pub status: RehydrationBlockerStatus,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedProofBeadSummary {
    pub bead_id: String,
    pub state: BlockedProofBeadState,
    pub priority: u8,
    pub assignee: Option<String>,
    pub updated_at_ms: u64,
    pub deferred_command: String,
    pub referenced_paths: Vec<RehydrationPathRef>,
    pub sibling_blockers: Vec<RehydrationBlockerRef>,
    pub latest_blocker_comment: String,
    pub source_only_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedProofRchSnapshot {
    pub active_cargo_processes: u32,
    pub max_active_cargo_processes: u32,
    pub queue_depth: u32,
    pub max_queue_depth: u32,
    pub available_workers: u32,
}

impl BlockedProofRchSnapshot {
    #[must_use]
    pub fn validation_lane_is_safe(&self) -> bool {
        self.active_cargo_processes < self.max_active_cargo_processes
            && self.queue_depth < self.max_queue_depth
            && self.available_workers > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedProofRehydrationInput {
    pub schema_version: String,
    pub now_ms: u64,
    pub max_blocker_age_ms: u64,
    pub rch_snapshot: BlockedProofRchSnapshot,
    pub agent_mail_healthy: bool,
    pub proof_cache_hit_beads: Vec<String>,
    pub coalesced_commands: Vec<String>,
    pub blocked_beads: Vec<BlockedProofBeadSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedProofRehydrationAction {
    ReadyForReproof,
    WaitForCapacity,
    WaitForExistingProof,
    ReuseCacheReceipt,
    SourceOnlyDuringPressure,
    FailClosedReview,
}

impl BlockedProofRehydrationAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadyForReproof => "ready_for_reproof",
            Self::WaitForCapacity => "wait_for_capacity",
            Self::WaitForExistingProof => "wait_for_existing_proof",
            Self::ReuseCacheReceipt => "reuse_cache_receipt",
            Self::SourceOnlyDuringPressure => "source_only_during_pressure",
            Self::FailClosedReview => "fail_closed_review",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedProofRehydrationCandidate {
    pub schema_version: String,
    pub bead_id: String,
    pub command: String,
    pub command_digest: String,
    pub action: BlockedProofRehydrationAction,
    pub reason_code: String,
    pub retry_after_ms: Option<u64>,
    pub required_preflight: String,
    pub status_recommendation: String,
    pub fail_closed: bool,
    pub priority_rank: u32,
    pub evidence_snippet: String,
    pub decision_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedProofRehydrationPlan {
    pub schema_version: String,
    pub generated_at_ms: u64,
    pub candidates: Vec<BlockedProofRehydrationCandidate>,
    pub human_summary: String,
}

pub fn build_blocked_proof_rehydration_plan(
    input: &BlockedProofRehydrationInput,
) -> Result<BlockedProofRehydrationPlan, RecoveryPlannerError> {
    validate_rehydration_input(input)?;

    let cache_hits = input
        .proof_cache_hit_beads
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let coalesced_commands = input
        .coalesced_commands
        .iter()
        .map(|command| normalize_rehydration_command(command))
        .collect::<BTreeSet<_>>();

    let mut ordered = input.blocked_beads.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        let left_age = input.now_ms.saturating_sub(left.updated_at_ms);
        let right_age = input.now_ms.saturating_sub(right.updated_at_ms);
        left.priority
            .cmp(&right.priority)
            .then_with(|| right_age.cmp(&left_age))
            .then_with(|| left.bead_id.cmp(&right.bead_id))
    });

    let mut seen_commands = BTreeSet::new();
    let mut candidates = Vec::with_capacity(ordered.len());
    for bead in ordered {
        let normalized_command = normalize_rehydration_command(&bead.deferred_command);
        let duplicate_command = seen_commands.contains(normalized_command.as_str());
        let coalesced_command = coalesced_commands.contains(normalized_command.as_str());
        let candidate = classify_blocked_proof_rehydration_candidate(
            input,
            bead,
            &normalized_command,
            duplicate_command,
            cache_hits.contains(bead.bead_id.as_str()),
            coalesced_command,
            u32::try_from(candidates.len().saturating_add(1)).unwrap_or(u32::MAX),
        )?;
        if !candidate.fail_closed {
            seen_commands.insert(normalized_command);
        }
        candidates.push(candidate);
    }

    let human_summary = render_blocked_proof_rehydration_human(&candidates, input.now_ms);

    Ok(BlockedProofRehydrationPlan {
        schema_version: BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION.to_string(),
        generated_at_ms: input.now_ms,
        candidates,
        human_summary,
    })
}

#[must_use]
pub fn render_blocked_proof_rehydration_human(
    candidates: &[BlockedProofRehydrationCandidate],
    generated_at_ms: u64,
) -> String {
    let ready = candidates
        .iter()
        .filter(|candidate| candidate.action == BlockedProofRehydrationAction::ReadyForReproof)
        .count();
    let waiting = candidates
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.action,
                BlockedProofRehydrationAction::WaitForCapacity
                    | BlockedProofRehydrationAction::WaitForExistingProof
            )
        })
        .count();
    let fail_closed = candidates
        .iter()
        .filter(|candidate| candidate.fail_closed)
        .count();
    let source_only = candidates
        .iter()
        .filter(|candidate| {
            candidate.action == BlockedProofRehydrationAction::SourceOnlyDuringPressure
        })
        .count();

    let mut output = format!(
        "blocked_proof_rehydration generated_at_ms={} candidates={} ready={} waiting={} source_only={} fail_closed={}",
        generated_at_ms,
        candidates.len(),
        ready,
        waiting,
        source_only,
        fail_closed
    );

    for candidate in candidates {
        output.push_str(&format!(
            "\n- bead={} action={} reason_code={} retry_after_ms={} status={} command_digest={} preflight={} evidence={}",
            candidate.bead_id,
            candidate.action.as_str(),
            candidate.reason_code,
            candidate
                .retry_after_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string()),
            candidate.status_recommendation,
            candidate.command_digest,
            candidate.required_preflight,
            candidate.evidence_snippet
        ));
    }

    output
}

fn classify_blocked_proof_rehydration_candidate(
    input: &BlockedProofRehydrationInput,
    bead: &BlockedProofBeadSummary,
    command: &str,
    duplicate_command: bool,
    cache_hit: bool,
    coalesced_command: bool,
    priority_rank: u32,
) -> Result<BlockedProofRehydrationCandidate, RecoveryPlannerError> {
    let command_digest = digest_rehydration_command(command);
    let stale_age = input.now_ms.saturating_sub(bead.updated_at_ms) >= input.max_blocker_age_ms;
    let missing_path = bead.referenced_paths.iter().find(|path| !path.exists);
    let closed_blocker = bead
        .sibling_blockers
        .iter()
        .find(|blocker| blocker.status == RehydrationBlockerStatus::Closed);

    let (
        action,
        reason_code,
        retry_after_ms,
        required_preflight,
        status_recommendation,
        fail_closed,
        evidence,
    ) = if let Some(path) = missing_path {
        (
            BlockedProofRehydrationAction::FailClosedReview,
            rehydration_reason_codes::STALE_COMMAND_MISSING_PATH,
            None,
            "refresh deferred command before reproof".to_string(),
            "remain_blocked".to_string(),
            true,
            format!("referenced path is missing: {}", path.path),
        )
    } else if let Some(blocker) = closed_blocker {
        (
            BlockedProofRehydrationAction::FailClosedReview,
            rehydration_reason_codes::STALE_CLOSED_BLOCKER,
            None,
            "refresh blocker evidence before reproof".to_string(),
            "remain_blocked".to_string(),
            true,
            format!("sibling blocker {} is already closed", blocker.bead_id),
        )
    } else if stale_age {
        (
            BlockedProofRehydrationAction::FailClosedReview,
            rehydration_reason_codes::STALE_BLOCKER_EVIDENCE,
            None,
            "refresh stale blocker comment before reproof".to_string(),
            "remain_blocked".to_string(),
            true,
            "blocker evidence is older than freshness window".to_string(),
        )
    } else if duplicate_command || coalesced_command {
        (
            BlockedProofRehydrationAction::WaitForExistingProof,
            rehydration_reason_codes::WAIT_FOR_EXISTING_PROOF,
            Some(DEFAULT_REHYDRATION_RETRY_AFTER_MS),
            "wait for existing proof receipt".to_string(),
            "remain_blocked".to_string(),
            false,
            "equivalent proof work already in flight".to_string(),
        )
    } else if cache_hit {
        (
            BlockedProofRehydrationAction::ReuseCacheReceipt,
            rehydration_reason_codes::REUSE_CACHE_RECEIPT,
            None,
            "verify cached receipt freshness".to_string(),
            "ready_to_close_with_receipt".to_string(),
            false,
            "fresh proof-cache receipt is available".to_string(),
        )
    } else if !input.rch_snapshot.validation_lane_is_safe() {
        if bead.source_only_allowed {
            (
                BlockedProofRehydrationAction::SourceOnlyDuringPressure,
                rehydration_reason_codes::SOURCE_ONLY_DURING_PRESSURE,
                Some(DEFAULT_REHYDRATION_RETRY_AFTER_MS),
                "run source-only checks and defer rch proof".to_string(),
                "remain_blocked".to_string(),
                false,
                format!(
                    "active_cargo={} queue_depth={} workers={}",
                    input.rch_snapshot.active_cargo_processes,
                    input.rch_snapshot.queue_depth,
                    input.rch_snapshot.available_workers
                ),
            )
        } else {
            (
                BlockedProofRehydrationAction::WaitForCapacity,
                rehydration_reason_codes::WAIT_FOR_CAPACITY,
                Some(DEFAULT_REHYDRATION_RETRY_AFTER_MS),
                "wait for safe rch lane".to_string(),
                "remain_blocked".to_string(),
                false,
                format!(
                    "active_cargo={} queue_depth={} workers={}",
                    input.rch_snapshot.active_cargo_processes,
                    input.rch_snapshot.queue_depth,
                    input.rch_snapshot.available_workers
                ),
            )
        }
    } else {
        (
            BlockedProofRehydrationAction::ReadyForReproof,
            rehydration_reason_codes::READY_FOR_REPROOF,
            None,
            if input.agent_mail_healthy {
                "reserve files and run focused rch proof".to_string()
            } else {
                "use bead assignee as soft lock and run focused rch proof".to_string()
            },
            "ready_for_reproof".to_string(),
            false,
            "fresh blocker evidence and safe rch lane".to_string(),
        )
    };

    let evidence_snippet =
        bounded_rehydration_snippet(&format!("{}; {}", evidence, bead.latest_blocker_comment));
    let decision_digest = digest_rehydration_candidate(
        &bead.bead_id,
        action,
        reason_code,
        &command_digest,
        &required_preflight,
        &evidence_snippet,
    )?;

    Ok(BlockedProofRehydrationCandidate {
        schema_version: BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION.to_string(),
        bead_id: bead.bead_id.clone(),
        command: command.to_string(),
        command_digest,
        action,
        reason_code: reason_code.to_string(),
        retry_after_ms,
        required_preflight,
        status_recommendation,
        fail_closed,
        priority_rank,
        evidence_snippet,
        decision_digest,
    })
}

fn validate_rehydration_input(
    input: &BlockedProofRehydrationInput,
) -> Result<(), RecoveryPlannerError> {
    if input.schema_version != BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION {
        return Err(RecoveryPlannerError::InvalidInput(
            "blocked proof rehydration schema_version mismatch".to_string(),
        ));
    }

    if input.max_blocker_age_ms == 0 {
        return Err(RecoveryPlannerError::InvalidInput(
            "max_blocker_age_ms must be positive".to_string(),
        ));
    }

    for bead in &input.blocked_beads {
        validate_rehydration_text("bead_id", &bead.bead_id)?;
        validate_rehydration_text("deferred_command", &bead.deferred_command)?;
        validate_rehydration_text("latest_blocker_comment", &bead.latest_blocker_comment)?;
        for path in &bead.referenced_paths {
            validate_rehydration_text("referenced_path", &path.path)?;
        }
        for blocker in &bead.sibling_blockers {
            validate_rehydration_text("blocker.bead_id", &blocker.bead_id)?;
            validate_rehydration_text("blocker.summary", &blocker.summary)?;
        }
    }

    Ok(())
}

fn validate_rehydration_text(field: &'static str, value: &str) -> Result<(), RecoveryPlannerError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(RecoveryPlannerError::InvalidInput(format!(
            "{field} must be non-empty text without control characters"
        )));
    }
    Ok(())
}

fn normalize_rehydration_command(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn bounded_rehydration_snippet(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(180)
        .collect()
}

fn digest_rehydration_command(command: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"blocked_proof_rehydration_command_v1:");
    hasher.update(len_to_u64(command.len()).to_le_bytes());
    hasher.update(command.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn digest_rehydration_candidate(
    bead_id: &str,
    action: BlockedProofRehydrationAction,
    reason_code: &str,
    command_digest: &str,
    required_preflight: &str,
    evidence_snippet: &str,
) -> Result<String, RecoveryPlannerError> {
    #[derive(Serialize)]
    struct Material<'a> {
        schema_version: &'a str,
        bead_id: &'a str,
        action: &'a str,
        reason_code: &'a str,
        command_digest: &'a str,
        required_preflight: &'a str,
        evidence_snippet: &'a str,
    }

    let material = Material {
        schema_version: BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION,
        bead_id,
        action: action.as_str(),
        reason_code,
        command_digest,
        required_preflight,
        evidence_snippet,
    };

    let bytes = serde_json::to_vec(&material).map_err(|err| {
        RecoveryPlannerError::DigestError(format!(
            "failed to serialize rehydration digest material: {err}"
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"blocked_proof_rehydration_candidate_v1:");
    hasher.update(len_to_u64(bytes.len()).to_le_bytes());
    hasher.update(bytes);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
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

        if let Some(coalesced_decision) = self.plan_from_proof_coalescing(input)? {
            return Ok(coalesced_decision);
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
            || input.queue_age_ms >= self.config.max_queue_age_ms
    }

    fn plan_from_proof_coalescing(
        &self,
        input: &RecoveryPlannerInput,
    ) -> Result<Option<RecoveryDecision>, RecoveryPlannerError> {
        if let Some(cache) = &input.proof_cache {
            return RecoveryDecision::new(
                input,
                RecoveryAction::ReuseReceipt,
                reason_codes::REUSE_RECEIPT,
                format!(
                    "Proof cache hit {} has reusable receipt {}",
                    cache.cache_key_hex, cache.receipt_path
                ),
                "Reuse completed proof receipt".to_string(),
                None,
                None,
            )
            .map(Some);
        }

        let Some(coalescer) = &input.proof_coalescer else {
            return Ok(None);
        };

        match coalescer.required_action.as_str() {
            "wait_for_receipt" | "join_existing_lease" => {
                if coalescer.receipt_path.is_some() {
                    return self.reuse_coalesced_receipt(input, coalescer).map(Some);
                }
                return RecoveryDecision::new(
                    input,
                    RecoveryAction::WaitForExistingProof,
                    reason_codes::WAIT_FOR_EXISTING_PROOF,
                    format!(
                        "Proof work is already coalesced on lease {} from producer {}",
                        coalescer.lease_id, coalescer.producer_agent
                    ),
                    "Wait for existing proof receipt".to_string(),
                    Some(60_000),
                    None,
                )
                .map(Some);
            }
            "retry_with_new_fence" => {
                return RecoveryDecision::new(
                    input,
                    RecoveryAction::RetryWithNewFence,
                    reason_codes::RETRY_WITH_NEW_FENCE,
                    format!(
                        "Stale proof lease {} requires a fresh fencing token before retry",
                        coalescer.lease_id
                    ),
                    "Retry with new coalescer fencing token".to_string(),
                    Some(15_000),
                    input.rch_outcome.worker_id.clone(),
                )
                .map(Some);
            }
            "fail_closed" | "repair_state" => {
                return self
                    .create_fail_closed_decision(
                        input,
                        &format!(
                            "Proof coalescer rejected recovery for lease {}: {}",
                            coalescer.lease_id, coalescer.diagnostic
                        ),
                    )
                    .map(Some);
            }
            _ => {}
        }

        if coalescer.receipt_path.is_some()
            || matches!(
                input.proof_source,
                ProofEvidenceSource::ProofCacheHit | ProofEvidenceSource::CoalescedCompleted
            )
        {
            return self.reuse_coalesced_receipt(input, coalescer).map(Some);
        }

        if matches!(
            input.proof_source,
            ProofEvidenceSource::CoalescedInflight | ProofEvidenceSource::CoalescedWaiter
        ) || matches!(
            coalescer.lease_state.as_str(),
            "running" | "joined" | "proposed"
        ) {
            return RecoveryDecision::new(
                input,
                RecoveryAction::WaitForExistingProof,
                reason_codes::WAIT_FOR_EXISTING_PROOF,
                format!(
                    "Proof work is already in flight on lease {} from producer {}",
                    coalescer.lease_id, coalescer.producer_agent
                ),
                "Wait for existing proof receipt".to_string(),
                Some(60_000),
                None,
            )
            .map(Some);
        }

        if matches!(input.proof_source, ProofEvidenceSource::CoalescerRejected)
            || coalescer.lease_state == "failed_closed"
        {
            return self
                .create_fail_closed_decision(
                    input,
                    &format!(
                        "Proof coalescer state is fail-closed for lease {}: {}",
                        coalescer.lease_id, coalescer.diagnostic
                    ),
                )
                .map(Some);
        }

        Ok(None)
    }

    fn reuse_coalesced_receipt(
        &self,
        input: &RecoveryPlannerInput,
        coalescer: &ValidationProofCoalescerEvidence,
    ) -> Result<RecoveryDecision, RecoveryPlannerError> {
        let receipt_path = coalescer
            .receipt_path
            .as_deref()
            .unwrap_or("coalesced receipt");
        RecoveryDecision::new(
            input,
            RecoveryAction::ReuseReceipt,
            reason_codes::REUSE_RECEIPT,
            format!(
                "Coalesced proof lease {} has reusable receipt {}",
                coalescer.lease_id, receipt_path
            ),
            "Reuse completed proof receipt".to_string(),
            None,
            None,
        )
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
        if is_storage_pressure_outcome(input) {
            return RecoveryDecision::new(
                input,
                RecoveryAction::DrainWorkerThenRetry,
                reason_codes::DRAIN_WORKER_THEN_RETRY,
                "Worker storage pressure - drain saturated worker before retry".to_string(),
                "Drain storage-pressured worker and retry on healthy capacity".to_string(),
                Some(120_000),
                None,
            );
        }

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

fn is_storage_pressure_outcome(input: &RecoveryPlannerInput) -> bool {
    input.rch_outcome.reason_code == "RCH-WORKER-STORAGE-PRESSURE" || {
        let detail = input.rch_outcome.detail.to_ascii_lowercase();
        detail.contains("no space left on device")
            || detail.contains("os error 28")
            || detail.contains("enospc")
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
    hasher.update(len_to_u64(bytes.len()).to_le_bytes());
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Ok(format!("sha256:{}", hex::encode(digest)))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::rch_adapter::{RchArtifactDigest, RchExecutionMode, RchValidationAction};

    const NOW_MS: u64 = 1_701_000_000_000;

    fn default_input() -> RecoveryPlannerInput {
        RecoveryPlannerInput {
            schema_version: RECOVERY_PLANNER_SCHEMA_VERSION.to_string(),
            request_id: "req-test-001".to_string(),
            trace_id: "trace-test-001".to_string(),
            rch_outcome: successful_rch_outcome(),
            flight_recorder_observations: vec![],
            proof_source: ProofEvidenceSource::FreshExecution,
            proof_coalescer: None,
            proof_cache: None,
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

    fn coalescer_evidence(
        required_action: &str,
        lease_state: &str,
        receipt_path: Option<&str>,
    ) -> ValidationProofCoalescerEvidence {
        ValidationProofCoalescerEvidence {
            decision_id: "decision-coalesced-001".to_string(),
            proof_work_key_hex: "a".repeat(64),
            lease_id: "lease-coalesced-001".to_string(),
            lease_path: "artifacts/validation/proof-coalescer/lease.json".to_string(),
            lease_state: lease_state.to_string(),
            producer_agent: "PearlLeopard".to_string(),
            producer_bead_id: "bd-producer".to_string(),
            waiter_agent: Some("RedGlen".to_string()),
            trace_id: "trace-coalesced-001".to_string(),
            receipt_id: receipt_path.map(|_| "receipt-coalesced-001".to_string()),
            receipt_path: receipt_path.map(str::to_string),
            proof_cache_key_hex: "b".repeat(64),
            reason_code: "COALESCER_TEST".to_string(),
            event_code: "VPCO-TEST".to_string(),
            required_action: required_action.to_string(),
            diagnostic: "coalescer test diagnostic".to_string(),
        }
    }

    fn proof_cache_evidence() -> ValidationProofCacheReuseEvidence {
        ValidationProofCacheReuseEvidence {
            decision_id: "cache-decision-001".to_string(),
            cache_key_hex: "c".repeat(64),
            entry_id: "cache-entry-001".to_string(),
            entry_path: "artifacts/validation/proof-cache/entry.json".to_string(),
            receipt_id: "cache-receipt-001".to_string(),
            receipt_path: "artifacts/validation/proof-cache/receipt.json".to_string(),
            reason_code: "CACHE_HIT".to_string(),
            event_code: "VPCACHE-001".to_string(),
            required_action: "reuse_receipt".to_string(),
            diagnostic: "proof cache hit".to_string(),
        }
    }

    fn rehydration_bead(
        bead_id: &str,
        priority: u8,
        updated_at_ms: u64,
        command: &str,
    ) -> BlockedProofBeadSummary {
        BlockedProofBeadSummary {
            bead_id: bead_id.to_string(),
            state: BlockedProofBeadState::Blocked,
            priority,
            assignee: Some("ScarletCanyon".to_string()),
            updated_at_ms,
            deferred_command: command.to_string(),
            referenced_paths: vec![RehydrationPathRef {
                path: "crates/franken-node/tests/validation_proof_cache.rs".to_string(),
                exists: true,
            }],
            sibling_blockers: Vec::new(),
            latest_blocker_comment: format!("Deferred proof command for {bead_id}: {command}"),
            source_only_allowed: false,
        }
    }

    fn rehydration_input(
        blocked_beads: Vec<BlockedProofBeadSummary>,
    ) -> BlockedProofRehydrationInput {
        BlockedProofRehydrationInput {
            schema_version: BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION.to_string(),
            now_ms: NOW_MS,
            max_blocker_age_ms: DEFAULT_REHYDRATION_MAX_BLOCKER_AGE_MS,
            rch_snapshot: BlockedProofRchSnapshot {
                active_cargo_processes: 0,
                max_active_cargo_processes: 2,
                queue_depth: 0,
                max_queue_depth: 8,
                available_workers: 4,
            },
            agent_mail_healthy: true,
            proof_cache_hit_beads: Vec::new(),
            coalesced_commands: Vec::new(),
            blocked_beads,
        }
    }

    #[test]
    fn blocked_proof_rehydration_orders_by_priority_and_age_and_suppresses_duplicates() {
        let command = "rch exec -- cargo test -p frankenengine-node validation_proof_cache";
        let mut input = rehydration_input(vec![
            rehydration_bead("bd-low", 3, NOW_MS - 1_000, command),
            rehydration_bead("bd-old-high", 1, NOW_MS - 120_000, command),
            rehydration_bead(
                "bd-new-high",
                1,
                NOW_MS - 1_000,
                "rch exec -- cargo test -p frankenengine-node validation_readiness",
            ),
        ]);
        input
            .coalesced_commands
            .push("rch exec -- cargo test -p frankenengine-node validation_readiness".to_string());

        let plan = build_blocked_proof_rehydration_plan(&input).unwrap();

        assert_eq!(
            plan.schema_version,
            BLOCKED_PROOF_REHYDRATION_SCHEMA_VERSION
        );
        assert_eq!(plan.candidates[0].bead_id, "bd-old-high");
        assert_eq!(
            plan.candidates[0].action,
            BlockedProofRehydrationAction::ReadyForReproof
        );
        assert_eq!(
            plan.candidates[1].action,
            BlockedProofRehydrationAction::WaitForExistingProof
        );
        assert_eq!(
            plan.candidates[2].reason_code,
            rehydration_reason_codes::WAIT_FOR_EXISTING_PROOF
        );
        assert!(plan.human_summary.contains("ready=1"));
        assert!(plan.human_summary.contains("waiting=2"));
    }

    #[test]
    fn blocked_proof_rehydration_fails_closed_for_missing_path_and_closed_blocker() {
        let mut missing = rehydration_bead(
            "bd-missing",
            2,
            NOW_MS - 10_000,
            "rch exec -- cargo test -p frankenengine-node missing_path_test",
        );
        let missing_path = missing
            .referenced_paths
            .first_mut()
            .expect("rehydration fixture includes a referenced path");
        missing_path.exists = false;
        missing_path.path = "crates/franken-node/tests/deleted_validation_test.rs".to_string();

        let mut closed_blocker = rehydration_bead(
            "bd-closed-blocker",
            2,
            NOW_MS - 9_000,
            "rch exec -- cargo test -p frankenengine-node stale_blocker_test",
        );
        closed_blocker.sibling_blockers.push(RehydrationBlockerRef {
            bead_id: "bd-franken-engine-stale".to_string(),
            status: RehydrationBlockerStatus::Closed,
            summary: "prior sibling API drift is closed".to_string(),
        });

        let plan =
            build_blocked_proof_rehydration_plan(&rehydration_input(vec![missing, closed_blocker]))
                .unwrap();

        assert!(
            plan.candidates
                .iter()
                .all(|candidate| candidate.fail_closed)
        );
        assert!(plan.candidates.iter().any(|candidate| {
            candidate.reason_code == rehydration_reason_codes::STALE_COMMAND_MISSING_PATH
                && candidate.evidence_snippet.contains("missing")
        }));
        assert!(plan.candidates.iter().any(|candidate| {
            candidate.reason_code == rehydration_reason_codes::STALE_CLOSED_BLOCKER
                && candidate
                    .evidence_snippet
                    .contains("bd-franken-engine-stale")
        }));
    }

    #[test]
    fn blocked_proof_rehydration_fails_closed_at_max_blocker_age_boundary() {
        let boundary = rehydration_bead(
            "bd-boundary-stale",
            1,
            NOW_MS - DEFAULT_REHYDRATION_MAX_BLOCKER_AGE_MS,
            "rch exec -- cargo test -p frankenengine-node boundary_stale_blocker",
        );

        let plan = build_blocked_proof_rehydration_plan(&rehydration_input(vec![boundary]))
            .expect("rehydration plan");
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.bead_id == "bd-boundary-stale")
            .expect("boundary candidate");

        assert_eq!(
            candidate.action,
            BlockedProofRehydrationAction::FailClosedReview
        );
        assert_eq!(
            candidate.reason_code,
            rehydration_reason_codes::STALE_BLOCKER_EVIDENCE
        );
        assert!(candidate.fail_closed);
    }

    #[test]
    fn blocked_proof_rehydration_preserves_source_only_work_during_cargo_pressure() {
        let mut source_only = rehydration_bead(
            "bd-source-only",
            2,
            NOW_MS - 20_000,
            "rch exec -- cargo test -p frankenengine-node source_only_deferred",
        );
        source_only.source_only_allowed = true;

        let mut remote_required = rehydration_bead(
            "bd-remote-required",
            2,
            NOW_MS - 10_000,
            "rch exec -- cargo test -p frankenengine-node remote_required_deferred",
        );
        remote_required.source_only_allowed = false;

        let mut input = rehydration_input(vec![source_only, remote_required]);
        input.rch_snapshot.active_cargo_processes = 5;

        let plan = build_blocked_proof_rehydration_plan(&input).unwrap();
        let source_candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.bead_id == "bd-source-only")
            .unwrap();
        let remote_candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.bead_id == "bd-remote-required")
            .unwrap();

        assert_eq!(
            source_candidate.action,
            BlockedProofRehydrationAction::SourceOnlyDuringPressure
        );
        assert_eq!(
            source_candidate.reason_code,
            rehydration_reason_codes::SOURCE_ONLY_DURING_PRESSURE
        );
        assert_eq!(
            remote_candidate.action,
            BlockedProofRehydrationAction::WaitForCapacity
        );
        assert!(plan.human_summary.contains("source_only=1"));
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
    fn proof_cache_hit_reuses_receipt_instead_of_retrying() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.rch_outcome.timeout_class = RchTimeoutClass::ProcessWall;
        input.proof_source = ProofEvidenceSource::ProofCacheHit;
        input.proof_cache = Some(proof_cache_evidence());

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::ReuseReceipt);
        assert_eq!(decision.reason_code, reason_codes::REUSE_RECEIPT);
        assert!(decision.retry_after_ms.is_none());
        assert!(decision.operator_message.contains("reusable receipt"));
    }

    #[test]
    fn coalesced_inflight_proof_waits_instead_of_retrying() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.rch_outcome.timeout_class = RchTimeoutClass::CargoTestTimeout;
        input.proof_source = ProofEvidenceSource::CoalescedWaiter;
        input.proof_coalescer = Some(coalescer_evidence("join_existing_lease", "running", None));

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::WaitForExistingProof);
        assert_eq!(decision.reason_code, reason_codes::WAIT_FOR_EXISTING_PROOF);
        assert_eq!(decision.retry_after_ms, Some(60_000));
    }

    #[test]
    fn stale_coalesced_lease_requires_new_fencing_token() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.rch_outcome.timeout_class = RchTimeoutClass::ProcessIdle;
        input.proof_source = ProofEvidenceSource::CoalescedInflight;
        input.proof_coalescer = Some(coalescer_evidence("retry_with_new_fence", "running", None));

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::RetryWithNewFence);
        assert_eq!(decision.reason_code, reason_codes::RETRY_WITH_NEW_FENCE);
        assert_eq!(decision.retry_after_ms, Some(15_000));
        assert_eq!(decision.worker_preference, input.rch_outcome.worker_id);
    }

    #[test]
    fn completed_coalesced_receipt_is_reused() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::ContentionDeferred;
        input.proof_source = ProofEvidenceSource::CoalescedCompleted;
        input.proof_coalescer = Some(coalescer_evidence(
            "wait_for_receipt",
            "completed",
            Some("artifacts/validation/proof-coalescer/receipt.json"),
        ));

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::ReuseReceipt);
        assert_eq!(decision.reason_code, reason_codes::REUSE_RECEIPT);
        assert!(decision.operator_message.contains("Coalesced proof lease"));
    }

    #[test]
    fn coalescer_fail_closed_state_remains_fail_closed() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerFilesystemError;
        input.proof_source = ProofEvidenceSource::CoalescerRejected;
        input.proof_coalescer = Some(coalescer_evidence("fail_closed", "failed_closed", None));

        let decision = planner.plan_recovery(&input).unwrap();
        assert_eq!(decision.action, RecoveryAction::FailClosed);
        assert_eq!(decision.reason_code, reason_codes::FAIL_CLOSED);
        assert!(decision.fail_closed);
        assert!(
            decision
                .operator_message
                .contains("Proof coalescer rejected")
        );
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
    fn storage_pressure_drains_worker_without_same_worker_preference() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerFilesystemError;
        input.rch_outcome.reason_code = "RCH-WORKER-STORAGE-PRESSURE".to_string();
        input.rch_outcome.detail = "failed to unpack package `linux-raw-sys v0.12.1`: No space left on device (os error 28)".to_string();
        input.rch_outcome.worker_id = Some("vmi1227854".to_string());

        let decision = planner.plan_recovery(&input).unwrap();

        assert_eq!(decision.action, RecoveryAction::DrainWorkerThenRetry);
        assert_eq!(decision.reason_code, reason_codes::DRAIN_WORKER_THEN_RETRY);
        assert_eq!(decision.retry_after_ms, Some(120_000));
        assert!(decision.worker_preference.is_none());
        assert!(decision.operator_message.contains("storage pressure"));
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
    fn queue_age_at_expiry_boundary_fails_closed() {
        let planner = ValidationRecoveryPlanner::new(RecoveryPlannerConfig::default());
        let mut input = default_input();
        input.rch_outcome.outcome = RchOutcomeClass::WorkerTimeout;
        input.queue_age_ms = DEFAULT_MAX_QUEUE_AGE_MS;

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

    #[test]
    fn validation_lane_is_safe_fails_closed_at_active_cargo_boundary() {
        let under = BlockedProofRchSnapshot {
            active_cargo_processes: 1,
            max_active_cargo_processes: 2,
            queue_depth: 0,
            max_queue_depth: 8,
            available_workers: 4,
        };
        assert!(under.validation_lane_is_safe());

        // active == max: adding one more would exceed the cap; must fail closed
        // to match CapacitySnapshot::has_cargo_capacity (line 166) which uses
        // `<` on the same boundary.
        let at_cap = BlockedProofRchSnapshot {
            active_cargo_processes: 2,
            max_active_cargo_processes: 2,
            queue_depth: 0,
            max_queue_depth: 8,
            available_workers: 4,
        };
        assert!(!at_cap.validation_lane_is_safe());

        let over = BlockedProofRchSnapshot {
            active_cargo_processes: 3,
            max_active_cargo_processes: 2,
            queue_depth: 0,
            max_queue_depth: 8,
            available_workers: 4,
        };
        assert!(!over.validation_lane_is_safe());
    }
}
