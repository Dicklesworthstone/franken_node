//! bd-2gr: product-layer epoch transition coordination.
//!
//! Integrates canonical epoch primitives from 10.14/10.15:
//! - monotonic epoch store (`control_epoch`)
//! - epoch transition barrier (`epoch_transition_barrier`)
//! - abort semantics (`transition_abort`)

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::control_plane::control_epoch::{EpochError, EpochStore};
use crate::control_plane::epoch_transition_barrier::{
    AbortReason, BarrierCommitOutcome, BarrierConfig, BarrierError, BarrierInstance, DrainAck,
    EpochTransitionBarrier,
};
use crate::control_plane::transition_abort::{
    ParticipantAbortState, TransitionAbortManager, TransitionAbortReason,
};

use crate::capacity_defaults::aliases::MAX_EVENTS;
const MAX_HISTORY_ENTRIES: usize = 4096;

pub const EPOCH_PROPOSED: &str = "EPOCH_PROPOSED";
pub const EPOCH_DRAIN_REQUESTED: &str = "EPOCH_DRAIN_REQUESTED";
pub const EPOCH_DRAIN_CONFIRMED: &str = "EPOCH_DRAIN_CONFIRMED";
pub const EPOCH_ADVANCED: &str = "EPOCH_ADVANCED";
pub const STALE_EPOCH_REJECTED: &str = "STALE_EPOCH_REJECTED";
pub const FUTURE_EPOCH_REJECTED: &str = "FUTURE_EPOCH_REJECTED";
pub const EPOCH_TRANSITION_ABORTED: &str = "EPOCH_TRANSITION_ABORTED";
pub const EPOCH_TRANSITION_COMMIT_ABORTED: &str = "EPOCH_TRANSITION_COMMIT_ABORTED";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTransitionLogEvent {
    pub event_code: String,
    pub epoch_current: u64,
    pub epoch_artifact: Option<u64>,
    pub transition_id: Option<String>,
    pub service_id: Option<String>,
    pub transition_reason: Option<String>,
    pub quiescence_status: Option<String>,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTransitionRecord {
    pub transition_id: String,
    pub pre_epoch: u64,
    pub target_epoch: u64,
    pub initiator: String,
    pub reason: String,
    pub timestamp_ms: u64,
    pub outcome: String,
    pub abort_reason: Option<String>,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTransitionProposal {
    pub transition_id: String,
    pub pre_epoch: u64,
    pub target_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochTransitionError {
    NoActiveTransition,
    Barrier(BarrierError),
    Epoch(EpochError),
    EpochAdvanceMismatch {
        expected: u64,
        actual: u64,
    },
    StaleEpochRejected {
        presented_epoch: u64,
        current_epoch: u64,
    },
    FutureEpochRejected {
        presented_epoch: u64,
        current_epoch: u64,
    },
    CommitAborted {
        barrier_id: String,
        reason: String,
    },
}

impl EpochTransitionError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoActiveTransition => "EPOCH_TRANSITION_NO_ACTIVE",
            Self::Barrier(err) => err.code(),
            Self::Epoch(err) => err.code(),
            Self::EpochAdvanceMismatch { .. } => "EPOCH_TRANSITION_ADVANCE_MISMATCH",
            Self::StaleEpochRejected { .. } => STALE_EPOCH_REJECTED,
            Self::FutureEpochRejected { .. } => FUTURE_EPOCH_REJECTED,
            Self::CommitAborted { .. } => EPOCH_TRANSITION_COMMIT_ABORTED,
        }
    }
}

impl fmt::Display for EpochTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoActiveTransition => write!(f, "{}: no active transition", self.code()),
            Self::Barrier(err) => write!(f, "{err}"),
            Self::Epoch(err) => write!(f, "{err}"),
            Self::EpochAdvanceMismatch { expected, actual } => write!(
                f,
                "{}: expected advanced epoch {} but got {}",
                self.code(),
                expected,
                actual
            ),
            Self::StaleEpochRejected {
                presented_epoch,
                current_epoch,
            } => write!(
                f,
                "{}: presented epoch {} < current {}",
                self.code(),
                presented_epoch,
                current_epoch
            ),
            Self::FutureEpochRejected {
                presented_epoch,
                current_epoch,
            } => write!(
                f,
                "{}: presented epoch {} > current {}",
                self.code(),
                presented_epoch,
                current_epoch
            ),
            Self::CommitAborted { barrier_id, reason } => write!(
                f,
                "{}: barrier {} auto-aborted during commit attempt: {}",
                self.code(),
                barrier_id,
                reason
            ),
        }
    }
}

impl std::error::Error for EpochTransitionError {}

impl From<BarrierError> for EpochTransitionError {
    fn from(value: BarrierError) -> Self {
        Self::Barrier(value)
    }
}

impl From<EpochError> for EpochTransitionError {
    fn from(value: EpochError) -> Self {
        Self::Epoch(value)
    }
}

#[derive(Debug, Clone)]
struct PendingTransitionMetadata {
    transition_id: String,
    pre_epoch: u64,
    target_epoch: u64,
    initiator: String,
    reason: String,
    #[allow(dead_code)]
    started_at_ms: u64,
}

pub struct ProductEpochCoordinator {
    epoch_store: EpochStore,
    barrier: EpochTransitionBarrier,
    abort_manager: TransitionAbortManager,
    max_epoch_lag: u64,
    events: Vec<EpochTransitionLogEvent>,
    history: Vec<EpochTransitionRecord>,
    pending: Option<PendingTransitionMetadata>,
}

impl ProductEpochCoordinator {
    #[must_use]
    pub fn new(initial_epoch: u64, max_epoch_lag: u64, barrier_config: BarrierConfig) -> Self {
        Self {
            epoch_store: if initial_epoch == 0 {
                EpochStore::new()
            } else {
                EpochStore::recover(initial_epoch)
            },
            barrier: EpochTransitionBarrier::new(barrier_config),
            abort_manager: TransitionAbortManager::new(),
            max_epoch_lag,
            events: Vec::new(),
            history: Vec::new(),
            pending: None,
        }
    }

    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.epoch_store.epoch_read().value()
    }

    #[must_use]
    pub fn max_epoch_lag(&self) -> u64 {
        self.max_epoch_lag
    }

    pub fn register_service(&mut self, service_id: &str) {
        self.barrier.register_participant(service_id);
    }

    #[must_use]
    pub fn events(&self) -> &[EpochTransitionLogEvent] {
        &self.events
    }

    #[must_use]
    pub fn history(&self) -> &[EpochTransitionRecord] {
        &self.history
    }

    #[must_use]
    pub fn abort_manager(&self) -> &TransitionAbortManager {
        &self.abort_manager
    }

    pub fn validate_operation_epoch(
        &mut self,
        service_id: &str,
        presented_epoch: u64,
        trace_id: &str,
    ) -> Result<(), EpochTransitionError> {
        let current = self.current_epoch();
        if presented_epoch < current {
            self.emit_event(EpochTransitionLogEvent {
                event_code: STALE_EPOCH_REJECTED.to_string(),
                epoch_current: current,
                epoch_artifact: Some(presented_epoch),
                transition_id: self.pending.as_ref().map(|p| p.transition_id.clone()),
                service_id: Some(service_id.to_string()),
                transition_reason: self.pending.as_ref().map(|p| p.reason.clone()),
                quiescence_status: Some("stale".to_string()),
                trace_id: trace_id.to_string(),
            });
            return Err(EpochTransitionError::StaleEpochRejected {
                presented_epoch,
                current_epoch: current,
            });
        }
        if presented_epoch > current {
            self.emit_event(EpochTransitionLogEvent {
                event_code: FUTURE_EPOCH_REJECTED.to_string(),
                epoch_current: current,
                epoch_artifact: Some(presented_epoch),
                transition_id: self.pending.as_ref().map(|p| p.transition_id.clone()),
                service_id: Some(service_id.to_string()),
                transition_reason: self.pending.as_ref().map(|p| p.reason.clone()),
                quiescence_status: Some("future".to_string()),
                trace_id: trace_id.to_string(),
            });
            return Err(EpochTransitionError::FutureEpochRejected {
                presented_epoch,
                current_epoch: current,
            });
        }
        Ok(())
    }

    pub fn validate_replica_lag(
        &mut self,
        service_id: &str,
        observed_epoch: u64,
        trace_id: &str,
    ) -> Result<(), EpochTransitionError> {
        let current = self.current_epoch();
        if observed_epoch > current {
            return Err(EpochTransitionError::FutureEpochRejected {
                presented_epoch: observed_epoch,
                current_epoch: current,
            });
        }
        if current.saturating_sub(observed_epoch) >= self.max_epoch_lag {
            self.emit_event(EpochTransitionLogEvent {
                event_code: STALE_EPOCH_REJECTED.to_string(),
                epoch_current: current,
                epoch_artifact: Some(observed_epoch),
                transition_id: self.pending.as_ref().map(|p| p.transition_id.clone()),
                service_id: Some(service_id.to_string()),
                transition_reason: self.pending.as_ref().map(|p| p.reason.clone()),
                quiescence_status: Some("lag_exceeded".to_string()),
                trace_id: trace_id.to_string(),
            });
            return Err(EpochTransitionError::StaleEpochRejected {
                presented_epoch: observed_epoch,
                current_epoch: current,
            });
        }
        Ok(())
    }

    pub fn propose_transition(
        &mut self,
        initiator: &str,
        reason: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<EpochTransitionProposal, EpochTransitionError> {
        let current = self.current_epoch();
        let target = current.saturating_add(1);
        let instance = self
            .barrier
            .propose(current, target, timestamp_ms, trace_id)?;
        let participants: Vec<String> = instance.participants.iter().cloned().collect();
        let proposal = EpochTransitionProposal {
            transition_id: instance.barrier_id.clone(),
            pre_epoch: current,
            target_epoch: target,
        };
        self.pending = Some(PendingTransitionMetadata {
            transition_id: proposal.transition_id.clone(),
            pre_epoch: proposal.pre_epoch,
            target_epoch: proposal.target_epoch,
            initiator: initiator.to_string(),
            reason: reason.to_string(),
            started_at_ms: timestamp_ms,
        });
        self.emit_event(EpochTransitionLogEvent {
            event_code: EPOCH_PROPOSED.to_string(),
            epoch_current: current,
            epoch_artifact: Some(target),
            transition_id: Some(proposal.transition_id.clone()),
            service_id: Some(initiator.to_string()),
            transition_reason: Some(reason.to_string()),
            quiescence_status: Some("proposed".to_string()),
            trace_id: trace_id.to_string(),
        });
        for participant in participants {
            self.emit_event(EpochTransitionLogEvent {
                event_code: EPOCH_DRAIN_REQUESTED.to_string(),
                epoch_current: current,
                epoch_artifact: Some(target),
                transition_id: Some(proposal.transition_id.clone()),
                service_id: Some(participant),
                transition_reason: Some(reason.to_string()),
                quiescence_status: Some("drain_requested".to_string()),
                trace_id: trace_id.to_string(),
            });
        }
        Ok(proposal)
    }

    pub fn ack_drain(
        &mut self,
        service_id: &str,
        drained_items: u64,
        elapsed_ms: u64,
        trace_id: &str,
    ) -> Result<(), EpochTransitionError> {
        let barrier = self.active_barrier_snapshot()?;
        self.barrier.record_drain_ack(DrainAck {
            participant_id: service_id.to_string(),
            barrier_id: barrier.barrier_id.clone(),
            drained_items,
            elapsed_ms,
            trace_id: trace_id.to_string(),
        })?;
        self.emit_event(EpochTransitionLogEvent {
            event_code: EPOCH_DRAIN_CONFIRMED.to_string(),
            epoch_current: barrier.current_epoch,
            epoch_artifact: Some(barrier.target_epoch),
            transition_id: Some(barrier.barrier_id),
            service_id: Some(service_id.to_string()),
            transition_reason: self.pending.as_ref().map(|p| p.reason.clone()),
            quiescence_status: Some("drained".to_string()),
            trace_id: trace_id.to_string(),
        });
        Ok(())
    }

    pub fn commit_transition(
        &mut self,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<u64, EpochTransitionError> {
        let pending = self
            .pending
            .clone()
            .ok_or(EpochTransitionError::NoActiveTransition)?;
        let target_epoch = match self.barrier.try_commit(timestamp_ms, trace_id)? {
            BarrierCommitOutcome::Committed { target_epoch } => target_epoch,
            BarrierCommitOutcome::Aborted { reason, .. } => {
                let snapshot = self
                    .barrier
                    .active_barrier()
                    .cloned()
                    .ok_or(EpochTransitionError::NoActiveTransition)?;
                let elapsed_ms = timestamp_ms.saturating_sub(snapshot.propose_timestamp_ms);
                self.record_abort_outcome(
                    snapshot.clone(),
                    pending,
                    transition_abort_reason_from_barrier_reason(&reason, elapsed_ms),
                    timestamp_ms,
                    trace_id,
                );
                return Err(EpochTransitionError::CommitAborted {
                    barrier_id: snapshot.barrier_id,
                    reason: reason.to_string(),
                });
            }
        };
        let manifest_hash = manifest_hash_for_transition(
            &pending.transition_id,
            &pending.initiator,
            &pending.reason,
            pending.target_epoch,
        );
        let advanced = self
            .epoch_store
            .epoch_advance(&manifest_hash, timestamp_ms, trace_id)?;
        let actual_epoch = advanced.new_epoch.value();
        if actual_epoch != target_epoch {
            return Err(EpochTransitionError::EpochAdvanceMismatch {
                expected: target_epoch,
                actual: actual_epoch,
            });
        }
        self.emit_event(EpochTransitionLogEvent {
            event_code: EPOCH_ADVANCED.to_string(),
            epoch_current: actual_epoch,
            epoch_artifact: Some(actual_epoch),
            transition_id: Some(pending.transition_id.clone()),
            service_id: Some(pending.initiator.clone()),
            transition_reason: Some(pending.reason.clone()),
            quiescence_status: Some("committed".to_string()),
            trace_id: trace_id.to_string(),
        });
        push_bounded(
            &mut self.history,
            EpochTransitionRecord {
                transition_id: pending.transition_id,
                pre_epoch: pending.pre_epoch,
                target_epoch: pending.target_epoch,
                initiator: pending.initiator,
                reason: pending.reason,
                timestamp_ms,
                outcome: "COMMITTED".to_string(),
                abort_reason: None,
                trace_id: trace_id.to_string(),
            },
            MAX_HISTORY_ENTRIES,
        );
        self.pending = None;
        Ok(actual_epoch)
    }

    pub fn abort_transition_timeout(
        &mut self,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<u64, EpochTransitionError> {
        let snapshot = self.active_barrier_snapshot()?;
        let pending = self
            .pending
            .clone()
            .ok_or(EpochTransitionError::NoActiveTransition)?;
        let elapsed_ms = timestamp_ms.saturating_sub(snapshot.propose_timestamp_ms);
        let missing = snapshot.missing_acks();
        let current_epoch = self.barrier.abort(
            AbortReason::Timeout {
                missing_participants: missing,
            },
            timestamp_ms,
            trace_id,
        )?;
        self.record_abort_outcome(
            snapshot,
            pending,
            TransitionAbortReason::Timeout { elapsed_ms },
            timestamp_ms,
            trace_id,
        );
        Ok(current_epoch)
    }

    pub fn abort_transition_cancellation(
        &mut self,
        source: &str,
        timestamp_ms: u64,
        trace_id: &str,
    ) -> Result<u64, EpochTransitionError> {
        let snapshot = self.active_barrier_snapshot()?;
        let pending = self
            .pending
            .clone()
            .ok_or(EpochTransitionError::NoActiveTransition)?;
        let current_epoch = self.barrier.abort(
            AbortReason::Cancelled {
                detail: source.to_string(),
            },
            timestamp_ms,
            trace_id,
        )?;
        self.record_abort_outcome(
            snapshot,
            pending,
            TransitionAbortReason::Cancellation {
                source: source.to_string(),
            },
            timestamp_ms,
            trace_id,
        );
        Ok(current_epoch)
    }

    fn record_abort_outcome(
        &mut self,
        snapshot: BarrierInstance,
        pending: PendingTransitionMetadata,
        reason: TransitionAbortReason,
        timestamp_ms: u64,
        trace_id: &str,
    ) {
        let elapsed_ms = timestamp_ms.saturating_sub(snapshot.propose_timestamp_ms);
        let participant_states =
            participant_states_from_snapshot(&snapshot, snapshot.current_epoch);
        let event = self.abort_manager.record_abort(
            &snapshot.barrier_id,
            reason.clone(),
            snapshot.current_epoch,
            snapshot.target_epoch,
            participant_states,
            elapsed_ms,
            timestamp_ms,
            trace_id,
        );
        self.emit_event(EpochTransitionLogEvent {
            event_code: EPOCH_TRANSITION_ABORTED.to_string(),
            epoch_current: snapshot.current_epoch,
            epoch_artifact: Some(snapshot.target_epoch),
            transition_id: Some(snapshot.barrier_id.clone()),
            service_id: Some(pending.initiator.clone()),
            transition_reason: Some(pending.reason.clone()),
            quiescence_status: Some("aborted".to_string()),
            trace_id: trace_id.to_string(),
        });
        push_bounded(
            &mut self.history,
            EpochTransitionRecord {
                transition_id: pending.transition_id,
                pre_epoch: pending.pre_epoch,
                target_epoch: pending.target_epoch,
                initiator: pending.initiator,
                reason: pending.reason,
                timestamp_ms: event.timestamp_ms,
                outcome: "ABORTED".to_string(),
                abort_reason: Some(reason.to_string()),
                trace_id: trace_id.to_string(),
            },
            MAX_HISTORY_ENTRIES,
        );
        self.pending = None;
    }

    fn active_barrier_snapshot(&self) -> Result<BarrierInstance, EpochTransitionError> {
        self.barrier
            .active_barrier()
            .cloned()
            .ok_or(EpochTransitionError::NoActiveTransition)
    }

    fn emit_event(&mut self, event: EpochTransitionLogEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }
}

impl Default for ProductEpochCoordinator {
    fn default() -> Self {
        Self::new(0, 1, BarrierConfig::default())
    }
}

fn participant_states_from_snapshot(
    snapshot: &BarrierInstance,
    current_epoch: u64,
) -> Vec<ParticipantAbortState> {
    snapshot
        .participants
        .iter()
        .map(|participant| ParticipantAbortState {
            participant_id: participant.clone(),
            had_acked: snapshot.acks.contains_key(participant),
            current_epoch,
            in_flight_items: if snapshot.acks.contains_key(participant) {
                0
            } else {
                1
            },
        })
        .collect::<Vec<_>>()
}

fn transition_abort_reason_from_barrier_reason(
    reason: &AbortReason,
    elapsed_ms: u64,
) -> TransitionAbortReason {
    match reason {
        AbortReason::Timeout { .. } => TransitionAbortReason::Timeout { elapsed_ms },
        AbortReason::DrainFailed {
            participant_id,
            detail,
        } => TransitionAbortReason::ParticipantFailure {
            participant_id: participant_id.clone(),
            detail: detail.clone(),
        },
        AbortReason::Cancelled { detail } => TransitionAbortReason::Cancellation {
            source: detail.clone(),
        },
    }
}

fn manifest_hash_for_transition(
    transition_id: &str,
    initiator: &str,
    reason: &str,
    target_epoch: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"epoch_transition_hash_v1:");
    // Length-prefixed encoding prevents delimiter-collision ambiguity.
    for field in [transition_id, initiator, reason] {
        hasher.update((u64::try_from(field.len()).unwrap_or(u64::MAX)).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.update(target_epoch.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_and_future_operations_are_rejected() {
        let mut coordinator = ProductEpochCoordinator::new(5, 1, BarrierConfig::default());
        let stale = coordinator
            .validate_operation_epoch("svc-a", 4, "trace-stale")
            .expect_err("stale must reject");
        assert_eq!(stale.code(), STALE_EPOCH_REJECTED);

        let future = coordinator
            .validate_operation_epoch("svc-a", 6, "trace-future")
            .expect_err("future must reject");
        assert_eq!(future.code(), FUTURE_EPOCH_REJECTED);
    }

    #[test]
    fn barrier_blocks_new_epoch_operations_until_commit() {
        let mut coordinator = ProductEpochCoordinator::new(10, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        coordinator.register_service("svc-b");

        let proposal = coordinator
            .propose_transition("operator-1", "rotation", 1_000, "trace-propose")
            .expect("should succeed");
        assert_eq!(proposal.pre_epoch, 10);
        assert_eq!(proposal.target_epoch, 11);

        let future = coordinator
            .validate_operation_epoch("svc-a", 11, "trace-before-commit")
            .expect_err("new epoch should be blocked pre-commit");
        assert_eq!(future.code(), FUTURE_EPOCH_REJECTED);

        coordinator
            .ack_drain("svc-a", 4, 25, "trace-ack-a")
            .expect("should succeed");
        coordinator
            .ack_drain("svc-b", 2, 30, "trace-ack-b")
            .expect("should succeed");
        let committed = coordinator
            .commit_transition(1_050, "trace-commit")
            .expect("should succeed");
        assert_eq!(committed, 11);
        assert_eq!(coordinator.current_epoch(), 11);
    }

    #[test]
    fn timeout_abort_keeps_pre_epoch_and_records_event() {
        let mut coordinator = ProductEpochCoordinator::new(3, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        coordinator.register_service("svc-b");
        coordinator.register_service("svc-c");
        coordinator
            .propose_transition("operator-1", "key-rotation", 1_000, "trace-propose")
            .expect("should succeed");
        coordinator
            .ack_drain("svc-a", 3, 10, "trace-ack-a")
            .expect("should succeed");

        let epoch_after_abort = coordinator
            .abort_transition_timeout(40_000, "trace-timeout")
            .expect("should succeed");
        assert_eq!(epoch_after_abort, 3);
        assert_eq!(coordinator.current_epoch(), 3);
        assert_eq!(coordinator.abort_manager().abort_count(), 1);
        assert_eq!(coordinator.history().len(), 1);
        assert_eq!(coordinator.history()[0].outcome, "ABORTED");
    }

    #[test]
    fn concurrent_proposals_are_serialized() {
        let mut coordinator = ProductEpochCoordinator::new(1, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        coordinator.register_service("svc-b");
        coordinator
            .propose_transition("operator-1", "rotation-a", 1_000, "trace-a")
            .expect("should succeed");
        let err = coordinator
            .propose_transition("operator-2", "rotation-b", 1_001, "trace-b")
            .expect_err("concurrent proposal must fail");
        assert_eq!(err.code(), "ERR_BARRIER_CONCURRENT");
    }

    #[test]
    fn replica_lag_guard_enforces_max_epoch_lag() {
        let mut coordinator = ProductEpochCoordinator::new(20, 2, BarrierConfig::default());
        // lag=1, max_epoch_lag=2 → 1 < 2 → OK
        coordinator
            .validate_replica_lag("svc-a", 19, "trace-lag-ok")
            .expect("should succeed");
        // lag=2, max_epoch_lag=2 → 2 >= 2 → fail-closed at boundary
        let err = coordinator
            .validate_replica_lag("svc-a", 18, "trace-lag-bad")
            .expect_err("lag at max should fail (fail-closed)");
        assert_eq!(err.code(), STALE_EPOCH_REJECTED);
    }

    #[test]
    fn five_service_quiescence_transition_commits() {
        let mut coordinator = ProductEpochCoordinator::new(30, 1, BarrierConfig::default());
        for service_id in ["svc-a", "svc-b", "svc-c", "svc-d", "svc-e"] {
            coordinator.register_service(service_id);
        }
        let proposal = coordinator
            .propose_transition(
                "operator-1",
                "planned-rotation",
                10_000,
                "trace-five-propose",
            )
            .expect("proposal succeeds");
        assert_eq!(proposal.pre_epoch, 30);
        assert_eq!(proposal.target_epoch, 31);

        coordinator
            .ack_drain("svc-a", 2, 5, "trace-five-a")
            .expect("svc-a drained");
        coordinator
            .ack_drain("svc-b", 3, 7, "trace-five-b")
            .expect("svc-b drained");
        coordinator
            .ack_drain("svc-c", 1, 9, "trace-five-c")
            .expect("svc-c drained");
        coordinator
            .ack_drain("svc-d", 4, 12, "trace-five-d")
            .expect("svc-d drained");
        coordinator
            .ack_drain("svc-e", 8, 30, "trace-five-e")
            .expect("svc-e drained");

        let committed = coordinator
            .commit_transition(10_040, "trace-five-commit")
            .expect("commit succeeds");
        assert_eq!(committed, 31);
        assert_eq!(coordinator.current_epoch(), 31);
    }

    #[test]
    fn epoch_transitions_are_monotonic_across_commits() {
        let mut coordinator = ProductEpochCoordinator::new(1, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");

        let mut observed = vec![coordinator.current_epoch()];
        for index in 0..3 {
            coordinator
                .propose_transition(
                    "operator-1",
                    "periodic-rotation",
                    1_000 + index,
                    "trace-monotonic-propose",
                )
                .expect("proposal succeeds");
            coordinator
                .ack_drain("svc-a", 1, 1, "trace-monotonic-ack")
                .expect("drain ack succeeds");
            let committed = coordinator
                .commit_transition(1_100 + index, "trace-monotonic-commit")
                .expect("commit succeeds");
            observed.push(committed);
        }
        assert_eq!(observed, vec![1, 2, 3, 4]);
    }

    #[test]
    fn history_records_commit_and_abort_metadata() {
        let mut coordinator = ProductEpochCoordinator::new(9, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        coordinator.register_service("svc-b");

        coordinator
            .propose_transition("operator-1", "rotation-1", 1_000, "trace-h1")
            .expect("proposal one succeeds");
        coordinator
            .ack_drain("svc-a", 1, 5, "trace-h1-a")
            .expect("svc-a drained");
        coordinator
            .ack_drain("svc-b", 1, 6, "trace-h1-b")
            .expect("svc-b drained");
        coordinator
            .commit_transition(1_010, "trace-h1-commit")
            .expect("commit succeeds");

        coordinator
            .propose_transition("operator-1", "rotation-2", 2_000, "trace-h2")
            .expect("proposal two succeeds");
        coordinator
            .ack_drain("svc-a", 1, 5, "trace-h2-a")
            .expect("svc-a drained");
        coordinator
            .abort_transition_timeout(40_000, "trace-h2-timeout")
            .expect("timeout abort succeeds");

        assert_eq!(coordinator.history().len(), 2);
        assert_eq!(coordinator.history()[0].outcome, "COMMITTED");
        assert_eq!(coordinator.history()[0].pre_epoch, 9);
        assert_eq!(coordinator.history()[0].target_epoch, 10);
        assert_eq!(coordinator.history()[1].outcome, "ABORTED");
        assert_eq!(coordinator.history()[1].pre_epoch, 10);
        assert_eq!(coordinator.history()[1].target_epoch, 11);
        assert!(coordinator.history()[1].abort_reason.is_some());
    }

    #[test]
    fn timed_out_commit_attempt_fails_closed_without_advancing_epoch() {
        let mut coordinator = ProductEpochCoordinator::new(7, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        coordinator.register_service("svc-b");

        coordinator
            .propose_transition("operator-1", "rotation", 1_000, "trace-propose")
            .expect("proposal succeeds");
        coordinator
            .ack_drain("svc-a", 1, 5, "trace-ack-a")
            .expect("svc-a drained");

        let err = coordinator
            .commit_transition(40_000, "trace-timeout-commit")
            .expect_err("timed out commit must fail closed");
        assert_eq!(err.code(), EPOCH_TRANSITION_COMMIT_ABORTED);
        assert_eq!(coordinator.current_epoch(), 7);
        assert_eq!(coordinator.abort_manager().abort_count(), 1);
        assert_eq!(coordinator.history().len(), 1);
        assert_eq!(coordinator.history()[0].outcome, "ABORTED");
        assert_eq!(coordinator.history()[0].pre_epoch, 7);
        assert_eq!(coordinator.history()[0].target_epoch, 8);

        let reproposal = coordinator
            .propose_transition("operator-2", "retry", 41_000, "trace-repropose")
            .expect("pending transition should be cleared after abort");
        assert_eq!(reproposal.pre_epoch, 7);
        assert_eq!(reproposal.target_epoch, 8);
    }

    #[test]
    fn commit_without_active_transition_returns_no_active_transition() {
        let mut coordinator = ProductEpochCoordinator::new(2, 1, BarrierConfig::default());

        let err = coordinator
            .commit_transition(1_000, "trace-no-active-commit")
            .expect_err("commit without proposal must fail");

        assert_eq!(err.code(), "EPOCH_TRANSITION_NO_ACTIVE");
        assert!(matches!(err, EpochTransitionError::NoActiveTransition));
        assert_eq!(coordinator.current_epoch(), 2);
        assert!(coordinator.history().is_empty());
    }

    #[test]
    fn ack_without_active_transition_returns_no_active_transition() {
        let mut coordinator = ProductEpochCoordinator::new(2, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");

        let err = coordinator
            .ack_drain("svc-a", 0, 0, "trace-no-active-ack")
            .expect_err("ack without proposal must fail");

        assert_eq!(err.code(), "EPOCH_TRANSITION_NO_ACTIVE");
        assert!(matches!(err, EpochTransitionError::NoActiveTransition));
        assert!(
            coordinator
                .events()
                .iter()
                .all(|event| event.event_code != EPOCH_DRAIN_CONFIRMED)
        );
    }

    #[test]
    fn abort_timeout_without_active_transition_returns_no_active_transition() {
        let mut coordinator = ProductEpochCoordinator::new(2, 1, BarrierConfig::default());

        let err = coordinator
            .abort_transition_timeout(2_000, "trace-no-active-timeout")
            .expect_err("timeout abort without proposal must fail");

        assert_eq!(err.code(), "EPOCH_TRANSITION_NO_ACTIVE");
        assert!(matches!(err, EpochTransitionError::NoActiveTransition));
        assert_eq!(coordinator.abort_manager().abort_count(), 0);
        assert!(coordinator.history().is_empty());
    }

    #[test]
    fn abort_cancellation_without_active_transition_returns_no_active_transition() {
        let mut coordinator = ProductEpochCoordinator::new(2, 1, BarrierConfig::default());

        let err = coordinator
            .abort_transition_cancellation("operator-cancel", 2_000, "trace-no-active-cancel")
            .expect_err("cancellation abort without proposal must fail");

        assert_eq!(err.code(), "EPOCH_TRANSITION_NO_ACTIVE");
        assert!(matches!(err, EpochTransitionError::NoActiveTransition));
        assert_eq!(coordinator.abort_manager().abort_count(), 0);
        assert!(coordinator.history().is_empty());
    }

    #[test]
    fn future_replica_lag_rejected_without_stale_event() {
        let mut coordinator = ProductEpochCoordinator::new(20, 2, BarrierConfig::default());

        let err = coordinator
            .validate_replica_lag("svc-a", 21, "trace-future-lag")
            .expect_err("future replica epoch must fail");

        assert_eq!(err.code(), FUTURE_EPOCH_REJECTED);
        assert!(
            coordinator
                .events()
                .iter()
                .all(|event| event.event_code != STALE_EPOCH_REJECTED)
        );
    }

    #[test]
    fn commit_without_all_acks_rejects_without_advancing_epoch() {
        let mut coordinator = ProductEpochCoordinator::new(4, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        coordinator.register_service("svc-b");
        coordinator
            .propose_transition(
                "operator-1",
                "partial-drain",
                1_000,
                "trace-partial-propose",
            )
            .expect("proposal succeeds");
        coordinator
            .ack_drain("svc-a", 1, 5, "trace-partial-ack-a")
            .expect("svc-a ack succeeds");

        let err = coordinator
            .commit_transition(1_100, "trace-partial-commit")
            .expect_err("commit must reject missing ack");

        assert_eq!(
            err.code(),
            crate::control_plane::epoch_transition_barrier::error_codes::ERR_BARRIER_NOT_ALL_ACKED
        );
        assert_eq!(coordinator.current_epoch(), 4);
        assert!(coordinator.history().is_empty());
        assert!(
            coordinator
                .events()
                .iter()
                .all(|event| event.event_code != EPOCH_ADVANCED)
        );
    }

    #[test]
    fn unknown_service_ack_is_rejected_without_confirming_drain() {
        let mut coordinator = ProductEpochCoordinator::new(4, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        coordinator
            .propose_transition("operator-1", "unknown-ack", 1_000, "trace-unknown-propose")
            .expect("proposal succeeds");

        let err = coordinator
            .ack_drain("svc-unknown", 1, 5, "trace-unknown-ack")
            .expect_err("unknown participant ack must fail");

        assert_eq!(
            err.code(),
            crate::control_plane::epoch_transition_barrier::error_codes::ERR_BARRIER_UNKNOWN_PARTICIPANT
        );
        assert!(coordinator.events().iter().all(|event| {
            event.event_code != EPOCH_DRAIN_CONFIRMED
                || event.service_id.as_deref() != Some("svc-unknown")
        }));
    }

    #[test]
    fn push_bounded_zero_capacity_discards_without_panicking() {
        let mut events = vec![EpochTransitionLogEvent {
            event_code: EPOCH_PROPOSED.to_string(),
            epoch_current: 1,
            epoch_artifact: Some(2),
            transition_id: Some("transition-old".to_string()),
            service_id: Some("svc-a".to_string()),
            transition_reason: Some("old".to_string()),
            quiescence_status: Some("proposed".to_string()),
            trace_id: "trace-old".to_string(),
        }];

        push_bounded(
            &mut events,
            EpochTransitionLogEvent {
                event_code: EPOCH_ADVANCED.to_string(),
                epoch_current: 2,
                epoch_artifact: Some(2),
                transition_id: Some("transition-new".to_string()),
                service_id: Some("svc-a".to_string()),
                transition_reason: Some("new".to_string()),
                quiescence_status: Some("committed".to_string()),
                trace_id: "trace-new".to_string(),
            },
            0,
        );

        assert!(events.is_empty());
    }

    #[test]
    fn proposal_without_registered_participants_is_rejected_without_events() {
        let mut coordinator = ProductEpochCoordinator::new(12, 1, BarrierConfig::default());

        let err = coordinator
            .propose_transition(
                "operator-1",
                "no-participants",
                1_000,
                "trace-no-participants",
            )
            .expect_err("proposal without participants must fail closed");

        assert_eq!(
            err.code(),
            crate::control_plane::epoch_transition_barrier::error_codes::ERR_BARRIER_NO_PARTICIPANTS
        );
        assert!(matches!(
            err,
            EpochTransitionError::Barrier(BarrierError::NoParticipants)
        ));
        assert_eq!(coordinator.current_epoch(), 12);
        assert!(coordinator.events().is_empty());
        assert!(coordinator.history().is_empty());
    }

    #[test]
    fn proposal_at_max_epoch_is_rejected_without_pending_state() {
        let mut coordinator = ProductEpochCoordinator::new(u64::MAX, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");

        let err = coordinator
            .propose_transition("operator-1", "overflow", 1_000, "trace-overflow")
            .expect_err("max epoch transition must fail before reusing epoch-scoped state");

        assert_eq!(
            err.code(),
            crate::control_plane::epoch_transition_barrier::error_codes::ERR_BARRIER_EPOCH_OVERFLOW
        );
        assert!(matches!(
            err,
            EpochTransitionError::Barrier(BarrierError::EpochOverflow { current: u64::MAX })
        ));
        assert_eq!(coordinator.current_epoch(), u64::MAX);
        assert!(coordinator.events().is_empty());
        assert!(coordinator.history().is_empty());
    }

    #[test]
    fn stale_operation_during_pending_transition_records_context() {
        let mut coordinator = ProductEpochCoordinator::new(9, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        let proposal = coordinator
            .propose_transition("operator-1", "stale-check", 1_000, "trace-propose")
            .expect("proposal should establish pending context");

        let err = coordinator
            .validate_operation_epoch("svc-runtime", 8, "trace-stale-operation")
            .expect_err("stale operation epoch must reject");

        assert_eq!(err.code(), STALE_EPOCH_REJECTED);
        let event = coordinator
            .events()
            .last()
            .expect("stale rejection should emit an event");
        assert_eq!(event.event_code, STALE_EPOCH_REJECTED);
        assert_eq!(
            event.transition_id.as_deref(),
            Some(proposal.transition_id.as_str())
        );
        assert_eq!(event.service_id.as_deref(), Some("svc-runtime"));
        assert_eq!(event.transition_reason.as_deref(), Some("stale-check"));
        assert_eq!(event.quiescence_status.as_deref(), Some("stale"));
        assert_eq!(event.epoch_artifact, Some(8));
    }

    #[test]
    fn future_operation_during_pending_transition_records_context() {
        let mut coordinator = ProductEpochCoordinator::new(9, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        let proposal = coordinator
            .propose_transition("operator-1", "future-check", 1_000, "trace-propose")
            .expect("proposal should establish pending context");

        let err = coordinator
            .validate_operation_epoch("svc-runtime", 10, "trace-future-operation")
            .expect_err("future operation epoch must reject before commit");

        assert_eq!(err.code(), FUTURE_EPOCH_REJECTED);
        let event = coordinator
            .events()
            .last()
            .expect("future rejection should emit an event");
        assert_eq!(event.event_code, FUTURE_EPOCH_REJECTED);
        assert_eq!(
            event.transition_id.as_deref(),
            Some(proposal.transition_id.as_str())
        );
        assert_eq!(event.service_id.as_deref(), Some("svc-runtime"));
        assert_eq!(event.transition_reason.as_deref(), Some("future-check"));
        assert_eq!(event.quiescence_status.as_deref(), Some("future"));
        assert_eq!(event.epoch_artifact, Some(10));
    }

    #[test]
    fn replica_lag_at_boundary_records_lag_exceeded_event() {
        let mut coordinator = ProductEpochCoordinator::new(20, 2, BarrierConfig::default());

        let err = coordinator
            .validate_replica_lag("svc-replica", 18, "trace-lag-boundary")
            .expect_err("lag equal to the configured maximum must fail closed");

        assert_eq!(err.code(), STALE_EPOCH_REJECTED);
        let event = coordinator
            .events()
            .last()
            .expect("lag rejection should emit an event");
        assert_eq!(event.event_code, STALE_EPOCH_REJECTED);
        assert_eq!(event.epoch_current, 20);
        assert_eq!(event.epoch_artifact, Some(18));
        assert_eq!(event.service_id.as_deref(), Some("svc-replica"));
        assert_eq!(event.transition_id, None);
        assert_eq!(event.transition_reason, None);
        assert_eq!(event.quiescence_status.as_deref(), Some("lag_exceeded"));
    }

    #[test]
    fn commit_after_cancellation_abort_returns_no_active_transition() {
        let mut coordinator = ProductEpochCoordinator::new(6, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        coordinator
            .propose_transition("operator-1", "cancel-before-commit", 1_000, "trace-propose")
            .expect("proposal should succeed");
        coordinator
            .abort_transition_cancellation("operator-cancel", 1_050, "trace-cancel")
            .expect("cancellation abort should clear pending transition");

        let err = coordinator
            .commit_transition(1_060, "trace-commit-after-cancel")
            .expect_err("commit after cancellation must fail closed");

        assert_eq!(err.code(), "EPOCH_TRANSITION_NO_ACTIVE");
        assert!(matches!(err, EpochTransitionError::NoActiveTransition));
        assert_eq!(coordinator.current_epoch(), 6);
        assert_eq!(coordinator.history().len(), 1);
        assert_eq!(coordinator.history()[0].outcome, "ABORTED");
    }

    #[test]
    fn ack_after_cancellation_abort_is_rejected_without_new_confirmation() {
        let mut coordinator = ProductEpochCoordinator::new(6, 1, BarrierConfig::default());
        coordinator.register_service("svc-a");
        coordinator
            .propose_transition("operator-1", "cancel-before-ack", 1_000, "trace-propose")
            .expect("proposal should succeed");
        coordinator
            .abort_transition_cancellation("operator-cancel", 1_050, "trace-cancel")
            .expect("cancellation abort should terminalize barrier");
        let confirmations_before = coordinator
            .events()
            .iter()
            .filter(|event| event.event_code == EPOCH_DRAIN_CONFIRMED)
            .count();

        let err = coordinator
            .ack_drain("svc-a", 0, 0, "trace-ack-after-cancel")
            .expect_err("ack after cancellation must fail closed");

        assert_eq!(
            err.code(),
            crate::control_plane::epoch_transition_barrier::error_codes::ERR_BARRIER_ALREADY_COMPLETE
        );
        let confirmations_after = coordinator
            .events()
            .iter()
            .filter(|event| event.event_code == EPOCH_DRAIN_CONFIRMED)
            .count();
        assert_eq!(confirmations_after, confirmations_before);
        assert_eq!(coordinator.current_epoch(), 6);
        assert_eq!(coordinator.history().len(), 1);
    }

    // === NEGATIVE-PATH ROBUSTNESS TESTS ===

    #[test]
    fn unicode_injection_in_identifiers_and_reasons_handled_safely() {
        let mut coordinator = ProductEpochCoordinator::new(1, 1, BarrierConfig::default());
        let malicious_service = "svc\u{202e}evil\u{200b}\u{0000}inject";
        let malicious_initiator = "operator\u{feff}\u{1f4a9}\u{2028}bypass";
        let malicious_reason = "reason\u{0085}\u{2029}\u{00ad}payload\u{061c}";
        let malicious_trace = "trace\u{034f}\u{180e}\u{200c}id";

        coordinator.register_service(malicious_service);

        // Unicode injection should not break proposal or validation
        let proposal = coordinator
            .propose_transition(malicious_initiator, malicious_reason, 1000, malicious_trace)
            .expect("unicode in identifiers should be handled safely");
        assert!(proposal.transition_id.len() > 0);

        // Validation with Unicode should work
        coordinator
            .validate_operation_epoch(malicious_service, 1, malicious_trace)
            .expect("unicode service validation should work");

        // Events should contain the Unicode safely
        assert!(!coordinator.events().is_empty());
        let event = &coordinator.events()[0];
        assert!(event.service_id.as_ref().unwrap().contains("svc"));
        assert!(event.transition_reason.as_ref().unwrap().contains("reason"));
    }

    #[test]
    fn extreme_timestamp_arithmetic_near_overflow_boundaries() {
        let mut coordinator = ProductEpochCoordinator::new(1, 1, BarrierConfig::default());
        coordinator.register_service("svc-boundary");

        // Test near u64::MAX boundaries
        let near_max = u64::MAX - 1000;
        let proposal = coordinator
            .propose_transition("operator", "boundary-test", near_max, "trace-near-max")
            .expect("near-max timestamp should work");

        // Arithmetic should be protected with saturating operations
        coordinator
            .ack_drain("svc-boundary", 1, 500, "trace-ack")
            .expect("ack should work with extreme timestamp");

        // Commit with overflow-prone timestamp
        let committed = coordinator
            .commit_transition(u64::MAX, "trace-max-commit")
            .expect("max timestamp commit should use saturating arithmetic");
        assert_eq!(committed, 2);

        // History should record extreme timestamp safely
        assert_eq!(coordinator.history().len(), 1);
        let record = &coordinator.history()[0];
        assert_eq!(record.timestamp_ms, u64::MAX);

        // Elapsed calculations should be saturating
        assert!(record.timestamp_ms >= near_max);
    }

    #[test]
    fn memory_pressure_with_massive_event_and_history_volumes() {
        let mut coordinator = ProductEpochCoordinator::new(1, 10000, BarrierConfig::default());
        coordinator.register_service("svc-pressure");

        // Force MAX_EVENTS overflow to test push_bounded robustness
        for i in 0..MAX_EVENTS + 1000 {
            coordinator
                .validate_operation_epoch("svc-pressure", 0, &format!("trace-{}", i))
                .expect_err("should reject stale");
        }

        // Events should be bounded to MAX_EVENTS
        assert!(coordinator.events().len() <= MAX_EVENTS);

        // Force MAX_HISTORY_ENTRIES overflow
        for i in 0..MAX_HISTORY_ENTRIES + 500 {
            let mut temp_coord = ProductEpochCoordinator::new(1, 1, BarrierConfig::default());
            temp_coord.register_service("svc-temp");

            // Create transition and commit to generate history
            temp_coord
                .propose_transition("op", "history-pressure", 1000 + i as u64, "trace")
                .expect("proposal should work");
            temp_coord
                .ack_drain("svc-temp", 1, 1, "trace")
                .expect("ack should work");

            // Transfer history entry to main coordinator
            if let Ok(epoch) = temp_coord.commit_transition(2000 + i as u64, "trace") {
                push_bounded(
                    &mut coordinator.history,
                    EpochTransitionRecord {
                        transition_id: format!("pressure-{}", i),
                        pre_epoch: epoch.saturating_sub(1),
                        target_epoch: epoch,
                        initiator: "pressure-test".to_string(),
                        reason: "memory-test".to_string(),
                        timestamp_ms: 1000 + i as u64,
                        outcome: "COMMITTED".to_string(),
                        abort_reason: None,
                        trace_id: format!("trace-{}", i),
                    },
                    MAX_HISTORY_ENTRIES,
                );
            }
        }

        // History should be bounded
        assert!(coordinator.history().len() <= MAX_HISTORY_ENTRIES);
    }

    #[test]
    fn malformed_service_registration_edge_cases() {
        let mut coordinator = ProductEpochCoordinator::new(5, 1, BarrierConfig::default());

        // Empty service ID
        coordinator.register_service("");

        // Very long service ID (potential DoS)
        let long_service = "a".repeat(100_000);
        coordinator.register_service(&long_service);

        // Null bytes in service ID
        coordinator.register_service("svc\0hidden");

        // Control characters
        coordinator.register_service("svc\n\r\t\x7f");

        // Proposal should handle all registered services
        let proposal = coordinator
            .propose_transition("operator", "malformed-test", 1000, "trace")
            .expect("should handle malformed service IDs");

        // Should be able to validate operations against any service
        coordinator
            .validate_operation_epoch("", 5, "trace-empty")
            .expect("empty service should work");
        coordinator
            .validate_operation_epoch(&long_service, 5, "trace-long")
            .expect("long service should work");
        coordinator
            .validate_operation_epoch("svc\0hidden", 5, "trace-null")
            .expect("null-containing service should work");

        // Events should contain all the weird service IDs safely
        assert!(!coordinator.events().is_empty());
    }

    #[test]
    fn concurrent_epoch_arithmetic_boundary_conditions() {
        // Test epoch 0 boundaries
        let mut coord_zero = ProductEpochCoordinator::new(0, u64::MAX, BarrierConfig::default());
        coord_zero.register_service("svc-zero");

        // Should handle epoch 0 -> 1 transition
        let proposal = coord_zero
            .propose_transition("op-zero", "from-zero", 1000, "trace-zero")
            .expect("epoch 0 should transition to 1");
        assert_eq!(proposal.pre_epoch, 0);
        assert_eq!(proposal.target_epoch, 1);

        // Test near-max epoch lag calculations
        let mut coord_lag = ProductEpochCoordinator::new(u64::MAX - 100, u64::MAX, BarrierConfig::default());

        // Should handle extreme lag validation without overflow
        coord_lag
            .validate_replica_lag("svc-lag", 0, "trace-extreme-lag")
            .expect_err("extreme lag should be rejected");

        // Lag calculation should use saturating arithmetic
        coord_lag
            .validate_replica_lag("svc-lag", u64::MAX - 200, "trace-normal-lag")
            .expect("reasonable lag should work");

        // Edge case: exactly at max lag boundary
        let mut coord_boundary = ProductEpochCoordinator::new(100, 50, BarrierConfig::default());
        coord_boundary
            .validate_replica_lag("svc-boundary", 50, "trace-boundary")
            .expect_err("at-boundary lag should fail (fail-closed)");
        coord_boundary
            .validate_replica_lag("svc-boundary", 51, "trace-just-under")
            .expect("just-under-boundary should work");
    }

    #[test]
    fn manifest_hash_collision_resistance_edge_cases() {
        // Test hash collision scenarios with carefully crafted inputs
        let hash1 = manifest_hash_for_transition(
            "transition_id_1",
            "initiator_a",
            "reason_x",
            100,
        );

        // Different field arrangement that could collide without length prefixing
        let hash2 = manifest_hash_for_transition(
            "transition_id",
            "_1initiator_a",
            "reason_x",
            100,
        );

        // Should be different due to length prefixing
        assert_ne!(hash1, hash2, "length prefixing should prevent delimiter collision");

        // Test with embedded delimiter-like content
        let hash3 = manifest_hash_for_transition(
            "transition:id",
            "init|iator",
            "reason;with;delims",
            u64::MAX,
        );

        let hash4 = manifest_hash_for_transition(
            "transition",
            "id:init|iator",
            "reason;with;delims",
            u64::MAX,
        );

        assert_ne!(hash3, hash4, "embedded delimiters should not cause collision");

        // Test extreme epoch values
        let hash_min = manifest_hash_for_transition("a", "b", "c", 0);
        let hash_max = manifest_hash_for_transition("a", "b", "c", u64::MAX);
        assert_ne!(hash_min, hash_max);

        // Test empty strings
        let hash_empty = manifest_hash_for_transition("", "", "", 1);
        let hash_space = manifest_hash_for_transition(" ", " ", " ", 1);
        assert_ne!(hash_empty, hash_space);
    }

    #[test]
    fn abort_cascades_and_state_consistency_edge_cases() {
        let mut coordinator = ProductEpochCoordinator::new(10, 1, BarrierConfig::default());
        coordinator.register_service("svc-cascade");

        // Start multiple cascading operations
        coordinator
            .propose_transition("op1", "cascade-test", 1000, "trace-1")
            .expect("first proposal should work");

        // Timeout abort should clear all pending state
        coordinator
            .abort_transition_timeout(40000, "trace-timeout")
            .expect("timeout should work");

        assert!(coordinator.pending.is_none(), "pending should be cleared");
        assert_eq!(coordinator.abort_manager().abort_count(), 1);

        // Should be able to immediately propose again
        let proposal2 = coordinator
            .propose_transition("op2", "after-abort", 41000, "trace-2")
            .expect("post-abort proposal should work");
        assert_eq!(proposal2.pre_epoch, 10); // Should not have advanced

        // Cancellation abort during drain phase
        coordinator
            .abort_transition_cancellation("emergency", 42000, "trace-cancel")
            .expect("cancellation should work");

        assert!(coordinator.pending.is_none(), "pending should be cleared again");
        assert_eq!(coordinator.abort_manager().abort_count(), 2);

        // History should record both aborts
        assert_eq!(coordinator.history().len(), 2);
        assert!(coordinator.history().iter().all(|h| h.outcome == "ABORTED"));

        // Events should show proper abort sequence
        let abort_events: Vec<_> = coordinator
            .events()
            .iter()
            .filter(|e| e.event_code == EPOCH_TRANSITION_ABORTED)
            .collect();
        assert_eq!(abort_events.len(), 2);
    }

    #[test]
    fn error_propagation_and_fail_closed_semantics() {
        let mut coordinator = ProductEpochCoordinator::new(5, 1, BarrierConfig::default());
        coordinator.register_service("svc-error");

        // Test commit failure propagation
        coordinator
            .propose_transition("op", "error-test", 1000, "trace-error")
            .expect("proposal should work");

        // Partial ack then force timeout to test commit failure
        coordinator
            .ack_drain("svc-error", 100, 50, "trace-ack")
            .expect("ack should work");

        // Force a commit timeout by waiting
        let err = coordinator
            .commit_transition(50000, "trace-late-commit")
            .expect_err("late commit should auto-abort");

        assert_eq!(err.code(), EPOCH_TRANSITION_COMMIT_ABORTED);
        assert_eq!(coordinator.current_epoch(), 5); // Should not advance

        // Test error chain propagation - operation after failed commit
        let stale_err = coordinator
            .validate_operation_epoch("svc-error", 6, "trace-post-fail")
            .expect_err("future epoch should still be rejected");
        assert_eq!(stale_err.code(), FUTURE_EPOCH_REJECTED);

        // Test validation with epoch exactly at boundary conditions
        coordinator
            .validate_operation_epoch("svc-error", 5, "trace-current")
            .expect("current epoch should work");

        // Test error when no participants registered (fail-closed)
        let mut empty_coord = ProductEpochCoordinator::new(1, 1, BarrierConfig::default());
        let err = empty_coord
            .propose_transition("op", "empty", 1000, "trace")
            .expect_err("no participants should fail closed");

        assert!(matches!(err, EpochTransitionError::Barrier(_)));
        assert_eq!(empty_coord.current_epoch(), 1); // Should not change
        assert!(empty_coord.events().is_empty()); // Should not emit events
    }
}
