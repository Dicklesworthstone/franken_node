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
    AbortReason, BarrierConfig, BarrierError, BarrierInstance, DrainAck, EpochTransitionBarrier,
};
use crate::control_plane::transition_abort::{
    ParticipantAbortState, TransitionAbortManager, TransitionAbortReason,
};

pub const EPOCH_PROPOSED: &str = "EPOCH_PROPOSED";
pub const EPOCH_DRAIN_REQUESTED: &str = "EPOCH_DRAIN_REQUESTED";
pub const EPOCH_DRAIN_CONFIRMED: &str = "EPOCH_DRAIN_CONFIRMED";
pub const EPOCH_ADVANCED: &str = "EPOCH_ADVANCED";
pub const STALE_EPOCH_REJECTED: &str = "STALE_EPOCH_REJECTED";
pub const FUTURE_EPOCH_REJECTED: &str = "FUTURE_EPOCH_REJECTED";
pub const EPOCH_TRANSITION_ABORTED: &str = "EPOCH_TRANSITION_ABORTED";

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
            self.events.push(EpochTransitionLogEvent {
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
            self.events.push(EpochTransitionLogEvent {
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
        if current.saturating_sub(observed_epoch) > self.max_epoch_lag {
            self.events.push(EpochTransitionLogEvent {
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
        self.events.push(EpochTransitionLogEvent {
            event_code: EPOCH_PROPOSED.to_string(),
            epoch_current: current,
            epoch_artifact: Some(target),
            transition_id: Some(proposal.transition_id.clone()),
            service_id: Some(initiator.to_string()),
            transition_reason: Some(reason.to_string()),
            quiescence_status: Some("proposed".to_string()),
            trace_id: trace_id.to_string(),
        });
        for participant in instance.participants.iter().cloned() {
            self.events.push(EpochTransitionLogEvent {
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
        self.events.push(EpochTransitionLogEvent {
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
        let target_epoch = self.barrier.try_commit(timestamp_ms, trace_id)?;
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
        self.events.push(EpochTransitionLogEvent {
            event_code: EPOCH_ADVANCED.to_string(),
            epoch_current: actual_epoch,
            epoch_artifact: Some(actual_epoch),
            transition_id: Some(pending.transition_id.clone()),
            service_id: Some(pending.initiator.clone()),
            transition_reason: Some(pending.reason.clone()),
            quiescence_status: Some("committed".to_string()),
            trace_id: trace_id.to_string(),
        });
        self.history.push(EpochTransitionRecord {
            transition_id: pending.transition_id,
            pre_epoch: pending.pre_epoch,
            target_epoch: pending.target_epoch,
            initiator: pending.initiator,
            reason: pending.reason,
            timestamp_ms,
            outcome: "COMMITTED".to_string(),
            abort_reason: None,
            trace_id: trace_id.to_string(),
        });
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
        self.events.push(EpochTransitionLogEvent {
            event_code: EPOCH_TRANSITION_ABORTED.to_string(),
            epoch_current: snapshot.current_epoch,
            epoch_artifact: Some(snapshot.target_epoch),
            transition_id: Some(snapshot.barrier_id.clone()),
            service_id: Some(pending.initiator.clone()),
            transition_reason: Some(pending.reason.clone()),
            quiescence_status: Some("aborted".to_string()),
            trace_id: trace_id.to_string(),
        });
        self.history.push(EpochTransitionRecord {
            transition_id: pending.transition_id,
            pre_epoch: pending.pre_epoch,
            target_epoch: pending.target_epoch,
            initiator: pending.initiator,
            reason: pending.reason,
            timestamp_ms: event.timestamp_ms,
            outcome: "ABORTED".to_string(),
            abort_reason: Some(reason.to_string()),
            trace_id: trace_id.to_string(),
        });
        self.pending = None;
    }

    fn active_barrier_snapshot(&self) -> Result<BarrierInstance, EpochTransitionError> {
        self.barrier
            .active_barrier()
            .cloned()
            .ok_or(EpochTransitionError::NoActiveTransition)
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

fn manifest_hash_for_transition(
    transition_id: &str,
    initiator: &str,
    reason: &str,
    target_epoch: u64,
) -> String {
    let canonical = format!("epoch-manifest|{transition_id}|{initiator}|{reason}|{target_epoch}");
    let digest = Sha256::digest(canonical.as_bytes());
    format!("{digest:x}")
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
            .unwrap();
        assert_eq!(proposal.pre_epoch, 10);
        assert_eq!(proposal.target_epoch, 11);

        let future = coordinator
            .validate_operation_epoch("svc-a", 11, "trace-before-commit")
            .expect_err("new epoch should be blocked pre-commit");
        assert_eq!(future.code(), FUTURE_EPOCH_REJECTED);

        coordinator
            .ack_drain("svc-a", 4, 25, "trace-ack-a")
            .unwrap();
        coordinator
            .ack_drain("svc-b", 2, 30, "trace-ack-b")
            .unwrap();
        let committed = coordinator
            .commit_transition(1_050, "trace-commit")
            .unwrap();
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
            .unwrap();
        coordinator
            .ack_drain("svc-a", 3, 10, "trace-ack-a")
            .unwrap();

        let epoch_after_abort = coordinator
            .abort_transition_timeout(40_000, "trace-timeout")
            .unwrap();
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
            .unwrap();
        let err = coordinator
            .propose_transition("operator-2", "rotation-b", 1_001, "trace-b")
            .expect_err("concurrent proposal must fail");
        assert_eq!(err.code(), "ERR_BARRIER_CONCURRENT");
    }

    #[test]
    fn replica_lag_guard_enforces_max_epoch_lag() {
        let mut coordinator = ProductEpochCoordinator::new(20, 1, BarrierConfig::default());
        coordinator
            .validate_replica_lag("svc-a", 19, "trace-lag-ok")
            .unwrap();
        let err = coordinator
            .validate_replica_lag("svc-a", 18, "trace-lag-bad")
            .expect_err("lag beyond max should fail");
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
}
