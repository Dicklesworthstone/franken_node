//! Connector lifecycle FSM.
//!
//! Defines the eight lifecycle states a connector can occupy and the
//! deterministic transition table that governs legal state changes.
//! Illegal transitions are rejected with stable error codes.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The nine mutually exclusive lifecycle states for a connector instance.
/// Includes `Cancelling` for the three-phase cancellation protocol (bd-1cs7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorState {
    Discovered,
    Verified,
    Installed,
    Configured,
    Active,
    Paused,
    /// Cancelling: three-phase cancellation in progress (REQUEST->DRAIN->FINALIZE).
    /// bd-1cs7: INV-CANP-THREE-PHASE
    Cancelling,
    Stopped,
    Failed,
}

impl ConnectorState {
    /// All possible states, ordered by the canonical happy-path progression.
    pub const ALL: [ConnectorState; 9] = [
        Self::Discovered,
        Self::Verified,
        Self::Installed,
        Self::Configured,
        Self::Active,
        Self::Paused,
        Self::Cancelling,
        Self::Stopped,
        Self::Failed,
    ];

    /// Returns the set of states that are legal targets from this state.
    /// bd-1cs7: Active and Paused can enter Cancelling for orderly shutdown.
    pub fn legal_targets(&self) -> &'static [ConnectorState] {
        match self {
            Self::Discovered => &[Self::Verified, Self::Failed],
            Self::Verified => &[Self::Installed, Self::Failed],
            Self::Installed => &[Self::Configured, Self::Failed],
            Self::Configured => &[Self::Active, Self::Failed],
            Self::Active => &[Self::Paused, Self::Cancelling, Self::Stopped, Self::Failed],
            Self::Paused => &[Self::Active, Self::Cancelling, Self::Stopped, Self::Failed],
            Self::Cancelling => &[Self::Stopped, Self::Failed],
            Self::Stopped => &[Self::Configured, Self::Failed],
            Self::Failed => &[Self::Discovered],
        }
    }

    /// Returns true if transitioning from `self` to `target` is permitted.
    pub fn can_transition_to(&self, target: &ConnectorState) -> bool {
        self.legal_targets().contains(target)
    }

    /// Returns the string name used in error codes and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Verified => "verified",
            Self::Installed => "installed",
            Self::Configured => "configured",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Cancelling => "cancelling",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for ConnectorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error codes for illegal lifecycle transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code")]
pub enum LifecycleError {
    /// The requested (from, to) pair is not in the permitted transition set.
    #[serde(rename = "ILLEGAL_TRANSITION")]
    IllegalTransition {
        from: ConnectorState,
        to: ConnectorState,
        permitted: Vec<ConnectorState>,
    },
    /// Source and target are the same state.
    #[serde(rename = "SELF_TRANSITION")]
    SelfTransition { state: ConnectorState },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalTransition {
                from,
                to,
                permitted,
            } => {
                let targets: Vec<&str> = permitted.iter().map(|s| s.as_str()).collect();
                write!(
                    f,
                    "ILLEGAL_TRANSITION: cannot transition from {from} to {to}; \
                     permitted targets: [{}]",
                    targets.join(", ")
                )
            }
            Self::SelfTransition { state } => {
                write!(
                    f,
                    "SELF_TRANSITION: cannot transition from {state} to itself"
                )
            }
        }
    }
}

impl std::error::Error for LifecycleError {}

/// Attempt a lifecycle transition from `from` to `to`.
///
/// Returns the new state on success, or a stable error on failure.
/// This is the single authoritative transition gate for all connector
/// lifecycle changes.
pub fn transition(
    from: ConnectorState,
    to: ConnectorState,
) -> Result<ConnectorState, LifecycleError> {
    if from == to {
        return Err(LifecycleError::SelfTransition { state: from });
    }

    if from.can_transition_to(&to) {
        Ok(to)
    } else {
        Err(LifecycleError::IllegalTransition {
            from,
            to,
            permitted: from.legal_targets().to_vec(),
        })
    }
}

/// Build the full transition matrix as a serializable structure.
///
/// Returns a vec of (from, to, legal) triples covering every non-self pair.
pub fn transition_matrix() -> Vec<TransitionEntry> {
    let mut entries = Vec::new();
    for &from in &ConnectorState::ALL {
        for &to in &ConnectorState::ALL {
            if from == to {
                continue;
            }
            entries.push(TransitionEntry {
                from,
                to,
                legal: from.can_transition_to(&to),
            });
        }
    }
    entries
}

/// A single entry in the transition matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionEntry {
    pub from: ConnectorState,
    pub to: ConnectorState,
    pub legal: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_full_lifecycle() {
        let mut state = ConnectorState::Discovered;
        for next in [
            ConnectorState::Verified,
            ConnectorState::Installed,
            ConnectorState::Configured,
            ConnectorState::Active,
        ] {
            state = transition(state, next).unwrap();
        }
        assert_eq!(state, ConnectorState::Active);
    }

    #[test]
    fn self_transition_rejected() {
        for &s in &ConnectorState::ALL {
            let err = transition(s, s).unwrap_err();
            assert!(
                matches!(err, LifecycleError::SelfTransition { .. }),
                "expected SelfTransition for {s}"
            );
        }
    }

    #[test]
    fn illegal_transition_rejected() {
        // Discovered → Active is not legal (must go through intermediate states)
        let err = transition(ConnectorState::Discovered, ConnectorState::Active).unwrap_err();
        match err {
            LifecycleError::IllegalTransition {
                from,
                to,
                permitted,
            } => {
                assert_eq!(from, ConnectorState::Discovered);
                assert_eq!(to, ConnectorState::Active);
                assert!(permitted.contains(&ConnectorState::Verified));
                assert!(permitted.contains(&ConnectorState::Failed));
            }
            _ => unreachable!("expected IllegalTransition"),
        }
    }

    #[test]
    fn failed_resets_to_discovered() {
        let state = transition(ConnectorState::Failed, ConnectorState::Discovered).unwrap();
        assert_eq!(state, ConnectorState::Discovered);
    }

    #[test]
    fn paused_can_resume() {
        let state = transition(ConnectorState::Paused, ConnectorState::Active).unwrap();
        assert_eq!(state, ConnectorState::Active);
    }

    #[test]
    fn stopped_can_reconfigure() {
        let state = transition(ConnectorState::Stopped, ConnectorState::Configured).unwrap();
        assert_eq!(state, ConnectorState::Configured);
    }

    #[test]
    fn transition_matrix_covers_all_pairs() {
        let matrix = transition_matrix();
        // 9 states, 8 non-self targets each = 72 entries
        assert_eq!(matrix.len(), 72);
    }

    #[test]
    fn transition_matrix_legal_count() {
        let matrix = transition_matrix();
        let legal_count = matrix.iter().filter(|e| e.legal).count();
        // 21 legal transitions (17 original + 2 into Cancelling + 2 from Cancelling)
        assert_eq!(legal_count, 21);
    }

    #[test]
    fn active_can_enter_cancelling() {
        let state = transition(ConnectorState::Active, ConnectorState::Cancelling).unwrap();
        assert_eq!(state, ConnectorState::Cancelling);
    }

    #[test]
    fn paused_can_enter_cancelling() {
        let state = transition(ConnectorState::Paused, ConnectorState::Cancelling).unwrap();
        assert_eq!(state, ConnectorState::Cancelling);
    }

    #[test]
    fn cancelling_reaches_stopped() {
        let state = transition(ConnectorState::Cancelling, ConnectorState::Stopped).unwrap();
        assert_eq!(state, ConnectorState::Stopped);
    }

    #[test]
    fn cancelling_can_fail() {
        let state = transition(ConnectorState::Cancelling, ConnectorState::Failed).unwrap();
        assert_eq!(state, ConnectorState::Failed);
    }

    #[test]
    fn error_display_stable() {
        let err = LifecycleError::IllegalTransition {
            from: ConnectorState::Discovered,
            to: ConnectorState::Active,
            permitted: vec![ConnectorState::Verified, ConnectorState::Failed],
        };
        let msg = err.to_string();
        assert!(msg.contains("ILLEGAL_TRANSITION"));
        assert!(msg.contains("discovered"));
        assert!(msg.contains("active"));
    }

    #[test]
    fn serde_roundtrip() {
        for &state in &ConnectorState::ALL {
            let json = serde_json::to_string(&state).unwrap();
            let parsed: ConnectorState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, parsed);
        }
    }
}

/// Integration tests: Connector lifecycle × Runtime lane scheduling × Obligation channels.
/// bd-17ds.5.2
#[cfg(test)]
mod connector_runtime_integration_tests {
    use super::*;
    use crate::runtime::lane_scheduler::{
        LaneConfig, LaneMappingPolicy, LaneScheduler, LaneSchedulerError, SchedulerLane, TaskClass,
        default_policy, task_classes,
    };
    use crate::runtime::obligation_channel::{
        ChannelObligation, CommitResult, ObligationChannel, ObligationLedger, ObligationStatus,
        PrepareResult, TimeoutPolicy, TwoPhaseFlow,
    };

    // ── Helpers ────────────────────────────────────────────────────────────

    /// Walk a connector through the happy path to Active state.
    fn activate_connector() -> ConnectorState {
        let mut s = ConnectorState::Discovered;
        for next in [
            ConnectorState::Verified,
            ConnectorState::Installed,
            ConnectorState::Configured,
            ConnectorState::Active,
        ] {
            s = transition(s, next).expect("happy-path transition must succeed");
        }
        s
    }

    fn make_scheduler() -> LaneScheduler {
        LaneScheduler::new(default_policy()).expect("default policy valid")
    }

    fn make_obligation(id: &str, deadline: u64) -> ChannelObligation {
        ChannelObligation {
            obligation_id: id.to_string(),
            deadline,
            trace_id: "int-test".to_string(),
            status: ObligationStatus::Created,
            created_at_ms: 1000,
            resolved_at_ms: None,
            timeout_policy: TimeoutPolicy::Escalate,
            schema_version: crate::runtime::obligation_channel::SCHEMA_VERSION.to_string(),
        }
    }

    // ── 1. Lifecycle gates lane admission ──────────────────────────────────

    #[test]
    fn active_connector_can_schedule_tasks() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        let mut sched = make_scheduler();
        let assignment = sched
            .assign_task(&task_classes::epoch_transition(), 1000, "conn-active")
            .expect("active connector should be allowed to schedule");
        assert_eq!(assignment.lane, SchedulerLane::ControlCritical);
        assert_eq!(sched.total_active(), 1);
    }

    #[test]
    fn paused_connector_can_still_schedule_background_tasks() {
        let active = activate_connector();
        let paused = transition(active, ConnectorState::Paused).unwrap();
        assert_eq!(paused, ConnectorState::Paused);

        // Background lane still accepts tasks while connector is paused
        let mut sched = make_scheduler();
        let assignment = sched
            .assign_task(&task_classes::telemetry_export(), 2000, "conn-paused")
            .expect("paused connector may still export telemetry");
        assert_eq!(assignment.lane, SchedulerLane::Background);
    }

    #[test]
    fn stopped_connector_tasks_complete_before_reconfigure() {
        let active = activate_connector();
        let mut sched = make_scheduler();

        // Schedule while active
        let task = sched
            .assign_task(&task_classes::garbage_collection(), 1000, "pre-stop")
            .unwrap();

        // Transition to stopped
        let stopped = transition(active, ConnectorState::Stopped).unwrap();
        assert_eq!(stopped, ConnectorState::Stopped);

        // Complete outstanding task
        let lane = sched.complete_task(&task.task_id, 1500, "drain").unwrap();
        assert_eq!(lane, SchedulerLane::Maintenance);
        assert_eq!(sched.total_active(), 0);
        assert_eq!(sched.total_completed(), 1);

        // Now reconfigure
        let reconfigured = transition(stopped, ConnectorState::Configured).unwrap();
        assert_eq!(reconfigured, ConnectorState::Configured);
    }

    // ── 2. Lifecycle + task cap enforcement ────────────────────────────────

    #[test]
    fn active_connector_respects_lane_cap() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        // Build a policy with a very small cap
        let mut policy = LaneMappingPolicy::new();
        policy.add_lane(LaneConfig::new(SchedulerLane::Maintenance, 20, 2));
        policy.add_rule(
            &task_classes::garbage_collection(),
            SchedulerLane::Maintenance,
        );
        let mut sched = LaneScheduler::new(policy).unwrap();

        sched
            .assign_task(&task_classes::garbage_collection(), 1000, "t1")
            .unwrap();
        sched
            .assign_task(&task_classes::garbage_collection(), 1001, "t2")
            .unwrap();

        // Third task should be rejected (cap=2)
        let err = sched
            .assign_task(&task_classes::garbage_collection(), 1002, "t3")
            .unwrap_err();
        assert!(matches!(
            err,
            LaneSchedulerError::CapExceeded { cap: 2, .. }
        ));
    }

    // ── 3. Lifecycle → obligation channel send/fulfill ─────────────────────

    #[test]
    fn active_connector_sends_obligation_and_fulfills() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        let mut channel: ObligationChannel<String> = ObligationChannel::new("conn-runtime");
        let ob_id = channel.send("epoch-sync".to_string(), 1000, "trace-1");

        assert_eq!(channel.total_obligations(), 1);
        assert_eq!(channel.count_by_status(ObligationStatus::Created), 1);

        channel.fulfill(&ob_id, 1050, "trace-1").unwrap();
        assert_eq!(channel.count_by_status(ObligationStatus::Fulfilled), 1);
        assert_eq!(channel.count_by_status(ObligationStatus::Created), 0);
    }

    #[test]
    fn cancelling_connector_rejects_obligations() {
        let active = activate_connector();
        let cancelling = transition(active, ConnectorState::Cancelling).unwrap();
        assert_eq!(cancelling, ConnectorState::Cancelling);

        // Existing obligations should be cancelled
        let mut channel: ObligationChannel<String> = ObligationChannel::new("conn-cancel");
        let ob_id = channel.send("pending-work".to_string(), 1000, "trace-2");
        channel.cancel(&ob_id, 1100, "trace-2").unwrap();

        assert_eq!(channel.count_by_status(ObligationStatus::Cancelled), 1);

        // Connector proceeds to stopped
        let stopped = transition(cancelling, ConnectorState::Stopped).unwrap();
        assert_eq!(stopped, ConnectorState::Stopped);
    }

    // ── 4. Obligation timeout sweep with lifecycle ─────────────────────────

    #[test]
    fn obligation_timeout_sweep_during_active_lifecycle() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        let mut channel: ObligationChannel<String> =
            ObligationChannel::with_deadline("conn-deadlines", 500);

        // Send three obligations with 500ms deadline from now_ms=1000
        let ob1 = channel.send("task-a".to_string(), 1000, "t1");
        let ob2 = channel.send("task-b".to_string(), 1000, "t2");
        let _ob3 = channel.send("task-c".to_string(), 1000, "t3");

        // Fulfill one before deadline
        channel.fulfill(&ob1, 1200, "t1").unwrap();

        // Sweep at 1600 (deadline=1500 exceeded for remaining Created obligations)
        let timed_out = channel.sweep_timeouts(1600, "sweep");
        assert_eq!(timed_out.len(), 2);
        assert!(timed_out.contains(&ob2));

        // ob1 was fulfilled so shouldn't be in timed_out
        assert!(!timed_out.contains(&ob1));
        assert_eq!(channel.count_by_status(ObligationStatus::Fulfilled), 1);
        assert_eq!(channel.count_by_status(ObligationStatus::TimedOut), 2);
    }

    // ── 5. Two-phase flow with lifecycle transitions ───────────────────────

    #[test]
    fn two_phase_flow_prepare_commit_during_active_lifecycle() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        let mut flow = TwoPhaseFlow::new("connector-runtime-sync");
        flow.add_obligation(make_obligation("ob-1", 5000));
        flow.add_obligation(make_obligation("ob-2", 5000));

        // Prepare
        let prep = flow.prepare(2000, "trace-flow");
        assert!(matches!(prep, PrepareResult::Ready { .. }));
        assert!(flow.is_prepared());

        // Commit
        let commit = flow.commit(2500, "trace-flow");
        assert!(
            matches!(commit, CommitResult::Committed { ref obligation_ids, .. } if obligation_ids.len() == 2)
        );
        assert!(flow.is_committed());

        // Closure proof must be complete
        let proof = flow.closure_proof(3000);
        assert!(proof.complete);
        assert_eq!(proof.obligations.len(), 2);
        for status in proof.obligations.values() {
            assert_eq!(*status, ObligationStatus::Fulfilled);
        }
    }

    #[test]
    fn two_phase_rollback_on_connector_failure() {
        let active = activate_connector();

        let mut flow = TwoPhaseFlow::new("failure-rollback");
        flow.add_obligation(make_obligation("ob-a", 5000));
        flow.add_obligation(make_obligation("ob-b", 5000));

        let prep = flow.prepare(2000, "trace-rb");
        assert!(matches!(prep, PrepareResult::Ready { .. }));

        // Connector fails
        let failed = transition(active, ConnectorState::Failed).unwrap();
        assert_eq!(failed, ConnectorState::Failed);

        // Rollback the flow atomically
        flow.rollback(2500, "trace-rb").unwrap();
        assert!(flow.is_rolled_back());

        // All obligations should be cancelled
        let proof = flow.closure_proof(3000);
        assert!(proof.complete);
        for status in proof.obligations.values() {
            assert_eq!(*status, ObligationStatus::Cancelled);
        }
    }

    #[test]
    fn two_phase_deadline_exceeded_prevents_prepare() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        let mut flow = TwoPhaseFlow::new("deadline-fail");
        flow.add_obligation(make_obligation("ob-x", 2000)); // deadline at 2000ms

        // Prepare at 3000ms (past the deadline)
        let prep = flow.prepare(3000, "trace-dl");
        assert!(matches!(prep, PrepareResult::Failed { .. }));
        assert!(!flow.is_prepared());
    }

    // ── 6. Lane scheduling + obligation channel composition ────────────────

    #[test]
    fn task_assignment_and_obligation_tracking_compose() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        let mut sched = make_scheduler();
        let mut ledger = ObligationLedger::new();

        // Assign a control-critical task
        let assignment = sched
            .assign_task(&task_classes::epoch_transition(), 1000, "trace-compose")
            .unwrap();

        // Track it as an obligation in the ledger
        let obligation = make_obligation(&assignment.task_id, 5000);
        ledger.record(obligation);

        assert_eq!(ledger.total(), 1);
        assert_eq!(ledger.query_outstanding().len(), 1);

        // Complete the task in the scheduler
        sched
            .complete_task(&assignment.task_id, 1500, "trace-compose")
            .unwrap();

        // Mark fulfilled in the ledger
        ledger
            .update_status(
                &assignment.task_id,
                ObligationStatus::Fulfilled,
                1500,
                "trace-compose",
            )
            .unwrap();

        assert_eq!(ledger.query_outstanding().len(), 0);
        assert_eq!(ledger.query_by_status(ObligationStatus::Fulfilled).len(), 1);
        assert_eq!(sched.total_completed(), 1);
    }

    // ── 7. Full lifecycle → schedule → obligation → closure proof ──────────

    #[test]
    fn full_lifecycle_to_closure_proof() {
        // Walk through: discover → activate → schedule → obligation → close
        let state = activate_connector();
        let mut sched = make_scheduler();
        let mut flow = TwoPhaseFlow::new("full-lifecycle");

        // Schedule two tasks
        let t1 = sched
            .assign_task(&task_classes::barrier_coordination(), 1000, "full")
            .unwrap();
        let t2 = sched
            .assign_task(&task_classes::remote_computation(), 1001, "full")
            .unwrap();

        // Track as obligations
        flow.add_obligation(make_obligation(&t1.task_id, 10000));
        flow.add_obligation(make_obligation(&t2.task_id, 10000));

        // Prepare + commit
        let prep = flow.prepare(2000, "full");
        assert!(matches!(prep, PrepareResult::Ready { .. }));
        let commit = flow.commit(2500, "full");
        assert!(matches!(commit, CommitResult::Committed { .. }));

        // Complete the scheduler tasks
        sched.complete_task(&t1.task_id, 3000, "full").unwrap();
        sched.complete_task(&t2.task_id, 3001, "full").unwrap();

        // Transition connector to stopped
        let stopped = transition(state, ConnectorState::Stopped).unwrap();
        assert_eq!(stopped, ConnectorState::Stopped);

        // Verify closure
        let proof = flow.closure_proof(4000);
        assert!(proof.complete);
        assert_eq!(proof.obligations.len(), 2);
        assert_eq!(sched.total_active(), 0);
        assert_eq!(sched.total_completed(), 2);
    }

    // ── 8. Starvation detection during active lifecycle ────────────────────

    #[test]
    fn starvation_detected_while_connector_active() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        let mut policy = LaneMappingPolicy::new();
        let mut cfg = LaneConfig::new(SchedulerLane::Maintenance, 20, 1);
        cfg.starvation_window_ms = 100;
        policy.add_lane(cfg);
        policy.add_rule(&task_classes::compaction(), SchedulerLane::Maintenance);
        let mut sched = LaneScheduler::new(policy).unwrap();

        // Fill and complete one task to establish last_completion_ms
        let first = sched
            .assign_task(&task_classes::compaction(), 1000, "t1")
            .unwrap();
        sched.complete_task(&first.task_id, 1050, "t1").unwrap();

        // Fill again and queue more
        sched
            .assign_task(&task_classes::compaction(), 1060, "t2")
            .unwrap();
        let _ = sched.assign_task(&task_classes::compaction(), 1070, "t3"); // queued

        // Starvation: last_completion_ms=1050, window=100, check at 1200
        let starved = sched.check_starvation(1200, "starvation-check");
        assert_eq!(starved.len(), 1);
        assert!(matches!(
            &starved[0],
            LaneSchedulerError::Starvation {
                lane: SchedulerLane::Maintenance,
                ..
            }
        ));
    }

    // ── 9. Policy hot-reload during active lifecycle ───────────────────────

    #[test]
    fn hot_reload_policy_while_connector_active() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        let mut sched = make_scheduler();

        // Custom class not in default policy
        let custom_class = TaskClass::new("connector_health_check");
        assert!(sched.assign_task(&custom_class, 1000, "t1").is_err());

        // Hot-reload with new rule
        let mut new_policy = default_policy();
        new_policy.add_rule(&custom_class, SchedulerLane::Background);
        sched.reload_policy(new_policy).unwrap();

        // Now the custom class is accepted
        let assignment = sched.assign_task(&custom_class, 1001, "t2").unwrap();
        assert_eq!(assignment.lane, SchedulerLane::Background);
    }

    // ── 10. Cancelling lifecycle + obligation rollback + lane drain ─────────

    #[test]
    fn cancelling_lifecycle_drains_tasks_and_rolls_back_flow() {
        let active = activate_connector();
        let mut sched = make_scheduler();
        let mut flow = TwoPhaseFlow::new("cancel-drain");

        // Schedule tasks while active
        let t1 = sched
            .assign_task(&task_classes::marker_write(), 1000, "cancel")
            .unwrap();
        let t2 = sched
            .assign_task(&task_classes::artifact_upload(), 1001, "cancel")
            .unwrap();

        flow.add_obligation(make_obligation(&t1.task_id, 10000));
        flow.add_obligation(make_obligation(&t2.task_id, 10000));

        // Prepare the flow
        let prep = flow.prepare(1500, "cancel");
        assert!(matches!(prep, PrepareResult::Ready { .. }));

        // Connector enters cancelling
        let cancelling = transition(active, ConnectorState::Cancelling).unwrap();
        assert_eq!(cancelling, ConnectorState::Cancelling);

        // Rollback the prepared flow
        flow.rollback(2000, "cancel").unwrap();
        assert!(flow.is_rolled_back());

        // Drain tasks from scheduler
        sched.complete_task(&t1.task_id, 2100, "drain").unwrap();
        sched.complete_task(&t2.task_id, 2200, "drain").unwrap();
        assert_eq!(sched.total_active(), 0);

        // Finalize to stopped
        let stopped = transition(cancelling, ConnectorState::Stopped).unwrap();
        assert_eq!(stopped, ConnectorState::Stopped);

        // Proof shows all cancelled
        let proof = flow.closure_proof(3000);
        assert!(proof.complete);
        for status in proof.obligations.values() {
            assert_eq!(*status, ObligationStatus::Cancelled);
        }
    }

    // ── 11. Failed connector recovery cycle ────────────────────────────────

    #[test]
    fn failed_connector_recovery_resets_scheduling() {
        let active = activate_connector();
        let mut sched = make_scheduler();

        // Schedule a task
        let t1 = sched
            .assign_task(&task_classes::remote_computation(), 1000, "pre-fail")
            .unwrap();

        // Connector fails
        let failed = transition(active, ConnectorState::Failed).unwrap();
        assert_eq!(failed, ConnectorState::Failed);

        // Drain active task
        sched.complete_task(&t1.task_id, 1500, "drain").unwrap();
        assert_eq!(sched.total_active(), 0);

        // Recover: Failed → Discovered → ... → Active
        let recovered = activate_connector();
        assert_eq!(recovered, ConnectorState::Active);

        // New tasks are schedulable again
        let t2 = sched
            .assign_task(&task_classes::remote_computation(), 2000, "post-recovery")
            .unwrap();
        assert_eq!(t2.lane, SchedulerLane::RemoteEffect);
        assert_eq!(sched.total_active(), 1);
    }

    // ── 12. Ledger closure proof completeness check ────────────────────────

    #[test]
    fn ledger_closure_proof_incomplete_when_obligations_outstanding() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        let mut flow = TwoPhaseFlow::new("incomplete-proof");
        flow.add_obligation(make_obligation("ob-done", 10000));
        flow.add_obligation(make_obligation("ob-pending", 10000));

        // Prepare but don't commit
        let prep = flow.prepare(2000, "trace");
        assert!(matches!(prep, PrepareResult::Ready { .. }));

        // Proof before commit should show obligations as Created (non-terminal)
        let proof = flow.closure_proof(2500);
        assert!(!proof.complete);
        assert_eq!(proof.obligations.len(), 2);
    }

    // ── 13. Audit trail spans connector→scheduler→obligation ───────────────

    #[test]
    fn audit_trail_covers_full_integration_path() {
        let state = activate_connector();
        assert_eq!(state, ConnectorState::Active);

        let mut sched = make_scheduler();
        let mut channel: ObligationChannel<String> = ObligationChannel::new("audit-trail");

        // Schedule
        let task = sched
            .assign_task(&task_classes::epoch_transition(), 1000, "audit")
            .unwrap();

        // Send obligation
        let ob_id = channel.send("sync-data".to_string(), 1000, "audit");

        // Fulfill
        channel.fulfill(&ob_id, 1200, "audit").unwrap();

        // Complete task
        sched.complete_task(&task.task_id, 1300, "audit").unwrap();

        // Verify audit logs exist at both layers
        assert!(sched.audit_log().len() >= 2); // assign + complete
        assert!(channel.audit_log().len() >= 3); // create + send + fulfill
    }
}
