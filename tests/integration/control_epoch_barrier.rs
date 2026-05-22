//! Integration coverage for canonical control epoch barriers.
//!
//! Bead: bd-1hbw.1

use frankenengine_node::connector::fencing::{FenceState, FencedWrite, FencingError};
use frankenengine_node::connector::health_gate::{HealthGateResult, standard_checks};
use frankenengine_node::connector::lifecycle::ConnectorState;
use frankenengine_node::connector::rollout_state::{
    EpochPersistError, RolloutPhase, RolloutState, persist_epoch_scoped,
};
use frankenengine_node::control_plane::control_epoch::{ControlEpoch, ValidityWindowPolicy};
use frankenengine_node::control_plane::epoch_transition_barrier::BarrierConfig;
use frankenengine_node::runtime::epoch_transition::{
    EPOCH_ADVANCED, EPOCH_DRAIN_CONFIRMED, EPOCH_DRAIN_REQUESTED, EPOCH_TRANSITION_ABORTED,
    FUTURE_EPOCH_REJECTED, ProductEpochCoordinator,
};
use serde_json::json;
use tempfile::TempDir;

fn coordinator_at(epoch: u64) -> ProductEpochCoordinator {
    let mut coordinator = ProductEpochCoordinator::new(epoch, 2, BarrierConfig::new(10_000, 500));
    for service_id in [
        "connector_fencing",
        "connector_lifecycle",
        "connector_rollout_state",
    ] {
        coordinator.register_service(service_id);
    }
    coordinator
}

fn assert_fencing_accepts_epoch(epoch: ControlEpoch) {
    let mut fence = FenceState::new("control-epoch-object".to_string());
    let lease = fence.acquire_lease_with_epoch(
        "connector_fencing".to_string(),
        "2026-05-01T00:00:00Z".to_string(),
        "2026-06-01T00:00:00Z".to_string(),
        epoch,
    );
    let write = FencedWrite {
        fence_seq: Some(1),
        target_object_id: "control-epoch-object".to_string(),
        payload: json!({"op": "post-barrier-write"}),
    };
    let validity = ValidityWindowPolicy::new(epoch, 1);

    fence
        .validate_write_epoch_scoped(
            &write,
            &lease,
            "2026-05-15T00:00:00Z",
            &validity,
            "trace-fencing-accepted",
        )
        .expect("committed epoch fencing token should be accepted");
}

fn assert_rollout_persists_at_epoch(epoch: ControlEpoch) {
    let checks = standard_checks(true, true, true, true);
    let health = HealthGateResult::evaluate(checks);
    let state = RolloutState::new_with_epoch(
        "connector_rollout_state".to_string(),
        epoch,
        ConnectorState::Configured,
        health,
        RolloutPhase::Ramp,
    );
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("rollout-state.json");
    let validity = ValidityWindowPolicy::new(epoch, 1);

    persist_epoch_scoped(&state, &path, &validity, "trace-rollout-accepted")
        .expect("committed epoch rollout state should persist");
    assert!(path.exists());
}

#[test]
fn barrier_commit_state_is_metamorphic_under_ack_order_permutation() -> Result<(), String> {
    #[derive(Debug, PartialEq, Eq)]
    struct AckOrderRun {
        committed: u64,
        current: u64,
        history: (u64, u64, String, String, String, Option<String>),
        drain_confirmations: Vec<(String, u64, Option<u64>, String)>,
    }

    fn ack_payload(service_id: &str) -> Result<(u64, u64, &'static str), String> {
        match service_id {
            "connector_fencing" => Ok((1, 5, "trace-ack-connector-fencing")),
            "connector_lifecycle" => Ok((2, 7, "trace-ack-connector-lifecycle")),
            "connector_rollout_state" => Ok((3, 11, "trace-ack-connector-rollout-state")),
            other => Err(format!("unexpected service id {other}")),
        }
    }

    fn run_ack_order(order: &[&str]) -> Result<AckOrderRun, String> {
        let mut coordinator = coordinator_at(42);
        let proposal = coordinator
            .propose_transition("operator", "ack-order-mr", 10_000, "trace-propose")
            .map_err(|err| err.to_string())?;
        assert_eq!(proposal.pre_epoch, 42);
        assert_eq!(proposal.target_epoch, 43);

        for service_id in order {
            let (drained_items, elapsed_ms, trace_id) = ack_payload(service_id)?;
            coordinator
                .ack_drain(service_id, drained_items, elapsed_ms, trace_id)
                .map_err(|err| err.to_string())?;
        }

        let committed = coordinator
            .commit_transition(10_100, "trace-commit")
            .map_err(|err| err.to_string())?;
        let history = coordinator
            .history()
            .first()
            .ok_or_else(|| "committed transition did not record history".to_string())?;
        let mut drain_confirmations = Vec::new();
        for event in coordinator
            .events()
            .iter()
            .filter(|event| event.event_code == EPOCH_DRAIN_CONFIRMED)
        {
            let service_id = event
                .service_id
                .clone()
                .ok_or_else(|| "drain confirmation missing service id".to_string())?;
            let status = event
                .quiescence_status
                .clone()
                .ok_or_else(|| "drain confirmation missing status".to_string())?;
            drain_confirmations.push((
                service_id,
                event.epoch_current,
                event.epoch_artifact,
                status,
            ));
        }
        drain_confirmations.sort();

        Ok(AckOrderRun {
            committed,
            current: coordinator.current_epoch(),
            history: (
                history.pre_epoch,
                history.target_epoch,
                history.initiator.clone(),
                history.reason.clone(),
                history.outcome.clone(),
                history.abort_reason.clone(),
            ),
            drain_confirmations,
        })
    }

    let forward = run_ack_order(&[
        "connector_fencing",
        "connector_lifecycle",
        "connector_rollout_state",
    ])?;
    let permuted = run_ack_order(&[
        "connector_rollout_state",
        "connector_fencing",
        "connector_lifecycle",
    ])?;

    assert_eq!(forward.committed, 43);
    assert_eq!(forward.current, 43);
    assert_eq!(forward, permuted);
    Ok(())
}

#[test]
fn barrier_commit_advances_control_epoch_before_connectors_accept_target_epoch() {
    let mut coordinator = coordinator_at(41);

    let proposal = coordinator
        .propose_transition(
            "operator",
            "connector-control-epoch-rotation",
            1_000,
            "trace-propose",
        )
        .expect("barrier proposal should succeed");
    assert_eq!(proposal.pre_epoch, 41);
    assert_eq!(proposal.target_epoch, 42);

    let pre_commit = coordinator
        .validate_operation_epoch("connector_rollout_state", 42, "trace-pre-commit")
        .expect_err("target epoch must remain blocked until every participant drains");
    assert_eq!(pre_commit.code(), FUTURE_EPOCH_REJECTED);

    for service_id in [
        "connector_fencing",
        "connector_lifecycle",
        "connector_rollout_state",
    ] {
        coordinator
            .ack_drain(service_id, 1, 20, "trace-ack")
            .expect("registered service should ack drain");
    }

    let committed_epoch = coordinator
        .commit_transition(1_200, "trace-commit")
        .expect("all drain acknowledgements should commit");
    let committed = ControlEpoch::new(committed_epoch);
    assert_eq!(committed, ControlEpoch::new(42));
    assert_eq!(coordinator.current_epoch(), 42);
    assert!(
        coordinator
            .events()
            .iter()
            .any(|event| event.event_code == EPOCH_DRAIN_REQUESTED
                && event.service_id.as_deref() == Some("connector_rollout_state"))
    );
    assert!(
        coordinator
            .events()
            .iter()
            .any(|event| event.event_code == EPOCH_ADVANCED)
    );

    coordinator
        .validate_operation_epoch("connector_rollout_state", 42, "trace-post-commit")
        .expect("committed target epoch should be accepted");
    assert_fencing_accepts_epoch(committed);
    assert_rollout_persists_at_epoch(committed);

    assert_eq!(coordinator.history().len(), 1);
    assert_eq!(coordinator.history()[0].outcome, "COMMITTED");
}

#[test]
fn barrier_abort_preserves_pre_epoch_and_rejects_target_epoch_connectors() {
    let mut coordinator = coordinator_at(7);

    let proposal = coordinator
        .propose_transition("operator", "abort-before-rollout", 2_000, "trace-propose")
        .expect("barrier proposal should succeed");
    assert_eq!(proposal.target_epoch, 8);
    coordinator
        .ack_drain("connector_fencing", 2, 25, "trace-fencing-ack")
        .expect("one participant can drain before abort");

    let epoch_after_abort = coordinator
        .abort_transition_timeout(12_000, "trace-timeout-abort")
        .expect("timeout abort should succeed");
    assert_eq!(epoch_after_abort, 7);
    assert_eq!(coordinator.current_epoch(), 7);
    assert_eq!(coordinator.abort_manager().abort_count(), 1);
    assert_eq!(coordinator.history().len(), 1);
    assert_eq!(coordinator.history()[0].outcome, "ABORTED");
    assert!(
        coordinator
            .events()
            .iter()
            .any(|event| event.event_code == EPOCH_TRANSITION_ABORTED)
    );

    let err = coordinator
        .validate_operation_epoch("connector_rollout_state", 8, "trace-aborted-target")
        .expect_err("aborted target epoch must remain rejected");
    assert_eq!(err.code(), FUTURE_EPOCH_REJECTED);

    let mut fence = FenceState::new("aborted-control-epoch-object".to_string());
    let future_lease = fence.acquire_lease_with_epoch(
        "connector_fencing".to_string(),
        "2026-05-01T00:00:00Z".to_string(),
        "2026-06-01T00:00:00Z".to_string(),
        ControlEpoch::new(8),
    );
    let write = FencedWrite {
        fence_seq: Some(1),
        target_object_id: "aborted-control-epoch-object".to_string(),
        payload: json!({"op": "aborted-target-write"}),
    };
    let validity = ValidityWindowPolicy::new(ControlEpoch::new(7), 1);
    let fence_err = fence
        .validate_write_epoch_scoped(
            &write,
            &future_lease,
            "2026-05-15T00:00:00Z",
            &validity,
            "trace-fencing-aborted-target",
        )
        .expect_err("future fencing token from aborted epoch should fail closed");
    assert!(matches!(fence_err, FencingError::EpochRejected { .. }));

    let health = HealthGateResult::evaluate(standard_checks(true, true, true, true));
    let future_rollout = RolloutState::new_with_epoch(
        "connector_rollout_state".to_string(),
        ControlEpoch::new(8),
        ConnectorState::Configured,
        health,
        RolloutPhase::Canary,
    );
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("future-rollout-state.json");
    let rollout_err = persist_epoch_scoped(
        &future_rollout,
        &path,
        &validity,
        "trace-rollout-aborted-target",
    )
    .expect_err("future rollout state from aborted epoch should fail closed");
    assert!(matches!(
        rollout_err,
        EpochPersistError::FutureEpochRejected { .. }
    ));
    assert!(!path.exists());

    let reproposal = coordinator
        .propose_transition("operator", "retry-after-abort", 13_000, "trace-retry")
        .expect("aborted barrier should clear pending state for retry");
    assert_eq!(reproposal.pre_epoch, 7);
    assert_eq!(reproposal.target_epoch, 8);
}
