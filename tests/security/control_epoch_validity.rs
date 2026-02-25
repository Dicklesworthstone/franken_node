// Security conformance tests for bd-181w: control-plane epoch validity adoption.
//
// Validates that control artifacts and remote contracts use canonical
// fail-closed epoch-window checks from `control_plane::control_epoch`.

pub use frankenengine_node::control_plane;
pub use frankenengine_node::connector;

use connector::fencing::{FenceState, FencedWrite, FencingError, epoch_event_codes as fencing_epv};
use connector::health_gate::{
    EpochScopedHealthPolicy, epoch_event_codes as health_epv, evaluate_epoch_scoped_policy,
    standard_checks,
};
use connector::lifecycle::ConnectorState;
use connector::rollout_state::{
    RolloutPhase, RolloutState, epoch_event_codes as rollout_epv, persist_epoch_scoped,
};
use control_plane::control_epoch::{ControlEpoch, ValidityWindowPolicy};
use serde_json::json;
use tempfile::TempDir;

#[test]
fn control_artifact_current_epoch_is_accepted() {
    let policy = EpochScopedHealthPolicy::new(
        "health-policy-epv-current".to_string(),
        ControlEpoch::new(12),
        standard_checks(true, true, true, true),
        "trace-health-current".to_string(),
    );
    let validity = ValidityWindowPolicy::new(ControlEpoch::new(12), 2);

    let outcome = evaluate_epoch_scoped_policy(&policy, &validity)
        .expect("current-epoch health policy should be accepted");

    assert_eq!(
        outcome.epoch_check_event_code,
        health_epv::EPOCH_CHECK_PASSED
    );
    assert_eq!(outcome.epoch_event.event_code, "EPOCH_ARTIFACT_ACCEPTED");
    assert_eq!(outcome.scope_log.event_code, health_epv::EPOCH_SCOPE_LOGGED);
}

#[test]
fn past_but_valid_rollout_epoch_is_accepted() {
    let checks = standard_checks(true, true, true, true);
    let health = connector::health_gate::HealthGateResult::evaluate(checks);
    let state = RolloutState::new_with_epoch(
        "connector-epoch-valid".to_string(),
        ControlEpoch::new(10),
        ConnectorState::Configured,
        health,
        RolloutPhase::Canary,
    );

    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("rollout-state.json");
    let validity = ValidityWindowPolicy::new(ControlEpoch::new(12), 2);

    let outcome = persist_epoch_scoped(&state, &path, &validity, "trace-rollout-valid")
        .expect("epoch inside [current-lookback, current] should be accepted");

    assert!(path.exists(), "epoch-scoped persist should write state");
    assert_eq!(
        outcome.epoch_check_event_code,
        rollout_epv::EPOCH_CHECK_PASSED
    );
    assert_eq!(
        outcome.scope_log.event_code,
        rollout_epv::EPOCH_SCOPE_LOGGED
    );
}

#[test]
fn future_epoch_fencing_token_is_rejected_fail_closed() {
    let mut fence = FenceState::new("obj-future".to_string());
    let lease = fence.acquire_lease_with_epoch(
        "writer-a".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
        "2030-01-01T00:00:00Z".to_string(),
        ControlEpoch::new(13),
    );
    let write = FencedWrite {
        fence_seq: Some(1),
        target_object_id: "obj-future".to_string(),
        payload: json!({"op": "write"}),
    };
    let validity = ValidityWindowPolicy::new(ControlEpoch::new(12), 2);

    let err = fence
        .validate_write_epoch_scoped(
            &write,
            &lease,
            "2026-06-01T00:00:00Z",
            &validity,
            "trace-fencing-future",
        )
        .expect_err("future epoch must be rejected");

    match err {
        FencingError::EpochRejected { rejection } => {
            assert_eq!(rejection.artifact_epoch, ControlEpoch::new(13));
            assert_eq!(rejection.current_epoch, ControlEpoch::new(12));
            assert_eq!(
                FencingError::EpochRejected {
                    rejection: rejection.clone()
                }
                .epoch_event_code(),
                Some(fencing_epv::FUTURE_EPOCH_REJECTED)
            );
        }
        _ => panic!("expected epoch rejection"),
    }
}

#[test]
fn expired_rollout_epoch_is_rejected() {
    let checks = standard_checks(true, true, true, true);
    let health = connector::health_gate::HealthGateResult::evaluate(checks);
    let state = RolloutState::new_with_epoch(
        "connector-epoch-expired".to_string(),
        ControlEpoch::new(8),
        ConnectorState::Configured,
        health,
        RolloutPhase::Shadow,
    );

    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("rollout-state-expired.json");
    let validity = ValidityWindowPolicy::new(ControlEpoch::new(12), 2);

    let err = persist_epoch_scoped(&state, &path, &validity, "trace-rollout-expired")
        .expect_err("expired epoch should be rejected");

    match err {
        connector::rollout_state::EpochPersistError::StaleEpochRejected { rejection } => {
            assert_eq!(rejection.artifact_epoch, ControlEpoch::new(8));
            assert_eq!(rejection.current_epoch, ControlEpoch::new(12));
        }
        _ => panic!("expected stale epoch rejection"),
    }
}

#[test]
fn accepted_high_impact_operations_emit_epoch_scope_logs() {
    // Health policy acceptance emits EPV-004.
    let policy = EpochScopedHealthPolicy::new(
        "health-policy-epv-log".to_string(),
        ControlEpoch::new(20),
        standard_checks(true, true, true, true),
        "trace-health-log".to_string(),
    );
    let validity = ValidityWindowPolicy::new(ControlEpoch::new(20), 1);
    let health_outcome = evaluate_epoch_scoped_policy(&policy, &validity).expect("accepted");
    assert_eq!(
        health_outcome.scope_log.event_code,
        health_epv::EPOCH_SCOPE_LOGGED
    );

    // Rollout plan acceptance emits EPV-004.
    let checks = standard_checks(true, true, true, true);
    let health = connector::health_gate::HealthGateResult::evaluate(checks);
    let state = RolloutState::new_with_epoch(
        "connector-epv-log".to_string(),
        ControlEpoch::new(20),
        ConnectorState::Configured,
        health,
        RolloutPhase::Ramp,
    );
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("rollout-state-log.json");
    let rollout_outcome = persist_epoch_scoped(&state, &path, &validity, "trace-rollout-log")
        .expect("accepted rollout epoch should be persisted");
    assert_eq!(
        rollout_outcome.scope_log.event_code,
        rollout_epv::EPOCH_SCOPE_LOGGED
    );

    // Fencing token acceptance emits EPV-004.
    let mut fence = FenceState::new("obj-log".to_string());
    let lease = fence.acquire_lease_with_epoch(
        "writer-log".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
        "2030-01-01T00:00:00Z".to_string(),
        ControlEpoch::new(20),
    );
    let write = FencedWrite {
        fence_seq: Some(1),
        target_object_id: "obj-log".to_string(),
        payload: json!({"op": "write"}),
    };
    let fencing_outcome = fence
        .validate_write_epoch_scoped(
            &write,
            &lease,
            "2026-06-01T00:00:00Z",
            &validity,
            "trace-fencing-log",
        )
        .expect("accepted fencing token epoch");
    assert_eq!(
        fencing_outcome.scope_log.event_code,
        fencing_epv::EPOCH_SCOPE_LOGGED
    );
}
