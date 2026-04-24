use frankenengine_node::connector::health_gate::{HealthGateResult, standard_checks};
use frankenengine_node::connector::lifecycle::ConnectorState;
use frankenengine_node::connector::obligation_tracker::{
    ObligationState, ObligationTracker, event_codes,
};
use frankenengine_node::connector::rollout_state::{
    PersistError, RolloutPhase, RolloutState,
    persist_with_obligation_tracker_and_rename_and_orphan_for_test,
    persist_with_obligation_tracker_and_rename_for_test, persist_with_obligation_tracker_for_test,
};
use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use tempfile::TempDir;

fn sample_state() -> RolloutState {
    RolloutState::new_with_epoch(
        "test-connector-1".to_string(),
        ControlEpoch::new(6),
        ConnectorState::Configured,
        HealthGateResult::evaluate(standard_checks(true, true, true, true)),
        RolloutPhase::Shadow,
    )
}

fn temp_leftovers(dir: &std::path::Path, marker: &str) -> Vec<String> {
    let mut leftovers = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.contains(marker))
        .collect::<Vec<_>>();
    leftovers.sort();
    leftovers
}

#[test]
fn rollout_persist_commits_two_phase_obligation() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state-obligation.json");
    let state = sample_state();
    let mut tracker = ObligationTracker::new();

    persist_with_obligation_tracker_for_test(
        &state,
        &path,
        &mut tracker,
        "trace-rollout-obligation",
    )
    .expect("persist should reserve and commit rollout obligation");

    assert_eq!(tracker.count_in_state(ObligationState::Committed), 1);
    assert_eq!(tracker.count_in_state(ObligationState::Reserved), 0);
    assert_eq!(tracker.count_in_state(ObligationState::RolledBack), 0);
    let audit = tracker.export_audit_log_jsonl();
    assert!(audit.contains(event_codes::OBL_RESERVED));
    assert!(audit.contains(event_codes::OBL_COMMITTED));
}

#[test]
fn failed_rollout_rename_rolls_back_obligation_and_orphans_temp() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state-rename-failure.json");
    let state = sample_state();
    let mut tracker = ObligationTracker::new();

    let err = persist_with_obligation_tracker_and_rename_for_test(
        &state,
        &path,
        &mut tracker,
        "trace-rollout-rename-failure",
        |_from, _to| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "forced rename failure",
            ))
        },
    )
    .expect_err("forced rename failure must fail persistence");

    assert!(matches!(err, PersistError::IoError { .. }));
    assert!(!path.exists());
    assert_eq!(tracker.count_in_state(ObligationState::Committed), 0);
    assert_eq!(tracker.count_in_state(ObligationState::Reserved), 0);
    assert_eq!(tracker.count_in_state(ObligationState::RolledBack), 1);
    let audit = tracker.export_audit_log_jsonl();
    assert!(audit.contains(event_codes::OBL_RESERVED));
    assert!(audit.contains(event_codes::OBL_ROLLED_BACK));
    assert!(!audit.contains(event_codes::OBL_COMMITTED));
    assert_eq!(temp_leftovers(dir.path(), ".orphaned-").len(), 1);
}

#[test]
fn failed_rollout_rename_surfaces_orphan_failure() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state-orphan-failure.json");
    let state = sample_state();
    let mut tracker = ObligationTracker::new();

    let err = persist_with_obligation_tracker_and_rename_and_orphan_for_test(
        &state,
        &path,
        &mut tracker,
        "trace-rollout-orphan-failure",
        |_from, _to| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "forced persist rename failure",
            ))
        },
        |_from, _to| Err(std::io::Error::other("forced orphan rename failure")),
    )
    .expect_err("orphan rename failure must be surfaced");

    assert!(
        matches!(&err, PersistError::IoError { .. }),
        "expected IoError for surfaced orphan failure, got {err:?}"
    );
    let message = if let PersistError::IoError { message } = err {
        message
    } else {
        String::new()
    };
    assert!(message.contains("forced persist rename failure"));
    assert!(message.contains("forced orphan rename failure"));
    assert!(!path.exists());
    assert_eq!(tracker.count_in_state(ObligationState::Committed), 0);
    assert_eq!(tracker.count_in_state(ObligationState::Reserved), 0);
    assert_eq!(tracker.count_in_state(ObligationState::RolledBack), 1);
    assert_eq!(temp_leftovers(dir.path(), ".tmp.").len(), 1);
    assert_eq!(temp_leftovers(dir.path(), ".orphaned-").len(), 0);
}
