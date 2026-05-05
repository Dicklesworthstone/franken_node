use frankenengine_node::canonical_lock_key;
use frankenengine_node::connector::health_gate::{HealthGateResult, standard_checks};
use frankenengine_node::connector::lifecycle::ConnectorState;
use frankenengine_node::connector::obligation_tracker::{
    ObligationState, ObligationTracker, event_codes,
};
use frankenengine_node::connector::region_ownership::{RegionError, atomic_next_for_test};
use frankenengine_node::connector::rollout_state::{
    PersistError, RolloutPhase, RolloutState, load, persist_lock_registry_key_for_test,
    persist_with_obligation_tracker_and_rename_and_orphan_for_test,
    persist_with_obligation_tracker_and_rename_for_test, persist_with_obligation_tracker_for_test,
};
use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use std::sync::atomic::{AtomicU64, Ordering};
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
fn region_sequence_fails_closed_at_u64_boundary() {
    let counter = AtomicU64::new(u64::MAX - 1);

    let last_unique = atomic_next_for_test(&counter, "region_sequence").unwrap();
    assert_eq!(last_unique, u64::MAX - 1);
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);

    let err = atomic_next_for_test(&counter, "region_sequence").unwrap_err();
    assert_eq!(
        err,
        RegionError::SequenceExhausted {
            counter: "region_sequence".to_string(),
            last_value: u64::MAX
        }
    );
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
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
fn rollout_persist_lock_key_is_stable_before_lock_file_exists() {
    let dir = TempDir::new().unwrap();
    let rollout_dir = dir.path().join("rollouts").join("primary");
    std::fs::create_dir_all(&rollout_dir).expect("create rollout dir");
    let equivalent_path = rollout_dir.join("..").join("primary").join("state.json");
    let canonical_path = rollout_dir
        .canonicalize()
        .expect("canonicalize rollout dir")
        .join("state.json");

    assert!(
        !rollout_dir.join("state.json.lock").exists(),
        "regression must derive the registry key before the lock file exists"
    );

    let equivalent_key =
        persist_lock_registry_key_for_test(&equivalent_path).expect("equivalent key");
    let canonical_key = persist_lock_registry_key_for_test(&canonical_path).expect("canonical key");

    assert_eq!(equivalent_key, canonical_key);
    assert_eq!(
        equivalent_key,
        rollout_dir
            .canonicalize()
            .expect("canonicalize expected key dir")
            .join("state.json.lock")
    );
}

#[test]
fn rollout_persist_serializes_concurrent_writes_through_equivalent_paths() {
    let dir = TempDir::new().unwrap();
    let rollout_dir = dir.path().join("rollouts").join("primary");
    std::fs::create_dir_all(&rollout_dir).expect("create rollout dir");
    let equivalent_path = rollout_dir.join("..").join("primary").join("state.json");
    let canonical_path = rollout_dir
        .canonicalize()
        .expect("canonicalize rollout dir")
        .join("state.json");
    let state_a = sample_state();
    let mut state_b = sample_state();
    state_b.connector_id = "test-connector-2".to_string();
    state_b.bump_version();

    let (rename_entered_tx, rename_entered_rx) = std::sync::mpsc::channel();
    let (allow_rename_tx, allow_rename_rx) = std::sync::mpsc::channel();
    let equivalent_for_thread = equivalent_path.clone();
    let state_a_for_thread = state_a.clone();
    let writer_a = std::thread::spawn(move || {
        let mut tracker = ObligationTracker::new();
        persist_with_obligation_tracker_and_rename_for_test(
            &state_a_for_thread,
            &equivalent_for_thread,
            &mut tracker,
            "trace-rollout-equivalent-a",
            |from, to| {
                rename_entered_tx
                    .send(())
                    .expect("notify first writer entered rename");
                allow_rename_rx
                    .recv()
                    .expect("test should release first writer");
                std::fs::rename(from, to)
            },
        )
    });

    rename_entered_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("first writer must block inside rename");

    let (writer_b_started_tx, writer_b_started_rx) = std::sync::mpsc::channel();
    let (writer_b_done_tx, writer_b_done_rx) = std::sync::mpsc::channel();
    let canonical_for_thread = canonical_path.clone();
    let state_b_for_thread = state_b.clone();
    let writer_b = std::thread::spawn(move || {
        let mut tracker = ObligationTracker::new();
        writer_b_started_tx
            .send(())
            .expect("notify second writer started");
        let result = persist_with_obligation_tracker_for_test(
            &state_b_for_thread,
            &canonical_for_thread,
            &mut tracker,
            "trace-rollout-equivalent-b",
        );
        writer_b_done_tx
            .send(result.is_ok())
            .expect("notify second writer completed");
        result
    });

    writer_b_started_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("second writer must start before first write is released");
    assert!(
        matches!(
            writer_b_done_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "canonical spelling must wait behind equivalent spelling while the first write holds the shared lock"
    );

    allow_rename_tx
        .send(())
        .expect("release first writer rename barrier");
    writer_a
        .join()
        .expect("first writer join")
        .expect("first write succeeds");
    writer_b
        .join()
        .expect("second writer join")
        .expect("second write succeeds after first releases the shared lock");

    assert_eq!(
        load(&canonical_path).expect("load final rollout state"),
        state_b,
        "second writer must observe the first write before replacing it with version 2"
    );
}

#[cfg(unix)]
#[test]
fn canonical_lock_key_normalizes_symlinked_parent_before_lock_file_exists() {
    let dir = TempDir::new().unwrap();
    let real_dir = dir.path().join("real-root");
    let alias_dir = dir.path().join("alias-root");
    std::fs::create_dir_all(&real_dir).expect("create real dir");
    std::os::unix::fs::symlink(&real_dir, &alias_dir).expect("create symlink alias");

    let alias_lock_path = alias_dir.join("state.json.lock");
    let real_lock_path = real_dir.join("state.json.lock");
    assert!(
        !real_lock_path.exists(),
        "regression must derive the key before the lock file exists"
    );

    let alias_key = canonical_lock_key(&alias_lock_path).expect("alias lock key");
    let real_key = canonical_lock_key(&real_lock_path).expect("real lock key");

    assert_eq!(
        alias_key, real_key,
        "symlinked parent paths must converge on one lock key before the lock file exists"
    );
}

#[test]
fn canonical_lock_key_fails_closed_when_parent_is_missing() {
    let dir = TempDir::new().unwrap();
    let missing_parent_lock_path = dir.path().join("missing-parent").join("state.json.lock");

    let err = canonical_lock_key(&missing_parent_lock_path)
        .expect_err("missing lock parent must fail closed");

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(
        err.to_string()
            .contains("failed canonicalizing lock key parent"),
        "error must name the canonicalization failure: {err}"
    );
}

#[cfg(unix)]
#[test]
fn rollout_persist_lock_key_preserves_non_utf8_state_file_names() {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let dir = TempDir::new().unwrap();
    let state_file_name = OsString::from_vec(b"state-\xFF.json".to_vec());
    let state_path = dir.path().join(state_file_name);

    let lock_key = persist_lock_registry_key_for_test(&state_path)
        .expect("non-UTF8 rollout state path should derive an exact lock key");

    assert_eq!(
        lock_key.file_name().expect("lock key file name").as_bytes(),
        b"state-\xFF.json.lock",
        "lock-key derivation must append .lock without lossy UTF-8 fallback"
    );
    assert_eq!(
        lock_key.parent().expect("lock key parent"),
        dir.path().canonicalize().expect("canonical temp dir")
    );
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
