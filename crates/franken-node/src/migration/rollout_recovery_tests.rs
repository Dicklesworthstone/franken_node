//! Real filesystem integration tests for rollout -> native rewrite recovery.
//! Forced progression in these tests isolates recovery, not lockstep certification.

use super::*;
use super::super::rewrite_transaction::{Edit, RewriteTransaction};
use super::super::rollback::{self, RollbackStatus, TransactionState};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn applied_project() -> (tempfile::TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("a.js"), b"original-a").unwrap();
    fs::write(root.path().join("b.js"), b"original-b").unwrap();
    fs::set_permissions(root.path().join("a.js"), fs::Permissions::from_mode(0o755)).unwrap();
    RewriteTransaction::open(root.path()).unwrap().apply(&[
        Edit { path: "a.js", before: b"original-a", after: b"rewritten-a" },
        Edit { path: "b.js", before: b"original-b", after: b"rewritten-b" },
    ]).unwrap();
    let history = rollback::run(root.path(), None, false);
    assert_eq!(history.status, RollbackStatus::History, "{history:#?}");
    let id = history.history.iter().find(|entry| entry.state == TransactionState::Applied)
        .unwrap().transaction_id.clone();
    (root, id)
}

fn forced() -> RolloutConfig {
    RolloutConfig { force: true, ..RolloutConfig::default() }
}

fn sources(root: &Path, original: bool) {
    assert_eq!(fs::read(root.join("a.js")).unwrap(), if original { b"original-a".as_slice() } else { b"rewritten-a".as_slice() });
    assert_eq!(fs::read(root.join("b.js")).unwrap(), if original { b"original-b".as_slice() } else { b"rewritten-b".as_slice() });
    assert_eq!(fs::metadata(root.join("a.js")).unwrap().mode() & 0o777, 0o755);
}

#[test]
fn binding_is_explicit_persistent_and_does_not_restore_sources() {
    let (root, id) = applied_project();
    let manager = RolloutManager::new(root.path(), Some(&id));
    let state = manager.load_or_init().unwrap();
    assert_eq!(state.rollback_plan_id.as_deref(), Some(id.as_str()));
    let preview = rollback::run(root.path(), Some(&id), false);
    assert_eq!(state.rollback_journal_sha256.as_deref(), Some(preview.transaction.as_ref().unwrap().journal_sha256.as_str()));
    let reopened = RolloutManager::new(root.path(), Some(&id)).load_or_init().unwrap();
    assert_eq!(reopened, state);
    sources(root.path(), false);
}

#[test]
fn ordinary_migration_id_never_guesses_the_latest_transaction() {
    let (root, _) = applied_project();
    let manager = RolloutManager::new(root.path(), Some("mig-unbound"));
    manager.promote(&forced(), None, None).unwrap();
    let report = manager.rollback("operator cancellation").unwrap();
    assert!(report.source_rollback.is_none());
    assert!(report.message.contains("no source files restored"));
    sources(root.path(), false);
}

#[test]
fn missing_or_completed_transaction_cannot_be_bound_for_promotion() {
    let (root, id) = applied_project();
    assert!(RolloutManager::new(root.path(), Some("txn-missing")).load_or_init().is_err());
    assert_eq!(rollback::run(root.path(), Some(&id), true).status, RollbackStatus::RolledBack);
    assert!(RolloutManager::new(root.path(), Some(&id)).promote(&forced(), None, None).is_err());
    sources(root.path(), true);
}

#[test]
fn rollout_rollback_restores_sources_modes_and_records_exact_transaction() {
    let (root, id) = applied_project();
    let manager = RolloutManager::new(root.path(), Some(&id));
    let promoted = manager.promote(&forced(), None, None).unwrap();
    assert!(!promoted.source_rollback.unwrap().restoration_recorded);
    let report = manager.rollback("regression").unwrap();
    sources(root.path(), true);
    assert_eq!(report.stage, RolloutStage::Aborted);
    assert_eq!(report.status, RolloutStatus::RolledBack);
    assert!(report.source_rollback.as_ref().unwrap().restoration_recorded);
    assert_eq!(report.source_rollback.as_ref().unwrap().transaction_id, id);
    assert!(report.history.iter().any(|event| event.action == "rollback_started"));
    assert_eq!(report.history.last().unwrap().action, "rollback");
    assert!(root.path().join(".migrate-backup/a.js").exists());
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("original-a") && !json.contains("rewritten-a"));
    assert_eq!(serde_json::from_str::<RolloutReport>(&json).unwrap(), report);
}

#[test]
fn confidence_failure_performs_source_restoration_not_just_a_state_change() {
    let (root, id) = applied_project();
    let manager = RolloutManager::new(root.path(), Some(&id));
    manager.promote(&forced(), None, None).unwrap();
    let mut state = manager.load_or_init().unwrap();
    state.confidence_score = 0.5;
    manager.persist(&state).unwrap();
    let error = manager.promote(&RolloutConfig::default(), None, None).unwrap_err();
    assert!(error.contains("below minimum threshold"), "{error}");
    sources(root.path(), true);
    assert!(manager.status().unwrap().source_rollback.unwrap().restoration_recorded);
}

#[test]
fn conflict_blocks_all_restoration_and_remains_failed_across_restart() {
    let (root, id) = applied_project();
    let manager = RolloutManager::new(root.path(), Some(&id));
    manager.promote(&forced(), None, None).unwrap();
    fs::write(root.path().join("b.js"), b"independent user work").unwrap();
    let error = manager.rollback("regression").unwrap_err();
    assert!(error.contains("preserving the user's edit"), "{error}");
    assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"rewritten-a");
    assert_eq!(fs::read(root.path().join("b.js")).unwrap(), b"independent user work");
    let reopened = RolloutManager::new(root.path(), Some(&id));
    let report = reopened.status().unwrap();
    assert!(!report.ok);
    assert_eq!(report.stage, RolloutStage::Aborted);
    assert_eq!(report.status, RolloutStatus::Failed);
    assert!(!report.source_rollback.unwrap().restoration_recorded);
    assert!(reopened.promote(&forced(), Some(RolloutStage::Default), None).is_err());
    // Explicitly resolve the fixture's conflict; the rollback never does this.
    fs::write(root.path().join("b.js"), b"rewritten-b").unwrap();
    reopened.rollback("retry same admitted transaction").unwrap();
    sources(root.path(), true);
}

#[test]
fn automatic_rollback_errors_are_propagated_and_cannot_claim_success() {
    let (root, id) = applied_project();
    let manager = RolloutManager::new(root.path(), Some(&id));
    manager.promote(&forced(), None, None).unwrap();
    let mut state = manager.load_or_init().unwrap();
    state.confidence_score = 0.1;
    manager.persist(&state).unwrap();
    fs::write(root.path().join("b.js"), b"user work").unwrap();
    let error = manager.promote(&RolloutConfig::default(), None, None).unwrap_err();
    assert!(error.contains("automatic rollback did not complete"), "{error}");
    assert!(error.contains("preserving the user's edit"));
    assert_eq!(manager.status().unwrap().status, RolloutStatus::Failed);
    assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"rewritten-a");
}

#[test]
fn completed_rollout_rollback_retry_does_not_touch_later_work_or_duplicate_history() {
    let (root, id) = applied_project();
    let manager = RolloutManager::new(root.path(), Some(&id));
    manager.load_or_init().unwrap();
    let first = manager.rollback("regression").unwrap();
    fs::write(root.path().join("a.js"), b"later work").unwrap();
    let second = RolloutManager::new(root.path(), Some(&id)).rollback("retry").unwrap();
    assert_eq!(second.history, first.history);
    assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"later work");
    assert!(second.message.contains("not changed or re-certified"));
}

#[test]
fn an_external_restore_or_changed_source_refuses_even_forced_promotion() {
    for restored in [false, true] {
        let (root, id) = applied_project();
        let manager = RolloutManager::new(root.path(), Some(&id));
        manager.load_or_init().unwrap();
        if restored {
            assert_eq!(rollback::run(root.path(), Some(&id), true).status, RollbackStatus::RolledBack);
        } else {
            fs::write(root.path().join("a.js"), b"changed source").unwrap();
        }
        let error = manager.promote(&forced(), None, None).unwrap_err();
        assert!(error.contains("bound rewrite is not intact"), "{error}");
        assert_eq!(manager.status().unwrap().stage, RolloutStage::Shadow);
    }
}

#[test]
fn substituted_journal_cannot_redefine_the_bound_rollout_inventory() {
    let (root, id) = applied_project();
    let manager = RolloutManager::new(root.path(), Some(&id));
    manager.load_or_init().unwrap();
    let path = root.path().join(".migrate-backup/.franken-rewrite").join(&id).join("applied.json");
    let original = fs::read(&path).unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
    changed["records"].as_array_mut().unwrap().pop();
    fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    let error = manager.rollback("regression").unwrap_err();
    assert!(error.contains("bound recovery plan"), "{error}");
    sources(root.path(), false);
    assert_eq!(manager.status().unwrap().status, RolloutStatus::Failed);
    fs::write(&path, original).unwrap();
    manager.rollback("retry").unwrap();
    sources(root.path(), true);
}

#[test]
fn metadata_updates_cannot_remove_the_binding_or_revive_an_aborted_rollout() {
    let (root, id) = applied_project();
    let manager = RolloutManager::new(root.path(), Some(&id));
    let before = manager.load_or_init().unwrap();
    let mut changed = before.clone();
    changed.rollback_journal_sha256 = Some("0".repeat(64));
    assert!(manager.persist(&changed).is_err());
    changed.rollback_plan_id = None;
    changed.rollback_journal_sha256 = None;
    assert!(manager.persist(&changed).is_err());
    assert_eq!(manager.load_or_init().unwrap(), before);
    manager.rollback("regression").unwrap();
    assert!(manager.persist(&before).is_err());
}

#[test]
fn invalid_state_ids_confidence_and_ramp_configuration_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    for id in ["../outside", "x/y", "", "x\\y", "/absolute"] {
        let manager = RolloutManager::new(root.path(), Some(id));
        assert!(manager.load_or_init().is_err());
        assert!(manager.rollback("no").is_err());
    }
    assert!(!root.path().join(".franken-node").exists());
    let manager = RolloutManager::new(root.path(), Some("mig-bounds"));
    let state = manager.load_or_init().unwrap();
    for score in [f64::NAN, f64::INFINITY, -0.1, 1.1] {
        let mut changed = state.clone();
        changed.confidence_score = score;
        assert!(manager.persist(&changed).is_err());
        let config = RolloutConfig { min_confidence_score: score, ..forced() };
        assert!(manager.promote(&config, None, None).is_err());
    }
    for step in [0, 101, 255] {
        assert!(manager.promote(&RolloutConfig { ramp_step_pct: step, ..forced() }, None, None).is_err());
    }
    assert_eq!(manager.load_or_init().unwrap(), state);
}

#[test]
fn promotion_cannot_skip_stages_regress_the_ramp_or_bypass_recovery() {
    let root = tempfile::tempdir().unwrap();
    let manager = RolloutManager::new(root.path(), Some("mig-stages"));
    let config = RolloutConfig { require_lockstep_evidence: false, ..RolloutConfig::default() };
    assert!(manager.promote(&config, Some(RolloutStage::Ramp), Some(90)).is_err());
    manager.promote(&config, None, None).unwrap();
    assert!(manager.promote(&config, Some(RolloutStage::Default), None).is_err());
    manager.promote(&config, None, None).unwrap();
    assert!(manager.promote(&config, Some(RolloutStage::Ramp), Some(25)).is_err());
    assert!(manager.promote(&forced(), Some(RolloutStage::Aborted), None).is_err());
    manager.promote(&RolloutConfig { ramp_step_pct: 100, ..config }, None, None).unwrap();
    assert_eq!(manager.status().unwrap().ramp_pct, 100);
}

#[test]
fn lifecycle_operations_respect_the_project_wide_store_lock() {
    let (root, id) = applied_project();
    let manager = RolloutManager::new(root.path(), Some(&id));
    let state = manager.load_or_init().unwrap();
    let lock = manager.open_store().unwrap();
    assert!(manager.status().is_err());
    assert!(manager.persist(&state).is_err());
    assert!(manager.promote(&forced(), None, None).is_err());
    assert!(manager.rollback("busy").is_err());
    sources(root.path(), false);
    drop(lock);
    manager.rollback("lock released").unwrap();
    sources(root.path(), true);
}

#[test]
fn process_exit_between_intent_restore_and_completion_is_restart_safe() {
    const ROOT: &str = "FRANKEN_ROLLOUT_RECOVERY_ROOT";
    const ID: &str = "FRANKEN_ROLLOUT_RECOVERY_ID";
    const RESTORE: &str = "FRANKEN_ROLLOUT_RECOVERY_RESTORE";
    if let Some(root) = std::env::var_os(ROOT) {
        let root = PathBuf::from(root);
        let id = std::env::var(ID).unwrap();
        let manager = RolloutManager::new(&root, Some(&id));
        let store = manager.open_store().unwrap();
        let mut intent = manager.load_or_init_locked(&store).unwrap();
        intent.current_stage = RolloutStage::Aborted;
        intent.status = RolloutStatus::Failed;
        intent.ramp_pct = 0;
        manager.persist_locked(&store, &intent).unwrap();
        if std::env::var(RESTORE).unwrap() == "yes" {
            manager.restore_bound_source(&intent).unwrap();
        }
        // Real process exit skips lock destructors and final state publication.
        std::process::exit(73);
    }
    for restore in [false, true] {
        let (root, id) = applied_project();
        let manager = RolloutManager::new(root.path(), Some(&id));
        manager.load_or_init().unwrap();
        let path = module_path!().split_once("::").map_or("", |(_, path)| path);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("{path}::process_exit_between_intent_restore_and_completion_is_restart_safe")])
            .env(ROOT, root.path()).env(ID, &id).env(RESTORE, if restore { "yes" } else { "no" })
            .output().unwrap();
        assert_eq!(output.status.code(), Some(73), "{output:?}");
        assert_eq!(manager.status().unwrap().status, RolloutStatus::Failed);
        assert!(manager.promote(&forced(), None, None).is_err());
        if restore {
            // Native completion is already durable; a later edit is not undone
            // merely because rollout completion was interrupted.
            fs::write(root.path().join("a.js"), b"after crash user work").unwrap();
        }
        let report = RolloutManager::new(root.path(), Some(&id)).rollback("recover").unwrap();
        assert!(report.source_rollback.unwrap().restoration_recorded);
        if restore {
            assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after crash user work");
        } else {
            sources(root.path(), true);
        }
    }
}
