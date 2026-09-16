//! Real filesystem tests of the primary migration rewrite API.
//! These do not execute guest code or claim transformation equivalence.

use frankenengine_node::migration::run_rewrite;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

const A: &str = "const fs = require('fs');\nconsole.log(fs.existsSync('package.json'));\n";
const B: &str = "const path = require('path');\nconsole.log(path.sep);\n";

fn project() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("package.json"),
        r#"{"name":"rewrite-test","version":"1.0.0","engines":{"node":">=20"}}"#).unwrap();
    fs::write(root.path().join("a.js"), A).unwrap();
    fs::write(root.path().join("z.js"), B).unwrap();
    fs::set_permissions(root.path().join("a.js"), fs::Permissions::from_mode(0o755)).unwrap();
    root
}

fn originals(root: &Path) {
    assert_eq!(fs::read_to_string(root.join("a.js")).unwrap(), A);
    assert_eq!(fs::read_to_string(root.join("z.js")).unwrap(), B);
}

fn pending(root: &Path) -> PathBuf {
    root.join(".migrate-backup/.franken-rewrite/pending.json")
}

#[test]
fn primary_apply_installs_complete_plan_and_preserves_executable_sources() {
    let root = project();
    let report = run_rewrite(root.path(), true).unwrap();
    assert_eq!(report.rewrites_planned, 2);
    assert_eq!(report.rewrites_applied, 2);
    assert_eq!(report.rollback_entries.len(), 2);
    assert!(fs::read_to_string(root.path().join("a.js")).unwrap().contains("import fs from \"node:fs\""));
    assert!(fs::read_to_string(root.path().join("z.js")).unwrap().contains("import path from \"node:path\""));
    assert_eq!(fs::metadata(root.path().join("a.js")).unwrap().permissions().mode() & 0o777, 0o755);
    assert_eq!(fs::read_to_string(root.path().join(".migrate-backup/a.js")).unwrap(), A);
    assert_eq!(fs::metadata(root.path().join(".migrate-backup/a.js")).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(!pending(root.path()).exists());
}

#[test]
fn primary_late_backup_conflict_does_not_mutate_earlier_sources_or_manifest() {
    let root = project();
    let manifest = r#"{"name":"needs-pin","version":"1.0.0"}"#;
    fs::write(root.path().join("package.json"), manifest).unwrap();
    fs::create_dir(root.path().join(".migrate-backup")).unwrap();
    fs::write(root.path().join(".migrate-backup/z.js"), "prior unrelated original").unwrap();
    let error = run_rewrite(root.path(), true).unwrap_err();
    assert!(format!("{error:#}").contains("backup conflict"));
    originals(root.path());
    assert_eq!(fs::read_to_string(root.path().join("package.json")).unwrap(), manifest);
    assert!(!root.path().join(".migrate-backup/a.js").exists());
    assert!(!pending(root.path()).exists());
}

#[test]
fn primary_dry_run_never_creates_locks_backups_or_a_journal() {
    let root = project();
    let report = run_rewrite(root.path(), false).unwrap();
    assert_eq!(report.rewrites_planned, 2);
    assert_eq!(report.rewrites_applied, 0);
    originals(root.path());
    assert!(!root.path().join(".migrate-backup").exists());
}

#[test]
fn primary_repeated_success_is_a_noop_and_preserves_immutable_backups() {
    let root = project();
    run_rewrite(root.path(), true).unwrap();
    let after = fs::read(root.path().join("a.js")).unwrap();
    let report = run_rewrite(root.path(), true).unwrap();
    assert_eq!(report.rewrites_applied, 0);
    assert!(report.rollback_entries.is_empty());
    assert_eq!(fs::read(root.path().join("a.js")).unwrap(), after);
    assert_eq!(fs::read_to_string(root.path().join(".migrate-backup/a.js")).unwrap(), A);
}

#[test]
fn primary_refuses_hardlinked_sources_without_partially_applying_other_edits() {
    let root = project();
    fs::hard_link(root.path().join("z.js"), root.path().join("z-alias.js")).unwrap();
    assert!(run_rewrite(root.path(), true).is_err());
    originals(root.path());
}

#[test]
fn primary_refuses_a_redirected_backup_parent_without_outside_writes() {
    let root = project();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("nested")).unwrap();
    fs::write(root.path().join("nested/source.js"), A).unwrap();
    fs::create_dir(root.path().join(".migrate-backup")).unwrap();
    symlink(outside.path(), root.path().join(".migrate-backup/nested")).unwrap();
    assert!(run_rewrite(root.path(), true).is_err());
    originals(root.path());
    assert!(!outside.path().join("source.js").exists());
}

#[test]
fn primary_refuses_an_overfull_plan_instead_of_dropping_early_rollback_entries() {
    let root = project();
    for index in 0..1000 {
        fs::write(root.path().join(format!("file-{index:04}.js")), A).unwrap();
    }
    let error = run_rewrite(root.path(), true).unwrap_err();
    assert!(error.to_string().contains("rewrite plan exceeds entry limit"));
    originals(root.path());
    assert_eq!(fs::read_to_string(root.path().join("file-0000.js")).unwrap(), A);
    assert_eq!(fs::read_to_string(root.path().join("file-0999.js")).unwrap(), A);
    assert!(!pending(root.path()).exists());
}

fn interrupted_fixture(root: &Path) -> Vec<String> {
    let plan = run_rewrite(root, false).unwrap();
    let store = root.join(".migrate-backup/.franken-rewrite");
    fs::create_dir_all(store.join("fixture-session")).unwrap();
    let mut records = Vec::new();
    let mut after = Vec::new();
    for entry in &plan.rollback_entries {
        fs::write(root.join(".migrate-backup").join(&entry.path), &entry.original_content).unwrap();
        let mode = fs::metadata(root.join(&entry.path)).unwrap().permissions().mode() & 0o777;
        records.push(serde_json::json!({
            "path": entry.path, "mode": mode,
            "before_sha256": hex::encode(Sha256::digest(entry.original_content.as_bytes())),
            "after_sha256": hex::encode(Sha256::digest(entry.rewritten_content.as_bytes())),
            "before_bytes": entry.original_content.len(), "after_bytes": entry.rewritten_content.len()
        }));
        after.push(entry.rewritten_content.clone());
    }
    fs::write(pending(root), serde_json::to_vec(&serde_json::json!({
        "schema_version": "franken-node/rewrite-transaction/v1", "session": "fixture-session", "records": records
    })).unwrap()).unwrap();
    fs::write(root.join("a.js"), &after[0]).unwrap();
    after
}

#[test]
fn primary_recovers_pending_partial_install_before_planning_the_next_apply() {
    let root = project();
    interrupted_fixture(root.path());
    let report = run_rewrite(root.path(), true).unwrap();
    assert_eq!(report.rewrites_applied, 2, "recovery must precede planning; otherwise only z.js gets planned");
    assert_eq!(report.rollback_entries[0].original_content, A);
    assert_eq!(report.rollback_entries[1].original_content, B);
    assert!(!pending(root.path()).exists());
    assert!(root.path().join(".migrate-backup/.franken-rewrite/fixture-session/rolled-back.json").is_file());
}

#[test]
fn primary_dry_run_does_not_recover_an_interrupted_live_apply() {
    let root = project();
    let after = interrupted_fixture(root.path());
    let journal = fs::read(pending(root.path())).unwrap();
    run_rewrite(root.path(), false).unwrap();
    assert_eq!(fs::read_to_string(root.path().join("a.js")).unwrap(), after[0]);
    assert_eq!(fs::read(pending(root.path())).unwrap(), journal);
}

#[test]
fn primary_recovery_conflict_preserves_user_edits_and_refuses_new_work() {
    let root = project();
    interrupted_fixture(root.path());
    fs::write(root.path().join("z.js"), "const user_edit = true;\n").unwrap();
    let error = run_rewrite(root.path(), true).unwrap_err();
    assert!(format!("{error:#}").contains("recovery conflict"));
    assert_eq!(fs::read_to_string(root.path().join("a.js")).unwrap(), A);
    assert_eq!(fs::read_to_string(root.path().join("z.js")).unwrap(), "const user_edit = true;\n");
    assert!(pending(root.path()).exists());
}
