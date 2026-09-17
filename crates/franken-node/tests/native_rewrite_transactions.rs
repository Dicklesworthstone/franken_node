//! Real filesystem tests of the primary migration rewrite API.
//! ESM regressions also execute trusted Node fixtures; no native-runtime parity is claimed.

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
    assert!(!outside.path().join("source.js")).exists());
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

#[test]
fn primary_rewrite_then_operator_rollback_restores_the_complete_original_project() {
    use frankenengine_node::migration::rollback::{self, RollbackStatus, TransactionState};
    let root = project();
    let manifest = r#"{"name":"needs-pin","version":"1.0.0"}"#;
    fs::write(root.path().join("package.json"), manifest).unwrap();
    fs::write(root.path().join("keep.txt"), "unrelated input").unwrap();
    let before = run_rewrite(root.path(), false).unwrap();
    assert_eq!(before.rewrites_planned, 3);
    let applied = run_rewrite(root.path(), true).unwrap();
    assert_eq!(applied.rewrites_applied, 3);
    let history = rollback::run(root.path(), None, false);
    assert_eq!(history.status, RollbackStatus::History, "{history:#?}");
    assert_eq!(history.history.len(), 1);
    let id = &history.history[0].transaction_id;
    assert_eq!(history.history[0].state, TransactionState::Applied);
    let preview = rollback::run(root.path(), Some(id), false);
    assert_eq!(preview.status, RollbackStatus::Ready, "{preview:#?}");
    assert_eq!(preview.files.len(), 3);
    assert!(fs::read_to_string(root.path().join("a.js")).unwrap().contains("import fs"));
    let restored = rollback::run(root.path(), Some(id), true);
    assert_eq!(restored.status, RollbackStatus::RolledBack, "{restored:#?}");
    originals(root.path());
    assert_eq!(fs::read_to_string(root.path().join("package.json")).unwrap(), manifest);
    assert_eq!(fs::read_to_string(root.path().join("keep.txt")).unwrap(), "unrelated input");
    assert_eq!(fs::metadata(root.path().join("a.js")).unwrap().permissions().mode() & 0o777, 0o755);
    assert!(run_rewrite(root.path(), false).unwrap().rewrites_planned == 3);
    assert!(!pending(root.path()).exists());
}

#[test]
fn primary_rollback_refuses_later_user_edits_without_restoring_other_sources() {
    use frankenengine_node::migration::rollback::{self, RollbackStatus};
    let root = project();
    run_rewrite(root.path(), true).unwrap();
    let history = rollback::run(root.path(), None, false);
    let id = &history.history[0].transaction_id;
    let after_a = fs::read(root.path().join("a.js")).unwrap();
    fs::write(root.path().join("z.js"), "const my_work = 42;\n").unwrap();
    let report = rollback::run(root.path(), Some(id), true);
    assert_eq!(report.status, RollbackStatus::Conflict, "{report:#?}");
    assert_eq!(report.exit_code(), 1);
    assert_eq!(fs::read(root.path().join("a.js")).unwrap(), after_a);
    assert_eq!(fs::read_to_string(root.path().join("z.js")).unwrap(), "const my_work = 42;\n");
    assert!(!pending(root.path()).exists());
}

#[test]
fn primary_reapply_after_rollback_is_safe_against_old_transaction_retries() {
    use frankenengine_node::migration::rollback::{self, RollbackStatus, TransactionState};
    let root = project();
    run_rewrite(root.path(), true).unwrap();
    let id = rollback::run(root.path(), None, false).history[0].transaction_id.clone();
    assert_eq!(rollback::run(root.path(), Some(&id), true).status, RollbackStatus::RolledBack);
    assert_eq!(run_rewrite(root.path(), true).unwrap().rewrites_applied, 2);
    let after_a = fs::read(root.path().join("a.js")).unwrap();
    let retry = rollback::run(root.path(), Some(&id), true);
    assert_eq!(retry.status, RollbackStatus::AlreadyRolledBack, "{retry:#?}");
    assert_eq!(fs::read(root.path().join("a.js")).unwrap(), after_a);
    let history = rollback::run(root.path(), None, false);
    assert_eq!(history.history.len(), 2);
    assert_eq!(history.history.iter().filter(|row| row.state == TransactionState::Applied).count(), 1);
    assert_eq!(fs::read_to_string(root.path().join(".migrate-backup/a.js")).unwrap(), A);
}

#[test]
fn primary_rollback_history_and_preview_do_not_expose_saved_source_contents() {
    use frankenengine_node::migration::rollback::{self, RollbackReport, RollbackStatus};
    let root = project();
    let empty = rollback::run(root.path(), None, false);
    assert_eq!(empty.status, RollbackStatus::History);
    assert!(!root.path().join(".migrate-backup").exists());
    run_rewrite(root.path(), true).unwrap();
    let history = rollback::run(root.path(), None, false);
    let id = &history.history[0].transaction_id;
    let preview = rollback::run(root.path(), Some(id), false);
    assert_eq!(preview.status, RollbackStatus::Ready);
    for report in [&history, &preview] {
        let encoded = serde_json::to_string(report).unwrap();
        assert!(!encoded.contains("require('fs')"));
        assert!(!encoded.contains("existsSync"));
        assert_eq!(serde_json::from_str::<RollbackReport>(&encoded).unwrap(), *report);
    }
}

/// Execute the actual public rewrite, writer and rollback paths on trusted
/// fixtures. Node before/after agreement measures these transformations, not
/// native Franken compatibility or equivalence of unexecuted applications.
mod esm_source_rewrites {
    use super::*;
    use std::process::{Command, Output};

    fn fixture(source: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::write(root.path().join("package.json"),
            r#"{"name":"esm-rewrite","version":"1.0.0","type":"module","engines":{"node":">=20"}}"#).unwrap();
        fs::write(root.path().join("src/main.mjs"), source).unwrap();
        fs::set_permissions(root.path().join("src/main.mjs"), fs::Permissions::from_mode(0o755)).unwrap();
        root
    }

    fn execute(root: &Path) -> Output {
        Command::new("node").arg("src/main.mjs").current_dir(root).output().expect("real Node required")
    }

    fn equivalent(before: &Output, after: &Output) {
        assert!(before.status.success(), "reference stderr: {:?}", before.stderr);
        assert!(after.status.success(), "rewritten stderr: {:?}", after.stderr);
        assert_eq!(before.stdout, after.stdout);
        assert_eq!(before.stderr, after.stderr);
    }

    #[test]
    fn primary_multiline_and_dynamic_imports_execute_then_rollback_to_original_bytes() {
        use frankenengine_node::migration::rollback::{self, RollbackStatus};
        let source = "#!/usr/bin/env node\nimport {\n basename\n} /* load */ from 'path';\nexport { sep } from 'path';\nconst fs=await import(\n'fs/promises'\n);\nconsole.log(basename('/x/y'),typeof fs.readFile);\n";
        let root = fixture(source);
        let before = execute(root.path());
        let plan = run_rewrite(root.path(), false).unwrap();
        assert_eq!(plan.rewrites_planned, 1);
        assert_eq!(plan.rewrites_applied, 0);
        assert!(!root.path().join(".migrate-backup").exists());
        let report = run_rewrite(root.path(), true).unwrap();
        assert_eq!(report.rewrites_applied, 1, "{report:#?}");
        assert_eq!(report.manual_review_items, 0, "{report:#?}");
        let rewritten = fs::read_to_string(root.path().join("src/main.mjs")).unwrap();
        assert!(rewritten.contains("from 'node:path'"));
        assert!(rewritten.contains("import(\n'node:fs/promises'\n)"));
        assert_eq!(fs::read_to_string(root.path().join(".migrate-backup/src/main.mjs")).unwrap(), source);
        assert_eq!(fs::metadata(root.path().join("src/main.mjs")).unwrap().permissions().mode() & 0o777, 0o755);
        equivalent(&before, &execute(root.path()));
        let repeated = run_rewrite(root.path(), true).unwrap();
        assert_eq!(repeated.rewrites_applied, 0);
        assert!(repeated.rollback_entries.is_empty());
        let history = rollback::run(root.path(), None, false);
        assert_eq!(history.history.len(), 1);
        let restored = rollback::run(root.path(), Some(&history.history[0].transaction_id), true);
        assert_eq!(restored.status, RollbackStatus::RolledBack, "{restored:#?}");
        assert_eq!(fs::read_to_string(root.path().join("src/main.mjs")).unwrap(), source);
        equivalent(&before, &execute(root.path()));
    }

    #[test]
    fn primary_preserves_multiline_template_data_that_looks_like_imports() {
        let source = "import path from 'path';\nconst text=`payload\nimport fs from 'fs';\nrequire('os');\nmodule.exports = 1;\nend`;\nconsole.log(text,path.basename('/a/b'));\n";
        let root = fixture(source);
        let before = execute(root.path());
        let report = run_rewrite(root.path(), true).unwrap();
        assert_eq!(report.rewrites_applied, 1, "{report:#?}");
        assert_eq!(report.manual_review_items, 0, "{report:#?}");
        equivalent(&before, &execute(root.path()));
        let rewritten = fs::read_to_string(root.path().join("src/main.mjs")).unwrap();
        assert!(rewritten.contains("\nimport fs from 'fs';\n"));
        assert!(!rewritten.contains("node:fs"));
    }

    #[test]
    fn primary_does_not_redirect_builtin_named_third_party_package_exports() {
        let source = "import custom from 'fs/custom';import {basename} from 'path';console.log(custom,basename('/a/b'));";
        let root = fixture(source);
        let package = root.path().join("node_modules/fs");
        fs::create_dir_all(&package).unwrap();
        fs::write(package.join("package.json"), r#"{"name":"fs","type":"module","exports":{"./custom":"./custom.mjs"}}"#).unwrap();
        fs::write(package.join("custom.mjs"), "export default 'external-package';").unwrap();
        let before = execute(root.path());
        let report = run_rewrite(root.path(), true).unwrap();
        assert_eq!(report.rewrites_applied, 1);
        assert_eq!(report.rollback_entries.len(), 1);
        let rewritten = fs::read_to_string(root.path().join("src/main.mjs")).unwrap();
        assert!(rewritten.contains("from 'fs/custom'"));
        assert!(rewritten.contains("from 'node:path'"));
        equivalent(&before, &execute(root.path()));
        assert_eq!(fs::read_to_string(package.join("custom.mjs")).unwrap(), "export default 'external-package';");
    }

    #[test]
    fn primary_rejects_malformed_or_unresolved_imports_without_installing_partial_source() {
        for source in ["import fs from 'fs'; const x = ;", "import fs from 'fs'; import(name);",
                       "import fs from 'fs'; const x=require('path');"] {
            let root = fixture(source);
            let report = run_rewrite(root.path(), true).unwrap();
            assert_eq!(report.rewrites_applied, 0, "{report:#?}");
            assert_eq!(report.rewrites_planned, 0);
            assert!(report.manual_review_items > 0);
            assert!(report.rollback_entries.is_empty());
            assert_eq!(fs::read_to_string(root.path().join("src/main.mjs")).unwrap(), source);
            assert!(!root.path().join(".migrate-backup/src/main.mjs").exists());
        }
    }

    #[test]
    fn primary_multiple_imports_on_one_line_are_all_migrated() {
        let source = "import fs from 'fs';import path from 'path';import os from 'os';console.log(typeof fs.readFile,path.basename('/a/b'),typeof os.platform);";
        let root = fixture(source);
        let before = execute(root.path());
        let report = run_rewrite(root.path(), true).unwrap();
        assert_eq!(report.rewrites_applied, 1);
        let rewritten = fs::read_to_string(root.path().join("src/main.mjs")).unwrap();
        for specifier in ["node:fs", "node:path", "node:os"] { assert!(rewritten.contains(specifier)); }
        equivalent(&before, &execute(root.path()));
    }

    #[test]
    fn primary_jsx_preserves_import_like_text_while_migrating_the_real_import() {
        let root = fixture("import path from 'path';const view=<div>import fs from 'fs';</div>;export {view};");
        // The selected JavaScript grammar accepts JSX syntax; this test checks
        // source preservation only, not Node's ability to execute JSX directly.
        let report = run_rewrite(root.path(), true).unwrap();
        assert_eq!(report.rewrites_applied, 1, "{report:#?}");
        assert_eq!(report.manual_review_items, 0);
        let rewritten = fs::read_to_string(root.path().join("src/main.mjs")).unwrap();
        assert!(rewritten.contains("from 'node:path'"));
        assert!(rewritten.contains("<div>import fs from 'fs';</div>"));
    }
}
