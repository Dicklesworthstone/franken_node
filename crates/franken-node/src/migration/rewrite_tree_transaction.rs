//! Whole new directory trees as records in the existing write-ahead journal.
//!
//! The staged root is consumed atomically; its presence proves a colliding live
//! pathname is not ours. Rollback moves an unchanged complete tree into private
//! retained storage. A new user descendant is a conflict, never disposable data.

use super::{
    AppliedRewrite, CreateFile, CreateTree, Edit, InstallRequest, Journal,
    MAX_JOURNAL_BYTES, PENDING, RenameFlags, RewriteTransaction, TREE_JOURNAL_VERSION,
    directory, parent_and_name, read_optional, read_required, renameat_with,
    rollback, same_version, trees, verify_image,
};
use anyhow::{Context, Result, ensure};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

struct TreeState {
    parent: File,
    name: OsString,
    session: File,
    index: Vec<u8>,
    current: Option<Metadata>,
    queued: Option<Metadata>,
    retired: Option<Metadata>,
}

impl RewriteTransaction {
    /// Install a complete reviewed plan, including wholly new directory roots.
    /// Each root is one atomic target; the combined plan remains recoverable,
    /// not globally atomic. Unchanged/file-only plans retain their old schema.
    pub fn apply_with_trees_receipt(
        &self,
        edits: &[Edit<'_>],
        creations: &[CreateFile<'_>],
        trees: &[CreateTree<'_>],
    ) -> Result<Option<AppliedRewrite>> {
        if trees.is_empty() {
            return self.apply_with_creations_receipt(edits, creations);
        }
        ensure!(read_optional(&self.store, OsStr::new(PENDING), MAX_JOURNAL_BYTES)?.is_none(),
            "unfinished rewrite must be recovered before creating directory trees");
        let journal = self.prepare_bound_plan(edits, creations, trees, TREE_JOURNAL_VERSION, None)?;
        self.apply_prepared(journal)
    }

    /// The same caller-owned request slot binds the entire candidate, including
    /// its tree roots. A recorded request cannot be repeated or downgraded to a
    /// file-only plan. Inspection remains side-effect free and recovery explicit.
    pub fn apply_with_trees_for_request(
        &self,
        request: &InstallRequest,
        edits: &[Edit<'_>],
        creations: &[CreateFile<'_>],
        trees: &[CreateTree<'_>],
    ) -> Result<AppliedRewrite> {
        if trees.is_empty() {
            return self.apply_for_request(request, edits, creations);
        }
        request.check_project(&self.project)?;
        ensure!(rollback::lookup_request(self, request)?.is_none(),
            "installation request already has a recorded outcome; inspect it instead of applying again");
        ensure!(read_optional(&self.store, OsStr::new(PENDING), MAX_JOURNAL_BYTES)?.is_none(),
            "unfinished rewrite requires explicit recovery before a named installation");
        let journal = self.prepare_bound_plan(edits, creations, trees, TREE_JOURNAL_VERSION, Some(request))?;
        self.apply_prepared(journal)?.context("named tree installation has no journal identity")
    }

    fn inspect_tree(&self, journal: &Journal, ordinal: usize) -> Result<TreeState> {
        let record = journal.records.get(ordinal).context("invalid tree record ordinal")?;
        let summary = record.tree.as_ref().context("record is not a tree creation")?;
        ensure!(journal.schema_version == TREE_JOURNAL_VERSION && record.created,
            "tree creation requires an absent-preimage v5 journal");
        let session = directory(&self.store, Path::new(&journal.session), false)?;
        ensure!(session.metadata()?.mode() & 0o7777 == 0o700,
            "tree recovery directory must remain private");
        let image = read_required(&session, OsStr::new(&format!("{ordinal}.after")), trees::MAX_INDEX_BYTES)?;
        ensure!(verify_image(&image, &record.after_sha256, record.after_bytes, Some(0o600)),
            "tree recovery index integrity or permissions changed");
        ensure!(trees::summarize(&image.bytes)? == *summary
            && trees::root_mode(&image.bytes)? == record.mode,
            "tree index differs from its journal summary or root mode");
        let (parent, name) = parent_and_name(&self.root, &record.path, false)?;
        ensure!(parent.metadata()?.dev() == session.metadata()?.dev(),
            "tree target and transaction no longer share a filesystem");
        let queued = trees::verify(&session, OsStr::new(&format!("{ordinal}.new")), &image.bytes)?;
        let retired = trees::verify(&session, OsStr::new(&format!("{ordinal}.retired")), &image.bytes)?;
        ensure!(queued.is_none() || retired.is_none(), "tree is both queued and retired");
        let current = trees::verify(&parent, &name, &image.bytes)?;
        if current.is_some() {
            ensure!(queued.is_none(), "uninstalled tree target appeared; preserving it: {}", record.path);
            ensure!(retired.is_none(), "retired tree target reappeared; preserving it: {}", record.path);
        }
        ensure!(queued.is_some() || retired.is_some() || current.is_some(),
            "all copies of the recorded tree are missing; recovery evidence is incomplete");
        Ok(TreeState { parent, name, session, index: image.bytes, current, queued, retired })
    }

    pub(super) fn tree_is_original(&self, journal: &Journal, ordinal: usize) -> Result<bool> {
        Ok(self.inspect_tree(journal, ordinal)?.current.is_none())
    }

    pub(super) fn check_tree_ready(&self, journal: &Journal, ordinal: usize) -> Result<()> {
        let state = self.inspect_tree(journal, ordinal)?;
        ensure!(state.current.is_none() && state.queued.is_some() && state.retired.is_none(),
            "tree creation is not queued against an absent root");
        Ok(())
    }

    pub(super) fn install_tree(&self, journal: &Journal, ordinal: usize) -> Result<()> {
        let state = self.inspect_tree(journal, ordinal)?;
        let queued = state.queued.as_ref().context("tree creation is not queued")?;
        ensure!(state.current.is_none() && state.retired.is_none(),
            "tree creation target is not absent");
        let leaf = format!("{ordinal}.new");
        let checked = trees::verify(&state.session, OsStr::new(&leaf), &state.index)?
            .context("staged tree disappeared")?;
        ensure!(same_version(queued, &checked), "staged tree changed before installation");
        renameat_with(&state.session, leaf.as_str(), &state.parent, &state.name, RenameFlags::NOREPLACE)?;
        self.dirty.borrow_mut().mark(&state.session)?;
        self.dirty.borrow_mut().mark(&state.parent)
    }

    pub(super) fn restore_tree(&self, journal: &Journal, ordinal: usize) -> Result<()> {
        let state = self.inspect_tree(journal, ordinal)?;
        if let Some(current) = &state.current {
            let checked = trees::verify(&state.parent, &state.name, &state.index)?
                .context("created tree disappeared before retirement")?;
            ensure!(same_version(current, &checked), "created tree changed before retirement");
            renameat_with(&state.parent, &state.name, &state.session,
                format!("{ordinal}.retired").as_str(), RenameFlags::NOREPLACE)?;
        }
        // A retry must persist both sides even after observing the completed
        // rename. The complete immutable bytes remain private and recoverable.
        self.dirty.borrow_mut().mark(&state.parent)?;
        self.dirty.borrow_mut().mark(&state.session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{DURABILITY_LOG, STORE, digest};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app.cjs"), b"before").unwrap();
        root
    }
    fn edits() -> [Edit<'static>; 1] {
        [Edit { path: "app.cjs", before: b"before", after: b"after" }]
    }
    fn files() -> [CreateFile<'static>; 1] {
        [CreateFile { path: "helper.cjs", after: b"helper", mode: 0o640 }]
    }
    fn entries() -> [trees::Entry<'static>; 3] {
        [trees::Entry { path: "deep", contents: None, mode: 0o750 },
         trees::Entry { path: "deep/answer.cjs", contents: Some(b"module.exports=42;"), mode: 0o640 },
         trees::Entry { path: "empty", contents: None, mode: 0o500 }]
    }
    fn tree<'a>(entries: &'a [trees::Entry<'a>]) -> CreateTree<'a> {
        CreateTree { path: "src", mode: 0o750, entries }
    }
    fn store(root: &Path) -> PathBuf { root.join(".migrate-backup").join(STORE) }
    fn apply(root: &Path) -> AppliedRewrite {
        RewriteTransaction::open_without_recovery(root).unwrap()
            .apply_with_trees_receipt(&edits(), &files(), &[tree(&entries())]).unwrap().unwrap()
    }
    fn restore(root: &Path, receipt: &AppliedRewrite) -> rollback::RollbackReport {
        rollback::run_pinned(root, &receipt.transaction_id, &receipt.journal_sha256, true)
    }

    #[test]
    fn complete_mixed_plan_installs_and_pinned_rollback_retains_every_created_byte() {
        let root = root();
        let receipt = apply(root.path());
        assert_eq!(receipt.files, 3); // replacement, regular creation, tree root
        let session = store(root.path()).join(&receipt.transaction_id);
        let raw = fs::read(session.join("applied.json")).unwrap();
        let journal: Journal = serde_json::from_slice(&raw).unwrap();
        assert_eq!(journal.schema_version, TREE_JOURNAL_VERSION);
        assert_eq!(journal.records[2].tree, Some(trees::Summary { files: 1, directories: 3, bytes: 18 }));
        assert_eq!(receipt.journal_sha256, digest(&raw));
        assert!(root.path().join("src/empty").is_dir());
        assert_eq!(fs::metadata(root.path().join("src/deep")).unwrap().mode() & 0o777, 0o750);
        assert_eq!(fs::read(root.path().join("src/deep/answer.cjs")).unwrap(), b"module.exports=42;");
        let preview = rollback::run_pinned(root.path(), &receipt.transaction_id, &receipt.journal_sha256, false);
        assert_eq!(preview.status, rollback::RollbackStatus::Ready);
        assert!(preview.files[2].original_absent);
        assert_eq!(preview.files[2].path, "src");
        assert_eq!(restore(root.path(), &receipt).status, rollback::RollbackStatus::RolledBack);
        assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"before");
        assert!(!root.path().join("src").exists());
        assert!(!root.path().join("helper.cjs").exists());
        assert_eq!(fs::read(session.join("2.retired/deep/answer.cjs")).unwrap(), b"module.exports=42;");
        assert_eq!(fs::read(session.join("1.retired")).unwrap(), b"helper");
        fs::create_dir(root.path().join("src")).unwrap();
        fs::write(root.path().join("src/later"), b"later user work").unwrap();
        assert_eq!(restore(root.path(), &receipt).status, rollback::RollbackStatus::AlreadyRolledBack);
        assert_eq!(fs::read(root.path().join("src/later")).unwrap(), b"later user work");
    }

    #[test]
    fn later_descendants_modes_aliases_and_bytes_block_all_explicit_rollback_writes() {
        for mutation in 0..5 {
            let root = root();
            let receipt = apply(root.path());
            let path = root.path().join("src/deep/answer.cjs");
            match mutation {
                0 => fs::write(root.path().join("src/user-work"), b"preserve").unwrap(),
                1 => fs::write(&path, b"changed").unwrap(),
                2 => fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap(),
                3 => fs::hard_link(&path, root.path().join("alias")).unwrap(),
                _ => {
                    fs::rename(&path, root.path().join("saved")).unwrap();
                    symlink("../../saved", &path).unwrap();
                }
            }
            assert_eq!(restore(root.path(), &receipt).status, rollback::RollbackStatus::Conflict);
            assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"after");
            assert_eq!(fs::read(root.path().join("helper.cjs")).unwrap(), b"helper");
            assert!(!store(root.path()).join(PENDING).exists());
            assert!(root.path().join("src").is_dir());
        }
    }

    #[test]
    fn collision_with_even_an_identical_tree_never_becomes_owned_recovery_work() {
        let root = root();
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        let entries = entries();
        let tree = tree(&entries);
        let journal = writer.prepare_bound_plan(&edits(), &files(), &[tree], TREE_JOURNAL_VERSION, None).unwrap();
        writer.install(&journal, 0).unwrap();
        let (index, _) = trees::encode(&self::tree(&entries)).unwrap();
        trees::stage(&File::open(root.path()).unwrap(), OsStr::new("src"), &self::tree(&entries), &index).unwrap();
        let inode = fs::metadata(root.path().join("src")).unwrap().ino();
        assert!(writer.install(&journal, 2).is_err());
        assert!(writer.recover_pending().is_err());
        assert_eq!(fs::metadata(root.path().join("src")).unwrap().ino(), inode);
        assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"before");
        assert!(store(root.path()).join(&journal.session).join("2.new").is_dir());
        assert!(store(root.path()).join(PENDING).is_file());
    }

    #[test]
    fn corrupt_or_missing_index_or_staging_never_install_any_live_target() {
        for mutation in 0..4 {
            let root = root();
            let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
            let journal = writer.prepare_bound_plan(&edits(), &files(), &[tree(&entries())], TREE_JOURNAL_VERSION, None).unwrap();
            let session = store(root.path()).join(&journal.session);
            match mutation {
                0 => fs::write(session.join("2.after"), b"{}").unwrap(),
                1 => fs::write(session.join("2.new/deep/answer.cjs"), b"changed").unwrap(),
                2 => fs::write(session.join("2.new/extra"), b"unrecorded").unwrap(),
                _ => fs::rename(session.join("2.new"), session.join("saved-tree")).unwrap(),
            }
            assert!(writer.apply_prepared(journal).is_err());
            assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"before");
            assert!(!root.path().join("helper.cjs").exists());
            assert!(!root.path().join("src").exists());
            assert!(store(root.path()).join(PENDING).is_file());
        }
    }

    #[test]
    fn schema_downgrade_false_summaries_and_overlapping_roots_cannot_redefine_tree_records() {
        let root = root();
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        let journal = writer.prepare_bound_plan(&edits(), &files(), &[tree(&entries())], TREE_JOURNAL_VERSION, None).unwrap();
        for schema in [super::super::JOURNAL_VERSION, super::super::VERSIONED_JOURNAL_VERSION,
            super::super::creations::JOURNAL_VERSION, super::super::REQUEST_JOURNAL_VERSION] {
            let mut changed = journal.clone();
            changed.schema_version = schema.into();
            assert!(RewriteTransaction::validate_journal(&changed).is_err());
        }
        let mut changed = journal.clone();
        changed.records[2].tree.as_mut().unwrap().files += 1;
        assert!(writer.check_tree_ready(&changed, 2).is_err());
        changed = journal.clone();
        changed.records[2].mode = 0o700;
        assert!(writer.check_tree_ready(&changed, 2).is_err());
        changed = journal.clone();
        changed.records[0].path = "src/other".into();
        assert!(RewriteTransaction::validate_journal(&changed).is_err());
        changed = journal.clone();
        changed.records[2].tree.as_mut().unwrap().directories = usize::MAX;
        assert!(RewriteTransaction::validate_journal(&changed).is_err());
        assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"before");
        assert!(!root.path().join("src").exists());
    }

    #[test]
    fn request_identity_covers_tree_plans_and_cannot_downgrade_on_retry() {
        let root = root();
        let request = InstallRequest::new(root.path(), "tree-1", &"a".repeat(64), &"b".repeat(64)).unwrap();
        let receipt = RewriteTransaction::open_without_recovery(root.path()).unwrap()
            .apply_with_trees_for_request(&request, &edits(), &files(), &[tree(&entries())]).unwrap();
        assert_eq!(rollback::inspect_request(root.path(), &request).unwrap().unwrap().transaction_id, request.transaction_id());
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        assert!(writer.apply_for_request(&request, &[], &[]).is_err());
        assert!(writer.apply_with_trees_for_request(&request, &edits(), &files(), &[tree(&entries())]).is_err());
        drop(writer);
        assert_eq!(restore(root.path(), &receipt).status, rollback::RollbackStatus::RolledBack);
        assert_eq!(rollback::inspect_request(root.path(), &request).unwrap().unwrap().state, rollback::TransactionState::RolledBack);
    }

    #[test]
    fn each_abrupt_process_exit_boundary_uses_the_same_startup_and_explicit_recovery() {
        const ROOT: &str = "FRANKEN_TREE_CRASH_ROOT";
        const STEP: &str = "FRANKEN_TREE_CRASH_STEP";
        if let Some(root) = std::env::var_os(ROOT) {
            let writer = RewriteTransaction::open_without_recovery(Path::new(&root)).unwrap();
            let journal = writer.prepare_bound_plan(&edits(), &files(), &[tree(&entries())], TREE_JOURNAL_VERSION, None).unwrap();
            for index in 0..std::env::var(STEP).unwrap().parse::<usize>().unwrap() {
                writer.install(&journal, index).unwrap();
            }
            std::process::exit(73);
        }
        let module = module_path!().split_once("::").unwrap().1;
        for step in 0..=3 {
            let root = root();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &format!("{module}::each_abrupt_process_exit_boundary_uses_the_same_startup_and_explicit_recovery")])
                .env(ROOT, root.path()).env(STEP, step.to_string()).output().unwrap();
            assert_eq!(child.status.code(), Some(73), "{}", String::from_utf8_lossy(&child.stderr));
            let pending = fs::read(store(root.path()).join(PENDING)).unwrap();
            let journal: Journal = serde_json::from_slice(&pending).unwrap();
            if step % 2 == 0 {
                drop(RewriteTransaction::open(root.path()).unwrap());
            } else {
                assert_eq!(rollback::run_pinned(root.path(), &journal.session, &digest(&pending), true).status,
                    rollback::RollbackStatus::RolledBack);
            }
            assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"before");
            assert!(!root.path().join("src").exists());
            assert!(!root.path().join("helper.cjs").exists());
            let session = store(root.path()).join(&journal.session);
            assert!(session.join("rolled-back.json").is_file());
            assert_eq!(session.join("2.retired").exists(), step == 3);
            assert_eq!(session.join("2.new").exists(), step != 3);
        }
    }

    #[test]
    fn tree_staging_is_durable_before_journal_and_live_renames_before_completion() {
        let root = root();
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        DURABILITY_LOG.with(|log| log.borrow_mut().clear());
        writer.apply_with_trees_receipt(&edits(), &files(), &[tree(&entries())]).unwrap();
        let log = DURABILITY_LOG.with(|log| log.borrow().clone());
        let tree = log.iter().position(|kind| *kind == "tree").unwrap();
        let journal = log.iter().position(|kind| *kind == "journal").unwrap();
        let archive = log.iter().position(|kind| *kind == "archive").unwrap();
        assert!(tree < journal && journal < archive);
        assert!(log[journal + 1..archive].contains(&"dir"));
    }
}
