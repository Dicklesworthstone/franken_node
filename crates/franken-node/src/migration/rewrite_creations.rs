//! Creation records for the native rewrite journal. A missing original is not
//! an empty original. Installation consumes a durable `.new` image via an
//! atomic no-replace rename. Recovery retains created bytes as `.retired`
//! rather than unlinking them. Existing files and directories are never deleted.

use super::{
    AppliedRewrite, Contents, Edit, Journal, MAX_FILE_BYTES, RenameFlags,
    RewriteTransaction, directory, parent_and_name, read_optional, read_required,
    renameat_with, same_version, verify_image,
};
use anyhow::{Context, Result, ensure};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(super) const JOURNAL_VERSION: &str = "franken-node/rewrite-transaction/v3";

/// An explicitly approved absent pathname and its exact new bytes/mode.
/// Parents must already exist; this cannot replace an existing file or link.
/// Deliberately not Debug: source bytes can contain private project data.
pub struct CreateFile<'a> {
    pub path: &'a str,
    pub after: &'a [u8],
    pub mode: u32,
}

struct CreationState {
    parent: File,
    name: OsString,
    session: File,
    current: Option<Contents>,
    queued: bool,
    retired: bool,
}

impl RewriteTransaction {
    /// Apply existing-file replacements and new regular files as one recoverable
    /// plan. Empty creation sets keep v2 journals; all nonempty creation sets use
    /// v3. Callers still own validation/approval and must hold this writer guard.
    pub fn apply_with_creations_receipt(
        &self,
        edits: &[Edit<'_>],
        creations: &[CreateFile<'_>],
    ) -> Result<Option<AppliedRewrite>> {
        if creations.is_empty() {
            return self.apply_versioned_with_receipt(edits);
        }
        let journal = self.prepare_changes(edits, creations, JOURNAL_VERSION)?;
        self.apply_prepared(journal)
    }

    fn inspect_creation(&self, journal: &Journal, index: usize) -> Result<CreationState> {
        let record = journal.records.get(index).context("invalid creation record index")?;
        ensure!((journal.schema_version == JOURNAL_VERSION
            || journal.schema_version == super::REQUEST_JOURNAL_VERSION) && record.created,
            "not a creation journal record");
        let session = directory(&self.store, Path::new(&journal.session), false)?;
        ensure!(session.metadata()?.mode() & 0o7777 == 0o700,
            "creation recovery directory must remain private");
        let (parent, name) = parent_and_name(&self.root, &record.path, false)?;
        let queued = read_optional(&session, OsStr::new(&format!("{index}.new")), MAX_FILE_BYTES)?;
        let retired = read_optional(&session, OsStr::new(&format!("{index}.retired")), MAX_FILE_BYTES)?;
        ensure!(queued.is_none() || retired.is_none(),
            "creation cannot be both uninstalled and retired");
        for image in queued.iter().chain(retired.iter()) {
            ensure!(verify_image(image, &record.after_sha256, record.after_bytes, Some(record.mode)),
                "creation recovery image content or permissions changed");
        }
        let current = read_optional(&parent, &name, MAX_FILE_BYTES)?;
        if let Some(current) = &current {
            // A failed NOREPLACE must not roll back somebody else's colliding
            // file, including a byte-identical one. A retired file reappearing
            // before completion likewise belongs to later work, not this retry.
            ensure!(queued.is_none(), "uninstalled creation target appeared; preserving it: {}", record.path);
            ensure!(retired.is_none(), "retired creation target reappeared; preserving it: {}", record.path);
            ensure!(verify_image(current, &record.after_sha256, record.after_bytes, Some(record.mode)),
                "created source content or permissions changed; preserving the user's edit: {}", record.path);
        }
        Ok(CreationState {
            parent, name, session, current,
            queued: queued.is_some(), retired: retired.is_some(),
        })
    }

    /// Pure preview used by explicit rollback's all-file preflight.
    pub(super) fn creation_is_original(&self, journal: &Journal, index: usize) -> Result<bool> {
        Ok(self.inspect_creation(journal, index)?.current.is_none())
    }

    pub(super) fn check_creation_ready(&self, journal: &Journal, index: usize) -> Result<()> {
        let state = self.inspect_creation(journal, index)?;
        ensure!(state.current.is_none() && state.queued && !state.retired,
            "creation is not queued against an absent target");
        Ok(())
    }

    pub(super) fn install_created(&self, journal: &Journal, index: usize) -> Result<()> {
        let state = self.inspect_creation(journal, index)?;
        ensure!(state.current.is_none() && state.queued && !state.retired,
            "creation is not queued against an absent target");
        // The .new image was fsynced before the durable journal. NOREPLACE
        // atomically preserves any pathname that appears after inspection.
        renameat_with(
            &state.session, format!("{index}.new").as_str(),
            &state.parent, &state.name, RenameFlags::NOREPLACE,
        )?;
        self.dirty.borrow_mut().mark(&state.session)?;
        self.dirty.borrow_mut().mark(&state.parent)
    }

    pub(super) fn restore_created(&self, journal: &Journal, index: usize) -> Result<()> {
        let state = self.inspect_creation(journal, index)?;
        if let Some(current) = &state.current {
            let checked = read_required(&state.parent, &state.name, MAX_FILE_BYTES)?;
            ensure!(same_version(&current.metadata, &checked.metadata) && current.bytes == checked.bytes,
                "created source changed before retirement");
            // Keep the exact new file in this private transaction. Never unlink
            // source bytes, replace an existing receipt, or follow a symlink.
            renameat_with(
                &state.parent, &state.name,
                &state.session, format!("{index}.retired").as_str(), RenameFlags::NOREPLACE,
            )?;
        }
        // Also flush on a retry which observes an already absent source: an
        // earlier process may have exited after rename but before either fsync.
        self.dirty.borrow_mut().mark(&state.parent)?;
        self.dirty.borrow_mut().mark(&state.session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{DURABILITY_LOG, PENDING, STORE, digest, rollback};
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("lib")).unwrap();
        fs::write(root.path().join("app.js"), b"original").unwrap();
        root
    }

    fn edits() -> [Edit<'static>; 1] {
        [Edit { path: "app.js", before: b"original", after: b"rewritten" }]
    }

    fn additions() -> [CreateFile<'static>; 2] {
        [
            CreateFile { path: "lib/helper.cjs", after: b"module.exports = 42;", mode: 0o640 },
            CreateFile { path: "lib/empty.cjs", after: b"", mode: 0o400 },
        ]
    }

    fn store(root: &Path) -> PathBuf {
        root.join(".migrate-backup").join(STORE)
    }

    fn applied(root: &Path) -> AppliedRewrite {
        RewriteTransaction::open_without_recovery(root).unwrap()
            .apply_with_creations_receipt(&edits(), &additions()).unwrap().unwrap()
    }

    fn restore(root: &Path, receipt: &AppliedRewrite) -> rollback::RollbackReport {
        rollback::run_pinned(root, &receipt.transaction_id, &receipt.journal_sha256, true)
    }

    fn original(root: &Path) {
        assert_eq!(fs::read(root.join("app.js")).unwrap(), b"original");
        assert!(!root.join("lib/helper.cjs").exists());
        assert!(!root.join("lib/empty.cjs").exists());
        assert!(root.join("lib").is_dir());
    }

    #[test]
    fn mixed_plan_creates_exact_images_and_restores_absence_without_deleting_bytes() {
        let root = fixture();
        let receipt = applied(root.path());
        assert_eq!(receipt.files, 3);
        assert_eq!(fs::read(root.path().join("app.js")).unwrap(), b"rewritten");
        for creation in additions() {
            assert_eq!(fs::read(root.path().join(creation.path)).unwrap(), creation.after);
            assert_eq!(fs::metadata(root.path().join(creation.path)).unwrap().mode() & 0o777, creation.mode);
        }
        let session = store(root.path()).join(&receipt.transaction_id);
        let journal: Journal = serde_json::from_slice(&fs::read(session.join("applied.json")).unwrap()).unwrap();
        assert_eq!(journal.schema_version, JOURNAL_VERSION);
        assert!(!journal.records[0].created && journal.records[1].created && journal.records[2].created);
        assert_eq!(digest(&serde_json::to_vec(&journal).unwrap()), receipt.journal_sha256);
        assert!(!session.join("1.before").exists() && !session.join("1.new").exists());
        let preview = rollback::run_pinned(root.path(), &receipt.transaction_id, &receipt.journal_sha256, false);
        assert_eq!(preview.status, rollback::RollbackStatus::Ready);
        assert!(preview.files[1].original_absent && preview.files[2].original_absent);
        assert_eq!(preview.files[1].preflight_state, rollback::SourceState::Rewritten);
        assert!(!session.join("1.retired").exists());
        assert_eq!(restore(root.path(), &receipt).status, rollback::RollbackStatus::RolledBack);
        original(root.path());
        assert_eq!(fs::read(session.join("1.retired")).unwrap(), additions()[0].after);
        assert_eq!(fs::read(session.join("2.retired")).unwrap(), b"");
        assert!(session.join("1.after").is_file());
        fs::write(root.path().join("lib/helper.cjs"), b"later user work").unwrap();
        assert_eq!(restore(root.path(), &receipt).status, rollback::RollbackStatus::AlreadyRolledBack);
        assert_eq!(fs::read(root.path().join("lib/helper.cjs")).unwrap(), b"later user work");
    }

    #[test]
    fn a_collision_even_with_identical_bytes_is_not_this_transactions_creation() {
        let root = fixture();
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        let journal = writer.prepare_changes(&edits(), &additions(), JOURNAL_VERSION).unwrap();
        writer.install(&journal, 0).unwrap();
        let colliding = root.path().join("lib/helper.cjs");
        fs::write(&colliding, additions()[0].after).unwrap();
        fs::set_permissions(&colliding, Permissions::from_mode(additions()[0].mode)).unwrap();
        let inode = fs::metadata(&colliding).unwrap().ino();
        assert!(writer.install(&journal, 1).is_err());
        assert!(writer.recover_pending().is_err());
        assert_eq!(fs::metadata(&colliding).unwrap().ino(), inode);
        assert_eq!(fs::read(&colliding).unwrap(), additions()[0].after);
        assert_eq!(fs::read(root.path().join("app.js")).unwrap(), b"original");
        assert!(store(root.path()).join(PENDING).exists());
        assert!(store(root.path()).join(&journal.session).join("1.new").is_file());
        assert!(!store(root.path()).join(&journal.session).join("1.retired").exists());
    }

    #[test]
    fn existing_paths_duplicates_reserved_paths_modes_and_missing_parents_fail_preflight() {
        let root = fixture();
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        for path in ["app.js", "lib", "missing/helper.cjs", "../outside", ".git/config", ".franken-node/key", ".migrate-backup/file"] {
            assert!(writer.apply_with_creations_receipt(&edits(), &[
                CreateFile { path, after: b"new", mode: 0o600 },
            ]).is_err(), "{path}");
            original(root.path());
        }
        for mode in [0, 0o200, 0o4644, 0o1777] {
            assert!(writer.apply_with_creations_receipt(&edits(), &[
                CreateFile { path: "lib/helper.cjs", after: b"new", mode },
            ]).is_err());
        }
        assert!(writer.apply_with_creations_receipt(&[], &[
            CreateFile { path: "lib/helper.cjs", after: b"one", mode: 0o600 },
            CreateFile { path: "lib/helper.cjs", after: b"two", mode: 0o600 },
        ]).is_err());
        assert_eq!(fs::read_dir(store(root.path())).unwrap().count(), 1);
        original(root.path());
    }

    #[test]
    fn symlink_leaves_and_parents_never_redirect_creation() {
        for parent in [false, true] {
            let root = fixture();
            let outside = tempfile::tempdir().unwrap();
            let path = if parent { "alias/helper.cjs" } else { "lib/helper.cjs" };
            symlink(if parent { outside.path().to_owned() } else { outside.path().join("absent") },
                root.path().join(if parent { "alias" } else { path })).unwrap();
            let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
            assert!(writer.apply_with_creations_receipt(&edits(), &[
                CreateFile { path, after: b"new", mode: 0o600 },
            ]).is_err());
            assert_eq!(fs::read(root.path().join("app.js")).unwrap(), b"original");
            assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
            assert!(!store(root.path()).join(PENDING).exists());
        }
    }

    #[test]
    fn all_file_rollback_preflight_preserves_a_later_modified_or_linked_creation() {
        for mutation in 0..4 {
            let root = fixture();
            let receipt = applied(root.path());
            let path = root.path().join("lib/helper.cjs");
            match mutation {
                0 => fs::write(&path, b"user edit").unwrap(),
                1 => fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap(),
                2 => fs::hard_link(&path, root.path().join("alias.cjs")).unwrap(),
                _ => {
                    fs::rename(&path, root.path().join("saved-helper")).unwrap();
                    symlink("../saved-helper", &path).unwrap();
                }
            }
            let report = restore(root.path(), &receipt);
            assert_eq!(report.status, rollback::RollbackStatus::Conflict, "{report:?}");
            assert_eq!(fs::read(root.path().join("app.js")).unwrap(), b"rewritten");
            assert!(root.path().join("lib/empty.cjs").exists());
            assert!(!store(root.path()).join(PENDING).exists());
        }
    }

    #[test]
    fn absent_preimages_cannot_be_smuggled_into_older_schemas_or_empty_file_records() {
        let root = fixture();
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        let journal = writer.prepare_changes(&edits(), &additions(), JOURNAL_VERSION).unwrap();
        for schema in [super::super::JOURNAL_VERSION, super::super::VERSIONED_JOURNAL_VERSION] {
            let mut changed = journal.clone();
            changed.schema_version = schema.into();
            assert!(RewriteTransaction::validate_journal(&changed).is_err());
        }
        for mutation in 0..3 {
            let mut changed = journal.clone();
            match mutation {
                0 => changed.records[1].before_bytes = 1,
                1 => changed.records[1].before_sha256 = "a".repeat(64),
                _ => changed.records[1].mode = 0o200,
            }
            assert!(RewriteTransaction::validate_journal(&changed).is_err());
        }
        let replacement = &journal.records[0];
        assert!(!serde_json::to_string(replacement).unwrap().contains("created"));
        original(root.path());
    }

    #[test]
    fn queued_image_corruption_cannot_install_or_fall_back_to_an_after_image() {
        let root = fixture();
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        let journal = writer.prepare_changes(&edits(), &additions(), JOURNAL_VERSION).unwrap();
        fs::write(store(root.path()).join(&journal.session).join("1.new"), b"tampered").unwrap();
        assert!(writer.apply_prepared(journal).is_err());
        original(root.path());
        assert!(store(root.path()).join(PENDING).exists());
    }

    #[test]
    fn a_retired_creation_reappearing_before_completion_is_preserved_even_if_identical() {
        let root = fixture();
        let receipt = applied(root.path());
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        let session = store(root.path()).join(&receipt.transaction_id);
        let raw = fs::read(session.join("applied.json")).unwrap();
        let journal: Journal = serde_json::from_slice(&raw).unwrap();
        writer.publish_journal(&raw).unwrap();
        writer.restore_created(&journal, 1).unwrap();
        fs::write(root.path().join("lib/helper.cjs"), additions()[0].after).unwrap();
        fs::set_permissions(root.path().join("lib/helper.cjs"), Permissions::from_mode(0o640)).unwrap();
        assert!(writer.recover_pending().is_err());
        assert_eq!(fs::read(root.path().join("lib/helper.cjs")).unwrap(), additions()[0].after);
        assert_eq!(fs::read(session.join("1.retired")).unwrap(), additions()[0].after);
        assert!(!session.join("rolled-back.json").exists());
    }

    #[test]
    fn process_exit_at_each_install_boundary_recovers_the_same_mixed_plan() {
        const ROOT: &str = "FRANKEN_CREATION_CRASH_ROOT";
        const COUNT: &str = "FRANKEN_CREATION_CRASH_COUNT";
        if let Some(root) = std::env::var_os(ROOT) {
            let writer = RewriteTransaction::open_without_recovery(Path::new(&root)).unwrap();
            let journal = writer.prepare_changes(&edits(), &additions(), JOURNAL_VERSION).unwrap();
            for index in 0..std::env::var(COUNT).unwrap().parse::<usize>().unwrap() {
                writer.install(&journal, index).unwrap();
            }
            std::process::exit(73);
        }
        let module = module_path!().split_once("::").unwrap().1;
        for count in 0..=3 {
            let root = fixture();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &format!("{module}::process_exit_at_each_install_boundary_recovers_the_same_mixed_plan")])
                .env(ROOT, root.path()).env(COUNT, count.to_string()).output().unwrap();
            assert_eq!(output.status.code(), Some(73), "{}", String::from_utf8_lossy(&output.stderr));
            assert!(store(root.path()).join(PENDING).exists());
            let raw = fs::read(store(root.path()).join(PENDING)).unwrap();
            let journal: Journal = serde_json::from_slice(&raw).unwrap();
            drop(RewriteTransaction::open(root.path()).unwrap());
            original(root.path());
            let session = store(root.path()).join(&journal.session);
            assert!(session.join("rolled-back.json").is_file());
            for index in 1..=2 {
                assert_eq!(session.join(format!("{index}.retired")).exists(), index < count);
            }
        }
    }

    #[test]
    fn replacement_of_a_created_file_can_be_rolled_back_before_restoring_its_absence() {
        let root = fixture();
        let first = applied(root.path());
        let second = RewriteTransaction::open_without_recovery(root.path()).unwrap()
            .apply_versioned_with_receipt(&[Edit {
                path: "lib/helper.cjs", before: additions()[0].after, after: b"second generation",
            }]).unwrap().unwrap();
        assert_eq!(restore(root.path(), &first).status, rollback::RollbackStatus::Conflict);
        assert_eq!(restore(root.path(), &second).status, rollback::RollbackStatus::RolledBack);
        assert_eq!(restore(root.path(), &first).status, rollback::RollbackStatus::RolledBack);
        original(root.path());
    }

    #[test]
    fn new_file_bytes_are_durable_before_intent_and_both_rename_parents_before_completion() {
        let root = fixture();
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        DURABILITY_LOG.with(|log| log.borrow_mut().clear());
        writer.apply_with_creations_receipt(&edits(), &additions()).unwrap();
        let log = DURABILITY_LOG.with(|log| std::mem::take(&mut *log.borrow_mut()));
        assert_eq!(log, [
            "file", "file", // replacement before + after
            "file", "file", "file", "file", // creation after + new pairs
            "dir", "dir", // session and store
            "file", "journal", // durable intent
            "file", // replacement (creations rename already durable images)
            "dir", "dir", "dir", // root, lib, session, each once
            "archive", "archive",
        ]);
    }
}
