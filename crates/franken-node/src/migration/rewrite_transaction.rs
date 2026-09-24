//! Recoverable installation of a complete migration rewrite plan (Linux).
//!
//! All sources/backups are checked before the first live replacement. A durable
//! pending journal precedes replacement; an interrupted operation is rolled back
//! before another apply may plan work. Recovery overwrites only a known postimage
//! and never silently clobbers an unrelated edit. Original backups are immutable.
//!
//! Each replacement is atomic, not the entire multi-file operation. The advisory
//! lock coordinates cooperating rewrites, not arbitrary editors. Directory-handle
//! relative NOFOLLOW operations reject symlink redirection, but this is not an OS
//! sandbox against a privileged actor renaming directories or forging journals.
//!
//! Durability protocol (survives power loss / kernel crash, not only process
//! exit, whose page cache survives anyway):
//! 1. Every staged file's data is fsynced before it is renamed into place, so a
//!    persisted rename can never expose an empty or torn file.
//! 2. Renames only mark their parent directory dirty; each distinct dirty
//!    directory is fsynced once per phase (batched, deduplicated by dev/inode).
//! 3. PREPARE: backups, after-images and the session directory are made durable
//!    (phase flush) BEFORE the pending journal is published; the journal's own
//!    rename is then made durable by fsyncing the store. A durable journal thus
//!    never references non-durable recovery material.
//! 4. INSTALL/RECOVER: every replaced source's directory is flushed BEFORE the
//!    journal is archived, so the journal is never retired while a partially
//!    persisted multi-file state could remain.
//! 5. Directories created on demand are made durable in their parent at once.

use anyhow::{Context, Result, bail, ensure};
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock, mkdirat,
    open, openat, renameat_with, unlinkat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "rewrite_rollback.rs"]
pub mod rollback;

pub const MAX_EDITS: usize = 1_000;
pub const MAX_PLAN_BYTES: usize = 256 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 10 * 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 2 * 1024 * 1024;
const JOURNAL_VERSION: &str = "franken-node/rewrite-transaction/v1";
const STORE: &str = ".franken-rewrite";
const PENDING: &str = "pending.json";

pub struct Edit<'a> {
    pub path: &'a str,
    pub before: &'a [u8],
    pub after: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    path: String,
    before_sha256: String,
    after_sha256: String,
    before_bytes: usize,
    after_bytes: usize,
    mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Journal {
    schema_version: String,
    session: String,
    records: Vec<Record>,
}

struct Contents {
    bytes: Vec<u8>,
    metadata: Metadata,
}

/// Owns the lock through recovery, planning and installation. Keep this guard
/// alive while producing the plan, not merely while writing its last file.
pub struct RewriteTransaction {
    root: File,
    backups: File,
    store: File,
    _lock: File,
    /// Directories whose entries changed since the last phase flush.
    dirty: std::cell::RefCell<DirtyDirectories>,
}

impl Drop for RewriteTransaction {
    fn drop(&mut self) {
        // flock belongs to the open file description, not this descriptor.
        // A concurrently spawned child can transiently inherit a duplicate
        // before CLOEXEC closes it. Release when the owner ends, rather than
        // leaving the next operation locked out until that duplicate closes.
        let _ = flock(&self._lock, FlockOperation::Unlock);
    }
}

fn unique_name(prefix: &str) -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let clock = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("{prefix}-{:x}-{clock:x}-{:x}", std::process::id(), SEQUENCE.fetch_add(1, Ordering::Relaxed))
}

fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

#[cfg(test)]
thread_local! {
    /// Ordered record of durability barriers issued on this thread (tests only).
    static DURABILITY_LOG: std::cell::RefCell<Vec<&'static str>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn record_barrier(kind: &'static str) {
    #[cfg(test)]
    DURABILITY_LOG.with(|log| log.borrow_mut().push(kind));
    #[cfg(not(test))]
    let _ = kind;
}

/// fsync `file` (data or directory entries), recording the barrier `kind`.
fn durable_sync(file: &File, kind: &'static str) -> Result<()> {
    file.sync_all().with_context(|| format!("rewrite durability barrier failed ({kind})"))?;
    record_barrier(kind);
    Ok(())
}

/// Directories whose entries changed in the current phase. Each is fsynced
/// once by [`DirtyDirectories::flush`], deduplicated by (device, inode).
#[derive(Default)]
struct DirtyDirectories {
    dirs: BTreeMap<(u64, u64), File>,
}

impl DirtyDirectories {
    fn mark(&mut self, dir: &File) -> Result<()> {
        let metadata = dir.metadata()?;
        if let std::collections::btree_map::Entry::Vacant(slot) = self.dirs.entry((metadata.dev(), metadata.ino())) {
            slot.insert(dir.try_clone()?);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        for dir in std::mem::take(&mut self.dirs).into_values() {
            durable_sync(&dir, "dir")?;
        }
        Ok(())
    }
}

fn validate_path(path: &str) -> Result<()> {
    ensure!(!path.is_empty() && path.len() <= 4096 && !path.contains(['\\', '\0'])
        && !path.chars().any(char::is_control), "invalid rewrite path");
    let parsed = Path::new(path);
    ensure!(parsed.components().all(|part| matches!(part, Component::Normal(_)))
        && parsed.components().map(|part| part.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/") == path,
        "rewrite path must be a canonical relative file path");
    ensure!(!parsed.components().any(|part| part.as_os_str() == ".git")
        && ![".migrate-backup", ".franken-node", STORE].iter()
            .any(|reserved| parsed.components().next().is_some_and(|part| part.as_os_str() == *reserved)),
        "rewrite path targets reserved metadata");
    Ok(())
}

fn same_version(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino() && a.len() == b.len() && a.mode() == b.mode()
        && a.mtime() == b.mtime() && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime() && a.ctime_nsec() == b.ctime_nsec()
}

fn directory(parent: &File, path: &Path, create: bool) -> Result<File> {
    let mut current = parent.try_clone()?;
    for component in path.components() {
        let Component::Normal(name) = component else { bail!("invalid directory component"); };
        if create {
            match mkdirat(&current, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => durable_sync(&current, "mkdir")?,
                Err(Errno::EXIST) => {},
                Err(error) => return Err(error.into()),
            }
        }
        current = File::from(openat(&current, name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())
            .with_context(|| format!("open rewrite directory {} without following links", name.to_string_lossy()))?);
    }
    Ok(current)
}

fn parent_and_name(root: &File, path: &str, create: bool) -> Result<(File, OsString)> {
    validate_path(path)?;
    let path = Path::new(path);
    Ok((directory(root, path.parent().unwrap_or_else(|| Path::new("")), create)?,
        path.file_name().context("rewrite filename missing")?.to_owned()))
}

fn read_optional(parent: &File, name: &OsStr, limit: usize) -> Result<Option<Contents>> {
    let fd = match openat(parent, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut file = File::from(fd);
    let before = file.metadata()?;
    ensure!(before.is_file() && before.nlink() == 1, "rewrite input must be a regular, unaliased file");
    ensure!(before.len() <= limit as u64, "rewrite input exceeds byte limit");
    let mut bytes = Vec::new();
    Read::take(&mut file, limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit && same_version(&before, &file.metadata()?), "rewrite input changed during read");
    Ok(Some(Contents { bytes, metadata: before }))
}

fn read_required(parent: &File, name: &OsStr, limit: usize) -> Result<Contents> {
    read_optional(parent, name, limit)?.context("required rewrite file is missing")
}

/// Private staging file with ownership-bound cleanup. The temporary name is
/// always generated here and opened EXCL, never taken from journal input.
struct StagedFile<'a> {
    parent: &'a File,
    name: String,
    installed: bool,
}

impl Drop for StagedFile<'_> {
    fn drop(&mut self) {
        if !self.installed {
            let _ = unlinkat(self.parent, self.name.as_str(), AtFlags::empty());
        }
    }
}

fn stage<'a>(parent: &'a File, bytes: &[u8], mode: u32) -> Result<StagedFile<'a>> {
    let name = unique_name(".rewrite-stage");
    let mut file = File::from(openat(parent, name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600))?);
    let staged = StagedFile { parent, name, installed: false };
    file.write_all(bytes)?;
    file.set_permissions(Permissions::from_mode(mode))?;
    // Data must be durable before any rename can make it visible (protocol 1).
    durable_sync(&file, "file")?;
    Ok(staged)
}


fn verify_image(contents: &Contents, sha256: &str, length: usize, mode: Option<u32>) -> bool {
    contents.bytes.len() == length && digest(&contents.bytes) == sha256
        && mode.is_none_or(|mode| contents.metadata.mode() & 0o7777 == mode)
}

impl RewriteTransaction {
    pub fn open(project: &Path) -> Result<Self> {
        let project = project.canonicalize().context("resolve rewrite project")?;
        let root = File::from(open(&project,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?);
        let backups = directory(&root, Path::new(".migrate-backup"), true)?;
        let store = directory(&backups, Path::new(STORE), true)?;
        let lock = File::from(openat(&store, "lock", OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600))?);
        let metadata = lock.metadata()?;
        ensure!(metadata.is_file() && metadata.nlink() == 1, "invalid rewrite lock file");
        flock(&lock, FlockOperation::NonBlockingLockExclusive).context("another rewrite transaction holds the project lock")?;
        let transaction = Self { root, backups, store, _lock: lock, dirty: Default::default() };
        transaction.recover_pending().context("pending rewrite recovery failed; refusing a new apply")?;
        Ok(transaction)
    }

    fn validate_journal(journal: &Journal) -> Result<()> {
        ensure!(journal.schema_version == JOURNAL_VERSION, "unsupported rewrite transaction schema");
        ensure!(!journal.session.is_empty() && journal.session.len() <= 96
            && journal.session.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'), "invalid rewrite session");
        ensure!(!journal.records.is_empty() && journal.records.len() <= MAX_EDITS, "invalid rewrite journal count");
        let mut paths = BTreeSet::new();
        let mut total = 0_usize;
        for record in &journal.records {
            validate_path(&record.path)?;
            ensure!(paths.insert(&record.path), "duplicate rewrite target");
            ensure!(record.mode <= 0o777 && record.before_bytes <= MAX_FILE_BYTES && record.after_bytes <= MAX_FILE_BYTES,
                "invalid rewrite journal bounds or mode");
            for hash in [&record.before_sha256, &record.after_sha256] {
                ensure!(hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "invalid rewrite digest");
            }
            total = total.checked_add(record.before_bytes).and_then(|v| v.checked_add(record.after_bytes))
                .context("rewrite journal byte overflow")?;
            ensure!(total <= MAX_PLAN_BYTES, "rewrite journal exceeds total byte budget");
        }
        Ok(())
    }

    fn prepare(&self, edits: &[Edit<'_>]) -> Result<Journal> {
        ensure!(!edits.is_empty() && edits.len() <= MAX_EDITS, "rewrite plan entry limit exceeded");
        let mut journal = Journal { schema_version: JOURNAL_VERSION.into(), session: unique_name("txn"), records: Vec::new() };
        let mut total = 0_usize;
        let mut paths = BTreeSet::new();
        // Complete preflight BEFORE creating backups or replacing source files.
        for edit in edits {
            validate_path(edit.path)?;
            ensure!(paths.insert(edit.path), "duplicate rewrite target");
            total = total.checked_add(edit.before.len()).and_then(|v| v.checked_add(edit.after.len())).context("rewrite plan byte overflow")?;
            ensure!(total <= MAX_PLAN_BYTES && edit.before.len() <= MAX_FILE_BYTES && edit.after.len() <= MAX_FILE_BYTES,
                "rewrite plan byte limit exceeded");
            let (parent, name) = parent_and_name(&self.root, edit.path, false)?;
            let source = read_required(&parent, &name, MAX_FILE_BYTES)?;
            ensure!(source.bytes == edit.before, "source changed since rewrite planning: {}", edit.path);
            let mode = source.metadata.mode() & 0o7777;
            ensure!(mode <= 0o777, "special permission bits require manual migration: {}", edit.path);
            let (parent, name) = parent_and_name(&self.backups, edit.path, true)?;
            if let Some(backup) = read_optional(&parent, &name, MAX_FILE_BYTES)? {
                ensure!(backup.bytes == edit.before, "immutable migration backup conflict: {}", edit.path);
            }
            journal.records.push(Record { path: edit.path.into(), before_sha256: digest(edit.before), after_sha256: digest(edit.after),
                before_bytes: edit.before.len(), after_bytes: edit.after.len(), mode });
        }
        Self::validate_journal(&journal)?;
        mkdirat(&self.store, journal.session.as_str(), Mode::from_raw_mode(0o700))?;
        self.dirty.borrow_mut().mark(&self.store)?;
        let session = directory(&self.store, Path::new(&journal.session), false)?;
        for (index, edit) in edits.iter().enumerate() {
            let (parent, name) = parent_and_name(&self.backups, edit.path, false)?;
            if let Some(backup) = read_optional(&parent, &name, MAX_FILE_BYTES)? {
                ensure!(backup.bytes == edit.before, "immutable migration backup changed: {}", edit.path);
            } else {
                self.publish_staged(&parent, &name, edit.before, 0o600)?;
            }
            self.publish_staged(&session, OsStr::new(&format!("{index}.after")), edit.after, 0o600)?;
        }
        // Recovery material must be durable before the journal references it.
        self.flush_dirty()?;
        let encoded = serde_json::to_vec(&journal)?;
        ensure!(encoded.len() <= MAX_JOURNAL_BYTES, "rewrite journal exceeds metadata budget");
        self.publish_journal(&encoded)?;
        Ok(journal)
    }

    /// Stage `bytes` and create-only rename them to `name`; the directory entry
    /// is made durable by the phase flush (protocol 2).
    fn publish_staged(&self, parent: &File, name: &OsStr, bytes: &[u8], mode: u32) -> Result<()> {
        let mut staged = stage(parent, bytes, mode)?;
        renameat_with(parent, staged.name.as_str(), parent, name, RenameFlags::NOREPLACE)?;
        staged.installed = true;
        self.dirty.borrow_mut().mark(parent)
    }

    /// Publish the pending journal and make its directory entry durable at once:
    /// no source may be replaced until the journal is on stable storage.
    fn publish_journal(&self, encoded: &[u8]) -> Result<()> {
        let mut staged = stage(&self.store, encoded, 0o600)?;
        renameat_with(&self.store, staged.name.as_str(), &self.store, PENDING, RenameFlags::NOREPLACE)?;
        staged.installed = true;
        durable_sync(&self.store, "journal")
    }

    fn flush_dirty(&self) -> Result<()> {
        self.dirty.borrow_mut().flush()
    }

    fn replace_image(
        &self,
        record: &Record,
        expected_hash: &str,
        expected_length: usize,
        bytes: &[u8],
    ) -> Result<()> {
        let (parent, name) = parent_and_name(&self.root, &record.path, false)?;
        let current = read_required(&parent, &name, MAX_FILE_BYTES)?;
        ensure!(
            verify_image(&current, expected_hash, expected_length, Some(record.mode)),
            "rewrite conflict; refusing to overwrite changed source: {}",
            record.path
        );
        let mut staged = stage(&parent, bytes, record.mode)?;
        // Recheck after potentially slow staging, immediately before rename.
        let checked = read_required(&parent, &name, MAX_FILE_BYTES)?;
        ensure!(
            same_version(&current.metadata, &checked.metadata) && checked.bytes == current.bytes,
            "rewrite source changed while staging: {}",
            record.path
        );
        renameat_with(&parent, staged.name.as_str(), &parent, &name, RenameFlags::empty())?;
        staged.installed = true;
        self.dirty.borrow_mut().mark(&parent)
    }

    pub(crate) fn install(&self, journal: &Journal, index: usize) -> Result<()> {
        let record = &journal.records[index];
        let session = directory(&self.store, Path::new(&journal.session), false)?;
        let after = read_required(&session, OsStr::new(&format!("{index}.after")), MAX_FILE_BYTES)?;
        ensure!(verify_image(&after, &record.after_sha256, record.after_bytes, None), "staged rewrite bytes changed");
        self.replace_image(record, &record.before_sha256, record.before_bytes, &after.bytes)
    }

    fn archive(&self, journal: &Journal, name: &str) -> Result<()> {
        let session = directory(&self.store, Path::new(&journal.session), false)?;
        renameat_with(&self.store, PENDING, &session, name, RenameFlags::NOREPLACE)?;
        // Both directory entries changed; persist the retirement itself.
        durable_sync(&session, "archive")?;
        durable_sync(&self.store, "archive")
    }

    fn recover_pending(&self) -> Result<bool> {
        let Some(pending) = read_optional(&self.store, OsStr::new(PENDING), MAX_JOURNAL_BYTES)? else { return Ok(false); };
        let journal: Journal = serde_json::from_slice(&pending.bytes).context("decode bounded pending rewrite journal")?;
        Self::validate_journal(&journal)?;
        // Verify the session exists and is not a symlink before any restoration.
        let _session = directory(&self.store, Path::new(&journal.session), false)?;
        let mut errors = Vec::new();
        for record in journal.records.iter().rev() {
            let restored = (|| -> Result<()> {
                let (parent, name) = parent_and_name(&self.root, &record.path, false)?;
                let current = read_required(&parent, &name, MAX_FILE_BYTES)?;
                if verify_image(&current, &record.before_sha256, record.before_bytes, Some(record.mode)) { return Ok(()); }
                ensure!(
                    verify_image(&current, &record.after_sha256, record.after_bytes, Some(record.mode)),
                    "recovery conflict; preserve unrelated edits to {}",
                    record.path
                );
                let (parent, name) = parent_and_name(&self.backups, &record.path, false)?;
                let before = read_required(&parent, &name, MAX_FILE_BYTES)?;
                ensure!(
                    verify_image(&before, &record.before_sha256, record.before_bytes, None),
                    "recovery backup integrity failure: {}",
                    record.path
                );
                self.replace_image(record, &record.after_sha256, record.after_bytes, &before.bytes)
            })();
            if let Err(error) = restored { errors.push(format!("{error:#}")); }
        }
        ensure!(errors.is_empty(), "rewrite recovery incomplete; pending journal retained: {}", errors.join("; "));
        // Restored sources must be durable before the journal is retired.
        self.flush_dirty()?;
        self.archive(&journal, "rolled-back.json")?;
        Ok(true)
    }

    pub fn apply(&self, edits: &[Edit<'_>]) -> Result<()> {
        if edits.is_empty() { return Ok(()); }
        let journal = self.prepare(edits)?;
        let result = (|| -> Result<()> {
            // A source may have changed while other files/backups were staged.
            // Recheck the entire plan before replacing even the first source.
            for record in &journal.records {
                let (parent, name) = parent_and_name(&self.root, &record.path, false)?;
                let current = read_required(&parent, &name, MAX_FILE_BYTES)?;
                ensure!(verify_image(&current, &record.before_sha256, record.before_bytes, Some(record.mode)),
                    "source changed before rewrite commit: {}", record.path);
            }
            for index in 0..journal.records.len() {
                self.install(&journal, index)?;
            }
            // Every replaced source must be durable before the journal retires.
            self.flush_dirty()?;
            self.archive(&journal, "applied.json")
        })();
        if let Err(error) = result {
            return match self.recover_pending() {
                Ok(true) => Err(error.context("rewrite installation failed; original sources restored")),
                Ok(false) => Err(error.context("rewrite completion durability failed; inspect retained transaction evidence")),
                Err(recovery) => Err(anyhow::anyhow!("rewrite installation failed: {error:#}; recovery also failed: {recovery:#}")),
            };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn owner_drop_releases_lock_even_when_a_duplicate_descriptor_remains() {
        let root = tempfile::tempdir().unwrap();
        let transaction = RewriteTransaction::open(root.path()).unwrap();
        // A real dup shares the same kernel lock description as a forked child.
        let inherited = transaction._lock.try_clone().unwrap();
        assert!(RewriteTransaction::open(root.path()).is_err());
        drop(transaction);
        let next = RewriteTransaction::open(root.path()).unwrap();
        drop(inherited);
        assert!(RewriteTransaction::open(root.path()).is_err());
        drop(next);
        drop(RewriteTransaction::open(root.path()).unwrap());
    }

    fn project() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("a.js"), b"before-a").unwrap();
        fs::write(root.path().join("b.js"), b"before-b").unwrap();
        fs::set_permissions(root.path().join("a.js"), Permissions::from_mode(0o755)).unwrap();
        root
    }
    fn edits() -> [Edit<'static>; 2] {
        [Edit { path: "a.js", before: b"before-a", after: b"after-a" },
         Edit { path: "b.js", before: b"before-b", after: b"after-b" }]
    }
    fn pending(root: &Path) -> std::path::PathBuf { root.join(".migrate-backup/.franken-rewrite/pending.json") }
    fn assert_original(root: &Path) {
        assert_eq!(fs::read(root.join("a.js")).unwrap(), b"before-a");
        assert_eq!(fs::read(root.join("b.js")).unwrap(), b"before-b");
        assert_eq!(fs::metadata(root.join("a.js")).unwrap().mode() & 0o777, 0o755);
    }

    #[test]
    fn commits_all_sources_preserves_modes_and_keeps_private_original_backups() {
        let root = project();
        RewriteTransaction::open(root.path()).unwrap().apply(&edits()).unwrap();
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a");
        assert_eq!(fs::read(root.path().join("b.js")).unwrap(), b"after-b");
        assert_eq!(fs::metadata(root.path().join("a.js")).unwrap().mode() & 0o777, 0o755);
        assert_eq!(fs::read(root.path().join(".migrate-backup/a.js")).unwrap(), b"before-a");
        assert_eq!(fs::metadata(root.path().join(".migrate-backup/a.js")).unwrap().mode() & 0o777, 0o600);
        assert!(!pending(root.path()).exists());
        drop(RewriteTransaction::open(root.path()).unwrap());
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a");
    }

    #[test]
    fn later_backup_conflict_cannot_leave_an_earlier_source_rewritten() {
        let root = project();
        fs::create_dir(root.path().join(".migrate-backup")).unwrap();
        fs::write(root.path().join(".migrate-backup/b.js"), b"older-original").unwrap();
        let error = RewriteTransaction::open(root.path()).unwrap().apply(&edits()).unwrap_err();
        assert!(error.to_string().contains("backup conflict"));
        assert_original(root.path());
        assert!(!root.path().join(".migrate-backup/a.js").exists());
        assert_eq!(fs::read(root.path().join(".migrate-backup/b.js")).unwrap(), b"older-original");
    }

    #[test]
    fn stale_source_preimage_rejects_the_entire_plan() {
        let root = project();
        let mut plan = edits();
        plan[1].before = b"stale";
        assert!(RewriteTransaction::open(root.path()).unwrap().apply(&plan).is_err());
        assert_original(root.path());
        assert!(!pending(root.path()).exists());
    }

    fn take_durability_log() -> Vec<&'static str> {
        DURABILITY_LOG.with(|log| std::mem::take(&mut *log.borrow_mut()))
    }

    #[test]
    fn apply_issues_durability_barriers_in_journal_protocol_order() {
        let root = project();
        let transaction = RewriteTransaction::open(root.path()).unwrap();
        // open() created .migrate-backup and the store: each made durable in its parent.
        assert_eq!(take_durability_log(), ["mkdir", "mkdir"]);
        transaction.apply(&edits()).unwrap();
        assert_eq!(
            take_durability_log(),
            [
                // PREPARE: 2 backups + 2 after-images, data synced before rename.
                "file", "file", "file", "file",
                // One flush per distinct dirty directory: store (session mkdir),
                // backups, session. Recovery material durable BEFORE the journal.
                "dir", "dir", "dir",
                // Journal data, then its directory entry.
                "file", "journal",
                // INSTALL: two replaced sources, data synced before each rename.
                "file", "file",
                // Source directory flushed once, BEFORE the journal is retired.
                "dir",
                // Retirement persisted in both directories.
                "archive", "archive",
            ]
        );
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a");
        assert_eq!(fs::read(root.path().join("b.js")).unwrap(), b"after-b");
    }

    #[test]
    fn recovery_flushes_restored_sources_before_retiring_the_journal() {
        let root = project();
        {
            let transaction = RewriteTransaction::open(root.path()).unwrap();
            let journal = transaction.prepare(&edits()).unwrap();
            transaction.install(&journal, 0).unwrap();
        }
        let _ = take_durability_log();
        let _transaction = RewriteTransaction::open(root.path()).unwrap();
        // One restored source (b.js was never replaced), its directory flushed,
        // then the journal archived durably.
        assert_eq!(take_durability_log(), ["file", "dir", "archive", "archive"]);
        assert_original(root.path());
    }

    #[test]
    fn interrupted_partial_install_is_recovered_before_new_planning() {
        let root = project();
        {
            let transaction = RewriteTransaction::open(root.path()).unwrap();
            let journal = transaction.prepare(&edits()).unwrap();
            transaction.install(&journal, 0).unwrap();
            // Dropping simulates losing the owner without committing a final
            // journal. Recovery reads only persisted files, not this handle.
        }
        assert!(pending(root.path()).exists());
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a");
        let transaction = RewriteTransaction::open(root.path()).unwrap();
        assert_original(root.path());
        assert!(!pending(root.path()).exists());
        transaction.apply(&edits()).unwrap();
        assert_eq!(fs::read(root.path().join("b.js")).unwrap(), b"after-b");
    }

    #[test]
    fn interrupted_after_last_replace_without_commit_marker_is_recovered() {
        let root = project();
        {
            let transaction = RewriteTransaction::open(root.path()).unwrap();
            let journal = transaction.prepare(&edits()).unwrap();
            for index in 0..2 { transaction.install(&journal, index).unwrap(); }
        }
        drop(RewriteTransaction::open(root.path()).unwrap());
        assert_original(root.path());
    }

    #[test]
    fn abruptly_exiting_writer_leaves_a_recoverable_journal() {
        const CHILD_ROOT: &str = "FRANKEN_REWRITE_TEST_CRASH_ROOT";
        if let Some(path) = std::env::var_os(CHILD_ROOT) {
            let transaction = RewriteTransaction::open(Path::new(&path)).unwrap();
            let journal = transaction.prepare(&edits()).unwrap();
            transaction.install(&journal, 0).unwrap();
            std::process::exit(73); // no destructors, no successful-commit marker
        }
        let root = project();
        // The same production tests run both as a standalone library and as
        // migration::rewrite_transaction inside the product. Strip only the
        // crate name so the child selects this exact test in either layout.
        let module = module_path!().split_once("::").map_or(module_path!(), |(_, path)| path);
        let test_name = format!("{module}::abruptly_exiting_writer_leaves_a_recoverable_journal");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name.as_str(), "--nocapture"])
            .env(CHILD_ROOT, root.path()).output().unwrap();
        assert_eq!(output.status.code(), Some(73), "{}", String::from_utf8_lossy(&output.stdout));
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a");
        assert!(pending(root.path()).exists());
        drop(RewriteTransaction::open(root.path()).unwrap());
        assert_original(root.path());
        assert!(!pending(root.path()).exists());
    }

    #[test]
    fn recovery_preserves_unrelated_edits_and_restores_other_safe_sources() {
        let root = project();
        {
            let transaction = RewriteTransaction::open(root.path()).unwrap();
            let journal = transaction.prepare(&edits()).unwrap();
            transaction.install(&journal, 0).unwrap();
            fs::write(root.path().join("b.js"), b"user-edit").unwrap();
        }
        assert!(RewriteTransaction::open(root.path()).is_err());
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"before-a");
        assert_eq!(fs::read(root.path().join("b.js")).unwrap(), b"user-edit");
        assert!(pending(root.path()).exists());
        fs::write(root.path().join("b.js"), b"before-b").unwrap();
        drop(RewriteTransaction::open(root.path()).unwrap());
        assert!(!pending(root.path()).exists());
    }

    #[test]
    fn corrupted_backup_blocks_recovery_without_overwriting_the_source() {
        let root = project();
        {
            let transaction = RewriteTransaction::open(root.path()).unwrap();
            let journal = transaction.prepare(&edits()).unwrap();
            transaction.install(&journal, 0).unwrap();
        }
        fs::write(root.path().join(".migrate-backup/a.js"), b"tampered").unwrap();
        assert!(RewriteTransaction::open(root.path()).is_err());
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a");
        assert!(pending(root.path()).exists());
    }

    #[test]
    fn lock_is_held_through_planning_and_released_on_owner_drop() {
        let root = project();
        let first = RewriteTransaction::open(root.path()).unwrap();
        assert!(RewriteTransaction::open(root.path()).is_err());
        drop(first);
        assert!(RewriteTransaction::open(root.path()).is_ok());
    }

    #[test]
    fn source_and_backup_symlinks_never_redirect_writes() {
        for backup in [false, true] {
            let root = project();
            let outside = tempfile::NamedTempFile::new().unwrap();
            fs::write(outside.path(), b"before-b").unwrap();
            let path = if backup {
                fs::create_dir(root.path().join(".migrate-backup")).unwrap();
                root.path().join(".migrate-backup/b.js")
            } else {
                fs::rename(root.path().join("b.js"), root.path().join("saved-b.js")).unwrap();
                root.path().join("b.js")
            };
            symlink(outside.path(), path).unwrap();
            assert!(RewriteTransaction::open(root.path()).unwrap().apply(&edits()).is_err());
            assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"before-a");
            assert_eq!(fs::read(outside.path()).unwrap(), b"before-b");
        }
    }

    #[test]
    fn symlinked_parent_directory_is_not_traversed() {
        let root = project();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("file.js"), b"before").unwrap();
        symlink(outside.path(), root.path().join("alias")).unwrap();
        let edits = [Edit { path: "alias/file.js", before: b"before", after: b"after" }];
        assert!(RewriteTransaction::open(root.path()).unwrap().apply(&edits).is_err());
        assert_eq!(fs::read(outside.path().join("file.js")).unwrap(), b"before");
    }

    #[test]
    fn hardlinked_sources_fail_closed() {
        let root = project();
        fs::hard_link(root.path().join("b.js"), root.path().join("alias.js")).unwrap();
        assert!(RewriteTransaction::open(root.path()).unwrap().apply(&edits()).is_err());
        assert_original(root.path());
    }

    #[test]
    fn duplicate_and_noncanonical_paths_are_rejected_before_edits() {
        let root = project();
        let transaction = RewriteTransaction::open(root.path()).unwrap();
        let duplicate = [Edit { path: "a.js", before: b"before-a", after: b"after" },
            Edit { path: "a.js", before: b"before-a", after: b"other" }];
        assert!(transaction.apply(&duplicate).is_err());
        for path in ["../a.js", "/a.js", "a/../a.js", "./a.js", "a//b.js", "a\\b.js", ".git/config", ".migrate-backup/a.js", ".franken-node/package.json"] {
            assert!(transaction.apply(&[Edit { path, before: b"", after: b"" }]).is_err(), "{path}");
        }
        assert_original(root.path());
    }

    #[test]
    fn oversized_replacement_is_rejected_before_backup_or_source_mutation() {
        let root = project();
        let bytes = vec![b'x'; MAX_FILE_BYTES + 1];
        let edits = [Edit { path: "a.js", before: b"before-a", after: &bytes }];
        assert!(RewriteTransaction::open(root.path()).unwrap().apply(&edits).is_err());
        assert_original(root.path());
        assert!(!root.path().join(".migrate-backup/a.js").exists());
    }

    #[test]
    fn forged_journal_paths_are_rejected_before_recovery_writes() {
        let root = project();
        {
            let transaction = RewriteTransaction::open(root.path()).unwrap();
            let journal = transaction.prepare(&edits()).unwrap();
            transaction.install(&journal, 0).unwrap();
        }
        let mut journal: serde_json::Value = serde_json::from_slice(&fs::read(pending(root.path())).unwrap()).unwrap();
        journal["records"][0]["path"] = "../outside.js".into();
        fs::write(pending(root.path()), serde_json::to_vec(&journal).unwrap()).unwrap();
        assert!(RewriteTransaction::open(root.path()).is_err());
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a");
    }

    #[test]
    fn staged_after_image_corruption_cannot_be_installed() {
        let root = project();
        let transaction = RewriteTransaction::open(root.path()).unwrap();
        let journal = transaction.prepare(&edits()).unwrap();
        fs::write(root.path().join(".migrate-backup").join(STORE).join(&journal.session).join("0.after"), b"tampered").unwrap();
        assert!(transaction.install(&journal, 0).is_err());
        transaction.recover_pending().unwrap();
        assert_original(root.path());
    }

    #[test]
    fn successful_empty_plan_does_not_create_pending_work() {
        let root = project();
        RewriteTransaction::open(root.path()).unwrap().apply(&[]).unwrap();
        assert!(!pending(root.path()).exists());
        assert_original(root.path());
    }
}
