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
use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock, mkdirat, open, openat,
    renameat_with, unlinkat,
};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata, Permissions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "rewrite_rollback.rs"]
pub mod rollback;

#[path = "rewrite_creations.rs"]
mod creations;
pub use creations::CreateFile;

pub const MAX_EDITS: usize = 1_000;
pub const MAX_PLAN_BYTES: usize = 256 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 10 * 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = 2 * 1024 * 1024;
const JOURNAL_VERSION: &str = "franken-node/rewrite-transaction/v1";
const VERSIONED_JOURNAL_VERSION: &str = "franken-node/rewrite-transaction/v2";
const REQUEST_JOURNAL_VERSION: &str = "franken-node/rewrite-transaction/v4";
const STORE: &str = ".franken-rewrite";
const PENDING: &str = "pending.json";

pub struct Edit<'a> {
    pub path: &'a str,
    pub before: &'a [u8],
    pub after: &'a [u8],
}

/// Identity of the journal that this exact writer durably applied. This is a
/// local recovery receipt, not an authenticated validation or fleet decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedRewrite {
    pub transaction_id: String,
    pub journal_sha256: String,
    pub files: usize,
}

/// Caller-owned retry identity bound to one project and two reviewed captures.
/// This is local recovery metadata, not a signature or reusable PASS report.
/// The native journal retains it BEFORE installation, so losing stdout cannot
/// turn a completed request into another installation. Fields are immutable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    request_id: String,
    project_sha256: String,
    input_sha256: String,
    candidate_input_sha256: String,
}

impl InstallRequest {
    pub fn new(project: &Path, request_id: &str, input: &str, candidate: &str) -> Result<Self> {
        let request = Self {
            request_id: request_id.into(),
            project_sha256: Self::project_digest(project)?,
            input_sha256: input.into(),
            candidate_input_sha256: candidate.into(),
        };
        request.validate()?;
        Ok(request)
    }

    fn project_digest(project: &Path) -> Result<String> {
        let project = project.canonicalize().context("resolve installation request project")?;
        let mut hash = Sha256::new();
        hash.update(b"franken-node/install-request-project/v1\0");
        hash.update(project.as_os_str().as_bytes());
        Ok(hex::encode(hash.finalize()))
    }

    pub fn check_project(&self, project: &Path) -> Result<()> {
        self.validate()?;
        ensure!(Self::project_digest(project)? == self.project_sha256,
            "installation request belongs to a different project");
        Ok(())
    }

    pub fn id(&self) -> &str { &self.request_id }
    pub fn input_sha256(&self) -> &str { &self.input_sha256 }
    pub fn candidate_input_sha256(&self) -> &str { &self.candidate_input_sha256 }

    /// Only the opaque ID chooses this slot. Reusing the ID with different
    /// reviewed hashes must conflict, not silently select a second slot.
    pub fn transaction_id(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"franken-node/install-request-slot/v1\0");
        hash.update(self.request_id.as_bytes());
        format!("txn-request-{}", hex::encode(hash.finalize()))
    }

    fn validate(&self) -> Result<()> {
        ensure!(!self.request_id.is_empty() && self.request_id.len() <= 64
            && self.request_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "request ID must be 1..=64 ASCII letters, digits, hyphens or underscores");
        for pin in [&self.project_sha256, &self.input_sha256, &self.candidate_input_sha256] {
            ensure!(pin.len() == 64
                && pin.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "installation request hashes must be lowercase SHA-256 digests");
        }
        Ok(())
    }
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
    /// Version three distinguishes a missing preimage from an empty file.
    #[serde(default, skip_serializing_if = "is_false")]
    created: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Journal {
    schema_version: String,
    session: String,
    records: Vec<Record>,
    // Omission preserves every historical v1/v2/v3 journal digest. Old readers
    // reject v4 rather than recovering without understanding request identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request: Option<InstallRequest>,
}

struct Contents {
    bytes: Vec<u8>,
    metadata: Metadata,
}

/// Owns the lock through recovery, planning and installation. Keep this guard
/// alive while producing the plan, not merely while writing its last file.
pub struct RewriteTransaction {
    project: PathBuf,
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
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{prefix}-{:x}-{clock:x}-{:x}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

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
    file.sync_all()
        .with_context(|| format!("rewrite durability barrier failed ({kind})"))?;
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
        if let std::collections::btree_map::Entry::Vacant(slot) =
            self.dirs.entry((metadata.dev(), metadata.ino()))
        {
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
    ensure!(
        !path.is_empty()
            && path.len() <= 4096
            && !path.contains(['\\', '\0'])
            && !path.chars().any(char::is_control),
        "invalid rewrite path"
    );
    let parsed = Path::new(path);
    ensure!(
        parsed
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
            && parsed
                .components()
                .map(|part| part.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/")
                == path,
        "rewrite path must be a canonical relative file path"
    );
    ensure!(
        !parsed.components().any(|part| part.as_os_str() == ".git")
            && ![".migrate-backup", ".franken-node", STORE]
                .iter()
                .any(|reserved| parsed
                    .components()
                    .next()
                    .is_some_and(|part| part.as_os_str() == *reserved)),
        "rewrite path targets reserved metadata"
    );
    Ok(())
}

fn same_version(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn directory(parent: &File, path: &Path, create: bool) -> Result<File> {
    let mut current = parent.try_clone()?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            bail!("invalid directory component");
        };
        if create {
            match mkdirat(&current, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => durable_sync(&current, "mkdir")?,
                Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        current = File::from(
            openat(
                &current,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .with_context(|| {
                format!(
                    "open rewrite directory {} without following links",
                    name.to_string_lossy()
                )
            })?,
        );
    }
    Ok(current)
}

fn parent_and_name(root: &File, path: &str, create: bool) -> Result<(File, OsString)> {
    validate_path(path)?;
    let path = Path::new(path);
    Ok((
        directory(root, path.parent().unwrap_or_else(|| Path::new("")), create)?,
        path.file_name()
            .context("rewrite filename missing")?
            .to_owned(),
    ))
}

fn read_optional(parent: &File, name: &OsStr, limit: usize) -> Result<Option<Contents>> {
    let fd = match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut file = File::from(fd);
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.nlink() == 1,
        "rewrite input must be a regular, unaliased file"
    );
    ensure!(
        before.len() <= limit as u64,
        "rewrite input exceeds byte limit"
    );
    let mut bytes = Vec::new();
    Read::take(&mut file, limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit && same_version(&before, &file.metadata()?),
        "rewrite input changed during read"
    );
    Ok(Some(Contents {
        bytes,
        metadata: before,
    }))
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
    let mut file = File::from(openat(
        parent,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    let staged = StagedFile {
        parent,
        name,
        installed: false,
    };
    file.write_all(bytes)?;
    file.set_permissions(Permissions::from_mode(mode))?;
    // Data must be durable before any rename can make it visible (protocol 1).
    durable_sync(&file, "file")?;
    Ok(staged)
}

fn verify_image(contents: &Contents, sha256: &str, length: usize, mode: Option<u32>) -> bool {
    contents.bytes.len() == length
        && digest(&contents.bytes) == sha256
        && mode.is_none_or(|mode| contents.metadata.mode() & 0o7777 == mode)
}

impl RewriteTransaction {
    pub fn open(project: &Path) -> Result<Self> {
        Self::open_selected(project, true)
    }

    /// Acquire the existing writer lock without implicitly restoring sources.
    /// Reviewed-candidate installation must not recover another operation before
    /// its own validation. An unfinished journal requires explicit recovery.
    pub fn open_without_recovery(project: &Path) -> Result<Self> {
        Self::open_selected(project, false)
    }

    fn open_selected(project: &Path, recover: bool) -> Result<Self> {
        let project = project.canonicalize().context("resolve rewrite project")?;
        let root = File::from(open(
            &project,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let backups = directory(&root, Path::new(".migrate-backup"), true)?;
        let store = directory(&backups, Path::new(STORE), true)?;
        let lock = File::from(openat(
            &store,
            "lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        let metadata = lock.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "invalid rewrite lock file"
        );
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .context("another rewrite transaction holds the project lock")?;
        let transaction = Self {
            project,
            root,
            backups,
            store,
            _lock: lock,
            dirty: Default::default(),
        };
        if recover {
            transaction
                .recover_pending()
                .context("pending rewrite recovery failed; refusing a new apply")?;
        } else {
            ensure!(
                read_optional(&transaction.store, OsStr::new(PENDING), MAX_JOURNAL_BYTES)?.is_none(),
                "unfinished rewrite requires explicit recovery before reviewed migration installation"
            );
        }
        Ok(transaction)
    }

    fn validate_journal(journal: &Journal) -> Result<()> {
        ensure!(
            journal.schema_version == JOURNAL_VERSION
                || journal.schema_version == VERSIONED_JOURNAL_VERSION
                || journal.schema_version == creations::JOURNAL_VERSION
                || journal.schema_version == REQUEST_JOURNAL_VERSION,
            "unsupported rewrite transaction schema"
        );
        ensure!(
            !journal.session.is_empty()
                && journal.session.len() <= 96
                && journal
                    .session
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid rewrite session"
        );
        if journal.schema_version == REQUEST_JOURNAL_VERSION {
            let request = journal.request.as_ref().context("request journal is missing its binding")?;
            request.validate()?;
            ensure!(journal.session == request.transaction_id(), "request journal slot differs from its binding");
            ensure!(!journal.records.is_empty() || request.input_sha256 == request.candidate_input_sha256,
                "an unchanged request must bind identical captures");
        } else {
            ensure!(journal.request.is_none(), "request bindings require the request journal schema");
        }
        ensure!(
            (!journal.records.is_empty() || journal.schema_version == REQUEST_JOURNAL_VERSION)
                && journal.records.len() <= MAX_EDITS,
            "invalid rewrite journal count"
        );
        let mut paths = BTreeSet::new();
        let mut total = 0_usize;
        for record in &journal.records {
            validate_path(&record.path)?;
            ensure!(paths.insert(&record.path), "duplicate rewrite target");
            if record.created {
                ensure!(
                    (journal.schema_version == creations::JOURNAL_VERSION
                        || journal.schema_version == REQUEST_JOURNAL_VERSION)
                        && record.before_bytes == 0
                        && record.before_sha256 == digest(b"")
                        && record.mode & 0o400 != 0,
                    "invalid absent-preimage creation record"
                );
            }
            ensure!(
                record.mode <= 0o777
                    && record.before_bytes <= MAX_FILE_BYTES
                    && record.after_bytes <= MAX_FILE_BYTES,
                "invalid rewrite journal bounds or mode"
            );
            for hash in [&record.before_sha256, &record.after_sha256] {
                ensure!(
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "invalid rewrite digest"
                );
            }
            total = total
                .checked_add(record.before_bytes)
                .and_then(|v| v.checked_add(record.after_bytes))
                .context("rewrite journal byte overflow")?;
            ensure!(
                total <= MAX_PLAN_BYTES,
                "rewrite journal exceeds total byte budget"
            );
        }
        Ok(())
    }

    fn prepare(&self, edits: &[Edit<'_>]) -> Result<Journal> {
        self.prepare_with_preimages(edits, false)
    }

    fn prepare_with_preimages(&self, edits: &[Edit<'_>], versioned: bool) -> Result<Journal> {
        self.prepare_changes(
            edits,
            &[],
            if versioned { VERSIONED_JOURNAL_VERSION } else { JOURNAL_VERSION },
        )
    }

    fn prepare_changes(
        &self,
        edits: &[Edit<'_>],
        creations: &[CreateFile<'_>],
        schema: &str,
    ) -> Result<Journal> {
        self.prepare_bound_changes(edits, creations, schema, None)
    }

    fn prepare_bound_changes(
        &self,
        edits: &[Edit<'_>],
        creations: &[CreateFile<'_>],
        schema: &str,
        request: Option<&InstallRequest>,
    ) -> Result<Journal> {
        let count = edits.len().checked_add(creations.len()).context("rewrite count overflow")?;
        ensure!(
            (count > 0 || request.is_some()) && count <= MAX_EDITS,
            "rewrite plan entry limit exceeded"
        );
        ensure!(creations.is_empty() || schema == creations::JOURNAL_VERSION || schema == REQUEST_JOURNAL_VERSION,
            "new files require the creation journal schema");
        let versioned = schema != JOURNAL_VERSION;
        let mut journal = Journal {
            schema_version: schema.into(),
            session: request.map_or_else(|| unique_name("txn"), InstallRequest::transaction_id),
            records: Vec::new(),
            request: request.cloned(),
        };
        let mut total = 0_usize;
        let mut paths = BTreeSet::new();
        // Complete preflight BEFORE creating backups or replacing source files.
        for edit in edits {
            validate_path(edit.path)?;
            ensure!(paths.insert(edit.path), "duplicate rewrite target");
            total = total
                .checked_add(edit.before.len())
                .and_then(|v| v.checked_add(edit.after.len()))
                .context("rewrite plan byte overflow")?;
            ensure!(
                total <= MAX_PLAN_BYTES
                    && edit.before.len() <= MAX_FILE_BYTES
                    && edit.after.len() <= MAX_FILE_BYTES,
                "rewrite plan byte limit exceeded"
            );
            let (parent, name) = parent_and_name(&self.root, edit.path, false)?;
            let source = read_required(&parent, &name, MAX_FILE_BYTES)?;
            ensure!(
                source.bytes == edit.before,
                "source changed since rewrite planning: {}",
                edit.path
            );
            let mode = source.metadata.mode() & 0o7777;
            ensure!(
                mode <= 0o777,
                "special permission bits require manual migration: {}",
                edit.path
            );
            if !versioned {
                let (parent, name) = parent_and_name(&self.backups, edit.path, true)?;
                if let Some(backup) = read_optional(&parent, &name, MAX_FILE_BYTES)? {
                    ensure!(
                        backup.bytes == edit.before,
                        "immutable migration backup conflict: {}",
                        edit.path
                    );
                }
            }
            journal.records.push(Record {
                path: edit.path.into(),
                before_sha256: digest(edit.before),
                after_sha256: digest(edit.after),
                before_bytes: edit.before.len(),
                after_bytes: edit.after.len(),
                mode,
                created: false,
            });
        }
        for creation in creations {
            validate_path(creation.path)?;
            ensure!(paths.insert(creation.path), "duplicate rewrite target");
            total = total.checked_add(creation.after.len()).context("rewrite plan byte overflow")?;
            ensure!(total <= MAX_PLAN_BYTES && creation.after.len() <= MAX_FILE_BYTES,
                "rewrite plan byte limit exceeded");
            ensure!(creation.mode <= 0o777 && creation.mode & 0o400 != 0,
                "created files require ordinary owner-readable permissions");
            // Parents must already exist. No directory creation or structural
            // replacement is smuggled into an absent-file approval.
            let (parent, name) = parent_and_name(&self.root, creation.path, false)?;
            ensure!(read_optional(&parent, &name, MAX_FILE_BYTES)?.is_none(),
                "creation target already exists: {}", creation.path);
            ensure!(parent.metadata()?.dev() == self.store.metadata()?.dev(),
                "creation target must share the transaction filesystem: {}", creation.path);
            journal.records.push(Record {
                path: creation.path.into(),
                before_sha256: digest(b""),
                after_sha256: digest(creation.after),
                before_bytes: 0,
                after_bytes: creation.after.len(),
                mode: creation.mode,
                created: true,
            });
        }
        Self::validate_journal(&journal)?;
        mkdirat(
            &self.store,
            journal.session.as_str(),
            Mode::from_raw_mode(0o700),
        )?;
        self.dirty.borrow_mut().mark(&self.store)?;
        let session = directory(&self.store, Path::new(&journal.session), false)?;
        for (index, edit) in edits.iter().enumerate() {
            if versioned {
                // The preimage belongs to this journal, not to the first edit
                // ever made to this pathname. An earlier generation's backups
                // are never overwritten, adopted or used as a fallback.
                self.publish_staged(
                    &session,
                    OsStr::new(&format!("{index}.before")),
                    edit.before,
                    0o600,
                )?;
            } else {
                let (parent, name) = parent_and_name(&self.backups, edit.path, false)?;
                if let Some(backup) = read_optional(&parent, &name, MAX_FILE_BYTES)? {
                    ensure!(
                        backup.bytes == edit.before,
                        "immutable migration backup changed: {}",
                        edit.path
                    );
                } else {
                    self.publish_staged(&parent, &name, edit.before, 0o600)?;
                }
            }
            self.publish_staged(
                &session,
                OsStr::new(&format!("{index}.after")),
                edit.after,
                0o600,
            )?;
        }
        for (offset, creation) in creations.iter().enumerate() {
            let index = edits.len() + offset;
            self.publish_staged(
                &session,
                OsStr::new(&format!("{index}.after")),
                creation.after,
                0o600,
            )?;
            // This durable image is consumed by the no-replace installation
            // rename. Its continued presence proves we did not create a
            // colliding pathname, even if that other file has identical bytes.
            self.publish_staged(
                &session,
                OsStr::new(&format!("{index}.new")),
                creation.after,
                creation.mode,
            )?;
        }
        // Recovery material must be durable before the journal references it.
        self.flush_dirty()?;
        let encoded = serde_json::to_vec(&journal)?;
        ensure!(
            encoded.len() <= MAX_JOURNAL_BYTES,
            "rewrite journal exceeds metadata budget"
        );
        self.publish_journal(&encoded)?;
        Ok(journal)
    }

    /// Select recovery material only from the validated journal's schema and
    /// record ordinal. Never try a legacy or another session's backup when a
    /// versioned preimage is missing or damaged. Callers verify its content hash.
    fn read_preimage(&self, journal: &Journal, index: usize) -> Result<Contents> {
        let record = journal.records.get(index).context("invalid preimage record index")?;
        ensure!(!record.created, "a created file has no original image");
        match journal.schema_version.as_str() {
            JOURNAL_VERSION => {
                let (parent, name) = parent_and_name(&self.backups, &record.path, false)?;
                read_required(&parent, &name, MAX_FILE_BYTES)
            }
            VERSIONED_JOURNAL_VERSION | creations::JOURNAL_VERSION | REQUEST_JOURNAL_VERSION => {
                let session = directory(&self.store, Path::new(&journal.session), false)?;
                let image = read_required(&session, OsStr::new(&format!("{index}.before")), MAX_FILE_BYTES)?;
                ensure!(image.metadata.mode() & 0o7777 == 0o600,
                    "transaction preimage must retain private permissions");
                Ok(image)
            }
            _ => bail!("unsupported rewrite preimage schema"),
        }
    }

    /// Stage `bytes` and create-only rename them to `name`; the directory entry
    /// is made durable by the phase flush (protocol 2).
    fn publish_staged(&self, parent: &File, name: &OsStr, bytes: &[u8], mode: u32) -> Result<()> {
        let mut staged = stage(parent, bytes, mode)?;
        renameat_with(
            parent,
            staged.name.as_str(),
            parent,
            name,
            RenameFlags::NOREPLACE,
        )?;
        staged.installed = true;
        self.dirty.borrow_mut().mark(parent)
    }

    /// Publish the pending journal and make its directory entry durable at once:
    /// no source may be replaced until the journal is on stable storage.
    fn publish_journal(&self, encoded: &[u8]) -> Result<()> {
        let mut staged = stage(&self.store, encoded, 0o600)?;
        renameat_with(
            &self.store,
            staged.name.as_str(),
            &self.store,
            PENDING,
            RenameFlags::NOREPLACE,
        )?;
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
        renameat_with(
            &parent,
            staged.name.as_str(),
            &parent,
            &name,
            RenameFlags::empty(),
        )?;
        staged.installed = true;
        self.dirty.borrow_mut().mark(&parent)
    }

    pub(crate) fn install(&self, journal: &Journal, index: usize) -> Result<()> {
        let record = &journal.records[index];
        let session = directory(&self.store, Path::new(&journal.session), false)?;
        let after = read_required(
            &session,
            OsStr::new(&format!("{index}.after")),
            MAX_FILE_BYTES,
        )?;
        ensure!(
            verify_image(&after, &record.after_sha256, record.after_bytes, None),
            "staged rewrite bytes changed"
        );
        if record.created {
            return self.install_created(journal, index);
        }
        self.replace_image(
            record,
            &record.before_sha256,
            record.before_bytes,
            &after.bytes,
        )
    }

    fn archive(&self, journal: &Journal, name: &str) -> Result<()> {
        let session = directory(&self.store, Path::new(&journal.session), false)?;
        renameat_with(&self.store, PENDING, &session, name, RenameFlags::NOREPLACE)?;
        // Both directory entries changed; persist the retirement itself.
        durable_sync(&session, "archive")?;
        durable_sync(&self.store, "archive")
    }

    fn recover_pending(&self) -> Result<bool> {
        let Some(pending) = read_optional(&self.store, OsStr::new(PENDING), MAX_JOURNAL_BYTES)?
        else {
            return Ok(false);
        };
        let journal: Journal = serde_json::from_slice(&pending.bytes)
            .context("decode bounded pending rewrite journal")?;
        Self::validate_journal(&journal)?;
        // Verify the session exists and is not a symlink before any restoration.
        let _session = directory(&self.store, Path::new(&journal.session), false)?;
        let mut errors = Vec::new();
        for (index, record) in journal.records.iter().enumerate().rev() {
            let restored = (|| -> Result<()> {
                if record.created {
                    return self.restore_created(&journal, index);
                }
                let (parent, name) = parent_and_name(&self.root, &record.path, false)?;
                let current = read_required(&parent, &name, MAX_FILE_BYTES)?;
                if verify_image(
                    &current,
                    &record.before_sha256,
                    record.before_bytes,
                    Some(record.mode),
                ) {
                    return Ok(());
                }
                ensure!(
                    verify_image(
                        &current,
                        &record.after_sha256,
                        record.after_bytes,
                        Some(record.mode)
                    ),
                    "recovery conflict; preserve unrelated edits to {}",
                    record.path
                );
                let before = self.read_preimage(&journal, index)?;
                ensure!(
                    verify_image(&before, &record.before_sha256, record.before_bytes, None),
                    "recovery backup integrity failure: {}",
                    record.path
                );
                self.replace_image(
                    record,
                    &record.after_sha256,
                    record.after_bytes,
                    &before.bytes,
                )
            })();
            if let Err(error) = restored {
                errors.push(format!("{error:#}"));
            }
        }
        ensure!(
            errors.is_empty(),
            "rewrite recovery incomplete; pending journal retained: {}",
            errors.join("; ")
        );
        // Restored sources must be durable before the journal is retired.
        self.flush_dirty()?;
        self.archive(&journal, "rolled-back.json")?;
        Ok(true)
    }

    pub fn apply(&self, edits: &[Edit<'_>]) -> Result<()> {
        self.apply_with_receipt(edits).map(|_| ())
    }

    /// Return this operation's identity, never infer the newest history entry
    /// after dropping the lock. Empty plans return None and create no journal.
    pub fn apply_with_receipt(&self, edits: &[Edit<'_>]) -> Result<Option<AppliedRewrite>> {
        if edits.is_empty() {
            return Ok(None);
        }
        let journal = self.prepare(edits)?;
        self.apply_prepared(journal)
    }

    /// Install a new generation using private, journal-scoped original images.
    /// This supports repeated reviewed migrations of the same files. Recovery
    /// remains the shared pinned protocol, including for historical v1 journals.
    /// The path-global first-original API above retains its existing contract.
    pub fn apply_versioned_with_receipt(&self, edits: &[Edit<'_>]) -> Result<Option<AppliedRewrite>> {
        if edits.is_empty() {
            return Ok(None);
        }
        let journal = self.prepare_with_preimages(edits, true)?;
        self.apply_prepared(journal)
    }

    /// Record and install one previously unseen reviewed request. Callers own
    /// live validation and hold this lock through it. Replays use inspect_request
    /// instead: this method never treats an old record as a new apply. A named
    /// unchanged plan gets a zero-file journal so its outcome is discoverable.
    pub fn apply_for_request(
        &self,
        request: &InstallRequest,
        edits: &[Edit<'_>],
        creations: &[CreateFile<'_>],
    ) -> Result<AppliedRewrite> {
        request.check_project(&self.project)?;
        ensure!(rollback::lookup_request(self, request)?.is_none(),
            "installation request already has a recorded outcome; inspect it instead of applying again");
        ensure!(read_optional(&self.store, OsStr::new(PENDING), MAX_JOURNAL_BYTES)?.is_none(),
            "unfinished rewrite requires explicit recovery before a named installation");
        let journal = self.prepare_bound_changes(edits, creations, REQUEST_JOURNAL_VERSION, Some(request))?;
        self.apply_prepared(journal)?.context("named installation did not return its journal identity")
    }

    fn apply_prepared(&self, journal: Journal) -> Result<Option<AppliedRewrite>> {
        let receipt = AppliedRewrite {
            transaction_id: journal.session.clone(),
            journal_sha256: digest(&serde_json::to_vec(&journal)?),
            files: journal.records.len(),
        };
        let result = (|| -> Result<()> {
            // A source may have changed while other files/backups were staged.
            // Recheck the entire plan before replacing even the first source.
            for (index, record) in journal.records.iter().enumerate() {
                if record.created {
                    self.check_creation_ready(&journal, index)?;
                    continue;
                }
                if journal.schema_version != JOURNAL_VERSION {
                    let before = self.read_preimage(&journal, index)?;
                    ensure!(
                        verify_image(&before, &record.before_sha256, record.before_bytes, None),
                        "transaction preimage integrity failed before installation: {}",
                        record.path
                    );
                }
                let (parent, name) = parent_and_name(&self.root, &record.path, false)?;
                let current = read_required(&parent, &name, MAX_FILE_BYTES)?;
                ensure!(
                    verify_image(
                        &current,
                        &record.before_sha256,
                        record.before_bytes,
                        Some(record.mode)
                    ),
                    "source changed before rewrite commit: {}",
                    record.path
                );
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
                Ok(true) => {
                    Err(error.context("rewrite installation failed; original sources restored"))
                }
                Ok(false) => Err(error.context(
                    "rewrite completion durability failed; inspect retained transaction evidence",
                )),
                Err(recovery) => Err(anyhow::anyhow!(
                    "rewrite installation failed: {error:#}; recovery also failed: {recovery:#}"
                )),
            };
        }
        Ok(Some(receipt))
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
        [
            Edit {
                path: "a.js",
                before: b"before-a",
                after: b"after-a",
            },
            Edit {
                path: "b.js",
                before: b"before-b",
                after: b"after-b",
            },
        ]
    }
    fn pending(root: &Path) -> std::path::PathBuf {
        root.join(".migrate-backup/.franken-rewrite/pending.json")
    }
    fn assert_original(root: &Path) {
        assert_eq!(fs::read(root.join("a.js")).unwrap(), b"before-a");
        assert_eq!(fs::read(root.join("b.js")).unwrap(), b"before-b");
        assert_eq!(
            fs::metadata(root.join("a.js")).unwrap().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn commits_all_sources_preserves_modes_and_keeps_private_original_backups() {
        let root = project();
        RewriteTransaction::open(root.path())
            .unwrap()
            .apply(&edits())
            .unwrap();
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a");
        assert_eq!(fs::read(root.path().join("b.js")).unwrap(), b"after-b");
        assert_eq!(
            fs::metadata(root.path().join("a.js")).unwrap().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::read(root.path().join(".migrate-backup/a.js")).unwrap(),
            b"before-a"
        );
        assert_eq!(
            fs::metadata(root.path().join(".migrate-backup/a.js"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!pending(root.path()).exists());
        drop(RewriteTransaction::open(root.path()).unwrap());
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a");
    }

    #[test]
    fn later_backup_conflict_cannot_leave_an_earlier_source_rewritten() {
        let root = project();
        fs::create_dir(root.path().join(".migrate-backup")).unwrap();
        fs::write(root.path().join(".migrate-backup/b.js"), b"older-original").unwrap();
        let error = RewriteTransaction::open(root.path())
            .unwrap()
            .apply(&edits())
            .unwrap_err();
        assert!(error.to_string().contains("backup conflict"));
        assert_original(root.path());
        assert!(!root.path().join(".migrate-backup/a.js").exists());
        assert_eq!(
            fs::read(root.path().join(".migrate-backup/b.js")).unwrap(),
            b"older-original"
        );
    }

    #[test]
    fn stale_source_preimage_rejects_the_entire_plan() {
        let root = project();
        let mut plan = edits();
        plan[1].before = b"stale";
        assert!(
            RewriteTransaction::open(root.path())
                .unwrap()
                .apply(&plan)
                .is_err()
        );
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
                "dir", "dir", "dir", // Journal data, then its directory entry.
                "file", "journal",
                // INSTALL: two replaced sources, data synced before each rename.
                "file", "file",
                // Source directory flushed once, BEFORE the journal is retired.
                "dir", // Retirement persisted in both directories.
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
            for index in 0..2 {
                transaction.install(&journal, index).unwrap();
            }
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
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, path)| path);
        let test_name = format!("{module}::abruptly_exiting_writer_leaves_a_recoverable_journal");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name.as_str(), "--nocapture"])
            .env(CHILD_ROOT, root.path())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(73),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
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
            assert!(
                RewriteTransaction::open(root.path())
                    .unwrap()
                    .apply(&edits())
                    .is_err()
            );
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
        let edits = [Edit {
            path: "alias/file.js",
            before: b"before",
            after: b"after",
        }];
        assert!(
            RewriteTransaction::open(root.path())
                .unwrap()
                .apply(&edits)
                .is_err()
        );
        assert_eq!(fs::read(outside.path().join("file.js")).unwrap(), b"before");
    }

    #[test]
    fn hardlinked_sources_fail_closed() {
        let root = project();
        fs::hard_link(root.path().join("b.js"), root.path().join("alias.js")).unwrap();
        assert!(
            RewriteTransaction::open(root.path())
                .unwrap()
                .apply(&edits())
                .is_err()
        );
        assert_original(root.path());
    }

    #[test]
    fn duplicate_and_noncanonical_paths_are_rejected_before_edits() {
        let root = project();
        let transaction = RewriteTransaction::open(root.path()).unwrap();
        let duplicate = [
            Edit {
                path: "a.js",
                before: b"before-a",
                after: b"after",
            },
            Edit {
                path: "a.js",
                before: b"before-a",
                after: b"other",
            },
        ];
        assert!(transaction.apply(&duplicate).is_err());
        for path in [
            "../a.js",
            "/a.js",
            "a/../a.js",
            "./a.js",
            "a//b.js",
            "a\\b.js",
            ".git/config",
            ".migrate-backup/a.js",
            ".franken-node/package.json",
        ] {
            assert!(
                transaction
                    .apply(&[Edit {
                        path,
                        before: b"",
                        after: b""
                    }])
                    .is_err(),
                "{path}"
            );
        }
        assert_original(root.path());
    }

    #[test]
    fn oversized_replacement_is_rejected_before_backup_or_source_mutation() {
        let root = project();
        let bytes = vec![b'x'; MAX_FILE_BYTES + 1];
        let edits = [Edit {
            path: "a.js",
            before: b"before-a",
            after: &bytes,
        }];
        assert!(
            RewriteTransaction::open(root.path())
                .unwrap()
                .apply(&edits)
                .is_err()
        );
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
        let mut journal: serde_json::Value =
            serde_json::from_slice(&fs::read(pending(root.path())).unwrap()).unwrap();
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
        fs::write(
            root.path()
                .join(".migrate-backup")
                .join(STORE)
                .join(&journal.session)
                .join("0.after"),
            b"tampered",
        )
        .unwrap();
        assert!(transaction.install(&journal, 0).is_err());
        transaction.recover_pending().unwrap();
        assert_original(root.path());
    }

    #[test]
    fn successful_empty_plan_does_not_create_pending_work() {
        let root = project();
        RewriteTransaction::open(root.path())
            .unwrap()
            .apply(&[])
            .unwrap();
        assert!(!pending(root.path()).exists());
        assert_original(root.path());
    }
}

#[cfg(test)]
mod applied_receipt_tests {
    use super::*;
    use std::fs;

    #[test]
    fn returned_receipt_selects_exact_pinned_rollback_without_guessing_history() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app.js"), b"original").unwrap();
        let receipt = {
            let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
            writer.apply_with_receipt(&[Edit { path: "app.js", before: b"original", after: b"candidate" }])
                .unwrap().unwrap()
        };
        assert_eq!(receipt.files, 1);
        let preview = rollback::run_pinned(root.path(), &receipt.transaction_id, &receipt.journal_sha256, false);
        assert_eq!(preview.status, rollback::RollbackStatus::Ready);
        assert_eq!(preview.transaction.unwrap().journal_sha256, receipt.journal_sha256);
        let restored = rollback::run_pinned(root.path(), &receipt.transaction_id, &receipt.journal_sha256, true);
        assert_eq!(restored.status, rollback::RollbackStatus::RolledBack);
        assert_eq!(fs::read(root.path().join("app.js")).unwrap(), b"original");
    }

    #[test]
    fn reviewed_open_refuses_pending_work_without_restoring_any_source() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app.js"), b"original").unwrap();
        {
            let writer = RewriteTransaction::open(root.path()).unwrap();
            let journal = writer.prepare(&[Edit { path: "app.js", before: b"original", after: b"candidate" }]).unwrap();
            writer.install(&journal, 0).unwrap();
        }
        assert!(RewriteTransaction::open_without_recovery(root.path()).is_err());
        assert_eq!(fs::read(root.path().join("app.js")).unwrap(), b"candidate");
        assert!(root.path().join(".migrate-backup/.franken-rewrite/pending.json").exists());
        // The existing explicit recovery-capable entrypoint retains its contract.
        drop(RewriteTransaction::open(root.path()).unwrap());
        assert_eq!(fs::read(root.path().join("app.js")).unwrap(), b"original");
    }

    #[test]
    fn empty_apply_returns_no_transaction_and_keeps_history_empty() {
        let root = tempfile::tempdir().unwrap();
        {
            let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
            assert!(writer.apply_with_receipt(&[]).unwrap().is_none());
            assert!(RewriteTransaction::open_without_recovery(root.path()).is_err());
        }
        assert!(rollback::run(root.path(), None, false).history.is_empty());
    }
}

#[cfg(test)]
mod versioned_preimage_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    fn project() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("a.js"), b"a0").unwrap();
        fs::write(root.path().join("b.js"), b"b0").unwrap();
        fs::set_permissions(root.path().join("a.js"), Permissions::from_mode(0o751)).unwrap();
        root
    }

    fn apply(root: &Path, before: [&[u8]; 2], after: [&[u8]; 2]) -> AppliedRewrite {
        let writer = RewriteTransaction::open_without_recovery(root).unwrap();
        writer.apply_versioned_with_receipt(&[
            Edit { path: "a.js", before: before[0], after: after[0] },
            Edit { path: "b.js", before: before[1], after: after[1] },
        ]).unwrap().unwrap()
    }

    fn session(root: &Path, receipt: &AppliedRewrite) -> PathBuf {
        root.join(".migrate-backup").join(STORE).join(&receipt.transaction_id)
    }

    fn sources(root: &Path, a: &[u8], b: &[u8]) {
        assert_eq!(fs::read(root.join("a.js")).unwrap(), a);
        assert_eq!(fs::read(root.join("b.js")).unwrap(), b);
        assert_eq!(fs::metadata(root.join("a.js")).unwrap().mode() & 0o777, 0o751);
    }

    fn restore(root: &Path, receipt: &AppliedRewrite) -> rollback::RollbackReport {
        rollback::run_pinned(root, &receipt.transaction_id, &receipt.journal_sha256, true)
    }

    #[test]
    fn repeated_migrations_restore_the_immediate_predecessor_instead_of_the_first_original() {
        let root = project();
        let first = apply(root.path(), [b"a0", b"b0"], [b"a1", b"b1"]);
        let second = apply(root.path(), [b"a1", b"b1"], [b"a2", b"b2"]);
        assert_ne!(first.transaction_id, second.transaction_id);
        assert_ne!(first.journal_sha256, second.journal_sha256);
        sources(root.path(), b"a2", b"b2");
        for (receipt, a, b) in [(&first, b"a0", b"b0"), (&second, b"a1", b"b1")] {
            let directory = session(root.path(), receipt);
            let journal: Journal = serde_json::from_slice(&fs::read(directory.join("applied.json")).unwrap()).unwrap();
            assert_eq!(journal.schema_version, VERSIONED_JOURNAL_VERSION);
            assert_eq!(digest(&serde_json::to_vec(&journal).unwrap()), receipt.journal_sha256);
            assert_eq!(fs::read(directory.join("0.before")).unwrap(), a);
            assert_eq!(fs::read(directory.join("1.before")).unwrap(), b);
            assert_eq!(fs::metadata(directory.join("0.before")).unwrap().mode() & 0o777, 0o600);
        }
        assert!(!root.path().join(".migrate-backup/a.js").exists());
        assert_eq!(restore(root.path(), &first).status, rollback::RollbackStatus::Conflict);
        sources(root.path(), b"a2", b"b2");
        assert_eq!(restore(root.path(), &second).status, rollback::RollbackStatus::RolledBack);
        sources(root.path(), b"a1", b"b1");
        assert_eq!(restore(root.path(), &first).status, rollback::RollbackStatus::RolledBack);
        sources(root.path(), b"a0", b"b0");
        assert_eq!(fs::read(session(root.path(), &second).join("0.before")).unwrap(), b"a1");
        fs::write(root.path().join("a.js"), b"later user work").unwrap();
        assert_eq!(restore(root.path(), &second).status, rollback::RollbackStatus::AlreadyRolledBack);
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"later user work");
    }

    #[test]
    fn a_versioned_install_can_follow_a_legacy_journal_without_replacing_its_backups() {
        let root = project();
        let legacy = {
            let writer = RewriteTransaction::open(root.path()).unwrap();
            writer.apply_with_receipt(&[
                Edit { path: "a.js", before: b"a0", after: b"a1" },
                Edit { path: "b.js", before: b"b0", after: b"b1" },
            ]).unwrap().unwrap()
        };
        let original_journal = fs::read(session(root.path(), &legacy).join("applied.json")).unwrap();
        let second = apply(root.path(), [b"a1", b"b1"], [b"a2", b"b2"]);
        assert_eq!(fs::read(root.path().join(".migrate-backup/a.js")).unwrap(), b"a0");
        assert_eq!(fs::read(session(root.path(), &legacy).join("applied.json")).unwrap(), original_journal);
        assert_eq!(restore(root.path(), &legacy).status, rollback::RollbackStatus::Conflict);
        assert_eq!(restore(root.path(), &second).status, rollback::RollbackStatus::RolledBack);
        sources(root.path(), b"a1", b"b1");
        assert_eq!(restore(root.path(), &legacy).status, rollback::RollbackStatus::RolledBack);
        sources(root.path(), b"a0", b"b0");
    }

    #[test]
    fn damaged_versioned_preimages_never_fall_back_to_legacy_backups() {
        for mutation in 0..5 {
            let root = project();
            let receipt = apply(root.path(), [b"a0", b"b0"], [b"a1", b"b1"]);
            // Even a byte-correct global backup cannot substitute for this
            // journal's missing, linked, corrupt or non-private preimage.
            fs::write(root.path().join(".migrate-backup/a.js"), b"a0").unwrap();
            fs::write(root.path().join(".migrate-backup/b.js"), b"b0").unwrap();
            let before = session(root.path(), &receipt).join("1.before");
            let saved = root.path().join("retained-before");
            match mutation {
                0 => fs::rename(&before, &saved).unwrap(),
                1 => fs::write(&before, b"corrupt").unwrap(),
                2 => {
                    fs::rename(&before, &saved).unwrap();
                    symlink(&saved, &before).unwrap();
                }
                3 => fs::hard_link(&before, &saved).unwrap(),
                _ => fs::set_permissions(&before, Permissions::from_mode(0o644)).unwrap(),
            }
            let report = restore(root.path(), &receipt);
            assert_eq!(report.status, rollback::RollbackStatus::Conflict, "mutation {mutation}: {report:?}");
            sources(root.path(), b"a1", b"b1");
            assert!(!root.path().join(".migrate-backup").join(STORE).join(PENDING).exists());
            assert!(!session(root.path(), &receipt).join("rolled-back.json").exists());
        }
    }

    #[test]
    fn pending_second_generation_recovers_without_undoing_the_completed_first() {
        let root = project();
        let first = apply(root.path(), [b"a0", b"b0"], [b"a1", b"b1"]);
        let second = {
            let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
            let journal = writer.prepare_with_preimages(&[
                Edit { path: "a.js", before: b"a1", after: b"a2" },
                Edit { path: "b.js", before: b"b1", after: b"b2" },
            ], true).unwrap();
            writer.install(&journal, 0).unwrap();
            AppliedRewrite {
                transaction_id: journal.session.clone(),
                journal_sha256: digest(&serde_json::to_vec(&journal).unwrap()),
                files: 2,
            }
        };
        sources(root.path(), b"a2", b"b1");
        assert!(RewriteTransaction::open_without_recovery(root.path()).is_err());
        // The actual startup recovery path dispatches v2; there is no second
        // recovery implementation and no reliance on a global original.
        drop(RewriteTransaction::open(root.path()).unwrap());
        sources(root.path(), b"a1", b"b1");
        assert!(session(root.path(), &second).join("rolled-back.json").is_file());
        assert!(!session(root.path(), &first).join("rolled-back.json").exists());
        assert_eq!(restore(root.path(), &first).status, rollback::RollbackStatus::RolledBack);
        sources(root.path(), b"a0", b"b0");
    }

    #[test]
    fn a_later_user_conflict_blocks_the_complete_versioned_rollback_preflight() {
        let root = project();
        let receipt = apply(root.path(), [b"a0", b"b0"], [b"a1", b"b1"]);
        fs::write(root.path().join("b.js"), b"independent user edit").unwrap();
        assert_eq!(restore(root.path(), &receipt).status, rollback::RollbackStatus::Conflict);
        sources(root.path(), b"a1", b"independent user edit");
        // Explicit conflict resolution, not something performed by recovery.
        fs::write(root.path().join("b.js"), b"b1").unwrap();
        assert_eq!(restore(root.path(), &receipt).status, rollback::RollbackStatus::RolledBack);
        sources(root.path(), b"a0", b"b0");
    }

    #[test]
    fn versioned_images_are_durable_before_intent_and_sources_before_completion() {
        let root = project();
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        DURABILITY_LOG.with(|log| log.borrow_mut().clear());
        writer.apply_versioned_with_receipt(&[
            Edit { path: "a.js", before: b"a0", after: b"a1" },
            Edit { path: "b.js", before: b"b0", after: b"b1" },
        ]).unwrap();
        let log = DURABILITY_LOG.with(|log| std::mem::take(&mut *log.borrow_mut()));
        assert_eq!(log, [
            "file", "file", "file", "file", // both before/after pairs
            "dir", "dir", // session contents and its entry in the store
            "file", "journal", // pending intent
            "file", "file", "dir", // installed sources and their directory
            "archive", "archive", // completed journal and pending retirement
        ]);
    }

    #[test]
    fn versioned_preflight_rejects_a_stale_later_source_before_creating_a_session() {
        let root = project();
        {
            let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
            assert!(writer.apply_versioned_with_receipt(&[
                Edit { path: "a.js", before: b"a0", after: b"a1" },
                Edit { path: "b.js", before: b"stale", after: b"b1" },
            ]).is_err());
            assert!(writer.apply_versioned_with_receipt(&[]).unwrap().is_none());
        }
        sources(root.path(), b"a0", b"b0");
        let store = root.path().join(".migrate-backup").join(STORE);
        assert_eq!(fs::read_dir(store).unwrap().count(), 1); // only the lock
        assert!(rollback::run(root.path(), None, false).history.is_empty());
    }

    #[test]
    fn failed_second_generation_install_restores_only_its_own_preimages() {
        let root = project();
        let first = apply(root.path(), [b"a0", b"b0"], [b"a1", b"b1"]);
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        let journal = writer.prepare_with_preimages(&[
            Edit { path: "a.js", before: b"a1", after: b"a2" },
            Edit { path: "b.js", before: b"b1", after: b"b2" },
        ], true).unwrap();
        let session = root.path().join(".migrate-backup").join(STORE).join(&journal.session);
        fs::write(session.join("1.after"), b"damaged after-image").unwrap();
        let error = writer.apply_prepared(journal).unwrap_err();
        assert!(format!("{error:#}").contains("original sources restored"), "{error:#}");
        sources(root.path(), b"a1", b"b1");
        assert!(session.join("rolled-back.json").is_file());
        assert!(!root.path().join(".migrate-backup").join(STORE)
            .join(&first.transaction_id).join("rolled-back.json").exists());
    }

    #[test]
    fn versioned_preimage_corruption_is_detected_before_any_live_replacement() {
        let root = project();
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        let journal = writer.prepare_with_preimages(&[
            Edit { path: "a.js", before: b"a0", after: b"a1" },
            Edit { path: "b.js", before: b"b0", after: b"b1" },
        ], true).unwrap();
        fs::write(root.path().join(".migrate-backup").join(STORE)
            .join(&journal.session).join("1.before"), b"damaged preimage").unwrap();
        let error = writer.apply_prepared(journal).unwrap_err();
        assert!(format!("{error:#}").contains("preimage integrity failed before installation"), "{error:#}");
        sources(root.path(), b"a0", b"b0");
    }

    #[test]
    fn preimages_from_another_generation_and_changed_schema_cannot_satisfy_a_pin() {
        let root = project();
        let first = apply(root.path(), [b"a0", b"b0"], [b"a1", b"b1"]);
        let second = apply(root.path(), [b"a1", b"b1"], [b"a2", b"b2"]);
        let preimage = session(root.path(), &second).join("0.before");
        let actual = fs::read(&preimage).unwrap();
        fs::write(&preimage, fs::read(session(root.path(), &first).join("0.before")).unwrap()).unwrap();
        assert_eq!(restore(root.path(), &second).status, rollback::RollbackStatus::Conflict);
        sources(root.path(), b"a2", b"b2");
        fs::write(&preimage, actual).unwrap();
        let path = session(root.path(), &second).join("applied.json");
        let raw = fs::read(&path).unwrap();
        let mut journal: Journal = serde_json::from_slice(&raw).unwrap();
        journal.schema_version = JOURNAL_VERSION.into();
        fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
        let report = restore(root.path(), &second);
        assert_ne!(report.status, rollback::RollbackStatus::RolledBack);
        sources(root.path(), b"a2", b"b2");
        fs::write(&path, raw).unwrap();
        assert_eq!(restore(root.path(), &second).status, rollback::RollbackStatus::RolledBack);
        sources(root.path(), b"a1", b"b1");
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use rollback::{RollbackStatus, TransactionState};

    fn project() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app.cjs"), b"before").unwrap();
        root
    }

    fn request(root: &Path, id: &str) -> InstallRequest {
        InstallRequest::new(root, id, &"a".repeat(64), &"b".repeat(64)).unwrap()
    }

    fn edits() -> [Edit<'static>; 1] {
        [Edit { path: "app.cjs", before: b"before", after: b"after" }]
    }

    fn session(root: &Path, request: &InstallRequest) -> PathBuf {
        root.join(".migrate-backup").join(STORE).join(request.transaction_id())
    }

    #[test]
    fn request_validation_and_unused_lookup_never_create_metadata() {
        let root = project();
        for id in ["", "../escape", "has space", "line\n", "nonascii-\u{03b1}"] {
            assert!(InstallRequest::new(root.path(), id, &"a".repeat(64), &"b".repeat(64)).is_err());
        }
        assert!(InstallRequest::new(root.path(), &"x".repeat(65), &"a".repeat(64), &"b".repeat(64)).is_err());
        for hash in ["a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64)] {
            assert!(InstallRequest::new(root.path(), "valid", &hash, &"b".repeat(64)).is_err());
        }
        let request = request(root.path(), "Pipeline_07-build-2");
        assert!(rollback::inspect_request(root.path(), &request).unwrap().is_none());
        assert!(!root.path().join(".migrate-backup").exists());
        assert_eq!(request.transaction_id().len(), 76);
        assert_eq!(serde_json::from_slice::<InstallRequest>(&serde_json::to_vec(&request).unwrap()).unwrap(), request);
    }

    #[test]
    fn recorded_request_is_exact_history_not_authority_to_repeat_or_certify_sources() {
        let root = project();
        let request = request(root.path(), "deployment-17");
        let receipt = RewriteTransaction::open_without_recovery(root.path()).unwrap()
            .apply_for_request(&request, &edits(), &[]).unwrap();
        let raw = fs::read(session(root.path(), &request).join("applied.json")).unwrap();
        let journal: Journal = serde_json::from_slice(&raw).unwrap();
        assert_eq!(journal.schema_version, REQUEST_JOURNAL_VERSION);
        assert_eq!(journal.request.as_ref(), Some(&request));
        assert_eq!(receipt.transaction_id, request.transaction_id());
        assert_eq!(receipt.journal_sha256, digest(&serde_json::to_vec(&journal).unwrap()));
        fs::write(root.path().join("app.cjs"), b"later user work").unwrap();
        let found = rollback::inspect_request(root.path(), &request).unwrap().unwrap();
        assert_eq!(found.state, TransactionState::Applied);
        assert_eq!(found.journal_sha256, receipt.journal_sha256);
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        assert!(writer.apply_for_request(&request, &edits(), &[]).is_err());
        assert!(rollback::inspect_request(root.path(), &request).is_err()); // real lock
        drop(writer);
        assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"later user work");
        assert_eq!(fs::read(session(root.path(), &request).join("applied.json")).unwrap(), raw);
    }

    #[test]
    fn request_id_reuse_with_different_pins_or_project_never_selects_new_work() {
        let root = project();
        let original = request(root.path(), "same-id");
        RewriteTransaction::open_without_recovery(root.path()).unwrap()
            .apply_for_request(&original, &edits(), &[]).unwrap();
        for (input, candidate) in [("b", "a"), ("a", "c")] {
            let changed = InstallRequest::new(root.path(), "same-id", &input.repeat(64), &candidate.repeat(64)).unwrap();
            assert_eq!(changed.transaction_id(), original.transaction_id());
            assert!(rollback::inspect_request(root.path(), &changed).is_err());
        }
        let other = project();
        assert!(rollback::inspect_request(other.path(), &original).is_err());
        assert!(!other.path().join(".migrate-backup").exists());
        assert!(RewriteTransaction::open_without_recovery(other.path()).unwrap()
            .apply_for_request(&original, &edits(), &[]).is_err());
        assert_eq!(fs::read(other.path().join("app.cjs")).unwrap(), b"before");
        assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"after");
    }

    #[test]
    fn named_noop_is_durable_and_cannot_hide_a_nonidentical_capture() {
        let root = project();
        let invalid = request(root.path(), "invalid-noop");
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        assert!(writer.apply_for_request(&invalid, &[], &[]).is_err());
        assert!(!session(root.path(), &invalid).exists());
        let request = InstallRequest::new(root.path(), "noop", &"a".repeat(64), &"a".repeat(64)).unwrap();
        let receipt = writer.apply_for_request(&request, &[], &[]).unwrap();
        assert_eq!(receipt.files, 0);
        drop(writer);
        assert_eq!(rollback::inspect_request(root.path(), &request).unwrap().unwrap().state, TransactionState::Applied);
        assert_eq!(rollback::run_pinned(root.path(), &receipt.transaction_id, &receipt.journal_sha256, true).status,
            RollbackStatus::RolledBack);
        assert_eq!(rollback::inspect_request(root.path(), &request).unwrap().unwrap().state, TransactionState::RolledBack);
        assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"before");
    }

    #[test]
    fn rolled_back_request_remains_consumed_and_preserves_later_work() {
        let root = project();
        let request = request(root.path(), "mixed-install");
        let receipt = RewriteTransaction::open_without_recovery(root.path()).unwrap()
            .apply_for_request(&request, &edits(), &[CreateFile { path: "helper.cjs", after: b"new", mode: 0o640 }])
            .unwrap();
        assert_eq!(receipt.files, 2);
        assert_eq!(rollback::run_pinned(root.path(), &receipt.transaction_id, &receipt.journal_sha256, true).status,
            RollbackStatus::RolledBack);
        assert!(!root.path().join("helper.cjs").exists());
        assert_eq!(fs::read(session(root.path(), &request).join("1.retired")).unwrap(), b"new");
        fs::write(root.path().join("helper.cjs"), b"later helper").unwrap();
        let found = rollback::inspect_request(root.path(), &request).unwrap().unwrap();
        assert_eq!(found.state, TransactionState::RolledBack);
        assert!(RewriteTransaction::open_without_recovery(root.path()).unwrap()
            .apply_for_request(&request, &edits(), &[]).is_err());
        assert_eq!(fs::read(root.path().join("helper.cjs")).unwrap(), b"later helper");
        assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"before");
    }

    #[test]
    fn incomplete_staging_and_substituted_bindings_fail_closed_without_recovery() {
        let root = project();
        let request = request(root.path(), "incomplete");
        let writer = RewriteTransaction::open_without_recovery(root.path()).unwrap();
        fs::create_dir(session(root.path(), &request)).unwrap();
        assert!(writer.apply_for_request(&request, &edits(), &[]).is_err());
        drop(writer);
        assert!(rollback::inspect_request(root.path(), &request).is_err());
        assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"before");
        let request = InstallRequest::new(root.path(), "complete", &"a".repeat(64), &"b".repeat(64)).unwrap();
        RewriteTransaction::open_without_recovery(root.path()).unwrap()
            .apply_for_request(&request, &edits(), &[]).unwrap();
        let path = session(root.path(), &request).join("applied.json");
        let mut journal: Journal = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        journal.request.as_mut().unwrap().candidate_input_sha256 = "c".repeat(64);
        fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
        assert!(rollback::inspect_request(root.path(), &request).is_err());
        assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"after");
    }

    #[test]
    fn request_schema_is_mandatory_and_old_journal_bytes_are_unchanged() {
        let root = project();
        let writer = RewriteTransaction::open(root.path()).unwrap();
        let journal = writer.prepare(&edits()).unwrap();
        let encoded = serde_json::to_vec(&journal).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert!(raw.get("request").is_none());
        assert_eq!(encoded, serde_json::to_vec(&serde_json::from_slice::<Journal>(&encoded).unwrap()).unwrap());
        let request = request(root.path(), "schema");
        let mut changed = journal;
        changed.request = Some(request.clone());
        for schema in [JOURNAL_VERSION, VERSIONED_JOURNAL_VERSION, creations::JOURNAL_VERSION] {
            changed.schema_version = schema.into();
            assert!(RewriteTransaction::validate_journal(&changed).is_err());
        }
        changed.schema_version = REQUEST_JOURNAL_VERSION.into();
        assert!(RewriteTransaction::validate_journal(&changed).is_err()); // old random slot
        changed.session = request.transaction_id();
        RewriteTransaction::validate_journal(&changed).unwrap();
        changed.request = None;
        assert!(RewriteTransaction::validate_journal(&changed).is_err());
    }

    #[test]
    fn process_exit_before_and_after_commit_keeps_the_request_bound_to_one_journal() {
        const ROOT: &str = "FRANKEN_REQUEST_CRASH_ROOT";
        const STEP: &str = "FRANKEN_REQUEST_CRASH_STEP";
        if let Some(root) = std::env::var_os(ROOT) {
            let root = PathBuf::from(root);
            let request = request(&root, "crash-case");
            let writer = RewriteTransaction::open_without_recovery(&root).unwrap();
            let journal = writer.prepare_bound_changes(&edits(),
                &[CreateFile { path: "helper.cjs", after: b"helper", mode: 0o600 }],
                REQUEST_JOURNAL_VERSION, Some(&request)).unwrap();
            let step: usize = std::env::var(STEP).unwrap().parse().unwrap();
            if step == 3 {
                writer.apply_prepared(journal).unwrap();
            } else {
                for index in 0..step { writer.install(&journal, index).unwrap(); }
            }
            std::process::exit(73); // no destructors and no stdout delivery
        }
        let module = module_path!().split_once("::").map_or(module_path!(), |(_, m)| m);
        let test = format!("{module}::process_exit_before_and_after_commit_keeps_the_request_bound_to_one_journal");
        for step in 0..=3 {
            let root = project();
            let request = request(root.path(), "crash-case");
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test]).env(ROOT, root.path()).env(STEP, step.to_string())
                .output().unwrap();
            assert_eq!(child.status.code(), Some(73), "{}", String::from_utf8_lossy(&child.stderr));
            let found = rollback::inspect_request(root.path(), &request).unwrap().unwrap();
            assert_eq!(found.state, if step == 3 { TransactionState::Applied } else { TransactionState::ApplyInterrupted });
            assert_eq!(found.transaction_id, request.transaction_id());
            // Inspection cannot implicitly finish or undo an interrupted apply.
            assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), if step == 0 { b"before".as_slice() } else { b"after" });
            assert_eq!(rollback::run_pinned(root.path(), &found.transaction_id, &found.journal_sha256, true).status,
                RollbackStatus::RolledBack);
            assert_eq!(fs::read(root.path().join("app.cjs")).unwrap(), b"before");
            assert!(!root.path().join("helper.cjs").exists());
            assert_eq!(rollback::inspect_request(root.path(), &request).unwrap().unwrap().state, TransactionState::RolledBack);
        }
    }
}
