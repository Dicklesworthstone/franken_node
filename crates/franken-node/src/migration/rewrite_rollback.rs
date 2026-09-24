//! Operator-directed restoration of an applied or interrupted native rewrite.
//!
//! Preview/history never create state or recover pending work. Applying requires
//! an explicit transaction ID and a complete preflight, then uses the SAME
//! write-ahead recovery protocol as the rewrite writer. No shell, Git restore,
//! source deletion, or runtime execution is involved. Local journals are trusted
//! recovery metadata, not signatures; this is not an adversarial OS sandbox.

use super::{Journal, MAX_FILE_BYTES, MAX_JOURNAL_BYTES, PENDING, RewriteTransaction, STORE,
    digest, directory, parent_and_name, read_optional, read_required, verify_image};
use anyhow::{Context, Result, ensure};
use rustix::fs::{Dir, FlockOperation, Mode, OFlags, flock, open, openat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_HISTORY_ENTRIES: usize = 1_000;
const MAX_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RollbackStatus { History, Ready, Conflict, RolledBack, AlreadyRolledBack, Error }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionState { Applied, ApplyInterrupted, RollbackPending, RolledBack }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub transaction_id: String,
    pub state: TransactionState,
    pub files: usize,
    /// Hash of the validated, canonically reserialized local journal.
    pub journal_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState { Original, Rewritten, Conflict }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackFile {
    pub path: String,
    /// State observed during preflight, NOT a claim about later concurrent edits.
    pub preflight_state: SourceState,
    pub original_sha256: String,
    pub rewritten_sha256: String,
    pub mode: u32,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReport {
    pub schema_version: String,
    pub project_path: String,
    pub status: RollbackStatus,
    pub apply_requested: bool,
    pub transaction: Option<HistoryEntry>,
    pub pending_transaction_id: Option<String>,
    pub history: Vec<HistoryEntry>,
    pub files: Vec<RollbackFile>,
    pub errors: Vec<String>,
}

impl RollbackReport {
    pub fn exit_code(&self) -> u8 {
        match self.status {
            RollbackStatus::Conflict => 1,
            RollbackStatus::Error => 2,
            _ => 0,
        }
    }
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(id.starts_with("txn-") && id.len() > 4 && id.len() <= 96
        && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "transaction ID must be a single txn- identifier from migration rollback history");
    Ok(())
}

fn existing_directory(parent: &File, name: &str) -> Result<Option<File>> {
    match openat(parent, name, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("open existing rollback directory {name} without following links")),
    }
}

/// Acquire the writer's existing lock, but do not create directories, lock
/// files, or trigger recovery merely because an operator requested inspection.
fn open_existing(project: &Path) -> Result<Option<RewriteTransaction>> {
    let root = File::from(open(project,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?);
    let Some(backups) = existing_directory(&root, ".migrate-backup")? else { return Ok(None); };
    let Some(store) = existing_directory(&backups, STORE)? else { return Ok(None); };
    let lock = File::from(openat(&store, "lock",
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())
        .context("open existing rewrite lock")?);
    let metadata = lock.metadata()?;
    ensure!(metadata.is_file() && metadata.nlink() == 1, "invalid rewrite lock file");
    flock(&lock, FlockOperation::NonBlockingLockExclusive).context("another rewrite holds the project lock")?;
    Ok(Some(RewriteTransaction { root, backups, store, _lock: lock, dirty: Default::default() }))
}

struct JournalReader { remaining: usize }

impl JournalReader {
    fn new() -> Self { Self { remaining: MAX_HISTORY_BYTES } }

    fn read(&mut self, parent: &File, name: &str) -> Result<Option<Journal>> {
        let Some(contents) = read_optional(parent, OsStr::new(name), MAX_JOURNAL_BYTES.min(self.remaining))?
            else { return Ok(None); };
        self.remaining = self.remaining.checked_sub(contents.bytes.len()).context("rollback history byte budget exhausted")?;
        let journal: Journal = serde_json::from_slice(&contents.bytes).context("decode rollback journal")?;
        RewriteTransaction::validate_journal(&journal)?;
        validate_id(&journal.session)?;
        Ok(Some(journal))
    }
}

struct Selected { journal: Journal, state: TransactionState }

impl Selected {
    fn history_entry(&self) -> Result<HistoryEntry> {
        Ok(HistoryEntry { transaction_id: self.journal.session.clone(), state: self.state,
            files: self.journal.records.len(), journal_sha256: digest(&serde_json::to_vec(&self.journal)?) })
    }
}

fn select(transaction: &RewriteTransaction, id: &str, pending: Option<&Journal>,
    reader: &mut JournalReader) -> Result<Option<Selected>> {
    validate_id(id)?;
    let session = directory(&transaction.store, Path::new(id), false)?;
    let applied = reader.read(&session, "applied.json")?;
    let restored = reader.read(&session, "rolled-back.json")?;
    let pending = pending.filter(|journal| journal.session == id);
    for journal in applied.iter().chain(restored.iter()).chain(pending) {
        ensure!(journal.session == id, "journal transaction ID does not match its directory");
    }
    if let (Some(applied), Some(restored)) = (&applied, &restored) {
        ensure!(applied == restored, "applied and rollback journals disagree");
    }
    ensure!(restored.is_none() || pending.is_none(), "completed rollback also has a pending journal");
    if let (Some(applied), Some(pending)) = (&applied, pending) {
        ensure!(applied == pending, "pending journal does not match the applied transaction");
    }
    let state = if restored.is_some() { TransactionState::RolledBack }
        else if applied.is_some() && pending.is_some() { TransactionState::RollbackPending }
        else if pending.is_some() { TransactionState::ApplyInterrupted }
        else { TransactionState::Applied };
    let journal = applied.or(restored).or_else(|| pending.cloned());
    Ok(journal.map(|journal| Selected { journal, state }))
}

fn history(transaction: &RewriteTransaction, pending: Option<&Journal>, reader: &mut JournalReader) -> Result<Vec<HistoryEntry>> {
    let mut names = Vec::new();
    for (index, entry) in Dir::read_from(&transaction.store)?.enumerate() {
        ensure!(index < MAX_DIRECTORY_ENTRIES, "rollback transaction directory limit exceeded");
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if !bytes.starts_with(b"txn-") { continue; }
        let name = std::str::from_utf8(bytes).context("non-UTF-8 transaction name")?;
        validate_id(name)?;
        ensure!(names.len() < MAX_HISTORY_ENTRIES, "rollback history entry limit exceeded");
        names.push(name.to_owned());
    }
    names.sort();
    // The bounded directory inventory must contain the pending session too.
    if let Some(pending) = pending {
        ensure!(names.iter().any(|id| id == &pending.session), "pending transaction directory is missing");
    }
    let mut result = Vec::new();
    for id in names {
        if let Some(selected) = select(transaction, &id, pending, reader)? {
            result.push(selected.history_entry()?);
        }
        // Incomplete pre-journal staging sessions are not applied transactions.
    }
    Ok(result)
}

fn preflight(transaction: &RewriteTransaction, journal: &Journal) -> Vec<RollbackFile> {
    journal.records.iter().map(|record| {
        let state = (|| -> Result<SourceState> {
            let (parent, name) = parent_and_name(&transaction.backups, &record.path, false)?;
            let original = read_required(&parent, &name, MAX_FILE_BYTES)?;
            ensure!(verify_image(&original, &record.before_sha256, record.before_bytes, None),
                "original backup integrity mismatch");
            let (parent, name) = parent_and_name(&transaction.root, &record.path, false)?;
            let current = read_required(&parent, &name, MAX_FILE_BYTES)?;
            if verify_image(&current, &record.before_sha256, record.before_bytes, Some(record.mode)) {
                return Ok(SourceState::Original);
            }
            ensure!(verify_image(&current, &record.after_sha256, record.after_bytes, Some(record.mode)),
                "source content or permissions changed; preserving the user's edit");
            Ok(SourceState::Rewritten)
        })();
        let (preflight_state, error) = match state {
            Ok(state) => (state, None),
            Err(error) => (SourceState::Conflict, Some(format!("{error:#}"))),
        };
        RollbackFile { path: record.path.clone(), preflight_state,
            original_sha256: record.before_sha256.clone(), rewritten_sha256: record.after_sha256.clone(),
            mode: record.mode, error }
    }).collect()
}

/// With no ID, list retained transactions. With an ID, preview restoration.
/// Only `apply=true` may restore files. Recovery failures retain the existing
/// pending journal so either this command or the next rewrite can resume.
pub fn run(project: &Path, id: Option<&str>, apply: bool) -> RollbackReport {
    let mut report = RollbackReport { schema_version: "franken-node/migration-rollback/v1".into(),
        project_path: project.to_string_lossy().into_owned(), status: RollbackStatus::Error,
        apply_requested: apply, transaction: None, pending_transaction_id: None,
        history: Vec::new(), files: Vec::new(), errors: Vec::new() };
    let operation = (|| -> Result<()> {
        ensure!(!apply || id.is_some(), "applying rollback requires an explicit transaction ID");
        if let Some(id) = id { validate_id(id)?; }
        let project = project.canonicalize().context("resolve rollback project")?;
        report.project_path = project.to_string_lossy().into_owned();
        let Some(transaction) = open_existing(&project)? else {
            ensure!(id.is_none(), "project has no native rewrite transaction history");
            report.status = RollbackStatus::History;
            return Ok(());
        };
        let mut reader = JournalReader::new();
        let pending = reader.read(&transaction.store, PENDING)?;
        report.pending_transaction_id = pending.as_ref().map(|journal| journal.session.clone());
        let Some(id) = id else {
            report.history = history(&transaction, pending.as_ref(), &mut reader)?;
            report.status = RollbackStatus::History;
            return Ok(());
        };
        let selected = select(&transaction, id, pending.as_ref(), &mut reader)?
            .context("transaction has neither an applied nor a recoverable journal")?;
        report.transaction = Some(selected.history_entry()?);
        if selected.state == TransactionState::RolledBack {
            // Retrying an old ID must NEVER undo later independent edits or a
            // subsequent migration. This describes the receipt, not live state.
            report.status = RollbackStatus::AlreadyRolledBack;
            return Ok(());
        }
        if pending.as_ref().is_some_and(|journal| journal.session != id) {
            report.status = RollbackStatus::Conflict;
            report.errors.push("another transaction is pending; recover that exact transaction first".into());
            return Ok(());
        }
        report.files = preflight(&transaction, &selected.journal);
        if report.files.iter().any(|file| file.preflight_state == SourceState::Conflict) {
            report.status = RollbackStatus::Conflict;
            report.errors.push("rollback preflight failed; no source files changed by this request".into());
            return Ok(());
        }
        if !apply { report.status = RollbackStatus::Ready; return Ok(()); }
        if pending.is_none() {
            // Persist intent before touching even one source. The writer's
            // recovery protocol already converges monotonically to originals.
            let encoded = serde_json::to_vec(&selected.journal)?;
            ensure!(encoded.len() <= MAX_JOURNAL_BYTES, "rollback journal exceeds metadata budget");
            transaction.publish_journal(&encoded)?;
            report.pending_transaction_id = Some(id.to_owned());
        }
        ensure!(transaction.recover_pending().context(
            "rollback incomplete; preserve the pending journal and backups for recovery")?,
            "rollback pending journal unexpectedly disappeared");
        report.status = RollbackStatus::RolledBack;
        if let Some(entry) = report.transaction.as_mut() { entry.state = TransactionState::RolledBack; }
        report.pending_transaction_id = None;
        Ok(())
    })();
    if let Err(error) = operation {
        report.status = RollbackStatus::Error;
        report.errors.push(format!("{error:#}"));
    }
    report
}

pub fn render(report: &RollbackReport) -> String {
    let mut text = format!("franken-node migrate rollback\ntarget: {}\nstatus: {:?}\n",
        report.project_path, report.status);
    for entry in report.history.iter().chain(report.transaction.iter()) {
        let _ = writeln!(text, "{} {:?} files={} journal_sha256={}",
            entry.transaction_id, entry.state, entry.files, entry.journal_sha256);
    }
    for file in &report.files {
        let _ = writeln!(text, "  {:?} {}{}", file.preflight_state, file.path,
            file.error.as_ref().map_or(String::new(), |error| format!(": {error}")));
    }
    for error in &report.errors { let _ = writeln!(text, "error: {error}"); }
    if report.status == RollbackStatus::Ready {
        text.push_str("Preview only; repeat with the same --transaction and --apply to restore.\n");
    } else if report.status == RollbackStatus::AlreadyRolledBack {
        text.push_str("Restoration was already recorded. Current sources were not changed or certified.\n");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::Edit;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("a.js"), "before-a-private").unwrap();
        fs::write(root.path().join("b.js"), "before-b-private").unwrap();
        fs::set_permissions(root.path().join("a.js"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(root.path().join("b.js"), fs::Permissions::from_mode(0o644)).unwrap();
        root
    }

    fn edits() -> [Edit<'static>; 2] {
        [Edit { path: "a.js", before: b"before-a-private", after: b"after-a-private" },
         Edit { path: "b.js", before: b"before-b-private", after: b"after-b-private" }]
    }

    fn applied(root: &Path) -> String {
        RewriteTransaction::open(root).unwrap().apply(&edits()).unwrap();
        let report = run(root, None, false);
        assert_eq!(report.status, RollbackStatus::History, "{report:#?}");
        report.history.iter().find(|entry| entry.state == TransactionState::Applied).unwrap().transaction_id.clone()
    }

    fn store(root: &Path) -> PathBuf { root.join(".migrate-backup/.franken-rewrite") }

    fn assert_source(root: &Path, after: bool) {
        assert_eq!(fs::read(root.join("a.js")).unwrap(), if after { b"after-a-private".as_slice() } else { b"before-a-private".as_slice() });
        assert_eq!(fs::read(root.join("b.js")).unwrap(), if after { b"after-b-private".as_slice() } else { b"before-b-private".as_slice() });
        assert_eq!(fs::metadata(root.join("a.js")).unwrap().mode() & 0o777, 0o755);
        assert_eq!(fs::metadata(root.join("b.js")).unwrap().mode() & 0o777, 0o644);
    }

    fn journal(root: &Path, id: &str) -> Journal {
        serde_json::from_slice(&fs::read(store(root).join(id).join("applied.json")).unwrap()).unwrap()
    }

    #[test]
    fn empty_history_does_not_create_backups_or_lock_files() {
        let root = fixture();
        assert_eq!(run(root.path(), None, false).status, RollbackStatus::History);
        assert!(!root.path().join(".migrate-backup").exists());
        fs::create_dir(root.path().join(".migrate-backup")).unwrap();
        assert!(run(root.path(), None, false).history.is_empty());
        assert!(!store(root.path()).exists());
    }

    #[test]
    fn preview_retains_sources_journals_and_backups_without_starting_recovery() {
        let root = fixture();
        let id = applied(root.path());
        let before = fs::read(store(root.path()).join(&id).join("applied.json")).unwrap();
        let preview = run(root.path(), Some(&id), false);
        assert_eq!(preview.status, RollbackStatus::Ready, "{preview:#?}");
        assert_eq!(preview.files.len(), 2);
        assert!(preview.files.iter().all(|file| file.preflight_state == SourceState::Rewritten));
        assert_source(root.path(), true);
        assert!(!store(root.path()).join(PENDING).exists());
        assert!(!store(root.path()).join(&id).join("rolled-back.json").exists());
        assert_eq!(before, fs::read(store(root.path()).join(&id).join("applied.json")).unwrap());
        assert!(render(&preview).contains("Preview only"));
        let json = serde_json::to_string(&preview).unwrap();
        assert!(!json.contains("before-a-private") && !json.contains("after-a-private"));
        assert_eq!(serde_json::from_str::<RollbackReport>(&json).unwrap(), preview);
    }

    #[test]
    fn applied_transaction_restores_exact_originals_and_executable_modes() {
        let root = fixture();
        let id = applied(root.path());
        let report = run(root.path(), Some(&id), true);
        assert_eq!(report.status, RollbackStatus::RolledBack, "{report:#?}");
        assert_eq!(report.exit_code(), 0);
        assert_source(root.path(), false);
        assert_eq!(fs::read(root.path().join(".migrate-backup/a.js")).unwrap(), b"before-a-private");
        assert!(store(root.path()).join(&id).join("applied.json").exists());
        assert!(store(root.path()).join(&id).join("rolled-back.json").exists());
        assert!(!store(root.path()).join(PENDING).exists());
        assert_eq!(report.transaction.unwrap().state, TransactionState::RolledBack);
    }

    #[test]
    fn retrying_a_completed_rollback_never_overwrites_later_edits() {
        let root = fixture();
        let id = applied(root.path());
        assert_eq!(run(root.path(), Some(&id), true).status, RollbackStatus::RolledBack);
        fs::write(root.path().join("a.js"), "later user work").unwrap();
        let report = run(root.path(), Some(&id), true);
        assert_eq!(report.status, RollbackStatus::AlreadyRolledBack);
        assert!(report.files.is_empty());
        assert_eq!(fs::read_to_string(root.path().join("a.js")).unwrap(), "later user work");
        assert!(render(&report).contains("not changed or certified"));
    }

    #[test]
    fn late_source_conflict_cannot_partially_restore_an_earlier_file() {
        let root = fixture();
        let id = applied(root.path());
        fs::write(root.path().join("b.js"), "user edit").unwrap();
        let report = run(root.path(), Some(&id), true);
        assert_eq!(report.status, RollbackStatus::Conflict, "{report:#?}");
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.files[0].preflight_state, SourceState::Rewritten);
        assert_eq!(report.files[1].preflight_state, SourceState::Conflict);
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a-private");
        assert_eq!(fs::read(root.path().join("b.js")).unwrap(), b"user edit");
        assert!(!store(root.path()).join(PENDING).exists());
    }

    #[test]
    fn changed_permissions_and_missing_sources_are_conflicts_not_overwrite_requests() {
        for missing in [false, true] {
            let root = fixture();
            let id = applied(root.path());
            if missing { fs::rename(root.path().join("b.js"), root.path().join("saved-b.js")).unwrap(); }
            else { fs::set_permissions(root.path().join("b.js"), fs::Permissions::from_mode(0o600)).unwrap(); }
            assert_eq!(run(root.path(), Some(&id), true).status, RollbackStatus::Conflict);
            assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a-private");
            assert!(!store(root.path()).join(PENDING).exists());
        }
    }

    #[test]
    fn corrupt_or_missing_backup_is_refused_before_any_source_replacement() {
        for missing in [false, true] {
            let root = fixture();
            let id = applied(root.path());
            let backup = root.path().join(".migrate-backup/b.js");
            if missing { fs::rename(&backup, root.path().join("saved-backup")).unwrap(); }
            else { fs::write(&backup, "corrupt").unwrap(); }
            assert_eq!(run(root.path(), Some(&id), true).status, RollbackStatus::Conflict);
            assert_source(root.path(), true);
            assert!(!store(root.path()).join(PENDING).exists());
        }
    }

    #[test]
    fn source_and_backup_symlinks_cannot_redirect_rollback() {
        for backup in [false, true] {
            let root = fixture();
            let id = applied(root.path());
            let outside = tempfile::NamedTempFile::new().unwrap();
            fs::write(outside.path(), "external unchanged").unwrap();
            let target = root.path().join(if backup { ".migrate-backup/b.js" } else { "b.js" });
            fs::rename(&target, root.path().join("saved-b" )).unwrap();
            symlink(outside.path(), target).unwrap();
            assert_eq!(run(root.path(), Some(&id), true).status, RollbackStatus::Conflict);
            assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a-private");
            assert_eq!(fs::read_to_string(outside.path()).unwrap(), "external unchanged");
        }
    }

    #[test]
    fn hardlinked_source_and_backup_files_are_refused() {
        for backup in [false, true] {
            let root = fixture();
            let id = applied(root.path());
            let target = root.path().join(if backup { ".migrate-backup/b.js" } else { "b.js" });
            fs::hard_link(target, root.path().join("alias-b")).unwrap();
            assert_eq!(run(root.path(), Some(&id), true).status, RollbackStatus::Conflict);
            assert_source(root.path(), true);
        }
    }

    #[test]
    fn metadata_directory_or_session_symlinks_fail_closed() {
        for session in [false, true] {
            let root = fixture();
            let id = applied(root.path());
            let target = if session { store(root.path()).join(&id) } else { store(root.path()) };
            let saved = root.path().join("saved-metadata");
            fs::rename(&target, &saved).unwrap();
            symlink(saved, target).unwrap();
            assert_eq!(run(root.path(), Some(&id), true).status, RollbackStatus::Error);
            assert_source(root.path(), true);
        }
    }

    #[test]
    fn invalid_identifiers_and_apply_without_selection_never_create_state() {
        let root = fixture();
        for id in ["", "txn-", "latest", "../txn-a", "/txn-a", "txn-a/../b", "txn-a\\b", "txn-a\n"] {
            assert_eq!(run(root.path(), Some(id), true).status, RollbackStatus::Error, "{id:?}");
        }
        assert_eq!(run(root.path(), None, true).status, RollbackStatus::Error);
        assert!(!root.path().join(".migrate-backup").exists());
        assert_eq!(run(&root.path().join("absent"), None, false).status, RollbackStatus::Error);
    }

    #[test]
    fn forged_journal_paths_and_transaction_identity_are_rejected() {
        for identity in [false, true] {
            let root = fixture();
            let id = applied(root.path());
            let mut data = journal(root.path(), &id);
            if identity { data.session = "txn-different".into(); }
            else { data.records[0].path = "../outside".into(); }
            fs::write(store(root.path()).join(&id).join("applied.json"), serde_json::to_vec(&data).unwrap()).unwrap();
            assert_eq!(run(root.path(), Some(&id), true).status, RollbackStatus::Error);
            assert_source(root.path(), true);
        }
    }

    #[test]
    fn inconsistent_completed_receipt_cannot_claim_idempotent_success() {
        let root = fixture();
        let id = applied(root.path());
        let mut data = journal(root.path(), &id);
        data.records[0].before_sha256 = "0".repeat(64);
        fs::write(store(root.path()).join(&id).join("rolled-back.json"), serde_json::to_vec(&data).unwrap()).unwrap();
        assert_eq!(run(root.path(), Some(&id), true).status, RollbackStatus::Error);
        assert_source(root.path(), true);
    }

    #[test]
    fn unrelated_pending_transaction_blocks_rollback_without_implicit_recovery() {
        let root = fixture();
        let id = applied(root.path());
        fs::write(root.path().join("c.js"), "original-c").unwrap();
        let transaction = RewriteTransaction::open(root.path()).unwrap();
        let pending = transaction.prepare(&[Edit { path: "c.js", before: b"original-c", after: b"changed-c" }]).unwrap();
        transaction.install(&pending, 0).unwrap();
        drop(transaction);
        let report = run(root.path(), Some(&id), true);
        assert_eq!(report.status, RollbackStatus::Conflict);
        assert_eq!(report.pending_transaction_id.as_deref(), Some(pending.session.as_str()));
        assert_eq!(fs::read(root.path().join("c.js")).unwrap(), b"changed-c");
        assert_source(root.path(), true);
        let history = run(root.path(), None, false);
        assert_eq!(history.history.len(), 2);
        assert!(history.history.iter().any(|row| row.state == TransactionState::ApplyInterrupted));
    }

    #[test]
    fn explicit_interrupted_apply_recovery_does_not_plan_or_install_new_rewrites() {
        let root = fixture();
        let transaction = RewriteTransaction::open(root.path()).unwrap();
        let pending = transaction.prepare(&edits()).unwrap();
        transaction.install(&pending, 0).unwrap();
        drop(transaction);
        let preview = run(root.path(), Some(&pending.session), false);
        assert_eq!(preview.status, RollbackStatus::Ready);
        assert_eq!(preview.transaction.unwrap().state, TransactionState::ApplyInterrupted);
        assert_eq!(fs::read(root.path().join("a.js")).unwrap(), b"after-a-private");
        let report = run(root.path(), Some(&pending.session), true);
        assert_eq!(report.status, RollbackStatus::RolledBack, "{report:#?}");
        assert_source(root.path(), false);
        assert!(!store(root.path()).join(&pending.session).join("applied.json").exists());
        assert!(store(root.path()).join(&pending.session).join("rolled-back.json").exists());
    }

    #[test]
    fn crash_during_rollback_is_resumable_by_rollback_and_by_the_original_writer() {
        const CHILD_ROOT: &str = "FRANKEN_ROLLBACK_CRASH_ROOT";
        const CHILD_ID: &str = "FRANKEN_ROLLBACK_CRASH_ID";
        const CHILD_COUNT: &str = "FRANKEN_ROLLBACK_CRASH_COUNT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            let id = std::env::var(CHILD_ID).unwrap();
            let count: usize = std::env::var(CHILD_COUNT).unwrap().parse().unwrap();
            let transaction = open_existing(&root).unwrap().unwrap();
            let selected = select(&transaction, &id, None, &mut JournalReader::new()).unwrap().unwrap();
            assert!(preflight(&transaction, &selected.journal).iter().all(|file| file.error.is_none()));
            transaction.publish_journal(&serde_json::to_vec(&selected.journal).unwrap()).unwrap();
            for record in selected.journal.records.iter().rev().take(count) {
                let (parent, name) = parent_and_name(&transaction.backups, &record.path, false).unwrap();
                let before = read_required(&parent, &name, MAX_FILE_BYTES).unwrap();
                transaction.replace_image(record, &record.after_sha256, record.after_bytes, &before.bytes).unwrap();
            }
            // Skip destructors and completion archival at real process exit.
            std::process::exit(73);
        }
        for (count, original_writer) in [(0, false), (1, false), (2, false), (1, true)] {
            let root = fixture();
            let id = applied(root.path());
            let path = module_path!().split_once("::").map_or("", |(_, path)| path);
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &format!("{path}::crash_during_rollback_is_resumable_by_rollback_and_by_the_original_writer")])
                .env(CHILD_ROOT, root.path()).env(CHILD_ID, &id).env(CHILD_COUNT, count.to_string())
                .output().unwrap();
            assert_eq!(output.status.code(), Some(73), "{}", String::from_utf8_lossy(&output.stderr));
            let preview = run(root.path(), Some(&id), false);
            assert_eq!(preview.status, RollbackStatus::Ready, "{preview:#?}");
            assert_eq!(preview.transaction.unwrap().state, TransactionState::RollbackPending);
            assert_eq!(preview.files.iter().filter(|file| file.preflight_state == SourceState::Original).count(), count);
            assert!(store(root.path()).join(PENDING).exists());
            if original_writer { drop(RewriteTransaction::open(root.path()).unwrap()); }
            else { assert_eq!(run(root.path(), Some(&id), true).status, RollbackStatus::RolledBack); }
            assert_source(root.path(), false);
            assert!(!store(root.path()).join(PENDING).exists());
        }
    }

    #[test]
    fn history_and_preview_respect_the_existing_writer_lock() {
        let root = fixture();
        let id = applied(root.path());
        let writer = RewriteTransaction::open(root.path()).unwrap();
        assert_eq!(run(root.path(), None, false).status, RollbackStatus::Error);
        assert_eq!(run(root.path(), Some(&id), true).status, RollbackStatus::Error);
        assert_source(root.path(), true);
        drop(writer);
        assert_eq!(run(root.path(), Some(&id), false).status, RollbackStatus::Ready);
    }

    #[test]
    fn already_restored_files_are_not_replaced_again() {
        let root = fixture();
        let id = applied(root.path());
        fs::write(root.path().join("b.js"), b"before-b-private").unwrap();
        let inode = fs::metadata(root.path().join("b.js")).unwrap().ino();
        let report = run(root.path(), Some(&id), true);
        assert_eq!(report.status, RollbackStatus::RolledBack);
        assert_eq!(report.files[1].preflight_state, SourceState::Original);
        assert_eq!(fs::metadata(root.path().join("b.js")).unwrap().ino(), inode);
        assert_source(root.path(), false);
    }

    #[test]
    fn repeated_apply_rollback_cycles_keep_history_and_never_undo_a_newer_apply() {
        let root = fixture();
        let first = applied(root.path());
        assert_eq!(run(root.path(), Some(&first), true).status, RollbackStatus::RolledBack);
        let second = applied(root.path());
        assert_ne!(first, second);
        assert_eq!(run(root.path(), Some(&first), true).status, RollbackStatus::AlreadyRolledBack);
        assert_source(root.path(), true);
        assert_eq!(run(root.path(), None, false).history.len(), 2);
        assert_eq!(run(root.path(), Some(&second), true).status, RollbackStatus::RolledBack);
        assert_source(root.path(), false);
    }

    #[test]
    fn oversized_journals_and_history_budgets_fail_without_source_changes() {
        let root = fixture();
        let id = applied(root.path());
        let store_handle = open_existing(root.path()).unwrap().unwrap();
        let session = directory(&store_handle.store, Path::new(&id), false).unwrap();
        assert!(JournalReader { remaining: 1 }.read(&session, "applied.json").is_err());
        drop(store_handle);
        fs::OpenOptions::new().write(true).open(store(root.path()).join(id).join("applied.json"))
            .unwrap().set_len(MAX_JOURNAL_BYTES as u64 + 1).unwrap();
        assert_eq!(run(root.path(), None, false).status, RollbackStatus::Error);
        assert_source(root.path(), true);
    }
}
