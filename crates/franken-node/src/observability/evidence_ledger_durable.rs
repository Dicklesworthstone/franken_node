//! Durable frankensqlite-backed sink for evidence-ledger entries
//! (bd-reality-20260820-w0fc6.3).
//!
//! [`crate::observability::evidence_ledger`] keeps a bounded in-memory ring
//! buffer whose only previous durable escape was lab-mode JSONL spill. This
//! module provides the production sink: every spilled entry line lands in a
//! WAL-database (`journal_mode=WAL`, `synchronous=FULL`) inside an explicit
//! committed transaction, because on published fsqlite 0.1.19 only COMMITTED
//! transactions survive process death (the retained-autocommit overlay dies
//! with the process — proven by the fleet transport's cross-process SIGABRT
//! test).
//!
//! Framing contract: the sink implements [`std::io::Write`], so it plugs into
//! `LabSpillMode::new`'s generic-writer slot unchanged. Spill writes emit one
//! compact JSON object per entry followed by `\n`; the sink buffers incoming
//! fragments and commits exactly one row per completed line, preserving the
//! append order. A trailing fragment without a newline is not an entry and is
//! discarded when the writer closes.
//!
//! Legacy migration: the historical spill files under `.franken-node/state/`
//! remain readable exactly once via
//! [`DurableEvidenceLedger::import_legacy_spill`]; deleting the database rolls
//! back to them.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fsqlite::compat::TransactionExt;
use fsqlite::{Connection, SqliteValue};

/// Historical spill-file candidates, oldest convention first. Shared with the
/// ops metrics readers so legacy counting and one-time import agree.
pub const LEGACY_SPILL_FILE_CANDIDATES: &[&str] = &[
    "evidence_spill.jsonl",
    "durable_evidence_spill.jsonl",
    "spill.jsonl",
];

const EVIDENCE_DB_FILE: &str = "evidence-ledger.db";
const EVIDENCE_DB_SCHEMA_VERSION: &str = "franken-node/evidence-ledger-durable-store/v1";
const META_KEY_SCHEMA_VERSION: &str = "schema_version";
const META_KEY_LEGACY_SPILL_IMPORT: &str = "legacy_spill_import";
const BUSY_TIMEOUT_MILLIS: u64 = 5_000;

/// Database path backing the state directory's evidence ledger.
#[must_use]
pub fn durable_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join(EVIDENCE_DB_FILE)
}

fn open_tier1_connection(db_path: &Path) -> io::Result<Connection> {
    let connection = Connection::open(db_path.to_string_lossy().as_ref())
        .map_err(|err| io::Error::other(format!("open {}: {err}", db_path.display())))?;
    for pragma in [
        "PRAGMA journal_mode=WAL;",
        "PRAGMA synchronous=FULL;",
        format!("PRAGMA busy_timeout={BUSY_TIMEOUT_MILLIS};").as_str(),
    ] {
        connection
            .query(pragma)
            .map_err(|err| io::Error::other(format!("pragma {pragma}: {err}")))?;
    }
    Ok(connection)
}

fn ensure_schema(connection: &Connection) -> io::Result<()> {
    let mut tx = connection
        .transaction()
        .map_err(|err| io::Error::other(format!("begin schema transaction: {err}")))?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS evidence_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence_entries (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            recorded_at TEXT NOT NULL,
            entry_json TEXT NOT NULL
        );",
    )
    .map_err(|err| io::Error::other(format!("ensure schema: {err}")))?;
    tx.execute_with_params(
        "INSERT INTO evidence_meta(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        &[
            SqliteValue::Text(META_KEY_SCHEMA_VERSION.into()),
            SqliteValue::Text(EVIDENCE_DB_SCHEMA_VERSION.into()),
        ],
    )
    .map_err(|err| io::Error::other(format!("record schema version: {err}")))?;
    tx.commit()
        .map_err(|err| io::Error::other(format!("commit schema: {err}")))
}

/// Durable WAL-backed evidence ledger store.
pub struct DurableEvidenceLedger {
    db_path: PathBuf,
    state_dir: PathBuf,
    connection: Mutex<Option<Connection>>,
}

impl DurableEvidenceLedger {
    /// Open (creating if needed) the durable store under `state_dir`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the directory or database cannot be opened
    /// with the Tier-1 durability pragmas.
    pub fn open(state_dir: impl Into<PathBuf>) -> io::Result<Self> {
        let state_dir = state_dir.into();
        std::fs::create_dir_all(&state_dir)?;
        let db_path = durable_store_path(&state_dir);
        let connection = open_tier1_connection(&db_path)?;
        ensure_schema(&connection)?;
        Ok(Self {
            db_path,
            state_dir,
            connection: Mutex::new(Some(connection)),
        })
    }

    /// Conventional project location `.franken-node/state/` under `project_root`.
    ///
    /// # Errors
    ///
    /// Same as [`Self::open`].
    pub fn open_default(project_root: &Path) -> io::Result<Self> {
        Self::open(project_root.join(".franken-node/state"))
    }

    /// Path of the underlying database file.
    #[must_use]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Append one already-encoded entry payload durably.
    ///
    /// The payload must be valid JSON; it is stored verbatim so readers can
    /// reconstruct byte-stable entries. Each call commits one transaction.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the payload is not valid UTF-8 JSON or the
    /// transaction fails.
    pub fn append_json(&self, entry_json: &str) -> io::Result<()> {
        if serde_json::from_str::<serde_json::Value>(entry_json).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "evidence entry payload is not valid JSON",
            ));
        }
        self.with_connection(|connection| {
            let mut tx = connection
                .transaction()
                .map_err(|err| io::Error::other(format!("begin entry transaction: {err}")))?;
            tx.execute_with_params(
                "INSERT INTO evidence_entries(recorded_at, entry_json) VALUES (?1, ?2);",
                &[
                    SqliteValue::Text(chrono::Utc::now().to_rfc3339().into()),
                    SqliteValue::Text(entry_json.to_string().into()),
                ],
            )
            .map_err(|err| io::Error::other(format!("insert entry: {err}")))?;
            tx.commit()
                .map_err(|err| io::Error::other(format!("commit entry: {err}")))
        })
    }

    /// Number of durably stored entries.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the store cannot be read.
    pub fn count(&self) -> io::Result<u64> {
        self.with_connection(|connection| {
            let rows = connection
                .query("SELECT COUNT(*) FROM evidence_entries;")
                .map_err(|err| io::Error::other(format!("count entries: {err}")))?;
            Ok(rows
                .first()
                .and_then(|row| row.values().first())
                .and_then(|value| match value {
                    SqliteValue::Integer(count) => u64::try_from(*count).ok(),
                    _ => None,
                })
                .unwrap_or(0))
        })
    }

    /// Newest stored `recorded_at` timestamp, if any entries exist.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the store cannot be read.
    pub fn latest_recorded_at(&self) -> io::Result<Option<String>> {
        self.with_connection(|connection| {
            let rows = connection
                .query("SELECT MAX(recorded_at) FROM evidence_entries;")
                .map_err(|err| io::Error::other(format!("latest timestamp: {err}")))?;
            Ok(rows
                .first()
                .and_then(|row| row.values().first())
                .and_then(|value| match value {
                    SqliteValue::Text(text) => Some(text.to_string()),
                    _ => None,
                }))
        })
    }

    /// Import legacy JSONL spill files once, guarded by a meta marker.
    ///
    /// Files are read in [`LEGACY_SPILL_FILE_CANDIDATES`] order and their
    /// non-empty lines inserted in order, one transaction per line so a crash
    /// mid-import resumes instead of duplicating.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a readable line is not valid UTF-8 JSON or a
    /// transaction fails.
    pub fn import_legacy_spill(&self) -> io::Result<u64> {
        let already_imported = self.meta_marker_set(META_KEY_LEGACY_SPILL_IMPORT)?;
        if already_imported {
            return Ok(0);
        }
        let mut imported = 0_u64;
        for candidate in LEGACY_SPILL_FILE_CANDIDATES {
            let path = self.state_dir.join(candidate);
            if !path.is_file() {
                continue;
            }
            let raw = std::fs::read_to_string(&path)
                .map_err(|err| io::Error::other(format!("read {}: {err}", path.display())))?;
            for line in raw.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                self.append_json(line)?;
                imported += 1;
            }
        }
        self.set_meta_marker(META_KEY_LEGACY_SPILL_IMPORT, &format!("{imported} records"))?;
        Ok(imported)
    }

    fn meta_marker_set(&self, key: &str) -> io::Result<bool> {
        self.with_connection(|connection| {
            let rows = connection
                .query_with_params(
                    "SELECT value FROM evidence_meta WHERE key = ?1;",
                    &[SqliteValue::Text(key.to_string().into())],
                )
                .map_err(|err| io::Error::other(err.to_string()))?;
            Ok(!rows.is_empty())
        })
    }

    fn set_meta_marker(&self, key: &str, value: &str) -> io::Result<()> {
        self.with_connection(|connection| {
            let mut tx = connection
                .transaction()
                .map_err(|err| io::Error::other(err.to_string()))?;
            tx.execute_with_params(
                "INSERT INTO evidence_meta(key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                &[
                    SqliteValue::Text(key.to_string().into()),
                    SqliteValue::Text(value.to_string().into()),
                ],
            )
            .map_err(|err| io::Error::other(err.to_string()))?;
            tx.commit().map_err(|err| io::Error::other(err.to_string()))
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> io::Result<T>,
    ) -> io::Result<T> {
        let guard = self
            .connection
            .lock()
            .map_err(|_| io::Error::other("durable evidence ledger mutex poisoned"))?;
        let connection = guard
            .as_ref()
            .ok_or_else(|| io::Error::other("durable evidence ledger connection closed"))?;
        operation(connection)
    }
}

/// [`io::Write`] adapter committing each newline-framed entry line durably.
///
/// Compatible with `LabSpillMode::new`'s `Box<dyn Write + Send>` spill slot:
/// serde may split one entry across several `write` calls, so fragments are
/// buffered until a complete `\n`-terminated line arrives, validated as JSON,
/// and committed as one row.
pub struct DurableEvidenceSink {
    ledger: DurableEvidenceLedger,
    buffer: Vec<u8>,
    committed_entries: u64,
}

impl DurableEvidenceSink {
    /// Open the conventional project location for the sink.
    ///
    /// # Errors
    ///
    /// Same as [`DurableEvidenceLedger::open_default`].
    pub fn open_default(project_root: &Path) -> io::Result<Self> {
        Ok(Self {
            ledger: DurableEvidenceLedger::open_default(project_root)?,
            buffer: Vec::new(),
            committed_entries: 0,
        })
    }

    /// Entries durably committed through this sink so far.
    #[must_use]
    pub fn committed_entries(&self) -> u64 {
        self.committed_entries
    }

    /// Borrow the underlying durable store (read-side surface).
    #[must_use]
    pub const fn ledger(&self) -> &DurableEvidenceLedger {
        &self.ledger
    }

    fn commit_complete_lines(&mut self) -> io::Result<()> {
        while let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=newline).collect();
            let payload = &line[..line.len() - 1];
            if payload.iter().all(|byte| byte.is_ascii_whitespace()) {
                continue;
            }
            let entry_json = std::str::from_utf8(payload)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
                .trim_end_matches('\r');
            self.ledger.append_json(entry_json)?;
            self.committed_entries += 1;
        }
        Ok(())
    }
}

impl Write for DurableEvidenceSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        self.commit_complete_lines()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Every completed line was already committed; flush is a no-op kept
        // for callers that treat the writer like a buffered file.
        Ok(())
    }
}

impl Drop for DurableEvidenceSink {
    fn drop(&mut self) {
        // A trailing fragment without a newline never formed an entry; drop it
        // rather than committing a torn record.
    }
}

/// Count durably stored entries when the store exists.
///
/// Returns `Ok(None)` when no database exists yet, letting callers fall back
/// to legacy spill counting.
///
/// # Errors
///
/// Returns an I/O error when the database exists but cannot be read.
pub fn count_durable_entries(state_dir: &Path) -> io::Result<Option<u64>> {
    let db_path = durable_store_path(state_dir);
    if !db_path.is_file() {
        return Ok(None);
    }
    let ledger = DurableEvidenceLedger::open(state_dir)?;
    Ok(Some(ledger.count()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_dir(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join(format!("{tag}-state"));
        (dir, state_dir)
    }

    #[test]
    fn sink_commits_each_completed_line_durably() {
        let (_dir, state_dir) = temp_state_dir("commit-lines");
        let mut sink = DurableEvidenceSink::open_default(&state_dir).expect("open sink");

        // One entry fragmented across three write calls, plus a second entry
        // in two calls: both must land exactly once, in order.
        sink.write_all(br#"{"decision_id":"DEC-001""#)
            .expect("fragment 1");
        assert_eq!(
            sink.committed_entries(),
            0,
            "incomplete line must not commit"
        );
        sink.write_all(b",\"trace_id\":\"t-1\"}")
            .expect("fragment 2");
        sink.write_all(b"\n").expect("newline");
        assert_eq!(sink.committed_entries(), 1);
        sink.write_all(br#"{"decision_id":"DEC-002"}"#)
            .expect("entry 2 json");
        sink.write_all(b"\n").expect("entry 2 newline");
        assert_eq!(sink.committed_entries(), 2);

        let ledger = DurableEvidenceLedger::open(&state_dir).expect("reopen");
        assert_eq!(ledger.count().expect("count"), 2);
        assert!(ledger.latest_recorded_at().expect("latest").is_some());
    }

    #[test]
    fn sink_rejects_invalid_json_lines_and_keeps_counting() {
        let (_dir, state_dir) = temp_state_dir("invalid-json");
        let mut sink = DurableEvidenceSink::open_default(&state_dir).expect("open sink");
        sink.write_all(b"{not-json\n")
            .expect_err("invalid JSON must fail");
        sink.write_all(br#"{"ok":true}"#).expect("valid entry");
        sink.write_all(b"\n").expect("newline");
        assert_eq!(sink.committed_entries(), 1);
        let ledger = DurableEvidenceLedger::open(&state_dir).expect("reopen");
        assert_eq!(ledger.count().expect("count"), 1);
    }

    #[test]
    fn trailing_fragment_without_newline_is_not_committed() {
        let (_dir, state_dir) = temp_state_dir("trailing");
        {
            let mut sink = DurableEvidenceSink::open_default(&state_dir).expect("open sink");
            sink.write_all(br#"{"decision_id":"DEC-003"}"#)
                .expect("write without newline");
        }
        let ledger = DurableEvidenceLedger::open(&state_dir).expect("reopen");
        assert_eq!(ledger.count().expect("count"), 0);
    }

    #[test]
    fn legacy_spill_import_is_one_time_and_ordered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join(".franken-node/state");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        std::fs::write(
            state_dir.join("evidence_spill.jsonl"),
            "{\"n\":1}\n{\"n\":2}\n",
        )
        .expect("write first spill");
        std::fs::write(state_dir.join("spill.jsonl"), "{\"n\":3}\n").expect("write second spill");

        let ledger = DurableEvidenceLedger::open(&state_dir).expect("open");
        let imported = ledger.import_legacy_spill().expect("first import");
        assert_eq!(imported, 3);
        assert_eq!(ledger.import_legacy_spill().expect("second import"), 0);
        assert_eq!(ledger.count().expect("count"), 3);
    }

    #[test]
    fn durable_count_prefers_store_presence_over_legacy_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join(".franken-node/state");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        assert_eq!(
            count_durable_entries(&state_dir).expect("no store yet"),
            None,
            "missing database must signal legacy fallback"
        );

        let mut sink = DurableEvidenceSink::open_default(&state_dir).expect("open sink");
        sink.write_all(br#"{"decision_id":"DEC-004"}"#)
            .expect("json");
        sink.write_all(b"\n").expect("newline");
        assert_eq!(
            count_durable_entries(&state_dir).expect("store present"),
            Some(1)
        );
    }
}
