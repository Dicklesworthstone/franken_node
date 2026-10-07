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

use ed25519_dalek::SigningKey;
use fsqlite::compat::TransactionExt;
use fsqlite::{Connection, SqliteValue};

use crate::observability::evidence_ledger::{
    EvidenceEntry, evidence_entry_hash_hex, sign_chained_evidence_entry,
};

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
    // Opening an up-to-date store must not write: every `run` opens the
    // ledger, and a committed schema write costs a synchronous=FULL commit
    // (an fsync) before the entry's own commit.
    if schema_is_current(connection) {
        return Ok(());
    }
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

/// Whether both tables exist and the recorded schema version is current. A
/// missing table or any read error answers `false`, so `ensure_schema` runs.
fn schema_is_current(connection: &Connection) -> bool {
    let Ok(rows) = connection.query_with_params(
        "SELECT value FROM evidence_meta WHERE key = ?1;",
        &[SqliteValue::Text(META_KEY_SCHEMA_VERSION.into())],
    ) else {
        return false;
    };
    let version_is_current = matches!(
        rows.first().and_then(|row| row.values().first()),
        Some(SqliteValue::Text(version)) if version.to_string() == EVIDENCE_DB_SCHEMA_VERSION
    );
    version_is_current
        && connection
            .query(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'evidence_entries';",
            )
            .is_ok_and(|rows| !rows.is_empty())
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

    /// Link `entry` to the newest stored entry (`prev_entry_hash`), sign its
    /// contents and exact predecessor with the `chain-v1` contract, and append
    /// it, all inside one committed transaction so concurrent appenders cannot
    /// fork the chain. Returns the entry as stored. Existing legacy entries
    /// remain unchanged and individually verifiable; appending does not upgrade
    /// their unauthenticated predecessor links.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the newest stored row is not an evidence
    /// entry, or the transaction fails.
    pub fn append_signed_chained(
        &self,
        mut entry: EvidenceEntry,
        signing_key: &SigningKey,
    ) -> io::Result<EvidenceEntry> {
        self.with_connection(|connection| {
            let mut tx = connection
                .transaction()
                .map_err(|err| io::Error::other(format!("begin entry transaction: {err}")))?;
            let rows = connection
                .query("SELECT entry_json FROM evidence_entries ORDER BY seq DESC LIMIT 1;")
                .map_err(|err| io::Error::other(format!("read chain head: {err}")))?;
            entry.prev_entry_hash = match rows.first().map(|row| row.values().first()) {
                Some(Some(SqliteValue::Text(previous_json))) => {
                    let previous: EvidenceEntry = serde_json::from_str(previous_json.as_ref())
                        .map_err(|err| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("newest stored row is not an evidence entry: {err}"),
                            )
                        })?;
                    evidence_entry_hash_hex(&previous)
                }
                None => String::new(),
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "newest stored row is not a text evidence entry; refusing to reset the chain",
                    ));
                }
            };
            sign_chained_evidence_entry(&mut entry, signing_key);
            let entry_json = serde_json::to_string(&entry)
                .map_err(|err| io::Error::other(format!("encode entry: {err}")))?;
            tx.execute_with_params(
                "INSERT INTO evidence_entries(recorded_at, entry_json) VALUES (?1, ?2);",
                &[
                    SqliteValue::Text(chrono::Utc::now().to_rfc3339().into()),
                    SqliteValue::Text(entry_json.into()),
                ],
            )
            .map_err(|err| io::Error::other(format!("insert entry: {err}")))?;
            tx.commit()
                .map_err(|err| io::Error::other(format!("commit entry: {err}")))?;
            Ok(entry)
        })
    }

    /// Every stored entry payload, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the store cannot be read.
    pub fn entries_json(&self) -> io::Result<Vec<String>> {
        self.with_connection(|connection| {
            let rows = connection
                .query("SELECT entry_json FROM evidence_entries ORDER BY seq ASC;")
                .map_err(|err| io::Error::other(format!("read entries: {err}")))?;
            Ok(rows
                .iter()
                .filter_map(|row| match row.values().first() {
                    Some(SqliteValue::Text(json)) => Some(json.to_string()),
                    _ => None,
                })
                .collect())
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
            // bd-o776s: carry the offending payload in the error so a failed
            // commit is diagnosable from the panic/assert site alone.
            self.ledger.append_json(entry_json).map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!("evidence sink rejected entry {entry_json:?}: {err}"),
                )
            })?;
            self.committed_entries += 1;
        }
        Ok(())
    }
}

impl Write for DurableEvidenceSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        eprintln!(
            "DBG sink.write len={} newline_in_buf={}",
            buf.len(),
            buf.contains(&b'\n')
        );
        self.buffer.extend_from_slice(buf);
        self.commit_complete_lines()?;
        eprintln!(
            "DBG after commit: buffered={} committed={}",
            self.buffer.len(),
            self.committed_entries
        );
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
    use crate::observability::evidence_ledger::{
        evidence_entry_has_chained_signature, sign_evidence_entry, test_entry,
        verify_evidence_entry,
    };

    fn temp_state_dir(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join(format!("{tag}-state"));
        (dir, state_dir)
    }

    #[test]
    fn chained_append_authenticates_persisted_predecessors_and_preserves_opaque_payloads() {
        let (_dir, state_dir) = temp_state_dir("chained-signatures");
        let signing_key = SigningKey::from_bytes(&[0xA7; 32]);
        let verifying_key = signing_key.verifying_key();
        let ledger = DurableEvidenceLedger::open(&state_dir).expect("open durable chain");
        let payloads = [
            serde_json::Value::Null,
            serde_json::json!(["opaque", 42, true]),
            serde_json::json!({"receipt_id": "run-c", "nested": {"denied": true}}),
        ];
        let mut previous_hash = String::new();
        let mut expected_entries = Vec::new();
        for (index, payload) in payloads.iter().enumerate() {
            let mut entry = test_entry(
                &format!("DURABLE-CHAIN-{index}"),
                u64::try_from(index + 1).expect("small fixture epoch"),
            );
            entry.payload = payload.clone();
            entry.prev_entry_hash =
                "caller cannot select the transaction's predecessor".to_string();
            let stored = ledger
                .append_signed_chained(entry, &signing_key)
                .expect("append transaction signs its chosen predecessor");
            assert_eq!(stored.prev_entry_hash, previous_hash);
            assert_eq!(&stored.payload, payload);
            assert!(evidence_entry_has_chained_signature(&stored));
            verify_evidence_entry(&stored, &verifying_key).expect("durable chained signature");
            previous_hash = evidence_entry_hash_hex(&stored);
            expected_entries.push(stored);
        }
        drop(ledger);

        let reopened = DurableEvidenceLedger::open(&state_dir).expect("reopen committed chain");
        let persisted = reopened
            .entries_json()
            .expect("read committed chain")
            .iter()
            .map(|row| serde_json::from_str::<EvidenceEntry>(row).expect("decode committed entry"))
            .collect::<Vec<_>>();
        assert_eq!(persisted, expected_entries);
        for entry in &persisted {
            verify_evidence_entry(entry, &verifying_key).expect("signature survives reopen");
        }

        let mut relinked_successor = persisted[2].clone();
        relinked_successor.prev_entry_hash = evidence_entry_hash_hex(&persisted[0]);
        assert!(
            verify_evidence_entry(&relinked_successor, &verifying_key).is_err(),
            "deleting the persisted middle entry cannot be hidden by relinking its successor"
        );
    }

    #[test]
    fn chained_append_does_not_resign_or_upgrade_existing_legacy_entries() {
        let (_dir, state_dir) = temp_state_dir("legacy-chain-boundary");
        let signing_key = SigningKey::from_bytes(&[0xB8; 32]);
        let verifying_key = signing_key.verifying_key();
        let ledger = DurableEvidenceLedger::open(&state_dir).expect("open durable chain");
        let mut legacy = test_entry("LEGACY-RETAINED", 1);
        sign_evidence_entry(&mut legacy, &signing_key);
        let legacy_json = serde_json::to_string(&legacy).expect("encode legacy entry");
        ledger
            .append_json(&legacy_json)
            .expect("retain existing legacy row");

        let appended = ledger
            .append_signed_chained(test_entry("BOUND-AFTER-LEGACY", 2), &signing_key)
            .expect("append a bound successor");
        assert_eq!(appended.prev_entry_hash, evidence_entry_hash_hex(&legacy));
        assert!(evidence_entry_has_chained_signature(&appended));
        verify_evidence_entry(&appended, &verifying_key)
            .expect("new successor authenticates parent");
        let rows = ledger.entries_json().expect("read mixed-version rows");
        assert_eq!(
            rows[0], legacy_json,
            "the earlier row is not silently re-signed"
        );
        assert!(!evidence_entry_has_chained_signature(&legacy));
        verify_evidence_entry(&legacy, &verifying_key).expect("legacy contents remain verifiable");
    }

    #[test]
    fn chained_append_refuses_an_unreadable_head_without_minting_a_new_genesis() {
        let (_dir, state_dir) = temp_state_dir("corrupted-chain-head");
        let signing_key = SigningKey::from_bytes(&[0xC9; 32]);
        let ledger = DurableEvidenceLedger::open(&state_dir).expect("open durable chain");
        ledger
            .append_signed_chained(test_entry("ORIGINAL-GENESIS", 1), &signing_key)
            .expect("append original signed genesis");
        ledger
            .with_connection(|connection| {
                let mut tx = connection.transaction().map_err(|error| {
                    io::Error::other(format!("begin corrupt-head fixture: {error}"))
                })?;
                tx.execute_batch("UPDATE evidence_entries SET entry_json = X'00';")
                    .map_err(|error| {
                        io::Error::other(format!("write corrupt-head fixture: {error}"))
                    })?;
                tx.commit().map_err(|error| {
                    io::Error::other(format!("commit corrupt-head fixture: {error}"))
                })
            })
            .expect("store an actual non-Text BLOB as the newest row");
        let rows_before = ledger.count().expect("count corrupt-head rows");
        assert_eq!(rows_before, 1);
        assert!(
            ledger
                .entries_json()
                .expect("read stored BLOB fixture")
                .is_empty(),
            "the stored BLOB is not exposed as a Text entry"
        );

        let error = ledger
            .append_signed_chained(test_entry("REFUSED-NEW-GENESIS", 2), &signing_key)
            .expect_err("a present unreadable head cannot become an empty predecessor");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("refusing to reset the chain"));
        assert_eq!(
            ledger.count().expect("count rows after refused append"),
            rows_before,
            "the refused append must not mint or persist another signed genesis"
        );
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

        eprintln!(
            "DBG sink_db={:?} sink_ledger_count={:?}",
            sink.ledger().db_path(),
            sink.ledger().count()
        );
        let ledger = DurableEvidenceLedger::open_default(&state_dir).expect("reopen");
        eprintln!(
            "DBG reopen_db={:?} reopen_count={}",
            ledger.db_path(),
            ledger.count().unwrap_or(u64::MAX)
        );
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
        let ledger = DurableEvidenceLedger::open_default(&state_dir).expect("reopen");
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
        let ledger = DurableEvidenceLedger::open_default(&state_dir).expect("reopen");
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
        // bd-rjc2m.7: the sink nests under <project>/.franken-node/state, so
        // drive it with a project root and count from the resulting state dir.
        let mut sink = DurableEvidenceSink::open_default(dir.path()).expect("open sink");
        sink.write_all(br#"{"decision_id":"DEC-004"}"#)
            .expect("json");
        sink.write_all(b"\n").expect("newline");
        assert_eq!(
            count_durable_entries(&state_dir).expect("store present"),
            Some(1)
        );
    }
}
