//! Durable frankensqlite-backed persistence adapter (bd-reality-20260820-w0fc6.3).
//!
//! [`DurableFrankensqliteAdapter`] is the file-backed counterpart of the
//! in-memory conformance model in
//! [`crate::storage::frankensqlite_adapter`]: same authorization matrix (the
//! model's `check_authorization` is reused verbatim), same bounds and
//! append-only audit semantics, but every committed write lands in a
//! WAL-durable database (`journal_mode=WAL`, `synchronous=FULL`) instead of a
//! `BTreeMap`.
//!
//! Durability contract (proven by the fleet transport's cross-process SIGABRT
//! test): only COMMITTED transactions survive process death on published
//! fsqlite 0.1.19 — bare statements ride the retained-autocommit overlay. So
//! every mutating operation here runs inside `transaction()` + `commit()`.
//!
//! Replay semantics: the `audit_journal` table records `(class, key,
//! sha256(value))` per Tier-1 append; `replay()` re-reads the live store and
//! constant-time-compares digests, flagging any mismatch, mirroring the
//! model's fail-closed replay contract.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
pub(crate) use crate::storage::frankensqlite_adapter::check_authorization;
pub use crate::storage::frankensqlite_adapter::{
    AdapterError, AdapterEvent, AdapterSummary, CallerContext, MAX_STORE_ENTRIES,
    MAX_STORE_KEY_BYTES, MAX_STORE_VALUE_BYTES, PersistenceClass, ReadResult, WriteResult,
};
use crate::storage::frankensqlite_adapter::{DurabilityTier, event_codes, sanitize_log_key};
use fsqlite::compat::TransactionExt;
use fsqlite::{Connection, SqliteValue};
use sha2::{Digest, Sha256};

const DURABLE_ADAPTER_SCHEMA_VERSION: i64 = 1;
const AUDIT_JOURNAL_TABLE: &str = "adapter_audit_journal";

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// File-backed adapter: the production persistence implementation.
pub struct DurableFrankensqliteAdapter {
    db_path: PathBuf,
    connection: Mutex<Option<Connection>>,
    events: Mutex<Vec<AdapterEvent>>,
    write_count: AtomicUsize,
    write_failures: AtomicUsize,
    reads_total: AtomicUsize,
    replay_count: AtomicUsize,
    replay_mismatches: AtomicUsize,
    writes_by_tier: Mutex<std::collections::BTreeMap<DurabilityTier, usize>>,
}

impl DurableFrankensqliteAdapter {
    /// Open (creating if needed) the durable store at `db_path`.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::ConfigValidationFailed`] when the database or
    /// its durability pragmas cannot be established.
    pub fn new(db_path: impl Into<PathBuf>) -> Result<Self, AdapterError> {
        let db_path = db_path.into();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                AdapterError::ConfigValidationFailed {
                    reason: format!("create adapter state dir {}: {err}", parent.display()),
                }
            })?;
        }
        let connection = Self::open_tier1(&db_path)?;
        let adapter = Self {
            db_path,
            connection: Mutex::new(Some(connection)),
            events: Mutex::new(Vec::new()),
            write_count: AtomicUsize::new(0),
            write_failures: AtomicUsize::new(0),
            reads_total: AtomicUsize::new(0),
            replay_count: AtomicUsize::new(0),
            replay_mismatches: AtomicUsize::new(0),
            writes_by_tier: Mutex::new(std::collections::BTreeMap::new()),
        };
        adapter.ensure_schema()?;
        Ok(adapter)
    }

    /// Open at the conventional project location
    /// `.franken-node/state/frankensqlite/telemetry.db` relative to the
    /// current working directory (CLI convention).
    ///
    /// # Errors
    ///
    /// Same as [`Self::new`].
    pub fn open_default() -> Result<Self, AdapterError> {
        let path = std::env::current_dir()
            .map_err(|err| AdapterError::ConfigValidationFailed {
                reason: format!("resolve cwd: {err}"),
            })?
            .join(".franken-node/state/frankensqlite/telemetry.db");
        Self::new(path)
    }

    /// Path of the underlying database file.
    #[must_use]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    fn open_tier1(db_path: &Path) -> Result<Connection, AdapterError> {
        let connection = Connection::open(db_path.to_string_lossy().as_ref()).map_err(|err| {
            AdapterError::ConfigValidationFailed {
                reason: format!("open {}: {err}", db_path.display()),
            }
        })?;
        for pragma in [
            "PRAGMA journal_mode=WAL;",
            "PRAGMA synchronous=FULL;",
            "PRAGMA busy_timeout=5000;",
        ] {
            connection
                .query(pragma)
                .map_err(|err| AdapterError::ConfigValidationFailed {
                    reason: format!("pragma {pragma}: {err}"),
                })?;
        }
        Ok(connection)
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, AdapterError>,
    ) -> Result<T, AdapterError> {
        let guard = self
            .connection
            .lock()
            .map_err(|_| AdapterError::WriteFailure {
                key: String::new(),
                reason: "adapter db mutex poisoned".to_string(),
            })?;
        let connection = guard.as_ref().ok_or_else(|| AdapterError::WriteFailure {
            key: String::new(),
            reason: "adapter db connection closed".to_string(),
        })?;
        operation(connection)
    }

    fn ensure_schema(&self) -> Result<(), AdapterError> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS adapter_store (
                        class TEXT NOT NULL,
                        key TEXT NOT NULL,
                        value BLOB NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (class, key)
                    );",
                )
                .map_err(|err| AdapterError::WriteFailure {
                    key: String::new(),
                    reason: format!("create adapter_store: {err}"),
                })?;
            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS adapter_audit_journal (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        class TEXT NOT NULL,
                        key TEXT NOT NULL UNIQUE,
                        value_sha256 TEXT NOT NULL,
                        recorded_at TEXT NOT NULL
                    );",
                )
                .map_err(|err| AdapterError::WriteFailure {
                    key: String::new(),
                    reason: format!("create adapter_audit_journal: {err}"),
                })?;
            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS adapter_schema_versions (
                        version INTEGER PRIMARY KEY,
                        applied_at TEXT NOT NULL,
                        description TEXT NOT NULL
                    );",
                )
                .map_err(|err| AdapterError::WriteFailure {
                    key: String::new(),
                    reason: format!("create adapter_schema_versions: {err}"),
                })?;
            connection
                .execute_with_params(
                    "INSERT INTO adapter_schema_versions(version, applied_at, description)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(version) DO NOTHING;",
                    &[
                        SqliteValue::Integer(DURABLE_ADAPTER_SCHEMA_VERSION),
                        SqliteValue::Text(now_rfc3339().into()),
                        SqliteValue::Text(
                            "initial durable adapter schema (WAL/FULL tier mapping)".into(),
                        ),
                    ],
                )
                .map_err(|err| AdapterError::WriteFailure {
                    key: String::new(),
                    reason: format!("seed schema version: {err}"),
                })?;
            Ok(())
        })
    }

    fn emit_event(&self, code: &str, class_label: &str, detail: String) {
        let mut events = match self.events.lock() {
            Ok(events) => events,
            Err(_) => return,
        };
        if events.len() >= MAX_AUDIT_LOG_ENTRIES {
            // Bounded ring: drop the oldest to keep memory bounded like the model.
            let excess = events.len().saturating_sub(MAX_AUDIT_LOG_ENTRIES) + 1;
            let _ = events.drain(..excess);
        }
        events.push(AdapterEvent {
            code: code.to_string(),
            persistence_class: class_label.to_string(),
            detail,
        });
    }

    fn record_failure(
        &self,
        class: PersistenceClass,
        key: &str,
        reason: impl Into<String>,
    ) -> AdapterError {
        let reason = reason.into();
        self.write_failures.fetch_add(1, Ordering::Relaxed);
        self.emit_event(
            event_codes::FRANKENSQLITE_WRITE_FAIL,
            class.label(),
            format!("key={}, {reason}", key),
        );
        AdapterError::WriteFailure {
            key: key.to_string(),
            reason,
        }
    }
}

/// The write/read backend surface shared by the in-memory conformance model
/// and the durable implementation, so telemetry can hold either behind one
/// type.
///
/// Deliberately NOT `Send`: the durable backend owns an fsqlite
/// [`fsqlite::Connection`], which is not `Send` on the published 0.1.19
/// line. Cross-thread users own the backend inside their worker thread.
pub trait AdapterWriteBackend {
    /// Authorize + durably persist one entry.
    ///
    /// # Errors
    ///
    /// Mirrors [`crate::storage::frankensqlite_adapter::FrankensqliteAdapter::write`].
    fn write(
        &mut self,
        caller: &CallerContext,
        class: PersistenceClass,
        key: &str,
        value: &[u8],
    ) -> Result<WriteResult, AdapterError>;

    /// Authorize + read one entry without creating it.
    ///
    /// # Errors
    ///
    /// Mirrors [`crate::storage::frankensqlite_adapter::FrankensqliteAdapter::read`].
    fn read(
        &mut self,
        caller: &CallerContext,
        class: PersistenceClass,
        key: &str,
    ) -> Result<ReadResult, AdapterError>;
}

/// The in-memory conformance model satisfies the same backend surface, so
/// telemetry and other `Send` contexts can hold the model while single-thread
/// owners (CLI, per-worker threads) use the durable backend directly.
impl AdapterWriteBackend for crate::storage::frankensqlite_adapter::FrankensqliteAdapter {
    fn write(
        &mut self,
        caller: &CallerContext,
        class: PersistenceClass,
        key: &str,
        value: &[u8],
    ) -> Result<WriteResult, AdapterError> {
        self.write(caller, class, key, value)
    }

    fn read(
        &mut self,
        caller: &CallerContext,
        class: PersistenceClass,
        key: &str,
    ) -> Result<ReadResult, AdapterError> {
        self.read(caller, class, key)
    }
}

impl AdapterWriteBackend for DurableFrankensqliteAdapter {
    fn write(
        &mut self,
        caller: &CallerContext,
        class: PersistenceClass,
        key: &str,
        value: &[u8],
    ) -> Result<WriteResult, AdapterError> {
        check_authorization(caller, "write", class).map_err(AdapterError::AuthorizationFailed)?;
        let start = Instant::now();
        let tier = class.tier();
        let class_label = class.label().to_string();

        if key.len() > MAX_STORE_KEY_BYTES {
            return Err(self.record_failure(
                class,
                key,
                format!(
                    "key length {} bytes exceeds maximum {MAX_STORE_KEY_BYTES}",
                    key.len()
                ),
            ));
        }
        if value.len() > MAX_STORE_VALUE_BYTES {
            return Err(self.record_failure(
                class,
                key,
                format!(
                    "value length {} bytes exceeds maximum {MAX_STORE_VALUE_BYTES}",
                    value.len()
                ),
            ));
        }

        let class_column = class.label().to_string();

        self.with_connection(|connection| {
            // Append-only audit semantics: duplicate AuditLog keys are a
            // contract violation, checked transactionally.
            let mut tx = connection
                .transaction()
                .map_err(|err| AdapterError::WriteFailure {
                    key: key.to_string(),
                    reason: format!("begin transaction: {err}"),
                })?;

            if matches!(class, PersistenceClass::AuditLog) {
                let existing = tx
                    .query_with_params(
                        "SELECT key FROM adapter_store WHERE class = ?1 AND key = ?2;",
                        &[
                            SqliteValue::Text(class_column.clone().into()),
                            SqliteValue::Text(key.to_string().into()),
                        ],
                    )
                    .map_err(|err| AdapterError::WriteFailure {
                        key: key.to_string(),
                        reason: format!("duplicate probe failed: {err}"),
                    })?;
                if !existing.is_empty() {
                    return Err(self.record_failure(
                        class,
                        key,
                        "duplicate audit log keys violate append-only semantics",
                    ));
                }
            }

            // Capacity: count rows for NEW keys before inserting.
            let count_rows = tx
                .query("SELECT COUNT(*) FROM adapter_store;")
                .map_err(|err| AdapterError::WriteFailure {
                    key: key.to_string(),
                    reason: format!("capacity probe failed: {err}"),
                })?;
            let current_count = match count_rows.first().and_then(|row| row.values().first()) {
                Some(SqliteValue::Integer(count)) => usize::try_from(*count).unwrap_or(usize::MAX),
                _ => 0,
            };
            if current_count >= MAX_STORE_ENTRIES {
                return Err(self.record_failure(
                    class,
                    key,
                    format!("store entry capacity {MAX_STORE_ENTRIES} reached for new key"),
                ));
            }

            tx.execute_with_params(
                "INSERT INTO adapter_store(class, key, value, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(class, key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at;",
                &[
                    SqliteValue::Text(class_column.clone().into()),
                    SqliteValue::Text(key.to_string().into()),
                    SqliteValue::Blob(value.to_vec().into()),
                    SqliteValue::Text(now_rfc3339().into()),
                ],
            )
            .map_err(|err| AdapterError::WriteFailure {
                key: key.to_string(),
                reason: format!("insert failed: {err}"),
            })?;

            if matches!(class, PersistenceClass::AuditLog) {
                let digest = Sha256::digest(value);
                tx.execute_with_params(
                    "INSERT INTO adapter_audit_journal(class, key, value_sha256, recorded_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(key) DO UPDATE SET
                        value_sha256 = excluded.value_sha256,
                        recorded_at = excluded.recorded_at;",
                    &[
                        SqliteValue::Text(class_column.into()),
                        SqliteValue::Text(key.to_string().into()),
                        SqliteValue::Text(hex::encode(digest).into()),
                        SqliteValue::Text(now_rfc3339().into()),
                    ],
                )
                .map_err(|err| AdapterError::WriteFailure {
                    key: key.to_string(),
                    reason: format!("journal insert failed: {err}"),
                })?;
            }

            // The commit is the durability boundary under WAL/FULL.
            tx.commit().map_err(|err| AdapterError::WriteFailure {
                key: key.to_string(),
                reason: format!("commit failed: {err}"),
            })?;
            Ok(())
        })?;

        let latency = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.write_count.fetch_add(1, Ordering::Relaxed);
        {
            let mut tier_writes = self
                .writes_by_tier
                .lock()
                .expect("adapter tier write counters lock");
            let updated = tier_writes.entry(tier).or_insert(0);
            *updated = updated.saturating_add(1);
        }
        self.emit_event(
            event_codes::FRANKENSQLITE_WRITE_SUCCESS,
            &class_label,
            format!(
                "key={}, tier={tier}, latency_us={latency}",
                sanitize_log_key(key)
            ),
        );

        Ok(WriteResult {
            success: true,
            key: key.to_string(),
            persistence_class: class,
            tier,
            latency_us: latency,
        })
    }

    fn read(
        &mut self,
        caller: &CallerContext,
        class: PersistenceClass,
        key: &str,
    ) -> Result<ReadResult, AdapterError> {
        check_authorization(caller, "read", class).map_err(AdapterError::AuthorizationFailed)?;
        self.reads_total.fetch_add(1, Ordering::Relaxed);
        let class_column = class.label().to_string();
        let tier = class.tier();
        let found_row = self.with_connection(|connection| {
            let rows = connection
                .query_with_params(
                    "SELECT value FROM adapter_store WHERE class = ?1 AND key = ?2;",
                    &[
                        SqliteValue::Text(class_column.into()),
                        SqliteValue::Text(key.to_string().into()),
                    ],
                )
                .map_err(|err| AdapterError::ReadFailure {
                    key: key.to_string(),
                    reason: format!("query failed: {err}"),
                })?;
            Ok(rows
                .first()
                .and_then(|row| row.values().first())
                .and_then(|value| match value {
                    SqliteValue::Blob(bytes) => Some(bytes.to_vec()),
                    _ => None,
                }))
        })?;
        let cache_hit = false;
        Ok(ReadResult {
            found: found_row.is_some(),
            key: key.to_string(),
            value: found_row,
            persistence_class: class,
            tier,
            cache_hit,
        })
    }
}

impl DurableFrankensqliteAdapter {
    /// Replay the audit journal against the live store.
    ///
    /// Returns `(key, ok)` pairs; any digest mismatch marks the gate
    /// fail-closed exactly like the in-memory model.
    /// # Errors
    ///
    /// Returns [`AdapterError::WriteFailure`] when the journal is unreadable.
    pub fn replay(&mut self) -> Result<Vec<(String, bool)>, AdapterError> {
        self.replay_count.fetch_add(1, Ordering::Relaxed);
        let pairs = self.with_connection(|connection| {
            let rows = connection
                .query(&format!(
                    "SELECT j.key, j.value_sha256, s.value
                     FROM {AUDIT_JOURNAL_TABLE} j
                     LEFT JOIN adapter_store s
                       ON s.class = j.class AND s.key = j.key
                     ORDER BY j.seq ASC;"
                ))
                .map_err(|err| AdapterError::WriteFailure {
                    key: String::new(),
                    reason: format!("replay query failed: {err}"),
                })?;
            let mut results = Vec::with_capacity(rows.len());
            for row in &rows {
                let values = row.values();
                let key = match values.first() {
                    Some(SqliteValue::Text(text)) => text.to_string(),
                    _ => continue,
                };
                let expected = match values.get(1) {
                    Some(SqliteValue::Text(text)) => text.to_string(),
                    _ => continue,
                };
                let actual = match values.get(2) {
                    Some(SqliteValue::Blob(bytes)) => hex::encode(Sha256::digest(bytes.as_ref())),
                    _ => String::new(),
                };
                let ok = constant_time_eq_hex(&expected, &actual);
                results.push((key, ok));
            }
            Ok(results)
        })?;
        let mismatches = pairs.iter().filter(|(_, ok)| !ok).count();
        self.replay_mismatches
            .fetch_add(mismatches, Ordering::Relaxed);
        if mismatches > 0 {
            self.emit_event(
                event_codes::FRANKENSQLITE_REPLAY_MISMATCH,
                "audit_log",
                format!("{mismatches} journal entries disagree with the store"),
            );
        } else {
            self.emit_event(
                event_codes::FRANKENSQLITE_REPLAY_START,
                "audit_log",
                format!("replayed {} journal entries cleanly", pairs.len()),
            );
        }
        Ok(pairs)
    }

    /// Count surviving Tier-1 keys after reopen (crash-recovery surface).
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::WriteFailure`] when the store cannot be read.
    pub fn crash_recovery(&mut self) -> Result<usize, AdapterError> {
        self.with_connection(|connection| {
            let table = connection
                .query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'adapter_store';")
                .map_err(|err| {
                    AdapterError::WriteFailure {
                        key: String::new(),
                        reason: format!("table probe failed: {err}"),
                    }
                })?;
            if table.is_empty() {
                return Ok(0);
            }
            let rows = connection
                .query(&format!(
                    "SELECT COUNT(*) FROM adapter_store WHERE class IN ('{}', '{}');",
                    PersistenceClass::ControlState.label(),
                    PersistenceClass::AuditLog.label(),
                ))
                .map_err(|err| {
                    AdapterError::WriteFailure {
                        key: String::new(),
                        reason: format!("count failed: {err}"),
                    }
                })?;
            let count = match rows.first().and_then(|row| row.values().first()) {
                Some(SqliteValue::Integer(value)) => usize::try_from(*value).unwrap_or(0),
                _ => 0,
            };
            Ok(count)
        })
    }

    /// Current persisted schema version.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::SchemaMigrationFailed`] when unreadable.
    pub fn schema_version(&self) -> Result<i64, AdapterError> {
        self.with_connection(|connection| {
            let table = connection
                .query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'adapter_schema_versions';")
                .map_err(|err| {
                    AdapterError::SchemaMigrationFailed {
                        version: 0,
                        reason: format!("table probe failed: {err}"),
                    }
                })?;
            if table.is_empty() {
                return Ok(0);
            }
            let rows = connection
                .query("SELECT COALESCE(MAX(version), 0) FROM adapter_schema_versions;")
                .map_err(|err| {
                    AdapterError::SchemaMigrationFailed {
                        version: 0,
                        reason: format!("version query failed: {err}"),
                    }
                })?;
            match rows.first().and_then(|row| row.values().first()) {
                Some(SqliteValue::Integer(version)) => Ok(*version),
                _ => Ok(0),
            }
        })
    }

    /// Monotonic schema migration; rejects versions <= current.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::SchemaMigrationFailed`] for non-monotonic or
    /// out-of-range versions.
    pub fn migrate(&mut self, version: i64, description: &str) -> Result<(), AdapterError> {
        let current = self.schema_version()?;
        let version_u32 = u32::try_from(version).unwrap_or(u32::MAX);
        if version <= current {
            return Err(AdapterError::SchemaMigrationFailed {
                version: version_u32,
                reason: format!("migration must be monotonic; current version is {current}"),
            });
        }
        self.with_connection(|connection| {
            let mut tx =
                connection
                    .transaction()
                    .map_err(|err| AdapterError::SchemaMigrationFailed {
                        version: version_u32,
                        reason: format!("begin transaction: {err}"),
                    })?;
            tx.execute_with_params(
                "INSERT INTO adapter_schema_versions(version, applied_at, description)
                 VALUES (?1, ?2, ?3);",
                &[
                    SqliteValue::Integer(version),
                    SqliteValue::Text(now_rfc3339().into()),
                    SqliteValue::Text(description.to_string().into()),
                ],
            )
            .map_err(|err| AdapterError::SchemaMigrationFailed {
                version: version_u32,
                reason: format!("insert failed: {err}"),
            })?;
            tx.commit()
                .map_err(|err| AdapterError::SchemaMigrationFailed {
                    version: version_u32,
                    reason: format!("commit failed: {err}"),
                })
        })
    }

    /// Aggregate counters over the durable store's lifetime in this process.
    #[must_use]
    pub fn summary(&self) -> AdapterSummary {
        let writes_by_tier: std::collections::BTreeMap<String, usize> = self
            .writes_by_tier
            .lock()
            .expect("adapter tier write counters lock")
            .iter()
            .map(|(tier, count)| (tier.label().to_string(), *count))
            .collect();
        AdapterSummary {
            total_writes: self.write_count.load(Ordering::Relaxed),
            total_reads: self.reads_total.load(Ordering::Relaxed),
            write_failures: self.write_failures.load(Ordering::Relaxed),
            replay_count: self.replay_count.load(Ordering::Relaxed),
            replay_mismatches: self.replay_mismatches.load(Ordering::Relaxed),
            audit_log_truncated: false,
            writes_by_tier,
            schema_version: u32::try_from(self.schema_version().unwrap_or(0)).unwrap_or(u32::MAX),
        }
    }

    /// Drain recorded events (bounded like the model's window).
    pub fn take_events(&self) -> Vec<AdapterEvent> {
        let mut events = self.events.lock().expect("adapter events lock");
        std::mem::take(&mut *events)
    }
}

fn constant_time_eq_hex(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    left.as_bytes().ct_eq(right.as_bytes()).into()
}
