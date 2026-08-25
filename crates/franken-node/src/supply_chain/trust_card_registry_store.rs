//! Durable frankensqlite-backed trust-card registry store
//! (bd-reality-20260820-w0fc6.3).
//!
//! The authoritative home for the canonical trust-card registry snapshot and
//! its signed high-water marker is now a WAL-database under the state
//! directory instead of `trust-card-registry.v1.json` +
//! `trust-card-registry.v1.json.high-water.json`. This mirrors
//! [`crate::control_plane::fleet_transport_durable`]: the connection runs
//! `journal_mode=WAL` with `synchronous=FULL`, so a committed transaction is
//! the durability boundary (Tier-1 semantics of
//! `docs/specs/frankensqlite_persistence_contract.md`). A bare statement can
//! sit in fsqlite 0.1.19's retained autocommit overlay and die with the
//! process, so every mutation here goes through an explicit committed
//! transaction.
//!
//! Deliberate divergences from the legacy two-file layout:
//! * snapshot and high-water rows are updated inside ONE transaction, so the
//!   pair can no longer tear apart across a crash between the two files;
//! * cross-process writer serialization comes from SQLite locking plus a busy
//!   timeout instead of the ad-hoc flock sidecar file;
//! * the legacy JSON pair remains readable exactly once as a one-time import
//!   source (`import_legacy_state`); deleting the database rolls back to it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fsqlite::compat::TransactionExt;
use fsqlite::{Connection, SqliteValue};

use crate::supply_chain::trust_card::TrustCardError;

const REGISTRY_DB_SCHEMA_VERSION: &str = "franken-node/trust-card-registry-durable-store/v1";
const META_KEY_SCHEMA_VERSION: &str = "schema_version";
const META_KEY_LEGACY_JSON_IMPORT: &str = "legacy_json_import";
pub(crate) const SLOT_SNAPSHOT: &str = "snapshot";
pub(crate) const SLOT_HIGH_WATER: &str = "high_water";
const BUSY_TIMEOUT_MILLIS: u64 = 5_000;

/// Path of the durable database backing the snapshot file at `snapshot_path`.
///
/// The database lives next to the legacy JSON location so operators find it
/// where they already look: `state/trust-card-registry.v1.json` becomes
/// `state/trust-card-registry.v1.db`.
#[must_use]
pub fn durable_store_path(snapshot_path: &Path) -> PathBuf {
    snapshot_path.with_extension("db")
}

/// Read one canonical-JSON slot out of an open connection.
pub(crate) fn read_slot(
    connection: &Connection,
    slot: &str,
) -> Result<Option<String>, TrustCardError> {
    let rows = connection
        .query_with_params(
            "SELECT canonical_json FROM registry_state WHERE slot = ?1;",
            &[SqliteValue::Text(slot.into())],
        )
        .map_err(|err| TrustCardError::SnapshotRead {
            path: PathBuf::from("trust-card-registry-durable-store"),
            detail: format!("read slot {slot}: {err}"),
        })?;
    match rows.first() {
        None => Ok(None),
        Some(row) => {
            let value = row
                .values()
                .first()
                .ok_or_else(|| TrustCardError::SnapshotRead {
                    path: PathBuf::from("trust-card-registry-durable-store"),
                    detail: format!("slot {slot}: missing canonical_json column"),
                })?;
            let SqliteValue::Text(encoded) = value else {
                return Err(TrustCardError::SnapshotRead {
                    path: PathBuf::from("trust-card-registry-durable-store"),
                    detail: format!("slot {slot}: expected text payload"),
                });
            };
            Ok(Some(encoded.to_string()))
        }
    }
}

/// Upsert one canonical-JSON slot inside the caller's transaction.
pub(crate) fn upsert_slot(
    tx: &fsqlite::compat::Transaction<'_>,
    slot: &str,
    encoded: &str,
) -> Result<(), TrustCardError> {
    tx.execute_with_params(
        "INSERT INTO registry_state(slot, canonical_json) VALUES (?1, ?2)
         ON CONFLICT(slot) DO UPDATE SET canonical_json = excluded.canonical_json;",
        &[
            SqliteValue::Text(slot.into()),
            SqliteValue::Text(encoded.into()),
        ],
    )
    .map_err(|err| TrustCardError::SnapshotWrite {
        path: PathBuf::from("trust-card-registry-durable-store"),
        detail: format!("upsert slot {slot}: {err}"),
    })?;
    Ok(())
}

/// Durable WAL-backed store for the trust-card registry state.
pub struct TrustCardRegistryStore {
    db_path: PathBuf,
    connection: Mutex<Option<Connection>>,
}

impl TrustCardRegistryStore {
    /// Open (creating if needed) the durable store for `snapshot_path`.
    ///
    /// # Errors
    ///
    /// Returns [`TrustCardError::SnapshotWrite`] when the parent directory or
    /// the database cannot be opened with the Tier-1 durability pragmas.
    pub fn open(snapshot_path: &Path) -> Result<Self, TrustCardError> {
        let db_path = durable_store_path(snapshot_path);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| TrustCardError::SnapshotWrite {
                path: db_path.clone(),
                detail: format!("create state dir: {err}"),
            })?;
        }
        let connection = Connection::open(db_path.to_string_lossy().as_ref()).map_err(|err| {
            TrustCardError::SnapshotWrite {
                path: db_path.clone(),
                detail: format!("open durable registry store: {err}"),
            }
        })?;
        for pragma in [
            "PRAGMA journal_mode=WAL;",
            "PRAGMA synchronous=FULL;",
            format!("PRAGMA busy_timeout={BUSY_TIMEOUT_MILLIS};").as_str(),
        ] {
            connection
                .query(pragma)
                .map_err(|err| TrustCardError::SnapshotWrite {
                    path: db_path.clone(),
                    detail: format!("pragma {pragma}: {err}"),
                })?;
        }
        Ok(Self {
            db_path,
            connection: Mutex::new(Some(connection)),
        })
    }

    /// Path of the underlying database file (operator-inspection surface).
    #[must_use]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Load `(snapshot_json, high_water_json)` when the store holds state.
    ///
    /// # Errors
    ///
    /// Returns [`TrustCardError::SnapshotRead`] when the store cannot be read.
    pub fn load_state(&self) -> Result<Option<(String, Option<String>)>, TrustCardError> {
        self.with_connection(|connection| {
            let table = connection
                .query_with_params(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'registry_state';",
                    &[],
                )
                .map_err(|err| TrustCardError::SnapshotRead {
                    path: self.db_path.clone(),
                    detail: err.to_string(),
                })?;
            if table.is_empty() {
                return Ok(None);
            }
            let Some(snapshot) = read_slot(connection, SLOT_SNAPSHOT)? else {
                return Ok(None);
            };
            let high_water = read_slot(connection, SLOT_HIGH_WATER)?;
            Ok(Some((snapshot, high_water)))
        })
    }

    /// Run `operation` inside one exclusive committed transaction.
    ///
    /// The commit is the WAL-durable boundary; a dropped transaction rolls
    /// back. Writers serialize through SQLite locking plus the configured
    /// busy timeout.
    ///
    /// # Errors
    ///
    /// Propagates the operation's error after rolling back.
    pub fn with_immediate_transaction<T>(
        &self,
        operation: impl FnOnce(
            &Connection,
            &fsqlite::compat::Transaction<'_>,
        ) -> Result<T, TrustCardError>,
    ) -> Result<T, TrustCardError> {
        self.with_connection(|connection| {
            let mut tx = connection
                .transaction()
                .map_err(|err| TrustCardError::SnapshotWrite {
                    path: self.db_path.clone(),
                    detail: format!("begin transaction: {err}"),
                })?;
            ensure_schema(&tx)?;
            let outcome = operation(connection, &tx)?;
            tx.commit().map_err(|err| TrustCardError::SnapshotWrite {
                path: self.db_path.clone(),
                detail: format!("commit: {err}"),
            })?;
            Ok(outcome)
        })
    }

    /// Import validated legacy JSON content once.
    ///
    /// Callers MUST have validated both payloads before handing them over;
    /// this function stores them verbatim in one atomic transaction and
    /// records the import marker.
    ///
    /// # Errors
    ///
    /// Returns [`TrustCardError::SnapshotWrite`] when the transaction fails.
    pub fn import_legacy_state(
        &self,
        snapshot_json: &str,
        high_water_json: Option<&str>,
    ) -> Result<(), TrustCardError> {
        self.with_immediate_transaction(|_connection, tx| {
            upsert_slot(tx, SLOT_SNAPSHOT, snapshot_json)?;
            if let Some(encoded) = high_water_json {
                upsert_slot(tx, SLOT_HIGH_WATER, encoded)?;
            }
            mark_legacy_import(tx, "imported on first durable load")?;
            Ok(())
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> Result<T, TrustCardError>,
    ) -> Result<T, TrustCardError> {
        let guard = self
            .connection
            .lock()
            .map_err(|_| TrustCardError::SnapshotRead {
                path: self.db_path.clone(),
                detail: "durable registry mutex poisoned".to_string(),
            })?;
        let connection = guard.as_ref().ok_or_else(|| TrustCardError::SnapshotRead {
            path: self.db_path.clone(),
            detail: "durable registry connection closed".to_string(),
        })?;
        operation(connection)
    }
}

fn ensure_schema(tx: &fsqlite::compat::Transaction<'_>) -> Result<(), TrustCardError> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS registry_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS registry_state (
            slot TEXT PRIMARY KEY,
            canonical_json TEXT NOT NULL
        );",
    )
    .map_err(|err| TrustCardError::SnapshotWrite {
        path: PathBuf::from("trust-card-registry-durable-store"),
        detail: format!("ensure schema: {err}"),
    })?;
    tx.execute_with_params(
        "INSERT INTO registry_meta(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        &[
            SqliteValue::Text(META_KEY_SCHEMA_VERSION.into()),
            SqliteValue::Text(REGISTRY_DB_SCHEMA_VERSION.into()),
        ],
    )
    .map_err(|err| TrustCardError::SnapshotWrite {
        path: PathBuf::from("trust-card-registry-durable-store"),
        detail: format!("record schema version: {err}"),
    })?;
    Ok(())
}

fn mark_legacy_import(
    tx: &fsqlite::compat::Transaction<'_>,
    note: &str,
) -> Result<(), TrustCardError> {
    tx.execute_with_params(
        "INSERT INTO registry_meta(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        &[
            SqliteValue::Text(META_KEY_LEGACY_JSON_IMPORT.into()),
            SqliteValue::Text(note.into()),
        ],
    )
    .map_err(|err| TrustCardError::SnapshotWrite {
        path: PathBuf::from("trust-card-registry-durable-store"),
        detail: format!("mark legacy import: {err}"),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_snapshot_path(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir
            .path()
            .join(format!("{tag}-trust-card-registry.v1.json"));
        (dir, path)
    }

    #[test]
    fn durable_store_path_replaces_json_extension() {
        let path = Path::new("/tmp/state/trust-card-registry.v1.json");
        assert_eq!(
            durable_store_path(path),
            PathBuf::from("/tmp/state/trust-card-registry.v1.db")
        );
        // Extensionless paths still get a deterministic sibling.
        assert_eq!(
            durable_store_path(Path::new("/tmp/registry")),
            PathBuf::from("/tmp/registry.db")
        );
    }

    #[test]
    fn open_creates_parent_directory_and_tier1_pragmas() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a/b/state/trust-card-registry.v1.json");
        let store = TrustCardRegistryStore::open(&nested).expect("open creates parents");
        assert!(nested.parent().expect("parent").is_dir());
        let journal_mode: String = store
            .with_connection(|connection| {
                Ok(connection
                    .query("PRAGMA journal_mode;")
                    .expect("journal pragma")
                    .first()
                    .and_then(|row| row.values().first().cloned())
                    .map(|value| match value {
                        // bd-o776s: SqliteValue::Text carries SmallText; both
                        // arms must produce the String the caller asserts on.
                        SqliteValue::Text(text) => text.to_string(),
                        other => format!("{other:?}"),
                    })
                    .unwrap_or_default())
            })
            .expect("with_connection");
        assert_eq!(journal_mode, "wal");
    }

    #[test]
    fn load_state_returns_none_for_fresh_store() {
        let (_dir, path) = temp_snapshot_path("fresh");
        let store = TrustCardRegistryStore::open(&path).expect("open");
        assert!(store.load_state().expect("load fresh").is_none());
    }

    #[test]
    fn persist_roundtrip_preserves_both_slots_atomically() {
        let (_dir, path) = temp_snapshot_path("roundtrip");
        let store = TrustCardRegistryStore::open(&path).expect("open");
        store
            .import_legacy_state(
                "{\"snapshot_epoch\":7}",
                Some("{\"snapshot_epoch\":7,\"hw\":true}"),
            )
            .expect("persist");
        let (snapshot, high_water) = store.load_state().expect("reload").expect("rows exist");
        assert_eq!(snapshot, "{\"snapshot_epoch\":7}");
        assert_eq!(
            high_water.as_deref(),
            Some("{\"snapshot_epoch\":7,\"hw\":true}")
        );
        // The schema version meta row landed with the same transaction.
        let schema_version = store
            .with_connection(|connection| {
                Ok(connection
                    .query("SELECT value FROM registry_meta WHERE key = 'schema_version';")
                    .expect("meta query"))
            })
            .expect("meta read");
        assert_eq!(schema_version.len(), 1);
    }

    #[test]
    fn import_overwrites_previous_content_idempotently() {
        let (_dir, path) = temp_snapshot_path("idempotent");
        let store = TrustCardRegistryStore::open(&path).expect("open");
        store
            .import_legacy_state("{\"epoch\":1}", None)
            .expect("first import");
        store
            .import_legacy_state("{\"epoch\":2}", Some("{\"epoch\":2}"))
            .expect("second import");
        let (snapshot, high_water) = store.load_state().expect("reload").expect("rows exist");
        assert_eq!(snapshot, "{\"epoch\":2}");
        assert_eq!(high_water.as_deref(), Some("{\"epoch\":2}"));
    }

    #[test]
    fn transaction_error_rolls_back_all_slots() {
        let (_dir, path) = temp_snapshot_path("rollback");
        let store = TrustCardRegistryStore::open(&path).expect("open");
        let failure: Result<(), TrustCardError> = store.with_immediate_transaction(|_c, tx| {
            upsert_slot(tx, SLOT_SNAPSHOT, "{\"epoch\":9}")?;
            Err(TrustCardError::InvalidSnapshot(
                "simulated mid-transaction failure".to_string(),
            ))
        });
        assert!(failure.is_err());
        assert!(store.load_state().expect("load after rollback").is_none());
    }
}
