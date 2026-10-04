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
//!   The import-once decision is made inside the transaction that would seed
//!   the store, and the import only ever INSERTs: it can never overwrite a
//!   snapshot or high-water row that a concurrent first load (or any later
//!   revoke/quarantine) already committed (franken_node#4).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fsqlite::compat::TransactionExt;
use fsqlite::{Connection, SqliteValue};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::TrustConfig;
use crate::security::constant_time;
use crate::supply_chain::trust_card::{TrustCardError, get_registry_key};

/// Project-relative location of the authoritative trust-card registry
/// snapshot; its durable store is [`durable_store_path`] of it.
pub const TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH: &str =
    ".franken-node/state/trust-card-registry.v1.json";

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

/// The trust-card registry snapshot path of the project rooted at
/// `project_root`. Every consumer (run preflight, the dispatch-time recheck,
/// auto-quarantine, `remotecap issue`, doctor and the trust commands) resolves
/// the registry here (bd-reality-20260923-26n9r.1).
#[must_use]
pub fn registry_snapshot_path(project_root: &Path) -> PathBuf {
    project_root.join(TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH)
}

/// Registry-meta key holding the signed [`RevocationFrontier`] record.
const META_KEY_REVOCATION_FRONTIER: &str = "revocation_frontier";
/// Where earlier builds kept an UNSIGNED frontier (bare epoch seconds). It is
/// never read (anyone able to write the store could forge it) and is removed
/// whenever a signed frontier is recorded.
const META_KEY_LEGACY_REVOCATION_FRONTIER: &str = "revocation_frontier_epoch_secs";

pub const REVOCATION_FRONTIER_SCHEMA: &str = "franken-node/revocation-frontier/v1";

type HmacSha256 = Hmac<Sha256>;

/// The revocation frontier: when, and by what, the registry's trust signals
/// were last refreshed from the network without error
/// (bd-reality-20260923-26n9r.1). It is DATA, not a file mtime (merely opening
/// the fsqlite store rewrites the database file), and it is authenticated
/// with the registry signing key, so editing the store can neither forge a
/// frontier nor move one forward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationFrontier {
    pub schema_version: String,
    /// Unix time of the refresh.
    pub frontier_epoch_secs: u64,
    /// The refresh that established it, e.g. `trust sync --force`.
    pub source: String,
    /// Hex HMAC-SHA256 under the registry signing key over the schema, the
    /// frontier time and the length-prefixed source.
    pub mac: String,
}

fn revocation_frontier_mac(
    registry_key: &[u8],
    frontier_epoch_secs: u64,
    source: &str,
) -> Result<String, TrustCardError> {
    let mut mac =
        HmacSha256::new_from_slice(registry_key).map_err(|_| TrustCardError::InvalidRegistryKey)?;
    mac.update(REVOCATION_FRONTIER_SCHEMA.as_bytes());
    mac.update(&[0]);
    mac.update(&frontier_epoch_secs.to_be_bytes());
    mac.update(
        &u64::try_from(source.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    mac.update(source.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Record, signed with the registry key from `trust_config`, that the
/// registry's trust signals were refreshed from the network at `epoch_secs`
/// by `source`.
///
/// # Errors
///
/// Returns [`TrustCardError::InvalidInput`] when the registry signing key is
/// not configured, and [`TrustCardError::SnapshotWrite`] when the store cannot
/// be updated.
pub fn record_revocation_frontier(
    snapshot_path: &Path,
    trust_config: &TrustConfig,
    epoch_secs: u64,
    source: &str,
) -> Result<RevocationFrontier, TrustCardError> {
    let registry_key = get_registry_key(trust_config)?;
    let frontier = RevocationFrontier {
        schema_version: REVOCATION_FRONTIER_SCHEMA.to_string(),
        frontier_epoch_secs: epoch_secs,
        source: source.to_string(),
        mac: revocation_frontier_mac(&registry_key, epoch_secs, source)?,
    };
    let encoded =
        serde_json::to_string(&frontier).map_err(|err| TrustCardError::SnapshotWrite {
            path: PathBuf::from("trust-card-registry-durable-store"),
            detail: format!("encode revocation frontier: {err}"),
        })?;
    let store = TrustCardRegistryStore::open(snapshot_path)?;
    store.with_immediate_transaction(|_connection, tx| {
        fn write_error(err: impl std::fmt::Display) -> TrustCardError {
            TrustCardError::SnapshotWrite {
                path: PathBuf::from("trust-card-registry-durable-store"),
                detail: format!("record revocation frontier: {err}"),
            }
        }
        tx.execute_with_params(
            "INSERT INTO registry_meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            &[
                SqliteValue::Text(META_KEY_REVOCATION_FRONTIER.into()),
                SqliteValue::Text(encoded.as_str().into()),
            ],
        )
        .map_err(write_error)?;
        tx.execute_with_params(
            "DELETE FROM registry_meta WHERE key = ?1;",
            &[SqliteValue::Text(
                META_KEY_LEGACY_REVOCATION_FRONTIER.into(),
            )],
        )
        .map_err(write_error)?;
        Ok(())
    })?;
    Ok(frontier)
}

/// The recorded revocation frontier, authenticated with the registry key from
/// `trust_config`, or `None` when the durable store does not exist or no
/// signed frontier has ever been recorded.
///
/// # Errors
///
/// Returns [`TrustCardError::SnapshotRead`] when an existing store cannot be
/// read, or its frontier is malformed or fails authentication (it was not
/// recorded with this registry's key, or was edited since), and
/// [`TrustCardError::InvalidInput`] when the registry key is not configured.
pub fn read_revocation_frontier(
    snapshot_path: &Path,
    trust_config: &TrustConfig,
) -> Result<Option<RevocationFrontier>, TrustCardError> {
    if !durable_store_path(snapshot_path).is_file() {
        return Ok(None);
    }
    let store = TrustCardRegistryStore::open(snapshot_path)?;
    let encoded = store.with_connection(|connection| {
        let table = connection
            .query_with_params(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'registry_meta';",
                &[],
            )
            .map_err(|err| TrustCardError::SnapshotRead {
                path: store.db_path.clone(),
                detail: err.to_string(),
            })?;
        if table.is_empty() {
            return Ok(None);
        }
        let rows = connection
            .query_with_params(
                "SELECT value FROM registry_meta WHERE key = ?1;",
                &[SqliteValue::Text(META_KEY_REVOCATION_FRONTIER.into())],
            )
            .map_err(|err| TrustCardError::SnapshotRead {
                path: store.db_path.clone(),
                detail: format!("read revocation frontier: {err}"),
            })?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        match row.values().first() {
            Some(SqliteValue::Text(value)) => Ok(Some(value.to_string())),
            _ => Err(TrustCardError::SnapshotRead {
                path: store.db_path.clone(),
                detail: "revocation frontier is not text".to_string(),
            }),
        }
    })?;
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let read_error = |detail: String| TrustCardError::SnapshotRead {
        path: store.db_path.clone(),
        detail,
    };
    let frontier: RevocationFrontier = serde_json::from_str(&encoded)
        .map_err(|err| read_error(format!("malformed revocation frontier: {err}")))?;
    if frontier.schema_version != REVOCATION_FRONTIER_SCHEMA {
        return Err(read_error(format!(
            "unsupported revocation frontier schema `{}`",
            frontier.schema_version
        )));
    }
    let registry_key = get_registry_key(trust_config)?;
    let expected = revocation_frontier_mac(
        &registry_key,
        frontier.frontier_epoch_secs,
        &frontier.source,
    )?;
    if !constant_time::ct_eq(&frontier.mac, &expected) {
        return Err(read_error(
            "revocation frontier failed authentication: it was not recorded with this registry's signing key, or it was edited since"
                .to_string(),
        ));
    }
    Ok(Some(frontier))
}

/// Age in seconds of the recorded revocation frontier at `now_secs` (a clock
/// earlier than the frontier saturates to zero), or `None` when none exists.
///
/// # Errors
///
/// Propagates [`read_revocation_frontier`] failures.
pub fn revocation_frontier_age_secs(
    snapshot_path: &Path,
    trust_config: &TrustConfig,
    now_secs: u64,
) -> Result<Option<u64>, TrustCardError> {
    Ok(
        read_revocation_frontier(snapshot_path, trust_config)?.map(|frontier| {
            crate::security::revocation_freshness::snapshot_age_secs(
                frontier.frontier_epoch_secs,
                now_secs,
            )
        }),
    )
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

/// Insert one canonical-JSON slot inside the caller's transaction, failing
/// (never updating) when the slot already holds a row.
fn insert_new_slot(
    tx: &fsqlite::compat::Transaction<'_>,
    slot: &str,
    encoded: &str,
) -> Result<(), TrustCardError> {
    tx.execute_with_params(
        "INSERT INTO registry_state(slot, canonical_json) VALUES (?1, ?2);",
        &[
            SqliteValue::Text(slot.into()),
            SqliteValue::Text(encoded.into()),
        ],
    )
    .map_err(|err| TrustCardError::SnapshotWrite {
        path: PathBuf::from("trust-card-registry-durable-store"),
        detail: format!("insert slot {slot}: {err}"),
    })?;
    Ok(())
}

/// What [`TrustCardRegistryStore::import_legacy_state`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyImportOutcome {
    /// The store was empty and now holds the imported legacy state.
    Imported,
    /// The store already held state (or had already imported once), so
    /// nothing was written; the stored rows stay authoritative.
    AlreadySeeded,
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
    /// Callers MUST have validated both payloads before handing them over.
    /// Inside ONE transaction this checks whether the store already holds a
    /// snapshot (or has already imported once); only when it holds neither
    /// does it store the payloads verbatim and record the import marker.
    /// Rows are only ever inserted, never updated, so a stale importer can
    /// never move the snapshot or the signed high-water mark backwards over
    /// state another process committed after this caller read the legacy
    /// files (franken_node#4): it gets [`LegacyImportOutcome::AlreadySeeded`]
    /// (or, if it loses a race to a concurrent importer's commit, an error)
    /// and must load the stored state instead.
    ///
    /// # Errors
    ///
    /// Returns [`TrustCardError::SnapshotWrite`] when the transaction fails,
    /// including when a concurrent importer inserted the rows first.
    pub fn import_legacy_state(
        &self,
        snapshot_json: &str,
        high_water_json: Option<&str>,
    ) -> Result<LegacyImportOutcome, TrustCardError> {
        self.with_immediate_transaction(|connection, tx| {
            if read_slot(connection, SLOT_SNAPSHOT)?.is_some()
                || legacy_import_recorded(connection)?
            {
                return Ok(LegacyImportOutcome::AlreadySeeded);
            }
            insert_new_slot(tx, SLOT_SNAPSHOT, snapshot_json)?;
            if let Some(encoded) = high_water_json {
                insert_new_slot(tx, SLOT_HIGH_WATER, encoded)?;
            }
            mark_legacy_import(tx, "imported on first durable load")?;
            Ok(LegacyImportOutcome::Imported)
        })
    }

    /// Overwrite one slot verbatim: a test-only stand-in for an attacker or
    /// operator editing the database directly.
    #[cfg(test)]
    pub(crate) fn overwrite_slot_for_tests(
        &self,
        slot: &str,
        encoded: &str,
    ) -> Result<(), TrustCardError> {
        self.with_immediate_transaction(|_connection, tx| upsert_slot(tx, slot, encoded))
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

/// Whether the legacy JSON import marker is recorded.
fn legacy_import_recorded(connection: &Connection) -> Result<bool, TrustCardError> {
    let rows = connection
        .query_with_params(
            "SELECT value FROM registry_meta WHERE key = ?1;",
            &[SqliteValue::Text(META_KEY_LEGACY_JSON_IMPORT.into())],
        )
        .map_err(|err| TrustCardError::SnapshotRead {
            path: PathBuf::from("trust-card-registry-durable-store"),
            detail: format!("read legacy import marker: {err}"),
        })?;
    Ok(!rows.is_empty())
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

    /// franken_node#4: a second (stale) import never overwrites the first.
    #[test]
    fn import_happens_once_and_never_overwrites_seeded_rows() {
        let (_dir, path) = temp_snapshot_path("idempotent");
        let store = TrustCardRegistryStore::open(&path).expect("open");
        assert_eq!(
            store
                .import_legacy_state("{\"epoch\":2}", Some("{\"hw\":2}"))
                .expect("first import"),
            LegacyImportOutcome::Imported
        );
        assert_eq!(
            store
                .import_legacy_state("{\"epoch\":1}", Some("{\"hw\":1}"))
                .expect("second import"),
            LegacyImportOutcome::AlreadySeeded
        );
        let (snapshot, high_water) = store.load_state().expect("reload").expect("rows exist");
        assert_eq!(snapshot, "{\"epoch\":2}");
        assert_eq!(high_water.as_deref(), Some("{\"hw\":2}"));
    }

    /// State written by the normal persist path (no import marker) also
    /// blocks the import, and so does the marker alone.
    #[test]
    fn import_is_skipped_when_rows_or_the_marker_exist() {
        let (_dir, path) = temp_snapshot_path("seeded");
        let store = TrustCardRegistryStore::open(&path).expect("open");
        store
            .overwrite_slot_for_tests(SLOT_SNAPSHOT, "{\"epoch\":5}")
            .expect("seed snapshot");
        assert_eq!(
            store
                .import_legacy_state("{\"epoch\":1}", Some("{\"hw\":1}"))
                .expect("import"),
            LegacyImportOutcome::AlreadySeeded
        );
        let (snapshot, high_water) = store.load_state().expect("reload").expect("rows exist");
        assert_eq!(snapshot, "{\"epoch\":5}");
        assert_eq!(high_water, None);

        let (_dir, path) = temp_snapshot_path("marker");
        let store = TrustCardRegistryStore::open(&path).expect("open");
        store
            .with_immediate_transaction(|_connection, tx| mark_legacy_import(tx, "earlier"))
            .expect("mark");
        assert_eq!(
            store
                .import_legacy_state("{\"epoch\":1}", None)
                .expect("import"),
            LegacyImportOutcome::AlreadySeeded
        );
        assert!(store.load_state().expect("reload").is_none());
    }

    fn frontier_trust_config(key_byte: u8) -> TrustConfig {
        use base64::Engine as _;
        let mut config = crate::config::Config::for_profile(crate::config::Profile::Balanced);
        config.trust.registry_signing_key =
            Some(base64::engine::general_purpose::STANDARD.encode([key_byte; 32]));
        config.trust
    }

    fn write_meta(path: &Path, key: &str, value: &str) {
        let store = TrustCardRegistryStore::open(path).expect("open");
        store
            .with_immediate_transaction(|_connection, tx| {
                tx.execute_with_params(
                    "INSERT INTO registry_meta(key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                    &[
                        SqliteValue::Text(key.into()),
                        SqliteValue::Text(value.into()),
                    ],
                )
                .map_err(|err| TrustCardError::SnapshotWrite {
                    path: PathBuf::from("test"),
                    detail: err.to_string(),
                })?;
                Ok(())
            })
            .expect("write registry meta");
    }

    #[test]
    fn revocation_frontier_round_trips_signed_with_the_registry_key() {
        let (_dir, path) = temp_snapshot_path("frontier");
        let config = frontier_trust_config(7);
        assert_eq!(
            read_revocation_frontier(&path, &config).expect("no store yet"),
            None
        );
        let recorded = record_revocation_frontier(&path, &config, 1_000, "trust sync --force")
            .expect("record frontier");
        assert_eq!(recorded.schema_version, REVOCATION_FRONTIER_SCHEMA);
        assert_eq!(
            read_revocation_frontier(&path, &config).expect("read frontier"),
            Some(recorded)
        );
        assert_eq!(
            revocation_frontier_age_secs(&path, &config, 1_300).expect("age"),
            Some(300)
        );
        // A clock behind the frontier saturates to fresh.
        assert_eq!(
            revocation_frontier_age_secs(&path, &config, 10).expect("age"),
            Some(0)
        );
    }

    #[test]
    fn revocation_frontier_edited_or_signed_by_another_key_fails_authentication() {
        let (_dir, path) = temp_snapshot_path("frontier-tamper");
        let config = frontier_trust_config(7);
        let recorded = record_revocation_frontier(&path, &config, 1_000, "trust sync --force")
            .expect("record frontier");

        let mut moved_forward = recorded.clone();
        moved_forward.frontier_epoch_secs = 9_999;
        let mut resourced = recorded;
        resourced.source = "trust sync --force (forged)".to_string();
        for edited in [moved_forward, resourced] {
            write_meta(
                &path,
                META_KEY_REVOCATION_FRONTIER,
                &serde_json::to_string(&edited).expect("encode"),
            );
            let err = read_revocation_frontier(&path, &config).expect_err("edited frontier");
            assert!(err.to_string().contains("failed authentication"), "{err}");
        }

        record_revocation_frontier(
            &path,
            &frontier_trust_config(8),
            1_000,
            "trust sync --force",
        )
        .expect("record under another registry's key");
        let err = read_revocation_frontier(&path, &config).expect_err("foreign key");
        assert!(err.to_string().contains("failed authentication"), "{err}");

        write_meta(&path, META_KEY_REVOCATION_FRONTIER, "1000");
        let err = read_revocation_frontier(&path, &config).expect_err("bare integer");
        assert!(
            err.to_string().contains("malformed revocation frontier"),
            "{err}"
        );
    }

    #[test]
    fn unsigned_legacy_revocation_frontier_is_ignored_and_removed_on_record() {
        let (_dir, path) = temp_snapshot_path("frontier-legacy");
        let config = frontier_trust_config(7);
        write_meta(&path, META_KEY_LEGACY_REVOCATION_FRONTIER, "99999999999");
        assert_eq!(
            read_revocation_frontier(&path, &config).expect("read"),
            None,
            "an unsigned frontier anyone could write must not count"
        );
        record_revocation_frontier(&path, &config, 5, "trust sync --force").expect("record");
        let store = TrustCardRegistryStore::open(&path).expect("open");
        let legacy_rows = store
            .with_connection(|connection| {
                connection
                    .query_with_params(
                        "SELECT value FROM registry_meta WHERE key = ?1;",
                        &[SqliteValue::Text(
                            META_KEY_LEGACY_REVOCATION_FRONTIER.into(),
                        )],
                    )
                    .map_err(|err| TrustCardError::SnapshotRead {
                        path: PathBuf::from("test"),
                        detail: err.to_string(),
                    })
            })
            .expect("query legacy key");
        assert!(legacy_rows.is_empty());
    }

    #[test]
    fn registry_snapshot_path_is_the_project_state_location() {
        assert_eq!(
            registry_snapshot_path(Path::new("/work/app")),
            PathBuf::from("/work/app/.franken-node/state/trust-card-registry.v1.json")
        );
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
