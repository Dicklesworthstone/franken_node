//! Durable frankensqlite-backed fleet transport (bd-reality-20260820-w0fc6.3).
//!
//! Implements [`FleetTransport`] on top of the published `fsqlite` crate so
//! the fleet action log and node statuses live in a WAL-durable database
//! instead of `actions.jsonl` + `nodes/node-<id>.json` sidecars. This is the
//! authoritative store per the charter substrate row ("all durable state goes
//! through frankensqlite"); the legacy JSONL layout remains readable exactly
//! once at `initialize` as an import path, and deleting the database files
//! rolls back to it (the importer re-runs from the untouched JSONL).
//!
//! Durability: the connection runs `journal_mode=WAL` with
//! `synchronous=FULL`, so every committed transaction survives process crash
//! without a separate checkpoint step (Tier-1 semantics of
//! `docs/specs/frankensqlite_persistence_contract.md`).
//!
//! Divergence from [`FileFleetTransport`] (deliberate, documented):
//! * actions are keyed by `action_id`; republishing the same id is an
//!   idempotent overwrite instead of a duplicate log line;
//! * torn trailing lines cannot happen (transactions are atomic);
//! * cross-process contention is handled by SQLite busy-timeout instead of
//!   ad-hoc flock files.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use fsqlite::compat::TransactionExt;
use fsqlite::{Connection, SqliteValue};

use super::fleet_transport::{
    FLEET_ACTION_LOG_FILE, FleetAction, FleetActionRecord, FleetSharedState, FleetTransport,
    FleetTransportError, NodeStatus,
};

const FLEET_DB_FILE: &str = "fleet-state.db";
const FLEET_DB_SCHEMA_VERSION: &str = "franken-node/fleet-durable-store/v1";
const META_INITIALIZED_KEY: &str = "initialized";
const META_JSONL_IMPORT_KEY: &str = "legacy_jsonl_imported";
/// bd-ymbjw: fsqlite surfaces WAL write-write races as immediate
/// "database is busy (snapshot conflict …)" errors. Unlike a plain lock wait,
/// a snapshot conflict is not resolved by `busy_timeout` — the failing
/// transaction must be rolled back and retried from scratch. Fleet stores are
/// accessed concurrently by design (a polling `fleet agent` alongside
/// operator commands), so the transport absorbs these transients itself
/// instead of leaking them into CLI error envelopes.
const SNAPSHOT_CONFLICT_RETRY_ATTEMPTS: u32 = 6;
const SNAPSHOT_CONFLICT_BACKOFF_BASE_MILLIS: u64 = 20;

fn is_transient_snapshot_conflict(err: &FleetTransportError) -> bool {
    match err {
        FleetTransportError::IoError { detail }
        | FleetTransportError::LockContention { detail } => {
            let detail = detail.to_ascii_lowercase();
            detail.contains("snapshot conflict")
                || detail.contains("database is busy")
                || detail.contains("database is locked")
        }
        _ => false,
    }
}

fn snapshot_conflict_backoff(attempt: u32) -> Duration {
    // Deterministic exponential backoff: 20ms * 2^attempt, capped.
    let shift = attempt.min(5);
    Duration::from_millis(SNAPSHOT_CONFLICT_BACKOFF_BASE_MILLIS.saturating_mul(1 << shift))
}

const BUSY_TIMEOUT_MILLIS: u64 = 5_000;

fn text(value: &SqliteValue, column: &str) -> Result<String, FleetTransportError> {
    match value {
        SqliteValue::Text(text) => Ok(text.to_string()),
        other => Err(FleetTransportError::serialization(format!(
            "column {column}: expected text, got {other:?}"
        ))),
    }
}

fn parse_row_json<T: serde::de::DeserializeOwned>(
    value: &SqliteValue,
    column: &str,
) -> Result<T, FleetTransportError> {
    let raw = text(value, column)?;
    serde_json::from_str(&raw)
        .map_err(|err| FleetTransportError::serialization(format!("column {column}: {err}")))
}

/// Durable WAL-backed implementation of [`FleetTransport`].
pub struct DurableFleetTransport {
    db_path: PathBuf,
    state_dir: PathBuf,
    connection: Mutex<Option<Connection>>,
}

impl DurableFleetTransport {
    /// Open (creating if needed) the durable fleet database under `state_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`FleetTransportError::Io`] when the directory or database
    /// cannot be opened with the Tier-1 durability pragmas.
    pub fn new(state_dir: impl Into<PathBuf>) -> Result<Self, FleetTransportError> {
        let state_dir = state_dir.into();
        std::fs::create_dir_all(&state_dir)
            .map_err(|err| FleetTransportError::io(format!("create fleet state dir: {err}")))?;
        let db_path = state_dir.join(FLEET_DB_FILE);
        let connection = Self::open_tier1_connection(&db_path)?;
        Ok(Self {
            db_path,
            state_dir,
            connection: Mutex::new(Some(connection)),
        })
    }

    /// Path of the underlying database file (operator-inspection surface).
    #[must_use]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Legacy JSONL action log location used by the one-time importer.
    #[must_use]
    pub fn legacy_action_log(&self) -> PathBuf {
        self.state_dir.join(FLEET_ACTION_LOG_FILE)
    }

    fn open_tier1_connection(db_path: &Path) -> Result<Connection, FleetTransportError> {
        let connection = Connection::open(db_path.to_string_lossy().as_ref())
            .map_err(|err| FleetTransportError::io(format!("open {}: {err}", db_path.display())))?;
        for pragma in [
            "PRAGMA journal_mode=WAL;",
            "PRAGMA synchronous=FULL;",
            format!("PRAGMA busy_timeout={BUSY_TIMEOUT_MILLIS};").as_str(),
            "PRAGMA foreign_keys=ON;",
        ] {
            connection
                .query(pragma)
                .map_err(|err| FleetTransportError::io(format!("pragma {pragma}: {err}")))?;
        }
        Ok(connection)
    }

    fn with_connection<T>(
        &self,
        operation: impl Fn(&Connection) -> Result<T, FleetTransportError>,
    ) -> Result<T, FleetTransportError> {
        // bd-ymbjw: snapshot conflicts abort the failing statement without
        // persisting anything (single autocommit statement per operation in
        // this transport), so re-running the closure from scratch is safe.
        let mut attempt = 0_u32;
        loop {
            let guard = self
                .connection
                .lock()
                .map_err(|_| FleetTransportError::io("fleet db mutex poisoned".to_string()))?;
            let connection = guard
                .as_ref()
                .ok_or_else(|| FleetTransportError::io("fleet db connection closed".to_string()))?;
            match operation(connection) {
                Ok(value) => return Ok(value),
                Err(err)
                    if is_transient_snapshot_conflict(&err)
                        && attempt + 1 < SNAPSHOT_CONFLICT_RETRY_ATTEMPTS =>
                {
                    drop(guard);
                    std::thread::sleep(snapshot_conflict_backoff(attempt));
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn ensure_initialized(&self) -> Result<(), FleetTransportError> {
        let flag = self.with_connection(|connection| {
            // A fresh database has no tables at all; that is the
            // not-initialized state, not an I/O failure.
            let table = connection
                .query_with_params(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'fleet_meta';",
                    &[],
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            if table.is_empty() {
                return Ok(false);
            }
            let rows = connection
                .query_with_params(
                    "SELECT value FROM fleet_meta WHERE key = ?1;",
                    &[SqliteValue::Text(META_INITIALIZED_KEY.into())],
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            Ok(rows.len() == 1)
        })?;
        if flag {
            Ok(())
        } else {
            Err(FleetTransportError::NotInitialized {
                detail: "call initialize() before using the durable fleet transport".to_string(),
            })
        }
    }

    /// Import the legacy JSONL layout once; idempotent via a meta marker.
    fn import_legacy_layout_if_needed(&self) -> Result<usize, FleetTransportError> {
        self.with_connection(|connection| {
            let already = connection
                .query_with_params(
                    "SELECT value FROM fleet_meta WHERE key = ?1;",
                    &[SqliteValue::Text(META_JSONL_IMPORT_KEY.into())],
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            if !already.is_empty() {
                return Ok(0);
            }

            let mut imported = 0_usize;
            imported += self.import_legacy_actions(connection)?;
            imported += self.import_legacy_nodes(connection)?;

            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS fleet_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );",
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            connection
                .execute_with_params(
                    "INSERT INTO fleet_meta(key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                    &[
                        SqliteValue::Text(META_JSONL_IMPORT_KEY.into()),
                        SqliteValue::Text(format!("{} records", imported).into()),
                    ],
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            Ok(imported)
        })
    }

    fn import_legacy_actions(&self, connection: &Connection) -> Result<usize, FleetTransportError> {
        let actions_path = self.state_dir.join(FLEET_ACTION_LOG_FILE);
        if !actions_path.is_file() {
            return Ok(0);
        }
        let raw = std::fs::read_to_string(&actions_path).map_err(|err| {
            FleetTransportError::io(format!("read {}: {err}", actions_path.display()))
        })?;
        let mut imported = 0_usize;
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let record: FleetActionRecord = serde_json::from_str(line).map_err(|err| {
                FleetTransportError::serialization(format!(
                    "legacy {}: {err}",
                    actions_path.display()
                ))
            })?;
            Self::insert_action(connection, &record)?;
            imported += 1;
        }
        Ok(imported)
    }

    fn import_legacy_nodes(&self, connection: &Connection) -> Result<usize, FleetTransportError> {
        let nodes_dir = self.state_dir.join(super::fleet_transport::FLEET_NODE_DIR);
        if !nodes_dir.is_dir() {
            return Ok(0);
        }
        let mut imported = 0_usize;
        let entries = std::fs::read_dir(&nodes_dir)
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).map_err(|err| {
                FleetTransportError::io(format!("read {}: {err}", path.display()))
            })?;
            let status: NodeStatus = serde_json::from_str(&raw).map_err(|err| {
                FleetTransportError::serialization(format!("legacy {}: {err}", path.display()))
            })?;
            Self::upsert_status(connection, &status)?;
            imported += 1;
        }
        Ok(imported)
    }

    fn insert_action(
        connection: &Connection,
        record: &FleetActionRecord,
    ) -> Result<(), FleetTransportError> {
        let action_json = serde_json::to_string(record)
            .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
        // Explicit transaction: the commit is the WAL-durable boundary under
        // synchronous=FULL; a bare statement can sit in the retained
        // autocommit overlay and die with the process.
        let mut tx = connection
            .transaction()
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        tx.execute_with_params(
            "INSERT INTO fleet_actions(action_id, emitted_at, action_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(action_id) DO UPDATE SET
                emitted_at = excluded.emitted_at,
                action_json = excluded.action_json;",
            &[
                SqliteValue::Text(record.action_id.clone().into()),
                SqliteValue::Text(record.emitted_at.to_rfc3339().into()),
                SqliteValue::Text(action_json.into()),
            ],
        )
        .map_err(|err| FleetTransportError::io(err.to_string()))?;
        tx.commit()
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        Ok(())
    }

    fn upsert_status(
        connection: &Connection,
        status: &NodeStatus,
    ) -> Result<(), FleetTransportError> {
        let status_json = serde_json::to_string(status)
            .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
        let mut tx = connection
            .transaction()
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        tx.execute_with_params(
            "INSERT INTO fleet_nodes(zone_id, node_id, status_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(zone_id, node_id) DO UPDATE SET
                status_json = excluded.status_json;",
            &[
                SqliteValue::Text(status.zone_id.clone().into()),
                SqliteValue::Text(status.node_id.clone().into()),
                SqliteValue::Text(status_json.into()),
            ],
        )
        .map_err(|err| FleetTransportError::io(err.to_string()))?;
        tx.commit()
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        Ok(())
    }

    fn query_actions(
        connection: &Connection,
    ) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        // Ordering contract mirrors FileFleetTransport::read_shared_state:
        // emitted_at, then action_id.
        let rows = connection
            .query(
                "SELECT action_json FROM fleet_actions
                 ORDER BY emitted_at ASC, action_id ASC;",
            )
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        rows.iter()
            .map(|row| parse_row_json(&row.values()[0], "action_json"))
            .collect()
    }

    fn query_nodes(connection: &Connection) -> Result<Vec<NodeStatus>, FleetTransportError> {
        let rows = connection
            .query("SELECT status_json FROM fleet_nodes ORDER BY zone_id ASC, node_id ASC;")
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        rows.iter()
            .map(|row| parse_row_json(&row.values()[0], "status_json"))
            .collect()
    }

    /// Same staleness helper as [`FileFleetTransport::list_stale_nodes`].
    ///
    /// # Errors
    ///
    /// Propagates [`FleetTransport::list_node_statuses`] failures.
    pub fn list_stale_nodes(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        staleness_threshold: Duration,
    ) -> Result<Vec<NodeStatus>, FleetTransportError> {
        let staleness_threshold = chrono::TimeDelta::from_std(staleness_threshold)
            .map_err(|err| FleetTransportError::stale_state(format!("invalid threshold: {err}")))?;
        let mut stale_nodes: Vec<NodeStatus> = FleetTransport::list_node_statuses(self)?
            .into_iter()
            .filter(|status| now.signed_duration_since(status.last_seen) >= staleness_threshold)
            .collect();
        stale_nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        Ok(stale_nodes)
    }
}

/// Count node status records directly from the durable store.
/// Replaces `count_matching_files(nodes/, ...)` in the ops metrics readers
/// now that `nodes/node-<id>.json` files are a legacy import source only.
///
/// # Errors
///
/// Returns [`FleetTransportError::Io`] when the store cannot be opened.
pub fn count_node_statuses(state_dir: &Path) -> Result<u64, FleetTransportError> {
    let db_path = state_dir.join(FLEET_DB_FILE);
    if !db_path.is_file() {
        return Ok(0);
    }
    let connection = DurableFleetTransport::open_tier1_connection(&db_path)?;
    let table = connection
        .query("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'fleet_nodes';")
        .map_err(|err| FleetTransportError::io(err.to_string()))?;
    if table.is_empty() {
        return Ok(0);
    }
    let rows = connection
        .query("SELECT COUNT(*) FROM fleet_nodes;")
        .map_err(|err| FleetTransportError::io(err.to_string()))?;
    match rows.first().and_then(|row| row.values().first()) {
        Some(SqliteValue::Integer(value)) => Ok(u64::try_from(*value).unwrap_or(u64::MAX)),
        _ => Ok(0),
    }
}

impl FleetTransport for DurableFleetTransport {
    fn initialize(&mut self) -> Result<(), FleetTransportError> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS fleet_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );",
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS fleet_actions (
                        seq INTEGER PRIMARY KEY AUTOINCREMENT,
                        action_id TEXT NOT NULL UNIQUE,
                        emitted_at TEXT NOT NULL,
                        action_json TEXT NOT NULL
                    );",
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS fleet_nodes (
                        zone_id TEXT NOT NULL,
                        node_id TEXT NOT NULL,
                        status_json TEXT NOT NULL,
                        PRIMARY KEY (zone_id, node_id)
                    );",
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            connection
                .execute_with_params(
                    "INSERT INTO fleet_meta(key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                    &[
                        SqliteValue::Text(META_SCHEMA_VERSION.into()),
                        SqliteValue::Text(FLEET_DB_SCHEMA_VERSION.into()),
                    ],
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            Ok(())
        })?;
        self.import_legacy_layout_if_needed()?;
        self.with_connection(|connection| {
            connection
                .execute_with_params(
                    "INSERT INTO fleet_meta(key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                    &[
                        SqliteValue::Text(META_INITIALIZED_KEY.into()),
                        SqliteValue::Text("true".into()),
                    ],
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            Ok(())
        })
    }

    fn publish_action(&mut self, action: &FleetActionRecord) -> Result<(), FleetTransportError> {
        self.ensure_initialized()?;
        self.with_connection(|connection| Self::insert_action(connection, action))
    }

    fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        self.ensure_initialized()?;
        self.with_connection(Self::query_actions)
    }

    fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
        self.ensure_initialized()?;
        self.with_connection(|connection| Self::upsert_status(connection, status))
    }

    fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
        self.ensure_initialized()?;
        self.with_connection(Self::query_nodes)
    }

    fn read_shared_state(&self) -> Result<FleetSharedState, FleetTransportError> {
        self.ensure_initialized()?;
        let (actions, nodes) = self.with_connection(|connection| {
            Ok((
                Self::query_actions(connection)?,
                Self::query_nodes(connection)?,
            ))
        })?;
        // Keep the shared-state sort contract even though SQL pre-sorts.
        let mut actions = actions;
        actions.sort_by(|left, right| {
            left.emitted_at
                .cmp(&right.emitted_at)
                .then_with(|| left.action_id.cmp(&right.action_id))
        });
        let mut nodes = nodes;
        nodes.sort_by(|left, right| {
            left.zone_id
                .cmp(&right.zone_id)
                .then_with(|| left.node_id.cmp(&right.node_id))
        });
        Ok(FleetSharedState {
            schema_version: super::fleet_transport::FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions,
            nodes,
        })
    }
}

const META_SCHEMA_VERSION: &str = "schema_version";

/// Count active quarantine incidents directly from the durable store.
///
/// Mirrors `main.rs::count_active_fleet_quarantines` semantics over the
/// durable store: replay actions in append order, add on Quarantine, remove
/// on Release, and count the surviving incident set. Replaces direct
/// `actions.jsonl` parsing in the ops metrics readers.
///
/// # Errors
///
/// Returns [`FleetTransportError::Io`] when the store cannot be opened or
/// [`FleetTransportError::Serialization`] when a stored action is corrupt.
pub fn count_active_quarantine_actions(state_dir: &Path) -> Result<u64, FleetTransportError> {
    let db_path = state_dir.join(FLEET_DB_FILE);
    if !db_path.is_file() {
        return Ok(0);
    }
    let connection = DurableFleetTransport::open_tier1_connection(&db_path)?;
    let rows = connection
        .query("SELECT action_json FROM fleet_actions ORDER BY seq ASC;")
        .map_err(|err| FleetTransportError::io(err.to_string()))?;
    let mut active_incidents = std::collections::BTreeSet::new();
    for row in &rows {
        let record: FleetActionRecord = parse_row_json(&row.values()[0], "action_json")?;
        match record.action {
            FleetAction::Quarantine { incident_id, .. } => {
                active_incidents.insert(incident_id);
            }
            FleetAction::Release { incident_id, .. } => {
                active_incidents.remove(&incident_id);
            }
            FleetAction::PolicyUpdate { .. } => {}
            #[cfg(feature = "control-plane")]
            FleetAction::Revoke { .. } => {}
        }
    }
    Ok(u64::try_from(active_incidents.len()).unwrap_or(u64::MAX))
}
