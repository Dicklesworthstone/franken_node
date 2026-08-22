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

use fsqlite::{Connection, SqliteValue};

use super::fleet_transport::{
    FleetAction, FleetActionRecord, FleetSharedState, FleetTransport, FleetTransportError,
    NodeStatus, FLEET_ACTION_LOG_FILE,
};

const FLEET_DB_FILE: &str = "fleet-state.db";
const FLEET_DB_SCHEMA_VERSION: &str = "franken-node/fleet-durable-store/v1";
const META_INITIALIZED_KEY: &str = "initialized";
const META_JSONL_IMPORT_KEY: &str = "legacy_jsonl_imported";
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
        operation: impl FnOnce(&Connection) -> Result<T, FleetTransportError>,
    ) -> Result<T, FleetTransportError> {
        let guard = self
            .connection
            .lock()
            .map_err(|_| FleetTransportError::io("fleet db mutex poisoned".to_string()))?;
        let connection = guard
            .as_ref()
            .ok_or_else(|| FleetTransportError::io("fleet db connection closed".to_string()))?;
        operation(connection)
    }

    fn ensure_initialized(&self) -> Result<(), FleetTransportError> {
        let flag = self.with_connection(|connection| {
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

            connection.execute(
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
        let raw = std::fs::read_to_string(&actions_path)
            .map_err(|err| FleetTransportError::io(format!("read {}: {err}", actions_path.display())))?;
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
        let entries =
            std::fs::read_dir(&nodes_dir).map_err(|err| FleetTransportError::io(err.to_string()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path)
                .map_err(|err| FleetTransportError::io(format!("read {}: {err}", path.display())))?;
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
        connection
            .execute_with_params(
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
        Ok(())
    }

    fn upsert_status(
        connection: &Connection,
        status: &NodeStatus,
    ) -> Result<(), FleetTransportError> {
        let status_json = serde_json::to_string(status)
            .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
        connection
            .execute_with_params(
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
        Ok(())
    }

    fn query_actions(connection: &Connection) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        // Ordering contract mirrors FileFleetTransport::read_shared_state:
        // emitted_at, then action_id.
        let rows = connection
            .query(
                "SELECT action_json FROM fleet_actions
                 ORDER BY emitted_at ASC, action_id ASC;",
            )
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        rows.iter().map(|row| parse_row_json(&row.values()[0], "action_json")).collect()
    }

    fn query_nodes(connection: &Connection) -> Result<Vec<NodeStatus>, FleetTransportError> {
        let rows = connection
            .query(
                "SELECT status_json FROM fleet_nodes ORDER BY zone_id ASC, node_id ASC;",
            )
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        rows.iter().map(|row| parse_row_json(&row.values()[0], "status_json")).collect()
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
            Ok((Self::query_actions(connection)?, Self::query_nodes(connection)?))
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_action(action_id: &str, incident_id: &str) -> FleetActionRecord {
        FleetActionRecord {
            action_id: action_id.to_string(),
            emitted_at: Utc::now(),
            action: FleetAction::Quarantine {
                zone_id: "zone-a".to_string(),
                incident_id: incident_id.to_string(),
                target_id: "ext-1".to_string(),
                target_kind: super::super::fleet_transport::FleetTargetKind::Extension,
                reason: "test".to_string(),
                quarantine_version: 1,
            },
        }
    }

    fn release_action(action_id: &str, incident_id: &str) -> FleetActionRecord {
        FleetActionRecord {
            action_id: action_id.to_string(),
            emitted_at: Utc::now(),
            action: FleetAction::Release {
                zone_id: "zone-a".to_string(),
                incident_id: incident_id.to_string(),
                reason: Some("test".to_string()),
            },
        }
    }

    fn sample_node(node_id: &str) -> NodeStatus {
        NodeStatus {
            zone_id: "zone-a".to_string(),
            node_id: node_id.to_string(),
            last_seen: Utc::now(),
            quarantine_version: 0,
            health: super::super::fleet_transport::NodeHealth::Healthy,
        }
    }

    #[test]
    fn writes_survive_reopen_and_read_back_in_contract_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join("fleet");
        {
            let mut transport = DurableFleetTransport::new(&state_dir).expect("open");
            transport.initialize().expect("initialize");
            transport
                .publish_action(&sample_action("a-2", "inc-2"))
                .expect("publish a-2");
            transport
                .publish_action(&sample_action("a-1", "inc-1"))
                .expect("publish a-1");
            transport
                .upsert_node_status(&sample_node("node-1"))
                .expect("upsert node");
        }

        let mut reopened = DurableFleetTransport::new(&state_dir).expect("reopen");
        reopened.initialize().expect("re-initialize is idempotent");
        let actions = reopened.list_actions().expect("list actions");
        assert_eq!(actions.len(), 2, "both actions survive reopen");
        assert_eq!(actions[0].action_id, "a-1", "sorted by action_id within equal timestamps");
        let nodes = reopened.list_node_statuses().expect("list nodes");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node-1");
        let state = reopened.read_shared_state().expect("shared state");
        assert_eq!(state.actions.len(), 2);
        assert_eq!(state.nodes.len(), 1);
    }

    #[test]
    fn republishing_same_action_id_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
        transport.initialize().expect("initialize");
        transport
            .publish_action(&sample_action("a-1", "inc-1"))
            .expect("publish first");
        transport
            .publish_action(&sample_action("a-1", "inc-1"))
            .expect("republish same id");
        assert_eq!(transport.list_actions().expect("list").len(), 1);
    }

    #[test]
    fn reads_fail_closed_before_initialize() {
        let dir = tempfile::tempdir().expect("tempdir");
        let transport = DurableFleetTransport::new(dir.path()).expect("open");
        let err = transport
            .list_actions()
            .expect_err("uninitialized transport must fail closed");
        assert!(matches!(err, FleetTransportError::NotInitialized { .. }));
    }

    #[test]
    fn legacy_jsonl_layout_imports_once_and_rollback_restores_import() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().join("fleet");
        std::fs::create_dir_all(state_dir.join("nodes")).expect("nodes dir");

        let record = sample_action("legacy-1", "inc-legacy");
        std::fs::write(
            state_dir.join(FLEET_ACTION_LOG_FILE),
            format!("{}\n", serde_json::to_string(&record).expect("serialize")),
        )
        .expect("write legacy actions.jsonl");
        let node = sample_node("legacy-node");
        std::fs::write(
            state_dir.join("nodes").join("node-legacy-node.json"),
            serde_json::to_string_pretty(&node).expect("serialize node"),
        )
        .expect("write legacy node file");

        let mut transport = DurableFleetTransport::new(&state_dir).expect("open");
        transport.initialize().expect("initialize imports legacy");
        assert_eq!(transport.list_actions().expect("list").len(), 1);
        assert_eq!(transport.list_node_statuses().expect("nodes").len(), 1);

        // Re-initializing the SAME database must not double-import.
        transport.initialize().expect("second initialize");
        assert_eq!(transport.list_actions().expect("list").len(), 1);
        drop(transport);

        // Rollback = delete the database; the importer re-runs from JSONL.
        std::fs::remove_file(state_dir.join(FLEET_DB_FILE)).expect("remove db");
        let _ = std::fs::remove_file(state_dir.join(format!("{FLEET_DB_FILE}-wal")));
        let _ = std::fs::remove_file(state_dir.join(format!("{FLEET_DB_FILE}-shm")));
        let mut rolled_back = DurableFleetTransport::new(&state_dir).expect("reopen");
        rolled_back.initialize().expect("re-import after rollback");
        let actions = rolled_back.list_actions().expect("list");
        assert_eq!(actions.len(), 1, "legacy record restored exactly once");
        assert_eq!(actions[0].action_id, "legacy-1");
    }

    #[test]
    fn quarantine_incident_count_matches_file_reader_semantics() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut transport = DurableFleetTransport::new(dir.path()).expect("open");
        transport.initialize().expect("initialize");
        transport
            .publish_action(&sample_action("q-1", "inc-1"))
            .expect("quarantine inc-1");
        transport
            .publish_action(&sample_action("q-2", "inc-2"))
            .expect("quarantine inc-2");
        transport
            .publish_action(&release_action("r-1", "inc-1"))
            .expect("release inc-1");

        let count =
            count_active_quarantine_actions(dir.path()).expect("count from durable store");
        assert_eq!(count, 1, "only inc-2 remains active");

        // Missing database behaves like the missing actions.jsonl case: zero.
        let empty = tempfile::tempdir().expect("empty tempdir");
        assert_eq!(
            count_active_quarantine_actions(empty.path()).expect("missing db"),
            0
        );
    }
}
