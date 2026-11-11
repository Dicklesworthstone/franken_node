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
//! Storage behavior under the shared [`FleetTransport`] contract:
//! * actions are keyed by `action_id`; exact retries are deduplicated and
//!   different records with the same ID are rejected without changing history;
//! * action and node capacity is checked in the admitting transaction, without
//!   evicting retained containment or recorded nodes; retries and heartbeats for
//!   existing records remain usable at capacity;
//! * shared-state readers use one database snapshot for actions and node
//!   checkpoints, including when another process is publishing concurrently;
//! * torn trailing lines cannot happen (transactions are atomic);
//! * cross-process contention is handled by SQLite busy-timeout instead of
//!   ad-hoc flock files.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use fsqlite::compat::{Transaction, TransactionExt};
use fsqlite::{Connection, SqliteValue};

use crate::capacity_defaults::aliases::{MAX_ACTION_LOG_ENTRIES, MAX_NODES_CAP};

use super::fleet_transport::{
    FLEET_ACTION_LOG_FILE, FLEET_GUARDED_POLICY_RECEIPT_SCHEMA, FleetAction, FleetActionRecord,
    FleetGuardedPolicyObservationScope, FleetGuardedPolicyReceipt, FleetSharedState, FleetTransport,
    FleetTransportError, GuardedFleetPolicyPublication, MAX_ACTION_RECORD_BYTES,
    MAX_GUARDED_POLICY_RECEIPT_BYTES, MAX_GUARDED_POLICY_STALE_AFTER, NodeStatus, validate_action_record,
    validate_fleet_native_session_publication, validate_fleet_policy_publication,
    validate_guarded_fleet_policy_publication, validate_node_status,
};

const FLEET_DB_FILE: &str = "fleet-state.db";
const FLEET_DB_SCHEMA_VERSION: &str = "franken-node/fleet-durable-store/v1";
const META_INITIALIZED_KEY: &str = "initialized";
const META_JSONL_IMPORT_KEY: &str = "legacy_jsonl_imported";
const META_MUTATION_CONFLICT_KEY: &str = "action_node_mutation_conflict";
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

fn parse_action_row(value: &SqliteValue) -> Result<FleetActionRecord, FleetTransportError> {
    let raw = text(value, "action_json")?;
    if raw.len() > MAX_ACTION_RECORD_BYTES {
        return Err(FleetTransportError::serialization(format!(
            "stored fleet action exceeds {MAX_ACTION_RECORD_BYTES} bytes"
        )));
    }
    let record: FleetActionRecord = serde_json::from_str(&raw)
        .map_err(|err| FleetTransportError::serialization(format!("column action_json: {err}")))?;
    validate_action_record(&record)?;
    Ok(record)
}

/// The caller holds the write transaction that inserted or updated a record.
/// Checking after the upsert permits exact action retries and existing-node
/// heartbeats at capacity, while a new over-capacity row is rolled back with
/// the rest of its transaction. Never drop an older obligation to make room.
fn enforce_table_capacity(
    tx: &Transaction<'_>,
    table: &str,
    capacity: usize,
) -> Result<(), FleetTransportError> {
    let rows = tx
        .query(&format!("SELECT COUNT(*) FROM {table};"))
        .map_err(|err| FleetTransportError::io(err.to_string()))?;
    let count = match rows.as_slice() {
        [row] => match row.values() {
            [SqliteValue::Integer(count)] => usize::try_from(*count).map_err(|_| {
                FleetTransportError::serialization(format!("{table}: invalid stored record count"))
            })?,
            _ => {
                return Err(FleetTransportError::serialization(format!(
                    "{table}: invalid stored record count"
                )));
            }
        },
        _ => {
            return Err(FleetTransportError::serialization(format!(
                "{table}: missing stored record count"
            )));
        }
    };
    if count > capacity {
        return Err(FleetTransportError::serialization(format!(
            "{table} exceeds the maximum {capacity} records; refusing to discard retained fleet state"
        )));
    }
    Ok(())
}

/// Every action/status writer changes this same row inside its transaction.
/// A guarded publication cannot commit a decision from an older node snapshot
/// while another writer changes an unrelated node/action row. The value only
/// forces a real write conflict; it is not an epoch or externally visible clock.
fn serialize_fleet_mutation(tx: &Transaction<'_>) -> Result<(), FleetTransportError> {
    tx.execute_with_params(
        "INSERT INTO fleet_meta(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        &[
            SqliteValue::Text(META_MUTATION_CONFLICT_KEY.into()),
            SqliteValue::Text(uuid::Uuid::now_v7().to_string().into()),
        ],
    )
    .map_err(|error| FleetTransportError::io(error.to_string()))?;
    Ok(())
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
        // bd-ymbjw: publication/status transactions roll back before an error
        // escapes the closure. Retry the complete operation with a fresh
        // snapshot; never retry only the last statement of an admission.
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
            Self::upsert_status(connection, &status, None)?;
            imported += 1;
        }
        Ok(imported)
    }

    fn insert_action(
        connection: &Connection,
        record: &FleetActionRecord,
    ) -> Result<(), FleetTransportError> {
        validate_action_record(record)?;
        // Explicit transaction: the commit is the WAL-durable boundary under
        // synchronous=FULL; a bare statement can sit in the retained
        // autocommit overlay and die with the process.
        let mut tx = connection
            .transaction()
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        serialize_fleet_mutation(&tx)?;
        Self::insert_action_in_transaction(&tx, record)?;
        tx.commit()
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        Ok(())
    }

    fn insert_action_in_transaction(
        tx: &Transaction<'_>,
        record: &FleetActionRecord,
    ) -> Result<(), FleetTransportError> {
        validate_action_record(record)?;
        let action_json = serde_json::to_string(record)
            .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
        if matches!(
            &record.action,
            FleetAction::PolicyUpdate {
                artifact: Some(_),
                ..
            } | FleetAction::NativeSessionHold { .. }
                | FleetAction::NativeSessionResume { .. }
        ) {
            let rows = tx
                .query(&format!(
                    "SELECT action_json FROM fleet_actions ORDER BY seq ASC LIMIT {};",
                    MAX_ACTION_LOG_ENTRIES.saturating_add(1)
                ))
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            if rows.len() > MAX_ACTION_LOG_ENTRIES {
                return Err(FleetTransportError::serialization(
                    "fleet policy history exceeds the action bound",
                ));
            }
            let existing = rows
                .iter()
                .map(|row| parse_action_row(&row.values()[0]))
                .collect::<Result<Vec<_>, _>>()?;
            validate_fleet_policy_publication(record, &existing)?;
            validate_fleet_native_session_publication(record, &existing)?;
        }
        tx.execute_with_params(
            "INSERT INTO fleet_actions(action_id, emitted_at, action_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(action_id) DO NOTHING;",
            &[
                SqliteValue::Text(record.action_id.clone().into()),
                SqliteValue::Text(record.emitted_at.to_rfc3339().into()),
                SqliteValue::Text(action_json.into()),
            ],
        )
        .map_err(|err| FleetTransportError::io(err.to_string()))?;
        // Compare inside the same transaction that admitted the ID. The
        // unique index chooses one record even across independent processes;
        // snapshot conflicts retry the complete transaction, never an update.
        // A mismatched retry rolls back and cannot rewrite a past quarantine,
        // release, timestamp or target that another node already consumed.
        let rows = tx
            .query_with_params(
                "SELECT action_json FROM fleet_actions WHERE action_id = ?1;",
                &[SqliteValue::Text(record.action_id.clone().into())],
            )
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        let [row] = rows.as_slice() else {
            return Err(FleetTransportError::io(
                "fleet action admission did not resolve exactly one stored record",
            ));
        };
        if parse_action_row(&row.values()[0])? != *record {
            return Err(FleetTransportError::action_conflict(format!(
                "action_id `{}` already identifies a different fleet action",
                record.action_id
            )));
        }
        enforce_table_capacity(tx, "fleet_actions", MAX_ACTION_LOG_ENTRIES)?;
        Ok(())
    }

    fn upsert_status(
        connection: &Connection,
        status: &NodeStatus,
        supervisor_root: Option<&ed25519_dalek::VerifyingKey>,
    ) -> Result<(), FleetTransportError> {
        validate_node_status(status)?;
        let status_json = serde_json::to_string(status)
            .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
        let mut tx = connection
            .transaction()
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        serialize_fleet_mutation(&tx)?;
        if let Some(root) = supervisor_root {
            Self::retain_supervisor_head(&tx, status, &status_json, root)?;
        }
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
        enforce_table_capacity(&tx, "fleet_nodes", MAX_NODES_CAP)?;
        tx.commit()
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        Ok(())
    }

    /// Retain authenticated monotonic identity separately from availability.
    /// A degraded heartbeat may clear its public drain without erasing the
    /// last signed project/generation or making an old good receipt reusable.
    fn retain_supervisor_head(
        tx: &Transaction<'_>,
        status: &NodeStatus,
        status_json: &str,
        root: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), FleetTransportError> {
        let identity = [
            SqliteValue::Text(status.zone_id.clone().into()),
            SqliteValue::Text(status.node_id.clone().into()),
        ];
        let rows = tx.query_with_params(
            "SELECT status_json FROM fleet_node_supervisor_heads WHERE zone_id = ?1 AND node_id = ?2;",
            &identity,
        ).map_err(|error| FleetTransportError::io(error.to_string()))?;
        let current = tx
            .query_with_params(
                "SELECT status_json FROM fleet_nodes WHERE zone_id = ?1 AND node_id = ?2;",
                &identity,
            )
            .map_err(|error| FleetTransportError::io(error.to_string()))?;
        let current: Option<NodeStatus> = current
            .first()
            .map(|row| parse_row_json(&row.values()[0], "status_json"))
            .transpose()?;
        if let Some(current) = &current {
            validate_node_status(current)?;
            // The coordinator stamps requests before serializing their writes.
            // Reject an older request even when it carries no drain, so two
            // reordered degraded heartbeats cannot lower the withdrawal barrier.
            if status.last_seen < current.last_seen {
                return Err(FleetTransportError::stale_state(
                    "enrolled node heartbeat precedes its retained coordinator timestamp",
                ));
            }
        }
        let next = match &status.native_session_drain {
            Some(drain) => {
                let attestation = drain.supervisor_attestation.as_ref().ok_or_else(|| {
                    FleetTransportError::serialization(
                        "enrolled supervisor requires a signed native drain observation",
                    )
                })?;
                attestation.verify(drain, &status.node_id, &status.zone_id, root)?;
                Some(attestation)
            }
            None => None,
        };
        if let Some(row) = rows.first() {
            let previous: NodeStatus = parse_row_json(&row.values()[0], "supervisor_head_json")?;
            validate_node_status(&previous)?;
            let drain = previous.native_session_drain.as_ref().ok_or_else(|| {
                FleetTransportError::serialization("retained supervisor head lost its signed drain")
            })?;
            let attestation = drain.supervisor_attestation.as_ref().ok_or_else(|| {
                FleetTransportError::serialization("retained supervisor head lost its signature")
            })?;
            attestation.verify(drain, &status.node_id, &status.zone_id, root)?;
            if let Some(next) = next {
                next.validate_successor_of(attestation)?;
                if next.generation == attestation.generation
                    && status.native_session_drain.as_ref().is_some_and(|current| {
                        current.session_set_sha256 != drain.session_set_sha256
                            || current.admitted_sessions != drain.admitted_sessions
                    })
                {
                    return Err(FleetTransportError::stale_state(
                        "native supervisor drain generation cannot replace its retained session population",
                    ));
                }
                if let Some(current) = &current {
                    if current
                        .native_session_drain
                        .as_ref()
                        .and_then(|drain| drain.supervisor_attestation.as_ref())
                        .is_none()
                        && next.observed_at <= current.last_seen
                    {
                        return Err(FleetTransportError::stale_state(
                            "native drain evidence was withdrawn; a new supervisor observation is required",
                        ));
                    }
                }
            }
        }
        if next.is_some() {
            tx.execute_with_params(
                "INSERT INTO fleet_node_supervisor_heads(zone_id, node_id, status_json)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(zone_id, node_id) DO UPDATE SET status_json = excluded.status_json;",
                &[
                    identity[0].clone(),
                    identity[1].clone(),
                    SqliteValue::Text(status_json.to_owned().into()),
                ],
            )
            .map_err(|error| FleetTransportError::io(error.to_string()))?;
            enforce_table_capacity(tx, "fleet_node_supervisor_heads", MAX_NODES_CAP)?;
        }
        Ok(())
    }

    /// Coordinator ingestion with an independently enrolled supervisor root.
    /// The status and retained signature head commit in the same WAL transaction.
    #[cfg(feature = "fleet-control-plane-server")]
    pub(super) fn upsert_node_status_with_supervisor(
        &mut self,
        status: &NodeStatus,
        root: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), FleetTransportError> {
        self.ensure_initialized()?;
        self.with_connection(|connection| Self::upsert_status(connection, status, Some(root)))
    }

    fn query_actions(
        connection: &Connection,
    ) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        // The committed sequence matches the file log's append order. Issuer
        // clocks cannot reorder a quarantine relative to its release.
        let rows = connection
            .query(&format!(
                "SELECT action_json FROM fleet_actions
                 ORDER BY seq ASC LIMIT {};",
                MAX_ACTION_LOG_ENTRIES.saturating_add(1)
            ))
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        if rows.len() > MAX_ACTION_LOG_ENTRIES {
            return Err(FleetTransportError::serialization(format!(
                "stored fleet action snapshot exceeds {MAX_ACTION_LOG_ENTRIES} entries"
            )));
        }
        rows.iter()
            .map(|row| parse_action_row(&row.values()[0]))
            .collect()
    }

    fn query_nodes(connection: &Connection) -> Result<Vec<NodeStatus>, FleetTransportError> {
        let rows = connection
            .query(&format!(
                "SELECT status_json FROM fleet_nodes ORDER BY zone_id ASC, node_id ASC LIMIT {};",
                MAX_NODES_CAP.saturating_add(1)
            ))
            .map_err(|err| FleetTransportError::io(err.to_string()))?;
        if rows.len() > MAX_NODES_CAP {
            return Err(FleetTransportError::serialization(format!(
                "stored fleet node snapshot exceeds {MAX_NODES_CAP} entries"
            )));
        }
        rows.iter()
            .map(|row| {
                let status = parse_row_json(&row.values()[0], "status_json")?;
                validate_node_status(&status)?;
                Ok(status)
            })
            .collect()
    }

    /// Atomically publish under a maintenance hold after projecting the
    /// transaction's actual node snapshot. The HTTP coordinator supplies its
    /// incarnation-bound enrolled-heartbeat projection here; it must never
    /// substitute evidence received from the publishing client.
    ///
    /// Both callbacks are rerun after a snapshot conflict. `now` is sampled
    /// after the node projection, so a retried admission cannot reuse an older
    /// freshness decision. Original committed receipts are returned unchanged
    /// apart from the explicit retry flag, including after a later resume.
    pub fn publish_policy_with_maintenance_guard_projected(
        &mut self,
        request: &GuardedFleetPolicyPublication,
        observation_scope: FleetGuardedPolicyObservationScope,
        max_stale_after: Duration,
        now: impl Fn() -> DateTime<Utc>,
        project_nodes: impl Fn(&mut Vec<NodeStatus>) -> Result<(), FleetTransportError>,
    ) -> Result<FleetGuardedPolicyReceipt, FleetTransportError> {
        request.validate()?;
        if max_stale_after.is_zero() {
            return Err(FleetTransportError::stale_state(
                "guarded policy coordinator freshness must be positive",
            ));
        }
        self.ensure_initialized()?;
        self.with_connection(|connection| {
            let mut tx = connection
                .transaction()
                .map_err(|error| FleetTransportError::io(error.to_string()))?;
            serialize_fleet_mutation(&tx)?;
            let retained = tx
                .query_with_params(
                    "SELECT hold_action_id, receipt_json FROM fleet_guarded_policy_publications
                     WHERE action_id = ?1;",
                    &[SqliteValue::Text(request.action.action_id.clone().into())],
                )
                .map_err(|error| FleetTransportError::io(error.to_string()))?;
            if let [row] = retained.as_slice() {
                let [owner, receipt_json] = row.values() else {
                    return Err(FleetTransportError::serialization(
                        "stored guarded policy receipt has an invalid row shape",
                    ));
                };
                let raw = text(receipt_json, "receipt_json")?;
                if raw.len() > MAX_GUARDED_POLICY_RECEIPT_BYTES {
                    return Err(FleetTransportError::serialization(
                        "stored guarded policy receipt exceeds its byte bound",
                    ));
                }
                let mut receipt: FleetGuardedPolicyReceipt = serde_json::from_str(&raw)
                    .map_err(|error| FleetTransportError::serialization(error.to_string()))?;
                receipt.validate()?;
                if receipt.already_published
                    || text(owner, "hold_action_id")? != receipt.guard.hold_action_id
                {
                    return Err(FleetTransportError::serialization(
                        "stored guarded policy receipt has inconsistent admission identity",
                    ));
                }
                if receipt.action != request.action
                    || receipt.guard.hold_action_id != request.guard.hold_action_id
                {
                    return Err(FleetTransportError::action_conflict(
                        "guarded policy action already belongs to a different action or hold",
                    ));
                }
                let actions = tx
                    .query_with_params(
                        "SELECT action_json FROM fleet_actions WHERE action_id = ?1;",
                        &[SqliteValue::Text(request.action.action_id.clone().into())],
                    )
                    .map_err(|error| FleetTransportError::io(error.to_string()))?;
                if actions.len() != 1
                    || parse_action_row(&actions[0].values()[0])? != receipt.action
                {
                    return Err(FleetTransportError::serialization(
                        "guarded policy receipt no longer matches its immutable action",
                    ));
                }
                receipt.already_published = true;
                tx.commit()
                    .map_err(|error| FleetTransportError::io(error.to_string()))?;
                return Ok(receipt);
            }
            if !retained.is_empty() {
                return Err(FleetTransportError::serialization(
                    "guarded policy receipt identity is not unique",
                ));
            }
            let mut state = FleetSharedState {
                schema_version: super::fleet_transport::FLEET_SHARED_STATE_SCHEMA.to_owned(),
                actions: Self::query_actions(connection)?,
                nodes: Self::query_nodes(connection)?,
            };
            project_nodes(&mut state.nodes)?;
            let accepted_at = now();
            let evidence = validate_guarded_fleet_policy_publication(
                request,
                &state,
                accepted_at,
                max_stale_after.min(MAX_GUARDED_POLICY_STALE_AFTER),
            )?;
            let receipt = FleetGuardedPolicyReceipt {
                schema_version: FLEET_GUARDED_POLICY_RECEIPT_SCHEMA.to_owned(),
                action: request.action.clone(),
                guard: request.guard.clone(),
                evidence,
                accepted_at,
                observation_scope,
                already_published: false,
                fleet_quiescence_certified: false,
            };
            // Reject oversized or contradictory evidence before appending
            // either record. A failed commit rolls both records back together.
            receipt.validate()?;
            let receipt_json = serde_json::to_string(&receipt)
                .map_err(|error| FleetTransportError::serialization(error.to_string()))?;
            Self::insert_action_in_transaction(&tx, &request.action)?;
            tx.execute_with_params(
                "INSERT INTO fleet_guarded_policy_publications(action_id, hold_action_id, receipt_json)
                 VALUES (?1, ?2, ?3);",
                &[
                    SqliteValue::Text(request.action.action_id.clone().into()),
                    SqliteValue::Text(request.guard.hold_action_id.clone().into()),
                    SqliteValue::Text(receipt_json.into()),
                ],
            )
            .map_err(|error| FleetTransportError::io(error.to_string()))?;
            enforce_table_capacity(&tx, "fleet_guarded_policy_publications", MAX_ACTION_LOG_ENTRIES)?;
            tx.commit()
                .map_err(|error| FleetTransportError::io(error.to_string()))?;
            Ok(receipt)
        })
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
                .execute(
                    "CREATE TABLE IF NOT EXISTS fleet_node_supervisor_heads (
                        zone_id TEXT NOT NULL,
                        node_id TEXT NOT NULL,
                        status_json TEXT NOT NULL,
                        PRIMARY KEY (zone_id, node_id)
                    );",
                )
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS fleet_guarded_policy_publications (
                        action_id TEXT PRIMARY KEY REFERENCES fleet_actions(action_id),
                        hold_action_id TEXT NOT NULL,
                        receipt_json TEXT NOT NULL
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

    fn publish_policy_with_maintenance_guard(
        &mut self,
        request: &GuardedFleetPolicyPublication,
    ) -> Result<FleetGuardedPolicyReceipt, FleetTransportError> {
        self.publish_policy_with_maintenance_guard_projected(
            request,
            FleetGuardedPolicyObservationScope::LocalSupervisorObservations,
            MAX_GUARDED_POLICY_STALE_AFTER,
            Utc::now,
            |_| Ok(()),
        )
    }

    fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        self.ensure_initialized()?;
        self.with_connection(Self::query_actions)
    }

    fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
        self.ensure_initialized()?;
        self.with_connection(|connection| Self::upsert_status(connection, status, None))
    }

    fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
        self.ensure_initialized()?;
        self.with_connection(Self::query_nodes)
    }

    fn read_shared_state(&self) -> Result<FleetSharedState, FleetTransportError> {
        self.ensure_initialized()?;
        let (actions, nodes) = self.with_connection(|connection| {
            // The connection mutex only protects this process. Keep both
            // reads in one SQL transaction so a concurrently committed action
            // and application checkpoint cannot produce a mixed-generation
            // status/reconcile response.
            let mut tx = connection
                .transaction()
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            let snapshot = (
                Self::query_actions(connection)?,
                Self::query_nodes(connection)?,
            );
            tx.commit()
                .map_err(|err| FleetTransportError::io(err.to_string()))?;
            Ok(snapshot)
        })?;
        // Preserve the committed action sequence; only node presentation sorts.
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
            FleetAction::PolicyUpdate { .. }
            | FleetAction::NativeSessionHold { .. }
            | FleetAction::NativeSessionResume { .. } => {}
            #[cfg(feature = "control-plane")]
            FleetAction::Revoke { .. } => {}
        }
    }
    Ok(u64::try_from(active_incidents.len()).unwrap_or(u64::MAX))
}
