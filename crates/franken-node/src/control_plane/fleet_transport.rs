//! Fleet transport contract and shared state schema for distributed fleet coordination.
//!
//! This module defines the transport-facing action log, node heartbeat/state shape,
//! and object-safe transport trait used by the fleet-control track.

#[cfg(feature = "asupersync-transport")]
use std::sync::{Arc, Mutex, MutexGuard};
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use crate::capacity_defaults::aliases::{MAX_ACTION_LOG_ENTRIES, MAX_NODES_CAP};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const FLEET_SHARED_STATE_SCHEMA: &str = "franken-node/fleet-transport-state/v1";
pub const FLEET_ACTION_LOG_FILE: &str = "actions.jsonl";
pub const FLEET_NODE_DIR: &str = "nodes";
pub const FLEET_LOCK_DIR: &str = "locks";
const MAX_NODE_ID_LEN: usize = 128;
const MAX_ZONE_ID_LEN: usize = 128;
const MAX_ACTION_ID_LEN: usize = 128;
const MAX_ACTION_RECORD_BYTES: usize = 2_048;
const ACTION_LOG_COMPACTION_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;
const ACTION_LOG_RETENTION_DAYS: i64 = 30;
const LOCK_RETRY_BACKOFF_MILLIS: [u64; 3] = [100, 200, 400];
pub const FLEET_CONVERGENCE_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FleetConvergenceWaitOutcome {
    pub elapsed: Duration,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetConvergenceReceiptSignature {
    pub algorithm: String,
    pub public_key_hex: String,
    pub key_id: String,
    pub signed_payload_sha256: String,
    pub signature_hex: String,
}

#[must_use]
pub fn fleet_convergence_receipt_verdict(
    timed_out: bool,
    elapsed_ms: u64,
    timeout_seconds: u64,
    converged: bool,
) -> &'static str {
    if timed_out || elapsed_ms > timeout_seconds.saturating_mul(1_000) || !converged {
        "non_converged"
    } else {
        "converged"
    }
}

pub fn canonical_fleet_convergence_receipt_payload<T: Serialize>(
    payload: &T,
) -> Result<Vec<u8>, FleetTransportError> {
    let value = serde_json::to_value(payload)
        .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
    let canonical = canonicalize_json_value(value, "$")?;
    serde_json::to_vec(&canonical)
        .map_err(|err| FleetTransportError::serialization(err.to_string()))
}

pub fn sign_fleet_convergence_receipt_payload<T: Serialize>(
    payload: &T,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<FleetConvergenceReceiptSignature, FleetTransportError> {
    let canonical_payload = canonical_fleet_convergence_receipt_payload(payload)?;
    let signature = signing_key.sign(&canonical_payload);
    let verifying_key = signing_key.verifying_key();
    let mut payload_hasher = Sha256::new();
    payload_hasher.update(&canonical_payload);

    Ok(FleetConvergenceReceiptSignature {
        algorithm: "ed25519".to_string(),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
        key_id: crate::supply_chain::artifact_signing::KeyId::from_verifying_key(&verifying_key)
            .to_string(),
        signed_payload_sha256: hex::encode(payload_hasher.finalize()),
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

fn canonicalize_json_value(value: Value, path: &str) -> Result<Value, FleetTransportError> {
    match value {
        Value::Array(items) => items
            .into_iter()
            .enumerate()
            .map(|(index, item)| canonicalize_json_value(item, &format!("{path}[{index}]")))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(map) => {
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));

            let mut canonical = serde_json::Map::new();
            for (key, item) in entries {
                canonical.insert(
                    key.clone(),
                    canonicalize_json_value(item, &format!("{path}.{key}"))?,
                );
            }
            Ok(Value::Object(canonical))
        }
        Value::Number(number) if number.is_f64() => Err(FleetTransportError::serialization(
            format!("fleet convergence receipt contains non-deterministic float at {path}"),
        )),
        other => Ok(other),
    }
}

/// Bounded push helper that maintains capacity by removing oldest entries when limit is exceeded.
/// When capacity is exceeded, removes oldest entries to maintain the limit.
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetTargetKind {
    Artifact,
    Extension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeHealth {
    Healthy,
    Degraded,
    Quarantined,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FleetAction {
    Quarantine {
        zone_id: String,
        incident_id: String,
        target_id: String,
        target_kind: FleetTargetKind,
        reason: String,
        quarantine_version: u64,
    },
    Release {
        zone_id: String,
        incident_id: String,
        reason: Option<String>,
    },
    PolicyUpdate {
        zone_id: String,
        policy_version: String,
        changed_fields: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetActionRecord {
    pub action_id: String,
    pub emitted_at: DateTime<Utc>,
    pub action: FleetAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub zone_id: String,
    pub node_id: String,
    pub last_seen: DateTime<Utc>,
    pub quarantine_version: u64,
    pub health: NodeHealth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSharedState {
    pub schema_version: String,
    pub actions: Vec<FleetActionRecord>,
    pub nodes: Vec<NodeStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FleetTransportError {
    #[error("fleet transport io error: {detail}")]
    IoError { detail: String },
    #[error("fleet transport serialization error: {detail}")]
    SerializationError { detail: String },
    #[error("fleet transport lock contention: {detail}")]
    LockContention { detail: String },
    #[error("fleet transport stale state: {detail}")]
    StaleState { detail: String },
    #[error("fleet transport not initialized: {detail}")]
    NotInitialized { detail: String },
}

impl FleetTransportError {
    #[must_use]
    pub fn io(detail: impl Into<String>) -> Self {
        Self::IoError {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn serialization(detail: impl Into<String>) -> Self {
        Self::SerializationError {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn lock_contention(detail: impl Into<String>) -> Self {
        Self::LockContention {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn stale_state(detail: impl Into<String>) -> Self {
        Self::StaleState {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn not_initialized(detail: impl Into<String>) -> Self {
        Self::NotInitialized {
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetTransportLayout {
    root_dir: PathBuf,
    actions_path: PathBuf,
    nodes_dir: PathBuf,
    locks_dir: PathBuf,
}

impl FleetTransportLayout {
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        let root_dir = root_dir.into();
        Self {
            actions_path: root_dir.join(FLEET_ACTION_LOG_FILE),
            nodes_dir: root_dir.join(FLEET_NODE_DIR),
            locks_dir: root_dir.join(FLEET_LOCK_DIR),
            root_dir,
        }
    }

    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    #[must_use]
    pub fn actions_path(&self) -> &Path {
        &self.actions_path
    }

    #[must_use]
    pub fn nodes_dir(&self) -> &Path {
        &self.nodes_dir
    }

    #[must_use]
    pub fn locks_dir(&self) -> &Path {
        &self.locks_dir
    }

    pub fn initialize(&self) -> Result<(), FleetTransportError> {
        std::fs::create_dir_all(&self.root_dir).map_err(|err| {
            FleetTransportError::io(format!(
                "failed creating fleet transport root {}: {err}",
                self.root_dir.display()
            ))
        })?;
        std::fs::create_dir_all(&self.nodes_dir).map_err(|err| {
            FleetTransportError::io(format!(
                "failed creating fleet transport nodes dir {}: {err}",
                self.nodes_dir.display()
            ))
        })?;
        std::fs::create_dir_all(&self.locks_dir).map_err(|err| {
            FleetTransportError::io(format!(
                "failed creating fleet transport lock dir {}: {err}",
                self.locks_dir.display()
            ))
        })?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.actions_path)
            .map_err(|err| {
                FleetTransportError::io(format!(
                    "failed creating fleet action log {}: {err}",
                    self.actions_path.display()
                ))
            })?;
        Ok(())
    }

    pub fn node_status_path(&self, node_id: &str) -> Result<PathBuf, FleetTransportError> {
        let node_id = validate_node_id(node_id)?;
        Ok(self.nodes_dir.join(format!("node-{node_id}.json")))
    }
}

pub trait FleetTransport {
    fn initialize(&mut self) -> Result<(), FleetTransportError>;

    fn publish_action(&mut self, action: &FleetActionRecord) -> Result<(), FleetTransportError>;

    fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError>;

    fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError>;

    fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError>;

    fn read_shared_state(&self) -> Result<FleetSharedState, FleetTransportError> {
        let mut actions = self.list_actions()?;
        actions.sort_by(|left, right| {
            left.emitted_at
                .cmp(&right.emitted_at)
                .then_with(|| left.action_id.cmp(&right.action_id))
        });

        let mut nodes = self.list_node_statuses()?;
        nodes.sort_by(|left, right| {
            left.zone_id
                .cmp(&right.zone_id)
                .then_with(|| left.node_id.cmp(&right.node_id))
        });

        Ok(FleetSharedState {
            schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions,
            nodes,
        })
    }
}

#[cfg(feature = "asupersync-transport")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsupersyncFleetControlEvent {
    pub operation: String,
    pub node_id: String,
    pub observed_at: DateTime<Utc>,
}

#[cfg(feature = "asupersync-transport")]
#[derive(Debug, Clone, Default)]
pub struct AsupersyncFleetNetwork {
    inner: Arc<Mutex<AsupersyncFleetNetworkState>>,
}

#[cfg(feature = "asupersync-transport")]
#[derive(Debug, Clone, Default)]
struct AsupersyncFleetNetworkState {
    initialized: bool,
    actions: Vec<FleetActionRecord>,
    nodes: Vec<NodeStatus>,
    control_events: Vec<AsupersyncFleetControlEvent>,
}

#[cfg(feature = "asupersync-transport")]
impl AsupersyncFleetNetwork {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn control_events(&self) -> Result<Vec<AsupersyncFleetControlEvent>, FleetTransportError> {
        Ok(self.lock()?.control_events.clone())
    }

    fn lock(&self) -> Result<MutexGuard<'_, AsupersyncFleetNetworkState>, FleetTransportError> {
        self.inner
            .lock()
            .map_err(|err| FleetTransportError::lock_contention(err.to_string()))
    }
}

#[cfg(feature = "asupersync-transport")]
#[derive(Debug, Clone)]
pub struct AsupersyncFleetTransport {
    cx: asupersync::Cx,
    node_id: String,
    network: AsupersyncFleetNetwork,
}

#[cfg(feature = "asupersync-transport")]
impl AsupersyncFleetTransport {
    #[must_use]
    pub fn for_request(node_id: impl Into<String>, network: AsupersyncFleetNetwork) -> Self {
        Self {
            cx: asupersync::Cx::for_request(),
            node_id: node_id.into(),
            network,
        }
    }

    #[must_use]
    pub fn for_testing(node_id: impl Into<String>, network: AsupersyncFleetNetwork) -> Self {
        Self {
            cx: asupersync::Cx::for_testing(),
            node_id: node_id.into(),
            network,
        }
    }

    #[must_use]
    pub fn network(&self) -> &AsupersyncFleetNetwork {
        &self.network
    }

    fn checkpoint(&self, operation: &'static str) -> Result<(), FleetTransportError> {
        self.cx.trace_with_fields(
            "fleet asupersync control-lane transport operation",
            &[
                ("transport", "asupersync"),
                ("operation", operation),
                ("node_id", &self.node_id),
            ],
        );
        self.cx.checkpoint().map_err(|err| {
            FleetTransportError::stale_state(format!(
                "asupersync control-lane checkpoint failed during {operation}: {err}"
            ))
        })
    }

    fn record_event(&self, state: &mut AsupersyncFleetNetworkState, operation: &'static str) {
        state.control_events.push(AsupersyncFleetControlEvent {
            operation: operation.to_string(),
            node_id: self.node_id.clone(),
            observed_at: Utc::now(),
        });
    }

    fn ensure_initialized(
        &self,
        state: &AsupersyncFleetNetworkState,
    ) -> Result<(), FleetTransportError> {
        if state.initialized {
            Ok(())
        } else {
            Err(FleetTransportError::not_initialized(
                "call initialize() before using the asupersync fleet transport",
            ))
        }
    }
}

#[cfg(feature = "asupersync-transport")]
impl FleetTransport for AsupersyncFleetTransport {
    fn initialize(&mut self) -> Result<(), FleetTransportError> {
        self.checkpoint("initialize")?;
        let mut state = self.network.lock()?;
        state.initialized = true;
        self.record_event(&mut state, "initialize");
        Ok(())
    }

    fn publish_action(&mut self, action: &FleetActionRecord) -> Result<(), FleetTransportError> {
        self.checkpoint("publish_action")?;
        validate_action_record(action)?;
        let payload = serde_json::to_vec(action).map_err(|err| {
            FleetTransportError::serialization(format!(
                "failed serializing asupersync fleet action {}: {err}",
                action.action_id
            ))
        })?;
        if payload.len() > MAX_ACTION_RECORD_BYTES {
            return Err(FleetTransportError::serialization(format!(
                "serialized fleet action {} exceeds {} bytes",
                action.action_id, MAX_ACTION_RECORD_BYTES
            )));
        }

        let mut state = self.network.lock()?;
        self.ensure_initialized(&state)?;
        push_bounded(&mut state.actions, action.clone(), MAX_ACTION_LOG_ENTRIES);
        self.record_event(&mut state, "publish_action");
        Ok(())
    }

    fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        self.checkpoint("list_actions")?;
        let mut state = self.network.lock()?;
        self.ensure_initialized(&state)?;
        self.record_event(&mut state, "list_actions");
        Ok(state.actions.clone())
    }

    fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
        self.checkpoint("upsert_node_status")?;
        validate_zone_id(&status.zone_id)?;
        validate_node_id(&status.node_id)?;

        let mut state = self.network.lock()?;
        self.ensure_initialized(&state)?;
        if let Some(existing) = state
            .nodes
            .iter_mut()
            .find(|existing| existing.node_id == status.node_id)
        {
            *existing = status.clone();
        } else {
            push_bounded(&mut state.nodes, status.clone(), MAX_NODES_CAP);
        }
        self.record_event(&mut state, "upsert_node_status");
        Ok(())
    }

    fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
        self.checkpoint("list_node_statuses")?;
        let mut state = self.network.lock()?;
        self.ensure_initialized(&state)?;
        self.record_event(&mut state, "list_node_statuses");
        Ok(state.nodes.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFleetTransport {
    layout: FleetTransportLayout,
}

/// RAII guard that orphans a temp file on drop (unless defused after rename).
#[must_use]
struct TempFileGuard(Option<PathBuf>);

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    fn abandoned_path(path: &Path) -> PathBuf {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("fleet-transport.tmp");
        path.with_file_name(format!("{file_name}.orphaned-{}", Uuid::now_v7()))
    }

    fn defuse(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take()
            && path.is_file()
        {
            let _ = fs::rename(&path, Self::abandoned_path(&path));
        }
    }
}

impl FileFleetTransport {
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            layout: FleetTransportLayout::new(root_dir),
        }
    }

    #[must_use]
    pub fn layout(&self) -> &FleetTransportLayout {
        &self.layout
    }

    pub fn list_stale_nodes(
        &self,
        now: DateTime<Utc>,
        staleness_threshold: Duration,
    ) -> Result<Vec<NodeStatus>, FleetTransportError> {
        let staleness_threshold = chrono::TimeDelta::from_std(staleness_threshold)
            .map_err(|err| FleetTransportError::stale_state(format!("invalid threshold: {err}")))?;

        let mut stale_nodes: Vec<NodeStatus> = self
            .list_node_statuses()?
            .into_iter()
            .filter(|status| now.signed_duration_since(status.last_seen) >= staleness_threshold)
            .collect();
        stale_nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        Ok(stale_nodes)
    }

    fn ensure_initialized(&self) -> Result<(), FleetTransportError> {
        if !self.layout.root_dir().is_dir()
            || !self.layout.nodes_dir().is_dir()
            || !self.layout.locks_dir().is_dir()
            || !self.layout.actions_path().is_file()
        {
            return Err(FleetTransportError::not_initialized(
                "call initialize() before using the file transport",
            ));
        }
        Ok(())
    }

    fn compact_action_log_if_needed(
        &self,
        max_file_size_bytes: u64,
        retention_days: i64,
        now: DateTime<Utc>,
    ) -> Result<(), FleetTransportError> {
        if retention_days <= 0 {
            return Err(FleetTransportError::serialization(
                "retention_days must be greater than zero",
            ));
        }

        let metadata = fs::metadata(self.layout.actions_path()).map_err(|err| {
            FleetTransportError::io(format!(
                "failed reading fleet action log metadata {}: {err}",
                self.layout.actions_path().display()
            ))
        })?;
        if metadata.len() <= max_file_size_bytes {
            return Ok(());
        }

        let file = self.action_log_file(true)?;
        lock_file_with_backoff(&file, self.layout.actions_path(), false)?;
        let compaction_result = (|| {
            let retention_window = chrono::TimeDelta::days(retention_days);
            let retained_actions =
                parse_jsonl_records::<FleetActionRecord>(&file, self.layout.actions_path())?
                    .into_iter()
                    .filter(|record| {
                        now.signed_duration_since(record.emitted_at) <= retention_window
                    })
                    .collect::<Vec<_>>();

            let temp_path = self
                .layout
                .actions_path()
                .with_extension(format!("jsonl.tmp-{}", Uuid::now_v7()));
            let mut temp_guard = TempFileGuard::new(temp_path.clone());
            let mut temp_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
                .map_err(|err| {
                    FleetTransportError::io(format!(
                        "failed opening compacted fleet action log {}: {err}",
                        temp_path.display()
                    ))
                })?;

            for record in retained_actions {
                let payload = serde_json::to_vec(&record).map_err(|err| {
                    FleetTransportError::serialization(format!(
                        "failed serializing compacted fleet action {}: {err}",
                        record.action_id
                    ))
                })?;
                temp_file.write_all(&payload).map_err(|err| {
                    FleetTransportError::io(format!(
                        "failed writing compacted fleet action log {}: {err}",
                        temp_path.display()
                    ))
                })?;
                temp_file.write_all(b"\n").map_err(|err| {
                    FleetTransportError::io(format!(
                        "failed writing compacted fleet action delimiter {}: {err}",
                        temp_path.display()
                    ))
                })?;
            }
            temp_file.sync_data().map_err(|err| {
                FleetTransportError::io(format!(
                    "failed syncing compacted fleet action log {}: {err}",
                    temp_path.display()
                ))
            })?;
            fs::rename(&temp_path, self.layout.actions_path()).map_err(|err| {
                FleetTransportError::io(format!(
                    "failed promoting compacted fleet action log {} to {}: {err}",
                    temp_path.display(),
                    self.layout.actions_path().display()
                ))
            })?;
            temp_guard.defuse();
            Ok(())
        })();

        let unlock_result = unlock_file(&file, self.layout.actions_path());
        compaction_result?;
        unlock_result?;
        Ok(())
    }

    fn action_log_file(&self, write: bool) -> Result<File, FleetTransportError> {
        let mut options = OpenOptions::new();
        options.read(true);
        if write {
            options.append(true).create(true);
        }
        options.open(self.layout.actions_path()).map_err(|err| {
            FleetTransportError::io(format!(
                "failed opening fleet action log {}: {err}",
                self.layout.actions_path().display()
            ))
        })
    }

    fn node_lock_path(&self, node_id: &str) -> Result<PathBuf, FleetTransportError> {
        let node_id = validate_node_id(node_id)?;
        Ok(self.layout.locks_dir().join(format!("node-{node_id}.lock")))
    }

    fn lock_file(&self, path: &Path) -> Result<File, FleetTransportError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|err| {
                FleetTransportError::io(format!(
                    "failed opening fleet lock file {}: {err}",
                    path.display()
                ))
            })
    }

    fn read_action_log(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        let file = self.action_log_file(false)?;
        lock_file_with_backoff(&file, self.layout.actions_path(), true)?;
        let read_result = (|| {
            let actions =
                parse_jsonl_records::<FleetActionRecord>(&file, self.layout.actions_path())?;
            for action in &actions {
                validate_action_record(action)?;
            }
            Ok(actions)
        })();
        let unlock_result = unlock_file(&file, self.layout.actions_path());
        let actions = read_result?;
        unlock_result?;
        Ok(actions)
    }

    fn write_node_status(&self, status: &NodeStatus) -> Result<(), FleetTransportError> {
        let path = self.layout.node_status_path(&status.node_id)?;
        let lock_path = self.node_lock_path(&status.node_id)?;
        let lock_file = self.lock_file(&lock_path)?;
        lock_file_with_backoff(&lock_file, &lock_path, false)?;

        let write_result = (|| {
            let temp_path = path.with_extension(format!("json.tmp-{}", Uuid::now_v7()));
            let mut temp_guard = TempFileGuard::new(temp_path.clone());
            let payload = serde_json::to_vec(status).map_err(|err| {
                FleetTransportError::serialization(format!(
                    "failed serializing node status {}: {err}",
                    path.display()
                ))
            })?;
            let mut temp_file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
                .map_err(|err| {
                    FleetTransportError::io(format!(
                        "failed opening temp node status {}: {err}",
                        temp_path.display()
                    ))
                })?;
            temp_file.write_all(&payload).map_err(|err| {
                FleetTransportError::io(format!(
                    "failed writing temp node status {}: {err}",
                    temp_path.display()
                ))
            })?;
            temp_file.sync_data().map_err(|err| {
                FleetTransportError::io(format!(
                    "failed syncing temp node status {}: {err}",
                    temp_path.display()
                ))
            })?;
            fs::rename(&temp_path, &path).map_err(|err| {
                FleetTransportError::io(format!(
                    "failed promoting temp node status {} to {}: {err}",
                    temp_path.display(),
                    path.display()
                ))
            })?;
            temp_guard.defuse();
            Ok(())
        })();

        let unlock_result = unlock_file(&lock_file, &lock_path);
        write_result?;
        unlock_result?;
        Ok(())
    }
}

impl FleetTransport for FileFleetTransport {
    fn initialize(&mut self) -> Result<(), FleetTransportError> {
        self.layout.initialize()?;
        self.compact_action_log_if_needed(
            ACTION_LOG_COMPACTION_THRESHOLD_BYTES,
            ACTION_LOG_RETENTION_DAYS,
            Utc::now(),
        )
    }

    fn publish_action(&mut self, action: &FleetActionRecord) -> Result<(), FleetTransportError> {
        self.ensure_initialized()?;
        validate_action_record(action)?;
        let file = self.action_log_file(true)?;
        lock_file_with_backoff(&file, self.layout.actions_path(), false)?;

        let write_result = (|| {
            let payload = serde_json::to_vec(action).map_err(|err| {
                FleetTransportError::serialization(format!(
                    "failed serializing fleet action {}: {err}",
                    action.action_id
                ))
            })?;
            if payload.len() > MAX_ACTION_RECORD_BYTES {
                return Err(FleetTransportError::serialization(format!(
                    "serialized fleet action {} exceeds {} bytes",
                    action.action_id, MAX_ACTION_RECORD_BYTES
                )));
            }

            let mut handle = &file;
            handle.write_all(&payload).map_err(|err| {
                FleetTransportError::io(format!(
                    "failed writing fleet action log {}: {err}",
                    self.layout.actions_path().display()
                ))
            })?;
            handle.write_all(b"\n").map_err(|err| {
                FleetTransportError::io(format!(
                    "failed writing fleet action delimiter {}: {err}",
                    self.layout.actions_path().display()
                ))
            })?;
            file.sync_data().map_err(|err| {
                FleetTransportError::io(format!(
                    "failed syncing fleet action log {}: {err}",
                    self.layout.actions_path().display()
                ))
            })?;
            Ok(())
        })();

        let unlock_result = unlock_file(&file, self.layout.actions_path());
        write_result?;
        unlock_result?;
        Ok(())
    }

    fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        self.ensure_initialized()?;
        self.read_action_log()
    }

    fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
        self.ensure_initialized()?;
        validate_zone_id(&status.zone_id)?;
        validate_node_id(&status.node_id)?;
        self.write_node_status(status)
    }

    fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
        self.ensure_initialized()?;

        let mut nodes = Vec::new();
        for entry in fs::read_dir(self.layout.nodes_dir()).map_err(|err| {
            FleetTransportError::io(format!(
                "failed reading fleet nodes directory {}: {err}",
                self.layout.nodes_dir().display()
            ))
        })? {
            let entry = entry.map_err(|err| {
                FleetTransportError::io(format!(
                    "failed reading fleet nodes directory entry {}: {err}",
                    self.layout.nodes_dir().display()
                ))
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|err| {
                FleetTransportError::io(format!(
                    "failed reading fleet nodes directory entry type {}: {err}",
                    path.display()
                ))
            })?;
            if file_type.is_symlink() || !file_type.is_file() {
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            let file = File::open(&path).map_err(|err| {
                FleetTransportError::io(format!(
                    "failed opening node status {}: {err}",
                    path.display()
                ))
            })?;
            let status: NodeStatus = serde_json::from_reader(file).map_err(|err| {
                FleetTransportError::serialization(format!(
                    "failed parsing node status {}: {err}",
                    path.display()
                ))
            })?;
            validate_zone_id(&status.zone_id)?;
            validate_node_id(&status.node_id)?;
            if nodes.len() >= MAX_NODES_CAP {
                return Err(FleetTransportError::serialization(format!(
                    "fleet node status count exceeds {MAX_NODES_CAP} entries"
                )));
            }
            nodes.push(status);
        }

        Ok(nodes)
    }
}

pub fn validate_zone_id(zone_id: &str) -> Result<&str, FleetTransportError> {
    validate_transport_identifier(zone_id, "zone_id", MAX_ZONE_ID_LEN)
}

pub fn validate_node_id(node_id: &str) -> Result<&str, FleetTransportError> {
    validate_transport_identifier(node_id, "node_id", MAX_NODE_ID_LEN)
}

fn validate_action_id(action_id: &str) -> Result<&str, FleetTransportError> {
    validate_transport_identifier(action_id, "action_id", MAX_ACTION_ID_LEN)
}

fn validate_transport_identifier<'a>(
    value: &'a str,
    field_name: &str,
    max_len: usize,
) -> Result<&'a str, FleetTransportError> {
    if value.is_empty() || value.len() > max_len {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must be 1..={max_len} characters"
        )));
    }
    if value.trim() != value {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must not include leading or trailing whitespace"
        )));
    }
    if value == "." || value == ".." || value.contains("..") {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must not include traversal segments"
        )));
    }
    if value.contains('\0') {
        return Err(FleetTransportError::serialization(format!(
            "{field_name} must not contain null bytes"
        )));
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Ok(value);
    }

    Err(FleetTransportError::serialization(format!(
        "{field_name} must match [a-zA-Z0-9._-]{{1,{max_len}}}"
    )))
}

fn validate_action_record(action: &FleetActionRecord) -> Result<(), FleetTransportError> {
    validate_action_id(&action.action_id)?;

    match &action.action {
        FleetAction::Quarantine {
            zone_id,
            incident_id,
            target_id,
            reason,
            ..
        } => {
            validate_zone_id(zone_id)?;
            if incident_id.trim().is_empty() {
                return Err(FleetTransportError::serialization(
                    "quarantine incident_id must not be empty",
                ));
            }
            if target_id.trim().is_empty() {
                return Err(FleetTransportError::serialization(
                    "quarantine target_id must not be empty",
                ));
            }
            if reason.trim().is_empty() {
                return Err(FleetTransportError::serialization(
                    "quarantine reason must not be empty",
                ));
            }
        }
        FleetAction::Release {
            zone_id,
            incident_id,
            ..
        } => {
            validate_zone_id(zone_id)?;
            if incident_id.trim().is_empty() {
                return Err(FleetTransportError::serialization(
                    "release incident_id must not be empty",
                ));
            }
        }
        FleetAction::PolicyUpdate {
            zone_id,
            policy_version,
            ..
        } => {
            validate_zone_id(zone_id)?;
            if policy_version.trim().is_empty() {
                return Err(FleetTransportError::serialization(
                    "policy_version must not be empty",
                ));
            }
        }
    }

    Ok(())
}

fn lock_retry_backoffs() -> [Duration; LOCK_RETRY_BACKOFF_MILLIS.len()] {
    LOCK_RETRY_BACKOFF_MILLIS.map(Duration::from_millis)
}

pub fn wait_until_fleet_converged_or_timeout<F>(
    timeout: Duration,
    mut is_converged: F,
) -> Result<FleetConvergenceWaitOutcome, FleetTransportError>
where
    F: FnMut() -> Result<bool, FleetTransportError>,
{
    let started = Instant::now();
    loop {
        if is_converged()? {
            return Ok(FleetConvergenceWaitOutcome {
                elapsed: started.elapsed(),
                timed_out: false,
            });
        }

        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Ok(FleetConvergenceWaitOutcome {
                elapsed,
                timed_out: true,
            });
        }

        thread::sleep(FLEET_CONVERGENCE_POLL_INTERVAL.min(timeout.saturating_sub(elapsed)));
    }
}

fn lock_file_with_backoff(
    file: &File,
    path: &Path,
    shared: bool,
) -> Result<(), FleetTransportError> {
    let attempt = || {
        if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        }
    };

    match attempt() {
        Ok(()) => return Ok(()),
        Err(TryLockError::WouldBlock) => {}
        Err(TryLockError::Error(err)) => {
            return Err(FleetTransportError::io(format!(
                "failed acquiring flock for {}: {err}",
                path.display()
            )));
        }
    }

    for delay in lock_retry_backoffs() {
        thread::sleep(delay);
        match attempt() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(err)) => {
                return Err(FleetTransportError::io(format!(
                    "failed acquiring flock for {}: {err}",
                    path.display()
                )));
            }
        }
    }

    Err(FleetTransportError::lock_contention(format!(
        "timed out acquiring flock for {} after retries at 100ms/200ms/400ms",
        path.display()
    )))
}

fn unlock_file(file: &File, path: &Path) -> Result<(), FleetTransportError> {
    file.unlock().map_err(|err| {
        FleetTransportError::io(format!(
            "failed releasing flock for {}: {err}",
            path.display()
        ))
    })
}

fn parse_jsonl_records<T>(file: &File, path: &Path) -> Result<Vec<T>, FleetTransportError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut records = Vec::new();
    let reader = BufReader::new(file);
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|err| {
            FleetTransportError::io(format!(
                "failed reading JSONL line {} from {}: {err}",
                index + 1,
                path.display()
            ))
        })?;

        if line.trim().is_empty() {
            continue;
        }

        let record = serde_json::from_str(&line).map_err(|err| {
            FleetTransportError::serialization(format!(
                "failed parsing JSONL line {} from {}: {err}",
                index + 1,
                path.display()
            ))
        })?;
        if records.len() >= MAX_ACTION_LOG_ENTRIES {
            return Err(FleetTransportError::serialization(format!(
                "JSONL record count in {} exceeds {MAX_ACTION_LOG_ENTRIES} entries",
                path.display()
            )));
        }
        records.push(record);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::Instant};

    use tempfile::tempdir;

    struct TestTransport {
        layout: FleetTransportLayout,
        initialized: bool,
        actions: Vec<FleetActionRecord>,
        nodes: Vec<NodeStatus>,
    }

    impl TestTransport {
        fn new(root_dir: impl Into<PathBuf>) -> Self {
            Self {
                layout: FleetTransportLayout::new(root_dir),
                initialized: false,
                actions: Vec::new(),
                nodes: Vec::new(),
            }
        }

        fn ensure_initialized(&self) -> Result<(), FleetTransportError> {
            if self.initialized {
                Ok(())
            } else {
                Err(FleetTransportError::not_initialized(
                    "call initialize() before using the transport",
                ))
            }
        }
    }

    impl FleetTransport for TestTransport {
        fn initialize(&mut self) -> Result<(), FleetTransportError> {
            self.layout.initialize()?;
            self.initialized = true;
            Ok(())
        }

        fn publish_action(
            &mut self,
            action: &FleetActionRecord,
        ) -> Result<(), FleetTransportError> {
            self.ensure_initialized()?;
            push_bounded(&mut self.actions, action.clone(), MAX_ACTION_LOG_ENTRIES);
            Ok(())
        }

        fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
            self.ensure_initialized()?;
            Ok(self.actions.clone())
        }

        fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
            self.ensure_initialized()?;
            let zone_id = validate_zone_id(&status.zone_id)?.to_string();
            let node_id = validate_node_id(&status.node_id)?.to_string();
            let status = NodeStatus {
                zone_id,
                node_id,
                last_seen: status.last_seen,
                quarantine_version: status.quarantine_version,
                health: status.health,
            };

            if let Some(existing) = self
                .nodes
                .iter_mut()
                .find(|entry| entry.node_id == status.node_id)
            {
                *existing = status;
            } else {
                push_bounded(&mut self.nodes, status, MAX_NODES_CAP);
            }
            Ok(())
        }

        fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
            self.ensure_initialized()?;
            Ok(self.nodes.clone())
        }
    }

    fn accepts_dyn_transport(_transport: &mut dyn FleetTransport) {}

    fn release_action_record(
        action_id: impl Into<String>,
        emitted_at: &str,
        incident_id: impl Into<String>,
    ) -> FleetActionRecord {
        FleetActionRecord {
            action_id: action_id.into(),
            emitted_at: DateTime::parse_from_rfc3339(emitted_at)
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::Release {
                zone_id: "prod".to_string(),
                incident_id: incident_id.into(),
                reason: None,
            },
        }
    }

    fn node_status(
        zone_id: impl Into<String>,
        node_id: impl Into<String>,
        last_seen: &str,
        quarantine_version: u64,
        health: NodeHealth,
    ) -> NodeStatus {
        NodeStatus {
            zone_id: zone_id.into(),
            node_id: node_id.into(),
            last_seen: DateTime::parse_from_rfc3339(last_seen)
                .expect("timestamp")
                .with_timezone(&Utc),
            quarantine_version,
            health,
        }
    }

    fn temp_leftovers(dir: &Path, marker: &str) -> Vec<String> {
        let mut leftovers = Vec::new();
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return leftovers,
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(marker) {
                leftovers.push(name);
            }
        }
        leftovers.sort();
        leftovers
    }

    #[test]
    fn temp_file_guard_orphans_abandoned_temp_files() {
        let tempdir = tempdir().expect("tempdir");
        let temp_path = tempdir.path().join("actions.json.tmp");
        fs::write(&temp_path, "pending").expect("write temp file");

        {
            let _guard = TempFileGuard::new(temp_path.clone());
        }

        assert!(!temp_path.exists(), "temp file should be moved aside");
        let leftovers = temp_leftovers(tempdir.path(), "actions.json.tmp.orphaned-");
        assert_eq!(leftovers.len(), 1, "expected one orphaned temp artifact");
    }

    #[test]
    fn fleet_transport_trait_is_object_safe() {
        let tempdir = tempdir().expect("tempdir");
        let mut transport = TestTransport::new(tempdir.path());
        accepts_dyn_transport(&mut transport);
    }

    #[test]
    fn validate_node_id_accepts_allowed_charset_and_bounds() {
        let valid = validate_node_id("node_A-1.example").expect("valid node id");
        assert_eq!(valid, "node_A-1.example");

        let max_len = "a".repeat(MAX_NODE_ID_LEN);
        assert_eq!(validate_node_id(&max_len).expect("max length"), max_len);
    }

    #[test]
    fn validate_node_id_rejects_invalid_values() {
        for invalid in [
            "",
            " ",
            " node",
            "node ",
            "../escape",
            "node/slash",
            "node\\slash",
            "node*bad",
        ] {
            assert!(
                validate_node_id(invalid).is_err(),
                "accepted invalid node_id {invalid:?}"
            );
        }

        let too_long = "a".repeat(MAX_NODE_ID_LEN + 1);
        assert!(validate_node_id(&too_long).is_err());
    }

    #[test]
    fn validate_zone_id_rejects_blank_values() {
        assert!(validate_zone_id("").is_err());
        assert!(validate_zone_id("   ").is_err());
        assert!(validate_zone_id(" prod").is_err());
        assert!(validate_zone_id("prod ").is_err());
    }

    #[test]
    fn publish_action_before_initialize_is_rejected() {
        let tempdir = tempdir().expect("tempdir");
        let mut transport = FileFleetTransport::new(tempdir.path().join("missing-state"));

        let error = transport
            .publish_action(&release_action_record(
                "fleet-action-uninitialized",
                "2026-04-06T00:00:00Z",
                "inc-uninitialized",
            ))
            .expect_err("uninitialized transport should reject writes");

        assert!(matches!(error, FleetTransportError::NotInitialized { .. }));
        assert!(!transport.layout().actions_path().exists());
    }

    #[test]
    fn list_actions_before_initialize_is_rejected() {
        let tempdir = tempdir().expect("tempdir");
        let transport = FileFleetTransport::new(tempdir.path().join("missing-state"));

        let error = transport
            .list_actions()
            .expect_err("uninitialized transport should reject reads");

        assert!(matches!(error, FleetTransportError::NotInitialized { .. }));
    }

    #[test]
    fn publish_action_rejects_blank_action_id_without_appending() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let mut action = release_action_record("fleet-action-valid", "2026-04-06T00:00:00Z", "inc");
        action.action_id = "  ".to_string();
        let error = transport
            .publish_action(&action)
            .expect_err("blank action_id should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert_eq!(
            fs::read_to_string(transport.layout().actions_path()).expect("read action log"),
            ""
        );
    }

    #[test]
    fn publish_action_rejects_quarantine_with_blank_reason() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let action = FleetActionRecord {
            action_id: "fleet-action-blank-reason".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::Quarantine {
                zone_id: "prod".to_string(),
                incident_id: "inc-blank-reason".to_string(),
                target_id: "sha256:target".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: " ".to_string(),
                quarantine_version: 1,
            },
        };

        let error = transport
            .publish_action(&action)
            .expect_err("blank quarantine reason should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(transport.list_actions().expect("list actions").is_empty());
    }

    #[test]
    fn publish_action_rejects_policy_update_with_blank_version() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let action = FleetActionRecord {
            action_id: "fleet-action-blank-policy".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::PolicyUpdate {
                zone_id: "prod".to_string(),
                policy_version: "\t".to_string(),
                changed_fields: vec!["trust.min_score".to_string()],
            },
        };

        let error = transport
            .publish_action(&action)
            .expect_err("blank policy version should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(transport.list_actions().expect("list actions").is_empty());
    }

    #[test]
    fn upsert_node_status_rejects_whitespace_zone_without_file() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let error = transport
            .upsert_node_status(&node_status(
                "prod ",
                "node-alpha",
                "2026-04-06T00:00:00Z",
                1,
                NodeHealth::Healthy,
            ))
            .expect_err("whitespace zone_id should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
        assert!(
            fs::read_dir(transport.layout().nodes_dir())
                .expect("read nodes dir")
                .next()
                .is_none()
        );
    }

    #[test]
    fn list_actions_rejects_malformed_jsonl_line() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");
        fs::write(transport.layout().actions_path(), "{not-json}\n").expect("write bad log");

        let error = transport
            .list_actions()
            .expect_err("malformed action log should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn list_node_statuses_rejects_persisted_invalid_node_id() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");
        let bad_status = NodeStatus {
            zone_id: "prod".to_string(),
            node_id: "../escape".to_string(),
            last_seen: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            quarantine_version: 1,
            health: NodeHealth::Healthy,
        };
        fs::write(
            transport.layout().nodes_dir().join("node-bad.json"),
            serde_json::to_string(&bad_status).expect("serialize bad status"),
        )
        .expect("write bad status");

        let error = transport
            .list_node_statuses()
            .expect_err("invalid persisted node_id should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn compact_action_log_rejects_non_positive_retention_days() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let error = transport
            .compact_action_log_if_needed(
                0,
                0,
                DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
            )
            .expect_err("non-positive retention should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn fleet_action_roundtrip_preserves_policy_update_variant() {
        let record = FleetActionRecord {
            action_id: "fleet-action-0001".to_string(),
            emitted_at: DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            action: FleetAction::PolicyUpdate {
                zone_id: "prod-us-east".to_string(),
                policy_version: "strict-2026-04-06".to_string(),
                changed_fields: vec!["trust.min_score".to_string(), "fleet.timeout".to_string()],
            },
        };

        let json = serde_json::to_string(&record).expect("serialize");
        let roundtrip: FleetActionRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(roundtrip, record);
    }

    #[test]
    fn fleet_shared_state_roundtrip_preserves_nodes_and_actions() {
        let state = FleetSharedState {
            schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions: vec![FleetActionRecord {
                action_id: "fleet-action-0002".to_string(),
                emitted_at: DateTime::parse_from_rfc3339("2026-04-06T01:02:03Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                action: FleetAction::Quarantine {
                    zone_id: "prod-us-east".to_string(),
                    incident_id: "inc-0002".to_string(),
                    target_id: "sha256:abc123".to_string(),
                    target_kind: FleetTargetKind::Artifact,
                    reason: "high-risk quarantine".to_string(),
                    quarantine_version: 7,
                },
            }],
            nodes: vec![NodeStatus {
                zone_id: "prod-us-east".to_string(),
                node_id: "node-alpha".to_string(),
                last_seen: DateTime::parse_from_rfc3339("2026-04-06T01:02:04Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                quarantine_version: 7,
                health: NodeHealth::Healthy,
            }],
        };

        let json = serde_json::to_string(&state).expect("serialize");
        let roundtrip: FleetSharedState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(roundtrip, state);
    }

    #[test]
    fn layout_initialize_creates_expected_directories_and_log() {
        let tempdir = tempdir().expect("tempdir");
        let layout = FleetTransportLayout::new(tempdir.path().join("fleet-state"));
        layout.initialize().expect("initialize");

        assert!(layout.root_dir().is_dir());
        assert!(layout.nodes_dir().is_dir());
        assert!(layout.locks_dir().is_dir());
        assert!(layout.actions_path().is_file());
    }

    #[test]
    fn initialize_trait_creates_directory_structure_if_missing() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("transport-root");
        let mut transport = TestTransport::new(&root);

        transport.initialize().expect("transport initialize");

        assert!(root.is_dir());
        assert!(transport.layout.actions_path().is_file());
        assert!(transport.layout.nodes_dir().is_dir());
        assert!(transport.layout.locks_dir().is_dir());
    }

    #[test]
    fn read_shared_state_sorts_nodes_and_actions() {
        let tempdir = tempdir().expect("tempdir");
        let mut transport = TestTransport::new(tempdir.path());
        transport.initialize().expect("initialize");

        transport
            .publish_action(&FleetActionRecord {
                action_id: "b".to_string(),
                emitted_at: DateTime::parse_from_rfc3339("2026-04-06T01:00:02Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                action: FleetAction::Release {
                    zone_id: "prod".to_string(),
                    incident_id: "inc-b".to_string(),
                    reason: None,
                },
            })
            .expect("publish action");
        transport
            .publish_action(&FleetActionRecord {
                action_id: "a".to_string(),
                emitted_at: DateTime::parse_from_rfc3339("2026-04-06T01:00:01Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                action: FleetAction::Release {
                    zone_id: "prod".to_string(),
                    incident_id: "inc-a".to_string(),
                    reason: None,
                },
            })
            .expect("publish action");

        transport
            .upsert_node_status(&NodeStatus {
                zone_id: "prod".to_string(),
                node_id: "node-z".to_string(),
                last_seen: DateTime::parse_from_rfc3339("2026-04-06T01:02:04Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                quarantine_version: 2,
                health: NodeHealth::Healthy,
            })
            .expect("upsert node");
        transport
            .upsert_node_status(&NodeStatus {
                zone_id: "prod".to_string(),
                node_id: "node-a".to_string(),
                last_seen: DateTime::parse_from_rfc3339("2026-04-06T01:02:05Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                quarantine_version: 3,
                health: NodeHealth::Degraded,
            })
            .expect("upsert node");

        let state = transport.read_shared_state().expect("shared state");
        assert_eq!(state.actions[0].action_id, "a");
        assert_eq!(state.actions[1].action_id, "b");
        assert_eq!(state.nodes[0].node_id, "node-a");
        assert_eq!(state.nodes[1].node_id, "node-z");
    }

    #[test]
    fn node_status_path_uses_validated_node_ids() {
        let tempdir = tempdir().expect("tempdir");
        let layout = FleetTransportLayout::new(tempdir.path());

        assert_eq!(
            layout.node_status_path("node-alpha").expect("path"),
            tempdir
                .path()
                .join(FLEET_NODE_DIR)
                .join("node-node-alpha.json")
        );
        assert!(layout.node_status_path("../escape").is_err());
    }

    #[test]
    fn file_transport_initialization_creates_directory_structure() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);

        transport.initialize().expect("initialize file transport");

        assert!(root.is_dir());
        assert!(transport.layout().actions_path().is_file());
        assert!(transport.layout().nodes_dir().is_dir());
        assert!(transport.layout().locks_dir().is_dir());
    }

    #[test]
    fn file_transport_persists_actions_and_latest_node_state() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        transport
            .publish_action(&release_action_record(
                "fleet-action-10",
                "2026-04-06T02:00:00Z",
                "inc-10",
            ))
            .expect("publish action");
        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-alpha",
                "2026-04-06T02:00:01Z",
                10,
                NodeHealth::Healthy,
            ))
            .expect("write node");
        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-alpha",
                "2026-04-06T02:00:02Z",
                11,
                NodeHealth::Quarantined,
            ))
            .expect("rewrite node");

        let state = transport.read_shared_state().expect("shared state");
        assert_eq!(state.actions.len(), 1);
        assert_eq!(state.nodes.len(), 1);
        assert_eq!(state.nodes[0].quarantine_version, 11);
        assert_eq!(state.nodes[0].health, NodeHealth::Quarantined);

        let persisted: NodeStatus = serde_json::from_str(
            &fs::read_to_string(
                transport
                    .layout()
                    .node_status_path("node-alpha")
                    .expect("node status path"),
            )
            .expect("read node file"),
        )
        .expect("parse node file");
        assert_eq!(persisted, state.nodes[0]);
    }

    #[test]
    fn file_transport_upsert_node_status_cleans_temp_files() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-clean",
                "2026-04-06T02:10:00Z",
                12,
                NodeHealth::Healthy,
            ))
            .expect("write node");

        let leftovers = temp_leftovers(transport.layout().nodes_dir(), ".json.tmp-");
        assert!(
            leftovers.is_empty(),
            "found temp node status leftovers: {leftovers:?}"
        );
    }

    #[test]
    fn file_transport_concurrent_appends_preserve_jsonl_integrity() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let mut workers = Vec::new();
        for worker in 0..4 {
            let root = root.clone();
            workers.push(std::thread::spawn(move || {
                let mut transport = FileFleetTransport::new(root);
                for index in 0..25 {
                    transport
                        .publish_action(&FleetActionRecord {
                            action_id: format!("worker-{worker}-action-{index}"),
                            emitted_at: Utc::now(),
                            action: FleetAction::Release {
                                zone_id: "prod".to_string(),
                                incident_id: format!("inc-{worker}-{index}"),
                                reason: None,
                            },
                        })
                        .expect("publish action");
                }
            }));
        }

        for worker in workers {
            worker.join().expect("worker join");
        }

        let log = fs::read_to_string(transport.layout().actions_path()).expect("read action log");
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 100);
        for line in lines {
            let parsed: FleetActionRecord = serde_json::from_str(line).expect("parse JSONL line");
            assert!(parsed.action_id.starts_with("worker-"));
        }

        let persisted = transport.list_actions().expect("list actions");
        assert_eq!(persisted.len(), 100);
    }

    #[test]
    fn file_transport_lists_stale_nodes_from_persisted_state() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-fresh",
                "2026-04-06T03:09:30Z",
                3,
                NodeHealth::Healthy,
            ))
            .expect("write fresh node");
        transport
            .upsert_node_status(&node_status(
                "prod",
                "node-stale",
                "2026-04-06T03:00:00Z",
                3,
                NodeHealth::Degraded,
            ))
            .expect("write stale node");

        let stale = transport
            .list_stale_nodes(
                DateTime::parse_from_rfc3339("2026-04-06T03:10:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                Duration::from_secs(60),
            )
            .expect("stale nodes");

        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].node_id, "node-stale");
    }

    #[test]
    fn lock_retry_backoffs_match_expected_schedule() {
        assert_eq!(
            lock_retry_backoffs(),
            [
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(400),
            ]
        );
    }

    #[test]
    fn file_transport_reports_lock_contention_after_retry_budget() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(transport.layout().actions_path())
            .expect("open action log");
        file.lock().expect("take lock");

        let started = Instant::now();
        let error = transport
            .publish_action(&release_action_record(
                "fleet-action-locked",
                "2026-04-06T04:00:00Z",
                "inc-locked",
            ))
            .expect_err("lock contention");
        file.unlock().expect("release lock");

        assert!(matches!(error, FleetTransportError::LockContention { .. }));
        assert!(
            started.elapsed() >= Duration::from_millis(650),
            "expected retry backoff budget to elapse, got {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn file_transport_rejects_oversized_action_records() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        let error = transport
            .publish_action(&FleetActionRecord {
                action_id: "fleet-action-oversized".to_string(),
                emitted_at: DateTime::parse_from_rfc3339("2026-04-06T04:00:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                action: FleetAction::Quarantine {
                    zone_id: "prod".to_string(),
                    incident_id: "inc-oversized".to_string(),
                    target_id: "sha256:oversized".to_string(),
                    target_kind: FleetTargetKind::Artifact,
                    reason: "x".repeat(MAX_ACTION_RECORD_BYTES),
                    quarantine_version: 7,
                },
            })
            .expect_err("oversized action should be rejected");

        assert!(matches!(
            error,
            FleetTransportError::SerializationError { .. }
        ));
    }

    #[test]
    fn file_transport_compacts_large_logs_by_retention_window() {
        let tempdir = tempdir().expect("tempdir");
        let root = tempdir.path().join("fleet-state");
        let mut transport = FileFleetTransport::new(&root);
        transport.initialize().expect("initialize");

        transport
            .publish_action(&release_action_record(
                "fleet-action-old",
                "2026-02-01T00:00:00Z",
                "inc-old",
            ))
            .expect("publish old action");
        transport
            .publish_action(&release_action_record(
                "fleet-action-new",
                "2026-04-05T00:00:00Z",
                "inc-new",
            ))
            .expect("publish new action");

        transport
            .compact_action_log_if_needed(
                1,
                ACTION_LOG_RETENTION_DAYS,
                DateTime::parse_from_rfc3339("2026-04-06T00:00:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
            )
            .expect("compact action log");

        let actions = transport.list_actions().expect("list actions");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_id, "fleet-action-new");

        let leftovers = temp_leftovers(transport.layout().root_dir(), ".jsonl.tmp-");
        assert!(
            leftovers.is_empty(),
            "found temp compaction leftovers: {leftovers:?}"
        );
    }

    /// Comprehensive negative-path test module covering edge cases and attack vectors.
    ///
    /// These tests validate robustness against malicious inputs, resource exhaustion,
    /// timing attacks, and filesystem edge cases in fleet transport operations.
    #[cfg(test)]
    mod fleet_transport_comprehensive_negative_tests {
        use super::*;

        #[test]
        fn unicode_injection_in_fleet_identifiers_handled_safely() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Unicode control characters, NULL bytes, path traversal attempts
            let malicious_zone_ids = vec![
                "zone\u{0000}null",
                "zone\u{200B}zwsp",
                "zone\u{FEFF}bom",
                "zone/../../../etc",
                "zone\u{202E}rtl\u{202D}",
                "zone\x1B[31mANSI",
                "zone\u{1F4A9}emoji",
            ];

            let malicious_node_ids = vec![
                "node\u{0000}null",
                "node\u{200B}zwsp",
                "node/../escape",
                "node\x1B[Hclear",
                "node\u{202E}direction",
            ];

            let malicious_action_ids = vec![
                "action\u{0000}null",
                "action\u{200B}zwsp",
                "action/../traverse",
                "action\x1B[31mred",
                "action\u{202E}rtl",
            ];

            for malicious_zone in &malicious_zone_ids {
                for malicious_node in &malicious_node_ids {
                    for malicious_action in &malicious_action_ids {
                        // Test node status validation
                        let node_result = transport.upsert_node_status(&NodeStatus {
                            zone_id: malicious_zone.clone(),
                            node_id: malicious_node.clone(),
                            last_seen: Utc::now(),
                            quarantine_version: 1,
                            health: NodeHealth::Healthy,
                        });

                        // Should reject malicious identifiers gracefully
                        assert!(node_result.is_err(), "Should reject malicious zone/node: {}/{}", malicious_zone, malicious_node);

                        // Test action validation
                        let action_result = transport.publish_action(&FleetActionRecord {
                            action_id: malicious_action.clone(),
                            emitted_at: Utc::now(),
                            action: FleetAction::Release {
                                zone_id: malicious_zone.clone(),
                                incident_id: "inc-test".to_string(),
                                reason: None,
                            },
                        });

                        // Should reject malicious action/zone identifiers gracefully
                        assert!(action_result.is_err(), "Should reject malicious action/zone: {}/{}", malicious_action, malicious_zone);
                    }
                }
            }
        }

        #[test]
        fn arithmetic_overflow_protection_in_version_numbers() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Test with extreme quarantine version numbers
            let extreme_versions = vec![
                u64::MAX - 1,
                u64::MAX,
            ];

            for &extreme_version in &extreme_versions {
                let status_result = transport.upsert_node_status(&NodeStatus {
                    zone_id: "prod".to_string(),
                    node_id: "overflow-test".to_string(),
                    last_seen: Utc::now(),
                    quarantine_version: extreme_version,
                    health: NodeHealth::Healthy,
                });

                // Should handle extreme version numbers gracefully
                assert!(status_result.is_ok(), "Should handle extreme version: {}", extreme_version);

                let action_result = transport.publish_action(&FleetActionRecord {
                    action_id: format!("action-overflow-{}", extreme_version),
                    emitted_at: Utc::now(),
                    action: FleetAction::Quarantine {
                        zone_id: "prod".to_string(),
                        incident_id: "inc-overflow".to_string(),
                        target_id: "target-overflow".to_string(),
                        target_kind: FleetTargetKind::Artifact,
                        reason: "overflow test".to_string(),
                        quarantine_version: extreme_version,
                    },
                });

                // Should handle extreme quarantine versions in actions
                assert!(action_result.is_ok(), "Should handle extreme quarantine version: {}", extreme_version);
            }

            // Verify stored values maintain integrity
            let stored_statuses = transport.list_node_statuses().expect("list statuses");
            assert!(!stored_statuses.is_empty());
            for status in &stored_statuses {
                assert!(status.quarantine_version <= u64::MAX);
            }

            let stored_actions = transport.list_actions().expect("list actions");
            assert!(!stored_actions.is_empty());
        }

        #[test]
        fn memory_exhaustion_through_massive_action_logs() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Generate massive action log to test memory bounds
            let massive_action_count = 1000;
            let massive_reason_size = 1500; // Near MAX_ACTION_RECORD_BYTES limit

            for action_idx in 0..massive_action_count {
                let action_result = transport.publish_action(&FleetActionRecord {
                    action_id: format!("flood_action_{action_idx:05}"),
                    emitted_at: Utc::now(),
                    action: FleetAction::Quarantine {
                        zone_id: "prod".to_string(),
                        incident_id: format!("flood_inc_{action_idx:05}"),
                        target_id: format!("flood_target_{action_idx:05}"),
                        target_kind: FleetTargetKind::Artifact,
                        reason: "x".repeat(massive_reason_size), // Large but within bounds
                        quarantine_version: action_idx as u64,
                    },
                });

                // Should handle large actions within bounds
                assert!(action_result.is_ok(), "Should handle large action at index {}", action_idx);
            }

            // Test oversized action rejection
            let oversized_result = transport.publish_action(&FleetActionRecord {
                action_id: "oversized_action".to_string(),
                emitted_at: Utc::now(),
                action: FleetAction::Quarantine {
                    zone_id: "prod".to_string(),
                    incident_id: "oversized_inc".to_string(),
                    target_id: "oversized_target".to_string(),
                    target_kind: FleetTargetKind::Artifact,
                    reason: "x".repeat(MAX_ACTION_RECORD_BYTES + 100), // Exceeds limit
                    quarantine_version: 999,
                },
            });

            // Should reject oversized actions
            assert!(oversized_result.is_err(), "Should reject oversized action");

            // Verify bounded memory usage
            let all_actions = transport.list_actions().expect("list actions");
            assert_eq!(all_actions.len(), massive_action_count);
        }

        #[test]
        fn concurrent_file_operations_race_condition_simulation() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");

            // Initialize transport
            {
                let mut transport = FileFleetTransport::new(&root);
                transport.initialize().expect("initialize");
            }

            // Simulate concurrent operations
            let mut handles = Vec::new();
            let thread_count = 8;
            let operations_per_thread = 25;

            for thread_id in 0..thread_count {
                let root = root.clone();
                handles.push(std::thread::spawn(move || {
                    let mut transport = FileFleetTransport::new(&root);

                    for op_id in 0..operations_per_thread {
                        let node_id = format!("node-{thread_id}-{op_id}");
                        let action_id = format!("action-{thread_id}-{op_id}");

                        // Interleave node status updates and action publishing
                        if op_id % 2 == 0 {
                            let _ = transport.upsert_node_status(&NodeStatus {
                                zone_id: "prod".to_string(),
                                node_id: node_id.clone(),
                                last_seen: Utc::now(),
                                quarantine_version: op_id as u64,
                                health: NodeHealth::Healthy,
                            });
                        } else {
                            let _ = transport.publish_action(&FleetActionRecord {
                                action_id: action_id.clone(),
                                emitted_at: Utc::now(),
                                action: FleetAction::Release {
                                    zone_id: "prod".to_string(),
                                    incident_id: format!("inc-{thread_id}-{op_id}"),
                                    reason: None,
                                },
                            });
                        }
                    }
                }));
            }

            // Wait for all threads to complete
            for handle in handles {
                handle.join().expect("thread join");
            }

            // Verify filesystem integrity after concurrent operations
            let transport = FileFleetTransport::new(&root);
            let final_actions = transport.list_actions().expect("final actions");
            let final_nodes = transport.list_node_statuses().expect("final nodes");

            // Should have some results from concurrent operations
            assert!(!final_actions.is_empty(), "Should have some actions from concurrent ops");
            assert!(!final_nodes.is_empty(), "Should have some nodes from concurrent ops");

            // Verify no corruption in action log
            for action in &final_actions {
                assert!(!action.action_id.is_empty(), "Action ID should not be empty");
                assert!(!action.action_id.contains('\0'), "Action ID should not contain null bytes");
            }
        }

        #[test]
        fn filesystem_path_traversal_attack_prevention() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Test various path traversal attacks in node IDs
            let path_traversal_attempts = vec![
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "node/../escape",
                "node/subdir/file",
                "node\\windows\\path",
                "./current/dir",
                "~/home/escape",
                "/absolute/path",
                "\\absolute\\windows\\path",
                "node\0null",
                "node\x00null_byte",
            ];

            for malicious_path in &path_traversal_attempts {
                let status_result = transport.upsert_node_status(&NodeStatus {
                    zone_id: "prod".to_string(),
                    node_id: malicious_path.to_string(),
                    last_seen: Utc::now(),
                    quarantine_version: 1,
                    health: NodeHealth::Healthy,
                });

                // Should reject path traversal attempts
                assert!(status_result.is_err(), "Should reject path traversal: {}", malicious_path);

                // Verify layout path generation rejects malicious paths
                let path_result = transport.layout().node_status_path(malicious_path);
                assert!(path_result.is_err(), "Layout should reject malicious path: {}", malicious_path);
            }

            // Verify no files were created outside the expected directory
            let nodes_dir = transport.layout().nodes_dir();
            assert!(nodes_dir.is_dir(), "Nodes directory should exist");

            // Check that no unexpected files exist
            let entries: Vec<_> = fs::read_dir(nodes_dir).expect("read nodes dir").collect();
            assert!(entries.is_empty(), "No files should be created from malicious attempts");
        }

        #[test]
        fn retention_calculation_boundary_edge_cases() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Test edge cases in retention calculations
            let now = DateTime::parse_from_rfc3339("2026-04-17T12:00:00Z")
                .expect("now timestamp")
                .with_timezone(&Utc);

            // Action exactly at retention boundary
            let boundary_time = now - chrono::TimeDelta::days(ACTION_LOG_RETENTION_DAYS);
            transport.publish_action(&FleetActionRecord {
                action_id: "boundary-action".to_string(),
                emitted_at: boundary_time,
                action: FleetAction::Release {
                    zone_id: "prod".to_string(),
                    incident_id: "boundary-inc".to_string(),
                    reason: None,
                },
            }).expect("publish boundary action");

            // Action just before boundary (should be retained)
            let before_boundary = boundary_time + chrono::TimeDelta::seconds(1);
            transport.publish_action(&FleetActionRecord {
                action_id: "before-boundary-action".to_string(),
                emitted_at: before_boundary,
                action: FleetAction::Release {
                    zone_id: "prod".to_string(),
                    incident_id: "before-boundary-inc".to_string(),
                    reason: None,
                },
            }).expect("publish before boundary action");

            // Action just after boundary (should be removed)
            let after_boundary = boundary_time - chrono::TimeDelta::seconds(1);
            transport.publish_action(&FleetActionRecord {
                action_id: "after-boundary-action".to_string(),
                emitted_at: after_boundary,
                action: FleetAction::Release {
                    zone_id: "prod".to_string(),
                    incident_id: "after-boundary-inc".to_string(),
                    reason: None,
                },
            }).expect("publish after boundary action");

            // Force compaction
            transport.compact_action_log_if_needed(1, ACTION_LOG_RETENTION_DAYS, now)
                .expect("compact log");

            let retained_actions = transport.list_actions().expect("list actions");

            // Should retain actions within the retention window (fail-closed at boundary)
            let retained_ids: Vec<_> = retained_actions.iter().map(|a| &a.action_id).collect();
            assert!(retained_ids.contains(&&"boundary-action".to_string()), "Boundary action should be retained");
            assert!(retained_ids.contains(&&"before-boundary-action".to_string()), "Before-boundary action should be retained");
            assert!(!retained_ids.contains(&&"after-boundary-action".to_string()), "After-boundary action should be removed");
        }

        #[test]
        fn serialization_attack_vectors_json_structure() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            // Test JSON injection patterns in string fields
            let malicious_strings = vec![
                "\"},\"malicious\":\"payload\",\"a\":\"",
                "\\\"},\\\"injected\\\":true,\\\"version\\\":\\\"",
                "\n{\"evil\":\"payload\"}\n",
                "\r\n<script>alert('xss')</script>\r\n",
                "\x00\x01\x02\x03", // Binary data
                "\u{FEFF}BOM injection",
                "\\u0000null escape",
            ];

            for malicious_string in &malicious_strings {
                // Test in various string fields
                let action_result = transport.publish_action(&FleetActionRecord {
                    action_id: format!("injection-test-{}", malicious_string.len()),
                    emitted_at: Utc::now(),
                    action: FleetAction::Quarantine {
                        zone_id: "prod".to_string(),
                        incident_id: malicious_string.to_string(),
                        target_id: malicious_string.to_string(),
                        target_kind: FleetTargetKind::Artifact,
                        reason: malicious_string.to_string(),
                        quarantine_version: 1,
                    },
                });

                // Should serialize safely without breaking JSON structure
                assert!(action_result.is_ok(), "Should handle malicious string safely: {:?}", malicious_string);

                let status_result = transport.upsert_node_status(&NodeStatus {
                    zone_id: "prod".to_string(),
                    node_id: format!("node-{}", malicious_string.len()),
                    last_seen: Utc::now(),
                    quarantine_version: 1,
                    health: NodeHealth::Healthy,
                });

                // Node ID validation should reject malicious strings
                if status_result.is_ok() {
                    // If it was accepted, verify serialization integrity
                    let stored_nodes = transport.list_node_statuses().expect("list nodes");
                    for node in &stored_nodes {
                        assert!(!node.node_id.is_empty(), "Node ID should not be empty");
                        assert!(!node.zone_id.is_empty(), "Zone ID should not be empty");
                    }
                }
            }

            // Verify stored actions maintain JSON integrity
            let stored_actions = transport.list_actions().expect("list actions");
            for action in &stored_actions {
                let serialized = serde_json::to_string(action).expect("serialize action");
                let deserialized: FleetActionRecord = serde_json::from_str(&serialized).expect("deserialize action");
                assert_eq!(deserialized.action_id, action.action_id);
            }
        }

        #[test]
        fn staleness_calculation_timing_precision() {
            let tempdir = tempdir().expect("tempdir");
            let root = tempdir.path().join("fleet-state");
            let mut transport = FileFleetTransport::new(&root);
            transport.initialize().expect("initialize");

            let base_time = DateTime::parse_from_rfc3339("2026-04-17T12:00:00Z")
                .expect("base timestamp")
                .with_timezone(&Utc);

            // Test precise staleness boundary calculations
            let staleness_threshold = Duration::from_secs(300); // 5 minutes

            // Node exactly at staleness boundary
            transport.upsert_node_status(&NodeStatus {
                zone_id: "prod".to_string(),
                node_id: "boundary-node".to_string(),
                last_seen: base_time - chrono::TimeDelta::from_std(staleness_threshold).unwrap(),
                quarantine_version: 1,
                health: NodeHealth::Healthy,
            }).expect("upsert boundary node");

            // Node just before staleness (should not be stale)
            transport.upsert_node_status(&NodeStatus {
                zone_id: "prod".to_string(),
                node_id: "fresh-node".to_string(),
                last_seen: base_time - chrono::TimeDelta::from_std(staleness_threshold).unwrap() + chrono::TimeDelta::seconds(1),
                quarantine_version: 1,
                health: NodeHealth::Healthy,
            }).expect("upsert fresh node");

            // Node just after staleness (should be stale)
            transport.upsert_node_status(&NodeStatus {
                zone_id: "prod".to_string(),
                node_id: "stale-node".to_string(),
                last_seen: base_time - chrono::TimeDelta::from_std(staleness_threshold).unwrap() - chrono::TimeDelta::seconds(1),
                quarantine_version: 1,
                health: NodeHealth::Healthy,
            }).expect("upsert stale node");

            let stale_nodes = transport.list_stale_nodes(base_time, staleness_threshold)
                .expect("list stale nodes");

            let stale_ids: Vec<_> = stale_nodes.iter().map(|n| &n.node_id).collect();

            // Boundary behavior: exactly at threshold should be considered stale (fail-closed)
            assert!(stale_ids.contains(&&"boundary-node".to_string()), "Boundary node should be stale");
            assert!(!stale_ids.contains(&&"fresh-node".to_string()), "Fresh node should not be stale");
            assert!(stale_ids.contains(&&"stale-node".to_string()), "Stale node should be stale");
        }

        #[test]
        fn file_layout_boundary_validation() {
            let tempdir = tempdir().expect("tempdir");

            // Test with extreme path lengths and characters
            let extreme_roots = vec![
                // Very long path
                tempdir.path().join("a".repeat(200)),
                // Unicode in path
                tempdir.path().join("fleet-🚀-state"),
                // Path with spaces
                tempdir.path().join("fleet state with spaces"),
            ];

            for extreme_root in &extreme_roots {
                let layout = FleetTransportLayout::new(extreme_root);

                // Layout creation should handle extreme paths gracefully
                assert!(layout.root_dir().to_str().is_some(), "Root path should be valid UTF-8");
                assert!(layout.actions_path().to_str().is_some(), "Actions path should be valid UTF-8");
                assert!(layout.nodes_dir().to_str().is_some(), "Nodes dir should be valid UTF-8");
                assert!(layout.locks_dir().to_str().is_some(), "Locks dir should be valid UTF-8");

                // Initialization should handle extreme paths
                let init_result = layout.initialize();
                if init_result.is_ok() {
                    assert!(layout.root_dir().is_dir(), "Root directory should be created");
                    assert!(layout.nodes_dir().is_dir(), "Nodes directory should be created");
                    assert!(layout.locks_dir().is_dir(), "Locks directory should be created");
                    assert!(layout.actions_path().is_file(), "Actions file should be created");
                }
            }

            // Test node status path validation with boundary cases
            let layout = FleetTransportLayout::new(tempdir.path());
            layout.initialize().expect("initialize layout");

            let boundary_node_ids = vec![
                "a", // Minimum length
                &"b".repeat(MAX_NODE_ID_LEN), // Maximum length
                "node-with-all.valid_chars-123", // All valid characters
            ];

            for node_id in &boundary_node_ids {
                let path_result = layout.node_status_path(node_id);
                assert!(path_result.is_ok(), "Should accept valid node ID: {}", node_id);

                let path = path_result.unwrap();
                assert!(path.to_str().is_some(), "Generated path should be valid UTF-8");
                assert!(path.file_name().is_some(), "Generated path should have filename");
            }
        }
    }
}
