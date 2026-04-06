//! Fleet transport contract and shared state schema for distributed fleet coordination.
//!
//! This module defines the transport-facing action log, node heartbeat/state shape,
//! and object-safe transport trait used by the fleet-control track.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const FLEET_SHARED_STATE_SCHEMA: &str = "franken-node/fleet-transport-state/v1";
pub const FLEET_ACTION_LOG_FILE: &str = "actions.jsonl";
pub const FLEET_NODE_DIR: &str = "nodes";
pub const FLEET_LOCK_DIR: &str = "locks";
const MAX_NODE_ID_LEN: usize = 128;
const LOCK_RETRY_BACKOFF_MILLIS: [u64; 3] = [100, 200, 400];

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
        nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));

        Ok(FleetSharedState {
            schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions,
            nodes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFleetTransport {
    layout: FleetTransportLayout,
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
            .filter(|status| now.signed_duration_since(status.last_seen) > staleness_threshold)
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
        let read_result =
            parse_jsonl_records::<FleetActionRecord>(&file, self.layout.actions_path());
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
            let temp_path = path.with_extension("json.tmp");
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
        self.layout.initialize()
    }

    fn publish_action(&mut self, action: &FleetActionRecord) -> Result<(), FleetTransportError> {
        self.ensure_initialized()?;
        let file = self.action_log_file(true)?;
        lock_file_with_backoff(&file, self.layout.actions_path(), false)?;

        let write_result = (|| {
            let payload = serde_json::to_vec(action).map_err(|err| {
                FleetTransportError::serialization(format!(
                    "failed serializing fleet action {}: {err}",
                    action.action_id
                ))
            })?;

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
            validate_node_id(&status.node_id)?;
            nodes.push(status);
        }

        Ok(nodes)
    }
}

pub fn validate_node_id(node_id: &str) -> Result<&str, FleetTransportError> {
    if node_id.is_empty() || node_id.len() > MAX_NODE_ID_LEN {
        return Err(FleetTransportError::serialization(format!(
            "node_id must be 1..={MAX_NODE_ID_LEN} characters"
        )));
    }

    if node_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Ok(node_id);
    }

    Err(FleetTransportError::serialization(
        "node_id must match [a-zA-Z0-9._-]{1,128}",
    ))
}

fn lock_retry_backoffs() -> [Duration; LOCK_RETRY_BACKOFF_MILLIS.len()] {
    LOCK_RETRY_BACKOFF_MILLIS.map(Duration::from_millis)
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
            self.actions.push(action.clone());
            Ok(())
        }

        fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
            self.ensure_initialized()?;
            Ok(self.actions.clone())
        }

        fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
            self.ensure_initialized()?;
            let node_id = validate_node_id(&status.node_id)?.to_string();
            let status = NodeStatus {
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
                self.nodes.push(status);
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
        node_id: impl Into<String>,
        last_seen: &str,
        quarantine_version: u64,
        health: NodeHealth,
    ) -> NodeStatus {
        NodeStatus {
            node_id: node_id.into(),
            last_seen: DateTime::parse_from_rfc3339(last_seen)
                .expect("timestamp")
                .with_timezone(&Utc),
            quarantine_version,
            health,
        }
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
                    target_id: "sha256:abc123".to_string(),
                    target_kind: FleetTargetKind::Artifact,
                    reason: "high-risk quarantine".to_string(),
                    quarantine_version: 7,
                },
            }],
            nodes: vec![NodeStatus {
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
                "node-alpha",
                "2026-04-06T02:00:01Z",
                10,
                NodeHealth::Healthy,
            ))
            .expect("write node");
        transport
            .upsert_node_status(&node_status(
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
                "node-fresh",
                "2026-04-06T03:09:30Z",
                3,
                NodeHealth::Healthy,
            ))
            .expect("write fresh node");
        transport
            .upsert_node_status(&node_status(
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
}
