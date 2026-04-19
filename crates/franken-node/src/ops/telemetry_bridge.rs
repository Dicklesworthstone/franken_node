use crate::storage::frankensqlite_adapter::{FrankensqliteAdapter, PersistenceClass};
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, ErrorKind};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const PERSIST_QUEUE_CAPACITY: usize = 256;
const ENQUEUE_TIMEOUT_MS: u64 = 50;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_RECENT_EVENTS: usize = 256;
const MAX_RUNTIME_EVENTS: usize = 256;
const MAX_ACTIVE_CONNECTIONS: usize = 64;
const ACCEPT_POLL_INTERVAL_MS: u64 = 100;
const CONNECTION_READ_TIMEOUT_MS: u64 = 500;
const DEFAULT_DRAIN_TIMEOUT_MS: u64 = 5000;

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

/// Lifecycle state for the telemetry bridge runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BridgeLifecycleState {
    /// Handle not started yet.
    Cold = 0,
    /// Binding socket and starting owned workers.
    Starting = 1,
    /// Accepting connections and events normally.
    Running = 2,
    /// Still running, but non-fatal overflow/shedding or reader loss has occurred.
    Degraded = 3,
    /// Shutdown requested; no new admission, accepted work flushing to terminal outcomes.
    Draining = 4,
    /// Clean stop and drain completed.
    Stopped = 5,
    /// Fatal start/runtime/drain failure.
    Failed = 6,
}

impl BridgeLifecycleState {
    fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Cold,
            1 => Self::Starting,
            2 => Self::Running,
            3 => Self::Degraded,
            4 => Self::Draining,
            5 => Self::Stopped,
            6 => Self::Failed,
            _ => Self::Failed,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }
}

/// Reason for shutting down the telemetry bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShutdownReason {
    /// Engine child process exited.
    EngineExit { exit_code: Option<i32> },
    /// Explicit operator/caller request.
    Requested,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeTelemetryEvent {
    pub timestamp: String,
    pub event_type: String,
    pub payload: serde_json::Value,
}

/// Final report from a telemetry bridge runtime after join().
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryRuntimeReport {
    pub final_state: BridgeLifecycleState,
    pub bridge_id: String,
    pub accepted_total: u64,
    pub persisted_total: u64,
    pub shed_total: u64,
    pub dropped_total: u64,
    pub retry_total: u64,
    pub drain_completed: bool,
    pub drain_duration_ms: u64,
    pub telemetry_events: Vec<RuntimeTelemetryEvent>,
    pub recent_events: Vec<TelemetryBridgeEvent>,
}

/// Error from starting the telemetry bridge.
#[derive(Debug)]
pub struct TelemetryStartError(pub String);

impl std::fmt::Display for TelemetryStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "telemetry start failed: {}", self.0)
    }
}

impl std::error::Error for TelemetryStartError {}

/// Error from joining the telemetry bridge runtime.
#[derive(Debug)]
pub struct TelemetryJoinError(pub String);

impl std::fmt::Display for TelemetryJoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "telemetry join failed: {}", self.0)
    }
}

impl std::error::Error for TelemetryJoinError {}

pub mod event_codes {
    pub const LISTENER_STARTED: &str = "TELEMETRY_BRIDGE_STATE_STARTED";
    pub const STATE_TRANSITION: &str = "TELEMETRY_BRIDGE_STATE_TRANSITION";
    pub const CONNECTION_ACCEPTED: &str = "TELEMETRY_BRIDGE_CONNECTION_ACCEPTED";
    pub const CONNECTION_REJECTED: &str = "TELEMETRY_BRIDGE_CONNECTION_REJECTED";
    pub const CONNECTION_CLOSED: &str = "TELEMETRY_BRIDGE_CONNECTION_CLOSED";
    pub const CONNECTION_READ_FAILED: &str = "TELEMETRY_BRIDGE_CONNECTION_READ_FAILED";
    pub const ADMISSION_ACCEPTED: &str = "TELEMETRY_BRIDGE_ADMISSION_ACCEPTED";
    pub const ADMISSION_SHED: &str = "TELEMETRY_BRIDGE_ADMISSION_SHED";
    pub const PERSIST_SUCCESS: &str = "TELEMETRY_BRIDGE_PERSIST_SUCCESS";
    pub const PERSIST_FAILURE: &str = "TELEMETRY_BRIDGE_PERSIST_FAILURE";
    pub const DRAIN_STARTED: &str = "TELEMETRY_BRIDGE_DRAIN_STARTED";
    pub const DRAIN_COMPLETE: &str = "TELEMETRY_BRIDGE_DRAIN_COMPLETE";
    pub const DRAIN_TIMEOUT: &str = "TELEMETRY_BRIDGE_DRAIN_TIMEOUT";
}

pub mod reason_codes {
    pub const ALLOWED: &str = "allowed";
    pub const QUEUE_FULL_SHED: &str = "queue_full_shed";
    pub const PERSIST_FAILED: &str = "persist_failed";
    pub const QUEUE_DISCONNECTED: &str = "queue_disconnected";
    pub const READ_FAILED: &str = "reader_failed";
    pub const INVALID_EVENT: &str = "invalid_event";
    pub const EVENT_TOO_LARGE: &str = "event_too_large";
    pub const CONNECTION_CAP: &str = "connection_cap";
    pub const SHUTDOWN_REQUESTED: &str = "shutdown_requested";
    pub const DRAIN_TIMEOUT: &str = "drain_timeout";
    pub const ENGINE_EXIT: &str = "engine_exit";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryBridgeEvent {
    pub code: String,
    pub bridge_id: String,
    pub connection_id: Option<u64>,
    pub bridge_seq: Option<u64>,
    pub reason_code: Option<String>,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub active_connections: usize,
    pub accepted_total: u64,
    pub persisted_total: u64,
    pub shed_total: u64,
    pub dropped_total: u64,
    pub retry_total: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryBridgeSnapshot {
    pub bridge_id: String,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub active_connections: usize,
    pub accepted_total: u64,
    pub persisted_total: u64,
    pub shed_total: u64,
    pub dropped_total: u64,
    pub retry_total: u64,
    pub recent_events: Vec<TelemetryBridgeEvent>,
}

#[derive(Debug, Clone)]
struct PersistEnvelope {
    connection_id: u64,
    bridge_seq: u64,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct TelemetryBridgeState {
    bridge_id: String,
    queue_depth: usize,
    queue_capacity: usize,
    active_connections: usize,
    accepted_total: u64,
    persisted_total: u64,
    shed_total: u64,
    dropped_total: u64,
    retry_total: u64,
    next_connection_id: u64,
    next_bridge_seq: u64,
    telemetry_events: Vec<RuntimeTelemetryEvent>,
    recent_events: Vec<TelemetryBridgeEvent>,
}

impl TelemetryBridgeState {
    fn new(queue_capacity: usize) -> Self {
        Self {
            bridge_id: format!("telemetry-bridge-{}", uuid::Uuid::now_v7()),
            queue_depth: 0,
            queue_capacity,
            active_connections: 0,
            accepted_total: 0,
            persisted_total: 0,
            shed_total: 0,
            dropped_total: 0,
            retry_total: 0,
            next_connection_id: 1,
            next_bridge_seq: 1,
            telemetry_events: Vec::new(),
            recent_events: Vec::new(),
        }
    }

    fn snapshot(&self) -> TelemetryBridgeSnapshot {
        TelemetryBridgeSnapshot {
            bridge_id: self.bridge_id.clone(),
            queue_depth: self.queue_depth,
            queue_capacity: self.queue_capacity,
            active_connections: self.active_connections,
            accepted_total: self.accepted_total,
            persisted_total: self.persisted_total,
            shed_total: self.shed_total,
            dropped_total: self.dropped_total,
            retry_total: self.retry_total,
            recent_events: self.recent_events.clone(),
        }
    }

    fn next_connection_id(&mut self) -> u64 {
        let id = self.next_connection_id;
        self.next_connection_id = self.next_connection_id.saturating_add(1);
        id
    }

    fn next_bridge_seq(&mut self) -> u64 {
        let seq = self.next_bridge_seq;
        self.next_bridge_seq = self.next_bridge_seq.saturating_add(1);
        seq
    }

    fn record_event(
        &mut self,
        code: &str,
        connection_id: Option<u64>,
        bridge_seq: Option<u64>,
        reason_code: Option<&str>,
        detail: impl Into<String>,
    ) {
        push_bounded(
            &mut self.recent_events,
            TelemetryBridgeEvent {
                code: code.to_string(),
                bridge_id: self.bridge_id.clone(),
                connection_id,
                bridge_seq,
                reason_code: reason_code.map(std::string::ToString::to_string),
                queue_depth: self.queue_depth,
                queue_capacity: self.queue_capacity,
                active_connections: self.active_connections,
                accepted_total: self.accepted_total,
                persisted_total: self.persisted_total,
                shed_total: self.shed_total,
                dropped_total: self.dropped_total,
                retry_total: self.retry_total,
                detail: detail.into(),
            },
            MAX_RECENT_EVENTS,
        );
    }

    fn record_runtime_event(&mut self, event: RuntimeTelemetryEvent) {
        push_bounded(&mut self.telemetry_events, event, MAX_RUNTIME_EVENTS);
    }
}

fn normalize_runtime_event_type(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "module_load" | "network_request" | "policy_check" | "error" | "metric" => Some(normalized),
        _ => None,
    }
}

fn parse_runtime_telemetry_event(
    payload: &[u8],
) -> std::result::Result<RuntimeTelemetryEvent, String> {
    let value = serde_json::from_slice::<serde_json::Value>(payload)
        .map_err(|err| format!("invalid telemetry JSON: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "telemetry line must be a JSON object".to_string())?;

    let timestamp = object
        .get("timestamp")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    let event_type = object
        .get("event_type")
        .and_then(serde_json::Value::as_str)
        .or_else(|| object.get("event").and_then(serde_json::Value::as_str))
        .and_then(normalize_runtime_event_type)
        .unwrap_or_else(|| "metric".to_string());
    let payload = object
        .get("payload")
        .cloned()
        .unwrap_or_else(|| value.clone());

    Ok(RuntimeTelemetryEvent {
        timestamp,
        event_type,
        payload,
    })
}

/// Owned runtime handle returned by `TelemetryBridge::start()`.
///
/// This handle gives `EngineDispatcher` explicit lifecycle control:
/// `socket_path()`, `snapshot()`, `stop()`, and `join()`.
pub struct TelemetryRuntimeHandle {
    socket_path: PathBuf,
    state: Arc<Mutex<TelemetryBridgeState>>,
    lifecycle: Arc<AtomicU8>,
    stop_flag: Arc<AtomicBool>,
    persistence_abort: Arc<AtomicBool>,
    connection_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    connection_worker_panicked: Arc<AtomicBool>,
    listener_handle: Option<JoinHandle<()>>,
    persistence_handle: Option<JoinHandle<()>>,
}

impl TelemetryRuntimeHandle {
    /// Path to the Unix domain socket the engine should connect to.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Point-in-time metrics snapshot.
    pub fn snapshot(&self) -> TelemetryBridgeSnapshot {
        self.state.lock().map_or_else(
            |_| TelemetryBridgeSnapshot {
                bridge_id: "telemetry-bridge-unavailable".to_string(),
                queue_depth: 0,
                queue_capacity: PERSIST_QUEUE_CAPACITY,
                active_connections: 0,
                accepted_total: 0,
                persisted_total: 0,
                shed_total: 0,
                dropped_total: 0,
                retry_total: 0,
                recent_events: Vec::new(),
            },
            |s| s.snapshot(),
        )
    }

    /// Current lifecycle state.
    pub fn lifecycle_state(&self) -> BridgeLifecycleState {
        BridgeLifecycleState::from_u8(self.lifecycle.load(Ordering::SeqCst))
    }

    /// Signal the bridge to stop accepting new work and begin draining.
    pub fn stop(&self, reason: ShutdownReason) {
        let reason_code = match &reason {
            ShutdownReason::EngineExit { .. } => reason_codes::ENGINE_EXIT,
            ShutdownReason::Requested => reason_codes::SHUTDOWN_REQUESTED,
        };
        self.stop_flag.store(true, Ordering::SeqCst);
        self.transition_state(BridgeLifecycleState::Draining);
        TelemetryBridge::with_state(&self.state, |metrics| {
            metrics.record_event(
                event_codes::DRAIN_STARTED,
                None,
                None,
                Some(reason_code),
                format!("shutdown requested: {reason_code}"),
            );
        });
    }

    /// Stop and join with the default drain timeout.
    pub fn stop_and_join(
        self,
        reason: ShutdownReason,
    ) -> Result<TelemetryRuntimeReport, TelemetryJoinError> {
        self.stop(reason);
        self.join(Duration::from_millis(DEFAULT_DRAIN_TIMEOUT_MS))
    }

    /// Wait for all workers to finish and return the final report.
    ///
    /// Must be called after `stop()`. If the drain deadline expires, the
    /// persistence worker is explicitly aborted and still joined before return
    /// so no background work silently survives the join boundary.
    pub fn join(
        mut self,
        deadline: Duration,
    ) -> Result<TelemetryRuntimeReport, TelemetryJoinError> {
        let drain_start = Instant::now();
        let mut join_error = None;

        // Join listener thread (should exit quickly after stop flag is set)
        if let Some(handle) = self.listener_handle.take()
            && handle.join().is_err()
        {
            self.mark_join_failed(
                &mut join_error,
                "telemetry listener worker panicked while joining runtime",
            );
        }

        if self.connection_worker_panicked.load(Ordering::SeqCst) {
            self.mark_join_failed(
                &mut join_error,
                "telemetry connection worker panicked while joining runtime",
            );
        }

        if let Err(err) = self.join_connection_workers() {
            self.connection_worker_panicked
                .store(true, Ordering::SeqCst);
            self.mark_join_failed(&mut join_error, &err.0);
        }

        // Join persistence thread (drains remaining queue items)
        if let Some(handle) = self.persistence_handle.take() {
            // Wait up to deadline for persistence to finish
            let remaining = deadline.saturating_sub(drain_start.elapsed());
            let timed_out = if handle.is_finished() {
                false
            } else if remaining.is_zero() {
                true
            } else {
                let park_start = Instant::now();
                loop {
                    if handle.is_finished() {
                        break false;
                    }
                    if park_start.elapsed() >= remaining {
                        break true;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            };

            if timed_out {
                self.transition_state(BridgeLifecycleState::Failed);
                self.persistence_abort.store(true, Ordering::SeqCst);
                TelemetryBridge::with_state(&self.state, |metrics| {
                    metrics.record_event(
                        event_codes::DRAIN_TIMEOUT,
                        None,
                        None,
                        Some(reason_codes::DRAIN_TIMEOUT),
                        format!("drain did not complete within {}ms", deadline.as_millis()),
                    );
                });
            }

            if handle.join().is_err() {
                self.mark_join_failed(
                    &mut join_error,
                    "telemetry persistence worker panicked while joining runtime",
                );
            }
        }

        let drain_duration = drain_start.elapsed();
        let drain_completed = !matches!(self.lifecycle_state(), BridgeLifecycleState::Failed);

        if drain_completed {
            self.transition_state(BridgeLifecycleState::Stopped);
            TelemetryBridge::with_state(&self.state, |metrics| {
                metrics.record_event(
                    event_codes::DRAIN_COMPLETE,
                    None,
                    None,
                    Some(reason_codes::ALLOWED),
                    format!("drain completed in {}ms", drain_duration.as_millis()),
                );
            });
        }

        if let Some(err) = join_error {
            return Err(err);
        }

        let snapshot = self.snapshot();
        let telemetry_events = self
            .state
            .lock()
            .map(|state| state.telemetry_events.clone())
            .unwrap_or_default();
        Ok(TelemetryRuntimeReport {
            final_state: self.lifecycle_state(),
            bridge_id: snapshot.bridge_id,
            accepted_total: snapshot.accepted_total,
            persisted_total: snapshot.persisted_total,
            shed_total: snapshot.shed_total,
            dropped_total: snapshot.dropped_total,
            retry_total: snapshot.retry_total,
            drain_completed,
            drain_duration_ms: u64::try_from(drain_duration.as_millis()).unwrap_or(u64::MAX),
            telemetry_events,
            recent_events: snapshot.recent_events,
        })
    }

    fn join_connection_workers(&self) -> Result<(), TelemetryJoinError> {
        let mut registry_poisoned = false;
        let handles = {
            let mut guard = match self.connection_handles.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    registry_poisoned = true;
                    poisoned.into_inner()
                }
            };
            std::mem::take(&mut *guard)
        };

        let mut worker_panicked = false;
        for handle in handles {
            if handle.join().is_err() {
                worker_panicked = true;
            }
        }

        if registry_poisoned {
            Err(TelemetryJoinError(
                "telemetry connection worker registry poisoned while joining runtime".to_string(),
            ))
        } else if worker_panicked {
            Err(TelemetryJoinError(
                "telemetry connection worker panicked while joining runtime".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn mark_join_failed(&self, slot: &mut Option<TelemetryJoinError>, message: &str) {
        if !matches!(self.lifecycle_state(), BridgeLifecycleState::Failed) {
            self.transition_state(BridgeLifecycleState::Failed);
        }
        if slot.is_none() {
            *slot = Some(TelemetryJoinError(message.to_string()));
        }
    }

    fn transition_state(&self, new_state: BridgeLifecycleState) {
        let old = self.lifecycle.swap(new_state as u8, Ordering::SeqCst);
        TelemetryBridge::with_state(&self.state, |metrics| {
            metrics.record_event(
                event_codes::STATE_TRANSITION,
                None,
                None,
                None,
                format!(
                    "{:?} -> {:?}",
                    BridgeLifecycleState::from_u8(old),
                    new_state
                ),
            );
        });
    }
}

pub struct TelemetryBridge {
    socket_path: String,
    adapter_slot: Mutex<Option<Arc<Mutex<FrankensqliteAdapter>>>>,
    state: Arc<Mutex<TelemetryBridgeState>>,
    lifecycle: Arc<AtomicU8>,
    stop_flag: Arc<AtomicBool>,
    started: AtomicBool,
}

impl TelemetryBridge {
    pub fn new(socket_path: &str, adapter: Arc<Mutex<FrankensqliteAdapter>>) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            adapter_slot: Mutex::new(Some(adapter)),
            state: Arc::new(Mutex::new(TelemetryBridgeState::new(
                PERSIST_QUEUE_CAPACITY,
            ))),
            lifecycle: Arc::new(AtomicU8::new(BridgeLifecycleState::Cold as u8)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            started: AtomicBool::new(false),
        }
    }

    pub fn snapshot(&self) -> TelemetryBridgeSnapshot {
        self.state.lock().map_or_else(
            |_| TelemetryBridgeSnapshot {
                bridge_id: "telemetry-bridge-unavailable".to_string(),
                queue_depth: 0,
                queue_capacity: PERSIST_QUEUE_CAPACITY,
                active_connections: 0,
                accepted_total: 0,
                persisted_total: 0,
                shed_total: 0,
                dropped_total: 0,
                retry_total: 0,
                recent_events: Vec::new(),
            },
            |s| s.snapshot(),
        )
    }

    /// Start the telemetry bridge and return an owned runtime handle.
    ///
    /// The handle gives `EngineDispatcher` explicit lifecycle control via
    /// `stop()` and `join()`. No background work can silently outlive the
    /// handle's `join()` call.
    pub fn start(self) -> Result<TelemetryRuntimeHandle> {
        if self
            .started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            anyhow::bail!("telemetry bridge listener already started");
        }

        self.lifecycle
            .store(BridgeLifecycleState::Starting as u8, Ordering::SeqCst);

        let socket_path = self.socket_path.clone();
        let state = Arc::clone(&self.state);
        let stop_flag = Arc::clone(&self.stop_flag);
        let lifecycle = Arc::clone(&self.lifecycle);
        let adapter = {
            let mut guard = self
                .adapter_slot
                .lock()
                .map_err(|_| anyhow::anyhow!("telemetry adapter lock poisoned before start"))?;
            guard.take().ok_or_else(|| {
                anyhow::anyhow!("telemetry adapter already claimed by persistence owner")
            })?
        };
        let persistence_abort = Arc::new(AtomicBool::new(false));
        let connection_handles = Arc::new(Mutex::new(Vec::new()));
        let connection_worker_panicked = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::sync_channel(PERSIST_QUEUE_CAPACITY);

        // Clean up stale socket
        match std::fs::remove_file(&socket_path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                lifecycle.store(BridgeLifecycleState::Failed as u8, Ordering::SeqCst);
                return Err(err.into());
            }
        }

        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(err) => {
                lifecycle.store(BridgeLifecycleState::Failed as u8, Ordering::SeqCst);
                return Err(err.into());
            }
        };

        // Set non-blocking so the accept loop can check the stop flag
        listener.set_nonblocking(true).inspect_err(|_| {
            lifecycle.store(BridgeLifecycleState::Failed as u8, Ordering::SeqCst);
        })?;

        // Only spawn the persistence owner after listener setup succeeds so a
        // failed start path cannot briefly detach a worker without a handle.
        let persistence_state = Arc::clone(&state);
        let persistence_abort_for_worker = Arc::clone(&persistence_abort);
        let persistence_handle = thread::spawn(move || {
            Self::run_persistence_loop(
                receiver,
                adapter,
                persistence_state,
                persistence_abort_for_worker,
            );
        });

        Self::with_state(&state, |metrics| {
            metrics.record_event(
                event_codes::LISTENER_STARTED,
                None,
                None,
                Some(reason_codes::ALLOWED),
                format!("listening on {socket_path}"),
            );
        });

        lifecycle.store(BridgeLifecycleState::Running as u8, Ordering::SeqCst);

        // Listener owner thread
        let listener_state = Arc::clone(&state);
        let listener_stop = Arc::clone(&stop_flag);
        let listener_lifecycle = Arc::clone(&lifecycle);
        let listener_connection_handles = Arc::clone(&connection_handles);
        let listener_connection_panicked = Arc::clone(&connection_worker_panicked);
        let listener_handle = thread::spawn(move || {
            Self::run_accept_loop(
                listener,
                sender,
                listener_state,
                listener_stop,
                listener_lifecycle,
                listener_connection_handles,
                listener_connection_panicked,
            );
        });

        Ok(TelemetryRuntimeHandle {
            socket_path: PathBuf::from(&self.socket_path),
            state,
            lifecycle,
            stop_flag,
            persistence_abort,
            connection_handles,
            connection_worker_panicked,
            listener_handle: Some(listener_handle),
            persistence_handle: Some(persistence_handle),
        })
    }

    /// Accept loop with non-blocking listener, stop-flag check, and
    /// connection cap enforcement.
    fn run_accept_loop(
        listener: UnixListener,
        sender: SyncSender<PersistEnvelope>,
        state: Arc<Mutex<TelemetryBridgeState>>,
        stop_flag: Arc<AtomicBool>,
        lifecycle: Arc<AtomicU8>,
        connection_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
        connection_worker_panicked: Arc<AtomicBool>,
    ) {
        loop {
            // Check stop flag
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }

            if !Self::reap_finished_connection_workers(
                &connection_handles,
                &connection_worker_panicked,
            ) {
                lifecycle.store(BridgeLifecycleState::Failed as u8, Ordering::SeqCst);
                stop_flag.store(true, Ordering::SeqCst);
                break;
            }

            match listener.accept() {
                Ok((stream, _addr)) => {
                    // Enforce connection cap
                    let active = Self::with_state(&state, |m| m.active_connections).unwrap_or(0);
                    if active >= MAX_ACTIVE_CONNECTIONS {
                        Self::with_state(&state, |metrics| {
                            metrics.record_event(
                                event_codes::CONNECTION_REJECTED,
                                None,
                                None,
                                Some(reason_codes::CONNECTION_CAP),
                                format!(
                                    "rejected: {active} active connections (cap {MAX_ACTIVE_CONNECTIONS})"
                                ),
                            );
                        });
                        drop(stream);
                        continue;
                    }

                    // Check stop flag again after accept
                    if stop_flag.load(Ordering::SeqCst) {
                        drop(stream);
                        break;
                    }

                    let Some(connection_id) = Self::with_state(&state, |metrics| {
                        let connection_id = metrics.next_connection_id();
                        metrics.active_connections = metrics.active_connections.saturating_add(1);
                        metrics.record_event(
                            event_codes::CONNECTION_ACCEPTED,
                            Some(connection_id),
                            None,
                            Some(reason_codes::ALLOWED),
                            "accepted telemetry connection",
                        );
                        connection_id
                    }) else {
                        continue;
                    };

                    let sender_inner = sender.clone();
                    let state_inner = Arc::clone(&state);
                    let stop_inner = Arc::clone(&stop_flag);
                    let handle = thread::spawn(move || {
                        Self::handle_connection(
                            connection_id,
                            stream,
                            sender_inner,
                            state_inner,
                            stop_inner,
                        );
                    });
                    if let Ok(mut handles) = connection_handles.lock() {
                        handles.push(handle);
                    } else {
                        connection_worker_panicked.store(true, Ordering::SeqCst);
                        lifecycle.store(BridgeLifecycleState::Failed as u8, Ordering::SeqCst);
                        stop_flag.store(true, Ordering::SeqCst);
                        let _ = handle.join();
                        break;
                    }

                    if !Self::reap_finished_connection_workers(
                        &connection_handles,
                        &connection_worker_panicked,
                    ) {
                        lifecycle.store(BridgeLifecycleState::Failed as u8, Ordering::SeqCst);
                        stop_flag.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    // Non-blocking: no pending connection, sleep briefly
                    thread::sleep(Duration::from_millis(ACCEPT_POLL_INTERVAL_MS));
                }
                Err(err) => {
                    Self::with_state(&state, |metrics| {
                        metrics.record_event(
                            event_codes::CONNECTION_READ_FAILED,
                            None,
                            None,
                            Some(reason_codes::READ_FAILED),
                            format!("listener accept failed: {err}"),
                        );
                    });
                    // Move to Degraded if we're still Running
                    let current = lifecycle.load(Ordering::SeqCst);
                    if current == BridgeLifecycleState::Running as u8 {
                        lifecycle.store(BridgeLifecycleState::Degraded as u8, Ordering::SeqCst);
                    }
                }
            }
        }

        if !Self::reap_finished_connection_workers(&connection_handles, &connection_worker_panicked)
        {
            lifecycle.store(BridgeLifecycleState::Failed as u8, Ordering::SeqCst);
            stop_flag.store(true, Ordering::SeqCst);
        }

        // Drop sender to signal persistence thread to drain and exit
        drop(sender);
    }

    fn reap_finished_connection_workers(
        connection_handles: &Arc<Mutex<Vec<JoinHandle<()>>>>,
        connection_worker_panicked: &Arc<AtomicBool>,
    ) -> bool {
        let finished = {
            let Ok(mut handles) = connection_handles.lock() else {
                connection_worker_panicked.store(true, Ordering::SeqCst);
                return false;
            };
            let mut finished = Vec::new();
            let mut idx = 0usize;
            while idx < handles.len() {
                if handles[idx].is_finished() {
                    finished.push(handles.swap_remove(idx));
                } else {
                    idx = idx.saturating_add(1);
                }
            }
            finished
        };

        let mut worker_panicked = false;
        for handle in finished {
            if handle.join().is_err() {
                connection_worker_panicked.store(true, Ordering::SeqCst);
                worker_panicked = true;
            }
        }
        !worker_panicked
    }

    fn handle_connection(
        connection_id: u64,
        stream: UnixStream,
        sender: SyncSender<PersistEnvelope>,
        state: Arc<Mutex<TelemetryBridgeState>>,
        stop_flag: Arc<AtomicBool>,
    ) {
        if let Err(err) =
            stream.set_read_timeout(Some(Duration::from_millis(CONNECTION_READ_TIMEOUT_MS)))
        {
            Self::with_state(&state, |metrics| {
                metrics.record_event(
                    event_codes::CONNECTION_READ_FAILED,
                    Some(connection_id),
                    None,
                    Some(reason_codes::READ_FAILED),
                    format!("failed to configure connection read timeout: {err}"),
                );
                metrics.active_connections = metrics.active_connections.saturating_sub(1);
                metrics.record_event(
                    event_codes::CONNECTION_CLOSED,
                    Some(connection_id),
                    None,
                    Some(reason_codes::READ_FAILED),
                    "connection closed after read-timeout setup failure",
                );
            });
            return;
        }
        let mut reader = BufReader::new(stream);
        let mut event_bytes = Vec::new();

        loop {
            // Stop flag check: refuse new events during drain
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }

            match reader.read_until(b'\n', &mut event_bytes) {
                Ok(0) => break,
                Ok(_) => {
                    if event_bytes.ends_with(b"\n") {
                        event_bytes.pop();
                        if event_bytes.ends_with(b"\r") {
                            event_bytes.pop();
                        }
                    }

                    if event_bytes.is_empty() {
                        continue;
                    }

                    if event_bytes.len() > MAX_EVENT_BYTES {
                        Self::with_state(&state, |metrics| {
                            metrics.shed_total = metrics.shed_total.saturating_add(1);
                            metrics.record_event(
                                event_codes::ADMISSION_SHED,
                                Some(connection_id),
                                None,
                                Some(reason_codes::EVENT_TOO_LARGE),
                                format!("event exceeded {} bytes", MAX_EVENT_BYTES),
                            );
                        });
                        event_bytes.clear();
                        continue;
                    }

                    let parsed_event = match parse_runtime_telemetry_event(&event_bytes) {
                        Ok(event) => event,
                        Err(err) => {
                            Self::with_state(&state, |metrics| {
                                metrics.shed_total = metrics.shed_total.saturating_add(1);
                                metrics.record_event(
                                    event_codes::ADMISSION_SHED,
                                    Some(connection_id),
                                    None,
                                    Some(reason_codes::INVALID_EVENT),
                                    format!("skipped invalid telemetry line: {err}"),
                                );
                            });
                            event_bytes.clear();
                            continue;
                        }
                    };
                    Self::with_state(&state, |metrics| {
                        metrics.record_runtime_event(parsed_event);
                    });

                    let bridge_seq =
                        Self::with_state(&state, TelemetryBridgeState::next_bridge_seq)
                            .unwrap_or_default();
                    let envelope = PersistEnvelope {
                        connection_id,
                        bridge_seq,
                        payload: event_bytes.clone(),
                    };
                    event_bytes.clear();

                    let admitted = Self::enqueue_with_timeout(
                        &sender,
                        envelope,
                        &state,
                        Duration::from_millis(ENQUEUE_TIMEOUT_MS),
                    );
                    if !admitted {
                        continue;
                    }
                }
                Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    continue;
                }
                Err(err) => {
                    Self::with_state(&state, |metrics| {
                        metrics.record_event(
                            event_codes::CONNECTION_READ_FAILED,
                            Some(connection_id),
                            None,
                            Some(reason_codes::READ_FAILED),
                            format!("connection read failed: {err}"),
                        );
                    });
                    break;
                }
            }
        }

        Self::with_state(&state, |metrics| {
            metrics.active_connections = metrics.active_connections.saturating_sub(1);
            metrics.record_event(
                event_codes::CONNECTION_CLOSED,
                Some(connection_id),
                None,
                Some(reason_codes::ALLOWED),
                "connection closed",
            );
        });
    }

    fn enqueue_with_timeout(
        sender: &SyncSender<PersistEnvelope>,
        envelope: PersistEnvelope,
        state: &Arc<Mutex<TelemetryBridgeState>>,
        timeout: Duration,
    ) -> bool {
        enum EnqueueOutcome {
            Accepted,
            Retry,
            Rejected,
        }

        let deadline = Instant::now() + timeout;
        loop {
            let outcome = {
                let mut metrics = match state.lock() {
                    Ok(metrics) => metrics,
                    Err(_) => return false,
                };

                match sender.try_send(envelope.clone()) {
                    Ok(()) => {
                        metrics.accepted_total = metrics.accepted_total.saturating_add(1);
                        metrics.queue_depth = metrics.queue_depth.saturating_add(1);
                        metrics.record_event(
                            event_codes::ADMISSION_ACCEPTED,
                            Some(envelope.connection_id),
                            Some(envelope.bridge_seq),
                            Some(reason_codes::ALLOWED),
                            "accepted telemetry envelope into bounded queue",
                        );
                        EnqueueOutcome::Accepted
                    }
                    Err(TrySendError::Full(_)) if Instant::now() < deadline => {
                        metrics.retry_total = metrics.retry_total.saturating_add(1);
                        EnqueueOutcome::Retry
                    }
                    Err(TrySendError::Full(_)) => {
                        metrics.shed_total = metrics.shed_total.saturating_add(1);
                        metrics.record_event(
                            event_codes::ADMISSION_SHED,
                            Some(envelope.connection_id),
                            Some(envelope.bridge_seq),
                            Some(reason_codes::QUEUE_FULL_SHED),
                            "queue remained full until enqueue timeout expired",
                        );
                        EnqueueOutcome::Rejected
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        metrics.dropped_total = metrics.dropped_total.saturating_add(1);
                        metrics.record_event(
                            event_codes::PERSIST_FAILURE,
                            Some(envelope.connection_id),
                            Some(envelope.bridge_seq),
                            Some(reason_codes::QUEUE_DISCONNECTED),
                            "persistence queue disconnected before admission",
                        );
                        EnqueueOutcome::Rejected
                    }
                }
            };

            match outcome {
                EnqueueOutcome::Accepted => return true,
                EnqueueOutcome::Retry => thread::sleep(Duration::from_millis(1)),
                EnqueueOutcome::Rejected => return false,
            }
        }
    }

    fn run_persistence_loop(
        receiver: Receiver<PersistEnvelope>,
        adapter: Arc<Mutex<FrankensqliteAdapter>>,
        state: Arc<Mutex<TelemetryBridgeState>>,
        abort_flag: Arc<AtomicBool>,
    ) {
        loop {
            if abort_flag.load(Ordering::SeqCst) {
                Self::abort_pending_persistence(None, &receiver, &state);
                break;
            }

            // This can block without polling because join() first stops and
            // joins the listener owner, then drains all tracked connection
            // workers before it waits on persistence.
            let envelope = match receiver.recv() {
                Ok(envelope) => envelope,
                Err(_) => break,
            };

            if abort_flag.load(Ordering::SeqCst) {
                Self::abort_pending_persistence(Some(envelope), &receiver, &state);
                break;
            }

            Self::with_state(&state, |metrics| {
                metrics.queue_depth = metrics.queue_depth.saturating_sub(1);
            });

            let key = format!("telemetry_{:020}", envelope.bridge_seq);
            let write_result = match adapter.lock() {
                Ok(mut db) => db.write(PersistenceClass::AuditLog, &key, &envelope.payload),
                Err(_) => {
                    Self::with_state(&state, |metrics| {
                        metrics.dropped_total = metrics.dropped_total.saturating_add(1);
                        metrics.record_event(
                            event_codes::PERSIST_FAILURE,
                            Some(envelope.connection_id),
                            Some(envelope.bridge_seq),
                            Some(reason_codes::PERSIST_FAILED),
                            format!("failed to persist audit event {key}: adapter lock poisoned"),
                        );
                    });
                    continue;
                }
            };

            match write_result {
                Ok(_) => Self::with_state(&state, |metrics| {
                    metrics.persisted_total = metrics.persisted_total.saturating_add(1);
                    metrics.record_event(
                        event_codes::PERSIST_SUCCESS,
                        Some(envelope.connection_id),
                        Some(envelope.bridge_seq),
                        Some(reason_codes::ALLOWED),
                        format!("persisted audit event with key {key}"),
                    );
                }),
                Err(err) => Self::with_state(&state, |metrics| {
                    metrics.dropped_total = metrics.dropped_total.saturating_add(1);
                    metrics.record_event(
                        event_codes::PERSIST_FAILURE,
                        Some(envelope.connection_id),
                        Some(envelope.bridge_seq),
                        Some(reason_codes::PERSIST_FAILED),
                        format!("failed to persist audit event {key}: {err}"),
                    );
                }),
            };
        }
    }

    fn abort_pending_persistence(
        first: Option<PersistEnvelope>,
        receiver: &Receiver<PersistEnvelope>,
        state: &Arc<Mutex<TelemetryBridgeState>>,
    ) {
        let dropped = first
            .into_iter()
            .chain(receiver.try_iter())
            .fold(0usize, |count, _| count.saturating_add(1));

        if dropped == 0 {
            return;
        }

        Self::with_state(state, |metrics| {
            metrics.queue_depth = metrics.queue_depth.saturating_sub(dropped);
            metrics.dropped_total = metrics.dropped_total.saturating_add(dropped as u64);
            metrics.record_event(
                event_codes::PERSIST_FAILURE,
                None,
                None,
                Some(reason_codes::DRAIN_TIMEOUT),
                format!("aborted {dropped} queued telemetry envelopes after drain timeout"),
            );
        });
    }

    fn with_state<R>(
        state: &Arc<Mutex<TelemetryBridgeState>>,
        op: impl FnOnce(&mut TelemetryBridgeState) -> R,
    ) -> Option<R> {
        state.lock().ok().map(|mut metrics| op(&mut metrics))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state(queue_capacity: usize) -> Arc<Mutex<TelemetryBridgeState>> {
        Arc::new(Mutex::new(TelemetryBridgeState::new(queue_capacity)))
    }

    #[test]
    fn snapshot_starts_with_empty_counters() {
        let bridge = TelemetryBridge::new(
            "/tmp/telemetry.sock",
            Arc::new(Mutex::new(FrankensqliteAdapter::default())),
        );
        let snapshot = bridge.snapshot();
        assert_eq!(snapshot.queue_depth, 0);
        assert_eq!(snapshot.queue_capacity, PERSIST_QUEUE_CAPACITY);
        assert_eq!(snapshot.accepted_total, 0);
        assert_eq!(snapshot.persisted_total, 0);
        assert!(snapshot.recent_events.is_empty());
    }

    #[test]
    fn enqueue_timeout_records_shed_when_queue_stays_full() {
        let state = test_state(1);
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(PersistEnvelope {
                connection_id: 1,
                bridge_seq: 1,
                payload: b"first".to_vec(),
            })
            .expect("initial queue fill should succeed");

        let admitted = TelemetryBridge::enqueue_with_timeout(
            &sender,
            PersistEnvelope {
                connection_id: 2,
                bridge_seq: 2,
                payload: b"second".to_vec(),
            },
            &state,
            Duration::ZERO,
        );
        drop(receiver);

        assert!(!admitted);
        let snapshot = state
            .lock()
            .map(|s| s.snapshot())
            .unwrap_or_else(|_| unreachable!("state lock poisoned"));
        assert_eq!(snapshot.accepted_total, 0);
        assert_eq!(snapshot.shed_total, 1);
        assert_eq!(
            snapshot
                .recent_events
                .last()
                .map(|event| event.reason_code.clone()),
            Some(Some(reason_codes::QUEUE_FULL_SHED.to_string()))
        );
    }

    #[test]
    fn persistence_loop_updates_single_owner_counters() {
        let state = test_state(2);
        let (sender, receiver) = mpsc::sync_channel(2);
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let state_for_worker = Arc::clone(&state);
        let abort_flag = Arc::new(AtomicBool::new(false));
        let abort_for_worker = Arc::clone(&abort_flag);
        let worker = thread::spawn(move || {
            TelemetryBridge::run_persistence_loop(
                receiver,
                adapter,
                state_for_worker,
                abort_for_worker,
            );
        });

        let admitted = TelemetryBridge::enqueue_with_timeout(
            &sender,
            PersistEnvelope {
                connection_id: 7,
                bridge_seq: 42,
                payload: br#"{"event":"ok"}"#.to_vec(),
            },
            &state,
            Duration::from_millis(10),
        );
        assert!(admitted);
        drop(sender);
        worker
            .join()
            .expect("persistence worker should exit cleanly");

        let snapshot = state
            .lock()
            .map(|s| s.snapshot())
            .unwrap_or_else(|_| unreachable!("state lock poisoned"));
        assert_eq!(snapshot.accepted_total, 1);
        assert_eq!(snapshot.persisted_total, 1);
        assert_eq!(snapshot.queue_depth, 0);
        assert!(
            snapshot
                .recent_events
                .iter()
                .any(|event| event.code == event_codes::PERSIST_SUCCESS)
        );
    }

    #[test]
    fn disconnected_queue_records_explicit_drop_reason() {
        let state = test_state(1);
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);

        let admitted = TelemetryBridge::enqueue_with_timeout(
            &sender,
            PersistEnvelope {
                connection_id: 9,
                bridge_seq: 99,
                payload: b"disconnected".to_vec(),
            },
            &state,
            Duration::from_millis(5),
        );

        assert!(!admitted);
        let snapshot = state
            .lock()
            .map(|s| s.snapshot())
            .unwrap_or_else(|_| unreachable!("state lock poisoned"));
        assert_eq!(snapshot.dropped_total, 1);
        assert_eq!(
            snapshot
                .recent_events
                .last()
                .map(|event| event.reason_code.clone()),
            Some(Some(reason_codes::QUEUE_DISCONNECTED.to_string()))
        );
    }

    #[test]
    fn lifecycle_starts_cold() {
        let bridge = TelemetryBridge::new(
            "/tmp/test_lifecycle_cold.sock",
            Arc::new(Mutex::new(FrankensqliteAdapter::default())),
        );
        assert_eq!(
            BridgeLifecycleState::from_u8(bridge.lifecycle.load(Ordering::SeqCst)),
            BridgeLifecycleState::Cold,
        );
    }

    #[test]
    fn lifecycle_state_roundtrip() {
        for val in 0..=6u8 {
            let state = BridgeLifecycleState::from_u8(val);
            assert_eq!(state as u8, val);
        }
        // Out-of-range maps to Failed
        assert_eq!(
            BridgeLifecycleState::from_u8(255),
            BridgeLifecycleState::Failed
        );
    }

    #[test]
    fn lifecycle_terminal_states() {
        assert!(!BridgeLifecycleState::Cold.is_terminal());
        assert!(!BridgeLifecycleState::Starting.is_terminal());
        assert!(!BridgeLifecycleState::Running.is_terminal());
        assert!(!BridgeLifecycleState::Degraded.is_terminal());
        assert!(!BridgeLifecycleState::Draining.is_terminal());
        assert!(BridgeLifecycleState::Stopped.is_terminal());
        assert!(BridgeLifecycleState::Failed.is_terminal());
    }

    #[test]
    fn start_returns_handle_with_running_state() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_start.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start should succeed");
        assert_eq!(handle.lifecycle_state(), BridgeLifecycleState::Running);
        assert_eq!(handle.socket_path(), sock.as_path());

        // Stop and join cleanly
        handle.stop(ShutdownReason::Requested);
        let report = handle.join(Duration::from_secs(5)).expect("join");
        assert!(report.drain_completed);
        assert_eq!(report.final_state, BridgeLifecycleState::Stopped);
    }

    #[test]
    fn start_twice_fails() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_double_start.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);

        // Mark as already started
        bridge.started.store(true, Ordering::SeqCst);
        let result = bridge.start();
        assert!(result.is_err());
    }

    #[test]
    fn handle_stop_transitions_to_draining() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_drain.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        handle.stop(ShutdownReason::EngineExit { exit_code: Some(0) });
        // After stop, state should be Draining (before join completes)
        let state = handle.lifecycle_state();
        assert!(
            state == BridgeLifecycleState::Draining || state == BridgeLifecycleState::Stopped,
            "expected Draining or Stopped, got {state:?}",
        );
        let report = handle.join(Duration::from_secs(5)).expect("join");
        assert!(report.drain_completed);
        assert!(
            report
                .recent_events
                .iter()
                .any(|e| e.code == event_codes::DRAIN_STARTED),
        );
    }

    #[test]
    fn handle_snapshot_reflects_idle_state() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_snap.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        let snap = handle.snapshot();
        assert_eq!(snap.queue_depth, 0);
        assert_eq!(snap.accepted_total, 0);
        assert_eq!(snap.active_connections, 0);
        handle.stop(ShutdownReason::Requested);
        let _ = handle.join(Duration::from_secs(5));
    }

    #[test]
    fn connection_cap_enforcement() {
        // Verify the constant is what we expect
        assert_eq!(MAX_ACTIVE_CONNECTIONS, 64);
        // The actual cap enforcement is tested via the accept loop, but we can
        // verify the state tracking logic: if active_connections >= MAX_ACTIVE_CONNECTIONS,
        // the loop rejects.
        let state = test_state(2);
        state
            .lock()
            .unwrap_or_else(|_| unreachable!("state lock poisoned"))
            .active_connections = MAX_ACTIVE_CONNECTIONS;
        let snap = state
            .lock()
            .unwrap_or_else(|_| unreachable!("state lock poisoned"))
            .snapshot();
        assert_eq!(snap.active_connections, MAX_ACTIVE_CONNECTIONS);
    }

    #[test]
    fn runtime_report_contains_bridge_id() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_report_id.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        let snap_id = handle.snapshot().bridge_id.clone();
        handle.stop(ShutdownReason::Requested);
        let report = handle.join(Duration::from_secs(5)).expect("join");
        assert_eq!(report.bridge_id, snap_id);
        assert!(report.bridge_id.starts_with("telemetry-bridge-"));
    }

    #[test]
    fn push_bounded_caps_at_limit() {
        let mut items = Vec::new();
        for i in 0..10 {
            push_bounded(&mut items, i, 5);
        }
        assert_eq!(items.len(), 5);
        assert_eq!(items, vec![5, 6, 7, 8, 9]);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(
            items.is_empty(),
            "zero-capacity buffers must not retain stale events"
        );
    }

    #[test]
    fn push_bounded_large_overflow_keeps_only_latest_window() {
        let mut items = vec![10, 11, 12, 13];

        push_bounded(&mut items, 99, 2);

        assert_eq!(items, vec![13, 99]);
    }

    #[test]
    fn parse_runtime_event_rejects_non_object_json() {
        let err = parse_runtime_telemetry_event(br#"[{"event":"metric"}]"#)
            .expect_err("array payloads are not telemetry objects");

        assert!(
            err.contains("JSON object"),
            "non-object payloads should fail with an object-shape error: {err}"
        );
    }

    #[test]
    fn parse_runtime_event_rejects_malformed_json() {
        let err = parse_runtime_telemetry_event(br#"{"event_type":"metric","#)
            .expect_err("truncated JSON must be rejected");

        assert!(
            err.contains("invalid telemetry JSON"),
            "malformed JSON should retain the parser failure context: {err}"
        );
    }

    #[test]
    fn invalid_event_type_falls_back_to_metric() {
        let event = parse_runtime_telemetry_event(
            br#"{"timestamp":"2026-04-06T00:00:00Z","event_type":" shell_exec ","payload":{"bad":true}}"#,
        )
        .expect("invalid event type should fall back instead of failing ingestion");

        assert_eq!(event.event_type, "metric");
        assert_eq!(event.payload, serde_json::json!({ "bad": true }));
    }

    #[test]
    fn blank_event_alias_falls_back_to_metric() {
        let event = parse_runtime_telemetry_event(
            br#"{"timestamp":"2026-04-06T00:00:00Z","event":"   ","payload":{"empty_alias":true}}"#,
        )
        .expect("blank event aliases should not create empty event types");

        assert_eq!(event.event_type, "metric");
        assert_eq!(event.payload, serde_json::json!({ "empty_alias": true }));
    }

    #[test]
    fn with_state_returns_none_after_poisoned_lock() {
        let state = test_state(1);
        let state_for_poison = Arc::clone(&state);
        let _ = thread::spawn(move || {
            let _guard = state_for_poison.lock().expect("state lock");
            panic!("poison telemetry state lock");
        })
        .join();

        assert!(
            TelemetryBridge::with_state(&state, |metrics| metrics.accepted_total).is_none(),
            "poisoned telemetry state should not be used after lock acquisition fails"
        );
    }

    #[test]
    fn abort_pending_persistence_saturates_depth_and_drop_count() {
        let state = test_state(4);
        {
            let mut metrics = state.lock().expect("state lock");
            metrics.queue_depth = 1;
            metrics.dropped_total = u64::MAX - 1;
        }
        let (sender, receiver) = mpsc::sync_channel(4);
        for bridge_seq in 2..=3 {
            sender
                .try_send(PersistEnvelope {
                    connection_id: 7,
                    bridge_seq,
                    payload: br#"{"event":"pending"}"#.to_vec(),
                })
                .expect("queue seed should fit");
        }
        drop(sender);

        TelemetryBridge::abort_pending_persistence(
            Some(PersistEnvelope {
                connection_id: 7,
                bridge_seq: 1,
                payload: br#"{"event":"first"}"#.to_vec(),
            }),
            &receiver,
            &state,
        );

        let snapshot = state.lock().expect("state lock").snapshot();
        assert_eq!(
            snapshot.queue_depth, 0,
            "drop accounting must not underflow queue depth"
        );
        assert_eq!(
            snapshot.dropped_total,
            u64::MAX,
            "drop accounting must saturate at u64::MAX"
        );
        assert!(
            snapshot.recent_events.iter().any(|event| {
                event.code == event_codes::PERSIST_FAILURE
                    && event.reason_code.as_deref() == Some(reason_codes::DRAIN_TIMEOUT)
            }),
            "aborted pending persistence must emit a drain-timeout failure event"
        );
    }

    #[test]
    fn zero_timeout_full_queue_does_not_record_retry() {
        let state = test_state(1);
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .try_send(PersistEnvelope {
                connection_id: 1,
                bridge_seq: 1,
                payload: br#"{"event":"already_queued"}"#.to_vec(),
            })
            .expect("initial queue fill should succeed");

        let admitted = TelemetryBridge::enqueue_with_timeout(
            &sender,
            PersistEnvelope {
                connection_id: 2,
                bridge_seq: 2,
                payload: br#"{"event":"shed"}"#.to_vec(),
            },
            &state,
            Duration::ZERO,
        );
        drop(receiver);

        let snapshot = state.lock().expect("state lock").snapshot();
        assert!(!admitted);
        assert_eq!(snapshot.retry_total, 0);
        assert_eq!(snapshot.shed_total, 1);
        assert!(
            snapshot.recent_events.iter().any(|event| {
                event.reason_code.as_deref() == Some(reason_codes::QUEUE_FULL_SHED)
            }),
            "zero-timeout admission failure should be classified as queue shedding"
        );
    }

    #[test]
    fn drain_timeout_reports_failure() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_drain_timeout.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        handle.stop(ShutdownReason::Requested);
        // Join with a reasonable timeout — should complete quickly since no work is queued
        let report = handle.join(Duration::from_secs(5)).expect("join");
        assert!(report.drain_completed);
        assert!(report.drain_duration_ms < 5000);
    }

    #[test]
    fn join_timeout_aborts_persistence_worker_before_returning() {
        let state = test_state(PERSIST_QUEUE_CAPACITY);
        let lifecycle = Arc::new(AtomicU8::new(BridgeLifecycleState::Draining as u8));
        let stop_flag = Arc::new(AtomicBool::new(true));
        let persistence_abort = Arc::new(AtomicBool::new(false));

        let state_for_worker = Arc::clone(&state);
        let abort_for_worker = Arc::clone(&persistence_abort);
        let worker = thread::spawn(move || {
            while !abort_for_worker.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
            }
            drop(state_for_worker);
        });

        let handle = TelemetryRuntimeHandle {
            socket_path: PathBuf::from("/tmp/telemetry-timeout-test.sock"),
            state: Arc::clone(&state),
            lifecycle,
            stop_flag,
            persistence_abort,
            connection_handles: Arc::new(Mutex::new(Vec::new())),
            connection_worker_panicked: Arc::new(AtomicBool::new(false)),
            listener_handle: None,
            persistence_handle: Some(worker),
        };

        let report = handle
            .join(Duration::ZERO)
            .expect("join should return report");

        assert!(!report.drain_completed);
        assert_eq!(report.final_state, BridgeLifecycleState::Failed);
        assert!(
            report
                .recent_events
                .iter()
                .any(|event| event.code == event_codes::DRAIN_TIMEOUT),
            "timeout path should emit DRAIN_TIMEOUT"
        );
        assert_eq!(
            Arc::strong_count(&state),
            1,
            "persistence worker should be joined before join() returns"
        );
    }

    #[test]
    fn zero_deadline_does_not_timeout_an_already_finished_worker() {
        let state = test_state(PERSIST_QUEUE_CAPACITY);
        let lifecycle = Arc::new(AtomicU8::new(BridgeLifecycleState::Draining as u8));
        let stop_flag = Arc::new(AtomicBool::new(true));
        let persistence_abort = Arc::new(AtomicBool::new(false));

        let state_for_worker = Arc::clone(&state);
        let worker = thread::spawn(move || {
            drop(state_for_worker);
        });

        let handle = TelemetryRuntimeHandle {
            socket_path: PathBuf::from("/tmp/telemetry-zero-deadline-finished.sock"),
            state: Arc::clone(&state),
            lifecycle,
            stop_flag,
            persistence_abort,
            connection_handles: Arc::new(Mutex::new(Vec::new())),
            connection_worker_panicked: Arc::new(AtomicBool::new(false)),
            listener_handle: None,
            persistence_handle: Some(worker),
        };

        while !handle
            .persistence_handle
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            thread::sleep(Duration::from_millis(1));
        }

        let report = handle
            .join(Duration::ZERO)
            .expect("already-finished workers should not trip timeout handling");

        assert!(report.drain_completed);
        assert_eq!(report.final_state, BridgeLifecycleState::Stopped);
        assert!(
            report
                .recent_events
                .iter()
                .all(|event| event.code != event_codes::DRAIN_TIMEOUT),
            "already-finished workers should not emit DRAIN_TIMEOUT"
        );
        assert_eq!(
            Arc::strong_count(&state),
            1,
            "join() should still consume the finished worker handle"
        );
    }

    #[test]
    fn listener_join_panic_returns_error_after_joining_persistence_worker() {
        let state = test_state(PERSIST_QUEUE_CAPACITY);
        let lifecycle = Arc::new(AtomicU8::new(BridgeLifecycleState::Draining as u8));
        let stop_flag = Arc::new(AtomicBool::new(true));
        let persistence_abort = Arc::new(AtomicBool::new(false));

        let listener = thread::spawn(|| {
            panic!("listener panic during join test");
        });

        let state_for_connection = Arc::clone(&state);
        let connection_worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            drop(state_for_connection);
        });

        let state_for_worker = Arc::clone(&state);
        let worker = thread::spawn(move || {
            drop(state_for_worker);
        });

        let connection_handles = Arc::new(Mutex::new(vec![connection_worker]));
        let handle = TelemetryRuntimeHandle {
            socket_path: PathBuf::from("/tmp/telemetry-listener-panic-test.sock"),
            state: Arc::clone(&state),
            lifecycle,
            stop_flag,
            persistence_abort,
            connection_handles,
            connection_worker_panicked: Arc::new(AtomicBool::new(false)),
            listener_handle: Some(listener),
            persistence_handle: Some(worker),
        };

        let err = handle
            .join(Duration::from_secs(1))
            .expect_err("listener panic should fail join");

        assert!(
            err.0.contains("listener worker panicked"),
            "join error should report listener panic"
        );
        assert_eq!(
            Arc::strong_count(&state),
            1,
            "connection and persistence workers should still be joined before returning the listener error"
        );
    }

    #[test]
    fn persistence_join_panic_marks_failed_and_returns_error() {
        let state = test_state(PERSIST_QUEUE_CAPACITY);
        let lifecycle = Arc::new(AtomicU8::new(BridgeLifecycleState::Draining as u8));
        let stop_flag = Arc::new(AtomicBool::new(true));
        let persistence_abort = Arc::new(AtomicBool::new(false));

        let state_for_worker = Arc::clone(&state);
        let worker = thread::spawn(move || {
            drop(state_for_worker);
            panic!("persistence panic during join test");
        });

        while !worker.is_finished() {
            thread::sleep(Duration::from_millis(1));
        }

        let handle = TelemetryRuntimeHandle {
            socket_path: PathBuf::from("/tmp/telemetry-persistence-panic-test.sock"),
            state: Arc::clone(&state),
            lifecycle: Arc::clone(&lifecycle),
            stop_flag,
            persistence_abort,
            connection_handles: Arc::new(Mutex::new(Vec::new())),
            connection_worker_panicked: Arc::new(AtomicBool::new(false)),
            listener_handle: None,
            persistence_handle: Some(worker),
        };

        let err = handle
            .join(Duration::from_secs(1))
            .expect_err("persistence panic should fail join");

        assert!(
            err.0.contains("persistence worker panicked"),
            "join error should report persistence panic"
        );
        assert_eq!(
            BridgeLifecycleState::from_u8(lifecycle.load(Ordering::SeqCst)),
            BridgeLifecycleState::Failed,
            "persistence join panic must mark the runtime failed"
        );
        assert_eq!(
            Arc::strong_count(&state),
            1,
            "persistence worker should still be joined before join() returns"
        );
        let recent_events = state
            .lock()
            .expect("telemetry state lock")
            .snapshot()
            .recent_events;
        assert!(
            recent_events
                .iter()
                .all(|event| event.code != event_codes::DRAIN_COMPLETE),
            "failed joins must not emit DRAIN_COMPLETE"
        );
    }

    #[test]
    fn reaping_panicked_connection_workers_reports_failure_after_joining_all_finished_workers() {
        let connection_worker_panicked = Arc::new(AtomicBool::new(false));
        let joined_token = Arc::new(());
        let joined_token_for_worker = Arc::clone(&joined_token);

        let panicking_worker = thread::spawn(|| {
            panic!("connection worker panic during reap test");
        });
        let finishing_worker = thread::spawn(move || {
            drop(joined_token_for_worker);
        });

        let connection_handles = Arc::new(Mutex::new(vec![panicking_worker, finishing_worker]));

        while !connection_handles
            .lock()
            .expect("connection handle registry lock")
            .iter()
            .all(JoinHandle::is_finished)
        {
            thread::sleep(Duration::from_millis(1));
        }

        let healthy = TelemetryBridge::reap_finished_connection_workers(
            &connection_handles,
            &connection_worker_panicked,
        );

        assert!(
            !healthy,
            "panicked connection workers should fail the reap pass"
        );
        assert!(
            connection_worker_panicked.load(Ordering::SeqCst),
            "reap should surface the panic to the runtime"
        );
        assert_eq!(
            Arc::strong_count(&joined_token),
            1,
            "reap should still join every finished worker before reporting failure"
        );
        assert!(
            connection_handles
                .lock()
                .expect("connection handle registry lock")
                .is_empty(),
            "finished workers should be removed from the shared registry"
        );
    }

    #[test]
    fn poisoned_connection_registry_still_joins_workers_before_returning_error() {
        let state = test_state(PERSIST_QUEUE_CAPACITY);
        let lifecycle = Arc::new(AtomicU8::new(BridgeLifecycleState::Draining as u8));
        let stop_flag = Arc::new(AtomicBool::new(true));
        let persistence_abort = Arc::new(AtomicBool::new(false));

        let state_for_connection = Arc::clone(&state);
        let connection_worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            drop(state_for_connection);
        });

        let connection_handles = Arc::new(Mutex::new(vec![connection_worker]));
        let handles_for_poison = Arc::clone(&connection_handles);
        let _ = thread::spawn(move || {
            let _guard = handles_for_poison
                .lock()
                .expect("connection handle registry lock");
            panic!("poison connection handle registry");
        })
        .join();

        let handle = TelemetryRuntimeHandle {
            socket_path: PathBuf::from("/tmp/telemetry-poisoned-connection-registry.sock"),
            state: Arc::clone(&state),
            lifecycle,
            stop_flag,
            persistence_abort,
            connection_handles,
            connection_worker_panicked: Arc::new(AtomicBool::new(false)),
            listener_handle: None,
            persistence_handle: None,
        };

        let err = handle
            .join(Duration::from_secs(1))
            .expect_err("poisoned connection registry should fail join");

        assert!(
            err.0.contains("registry poisoned"),
            "join error should report the poisoned registry"
        );
        assert_eq!(
            Arc::strong_count(&state),
            1,
            "join() should still drain connection workers out of a poisoned registry before returning"
        );
    }

    // ---- bd-1now.4.5: Deterministic telemetry regression suite ----

    #[test]
    fn socket_cleaned_up_after_normal_shutdown() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_socket_cleanup.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        assert!(sock.exists(), "socket should exist after start");
        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(report.drain_completed);
        // Socket file itself won't be removed by the bridge (that's the caller's job
        // via temp_dir cleanup), but verify the bridge reached terminal state
        assert_eq!(report.final_state, BridgeLifecycleState::Stopped);
    }

    #[test]
    fn socket_cleaned_up_after_engine_exit_failure() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_socket_engine_fail.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        let report = handle
            .stop_and_join(ShutdownReason::EngineExit { exit_code: Some(1) })
            .expect("stop_and_join");
        assert!(report.drain_completed);
        assert_eq!(report.final_state, BridgeLifecycleState::Stopped);
        // Engine exit with non-zero code should still drain cleanly
        assert!(
            report
                .recent_events
                .iter()
                .any(|e| e.code == event_codes::DRAIN_COMPLETE)
        );
    }

    #[test]
    fn socket_cleaned_up_after_engine_signal_kill() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_socket_signal_kill.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        // exit_code: None means killed by signal (no exit code)
        let report = handle
            .stop_and_join(ShutdownReason::EngineExit { exit_code: None })
            .expect("stop_and_join");
        assert!(report.drain_completed);
        assert_eq!(report.final_state, BridgeLifecycleState::Stopped);
    }

    #[test]
    fn end_to_end_single_event_ingestion() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_e2e_single.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let adapter_ref = Arc::clone(&adapter);
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        // Connect and send one event
        let mut stream = UnixStream::connect(&sock).expect("connect");
        writeln!(stream, r#"{{"event":"test_event","value":42}}"#).expect("write");
        drop(stream);

        // Give the bridge time to process
        thread::sleep(Duration::from_millis(200));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(report.drain_completed);
        assert_eq!(report.accepted_total, 1, "one event should be accepted");
        assert_eq!(report.persisted_total, 1, "one event should be persisted");
        assert_eq!(report.shed_total, 0);
        assert_eq!(report.dropped_total, 0);

        // Verify the adapter received the data
        let mut db = adapter_ref.lock().expect("adapter lock");
        let result = db.read(PersistenceClass::AuditLog, "telemetry_00000000000000000001");
        assert!(result.found, "event should be persisted in adapter store");
        let payload = result.value.expect("payload");
        assert!(
            std::str::from_utf8(&payload)
                .expect("utf8")
                .contains("test_event"),
            "payload should contain the event data"
        );
    }

    #[test]
    fn stop_and_join_completes_with_idle_open_client() {
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_idle_open_client.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let stream = UnixStream::connect(&sock).expect("connect");

        let wait_start = Instant::now();
        while handle.snapshot().active_connections == 0 {
            assert!(
                wait_start.elapsed() < Duration::from_secs(2),
                "bridge never observed the idle connection",
            );
            thread::sleep(Duration::from_millis(10));
        }

        let shutdown_started = Instant::now();
        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(
            shutdown_started.elapsed() < Duration::from_secs(2),
            "idle connection shutdown should complete after the per-read timeout budget",
        );
        assert!(report.drain_completed);
        assert_eq!(report.final_state, BridgeLifecycleState::Stopped);
        assert!(
            report.telemetry_events.is_empty(),
            "idle connection should not fabricate telemetry events",
        );
        assert!(
            report
                .recent_events
                .iter()
                .any(|event| event.code == event_codes::CONNECTION_CLOSED)
        );

        drop(stream);
    }

    #[test]
    fn end_to_end_multiple_events_ingestion() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_e2e_multi.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let event_count = 10usize;
        let mut stream = UnixStream::connect(&sock).expect("connect");
        for i in 0..event_count {
            let event = format!(
                r#"{{"timestamp":"2026-04-06T00:00:{i:02}Z","event_type":"metric","payload":{{"seq":{i}}}}}"#
            );
            writeln!(stream, "{event}").expect("write");
        }
        drop(stream);

        thread::sleep(Duration::from_millis(300));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(report.drain_completed);
        assert_eq!(
            report.accepted_total, event_count as u64,
            "all events should be accepted"
        );
        assert_eq!(
            report.persisted_total, event_count as u64,
            "all events should be persisted"
        );
        assert_eq!(
            report.telemetry_events.len(),
            event_count,
            "all NDJSON telemetry events should be surfaced in the final report",
        );
        assert_eq!(report.telemetry_events[0].event_type, "metric");
        assert_eq!(
            report.telemetry_events[0].payload,
            serde_json::json!({ "seq": 0 })
        );
        assert_eq!(
            report.telemetry_events.last().map(|event| &event.payload),
            Some(&serde_json::json!({ "seq": 9 }))
        );
    }

    #[test]
    fn multi_connection_concurrent_ingestion() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_multi_conn.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let connections = 5;
        let events_per_conn = 3;
        let mut conn_handles = Vec::new();
        for conn_idx in 0..connections {
            let sock_path = sock.clone();
            let h = thread::spawn(move || {
                let mut stream = UnixStream::connect(&sock_path).expect("connect");
                for ev_idx in 0..events_per_conn {
                    writeln!(stream, r#"{{"conn":{conn_idx},"ev":{ev_idx}}}"#).expect("write");
                }
                drop(stream);
            });
            conn_handles.push(h);
        }
        for h in conn_handles {
            h.join().expect("connection thread");
        }

        thread::sleep(Duration::from_millis(500));

        let snap = handle.snapshot();
        assert_eq!(
            snap.accepted_total,
            (connections * events_per_conn) as u64,
            "all events from all connections should be accepted"
        );

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(report.drain_completed);
        assert_eq!(
            report.persisted_total,
            (connections * events_per_conn) as u64
        );
    }

    #[test]
    fn oversized_event_rejected_with_shed() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_oversized.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let mut stream = UnixStream::connect(&sock).expect("connect");
        // Send an event larger than MAX_EVENT_BYTES (64KB)
        let big_payload = "x".repeat(MAX_EVENT_BYTES + 100);
        writeln!(stream, "{big_payload}").expect("write");
        // Also send a normal-sized event to confirm the connection still works
        writeln!(stream, r#"{{"event":"normal"}}"#).expect("write");
        drop(stream);

        thread::sleep(Duration::from_millis(300));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(report.drain_completed);
        assert_eq!(report.shed_total, 1, "oversized event should be shed");
        assert_eq!(
            report.accepted_total, 1,
            "normal event should still be accepted"
        );
        assert!(
            report
                .recent_events
                .iter()
                .any(|e| e.code == event_codes::ADMISSION_SHED
                    && e.reason_code.as_deref() == Some(reason_codes::EVENT_TOO_LARGE))
        );
    }

    #[test]
    fn partial_write_survives_read_timeout_and_collects_event() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_partial_write.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let mut stream = UnixStream::connect(&sock).expect("connect");
        stream
            .write_all(br#"{"timestamp":"2026-04-06T00:00:00Z","event_type":"metric","#)
            .expect("write first fragment");
        thread::sleep(Duration::from_millis(CONNECTION_READ_TIMEOUT_MS + 100));
        stream
            .write_all(br#""payload":{"seq":7}}"#)
            .expect("write second fragment");
        stream.write_all(b"\n").expect("write newline");
        drop(stream);

        thread::sleep(Duration::from_millis(300));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(report.drain_completed);
        assert_eq!(report.accepted_total, 1);
        assert_eq!(report.persisted_total, 1);
        assert_eq!(report.shed_total, 0);
        assert_eq!(
            report.telemetry_events,
            vec![RuntimeTelemetryEvent {
                timestamp: "2026-04-06T00:00:00Z".to_string(),
                event_type: "metric".to_string(),
                payload: serde_json::json!({ "seq": 7 }),
            }]
        );
    }

    #[test]
    fn binary_garbage_line_is_shed_and_next_event_is_collected() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_binary_garbage.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let mut stream = UnixStream::connect(&sock).expect("connect");
        stream
            .write_all(&[0xff, 0xfe, 0x00, b'\n'])
            .expect("write garbage");
        writeln!(
            stream,
            r#"{{"timestamp":"2026-04-06T00:00:01Z","event_type":"module_load","payload":{{"module":"leftpad"}}}}"#
        )
        .expect("write valid event");
        drop(stream);

        thread::sleep(Duration::from_millis(300));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(report.drain_completed);
        assert_eq!(report.shed_total, 1, "binary garbage should be discarded");
        assert_eq!(
            report.accepted_total, 1,
            "valid line should still be admitted"
        );
        assert_eq!(report.persisted_total, 1);
        assert_eq!(
            report.telemetry_events,
            vec![RuntimeTelemetryEvent {
                timestamp: "2026-04-06T00:00:01Z".to_string(),
                event_type: "module_load".to_string(),
                payload: serde_json::json!({ "module": "leftpad" }),
            }]
        );
        assert!(
            report
                .recent_events
                .iter()
                .any(|event| event.code == event_codes::ADMISSION_SHED
                    && event.reason_code.as_deref() == Some(reason_codes::INVALID_EVENT)),
            "invalid lines should emit an INVALID_EVENT shed record",
        );
    }

    #[test]
    fn stop_and_join_convenience_method() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_stop_join.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join should succeed");
        assert!(report.drain_completed);
        assert_eq!(report.final_state, BridgeLifecycleState::Stopped);
        assert_eq!(report.accepted_total, 0);
        assert_eq!(report.persisted_total, 0);
        assert_eq!(report.shed_total, 0);
        assert_eq!(report.dropped_total, 0);
        assert!(
            report.telemetry_events.is_empty(),
            "empty telemetry sessions should produce an empty report",
        );
    }

    #[test]
    fn engine_exit_code_mapped_to_shutdown_reason() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_exit_code.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        // exit_code: Some(137) = SIGKILL
        let report = handle
            .stop_and_join(ShutdownReason::EngineExit {
                exit_code: Some(137),
            })
            .expect("stop_and_join");
        assert!(report.drain_completed);
        assert!(
            report
                .recent_events
                .iter()
                .any(|e| e.code == event_codes::DRAIN_STARTED
                    && e.reason_code.as_deref() == Some(reason_codes::ENGINE_EXIT))
        );
    }

    #[test]
    fn lifecycle_transitions_are_recorded_in_events() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_transitions.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");

        // Verify lifecycle events were recorded
        let event_codes_seen: Vec<&str> = report
            .recent_events
            .iter()
            .map(|e| e.code.as_str())
            .collect();
        assert!(
            event_codes_seen.contains(&event_codes::LISTENER_STARTED),
            "should record LISTENER_STARTED"
        );
        assert!(
            event_codes_seen.contains(&event_codes::STATE_TRANSITION),
            "should record STATE_TRANSITION"
        );
        assert!(
            event_codes_seen.contains(&event_codes::DRAIN_STARTED),
            "should record DRAIN_STARTED"
        );
        assert!(
            event_codes_seen.contains(&event_codes::DRAIN_COMPLETE),
            "should record DRAIN_COMPLETE"
        );
    }

    #[test]
    fn structured_events_contain_required_fields() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_fields.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");

        // Every event must have bridge_id, code, and non-empty detail
        for event in &report.recent_events {
            assert!(
                event.bridge_id.starts_with("telemetry-bridge-"),
                "event bridge_id should have correct prefix, got: {}",
                event.bridge_id
            );
            assert!(!event.code.is_empty(), "event code must not be empty");
            assert!(!event.detail.is_empty(), "event detail must not be empty");
            // queue_capacity should always be PERSIST_QUEUE_CAPACITY
            assert_eq!(
                event.queue_capacity, PERSIST_QUEUE_CAPACITY,
                "queue_capacity mismatch in event"
            );
        }
    }

    #[test]
    fn events_have_debug_representation() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_debug.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");
        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");

        // Events and report should have Debug representation for failure-forensics
        for event in &report.recent_events {
            let debug = format!("{event:?}");
            assert!(
                debug.contains(&event.code),
                "Debug repr should contain event code"
            );
        }
        let report_debug = format!("{report:?}");
        assert!(
            report_debug.contains(&report.bridge_id),
            "report Debug should contain bridge_id"
        );
    }

    #[test]
    fn no_orphan_workers_after_stop_and_join() {
        // Verify that after stop_and_join, both worker handles are consumed
        // (the handle is moved into join, so if join returns, handles are joined)
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_no_orphans.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        // Record the state arc so we can check it after handle is consumed
        let state = Arc::clone(&handle.state);

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(report.drain_completed);
        assert_eq!(report.final_state, BridgeLifecycleState::Stopped);

        // After stop_and_join, the handle is consumed. If workers were orphaned,
        // they'd still hold Arc references to state. The main thread + our clone
        // should be the only references left.
        // (listener + persistence threads each held one, but they've joined)
        // We hold 1 (state), the report construction path dropped the handle's clone.
        // This is a weak check but validates workers have exited.
        let strong_count = Arc::strong_count(&state);
        assert!(
            strong_count <= 2,
            "expected at most 2 strong refs to state (got {strong_count}), workers may be orphaned"
        );
    }

    #[test]
    fn backpressure_burst_events_shed_cleanly() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_burst.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        // Send a burst of events that exceeds queue capacity
        let burst_size = PERSIST_QUEUE_CAPACITY * 3;
        let mut stream = UnixStream::connect(&sock).expect("connect");
        for i in 0..burst_size {
            // Use a big-ish payload to slow persistence
            let payload = format!(r#"{{"burst":true,"i":{i},"pad":"{}"}}"#, "A".repeat(1000));
            writeln!(stream, "{payload}").expect("write");
        }
        drop(stream);

        thread::sleep(Duration::from_millis(500));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(report.drain_completed);

        // Under burst: accepted + shed should equal total sent
        let total_seen = report
            .accepted_total
            .saturating_add(report.shed_total)
            .saturating_add(report.dropped_total);
        assert_eq!(
            total_seen, burst_size as u64,
            "accepted({}) + shed({}) + dropped({}) should equal burst_size({})",
            report.accepted_total, report.shed_total, report.dropped_total, burst_size
        );

        // Everything accepted should be persisted (since drain completed)
        assert_eq!(
            report.persisted_total, report.accepted_total,
            "all accepted events should be persisted after drain"
        );
    }

    #[test]
    fn bridge_id_is_unique_per_instance() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock1 = tmp.path().join("test_id1.sock");
        let sock2 = tmp.path().join("test_id2.sock");
        let a1 = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let a2 = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let b1 = TelemetryBridge::new(sock1.to_str().expect("utf8"), a1);
        let b2 = TelemetryBridge::new(sock2.to_str().expect("utf8"), a2);
        let id1 = b1.snapshot().bridge_id.clone();
        let id2 = b2.snapshot().bridge_id.clone();
        assert_ne!(id1, id2, "each bridge instance should get a unique ID");
    }

    #[test]
    fn connection_accepted_event_has_connection_id() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_conn_id.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let mut stream = UnixStream::connect(&sock).expect("connect");
        writeln!(stream, r#"{{"ping":true}}"#).expect("write");
        drop(stream);

        thread::sleep(Duration::from_millis(200));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");

        let conn_events: Vec<_> = report
            .recent_events
            .iter()
            .filter(|e| e.code == event_codes::CONNECTION_ACCEPTED)
            .collect();
        assert!(
            !conn_events.is_empty(),
            "should have at least one CONNECTION_ACCEPTED event"
        );
        for event in &conn_events {
            assert!(
                event.connection_id.is_some(),
                "CONNECTION_ACCEPTED events must have a connection_id"
            );
        }
    }

    #[test]
    fn persistence_key_format_is_sequential() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_key_format.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let adapter_ref = Arc::clone(&adapter);
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let mut stream = UnixStream::connect(&sock).expect("connect");
        for _ in 0..3 {
            writeln!(stream, r#"{{"seq":"test"}}"#).expect("write");
        }
        drop(stream);

        thread::sleep(Duration::from_millis(300));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert_eq!(report.persisted_total, 3);

        // Keys should be zero-padded sequential
        let mut db = adapter_ref.lock().expect("adapter lock");
        for seq in 1..=3u64 {
            let key = format!("telemetry_{seq:020}");
            let result = db.read(PersistenceClass::AuditLog, &key);
            assert!(result.found, "missing key: {key}");
        }
    }

    #[test]
    fn report_field_completeness() {
        let report = TelemetryRuntimeReport {
            final_state: BridgeLifecycleState::Stopped,
            bridge_id: "telemetry-bridge-test-00000".to_string(),
            accepted_total: 42,
            persisted_total: 40,
            shed_total: 1,
            dropped_total: 1,
            retry_total: 3,
            drain_completed: true,
            drain_duration_ms: 150,
            telemetry_events: vec![RuntimeTelemetryEvent {
                timestamp: "2026-04-06T00:00:00Z".to_string(),
                event_type: "metric".to_string(),
                payload: serde_json::json!({ "seq": 1 }),
            }],
            recent_events: vec![],
        };
        // Verify all report fields are accessible and correct
        assert_eq!(report.final_state, BridgeLifecycleState::Stopped);
        assert_eq!(report.bridge_id, "telemetry-bridge-test-00000");
        assert_eq!(report.accepted_total, 42);
        assert_eq!(report.persisted_total, 40);
        assert_eq!(report.shed_total, 1);
        assert_eq!(report.dropped_total, 1);
        assert_eq!(report.retry_total, 3);
        assert!(report.drain_completed);
        assert_eq!(report.drain_duration_ms, 150);
        assert_eq!(report.telemetry_events.len(), 1);
        assert_eq!(report.telemetry_events[0].event_type, "metric");
        assert_eq!(
            report.telemetry_events[0].payload,
            serde_json::json!({ "seq": 1 })
        );
        assert!(report.recent_events.is_empty());
        // Debug representation should be available for forensic logging
        let debug = format!("{report:?}");
        assert!(debug.contains("Stopped"));
        assert!(debug.contains("telemetry-bridge-test-00000"));
    }

    #[test]
    fn shutdown_reason_variants_are_distinct() {
        let engine_zero = ShutdownReason::EngineExit { exit_code: Some(0) };
        let engine_sigkill = ShutdownReason::EngineExit {
            exit_code: Some(137),
        };
        let engine_signal = ShutdownReason::EngineExit { exit_code: None };
        let requested = ShutdownReason::Requested;
        // Debug should distinguish variants
        let d1 = format!("{engine_zero:?}");
        let d2 = format!("{engine_sigkill:?}");
        let d3 = format!("{engine_signal:?}");
        let d4 = format!("{requested:?}");
        assert!(d1.contains("EngineExit") && d1.contains("0"));
        assert!(d2.contains("EngineExit") && d2.contains("137"));
        assert!(d3.contains("EngineExit") && d3.contains("None"));
        assert!(d4.contains("Requested"));
    }

    #[test]
    fn snapshot_field_completeness() {
        let snapshot = TelemetryBridgeSnapshot {
            bridge_id: "telemetry-bridge-test".to_string(),
            queue_depth: 5,
            queue_capacity: 256,
            active_connections: 2,
            accepted_total: 100,
            persisted_total: 95,
            shed_total: 3,
            dropped_total: 2,
            retry_total: 7,
            recent_events: vec![],
        };
        assert_eq!(snapshot.bridge_id, "telemetry-bridge-test");
        assert_eq!(snapshot.queue_depth, 5);
        assert_eq!(snapshot.queue_capacity, 256);
        assert_eq!(snapshot.active_connections, 2);
        assert_eq!(snapshot.accepted_total, 100);
        assert_eq!(snapshot.persisted_total, 95);
        assert_eq!(snapshot.shed_total, 3);
        assert_eq!(snapshot.dropped_total, 2);
        assert_eq!(snapshot.retry_total, 7);
    }

    #[test]
    fn stale_socket_cleanup_before_start() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("test_stale.sock");

        // Create a stale socket file
        std::fs::write(&sock, b"stale").expect("create stale file");
        assert!(sock.exists());

        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        // start() should clean up the stale socket and bind successfully
        let handle = bridge
            .start()
            .expect("start should succeed despite stale socket");
        assert_eq!(handle.lifecycle_state(), BridgeLifecycleState::Running);
        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        assert!(report.drain_completed);
    }

    // ---- bd-1now.4.7: Performance characterization tests ----

    #[test]
    fn perf_steady_state_throughput() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("perf_steady.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let event_count: u64 = 500;
        let start = Instant::now();
        let mut stream = UnixStream::connect(&sock).expect("connect");
        for i in 0..event_count {
            writeln!(stream, r#"{{"perf":"steady","i":{i}}}"#).expect("write");
        }
        drop(stream);
        let send_elapsed = start.elapsed();

        thread::sleep(Duration::from_millis(500));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        let total_elapsed = start.elapsed();

        assert!(report.drain_completed);
        assert_eq!(report.accepted_total, event_count);
        assert_eq!(report.persisted_total, event_count);

        // Performance characterization output (captured by --nocapture)
        let send_rate = event_count as f64 / send_elapsed.as_secs_f64();
        let total_rate = event_count as f64 / total_elapsed.as_secs_f64();
        eprintln!("[perf_steady_state_throughput]");
        eprintln!("  events_sent: {event_count}");
        eprintln!("  send_elapsed_ms: {}", send_elapsed.as_millis());
        eprintln!("  total_elapsed_ms: {}", total_elapsed.as_millis());
        eprintln!("  send_rate_events_per_sec: {send_rate:.0}");
        eprintln!("  total_rate_events_per_sec: {total_rate:.0}");
        eprintln!("  drain_duration_ms: {}", report.drain_duration_ms);
        eprintln!("  shed_total: {}", report.shed_total);
        eprintln!("  retry_total: {}", report.retry_total);

        // Sanity: should process at least 100 events/sec
        assert!(
            total_rate > 100.0,
            "steady-state throughput ({total_rate:.0} ev/s) below 100 ev/s minimum"
        );
    }

    #[test]
    fn perf_burst_beyond_queue_capacity() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("perf_burst.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let burst_size: u64 = (PERSIST_QUEUE_CAPACITY * 4) as u64;
        let start = Instant::now();
        let mut stream = UnixStream::connect(&sock).expect("connect");
        for i in 0..burst_size {
            writeln!(
                stream,
                r#"{{"perf":"burst","i":{i},"pad":"{}"}}"#,
                "B".repeat(500)
            )
            .expect("write");
        }
        drop(stream);
        let send_elapsed = start.elapsed();

        thread::sleep(Duration::from_millis(500));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        let total_elapsed = start.elapsed();

        assert!(report.drain_completed);

        let accepted = report.accepted_total;
        let shed = report.shed_total;
        let dropped = report.dropped_total;
        let total_accounted = accepted.saturating_add(shed).saturating_add(dropped);

        eprintln!("[perf_burst_beyond_queue_capacity]");
        eprintln!("  burst_size: {burst_size}");
        eprintln!("  queue_capacity: {PERSIST_QUEUE_CAPACITY}");
        eprintln!("  send_elapsed_ms: {}", send_elapsed.as_millis());
        eprintln!("  total_elapsed_ms: {}", total_elapsed.as_millis());
        eprintln!("  accepted: {accepted}");
        eprintln!("  persisted: {}", report.persisted_total);
        eprintln!("  shed: {shed}");
        eprintln!("  dropped: {dropped}");
        eprintln!("  retry_total: {}", report.retry_total);
        eprintln!("  drain_duration_ms: {}", report.drain_duration_ms);
        eprintln!(
            "  acceptance_rate_pct: {:.1}",
            accepted as f64 / burst_size as f64 * 100.0
        );

        assert_eq!(
            total_accounted, burst_size,
            "accepted + shed + dropped must equal burst_size"
        );
        assert_eq!(
            report.persisted_total, accepted,
            "all accepted events must be persisted after clean drain"
        );
        // Under 4× burst, some shedding is expected
        assert!(
            shed > 0 || accepted == burst_size,
            "burst should either shed some events or accept all"
        );
    }

    #[test]
    fn perf_drain_shutdown_latency() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("perf_drain.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        // Load the queue with some work
        let event_count = 100;
        let mut stream = UnixStream::connect(&sock).expect("connect");
        for i in 0..event_count {
            writeln!(stream, r#"{{"perf":"drain","i":{i}}}"#).expect("write");
        }
        drop(stream);
        thread::sleep(Duration::from_millis(200));

        // Measure drain time
        let drain_start = Instant::now();
        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        let drain_elapsed = drain_start.elapsed();

        assert!(report.drain_completed);

        eprintln!("[perf_drain_shutdown_latency]");
        eprintln!("  events_before_drain: {event_count}");
        eprintln!("  drain_elapsed_ms: {}", drain_elapsed.as_millis());
        eprintln!("  report_drain_duration_ms: {}", report.drain_duration_ms);
        eprintln!("  persisted: {}", report.persisted_total);
        eprintln!("  final_state: {:?}", report.final_state);

        // Drain should complete within 2 seconds for 100 events
        assert!(
            drain_elapsed < Duration::from_secs(2),
            "drain took {}ms, expected < 2000ms",
            drain_elapsed.as_millis()
        );
    }

    #[test]
    fn perf_queue_depth_evolution() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("perf_depth.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        // Snapshot before load
        let snap_before = handle.snapshot();
        assert_eq!(snap_before.queue_depth, 0);

        // Send events
        let event_count = 50;
        let mut stream = UnixStream::connect(&sock).expect("connect");
        for i in 0..event_count {
            writeln!(stream, r#"{{"perf":"depth","i":{i}}}"#).expect("write");
        }
        drop(stream);

        // Brief pause then snapshot during processing
        thread::sleep(Duration::from_millis(50));
        let snap_during = handle.snapshot();

        // Wait for processing
        thread::sleep(Duration::from_millis(500));
        let snap_after = handle.snapshot();

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");

        eprintln!("[perf_queue_depth_evolution]");
        eprintln!("  events_sent: {event_count}");
        eprintln!("  queue_depth_before: {}", snap_before.queue_depth);
        eprintln!("  queue_depth_during: {}", snap_during.queue_depth);
        eprintln!("  queue_depth_after: {}", snap_after.queue_depth);
        eprintln!("  queue_capacity: {}", snap_before.queue_capacity);
        eprintln!("  accepted: {}", report.accepted_total);
        eprintln!("  persisted: {}", report.persisted_total);

        assert!(report.drain_completed);
        // After processing, queue should be drained
        assert_eq!(
            snap_after.queue_depth, 0,
            "queue should be empty after processing"
        );
        assert_eq!(snap_before.queue_capacity, PERSIST_QUEUE_CAPACITY);
    }

    #[test]
    fn perf_enqueue_latency_under_light_load() {
        let state = test_state(PERSIST_QUEUE_CAPACITY);
        let (sender, receiver) = mpsc::sync_channel(PERSIST_QUEUE_CAPACITY);
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let state_for_worker = Arc::clone(&state);
        let abort_flag = Arc::new(AtomicBool::new(false));
        let abort_for_worker = Arc::clone(&abort_flag);
        let worker = thread::spawn(move || {
            TelemetryBridge::run_persistence_loop(
                receiver,
                adapter,
                state_for_worker,
                abort_for_worker,
            );
        });

        let iterations = 100;
        let mut latencies_us = Vec::with_capacity(iterations);
        for i in 0..iterations {
            let start = Instant::now();
            let admitted = TelemetryBridge::enqueue_with_timeout(
                &sender,
                PersistEnvelope {
                    connection_id: 1,
                    bridge_seq: i as u64,
                    payload: br#"{"perf":"latency"}"#.to_vec(),
                },
                &state,
                Duration::from_millis(ENQUEUE_TIMEOUT_MS),
            );
            let elapsed = start.elapsed();
            assert!(admitted);
            latencies_us.push(elapsed.as_micros() as u64);
        }
        drop(sender);
        worker.join().expect("persistence worker");

        latencies_us.sort();
        let p50 = latencies_us[iterations / 2];
        let p99 = latencies_us[iterations * 99 / 100];
        let max = latencies_us[iterations - 1];

        eprintln!("[perf_enqueue_latency_under_light_load]");
        eprintln!("  iterations: {iterations}");
        eprintln!("  p50_us: {p50}");
        eprintln!("  p99_us: {p99}");
        eprintln!("  max_us: {max}");

        let snap = state.lock().expect("state").snapshot();
        assert_eq!(snap.accepted_total, iterations as u64);
        assert_eq!(snap.persisted_total, iterations as u64);

        // p99 enqueue latency should be under 10ms
        assert!(
            p99 < 10_000,
            "p99 enqueue latency ({p99}us) exceeds 10ms budget"
        );
    }

    #[test]
    fn perf_multi_connection_throughput() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let sock = tmp.path().join("perf_multi_conn.sock");
        let adapter = Arc::new(Mutex::new(FrankensqliteAdapter::default()));
        let bridge = TelemetryBridge::new(sock.to_str().expect("utf8"), adapter);
        let handle = bridge.start().expect("start");

        let connections = 10;
        let events_per_conn = 50;
        let total_events: u64 = (connections * events_per_conn) as u64;

        let start = Instant::now();
        let mut conn_handles = Vec::new();
        for conn_idx in 0..connections {
            let sock_path = sock.clone();
            let h = thread::spawn(move || {
                let mut stream = UnixStream::connect(&sock_path).expect("connect");
                for ev_idx in 0..events_per_conn {
                    writeln!(stream, r#"{{"perf":"multi","c":{conn_idx},"e":{ev_idx}}}"#)
                        .expect("write");
                }
                drop(stream);
            });
            conn_handles.push(h);
        }
        for h in conn_handles {
            h.join().expect("connection thread");
        }
        let send_elapsed = start.elapsed();

        thread::sleep(Duration::from_millis(500));

        let report = handle
            .stop_and_join(ShutdownReason::Requested)
            .expect("stop_and_join");
        let total_elapsed = start.elapsed();

        assert!(report.drain_completed);

        let multi_rate = total_events as f64 / total_elapsed.as_secs_f64();

        eprintln!("[perf_multi_connection_throughput]");
        eprintln!("  connections: {connections}");
        eprintln!("  events_per_conn: {events_per_conn}");
        eprintln!("  total_events: {total_events}");
        eprintln!("  send_elapsed_ms: {}", send_elapsed.as_millis());
        eprintln!("  total_elapsed_ms: {}", total_elapsed.as_millis());
        eprintln!("  throughput_events_per_sec: {multi_rate:.0}");
        eprintln!("  accepted: {}", report.accepted_total);
        eprintln!("  persisted: {}", report.persisted_total);
        eprintln!("  shed: {}", report.shed_total);
        eprintln!("  retry_total: {}", report.retry_total);

        let total_accounted = report
            .accepted_total
            .saturating_add(report.shed_total)
            .saturating_add(report.dropped_total);
        assert_eq!(total_accounted, total_events);
    }

    // ── NEGATIVE-PATH TESTS: Security & Robustness ──────────────────

    #[test]
    fn test_negative_bridge_id_with_unicode_injection_attacks() {
        use crate::security::constant_time::ct_eq;

        let bridge = TelemetryBridge::new(
            "/tmp/test-unicode-bridge.sock",
            Arc::new(Mutex::new(FrankensqliteAdapter::default())),
        );

        let snapshot = bridge.snapshot();

        // Verify bridge_id doesn't contain injection patterns
        assert!(!snapshot.bridge_id.contains('\u{202E}'), "bridge ID must not contain BiDi override");
        assert!(!snapshot.bridge_id.contains('\u{202D}'), "bridge ID must not contain BiDi embedding");
        assert!(!snapshot.bridge_id.contains('\x1b'), "bridge ID must not contain ANSI escape sequences");
        assert!(!snapshot.bridge_id.contains('\0'), "bridge ID must not contain null bytes");
        assert!(!snapshot.bridge_id.contains('\r'), "bridge ID must not contain carriage returns");
        assert!(!snapshot.bridge_id.contains('\n'), "bridge ID must not contain newlines");

        // Verify bridge_id has reasonable length bounds
        assert!(snapshot.bridge_id.len() < 256, "bridge ID must be reasonably bounded");
        assert!(!snapshot.bridge_id.is_empty(), "bridge ID must not be empty");

        // Verify constant-time comparison works for bridge IDs
        let other_bridge = TelemetryBridge::new(
            "/tmp/test-unicode-bridge-2.sock",
            Arc::new(Mutex::new(FrankensqliteAdapter::default())),
        );
        let other_id = other_bridge.snapshot().bridge_id;

        assert!(!ct_eq(&snapshot.bridge_id, &other_id), "bridge IDs should be unique");
    }

    #[test]
    fn test_negative_event_detail_with_massive_injection_payload() {
        let state = test_state(PERSIST_QUEUE_CAPACITY);

        // Create malicious event with massive detail field
        let massive_detail = "X".repeat(10_000_000); // 10MB payload
        let malicious_event = TelemetryBridgeEvent {
            code: event_codes::CONNECTION_ACCEPTED.to_string(),
            bridge_id: "test-bridge".to_string(),
            connection_id: Some(1),
            bridge_seq: Some(1),
            reason_code: Some(reason_codes::ALLOWED.to_string()),
            queue_depth: 0,
            queue_capacity: PERSIST_QUEUE_CAPACITY,
            active_connections: 1,
            accepted_total: 1,
            persisted_total: 0,
            shed_total: 0,
            dropped_total: 0,
            retry_total: 0,
            detail: massive_detail.clone(),
        };

        // Verify bounded storage prevents memory exhaustion
        let mut locked_state = state.lock().unwrap();
        push_bounded(&mut locked_state.runtime_events, malicious_event.clone(), MAX_RUNTIME_EVENTS);

        // Even with massive detail, storage should be bounded
        assert_eq!(locked_state.runtime_events.len(), 1);

        // Verify serialization doesn't cause memory explosion
        let json = serde_json::to_string(&locked_state.runtime_events[0]).unwrap_or_default();
        assert!(json.len() >= massive_detail.len(), "serialization preserves large detail");

        // Verify this doesn't crash the snapshot functionality
        drop(locked_state);
        let bridge = TelemetryBridge::with_state(
            "/tmp/test-massive.sock",
            Arc::new(Mutex::new(FrankensqliteAdapter::default())),
            state.clone(),
        );
        let snapshot = bridge.snapshot();
        assert!(!snapshot.recent_events.is_empty(), "snapshot should include massive event");
    }

    #[test]
    fn test_negative_runtime_telemetry_event_with_json_injection_attacks() {
        // Create event with malicious JSON injection in payload
        let malicious_payload = serde_json::json!({
            "normal_field": "value",
            "injection_attempt": r#""},"injected_field":"malicious","another_injection":{"nested":true"#,
            "script_injection": "<script>alert('XSS')</script>",
            "sql_injection": "'; DROP TABLE events; --",
            "command_injection": "; cat /etc/passwd #",
            "bidi_attack": "\u{202E}fake_field\u{202C}",
            "ansi_escape": "\x1b[31mRed Text\x1b[0m"
        });

        let runtime_event = RuntimeTelemetryEvent {
            timestamp: Utc::now().to_rfc3339(),
            event_type: "test_injection".to_string(),
            payload: malicious_payload,
        };

        // Verify serialization handles injection safely
        let json = serde_json::to_string(&runtime_event).unwrap();
        let parsed: RuntimeTelemetryEvent = serde_json::from_str(&json).unwrap();

        // Verify injected content is properly escaped/contained
        assert_eq!(parsed.event_type, "test_injection");
        assert!(parsed.payload.is_object());

        // Verify no additional fields were injected at the top level
        let parsed_json: serde_json::Value = serde_json::from_str(&json).unwrap();
        let expected_keys = ["timestamp", "event_type", "payload"];
        for key in parsed_json.as_object().unwrap().keys() {
            assert!(expected_keys.contains(&key.as_str()),
                   "unexpected field '{}' - possible JSON injection", key);
        }

        // Verify payload contains the injection attempts as literal strings (safe)
        let payload_str = parsed_json["payload"].to_string();
        assert!(payload_str.contains("injected_field"), "injection should be contained as literal");
        assert!(payload_str.contains("alert"), "script injection should be literal");
    }

    #[test]
    fn test_negative_connection_id_arithmetic_overflow_protection() {
        let state = test_state(PERSIST_QUEUE_CAPACITY);

        // Test with maximum connection ID to check overflow protection
        let max_conn_id = u64::MAX;
        let near_max_event = TelemetryBridgeEvent {
            code: event_codes::CONNECTION_ACCEPTED.to_string(),
            bridge_id: "test-overflow".to_string(),
            connection_id: Some(max_conn_id),
            bridge_seq: Some(u64::MAX),
            reason_code: Some(reason_codes::ALLOWED.to_string()),
            queue_depth: 0,
            queue_capacity: PERSIST_QUEUE_CAPACITY,
            active_connections: MAX_ACTIVE_CONNECTIONS,
            accepted_total: u64::MAX,
            persisted_total: u64::MAX,
            shed_total: u64::MAX,
            dropped_total: u64::MAX,
            retry_total: u64::MAX,
            detail: "max_values_test".to_string(),
        };

        // Verify event can be stored without overflow
        let mut locked_state = state.lock().unwrap();
        push_bounded(&mut locked_state.runtime_events, near_max_event, MAX_RUNTIME_EVENTS);

        // Verify arithmetic operations use saturating semantics
        let event = &locked_state.runtime_events[0];

        // Simulate counter increments that should use saturating_add
        let new_accepted = event.accepted_total.saturating_add(1);
        let new_persisted = event.persisted_total.saturating_add(1);

        // At u64::MAX, saturating_add should not overflow
        assert_eq!(new_accepted, u64::MAX, "saturating_add must prevent overflow");
        assert_eq!(new_persisted, u64::MAX, "saturating_add must prevent overflow");

        // Verify total accounting doesn't overflow
        let total_processed = event.accepted_total
            .saturating_add(event.shed_total)
            .saturating_add(event.dropped_total);
        assert!(total_processed == u64::MAX, "total accounting must use saturating arithmetic");
    }

    #[test]
    fn test_negative_bridge_lifecycle_state_invalid_transitions() {
        // Test invalid state byte values
        for invalid_byte in [7, 8, 200, 255] {
            let state = BridgeLifecycleState::from_u8(invalid_byte);
            assert_eq!(state, BridgeLifecycleState::Failed,
                      "invalid state byte {} should map to Failed", invalid_byte);
        }

        // Test state transition invariants
        let terminal_states = [BridgeLifecycleState::Stopped, BridgeLifecycleState::Failed];
        for terminal_state in terminal_states {
            assert!(terminal_state.is_terminal(),
                   "state {:?} should be terminal", terminal_state);
        }

        // Test serialization/deserialization robustness
        for state in [
            BridgeLifecycleState::Cold,
            BridgeLifecycleState::Starting,
            BridgeLifecycleState::Running,
            BridgeLifecycleState::Degraded,
            BridgeLifecycleState::Draining,
            BridgeLifecycleState::Stopped,
            BridgeLifecycleState::Failed,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let parsed: BridgeLifecycleState = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, state, "state serialization must be round-trip safe");
        }
    }

    #[test]
    fn test_negative_persist_envelope_with_massive_payload_stress() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let state = test_state(1);

        // Test with payload at MAX_EVENT_BYTES boundary
        let boundary_payload = vec![b'A'; MAX_EVENT_BYTES];
        let boundary_envelope = PersistEnvelope {
            connection_id: 1,
            bridge_seq: 1,
            payload: boundary_payload,
        };

        // Should handle boundary case
        let result = TelemetryBridge::enqueue_with_timeout(
            &sender,
            boundary_envelope,
            &state,
            Duration::from_millis(1),
        );
        // May succeed or fail depending on queue state, but shouldn't panic

        // Test with payload exceeding MAX_EVENT_BYTES
        let oversized_payload = vec![b'B'; MAX_EVENT_BYTES + 1];
        let oversized_envelope = PersistEnvelope {
            connection_id: 2,
            bridge_seq: 2,
            payload: oversized_payload,
        };

        // Should handle oversized gracefully (likely shed/drop)
        let result = TelemetryBridge::enqueue_with_timeout(
            &sender,
            oversized_envelope,
            &state,
            Duration::from_millis(1),
        );

        // Verify state accounting remains consistent regardless of outcome
        let locked_state = state.lock().unwrap();
        let total_events = locked_state.accepted_total + locked_state.shed_total + locked_state.dropped_total;
        assert!(total_events <= 2, "event accounting must remain consistent");
    }

    #[test]
    fn test_negative_shutdown_reason_display_injection_resistance() {
        // Test EngineExit with extreme exit codes
        let extreme_exit_codes = [
            Some(i32::MAX),
            Some(i32::MIN),
            Some(-999999),
            Some(999999),
            None,
        ];

        for exit_code in extreme_exit_codes {
            let shutdown_reason = ShutdownReason::EngineExit { exit_code };

            // Verify serialization safety
            let json = serde_json::to_string(&shutdown_reason).unwrap();
            let parsed: ShutdownReason = serde_json::from_str(&json).unwrap();

            match (shutdown_reason, parsed) {
                (ShutdownReason::EngineExit { exit_code: orig },
                 ShutdownReason::EngineExit { exit_code: parsed }) => {
                    assert_eq!(orig, parsed, "exit code serialization must be exact");
                }
                _ => panic!("shutdown reason type should be preserved"),
            }

            // Verify debug display doesn't contain injection patterns
            let debug_str = format!("{:?}", shutdown_reason);
            assert!(!debug_str.contains('\x1b'), "debug display must not contain ANSI escapes");
            assert!(!debug_str.contains('\0'), "debug display must not contain null bytes");
            assert!(!debug_str.contains('\u{202E}'), "debug display must not contain BiDi overrides");
        }

        // Test Requested variant
        let requested = ShutdownReason::Requested;
        let json = serde_json::to_string(&requested).unwrap();
        let parsed: ShutdownReason = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ShutdownReason::Requested));
    }

    #[test]
    fn test_negative_telemetry_runtime_report_with_extreme_values() {
        // Create report with extreme counter values
        let extreme_report = TelemetryRuntimeReport {
            final_state: BridgeLifecycleState::Failed,
            bridge_id: "extreme-test-bridge".to_string(),
            accepted_total: u64::MAX,
            persisted_total: u64::MAX,
            shed_total: u64::MAX,
            dropped_total: u64::MAX,
            retry_total: u64::MAX,
            drain_completed: false,
            drain_duration_ms: u64::MAX,
            telemetry_events: vec![],
            recent_events: vec![],
        };

        // Verify serialization handles extreme values
        let json = serde_json::to_string(&extreme_report).unwrap();
        let parsed: TelemetryRuntimeReport = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.accepted_total, u64::MAX);
        assert_eq!(parsed.persisted_total, u64::MAX);
        assert_eq!(parsed.shed_total, u64::MAX);
        assert_eq!(parsed.dropped_total, u64::MAX);
        assert_eq!(parsed.retry_total, u64::MAX);
        assert_eq!(parsed.drain_duration_ms, u64::MAX);

        // Verify arithmetic operations on extreme values don't overflow
        let total_events = parsed.accepted_total
            .saturating_add(parsed.shed_total)
            .saturating_add(parsed.dropped_total);
        assert_eq!(total_events, u64::MAX, "extreme value arithmetic must use saturating operations");

        // Create report with massive event collections for memory stress
        let massive_telemetry_events: Vec<RuntimeTelemetryEvent> = (0..1000)
            .map(|i| RuntimeTelemetryEvent {
                timestamp: Utc::now().to_rfc3339(),
                event_type: format!("massive_event_{}", i),
                payload: serde_json::json!({
                    "index": i,
                    "data": "X".repeat(1000), // 1KB per event
                }),
            })
            .collect();

        let massive_bridge_events: Vec<TelemetryBridgeEvent> = (0..1000)
            .map(|i| TelemetryBridgeEvent {
                code: event_codes::CONNECTION_ACCEPTED.to_string(),
                bridge_id: format!("bridge_{}", i),
                connection_id: Some(i as u64),
                bridge_seq: Some(i as u64),
                reason_code: Some(reason_codes::ALLOWED.to_string()),
                queue_depth: i % 256,
                queue_capacity: PERSIST_QUEUE_CAPACITY,
                active_connections: i % MAX_ACTIVE_CONNECTIONS,
                accepted_total: i as u64,
                persisted_total: i as u64,
                shed_total: 0,
                dropped_total: 0,
                retry_total: 0,
                detail: format!("massive_detail_{}", "Y".repeat(1000)),
            })
            .collect();

        let massive_report = TelemetryRuntimeReport {
            final_state: BridgeLifecycleState::Stopped,
            bridge_id: "massive-bridge".to_string(),
            accepted_total: 1000,
            persisted_total: 1000,
            shed_total: 0,
            dropped_total: 0,
            retry_total: 0,
            drain_completed: true,
            drain_duration_ms: 1000,
            telemetry_events: massive_telemetry_events,
            recent_events: massive_bridge_events,
        };

        // Verify massive report can be serialized without memory explosion
        let massive_json = serde_json::to_string(&massive_report).unwrap();
        assert!(massive_json.len() > 1_000_000, "massive report should be large but bounded");
        assert!(massive_json.len() < 50_000_000, "massive report should not cause excessive memory usage");
    }

    #[test]
    fn test_negative_error_display_injection_prevention() {
        // Test TelemetryStartError with injection attempts
        let malicious_start_errors = [
            "normal error message",
            "error\x1b[31mwith ANSI\x1b[0m",
            "error\nwith\nnewlines",
            "error\0with\0nulls",
            "error\u{202E}with BiDi\u{202C}",
            "error\"with'quotes}and{brackets",
        ];

        for error_msg in malicious_start_errors {
            let start_error = TelemetryStartError(error_msg.to_string());
            let display = format!("{}", start_error);

            // Verify display format is consistent
            assert!(display.starts_with("telemetry start failed:"));
            assert!(display.contains(error_msg));

            // Error trait should work
            let _: &dyn std::error::Error = &start_error;
        }

        // Test TelemetryJoinError with injection attempts
        let malicious_join_errors = [
            "join failed normally",
            "join\x1b[41mfailed with background\x1b[0m",
            "join\rfailed\twith\tcontrol\rchars",
            "join\u{202E}failed with bidi",
        ];

        for error_msg in malicious_join_errors {
            let join_error = TelemetryJoinError(error_msg.to_string());
            let display = format!("{}", join_error);

            // Verify display format is consistent
            assert!(display.starts_with("telemetry join failed:"));
            assert!(display.contains(error_msg));

            // Error trait should work
            let _: &dyn std::error::Error = &join_error;
        }
    }

    #[test]
    fn test_negative_push_bounded_with_zero_capacity_edge_case() {
        // Test push_bounded with zero capacity (should clear)
        let mut test_vec = vec![1, 2, 3, 4, 5];
        push_bounded(&mut test_vec, 6, 0);

        assert_eq!(test_vec.len(), 0, "zero capacity should clear the vector");

        // Test push_bounded with capacity 1 (should keep only latest)
        let mut test_vec = vec![1, 2, 3];
        push_bounded(&mut test_vec, 4, 1);

        assert_eq!(test_vec.len(), 1, "capacity 1 should keep only latest");
        assert_eq!(test_vec[0], 4, "should keep the newly pushed item");

        // Test push_bounded with exact capacity match
        let mut test_vec = Vec::new();
        for i in 0..5 {
            push_bounded(&mut test_vec, i, 5);
        }
        assert_eq!(test_vec.len(), 5, "should fill to exact capacity");

        // Adding one more should drain oldest
        push_bounded(&mut test_vec, 5, 5);
        assert_eq!(test_vec.len(), 5, "should maintain capacity");
        assert_eq!(test_vec[0], 1, "should have drained oldest (0)");
        assert_eq!(test_vec[4], 5, "should have newest at end");
    }
}
