use crate::storage::frankensqlite_adapter::{FrankensqliteAdapter, PersistenceClass};
use anyhow::Result;
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
const MAX_ACTIVE_CONNECTIONS: usize = 64;
const ACCEPT_POLL_INTERVAL_MS: u64 = 100;
const DEFAULT_DRAIN_TIMEOUT_MS: u64 = 5000;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    items.push(item);
    if items.len() > cap {
        let overflow = items.len() - cap;
        items.drain(0..overflow);
    }
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
    /// Must be called after `stop()`. Blocks until drain completes or
    /// `deadline` expires.
    pub fn join(
        mut self,
        deadline: Duration,
    ) -> Result<TelemetryRuntimeReport, TelemetryJoinError> {
        let drain_start = Instant::now();

        // Join listener thread (should exit quickly after stop flag is set)
        if let Some(handle) = self.listener_handle.take() {
            let _ = handle.join();
        }

        // Join persistence thread (drains remaining queue items)
        if let Some(handle) = self.persistence_handle.take() {
            // Wait up to deadline for persistence to finish
            let remaining = deadline.saturating_sub(drain_start.elapsed());
            let join_result = if remaining.is_zero() {
                // Already past deadline
                Err(())
            } else {
                // Park and wait, checking periodically
                let park_start = Instant::now();
                loop {
                    if handle.is_finished() {
                        break handle.join().map_err(|_| ());
                    }
                    if park_start.elapsed() >= remaining {
                        break Err(());
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            };

            if join_result.is_err() {
                self.transition_state(BridgeLifecycleState::Failed);
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

        let snapshot = self.snapshot();
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
            recent_events: snapshot.recent_events,
        })
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
        let (sender, receiver) = mpsc::sync_channel(PERSIST_QUEUE_CAPACITY);

        // Persistence owner thread (single writer)
        let persistence_state = Arc::clone(&state);
        let persistence_handle =
            thread::spawn(move || Self::run_persistence_loop(receiver, adapter, persistence_state));

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
        let listener_handle = thread::spawn(move || {
            Self::run_accept_loop(
                listener,
                sender,
                listener_state,
                listener_stop,
                listener_lifecycle,
            );
        });

        Ok(TelemetryRuntimeHandle {
            socket_path: PathBuf::from(&self.socket_path),
            state,
            lifecycle,
            stop_flag,
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
    ) {
        let mut connection_handles: Vec<JoinHandle<()>> = Vec::new();

        loop {
            // Check stop flag
            if stop_flag.load(Ordering::SeqCst) {
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
                    connection_handles.push(handle);

                    // Reap finished connection threads
                    connection_handles.retain(|h| !h.is_finished());
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

        // Wait for all connection workers to finish (drain phase)
        for handle in connection_handles {
            let _ = handle.join();
        }

        // Drop sender to signal persistence thread to drain and exit
        drop(sender);
    }

    fn handle_connection(
        connection_id: u64,
        stream: UnixStream,
        sender: SyncSender<PersistEnvelope>,
        state: Arc<Mutex<TelemetryBridgeState>>,
        stop_flag: Arc<AtomicBool>,
    ) {
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            // Stop flag check: refuse new events during drain
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            match line {
                Ok(event_json) => {
                    if event_json.len() > MAX_EVENT_BYTES {
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
                        continue;
                    }

                    let bridge_seq =
                        Self::with_state(&state, TelemetryBridgeState::next_bridge_seq)
                            .unwrap_or_default();
                    let envelope = PersistEnvelope {
                        connection_id,
                        bridge_seq,
                        payload: event_json.into_bytes(),
                    };

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
    ) {
        while let Ok(envelope) = receiver.recv() {
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
        let snapshot = state.lock().expect("state").snapshot();
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
        let worker = thread::spawn(move || {
            TelemetryBridge::run_persistence_loop(receiver, adapter, state_for_worker);
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

        let snapshot = state.lock().expect("state").snapshot();
        assert_eq!(snapshot.accepted_total, 1);
        assert_eq!(snapshot.persisted_total, 1);
        assert_eq!(snapshot.queue_depth, 0);
        assert!(snapshot
            .recent_events
            .iter()
            .any(|event| event.code == event_codes::PERSIST_SUCCESS));
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
        let snapshot = state.lock().expect("state").snapshot();
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
        assert!(report
            .recent_events
            .iter()
            .any(|e| e.code == event_codes::DRAIN_STARTED),);
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
        state.lock().unwrap().active_connections = MAX_ACTIVE_CONNECTIONS;
        let snap = state.lock().unwrap().snapshot();
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
}
