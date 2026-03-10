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

pub mod event_codes {
    pub const LISTENER_STARTED: &str = "TELEMETRY_BRIDGE_STATE_STARTED";
    pub const CONNECTION_ACCEPTED: &str = "TELEMETRY_BRIDGE_CONNECTION_ACCEPTED";
    pub const CONNECTION_CLOSED: &str = "TELEMETRY_BRIDGE_CONNECTION_CLOSED";
    pub const CONNECTION_READ_FAILED: &str = "TELEMETRY_BRIDGE_CONNECTION_READ_FAILED";
    pub const ADMISSION_ACCEPTED: &str = "TELEMETRY_BRIDGE_ADMISSION_ACCEPTED";
    pub const ADMISSION_SHED: &str = "TELEMETRY_BRIDGE_ADMISSION_SHED";
    pub const PERSIST_SUCCESS: &str = "TELEMETRY_BRIDGE_PERSIST_SUCCESS";
    pub const PERSIST_FAILURE: &str = "TELEMETRY_BRIDGE_PERSIST_FAILURE";
}

pub mod reason_codes {
    pub const ALLOWED: &str = "allowed";
    pub const QUEUE_FULL_SHED: &str = "queue_full_shed";
    pub const PERSIST_FAILED: &str = "persist_failed";
    pub const QUEUE_DISCONNECTED: &str = "queue_disconnected";
    pub const READ_FAILED: &str = "reader_failed";
    pub const EVENT_TOO_LARGE: &str = "event_too_large";
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

pub struct TelemetryBridge {
    socket_path: String,
    adapter_slot: Mutex<Option<Arc<Mutex<FrankensqliteAdapter>>>>,
    state: Arc<Mutex<TelemetryBridgeState>>,
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

    /// Spawns a background listener and routes persistence through a single
    /// bounded queue + persistence owner instead of shared mutex writes from
    /// each connection thread.
    pub fn start_listener(&self) -> Result<()> {
        if self
            .started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            anyhow::bail!("telemetry bridge listener already started");
        }

        let socket_path = self.socket_path.clone();
        let state = Arc::clone(&self.state);
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

        let persistence_state = Arc::clone(&state);
        thread::spawn(move || Self::run_persistence_loop(receiver, adapter, persistence_state));

        match std::fs::remove_file(&socket_path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                self.started.store(false, Ordering::SeqCst);
                return Err(err.into());
            }
        }

        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(err) => {
                self.started.store(false, Ordering::SeqCst);
                return Err(err.into());
            }
        };

        Self::with_state(&state, |metrics| {
            metrics.record_event(
                event_codes::LISTENER_STARTED,
                None,
                None,
                Some(reason_codes::ALLOWED),
                format!("listening on {}", socket_path),
            );
        });

        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let Some(connection_id) = Self::with_state(&state, |metrics| {
                            let connection_id = metrics.next_connection_id();
                            metrics.active_connections =
                                metrics.active_connections.saturating_add(1);
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
                        thread::spawn(move || {
                            Self::handle_connection(
                                connection_id,
                                stream,
                                sender_inner,
                                state_inner,
                            );
                        });
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
                    }
                }
            }
        });

        Ok(())
    }

    fn handle_connection(
        connection_id: u64,
        stream: UnixStream,
        sender: SyncSender<PersistEnvelope>,
        state: Arc<Mutex<TelemetryBridgeState>>,
    ) {
        let reader = BufReader::new(stream);
        for line in reader.lines() {
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
            }
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
}
