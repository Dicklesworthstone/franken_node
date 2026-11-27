//! Live HTTP fleet coordinator (`franken-node fleet serve`).
//!
//! [`FleetControlPlaneService`] is the request handler: it authenticates the
//! bearer token, validates every record with the same rules the transports
//! apply, and reads/writes the coordinator's WAL-durable fleet store
//! ([`DurableFleetTransport`]). It is pure request -> response logic so every
//! route is unit-testable without a socket.
//!
//! [`serve_fleet_control_plane`] binds a real TCP listener with the charter's
//! HTTP substrate (`fastapi_rust` on the `asupersync` runtime) and routes each
//! request into the service. The wire contract (paths, bodies, schema tag) is
//! shared with the client in [`super::fleet_transport_http`].
//!
//! The listener awaits a bounded store queue without blocking its reactor.
//! Deadlines and cancellation prevent queued work from starting. An operation
//! that has already started remains owned by the store worker until it finishes;
//! losing its response does not prove a mutation was aborted. Service shutdown
//! refuses queued work and joins the active operation, including any storage wait.
//!
//! Heartbeats are stamped with the coordinator's clock on ingest, so node
//! staleness is judged on one clock for the whole fleet regardless of client
//! clock skew.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::capacity_defaults::aliases::MAX_NODES_CAP;
use crate::control_plane::control_epoch::EpochSigningKey;

use super::fleet_transport::GuardedFleetNativeSessionResume;
use super::fleet_transport::{
    FleetAction, FleetActionRecord, FleetEpochCommitSigner, FleetGuardedPolicyObservationScope,
    FleetTransport, FleetTransportError, GuardedFleetPolicyPublication,
    MAX_GUARDED_POLICY_REQUEST_BYTES, MAX_GUARDED_POLICY_STALE_AFTER, NodeHealth, NodeStatus,
    SeqlockControlPage, validate_action_record, validate_node_id, validate_node_status,
    validate_zone_id,
};
use super::fleet_transport_durable::{DurableFleetTransport, FleetCertifiedMaintenanceAuthority};
use super::fleet_transport_http::FLEET_HTTP_GUARDED_RESUME_PATH;
use super::fleet_transport_http::{
    FLEET_HTTP_ACTIONS_PATH, FLEET_HTTP_API_SCHEMA, FLEET_HTTP_EPOCH_BARRIER_PATH,
    FLEET_HTTP_EPOCH_COMMIT_RESPONSE_SCHEMA, FLEET_HTTP_EPOCH_COMMIT_ROUTE,
    FLEET_HTTP_EPOCH_COMMITS_PREFIX, FLEET_HTTP_GUARDED_POLICY_PATH, FLEET_HTTP_HEALTH_PATH,
    FLEET_HTTP_MAX_REQUEST_BYTES, FLEET_HTTP_NODES_PATH, FLEET_HTTP_STATE_PATH, FleetHttpAck,
    FleetHttpActionList, FleetHttpEpochBarrierRequest, FleetHttpEpochBarrierResponse,
    FleetHttpHealth, FleetHttpNodeList, FleetHttpProblem, FleetHttpState, bearer_token_matches,
    parse_bearer_header, validate_bearer_token,
};

/// Service name reported by the health route.
pub const FLEET_HTTP_SERVICE_NAME: &str = "franken-node-fleet-control-plane";
/// Store label reported by the health route.
pub const FLEET_HTTP_STORE_LABEL: &str = "frankensqlite_durable";

pub const FLEET_HTTP_LISTENING: &str = "FLEET_HTTP_LISTENING";
pub const FLEET_HTTP_REQUEST: &str = "FLEET_HTTP_REQUEST";
pub const FLEET_HTTP_SHUTDOWN: &str = "FLEET_HTTP_SHUTDOWN";

pub const FLEET_NODE_CREDENTIALS_SCHEMA: &str = "franken-node/fleet-node-credentials/v1";
pub const MAX_FLEET_NODE_CREDENTIALS_BYTES: usize = 1 << 20;
pub const MAX_FLEET_NODE_CREDENTIALS: usize = 1_024;

// At most 8 MiB of admitted request bodies can wait behind the active store
// operation (16 * the guarded-policy limit). Store operations remain serialized;
// overload must not turn into an unbounded backlog of delayed control effects.
const FLEET_STORE_QUEUE_CAPACITY: usize = 16;
// Shorter than the listener's 30-second request budget. This bounds waiting,
// not an in-flight fsync: once started, a lost answer has an unknown outcome.
const FLEET_STORE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Coordinator-owned enrollment. Only token digests belong in this file; the
/// random bearer tokens remain in the separately provisioned agents' key files.
/// Enrollment authenticates application checkpoints, not native quiescence.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeCredentialsDocument {
    schema_version: String,
    nodes: Vec<NodeCredentialRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeCredentialRecord {
    zone_id: String,
    node_id: String,
    token_sha256: String,
    /// Independently provisioned protected supervisor root, never inferred
    /// from the heartbeat that it is supposed to authenticate.
    #[serde(default)]
    supervisor_public_key_hex: Option<String>,
}

#[derive(Clone)]
struct EnrolledNode {
    zone_id: String,
    node_id: String,
    token_sha256: [u8; 32],
    supervisor_public_key: Option<ed25519_dalek::VerifyingKey>,
}

/// Validated, bounded enrollment for the existing TLS bearer transport. Each
/// credential has exactly one concrete node/zone audience and no control-action
/// authority. Restart the coordinator to apply an updated enrollment file.
pub struct FleetNodeCredentials {
    nodes: Vec<EnrolledNode>,
}

impl std::fmt::Debug for FleetNodeCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetNodeCredentials")
            .field("node_count", &self.nodes.len())
            .finish_non_exhaustive()
    }
}

impl FleetNodeCredentials {
    fn supervisor_roots(
        &self,
    ) -> Result<BTreeMap<(String, String), ed25519_dalek::VerifyingKey>, FleetTransportError> {
        self.nodes
            .iter()
            .map(|node| {
                let key = node.supervisor_public_key.ok_or_else(|| {
                    FleetTransportError::stale_state(format!(
                        "certified maintenance participant `{}/{}` lacks a pinned supervisor root",
                        node.zone_id, node.node_id
                    ))
                })?;
                Ok(((node.zone_id.clone(), node.node_id.clone()), key))
            })
            .collect()
    }

    /// Load a bounded enrollment file without disclosing credential contents
    /// in errors. Invalid/empty files never fall back to shared-token mode.
    pub fn load(path: &Path) -> Result<Self, FleetTransportError> {
        let file = std::fs::File::open(path).map_err(|_| {
            FleetTransportError::not_initialized("cannot open fleet node credentials")
        })?;
        let metadata = file.metadata().map_err(|_| {
            FleetTransportError::not_initialized("cannot inspect fleet node credentials")
        })?;
        if !metadata.is_file() || metadata.len() > MAX_FLEET_NODE_CREDENTIALS_BYTES as u64 {
            return Err(FleetTransportError::not_initialized(
                "fleet node credentials must be a regular file within the enrollment byte limit",
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_FLEET_NODE_CREDENTIALS_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                FleetTransportError::not_initialized("cannot read fleet node credentials")
            })?;
        Self::from_json(&bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, FleetTransportError> {
        if bytes.len() > MAX_FLEET_NODE_CREDENTIALS_BYTES {
            return Err(FleetTransportError::not_initialized(
                "fleet node credentials exceed the enrollment byte limit",
            ));
        }
        let document: NodeCredentialsDocument = serde_json::from_slice(bytes).map_err(|_| {
            FleetTransportError::not_initialized("invalid fleet node credentials document")
        })?;
        if document.schema_version != FLEET_NODE_CREDENTIALS_SCHEMA
            || document.nodes.is_empty()
            || document.nodes.len() > MAX_FLEET_NODE_CREDENTIALS
        {
            return Err(FleetTransportError::not_initialized(
                "fleet node credentials require the supported schema and 1..=1024 enrolled nodes",
            ));
        }
        let mut identities = BTreeSet::new();
        let mut digests = BTreeSet::new();
        let mut nodes = Vec::with_capacity(document.nodes.len());
        for record in document.nodes {
            validate_zone_id(&record.zone_id)?;
            validate_node_id(&record.node_id)?;
            if record.zone_id == "all"
                || !identities.insert((record.zone_id.clone(), record.node_id.clone()))
            {
                return Err(FleetTransportError::not_initialized(
                    "fleet node credentials require unique node/zone identities in concrete zones",
                ));
            }
            if record.token_sha256.len() != 64
                || !record
                    .token_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(FleetTransportError::not_initialized(
                    "fleet node credential pins must be lowercase SHA-256 digests",
                ));
            }
            let digest: [u8; 32] = hex::decode(&record.token_sha256)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    FleetTransportError::not_initialized("invalid fleet node credential pin")
                })?;
            if !digests.insert(digest) {
                return Err(FleetTransportError::not_initialized(
                    "fleet node credentials must not share a bearer token",
                ));
            }
            let supervisor_public_key =
                record
                    .supervisor_public_key_hex
                    .as_deref()
                    .map(|pin| {
                        let bytes: [u8; 32] = hex::decode(pin)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .filter(|_| pin.len() == 64 && pin.bytes().all(|byte| {
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                    }))
                    .ok_or_else(|| FleetTransportError::not_initialized(
                        "supervisor public-key pins must be 32-byte lowercase Ed25519 keys",
                    ))?;
                        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                            .ok()
                            .filter(|key| !key.is_weak())
                            .ok_or_else(|| {
                                FleetTransportError::not_initialized(
                                    "invalid supervisor public-key pin",
                                )
                            })
                    })
                    .transpose()?;
            nodes.push(EnrolledNode {
                zone_id: record.zone_id,
                node_id: record.node_id,
                token_sha256: digest,
                supervisor_public_key,
            });
        }
        Ok(Self { nodes })
    }
}

#[derive(Clone)]
enum FleetPrincipal {
    Operator,
    Node { zone_id: String, node_id: String },
}

impl FleetPrincipal {
    fn filter_actions(&self, actions: &mut Vec<FleetActionRecord>) {
        if let Self::Node { zone_id, .. } = self {
            actions.retain(|record| {
                let action_zone = match &record.action {
                    FleetAction::Quarantine { zone_id, .. }
                    | FleetAction::Release { zone_id, .. }
                    | FleetAction::NativeSessionHold { zone_id, .. }
                    | FleetAction::NativeSessionResume { zone_id, .. }
                    | FleetAction::PolicyUpdate { zone_id, .. } => zone_id,
                    #[cfg(feature = "control-plane")]
                    FleetAction::Revoke { scope, .. } => &scope.zone_id,
                };
                action_zone == "all" || action_zone == zone_id
            });
        }
    }

    fn filter_nodes(&self, nodes: &mut Vec<NodeStatus>) {
        if let Self::Node { zone_id, node_id } = self {
            nodes.retain(|status| &status.zone_id == zone_id && &status.node_id == node_id);
        }
    }
}

// Observations belong to one coordinator incarnation and bind the exact
// accepted heartbeat. They are written/read on the same store thread as durable
// heartbeats, so a concurrent request cannot authenticate an older read. A
// different writer sharing the durable store cannot substitute a checkpoint
// under an already authenticated identity. After restart, retained checkpoints
// need a fresh node-authenticated heartbeat before convergence.
type AuthenticatedNodes = BTreeMap<(String, String), NodeStatus>;

fn enrolled_node_view(
    nodes: &mut Vec<NodeStatus>,
    credentials: &FleetNodeCredentials,
    authenticated: &AuthenticatedNodes,
    now: DateTime<Utc>,
) -> Result<(), FleetTransportError> {
    let mut present = BTreeSet::new();
    for node in nodes.iter_mut() {
        present.insert((node.zone_id.clone(), node.node_id.clone()));
        if authenticated.get(&(node.zone_id.clone(), node.node_id.clone())) != Some(&*node)
            || verify_supervisor_observation(node, credentials, now).is_err()
        {
            node.applied_actions = None;
            node.native_session_drain = None;
            if node.health == NodeHealth::Maintenance {
                // Maintenance is an acknowledgement of a held terminal drain,
                // so it cannot survive removal of its authenticated evidence.
                // Keep the participant visible after coordinator restart and
                // allow a fresh enrolled heartbeat to establish it again.
                node.health = NodeHealth::Stale;
            }
        }
    }
    for node in &credentials.nodes {
        if present.insert((node.zone_id.clone(), node.node_id.clone())) {
            if nodes.len() >= MAX_NODES_CAP {
                return Err(FleetTransportError::serialization(
                    "enrolled fleet inventory exceeds the bounded node capacity",
                ));
            }
            // Enrollment defines an expected participant, even before its
            // first heartbeat. Absence must not shrink convergence's population.
            nodes.push(NodeStatus {
                zone_id: node.zone_id.clone(),
                node_id: node.node_id.clone(),
                last_seen: DateTime::<Utc>::UNIX_EPOCH,
                quarantine_version: 0,
                health: NodeHealth::Stale,
                applied_actions: None,
                native_session_drain: None,
            });
        }
    }
    nodes.sort_by(|left, right| {
        (&left.zone_id, &left.node_id).cmp(&(&right.zone_id, &right.node_id))
    });
    Ok(())
}

/// Bearer authentication establishes the sender; an enrolled root additionally
/// establishes which protected supervisor produced its local drain evidence.
/// Recheck the signature's clock at every read/guard, since last_seen is stamped
/// by the coordinator and must not extend the lifetime of a replayed signature.
fn verify_supervisor_observation(
    status: &NodeStatus,
    credentials: &FleetNodeCredentials,
    now: DateTime<Utc>,
) -> Result<(), FleetTransportError> {
    let Some(root) = credentials
        .nodes
        .iter()
        .find(|node| node.node_id == status.node_id && node.zone_id == status.zone_id)
        .and_then(|node| node.supervisor_public_key.as_ref())
    else {
        return Ok(());
    };
    let Some(drain) = &status.native_session_drain else {
        // A node may still report degraded/lost evidence; no drain means the
        // existing maintenance/publication gates remain closed.
        return Ok(());
    };
    let attestation = drain.supervisor_attestation.as_ref().ok_or_else(|| {
        FleetTransportError::serialization(
            "enrolled supervisor requires a signed native drain observation",
        )
    })?;
    attestation.verify(drain, &status.node_id, &status.zone_id, root)?;
    attestation.validate_freshness(now)
}

/// One HTTP request as the service sees it.
#[derive(Debug, Clone, Copy)]
pub struct FleetHttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub authorization: Option<&'a str>,
    pub body: &'a [u8],
}

/// The service's answer: a status code and a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Stable outcome label for the access log (`ok`, `unauthorized`, ...).
    pub outcome: &'static str,
}

impl FleetHttpResponse {
    fn json<T: Serialize>(status: u16, outcome: &'static str, value: &T) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|err| {
            format!(
                "{{\"schema_version\":\"{FLEET_HTTP_API_SCHEMA}\",\"status\":500,\"code\":\"FLEET_HTTP_ENCODE\",\"detail\":\"{err}\"}}"
            )
            .into_bytes()
        });
        Self {
            status,
            body,
            outcome,
        }
    }

    fn problem(status: u16, outcome: &'static str, code: &str, detail: impl Into<String>) -> Self {
        Self::json(
            status,
            outcome,
            &FleetHttpProblem {
                schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                status,
                code: code.to_string(),
                detail: detail.into(),
            },
        )
    }
}

/// Structured event emitted for listening, every request, and shutdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FleetHttpEvent {
    pub event_code: &'static str,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requests_served: Option<u64>,
}

impl FleetHttpEvent {
    fn new(event_code: &'static str) -> Self {
        Self {
            event_code,
            timestamp: Utc::now().to_rfc3339(),
            bound_addr: None,
            method: None,
            path: None,
            status: None,
            outcome: None,
            requests_served: None,
        }
    }
}

/// Route handler over the coordinator's durable store.
pub struct FleetControlPlaneService {
    /// Jobs for the store thread. The durable store's database connection is
    /// not `Send`, so one dedicated thread owns it for the service's lifetime
    /// and every request is executed there, serialized; that is also the
    /// single-writer discipline the WAL store wants.
    store: Mutex<Option<mpsc::SyncSender<StoreJob>>>,
    /// Serialized with the worker's start decision. Shutdown cancels queued
    /// operations but must still join any operation that already started.
    store_closing: Arc<Mutex<bool>>,
    store_request_timeout: Duration,
    /// Join handle for the store thread so dropping the service synchronously
    /// drains and closes `DurableFleetTransport` (releasing `fleet-state.db`
    /// locks before any successor coordinator incarnation opens `state_dir`).
    store_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    state_dir: PathBuf,
    token: String,
    node_credentials: Option<Arc<FleetNodeCredentials>>,
    epoch_signing_key: Arc<EpochSigningKey>,
    epoch_commit_signer: Option<Arc<FleetEpochCommitSigner>>,
    seqlock_page: Arc<SeqlockControlPage>,
    clock: fn() -> DateTime<Utc>,
}

impl Drop for FleetControlPlaneService {
    fn drop(&mut self) {
        *self
            .store_closing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        let mut sender = match self.store.lock() {
            Ok(sender) => sender,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _ = sender.take();
        drop(sender);

        let mut handle = match self.store_thread.lock() {
            Ok(handle) => handle,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(handle) = handle.take() {
            let _ = handle.join();
        }
    }
}

type StoreJob = Box<dyn FnOnce(&mut DurableFleetTransport, &mut AuthenticatedNodes) + Send>;

#[derive(Clone)]
struct StoreRequestBudget {
    deadline: Instant,
    request_context: Option<(asupersync::Cx, Option<asupersync::Time>)>,
}

impl From<Instant> for StoreRequestBudget {
    fn from(deadline: Instant) -> Self {
        Self {
            deadline,
            request_context: None,
        }
    }
}

impl StoreRequestBudget {
    fn permits_start(&self) -> bool {
        Instant::now() < self.deadline
            && self.request_context.as_ref().is_none_or(|(cx, deadline)| {
                deadline.is_none_or(|deadline| cx.now() < deadline) && cx.checkpoint().is_ok()
            })
    }
}

enum StoreExecution<T> {
    Queued,
    Running,
    Completed(Result<T, FleetTransportError>),
    Cancelled,
    Stopped { started: bool },
    Consumed,
}

struct StoreCompletion<T> {
    execution: Mutex<StoreExecution<T>>,
    ready: Condvar,
}

/// Only the worker owns this sender. Dropping a queued job or unwinding a
/// failed worker wakes both synchronous and async callers without certifying
/// whether an already-started database operation committed.
struct StoreReply<T> {
    completion: Arc<StoreCompletion<T>>,
    notification: Option<asupersync::channel::oneshot::Sender<()>>,
}

impl<T> StoreReply<T> {
    fn begin(&self, budget: &StoreRequestBudget) -> bool {
        let mut execution = self
            .completion
            .execution
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !matches!(*execution, StoreExecution::Queued) {
            return false;
        }
        if !budget.permits_start() {
            *execution = StoreExecution::Cancelled;
            return false;
        }
        *execution = StoreExecution::Running;
        true
    }

    fn complete(mut self, result: Result<T, FleetTransportError>) {
        *self
            .completion
            .execution
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = StoreExecution::Completed(result);
        self.completion.ready.notify_all();
        if let Some(notification) = self.notification.take() {
            let _ = notification.send_blocking(());
        }
    }
}

impl<T> Drop for StoreReply<T> {
    fn drop(&mut self) {
        let mut execution = self
            .completion
            .execution
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *execution {
            StoreExecution::Queued => *execution = StoreExecution::Stopped { started: false },
            StoreExecution::Running => *execution = StoreExecution::Stopped { started: true },
            _ => {}
        }
        drop(execution);
        self.completion.ready.notify_all();
    }
}

#[derive(Debug)]
enum StoreRequestFailure {
    Operation(FleetTransportError),
    Busy,
    CancelledBeforeStart,
    OutcomeUnknown,
    StoppedBeforeStart,
}

impl StoreRequestFailure {
    fn into_transport(self) -> FleetTransportError {
        match self {
            Self::Operation(error) => error,
            Self::Busy => FleetTransportError::lock_contention(
                "fleet store queue is full; operation was not accepted",
            ),
            Self::CancelledBeforeStart => FleetTransportError::stale_state(
                "fleet store request expired or was cancelled before execution; no operation started",
            ),
            Self::OutcomeUnknown => FleetTransportError::io(
                "fleet store operation started but its answer is unavailable; outcome is unknown, inspect durable state before retrying",
            ),
            Self::StoppedBeforeStart => {
                FleetTransportError::io("fleet store worker stopped before this operation started")
            }
        }
    }

    fn response(self) -> FleetHttpResponse {
        let (status, outcome, code) = match &self {
            Self::Operation(error) => return store_error(error),
            Self::Busy => (503, "busy", "FLEET_HTTP_STORE_QUEUE_FULL"),
            Self::CancelledBeforeStart => (
                504,
                "cancelled_before_start",
                "FLEET_HTTP_STORE_NOT_STARTED",
            ),
            Self::OutcomeUnknown => (504, "outcome_unknown", "FLEET_HTTP_STORE_OUTCOME_UNKNOWN"),
            Self::StoppedBeforeStart => (503, "store_stopped", "FLEET_HTTP_STORE_STOPPED"),
        };
        FleetHttpResponse::problem(status, outcome, code, self.into_transport().to_string())
    }
}

struct StoreRequest<T> {
    completion: Arc<StoreCompletion<T>>,
    notification: asupersync::channel::oneshot::Receiver<()>,
    deadline: Instant,
}

impl<T> StoreRequest<T> {
    /// Completion wins a race with cancellation/deadline. Otherwise the exact
    /// start state determines whether refusal is certain or outcome is unknown.
    fn resolve(execution: &mut StoreExecution<T>) -> Result<T, StoreRequestFailure> {
        match execution {
            StoreExecution::Completed(_) => {
                let StoreExecution::Completed(result) =
                    std::mem::replace(execution, StoreExecution::Consumed)
                else {
                    unreachable!("completed result was inspected under the same mutex")
                };
                result.map_err(StoreRequestFailure::Operation)
            }
            StoreExecution::Queued => {
                *execution = StoreExecution::Cancelled;
                Err(StoreRequestFailure::CancelledBeforeStart)
            }
            StoreExecution::Cancelled => Err(StoreRequestFailure::CancelledBeforeStart),
            StoreExecution::Running | StoreExecution::Stopped { started: true } => {
                Err(StoreRequestFailure::OutcomeUnknown)
            }
            StoreExecution::Stopped { started: false } | StoreExecution::Consumed => {
                Err(StoreRequestFailure::StoppedBeforeStart)
            }
        }
    }

    fn wait(self) -> Result<T, StoreRequestFailure> {
        let mut execution = self
            .completion
            .execution
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while matches!(*execution, StoreExecution::Queued | StoreExecution::Running) {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (next, _) = self
                .completion
                .ready
                .wait_timeout(execution, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            execution = next;
        }
        Self::resolve(&mut execution)
    }

    async fn wait_async(mut self, cx: &asupersync::Cx) -> Result<T, StoreRequestFailure> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if !remaining.is_zero() {
            let _ =
                asupersync::time::timeout(cx.now(), remaining, self.notification.recv(cx)).await;
        }
        Self::resolve(
            &mut self
                .completion
                .execution
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }
}

impl<T> Drop for StoreRequest<T> {
    fn drop(&mut self) {
        let mut execution = self
            .completion
            .execution
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(*execution, StoreExecution::Queued) {
            // A cancelled HTTP future owns the queued request. Dropping it
            // prevents a late side effect; Running remains worker-owned.
            *execution = StoreExecution::Cancelled;
        }
    }
}

enum PendingFleetResponse {
    Ready(FleetHttpResponse),
    Store(StoreRequest<FleetHttpResponse>),
}

impl From<FleetHttpResponse> for PendingFleetResponse {
    fn from(response: FleetHttpResponse) -> Self {
        Self::Ready(response)
    }
}

impl std::fmt::Debug for FleetControlPlaneService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetControlPlaneService")
            .field("token", &"<redacted>")
            .field("enrolled_node_count", &self.enrolled_node_count())
            .finish_non_exhaustive()
    }
}

impl FleetControlPlaneService {
    /// Open (initializing if needed) the durable store under `state_dir` on
    /// the service's store thread.
    ///
    /// # Errors
    ///
    /// Fails on an unusable token or an unopenable store.
    pub fn open(state_dir: PathBuf, token: &str) -> Result<Self, FleetTransportError> {
        Self::open_with_store_limits(
            state_dir,
            token,
            FLEET_STORE_QUEUE_CAPACITY,
            FLEET_STORE_REQUEST_TIMEOUT,
        )
    }

    fn open_with_store_limits(
        state_dir: PathBuf,
        token: &str,
        queue_capacity: usize,
        request_timeout: Duration,
    ) -> Result<Self, FleetTransportError> {
        if queue_capacity == 0
            || queue_capacity > FLEET_STORE_QUEUE_CAPACITY
            || request_timeout.is_zero()
            || request_timeout > FLEET_STORE_REQUEST_TIMEOUT
        {
            return Err(FleetTransportError::not_initialized(
                "fleet store limits must be positive and within the service bounds",
            ));
        }
        validate_bearer_token(token).map_err(FleetTransportError::not_initialized)?;
        let epoch_key_material = Sha256::digest(format!("fleet-epoch-signing:{token}").as_bytes());
        let epoch_signing_key = EpochSigningKey::new(epoch_key_material.as_slice())
            .map_err(|err| FleetTransportError::not_initialized(err.to_string()))?;
        let epoch_signing_key = Arc::new(epoch_signing_key);
        let store_epoch_key = Arc::clone(&epoch_signing_key);
        let seqlock_page = Arc::new(SeqlockControlPage::new());
        let startup_seqlock_page = Arc::clone(&seqlock_page);
        let store_dir = state_dir.clone();
        let (jobs, inbox) = mpsc::sync_channel::<StoreJob>(queue_capacity);
        let store_closing = Arc::new(Mutex::new(false));
        let (ready, opened) = mpsc::sync_channel::<Result<(), FleetTransportError>>(1);
        let store_thread = std::thread::Builder::new()
            .name("fleet-control-plane-store".to_string())
            .spawn(move || {
                let seqlock_path = store_dir.join("seqlock.page");
                let mut transport =
                    match DurableFleetTransport::new(store_dir).and_then(|mut transport| {
                        transport.initialize()?;
                        let recovered_epoch = transport.current_fleet_epoch(&store_epoch_key)?;
                        if recovered_epoch > 0 {
                            let state = transport.read_shared_state()?;
                            let checkpoint = super::fleet_transport::fleet_action_log_checkpoint(
                                &state.actions,
                            )?;
                            let active_hold_count =
                                super::fleet_transport::fleet_native_session_holds(
                                    &state.actions,
                                    "all",
                                )?
                                .len() as u64;
                            let max_action_qv = state
                                .actions
                                .iter()
                                .filter_map(|record| match &record.action {
                                    FleetAction::Quarantine {
                                        quarantine_version, ..
                                    } => Some(*quarantine_version),
                                    _ => None,
                                })
                                .max()
                                .unwrap_or(0);
                            let max_node_qv = state
                                .nodes
                                .iter()
                                .map(|node| node.quarantine_version)
                                .max()
                                .unwrap_or(0);
                            let max_qv = max_action_qv.max(max_node_qv);
                            let mut digest_prefix = [0_u8; 32];
                            if let Ok(decoded) = hex::decode(&checkpoint.actions_sha256)
                                && decoded.len() == 32
                            {
                                digest_prefix.copy_from_slice(&decoded);
                            }
                            startup_seqlock_page.publish(
                                recovered_epoch,
                                max_qv,
                                active_hold_count,
                                checkpoint.action_count,
                                digest_prefix,
                            );
                            startup_seqlock_page.write_shared_page(&seqlock_path)?;
                        }
                        Ok(transport)
                    }) {
                        Ok(transport) => {
                            let _ = ready.send(Ok(()));
                            transport
                        }
                        Err(err) => {
                            let _ = ready.send(Err(err));
                            return;
                        }
                    };
                let mut authenticated_nodes = AuthenticatedNodes::new();
                // Ends when the service (the only sender) is dropped.
                while let Ok(job) = inbox.recv() {
                    job(&mut transport, &mut authenticated_nodes);
                }
            })
            .map_err(|err| FleetTransportError::io(format!("spawn fleet store thread: {err}")))?;
        let startup_result = opened
            .recv()
            .map_err(|_| FleetTransportError::io("fleet store thread exited during startup"))
            .and_then(|result| result);
        if let Err(err) = startup_result {
            drop(jobs);
            let _ = store_thread.join();
            return Err(err);
        }
        Ok(Self {
            store: Mutex::new(Some(jobs)),
            store_closing,
            store_request_timeout: request_timeout,
            store_thread: Mutex::new(Some(store_thread)),
            state_dir,
            token: token.to_string(),
            node_credentials: None,
            epoch_signing_key,
            epoch_commit_signer: None,
            seqlock_page,
            clock: Utc::now,
        })
    }

    /// Require a distinct enrolled credential for every node acknowledgement.
    /// The operator credential retains control-action and read authority only.
    pub fn with_node_credentials(
        mut self,
        credentials: FleetNodeCredentials,
    ) -> Result<Self, FleetTransportError> {
        if self.node_credentials.is_some() {
            return Err(FleetTransportError::not_initialized(
                "restart the fleet coordinator to replace node enrollment",
            ));
        }
        let operator_digest: [u8; 32] = Sha256::digest(self.token.as_bytes()).into();
        if credentials
            .nodes
            .iter()
            .any(|node| bool::from(operator_digest.ct_eq(&node.token_sha256)))
        {
            return Err(FleetTransportError::not_initialized(
                "operator and node credentials must be distinct",
            ));
        }
        self.node_credentials = Some(Arc::new(credentials));
        Ok(self)
    }

    /// Enable independent public commit proofs with an explicitly provisioned
    /// identity/key pair. Existing signed history pins both across restarts.
    pub fn with_epoch_commit_signer(
        mut self,
        signer: FleetEpochCommitSigner,
    ) -> Result<Self, FleetTransportError> {
        if self.epoch_commit_signer.is_some() {
            return Err(FleetTransportError::not_initialized(
                "restart the fleet coordinator to replace its epoch signing identity",
            ));
        }
        let signer = Arc::new(signer);
        let candidate = Arc::clone(&signer);
        let key = Arc::clone(&self.epoch_signing_key);
        self.with_store(move |transport, _| {
            transport.validate_epoch_commit_signer(&key, &candidate)
        })?;
        self.epoch_commit_signer = Some(signer);
        Ok(self)
    }

    #[must_use]
    pub fn enrolled_node_count(&self) -> usize {
        self.node_credentials
            .as_ref()
            .map_or(0, |credentials| credentials.nodes.len())
    }

    /// Lock-free seqlock control page reflecting the latest coordinator-authenticated epoch.
    #[must_use]
    pub fn seqlock_page(&self) -> &SeqlockControlPage {
        &self.seqlock_page
    }

    fn authenticate(&self, authorization: Option<&str>) -> Option<FleetPrincipal> {
        let token = authorization.and_then(parse_bearer_header)?;
        validate_bearer_token(token).ok()?;
        let is_operator = bearer_token_matches(token, &self.token);
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut matched = None;
        if let Some(credentials) = &self.node_credentials {
            // Compare every pin in constant time; never stop at a matching
            // prefix or skip later enrolled identities after a match.
            for node in &credentials.nodes {
                if bool::from(digest.ct_eq(&node.token_sha256)) {
                    matched = Some(FleetPrincipal::Node {
                        zone_id: node.zone_id.clone(),
                        node_id: node.node_id.clone(),
                    });
                }
            }
        }
        if is_operator {
            Some(FleetPrincipal::Operator)
        } else {
            matched
        }
    }

    /// Replace the heartbeat clock (deterministic tests).
    #[must_use]
    pub fn with_clock(mut self, clock: fn() -> DateTime<Utc>) -> Self {
        self.clock = clock;
        self
    }

    /// Answer one request from a synchronous caller with a finite wait budget.
    /// The live listener uses `handle_async` so storage never blocks its reactor.
    #[must_use]
    pub fn handle(&self, request: FleetHttpRequest<'_>) -> FleetHttpResponse {
        match self.dispatch_request(request, Instant::now() + self.store_request_timeout) {
            PendingFleetResponse::Ready(response) => response,
            PendingFleetResponse::Store(pending) => {
                pending.wait().unwrap_or_else(StoreRequestFailure::response)
            }
        }
    }

    /// Await the single owned store worker under the request's cancellation
    /// context and the smaller of its HTTP deadline and store wait budget.
    pub async fn handle_async(
        &self,
        cx: &asupersync::Cx,
        http_deadline: Option<asupersync::Time>,
        request: FleetHttpRequest<'_>,
    ) -> FleetHttpResponse {
        let budget = http_deadline.map_or(self.store_request_timeout, |deadline| {
            Duration::from_nanos(deadline.as_nanos().saturating_sub(cx.now().as_nanos()))
                .min(self.store_request_timeout)
        });
        if budget.is_zero() || cx.checkpoint().is_err() {
            return StoreRequestFailure::CancelledBeforeStart.response();
        }
        match self.dispatch_request(
            request,
            StoreRequestBudget {
                deadline: Instant::now() + budget,
                request_context: Some((cx.clone(), http_deadline)),
            },
        ) {
            PendingFleetResponse::Ready(response) => response,
            PendingFleetResponse::Store(pending) => pending
                .wait_async(cx)
                .await
                .unwrap_or_else(StoreRequestFailure::response),
        }
    }

    fn dispatch_request(
        &self,
        request: FleetHttpRequest<'_>,
        budget: impl Into<StoreRequestBudget>,
    ) -> PendingFleetResponse {
        let budget = budget.into();
        let path = request.path.split('?').next().unwrap_or_default();
        let path = if path.len() > 1 {
            path.trim_end_matches('/')
        } else {
            path
        };
        let epoch_export = path.strip_prefix(FLEET_HTTP_EPOCH_COMMITS_PREFIX);
        let known_path = epoch_export.is_some()
            || matches!(
                path,
                FLEET_HTTP_HEALTH_PATH
                    | FLEET_HTTP_ACTIONS_PATH
                    | FLEET_HTTP_NODES_PATH
                    | FLEET_HTTP_STATE_PATH
                    | FLEET_HTTP_GUARDED_POLICY_PATH
                    | FLEET_HTTP_GUARDED_RESUME_PATH
                    | FLEET_HTTP_EPOCH_BARRIER_PATH
            );
        if !known_path {
            return FleetHttpResponse::problem(
                404,
                "not_found",
                "FLEET_HTTP_NOT_FOUND",
                format!("no fleet route at `{path}`"),
            )
            .into();
        }
        if path == FLEET_HTTP_HEALTH_PATH {
            if request.method != "GET" {
                return method_not_allowed(request.method, path).into();
            }
            return FleetHttpResponse::json(
                200,
                "ok",
                &FleetHttpHealth {
                    schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                    status: "ok".to_string(),
                    service: FLEET_HTTP_SERVICE_NAME.to_string(),
                    store: FLEET_HTTP_STORE_LABEL.to_string(),
                },
            )
            .into();
        }

        let Some(principal) = self.authenticate(request.authorization) else {
            return FleetHttpResponse::problem(
                401,
                "unauthorized",
                "FLEET_HTTP_UNAUTHORIZED",
                "a valid `Authorization: Bearer <token>` header is required",
            )
            .into();
        };
        let request_limit = if matches!(
            path,
            FLEET_HTTP_GUARDED_POLICY_PATH | FLEET_HTTP_GUARDED_RESUME_PATH
        ) {
            MAX_GUARDED_POLICY_REQUEST_BYTES
        } else {
            FLEET_HTTP_MAX_REQUEST_BYTES
        };
        if request.body.len() > request_limit {
            return FleetHttpResponse::problem(
                413,
                "too_large",
                "FLEET_HTTP_BODY_TOO_LARGE",
                format!(
                    "request body is {} bytes; the route limit is {request_limit}",
                    request.body.len()
                ),
            )
            .into();
        }

        if request.method == "POST" {
            let permitted = match (&principal, path) {
                (FleetPrincipal::Operator, FLEET_HTTP_ACTIONS_PATH)
                | (FleetPrincipal::Operator, FLEET_HTTP_GUARDED_POLICY_PATH)
                | (FleetPrincipal::Operator, FLEET_HTTP_GUARDED_RESUME_PATH)
                | (FleetPrincipal::Operator, FLEET_HTTP_EPOCH_BARRIER_PATH)
                | (FleetPrincipal::Node { .. }, FLEET_HTTP_NODES_PATH) => true,
                (FleetPrincipal::Operator, FLEET_HTTP_NODES_PATH) => {
                    self.node_credentials.is_none()
                }
                _ => false,
            };
            if !permitted {
                return FleetHttpResponse::problem(
                    403,
                    "forbidden",
                    "FLEET_HTTP_CREDENTIAL_SCOPE",
                    "credential is not authorized for this fleet operation",
                )
                .into();
            }
        }
        if matches!(&principal, FleetPrincipal::Node { .. })
            && request.method == "GET"
            && (path == FLEET_HTTP_STATE_PATH || epoch_export.is_some())
        {
            return FleetHttpResponse::problem(
                403,
                "forbidden",
                "FLEET_HTTP_CREDENTIAL_SCOPE",
                "whole-fleet inventory and convergence require an operator credential",
            )
            .into();
        }

        let enrollment = self.node_credentials.clone();

        if let Some(encoded_epoch) = epoch_export {
            if request.method != "GET" {
                return method_not_allowed(request.method, path).into();
            }
            let Some(epoch) = encoded_epoch
                .parse::<u64>()
                .ok()
                .filter(|epoch| *epoch > 0 && epoch.to_string() == encoded_epoch)
            else {
                return FleetHttpResponse::problem(
                    400,
                    "bad_request",
                    "FLEET_HTTP_INVALID_EPOCH",
                    "a retained epoch must be a canonical positive decimal u64",
                )
                .into();
            };
            let Some(signer) = self.epoch_commit_signer.clone() else {
                return FleetHttpResponse::problem(
                    409,
                    "conflict",
                    "FLEET_HTTP_COORDINATOR_SIGNING_KEY_REQUIRED",
                    "retained public epoch proof export requires its provisioned coordinator signing key",
                ).into();
            };
            let key = Arc::clone(&self.epoch_signing_key);
            return self.with_transport(&budget, move |transport, _| {
                let (evidence, certificate, proof) =
                    transport.export_epoch_commit(&key, &signer, epoch)?;
                Ok(FleetHttpResponse::json(
                    200,
                    "ok",
                    &FleetHttpEpochBarrierResponse {
                        schema_version: FLEET_HTTP_EPOCH_COMMIT_RESPONSE_SCHEMA.to_owned(),
                        already_committed: true,
                        evidence,
                        certificate,
                        commit_proof: Some(proof),
                    },
                ))
            });
        }

        match (request.method, path) {
            ("GET", FLEET_HTTP_ACTIONS_PATH) => {
                self.with_transport(&budget, move |transport, _| {
                    let mut actions = transport.list_actions()?;
                    principal.filter_actions(&mut actions);
                    Ok(FleetHttpResponse::json(
                        200,
                        "ok",
                        &FleetHttpActionList {
                            schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                            actions,
                        },
                    ))
                })
            }
            ("POST", FLEET_HTTP_ACTIONS_PATH) => {
                let action: FleetActionRecord = match parse_body(request.body) {
                    Ok(action) => action,
                    Err(response) => return response.into(),
                };
                if let Err(err) = validate_action_record(&action) {
                    return invalid_record(&err).into();
                }
                self.with_transport(&budget, move |transport, _| {
                    transport.publish_action(&action)?;
                    Ok(FleetHttpResponse::json(
                        201,
                        "ok",
                        &FleetHttpAck {
                            schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                            accepted: action.action_id.clone(),
                            recorded_at: None,
                        },
                    ))
                })
            }
            ("POST", FLEET_HTTP_GUARDED_POLICY_PATH) => {
                let Some(enrollment) = enrollment else {
                    return FleetHttpResponse::problem(
                        409,
                        "conflict",
                        "FLEET_HTTP_NODE_ENROLLMENT_REQUIRED",
                        "guarded policy publication requires enrolled node credentials and fresh node-authenticated maintenance observations",
                    ).into();
                };
                let publication: GuardedFleetPolicyPublication = match parse_body(request.body) {
                    Ok(publication) => publication,
                    Err(response) => return response.into(),
                };
                if let Err(err) = publication.validate() {
                    return invalid_record(&err).into();
                }
                let epoch_signing_key = Arc::clone(&self.epoch_signing_key);
                let epoch_commit_signer = self.epoch_commit_signer.clone();
                let clock = self.clock;
                self.with_transport(&budget, move |transport, authenticated| {
                    // Project the exact authenticated observations within the
                    // durable transaction, on the same serialized store thread
                    // as heartbeat acceptance. Missing enrolled nodes remain
                    // participants and cannot disappear from the guard.
                    let receipt = if publication.guard.certified_epoch.is_some() {
                        let signer = epoch_commit_signer.as_deref().ok_or_else(|| {
                            FleetTransportError::stale_state(
                                "certified policy publication requires its provisioned coordinator signing key",
                            )
                        })?;
                        let roots = enrollment.supervisor_roots()?;
                        transport.publish_policy_with_certified_maintenance_guard_projected(
                            &publication,
                            &FleetCertifiedMaintenanceAuthority {
                                epoch_signing_key: &epoch_signing_key,
                                coordinator_signer: signer,
                                enrolled_supervisors: &roots,
                            },
                            MAX_GUARDED_POLICY_STALE_AFTER,
                            clock,
                            |nodes| enrolled_node_view(nodes, &enrollment, authenticated, clock()),
                        )?
                    } else {
                        transport.publish_policy_with_maintenance_guard_projected(
                            &publication,
                            FleetGuardedPolicyObservationScope::EnrolledNodeObservations,
                            MAX_GUARDED_POLICY_STALE_AFTER,
                            clock,
                            |nodes| enrolled_node_view(nodes, &enrollment, authenticated, clock()),
                        )?
                    };
                    Ok(FleetHttpResponse::json(
                        if receipt.already_published { 200 } else { 201 },
                        "ok",
                        &receipt,
                    ))
                })
            }
            ("POST", FLEET_HTTP_GUARDED_RESUME_PATH) => {
                let Some(enrollment) = enrollment else {
                    return FleetHttpResponse::problem(
                        409,
                        "conflict",
                        "FLEET_HTTP_NODE_ENROLLMENT_REQUIRED",
                        "guarded resume requires enrolled node credentials and fresh post-policy maintenance acknowledgements",
                    ).into();
                };
                let resume: GuardedFleetNativeSessionResume = match parse_body(request.body) {
                    Ok(resume) => resume,
                    Err(response) => return response.into(),
                };
                if let Err(error) = resume.validate() {
                    return invalid_record(&error).into();
                }
                let epoch_signing_key = Arc::clone(&self.epoch_signing_key);
                let epoch_commit_signer = self.epoch_commit_signer.clone();
                let clock = self.clock;
                self.with_transport(&budget, move |transport, authenticated| {
                    let receipt = if resume.guard.certified_epoch.is_some() {
                        let signer = epoch_commit_signer.as_deref().ok_or_else(|| {
                            FleetTransportError::stale_state(
                                "certified resume requires its provisioned coordinator signing key",
                            )
                        })?;
                        let roots = enrollment.supervisor_roots()?;
                        transport.resume_native_sessions_with_certified_maintenance_guard_projected(
                            &resume,
                            &FleetCertifiedMaintenanceAuthority {
                                epoch_signing_key: &epoch_signing_key,
                                coordinator_signer: signer,
                                enrolled_supervisors: &roots,
                            },
                            MAX_GUARDED_POLICY_STALE_AFTER,
                            clock,
                            |nodes| enrolled_node_view(nodes, &enrollment, authenticated, clock()),
                        )?
                    } else {
                        transport.resume_native_sessions_with_maintenance_guard_projected(
                            &resume,
                            FleetGuardedPolicyObservationScope::EnrolledNodeObservations,
                            MAX_GUARDED_POLICY_STALE_AFTER,
                            clock,
                            |nodes| enrolled_node_view(nodes, &enrollment, authenticated, clock()),
                        )?
                    };
                    Ok(FleetHttpResponse::json(
                        if receipt.already_resumed { 200 } else { 201 },
                        "ok",
                        &receipt,
                    ))
                })
            }
            ("POST", FLEET_HTTP_EPOCH_BARRIER_PATH) => {
                let Some(enrollment) = enrollment else {
                    return FleetHttpResponse::problem(
                        409,
                        "conflict",
                        "FLEET_HTTP_NODE_ENROLLMENT_REQUIRED",
                        "epoch-barrier quiescence certification requires enrolled per-node Ed25519 supervisor credentials",
                    ).into();
                };
                let mut roots = BTreeMap::new();
                for node in &enrollment.nodes {
                    let Some(key) = node.supervisor_public_key else {
                        return FleetHttpResponse::problem(
                            409,
                            "conflict",
                            "FLEET_HTTP_SUPERVISOR_KEY_REQUIRED",
                            format!(
                                "enrolled participant `{}/{}` lacks a pinned supervisor_public_key_hex",
                                node.zone_id, node.node_id
                            ),
                        ).into();
                    };
                    roots.insert((node.zone_id.clone(), node.node_id.clone()), key);
                }
                let barrier_req: FleetHttpEpochBarrierRequest = match parse_body(request.body) {
                    Ok(req) => req,
                    Err(response) => return response.into(),
                };
                if let Err(error) = barrier_req.validate() {
                    return invalid_record(&error).into();
                }
                if barrier_req.operation_id.is_some() && self.epoch_commit_signer.is_none() {
                    return FleetHttpResponse::problem(
                        409,
                        "conflict",
                        "FLEET_HTTP_COORDINATOR_SIGNING_KEY_REQUIRED",
                        "retryable epoch operations require a provisioned coordinator signing key",
                    )
                    .into();
                }
                let clock = self.clock;
                let epoch_signing_key = Arc::clone(&self.epoch_signing_key);
                let epoch_commit_signer = self.epoch_commit_signer.clone();
                let seqlock_page = Arc::clone(&self.seqlock_page);
                let seqlock_path = self.state_dir.join("seqlock.page");
                self.with_transport(&budget, move |transport, authenticated| {
                    let (evidence, certificate, max_qv, already_committed) =
                        transport.certify_epoch_quiescence_projected(
                            &epoch_signing_key,
                            epoch_commit_signer.as_deref(),
                            &roots,
                            super::fleet_transport::FleetEpochBarrierParams {
                                operation_id: barrier_req.operation_id.as_deref(),
                                operation_request_sha256: None,
                                expected_action_log: barrier_req.expected_action_log.as_ref(),
                                initiator: &barrier_req.initiator,
                                reason: &barrier_req.reason,
                                now: clock(),
                                stale_after: barrier_req.stale_after,
                                trace_id: &barrier_req.trace_id,
                            },
                            clock,
                            |nodes| enrolled_node_view(nodes, &enrollment, authenticated, clock()),
                        )?;
                    let commit_proof = epoch_commit_signer
                        .as_ref()
                        .map(|signer| {
                            transport
                                .export_epoch_commit(&epoch_signing_key, signer, certificate.committed_epoch)
                                .map(|(_, _, proof)| proof)
                        })
                        .transpose()?;
                    if !already_committed {
                        let checkpoint = &certificate.action_log_checkpoint;
                        let mut digest_prefix = [0_u8; 32];
                        if let Ok(decoded) = hex::decode(&checkpoint.actions_sha256)
                            && decoded.len() == 32
                        {
                            digest_prefix.copy_from_slice(&decoded);
                        }
                        let active_hold_count = certificate
                            .participants
                            .iter()
                            .flat_map(|participant| participant.active_hold_ids.iter())
                            .collect::<BTreeSet<_>>()
                            .len() as u64;
                        seqlock_page.publish(
                            certificate.committed_epoch,
                            max_qv,
                            active_hold_count,
                            checkpoint.action_count,
                            digest_prefix,
                        );
                        seqlock_page.write_shared_page(&seqlock_path).map_err(|error| {
                            FleetTransportError::io(format!(
                                "fleet epoch {} committed durably, but control cache publication failed: {error}",
                                certificate.committed_epoch
                            ))
                        })?;
                    }
                    Ok(FleetHttpResponse::json(
                        200,
                        "ok",
                        &FleetHttpEpochBarrierResponse {
                            schema_version: if commit_proof.is_some() {
                                FLEET_HTTP_EPOCH_COMMIT_RESPONSE_SCHEMA
                            } else {
                                FLEET_HTTP_API_SCHEMA
                            }.to_owned(),
                            already_committed,
                            evidence,
                            certificate,
                            commit_proof,
                        },
                    ))
                })
            }
            ("GET", FLEET_HTTP_NODES_PATH) => {
                let clock = self.clock;
                self.with_transport(&budget, move |transport, authenticated| {
                    let mut nodes = transport.list_node_statuses()?;
                    if let Some(credentials) = &enrollment {
                        enrolled_node_view(&mut nodes, credentials, authenticated, clock())?;
                    }
                    principal.filter_nodes(&mut nodes);
                    Ok(FleetHttpResponse::json(
                        200,
                        "ok",
                        &FleetHttpNodeList {
                            schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                            nodes,
                        },
                    ))
                })
            }
            ("POST", FLEET_HTTP_NODES_PATH) => {
                let mut status: NodeStatus = match parse_body(request.body) {
                    Ok(status) => status,
                    Err(response) => return response.into(),
                };
                if let Err(err) = validate_node_status(&status) {
                    return invalid_record(&err).into();
                }
                if let FleetPrincipal::Node { zone_id, node_id } = &principal
                    && (status.zone_id != *zone_id || status.node_id != *node_id)
                {
                    return FleetHttpResponse::problem(
                        403,
                        "forbidden",
                        "FLEET_HTTP_NODE_IDENTITY_MISMATCH",
                        "heartbeat identity does not match the enrolled credential",
                    )
                    .into();
                }
                let recorded_at = (self.clock)();
                if let Some(credentials) = &enrollment
                    && let Err(error) =
                        verify_supervisor_observation(&status, credentials, recorded_at)
                {
                    return invalid_record(&error).into();
                }
                status.last_seen = recorded_at;
                self.with_transport(&budget, move |transport, authenticated| {
                    let root = enrollment.as_ref().and_then(|credentials| {
                        credentials
                            .nodes
                            .iter()
                            .find(|node| {
                                node.node_id == status.node_id && node.zone_id == status.zone_id
                            })
                            .and_then(|node| node.supervisor_public_key.as_ref())
                    });
                    if let Some(root) = root {
                        transport.upsert_node_status_with_supervisor(&status, root)?;
                    } else {
                        transport.upsert_node_status(&status)?;
                    }
                    if matches!(principal, FleetPrincipal::Node { .. }) {
                        authenticated.insert(
                            (status.zone_id.clone(), status.node_id.clone()),
                            status.clone(),
                        );
                    }
                    Ok(FleetHttpResponse::json(
                        200,
                        "ok",
                        &FleetHttpAck {
                            schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                            accepted: format!("{}/{}", status.zone_id, status.node_id),
                            recorded_at: Some(recorded_at.to_rfc3339()),
                        },
                    ))
                })
            }
            ("GET", FLEET_HTTP_STATE_PATH) => {
                let clock = self.clock;
                self.with_transport(&budget, move |transport, authenticated| {
                    let mut state = transport.read_shared_state()?;
                    if let Some(credentials) = &enrollment {
                        enrolled_node_view(&mut state.nodes, credentials, authenticated, clock())?;
                    }
                    Ok(FleetHttpResponse::json(
                        200,
                        "ok",
                        &FleetHttpState {
                            schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                            state,
                        },
                    ))
                })
            }
            (method, path) => method_not_allowed(method, path).into(),
        }
    }

    /// Enqueue a bounded store operation without blocking the HTTP reactor.
    fn with_transport(
        &self,
        budget: &StoreRequestBudget,
        operation: impl FnOnce(
            &mut DurableFleetTransport,
            &mut AuthenticatedNodes,
        ) -> Result<FleetHttpResponse, FleetTransportError>
        + Send
        + 'static,
    ) -> PendingFleetResponse {
        match self.enqueue_store(budget.clone(), operation) {
            Ok(pending) => PendingFleetResponse::Store(pending),
            Err(error) => error.response().into(),
        }
    }

    fn with_store<T: Send + 'static>(
        &self,
        operation: impl FnOnce(
            &mut DurableFleetTransport,
            &mut AuthenticatedNodes,
        ) -> Result<T, FleetTransportError>
        + Send
        + 'static,
    ) -> Result<T, FleetTransportError> {
        self.enqueue_store(Instant::now() + self.store_request_timeout, operation)
            .and_then(StoreRequest::wait)
            .map_err(StoreRequestFailure::into_transport)
    }

    fn enqueue_store<T: Send + 'static>(
        &self,
        budget: impl Into<StoreRequestBudget>,
        operation: impl FnOnce(
            &mut DurableFleetTransport,
            &mut AuthenticatedNodes,
        ) -> Result<T, FleetTransportError>
        + Send
        + 'static,
    ) -> Result<StoreRequest<T>, StoreRequestFailure> {
        let budget = budget.into();
        if !budget.permits_start() {
            return Err(StoreRequestFailure::CancelledBeforeStart);
        }
        let deadline = budget.deadline;
        let completion = Arc::new(StoreCompletion {
            execution: Mutex::new(StoreExecution::Queued),
            ready: Condvar::new(),
        });
        let (notification, receiver) = asupersync::channel::oneshot::channel();
        let reply = StoreReply {
            completion: Arc::clone(&completion),
            notification: Some(notification),
        };
        let closing = Arc::clone(&self.store_closing);
        let job: StoreJob = Box::new(move |transport, authenticated| {
            let started = {
                let closing = closing
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                !*closing && reply.begin(&budget)
            };
            if started {
                reply.complete(operation(transport, authenticated));
            }
        });
        {
            let sender = match self.store.lock() {
                Ok(sender) => sender,
                // Sending cannot leave the sender half-updated, so a poisoned
                // lock is still safe to use.
                Err(poisoned) => poisoned.into_inner(),
            };
            let sender = sender
                .as_ref()
                .ok_or(StoreRequestFailure::StoppedBeforeStart)?;
            match sender.try_send(job) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => return Err(StoreRequestFailure::Busy),
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(StoreRequestFailure::StoppedBeforeStart);
                }
            }
        }
        Ok(StoreRequest {
            completion,
            notification: receiver,
            deadline,
        })
    }
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, FleetHttpResponse> {
    serde_json::from_slice(body).map_err(|err| {
        FleetHttpResponse::problem(
            400,
            "bad_request",
            "FLEET_HTTP_MALFORMED_BODY",
            format!("request body is not a valid record: {err}"),
        )
    })
}

fn invalid_record(err: &FleetTransportError) -> FleetHttpResponse {
    FleetHttpResponse::problem(422, "invalid", "FLEET_HTTP_INVALID_RECORD", err.to_string())
}

fn method_not_allowed(method: &str, path: &str) -> FleetHttpResponse {
    FleetHttpResponse::problem(
        405,
        "method_not_allowed",
        "FLEET_HTTP_METHOD_NOT_ALLOWED",
        format!("`{method}` is not allowed on `{path}`"),
    )
}

fn store_error(err: &FleetTransportError) -> FleetHttpResponse {
    match err {
        FleetTransportError::ActionConflict { .. } => FleetHttpResponse::problem(
            409,
            "conflict",
            "FLEET_HTTP_ACTION_CONFLICT",
            err.to_string(),
        ),
        FleetTransportError::StaleState { .. } => {
            FleetHttpResponse::problem(409, "conflict", "FLEET_HTTP_STALE_STATE", err.to_string())
        }
        FleetTransportError::LockContention { .. } => {
            FleetHttpResponse::problem(503, "busy", "FLEET_HTTP_STORE_BUSY", err.to_string())
        }
        FleetTransportError::SerializationError { .. } => {
            FleetHttpResponse::problem(422, "invalid", "FLEET_HTTP_INVALID_RECORD", err.to_string())
        }
        _ => FleetHttpResponse::problem(
            500,
            "store_error",
            "FLEET_HTTP_STORE_ERROR",
            err.to_string(),
        ),
    }
}

/// Listener configuration for [`serve_fleet_control_plane`].
#[derive(Debug, Clone)]
pub struct FleetHttpServerConfig {
    /// `ip:port` to listen on; port 0 picks a free port.
    pub bind: String,
    /// Stop after this many requests (scripted drills); `None` serves until
    /// shutdown is requested.
    pub max_requests: Option<u64>,
}

/// Why the coordinator could not start or keep serving.
#[derive(Debug, thiserror::Error)]
pub enum FleetHttpServerError {
    #[error("fleet control plane could not bind {bind}: {detail}")]
    Bind { bind: String, detail: String },
    #[error("fleet control plane runtime failed: {detail}")]
    Runtime { detail: String },
}

/// Shared counters/flags between the accept loop, the request handlers and
/// whoever asks the server to stop (a signal handler, a drill limit).
#[derive(Debug)]
pub struct FleetHttpServerControl {
    shutdown: Arc<AtomicBool>,
    requests_served: AtomicU64,
}

impl FleetHttpServerControl {
    /// Control block driven by an externally owned shutdown flag (for example
    /// one a SIGINT/SIGTERM handler sets).
    #[must_use]
    pub fn with_shutdown_flag(shutdown: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            shutdown,
            requests_served: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn new() -> Arc<Self> {
        Self::with_shutdown_flag(Arc::new(AtomicBool::new(false)))
    }

    /// Ask the server to stop accepting requests and return.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn requests_served(&self) -> u64 {
        self.requests_served.load(Ordering::SeqCst)
    }

    fn record_request(&self, max_requests: Option<u64>) {
        let served = self
            .requests_served
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        if max_requests.is_some_and(|limit| served >= limit) {
            self.request_shutdown();
        }
    }
}

/// Build the listening event (exposed for the CLI's human output).
#[must_use]
pub fn listening_event(bound: SocketAddr) -> FleetHttpEvent {
    FleetHttpEvent {
        bound_addr: Some(bound.to_string()),
        ..FleetHttpEvent::new(FLEET_HTTP_LISTENING)
    }
}

fn request_event(method: &str, path: &str, response: &FleetHttpResponse) -> FleetHttpEvent {
    FleetHttpEvent {
        method: Some(method.to_string()),
        path: Some(path.chars().take(256).collect()),
        status: Some(response.status),
        outcome: Some(response.outcome),
        ..FleetHttpEvent::new(FLEET_HTTP_REQUEST)
    }
}

fn shutdown_event(requests_served: u64) -> FleetHttpEvent {
    FleetHttpEvent {
        requests_served: Some(requests_served),
        ..FleetHttpEvent::new(FLEET_HTTP_SHUTDOWN)
    }
}

/// Callback that receives every structured server event.
pub type FleetHttpEventSink = Arc<dyn Fn(&FleetHttpEvent) + Send + Sync>;

/// Bind `config.bind`, then serve `service` until `control` asks for shutdown
/// (or `max_requests` is reached). The listening event carrying the actually
/// bound address is delivered to `on_event` before the first request is
/// accepted. Returns the number of requests served.
///
/// The listener is `fastapi_rust`'s `TcpServer` on an `asupersync` runtime;
/// each route is registered for exactly its method, so fastapi_rust answers
/// unknown paths with 404 and wrong methods with 405 itself.
///
/// # Errors
///
/// [`FleetHttpServerError::Bind`] when the address is not an `ip:port` or the
/// socket cannot be bound; [`FleetHttpServerError::Runtime`] when the runtime
/// cannot start or the accept loop fails.
pub fn serve_fleet_control_plane(
    service: Arc<FleetControlPlaneService>,
    config: &FleetHttpServerConfig,
    control: Arc<FleetHttpServerControl>,
    on_event: FleetHttpEventSink,
) -> Result<u64, FleetHttpServerError> {
    use asupersync::net::TcpListener;
    use asupersync::runtime::RuntimeBuilder;
    use fastapi_rust::http::ParseLimits;
    use fastapi_rust::{Cx, ServerConfig, ServerError, TcpServer};

    let bind: SocketAddr = config
        .bind
        .parse()
        .map_err(|err| FleetHttpServerError::Bind {
            bind: config.bind.clone(),
            detail: format!("expected ip:port ({err})"),
        })?;
    let server_config = ServerConfig::new(bind.to_string())
        .with_request_timeout_secs(30)
        .with_keep_alive_timeout_secs(5)
        .with_drain_timeout_secs(2)
        .with_parse_limits(ParseLimits {
            // Headers plus the largest body the service accepts; anything
            // bigger is cut off by the parser before a handler allocates it.
            max_request_size: MAX_GUARDED_POLICY_REQUEST_BYTES.saturating_add(16 * 1024),
            ..ParseLimits::default()
        });
    let server = Arc::new(TcpServer::new(server_config));
    let app = Arc::new(build_fleet_app(
        &service,
        &control,
        &on_event,
        &server,
        config.max_requests,
    ));

    // Construct every fallible runtime resource before starting the owned
    // shutdown watcher; failed runtime creation must not leave it running.
    let runtime =
        RuntimeBuilder::current_thread()
            .build()
            .map_err(|err| FleetHttpServerError::Runtime {
                detail: err.to_string(),
            })?;

    // Bridge the shutdown flag (set by a signal handler or the drill limit)
    // into the server's drain. The accept loop polls with a short timeout, so
    // it notices the drain promptly even while idle.
    let finished = Arc::new(AtomicBool::new(false));
    let watcher = {
        let server = Arc::clone(&server);
        let control = Arc::clone(&control);
        let finished = Arc::clone(&finished);
        std::thread::spawn(move || {
            while !finished.load(Ordering::SeqCst) {
                if control.shutdown_requested() {
                    server.shutdown();
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        })
    };

    let serve_sink = Arc::clone(&on_event);
    let outcome = runtime.block_on(async move {
        let cx = Cx::current().ok_or_else(|| FleetHttpServerError::Runtime {
            detail: "asupersync runtime did not install a request context".to_string(),
        })?;
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|err| FleetHttpServerError::Bind {
                bind: bind.to_string(),
                detail: err.to_string(),
            })?;
        let bound = listener
            .local_addr()
            .map_err(|err| FleetHttpServerError::Bind {
                bind: bind.to_string(),
                detail: err.to_string(),
            })?;
        serve_sink(&listening_event(bound));
        match server.serve_on_app_concurrent(&cx, listener, app).await {
            Ok(()) | Err(ServerError::Shutdown) => Ok(()),
            Err(err) => Err(FleetHttpServerError::Runtime {
                detail: err.to_string(),
            }),
        }
    });
    finished.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    outcome?;
    let served = control.requests_served();
    on_event(&shutdown_event(served));
    Ok(served)
}

fn build_fleet_app(
    service: &Arc<FleetControlPlaneService>,
    control: &Arc<FleetHttpServerControl>,
    on_event: &FleetHttpEventSink,
    server: &Arc<fastapi_rust::TcpServer>,
    max_requests: Option<u64>,
) -> fastapi_rust::App {
    use fastapi_rust::{App, Request, RequestContext, Response, ResponseBody, StatusCode};

    let route = |method: &'static str| {
        let service = Arc::clone(service);
        let control = Arc::clone(control);
        let on_event = Arc::clone(on_event);
        let server = Arc::clone(server);
        move |ctx: &RequestContext, request: &mut Request| {
            let path = request.path().to_string();
            let authorization = request
                .headers()
                .get("authorization")
                .and_then(|value| std::str::from_utf8(value).ok())
                .map(str::to_string);
            let body = request.take_body().into_bytes();
            let cx = ctx.cx().clone();
            let deadline = ctx.deadline();
            let service = Arc::clone(&service);
            let control = Arc::clone(&control);
            let on_event = Arc::clone(&on_event);
            let server = Arc::clone(&server);
            async move {
                let response = service
                    .handle_async(
                        &cx,
                        deadline,
                        FleetHttpRequest {
                            method,
                            path: &path,
                            authorization: authorization.as_deref(),
                            body: &body,
                        },
                    )
                    .await;
                on_event(&request_event(method, &path, &response));
                control.record_request(max_requests);
                if control.shutdown_requested() {
                    server.shutdown();
                }
                Response::with_status(StatusCode::from_u16(response.status))
                    .header("content-type", b"application/json".to_vec())
                    .header("cache-control", b"no-store".to_vec())
                    .body(ResponseBody::Bytes(response.body))
            }
        }
    };

    App::builder()
        .get(FLEET_HTTP_HEALTH_PATH, route("GET"))
        .get(FLEET_HTTP_ACTIONS_PATH, route("GET"))
        .post(FLEET_HTTP_ACTIONS_PATH, route("POST"))
        .post(FLEET_HTTP_GUARDED_POLICY_PATH, route("POST"))
        .post(FLEET_HTTP_GUARDED_RESUME_PATH, route("POST"))
        .post(FLEET_HTTP_EPOCH_BARRIER_PATH, route("POST"))
        .get(FLEET_HTTP_EPOCH_COMMIT_ROUTE, route("GET"))
        .get(FLEET_HTTP_NODES_PATH, route("GET"))
        .post(FLEET_HTTP_NODES_PATH, route("POST"))
        .get(FLEET_HTTP_STATE_PATH, route("GET"))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::fleet_transport::{
        FleetAction, FleetTargetKind, NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA,
        NativeSessionDrainAttestation, NativeSessionDrainCheckpoint, NodeHealth,
        fleet_application_checkpoint,
    };
    use ed25519_dalek::Signer as _;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
    const NODE_TOKEN: &str = "independent-node-token-0123456789abcdef0123456789abcdef";

    fn fixed_clock() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-06T12:00:00Z")
            .expect("fixed instant")
            .with_timezone(&Utc)
    }

    fn service() -> (tempfile::TempDir, FleetControlPlaneService) {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = FleetControlPlaneService::open(dir.path().join("fleet"), TOKEN)
            .expect("open service")
            .with_clock(fixed_clock);
        (dir, service)
    }

    fn service_with_one_waiter() -> (tempfile::TempDir, FleetControlPlaneService) {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = FleetControlPlaneService::open_with_store_limits(
            dir.path().join("fleet"),
            TOKEN,
            1,
            FLEET_STORE_REQUEST_TIMEOUT,
        )
        .expect("open bounded service")
        .with_clock(fixed_clock);
        (dir, service)
    }

    fn stall_store(service: &FleetControlPlaneService) -> (StoreRequest<()>, mpsc::Sender<()>) {
        let (entered, started) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let pending = service
            .enqueue_store(Instant::now() + FLEET_STORE_REQUEST_TIMEOUT, move |_, _| {
                entered.send(()).expect("announce active operation");
                proceed
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| FleetTransportError::io("test did not release store worker"))
            })
            .expect("admit blocking operation");
        started
            .recv_timeout(Duration::from_secs(5))
            .expect("worker reached controlled stall");
        (pending, release)
    }

    fn wait_response(pending: PendingFleetResponse) -> FleetHttpResponse {
        match pending {
            PendingFleetResponse::Ready(response) => response,
            PendingFleetResponse::Store(pending) => {
                pending.wait().unwrap_or_else(StoreRequestFailure::response)
            }
        }
    }

    fn response_code(response: &FleetHttpResponse) -> String {
        serde_json::from_slice::<serde_json::Value>(&response.body).expect("JSON response")["code"]
            .as_str()
            .expect("problem code")
            .to_owned()
    }

    #[test]
    fn bounded_store_overload_refuses_unaccepted_mutation_and_recovers() {
        let (_dir, service) = service_with_one_waiter();
        let (active, release) = stall_store(&service);
        let auth = bearer();
        let accepted = serde_json::to_vec(&quarantine_action("queued-action")).unwrap();
        let rejected = serde_json::to_vec(&quarantine_action("overloaded-action")).unwrap();
        let queued = service.dispatch_request(
            request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &accepted),
            Instant::now() + FLEET_STORE_REQUEST_TIMEOUT,
        );
        let overloaded = service.handle(request(
            "POST",
            FLEET_HTTP_ACTIONS_PATH,
            Some(&auth),
            &rejected,
        ));
        release.send(()).unwrap();
        active.wait().unwrap();
        let accepted = wait_response(queued);
        let actions = service.with_store(|store, _| store.list_actions()).unwrap();
        assert_eq!(overloaded.status, 503);
        assert_eq!(response_code(&overloaded), "FLEET_HTTP_STORE_QUEUE_FULL");
        assert_eq!(accepted.status, 201);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_id, "queued-action");
    }

    #[test]
    fn queued_store_deadline_cancels_mutation_before_worker_can_start() {
        let (_dir, service) = service();
        let (active, release) = stall_store(&service);
        let auth = bearer();
        let body = serde_json::to_vec(&quarantine_action("expired-action")).unwrap();
        let pending = service.dispatch_request(
            request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body),
            Instant::now() + Duration::from_millis(20),
        );
        let response = wait_response(pending);
        release.send(()).unwrap();
        active.wait().unwrap();
        let actions = service.with_store(|store, _| store.list_actions()).unwrap();
        assert_eq!(response.status, 504);
        assert_eq!(response_code(&response), "FLEET_HTTP_STORE_NOT_STARTED");
        assert!(actions.is_empty(), "expired work must never publish later");
    }

    #[test]
    fn dropped_queued_request_cancels_work_without_affecting_the_next_request() {
        let (_dir, service) = service();
        let (active, release) = stall_store(&service);
        let auth = bearer();
        let body = serde_json::to_vec(&quarantine_action("abandoned-action")).unwrap();
        let pending = service.dispatch_request(
            request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body),
            Instant::now() + FLEET_STORE_REQUEST_TIMEOUT,
        );
        drop(pending);
        release.send(()).unwrap();
        active.wait().unwrap();
        let actions = service.with_store(|store, _| store.list_actions()).unwrap();
        assert!(
            actions.is_empty(),
            "abandoned HTTP future must cancel queued work"
        );
        let response = service.handle(request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body));
        assert_eq!(
            response.status, 201,
            "cancellation must not poison the worker"
        );
    }

    #[test]
    fn started_store_timeout_reports_unknown_outcome_and_retains_commit() {
        let (_dir, service) = service_with_one_waiter();
        let (entered, started) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let mut pending = service
            .enqueue_store(
                Instant::now() + FLEET_STORE_REQUEST_TIMEOUT,
                move |store, _| {
                    entered.send(()).unwrap();
                    proceed.recv_timeout(Duration::from_secs(5)).unwrap();
                    store.publish_action(&quarantine_action("started-action"))
                },
            )
            .unwrap();
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        // Advance the observer's deadline only after the worker's start has
        // been observed, independent of CI scheduling speed.
        pending.deadline = Instant::now();
        let outcome = pending.wait();
        release.send(()).unwrap();
        let actions = service.with_store(|store, _| store.list_actions()).unwrap();
        assert!(matches!(outcome, Err(StoreRequestFailure::OutcomeUnknown)));
        assert_eq!(actions.len(), 1, "a timeout cannot undo a started commit");
        assert_eq!(actions[0].action_id, "started-action");
        assert_eq!(
            response_code(&StoreRequestFailure::OutcomeUnknown.response()),
            "FLEET_HTTP_STORE_OUTCOME_UNKNOWN"
        );
    }

    #[test]
    fn store_reply_completion_wins_timeout_and_worker_loss_is_not_an_abort() {
        let (_dir, service) = service();
        let complete = service
            .enqueue_store(Instant::now() + FLEET_STORE_REQUEST_TIMEOUT, |_, _| Ok(7))
            .unwrap();
        // The following serialized operation proves that the first result is
        // available before simulating an observer that reaches its deadline.
        service.with_store(|_, _| Ok(())).unwrap();
        let mut complete = complete;
        complete.deadline = Instant::now();
        assert_eq!(complete.wait().unwrap(), 7);

        for started in [false, true] {
            let completion = Arc::new(StoreCompletion {
                execution: Mutex::new(if started {
                    StoreExecution::<()>::Running
                } else {
                    StoreExecution::Queued
                }),
                ready: Condvar::new(),
            });
            let (notification, receiver) = asupersync::channel::oneshot::channel();
            let reply = StoreReply {
                completion: Arc::clone(&completion),
                notification: Some(notification),
            };
            let pending = StoreRequest {
                completion,
                notification: receiver,
                deadline: Instant::now() + FLEET_STORE_REQUEST_TIMEOUT,
            };
            drop(reply);
            let outcome = pending.wait();
            if started {
                assert!(matches!(outcome, Err(StoreRequestFailure::OutcomeUnknown)));
            } else {
                assert!(matches!(
                    outcome,
                    Err(StoreRequestFailure::StoppedBeforeStart)
                ));
            }
        }
    }

    #[test]
    fn async_store_wait_yields_reactor_and_drop_prevents_late_mutation() {
        use std::future::Future as _;
        use std::task::{Context, Poll, Waker};

        let (_dir, service) = service();
        let (active, release) = stall_store(&service);
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        let auth = bearer();
        let body = serde_json::to_vec(&quarantine_action("cancelled-async-action")).unwrap();
        let health = runtime.block_on(async {
            let cx = asupersync::Cx::current().expect("request runtime context");
            let pending = service.handle_async(
                &cx,
                None,
                request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body),
            );
            let mut pending = std::pin::pin!(pending);
            let mut task = Context::from_waker(Waker::noop());
            assert!(matches!(pending.as_mut().poll(&mut task), Poll::Pending));
            // This executes on the same current-thread runtime while its
            // database worker is blocked by a different request.
            service
                .handle_async(&cx, None, request("GET", FLEET_HTTP_HEALTH_PATH, None, &[]))
                .await
        });
        release.send(()).unwrap();
        active.wait().unwrap();
        let actions = service.with_store(|store, _| store.list_actions()).unwrap();
        assert_eq!(health.status, 200);
        assert!(actions.is_empty());
    }

    #[test]
    fn expired_http_deadline_never_enqueues_a_store_mutation() {
        let (_dir, service) = service();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        let auth = bearer();
        let body = serde_json::to_vec(&quarantine_action("expired-http-action")).unwrap();
        let response = runtime.block_on(async {
            let cx = asupersync::Cx::current().unwrap();
            service
                .handle_async(
                    &cx,
                    Some(cx.now()),
                    request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body),
                )
                .await
        });
        assert_eq!(response.status, 504);
        assert_eq!(response_code(&response), "FLEET_HTTP_STORE_NOT_STARTED");
        assert!(
            service
                .with_store(|store, _| store.list_actions())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn async_store_deadline_wakes_without_a_store_reply() {
        let (_dir, service) = service();
        let (active, release) = stall_store(&service);
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        let auth = bearer();
        let body = serde_json::to_vec(&quarantine_action("async-expired-action")).unwrap();
        let response = runtime.block_on(async {
            let cx = asupersync::Cx::current().unwrap();
            let PendingFleetResponse::Store(mut pending) = service.dispatch_request(
                request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body),
                Instant::now() + FLEET_STORE_REQUEST_TIMEOUT,
            ) else {
                panic!("request must be queued behind the blocked worker");
            };
            pending.deadline = Instant::now() + Duration::from_millis(20);
            pending
                .wait_async(&cx)
                .await
                .unwrap_or_else(StoreRequestFailure::response)
        });
        release.send(()).unwrap();
        active.wait().unwrap();
        let actions = service.with_store(|store, _| store.list_actions()).unwrap();
        assert_eq!(response.status, 504);
        assert_eq!(response_code(&response), "FLEET_HTTP_STORE_NOT_STARTED");
        assert!(actions.is_empty());
    }

    #[test]
    fn worker_observes_request_cancellation_before_waiter_is_repolled() {
        let (_dir, service) = service();
        let (active, release) = stall_store(&service);
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        let auth = bearer();
        let body = serde_json::to_vec(&quarantine_action("cancelled-context-action")).unwrap();
        let (response, actions) = runtime.block_on(async {
            let cx = asupersync::Cx::current().unwrap();
            let pending = service.dispatch_request(
                request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body),
                StoreRequestBudget {
                    deadline: Instant::now() + FLEET_STORE_REQUEST_TIMEOUT,
                    request_context: Some((cx.clone(), None)),
                },
            );
            cx.set_cancel_requested(true);
            release.send(()).unwrap();
            active.wait().unwrap();
            // The serialized read runs after the queued job's start decision.
            // Its waiter has never been polled or dropped since cancellation.
            let actions = service.with_store(|store, _| store.list_actions()).unwrap();
            (wait_response(pending), actions)
        });
        assert_eq!(response.status, 504);
        assert_eq!(response_code(&response), "FLEET_HTTP_STORE_NOT_STARTED");
        assert!(actions.is_empty());
    }

    fn bearer() -> String {
        format!("Bearer {TOKEN}")
    }

    fn request<'a>(
        method: &'a str,
        path: &'a str,
        authorization: Option<&'a str>,
        body: &'a [u8],
    ) -> FleetHttpRequest<'a> {
        FleetHttpRequest {
            method,
            path,
            authorization,
            body,
        }
    }

    fn quarantine_action(action_id: &str) -> FleetActionRecord {
        FleetActionRecord {
            action_id: action_id.to_string(),
            emitted_at: fixed_clock(),
            action: FleetAction::Quarantine {
                zone_id: "zone-a".to_string(),
                incident_id: "inc-1".to_string(),
                target_id: "npm:left-pad".to_string(),
                target_kind: FleetTargetKind::Extension,
                reason: "drill".to_string(),
                quarantine_version: 3,
            },
        }
    }

    fn heartbeat(node_id: &str) -> NodeStatus {
        NodeStatus {
            zone_id: "zone-a".to_string(),
            node_id: node_id.to_string(),
            last_seen: DateTime::parse_from_rfc3339("1999-01-01T00:00:00Z")
                .expect("old instant")
                .with_timezone(&Utc),
            quarantine_version: 3,
            health: NodeHealth::Healthy,
            applied_actions: None,
            native_session_drain: None,
        }
    }

    fn supervisor_enrollment(root: &ed25519_dalek::SigningKey) -> FleetNodeCredentials {
        FleetNodeCredentials::from_json(
            &serde_json::to_vec(&serde_json::json!({
                "schema_version": FLEET_NODE_CREDENTIALS_SCHEMA,
                "nodes": [{
                    "zone_id": "zone-a", "node_id": "node-a",
                    "token_sha256": hex::encode(Sha256::digest(NODE_TOKEN.as_bytes())),
                    "supervisor_public_key_hex": hex::encode(root.verifying_key().as_bytes())
                }]
            }))
            .unwrap(),
        )
        .expect("independently enrolled supervisor")
    }

    fn signed_maintenance(
        root: &ed25519_dalek::SigningKey,
        observed_at: DateTime<Utc>,
    ) -> NodeStatus {
        let action = FleetActionRecord {
            action_id: "supervisor-maintenance".into(),
            emitted_at: fixed_clock(),
            action: FleetAction::NativeSessionHold {
                zone_id: "zone-a".into(),
                reason: "verified supervisor maintenance".into(),
            },
        };
        let checkpoint = fleet_application_checkpoint(&[action], "zone-a").unwrap();
        let mut drain = NativeSessionDrainCheckpoint {
            applied_actions: checkpoint.clone(),
            session_set_sha256: hex::encode(Sha256::digest(b"retained-two-session-population")),
            admitted_sessions: 2,
            terminal_sessions: 2,
            pending_sessions: 0,
            indeterminate_sessions: 0,
            fence_held: true,
            supervisor_attestation: None,
        };
        let mut attestation = NativeSessionDrainAttestation {
            schema_version: NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA.into(),
            node_id: "node-a".into(),
            zone_id: "zone-a".into(),
            drain_id: "01900000-0000-7000-8000-000000000001".into(),
            generation: 2,
            project_root_sha256: hex::encode(Sha256::digest(b"private-project-root")),
            observed_at,
            product_root_key_id: format!(
                "ed25519:{}",
                hex::encode(root.verifying_key().as_bytes())
            ),
            checkpoint_sha256: drain.observation_sha256().unwrap(),
            signature_hex: String::new(),
        };
        attestation.signature_hex = hex::encode(
            root.sign(&attestation.signing_payload().unwrap())
                .to_bytes(),
        );
        drain.supervisor_attestation = Some(attestation);
        let mut status = heartbeat("node-a");
        status.health = NodeHealth::Maintenance;
        status.applied_actions = Some(checkpoint);
        status.native_session_drain = Some(drain);
        status
    }

    fn resign_observation(status: &mut NodeStatus, root: &ed25519_dalek::SigningKey) {
        let drain = status.native_session_drain.as_mut().unwrap();
        let digest = drain.observation_sha256().unwrap();
        let attestation = drain.supervisor_attestation.as_mut().unwrap();
        attestation.checkpoint_sha256 = digest;
        attestation.signature_hex = hex::encode(
            root.sign(&attestation.signing_payload().unwrap())
                .to_bytes(),
        );
    }

    fn epoch_barrier_response(
        service: &FleetControlPlaneService,
        trace: &str,
    ) -> FleetHttpResponse {
        service.handle(request(
            "POST",
            FLEET_HTTP_EPOCH_BARRIER_PATH,
            Some(&bearer()),
            &serde_json::to_vec(&FleetHttpEpochBarrierRequest {
                operation_id: None,
                expected_action_log: None,
                initiator: "operator".to_string(),
                reason: "held-population epoch transition".to_string(),
                trace_id: trace.to_string(),
                stale_after: std::time::Duration::from_secs(30),
            })
            .unwrap(),
        ))
    }

    fn service_with_committed_epoch(
        root: &ed25519_dalek::SigningKey,
    ) -> (tempfile::TempDir, FleetControlPlaneService) {
        service_with_epoch_signer(root, None)
    }

    fn coordinator_signer() -> FleetEpochCommitSigner {
        FleetEpochCommitSigner::new(
            "coordinator-test",
            ed25519_dalek::SigningKey::from_bytes(&[43; 32]),
        )
        .unwrap()
    }

    fn service_with_epoch_signer(
        root: &ed25519_dalek::SigningKey,
        signer: Option<FleetEpochCommitSigner>,
    ) -> (tempfile::TempDir, FleetControlPlaneService) {
        let (dir, service) = service_with_held_population(root, signer);
        let response = epoch_barrier_response(&service, "trace-first-epoch");
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let response: FleetHttpEpochBarrierResponse =
            serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response.certificate.pre_epoch, 0);
        assert_eq!(response.certificate.committed_epoch, 1);
        (dir, service)
    }

    fn service_with_held_population(
        root: &ed25519_dalek::SigningKey,
        signer: Option<FleetEpochCommitSigner>,
    ) -> (tempfile::TempDir, FleetControlPlaneService) {
        let (dir, service) = service();
        let service = service
            .with_node_credentials(supervisor_enrollment(root))
            .unwrap();
        let service = if let Some(signer) = signer {
            service.with_epoch_commit_signer(signer).unwrap()
        } else {
            service
        };
        let hold = FleetActionRecord {
            action_id: "supervisor-maintenance".into(),
            emitted_at: fixed_clock(),
            action: FleetAction::NativeSessionHold {
                zone_id: "zone-a".into(),
                reason: "verified supervisor maintenance".into(),
            },
        };
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_ACTIONS_PATH,
                    Some(&bearer()),
                    &serde_json::to_vec(&hold).unwrap(),
                ))
                .status,
            201
        );
        let auth = format!("Bearer {NODE_TOKEN}");
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_NODES_PATH,
                    Some(&auth),
                    &serde_json::to_vec(&signed_maintenance(root, fixed_clock())).unwrap(),
                ))
                .status,
            200
        );
        (dir, service)
    }

    fn export_epoch(service: &FleetControlPlaneService, epoch: u64) -> FleetHttpResponse {
        service.handle(request(
            "GET",
            &format!("{FLEET_HTTP_EPOCH_COMMITS_PREFIX}{epoch}"),
            Some(&bearer()),
            b"",
        ))
    }

    fn retryable_epoch_request(
        service: &FleetControlPlaneService,
        operation_id: &str,
    ) -> FleetHttpEpochBarrierRequest {
        let response = service.handle(request("GET", FLEET_HTTP_STATE_PATH, Some(&bearer()), b""));
        assert_eq!(response.status, 200);
        let state: FleetHttpState = serde_json::from_slice(&response.body).unwrap();
        FleetHttpEpochBarrierRequest {
            operation_id: Some(operation_id.to_owned()),
            expected_action_log: Some(
                super::super::fleet_transport::fleet_action_log_checkpoint(&state.state.actions)
                    .unwrap(),
            ),
            initiator: "epoch-operation-test".to_owned(),
            reason: "certify the retained held population".to_owned(),
            trace_id: format!("trace-{operation_id}"),
            stale_after: std::time::Duration::from_secs(30),
        }
    }

    fn post_epoch_operation(
        service: &FleetControlPlaneService,
        operation: &FleetHttpEpochBarrierRequest,
    ) -> FleetHttpResponse {
        service.handle(request(
            "POST",
            FLEET_HTTP_EPOCH_BARRIER_PATH,
            Some(&bearer()),
            &serde_json::to_vec(operation).unwrap(),
        ))
    }

    #[test]
    fn epoch_operation_retry_recovers_signed_history_without_regressing_the_live_cache() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (dir, service) = service_with_held_population(&root, Some(coordinator_signer()));
        let first_request = retryable_epoch_request(&service, "operation-one");
        let first = post_epoch_operation(&service, &first_request);
        assert_eq!(
            first.status,
            200,
            "{}",
            String::from_utf8_lossy(&first.body)
        );
        let first: FleetHttpEpochBarrierResponse = serde_json::from_slice(&first.body).unwrap();
        assert!(!first.already_committed);
        assert_eq!(first.certificate.committed_epoch, 1);
        assert_eq!(
            first.certificate.operation_id.as_deref(),
            Some("operation-one")
        );
        assert!(first.commit_proof.is_some());

        let second_request = retryable_epoch_request(&service, "operation-two");
        let second = post_epoch_operation(&service, &second_request);
        assert_eq!(
            second.status,
            200,
            "{}",
            String::from_utf8_lossy(&second.body)
        );
        let second: FleetHttpEpochBarrierResponse = serde_json::from_slice(&second.body).unwrap();
        assert_eq!(second.certificate.committed_epoch, 2);
        let live_cache = service.seqlock_page().read_safepoint();

        let retry = post_epoch_operation(&service, &first_request);
        assert_eq!(retry.status, 200);
        let retry: FleetHttpEpochBarrierResponse = serde_json::from_slice(&retry.body).unwrap();
        assert!(retry.already_committed);
        assert_eq!(retry.evidence, first.evidence);
        assert_eq!(retry.certificate, first.certificate);
        assert_eq!(retry.commit_proof, first.commit_proof);
        assert_eq!(service.seqlock_page().read_safepoint(), live_cache);
        drop(service);

        let service = FleetControlPlaneService::open(dir.path().join("fleet"), TOKEN)
            .unwrap()
            .with_clock(fixed_clock)
            .with_node_credentials(supervisor_enrollment(&root))
            .unwrap()
            .with_epoch_commit_signer(coordinator_signer())
            .unwrap();
        let recovered_cache = service.seqlock_page().read_safepoint();
        assert_eq!(recovered_cache.control_epoch, 2);
        let recovered = post_epoch_operation(&service, &first_request);
        assert_eq!(
            recovered.status,
            200,
            "{}",
            String::from_utf8_lossy(&recovered.body)
        );
        let recovered: FleetHttpEpochBarrierResponse =
            serde_json::from_slice(&recovered.body).unwrap();
        assert!(recovered.already_committed);
        assert_eq!(recovered.evidence, first.evidence);
        assert_eq!(recovered.certificate, first.certificate);
        assert_eq!(recovered.commit_proof, first.commit_proof);
        assert_eq!(service.seqlock_page().read_safepoint(), recovered_cache);
        let new_request = retryable_epoch_request(&service, "operation-three");
        assert_eq!(
            post_epoch_operation(&service, &new_request).status,
            409,
            "recovery must not reauthenticate nodes or certify a new population"
        );
        assert_eq!(service.seqlock_page().read_safepoint(), recovered_cache);
    }

    #[test]
    fn epoch_operation_id_binds_original_intent_before_freshness_clamping() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (_dir, service) = service_with_held_population(&root, Some(coordinator_signer()));
        let mut original = retryable_epoch_request(&service, "exact-epoch-intent");
        original.stale_after = std::time::Duration::from_secs(301);
        let first = post_epoch_operation(&service, &original);
        assert_eq!(first.status, 200);
        let first: FleetHttpEpochBarrierResponse = serde_json::from_slice(&first.body).unwrap();
        assert_eq!(first.evidence.stale_after, MAX_GUARDED_POLICY_STALE_AFTER);
        let cache = service.seqlock_page().read_safepoint();
        for field in 0..6 {
            let mut changed = original.clone();
            match field {
                0 => changed.initiator.push_str("-other"),
                1 => changed.reason.push_str("-other"),
                2 => changed.trace_id.push_str("-other"),
                3 => changed.stale_after = std::time::Duration::from_secs(302),
                4 => changed.expected_action_log = None,
                _ => {
                    changed.expected_action_log.as_mut().unwrap().actions_sha256 = "00".repeat(32);
                }
            }
            let refused = post_epoch_operation(&service, &changed);
            assert_eq!(
                refused.status,
                409,
                "changed field {field}: {}",
                String::from_utf8_lossy(&refused.body)
            );
            assert_eq!(service.seqlock_page().read_safepoint(), cache);
        }
        let retry = post_epoch_operation(&service, &original);
        assert_eq!(retry.status, 200);
        let retry: FleetHttpEpochBarrierResponse = serde_json::from_slice(&retry.body).unwrap();
        assert!(retry.already_committed);
        assert_eq!(retry.certificate, first.certificate);
        assert_eq!(export_epoch(&service, 2).status, 409);
    }

    #[test]
    fn epoch_operation_requires_signing_authority_and_the_expected_first_snapshot() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (_dir, service) = service_with_held_population(&root, None);
        let original = retryable_epoch_request(&service, "guarded-epoch-start");
        assert_eq!(post_epoch_operation(&service, &original).status, 409);
        assert_eq!(service.seqlock_page().read_safepoint().control_epoch, 0);
        let service = service
            .with_epoch_commit_signer(coordinator_signer())
            .unwrap();
        let mut wrong_snapshot = original.clone();
        wrong_snapshot
            .expected_action_log
            .as_mut()
            .unwrap()
            .actions_sha256 = "00".repeat(32);
        assert_eq!(post_epoch_operation(&service, &wrong_snapshot).status, 409);
        assert_eq!(export_epoch(&service, 1).status, 409);
        let mut bad_id = original.clone();
        bad_id.operation_id = Some("../outside".to_owned());
        assert_eq!(post_epoch_operation(&service, &bad_id).status, 400);
        assert_eq!(export_epoch(&service, 1).status, 409);

        let accepted = post_epoch_operation(&service, &original);
        assert_eq!(
            accepted.status,
            200,
            "{}",
            String::from_utf8_lossy(&accepted.body)
        );
        let accepted: FleetHttpEpochBarrierResponse =
            serde_json::from_slice(&accepted.body).unwrap();
        assert_eq!(accepted.certificate.committed_epoch, 1);
    }

    #[test]
    fn epoch_operation_recovers_after_a_committed_cache_publication_failure() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (dir, service) = service_with_held_population(&root, Some(coordinator_signer()));
        let operation = retryable_epoch_request(&service, "cache-failure-epoch");
        std::fs::create_dir(dir.path().join("fleet/seqlock.page")).unwrap();
        let failed = post_epoch_operation(&service, &operation);
        assert_eq!(failed.status, 500);
        assert!(String::from_utf8_lossy(&failed.body).contains("committed durably"));

        let recovered = post_epoch_operation(&service, &operation);
        assert_eq!(
            recovered.status,
            200,
            "{}",
            String::from_utf8_lossy(&recovered.body)
        );
        let recovered: FleetHttpEpochBarrierResponse =
            serde_json::from_slice(&recovered.body).unwrap();
        assert!(recovered.already_committed);
        assert_eq!(recovered.certificate.committed_epoch, 1);
        assert!(recovered.commit_proof.is_some());
        assert_eq!(export_epoch(&service, 2).status, 409);
        assert_eq!(service.seqlock_page().read_safepoint().control_epoch, 1);
    }

    #[test]
    fn epoch_commit_export_survives_restart_without_renewing_node_authority() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (dir, service) = service_with_epoch_signer(&root, Some(coordinator_signer()));
        let exported = export_epoch(&service, 1);
        assert_eq!(
            exported.status,
            200,
            "{}",
            String::from_utf8_lossy(&exported.body)
        );
        let response: FleetHttpEpochBarrierResponse =
            serde_json::from_slice(&exported.body).unwrap();
        assert_eq!(
            response.schema_version,
            FLEET_HTTP_EPOCH_COMMIT_RESPONSE_SCHEMA
        );
        response
            .commit_proof
            .as_ref()
            .unwrap()
            .verify_with_coordinator(
                &response.evidence,
                &response.certificate,
                "coordinator-test",
                &coordinator_signer().verifying_key(),
            )
            .unwrap();
        let before = service.seqlock_page().read_safepoint();
        assert_eq!(export_epoch(&service, 1).body, exported.body);
        assert_eq!(service.seqlock_page().read_safepoint(), before);
        drop(service);

        let service = FleetControlPlaneService::open(dir.path().join("fleet"), TOKEN)
            .unwrap()
            .with_clock(fixed_clock)
            .with_node_credentials(supervisor_enrollment(&root))
            .unwrap()
            .with_epoch_commit_signer(coordinator_signer())
            .unwrap();
        assert_eq!(export_epoch(&service, 1).body, exported.body);
        assert_eq!(
            epoch_barrier_response(&service, "trace-unrefreshed-after-export").status,
            409,
            "historical export must not reauthenticate retained supervisor observations"
        );
        assert_eq!(service.seqlock_page().read_safepoint().control_epoch, 1);
        assert_eq!(export_epoch(&service, 2).status, 409);
    }

    #[test]
    fn epoch_commit_export_recovers_after_post_commit_cache_failure() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (dir, service) = service_with_held_population(&root, Some(coordinator_signer()));
        std::fs::create_dir(dir.path().join("fleet/seqlock.page")).unwrap();
        let failed = epoch_barrier_response(&service, "trace-cache-publication-failed");
        assert_eq!(
            failed.status,
            500,
            "{}",
            String::from_utf8_lossy(&failed.body)
        );
        assert!(String::from_utf8_lossy(&failed.body).contains("committed durably"));
        let first = export_epoch(&service, 1);
        assert_eq!(
            first.status,
            200,
            "{}",
            String::from_utf8_lossy(&first.body)
        );
        assert_eq!(export_epoch(&service, 1).body, first.body);
        assert_eq!(export_epoch(&service, 2).status, 409);
        assert_eq!(service.seqlock_page().read_safepoint().control_epoch, 1);
    }

    #[test]
    fn epoch_commit_legacy_history_cannot_gain_public_authority_retroactively() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (_dir, service) = service_with_committed_epoch(&root);
        assert_eq!(export_epoch(&service, 1).status, 409);
        let service = service
            .with_epoch_commit_signer(coordinator_signer())
            .unwrap();
        let legacy = export_epoch(&service, 1);
        assert_eq!(legacy.status, 409);
        assert!(String::from_utf8_lossy(&legacy.body).contains("HMAC-only"));
        let second = epoch_barrier_response(&service, "trace-new-signed-epoch");
        assert_eq!(
            second.status,
            200,
            "{}",
            String::from_utf8_lossy(&second.body)
        );
        let second: FleetHttpEpochBarrierResponse = serde_json::from_slice(&second.body).unwrap();
        assert_eq!(second.certificate.committed_epoch, 2);
        assert!(second.commit_proof.is_some());
        assert_eq!(export_epoch(&service, 2).status, 200);
        assert_eq!(export_epoch(&service, 1).status, 409);
    }

    #[test]
    fn epoch_commit_signed_head_rejects_missing_or_foreign_coordinator_signer() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (dir, service) = service_with_epoch_signer(&root, Some(coordinator_signer()));
        drop(service);
        let state_dir = dir.path().join("fleet");
        for (identity, seed) in [("other-coordinator", 43), ("coordinator-test", 44)] {
            let service = FleetControlPlaneService::open(state_dir.clone(), TOKEN).unwrap();
            let signer = FleetEpochCommitSigner::new(
                identity,
                ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            )
            .unwrap();
            assert!(service.with_epoch_commit_signer(signer).is_err());
        }
        let service = FleetControlPlaneService::open(state_dir, TOKEN)
            .unwrap()
            .with_clock(fixed_clock)
            .with_node_credentials(supervisor_enrollment(&root))
            .unwrap();
        let auth = format!("Bearer {NODE_TOKEN}");
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_NODES_PATH,
                    Some(&auth),
                    &serde_json::to_vec(&signed_maintenance(&root, fixed_clock())).unwrap()
                ))
                .status,
            200
        );
        let refused = epoch_barrier_response(&service, "trace-key-downgrade");
        assert_eq!(refused.status, 409);
        assert!(String::from_utf8_lossy(&refused.body).contains("signing key"));
        assert_eq!(service.seqlock_page().read_safepoint().control_epoch, 1);
        assert_eq!(export_epoch(&service, 1).status, 409);
    }

    #[test]
    fn epoch_commit_export_requires_operator_and_canonical_retained_epoch() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (_dir, service) = service_with_epoch_signer(&root, Some(coordinator_signer()));
        let path = format!("{FLEET_HTTP_EPOCH_COMMITS_PREFIX}1");
        assert_eq!(service.handle(request("GET", &path, None, b"")).status, 401);
        assert_eq!(
            service
                .handle(request(
                    "GET",
                    &path,
                    Some(&format!("Bearer {NODE_TOKEN}")),
                    b""
                ))
                .status,
            403
        );
        for encoded in ["0", "01", "+1", "-1", "18446744073709551616", "1/extra"] {
            let path = format!("{FLEET_HTTP_EPOCH_COMMITS_PREFIX}{encoded}");
            assert_eq!(
                service
                    .handle(request("GET", &path, Some(&bearer()), b""))
                    .status,
                400,
                "{encoded}"
            );
        }
        assert_eq!(export_epoch(&service, 2).status, 409);
        assert_eq!(export_epoch(&service, 1).status, 200);
    }

    #[test]
    fn epoch_commit_operator_hmac_cannot_rebind_retained_public_authorization() {
        use crate::control_plane::control_epoch::{EpochStore, EpochTransition};
        use crate::control_plane::fleet_transport::{
            FleetEpochQuiescenceCertificate, FleetNativeDrainEvidence,
            fleet_epoch_quiescence_manifest_hash,
        };
        use fsqlite::compat::TransactionExt as _;

        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (dir, service) = service_with_epoch_signer(&root, Some(coordinator_signer()));
        drop(service);
        let state_dir = dir.path().join("fleet");
        {
            let connection = fsqlite::Connection::open(
                state_dir.join("fleet-state.db").to_string_lossy().as_ref(),
            )
            .unwrap();
            for pragma in [
                "PRAGMA journal_mode=WAL;",
                "PRAGMA synchronous=FULL;",
                "PRAGMA busy_timeout=5000;",
            ] {
                connection.query(pragma).unwrap();
            }
            let mut tx = connection.transaction().unwrap();
            let rows = tx
                .query("SELECT commit_json FROM fleet_epoch_commits WHERE epoch = '1';")
                .unwrap();
            let fsqlite::SqliteValue::Text(raw) = &rows[0].values()[0] else {
                panic!("commit JSON text");
            };
            assert!(
                !raw.contains("commit_signature_hex"),
                "write transactions retain authorization, never a premature commit signature"
            );
            let mut commit: serde_json::Value = serde_json::from_str(raw.as_ref()).unwrap();
            assert!(commit["coordinator_authorization"].is_object());
            let evidence: FleetNativeDrainEvidence =
                serde_json::from_value(commit["evidence"].clone()).unwrap();
            let mut certificate: FleetEpochQuiescenceCertificate =
                serde_json::from_value(commit["certificate"].clone()).unwrap();
            certificate.reason = "forged using the operator's known HMAC key".to_owned();
            let old: EpochTransition =
                serde_json::from_value(commit["transition"].clone()).unwrap();
            let material = Sha256::digest(format!("fleet-epoch-signing:{TOKEN}").as_bytes());
            let key = EpochSigningKey::new(material.as_slice()).unwrap();
            let mut forged_store = EpochStore::recover(certificate.pre_epoch, key.clone());
            let forged = forged_store
                .epoch_advance(
                    &fleet_epoch_quiescence_manifest_hash(&evidence, &certificate).unwrap(),
                    old.timestamp,
                    &certificate.trace_id,
                )
                .unwrap();
            assert!(
                forged.verify(&key),
                "attack must retain a valid operator HMAC"
            );
            commit["certificate"] = serde_json::to_value(certificate).unwrap();
            commit["transition"] = serde_json::to_value(forged).unwrap();
            tx.execute_with_params(
                "UPDATE fleet_epoch_commits SET commit_json = ?1 WHERE epoch = '1';",
                &[fsqlite::SqliteValue::Text(
                    serde_json::to_string(&commit).unwrap().into(),
                )],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let error = FleetControlPlaneService::open(state_dir, TOKEN).expect_err(
            "valid HMAC cannot replace the coordinator's independent live authorization",
        );
        assert!(error.to_string().contains("statement"), "{error}");
    }

    /// The SDK is an independent crate already used by the product. Verify the
    /// actual serialized durable response through its separate implementation,
    /// with no producer proof helpers or candidate-supplied enrollment.
    #[test]
    fn epoch_commit_durable_response_passes_standalone_verifier() {
        use crate::control_plane::fleet_transport::fleet_action_log_checkpoint;
        use frankenengine_verifier_sdk::fleet_quiescence::{
            FleetCoordinatorTrust, parse_fleet_quiescence_policy, verify_fleet_epoch_commit,
        };

        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (_dir, service) = service_with_epoch_signer(&root, Some(coordinator_signer()));
        let exported = export_epoch(&service, 1);
        assert_eq!(exported.status, 200);

        // Construct enrollment and action expectations from the trusted test
        // setup, independently of every field in the exported candidate.
        let hold = FleetActionRecord {
            action_id: "supervisor-maintenance".into(),
            emitted_at: fixed_clock(),
            action: FleetAction::NativeSessionHold {
                zone_id: "zone-a".into(),
                reason: "verified supervisor maintenance".into(),
            },
        };
        let actions = [hold];
        let policy = serde_json::json!({
            "schema_version": "franken-verifier/fleet-quiescence-policy/v1",
            "evaluation_time": (fixed_clock() + chrono::Duration::seconds(1))
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            "max_observation_age_secs": 30,
            "expected_action_log": fleet_action_log_checkpoint(&actions).unwrap(),
            "expected_pre_epoch": 0,
            "expected_trace_id": "trace-first-epoch",
            "participants": [{
                "zone_id": "zone-a", "node_id": "node-a",
                "supervisor_public_key_hex": hex::encode(root.verifying_key().as_bytes()),
                "project_root_sha256": hex::encode(Sha256::digest(b"private-project-root")),
                "minimum_generation": 2,
                "expected_applied_actions": fleet_application_checkpoint(&actions, "zone-a").unwrap(),
                "expected_active_hold_ids": ["supervisor-maintenance"]
            }]
        });
        let policy = parse_fleet_quiescence_policy(&serde_json::to_vec(&policy).unwrap()).unwrap();
        let trust = FleetCoordinatorTrust {
            coordinator_id: "coordinator-test".into(),
            coordinator_public_key_hex: hex::encode(
                coordinator_signer().verifying_key().as_bytes(),
            ),
        };
        let facts = verify_fleet_epoch_commit(&exported.body, &policy, &trust).unwrap();
        assert!(facts.epoch_commit_authenticated);
        assert!(!facts.current_quiescence_proven);
        assert_eq!(facts.committed_epoch, 1);
        assert_eq!(facts.participant_count, 1);
        assert_eq!(facts.terminal_sessions, 2);

        let foreign = FleetCoordinatorTrust {
            coordinator_public_key_hex: hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[44; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
            ..trust.clone()
        };
        assert!(verify_fleet_epoch_commit(&exported.body, &policy, &foreign).is_err());
        let mut tampered: serde_json::Value = serde_json::from_slice(&exported.body).unwrap();
        tampered["certificate"]["reason"] = "substituted after durable commit".into();
        assert!(
            verify_fleet_epoch_commit(&serde_json::to_vec(&tampered).unwrap(), &policy, &trust)
                .is_err()
        );
    }

    #[test]
    fn fleet_epoch_recovery_is_monotonic_and_requires_fresh_enrolled_nodes() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let (dir, service) = service_with_committed_epoch(&root);
        drop(service);
        let service = FleetControlPlaneService::open(dir.path().join("fleet"), TOKEN)
            .unwrap()
            .with_clock(fixed_clock)
            .with_node_credentials(supervisor_enrollment(&root))
            .unwrap();
        assert_eq!(
            epoch_barrier_response(&service, "trace-missing-after-restart").status,
            409,
            "recovered signed history cannot replace a fresh enrolled heartbeat"
        );
        let auth = format!("Bearer {NODE_TOKEN}");
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_NODES_PATH,
                    Some(&auth),
                    &serde_json::to_vec(&signed_maintenance(&root, fixed_clock())).unwrap(),
                ))
                .status,
            200
        );
        let response = epoch_barrier_response(&service, "trace-second-epoch");
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let response: FleetHttpEpochBarrierResponse =
            serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response.certificate.pre_epoch, 1);
        assert_eq!(response.certificate.committed_epoch, 2);
        assert_eq!(
            SeqlockControlPage::read_shared_page(&dir.path().join("fleet/seqlock.page"))
                .unwrap()
                .control_epoch,
            2
        );

        let resume = FleetActionRecord {
            action_id: "resume-after-epoch-recovery".into(),
            emitted_at: fixed_clock(),
            action: FleetAction::NativeSessionResume {
                zone_id: "zone-a".into(),
                hold_action_id: "supervisor-maintenance".into(),
                reason: Some("resume the certified population".into()),
            },
        };
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_ACTIONS_PATH,
                    Some(&bearer()),
                    &serde_json::to_vec(&resume).unwrap(),
                ))
                .status,
            201
        );
        assert_eq!(
            epoch_barrier_response(&service, "trace-resumed-after-restart").status,
            409,
            "a committed epoch cannot authorize reusing a released hold"
        );
        let recovered = DurableFleetTransport::new(dir.path().join("fleet")).unwrap();
        assert_eq!(
            recovered
                .current_fleet_epoch(&service.epoch_signing_key)
                .unwrap(),
            2,
            "a rejected resumed population must not advance durable epoch authority"
        );
    }

    #[test]
    fn fleet_epoch_recovery_rejects_changed_key_tampering_and_missing_history() {
        for scenario in [
            "changed_key",
            "altered_certificate",
            "missing_head",
            "missing_commit",
        ] {
            let root = ed25519_dalek::SigningKey::from_bytes(&[52; 32]);
            let (dir, service) = service_with_committed_epoch(&root);
            drop(service);
            let state_dir = dir.path().join("fleet");
            if scenario != "changed_key" {
                use fsqlite::compat::TransactionExt as _;
                let connection = fsqlite::Connection::open(
                    state_dir.join("fleet-state.db").to_string_lossy().as_ref(),
                )
                .unwrap();
                for pragma in [
                    "PRAGMA journal_mode=WAL;",
                    "PRAGMA synchronous=FULL;",
                    "PRAGMA busy_timeout=5000;",
                ] {
                    connection.query(pragma).unwrap();
                }
                let mut tx = connection.transaction().unwrap();
                match scenario {
                    "altered_certificate" => {
                        let rows = tx
                            .query("SELECT commit_json FROM fleet_epoch_commits WHERE epoch = '1';")
                            .unwrap();
                        let fsqlite::SqliteValue::Text(raw) = &rows[0].values()[0] else {
                            panic!("stored epoch commit must be JSON text");
                        };
                        let mut commit: serde_json::Value =
                            serde_json::from_str(raw.as_ref()).unwrap();
                        commit["certificate"]["participants"][0]["session_set_sha256"] =
                            serde_json::Value::String("a".repeat(64));
                        tx.execute_with_params(
                            "UPDATE fleet_epoch_commits SET commit_json = ?1 WHERE epoch = '1';",
                            &[fsqlite::SqliteValue::Text(
                                serde_json::to_string(&commit).unwrap().into(),
                            )],
                        )
                        .unwrap();
                    }
                    "missing_head" => {
                        tx.execute(
                            "UPDATE fleet_meta SET key = 'lost_epoch_head' WHERE key = 'authenticated_epoch_head';",
                        )
                        .unwrap();
                    }
                    _ => {
                        tx.execute(
                            "UPDATE fleet_epoch_commits SET epoch = '99' WHERE epoch = '1';",
                        )
                        .unwrap();
                    }
                }
                tx.commit().unwrap();
            }
            let token = if scenario == "changed_key" {
                "changed-operator-token-0123456789abcdef0123456789abcdef"
            } else {
                TOKEN
            };
            assert!(
                FleetControlPlaneService::open(state_dir, token).is_err(),
                "{scenario}: invalid recovery state must not reset the fleet epoch"
            );
        }
    }

    #[test]
    fn unsigned_epoch_cache_cannot_bootstrap_authoritative_history() {
        let (dir, service) = service();
        drop(service);
        let page = SeqlockControlPage::new();
        page.publish(9, 1, 0, 0, [0; 32]);
        page.write_shared_page(&dir.path().join("fleet/seqlock.page"))
            .unwrap();
        assert!(
            FleetControlPlaneService::open(dir.path().join("fleet"), TOKEN).is_err(),
            "an unsigned cache cannot authorize epoch recovery or silent genesis"
        );
    }

    #[test]
    fn enrolled_supervisor_drains_require_the_pinned_key_and_exact_observation() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        let (_dir, service) = service();
        let service = service
            .with_node_credentials(supervisor_enrollment(&root))
            .unwrap();
        let auth = format!("Bearer {NODE_TOKEN}");
        let status = signed_maintenance(&root, fixed_clock());
        let post = |status: &NodeStatus| {
            service.handle(request(
                "POST",
                FLEET_HTTP_NODES_PATH,
                Some(&auth),
                &serde_json::to_vec(status).unwrap(),
            ))
        };
        assert_eq!(
            post(&status).status,
            200,
            "useful signed maintenance heartbeat"
        );
        assert_eq!(post(&status).status, 200, "exact retry remains idempotent");
        let mut missing = status.clone();
        missing
            .native_session_drain
            .as_mut()
            .unwrap()
            .supervisor_attestation = None;
        assert_eq!(
            post(&missing).status,
            422,
            "a bearer cannot invent a terminal census"
        );
        let foreign = signed_maintenance(
            &ed25519_dalek::SigningKey::from_bytes(&[24; 32]),
            fixed_clock(),
        );
        assert_eq!(
            post(&foreign).status,
            422,
            "producer-selected root is not an anchor"
        );

        for mutation in 0..10 {
            let mut changed = status.clone();
            let drain = changed.native_session_drain.as_mut().unwrap();
            match mutation {
                0 => {
                    drain.admitted_sessions += 1;
                    drain.terminal_sessions += 1;
                }
                1 => drain.session_set_sha256 = "a".repeat(64),
                2 => drain.applied_actions.actions_sha256 = "b".repeat(64),
                3 => {
                    drain
                        .supervisor_attestation
                        .as_mut()
                        .unwrap()
                        .project_root_sha256 = "c".repeat(64)
                }
                4 => drain.supervisor_attestation.as_mut().unwrap().generation += 1,
                5 => {
                    drain.supervisor_attestation.as_mut().unwrap().drain_id =
                        "01900000-0000-7000-8000-000000000002".into()
                }
                6 => {
                    drain.supervisor_attestation.as_mut().unwrap().observed_at -=
                        chrono::Duration::seconds(1)
                }
                7 => drain.supervisor_attestation.as_mut().unwrap().node_id = "node-b".into(),
                8 => drain.supervisor_attestation.as_mut().unwrap().signature_hex = "0".repeat(128),
                _ => drain.supervisor_attestation.as_mut().unwrap().zone_id = "zone-b".into(),
            }
            assert_eq!(post(&changed).status, 422, "tampered field {mutation}");
        }
        let response = service.handle(request("GET", FLEET_HTTP_NODES_PATH, Some(&bearer()), b""));
        let nodes: FleetHttpNodeList = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            nodes.nodes[0].native_session_drain, status.native_session_drain,
            "refused substitutions preserve accepted evidence"
        );
        let public = String::from_utf8(response.body).unwrap();
        assert!(!public.contains("private-project-root"));
        assert!(!public.contains(NODE_TOKEN));
    }

    #[test]
    fn supervisor_signature_age_cannot_be_extended_by_heartbeats_or_guard_reads() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[25; 32]);
        let (_dir, service) = service();
        let service = service
            .with_node_credentials(supervisor_enrollment(&root))
            .unwrap();
        let auth = format!("Bearer {NODE_TOKEN}");
        for offset in [-300, 1] {
            let invalid =
                signed_maintenance(&root, fixed_clock() + chrono::Duration::seconds(offset));
            assert_eq!(
                service
                    .handle(request(
                        "POST",
                        FLEET_HTTP_NODES_PATH,
                        Some(&auth),
                        &serde_json::to_vec(&invalid).unwrap()
                    ))
                    .status,
                422
            );
        }
        let valid = signed_maintenance(&root, fixed_clock() - chrono::Duration::seconds(299));
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_NODES_PATH,
                    Some(&auth),
                    &serde_json::to_vec(&valid).unwrap()
                ))
                .status,
            200
        );
        fn one_second_later() -> DateTime<Utc> {
            fixed_clock() + chrono::Duration::seconds(1)
        }
        let service = service.with_clock(one_second_later);
        let response = service.handle(request("GET", FLEET_HTTP_STATE_PATH, Some(&bearer()), b""));
        let snapshot: FleetHttpState = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(snapshot.state.nodes[0].health, NodeHealth::Stale);
        assert!(snapshot.state.nodes[0].native_session_drain.is_none());
        assert!(snapshot.state.nodes[0].applied_actions.is_none());
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_NODES_PATH,
                    Some(&auth),
                    &serde_json::to_vec(&valid).unwrap()
                ))
                .status,
            422,
            "receipt remains expired despite fresh ingest time"
        );
    }

    #[test]
    fn signed_supervisor_history_survives_coordinator_restart_without_becoming_fresh() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[26; 32]);
        let (dir, service) = service();
        let service = service
            .with_node_credentials(supervisor_enrollment(&root))
            .unwrap();
        let auth = format!("Bearer {NODE_TOKEN}");
        let original = signed_maintenance(&root, fixed_clock() - chrono::Duration::seconds(2));
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_NODES_PATH,
                    Some(&auth),
                    &serde_json::to_vec(&original).unwrap()
                ))
                .status,
            200
        );
        drop(service);
        let service = FleetControlPlaneService::open(dir.path().join("fleet"), TOKEN)
            .unwrap()
            .with_clock(fixed_clock)
            .with_node_credentials(supervisor_enrollment(&root))
            .unwrap();
        let response = service.handle(request("GET", FLEET_HTTP_NODES_PATH, Some(&bearer()), b""));
        let nodes: FleetHttpNodeList = serde_json::from_slice(&response.body).unwrap();
        assert!(
            nodes.nodes[0].native_session_drain.is_none(),
            "retained signature is not a fresh heartbeat"
        );
        for mutation in 0..5 {
            let mut changed = original.clone();
            let attestation = changed
                .native_session_drain
                .as_mut()
                .unwrap()
                .supervisor_attestation
                .as_mut()
                .unwrap();
            attestation.observed_at += chrono::Duration::seconds(1);
            match mutation {
                0 => attestation.generation -= 1,
                1 => attestation.project_root_sha256 = "d".repeat(64),
                2 => attestation.drain_id = "01900000-0000-7000-8000-000000000003".into(),
                _ => {}
            }
            let checkpoint = changed.native_session_drain.as_mut().unwrap();
            match mutation {
                3 => checkpoint.session_set_sha256 = "e".repeat(64),
                4 => {
                    checkpoint.admitted_sessions += 1;
                    checkpoint.terminal_sessions += 1;
                }
                _ => {}
            }
            resign_observation(&mut changed, &root);
            let response = service.handle(request(
                "POST",
                FLEET_HTTP_NODES_PATH,
                Some(&auth),
                &serde_json::to_vec(&changed).unwrap(),
            ));
            assert_ne!(
                response.status, 200,
                "signed regression {mutation} must still refuse"
            );
        }
        let mut refreshed = original;
        refreshed
            .native_session_drain
            .as_mut()
            .unwrap()
            .supervisor_attestation
            .as_mut()
            .unwrap()
            .observed_at = fixed_clock();
        resign_observation(&mut refreshed, &root);
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_NODES_PATH,
                    Some(&auth),
                    &serde_json::to_vec(&refreshed).unwrap()
                ))
                .status,
            200
        );
    }

    #[test]
    fn degraded_heartbeat_cannot_erase_supervisor_history_or_replay_old_good_evidence() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[27; 32]);
        let (dir, service) = service();
        let service = service
            .with_node_credentials(supervisor_enrollment(&root))
            .unwrap();
        let auth = format!("Bearer {NODE_TOKEN}");
        let original = signed_maintenance(&root, fixed_clock() - chrono::Duration::seconds(2));
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_NODES_PATH,
                    Some(&auth),
                    &serde_json::to_vec(&original).unwrap()
                ))
                .status,
            200
        );
        let mut degraded = heartbeat("node-a");
        degraded.health = NodeHealth::Degraded;
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_NODES_PATH,
                    Some(&auth),
                    &serde_json::to_vec(&degraded).unwrap()
                ))
                .status,
            200,
            "loss of supervisor evidence must remain reportable"
        );
        drop(service);
        fn next_poll() -> DateTime<Utc> {
            fixed_clock() + chrono::Duration::seconds(1)
        }
        let service = FleetControlPlaneService::open(dir.path().join("fleet"), TOKEN)
            .unwrap()
            .with_clock(next_poll)
            .with_node_credentials(supervisor_enrollment(&root))
            .unwrap();
        let post = |status: &NodeStatus| {
            service.handle(request(
                "POST",
                FLEET_HTTP_NODES_PATH,
                Some(&auth),
                &serde_json::to_vec(status).unwrap(),
            ))
        };
        assert_ne!(
            post(&original).status,
            200,
            "cached good evidence was explicitly withdrawn"
        );
        let mut switched = signed_maintenance(&root, next_poll());
        switched
            .native_session_drain
            .as_mut()
            .unwrap()
            .supervisor_attestation
            .as_mut()
            .unwrap()
            .project_root_sha256 = "e".repeat(64);
        resign_observation(&mut switched, &root);
        assert_ne!(
            post(&switched).status,
            200,
            "shared user root cannot replace enrolled project identity"
        );
        assert_eq!(
            post(&signed_maintenance(&root, next_poll())).status,
            200,
            "fresh supervisor observation can restore availability"
        );
    }

    #[test]
    fn reordered_degraded_heartbeats_cannot_lower_the_supervisor_withdrawal_barrier() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[29; 32]);
        let dir = tempfile::tempdir().unwrap();
        let mut store = DurableFleetTransport::new(dir.path()).unwrap();
        store.initialize().unwrap();
        let mut original = signed_maintenance(&root, fixed_clock());
        original.last_seen = fixed_clock();
        store
            .upsert_node_status_with_supervisor(&original, &root.verifying_key())
            .unwrap();

        let mut degraded = heartbeat("node-a");
        degraded.health = NodeHealth::Degraded;
        degraded.last_seen = fixed_clock() + chrono::Duration::seconds(2);
        store
            .upsert_node_status_with_supervisor(&degraded, &root.verifying_key())
            .unwrap();
        let mut delayed = degraded.clone();
        delayed.last_seen = fixed_clock() + chrono::Duration::seconds(1);
        assert!(
            store
                .upsert_node_status_with_supervisor(&delayed, &root.verifying_key())
                .is_err(),
            "a request recorded earlier must not overwrite the later withdrawal"
        );
        drop(store);

        let mut store = DurableFleetTransport::new(dir.path()).unwrap();
        let mut cached =
            signed_maintenance(&root, fixed_clock() + chrono::Duration::milliseconds(1500));
        cached.last_seen = fixed_clock() + chrono::Duration::seconds(3);
        assert!(
            store
                .upsert_node_status_with_supervisor(&cached, &root.verifying_key())
                .is_err(),
            "an unsubmitted cached observation predating withdrawal stays unusable after restart"
        );
        let retained = store.list_node_statuses().unwrap();
        assert_eq!(retained, vec![degraded]);
        let mut fresh = signed_maintenance(&root, cached.last_seen);
        fresh.last_seen = cached.last_seen;
        store
            .upsert_node_status_with_supervisor(&fresh, &root.verifying_key())
            .unwrap();
    }

    #[test]
    fn health_is_unauthenticated_and_reports_schema() {
        let (_dir, service) = service();
        let response = service.handle(request("GET", FLEET_HTTP_HEALTH_PATH, None, b""));
        assert_eq!(response.status, 200);
        let health: FleetHttpHealth = serde_json::from_slice(&response.body).expect("health");
        assert_eq!(health.schema_version, FLEET_HTTP_API_SCHEMA);
        assert_eq!(health.status, "ok");
        assert_eq!(health.store, FLEET_HTTP_STORE_LABEL);
    }

    #[test]
    fn data_routes_require_the_exact_bearer_token() {
        let (_dir, service) = service();
        for path in [
            FLEET_HTTP_ACTIONS_PATH,
            FLEET_HTTP_NODES_PATH,
            FLEET_HTTP_STATE_PATH,
        ] {
            let missing = service.handle(request("GET", path, None, b""));
            assert_eq!(missing.status, 401, "{path}");
            let wrong = format!("Bearer {}", "f".repeat(48));
            let refused = service.handle(request("GET", path, Some(&wrong), b""));
            assert_eq!(refused.status, 401, "{path}");
            let basic = service.handle(request("GET", path, Some("Basic abc"), b""));
            assert_eq!(basic.status, 401, "{path}");
            let auth = bearer();
            let allowed = service.handle(request("GET", path, Some(&auth), b""));
            assert_eq!(allowed.status, 200, "{path}");
        }
    }

    #[test]
    fn published_actions_are_listed_and_idempotent_by_id() {
        let (_dir, service) = service();
        let auth = bearer();
        let body = serde_json::to_vec(&quarantine_action("op-1")).expect("encode");
        let published =
            service.handle(request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body));
        assert_eq!(published.status, 201);
        let ack: FleetHttpAck = serde_json::from_slice(&published.body).expect("ack");
        assert_eq!(ack.accepted, "op-1");
        // Retrying the exact record succeeds without changing or duplicating it.
        let again = service.handle(request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body));
        assert_eq!(again.status, 201);

        let listed = service.handle(request("GET", FLEET_HTTP_ACTIONS_PATH, Some(&auth), b""));
        let list: FleetHttpActionList = serde_json::from_slice(&listed.body).expect("list");
        assert_eq!(list.actions, vec![quarantine_action("op-1")]);
    }

    #[test]
    fn conflicting_action_id_returns_409_and_preserves_the_original() {
        let (_dir, service) = service();
        let auth = bearer();
        let original = quarantine_action("op-conflict");
        let body = serde_json::to_vec(&original).expect("encode original");
        assert_eq!(
            service
                .handle(request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body))
                .status,
            201
        );

        let mut changed = original.clone();
        changed.action = FleetAction::Release {
            zone_id: "zone-a".into(),
            incident_id: "inc-1".into(),
            reason: Some("conflicting retry".into()),
        };
        let body = serde_json::to_vec(&changed).expect("encode conflicting retry");
        let response = service.handle(request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body));
        assert_eq!(response.status, 409);
        let problem: FleetHttpProblem = serde_json::from_slice(&response.body).expect("problem");
        assert_eq!(problem.code, "FLEET_HTTP_ACTION_CONFLICT");

        let listed = service.handle(request("GET", FLEET_HTTP_ACTIONS_PATH, Some(&auth), b""));
        let list: FleetHttpActionList = serde_json::from_slice(&listed.body).expect("list");
        assert_eq!(list.actions, vec![original]);
    }

    #[test]
    fn heartbeats_are_stamped_with_the_coordinator_clock() {
        let (_dir, service) = service();
        let auth = bearer();
        let body = serde_json::to_vec(&heartbeat("node-1")).expect("encode");
        let response = service.handle(request("POST", FLEET_HTTP_NODES_PATH, Some(&auth), &body));
        assert_eq!(response.status, 200);
        let ack: FleetHttpAck = serde_json::from_slice(&response.body).expect("ack");
        assert_eq!(ack.accepted, "zone-a/node-1");
        assert_eq!(
            ack.recorded_at.as_deref(),
            Some(fixed_clock().to_rfc3339().as_str())
        );

        let listed = service.handle(request("GET", FLEET_HTTP_NODES_PATH, Some(&auth), b""));
        let nodes: FleetHttpNodeList = serde_json::from_slice(&listed.body).expect("nodes");
        assert_eq!(nodes.nodes.len(), 1);
        assert_eq!(nodes.nodes[0].last_seen, fixed_clock());
    }

    #[test]
    fn state_route_combines_actions_and_nodes() {
        let (_dir, service) = service();
        let auth = bearer();
        let action = serde_json::to_vec(&quarantine_action("op-2")).expect("encode");
        let node = serde_json::to_vec(&heartbeat("node-2")).expect("encode");
        assert_eq!(
            service
                .handle(request(
                    "POST",
                    FLEET_HTTP_ACTIONS_PATH,
                    Some(&auth),
                    &action
                ))
                .status,
            201
        );
        assert_eq!(
            service
                .handle(request("POST", FLEET_HTTP_NODES_PATH, Some(&auth), &node))
                .status,
            200
        );
        let state = service.handle(request("GET", FLEET_HTTP_STATE_PATH, Some(&auth), b""));
        let state: FleetHttpState = serde_json::from_slice(&state.body).expect("state");
        assert_eq!(state.state.actions.len(), 1);
        assert_eq!(state.state.nodes.len(), 1);
    }

    #[test]
    fn malformed_invalid_and_oversized_bodies_are_rejected() {
        let (_dir, service) = service();
        let auth = bearer();
        let malformed = service.handle(request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), b"{"));
        assert_eq!(malformed.status, 400);

        let mut bad = quarantine_action("op/../escape");
        bad.action_id = "op/../escape".to_string();
        let body = serde_json::to_vec(&bad).expect("encode");
        let invalid = service.handle(request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &body));
        assert_eq!(invalid.status, 422);

        let mut bad_node = heartbeat("node 1");
        bad_node.node_id = "node 1".to_string();
        let body = serde_json::to_vec(&bad_node).expect("encode");
        let invalid = service.handle(request("POST", FLEET_HTTP_NODES_PATH, Some(&auth), &body));
        assert_eq!(invalid.status, 422);

        let huge = vec![b' '; FLEET_HTTP_MAX_REQUEST_BYTES + 1];
        let too_large =
            service.handle(request("POST", FLEET_HTTP_ACTIONS_PATH, Some(&auth), &huge));
        assert_eq!(too_large.status, 413);

        // Nothing invalid was persisted.
        let listed = service.handle(request("GET", FLEET_HTTP_ACTIONS_PATH, Some(&auth), b""));
        let list: FleetHttpActionList = serde_json::from_slice(&listed.body).expect("list");
        assert!(list.actions.is_empty());
    }

    #[test]
    fn unknown_routes_and_methods_are_refused() {
        let (_dir, service) = service();
        let auth = bearer();
        assert_eq!(
            service
                .handle(request("GET", "/v2/fleet/admin", Some(&auth), b""))
                .status,
            404
        );
        assert_eq!(
            service
                .handle(request("DELETE", FLEET_HTTP_ACTIONS_PATH, Some(&auth), b""))
                .status,
            405
        );
        assert_eq!(
            service
                .handle(request("POST", FLEET_HTTP_HEALTH_PATH, None, b""))
                .status,
            405
        );
        // Query strings and trailing slashes do not change routing.
        assert_eq!(
            service
                .handle(request("GET", "/v2/fleet/nodes/?zone=a", Some(&auth), b""))
                .status,
            200
        );
    }

    #[test]
    fn service_refuses_weak_tokens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = FleetControlPlaneService::open(dir.path().join("fleet"), "short")
            .expect_err("weak token refused");
        assert!(err.to_string().contains("at least"), "{err}");
    }

    #[test]
    fn node_credentials_reject_invalid_duplicate_and_unbounded_enrollment() {
        let valid = serde_json::json!({
            "schema_version": FLEET_NODE_CREDENTIALS_SCHEMA,
            "nodes": [{"zone_id": "zone-a", "node_id": "node-a",
                "token_sha256": hex::encode(Sha256::digest(b"node-a-independent-token"))}]
        });
        let parse = |value: &serde_json::Value| {
            FleetNodeCredentials::from_json(&serde_json::to_vec(value).expect("encode document"))
        };
        assert!(parse(&valid).is_ok());
        for pin in [
            "g".repeat(64),
            "1".repeat(63),
            "0".repeat(64),
            "A".repeat(64),
        ] {
            let mut bad_key = valid.clone();
            bad_key["nodes"][0]["supervisor_public_key_hex"] = pin.into();
            assert!(
                parse(&bad_key).is_err(),
                "malformed supervisor pin must never downgrade enrollment"
            );
        }
        let mut empty = valid.clone();
        empty["nodes"] = serde_json::json!([]);
        let mut wrong_schema = valid.clone();
        wrong_schema["schema_version"] = "future".into();
        let mut duplicate_identity = valid.clone();
        let mut second = duplicate_identity["nodes"][0].clone();
        second["token_sha256"] = "b".repeat(64).into();
        duplicate_identity["nodes"]
            .as_array_mut()
            .expect("nodes")
            .push(second);
        let mut duplicate_token = valid.clone();
        let mut second = duplicate_token["nodes"][0].clone();
        second["node_id"] = "node-b".into();
        duplicate_token["nodes"]
            .as_array_mut()
            .expect("nodes")
            .push(second);
        let mut wildcard = valid.clone();
        wildcard["nodes"][0]["zone_id"] = "all".into();
        let mut invalid_id = valid.clone();
        invalid_id["nodes"][0]["node_id"] = "../escape".into();
        let mut short_digest = valid.clone();
        short_digest["nodes"][0]["token_sha256"] = "a".repeat(63).into();
        let mut uppercase_digest = valid.clone();
        uppercase_digest["nodes"][0]["token_sha256"] = "A".repeat(64).into();
        let mut plaintext = valid.clone();
        plaintext["nodes"][0]["token"] = "secret-must-not-appear-in-errors".into();
        let mut too_many = valid.clone();
        too_many["nodes"] = serde_json::Value::Array(vec![
            valid["nodes"][0].clone();
            MAX_FLEET_NODE_CREDENTIALS + 1
        ]);
        for invalid in [
            empty,
            wrong_schema,
            duplicate_identity,
            duplicate_token,
            wildcard,
            invalid_id,
            short_digest,
            uppercase_digest,
            plaintext,
            too_many,
        ] {
            let error = parse(&invalid).expect_err("invalid enrollment must refuse");
            assert!(
                !error
                    .to_string()
                    .contains("secret-must-not-appear-in-errors")
            );
        }
        let oversized = vec![b' '; MAX_FLEET_NODE_CREDENTIALS_BYTES + 1];
        assert!(FleetNodeCredentials::from_json(&oversized).is_err());
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("oversized-enrollment.json");
        std::fs::write(&path, &oversized).expect("write oversized file");
        assert!(FleetNodeCredentials::load(&path).is_err());
        assert!(FleetNodeCredentials::load(dir.path()).is_err());
    }

    #[test]
    fn enrolled_credentials_cannot_equal_the_operator_or_be_replaced_in_process() {
        let enrollment = |token: &str| {
            FleetNodeCredentials::from_json(
                &serde_json::to_vec(&serde_json::json!({
                    "schema_version": FLEET_NODE_CREDENTIALS_SCHEMA,
                    "nodes": [{"zone_id": "zone-a", "node_id": "node-a",
                        "token_sha256": hex::encode(Sha256::digest(token.as_bytes()))}]
                }))
                .expect("encode"),
            )
            .expect("valid enrollment")
        };
        let (_dir, service) = service();
        let error = service
            .with_node_credentials(enrollment(TOKEN))
            .expect_err("role collision");
        assert!(error.to_string().contains("distinct"));
        assert!(!error.to_string().contains(TOKEN));
        let (_dir, service) = self::service();
        let service = service
            .with_node_credentials(enrollment("first-node-credential"))
            .expect("enroll node");
        assert_eq!(service.enrolled_node_count(), 1);
        let debug = format!("{service:?}");
        assert!(!debug.contains(TOKEN));
        assert!(!debug.contains("first-node-credential"));
        assert!(
            service
                .with_node_credentials(enrollment("replacement-node-credential"))
                .is_err()
        );
    }

    #[test]
    fn maintenance_view_requires_a_fresh_authenticated_heartbeat() {
        use crate::control_plane::fleet_transport::{
            NativeSessionDrainCheckpoint, fleet_application_checkpoint, validate_node_status,
        };
        let hold = FleetActionRecord {
            action_id: "maintenance-a".into(),
            emitted_at: fixed_clock(),
            action: FleetAction::NativeSessionHold {
                zone_id: "zone-a".into(),
                reason: "replace admitted runtime".into(),
            },
        };
        let checkpoint = fleet_application_checkpoint(&[hold], "zone-a").unwrap();
        let mut held = heartbeat("node-a");
        held.health = NodeHealth::Maintenance;
        held.applied_actions = Some(checkpoint.clone());
        held.native_session_drain = Some(NativeSessionDrainCheckpoint {
            applied_actions: checkpoint,
            session_set_sha256: hex::encode(Sha256::digest(b"unit-test-empty-population")),
            admitted_sessions: 0,
            terminal_sessions: 0,
            pending_sessions: 0,
            indeterminate_sessions: 0,
            fence_held: true,
            supervisor_attestation: None,
        });
        validate_node_status(&held).unwrap();
        let credentials = FleetNodeCredentials {
            nodes: vec![EnrolledNode {
                zone_id: "zone-a".into(),
                node_id: "node-a".into(),
                token_sha256: Sha256::digest(b"independent-node-credential").into(),
                supervisor_public_key: None,
            }],
        };
        let mut nodes = vec![held.clone()];
        enrolled_node_view(
            &mut nodes,
            &credentials,
            &AuthenticatedNodes::new(),
            fixed_clock(),
        )
        .unwrap();
        assert_eq!(
            nodes.len(),
            1,
            "restart must not erase the enrolled participant"
        );
        assert_eq!(nodes[0].health, NodeHealth::Stale);
        assert!(nodes[0].applied_actions.is_none());
        assert!(nodes[0].native_session_drain.is_none());
        validate_node_status(&nodes[0]).expect("unverified maintenance remains a readable status");

        let authenticated = BTreeMap::from([(("zone-a".into(), "node-a".into()), held.clone())]);
        let mut nodes = vec![held.clone()];
        enrolled_node_view(&mut nodes, &credentials, &authenticated, fixed_clock()).unwrap();
        assert_eq!(nodes, vec![held]);
        nodes[0].last_seen = fixed_clock();
        enrolled_node_view(&mut nodes, &credentials, &authenticated, fixed_clock()).unwrap();
        assert_eq!(
            nodes[0].health,
            NodeHealth::Stale,
            "changed retained status is not authenticated"
        );
    }

    #[test]
    fn maintenance_actions_preserve_enrolled_zone_filtering() {
        let mut actions = Vec::new();
        for zone in ["all", "zone-a", "zone-b"] {
            let hold = format!("hold-{zone}");
            actions.push(FleetActionRecord {
                action_id: hold.clone(),
                emitted_at: fixed_clock(),
                action: FleetAction::NativeSessionHold {
                    zone_id: zone.into(),
                    reason: "maintenance".into(),
                },
            });
            actions.push(FleetActionRecord {
                action_id: format!("resume-{zone}"),
                emitted_at: fixed_clock(),
                action: FleetAction::NativeSessionResume {
                    zone_id: zone.into(),
                    hold_action_id: hold,
                    reason: None,
                },
            });
        }
        let all = actions.clone();
        FleetPrincipal::Node {
            zone_id: "zone-a".into(),
            node_id: "node-a".into(),
        }
        .filter_actions(&mut actions);
        assert_eq!(actions, all[..4]);
        crate::control_plane::fleet_transport::fleet_application_checkpoint(&actions, "zone-a")
            .expect("filter retains each applicable resume's original owner");
    }

    #[test]
    fn max_requests_triggers_shutdown() {
        let control = FleetHttpServerControl::new();
        control.record_request(Some(2));
        assert!(!control.shutdown_requested());
        control.record_request(Some(2));
        assert!(control.shutdown_requested());
        assert_eq!(control.requests_served(), 2);
    }
}
