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
//! Heartbeats are stamped with the coordinator's clock on ingest, so node
//! staleness is judged on one clock for the whole fleet regardless of client
//! clock skew.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::capacity_defaults::aliases::MAX_NODES_CAP;

use super::fleet_transport::{
    FleetAction, FleetActionRecord, FleetTransport, FleetTransportError, NodeHealth, NodeStatus,
    validate_action_record, validate_node_id, validate_node_status, validate_zone_id,
};
use super::fleet_transport_durable::DurableFleetTransport;
use super::fleet_transport_http::{
    FLEET_HTTP_ACTIONS_PATH, FLEET_HTTP_API_SCHEMA, FLEET_HTTP_HEALTH_PATH,
    FLEET_HTTP_MAX_REQUEST_BYTES, FLEET_HTTP_NODES_PATH, FLEET_HTTP_STATE_PATH, FleetHttpAck,
    FleetHttpActionList, FleetHttpHealth, FleetHttpNodeList, FleetHttpProblem, FleetHttpState,
    bearer_token_matches, parse_bearer_header, validate_bearer_token,
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
}

#[derive(Clone)]
struct EnrolledNode {
    zone_id: String,
    node_id: String,
    token_sha256: [u8; 32],
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
            nodes.push(EnrolledNode {
                zone_id: record.zone_id,
                node_id: record.node_id,
                token_sha256: digest,
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
) -> Result<(), FleetTransportError> {
    let mut present = BTreeSet::new();
    for node in nodes.iter_mut() {
        present.insert((node.zone_id.clone(), node.node_id.clone()));
        if authenticated.get(&(node.zone_id.clone(), node.node_id.clone())) != Some(&*node) {
            node.applied_actions = None;
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
            });
        }
    }
    nodes.sort_by(|left, right| {
        (&left.zone_id, &left.node_id).cmp(&(&right.zone_id, &right.node_id))
    });
    Ok(())
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
    store: Mutex<mpsc::Sender<StoreJob>>,
    token: String,
    node_credentials: Option<Arc<FleetNodeCredentials>>,
    clock: fn() -> DateTime<Utc>,
}

type StoreJob = Box<dyn FnOnce(&mut DurableFleetTransport, &mut AuthenticatedNodes) + Send>;

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
        validate_bearer_token(token).map_err(FleetTransportError::not_initialized)?;
        let (jobs, inbox) = mpsc::channel::<StoreJob>();
        let (ready, opened) = mpsc::sync_channel::<Result<(), FleetTransportError>>(1);
        std::thread::Builder::new()
            .name("fleet-control-plane-store".to_string())
            .spawn(move || {
                let mut transport = match DurableFleetTransport::new(state_dir)
                    .and_then(|mut transport| transport.initialize().map(|()| transport))
                {
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
        opened
            .recv()
            .map_err(|_| FleetTransportError::io("fleet store thread exited during startup"))??;
        Ok(Self {
            store: Mutex::new(jobs),
            token: token.to_string(),
            node_credentials: None,
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

    #[must_use]
    pub fn enrolled_node_count(&self) -> usize {
        self.node_credentials
            .as_ref()
            .map_or(0, |credentials| credentials.nodes.len())
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

    /// Answer one request.
    #[must_use]
    pub fn handle(&self, request: FleetHttpRequest<'_>) -> FleetHttpResponse {
        let path = request.path.split('?').next().unwrap_or_default();
        let path = if path.len() > 1 {
            path.trim_end_matches('/')
        } else {
            path
        };
        let known_path = matches!(
            path,
            FLEET_HTTP_HEALTH_PATH
                | FLEET_HTTP_ACTIONS_PATH
                | FLEET_HTTP_NODES_PATH
                | FLEET_HTTP_STATE_PATH
        );
        if !known_path {
            return FleetHttpResponse::problem(
                404,
                "not_found",
                "FLEET_HTTP_NOT_FOUND",
                format!("no fleet route at `{path}`"),
            );
        }
        if path == FLEET_HTTP_HEALTH_PATH {
            if request.method != "GET" {
                return method_not_allowed(request.method, path);
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
            );
        }

        let Some(principal) = self.authenticate(request.authorization) else {
            return FleetHttpResponse::problem(
                401,
                "unauthorized",
                "FLEET_HTTP_UNAUTHORIZED",
                "a valid `Authorization: Bearer <token>` header is required",
            );
        };
        if request.body.len() > FLEET_HTTP_MAX_REQUEST_BYTES {
            return FleetHttpResponse::problem(
                413,
                "too_large",
                "FLEET_HTTP_BODY_TOO_LARGE",
                format!(
                    "request body is {} bytes; the limit is {FLEET_HTTP_MAX_REQUEST_BYTES}",
                    request.body.len()
                ),
            );
        }

        if request.method == "POST" {
            let permitted = match (&principal, path) {
                (FleetPrincipal::Operator, FLEET_HTTP_ACTIONS_PATH)
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
                );
            }
        }
        if matches!(&principal, FleetPrincipal::Node { .. })
            && request.method == "GET"
            && path == FLEET_HTTP_STATE_PATH
        {
            return FleetHttpResponse::problem(
                403,
                "forbidden",
                "FLEET_HTTP_CREDENTIAL_SCOPE",
                "whole-fleet inventory and convergence require an operator credential",
            );
        }

        let enrollment = self.node_credentials.clone();

        match (request.method, path) {
            ("GET", FLEET_HTTP_ACTIONS_PATH) => self.with_transport(move |transport, _| {
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
            }),
            ("POST", FLEET_HTTP_ACTIONS_PATH) => {
                let action: FleetActionRecord = match parse_body(request.body) {
                    Ok(action) => action,
                    Err(response) => return response,
                };
                if let Err(err) = validate_action_record(&action) {
                    return invalid_record(&err);
                }
                self.with_transport(move |transport, _| {
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
            ("GET", FLEET_HTTP_NODES_PATH) => {
                self.with_transport(move |transport, authenticated| {
                    let mut nodes = transport.list_node_statuses()?;
                    if let Some(credentials) = &enrollment {
                        enrolled_node_view(&mut nodes, credentials, authenticated)?;
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
                    Err(response) => return response,
                };
                if let Err(err) = validate_node_status(&status) {
                    return invalid_record(&err);
                }
                if let FleetPrincipal::Node { zone_id, node_id } = &principal
                    && (status.zone_id != *zone_id || status.node_id != *node_id)
                {
                    return FleetHttpResponse::problem(
                        403,
                        "forbidden",
                        "FLEET_HTTP_NODE_IDENTITY_MISMATCH",
                        "heartbeat identity does not match the enrolled credential",
                    );
                }
                let recorded_at = (self.clock)();
                status.last_seen = recorded_at;
                self.with_transport(move |transport, authenticated| {
                    transport.upsert_node_status(&status)?;
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
                self.with_transport(move |transport, authenticated| {
                    let mut state = transport.read_shared_state()?;
                    if let Some(credentials) = &enrollment {
                        enrolled_node_view(&mut state.nodes, credentials, authenticated)?;
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
            (method, path) => method_not_allowed(method, path),
        }
    }

    /// Run `operation` against the durable store on the store thread and wait
    /// for its answer.
    fn with_transport(
        &self,
        operation: impl FnOnce(
            &mut DurableFleetTransport,
            &mut AuthenticatedNodes,
        ) -> Result<FleetHttpResponse, FleetTransportError>
        + Send
        + 'static,
    ) -> FleetHttpResponse {
        let (reply, answer) = mpsc::sync_channel(1);
        let job: StoreJob = Box::new(move |transport, authenticated| {
            let _ = reply.send(operation(transport, authenticated));
        });
        let sent = {
            let sender = match self.store.lock() {
                Ok(sender) => sender,
                // Sending cannot leave the sender half-updated, so a poisoned
                // lock is still safe to use.
                Err(poisoned) => poisoned.into_inner(),
            };
            sender.send(job)
        };
        if sent.is_err() {
            return store_error(&FleetTransportError::io("fleet store thread has stopped"));
        }
        match answer.recv() {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => store_error(&err),
            Err(_) => store_error(&FleetTransportError::io(
                "fleet store thread stopped before answering",
            )),
        }
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
            max_request_size: FLEET_HTTP_MAX_REQUEST_BYTES.saturating_add(16 * 1024),
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

    let runtime =
        RuntimeBuilder::current_thread()
            .build()
            .map_err(|err| FleetHttpServerError::Runtime {
                detail: err.to_string(),
            })?;
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
        move |_ctx: &RequestContext, request: &mut Request| {
            let path = request.path().to_string();
            let authorization = request
                .headers()
                .get("authorization")
                .and_then(|value| std::str::from_utf8(value).ok())
                .map(str::to_string);
            let body = request.take_body().into_bytes();
            let response = service.handle(FleetHttpRequest {
                method,
                path: &path,
                authorization: authorization.as_deref(),
                body: &body,
            });
            on_event(&request_event(method, &path, &response));
            control.record_request(max_requests);
            if control.shutdown_requested() {
                server.shutdown();
            }
            std::future::ready(
                Response::with_status(StatusCode::from_u16(response.status))
                    .header("content-type", b"application/json".to_vec())
                    .header("cache-control", b"no-store".to_vec())
                    .body(ResponseBody::Bytes(response.body)),
            )
        }
    };

    App::builder()
        .get(FLEET_HTTP_HEALTH_PATH, route("GET"))
        .get(FLEET_HTTP_ACTIONS_PATH, route("GET"))
        .post(FLEET_HTTP_ACTIONS_PATH, route("POST"))
        .get(FLEET_HTTP_NODES_PATH, route("GET"))
        .post(FLEET_HTTP_NODES_PATH, route("POST"))
        .get(FLEET_HTTP_STATE_PATH, route("GET"))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::fleet_transport::{FleetAction, FleetTargetKind, NodeHealth};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

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
        }
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
    fn max_requests_triggers_shutdown() {
        let control = FleetHttpServerControl::new();
        control.record_request(Some(2));
        assert!(!control.shutdown_requested());
        control.record_request(Some(2));
        assert!(control.shutdown_requested());
        assert_eq!(control.requests_served(), 2);
    }
}
