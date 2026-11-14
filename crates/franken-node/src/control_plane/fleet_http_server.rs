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
use crate::control_plane::control_epoch::EpochSigningKey;

use super::fleet_transport::{
    FleetAction, FleetActionRecord, FleetGuardedPolicyObservationScope, FleetTransport,
    FleetTransportError, GuardedFleetPolicyPublication, MAX_GUARDED_POLICY_REQUEST_BYTES,
    MAX_GUARDED_POLICY_STALE_AFTER, NodeHealth, NodeStatus, SeqlockControlPage,
    validate_action_record, validate_node_id, validate_node_status, validate_zone_id,
};
use super::fleet_transport_durable::DurableFleetTransport;
use super::fleet_transport_http::{
    FLEET_HTTP_ACTIONS_PATH, FLEET_HTTP_API_SCHEMA, FLEET_HTTP_EPOCH_BARRIER_PATH,
    FLEET_HTTP_GUARDED_POLICY_PATH, FLEET_HTTP_HEALTH_PATH, FLEET_HTTP_MAX_REQUEST_BYTES,
    FLEET_HTTP_NODES_PATH, FLEET_HTTP_STATE_PATH, FleetHttpAck, FleetHttpActionList,
    FleetHttpEpochBarrierRequest, FleetHttpEpochBarrierResponse, FleetHttpHealth,
    FleetHttpNodeList, FleetHttpProblem, FleetHttpState, bearer_token_matches, parse_bearer_header,
    validate_bearer_token,
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
    store: Mutex<mpsc::Sender<StoreJob>>,
    state_dir: PathBuf,
    token: String,
    node_credentials: Option<Arc<FleetNodeCredentials>>,
    epoch_signing_key: Arc<EpochSigningKey>,
    seqlock_page: Arc<SeqlockControlPage>,
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
        let epoch_key_material = Sha256::digest(format!("fleet-epoch-signing:{token}").as_bytes());
        let epoch_signing_key = EpochSigningKey::new(epoch_key_material.as_slice())
            .map_err(|err| FleetTransportError::not_initialized(err.to_string()))?;
        let epoch_signing_key = Arc::new(epoch_signing_key);
        let store_epoch_key = Arc::clone(&epoch_signing_key);
        let seqlock_page = Arc::new(SeqlockControlPage::new());
        let store_dir = state_dir.clone();
        let (jobs, inbox) = mpsc::channel::<StoreJob>();
        let (ready, opened) = mpsc::sync_channel::<Result<(), FleetTransportError>>(1);
        std::thread::Builder::new()
            .name("fleet-control-plane-store".to_string())
            .spawn(move || {
                let mut transport =
                    match DurableFleetTransport::new(store_dir).and_then(|mut transport| {
                        transport.initialize()?;
                        transport.current_fleet_epoch(&store_epoch_key)?;
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
        opened
            .recv()
            .map_err(|_| FleetTransportError::io("fleet store thread exited during startup"))??;
        Ok(Self {
            store: Mutex::new(jobs),
            state_dir,
            token: token.to_string(),
            node_credentials: None,
            epoch_signing_key,
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
                | FLEET_HTTP_GUARDED_POLICY_PATH
                | FLEET_HTTP_EPOCH_BARRIER_PATH
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
        let request_limit = if path == FLEET_HTTP_GUARDED_POLICY_PATH {
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
            );
        }

        if request.method == "POST" {
            let permitted = match (&principal, path) {
                (FleetPrincipal::Operator, FLEET_HTTP_ACTIONS_PATH)
                | (FleetPrincipal::Operator, FLEET_HTTP_GUARDED_POLICY_PATH)
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
            ("POST", FLEET_HTTP_GUARDED_POLICY_PATH) => {
                let Some(enrollment) = enrollment else {
                    return FleetHttpResponse::problem(
                        409,
                        "conflict",
                        "FLEET_HTTP_NODE_ENROLLMENT_REQUIRED",
                        "guarded policy publication requires enrolled node credentials and fresh node-authenticated maintenance observations",
                    );
                };
                let publication: GuardedFleetPolicyPublication = match parse_body(request.body) {
                    Ok(publication) => publication,
                    Err(response) => return response,
                };
                if let Err(err) = publication.validate() {
                    return invalid_record(&err);
                }
                let clock = self.clock;
                self.with_transport(move |transport, authenticated| {
                    // Project the exact authenticated observations within the
                    // durable transaction, on the same serialized store thread
                    // as heartbeat acceptance. Missing enrolled nodes remain
                    // participants and cannot disappear from the guard.
                    let receipt = transport.publish_policy_with_maintenance_guard_projected(
                        &publication,
                        FleetGuardedPolicyObservationScope::EnrolledNodeObservations,
                        MAX_GUARDED_POLICY_STALE_AFTER,
                        clock,
                        |nodes| enrolled_node_view(nodes, &enrollment, authenticated, clock()),
                    )?;
                    Ok(FleetHttpResponse::json(
                        if receipt.already_published { 200 } else { 201 },
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
                    );
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
                        );
                    };
                    roots.insert((node.zone_id.clone(), node.node_id.clone()), key);
                }
                let barrier_req: FleetHttpEpochBarrierRequest = match parse_body(request.body) {
                    Ok(req) => req,
                    Err(response) => return response,
                };
                let clock = self.clock;
                let epoch_signing_key = Arc::clone(&self.epoch_signing_key);
                let seqlock_page = Arc::clone(&self.seqlock_page);
                let seqlock_path = self.state_dir.join("seqlock.page");
                self.with_transport(move |transport, authenticated| {
                    let (evidence, certificate, max_qv) = transport.certify_epoch_quiescence_projected(
                        &epoch_signing_key,
                        &roots,
                        super::fleet_transport::FleetEpochBarrierParams {
                            initiator: &barrier_req.initiator,
                            reason: &barrier_req.reason,
                            now: clock(),
                            stale_after: barrier_req
                                .stale_after
                                .min(MAX_GUARDED_POLICY_STALE_AFTER),
                            trace_id: &barrier_req.trace_id,
                        },
                        clock,
                        |nodes| enrolled_node_view(nodes, &enrollment, authenticated, clock()),
                    )?;
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
                    Ok(FleetHttpResponse::json(
                        200,
                        "ok",
                        &FleetHttpEpochBarrierResponse {
                            schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                            evidence,
                            certificate,
                        },
                    ))
                })
            }
            ("GET", FLEET_HTTP_NODES_PATH) => {
                let clock = self.clock;
                self.with_transport(move |transport, authenticated| {
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
                if let Some(credentials) = &enrollment
                    && let Err(error) =
                        verify_supervisor_observation(&status, credentials, recorded_at)
                {
                    return invalid_record(&error);
                }
                status.last_seen = recorded_at;
                self.with_transport(move |transport, authenticated| {
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
                self.with_transport(move |transport, authenticated| {
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
        .post(FLEET_HTTP_GUARDED_POLICY_PATH, route("POST"))
        .post(FLEET_HTTP_EPOCH_BARRIER_PATH, route("POST"))
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
        let (dir, service) = service();
        let service = service
            .with_node_credentials(supervisor_enrollment(root))
            .unwrap();
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
            let connection = fsqlite::Connection::open(
                state_dir.join("fleet-state.db").to_string_lossy().as_ref(),
            )
            .unwrap();
            match scenario {
                "changed_key" => {}
                "altered_certificate" => {
                    let rows = connection
                        .query("SELECT commit_json FROM fleet_epoch_commits WHERE epoch = '1';")
                        .unwrap();
                    let fsqlite::SqliteValue::Text(raw) = &rows[0].values()[0] else {
                        panic!("stored epoch commit must be JSON text");
                    };
                    let mut commit: serde_json::Value = serde_json::from_str(raw.as_ref()).unwrap();
                    commit["certificate"]["participants"][0]["session_set_sha256"] =
                        serde_json::Value::String("a".repeat(64));
                    connection
                        .execute_with_params(
                            "UPDATE fleet_epoch_commits SET commit_json = ?1 WHERE epoch = '1';",
                            &[fsqlite::SqliteValue::Text(
                                serde_json::to_string(&commit).unwrap().into(),
                            )],
                        )
                        .unwrap();
                }
                "missing_head" => {
                    connection.execute(
                        "UPDATE fleet_meta SET key = 'lost_epoch_head' WHERE key = 'authenticated_epoch_head';",
                    ).unwrap();
                }
                _ => {
                    connection
                        .execute("UPDATE fleet_epoch_commits SET epoch = '99' WHERE epoch = '1';")
                        .unwrap();
                }
            }
            drop(connection);
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
