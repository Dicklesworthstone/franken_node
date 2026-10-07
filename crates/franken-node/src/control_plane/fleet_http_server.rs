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

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::fleet_transport::{
    FleetActionRecord, FleetTransport, FleetTransportError, NodeStatus, validate_action_record,
    validate_node_status,
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
    clock: fn() -> DateTime<Utc>,
}

type StoreJob = Box<dyn FnOnce(&mut DurableFleetTransport) + Send>;

impl std::fmt::Debug for FleetControlPlaneService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetControlPlaneService")
            .field("token", &"<redacted>")
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
                // Ends when the service (the only sender) is dropped.
                while let Ok(job) = inbox.recv() {
                    job(&mut transport);
                }
            })
            .map_err(|err| FleetTransportError::io(format!("spawn fleet store thread: {err}")))?;
        opened
            .recv()
            .map_err(|_| FleetTransportError::io("fleet store thread exited during startup"))??;
        Ok(Self {
            store: Mutex::new(jobs),
            token: token.to_string(),
            clock: Utc::now,
        })
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

        let authorized = request
            .authorization
            .and_then(parse_bearer_header)
            .is_some_and(|presented| bearer_token_matches(presented, &self.token));
        if !authorized {
            return FleetHttpResponse::problem(
                401,
                "unauthorized",
                "FLEET_HTTP_UNAUTHORIZED",
                "a valid `Authorization: Bearer <token>` header is required",
            );
        }
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

        match (request.method, path) {
            ("GET", FLEET_HTTP_ACTIONS_PATH) => self.with_transport(|transport| {
                let actions = transport.list_actions()?;
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
                self.with_transport(move |transport| {
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
            ("GET", FLEET_HTTP_NODES_PATH) => self.with_transport(|transport| {
                let nodes = transport.list_node_statuses()?;
                Ok(FleetHttpResponse::json(
                    200,
                    "ok",
                    &FleetHttpNodeList {
                        schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                        nodes,
                    },
                ))
            }),
            ("POST", FLEET_HTTP_NODES_PATH) => {
                let mut status: NodeStatus = match parse_body(request.body) {
                    Ok(status) => status,
                    Err(response) => return response,
                };
                if let Err(err) = validate_node_status(&status) {
                    return invalid_record(&err);
                }
                let recorded_at = (self.clock)();
                status.last_seen = recorded_at;
                self.with_transport(move |transport| {
                    transport.upsert_node_status(&status)?;
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
            ("GET", FLEET_HTTP_STATE_PATH) => self.with_transport(|transport| {
                let state = transport.read_shared_state()?;
                Ok(FleetHttpResponse::json(
                    200,
                    "ok",
                    &FleetHttpState {
                        schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                        state,
                    },
                ))
            }),
            (method, path) => method_not_allowed(method, path),
        }
    }

    /// Run `operation` against the durable store on the store thread and wait
    /// for its answer.
    fn with_transport(
        &self,
        operation: impl FnOnce(
            &mut DurableFleetTransport,
        ) -> Result<FleetHttpResponse, FleetTransportError>
        + Send
        + 'static,
    ) -> FleetHttpResponse {
        let (reply, answer) = mpsc::sync_channel(1);
        let job: StoreJob = Box::new(move |transport| {
            let _ = reply.send(operation(transport));
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
                .handle(request("GET", "/v1/fleet/admin", Some(&auth), b""))
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
                .handle(request("GET", "/v1/fleet/nodes/?zone=a", Some(&auth), b""))
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
    fn max_requests_triggers_shutdown() {
        let control = FleetHttpServerControl::new();
        control.record_request(Some(2));
        assert!(!control.shutdown_requested());
        control.record_request(Some(2));
        assert!(control.shutdown_requested());
        assert_eq!(control.requests_served(), 2);
    }
}
