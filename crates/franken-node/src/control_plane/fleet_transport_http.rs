//! Live HTTP fleet control plane: wire contract and client transport.
//!
//! The coordinator (`franken-node fleet serve`, see `fleet_http_server`) owns
//! the authoritative durable fleet store and exposes it over HTTP. Every other
//! node reaches it through [`HttpFleetTransport`], which implements the same
//! [`FleetTransport`] contract as the local durable store, so `fleet agent`,
//! `fleet status`, `fleet reconcile`, `fleet release` and `trust quarantine`
//! drive a real multi-node fleet without a shared filesystem.
//!
//! Security contract (fail closed):
//! * every request except `GET /v2/fleet/health` carries
//!   `Authorization: Bearer <token>`; the coordinator compares it in constant
//!   time and answers `401` otherwise;
//! * plaintext `http://` is accepted only for loopback hosts; a remote
//!   coordinator must be reached over `https://` (for example behind a
//!   TLS-terminating proxy) so the bearer token never crosses a network in
//!   clear text;
//! * redirects are refused before reading their bodies: neither authenticated
//!   fleet requests nor unauthenticated health probes may leave the configured
//!   coordinator origin or silently change their fixed API route;
//! * response bodies are size-bounded before they are parsed, and every
//!   record the coordinator returns is re-validated by the client with the
//!   same rules the coordinator applies on ingest.
//! * v2 routes and schemas require coordinator append order. Legacy v1
//!   requests cannot publish actions or acknowledgements before discovering
//!   the incompatible ordering contract in a response.

use std::{collections::BTreeSet, time::Duration};

use serde::{Deserialize, Serialize};

use crate::capacity_defaults::aliases::{MAX_ACTION_LOG_ENTRIES, MAX_NODES_CAP};

use super::fleet_transport::{
    FLEET_EPOCH_BARRIER_CERTIFIED_DRAIN_SCOPE, FLEET_EPOCH_QUIESCENCE_CERTIFICATE_SCHEMA,
    FLEET_SHARED_STATE_SCHEMA, FleetAcknowledgementStage, FleetActionRecord,
    FleetEpochQuiescenceCertificate, FleetGuardedPolicyObservationScope, FleetGuardedPolicyReceipt,
    FleetNativeDrainEvidence, FleetNativeDrainReadiness, FleetSharedState, FleetTransport,
    FleetTransportError, GuardedFleetPolicyPublication, MAX_GUARDED_POLICY_RECEIPT_BYTES,
    MAX_GUARDED_POLICY_REQUEST_BYTES, MAX_GUARDED_POLICY_STALE_AFTER,
    MAX_NATIVE_SESSION_MAINTENANCE_HOLDS, NodeHealth, NodeStatus, validate_action_id,
    validate_action_record, validate_node_status,
};

/// Schema tag carried by every response; v2 binds coordinator append order.
pub const FLEET_HTTP_API_SCHEMA: &str = "franken-node/fleet-http-api/v2";
/// Liveness probe; the only unauthenticated route.
pub const FLEET_HTTP_HEALTH_PATH: &str = "/v2/fleet/health";
/// `GET` lists actions, `POST` publishes one.
pub const FLEET_HTTP_ACTIONS_PATH: &str = "/v2/fleet/actions";
/// `GET` lists node statuses, `POST` upserts one (heartbeat).
pub const FLEET_HTTP_NODES_PATH: &str = "/v2/fleet/nodes";
/// `GET` returns the consolidated shared state (actions + nodes).
pub const FLEET_HTTP_STATE_PATH: &str = "/v2/fleet/state";
/// `POST` atomically checks enrolled maintenance observations and publishes a policy.
pub const FLEET_HTTP_GUARDED_POLICY_PATH: &str = "/v2/fleet/policies/guarded";
/// `POST` proposes, verifies enrolled supervisor drains, and commits an epoch transition barrier.
pub const FLEET_HTTP_EPOCH_BARRIER_PATH: &str = "/v2/fleet/epoch-barrier";
/// Request body bound for ordinary fleet routes. Guarded publication has its
/// own larger bound because it retains the complete participant identities.
pub const FLEET_HTTP_MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Upper bound on any response body the client reads.
pub const FLEET_HTTP_MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
/// Shortest accepted bearer token (hex-encoded 128 bits).
pub const FLEET_HTTP_MIN_TOKEN_LEN: usize = 32;
/// Longest accepted bearer token.
pub const FLEET_HTTP_MAX_TOKEN_LEN: usize = 512;
/// Default per-request client timeout.
pub const FLEET_HTTP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// `GET /v2/fleet/health` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHttpHealth {
    pub schema_version: String,
    pub status: String,
    pub service: String,
    pub store: String,
}

/// `GET /v2/fleet/actions` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHttpActionList {
    pub schema_version: String,
    pub actions: Vec<FleetActionRecord>,
}

/// `GET /v2/fleet/nodes` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHttpNodeList {
    pub schema_version: String,
    pub nodes: Vec<NodeStatus>,
}

/// `GET /v2/fleet/state` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHttpState {
    pub schema_version: String,
    pub state: FleetSharedState,
}

/// `POST /v2/fleet/epoch-barrier` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetHttpEpochBarrierRequest {
    pub initiator: String,
    pub reason: String,
    pub trace_id: String,
    pub stale_after: Duration,
}

/// `POST /v2/fleet/epoch-barrier` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetHttpEpochBarrierResponse {
    pub schema_version: String,
    pub evidence: FleetNativeDrainEvidence,
    pub certificate: FleetEpochQuiescenceCertificate,
}

impl FleetHttpEpochBarrierResponse {
    /// Validate one complete, request-bound claim instead of trusting summary
    /// booleans. Supervisor signatures establish internal integrity here;
    /// enrollment authority still comes from the configured coordinator, never
    /// from keys supplied by this response.
    fn validate_for_request(
        &self,
        request: &FleetHttpEpochBarrierRequest,
    ) -> Result<(), FleetTransportError> {
        let evidence = &self.evidence;
        let certificate = &self.certificate;
        if self.schema_version != FLEET_HTTP_API_SCHEMA
            || evidence.schema_version != "franken-node/fleet-native-drain-evidence/v1"
            || evidence.scope != FLEET_EPOCH_BARRIER_CERTIFIED_DRAIN_SCOPE
            || !evidence.complete
            || !evidence.fleet_quiescence_certified
            || !evidence.uncovered_zones.is_empty()
            || evidence.nodes.is_empty()
            || evidence.nodes.len() > MAX_NODES_CAP
            || evidence.nodes.len() != certificate.participants.len()
            || !certificate.fleet_quiescence_certified
            || certificate.schema_version != FLEET_EPOCH_QUIESCENCE_CERTIFICATE_SCHEMA
            || certificate.pre_epoch.checked_add(1) != Some(certificate.committed_epoch)
            || certificate.transition_id.trim().is_empty()
            || certificate.initiator != request.initiator
            || certificate.reason != request.reason
            || certificate.trace_id != request.trace_id
            || certificate.certified_at != evidence.observed_at
            || evidence.stale_after.is_zero()
            || evidence.stale_after != request.stale_after.min(MAX_GUARDED_POLICY_STALE_AFTER)
            || evidence.action_count == 0
            || evidence.action_count != certificate.action_log_checkpoint.action_count
        {
            return Err(FleetTransportError::serialization(
                "coordinator returned an incomplete or request-mismatched epoch-barrier response",
            ));
        }
        certificate.action_log_checkpoint.validate()?;
        let threshold = chrono::TimeDelta::from_std(evidence.stale_after)
            .map_err(|error| FleetTransportError::serialization(error.to_string()))?;
        let mut previous_identity = None;
        for (node, participant) in evidence.nodes.iter().zip(&certificate.participants) {
            let identity = (node.zone_id.as_str(), node.node_id.as_str());
            if previous_identity.is_some_and(|previous| previous >= identity)
                || node.zone_id == "all"
                || participant.zone_id != node.zone_id
                || participant.node_id != node.node_id
                || participant.stage != FleetAcknowledgementStage::EpochBarrierCertified
                || !node.ready
                || node.reason != FleetNativeDrainReadiness::Ready
                || node.health != Some(NodeHealth::Maintenance)
                || node.expected_actions.action_count == 0
                || node.expected_actions.action_count > evidence.action_count
                || node.applied_actions.as_ref() != Some(&node.expected_actions)
                || participant.active_hold_ids.is_empty()
                || participant.active_hold_ids.len() > MAX_NATIVE_SESSION_MAINTENANCE_HOLDS
                || participant
                    .active_hold_ids
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(FleetTransportError::serialization(
                    "epoch-barrier response has an invalid or mismatched held participant",
                ));
            }
            previous_identity = Some(identity);
            for hold in &participant.active_hold_ids {
                validate_action_id(hold)?;
            }
            let last_seen = node.last_seen.ok_or_else(|| {
                FleetTransportError::serialization("epoch-barrier participant lacks a heartbeat")
            })?;
            if last_seen > evidence.observed_at
                || evidence.observed_at.signed_duration_since(last_seen) >= threshold
            {
                return Err(FleetTransportError::stale_state(
                    "epoch-barrier response contains a stale or future heartbeat",
                ));
            }
            validate_node_status(&NodeStatus {
                zone_id: node.zone_id.clone(),
                node_id: node.node_id.clone(),
                last_seen,
                quarantine_version: 0,
                health: NodeHealth::Maintenance,
                applied_actions: node.applied_actions.clone(),
                native_session_drain: node.native_session_drain.clone(),
            })?;
            let drain = node.native_session_drain.as_ref().ok_or_else(|| {
                FleetTransportError::serialization("epoch-barrier participant lacks a native drain")
            })?;
            let attestation = drain.supervisor_attestation.as_ref().ok_or_else(|| {
                FleetTransportError::serialization(
                    "epoch-barrier participant lacks a supervisor signature",
                )
            })?;
            if !drain.fence_held
                || !drain.population_is_terminal()
                || drain.applied_actions != node.expected_actions
                || participant.drain_id != attestation.drain_id
                || participant.generation != attestation.generation
                || participant.admitted_sessions != drain.admitted_sessions
                || participant.terminal_sessions != drain.terminal_sessions
                || participant.session_set_sha256 != drain.session_set_sha256
                || participant.checkpoint_sha256 != attestation.checkpoint_sha256
                || participant.supervisor_key_id != attestation.product_root_key_id
            {
                return Err(FleetTransportError::serialization(
                    "epoch-barrier certificate differs from its signed native population",
                ));
            }
            let root: [u8; 32] = participant
                .supervisor_key_id
                .strip_prefix("ed25519:")
                .and_then(|encoded| hex::decode(encoded).ok())
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    FleetTransportError::serialization("invalid epoch-barrier supervisor key")
                })?;
            let root = ed25519_dalek::VerifyingKey::from_bytes(&root).map_err(|_| {
                FleetTransportError::serialization("invalid epoch-barrier supervisor key")
            })?;
            attestation.verify(drain, &node.node_id, &node.zone_id, &root)?;
            attestation.validate_freshness(evidence.observed_at)?;
        }
        Ok(())
    }
}

/// Acknowledgement for a successful `POST`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHttpAck {
    pub schema_version: String,
    pub accepted: String,
    /// For node heartbeats: the coordinator clock reading it stored as
    /// `last_seen`, so staleness is judged on one clock for the whole fleet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<String>,
}

/// RFC 7807 style error body returned for every non-2xx response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHttpProblem {
    pub schema_version: String,
    pub status: u16,
    pub code: String,
    pub detail: String,
}

/// Validate a bearer token: printable ASCII without whitespace, bounded length.
///
/// # Errors
///
/// Returns a human-readable reason when the token is unusable.
pub fn validate_bearer_token(token: &str) -> Result<(), String> {
    if token.len() < FLEET_HTTP_MIN_TOKEN_LEN {
        return Err(format!(
            "fleet control-plane token must be at least {FLEET_HTTP_MIN_TOKEN_LEN} characters"
        ));
    }
    if token.len() > FLEET_HTTP_MAX_TOKEN_LEN {
        return Err(format!(
            "fleet control-plane token must be at most {FLEET_HTTP_MAX_TOKEN_LEN} characters"
        ));
    }
    if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(
            "fleet control-plane token must be printable ASCII without whitespace".to_string(),
        );
    }
    Ok(())
}

/// Extract the token from an `Authorization` header value (`Bearer <token>`).
#[must_use]
pub fn parse_bearer_header(value: &str) -> Option<&str> {
    let (scheme, token) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

/// Constant-time token comparison (no early exit on the first differing byte).
#[must_use]
pub fn bearer_token_matches(presented: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    // Length is not secret (tokens have a fixed format), but compare digests so
    // the byte comparison itself always runs over equal-length inputs.
    use sha2::{Digest, Sha256};
    let presented_digest = Sha256::digest(presented.as_bytes());
    let expected_digest = Sha256::digest(expected.as_bytes());
    presented_digest.ct_eq(&expected_digest).into()
}

/// Parsed and policy-checked coordinator base URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetControlPlaneUrl {
    base: String,
    loopback: bool,
}

impl FleetControlPlaneUrl {
    /// Parse a coordinator URL such as `http://127.0.0.1:9440` or
    /// `https://fleet.example.com`.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTP(S) schemes, URLs carrying credentials, query strings
    /// or fragments, and plaintext `http://` to a non-loopback host.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let (scheme, rest) = trimmed.split_once("://").ok_or_else(|| {
            format!("fleet control-plane URL `{trimmed}` must start with http:// or https://")
        })?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "fleet control-plane URL scheme `{scheme}` is not supported; use http:// (loopback only) or https://"
            ));
        }
        if rest.contains('?') || rest.contains('#') {
            return Err(
                "fleet control-plane URL must not carry a query string or fragment".to_string(),
            );
        }
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return Err(format!("fleet control-plane URL `{trimmed}` has no host"));
        }
        if authority.contains('@') {
            return Err(
                "fleet control-plane URL must not embed credentials; use the token file"
                    .to_string(),
            );
        }
        let host = authority_host(authority);
        if host.is_empty() {
            return Err(format!("fleet control-plane URL `{trimmed}` has no host"));
        }
        let loopback = host_is_loopback(host);
        if scheme == "http" && !loopback {
            return Err(format!(
                "plaintext http:// to non-loopback host `{host}` would expose the fleet bearer token; \
                 reach a remote coordinator over https:// (e.g. behind a TLS-terminating proxy)"
            ));
        }
        let path = rest[authority.len()..].trim_end_matches('/');
        if !path.is_empty() {
            return Err(format!(
                "fleet control-plane URL must be a bare origin (got path `{path}`); routes are fixed under /v2/fleet"
            ));
        }
        Ok(Self {
            base: format!("{scheme}://{authority}"),
            loopback,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.base
    }

    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.loopback
    }

    #[must_use]
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]:9440`.
        return rest.split(']').next().unwrap_or_default();
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, port)| {
            if port.bytes().all(|byte| byte.is_ascii_digit()) {
                host
            } else {
                authority
            }
        })
}

/// Loopback hosts for which plaintext HTTP is acceptable.
#[must_use]
pub fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Client side of the live fleet control plane.
pub struct HttpFleetTransport {
    url: FleetControlPlaneUrl,
    token: String,
    agent: ureq::Agent,
}

impl std::fmt::Debug for HttpFleetTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpFleetTransport")
            .field("url", &self.url.as_str())
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl HttpFleetTransport {
    /// Build a client for the coordinator at `url`, authenticating with `token`.
    ///
    /// # Errors
    ///
    /// Returns [`FleetTransportError::NotInitialized`] for an unusable URL or
    /// token; nothing is sent over the network here.
    pub fn new(url: &str, token: &str, timeout: Duration) -> Result<Self, FleetTransportError> {
        let url = FleetControlPlaneUrl::parse(url).map_err(FleetTransportError::not_initialized)?;
        let token = token.trim().to_string();
        validate_bearer_token(&token).map_err(FleetTransportError::not_initialized)?;
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            // Origin admission applies to the configured coordinator only. A
            // redirect must not forward an action body or substitute another
            // server's state, even when the HTTP client strips Authorization.
            .max_redirects(0)
            .http_status_as_error(false)
            .build();
        Ok(Self {
            url,
            token,
            agent: ureq::Agent::new_with_config(config),
        })
    }

    #[must_use]
    pub fn url(&self) -> &FleetControlPlaneUrl {
        &self.url
    }

    /// Probe the unauthenticated liveness route.
    ///
    /// # Errors
    ///
    /// Fails when the coordinator is unreachable or answers with anything
    /// other than a well-formed healthy response.
    pub fn health(&self) -> Result<FleetHttpHealth, FleetTransportError> {
        let health: FleetHttpHealth = self.get_json(FLEET_HTTP_HEALTH_PATH, false)?;
        if health.schema_version != FLEET_HTTP_API_SCHEMA || health.status != "ok" {
            return Err(FleetTransportError::stale_state(format!(
                "fleet control plane at {} is not healthy (schema={}, status={})",
                self.url.as_str(),
                health.schema_version,
                health.status
            )));
        }
        Ok(health)
    }

    fn authorization(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        authenticated: bool,
    ) -> Result<T, FleetTransportError> {
        let endpoint = self.url.endpoint(path);
        let mut request = self
            .agent
            .get(&endpoint)
            .header("Accept", "application/json");
        if authenticated {
            request = request.header("Authorization", &self.authorization());
        }
        let response = request
            .call()
            .map_err(|err| self.unreachable(&endpoint, &err))?;
        self.decode(&endpoint, response)
    }

    fn post_json<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, FleetTransportError> {
        self.post_json_with_limits(
            path,
            body,
            FLEET_HTTP_MAX_REQUEST_BYTES,
            FLEET_HTTP_MAX_RESPONSE_BYTES,
        )
    }

    fn post_json_with_limits<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        request_limit: usize,
        response_limit: u64,
    ) -> Result<T, FleetTransportError> {
        let endpoint = self.url.endpoint(path);
        let payload = serde_json::to_vec(body)
            .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
        if payload.len() > request_limit {
            return Err(FleetTransportError::serialization(format!(
                "fleet request body is {} bytes; the route accepts at most {request_limit}",
                payload.len()
            )));
        }
        let response = self
            .agent
            .post(&endpoint)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Authorization", &self.authorization())
            .send(&payload[..])
            .map_err(|err| self.unreachable(&endpoint, &err))?;
        self.decode_with_limit(&endpoint, response, response_limit)
    }

    fn unreachable(&self, endpoint: &str, err: &ureq::Error) -> FleetTransportError {
        FleetTransportError::io(format!(
            "fleet control plane unreachable at {endpoint}: {err}"
        ))
    }

    fn decode<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        response: ureq::http::Response<ureq::Body>,
    ) -> Result<T, FleetTransportError> {
        self.decode_with_limit(endpoint, response, FLEET_HTTP_MAX_RESPONSE_BYTES)
    }

    fn decode_with_limit<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        mut response: ureq::http::Response<ureq::Body>,
        response_limit: u64,
    ) -> Result<T, FleetTransportError> {
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            // Do not consume an untrusted or stalled redirect body and do not
            // expose its Location value as an operator-approved destination.
            return Err(FleetTransportError::io(format!(
                "fleet control plane at {endpoint} returned HTTP {status}; redirects are refused to preserve the configured coordinator origin"
            )));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(response_limit)
            .read_to_vec()
            .map_err(|err| {
                FleetTransportError::io(format!("failed reading response from {endpoint}: {err}"))
            })?;
        if !(200..300).contains(&status) {
            let detail = serde_json::from_slice::<FleetHttpProblem>(&body).map_or_else(
                |_| String::from_utf8_lossy(&body).chars().take(512).collect(),
                |problem| format!("{}: {}", problem.code, problem.detail),
            );
            return Err(match status {
                401 | 403 => FleetTransportError::not_initialized(format!(
                    "fleet control plane at {endpoint} refused the bearer token (HTTP {status}): {detail}"
                )),
                400 | 413 | 422 => FleetTransportError::serialization(format!(
                    "fleet control plane at {endpoint} rejected the request (HTTP {status}): {detail}"
                )),
                409 => FleetTransportError::action_conflict(format!(
                    "fleet control plane at {endpoint} rejected a conflicting action (HTTP {status}): {detail}"
                )),
                423 | 429 | 503 => FleetTransportError::lock_contention(format!(
                    "fleet control plane at {endpoint} is busy (HTTP {status}): {detail}"
                )),
                _ => FleetTransportError::io(format!(
                    "fleet control plane at {endpoint} failed (HTTP {status}): {detail}"
                )),
            });
        }
        serde_json::from_slice(&body).map_err(|err| {
            FleetTransportError::serialization(format!(
                "fleet control plane at {endpoint} returned a malformed body: {err}"
            ))
        })
    }

    fn check_schema(&self, schema_version: &str) -> Result<(), FleetTransportError> {
        if schema_version == FLEET_HTTP_API_SCHEMA {
            return Ok(());
        }
        Err(FleetTransportError::serialization(format!(
            "fleet control plane at {} speaks `{schema_version}`, expected `{FLEET_HTTP_API_SCHEMA}`",
            self.url.as_str()
        )))
    }

    /// Same staleness helper as the local transports, judged on the
    /// coordinator-stamped `last_seen` values.
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

/// Preserve the bounded history required by checkpoint application. Never
/// truncate a remote history, reorder the coordinator's committed sequence, or
/// select one record for a repeated immutable ID.
fn validate_action_snapshot(actions: &[FleetActionRecord]) -> Result<(), FleetTransportError> {
    if actions.len() > MAX_ACTION_LOG_ENTRIES {
        return Err(FleetTransportError::serialization(format!(
            "fleet action snapshot exceeds {MAX_ACTION_LOG_ENTRIES} entries"
        )));
    }
    {
        let mut ids = BTreeSet::new();
        for action in actions.iter() {
            validate_action_record(action)?;
            if !ids.insert(action.action_id.as_str()) {
                return Err(FleetTransportError::serialization(format!(
                    "fleet action snapshot repeats action_id `{}`",
                    action.action_id
                )));
            }
        }
    }
    Ok(())
}

/// Node identity is scoped by zone. An ambiguous or oversized remote snapshot
/// is refused in full; dropping a duplicate could hide an unhealthy heartbeat.
fn validate_node_snapshot(nodes: &mut [NodeStatus]) -> Result<(), FleetTransportError> {
    if nodes.len() > MAX_NODES_CAP {
        return Err(FleetTransportError::serialization(format!(
            "fleet node snapshot exceeds {MAX_NODES_CAP} entries"
        )));
    }
    {
        let mut ids = BTreeSet::new();
        for status in nodes.iter() {
            validate_node_status(status)?;
            if !ids.insert((status.zone_id.as_str(), status.node_id.as_str())) {
                return Err(FleetTransportError::serialization(format!(
                    "fleet node snapshot repeats node `{}/{}`",
                    status.zone_id, status.node_id
                )));
            }
        }
    }
    nodes.sort_by(|left, right| {
        left.zone_id
            .cmp(&right.zone_id)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    Ok(())
}

impl FleetTransport for HttpFleetTransport {
    /// Initialization for a remote store is a health probe plus one
    /// fully validated authenticated node snapshot, so a wrong token or
    /// malformed coordinator state fails here rather than mid-command.
    fn initialize(&mut self) -> Result<(), FleetTransportError> {
        self.health()?;
        self.list_node_statuses().map(|_| ())
    }

    fn publish_action(&mut self, action: &FleetActionRecord) -> Result<(), FleetTransportError> {
        validate_action_record(action)?;
        let ack: FleetHttpAck = self.post_json(FLEET_HTTP_ACTIONS_PATH, action)?;
        self.check_schema(&ack.schema_version)?;
        if ack.accepted != action.action_id {
            return Err(FleetTransportError::stale_state(format!(
                "fleet control plane acknowledged `{}` for published action `{}`",
                ack.accepted, action.action_id
            )));
        }
        Ok(())
    }

    fn publish_policy_with_maintenance_guard(
        &mut self,
        request: &GuardedFleetPolicyPublication,
    ) -> Result<FleetGuardedPolicyReceipt, FleetTransportError> {
        request.validate()?;
        let receipt: FleetGuardedPolicyReceipt = self.post_json_with_limits(
            FLEET_HTTP_GUARDED_POLICY_PATH,
            request,
            MAX_GUARDED_POLICY_REQUEST_BYTES,
            MAX_GUARDED_POLICY_RECEIPT_BYTES as u64,
        )?;
        receipt.validate()?;
        if receipt.action != request.action
            || receipt.guard.hold_action_id != request.guard.hold_action_id
            || receipt.observation_scope
                != FleetGuardedPolicyObservationScope::EnrolledNodeObservations
            || (!receipt.already_published && receipt.guard != request.guard)
        {
            return Err(FleetTransportError::stale_state(
                "fleet coordinator returned a guarded publication receipt for a different action, owner, observation scope or initial request",
            ));
        }
        Ok(receipt)
    }

    /// Refuse histories exceeding the checkpoint/file transport bound, even if
    /// a coordinator's durable store has admitted more records. Retain every
    /// accepted action in the coordinator's append order.
    fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        let listed: FleetHttpActionList = self.get_json(FLEET_HTTP_ACTIONS_PATH, true)?;
        self.check_schema(&listed.schema_version)?;
        validate_action_snapshot(&listed.actions)?;
        Ok(listed.actions)
    }

    fn upsert_node_status(&mut self, status: &NodeStatus) -> Result<(), FleetTransportError> {
        validate_node_status(status)?;
        let ack: FleetHttpAck = self.post_json(FLEET_HTTP_NODES_PATH, status)?;
        self.check_schema(&ack.schema_version)?;
        let expected = format!("{}/{}", status.zone_id, status.node_id);
        if ack.accepted != expected {
            return Err(FleetTransportError::stale_state(format!(
                "fleet control plane acknowledged `{}` for heartbeat `{expected}`",
                ack.accepted
            )));
        }
        Ok(())
    }

    /// Apply the file transport's node-count bound without truncation and
    /// return one validated status per scoped identity, sorted by zone and ID.
    fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
        let mut listed: FleetHttpNodeList = self.get_json(FLEET_HTTP_NODES_PATH, true)?;
        self.check_schema(&listed.schema_version)?;
        validate_node_snapshot(&mut listed.nodes)?;
        Ok(listed.nodes)
    }

    fn read_shared_state(&self) -> Result<FleetSharedState, FleetTransportError> {
        let mut state: FleetHttpState = self.get_json(FLEET_HTTP_STATE_PATH, true)?;
        self.check_schema(&state.schema_version)?;
        if state.state.schema_version != FLEET_SHARED_STATE_SCHEMA {
            return Err(FleetTransportError::serialization(format!(
                "fleet shared state uses `{}`, expected `{FLEET_SHARED_STATE_SCHEMA}`",
                state.state.schema_version
            )));
        }
        validate_action_snapshot(&state.state.actions)?;
        validate_node_snapshot(&mut state.state.nodes)?;
        Ok(state.state)
    }
}

impl HttpFleetTransport {
    /// Request distributed epoch-barrier quiescence certification from the live coordinator.
    pub fn certify_epoch_barrier(
        &self,
        request: &FleetHttpEpochBarrierRequest,
    ) -> Result<FleetHttpEpochBarrierResponse, FleetTransportError> {
        if request.initiator.trim().is_empty()
            || request.reason.trim().is_empty()
            || request.trace_id.trim().is_empty()
            || request.stale_after.is_zero()
        {
            return Err(FleetTransportError::serialization(
                "epoch-barrier requests require an initiator, reason, trace and positive freshness window",
            ));
        }
        let response: FleetHttpEpochBarrierResponse = self.post_json_with_limits(
            FLEET_HTTP_EPOCH_BARRIER_PATH,
            request,
            FLEET_HTTP_MAX_REQUEST_BYTES,
            MAX_GUARDED_POLICY_RECEIPT_BYTES as u64,
        )?;
        response.validate_for_request(request)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certified_epoch_response() -> (FleetHttpEpochBarrierRequest, FleetHttpEpochBarrierResponse) {
        use std::collections::BTreeMap;

        use chrono::{DateTime, Utc};
        use ed25519_dalek::{Signer, SigningKey};

        use super::super::fleet_transport::{
            FleetAction, FleetEpochBarrierParams, NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA,
            NativeSessionDrainAttestation, NativeSessionDrainCheckpoint,
            certify_fleet_epoch_quiescence, fleet_application_checkpoint,
        };
        use crate::control_plane::control_epoch::EpochSigningKey;
        use crate::control_plane::epoch_transition_barrier::BarrierConfig;
        use crate::runtime::epoch_transition::ProductEpochCoordinator;

        let now = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let key = SigningKey::from_bytes(&[73; 32]);
        let actions = vec![FleetActionRecord {
            action_id: "hold-client-contract".to_string(),
            emitted_at: now,
            action: FleetAction::NativeSessionHold {
                zone_id: "east".to_string(),
                reason: "certify a closed admission population".to_string(),
            },
        }];
        let applied = fleet_application_checkpoint(&actions, "east").unwrap();
        let mut drain = NativeSessionDrainCheckpoint {
            applied_actions: applied.clone(),
            session_set_sha256: "ab".repeat(32),
            admitted_sessions: 2,
            terminal_sessions: 2,
            pending_sessions: 0,
            indeterminate_sessions: 0,
            fence_held: true,
            supervisor_attestation: None,
        };
        let mut attestation = NativeSessionDrainAttestation {
            schema_version: NATIVE_SESSION_DRAIN_ATTESTATION_SCHEMA.to_string(),
            node_id: "node-a".to_string(),
            zone_id: "east".to_string(),
            drain_id: uuid::Uuid::from_u128(1).to_string(),
            generation: 1,
            project_root_sha256: "cd".repeat(32),
            observed_at: now,
            product_root_key_id: format!("ed25519:{}", hex::encode(key.verifying_key().as_bytes())),
            checkpoint_sha256: drain.observation_sha256().unwrap(),
            signature_hex: String::new(),
        };
        attestation.signature_hex =
            hex::encode(key.sign(&attestation.signing_payload().unwrap()).to_bytes());
        drain.supervisor_attestation = Some(attestation);
        let state = FleetSharedState {
            schema_version: FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions,
            nodes: vec![NodeStatus {
                zone_id: "east".to_string(),
                node_id: "node-a".to_string(),
                last_seen: now,
                quarantine_version: 1,
                health: NodeHealth::Maintenance,
                applied_actions: Some(applied),
                native_session_drain: Some(drain),
            }],
        };
        let roots = BTreeMap::from([(
            ("east".to_string(), "node-a".to_string()),
            key.verifying_key(),
        )]);
        let request = FleetHttpEpochBarrierRequest {
            initiator: "operator".to_string(),
            reason: "advance while admissions are closed".to_string(),
            trace_id: "trace-epoch-client".to_string(),
            stale_after: Duration::from_secs(30),
        };
        let mut coordinator = ProductEpochCoordinator::new(
            7,
            2,
            BarrierConfig::default(),
            EpochSigningKey::new(b"epoch-client-contract-signing-key").unwrap(),
        );
        let (evidence, certificate) = certify_fleet_epoch_quiescence(
            &mut coordinator,
            &state,
            &roots,
            FleetEpochBarrierParams {
                initiator: &request.initiator,
                reason: &request.reason,
                now,
                stale_after: request.stale_after,
                trace_id: &request.trace_id,
            },
        )
        .unwrap();
        (
            request,
            FleetHttpEpochBarrierResponse {
                schema_version: FLEET_HTTP_API_SCHEMA.to_string(),
                evidence,
                certificate,
            },
        )
    }

    #[test]
    fn epoch_response_accepts_actual_signed_barrier_certificate() {
        let (request, response) = certified_epoch_response();
        response.validate_for_request(&request).unwrap();
        assert_eq!(response.certificate.pre_epoch, 7);
        assert_eq!(response.certificate.committed_epoch, 8);
    }

    #[test]
    fn epoch_response_rejects_request_population_and_attestation_substitution() {
        type Mutation = fn(&mut FleetHttpEpochBarrierResponse);
        let cases: &[(&str, Mutation)] = &[
            ("other trace", |r| r.certificate.trace_id.push_str("-other")),
            ("other initiator", |r| {
                r.certificate.initiator.push_str("-other")
            }),
            ("other reason", |r| r.certificate.reason.push_str("-other")),
            ("epoch skip", |r| r.certificate.committed_epoch += 1),
            ("epoch overflow", |r| {
                r.certificate.pre_epoch = u64::MAX;
                r.certificate.committed_epoch = 0;
            }),
            ("no transition", |r| r.certificate.transition_id.clear()),
            ("empty population", |r| {
                r.evidence.nodes.clear();
                r.certificate.participants.clear();
            }),
            ("missing participant", |r| {
                r.certificate.participants.clear()
            }),
            ("duplicate population", |r| {
                r.evidence.nodes.push(r.evidence.nodes[0].clone());
                r.certificate
                    .participants
                    .push(r.certificate.participants[0].clone());
            }),
            ("incomplete evidence", |r| r.evidence.complete = false),
            ("uncovered zone", |r| {
                r.evidence.uncovered_zones.push("west".to_string())
            }),
            ("different observation time", |r| {
                r.evidence.observed_at += chrono::TimeDelta::seconds(1);
            }),
            ("weaker freshness", |r| {
                r.evidence.stale_after = Duration::from_secs(31)
            }),
            ("action population differs", |r| {
                r.evidence.action_count += 1
            }),
            ("invalid action digest", |r| {
                r.certificate.action_log_checkpoint.actions_sha256 = "invalid".to_string();
            }),
            ("other node", |r| {
                r.certificate.participants[0].node_id = "node-b".to_string()
            }),
            ("wrong acknowledgement stage", |r| {
                r.certificate.participants[0].stage = FleetAcknowledgementStage::PolicyApplied;
            }),
            ("missing hold", |r| {
                r.certificate.participants[0].active_hold_ids.clear()
            }),
            ("duplicate hold", |r| {
                r.certificate.participants[0]
                    .active_hold_ids
                    .push("hold-client-contract".to_string());
            }),
            ("unsafe hold identity", |r| {
                r.certificate.participants[0].active_hold_ids[0] = "../hold".to_string();
            }),
            ("unready node", |r| r.evidence.nodes[0].ready = false),
            ("contradictory readiness", |r| {
                r.evidence.nodes[0].reason = FleetNativeDrainReadiness::HoldNotActive;
            }),
            ("admission reopened", |r| {
                r.evidence.nodes[0].health = Some(NodeHealth::Healthy)
            }),
            ("missing heartbeat", |r| {
                r.evidence.nodes[0].last_seen = None
            }),
            ("stale heartbeat", |r| {
                r.evidence.nodes[0].last_seen =
                    Some(r.evidence.observed_at - chrono::TimeDelta::seconds(30));
            }),
            ("future heartbeat", |r| {
                r.evidence.nodes[0].last_seen =
                    Some(r.evidence.observed_at + chrono::TimeDelta::seconds(1));
            }),
            ("different action snapshot", |r| {
                r.evidence.nodes[0].expected_actions.actions_sha256 = "ef".repeat(32);
            }),
            ("missing drain", |r| {
                r.evidence.nodes[0].native_session_drain = None
            }),
            ("missing signature", |r| {
                r.evidence.nodes[0]
                    .native_session_drain
                    .as_mut()
                    .unwrap()
                    .supervisor_attestation = None;
            }),
            ("other drain generation", |r| {
                r.certificate.participants[0].generation += 1
            }),
            ("other session population", |r| {
                r.certificate.participants[0].admitted_sessions += 1
            }),
            ("other checkpoint", |r| {
                r.certificate.participants[0].checkpoint_sha256 = "ef".repeat(32)
            }),
            ("invalid signature", |r| {
                r.evidence.nodes[0]
                    .native_session_drain
                    .as_mut()
                    .unwrap()
                    .supervisor_attestation
                    .as_mut()
                    .unwrap()
                    .signature_hex = "00".repeat(64);
            }),
        ];
        let (request, response) = certified_epoch_response();
        response.validate_for_request(&request).unwrap();
        for (label, mutate) in cases {
            let mut changed = response.clone();
            mutate(&mut changed);
            assert!(changed.validate_for_request(&request).is_err(), "{label}");
        }
    }

    #[test]
    fn epoch_response_rejects_expired_but_cryptographically_valid_supervisor_evidence() {
        use ed25519_dalek::{Signer, SigningKey};

        let (request, mut response) = certified_epoch_response();
        let drain = response.evidence.nodes[0]
            .native_session_drain
            .as_mut()
            .unwrap();
        let attestation = drain.supervisor_attestation.as_mut().unwrap();
        attestation.observed_at -= chrono::TimeDelta::seconds(301);
        let key = SigningKey::from_bytes(&[73; 32]);
        attestation.signature_hex =
            hex::encode(key.sign(&attestation.signing_payload().unwrap()).to_bytes());
        drain
            .supervisor_attestation
            .as_ref()
            .unwrap()
            .verify(drain, "node-a", "east", &key.verifying_key())
            .unwrap();
        let error = response.validate_for_request(&request).unwrap_err();
        assert!(error.to_string().contains("expired"), "{error}");
    }

    #[test]
    fn invalid_epoch_requests_are_rejected_before_network_access() {
        let client = HttpFleetTransport::new(
            "http://127.0.0.1:1",
            "0123456789abcdef0123456789abcdef",
            Duration::from_secs(1),
        )
        .unwrap();
        let (request, _) = certified_epoch_response();
        for field in ["initiator", "reason", "trace", "freshness"] {
            let mut invalid = request.clone();
            match field {
                "initiator" => invalid.initiator.clear(),
                "reason" => invalid.reason.clear(),
                "trace" => invalid.trace_id.clear(),
                _ => invalid.stale_after = Duration::ZERO,
            }
            let error = client.certify_epoch_barrier(&invalid).unwrap_err();
            assert!(
                error.to_string().contains("positive freshness window"),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn loopback_http_urls_are_accepted() {
        for raw in [
            "http://127.0.0.1:9440",
            "http://localhost:9440/",
            "http://[::1]:9440",
            "HTTP://127.0.0.1",
        ] {
            let url = FleetControlPlaneUrl::parse(raw).expect(raw);
            assert!(url.is_loopback(), "{raw}");
            assert!(!url.as_str().ends_with('/'), "{raw}");
        }
        let url = FleetControlPlaneUrl::parse("http://127.0.0.1:9440").expect("parse");
        assert_eq!(
            url.endpoint(FLEET_HTTP_ACTIONS_PATH),
            "http://127.0.0.1:9440/v2/fleet/actions"
        );
    }

    #[test]
    fn plaintext_remote_urls_are_refused() {
        let err = FleetControlPlaneUrl::parse("http://10.0.0.5:9440").expect_err("refused");
        assert!(err.contains("https://"), "{err}");
        let err = FleetControlPlaneUrl::parse("http://fleet.example.com").expect_err("refused");
        assert!(err.contains("bearer token"), "{err}");
    }

    #[test]
    fn https_remote_urls_are_accepted() {
        let url = FleetControlPlaneUrl::parse("https://fleet.example.com:8443").expect("https");
        assert!(!url.is_loopback());
        assert_eq!(url.as_str(), "https://fleet.example.com:8443");
    }

    #[test]
    fn malformed_urls_are_refused() {
        for raw in [
            "",
            "127.0.0.1:9440",
            "ftp://127.0.0.1",
            "http://",
            "http://user:pw@127.0.0.1:9440",
            "http://127.0.0.1:9440/v2/fleet",
            "http://127.0.0.1:9440/?x=1",
            "https://fleet.example.com#frag",
        ] {
            assert!(FleetControlPlaneUrl::parse(raw).is_err(), "{raw} accepted");
        }
    }

    #[test]
    fn bearer_tokens_are_validated() {
        assert!(validate_bearer_token(&"a".repeat(FLEET_HTTP_MIN_TOKEN_LEN)).is_ok());
        assert!(validate_bearer_token(&"a".repeat(FLEET_HTTP_MIN_TOKEN_LEN - 1)).is_err());
        assert!(validate_bearer_token(&"a".repeat(FLEET_HTTP_MAX_TOKEN_LEN + 1)).is_err());
        let mut spaced = "a".repeat(FLEET_HTTP_MIN_TOKEN_LEN);
        spaced.push(' ');
        spaced.push('b');
        assert!(validate_bearer_token(&spaced).is_err());
        let mut control = "a".repeat(FLEET_HTTP_MIN_TOKEN_LEN);
        control.push('\u{7}');
        assert!(validate_bearer_token(&control).is_err());
    }

    #[test]
    fn bearer_header_parsing_is_strict() {
        assert_eq!(parse_bearer_header("Bearer abc"), Some("abc"));
        assert_eq!(parse_bearer_header("bearer   abc  "), Some("abc"));
        assert_eq!(parse_bearer_header("Basic abc"), None);
        assert_eq!(parse_bearer_header("Bearer "), None);
        assert_eq!(parse_bearer_header("Bearer"), None);
        assert_eq!(parse_bearer_header(""), None);
    }

    #[test]
    fn token_comparison_is_exact() {
        let token = "f".repeat(64);
        assert!(bearer_token_matches(&token, &token));
        assert!(!bearer_token_matches(&"e".repeat(64), &token));
        assert!(!bearer_token_matches(&"f".repeat(63), &token));
        assert!(!bearer_token_matches("", &token));
    }

    #[test]
    fn client_construction_rejects_bad_inputs_without_network() {
        let token = "0123456789abcdef0123456789abcdef";
        assert!(
            HttpFleetTransport::new("http://10.1.2.3:1", token, FLEET_HTTP_DEFAULT_TIMEOUT)
                .is_err()
        );
        assert!(
            HttpFleetTransport::new("http://127.0.0.1:1", "short", FLEET_HTTP_DEFAULT_TIMEOUT)
                .is_err()
        );
        let client =
            HttpFleetTransport::new("http://127.0.0.1:1", token, FLEET_HTTP_DEFAULT_TIMEOUT)
                .expect("valid client");
        assert!(
            !format!("{client:?}").contains(token),
            "token must be redacted"
        );
    }

    #[test]
    fn unreachable_coordinator_fails_closed() {
        // Port 1 on loopback is reserved and refuses connections.
        let mut client = HttpFleetTransport::new(
            "http://127.0.0.1:1",
            "0123456789abcdef0123456789abcdef",
            Duration::from_secs(2),
        )
        .expect("client");
        let err = client.initialize().expect_err("nothing listens on port 1");
        assert!(err.to_string().contains("unreachable"), "{err}");
    }
}
