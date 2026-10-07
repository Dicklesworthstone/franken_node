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
//! * every request except `GET /v1/fleet/health` carries
//!   `Authorization: Bearer <token>`; the coordinator compares it in constant
//!   time and answers `401` otherwise;
//! * plaintext `http://` is accepted only for loopback hosts; a remote
//!   coordinator must be reached over `https://` (for example behind a
//!   TLS-terminating proxy) so the bearer token never crosses a network in
//!   clear text;
//! * response bodies are size-bounded before they are parsed, and every
//!   record the coordinator returns is re-validated by the client with the
//!   same rules the coordinator applies on ingest.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::fleet_transport::{
    FleetActionRecord, FleetSharedState, FleetTransport, FleetTransportError, NodeStatus,
    validate_action_record, validate_node_status,
};

/// Schema tag carried by every fleet HTTP API response body.
pub const FLEET_HTTP_API_SCHEMA: &str = "franken-node/fleet-http-api/v1";
/// Liveness probe; the only unauthenticated route.
pub const FLEET_HTTP_HEALTH_PATH: &str = "/v1/fleet/health";
/// `GET` lists actions, `POST` publishes one.
pub const FLEET_HTTP_ACTIONS_PATH: &str = "/v1/fleet/actions";
/// `GET` lists node statuses, `POST` upserts one (heartbeat).
pub const FLEET_HTTP_NODES_PATH: &str = "/v1/fleet/nodes";
/// `GET` returns the consolidated shared state (actions + nodes).
pub const FLEET_HTTP_STATE_PATH: &str = "/v1/fleet/state";
/// Upper bound on any request body the coordinator accepts.
pub const FLEET_HTTP_MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Upper bound on any response body the client reads.
pub const FLEET_HTTP_MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
/// Shortest accepted bearer token (hex-encoded 128 bits).
pub const FLEET_HTTP_MIN_TOKEN_LEN: usize = 32;
/// Longest accepted bearer token.
pub const FLEET_HTTP_MAX_TOKEN_LEN: usize = 512;
/// Default per-request client timeout.
pub const FLEET_HTTP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// `GET /v1/fleet/health` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHttpHealth {
    pub schema_version: String,
    pub status: String,
    pub service: String,
    pub store: String,
}

/// `GET /v1/fleet/actions` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHttpActionList {
    pub schema_version: String,
    pub actions: Vec<FleetActionRecord>,
}

/// `GET /v1/fleet/nodes` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHttpNodeList {
    pub schema_version: String,
    pub nodes: Vec<NodeStatus>,
}

/// `GET /v1/fleet/state` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHttpState {
    pub schema_version: String,
    pub state: FleetSharedState,
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
                "fleet control-plane URL must be a bare origin (got path `{path}`); routes are fixed under /v1/fleet"
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
        let endpoint = self.url.endpoint(path);
        let payload = serde_json::to_vec(body)
            .map_err(|err| FleetTransportError::serialization(err.to_string()))?;
        if payload.len() > FLEET_HTTP_MAX_REQUEST_BYTES {
            return Err(FleetTransportError::serialization(format!(
                "fleet request body is {} bytes; the coordinator accepts at most {FLEET_HTTP_MAX_REQUEST_BYTES}",
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
        self.decode(&endpoint, response)
    }

    fn unreachable(&self, endpoint: &str, err: &ureq::Error) -> FleetTransportError {
        FleetTransportError::io(format!(
            "fleet control plane unreachable at {endpoint}: {err}"
        ))
    }

    fn decode<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        mut response: ureq::http::Response<ureq::Body>,
    ) -> Result<T, FleetTransportError> {
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(FLEET_HTTP_MAX_RESPONSE_BYTES)
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

impl FleetTransport for HttpFleetTransport {
    /// Initialization for a remote store is a health probe plus one
    /// authenticated read, so a wrong token fails here rather than mid-command.
    fn initialize(&mut self) -> Result<(), FleetTransportError> {
        self.health()?;
        let listed: FleetHttpNodeList = self.get_json(FLEET_HTTP_NODES_PATH, true)?;
        self.check_schema(&listed.schema_version)
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

    fn list_actions(&self) -> Result<Vec<FleetActionRecord>, FleetTransportError> {
        let listed: FleetHttpActionList = self.get_json(FLEET_HTTP_ACTIONS_PATH, true)?;
        self.check_schema(&listed.schema_version)?;
        for action in &listed.actions {
            validate_action_record(action)?;
        }
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

    fn list_node_statuses(&self) -> Result<Vec<NodeStatus>, FleetTransportError> {
        let listed: FleetHttpNodeList = self.get_json(FLEET_HTTP_NODES_PATH, true)?;
        self.check_schema(&listed.schema_version)?;
        for status in &listed.nodes {
            validate_node_status(status)?;
        }
        Ok(listed.nodes)
    }

    fn read_shared_state(&self) -> Result<FleetSharedState, FleetTransportError> {
        let state: FleetHttpState = self.get_json(FLEET_HTTP_STATE_PATH, true)?;
        self.check_schema(&state.schema_version)?;
        for action in &state.state.actions {
            validate_action_record(action)?;
        }
        for status in &state.state.nodes {
            validate_node_status(status)?;
        }
        Ok(state.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "http://127.0.0.1:9440/v1/fleet/actions"
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
            "http://127.0.0.1:9440/v1/fleet",
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
