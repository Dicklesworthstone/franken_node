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
    FLEET_SHARED_STATE_SCHEMA, FleetAcknowledgementStage, FleetActionLogCheckpoint,
    FleetActionRecord, FleetCertifiedEpochBoundary, FleetEpochBarrierOperation,
    FleetEpochCommitProof, FleetEpochQuiescenceCertificate, FleetGuardedPolicyObservationScope,
    FleetGuardedPolicyReceipt, FleetNativeDrainEvidence, FleetNativeDrainReadiness,
    FleetSharedState, FleetTransport, FleetTransportError, GuardedFleetPolicyPublication,
    MAX_GUARDED_POLICY_RECEIPT_BYTES, MAX_GUARDED_POLICY_REQUEST_BYTES,
    MAX_GUARDED_POLICY_STALE_AFTER, MAX_NATIVE_SESSION_MAINTENANCE_HOLDS, NodeHealth, NodeStatus,
    fleet_epoch_operation_request_sha256, validate_action_id, validate_action_record,
    validate_node_status,
};
use super::fleet_transport::{FleetGuardedResumeReceipt, GuardedFleetNativeSessionResume};

/// Schema for ordinary responses; v2 binds coordinator append order.
pub const FLEET_HTTP_API_SCHEMA: &str = "franken-node/fleet-http-api/v2";
/// Stronger envelope only for independently signed epoch commit responses.
pub const FLEET_HTTP_EPOCH_COMMIT_RESPONSE_SCHEMA: &str =
    "franken-node/fleet-epoch-commit-response/v1";
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
/// `POST` checks post-policy acknowledgements and atomically releases one owner.
pub const FLEET_HTTP_GUARDED_RESUME_PATH: &str = "/v2/fleet/maintenance/guarded-resume";
/// `POST` proposes, verifies enrolled supervisor drains, and commits an epoch transition barrier.
pub const FLEET_HTTP_EPOCH_BARRIER_PATH: &str = "/v2/fleet/epoch-barrier";
/// Operator-only retained commit export; append a canonical positive epoch.
pub const FLEET_HTTP_EPOCH_COMMITS_PREFIX: &str = "/v2/fleet/epoch-commits/";
pub const FLEET_HTTP_EPOCH_COMMIT_ROUTE: &str = "/v2/fleet/epoch-commits/{epoch}";
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
    /// Stable identity for retrying exactly one epoch commit. Recovery returns
    /// historical evidence; it never certifies the current session population.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// Optional full action snapshot required for the first commit. A retry
    /// retains this original precondition even when the live log has advanced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_action_log: Option<FleetActionLogCheckpoint>,
    pub initiator: String,
    pub reason: String,
    pub trace_id: String,
    pub stale_after: Duration,
}

impl FleetHttpEpochBarrierRequest {
    pub(crate) fn validate(&self) -> Result<(), FleetTransportError> {
        if self.initiator.trim().is_empty()
            || self.reason.trim().is_empty()
            || self.trace_id.trim().is_empty()
            || self.stale_after.is_zero()
        {
            return Err(FleetTransportError::serialization(
                "epoch-barrier requests require an initiator, reason, trace and positive freshness window",
            ));
        }
        if let Some(operation_id) = &self.operation_id {
            validate_action_id(operation_id)?;
        }
        if let Some(expected) = &self.expected_action_log {
            expected.validate()?;
        }
        Ok(())
    }

    fn operation_request_sha256(&self) -> Result<Option<String>, FleetTransportError> {
        self.operation_id
            .as_deref()
            .map(|operation_id| {
                fleet_epoch_operation_request_sha256(
                    operation_id,
                    &self.initiator,
                    &self.reason,
                    &self.trace_id,
                    self.stale_after,
                    self.expected_action_log.as_ref(),
                )
            })
            .transpose()
    }
}

/// `POST /v2/fleet/epoch-barrier` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetHttpEpochBarrierResponse {
    pub schema_version: String,
    /// True for recovery/export of a historical commit. Its timestamp and
    /// supervisor evidence are unchanged and establish no present quiescence.
    #[serde(default)]
    pub already_committed: bool,
    pub evidence: FleetNativeDrainEvidence,
    pub certificate: FleetEpochQuiescenceCertificate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_proof: Option<FleetEpochCommitProof>,
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
        request.validate()?;
        self.validate_observation(request)?;
        if self.certificate.operation_id != request.operation_id
            || self.certificate.operation_request_sha256 != request.operation_request_sha256()?
            || (self.already_committed && request.operation_id.is_none())
            || (request.operation_id.is_some() && self.commit_proof.is_none())
            || request
                .expected_action_log
                .as_ref()
                .is_some_and(|expected| expected != &self.certificate.action_log_checkpoint)
        {
            return Err(FleetTransportError::stale_state(
                "epoch-barrier response does not bind the exact requested operation or action snapshot",
            ));
        }
        Ok(())
    }

    /// Check the historical observation independently of its original request.
    /// Export knows the epoch, not the unclamped freshness or optional original
    /// precondition; its signed operation digest must not be reconstructed from
    /// a fabricated request.
    fn validate_observation(
        &self,
        request: &FleetHttpEpochBarrierRequest,
    ) -> Result<(), FleetTransportError> {
        let evidence = &self.evidence;
        let certificate = &self.certificate;
        let valid_envelope = match &self.commit_proof {
            Some(_) => self.schema_version == FLEET_HTTP_EPOCH_COMMIT_RESPONSE_SCHEMA,
            None => self.schema_version == FLEET_HTTP_API_SCHEMA,
        };
        if !valid_envelope
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
        match (
            certificate.operation_id.as_deref(),
            certificate.operation_request_sha256.as_deref(),
        ) {
            (None, None) => {}
            (Some(operation_id), Some(digest)) => {
                validate_action_id(operation_id)?;
                if digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(FleetTransportError::serialization(
                        "epoch operation request digest must be lowercase SHA-256",
                    ));
                }
            }
            _ => {
                return Err(FleetTransportError::serialization(
                    "epoch operation identity and request digest must be present together",
                ));
            }
        }
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
            attestation
                .validate_freshness_with_limit(evidence.observed_at, evidence.stale_after)?;
        }
        if let Some(proof) = &self.commit_proof {
            proof.verify_integrity(evidence, certificate)?;
        }
        Ok(())
    }

    fn validate_for_export(&self, epoch: u64) -> Result<(), FleetTransportError> {
        if self.schema_version != FLEET_HTTP_EPOCH_COMMIT_RESPONSE_SCHEMA
            || self.commit_proof.is_none()
            || self.certificate.committed_epoch != epoch
        {
            return Err(FleetTransportError::stale_state(
                "coordinator did not return an independently signed commit for the requested epoch",
            ));
        }
        self.validate_observation(&FleetHttpEpochBarrierRequest {
            operation_id: self.certificate.operation_id.clone(),
            expected_action_log: None,
            initiator: self.certificate.initiator.clone(),
            reason: self.certificate.reason.clone(),
            trace_id: self.certificate.trace_id.clone(),
            stale_after: self.evidence.stale_after,
        })
    }
}

fn validate_guarded_policy_response(
    request: &GuardedFleetPolicyPublication,
    receipt: &FleetGuardedPolicyReceipt,
) -> Result<(), FleetTransportError> {
    receipt.validate()?;
    if receipt.action != request.action
        || receipt.guard.hold_action_id != request.guard.hold_action_id
        || receipt.guard.certified_epoch != request.guard.certified_epoch
        || receipt.observation_scope != FleetGuardedPolicyObservationScope::EnrolledNodeObservations
        || (!receipt.already_published && receipt.guard != request.guard)
    {
        return Err(FleetTransportError::stale_state(
            "fleet coordinator returned a guarded publication receipt for a different action, owner, certified epoch, observation scope or initial request",
        ));
    }
    Ok(())
}

fn validate_guarded_resume_response(
    request: &GuardedFleetNativeSessionResume,
    receipt: &FleetGuardedResumeReceipt,
) -> Result<(), FleetTransportError> {
    receipt.validate()?;
    if receipt.request.action != request.action
        || receipt.request.policy_action != request.policy_action
        || receipt.request.guard.hold_action_id != request.guard.hold_action_id
        || receipt.request.guard.certified_epoch != request.guard.certified_epoch
        || receipt.observation_scope != FleetGuardedPolicyObservationScope::EnrolledNodeObservations
        || (!receipt.already_resumed && receipt.request != *request)
    {
        return Err(FleetTransportError::stale_state(
            "fleet coordinator returned a guarded resume for a different action, policy, owner, certified epoch or request",
        ));
    }
    Ok(())
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
    timeout: Duration,
    operation_deadline: Option<std::time::Instant>,
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
            timeout,
            operation_deadline: None,
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

    fn request_agent(&self) -> Result<ureq::Agent, FleetTransportError> {
        let Some(deadline) = self.operation_deadline else {
            return Ok(self.agent.clone());
        };
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| FleetTransportError::stale_state("fleet operation deadline elapsed"))?;
        // One budget covers every request and response body, including health
        // probes and retries; each request receives only its remaining share.
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout.min(remaining)))
            .max_redirects(0)
            .http_status_as_error(false)
            .build();
        Ok(ureq::Agent::new_with_config(config))
    }

    fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        authenticated: bool,
    ) -> Result<T, FleetTransportError> {
        self.get_json_with_limit(path, authenticated, FLEET_HTTP_MAX_RESPONSE_BYTES)
    }

    fn get_json_with_limit<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        authenticated: bool,
        response_limit: u64,
    ) -> Result<T, FleetTransportError> {
        let endpoint = self.url.endpoint(path);
        let agent = self.request_agent()?;
        let mut request = agent.get(&endpoint).header("Accept", "application/json");
        if authenticated {
            request = request.header("Authorization", &self.authorization());
        }
        let response = request
            .call()
            .map_err(|err| self.unreachable(&endpoint, &err))?;
        self.decode_with_limit(&endpoint, response, response_limit)
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
        let agent = self.request_agent()?;
        let response = agent
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
    fn supports_certified_maintenance(&self) -> bool {
        true
    }

    fn certify_maintenance_epoch(
        &self,
        operation: &FleetEpochBarrierOperation,
    ) -> Result<FleetCertifiedEpochBoundary, FleetTransportError> {
        operation.validate()?;
        let response = self.certify_epoch_barrier(&FleetHttpEpochBarrierRequest {
            operation_id: Some(operation.operation_id.clone()),
            expected_action_log: Some(operation.expected_action_log.clone()),
            initiator: operation.initiator.clone(),
            reason: operation.reason.clone(),
            trace_id: operation.trace_id.clone(),
            stale_after: operation.stale_after,
        })?;
        let boundary = FleetCertifiedEpochBoundary {
            already_committed: response.already_committed,
            evidence: response.evidence,
            certificate: response.certificate,
            commit_proof: response.commit_proof.ok_or_else(|| {
                FleetTransportError::stale_state(
                    "certified maintenance requires an independent coordinator commit proof",
                )
            })?,
        };
        boundary.validate_for_operation(operation)?;
        Ok(boundary)
    }
    fn set_operation_deadline(
        &mut self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), FleetTransportError> {
        self.operation_deadline = deadline;
        Ok(())
    }

    fn resume_native_sessions_with_maintenance_guard(
        &mut self,
        request: &GuardedFleetNativeSessionResume,
    ) -> Result<FleetGuardedResumeReceipt, FleetTransportError> {
        request.validate()?;
        let receipt: FleetGuardedResumeReceipt = self.post_json_with_limits(
            FLEET_HTTP_GUARDED_RESUME_PATH,
            request,
            MAX_GUARDED_POLICY_REQUEST_BYTES,
            MAX_GUARDED_POLICY_RECEIPT_BYTES as u64,
        )?;
        validate_guarded_resume_response(request, &receipt)?;
        Ok(receipt)
    }

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
        validate_guarded_policy_response(request, &receipt)?;
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
    /// Retrieve an exact historical signed commit. Export never starts a
    /// barrier or renews supervisor observations; independent trust requires
    /// caller-enrolled roots, as provided by the standalone verifier.
    pub fn export_epoch_commit(
        &self,
        epoch: u64,
    ) -> Result<FleetHttpEpochBarrierResponse, FleetTransportError> {
        if epoch == 0 {
            return Err(FleetTransportError::serialization(
                "a committed fleet epoch must be positive",
            ));
        }
        let mut response: FleetHttpEpochBarrierResponse = self.get_json_with_limit(
            &format!("{FLEET_HTTP_EPOCH_COMMITS_PREFIX}{epoch}"),
            true,
            MAX_GUARDED_POLICY_RECEIPT_BYTES as u64,
        )?;
        response.validate_for_export(epoch)?;
        // This read-only route retrieves an existing commit. Older servers
        // omit the unsigned transport hint; the verified epoch and proof
        // establish its identity independently of that presentation field.
        response.already_committed = true;
        Ok(response)
    }

    /// Request distributed epoch-barrier quiescence certification from the live coordinator.
    pub fn certify_epoch_barrier(
        &self,
        request: &FleetHttpEpochBarrierRequest,
    ) -> Result<FleetHttpEpochBarrierResponse, FleetTransportError> {
        request.validate()?;
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
            operation_id: None,
            expected_action_log: None,
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
                operation_id: None,
                operation_request_sha256: None,
                expected_action_log: None,
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
                already_committed: false,
                evidence,
                certificate,
                commit_proof: None,
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
    fn epoch_operation_response_binds_unclamped_request_and_exports_original_proof() {
        let (mut request, mut response) = certified_epoch_response();
        request.operation_id = Some("retryable-client-operation".to_owned());
        request.expected_action_log = Some(response.certificate.action_log_checkpoint.clone());
        request.stale_after = Duration::from_secs(301);
        response.evidence.stale_after = MAX_GUARDED_POLICY_STALE_AFTER;
        response.certificate.operation_id = request.operation_id.clone();
        response.certificate.operation_request_sha256 = request.operation_request_sha256().unwrap();
        let signer = super::super::fleet_transport::FleetEpochCommitSigner::new(
            "coordinator-test",
            ed25519_dalek::SigningKey::from_bytes(&[43; 32]),
        )
        .unwrap();
        let authorization = signer
            .authorize(&response.evidence, &response.certificate)
            .unwrap();
        response.commit_proof = Some(
            signer
                .attest_committed(authorization, &response.evidence, &response.certificate)
                .unwrap(),
        );
        response.schema_version = FLEET_HTTP_EPOCH_COMMIT_RESPONSE_SCHEMA.to_owned();
        response.validate_for_request(&request).unwrap();
        response.validate_for_export(8).unwrap();
        response.already_committed = true;
        response.validate_for_request(&request).unwrap();
        response.validate_for_export(8).unwrap();

        for field in 0..4 {
            let mut changed = request.clone();
            match field {
                0 => changed.operation_id = Some("another-operation".to_owned()),
                1 => changed.expected_action_log = None,
                2 => changed.stale_after = Duration::from_secs(302),
                _ => changed.operation_id = None,
            }
            assert!(
                response.validate_for_request(&changed).is_err(),
                "changed original request field {field} must not recover another intent"
            );
        }

        response.commit_proof = None;
        response.schema_version = FLEET_HTTP_API_SCHEMA.to_owned();
        assert!(
            response.validate_for_request(&request).is_err(),
            "retryable operations require an independently signed retained commit"
        );
        response.certificate.operation_request_sha256 = None;
        assert!(response.validate_for_request(&request).is_err());
    }

    #[test]
    fn epoch_operation_client_checks_ids_and_snapshot_preconditions_before_network_io() {
        let (mut request, mut response) = certified_epoch_response();
        request.operation_id = Some("../invalid".to_owned());
        assert!(request.validate().is_err());
        request.operation_id = None;
        request.expected_action_log = Some(response.certificate.action_log_checkpoint.clone());
        request.expected_action_log.as_mut().unwrap().actions_sha256 = "invalid".to_owned();
        assert!(request.validate().is_err());
        request.expected_action_log = Some(response.certificate.action_log_checkpoint.clone());
        request.expected_action_log.as_mut().unwrap().actions_sha256 = "00".repeat(32);
        request.validate().unwrap();
        assert!(response.validate_for_request(&request).is_err());
        request.expected_action_log = Some(response.certificate.action_log_checkpoint.clone());
        response.validate_for_request(&request).unwrap();

        response.already_committed = true;
        assert!(
            response.validate_for_request(&request).is_err(),
            "one-shot certification cannot be silently answered with historical recovery"
        );
    }

    #[test]
    fn epoch_response_does_not_renew_signed_observations_with_fresh_heartbeats() {
        use ed25519_dalek::{Signer, SigningKey};

        let (mut request, mut response) = certified_epoch_response();
        let observed = response.evidence.observed_at;
        let now = observed + chrono::Duration::seconds(30);
        response.evidence.observed_at = now;
        response.certificate.certified_at = now;
        response.evidence.nodes[0].last_seen = Some(now);

        // The existing signed population remains cryptographically valid and
        // below the protocol's 300s ceiling, but violates this 30s request.
        let error = response.validate_for_request(&request).unwrap_err();
        assert!(error.to_string().contains("future-dated or expired"));

        request.stale_after = Duration::new(30, 1);
        response.evidence.stale_after = request.stale_after;
        response.validate_for_request(&request).unwrap();
        response.evidence.observed_at += chrono::Duration::nanoseconds(1);
        response.certificate.certified_at = response.evidence.observed_at;
        response.evidence.nodes[0].last_seen = Some(response.evidence.observed_at);
        assert!(response.validate_for_request(&request).is_err());

        // A genuinely new supervisor observation, signed by the same enrolled
        // authority, restores useful certification without changing the gate.
        let drain = response.evidence.nodes[0]
            .native_session_drain
            .as_mut()
            .unwrap();
        let attestation = drain.supervisor_attestation.as_mut().unwrap();
        attestation.observed_at = response.evidence.observed_at;
        attestation.signature_hex = hex::encode(
            SigningKey::from_bytes(&[73; 32])
                .sign(&attestation.signing_payload().unwrap())
                .to_bytes(),
        );
        response.validate_for_request(&request).unwrap();
    }

    #[test]
    fn epoch_commit_accepts_independent_cross_language_signature_vector() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sdk/verifier/tests/fixtures/fleet_epoch_commit.json"
        )))
        .unwrap();
        assert_eq!(fixture["live_execution_performed"], false);
        let response: FleetHttpEpochBarrierResponse =
            serde_json::from_value(fixture["http_response"].clone()).unwrap();
        // Historical servers omitted the unsigned transport hint. Existing
        // independently signed exports retain their verification contract.
        assert!(!response.already_committed);
        response.validate_for_export(8).unwrap();
        let root_bytes: [u8; 32] = hex::decode(
            fixture["coordinator_trust"]["coordinator_public_key_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        let root = ed25519_dalek::VerifyingKey::from_bytes(&root_bytes).unwrap();
        response
            .commit_proof
            .as_ref()
            .unwrap()
            .verify_with_coordinator(
                &response.evidence,
                &response.certificate,
                "coordinator-test",
                &root,
            )
            .unwrap();
    }

    #[test]
    fn epoch_commit_client_rejects_downgrade_and_wrong_historical_epoch() {
        let (request, mut response) = certified_epoch_response();
        let signer = super::super::fleet_transport::FleetEpochCommitSigner::new(
            "coordinator-test",
            ed25519_dalek::SigningKey::from_bytes(&[43; 32]),
        )
        .unwrap();
        let authorization = signer
            .authorize(&response.evidence, &response.certificate)
            .unwrap();
        let proof = signer
            .attest_committed(authorization, &response.evidence, &response.certificate)
            .unwrap();
        assert!(
            response.validate_for_export(8).is_err(),
            "legacy claims cannot be exported as public proof"
        );
        response.commit_proof = Some(proof);
        assert!(
            response.validate_for_request(&request).is_err(),
            "proof cannot silently change the old envelope contract"
        );
        response.schema_version = FLEET_HTTP_EPOCH_COMMIT_RESPONSE_SCHEMA.to_owned();
        response.validate_for_request(&request).unwrap();
        response.validate_for_export(8).unwrap();
        assert!(response.validate_for_export(7).is_err());
        response.commit_proof = None;
        assert!(
            response.validate_for_request(&request).is_err(),
            "new envelope cannot omit its proof"
        );
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
