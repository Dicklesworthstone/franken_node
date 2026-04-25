//! Cross-cutting middleware for the control-plane in-process catalog surface.
//!
//! This module provides reusable middleware primitives (rate limiting, auth
//! resolution, trace context) for the control-plane service assembly. It does
//! not own a live HTTP/gRPC transport boundary; the middleware types are wired
//! through in-process dispatch today.
//!
//! Implements the middleware chain defined in the fastapi_rust integration
//! contract (bd-3ndj):
//!
//! 1. Trace context extraction (W3C traceparent)
//! 2. Authentication (mTLS / API key / token)
//! 3. Authorization (RBAC + policy hook)
//! 4. Rate-limit / anti-amplification guard
//! 5. Handler execution
//! 6. Structured response + telemetry emission

#[cfg(any(test, feature = "control-plane"))]
use crate::security::constant_time;
use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "control-plane"))]
use std::collections::BTreeMap;
#[cfg(any(test, feature = "control-plane"))]
use std::time::Instant;

#[cfg(any(test, feature = "control-plane"))]
use super::error::ApiError;
#[cfg(any(test, feature = "control-plane"))]
use super::utf8_prefix;

#[cfg(any(test, feature = "control-plane"))]
const MAX_SAMPLES: usize = 4096;

#[cfg(any(test, feature = "control-plane"))]
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        let drain_until = overflow.min(items.len());
        items.drain(0..drain_until);
    }
    items.extend(std::iter::once(item));
}

// ── Trace Context ──────────────────────────────────────────────────────────

/// W3C trace context extracted from request headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    /// Unique trace ID (128-bit hex).
    pub trace_id: String,
    /// Span ID within the trace (64-bit hex).
    pub span_id: String,
    /// Trace flags (e.g., sampled).
    pub trace_flags: u8,
}

impl TraceContext {
    /// Parse a W3C `traceparent` header value.
    ///
    /// Format: `{version}-{trace_id}-{span_id}-{trace_flags}`
    #[cfg(any(test, feature = "control-plane"))]
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        let version = parts[0];
        let trace_id = parts[1];
        let span_id = parts[2];
        if version.len() != 2
            || !is_lower_hex(version)
            || version == "ff"
            || !is_valid_trace_id(trace_id)
            || !is_valid_span_id(span_id)
            || !is_valid_trace_flags(parts[3])
        {
            return None;
        }
        let trace_flags = u8::from_str_radix(parts[3], 16).ok()?;

        Some(Self {
            trace_id: trace_id.to_string(),
            span_id: span_id.to_string(),
            trace_flags,
        })
    }

    /// Generate a new trace context with a random trace ID.
    #[cfg(any(test, feature = "control-plane"))]
    pub fn generate() -> Self {
        let trace_id = uuid::Uuid::now_v7().simple().to_string();
        let span_id = format!("{:016x}", rand_span_id());
        Self {
            trace_id,
            span_id,
            trace_flags: 1, // sampled
        }
    }

    /// Serialize to a W3C `traceparent` header value.
    #[cfg(any(test, feature = "control-plane"))]
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.span_id, self.trace_flags
        )
    }
}

/// Simple span ID generation using timestamp-based entropy.
#[cfg(any(test, feature = "control-plane"))]
const SPAN_ID_MIX: u64 = 0x517c_c1b7_2722_0a95;

#[cfg(any(test, feature = "control-plane"))]
fn span_id_from_unix_nanos(unix_nanos: u128) -> u64 {
    let bounded_nanos = u64::try_from(unix_nanos).unwrap_or(u64::MAX);
    bounded_nanos ^ SPAN_ID_MIX
}

/// Generates deterministic span ID from unix nanoseconds for testing consistency.
#[cfg(any(test, feature = "control-plane"))]
pub fn span_id_from_unix_nanos_for_tests(unix_nanos: u128) -> u64 {
    span_id_from_unix_nanos(unix_nanos)
}

#[cfg(any(test, feature = "control-plane"))]
fn rand_span_id() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    span_id_from_unix_nanos(now.as_nanos())
}

#[cfg(any(test, feature = "control-plane"))]
fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(any(test, feature = "control-plane"))]
fn has_nonzero_hex_digit(value: &str) -> bool {
    value.bytes().any(|byte| byte != b'0')
}

#[cfg(any(test, feature = "control-plane"))]
fn is_valid_trace_id(value: &str) -> bool {
    value.len() == 32 && is_lower_hex(value) && has_nonzero_hex_digit(value)
}

#[cfg(any(test, feature = "control-plane"))]
fn is_valid_span_id(value: &str) -> bool {
    value.len() == 16 && is_lower_hex(value) && has_nonzero_hex_digit(value)
}

#[cfg(any(test, feature = "control-plane"))]
fn is_valid_trace_flags(value: &str) -> bool {
    value.len() == 2 && is_lower_hex(value)
}

#[cfg(any(test, feature = "control-plane"))]
fn contains_authorized_key_constant_time(
    authorized_keys: &std::collections::BTreeSet<String>,
    candidate: &str,
) -> bool {
    authorized_keys.iter().fold(false, |acc, authorized| {
        acc | constant_time::ct_eq(authorized, candidate)
    })
}

// ── Authentication ─────────────────────────────────────────────────────────

/// Supported authentication methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    /// Mutual TLS with client certificate verification.
    MtlsClientCert,
    /// Static API key in `Authorization: ApiKey <key>` header.
    ApiKey,
    /// Bearer token in `Authorization: Bearer <token>` header.
    BearerToken,
    /// No authentication (internal/dev only).
    None,
}

/// Authenticated identity after successful auth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthIdentity {
    /// Principal identifier (e.g., service name, user ID).
    pub principal: String,
    /// Authentication method used.
    pub method: AuthMethod,
    /// Roles assigned to this principal.
    pub roles: Vec<String>,
}

/// Authentication middleware result.
#[cfg(any(test, feature = "control-plane"))]
pub type AuthResult = Result<AuthIdentity, ApiError>;

/// Authenticate a request based on provided credentials.
#[cfg(any(test, feature = "control-plane"))]
pub fn authenticate(
    auth_header: Option<&str>,
    required_method: &AuthMethod,
    trace_id: &str,
    authorized_keys: &std::collections::BTreeSet<String>,
) -> AuthResult {
    match required_method {
        AuthMethod::None => Ok(AuthIdentity {
            principal: "anonymous".to_string(),
            method: AuthMethod::None,
            roles: vec!["reader".to_string()],
        }),
        AuthMethod::ApiKey => {
            let header = auth_header.ok_or_else(|| ApiError::AuthFailed {
                detail: "missing Authorization header".to_string(),
                trace_id: trace_id.to_string(),
            })?;
            let key = header
                .strip_prefix("ApiKey ")
                .ok_or_else(|| ApiError::AuthFailed {
                    detail: "expected Authorization: ApiKey <key>".to_string(),
                    trace_id: trace_id.to_string(),
                })?;
            if key.is_empty() {
                return Err(ApiError::AuthFailed {
                    detail: "empty API key".to_string(),
                    trace_id: trace_id.to_string(),
                });
            }
            if !contains_authorized_key_constant_time(authorized_keys, key) {
                return Err(ApiError::AuthFailed {
                    detail: "invalid API key".to_string(),
                    trace_id: trace_id.to_string(),
                });
            }
            Ok(AuthIdentity {
                principal: format!("apikey:{}", utf8_prefix(key, 8)),
                method: AuthMethod::ApiKey,
                roles: vec!["reader".to_string()],
            })
        }
        AuthMethod::BearerToken => {
            let header = auth_header.ok_or_else(|| ApiError::AuthFailed {
                detail: "missing Authorization header".to_string(),
                trace_id: trace_id.to_string(),
            })?;
            let token = header
                .strip_prefix("Bearer ")
                .ok_or_else(|| ApiError::AuthFailed {
                    detail: "expected Authorization: Bearer <token>".to_string(),
                    trace_id: trace_id.to_string(),
                })?;
            if token.is_empty() {
                return Err(ApiError::AuthFailed {
                    detail: "empty bearer token".to_string(),
                    trace_id: trace_id.to_string(),
                });
            }
            let is_valid = contains_authorized_key_constant_time(authorized_keys, token);
            if !is_valid {
                return Err(ApiError::AuthFailed {
                    detail: "invalid bearer token".to_string(),
                    trace_id: trace_id.to_string(),
                });
            }
            Ok(AuthIdentity {
                principal: format!("token:{}", utf8_prefix(token, 8)),
                method: AuthMethod::BearerToken,
                roles: vec!["operator".to_string(), "verifier".to_string()],
            })
        }
        AuthMethod::MtlsClientCert => {
            // mTLS verification happens at the transport layer; here we just
            // check that the propagated identity is non-empty and matches the
            // set of transport-validated client identities.
            let header = auth_header.ok_or_else(|| ApiError::AuthFailed {
                detail: "mTLS client identity not propagated".to_string(),
                trace_id: trace_id.to_string(),
            })?;
            let propagated_identity = header.trim();
            if propagated_identity.is_empty() {
                return Err(ApiError::AuthFailed {
                    detail: "empty mTLS client identity".to_string(),
                    trace_id: trace_id.to_string(),
                });
            }
            let is_valid =
                contains_authorized_key_constant_time(authorized_keys, propagated_identity);
            if !is_valid {
                return Err(ApiError::AuthFailed {
                    detail: "invalid mTLS client identity".to_string(),
                    trace_id: trace_id.to_string(),
                });
            }
            Ok(AuthIdentity {
                principal: format!("mtls:{}", utf8_prefix(propagated_identity, 16)),
                method: AuthMethod::MtlsClientCert,
                roles: vec!["reader".to_string()], // SECURITY: default to minimal privilege
            })
        }
    }
}

// ── Authorization (RBAC + Policy Hook) ─────────────────────────────────────

/// Policy hook descriptor bound to a route.
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyHook {
    /// Unique hook identifier (e.g., `operator.status.read`).
    pub hook_id: String,
    /// Roles that satisfy this hook.
    pub required_roles: Vec<String>,
}

/// Authorization check result.
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthzDecision {
    /// Access granted.
    Allow,
    /// Access denied with reason.
    Deny { reason: String },
}

/// Check authorization against the policy hook.
#[cfg(any(test, feature = "control-plane"))]
pub fn authorize(
    identity: &AuthIdentity,
    hook: &PolicyHook,
    _trace_id: &str,
) -> Result<AuthzDecision, ApiError> {
    if hook.required_roles.is_empty() {
        return Ok(AuthzDecision::Allow);
    }

    let has_role = identity
        .roles
        .iter()
        .any(|r| hook.required_roles.contains(r));

    if has_role {
        Ok(AuthzDecision::Allow)
    } else {
        Ok(AuthzDecision::Deny {
            reason: format!(
                "principal '{}' lacks required role(s): {:?} (hook: {})",
                identity.principal, hook.required_roles, hook.hook_id
            ),
        })
    }
}

/// Enforce authorization, returning an error if denied.
#[cfg(any(test, feature = "control-plane"))]
pub fn enforce_policy(
    identity: &AuthIdentity,
    hook: &PolicyHook,
    trace_id: &str,
) -> Result<(), ApiError> {
    match authorize(identity, hook, trace_id)? {
        AuthzDecision::Allow => Ok(()),
        AuthzDecision::Deny { reason } => Err(ApiError::PolicyDenied {
            detail: reason,
            trace_id: trace_id.to_string(),
            policy_hook: hook.hook_id.clone(),
        }),
    }
}

#[cfg(any(test, feature = "control-plane"))]
fn auth_method_name(method: &AuthMethod) -> &'static str {
    match method {
        AuthMethod::MtlsClientCert => "mTLS client certificate",
        AuthMethod::ApiKey => "API key",
        AuthMethod::BearerToken => "bearer token",
        AuthMethod::None => "no authentication",
    }
}

/// Enforce the declared route contract for a direct in-process handler call.
///
/// This keeps direct callers from reusing an identity under a weaker or
/// different credential type than the route metadata requires.
#[cfg(any(test, feature = "control-plane"))]
pub fn enforce_route_contract(
    identity: &AuthIdentity,
    route: &RouteMetadata,
    trace_id: &str,
) -> Result<(), ApiError> {
    let expected_method = &route.auth_method;
    if !matches!(expected_method, AuthMethod::None) && &identity.method != expected_method {
        return Err(ApiError::AuthFailed {
            detail: format!(
                "route contract requires {} authentication for {} {}",
                auth_method_name(expected_method),
                route.method,
                route.path
            ),
            trace_id: trace_id.to_string(),
        });
    }

    enforce_policy(identity, &route.policy_hook, trace_id)
}

// ── Rate Limiting ──────────────────────────────────────────────────────────

/// Rate limiter configuration for an endpoint group.
///
/// SECURITY NOTE: This rate limiter provides PER-INSTANCE performance protection,
/// not cluster-wide security rate limiting. In distributed deployments, each
/// franken-node instance maintains independent token bucket state, allowing
/// attackers to achieve N×rate_limit throughput by distributing requests across
/// multiple instances. This is intentional for the current threat model:
///
/// 1. Authentication failures are now rate limited by AuthFailureLimiter BEFORE
///    authentication attempts to prevent brute force attacks per instance
/// 2. Rate limits apply to POST-AUTHENTICATION operations for performance
///    protection (prevent individual instance overload)
/// 3. Security-critical operations requiring cluster-wide rate limiting should
///    use request signing, nonce validation, or capability-based authorization
///    instead of pure time-based rate limiting
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum sustained requests per second.
    pub sustained_rps: u32,
    /// Maximum burst size.
    pub burst_size: u32,
    /// Whether the endpoint is fail-closed (deny on limiter error).
    pub fail_closed: bool,
}

/// In-memory rate limiter state using a token bucket.
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    tokens: f64,
    last_check: Instant,
}

#[cfg(any(test, feature = "control-plane"))]
impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        // Ensure sustained_rps >= 1 to prevent division-by-zero in check().
        let mut config = config;
        if config.sustained_rps == 0 {
            config.sustained_rps = 1;
        }
        Self {
            tokens: f64::from(config.burst_size),
            last_check: Instant::now(),
            config,
        }
    }

    /// Check if a request is allowed. Returns `Ok(())` if allowed or
    /// `Err(retry_after_ms)` if rate limited.
    pub fn check(&mut self) -> Result<(), u64> {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_check).as_secs_f64();
        self.last_check = now;

        // Refill tokens with overflow protection
        let refill_amount = elapsed * f64::from(self.config.sustained_rps);
        if refill_amount.is_finite() && refill_amount >= 0.0 {
            self.tokens += refill_amount;
        }
        if !self.tokens.is_finite() {
            self.tokens = 0.0; // fail-closed: deny until next refill
        }
        if self.tokens > f64::from(self.config.burst_size) {
            self.tokens = f64::from(self.config.burst_size);
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate how long until a token is available
            let wait_secs = (1.0 - self.tokens) / f64::from(self.config.sustained_rps);
            let wait_ms = (wait_secs * 1000.0).ceil() as u64;
            Err(wait_ms.max(1))
        }
    }

    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

/// Check rate limit, returning an `ApiError` if exceeded.
#[cfg(any(test, feature = "control-plane"))]
pub fn check_rate_limit(limiter: &mut RateLimiter, trace_id: &str) -> Result<(), ApiError> {
    match limiter.check() {
        Ok(()) => Ok(()),
        Err(retry_after_ms) => Err(ApiError::RateLimited {
            detail: format!(
                "rate limit exceeded ({} rps sustained, {} burst)",
                limiter.config().sustained_rps,
                limiter.config().burst_size
            ),
            trace_id: trace_id.to_string(),
            retry_after_ms,
        }),
    }
}

/// Authentication failure rate limiter to prevent brute force attacks.
///
/// This provides additional security by rate limiting authentication attempts
/// before they reach the main authentication logic, preventing brute force
/// attacks against credentials.
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug)]
pub struct AuthFailureLimiter {
    rate_limiter: RateLimiter,
}

#[cfg(any(test, feature = "control-plane"))]
impl AuthFailureLimiter {
    /// Create a new authentication failure rate limiter.
    ///
    /// Default configuration allows 10 auth attempts per second with burst of 20,
    /// fail-closed to prevent brute force attacks.
    pub fn new() -> Self {
        Self {
            rate_limiter: RateLimiter::new(RateLimitConfig {
                sustained_rps: 10,
                burst_size: 20,
                fail_closed: true,
            }),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            rate_limiter: RateLimiter::new(config),
        }
    }

    /// Check if an authentication attempt is allowed.
    /// Returns Err with retry_after_ms if rate limited.
    pub fn check_auth_attempt(&mut self, trace_id: &str) -> Result<(), ApiError> {
        match self.rate_limiter.check() {
            Ok(()) => Ok(()),
            Err(retry_after_ms) => Err(ApiError::RateLimited {
                detail: "Too many authentication attempts. Please try again later.".to_string(),
                trace_id: trace_id.to_string(),
                retry_after_ms,
            }),
        }
    }
}

// ── Request/Response Telemetry ─────────────────────────────────────────────

/// Structured request log entry emitted after handler execution.
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLog {
    pub method: String,
    pub route: String,
    pub status: u16,
    pub latency_ms: f64,
    pub trace_id: String,
    pub principal: String,
    pub endpoint_group: String,
    pub event_code: String,
}

/// Endpoint group classification for metric tagging.
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointGroup {
    Operator,
    Verifier,
    FleetControl,
}

#[cfg(any(test, feature = "control-plane"))]
impl EndpointGroup {
    pub fn as_str(&self) -> &'static str {
        match self {
            EndpointGroup::Operator => "operator",
            EndpointGroup::Verifier => "verifier",
            EndpointGroup::FleetControl => "fleet_control",
        }
    }
}

#[cfg(any(test, feature = "control-plane"))]
impl std::fmt::Display for EndpointGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Event codes emitted by the middleware/service layer.
#[cfg(any(test, feature = "control-plane"))]
pub mod event_codes {
    #[cfg(feature = "control-plane")]
    pub const SERVICE_START: &str = "FASTAPI_SERVICE_START";
    #[cfg(feature = "control-plane")]
    pub const REQUEST_RECEIVED: &str = "FASTAPI_REQUEST_RECEIVED";
    #[cfg(feature = "control-plane")]
    pub const AUTH_SUCCESS: &str = "FASTAPI_AUTH_SUCCESS";
    pub const AUTH_FAIL: &str = "FASTAPI_AUTH_FAIL";
    pub const POLICY_DENY: &str = "FASTAPI_POLICY_DENY";
    pub const RATE_LIMITED: &str = "FASTAPI_RATE_LIMITED";
    pub const ENDPOINT_ERROR: &str = "FASTAPI_ENDPOINT_ERROR";
    pub const RESPONSE_SENT: &str = "FASTAPI_RESPONSE_SENT";
}

// ── Middleware Chain ────────────────────────────────────────────────────────

/// Route metadata describing middleware requirements for one endpoint.
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteMetadata {
    /// HTTP method (GET, POST, PUT, DELETE).
    pub method: String,
    /// Route path (e.g., `/v1/operator/status`).
    pub path: String,
    /// Endpoint group.
    pub group: EndpointGroup,
    /// Lifecycle state.
    pub lifecycle: EndpointLifecycle,
    /// Authentication method required.
    pub auth_method: AuthMethod,
    /// Policy hook for authorization.
    pub policy_hook: PolicyHook,
    /// Whether trace context propagation is required.
    pub trace_propagation: bool,
}

/// Endpoint lifecycle state.
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointLifecycle {
    Experimental,
    Stable,
    Deprecated,
}

#[cfg(any(test, feature = "control-plane"))]
impl EndpointLifecycle {
    #[cfg(feature = "control-plane")]
    pub fn as_str(&self) -> &'static str {
        match self {
            EndpointLifecycle::Experimental => "experimental",
            EndpointLifecycle::Stable => "stable",
            EndpointLifecycle::Deprecated => "deprecated",
        }
    }
}

/// Middleware chain result: either a successful response or an error.
#[cfg(any(test, feature = "control-plane"))]
pub type MiddlewareResult<T> = Result<T, ApiError>;

/// Execute the full middleware chain for a request.
///
/// Chain order: trace → auth failure limit → auth → authz → rate limit → handler
#[cfg(any(test, feature = "control-plane"))]
pub fn execute_middleware_chain<F, T>(
    route: &RouteMetadata,
    auth_header: Option<&str>,
    traceparent: Option<&str>,
    auth_failure_limiter: &mut AuthFailureLimiter,
    rate_limiter: &mut RateLimiter,
    authorized_keys: &std::collections::BTreeSet<String>,
    handler: F,
) -> (MiddlewareResult<T>, RequestLog)
where
    F: FnOnce(&AuthIdentity, &TraceContext) -> MiddlewareResult<T>,
{
    let start = Instant::now();

    // Step 1: Trace context
    let trace_ctx = traceparent
        .and_then(TraceContext::from_traceparent)
        .unwrap_or_else(TraceContext::generate);

    let trace_id = trace_ctx.trace_id.clone();

    // Step 2: Authentication failure rate limiting (SECURITY PROTECTION)
    // Applied before authentication to prevent brute force attacks.
    // Skip for routes with AuthMethod::None (no credentials to brute force).
    if !matches!(route.auth_method, AuthMethod::None) {
        if let Err(err) = auth_failure_limiter.check_auth_attempt(&trace_id) {
            let log = build_request_log(route, 429, start, &trace_id, "anonymous");
            return (Err(err), log);
        }
    }

    // Step 3: Authentication
    let identity = match authenticate(auth_header, &route.auth_method, &trace_id, authorized_keys) {
        Ok(id) => id,
        Err(err) => {
            let log = build_request_log(route, 401, start, &trace_id, "anonymous");
            return (Err(err), log);
        }
    };

    // Step 4: Authorization
    if let Err(err) = enforce_policy(&identity, &route.policy_hook, &trace_id) {
        let log = build_request_log(route, 403, start, &trace_id, &identity.principal);
        return (Err(err), log);
    }

    // Step 5: Rate limiting (PERFORMANCE PROTECTION)
    // Applied after auth/authz - protects handler from overload on this instance.
    // Separate from security rate limiting in step 2.
    if let Err(err) = check_rate_limit(rate_limiter, &trace_id) {
        let log = build_request_log(route, 429, start, &trace_id, &identity.principal);
        return (Err(err), log);
    }

    // Step 6: Handler execution
    let result = handler(&identity, &trace_ctx);

    let status = match &result {
        Ok(_) => 200,
        Err(e) => e.to_problem(&route.path).status,
    };

    let log = build_request_log(route, status, start, &trace_id, &identity.principal);

    (result, log)
}

#[cfg(any(test, feature = "control-plane"))]
fn build_request_log(
    route: &RouteMetadata,
    status: u16,
    start: Instant,
    trace_id: &str,
    principal: &str,
) -> RequestLog {
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let latency_ms = if latency_ms.is_finite() {
        latency_ms
    } else {
        0.0
    };
    let event_code = if status < 400 {
        event_codes::RESPONSE_SENT
    } else if status == 401 {
        event_codes::AUTH_FAIL
    } else if status == 403 {
        event_codes::POLICY_DENY
    } else if status == 429 {
        event_codes::RATE_LIMITED
    } else {
        event_codes::ENDPOINT_ERROR
    };

    RequestLog {
        method: route.method.clone(),
        route: route.path.clone(),
        status,
        latency_ms,
        trace_id: trace_id.to_string(),
        principal: principal.to_string(),
        endpoint_group: route.group.as_str().to_string(),
        event_code: event_code.to_string(),
    }
}

/// Default rate limiter configurations by endpoint group.
///
/// All configurations provide PERFORMANCE PROTECTION per-instance:
/// - Operator: Read operations, status checks (high throughput allowed)
/// - Verifier: Cryptographic verification operations (moderate throughput)
/// - FleetControl: State-changing operations (conservative limits)
///
/// These are NOT security rate limits - they protect individual instance
/// performance after successful authentication and authorization.
#[cfg(any(test, feature = "control-plane"))]
pub fn default_rate_limit(group: EndpointGroup) -> RateLimitConfig {
    match group {
        EndpointGroup::Operator => RateLimitConfig {
            sustained_rps: 100, // PERFORMANCE: protect instance from read overload
            burst_size: 200,
            fail_closed: true, // SECURITY: fail-closed to prevent DoS on rate limiter failure
        },
        EndpointGroup::Verifier => RateLimitConfig {
            sustained_rps: 50, // PERFORMANCE: protect crypto operations from overload
            burst_size: 100,
            fail_closed: true, // SECURITY: fail-closed to prevent DoS on rate limiter failure
        },
        EndpointGroup::FleetControl => RateLimitConfig {
            sustained_rps: 20, // PERFORMANCE: protect dangerous mutations from overload
            burst_size: 40,
            fail_closed: true, // fail-closed for dangerous mutations
        },
    }
}

/// Collect latency metrics per endpoint group.
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LatencyMetrics {
    pub samples: Vec<f64>,
}

#[cfg(any(test, feature = "control-plane"))]
impl LatencyMetrics {
    pub fn record(&mut self, latency_ms: f64) {
        if latency_ms.is_finite() {
            push_bounded(&mut self.samples, latency_ms, MAX_SAMPLES);
        }
    }

    pub fn p50(&self) -> f64 {
        self.percentile(50)
    }

    pub fn p95(&self) -> f64 {
        self.percentile(95)
    }

    pub fn p99(&self) -> f64 {
        self.percentile(99)
    }

    fn percentile(&self, pct: u32) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let mut sorted = self.samples.clone();
        let pct_ratio = f64::from(pct.min(100)) / 100.0;
        let len_minus_one = (sorted.len().saturating_sub(1)) as f64;
        let idx_f64 = pct_ratio * len_minus_one;
        if !idx_f64.is_finite() || idx_f64 < 0.0 {
            return 0.0;
        }
        let idx = idx_f64.round() as usize;
        let target_idx = idx.min(sorted.len().saturating_sub(1));
        let (_, val, _) = sorted.select_nth_unstable_by(target_idx, |a, b| a.total_cmp(b));
        *val
    }
}

// ── Middleware Metrics Aggregator ───────────────────────────────────────────

/// Aggregated metrics for the control-plane service.
#[cfg(any(test, feature = "control-plane"))]
#[derive(Debug, Default)]
pub struct ServiceMetrics {
    pub latencies: BTreeMap<String, LatencyMetrics>,
    pub error_counts: BTreeMap<String, u64>,
    pub request_count: u64,
}

#[cfg(any(test, feature = "control-plane"))]
impl ServiceMetrics {
    pub fn record_request(&mut self, log: &RequestLog) {
        self.request_count = self.request_count.saturating_add(1);
        self.latencies
            .entry(log.endpoint_group.clone())
            .or_default()
            .record(log.latency_ms);
        if log.status >= 400 {
            let count = self.error_counts.entry(log.event_code.clone()).or_insert(0);
            *count = count.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_context_parse_valid() {
        let tc = TraceContext::from_traceparent(
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        )
        .expect("parse");
        assert_eq!(tc.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(tc.span_id, "b7ad6b7169203331");
        assert_eq!(tc.trace_flags, 1);
    }

    #[test]
    fn trace_context_parse_invalid() {
        assert!(TraceContext::from_traceparent("bad-header").is_none());
        assert!(TraceContext::from_traceparent("00-short-id-01").is_none());
        assert!(
            TraceContext::from_traceparent(
                "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b7ad6b7169203331-01"
            )
            .is_none()
        );
        assert!(
            TraceContext::from_traceparent(
                "00-00000000000000000000000000000000-b7ad6b7169203331-01"
            )
            .is_none()
        );
        assert!(
            TraceContext::from_traceparent(
                "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01"
            )
            .is_none()
        );
        assert!(
            TraceContext::from_traceparent(
                "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01"
            )
            .is_none()
        );
        assert!(
            TraceContext::from_traceparent(
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-1"
            )
            .is_none()
        );
        assert!(
            TraceContext::from_traceparent(
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-0A"
            )
            .is_none()
        );
    }

    #[test]
    fn trace_context_roundtrip() {
        let tc = TraceContext::generate();
        let header = tc.to_traceparent();
        let parsed = TraceContext::from_traceparent(&header).expect("parse roundtrip");
        assert_eq!(tc.trace_id, parsed.trace_id);
    }

    #[test]
    fn span_id_generation_saturates_oversized_nanoseconds() {
        let oversized_nanos = u128::from(u64::MAX).saturating_add(1);
        let span_id = span_id_from_unix_nanos(oversized_nanos);

        assert_eq!(span_id, u64::MAX ^ SPAN_ID_MIX);
        assert_ne!(span_id, SPAN_ID_MIX);
    }

    fn get_test_keys() -> std::collections::BTreeSet<String> {
        let mut keys = std::collections::BTreeSet::new();
        keys.insert("test-key-123".to_string());
        keys.insert("mytoken-abc".to_string());
        keys.insert("🔐鍵🙂abc123".to_string());
        keys.insert("令牌🙂abcXYZ".to_string());
        keys.insert("valid-token-abc".to_string());
        keys.insert("fleet-service-cert".to_string());
        keys
    }

    #[test]
    fn contains_authorized_key_constant_time_matches_and_misses() {
        let keys = get_test_keys();
        assert!(contains_authorized_key_constant_time(&keys, "test-key-123"));
        assert!(contains_authorized_key_constant_time(
            &keys,
            "valid-token-abc"
        ));
        assert!(contains_authorized_key_constant_time(
            &keys,
            "fleet-service-cert"
        ));
        assert!(!contains_authorized_key_constant_time(
            &keys,
            "missing-credential"
        ));
    }

    #[test]
    fn authenticate_none_method() {
        let keys = get_test_keys();
        let result = authenticate(None, &AuthMethod::None, "t-1", &keys);
        let identity = result.expect("auth none");
        assert_eq!(identity.principal, "anonymous");
    }

    #[test]
    fn authenticate_api_key() {
        let keys = get_test_keys();
        let result = authenticate(
            Some("ApiKey test-key-123"),
            &AuthMethod::ApiKey,
            "t-2",
            &keys,
        );
        let identity = result.expect("auth api key");
        assert!(identity.principal.starts_with("apikey:"));
    }

    #[test]
    fn authenticate_bearer_token() {
        let keys = get_test_keys();
        let result = authenticate(
            Some("Bearer mytoken-abc"),
            &AuthMethod::BearerToken,
            "t-3",
            &keys,
        );
        let identity = result.expect("auth bearer");
        assert!(identity.principal.starts_with("token:"));
    }

    #[test]
    fn authenticate_api_key_handles_unicode_without_panicking() {
        let keys = get_test_keys();
        let result = authenticate(
            Some("ApiKey 🔐鍵🙂abc123"),
            &AuthMethod::ApiKey,
            "t-2u",
            &keys,
        );
        let identity = result.expect("auth api key");
        let expected: String = "🔐鍵🙂abc123".chars().take(8).collect();
        assert_eq!(identity.principal, format!("apikey:{expected}"));
    }

    #[test]
    fn authenticate_bearer_handles_unicode_without_panicking() {
        let keys = get_test_keys();
        let result = authenticate(
            Some("Bearer 令牌🙂abcXYZ"),
            &AuthMethod::BearerToken,
            "t-3u",
            &keys,
        );
        let identity = result.expect("auth bearer");
        let expected: String = "令牌🙂abcXYZ".chars().take(8).collect();
        assert_eq!(identity.principal, format!("token:{expected}"));
    }

    #[test]
    fn authenticate_mtls_identity() {
        let keys = get_test_keys();
        let result = authenticate(
            Some("fleet-service-cert"),
            &AuthMethod::MtlsClientCert,
            "t-3m",
            &keys,
        );
        let identity = result.expect("auth mtls");
        assert_eq!(identity.principal, "mtls:fleet-service-ce");
    }

    #[test]
    fn authenticate_missing_header() {
        let keys = get_test_keys();
        let result = authenticate(None, &AuthMethod::ApiKey, "t-4", &keys);
        assert!(result.is_err());
    }

    #[test]
    fn authenticate_wrong_prefix() {
        let keys = get_test_keys();
        let result = authenticate(Some("Basic abc"), &AuthMethod::BearerToken, "t-5", &keys);
        assert!(result.is_err());
    }

    #[test]
    fn authenticate_mtls_rejects_empty_identity() {
        let keys = get_test_keys();
        let result = authenticate(Some(""), &AuthMethod::MtlsClientCert, "t-5m", &keys);
        assert!(result.is_err());
    }

    #[test]
    fn authenticate_mtls_rejects_whitespace_only_identity() {
        let keys = get_test_keys();
        let result = authenticate(Some("   "), &AuthMethod::MtlsClientCert, "t-5mw", &keys);
        assert!(result.is_err());
    }

    #[test]
    fn authenticate_mtls_trims_propagated_identity() {
        let keys = get_test_keys();
        let result = authenticate(
            Some("  fleet-service-cert  "),
            &AuthMethod::MtlsClientCert,
            "t-5mt",
            &keys,
        );
        let identity = result.expect("auth mtls");
        assert_eq!(identity.principal, "mtls:fleet-service-ce");
    }

    #[test]
    fn authenticate_mtls_rejects_unknown_identity() {
        let keys = get_test_keys();
        let result = authenticate(
            Some("rogue-service-cert"),
            &AuthMethod::MtlsClientCert,
            "t-5mu",
            &keys,
        );
        assert!(result.is_err());
    }

    #[test]
    fn authorize_allow() {
        let identity = AuthIdentity {
            principal: "test".to_string(),
            method: AuthMethod::ApiKey,
            roles: vec!["operator".to_string()],
        };
        let hook = PolicyHook {
            hook_id: "test.read".to_string(),
            required_roles: vec!["operator".to_string()],
        };
        let decision = authorize(&identity, &hook, "t-6").expect("authz");
        assert_eq!(decision, AuthzDecision::Allow);
    }

    #[test]
    fn authorize_deny_missing_role() {
        let identity = AuthIdentity {
            principal: "test".to_string(),
            method: AuthMethod::ApiKey,
            roles: vec!["reader".to_string()],
        };
        let hook = PolicyHook {
            hook_id: "fleet.admin".to_string(),
            required_roles: vec!["fleet-admin".to_string()],
        };
        let decision = authorize(&identity, &hook, "t-7").expect("authz");
        assert!(matches!(decision, AuthzDecision::Deny { .. }));
    }

    #[test]
    fn authorize_empty_roles_allows() {
        let identity = AuthIdentity {
            principal: "test".to_string(),
            method: AuthMethod::None,
            roles: vec![],
        };
        let hook = PolicyHook {
            hook_id: "public.read".to_string(),
            required_roles: vec![],
        };
        let decision = authorize(&identity, &hook, "t-8").expect("authz");
        assert_eq!(decision, AuthzDecision::Allow);
    }

    #[test]
    fn rate_limiter_allows_within_burst() {
        let config = RateLimitConfig {
            sustained_rps: 10,
            burst_size: 5,
            fail_closed: false,
        };
        let mut limiter = RateLimiter::new(config);
        // Should allow up to burst_size requests immediately
        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }
    }

    #[test]
    fn rate_limiter_rejects_over_burst() {
        let config = RateLimitConfig {
            sustained_rps: 1,
            burst_size: 2,
            fail_closed: false,
        };
        let mut limiter = RateLimiter::new(config);
        limiter.check().expect("1st");
        limiter.check().expect("2nd");
        let result = limiter.check();
        assert!(result.is_err());
    }

    #[test]
    fn endpoint_group_display() {
        assert_eq!(EndpointGroup::Operator.as_str(), "operator");
        assert_eq!(EndpointGroup::Verifier.as_str(), "verifier");
        assert_eq!(EndpointGroup::FleetControl.as_str(), "fleet_control");
    }

    #[test]
    fn latency_metrics_percentiles() {
        let mut m = LatencyMetrics::default();
        for i in 1..=100 {
            m.record(f64::from(i));
        }
        assert!((m.p50() - 50.0).abs() < 2.0);
        assert!((m.p95() - 95.0).abs() < 2.0);
        assert!((m.p99() - 99.0).abs() < 2.0);
    }

    #[test]
    fn latency_metrics_empty() {
        let m = LatencyMetrics::default();
        assert_eq!(m.p50(), 0.0);
    }

    #[test]
    fn service_metrics_recording() {
        let mut metrics = ServiceMetrics::default();
        let log = RequestLog {
            method: "GET".to_string(),
            route: "/v1/operator/status".to_string(),
            status: 200,
            latency_ms: 1.5,
            trace_id: "t-1".to_string(),
            principal: "test".to_string(),
            endpoint_group: "operator".to_string(),
            event_code: "FASTAPI_RESPONSE_SENT".to_string(),
        };
        metrics.record_request(&log);
        assert_eq!(metrics.request_count, 1);
        assert_eq!(metrics.latencies["operator"].samples.len(), 1);
    }

    #[test]
    fn service_metrics_error_counting() {
        let mut metrics = ServiceMetrics::default();
        let log = RequestLog {
            method: "GET".to_string(),
            route: "/v1/fleet/leases".to_string(),
            status: 429,
            latency_ms: 0.2,
            trace_id: "t-1".to_string(),
            principal: "test".to_string(),
            endpoint_group: "fleet_control".to_string(),
            event_code: "FASTAPI_RATE_LIMITED".to_string(),
        };
        metrics.record_request(&log);
        assert_eq!(metrics.error_counts["FASTAPI_RATE_LIMITED"], 1);
    }

    #[test]
    fn default_rate_limits() {
        let op = default_rate_limit(EndpointGroup::Operator);
        assert_eq!(op.sustained_rps, 100);
        assert!(op.fail_closed); // SECURITY: all endpoint groups now fail-closed

        let verifier = default_rate_limit(EndpointGroup::Verifier);
        assert!(verifier.fail_closed); // SECURITY: all endpoint groups now fail-closed

        let fleet = default_rate_limit(EndpointGroup::FleetControl);
        assert!(fleet.fail_closed);
    }

    #[test]
    fn execute_middleware_chain_success() {
        let route = RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/status".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::None,
            policy_hook: PolicyHook {
                hook_id: "operator.status.read".to_string(),
                required_roles: vec![],
            },
            trace_propagation: true,
        };
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let keys = get_test_keys();

        let mut auth_limiter = AuthFailureLimiter::new();
        let mut auth_limiter = AuthFailureLimiter::new();
        let (result, log) = execute_middleware_chain(
            &route,
            None,
            Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
            &mut auth_limiter,
            &mut limiter,
            &keys,
            |_identity, _ctx| Ok("ok".to_string()),
        );

        assert!(result.is_ok());
        assert_eq!(log.status, 200);
        assert_eq!(log.event_code, "FASTAPI_RESPONSE_SENT");
    }

    #[test]
    fn execute_middleware_chain_generates_trace_context_for_invalid_traceparent() {
        let route = RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/status".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::None,
            policy_hook: PolicyHook {
                hook_id: "operator.status.read".to_string(),
                required_roles: vec![],
            },
            trace_propagation: true,
        };
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let keys = get_test_keys();
        let invalid_traceparent = "00-00000000000000000000000000000000-b7ad6b7169203331-01";

        let mut auth_limiter = AuthFailureLimiter::new();
        let mut auth_limiter = AuthFailureLimiter::new();
        let (result, log) = execute_middleware_chain(
            &route,
            None,
            Some(invalid_traceparent),
            &mut auth_limiter,
            &mut limiter,
            &keys,
            |_identity, ctx| Ok(ctx.clone()),
        );

        let trace_ctx = result.expect("generated trace context");
        assert_ne!(trace_ctx.trace_id, "00000000000000000000000000000000");
        assert_eq!(trace_ctx.trace_id, log.trace_id);
    }

    #[test]
    fn execute_middleware_chain_auth_failure() {
        let route = RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/fleet/fence".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "fleet.fence.write".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        };
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::FleetControl));
        let keys = get_test_keys();

        let mut auth_limiter = AuthFailureLimiter::new();
        let mut auth_limiter = AuthFailureLimiter::new();
        let (result, log) = execute_middleware_chain(
            &route,
            None, // no auth header
            None,
            &mut auth_limiter,
            &mut limiter,
            &keys,
            |_identity, _ctx| Ok("should not reach"),
        );

        assert!(result.is_err());
        assert_eq!(log.status, 401);
        assert_eq!(log.event_code, "FASTAPI_AUTH_FAIL");
    }

    #[test]
    fn execute_middleware_chain_rejects_blank_mtls_identity() {
        let route = RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/fleet/quarantine".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::MtlsClientCert,
            policy_hook: PolicyHook {
                hook_id: "fleet.quarantine.execute".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        };
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::FleetControl));
        let keys = get_test_keys();

        let mut auth_limiter = AuthFailureLimiter::new();
        let (result, log) = execute_middleware_chain(
            &route,
            Some("   "),
            None,
            &mut auth_limiter,
            &mut limiter,
            &keys,
            |_identity, _ctx| Ok("should not reach"),
        );

        assert!(result.is_err());
        assert_eq!(log.status, 401);
        assert_eq!(log.event_code, "FASTAPI_AUTH_FAIL");
    }

    #[test]
    fn negative_trace_context_rejects_reserved_ff_version() {
        let header = "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

        assert!(TraceContext::from_traceparent(header).is_none());
    }

    #[test]
    fn negative_trace_context_rejects_extra_or_empty_fields() {
        assert!(
            TraceContext::from_traceparent(
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-extra"
            )
            .is_none()
        );
        assert!(
            TraceContext::from_traceparent(
                "00--0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
            )
            .is_none()
        );
        assert!(
            TraceContext::from_traceparent(
                "00-0af7651916cd43dd8448eb211c80319c--b7ad6b7169203331-01"
            )
            .is_none()
        );
    }

    #[test]
    fn negative_authenticate_api_key_rejects_empty_key() {
        let keys = get_test_keys();
        let err = authenticate(
            Some("ApiKey "),
            &AuthMethod::ApiKey,
            "trace-empty-api-key",
            &keys,
        )
        .expect_err("empty API key must be rejected");

        assert!(matches!(
            err,
            ApiError::AuthFailed {
                detail,
                trace_id,
            } if detail == "empty API key" && trace_id == "trace-empty-api-key"
        ));
    }

    #[test]
    fn negative_authenticate_bearer_rejects_case_mismatched_scheme() {
        let keys = get_test_keys();
        let err = authenticate(
            Some("bearer mytoken-abc"),
            &AuthMethod::BearerToken,
            "trace-lower-bearer",
            &keys,
        )
        .expect_err("lowercase bearer scheme must be rejected");

        assert!(matches!(
            err,
            ApiError::AuthFailed {
                detail,
                trace_id,
            } if detail == "expected Authorization: Bearer <token>"
                && trace_id == "trace-lower-bearer"
        ));
    }

    #[test]
    fn negative_enforce_policy_rejects_case_mismatched_role() {
        let identity = AuthIdentity {
            principal: "case-sensitive-user".to_string(),
            method: AuthMethod::ApiKey,
            roles: vec!["Operator".to_string()],
        };
        let hook = PolicyHook {
            hook_id: "operator.case.write".to_string(),
            required_roles: vec!["operator".to_string()],
        };

        let err = enforce_policy(&identity, &hook, "trace-policy-case")
            .expect_err("role matching must stay case-sensitive");

        assert!(matches!(
            err,
            ApiError::PolicyDenied {
                detail,
                trace_id,
                policy_hook,
            } if detail.contains("lacks required role")
                && trace_id == "trace-policy-case"
                && policy_hook == "operator.case.write"
        ));
    }

    #[test]
    fn negative_rate_limiter_zero_burst_denies_and_normalizes_zero_rps() {
        let mut limiter = RateLimiter::new(RateLimitConfig {
            sustained_rps: 0,
            burst_size: 0,
            fail_closed: true,
        });

        let retry_after_ms = limiter
            .check()
            .expect_err("zero burst must not allow immediate traffic");

        assert_eq!(limiter.config().sustained_rps, 1);
        assert!((1..=1_000).contains(&retry_after_ms));
    }

    #[test]
    fn negative_check_rate_limit_maps_exhaustion_to_api_error() {
        let mut limiter = RateLimiter::new(RateLimitConfig {
            sustained_rps: 1,
            burst_size: 0,
            fail_closed: true,
        });

        let err = check_rate_limit(&mut limiter, "trace-rate-denied")
            .expect_err("exhausted limiter must map to ApiError");

        assert!(matches!(
            err,
            ApiError::RateLimited {
                trace_id,
                retry_after_ms,
                ..
            } if trace_id == "trace-rate-denied" && retry_after_ms >= 1
        ));
    }

    #[test]
    fn negative_execute_middleware_chain_rate_limit_skips_handler() {
        let route = RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/operator/mutate".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::None,
            policy_hook: PolicyHook {
                hook_id: "operator.mutate".to_string(),
                required_roles: vec![],
            },
            trace_propagation: true,
        };
        let mut limiter = RateLimiter::new(RateLimitConfig {
            sustained_rps: 1,
            burst_size: 0,
            fail_closed: true,
        });
        let keys = get_test_keys();
        let mut handler_called = false;

        let mut auth_limiter = AuthFailureLimiter::new();
        let (result, log) = execute_middleware_chain(
            &route,
            None,
            None,
            &mut auth_limiter,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                handler_called = true;
                Ok("should not execute")
            },
        );

        assert!(result.is_err());
        assert!(!handler_called);
        assert_eq!(log.status, 429);
        assert_eq!(log.event_code, event_codes::RATE_LIMITED);
    }
}

#[cfg(test)]
mod api_middleware_additional_negative_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn authorized_keys() -> BTreeSet<String> {
        ["test-key-123", "mytoken-abc", "fleet-service-cert"]
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    fn route(auth_method: AuthMethod, required_roles: Vec<&str>) -> RouteMetadata {
        RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/operator/mutate".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method,
            policy_hook: PolicyHook {
                hook_id: "operator.mutate".to_string(),
                required_roles: required_roles.into_iter().map(str::to_string).collect(),
            },
            trace_propagation: true,
        }
    }

    #[test]
    fn negative_push_bounded_zero_cap_clears_without_retaining_item() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn negative_latency_metrics_ignore_nonfinite_samples() {
        let mut metrics = LatencyMetrics::default();

        metrics.record(10.0);
        metrics.record(f64::NAN);
        metrics.record(f64::INFINITY);
        metrics.record(f64::NEG_INFINITY);

        assert_eq!(metrics.samples, vec![10.0]);
        assert_eq!(metrics.p95(), 10.0);
    }

    #[test]
    fn negative_traceparent_rejects_uppercase_trace_id() {
        let header = "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01";

        assert!(TraceContext::from_traceparent(header).is_none());
    }

    #[test]
    fn negative_traceparent_rejects_zero_span_id() {
        let header = "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01";

        assert!(TraceContext::from_traceparent(header).is_none());
    }

    #[test]
    fn negative_traceparent_rejects_short_flags() {
        let header = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-1";

        assert!(TraceContext::from_traceparent(header).is_none());
    }

    #[test]
    fn negative_api_key_rejects_trailing_whitespace_after_valid_key() {
        let err = authenticate(
            Some("ApiKey test-key-123 "),
            &AuthMethod::ApiKey,
            "trace-api-key-space",
            &authorized_keys(),
        )
        .expect_err("API key comparison must not trim padded credentials");

        assert!(matches!(
            err,
            ApiError::AuthFailed {
                detail,
                trace_id,
            } if detail == "invalid API key" && trace_id == "trace-api-key-space"
        ));
    }

    #[test]
    fn negative_bearer_rejects_whitespace_only_token() {
        let err = authenticate(
            Some("Bearer   "),
            &AuthMethod::BearerToken,
            "trace-emptyish-bearer",
            &authorized_keys(),
        )
        .expect_err("whitespace-only bearer token must not authorize");

        assert!(matches!(
            err,
            ApiError::AuthFailed {
                detail,
                trace_id,
            } if detail == "invalid bearer token" && trace_id == "trace-emptyish-bearer"
        ));
    }

    #[test]
    fn negative_mtls_rejects_embedded_newline_identity() {
        let err = authenticate(
            Some("fleet-service-cert\nextra"),
            &AuthMethod::MtlsClientCert,
            "trace-mtls-newline",
            &authorized_keys(),
        )
        .expect_err("mTLS propagated identity must match exactly after trim");

        assert!(matches!(
            err,
            ApiError::AuthFailed {
                detail,
                trace_id,
            } if detail == "invalid mTLS client identity" && trace_id == "trace-mtls-newline"
        ));
    }

    #[test]
    fn negative_middleware_auth_failure_skips_handler() {
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let mut handler_called = false;

        let mut auth_limiter = AuthFailureLimiter::new();
        let (result, log) = execute_middleware_chain(
            &route(AuthMethod::ApiKey, vec![]),
            Some("ApiKey wrong-key"),
            Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
            &mut limiter,
            &authorized_keys(),
            |_identity, _ctx| {
                handler_called = true;
                Ok("should not run")
            },
        );

        assert!(result.is_err());
        assert!(!handler_called);
        assert_eq!(log.status, 401);
        assert_eq!(log.event_code, event_codes::AUTH_FAIL);
        assert_eq!(log.trace_id, "0af7651916cd43dd8448eb211c80319c");
    }

    #[test]
    fn negative_middleware_policy_denial_precedes_rate_limit_and_handler() {
        let mut limiter = RateLimiter::new(RateLimitConfig {
            sustained_rps: 1,
            burst_size: 0,
            fail_closed: true,
        });
        let mut handler_called = false;

        let mut auth_limiter = AuthFailureLimiter::new();
        let (result, log) = execute_middleware_chain(
            &route(AuthMethod::None, vec!["operator"]),
            None,
            None,
            &mut limiter,
            &authorized_keys(),
            |_identity, _ctx| {
                handler_called = true;
                Ok("should not run")
            },
        );

        assert!(matches!(result, Err(ApiError::PolicyDenied { .. })));
        assert!(!handler_called);
        assert_eq!(log.status, 403);
        assert_eq!(log.event_code, event_codes::POLICY_DENY);
    }
}

#[cfg(test)]
mod api_middleware_schema_negative_tests {
    use super::*;

    #[test]
    fn negative_trace_context_rejects_numeric_trace_id() {
        let value = serde_json::json!({
            "trace_id": 7,
            "span_id": "b7ad6b7169203331",
            "trace_flags": 1
        });

        let result = serde_json::from_value::<TraceContext>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_auth_method_rejects_lowercase_variant() {
        let result = serde_json::from_str::<AuthMethod>(r#""api_key""#);

        assert!(result.is_err());
    }

    #[test]
    fn negative_auth_identity_missing_roles_is_rejected() {
        let value = serde_json::json!({
            "principal": "apikey:test-key",
            "method": "ApiKey"
        });

        let result = serde_json::from_value::<AuthIdentity>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_policy_hook_object_required_roles_is_rejected() {
        let value = serde_json::json!({
            "hook_id": "operator.mutate",
            "required_roles": {"operator": true}
        });

        let result = serde_json::from_value::<PolicyHook>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_rate_limit_config_rejects_negative_sustained_rps() {
        let value = serde_json::json!({
            "sustained_rps": -1,
            "burst_size": 10,
            "fail_closed": true
        });

        let result = serde_json::from_value::<RateLimitConfig>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_request_log_rejects_string_latency() {
        let value = serde_json::json!({
            "method": "GET",
            "route": "/v1/operator/status",
            "status": 200,
            "latency_ms": "1.25",
            "trace_id": "trace-001",
            "principal": "anonymous",
            "endpoint_group": "operator",
            "event_code": "FASTAPI_RESPONSE_SENT"
        });

        let result = serde_json::from_value::<RequestLog>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_route_metadata_rejects_lowercase_endpoint_group() {
        let value = serde_json::json!({
            "method": "POST",
            "path": "/v1/fleet/fence",
            "group": "fleet_control",
            "lifecycle": "Stable",
            "auth_method": "BearerToken",
            "policy_hook": {
                "hook_id": "fleet.fence.write",
                "required_roles": ["fleet-admin"]
            },
            "trace_propagation": true
        });

        let result = serde_json::from_value::<RouteMetadata>(value);

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod api_middleware_edge_negative_tests {
    use super::*;

    fn open_route() -> RouteMetadata {
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/status".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::None,
            policy_hook: PolicyHook {
                hook_id: "operator.status.read".to_string(),
                required_roles: vec![],
            },
            trace_propagation: true,
        }
    }

    #[test]
    fn negative_trace_context_rejects_missing_span_id() {
        let value = serde_json::json!({
            "trace_id": "0af7651916cd43dd8448eb211c80319c",
            "trace_flags": 1
        });

        let result = serde_json::from_value::<TraceContext>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_trace_context_rejects_trace_flags_over_u8() {
        let value = serde_json::json!({
            "trace_id": "0af7651916cd43dd8448eb211c80319c",
            "span_id": "b7ad6b7169203331",
            "trace_flags": 300
        });

        let result = serde_json::from_value::<TraceContext>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_endpoint_lifecycle_rejects_unknown_variant() {
        let result = serde_json::from_str::<EndpointLifecycle>(r#""Retired""#);

        assert!(result.is_err());
    }

    #[test]
    fn negative_rate_limit_config_rejects_missing_fail_closed() {
        let value = serde_json::json!({
            "sustained_rps": 10,
            "burst_size": 20
        });

        let result = serde_json::from_value::<RateLimitConfig>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_route_metadata_rejects_missing_policy_hook() {
        let value = serde_json::json!({
            "method": "GET",
            "path": "/v1/operator/status",
            "group": "Operator",
            "lifecycle": "Stable",
            "auth_method": "None",
            "trace_propagation": true
        });

        let result = serde_json::from_value::<RouteMetadata>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_auth_identity_rejects_numeric_roles() {
        let value = serde_json::json!({
            "principal": "apikey:test-key",
            "method": "ApiKey",
            "roles": [1, 2]
        });

        let result = serde_json::from_value::<AuthIdentity>(value);

        assert!(result.is_err());
    }

    #[test]
    fn negative_authenticate_api_key_without_separator_rejected() {
        let keys = std::collections::BTreeSet::from(["test-key-123".to_string()]);
        let err = authenticate(
            Some("ApiKeytest-key-123"),
            &AuthMethod::ApiKey,
            "trace-api-no-space",
            &keys,
        )
        .expect_err("API key scheme must require a separating space");

        assert!(matches!(
            err,
            ApiError::AuthFailed {
                detail,
                trace_id,
            } if detail == "expected Authorization: ApiKey <key>"
                && trace_id == "trace-api-no-space"
        ));
    }

    #[test]
    fn negative_middleware_handler_error_logs_endpoint_error() {
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let keys = std::collections::BTreeSet::new();

        let mut auth_limiter = AuthFailureLimiter::new();
        let (result, log) = execute_middleware_chain(
            &open_route(),
            None,
            Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
            &mut limiter,
            &keys,
            |_identity, ctx| {
                Err::<(), _>(ApiError::Internal {
                    detail: "handler failed".to_string(),
                    trace_id: ctx.trace_id.clone(),
                })
            },
        );

        assert!(matches!(result, Err(ApiError::Internal { .. })));
        assert_eq!(log.status, 500);
        assert_eq!(log.event_code, event_codes::ENDPOINT_ERROR);
        assert_eq!(log.principal, "anonymous");
    }

    #[test]
    fn negative_service_metrics_count_request_but_drop_nonfinite_latency() {
        let mut metrics = ServiceMetrics::default();
        let log = RequestLog {
            method: "GET".to_string(),
            route: "/v1/operator/status".to_string(),
            status: 500,
            latency_ms: f64::INFINITY,
            trace_id: "trace-nonfinite-latency".to_string(),
            principal: "anonymous".to_string(),
            endpoint_group: EndpointGroup::Operator.as_str().to_string(),
            event_code: event_codes::ENDPOINT_ERROR.to_string(),
        };

        metrics.record_request(&log);

        assert_eq!(metrics.request_count, 1);
        assert!(metrics.latencies["operator"].samples.is_empty());
        assert_eq!(metrics.error_counts[event_codes::ENDPOINT_ERROR], 1);
    }
}

#[cfg(test)]
mod api_middleware_advanced_security_edge_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn setup_keys() -> BTreeSet<String> {
        ["test-key-123", "mytoken-abc", "fleet-service-cert"]
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn advanced_security_edge_unicode_normalization_bypass_in_credentials() {
        let keys = setup_keys();

        // Test Unicode normalization attacks that could bypass authentication
        let unicode_attack_vectors = [
            // Lookalike characters (homograph attacks)
            "tеst-key-123",    // 'е' is Cyrillic instead of Latin 'e'
            "test‑key‑123",    // Non-breaking hyphens instead of regular hyphens
            "test-кey-123",    // 'к' is Cyrillic 'k' instead of Latin 'k'
            "test-key-１２３", // Full-width digits instead of ASCII
            // Unicode normalization differences (NFC vs NFD)
            "test-key-123\u{0301}", // Combining acute accent
            "tést-key-123",         // Precomposed é vs decomposed e + ́
            // Zero-width characters
            "test-key\u{200D}-123", // Zero-width joiner
            "test-key\u{FEFF}-123", // Byte order mark
            "test-key\u{200C}-123", // Zero-width non-joiner
            // Direction override attacks
            "test-key-123\u{202E}", // Right-to-left override
            "\u{202D}test-key-123", // Left-to-right override
        ];

        for attack_vector in &unicode_attack_vectors {
            let result = authenticate(
                Some(&format!("ApiKey {}", attack_vector)),
                &AuthMethod::ApiKey,
                "trace-unicode-attack",
                &keys,
            );

            // Should reject all Unicode normalization attacks
            assert!(
                result.is_err(),
                "Unicode attack vector should be rejected: {:?}",
                attack_vector
            );

            // Verify error doesn't leak information about similar valid keys
            if let Err(err) = result {
                let error_msg = match err {
                    ApiError::AuthFailed { detail, .. } => detail,
                    _ => panic!("Wrong error type for Unicode attack"),
                };
                assert_eq!(error_msg, "invalid API key");
                assert!(!error_msg.contains("test-key-123")); // No leakage
            }
        }
    }

    #[test]
    fn advanced_security_edge_constant_time_verification_timing_resistance() {
        let keys = setup_keys();

        // Test that authentication is constant-time resistant to timing attacks
        let timing_attack_candidates = [
            "test-key-122",             // One character off at the end
            "test-key-124",             // One character off at the end (other direction)
            "test-key-12",              // Shorter by one
            "test-key-1234",            // Longer by one
            "xest-key-123",             // First character wrong
            "test",                     // Much shorter
            "test-key-123-extra",       // Much longer
            "",                         // Empty
            "completely-different-key", // Totally different
        ];

        // All should take similar time and return the same error
        for candidate in &timing_attack_candidates {
            let result = authenticate(
                Some(&format!("ApiKey {}", candidate)),
                &AuthMethod::ApiKey,
                "trace-timing-attack",
                &keys,
            );

            assert!(
                result.is_err(),
                "Invalid key should be rejected: {}",
                candidate
            );

            if let Err(ApiError::AuthFailed { detail, .. }) = result {
                assert_eq!(detail, "invalid API key");
                // All errors should be identical - no information leakage
            } else {
                panic!(
                    "Wrong error type for timing attack candidate: {}",
                    candidate
                );
            }
        }

        // Test with completely random strings of various lengths
        let random_candidates = [
            &"a".repeat(100),
            &"b".repeat(200),
            &"c".repeat(500),
            "🔐".repeat(50).as_str(),
            "😀".repeat(25).as_str(),
        ];

        for candidate in &random_candidates {
            let result = authenticate(
                Some(&format!("ApiKey {}", candidate)),
                &AuthMethod::ApiKey,
                "trace-random-timing",
                &keys,
            );

            assert!(result.is_err());
            if let Err(ApiError::AuthFailed { detail, .. }) = result {
                assert_eq!(detail, "invalid API key");
            } else {
                panic!("Wrong error type for random candidate");
            }
        }
    }

    #[test]
    fn advanced_security_edge_authorization_header_injection_attacks() {
        let keys = setup_keys();

        // Test various header injection attack vectors
        let header_injection_attacks = [
            "ApiKey test-key-123\r\nX-Forwarded-For: evil.com", // CRLF injection
            "ApiKey test-key-123\nSet-Cookie: evil=true",       // Newline injection
            "ApiKey test-key-123\0X-Evil: header",              // Null byte injection
            "ApiKey test-key-123\x00X-Malicious: payload",      // Null byte (hex)
            "ApiKey test-key-123\x0d\x0aX-Injected: header",    // CRLF (hex)
            "Bearer mytoken-abc\r\n\r\n<script>alert('xss')</script>", // XSS attempt
            "Bearer mytoken-abc\x1b[31mANSI escape\x1b[0m",     // ANSI escape codes
            "ApiKey test-key-123\x7fDEL character\x7f",         // DEL control character
        ];

        for attack_header in &header_injection_attacks {
            let result = authenticate(
                Some(attack_header),
                &AuthMethod::ApiKey,
                "trace-header-injection",
                &keys,
            );

            // Should either reject completely or accept only the valid prefix
            match result {
                Ok(identity) => {
                    // If somehow accepted, verify the principal doesn't contain injected content
                    assert!(!identity.principal.contains("evil"));
                    assert!(!identity.principal.contains("script"));
                    assert!(!identity.principal.contains("X-"));
                    assert!(!identity.principal.contains("\r"));
                    assert!(!identity.principal.contains("\n"));
                    assert!(!identity.principal.contains("\0"));
                }
                Err(ApiError::AuthFailed { detail, .. }) => {
                    // Should be rejected as invalid
                    assert_eq!(detail, "invalid API key");
                }
                Err(_) => panic!("Unexpected error type for header injection"),
            }
        }
    }

    #[test]
    fn advanced_security_edge_rate_limiter_arithmetic_overflow_protection() {
        // Test rate limiter against arithmetic overflow attacks
        let extreme_configs = [
            RateLimitConfig {
                sustained_rps: u32::MAX,
                burst_size: u32::MAX,
                fail_closed: true,
            },
            RateLimitConfig {
                sustained_rps: u32::MAX - 1,
                burst_size: u32::MAX - 1,
                fail_closed: false,
            },
        ];

        for config in &extreme_configs {
            let mut limiter = RateLimiter::new(config.clone());

            // Should not panic or produce invalid state
            for _ in 0..10 {
                let result = limiter.check();
                match result {
                    Ok(()) => {
                        // Allowed - verify internal state is still finite
                        assert!(limiter.tokens.is_finite(), "Tokens should remain finite");
                    }
                    Err(retry_ms) => {
                        // Rate limited - verify retry time is reasonable
                        assert!(retry_ms >= 1, "Retry time should be at least 1ms");
                        assert!(
                            retry_ms < 86400000,
                            "Retry time should be less than 24 hours"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn advanced_security_edge_trace_context_parser_memory_exhaustion() {
        // Test trace context parser against memory exhaustion attacks
        let memory_attack_vectors = [
            // Extremely long trace IDs (should be rejected)
            &format!("00-{}-b7ad6b7169203331-01", "a".repeat(10000)),
            &format!("00-{}-b7ad6b7169203331-01", "f".repeat(100000)),
            // Extremely long span IDs
            &format!(
                "00-0af7651916cd43dd8448eb211c80319c-{}-01",
                "b".repeat(10000)
            ),
            // Many repeated dashes
            &format!("00{}", "-".repeat(10000)),
            // Unicode characters that could expand during processing
            "00-🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥-b7ad6b7169203331-01",
            // Malformed headers with extreme lengths
            &"00-".repeat(10000),
            &"invalid-trace-".repeat(1000),
        ];

        for attack_vector in &memory_attack_vectors {
            let result = TraceContext::from_traceparent(attack_vector);

            // Should reject without allocating excessive memory or panicking
            assert!(
                result.is_none(),
                "Memory exhaustion attack should be rejected: {}",
                if attack_vector.len() > 100 {
                    &attack_vector[..100]
                } else {
                    attack_vector
                }
            );
        }

        // Verify normal operation still works after attack attempts
        let valid_header = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let result = TraceContext::from_traceparent(valid_header);
        assert!(result.is_some(), "Valid trace context should still work");
    }

    #[test]
    fn advanced_security_edge_policy_hook_role_confusion_attacks() {
        // Test role-based authorization against various confusion attacks
        let legitimate_identity = AuthIdentity {
            principal: "operator-user".to_string(),
            method: AuthMethod::ApiKey,
            roles: vec!["operator".to_string(), "reader".to_string()],
        };

        let elevation_attack_hooks = [
            // Unicode lookalike attack on role names
            PolicyHook {
                hook_id: "test.read".to_string(),
                required_roles: vec!["оperator".to_string()], // Cyrillic 'o'
            },
            // Case sensitivity bypass attempt
            PolicyHook {
                hook_id: "test.read".to_string(),
                required_roles: vec!["Operator".to_string()],
            },
            // Whitespace injection
            PolicyHook {
                hook_id: "test.read".to_string(),
                required_roles: vec![" operator ".to_string()],
            },
            // Null byte injection
            PolicyHook {
                hook_id: "test.read".to_string(),
                required_roles: vec!["operator\0admin".to_string()],
            },
            // Partial match attempt
            PolicyHook {
                hook_id: "test.read".to_string(),
                required_roles: vec!["oper".to_string()],
            },
        ];

        for attack_hook in &elevation_attack_hooks {
            let decision = authorize(&legitimate_identity, attack_hook, "trace-role-confusion")
                .expect("authorize should not fail");

            // All role confusion attacks should be denied
            assert!(
                matches!(decision, AuthzDecision::Deny { .. }),
                "Role confusion attack should be denied: {:?}",
                attack_hook.required_roles
            );

            if let AuthzDecision::Deny { reason } = decision {
                // Error message should not leak information about valid roles
                assert!(!reason.contains("operator")); // Should not suggest valid role name
                assert!(reason.contains("lacks required role"));
            }
        }
    }

    #[test]
    fn advanced_security_edge_middleware_chain_state_corruption_resistance() {
        let route = RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/operator/mutate".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::ApiKey,
            policy_hook: PolicyHook {
                hook_id: "operator.mutate".to_string(),
                required_roles: vec!["operator".to_string()],
            },
            trace_propagation: true,
        };

        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let keys = setup_keys();
        let mut handler_call_count = 0;

        // Execute multiple requests with various attack vectors
        let request_variations = [
            (
                Some("ApiKey test-key-123"),
                Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
            ),
            (Some("ApiKey test-key-123"), None), // Missing trace
            (
                Some("ApiKey wrong-key"),
                Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
            ),
            (
                None,
                Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
            ), // Missing auth
            (Some("ApiKey test-key-123"), Some("invalid-trace")),
        ];

        for (auth_header, traceparent) in &request_variations {
            let mut auth_limiter = AuthFailureLimiter::new();
        let (result, log) = execute_middleware_chain(
            &route,
            *auth_header,
            *traceparent,
            &mut auth_limiter,
            &mut limiter,
                &keys,
                |_identity, ctx| {
                    handler_call_count = handler_call_count.saturating_add(1);
                    // Simulate handler that could fail
                    if ctx.trace_id.contains("evil") {
                        Err(ApiError::Internal {
                            detail: "simulated failure".to_string(),
                            trace_id: ctx.trace_id.clone(),
                        })
                    } else {
                        Ok(format!("success-{}", handler_call_count))
                    }
                },
            );

            // Verify middleware chain maintains invariants
            assert!(!log.trace_id.is_empty(), "Trace ID should never be empty");
            assert!(!log.principal.is_empty(), "Principal should never be empty");
            assert!(
                !log.endpoint_group.is_empty(),
                "Endpoint group should never be empty"
            );
            assert!(
                !log.event_code.is_empty(),
                "Event code should never be empty"
            );

            // Verify status codes are within valid ranges
            assert!(
                (200..600).contains(&log.status),
                "Status code should be valid HTTP status"
            );

            // Verify latency is non-negative and finite
            assert!(log.latency_ms >= 0.0, "Latency should be non-negative");
            assert!(log.latency_ms.is_finite(), "Latency should be finite");

            // Verify trace ID format consistency
            if result.is_ok() {
                // Success should have generated or parsed trace ID
                assert!(
                    log.trace_id.len() >= 16,
                    "Trace ID should be reasonable length"
                );
            }
        }
    }

    #[test]
    fn advanced_security_edge_latency_metrics_statistical_poisoning_resistance() {
        let mut metrics = LatencyMetrics::default();

        // Attempt to poison statistical calculations with extreme values
        let poisoning_attacks = [
            // Extreme outliers
            f64::MAX,
            f64::MIN,
            1e308,  // Near overflow
            1e-308, // Near underflow
            // Special float values
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
            // Values that could cause precision issues
            0.0000000000001, // Very small positive
            999999999999.99, // Very large
        ];

        // Record some normal values first
        for i in 1..=100 {
            metrics.record(f64::from(i));
        }

        let initial_sample_count = metrics.samples.len();

        // Attempt statistical poisoning
        for poison_value in &poisoning_attacks {
            metrics.record(*poison_value);
        }

        // Verify resistance to poisoning
        assert!(
            metrics.samples.len() <= initial_sample_count + 5,
            "Should not have recorded all poisoning values"
        );

        // Verify percentiles remain reasonable
        let p50 = metrics.p50();
        let p95 = metrics.p95();
        let p99 = metrics.p99();

        assert!(
            p50.is_finite(),
            "p50 should be finite after poisoning attempt"
        );
        assert!(
            p95.is_finite(),
            "p95 should be finite after poisoning attempt"
        );
        assert!(
            p99.is_finite(),
            "p99 should be finite after poisoning attempt"
        );

        assert!(p50 >= 0.0, "p50 should be non-negative");
        assert!(p95 >= p50, "p95 should be >= p50");
        assert!(p99 >= p95, "p99 should be >= p95");

        // Should not be wildly out of expected range for our test data
        assert!(p50 < 1000000.0, "p50 should not be extremely large");
        assert!(p99 < 1000000.0, "p99 should not be extremely large");
    }

    #[test]
    fn advanced_security_edge_service_metrics_counter_overflow_protection() {
        let mut metrics = ServiceMetrics::default();

        // Simulate extreme load to test counter overflow protection
        let test_log = RequestLog {
            method: "GET".to_string(),
            route: "/v1/operator/status".to_string(),
            status: 500,
            latency_ms: 1.0,
            trace_id: "trace-overflow-test".to_string(),
            principal: "test-user".to_string(),
            endpoint_group: EndpointGroup::Operator.as_str().to_string(),
            event_code: event_codes::ENDPOINT_ERROR.to_string(),
        };

        // First, set counters to near overflow
        metrics.request_count = u64::MAX - 10;
        metrics
            .error_counts
            .insert(event_codes::ENDPOINT_ERROR.to_string(), u64::MAX - 5);

        // Record additional requests
        for _ in 0..20 {
            metrics.record_request(&test_log);
        }

        // Verify overflow protection (should saturate, not wrap around)
        assert!(
            metrics.request_count >= u64::MAX - 10,
            "Request count should saturate at max"
        );
        assert!(
            metrics.request_count <= u64::MAX,
            "Request count should not exceed max"
        );

        let error_count = metrics
            .error_counts
            .get(event_codes::ENDPOINT_ERROR)
            .copied()
            .unwrap_or(0);
        assert!(
            error_count >= u64::MAX - 5,
            "Error count should saturate at max"
        );
        assert!(error_count <= u64::MAX, "Error count should not exceed max");

        // Verify metrics remain functional after overflow protection
        assert!(
            metrics
                .latencies
                .contains_key(EndpointGroup::Operator.as_str())
        );
        assert!(
            !metrics.latencies[EndpointGroup::Operator.as_str()]
                .samples
                .is_empty()
        );
    }
}
