//! Cross-cutting middleware for the control-plane service skeleton.
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

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

use super::error::ApiError;
use super::utf8_prefix;

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
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        let trace_id = parts[1].to_string();
        let span_id = parts[2].to_string();
        let trace_flags = u8::from_str_radix(parts[3], 16).ok()?;

        if trace_id.len() != 32 || span_id.len() != 16 {
            return None;
        }

        Some(Self {
            trace_id,
            span_id,
            trace_flags,
        })
    }

    /// Generate a new trace context with a random trace ID.
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
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.span_id, self.trace_flags
        )
    }
}

/// Simple span ID generation using timestamp-based entropy.
fn rand_span_id() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Mix nanoseconds with a constant for uniqueness
    now.as_nanos() as u64 ^ 0x517c_c1b7_2722_0a95
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
pub type AuthResult = Result<AuthIdentity, ApiError>;

/// Authenticate a request based on provided credentials.
pub fn authenticate(
    auth_header: Option<&str>,
    required_method: &AuthMethod,
    trace_id: &str,
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
            Ok(AuthIdentity {
                principal: format!("apikey:{}", utf8_prefix(key, 8)),
                method: AuthMethod::ApiKey,
                roles: vec!["operator".to_string()],
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
            Ok(AuthIdentity {
                principal: format!("token:{}", utf8_prefix(token, 8)),
                method: AuthMethod::BearerToken,
                roles: vec!["operator".to_string(), "verifier".to_string()],
            })
        }
        AuthMethod::MtlsClientCert => {
            // mTLS verification happens at the transport layer; here we just
            // check that the identity was propagated via a header.
            let header = auth_header.ok_or_else(|| ApiError::AuthFailed {
                detail: "mTLS client identity not propagated".to_string(),
                trace_id: trace_id.to_string(),
            })?;
            Ok(AuthIdentity {
                principal: format!("mtls:{header}"),
                method: AuthMethod::MtlsClientCert,
                roles: vec![
                    "operator".to_string(),
                    "verifier".to_string(),
                    "fleet-admin".to_string(),
                ],
            })
        }
    }
}

// ── Authorization (RBAC + Policy Hook) ─────────────────────────────────────

/// Policy hook descriptor bound to a route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyHook {
    /// Unique hook identifier (e.g., `operator.status.read`).
    pub hook_id: String,
    /// Roles that satisfy this hook.
    pub required_roles: Vec<String>,
}

/// Authorization check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthzDecision {
    /// Access granted.
    Allow,
    /// Access denied with reason.
    Deny { reason: String },
}

/// Check authorization against the policy hook.
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

// ── Rate Limiting ──────────────────────────────────────────────────────────

/// Rate limiter configuration for an endpoint group.
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
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    tokens: f64,
    last_check: Instant,
}

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
        let elapsed = now.duration_since(self.last_check).as_secs_f64();
        self.last_check = now;

        // Refill tokens
        self.tokens += elapsed * f64::from(self.config.sustained_rps);
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

// ── Request/Response Telemetry ─────────────────────────────────────────────

/// Structured request log entry emitted after handler execution.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointGroup {
    Operator,
    Verifier,
    FleetControl,
}

impl EndpointGroup {
    pub fn as_str(&self) -> &'static str {
        match self {
            EndpointGroup::Operator => "operator",
            EndpointGroup::Verifier => "verifier",
            EndpointGroup::FleetControl => "fleet_control",
        }
    }
}

impl std::fmt::Display for EndpointGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Event codes emitted by the middleware/service layer.
pub mod event_codes {
    pub const SERVICE_START: &str = "FASTAPI_SERVICE_START";
    pub const REQUEST_RECEIVED: &str = "FASTAPI_REQUEST_RECEIVED";
    pub const AUTH_SUCCESS: &str = "FASTAPI_AUTH_SUCCESS";
    pub const AUTH_FAIL: &str = "FASTAPI_AUTH_FAIL";
    pub const POLICY_DENY: &str = "FASTAPI_POLICY_DENY";
    pub const RATE_LIMITED: &str = "FASTAPI_RATE_LIMITED";
    pub const ENDPOINT_ERROR: &str = "FASTAPI_ENDPOINT_ERROR";
    pub const RESPONSE_SENT: &str = "FASTAPI_RESPONSE_SENT";
}

// ── Middleware Chain ────────────────────────────────────────────────────────

/// Route metadata describing middleware requirements for one endpoint.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointLifecycle {
    Experimental,
    Stable,
    Deprecated,
}

impl EndpointLifecycle {
    pub fn as_str(&self) -> &'static str {
        match self {
            EndpointLifecycle::Experimental => "experimental",
            EndpointLifecycle::Stable => "stable",
            EndpointLifecycle::Deprecated => "deprecated",
        }
    }
}

/// Middleware chain result: either a successful response or an error.
pub type MiddlewareResult<T> = Result<T, ApiError>;

/// Execute the full middleware chain for a request.
///
/// Chain order: trace → auth → authz → rate limit → handler
pub fn execute_middleware_chain<F, T>(
    route: &RouteMetadata,
    auth_header: Option<&str>,
    traceparent: Option<&str>,
    rate_limiter: &mut RateLimiter,
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

    // Step 2: Authentication
    let identity = match authenticate(auth_header, &route.auth_method, &trace_id) {
        Ok(id) => id,
        Err(err) => {
            let log = build_request_log(route, 401, start, &trace_id, "anonymous");
            return (Err(err), log);
        }
    };

    // Step 3: Authorization
    if let Err(err) = enforce_policy(&identity, &route.policy_hook, &trace_id) {
        let log = build_request_log(route, 403, start, &trace_id, &identity.principal);
        return (Err(err), log);
    }

    // Step 4: Rate limiting
    if let Err(err) = check_rate_limit(rate_limiter, &trace_id) {
        let log = build_request_log(route, 429, start, &trace_id, &identity.principal);
        return (Err(err), log);
    }

    // Step 5: Handler execution
    let result = handler(&identity, &trace_ctx);

    let status = match &result {
        Ok(_) => 200,
        Err(e) => e.to_problem(&route.path).status,
    };

    let log = build_request_log(route, status, start, &trace_id, &identity.principal);

    (result, log)
}

fn build_request_log(
    route: &RouteMetadata,
    status: u16,
    start: Instant,
    trace_id: &str,
    principal: &str,
) -> RequestLog {
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
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
pub fn default_rate_limit(group: EndpointGroup) -> RateLimitConfig {
    match group {
        EndpointGroup::Operator => RateLimitConfig {
            sustained_rps: 100,
            burst_size: 200,
            fail_closed: false,
        },
        EndpointGroup::Verifier => RateLimitConfig {
            sustained_rps: 50,
            burst_size: 100,
            fail_closed: false,
        },
        EndpointGroup::FleetControl => RateLimitConfig {
            sustained_rps: 20,
            burst_size: 40,
            fail_closed: true, // fail-closed for dangerous mutations
        },
    }
}

/// Collect latency metrics per endpoint group.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LatencyMetrics {
    pub samples: Vec<f64>,
}

impl LatencyMetrics {
    pub fn record(&mut self, latency_ms: f64) {
        self.samples.push(latency_ms);
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
        let idx = (f64::from(pct) / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
        let target_idx = idx.min(sorted.len() - 1);
        let (_, val, _) = sorted.select_nth_unstable_by(target_idx, |a, b| {
            a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
        });
        *val
    }
}

// ── Middleware Metrics Aggregator ───────────────────────────────────────────

/// Aggregated metrics for the control-plane service.
#[derive(Debug, Default)]
pub struct ServiceMetrics {
    pub latencies: BTreeMap<String, LatencyMetrics>,
    pub error_counts: BTreeMap<String, u64>,
    pub request_count: u64,
}

impl ServiceMetrics {
    pub fn record_request(&mut self, log: &RequestLog) {
        self.request_count += 1;
        self.latencies
            .entry(log.endpoint_group.clone())
            .or_default()
            .record(log.latency_ms);
        if log.status >= 400 {
            *self.error_counts.entry(log.event_code.clone()).or_insert(0) += 1;
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
    }

    #[test]
    fn trace_context_roundtrip() {
        let tc = TraceContext::generate();
        let header = tc.to_traceparent();
        let parsed = TraceContext::from_traceparent(&header).expect("parse roundtrip");
        assert_eq!(tc.trace_id, parsed.trace_id);
    }

    #[test]
    fn authenticate_none_method() {
        let result = authenticate(None, &AuthMethod::None, "t-1");
        let identity = result.expect("auth none");
        assert_eq!(identity.principal, "anonymous");
    }

    #[test]
    fn authenticate_api_key() {
        let result = authenticate(Some("ApiKey test-key-123"), &AuthMethod::ApiKey, "t-2");
        let identity = result.expect("auth api key");
        assert!(identity.principal.starts_with("apikey:"));
    }

    #[test]
    fn authenticate_bearer_token() {
        let result = authenticate(Some("Bearer mytoken-abc"), &AuthMethod::BearerToken, "t-3");
        let identity = result.expect("auth bearer");
        assert!(identity.principal.starts_with("token:"));
    }

    #[test]
    fn authenticate_api_key_handles_unicode_without_panicking() {
        let result = authenticate(Some("ApiKey 🔐鍵🙂abc123"), &AuthMethod::ApiKey, "t-2u");
        let identity = result.expect("auth api key");
        let expected: String = "🔐鍵🙂abc123".chars().take(8).collect();
        assert_eq!(identity.principal, format!("apikey:{expected}"));
    }

    #[test]
    fn authenticate_bearer_handles_unicode_without_panicking() {
        let result = authenticate(
            Some("Bearer 令牌🙂abcXYZ"),
            &AuthMethod::BearerToken,
            "t-3u",
        );
        let identity = result.expect("auth bearer");
        let expected: String = "令牌🙂abcXYZ".chars().take(8).collect();
        assert_eq!(identity.principal, format!("token:{expected}"));
    }

    #[test]
    fn authenticate_missing_header() {
        let result = authenticate(None, &AuthMethod::ApiKey, "t-4");
        assert!(result.is_err());
    }

    #[test]
    fn authenticate_wrong_prefix() {
        let result = authenticate(Some("Basic abc"), &AuthMethod::BearerToken, "t-5");
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
        assert!(!op.fail_closed);

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

        let (result, log) = execute_middleware_chain(
            &route,
            None,
            Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
            &mut limiter,
            |_identity, _ctx| Ok("ok".to_string()),
        );

        assert!(result.is_ok());
        assert_eq!(log.status, 200);
        assert_eq!(log.event_code, "FASTAPI_RESPONSE_SENT");
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

        let (result, log) = execute_middleware_chain(
            &route,
            None, // no auth header
            None,
            &mut limiter,
            |_identity, _ctx| Ok("should not reach"),
        );

        assert!(result.is_err());
        assert_eq!(log.status, 401);
        assert_eq!(log.event_code, "FASTAPI_AUTH_FAIL");
    }
}
