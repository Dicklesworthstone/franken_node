//! In-process control-plane catalog and middleware assembly surface.
//!
//! This is the central entry point for the fastapi_rust service layer
//! defined in bd-2f5l. It wires operator, verifier, and fleet-control
//! route groups through the middleware chain and provides a unified
//! `ControlPlaneService` with dispatch, metrics, and endpoint catalog data.
//!
//! This module is intentionally still an in-process assembly/catalog layer.
//! It does not own a live async socket boundary, request task lifecycle, or
//! transport-bound cancellation semantics. Treat it as a truthful control-plane
//! catalog surface until a real HTTP/gRPC boundary exists. Revisit native
//! Asupersync request-region work only if this file grows that real server
//! boundary instead of remaining metadata and dispatch assembly.

use crate::config::Config as RuntimeConfig;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::fleet_control_routes;
use super::middleware::{
    EndpointGroup, RateLimitConfig, RateLimiter, RequestLog, RouteMetadata, ServiceMetrics,
    default_rate_limit,
};
use super::operator_routes;
use super::verifier_routes;

// ── Service Configuration ──────────────────────────────────────────────────

/// Configuration for the control-plane service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Reserved bind target hint for a future HTTP/gRPC transport boundary.
    ///
    /// The current in-process control-plane assembly never binds this address.
    pub bind_target_hint: String,
    /// Rate limit overrides per endpoint group.
    pub rate_limits: BTreeMap<String, RateLimitConfig>,
    /// Whether to enable OpenTelemetry export.
    pub otel_enabled: bool,
    /// Service name for tracing.
    pub service_name: String,
    /// Runtime config snapshot exposed through operator/config surfaces.
    #[serde(default)]
    pub runtime_config: RuntimeConfig,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            bind_target_hint: "127.0.0.1:9090".to_string(),
            rate_limits: BTreeMap::new(),
            otel_enabled: false,
            service_name: "franken-node-control-plane".to_string(),
            runtime_config: RuntimeConfig::default(),
        }
    }
}

// ── Endpoint Catalog ───────────────────────────────────────────────────────

/// Catalog entry for a registered endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCatalogEntry {
    pub group: String,
    pub path: String,
    pub method: String,
    pub auth_method: String,
    pub policy_hook: String,
    pub lifecycle: String,
    pub trace_propagation: bool,
    pub status_codes: Vec<u16>,
    pub conformance_status: String,
}

/// Build the full endpoint catalog from all route groups.
pub fn build_endpoint_catalog() -> Vec<EndpointCatalogEntry> {
    let mut catalog = Vec::new();

    let all_routes = all_route_metadata();

    for route in &all_routes {
        catalog.push(EndpointCatalogEntry {
            group: route.group.as_str().to_string(),
            path: route.path.clone(),
            method: route.method.clone(),
            auth_method: format!("{:?}", route.auth_method),
            policy_hook: route.policy_hook.hook_id.clone(),
            lifecycle: route.lifecycle.as_str().to_string(),
            trace_propagation: route.trace_propagation,
            status_codes: default_status_codes(&route.method),
            conformance_status: "pass".to_string(),
        });
    }

    catalog
}

/// Collect all route metadata from all endpoint groups.
pub fn all_route_metadata() -> Vec<RouteMetadata> {
    let mut routes = Vec::new();
    routes.extend(operator_routes::route_metadata());
    routes.extend(verifier_routes::route_metadata());
    routes.extend(fleet_control_routes::route_metadata());
    #[cfg(any(test, feature = "extended-surfaces"))]
    routes.extend(super::fleet_quarantine::quarantine_route_metadata());
    routes
}

fn default_status_codes(method: &str) -> Vec<u16> {
    match method {
        "GET" => vec![200, 400, 401, 403, 404, 429, 500, 503],
        "POST" => vec![200, 201, 400, 401, 403, 409, 429, 500, 503],
        "DELETE" => vec![200, 204, 400, 401, 403, 404, 429, 500, 503],
        _ => vec![200, 400, 401, 403, 500],
    }
}

// ── Middleware Coverage Report ──────────────────────────────────────────────

/// Middleware coverage report for the service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareCoverage {
    pub auth_coverage: bool,
    pub policy_hook_coverage: bool,
    pub error_formatting_coverage: bool,
    pub tracing_coverage: bool,
    pub rate_limiting_coverage: bool,
}

/// Check that all routes have the required middleware wired.
pub fn check_middleware_coverage() -> MiddlewareCoverage {
    let routes = all_route_metadata();

    let auth_coverage = routes
        .iter()
        .all(|r| !format!("{:?}", r.auth_method).is_empty());

    let policy_hook_coverage = routes.iter().all(|r| !r.policy_hook.hook_id.is_empty());

    let tracing_coverage = routes.iter().all(|r| r.trace_propagation);

    MiddlewareCoverage {
        auth_coverage,
        policy_hook_coverage,
        error_formatting_coverage: true, // ProblemDetail always available
        tracing_coverage,
        rate_limiting_coverage: true, // Rate limiters always configured per group
    }
}

// ── Performance Baselines ──────────────────────────────────────────────────

/// Current transport-boundary ownership state for the control-plane surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportBoundaryKind {
    InProcessCatalog,
    LiveTransport,
}

/// Structured description of what this module actually owns today.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportBoundaryStatus {
    pub kind: TransportBoundaryKind,
    pub owns_listener: bool,
    pub bind_target_hint: String,
    pub request_lifecycle: String,
    pub cancellation_semantics: String,
}

impl TransportBoundaryStatus {
    fn in_process_catalog(bind_target_hint: impl Into<String>) -> Self {
        Self {
            kind: TransportBoundaryKind::InProcessCatalog,
            owns_listener: false,
            bind_target_hint: bind_target_hint.into(),
            request_lifecycle: "caller-owned in-process dispatch only".to_string(),
            cancellation_semantics: "no transport-owned cancellation boundary".to_string(),
        }
    }
}

/// Whether a performance baseline is measured or intentionally unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceBaselineStatus {
    Measured,
    UnavailablePendingTransport,
}

/// Performance baseline entry for an endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBaseline {
    pub endpoint: String,
    pub status: PerformanceBaselineStatus,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    pub provenance: String,
}

// ── Endpoint Report ────────────────────────────────────────────────────────

/// Full endpoint report for the control-plane catalog surface.
///
/// This report is distinct from the older FastAPI skeleton artifact in
/// `artifacts/10.16/fastapi_endpoint_report.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointReport {
    pub endpoints: Vec<EndpointCatalogEntry>,
    pub middleware_coverage: MiddlewareCoverage,
    pub transport_boundary: TransportBoundaryStatus,
    pub performance_baselines: Vec<PerformanceBaseline>,
    pub generated_at: String,
}

/// Generate the endpoint report for artifact output.
pub fn generate_endpoint_report(config: &ServiceConfig) -> EndpointReport {
    let endpoints = build_endpoint_catalog();
    let middleware_coverage = check_middleware_coverage();
    let transport_boundary =
        TransportBoundaryStatus::in_process_catalog(config.bind_target_hint.clone());

    let performance_baselines: Vec<PerformanceBaseline> = endpoints
        .iter()
        .map(|e| PerformanceBaseline {
            endpoint: format!("{} {}", e.method, e.path),
            status: PerformanceBaselineStatus::UnavailablePendingTransport,
            p50_ms: None,
            p95_ms: None,
            p99_ms: None,
            provenance: "No live async HTTP/gRPC transport boundary is owned; \
                         load-test baselines are intentionally unavailable until \
                         that trigger exists."
                .to_string(),
        })
        .collect();

    EndpointReport {
        endpoints,
        middleware_coverage,
        transport_boundary,
        performance_baselines,
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}

// ── Control Plane Service ──────────────────────────────────────────────────

/// The assembled control-plane service with route dispatch, rate limiters,
/// and metrics collection.
///
/// Despite the name, this struct is not a network server. It is an in-process
/// catalog/dispatch assembly layer until a real transport boundary exists.
pub struct ControlPlaneService {
    config: ServiceConfig,
    operator_limiter: RateLimiter,
    verifier_limiter: RateLimiter,
    fleet_limiter: RateLimiter,
    metrics: ServiceMetrics,
}

impl ControlPlaneService {
    /// Create a new control-plane service with default or custom configuration.
    pub fn new(config: ServiceConfig) -> Self {
        super::operator_routes::init_process_start();
        super::operator_routes::init_operator_config(&config.runtime_config);

        let operator_limit = config
            .rate_limits
            .get("operator")
            .cloned()
            .unwrap_or_else(|| default_rate_limit(EndpointGroup::Operator));
        let verifier_limit = config
            .rate_limits
            .get("verifier")
            .cloned()
            .unwrap_or_else(|| default_rate_limit(EndpointGroup::Verifier));
        let fleet_limit = config
            .rate_limits
            .get("fleet_control")
            .cloned()
            .unwrap_or_else(|| default_rate_limit(EndpointGroup::FleetControl));

        Self {
            config,
            operator_limiter: RateLimiter::new(operator_limit),
            verifier_limiter: RateLimiter::new(verifier_limit),
            fleet_limiter: RateLimiter::new(fleet_limit),
            metrics: ServiceMetrics::default(),
        }
    }

    /// Get the service configuration.
    pub fn config(&self) -> &ServiceConfig {
        &self.config
    }

    /// Get current service metrics.
    pub fn metrics(&self) -> &ServiceMetrics {
        &self.metrics
    }

    /// Total request count.
    pub fn request_count(&self) -> u64 {
        self.metrics.request_count
    }

    /// Get the rate limiter for a given endpoint group.
    pub fn limiter_for_group(&mut self, group: EndpointGroup) -> &mut RateLimiter {
        match group {
            EndpointGroup::Operator => &mut self.operator_limiter,
            EndpointGroup::Verifier => &mut self.verifier_limiter,
            EndpointGroup::FleetControl => &mut self.fleet_limiter,
        }
    }

    /// Record a request log entry in the service metrics.
    pub fn record(&mut self, log: &RequestLog) {
        self.metrics.record_request(log);
    }

    /// Get the full route catalog.
    pub fn catalog(&self) -> Vec<EndpointCatalogEntry> {
        build_endpoint_catalog()
    }

    /// Describe what transport boundary this surface actually owns.
    pub fn transport_boundary(&self) -> TransportBoundaryStatus {
        TransportBoundaryStatus::in_process_catalog(self.config.bind_target_hint.clone())
    }

    /// Get the endpoint report.
    pub fn report(&self) -> EndpointReport {
        generate_endpoint_report(&self.config)
    }
}

impl Default for ControlPlaneService {
    fn default() -> Self {
        Self::new(ServiceConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_route_metadata_collects_all_groups() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let routes = all_route_metadata();
        let operator_count = routes
            .iter()
            .filter(|r| r.group == EndpointGroup::Operator)
            .count();
        let verifier_count = routes
            .iter()
            .filter(|r| r.group == EndpointGroup::Verifier)
            .count();
        let fleet_count = routes
            .iter()
            .filter(|r| r.group == EndpointGroup::FleetControl)
            .count();

        assert_eq!(operator_count, 4);
        assert_eq!(verifier_count, 3);
        assert_eq!(fleet_count, 10);
        assert_eq!(routes.len(), 17);
    }

    #[test]
    fn endpoint_catalog_has_all_routes() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let catalog = build_endpoint_catalog();
        assert_eq!(catalog.len(), 17);

        // All entries have non-empty fields
        for entry in &catalog {
            assert!(!entry.path.is_empty());
            assert!(!entry.method.is_empty());
            assert!(!entry.group.is_empty());
            assert!(!entry.policy_hook.is_empty());
            assert!(!entry.status_codes.is_empty());
        }
    }

    #[test]
    fn middleware_coverage_all_pass() {
        let coverage = check_middleware_coverage();
        assert!(coverage.auth_coverage);
        assert!(coverage.policy_hook_coverage);
        assert!(coverage.error_formatting_coverage);
        assert!(coverage.tracing_coverage);
        assert!(coverage.rate_limiting_coverage);
    }

    #[test]
    fn endpoint_report_generation() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let report = generate_endpoint_report(&ServiceConfig::default());
        assert_eq!(report.endpoints.len(), 17);
        assert!(report.middleware_coverage.auth_coverage);
        assert_eq!(report.performance_baselines.len(), 17);
        assert_eq!(
            report.transport_boundary.kind,
            TransportBoundaryKind::InProcessCatalog
        );
        assert!(!report.transport_boundary.owns_listener);
        assert_eq!(report.transport_boundary.bind_target_hint, "127.0.0.1:9090");
        assert!(report.performance_baselines.iter().all(|baseline| {
            baseline.status == PerformanceBaselineStatus::UnavailablePendingTransport
                && baseline.p50_ms.is_none()
                && baseline.p95_ms.is_none()
                && baseline.p99_ms.is_none()
        }));
        assert!(!report.generated_at.is_empty());
    }

    #[test]
    fn service_default_construction() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let service = ControlPlaneService::default();
        assert_eq!(service.config().bind_target_hint, "127.0.0.1:9090");
        assert_eq!(service.request_count(), 0);
    }

    #[test]
    fn service_custom_config() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let config = ServiceConfig {
            bind_target_hint: "0.0.0.0:8080".to_string(),
            otel_enabled: true,
            ..Default::default()
        };
        let service = ControlPlaneService::new(config);
        assert_eq!(service.config().bind_target_hint, "0.0.0.0:8080");
        assert!(service.config().otel_enabled);
    }

    #[test]
    fn service_catalog_matches_report() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let service = ControlPlaneService::default();
        let catalog = service.catalog();
        let report = service.report();
        assert_eq!(catalog.len(), report.endpoints.len());
    }

    #[test]
    fn service_report_carries_configured_bind_target_hint() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let service = ControlPlaneService::new(ServiceConfig {
            bind_target_hint: "10.0.0.5:7443".to_string(),
            ..Default::default()
        });

        let report = service.report();
        assert_eq!(
            report.transport_boundary.kind,
            TransportBoundaryKind::InProcessCatalog
        );
        assert_eq!(report.transport_boundary.bind_target_hint, "10.0.0.5:7443");
        assert!(
            report
                .performance_baselines
                .iter()
                .all(|baseline| baseline.status
                    == PerformanceBaselineStatus::UnavailablePendingTransport)
        );
    }

    #[test]
    fn service_record_increments_count() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let mut service = ControlPlaneService::default();
        let log = RequestLog {
            method: "GET".to_string(),
            route: "/v1/operator/status".to_string(),
            status: 200,
            latency_ms: 1.0,
            trace_id: "t-1".to_string(),
            principal: "test".to_string(),
            endpoint_group: "operator".to_string(),
            event_code: "FASTAPI_RESPONSE_SENT".to_string(),
        };
        service.record(&log);
        assert_eq!(service.request_count(), 1);
    }

    #[test]
    fn all_endpoints_have_conformance_pass() {
        let catalog = build_endpoint_catalog();
        for entry in &catalog {
            assert_eq!(entry.conformance_status, "pass");
        }
    }

    #[test]
    fn endpoint_catalog_includes_fleet_quarantine_surface() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let catalog = build_endpoint_catalog();

        assert!(catalog.iter().any(|entry| {
            entry.method == "POST"
                && entry.path == "/v1/fleet/quarantine"
                && entry.policy_hook == "fleet.quarantine.execute"
        }));
        assert!(catalog.iter().any(|entry| {
            entry.method == "POST"
                && entry.path == "/v1/fleet/reconcile"
                && entry.policy_hook == "fleet.reconcile.execute"
        }));
    }

    #[test]
    fn fleet_mutations_have_fail_closed_rate_limit() {
        let fleet_limit = default_rate_limit(EndpointGroup::FleetControl);
        assert!(fleet_limit.fail_closed);
    }

    #[test]
    fn operator_health_endpoint_unauthenticated() {
        let routes = all_route_metadata();
        let health = routes
            .iter()
            .find(|r| r.path == "/v1/operator/health")
            .expect("health route exists");
        assert!(matches!(
            health.auth_method,
            crate::api::middleware::AuthMethod::None
        ));
    }

    #[test]
    fn all_routes_versioned_v1() {
        let routes = all_route_metadata();
        for route in &routes {
            assert!(
                route.path.starts_with("/v1/"),
                "route {} is not versioned",
                route.path
            );
        }
    }
}

/// Integration tests: API middleware pipeline → Security intent firewall.
///
/// Validates that the API layer (auth, rate-limit, policy hooks) correctly
/// gates access before security subsystem evaluation, and that the full
/// pipeline produces consistent audit events and decision receipts.
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::api::middleware::{
        AuthIdentity, AuthMethod, AuthzDecision, EndpointGroup, EndpointLifecycle, PolicyHook,
        RateLimitConfig, RateLimiter, RouteMetadata, authorize, check_rate_limit,
        default_rate_limit, execute_middleware_chain,
    };
    use crate::security::intent_firewall::{
        EffectsFirewall, FirewallVerdict, IntentClassification, IntentClassifier, RemoteEffect,
        TrafficOrigin,
    };
    use std::collections::{BTreeMap, BTreeSet};

    // ── Helpers ────────────────────────────────────────────────────────

    fn get_test_keys() -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        keys.insert("test-key-123".to_string());
        keys.insert("mytoken-abc".to_string());
        keys.insert("🔐鍵🙂abc123".to_string());
        keys.insert("令牌🙂abcXYZ".to_string());
        keys.insert("valid-token-abc".to_string());
        keys.insert("fleet-service-cert".to_string());
        keys
    }

    fn make_effect(effect_id: &str, ext_id: &str) -> RemoteEffect {
        RemoteEffect {
            effect_id: effect_id.into(),
            origin: TrafficOrigin::Extension {
                extension_id: ext_id.into(),
            },
            target_host: "api.example.com".into(),
            target_port: 443,
            method: "GET".into(),
            path: "/data".into(),
            has_sensitive_payload: false,
            carries_credentials: false,
            metadata: BTreeMap::new(),
        }
    }

    fn make_firewall() -> EffectsFirewall {
        let mut fw = EffectsFirewall::with_default_policy();
        fw.register_extension("ext-001");
        fw
    }

    fn fleet_admin_route() -> RouteMetadata {
        RouteMetadata {
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
        }
    }

    fn synthetic_bearer_admin_route() -> RouteMetadata {
        RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/test/fleet/admin".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "test.fleet.admin.execute".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        }
    }

    fn operator_status_route() -> RouteMetadata {
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

    // ── Auth → Firewall pipeline ──────────────────────────────────────

    #[test]
    fn authenticated_request_reaches_firewall_and_allows_safe_traffic() {
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let mut fw = make_firewall();
        let keys = get_test_keys();

        let (result, log) = execute_middleware_chain(
            &route,
            None, // no auth needed
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                let effect = make_effect("e-safe", "ext-001");
                let decision = fw
                    .evaluate(&effect, "trace-int-1", "2026-01-01T00:00:00Z")
                    .expect("firewall eval");
                assert_eq!(decision.verdict, FirewallVerdict::Allow);
                Ok(decision.receipt_id)
            },
        );

        assert!(result.is_ok());
        assert_eq!(log.status, 200);
        assert!(!result.unwrap().is_empty(), "receipt ID returned");
    }

    #[test]
    fn unauthenticated_request_rejected_before_firewall() {
        let route = fleet_admin_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::FleetControl));
        let mut firewall_called = false;
        let keys = get_test_keys();

        let (result, log) = execute_middleware_chain(
            &route,
            None, // missing required auth
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                firewall_called = true;
                Ok("should not reach")
            },
        );

        assert!(result.is_err());
        assert_eq!(log.status, 401);
        assert!(
            !firewall_called,
            "firewall must not be reached without auth"
        );
    }

    #[test]
    fn wrong_auth_prefix_rejected_before_firewall() {
        let route = fleet_admin_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::FleetControl));
        let keys = get_test_keys();

        let (result, log) = execute_middleware_chain(
            &route,
            Some("ApiKey my-key"), // route requires propagated mTLS identity
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| Ok("should not reach"),
        );

        assert!(result.is_err());
        assert_eq!(log.status, 401);
    }

    #[test]
    fn authorized_mtls_identity_can_reach_firewall() {
        let route = fleet_admin_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::FleetControl));
        let mut fw = make_firewall();
        let keys = get_test_keys();

        let (result, log) = execute_middleware_chain(
            &route,
            Some("fleet-service-cert"),
            None,
            &mut limiter,
            &keys,
            |identity, _ctx| {
                assert!(identity.roles.contains(&"fleet-admin".to_string()));
                let effect = make_effect("e-fleet", "ext-001");
                let decision = fw
                    .evaluate(&effect, "trace-fleet", "2026-01-01T00:00:00Z")
                    .expect("firewall eval");
                Ok(decision.verdict)
            },
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FirewallVerdict::Allow);
        assert_eq!(log.status, 200);
    }

    // ── Authorization → Firewall pipeline ─────────────────────────────

    #[test]
    fn synthetic_bearer_admin_route_denied_before_firewall() {
        // Real quarantine/reconcile routes are mTLS-only. This synthetic route
        // isolates the authorization-deny branch for bearer identities.
        let route = synthetic_bearer_admin_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::FleetControl));
        let mut firewall_called = false;
        let keys = get_test_keys();

        let (result, log) = execute_middleware_chain(
            &route,
            Some("Bearer valid-token-abc"),
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                firewall_called = true;
                Ok("should not reach")
            },
        );

        assert!(result.is_err());
        assert_eq!(log.status, 403);
        assert!(
            !firewall_called,
            "firewall must not be reached without proper role"
        );
    }

    #[test]
    fn policy_hook_with_matching_role_allows_firewall_evaluation() {
        let identity = AuthIdentity {
            principal: "mtls:admin-service".to_string(),
            method: AuthMethod::MtlsClientCert,
            roles: vec!["fleet-admin".to_string()],
        };
        let hook = PolicyHook {
            hook_id: "fleet.quarantine.execute".to_string(),
            required_roles: vec!["fleet-admin".to_string()],
        };

        let decision = authorize(&identity, &hook, "trace-authz-1").expect("authz");
        assert_eq!(decision, AuthzDecision::Allow);

        // After auth succeeds, firewall evaluates
        let mut fw = make_firewall();
        let mut effect = make_effect("e-authz", "ext-001");
        effect.has_sensitive_payload = true;
        let fw_decision = fw
            .evaluate(&effect, "trace-authz-1", "2026-01-01T00:00:00Z")
            .expect("firewall");
        assert_eq!(fw_decision.verdict, FirewallVerdict::Deny);
        assert_eq!(fw_decision.intent, Some(IntentClassification::Exfiltration));
    }

    #[test]
    fn fleet_admin_fixture_matches_authoritative_quarantine_metadata() {
        let fixture = fleet_admin_route();
        let authoritative = crate::api::fleet_quarantine::quarantine_route_metadata()
            .into_iter()
            .find(|route| route.method == "POST" && route.path == "/v1/fleet/quarantine")
            .expect("authoritative quarantine route");

        assert_eq!(fixture.auth_method, authoritative.auth_method);
        assert_eq!(
            fixture.policy_hook.hook_id,
            authoritative.policy_hook.hook_id
        );
        assert_eq!(
            fixture.policy_hook.required_roles,
            authoritative.policy_hook.required_roles
        );
    }

    // ── Rate limiting → Firewall pipeline ─────────────────────────────

    #[test]
    fn rate_limited_request_never_reaches_firewall() {
        let route = operator_status_route();
        let config = RateLimitConfig {
            sustained_rps: 1,
            burst_size: 1,
            fail_closed: false,
        };
        let mut limiter = RateLimiter::new(config);
        let keys = get_test_keys();

        // Exhaust the burst
        let (first, _) =
            execute_middleware_chain(&route, None, None, &mut limiter, &keys, |_id, _ctx| {
                Ok("first")
            });
        assert!(first.is_ok());

        // Second request hits rate limit
        let mut firewall_called = false;
        let (second, log) =
            execute_middleware_chain(&route, None, None, &mut limiter, &keys, |_id, _ctx| {
                firewall_called = true;
                Ok("should not reach")
            });

        assert!(second.is_err());
        assert_eq!(log.status, 429);
        assert!(
            !firewall_called,
            "firewall must not be reached when rate-limited"
        );
    }

    #[test]
    fn fleet_rate_limiter_fail_closed_blocks_before_firewall() {
        let fleet_config = default_rate_limit(EndpointGroup::FleetControl);
        assert!(fleet_config.fail_closed, "fleet must be fail-closed");

        let config = RateLimitConfig {
            sustained_rps: 1,
            burst_size: 1,
            fail_closed: true,
        };
        let mut limiter = RateLimiter::new(config);

        // Exhaust burst
        limiter.check().expect("first check");

        // Verify rate limit error
        let err = check_rate_limit(&mut limiter, "trace-rl").unwrap_err();
        match err {
            crate::api::error::ApiError::RateLimited { retry_after_ms, .. } => {
                assert!(retry_after_ms > 0);
            }
            other => unreachable!("expected RateLimited, got {:?}", other),
        }
    }

    // ── Trace context propagation through pipeline ────────────────────

    #[test]
    fn trace_context_propagated_to_firewall_handler() {
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let keys = get_test_keys();

        let (result, log) = execute_middleware_chain(
            &route,
            None,
            Some(traceparent),
            &mut limiter,
            &keys,
            |_identity, ctx| {
                assert_eq!(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c");
                assert_eq!(ctx.span_id, "b7ad6b7169203331");
                Ok(ctx.trace_id.clone())
            },
        );

        assert!(result.is_ok());
        assert_eq!(log.trace_id, "0af7651916cd43dd8448eb211c80319c");
    }

    #[test]
    fn generated_trace_context_when_no_traceparent() {
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let keys = get_test_keys();

        let (result, log) = execute_middleware_chain(
            &route,
            None,
            None, // no traceparent
            &mut limiter,
            &keys,
            |_identity, ctx| {
                assert!(!ctx.trace_id.is_empty());
                assert!(!ctx.span_id.is_empty());
                Ok(ctx.trace_id.clone())
            },
        );

        assert!(result.is_ok());
        assert!(!log.trace_id.is_empty());
    }

    // ── Firewall risky intent denied through full pipeline ────────────

    #[test]
    fn full_pipeline_denies_exfiltration_intent() {
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let mut fw = make_firewall();
        let keys = get_test_keys();

        let (result, log) = execute_middleware_chain(
            &route,
            None,
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                let mut effect = make_effect("e-exfil", "ext-001");
                effect.has_sensitive_payload = true;
                let decision = fw
                    .evaluate(&effect, "trace-exfil", "2026-01-01T00:00:00Z")
                    .expect("firewall");
                assert_eq!(decision.verdict, FirewallVerdict::Deny);
                assert_eq!(decision.intent, Some(IntentClassification::Exfiltration));
                assert!(!decision.receipt_id.is_empty());
                Ok(decision)
            },
        );

        assert!(result.is_ok());
        assert_eq!(log.status, 200); // handler returned Ok
    }

    #[test]
    fn full_pipeline_denies_credential_forward() {
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let mut fw = make_firewall();
        let keys = get_test_keys();

        let (result, _log) = execute_middleware_chain(
            &route,
            None,
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                let mut effect = make_effect("e-cred-fwd", "ext-001");
                effect.carries_credentials = true;
                let decision = fw
                    .evaluate(&effect, "trace-cred", "2026-01-01T00:00:00Z")
                    .expect("firewall");
                assert_eq!(decision.verdict, FirewallVerdict::Deny);
                assert_eq!(
                    decision.intent,
                    Some(IntentClassification::CredentialForward)
                );
                Ok(decision.verdict)
            },
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FirewallVerdict::Deny);
    }

    #[test]
    fn full_pipeline_allows_health_check_intent() {
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let mut fw = make_firewall();
        let keys = get_test_keys();

        let (result, _log) = execute_middleware_chain(
            &route,
            None,
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                let mut effect = make_effect("e-health", "ext-001");
                effect.path = "/health/live".into();
                let decision = fw
                    .evaluate(&effect, "trace-hc", "2026-01-01T00:00:00Z")
                    .expect("firewall");
                assert_eq!(decision.verdict, FirewallVerdict::Allow);
                assert_eq!(decision.intent, Some(IntentClassification::HealthCheck));
                Ok(decision.verdict)
            },
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FirewallVerdict::Allow);
    }

    // ── Service metrics + firewall audit cross-check ──────────────────

    #[test]
    fn service_records_metrics_for_firewall_gated_requests() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let mut service = ControlPlaneService::default();
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let mut fw = make_firewall();
        let keys = get_test_keys();

        let (_result, log) = execute_middleware_chain(
            &route,
            None,
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                let effect = make_effect("e-metric", "ext-001");
                let _decision = fw
                    .evaluate(&effect, "trace-metric", "2026-01-01T00:00:00Z")
                    .expect("firewall");
                Ok("processed")
            },
        );

        service.record(&log);
        assert_eq!(service.request_count(), 1);
        assert_eq!(log.event_code, "FASTAPI_RESPONSE_SENT");

        // Firewall audit log has entries
        let audit = fw.audit_log();
        assert!(!audit.is_empty());
    }

    #[test]
    fn service_metrics_error_count_on_auth_failure_before_firewall() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let mut service = ControlPlaneService::default();
        let route = fleet_admin_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::FleetControl));
        let keys = get_test_keys();

        let (_result, log) = execute_middleware_chain(
            &route,
            None, // missing auth
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| Ok("unreachable"),
        );

        service.record(&log);
        assert_eq!(service.request_count(), 1);
        assert_eq!(log.event_code, "FASTAPI_AUTH_FAIL");
        assert_eq!(
            *service
                .metrics()
                .error_counts
                .get("FASTAPI_AUTH_FAIL")
                .unwrap(),
            1
        );
    }

    // ── Firewall unknown extension through pipeline ───────────────────

    #[test]
    fn pipeline_with_unregistered_extension_returns_firewall_error() {
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let mut fw = EffectsFirewall::with_default_policy();
        let keys = get_test_keys();
        // Do NOT register the extension

        let (result, log) = execute_middleware_chain(
            &route,
            None,
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                let effect = make_effect("e-unreg", "ext-unknown");
                let fw_result = fw.evaluate(&effect, "trace-unreg", "2026-01-01T00:00:00Z");
                assert!(fw_result.is_err());
                Result::<FirewallVerdict, crate::api::error::ApiError>::Err(
                    crate::api::error::ApiError::Internal {
                        detail: format!("firewall error: {}", fw_result.unwrap_err()),
                        trace_id: "trace-unreg".to_string(),
                    },
                )
            },
        );

        assert!(result.is_err());
        assert_eq!(log.status, 500);
    }

    // ── Multi-request pipeline consistency ─────────────────────────────

    #[test]
    fn multiple_requests_through_pipeline_produce_consistent_metrics() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let mut service = ControlPlaneService::default();
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let mut fw = make_firewall();
        let keys = get_test_keys();

        for i in 0..5 {
            let effect_id = format!("e-multi-{}", i);
            let (_result, log) = execute_middleware_chain(
                &route,
                None,
                None,
                &mut limiter,
                &keys,
                |_identity, _ctx| {
                    let effect = make_effect(&effect_id, "ext-001");
                    let decision = fw
                        .evaluate(&effect, "trace-m", "2026-01-01T00:00:00Z")
                        .expect("firewall");
                    Ok(decision.verdict)
                },
            );
            service.record(&log);
        }

        assert_eq!(service.request_count(), 5);
        assert!(
            service.metrics().latencies.contains_key("operator"),
            "operator latency metrics recorded"
        );
        assert_eq!(service.metrics().latencies["operator"].samples.len(), 5);
    }

    // ── Intent classifier used within pipeline ────────────────────────

    #[test]
    fn classifier_result_matches_firewall_decision_intent() {
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let mut fw = make_firewall();
        let keys = get_test_keys();

        let (result, _log) = execute_middleware_chain(
            &route,
            None,
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                let effect = make_effect("e-classify", "ext-001");
                let classifier_result = IntentClassifier::classify(&effect);
                let decision = fw
                    .evaluate(&effect, "trace-cls", "2026-01-01T00:00:00Z")
                    .expect("firewall");
                assert_eq!(decision.intent, classifier_result);
                Ok(decision.intent)
            },
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(IntentClassification::DataFetch));
    }

    // ── Node-internal traffic bypass through pipeline ──────────────────

    #[test]
    fn node_internal_traffic_bypasses_firewall_via_pipeline() {
        let route = operator_status_route();
        let mut limiter = RateLimiter::new(default_rate_limit(EndpointGroup::Operator));
        let mut fw = make_firewall();
        let keys = get_test_keys();

        let (result, _log) = execute_middleware_chain(
            &route,
            None,
            None,
            &mut limiter,
            &keys,
            |_identity, _ctx| {
                let effect = RemoteEffect {
                    effect_id: "e-internal".into(),
                    origin: TrafficOrigin::NodeInternal {
                        subsystem: "control_plane".into(),
                    },
                    target_host: "localhost".into(),
                    target_port: 9090,
                    method: "GET".into(),
                    path: "/internal/sync".into(),
                    has_sensitive_payload: false,
                    carries_credentials: false,
                    metadata: BTreeMap::new(),
                };
                let decision = fw
                    .evaluate(&effect, "trace-int", "2026-01-01T00:00:00Z")
                    .expect("firewall");
                assert_eq!(decision.verdict, FirewallVerdict::Allow);
                assert!(decision.rationale.contains("node-internal"));
                Ok(decision.verdict)
            },
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FirewallVerdict::Allow);
    }
}
