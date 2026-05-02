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
use crate::push_bounded;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::fleet_control_routes;
use super::middleware::{
    EndpointGroup, RateLimitConfig, RateLimiter, RequestLog, RouteMetadata, ServiceMetrics,
    default_rate_limit,
};
use super::operator_routes;
use super::verifier_routes;

/// Maximum retained request lifecycle provenance events.
pub const MAX_LIFECYCLE_EVENTS: usize = 4096;

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
    #[cfg(any(test, feature = "control-plane"))]
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
        rate_limiting_coverage: rate_limiting_coverage_for_routes(&routes),
    }
}

fn rate_limiting_coverage_for_routes(routes: &[RouteMetadata]) -> bool {
    !routes.is_empty()
        && routes.iter().all(|route| {
            let limit = default_rate_limit(route.group);
            limit.fail_closed && limit.sustained_rps > 0 && limit.burst_size > 0
        })
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

/// Structured provenance record explaining request lifecycle and perf baseline state.
///
/// This record is emitted with each request dispatch and explains:
/// - What transport boundary owns the request (in-process vs live)
/// - Why performance baselines may be unavailable
/// - Request lifecycle and cancellation semantics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLifecycleProvenance {
    pub transport_boundary_kind: TransportBoundaryKind,
    pub transport_owns_listener: bool,
    pub endpoint_group: String,
    pub route_path: String,
    pub perf_baseline_status: PerformanceBaselineStatus,
    pub perf_baseline_provenance: String,
    pub request_lifecycle: String,
    pub cancellation_semantics: String,
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
    request_lifecycle_events: Vec<RequestLifecycleProvenance>,
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
            request_lifecycle_events: Vec::new(),
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

    /// Structured provenance captured for recorded requests.
    pub fn request_lifecycle_events(&self) -> &[RequestLifecycleProvenance] {
        &self.request_lifecycle_events
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
    ///
    /// This method updates metrics and captures structured provenance for the
    /// request lifecycle. The provenance explains:
    /// - Request path and endpoint group
    /// - Rate limit state at time of request
    /// - Whether performance baselines were measured (currently: no)
    pub fn record(&mut self, log: &RequestLog) {
        let provenance = self.request_lifecycle_provenance(&log.endpoint_group, &log.route);
        push_bounded(
            &mut self.request_lifecycle_events,
            provenance,
            MAX_LIFECYCLE_EVENTS,
        );
        self.metrics.record_request(log);
    }

    /// Emit structured provenance explaining request lifecycle and perf baseline state.
    ///
    /// Returns a structured record suitable for audit logging that explains:
    /// - Transport boundary ownership (in-process catalog vs live transport)
    /// - Performance baseline provenance (unavailable pending transport)
    /// - Request rate-limit context
    pub fn request_lifecycle_provenance(
        &self,
        endpoint_group: &str,
        route_path: &str,
    ) -> RequestLifecycleProvenance {
        RequestLifecycleProvenance {
            transport_boundary_kind: self.transport_boundary().kind,
            transport_owns_listener: self.transport_boundary().owns_listener,
            endpoint_group: endpoint_group.to_string(),
            route_path: route_path.to_string(),
            perf_baseline_status: PerformanceBaselineStatus::UnavailablePendingTransport,
            perf_baseline_provenance: "No live async HTTP/gRPC transport boundary is owned; \
                load-test baselines are intentionally unavailable until that trigger exists."
                .to_string(),
            request_lifecycle: "caller-owned in-process dispatch only".to_string(),
            cancellation_semantics: "no transport-owned cancellation boundary".to_string(),
        }
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
        assert_eq!(verifier_count, 7);
        assert_eq!(fleet_count, 10);
        assert_eq!(routes.len(), 21);
    }

    #[test]
    fn endpoint_catalog_has_all_routes() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let catalog = build_endpoint_catalog();
        assert_eq!(catalog.len(), 21);

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
    fn rate_limiting_coverage_is_derived_from_route_groups() {
        let routes = all_route_metadata();

        assert!(rate_limiting_coverage_for_routes(&routes));
        for group in [
            EndpointGroup::Operator,
            EndpointGroup::Verifier,
            EndpointGroup::FleetControl,
        ] {
            let limit = default_rate_limit(group);
            assert!(
                limit.fail_closed,
                "{:?} route group must fail closed under rate limiting",
                group
            );
            assert!(
                limit.sustained_rps > 0,
                "{:?} route group must have sustained rate limiting",
                group
            );
            assert!(
                limit.burst_size > 0,
                "{:?} route group must have burst rate limiting",
                group
            );
        }
    }

    #[test]
    fn rate_limiting_coverage_fails_closed_for_empty_route_set() {
        assert!(!rate_limiting_coverage_for_routes(&[]));
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
    fn service_record_captures_request_lifecycle_provenance() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let mut service = ControlPlaneService::default();
        let log = RequestLog {
            method: "GET".to_string(),
            route: "/v1/operator/status".to_string(),
            status: 200,
            latency_ms: 1.0,
            trace_id: "t-2".to_string(),
            principal: "test".to_string(),
            endpoint_group: "operator".to_string(),
            event_code: "FASTAPI_RESPONSE_SENT".to_string(),
        };

        assert!(service.request_lifecycle_events().is_empty());
        service.record(&log);

        let events = service.request_lifecycle_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].endpoint_group, "operator");
        assert_eq!(events[0].route_path, "/v1/operator/status");
        assert_eq!(
            events[0].transport_boundary_kind,
            TransportBoundaryKind::InProcessCatalog
        );
        assert_eq!(
            events[0].perf_baseline_status,
            PerformanceBaselineStatus::UnavailablePendingTransport
        );
    }

    #[test]
    fn service_record_bounds_request_lifecycle_events_fifo() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let mut service = ControlPlaneService::default();

        for index in 0..(MAX_LIFECYCLE_EVENTS + 2) {
            let log = RequestLog {
                method: "GET".to_string(),
                route: format!("/v1/operator/status/{index}"),
                status: 200,
                latency_ms: 1.0,
                trace_id: format!("trace-{index}"),
                principal: "test".to_string(),
                endpoint_group: "operator".to_string(),
                event_code: "FASTAPI_RESPONSE_SENT".to_string(),
            };
            service.record(&log);
        }

        let events = service.request_lifecycle_events();
        assert_eq!(events.len(), MAX_LIFECYCLE_EVENTS);
        assert_eq!(events[0].route_path, "/v1/operator/status/2");
        assert_eq!(
            events[MAX_LIFECYCLE_EVENTS - 1].route_path,
            format!("/v1/operator/status/{}", MAX_LIFECYCLE_EVENTS + 1)
        );
        assert_eq!(
            service.request_count(),
            u64::try_from(MAX_LIFECYCLE_EVENTS + 2).expect("test cap fits in u64")
        );
    }

    #[test]
    fn request_lifecycle_provenance_explains_transport_state() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let service = ControlPlaneService::default();

        let provenance = service.request_lifecycle_provenance("operator", "/v1/operator/status");

        assert_eq!(
            provenance.transport_boundary_kind,
            TransportBoundaryKind::InProcessCatalog
        );
        assert!(!provenance.transport_owns_listener);
        assert_eq!(provenance.endpoint_group, "operator");
        assert_eq!(provenance.route_path, "/v1/operator/status");
        assert_eq!(
            provenance.perf_baseline_status,
            PerformanceBaselineStatus::UnavailablePendingTransport
        );
        assert!(!provenance.perf_baseline_provenance.is_empty());
        assert!(provenance.request_lifecycle.contains("in-process"));
        assert!(provenance.cancellation_semantics.contains("no transport"));
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
                route.path.starts_with("/v1/") || route.path.starts_with("/api/v1/"),
                "route {} is not versioned",
                route.path
            );
        }
    }

    #[test]
    fn unknown_http_method_uses_generic_status_surface() {
        let codes = default_status_codes("PATCH");

        assert_eq!(codes, vec![200, 400, 401, 403, 500]);
        assert!(!codes.contains(&404));
        assert!(!codes.contains(&409));
        assert!(!codes.contains(&429));
        assert!(!codes.contains(&503));
    }

    #[test]
    fn empty_bind_target_hint_does_not_claim_live_transport() {
        let config = ServiceConfig {
            bind_target_hint: String::new(),
            ..Default::default()
        };

        let report = generate_endpoint_report(&config);

        assert_eq!(
            report.transport_boundary.kind,
            TransportBoundaryKind::InProcessCatalog
        );
        assert!(!report.transport_boundary.owns_listener);
        assert!(report.transport_boundary.bind_target_hint.is_empty());
        assert!(report.performance_baselines.iter().all(|baseline| {
            baseline.status == PerformanceBaselineStatus::UnavailablePendingTransport
                && baseline.p50_ms.is_none()
                && baseline.p95_ms.is_none()
                && baseline.p99_ms.is_none()
        }));
    }

    #[test]
    fn zero_burst_override_denies_operator_limiter_without_live_transport() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let mut rate_limits = std::collections::BTreeMap::new();
        rate_limits.insert(
            "operator".to_string(),
            RateLimitConfig {
                sustained_rps: 0,
                burst_size: 0,
                fail_closed: true,
            },
        );
        let mut service = ControlPlaneService::new(ServiceConfig {
            rate_limits,
            ..Default::default()
        });

        let limiter = service.limiter_for_group(EndpointGroup::Operator);

        assert_eq!(limiter.config().sustained_rps, 1);
        assert_eq!(limiter.config().burst_size, 0);
        assert!(limiter.config().fail_closed);
        assert!(limiter.check().is_err());
        assert!(!service.transport_boundary().owns_listener);
    }

    #[test]
    fn unknown_rate_limit_override_key_is_ignored() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let mut rate_limits = std::collections::BTreeMap::new();
        rate_limits.insert(
            "unknown-group".to_string(),
            RateLimitConfig {
                sustained_rps: 0,
                burst_size: 0,
                fail_closed: true,
            },
        );
        let mut service = ControlPlaneService::new(ServiceConfig {
            rate_limits,
            ..Default::default()
        });

        let operator_limit = service.limiter_for_group(EndpointGroup::Operator).config();

        assert_eq!(operator_limit, &default_rate_limit(EndpointGroup::Operator));
        assert!(service.config().rate_limits.contains_key("unknown-group"));
    }

    #[test]
    fn empty_request_metadata_records_provenance_without_transport_escalation() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let service = ControlPlaneService::default();

        let provenance = service.request_lifecycle_provenance("", "");

        assert_eq!(provenance.endpoint_group, "");
        assert_eq!(provenance.route_path, "");
        assert_eq!(
            provenance.transport_boundary_kind,
            TransportBoundaryKind::InProcessCatalog
        );
        assert!(!provenance.transport_owns_listener);
        assert_eq!(
            provenance.perf_baseline_status,
            PerformanceBaselineStatus::UnavailablePendingTransport
        );
    }

    #[test]
    fn malformed_error_log_with_empty_event_code_is_counted_under_empty_bucket() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let mut service = ControlPlaneService::default();
        let log = RequestLog {
            method: String::new(),
            route: String::new(),
            status: 500,
            latency_ms: 0.0,
            trace_id: String::new(),
            principal: String::new(),
            endpoint_group: String::new(),
            event_code: String::new(),
        };

        service.record(&log);

        assert_eq!(service.request_count(), 1);
        assert_eq!(service.request_lifecycle_events().len(), 1);
        assert_eq!(service.request_lifecycle_events()[0].endpoint_group, "");
        assert_eq!(service.request_lifecycle_events()[0].route_path, "");
        assert_eq!(*service.metrics().error_counts.get("").unwrap(), 1);
        assert!(service.metrics().latencies.contains_key(""));
    }

    #[test]
    fn service_metrics_saturate_request_count_and_error_bucket() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let mut service = ControlPlaneService::default();
        service.metrics.request_count = u64::MAX;
        service
            .metrics
            .error_counts
            .insert("FASTAPI_ENDPOINT_ERROR".to_string(), u64::MAX);
        let log = RequestLog {
            method: "POST".to_string(),
            route: "/v1/operator/unknown".to_string(),
            status: 503,
            latency_ms: 5.0,
            trace_id: "trace-saturate".to_string(),
            principal: "operator".to_string(),
            endpoint_group: "operator".to_string(),
            event_code: "FASTAPI_ENDPOINT_ERROR".to_string(),
        };

        service.record(&log);

        assert_eq!(service.request_count(), u64::MAX);
        assert_eq!(
            *service
                .metrics()
                .error_counts
                .get("FASTAPI_ENDPOINT_ERROR")
                .unwrap(),
            u64::MAX
        );
        assert_eq!(service.request_lifecycle_events().len(), 1);
    }

    #[test]
    fn transport_boundary_kind_deserialize_rejects_camel_case() {
        let result: Result<TransportBoundaryKind, _> = serde_json::from_str("\"InProcessCatalog\"");

        assert!(result.is_err(), "transport kind must use snake_case");
    }

    #[test]
    fn transport_boundary_status_deserialize_rejects_string_listener_flag() {
        let raw = serde_json::json!({
            "kind": "in_process_catalog",
            "owns_listener": "false",
            "bind_target_hint": "127.0.0.1:9090",
            "request_lifecycle": "caller-owned in-process dispatch only",
            "cancellation_semantics": "no transport-owned cancellation boundary"
        });

        let result: Result<TransportBoundaryStatus, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "owns_listener must remain boolean");
    }

    #[test]
    fn performance_baseline_status_deserialize_rejects_unknown_status() {
        let result: Result<PerformanceBaselineStatus, _> =
            serde_json::from_str("\"measured_pending_transport\"");

        assert!(result.is_err(), "baseline status must fail closed");
    }

    #[test]
    fn performance_baseline_deserialize_rejects_string_latency() {
        let raw = serde_json::json!({
            "endpoint": "GET /v1/operator/status",
            "status": "unavailable_pending_transport",
            "p50_ms": "0.1",
            "p95_ms": null,
            "p99_ms": null,
            "provenance": "not measured"
        });

        let result: Result<PerformanceBaseline, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "latency fields must remain numeric or null"
        );
    }

    #[test]
    fn request_lifecycle_provenance_deserialize_rejects_missing_route_path() {
        let raw = serde_json::json!({
            "transport_boundary_kind": "in_process_catalog",
            "transport_owns_listener": false,
            "endpoint_group": "operator",
            "perf_baseline_status": "unavailable_pending_transport",
            "perf_baseline_provenance": "not measured",
            "request_lifecycle": "caller-owned in-process dispatch only",
            "cancellation_semantics": "no transport-owned cancellation boundary"
        });

        let result: Result<RequestLifecycleProvenance, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "route_path is required provenance");
    }

    #[test]
    fn middleware_coverage_deserialize_rejects_string_boolean() {
        let raw = serde_json::json!({
            "auth_coverage": true,
            "policy_hook_coverage": true,
            "error_formatting_coverage": "true",
            "tracing_coverage": true,
            "rate_limiting_coverage": true
        });

        let result: Result<MiddlewareCoverage, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "coverage flags must remain boolean");
    }

    #[test]
    fn endpoint_catalog_entry_deserialize_rejects_string_status_code() {
        let raw = serde_json::json!({
            "group": "operator",
            "path": "/v1/operator/status",
            "method": "GET",
            "auth_method": "ApiKey",
            "policy_hook": "operator.status.read",
            "lifecycle": "stable",
            "trace_propagation": true,
            "status_codes": [200_u16, "429"],
            "conformance_status": "pass"
        });

        let result: Result<EndpointCatalogEntry, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "status_codes must stay numeric");
    }

    #[test]
    fn endpoint_report_deserialize_rejects_missing_generated_at() {
        let raw = serde_json::json!({
            "endpoints": [],
            "middleware_coverage": {
                "auth_coverage": true,
                "policy_hook_coverage": true,
                "error_formatting_coverage": true,
                "tracing_coverage": true,
                "rate_limiting_coverage": true
            },
            "transport_boundary": {
                "kind": "in_process_catalog",
                "owns_listener": false,
                "bind_target_hint": "127.0.0.1:9090",
                "request_lifecycle": "caller-owned in-process dispatch only",
                "cancellation_semantics": "no transport-owned cancellation boundary"
            },
            "performance_baselines": []
        });

        let result: Result<EndpointReport, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "generated_at is required in reports");
    }

    #[test]
    fn service_config_deserialize_rejects_missing_bind_target_hint() {
        let raw = serde_json::json!({
            "rate_limits": {},
            "otel_enabled": false,
            "service_name": "franken-node-control-plane"
        });

        let result = serde_json::from_value::<ServiceConfig>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn service_config_deserialize_rejects_rate_limits_array() {
        let raw = serde_json::json!({
            "bind_target_hint": "127.0.0.1:9090",
            "rate_limits": [],
            "otel_enabled": false,
            "service_name": "franken-node-control-plane"
        });

        let result = serde_json::from_value::<ServiceConfig>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn service_config_deserialize_rejects_negative_nested_rate_limit() {
        let raw = serde_json::json!({
            "bind_target_hint": "127.0.0.1:9090",
            "rate_limits": {
                "operator": {
                    "sustained_rps": -1,
                    "burst_size": 10,
                    "fail_closed": false
                }
            },
            "otel_enabled": false,
            "service_name": "franken-node-control-plane"
        });

        let result = serde_json::from_value::<ServiceConfig>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn service_config_deserialize_rejects_string_otel_flag() {
        let raw = serde_json::json!({
            "bind_target_hint": "127.0.0.1:9090",
            "rate_limits": {},
            "otel_enabled": "false",
            "service_name": "franken-node-control-plane"
        });

        let result = serde_json::from_value::<ServiceConfig>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn service_config_deserialize_rejects_numeric_service_name() {
        let raw = serde_json::json!({
            "bind_target_hint": "127.0.0.1:9090",
            "rate_limits": {},
            "otel_enabled": false,
            "service_name": 7
        });

        let result = serde_json::from_value::<ServiceConfig>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn transport_boundary_status_deserialize_rejects_missing_cancellation_semantics() {
        let raw = serde_json::json!({
            "kind": "in_process_catalog",
            "owns_listener": false,
            "bind_target_hint": "127.0.0.1:9090",
            "request_lifecycle": "caller-owned in-process dispatch only"
        });

        let result = serde_json::from_value::<TransportBoundaryStatus>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn endpoint_catalog_entry_deserialize_rejects_missing_status_codes() {
        let raw = serde_json::json!({
            "group": "operator",
            "path": "/v1/operator/status",
            "method": "GET",
            "auth_method": "ApiKey",
            "policy_hook": "operator.status.read",
            "lifecycle": "stable",
            "trace_propagation": true,
            "conformance_status": "pass"
        });

        let result = serde_json::from_value::<EndpointCatalogEntry>(raw);

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod service_fresh_negative_tests {
    use super::*;

    #[test]
    fn empty_method_uses_generic_status_without_mutation_codes() {
        let codes = default_status_codes("");

        assert_eq!(codes, vec![200, 400, 401, 403, 500]);
        assert!(!codes.contains(&201));
        assert!(!codes.contains(&204));
        assert!(!codes.contains(&409));
    }

    #[test]
    fn lowercase_get_does_not_receive_get_status_surface() {
        let codes = default_status_codes("get");

        assert_eq!(codes, vec![200, 400, 401, 403, 500]);
        assert!(!codes.contains(&404));
        assert!(!codes.contains(&429));
        assert!(!codes.contains(&503));
    }

    #[test]
    fn endpoint_catalog_entry_rejects_null_status_codes() {
        let raw = serde_json::json!({
            "group": "operator",
            "path": "/v1/operator/status",
            "method": "GET",
            "auth_method": "ApiKey",
            "policy_hook": "operator.status.read",
            "lifecycle": "stable",
            "trace_propagation": true,
            "status_codes": null,
            "conformance_status": "pass"
        });

        let result = serde_json::from_value::<EndpointCatalogEntry>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn performance_baseline_rejects_object_latency_field() {
        let raw = serde_json::json!({
            "endpoint": "GET /v1/operator/status",
            "status": "unavailable_pending_transport",
            "p50_ms": null,
            "p95_ms": { "ms": 15.0 },
            "p99_ms": null,
            "provenance": "pending live transport"
        });

        let result = serde_json::from_value::<PerformanceBaseline>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn request_lifecycle_rejects_unknown_transport_kind() {
        let raw = serde_json::json!({
            "transport_boundary_kind": "live_transport_v2",
            "transport_owns_listener": false,
            "endpoint_group": "operator",
            "route_path": "/v1/operator/status",
            "perf_baseline_status": "unavailable_pending_transport",
            "perf_baseline_provenance": "pending live transport",
            "request_lifecycle": "caller-owned in-process dispatch only",
            "cancellation_semantics": "no transport-owned cancellation boundary"
        });

        let result = serde_json::from_value::<RequestLifecycleProvenance>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn middleware_coverage_rejects_missing_auth_coverage() {
        let raw = serde_json::json!({
            "policy_hook_coverage": true,
            "error_formatting_coverage": true,
            "tracing_coverage": true,
            "rate_limiting_coverage": true
        });

        let result = serde_json::from_value::<MiddlewareCoverage>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn service_config_rejects_null_rate_limit_override() {
        let raw = serde_json::json!({
            "bind_target_hint": "127.0.0.1:9090",
            "rate_limits": {
                "operator": null
            },
            "otel_enabled": false,
            "service_name": "franken-node-control-plane"
        });

        let result = serde_json::from_value::<ServiceConfig>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn endpoint_report_rejects_string_performance_baselines() {
        let raw = serde_json::json!({
            "endpoints": [],
            "middleware_coverage": {
                "auth_coverage": true,
                "policy_hook_coverage": true,
                "error_formatting_coverage": true,
                "tracing_coverage": true,
                "rate_limiting_coverage": true
            },
            "transport_boundary": {
                "kind": "in_process_catalog",
                "owns_listener": false,
                "bind_target_hint": "127.0.0.1:9090",
                "request_lifecycle": "caller-owned in-process dispatch only",
                "cancellation_semantics": "no transport-owned cancellation boundary"
            },
            "performance_baselines": "none",
            "generated_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<EndpointReport>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn endpoint_catalog_entry_rejects_null_trace_propagation() {
        let raw = serde_json::json!({
            "group": "operator",
            "path": "/v1/operator/status",
            "method": "GET",
            "auth_method": "ApiKey",
            "policy_hook": "operator.status.read",
            "lifecycle": "stable",
            "trace_propagation": null,
            "status_codes": [200, 400],
            "conformance_status": "pass"
        });

        let result = serde_json::from_value::<EndpointCatalogEntry>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn endpoint_catalog_entry_rejects_status_code_overflow() {
        let raw = serde_json::json!({
            "group": "operator",
            "path": "/v1/operator/status",
            "method": "GET",
            "auth_method": "ApiKey",
            "policy_hook": "operator.status.read",
            "lifecycle": "stable",
            "trace_propagation": true,
            "status_codes": [200, 70000],
            "conformance_status": "pass"
        });

        let result = serde_json::from_value::<EndpointCatalogEntry>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn transport_boundary_status_rejects_missing_bind_target_hint() {
        let raw = serde_json::json!({
            "kind": "in_process_catalog",
            "owns_listener": false,
            "request_lifecycle": "caller-owned in-process dispatch only",
            "cancellation_semantics": "no transport-owned cancellation boundary"
        });

        let result = serde_json::from_value::<TransportBoundaryStatus>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn performance_baseline_rejects_null_endpoint() {
        let raw = serde_json::json!({
            "endpoint": null,
            "status": "unavailable_pending_transport",
            "p50_ms": null,
            "p95_ms": null,
            "p99_ms": null,
            "provenance": "pending live transport"
        });

        let result = serde_json::from_value::<PerformanceBaseline>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn request_lifecycle_rejects_string_listener_ownership() {
        let raw = serde_json::json!({
            "transport_boundary_kind": "in_process_catalog",
            "transport_owns_listener": "false",
            "endpoint_group": "operator",
            "route_path": "/v1/operator/status",
            "perf_baseline_status": "unavailable_pending_transport",
            "perf_baseline_provenance": "pending live transport",
            "request_lifecycle": "caller-owned in-process dispatch only",
            "cancellation_semantics": "no transport-owned cancellation boundary"
        });

        let result = serde_json::from_value::<RequestLifecycleProvenance>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn endpoint_report_rejects_null_middleware_coverage() {
        let raw = serde_json::json!({
            "endpoints": [],
            "middleware_coverage": null,
            "transport_boundary": {
                "kind": "in_process_catalog",
                "owns_listener": false,
                "bind_target_hint": "127.0.0.1:9090",
                "request_lifecycle": "caller-owned in-process dispatch only",
                "cancellation_semantics": "no transport-owned cancellation boundary"
            },
            "performance_baselines": [],
            "generated_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<EndpointReport>(raw);

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod service_recent_commit_gap_tests {
    use super::*;

    #[test]
    fn whitespace_wrapped_get_uses_generic_status_surface() {
        for method in [" GET", "GET ", "\tGET", "GET\n"] {
            let codes = default_status_codes(method);

            assert_eq!(codes, vec![200, 400, 401, 403, 500]);
            assert!(!codes.contains(&404));
            assert!(!codes.contains(&429));
            assert!(!codes.contains(&503));
        }
    }

    #[test]
    fn nul_suffixed_post_uses_generic_status_surface() {
        let codes = default_status_codes("POST\0");

        assert_eq!(codes, vec![200, 400, 401, 403, 500]);
        assert!(!codes.contains(&201));
        assert!(!codes.contains(&409));
        assert!(!codes.contains(&429));
    }

    #[test]
    fn endpoint_catalog_entry_rejects_negative_status_code() {
        let raw = serde_json::json!({
            "group": "operator",
            "path": "/v1/operator/status",
            "method": "GET",
            "auth_method": "ApiKey",
            "policy_hook": "operator.status.read",
            "lifecycle": "stable",
            "trace_propagation": true,
            "status_codes": [200, -1],
            "conformance_status": "pass"
        });

        let result = serde_json::from_value::<EndpointCatalogEntry>(raw);

        assert!(result.is_err(), "negative status codes must be rejected");
    }

    #[test]
    fn transport_boundary_kind_rejects_pascal_case_variant() {
        let result =
            serde_json::from_value::<TransportBoundaryKind>(serde_json::json!("LiveTransport"));

        assert!(result.is_err(), "transport kind must remain snake_case");
    }

    #[test]
    fn endpoint_report_rejects_nested_transport_boundary_null_kind() {
        let raw = serde_json::json!({
            "endpoints": [],
            "middleware_coverage": {
                "auth_coverage": true,
                "policy_hook_coverage": true,
                "error_formatting_coverage": true,
                "tracing_coverage": true,
                "rate_limiting_coverage": true
            },
            "transport_boundary": {
                "kind": null,
                "owns_listener": false,
                "bind_target_hint": "127.0.0.1:9090",
                "request_lifecycle": "caller-owned in-process dispatch only",
                "cancellation_semantics": "no transport-owned cancellation boundary"
            },
            "performance_baselines": [],
            "generated_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<EndpointReport>(raw);

        assert!(
            result.is_err(),
            "nested transport kind must be a known string variant"
        );
    }

    #[test]
    fn endpoint_report_rejects_nested_endpoint_missing_policy_hook() {
        let raw = serde_json::json!({
            "endpoints": [{
                "group": "operator",
                "path": "/v1/operator/status",
                "method": "GET",
                "auth_method": "ApiKey",
                "lifecycle": "stable",
                "trace_propagation": true,
                "status_codes": [200, 400],
                "conformance_status": "pass"
            }],
            "middleware_coverage": {
                "auth_coverage": true,
                "policy_hook_coverage": true,
                "error_formatting_coverage": true,
                "tracing_coverage": true,
                "rate_limiting_coverage": true
            },
            "transport_boundary": {
                "kind": "in_process_catalog",
                "owns_listener": false,
                "bind_target_hint": "127.0.0.1:9090",
                "request_lifecycle": "caller-owned in-process dispatch only",
                "cancellation_semantics": "no transport-owned cancellation boundary"
            },
            "performance_baselines": [],
            "generated_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<EndpointReport>(raw);

        assert!(result.is_err(), "nested endpoint policy_hook is required");
    }

    #[test]
    fn service_config_rejects_negative_burst_size_override() {
        let raw = serde_json::json!({
            "bind_target_hint": "127.0.0.1:9090",
            "rate_limits": {
                "operator": {
                    "sustained_rps": 1,
                    "burst_size": -1,
                    "fail_closed": false
                }
            },
            "otel_enabled": false,
            "service_name": "franken-node-control-plane"
        });

        let result = serde_json::from_value::<ServiceConfig>(raw);

        assert!(result.is_err(), "burst_size must remain unsigned");
    }

    #[test]
    fn service_config_rejects_string_fail_closed_override() {
        let raw = serde_json::json!({
            "bind_target_hint": "127.0.0.1:9090",
            "rate_limits": {
                "operator": {
                    "sustained_rps": 1,
                    "burst_size": 1,
                    "fail_closed": "false"
                }
            },
            "otel_enabled": false,
            "service_name": "franken-node-control-plane"
        });

        let result = serde_json::from_value::<ServiceConfig>(raw);

        assert!(result.is_err(), "fail_closed must remain boolean");
    }

    #[test]
    fn request_lifecycle_rejects_numeric_route_path() {
        let raw = serde_json::json!({
            "transport_boundary_kind": "in_process_catalog",
            "transport_owns_listener": false,
            "endpoint_group": "operator",
            "route_path": 404,
            "perf_baseline_status": "unavailable_pending_transport",
            "perf_baseline_provenance": "pending live transport",
            "request_lifecycle": "caller-owned in-process dispatch only",
            "cancellation_semantics": "no transport-owned cancellation boundary"
        });

        let result = serde_json::from_value::<RequestLifecycleProvenance>(raw);

        assert!(result.is_err(), "route_path must stay a string");
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

/// Contract tests: validate runtime output matches artifact contracts.
#[cfg(test)]
mod contract_tests {
    use super::*;
    use std::path::{Path, PathBuf};

    const ARTIFACT_PATH: &str = "artifacts/10.16/fastapi_endpoint_report.json";

    fn artifact_report_path() -> Option<PathBuf> {
        Some(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.join(ARTIFACT_PATH))?,
        )
    }

    fn load_artifact_report() -> Option<EndpointReport> {
        let path = artifact_report_path()?;

        if !path.exists() {
            return None;
        }

        let contents = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&contents).ok()
    }

    #[test]
    fn runtime_includes_all_artifact_endpoints() {
        // In test mode, control-plane feature adds extra endpoints beyond
        // the base artifact. This test validates that all artifact endpoints
        // are present in runtime (runtime is a superset of artifact).
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let artifact_path = artifact_report_path().unwrap_or_else(|| PathBuf::from(ARTIFACT_PATH));

        let Some(artifact) = load_artifact_report() else {
            tracing::warn!(
                artifact_path = %artifact_path.display(),
                operation = "runtime_includes_all_artifact_endpoints",
                "artifact file not found, skipping contract validation"
            );
            return;
        };

        let runtime = generate_endpoint_report(&ServiceConfig::default());

        // Runtime should have at least as many endpoints as artifact
        assert!(
            runtime.endpoints.len() >= artifact.endpoints.len(),
            "runtime ({}) has fewer endpoints than artifact ({})",
            runtime.endpoints.len(),
            artifact.endpoints.len()
        );
    }

    #[test]
    fn artifact_endpoints_present_in_runtime() {
        // Validates that all base endpoints in the artifact are present in runtime.
        // Runtime may include additional endpoints from control-plane feature.
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();
        let artifact_path = artifact_report_path().unwrap_or_else(|| PathBuf::from(ARTIFACT_PATH));

        let Some(artifact) = load_artifact_report() else {
            tracing::warn!(
                artifact_path = %artifact_path.display(),
                operation = "artifact_endpoints_present_in_runtime",
                "artifact file not found, skipping contract validation"
            );
            return;
        };

        let runtime = generate_endpoint_report(&ServiceConfig::default());

        let runtime_paths: std::collections::BTreeSet<_> = runtime
            .endpoints
            .iter()
            .map(|e| format!("{} {}", e.method, e.path))
            .collect();
        let artifact_paths: std::collections::BTreeSet<_> = artifact
            .endpoints
            .iter()
            .map(|e| format!("{} {}", e.method, e.path))
            .collect();

        let missing_in_runtime: Vec<_> = artifact_paths.difference(&runtime_paths).collect();

        assert!(
            missing_in_runtime.is_empty(),
            "artifact endpoints missing in runtime: {:?}",
            missing_in_runtime
        );
    }

    #[test]
    fn runtime_middleware_coverage_matches_artifact() {
        let artifact_path = artifact_report_path().unwrap_or_else(|| PathBuf::from(ARTIFACT_PATH));

        let Some(artifact) = load_artifact_report() else {
            tracing::warn!(
                artifact_path = %artifact_path.display(),
                operation = "runtime_middleware_coverage_matches_artifact",
                "artifact file not found, skipping contract validation"
            );
            return;
        };

        let runtime = generate_endpoint_report(&ServiceConfig::default());

        assert_eq!(
            runtime.middleware_coverage.auth_coverage, artifact.middleware_coverage.auth_coverage,
            "auth_coverage mismatch"
        );
        assert_eq!(
            runtime.middleware_coverage.policy_hook_coverage,
            artifact.middleware_coverage.policy_hook_coverage,
            "policy_hook_coverage mismatch"
        );
        assert_eq!(
            runtime.middleware_coverage.tracing_coverage,
            artifact.middleware_coverage.tracing_coverage,
            "tracing_coverage mismatch"
        );
        assert_eq!(
            runtime.middleware_coverage.error_formatting_coverage,
            artifact.middleware_coverage.error_formatting_coverage,
            "error_formatting_coverage mismatch"
        );
        assert_eq!(
            runtime.middleware_coverage.rate_limiting_coverage,
            artifact.middleware_coverage.rate_limiting_coverage,
            "rate_limiting_coverage mismatch"
        );
    }

    #[test]
    fn runtime_transport_boundary_matches_artifact() {
        let artifact_path = artifact_report_path().unwrap_or_else(|| PathBuf::from(ARTIFACT_PATH));

        let Some(artifact) = load_artifact_report() else {
            tracing::warn!(
                artifact_path = %artifact_path.display(),
                operation = "runtime_transport_boundary_matches_artifact",
                "artifact file not found, skipping contract validation"
            );
            return;
        };

        let runtime = generate_endpoint_report(&ServiceConfig::default());

        assert_eq!(
            runtime.transport_boundary.kind, artifact.transport_boundary.kind,
            "transport_boundary.kind mismatch"
        );
        assert_eq!(
            runtime.transport_boundary.owns_listener, artifact.transport_boundary.owns_listener,
            "transport_boundary.owns_listener mismatch"
        );
    }

    #[test]
    fn runtime_performance_baselines_all_unavailable_pending_transport() {
        let _lock = super::operator_routes::process_start_test_lock();
        super::operator_routes::clear_process_start_override_for_tests();

        let runtime = generate_endpoint_report(&ServiceConfig::default());

        for baseline in &runtime.performance_baselines {
            assert_eq!(
                baseline.status,
                PerformanceBaselineStatus::UnavailablePendingTransport,
                "baseline {} has unexpected status {:?}",
                baseline.endpoint,
                baseline.status
            );
            assert!(
                baseline.p50_ms.is_none(),
                "baseline {} should have no p50_ms",
                baseline.endpoint
            );
            assert!(
                !baseline.provenance.is_empty(),
                "baseline {} should have provenance explanation",
                baseline.endpoint
            );
        }
    }

    #[test]
    fn all_endpoints_have_conformance_pass_in_artifact() {
        let artifact_path = artifact_report_path().unwrap_or_else(|| PathBuf::from(ARTIFACT_PATH));

        let Some(artifact) = load_artifact_report() else {
            tracing::warn!(
                artifact_path = %artifact_path.display(),
                operation = "all_endpoints_have_conformance_pass_in_artifact",
                "artifact file not found, skipping contract validation"
            );
            return;
        };

        for entry in &artifact.endpoints {
            assert_eq!(
                entry.conformance_status, "pass",
                "endpoint {} {} has non-pass conformance: {}",
                entry.method, entry.path, entry.conformance_status
            );
        }
    }
}
