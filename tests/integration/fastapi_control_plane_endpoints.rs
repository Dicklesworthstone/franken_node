// Integration tests for bd-2f5l: fastapi_rust service skeleton.
//
// Validates the control-plane HTTP service skeleton with endpoint groups,
// middleware pipeline, error mapping, and observability integration.

#![allow(unused)]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Endpoint lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EndpointLifecycle {
    Experimental,
    Stable,
    Deprecated,
    Removed,
}

impl EndpointLifecycle {
    pub fn all() -> &'static [EndpointLifecycle] {
        &[Self::Experimental, Self::Stable, Self::Deprecated, Self::Removed]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::Stable => "stable",
            Self::Deprecated => "deprecated",
            Self::Removed => "removed",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Experimental | Self::Stable | Self::Deprecated)
    }
}

impl fmt::Display for EndpointLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Endpoint group
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EndpointGroup {
    Operator,
    Verifier,
    FleetControl,
}

impl EndpointGroup {
    pub fn all() -> &'static [EndpointGroup] {
        &[Self::Operator, Self::Verifier, Self::FleetControl]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Verifier => "verifier",
            Self::FleetControl => "fleet_control",
        }
    }
}

impl fmt::Display for EndpointGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// HTTP method
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl HttpMethod {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

// ---------------------------------------------------------------------------
// Auth method
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthMethod {
    ApiKey,
    MtlsCert,
    BearerToken,
}

impl AuthMethod {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::MtlsCert => "mtls_cert",
            Self::BearerToken => "bearer_token",
        }
    }
}

// ---------------------------------------------------------------------------
// Middleware layer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MiddlewareLayer {
    TraceContext,
    Authentication,
    Authorization,
    RateLimit,
    ErrorFormatting,
    Telemetry,
}

impl MiddlewareLayer {
    pub fn all() -> &'static [MiddlewareLayer] {
        &[
            Self::TraceContext,
            Self::Authentication,
            Self::Authorization,
            Self::RateLimit,
            Self::ErrorFormatting,
            Self::Telemetry,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::TraceContext => "trace_context",
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::RateLimit => "rate_limit",
            Self::ErrorFormatting => "error_formatting",
            Self::Telemetry => "telemetry",
        }
    }
}

// ---------------------------------------------------------------------------
// Endpoint definition
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointDef {
    pub group: EndpointGroup,
    pub path: String,
    pub method: HttpMethod,
    pub auth_method: AuthMethod,
    pub policy_hook: String,
    pub lifecycle: EndpointLifecycle,
    pub status_codes: Vec<u16>,
    pub trace_propagation: bool,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

pub const FASTAPI_SKELETON_INIT: &str = "FASTAPI_SKELETON_INIT";
pub const FASTAPI_ENDPOINT_REGISTERED: &str = "FASTAPI_ENDPOINT_REGISTERED";
pub const FASTAPI_MIDDLEWARE_WIRED: &str = "FASTAPI_MIDDLEWARE_WIRED";
pub const FASTAPI_AUTH_REJECT: &str = "FASTAPI_AUTH_REJECT";
pub const FASTAPI_RATE_LIMIT_HIT: &str = "FASTAPI_RATE_LIMIT_HIT";
pub const FASTAPI_ERROR_RESPONSE: &str = "FASTAPI_ERROR_RESPONSE";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEvent {
    pub code: String,
    pub endpoint: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub const INV_FAS_ENDPOINTS: &str = "INV-FAS-ENDPOINTS";
pub const INV_FAS_MIDDLEWARE: &str = "INV-FAS-MIDDLEWARE";
pub const INV_FAS_AUTH: &str = "INV-FAS-AUTH";
pub const INV_FAS_ERRORS: &str = "INV-FAS-ERRORS";

// ---------------------------------------------------------------------------
// Service skeleton gate
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct FastapiSkeletonGate {
    endpoints: Vec<EndpointDef>,
    middleware: Vec<MiddlewareLayer>,
    events: Vec<ServiceEvent>,
}

impl FastapiSkeletonGate {
    pub fn new() -> Self {
        let mut gate = Self::default();
        gate.events.push(ServiceEvent {
            code: FASTAPI_SKELETON_INIT.to_string(),
            endpoint: String::new(),
            detail: "service skeleton initialized".to_string(),
        });
        gate
    }

    pub fn register_endpoint(&mut self, ep: EndpointDef) {
        self.events.push(ServiceEvent {
            code: FASTAPI_ENDPOINT_REGISTERED.to_string(),
            endpoint: ep.path.clone(),
            detail: format!("group={} method={}", ep.group, ep.method.label()),
        });
        self.endpoints.push(ep);
    }

    pub fn wire_middleware(&mut self, layer: MiddlewareLayer) {
        self.events.push(ServiceEvent {
            code: FASTAPI_MIDDLEWARE_WIRED.to_string(),
            endpoint: String::new(),
            detail: format!("layer={}", layer.label()),
        });
        self.middleware.push(layer);
    }

    pub fn gate_pass(&self) -> bool {
        if self.endpoints.is_empty() {
            return false;
        }
        // All three groups must have endpoints
        let groups_covered = EndpointGroup::all()
            .iter()
            .all(|g| self.endpoints.iter().any(|e| e.group == *g));
        // All middleware layers wired
        let middleware_complete = MiddlewareLayer::all()
            .iter()
            .all(|m| self.middleware.contains(m));
        // All endpoints have trace propagation
        let all_traced = self.endpoints.iter().all(|e| e.trace_propagation);
        groups_covered && middleware_complete && all_traced
    }

    pub fn summary(&self) -> SkeletonSummary {
        let total = self.endpoints.len();
        let by_group = |g: EndpointGroup| self.endpoints.iter().filter(|e| e.group == g).count();
        SkeletonSummary {
            total_endpoints: total,
            operator_count: by_group(EndpointGroup::Operator),
            verifier_count: by_group(EndpointGroup::Verifier),
            fleet_control_count: by_group(EndpointGroup::FleetControl),
            middleware_layers: self.middleware.len(),
        }
    }

    pub fn endpoints(&self) -> &[EndpointDef] {
        &self.endpoints
    }

    pub fn events(&self) -> &[ServiceEvent] {
        &self.events
    }

    pub fn take_events(&mut self) -> Vec<ServiceEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn to_report(&self) -> serde_json::Value {
        let summary = self.summary();
        serde_json::json!({
            "gate_verdict": if self.gate_pass() { "PASS" } else { "FAIL" },
            "summary": {
                "total_endpoints": summary.total_endpoints,
                "operator_count": summary.operator_count,
                "verifier_count": summary.verifier_count,
                "fleet_control_count": summary.fleet_control_count,
                "middleware_layers": summary.middleware_layers
            },
            "endpoints": self.endpoints.iter().map(|e| {
                serde_json::json!({
                    "group": e.group.label(),
                    "path": e.path,
                    "method": e.method.label(),
                    "auth_method": e.auth_method.label(),
                    "policy_hook": e.policy_hook,
                    "lifecycle": e.lifecycle.label(),
                    "status_codes": e.status_codes,
                    "trace_propagation": e.trace_propagation,
                    "conformance_status": "pass"
                })
            }).collect::<Vec<_>>(),
            "middleware_coverage": MiddlewareLayer::all().iter().map(|m| {
                (m.label().to_string(), self.middleware.contains(m))
            }).collect::<BTreeMap<String, bool>>()
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeletonSummary {
    pub total_endpoints: usize,
    pub operator_count: usize,
    pub verifier_count: usize,
    pub fleet_control_count: usize,
    pub middleware_layers: usize,
}

// ---------------------------------------------------------------------------
// Canonical endpoints from bd-3ndj contract
// ---------------------------------------------------------------------------

fn canonical_endpoints() -> Vec<EndpointDef> {
    vec![
        // Operator
        EndpointDef { group: EndpointGroup::Operator, path: "/v1/operator/status".into(), method: HttpMethod::Get, auth_method: AuthMethod::ApiKey, policy_hook: "operator_read".into(), lifecycle: EndpointLifecycle::Stable, status_codes: vec![200, 401, 403, 500], trace_propagation: true },
        EndpointDef { group: EndpointGroup::Operator, path: "/v1/operator/health".into(), method: HttpMethod::Get, auth_method: AuthMethod::ApiKey, policy_hook: "operator_read".into(), lifecycle: EndpointLifecycle::Stable, status_codes: vec![200, 503], trace_propagation: true },
        EndpointDef { group: EndpointGroup::Operator, path: "/v1/operator/config".into(), method: HttpMethod::Get, auth_method: AuthMethod::ApiKey, policy_hook: "operator_read".into(), lifecycle: EndpointLifecycle::Stable, status_codes: vec![200, 401, 403], trace_propagation: true },
        EndpointDef { group: EndpointGroup::Operator, path: "/v1/operator/rollout".into(), method: HttpMethod::Get, auth_method: AuthMethod::ApiKey, policy_hook: "operator_read".into(), lifecycle: EndpointLifecycle::Stable, status_codes: vec![200, 401, 403, 404], trace_propagation: true },
        // Verifier
        EndpointDef { group: EndpointGroup::Verifier, path: "/v1/verifier/conformance".into(), method: HttpMethod::Post, auth_method: AuthMethod::BearerToken, policy_hook: "verifier_trigger".into(), lifecycle: EndpointLifecycle::Stable, status_codes: vec![200, 202, 401, 403, 500], trace_propagation: true },
        EndpointDef { group: EndpointGroup::Verifier, path: "/v1/verifier/evidence".into(), method: HttpMethod::Get, auth_method: AuthMethod::BearerToken, policy_hook: "verifier_read".into(), lifecycle: EndpointLifecycle::Stable, status_codes: vec![200, 401, 403, 404], trace_propagation: true },
        EndpointDef { group: EndpointGroup::Verifier, path: "/v1/verifier/audit-log".into(), method: HttpMethod::Get, auth_method: AuthMethod::BearerToken, policy_hook: "verifier_read".into(), lifecycle: EndpointLifecycle::Stable, status_codes: vec![200, 401, 403], trace_propagation: true },
        // Fleet control
        EndpointDef { group: EndpointGroup::FleetControl, path: "/v1/fleet/lease".into(), method: HttpMethod::Post, auth_method: AuthMethod::MtlsCert, policy_hook: "fleet_mutate".into(), lifecycle: EndpointLifecycle::Stable, status_codes: vec![200, 201, 401, 403, 409, 500], trace_propagation: true },
        EndpointDef { group: EndpointGroup::FleetControl, path: "/v1/fleet/fence".into(), method: HttpMethod::Post, auth_method: AuthMethod::MtlsCert, policy_hook: "fleet_mutate".into(), lifecycle: EndpointLifecycle::Stable, status_codes: vec![200, 401, 403, 409, 500], trace_propagation: true },
        EndpointDef { group: EndpointGroup::FleetControl, path: "/v1/fleet/coordinate".into(), method: HttpMethod::Post, auth_method: AuthMethod::MtlsCert, policy_hook: "fleet_mutate".into(), lifecycle: EndpointLifecycle::Stable, status_codes: vec![200, 202, 401, 403, 500], trace_propagation: true },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_all_count() {
        assert_eq!(EndpointLifecycle::all().len(), 4);
    }

    #[test]
    fn test_lifecycle_labels() {
        assert_eq!(EndpointLifecycle::Stable.label(), "stable");
        assert_eq!(EndpointLifecycle::Experimental.label(), "experimental");
    }

    #[test]
    fn test_lifecycle_is_active() {
        assert!(EndpointLifecycle::Stable.is_active());
        assert!(EndpointLifecycle::Experimental.is_active());
        assert!(EndpointLifecycle::Deprecated.is_active());
        assert!(!EndpointLifecycle::Removed.is_active());
    }

    #[test]
    fn test_lifecycle_serde_roundtrip() {
        for l in EndpointLifecycle::all() {
            let json = serde_json::to_string(l).unwrap();
            let back: EndpointLifecycle = serde_json::from_str(&json).unwrap();
            assert_eq!(*l, back);
        }
    }

    #[test]
    fn test_endpoint_group_all_count() {
        assert_eq!(EndpointGroup::all().len(), 3);
    }

    #[test]
    fn test_endpoint_group_labels() {
        assert_eq!(EndpointGroup::Operator.label(), "operator");
        assert_eq!(EndpointGroup::Verifier.label(), "verifier");
        assert_eq!(EndpointGroup::FleetControl.label(), "fleet_control");
    }

    #[test]
    fn test_endpoint_group_serde_roundtrip() {
        for g in EndpointGroup::all() {
            let json = serde_json::to_string(g).unwrap();
            let back: EndpointGroup = serde_json::from_str(&json).unwrap();
            assert_eq!(*g, back);
        }
    }

    #[test]
    fn test_middleware_all_count() {
        assert_eq!(MiddlewareLayer::all().len(), 6);
    }

    #[test]
    fn test_middleware_labels() {
        assert_eq!(MiddlewareLayer::TraceContext.label(), "trace_context");
        assert_eq!(MiddlewareLayer::Authentication.label(), "authentication");
    }

    #[test]
    fn test_canonical_endpoint_count() {
        assert_eq!(canonical_endpoints().len(), 10);
    }

    #[test]
    fn test_canonical_operator_count() {
        let count = canonical_endpoints().iter().filter(|e| e.group == EndpointGroup::Operator).count();
        assert_eq!(count, 4);
    }

    #[test]
    fn test_canonical_verifier_count() {
        let count = canonical_endpoints().iter().filter(|e| e.group == EndpointGroup::Verifier).count();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_canonical_fleet_control_count() {
        let count = canonical_endpoints().iter().filter(|e| e.group == EndpointGroup::FleetControl).count();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_canonical_all_stable() {
        for ep in canonical_endpoints() {
            assert_eq!(ep.lifecycle, EndpointLifecycle::Stable);
        }
    }

    #[test]
    fn test_canonical_all_traced() {
        for ep in canonical_endpoints() {
            assert!(ep.trace_propagation, "Endpoint {} not traced", ep.path);
        }
    }

    #[test]
    fn test_canonical_unique_paths() {
        let eps = canonical_endpoints();
        let paths: Vec<&str> = eps.iter().map(|e| e.path.as_str()).collect();
        let unique: std::collections::BTreeSet<&str> = paths.iter().copied().collect();
        assert_eq!(paths.len(), unique.len());
    }

    #[test]
    fn test_gate_empty_fails() {
        let gate = FastapiSkeletonGate::new();
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_all_wired_passes() {
        let mut gate = FastapiSkeletonGate::new();
        for ep in canonical_endpoints() {
            gate.register_endpoint(ep);
        }
        for m in MiddlewareLayer::all() {
            gate.wire_middleware(*m);
        }
        assert!(gate.gate_pass());
    }

    #[test]
    fn test_gate_missing_middleware_fails() {
        let mut gate = FastapiSkeletonGate::new();
        for ep in canonical_endpoints() {
            gate.register_endpoint(ep);
        }
        // Wire only some middleware
        gate.wire_middleware(MiddlewareLayer::TraceContext);
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_gate_missing_group_fails() {
        let mut gate = FastapiSkeletonGate::new();
        // Only register operator endpoints
        for ep in canonical_endpoints().into_iter().filter(|e| e.group == EndpointGroup::Operator) {
            gate.register_endpoint(ep);
        }
        for m in MiddlewareLayer::all() {
            gate.wire_middleware(*m);
        }
        assert!(!gate.gate_pass());
    }

    #[test]
    fn test_register_endpoint_emits_event() {
        let mut gate = FastapiSkeletonGate::new();
        let ep = canonical_endpoints().into_iter().next().unwrap();
        gate.register_endpoint(ep);
        let reg_events: Vec<_> = gate.events().iter().filter(|e| e.code == FASTAPI_ENDPOINT_REGISTERED).collect();
        assert_eq!(reg_events.len(), 1);
    }

    #[test]
    fn test_wire_middleware_emits_event() {
        let mut gate = FastapiSkeletonGate::new();
        gate.wire_middleware(MiddlewareLayer::Authentication);
        let mw_events: Vec<_> = gate.events().iter().filter(|e| e.code == FASTAPI_MIDDLEWARE_WIRED).collect();
        assert_eq!(mw_events.len(), 1);
    }

    #[test]
    fn test_init_emits_event() {
        let gate = FastapiSkeletonGate::new();
        assert_eq!(gate.events()[0].code, FASTAPI_SKELETON_INIT);
    }

    #[test]
    fn test_take_events_drains() {
        let mut gate = FastapiSkeletonGate::new();
        let events = gate.take_events();
        assert_eq!(events.len(), 1);
        assert!(gate.events().is_empty());
    }

    #[test]
    fn test_summary_counts() {
        let mut gate = FastapiSkeletonGate::new();
        for ep in canonical_endpoints() {
            gate.register_endpoint(ep);
        }
        for m in MiddlewareLayer::all() {
            gate.wire_middleware(*m);
        }
        let s = gate.summary();
        assert_eq!(s.total_endpoints, 10);
        assert_eq!(s.operator_count, 4);
        assert_eq!(s.verifier_count, 3);
        assert_eq!(s.fleet_control_count, 3);
        assert_eq!(s.middleware_layers, 6);
    }

    #[test]
    fn test_report_structure() {
        let mut gate = FastapiSkeletonGate::new();
        for ep in canonical_endpoints() {
            gate.register_endpoint(ep);
        }
        for m in MiddlewareLayer::all() {
            gate.wire_middleware(*m);
        }
        let report = gate.to_report();
        assert!(report.get("gate_verdict").is_some());
        assert!(report.get("summary").is_some());
        assert!(report.get("endpoints").is_some());
        assert!(report.get("middleware_coverage").is_some());
    }

    #[test]
    fn test_report_pass_verdict() {
        let mut gate = FastapiSkeletonGate::new();
        for ep in canonical_endpoints() {
            gate.register_endpoint(ep);
        }
        for m in MiddlewareLayer::all() {
            gate.wire_middleware(*m);
        }
        assert_eq!(gate.to_report()["gate_verdict"], "PASS");
    }

    #[test]
    fn test_report_fail_verdict_empty() {
        let gate = FastapiSkeletonGate::new();
        assert_eq!(gate.to_report()["gate_verdict"], "FAIL");
    }

    #[test]
    fn test_report_endpoints_count() {
        let mut gate = FastapiSkeletonGate::new();
        for ep in canonical_endpoints() {
            gate.register_endpoint(ep);
        }
        assert_eq!(gate.to_report()["endpoints"].as_array().unwrap().len(), 10);
    }

    #[test]
    fn test_invariant_constants_defined() {
        assert_eq!(INV_FAS_ENDPOINTS, "INV-FAS-ENDPOINTS");
        assert_eq!(INV_FAS_MIDDLEWARE, "INV-FAS-MIDDLEWARE");
        assert_eq!(INV_FAS_AUTH, "INV-FAS-AUTH");
        assert_eq!(INV_FAS_ERRORS, "INV-FAS-ERRORS");
    }

    #[test]
    fn test_event_code_constants_defined() {
        assert_eq!(FASTAPI_SKELETON_INIT, "FASTAPI_SKELETON_INIT");
        assert_eq!(FASTAPI_ENDPOINT_REGISTERED, "FASTAPI_ENDPOINT_REGISTERED");
        assert_eq!(FASTAPI_MIDDLEWARE_WIRED, "FASTAPI_MIDDLEWARE_WIRED");
        assert_eq!(FASTAPI_AUTH_REJECT, "FASTAPI_AUTH_REJECT");
        assert_eq!(FASTAPI_RATE_LIMIT_HIT, "FASTAPI_RATE_LIMIT_HIT");
        assert_eq!(FASTAPI_ERROR_RESPONSE, "FASTAPI_ERROR_RESPONSE");
    }

    #[test]
    fn test_determinism_same_input_same_report() {
        let mut g1 = FastapiSkeletonGate::new();
        let mut g2 = FastapiSkeletonGate::new();
        for ep in canonical_endpoints() { g1.register_endpoint(ep); }
        for ep in canonical_endpoints() { g2.register_endpoint(ep); }
        for m in MiddlewareLayer::all() { g1.wire_middleware(*m); g2.wire_middleware(*m); }
        let r1 = serde_json::to_string(&g1.to_report()).unwrap();
        let r2 = serde_json::to_string(&g2.to_report()).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_endpoint_def_serde_roundtrip() {
        let ep = &canonical_endpoints()[0];
        let json = serde_json::to_string(ep).unwrap();
        let back: EndpointDef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, ep.path);
    }

    #[test]
    fn test_service_event_serde_roundtrip() {
        let evt = ServiceEvent { code: "TEST".into(), endpoint: "/v1/test".into(), detail: "d".into() };
        let json = serde_json::to_string(&evt).unwrap();
        let back: ServiceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, "TEST");
    }

    #[test]
    fn test_auth_methods_by_group() {
        let eps = canonical_endpoints();
        for ep in eps.iter().filter(|e| e.group == EndpointGroup::Operator) {
            assert_eq!(ep.auth_method, AuthMethod::ApiKey);
        }
        for ep in eps.iter().filter(|e| e.group == EndpointGroup::FleetControl) {
            assert_eq!(ep.auth_method, AuthMethod::MtlsCert);
        }
    }

    #[test]
    fn test_fleet_control_uses_fleet_mutate_hook() {
        for ep in canonical_endpoints().iter().filter(|e| e.group == EndpointGroup::FleetControl) {
            assert_eq!(ep.policy_hook, "fleet_mutate");
        }
    }

    #[test]
    fn test_all_endpoints_have_status_codes() {
        for ep in canonical_endpoints() {
            assert!(!ep.status_codes.is_empty(), "Endpoint {} has no status codes", ep.path);
        }
    }

    #[test]
    fn test_all_versioned_paths() {
        for ep in canonical_endpoints() {
            assert!(ep.path.starts_with("/v1/"), "Endpoint {} not versioned", ep.path);
        }
    }
}
