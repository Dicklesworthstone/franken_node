//! Fleet-control endpoint group: lease management, fencing operations,
//! multi-node coordination.
//!
//! Routes:
//! - `GET    /v1/fleet/leases`       — list active leases
//! - `POST   /v1/fleet/leases`       — acquire a lease
//! - `DELETE /v1/fleet/leases/{id}`   — release a lease
//! - `POST   /v1/fleet/fence`        — execute a fencing operation
//! - `POST   /v1/fleet/coordinate`   — multi-node coordination command

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::error::ApiError;
use super::middleware::{
    AuthIdentity, AuthMethod, EndpointGroup, EndpointLifecycle, PolicyHook, RouteMetadata,
    TraceContext,
};
use super::trust_card_routes::ApiResponse;
use super::utf8_prefix;

// ── Response Types ─────────────────────────────────────────────────────────

/// Lease record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub lease_id: String,
    pub holder: String,
    pub resource: String,
    pub acquired_at: String,
    pub expires_at: String,
    pub fencing_token: u64,
}

/// Fencing operation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencingResult {
    pub operation_id: String,
    pub target_node: String,
    pub action: FencingAction,
    pub status: FencingStatus,
    pub fencing_token: u64,
    pub executed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencingAction {
    Isolate,
    Drain,
    Rejoin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencingStatus {
    Completed,
    Pending,
    Failed,
}

/// Multi-node coordination command result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationResult {
    pub command_id: String,
    pub command_type: String,
    pub participating_nodes: Vec<String>,
    pub ack_count: u32,
    pub total_nodes: u32,
    pub status: CoordinationStatus,
    pub issued_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordinationStatus {
    Acknowledged,
    Partial,
    Timeout,
}

/// Request to acquire a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseAcquireRequest {
    pub resource: String,
    pub ttl_seconds: u32,
}

/// Request for a fencing operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencingRequest {
    pub target_node: String,
    pub action: FencingAction,
    pub reason: String,
}

/// Multi-node coordination command request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationRequest {
    pub command_type: String,
    pub target_nodes: Vec<String>,
    pub timeout_seconds: u32,
}

fn validate_coordination_targets(target_nodes: &[String], trace_id: &str) -> Result<(), ApiError> {
    if target_nodes.is_empty() {
        return Err(ApiError::BadRequest {
            detail: "coordination requires at least one target node".to_string(),
            trace_id: trace_id.to_string(),
        });
    }

    let mut seen = BTreeSet::new();
    for node_id in target_nodes {
        if !seen.insert(node_id.as_str()) {
            return Err(ApiError::BadRequest {
                detail: format!("duplicate target node `{node_id}` is not allowed"),
                trace_id: trace_id.to_string(),
            });
        }
    }

    Ok(())
}

// ── Route Metadata ─────────────────────────────────────────────────────────

pub fn route_metadata() -> Vec<RouteMetadata> {
    vec![
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/fleet/leases".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "fleet.leases.read".to_string(),
                required_roles: vec!["operator".to_string(), "fleet-admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/fleet/leases".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "fleet.leases.acquire".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "DELETE".to_string(),
            path: "/v1/fleet/leases/{lease_id}".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "fleet.leases.release".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/fleet/fence".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::MtlsClientCert,
            policy_hook: PolicyHook {
                hook_id: "fleet.fence.execute".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/fleet/coordinate".to_string(),
            group: EndpointGroup::FleetControl,
            lifecycle: EndpointLifecycle::Experimental,
            auth_method: AuthMethod::MtlsClientCert,
            policy_hook: PolicyHook {
                hook_id: "fleet.coordinate.execute".to_string(),
                required_roles: vec!["fleet-admin".to_string()],
            },
            trace_propagation: true,
        },
    ]
}

// ── Handlers ───────────────────────────────────────────────────────────────

/// Handle `GET /v1/fleet/leases`.
pub fn list_leases(
    _identity: &AuthIdentity,
    _trace: &TraceContext,
) -> Result<ApiResponse<Vec<Lease>>, ApiError> {
    // Skeleton: return empty lease list.
    Ok(ApiResponse {
        ok: true,
        data: Vec::new(),
        page: None,
    })
}

/// Handle `POST /v1/fleet/leases`.
pub fn acquire_lease(
    identity: &AuthIdentity,
    trace: &TraceContext,
    request: &LeaseAcquireRequest,
) -> Result<ApiResponse<Lease>, ApiError> {
    let lease_id = format!("lease-{}", utf8_prefix(&trace.trace_id, 12));
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::seconds(i64::from(request.ttl_seconds));

    let lease = Lease {
        lease_id,
        holder: identity.principal.clone(),
        resource: request.resource.clone(),
        acquired_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        fencing_token: 1,
    };

    Ok(ApiResponse {
        ok: true,
        data: lease,
        page: None,
    })
}

/// Handle `DELETE /v1/fleet/leases/{lease_id}`.
pub fn release_lease(
    _identity: &AuthIdentity,
    _trace: &TraceContext,
    _lease_id: &str,
) -> Result<ApiResponse<bool>, ApiError> {
    // Skeleton: always succeeds.
    Ok(ApiResponse {
        ok: true,
        data: true,
        page: None,
    })
}

/// Handle `POST /v1/fleet/fence`.
pub fn execute_fence(
    _identity: &AuthIdentity,
    trace: &TraceContext,
    request: &FencingRequest,
) -> Result<ApiResponse<FencingResult>, ApiError> {
    let operation_id = format!("fence-{}", utf8_prefix(&trace.trace_id, 12));

    let result = FencingResult {
        operation_id,
        target_node: request.target_node.clone(),
        action: request.action,
        status: FencingStatus::Completed,
        fencing_token: 1,
        executed_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

/// Handle `POST /v1/fleet/coordinate`.
pub fn execute_coordination(
    _identity: &AuthIdentity,
    trace: &TraceContext,
    request: &CoordinationRequest,
) -> Result<ApiResponse<CoordinationResult>, ApiError> {
    validate_coordination_targets(&request.target_nodes, &trace.trace_id)?;

    let command_id = format!("coord-{}", utf8_prefix(&trace.trace_id, 12));

    let result = CoordinationResult {
        command_id,
        command_type: request.command_type.clone(),
        participating_nodes: request.target_nodes.clone(),
        ack_count: u32::try_from(request.target_nodes.len()).unwrap_or(u32::MAX),
        total_nodes: u32::try_from(request.target_nodes.len()).unwrap_or(u32::MAX),
        status: CoordinationStatus::Acknowledged,
        issued_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::AuthMethod;

    fn admin_identity() -> AuthIdentity {
        AuthIdentity {
            principal: "fleet-admin-1".to_string(),
            method: AuthMethod::MtlsClientCert,
            roles: vec!["fleet-admin".to_string()],
        }
    }

    fn test_trace() -> TraceContext {
        TraceContext {
            trace_id: "test-trace-fleet-001".to_string(),
            span_id: "0000000000000003".to_string(),
            trace_flags: 1,
        }
    }

    #[test]
    fn route_metadata_has_five_endpoints() {
        let routes = route_metadata();
        assert_eq!(routes.len(), 5);
        assert!(
            routes
                .iter()
                .all(|r| r.group == EndpointGroup::FleetControl)
        );
    }

    #[test]
    fn fencing_requires_mtls() {
        let routes = route_metadata();
        let fence = routes
            .iter()
            .find(|r| r.path.contains("fence"))
            .expect("should exist");
        assert_eq!(fence.auth_method, AuthMethod::MtlsClientCert);
    }

    #[test]
    fn coordinate_is_experimental() {
        let routes = route_metadata();
        let coord = routes
            .iter()
            .find(|r| r.path.contains("coordinate"))
            .expect("should exist");
        assert_eq!(coord.lifecycle, EndpointLifecycle::Experimental);
    }

    #[test]
    fn list_leases_returns_empty() {
        let identity = admin_identity();
        let trace = test_trace();
        let result = list_leases(&identity, &trace).expect("list leases");
        assert!(result.ok);
        assert!(result.data.is_empty());
    }

    #[test]
    fn acquire_lease_returns_lease() {
        let identity = admin_identity();
        let trace = test_trace();
        let request = LeaseAcquireRequest {
            resource: "control-plane-lock".to_string(),
            ttl_seconds: 300,
        };
        let result = acquire_lease(&identity, &trace, &request).expect("acquire");
        assert!(result.ok);
        assert!(result.data.lease_id.starts_with("lease-"));
        assert_eq!(result.data.resource, "control-plane-lock");
        assert_eq!(result.data.holder, "fleet-admin-1");
    }

    #[test]
    fn acquire_lease_handles_unicode_trace_id() {
        let identity = admin_identity();
        let trace = TraceContext {
            trace_id: "🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂".to_string(),
            span_id: "0000000000000003".to_string(),
            trace_flags: 1,
        };
        let request = LeaseAcquireRequest {
            resource: "control-plane-lock".to_string(),
            ttl_seconds: 300,
        };

        let result = acquire_lease(&identity, &trace, &request).expect("acquire");
        let expected: String = trace.trace_id.chars().take(12).collect();
        assert_eq!(result.data.lease_id, format!("lease-{expected}"));
    }

    #[test]
    fn release_lease_succeeds() {
        let identity = admin_identity();
        let trace = test_trace();
        let result = release_lease(&identity, &trace, "lease-test-001").expect("release");
        assert!(result.ok);
        assert!(result.data);
    }

    #[test]
    fn execute_fence_completes() {
        let identity = admin_identity();
        let trace = test_trace();
        let request = FencingRequest {
            target_node: "node-2".to_string(),
            action: FencingAction::Isolate,
            reason: "suspected compromise".to_string(),
        };
        let result = execute_fence(&identity, &trace, &request).expect("fence");
        assert!(result.ok);
        assert_eq!(result.data.status, FencingStatus::Completed);
        assert_eq!(result.data.action, FencingAction::Isolate);
    }

    #[test]
    fn execute_coordination_acknowledged() {
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "policy-update".to_string(),
            target_nodes: vec!["node-1".to_string(), "node-2".to_string()],
            timeout_seconds: 30,
        };
        let result = execute_coordination(&identity, &trace, &request).expect("coordinate");
        assert!(result.ok);
        assert_eq!(result.data.status, CoordinationStatus::Acknowledged);
        assert_eq!(result.data.ack_count, 2);
    }

    #[test]
    fn execute_coordination_rejects_empty_target_set() {
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "policy-update".to_string(),
            target_nodes: Vec::new(),
            timeout_seconds: 30,
        };

        let err = execute_coordination(&identity, &trace, &request).expect_err("empty targets");
        assert!(matches!(
            err,
            ApiError::BadRequest { ref trace_id, .. } if trace_id == "test-trace-fleet-001"
        ));
        let problem = err.to_problem("/v1/fleet/coordinate");
        assert_eq!(problem.status, 400);
        assert!(problem.detail.contains("at least one target node"));
    }

    #[test]
    fn execute_coordination_rejects_duplicate_target_nodes() {
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "policy-update".to_string(),
            target_nodes: vec!["node-1".to_string(), "node-1".to_string()],
            timeout_seconds: 30,
        };

        let err = execute_coordination(&identity, &trace, &request).expect_err("duplicate targets");
        assert!(matches!(
            err,
            ApiError::BadRequest { ref trace_id, .. } if trace_id == "test-trace-fleet-001"
        ));
        let problem = err.to_problem("/v1/fleet/coordinate");
        assert_eq!(problem.status, 400);
        assert!(problem.detail.contains("duplicate target node `node-1`"));
    }

    #[test]
    fn fleet_admin_role_required_for_mutations() {
        let routes = route_metadata();
        let mutation_routes: Vec<_> = routes
            .iter()
            .filter(|r| r.method == "POST" || r.method == "DELETE")
            .collect();
        for route in mutation_routes {
            assert!(
                route
                    .policy_hook
                    .required_roles
                    .contains(&"fleet-admin".to_string()),
                "mutation route {} requires fleet-admin role",
                route.path
            );
        }
    }
}
