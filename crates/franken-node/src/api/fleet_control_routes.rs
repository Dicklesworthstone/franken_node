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
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use super::error::ApiError;
use super::middleware::{
    AuthIdentity, AuthMethod, EndpointGroup, EndpointLifecycle, PolicyHook, RouteMetadata,
    TraceContext,
};
use super::trust_card_routes::ApiResponse;
use super::utf8_prefix;
use crate::capacity_defaults::aliases::MAX_LEASES;

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

#[derive(Debug, Clone)]
struct StoredLease {
    lease: Lease,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
struct FleetLeaseState {
    leases: BTreeMap<String, StoredLease>,
    next_lease_seq: u64,
    next_fencing_seq: u64,
    next_coordination_seq: u64,
}

impl Default for FleetLeaseState {
    fn default() -> Self {
        Self {
            leases: BTreeMap::new(),
            next_lease_seq: 1,
            next_fencing_seq: 1,
            next_coordination_seq: 1,
        }
    }
}

impl FleetLeaseState {
    fn sweep_expired(&mut self, now: chrono::DateTime<chrono::Utc>) {
        let expired_ids: Vec<String> = self
            .leases
            .iter()
            .filter(|(_, stored)| stored.expires_at <= now)
            .map(|(lease_id, _)| lease_id.clone())
            .collect();

        for lease_id in expired_ids {
            self.leases.remove(&lease_id);
        }
    }

    fn next_lease_id(&mut self, trace_id: &str) -> String {
        let lease_id = format!(
            "lease-{}-{:04}",
            utf8_prefix(trace_id, 12),
            self.next_lease_seq
        );
        self.next_lease_seq = self.next_lease_seq.saturating_add(1);
        lease_id
    }

    fn issue_fencing_token(&mut self) -> u64 {
        let fencing_seq = self.next_fencing_seq;
        self.next_fencing_seq = self.next_fencing_seq.saturating_add(1);
        fencing_seq
    }

    fn next_coordination_id(&mut self, trace_id: &str) -> String {
        let command_id = format!(
            "coord-{}-{:04}",
            utf8_prefix(trace_id, 12),
            self.next_coordination_seq
        );
        self.next_coordination_seq = self.next_coordination_seq.saturating_add(1);
        command_id
    }

    fn active_leases(&self) -> Vec<Lease> {
        let mut leases: Vec<Lease> = self
            .leases
            .values()
            .map(|stored| stored.lease.clone())
            .collect();
        leases.sort_by(|left, right| {
            left.acquired_at
                .cmp(&right.acquired_at)
                .then_with(|| left.lease_id.cmp(&right.lease_id))
        });
        leases
    }
}

fn fleet_lease_state() -> &'static Mutex<FleetLeaseState> {
    static STATE: OnceLock<Mutex<FleetLeaseState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(FleetLeaseState::default()))
}

fn with_fleet_lease_state<T>(
    trace_id: &str,
    f: impl FnOnce(&mut FleetLeaseState) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let mut state = fleet_lease_state().lock().map_err(|_| ApiError::Internal {
        detail: "fleet lease state lock poisoned".to_string(),
        trace_id: trace_id.to_string(),
    })?;
    f(&mut state)
}

fn normalize_required_field(
    value: &str,
    field_name: &str,
    trace_id: &str,
) -> Result<String, ApiError> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(ApiError::BadRequest {
            detail: format!("fleet field `{field_name}` must not be empty"),
            trace_id: trace_id.to_string(),
        });
    }
    Ok(normalized.to_string())
}

fn validate_coordination_targets(
    target_nodes: &[String],
    trace_id: &str,
) -> Result<Vec<String>, ApiError> {
    if target_nodes.is_empty() {
        return Err(ApiError::BadRequest {
            detail: "coordination requires at least one target node".to_string(),
            trace_id: trace_id.to_string(),
        });
    }

    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(target_nodes.len());
    for node_id in target_nodes {
        let normalized_node = normalize_required_field(node_id, "target_node", trace_id)?;
        if !seen.insert(normalized_node.clone()) {
            return Err(ApiError::BadRequest {
                detail: format!("duplicate target node `{normalized_node}` is not allowed"),
                trace_id: trace_id.to_string(),
            });
        }
        normalized.push(normalized_node);
    }

    Ok(normalized)
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
    trace: &TraceContext,
) -> Result<ApiResponse<Vec<Lease>>, ApiError> {
    with_fleet_lease_state(&trace.trace_id, |state| {
        state.sweep_expired(chrono::Utc::now());
        Ok(ApiResponse {
            ok: true,
            data: state.active_leases(),
            page: None,
        })
    })
}

/// Handle `POST /v1/fleet/leases`.
pub fn acquire_lease(
    identity: &AuthIdentity,
    trace: &TraceContext,
    request: &LeaseAcquireRequest,
) -> Result<ApiResponse<Lease>, ApiError> {
    let resource = normalize_required_field(&request.resource, "resource", &trace.trace_id)?;
    if request.ttl_seconds == 0 {
        return Err(ApiError::BadRequest {
            detail: "fleet lease ttl_seconds must be greater than zero".to_string(),
            trace_id: trace.trace_id.clone(),
        });
    }

    with_fleet_lease_state(&trace.trace_id, |state| {
        let now = chrono::Utc::now();
        state.sweep_expired(now);

        if state.leases.len() >= MAX_LEASES {
            return Err(ApiError::Conflict {
                detail: format!("fleet lease registry is at capacity ({MAX_LEASES})"),
                trace_id: trace.trace_id.clone(),
            });
        }

        if let Some(existing) = state
            .leases
            .values()
            .find(|stored| stored.lease.resource == resource)
        {
            return Err(ApiError::Conflict {
                detail: format!(
                    "resource `{}` is already leased by `{}` via `{}`",
                    resource, existing.lease.holder, existing.lease.lease_id
                ),
                trace_id: trace.trace_id.clone(),
            });
        }

        let lease_id = state.next_lease_id(&trace.trace_id);
        let expires_at = now + chrono::Duration::seconds(i64::from(request.ttl_seconds));
        let lease = Lease {
            lease_id: lease_id.clone(),
            holder: identity.principal.clone(),
            resource: resource.clone(),
            acquired_at: now.to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
            fencing_token: state.issue_fencing_token(),
        };

        state.leases.insert(
            lease_id,
            StoredLease {
                lease: lease.clone(),
                expires_at,
            },
        );

        Ok(ApiResponse {
            ok: true,
            data: lease,
            page: None,
        })
    })
}

/// Handle `DELETE /v1/fleet/leases/{lease_id}`.
pub fn release_lease(
    _identity: &AuthIdentity,
    trace: &TraceContext,
    lease_id: &str,
) -> Result<ApiResponse<bool>, ApiError> {
    let lease_id = normalize_required_field(lease_id, "lease_id", &trace.trace_id)?;
    with_fleet_lease_state(&trace.trace_id, |state| {
        state.sweep_expired(chrono::Utc::now());
        state
            .leases
            .remove(&lease_id)
            .ok_or_else(|| ApiError::NotFound {
                detail: format!("no active fleet lease found for `{lease_id}`"),
                trace_id: trace.trace_id.clone(),
            })?;

        Ok(ApiResponse {
            ok: true,
            data: true,
            page: None,
        })
    })
}

/// Handle `POST /v1/fleet/fence`.
pub fn execute_fence(
    _identity: &AuthIdentity,
    trace: &TraceContext,
    request: &FencingRequest,
) -> Result<ApiResponse<FencingResult>, ApiError> {
    let target_node =
        normalize_required_field(&request.target_node, "target_node", &trace.trace_id)?;
    let _reason = normalize_required_field(&request.reason, "reason", &trace.trace_id)?;

    with_fleet_lease_state(&trace.trace_id, |state| {
        let fencing_token = state.issue_fencing_token();
        let operation_id = format!(
            "fence-{}-{:04}",
            utf8_prefix(&trace.trace_id, 12),
            fencing_token
        );

        let result = FencingResult {
            operation_id,
            target_node: target_node.clone(),
            action: request.action,
            status: FencingStatus::Completed,
            fencing_token,
            executed_at: chrono::Utc::now().to_rfc3339(),
        };

        Ok(ApiResponse {
            ok: true,
            data: result,
            page: None,
        })
    })
}

/// Handle `POST /v1/fleet/coordinate`.
pub fn execute_coordination(
    _identity: &AuthIdentity,
    trace: &TraceContext,
    request: &CoordinationRequest,
) -> Result<ApiResponse<CoordinationResult>, ApiError> {
    let command_type =
        normalize_required_field(&request.command_type, "command_type", &trace.trace_id)?;
    let target_nodes = validate_coordination_targets(&request.target_nodes, &trace.trace_id)?;
    if request.timeout_seconds == 0 {
        return Err(ApiError::BadRequest {
            detail: "coordination timeout_seconds must be greater than zero".to_string(),
            trace_id: trace.trace_id.clone(),
        });
    }

    with_fleet_lease_state(&trace.trace_id, |state| {
        let command_id = state.next_coordination_id(&trace.trace_id);

        let result = CoordinationResult {
            command_id,
            command_type: command_type.clone(),
            participating_nodes: target_nodes.clone(),
            ack_count: u32::try_from(target_nodes.len()).unwrap_or(u32::MAX),
            total_nodes: u32::try_from(target_nodes.len()).unwrap_or(u32::MAX),
            status: CoordinationStatus::Acknowledged,
            issued_at: chrono::Utc::now().to_rfc3339(),
        };

        Ok(ApiResponse {
            ok: true,
            data: result,
            page: None,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::AuthMethod;
    use std::sync::{Mutex, MutexGuard, OnceLock};

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

    fn test_guard() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("test guard")
    }

    fn reset_fleet_lease_state() {
        let mut state = fleet_lease_state().lock().expect("state lock");
        *state = FleetLeaseState::default();
    }

    #[test]
    fn route_metadata_has_five_endpoints() {
        let _guard = test_guard();
        reset_fleet_lease_state();
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
        let _guard = test_guard();
        reset_fleet_lease_state();
        let routes = route_metadata();
        let fence = routes
            .iter()
            .find(|r| r.path.contains("fence"))
            .expect("should exist");
        assert_eq!(fence.auth_method, AuthMethod::MtlsClientCert);
    }

    #[test]
    fn coordinate_is_experimental() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let routes = route_metadata();
        let coord = routes
            .iter()
            .find(|r| r.path.contains("coordinate"))
            .expect("should exist");
        assert_eq!(coord.lifecycle, EndpointLifecycle::Experimental);
    }

    #[test]
    fn list_leases_returns_empty() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let result = list_leases(&identity, &trace).expect("list leases");
        assert!(result.ok);
        assert!(result.data.is_empty());
    }

    #[test]
    fn acquire_lease_returns_lease() {
        let _guard = test_guard();
        reset_fleet_lease_state();
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
        let _guard = test_guard();
        reset_fleet_lease_state();
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
        assert_eq!(result.data.lease_id, format!("lease-{expected}-0001"));
    }

    #[test]
    fn release_lease_succeeds() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = LeaseAcquireRequest {
            resource: "control-plane-lock".to_string(),
            ttl_seconds: 300,
        };
        let lease = acquire_lease(&identity, &trace, &request).expect("acquire");
        let result = release_lease(&identity, &trace, &lease.data.lease_id).expect("release");
        assert!(result.ok);
        assert!(result.data);
    }

    #[test]
    fn execute_fence_completes() {
        let _guard = test_guard();
        reset_fleet_lease_state();
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
        let _guard = test_guard();
        reset_fleet_lease_state();
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
        let _guard = test_guard();
        reset_fleet_lease_state();
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
        let _guard = test_guard();
        reset_fleet_lease_state();
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
        let _guard = test_guard();
        reset_fleet_lease_state();
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

    #[test]
    fn list_leases_returns_active_lease_after_acquire() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = LeaseAcquireRequest {
            resource: "control-plane-lock".to_string(),
            ttl_seconds: 300,
        };

        let acquired = acquire_lease(&identity, &trace, &request).expect("acquire");
        let listed = list_leases(&identity, &trace).expect("list");

        assert_eq!(listed.data.len(), 1);
        assert_eq!(listed.data[0].lease_id, acquired.data.lease_id);
        assert_eq!(listed.data[0].resource, "control-plane-lock");
    }

    #[test]
    fn release_lease_rejects_unknown_id() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();

        let err = release_lease(&identity, &trace, "lease-missing-0001").expect_err("missing");
        assert!(matches!(err, ApiError::NotFound { .. }));
    }

    #[test]
    fn acquire_lease_rejects_duplicate_active_resource() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = LeaseAcquireRequest {
            resource: "control-plane-lock".to_string(),
            ttl_seconds: 300,
        };

        acquire_lease(&identity, &trace, &request).expect("first");
        let err = acquire_lease(&identity, &trace, &request).expect_err("duplicate resource");
        assert!(matches!(err, ApiError::Conflict { .. }));
    }

    #[test]
    fn acquire_lease_rejects_zero_ttl() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = LeaseAcquireRequest {
            resource: "control-plane-lock".to_string(),
            ttl_seconds: 0,
        };

        let err = acquire_lease(&identity, &trace, &request).expect_err("zero ttl");
        assert!(matches!(err, ApiError::BadRequest { .. }));
    }

    #[test]
    fn acquire_lease_rejects_blank_resource() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = LeaseAcquireRequest {
            resource: "   ".to_string(),
            ttl_seconds: 300,
        };

        let err = acquire_lease(&identity, &trace, &request).expect_err("blank resource");
        assert!(matches!(err, ApiError::BadRequest { .. }));
    }

    #[test]
    fn release_lease_removes_active_lease() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = LeaseAcquireRequest {
            resource: "control-plane-lock".to_string(),
            ttl_seconds: 300,
        };

        let lease = acquire_lease(&identity, &trace, &request).expect("acquire");
        release_lease(&identity, &trace, &lease.data.lease_id).expect("release");
        let listed = list_leases(&identity, &trace).expect("list");
        assert!(listed.data.is_empty());
    }

    #[test]
    fn execute_fence_rejects_blank_target_node() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = FencingRequest {
            target_node: "   ".to_string(),
            action: FencingAction::Isolate,
            reason: "suspected compromise".to_string(),
        };

        let err = execute_fence(&identity, &trace, &request).expect_err("blank target");
        assert!(matches!(err, ApiError::BadRequest { .. }));
    }

    #[test]
    fn execute_fence_issues_unique_monotonic_tokens() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = FencingRequest {
            target_node: "node-2".to_string(),
            action: FencingAction::Isolate,
            reason: "suspected compromise".to_string(),
        };

        let first = execute_fence(&identity, &trace, &request).expect("first fence");
        let second = execute_fence(&identity, &trace, &request).expect("second fence");

        assert_ne!(first.data.operation_id, second.data.operation_id);
        assert!(second.data.fencing_token > first.data.fencing_token);
    }

    #[test]
    fn execute_coordination_rejects_blank_command_type() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "   ".to_string(),
            target_nodes: vec!["node-1".to_string()],
            timeout_seconds: 30,
        };

        let err = execute_coordination(&identity, &trace, &request).expect_err("blank command");
        assert!(matches!(err, ApiError::BadRequest { .. }));
    }

    #[test]
    fn execute_coordination_rejects_zero_timeout() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "policy-update".to_string(),
            target_nodes: vec!["node-1".to_string()],
            timeout_seconds: 0,
        };

        let err = execute_coordination(&identity, &trace, &request).expect_err("zero timeout");
        assert!(matches!(err, ApiError::BadRequest { .. }));
    }

    #[test]
    fn execute_coordination_rejects_blank_target_node() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "policy-update".to_string(),
            target_nodes: vec!["node-1".to_string(), "   ".to_string()],
            timeout_seconds: 30,
        };

        let err = execute_coordination(&identity, &trace, &request).expect_err("blank target");
        assert!(matches!(err, ApiError::BadRequest { .. }));
    }

    #[test]
    fn execute_coordination_issues_unique_command_ids_for_same_trace() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "policy-update".to_string(),
            target_nodes: vec!["node-1".to_string(), "node-2".to_string()],
            timeout_seconds: 30,
        };

        let first = execute_coordination(&identity, &trace, &request).expect("first command");
        let second = execute_coordination(&identity, &trace, &request).expect("second command");

        assert_ne!(first.data.command_id, second.data.command_id);
    }

    #[test]
    fn acquire_lease_rejects_padded_duplicate_resource() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let padded = LeaseAcquireRequest {
            resource: "  control-plane-lock  ".to_string(),
            ttl_seconds: 300,
        };
        let canonical = LeaseAcquireRequest {
            resource: "control-plane-lock".to_string(),
            ttl_seconds: 300,
        };

        let first = acquire_lease(&identity, &trace, &padded).expect("first lease");
        assert_eq!(first.data.resource, "control-plane-lock");

        let err = acquire_lease(&identity, &trace, &canonical)
            .expect_err("canonical duplicate must be rejected");
        assert!(matches!(err, ApiError::Conflict { .. }));
    }

    #[test]
    fn sweep_expired_removes_lease_at_exact_expiry_boundary() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let now = chrono::Utc::now();
        let mut state = FleetLeaseState::default();
        state.leases.insert(
            "lease-boundary-0001".to_string(),
            StoredLease {
                lease: Lease {
                    lease_id: "lease-boundary-0001".to_string(),
                    holder: "fleet-admin-1".to_string(),
                    resource: "control-plane-lock".to_string(),
                    acquired_at: now.to_rfc3339(),
                    expires_at: now.to_rfc3339(),
                    fencing_token: 1,
                },
                expires_at: now,
            },
        );

        state.sweep_expired(now);

        assert!(
            state.leases.is_empty(),
            "lease expiring exactly at now must not remain active"
        );
    }

    #[test]
    fn release_lease_rejects_expired_lease_after_sweep() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let expired_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        {
            let mut state = fleet_lease_state().lock().expect("state lock");
            state.leases.insert(
                "lease-expired-0001".to_string(),
                StoredLease {
                    lease: Lease {
                        lease_id: "lease-expired-0001".to_string(),
                        holder: "fleet-admin-1".to_string(),
                        resource: "control-plane-lock".to_string(),
                        acquired_at: expired_at.to_rfc3339(),
                        expires_at: expired_at.to_rfc3339(),
                        fencing_token: 1,
                    },
                    expires_at: expired_at,
                },
            );
        }

        let err = release_lease(&identity, &trace, "lease-expired-0001")
            .expect_err("expired lease should be swept before release");

        assert!(matches!(err, ApiError::NotFound { .. }));
    }

    #[test]
    fn fleet_control_routes_do_not_allow_anonymous_access() {
        for route in route_metadata() {
            assert_ne!(
                route.auth_method,
                AuthMethod::None,
                "{} must not bypass fleet-control auth",
                route.path
            );
            assert!(
                route
                    .policy_hook
                    .required_roles
                    .contains(&"fleet-admin".to_string())
                    || route
                        .policy_hook
                        .required_roles
                        .contains(&"operator".to_string()),
                "{} must require an operator or fleet-admin role",
                route.path
            );
        }
    }

    #[test]
    fn lease_request_deserialize_rejects_missing_resource() {
        let raw = serde_json::json!({
            "ttl_seconds": 30_u32
        });

        let result: Result<LeaseAcquireRequest, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "resource is required for lease acquisition"
        );
    }

    #[test]
    fn lease_request_deserialize_rejects_ttl_overflow() {
        let raw = serde_json::json!({
            "resource": "control-plane-lock",
            "ttl_seconds": 4_294_967_296_u64
        });

        let result: Result<LeaseAcquireRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "u32 ttl overflow must fail closed");
    }

    #[test]
    fn fencing_request_deserialize_rejects_unknown_action() {
        let raw = serde_json::json!({
            "target_node": "node-2",
            "action": "PowerCycle",
            "reason": "unsupported action should fail closed"
        });

        let result: Result<FencingRequest, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "unknown fencing action must not deserialize"
        );
    }

    #[test]
    fn coordination_request_deserialize_rejects_target_type_confusion() {
        let raw = serde_json::json!({
            "command_type": "policy-update",
            "target_nodes": "node-1",
            "timeout_seconds": 30_u32
        });

        let result: Result<CoordinationRequest, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "target_nodes must be an array, not a scalar"
        );
    }

    #[test]
    fn release_lease_rejects_blank_lease_id_as_bad_request() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();

        let err = release_lease(&identity, &trace, " \t\n ").expect_err("blank lease id");

        assert!(matches!(
            err,
            ApiError::BadRequest {
                ref detail,
                ref trace_id
            } if detail.contains("lease_id") && trace_id == "test-trace-fleet-001"
        ));
    }

    #[test]
    fn release_lease_rejects_trimmed_unknown_lease_id_as_not_found() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();

        let err = release_lease(&identity, &trace, "  lease-missing-0002  ")
            .expect_err("unknown trimmed lease id");

        assert!(matches!(
            err,
            ApiError::NotFound { ref detail, .. }
                if detail.contains("lease-missing-0002")
                    && !detail.contains("  lease-missing-0002  ")
        ));
    }

    #[test]
    fn execute_fence_rejects_blank_reason() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = FencingRequest {
            target_node: "node-2".to_string(),
            action: FencingAction::Drain,
            reason: "\n\t ".to_string(),
        };

        let err = execute_fence(&identity, &trace, &request).expect_err("blank reason");

        assert!(matches!(
            err,
            ApiError::BadRequest {
                ref detail,
                ref trace_id
            } if detail.contains("reason") && trace_id == "test-trace-fleet-001"
        ));
    }

    #[test]
    fn execute_coordination_rejects_padded_duplicate_target_nodes() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "policy-update".to_string(),
            target_nodes: vec![" node-1 ".to_string(), "node-1".to_string()],
            timeout_seconds: 30,
        };

        let err =
            execute_coordination(&identity, &trace, &request).expect_err("padded duplicate target");

        assert!(matches!(
            err,
            ApiError::BadRequest { ref detail, .. } if detail.contains("duplicate target node `node-1`")
        ));
    }

    #[test]
    fn lease_request_deserialize_rejects_resource_type_confusion() {
        let raw = serde_json::json!({
            "resource": 42_u32,
            "ttl_seconds": 30_u32
        });

        let result: Result<LeaseAcquireRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "resource must be a string");
    }

    #[test]
    fn fencing_request_deserialize_rejects_missing_reason() {
        let raw = serde_json::json!({
            "target_node": "node-2",
            "action": "Drain"
        });

        let result: Result<FencingRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "fencing reason is required");
    }

    #[test]
    fn coordination_request_deserialize_rejects_missing_timeout() {
        let raw = serde_json::json!({
            "command_type": "policy-update",
            "target_nodes": ["node-1"]
        });

        let result: Result<CoordinationRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "timeout_seconds is required");
    }

    #[test]
    fn coordination_request_deserialize_rejects_timeout_type_confusion() {
        let raw = serde_json::json!({
            "command_type": "policy-update",
            "target_nodes": ["node-1"],
            "timeout_seconds": "30"
        });

        let result: Result<CoordinationRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "timeout_seconds must be numeric");
    }

    #[test]
    fn lease_deserialize_rejects_missing_fencing_token() {
        let raw = serde_json::json!({
            "lease_id": "lease-schema-0001",
            "holder": "fleet-admin-1",
            "resource": "control-plane-lock",
            "acquired_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T00:01:00Z"
        });

        let result = serde_json::from_value::<Lease>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn lease_deserialize_rejects_negative_fencing_token() {
        let raw = serde_json::json!({
            "lease_id": "lease-schema-0002",
            "holder": "fleet-admin-1",
            "resource": "control-plane-lock",
            "acquired_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T00:01:00Z",
            "fencing_token": -1
        });

        let result = serde_json::from_value::<Lease>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn fencing_result_deserialize_rejects_unknown_status() {
        let raw = serde_json::json!({
            "operation_id": "fence-schema-0001",
            "target_node": "node-2",
            "action": "Drain",
            "status": "Bypassed",
            "fencing_token": 1,
            "executed_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<FencingResult>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn fencing_result_deserialize_rejects_string_fencing_token() {
        let raw = serde_json::json!({
            "operation_id": "fence-schema-0002",
            "target_node": "node-2",
            "action": "Drain",
            "status": "Completed",
            "fencing_token": "1",
            "executed_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<FencingResult>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn coordination_result_deserialize_rejects_missing_participating_nodes() {
        let raw = serde_json::json!({
            "command_id": "coord-schema-0001",
            "command_type": "policy-update",
            "ack_count": 1,
            "total_nodes": 1,
            "status": "Acknowledged",
            "issued_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<CoordinationResult>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn coordination_result_deserialize_rejects_negative_ack_count() {
        let raw = serde_json::json!({
            "command_id": "coord-schema-0002",
            "command_type": "policy-update",
            "participating_nodes": ["node-1"],
            "ack_count": -1,
            "total_nodes": 1,
            "status": "Partial",
            "issued_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<CoordinationResult>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn coordination_result_deserialize_rejects_unknown_status() {
        let raw = serde_json::json!({
            "command_id": "coord-schema-0003",
            "command_type": "policy-update",
            "participating_nodes": ["node-1"],
            "ack_count": 1,
            "total_nodes": 1,
            "status": "SplitBrain",
            "issued_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<CoordinationResult>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn acquire_lease_zero_ttl_does_not_allocate_sequence_or_lease() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = LeaseAcquireRequest {
            resource: "control-plane-lock".to_string(),
            ttl_seconds: 0,
        };

        let err = acquire_lease(&identity, &trace, &request).expect_err("zero ttl");

        assert!(matches!(err, ApiError::BadRequest { .. }));
        let state = fleet_lease_state().lock().expect("state lock");
        assert!(state.leases.is_empty());
        assert_eq!(state.next_lease_seq, 1);
        assert_eq!(state.next_fencing_seq, 1);
    }

    #[test]
    fn acquire_lease_blank_resource_does_not_allocate_sequence_or_lease() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = LeaseAcquireRequest {
            resource: "\n\t ".to_string(),
            ttl_seconds: 300,
        };

        let err = acquire_lease(&identity, &trace, &request).expect_err("blank resource");

        assert!(matches!(err, ApiError::BadRequest { .. }));
        let state = fleet_lease_state().lock().expect("state lock");
        assert!(state.leases.is_empty());
        assert_eq!(state.next_lease_seq, 1);
        assert_eq!(state.next_fencing_seq, 1);
    }

    #[test]
    fn acquire_lease_duplicate_resource_does_not_allocate_second_sequence() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = LeaseAcquireRequest {
            resource: "control-plane-lock".to_string(),
            ttl_seconds: 300,
        };
        acquire_lease(&identity, &trace, &request).expect("first lease");

        let err = acquire_lease(&identity, &trace, &request).expect_err("duplicate resource");

        assert!(matches!(err, ApiError::Conflict { .. }));
        let state = fleet_lease_state().lock().expect("state lock");
        assert_eq!(state.leases.len(), 1);
        assert_eq!(state.next_lease_seq, 2);
        assert_eq!(state.next_fencing_seq, 2);
    }

    #[test]
    fn release_lease_blank_id_does_not_sweep_or_remove_existing_state() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let expired_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        {
            let mut state = fleet_lease_state().lock().expect("state lock");
            state.leases.insert(
                "lease-expired-blank-release".to_string(),
                StoredLease {
                    lease: Lease {
                        lease_id: "lease-expired-blank-release".to_string(),
                        holder: "fleet-admin-1".to_string(),
                        resource: "control-plane-lock".to_string(),
                        acquired_at: expired_at.to_rfc3339(),
                        expires_at: expired_at.to_rfc3339(),
                        fencing_token: 1,
                    },
                    expires_at: expired_at,
                },
            );
        }
        let identity = admin_identity();
        let trace = test_trace();

        let err = release_lease(&identity, &trace, "  ").expect_err("blank lease id");

        assert!(matches!(err, ApiError::BadRequest { .. }));
        let state = fleet_lease_state().lock().expect("state lock");
        assert!(state.leases.contains_key("lease-expired-blank-release"));
    }

    #[test]
    fn execute_fence_blank_target_does_not_issue_fencing_token() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = FencingRequest {
            target_node: " ".to_string(),
            action: FencingAction::Drain,
            reason: "maintenance".to_string(),
        };

        let err = execute_fence(&identity, &trace, &request).expect_err("blank target");

        assert!(matches!(err, ApiError::BadRequest { .. }));
        let state = fleet_lease_state().lock().expect("state lock");
        assert_eq!(state.next_fencing_seq, 1);
    }

    #[test]
    fn execute_fence_blank_reason_does_not_issue_fencing_token() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = FencingRequest {
            target_node: "node-2".to_string(),
            action: FencingAction::Isolate,
            reason: "\t\n".to_string(),
        };

        let err = execute_fence(&identity, &trace, &request).expect_err("blank reason");

        assert!(matches!(err, ApiError::BadRequest { .. }));
        let state = fleet_lease_state().lock().expect("state lock");
        assert_eq!(state.next_fencing_seq, 1);
    }

    #[test]
    fn execute_coordination_empty_targets_does_not_allocate_command_id() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "policy-update".to_string(),
            target_nodes: Vec::new(),
            timeout_seconds: 30,
        };

        let err = execute_coordination(&identity, &trace, &request).expect_err("empty targets");

        assert!(matches!(err, ApiError::BadRequest { .. }));
        let state = fleet_lease_state().lock().expect("state lock");
        assert_eq!(state.next_coordination_seq, 1);
    }

    #[test]
    fn execute_coordination_duplicate_targets_do_not_allocate_command_id() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "policy-update".to_string(),
            target_nodes: vec![" node-1 ".to_string(), "node-1".to_string()],
            timeout_seconds: 30,
        };

        let err = execute_coordination(&identity, &trace, &request).expect_err("duplicate");

        assert!(matches!(err, ApiError::BadRequest { .. }));
        let state = fleet_lease_state().lock().expect("state lock");
        assert_eq!(state.next_coordination_seq, 1);
    }
}
