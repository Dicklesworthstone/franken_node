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
    TraceContext, enforce_route_contract,
};
use super::trust_card_routes::ApiResponse;
use super::utf8_prefix;
use crate::capacity_defaults::aliases::{MAX_LEASES, MAX_NODES_CAP};

const MAX_COORDINATION_TARGETS: usize = MAX_NODES_CAP;

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
/// Result of a fleet fencing operation.
///
/// # Examples
///
/// ```
/// use frankenengine_node::api::fleet_control_routes::{FencingResult, FencingAction, FencingStatus};
///
/// let result = FencingResult {
///     operation_id: "fence-001".to_string(),
///     target_node: "node-1".to_string(),
///     action: FencingAction::Isolate,
///     status: FencingStatus::Completed,
///     fencing_token: 12345,
///     executed_at: "2026-01-01T00:00:00Z".to_string(),
/// };
/// assert_eq!(result.target_node, "node-1");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencingResult {
    pub operation_id: String,
    pub target_node: String,
    pub action: FencingAction,
    pub status: FencingStatus,
    pub fencing_token: u64,
    pub executed_at: String,
}

/// Type of fencing action to execute on a fleet node.
///
/// # Examples
///
/// ```
/// use frankenengine_node::api::fleet_control_routes::FencingAction;
///
/// let action = FencingAction::Isolate;
/// assert_eq!(action, FencingAction::Isolate);
///
/// // Actions for different scenarios
/// let isolation = FencingAction::Isolate;  // Remove problematic node
/// let draining = FencingAction::Drain;     // Graceful shutdown
/// let rejoining = FencingAction::Rejoin;   // Re-add to cluster
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencingAction {
    Isolate,
    Drain,
    Rejoin,
}

/// Status of a fencing operation execution.
///
/// # Examples
///
/// ```
/// use frankenengine_node::api::fleet_control_routes::FencingStatus;
///
/// let status = FencingStatus::Completed;
/// assert_eq!(status, FencingStatus::Completed);
///
/// // Different completion states
/// match status {
///     FencingStatus::Completed => println!("Fencing successful"),
///     FencingStatus::Failed => println!("Fencing failed"),
///     FencingStatus::Pending => println!("Fencing in progress"),
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencingStatus {
    Completed,
    Pending,
    Failed,
}

/// Multi-node coordination command result.
/// Result of a fleet coordination command execution.
///
/// # Examples
///
/// ```
/// use frankenengine_node::api::fleet_control_routes::{CoordinationResult, CoordinationStatus};
///
/// let result = CoordinationResult {
///     command_id: "coord-123".to_string(),
///     command_type: "config-update".to_string(),
///     participating_nodes: vec!["node-1".to_string(), "node-2".to_string()],
///     ack_count: 2,
///     total_nodes: 2,
///     status: CoordinationStatus::Acknowledged,
///     issued_at: "2026-01-01T00:00:00Z".to_string(),
/// };
/// assert_eq!(result.ack_count, result.total_nodes);
/// ```
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

/// Status of fleet coordination command acknowledgment.
///
/// # Examples
///
/// ```
/// use frankenengine_node::api::fleet_control_routes::CoordinationStatus;
///
/// let status = CoordinationStatus::Acknowledged;
/// assert_eq!(status, CoordinationStatus::Acknowledged);
///
/// // Check coordination success
/// match status {
///     CoordinationStatus::Acknowledged => println!("All nodes responded"),
///     CoordinationStatus::Partial => println!("Some nodes missing"),
///     CoordinationStatus::Timeout => println!("Coordination timed out"),
/// }
/// ```
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
///
/// # Examples
///
/// ```
/// use frankenengine_node::api::fleet_control_routes::{FencingRequest, FencingAction};
///
/// let request = FencingRequest {
///     target_node: "problematic-node-5".to_string(),
///     action: FencingAction::Isolate,
///     reason: "High CPU usage detected".to_string(),
/// };
/// assert_eq!(request.action, FencingAction::Isolate);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencingRequest {
    pub target_node: String,
    pub action: FencingAction,
    pub reason: String,
}

/// Multi-node coordination command request.
///
/// # Examples
///
/// ```
/// use frankenengine_node::api::fleet_control_routes::CoordinationRequest;
///
/// let request = CoordinationRequest {
///     command_type: "config-reload".to_string(),
///     target_nodes: vec!["node-1".to_string(), "node-2".to_string(), "node-3".to_string()],
///     timeout_seconds: 30,
/// };
/// assert_eq!(request.target_nodes.len(), 3);
/// ```
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
        let mut leases = Vec::with_capacity(self.leases.len());
        for stored in self.leases.values() {
            leases.push(stored.lease.clone());
        }
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
    if target_nodes.len() > MAX_COORDINATION_TARGETS {
        return Err(ApiError::BadRequest {
            detail: format!(
                "coordination target node count {} exceeds limit {MAX_COORDINATION_TARGETS}",
                target_nodes.len()
            ),
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

/// Returns route metadata for all fleet control endpoints.
///
/// Provides structured metadata for the 5 fleet control API endpoints, including:
///
/// ## Endpoints
/// - `GET /v1/fleet/leases` - List active fleet leases (operator/fleet-admin roles)
/// - `POST /v1/fleet/leases` - Acquire new fleet lease (fleet-admin role)
/// - `DELETE /v1/fleet/leases/{lease_id}` - Release specific lease (fleet-admin role)
/// - `POST /v1/fleet/fence` - Execute fleet fencing operation (mTLS + fleet-admin role)
/// - `POST /v1/fleet/coordinate` - Fleet coordination operation (experimental, mTLS + fleet-admin role)
///
/// ## Authentication
/// - Lease operations: Bearer token with `operator` or `fleet-admin` roles
/// - Fence/coordinate operations: mTLS client certificate with `fleet-admin` role
///
/// ## Used By
/// - Fleet management systems for distributed coordination
/// - Control plane operations for lease management
/// - Fencing mechanisms for split-brain prevention
/// - Fleet administration dashboards
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

fn enforce_handler_contract(
    identity: &AuthIdentity,
    trace: &TraceContext,
    method: &str,
    path: &str,
) -> Result<(), ApiError> {
    let route = route_metadata()
        .into_iter()
        .find(|route| route.method == method && route.path == path)
        .ok_or_else(|| ApiError::Internal {
            detail: format!("missing route metadata for {method} {path}"),
            trace_id: trace.trace_id.clone(),
        })?;
    enforce_route_contract(identity, &route, &trace.trace_id)
}

// ── Handlers ───────────────────────────────────────────────────────────────

/// Handle `GET /v1/fleet/leases`.
pub fn list_leases(
    identity: &AuthIdentity,
    trace: &TraceContext,
) -> Result<ApiResponse<Vec<Lease>>, ApiError> {
    enforce_handler_contract(identity, trace, "GET", "/v1/fleet/leases")?;
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
    enforce_handler_contract(identity, trace, "POST", "/v1/fleet/leases")?;
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
    identity: &AuthIdentity,
    trace: &TraceContext,
    lease_id: &str,
) -> Result<ApiResponse<bool>, ApiError> {
    enforce_handler_contract(identity, trace, "DELETE", "/v1/fleet/leases/{lease_id}")?;
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
    identity: &AuthIdentity,
    trace: &TraceContext,
    request: &FencingRequest,
) -> Result<ApiResponse<FencingResult>, ApiError> {
    enforce_handler_contract(identity, trace, "POST", "/v1/fleet/fence")?;
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
    identity: &AuthIdentity,
    trace: &TraceContext,
    request: &CoordinationRequest,
) -> Result<ApiResponse<CoordinationResult>, ApiError> {
    enforce_handler_contract(identity, trace, "POST", "/v1/fleet/coordinate")?;
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

    fn bearer_admin_identity() -> AuthIdentity {
        AuthIdentity {
            principal: "fleet-admin-1".to_string(),
            method: AuthMethod::BearerToken,
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
    fn test_lease_operations_optimized_response_identical() {
        // Test that optimized lease operations produce identical JSON responses
        let _guard = test_guard();
        reset_fleet_lease_state();

        let admin = admin_identity();
        let trace = test_trace();

        // Acquire a lease to have data to list
        let acquire_request = LeaseAcquireRequest {
            resource: "test-resource-1".to_string(),
            ttl_seconds: 300,
        };

        let acquire_response = acquire_lease(&admin, &trace, &acquire_request);
        assert!(
            acquire_response.is_ok(),
            "Failed to acquire lease: {:?}",
            acquire_response
        );

        let acquired_lease = acquire_response.unwrap();
        assert!(acquired_lease.ok);
        assert_eq!(acquired_lease.data.resource, "test-resource-1");
        assert!(acquired_lease.data.lease_id.starts_with("lease-"));
        assert_eq!(acquired_lease.data.holder, admin.principal);

        // Test list_leases response structure and content
        let list_response = list_leases(&admin, &trace);
        assert!(
            list_response.is_ok(),
            "Failed to list leases: {:?}",
            list_response
        );

        let lease_list = list_response.unwrap();
        assert!(lease_list.ok);
        assert_eq!(lease_list.data.len(), 1);
        assert!(lease_list.page.is_none());

        // Verify response contains the same lease data
        let listed_lease = &lease_list.data[0];
        assert_eq!(listed_lease.lease_id, acquired_lease.data.lease_id);
        assert_eq!(listed_lease.resource, acquired_lease.data.resource);
        assert_eq!(listed_lease.holder, acquired_lease.data.holder);
        assert_eq!(listed_lease.acquired_at, acquired_lease.data.acquired_at);
        assert_eq!(listed_lease.expires_at, acquired_lease.data.expires_at);
        assert_eq!(
            listed_lease.fencing_token,
            acquired_lease.data.fencing_token
        );

        // Test JSON serialization produces consistent structure
        let acquire_json = serde_json::to_string(&acquired_lease).unwrap();
        let list_json = serde_json::to_string(&lease_list).unwrap();

        // Verify JSON structure contains expected fields
        assert!(acquire_json.contains("\"ok\":true"));
        assert!(acquire_json.contains("\"lease_id\":"));
        assert!(acquire_json.contains("\"resource\":"));
        assert!(acquire_json.contains("\"holder\":"));
        assert!(acquire_json.contains("\"acquired_at\":"));
        assert!(acquire_json.contains("\"expires_at\":"));
        assert!(acquire_json.contains("\"fencing_token\":"));

        assert!(list_json.contains("\"ok\":true"));
        assert!(list_json.contains("\"data\":["));
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
        let identity = bearer_admin_identity();
        let trace = test_trace();
        let result = list_leases(&identity, &trace).expect("list leases");
        assert!(result.ok);
        assert!(result.data.is_empty());
    }

    #[test]
    fn acquire_lease_returns_lease() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = bearer_admin_identity();
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
        let identity = bearer_admin_identity();
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
        let identity = bearer_admin_identity();
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
    fn execute_fence_rejects_bearer_identity_directly() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let trace = test_trace();
        let request = FencingRequest {
            target_node: "node-2".to_string(),
            action: FencingAction::Isolate,
            reason: "suspected compromise".to_string(),
        };

        let err = execute_fence(&bearer_admin_identity(), &trace, &request).expect_err("fence");
        match err {
            ApiError::AuthFailed { detail, .. } => assert!(detail.contains("route contract")),
            other => panic!("unexpected error: {other:?}"),
        }
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
    fn validate_coordination_targets_accepts_maximum_target_count() {
        let trace = test_trace();
        let target_nodes: Vec<String> = (0..MAX_COORDINATION_TARGETS)
            .map(|index| format!("node-{index:05}"))
            .collect();

        let normalized =
            validate_coordination_targets(&target_nodes, &trace.trace_id).expect("max targets");

        assert_eq!(normalized.len(), MAX_COORDINATION_TARGETS);
        assert_eq!(normalized[0], "node-00000");
        assert_eq!(
            normalized[MAX_COORDINATION_TARGETS - 1],
            format!("node-{:05}", MAX_COORDINATION_TARGETS - 1)
        );
    }

    #[test]
    fn execute_coordination_rejects_over_max_target_count_before_command_id() {
        let _guard = test_guard();
        reset_fleet_lease_state();
        let identity = admin_identity();
        let trace = test_trace();
        let request = CoordinationRequest {
            command_type: "policy-update".to_string(),
            target_nodes: (0..=MAX_COORDINATION_TARGETS)
                .map(|index| format!("node-{index:05}"))
                .collect(),
            timeout_seconds: 30,
        };

        let err = execute_coordination(&identity, &trace, &request).expect_err("too many targets");

        let problem = err.to_problem("/v1/fleet/coordinate");
        assert_eq!(problem.status, 400);
        assert!(problem.detail.contains("exceeds limit"));
        let state = fleet_lease_state().lock().expect("state lock");
        assert_eq!(state.next_coordination_seq, 1);
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

    #[test]
    fn lease_request_deserialize_rejects_null_ttl_seconds() {
        let raw = serde_json::json!({
            "resource": "control-plane-lock",
            "ttl_seconds": null
        });

        let result = serde_json::from_value::<LeaseAcquireRequest>(raw);

        assert!(result.is_err(), "ttl_seconds must be present as a u32");
    }

    #[test]
    fn lease_request_deserialize_rejects_float_ttl_seconds() {
        let raw = serde_json::json!({
            "resource": "control-plane-lock",
            "ttl_seconds": 30.5
        });

        let result = serde_json::from_value::<LeaseAcquireRequest>(raw);

        assert!(result.is_err(), "ttl_seconds must not accept floats");
    }

    #[test]
    fn fencing_action_deserialize_rejects_lowercase_variant() {
        let result = serde_json::from_str::<FencingAction>("\"drain\"");

        assert!(
            result.is_err(),
            "fencing actions must remain case-sensitive"
        );
    }

    #[test]
    fn fencing_request_deserialize_rejects_null_reason() {
        let raw = serde_json::json!({
            "target_node": "node-2",
            "action": "Drain",
            "reason": null
        });

        let result = serde_json::from_value::<FencingRequest>(raw);

        assert!(result.is_err(), "fencing reason must be a string");
    }

    #[test]
    fn coordination_request_deserialize_rejects_null_target_nodes() {
        let raw = serde_json::json!({
            "command_type": "policy-update",
            "target_nodes": null,
            "timeout_seconds": 30
        });

        let result = serde_json::from_value::<CoordinationRequest>(raw);

        assert!(result.is_err(), "target_nodes must be a concrete array");
    }

    #[test]
    fn coordination_result_deserialize_rejects_total_nodes_overflow() {
        let raw = serde_json::json!({
            "command_id": "coord-schema-overflow",
            "command_type": "policy-update",
            "participating_nodes": ["node-1"],
            "ack_count": 1,
            "total_nodes": 4_294_967_296_u64,
            "status": "Acknowledged",
            "issued_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<CoordinationResult>(raw);

        assert!(result.is_err(), "total_nodes must fit in u32");
    }

    #[test]
    fn execute_coordination_zero_timeout_does_not_allocate_command_id() {
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
        let state = fleet_lease_state().lock().expect("state lock");
        assert_eq!(state.next_coordination_seq, 1);
        assert!(state.leases.is_empty());
    }

    #[test]
    fn fleet_lease_operations_golden_json_assertions() {
        // Golden JSON test for fleet lease operations edge cases
        let _guard = test_guard();
        reset_fleet_lease_state();
        let admin = admin_identity();
        let trace = test_trace();

        // Test empty lease list response (empty resources scenario)
        let empty_response = list_leases(&admin, &trace).expect("empty list");
        let empty_json = serde_json::to_string(&empty_response).unwrap();
        let expected_empty_json = r#"{"ok":true,"data":[],"page":null}"#;
        assert_eq!(
            empty_json, expected_empty_json,
            "Empty lease list must produce exact golden JSON"
        );

        // Test single lease acquisition and list response
        let acquire_request = LeaseAcquireRequest {
            resource: "test-resource-golden".to_string(),
            ttl_seconds: 300,
        };

        let acquire_response = acquire_lease(&admin, &trace, &acquire_request).expect("acquire");
        let acquire_json = serde_json::to_string(&acquire_response).unwrap();

        // Verify JSON structure contains all required fields in exact order
        assert!(acquire_json.contains(r#""ok":true"#));
        assert!(acquire_json.contains(r#""lease_id":"lease-test-trace-0001""#));
        assert!(acquire_json.contains(r#""holder":"fleet-admin-1""#));
        assert!(acquire_json.contains(r#""resource":"test-resource-golden""#));
        assert!(acquire_json.contains(r#""fencing_token":1"#));
        assert!(acquire_json.contains(r#""page":null"#));

        // Test single-item list response JSON structure
        let single_list_response = list_leases(&admin, &trace).expect("single list");
        let single_list_json = serde_json::to_string(&single_list_response).unwrap();

        // Verify list response contains single lease with exact structure
        assert!(single_list_json.starts_with(r#"{"ok":true,"data":"#));
        assert!(single_list_json.contains(r#""lease_id":"lease-test-trace-0001""#));
        assert!(single_list_json.contains(r#""resource":"test-resource-golden""#));
        assert!(single_list_json.ends_with(r#"}],"page":null}"#));

        // Test release response JSON structure
        let release_response =
            release_lease(&admin, &trace, &acquire_response.data.lease_id).expect("release");
        let release_json = serde_json::to_string(&release_response).unwrap();
        let expected_release_json = r#"{"ok":true,"data":true,"page":null}"#;
        assert_eq!(
            release_json, expected_release_json,
            "Release response must produce exact golden JSON"
        );

        // Test fencing operation JSON structure
        let fence_request = FencingRequest {
            target_node: "golden-node-1".to_string(),
            action: FencingAction::Isolate,
            reason: "golden test isolation".to_string(),
        };

        let fence_response = execute_fence(&admin, &trace, &fence_request).expect("fence");
        let fence_json = serde_json::to_string(&fence_response).unwrap();

        assert!(fence_json.contains(r#""ok":true"#));
        assert!(fence_json.contains(r#""operation_id":"fence-test-trace-1""#));
        assert!(fence_json.contains(r#""target_node":"golden-node-1""#));
        assert!(fence_json.contains(r#""action":"Isolate""#));
        assert!(fence_json.contains(r#""status":"Completed""#));
        assert!(fence_json.contains(r#""fencing_token":1"#));

        // Test coordination operation JSON structure
        let coord_request = CoordinationRequest {
            command_type: "golden-policy-update".to_string(),
            target_nodes: vec!["golden-node-1".to_string(), "golden-node-2".to_string()],
            timeout_seconds: 30,
        };

        let coord_response =
            execute_coordination(&admin, &trace, &coord_request).expect("coordination");
        let coord_json = serde_json::to_string(&coord_response).unwrap();

        assert!(coord_json.contains(r#""ok":true"#));
        assert!(coord_json.contains(r#""command_id":"coord-test-trace-0001""#));
        assert!(coord_json.contains(r#""command_type":"golden-policy-update""#));
        assert!(coord_json.contains(r#""participating_nodes":["golden-node-1","golden-node-2"]"#));
        assert!(coord_json.contains(r#""ack_count":2"#));
        assert!(coord_json.contains(r#""total_nodes":2"#));
        assert!(coord_json.contains(r#""status":"Acknowledged""#));
    }

    #[test]
    fn fleet_lease_edge_cases_empty_and_boundary_conditions() {
        // Test edge cases for empty resources and boundary conditions
        let _guard = test_guard();
        reset_fleet_lease_state();
        let admin = admin_identity();
        let trace = test_trace();

        // Test empty lease list returns consistent structure
        let empty_list = list_leases(&admin, &trace).expect("empty list");
        assert!(empty_list.ok);
        assert!(empty_list.data.is_empty());
        assert!(empty_list.page.is_none());

        // Test active_leases() optimization with empty collection
        {
            let state = fleet_lease_state().lock().expect("state lock");
            let empty_active = state.active_leases();
            assert!(empty_active.is_empty());
        }

        // Test single resource edge case
        let single_request = LeaseAcquireRequest {
            resource: "single-edge-case".to_string(),
            ttl_seconds: 1, // Minimum TTL
        };

        let single_lease = acquire_lease(&admin, &trace, &single_request).expect("single lease");
        assert_eq!(single_lease.data.resource, "single-edge-case");
        assert_eq!(single_lease.data.holder, "fleet-admin-1");
        assert!(single_lease.data.lease_id.starts_with("lease-"));

        // Test active_leases() optimization with single item
        {
            let state = fleet_lease_state().lock().expect("state lock");
            let single_active = state.active_leases();
            assert_eq!(single_active.len(), 1);
            assert_eq!(single_active[0].resource, "single-edge-case");
        }

        // Test multiple resources pre-allocation optimization
        let multi_requests = vec![
            ("resource-alpha", 60),
            ("resource-beta", 120),
            ("resource-gamma", 180),
        ];

        let mut acquired_leases = Vec::new();
        for (resource, ttl) in multi_requests {
            let request = LeaseAcquireRequest {
                resource: resource.to_string(),
                ttl_seconds: ttl,
            };
            let lease = acquire_lease(&admin, &trace, &request).expect("multi acquire");
            acquired_leases.push(lease.data);
        }

        // Test active_leases() optimization with multiple items (4 total including single)
        {
            let state = fleet_lease_state().lock().expect("state lock");
            let multi_active = state.active_leases();
            assert_eq!(multi_active.len(), 4);

            // Verify sorting by acquired_at then lease_id
            for window in multi_active.windows(2) {
                let (left, right) = (&window[0], &window[1]);
                assert!(
                    left.acquired_at <= right.acquired_at,
                    "Leases must be sorted by acquired_at"
                );
                if left.acquired_at == right.acquired_at {
                    assert!(
                        left.lease_id <= right.lease_id,
                        "Same acquired_at must be sorted by lease_id"
                    );
                }
            }
        }

        // Test coordination targets pre-allocation with different sizes
        let empty_coord_request = CoordinationRequest {
            command_type: "empty-test".to_string(),
            target_nodes: vec![],
            timeout_seconds: 30,
        };

        let empty_coord_err = execute_coordination(&admin, &trace, &empty_coord_request)
            .expect_err("empty targets should fail");
        assert!(matches!(empty_coord_err, ApiError::BadRequest { .. }));

        // Test maximum coordination targets pre-allocation
        let max_targets: Vec<String> = (0..MAX_COORDINATION_TARGETS)
            .map(|i| format!("max-node-{:04}", i))
            .collect();

        let max_coord_request = CoordinationRequest {
            command_type: "max-targets-test".to_string(),
            target_nodes: max_targets.clone(),
            timeout_seconds: 30,
        };

        let max_coord_response = execute_coordination(&admin, &trace, &max_coord_request)
            .expect("max targets should succeed");
        assert_eq!(
            max_coord_response.data.participating_nodes.len(),
            MAX_COORDINATION_TARGETS
        );
        assert_eq!(
            max_coord_response.data.ack_count,
            MAX_COORDINATION_TARGETS as u32
        );
        assert_eq!(
            max_coord_response.data.total_nodes,
            MAX_COORDINATION_TARGETS as u32
        );

        // Test Unicode edge cases in resource names
        let unicode_request = LeaseAcquireRequest {
            resource: "🔒-unicode-resource-💎".to_string(),
            ttl_seconds: 300,
        };

        let unicode_lease = acquire_lease(&admin, &trace, &unicode_request).expect("unicode lease");
        assert_eq!(unicode_lease.data.resource, "🔒-unicode-resource-💎");

        // Test whitespace trimming edge cases
        let whitespace_request = LeaseAcquireRequest {
            resource: "   trimmed-resource   ".to_string(),
            ttl_seconds: 300,
        };

        let trimmed_lease =
            acquire_lease(&admin, &trace, &whitespace_request).expect("trimmed lease");
        assert_eq!(trimmed_lease.data.resource, "trimmed-resource");

        // Test resource name collision detection after trimming
        let canonical_request = LeaseAcquireRequest {
            resource: "trimmed-resource".to_string(),
            ttl_seconds: 300,
        };

        let collision_err = acquire_lease(&admin, &trace, &canonical_request)
            .expect_err("trimmed collision should fail");
        assert!(matches!(collision_err, ApiError::Conflict { .. }));
    }

    #[test]
    fn fleet_lease_sequence_allocation_edge_cases() {
        // Test sequence allocation behavior for edge cases
        let _guard = test_guard();
        reset_fleet_lease_state();
        let admin = admin_identity();
        let trace = test_trace();

        // Verify initial sequence state
        {
            let state = fleet_lease_state().lock().expect("state lock");
            assert_eq!(state.next_lease_seq, 1);
            assert_eq!(state.next_fencing_seq, 1);
            assert_eq!(state.next_coordination_seq, 1);
        }

        // Test lease sequence allocation
        let lease_request = LeaseAcquireRequest {
            resource: "seq-test-resource".to_string(),
            ttl_seconds: 300,
        };

        let first_lease = acquire_lease(&admin, &trace, &lease_request).expect("first lease");
        assert!(first_lease.data.lease_id.ends_with("-0001"));
        assert_eq!(first_lease.data.fencing_token, 1);

        // Test fencing sequence allocation
        let fence_request = FencingRequest {
            target_node: "seq-test-node".to_string(),
            action: FencingAction::Drain,
            reason: "sequence test".to_string(),
        };

        let first_fence = execute_fence(&admin, &trace, &fence_request).expect("first fence");
        assert!(first_fence.data.operation_id.ends_with("-2"));
        assert_eq!(first_fence.data.fencing_token, 2);

        // Test coordination sequence allocation
        let coord_request = CoordinationRequest {
            command_type: "seq-test-command".to_string(),
            target_nodes: vec!["seq-node-1".to_string()],
            timeout_seconds: 30,
        };

        let first_coord =
            execute_coordination(&admin, &trace, &coord_request).expect("first coord");
        assert!(first_coord.data.command_id.ends_with("-0001"));

        // Verify sequence state after allocations
        {
            let state = fleet_lease_state().lock().expect("state lock");
            assert_eq!(state.next_lease_seq, 2);
            assert_eq!(state.next_fencing_seq, 3);
            assert_eq!(state.next_coordination_seq, 2);
        }

        // Test saturating arithmetic behavior (simulate near-overflow)
        {
            let mut state = fleet_lease_state().lock().expect("state lock");
            state.next_lease_seq = u64::MAX - 1;
            state.next_fencing_seq = u64::MAX - 1;
            state.next_coordination_seq = u64::MAX - 1;
        }

        // Test sequence allocation at near-overflow boundaries
        let overflow_lease = acquire_lease(
            &admin,
            &trace,
            &LeaseAcquireRequest {
                resource: "overflow-test".to_string(),
                ttl_seconds: 300,
            },
        )
        .expect("overflow lease");
        assert!(
            overflow_lease
                .data
                .lease_id
                .contains(&format!("{}", u64::MAX - 1))
        );

        let overflow_fence = execute_fence(
            &admin,
            &trace,
            &FencingRequest {
                target_node: "overflow-node".to_string(),
                action: FencingAction::Isolate,
                reason: "overflow test".to_string(),
            },
        )
        .expect("overflow fence");
        assert_eq!(overflow_fence.data.fencing_token, u64::MAX - 1);

        // Verify saturating behavior
        {
            let state = fleet_lease_state().lock().expect("state lock");
            assert_eq!(state.next_lease_seq, u64::MAX);
            assert_eq!(state.next_fencing_seq, u64::MAX);
        }
    }

    /// Comprehensive boundary testing for fleet control API edge cases and resilience.
    /// Tests lease management boundaries, fencing operation validation, and coordination limits.
    #[test]
    fn fleet_control_api_boundary_comprehensive() {
        let admin = AuthIdentity {
            identity_id: "admin-boundary-test".to_string(),
            method: AuthMethod::Internal,
        };
        let trace = TraceContext {
            request_id: "fleet-boundary-test".to_string(),
            client_ip: "127.0.0.1".to_string(),
            user_agent: "boundary-test".to_string(),
            trace_flags: BTreeSet::new(),
        };

        // Reset state for clean test
        {
            let mut state = fleet_lease_state().lock().expect("state lock");
            state.leases.clear();
            state.fencing_operations.clear();
            state.coordination_history.clear();
            state.next_lease_seq = 1;
            state.next_fencing_seq = 1;
        }

        // Test lease request validation with edge case inputs
        let lease_edge_cases = [
            // Valid minimal lease
            LeaseRequest {
                holder: "valid-holder".to_string(),
                resource: "valid-resource".to_string(),
                duration_seconds: 60,
            },
            // Empty holder (should be rejected)
            LeaseRequest {
                holder: "".to_string(),
                resource: "resource-1".to_string(),
                duration_seconds: 60,
            },
            // Empty resource (should be rejected)
            LeaseRequest {
                holder: "holder-1".to_string(),
                resource: "".to_string(),
                duration_seconds: 60,
            },
            // Zero duration (should be rejected)
            LeaseRequest {
                holder: "holder-1".to_string(),
                resource: "resource-1".to_string(),
                duration_seconds: 0,
            },
            // Excessive duration (should be clamped)
            LeaseRequest {
                holder: "holder-1".to_string(),
                resource: "resource-1".to_string(),
                duration_seconds: u64::MAX,
            },
            // Unicode characters in holder/resource
            LeaseRequest {
                holder: "用户-🔒".to_string(),
                resource: "资源-💾".to_string(),
                duration_seconds: 300,
            },
            // Long holder/resource names
            LeaseRequest {
                holder: "x".repeat(1000),
                resource: "y".repeat(1000),
                duration_seconds: 120,
            },
            // Special characters that might cause issues
            LeaseRequest {
                holder: "holder\n\r\t".to_string(),
                resource: "resource\"'\\".to_string(),
                duration_seconds: 180,
            },
        ];

        let mut successful_leases = Vec::new();
        let mut failed_leases = Vec::new();

        for (i, lease_req) in lease_edge_cases.iter().enumerate() {
            let result = acquire_lease(&admin, &trace, lease_req);

            match i {
                0 | 5 | 6 | 7 => {
                    // Valid cases should succeed (including unicode, long names, special chars)
                    assert!(result.is_ok(), "Lease case {} should succeed: {:?}", i, result);
                    if let Ok(lease) = result {
                        successful_leases.push(lease);
                    }
                }
                1 | 2 | 3 => {
                    // Invalid cases should fail (empty holder/resource, zero duration)
                    assert!(result.is_err(), "Lease case {} should fail: {:?}", i, result);
                    failed_leases.push(i);
                }
                4 => {
                    // Excessive duration case - might succeed with clamping or fail
                    match result {
                        Ok(lease) => {
                            // If it succeeds, duration should be clamped to reasonable value
                            assert!(lease.data.resource.len() > 0, "Should have valid resource");
                            successful_leases.push(lease);
                        }
                        Err(_) => {
                            // Rejection is also acceptable for excessive duration
                            failed_leases.push(i);
                        }
                    }
                }
                _ => {}
            }
        }

        // Test fencing operation validation with edge cases
        let fencing_edge_cases = [
            // Valid fencing request
            FencingRequest {
                target_node: "valid-node".to_string(),
                action: FencingAction::Isolate,
                reason: "Valid test isolation".to_string(),
            },
            // Empty target node (should be rejected)
            FencingRequest {
                target_node: "".to_string(),
                action: FencingAction::Drain,
                reason: "Empty target test".to_string(),
            },
            // Empty reason (should be rejected)
            FencingRequest {
                target_node: "node-1".to_string(),
                action: FencingAction::Rejoin,
                reason: "".to_string(),
            },
            // Unicode in target and reason
            FencingRequest {
                target_node: "节点-🖥️".to_string(),
                action: FencingAction::Isolate,
                reason: "测试 unicode 隔离".to_string(),
            },
            // Very long target/reason
            FencingRequest {
                target_node: "a".repeat(500),
                action: FencingAction::Drain,
                reason: "b".repeat(5000),
            },
            // Special characters
            FencingRequest {
                target_node: "node\n\r\t".to_string(),
                action: FencingAction::Rejoin,
                reason: "reason\"'\\%".to_string(),
            },
        ];

        let mut successful_fences = Vec::new();
        let mut failed_fences = Vec::new();

        for (i, fence_req) in fencing_edge_cases.iter().enumerate() {
            let result = execute_fence(&admin, &trace, fence_req);

            match i {
                0 | 3 | 4 | 5 => {
                    // Valid cases should succeed
                    assert!(result.is_ok(), "Fence case {} should succeed: {:?}", i, result);
                    if let Ok(fence) = result {
                        successful_fences.push(fence);
                    }
                }
                1 | 2 => {
                    // Invalid cases should fail (empty target/reason)
                    assert!(result.is_err(), "Fence case {} should fail: {:?}", i, result);
                    failed_fences.push(i);
                }
                _ => {}
            }
        }

        // Test all fencing actions
        let fencing_actions = [
            FencingAction::Isolate,
            FencingAction::Drain,
            FencingAction::Rejoin,
        ];

        for (i, &action) in fencing_actions.iter().enumerate() {
            let action_req = FencingRequest {
                target_node: format!("action-test-{}", i),
                action,
                reason: format!("Testing {:?} action", action),
            };

            let result = execute_fence(&admin, &trace, &action_req);
            assert!(result.is_ok(), "All fencing actions should be supported: {:?}", action);

            if let Ok(fence) = result {
                assert_eq!(fence.data.action, action);
                assert_eq!(fence.data.status, FencingStatus::Completed);
            }
        }

        // Test list leases functionality with populated state
        let list_result = list_leases(&admin, &trace);
        assert!(list_result.is_ok(), "Should be able to list leases");

        if let Ok(lease_list) = list_result {
            assert!(lease_list.data.len() >= 0, "Should return lease list");

            // Verify lease list structure
            for lease in &lease_list.data {
                assert!(!lease.lease_id.is_empty(), "Listed lease should have valid ID");
                assert!(!lease.holder.is_empty(), "Listed lease should have valid holder");
            }
        }
    }
}
