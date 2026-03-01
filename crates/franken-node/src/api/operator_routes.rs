//! Operator endpoint group: node status, health, configuration, rollout state.
//!
//! Routes:
//! - `GET /v1/operator/status` — node status summary
//! - `GET /v1/operator/health` — health check (liveness + readiness)
//! - `GET /v1/operator/config` — current configuration view
//! - `GET /v1/operator/rollout` — rollout state query

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Instant;

use super::error::ApiError;
use super::middleware::{
    AuthIdentity, AuthMethod, EndpointGroup, EndpointLifecycle, PolicyHook, RouteMetadata,
    TraceContext,
};
use super::trust_card_routes::ApiResponse;

static PROCESS_START: OnceLock<Instant> = OnceLock::new();

fn process_uptime_seconds() -> u64 {
    PROCESS_START.get_or_init(Instant::now).elapsed().as_secs()
}

// ── Response Types ─────────────────────────────────────────────────────────

/// Node status summary returned by `GET /v1/operator/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_id: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub policy_profile: String,
    pub active_extensions: u32,
    pub quarantined_extensions: u32,
    pub control_epoch: u64,
}

/// Health check result returned by `GET /v1/operator/health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    pub live: bool,
    pub ready: bool,
    pub checks: Vec<HealthComponent>,
}

/// Individual health component status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthComponent {
    pub name: String,
    pub status: ComponentStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentStatus {
    Ok,
    Degraded,
    Down,
}

/// Current configuration view returned by `GET /v1/operator/config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigView {
    pub profile: String,
    pub compatibility_mode: String,
    pub trust_revocation_fresh: bool,
    pub quarantine_on_high_risk: bool,
    pub replay_persist_high_severity: bool,
    pub fleet_convergence_timeout_seconds: u32,
    pub observability_namespace: String,
}

/// Rollout state returned by `GET /v1/operator/rollout`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutState {
    pub current_phase: String,
    pub target_version: String,
    pub canary_percentage: u8,
    pub healthy_nodes: u32,
    pub total_nodes: u32,
    pub last_transition: String,
}

// ── Route Metadata ─────────────────────────────────────────────────────────

/// Route metadata for the operator endpoint group.
pub fn route_metadata() -> Vec<RouteMetadata> {
    vec![
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/status".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::ApiKey,
            policy_hook: PolicyHook {
                hook_id: "operator.status.read".to_string(),
                required_roles: vec!["operator".to_string(), "reader".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/health".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::None,
            policy_hook: PolicyHook {
                hook_id: "operator.health.read".to_string(),
                required_roles: vec![],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/config".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::ApiKey,
            policy_hook: PolicyHook {
                hook_id: "operator.config.read".to_string(),
                required_roles: vec!["operator".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/operator/rollout".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::ApiKey,
            policy_hook: PolicyHook {
                hook_id: "operator.rollout.read".to_string(),
                required_roles: vec!["operator".to_string()],
            },
            trace_propagation: true,
        },
    ]
}

// ── Handlers ───────────────────────────────────────────────────────────────

/// Handle `GET /v1/operator/status`.
pub fn get_status(
    _identity: &AuthIdentity,
    _trace: &TraceContext,
) -> Result<ApiResponse<NodeStatus>, ApiError> {
    let status = NodeStatus {
        node_id: "franken-node-primary".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: process_uptime_seconds(),
        policy_profile: "balanced".to_string(),
        active_extensions: 0,
        quarantined_extensions: 0,
        control_epoch: 1,
    };

    Ok(ApiResponse {
        ok: true,
        data: status,
        page: None,
    })
}

/// Handle `GET /v1/operator/health`.
pub fn get_health(
    _identity: &AuthIdentity,
    _trace: &TraceContext,
) -> Result<ApiResponse<HealthCheck>, ApiError> {
    let health = HealthCheck {
        live: true,
        ready: true,
        checks: vec![
            HealthComponent {
                name: "control_plane".to_string(),
                status: ComponentStatus::Ok,
                detail: None,
            },
            HealthComponent {
                name: "trust_registry".to_string(),
                status: ComponentStatus::Ok,
                detail: None,
            },
            HealthComponent {
                name: "policy_engine".to_string(),
                status: ComponentStatus::Ok,
                detail: None,
            },
        ],
    };

    Ok(ApiResponse {
        ok: true,
        data: health,
        page: None,
    })
}

/// Handle `GET /v1/operator/config`.
pub fn get_config(
    _identity: &AuthIdentity,
    _trace: &TraceContext,
) -> Result<ApiResponse<ConfigView>, ApiError> {
    let config = ConfigView {
        profile: "balanced".to_string(),
        compatibility_mode: "balanced".to_string(),
        trust_revocation_fresh: true,
        quarantine_on_high_risk: true,
        replay_persist_high_severity: true,
        fleet_convergence_timeout_seconds: 120,
        observability_namespace: "franken_node".to_string(),
    };

    Ok(ApiResponse {
        ok: true,
        data: config,
        page: None,
    })
}

/// Handle `GET /v1/operator/rollout`.
pub fn get_rollout(
    _identity: &AuthIdentity,
    _trace: &TraceContext,
) -> Result<ApiResponse<RolloutState>, ApiError> {
    let rollout = RolloutState {
        current_phase: "stable".to_string(),
        target_version: env!("CARGO_PKG_VERSION").to_string(),
        canary_percentage: 0,
        healthy_nodes: 1,
        total_nodes: 1,
        last_transition: chrono::Utc::now().to_rfc3339(),
    };

    Ok(ApiResponse {
        ok: true,
        data: rollout,
        page: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::AuthMethod;

    fn test_identity() -> AuthIdentity {
        AuthIdentity {
            principal: "test-operator".to_string(),
            method: AuthMethod::ApiKey,
            roles: vec!["operator".to_string()],
        }
    }

    fn test_trace() -> TraceContext {
        TraceContext {
            trace_id: "test-trace-001".to_string(),
            span_id: "0000000000000001".to_string(),
            trace_flags: 1,
        }
    }

    #[test]
    fn route_metadata_has_four_endpoints() {
        let routes = route_metadata();
        assert_eq!(routes.len(), 4);
        assert!(routes.iter().all(|r| r.group == EndpointGroup::Operator));
    }

    #[test]
    fn health_endpoint_no_auth() {
        let routes = route_metadata();
        let health = routes.iter().find(|r| r.path.contains("health")).unwrap();
        assert_eq!(health.auth_method, AuthMethod::None);
        assert!(health.policy_hook.required_roles.is_empty());
    }

    #[test]
    fn get_status_returns_ok() {
        let identity = test_identity();
        let trace = test_trace();
        let result = get_status(&identity, &trace).expect("status");
        assert!(result.ok);
        assert!(!result.data.node_id.is_empty());
    }

    #[test]
    fn status_uptime_is_monotonic() {
        let identity = test_identity();
        let trace = test_trace();
        let first = get_status(&identity, &trace).expect("first");
        std::thread::sleep(std::time::Duration::from_millis(5));
        let second = get_status(&identity, &trace).expect("second");
        assert!(second.data.uptime_seconds >= first.data.uptime_seconds);
    }

    #[test]
    fn get_health_returns_live_ready() {
        let identity = test_identity();
        let trace = test_trace();
        let result = get_health(&identity, &trace).expect("health");
        assert!(result.ok);
        assert!(result.data.live);
        assert!(result.data.ready);
        assert!(!result.data.checks.is_empty());
    }

    #[test]
    fn get_config_returns_balanced_profile() {
        let identity = test_identity();
        let trace = test_trace();
        let result = get_config(&identity, &trace).expect("config");
        assert!(result.ok);
        assert_eq!(result.data.profile, "balanced");
    }

    #[test]
    fn get_rollout_returns_stable_phase() {
        let identity = test_identity();
        let trace = test_trace();
        let result = get_rollout(&identity, &trace).expect("rollout");
        assert!(result.ok);
        assert_eq!(result.data.current_phase, "stable");
    }

    #[test]
    fn all_stable_lifecycle() {
        for route in route_metadata() {
            assert_eq!(route.lifecycle, EndpointLifecycle::Stable);
        }
    }

    #[test]
    fn all_routes_have_trace_propagation() {
        for route in route_metadata() {
            assert!(route.trace_propagation);
        }
    }
}
