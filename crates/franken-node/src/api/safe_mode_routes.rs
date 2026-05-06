//! Safe-mode operator endpoint group.
//!
//! Routes:
//! - `POST /api/v1/control/safe-mode/enter` - enter safe mode
//! - `GET /api/v1/control/safe-mode/status` - inspect safe-mode state
//! - `POST /api/v1/control/safe-mode/exit` - exit safe mode after pre-exit checks

use crate::runtime::safe_mode::{
    ExitVerification, SafeModeController, SafeModeEntryReason, SafeModeEntryReceipt, SafeModeEvent,
    SafeModeStatus,
};
use serde::{Deserialize, Serialize};

use super::error::ApiError;
use super::middleware::{
    AuthIdentity, AuthMethod, EndpointGroup, EndpointLifecycle, PolicyHook, RouteMetadata,
    TraceContext, enforce_route_contract,
};
use super::trust_card_routes::ApiResponse;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeEnterRequest {
    pub reason: SafeModeEntryReason,
    pub operator_id: String,
    pub timestamp: String,
    pub trust_state_hash: String,
    #[serde(default)]
    pub inconsistencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeExitRequest {
    pub operator_id: String,
    pub timestamp: String,
    pub confirm: bool,
    pub trust_state_consistent: bool,
    pub no_unresolved_incidents: bool,
    pub evidence_ledger_intact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeOperatorResult {
    pub schema_version: String,
    pub action: String,
    pub operator_id: Option<String>,
    pub status: SafeModeStatus,
    pub events: Vec<SafeModeEvent>,
    pub entry_receipt: Option<SafeModeEntryReceipt>,
}

fn normalize_required_field(value: &str, field: &str, trace_id: &str) -> Result<String, ApiError> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(ApiError::BadRequest {
            detail: format!("{field} must not be empty"),
            trace_id: trace_id.to_string(),
        });
    }
    if normalized.contains('\0') {
        return Err(ApiError::BadRequest {
            detail: format!("{field} must not contain NUL bytes"),
            trace_id: trace_id.to_string(),
        });
    }
    Ok(normalized.to_string())
}

pub fn route_metadata() -> Vec<RouteMetadata> {
    vec![
        RouteMetadata {
            method: "POST".to_string(),
            path: "/api/v1/control/safe-mode/enter".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "safe_mode.enter".to_string(),
                required_roles: vec!["safe-mode-admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "GET".to_string(),
            path: "/api/v1/control/safe-mode/status".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "safe_mode.status".to_string(),
                required_roles: vec!["operator".to_string(), "safe-mode-admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "POST".to_string(),
            path: "/api/v1/control/safe-mode/exit".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "safe_mode.exit".to_string(),
                required_roles: vec!["safe-mode-admin".to_string()],
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

fn result_from_controller(
    action: &str,
    operator_id: Option<String>,
    controller: &SafeModeController,
    timestamp: &str,
) -> SafeModeOperatorResult {
    SafeModeOperatorResult {
        schema_version: "franken-node/safe-mode-api/v1".to_string(),
        action: action.to_string(),
        operator_id,
        status: controller.status(timestamp),
        events: controller.events().to_vec(),
        entry_receipt: controller.entry_receipt().cloned(),
    }
}

pub fn enter_safe_mode_route(
    identity: &AuthIdentity,
    trace: &TraceContext,
    controller: &mut SafeModeController,
    request: &SafeModeEnterRequest,
) -> Result<ApiResponse<SafeModeOperatorResult>, ApiError> {
    enforce_handler_contract(identity, trace, "POST", "/api/v1/control/safe-mode/enter")?;
    let operator_id =
        normalize_required_field(&request.operator_id, "operator_id", &trace.trace_id)?;
    let trust_state_hash = normalize_required_field(
        &request.trust_state_hash,
        "trust_state_hash",
        &trace.trace_id,
    )?;
    let timestamp = normalize_required_field(&request.timestamp, "timestamp", &trace.trace_id)?;
    for inconsistency in &request.inconsistencies {
        normalize_required_field(inconsistency, "inconsistency", &trace.trace_id)?;
    }

    controller.enter_safe_mode(
        request.reason.clone(),
        &timestamp,
        &trust_state_hash,
        request.inconsistencies.clone(),
    );

    Ok(ApiResponse {
        ok: true,
        data: result_from_controller("enter", Some(operator_id), controller, &timestamp),
        page: None,
    })
}

pub fn safe_mode_status_route(
    identity: &AuthIdentity,
    trace: &TraceContext,
    controller: &SafeModeController,
    timestamp: &str,
) -> Result<ApiResponse<SafeModeOperatorResult>, ApiError> {
    enforce_handler_contract(identity, trace, "GET", "/api/v1/control/safe-mode/status")?;
    let timestamp = normalize_required_field(timestamp, "timestamp", &trace.trace_id)?;
    Ok(ApiResponse {
        ok: true,
        data: result_from_controller("status", None, controller, &timestamp),
        page: None,
    })
}

pub fn exit_safe_mode_route(
    identity: &AuthIdentity,
    trace: &TraceContext,
    controller: &mut SafeModeController,
    request: &SafeModeExitRequest,
) -> Result<ApiResponse<SafeModeOperatorResult>, ApiError> {
    enforce_handler_contract(identity, trace, "POST", "/api/v1/control/safe-mode/exit")?;
    let operator_id =
        normalize_required_field(&request.operator_id, "operator_id", &trace.trace_id)?;
    let timestamp = normalize_required_field(&request.timestamp, "timestamp", &trace.trace_id)?;
    let verification = ExitVerification {
        trust_state_consistent: request.trust_state_consistent,
        no_unresolved_incidents: request.no_unresolved_incidents,
        evidence_ledger_intact: request.evidence_ledger_intact,
        operator_confirmed: request.confirm,
    };

    controller
        .exit_safe_mode(&verification, &operator_id, &timestamp)
        .map_err(|err| ApiError::BadRequest {
            detail: err.to_string(),
            trace_id: trace.trace_id.clone(),
        })?;

    Ok(ApiResponse {
        ok: true,
        data: result_from_controller("exit", Some(operator_id), controller, &timestamp),
        page: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::safe_mode::SafeModeConfig;

    fn identity(role: &str) -> AuthIdentity {
        AuthIdentity {
            principal: "safe-mode-test-operator".to_string(),
            method: AuthMethod::BearerToken,
            roles: vec![role.to_string()],
        }
    }

    fn trace() -> TraceContext {
        TraceContext {
            trace_id: "safe-mode-route-trace".to_string(),
            span_id: "0000000000000001".to_string(),
            trace_flags: 1,
        }
    }

    #[test]
    fn route_metadata_declares_enter_status_exit() {
        let routes = route_metadata();
        assert_eq!(routes.len(), 3);
        assert!(
            routes
                .iter()
                .all(|route| route.group == EndpointGroup::Operator)
        );
        assert!(
            routes
                .iter()
                .any(|route| route.path == "/api/v1/control/safe-mode/enter")
        );
        assert!(
            routes
                .iter()
                .any(|route| route.path == "/api/v1/control/safe-mode/status")
        );
        assert!(
            routes
                .iter()
                .any(|route| route.path == "/api/v1/control/safe-mode/exit")
        );
    }

    #[test]
    fn enter_status_exit_round_trip_through_controller() {
        let mut controller = SafeModeController::new(SafeModeConfig::default());
        let trace = trace();
        let enter = SafeModeEnterRequest {
            reason: SafeModeEntryReason::TrustCorruption,
            operator_id: "secops-1".to_string(),
            timestamp: "2026-05-06T16:00:00Z".to_string(),
            trust_state_hash: "sha256:trusted".to_string(),
            inconsistencies: Vec::new(),
        };

        let entered = enter_safe_mode_route(
            &identity("safe-mode-admin"),
            &trace,
            &mut controller,
            &enter,
        )
        .expect("enter safe mode");
        assert!(entered.data.status.safe_mode_active);
        assert_eq!(entered.data.operator_id.as_deref(), Some("secops-1"));

        let status = safe_mode_status_route(
            &identity("operator"),
            &trace,
            &controller,
            "2026-05-06T16:01:00Z",
        )
        .expect("status");
        assert!(status.data.status.safe_mode_active);

        let exit = SafeModeExitRequest {
            operator_id: "secops-1".to_string(),
            timestamp: "2026-05-06T16:02:00Z".to_string(),
            confirm: true,
            trust_state_consistent: true,
            no_unresolved_incidents: true,
            evidence_ledger_intact: true,
        };
        let exited =
            exit_safe_mode_route(&identity("safe-mode-admin"), &trace, &mut controller, &exit)
                .expect("exit safe mode");
        assert!(!exited.data.status.safe_mode_active);
    }

    #[test]
    fn exit_rejects_missing_operator_confirmation() {
        let mut controller = SafeModeController::new(SafeModeConfig::default());
        controller.enter_safe_mode(
            SafeModeEntryReason::TrustCorruption,
            "2026-05-06T16:00:00Z",
            "sha256:trusted",
            Vec::new(),
        );
        let request = SafeModeExitRequest {
            operator_id: "secops-1".to_string(),
            timestamp: "2026-05-06T16:02:00Z".to_string(),
            confirm: false,
            trust_state_consistent: true,
            no_unresolved_incidents: true,
            evidence_ledger_intact: true,
        };

        let err = exit_safe_mode_route(
            &identity("safe-mode-admin"),
            &trace(),
            &mut controller,
            &request,
        )
        .expect_err("exit without confirmation should fail");
        assert!(matches!(err, ApiError::BadRequest { .. }));
        assert!(controller.is_active());
    }
}
