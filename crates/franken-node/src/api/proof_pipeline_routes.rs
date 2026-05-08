//! Proof-pipeline operator endpoint group.
//!
//! Routes:
//! - `GET /api/v1/proofs/queue/status` - inspect broker proof queue health
//! - `POST /api/v1/proofs/workers/restart` - validate proof worker restart requests

use crate::ops::proof_pipeline::{
    ProofPipelineQueueReport, ProofWorkerRestartReport, ProofWorkerRestartRequest,
    ProofWorkerRestartTarget, build_queue_report, evaluate_worker_restart_request,
};
use crate::ops::validation_readiness::ValidationReadinessInput;
use serde::{Deserialize, Serialize};

use super::error::ApiError;
use super::middleware::{
    AuthIdentity, AuthMethod, EndpointGroup, EndpointLifecycle, PolicyHook, RouteMetadata,
    TraceContext, enforce_route_contract,
};
use super::trust_card_routes::ApiResponse;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofWorkerRestartApiRequest {
    pub operator_id: String,
    pub reason: String,
    pub confirm: bool,
    #[serde(default)]
    pub worker_id: Option<String>,
    #[serde(default)]
    pub all_workers: bool,
}

pub fn route_metadata() -> Vec<RouteMetadata> {
    vec![
        RouteMetadata {
            method: "GET".to_string(),
            path: "/api/v1/proofs/queue/status".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "proof_pipeline.queue.status".to_string(),
                required_roles: vec!["operator".to_string(), "pipeline_admin".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "POST".to_string(),
            path: "/api/v1/proofs/workers/restart".to_string(),
            group: EndpointGroup::Operator,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "proof_pipeline.workers.restart".to_string(),
                required_roles: vec!["pipeline_admin".to_string()],
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

pub fn proof_queue_status_route(
    identity: &AuthIdentity,
    trace: &TraceContext,
    input: &ValidationReadinessInput,
) -> Result<ApiResponse<ProofPipelineQueueReport>, ApiError> {
    enforce_handler_contract(identity, trace, "GET", "/api/v1/proofs/queue/status")?;
    let report = build_queue_report(input, trace.trace_id.clone(), chrono::Utc::now());
    Ok(ApiResponse {
        ok: true,
        data: report,
        page: None,
    })
}

pub fn restart_proof_workers_route(
    identity: &AuthIdentity,
    trace: &TraceContext,
    input: &ValidationReadinessInput,
    request: &ProofWorkerRestartApiRequest,
) -> Result<ApiResponse<ProofWorkerRestartReport>, ApiError> {
    enforce_handler_contract(identity, trace, "POST", "/api/v1/proofs/workers/restart")?;
    let target = restart_target(request, &trace.trace_id)?;
    let restart_request = ProofWorkerRestartRequest {
        operator_id: request.operator_id.clone(),
        operator_roles: identity.roles.clone(),
        target,
        reason: request.reason.clone(),
        confirm: request.confirm,
    };
    let report = evaluate_worker_restart_request(
        input,
        &restart_request,
        trace.trace_id.clone(),
        chrono::Utc::now(),
    );
    if !report.ok {
        return Err(ApiError::BadRequest {
            detail: format!("{}: {}", report.reason_code, report.audit_event),
            trace_id: trace.trace_id.clone(),
        });
    }
    Ok(ApiResponse {
        ok: true,
        data: report,
        page: None,
    })
}

fn restart_target(
    request: &ProofWorkerRestartApiRequest,
    trace_id: &str,
) -> Result<ProofWorkerRestartTarget, ApiError> {
    match (request.all_workers, request.worker_id.as_deref()) {
        (true, None) => Ok(ProofWorkerRestartTarget::AllWorkers),
        (false, Some(worker_id)) => Ok(ProofWorkerRestartTarget::WorkerId(worker_id.to_string())),
        (true, Some(_)) => Err(ApiError::BadRequest {
            detail: "worker_id and all_workers are mutually exclusive".to_string(),
            trace_id: trace_id.to_string(),
        }),
        (false, None) => Err(ApiError::BadRequest {
            detail: "worker_id or all_workers is required".to_string(),
            trace_id: trace_id.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::validation_broker::{
        ProofEvidenceSource, ProofStatusKind, QueueState, RchMode, STATUS_SCHEMA_VERSION,
        ValidationProofStatus,
    };
    use crate::ops::validation_readiness::RchWorkerReadiness;

    fn identity(role: &str) -> AuthIdentity {
        AuthIdentity {
            principal: "proof-pipeline-test-operator".to_string(),
            method: AuthMethod::BearerToken,
            roles: vec![role.to_string()],
        }
    }

    fn trace() -> TraceContext {
        TraceContext {
            trace_id: "proof-pipeline-route-trace".to_string(),
            span_id: "0000000000000002".to_string(),
            trace_flags: 1,
        }
    }

    fn input() -> ValidationReadinessInput {
        ValidationReadinessInput {
            proof_statuses: vec![ValidationProofStatus {
                schema_version: STATUS_SCHEMA_VERSION.to_string(),
                bead_id: "bd-proof".to_string(),
                thread_id: "bd-proof".to_string(),
                request_id: Some("req-1".to_string()),
                queue_id: Some("queue-1".to_string()),
                status: ProofStatusKind::Running,
                proof_source: ProofEvidenceSource::BrokerQueue,
                queue_state: Some(QueueState::Running),
                deduplicated: false,
                queue_depth: 1,
                artifact_paths: None,
                command_digest: None,
                exit: None,
                reason: None,
                proof_coalescer: None,
                proof_cache: None,
                readiness_ref: None,
                flight_recorder_ref: None,
                observed_at: chrono::Utc::now(),
            }],
            rch_workers: vec![RchWorkerReadiness {
                worker_id: "vmi-proof-1".to_string(),
                reachable: false,
                mode: RchMode::Unavailable,
                required_toolchains: vec!["stable".to_string()],
                observed_toolchains: Vec::new(),
                failure: Some("ssh timeout".to_string()),
            }],
            ..ValidationReadinessInput::default()
        }
    }

    #[test]
    fn route_metadata_declares_queue_status_and_worker_restart() {
        let routes = route_metadata();
        assert_eq!(routes.len(), 2);
        assert!(
            routes
                .iter()
                .all(|route| route.group == EndpointGroup::Operator)
        );
        assert!(
            routes
                .iter()
                .any(|route| route.path == "/api/v1/proofs/queue/status")
        );
        assert!(
            routes
                .iter()
                .any(|route| route.path == "/api/v1/proofs/workers/restart")
        );
    }

    #[test]
    fn queue_status_route_reports_running_proof() {
        let response =
            proof_queue_status_route(&identity("operator"), &trace(), &input()).expect("status");

        assert_eq!(response.data.summary.queue_depth, 1);
        assert_eq!(response.data.summary.degraded_workers, 1);
    }

    #[test]
    fn restart_route_accepts_pipeline_admin_for_degraded_worker() {
        let request = ProofWorkerRestartApiRequest {
            operator_id: "ops-1".to_string(),
            reason: "outage drill".to_string(),
            confirm: true,
            worker_id: Some("vmi-proof-1".to_string()),
            all_workers: false,
        };
        let response =
            restart_proof_workers_route(&identity("pipeline_admin"), &trace(), &input(), &request)
                .expect("restart");

        assert!(response.data.ok);
        assert_eq!(response.data.selected_workers, vec!["vmi-proof-1"]);
    }

    #[test]
    fn restart_route_rejects_operator_without_pipeline_admin_role() {
        let request = ProofWorkerRestartApiRequest {
            operator_id: "ops-1".to_string(),
            reason: "outage drill".to_string(),
            confirm: true,
            worker_id: Some("vmi-proof-1".to_string()),
            all_workers: false,
        };
        let err = restart_proof_workers_route(&identity("operator"), &trace(), &input(), &request)
            .expect_err("operator role should not restart proof workers");

        assert!(matches!(err, ApiError::PolicyDenied { .. }));
    }

    #[test]
    fn restart_route_rejects_ambiguous_target() {
        let request = ProofWorkerRestartApiRequest {
            operator_id: "ops-1".to_string(),
            reason: "outage drill".to_string(),
            confirm: true,
            worker_id: Some("vmi-proof-1".to_string()),
            all_workers: true,
        };
        let err =
            restart_proof_workers_route(&identity("pipeline_admin"), &trace(), &input(), &request)
                .expect_err("ambiguous target should fail");

        assert!(matches!(err, ApiError::BadRequest { .. }));
    }
}
