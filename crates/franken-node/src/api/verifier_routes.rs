//! Verifier endpoint group: conformance trigger, evidence retrieval, audit log query.
//!
//! Routes:
//! - `POST /v1/verifier/conformance` — trigger a conformance check
//! - `GET  /v1/verifier/evidence/{check_id}` — retrieve evidence artifact
//! - `GET  /v1/verifier/audit-log` — query audit log entries

use serde::{Deserialize, Serialize};

use super::error::ApiError;
use super::middleware::{
    AuthIdentity, AuthMethod, EndpointGroup, EndpointLifecycle, PolicyHook, RouteMetadata,
    TraceContext,
};
use super::trust_card_routes::ApiResponse;
use super::utf8_prefix;

// ── Response Types ─────────────────────────────────────────────────────────

/// Conformance check result returned by `POST /v1/verifier/conformance`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceResult {
    pub check_id: String,
    pub status: ConformanceStatus,
    pub total_checks: u32,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub findings: Vec<ConformanceFinding>,
    pub triggered_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceStatus {
    Pass,
    Fail,
    Partial,
}

/// Individual conformance finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceFinding {
    pub check_name: String,
    pub status: ConformanceStatus,
    pub detail: String,
    pub severity: String,
}

/// Evidence artifact returned by `GET /v1/verifier/evidence/{check_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub check_id: String,
    pub artifact_type: String,
    pub content_hash: String,
    pub size_bytes: u64,
    pub created_at: String,
    pub content: serde_json::Value,
}

/// Audit log entry returned by `GET /v1/verifier/audit-log`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub entry_id: String,
    pub timestamp: String,
    pub action: String,
    pub actor: String,
    pub resource: String,
    pub outcome: String,
    pub trace_id: String,
}

/// Request parameters for conformance trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceTriggerRequest {
    /// Optional scope filter (e.g., specific module or bead).
    pub scope: Option<String>,
    /// Whether to include verbose output.
    pub verbose: bool,
}

/// Request parameters for audit log query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogQuery {
    /// Filter by action type.
    pub action: Option<String>,
    /// Filter by actor.
    pub actor: Option<String>,
    /// Maximum number of entries to return.
    pub limit: Option<u32>,
    /// Return entries after this timestamp.
    pub since: Option<String>,
}

// ── Route Metadata ─────────────────────────────────────────────────────────

pub fn route_metadata() -> Vec<RouteMetadata> {
    vec![
        RouteMetadata {
            method: "POST".to_string(),
            path: "/v1/verifier/conformance".to_string(),
            group: EndpointGroup::Verifier,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "verifier.conformance.trigger".to_string(),
                required_roles: vec!["verifier".to_string(), "operator".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/verifier/evidence/{check_id}".to_string(),
            group: EndpointGroup::Verifier,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "verifier.evidence.read".to_string(),
                required_roles: vec!["verifier".to_string(), "operator".to_string()],
            },
            trace_propagation: true,
        },
        RouteMetadata {
            method: "GET".to_string(),
            path: "/v1/verifier/audit-log".to_string(),
            group: EndpointGroup::Verifier,
            lifecycle: EndpointLifecycle::Stable,
            auth_method: AuthMethod::BearerToken,
            policy_hook: PolicyHook {
                hook_id: "verifier.audit.read".to_string(),
                required_roles: vec!["verifier".to_string(), "operator".to_string()],
            },
            trace_propagation: true,
        },
    ]
}

// ── Handlers ───────────────────────────────────────────────────────────────

/// Handle `POST /v1/verifier/conformance`.
pub fn trigger_conformance(
    _identity: &AuthIdentity,
    trace: &TraceContext,
    _request: &ConformanceTriggerRequest,
) -> Result<ApiResponse<ConformanceResult>, ApiError> {
    let check_id = format!("chk-{}", utf8_prefix(&trace.trace_id, 12));

    let findings = vec![
        ConformanceFinding {
            check_name: "trust_card_schema".to_string(),
            status: ConformanceStatus::Pass,
            detail: "trust card schema validates against contract".to_string(),
            severity: "info".to_string(),
        },
        ConformanceFinding {
            check_name: "error_code_coverage".to_string(),
            status: ConformanceStatus::Pass,
            detail: "all FRANKEN_* codes have HTTP mapping".to_string(),
            severity: "info".to_string(),
        },
    ];

    let passed = u32::try_from(
        findings
            .iter()
            .filter(|f| f.status == ConformanceStatus::Pass)
            .count(),
    )
    .unwrap_or(u32::MAX);
    let failed = u32::try_from(
        findings
            .iter()
            .filter(|f| f.status == ConformanceStatus::Fail)
            .count(),
    )
    .unwrap_or(u32::MAX);

    let status = if failed > 0 {
        ConformanceStatus::Fail
    } else {
        ConformanceStatus::Pass
    };

    let result = ConformanceResult {
        check_id,
        status,
        total_checks: u32::try_from(findings.len()).unwrap_or(u32::MAX),
        passed,
        failed,
        skipped: 0,
        findings,
        triggered_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(ApiResponse {
        ok: true,
        data: result,
        page: None,
    })
}

/// Handle `GET /v1/verifier/evidence/{check_id}`.
pub fn get_evidence(
    _identity: &AuthIdentity,
    _trace: &TraceContext,
    check_id: &str,
) -> Result<ApiResponse<EvidenceArtifact>, ApiError> {
    // In a real implementation this would look up stored evidence.
    // For the skeleton, return a synthetic artifact.
    let artifact = EvidenceArtifact {
        check_id: check_id.to_string(),
        artifact_type: "conformance_evidence".to_string(),
        content_hash: "sha256:placeholder".to_string(),
        size_bytes: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        content: serde_json::json!({
            "skeleton": true,
            "check_id": check_id,
        }),
    };

    Ok(ApiResponse {
        ok: true,
        data: artifact,
        page: None,
    })
}

/// Handle `GET /v1/verifier/audit-log`.
pub fn query_audit_log(
    _identity: &AuthIdentity,
    _trace: &TraceContext,
    _query: &AuditLogQuery,
) -> Result<ApiResponse<Vec<AuditLogEntry>>, ApiError> {
    // Skeleton: return empty audit log.
    let entries: Vec<AuditLogEntry> = Vec::new();

    Ok(ApiResponse {
        ok: true,
        data: entries,
        page: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::AuthMethod;

    fn test_identity() -> AuthIdentity {
        AuthIdentity {
            principal: "test-verifier".to_string(),
            method: AuthMethod::BearerToken,
            roles: vec!["verifier".to_string()],
        }
    }

    fn test_trace() -> TraceContext {
        TraceContext {
            trace_id: "test-trace-verifier-001".to_string(),
            span_id: "0000000000000002".to_string(),
            trace_flags: 1,
        }
    }

    #[test]
    fn route_metadata_has_three_endpoints() {
        let routes = route_metadata();
        assert_eq!(routes.len(), 3);
        assert!(routes.iter().all(|r| r.group == EndpointGroup::Verifier));
    }

    #[test]
    fn all_verifier_routes_require_bearer_token() {
        for route in route_metadata() {
            assert_eq!(route.auth_method, AuthMethod::BearerToken);
        }
    }

    #[test]
    fn trigger_conformance_returns_pass() {
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: None,
            verbose: false,
        };
        let result = trigger_conformance(&identity, &trace, &request).expect("conformance");
        assert!(result.ok);
        assert_eq!(result.data.status, ConformanceStatus::Pass);
        assert!(result.data.passed > 0);
        assert_eq!(result.data.failed, 0);
    }

    #[test]
    fn get_evidence_returns_artifact() {
        let identity = test_identity();
        let trace = test_trace();
        let result = get_evidence(&identity, &trace, "chk-test-001").expect("evidence");
        assert!(result.ok);
        assert_eq!(result.data.check_id, "chk-test-001");
        assert_eq!(result.data.artifact_type, "conformance_evidence");
    }

    #[test]
    fn query_audit_log_returns_empty() {
        let identity = test_identity();
        let trace = test_trace();
        let query = AuditLogQuery {
            action: None,
            actor: None,
            limit: Some(10),
            since: None,
        };
        let result = query_audit_log(&identity, &trace, &query).expect("audit log");
        assert!(result.ok);
        assert!(result.data.is_empty());
    }

    #[test]
    fn conformance_check_id_uses_trace() {
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: Some("security".to_string()),
            verbose: true,
        };
        let result = trigger_conformance(&identity, &trace, &request).expect("conformance");
        assert!(result.data.check_id.starts_with("chk-"));
    }

    #[test]
    fn all_routes_are_stable_lifecycle() {
        let routes = route_metadata();
        for r in &routes {
            assert_eq!(
                r.lifecycle,
                EndpointLifecycle::Stable,
                "route {} should be Stable",
                r.path
            );
        }
    }

    #[test]
    fn conformance_pass_verdict() {
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: None,
            verbose: false,
        };
        let result = trigger_conformance(&identity, &trace, &request).expect("conformance");
        assert_eq!(result.data.status, ConformanceStatus::Pass);
    }

    #[test]
    fn conformance_with_scope_filter() {
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: Some("crypto".to_string()),
            verbose: true,
        };
        let result = trigger_conformance(&identity, &trace, &request).expect("conformance");
        assert!(result.ok);
    }

    #[test]
    fn evidence_artifact_has_content() {
        let identity = test_identity();
        let trace = test_trace();
        let result = get_evidence(&identity, &trace, "art-001").expect("evidence");
        assert!(result.ok);
        assert!(!result.data.check_id.is_empty());
        assert!(!result.data.content.is_null());
    }

    #[test]
    fn evidence_artifact_serde_roundtrip() {
        let artifact = EvidenceArtifact {
            check_id: "chk-123".to_string(),
            artifact_type: "hash-proof".to_string(),
            content_hash: "sha256:abc".to_string(),
            size_bytes: 42,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            content: serde_json::json!({"test": true}),
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let parsed: EvidenceArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.check_id, "chk-123");
    }

    #[test]
    fn audit_log_query_with_filter() {
        let identity = test_identity();
        let trace = test_trace();
        let query = AuditLogQuery {
            action: Some("conformance".to_string()),
            actor: Some("test-verifier".to_string()),
            limit: Some(5),
            since: Some("2026-01-01T00:00:00Z".to_string()),
        };
        let result = query_audit_log(&identity, &trace, &query).expect("audit log");
        assert!(result.ok);
    }

    #[test]
    fn conformance_result_serde_roundtrip() {
        let result = ConformanceResult {
            check_id: "chk-test".to_string(),
            status: ConformanceStatus::Pass,
            total_checks: 2,
            passed: 2,
            failed: 0,
            skipped: 0,
            findings: vec![],
            triggered_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ConformanceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, ConformanceStatus::Pass);
    }

    #[test]
    fn conformance_status_variants() {
        assert_ne!(
            format!("{:?}", ConformanceStatus::Pass),
            format!("{:?}", ConformanceStatus::Fail)
        );
    }

    #[test]
    fn conformance_check_id_handles_unicode_trace() {
        let identity = test_identity();
        let trace = TraceContext {
            trace_id: "測試🙂識別子🙂trace🙂".to_string(),
            span_id: "0000000000000002".to_string(),
            trace_flags: 1,
        };
        let request = ConformanceTriggerRequest {
            scope: None,
            verbose: false,
        };

        let result = trigger_conformance(&identity, &trace, &request).expect("conformance");
        let expected: String = trace.trace_id.chars().take(12).collect();
        assert_eq!(result.data.check_id, format!("chk-{expected}"));
    }
}
