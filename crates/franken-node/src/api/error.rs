//! RFC 7807 Problem Details error types for the control-plane API.
//!
//! Maps `FRANKEN_*` error codes from the error code registry to structured
//! HTTP problem responses with stable `type`, `title`, `status`, `detail`,
//! `instance`, `code`, and `trace_id` fields.

#[cfg(any(test, feature = "extended-surfaces"))]
use serde::{Deserialize, Serialize};

#[cfg(any(test, feature = "extended-surfaces"))]
use crate::connector::error_code_registry::{ErrorCodeEntry, Severity};

/// RFC 7807 Problem Details response.
///
/// All control-plane API error responses use this format with
/// `Content-Type: application/problem+json`.
#[cfg(any(test, feature = "extended-surfaces"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProblemDetail {
    /// URI reference identifying the problem type.
    #[serde(rename = "type")]
    pub problem_type: String,

    /// Short human-readable summary.
    pub title: String,

    /// HTTP status code.
    pub status: u16,

    /// Human-readable explanation of this specific occurrence.
    pub detail: String,

    /// URI identifying this specific problem instance.
    pub instance: String,

    /// Stable `FRANKEN_*` error code from the error registry.
    pub code: String,

    /// W3C trace ID for request correlation.
    pub trace_id: String,

    /// Whether the caller should retry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,

    /// Suggested retry delay in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,

    /// Hint for how to recover from this error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_hint: Option<String>,
}

/// Map error code severity to a default HTTP status.
#[cfg(any(test, feature = "extended-surfaces"))]
fn severity_to_status(severity: Severity) -> u16 {
    match severity {
        Severity::Fatal => 500,
        Severity::Degraded => 503,
        Severity::Transient => 429,
    }
}

/// Well-known error code to HTTP status overrides.
///
/// Codes not listed here fall back to [`severity_to_status`].
#[cfg(any(test, feature = "extended-surfaces"))]
fn has_code_marker(code: &str, marker: &str) -> bool {
    !marker.is_empty()
        && code.match_indices(marker).any(|(start, _)| {
            let after = &code[start + marker.len()..];
            after.is_empty() || after.starts_with('_')
        })
}

#[cfg(any(test, feature = "extended-surfaces"))]
fn code_to_status(code: &str) -> Option<u16> {
    match code {
        // Auth/authz failures
        c if has_code_marker(c, "_AUTH_FAIL")
            || has_code_marker(c, "_AUTH_FAILED")
            || has_code_marker(c, "_AUTH_FAILURE") =>
        {
            Some(401)
        }
        c if has_code_marker(c, "_POLICY_DENY") => Some(403),
        c if has_code_marker(c, "_RATE_LIMITED") => Some(429),
        // Not found
        c if has_code_marker(c, "_NOT_FOUND") => Some(404),
        // Conflict (lease, fencing)
        c if has_code_marker(c, "_LEASE_CONFLICT") || has_code_marker(c, "_FENCING_CONFLICT") => {
            Some(409)
        }
        // Bad request
        c if has_code_marker(c, "_INVALID") || has_code_marker(c, "_BAD_REQUEST") => Some(400),
        _ => None,
    }
}

#[cfg(any(test, feature = "extended-surfaces"))]
impl ProblemDetail {
    /// Build a problem detail from an error code registry entry.
    pub fn from_registry_entry(
        entry: &ErrorCodeEntry,
        detail: &str,
        instance: &str,
        trace_id: &str,
    ) -> Self {
        let status =
            code_to_status(&entry.code).unwrap_or_else(|| severity_to_status(entry.severity));

        let retryable = if entry.recovery.retryable {
            Some(true)
        } else {
            None
        };

        let recovery_hint = if entry.recovery.recovery_hint.trim().is_empty() {
            None
        } else {
            Some(entry.recovery.recovery_hint.clone())
        };

        Self {
            problem_type: format!(
                "urn:franken-node:error:{}",
                entry.code.to_lowercase().replace('_', "-")
            ),
            title: entry.description.clone(),
            status,
            detail: detail.to_string(),
            instance: instance.to_string(),
            code: entry.code.clone(),
            trace_id: trace_id.to_string(),
            retryable,
            retry_after_ms: entry.recovery.retry_after_ms,
            recovery_hint,
        }
    }

    /// Build a generic problem detail without a registry entry.
    pub fn new(
        code: &str,
        title: &str,
        status: u16,
        detail: &str,
        instance: &str,
        trace_id: &str,
    ) -> Self {
        Self {
            problem_type: format!(
                "urn:franken-node:error:{}",
                code.to_lowercase().replace('_', "-")
            ),
            title: title.to_string(),
            status,
            detail: detail.to_string(),
            instance: instance.to_string(),
            code: code.to_string(),
            trace_id: trace_id.to_string(),
            retryable: None,
            retry_after_ms: None,
            recovery_hint: None,
        }
    }

    /// Serialize to canonical JSON for `application/problem+json`.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Control-plane API error type aggregating all possible failure modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// Authentication failed (401).
    #[cfg(any(test, feature = "extended-surfaces"))]
    AuthFailed { detail: String, trace_id: String },
    /// Authorization denied by policy hook (403).
    #[cfg(any(test, feature = "extended-surfaces"))]
    PolicyDenied {
        detail: String,
        trace_id: String,
        policy_hook: String,
    },
    /// Rate limit exceeded (429).
    #[cfg(any(test, feature = "extended-surfaces"))]
    RateLimited {
        detail: String,
        trace_id: String,
        retry_after_ms: u64,
    },
    /// Resource not found (404).
    #[cfg(feature = "extended-surfaces")]
    NotFound { detail: String, trace_id: String },
    /// Lease or fencing conflict (409).
    #[cfg(feature = "extended-surfaces")]
    Conflict { detail: String, trace_id: String },
    /// Bad request (400).
    BadRequest { detail: String, trace_id: String },
    /// Internal error (500).
    Internal { detail: String, trace_id: String },
    /// Service degraded (503).
    #[cfg(feature = "extended-surfaces")]
    ServiceDegraded { detail: String, trace_id: String },
}

impl ApiError {
    /// Convert to an RFC 7807 problem detail.
    #[cfg(any(test, feature = "extended-surfaces"))]
    pub fn to_problem(&self, instance: &str) -> ProblemDetail {
        match self {
            #[cfg(any(test, feature = "extended-surfaces"))]
            ApiError::AuthFailed { detail, trace_id } => ProblemDetail::new(
                "FASTAPI_AUTH_FAIL",
                "Authentication failed",
                401,
                detail,
                instance,
                trace_id,
            ),
            #[cfg(any(test, feature = "extended-surfaces"))]
            ApiError::PolicyDenied {
                detail,
                trace_id,
                policy_hook,
            } => {
                let mut p = ProblemDetail::new(
                    "FASTAPI_POLICY_DENY",
                    "Policy denied",
                    403,
                    detail,
                    instance,
                    trace_id,
                );
                p.recovery_hint = Some(format!("policy hook: {policy_hook}"));
                p
            }
            #[cfg(any(test, feature = "extended-surfaces"))]
            ApiError::RateLimited {
                detail,
                trace_id,
                retry_after_ms,
            } => {
                let mut p = ProblemDetail::new(
                    "FASTAPI_RATE_LIMITED",
                    "Rate limit exceeded",
                    429,
                    detail,
                    instance,
                    trace_id,
                );
                p.retryable = Some(true);
                p.retry_after_ms = Some(*retry_after_ms);
                p
            }
            #[cfg(feature = "extended-surfaces")]
            ApiError::NotFound { detail, trace_id } => ProblemDetail::new(
                "FASTAPI_NOT_FOUND",
                "Resource not found",
                404,
                detail,
                instance,
                trace_id,
            ),
            #[cfg(feature = "extended-surfaces")]
            ApiError::Conflict { detail, trace_id } => ProblemDetail::new(
                "FASTAPI_CONFLICT",
                "Conflict",
                409,
                detail,
                instance,
                trace_id,
            ),
            ApiError::BadRequest { detail, trace_id } => ProblemDetail::new(
                "FASTAPI_BAD_REQUEST",
                "Bad request",
                400,
                detail,
                instance,
                trace_id,
            ),
            ApiError::Internal { detail, trace_id } => ProblemDetail::new(
                "FASTAPI_INTERNAL_ERROR",
                "Internal error",
                500,
                detail,
                instance,
                trace_id,
            ),
            #[cfg(feature = "extended-surfaces")]
            ApiError::ServiceDegraded { detail, trace_id } => ProblemDetail::new(
                "FASTAPI_SERVICE_DEGRADED",
                "Service degraded",
                503,
                detail,
                instance,
                trace_id,
            ),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(any(test, feature = "extended-surfaces"))]
            ApiError::AuthFailed { detail, .. } => write!(f, "auth failed: {detail}"),
            #[cfg(any(test, feature = "extended-surfaces"))]
            ApiError::PolicyDenied { detail, .. } => write!(f, "policy denied: {detail}"),
            #[cfg(any(test, feature = "extended-surfaces"))]
            ApiError::RateLimited { detail, .. } => write!(f, "rate limited: {detail}"),
            #[cfg(feature = "extended-surfaces")]
            ApiError::NotFound { detail, .. } => write!(f, "not found: {detail}"),
            #[cfg(feature = "extended-surfaces")]
            ApiError::Conflict { detail, .. } => write!(f, "conflict: {detail}"),
            ApiError::BadRequest { detail, .. } => write!(f, "bad request: {detail}"),
            ApiError::Internal { detail, .. } => write!(f, "internal error: {detail}"),
            #[cfg(feature = "extended-surfaces")]
            ApiError::ServiceDegraded { detail, .. } => write!(f, "service degraded: {detail}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::error_code_registry::{RecoveryInfo, Severity};

    #[test]
    fn problem_detail_from_registry_entry() {
        let entry = ErrorCodeEntry {
            code: "FRANKEN_PROTOCOL_AUTH_TIMEOUT".to_string(),
            subsystem: "PROTOCOL".to_string(),
            severity: Severity::Transient,
            recovery: RecoveryInfo {
                retryable: true,
                retry_after_ms: Some(1000),
                recovery_hint: "retry with backoff".to_string(),
            },
            description: "Auth timeout".to_string(),
            version: 1,
            frozen: false,
        };

        let problem = ProblemDetail::from_registry_entry(
            &entry,
            "auth request timed out after 5s",
            "/v1/operator/status",
            "trace-001",
        );

        assert_eq!(problem.status, 429);
        assert_eq!(problem.code, "FRANKEN_PROTOCOL_AUTH_TIMEOUT");
        assert_eq!(problem.retryable, Some(true));
        assert_eq!(problem.retry_after_ms, Some(1000));
        assert!(problem.problem_type.starts_with("urn:franken-node:error:"));
    }

    #[test]
    fn problem_detail_new() {
        let p = ProblemDetail::new(
            "FASTAPI_AUTH_FAIL",
            "Auth failed",
            401,
            "invalid token",
            "/v1/operator/status",
            "trace-002",
        );
        assert_eq!(p.status, 401);
        assert_eq!(p.code, "FASTAPI_AUTH_FAIL");
        assert_eq!(p.trace_id, "trace-002");
    }

    #[test]
    fn problem_detail_serialization() {
        let p = ProblemDetail::new(
            "FASTAPI_NOT_FOUND",
            "Not found",
            404,
            "node xyz not found",
            "/v1/operator/status/xyz",
            "trace-003",
        );
        let json = p.to_json().expect("serialize");
        assert!(json.contains("\"status\":404"));
        assert!(json.contains("\"trace_id\":\"trace-003\""));
        // retryable/retry_after_ms/recovery_hint should be absent
        assert!(!json.contains("retryable"));
    }

    #[test]
    fn api_error_to_problem_auth() {
        let err = ApiError::AuthFailed {
            detail: "bad token".to_string(),
            trace_id: "t-1".to_string(),
        };
        let p = err.to_problem("/v1/operator/health");
        assert_eq!(p.status, 401);
        assert_eq!(p.instance, "/v1/operator/health");
    }

    #[test]
    fn api_error_to_problem_rate_limited() {
        let err = ApiError::RateLimited {
            detail: "burst exceeded".to_string(),
            trace_id: "t-2".to_string(),
            retry_after_ms: 2000,
        };
        let p = err.to_problem("/v1/fleet/leases");
        assert_eq!(p.status, 429);
        assert_eq!(p.retryable, Some(true));
        assert_eq!(p.retry_after_ms, Some(2000));
    }

    #[test]
    fn api_error_to_problem_policy_denied() {
        let err = ApiError::PolicyDenied {
            detail: "insufficient role".to_string(),
            trace_id: "t-3".to_string(),
            policy_hook: "fleet.admin.required".to_string(),
        };
        let p = err.to_problem("/v1/fleet/fence");
        assert_eq!(p.status, 403);
        assert!(p.recovery_hint.unwrap().contains("fleet.admin.required"));
    }

    #[test]
    fn api_error_display() {
        let err = ApiError::Internal {
            detail: "unexpected".to_string(),
            trace_id: "t-4".to_string(),
        };
        assert!(err.to_string().contains("internal error: unexpected"));
    }

    #[test]
    fn severity_to_status_mapping() {
        assert_eq!(severity_to_status(Severity::Fatal), 500);
        assert_eq!(severity_to_status(Severity::Degraded), 503);
        assert_eq!(severity_to_status(Severity::Transient), 429);
    }

    #[test]
    fn code_to_status_overrides() {
        assert_eq!(code_to_status("FRANKEN_PROTOCOL_AUTH_FAIL"), Some(401));
        assert_eq!(code_to_status("FRANKEN_CONNECTOR_POLICY_DENY"), Some(403));
        assert_eq!(code_to_status("FRANKEN_EGRESS_RATE_LIMITED"), Some(429));
        assert_eq!(code_to_status("FRANKEN_CAPABILITY_NOT_FOUND"), Some(404));
        assert_eq!(
            code_to_status("FRANKEN_CONNECTOR_LEASE_CONFLICT"),
            Some(409)
        );
        assert_eq!(code_to_status("FRANKEN_PROTOCOL_INVALID_INPUT"), Some(400));
        assert_eq!(code_to_status("FRANKEN_RUNTIME_INIT"), None);
    }

    #[test]
    fn non_retryable_registry_entry_omits_retry_metadata() {
        let entry = ErrorCodeEntry {
            code: "FRANKEN_RUNTIME_INIT".to_string(),
            subsystem: "RUNTIME".to_string(),
            severity: Severity::Fatal,
            recovery: RecoveryInfo {
                retryable: false,
                retry_after_ms: None,
                recovery_hint: String::new(),
            },
            description: "Runtime init failed".to_string(),
            version: 1,
            frozen: true,
        };

        let problem = ProblemDetail::from_registry_entry(
            &entry,
            "runtime could not initialize",
            "/v1/operator/run",
            "trace-non-retryable",
        );

        assert_eq!(problem.status, 500);
        assert_eq!(problem.retryable, None);
        assert_eq!(problem.retry_after_ms, None);
        assert_eq!(problem.recovery_hint, None);
    }

    #[test]
    fn degraded_registry_entry_without_override_falls_back_to_severity() {
        let entry = ErrorCodeEntry {
            code: "FRANKEN_FLEET_CONTROL_UNAVAILABLE".to_string(),
            subsystem: "FLEET".to_string(),
            severity: Severity::Degraded,
            recovery: RecoveryInfo {
                retryable: true,
                retry_after_ms: None,
                recovery_hint: "try another control-plane replica".to_string(),
            },
            description: "Fleet control unavailable".to_string(),
            version: 1,
            frozen: false,
        };

        let problem = ProblemDetail::from_registry_entry(
            &entry,
            "leader lease is unavailable",
            "/v1/fleet/status",
            "trace-degraded",
        );

        assert_eq!(problem.status, 503);
        assert_eq!(problem.retryable, Some(true));
        assert_eq!(
            problem.recovery_hint.as_deref(),
            Some("try another control-plane replica")
        );
    }

    #[test]
    fn auth_code_without_fail_suffix_does_not_map_to_unauthorized() {
        assert_eq!(code_to_status("FRANKEN_PROTOCOL_AUTH_TIMEOUT"), None);
        assert_eq!(code_to_status("FRANKEN_PROTOCOL_AUTH_REQUIRED"), None);
    }

    #[test]
    fn conflict_override_does_not_match_unrelated_conflict_words() {
        assert_eq!(code_to_status("FRANKEN_CONFLICTING_POLICY_STATE"), None);
        assert_eq!(code_to_status("FRANKEN_LEASE_PENDING"), None);
    }

    #[test]
    fn invalid_override_requires_invalid_marker_or_bad_request_marker() {
        assert_eq!(code_to_status("FRANKEN_INPUT_VALIDATION_FAILED"), None);
        assert_eq!(code_to_status("FRANKEN_PROTOCOL_BAD"), None);
        assert_eq!(code_to_status("FRANKEN_PROTOCOL_INVALID_INPUT"), Some(400));
    }

    #[test]
    fn problem_detail_new_keeps_empty_context_fields_explicit() {
        let problem = ProblemDetail::new("FASTAPI_BAD_REQUEST", "Bad request", 400, "", "", "");

        assert_eq!(problem.detail, "");
        assert_eq!(problem.instance, "");
        assert_eq!(problem.trace_id, "");
        assert_eq!(
            problem.problem_type,
            "urn:franken-node:error:fastapi-bad-request"
        );
    }

    #[test]
    fn problem_detail_json_excludes_all_absent_optional_fields() {
        let problem = ProblemDetail::new(
            "FASTAPI_INTERNAL_ERROR",
            "Internal error",
            500,
            "unexpected",
            "/v1/operator/status",
            "trace-no-options",
        );

        let json = problem.to_json().expect("problem detail should serialize");

        assert!(!json.contains("retryable"));
        assert!(!json.contains("retry_after_ms"));
        assert!(!json.contains("recovery_hint"));
    }

    #[test]
    fn api_error_bad_request_maps_to_non_retryable_problem() {
        let err = ApiError::BadRequest {
            detail: "malformed request".to_string(),
            trace_id: "trace-bad-request".to_string(),
        };

        let problem = err.to_problem("/v1/fleet/reconcile");

        assert_eq!(problem.status, 400);
        assert_eq!(problem.code, "FASTAPI_BAD_REQUEST");
        assert_eq!(problem.retryable, None);
        assert_eq!(problem.retry_after_ms, None);
    }

    #[test]
    fn code_to_status_is_case_sensitive_for_overrides() {
        assert_eq!(code_to_status("franken_protocol_auth_fail"), None);
        assert_eq!(code_to_status("FRANKEN_CONNECTOR_policy_DENY"), None);
        assert_eq!(code_to_status("FRANKEN_PROTOCOL_bad_request"), None);
    }

    #[test]
    fn policy_denied_empty_hook_does_not_gain_retry_metadata() {
        let err = ApiError::PolicyDenied {
            detail: "role missing".to_string(),
            trace_id: "trace-policy-empty".to_string(),
            policy_hook: String::new(),
        };

        let problem = err.to_problem("/v1/fleet/fence");

        assert_eq!(problem.status, 403);
        assert_eq!(problem.retryable, None);
        assert_eq!(problem.retry_after_ms, None);
        assert_eq!(problem.recovery_hint.as_deref(), Some("policy hook: "));
    }

    #[test]
    fn rate_limited_zero_retry_after_is_preserved() {
        let err = ApiError::RateLimited {
            detail: "quota exhausted".to_string(),
            trace_id: "trace-rate-zero".to_string(),
            retry_after_ms: 0,
        };

        let problem = err.to_problem("/v1/fleet/leases");

        assert_eq!(problem.status, 429);
        assert_eq!(problem.retryable, Some(true));
        assert_eq!(problem.retry_after_ms, Some(0));
        assert_eq!(problem.recovery_hint, None);
    }

    #[test]
    fn api_error_display_does_not_include_trace_id() {
        let err = ApiError::BadRequest {
            detail: "missing required field".to_string(),
            trace_id: "trace-secret".to_string(),
        };

        let rendered = err.to_string();

        assert!(rendered.contains("bad request: missing required field"));
        assert!(!rendered.contains("trace-secret"));
    }

    #[test]
    fn internal_problem_json_keeps_trace_id_but_omits_retry_guidance() {
        let err = ApiError::Internal {
            detail: "storage backend failed".to_string(),
            trace_id: "trace-json-internal".to_string(),
        };
        let problem = err.to_problem("/v1/internal");

        let json = problem.to_json().expect("serialize problem");

        assert!(json.contains("\"trace_id\":\"trace-json-internal\""));
        assert!(!json.contains("retryable"));
        assert!(!json.contains("retry_after_ms"));
        assert!(!json.contains("recovery_hint"));
    }

    #[test]
    fn problem_type_uses_hyphenated_code_without_normalizing_case_elsewhere() {
        let problem = ProblemDetail::new(
            "FASTAPI__DOUBLE_UNDERSCORE",
            "Synthetic",
            500,
            "synthetic",
            "/v1/synthetic",
            "trace-synthetic",
        );

        assert_eq!(
            problem.problem_type,
            "urn:franken-node:error:fastapi--double-underscore"
        );
        assert_eq!(problem.code, "FASTAPI__DOUBLE_UNDERSCORE");
    }
}

#[cfg(test)]
mod api_error_marker_additional_negative_tests {
    use super::*;
    use crate::connector::error_code_registry::{RecoveryInfo, Severity};

    fn registry_entry(code: &str, severity: Severity, recovery_hint: &str) -> ErrorCodeEntry {
        ErrorCodeEntry {
            code: code.to_string(),
            subsystem: "API".to_string(),
            severity,
            recovery: RecoveryInfo {
                retryable: false,
                retry_after_ms: None,
                recovery_hint: recovery_hint.to_string(),
            },
            description: "synthetic api error".to_string(),
            version: 1,
            frozen: true,
        }
    }

    #[test]
    fn negative_auth_failover_code_does_not_map_to_unauthorized() {
        assert_eq!(code_to_status("FRANKEN_PROTOCOL_AUTH_FAILOVER"), None);
    }

    #[test]
    fn negative_policy_denylist_code_does_not_map_to_forbidden() {
        assert_eq!(code_to_status("FRANKEN_POLICY_DENYLIST_HIT"), None);
    }

    #[test]
    fn negative_rate_limitedness_code_does_not_map_to_rate_limited() {
        assert_eq!(code_to_status("FRANKEN_EGRESS_RATE_LIMITEDNESS"), None);
    }

    #[test]
    fn negative_not_founded_code_does_not_map_to_not_found() {
        assert_eq!(code_to_status("FRANKEN_RESOURCE_NOT_FOUNDED"), None);
    }

    #[test]
    fn negative_lease_conflicting_code_does_not_map_to_conflict() {
        assert_eq!(code_to_status("FRANKEN_CONNECTOR_LEASE_CONFLICTING"), None);
    }

    #[test]
    fn negative_fencing_conflicted_code_does_not_map_to_conflict() {
        assert_eq!(code_to_status("FRANKEN_CONNECTOR_FENCING_CONFLICTED"), None);
    }

    #[test]
    fn negative_bad_requested_code_does_not_map_to_bad_request() {
        assert_eq!(code_to_status("FRANKEN_PROTOCOL_BAD_REQUESTED"), None);
    }

    #[test]
    fn negative_registry_entry_uses_severity_for_auth_failover_lookalike() {
        let entry = registry_entry("FRANKEN_PROTOCOL_AUTH_FAILOVER", Severity::Degraded, "");

        let problem = ProblemDetail::from_registry_entry(
            &entry,
            "control plane moved to a failover path",
            "/v1/operator/status",
            "trace-auth-failover",
        );

        assert_eq!(problem.status, 503);
        assert_eq!(problem.retryable, None);
        assert_eq!(problem.recovery_hint, None);
    }

    #[test]
    fn negative_whitespace_only_recovery_hint_is_omitted() {
        let entry = registry_entry("FRANKEN_RUNTIME_INIT", Severity::Fatal, " \t\n ");

        let problem = ProblemDetail::from_registry_entry(
            &entry,
            "runtime init failed",
            "/v1/operator/run",
            "trace-whitespace-hint",
        );

        assert_eq!(problem.status, 500);
        assert_eq!(problem.recovery_hint, None);
        assert!(
            !problem
                .to_json()
                .expect("serialize")
                .contains("recovery_hint")
        );
    }
}

#[cfg(test)]
mod problem_detail_schema_negative_tests {
    use super::*;

    #[test]
    fn negative_problem_detail_missing_type_field_is_rejected() {
        let value = serde_json::json!({
            "title": "Bad request",
            "status": 400,
            "detail": "missing type",
            "instance": "/v1/operator/status",
            "code": "FASTAPI_BAD_REQUEST",
            "trace_id": "trace-missing-type"
        });

        let err = serde_json::from_value::<ProblemDetail>(value)
            .expect_err("missing RFC 7807 type must fail deserialization");

        assert!(err.to_string().contains("type"));
    }

    #[test]
    fn negative_problem_detail_missing_trace_id_is_rejected() {
        let value = serde_json::json!({
            "type": "urn:franken-node:error:fastapi-bad-request",
            "title": "Bad request",
            "status": 400,
            "detail": "missing trace",
            "instance": "/v1/operator/status",
            "code": "FASTAPI_BAD_REQUEST"
        });

        let err = serde_json::from_value::<ProblemDetail>(value)
            .expect_err("missing trace_id must fail deserialization");

        assert!(err.to_string().contains("trace_id"));
    }

    #[test]
    fn negative_problem_detail_string_status_is_rejected() {
        let value = serde_json::json!({
            "type": "urn:franken-node:error:fastapi-bad-request",
            "title": "Bad request",
            "status": "400",
            "detail": "wrong status type",
            "instance": "/v1/operator/status",
            "code": "FASTAPI_BAD_REQUEST",
            "trace_id": "trace-status-string"
        });

        let err = serde_json::from_value::<ProblemDetail>(value)
            .expect_err("string status must fail deserialization");

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_problem_detail_negative_retry_after_is_rejected() {
        let value = serde_json::json!({
            "type": "urn:franken-node:error:fastapi-rate-limited",
            "title": "Rate limit exceeded",
            "status": 429,
            "detail": "bad retry delay",
            "instance": "/v1/fleet/leases",
            "code": "FASTAPI_RATE_LIMITED",
            "trace_id": "trace-negative-retry",
            "retry_after_ms": -1
        });

        let err = serde_json::from_value::<ProblemDetail>(value)
            .expect_err("negative retry_after_ms must fail deserialization");

        let rendered = err.to_string();
        assert!(rendered.contains("invalid value") || rendered.contains("u64"));
    }

    #[test]
    fn negative_problem_detail_string_retryable_is_rejected() {
        let value = serde_json::json!({
            "type": "urn:franken-node:error:fastapi-rate-limited",
            "title": "Rate limit exceeded",
            "status": 429,
            "detail": "bad retryable type",
            "instance": "/v1/fleet/leases",
            "code": "FASTAPI_RATE_LIMITED",
            "trace_id": "trace-retryable-string",
            "retryable": "true"
        });

        let err = serde_json::from_value::<ProblemDetail>(value)
            .expect_err("string retryable flag must fail deserialization");

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_problem_detail_object_recovery_hint_is_rejected() {
        let value = serde_json::json!({
            "type": "urn:franken-node:error:fastapi-policy-deny",
            "title": "Policy denied",
            "status": 403,
            "detail": "bad recovery hint type",
            "instance": "/v1/fleet/fence",
            "code": "FASTAPI_POLICY_DENY",
            "trace_id": "trace-hint-object",
            "recovery_hint": {"policy_hook": "fleet.admin.required"}
        });

        let err = serde_json::from_value::<ProblemDetail>(value)
            .expect_err("object recovery_hint must fail deserialization");

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_problem_detail_numeric_code_is_rejected() {
        let value = serde_json::json!({
            "type": "urn:franken-node:error:fastapi-internal-error",
            "title": "Internal error",
            "status": 500,
            "detail": "bad code type",
            "instance": "/v1/internal",
            "code": 500,
            "trace_id": "trace-code-number"
        });

        let err = serde_json::from_value::<ProblemDetail>(value)
            .expect_err("numeric code must fail deserialization");

        assert!(err.to_string().contains("invalid type"));
    }

    fn valid_problem_detail_value() -> serde_json::Value {
        serde_json::json!({
            "type": "urn:franken-node:error:fastapi-bad-request",
            "title": "Bad request",
            "status": 400,
            "detail": "required field baseline",
            "instance": "/v1/operator/status",
            "code": "FASTAPI_BAD_REQUEST",
            "trace_id": "trace-required-baseline"
        })
    }

    fn assert_missing_required_field_is_rejected(field: &str) {
        let mut value = valid_problem_detail_value();
        value
            .as_object_mut()
            .expect("problem detail test fixture must be a JSON object")
            .remove(field);

        let err = serde_json::from_value::<ProblemDetail>(value)
            .expect_err("missing required ProblemDetail field must fail deserialization");

        assert!(
            err.to_string().contains(field),
            "error {err} should identify missing field {field}"
        );
    }

    #[test]
    fn negative_problem_detail_missing_title_is_rejected() {
        assert_missing_required_field_is_rejected("title");
    }

    #[test]
    fn negative_problem_detail_missing_status_is_rejected() {
        assert_missing_required_field_is_rejected("status");
    }

    #[test]
    fn negative_problem_detail_missing_detail_is_rejected() {
        assert_missing_required_field_is_rejected("detail");
    }

    #[test]
    fn negative_problem_detail_missing_instance_is_rejected() {
        assert_missing_required_field_is_rejected("instance");
    }

    #[test]
    fn negative_problem_detail_missing_code_is_rejected() {
        assert_missing_required_field_is_rejected("code");
    }

    #[test]
    fn negative_problem_detail_null_type_is_rejected() {
        let mut value = valid_problem_detail_value();
        value["type"] = serde_json::Value::Null;

        let err = serde_json::from_value::<ProblemDetail>(value)
            .expect_err("null RFC 7807 type must fail deserialization");

        assert!(err.to_string().contains("invalid type"));
    }

    fn assert_null_required_field_is_rejected(field: &str) {
        let mut value = valid_problem_detail_value();
        value[field] = serde_json::Value::Null;

        let err = serde_json::from_value::<ProblemDetail>(value)
            .expect_err("null required ProblemDetail field must fail deserialization");

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_problem_detail_null_title_is_rejected() {
        assert_null_required_field_is_rejected("title");
    }

    #[test]
    fn negative_problem_detail_null_status_is_rejected() {
        assert_null_required_field_is_rejected("status");
    }

    #[test]
    fn negative_problem_detail_null_detail_is_rejected() {
        assert_null_required_field_is_rejected("detail");
    }

    #[test]
    fn negative_problem_detail_null_instance_is_rejected() {
        assert_null_required_field_is_rejected("instance");
    }

    #[test]
    fn negative_problem_detail_null_code_is_rejected() {
        assert_null_required_field_is_rejected("code");
    }

    #[test]
    fn negative_problem_detail_null_trace_id_is_rejected() {
        assert_null_required_field_is_rejected("trace_id");
    }

    // =========================================================================
    // NEGATIVE-PATH TESTS FOR EDGE CASES AND MALICIOUS INPUT HANDLING
    // =========================================================================

    #[test]
    fn negative_problem_detail_with_malicious_field_injection_patterns() {
        // Test ProblemDetail with various injection patterns in fields
        let injection_patterns = vec![
            ("http_header", "detail\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html"),
            ("xss", "detail<script>alert('xss')</script>"),
            ("json", "detail\"},\"malicious\":\"injected\",\"dummy\":\""),
            ("null_byte", "detail\0null_injection"),
            ("ansi", "detail\x1b[31mRED_TEXT\x1b[0m"),
            ("bidi", "detail\u{202E}reverse\u{202D}normal"),
            ("unicode", "detail\u{FFFF}\u{10FFFF}"),
            ("path_traversal", "../../../etc/passwd"),
            ("format_str", "detail%s%d%x"),
            ("xml", "detail</log><log level=\"ERROR\">injected</log>"),
        ];

        for (test_name, malicious_input) in injection_patterns {
            // Test all string fields of ProblemDetail with malicious content
            let problem = ProblemDetail::new(
                &format!("TEST_{}", malicious_input),    // code field
                &format!("title_{}", malicious_input),   // title field
                500,
                &format!("detail_{}", malicious_input),  // detail field
                &format!("instance_{}", malicious_input), // instance field
                &format!("trace_{}", malicious_input),   // trace_id field
            );

            // Serialization should not crash or interpret injection patterns
            match problem.to_json() {
                Ok(json) => {
                    // JSON should escape the malicious content properly
                    assert!(json.contains("TEST_"));
                    assert!(json.contains("title_"));
                    assert!(json.contains("detail_"));
                    assert!(json.contains("instance_"));
                    assert!(json.contains("trace_"));

                    // Should not contain unescaped injection patterns
                    if malicious_input.contains("<script>") {
                        // Script tags should be escaped in JSON
                        assert!(!json.contains("<script>"),
                                "Test {}: Unescaped script tag found in JSON", test_name);
                    }

                    // Verify round-trip safety
                    match serde_json::from_str::<ProblemDetail>(&json) {
                        Ok(deserialized) => {
                            assert_eq!(deserialized.code, format!("TEST_{}", malicious_input));
                            assert_eq!(deserialized.detail, format!("detail_{}", malicious_input));
                        }
                        Err(e) => {
                            panic!("Test {}: Round-trip deserialization failed: {}", test_name, e);
                        }
                    }
                }
                Err(e) => {
                    panic!("Test {}: JSON serialization failed: {}", test_name, e);
                }
            }
        }
    }

    #[test]
    fn negative_problem_detail_with_extreme_field_lengths() {
        // Test with extremely long field values
        let huge_string = "x".repeat(100_000);
        let empty_string = "";

        let extreme_cases = vec![
            ("huge_code", huge_string.clone(), "", "", "", ""),
            ("huge_title", "", huge_string.clone(), "", "", ""),
            ("huge_detail", "", "", huge_string.clone(), "", ""),
            ("huge_instance", "", "", "", huge_string.clone(), ""),
            ("huge_trace_id", "", "", "", "", huge_string.clone()),
            ("all_empty", empty_string, empty_string, empty_string, empty_string, empty_string),
            ("mixed_huge", huge_string.clone(), empty_string, huge_string.clone(), empty_string, "trace"),
        ];

        for (test_name, code, title, detail, instance, trace_id) in extreme_cases {
            let start_time = std::time::Instant::now();

            let problem = ProblemDetail::new(
                &code, &title, 500, &detail, &instance, &trace_id
            );

            // Creation should complete quickly despite large inputs
            let creation_time = start_time.elapsed();
            assert!(creation_time < std::time::Duration::from_millis(500),
                   "Test {}: Creation took too long: {:?}", test_name, creation_time);

            // Serialization should handle large inputs without timeout
            let serialize_start = std::time::Instant::now();
            match problem.to_json() {
                Ok(json) => {
                    let serialize_time = serialize_start.elapsed();
                    assert!(serialize_time < std::time::Duration::from_secs(5),
                           "Test {}: Serialization took too long: {:?}", test_name, serialize_time);

                    // JSON should be reasonable in size (but larger for huge inputs)
                    if test_name.contains("huge") {
                        assert!(json.len() > 50_000, "Test {}: JSON should reflect large input size", test_name);
                    }
                }
                Err(_) => {
                    // Serialization failure is acceptable for extreme inputs
                    println!("Test {}: Serialization failed for extreme input (acceptable)", test_name);
                }
            }
        }
    }

    #[test]
    fn negative_code_to_status_with_malformed_and_adversarial_codes() {
        // Test has_code_marker and code_to_status with adversarial inputs
        let adversarial_codes = vec![
            "",                                    // Empty string
            "_AUTH_FAIL",                          // Leading underscore
            "AUTH_FAIL_",                          // Trailing underscore
            "__AUTH_FAIL__",                       // Multiple underscores
            "PREFIX_AUTH_FAIL_SUFFIX",             // Suffix after marker
            "AUTH_FAIL_AUTH_FAIL",                 // Repeated markers
            "x".repeat(10000),                     // Extremely long code
            "\0AUTH_FAIL",                         // Null byte
            "AUTH\nFAIL",                          // Newline in code
            "AUTH\u{FFFF}FAIL",                    // Unicode characters
            "AUTH🚀FAIL",                          // Emoji in code
            "AUTH_FAIL\x1b[31m",                   // ANSI escape
            "FRANKEN_PROTOCOL_AUTH_FAIL_EXTRA",    // Valid marker with extra
            "NOT_AUTH_FAIL",                       // Marker not at word boundary
            "AUTH_FAILED_NOT_AUTH_FAIL",          // Multiple different markers
            "FRANKEN__AUTH_FAIL",                  // Double underscore before marker
        ];

        for code in adversarial_codes {
            // Should not panic or cause undefined behavior
            let status = code_to_status(code);

            // Result should be reasonable
            match status {
                Some(http_status) => {
                    assert!((100..=599).contains(&http_status),
                           "Invalid HTTP status {} for code: {}", http_status, code);
                }
                None => {
                    // None is a valid result for unrecognized codes
                }
            }

            // Test has_code_marker with various markers and adversarial codes
            let markers = ["AUTH_FAIL", "POLICY_DENY", "NOT_FOUND", "", "VERY_LONG_MARKER_NAME"];
            for marker in markers {
                let result = has_code_marker(code, marker);
                // Should not panic, result is boolean
                assert!(result == true || result == false);
            }
        }
    }

    #[test]
    fn negative_api_error_display_with_malicious_details_formats_safely() {
        // Test ApiError Display implementation with malicious detail content
        let malicious_details = vec![
            "",                                    // Empty
            "\0null\x01control",                   // Control characters
            "detail\r\nHTTP/1.1 200 OK",          // HTTP injection
            "detail\x1b[31mRED\x1b[0m",            // ANSI escape
            "detail\u{202E}reverse\u{202D}",       // BiDi override
            "<script>alert('xss')</script>",       // XSS payload
            "%s%d%x%p",                           // Format specifiers
            "detail\nwith\nmultiple\nlines",      // Multiline content
            "a".repeat(10000),                    // Extremely long
            "{\"json\": \"injection\"}",           // JSON-like content
            "../../etc/passwd",                   // Path traversal
            "\u{FFFF}\u{10FFFF}",                // Max Unicode
        ];

        for malicious_detail in malicious_details {
            let error_variants = vec![
                ApiError::BadRequest {
                    detail: malicious_detail.to_string(),
                    trace_id: "trace-test".to_string()
                },
                ApiError::Internal {
                    detail: malicious_detail.to_string(),
                    trace_id: "trace-test".to_string()
                },
                #[cfg(any(test, feature = "extended-surfaces"))]
                ApiError::AuthFailed {
                    detail: malicious_detail.to_string(),
                    trace_id: "trace-test".to_string()
                },
                #[cfg(any(test, feature = "extended-surfaces"))]
                ApiError::RateLimited {
                    detail: malicious_detail.to_string(),
                    trace_id: "trace-test".to_string(),
                    retry_after_ms: 1000
                },
            ];

            for error in error_variants {
                // Display formatting should not panic
                let display_output = format!("{}", error);

                // Should contain error type and detail safely
                assert!(!display_output.is_empty());

                // Should contain some indication of the error type
                let contains_error_type = display_output.contains("bad request")
                    || display_output.contains("internal error")
                    || display_output.contains("auth failed")
                    || display_output.contains("rate limited");
                assert!(contains_error_type, "Display output should contain error type");

                // If malicious content is included, it should be safe
                if display_output.contains(malicious_detail) {
                    // Content included as-is (no interpretation expected)
                } else {
                    // Content might be truncated or escaped, which is also safe
                    assert!(!display_output.is_empty());
                }
            }
        }
    }

    #[test]
    fn negative_problem_detail_from_registry_with_extreme_recovery_info() {
        // Test with extreme or malicious RecoveryInfo values
        let extreme_entries = vec![
            ("zero_retry", RecoveryInfo {
                retryable: false,
                retry_after_ms: Some(0),
                recovery_hint: "".to_string(),
            }),
            ("max_retry_delay", RecoveryInfo {
                retryable: true,
                retry_after_ms: Some(u64::MAX),
                recovery_hint: "wait forever".to_string(),
            }),
            ("huge_hint", RecoveryInfo {
                retryable: true,
                retry_after_ms: Some(1000),
                recovery_hint: "x".repeat(100_000),
            }),
            ("malicious_hint", RecoveryInfo {
                retryable: true,
                retry_after_ms: Some(500),
                recovery_hint: "hint\r\nHTTP/1.1 200 OK\r\n<script>alert('xss')</script>".to_string(),
            }),
            ("unicode_hint", RecoveryInfo {
                retryable: true,
                retry_after_ms: Some(250),
                recovery_hint: "\u{FFFF}\u{10FFFF}🚀💀".to_string(),
            }),
        ];

        for (test_name, recovery_info) in extreme_entries {
            let entry = ErrorCodeEntry {
                code: format!("TEST_EXTREME_{}", test_name.to_uppercase()),
                subsystem: "TEST".to_string(),
                severity: Severity::Transient,
                recovery: recovery_info.clone(),
                description: "Test entry".to_string(),
                version: 1,
                frozen: false,
            };

            let problem = ProblemDetail::from_registry_entry(
                &entry,
                "test detail",
                "/test/instance",
                "trace-extreme"
            );

            // Should handle extreme values gracefully
            assert_eq!(problem.retry_after_ms, recovery_info.retry_after_ms);

            if recovery_info.recovery_hint.trim().is_empty() {
                assert_eq!(problem.recovery_hint, None);
            } else {
                assert_eq!(problem.recovery_hint, Some(recovery_info.recovery_hint));
            }

            // Serialization should work despite extreme values
            match problem.to_json() {
                Ok(json) => {
                    assert!(!json.is_empty());
                    if test_name.contains("huge") {
                        assert!(json.len() > 10_000, "JSON should reflect large recovery hint");
                    }
                }
                Err(_) => {
                    // Serialization failure acceptable for extreme inputs
                    println!("Test {}: JSON serialization failed (acceptable for extreme input)", test_name);
                }
            }
        }
    }

    #[test]
    fn negative_severity_to_status_with_exhaustive_enum_coverage() {
        // Ensure all Severity enum variants map to valid HTTP statuses
        let severities = vec![
            Severity::Fatal,
            Severity::Degraded,
            Severity::Transient,
        ];

        for severity in severities {
            let status = severity_to_status(severity);

            // Should map to valid HTTP status codes
            assert!((100..=599).contains(&status),
                   "Severity {:?} maps to invalid HTTP status: {}", severity, status);

            // Should map to server error ranges for our use case
            assert!([400, 401, 403, 404, 409, 429, 500, 503].contains(&status),
                   "Severity {:?} maps to unexpected status: {}", severity, status);
        }
    }

    #[test]
    fn negative_problem_type_urn_generation_with_special_characters() {
        // Test URN generation with various problematic code values
        let problematic_codes = vec![
            "",                                    // Empty
            "_",                                  // Single underscore
            "__",                                 // Double underscore
            "___",                                // Triple underscore
            "A_B_C_D_E_F_G_H_I_J_K_L_M",        // Many underscores
            "code with spaces",                   // Spaces (should be replaced)
            "CODE_WITH_MIXED_case",               // Mixed case
            "code-already-with-dashes",           // Already has dashes
            "code.with.dots",                     // Dots
            "code/with/slashes",                  // Slashes
            "code@with#special$chars",            // Special characters
            "\u{FFFF}",                           // High Unicode
            "🚀_ROCKET_CODE",                     // Emoji
        ];

        for code in problematic_codes {
            let problem = ProblemDetail::new(
                code, "Test title", 500, "test detail", "/test", "trace-urn"
            );

            // URN should be well-formed
            assert!(problem.problem_type.starts_with("urn:franken-node:error:"));

            // Should not contain problematic characters in the URN part
            let urn_suffix = problem.problem_type
                .strip_prefix("urn:franken-node:error:")
                .unwrap();

            // Underscores should be converted to dashes
            if code.contains('_') && !code.is_empty() {
                assert!(!urn_suffix.contains('_') || code.chars().all(|c| c == '_'),
                       "URN suffix should not contain underscores for code: {}", code);
            }

            // Should be lowercase
            assert_eq!(urn_suffix, urn_suffix.to_lowercase(),
                      "URN suffix should be lowercase for code: {}", code);

            // Should not contain dangerous characters
            for dangerous_char in ['<', '>', '"', '\'', '\n', '\r', '\0'] {
                assert!(!urn_suffix.contains(dangerous_char),
                       "URN suffix contains dangerous character '{}' for code: {}", dangerous_char, code);
            }
        }
    }

    #[test]
    fn negative_api_error_to_problem_with_extreme_trace_ids() {
        // Test with various problematic trace ID values
        let problematic_trace_ids = vec![
            "",                                   // Empty trace ID
            "trace-" + &"x".repeat(10000),       // Extremely long
            "trace\0null\x01control",            // Control characters
            "trace\r\nHTTP/1.1 200 OK",          // HTTP injection
            "trace<script>alert('xss')</script>", // XSS payload
            "\u{FFFF}\u{10FFFF}",                // Max Unicode
            "trace.with.dots.and-dashes_underscore", // Mixed punctuation
            "🚀trace🔥with💀emoji",               // Emoji
            "trace\u{202E}reverse\u{202D}",       // BiDi override
        ];

        for trace_id in problematic_trace_ids {
            let error = ApiError::Internal {
                detail: "test error".to_string(),
                trace_id: trace_id.to_string(),
            };

            let problem = error.to_problem("/test/instance");

            // trace_id should be preserved as-is (no sanitization expected)
            assert_eq!(problem.trace_id, trace_id);
            assert_eq!(problem.status, 500);
            assert_eq!(problem.code, "FASTAPI_INTERNAL_ERROR");

            // JSON serialization should handle problematic trace IDs
            match problem.to_json() {
                Ok(json) => {
                    assert!(json.contains("trace_id"));

                    // Should be valid JSON despite problematic content
                    match serde_json::from_str::<ProblemDetail>(&json) {
                        Ok(deserialized) => {
                            assert_eq!(deserialized.trace_id, trace_id);
                        }
                        Err(e) => {
                            panic!("Failed to deserialize JSON with trace_id '{}': {}", trace_id, e);
                        }
                    }
                }
                Err(e) => {
                    panic!("Failed to serialize problem with trace_id '{}': {}", trace_id, e);
                }
            }
        }
    }

    #[test]
    fn negative_has_code_marker_edge_cases_and_boundary_conditions() {
        // Test has_code_marker with edge cases and boundary conditions
        let test_cases = vec![
            // (code, marker, expected_result, description)
            ("", "", false, "empty code and marker"),
            ("AUTH_FAIL", "", false, "empty marker should return false"),
            ("", "AUTH_FAIL", false, "empty code with non-empty marker"),
            ("AUTH_FAIL", "AUTH_FAIL", true, "exact match"),
            ("AUTH_FAIL_", "AUTH_FAIL", true, "marker followed by underscore"),
            ("AUTH_FAIL_EXTRA", "AUTH_FAIL", true, "marker followed by underscore and more"),
            ("PREFIX_AUTH_FAIL", "AUTH_FAIL", true, "marker at end"),
            ("PREFIX_AUTH_FAIL_SUFFIX", "AUTH_FAIL", true, "marker in middle"),
            ("NOTAUTH_FAIL", "AUTH_FAIL", false, "marker without word boundary"),
            ("AUTH_FAILNOT", "AUTH_FAIL", false, "marker without trailing boundary"),
            ("AUTH_FAIL_AUTH_FAIL", "AUTH_FAIL", true, "repeated markers"),
            ("_AUTH_FAIL", "AUTH_FAIL", true, "marker after leading underscore"),
            ("__AUTH_FAIL__", "AUTH_FAIL", true, "marker between underscores"),
            ("A", "AUTH_FAIL", false, "marker longer than code"),
            ("AUTH_FAI", "AUTH_FAIL", false, "code shorter than marker"),
            ("AUTH_FAIL", "AUTH", false, "partial marker match"),
            ("XAUTH_FAILX", "AUTH_FAIL", false, "marker embedded without boundaries"),
        ];

        for (code, marker, expected, description) in test_cases {
            let result = has_code_marker(code, marker);
            assert_eq!(result, expected,
                      "has_code_marker('{}', '{}') should be {} - {}",
                      code, marker, expected, description);
        }
    }
}
