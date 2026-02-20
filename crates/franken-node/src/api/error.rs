//! RFC 7807 Problem Details error types for the control-plane API.
//!
//! Maps `FRANKEN_*` error codes from the error code registry to structured
//! HTTP problem responses with stable `type`, `title`, `status`, `detail`,
//! `instance`, `code`, and `trace_id` fields.

use serde::{Deserialize, Serialize};

use crate::connector::error_code_registry::{ErrorCodeEntry, Severity};

/// RFC 7807 Problem Details response.
///
/// All control-plane API error responses use this format with
/// `Content-Type: application/problem+json`.
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
fn code_to_status(code: &str) -> Option<u16> {
    match code {
        // Auth/authz failures
        c if c.contains("_AUTH_") && c.contains("FAIL") => Some(401),
        c if c.contains("_POLICY_DENY") => Some(403),
        c if c.contains("_RATE_LIMITED") => Some(429),
        // Not found
        c if c.contains("_NOT_FOUND") => Some(404),
        // Conflict (lease, fencing)
        c if c.contains("_LEASE_CONFLICT") || c.contains("_FENCING_CONFLICT") => Some(409),
        // Bad request
        c if c.contains("_INVALID_") || c.contains("_BAD_REQUEST") => Some(400),
        _ => None,
    }
}

impl ProblemDetail {
    /// Build a problem detail from an error code registry entry.
    pub fn from_registry_entry(
        entry: &ErrorCodeEntry,
        detail: &str,
        instance: &str,
        trace_id: &str,
    ) -> Self {
        let status = code_to_status(&entry.code)
            .unwrap_or_else(|| severity_to_status(entry.severity));

        let retryable = if entry.recovery.retryable {
            Some(true)
        } else {
            None
        };

        let recovery_hint = if entry.recovery.recovery_hint.is_empty() {
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
    AuthFailed { detail: String, trace_id: String },
    /// Authorization denied by policy hook (403).
    PolicyDenied { detail: String, trace_id: String, policy_hook: String },
    /// Rate limit exceeded (429).
    RateLimited { detail: String, trace_id: String, retry_after_ms: u64 },
    /// Resource not found (404).
    NotFound { detail: String, trace_id: String },
    /// Lease or fencing conflict (409).
    Conflict { detail: String, trace_id: String },
    /// Bad request (400).
    BadRequest { detail: String, trace_id: String },
    /// Internal error (500).
    Internal { detail: String, trace_id: String },
    /// Service degraded (503).
    ServiceDegraded { detail: String, trace_id: String },
}

impl ApiError {
    /// Convert to an RFC 7807 problem detail.
    pub fn to_problem(&self, instance: &str) -> ProblemDetail {
        match self {
            ApiError::AuthFailed { detail, trace_id } => ProblemDetail::new(
                "FASTAPI_AUTH_FAIL",
                "Authentication failed",
                401,
                detail,
                instance,
                trace_id,
            ),
            ApiError::PolicyDenied { detail, trace_id, policy_hook } => {
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
            ApiError::RateLimited { detail, trace_id, retry_after_ms } => {
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
            ApiError::NotFound { detail, trace_id } => ProblemDetail::new(
                "FASTAPI_NOT_FOUND",
                "Resource not found",
                404,
                detail,
                instance,
                trace_id,
            ),
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
            ApiError::AuthFailed { detail, .. } => write!(f, "auth failed: {detail}"),
            ApiError::PolicyDenied { detail, .. } => write!(f, "policy denied: {detail}"),
            ApiError::RateLimited { detail, .. } => write!(f, "rate limited: {detail}"),
            ApiError::NotFound { detail, .. } => write!(f, "not found: {detail}"),
            ApiError::Conflict { detail, .. } => write!(f, "conflict: {detail}"),
            ApiError::BadRequest { detail, .. } => write!(f, "bad request: {detail}"),
            ApiError::Internal { detail, .. } => write!(f, "internal error: {detail}"),
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
        assert_eq!(code_to_status("FRANKEN_CONNECTOR_LEASE_CONFLICT"), Some(409));
        assert_eq!(code_to_status("FRANKEN_PROTOCOL_INVALID_INPUT"), Some(400));
        assert_eq!(code_to_status("FRANKEN_RUNTIME_INIT"), None);
    }
}
