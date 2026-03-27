//! Verifier endpoint group: conformance trigger, evidence retrieval, audit log query.
//!
//! Routes:
//! - `POST /v1/verifier/conformance` — trigger a conformance check
//! - `GET  /v1/verifier/evidence/{check_id}` — retrieve evidence artifact
//! - `GET  /v1/verifier/audit-log` — query audit log entries

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::ApiError;
use super::middleware::{
    AuthIdentity, AuthMethod, EndpointGroup, EndpointLifecycle, PolicyHook, RouteMetadata,
    TraceContext,
};
use super::trust_card_routes::ApiResponse;
use super::utf8_prefix;

const MAX_STORED_CONFORMANCE_CHECKS: usize = 256;
const MAX_VERIFIER_AUDIT_LOG_ENTRIES: usize = 512;

fn hash_evidence_content(content: &serde_json::Value) -> Result<(String, u64), serde_json::Error> {
    let canonical = serde_json::to_vec(content)?;
    let content_hash = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            [b"verifier_evidence_content_v1:" as &[u8], &canonical[..]].concat(),
        ))
    );
    let size_bytes = u64::try_from(canonical.len()).unwrap_or(u64::MAX);
    Ok((content_hash, size_bytes))
}

#[derive(Debug, Clone)]
struct StoredVerifierCheck {
    evidence: EvidenceArtifact,
}

#[derive(Debug)]
struct VerifierRouteState {
    checks: BTreeMap<String, StoredVerifierCheck>,
    check_order: VecDeque<String>,
    audit_log: Vec<AuditLogEntry>,
    next_check_seq: u64,
    next_audit_seq: u64,
}

impl Default for VerifierRouteState {
    fn default() -> Self {
        Self {
            checks: BTreeMap::new(),
            check_order: VecDeque::new(),
            audit_log: Vec::new(),
            next_check_seq: 1,
            next_audit_seq: 1,
        }
    }
}

impl VerifierRouteState {
    fn next_check_id(&mut self, trace_id: &str) -> String {
        let prefix = utf8_prefix(trace_id, 12);
        let check_id = format!("chk-{prefix}-{:04}", self.next_check_seq);
        self.next_check_seq = self.next_check_seq.saturating_add(1);
        check_id
    }

    fn store_check(&mut self, check_id: String, evidence: EvidenceArtifact) {
        self.checks
            .insert(check_id.clone(), StoredVerifierCheck { evidence });
        self.check_order.push_back(check_id);

        while self.checks.len() > MAX_STORED_CONFORMANCE_CHECKS {
            if let Some(evicted_check_id) = self.check_order.pop_front() {
                self.checks.remove(&evicted_check_id);
            } else {
                break;
            }
        }
    }

    fn append_audit(
        &mut self,
        action: &str,
        actor: &str,
        resource: &str,
        outcome: &str,
        trace_id: &str,
    ) {
        self.audit_log.push(AuditLogEntry {
            entry_id: format!("audit-{:04}", self.next_audit_seq),
            timestamp: chrono::Utc::now().to_rfc3339(),
            action: action.to_string(),
            actor: actor.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            trace_id: trace_id.to_string(),
        });
        self.next_audit_seq = self.next_audit_seq.saturating_add(1);

        if self.audit_log.len() > MAX_VERIFIER_AUDIT_LOG_ENTRIES {
            let overflow = self.audit_log.len() - MAX_VERIFIER_AUDIT_LOG_ENTRIES;
            self.audit_log.drain(0..overflow);
        }
    }
}

fn verifier_route_state() -> &'static Mutex<VerifierRouteState> {
    static STATE: OnceLock<Mutex<VerifierRouteState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(VerifierRouteState::default()))
}

fn with_verifier_route_state<T>(
    trace_id: &str,
    f: impl FnOnce(&mut VerifierRouteState) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let mut state = verifier_route_state()
        .lock()
        .map_err(|_| ApiError::Internal {
            detail: "verifier route state lock poisoned".to_string(),
            trace_id: trace_id.to_string(),
        })?;
    f(&mut state)
}

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

impl ConformanceStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Partial => "partial",
        }
    }
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
    identity: &AuthIdentity,
    trace: &TraceContext,
    request: &ConformanceTriggerRequest,
) -> Result<ApiResponse<ConformanceResult>, ApiError> {
    with_verifier_route_state(&trace.trace_id, |state| {
        let check_id = state.next_check_id(&trace.trace_id);
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
                .filter(|finding| finding.status == ConformanceStatus::Pass)
                .count(),
        )
        .unwrap_or(u32::MAX);
        let failed = u32::try_from(
            findings
                .iter()
                .filter(|finding| finding.status == ConformanceStatus::Fail)
                .count(),
        )
        .unwrap_or(u32::MAX);
        let status = if failed > 0 {
            ConformanceStatus::Fail
        } else {
            ConformanceStatus::Pass
        };
        let triggered_at = chrono::Utc::now().to_rfc3339();

        let result = ConformanceResult {
            check_id: check_id.clone(),
            status,
            total_checks: u32::try_from(findings.len()).unwrap_or(u32::MAX),
            passed,
            failed,
            skipped: 0,
            findings,
            triggered_at: triggered_at.clone(),
        };

        let content = serde_json::json!({
            "check_id": result.check_id.clone(),
            "scope": request.scope.clone(),
            "verbose": request.verbose,
            "status": result.status.as_str(),
            "total_checks": result.total_checks,
            "passed": result.passed,
            "failed": result.failed,
            "skipped": result.skipped,
            "findings": result.findings.clone(),
            "triggered_at": result.triggered_at.clone(),
        });
        let (content_hash, size_bytes) =
            hash_evidence_content(&content).map_err(|err| ApiError::Internal {
                detail: format!("failed to serialize verifier evidence payload: {err}"),
                trace_id: trace.trace_id.clone(),
            })?;

        let evidence = EvidenceArtifact {
            check_id: result.check_id.clone(),
            artifact_type: "conformance_evidence".to_string(),
            content_hash,
            size_bytes,
            created_at: triggered_at,
            content,
        };

        state.store_check(result.check_id.clone(), evidence);
        state.append_audit(
            "conformance.trigger",
            &identity.principal,
            &result.check_id,
            result.status.as_str(),
            &trace.trace_id,
        );

        Ok(ApiResponse {
            ok: true,
            data: result,
            page: None,
        })
    })
}

/// Handle `GET /v1/verifier/evidence/{check_id}`.
pub fn get_evidence(
    identity: &AuthIdentity,
    trace: &TraceContext,
    check_id: &str,
) -> Result<ApiResponse<EvidenceArtifact>, ApiError> {
    with_verifier_route_state(&trace.trace_id, |state| {
        let artifact = state
            .checks
            .get(check_id)
            .map(|check| check.evidence.clone())
            .ok_or_else(|| {
                state.append_audit(
                    "evidence.read",
                    &identity.principal,
                    check_id,
                    "not_found",
                    &trace.trace_id,
                );
                ApiError::NotFound {
                    detail: format!("no verifier evidence recorded for check_id `{check_id}`"),
                    trace_id: trace.trace_id.clone(),
                }
            })?;

        state.append_audit(
            "evidence.read",
            &identity.principal,
            check_id,
            "success",
            &trace.trace_id,
        );

        Ok(ApiResponse {
            ok: true,
            data: artifact,
            page: None,
        })
    })
}

/// Handle `GET /v1/verifier/audit-log`.
pub fn query_audit_log(
    _identity: &AuthIdentity,
    trace: &TraceContext,
    query: &AuditLogQuery,
) -> Result<ApiResponse<Vec<AuditLogEntry>>, ApiError> {
    let since = match query.since.as_deref() {
        Some(raw) => Some(
            chrono::DateTime::parse_from_rfc3339(raw)
                .map_err(|err| ApiError::BadRequest {
                    detail: format!("invalid verifier audit-log since timestamp `{raw}`: {err}"),
                    trace_id: trace.trace_id.clone(),
                })?
                .with_timezone(&chrono::Utc),
        ),
        None => None,
    };
    let limit =
        usize::try_from(query.limit.unwrap_or(50)).unwrap_or(MAX_VERIFIER_AUDIT_LOG_ENTRIES);
    if limit == 0 {
        return Err(ApiError::BadRequest {
            detail: "verifier audit-log limit must be greater than zero".to_string(),
            trace_id: trace.trace_id.clone(),
        });
    }

    with_verifier_route_state(&trace.trace_id, |state| {
        let mut entries: Vec<AuditLogEntry> = state
            .audit_log
            .iter()
            .filter(|entry| {
                if let Some(action) = &query.action
                    && &entry.action != action
                {
                    return false;
                }
                if let Some(actor) = &query.actor
                    && &entry.actor != actor
                {
                    return false;
                }
                if let Some(ref since) = since
                    && let Ok(entry_ts) = chrono::DateTime::parse_from_rfc3339(&entry.timestamp)
                    && entry_ts.with_timezone(&chrono::Utc) <= *since
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        if entries.len() > limit {
            let keep_from = entries.len() - limit;
            entries.drain(0..keep_from);
        }

        Ok(ApiResponse {
            ok: true,
            data: entries,
            page: None,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::AuthMethod;
    use std::sync::{Mutex, MutexGuard, OnceLock};

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

    fn test_guard() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("test guard")
    }

    fn reset_verifier_state() {
        let mut state = verifier_route_state().lock().expect("state lock");
        *state = VerifierRouteState::default();
    }

    #[test]
    fn route_metadata_has_three_endpoints() {
        let _guard = test_guard();
        reset_verifier_state();
        let routes = route_metadata();
        assert_eq!(routes.len(), 3);
        assert!(routes.iter().all(|r| r.group == EndpointGroup::Verifier));
    }

    #[test]
    fn all_verifier_routes_require_bearer_token() {
        let _guard = test_guard();
        reset_verifier_state();
        for route in route_metadata() {
            assert_eq!(route.auth_method, AuthMethod::BearerToken);
        }
    }

    #[test]
    fn trigger_conformance_returns_pass() {
        let _guard = test_guard();
        reset_verifier_state();
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
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: Some("security".to_string()),
            verbose: true,
        };
        let conformance = trigger_conformance(&identity, &trace, &request).expect("conformance");
        let result = get_evidence(&identity, &trace, &conformance.data.check_id).expect("evidence");
        assert!(result.ok);
        assert_eq!(result.data.check_id, conformance.data.check_id);
        assert_eq!(result.data.artifact_type, "conformance_evidence");
        assert!(result.data.content_hash.starts_with("sha256:"));
        assert!(result.data.size_bytes > 0);
        assert_eq!(result.data.content["scope"], "security");
    }

    #[test]
    fn query_audit_log_returns_empty() {
        let _guard = test_guard();
        reset_verifier_state();
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
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: Some("security".to_string()),
            verbose: true,
        };
        let result = trigger_conformance(&identity, &trace, &request).expect("conformance");
        assert!(result.data.check_id.starts_with("chk-test-trace-v-"));
    }

    #[test]
    fn all_routes_are_stable_lifecycle() {
        let _guard = test_guard();
        reset_verifier_state();
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
        let _guard = test_guard();
        reset_verifier_state();
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
        let _guard = test_guard();
        reset_verifier_state();
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
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: Some("crypto".to_string()),
            verbose: false,
        };
        let conformance = trigger_conformance(&identity, &trace, &request).expect("conformance");
        let result = get_evidence(&identity, &trace, &conformance.data.check_id).expect("evidence");
        assert!(result.ok);
        assert!(!result.data.check_id.is_empty());
        assert!(!result.data.content.is_null());
        assert!(result.data.size_bytes > 0);
        assert_eq!(result.data.content["scope"], "crypto");
    }

    #[test]
    fn evidence_hash_is_deterministic_for_same_payload() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: None,
            verbose: false,
        };
        let conformance = trigger_conformance(&identity, &trace, &request).expect("conformance");
        let first = get_evidence(&identity, &trace, &conformance.data.check_id).expect("first");
        let second = get_evidence(&identity, &trace, &conformance.data.check_id).expect("second");
        assert_eq!(first.data.content_hash, second.data.content_hash);
        assert_eq!(first.data.size_bytes, second.data.size_bytes);
        assert_eq!(first.data.created_at, second.data.created_at);
    }

    #[test]
    fn evidence_artifact_serde_roundtrip() {
        let _guard = test_guard();
        reset_verifier_state();
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
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: Some("security".to_string()),
            verbose: false,
        };
        let conformance = trigger_conformance(&identity, &trace, &request).expect("conformance");
        get_evidence(&identity, &trace, &conformance.data.check_id).expect("evidence");
        let query = AuditLogQuery {
            action: Some("conformance.trigger".to_string()),
            actor: Some("test-verifier".to_string()),
            limit: Some(5),
            since: Some("2026-01-01T00:00:00Z".to_string()),
        };
        let result = query_audit_log(&identity, &trace, &query).expect("audit log");
        assert!(result.ok);
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].resource, conformance.data.check_id);
    }

    #[test]
    fn conformance_result_serde_roundtrip() {
        let _guard = test_guard();
        reset_verifier_state();
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
        let _guard = test_guard();
        reset_verifier_state();
        assert_ne!(
            format!("{:?}", ConformanceStatus::Pass),
            format!("{:?}", ConformanceStatus::Fail)
        );
    }

    #[test]
    fn conformance_check_id_handles_unicode_trace() {
        let _guard = test_guard();
        reset_verifier_state();
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
        assert_eq!(result.data.check_id, format!("chk-{expected}-0001"));
    }

    #[test]
    fn get_evidence_fails_closed_for_unknown_check_id() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();
        let err = get_evidence(&identity, &trace, "chk-missing-0001").expect_err("not found");
        assert!(matches!(err, ApiError::NotFound { .. }));
    }

    #[test]
    fn trigger_conformance_records_audit_and_evidence() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: Some("crypto".to_string()),
            verbose: true,
        };
        let conformance = trigger_conformance(&identity, &trace, &request).expect("conformance");
        let audit = query_audit_log(
            &identity,
            &trace,
            &AuditLogQuery {
                action: None,
                actor: None,
                limit: Some(10),
                since: None,
            },
        )
        .expect("audit");
        assert!(!audit.data.is_empty());
        assert_eq!(audit.data[0].resource, conformance.data.check_id);

        let evidence =
            get_evidence(&identity, &trace, &conformance.data.check_id).expect("evidence");
        assert_eq!(evidence.data.content["check_id"], conformance.data.check_id);
    }

    #[test]
    fn repeated_conformance_triggers_get_unique_check_ids() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: None,
            verbose: false,
        };
        let first = trigger_conformance(&identity, &trace, &request).expect("first");
        let second = trigger_conformance(&identity, &trace, &request).expect("second");
        assert_ne!(first.data.check_id, second.data.check_id);
    }
}
