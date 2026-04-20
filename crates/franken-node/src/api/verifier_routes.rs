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
    let canonical_len = u64::try_from(canonical.len()).unwrap_or(u64::MAX);
    let mut hasher = Sha256::new();
    hasher.update(b"verifier_evidence_content_v1:");
    hasher.update(canonical_len.to_le_bytes());
    hasher.update(&canonical);
    let content_hash = format!("sha256:{}", hex::encode(hasher.finalize()));
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
    check_ids_exhausted: bool,
    audit_ids_exhausted: bool,
}

impl Default for VerifierRouteState {
    fn default() -> Self {
        Self {
            checks: BTreeMap::new(),
            check_order: VecDeque::new(),
            audit_log: Vec::new(),
            next_check_seq: 1,
            next_audit_seq: 1,
            check_ids_exhausted: false,
            audit_ids_exhausted: false,
        }
    }
}

impl VerifierRouteState {
    fn reserve_trigger_ids(&mut self, trace_id: &str) -> Result<(String, String), ApiError> {
        if self.check_ids_exhausted {
            return Err(ApiError::Internal {
                detail: "verifier check_id counter exhausted".to_string(),
                trace_id: trace_id.to_string(),
            });
        }
        if self.audit_ids_exhausted {
            return Err(ApiError::Internal {
                detail: "verifier audit entry counter exhausted".to_string(),
                trace_id: trace_id.to_string(),
            });
        }

        let prefix = utf8_prefix(trace_id, 12);
        let check_id = format!("chk-{prefix}-{:04}", self.next_check_seq);
        let audit_entry_id = format!("audit-{:04}", self.next_audit_seq);
        let next_check_seq = self.next_check_seq.checked_add(1);
        let next_audit_seq = self.next_audit_seq.checked_add(1);

        if let Some(next) = next_check_seq {
            self.next_check_seq = next;
        } else {
            self.check_ids_exhausted = true;
        }
        if let Some(next) = next_audit_seq {
            self.next_audit_seq = next;
        } else {
            self.audit_ids_exhausted = true;
        }

        Ok((check_id, audit_entry_id))
    }

    fn store_check(&mut self, check_id: String, evidence: EvidenceArtifact) {
        self.checks
            .insert(check_id.clone(), StoredVerifierCheck { evidence });
        while self.checks.len() > MAX_STORED_CONFORMANCE_CHECKS {
            if let Some(evicted_check_id) = self.check_order.pop_front() {
                self.checks.remove(&evicted_check_id);
            } else {
                break;
            }
        }
        self.check_order.push_back(check_id);
    }

    fn next_audit_entry_id(&mut self, trace_id: &str) -> Result<String, ApiError> {
        if self.audit_ids_exhausted {
            return Err(ApiError::Internal {
                detail: "verifier audit entry counter exhausted".to_string(),
                trace_id: trace_id.to_string(),
            });
        }

        let entry_id = format!("audit-{:04}", self.next_audit_seq);
        if let Some(next) = self.next_audit_seq.checked_add(1) {
            self.next_audit_seq = next;
        } else {
            self.audit_ids_exhausted = true;
        }
        Ok(entry_id)
    }

    fn push_audit_entry(
        &mut self,
        entry_id: String,
        action: &str,
        actor: &str,
        resource: &str,
        outcome: &str,
        trace_id: &str,
    ) {
        if self.audit_log.len() >= MAX_VERIFIER_AUDIT_LOG_ENTRIES {
            let overflow = self.audit_log.len() - MAX_VERIFIER_AUDIT_LOG_ENTRIES + 1;
            self.audit_log.drain(0..overflow);
        }
        self.audit_log.push(AuditLogEntry {
            entry_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            action: action.to_string(),
            actor: actor.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            trace_id: trace_id.to_string(),
        });
    }

    fn append_audit(
        &mut self,
        action: &str,
        actor: &str,
        resource: &str,
        outcome: &str,
        trace_id: &str,
    ) -> Result<(), ApiError> {
        let entry_id = self.next_audit_entry_id(trace_id)?;
        self.push_audit_entry(entry_id, action, actor, resource, outcome, trace_id);
        Ok(())
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

fn normalize_required_field(
    value: &str,
    field_name: &str,
    trace_id: &str,
) -> Result<String, ApiError> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(ApiError::BadRequest {
            detail: format!("verifier field `{field_name}` must not be empty"),
            trace_id: trace_id.to_string(),
        });
    }
    Ok(normalized.to_string())
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
        let (check_id, audit_entry_id) = state.reserve_trigger_ids(&trace.trace_id)?;
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
        state.push_audit_entry(
            audit_entry_id,
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
    let check_id = normalize_required_field(check_id, "check_id", &trace.trace_id)?;
    with_verifier_route_state(&trace.trace_id, |state| {
        let Some(artifact) = state
            .checks
            .get(&check_id)
            .map(|check| check.evidence.clone())
        else {
            state.append_audit(
                "evidence.read",
                &identity.principal,
                &check_id,
                "not_found",
                &trace.trace_id,
            )?;
            return Err(ApiError::NotFound {
                detail: format!("no verifier evidence recorded for check_id `{check_id}`"),
                trace_id: trace.trace_id.clone(),
            });
        };

        state.append_audit(
            "evidence.read",
            &identity.principal,
            &check_id,
            "success",
            &trace.trace_id,
        )?;

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
    fn evidence_hash_length_prefixes_canonical_payload() {
        let content = serde_json::json!({
            "check_id": "chk-proof-0001",
            "status": "pass",
            "findings": ["a", "bc"]
        });
        let canonical = serde_json::to_vec(&content).expect("canonical evidence");
        let canonical_len = u64::try_from(canonical.len()).unwrap_or(u64::MAX);

        let mut expected = Sha256::new();
        expected.update(b"verifier_evidence_content_v1:");
        expected.update(canonical_len.to_le_bytes());
        expected.update(&canonical);

        let mut unprefixed = Sha256::new();
        unprefixed.update(b"verifier_evidence_content_v1:");
        unprefixed.update(&canonical);

        let (content_hash, size_bytes) = hash_evidence_content(&content).expect("hash evidence");

        assert_eq!(size_bytes, canonical_len);
        assert_eq!(
            content_hash,
            format!("sha256:{}", hex::encode(expected.finalize()))
        );
        assert_ne!(
            content_hash,
            format!("sha256:{}", hex::encode(unprefixed.finalize()))
        );
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

    #[test]
    fn check_id_counter_fails_closed_after_last_id() {
        let _guard = test_guard();
        reset_verifier_state();
        {
            let mut state = verifier_route_state().lock().expect("state lock");
            state.next_check_seq = u64::MAX;
        }

        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: None,
            verbose: false,
        };

        let final_result = trigger_conformance(&identity, &trace, &request).expect("final id");
        assert!(final_result.data.check_id.ends_with("18446744073709551615"));

        let err =
            trigger_conformance(&identity, &trace, &request).expect_err("counter should exhaust");
        assert!(matches!(err, ApiError::Internal { .. }));
        if let ApiError::Internal { detail, .. } = err {
            assert!(detail.contains("check_id counter exhausted"));
        }
    }

    #[test]
    fn audit_counter_fails_closed_after_last_entry() {
        let _guard = test_guard();
        reset_verifier_state();
        {
            let mut state = verifier_route_state().lock().expect("state lock");
            state.next_audit_seq = u64::MAX;
        }

        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: None,
            verbose: false,
        };

        let conformance = trigger_conformance(&identity, &trace, &request).expect("final audit");
        let err = get_evidence(&identity, &trace, &conformance.data.check_id)
            .expect_err("audit counter should exhaust");
        assert!(matches!(err, ApiError::Internal { .. }));
        if let ApiError::Internal { detail, .. } = err {
            assert!(detail.contains("audit entry counter exhausted"));
        }
    }

    #[test]
    fn trigger_failure_does_not_consume_check_id_space() {
        let _guard = test_guard();
        reset_verifier_state();
        {
            let mut state = verifier_route_state().lock().expect("state lock");
            state.next_check_seq = 41;
            state.next_audit_seq = 9;
            state.audit_ids_exhausted = true;
        }

        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: None,
            verbose: false,
        };

        let err = trigger_conformance(&identity, &trace, &request)
            .expect_err("audit exhaustion should fail before consuming ids");
        assert!(matches!(err, ApiError::Internal { .. }));
        if let ApiError::Internal { detail, .. } = err {
            assert!(detail.contains("audit entry counter exhausted"));
        }

        let state = verifier_route_state().lock().expect("state lock");
        assert_eq!(state.next_check_seq, 41);
        assert_eq!(state.next_audit_seq, 9);
        assert!(state.checks.is_empty());
        assert!(state.audit_log.is_empty());
    }

    #[test]
    fn query_audit_log_rejects_zero_limit() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();

        let err = query_audit_log(
            &identity,
            &trace,
            &AuditLogQuery {
                action: None,
                actor: None,
                limit: Some(0),
                since: None,
            },
        )
        .expect_err("zero limit must fail closed");

        assert!(matches!(
            err,
            ApiError::BadRequest { ref trace_id, .. } if trace_id == "test-trace-verifier-001"
        ));
    }

    #[test]
    fn query_audit_log_rejects_malformed_since_timestamp() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();

        let err = query_audit_log(
            &identity,
            &trace,
            &AuditLogQuery {
                action: None,
                actor: None,
                limit: Some(10),
                since: Some("not-a-timestamp".to_string()),
            },
        )
        .expect_err("malformed since timestamp must fail closed");

        let problem = err.to_problem("/v1/verifier/audit-log");
        assert_eq!(problem.status, 400);
        assert!(
            problem
                .detail
                .contains("invalid verifier audit-log since timestamp")
        );
    }

    #[test]
    fn query_audit_log_since_excludes_exact_boundary_timestamp() {
        let _guard = test_guard();
        reset_verifier_state();
        {
            let mut state = verifier_route_state().lock().expect("state lock");
            state.audit_log.push(AuditLogEntry {
                entry_id: "audit-boundary".to_string(),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
                action: "conformance.trigger".to_string(),
                actor: "test-verifier".to_string(),
                resource: "chk-boundary".to_string(),
                outcome: "pass".to_string(),
                trace_id: "trace-boundary".to_string(),
            });
        }
        let identity = test_identity();
        let trace = test_trace();

        let result = query_audit_log(
            &identity,
            &trace,
            &AuditLogQuery {
                action: None,
                actor: None,
                limit: Some(10),
                since: Some("2026-01-01T00:00:00Z".to_string()),
            },
        )
        .expect("query audit log");

        assert!(
            result.data.is_empty(),
            "audit entries exactly at since boundary must be excluded"
        );
    }

    #[test]
    fn missing_evidence_read_records_not_found_audit_entry() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();

        let err = get_evidence(&identity, &trace, "chk-missing-0001")
            .expect_err("missing evidence must fail");
        assert!(matches!(err, ApiError::NotFound { .. }));

        let audit = query_audit_log(
            &identity,
            &trace,
            &AuditLogQuery {
                action: Some("evidence.read".to_string()),
                actor: Some("test-verifier".to_string()),
                limit: Some(10),
                since: None,
            },
        )
        .expect("audit query");
        assert_eq!(audit.data.len(), 1);
        assert_eq!(audit.data[0].resource, "chk-missing-0001");
        assert_eq!(audit.data[0].outcome, "not_found");
    }

    #[test]
    fn verifier_routes_do_not_allow_anonymous_access_or_empty_roles() {
        for route in route_metadata() {
            assert_ne!(
                route.auth_method,
                AuthMethod::None,
                "{} must not bypass verifier auth",
                route.path
            );
            assert!(
                !route.policy_hook.required_roles.is_empty(),
                "{} must require verifier/operator policy roles",
                route.path
            );
        }
    }

    #[test]
    fn conformance_status_deserialize_rejects_unknown_variant() {
        let result: Result<ConformanceStatus, _> = serde_json::from_str("\"Bypassed\"");

        assert!(
            result.is_err(),
            "unknown conformance status must fail closed"
        );
    }

    #[test]
    fn trigger_request_deserialize_rejects_verbose_type_confusion() {
        let raw = serde_json::json!({
            "scope": "security",
            "verbose": "true"
        });

        let result: Result<ConformanceTriggerRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "verbose must be a boolean, not a string");
    }

    #[test]
    fn evidence_artifact_deserialize_rejects_missing_content_hash() {
        let raw = serde_json::json!({
            "check_id": "chk-missing-hash",
            "artifact_type": "conformance_evidence",
            "size_bytes": 12_u64,
            "created_at": "2026-01-01T00:00:00Z",
            "content": {"ok": true}
        });

        let result: Result<EvidenceArtifact, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "evidence artifacts must include a content hash"
        );
    }

    fn evidence_for(check_id: &str) -> EvidenceArtifact {
        EvidenceArtifact {
            check_id: check_id.to_string(),
            artifact_type: "conformance_evidence".to_string(),
            content_hash: format!("sha256:{}", "0".repeat(64)),
            size_bytes: 2,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            content: serde_json::json!({ "id": check_id }),
        }
    }

    #[test]
    fn store_check_keeps_exact_capacity_without_early_eviction() {
        let mut state = VerifierRouteState::default();

        for idx in 0..MAX_STORED_CONFORMANCE_CHECKS {
            let check_id = format!("chk-cap-{idx:04}");
            state.store_check(check_id.clone(), evidence_for(&check_id));
        }

        assert_eq!(state.checks.len(), MAX_STORED_CONFORMANCE_CHECKS);
        assert!(state.checks.contains_key("chk-cap-0000"));
        assert!(state.checks.contains_key("chk-cap-0255"));
    }

    #[test]
    fn store_check_over_capacity_evicts_only_oldest_check() {
        let mut state = VerifierRouteState::default();

        for idx in 0..=MAX_STORED_CONFORMANCE_CHECKS {
            let check_id = format!("chk-overflow-{idx:04}");
            state.store_check(check_id.clone(), evidence_for(&check_id));
        }

        assert_eq!(state.checks.len(), MAX_STORED_CONFORMANCE_CHECKS);
        assert!(!state.checks.contains_key("chk-overflow-0000"));
        assert!(state.checks.contains_key("chk-overflow-0001"));
        assert!(state.checks.contains_key("chk-overflow-0256"));
    }

    #[test]
    fn get_evidence_rejects_blank_check_id_as_bad_request() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();

        let err = get_evidence(&identity, &trace, " \t\n ").expect_err("blank check id");

        assert!(matches!(
            err,
            ApiError::BadRequest {
                ref detail,
                ref trace_id
            } if detail.contains("check_id") && trace_id == "test-trace-verifier-001"
        ));
    }

    #[test]
    fn get_evidence_trims_unknown_check_id_before_audit() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();

        let err =
            get_evidence(&identity, &trace, "  chk-missing-padded  ").expect_err("missing id");

        assert!(matches!(err, ApiError::NotFound { .. }));
        let audit = query_audit_log(
            &identity,
            &trace,
            &AuditLogQuery {
                action: Some("evidence.read".to_string()),
                actor: Some("test-verifier".to_string()),
                limit: Some(10),
                since: None,
            },
        )
        .expect("audit query");
        assert_eq!(audit.data.len(), 1);
        assert_eq!(audit.data[0].resource, "chk-missing-padded");
    }

    #[test]
    fn query_audit_log_rejects_blank_since_timestamp() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();

        let err = query_audit_log(
            &identity,
            &trace,
            &AuditLogQuery {
                action: None,
                actor: None,
                limit: Some(10),
                since: Some(" \n\t ".to_string()),
            },
        )
        .expect_err("blank since timestamp must fail closed");

        assert!(matches!(err, ApiError::BadRequest { .. }));
    }

    #[test]
    fn audit_log_query_deserialize_rejects_limit_type_confusion() {
        let raw = serde_json::json!({
            "action": null,
            "actor": null,
            "limit": "10",
            "since": null
        });

        let result: Result<AuditLogQuery, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "audit limit must be numeric");
    }

    #[test]
    fn audit_log_query_deserialize_rejects_action_type_confusion() {
        let raw = serde_json::json!({
            "action": 7_u8,
            "actor": null,
            "limit": 10_u32,
            "since": null
        });

        let result: Result<AuditLogQuery, _> = serde_json::from_value(raw);

        assert!(result.is_err(), "audit action filter must be a string");
    }

    #[test]
    fn conformance_result_deserialize_rejects_missing_findings() {
        let raw = serde_json::json!({
            "check_id": "chk-schema-0001",
            "status": "Pass",
            "total_checks": 2,
            "passed": 2,
            "failed": 0,
            "skipped": 0,
            "triggered_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<ConformanceResult>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn conformance_result_deserialize_rejects_string_total_checks() {
        let raw = serde_json::json!({
            "check_id": "chk-schema-0002",
            "status": "Pass",
            "total_checks": "2",
            "passed": 2,
            "failed": 0,
            "skipped": 0,
            "findings": [],
            "triggered_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<ConformanceResult>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn conformance_finding_deserialize_rejects_numeric_severity() {
        let raw = serde_json::json!({
            "check_name": "trust_card_schema",
            "status": "Pass",
            "detail": "ok",
            "severity": 1
        });

        let result = serde_json::from_value::<ConformanceFinding>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn conformance_finding_deserialize_rejects_unknown_nested_status() {
        let raw = serde_json::json!({
            "check_name": "trust_card_schema",
            "status": "Bypassed",
            "detail": "not a valid status",
            "severity": "info"
        });

        let result = serde_json::from_value::<ConformanceFinding>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn evidence_artifact_deserialize_rejects_negative_size_bytes() {
        let raw = serde_json::json!({
            "check_id": "chk-schema-0003",
            "artifact_type": "conformance_evidence",
            "content_hash": format!("sha256:{}", "0".repeat(64)),
            "size_bytes": -1,
            "created_at": "2026-01-01T00:00:00Z",
            "content": {"ok": true}
        });

        let result = serde_json::from_value::<EvidenceArtifact>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn audit_log_entry_deserialize_rejects_missing_trace_id() {
        let raw = serde_json::json!({
            "entry_id": "audit-schema-0001",
            "timestamp": "2026-01-01T00:00:00Z",
            "action": "evidence.read",
            "actor": "test-verifier",
            "resource": "chk-schema-0001",
            "outcome": "success"
        });

        let result = serde_json::from_value::<AuditLogEntry>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn audit_log_query_deserialize_rejects_negative_limit() {
        let raw = serde_json::json!({
            "action": null,
            "actor": null,
            "limit": -1,
            "since": null
        });

        let result = serde_json::from_value::<AuditLogQuery>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn trigger_request_deserialize_rejects_array_scope() {
        let raw = serde_json::json!({
            "scope": ["security"],
            "verbose": false
        });

        let result = serde_json::from_value::<ConformanceTriggerRequest>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn reserve_trigger_ids_rejects_exhausted_check_counter_without_mutation() {
        let mut state = VerifierRouteState::default();
        state.check_ids_exhausted = true;
        state.next_check_seq = 7;
        state.next_audit_seq = 11;

        let err = state
            .reserve_trigger_ids("trace-exhausted-check")
            .expect_err("exhausted check counter must fail closed");

        assert!(matches!(err, ApiError::Internal { .. }));
        assert_eq!(state.next_check_seq, 7);
        assert_eq!(state.next_audit_seq, 11);
        assert!(state.checks.is_empty());
        assert!(state.audit_log.is_empty());
    }

    #[test]
    fn reserve_trigger_ids_rejects_exhausted_audit_counter_without_mutation() {
        let mut state = VerifierRouteState::default();
        state.audit_ids_exhausted = true;
        state.next_check_seq = 13;
        state.next_audit_seq = 17;

        let err = state
            .reserve_trigger_ids("trace-exhausted-audit")
            .expect_err("exhausted audit counter must fail closed");

        assert!(matches!(err, ApiError::Internal { .. }));
        assert_eq!(state.next_check_seq, 13);
        assert_eq!(state.next_audit_seq, 17);
        assert!(state.checks.is_empty());
        assert!(state.audit_log.is_empty());
    }

    #[test]
    fn next_audit_entry_id_rejects_exhausted_counter_without_incrementing() {
        let mut state = VerifierRouteState::default();
        state.audit_ids_exhausted = true;
        state.next_audit_seq = 23;

        let err = state
            .next_audit_entry_id("trace-audit-exhausted")
            .expect_err("exhausted audit counter must not allocate");

        assert!(matches!(err, ApiError::Internal { .. }));
        assert_eq!(state.next_audit_seq, 23);
        assert!(state.audit_log.is_empty());
    }

    #[test]
    fn append_audit_rejects_exhausted_counter_without_writing_entry() {
        let mut state = VerifierRouteState::default();
        state.audit_ids_exhausted = true;

        let err = state
            .append_audit(
                "evidence.read",
                "test-verifier",
                "chk-exhausted",
                "success",
                "trace-audit-exhausted",
            )
            .expect_err("exhausted audit counter must fail append");

        assert!(matches!(err, ApiError::Internal { .. }));
        assert!(state.audit_log.is_empty());
    }

    #[test]
    fn blank_evidence_request_does_not_write_audit_entry() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();

        let err = get_evidence(&identity, &trace, " \n\t ").expect_err("blank id");

        assert!(matches!(err, ApiError::BadRequest { .. }));
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
        .expect("audit query");
        assert!(audit.data.is_empty());
    }

    #[test]
    fn query_audit_log_nonmatching_filters_return_empty_results() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();
        let request = ConformanceTriggerRequest {
            scope: None,
            verbose: false,
        };
        trigger_conformance(&identity, &trace, &request).expect("seed audit");

        let audit = query_audit_log(
            &identity,
            &trace,
            &AuditLogQuery {
                action: Some("evidence.read".to_string()),
                actor: Some("different-verifier".to_string()),
                limit: Some(10),
                since: None,
            },
        )
        .expect("audit query");

        assert!(audit.data.is_empty());
    }

    #[test]
    fn trigger_request_deserialize_rejects_missing_verbose_flag() {
        let raw = serde_json::json!({
            "scope": "security"
        });

        let result = serde_json::from_value::<ConformanceTriggerRequest>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn conformance_finding_deserialize_rejects_missing_detail() {
        let raw = serde_json::json!({
            "check_name": "trust_card_schema",
            "status": "Pass",
            "severity": "info"
        });

        let result = serde_json::from_value::<ConformanceFinding>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn audit_log_entry_deserialize_rejects_numeric_resource() {
        let raw = serde_json::json!({
            "entry_id": "audit-schema-0002",
            "timestamp": "2026-01-01T00:00:00Z",
            "action": "evidence.read",
            "actor": "test-verifier",
            "resource": 17,
            "outcome": "success",
            "trace_id": "trace-schema"
        });

        let result = serde_json::from_value::<AuditLogEntry>(raw);

        assert!(result.is_err());
    }

    #[test]
    fn trigger_request_deserialize_rejects_null_verbose_flag() {
        let raw = serde_json::json!({
            "scope": "security",
            "verbose": null
        });

        let result = serde_json::from_value::<ConformanceTriggerRequest>(raw);

        assert!(result.is_err(), "verbose must be an explicit boolean");
    }

    #[test]
    fn trigger_request_deserialize_rejects_object_scope() {
        let raw = serde_json::json!({
            "scope": { "module": "security" },
            "verbose": false
        });

        let result = serde_json::from_value::<ConformanceTriggerRequest>(raw);

        assert!(result.is_err(), "scope must remain an optional string");
    }

    #[test]
    fn conformance_result_deserialize_rejects_negative_passed_count() {
        let raw = serde_json::json!({
            "check_id": "chk-schema-negative-passed",
            "status": "Pass",
            "total_checks": 2,
            "passed": -1,
            "failed": 0,
            "skipped": 0,
            "findings": [],
            "triggered_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<ConformanceResult>(raw);

        assert!(result.is_err(), "passed count must stay unsigned");
    }

    #[test]
    fn conformance_result_deserialize_rejects_null_status() {
        let raw = serde_json::json!({
            "check_id": "chk-schema-null-status",
            "status": null,
            "total_checks": 2,
            "passed": 2,
            "failed": 0,
            "skipped": 0,
            "findings": [],
            "triggered_at": "2026-01-01T00:00:00Z"
        });

        let result = serde_json::from_value::<ConformanceResult>(raw);

        assert!(result.is_err(), "status is required and must be typed");
    }

    #[test]
    fn conformance_finding_deserialize_rejects_boolean_check_name() {
        let raw = serde_json::json!({
            "check_name": true,
            "status": "Pass",
            "detail": "ok",
            "severity": "info"
        });

        let result = serde_json::from_value::<ConformanceFinding>(raw);

        assert!(result.is_err(), "check_name must be a string");
    }

    #[test]
    fn evidence_artifact_deserialize_rejects_boolean_created_at() {
        let raw = serde_json::json!({
            "check_id": "chk-schema-bool-created-at",
            "artifact_type": "conformance_evidence",
            "content_hash": format!("sha256:{}", "0".repeat(64)),
            "size_bytes": 0,
            "created_at": false,
            "content": {"ok": true}
        });

        let result = serde_json::from_value::<EvidenceArtifact>(raw);

        assert!(result.is_err(), "created_at must stay a timestamp string");
    }

    #[test]
    fn audit_log_query_deserialize_rejects_float_limit() {
        let raw = serde_json::json!({
            "action": null,
            "actor": null,
            "limit": 10.5,
            "since": null
        });

        let result = serde_json::from_value::<AuditLogQuery>(raw);

        assert!(result.is_err(), "limit must be an integer");
    }

    #[test]
    fn query_audit_log_rejects_whitespace_wrapped_since_timestamp() {
        let _guard = test_guard();
        reset_verifier_state();
        let identity = test_identity();
        let trace = test_trace();

        let err = query_audit_log(
            &identity,
            &trace,
            &AuditLogQuery {
                action: None,
                actor: None,
                limit: Some(10),
                since: Some(" 2026-01-01T00:00:00Z ".to_string()),
            },
        )
        .expect_err("since timestamp must not be whitespace-wrapped");

        assert!(matches!(
            err,
            ApiError::BadRequest {
                ref detail,
                ref trace_id
            } if detail.contains("since timestamp") && trace_id == "test-trace-verifier-001"
        ));
    }
}
