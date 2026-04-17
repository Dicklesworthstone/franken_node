//! Connector protocol conformance harness.
//!
//! Runs the standard method contract validator against connectors and
//! enforces a publication gate. Non-conformant connectors are blocked
//! unless a valid policy override is present.

use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::{debug, info, instrument, warn};

use super::connector_method_validator::{
    ContractReport, MethodDeclaration, MethodErrorCode, validate_contract,
};

/// A policy override that allows publication despite failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOverride {
    pub override_id: String,
    pub connector_id: String,
    pub reason: String,
    pub authorized_by: String,
    pub expires_at: String,
    pub scope: Vec<String>,
}

/// Error codes for publication gate decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateErrorCode {
    PublicationBlocked,
    OverrideExpired,
    OverrideInvalid,
    OverrideScopeMismatch,
    ConnectorIdMismatch,
}

impl fmt::Display for GateErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicationBlocked => write!(f, "PUBLICATION_BLOCKED"),
            Self::OverrideExpired => write!(f, "OVERRIDE_EXPIRED"),
            Self::OverrideInvalid => write!(f, "OVERRIDE_INVALID"),
            Self::OverrideScopeMismatch => write!(f, "OVERRIDE_SCOPE_MISMATCH"),
            Self::ConnectorIdMismatch => write!(f, "CONNECTOR_ID_MISMATCH"),
        }
    }
}

/// Result of the publication gate for a single connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicationGateResult {
    pub connector_id: String,
    pub conformance_verdict: String,
    pub gate_decision: String,
    pub override_applied: bool,
    pub errors: Vec<GateError>,
}

/// A publication gate error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateError {
    pub code: GateErrorCode,
    pub message: String,
}

/// Aggregate harness report for multiple connectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessReport {
    pub total_connectors: usize,
    pub passed: usize,
    pub blocked: usize,
    pub overridden: usize,
    pub results: Vec<PublicationGateResult>,
    pub verdict: String,
}

/// Run the conformance harness for a single connector.
///
/// Validates method contracts and applies policy overrides if available.
#[instrument(skip(declarations, override_policy), fields(methods = declarations.len()))]
pub fn check_publication(
    connector_id: &str,
    declarations: &[MethodDeclaration],
    override_policy: Option<&PolicyOverride>,
    current_time: &str,
) -> PublicationGateResult {
    info!(
        connector_id,
        methods = declarations.len(),
        "starting conformance check"
    );
    let contract_report = validate_contract(connector_id, declarations);

    if contract_report.verdict == "PASS" {
        info!(connector_id, "conformance PASS — publication allowed");
        return PublicationGateResult {
            connector_id: connector_id.to_string(),
            conformance_verdict: "PASS".to_string(),
            gate_decision: "ALLOW".to_string(),
            override_applied: false,
            errors: vec![],
        };
    }

    debug!(
        connector_id,
        failing = contract_report.summary.failing,
        "conformance FAIL — checking for override"
    );

    // Contract failed — check for override
    match override_policy {
        None => {
            warn!(
                connector_id,
                failing = contract_report.summary.failing,
                "publication BLOCKED — no override available"
            );
            PublicationGateResult {
                connector_id: connector_id.to_string(),
                conformance_verdict: "FAIL".to_string(),
                gate_decision: "BLOCK".to_string(),
                override_applied: false,
                errors: vec![GateError {
                    code: GateErrorCode::PublicationBlocked,
                    message: format!(
                        "Connector '{}' failed conformance with {} error(s)",
                        connector_id, contract_report.summary.failing
                    ),
                }],
            }
        }
        Some(policy) => apply_override(connector_id, &contract_report, policy, current_time),
    }
}

/// Apply a policy override to a failing conformance result.
#[instrument(skip(report, policy), fields(override_id = %policy.override_id))]
fn apply_override(
    connector_id: &str,
    report: &ContractReport,
    policy: &PolicyOverride,
    current_time: &str,
) -> PublicationGateResult {
    let mut errors = Vec::new();

    if policy.override_id.trim().is_empty() {
        errors.push(GateError {
            code: GateErrorCode::OverrideInvalid,
            message: "Override ID must not be empty".to_string(),
        });
    } else if policy.override_id != policy.override_id.trim() {
        errors.push(GateError {
            code: GateErrorCode::OverrideInvalid,
            message: format!(
                "Override '{}' contains leading or trailing whitespace",
                policy.override_id
            ),
        });
    }

    if policy.reason.trim().is_empty() {
        errors.push(GateError {
            code: GateErrorCode::OverrideInvalid,
            message: format!("Override '{}' must include a reason", policy.override_id),
        });
    }

    if policy.authorized_by.trim().is_empty() {
        errors.push(GateError {
            code: GateErrorCode::OverrideInvalid,
            message: format!(
                "Override '{}' must include an authorizing principal",
                policy.override_id
            ),
        });
    }

    if policy.expires_at.trim().is_empty() {
        errors.push(GateError {
            code: GateErrorCode::OverrideInvalid,
            message: format!("Override '{}' must include an expiry", policy.override_id),
        });
    }

    for scope in &policy.scope {
        if scope.trim().is_empty() || scope != scope.trim() {
            errors.push(GateError {
                code: GateErrorCode::OverrideInvalid,
                message: format!(
                    "Override '{}' contains malformed scope entry {:?}",
                    policy.override_id, scope
                ),
            });
            break;
        }
    }

    // Check connector match
    if connector_id != policy.connector_id {
        warn!(
            override_id = %policy.override_id,
            expected_connector = %policy.connector_id,
            actual_connector = connector_id,
            "override connector ID mismatch"
        );
        errors.push(GateError {
            code: GateErrorCode::ConnectorIdMismatch,
            message: format!(
                "Override '{}' is for connector '{}', but was applied to '{}'",
                policy.override_id, policy.connector_id, connector_id
            ),
        });
    }

    // Check expiry
    if !policy.expires_at.trim().is_empty() && current_time >= policy.expires_at.as_str() {
        warn!(
            override_id = %policy.override_id,
            expires_at = %policy.expires_at,
            "override expired"
        );
        errors.push(GateError {
            code: GateErrorCode::OverrideExpired,
            message: format!(
                "Override '{}' expired at {}",
                policy.override_id, policy.expires_at
            ),
        });
    }

    // Check scope coverage
    let failure_codes: Vec<String> = report
        .methods
        .iter()
        .filter(|m| m.status == "FAIL")
        .flat_map(|m| {
            m.errors.iter().map(|e| {
                format!(
                    "{}:{}",
                    match e.code {
                        MethodErrorCode::MethodMissing => "METHOD_MISSING",
                        MethodErrorCode::SchemaMismatch => "SCHEMA_MISMATCH",
                        MethodErrorCode::VersionIncompatible => "VERSION_INCOMPATIBLE",
                        MethodErrorCode::ResponseInvalid => "RESPONSE_INVALID",
                    },
                    m.method
                )
            })
        })
        .collect();

    let uncovered: Vec<&String> = failure_codes
        .iter()
        .filter(|code| !policy.scope.contains(code))
        .collect();

    if !uncovered.is_empty() {
        warn!(
            override_id = %policy.override_id,
            uncovered_count = uncovered.len(),
            "override scope mismatch"
        );
        errors.push(GateError {
            code: GateErrorCode::OverrideScopeMismatch,
            message: format!(
                "Override does not cover: {}",
                uncovered
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }

    if errors.is_empty() {
        info!(connector_id, override_id = %policy.override_id, "override accepted — publication allowed");
        PublicationGateResult {
            connector_id: connector_id.to_string(),
            conformance_verdict: "FAIL".to_string(),
            gate_decision: "ALLOW_OVERRIDE".to_string(),
            override_applied: true,
            errors: vec![],
        }
    } else {
        PublicationGateResult {
            connector_id: connector_id.to_string(),
            conformance_verdict: "FAIL".to_string(),
            gate_decision: "BLOCK".to_string(),
            override_applied: false,
            errors,
        }
    }
}

/// Run the harness across multiple connectors.
#[instrument(skip(connectors), fields(connector_count = connectors.len()))]
pub fn run_harness(
    connectors: &[(String, Vec<MethodDeclaration>, Option<PolicyOverride>)],
    current_time: &str,
) -> HarnessReport {
    info!(
        connector_count = connectors.len(),
        "starting conformance harness run"
    );
    let mut results = Vec::new();
    for (id, decls, override_policy) in connectors {
        results.push(check_publication(
            id,
            decls,
            override_policy.as_ref(),
            current_time,
        ));
    }

    let passed = results
        .iter()
        .filter(|r| r.gate_decision == "ALLOW")
        .count();
    let overridden = results
        .iter()
        .filter(|r| r.gate_decision == "ALLOW_OVERRIDE")
        .count();
    let blocked = results
        .iter()
        .filter(|r| r.gate_decision == "BLOCK")
        .count();
    let verdict = if blocked == 0 { "PASS" } else { "FAIL" };

    info!(passed, blocked, overridden, verdict, "harness run complete");

    HarnessReport {
        total_connectors: results.len(),
        passed,
        blocked,
        overridden,
        results,
        verdict: verdict.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::connector_method_validator::all_methods;

    fn full_declarations() -> Vec<MethodDeclaration> {
        all_methods()
            .into_iter()
            .map(|name| MethodDeclaration {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                has_input_schema: true,
                has_output_schema: true,
            })
            .collect()
    }

    fn missing_handshake_declarations() -> Vec<MethodDeclaration> {
        full_declarations()
            .into_iter()
            .filter(|d| d.name != "handshake")
            .collect()
    }

    fn valid_override() -> PolicyOverride {
        PolicyOverride {
            override_id: "OVERRIDE-TEST-001".to_string(),
            connector_id: "test-conn".to_string(),
            reason: "Testing override".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:handshake".to_string()],
        }
    }

    #[test]
    fn passing_connector_allowed() {
        let result = check_publication(
            "test-conn",
            &full_declarations(),
            None,
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "ALLOW");
        assert!(!result.override_applied);
    }

    #[test]
    fn failing_connector_blocked() {
        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            None,
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "BLOCK");
        assert_eq!(result.errors[0].code, GateErrorCode::PublicationBlocked);
    }

    #[test]
    fn valid_override_allows_publication() {
        let policy = valid_override();
        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "ALLOW_OVERRIDE");
        assert!(result.override_applied);
    }

    #[test]
    fn expired_override_blocks() {
        let policy = PolicyOverride {
            expires_at: "2020-01-01T00:00:00Z".to_string(),
            ..valid_override()
        };
        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "BLOCK");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.code == GateErrorCode::OverrideExpired)
        );
    }

    #[test]
    fn override_at_exact_expiry_blocks_fail_closed() {
        let policy = PolicyOverride {
            expires_at: "2026-01-01T00:00:00Z".to_string(),
            ..valid_override()
        };

        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(!result.override_applied);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.code == GateErrorCode::OverrideExpired)
        );
    }

    #[test]
    fn scope_mismatch_blocks() {
        let policy = PolicyOverride {
            scope: vec!["SCHEMA_MISMATCH:handshake".to_string()], // wrong scope
            ..valid_override()
        };
        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "BLOCK");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.code == GateErrorCode::OverrideScopeMismatch)
        );
    }

    #[test]
    fn empty_override_scope_blocks_and_lists_uncovered_failure() {
        let policy = PolicyOverride {
            scope: vec![],
            ..valid_override()
        };

        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        let scope_error = result
            .errors
            .iter()
            .find(|e| e.code == GateErrorCode::OverrideScopeMismatch)
            .expect("scope mismatch");
        assert_eq!(result.gate_decision, "BLOCK");
        assert!(!result.override_applied);
        assert!(scope_error.message.contains("METHOD_MISSING:handshake"));
    }

    #[test]
    fn partial_override_scope_blocks_when_second_failure_is_uncovered() {
        let mut declarations = missing_handshake_declarations();
        declarations
            .iter_mut()
            .find(|decl| decl.name == "describe")
            .expect("describe declaration")
            .has_output_schema = false;
        let policy = PolicyOverride {
            scope: vec!["METHOD_MISSING:handshake".to_string()],
            ..valid_override()
        };

        let result = check_publication(
            "test-conn",
            &declarations,
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        let scope_error = result
            .errors
            .iter()
            .find(|e| e.code == GateErrorCode::OverrideScopeMismatch)
            .expect("scope mismatch");
        assert_eq!(result.gate_decision, "BLOCK");
        assert!(scope_error.message.contains("SCHEMA_MISMATCH:describe"));
    }

    #[test]
    fn connector_id_mismatch_blocks() {
        let policy = valid_override(); // connector_id is "test-conn"
        let result = check_publication(
            "wrong-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "BLOCK");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.code == GateErrorCode::ConnectorIdMismatch)
        );
    }

    #[test]
    fn override_with_multiple_defects_reports_each_gate_error() {
        let policy = PolicyOverride {
            connector_id: "other-conn".to_string(),
            expires_at: "2020-01-01T00:00:00Z".to_string(),
            scope: vec![],
            ..valid_override()
        };

        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );
        let codes: Vec<&GateErrorCode> = result.errors.iter().map(|error| &error.code).collect();

        assert_eq!(result.gate_decision, "BLOCK");
        assert_eq!(result.errors.len(), 3);
        assert!(codes.contains(&&GateErrorCode::ConnectorIdMismatch));
        assert!(codes.contains(&&GateErrorCode::OverrideExpired));
        assert!(codes.contains(&&GateErrorCode::OverrideScopeMismatch));
    }

    #[test]
    fn connector_mismatch_error_message_preserves_expected_and_actual_ids() {
        let policy = valid_override();

        let result = check_publication(
            "wrong-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        let mismatch = result
            .errors
            .iter()
            .find(|e| e.code == GateErrorCode::ConnectorIdMismatch)
            .expect("connector mismatch");
        assert!(mismatch.message.contains("test-conn"));
        assert!(mismatch.message.contains("wrong-conn"));
        assert!(!result.override_applied);
    }

    #[test]
    fn override_with_empty_id_blocks_even_when_scope_matches() {
        let policy = PolicyOverride {
            override_id: String::new(),
            ..valid_override()
        };

        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(!result.override_applied);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.code == GateErrorCode::OverrideInvalid)
        );
    }

    #[test]
    fn override_with_blank_reason_blocks_even_when_scope_matches() {
        let policy = PolicyOverride {
            reason: " \t ".to_string(),
            ..valid_override()
        };

        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(result.errors.iter().any(|e| e.message.contains("reason")));
    }

    #[test]
    fn override_with_blank_authorizer_blocks_even_when_scope_matches() {
        let policy = PolicyOverride {
            authorized_by: String::new(),
            ..valid_override()
        };

        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("authorizing principal"))
        );
    }

    #[test]
    fn override_with_empty_expiry_blocks_without_expired_shadow_error() {
        let policy = PolicyOverride {
            expires_at: String::new(),
            ..valid_override()
        };

        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.code == GateErrorCode::OverrideInvalid)
        );
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.code == GateErrorCode::OverrideExpired)
        );
    }

    #[test]
    fn override_with_blank_scope_entry_blocks() {
        let policy = PolicyOverride {
            scope: vec!["METHOD_MISSING:handshake".to_string(), " ".to_string()],
            ..valid_override()
        };

        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("malformed scope"))
        );
    }

    #[test]
    fn override_with_trim_required_scope_entry_blocks() {
        let policy = PolicyOverride {
            scope: vec![" METHOD_MISSING:handshake ".to_string()],
            ..valid_override()
        };

        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        let codes: Vec<&GateErrorCode> = result.errors.iter().map(|error| &error.code).collect();

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(codes.contains(&&GateErrorCode::OverrideInvalid));
        assert!(codes.contains(&&GateErrorCode::OverrideScopeMismatch));
    }

    #[test]
    fn failed_connector_without_override_preserves_failure_context() {
        let result = check_publication(
            "test-conn",
            &missing_handshake_declarations(),
            None,
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.connector_id, "test-conn");
        assert_eq!(result.conformance_verdict, "FAIL");
        assert_eq!(result.gate_decision, "BLOCK");
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].message.contains("failed conformance"));
    }

    #[test]
    fn harness_with_only_blocked_connectors_fails_and_counts_all_blocks() {
        let connectors = vec![
            (
                "conn-fail-1".to_string(),
                missing_handshake_declarations(),
                None,
            ),
            (
                "conn-fail-2".to_string(),
                missing_handshake_declarations(),
                None,
            ),
        ];

        let report = run_harness(&connectors, "2026-01-01T00:00:00Z");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.total_connectors, 2);
        assert_eq!(report.passed, 0);
        assert_eq!(report.overridden, 0);
        assert_eq!(report.blocked, 2);
    }

    #[test]
    fn harness_all_pass() {
        let connectors = vec![
            ("conn-1".to_string(), full_declarations(), None),
            ("conn-2".to_string(), full_declarations(), None),
        ];
        let report = run_harness(&connectors, "2026-01-01T00:00:00Z");
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.passed, 2);
        assert_eq!(report.blocked, 0);
    }

    #[test]
    fn harness_mixed_results() {
        let connectors = vec![
            ("conn-ok".to_string(), full_declarations(), None),
            (
                "conn-fail".to_string(),
                missing_handshake_declarations(),
                None,
            ),
        ];
        let report = run_harness(&connectors, "2026-01-01T00:00:00Z");
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.passed, 1);
        assert_eq!(report.blocked, 1);
    }

    #[test]
    fn harness_with_override() {
        let policy = valid_override();
        let connectors = vec![(
            "test-conn".to_string(),
            missing_handshake_declarations(),
            Some(policy),
        )];
        let report = run_harness(&connectors, "2026-01-01T00:00:00Z");
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.overridden, 1);
    }

    #[test]
    fn empty_harness_passes() {
        let report = run_harness(&[], "2026-01-01T00:00:00Z");
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.total_connectors, 0);
    }

    #[test]
    fn serde_roundtrip() {
        let report = run_harness(
            &[("conn".to_string(), full_declarations(), None)],
            "2026-01-01T00:00:00Z",
        );
        let json = serde_json::to_string(&report).unwrap();
        let parsed: HarnessReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.verdict, "PASS");
    }
}
