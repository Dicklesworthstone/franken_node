//! Connector protocol conformance harness.
//!
//! Runs the standard method contract validator against connectors and
//! enforces a publication gate. Non-conformant connectors are blocked
//! unless a valid policy override is present.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::connector_method_validator::{
    validate_contract, ContractReport, MethodDeclaration, MethodErrorCode,
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
    OverrideScopeMismatch,
}

impl fmt::Display for GateErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicationBlocked => write!(f, "PUBLICATION_BLOCKED"),
            Self::OverrideExpired => write!(f, "OVERRIDE_EXPIRED"),
            Self::OverrideScopeMismatch => write!(f, "OVERRIDE_SCOPE_MISMATCH"),
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
pub fn check_publication(
    connector_id: &str,
    declarations: &[MethodDeclaration],
    override_policy: Option<&PolicyOverride>,
    current_time: &str,
) -> PublicationGateResult {
    let contract_report = validate_contract(connector_id, declarations);

    if contract_report.verdict == "PASS" {
        return PublicationGateResult {
            connector_id: connector_id.to_string(),
            conformance_verdict: "PASS".to_string(),
            gate_decision: "ALLOW".to_string(),
            override_applied: false,
            errors: vec![],
        };
    }

    // Contract failed — check for override
    match override_policy {
        None => PublicationGateResult {
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
        },
        Some(policy) => apply_override(connector_id, &contract_report, policy, current_time),
    }
}

/// Apply a policy override to a failing conformance result.
fn apply_override(
    connector_id: &str,
    report: &ContractReport,
    policy: &PolicyOverride,
    current_time: &str,
) -> PublicationGateResult {
    let mut errors = Vec::new();

    // Check expiry
    if current_time > policy.expires_at.as_str() {
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
pub fn run_harness(
    connectors: &[(String, Vec<MethodDeclaration>, Option<PolicyOverride>)],
    current_time: &str,
) -> HarnessReport {
    let mut results = Vec::new();
    for (id, decls, override_policy) in connectors {
        results.push(check_publication(
            id,
            decls,
            override_policy.as_ref(),
            current_time,
        ));
    }

    let passed = results.iter().filter(|r| r.gate_decision == "ALLOW").count();
    let overridden = results
        .iter()
        .filter(|r| r.gate_decision == "ALLOW_OVERRIDE")
        .count();
    let blocked = results
        .iter()
        .filter(|r| r.gate_decision == "BLOCK")
        .count();
    let verdict = if blocked == 0 { "PASS" } else { "FAIL" };

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
        let result = check_publication("test-conn", &full_declarations(), None, "2026-01-01T00:00:00Z");
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
        assert!(result
            .errors
            .iter()
            .any(|e| e.code == GateErrorCode::OverrideExpired));
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
        assert!(result
            .errors
            .iter()
            .any(|e| e.code == GateErrorCode::OverrideScopeMismatch));
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
