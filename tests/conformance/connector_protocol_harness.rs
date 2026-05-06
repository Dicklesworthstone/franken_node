//! Conformance tests: Connector protocol publication harness.
//!
//! Validates the publication gate logic: fail-closed behavior,
//! override scoping, expiry enforcement, and deterministic outcomes.
//!
//! Corresponds to bd-3en acceptance criteria:
//! - CI gate fails publication for non-conformant connectors
//! - Harness emits deterministic pass/fail reasons
//! - Bypass requires explicit policy override artifact

use frankenengine_node::conformance::connector_method_validator::{MethodDeclaration, all_methods};
use frankenengine_node::conformance::protocol_harness::{
    GateErrorCode, PolicyOverride, check_publication, run_harness,
};

const NOW: &str = "2026-01-01T00:00:00Z";
const CONNECTOR_ID: &str = "connector-under-test";

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
        .filter(|declaration| declaration.name != "handshake")
        .collect()
}

fn override_for(scope: Vec<&str>) -> PolicyOverride {
    PolicyOverride {
        override_id: "override-bd-3en".to_string(),
        connector_id: CONNECTOR_ID.to_string(),
        reason: "bounded publication exception for conformance test".to_string(),
        authorized_by: "security-review".to_string(),
        expires_at: "2030-01-01T00:00:00Z".to_string(),
        scope: scope.into_iter().map(str::to_string).collect(),
    }
}

fn has_error(
    errors: &[frankenengine_node::conformance::protocol_harness::GateError],
    code: GateErrorCode,
) -> bool {
    errors.iter().any(|error| error.code == code)
}

/// Publication gate is fail-closed: no override = blocked.
#[test]
fn fail_closed_default() {
    let result = check_publication(CONNECTOR_ID, &missing_handshake_declarations(), None, NOW);
    assert_eq!(result.conformance_verdict, "FAIL");
    assert_eq!(result.gate_decision, "BLOCK");
    assert!(!result.override_applied);
    assert!(has_error(&result.errors, GateErrorCode::PublicationBlocked));
}

/// Passing connector is allowed without override.
#[test]
fn passing_connector_no_override_needed() {
    let result = check_publication(CONNECTOR_ID, &full_declarations(), None, NOW);
    assert_eq!(result.conformance_verdict, "PASS");
    assert_eq!(result.gate_decision, "ALLOW");
    assert!(!result.override_applied);
    assert!(result.errors.is_empty());
}

/// Override must be scoped to the specific failure code.
#[test]
fn override_scope_must_match() {
    let policy = override_for(vec!["METHOD_MISSING:handshake"]);
    let result = check_publication(
        CONNECTOR_ID,
        &missing_handshake_declarations(),
        Some(&policy),
        NOW,
    );
    assert_eq!(result.gate_decision, "ALLOW_OVERRIDE");
    assert!(result.override_applied);
    assert!(result.errors.is_empty());
}

/// Wrong scope does not bypass the gate.
#[test]
fn wrong_scope_does_not_bypass() {
    let policy = override_for(vec!["SCHEMA_MISMATCH:handshake"]);
    let result = check_publication(
        CONNECTOR_ID,
        &missing_handshake_declarations(),
        Some(&policy),
        NOW,
    );
    assert_eq!(result.gate_decision, "BLOCK");
    assert!(!result.override_applied);
    assert!(has_error(
        &result.errors,
        GateErrorCode::OverrideScopeMismatch
    ));
}

/// Expired override does not bypass the gate.
#[test]
fn expired_override_rejected() {
    let policy = PolicyOverride {
        expires_at: "2020-01-01T00:00:00Z".to_string(),
        ..override_for(vec!["METHOD_MISSING:handshake"])
    };
    let result = check_publication(
        CONNECTOR_ID,
        &missing_handshake_declarations(),
        Some(&policy),
        NOW,
    );
    assert_eq!(result.gate_decision, "BLOCK");
    assert!(has_error(&result.errors, GateErrorCode::OverrideExpired));
}

/// Valid (non-expired) override is accepted.
#[test]
fn valid_override_accepted() {
    let policy = override_for(vec!["METHOD_MISSING:handshake"]);
    let result = check_publication(
        CONNECTOR_ID,
        &missing_handshake_declarations(),
        Some(&policy),
        NOW,
    );
    assert_eq!(result.gate_decision, "ALLOW_OVERRIDE");
    assert!(result.override_applied);
}

/// Harness with zero connectors passes through the real aggregate gate.
#[test]
fn empty_harness_passes() {
    let report = run_harness(&[], NOW);
    assert_eq!(report.verdict, "PASS");
    assert_eq!(report.total_connectors, 0);
    assert_eq!(report.blocked, 0);
}

/// Determinism: same input produces same output.
#[test]
fn deterministic_outcome() {
    let connectors = vec![
        (CONNECTOR_ID.to_string(), full_declarations(), None),
        (
            "blocked-connector".to_string(),
            missing_handshake_declarations(),
            None,
        ),
    ];
    let first = run_harness(&connectors, NOW);
    let second = run_harness(&connectors, NOW);
    assert_eq!(
        serde_json::to_value(&first).expect("serialize first harness report"),
        serde_json::to_value(&second).expect("serialize second harness report")
    );
}
