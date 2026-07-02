//! Golden artifact tests for remote capability envelope canonical forms
//!
//! Tests the deterministic serialization and validation output for:
//! - RemoteCap token structures with scope validation
//! - CapabilityProvider issuance patterns
//! - CapabilityGate authorization decisions and audit events
//! - RemoteScope normalization and validation logic

use crate::golden;
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteCap, RemoteCapAuditEvent,
    RemoteOperation, RemoteScope,
};
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn test_remote_capability_envelope_basic_structure() {
    // Test basic RemoteCap structure serialization
    let provider =
        CapabilityProvider::new("test-signing-secret").expect("Should create provider");

    let scope = RemoteScope::new(
        vec![
            RemoteOperation::NetworkEgress,
            RemoteOperation::FederationSync,
        ],
        vec![
            "https://api.example.com/".to_string(),
            "https://sync.example.com/".to_string(),
        ],
    );

    let (cap, _issue_event) = provider
        .issue(
            "test-issuer",
            scope,
            1234567890, // Fixed issued_at timestamp
            3600,       // TTL seconds (1 hour)
            true,       // operator authorized
            false,      // Not single-use
            "trace-issue-basic",
        )
        .expect("Should issue capability successfully");

    let cap_json = serde_json::to_value(&cap).expect("Should serialize to JSON");
    golden::assert_scrubbed_json_golden("remote_capability_envelope/basic_structure", &cap_json);
}

#[test]
fn test_remote_scope_normalization() {
    // Test RemoteScope normalization with duplicate operations and unsorted endpoints
    let scope = RemoteScope::new(
        vec![
            RemoteOperation::NetworkEgress,
            RemoteOperation::FederationSync,
            RemoteOperation::NetworkEgress, // Duplicate - should be normalized
            RemoteOperation::RemoteAttestationVerify,
        ],
        vec![
            "https://zzz.example.com/".to_string(), // Out of order
            "https://aaa.example.com/".to_string(),
            "https://mmm.example.com/".to_string(),
            "https://aaa.example.com/".to_string(), // Duplicate
        ],
    );

    let scope_json = serde_json::to_value(&scope).expect("Should serialize normalized scope");
    golden::assert_scrubbed_json_golden("remote_capability_envelope/normalized_scope", &scope_json);
}

#[test]
fn test_remote_scope_validation_patterns() {
    // Test various scope validation patterns
    let test_cases = vec![
        ("empty_scope", RemoteScope::new(vec![], vec![])),
        (
            "single_operation",
            RemoteScope::new(
                vec![RemoteOperation::TelemetryExport],
                vec!["https://telemetry.example.com/".to_string()],
            ),
        ),
        (
            "all_operations",
            RemoteScope::new(
                vec![
                    RemoteOperation::NetworkEgress,
                    RemoteOperation::FederationSync,
                    RemoteOperation::RevocationFetch,
                    RemoteOperation::RemoteAttestationVerify,
                    RemoteOperation::TelemetryExport,
                    RemoteOperation::RemoteComputation,
                    RemoteOperation::ArtifactUpload,
                ],
                vec![
                    "https://api.example.com/".to_string(),
                    "https://compute.example.com/".to_string(),
                    "https://storage.example.com/".to_string(),
                ],
            ),
        ),
        (
            "wildcard_endpoints",
            RemoteScope::new(
                vec![RemoteOperation::NetworkEgress],
                vec!["https://*.example.com/".to_string(), "*".to_string()],
            ),
        ),
    ];

    for (test_name, scope) in test_cases {
        let scope_json = serde_json::to_value(&scope).expect("Should serialize scope");
        golden::assert_scrubbed_json_golden(
            &format!("remote_capability_envelope/scope_validation/{}", test_name),
            &scope_json,
        );
    }
}

#[test]
fn test_capability_provider_issuance_patterns() {
    let provider =
        CapabilityProvider::new("test-signing-secret").expect("Should create provider");

    // Test different issuance patterns
    let test_cases = vec![
        (
            "single_use_capability",
            provider.issue(
                "test-issuer",
                RemoteScope::new(
                    vec![RemoteOperation::RemoteComputation],
                    vec!["https://compute.example.com/single-use".to_string()],
                ),
                1234567890,
                3600,
                true, // operator authorized
                true, // Single-use
                "trace-issuance-single",
            ),
        ),
        (
            "multi_use_capability",
            provider.issue(
                "test-issuer",
                RemoteScope::new(
                    vec![
                        RemoteOperation::NetworkEgress,
                        RemoteOperation::TelemetryExport,
                    ],
                    vec![
                        "https://api.example.com/".to_string(),
                        "https://telemetry.example.com/".to_string(),
                    ],
                ),
                1234567890,
                87000, // 24 hours later
                true,  // operator authorized
                false, // Multi-use
                "trace-issuance-multi",
            ),
        ),
        (
            "short_lived_capability",
            provider.issue(
                "ephemeral-issuer",
                RemoteScope::new(
                    vec![RemoteOperation::RevocationFetch],
                    vec!["https://revocation.example.com/".to_string()],
                ),
                1234567890,
                60, // 1 minute later
                true,
                false,
                "trace-issuance-short",
            ),
        ),
    ];

    for (test_name, capability_result) in test_cases {
        match capability_result {
            Ok((cap, _)) => {
                let cap_json = serde_json::to_value(&cap).expect("Should serialize capability");
                golden::assert_scrubbed_json_golden(
                    &format!("remote_capability_envelope/issuance_patterns/{}", test_name),
                    &cap_json,
                );
            }
            Err(err) => {
                let error_json = json!({
                    "error": true,
                    "message": format!("{}", err),
                    "test_case": test_name,
                });
                golden::assert_scrubbed_json_golden(
                    &format!(
                        "remote_capability_envelope/issuance_patterns/{}_error",
                        test_name
                    ),
                    &error_json,
                );
            }
        }
    }
}

#[test]
fn test_capability_gate_authorization_decisions() {
    let provider =
        CapabilityProvider::new("gate-test-secret").expect("Should create provider");
    let mut gate = CapabilityGate::new("gate-test-secret").expect("Should create gate");

    // Create test capability
    let scope = RemoteScope::new(
        vec![
            RemoteOperation::NetworkEgress,
            RemoteOperation::TelemetryExport,
        ],
        vec!["https://allowed.example.com/".to_string()],
    );

    let (cap, _issue_event) = provider
        .issue(
            "gate-issuer",
            scope,
            1234567890,
            87000,
            true,
            false,
            "trace-gate-issue",
        )
        .expect("Should issue capability");

    // Test authorization decisions
    let test_cases = vec![
        (
            "allowed_operation_and_endpoint",
            gate.authorize_network(
                Some(&cap),
                RemoteOperation::NetworkEgress,
                "https://allowed.example.com/api",
                1234567900,
                "trace-001",
            ),
        ),
        (
            "allowed_operation_different_endpoint",
            gate.authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://allowed.example.com/metrics",
                1234567900,
                "trace-002",
            ),
        ),
        (
            "disallowed_operation",
            gate.authorize_network(
                Some(&cap),
                RemoteOperation::RemoteComputation,
                "https://allowed.example.com/api",
                1234567900,
                "trace-003",
            ),
        ),
        (
            "disallowed_endpoint",
            gate.authorize_network(
                Some(&cap),
                RemoteOperation::NetworkEgress,
                "https://malicious.example.com/api",
                1234567900,
                "trace-004",
            ),
        ),
        (
            "expired_capability",
            gate.authorize_network(
                Some(&cap),
                RemoteOperation::NetworkEgress,
                "https://allowed.example.com/api",
                1234654900,
                "trace-005",
            ), // After expiry
        ),
    ];

    for (test_name, auth_result) in test_cases {
        let result_json = match auth_result {
            Ok(()) => json!({
                "authorized": true,
                "test_case": test_name,
            }),
            Err(err) => json!({
                "authorized": false,
                "error": format!("{}", err),
                "test_case": test_name,
            }),
        };

        golden::assert_scrubbed_json_golden(
            &format!(
                "remote_capability_envelope/authorization_decisions/{}",
                test_name
            ),
            &result_json,
        );
    }
}

#[test]
fn test_capability_gate_audit_events() {
    let provider =
        CapabilityProvider::new("audit-test-secret").expect("Should create provider");
    let mut gate = CapabilityGate::new("audit-test-secret").expect("Should create gate");

    let scope = RemoteScope::new(
        vec![RemoteOperation::NetworkEgress],
        vec!["https://api.example.com/".to_string()],
    );

    let (cap, _issue_event) = provider
        .issue(
            "audit-issuer",
            scope,
            1234567890,
            87000,
            true,
            false,
            "trace-audit-issue",
        )
        .expect("Should issue capability");

    // Generate various authorization attempts to create audit events
    let _ = gate.authorize_network(
        Some(&cap),
        RemoteOperation::NetworkEgress,
        "https://api.example.com/data",
        1234567900,
        "trace-audit-001",
    );
    let _ = gate.authorize_network(
        Some(&cap),
        RemoteOperation::FederationSync,
        "https://api.example.com/sync",
        1234567910,
        "trace-audit-002",
    ); // Should fail
    let _ = gate.authorize_network(
        Some(&cap),
        RemoteOperation::NetworkEgress,
        "https://unauthorized.com/",
        1234567920,
        "trace-audit-003",
    ); // Should fail

    // Capture audit events
    let audit_events = gate.audit_log();
    let audit_json = serde_json::to_value(audit_events).expect("Should serialize audit events");

    golden::assert_scrubbed_json_golden("remote_capability_envelope/audit_events", &audit_json);
}

#[test]
fn test_remote_capability_envelope_boundary_conditions() {
    let provider =
        CapabilityProvider::new("boundary-test-secret").expect("Should create provider");

    // Test boundary conditions
    let boundary_test_cases = vec![
        (
            "extremely_long_token_id",
            provider.issue(
                &"x".repeat(1000), // Very long issuer identity
                RemoteScope::new(
                    vec![RemoteOperation::NetworkEgress],
                    vec!["https://example.com/".to_string()],
                ),
                1234567890,
                87000,
                true,
                false,
                "trace-boundary-long",
            ),
        ),
        (
            "empty_endpoint_list",
            provider.issue(
                "issuer",
                RemoteScope::new(vec![RemoteOperation::NetworkEgress], vec![]),
                1234567890,
                87000,
                true,
                false,
                "trace-boundary-empty-endpoints",
            ),
        ),
        (
            "empty_operations_list",
            provider.issue(
                "issuer",
                RemoteScope::new(vec![], vec!["https://example.com/".to_string()]),
                1234567890,
                87000,
                true,
                false,
                "trace-boundary-empty-operations",
            ),
        ),
        (
            "zero_expiry_time",
            provider.issue(
                "issuer",
                RemoteScope::new(
                    vec![RemoteOperation::NetworkEgress],
                    vec!["https://example.com/".to_string()],
                ),
                1234567890,
                0, // Zero TTL (invalid) exercises fail-closed path
                true,
                false,
                "trace-boundary-zero",
            ),
        ),
    ];

    for (test_name, capability_result) in boundary_test_cases {
        let result_json = match capability_result {
            Ok((cap, _)) => {
                let cap_value = serde_json::to_value(&cap).expect("Should serialize");
                json!({
                    "success": true,
                    "capability": cap_value,
                    "test_case": test_name,
                })
            }
            Err(err) => json!({
                "success": false,
                "error": format!("{}", err),
                "test_case": test_name,
            }),
        };

        golden::assert_scrubbed_json_golden(
            &format!(
                "remote_capability_envelope/boundary_conditions/{}",
                test_name
            ),
            &result_json,
        );
    }
}

#[test]
fn test_connectivity_mode_impact() {
    let provider =
        CapabilityProvider::new("connectivity-test-secret").expect("Should create provider");

    let scope = RemoteScope::new(
        vec![RemoteOperation::NetworkEgress],
        vec!["https://example.com/".to_string()],
    );

    let (cap, _issue_event) = provider
        .issue(
            "issuer",
            scope,
            1234567890,
            87000,
            true,
            false,
            "trace-connectivity-issue",
        )
        .expect("Should issue capability");

    // Test both connectivity modes
    let connectivity_modes = vec![ConnectivityMode::Connected, ConnectivityMode::LocalOnly];

    for mode in connectivity_modes {
        let mut gate = CapabilityGate::with_mode("connectivity-test-secret", mode)
            .expect("Should create gate");

        let auth_result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::NetworkEgress,
            "https://example.com/api",
            1234567900,
            "trace-connectivity-test",
        );

        let result_json = json!({
            "connectivity_mode": format!("{}", mode),
            "authorized": auth_result.is_ok(),
            "error": auth_result.err().map(|e| format!("{}", e)),
        });

        golden::assert_scrubbed_json_golden(
            &format!("remote_capability_envelope/connectivity_modes/{:?}", mode),
            &result_json,
        );
    }
}

#[test]
fn test_remote_operation_enum_serialization() {
    // Test that RemoteOperation enum serialization is stable
    let operations = vec![
        RemoteOperation::NetworkEgress,
        RemoteOperation::FederationSync,
        RemoteOperation::RevocationFetch,
        RemoteOperation::RemoteAttestationVerify,
        RemoteOperation::TelemetryExport,
        RemoteOperation::RemoteComputation,
        RemoteOperation::ArtifactUpload,
    ];

    let operations_json = serde_json::to_value(&operations).expect("Should serialize operations");
    golden::assert_json_golden(
        "remote_capability_envelope/remote_operations_enum",
        &operations_json,
    );
}
