pub mod connector_method_validator;
pub mod fsqlite_inspired_suite;
pub mod protocol_harness;

/// Initialize tracing subscriber for test runs.
///
/// Call at the top of integration tests to get structured debug output.
/// Uses `try_init` so it's safe to call multiple times (only the first
/// call actually installs the subscriber).
#[cfg(test)]
pub fn init_test_tracing() {
    if let Err(e) = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
    {
        eprintln!("conformance: failed to initialize tracing: {}", e);
    }
}

#[cfg(test)]
mod tracing_integration_tests {
    use super::*;
    use connector_method_validator::{MethodDeclaration, MethodErrorCode, all_methods};
    use protocol_harness::{PolicyOverride, check_publication, run_harness};

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

    #[test]
    fn test_tracing_init_does_not_panic() {
        init_test_tracing();
        init_test_tracing(); // safe to call twice
    }

    #[test]
    fn test_validate_contract_emits_traces() {
        init_test_tracing();
        let report =
            connector_method_validator::validate_contract("traced-conn", &full_declarations());
        assert_eq!(report.verdict, "PASS");
    }

    #[test]
    fn test_validate_contract_failure_emits_warn() {
        init_test_tracing();
        let report = connector_method_validator::validate_contract(
            "traced-fail",
            &missing_handshake_declarations(),
        );
        assert_eq!(report.verdict, "FAIL");
        assert!(report.summary.failing > 0);
    }

    #[test]
    fn test_check_publication_traces_pass() {
        init_test_tracing();
        let result = check_publication(
            "traced-conn",
            &full_declarations(),
            None,
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "ALLOW");
    }

    #[test]
    fn test_check_publication_traces_block() {
        init_test_tracing();
        let result = check_publication(
            "traced-fail",
            &missing_handshake_declarations(),
            None,
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "BLOCK");
    }

    #[test]
    fn test_check_publication_traces_override() {
        init_test_tracing();
        let policy = PolicyOverride {
            override_id: "OVERRIDE-TRACE-001".to_string(),
            connector_id: "traced-conn".to_string(),
            reason: "Testing".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:handshake".to_string()],
        };
        let result = check_publication(
            "traced-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "ALLOW_OVERRIDE");
    }

    #[test]
    fn test_check_publication_traces_expired_override() {
        init_test_tracing();
        let policy = PolicyOverride {
            override_id: "OVERRIDE-EXP-001".to_string(),
            connector_id: "traced-conn".to_string(),
            reason: "Expired".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2020-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:handshake".to_string()],
        };
        let result = check_publication(
            "traced-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "BLOCK");
    }

    #[test]
    fn test_run_harness_traces_full_run() {
        init_test_tracing();
        let connectors = vec![
            ("conn-ok".to_string(), full_declarations(), None),
            (
                "conn-fail".to_string(),
                missing_handshake_declarations(),
                None,
            ),
        ];
        let report = run_harness(&connectors, "2026-01-01T00:00:00Z");
        assert_eq!(report.total_connectors, 2);
        assert_eq!(report.passed, 1);
        assert_eq!(report.blocked, 1);
    }

    #[test]
    fn test_run_harness_empty_traced() {
        init_test_tracing();
        let report = run_harness(&[], "2026-01-01T00:00:00Z");
        assert_eq!(report.verdict, "PASS");
    }

    #[test]
    fn test_version_mismatch_traced() {
        init_test_tracing();
        let mut decls = full_declarations();
        decls[0].version = "2.0.0".to_string(); // major version mismatch
        let report = connector_method_validator::validate_contract("version-mismatch", &decls);
        assert_eq!(report.verdict, "FAIL");
    }

    #[test]
    fn test_schema_missing_traced() {
        init_test_tracing();
        let mut decls = full_declarations();
        decls[0].has_input_schema = false;
        let report = connector_method_validator::validate_contract("schema-missing", &decls);
        assert_eq!(report.verdict, "FAIL");
    }

    #[test]
    fn test_override_scope_with_trailing_space_does_not_match_failure() {
        init_test_tracing();
        let policy = PolicyOverride {
            override_id: "OVERRIDE-SCOPE-SPACE".to_string(),
            connector_id: "traced-conn".to_string(),
            reason: "Whitespace scope should not match".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:handshake ".to_string()],
        };

        let result = check_publication(
            "traced-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(!result.override_applied);
        assert!(
            result.errors.iter().any(|error| {
                error.code == protocol_harness::GateErrorCode::OverrideScopeMismatch
            })
        );
    }

    #[test]
    fn test_override_scope_is_case_sensitive() {
        init_test_tracing();
        let policy = PolicyOverride {
            override_id: "OVERRIDE-SCOPE-CASE".to_string(),
            connector_id: "traced-conn".to_string(),
            reason: "Lowercase scope should not match".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            scope: vec!["method_missing:handshake".to_string()],
        };

        let result = check_publication(
            "traced-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(
            result.errors.iter().any(|error| {
                error.code == protocol_harness::GateErrorCode::OverrideScopeMismatch
            })
        );
    }

    #[test]
    fn test_override_with_wrong_connector_and_expiry_reports_both_errors() {
        init_test_tracing();
        let policy = PolicyOverride {
            override_id: "OVERRIDE-MULTI-FAIL".to_string(),
            connector_id: "other-conn".to_string(),
            reason: "Multiple negative gates".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2020-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:handshake".to_string()],
        };

        let result = check_publication(
            "traced-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(!result.override_applied);
        assert!(
            result.errors.iter().any(|error| {
                error.code == protocol_harness::GateErrorCode::ConnectorIdMismatch
            })
        );
        assert!(
            result
                .errors
                .iter()
                .any(|error| { error.code == protocol_harness::GateErrorCode::OverrideExpired })
        );
    }

    #[test]
    fn test_optional_only_connector_is_blocked_for_missing_required_methods() {
        init_test_tracing();
        let declarations = vec![MethodDeclaration {
            name: "simulate".to_string(),
            version: "1.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: true,
        }];

        let result =
            check_publication("optional-only", &declarations, None, "2026-01-01T00:00:00Z");

        assert_eq!(result.conformance_verdict, "FAIL");
        assert_eq!(result.gate_decision, "BLOCK");
        assert!(result.errors[0].message.contains("8 error"));
    }

    #[test]
    fn test_duplicate_required_declaration_with_last_invalid_schema_fails() {
        init_test_tracing();
        let mut declarations = full_declarations();
        declarations.push(MethodDeclaration {
            name: "handshake".to_string(),
            version: "1.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: false,
        });

        let report =
            connector_method_validator::validate_contract("duplicate-handshake", &declarations);
        let handshake = report
            .methods
            .iter()
            .find(|method| method.method == "handshake")
            .expect("handshake result");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(handshake.status, "FAIL");
        assert!(handshake.errors.iter().any(|error| {
            error.code == connector_method_validator::MethodErrorCode::SchemaMismatch
        }));
    }

    #[test]
    fn test_duplicate_required_declaration_with_last_major_version_fails() {
        init_test_tracing();
        let mut declarations = full_declarations();
        declarations.push(MethodDeclaration {
            name: "invoke".to_string(),
            version: "2.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: true,
        });

        let report =
            connector_method_validator::validate_contract("duplicate-invoke", &declarations);
        let invoke = report
            .methods
            .iter()
            .find(|method| method.method == "invoke")
            .expect("invoke result");

        assert_eq!(report.verdict, "FAIL");
        assert!(invoke.errors.iter().any(|error| {
            error.code == connector_method_validator::MethodErrorCode::VersionIncompatible
        }));
    }

    #[test]
    fn test_harness_counts_expired_overrides_as_blocked_not_overridden() {
        init_test_tracing();
        let expired_policy = PolicyOverride {
            override_id: "OVERRIDE-HARNESS-EXPIRED".to_string(),
            connector_id: "expired-conn".to_string(),
            reason: "Expired harness override".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2020-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:handshake".to_string()],
        };
        let connectors = vec![(
            "expired-conn".to_string(),
            missing_handshake_declarations(),
            Some(expired_policy),
        )];

        let report = run_harness(&connectors, "2026-01-01T00:00:00Z");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.blocked, 1);
        assert_eq!(report.overridden, 0);
        assert_eq!(report.results[0].gate_decision, "BLOCK");
    }

    #[test]
    fn test_whitespace_method_name_is_treated_as_missing_required_method() {
        init_test_tracing();
        let declarations = full_declarations()
            .into_iter()
            .map(|mut declaration| {
                if declaration.name == "handshake" {
                    declaration.name = "handshake ".to_string();
                }
                declaration
            })
            .collect::<Vec<_>>();

        let report =
            connector_method_validator::validate_contract("whitespace-method", &declarations);
        let handshake = report
            .methods
            .iter()
            .find(|method| method.method == "handshake")
            .expect("handshake result");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(handshake.status, "FAIL");
        assert_eq!(handshake.version_found, None);
        assert!(
            handshake
                .errors
                .iter()
                .any(|error| { error.code == MethodErrorCode::MethodMissing })
        );
    }

    #[test]
    fn test_blank_required_method_version_fails_compatibility() {
        init_test_tracing();
        let declarations = full_declarations()
            .into_iter()
            .map(|mut declaration| {
                if declaration.name == "describe" {
                    declaration.version.clear();
                }
                declaration
            })
            .collect::<Vec<_>>();

        let report = connector_method_validator::validate_contract("blank-version", &declarations);
        let describe = report
            .methods
            .iter()
            .find(|method| method.method == "describe")
            .expect("describe result");

        assert_eq!(report.verdict, "FAIL");
        assert!(
            describe
                .errors
                .iter()
                .any(|error| { error.code == MethodErrorCode::VersionIncompatible })
        );
    }

    #[test]
    fn test_whitespace_padded_method_version_fails_compatibility() {
        init_test_tracing();
        let declarations = full_declarations()
            .into_iter()
            .map(|mut declaration| {
                if declaration.name == "introspect" {
                    declaration.version = " 1.0.0 ".to_string();
                }
                declaration
            })
            .collect::<Vec<_>>();

        let report = connector_method_validator::validate_contract("padded-version", &declarations);
        let introspect = report
            .methods
            .iter()
            .find(|method| method.method == "introspect")
            .expect("introspect result");

        assert_eq!(report.verdict, "FAIL");
        assert!(
            introspect
                .errors
                .iter()
                .any(|error| { error.code == MethodErrorCode::VersionIncompatible })
        );
    }

    #[test]
    fn test_optional_method_with_invalid_schema_is_not_silently_skipped() {
        init_test_tracing();
        let declarations = full_declarations()
            .into_iter()
            .map(|mut declaration| {
                if declaration.name == "simulate" {
                    declaration.has_input_schema = false;
                }
                declaration
            })
            .collect::<Vec<_>>();

        let report =
            connector_method_validator::validate_contract("optional-schema", &declarations);
        let simulate = report
            .methods
            .iter()
            .find(|method| method.method == "simulate")
            .expect("simulate result");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(simulate.required, false);
        assert_eq!(simulate.status, "FAIL");
        assert!(
            simulate
                .errors
                .iter()
                .any(|error| { error.code == MethodErrorCode::SchemaMismatch })
        );
    }

    #[test]
    fn test_override_scope_for_optional_schema_failure_must_match_failure_code() {
        init_test_tracing();
        let declarations = full_declarations()
            .into_iter()
            .map(|mut declaration| {
                if declaration.name == "simulate" {
                    declaration.has_output_schema = false;
                }
                declaration
            })
            .collect::<Vec<_>>();
        let policy = PolicyOverride {
            override_id: "OVERRIDE-OPTIONAL-WRONG-SCOPE".to_string(),
            connector_id: "optional-schema".to_string(),
            reason: "Wrong override scope".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:simulate".to_string()],
        };

        let result = check_publication(
            "optional-schema",
            &declarations,
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(!result.override_applied);
        let scope_error = result
            .errors
            .iter()
            .find(|error| error.code == protocol_harness::GateErrorCode::OverrideScopeMismatch)
            .expect("scope mismatch");
        assert!(scope_error.message.contains("SCHEMA_MISMATCH:simulate"));
    }

    #[test]
    fn test_override_for_empty_declaration_set_must_cover_every_required_method() {
        init_test_tracing();
        let policy = PolicyOverride {
            override_id: "OVERRIDE-EMPTY-PARTIAL".to_string(),
            connector_id: "empty-connector".to_string(),
            reason: "Partial emergency override".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:handshake".to_string()],
        };

        let result = check_publication(
            "empty-connector",
            &[],
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(result.gate_decision, "BLOCK");
        assert!(!result.override_applied);
        let scope_error = result
            .errors
            .iter()
            .find(|error| error.code == protocol_harness::GateErrorCode::OverrideScopeMismatch)
            .expect("scope mismatch");
        assert!(scope_error.message.contains("METHOD_MISSING:describe"));
        assert!(scope_error.message.contains("METHOD_MISSING:shutdown"));
    }

    #[test]
    fn test_harness_with_pass_override_and_block_still_fails_overall() {
        init_test_tracing();
        let override_policy = PolicyOverride {
            override_id: "OVERRIDE-MIXED-PASS".to_string(),
            connector_id: "conn-override".to_string(),
            reason: "Scoped mixed harness override".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:handshake".to_string()],
        };
        let connectors = vec![
            ("conn-pass".to_string(), full_declarations(), None),
            (
                "conn-override".to_string(),
                missing_handshake_declarations(),
                Some(override_policy),
            ),
            (
                "conn-block".to_string(),
                missing_handshake_declarations(),
                None,
            ),
        ];

        let report = run_harness(&connectors, "2026-01-01T00:00:00Z");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.passed, 1);
        assert_eq!(report.overridden, 1);
        assert_eq!(report.blocked, 1);
        assert_eq!(report.results[2].gate_decision, "BLOCK");
    }
}
