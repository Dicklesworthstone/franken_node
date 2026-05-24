//! Conformance harness for connector method contract validator.
//!
//! Validates critical method validation invariants for connector contract compliance:
//! - **MUST-CMV-001**: All required methods MUST be validated as present or report METHOD_MISSING
//! - **MUST-CMV-002**: Version compatibility MUST fail for major version mismatches
//! - **MUST-CMV-003**: Contract reports MUST include all standard method specifications
//! - **MUST-CMV-004**: Schema presence validation MUST enforce input/output schema requirements
//! - **SHOULD-CMV-005**: Validation errors SHOULD provide actionable failure messages
//! - **SHOULD-CMV-006**: Report summaries SHOULD accurately count passing/failing methods
//! - **MAY-CMV-007**: Optional methods MAY be skipped without affecting verdict

use franken_node::conformance::connector_method_validator::{
    ContractReport, MethodDeclaration, MethodErrorCode, MethodValidationError,
    MethodValidationResult, ReportSummary, STANDARD_METHODS, validate_contract,
};

/// **MUST-CMV-001**: All required methods MUST be validated as present
/// or report METHOD_MISSING error code.
///
/// Specification: Required method enforcement
#[test]
fn conformance_must_cmv_001_required_methods_validated_or_missing_reported() {
    // Test case: Connector declaring no methods
    let empty_declarations = vec![];

    let report = validate_contract("test-connector-empty", &empty_declarations);

    // Count required methods from specification
    let required_count = STANDARD_METHODS.iter().filter(|spec| spec.required).count();

    // Should have validation results for all standard methods
    assert_eq!(
        report.methods.len(),
        STANDARD_METHODS.len(),
        "Report should include all standard methods"
    );

    // All required methods should be marked as FAIL with METHOD_MISSING
    let required_failures: Vec<_> = report
        .methods
        .iter()
        .filter(|result| result.required && result.status == "FAIL")
        .collect();

    assert_eq!(
        required_failures.len(),
        required_count,
        "All required methods should be marked as FAIL when missing"
    );

    for result in required_failures {
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e.code, MethodErrorCode::MethodMissing)),
            "Required method '{}' should have METHOD_MISSING error",
            result.method
        );

        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("Required method")
                    && e.message.contains("not implemented")),
            "Required method '{}' should have descriptive error message",
            result.method
        );
    }

    // Verdict should be FAIL when required methods are missing
    assert_eq!(
        report.verdict, "FAIL",
        "Contract should fail when required methods are missing"
    );

    // Summary should accurately reflect failures
    assert_eq!(
        report.summary.failing, required_count,
        "Summary should count all required method failures"
    );
    assert_eq!(
        report.summary.passing, 0,
        "Summary should show no passing methods when all required are missing"
    );
}

/// **MUST-CMV-002**: Version compatibility MUST fail for major version mismatches.
/// Compatible: same major, minor can be higher. Incompatible: different major.
///
/// Specification: Semantic version compatibility enforcement
#[test]
fn conformance_must_cmv_002_version_compatibility_enforced() {
    // Test cases: version compatibility matrix
    let version_test_cases = vec![
        // (declared_version, expected_result, description)
        ("1.0.0", true, "exact match should be compatible"),
        ("1.0.1", true, "patch upgrade should be compatible"),
        ("1.1.0", true, "minor upgrade should be compatible"),
        ("1.2.5", true, "minor.patch upgrade should be compatible"),
        ("0.9.9", false, "major downgrade should be incompatible"),
        ("2.0.0", false, "major upgrade should be incompatible"),
        (
            "2.1.0",
            false,
            "major upgrade with minor should be incompatible",
        ),
        (
            "0.1.0",
            false,
            "different major (0.x) should be incompatible",
        ),
    ];

    for (declared_version, should_be_compatible, description) in version_test_cases {
        let declarations = vec![MethodDeclaration {
            name: "handshake".to_string(), // Required method
            version: declared_version.to_string(),
            has_input_schema: true,
            has_output_schema: true,
        }];

        let report = validate_contract(
            &format!(
                "test-connector-version-{}",
                declared_version.replace('.', "-")
            ),
            &declarations,
        );

        let handshake_result = report
            .methods
            .iter()
            .find(|m| m.method == "handshake")
            .expect("handshake method should be in results");

        let has_version_error = handshake_result
            .errors
            .iter()
            .any(|e| matches!(e.code, MethodErrorCode::VersionIncompatible));

        if should_be_compatible {
            assert!(
                !has_version_error,
                "{}: version {} should be compatible with 1.0.0",
                description, declared_version
            );

            assert_eq!(
                handshake_result.status, "PASS",
                "{}: compatible version should result in PASS status",
                description
            );
        } else {
            assert!(
                has_version_error,
                "{}: version {} should be incompatible with 1.0.0",
                description, declared_version
            );

            assert_eq!(
                handshake_result.status, "FAIL",
                "{}: incompatible version should result in FAIL status",
                description
            );

            // Check error message quality
            let version_error = handshake_result
                .errors
                .iter()
                .find(|e| matches!(e.code, MethodErrorCode::VersionIncompatible))
                .unwrap();

            assert!(
                version_error.message.contains(declared_version)
                    && version_error.message.contains("1.0.0"),
                "Version error message should mention both versions: {}",
                version_error.message
            );
        }
    }
}

/// **MUST-CMV-003**: Contract reports MUST include validation results
/// for all standard method specifications.
///
/// Specification: Complete method coverage validation
#[test]
fn conformance_must_cmv_003_complete_method_coverage_validation() {
    // Create declarations for subset of methods to test partial coverage
    let partial_declarations = vec![
        MethodDeclaration {
            name: "handshake".to_string(),
            version: "1.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: true,
        },
        MethodDeclaration {
            name: "describe".to_string(),
            version: "1.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: true,
        },
        MethodDeclaration {
            name: "simulate".to_string(), // Optional method
            version: "1.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: true,
        },
        // Missing: introspect, capabilities, configure, invoke, health, shutdown
    ];

    let report = validate_contract("test-connector-partial", &partial_declarations);

    // Report MUST include all standard methods
    assert_eq!(
        report.methods.len(),
        STANDARD_METHODS.len(),
        "Report must include results for all {} standard methods",
        STANDARD_METHODS.len()
    );

    // Verify each standard method is covered
    for spec in STANDARD_METHODS {
        let method_result = report
            .methods
            .iter()
            .find(|r| r.method == spec.name)
            .expect(&format!(
                "Report must include result for method '{}'",
                spec.name
            ));

        assert_eq!(
            method_result.required, spec.required,
            "Method '{}' required flag must match specification",
            spec.name
        );

        assert_eq!(
            method_result.version_expected, spec.version,
            "Method '{}' expected version must match specification",
            spec.name
        );
    }

    // Verify declared methods are marked as PASS
    let declared_methods = ["handshake", "describe", "simulate"];
    for method_name in declared_methods {
        let result = report
            .methods
            .iter()
            .find(|r| r.method == method_name)
            .unwrap();

        assert_eq!(
            result.status, "PASS",
            "Declared method '{}' should have PASS status",
            method_name
        );

        assert!(
            result.errors.is_empty(),
            "Declared method '{}' should have no errors",
            method_name
        );
    }

    // Verify undeclared required methods are marked as FAIL
    let undeclared_required = [
        "introspect",
        "capabilities",
        "configure",
        "invoke",
        "health",
        "shutdown",
    ];
    for method_name in undeclared_required {
        let result = report
            .methods
            .iter()
            .find(|r| r.method == method_name)
            .unwrap();

        assert_eq!(
            result.status, "FAIL",
            "Undeclared required method '{}' should have FAIL status",
            method_name
        );

        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e.code, MethodErrorCode::MethodMissing)),
            "Undeclared required method '{}' should have METHOD_MISSING error",
            method_name
        );
    }

    // Summary must accurately reflect all methods
    assert_eq!(
        report.summary.total_methods,
        STANDARD_METHODS.len(),
        "Summary total_methods must match standard method count"
    );

    let expected_required = STANDARD_METHODS.iter().filter(|s| s.required).count();
    assert_eq!(
        report.summary.required_methods, expected_required,
        "Summary required_methods must match specification"
    );
}

/// **MUST-CMV-004**: Schema presence validation MUST enforce
/// input/output schema requirements for all methods.
///
/// Specification: Schema requirement enforcement
#[test]
fn conformance_must_cmv_004_schema_presence_validation_enforced() {
    // Test cases: schema presence combinations
    let schema_test_cases = vec![
        // (has_input, has_output, should_pass, description)
        (true, true, true, "both schemas present should pass"),
        (true, false, false, "missing output schema should fail"),
        (false, true, false, "missing input schema should fail"),
        (false, false, false, "missing both schemas should fail"),
    ];

    for (has_input, has_output, should_pass, description) in schema_test_cases {
        let declarations = vec![MethodDeclaration {
            name: "invoke".to_string(), // Required method
            version: "1.0.0".to_string(),
            has_input_schema: has_input,
            has_output_schema: has_output,
        }];

        let report = validate_contract(
            &format!("test-schema-{}-{}", has_input, has_output),
            &declarations,
        );

        let invoke_result = report
            .methods
            .iter()
            .find(|m| m.method == "invoke")
            .unwrap();

        if should_pass {
            assert_eq!(
                invoke_result.status, "PASS",
                "{}: should pass when schemas are present",
                description
            );

            assert!(
                invoke_result.errors.is_empty(),
                "{}: should have no errors when schemas are present",
                description
            );
        } else {
            assert_eq!(
                invoke_result.status, "FAIL",
                "{}: should fail when schemas are missing",
                description
            );

            let has_schema_error = invoke_result
                .errors
                .iter()
                .any(|e| matches!(e.code, MethodErrorCode::SchemaMismatch));

            assert!(
                has_schema_error,
                "{}: should have SCHEMA_MISMATCH error when schemas are missing",
                description
            );

            // Verify error message mentions specific schema missing
            let schema_error = invoke_result
                .errors
                .iter()
                .find(|e| matches!(e.code, MethodErrorCode::SchemaMismatch))
                .unwrap();

            if !has_input {
                assert!(
                    schema_error.message.contains("input")
                        || schema_error.message.contains("Input"),
                    "Schema error should mention missing input schema: {}",
                    schema_error.message
                );
            }

            if !has_output {
                assert!(
                    schema_error.message.contains("output")
                        || schema_error.message.contains("Output"),
                    "Schema error should mention missing output schema: {}",
                    schema_error.message
                );
            }
        }
    }
}

/// **SHOULD-CMV-005**: Validation errors SHOULD provide actionable failure messages
/// that clearly identify the problem and suggest remediation.
///
/// Specification: Error message quality
#[test]
fn conformance_should_cmv_005_validation_errors_provide_actionable_messages() {
    // Create scenario with multiple error types
    let problematic_declarations = vec![
        // Missing method (will be reported)
        // handshake: missing entirely

        // Version incompatible
        MethodDeclaration {
            name: "describe".to_string(),
            version: "2.0.0".to_string(), // Incompatible major version
            has_input_schema: true,
            has_output_schema: true,
        },
        // Schema missing
        MethodDeclaration {
            name: "introspect".to_string(),
            version: "1.0.0".to_string(),
            has_input_schema: false, // Missing input schema
            has_output_schema: true,
        },
        // Multiple issues
        MethodDeclaration {
            name: "capabilities".to_string(),
            version: "0.5.0".to_string(), // Incompatible version
            has_input_schema: false,      // Missing input schema
            has_output_schema: false,     // Missing output schema
        },
    ];

    let report = validate_contract("test-connector-errors", &problematic_declarations);

    // Check METHOD_MISSING error message quality
    let handshake_result = report
        .methods
        .iter()
        .find(|m| m.method == "handshake")
        .unwrap();

    let missing_error = handshake_result
        .errors
        .iter()
        .find(|e| matches!(e.code, MethodErrorCode::MethodMissing))
        .unwrap();

    assert!(
        missing_error.message.contains("Required method")
            && missing_error.message.contains("handshake"),
        "METHOD_MISSING error should identify specific method: {}",
        missing_error.message
    );

    assert!(
        missing_error.message.contains("not implemented")
            || missing_error.message.contains("missing"),
        "METHOD_MISSING error should clearly state the problem: {}",
        missing_error.message
    );

    // Check VERSION_INCOMPATIBLE error message quality
    let describe_result = report
        .methods
        .iter()
        .find(|m| m.method == "describe")
        .unwrap();

    let version_error = describe_result
        .errors
        .iter()
        .find(|e| matches!(e.code, MethodErrorCode::VersionIncompatible))
        .unwrap();

    assert!(
        version_error.message.contains("2.0.0") && version_error.message.contains("1.0.0"),
        "VERSION_INCOMPATIBLE error should mention both versions: {}",
        version_error.message
    );

    assert!(
        version_error.message.contains("not compatible")
            || version_error.message.contains("incompatible"),
        "VERSION_INCOMPATIBLE error should clearly state incompatibility: {}",
        version_error.message
    );

    // Check SCHEMA_MISMATCH error message quality
    let introspect_result = report
        .methods
        .iter()
        .find(|m| m.method == "introspect")
        .unwrap();

    let schema_error = introspect_result
        .errors
        .iter()
        .find(|e| matches!(e.code, MethodErrorCode::SchemaMismatch))
        .unwrap();

    assert!(
        schema_error.message.contains("schema") || schema_error.message.contains("Schema"),
        "SCHEMA_MISMATCH error should mention schema: {}",
        schema_error.message
    );

    // Check multiple error handling for capabilities method
    let capabilities_result = report
        .methods
        .iter()
        .find(|m| m.method == "capabilities")
        .unwrap();

    assert!(
        capabilities_result.errors.len() >= 2,
        "Method with multiple issues should have multiple errors: {} errors found",
        capabilities_result.errors.len()
    );

    // Should have both version and schema errors
    let has_version_error = capabilities_result
        .errors
        .iter()
        .any(|e| matches!(e.code, MethodErrorCode::VersionIncompatible));
    let has_schema_error = capabilities_result
        .errors
        .iter()
        .any(|e| matches!(e.code, MethodErrorCode::SchemaMismatch));

    assert!(
        has_version_error,
        "capabilities method should have version error"
    );
    assert!(
        has_schema_error,
        "capabilities method should have schema error"
    );
}

/// **SHOULD-CMV-006**: Report summaries SHOULD accurately count
/// passing/failing methods with correct totals.
///
/// Specification: Summary accuracy validation
#[test]
fn conformance_should_cmv_006_report_summaries_accurately_count_methods() {
    // Create scenario with known distribution of results
    let mixed_declarations = vec![
        // 2 passing methods
        MethodDeclaration {
            name: "handshake".to_string(),
            version: "1.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: true,
        },
        MethodDeclaration {
            name: "describe".to_string(),
            version: "1.1.0".to_string(), // Compatible minor upgrade
            has_input_schema: true,
            has_output_schema: true,
        },
        // 1 failing method (version incompatible)
        MethodDeclaration {
            name: "introspect".to_string(),
            version: "2.0.0".to_string(), // Incompatible major version
            has_input_schema: true,
            has_output_schema: true,
        },
        // 1 optional method (will be skipped)
        MethodDeclaration {
            name: "simulate".to_string(),
            version: "1.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: true,
        },
        // Missing methods: capabilities, configure, invoke, health, shutdown (all required)
    ];

    let report = validate_contract("test-connector-summary", &mixed_declarations);

    // Calculate expected counts
    let expected_total = STANDARD_METHODS.len();
    let expected_required = STANDARD_METHODS.iter().filter(|s| s.required).count();
    let expected_passing = 3; // handshake, describe, simulate
    let expected_failing = 6; // introspect (version error) + 5 missing required methods
    let expected_skipped = 0; // No optional methods are missing in this test

    // Verify summary accuracy
    assert_eq!(
        report.summary.total_methods, expected_total,
        "Summary total_methods should be {}, got {}",
        expected_total, report.summary.total_methods
    );

    assert_eq!(
        report.summary.required_methods, expected_required,
        "Summary required_methods should be {}, got {}",
        expected_required, report.summary.required_methods
    );

    assert_eq!(
        report.summary.passing, expected_passing,
        "Summary passing should be {}, got {}",
        expected_passing, report.summary.passing
    );

    assert_eq!(
        report.summary.failing, expected_failing,
        "Summary failing should be {}, got {}",
        expected_failing, report.summary.failing
    );

    // Verify total consistency
    assert_eq!(
        report.summary.passing + report.summary.failing + report.summary.skipped,
        report.summary.total_methods,
        "Summary counts should sum to total_methods"
    );

    // Verify verdict reflects failures
    assert_eq!(
        report.verdict, "FAIL",
        "Verdict should be FAIL when there are failing methods"
    );

    // Double-check by manually counting results
    let actual_passing = report.methods.iter().filter(|r| r.status == "PASS").count();
    let actual_failing = report.methods.iter().filter(|r| r.status == "FAIL").count();
    let actual_skipped = report.methods.iter().filter(|r| r.status == "SKIP").count();

    assert_eq!(
        report.summary.passing, actual_passing,
        "Summary passing count should match actual PASS results"
    );

    assert_eq!(
        report.summary.failing, actual_failing,
        "Summary failing count should match actual FAIL results"
    );

    assert_eq!(
        report.summary.skipped, actual_skipped,
        "Summary skipped count should match actual SKIP results"
    );
}

/// **MAY-CMV-007**: Optional methods MAY be skipped without affecting
/// the overall contract verdict when all required methods pass.
///
/// Specification: Optional method handling
#[test]
fn conformance_may_cmv_007_optional_methods_skipped_without_affecting_verdict() {
    // Create complete required method set, skip optional methods
    let required_only_declarations: Vec<MethodDeclaration> = STANDARD_METHODS
        .iter()
        .filter(|spec| spec.required)
        .map(|spec| MethodDeclaration {
            name: spec.name.to_string(),
            version: spec.version.to_string(),
            has_input_schema: true,
            has_output_schema: true,
        })
        .collect();

    let report = validate_contract("test-connector-required-only", &required_only_declarations);

    // Find optional methods in results
    let optional_results: Vec<_> = report.methods.iter().filter(|r| !r.required).collect();

    assert!(
        !optional_results.is_empty(),
        "Should have optional method results"
    );

    // All optional methods should be skipped
    for optional_result in optional_results {
        assert_eq!(
            optional_result.status, "SKIP",
            "Optional method '{}' should be skipped when not declared",
            optional_result.method
        );

        assert!(
            optional_result.errors.is_empty(),
            "Optional method '{}' should have no errors when skipped",
            optional_result.method
        );

        assert!(
            optional_result.version_found.is_none(),
            "Optional method '{}' should have no version_found when skipped",
            optional_result.method
        );
    }

    // Verdict should be PASS when all required methods are present and optional are skipped
    assert_eq!(
        report.verdict, "PASS",
        "Contract should pass when all required methods are present, even if optional methods are skipped"
    );

    // Summary should reflect skipped optional methods
    let expected_optional_count = STANDARD_METHODS.iter().filter(|s| !s.required).count();
    assert_eq!(
        report.summary.skipped, expected_optional_count,
        "Summary should count skipped optional methods"
    );

    // All required methods should be passing
    let required_count = STANDARD_METHODS.iter().filter(|s| s.required).count();
    assert_eq!(
        report.summary.passing, required_count,
        "All required methods should be passing"
    );

    assert_eq!(
        report.summary.failing, 0,
        "No methods should be failing when all required are declared correctly"
    );

    // Test that including optional method changes the verdict positively
    let with_optional_declarations: Vec<MethodDeclaration> = STANDARD_METHODS
        .iter()
        .map(|spec| MethodDeclaration {
            name: spec.name.to_string(),
            version: spec.version.to_string(),
            has_input_schema: true,
            has_output_schema: true,
        })
        .collect();

    let with_optional_report =
        validate_contract("test-connector-with-optional", &with_optional_declarations);

    // Both reports should have PASS verdict
    assert_eq!(
        with_optional_report.verdict, "PASS",
        "Contract should pass when optional methods are included"
    );

    // With optional should have higher passing count
    assert!(
        with_optional_report.summary.passing > report.summary.passing,
        "Including optional methods should increase passing count"
    );

    // With optional should have no skipped methods
    assert_eq!(
        with_optional_report.summary.skipped, 0,
        "Including all methods should result in no skipped methods"
    );
}
