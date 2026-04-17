//! Standard connector method contract validator.
//!
//! Validates that a connector implements all required methods with
//! schema-conformant inputs and outputs. Produces a machine-readable
//! validation report.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use tracing::{debug, info, instrument, warn};

/// The nine standard connector methods.
pub const STANDARD_METHODS: &[MethodSpec] = &[
    MethodSpec {
        name: "handshake",
        required: true,
        version: "1.0.0",
    },
    MethodSpec {
        name: "describe",
        required: true,
        version: "1.0.0",
    },
    MethodSpec {
        name: "introspect",
        required: true,
        version: "1.0.0",
    },
    MethodSpec {
        name: "capabilities",
        required: true,
        version: "1.0.0",
    },
    MethodSpec {
        name: "configure",
        required: true,
        version: "1.0.0",
    },
    MethodSpec {
        name: "simulate",
        required: false,
        version: "1.0.0",
    },
    MethodSpec {
        name: "invoke",
        required: true,
        version: "1.0.0",
    },
    MethodSpec {
        name: "health",
        required: true,
        version: "1.0.0",
    },
    MethodSpec {
        name: "shutdown",
        required: true,
        version: "1.0.0",
    },
];

/// Specification for a single connector method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodSpec {
    pub name: &'static str,
    pub required: bool,
    pub version: &'static str,
}

/// A connector's declaration of a method it implements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDeclaration {
    pub name: String,
    pub version: String,
    pub has_input_schema: bool,
    pub has_output_schema: bool,
}

/// Error codes for method validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MethodErrorCode {
    MethodMissing,
    SchemaMismatch,
    VersionIncompatible,
    ResponseInvalid,
}

impl fmt::Display for MethodErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MethodMissing => write!(f, "METHOD_MISSING"),
            Self::SchemaMismatch => write!(f, "SCHEMA_MISMATCH"),
            Self::VersionIncompatible => write!(f, "VERSION_INCOMPATIBLE"),
            Self::ResponseInvalid => write!(f, "RESPONSE_INVALID"),
        }
    }
}

/// Validation result for a single method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodValidationResult {
    pub method: String,
    pub required: bool,
    pub status: String,
    pub version_expected: String,
    pub version_found: Option<String>,
    pub errors: Vec<MethodValidationError>,
}

/// A single validation error for a method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodValidationError {
    pub code: MethodErrorCode,
    pub message: String,
}

/// The complete validation report for a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractReport {
    pub connector_id: String,
    pub schema_version: String,
    pub verdict: String,
    pub methods: Vec<MethodValidationResult>,
    pub summary: ReportSummary,
}

/// Summary counts for the validation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_methods: usize,
    pub required_methods: usize,
    pub passing: usize,
    pub failing: usize,
    pub skipped: usize,
}

/// Validate a connector's method declarations against the standard contract.
///
/// Takes the connector's declared methods and checks each against the
/// pinned specification. Returns a machine-readable report.
#[instrument(skip(declarations), fields(methods = declarations.len()))]
pub fn validate_contract(connector_id: &str, declarations: &[MethodDeclaration]) -> ContractReport {
    info!(
        connector_id,
        declared = declarations.len(),
        "validating connector contract"
    );
    let decl_map: BTreeMap<&str, &MethodDeclaration> =
        declarations.iter().map(|d| (d.name.as_str(), d)).collect();

    let mut results = Vec::new();

    for spec in STANDARD_METHODS {
        match decl_map.get(spec.name) {
            None => {
                let mut errors = Vec::new();
                if spec.required {
                    warn!(method = spec.name, "required method missing");
                    errors.push(MethodValidationError {
                        code: MethodErrorCode::MethodMissing,
                        message: format!("Required method '{}' is not implemented", spec.name),
                    });
                } else {
                    debug!(
                        method = spec.name,
                        "optional method not declared — skipping"
                    );
                }
                results.push(MethodValidationResult {
                    method: spec.name.to_string(),
                    required: spec.required,
                    status: if spec.required { "FAIL" } else { "SKIP" }.to_string(),
                    version_expected: spec.version.to_string(),
                    version_found: None,
                    errors,
                });
            }
            Some(decl) => {
                let mut errors = Vec::new();

                // Version compatibility check (major version must match)
                if !is_version_compatible(spec.version, &decl.version) {
                    warn!(
                        method = spec.name,
                        expected = spec.version,
                        found = %decl.version,
                        "version incompatible"
                    );
                    errors.push(MethodValidationError {
                        code: MethodErrorCode::VersionIncompatible,
                        message: format!(
                            "Method '{}' version {} is not compatible with pinned {}",
                            spec.name, decl.version, spec.version
                        ),
                    });
                }

                // Schema presence check
                if !decl.has_input_schema || !decl.has_output_schema {
                    warn!(
                        method = spec.name,
                        has_input = decl.has_input_schema,
                        has_output = decl.has_output_schema,
                        "schema mismatch"
                    );
                    errors.push(MethodValidationError {
                        code: MethodErrorCode::SchemaMismatch,
                        message: format!(
                            "Method '{}' missing {} schema",
                            spec.name,
                            if !decl.has_input_schema {
                                "input"
                            } else {
                                "output"
                            }
                        ),
                    });
                }

                if errors.is_empty() {
                    debug!(method = spec.name, "method PASS");
                }

                results.push(MethodValidationResult {
                    method: spec.name.to_string(),
                    required: spec.required,
                    status: if errors.is_empty() { "PASS" } else { "FAIL" }.to_string(),
                    version_expected: spec.version.to_string(),
                    version_found: Some(decl.version.clone()),
                    errors,
                });
            }
        }
    }

    let passing = results.iter().filter(|r| r.status == "PASS").count();
    let failing = results.iter().filter(|r| r.status == "FAIL").count();
    let skipped = results.iter().filter(|r| r.status == "SKIP").count();
    let required_count = STANDARD_METHODS.iter().filter(|m| m.required).count();

    let verdict = if failing == 0 { "PASS" } else { "FAIL" };

    info!(
        connector_id,
        passing, failing, skipped, verdict, "contract validation complete"
    );

    ContractReport {
        connector_id: connector_id.to_string(),
        schema_version: "1.0.0".to_string(),
        verdict: verdict.to_string(),
        methods: results,
        summary: ReportSummary {
            total_methods: STANDARD_METHODS.len(),
            required_methods: required_count,
            passing,
            failing,
            skipped,
        },
    }
}

/// Check if a declared version is compatible with the pinned version.
///
/// Uses major-version compatibility: major versions must match.
fn is_version_compatible(pinned: &str, declared: &str) -> bool {
    let Some(pinned_major) = parse_major_version(pinned) else {
        return false;
    };
    let Some(declared_major) = parse_major_version(declared) else {
        return false;
    };
    pinned_major == declared_major
}

fn parse_major_version(version: &str) -> Option<&str> {
    if version.trim() != version {
        return None;
    }
    let major = version.split('.').next()?;
    if major.is_empty() || !major.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(major)
}

/// Return the list of required method names.
pub fn required_methods() -> Vec<&'static str> {
    STANDARD_METHODS
        .iter()
        .filter(|m| m.required)
        .map(|m| m.name)
        .collect()
}

/// Return all method names.
pub fn all_methods() -> Vec<&'static str> {
    STANDARD_METHODS.iter().map(|m| m.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn required_only_declarations() -> Vec<MethodDeclaration> {
        required_methods()
            .into_iter()
            .map(|name| MethodDeclaration {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                has_input_schema: true,
                has_output_schema: true,
            })
            .collect()
    }

    #[test]
    fn nine_standard_methods() {
        assert_eq!(STANDARD_METHODS.len(), 9);
    }

    #[test]
    fn eight_required_methods() {
        assert_eq!(required_methods().len(), 8);
    }

    #[test]
    fn simulate_is_optional() {
        let sim = STANDARD_METHODS
            .iter()
            .find(|m| m.name == "simulate")
            .unwrap();
        assert!(!sim.required);
    }

    #[test]
    fn full_contract_passes() {
        let report = validate_contract("test-conn", &full_declarations());
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.summary.failing, 0);
    }

    #[test]
    fn required_only_passes() {
        let report = validate_contract("test-conn", &required_only_declarations());
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.summary.skipped, 1); // simulate skipped
    }

    #[test]
    fn missing_required_method_fails() {
        let decls: Vec<MethodDeclaration> = full_declarations()
            .into_iter()
            .filter(|d| d.name != "handshake")
            .collect();
        let report = validate_contract("test-conn", &decls);
        assert_eq!(report.verdict, "FAIL");
        let handshake = report
            .methods
            .iter()
            .find(|m| m.method == "handshake")
            .unwrap();
        assert_eq!(handshake.status, "FAIL");
        assert_eq!(handshake.errors[0].code, MethodErrorCode::MethodMissing);
    }

    #[test]
    fn incompatible_version_fails() {
        let mut decls = full_declarations();
        decls[0].version = "2.0.0".to_string(); // handshake pinned at 1.x
        let report = validate_contract("test-conn", &decls);
        assert_eq!(report.verdict, "FAIL");
        let handshake = report
            .methods
            .iter()
            .find(|m| m.method == "handshake")
            .unwrap();
        assert!(
            handshake
                .errors
                .iter()
                .any(|e| e.code == MethodErrorCode::VersionIncompatible)
        );
    }

    #[test]
    fn missing_schema_fails() {
        let mut decls = full_declarations();
        decls[0].has_output_schema = false;
        let report = validate_contract("test-conn", &decls);
        assert_eq!(report.verdict, "FAIL");
    }

    #[test]
    fn minor_version_compatible() {
        assert!(is_version_compatible("1.0.0", "1.2.3"));
    }

    #[test]
    fn major_version_incompatible() {
        assert!(!is_version_compatible("1.0.0", "2.0.0"));
    }

    #[test]
    fn report_has_connector_id() {
        let report = validate_contract("my-conn-42", &full_declarations());
        assert_eq!(report.connector_id, "my-conn-42");
    }

    #[test]
    fn report_summary_counts() {
        let report = validate_contract("test-conn", &full_declarations());
        assert_eq!(report.summary.total_methods, 9);
        assert_eq!(report.summary.required_methods, 8);
        assert_eq!(report.summary.passing, 9);
        assert_eq!(report.summary.failing, 0);
        assert_eq!(report.summary.skipped, 0);
    }

    #[test]
    fn empty_declarations_fails() {
        let report = validate_contract("test-conn", &[]);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.summary.failing, 8); // 8 required missing
        assert_eq!(report.summary.skipped, 1); // simulate optional
    }

    #[test]
    fn case_mismatched_required_method_name_is_treated_as_missing() {
        let mut decls = full_declarations();
        decls
            .iter_mut()
            .find(|decl| decl.name == "handshake")
            .expect("handshake declaration")
            .name = "Handshake".to_string();

        let report = validate_contract("test-conn", &decls);
        let handshake = report
            .methods
            .iter()
            .find(|method| method.method == "handshake")
            .expect("handshake result");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(handshake.status, "FAIL");
        assert_eq!(handshake.version_found, None);
        assert_eq!(handshake.errors[0].code, MethodErrorCode::MethodMissing);
    }

    #[test]
    fn whitespace_suffixed_required_method_name_is_treated_as_missing() {
        let mut decls = full_declarations();
        decls
            .iter_mut()
            .find(|decl| decl.name == "invoke")
            .expect("invoke declaration")
            .name = "invoke ".to_string();

        let report = validate_contract("test-conn", &decls);
        let invoke = report
            .methods
            .iter()
            .find(|method| method.method == "invoke")
            .expect("invoke result");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(invoke.status, "FAIL");
        assert_eq!(invoke.errors[0].code, MethodErrorCode::MethodMissing);
    }

    #[test]
    fn blank_version_fails_version_compatibility() {
        let mut decls = full_declarations();
        decls
            .iter_mut()
            .find(|decl| decl.name == "describe")
            .expect("describe declaration")
            .version = String::new();

        let report = validate_contract("test-conn", &decls);
        let describe = report
            .methods
            .iter()
            .find(|method| method.method == "describe")
            .expect("describe result");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(describe.status, "FAIL");
        assert!(
            describe
                .errors
                .iter()
                .any(|error| error.code == MethodErrorCode::VersionIncompatible)
        );
    }

    #[test]
    fn leading_whitespace_version_fails_version_compatibility() {
        let mut decls = full_declarations();
        decls
            .iter_mut()
            .find(|decl| decl.name == "capabilities")
            .expect("capabilities declaration")
            .version = " 1.0.0".to_string();

        let report = validate_contract("test-conn", &decls);
        let capabilities = report
            .methods
            .iter()
            .find(|method| method.method == "capabilities")
            .expect("capabilities result");

        assert_eq!(report.verdict, "FAIL");
        assert!(
            capabilities
                .errors
                .iter()
                .any(|error| error.code == MethodErrorCode::VersionIncompatible)
        );
    }

    #[test]
    fn optional_simulate_with_invalid_schema_fails_when_declared() {
        let mut decls = required_only_declarations();
        decls.push(MethodDeclaration {
            name: "simulate".to_string(),
            version: "1.0.0".to_string(),
            has_input_schema: false,
            has_output_schema: true,
        });

        let report = validate_contract("test-conn", &decls);
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
                .any(|error| error.code == MethodErrorCode::SchemaMismatch)
        );
    }

    #[test]
    fn duplicate_method_declaration_with_bad_later_entry_fails() {
        let mut decls = full_declarations();
        decls.push(MethodDeclaration {
            name: "health".to_string(),
            version: "2.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: true,
        });

        let report = validate_contract("test-conn", &decls);
        let health = report
            .methods
            .iter()
            .find(|method| method.method == "health")
            .expect("health result");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(health.version_found.as_deref(), Some("2.0.0"));
        assert!(
            health
                .errors
                .iter()
                .any(|error| error.code == MethodErrorCode::VersionIncompatible)
        );
    }

    #[test]
    fn unknown_only_declaration_does_not_satisfy_required_methods() {
        let decls = vec![MethodDeclaration {
            name: "custom_extension".to_string(),
            version: "1.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: true,
        }];

        let report = validate_contract("test-conn", &decls);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.summary.failing, 8);
        assert_eq!(report.summary.skipped, 1);
        assert!(
            report
                .methods
                .iter()
                .all(|method| method.method != "custom_extension")
        );
    }

    #[test]
    fn version_and_schema_errors_accumulate_for_same_method() {
        let mut decls = full_declarations();
        let configure = decls
            .iter_mut()
            .find(|decl| decl.name == "configure")
            .expect("configure declaration");
        configure.version = "2.0.0".to_string();
        configure.has_output_schema = false;

        let report = validate_contract("test-conn", &decls);
        let configure = report
            .methods
            .iter()
            .find(|method| method.method == "configure")
            .expect("configure result");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(configure.errors.len(), 2);
        assert!(
            configure
                .errors
                .iter()
                .any(|error| error.code == MethodErrorCode::VersionIncompatible)
        );
        assert!(
            configure
                .errors
                .iter()
                .any(|error| error.code == MethodErrorCode::SchemaMismatch)
        );
    }

    #[test]
    fn trailing_whitespace_version_fails_version_compatibility() {
        let mut decls = full_declarations();
        decls
            .iter_mut()
            .find(|decl| decl.name == "health")
            .expect("health declaration")
            .version = "1.0.0 ".to_string();

        let report = validate_contract("test-conn", &decls);
        let health = report
            .methods
            .iter()
            .find(|method| method.method == "health")
            .expect("health result");

        assert_eq!(report.verdict, "FAIL");
        assert!(
            health
                .errors
                .iter()
                .any(|error| error.code == MethodErrorCode::VersionIncompatible)
        );
    }

    #[test]
    fn non_numeric_major_version_fails_version_compatibility() {
        let mut decls = full_declarations();
        decls
            .iter_mut()
            .find(|decl| decl.name == "shutdown")
            .expect("shutdown declaration")
            .version = "one.0.0".to_string();

        let report = validate_contract("test-conn", &decls);
        let shutdown = report
            .methods
            .iter()
            .find(|method| method.method == "shutdown")
            .expect("shutdown result");

        assert_eq!(report.verdict, "FAIL");
        assert!(
            shutdown
                .errors
                .iter()
                .any(|error| error.code == MethodErrorCode::VersionIncompatible)
        );
    }

    #[test]
    fn zero_major_version_fails_version_compatibility() {
        let mut decls = full_declarations();
        decls
            .iter_mut()
            .find(|decl| decl.name == "introspect")
            .expect("introspect declaration")
            .version = "0.9.0".to_string();

        let report = validate_contract("test-conn", &decls);
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
                .any(|error| error.code == MethodErrorCode::VersionIncompatible)
        );
    }

    #[test]
    fn optional_simulate_with_incompatible_version_fails_when_declared() {
        let mut decls = required_only_declarations();
        decls.push(MethodDeclaration {
            name: "simulate".to_string(),
            version: "2.0.0".to_string(),
            has_input_schema: true,
            has_output_schema: true,
        });

        let report = validate_contract("test-conn", &decls);
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
                .any(|error| error.code == MethodErrorCode::VersionIncompatible)
        );
    }

    #[test]
    fn required_method_missing_both_schemas_reports_schema_mismatch() {
        let mut decls = full_declarations();
        let invoke = decls
            .iter_mut()
            .find(|decl| decl.name == "invoke")
            .expect("invoke declaration");
        invoke.has_input_schema = false;
        invoke.has_output_schema = false;

        let report = validate_contract("test-conn", &decls);
        let invoke = report
            .methods
            .iter()
            .find(|method| method.method == "invoke")
            .expect("invoke result");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(invoke.status, "FAIL");
        assert_eq!(invoke.errors.len(), 1);
        assert_eq!(invoke.errors[0].code, MethodErrorCode::SchemaMismatch);
    }

    #[test]
    fn multiple_missing_required_methods_are_reported_independently() {
        let decls: Vec<MethodDeclaration> = full_declarations()
            .into_iter()
            .filter(|decl| decl.name != "handshake" && decl.name != "health")
            .collect();

        let report = validate_contract("test-conn", &decls);
        let missing: Vec<&str> = report
            .methods
            .iter()
            .filter(|method| method.status == "FAIL")
            .map(|method| method.method.as_str())
            .collect();

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.summary.failing, 2);
        assert!(missing.contains(&"handshake"));
        assert!(missing.contains(&"health"));
    }

    #[test]
    fn required_method_prefix_lookalike_does_not_satisfy_contract() {
        let mut decls = full_declarations();
        decls
            .iter_mut()
            .find(|decl| decl.name == "handshake")
            .expect("handshake declaration")
            .name = "handshake.extra".to_string();

        let report = validate_contract("test-conn", &decls);
        let handshake = report
            .methods
            .iter()
            .find(|method| method.method == "handshake")
            .expect("handshake result");

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(handshake.status, "FAIL");
        assert_eq!(handshake.version_found, None);
        assert_eq!(handshake.errors[0].code, MethodErrorCode::MethodMissing);
    }

    #[test]
    fn negative_method_error_code_rejects_unknown_variant() {
        let err = serde_json::from_str::<MethodErrorCode>(r#""METHOD_TIMEOUT""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn negative_method_declaration_rejects_missing_name() {
        let err = serde_json::from_str::<MethodDeclaration>(
            r#"{
                "version":"1.0.0",
                "has_input_schema":true,
                "has_output_schema":true
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn negative_method_declaration_rejects_string_schema_flag() {
        let err = serde_json::from_str::<MethodDeclaration>(
            r#"{
                "name":"handshake",
                "version":"1.0.0",
                "has_input_schema":"true",
                "has_output_schema":true
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_validation_result_rejects_scalar_errors() {
        let err = serde_json::from_str::<MethodValidationResult>(
            r#"{
                "method":"handshake",
                "required":true,
                "status":"FAIL",
                "version_expected":"1.0.0",
                "version_found":null,
                "errors":"not-a-list"
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn negative_validation_error_rejects_unknown_code() {
        let err = serde_json::from_str::<MethodValidationError>(
            r#"{"code":"METHOD_TIMEOUT","message":"timed out"}"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn negative_contract_report_rejects_missing_summary() {
        let err = serde_json::from_str::<ContractReport>(
            r#"{
                "connector_id":"conn",
                "schema_version":"1.0.0",
                "verdict":"FAIL",
                "methods":[]
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("summary"));
    }

    #[test]
    fn negative_report_summary_rejects_negative_counts() {
        let err = serde_json::from_str::<ReportSummary>(
            r#"{
                "total_methods":-1,
                "required_methods":8,
                "passing":0,
                "failing":8,
                "skipped":1
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid value"));
    }

    #[test]
    fn negative_padded_major_version_is_not_parsed() {
        assert_eq!(parse_major_version(" 1.0.0"), None);
        assert_eq!(parse_major_version("1.0.0 "), None);
        assert!(!is_version_compatible("1.0.0", " 1.0.0"));
    }

    #[test]
    fn serde_roundtrip_report() {
        let report = validate_contract("test-conn", &full_declarations());
        let json = serde_json::to_string(&report).unwrap();
        let parsed: ContractReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.verdict, "PASS");
        assert_eq!(parsed.methods.len(), 9);
    }
}
