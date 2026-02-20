//! Standard connector method contract validator.
//!
//! Validates that a connector implements all required methods with
//! schema-conformant inputs and outputs. Produces a machine-readable
//! validation report.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

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
pub fn validate_contract(connector_id: &str, declarations: &[MethodDeclaration]) -> ContractReport {
    let decl_map: HashMap<&str, &MethodDeclaration> =
        declarations.iter().map(|d| (d.name.as_str(), d)).collect();

    let mut results = Vec::new();

    for spec in STANDARD_METHODS {
        match decl_map.get(spec.name) {
            None => {
                let mut errors = Vec::new();
                if spec.required {
                    errors.push(MethodValidationError {
                        code: MethodErrorCode::MethodMissing,
                        message: format!("Required method '{}' is not implemented", spec.name),
                    });
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
    let pinned_major = pinned.split('.').next().unwrap_or("0");
    let declared_major = declared.split('.').next().unwrap_or("0");
    pinned_major == declared_major
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
    fn serde_roundtrip_report() {
        let report = validate_contract("test-conn", &full_declarations());
        let json = serde_json::to_string(&report).unwrap();
        let parsed: ContractReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.verdict, "PASS");
        assert_eq!(parsed.methods.len(), 9);
    }
}
