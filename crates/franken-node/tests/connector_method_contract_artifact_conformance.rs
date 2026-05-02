#[path = "../src/conformance/connector_method_validator.rs"]
mod connector_method_validator;

use connector_method_validator::{MethodDeclaration, STANDARD_METHODS, validate_contract};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const CONNECTOR_METHOD_CONTRACT: &str =
    include_str!("../../../docs/specs/section_10_13/bd-1h6_contract.md");
const CONNECTOR_METHOD_REPORT: &str =
    include_str!("../../../artifacts/section_10_13/bd-1h6/connector_method_contract_report.json");

fn report() -> Value {
    serde_json::from_str(CONNECTOR_METHOD_REPORT)
        .expect("checked-in connector method contract report must be valid JSON")
}

fn array_field<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("report field `{field}` must be an array"))
}

fn object_field<'a>(value: &'a Value, field: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(field)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("report field `{field}` must be an object"))
}

fn str_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("report field `{field}` must be a string"))
}

fn bool_field(value: &Value, field: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("report field `{field}` must be a bool"))
}

fn u64_object_field(value: &serde_json::Map<String, Value>, field: &str) -> u64 {
    value
        .get(field)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("report field `{field}` must be a number"))
}

fn declarations_from_standard_methods(skip_method: Option<&str>) -> Vec<MethodDeclaration> {
    STANDARD_METHODS
        .iter()
        .filter(|spec| skip_method != Some(spec.name))
        .map(|spec| MethodDeclaration {
            name: spec.name.to_string(),
            version: spec.version.to_string(),
            has_input_schema: true,
            has_output_schema: true,
        })
        .collect()
}

#[test]
fn connector_method_artifact_matches_spec_and_validator_catalog() {
    assert!(
        CONNECTOR_METHOD_CONTRACT
            .contains("Every connector must implement a standard set of nine methods."),
        "bd-1h6 spec must remain the source for the standard method count"
    );
    assert!(
        CONNECTOR_METHOD_CONTRACT.contains("INV-METHOD-COMPLETE"),
        "bd-1h6 invariant text changed; update this conformance test with it"
    );

    let report = report();
    assert_eq!(
        str_field(&report, "schema"),
        "connector_method_contract_report"
    );
    assert_eq!(str_field(&report, "version"), "1.0.0");

    let methods = array_field(&report, "standard_methods");
    let summary = object_field(&report, "summary");
    assert_eq!(u64_object_field(summary, "total_methods"), 9);
    assert_eq!(u64_object_field(summary, "required_methods"), 8);
    assert_eq!(u64_object_field(summary, "optional_methods"), 1);
    assert_eq!(methods.len(), STANDARD_METHODS.len());

    let artifact_by_name = methods
        .iter()
        .map(|method| (str_field(method, "name"), method))
        .collect::<BTreeMap<_, _>>();
    let artifact_names = artifact_by_name.keys().copied().collect::<BTreeSet<_>>();
    let validator_names = STANDARD_METHODS
        .iter()
        .map(|spec| spec.name)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        artifact_names, validator_names,
        "artifact and validator must expose the same standard method names"
    );

    for spec in STANDARD_METHODS {
        let artifact = artifact_by_name
            .get(spec.name)
            .unwrap_or_else(|| panic!("artifact missing method {}", spec.name));
        assert!(
            CONNECTOR_METHOD_CONTRACT.contains(&format!("`{}`", spec.name)),
            "spec table must mention method {}",
            spec.name
        );
        assert_eq!(bool_field(artifact, "required"), spec.required);
        assert_eq!(str_field(artifact, "version"), spec.version);
        assert!(
            matches!(
                str_field(artifact, "direction"),
                "bidirectional" | "connector_to_host" | "host_to_connector"
            ),
            "method {} must declare a valid call direction",
            spec.name
        );
    }

    let validation = validate_contract(
        "artifact-backed-standard-methods",
        &declarations_from_standard_methods(None),
    );
    assert_eq!(validation.verdict, "PASS");
    assert_eq!(validation.summary.total_methods, 9);
    assert_eq!(validation.summary.required_methods, 8);
    assert_eq!(validation.summary.passing, 9);
    assert_eq!(validation.summary.failing, 0);
    assert_eq!(validation.summary.skipped, 0);
}

#[test]
fn missing_required_method_uses_checked_in_error_code() {
    let report = report();
    let error_codes = array_field(&report, "error_codes")
        .iter()
        .map(|code| code.as_str().expect("error codes must be strings"))
        .collect::<BTreeSet<_>>();
    assert!(error_codes.contains("METHOD_MISSING"));
    assert!(CONNECTOR_METHOD_CONTRACT.contains("`METHOD_MISSING`"));

    let validation = validate_contract(
        "missing-configure",
        &declarations_from_standard_methods(Some("configure")),
    );

    assert_eq!(validation.verdict, "FAIL");
    let configure = validation
        .methods
        .iter()
        .find(|method| method.method == "configure")
        .expect("configure must be in the validation report");
    assert_eq!(configure.status, "FAIL");
    assert_eq!(configure.errors.len(), 1);
    assert_eq!(configure.errors[0].code.to_string(), "METHOD_MISSING");
}

#[test]
fn optional_simulate_absence_is_skip_not_failure() {
    let artifact = report();
    let simulate = array_field(&artifact, "standard_methods")
        .iter()
        .find(|method| str_field(method, "name") == "simulate")
        .expect("simulate must be present in checked-in method artifact");
    assert!(!bool_field(simulate, "required"));

    let validation = validate_contract(
        "without-optional-simulate",
        &declarations_from_standard_methods(Some("simulate")),
    );

    assert_eq!(validation.verdict, "PASS");
    assert_eq!(validation.summary.failing, 0);
    assert_eq!(validation.summary.skipped, 1);
    let simulate = validation
        .methods
        .iter()
        .find(|method| method.method == "simulate")
        .expect("simulate must be in the validation report");
    assert_eq!(simulate.status, "SKIP");
    assert!(simulate.errors.is_empty());
}
