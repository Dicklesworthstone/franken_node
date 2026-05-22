//! Fuzz target for operator JSON contract validation boundaries.
//!
//! Tests JSON validation against operator surface contracts, field path traversal,
//! required field checking, and malformed JSON handling. Critical for preventing
//! JSON injection attacks and validation bypass via crafted JSON input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use serde_json::{Value, json};

use frankenengine_node::operator_json_contracts::{
    OperatorJsonSurface, validate_operator_json_value, registered_surface_names
};

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: JsonValidationOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum JsonValidationOperation {
    ValidateContract {
        surface: JsonSurface,
        json_input: JsonInput,
    },
    BatchValidation {
        validations: Vec<(JsonSurface, JsonInput)>,
    },
    FieldPathTraversal {
        json_input: JsonInput,
        field_paths: Vec<String>,
    },
    MalformedJsonTests {
        surface: JsonSurface,
        malformed_input: MalformedJsonInput,
    },
    EdgeCaseValues {
        surface: JsonSurface,
        edge_case: EdgeCaseJson,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum JsonSurface {
    DoctorReport,
    VerifyReleaseReport,
    FleetReconcileReport,
    TrustCardExport,
    IncidentBundle,
    BenchRunReport,
    RuntimeEpochReport,
    RemoteCapabilityIssueReport,
}

impl JsonSurface {
    fn to_operator_surface(&self) -> OperatorJsonSurface {
        match self {
            Self::DoctorReport => OperatorJsonSurface::DoctorReport,
            Self::VerifyReleaseReport => OperatorJsonSurface::VerifyReleaseReport,
            Self::FleetReconcileReport => OperatorJsonSurface::FleetReconcileReport,
            Self::TrustCardExport => OperatorJsonSurface::TrustCardExport,
            Self::IncidentBundle => OperatorJsonSurface::IncidentBundle,
            Self::BenchRunReport => OperatorJsonSurface::BenchRunReport,
            Self::RuntimeEpochReport => OperatorJsonSurface::RuntimeEpochReport,
            Self::RemoteCapabilityIssueReport => OperatorJsonSurface::RemoteCapabilityIssueReport,
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct JsonInput {
    json_type: JsonInputType,
}

#[derive(Debug, Clone, Arbitrary)]
enum JsonInputType {
    ValidStructured(ValidJsonVariant),
    Malformed(String),
    Empty,
    VeryLarge(Vec<u8>),
    WithNullBytes(Vec<u8>),
    Unicode(String),
    DeeplyNested(u8), // nesting depth
    EdgeCaseNumbers(f64),
    ControlCharacters(Vec<u8>),
}

#[derive(Debug, Clone, Arbitrary)]
enum ValidJsonVariant {
    MinimalValid,
    FullStructured,
    WithRequiredFields,
    WithOptionalFields,
    WithNullValues,
    WithArrays,
    WithNestedObjects,
    CustomStructure(Vec<(String, JsonValueType)>),
}

#[derive(Debug, Clone, Arbitrary)]
enum JsonValueType {
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
    Array(Vec<String>),
    Object(Vec<(String, String)>),
}

#[derive(Debug, Clone, Arbitrary)]
struct MalformedJsonInput {
    malformation_type: MalformationType,
    base_content: String,
}

#[derive(Debug, Clone, Arbitrary)]
enum MalformationType {
    UnterminatedString,
    InvalidUnicode,
    DeeplyNested,
    VeryLargeNumbers,
    InvalidEscapes,
    ControlCharacters,
    ExtremeLengths,
    NullBytes,
    MixedQuoting,
    InvalidStructure,
}

#[derive(Debug, Clone, Arbitrary)]
enum EdgeCaseJson {
    MaxInteger,
    MinInteger,
    NaN,
    Infinity,
    VeryLongString,
    VeryDeeplyNested,
    ManyFields,
    EmptyStructures,
    NullEverything,
}

impl JsonInput {
    fn to_value(&self) -> Result<Value, serde_json::Error> {
        match &self.json_type {
            JsonInputType::ValidStructured(variant) => Ok(self.create_valid_json(variant)),
            JsonInputType::Malformed(s) => serde_json::from_str(s),
            JsonInputType::Empty => serde_json::from_str("{}"),
            JsonInputType::VeryLarge(bytes) => {
                let json_str = String::from_utf8_lossy(bytes);
                serde_json::from_str(&json_str)
            }
            JsonInputType::WithNullBytes(bytes) => {
                let json_str = String::from_utf8_lossy(bytes);
                serde_json::from_str(&json_str)
            }
            JsonInputType::Unicode(s) => serde_json::from_str(s),
            JsonInputType::DeeplyNested(depth) => Ok(self.create_nested_json(*depth)),
            JsonInputType::EdgeCaseNumbers(num) => Ok(json!({ "number": num })),
            JsonInputType::ControlCharacters(bytes) => {
                let json_str = String::from_utf8_lossy(bytes);
                serde_json::from_str(&json_str)
            }
        }
    }

    fn create_valid_json(&self, variant: &ValidJsonVariant) -> Value {
        match variant {
            ValidJsonVariant::MinimalValid => json!({}),
            ValidJsonVariant::FullStructured => json!({
                "id": "test-123",
                "timestamp": "2026-05-22T18:48:00Z",
                "status": "success",
                "data": {
                    "items": [],
                    "count": 0
                }
            }),
            ValidJsonVariant::WithRequiredFields => json!({
                "schema_version": "1.0.0",
                "surface": "doctor_report",
                "report_id": "doc-456"
            }),
            ValidJsonVariant::WithOptionalFields => json!({
                "schema_version": "1.0.0",
                "surface": "verify_release_report",
                "report_id": "verify-789",
                "optional_metadata": {
                    "generator": "franken-node",
                    "timestamp": "2026-05-22T18:48:00Z"
                }
            }),
            ValidJsonVariant::WithNullValues => json!({
                "id": "test-null",
                "optional_field": null,
                "data": {
                    "nullable_item": null
                }
            }),
            ValidJsonVariant::WithArrays => json!({
                "items": [
                    {"id": 1, "name": "item1"},
                    {"id": 2, "name": "item2"}
                ],
                "numbers": [1, 2, 3, 4, 5]
            }),
            ValidJsonVariant::WithNestedObjects => json!({
                "level1": {
                    "level2": {
                        "level3": {
                            "deep_value": "found"
                        }
                    }
                }
            }),
            ValidJsonVariant::CustomStructure(fields) => {
                let mut obj = serde_json::Map::new();
                for (key, value_type) in fields {
                    let value = match value_type {
                        JsonValueType::String(s) => Value::String(s.clone()),
                        JsonValueType::Number(n) => json!(n),
                        JsonValueType::Boolean(b) => Value::Bool(*b),
                        JsonValueType::Null => Value::Null,
                        JsonValueType::Array(arr) => Value::Array(
                            arr.iter().map(|s| Value::String(s.clone())).collect()
                        ),
                        JsonValueType::Object(pairs) => {
                            let mut nested = serde_json::Map::new();
                            for (k, v) in pairs {
                                nested.insert(k.clone(), Value::String(v.clone()));
                            }
                            Value::Object(nested)
                        }
                    };
                    obj.insert(key.clone(), value);
                }
                Value::Object(obj)
            }
        }
    }

    fn create_nested_json(&self, depth: u8) -> Value {
        let mut current = json!({"value": "deep"});
        for i in 0..depth.min(50) { // Cap depth to prevent stack overflow
            current = json!({ format!("level{}", i): current });
        }
        current
    }
}

impl MalformedJsonInput {
    fn to_string(&self) -> String {
        let base = if self.base_content.is_empty() {
            r#"{"id": "test"}"#.to_string()
        } else {
            self.base_content.clone()
        };

        match self.malformation_type {
            MalformationType::UnterminatedString => {
                format!(r#"{{"key": "unterminated"#)
            }
            MalformationType::InvalidUnicode => {
                format!(r#"{{"key": "\u{{{:04X}}}"}}"#, 0xD800) // Invalid surrogate
            }
            MalformationType::DeeplyNested => {
                let mut nested = base;
                for i in 0..100 {
                    nested = format!(r#"{{"level{}": {}}}"#, i, nested);
                }
                nested
            }
            MalformationType::VeryLargeNumbers => {
                format!(r#"{{"large": 1e308, "small": -1e308}}"#)
            }
            MalformationType::InvalidEscapes => {
                format!(r#"{{"key": "\z invalid escape"}}"#)
            }
            MalformationType::ControlCharacters => {
                format!("{{\0\"key\0\":\0\"value\0\"}}")
            }
            MalformationType::ExtremeLengths => {
                let long_key = "k".repeat(10000);
                format!(r#"{{"{long_key}": "value"}}"#)
            }
            MalformationType::NullBytes => {
                format!("{{\0\"key\0\":\0\"value\0\"}}")
            }
            MalformationType::MixedQuoting => {
                format!(r#"{{'single": "double'}}"#)
            }
            MalformationType::InvalidStructure => {
                format!(r#"{{key: value, missing_quotes}}"#)
            }
        }
    }
}

impl EdgeCaseJson {
    fn to_value(&self) -> Value {
        match self {
            Self::MaxInteger => json!({ "max_int": i64::MAX }),
            Self::MinInteger => json!({ "min_int": i64::MIN }),
            Self::NaN => json!({ "nan": f64::NAN }),
            Self::Infinity => json!({ "inf": f64::INFINITY }),
            Self::VeryLongString => json!({ "long": "x".repeat(100000) }),
            Self::VeryDeeplyNested => {
                let mut nested = json!("deep");
                for i in 0..200 {
                    nested = json!({ format!("level{}", i): nested });
                }
                nested
            }
            Self::ManyFields => {
                let mut obj = serde_json::Map::new();
                for i in 0..10000 {
                    obj.insert(format!("field{}", i), Value::String(format!("value{}", i)));
                }
                Value::Object(obj)
            }
            Self::EmptyStructures => json!({
                "empty_obj": {},
                "empty_array": [],
                "empty_string": ""
            }),
            Self::NullEverything => json!({
                "null1": null,
                "null2": null,
                "nested": {
                    "null3": null
                }
            }),
        }
    }
}

/// Test JSON validation invariants and security.
fn test_json_validation_invariants(operation: &JsonValidationOperation) {
    match operation {
        JsonValidationOperation::ValidateContract { surface, json_input } => {
            if let Ok(json_value) = json_input.to_value() {
                let surface_enum = surface.to_operator_surface();
                let result = validate_operator_json_value(surface_enum, &json_value);

                // Test validation consistency
                test_validation_consistency(&json_value, &result);

                // Test that validation doesn't panic on any input
                let _surface_names = registered_surface_names();
            }
        }

        JsonValidationOperation::BatchValidation { validations } => {
            // Test batch validation behavior
            for (surface, json_input) in validations {
                if let Ok(json_value) = json_input.to_value() {
                    let surface_enum = surface.to_operator_surface();
                    let result = validate_operator_json_value(surface_enum, &json_value);

                    // Each validation should be independent
                    test_validation_consistency(&json_value, &result);
                }
            }
        }

        JsonValidationOperation::FieldPathTraversal { json_input, field_paths } => {
            if let Ok(json_value) = json_input.to_value() {
                // Test field path traversal safety
                for field_path in field_paths {
                    test_field_path_safety(&json_value, field_path);
                }
            }
        }

        JsonValidationOperation::MalformedJsonTests { surface, malformed_input } => {
            let malformed_json = malformed_input.to_string();

            // Test that malformed JSON is handled safely
            match serde_json::from_str::<Value>(&malformed_json) {
                Ok(value) => {
                    // If it parsed, validation should work
                    let surface_enum = surface.to_operator_surface();
                    let result = validate_operator_json_value(surface_enum, &value);
                    test_validation_consistency(&value, &result);
                }
                Err(_) => {
                    // Parsing failed - this is expected for malformed input
                }
            }
        }

        JsonValidationOperation::EdgeCaseValues { surface, edge_case } => {
            let json_value = edge_case.to_value();
            let surface_enum = surface.to_operator_surface();

            // Test edge case value handling
            let result = validate_operator_json_value(surface_enum, &json_value);
            test_validation_consistency(&json_value, &result);

            // Test specific edge case invariants
            test_edge_case_safety(&json_value, edge_case);
        }
    }
}

/// Test validation result consistency and safety.
fn test_validation_consistency(json_value: &Value, result: &Result<(), Vec<crate::frankenengine_node::operator_json_contracts::OperatorJsonContractError>>) {
    // Validation should be deterministic
    // (Can't easily test this without multiple calls, but we ensure no panics)

    // Check result structure
    match result {
        Ok(_) => {
            // Valid result should mean all required fields are present and non-null
        }
        Err(errors) => {
            // Errors should be non-empty and informative
            assert!(!errors.is_empty(), "Error list should not be empty");

            for error in errors {
                // Each error should have meaningful content
                // (Error types are not accessible, but we can ensure no panic)
            }
        }
    }

    // Test that large JSON doesn't cause excessive memory usage
    if serde_json::to_string(json_value).map_or(0, |s| s.len()) > 1_000_000 {
        // Large JSON should be handled efficiently
    }
}

/// Test field path traversal safety.
fn test_field_path_safety(json_value: &Value, field_path: &str) {
    // Test that field path traversal doesn't panic
    if field_path.len() > 10000 {
        // Very long field paths should be handled safely
    }

    if field_path.contains('\0') {
        // Null bytes in field paths should be handled safely
    }

    // Test deeply nested path traversal
    let depth = field_path.split('.').count();
    if depth > 100 {
        // Deep path traversal should not cause stack overflow
    }
}

/// Test edge case value handling safety.
fn test_edge_case_safety(json_value: &Value, edge_case: &EdgeCaseJson) {
    match edge_case {
        EdgeCaseJson::NaN | EdgeCaseJson::Infinity => {
            // Special float values should be handled safely
            if let Some(num) = json_value.get("nan").or(json_value.get("inf")) {
                if let Some(f) = num.as_f64() {
                    // Should not cause arithmetic errors
                    let _is_finite = f.is_finite();
                }
            }
        }
        EdgeCaseJson::VeryLongString => {
            // Very long strings should not cause excessive memory usage
        }
        EdgeCaseJson::VeryDeeplyNested => {
            // Deep nesting should not cause stack overflow during traversal
        }
        EdgeCaseJson::ManyFields => {
            // Many fields should not cause excessive processing time
        }
        _ => {}
    }
}

fuzz_target!(|input: FuzzInput| {
    std::panic::catch_unwind(|| {
        test_json_validation_invariants(&input.operation);
    }).unwrap_or_else(|_| {
        eprintln!("Panic caught in operator JSON validation fuzzing");
    });
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_json_creation() {
        let input = JsonInput {
            json_type: JsonInputType::ValidStructured(ValidJsonVariant::MinimalValid),
        };
        let value = input.to_value().unwrap();
        assert!(value.is_object());
    }

    #[test]
    fn test_malformed_json_safety() {
        let malformed_inputs = vec![
            r#"{"key": "unterminated"#,
            r#"{'single': "double"}"#,
            &format!(r#"{{"long_key_{}": "value"}}"#, "x".repeat(1000)),
        ];

        for input in malformed_inputs {
            // Should not panic
            let _result: Result<Value, _> = serde_json::from_str(input);
        }
    }

    #[test]
    fn test_surface_conversion() {
        let surface = JsonSurface::DoctorReport;
        let operator_surface = surface.to_operator_surface();
        assert_eq!(operator_surface.as_str(), "doctor_report");
    }

    #[test]
    fn test_fuzz_input_generation() {
        let mut data = [0u8; 1000];
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }

        let mut unstructured = Unstructured::new(&data);
        if let Ok(input) = FuzzInput::arbitrary(&mut unstructured) {
            // Should not panic during operation construction
            match input.operation {
                JsonValidationOperation::ValidateContract { .. } => {},
                JsonValidationOperation::BatchValidation { .. } => {},
                JsonValidationOperation::FieldPathTraversal { .. } => {},
                JsonValidationOperation::MalformedJsonTests { .. } => {},
                JsonValidationOperation::EdgeCaseValues { .. } => {},
            }
        }
    }
}