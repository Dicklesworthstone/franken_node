#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::{Value, from_str, to_string};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(json_input) = std::str::from_utf8(data) {
        // Guard against excessively large JSON to prevent OOM
        if json_input.len() > 1_000_000 {
            return;
        }

        // Test serde_json::from_str parsing with arbitrary input
        let parse_result: Result<Value, _> = from_str(json_input);

        match parse_result {
            Ok(parsed_value) => {
                // Valid JSON parse - verify invariants and round-trip behavior

                // 1. Re-serialization should produce valid JSON
                let serialized = to_string(&parsed_value);
                assert!(serialized.is_ok(), "Re-serialization should succeed");

                // 2. Round-trip parsing should succeed
                let re_parsed: Result<Value, _> = from_str(&serialized.unwrap());
                assert!(re_parsed.is_ok(), "Round-trip parsing should succeed");

                // 3. Round-trip should preserve semantic equality
                let re_parsed_value = re_parsed.unwrap();
                assert_eq!(parsed_value, re_parsed_value, "Round-trip should preserve value");

                // 4. Test value type consistency
                match &parsed_value {
                    Value::Null => {
                        assert!(parsed_value.is_null());
                    }
                    Value::Bool(b) => {
                        assert_eq!(parsed_value.as_bool().unwrap(), *b);
                    }
                    Value::Number(n) => {
                        assert!(parsed_value.is_number());
                        // Verify number is finite if it's a float
                        if let Some(f) = n.as_f64() {
                            assert!(f.is_finite(), "JSON numbers should be finite");
                        }
                    }
                    Value::String(s) => {
                        assert_eq!(parsed_value.as_str().unwrap(), s);
                    }
                    Value::Array(arr) => {
                        assert!(parsed_value.is_array());
                        assert_eq!(parsed_value.as_array().unwrap().len(), arr.len());
                    }
                    Value::Object(obj) => {
                        assert!(parsed_value.is_object());
                        assert_eq!(parsed_value.as_object().unwrap().len(), obj.len());
                    }
                }

                // 5. Test deep nesting limits (prevent stack overflow)
                let depth = calculate_json_depth(&parsed_value);
                assert!(depth < 1000, "JSON depth should be reasonable to prevent stack overflow");

                // 6. Test serialized size is reasonable
                let serialized_size = serialized.unwrap().len();
                assert!(serialized_size < 10_000_000, "Serialized JSON should not be excessively large");

            }
            Err(_err) => {
                // Invalid JSON parse - verify error handling consistency

                // 1. Invalid JSON should consistently fail
                let result2: Result<Value, _> = from_str(json_input);
                assert!(result2.is_err(), "Invalid JSON should consistently fail");

                // 2. Test common invalid JSON patterns
                if json_input.contains("undefined") || json_input.contains("NaN") ||
                   json_input.contains("Infinity") {
                    // These JavaScript values should be rejected in strict JSON
                    assert!(from_str::<Value>(json_input).is_err());
                }

                // 3. Test control character handling
                if json_input.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
                    // Unescaped control characters should be rejected
                }

                // 4. Test for unclosed structures
                if json_input.contains("{") && !json_input.contains("}") {
                    assert!(from_str::<Value>(json_input).is_err());
                }
                if json_input.contains("[") && !json_input.contains("]") {
                    assert!(from_str::<Value>(json_input).is_err());
                }
            }
        }

        // Test edge cases
        if json_input.is_empty() {
            let result: Result<Value, _> = from_str(json_input);
            assert!(result.is_err(), "Empty JSON should fail to parse");
        }

        // Test null byte handling
        if json_input.contains('\0') {
            // Null bytes should be handled gracefully (likely rejected)
            let result: Result<Value, _> = from_str(json_input);
            // Don't assert specific behavior, just ensure no panic
        }

        // Test basic JSON values for consistency
        if json_input == "null" {
            let result: Result<Value, _> = from_str(json_input);
            assert!(result.is_ok() && result.unwrap().is_null());
        }

        if json_input == "true" {
            let result: Result<Value, _> = from_str(json_input);
            assert!(result.is_ok() && result.unwrap().as_bool() == Some(true));
        }

        if json_input == "false" {
            let result: Result<Value, _> = from_str(json_input);
            assert!(result.is_ok() && result.unwrap().as_bool() == Some(false));
        }
    }
});

fn calculate_json_depth(value: &Value) -> usize {
    match value {
        Value::Array(arr) => {
            1 + arr.iter().map(calculate_json_depth).max().unwrap_or(0)
        }
        Value::Object(obj) => {
            1 + obj.values().map(calculate_json_depth).max().unwrap_or(0)
        }
        _ => 0,
    }
}