#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(toml_input) = std::str::from_utf8(data) {
        // Guard against excessively large TOML to prevent OOM
        if toml_input.len() > 500_000 {
            return;
        }

        // Test toml::from_str parsing with arbitrary input
        let parse_result: Result<TomlValue, _> = toml::from_str(toml_input);

        match parse_result {
            Ok(parsed_value) => {
                // Valid TOML parse - verify invariants and round-trip behavior

                // 1. Re-serialization should produce valid TOML
                let serialized = toml::to_string(&parsed_value);
                assert!(serialized.is_ok(), "Re-serialization should succeed");

                // 2. Round-trip parsing should succeed
                let re_parsed: Result<TomlValue, _> = toml::from_str(&serialized.unwrap());
                assert!(re_parsed.is_ok(), "Round-trip parsing should succeed");

                // 3. Round-trip should preserve semantic equality
                let re_parsed_value = re_parsed.unwrap();
                assert_eq!(parsed_value, re_parsed_value, "Round-trip should preserve value");

                // 4. Test value type consistency
                match &parsed_value {
                    TomlValue::String(s) => {
                        assert!(s.len() < 1_000_000, "String values should be reasonable size");
                    }
                    TomlValue::Integer(i) => {
                        // Integer should be within reasonable bounds
                        assert!(*i >= i64::MIN && *i <= i64::MAX);
                    }
                    TomlValue::Float(f) => {
                        // Float should be finite
                        assert!(f.is_finite(), "TOML floats should be finite");
                        assert!(!f.is_nan(), "TOML floats should not be NaN");
                    }
                    TomlValue::Boolean(_) => {
                        // Boolean is always valid
                    }
                    TomlValue::Datetime(dt) => {
                        // Datetime should have valid string representation
                        let dt_str = dt.to_string();
                        assert!(!dt_str.is_empty(), "Datetime should have valid string representation");
                    }
                    TomlValue::Array(arr) => {
                        // Array should have reasonable size
                        assert!(arr.len() < 100_000, "Arrays should have reasonable size");

                        // Check nesting depth to prevent stack overflow
                        let depth = calculate_toml_depth(&parsed_value);
                        assert!(depth < 1000, "TOML depth should be reasonable");
                    }
                    TomlValue::Table(table) => {
                        // Table should have reasonable size
                        assert!(table.len() < 100_000, "Tables should have reasonable size");

                        // Check for valid key names
                        for key in table.keys() {
                            assert!(!key.is_empty(), "Table keys should not be empty");
                            assert!(key.len() < 10_000, "Table keys should be reasonable size");
                        }

                        // Check nesting depth
                        let depth = calculate_toml_depth(&parsed_value);
                        assert!(depth < 1000, "TOML depth should be reasonable");
                    }
                }

                // 5. Test serialized size is reasonable
                let serialized_size = serialized.unwrap().len();
                assert!(serialized_size < 10_000_000, "Serialized TOML should not be excessively large");

                // 6. Test conversion to JSON (common operation)
                if let Ok(json_str) = serde_json::to_string(&parsed_value) {
                    let json_parse: Result<JsonValue, _> = serde_json::from_str(&json_str);
                    // Conversion should be consistent
                    assert!(json_parse.is_ok(), "TOML->JSON conversion should be valid");
                }

            }
            Err(_err) => {
                // Invalid TOML parse - verify error handling consistency

                // 1. Invalid TOML should consistently fail
                let result2: Result<TomlValue, _> = toml::from_str(toml_input);
                assert!(result2.is_err(), "Invalid TOML should consistently fail");

                // 2. Test common invalid TOML patterns
                if toml_input.contains("[[[[") {
                    // Excessive array nesting should be rejected
                    assert!(toml::from_str::<TomlValue>(toml_input).is_err());
                }

                // 3. Test malformed section headers
                if toml_input.contains("[") && !toml_input.contains("]") {
                    assert!(toml::from_str::<TomlValue>(toml_input).is_err());
                }

                // 4. Test incomplete key-value pairs
                if toml_input.contains("key =") && toml_input.trim().ends_with("=") {
                    assert!(toml::from_str::<TomlValue>(toml_input).is_err());
                }
            }
        }

        // Test edge cases
        if toml_input.is_empty() {
            let result: Result<TomlValue, _> = toml::from_str(toml_input);
            // Empty TOML should parse to empty table
            if result.is_ok() {
                match result.unwrap() {
                    TomlValue::Table(t) => assert!(t.is_empty()),
                    _ => {}
                }
            }
        }

        // Test null byte handling
        if toml_input.contains('\0') {
            // Null bytes should be handled gracefully (likely rejected)
            let result: Result<TomlValue, _> = toml::from_str(toml_input);
            // Don't assert specific behavior, just ensure no panic
        }

        // Test basic TOML values for consistency
        if toml_input.trim() == "key = \"value\"" {
            let result: Result<TomlValue, _> = toml::from_str(toml_input);
            assert!(result.is_ok());
            if let Ok(TomlValue::Table(table)) = result {
                assert!(table.contains_key("key"));
            }
        }

        // Test numeric values
        if toml_input.trim() == "num = 42" {
            let result: Result<TomlValue, _> = toml::from_str(toml_input);
            assert!(result.is_ok());
        }

        // Test boolean values
        if toml_input.trim() == "flag = true" {
            let result: Result<TomlValue, _> = toml::from_str(toml_input);
            assert!(result.is_ok());
        }
    }
});

fn calculate_toml_depth(value: &TomlValue) -> usize {
    match value {
        TomlValue::Array(arr) => {
            1 + arr.iter().map(calculate_toml_depth).max().unwrap_or(0)
        }
        TomlValue::Table(table) => {
            1 + table.values().map(calculate_toml_depth).max().unwrap_or(0)
        }
        _ => 0,
    }
}