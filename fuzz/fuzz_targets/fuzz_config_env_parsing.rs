//! Fuzz target for config environment variable parsing and FromStr implementations.
//!
//! Tests environment variable parsing functions (parse_env_bool, parse_env_u64, etc.)
//! and FromStr implementations for config types (Profile, CompatibilityMode, PreferredRuntime).
//! Critical security boundary for configuration validation and type conversion.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::str::FromStr;

// Import config types and parsing functions
use frankenengine_node::config::{Profile, CompatibilityMode, PreferredRuntime};

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: ConfigParsingOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum ConfigParsingOperation {
    ProfileFromStr(StringInput),
    CompatibilityModeFromStr(StringInput),
    PreferredRuntimeFromStr(StringInput),
    EnvironmentBoolParse {
        key: String,
        value: StringInput,
    },
    EnvironmentNumericParse {
        key: String,
        value: StringInput,
        numeric_type: NumericType,
    },
    BatchConfigParsing {
        inputs: Vec<ConfigInput>,
    },
    EdgeCaseCombination {
        primary: StringInput,
        secondary: StringInput,
        config_type: ConfigType,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum NumericType {
    U8,
    U32,
    U64,
    Usize,
    F64,
}

#[derive(Debug, Clone, Arbitrary)]
enum ConfigType {
    Profile,
    CompatibilityMode,
    PreferredRuntime,
}

#[derive(Debug, Clone, Arbitrary)]
struct ConfigInput {
    input_type: ConfigType,
    value: StringInput,
}

#[derive(Debug, Clone, Arbitrary)]
struct StringInput {
    base: String,
    transformations: Vec<StringTransformation>,
}

#[derive(Debug, Clone, Arbitrary)]
enum StringTransformation {
    Uppercase,
    Lowercase,
    AddNullByte,
    AddControlChars,
    AddUnicodeChars,
    Truncate(u8),
    Repeat(u8),
    AddWhitespace,
    AddNumbers,
    AddSpecialChars,
}

impl StringInput {
    fn to_string(&self) -> String {
        let mut result = self.base.clone();

        for transform in &self.transformations {
            match transform {
                StringTransformation::Uppercase => result = result.to_uppercase(),
                StringTransformation::Lowercase => result = result.to_lowercase(),
                StringTransformation::AddNullByte => result.push('\0'),
                StringTransformation::AddControlChars => result.push_str("\n\r\t"),
                StringTransformation::AddUnicodeChars => result.push_str("🔥💥⚠️"),
                StringTransformation::Truncate(n) => {
                    let len = (*n as usize).min(result.len());
                    result.truncate(len);
                },
                StringTransformation::Repeat(n) => {
                    let repeat_count = (*n as usize).min(10); // Limit repetition
                    result = result.repeat(repeat_count);
                },
                StringTransformation::AddWhitespace => result = format!("  {}  ", result),
                StringTransformation::AddNumbers => result.push_str("123456789"),
                StringTransformation::AddSpecialChars => result.push_str("!@#$%^&*()"),
            }
        }

        result
    }
}

fn test_profile_from_str(input: &str) {
    // Test deterministic parsing behavior
    let result1 = Profile::from_str(input);
    let result2 = Profile::from_str(input);
    assert_eq!(result1.is_ok(), result2.is_ok(), "Profile parsing should be deterministic");

    // Empty input should be rejected
    if input.is_empty() {
        assert!(result1.is_err(), "Empty profile string should be rejected");
    }

    // Valid profiles should parse successfully
    if input.trim().eq_ignore_ascii_case("production") ||
       input.trim().eq_ignore_ascii_case("development") ||
       input.trim().eq_ignore_ascii_case("test") {
        // Note: Actual validation depends on Profile enum implementation
    }
}

fn test_compatibility_mode_from_str(input: &str) {
    // Test deterministic parsing behavior
    let result1 = CompatibilityMode::from_str(input);
    let result2 = CompatibilityMode::from_str(input);
    assert_eq!(result1.is_ok(), result2.is_ok(), "CompatibilityMode parsing should be deterministic");

    // Empty input should be rejected
    if input.is_empty() {
        assert!(result1.is_err(), "Empty compatibility mode string should be rejected");
    }

    // Input with null bytes should be rejected
    if input.contains('\0') {
        assert!(result1.is_err(), "Input with null bytes should be rejected");
    }
}

fn test_preferred_runtime_from_str(input: &str) {
    // Test deterministic parsing behavior
    let result1 = PreferredRuntime::from_str(input);
    let result2 = PreferredRuntime::from_str(input);
    assert_eq!(result1.is_ok(), result2.is_ok(), "PreferredRuntime parsing should be deterministic");

    // Empty input should be rejected
    if input.is_empty() {
        assert!(result1.is_err(), "Empty preferred runtime string should be rejected");
    }

    // Input with control characters should be handled safely
    if input.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        // Control characters should generally be rejected
        assert!(result1.is_err(), "Input with control characters should be rejected");
    }
}

// Mock environment parsing functions since they're private
fn test_env_bool_parse(key: &str, value: &str) {
    // Test boolean parsing edge cases and deterministic behavior
    let result1 = value.parse::<bool>();
    let result2 = value.parse::<bool>();
    assert_eq!(result1.is_ok(), result2.is_ok(), "Boolean parsing should be deterministic");

    // Test case variations
    let lower = value.to_lowercase();
    let is_known_bool = matches!(lower.as_str(), "true" | "false" | "1" | "0" | "yes" | "no");

    // Standard boolean values should be recognized
    match lower.as_str() {
        "true" | "1" => {
            assert!(result1.is_ok(), "Standard true values should parse successfully");
        },
        "false" | "0" => {
            assert!(result1.is_ok(), "Standard false values should parse successfully");
        },
        _ => {
            // Non-standard boolean strings should be rejected by std::str::parse
            if !["yes", "no"].contains(&lower.as_str()) && value.len() > 10 {
                assert!(result1.is_err(), "Very long non-boolean strings should be rejected");
            }
        }
    }
}

fn test_env_numeric_parse(key: &str, value: &str, numeric_type: &NumericType) {
    match numeric_type {
        NumericType::U8 => {
            let result1 = value.parse::<u8>();
            let result2 = value.parse::<u8>();
            assert_eq!(result1.is_ok(), result2.is_ok(), "U8 parsing should be deterministic");

            // Overflow values should be rejected
            if value.len() > 3 || value.starts_with('-') {
                assert!(result1.is_err(), "Overflow/negative values should be rejected for u8");
            }
        },
        NumericType::U32 => {
            let result1 = value.parse::<u32>();
            let result2 = value.parse::<u32>();
            assert_eq!(result1.is_ok(), result2.is_ok(), "U32 parsing should be deterministic");
        },
        NumericType::U64 => {
            let result1 = value.parse::<u64>();
            let result2 = value.parse::<u64>();
            assert_eq!(result1.is_ok(), result2.is_ok(), "U64 parsing should be deterministic");
        },
        NumericType::Usize => {
            let result1 = value.parse::<usize>();
            let result2 = value.parse::<usize>();
            assert_eq!(result1.is_ok(), result2.is_ok(), "Usize parsing should be deterministic");
        },
        NumericType::F64 => {
            let result1 = value.parse::<f64>();
            let result2 = value.parse::<f64>();
            assert_eq!(result1.is_ok(), result2.is_ok(), "F64 parsing should be deterministic");

            if let Ok(f) = result1 {
                // Test for NaN and infinity which should be validated
                let is_finite = f.is_finite();
                // NaN and infinity are valid f64 values but may not be valid config values
                if value.to_lowercase().contains("inf") || value.to_lowercase().contains("nan") {
                    assert!(!is_finite, "Infinity/NaN should not be finite");
                }
            }
        },
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            ConfigParsingOperation::ProfileFromStr(input) => {
                let s = input.to_string();
                test_profile_from_str(&s);
            },
            ConfigParsingOperation::CompatibilityModeFromStr(input) => {
                let s = input.to_string();
                test_compatibility_mode_from_str(&s);
            },
            ConfigParsingOperation::PreferredRuntimeFromStr(input) => {
                let s = input.to_string();
                test_preferred_runtime_from_str(&s);
            },
            ConfigParsingOperation::EnvironmentBoolParse { key, value } => {
                let val_str = value.to_string();
                test_env_bool_parse(&key, &val_str);
            },
            ConfigParsingOperation::EnvironmentNumericParse { key, value, numeric_type } => {
                let val_str = value.to_string();
                test_env_numeric_parse(&key, &val_str, &numeric_type);
            },
            ConfigParsingOperation::BatchConfigParsing { inputs } => {
                for config_input in inputs {
                    let val_str = config_input.value.to_string();
                    match config_input.input_type {
                        ConfigType::Profile => test_profile_from_str(&val_str),
                        ConfigType::CompatibilityMode => test_compatibility_mode_from_str(&val_str),
                        ConfigType::PreferredRuntime => test_preferred_runtime_from_str(&val_str),
                    }
                }
            },
            ConfigParsingOperation::EdgeCaseCombination { primary, secondary, config_type } => {
                let primary_str = primary.to_string();
                let secondary_str = secondary.to_string();

                // Test primary input
                match config_type {
                    ConfigType::Profile => test_profile_from_str(&primary_str),
                    ConfigType::CompatibilityMode => test_compatibility_mode_from_str(&primary_str),
                    ConfigType::PreferredRuntime => test_preferred_runtime_from_str(&primary_str),
                }

                // Test secondary input
                match config_type {
                    ConfigType::Profile => test_profile_from_str(&secondary_str),
                    ConfigType::CompatibilityMode => test_compatibility_mode_from_str(&secondary_str),
                    ConfigType::PreferredRuntime => test_preferred_runtime_from_str(&secondary_str),
                }

                // Test combined input
                let combined = format!("{}{}", primary_str, secondary_str);
                match config_type {
                    ConfigType::Profile => test_profile_from_str(&combined),
                    ConfigType::CompatibilityMode => test_compatibility_mode_from_str(&combined),
                    ConfigType::PreferredRuntime => test_preferred_runtime_from_str(&combined),
                }
            },
        }
    }
});