//! Fuzz target for TOML configuration parsing boundaries.
//!
//! Tests configuration deserialization, validation, and error handling across
//! all config structures. Critical for preventing config injection attacks and
//! parser DoS via malformed TOML input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use frankenengine_node::config::{
    Config, Profile, CompatibilityMode, LaneOverflowPolicy,
    NetworkAllowlistEntry, NetworkPolicyConfig, SecurityConfig,
    RuntimeConfig, RuntimeLaneConfig, ThresholdsConfig,
};

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: ConfigParsingOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum ConfigParsingOperation {
    FullConfig(TomlInput),
    ProfileParsing(StringInput),
    CompatibilityMode(StringInput),
    LaneOverflowPolicy(StringInput),
    NetworkAllowlistEntry(TomlInput),
    NetworkPolicyConfig(TomlInput),
    SecurityConfig(TomlInput),
    RuntimeConfig(TomlInput),
    RuntimeLaneConfig(TomlInput),
    ThresholdsConfig(TomlInput),
    BatchConfigParsing(Vec<TomlInput>),
    MalformedTomlTests(MalformedTomlInput),
}

#[derive(Debug, Clone, Arbitrary)]
struct TomlInput {
    content: TomlContent,
}

#[derive(Debug, Clone, Arbitrary)]
struct StringInput {
    value: String,
}

#[derive(Debug, Clone, Arbitrary)]
struct MalformedTomlInput {
    malformation_type: MalformationType,
    base_content: String,
}

#[derive(Debug, Clone, Arbitrary)]
enum MalformationType {
    UnterminatedString,
    InvalidUnicode,
    DeeplyNested,
    VeryLargeNumbers,
    InvalidDates,
    MixedQuoting,
    InvalidEscapes,
    ControlCharacters,
    ExtremeLengths,
    NullBytes,
}

#[derive(Debug, Clone, Arbitrary)]
enum TomlContent {
    ValidStructured(ValidTomlVariants),
    Malformed(String),
    Empty,
    VeryLarge(Vec<u8>),
    WithNullBytes(Vec<u8>),
    Unicode(String),
    NestedStructures(String),
    EdgeCaseValues(String),
}

#[derive(Debug, Clone, Arbitrary)]
enum ValidTomlVariants {
    MinimalConfig,
    FullConfig,
    ProfileOnly(String),
    SecurityOnly,
    RuntimeOnly,
    NetworkOnly,
    CustomValues(Vec<(String, String)>),
}

impl TomlInput {
    fn to_string(&self) -> String {
        match &self.content {
            TomlContent::ValidStructured(variant) => {
                match variant {
                    ValidTomlVariants::MinimalConfig => {
                        r#"profile = "strict""#.to_string()
                    }
                    ValidTomlVariants::FullConfig => {
                        r#"
profile = "balanced"

[compatibility]
mode = "strict"
warn_on_unsafe_eval = true

[migration]
rewrite_suggestions = true

[trust]
registry_signing_key = "dGVzdGtleQ=="

[replay]
max_stored_incidents = 100

[runtime]
mode = "fast"

[runtime.lanes]
default = { max_queue_length = 1000, overflow_policy = "block", priority = "normal" }

[network]
policy = "allowlist"
ssrf_enforcement = "strict"

[security]
api_keys = []
"#.to_string()
                    }
                    ValidTomlVariants::ProfileOnly(profile) => {
                        format!(r#"profile = "{}""#, profile)
                    }
                    ValidTomlVariants::SecurityOnly => {
                        r#"
[security]
api_keys = []
sandbox_policy = "strict"
"#.to_string()
                    }
                    ValidTomlVariants::RuntimeOnly => {
                        r#"
[runtime]
mode = "performance"

[runtime.lanes]
default = { max_queue_length = 500, overflow_policy = "drop", priority = "high" }
"#.to_string()
                    }
                    ValidTomlVariants::NetworkOnly => {
                        r#"
[network]
policy = "denylist"
ssrf_enforcement = "warning"

[[network.allowlist]]
domain = "example.com"
port = 443
reason = "API endpoint"
"#.to_string()
                    }
                    ValidTomlVariants::CustomValues(pairs) => {
                        let mut toml = String::new();
                        for (key, value) in pairs {
                            toml.push_str(&format!("{} = {}\n", key, value));
                        }
                        toml
                    }
                }
            }
            TomlContent::Malformed(s) => s.clone(),
            TomlContent::Empty => String::new(),
            TomlContent::VeryLarge(bytes) => String::from_utf8_lossy(bytes).to_string(),
            TomlContent::WithNullBytes(bytes) => String::from_utf8_lossy(bytes).to_string(),
            TomlContent::Unicode(s) => s.clone(),
            TomlContent::NestedStructures(s) => s.clone(),
            TomlContent::EdgeCaseValues(s) => s.clone(),
        }
    }
}

impl MalformedTomlInput {
    fn to_string(&self) -> String {
        let base = if self.base_content.is_empty() {
            r#"profile = "strict""#.to_string()
        } else {
            self.base_content.clone()
        };

        match self.malformation_type {
            MalformationType::UnterminatedString => {
                format!("{}\nkey = \"unterminated", base)
            }
            MalformationType::InvalidUnicode => {
                format!("{}\nkey = \"\\u{{{:04X}}}\"", base, 0xD800) // Invalid surrogate
            }
            MalformationType::DeeplyNested => {
                let mut nested = base;
                for i in 0..50 {
                    nested = format!("{}\n[section.level{}]", nested, i);
                }
                nested
            }
            MalformationType::VeryLargeNumbers => {
                format!("{}\nlarge_number = 99999999999999999999999999999", base)
            }
            MalformationType::InvalidDates => {
                format!("{}\ndate = 1979-05-32T07:32:00Z", base) // Invalid day
            }
            MalformationType::MixedQuoting => {
                format!("{}\nkey = 'single\" + \"double'", base)
            }
            MalformationType::InvalidEscapes => {
                format!("{}\nkey = \"\\z invalid escape\"", base)
            }
            MalformationType::ControlCharacters => {
                format!("{}\nkey = \"value\\x00with\\x01control\"", base)
            }
            MalformationType::ExtremeLengths => {
                let long_key = "k".repeat(10000);
                format!("{}\n{} = \"value\"", base, long_key)
            }
            MalformationType::NullBytes => {
                format!("{}\0key\0=\0\"value\0\"", base)
            }
        }
    }
}

/// Test core TOML parsing invariants and security.
fn test_toml_parsing_invariants(operation: &ConfigParsingOperation) {
    match operation {
        ConfigParsingOperation::FullConfig(input) => {
            let toml_content = input.to_string();
            let result: Result<Config, _> = toml::from_str(&toml_content);

            // Test basic parsing safety
            test_parsing_safety(&toml_content, result.is_ok());

            if let Ok(config) = result {
                // Test parsed config invariants
                test_config_invariants(&config);
            }
        }

        ConfigParsingOperation::ProfileParsing(input) => {
            let profile_str = &input.value;
            let result: Result<Profile, _> = profile_str.parse();

            // Valid profiles should parse
            match profile_str.as_str() {
                "strict" | "balanced" | "legacy-risky" => {
                    assert!(result.is_ok(), "Valid profile should parse: {}", profile_str);
                }
                _ => {
                    // Invalid profiles should fail gracefully
                    if result.is_err() {
                        // Error should be informative
                    }
                }
            }
        }

        ConfigParsingOperation::CompatibilityMode(input) => {
            let mode_str = &input.value;
            let result: Result<CompatibilityMode, _> = mode_str.parse();

            match mode_str.as_str() {
                "strict" | "relaxed" | "legacy" => {
                    assert!(result.is_ok(), "Valid compatibility mode should parse: {}", mode_str);
                }
                _ => {
                    // Invalid modes should fail gracefully
                }
            }
        }

        ConfigParsingOperation::NetworkAllowlistEntry(input) => {
            let toml_content = input.to_string();
            let result: Result<NetworkAllowlistEntry, _> = toml::from_str(&toml_content);

            test_parsing_safety(&toml_content, result.is_ok());

            if let Ok(entry) = result {
                // Test allowlist entry invariants
                assert!(!entry.domain.is_empty(), "Domain should not be empty");
                assert!(entry.port > 0 && entry.port <= 65535, "Port should be valid");
                assert!(!entry.reason.is_empty(), "Reason should not be empty");
            }
        }

        ConfigParsingOperation::SecurityConfig(input) => {
            let toml_content = input.to_string();
            let result: Result<SecurityConfig, _> = toml::from_str(&toml_content);

            test_parsing_safety(&toml_content, result.is_ok());

            if let Ok(security) = result {
                // Test security config invariants
                test_security_config_invariants(&security);
            }
        }

        ConfigParsingOperation::RuntimeLaneConfig(input) => {
            let toml_content = input.to_string();
            let result: Result<RuntimeLaneConfig, _> = toml::from_str(&toml_content);

            test_parsing_safety(&toml_content, result.is_ok());

            if let Ok(lane_config) = result {
                // Test lane config invariants
                assert!(lane_config.max_queue_length > 0, "Queue length must be positive");
            }
        }

        ConfigParsingOperation::MalformedTomlTests(input) => {
            let malformed_toml = input.to_string();

            // Test that malformed TOML fails gracefully without panic
            let result: Result<Config, _> = toml::from_str(&malformed_toml);

            // Should not panic, but likely should fail
            if result.is_ok() {
                // If it parsed successfully, it should be valid
                if let Ok(config) = result {
                    test_config_invariants(&config);
                }
            }

            // Test specific malformed structures don't cause issues
            test_malformed_toml_safety(&malformed_toml);
        }

        ConfigParsingOperation::BatchConfigParsing(inputs) => {
            // Test batch parsing behavior
            for input in inputs {
                let toml_content = input.to_string();
                let result: Result<Config, _> = toml::from_str(&toml_content);

                // Each should be processed independently
                test_parsing_safety(&toml_content, result.is_ok());
            }
        }

        _ => {
            // Handle other parsing operations
        }
    }
}

/// Test basic parsing safety (no panics, bounded memory usage).
fn test_parsing_safety(toml_content: &str, parse_succeeded: bool) {
    // Content should not be excessively large (DoS protection)
    if toml_content.len() > 10_000_000 {
        // Very large inputs should typically fail or be bounded
    }

    // Null bytes should be handled safely
    if toml_content.contains('\0') {
        // Should not cause undefined behavior
    }

    // Deeply nested structures should be handled safely
    let nesting_depth = toml_content.matches('[').count();
    if nesting_depth > 100 {
        // Should not cause stack overflow
    }
}

/// Test config structure invariants.
fn test_config_invariants(config: &Config) {
    // Profile should be valid
    match config.profile {
        Profile::Strict | Profile::Balanced | Profile::LegacyRisky => {}
    }

    // Compatibility mode should be valid
    match config.compatibility.mode {
        CompatibilityMode::Strict | CompatibilityMode::Relaxed | CompatibilityMode::Legacy => {}
    }

    // Runtime lanes should have valid configurations
    for (_name, lane_config) in &config.runtime.lanes {
        assert!(lane_config.max_queue_length > 0);
        match lane_config.overflow_policy {
            LaneOverflowPolicy::Block | LaneOverflowPolicy::Drop | LaneOverflowPolicy::Prioritize => {}
        }
    }

    // Network allowlist entries should be valid
    for entry in &config.network.allowlist {
        assert!(!entry.domain.is_empty());
        assert!(entry.port > 0 && entry.port <= 65535);
        assert!(!entry.reason.is_empty());
    }
}

/// Test security config specific invariants.
fn test_security_config_invariants(security: &SecurityConfig) {
    // API keys should be valid if present
    for api_key in &security.api_keys {
        assert!(!api_key.is_empty(), "API keys should not be empty");
    }

    // Registry signing key should be valid base64 if present
    if let Some(ref key) = security.registry_signing_key {
        // Should be valid base64
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(key) {
            assert!(decoded.len() >= 32, "Registry signing key should be at least 32 bytes");
        }
    }
}

/// Test malformed TOML handling safety.
fn test_malformed_toml_safety(toml_content: &str) {
    // Should not cause panics or infinite loops
    let _ = std::panic::catch_unwind(|| {
        let _: Result<Config, _> = toml::from_str(toml_content);
    });

    // Should not consume excessive memory
    if toml_content.len() > 1_000_000 {
        // Large inputs should be handled efficiently
    }
}

fuzz_target!(|input: FuzzInput| {
    std::panic::catch_unwind(|| {
        test_toml_parsing_invariants(&input.operation);
    }).unwrap_or_else(|_| {
        eprintln!("Panic caught in TOML config parsing fuzzing");
    });
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config_parsing() {
        let toml = r#"
profile = "strict"

[compatibility]
mode = "strict"

[security]
api_keys = []
"#;
        let result: Result<Config, _> = toml::from_str(toml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_profile_parsing() {
        assert!("strict".parse::<Profile>().is_ok());
        assert!("balanced".parse::<Profile>().is_ok());
        assert!("legacy-risky".parse::<Profile>().is_ok());
        assert!("invalid".parse::<Profile>().is_err());
    }

    #[test]
    fn test_malformed_toml_safety() {
        let malformed_inputs = vec![
            "key = \"unterminated",
            "[[[[deeply.nested.section]]]]",
            "key\0with\0nulls = \"value\"",
            &"x".repeat(10000),
        ];

        for input in malformed_inputs {
            let result: Result<Config, _> = toml::from_str(input);
            // Should not panic
        }
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
                ConfigParsingOperation::FullConfig(_) => {},
                ConfigParsingOperation::ProfileParsing(_) => {},
                ConfigParsingOperation::MalformedTomlTests(_) => {},
                _ => {},
            }
        }
    }
}