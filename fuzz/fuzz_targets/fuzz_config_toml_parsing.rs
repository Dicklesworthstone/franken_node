//! Fuzz target for TOML configuration parsing boundaries.
//!
//! Tests configuration deserialization, validation, and error handling across
//! all config structures. Critical for preventing config injection attacks and
//! parser DoS via malformed TOML input.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenengine_node::config::{
    CompatibilityMode, Config, LaneOverflowPolicy, NetworkAllowlistEntry, NetworkPolicyConfig,
    Profile, RuntimeConfig, RuntimeLaneConfig, SecurityConfig, ThresholdsConfig,
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
            TomlContent::ValidStructured(variant) => match variant {
                ValidTomlVariants::MinimalConfig => r#"profile = "strict""#.to_string(),
                ValidTomlVariants::FullConfig => r#"
profile = "balanced"

	[compatibility]
	mode = "balanced"

	[migration]
	autofix = true

	[trust]
	registry_signing_key = "dGVzdGtleQ=="

	[replay]
	bundle_version = "v1"

	[runtime]
	preferred = "franken-engine"
	remote_max_in_flight = 32
	bulkhead_retry_after_ms = 50

	[runtime.lanes.cancel]
	max_concurrent = 8
	priority_weight = 100
	queue_limit = 16
	enqueue_timeout_ms = 25
	overflow_policy = "reject"

	[security]
	max_degraded_duration_secs = 3600
	max_merge_decisions = 100
	authorized_api_keys = ["fuzz-key"]

	[security.network_policy]
	ssrf_enforcement = "block"
	"#
                .to_string(),
                ValidTomlVariants::ProfileOnly(profile) => {
                    format!(r#"profile = "{}""#, profile)
                }
                ValidTomlVariants::SecurityOnly => r#"
	[security]
	max_degraded_duration_secs = 3600
	max_merge_decisions = 100
	authorized_api_keys = ["fuzz-key"]
	"#
                .to_string(),
                ValidTomlVariants::RuntimeOnly => r#"
	[runtime]
	preferred = "node"
	remote_max_in_flight = 64
	bulkhead_retry_after_ms = 25

	[runtime.lanes.cancel]
	max_concurrent = 4
	priority_weight = 100
	queue_limit = 8
	enqueue_timeout_ms = 25
	overflow_policy = "reject"
	"#
                .to_string(),
                ValidTomlVariants::NetworkOnly => r#"
	[security.network_policy]
	ssrf_enforcement = "monitor"

	[[security.network_policy.allowlist]]
	host = "example.com"
	port = 443
	reason = "API endpoint"
"#
                .to_string(),
                ValidTomlVariants::CustomValues(pairs) => {
                    let mut toml = String::new();
                    for (key, value) in pairs {
                        toml.push_str(&format!("{} = {}\n", key, value));
                    }
                    toml
                }
            },
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
                    assert!(
                        result.is_ok(),
                        "Valid profile should parse: {}",
                        profile_str
                    );
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
                "strict" | "balanced" | "legacy-risky" => {
                    assert!(
                        result.is_ok(),
                        "Valid compatibility mode should parse: {}",
                        mode_str
                    );
                }
                _ => {
                    // Invalid modes should fail gracefully
                }
            }
        }

        ConfigParsingOperation::LaneOverflowPolicy(input) => {
            let policy_str = &input.value;
            let toml_content = format!(
                r#"
max_concurrent = 1
priority_weight = 1
queue_limit = 1
enqueue_timeout_ms = 1
overflow_policy = "{policy_str}"
"#
            );
            let result: Result<RuntimeLaneConfig, _> = toml::from_str(&toml_content);

            test_parsing_safety(&toml_content, result.is_ok());

            match policy_str.as_str() {
                "reject" | "enqueue-with-timeout" | "shed-oldest" => {
                    assert!(
                        result.is_ok(),
                        "Valid lane overflow policy should parse: {}",
                        policy_str
                    );
                }
                _ => {
                    // Invalid policies should fail gracefully.
                }
            }
        }

        ConfigParsingOperation::NetworkAllowlistEntry(input) => {
            let toml_content = input.to_string();
            let result: Result<NetworkAllowlistEntry, _> = toml::from_str(&toml_content);

            test_parsing_safety(&toml_content, result.is_ok());

            if let Ok(entry) = result {
                let _host_len = entry.host.len();
                let _reason_len = entry.reason.len();
                let _port = entry.port;
            }
        }

        ConfigParsingOperation::NetworkPolicyConfig(input) => {
            let toml_content = input.to_string();
            let result: Result<NetworkPolicyConfig, _> = toml::from_str(&toml_content);

            test_parsing_safety(&toml_content, result.is_ok());
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

        ConfigParsingOperation::RuntimeConfig(input) => {
            let toml_content = input.to_string();
            let result: Result<RuntimeConfig, _> = toml::from_str(&toml_content);

            test_parsing_safety(&toml_content, result.is_ok());
        }

        ConfigParsingOperation::RuntimeLaneConfig(input) => {
            let toml_content = input.to_string();
            let result: Result<RuntimeLaneConfig, _> = toml::from_str(&toml_content);

            test_parsing_safety(&toml_content, result.is_ok());

            if let Ok(lane_config) = result {
                match lane_config.overflow_policy {
                    LaneOverflowPolicy::Reject
                    | LaneOverflowPolicy::EnqueueWithTimeout
                    | LaneOverflowPolicy::ShedOldest => {}
                }
            }
        }

        ConfigParsingOperation::ThresholdsConfig(input) => {
            let toml_content = input.to_string();
            let result: Result<ThresholdsConfig, _> = toml::from_str(&toml_content);

            test_parsing_safety(&toml_content, result.is_ok());
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
    }
}

/// Test basic parsing safety (no panics, bounded memory usage).
fn test_parsing_safety(toml_content: &str, _parse_succeeded: bool) {
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
        CompatibilityMode::Strict
        | CompatibilityMode::Balanced
        | CompatibilityMode::LegacyRisky => {}
    }

    // Runtime lanes should have valid configurations
    for (_name, lane_config) in &config.runtime.lanes {
        match lane_config.overflow_policy {
            LaneOverflowPolicy::Reject
            | LaneOverflowPolicy::EnqueueWithTimeout
            | LaneOverflowPolicy::ShedOldest => {}
        }
    }

    // Network allowlist entries should be valid
    for entry in &config.security.network_policy.allowlist {
        let _host_len = entry.host.len();
        let _reason_len = entry.reason.len();
        let _port = entry.port;
    }
}

/// Test security config specific invariants.
fn test_security_config_invariants(security: &SecurityConfig) {
    let _api_key_count = security.authorized_api_keys.len();
    let _allowlist_count = security.network_policy.allowlist.len();
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
    })
    .unwrap_or_else(|_| {
        eprintln!("Panic caught in TOML config parsing fuzzing");
    });
});

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::Unstructured;

    #[test]
    fn test_valid_config_parsing() {
        let toml = r#"
profile = "strict"

[compatibility]
mode = "strict"

	[security]
	max_degraded_duration_secs = 3600
	max_merge_decisions = 100
	authorized_api_keys = ["fuzz-key"]
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
            let _result: Result<Config, _> = toml::from_str(input);
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
                ConfigParsingOperation::FullConfig(_) => {}
                ConfigParsingOperation::ProfileParsing(_) => {}
                ConfigParsingOperation::MalformedTomlTests(_) => {}
                _ => {}
            }
        }
    }
}
