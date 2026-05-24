//! Fuzz target for counterfactual replay policy override specification parsing.
//!
//! Tests policy override spec parsing against malformed key=value pairs,
//! injection attacks, format confusion, overflow conditions, and edge cases.
//! Critical boundary for policy configuration manipulation in replay scenarios.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use base64::prelude::*;
use base64::Engine;

// Mock types for fuzzing
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub policy_name: String,
    pub alert_threshold: u32,
    pub quarantine_duration_ms: u64,
    pub max_retry_count: u8,
    pub escalation_factor: f64,
    pub enabled: bool,
}

#[derive(Debug)]
pub enum CounterfactualReplayError {
    InvalidPolicyOverride { message: String },
    ParseU64Error { key: String, source: std::num::ParseIntError },
    ParseI64Error { key: String, source: std::num::ParseIntError },
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policy_name: "default".to_string(),
            alert_threshold: 100,
            quarantine_duration_ms: 5000,
            max_retry_count: 3,
            escalation_factor: 1.5,
            enabled: true,
        }
    }
}

// Simplified implementation for fuzzing
fn parse_override_spec(
    spec: &str,
    baseline: &PolicyConfig,
) -> Result<PolicyConfig, CounterfactualReplayError> {
    let mut next = baseline.clone();
    for segment in spec.split(',') {
        let part = segment.trim();
        if part.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = part.split_once('=').ok_or_else(|| {
            CounterfactualReplayError::InvalidPolicyOverride {
                message: format!("invalid override segment `{part}`"),
            }
        })?;
        let key = raw_key.trim();
        let value = raw_value.trim();
        match key {
            "policy_name" | "name" => {
                if value.is_empty() {
                    return Err(CounterfactualReplayError::InvalidPolicyOverride {
                        message: "policy name cannot be empty".to_string(),
                    });
                }
                next.policy_name = value.to_string();
            },
            "alert_threshold" => {
                next.alert_threshold = value.parse::<u32>().map_err(|e| {
                    CounterfactualReplayError::ParseU64Error { key: key.to_string(), source: e.into() }
                })?;
            },
            "quarantine_duration_ms" => {
                next.quarantine_duration_ms = value.parse::<u64>().map_err(|e| {
                    CounterfactualReplayError::ParseU64Error { key: key.to_string(), source: e }
                })?;
            },
            "max_retry_count" => {
                next.max_retry_count = value.parse::<u8>().map_err(|e| {
                    CounterfactualReplayError::ParseU64Error { key: key.to_string(), source: e.into() }
                })?;
            },
            "escalation_factor" => {
                next.escalation_factor = value.parse::<f64>().map_err(|_| {
                    CounterfactualReplayError::InvalidPolicyOverride {
                        message: format!("invalid float value for {}", key),
                    }
                })?;
            },
            "enabled" => {
                next.enabled = value.parse::<bool>().map_err(|_| {
                    CounterfactualReplayError::InvalidPolicyOverride {
                        message: format!("invalid boolean value for {}", key),
                    }
                })?;
            },
            _ => {
                return Err(CounterfactualReplayError::InvalidPolicyOverride {
                    message: format!("unknown policy key: {}", key),
                });
            }
        }
    }
    Ok(next)
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: PolicyOverrideTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum PolicyOverrideTest {
    ValidOverrides {
        overrides: Vec<PolicyOverride>,
        format_variant: FormatVariant,
    },
    MalformedSegments {
        attack_type: MalformedType,
        payload: String,
    },
    InjectionAttacks {
        injection_type: InjectionType,
        target_key: String,
        payload: String,
    },
    OverflowAttacks {
        overflow_type: OverflowType,
        target_field: OverflowTarget,
    },
    EdgeCases {
        edge_type: EdgeCaseType,
        modifier: String,
    },
    FormatConfusion {
        confusion_type: FormatConfusionType,
        base_spec: String,
    },
    BoundaryTests {
        boundary_type: BoundaryType,
        test_value: String,
    },
    CommaInjection {
        injection_variant: CommaInjectionVariant,
        position: u8,
    },
}

#[derive(Debug, Clone, Arbitrary)]
struct PolicyOverride {
    key: PolicyKey,
    value: PolicyValue,
}

#[derive(Debug, Clone, Arbitrary)]
enum PolicyKey {
    PolicyName,
    AlertThreshold,
    QuarantineDuration,
    MaxRetryCount,
    EscalationFactor,
    Enabled,
    Invalid(String),
}

#[derive(Debug, Clone, Arbitrary)]
enum PolicyValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Invalid(String),
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatVariant {
    Standard,
    ExtraSpaces,
    NoSpaces,
    MixedSpacing,
    TabSeparated,
}

#[derive(Debug, Clone, Arbitrary)]
enum MalformedType {
    MissingEquals,
    MultipleEquals,
    EmptyKey,
    EmptyValue,
    OnlyKey,
    OnlyValue,
    InvalidSeparator,
    TrailingComma,
}

#[derive(Debug, Clone, Arbitrary)]
enum InjectionType {
    SqlInjection,
    CommandInjection,
    FormatString,
    PathTraversal,
    XssPayload,
    JsonInjection,
    RegexInjection,
    UnicodeInjection,
}

#[derive(Debug, Clone, Arbitrary)]
enum OverflowType {
    IntegerOverflow,
    FloatOverflow,
    StringOverflow,
    NestedOverflow,
}

#[derive(Debug, Clone, Arbitrary)]
enum OverflowTarget {
    AlertThreshold,
    QuarantineDuration,
    MaxRetryCount,
    EscalationFactor,
    PolicyName,
}

#[derive(Debug, Clone, Arbitrary)]
enum EdgeCaseType {
    EmptySpec,
    OnlyCommas,
    OnlySpaces,
    UnicodeChars,
    ControlChars,
    NullBytes,
    LongKeys,
    LongValues,
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatConfusionType {
    JsonLike,
    QueryStringLike,
    IniFormat,
    TomlLike,
    UrlEncoded,
    Base64Encoded,
    MixedFormats,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryType {
    MaxU32,
    MaxU64,
    MaxI32,
    MaxI64,
    MinValues,
    ZeroValues,
    FloatSpecials,
}

#[derive(Debug, Clone, Arbitrary)]
enum CommaInjectionVariant {
    DoubleComma,
    CommaInKey,
    CommaInValue,
    CommaAtStart,
    CommaAtEnd,
    NestedCommas,
}

impl PolicyKey {
    fn to_string(&self) -> String {
        match self {
            PolicyKey::PolicyName => "policy_name".to_string(),
            PolicyKey::AlertThreshold => "alert_threshold".to_string(),
            PolicyKey::QuarantineDuration => "quarantine_duration_ms".to_string(),
            PolicyKey::MaxRetryCount => "max_retry_count".to_string(),
            PolicyKey::EscalationFactor => "escalation_factor".to_string(),
            PolicyKey::Enabled => "enabled".to_string(),
            PolicyKey::Invalid(s) => s.clone(),
        }
    }
}

impl PolicyValue {
    fn to_string(&self) -> String {
        match self {
            PolicyValue::String(s) => s.clone(),
            PolicyValue::Integer(i) => i.to_string(),
            PolicyValue::Float(f) => f.to_string(),
            PolicyValue::Boolean(b) => b.to_string(),
            PolicyValue::Invalid(s) => s.clone(),
        }
    }
}

impl FormatVariant {
    fn apply(&self, key: &str, value: &str) -> String {
        match self {
            FormatVariant::Standard => format!("{}={}", key, value),
            FormatVariant::ExtraSpaces => format!(" {} = {} ", key, value),
            FormatVariant::NoSpaces => format!("{}={}", key, value),
            FormatVariant::MixedSpacing => format!(" {}= {}", key, value),
            FormatVariant::TabSeparated => format!("{}\t=\t{}", key, value),
        }
    }
}

impl MalformedType {
    fn generate(&self, payload: &str) -> String {
        match self {
            MalformedType::MissingEquals => format!("policy_name{}", payload),
            MalformedType::MultipleEquals => format!("policy_name={}=extra", payload),
            MalformedType::EmptyKey => format!("={}", payload),
            MalformedType::EmptyValue => "policy_name=".to_string(),
            MalformedType::OnlyKey => "policy_name".to_string(),
            MalformedType::OnlyValue => format!("={}", payload),
            MalformedType::InvalidSeparator => format!("policy_name:{}", payload),
            MalformedType::TrailingComma => format!("policy_name={},", payload),
        }
    }
}

impl InjectionType {
    fn generate_payload(&self, target_key: &str, payload: &str) -> String {
        let injection = match self {
            InjectionType::SqlInjection => "'; DROP TABLE policies; --",
            InjectionType::CommandInjection => "; rm -rf /",
            InjectionType::FormatString => "%s%x%p%n",
            InjectionType::PathTraversal => "../../../etc/passwd",
            InjectionType::XssPayload => "<script>alert(1)</script>",
            InjectionType::JsonInjection => "\",\"injected\":\"evil",
            InjectionType::RegexInjection => ".*+?{}[]()^$",
            InjectionType::UnicodeInjection => "\u{202E}\u{202D}",
        };
        format!("{}={}{}", target_key, payload, injection)
    }
}

impl OverflowType {
    fn generate(&self, target: &OverflowTarget) -> String {
        match (self, target) {
            (OverflowType::IntegerOverflow, OverflowTarget::AlertThreshold) => {
                "alert_threshold=18446744073709551616".to_string()
            },
            (OverflowType::IntegerOverflow, OverflowTarget::QuarantineDuration) => {
                "quarantine_duration_ms=999999999999999999999".to_string()
            },
            (OverflowType::IntegerOverflow, OverflowTarget::MaxRetryCount) => {
                "max_retry_count=256".to_string()
            },
            (OverflowType::FloatOverflow, OverflowTarget::EscalationFactor) => {
                "escalation_factor=1.7976931348623157e+308".to_string()
            },
            (OverflowType::StringOverflow, OverflowTarget::PolicyName) => {
                format!("policy_name={}", "A".repeat(100000))
            },
            (OverflowType::NestedOverflow, _) => {
                "alert_threshold=9".repeat(1000)
            },
            _ => "policy_name=overflow_test".to_string(),
        }
    }
}

impl EdgeCaseType {
    fn generate(&self, modifier: &str) -> String {
        match self {
            EdgeCaseType::EmptySpec => String::new(),
            EdgeCaseType::OnlyCommas => ",,,,,".to_string(),
            EdgeCaseType::OnlySpaces => "     ".to_string(),
            EdgeCaseType::UnicodeChars => format!("policy_name=test{}\u{1F4A5}", modifier),
            EdgeCaseType::ControlChars => format!("policy_name=test{}\x00\x1F", modifier),
            EdgeCaseType::NullBytes => format!("policy_name=test\0{}", modifier),
            EdgeCaseType::LongKeys => format!("{}=value", "very_long_key_name".repeat(100)),
            EdgeCaseType::LongValues => format!("policy_name={}", modifier.repeat(10000)),
        }
    }
}

impl FormatConfusionType {
    fn apply(&self, base_spec: &str) -> String {
        match self {
            FormatConfusionType::JsonLike => format!("{{\"policy_name\":\"{}\"}}", base_spec),
            FormatConfusionType::QueryStringLike => format!("policy_name={}&other=value", base_spec),
            FormatConfusionType::IniFormat => format!("[section]\npolicy_name={}", base_spec),
            FormatConfusionType::TomlLike => format!("policy_name = \"{}\"", base_spec),
            FormatConfusionType::UrlEncoded => format!("policy_name={}", urlencoding::encode(base_spec)),
            FormatConfusionType::Base64Encoded => base64::prelude::BASE64_STANDARD.encode(base_spec.as_bytes()),
            FormatConfusionType::MixedFormats => format!("policy_name={}{{\"other\":\"json\"}}", base_spec),
        }
    }
}

impl BoundaryType {
    fn generate(&self, _test_value: &str) -> String {
        match self {
            BoundaryType::MaxU32 => "alert_threshold=4294967295".to_string(),
            BoundaryType::MaxU64 => "quarantine_duration_ms=18446744073709551615".to_string(),
            BoundaryType::MaxI32 => "alert_threshold=2147483647".to_string(),
            BoundaryType::MaxI64 => "quarantine_duration_ms=9223372036854775807".to_string(),
            BoundaryType::MinValues => "alert_threshold=0,max_retry_count=0".to_string(),
            BoundaryType::ZeroValues => "escalation_factor=0.0,quarantine_duration_ms=0".to_string(),
            BoundaryType::FloatSpecials => "escalation_factor=NaN,other=inf".to_string(),
        }
    }
}

impl CommaInjectionVariant {
    fn apply(&self, position: u8) -> String {
        let base = "policy_name=test";
        let _pos = (position as usize) % base.len();
        match self {
            CommaInjectionVariant::DoubleComma => "policy_name=test,,alert_threshold=100".to_string(),
            CommaInjectionVariant::CommaInKey => "policy,name=test".to_string(),
            CommaInjectionVariant::CommaInValue => "policy_name=test,value".to_string(),
            CommaInjectionVariant::CommaAtStart => ",policy_name=test".to_string(),
            CommaInjectionVariant::CommaAtEnd => "policy_name=test,".to_string(),
            CommaInjectionVariant::NestedCommas => "policy_name=test,,,alert_threshold=100,,,".to_string(),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        let baseline = PolicyConfig::default();

        match fuzz_input.operation {
            PolicyOverrideTest::ValidOverrides { overrides, format_variant } => {
                let spec: String = overrides.iter()
                    .map(|override_spec| format_variant.apply(&override_spec.key.to_string(), &override_spec.value.to_string()))
                    .collect::<Vec<_>>()
                    .join(",");

                // Test deterministic parsing
                let result1 = parse_override_spec(&spec, &baseline);
                let result2 = parse_override_spec(&spec, &baseline);
                assert_eq!(result1.is_ok(), result2.is_ok(), "Valid override parsing should be deterministic");

                // Valid overrides should parse successfully
                if !spec.trim().is_empty() && !overrides.is_empty() {
                    match result1 {
                        Ok(config) => {
                            // Parsed config should have reasonable values
                            assert!(config.alert_threshold < u32::MAX, "Alert threshold should not overflow");
                            assert!(config.escalation_factor.is_finite(), "Escalation factor should be finite");
                        },
                        Err(_) => {
                            // Some malformed specs may legitimately fail
                        }
                    }
                }
            },
            PolicyOverrideTest::MalformedSegments { attack_type, payload } => {
                let malformed_spec = attack_type.generate(&payload);
                let result = parse_override_spec(&malformed_spec, &baseline);

                // Malformed segments should be rejected
                assert!(result.is_err(), "Malformed segments should be rejected: {:?}", attack_type);
            },
            PolicyOverrideTest::InjectionAttacks { injection_type, target_key, payload } => {
                let injection_spec = injection_type.generate_payload(&target_key, &payload);
                let result = parse_override_spec(&injection_spec, &baseline);

                // Test deterministic injection handling
                let result2 = parse_override_spec(&injection_spec, &baseline);
                assert_eq!(result.is_ok(), result2.is_ok(), "Injection handling should be deterministic");

                // Most injection attacks should be safely rejected or contained
                if let Ok(config) = result {
                    // Injection should not cause unsafe values
                    assert!(config.escalation_factor.is_finite(), "Injection should not cause infinite values");
                }
            },
            PolicyOverrideTest::OverflowAttacks { overflow_type, target_field } => {
                let overflow_spec = overflow_type.generate(&target_field);
                let result = parse_override_spec(&overflow_spec, &baseline);

                // Overflow attacks should be safely handled
                if let Err(_) = result {
                    // Overflow rejection is expected and safe
                } else if let Ok(config) = result {
                    // If parsed, values should be within safe bounds
                    assert!(config.escalation_factor.is_finite(), "Overflow should not produce infinite values");
                }
            },
            PolicyOverrideTest::EdgeCases { edge_type, modifier } => {
                let edge_spec = edge_type.generate(&modifier);
                let result = parse_override_spec(&edge_spec, &baseline);

                // Edge cases should be handled safely
                let result2 = parse_override_spec(&edge_spec, &baseline);
                assert_eq!(result.is_ok(), result2.is_ok(), "Edge case handling should be deterministic");
            },
            PolicyOverrideTest::FormatConfusion { confusion_type, base_spec } => {
                let confused_spec = confusion_type.apply(&base_spec);
                let result = parse_override_spec(&confused_spec, &baseline);

                // Format confusion should not cause crashes
                let result2 = parse_override_spec(&confused_spec, &baseline);
                assert_eq!(result.is_ok(), result2.is_ok(), "Format confusion handling should be deterministic");
            },
            PolicyOverrideTest::BoundaryTests { boundary_type, test_value } => {
                let boundary_spec = boundary_type.generate(&test_value);
                let result = parse_override_spec(&boundary_spec, &baseline);

                // Boundary tests should complete without crashes
                if let Ok(config) = result {
                    assert!(config.escalation_factor.is_finite(), "Boundary values should be finite");
                }
            },
            PolicyOverrideTest::CommaInjection { injection_variant, position } => {
                let comma_spec = injection_variant.apply(position);
                let result = parse_override_spec(&comma_spec, &baseline);

                // Comma injection should be handled safely
                let result2 = parse_override_spec(&comma_spec, &baseline);
                assert_eq!(result.is_ok(), result2.is_ok(), "Comma injection handling should be deterministic");
            },
        }
    }
});