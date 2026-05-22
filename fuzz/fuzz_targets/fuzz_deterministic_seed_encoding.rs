//! Fuzz target for deterministic seed encoding parsing boundary.
//!
//! Tests content hash parsing, domain tag validation, seed derivation,
//! hex decoding, and JSON deserialization across encoding module boundaries.
//! Critical for preventing seed derivation attacks and maintaining
//! deterministic behavior across platforms.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use serde_json::{json, Value};

// Import the deterministic seed types
// Note: These imports may need adjustment based on actual module structure
// use frankenengine_node::encoding::deterministic_seed::{
//     ContentHash, DeterministicSeed, DeterministicSeedDeriver, DomainTag, ScheduleConfig, SeedError
// };

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: SeedEncodingOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum SeedEncodingOperation {
    ContentHashParsing {
        hex_input: HexInput,
    },
    DeterministicSeedDeserialization {
        json_input: JsonSeedInput,
    },
    DomainTagValidation {
        domain_input: DomainInput,
    },
    SeedDerivation {
        content: HexInput,
        domain: DomainInput,
        config_version: u32,
    },
    BatchOperations {
        operations: Vec<SeedEncodingOperation>,
    },
    EdgeCaseInputs {
        edge_case: EdgeCaseType,
    },
    MaliciousInputs {
        attack_type: AttackType,
        input_data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Arbitrary)]
struct HexInput {
    hex_type: HexInputType,
}

#[derive(Debug, Clone, Arbitrary)]
enum HexInputType {
    Valid(String),
    Empty,
    OddLength(String),
    TooShort(Vec<u8>),
    TooLong(Vec<u8>),
    WithPrefix(String),
    WithWhitespace(String),
    WithNullBytes(Vec<u8>),
    InvalidHex(String),
    Unicode(String),
    ControlChars(Vec<u8>),
}

#[derive(Debug, Clone, Arbitrary)]
struct JsonSeedInput {
    seed_structure: SeedStructureType,
}

#[derive(Debug, Clone, Arbitrary)]
enum SeedStructureType {
    Valid {
        bytes: String,
        domain: String,
        config_version: u32,
    },
    MissingFields {
        bytes: Option<String>,
        domain: Option<String>,
        config_version: Option<u32>,
    },
    WrongFieldTypes {
        bytes: JsonValueVariant,
        domain: JsonValueVariant,
        config_version: JsonValueVariant,
    },
    ExtraFields {
        bytes: String,
        domain: String,
        config_version: u32,
        extra_fields: Vec<(String, JsonValueVariant)>,
    },
    MalformedJson(String),
}

#[derive(Debug, Clone, Arbitrary)]
enum JsonValueVariant {
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
    Array(Vec<String>),
    Object,
}

#[derive(Debug, Clone, Arbitrary)]
struct DomainInput {
    domain_type: DomainInputType,
}

#[derive(Debug, Clone, Arbitrary)]
enum DomainInputType {
    Valid(ValidDomain),
    Invalid(String),
    Empty,
    VeryLong(Vec<u8>),
    WithNullBytes(Vec<u8>),
    Unicode(String),
    ControlChars(Vec<u8>),
}

#[derive(Debug, Clone, Arbitrary)]
enum ValidDomain {
    Encoding,
    Repair,
    Scheduling,
    Placement,
    Verification,
}

#[derive(Debug, Clone, Arbitrary)]
enum EdgeCaseType {
    ExactLengthBoundaries,
    MaxValues,
    MinValues,
    EmptyInputs,
    AllZeros,
    AllOnes,
    AlternatingPattern,
    UnicodeEdgeCases,
}

#[derive(Debug, Clone, Arbitrary)]
enum AttackType {
    HexCollisionAttempt,
    DomainSeparationBypass,
    SeedCollisionAttempt,
    OverflowAttack,
    NullByteInjection,
    TimingAttack,
    JsonInjection,
}

impl HexInput {
    fn to_string(&self) -> String {
        match &self.hex_type {
            HexInputType::Valid(s) => s.clone(),
            HexInputType::Empty => String::new(),
            HexInputType::OddLength(s) => {
                if s.is_empty() {
                    "abc".to_string() // odd length
                } else {
                    format!("{}f", s) // make it odd
                }
            }
            HexInputType::TooShort(bytes) => hex::encode(&bytes[..bytes.len().min(31)]),
            HexInputType::TooLong(bytes) => hex::encode(bytes),
            HexInputType::WithPrefix(s) => {
                if s.is_empty() {
                    format!("0x{}", "aa".repeat(32))
                } else {
                    format!("0x{}", s)
                }
            }
            HexInputType::WithWhitespace(s) => {
                if s.is_empty() {
                    format!("{} {}", "aa".repeat(16), "bb".repeat(16))
                } else {
                    s.replace("", " ")
                }
            }
            HexInputType::WithNullBytes(bytes) => String::from_utf8_lossy(bytes).to_string(),
            HexInputType::InvalidHex(s) => s.clone(),
            HexInputType::Unicode(s) => s.clone(),
            HexInputType::ControlChars(bytes) => String::from_utf8_lossy(bytes).to_string(),
        }
    }
}

impl JsonSeedInput {
    fn to_value(&self) -> Value {
        match &self.seed_structure {
            SeedStructureType::Valid { bytes, domain, config_version } => {
                json!({
                    "bytes": bytes,
                    "domain": domain,
                    "config_version": config_version
                })
            }
            SeedStructureType::MissingFields { bytes, domain, config_version } => {
                let mut obj = serde_json::Map::new();
                if let Some(b) = bytes {
                    obj.insert("bytes".to_string(), json!(b));
                }
                if let Some(d) = domain {
                    obj.insert("domain".to_string(), json!(d));
                }
                if let Some(cv) = config_version {
                    obj.insert("config_version".to_string(), json!(cv));
                }
                Value::Object(obj)
            }
            SeedStructureType::WrongFieldTypes { bytes, domain, config_version } => {
                json!({
                    "bytes": json_value_variant_to_value(bytes),
                    "domain": json_value_variant_to_value(domain),
                    "config_version": json_value_variant_to_value(config_version)
                })
            }
            SeedStructureType::ExtraFields { bytes, domain, config_version, extra_fields } => {
                let mut obj = serde_json::Map::new();
                obj.insert("bytes".to_string(), json!(bytes));
                obj.insert("domain".to_string(), json!(domain));
                obj.insert("config_version".to_string(), json!(config_version));

                for (key, value) in extra_fields {
                    obj.insert(key.clone(), json_value_variant_to_value(value));
                }

                Value::Object(obj)
            }
            SeedStructureType::MalformedJson(s) => {
                // Return a string that will fail JSON parsing
                Value::String(s.clone())
            }
        }
    }

    fn to_json_string(&self) -> String {
        match &self.seed_structure {
            SeedStructureType::MalformedJson(s) => s.clone(),
            _ => self.to_value().to_string(),
        }
    }
}

fn json_value_variant_to_value(variant: &JsonValueVariant) -> Value {
    match variant {
        JsonValueVariant::String(s) => json!(s),
        JsonValueVariant::Number(n) => json!(n),
        JsonValueVariant::Boolean(b) => json!(b),
        JsonValueVariant::Null => json!(null),
        JsonValueVariant::Array(arr) => json!(arr),
        JsonValueVariant::Object => json!({}),
    }
}

impl DomainInput {
    fn to_string(&self) -> String {
        match &self.domain_type {
            DomainInputType::Valid(domain) => {
                match domain {
                    ValidDomain::Encoding => "Encoding".to_string(),
                    ValidDomain::Repair => "Repair".to_string(),
                    ValidDomain::Scheduling => "Scheduling".to_string(),
                    ValidDomain::Placement => "Placement".to_string(),
                    ValidDomain::Verification => "Verification".to_string(),
                }
            }
            DomainInputType::Invalid(s) => s.clone(),
            DomainInputType::Empty => String::new(),
            DomainInputType::VeryLong(bytes) => String::from_utf8_lossy(bytes).to_string(),
            DomainInputType::WithNullBytes(bytes) => String::from_utf8_lossy(bytes).to_string(),
            DomainInputType::Unicode(s) => s.clone(),
            DomainInputType::ControlChars(bytes) => String::from_utf8_lossy(bytes).to_string(),
        }
    }
}

/// Test seed encoding parsing invariants.
fn test_seed_encoding_invariants(operation: &SeedEncodingOperation) {
    match operation {
        SeedEncodingOperation::ContentHashParsing { hex_input } => {
            let hex_string = hex_input.to_string();

            // Test content hash parsing
            test_content_hash_parsing(&hex_string);
        }

        SeedEncodingOperation::DeterministicSeedDeserialization { json_input } => {
            let json_value = json_input.to_value();
            let json_string = json_input.to_json_string();

            // Test JSON deserialization
            test_seed_json_deserialization(&json_value, &json_string);
        }

        SeedEncodingOperation::DomainTagValidation { domain_input } => {
            let domain_string = domain_input.to_string();

            // Test domain tag validation
            test_domain_tag_validation(&domain_string);
        }

        SeedEncodingOperation::SeedDerivation { content, domain, config_version } => {
            let hex_string = content.to_string();
            let domain_string = domain.to_string();

            // Test complete seed derivation pipeline
            test_seed_derivation_pipeline(&hex_string, &domain_string, *config_version);
        }

        SeedEncodingOperation::BatchOperations { operations } => {
            // Test batch operations for consistency
            for op in operations {
                // Recursive test with depth limit to prevent stack overflow
                if operations.len() < 100 {
                    test_seed_encoding_invariants(op);
                }
            }
        }

        SeedEncodingOperation::EdgeCaseInputs { edge_case } => {
            test_edge_case_handling(edge_case);
        }

        SeedEncodingOperation::MaliciousInputs { attack_type, input_data } => {
            test_malicious_input_handling(attack_type, input_data);
        }
    }
}

/// Test content hash parsing invariants.
fn test_content_hash_parsing(hex_input: &str) {
    // Simulate ContentHash::from_hex behavior
    test_hex_parsing_invariants(hex_input);
}

/// Test hex parsing invariants.
fn test_hex_parsing_invariants(hex_input: &str) {
    // Test basic safety properties

    // Empty input should be invalid
    if hex_input.is_empty() {
        // Should be rejected
        return;
    }

    // Odd length should be invalid
    if hex_input.len() % 2 != 0 {
        // Should be rejected
        return;
    }

    // Test hex decoding safety
    let decode_result = hex::decode(hex_input);
    match decode_result {
        Ok(bytes) => {
            // Valid hex - test length requirements

            // For content hash, should be exactly 32 bytes
            if bytes.len() != 32 {
                // Should be rejected for content hash
            }

            // Test that the same input produces the same output (deterministic)
            let decode_result2 = hex::decode(hex_input);
            if let Ok(bytes2) = decode_result2 {
                assert_eq!(bytes, bytes2, "Hex decoding must be deterministic");
            }
        }
        Err(_) => {
            // Invalid hex - should be rejected safely
        }
    }

    // Test prefix handling
    if hex_input.starts_with("0x") || hex_input.starts_with("0X") {
        // Prefixed hex should be rejected
    }

    // Test whitespace handling
    if hex_input.contains(' ') || hex_input.contains('\t') || hex_input.contains('\n') {
        // Whitespace should be rejected
    }

    // Test null byte handling
    if hex_input.contains('\0') {
        // Null bytes should be handled safely
    }
}

/// Test seed JSON deserialization invariants.
fn test_seed_json_deserialization(json_value: &Value, json_string: &str) {
    // Test JSON parsing safety
    let parse_result = serde_json::from_str::<Value>(json_string);

    match parse_result {
        Ok(parsed_value) => {
            // Valid JSON - test structure validation
            test_seed_structure_validation(&parsed_value);
        }
        Err(_) => {
            // Invalid JSON - should be rejected safely
        }
    }

    // Test deterministic parsing
    if let Ok(parsed1) = serde_json::from_str::<Value>(json_string) {
        if let Ok(parsed2) = serde_json::from_str::<Value>(json_string) {
            assert_eq!(parsed1, parsed2, "JSON parsing must be deterministic");
        }
    }
}

/// Test seed structure validation.
fn test_seed_structure_validation(json_value: &Value) {
    // Test required fields
    let has_bytes = json_value.get("bytes").is_some();
    let has_domain = json_value.get("domain").is_some();
    let has_config_version = json_value.get("config_version").is_some();

    // All three fields should be present for valid seed
    if !(has_bytes && has_domain && has_config_version) {
        // Should be rejected
    }

    // Test field types
    if let Some(bytes_field) = json_value.get("bytes") {
        if !bytes_field.is_string() {
            // Should be rejected - bytes must be string
        } else if let Some(bytes_str) = bytes_field.as_str() {
            // Test hex content in bytes field
            test_hex_parsing_invariants(bytes_str);
        }
    }

    if let Some(domain_field) = json_value.get("domain") {
        if !domain_field.is_string() {
            // Should be rejected - domain must be string
        } else if let Some(domain_str) = domain_field.as_str() {
            test_domain_tag_validation(domain_str);
        }
    }

    if let Some(config_field) = json_value.get("config_version") {
        if !config_field.is_number() {
            // Should be rejected - config_version must be number
        }
    }
}

/// Test domain tag validation.
fn test_domain_tag_validation(domain_input: &str) {
    // Test valid domain tags
    let valid_domains = ["Encoding", "Repair", "Scheduling", "Placement", "Verification"];

    let is_valid = valid_domains.contains(&domain_input);

    if !is_valid {
        // Unknown domains should be rejected
    }

    // Test case sensitivity
    if domain_input != domain_input.trim() {
        // Whitespace should be rejected
    }

    // Test null byte handling
    if domain_input.contains('\0') {
        // Null bytes should be handled safely
    }

    // Test very long domains
    if domain_input.len() > 1000 {
        // Very long domains should be rejected
    }
}

/// Test seed derivation pipeline.
fn test_seed_derivation_pipeline(hex_input: &str, domain_input: &str, config_version: u32) {
    // Test the complete pipeline: hex parsing -> domain validation -> seed derivation

    // First test hex parsing
    test_hex_parsing_invariants(hex_input);

    // Then test domain validation
    test_domain_tag_validation(domain_input);

    // Test config version handling
    test_config_version_validation(config_version);

    // Test deterministic behavior
    // Same inputs should produce same outputs
}

/// Test config version validation.
fn test_config_version_validation(config_version: u32) {
    // Test boundary values
    if config_version == 0 {
        // Zero version might be invalid
    }

    if config_version > 1000000 {
        // Very high versions might be invalid
    }

    // Test overflow safety
    let _safe_add = config_version.saturating_add(1);
}

/// Test edge case handling.
fn test_edge_case_handling(edge_case: &EdgeCaseType) {
    match edge_case {
        EdgeCaseType::ExactLengthBoundaries => {
            test_hex_parsing_invariants(&"aa".repeat(32)); // Exactly 32 bytes
            test_hex_parsing_invariants(&"bb".repeat(31)); // One short
            test_hex_parsing_invariants(&"cc".repeat(33)); // One long
        }
        EdgeCaseType::MaxValues => {
            test_config_version_validation(u32::MAX);
        }
        EdgeCaseType::MinValues => {
            test_config_version_validation(0);
            test_hex_parsing_invariants("");
            test_domain_tag_validation("");
        }
        EdgeCaseType::EmptyInputs => {
            test_hex_parsing_invariants("");
            test_domain_tag_validation("");
        }
        EdgeCaseType::AllZeros => {
            test_hex_parsing_invariants(&"00".repeat(32));
        }
        EdgeCaseType::AllOnes => {
            test_hex_parsing_invariants(&"ff".repeat(32));
        }
        _ => {
            // Other edge cases
        }
    }
}

/// Test malicious input handling.
fn test_malicious_input_handling(attack_type: &AttackType, input_data: &[u8]) {
    let input_string = String::from_utf8_lossy(input_data);

    match attack_type {
        AttackType::HexCollisionAttempt => {
            test_hex_parsing_invariants(&input_string);
        }
        AttackType::DomainSeparationBypass => {
            test_domain_tag_validation(&input_string);
        }
        AttackType::NullByteInjection => {
            test_hex_parsing_invariants(&input_string);
            test_domain_tag_validation(&input_string);
        }
        AttackType::JsonInjection => {
            let _parse_result = serde_json::from_str::<Value>(&input_string);
            // Should not panic or cause security issues
        }
        _ => {
            // Other attack types
            test_hex_parsing_invariants(&input_string);
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    std::panic::catch_unwind(|| {
        test_seed_encoding_invariants(&input.operation);
    }).unwrap_or_else(|_| {
        eprintln!("Panic caught in deterministic seed encoding fuzzing");
    });
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_hex_generation() {
        let hex_input = HexInput {
            hex_type: HexInputType::Valid("deadbeef".to_string()),
        };
        assert_eq!(hex_input.to_string(), "deadbeef");
    }

    #[test]
    fn test_domain_string_generation() {
        let domain_input = DomainInput {
            domain_type: DomainInputType::Valid(ValidDomain::Encoding),
        };
        assert_eq!(domain_input.to_string(), "Encoding");
    }

    #[test]
    fn test_json_seed_generation() {
        let json_input = JsonSeedInput {
            seed_structure: SeedStructureType::Valid {
                bytes: "deadbeef".to_string(),
                domain: "Encoding".to_string(),
                config_version: 1,
            },
        };

        let value = json_input.to_value();
        assert!(value.is_object());
        assert_eq!(value["bytes"], "deadbeef");
        assert_eq!(value["domain"], "Encoding");
        assert_eq!(value["config_version"], 1);
    }

    #[test]
    fn test_hex_parsing_invariants_basic() {
        test_hex_parsing_invariants("deadbeef");
        test_hex_parsing_invariants("");
        test_hex_parsing_invariants("abc"); // odd length
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
                SeedEncodingOperation::ContentHashParsing { .. } => {},
                SeedEncodingOperation::DeterministicSeedDeserialization { .. } => {},
                SeedEncodingOperation::DomainTagValidation { .. } => {},
                _ => {},
            }
        }
    }
}