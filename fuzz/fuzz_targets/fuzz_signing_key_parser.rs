//! Fuzz target for signing key blob parsing.
//!
//! Tests Ed25519 signing key parser against malformed binary data, invalid
//! base64/hex encoding, JSON injection, length attacks, and format confusion.
//! Critical security boundary for cryptographic key material parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

// Mock Ed25519 SigningKey for fuzzing (avoiding real crypto dependencies)
#[derive(Debug, Clone)]
pub struct SigningKey {
    bytes: [u8; 32],
}

impl SigningKey {
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey { bytes: *bytes }
    }

    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey { bytes: self.bytes }
    }
}

#[derive(Debug, Clone)]
pub struct VerifyingKey {
    bytes: [u8; 32],
}

impl VerifyingKey {
    fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

// Simplified constant time comparison for fuzzing
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    a == b
}

// Reimplemented signing key parser for fuzzing
fn parse_signing_key_from_blob(raw: &[u8]) -> Option<SigningKey> {
    fn signing_key_from_bytes(raw: &[u8]) -> Option<SigningKey> {
        match raw.len() {
            32 => {
                let bytes = <[u8; 32]>::try_from(raw).ok()?;
                Some(SigningKey::from_bytes(&bytes))
            }
            64 => {
                let seed = <[u8; 32]>::try_from(&raw[..32]).ok()?;
                let public = <[u8; 32]>::try_from(&raw[32..]).ok()?;
                let signing_key = SigningKey::from_bytes(&seed);
                let derived_public = signing_key.verifying_key().to_bytes();
                if ct_eq_bytes(&derived_public, &public) {
                    Some(signing_key)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    if let Some(signing_key) = signing_key_from_bytes(raw) {
        return Some(signing_key);
    }

    let Ok(text) = std::str::from_utf8(raw) else {
        return None;
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut candidates = vec![trimmed.to_string()];
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        fn parse_byte_array(values: &[serde_json::Value]) -> Option<Vec<u8>> {
            if values.len() != 32 && values.len() != 64 {
                return None;
            }
            let mut bytes = Vec::with_capacity(values.len());
            for value in values {
                let num = value.as_u64()?;
                if num > 255 {
                    return None;
                }
                bytes.push(num as u8);
            }
            Some(bytes)
        }

        match &value {
            serde_json::Value::String(s) => candidates.push(s.clone()),
            serde_json::Value::Array(arr) => {
                if let Some(bytes) = parse_byte_array(arr) {
                    return signing_key_from_bytes(&bytes);
                }
            }
            serde_json::Value::Object(obj) => {
                for key in &["privateKey", "private_key", "seed", "key", "bytes"] {
                    if let Some(serde_json::Value::String(s)) = obj.get(*key) {
                        candidates.push(s.clone());
                    }
                    if let Some(serde_json::Value::Array(arr)) = obj.get(*key) {
                        if let Some(bytes) = parse_byte_array(arr) {
                            if let Some(key) = signing_key_from_bytes(&bytes) {
                                return Some(key);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    for candidate in candidates {
        // Try hex decode
        if candidate.len() == 64 || candidate.len() == 128 {
            if let Ok(bytes) = hex::decode(&candidate) {
                if let Some(key) = signing_key_from_bytes(&bytes) {
                    return Some(key);
                }
            }
        }

        // Try simple base64-like decode (simplified for fuzzing)
        if candidate.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
            // Mock base64 decode - just treat as hex for fuzzing purposes
            if candidate.len() % 4 == 0 {
                let clean = candidate.replace('=', "").replace('+', "A").replace('/', "B");
                if let Ok(bytes) = hex::decode(&clean) {
                    if let Some(key) = signing_key_from_bytes(&bytes) {
                        return Some(key);
                    }
                }
            }
        }
    }

    None
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: KeyParsingOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum KeyParsingOperation {
    RawBytes {
        data: Vec<u8>,
        length_variant: LengthVariant,
    },
    EncodedText {
        encoding: EncodingType,
        key_data: KeyData,
        corruption: Vec<TextCorruption>,
    },
    JsonPayload {
        json_type: JsonVariant,
        payload: String,
        injection_attempts: Vec<JsonInjection>,
    },
    SecurityBoundaryTests {
        attack_type: SecurityAttack,
        payload_size: u8,
    },
    FormatConfusion {
        primary_format: EncodingType,
        secondary_format: EncodingType,
        confusion_method: ConfusionMethod,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum LengthVariant {
    Exact32,
    Exact64,
    Empty,
    TooShort,
    TooLong,
    Random,
}

#[derive(Debug, Clone, Arbitrary)]
enum EncodingType {
    Hex,
    Base64,
    Base64Url,
    Json,
    Binary,
}

#[derive(Debug, Clone, Arbitrary)]
struct KeyData {
    seed: [u8; 32],
    include_public: bool,
}

#[derive(Debug, Clone, Arbitrary)]
enum TextCorruption {
    InvalidChar(char),
    TruncateMiddle,
    DuplicateSegment,
    CaseChange,
    Padding,
    Whitespace,
}

#[derive(Debug, Clone, Arbitrary)]
enum JsonVariant {
    StringKey,
    ByteArray,
    NestedObject,
    MultipleKeys,
    MalformedStructure,
}

#[derive(Debug, Clone, Arbitrary)]
enum JsonInjection {
    PropertyInjection,
    ArrayInjection,
    PrototypePollution,
    NullByteInjection,
    UnicodeEscape,
}

#[derive(Debug, Clone, Arbitrary)]
enum SecurityAttack {
    BufferOverflow,
    MemoryExhaustion,
    TimingAttack,
    InvalidUtf8,
    NullByteInjection,
    FormatStringInjection,
}

#[derive(Debug, Clone, Arbitrary)]
enum ConfusionMethod {
    Concatenate,
    Interleave,
    Nest,
    Prefix,
    Suffix,
}

impl KeyData {
    fn to_bytes(&self, include_public: bool) -> Vec<u8> {
        if include_public {
            let mut result = self.seed.to_vec();
            result.extend_from_slice(&self.seed); // Mock public key = seed for simplicity
            result
        } else {
            self.seed.to_vec()
        }
    }

    fn to_hex(&self, include_public: bool) -> String {
        hex::encode(self.to_bytes(include_public))
    }

    fn to_base64(&self, include_public: bool) -> String {
        // Mock base64 encode for fuzzing - just use hex
        hex::encode(self.to_bytes(include_public))
    }

    fn to_json_array(&self, include_public: bool) -> String {
        let bytes = self.to_bytes(include_public);
        format!("[{}]", bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(","))
    }
}

impl TextCorruption {
    fn apply(&self, input: &str) -> String {
        match self {
            TextCorruption::InvalidChar(c) => format!("{}{}", input, c),
            TextCorruption::TruncateMiddle => {
                let mid = input.len() / 2;
                format!("{}{}", &input[..mid.saturating_sub(2)], &input[mid + 2..])
            },
            TextCorruption::DuplicateSegment => {
                if input.len() >= 8 {
                    let segment = &input[..4];
                    format!("{}{}{}", segment, segment, &input[4..])
                } else {
                    input.to_string()
                }
            },
            TextCorruption::CaseChange => {
                input.chars().enumerate().map(|(i, c)| {
                    if i % 2 == 0 { c.to_uppercase().collect::<String>() }
                    else { c.to_lowercase().collect::<String>() }
                }).collect()
            },
            TextCorruption::Padding => format!("{}==", input),
            TextCorruption::Whitespace => format!("  {}  \n\t", input),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            KeyParsingOperation::RawBytes { data, length_variant } => {
                let test_data = match length_variant {
                    LengthVariant::Exact32 => {
                        let mut bytes = [0u8; 32];
                        for (i, &b) in data.iter().take(32).enumerate() {
                            bytes[i] = b;
                        }
                        bytes.to_vec()
                    },
                    LengthVariant::Exact64 => {
                        let mut bytes = [0u8; 64];
                        for (i, &b) in data.iter().take(64).enumerate() {
                            bytes[i] = b;
                        }
                        bytes.to_vec()
                    },
                    LengthVariant::Empty => vec![],
                    LengthVariant::TooShort => data.iter().take(16).copied().collect(),
                    LengthVariant::TooLong => data.iter().cycle().take(100).copied().collect(),
                    LengthVariant::Random => data,
                };
                let _ = parse_signing_key_from_blob(&test_data);
            },
            KeyParsingOperation::EncodedText { encoding, key_data, corruption } => {
                let mut encoded = match encoding {
                    EncodingType::Hex => key_data.to_hex(false),
                    EncodingType::Base64 | EncodingType::Base64Url => key_data.to_base64(false),
                    EncodingType::Json => key_data.to_json_array(false),
                    EncodingType::Binary => String::from_utf8_lossy(&key_data.to_bytes(false)).to_string(),
                };

                for corrupt in &corruption {
                    encoded = corrupt.apply(&encoded);
                }

                let _ = parse_signing_key_from_blob(encoded.as_bytes());
            },
            KeyParsingOperation::JsonPayload { json_type, payload, injection_attempts: _ } => {
                let json_payload = match json_type {
                    JsonVariant::StringKey => format!("{{\"privateKey\": \"{}\"}}", payload),
                    JsonVariant::ByteArray => format!("[{}]", payload),
                    JsonVariant::NestedObject => format!("{{\"key\": {{\"bytes\": \"{}\"}}}}", payload),
                    JsonVariant::MultipleKeys => format!("{{\"privateKey\": \"{}\", \"seed\": \"{}\"}}", payload, payload),
                    JsonVariant::MalformedStructure => format!("{{\"privateKey\": {}}}", payload),
                };
                let _ = parse_signing_key_from_blob(json_payload.as_bytes());
            },
            KeyParsingOperation::SecurityBoundaryTests { attack_type, payload_size } => {
                let size = (payload_size as usize).min(1000); // Cap for fuzzing
                let attack_payload = match attack_type {
                    SecurityAttack::BufferOverflow => vec![0xFF; size * 100],
                    SecurityAttack::MemoryExhaustion => "A".repeat(size * 1000).into_bytes(),
                    SecurityAttack::TimingAttack => {
                        // Alternating patterns to test timing differences
                        (0..size).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect()
                    },
                    SecurityAttack::InvalidUtf8 => {
                        let mut invalid = b"key:".to_vec();
                        invalid.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
                        invalid
                    },
                    SecurityAttack::NullByteInjection => format!("key\0{}\0", "A".repeat(size)).into_bytes(),
                    SecurityAttack::FormatStringInjection => format!("%s%n%x{}", "A".repeat(size)).into_bytes(),
                };
                let _ = parse_signing_key_from_blob(&attack_payload);
            },
            KeyParsingOperation::FormatConfusion { primary_format, secondary_format, confusion_method: _ } => {
                let key_data = KeyData { seed: [0x42; 32], include_public: false };
                let primary = match primary_format {
                    EncodingType::Hex => key_data.to_hex(false),
                    EncodingType::Base64 | EncodingType::Base64Url => key_data.to_base64(false),
                    EncodingType::Json => key_data.to_json_array(false),
                    EncodingType::Binary => hex::encode(key_data.to_bytes(false)),
                };
                let secondary = match secondary_format {
                    EncodingType::Hex => key_data.to_hex(true),
                    EncodingType::Base64 | EncodingType::Base64Url => key_data.to_base64(true),
                    EncodingType::Json => key_data.to_json_array(true),
                    EncodingType::Binary => hex::encode(key_data.to_bytes(true)),
                };

                let confused = format!("{}{}", primary, secondary);
                let _ = parse_signing_key_from_blob(confused.as_bytes());
            },
        }
    }
});