//! Fuzz target for replay signature hex decoding.
//!
//! Tests replay signature decoder against malformed hex input, length attacks,
//! case variations, invalid characters, and security boundary validation.
//! Critical security boundary for validating cryptographic signature input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

const ED25519_SIGNATURE_BYTES: usize = 64;

type ReplaySignature = [u8; ED25519_SIGNATURE_BYTES];

#[derive(Debug, Clone)]
pub enum LedgerError {
    SignatureInvalid { reason: String },
}

// Reimplemented functions for fuzzing
fn is_canonical_lower_hex(input: &str) -> bool {
    input.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
}

fn decode_replay_signature(signature: &str) -> Result<ReplaySignature, LedgerError> {
    // SECURITY: Cap signature hex length to prevent memory DoS attacks
    // Ed25519 signatures are 64 bytes = 128 hex chars. Allow up to 256 hex chars (128 raw bytes).
    if signature.len() > 256 {
        return Err(LedgerError::SignatureInvalid {
            reason: format!(
                "signature hex too long: {} chars (max 256)",
                signature.len()
            ),
        });
    }

    if signature.is_empty() {
        return Err(LedgerError::SignatureInvalid {
            reason: "signature cannot be empty".to_string(),
        });
    }

    if !is_canonical_lower_hex(signature) {
        return Err(LedgerError::SignatureInvalid {
            reason: "signature must use canonical lowercase hex".to_string(),
        });
    }

    if signature.len() == ED25519_SIGNATURE_BYTES * 2 {
        let mut signature_bytes = [0_u8; ED25519_SIGNATURE_BYTES];
        hex::decode_to_slice(signature, &mut signature_bytes).map_err(|e| {
            LedgerError::SignatureInvalid {
                reason: format!("invalid hex signature: {}", e),
            }
        })?;
        return Ok(signature_bytes);
    }

    let signature_bytes = hex::decode(signature).map_err(|e| LedgerError::SignatureInvalid {
        reason: format!("invalid hex signature: {}", e),
    })?;

    if signature_bytes.len() == ED25519_SIGNATURE_BYTES {
        let mut result = [0_u8; ED25519_SIGNATURE_BYTES];
        result.copy_from_slice(&signature_bytes);
        Ok(result)
    } else {
        Err(LedgerError::SignatureInvalid {
            reason: format!(
                "signature wrong length: {} bytes (expected {})",
                signature_bytes.len(),
                ED25519_SIGNATURE_BYTES
            ),
        })
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: SignatureDecodingOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum SignatureDecodingOperation {
    DirectHex(HexInput),
    AttackVectors {
        attack_type: AttackVector,
        payload_size: u8,
    },
    EdgeCaseVariations {
        base_sig: HexInput,
        variations: Vec<HexVariation>,
    },
    SecurityBoundaryTests {
        boundary_type: BoundaryTest,
        test_value: String,
    },
    CaseSensitivityTests {
        hex_string: String,
        case_transforms: Vec<CaseTransform>,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum AttackVector {
    BufferOverflow,
    MemoryExhaustion,
    InvalidCharacters,
    NullByteInjection,
    UnicodeConfusion,
    RegexDoS,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryTest {
    ExactLength,
    OffByOne,
    MaxLength,
    DoubleLength,
    ZeroLength,
    MegabyteLength,
}

#[derive(Debug, Clone, Arbitrary)]
enum CaseTransform {
    AllUppercase,
    AllLowercase,
    MixedCase,
    RandomCase,
}

#[derive(Debug, Clone, Arbitrary)]
struct HexInput {
    content: String,
    length_modifier: LengthModifier,
    character_set: CharacterSet,
}

#[derive(Debug, Clone, Arbitrary)]
enum LengthModifier {
    Exact,
    Short(u8),
    Long(u8),
    Double,
    Random(u8),
}

#[derive(Debug, Clone, Arbitrary)]
enum CharacterSet {
    ValidHex,
    InvalidChars,
    Mixed,
    Unicode,
    Control,
    Whitespace,
}

#[derive(Debug, Clone, Arbitrary)]
enum HexVariation {
    AddInvalidChar(char),
    ChangeCase,
    TruncateAt(u8),
    PadWithZeros,
    AddPrefix(String),
    AddSuffix(String),
    DuplicateSegment,
    RemoveRandomChar,
}

impl HexInput {
    fn generate(&self, base_length: usize) -> String {
        let target_length = match &self.length_modifier {
            LengthModifier::Exact => base_length,
            LengthModifier::Short(n) => base_length.saturating_sub(*n as usize),
            LengthModifier::Long(n) => base_length + (*n as usize),
            LengthModifier::Double => base_length * 2,
            LengthModifier::Random(n) => (*n as usize) % 300, // Cap at 300 chars
        };

        let base_chars = match &self.character_set {
            CharacterSet::ValidHex => "0123456789abcdef",
            CharacterSet::InvalidChars => "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ!@#$%",
            CharacterSet::Mixed => "0123456789abcdefGHIJKLMN!@#",
            CharacterSet::Unicode => "0123456789abcdef🔥💥⚠️αβγδ",
            CharacterSet::Control => "0123456789abcdef\0\x01\x02\x03\x7F",
            CharacterSet::Whitespace => "0123456789abcdef \t\n\r\x0B\x0C",
        };

        let mut result = self.content.clone();

        // Ensure we have content to work with
        if result.is_empty() && target_length > 0 {
            result = base_chars.chars().cycle()
                .take(target_length)
                .collect();
        }

        // Adjust length
        if result.len() > target_length {
            result.truncate(target_length);
        } else if result.len() < target_length {
            let padding: String = base_chars.chars().cycle()
                .take(target_length - result.len())
                .collect();
            result.push_str(&padding);
        }

        result
    }
}

impl HexVariation {
    fn apply(&self, input: &str) -> String {
        match self {
            HexVariation::AddInvalidChar(c) => format!("{}{}", input, c),
            HexVariation::ChangeCase => {
                input.chars().enumerate().map(|(i, c)| {
                    if i % 2 == 0 { c.to_uppercase().collect::<String>() }
                    else { c.to_lowercase().collect::<String>() }
                }).collect()
            },
            HexVariation::TruncateAt(n) => {
                let len = (*n as usize).min(input.len());
                input[..len].to_string()
            },
            HexVariation::PadWithZeros => format!("00{}", input),
            HexVariation::AddPrefix(prefix) => format!("{}{}", prefix, input),
            HexVariation::AddSuffix(suffix) => format!("{}{}", input, suffix),
            HexVariation::DuplicateSegment => {
                if input.len() >= 8 {
                    let segment = &input[..4];
                    format!("{}{}{}", segment, segment, &input[4..])
                } else {
                    input.to_string()
                }
            },
            HexVariation::RemoveRandomChar => {
                if !input.is_empty() {
                    let mut chars: Vec<char> = input.chars().collect();
                    if chars.len() > 1 {
                        chars.remove(0);
                    }
                    chars.into_iter().collect()
                } else {
                    input.to_string()
                }
            },
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            SignatureDecodingOperation::DirectHex(hex_input) => {
                let signature = hex_input.generate(128); // ED25519 signature hex length
                // Test deterministic signature decoding
                let result1 = decode_replay_signature(&signature);
                let result2 = decode_replay_signature(&signature);
                assert_eq!(result1.is_ok(), result2.is_ok(), "Signature decoding should be deterministic");
            },
            SignatureDecodingOperation::AttackVectors { attack_type, payload_size } => {
                let size = (payload_size as usize).min(500); // Cap size
                let attack_payload = match attack_type {
                    AttackVector::BufferOverflow => "A".repeat(size * 10),
                    AttackVector::MemoryExhaustion => "0".repeat(size * 100),
                    AttackVector::InvalidCharacters => "GGGGGGGG".repeat(size),
                    AttackVector::NullByteInjection => format!("abcd\0\0\0{}", "ef".repeat(size)),
                    AttackVector::UnicodeConfusion => format!("{}🔥💥", "ab".repeat(size)),
                    AttackVector::RegexDoS => "(".repeat(size) + &")".repeat(size),
                };
                let _ = decode_replay_signature(&attack_payload);
            },
            SignatureDecodingOperation::EdgeCaseVariations { base_sig, variations } => {
                let mut test_sig = base_sig.generate(128);
                for variation in &variations {
                    test_sig = variation.apply(&test_sig);
                }
                let _ = decode_replay_signature(&test_sig);
            },
            SignatureDecodingOperation::SecurityBoundaryTests { boundary_type, test_value } => {
                let boundary_input = match boundary_type {
                    BoundaryTest::ExactLength => "a".repeat(128),
                    BoundaryTest::OffByOne => "a".repeat(127),
                    BoundaryTest::MaxLength => "a".repeat(256),
                    BoundaryTest::DoubleLength => "a".repeat(256),
                    BoundaryTest::ZeroLength => String::new(),
                    BoundaryTest::MegabyteLength => "a".repeat(1024 * 1024),
                };
                let combined = format!("{}{}", boundary_input, test_value);
                let _ = decode_replay_signature(&combined);
            },
            SignatureDecodingOperation::CaseSensitivityTests { hex_string, case_transforms } => {
                let mut test_string = hex_string;
                for transform in &case_transforms {
                    test_string = match transform {
                        CaseTransform::AllUppercase => test_string.to_uppercase(),
                        CaseTransform::AllLowercase => test_string.to_lowercase(),
                        CaseTransform::MixedCase => {
                            test_string.chars().enumerate().map(|(i, c)| {
                                if i % 2 == 0 { c.to_uppercase().collect::<String>() }
                                else { c.to_lowercase().collect::<String>() }
                            }).collect()
                        },
                        CaseTransform::RandomCase => {
                            test_string.chars().enumerate().map(|(i, c)| {
                                if i % 3 == 0 { c.to_uppercase().collect::<String>() }
                                else { c.to_lowercase().collect::<String>() }
                            }).collect()
                        },
                    };
                }
                let _ = decode_replay_signature(&test_string);
            },
        }
    }
});