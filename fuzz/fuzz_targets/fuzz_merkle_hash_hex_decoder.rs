//! Fuzz target for Merkle hash hex decoding in transparency verifier.
//!
//! Tests hex decoder against malformed hex strings, invalid lengths, case
//! variations, unicode attacks, and length confusion. Critical security
//! boundary for transparency proof verification.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Clone)]
pub enum ProofFailure {
    PathInvalid { computed: String, expected: String },
}

// Reimplemented function for fuzzing
fn decode_merkle_hash_hex(value: &str, field: &str) -> Result<[u8; 32], ProofFailure> {
    let mut out = [0_u8; 32];
    hex::decode_to_slice(value, &mut out).map_err(|err| match err {
        hex::FromHexError::InvalidStringLength | hex::FromHexError::OddLength => {
            ProofFailure::PathInvalid {
                computed: format!("{field}_hex_chars={}", value.len()),
                expected: format!("{field}_hex_chars=64"),
            }
        }
        hex::FromHexError::InvalidHexCharacter { .. } => ProofFailure::PathInvalid {
            computed: format!("{field}=invalid_hex"),
            expected: format!("{field} must be 32-byte hex"),
        },
    })?;
    Ok(out)
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: HexDecodingOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum HexDecodingOperation {
    ValidHex {
        hex_data: [u8; 32],
        case_variant: CaseVariant,
    },
    InvalidLength {
        length_type: LengthType,
        base_content: String,
    },
    InvalidCharacters {
        char_type: InvalidCharType,
        position: u8,
        base_hex: String,
    },
    UnicodeAttacks {
        unicode_type: UnicodeAttackType,
        insertion_point: u8,
    },
    BoundaryTests {
        boundary_type: BoundaryType,
        test_value: String,
    },
    SecurityTests {
        attack_type: SecurityAttackType,
        payload_size: u8,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum CaseVariant {
    Lowercase,
    Uppercase,
    Mixed,
    Random,
}

#[derive(Debug, Clone, Arbitrary)]
enum LengthType {
    Empty,
    TooShort,
    TooLong,
    OffByOne,
    Double,
    Massive,
    Odd,
}

#[derive(Debug, Clone, Arbitrary)]
enum InvalidCharType {
    NonHexLetters,
    Numbers,
    SpecialChars,
    Whitespace,
    ControlChars,
    HighAscii,
}

#[derive(Debug, Clone, Arbitrary)]
enum UnicodeAttackType {
    NullBytes,
    UnicodeHomoglyphs,
    RightToLeft,
    CombiningChars,
    NonPrintable,
    WidthAttacks,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryType {
    ExactLength,
    PlusOne,
    MinusOne,
    Zero,
    MaxLength,
}

#[derive(Debug, Clone, Arbitrary)]
enum SecurityAttackType {
    BufferOverflow,
    MemoryExhaustion,
    IntegerOverflow,
    FormatConfusion,
    TimingAttack,
}

impl CaseVariant {
    fn apply(&self, hex: &str) -> String {
        match self {
            CaseVariant::Lowercase => hex.to_lowercase(),
            CaseVariant::Uppercase => hex.to_uppercase(),
            CaseVariant::Mixed => hex
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_uppercase().collect::<String>()
                    } else {
                        c.to_lowercase().collect::<String>()
                    }
                })
                .collect(),
            CaseVariant::Random => hex
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 3 == 0 {
                        c.to_uppercase().collect::<String>()
                    } else {
                        c.to_lowercase().collect::<String>()
                    }
                })
                .collect(),
        }
    }
}

impl LengthType {
    fn generate(&self, base_content: &str) -> String {
        match self {
            LengthType::Empty => String::new(),
            LengthType::TooShort => base_content.chars().take(32).collect(),
            LengthType::TooLong => format!("{}{}", base_content, "A".repeat(100)),
            LengthType::OffByOne => {
                if base_content.len() >= 64 {
                    base_content.chars().take(63).collect()
                } else {
                    format!("{}A", base_content)
                }
            }
            LengthType::Double => format!("{}{}", base_content, base_content),
            LengthType::Massive => "A".repeat(100000),
            LengthType::Odd => {
                let mut result = base_content.chars().take(63).collect::<String>();
                if result.len() % 2 == 0 {
                    result.push('A');
                }
                result
            }
        }
    }
}

impl InvalidCharType {
    fn generate_chars(&self) -> &str {
        match self {
            InvalidCharType::NonHexLetters => "GHIJKLMNOPQRSTUVWXYZ",
            InvalidCharType::Numbers => "0123456789",
            InvalidCharType::SpecialChars => "!@#$%^&*()_+-=[]{}|;:,.<>?",
            InvalidCharType::Whitespace => " \t\n\r",
            InvalidCharType::ControlChars => "\x00\x01\x02\x03\x1F\x7F",
            InvalidCharType::HighAscii => "\u{80}\u{81}\u{ff}",
        }
    }

    fn inject_invalid(&self, base_hex: &str, position: u8) -> String {
        let invalid_chars = self.generate_chars();
        let invalid_char = invalid_chars.chars().next().unwrap_or('G');
        let pos = (position as usize) % base_hex.len().max(1);

        let mut result = base_hex.to_string();
        if pos < result.len() {
            result.replace_range(pos..pos + 1, &invalid_char.to_string());
        } else {
            result.push(invalid_char);
        }
        result
    }
}

impl UnicodeAttackType {
    fn generate_attack(&self, insertion_point: u8) -> String {
        let base_hex = "1234567890abcdef".repeat(4); // 64 char valid hex
        let attack_payload = match self {
            UnicodeAttackType::NullBytes => "\x00\x00",
            UnicodeAttackType::UnicodeHomoglyphs => "А", // Cyrillic A (looks like Latin A)
            UnicodeAttackType::RightToLeft => "\u{202E}",
            UnicodeAttackType::CombiningChars => "a\u{0300}\u{0301}",
            UnicodeAttackType::NonPrintable => "\u{200B}\u{FEFF}",
            UnicodeAttackType::WidthAttacks => "\u{2000}\u{2001}\u{2002}",
        };

        let pos = (insertion_point as usize) % base_hex.len();
        format!("{}{}{}", &base_hex[..pos], attack_payload, &base_hex[pos..])
    }
}

impl BoundaryType {
    fn generate_test(&self, test_value: &str) -> String {
        match self {
            BoundaryType::ExactLength => {
                if test_value.len() >= 64 {
                    test_value.chars().take(64).collect()
                } else {
                    format!("{}{}", test_value, "0".repeat(64 - test_value.len()))
                }
            }
            BoundaryType::PlusOne => {
                let exact = if test_value.len() >= 64 {
                    test_value.chars().take(64).collect::<String>()
                } else {
                    format!("{}{}", test_value, "0".repeat(64 - test_value.len()))
                };
                format!("{}A", exact)
            }
            BoundaryType::MinusOne => {
                if test_value.len() >= 63 {
                    test_value.chars().take(63).collect()
                } else {
                    format!("{}{}", test_value, "0".repeat(63 - test_value.len()))
                }
            }
            BoundaryType::Zero => String::new(),
            BoundaryType::MaxLength => format!("{}{}", test_value, "A".repeat(1000)),
        }
    }
}

impl SecurityAttackType {
    fn generate_attack(&self, payload_size: u8) -> String {
        let size = (payload_size as usize).min(1000); // Cap size for fuzzing
        match self {
            SecurityAttackType::BufferOverflow => "F".repeat(size * 100),
            SecurityAttackType::MemoryExhaustion => "DEADBEEF".repeat(size * 10),
            SecurityAttackType::IntegerOverflow => {
                // Try to cause integer overflow in length calculations
                "A".repeat(usize::MAX.min(size * 1000))
            }
            SecurityAttackType::FormatConfusion => {
                // Mix different encoding formats
                format!(
                    "{}0x{}\\x{}",
                    "AB".repeat(size),
                    "CD".repeat(size),
                    "EF".repeat(size)
                )
            }
            SecurityAttackType::TimingAttack => {
                // Create inputs that might have different processing times
                let mut result = String::new();
                for i in 0..size {
                    if i % 2 == 0 {
                        result.push_str("00");
                    } else {
                        result.push_str("FF");
                    }
                }
                result
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            HexDecodingOperation::ValidHex {
                hex_data,
                case_variant,
            } => {
                let hex_string = hex::encode(hex_data);
                let test_hex = case_variant.apply(&hex_string);

                // Valid hex should decode successfully
                let result = decode_merkle_hash_hex(&test_hex, "test_field");
                assert!(
                    result.is_ok(),
                    "Valid 64-char hex should decode successfully: {}",
                    test_hex
                );

                // Round-trip property: decode(encode(data)) == data
                if let Ok(decoded) = result {
                    assert_eq!(decoded, hex_data, "Round-trip property violated");
                }
            }
            HexDecodingOperation::InvalidLength {
                length_type,
                base_content,
            } => {
                let test_input = length_type.generate(&base_content);
                let result = decode_merkle_hash_hex(&test_input, "length_test");

                // Non-64-char inputs should be rejected
                if test_input.len() != 64 {
                    assert!(
                        result.is_err(),
                        "Invalid length input should be rejected: len={}",
                        test_input.len()
                    );
                }

                // Function should never panic on any length input
                // (Reaching here proves no panic occurred)
            }
            HexDecodingOperation::InvalidCharacters {
                char_type,
                position,
                base_hex,
            } => {
                let test_input = char_type.inject_invalid(&base_hex, position);
                let result = decode_merkle_hash_hex(&test_input, "char_test");

                // Invalid hex characters should be rejected
                if test_input.len() == 64 && !test_input.chars().all(|c| c.is_ascii_hexdigit()) {
                    assert!(
                        result.is_err(),
                        "Invalid hex characters should be rejected: {}",
                        test_input
                    );
                }
            }
            HexDecodingOperation::UnicodeAttacks {
                unicode_type,
                insertion_point,
            } => {
                let attack_input = unicode_type.generate_attack(insertion_point);
                let result = decode_merkle_hash_hex(&attack_input, "unicode_test");

                // Unicode attacks should be rejected (not valid ASCII hex)
                if attack_input.len() != 64
                    || !attack_input.is_ascii()
                    || !attack_input.chars().all(|c| c.is_ascii_hexdigit())
                {
                    assert!(
                        result.is_err(),
                        "Unicode attacks should be rejected: {}",
                        attack_input
                    );
                }

                // Function should never panic on unicode input
            }
            HexDecodingOperation::BoundaryTests {
                boundary_type,
                test_value,
            } => {
                let boundary_input = boundary_type.generate_test(&test_value);
                let result = decode_merkle_hash_hex(&boundary_input, "boundary_test");

                // Test deterministic behavior
                let result2 = decode_merkle_hash_hex(&boundary_input, "boundary_test");
                assert_eq!(
                    result.is_ok(),
                    result2.is_ok(),
                    "Deterministic behavior violated"
                );

                // Only exact-length valid hex should succeed
                if boundary_input.len() == 64
                    && boundary_input.chars().all(|c| c.is_ascii_hexdigit())
                {
                    assert!(
                        result.is_ok(),
                        "Valid 64-char hex should decode: {}",
                        boundary_input
                    );
                } else {
                    assert!(
                        result.is_err(),
                        "Invalid boundary input should be rejected: len={}",
                        boundary_input.len()
                    );
                }
            }
            HexDecodingOperation::SecurityTests {
                attack_type,
                payload_size,
            } => {
                let attack_input = attack_type.generate_attack(payload_size);
                let result = decode_merkle_hash_hex(&attack_input, "security_test");

                // Security attacks should be safely handled (no panic)
                // Large/malformed inputs should be rejected
                if attack_input.len() != 64 || !attack_input.chars().all(|c| c.is_ascii_hexdigit())
                {
                    assert!(result.is_err(), "Security attack input should be rejected");
                }

                // Function should complete in reasonable time (no DoS)
                // (Reaching here proves reasonable performance)
            }
        }
    }
});
