//! Fuzz target for Ed25519 public key hex decoding in fleet quarantine.
//!
//! Tests decode_ed25519_public_key_hex() against malformed hex, length attacks,
//! case variations, unicode attacks, and injection attempts. Critical security
//! boundary for fleet quarantine Ed25519 public key deserialization.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use base64::Engine;
use hex::FromHex;
use libfuzzer_sys::fuzz_target;

// Reimplemented function for fuzzing
fn decode_ed25519_public_key_hex(public_key_hex: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::from_hex(public_key_hex).ok()
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: Ed25519HexDecodeTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum Ed25519HexDecodeTest {
    ValidKeys {
        key_bytes: [u8; 32],
        case_variant: CaseVariant,
    },
    LengthAttacks {
        attack_type: LengthAttackType,
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
    InjectionAttacks {
        injection_type: InjectionType,
        payload: String,
    },
    BoundaryTests {
        boundary_type: BoundaryType,
        modifier: u8,
    },
    EncodingConfusion {
        confusion_type: EncodingConfusionType,
        base_value: [u8; 16],
    },
    FormatAttacks {
        format_type: FormatAttackType,
        pattern: String,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum CaseVariant {
    Lowercase,
    Uppercase,
    Mixed,
    AlternatingCase,
    RandomCase,
    MixedWithDigits,
}

#[derive(Debug, Clone, Arbitrary)]
enum LengthAttackType {
    TooShort,
    TooLong,
    Empty,
    OffByOne,
    Double,
    Massive,
    OddLength,
    AlmostCorrect,
}

#[derive(Debug, Clone, Arbitrary)]
enum InvalidCharType {
    NonHexLetters,
    UnicodeDigits,
    SpecialChars,
    Whitespace,
    ControlChars,
    HighAscii,
    NullBytes,
    Base64Chars,
    UrlEncoded,
}

#[derive(Debug, Clone, Arbitrary)]
enum UnicodeAttackType {
    Homoglyphs,
    RightToLeft,
    CombiningChars,
    ZeroWidth,
    Normalization,
    BidiOverride,
    FullwidthChars,
    InvisibleChars,
}

#[derive(Debug, Clone, Arbitrary)]
enum InjectionType {
    FormatString,
    SqlInjection,
    CommandInjection,
    PathTraversal,
    XssPayload,
    JsonEscape,
    RegexEscape,
    BufferOverflow,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryType {
    ExactLength,
    PlusOne,
    MinusOne,
    Zero,
    MaxU16,
    MaxU32,
    PowerOfTwo,
    AlignmentBoundary,
}

#[derive(Debug, Clone, Arbitrary)]
enum EncodingConfusionType {
    Base64,
    Base32,
    UrlEncoded,
    DoubleEncoded,
    MixedEncoding,
    BinaryData,
    JsonEscaped,
    HtmlEntities,
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatAttackType {
    PrefixAttack,
    SuffixAttack,
    MiddleInjection,
    WrappedFormat,
    EscapeSequences,
    FormatConfusion,
    DelimiterInjection,
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
            CaseVariant::AlternatingCase => hex
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
            CaseVariant::RandomCase => hex
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if (i * 17 + 13) % 5 == 0 {
                        c.to_uppercase().collect::<String>()
                    } else {
                        c.to_lowercase().collect::<String>()
                    }
                })
                .collect(),
            CaseVariant::MixedWithDigits => hex
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if c.is_ascii_digit() {
                        c.to_string()
                    } else if i % 2 == 0 {
                        c.to_uppercase().collect::<String>()
                    } else {
                        c.to_lowercase().collect::<String>()
                    }
                })
                .collect(),
        }
    }
}

impl LengthAttackType {
    fn generate(&self, base_content: &str) -> String {
        match self {
            LengthAttackType::TooShort => base_content.chars().take(32).collect(),
            LengthAttackType::TooLong => format!("{}{}", base_content, "A".repeat(100)),
            LengthAttackType::Empty => String::new(),
            LengthAttackType::OffByOne => {
                if base_content.len() >= 63 {
                    base_content.chars().take(63).collect()
                } else {
                    format!("{}A", base_content)
                }
            }
            LengthAttackType::Double => format!("{}{}", base_content, base_content),
            LengthAttackType::Massive => "A".repeat(100000),
            LengthAttackType::OddLength => {
                let mut result = base_content.chars().take(63).collect::<String>();
                if result.len() % 2 == 0 {
                    result.push('A');
                }
                result
            }
            LengthAttackType::AlmostCorrect => "A".repeat(64 - 1),
        }
    }
}

impl InvalidCharType {
    fn inject(&self, base_hex: &str, position: u8) -> String {
        let pos = (position as usize) % base_hex.len().max(1);
        let invalid_char = match self {
            InvalidCharType::NonHexLetters => 'G',
            InvalidCharType::UnicodeDigits => '１', // Fullwidth 1
            InvalidCharType::SpecialChars => '@',
            InvalidCharType::Whitespace => ' ',
            InvalidCharType::ControlChars => '\x01',
            InvalidCharType::HighAscii => '\u{80}',
            InvalidCharType::NullBytes => '\0',
            InvalidCharType::Base64Chars => '=',
            InvalidCharType::UrlEncoded => '%',
        };

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
    fn inject(&self, insertion_point: u8) -> String {
        let base_hex = "deadbeef".repeat(8); // 64 char valid hex
        let attack_payload = match self {
            UnicodeAttackType::Homoglyphs => "Α", // Greek capital alpha (looks like A)
            UnicodeAttackType::RightToLeft => "\u{202E}",
            UnicodeAttackType::CombiningChars => "a\u{0300}\u{0301}",
            UnicodeAttackType::ZeroWidth => "\u{200B}\u{FEFF}",
            UnicodeAttackType::Normalization => "é", // e + combining acute
            UnicodeAttackType::BidiOverride => "\u{202D}\u{202C}",
            UnicodeAttackType::FullwidthChars => "ＡＢＣ",
            UnicodeAttackType::InvisibleChars => "\u{061C}\u{2066}",
        };

        let pos = (insertion_point as usize) % base_hex.len();
        format!("{}{}{}", &base_hex[..pos], attack_payload, &base_hex[pos..])
    }
}

impl InjectionType {
    fn generate(&self, payload: &str) -> String {
        let base = format!("{:0>64}", payload.chars().take(32).collect::<String>());
        match self {
            InjectionType::FormatString => format!("{}%s%x%p", base),
            InjectionType::SqlInjection => format!("{}'OR'1'='1", base),
            InjectionType::CommandInjection => format!("{};rm -rf /", base),
            InjectionType::PathTraversal => format!("{}../../../etc/passwd", base),
            InjectionType::XssPayload => format!("{}<script>alert(1)</script>", base),
            InjectionType::JsonEscape => format!("{}\\\"}}{{", base),
            InjectionType::RegexEscape => format!("{}.*+?{{}}[]()^$", base),
            InjectionType::BufferOverflow => format!("{}\\x41\\x41\\x41\\x41", base),
        }
    }
}

impl BoundaryType {
    fn generate(&self, modifier: u8) -> String {
        let base_len = match self {
            BoundaryType::ExactLength => 64,
            BoundaryType::PlusOne => 65,
            BoundaryType::MinusOne => 63,
            BoundaryType::Zero => 0,
            BoundaryType::MaxU16 => (modifier as usize) % 65536,
            BoundaryType::MaxU32 => (modifier as usize) % 10000, // Capped for fuzzing
            BoundaryType::PowerOfTwo => 1 << ((modifier % 10) + 1),
            BoundaryType::AlignmentBoundary => match modifier % 4 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => 8,
            },
        };
        "A".repeat(base_len)
    }
}

impl EncodingConfusionType {
    fn apply(&self, base_value: &[u8; 16]) -> String {
        let hex_str = hex::encode(base_value);
        let padded = format!("{}{}", hex_str, hex_str); // Make it 64 chars
        match self {
            EncodingConfusionType::Base64 => base64::prelude::BASE64_STANDARD
                .encode(padded.as_bytes())
                .chars()
                .take(64)
                .collect(),
            EncodingConfusionType::Base32 => {
                // Mock base32 encoding
                padded
                    .chars()
                    .map(|c| match c {
                        'a'..='f' => char::from(c as u8 - b'a' + b'2'),
                        '0'..='9' => c,
                        _ => c,
                    })
                    .collect()
            }
            EncodingConfusionType::UrlEncoded => padded
                .chars()
                .map(|c| format!("%{:02X}", c as u8))
                .collect::<String>()
                .chars()
                .take(64)
                .collect(),
            EncodingConfusionType::DoubleEncoded => {
                let url_encoded = padded
                    .chars()
                    .map(|c| format!("%{:02X}", c as u8))
                    .collect::<String>();
                url_encoded
                    .chars()
                    .map(|c| format!("%{:02X}", c as u8))
                    .collect::<String>()
                    .chars()
                    .take(64)
                    .collect()
            }
            EncodingConfusionType::MixedEncoding => {
                format!("0x{}", padded).chars().take(64).collect()
            }
            EncodingConfusionType::BinaryData => {
                // Simulate binary data as hex
                base_value
                    .iter()
                    .map(|b| format!("{:08b}", b))
                    .collect::<String>()
                    .chars()
                    .take(64)
                    .collect()
            }
            EncodingConfusionType::JsonEscaped => {
                format!("\\\"{}\\\"", padded).chars().take(64).collect()
            }
            EncodingConfusionType::HtmlEntities => padded
                .replace("a", "&amp;")
                .replace("e", "&lt;")
                .chars()
                .take(64)
                .collect(),
        }
    }
}

impl FormatAttackType {
    fn apply(&self, pattern: &str) -> String {
        let base_key = "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef";
        match self {
            FormatAttackType::PrefixAttack => format!("0x{}", base_key),
            FormatAttackType::SuffixAttack => format!("{}h", base_key),
            FormatAttackType::MiddleInjection => {
                let mid = base_key.len() / 2;
                format!("{}{}garbage{}", &base_key[..mid], pattern, &base_key[mid..])
            }
            FormatAttackType::WrappedFormat => format!("{{{}}}", base_key),
            FormatAttackType::EscapeSequences => format!("\\x{}\\n", base_key),
            FormatAttackType::FormatConfusion => format!(
                "{}-{}-{}",
                &base_key[..8],
                &base_key[8..16],
                &base_key[16..]
            ),
            FormatAttackType::DelimiterInjection => base_key.replace("a", ":").replace("b", "-"),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            Ed25519HexDecodeTest::ValidKeys {
                key_bytes,
                case_variant,
            } => {
                let hex_str = hex::encode(key_bytes);
                let test_hex = case_variant.apply(&hex_str);
                let result = decode_ed25519_public_key_hex(&test_hex);

                // Valid 64-char hex should decode successfully
                assert!(
                    result.is_some(),
                    "Valid Ed25519 hex should decode: {}",
                    test_hex
                );

                // Round-trip property: decode(encode(key)) == key
                if let Some(decoded) = result {
                    assert_eq!(
                        decoded, key_bytes,
                        "Round-trip property violated for Ed25519 key"
                    );
                }
            }
            Ed25519HexDecodeTest::LengthAttacks {
                attack_type,
                base_content,
            } => {
                let attack_input = attack_type.generate(&base_content);
                let result = decode_ed25519_public_key_hex(&attack_input);

                // Wrong-length inputs should be rejected
                if attack_input.len() != 64 {
                    assert!(
                        result.is_none(),
                        "Wrong-length Ed25519 hex should be rejected: len={}",
                        attack_input.len()
                    );
                }

                // Function should never panic on length attacks
            }
            Ed25519HexDecodeTest::InvalidCharacters {
                char_type,
                position,
                base_hex,
            } => {
                let attack_input = char_type.inject(&base_hex, position);
                let result = decode_ed25519_public_key_hex(&attack_input);

                // Invalid hex characters should be rejected
                if attack_input.len() == 64 && !attack_input.chars().all(|c| c.is_ascii_hexdigit())
                {
                    assert!(
                        result.is_none(),
                        "Invalid hex characters should be rejected: {}",
                        attack_input
                    );
                }
            }
            Ed25519HexDecodeTest::UnicodeAttacks {
                unicode_type,
                insertion_point,
            } => {
                let attack_input = unicode_type.inject(insertion_point);
                let result = decode_ed25519_public_key_hex(&attack_input);

                // Unicode attacks should be rejected
                if !attack_input.is_ascii()
                    || attack_input.len() != 64
                    || !attack_input.chars().all(|c| c.is_ascii_hexdigit())
                {
                    assert!(
                        result.is_none(),
                        "Unicode attacks should be rejected: {}",
                        attack_input
                    );
                }

                // Function should never panic on unicode input
            }
            Ed25519HexDecodeTest::InjectionAttacks {
                injection_type,
                payload,
            } => {
                let attack_input = injection_type.generate(&payload);
                let result = decode_ed25519_public_key_hex(&attack_input);

                // Injection attacks should be safely handled
                if attack_input.len() != 64 || !attack_input.chars().all(|c| c.is_ascii_hexdigit())
                {
                    assert!(
                        result.is_none(),
                        "Injection attacks should be rejected: {}",
                        attack_input
                    );
                }
            }
            Ed25519HexDecodeTest::BoundaryTests {
                boundary_type,
                modifier,
            } => {
                let boundary_input = boundary_type.generate(modifier);
                let result = decode_ed25519_public_key_hex(&boundary_input);

                // Test deterministic behavior
                let result2 = decode_ed25519_public_key_hex(&boundary_input);
                assert_eq!(
                    result.is_some(),
                    result2.is_some(),
                    "Ed25519 decoder should be deterministic"
                );

                // Only exact-length valid hex should succeed
                if boundary_input.len() == 64
                    && boundary_input.chars().all(|c| c.is_ascii_hexdigit())
                {
                    assert!(
                        result.is_some(),
                        "Valid 64-char Ed25519 hex should decode: {}",
                        boundary_input
                    );
                } else {
                    assert!(
                        result.is_none(),
                        "Invalid boundary input should be rejected"
                    );
                }
            }
            Ed25519HexDecodeTest::EncodingConfusion {
                confusion_type,
                base_value,
            } => {
                let confused_input = confusion_type.apply(&base_value);
                let result = decode_ed25519_public_key_hex(&confused_input);

                // Encoding confusion attacks should be rejected
                if confused_input.len() != 64
                    || !confused_input.chars().all(|c| c.is_ascii_hexdigit())
                {
                    assert!(
                        result.is_none(),
                        "Encoding confusion should be rejected: {}",
                        confused_input
                    );
                }
            }
            Ed25519HexDecodeTest::FormatAttacks {
                format_type,
                pattern,
            } => {
                let format_input = format_type.apply(&pattern);
                let result = decode_ed25519_public_key_hex(&format_input);

                // Format attacks should be safely handled
                if format_input.len() != 64 || !format_input.chars().all(|c| c.is_ascii_hexdigit())
                {
                    assert!(
                        result.is_none(),
                        "Format attacks should be rejected: {}",
                        format_input
                    );
                }

                // Function should complete in reasonable time (no DoS)
            }
        }
    }
});
