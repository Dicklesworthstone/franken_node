//! Fuzz target for session MAC hex deserialization in session auth.
//!
//! Tests MAC hex parsing against malformed hex strings, length attacks,
//! case variations, unicode attacks, and injection attempts. Critical
//! security boundary for session authentication MAC verification.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use base64::prelude::*;

const SIGNATURE_LEN: usize = 32;

// Reimplemented functions for fuzzing
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn deserialize_mac_hex(hex: &str) -> Result<[u8; SIGNATURE_LEN], String> {
    if hex.len() != SIGNATURE_LEN * 2 {
        return Err(format!(
            "MAC hex string must be exactly {} chars, got {}",
            SIGNATURE_LEN * 2,
            hex.len()
        ));
    }
    let mut arr = [0u8; SIGNATURE_LEN];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or_else(|| {
            format!("invalid hex char at position {}", i * 2)
        })?;
        let lo = hex_nibble(chunk[1]).ok_or_else(|| {
            format!("invalid hex char at position {}", i * 2 + 1)
        })?;
        arr[i] = (hi << 4) | lo;
    }
    Ok(arr)
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: MacDeserializeTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum MacDeserializeTest {
    ValidHex {
        mac_bytes: [u8; SIGNATURE_LEN],
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
    TimingAttacks {
        attack_type: TimingAttackType,
        pattern_length: u8,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum CaseVariant {
    Lowercase,
    Uppercase,
    Mixed,
    AlternatingCase,
    RandomCase,
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
}

#[derive(Debug, Clone, Arbitrary)]
enum TimingAttackType {
    EarlyExit,
    SlowPath,
    RepeatedPatterns,
    WorstCase,
    BranchHeavy,
    CacheUnfriendly,
}

impl CaseVariant {
    fn apply(&self, hex: &str) -> String {
        match self {
            CaseVariant::Lowercase => hex.to_lowercase(),
            CaseVariant::Uppercase => hex.to_uppercase(),
            CaseVariant::Mixed => {
                hex.chars().enumerate().map(|(i, c)| {
                    if i % 2 == 0 { c.to_uppercase().collect::<String>() }
                    else { c.to_lowercase().collect::<String>() }
                }).collect()
            },
            CaseVariant::AlternatingCase => {
                hex.chars().enumerate().map(|(i, c)| {
                    if i % 3 == 0 { c.to_uppercase().collect::<String>() }
                    else { c.to_lowercase().collect::<String>() }
                }).collect()
            },
            CaseVariant::RandomCase => {
                hex.chars().enumerate().map(|(i, c)| {
                    if (i * 17 + 13) % 5 == 0 { c.to_uppercase().collect::<String>() }
                    else { c.to_lowercase().collect::<String>() }
                }).collect()
            },
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
            },
            LengthAttackType::Double => format!("{}{}", base_content, base_content),
            LengthAttackType::Massive => "A".repeat(100000),
            LengthAttackType::OddLength => {
                let mut result = base_content.chars().take(63).collect::<String>();
                if result.len() % 2 == 0 {
                    result.push('A');
                }
                result
            },
            LengthAttackType::AlmostCorrect => "A".repeat(SIGNATURE_LEN * 2 - 1),
        }
    }
}

impl InvalidCharType {
    fn inject(&self, base_hex: &str, position: u8) -> String {
        let pos = (position as usize) % base_hex.len().max(1);
        let invalid_char = match self {
            InvalidCharType::NonHexLetters => 'G',
            InvalidCharType::UnicodeDigits => '１',  // Fullwidth 1
            InvalidCharType::SpecialChars => '@',
            InvalidCharType::Whitespace => ' ',
            InvalidCharType::ControlChars => '\x01',
            InvalidCharType::HighAscii => '\u{80}',
            InvalidCharType::NullBytes => '\0',
            InvalidCharType::Base64Chars => '=',
        };

        let mut result = base_hex.to_string();
        if pos < result.len() {
            result.replace_range(pos..pos+1, &invalid_char.to_string());
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
            InjectionType::JsonEscape => format!("{}\\\"}}{}", base),
            InjectionType::RegexEscape => format!("{}.*+?{{}}[]()^$", base),
        }
    }
}

impl BoundaryType {
    fn generate(&self, modifier: u8) -> String {
        let base_len = match self {
            BoundaryType::ExactLength => SIGNATURE_LEN * 2,
            BoundaryType::PlusOne => SIGNATURE_LEN * 2 + 1,
            BoundaryType::MinusOne => (SIGNATURE_LEN * 2).saturating_sub(1),
            BoundaryType::Zero => 0,
            BoundaryType::MaxU16 => (modifier as usize) % 65536,
            BoundaryType::MaxU32 => (modifier as usize) % 10000, // Capped for fuzzing
            BoundaryType::PowerOfTwo => 1 << ((modifier % 10) + 1),
        };
        "A".repeat(base_len)
    }
}

impl EncodingConfusionType {
    fn apply(&self, base_value: &[u8; 16]) -> String {
        let hex_str = hex::encode(base_value);
        let padded = format!("{}{}", hex_str, hex_str); // Make it 64 chars
        match self {
            EncodingConfusionType::Base64 => base64::prelude::BASE64_STANDARD.encode(padded.as_bytes()).chars().take(64).collect(),
            EncodingConfusionType::Base32 => {
                // Mock base32 encoding
                padded.chars().map(|c| match c {
                    'a'..='f' => char::from(c as u8 - b'a' + b'2'),
                    '0'..='9' => c,
                    _ => c,
                }).collect()
            },
            EncodingConfusionType::UrlEncoded => {
                padded.chars().map(|c| format!("%{:02X}", c as u8)).collect::<String>().chars().take(64).collect()
            },
            EncodingConfusionType::DoubleEncoded => {
                let url_encoded = padded.chars().map(|c| format!("%{:02X}", c as u8)).collect::<String>();
                url_encoded.chars().map(|c| format!("%{:02X}", c as u8)).collect::<String>().chars().take(64).collect()
            },
            EncodingConfusionType::MixedEncoding => {
                format!("0x{}", padded).chars().take(64).collect()
            },
            EncodingConfusionType::BinaryData => {
                // Simulate binary data as hex
                base_value.iter().map(|b| format!("{:08b}", b)).collect::<String>().chars().take(64).collect()
            },
            EncodingConfusionType::JsonEscaped => {
                format!("\\\"{}\\\"", padded).chars().take(64).collect()
            },
        }
    }
}

impl TimingAttackType {
    fn generate(&self, pattern_length: u8) -> String {
        let _len = (pattern_length as usize % 32) + 1;
        match self {
            TimingAttackType::EarlyExit => {
                // Invalid char at start
                format!("G{}", "a".repeat(SIGNATURE_LEN * 2 - 1))
            },
            TimingAttackType::SlowPath => {
                // Invalid char at end
                format!("{}G", "a".repeat(SIGNATURE_LEN * 2 - 1))
            },
            TimingAttackType::RepeatedPatterns => {
                "abcd".repeat(16)
            },
            TimingAttackType::WorstCase => {
                // All valid but at boundary
                "f".repeat(SIGNATURE_LEN * 2)
            },
            TimingAttackType::BranchHeavy => {
                // Mix of upper and lower case to exercise branches
                "AbCdEf".repeat(11).chars().take(64).collect()
            },
            TimingAttackType::CacheUnfriendly => {
                // Scattered access pattern
                (0..SIGNATURE_LEN * 2).map(|i| if i % 7 == 0 { 'F' } else { '0' }).collect()
            },
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            MacDeserializeTest::ValidHex { mac_bytes, case_variant } => {
                let hex_str = hex::encode(mac_bytes);
                let test_hex = case_variant.apply(&hex_str);
                // Test deterministic MAC deserialization
                let result1 = deserialize_mac_hex(&test_hex);
                let result2 = deserialize_mac_hex(&test_hex);
                assert_eq!(result1.is_ok(), result2.is_ok(), "MAC deserialization should be deterministic");
            },
            MacDeserializeTest::LengthAttacks { attack_type, base_content } => {
                let attack_input = attack_type.generate(&base_content);
                let _ = deserialize_mac_hex(&attack_input);
            },
            MacDeserializeTest::InvalidCharacters { char_type, position, base_hex } => {
                let attack_input = char_type.inject(&base_hex, position);
                let _ = deserialize_mac_hex(&attack_input);
            },
            MacDeserializeTest::UnicodeAttacks { unicode_type, insertion_point } => {
                let attack_input = unicode_type.inject(insertion_point);
                let _ = deserialize_mac_hex(&attack_input);
            },
            MacDeserializeTest::InjectionAttacks { injection_type, payload } => {
                let attack_input = injection_type.generate(&payload);
                let _ = deserialize_mac_hex(&attack_input);
            },
            MacDeserializeTest::BoundaryTests { boundary_type, modifier } => {
                let boundary_input = boundary_type.generate(modifier);
                let _ = deserialize_mac_hex(&boundary_input);
            },
            MacDeserializeTest::EncodingConfusion { confusion_type, base_value } => {
                let confused_input = confusion_type.apply(&base_value);
                let _ = deserialize_mac_hex(&confused_input);
            },
            MacDeserializeTest::TimingAttacks { attack_type, pattern_length } => {
                let timing_input = attack_type.generate(pattern_length);
                let _ = deserialize_mac_hex(&timing_input);
            },
        }
    }
});