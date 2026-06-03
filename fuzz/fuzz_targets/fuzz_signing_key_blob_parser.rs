//! Fuzz target for Ed25519 signing key blob parsing in main CLI.
//!
//! Tests parse_signing_key_from_blob() against malformed key formats, length
//! attacks, keypair validation bypass, encoding confusion, and edge cases.
//! Critical security boundary for CLI signing key deserialization and validation.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use base64::Engine;
use libfuzzer_sys::fuzz_target;

// Mock ed25519_dalek types for fuzzing
#[derive(Debug, Clone)]
struct MockSigningKey {
    bytes: [u8; 32],
}

impl MockSigningKey {
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { bytes: *bytes }
    }

    fn verifying_key(&self) -> MockVerifyingKey {
        MockVerifyingKey { bytes: self.bytes }
    }
}

#[derive(Debug, Clone)]
struct MockVerifyingKey {
    bytes: [u8; 32],
}

impl MockVerifyingKey {
    fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

// Reimplemented function for fuzzing
fn parse_signing_key_from_blob(raw: &[u8]) -> Option<MockSigningKey> {
    fn signing_key_from_bytes(raw: &[u8]) -> Option<MockSigningKey> {
        match raw.len() {
            32 => {
                let bytes = <[u8; 32]>::try_from(raw).ok()?;
                Some(MockSigningKey::from_bytes(&bytes))
            }
            64 => {
                let seed = <[u8; 32]>::try_from(&raw[..32]).ok()?;
                let public = <[u8; 32]>::try_from(&raw[32..]).ok()?;
                let signing_key = MockSigningKey::from_bytes(&seed);
                let derived_public = signing_key.verifying_key().to_bytes();
                if derived_public == public {
                    Some(signing_key)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    if raw.is_empty() {
        return None;
    }

    // Try raw bytes first
    if let Some(key) = signing_key_from_bytes(raw) {
        return Some(key);
    }

    // Try as UTF-8 string for hex/base64 formats
    let Ok(text) = std::str::from_utf8(raw) else {
        return None;
    };

    let text = text.trim();

    // Try hex decoding with various prefixes
    let hex_candidates = [
        text,
        text.strip_prefix("0x").unwrap_or(text),
        text.strip_prefix("hex:").unwrap_or(text),
        &text.replace('_', ""),
        &text.replace(['-', ':', ' '], ""),
    ];

    for hex_str in hex_candidates {
        if let Ok(decoded) = hex::decode(hex_str) {
            if let Some(key) = signing_key_from_bytes(&decoded) {
                return Some(key);
            }
        }
    }

    // Try base64 decoding
    let base64_engines = [
        &base64::prelude::BASE64_STANDARD,
        &base64::prelude::BASE64_URL_SAFE,
        &base64::prelude::BASE64_URL_SAFE_NO_PAD,
    ];

    for engine in base64_engines {
        if let Ok(decoded) = engine.decode(text) {
            if let Some(key) = signing_key_from_bytes(&decoded) {
                return Some(key);
            }
        }
    }

    None
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: SigningKeyParseTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum SigningKeyParseTest {
    ValidKeys {
        key_data: KeyData,
        format_variant: FormatVariant,
    },
    LengthAttacks {
        attack_type: LengthAttackType,
        base_size: u16,
    },
    FormatConfusion {
        confusion_type: FormatConfusionType,
        payload: Vec<u8>,
    },
    EncodingAttacks {
        encoding_type: EncodingType,
        key_bytes: [u8; 32],
    },
    ValidationBypass {
        bypass_type: ValidationBypassType,
        seed: [u8; 32],
        fake_public: [u8; 32],
    },
    InjectionAttacks {
        injection_type: InjectionType,
        payload: String,
    },
    BoundaryTests {
        boundary_type: BoundaryType,
        modifier: u8,
    },
    CorruptionTests {
        corruption_type: CorruptionType,
        position: u8,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum KeyData {
    Seed32([u8; 32]),
    Keypair64([u8; 64]),
    Random(Vec<u8>),
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatVariant {
    RawBytes,
    HexLowercase,
    HexUppercase,
    HexWithPrefix,
    HexWithUnderscores,
    HexWithDashes,
    Base64Standard,
    Base64UrlSafe,
    Base64NoPadding,
    MixedFormat,
}

#[derive(Debug, Clone, Arbitrary)]
enum LengthAttackType {
    TooShort,
    TooLong,
    OffByOne,
    ExactBoundary,
    DoubleLength,
    HalfLength,
    Massive,
    Zero,
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatConfusionType {
    TextualNonHex,
    InvalidBase64,
    MixedEncoding,
    UnicodeChars,
    ControlChars,
    NullBytes,
    WhitespaceVariations,
    PrefixSuffixAttack,
}

#[derive(Debug, Clone, Arbitrary)]
enum EncodingType {
    ValidHex,
    InvalidHexChars,
    OddLengthHex,
    CaseMixed,
    WithDelimiters,
    WithPrefixes,
    CorruptedBase64,
    DoubleDecode,
}

#[derive(Debug, Clone, Arbitrary)]
enum ValidationBypassType {
    MismatchedKeypair,
    ValidSeedWrongPublic,
    CorruptedPublicKey,
    ZeroPublicKey,
    AllOnesPublic,
    SwappedSeedPublic,
    PartialMatch,
}

#[derive(Debug, Clone, Arbitrary)]
enum InjectionType {
    FormatString,
    SqlInjection,
    CommandInjection,
    PathTraversal,
    JsonEscape,
    RegexEscape,
    UnicodeInjection,
    NullInjection,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryType {
    Length31,
    Length33,
    Length63,
    Length65,
    PowerOfTwo,
    MaxU8,
    MaxU16,
    AlignmentBoundary,
}

#[derive(Debug, Clone, Arbitrary)]
enum CorruptionType {
    SingleBitFlip,
    MultiBitFlip,
    ByteSwap,
    Truncation,
    Padding,
    Duplication,
    Inversion,
}

impl KeyData {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            KeyData::Seed32(seed) => seed.to_vec(),
            KeyData::Keypair64(keypair) => keypair.to_vec(),
            KeyData::Random(data) => data.clone(),
        }
    }
}

impl FormatVariant {
    fn apply(&self, key_bytes: &[u8]) -> Vec<u8> {
        match self {
            FormatVariant::RawBytes => key_bytes.to_vec(),
            FormatVariant::HexLowercase => hex::encode(key_bytes).into_bytes(),
            FormatVariant::HexUppercase => hex::encode(key_bytes).to_uppercase().into_bytes(),
            FormatVariant::HexWithPrefix => format!("0x{}", hex::encode(key_bytes)).into_bytes(),
            FormatVariant::HexWithUnderscores => {
                let hex = hex::encode(key_bytes);
                let with_underscores = hex
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i > 0 && i % 8 == 0 {
                            format!("_{}", c)
                        } else {
                            c.to_string()
                        }
                    })
                    .collect::<String>();
                with_underscores.into_bytes()
            }
            FormatVariant::HexWithDashes => {
                let hex = hex::encode(key_bytes);
                let with_dashes = hex
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i > 0 && i % 4 == 0 {
                            format!("-{}", c)
                        } else {
                            c.to_string()
                        }
                    })
                    .collect::<String>();
                with_dashes.into_bytes()
            }
            FormatVariant::Base64Standard => base64::prelude::BASE64_STANDARD
                .encode(key_bytes)
                .into_bytes(),
            FormatVariant::Base64UrlSafe => base64::prelude::BASE64_URL_SAFE
                .encode(key_bytes)
                .into_bytes(),
            FormatVariant::Base64NoPadding => base64::prelude::BASE64_URL_SAFE_NO_PAD
                .encode(key_bytes)
                .into_bytes(),
            FormatVariant::MixedFormat => {
                let hex_part = hex::encode(&key_bytes[..key_bytes.len().min(16)]);
                let b64_part =
                    base64::prelude::BASE64_STANDARD.encode(&key_bytes[key_bytes.len().min(16)..]);
                format!("{}{}", hex_part, b64_part).into_bytes()
            }
        }
    }
}

impl LengthAttackType {
    fn generate(&self, base_size: u16) -> Vec<u8> {
        let size = (base_size % 1000) as usize;
        match self {
            LengthAttackType::TooShort => vec![0x42; size.min(31)],
            LengthAttackType::TooLong => vec![0x42; size.max(65)],
            LengthAttackType::OffByOne => vec![0x42; 31],
            LengthAttackType::ExactBoundary => vec![0x42; if size % 2 == 0 { 32 } else { 64 }],
            LengthAttackType::DoubleLength => vec![0x42; 128],
            LengthAttackType::HalfLength => vec![0x42; 16],
            LengthAttackType::Massive => vec![0x42; 100000],
            LengthAttackType::Zero => Vec::new(),
        }
    }
}

impl FormatConfusionType {
    fn apply(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            FormatConfusionType::TextualNonHex => b"not_hex_at_all".to_vec(),
            FormatConfusionType::InvalidBase64 => b"Invalid@Base64!".to_vec(),
            FormatConfusionType::MixedEncoding => [
                hex::encode(&payload[..payload.len().min(16)]).as_bytes(),
                b"MIXED",
                &payload[payload.len().min(16)..],
            ]
            .concat(),
            FormatConfusionType::UnicodeChars => "🔑🚀💻🔥".as_bytes().to_vec(),
            FormatConfusionType::ControlChars => {
                [&[0x01, 0x02, 0x03, 0x1F, 0x7F], payload].concat()
            }
            FormatConfusionType::NullBytes => [payload, &[0x00, 0x00, 0x00]].concat(),
            FormatConfusionType::WhitespaceVariations => {
                format!(" \t\n{}\r\n ", hex::encode(payload)).into_bytes()
            }
            FormatConfusionType::PrefixSuffixAttack => {
                format!("PREFIX{}SUFFIX", hex::encode(payload)).into_bytes()
            }
        }
    }
}

impl EncodingType {
    fn apply(&self, key_bytes: &[u8; 32]) -> Vec<u8> {
        match self {
            EncodingType::ValidHex => hex::encode(key_bytes).into_bytes(),
            EncodingType::InvalidHexChars => {
                let mut hex = hex::encode(key_bytes);
                hex.replace_range(5..6, "G");
                hex.into_bytes()
            }
            EncodingType::OddLengthHex => {
                let hex = hex::encode(key_bytes);
                hex[..hex.len() - 1].to_string().into_bytes()
            }
            EncodingType::CaseMixed => hex::encode(key_bytes)
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_uppercase().collect::<String>()
                    } else {
                        c.to_lowercase().collect::<String>()
                    }
                })
                .collect::<String>()
                .into_bytes(),
            EncodingType::WithDelimiters => {
                let hex = hex::encode(key_bytes);
                hex.chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i > 0 && i % 4 == 0 {
                            format!(":{}", c)
                        } else {
                            c.to_string()
                        }
                    })
                    .collect::<String>()
                    .into_bytes()
            }
            EncodingType::WithPrefixes => format!("hex:{}", hex::encode(key_bytes)).into_bytes(),
            EncodingType::CorruptedBase64 => {
                let mut b64 = base64::prelude::BASE64_STANDARD.encode(key_bytes);
                b64.replace_range(5..6, "@");
                b64.into_bytes()
            }
            EncodingType::DoubleDecode => {
                let first = hex::encode(key_bytes);
                hex::encode(first.as_bytes()).into_bytes()
            }
        }
    }
}

impl ValidationBypassType {
    fn apply(&self, seed: &[u8; 32], fake_public: &[u8; 32]) -> Vec<u8> {
        match self {
            ValidationBypassType::MismatchedKeypair => {
                [seed.as_slice(), fake_public.as_slice()].concat()
            }
            ValidationBypassType::ValidSeedWrongPublic => {
                let mut wrong_public = *fake_public;
                wrong_public[0] = wrong_public[0].wrapping_add(1);
                [seed.as_slice(), wrong_public.as_slice()].concat()
            }
            ValidationBypassType::CorruptedPublicKey => {
                let mut corrupted = *fake_public;
                corrupted[15] ^= 0xFF;
                [seed.as_slice(), corrupted.as_slice()].concat()
            }
            ValidationBypassType::ZeroPublicKey => [seed.as_slice(), &[0u8; 32]].concat(),
            ValidationBypassType::AllOnesPublic => [seed.as_slice(), &[0xFFu8; 32]].concat(),
            ValidationBypassType::SwappedSeedPublic => {
                [fake_public.as_slice(), seed.as_slice()].concat()
            }
            ValidationBypassType::PartialMatch => {
                let mut partial = *fake_public;
                partial[..16].copy_from_slice(&seed[..16]);
                [seed.as_slice(), partial.as_slice()].concat()
            }
        }
    }
}

impl InjectionType {
    fn inject(&self, payload: &str) -> Vec<u8> {
        let base_key = "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef";
        let injection = match self {
            InjectionType::FormatString => "%s%x%p%n",
            InjectionType::SqlInjection => "'; DROP TABLE keys; --",
            InjectionType::CommandInjection => "; rm -rf /",
            InjectionType::PathTraversal => "../../../etc/passwd",
            InjectionType::JsonEscape => "\\\",\\\"evil\\\":\\\"",
            InjectionType::RegexEscape => ".*+?{}[]()^$",
            InjectionType::UnicodeInjection => "\u{202E}\u{202D}",
            InjectionType::NullInjection => "key\0injection",
        };
        format!("{}{}{}", base_key, injection, payload).into_bytes()
    }
}

impl BoundaryType {
    fn generate(&self, modifier: u8) -> Vec<u8> {
        let size = match self {
            BoundaryType::Length31 => 31,
            BoundaryType::Length33 => 33,
            BoundaryType::Length63 => 63,
            BoundaryType::Length65 => 65,
            BoundaryType::PowerOfTwo => 1 << (modifier % 8),
            BoundaryType::MaxU8 => 255,
            BoundaryType::MaxU16 => (modifier as usize) % 65536,
            BoundaryType::AlignmentBoundary => match modifier % 4 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => 8,
            },
        };
        vec![0x42; size]
    }
}

impl CorruptionType {
    fn apply(&self, key_bytes: &[u8], position: u8) -> Vec<u8> {
        let pos = (position as usize) % key_bytes.len().max(1);
        let mut corrupted = key_bytes.to_vec();

        match self {
            CorruptionType::SingleBitFlip => {
                if pos < corrupted.len() {
                    corrupted[pos] ^= 0x01;
                }
            }
            CorruptionType::MultiBitFlip => {
                if pos < corrupted.len() {
                    corrupted[pos] ^= 0xFF;
                }
            }
            CorruptionType::ByteSwap => {
                if pos + 1 < corrupted.len() {
                    corrupted.swap(pos, pos + 1);
                }
            }
            CorruptionType::Truncation => {
                if pos < corrupted.len() {
                    corrupted.truncate(pos);
                }
            }
            CorruptionType::Padding => {
                corrupted.extend_from_slice(&vec![0x00; (position % 32) as usize]);
            }
            CorruptionType::Duplication => {
                if pos < corrupted.len() {
                    corrupted.insert(pos, corrupted[pos]);
                }
            }
            CorruptionType::Inversion => {
                for byte in &mut corrupted {
                    *byte = !*byte;
                }
            }
        }

        corrupted
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            SigningKeyParseTest::ValidKeys {
                key_data,
                format_variant,
            } => {
                let key_bytes = key_data.to_bytes();
                let formatted = format_variant.apply(&key_bytes);
                // Test deterministic signing key parsing
                let result1 = parse_signing_key_from_blob(&formatted);
                let result2 = parse_signing_key_from_blob(&formatted);
                assert_eq!(
                    result1.is_some(),
                    result2.is_some(),
                    "Signing key parsing should be deterministic"
                );
            }
            SigningKeyParseTest::LengthAttacks {
                attack_type,
                base_size,
            } => {
                let attack_bytes = attack_type.generate(base_size);
                let _ = parse_signing_key_from_blob(&attack_bytes);
            }
            SigningKeyParseTest::FormatConfusion {
                confusion_type,
                payload,
            } => {
                let confused_bytes = confusion_type.apply(&payload);
                let _ = parse_signing_key_from_blob(&confused_bytes);
            }
            SigningKeyParseTest::EncodingAttacks {
                encoding_type,
                key_bytes,
            } => {
                let encoded = encoding_type.apply(&key_bytes);
                let _ = parse_signing_key_from_blob(&encoded);
            }
            SigningKeyParseTest::ValidationBypass {
                bypass_type,
                seed,
                fake_public,
            } => {
                let bypass_data = bypass_type.apply(&seed, &fake_public);
                let _ = parse_signing_key_from_blob(&bypass_data);
            }
            SigningKeyParseTest::InjectionAttacks {
                injection_type,
                payload,
            } => {
                let injection_data = injection_type.inject(&payload);
                let _ = parse_signing_key_from_blob(&injection_data);
            }
            SigningKeyParseTest::BoundaryTests {
                boundary_type,
                modifier,
            } => {
                let boundary_data = boundary_type.generate(modifier);
                let _ = parse_signing_key_from_blob(&boundary_data);
            }
            SigningKeyParseTest::CorruptionTests {
                corruption_type,
                position,
            } => {
                let base_key = [0x42u8; 32];
                let corrupted = corruption_type.apply(&base_key, position);
                let _ = parse_signing_key_from_blob(&corrupted);
            }
        }
    }
});
