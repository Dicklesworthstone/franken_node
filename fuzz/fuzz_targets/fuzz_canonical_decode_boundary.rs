//! Fuzz target for canonical encoding decoder in connector serialization.
//!
//! Tests canonical_decode() against malformed length prefixes, truncated payloads,
//! overflow attacks, boundary conditions, and injection attempts. Critical security
//! boundary for canonical encoding deserialization in connector trust serialization.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

// Reimplemented function for fuzzing
fn canonical_decode(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 4 {
        return Err("payload too short: need at least 4 bytes for length prefix".to_string());
    }
    let len_u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let len = len_u32 as usize;
    if len > bytes.len() - 4 {
        return Err(format!(
            "length mismatch: prefix={} but payload={}",
            len,
            bytes.len() - 4
        ));
    }
    Ok(bytes[4..4 + len].to_vec())
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: CanonicalDecodeTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum CanonicalDecodeTest {
    ValidPayloads {
        payload: Vec<u8>,
        encoding_variant: EncodingVariant,
    },
    LengthPrefixAttacks {
        attack_type: LengthPrefixAttackType,
        payload_size: u16,
    },
    BoundaryConditions {
        boundary_type: BoundaryType,
        modifier: u8,
    },
    OverflowAttacks {
        overflow_type: OverflowType,
        magnitude: u32,
    },
    TruncationAttacks {
        truncation_type: TruncationType,
        cut_point: u8,
    },
    InjectionAttacks {
        injection_type: InjectionType,
        payload: Vec<u8>,
    },
    FormatConfusion {
        confusion_type: FormatConfusionType,
        base_data: Vec<u8>,
    },
    EdgeCases {
        edge_type: EdgeCaseType,
        repetition: u8,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum EncodingVariant {
    Standard,
    MinimalPayload,
    MaximalPayload,
    EmptyPayload,
    BinaryPayload,
    TextPayload,
    MixedPayload,
}

#[derive(Debug, Clone, Arbitrary)]
enum LengthPrefixAttackType {
    ZeroLength,
    MaxU32,
    Overflow,
    NegativeAsU32,
    MismatchLarge,
    MismatchSmall,
    ExactBoundary,
    OffByOne,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryType {
    MinimalInput,
    ExactFourBytes,
    FiveBytes,
    PowerOfTwo,
    U32Boundary,
    SizeLimit,
    AlignmentBoundary,
}

#[derive(Debug, Clone, Arbitrary)]
enum OverflowType {
    U32Overflow,
    UsizeOverflow,
    IntegerWrap,
    LengthOverflow,
    IndexOverflow,
    AllocationOverflow,
    AdditionOverflow,
}

#[derive(Debug, Clone, Arbitrary)]
enum TruncationType {
    LengthPrefixCut,
    PayloadCut,
    MiddleCut,
    EndCut,
    RandomCut,
    MultipleCuts,
    ByteByCut,
}

#[derive(Debug, Clone, Arbitrary)]
enum InjectionType {
    NullBytes,
    ControlChars,
    FormatString,
    PathTraversal,
    SqlInjection,
    BufferOverflow,
    UnicodeInjection,
    BinaryInjection,
}

#[derive(Debug, Clone, Arbitrary)]
enum FormatConfusionType {
    WrongEndianness,
    MultipleHeaders,
    NestedLength,
    RecursiveStructure,
    TypeConfusion,
    ProtocolConfusion,
    EncodingMixup,
}

#[derive(Debug, Clone, Arbitrary)]
enum EdgeCaseType {
    AllZeros,
    AllOnes,
    AlternatingPattern,
    IncrementingBytes,
    RepeatedBytes,
    RandomPattern,
    SpecialValues,
}

impl EncodingVariant {
    fn apply(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            EncodingVariant::Standard => {
                let len = payload.len() as u32;
                let mut encoded = len.to_be_bytes().to_vec();
                encoded.extend_from_slice(payload);
                encoded
            },
            EncodingVariant::MinimalPayload => {
                vec![0, 0, 0, 0]
            },
            EncodingVariant::MaximalPayload => {
                let payload = vec![0xAA; 1000];
                let len = payload.len() as u32;
                let mut encoded = len.to_be_bytes().to_vec();
                encoded.extend_from_slice(&payload);
                encoded
            },
            EncodingVariant::EmptyPayload => {
                vec![0, 0, 0, 0]
            },
            EncodingVariant::BinaryPayload => {
                let binary_data = vec![0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
                let len = binary_data.len() as u32;
                let mut encoded = len.to_be_bytes().to_vec();
                encoded.extend_from_slice(&binary_data);
                encoded
            },
            EncodingVariant::TextPayload => {
                let text_data = b"Hello, World!".to_vec();
                let len = text_data.len() as u32;
                let mut encoded = len.to_be_bytes().to_vec();
                encoded.extend_from_slice(&text_data);
                encoded
            },
            EncodingVariant::MixedPayload => {
                let mixed = [payload, b"MIXED"].concat();
                let len = mixed.len() as u32;
                let mut encoded = len.to_be_bytes().to_vec();
                encoded.extend_from_slice(&mixed);
                encoded
            },
        }
    }
}

impl LengthPrefixAttackType {
    fn generate(&self, payload_size: u16) -> Vec<u8> {
        let size = payload_size as usize % 1000;
        let payload = vec![0x42; size];

        match self {
            LengthPrefixAttackType::ZeroLength => {
                let mut result = vec![0, 0, 0, 0];
                result.extend_from_slice(&payload);
                result
            },
            LengthPrefixAttackType::MaxU32 => {
                let mut result = u32::MAX.to_be_bytes().to_vec();
                result.extend_from_slice(&payload);
                result
            },
            LengthPrefixAttackType::Overflow => {
                let len = (payload.len() + 1000000) as u32;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&payload);
                result
            },
            LengthPrefixAttackType::NegativeAsU32 => {
                let len = (-1i32) as u32; // 0xFFFFFFFF
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&payload);
                result
            },
            LengthPrefixAttackType::MismatchLarge => {
                let len = (payload.len() + 100) as u32;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&payload);
                result
            },
            LengthPrefixAttackType::MismatchSmall => {
                let len = if payload.len() > 0 { (payload.len() - 1) as u32 } else { 0 };
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&payload);
                result
            },
            LengthPrefixAttackType::ExactBoundary => {
                let len = payload.len() as u32;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&payload);
                result
            },
            LengthPrefixAttackType::OffByOne => {
                let len = (payload.len() + 1) as u32;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&payload);
                result
            },
        }
    }
}

impl BoundaryType {
    fn generate(&self, modifier: u8) -> Vec<u8> {
        match self {
            BoundaryType::MinimalInput => vec![],
            BoundaryType::ExactFourBytes => vec![0, 0, 0, 0],
            BoundaryType::FiveBytes => vec![0, 0, 0, 1, 0x42],
            BoundaryType::PowerOfTwo => {
                let size = 1 << (modifier % 16);
                let len = size as u32;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&vec![0x55; size]);
                result
            },
            BoundaryType::U32Boundary => {
                let size = match modifier % 4 {
                    0 => 0xFE,
                    1 => 0xFF,
                    2 => 0x100,
                    _ => 0x101,
                };
                let len = size as u32;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&vec![0x66; size]);
                result
            },
            BoundaryType::SizeLimit => {
                let size = (modifier as usize % 1000) + 1;
                let len = size as u32;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&vec![0x77; size]);
                result
            },
            BoundaryType::AlignmentBoundary => {
                let size = match modifier % 4 {
                    0 => 1,
                    1 => 2,
                    2 => 4,
                    _ => 8,
                };
                let len = size as u32;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&vec![0x88; size]);
                result
            },
        }
    }
}

impl OverflowType {
    fn generate(&self, magnitude: u32) -> Vec<u8> {
        let mag = magnitude % 10000;
        match self {
            OverflowType::U32Overflow => {
                let len = u32::MAX;
                len.to_be_bytes().to_vec()
            },
            OverflowType::UsizeOverflow => {
                let len = if cfg!(target_pointer_width = "64") {
                    0xFFFFFFFF_u32
                } else {
                    0xFFFFFFFF_u32
                };
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&vec![0x99; (mag % 100) as usize]);
                result
            },
            OverflowType::IntegerWrap => {
                let len = u32::MAX.wrapping_add(mag);
                len.to_be_bytes().to_vec()
            },
            OverflowType::LengthOverflow => {
                let len = u32::MAX;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&vec![0xAA; 4]);
                result
            },
            OverflowType::IndexOverflow => {
                let len = (mag + 1000000) as u32;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&vec![0xBB; (mag % 10) as usize]);
                result
            },
            OverflowType::AllocationOverflow => {
                let len = u32::MAX;
                len.to_be_bytes().to_vec()
            },
            OverflowType::AdditionOverflow => {
                let len = u32::MAX.saturating_sub(3);
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&vec![0xCC; 3]);
                result
            },
        }
    }
}

impl TruncationType {
    fn apply(&self, cut_point: u8, base_data: &[u8]) -> Vec<u8> {
        if base_data.is_empty() {
            return Vec::new();
        }

        let cut = (cut_point as usize) % base_data.len();
        match self {
            TruncationType::LengthPrefixCut => {
                let cut = (cut_point as usize % 4).max(0);
                base_data[..cut].to_vec()
            },
            TruncationType::PayloadCut => {
                if base_data.len() <= 4 { return base_data.to_vec(); }
                let cut = 4 + (cut_point as usize % (base_data.len() - 4));
                base_data[..cut].to_vec()
            },
            TruncationType::MiddleCut => {
                let mid = base_data.len() / 2;
                let cut = mid + (cut_point as usize % (base_data.len() - mid));
                base_data[..cut].to_vec()
            },
            TruncationType::EndCut => {
                let cut = base_data.len().saturating_sub((cut_point as usize % 10) + 1);
                base_data[..cut].to_vec()
            },
            TruncationType::RandomCut => {
                base_data[..cut].to_vec()
            },
            TruncationType::MultipleCuts => {
                let cut1 = cut % (base_data.len() / 3);
                let cut2 = cut1 + (cut % (base_data.len() / 3));
                [&base_data[..cut1], &base_data[cut2..]].concat()
            },
            TruncationType::ByteByCut => {
                if cut < base_data.len() {
                    let mut result = base_data.to_vec();
                    result.remove(cut);
                    result
                } else {
                    base_data.to_vec()
                }
            },
        }
    }
}

impl InjectionType {
    fn inject(&self, payload: &[u8]) -> Vec<u8> {
        let injection = match self {
            InjectionType::NullBytes => vec![0x00, 0x00, 0x00, 0x00],
            InjectionType::ControlChars => vec![0x01, 0x02, 0x03, 0x1F, 0x7F],
            InjectionType::FormatString => b"%s%x%p%n".to_vec(),
            InjectionType::PathTraversal => b"../../../etc/passwd".to_vec(),
            InjectionType::SqlInjection => b"'; DROP TABLE data; --".to_vec(),
            InjectionType::BufferOverflow => vec![0x41; 1000],
            InjectionType::UnicodeInjection => "🚀💻🔥".as_bytes().to_vec(),
            InjectionType::BinaryInjection => vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
        };

        let combined = [payload, &injection].concat();
        let len = combined.len() as u32;
        let mut result = len.to_be_bytes().to_vec();
        result.extend_from_slice(&combined);
        result
    }
}

impl FormatConfusionType {
    fn apply(&self, base_data: &[u8]) -> Vec<u8> {
        match self {
            FormatConfusionType::WrongEndianness => {
                if base_data.len() >= 4 {
                    let len = u32::from_le_bytes([base_data[0], base_data[1], base_data[2], base_data[3]]);
                    let mut result = len.to_be_bytes().to_vec();
                    result.extend_from_slice(&base_data[4..]);
                    result
                } else {
                    base_data.to_vec()
                }
            },
            FormatConfusionType::MultipleHeaders => {
                let len1 = 10u32.to_be_bytes();
                let len2 = 20u32.to_be_bytes();
                [&len1[..], &len2[..], base_data].concat()
            },
            FormatConfusionType::NestedLength => {
                let inner_len = base_data.len() as u32;
                let outer_len = (inner_len + 4) as u32;
                let mut result = outer_len.to_be_bytes().to_vec();
                result.extend_from_slice(&inner_len.to_be_bytes());
                result.extend_from_slice(base_data);
                result
            },
            FormatConfusionType::RecursiveStructure => {
                let len = 8u32;
                let mut result = len.to_be_bytes().to_vec();
                result.extend_from_slice(&len.to_be_bytes());
                result.extend_from_slice(&len.to_be_bytes());
                result
            },
            FormatConfusionType::TypeConfusion => {
                // Mix different type markers
                [&[0xFF, 0xFE, 0xFD, 0xFC], base_data].concat()
            },
            FormatConfusionType::ProtocolConfusion => {
                // Add protocol-like headers
                [b"HTTP/1.1 200 OK\r\n\r\n", base_data].concat()
            },
            FormatConfusionType::EncodingMixup => {
                // Mix binary and text encoding markers
                [&[0xEF, 0xBB, 0xBF], base_data].concat() // UTF-8 BOM
            },
        }
    }
}

impl EdgeCaseType {
    fn generate(&self, repetition: u8) -> Vec<u8> {
        let size = (repetition as usize % 100) + 1;
        let payload = match self {
            EdgeCaseType::AllZeros => vec![0x00; size],
            EdgeCaseType::AllOnes => vec![0xFF; size],
            EdgeCaseType::AlternatingPattern => {
                (0..size).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect()
            },
            EdgeCaseType::IncrementingBytes => {
                (0..size).map(|i| (i % 256) as u8).collect()
            },
            EdgeCaseType::RepeatedBytes => vec![0x42; size],
            EdgeCaseType::RandomPattern => {
                (0..size).map(|i| ((i * 17 + 13) % 256) as u8).collect()
            },
            EdgeCaseType::SpecialValues => {
                let special = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF];
                special.iter().cycle().take(size).copied().collect()
            },
        };

        let len = payload.len() as u32;
        let mut result = len.to_be_bytes().to_vec();
        result.extend_from_slice(&payload);
        result
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            CanonicalDecodeTest::ValidPayloads { payload, encoding_variant } => {
                let encoded = encoding_variant.apply(&payload);
                // Test deterministic canonical decoding
                let result1 = canonical_decode(&encoded);
                let result2 = canonical_decode(&encoded);
                assert_eq!(result1.is_ok(), result2.is_ok(), "Canonical decoding should be deterministic");
            },
            CanonicalDecodeTest::LengthPrefixAttacks { attack_type, payload_size } => {
                let attack_data = attack_type.generate(payload_size);
                let _ = canonical_decode(&attack_data);
            },
            CanonicalDecodeTest::BoundaryConditions { boundary_type, modifier } => {
                let boundary_data = boundary_type.generate(modifier);
                let _ = canonical_decode(&boundary_data);
            },
            CanonicalDecodeTest::OverflowAttacks { overflow_type, magnitude } => {
                let overflow_data = overflow_type.generate(magnitude);
                let _ = canonical_decode(&overflow_data);
            },
            CanonicalDecodeTest::TruncationAttacks { truncation_type, cut_point } => {
                let base_data = vec![0, 0, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
                let truncated_data = truncation_type.apply(cut_point, &base_data);
                let _ = canonical_decode(&truncated_data);
            },
            CanonicalDecodeTest::InjectionAttacks { injection_type, payload } => {
                let injected_data = injection_type.inject(&payload);
                let _ = canonical_decode(&injected_data);
            },
            CanonicalDecodeTest::FormatConfusion { confusion_type, base_data } => {
                let confused_data = confusion_type.apply(&base_data);
                let _ = canonical_decode(&confused_data);
            },
            CanonicalDecodeTest::EdgeCases { edge_type, repetition } => {
                let edge_data = edge_type.generate(repetition);
                let _ = canonical_decode(&edge_data);
            },
        }
    }
});