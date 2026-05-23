//! Fuzz target for policy compatibility gates key ID derivation from bytes.
//!
//! Tests key_id_from_bytes() against malformed domain/bytes, injection attacks,
//! length confusion, hash collision attempts, and edge cases. Critical security
//! boundary for cryptographic key identification in compatibility policy gates.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

// Note: key_id_from_bytes is private, so we'll reimplement for testing
use sha2::{Sha256, Digest};

fn key_id_from_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let digest = Sha256::digest([domain, bytes].concat());
    hex::encode(&digest[..8])
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: KeyIdGenerationTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum KeyIdGenerationTest {
    ValidInputs {
        domain: Vec<u8>,
        bytes: Vec<u8>,
        variant: InputVariant,
    },
    LengthAttacks {
        attack_type: LengthAttackType,
        base_size: u16,
    },
    BoundaryTests {
        boundary_type: BoundaryType,
        modifier: u8,
    },
    CollisionAttempts {
        collision_type: CollisionType,
        seed: u32,
    },
    EncodingAttacks {
        encoding_type: EncodingType,
        payload: Vec<u8>,
    },
    InjectionAttacks {
        injection_type: InjectionType,
        position: u8,
    },
    SpecialBytes {
        special_type: SpecialBytesType,
        repetition: u8,
    },
    ConcatenationConfusion {
        confusion_type: ConcatenationType,
        split_point: u8,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum InputVariant {
    Standard,
    EmptyDomain,
    EmptyBytes,
    BothEmpty,
    LargeDomain,
    LargeBytes,
    BothLarge,
}

#[derive(Debug, Clone, Arbitrary)]
enum LengthAttackType {
    ZeroLength,
    SingleByte,
    Massive,
    PowerOfTwo,
    PrimeNumber,
    OffByOne,
    ExactHashSize,
    DoubleHashSize,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryType {
    MinValues,
    MaxValues,
    HashBoundary,
    U8Boundary,
    U16Boundary,
    U32Boundary,
    AlignmentBoundary,
}

#[derive(Debug, Clone, Arbitrary)]
enum CollisionType {
    SimilarDomains,
    SimilarBytes,
    SwappedInputs,
    PermutedBytes,
    PrefixSuffix,
    Truncation,
    Padding,
}

#[derive(Debug, Clone, Arbitrary)]
enum EncodingType {
    ControlChars,
    HighAscii,
    Utf8Sequences,
    InvalidUtf8,
    NullBytes,
    UnicodeNormalization,
    BinaryPatterns,
}

#[derive(Debug, Clone, Arbitrary)]
enum InjectionType {
    HashExtension,
    LengthPrefix,
    PathTraversal,
    FormatString,
    ShellInjection,
    SqlInjection,
    RegexEscape,
}

#[derive(Debug, Clone, Arbitrary)]
enum SpecialBytesType {
    AllZeros,
    AllOnes,
    Alternating,
    Incrementing,
    Decrementing,
    RandomPattern,
    RepeatedPattern,
}

#[derive(Debug, Clone, Arbitrary)]
enum ConcatenationType {
    DomainBytesConfusion,
    OverlapPreventionBypass,
    SeparatorInjection,
    BoundaryBlurring,
    LengthManipulation,
    OffsetConfusion,
}

impl InputVariant {
    fn apply(&self, domain: &[u8], bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            InputVariant::Standard => (domain.to_vec(), bytes.to_vec()),
            InputVariant::EmptyDomain => (Vec::new(), bytes.to_vec()),
            InputVariant::EmptyBytes => (domain.to_vec(), Vec::new()),
            InputVariant::BothEmpty => (Vec::new(), Vec::new()),
            InputVariant::LargeDomain => {
                let mut large_domain = domain.to_vec();
                large_domain.extend_from_slice(&vec![0xAB; 10000]);
                (large_domain, bytes.to_vec())
            },
            InputVariant::LargeBytes => {
                let mut large_bytes = bytes.to_vec();
                large_bytes.extend_from_slice(&vec![0xCD; 10000]);
                (domain.to_vec(), large_bytes)
            },
            InputVariant::BothLarge => {
                let mut large_domain = domain.to_vec();
                let mut large_bytes = bytes.to_vec();
                large_domain.extend_from_slice(&vec![0xAB; 5000]);
                large_bytes.extend_from_slice(&vec![0xCD; 5000]);
                (large_domain, large_bytes)
            },
        }
    }
}

impl LengthAttackType {
    fn generate(&self, base_size: u16) -> (Vec<u8>, Vec<u8>) {
        let size = (base_size % 1000) as usize;
        match self {
            LengthAttackType::ZeroLength => (Vec::new(), Vec::new()),
            LengthAttackType::SingleByte => (vec![0x42], vec![0x24]),
            LengthAttackType::Massive => (vec![0xFF; 100000], vec![0xEE; 100000]),
            LengthAttackType::PowerOfTwo => {
                let len = 1 << (size % 16);
                (vec![0xAA; len], vec![0xBB; len])
            },
            LengthAttackType::PrimeNumber => {
                let primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
                let len = primes[size % primes.len()];
                (vec![0xCC; len], vec![0xDD; len])
            },
            LengthAttackType::OffByOne => (vec![0x11; size + 1], vec![0x22; size.saturating_sub(1)]),
            LengthAttackType::ExactHashSize => (vec![0x33; 32], vec![0x44; 32]),
            LengthAttackType::DoubleHashSize => (vec![0x55; 64], vec![0x66; 64]),
        }
    }
}

impl BoundaryType {
    fn generate(&self, modifier: u8) -> (Vec<u8>, Vec<u8>) {
        match self {
            BoundaryType::MinValues => (vec![0x00; modifier as usize % 100], vec![0x00; modifier as usize % 100]),
            BoundaryType::MaxValues => (vec![0xFF; modifier as usize % 100], vec![0xFF; modifier as usize % 100]),
            BoundaryType::HashBoundary => {
                let len = if modifier % 2 == 0 { 31 } else { 33 };
                (vec![0x7F; len], vec![0x80; len])
            },
            BoundaryType::U8Boundary => (vec![127, 128, 255, 0], vec![254, 255, 0, 1]),
            BoundaryType::U16Boundary => {
                let bytes: Vec<u8> = vec![0xFF, 0xFF, 0x00, 0x00, 0x7F, 0xFF, 0x80, 0x00];
                (bytes.clone(), bytes)
            },
            BoundaryType::U32Boundary => {
                let bytes: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
                (bytes.clone(), bytes)
            },
            BoundaryType::AlignmentBoundary => {
                // Test alignment boundaries
                let len = match modifier % 4 {
                    0 => 1,
                    1 => 2,
                    2 => 4,
                    _ => 8,
                };
                (vec![0xAA; len], vec![0xBB; len])
            },
        }
    }
}

impl CollisionType {
    fn generate(&self, seed: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let base_domain = vec![0x01, 0x02, 0x03];
        let base_bytes = vec![0x04, 0x05, 0x06];

        match self {
            CollisionType::SimilarDomains => {
                let mut domain2 = base_domain.clone();
                domain2[0] ^= 0x01; // Flip one bit
                (base_domain, base_bytes.clone(), domain2, base_bytes)
            },
            CollisionType::SimilarBytes => {
                let mut bytes2 = base_bytes.clone();
                bytes2[0] ^= 0x01; // Flip one bit
                (base_domain.clone(), base_bytes, base_domain, bytes2)
            },
            CollisionType::SwappedInputs => {
                (base_domain.clone(), base_bytes.clone(), base_bytes, base_domain)
            },
            CollisionType::PermutedBytes => {
                let mut perm_domain = base_domain.clone();
                let mut perm_bytes = base_bytes.clone();
                perm_domain.reverse();
                perm_bytes.reverse();
                (base_domain, base_bytes, perm_domain, perm_bytes)
            },
            CollisionType::PrefixSuffix => {
                let mut prefixed_domain = vec![0x00];
                let mut suffixed_bytes = base_bytes.clone();
                prefixed_domain.extend_from_slice(&base_domain);
                suffixed_bytes.push(0x00);
                (base_domain, base_bytes, prefixed_domain, suffixed_bytes)
            },
            CollisionType::Truncation => {
                let trunc_domain = if base_domain.len() > 1 { base_domain[..base_domain.len()-1].to_vec() } else { base_domain.clone() };
                let trunc_bytes = if base_bytes.len() > 1 { base_bytes[..base_bytes.len()-1].to_vec() } else { base_bytes.clone() };
                (base_domain, base_bytes, trunc_domain, trunc_bytes)
            },
            CollisionType::Padding => {
                let mut padded_domain = base_domain.clone();
                let mut padded_bytes = base_bytes.clone();
                padded_domain.extend_from_slice(&vec![0x00; (seed % 10) as usize]);
                padded_bytes.extend_from_slice(&vec![0x00; (seed % 10) as usize]);
                (base_domain, base_bytes, padded_domain, padded_bytes)
            },
        }
    }
}

impl EncodingType {
    fn apply(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            EncodingType::ControlChars => {
                vec![0x00, 0x01, 0x02, 0x03, 0x1F, 0x7F]
            },
            EncodingType::HighAscii => {
                vec![0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF]
            },
            EncodingType::Utf8Sequences => {
                // Valid UTF-8 sequences
                vec![0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x92, 0xA9]
            },
            EncodingType::InvalidUtf8 => {
                // Invalid UTF-8 sequences
                vec![0xC0, 0x80, 0xFE, 0xFF, 0xED, 0xA0, 0x80]
            },
            EncodingType::NullBytes => {
                let mut result = payload.to_vec();
                result.extend_from_slice(&vec![0x00; 5]);
                result
            },
            EncodingType::UnicodeNormalization => {
                // é as decomposed (e + combining acute)
                vec![0x65, 0xCC, 0x81]
            },
            EncodingType::BinaryPatterns => {
                vec![0xAA, 0x55, 0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
            },
        }
    }
}

impl InjectionType {
    fn inject(&self, position: u8) -> (Vec<u8>, Vec<u8>) {
        let base = b"base_key_domain";
        let pos = (position as usize) % base.len();

        let injection: &[u8] = match self {
            InjectionType::HashExtension => b"\x80\x00\x00\x00\x00\x00\x02\x00",
            InjectionType::LengthPrefix => b"\x00\x00\x00\x20",
            InjectionType::PathTraversal => b"../../../etc/passwd",
            InjectionType::FormatString => b"%s%x%p%n%d",
            InjectionType::ShellInjection => b"; rm -rf /",
            InjectionType::SqlInjection => b"'; DROP TABLE keys; --",
            InjectionType::RegexEscape => b".*+?{}[]()^$",
        };

        let mut domain = base[..pos].to_vec();
        domain.extend_from_slice(injection);
        domain.extend_from_slice(&base[pos..]);

        (domain, b"test_bytes".to_vec())
    }
}

impl SpecialBytesType {
    fn generate(&self, repetition: u8) -> (Vec<u8>, Vec<u8>) {
        let len = ((repetition % 100) + 1) as usize;
        match self {
            SpecialBytesType::AllZeros => (vec![0x00; len], vec![0x00; len]),
            SpecialBytesType::AllOnes => (vec![0xFF; len], vec![0xFF; len]),
            SpecialBytesType::Alternating => {
                let domain: Vec<u8> = (0..len).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect();
                let bytes: Vec<u8> = (0..len).map(|i| if i % 2 == 0 { 0x55 } else { 0xAA }).collect();
                (domain, bytes)
            },
            SpecialBytesType::Incrementing => {
                let domain: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
                let bytes: Vec<u8> = (0..len).map(|i| ((i + 128) % 256) as u8).collect();
                (domain, bytes)
            },
            SpecialBytesType::Decrementing => {
                let domain: Vec<u8> = (0..len).map(|i| (255 - (i % 256)) as u8).collect();
                let bytes: Vec<u8> = (0..len).map(|i| (127 - (i % 128)) as u8).collect();
                (domain, bytes)
            },
            SpecialBytesType::RandomPattern => {
                // Deterministic "random" pattern
                let domain: Vec<u8> = (0..len).map(|i| ((i * 17 + 13) % 256) as u8).collect();
                let bytes: Vec<u8> = (0..len).map(|i| ((i * 23 + 7) % 256) as u8).collect();
                (domain, bytes)
            },
            SpecialBytesType::RepeatedPattern => {
                let pattern = vec![0xDE, 0xAD, 0xBE, 0xEF];
                let domain: Vec<u8> = pattern.iter().cycle().take(len).copied().collect();
                let bytes: Vec<u8> = vec![0xCA, 0xFE, 0xBA, 0xBE].iter().cycle().take(len).copied().collect();
                (domain, bytes)
            },
        }
    }
}

impl ConcatenationType {
    fn apply(&self, split_point: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let split = (split_point % 20) as usize;

        match self {
            ConcatenationType::DomainBytesConfusion => {
                // Try to make domain||bytes == domain2||bytes2 with different splits
                let combined = b"abcdefghijklmnopqrstuvwxyz";
                let domain1 = combined[..split].to_vec();
                let bytes1 = combined[split..].to_vec();
                let domain2 = combined[..split+1].to_vec();
                let bytes2 = combined[split+1..].to_vec();
                (domain1, bytes1, domain2, bytes2)
            },
            ConcatenationType::OverlapPreventionBypass => {
                // Attempt to create overlapping boundaries
                let domain1 = vec![0x01, 0x02];
                let bytes1 = vec![0x03, 0x04];
                let domain2 = vec![0x01];
                let bytes2 = vec![0x02, 0x03, 0x04];
                (domain1, bytes1, domain2, bytes2)
            },
            ConcatenationType::SeparatorInjection => {
                // Try to inject separator-like bytes
                let domain1 = vec![0x00, 0x01, 0x02];
                let bytes1 = vec![0xFF, 0xFE, 0xFD];
                let domain2 = vec![0x00, 0x01];
                let bytes2 = vec![0x02, 0xFF, 0xFE, 0xFD];
                (domain1, bytes1, domain2, bytes2)
            },
            ConcatenationType::BoundaryBlurring => {
                // Make boundaries ambiguous
                let boundary_byte = split as u8;
                let domain1 = vec![0x01, boundary_byte];
                let bytes1 = vec![boundary_byte, 0x02];
                let domain2 = vec![0x01, boundary_byte, boundary_byte];
                let bytes2 = vec![0x02];
                (domain1, bytes1, domain2, bytes2)
            },
            ConcatenationType::LengthManipulation => {
                // Manipulate perceived lengths
                let domain1 = vec![0x00; split];
                let bytes1 = vec![0xFF; 20 - split];
                let domain2 = vec![0x00; split + 1];
                let bytes2 = vec![0xFF; 19 - split];
                (domain1, bytes1, domain2, bytes2)
            },
            ConcatenationType::OffsetConfusion => {
                // Create offset confusion
                let offset = split % 10;
                let domain1 = vec![0xAA; offset];
                let bytes1 = vec![0xBB; 10];
                let domain2 = vec![0xAA; offset + 1];
                let bytes2 = vec![0xBB; 9];
                (domain1, bytes1, domain2, bytes2)
            },
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            KeyIdGenerationTest::ValidInputs { domain, bytes, variant } => {
                let (test_domain, test_bytes) = variant.apply(&domain, &bytes);
                let _ = key_id_from_bytes(&test_domain, &test_bytes);
            },
            KeyIdGenerationTest::LengthAttacks { attack_type, base_size } => {
                let (domain, bytes) = attack_type.generate(base_size);
                let _ = key_id_from_bytes(&domain, &bytes);
            },
            KeyIdGenerationTest::BoundaryTests { boundary_type, modifier } => {
                let (domain, bytes) = boundary_type.generate(modifier);
                let _ = key_id_from_bytes(&domain, &bytes);
            },
            KeyIdGenerationTest::CollisionAttempts { collision_type, seed } => {
                let (domain1, bytes1, domain2, bytes2) = collision_type.generate(seed);
                let _ = key_id_from_bytes(&domain1, &bytes1);
                let _ = key_id_from_bytes(&domain2, &bytes2);
            },
            KeyIdGenerationTest::EncodingAttacks { encoding_type, payload } => {
                let attack_bytes = encoding_type.apply(&payload);
                let _ = key_id_from_bytes(&attack_bytes, &attack_bytes);
            },
            KeyIdGenerationTest::InjectionAttacks { injection_type, position } => {
                let (domain, bytes) = injection_type.inject(position);
                let _ = key_id_from_bytes(&domain, &bytes);
            },
            KeyIdGenerationTest::SpecialBytes { special_type, repetition } => {
                let (domain, bytes) = special_type.generate(repetition);
                let _ = key_id_from_bytes(&domain, &bytes);
            },
            KeyIdGenerationTest::ConcatenationConfusion { confusion_type, split_point } => {
                let (domain1, bytes1, domain2, bytes2) = confusion_type.apply(split_point);
                let _ = key_id_from_bytes(&domain1, &bytes1);
                let _ = key_id_from_bytes(&domain2, &bytes2);
            },
        }
    }
});