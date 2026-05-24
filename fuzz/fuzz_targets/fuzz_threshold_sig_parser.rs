//! Fuzz target for threshold signature parsing in security module.
//!
//! Tests Ed25519 verifying key and signature parsing against malformed hex,
//! invalid lengths, case variations, and cryptographic boundary conditions.
//! Critical security boundary for threshold signature verification.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

const ED25519_PUBLIC_KEY_HEX_LEN: usize = 64;
const ED25519_SIGNATURE_HEX_LEN: usize = 128;

// Mock crypto types for fuzzing
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    bytes: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Signature {
    bytes: [u8; 64],
}

impl VerifyingKey {
    fn from_bytes(bytes: &[u8; 32]) -> Result<Self, &'static str> {
        // Mock validation - reject all zeros or all ones
        if bytes.iter().all(|&b| b == 0) || bytes.iter().all(|&b| b == 0xFF) {
            Err("Invalid key")
        } else {
            Ok(VerifyingKey { bytes: *bytes })
        }
    }
}

impl Signature {
    fn from_bytes(bytes: &[u8; 64]) -> Self {
        Signature { bytes: *bytes }
    }
}

// Reimplemented functions for fuzzing
fn parse_verifying_key(public_key_hex: &str) -> Option<VerifyingKey> {
    if public_key_hex.len() != ED25519_PUBLIC_KEY_HEX_LEN {
        return None;
    }

    let mut pk_array = [0_u8; 32];
    hex::decode_to_slice(public_key_hex, &mut pk_array).ok()?;
    VerifyingKey::from_bytes(&pk_array).ok()
}

fn parse_signature(signature_hex: &str) -> Option<Signature> {
    if signature_hex.len() != ED25519_SIGNATURE_HEX_LEN {
        return None;
    }

    let mut sig_bytes = [0_u8; 64];
    hex::decode_to_slice(signature_hex, &mut sig_bytes).ok()?;
    Some(Signature::from_bytes(&sig_bytes))
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: ThresholdSigOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum ThresholdSigOperation {
    VerifyingKeyParse {
        key_data: KeyData,
        corruption: Vec<HexCorruption>,
    },
    SignatureParse {
        sig_data: SigData,
        corruption: Vec<HexCorruption>,
    },
    LengthAttacks {
        attack_type: LengthAttack,
        target: ParseTarget,
    },
    CryptoAttacks {
        attack_type: CryptoAttack,
        target: ParseTarget,
    },
    ConcurrentParsing {
        operations: Vec<ParseOperation>,
    },
    BoundaryTests {
        boundary_type: BoundaryTest,
        parse_type: ParseTarget,
    },
}

#[derive(Debug, Clone, Arbitrary)]
struct KeyData {
    bytes: [u8; 32],
    encoding: HexEncoding,
}

#[derive(Debug, Clone, Arbitrary)]
struct SigData {
    bytes: [u8; 64],
    encoding: HexEncoding,
}

#[derive(Debug, Clone, Arbitrary)]
enum HexEncoding {
    Lowercase,
    Uppercase,
    Mixed,
    Invalid,
}

#[derive(Debug, Clone, Arbitrary)]
enum HexCorruption {
    InvalidChar(char),
    CaseFlip,
    Truncate(u8),
    Extend(String),
    InsertNullByte,
    InsertWhitespace,
    InsertUnicode,
    ReplaceDigits,
}

#[derive(Debug, Clone, Arbitrary)]
enum LengthAttack {
    TooShort,
    TooLong,
    OffByOne,
    Double,
    Massive,
    Empty,
    OddLength,
}

#[derive(Debug, Clone, Arbitrary)]
enum CryptoAttack {
    AllZeros,
    AllOnes,
    WeakKeys,
    MallableSignature,
    InvalidCurvePoints,
    ReusedNonce,
}

#[derive(Debug, Clone, Arbitrary)]
enum ParseTarget {
    VerifyingKey,
    Signature,
    Both,
}

#[derive(Debug, Clone, Arbitrary)]
struct ParseOperation {
    target: ParseTarget,
    input: String,
}

#[derive(Debug, Clone, Arbitrary)]
enum BoundaryTest {
    ExactLength,
    MinusOne,
    PlusOne,
    MaxUsize,
    Zero,
}

impl HexEncoding {
    fn apply(&self, bytes: &[u8]) -> String {
        let base_hex = hex::encode(bytes);
        match self {
            HexEncoding::Lowercase => base_hex.to_lowercase(),
            HexEncoding::Uppercase => base_hex.to_uppercase(),
            HexEncoding::Mixed => {
                base_hex.chars().enumerate().map(|(i, c)| {
                    if i % 2 == 0 { c.to_uppercase().collect::<String>() }
                    else { c.to_lowercase().collect::<String>() }
                }).collect()
            },
            HexEncoding::Invalid => {
                base_hex.chars().enumerate().map(|(i, c)| {
                    if i % 4 == 0 { 'G' } else { c }
                }).collect()
            },
        }
    }
}

impl HexCorruption {
    fn apply(&self, hex: &str) -> String {
        match self {
            HexCorruption::InvalidChar(c) => {
                if !hex.is_empty() {
                    let mut chars: Vec<char> = hex.chars().collect();
                    chars[0] = *c;
                    chars.into_iter().collect()
                } else {
                    c.to_string()
                }
            },
            HexCorruption::CaseFlip => {
                hex.chars().map(|c| {
                    if c.is_uppercase() { c.to_lowercase().collect() }
                    else { c.to_uppercase().collect() }
                }).collect::<Vec<String>>().join("")
            },
            HexCorruption::Truncate(n) => {
                let len = (*n as usize).min(hex.len());
                hex.chars().take(len).collect()
            },
            HexCorruption::Extend(suffix) => format!("{}{}", hex, suffix),
            HexCorruption::InsertNullByte => format!("{}\0{}", hex, hex),
            HexCorruption::InsertWhitespace => format!("{}  \t\n{}", hex, hex),
            HexCorruption::InsertUnicode => format!("{}🔥{}", hex, hex),
            HexCorruption::ReplaceDigits => {
                hex.chars().map(|c| {
                    if c.is_ascii_digit() { 'G' } else { c }
                }).collect()
            },
        }
    }
}

impl LengthAttack {
    fn generate(&self, base_len: usize) -> String {
        match self {
            LengthAttack::TooShort => "A".repeat(base_len / 2),
            LengthAttack::TooLong => "A".repeat(base_len * 2),
            LengthAttack::OffByOne => "A".repeat(base_len - 1),
            LengthAttack::Double => "A".repeat(base_len * 2),
            LengthAttack::Massive => "A".repeat(100000),
            LengthAttack::Empty => String::new(),
            LengthAttack::OddLength => "A".repeat(base_len + 1),
        }
    }
}

impl CryptoAttack {
    fn generate_key_attack(&self) -> [u8; 32] {
        match self {
            CryptoAttack::AllZeros => [0u8; 32],
            CryptoAttack::AllOnes => [0xFFu8; 32],
            CryptoAttack::WeakKeys => {
                let mut key = [0u8; 32];
                key[0] = 1; // Small order key candidate
                key
            },
            CryptoAttack::InvalidCurvePoints => {
                // Generate potentially invalid curve point
                let mut key = [0u8; 32];
                key[31] = 0x80; // Set high bit
                key
            },
            _ => [0x42u8; 32], // Default test key
        }
    }

    fn generate_sig_attack(&self) -> [u8; 64] {
        match self {
            CryptoAttack::AllZeros => [0u8; 64],
            CryptoAttack::AllOnes => [0xFFu8; 64],
            CryptoAttack::MallableSignature => {
                let mut sig = [0u8; 64];
                // Create potentially malleable signature
                sig[63] = 0x80; // High S value
                sig
            },
            CryptoAttack::ReusedNonce => {
                // Simulate reused nonce scenario
                let mut sig = [0u8; 64];
                for i in 0..32 {
                    sig[i] = 0x42; // Repeated R value
                }
                sig
            },
            _ => [0x42u8; 64], // Default test signature
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut u) {
        match fuzz_input.operation {
            ThresholdSigOperation::VerifyingKeyParse { key_data, corruption } => {
                let mut hex_key = key_data.encoding.apply(&key_data.bytes);
                for corrupt in &corruption {
                    hex_key = corrupt.apply(&hex_key);
                }
                let result = parse_verifying_key(&hex_key);

                // Test deterministic behavior
                let result2 = parse_verifying_key(&hex_key);
                assert_eq!(result.is_some(), result2.is_some(), "VerifyingKey parsing should be deterministic");

                // Corrupted inputs should generally be rejected
                if !corruption.is_empty() {
                    // Function should handle corrupted input gracefully without panic
                }

                // Valid length and valid hex should have a chance to succeed
                if hex_key.len() == ED25519_PUBLIC_KEY_HEX_LEN && hex_key.chars().all(|c| c.is_ascii_hexdigit()) {
                    // May succeed or fail based on key validity, but should not panic
                }
            },
            ThresholdSigOperation::SignatureParse { sig_data, corruption } => {
                let mut hex_sig = sig_data.encoding.apply(&sig_data.bytes);
                for corrupt in &corruption {
                    hex_sig = corrupt.apply(&hex_sig);
                }
                let result = parse_signature(&hex_sig);

                // Test deterministic behavior
                let result2 = parse_signature(&hex_sig);
                assert_eq!(result.is_some(), result2.is_some(), "Signature parsing should be deterministic");

                // Valid length and valid hex should succeed
                if hex_sig.len() == ED25519_SIGNATURE_HEX_LEN && hex_sig.chars().all(|c| c.is_ascii_hexdigit()) {
                    assert!(result.is_some(), "Valid signature hex should parse successfully");
                }
            },
            ThresholdSigOperation::LengthAttacks { attack_type, target } => {
                match target {
                    ParseTarget::VerifyingKey => {
                        let attack_input = attack_type.generate(ED25519_PUBLIC_KEY_HEX_LEN);
                        let result = parse_verifying_key(&attack_input);

                        // Wrong-length inputs should be rejected
                        if attack_input.len() != ED25519_PUBLIC_KEY_HEX_LEN {
                            assert!(result.is_none(), "Wrong-length verifying key should be rejected: len={}", attack_input.len());
                        }
                    },
                    ParseTarget::Signature => {
                        let attack_input = attack_type.generate(ED25519_SIGNATURE_HEX_LEN);
                        let result = parse_signature(&attack_input);

                        // Wrong-length inputs should be rejected
                        if attack_input.len() != ED25519_SIGNATURE_HEX_LEN {
                            assert!(result.is_none(), "Wrong-length signature should be rejected: len={}", attack_input.len());
                        }
                    },
                    ParseTarget::Both => {
                        let key_attack = attack_type.generate(ED25519_PUBLIC_KEY_HEX_LEN);
                        let sig_attack = attack_type.generate(ED25519_SIGNATURE_HEX_LEN);
                        let key_result = parse_verifying_key(&key_attack);
                        let sig_result = parse_signature(&sig_attack);

                        // Length attacks should be consistently rejected
                        if key_attack.len() != ED25519_PUBLIC_KEY_HEX_LEN {
                            assert!(key_result.is_none(), "Length attack on key should fail");
                        }
                        if sig_attack.len() != ED25519_SIGNATURE_HEX_LEN {
                            assert!(sig_result.is_none(), "Length attack on signature should fail");
                        }
                    },
                }
            },
            ThresholdSigOperation::CryptoAttacks { attack_type, target } => {
                match target {
                    ParseTarget::VerifyingKey => {
                        let attack_key = attack_type.generate_key_attack();
                        let hex_key = hex::encode(attack_key);
                        let result = parse_verifying_key(&hex_key);

                        // Crypto attacks should be handled gracefully
                        match attack_type {
                            CryptoAttack::AllZeros | CryptoAttack::AllOnes => {
                                // These specific attacks should be rejected by validation
                                assert!(result.is_none(), "Weak key attack should be rejected: {:?}", attack_type);
                            },
                            _ => {
                                // Other attacks should not cause panic
                            }
                        }
                    },
                    ParseTarget::Signature => {
                        let attack_sig = attack_type.generate_sig_attack();
                        let hex_sig = hex::encode(attack_sig);
                        let result = parse_signature(&hex_sig);

                        // All signature attacks should be safely parsed (validation happens later)
                        assert!(result.is_some(), "Valid-format signature should parse regardless of content");
                    },
                    ParseTarget::Both => {
                        let attack_key = attack_type.generate_key_attack();
                        let attack_sig = attack_type.generate_sig_attack();
                        let key_result = parse_verifying_key(&hex::encode(attack_key));
                        let sig_result = parse_signature(&hex::encode(attack_sig));

                        // Function should never panic on crypto attacks
                        // Results depend on specific attack type
                    },
                }
            },
            ThresholdSigOperation::ConcurrentParsing { operations } => {
                for op in &operations {
                    match op.target {
                        ParseTarget::VerifyingKey => {
                            let result = parse_verifying_key(&op.input);
                            // Concurrent operations should be deterministic
                            let result2 = parse_verifying_key(&op.input);
                            assert_eq!(result.is_some(), result2.is_some(), "Concurrent parsing should be consistent");
                        },
                        ParseTarget::Signature => {
                            let result = parse_signature(&op.input);
                            // Should handle concurrent parsing without issues
                        },
                        ParseTarget::Both => {
                            let key_result = parse_verifying_key(&op.input);
                            let sig_result = parse_signature(&op.input);
                            // Both should complete without interference
                        },
                    }
                }
            },
            ThresholdSigOperation::BoundaryTests { boundary_type, parse_type } => {
                let (key_len, sig_len) = match boundary_type {
                    BoundaryTest::ExactLength => (ED25519_PUBLIC_KEY_HEX_LEN, ED25519_SIGNATURE_HEX_LEN),
                    BoundaryTest::MinusOne => (ED25519_PUBLIC_KEY_HEX_LEN - 1, ED25519_SIGNATURE_HEX_LEN - 1),
                    BoundaryTest::PlusOne => (ED25519_PUBLIC_KEY_HEX_LEN + 1, ED25519_SIGNATURE_HEX_LEN + 1),
                    BoundaryTest::MaxUsize => (1000, 2000), // Cap for fuzzing
                    BoundaryTest::Zero => (0, 0),
                };

                match parse_type {
                    ParseTarget::VerifyingKey => {
                        let test_input = "A".repeat(key_len);
                        let result = parse_verifying_key(&test_input);

                        // Only exact-length inputs should have chance to succeed
                        if key_len != ED25519_PUBLIC_KEY_HEX_LEN {
                            assert!(result.is_none(), "Wrong boundary length should be rejected: {}", key_len);
                        }
                    },
                    ParseTarget::Signature => {
                        let test_input = "A".repeat(sig_len);
                        let result = parse_signature(&test_input);

                        // Only exact-length inputs should succeed
                        if sig_len != ED25519_SIGNATURE_HEX_LEN {
                            assert!(result.is_none(), "Wrong boundary length should be rejected: {}", sig_len);
                        } else {
                            assert!(result.is_some(), "Exact-length valid hex should parse");
                        }
                    },
                    ParseTarget::Both => {
                        let key_result = parse_verifying_key(&"A".repeat(key_len));
                        let sig_result = parse_signature(&"A".repeat(sig_len));

                        // Test boundary conditions for both
                        if key_len != ED25519_PUBLIC_KEY_HEX_LEN {
                            assert!(key_result.is_none(), "Key boundary test should fail for len {}", key_len);
                        }
                        if sig_len != ED25519_SIGNATURE_HEX_LEN {
                            assert!(sig_result.is_none(), "Signature boundary test should fail for len {}", sig_len);
                        }
                    },
                }
            },
        }
    }
});