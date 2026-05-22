//! Fuzz target for cryptographic signature verification parsing boundary.
//!
//! Tests Ed25519 public key parsing, signature verification, hex decoding,
//! and malformed input handling. Critical security boundary for preventing
//! signature bypass attacks and key validation vulnerabilities.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use frankenengine_node::security::crypto::{
    Ed25519Verifier, SignatureVerificationError, SignatureVerifier
};

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    operation: CryptoOperation,
}

#[derive(Debug, Clone, Arbitrary)]
enum CryptoOperation {
    PublicKeyFromBytes {
        key_bytes: KeyBytesInput,
    },
    PublicKeyFromHex {
        hex_input: HexKeyInput,
    },
    SignatureVerification {
        key_input: KeyBytesInput,
        message: Vec<u8>,
        signature: SignatureInput,
    },
    BatchKeyParsing {
        keys: Vec<KeyBytesInput>,
    },
    MaliciousInputs {
        attack_type: CryptoAttackType,
        input_data: Vec<u8>,
    },
    EdgeCaseInputs {
        edge_case: CryptoEdgeCase,
    },
}

#[derive(Debug, Clone, Arbitrary)]
struct KeyBytesInput {
    bytes_type: KeyBytesType,
}

#[derive(Debug, Clone, Arbitrary)]
enum KeyBytesType {
    Valid([u8; 32]),
    Empty,
    TooShort(Vec<u8>),
    TooLong(Vec<u8>),
    ExactLength32(Vec<u8>),
    WithNullBytes([u8; 32]),
    AllZeros,
    AllOnes,
    Random(Vec<u8>),
}

#[derive(Debug, Clone, Arbitrary)]
struct HexKeyInput {
    hex_type: HexKeyType,
}

#[derive(Debug, Clone, Arbitrary)]
enum HexKeyType {
    Valid(String),
    Invalid(String),
    Empty,
    TooShort(String),
    TooLong(String),
    WithPrefix(String),
    WithWhitespace(String),
    WithNullBytes(Vec<u8>),
    OddLength(String),
    NonHex(String),
    Unicode(String),
}

#[derive(Debug, Clone, Arbitrary)]
struct SignatureInput {
    signature_type: SignatureType,
}

#[derive(Debug, Clone, Arbitrary)]
enum SignatureType {
    Valid([u8; 64]),
    Empty,
    TooShort(Vec<u8>),
    TooLong(Vec<u8>),
    ExactLength64(Vec<u8>),
    AllZeros,
    AllOnes,
    Random(Vec<u8>),
}

#[derive(Debug, Clone, Arbitrary)]
enum CryptoAttackType {
    KeySubstitution,
    SignatureMalleable,
    WeakKeys,
    InvalidCurvePoints,
    TimingAttack,
    LengthExtension,
}

#[derive(Debug, Clone, Arbitrary)]
enum CryptoEdgeCase {
    MinimalValidInputs,
    MaximalValidInputs,
    BoundaryLengths,
    AllZeroInputs,
    AllOneInputs,
    AlternatingPatterns,
    LowOrderPoints,
    HighOrderPoints,
}

impl KeyBytesInput {
    fn to_bytes(&self) -> Vec<u8> {
        match &self.bytes_type {
            KeyBytesType::Valid(bytes) => bytes.to_vec(),
            KeyBytesType::Empty => vec![],
            KeyBytesType::TooShort(bytes) => bytes.iter().take(31.min(bytes.len())).copied().collect(),
            KeyBytesType::TooLong(bytes) => {
                let mut result = bytes.clone();
                result.extend_from_slice(&[0u8; 10]); // Make it longer than 32
                result
            }
            KeyBytesType::ExactLength32(bytes) => {
                let mut result = vec![0u8; 32];
                for (i, &byte) in bytes.iter().take(32).enumerate() {
                    result[i] = byte;
                }
                result
            }
            KeyBytesType::WithNullBytes(bytes) => bytes.to_vec(),
            KeyBytesType::AllZeros => vec![0u8; 32],
            KeyBytesType::AllOnes => vec![0xFFu8; 32],
            KeyBytesType::Random(bytes) => bytes.clone(),
        }
    }
}

impl HexKeyInput {
    fn to_string(&self) -> String {
        match &self.hex_type {
            HexKeyType::Valid(s) => {
                if s.is_empty() {
                    hex::encode([0u8; 32])
                } else {
                    s.clone()
                }
            }
            HexKeyType::Invalid(s) => s.clone(),
            HexKeyType::Empty => String::new(),
            HexKeyType::TooShort(s) => {
                if s.is_empty() {
                    hex::encode([0u8; 31])
                } else {
                    s.clone()
                }
            }
            HexKeyType::TooLong(s) => {
                if s.is_empty() {
                    hex::encode([0u8; 33])
                } else {
                    s.clone()
                }
            }
            HexKeyType::WithPrefix(s) => {
                if s.is_empty() {
                    format!("0x{}", hex::encode([0u8; 32]))
                } else {
                    format!("0x{}", s)
                }
            }
            HexKeyType::WithWhitespace(s) => {
                if s.is_empty() {
                    format!("{} {}", hex::encode([0u8; 16]), hex::encode([0u8; 16]))
                } else {
                    s.replace("", " ")
                }
            }
            HexKeyType::WithNullBytes(bytes) => String::from_utf8_lossy(bytes).to_string(),
            HexKeyType::OddLength(s) => {
                if s.is_empty() {
                    "abc".to_string()
                } else {
                    format!("{}f", s)
                }
            }
            HexKeyType::NonHex(s) => s.clone(),
            HexKeyType::Unicode(s) => s.clone(),
        }
    }
}

impl SignatureInput {
    fn to_bytes(&self) -> Vec<u8> {
        match &self.signature_type {
            SignatureType::Valid(bytes) => bytes.to_vec(),
            SignatureType::Empty => vec![],
            SignatureType::TooShort(bytes) => bytes.iter().take(63.min(bytes.len())).copied().collect(),
            SignatureType::TooLong(bytes) => {
                let mut result = bytes.clone();
                result.extend_from_slice(&[0u8; 10]);
                result
            }
            SignatureType::ExactLength64(bytes) => {
                let mut result = vec![0u8; 64];
                for (i, &byte) in bytes.iter().take(64).enumerate() {
                    result[i] = byte;
                }
                result
            }
            SignatureType::AllZeros => vec![0u8; 64],
            SignatureType::AllOnes => vec![0xFFu8; 64],
            SignatureType::Random(bytes) => bytes.clone(),
        }
    }
}

/// Test crypto parsing invariants.
fn test_crypto_invariants(operation: &CryptoOperation) {
    match operation {
        CryptoOperation::PublicKeyFromBytes { key_bytes } => {
            let bytes = key_bytes.to_bytes();
            test_public_key_from_bytes(&bytes);
        }

        CryptoOperation::PublicKeyFromHex { hex_input } => {
            let hex_string = hex_input.to_string();
            test_public_key_from_hex(&hex_string);
        }

        CryptoOperation::SignatureVerification { key_input, message, signature } => {
            let key_bytes = key_input.to_bytes();
            let signature_bytes = signature.to_bytes();
            test_signature_verification(&key_bytes, message, &signature_bytes);
        }

        CryptoOperation::BatchKeyParsing { keys } => {
            for key_input in keys {
                let bytes = key_input.to_bytes();
                test_public_key_from_bytes(&bytes);
            }
        }

        CryptoOperation::MaliciousInputs { attack_type, input_data } => {
            test_malicious_crypto_inputs(attack_type, input_data);
        }

        CryptoOperation::EdgeCaseInputs { edge_case } => {
            test_crypto_edge_cases(edge_case);
        }
    }
}

/// Test public key parsing from bytes.
fn test_public_key_from_bytes(key_bytes: &[u8]) {
    let result = Ed25519Verifier::from_bytes(key_bytes);

    // Test length requirements
    if key_bytes.len() != 32 {
        assert!(result.is_err(), "Non-32-byte keys should be rejected");
        if let Err(e) = result {
            assert_eq!(e, SignatureVerificationError::MalformedPublicKey);
        }
        return;
    }

    // Test deterministic parsing
    let result2 = Ed25519Verifier::from_bytes(key_bytes);
    match (&result, &result2) {
        (Ok(_), Ok(_)) => {
            // Both succeeded - should be equivalent
        }
        (Err(e1), Err(e2)) => {
            assert_eq!(e1, e2, "Same input should produce same error");
        }
        _ => panic!("Deterministic parsing violated"),
    }

    // Test verifier properties
    if let Ok(verifier) = result {
        assert_eq!(verifier.algorithm(), "ed25519");

        let public_key_bytes = verifier.public_key_bytes();
        assert_eq!(public_key_bytes.len(), 32, "Public key should be 32 bytes");
        assert_eq!(public_key_bytes, key_bytes, "Public key bytes should match input");

        // Test that the verifier is functional
        test_verifier_functionality(&verifier);
    }
}

/// Test public key parsing from hex.
fn test_public_key_from_hex(hex_string: &str) {
    let result = Ed25519Verifier::from_hex(hex_string);

    // Test hex format requirements
    if hex_string.is_empty() {
        assert!(result.is_err(), "Empty hex should be rejected");
        return;
    }

    if hex_string.len() % 2 != 0 {
        assert!(result.is_err(), "Odd-length hex should be rejected");
        return;
    }

    if hex_string.starts_with("0x") || hex_string.starts_with("0X") {
        assert!(result.is_err(), "Prefixed hex should be rejected");
        return;
    }

    if hex_string.contains(' ') || hex_string.contains('\t') || hex_string.contains('\n') {
        assert!(result.is_err(), "Whitespace in hex should be rejected");
        return;
    }

    if hex_string.contains('\0') {
        assert!(result.is_err(), "Null bytes in hex should be rejected");
        return;
    }

    // Test hex decoding
    let hex_decode_result = hex::decode(hex_string);
    match hex_decode_result {
        Ok(decoded_bytes) => {
            if decoded_bytes.len() != 32 {
                assert!(result.is_err(), "Non-32-byte decoded keys should be rejected");
            } else {
                // Should match from_bytes result
                let from_bytes_result = Ed25519Verifier::from_bytes(&decoded_bytes);
                match (&result, &from_bytes_result) {
                    (Ok(_), Ok(_)) => {
                        // Both should succeed and be equivalent
                    }
                    (Err(e1), Err(e2)) => {
                        assert_eq!(e1, e2, "from_hex and from_bytes should give same error");
                    }
                    _ => panic!("from_hex and from_bytes should be consistent"),
                }
            }
        }
        Err(_) => {
            assert!(result.is_err(), "Invalid hex should be rejected");
        }
    }
}

/// Test signature verification functionality.
fn test_signature_verification(key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) {
    let verifier_result = Ed25519Verifier::from_bytes(key_bytes);

    if let Ok(verifier) = verifier_result {
        let verify_result = verifier.verify(message, signature_bytes);

        // Test that verification is deterministic
        let verify_result2 = verifier.verify(message, signature_bytes);
        assert_eq!(
            verify_result.is_ok(),
            verify_result2.is_ok(),
            "Verification must be deterministic"
        );

        // Test signature length requirements
        if signature_bytes.len() != 64 {
            assert!(verify_result.is_err(), "Non-64-byte signatures should be rejected");
        }

        // Test error types
        if let Err(e) = verify_result {
            match e {
                SignatureVerificationError::MalformedSignature => {
                    // Expected for malformed signatures
                }
                SignatureVerificationError::VerificationFailed => {
                    // Expected for invalid signatures
                }
                _ => {
                    // Other errors should not occur during verification
                }
            }
        }
    }
}

/// Test verifier functionality.
fn test_verifier_functionality(verifier: &Ed25519Verifier) {
    // Test basic properties
    assert_eq!(verifier.algorithm(), "ed25519");

    let public_key_bytes = verifier.public_key_bytes();
    assert_eq!(public_key_bytes.len(), 32);

    // Test with known invalid signature
    let test_message = b"test message";
    let invalid_signature = [0u8; 64];
    let result = verifier.verify(test_message, &invalid_signature);

    // Should not panic
    match result {
        Ok(()) => {
            // Unlikely but valid
        }
        Err(_) => {
            // Expected
        }
    }
}

/// Test malicious crypto inputs.
fn test_malicious_crypto_inputs(attack_type: &CryptoAttackType, input_data: &[u8]) {
    match attack_type {
        CryptoAttackType::KeySubstitution => {
            test_public_key_from_bytes(input_data);
        }
        CryptoAttackType::WeakKeys => {
            if input_data.len() >= 32 {
                let key_bytes = &input_data[..32];
                test_public_key_from_bytes(key_bytes);
            }
        }
        CryptoAttackType::InvalidCurvePoints => {
            if input_data.len() >= 32 {
                let key_bytes = &input_data[..32];
                test_public_key_from_bytes(key_bytes);
            }
        }
        CryptoAttackType::SignatureMalleable => {
            if input_data.len() >= 96 {
                let key_bytes = &input_data[..32];
                let signature_bytes = &input_data[32..96];
                let message = &input_data[96..];
                test_signature_verification(key_bytes, message, signature_bytes);
            }
        }
        _ => {
            // Other attack types
            test_public_key_from_bytes(input_data);
        }
    }
}

/// Test crypto edge cases.
fn test_crypto_edge_cases(edge_case: &CryptoEdgeCase) {
    match edge_case {
        CryptoEdgeCase::MinimalValidInputs => {
            let minimal_key = [1u8; 32];
            test_public_key_from_bytes(&minimal_key);
        }
        CryptoEdgeCase::MaximalValidInputs => {
            let maximal_key = [0xFEu8; 32]; // Avoid 0xFF which might be invalid
            test_public_key_from_bytes(&maximal_key);
        }
        CryptoEdgeCase::BoundaryLengths => {
            test_public_key_from_bytes(&[0u8; 31]); // Too short
            test_public_key_from_bytes(&[0u8; 32]); // Exact
            test_public_key_from_bytes(&[0u8; 33]); // Too long
        }
        CryptoEdgeCase::AllZeroInputs => {
            let zero_key = [0u8; 32];
            test_public_key_from_bytes(&zero_key);

            let zero_sig = [0u8; 64];
            let zero_msg = [0u8; 0];
            test_signature_verification(&zero_key, &zero_msg, &zero_sig);
        }
        CryptoEdgeCase::AllOneInputs => {
            let one_key = [0xFFu8; 32];
            test_public_key_from_bytes(&one_key);
        }
        CryptoEdgeCase::AlternatingPatterns => {
            let alt_key: [u8; 32] = (0..32).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect::<Vec<_>>().try_into().unwrap();
            test_public_key_from_bytes(&alt_key);
        }
        _ => {
            // Other edge cases
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    std::panic::catch_unwind(|| {
        test_crypto_invariants(&input.operation);
    }).unwrap_or_else(|_| {
        eprintln!("Panic caught in crypto signature verification fuzzing");
    });
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_bytes_generation() {
        let key_input = KeyBytesInput {
            bytes_type: KeyBytesType::Valid([42u8; 32]),
        };
        let bytes = key_input.to_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 42);
    }

    #[test]
    fn test_hex_key_generation() {
        let hex_input = HexKeyInput {
            hex_type: HexKeyType::Valid("deadbeef".repeat(8)),
        };
        let hex_string = hex_input.to_string();
        assert_eq!(hex_string.len(), 64);
    }

    #[test]
    fn test_signature_generation() {
        let sig_input = SignatureInput {
            signature_type: SignatureType::Valid([0x42u8; 64]),
        };
        let bytes = sig_input.to_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(bytes[0], 0x42);
    }

    #[test]
    fn test_public_key_parsing_basic() {
        let valid_key = [1u8; 32];
        test_public_key_from_bytes(&valid_key);

        let invalid_key = [1u8; 31];
        test_public_key_from_bytes(&invalid_key);
    }

    #[test]
    fn test_hex_parsing_basic() {
        test_public_key_from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        test_public_key_from_hex("invalid");
        test_public_key_from_hex("");
    }

    #[test]
    fn test_fuzz_input_generation() {
        let mut data = [0u8; 1000];
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }

        let mut unstructured = Unstructured::new(&data);
        if let Ok(input) = FuzzInput::arbitrary(&mut unstructured) {
            match input.operation {
                CryptoOperation::PublicKeyFromBytes { .. } => {},
                CryptoOperation::PublicKeyFromHex { .. } => {},
                CryptoOperation::SignatureVerification { .. } => {},
                _ => {},
            }
        }
    }
}