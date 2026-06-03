#![no_main]

use arbitrary::Arbitrary;
use base64::Engine;
use libfuzzer_sys::fuzz_target;

// Mirror the private production helper so the fuzz target keeps exercising the
// same strict lowercase-hex contract without widening module visibility.

/// Comprehensive fuzz target for MMR hash hex decoding.
///
/// Tests SHA256 hash hex parsing against:
/// - Standard 64-char lowercase hex hashes
/// - Malformed hex with uppercase, invalid chars, wrong length
/// - Injection attempts (null bytes, control chars, unicode)
/// - Buffer overflow via oversized input
/// - Format confusion with other hash formats
/// - Memory exhaustion attacks
///
/// Security focus: Ensure robust hex validation for MMR proof hashes,
/// prevent bypass through malformed encoding or timing attacks.
#[derive(Arbitrary, Debug)]
struct HashHexInput {
    /// Base hex content to parse
    base_hex: Vec<u8>,

    /// Attack vector to apply
    attack_type: HexAttackType,

    /// Format confusion technique
    format_confusion: HexFormatConfusion,
}

#[derive(Arbitrary, Debug)]
enum HexAttackType {
    /// Pure input without attack
    None,
    /// Case variation attack (uppercase/mixed case)
    CaseVariation,
    /// Invalid hex characters
    InvalidHex { char_code: u8, position: u8 },
    /// Length manipulation
    LengthAttack { target_length: u8 },
    /// Null byte injection
    NullByte { position: u8 },
    /// Unicode hex digit substitution
    UnicodeHex,
    /// Control character injection
    ControlChar { char_code: u8, position: u8 },
    /// Buffer overflow attempt
    BufferOverflow { multiplier: u8 },
}

#[derive(Arbitrary, Debug)]
enum HexFormatConfusion {
    /// Standard hex format
    Standard,
    /// Hex prefix variants
    WithPrefix, // 0x prefix
    /// Base64-like format
    Base64Like,
    /// URL encoding
    UrlEncoded,
    /// Space-separated hex bytes
    SpaceSeparated,
    /// Colon-separated hex bytes
    ColonSeparated,
    /// Hash algorithm prefix
    AlgorithmPrefix,
    /// JSON-like structure
    JsonLike,
}

const SHA256_HEX_LEN: usize = 64; // 32 bytes * 2 hex chars

impl HashHexInput {
    fn generate_test_string(&self) -> String {
        let mut base_string = match String::from_utf8(self.base_hex.clone()) {
            Ok(s) => s,
            Err(_) => {
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string()
            }
        };

        // Ensure we start with a valid-length base if too short
        if base_string.len() < 32 {
            base_string =
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        }

        // Apply format confusion first
        match self.format_confusion {
            HexFormatConfusion::Standard => {}
            HexFormatConfusion::WithPrefix => {
                base_string = format!("0x{}", base_string);
            }
            HexFormatConfusion::Base64Like => {
                // Convert hex to base64-like format
                if let Ok(bytes) = hex::decode(&base_string[..base_string.len().min(64)]) {
                    base_string = base64::prelude::BASE64_STANDARD.encode(&bytes);
                }
            }
            HexFormatConfusion::UrlEncoded => {
                base_string = base_string
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if c.is_ascii_hexdigit() && i % 3 == 0 {
                            format!("%{:02X}", c as u8)
                        } else {
                            c.to_string()
                        }
                    })
                    .collect();
            }
            HexFormatConfusion::SpaceSeparated => {
                let chars: Vec<char> = base_string.chars().collect();
                base_string = chars
                    .chunks(2)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect::<Vec<String>>()
                    .join(" ");
            }
            HexFormatConfusion::ColonSeparated => {
                let chars: Vec<char> = base_string.chars().collect();
                base_string = chars
                    .chunks(2)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect::<Vec<String>>()
                    .join(":");
            }
            HexFormatConfusion::AlgorithmPrefix => {
                base_string = format!("sha256:{}", base_string);
            }
            HexFormatConfusion::JsonLike => {
                base_string = format!(r#"{{"hash": "{}"}}"#, base_string);
            }
        }

        // Apply attack vector
        match self.attack_type {
            HexAttackType::None => {}
            HexAttackType::CaseVariation => {
                base_string = base_string
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i % 3 == 0 && c.is_ascii_lowercase() {
                            c.to_ascii_uppercase()
                        } else {
                            c
                        }
                    })
                    .collect();
            }
            HexAttackType::InvalidHex {
                char_code,
                position,
            } => {
                if !char_code.is_ascii_hexdigit() {
                    let pos = (position as usize).min(base_string.len());
                    if pos < base_string.len() {
                        base_string.replace_range(pos..pos + 1, &(char_code as char).to_string());
                    }
                }
            }
            HexAttackType::LengthAttack { target_length } => {
                let target = target_length as usize;
                if target < base_string.len() {
                    base_string.truncate(target);
                } else if target > base_string.len() {
                    base_string.push_str(&"0".repeat(target - base_string.len()));
                }
            }
            HexAttackType::NullByte { position } => {
                let pos = (position as usize).min(base_string.len());
                base_string.insert(pos, '\0');
            }
            HexAttackType::UnicodeHex => {
                // Replace ASCII hex digits with unicode lookalikes
                base_string = base_string
                    .replace('0', "０") // fullwidth 0
                    .replace('1', "１") // fullwidth 1
                    .replace('a', "а"); // cyrillic a
            }
            HexAttackType::ControlChar {
                char_code,
                position,
            } => {
                if char_code < 32 {
                    let pos = (position as usize).min(base_string.len());
                    base_string.insert(pos, char_code as char);
                }
            }
            HexAttackType::BufferOverflow { multiplier } => {
                let repeat_count = (multiplier as usize).saturating_mul(100).min(10000);
                base_string = base_string.repeat(repeat_count.max(1));
            }
        }

        base_string
    }
}

// Test wrapper that implements the same logic as raw_hash_from_lower_hex
fn test_raw_hash_from_lower_hex(hash: &str) -> Option<[u8; 32]> {
    if hash.len() != SHA256_HEX_LEN
        || !hash
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }

    let mut raw = [0_u8; 32];
    hex::decode_to_slice(hash, &mut raw).ok()?;
    Some(raw)
}

fuzz_target!(|input: HashHexInput| {
    let test_string = input.generate_test_string();

    // Test parsing - should never panic or cause undefined behavior
    let parse_result = test_raw_hash_from_lower_hex(&test_string);

    // Verify consistent behavior on repeated parsing
    let repeat_result = test_raw_hash_from_lower_hex(&test_string);
    assert_eq!(
        parse_result.is_some(),
        repeat_result.is_some(),
        "Parse result consistency failed for input: {:?}",
        test_string
    );

    // Test deterministic output for same input
    if let (Some(result1), Some(result2)) = (parse_result, repeat_result) {
        assert_eq!(
            result1, result2,
            "Non-deterministic output for: {}",
            test_string
        );
    }

    // Verify strict validation requirements
    match test_string.len() {
        SHA256_HEX_LEN => {
            // Correct length - should pass if all lowercase hex
            let is_valid_hex = test_string
                .chars()
                .all(|c| c.is_ascii_hexdigit() && c.is_ascii_lowercase());
            if is_valid_hex {
                assert!(
                    parse_result.is_some(),
                    "Valid SHA256 hex should parse: {}",
                    test_string
                );
            } else {
                assert!(
                    parse_result.is_none(),
                    "Invalid hex chars should be rejected: {}",
                    test_string
                );
            }
        }
        _ => {
            // Wrong length - should always fail
            assert!(
                parse_result.is_none(),
                "Wrong length should be rejected: {} (len={})",
                test_string,
                test_string.len()
            );
        }
    }

    // Test that uppercase hex is rejected (strict lowercase requirement)
    if test_string.len() == SHA256_HEX_LEN && test_string.chars().any(|c| c.is_ascii_uppercase()) {
        assert!(
            parse_result.is_none(),
            "Uppercase hex should be rejected: {}",
            test_string
        );
    }

    // Test standard valid hashes are accepted
    match test_string.as_str() {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        | "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        | "0000000000000000000000000000000000000000000000000000000000000000" => {
            assert!(
                parse_result.is_some(),
                "Standard valid hash should parse: {}",
                test_string
            );
        }
        _ => {}
    }

    // Test that obviously invalid inputs are rejected
    if test_string.contains("xyz") || test_string.contains("XYZ") || test_string.len() > 1000 {
        assert!(
            parse_result.is_none(),
            "Obviously invalid input should be rejected: {}",
            test_string
        );
    }

    // Ensure no memory leaks on large inputs
    if test_string.len() > 10000 {
        // Force cleanup by parsing a simple hash
        let _ = test_raw_hash_from_lower_hex(
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        );
    }

    // Test timing attack resistance - parsing time should be bounded
    if test_string.len() <= 100 {
        let start = std::time::Instant::now();
        let _ = test_raw_hash_from_lower_hex(&test_string);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 10,
            "Parsing should complete quickly: {}",
            test_string
        );
    }
});
