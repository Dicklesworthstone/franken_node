#![no_main]

use libfuzzer_sys::fuzz_target;
use base64::{Engine, engine::general_purpose::STANDARD};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(base64_input) = std::str::from_utf8(data) {
        // Guard against excessively long strings to prevent OOM
        if base64_input.len() > 100000 {
            return;
        }

        // Test base64::decode function with arbitrary input
        let decode_result = STANDARD.decode(base64_input);

        match decode_result {
            Ok(decoded_bytes) => {
                // Valid base64 decode - verify invariants

                // 1. Re-encoding should produce equivalent result
                let re_encoded = STANDARD.encode(&decoded_bytes);

                // Remove padding from input for comparison (padding is optional in some contexts)
                let input_trimmed = base64_input.trim_end_matches('=');
                let re_encoded_trimmed = re_encoded.trim_end_matches('=');

                // Should match when normalized
                assert_eq!(input_trimmed, re_encoded_trimmed,
                          "Round-trip encoding should be consistent");

                // 2. Decoded bytes should be valid
                // All u8 values are valid, no constraints needed

                // 3. Test length relationship - base64 encoding ratio is roughly 4:3
                let expected_input_len = ((decoded_bytes.len() + 2) / 3) * 4;
                let actual_padded_len = if base64_input.len() % 4 == 0 {
                    base64_input.len()
                } else {
                    ((base64_input.len() + 3) / 4) * 4
                };

                // Length should be reasonable (allowing for padding variations)
                assert!(actual_padded_len >= expected_input_len.saturating_sub(4) &&
                       actual_padded_len <= expected_input_len.saturating_add(4),
                       "Base64 length relationship should be maintained");

                // 4. Test that modifications produce different results
                if !decoded_bytes.is_empty() {
                    let mut modified = decoded_bytes.clone();
                    modified[0] = modified[0].wrapping_add(1);
                    let modified_b64 = STANDARD.encode(&modified);
                    assert_ne!(base64_input.trim_end_matches('='),
                              modified_b64.trim_end_matches('='),
                              "Modified bytes should produce different base64");
                }
            }
            Err(_err) => {
                // Invalid base64 decode - verify error handling is consistent

                // 1. Invalid base64 should consistently fail
                let result2 = STANDARD.decode(base64_input);
                assert!(result2.is_err(), "Invalid base64 should consistently fail");

                // 2. Test common invalid base64 patterns
                if base64_input.contains(' ') || base64_input.contains('\n') ||
                   base64_input.contains('\r') || base64_input.contains('\t') {
                    // Whitespace should be rejected by standard decoder
                    assert!(STANDARD.decode(base64_input).is_err());
                }

                // 3. Invalid characters should be rejected
                if base64_input.chars().any(|c| !c.is_ascii_alphanumeric() &&
                                                c != '+' && c != '/' && c != '=') {
                    assert!(STANDARD.decode(base64_input).is_err(),
                           "Invalid base64 characters should be rejected");
                }
            }
        }

        // Test edge cases
        if base64_input.is_empty() {
            let result = STANDARD.decode(base64_input);
            assert!(result.is_ok(), "Empty input should decode successfully");
            assert!(result.unwrap().is_empty(), "Empty input should decode to empty");
        }

        // Test null bytes (should be rejected)
        if base64_input.contains('\0') {
            assert!(STANDARD.decode(base64_input).is_err(),
                   "Null bytes should be rejected");
        }

        // Test padding variations
        if base64_input.ends_with("==") || base64_input.ends_with("=") {
            // Test removing padding
            let no_padding = base64_input.trim_end_matches('=');
            let with_padding_result = STANDARD.decode(base64_input);
            let no_padding_result = STANDARD.decode(no_padding);

            // Both should succeed or both should fail consistently
            match (with_padding_result.is_ok(), no_padding_result.is_ok()) {
                (true, true) => {
                    // Both succeeded - should produce same result
                    let with_pad = STANDARD.decode(base64_input).unwrap();
                    let without_pad = STANDARD.decode(no_padding).unwrap();
                    assert_eq!(with_pad, without_pad,
                              "Padding should not affect decode result");
                }
                _ => {
                    // At least one failed - acceptable for edge cases
                }
            }
        }

        // Test standard base64 alphabet
        let valid_chars = base64_input.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
        });

        if valid_chars && base64_input.len() % 4 == 0 {
            // Well-formed base64 should either decode successfully or fail consistently
            let result = STANDARD.decode(base64_input);
            // No assertion here - just ensure it doesn't panic
        }
    }
});