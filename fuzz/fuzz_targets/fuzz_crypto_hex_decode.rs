#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(hex_input) = std::str::from_utf8(data) {
        // Guard against excessively long strings
        if hex_input.len() > 10000 {
            return;
        }

        // Test hex::decode function with arbitrary input
        let decode_result = hex::decode(hex_input);

        match decode_result {
            Ok(decoded_bytes) => {
                // Valid hex decode - verify invariants

                // 1. Decoded length should be half of input length (for valid hex)
                if hex_input.len() % 2 == 0 {
                    assert_eq!(decoded_bytes.len(), hex_input.len() / 2,
                              "Decoded bytes length should be half of hex string length");
                }

                // 2. Re-encoding should produce equivalent result (case-insensitive)
                let re_encoded = hex::encode(&decoded_bytes);
                assert_eq!(hex_input.to_ascii_lowercase(), re_encoded.to_ascii_lowercase(),
                          "Round-trip encoding should be consistent");

                // 3. Decoded bytes should be finite/valid
                for &byte in &decoded_bytes {
                    // All bytes are valid - no invariant needed for u8
                }

                // 4. Test that modifications produce different results
                if !decoded_bytes.is_empty() {
                    let mut modified = decoded_bytes.clone();
                    modified[0] = modified[0].wrapping_add(1);
                    let modified_hex = hex::encode(&modified);
                    assert_ne!(hex_input.to_ascii_lowercase(), modified_hex.to_ascii_lowercase(),
                              "Modified bytes should produce different hex");
                }
            }
            Err(_err) => {
                // Invalid hex decode - verify error handling is consistent

                // 1. Invalid hex should consistently fail
                let result2 = hex::decode(hex_input);
                assert!(result2.is_err(), "Invalid hex should consistently fail");

                // 2. Test common invalid hex patterns
                if hex_input.contains(' ') || hex_input.contains('\n') || hex_input.contains('\t') {
                    // Whitespace should be rejected
                    assert!(hex::decode(hex_input).is_err());
                }

                // 3. Odd length should be rejected for proper hex
                if hex_input.len() % 2 == 1 && hex_input.chars().all(|c| c.is_ascii_hexdigit()) {
                    assert!(hex::decode(hex_input).is_err(), "Odd length hex should fail");
                }
            }
        }

        // Test case-insensitive behavior
        let uppercase = hex_input.to_ascii_uppercase();
        let lowercase = hex_input.to_ascii_lowercase();

        let upper_result = hex::decode(&uppercase);
        let lower_result = hex::decode(&lowercase);

        // Both should succeed or both should fail
        match (upper_result, lower_result) {
            (Ok(upper_bytes), Ok(lower_bytes)) => {
                assert_eq!(upper_bytes, lower_bytes, "Case should not affect decoding result");
            }
            (Err(_), Err(_)) => {
                // Both failed - consistent behavior
            }
            _ => panic!("Case sensitivity inconsistency in hex decoding"),
        }

        // Test edge cases
        if hex_input.is_empty() {
            assert!(hex::decode(hex_input).unwrap().is_empty(), "Empty input should decode to empty");
        }

        // Test with null bytes (should be rejected)
        if hex_input.contains('\0') {
            // Null bytes in hex string should be rejected
            assert!(hex::decode(hex_input).is_err(), "Null bytes should be rejected");
        }
    }
});