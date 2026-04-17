use subtle::ConstantTimeEq;

/// Constant-time string comparison for signature verification.
///
/// Uses the `subtle` crate to avoid timing side-channels and compiler optimization
/// regressions. Validates length first to prevent O(N) Denial of Service attacks
/// where an attacker provides an excessively large input string.
///
/// INV-CT-01: Comparison runtime depends only on input lengths, not content.
#[must_use]
pub fn ct_eq(a: &str, b: &str) -> bool {
    ct_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Constant-time byte slice comparison.
///
/// INV-CT-02: Comparison runtime depends only on input lengths, not content.
#[must_use]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_strings_match() {
        assert!(ct_eq("abc123", "abc123"));
    }

    #[test]
    fn different_strings_do_not_match() {
        assert!(!ct_eq("abc123", "abc124"));
    }

    #[test]
    fn different_lengths_do_not_match() {
        assert!(!ct_eq("abc", "abcd"));
    }

    #[test]
    fn empty_strings_match() {
        assert!(ct_eq("", ""));
    }

    #[test]
    fn first_byte_differs() {
        assert!(!ct_eq("xbc", "abc"));
    }

    #[test]
    fn last_byte_differs() {
        assert!(!ct_eq("abx", "abc"));
    }

    #[test]
    fn ct_eq_bytes_equal() {
        assert!(ct_eq_bytes(b"hello", b"hello"));
    }

    #[test]
    fn ct_eq_bytes_differ() {
        assert!(!ct_eq_bytes(b"hello", b"hellx"));
    }

    #[test]
    fn ct_eq_bytes_different_len() {
        assert!(!ct_eq_bytes(b"abc", b"abcd"));
    }

    #[test]
    fn ct_eq_bytes_empty() {
        assert!(ct_eq_bytes(b"", b""));
    }

    #[test]
    fn ct_eq_bytes_32_equal() {
        let a = [0xABu8; 32];
        assert!(ct_eq_bytes(&a, &a));
    }

    #[test]
    fn ct_eq_bytes_32_last_differs() {
        let a = [0xABu8; 32];
        let mut b = a;
        b[31] = 0xAC;
        assert!(!ct_eq_bytes(&a, &b));
    }

    #[test]
    fn same_length_case_change_does_not_match() {
        assert!(!ct_eq(
            "abcdef0123456789abcdef0123456789",
            "abcdef0123456789abcdef012345678A",
        ));
    }

    #[test]
    fn embedded_nul_difference_does_not_match() {
        assert!(!ct_eq("token\0allow", "token\0deny_"));
    }

    #[test]
    fn prefix_match_with_truncated_digest_does_not_match() {
        let full = [0x42_u8; 32];
        let truncated = [0x42_u8; 31];

        assert!(!ct_eq_bytes(&full, &truncated));
    }

    #[test]
    fn empty_slice_does_not_match_single_nul_byte() {
        assert!(!ct_eq_bytes(b"", b"\0"));
    }

    #[test]
    fn reversed_digest_bytes_do_not_match() {
        let a = [1_u8, 2, 3, 4, 5, 6, 7, 8];
        let b = [8_u8, 7, 6, 5, 4, 3, 2, 1];

        assert!(!ct_eq_bytes(&a, &b));
    }

    #[test]
    fn middle_bit_flip_does_not_match() {
        let a = [0xAA_u8; 32];
        let mut b = a;
        b[16] ^= 0x01;

        assert!(!ct_eq_bytes(&a, &b));
    }

    #[test]
    fn same_prefix_and_suffix_with_middle_difference_does_not_match() {
        assert!(!ct_eq_bytes(
            b"receipt:v1:aaaaaaaa:tail",
            b"receipt:v1:bbbbbbbb:tail",
        ));
    }

    #[test]
    fn leading_space_token_does_not_match() {
        assert!(!ct_eq("bearer abc123", " bearer abc123"));
    }

    #[test]
    fn trailing_space_token_does_not_match() {
        assert!(!ct_eq("bearer abc123", "bearer abc123 "));
    }

    #[test]
    fn separator_substitution_does_not_match() {
        assert!(!ct_eq("scope:read:write", "scope/read/write"));
    }

    #[test]
    fn embedded_newline_substitution_does_not_match() {
        assert!(!ct_eq("claim\nadmin", "claim admin"));
    }

    #[test]
    fn high_bit_byte_pattern_does_not_match_zero_bytes() {
        let left = [0_u8; 16];
        let right = [0x80_u8; 16];

        assert!(!ct_eq_bytes(&left, &right));
    }

    #[test]
    fn common_prefix_with_extra_nul_byte_does_not_match() {
        assert!(!ct_eq_bytes(b"capability-id", b"capability-id\0"));
    }

    #[test]
    fn domain_label_change_does_not_match() {
        assert!(!ct_eq("fn:policy:v1:entry", "fn:policy:v2:entry"));
    }
}

#[cfg(test)]
mod constant_time_additional_negative_tests {
    use super::*;

    #[test]
    fn rejects_same_length_domain_separator_substitution() {
        assert!(!ct_eq(
            "sig:v1:artifact:abcdef012345",
            "mac:v1:artifact:abcdef012345",
        ));
    }

    #[test]
    fn rejects_same_length_hex_digit_transposition() {
        assert!(!ct_eq(
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdeg0123456789abcdee",
        ));
    }

    #[test]
    fn rejects_base64url_alphabet_substitution() {
        assert!(!ct_eq("ABCD-EFG_HIJK", "ABCD+EFG/HIJK"));
    }

    #[test]
    fn rejects_carriage_return_header_smuggling_variant() {
        assert!(!ct_eq("header:value\r\n", "header:value  "));
    }

    #[test]
    fn rejects_first_byte_bit_flip() {
        let left = [0b1010_1010_u8; 24];
        let mut right = left;
        right[0] ^= 0b0000_0001;

        assert!(!ct_eq_bytes(&left, &right));
    }

    #[test]
    fn rejects_length_prefix_collision_shape() {
        assert!(!ct_eq_bytes(b"1:ab2:c", b"1:a2:bc"));
    }

    #[test]
    fn rejects_zero_padded_same_length_payload() {
        let left = [0x41_u8, 0x42, 0x00, 0x00, 0x00, 0x00];
        let right = [0x41_u8, 0x42, 0x00, 0x00, 0x00, 0x01];

        assert!(!ct_eq_bytes(&left, &right));
    }

    #[test]
    fn rejects_case_preserving_scope_reorder() {
        assert!(!ct_eq("scope:read,write,admin", "scope:admin,read,write",));
    }

    #[test]
    fn rejects_delimiter_substitution_with_shared_visible_components() {
        assert!(!ct_eq(
            "role:user;admin:false",
            "role:user:admin:false",
        ));
    }

    #[test]
    fn rejects_trailing_nul_padding_with_same_visible_prefix() {
        assert!(!ct_eq("session-token\0", "session-token "));
    }

    #[test]
    fn rejects_json_boolean_flip_with_equal_serialized_width() {
        assert!(!ct_eq(
            r#"{"admin":false}"#,
            r#"{"admin":true }"#,
        ));
    }

    #[test]
    fn rejects_common_prefix_with_extra_presented_token_tail() {
        assert!(!ct_eq(
            "bearer:abcd1234",
            "bearer:abcd1234:extra",
        ));
    }

    #[test]
    fn rejects_receipt_component_reordering() {
        assert!(!ct_eq(
            "receipt:lane-a:epoch-1",
            "receipt:epoch-1:lane-a",
        ));
    }

    #[test]
    fn rejects_byte_slice_with_single_suffix_bit_flip() {
        let left = [0x5A_u8; 48];
        let mut right = left;
        right[47] ^= 0x04;

        assert!(!ct_eq_bytes(&left, &right));
    }

    #[test]
    fn rejects_empty_secret_against_whitespace_secret() {
        assert!(!ct_eq("", " "));
    }
}

#[cfg(test)]
mod comprehensive_boundary_negative_tests {
    use super::*;

    #[test]
    fn negative_ct_eq_with_maximum_unicode_codepoints() {
        // Test with maximum Unicode codepoint values
        let max_bmp = "\u{FFFF}"; // Maximum Basic Multilingual Plane
        let max_unicode = "\u{10FFFF}"; // Maximum Unicode codepoint
        let emoji_sequence = "🚀🔥💀\u{1F600}"; // Complex emoji sequence

        assert!(!ct_eq(max_bmp, max_unicode));
        assert!(!ct_eq(emoji_sequence, max_bmp));
        assert!(ct_eq(max_unicode, max_unicode)); // Self comparison should work

        // Test with zero-width characters that might be visually identical
        let zero_width_1 = "text\u{200B}more"; // Zero Width Space
        let zero_width_2 = "text\u{FEFF}more"; // Zero Width No-Break Space
        assert!(!ct_eq(zero_width_1, zero_width_2));
    }

    #[test]
    fn negative_ct_eq_bytes_with_large_arrays_different_tail_bytes() {
        // Test with large arrays where only the last few bytes differ
        let mut large_a = vec![0x42u8; 10000];
        let mut large_b = vec![0x42u8; 10000];

        // Modify only the very last bytes
        large_b[9999] = 0x43;
        large_b[9998] = 0x44;

        assert!(!ct_eq_bytes(&large_a, &large_b));

        // Test with same content to ensure it works
        large_a[9999] = 0x43;
        large_a[9998] = 0x44;
        assert!(ct_eq_bytes(&large_a, &large_b));
    }

    #[test]
    fn negative_ct_eq_bytes_with_alternating_bit_patterns() {
        // Test with alternating bit patterns that might expose timing differences
        let pattern_a = [0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55]; // 10101010, 01010101 repeated
        let pattern_b = [0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA]; // 01010101, 10101010 repeated

        assert!(!ct_eq_bytes(&pattern_a, &pattern_b));

        // Test with all ones vs all zeros
        let all_ones = [0xFF; 32];
        let all_zeros = [0x00; 32];
        assert!(!ct_eq_bytes(&all_ones, &all_zeros));
    }

    #[test]
    fn negative_ct_eq_with_control_character_boundary_conditions() {
        // Test with various control characters that might be normalized
        let with_tab = "prefix\tvalue";
        let with_space = "prefix value";
        let with_vtab = "prefix\x0Bvalue";
        let with_newline = "prefix\nvalue";

        assert!(!ct_eq(with_tab, with_space));
        assert!(!ct_eq(with_tab, with_vtab));
        assert!(!ct_eq(with_newline, with_space));

        // Test with carriage return vs newline
        let crlf = "line1\r\nline2";
        let lf = "line1\nline2";
        assert!(!ct_eq(crlf, lf));
    }

    #[test]
    fn negative_ct_eq_with_normalization_attack_vectors() {
        // Test Unicode normalization attack vectors
        let nfc = "café"; // NFC normalized (single é codepoint)
        let nfd = "cafe\u{0301}"; // NFD normalized (e + combining acute accent)

        // These look identical when rendered but are different byte sequences
        assert!(!ct_eq(nfc, nfd));

        // Test with different case folding scenarios
        let turkish_i_upper = "İSTANBUL"; // Turkish capital I with dot
        let turkish_i_lower = "istanbul"; // ASCII lowercase
        assert!(!ct_eq(turkish_i_upper.to_lowercase().as_str(), turkish_i_lower));
    }

    #[test]
    fn negative_ct_eq_bytes_with_memory_alignment_boundaries() {
        // Test with arrays that cross typical memory alignment boundaries
        for size in [1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128] {
            let mut a = vec![0x5A; size];
            let mut b = vec![0x5A; size];

            // Modify the middle byte
            if size > 0 {
                let mid = size / 2;
                b[mid] = 0x5B;
                assert!(!ct_eq_bytes(&a, &b), "Failed at size {}", size);

                // Restore and verify equal
                b[mid] = 0x5A;
                assert!(ct_eq_bytes(&a, &b), "Failed equality check at size {}", size);
            }
        }
    }

    #[test]
    fn negative_ct_eq_with_hash_prefix_collision_attempts() {
        // Test scenarios that might cause hash prefix collisions
        let prefix_a = "hash:sha256:prefix";
        let prefix_b = "hash:sha256:prefi_";
        let prefix_c = "hash:sha25_:prefix";

        assert!(!ct_eq(prefix_a, prefix_b));
        assert!(!ct_eq(prefix_a, prefix_c));

        // Test with common cryptographic prefixes
        let sig_prefix = "signature:rsa:";
        let mac_prefix = "signature:rs_";
        assert!(!ct_eq(sig_prefix, mac_prefix));
    }

    #[test]
    fn negative_ct_eq_with_encoding_boundary_conditions() {
        // Test with different encoding representations of similar data
        let hex_upper = "DEADBEEF";
        let hex_lower = "deadbeef";
        let hex_mixed = "DeAdBeEf";

        assert!(!ct_eq(hex_upper, hex_lower));
        assert!(!ct_eq(hex_upper, hex_mixed));
        assert!(!ct_eq(hex_lower, hex_mixed));

        // Test with base64 padding variations
        let base64_padded = "SGVsbG8=";
        let base64_no_pad = "SGVsbG8";
        assert!(!ct_eq(base64_padded, base64_no_pad));
    }

    #[test]
    fn negative_ct_eq_bytes_with_extreme_length_differences() {
        // Test with extremely different lengths to ensure early return
        let tiny = [0x42];
        let huge = vec![0x42; 65536];

        assert!(!ct_eq_bytes(&tiny, &huge));

        // Test empty vs non-empty with various sizes
        let empty = [];
        for size in [1, 16, 256, 1024] {
            let non_empty = vec![0x00; size];
            assert!(!ct_eq_bytes(&empty, &non_empty));
        }
    }

    #[test]
    fn negative_ct_eq_with_timing_attack_mitigation_verification() {
        // Test patterns that historically were vulnerable to timing attacks

        // Test with early vs late differences in same-length strings
        let early_diff = "aXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let late_diff =  "XXXXXXXXXXXXXXXXXXXXXXXXXXXa";
        let reference = "XXXXXXXXXXXXXXXXXXXXXXXXXXXX";

        assert!(!ct_eq(early_diff, reference));
        assert!(!ct_eq(late_diff, reference));

        // Both should fail in constant time regardless of difference position
        let early_diff_bytes = early_diff.as_bytes();
        let late_diff_bytes = late_diff.as_bytes();
        let reference_bytes = reference.as_bytes();

        assert!(!ct_eq_bytes(early_diff_bytes, reference_bytes));
        assert!(!ct_eq_bytes(late_diff_bytes, reference_bytes));
    }

    #[test]
    fn negative_ct_eq_with_jwt_like_structure_boundary_cases() {
        // Test with JWT-like structures that might be vulnerable to manipulation
        let jwt_valid = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.signature";
        let jwt_header_tamper = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJhdXRoMCJ9.signature";
        let jwt_payload_tamper = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdGFja2VyIn0.signature";
        let jwt_sig_tamper = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.tampered";

        assert!(!ct_eq(jwt_valid, jwt_header_tamper));
        assert!(!ct_eq(jwt_valid, jwt_payload_tamper));
        assert!(!ct_eq(jwt_valid, jwt_sig_tamper));
    }

    #[test]
    fn negative_ct_eq_bytes_with_side_channel_resistant_patterns() {
        // Test patterns specifically designed to verify side-channel resistance

        // Test with Hamming weight variations (different number of 1 bits)
        let low_hamming = [0x01, 0x01, 0x01, 0x01]; // Low Hamming weight
        let high_hamming = [0xFF, 0xFF, 0xFF, 0xFE]; // High Hamming weight

        assert!(!ct_eq_bytes(&low_hamming, &high_hamming));

        // Test with patterns that might trigger different CPU cache behavior
        let cache_line_a = vec![0xA5; 64]; // Typical cache line size
        let mut cache_line_b = vec![0xA5; 64];
        cache_line_b[32] = 0x5A; // Modify middle to avoid early detection

        assert!(!ct_eq_bytes(&cache_line_a, &cache_line_b));
    }
}
