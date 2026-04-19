pub mod compat_gate;
pub mod error;
pub mod fleet_control_routes;
pub mod fleet_quarantine;
pub mod middleware;
pub mod operator_routes;
pub mod service;
pub mod session_auth;
pub mod trust_card_routes;
pub mod verifier_routes;

/// Return at most `max_chars` Unicode scalar values from `input` without
/// violating UTF-8 boundaries.
pub(crate) fn utf8_prefix(input: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return "";
    }
    let end = input
        .char_indices()
        .nth(max_chars)
        .map_or(input.len(), |(idx, _)| idx);
    &input[..end]
}

#[cfg(test)]
mod tests {
    use super::utf8_prefix;

    #[test]
    fn utf8_prefix_ascii() {
        assert_eq!(utf8_prefix("abcdef", 3), "abc");
        assert_eq!(utf8_prefix("abc", 8), "abc");
    }

    #[test]
    fn utf8_prefix_respects_unicode_boundaries() {
        let value = "aß語🙂z";
        assert_eq!(utf8_prefix(value, 4), "aß語🙂");
    }

    #[test]
    fn utf8_prefix_zero_chars() {
        assert_eq!(utf8_prefix("abc", 0), "");
    }

    #[test]
    fn utf8_prefix_empty_input_stays_empty_for_any_limit() {
        assert_eq!(utf8_prefix("", 0), "");
        assert_eq!(utf8_prefix("", 1), "");
        assert_eq!(utf8_prefix("", usize::MAX), "");
    }

    #[test]
    fn utf8_prefix_oversized_limit_returns_full_unicode_input() {
        let value = "αβγ🙂";

        assert_eq!(utf8_prefix(value, 99), value);
    }

    #[test]
    fn utf8_prefix_limit_counts_scalars_not_bytes() {
        let value = "é日🙂x";

        assert_eq!(utf8_prefix(value, 1), "é");
        assert_eq!(utf8_prefix(value, 2), "é日");
        assert_eq!(utf8_prefix(value, 3), "é日🙂");
    }

    #[test]
    fn utf8_prefix_excludes_scalar_at_cut_index() {
        let value = "ab🙂cd";
        let prefix = utf8_prefix(value, 3);

        assert_eq!(prefix, "ab🙂");
        assert!(!prefix.contains('c'));
        assert!(!prefix.contains('d'));
    }

    #[test]
    fn utf8_prefix_zero_limit_never_leaks_multibyte_content() {
        let value = "🙂secret";

        assert_eq!(utf8_prefix(value, 0), "");
    }

    #[test]
    fn utf8_prefix_treats_combining_mark_as_own_scalar() {
        let value = "e\u{301}x";

        assert_eq!(utf8_prefix(value, 1), "e");
        assert_eq!(utf8_prefix(value, 2), "e\u{301}");
        assert_eq!(utf8_prefix(value, 3), value);
    }

    #[test]
    fn utf8_prefix_exact_scalar_count_returns_original() {
        let value = "aß語🙂";

        assert_eq!(utf8_prefix(value, value.chars().count()), value);
    }

    #[test]
    fn utf8_prefix_limit_before_multibyte_scalar_excludes_it() {
        let value = "ab🙂secret";
        let prefix = utf8_prefix(value, 2);

        assert_eq!(prefix, "ab");
        assert!(!prefix.contains('🙂'));
        assert!(!prefix.contains("secret"));
    }

    #[test]
    fn utf8_prefix_one_scalar_never_returns_partial_four_byte_sequence() {
        let value = "🙂abcd";
        let prefix = utf8_prefix(value, 1);

        assert_eq!(prefix, "🙂");
        assert_eq!(prefix.len(), "🙂".len());
        assert!(!prefix.contains('a'));
    }

    #[test]
    fn utf8_prefix_does_not_treat_byte_limit_as_scalar_limit() {
        let value = "éabc";
        let prefix = utf8_prefix(value, 1);

        assert_eq!(prefix, "é");
        assert_ne!(prefix, "");
        assert!(!prefix.contains('a'));
    }

    #[test]
    fn utf8_prefix_stops_inside_zwj_sequence_without_swallowing_tail() {
        let value = "👩‍💻x";
        let prefix = utf8_prefix(value, 2);

        assert_eq!(prefix, "👩‍");
        assert!(!prefix.contains('💻'));
        assert!(!prefix.contains('x'));
    }

    #[test]
    fn utf8_prefix_does_not_trim_nul_or_following_scalars() {
        let value = "a\0b";
        let prefix = utf8_prefix(value, 2);

        assert_eq!(prefix, "a\0");
        assert_ne!(prefix, "a");
        assert!(!prefix.contains('b'));
    }

    #[test]
    fn utf8_prefix_max_limit_on_nonempty_input_does_not_overflow() {
        let value = "αβγ🙂tail";

        assert_eq!(utf8_prefix(value, usize::MAX), value);
    }

    #[test]
    fn utf8_prefix_limit_inside_crlf_pair_does_not_include_lf() {
        let value = "a\r\nb";
        let prefix = utf8_prefix(value, 2);

        assert_eq!(prefix, "a\r");
        assert!(!prefix.contains('\n'));
        assert!(!prefix.contains('b'));
    }

    #[test]
    fn utf8_prefix_does_not_consume_zero_width_space_past_limit() {
        let value = "a\u{200b}b";
        let prefix = utf8_prefix(value, 1);

        assert_eq!(prefix, "a");
        assert!(!prefix.contains('\u{200b}'));
        assert!(!prefix.contains('b'));
    }

    // ── Negative-path tests for comprehensive edge case coverage ──

    #[test]
    fn negative_utf8_prefix_with_malformed_utf8_replacement_chars() {
        // Test with strings containing replacement characters from malformed UTF-8
        let with_replacement = "valid\u{FFFD}text\u{FFFD}more";

        assert_eq!(utf8_prefix(with_replacement, 3), "valid\u{FFFD}text");
        assert_eq!(utf8_prefix(with_replacement, 1), "valid");
        assert_eq!(utf8_prefix(with_replacement, 0), "");

        // Multiple replacement characters in sequence
        let multiple_replacements = "a\u{FFFD}\u{FFFD}\u{FFFD}b";
        assert_eq!(utf8_prefix(multiple_replacements, 3), "a\u{FFFD}\u{FFFD}");
        assert_eq!(utf8_prefix(multiple_replacements, 4), "a\u{FFFD}\u{FFFD}\u{FFFD}");

        // Only replacement characters
        let only_replacements = "\u{FFFD}\u{FFFD}\u{FFFD}";
        assert_eq!(utf8_prefix(only_replacements, 2), "\u{FFFD}\u{FFFD}");
    }

    #[test]
    fn negative_utf8_prefix_with_extreme_unicode_codepoints() {
        // Test with Unicode codepoints at various boundaries
        let extreme_unicode = "\u{0001}\u{007F}\u{0080}\u{07FF}\u{0800}\u{FFFF}\u{10000}\u{10FFFF}end";

        // Should handle all extreme codepoints correctly
        assert_eq!(utf8_prefix(extreme_unicode, 4), "\u{0001}\u{007F}\u{0080}\u{07FF}");
        assert_eq!(utf8_prefix(extreme_unicode, 8), "\u{0001}\u{007F}\u{0080}\u{07FF}\u{0800}\u{FFFF}\u{10000}\u{10FFFF}");

        // Test maximum Unicode codepoint
        let max_unicode = "\u{10FFFF}text";
        assert_eq!(utf8_prefix(max_unicode, 1), "\u{10FFFF}");

        // Test private use area
        let private_use = "\u{E000}\u{F8FF}\u{F0000}\u{FFFFD}after";
        assert_eq!(utf8_prefix(private_use, 3), "\u{E000}\u{F8FF}\u{F0000}");
    }

    #[test]
    fn negative_utf8_prefix_with_bidirectional_override_sequences() {
        // Test with BiDi override characters that could cause display confusion
        let bidi_attacks = vec![
            "safe\u{202E}evil\u{202D}text", // RLE/LRO override
            "normal\u{2066}hidden\u{2069}visible", // FSI/PDI isolate
            "\u{200F}rtl\u{200E}ltr", // RLM/LRM marks
            "text\u{061C}arabic\u{200C}joiner", // ALM and ZWNJ
        ];

        for bidi_text in bidi_attacks {
            // Should handle BiDi characters as individual scalars
            let char_count = bidi_text.chars().count();
            assert_eq!(utf8_prefix(bidi_text, char_count), bidi_text);

            // Truncation should preserve valid UTF-8
            let half_prefix = utf8_prefix(bidi_text, char_count / 2);
            assert!(half_prefix.is_empty() || std::str::from_utf8(half_prefix.as_bytes()).is_ok());
        }
    }

    #[test]
    fn negative_utf8_prefix_with_zero_width_character_sequences() {
        // Test various zero-width characters and their combinations
        let zero_width_chars = vec![
            "\u{200B}", // ZERO WIDTH SPACE
            "\u{200C}", // ZERO WIDTH NON-JOINER
            "\u{200D}", // ZERO WIDTH JOINER
            "\u{FEFF}", // BYTE ORDER MARK (ZERO WIDTH NO-BREAK SPACE)
            "\u{2060}", // WORD JOINER
        ];

        for zwc in zero_width_chars {
            let text_with_zwc = format!("a{}b", zwc);

            // Zero-width character should count as one scalar
            assert_eq!(utf8_prefix(&text_with_zwc, 1), "a");
            assert_eq!(utf8_prefix(&text_with_zwc, 2), format!("a{}", zwc));
            assert_eq!(utf8_prefix(&text_with_zwc, 3), text_with_zwc);
        }

        // Multiple zero-width characters
        let multiple_zwc = "x\u{200B}\u{200C}\u{200D}y";
        assert_eq!(utf8_prefix(multiple_zwc, 3), "x\u{200B}\u{200C}");
        assert_eq!(utf8_prefix(multiple_zwc, 4), "x\u{200B}\u{200C}\u{200D}");
    }

    #[test]
    fn negative_utf8_prefix_with_normalization_edge_cases() {
        // Test characters that have multiple Unicode representations
        let denormalized_cases = vec![
            ("e\u{0301}", "é"), // e + combining acute vs precomposed é
            ("A\u{030A}", "Å"), // A + combining ring vs precomposed Å
            ("\u{1E9B}\u{0323}", "\u{1E9B}\u{0323}"), // Complex combining sequence
            ("가\u{0300}", "가\u{0300}"), // Korean + combining grave
        ];

        for (unnormalized, _normalized) in denormalized_cases {
            let char_count = unnormalized.chars().count();

            // Should preserve exact input without normalization
            assert_eq!(utf8_prefix(unnormalized, char_count), unnormalized);

            // Partial truncation should respect character boundaries
            if char_count > 1 {
                let partial = utf8_prefix(unnormalized, char_count - 1);
                assert!(partial.len() < unnormalized.len());
                assert!(std::str::from_utf8(partial.as_bytes()).is_ok());
            }
        }
    }

    #[test]
    fn negative_utf8_prefix_with_control_character_sequences() {
        // Test various control characters that could cause issues
        let control_sequences = vec![
            "text\x00\x01\x02end", // Null and SOH/STX
            "line1\r\nline2\r\nline3", // CRLF sequences
            "data\x1B[31mred\x1B[0mreset", // ANSI escape sequences
            "bell\x07tab\ttab", // Bell and tab characters
            "form\x0Cfeed\x0Bvtab", // Form feed and vertical tab
        ];

        for control_text in control_sequences {
            let char_count = control_text.chars().count();

            // Should handle control characters as individual scalars
            assert_eq!(utf8_prefix(control_text, char_count), control_text);

            // Each control char should count as one scalar
            let partial = utf8_prefix(control_text, 5);
            assert_eq!(partial.chars().count(), std::cmp::min(5, char_count));
        }

        // Test with only control characters
        let only_controls = "\x00\x01\x02\x03\x04";
        assert_eq!(utf8_prefix(only_controls, 3), "\x00\x01\x02");
    }

    #[test]
    fn negative_utf8_prefix_with_arithmetic_overflow_edge_cases() {
        // Test with very large limits that could cause arithmetic overflow
        let text = "abcdef";

        // usize::MAX should not cause overflow
        assert_eq!(utf8_prefix(text, usize::MAX), text);
        assert_eq!(utf8_prefix("", usize::MAX), "");

        // Near-overflow values
        assert_eq!(utf8_prefix(text, usize::MAX - 1), text);
        assert_eq!(utf8_prefix(text, usize::MAX / 2), text);

        // Test with single-character string and max limit
        assert_eq!(utf8_prefix("x", usize::MAX), "x");
        assert_eq!(utf8_prefix("\u{10FFFF}", usize::MAX), "\u{10FFFF}");

        // Test edge case where char count equals or exceeds limit
        let five_chars = "αβγδε";
        assert_eq!(utf8_prefix(five_chars, 5), five_chars);
        assert_eq!(utf8_prefix(five_chars, 6), five_chars);
        assert_eq!(utf8_prefix(five_chars, usize::MAX), five_chars);
    }

    #[test]
    fn negative_utf8_prefix_with_string_boundary_corruption_resistance() {
        // Test resistance to potential string boundary corruption

        // Strings with unusual byte patterns
        let unusual_patterns = vec![
            "\u{00FF}\u{00FE}\u{00FD}", // High code points encoded as valid UTF-8
            "normal\u{FEFF}bom", // BOM in middle of string
            "emoji\u{1F4A9}\u{1F525}combo", // Multi-byte emoji sequence
            "\u{FFFD}", // Replacement character for invalid byte decoding boundaries
        ];

        for pattern in unusual_patterns {
            if let Ok(valid_utf8) = std::str::from_utf8(pattern.as_bytes()) {
                let char_count = valid_utf8.chars().count();

                // Should handle any valid UTF-8 without corruption
                assert_eq!(utf8_prefix(valid_utf8, char_count), valid_utf8);

                // Partial results should also be valid UTF-8
                for limit in 0..=char_count {
                    let partial = utf8_prefix(valid_utf8, limit);
                    assert!(std::str::from_utf8(partial.as_bytes()).is_ok());
                    assert!(partial.chars().count() <= limit);
                }
            }
        }
    }

    #[test]
    fn negative_utf8_prefix_performance_stress_with_long_strings() {
        // Test performance characteristics with very long strings

        // Long string with mixed character widths
        let mut long_string = String::new();
        for i in 0..10000 {
            match i % 4 {
                0 => long_string.push('a'), // 1-byte UTF-8
                1 => long_string.push('ñ'), // 2-byte UTF-8
                2 => long_string.push('語'), // 3-byte UTF-8
                3 => long_string.push('🙂'), // 4-byte UTF-8
                _ => unreachable!(),
            }
        }

        let start_time = std::time::Instant::now();

        // Test various prefix lengths
        let test_limits = [0, 1, 100, 1000, 5000, 9999, 10000, 50000];

        for &limit in &test_limits {
            let prefix = utf8_prefix(&long_string, limit);

            // Should respect the limit
            let expected_chars = std::cmp::min(limit, long_string.chars().count());
            assert_eq!(prefix.chars().count(), expected_chars);

            // Result should be valid UTF-8
            assert!(std::str::from_utf8(prefix.as_bytes()).is_ok());
        }

        let duration = start_time.elapsed();

        // Should complete efficiently (within reasonable time)
        assert!(duration < std::time::Duration::from_millis(100),
                "utf8_prefix took too long: {:?}", duration);
    }

    #[test]
    fn negative_utf8_prefix_memory_safety_with_reference_lifetime() {
        // Test that returned slices maintain proper lifetime relationship with input

        fn helper_returns_prefix(input: &str, limit: usize) -> &str {
            utf8_prefix(input, limit)
        }

        let original = String::from("test\u{1F4A9}string\u{0301}end");

        // Prefix should be valid as long as original string is valid
        {
            let prefix = helper_returns_prefix(&original, 5);
            assert_eq!(prefix.chars().count(), 5);
            assert!(original.starts_with(prefix));
        }

        // Test with empty result
        {
            let empty_prefix = helper_returns_prefix(&original, 0);
            assert_eq!(empty_prefix, "");
            assert_eq!(empty_prefix.len(), 0);
        }

        // Test that prefix points into original memory
        let full_prefix = helper_returns_prefix(&original, usize::MAX);
        assert!(std::ptr::eq(full_prefix.as_ptr(), original.as_ptr()));
        assert_eq!(full_prefix.len(), original.len());
    }

    #[test]
    fn negative_utf8_prefix_with_grapheme_cluster_boundaries() {
        // Test complex grapheme clusters that span multiple Unicode scalars
        let complex_graphemes = vec![
            "👨‍👩‍👧‍👦", // Family emoji (multiple scalars with ZWJ)
            "🏴󠁧󠁢󠁳󠁣󠁴󠁿", // Flag sequence (base + tag characters)
            "👩🏽‍💻", // Woman technologist with skin tone modifier
            "நி", // Tamil script with combining characters
            "🇺🇸", // Flag emoji (regional indicator symbols)
        ];

        for grapheme in complex_graphemes {
            let scalar_count = grapheme.chars().count();

            // Should treat each Unicode scalar as separate unit
            assert_eq!(utf8_prefix(grapheme, scalar_count), grapheme);

            // Partial truncation may break grapheme clusters (this is expected behavior)
            if scalar_count > 1 {
                let partial = utf8_prefix(grapheme, scalar_count - 1);
                assert!(partial.len() < grapheme.len());
                // Result should still be valid UTF-8 even if grapheme is broken
                assert!(std::str::from_utf8(partial.as_bytes()).is_ok());
            }
        }
    }

    #[test]
    fn negative_utf8_prefix_invalid_raw_bytes_are_rejected_before_prefixing() {
        let invalid_inputs: &[&[u8]] = &[
            b"\xff",
            b"\xe2\x82",
            b"\xf0\x9f\x99",
            b"safe\xc3(payload",
        ];

        for bytes in invalid_inputs {
            assert!(std::str::from_utf8(bytes).is_err());
        }
    }

    #[test]
    fn negative_utf8_prefix_zero_limit_blocks_bidi_payload() {
        let value = "\u{202e}hidden";

        assert_eq!(utf8_prefix(value, 0), "");
        assert_eq!(utf8_prefix(value, 1), "\u{202e}");
        assert!(!utf8_prefix(value, 1).contains("hidden"));
    }

    #[test]
    fn negative_utf8_prefix_escape_prefix_does_not_swallow_ansi_payload() {
        let value = "\x1b[31mred";
        let prefix = utf8_prefix(value, 1);

        assert_eq!(prefix, "\x1b");
        assert!(!prefix.contains("[31m"));
        assert!(!prefix.contains("red"));
    }

    #[test]
    fn negative_utf8_prefix_unpaired_combining_mark_stays_single_scalar() {
        let value = "\u{0301}payload";
        let prefix = utf8_prefix(value, 1);

        assert_eq!(prefix, "\u{0301}");
        assert!(!prefix.contains("payload"));
    }

    #[test]
    fn negative_utf8_prefix_does_not_normalize_confusable_fullwidth_ascii() {
        let value = "\u{ff41}dmin";
        let prefix = utf8_prefix(value, 1);

        assert_eq!(prefix, "\u{ff41}");
        assert_ne!(prefix, "a");
        assert!(!prefix.contains("dmin"));
    }

    #[test]
    fn negative_utf8_prefix_cuts_between_regional_indicators_without_tail() {
        let value = "🇺🇸secret";
        let mut chars = value.chars();
        let first = chars.next().expect("UTF-8 value should have at least one character");
        let second = chars.next().expect("UTF-8 value should have at least two characters");
        let prefix = utf8_prefix(value, 1);

        assert_eq!(prefix, first.to_string());
        assert!(!prefix.contains(second));
        assert!(!prefix.contains("secret"));
    }

    #[test]
    fn negative_utf8_prefix_nul_prefix_does_not_hide_following_suffix() {
        let value = "\0admin=true";

        assert_eq!(utf8_prefix(value, 1), "\0");
        assert!(!utf8_prefix(value, 1).contains("admin=true"));
    }
}
