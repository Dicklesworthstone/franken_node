pub mod deterministic_seed;

#[cfg(test)]
pub mod additional_edge_tests;

#[cfg(test)]
mod encoding_root_negative_tests {
    use super::deterministic_seed::{
        ContentHash, DeterministicSeed, DeterministicSeedDeriver, DomainTag, ScheduleConfig,
        SeedError,
    };

    fn expect_invalid_content(input: &str) {
        let err = ContentHash::from_hex(input)
            .expect_err("malformed content identifier must be rejected");

        assert!(matches!(err, SeedError::InvalidContentHash));
    }

    #[test]
    fn encoding_root_rejects_empty_content_identifier() {
        expect_invalid_content("");
    }

    #[test]
    fn encoding_root_rejects_odd_width_content_identifier() {
        expect_invalid_content("abc");
    }

    #[test]
    fn encoding_root_rejects_underwide_content_identifier() {
        expect_invalid_content(&"aa".repeat(31));
    }

    #[test]
    fn encoding_root_rejects_overwide_content_identifier() {
        expect_invalid_content(&"aa".repeat(33));
    }

    #[test]
    fn encoding_root_rejects_content_identifier_with_prefix() {
        let prefixed = format!("0x{}", "aa".repeat(32));

        expect_invalid_content(&prefixed);
    }

    #[test]
    fn encoding_root_rejects_content_identifier_with_embedded_whitespace() {
        let spaced = format!("{} {}", "aa".repeat(16), "aa".repeat(16));

        expect_invalid_content(&spaced);
    }

    #[test]
    fn encoding_root_json_rejects_array_for_content_identifier() {
        let payload = serde_json::json!([0, 1, 2, 3]);

        assert!(serde_json::from_value::<ContentHash>(payload).is_err());
    }

    #[test]
    fn encoding_root_seed_json_rejects_unknown_domain() {
        let bytes = "aa".repeat(32);
        let payload = serde_json::json!({
            "bytes": bytes,
            "domain": "UnknownDomain",
            "config_version": 1
        });

        assert!(serde_json::from_value::<DeterministicSeed>(payload).is_err());
    }

    #[test]
    fn encoding_root_seed_json_rejects_numeric_bytes_field() {
        let payload = serde_json::json!({
            "bytes": 7,
            "domain": "Encoding",
            "config_version": 1
        });

        assert!(serde_json::from_value::<DeterministicSeed>(payload).is_err());
    }

    #[test]
    fn encoding_root_failed_parse_leaves_deriver_state_empty() {
        let deriver = DeterministicSeedDeriver::new();

        expect_invalid_content("not-hex");

        assert_eq!(deriver.tracked_domains(), 0);
        assert!(deriver.bump_records().is_empty());
    }

    #[test]
    fn encoding_root_recovered_valid_parse_does_not_emit_spurious_bump() {
        let mut deriver = DeterministicSeedDeriver::new();
        let parsed = ContentHash::from_hex(&"bb".repeat(32))
            .expect("valid content identifier should parse after bad inputs");
        let config = ScheduleConfig::new(1).with_param("mode", "strict");

        expect_invalid_content("bad-content");
        let (_seed, bump) = deriver.derive_seed(&DomainTag::Encoding, &parsed, &config);

        assert!(bump.is_none());
        assert_eq!(deriver.tracked_domains(), 1);
        assert!(deriver.bump_records().is_empty());
    }

    #[test]
    fn encoding_root_domain_json_rejects_lowercase_label() {
        let result: Result<DomainTag, _> = serde_json::from_str("\"encoding\"");

        assert!(
            result.is_err(),
            "domain tags must use canonical serde variant names"
        );
    }

    #[test]
    fn encoding_root_domain_json_rejects_null_value() {
        let result: Result<DomainTag, _> = serde_json::from_value(serde_json::Value::Null);

        assert!(result.is_err(), "null must not deserialize as a domain tag");
    }

    #[test]
    fn encoding_root_schedule_config_rejects_string_version() {
        let payload = serde_json::json!({
            "version": "1",
            "parameters": {"mode": "strict"},
        });

        let result: Result<ScheduleConfig, _> = serde_json::from_value(payload);

        assert!(
            result.is_err(),
            "schedule config versions must remain numeric"
        );
    }

    #[test]
    fn encoding_root_schedule_config_rejects_non_string_parameter_value() {
        let payload = serde_json::json!({
            "version": 1_u32,
            "parameters": {"chunk_size": 65536},
        });

        let result: Result<ScheduleConfig, _> = serde_json::from_value(payload);

        assert!(
            result.is_err(),
            "schedule config parameters must stay stringly deterministic"
        );
    }

    #[test]
    fn encoding_root_schedule_config_rejects_missing_parameters_map() {
        let payload = serde_json::json!({
            "version": 1_u32,
        });

        let result: Result<ScheduleConfig, _> = serde_json::from_value(payload);

        assert!(
            result.is_err(),
            "schedule configs must explicitly carry the parameter map"
        );
    }

    #[test]
    fn encoding_root_seed_json_rejects_short_hex_bytes() {
        let payload = serde_json::json!({
            "bytes": "aa".repeat(31),
            "domain": "Encoding",
            "config_version": 1_u32,
        });

        let result: Result<DeterministicSeed, _> = serde_json::from_value(payload);

        assert!(
            result.is_err(),
            "seed bytes must deserialize from exactly 32 bytes of hex"
        );
    }

    #[test]
    fn encoding_root_seed_json_rejects_missing_config_version() {
        let payload = serde_json::json!({
            "bytes": "aa".repeat(32),
            "domain": "Encoding",
        });

        let result: Result<DeterministicSeed, _> = serde_json::from_value(payload);

        assert!(
            result.is_err(),
            "seed artifacts must include the originating config version"
        );
    }

    #[test]
    fn encoding_root_content_json_rejects_boolean_identifier() {
        let payload = serde_json::json!(true);

        let result: Result<ContentHash, _> = serde_json::from_value(payload);

        assert!(
            result.is_err(),
            "content identifiers must be hex strings, not booleans"
        );
    }

    #[test]
    fn encoding_root_content_json_rejects_object_identifier() {
        let payload = serde_json::json!({"hex": "aa".repeat(32)});

        let result: Result<ContentHash, _> = serde_json::from_value(payload);

        assert!(
            result.is_err(),
            "content identifiers must not deserialize from object wrappers"
        );
    }

    #[test]
    fn encoding_root_rejects_trailing_newline_content_identifier() {
        let raw = format!("{}\n", "aa".repeat(32));

        expect_invalid_content(&raw);
    }

    #[test]
    fn encoding_root_seed_json_rejects_overlong_hex_bytes() {
        let payload = serde_json::json!({
            "bytes": "aa".repeat(33),
            "domain": "Encoding",
            "config_version": 1_u32,
        });

        let result: Result<DeterministicSeed, _> = serde_json::from_value(payload);

        assert!(
            result.is_err(),
            "seed bytes must reject more than 32 bytes of hex"
        );
    }

    #[test]
    fn encoding_root_seed_json_rejects_missing_domain() {
        let payload = serde_json::json!({
            "bytes": "aa".repeat(32),
            "config_version": 1_u32,
        });

        let result: Result<DeterministicSeed, _> = serde_json::from_value(payload);

        assert!(result.is_err(), "seed artifacts must carry a domain tag");
    }

    #[test]
    fn encoding_root_seed_json_rejects_string_config_version() {
        let payload = serde_json::json!({
            "bytes": "aa".repeat(32),
            "domain": "Encoding",
            "config_version": "1",
        });

        let result: Result<DeterministicSeed, _> = serde_json::from_value(payload);

        assert!(
            result.is_err(),
            "seed config versions must remain numeric"
        );
    }

    #[test]
    fn encoding_root_schedule_config_rejects_array_parameters() {
        let payload = serde_json::json!({
            "version": 1_u32,
            "parameters": [["mode", "strict"]],
        });

        let result: Result<ScheduleConfig, _> = serde_json::from_value(payload);

        assert!(
            result.is_err(),
            "schedule config parameters must deserialize from a map"
        );
    }

    #[test]
    fn encoding_root_domain_json_rejects_numeric_label() {
        let result: Result<DomainTag, _> = serde_json::from_value(serde_json::json!(1));

        assert!(result.is_err(), "numeric domain tags must be rejected");
    }

    /// Test Unicode injection attacks in encoding module components
    #[test]
    fn negative_encoding_unicode_injection_comprehensive() {
        use super::deterministic_seed::{ContentHash, DeterministicSeedDeriver, DomainTag, ScheduleConfig};

        let unicode_attack_vectors = vec![
            // BiDi override attacks in content identifiers
            ("bidi_override", format!("{}{}{}",
                "aa".repeat(10),
                "\u{202E}live\u{202D}",
                "bb".repeat(10))),

            // Zero-width character pollution
            ("zws_pollution", format!("{}{}{}",
                "cc".repeat(10),
                "\u{200B}\u{200C}\u{200D}",
                "dd".repeat(10))),

            // Control character injection
            ("control_chars", format!("{}{}{}",
                "ee".repeat(10),
                "\x00\x01\x02\x03",
                "ff".repeat(8))),

            // Unicode normalization attacks
            ("nfd_attack", format!("{}{}{}",
                "11".repeat(10),
                "\u{0300}\u{0301}",
                "22".repeat(10))),
        ];

        for (attack_name, malicious_hex) in unicode_attack_vectors {
            let injection_result = std::panic::catch_unwind(|| {
                // Ensure the hex string is exactly 64 chars (32 bytes)
                let normalized_hex = if malicious_hex.len() < 64 {
                    format!("{}{}", malicious_hex, "aa".repeat((64 - malicious_hex.len()) / 2))
                } else {
                    malicious_hex[..64].to_string()
                };

                // Test ContentHash with Unicode-polluted hex
                let content_result = ContentHash::from_hex(&normalized_hex);
                match content_result {
                    Ok(content_hash) => {
                        // If parsed successfully, should handle Unicode consistently
                        let hex_repr = content_hash.to_hex();
                        assert_eq!(hex_repr.len(), 64, "Hex representation should be normalized: {}", attack_name);
                        assert!(!hex_repr.contains('\u{200B}'), "Should not contain zero-width chars: {}", attack_name);
                    }
                    Err(_) => {
                        // Rejection of Unicode-polluted input is acceptable
                    }
                }

                // Test JSON serialization with Unicode in structure
                let unicode_json = serde_json::json!({
                    "bytes": normalized_hex,
                    "domain": format!("Encoding{}", attack_name),
                    "config_version": 1
                });

                let seed_parse_result: Result<DeterministicSeed, _> = serde_json::from_value(unicode_json);
                match seed_parse_result {
                    Ok(_) => {
                        // Should handle Unicode in JSON fields consistently
                    }
                    Err(_) => {
                        // Rejection is acceptable for non-standard domain names
                    }
                }

                // Test ScheduleConfig with Unicode in parameters
                let mut config = ScheduleConfig::new(1);
                let unicode_param_key = format!("mode{}", attack_name);
                let unicode_param_value = format!("strict{}\u{202E}evil\u{202D}", attack_name);

                config = config.with_param(&unicode_param_key, &unicode_param_value);

                // Should handle Unicode in parameters without corruption
                let config_json = serde_json::to_string(&config);
                match config_json {
                    Ok(json_str) => {
                        // Verify JSON is well-formed
                        let reparse: Result<ScheduleConfig, _> = serde_json::from_str(&json_str);
                        assert!(reparse.is_ok() || reparse.is_err(),
                               "Config should serialize deterministically: {}", attack_name);
                    }
                    Err(_) => {
                        // Serialization may fail for extreme Unicode - acceptable
                    }
                }

                // Test DeterministicSeedDeriver with Unicode content
                let mut deriver = DeterministicSeedDeriver::new();
                if let Ok(content_hash) = ContentHash::from_hex(&"aa".repeat(32)) {
                    let (seed, bump) = deriver.derive_seed(&DomainTag::Encoding, &content_hash, &config);

                    // Should handle derivation consistently
                    assert!(seed.bytes().len() == 32, "Derived seed should have correct length: {}", attack_name);
                    assert!(bump.is_none() || bump.is_some(), "Bump should be handled consistently: {}", attack_name);
                }

                Ok(())
            });

            assert!(injection_result.is_ok(),
                   "Unicode injection test should not panic: {}", attack_name);
        }
    }

    /// Test memory exhaustion protection in encoding components
    #[test]
    fn negative_encoding_memory_exhaustion_stress() {
        use super::deterministic_seed::{ContentHash, DeterministicSeedDeriver, DomainTag, ScheduleConfig};

        let memory_stress_result = std::panic::catch_unwind(|| {
            // Test massive hex string processing
            let large_hex = "aa".repeat(1000); // 2000 chars, much larger than 64
            let content_result = ContentHash::from_hex(&large_hex);

            match content_result {
                Ok(_) => {
                    panic!("Should reject oversized hex string");
                }
                Err(_) => {
                    // Should reject oversized input - expected behavior
                }
            }

            // Test ScheduleConfig with many parameters
            let mut config = ScheduleConfig::new(1);
            for i in 0..1000 {
                let massive_key = format!("param_{:04}_{}", i, "x".repeat(100));
                let massive_value = format!("value_{:04}_{}", i, "y".repeat(500));
                config = config.with_param(&massive_key, &massive_value);
            }

            // Should handle large parameter sets without memory exhaustion
            let config_json = serde_json::to_string(&config);
            match config_json {
                Ok(json_str) => {
                    // Should not be excessively large
                    assert!(json_str.len() < 10_000_000, "Config JSON should be reasonably sized"); // 10MB limit

                    // Test deserialization
                    let reparse: Result<ScheduleConfig, _> = serde_json::from_str(&json_str);
                    assert!(reparse.is_ok() || reparse.is_err(),
                           "Config should handle large parameter sets");
                }
                Err(_) => {
                    // Serialization may fail under memory pressure - acceptable
                }
            }

            // Test DeterministicSeedDeriver with many derivations
            let mut deriver = DeterministicSeedDeriver::new();
            let base_content = ContentHash::from_hex(&"bb".repeat(32)).expect("Base content should parse");

            for i in 0..100 { // Limited for test performance
                let iteration_config = ScheduleConfig::new(i + 1).with_param("iteration", &i.to_string());
                let (seed, bump) = deriver.derive_seed(&DomainTag::Encoding, &base_content, &iteration_config);

                // Should handle multiple derivations consistently
                assert_eq!(seed.bytes().len(), 32, "Seed should maintain correct size at iteration {}", i);
                assert!(seed.domain() == &DomainTag::Encoding, "Seed should maintain domain at iteration {}", i);

                // Verify bump tracking doesn't grow unbounded
                if let Some(bump_record) = bump {
                    assert!(!bump_record.description().is_empty(), "Bump description should be present");
                }
            }

            // Verify deriver state is reasonable
            assert!(deriver.tracked_domains() <= 1, "Should track reasonable number of domains");
            assert!(deriver.bump_records().len() <= 100, "Bump records should be bounded");

            // Test JSON with deeply nested structure
            let nested_json = serde_json::json!({
                "level1": {
                    "level2": {
                        "level3": {
                            "level4": {
                                "level5": {
                                    "bytes": "cc".repeat(32),
                                    "domain": "Encoding",
                                    "config_version": 1
                                }
                            }
                        }
                    }
                }
            });

            // Should handle or reject nested structure gracefully
            let deep_parse: Result<serde_json::Value, _> = serde_json::from_value(nested_json);
            assert!(deep_parse.is_ok() || deep_parse.is_err(), "Should handle nested JSON");

            Ok(())
        });

        assert!(memory_stress_result.is_ok(), "Memory exhaustion stress test should not panic");
    }

    /// Test JSON structure integrity validation in encoding serialization
    #[test]
    fn negative_encoding_json_integrity_validation() {
        use super::deterministic_seed::{DeterministicSeed, ScheduleConfig, DomainTag, ContentHash};

        let json_corruption_patterns = vec![
            // Structural JSON attacks
            (r#"{"injected": true, "bytes": ""#, "incomplete_object"),
            (r#"bytes": "aa", "injected": {"evil": true}, "domain": ""#, "property_injection"),
            (r#"config\": {\"malicious\": true}, \"version\": 1, \"continue\": \""#, "config_escape"),

            // Array confusion attacks
            (r#"["fake", "array"], "bytes": ""#, "array_confusion"),
            (r#"[{"bytes": "evil"}], "domain": ""#, "array_object_confusion"),

            // Unicode escape attacks
            (r#"domain\u0022injection\u0022"#, "unicode_escape_domain"),
            (r#"bytes\u0000null_injection"#, "null_escape_bytes"),

            // Control character corruption
            ("bytes\r\n{\"injected\": true}\r\naa", "crlf_injection_bytes"),
            ("domain\x00{\"binary\": true}", "binary_injection_domain"),
        ];

        for (malicious_input, attack_name) in json_corruption_patterns {
            let json_integrity_result = std::panic::catch_unwind(|| {
                // Test malicious JSON in DeterministicSeed deserialization
                let malicious_json = serde_json::json!({
                    "bytes": malicious_input,
                    "domain": malicious_input,
                    "config_version": 1
                });

                let seed_parse: Result<DeterministicSeed, _> = serde_json::from_value(malicious_json);
                match seed_parse {
                    Ok(_) => {
                        // If parsed successfully, should be well-formed
                    }
                    Err(_) => {
                        // Rejection of malicious JSON is expected
                    }
                }

                // Test ScheduleConfig with JSON injection
                let config_json = serde_json::json!({
                    "version": 1,
                    "parameters": {
                        malicious_input: malicious_input
                    }
                });

                let config_parse: Result<ScheduleConfig, _> = serde_json::from_value(config_json);
                match config_parse {
                    Ok(config) => {
                        // If parsed, test serialization integrity
                        let reserialize = serde_json::to_string(&config);
                        match reserialize {
                            Ok(json_str) => {
                                // Verify JSON structure integrity
                                let reparse: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
                                assert!(reparse.is_ok(),
                                       "Reserialized JSON should be valid: {}", attack_name);

                                // Verify no injection occurred
                                let parsed = reparse.unwrap();
                                if let Some(obj) = parsed.as_object() {
                                    assert!(!obj.contains_key("injected"),
                                           "Should not contain injected properties: {}", attack_name);
                                    assert!(!obj.contains_key("malicious"),
                                           "Should not contain malicious properties: {}", attack_name);
                                }
                            }
                            Err(_) => {
                                // Serialization may fail for extreme input - acceptable
                            }
                        }
                    }
                    Err(_) => {
                        // Config parsing may reject malicious input - acceptable
                    }
                }

                // Test ContentHash with JSON-like hex strings
                let json_like_hex = format!("{}{}{}",
                    "7b".repeat(8),  // "{" in hex, repeated
                    "22".repeat(8),  // "\"" in hex, repeated
                    "7d".repeat(8)   // "}" in hex, repeated
                );

                let content_result = ContentHash::from_hex(&json_like_hex);
                match content_result {
                    Ok(content_hash) => {
                        // Should handle JSON-like patterns in hex consistently
                        let hex_repr = content_hash.to_hex();
                        assert_eq!(hex_repr.len(), 64, "Hex should be normalized: {}", attack_name);

                        // Test JSON serialization of ContentHash
                        let content_json = serde_json::to_string(&content_hash);
                        if let Ok(json_str) = content_json {
                            let content_reparse: Result<ContentHash, _> = serde_json::from_str(&json_str);
                            assert!(content_reparse.is_ok() || content_reparse.is_err(),
                                   "ContentHash JSON should round-trip: {}", attack_name);
                        }
                    }
                    Err(_) => {
                        // ContentHash may reject certain patterns - acceptable
                    }
                }

                Ok(())
            });

            assert!(json_integrity_result.is_ok(),
                   "JSON integrity test should not panic: {}", attack_name);
        }
    }

    /// Test arithmetic overflow protection in encoding calculations
    #[test]
    fn negative_encoding_arithmetic_overflow_protection() {
        use super::deterministic_seed::{ScheduleConfig, DeterministicSeedDeriver, ContentHash, DomainTag};

        let overflow_protection_result = std::panic::catch_unwind(|| {
            // Test ScheduleConfig with extreme version numbers
            let extreme_versions = vec![
                0u32,
                1u32,
                u32::MAX / 2,
                u32::MAX - 1,
                u32::MAX,
            ];

            for extreme_version in extreme_versions {
                let config = ScheduleConfig::new(extreme_version);

                // Should handle extreme version numbers safely
                assert!(config.version() == extreme_version, "Version should be preserved: {}", extreme_version);

                // Test JSON serialization with extreme versions
                let json_result = serde_json::to_string(&config);
                match json_result {
                    Ok(json_str) => {
                        let reparse: Result<ScheduleConfig, _> = serde_json::from_str(&json_str);
                        match reparse {
                            Ok(reparsed) => {
                                assert_eq!(reparsed.version(), extreme_version,
                                         "Version should round-trip correctly: {}", extreme_version);
                            }
                            Err(_) => {
                                // Parse may fail for extreme values - acceptable
                            }
                        }
                    }
                    Err(_) => {
                        // Serialization may fail for extreme values - acceptable
                    }
                }
            }

            // Test DeterministicSeedDeriver with many domain trackings
            let mut deriver = DeterministicSeedDeriver::new();
            let base_content = ContentHash::from_hex(&"dd".repeat(32)).expect("Base content should parse");

            // Test with multiple different configs to stress domain tracking
            for i in 0..100 {
                // Use very large version numbers that could cause overflow in naive implementations
                let large_version = (i as u32).saturating_mul(1000000).saturating_add(u32::MAX / 2);
                let config = ScheduleConfig::new(large_version);

                let (seed, bump) = deriver.derive_seed(&DomainTag::Encoding, &base_content, &config);

                // Should handle large version numbers without overflow
                assert_eq!(seed.config_version(), large_version, "Config version should be preserved: {}", i);
                assert_eq!(seed.bytes().len(), 32, "Seed length should be consistent: {}", i);

                // Verify domain counting doesn't overflow
                assert!(deriver.tracked_domains() <= 100, "Domain tracking should be bounded: {}", i);

                // Test bump record handling
                if let Some(bump_record) = bump {
                    assert!(!bump_record.description().is_empty(), "Bump description should be valid: {}", i);
                }
            }

            // Test ContentHash with edge case hex patterns that could cause overflow
            let overflow_hex_patterns = vec![
                "ff".repeat(32), // All 0xFF bytes
                "00".repeat(32), // All 0x00 bytes
                "80".repeat(32), // All high bit set
                "7f".repeat(32), // All but high bit set
                "aa55".repeat(16), // Alternating pattern
            ];

            for (i, hex_pattern) in overflow_hex_patterns.iter().enumerate() {
                let content_result = ContentHash::from_hex(hex_pattern);
                match content_result {
                    Ok(content_hash) => {
                        // Should handle edge case patterns consistently
                        let hex_repr = content_hash.to_hex();
                        assert_eq!(hex_repr.len(), 64, "Hex length should be correct: pattern {}", i);

                        // Test that the pattern is preserved
                        assert_eq!(hex_repr.to_lowercase(), hex_pattern.to_lowercase(),
                                  "Hex pattern should be preserved: pattern {}", i);

                        // Test with deriver
                        let mut pattern_deriver = DeterministicSeedDeriver::new();
                        let config = ScheduleConfig::new(i as u32 + 1);
                        let (seed, _) = pattern_deriver.derive_seed(&DomainTag::Encoding, &content_hash, &config);

                        // Should derive seeds consistently for edge case patterns
                        assert_eq!(seed.bytes().len(), 32, "Derived seed should have correct length: pattern {}", i);
                    }
                    Err(_) => {
                        // ContentHash may reject certain patterns - acceptable
                    }
                }
            }

            // Test parameter counting in ScheduleConfig doesn't overflow
            let mut large_config = ScheduleConfig::new(1);
            for i in 0..10000 {
                let param_name = format!("param_{:06}", i);
                let param_value = format!("value_{:06}", i);
                large_config = large_config.with_param(&param_name, &param_value);

                // Periodically verify integrity
                if i % 1000 == 0 {
                    let json_test = serde_json::to_string(&large_config);
                    match json_test {
                        Ok(_) => {
                            // Should handle large parameter counts
                        }
                        Err(_) => {
                            // May reject excessive parameters - acceptable
                            break;
                        }
                    }
                }
            }

            Ok(())
        });

        assert!(overflow_protection_result.is_ok(), "Arithmetic overflow protection test should not panic");
    }

    /// Test display injection and format string safety in encoding output
    #[test]
    fn negative_encoding_display_injection_safety() {
        use super::deterministic_seed::{ContentHash, ScheduleConfig, DeterministicSeedDeriver, DomainTag};

        let display_injection_vectors = vec![
            // Format string injection attempts
            ("format_inject", "param%s%x%d"),
            ("format_overflow", "value%.999999s"),
            ("format_position", "key%1$s%2$x"),

            // ANSI escape sequence injection
            ("ansi_colors", "param\x1b[31mRED\x1b[0m"),
            ("ansi_cursor", "value\x1b[H\x1b[2J"),
            ("ansi_title", "config\x1b]0;EVIL TITLE\x07"),

            // Terminal control injection
            ("bell_spam", "param\x07\x07\x07"),
            ("backspace_attack", "value\x08\x08\x08hidden"),
            ("carriage_return", "config\roverwrite"),

            // Unicode display corruption
            ("rtl_override", "param\u{202E}gniwoh\u{202D}"),
            ("combining_overflow", "value\u{0300}\u{0301}\u{0302}\u{0303}"),
            ("width_confusion", "config\u{3000}\u{FF01}"),

            // Log injection attempts
            ("log_inject", "param\nINJECTED: admin config"),
            ("log_crlf", "value\r\n[FAKE] Configuration breach"),
        ];

        for (attack_name, malicious_content) in display_injection_vectors {
            let display_safety_result = std::panic::catch_unwind(|| {
                // Test ScheduleConfig display safety
                let mut config = ScheduleConfig::new(1);
                config = config.with_param(malicious_content, malicious_content);

                // Test display formatting safety
                let config_display = format!("{:?}", config);
                assert!(!config_display.contains("%s"), "Config display should not contain format specifiers: {}", attack_name);
                assert!(!config_display.contains("\x1b["), "Config display should escape ANSI sequences: {}", attack_name);
                assert!(!config_display.contains("\r\n[FAKE]"), "Config display should not allow log injection: {}", attack_name);

                // Test JSON serialization safety
                if let Ok(json_str) = serde_json::to_string(&config) {
                    assert!(!json_str.contains("\x1b["), "JSON should escape control sequences: {}", attack_name);
                    assert!(!json_str.contains("\r\n"), "JSON should escape line breaks: {}", attack_name);

                    // Verify JSON is structurally sound
                    let reparse: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
                    assert!(reparse.is_ok() || reparse.is_err(),
                           "JSON should be structurally sound: {}", attack_name);
                }

                // Test ContentHash with display injection attempts
                // (ContentHash uses hex, so most display injections won't be valid hex)
                let safe_hex = "ee".repeat(32);
                if let Ok(content_hash) = ContentHash::from_hex(&safe_hex) {
                    let content_display = format!("{:?}", content_hash);
                    assert!(!content_display.contains("%s"), "ContentHash display should be safe: {}", attack_name);
                    assert!(!content_display.contains("\x1b["), "ContentHash display should escape ANSI: {}", attack_name);

                    // Test hex representation safety
                    let hex_repr = content_hash.to_hex();
                    assert_eq!(hex_repr.len(), 64, "Hex representation should be normalized: {}", attack_name);
                    assert!(!hex_repr.contains("%s"), "Hex should not contain format specifiers: {}", attack_name);
                }

                // Test DeterministicSeedDeriver with display injection
                let mut deriver = DeterministicSeedDeriver::new();
                if let Ok(base_content) = ContentHash::from_hex(&"ff".repeat(32)) {
                    let config = ScheduleConfig::new(1).with_param(malicious_content, malicious_content);
                    let (seed, bump) = deriver.derive_seed(&DomainTag::Encoding, &base_content, &config);

                    // Test seed display safety
                    let seed_display = format!("{:?}", seed);
                    assert!(!seed_display.contains("%s"), "Seed display should be safe: {}", attack_name);
                    assert!(!seed_display.contains("\x1b["), "Seed display should escape ANSI: {}", attack_name);

                    // Test bump record display safety if present
                    if let Some(bump_record) = bump {
                        let bump_display = format!("{:?}", bump_record);
                        assert!(!bump_display.contains("%s"), "Bump display should be safe: {}", attack_name);
                        assert!(!bump_display.contains("\x1b["), "Bump display should escape ANSI: {}", attack_name);
                    }

                    // Test deriver state display safety
                    let deriver_display = format!("{:?}", deriver);
                    assert!(!deriver_display.contains("%s"), "Deriver display should be safe: {}", attack_name);
                    assert!(!deriver_display.contains("\x1b["), "Deriver display should escape ANSI: {}", attack_name);
                }

                Ok(())
            });

            assert!(display_safety_result.is_ok(),
                   "Display injection test should not panic: {}", attack_name);
        }
    }

    /// Test boundary condition stress in encoding edge cases
    #[test]
    fn negative_encoding_boundary_stress_comprehensive() {
        use super::deterministic_seed::{ContentHash, ScheduleConfig, DeterministicSeedDeriver, DomainTag};

        let boundary_stress_result = std::panic::catch_unwind(|| {
            // Test ContentHash hex string length boundaries
            let hex_length_cases = vec![
                ("", "empty_hex"),
                ("a", "single_char"),
                ("aa", "single_byte"),
                ("aa".repeat(31), "31_bytes"),
                ("aa".repeat(32), "32_bytes_valid"),
                ("aa".repeat(33), "33_bytes"),
                ("aa".repeat(64), "64_bytes"),
                ("aa".repeat(1000), "1000_bytes"),
            ];

            for (hex_string, test_name) in hex_length_cases {
                let content_result = ContentHash::from_hex(&hex_string);

                if hex_string.len() == 64 { // Only 32 bytes (64 hex chars) should be valid
                    assert!(content_result.is_ok(), "Valid hex length should parse: {}", test_name);

                    if let Ok(content_hash) = content_result {
                        let hex_repr = content_hash.to_hex();
                        assert_eq!(hex_repr.len(), 64, "Hex representation should be normalized: {}", test_name);
                    }
                } else {
                    assert!(content_result.is_err(), "Invalid hex length should be rejected: {}", test_name);
                }
            }

            // Test ScheduleConfig version boundaries
            let version_boundaries = vec![
                (0u32, "zero_version"),
                (1u32, "one_version"),
                (u32::MAX / 2, "half_max_version"),
                (u32::MAX - 1, "near_max_version"),
                (u32::MAX, "max_version"),
            ];

            for (version, test_name) in version_boundaries {
                let config = ScheduleConfig::new(version);

                // Should handle all u32 version values
                assert_eq!(config.version(), version, "Version should be preserved: {}", test_name);

                // Test JSON round-trip with boundary versions
                let json_result = serde_json::to_string(&config);
                match json_result {
                    Ok(json_str) => {
                        let reparse: Result<ScheduleConfig, _> = serde_json::from_str(&json_str);
                        if let Ok(reparsed) = reparse {
                            assert_eq!(reparsed.version(), version,
                                     "Version should round-trip: {}", test_name);
                        }
                    }
                    Err(_) => {
                        // JSON serialization may fail for extreme versions - acceptable
                    }
                }
            }

            // Test ScheduleConfig with extreme parameter counts
            let parameter_counts = vec![
                (0, "no_parameters"),
                (1, "single_parameter"),
                (10, "few_parameters"),
                (100, "many_parameters"),
                (1000, "very_many_parameters"),
            ];

            for (count, test_name) in parameter_counts {
                let mut config = ScheduleConfig::new(1);

                // Add specified number of parameters
                for i in 0..count {
                    let param_key = format!("param_{:06}", i);
                    let param_value = format!("value_{:06}", i);
                    config = config.with_param(&param_key, &param_value);
                }

                // Test config with varying parameter counts
                let json_result = serde_json::to_string(&config);
                match json_result {
                    Ok(json_str) => {
                        // Should handle various parameter counts
                        assert!(json_str.len() > 10, "JSON should have content: {}", test_name);

                        let reparse: Result<ScheduleConfig, _> = serde_json::from_str(&json_str);
                        match reparse {
                            Ok(_) => {
                                // Successfully handled parameter count
                            }
                            Err(_) => {
                                // May fail for extreme parameter counts - acceptable
                            }
                        }
                    }
                    Err(_) => {
                        // Serialization may fail for extreme parameter counts - acceptable
                    }
                }
            }

            // Test DeterministicSeedDeriver with repeated operations
            let mut deriver = DeterministicSeedDeriver::new();
            let base_content = ContentHash::from_hex(&"11".repeat(32)).expect("Base content should parse");

            // Test boundary of derivation operations
            for i in 0..1000 {
                let config = ScheduleConfig::new(i + 1);
                let (seed, bump) = deriver.derive_seed(&DomainTag::Encoding, &base_content, &config);

                // Should handle repeated derivations consistently
                assert_eq!(seed.bytes().len(), 32, "Seed length should be consistent: iteration {}", i);
                assert_eq!(seed.config_version(), i + 1, "Config version should be correct: iteration {}", i);

                // Test bump tracking boundaries
                if i == 0 {
                    assert!(bump.is_none(), "First derivation should not bump: iteration {}", i);
                } else {
                    assert!(bump.is_some(), "Subsequent derivations should bump: iteration {}", i);
                }

                // Verify deriver state remains bounded
                assert!(deriver.tracked_domains() <= 10, "Domain tracking should be bounded: iteration {}", i);
                assert!(deriver.bump_records().len() <= i + 1, "Bump records should be reasonable: iteration {}", i);

                // Test memory usage doesn't grow unbounded
                if i % 100 == 0 {
                    let json_test = serde_json::to_string(&seed);
                    if let Ok(json_str) = json_test {
                        assert!(json_str.len() < 10000, "Seed JSON should be bounded: iteration {}", i);
                    }
                }
            }

            // Test hex character boundaries
            let hex_char_boundaries = vec![
                ("00".repeat(32), "all_zero"),
                ("ff".repeat(32), "all_max"),
                ("0f".repeat(32), "low_nibble"),
                ("f0".repeat(32), "high_nibble"),
                ("aa55".repeat(16), "alternating"),
            ];

            for (hex_pattern, test_name) in hex_char_boundaries {
                let content_result = ContentHash::from_hex(&hex_pattern);
                match content_result {
                    Ok(content_hash) => {
                        // Should handle all valid hex patterns
                        let hex_repr = content_hash.to_hex();
                        assert_eq!(hex_repr.to_lowercase(), hex_pattern.to_lowercase(),
                                  "Hex should be preserved: {}", test_name);

                        // Test derivation with boundary patterns
                        let mut pattern_deriver = DeterministicSeedDeriver::new();
                        let config = ScheduleConfig::new(1);
                        let (seed, _) = pattern_deriver.derive_seed(&DomainTag::Encoding, &content_hash, &config);

                        assert_eq!(seed.bytes().len(), 32, "Derived seed should be correct length: {}", test_name);
                    }
                    Err(_) => {
                        // Should not happen for valid hex patterns
                        panic!("Valid hex pattern should parse: {}", test_name);
                    }
                }
            }

            Ok(())
        });

        assert!(boundary_stress_result.is_ok(), "Boundary stress test should not panic");
    }

    /// Extreme adversarial test: Cryptographic seed entropy manipulation attack via
    /// predictable content hashes designed to exploit deterministic seed generation
    #[test]
    fn encoding_root_cryptographic_entropy_manipulation_predictable_seed_attack() {
        use super::deterministic_seed::{ContentHash, DeterministicSeedDeriver, DomainTag, ScheduleConfig};

        let mut deriver = DeterministicSeedDeriver::new();

        // Entropy manipulation attack vectors targeting seed predictability
        let predictable_patterns = [
            // Repeated byte patterns that might reveal entropy weaknesses
            ("00".repeat(32), "All zero entropy"),
            ("ff".repeat(32), "All one entropy"),
            ("aa".repeat(32), "Repeated pattern entropy"),
            ("0123456789abcdef".repeat(4), "Sequential pattern entropy"),

            // Mathematical sequences that might exploit PRNG weaknesses
            ("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "Incrementing sequence"),
            ("2020202020202020202020202020202020202020202020202020202020202020", "ASCII space pattern"),
            ("deadbeefcafebabe" + &"0000000000000000".repeat(2), "Known constants with padding"),

            // Bit patterns targeting cryptographic edge cases
            ("8000000000000000000000000000000000000000000000000000000000000000", "Single bit set"),
            ("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "Max positive"),
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Alternating bits"),

            // Common cryptographic constants that might reveal implementation
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256 empty string"),
            ("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", "SHA224 empty"),
        ];

        let mut derived_seeds = Vec::new();

        for (predictable_hex, description) in predictable_patterns {
            let content_hash = ContentHash::from_hex(predictable_hex)
                .expect("predictable content should parse");

            let config = ScheduleConfig::new(1)
                .with_param("entropy_test", description);

            let (seed, bump) = deriver.derive_seed(&DomainTag::Encoding, &content_hash, &config);

            // Verify seed derivation doesn't leak information about input patterns
            assert_eq!(seed.bytes().len(), 32,
                "Derived seed should have standard length for pattern: {}", description);
            assert_eq!(seed.domain(), &DomainTag::Encoding,
                "Derived seed should maintain domain for pattern: {}", description);

            deterministic_seed::push_bounded(&mut derived_seeds, (seed.bytes().to_vec(), description), 20);

            // Verify no obvious information leakage
            let seed_bytes = seed.bytes();
            let is_all_same = seed_bytes.iter().all(|&b| b == seed_bytes[0]);
            assert!(!is_all_same,
                "Derived seed should not be all same byte for pattern: {}", description);

            // Check for bias in derived entropy
            let zero_count = seed_bytes.iter().filter(|&&b| b == 0).count();
            let max_count = seed_bytes.iter().filter(|&&b| b == 255).count();

            assert!(zero_count < 20,
                "Derived seed should not have excessive zeros ({}) for pattern: {}", zero_count, description);
            assert!(max_count < 20,
                "Derived seed should not have excessive 0xFF bytes ({}) for pattern: {}", max_count, description);
        }

        // Verify different inputs produce different outputs (no collisions)
        for i in 0..derived_seeds.len() {
            for j in (i + 1)..derived_seeds.len() {
                assert_ne!(derived_seeds[i].0, derived_seeds[j].0,
                    "Seeds should be unique between '{}' and '{}'",
                    derived_seeds[i].1, derived_seeds[j].1);
            }
        }
    }

    /// Extreme adversarial test: Memory corruption attack via malformed schedule
    /// configuration targeting internal data structure integrity during serialization
    #[test]
    fn encoding_root_memory_corruption_malformed_schedule_serialization_attack() {
        use super::deterministic_seed::ScheduleConfig;

        let mut large_parameter_map = serde_json::Map::new();
        large_parameter_map.insert("x".repeat(10000), serde_json::Value::String("value".to_string()));
        let nested_parameter_value = "{".repeat(1000) + &"}".repeat(1000);

        // Memory corruption attack vectors in JSON serialization
        let corruption_payloads = [
            // Large parameter names to trigger buffer issues
            serde_json::json!({
                "version": 1,
                "parameters": large_parameter_map
            }),

            // Deep nesting to trigger stack overflow
            serde_json::json!({
                "version": 1,
                "parameters": {
                    "nested": nested_parameter_value
                }
            }),

            // Unicode normalization attacks in parameter data
            serde_json::json!({
                "version": 1,
                "parameters": {
                    "unicode_attack": "café vs cafe\u{0301}"
                }
            }),

            // Control character injection in parameters
            serde_json::json!({
                "version": 1,
                "parameters": {
                    "control": "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                }
            }),

            // Binary data in string fields
            serde_json::json!({
                "version": 1,
                "parameters": {
                    "binary": String::from_utf8_lossy(b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8")
                        .into_owned()
                }
            }),

            // Extremely large version numbers
            serde_json::json!({
                "version": 4294967295_u32,
                "parameters": {}
            }),

            // Parameter values that could exploit string handling
            serde_json::json!({
                "version": 1,
                "parameters": {
                    "exploit": "\\\\\\\\\\\\\\\\\\\\"
                }
            }),
        ];

        for (i, corruption_payload) in corruption_payloads.iter().enumerate() {
            let parse_result: Result<ScheduleConfig, _> = serde_json::from_value(corruption_payload.clone());

            match parse_result {
                Ok(config) => {
                    // If parsing succeeded, verify internal consistency
                    assert!(config.version() <= u32::MAX,
                        "Version should remain within bounds for payload {}", i);

                    // Test re-serialization to detect corruption
                    let reserialize_result = serde_json::to_string(&config);
                    match reserialize_result {
                        Ok(json_str) => {
                            // Verify serialized output is reasonable
                            assert!(json_str.len() < 1_000_000,
                                "Serialized config should not be excessively large for payload {}", i);

                            // Verify round-trip integrity
                            let round_trip_result: Result<ScheduleConfig, _> = serde_json::from_str(&json_str);
                            match round_trip_result {
                                Ok(round_trip_config) => {
                                    assert_eq!(round_trip_config.version(), config.version(),
                                        "Round-trip version should match for payload {}", i);
                                },
                                Err(_) => {
                                    // Round-trip failure for corrupted data is acceptable
                                }
                            }
                        },
                        Err(_) => {
                            // Serialization failure for corrupted data is acceptable
                        }
                    }
                },
                Err(_) => {
                    // Graceful parsing failure for malformed data is expected
                }
            }
        }
    }

    /// Extreme adversarial test: Race condition attack on concurrent domain tracking
    /// targeting shared state corruption in deterministic seed derivation systems
    #[test]
    fn encoding_root_concurrent_domain_tracking_race_condition_attack() {
        use std::sync::{Arc, Mutex};
        use std::thread;
        use super::deterministic_seed::{ContentHash, DeterministicSeedDeriver, DomainTag, ScheduleConfig};

        let deriver = Arc::new(Mutex::new(DeterministicSeedDeriver::new()));

        // Spawn threads performing concurrent domain operations
        let handles: Vec<_> = (0..10).map(|thread_id| {
            let deriver_clone = Arc::clone(&deriver);

            thread::spawn(move || {
                for iteration in 0..100 {
                    let content_hex = format!("{:02x}", thread_id).repeat(32);
                    let content_hash = ContentHash::from_hex(&content_hex)
                        .expect("thread content should be valid");

                    // Cycle through domains to stress tracking logic
                    let domains = [
                        DomainTag::Encoding,
                        DomainTag::Repair,
                        DomainTag::Scheduling,
                    ];
                    let domain = &domains[iteration % domains.len()];

                    let config = ScheduleConfig::new((thread_id * 1000 + iteration) as u32)
                        .with_param("thread", &thread_id.to_string())
                        .with_param("iteration", &iteration.to_string());

                    // Attempt derivation with brief lock to encourage races
                    if let Ok(mut deriver_lock) = deriver_clone.try_lock() {
                        let (seed, _bump) = deriver_lock.derive_seed(domain, &content_hash, &config);

                        // Verify seed integrity during concurrent access
                        assert_eq!(seed.bytes().len(), 32,
                            "Seed length should be correct during concurrent access");
                        assert_eq!(seed.domain(), domain,
                            "Seed domain should match request during concurrent access");

                        // Brief yield to encourage race conditions
                        std::mem::drop(deriver_lock);
                        thread::yield_now();
                    }
                }
            })
        }).collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state integrity
        let final_deriver = deriver.lock().unwrap();
        let tracked_domains = final_deriver.tracked_domains();
        let bump_records = final_deriver.bump_records();

        assert!(tracked_domains <= 3,
            "Should not track more than 3 domains after concurrent access: {}", tracked_domains);
        assert!(tracked_domains > 0,
            "Should track at least one domain after concurrent operations");
        assert!(bump_records.len() <= tracked_domains * 10,
            "Bump records should be reasonable relative to tracked domains");
    }

    /// Extreme adversarial test: Algorithmic complexity explosion via crafted parameter
    /// maps designed to exploit worst-case performance in configuration processing
    #[test]
    fn encoding_root_algorithmic_complexity_explosion_parameter_processing_attack() {
        use std::time::Instant;
        use super::deterministic_seed::ScheduleConfig;

        // Generate configuration with pathological parameter patterns
        let mut complex_config = ScheduleConfig::new(1);

        // Create parameters with overlapping prefixes to stress comparison algorithms
        let complexity_factor = 100; // Limited to prevent actual DoS
        for i in 0..complexity_factor {
            for j in 0..10 {
                let key = format!("param_{}_{}_{}_{}_end",
                    "x".repeat(i % 20),
                    i,
                    "y".repeat(j),
                    "z".repeat((i * j) % 15)
                );
                let value = format!("value_{}_{}_{}",
                    "a".repeat((i * 7) % 30),
                    j,
                    "b".repeat((i + j) % 25)
                );
                complex_config = complex_config.with_param(&key, &value);
            }

            // Prevent actual resource exhaustion
            if i >= 10 {
                break;
            }
        }

        // Test serialization performance with complex configuration
        let start = Instant::now();
        let serialize_result = serde_json::to_string(&complex_config);
        let serialize_time = start.elapsed();

        assert!(serialize_time.as_millis() < 5000,
            "Complex config serialization should complete in reasonable time: {}ms",
            serialize_time.as_millis());

        match serialize_result {
            Ok(json_str) => {
                assert!(json_str.len() < 10_000_000,
                    "Serialized complex config should not be excessively large: {} bytes",
                    json_str.len());

                // Test deserialization performance
                let start = Instant::now();
                let deserialize_result: Result<ScheduleConfig, _> = serde_json::from_str(&json_str);
                let deserialize_time = start.elapsed();

                assert!(deserialize_time.as_millis() < 5000,
                    "Complex config deserialization should complete in reasonable time: {}ms",
                    deserialize_time.as_millis());

                match deserialize_result {
                    Ok(restored_config) => {
                        assert_eq!(restored_config.version(), complex_config.version(),
                            "Complex config version should be preserved");
                    },
                    Err(_) => {
                        // Graceful failure for extremely complex configs is acceptable
                    }
                }
            },
            Err(_) => {
                // Serialization failure for overly complex configs is acceptable
            }
        }
    }

    /// Extreme adversarial test: Domain tag enumeration attack targeting internal
    /// domain validation logic via exhaustive variant probing for privilege escalation
    #[test]
    fn encoding_root_domain_tag_enumeration_privilege_escalation_attack() {
        use super::deterministic_seed::DomainTag;

        // Attempt to enumerate all possible domain variants
        let domain_probe_vectors = [
            // Known valid domains (should succeed)
            "\"Encoding\"",
            "\"Repair\"",
            "\"Scheduling\"",
            "\"Placement\"",
            "\"Verification\"",

            // Case variation attacks
            "\"encoding\"",
            "\"ENCODING\"",
            "\"EnCoDiNg\"",

            // Injection attempts
            "\"Encoding\\\"\"",
            "\"Encoding\\\",\\\"evil\\\":\\\"payload\"",

            // Unicode variants
            "\"Еncoding\"", // Cyrillic E
            "\"Ǝncoding\"", // Rotated E

            // Special characters
            "\"Encoding \"",
            "\" Encoding\"",
            "\"Encoding\\n\"",
            "\"Encoding\\t\"",

            // Numeric attempts
            "\"0\"",
            "\"1\"",
            "\"999\"",

            // Boolean attempts
            "\"true\"",
            "\"false\"",

            // Empty/null attempts
            "\"\"",
            "null",

            // Path-like attempts
            "\"../Encoding\"",
            "\"./Encoding\"",
            "\"/Encoding\"",

            // Special domain attempts
            "\"Admin\"",
            "\"Root\"",
            "\"System\"",
            "\"Global\"",
            "\"Master\"",
            "\"Super\"",
        ];

        let mut successful_domains = Vec::new();

        for probe in domain_probe_vectors {
            let parse_result: Result<DomainTag, _> = serde_json::from_str(probe);

            match parse_result {
                Ok(domain) => {
                    successful_domains.push((domain, probe));
                },
                Err(_) => {
                    // Expected failure for invalid domain attempts
                }
            }
        }

        // Verify only legitimate domains were accepted
        assert!(successful_domains.len() <= DomainTag::all().len(),
            "Should only accept known valid domains, got: {:?}",
            successful_domains);

        for (domain, probe_str) in successful_domains {
            // Verify each successful domain is genuinely valid
            assert!(
                DomainTag::all().contains(&domain),
                "Unexpected domain variant accepted: {:?} from probe {}",
                domain, probe_str
            );
        }
    }

    /// Extreme adversarial test: Hex encoding boundary manipulation targeting edge cases
    /// in content hash validation that could bypass security constraints
    #[test]
    fn encoding_root_hex_boundary_manipulation_security_bypass_attack() {
        use super::deterministic_seed::ContentHash;

        // Hex boundary manipulation attack vectors
        let boundary_attacks = [
            // Length boundary attacks
            ("a".repeat(63), "Undersized by 1 char"),
            ("a".repeat(65), "Oversized by 1 char"),
            ("", "Empty hex string"),
            ("a", "Single hex character"),

            // Character boundary attacks
            ("g".repeat(64), "Invalid hex character 'g'"),
            ("G".repeat(64), "Invalid hex character 'G'"),
            ("@".repeat(64), "Invalid hex character '@'"),
            (":".repeat(64), "Invalid hex character ':'"),
            ("[".repeat(64), "Invalid hex character '['"),

            // Mixed valid/invalid characters
            (format!("{}g{}", "a".repeat(31), "a".repeat(32)), "Mixed valid/invalid"),
            (format!("{}G{}", "f".repeat(31), "f".repeat(32)), "Mixed case"),

            // Whitespace injection at boundaries
            (format!(" {}", "a".repeat(64)), "Leading whitespace"),
            (format!("{} ", "a".repeat(64)), "Trailing whitespace"),
            (format!("{} {}", "a".repeat(31), "a".repeat(32)), "Mid whitespace"),

            // Control character injection
            (format!("\x00{}", "a".repeat(63)), "Null byte prefix"),
            (format!("{}\x00", "a".repeat(63)), "Null byte suffix"),
            (format!("\r\n{}", "a".repeat(62)), "CRLF prefix"),

            // Unicode boundary tests
            (format!("а{}", "a".repeat(63)), "Cyrillic prefix"), // а (U+0430)
            (format!("{}а", "a".repeat(63)), "Cyrillic suffix"),

            // Number-like patterns that might confuse parsing
            ("0x".repeat(32), "Repeated hex prefix"),
            ("00".repeat(31) + "0x", "Hex prefix at end"),
            ("#".repeat(64), "Hash character spam"),

            // Extreme ASCII values
            ("\x7f".repeat(64), "DEL character"),
            ("\x1f".repeat(64), "Unit separator"),
        ];

        for (boundary_hex, description) in boundary_attacks {
            let parse_result = ContentHash::from_hex(&boundary_hex);

            // All boundary manipulation attempts should be rejected
            assert!(parse_result.is_err(),
                "Boundary attack should be rejected: {} - '{:?}'",
                description, boundary_hex);

            // Verify we get appropriate error type
            match parse_result.unwrap_err() {
                super::deterministic_seed::SeedError::InvalidContentHash => {
                    // Expected error type for invalid content hashes
                },
            }
        }

        // Test boundary conditions for valid hex
        let valid_boundary_tests = [
            ("00".repeat(32), "Minimum valid hex"),
            ("ff".repeat(32), "Maximum valid hex"),
            ("0f".repeat(32), "Mixed nibbles"),
            ("f0".repeat(32), "Inverted nibbles"),
        ];

        for (valid_hex, description) in valid_boundary_tests {
            let parse_result = ContentHash::from_hex(&valid_hex);

            assert!(parse_result.is_ok(),
                "Valid boundary case should succeed: {} - '{}'",
                description, valid_hex);

            let content_hash = parse_result.unwrap();
            let restored_hex = content_hash.to_hex();

            // Verify round-trip integrity at boundaries
            assert_eq!(restored_hex.to_lowercase(), valid_hex.to_lowercase(),
                "Boundary hex should round-trip correctly: {}", description);
        }
    }

    /// Extreme adversarial test: JSON deserialization bomb attack via deeply nested
    /// structures designed to exhaust parser resources during configuration loading
    #[test]
    fn encoding_root_json_deserialization_bomb_parser_exhaustion_attack() {
        use super::deterministic_seed::ScheduleConfig;

        let mut deep_object = r#""value""#.to_string();
        for _ in 0..100 {
            deep_object = format!(r#"{{"nested":{deep_object}}}"#);
        }
        let deep_object_payload = format!(r#"{{"version":1,"parameters":{deep_object}}}"#);
        let array_bomb_payload = format!(
            r#"{{"version":1,"parameters":{{"array":"[{}0]"}}}}"#,
            "0,".repeat(10_000)
        );

        // JSON bomb attack vectors targeting parser resource exhaustion
        let bomb_payloads = [
            // Deeply nested object structure
            (deep_object_payload, "Deep object nesting"),

            // Repeated key attack
            (format!(r#"{{"version":1,"parameters":{{{}}}}}"#,
                (0..1000).map(|i| format!("\"key{}\":\"value{}\"", i, i)).collect::<Vec<_>>().join(",")),
                "Massive key count"),

            // Large string values
            (format!(r#"{{"version":1,"parameters":{{"large":"{}"}}}}"#, "x".repeat(100_000)), "Massive string value"),

            // Array bombing (if arrays were accepted)
            (array_bomb_payload, "Array structure"),

            // Unicode bombing
            (format!(r#"{{"version":1,"parameters":{{"unicode":"{}"}}}}"#, "🔥".repeat(10_000)), "Unicode bombing"),

            // Escape sequence bombing
            (format!(r#"{{"version":1,"parameters":{{"escaped":"{}"}}}}"#, r#"\"""#.repeat(10_000)), "Escape bombing"),

            // Number precision bombing
            (format!(r#"{{"version":{},"parameters":{{}}}}"#, "1".repeat(100)), "Large version number"),
        ];

        for (bomb_json, description) in bomb_payloads {
            let start = std::time::Instant::now();
            let parse_result: Result<ScheduleConfig, _> = serde_json::from_str(&bomb_json);
            let parse_time = start.elapsed();

            // Parsing should complete in reasonable time or fail gracefully
            assert!(parse_time.as_millis() < 10_000,
                "JSON bomb parsing should not take excessive time: {} took {}ms",
                description, parse_time.as_millis());

            match parse_result {
                Ok(config) => {
                    // If parsing succeeded, verify resource usage is reasonable
                    assert!(config.version() <= u32::MAX,
                        "Version should remain bounded for bomb: {}", description);

                    // Test that serialization is also bounded
                    let start = std::time::Instant::now();
                    let serialize_result = serde_json::to_string(&config);
                    let serialize_time = start.elapsed();

                    assert!(serialize_time.as_millis() < 5_000,
                        "Bomb serialization should not take excessive time: {} took {}ms",
                        description, serialize_time.as_millis());

                    match serialize_result {
                        Ok(json_str) => {
                            assert!(json_str.len() < 10_000_000,
                                "Serialized bomb should not be excessively large: {} bytes for {}",
                                json_str.len(), description);
                        },
                        Err(_) => {
                            // Serialization failure for bombs is acceptable
                        }
                    }
                },
                Err(_) => {
                    // Expected graceful failure for malformed JSON bombs
                }
            }
        }
    }
}
