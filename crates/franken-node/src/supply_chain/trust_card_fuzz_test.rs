//! Quick smoke test for trust card snapshot parsing fuzzing
//!
//! This module provides a quick way to test our fuzzing logic without
//! waiting for the full libfuzzer compilation.

#[cfg(test)]
mod tests {
    use crate::supply_chain::trust_card::TrustCardRegistrySnapshot;

    /// Test that the fuzzing target logic works correctly
    #[test]
    fn test_trust_card_snapshot_parse_fuzz_logic() {
        // Test cases that mirror what our fuzz harness will encounter
        let test_cases = vec![
            b"", // Empty
            b"{}", // Minimal JSON
            b"{\"schema_version\":\"test\",\"snapshot_epoch\":123,\"cache_ttl_secs\":300,\"cards_by_extension\":{},\"snapshot_hash\":\"abc\",\"registry_signature\":\"def\"}", // Valid-ish structure
            b"invalid json", // Invalid
            b"\x00\xff\x00\xff", // Binary data
            b"{\"snapshot_epoch\":18446744073709551615}", // Large number
            b"null", // Null
            b"[]", // Array instead of object
            b"{{}}", // Nested empty objects
        ];

        let mut parsed_count = 0;
        let mut error_count = 0;

        for (i, test_data) in test_cases.iter().enumerate() {
            println!(
                "Testing case {}: {:?}",
                i,
                std::str::from_utf8(test_data).unwrap_or("<binary>")
            );

            // Test UTF-8 conversion
            let utf8_result = std::str::from_utf8(test_data);

            // Test JSON parsing if UTF-8 succeeds
            if let Ok(json_str) = utf8_result {
                match serde_json::from_str::<TrustCardRegistrySnapshot>(json_str) {
                    Ok(_) => {
                        parsed_count += 1;
                        println!("  → Parsed successfully");
                    }
                    Err(e) => {
                        error_count += 1;
                        println!("  → Parse error (expected): {}", e);
                    }
                }
            } else {
                println!("  → Invalid UTF-8 (expected)");
                error_count += 1;
            }

            // Test direct byte parsing
            match serde_json::from_slice::<TrustCardRegistrySnapshot>(test_data) {
                Ok(_) => println!("  → Byte parse succeeded"),
                Err(e) => println!("  → Byte parse error (expected): {}", e),
            }

            println!();
        }

        println!(
            "Summary: {} parsed successfully, {} errors",
            parsed_count, error_count
        );

        // We expect mostly errors since most test cases are malformed
        assert!(
            error_count > 0,
            "Should have parsing errors for malformed inputs"
        );

        // Verify that no panics occurred (test itself would have failed)
        println!("✅ No panics occurred during fuzzing logic test");
    }

    /// Test edge cases that could cause issues
    #[test]
    fn test_trust_card_snapshot_parse_edge_cases() {
        // Large JSON string that could cause allocation issues
        let large_string = "A".repeat(50000);
        let large_json = format!("{{\"schema_version\":\"{}\"}}", large_string);

        // Should not panic even if it fails to parse
        let _ = serde_json::from_str::<TrustCardRegistrySnapshot>(&large_json);

        // Deeply nested JSON that could cause stack overflow
        let mut nested = "{}".to_string();
        for _ in 0..100 {
            nested = format!("{{{}}}", nested);
        }

        // Should not panic even with deep nesting
        let _ = serde_json::from_str::<TrustCardRegistrySnapshot>(&nested);

        println!("✅ Edge case tests completed without panics");
    }
}
