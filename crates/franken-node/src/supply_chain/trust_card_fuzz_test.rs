//! Quick smoke test for trust card snapshot parsing fuzzing
//!
//! This module provides a quick way to test our fuzzing logic without
//! waiting for the full libfuzzer compilation.

use frankenengine_node::supply_chain::trust_card::TrustCardRegistrySnapshot;

fn assert_snapshot_roundtrips(snapshot: &TrustCardRegistrySnapshot) {
    let encoded =
        serde_json::to_vec(snapshot).expect("parsed trust-card snapshot should serialize");
    let decoded = serde_json::from_slice::<TrustCardRegistrySnapshot>(&encoded)
        .expect("serialized trust-card snapshot should parse from bytes");
    assert_eq!(
        snapshot, &decoded,
        "trust-card snapshot must survive byte serde roundtrip"
    );

    let encoded_string =
        serde_json::to_string(snapshot).expect("parsed trust-card snapshot should stringify");
    let decoded_string = serde_json::from_str::<TrustCardRegistrySnapshot>(&encoded_string)
        .expect("serialized trust-card snapshot should parse from string");
    assert_eq!(
        snapshot, &decoded_string,
        "trust-card snapshot must survive string serde roundtrip"
    );
}

/// Test that the fuzzing target logic works correctly
#[test]
fn test_trust_card_snapshot_parse_fuzz_logic() {
    // Test cases that mirror what our fuzz harness will encounter
    let test_cases: &[&[u8]] = &[
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
    let mut byte_parsed_count = 0;
    let mut byte_error_count = 0;

    for (i, test_data) in test_cases.iter().enumerate() {
        println!(
            "Testing case {}: {:?}",
            i,
            std::str::from_utf8(test_data).unwrap_or("<binary>")
        );

        // Test UTF-8 conversion
        let utf8_result = std::str::from_utf8(test_data);

        // Test JSON parsing if UTF-8 succeeds
        let parsed_snapshot = if let Ok(json_str) = utf8_result {
            match serde_json::from_str::<TrustCardRegistrySnapshot>(json_str) {
                Ok(snapshot) => {
                    assert_snapshot_roundtrips(&snapshot);
                    parsed_count += 1;
                    println!("  → Parsed successfully");
                    Some(snapshot)
                }
                Err(e) => {
                    error_count += 1;
                    println!("  → Parse error (expected): {}", e);
                    None
                }
            }
        } else {
            println!("  → Invalid UTF-8 (expected)");
            error_count += 1;
            None
        };

        // Test direct byte parsing
        match serde_json::from_slice::<TrustCardRegistrySnapshot>(test_data) {
            Ok(byte_snapshot) => {
                assert_snapshot_roundtrips(&byte_snapshot);
                if let Some(parsed_snapshot) = &parsed_snapshot {
                    assert_eq!(
                        &byte_snapshot, parsed_snapshot,
                        "string and byte parsing must agree for case {i}"
                    );
                }
                byte_parsed_count += 1;
                println!("  → Byte parse succeeded");
            }
            Err(e) => {
                assert!(
                    parsed_snapshot.is_none(),
                    "byte parsing failed after string parsing succeeded for case {i}: {e}"
                );
                byte_error_count += 1;
                println!("  → Byte parse error (expected): {}", e);
            }
        }

        println!();
    }

    println!(
        "Summary: {} string parses, {} string errors, {} byte parses, {} byte errors",
        parsed_count, error_count, byte_parsed_count, byte_error_count
    );

    assert!(
        parsed_count > 0,
        "fuzz smoke corpus should include at least one valid trust-card snapshot"
    );
    assert_eq!(
        parsed_count, byte_parsed_count,
        "string and byte parsing should accept the same trust-card snapshot corpus cases"
    );
    assert_eq!(
        error_count, byte_error_count,
        "string and byte parsing should reject the same malformed corpus cases"
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

    serde_json::from_str::<TrustCardRegistrySnapshot>(&large_json)
        .expect_err("partial snapshot with huge schema_version must be rejected");

    // Deeply nested JSON that could cause stack overflow
    let mut nested = "{}".to_string();
    for _ in 0..100 {
        nested = format!("{{{}}}", nested);
    }

    serde_json::from_str::<TrustCardRegistrySnapshot>(&nested)
        .expect_err("deeply nested malformed JSON must be rejected");

    println!("✅ Edge case tests completed without panics");
}
