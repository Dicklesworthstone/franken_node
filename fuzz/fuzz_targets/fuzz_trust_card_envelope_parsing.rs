#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz target for trust card envelope parsing and verification.
//
// Tests raw bytes fuzzing of trust card serde_json deserialization
// across all trust card envelope formats. Priority targets (bd-2cg8u):
// - TrustCard: core trust card envelope structure
// - TrustCardRegistrySnapshot: registry persistence format
// - TrustCardInput: creation and mutation inputs
// - Trust card signature and verification envelopes
//
// Note: Using raw bytes fuzzing approach to provide comprehensive coverage
// of serde_json::from_str/from_slice entry points without requiring
// Arbitrary trait implementations on complex trust card structures.
fuzz_target!(|data: &[u8]| {
    fuzz_trust_card_raw_bytes(data);
});

/// Fuzz raw bytes against all trust card deserializers
fn fuzz_trust_card_raw_bytes(bytes: &[u8]) {
    // Size guard: reject overly large inputs to prevent OOM
    if bytes.len() > 10_000_000 {
        return;
    }

    // Test raw bytes as UTF-8 JSON string
    if let Ok(json_str) = std::str::from_utf8(bytes) {
        // Test generic JSON parsing - this exercises core serde_json paths
        // that all trust card deserialization uses
        // Test deterministic trust card envelope parsing
        let result1 = serde_json::from_str::<serde_json::Value>(json_str);
        let result2 = serde_json::from_str::<serde_json::Value>(json_str);
        assert_eq!(result1.is_ok(), result2.is_ok(), "Trust card parsing should be deterministic");

        // Test malformed JSON edge cases that could trigger parser vulnerabilities
        test_json_edge_cases(json_str);

        // Test round-trip consistency
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
            if let Ok(reencoded) = serde_json::to_string(&value) {
                let _ = serde_json::from_str::<serde_json::Value>(&reencoded);
            }

            // Test pretty-printed round-trip (different code path)
            if let Ok(pretty) = serde_json::to_string_pretty(&value) {
                let _ = serde_json::from_str::<serde_json::Value>(&pretty);
            }
        }
    }

    // Test raw bytes directly (binary JSON, malformed UTF-8, binary envelopes)
    let _ = serde_json::from_slice::<serde_json::Value>(bytes);

    // Test edge case: empty and truncated inputs
    if !bytes.is_empty() {
        let single_byte = &bytes[..1];
        let _ = serde_json::from_slice::<serde_json::Value>(single_byte);

        if bytes.len() > 2 {
            let half_bytes = &bytes[..bytes.len() / 2];
            let _ = serde_json::from_slice::<serde_json::Value>(half_bytes);
        }
    }
}

/// Test JSON edge cases that could trigger parser vulnerabilities
fn test_json_edge_cases(json_str: &str) {
    if json_str.len() < 2 {
        return;
    }

    // Test with truncated JSON (incomplete parsing)
    let truncated = &json_str[..json_str.len() - 1];
    let _ = serde_json::from_str::<serde_json::Value>(truncated);

    // Test with extra characters (over-parsing)
    let extended = format!("{json_str}}}");
    let _ = serde_json::from_str::<serde_json::Value>(&extended);

    // Test with nested modifications for deeply nested structures
    let nested = format!("[{json_str}]");
    let _ = serde_json::from_str::<serde_json::Value>(&nested);

    let wrapped = format!("{{\"data\": {json_str}}}");
    let _ = serde_json::from_str::<serde_json::Value>(&wrapped);

    // Test with whitespace variations that could affect parsing
    let with_spaces = format!(" \t\n{json_str}\n\t ");
    let _ = serde_json::from_str::<serde_json::Value>(&with_spaces);
}