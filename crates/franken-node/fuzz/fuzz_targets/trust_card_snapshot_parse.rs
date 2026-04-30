#![no_main]

use frankenengine_node::supply_chain::trust_card::{TrustCardRegistry, TrustCardRegistrySnapshot};
use libfuzzer_sys::fuzz_target;

const FUZZ_REGISTRY_KEY: &[u8] = b"trust-card-snapshot-parse-fuzz-key";

// Libfuzzer harness for trust card registry snapshot JSON parsing.
//
// Tests TrustCardRegistrySnapshot deserialization against arbitrary malformed inputs to find:
// 1. Parse crashes and panics
// 2. Stack overflow from deeply nested structures
// 3. Integer overflow in size calculations
// 4. OOM from unbounded allocations
// 5. Unsafe string operations
// 6. Lossy snapshot serde boundaries and validation panics
fuzz_target!(|data: &[u8]| {
    // Bound input size to prevent OOM and timeout (100KB limit)
    if data.len() > 100_000 {
        return;
    }

    // Test direct byte parsing (invalid UTF-8 should fail gracefully)
    let _ = std::str::from_utf8(data);

    // Convert to string for JSON parsing if possible
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Test trust card registry snapshot parsing with adversarial JSON
        exercise_snapshot_parse(serde_json::from_str::<TrustCardRegistrySnapshot>(json_str));

        // Test with common JSON fuzz variations if input looks JSON-ish
        if json_str.contains('{') {
            // Additional fuzz vectors for JSON edge cases
            test_json_edge_cases(json_str);
        }
    }

    // Test raw serde_json parsing on bytes (should handle encoding gracefully)
    exercise_snapshot_parse(serde_json::from_slice::<TrustCardRegistrySnapshot>(data));

    // INVARIANT: No crashes, panics, or sanitizer violations should occur
    // All errors should be returned as proper Result::Err, not panic.
    // If serde accepts a snapshot, re-encoding it must preserve the exact
    // boundary that snapshot validation will inspect.
});

fn exercise_snapshot_parse(result: serde_json::Result<TrustCardRegistrySnapshot>) {
    let Ok(snapshot) = result else {
        return;
    };

    let encoded =
        serde_json::to_vec(&snapshot).expect("accepted trust-card snapshot must serialize");
    let reparsed = serde_json::from_slice::<TrustCardRegistrySnapshot>(&encoded)
        .expect("serialized trust-card snapshot must parse");
    assert_eq!(
        reparsed, snapshot,
        "trust-card snapshot serde boundary must be lossless"
    );

    let _ = TrustCardRegistry::from_snapshot(reparsed, FUZZ_REGISTRY_KEY, 0);
}

/// Test additional JSON parsing edge cases
fn test_json_edge_cases(input: &str) {
    // Test with various encoding patterns that could cause issues
    let test_cases = [
        input,
        &input.replace("\"", "\\\""), // Escaped quotes
        &input.replace("}", "},"),    // Trailing comma
        &format!("[{}]", input),      // Wrapped in array
        &format!("null,{}", input),   // Null prefix
    ];

    for case in test_cases {
        exercise_snapshot_parse(serde_json::from_str::<TrustCardRegistrySnapshot>(case));
    }

    // Test deeply nested structures (should not stack overflow)
    if input.len() < 1000 {
        let mut nested = input.to_string();
        for _ in 0..100 {
            nested = format!("{{{nested}}}");
            exercise_snapshot_parse(serde_json::from_str::<TrustCardRegistrySnapshot>(&nested));
        }
    }

    // Test very large string values (should not cause OOM)
    if input.contains("\"") && input.len() < 100 {
        let large_string = "A".repeat(10_000);
        let modified = input.replace("\"", &format!("\"{}\"", large_string));
        exercise_snapshot_parse(serde_json::from_str::<TrustCardRegistrySnapshot>(&modified));
    }

    // Test number edge cases
    if input.contains(':') {
        let number_tests = [
            "999999999999999999999999999",  // Large number
            "-999999999999999999999999999", // Large negative
            "1e308",                        // Near float limit
            "1e-324",                       // Near float underflow
            "NaN",                          // Invalid float
            "Infinity",                     // Invalid float
            "-Infinity",                    // Invalid float
        ];

        for num in number_tests {
            let modified = input.replace(":", &format!(":{}", num));
            exercise_snapshot_parse(serde_json::from_str::<TrustCardRegistrySnapshot>(&modified));
        }
    }
}
