#![no_main]

use frankenengine_node::supply_chain::trust_card::TrustCardRegistrySnapshot;
use libfuzzer_sys::fuzz_target;

/// Libfuzzer harness for trust card registry snapshot JSON parsing
///
/// Tests TrustCardRegistrySnapshot deserialization against arbitrary malformed inputs to find:
/// 1. Parse crashes and panics
/// 2. Stack overflow from deeply nested structures
/// 3. Integer overflow in size calculations
/// 4. OOM from unbounded allocations
/// 5. Unsafe string operations
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
        let _ = serde_json::from_str::<TrustCardRegistrySnapshot>(json_str);

        // Test with common JSON fuzz variations if input looks JSON-ish
        if json_str.contains('{') {
            // Additional fuzz vectors for JSON edge cases
            test_json_edge_cases(json_str);
        }
    }

    // Test raw serde_json parsing on bytes (should handle encoding gracefully)
    let _ = serde_json::from_slice::<TrustCardRegistrySnapshot>(data);

    // INVARIANT: No crashes, panics, or sanitizer violations should occur
    // All errors should be returned as proper Result::Err, not panic
});

/// Test additional JSON parsing edge cases
fn test_json_edge_cases(input: &str) {
    // Test with various encoding patterns that could cause issues
    let test_cases = [
        input,
        &input.replace("\"", "\\\""),  // Escaped quotes
        &input.replace("}", "},"),     // Trailing comma
        &format!("[{}]", input),       // Wrapped in array
        &format!("null,{}", input),    // Null prefix
    ];

    for case in test_cases {
        let _ = serde_json::from_str::<TrustCardRegistrySnapshot>(case);
    }

    // Test deeply nested structures (should not stack overflow)
    if input.len() < 1000 {
        let mut nested = input.to_string();
        for _ in 0..100 {
            nested = format!("{{{nested}}}");
            let _ = serde_json::from_str::<TrustCardRegistrySnapshot>(&nested);
        }
    }

    // Test very large string values (should not cause OOM)
    if input.contains("\"") && input.len() < 100 {
        let large_string = "A".repeat(10_000);
        let modified = input.replace("\"", &format!("\"{}\"", large_string));
        let _ = serde_json::from_str::<TrustCardRegistrySnapshot>(&modified);
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
            let _ = serde_json::from_str::<TrustCardRegistrySnapshot>(&modified);
        }
    }
}