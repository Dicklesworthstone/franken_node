#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::supply_chain::quarantine::QuarantineAuditTimestamp;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Test both valid and invalid UTF-8 for parser robustness
    // Removed early returns to maximize fuzz coverage

    // First test invalid UTF-8 handling (robustness testing)
    if let Err(_) = str::from_utf8(data) {
        // Test parser behavior on invalid UTF-8 boundaries
        let _ = QuarantineAuditTimestamp::try_from(unsafe { std::str::from_utf8_unchecked(data) });
    }

    // Test valid UTF-8 strings with comprehensive edge case testing
    if let Ok(rfc3339_str) = str::from_utf8(data) {
        // Test direct parsing via TryFrom<&str> implementation
        // This is the main RFC3339 parsing path: DateTime::parse_from_rfc3339(value)
        let _ = QuarantineAuditTimestamp::try_from(rfc3339_str);

        // Test round-trip for valid timestamps
        if let Ok(timestamp) = QuarantineAuditTimestamp::try_from(rfc3339_str) {
            // Test canonical formatting doesn't panic
            let canonical = timestamp.canonical_rfc3339();

            // Test that canonical format is valid RFC3339 and parses back
            let reparsed = QuarantineAuditTimestamp::try_from(canonical.as_str());
            assert!(reparsed.is_ok(), "canonical format should parse back successfully");

            // Test Display trait doesn't panic
            let displayed = format!("{}", timestamp);
            assert_eq!(canonical, displayed, "Display should match canonical format");

            // Test conversion to DateTime<Utc> and back
            let datetime = chrono::DateTime::<chrono::Utc>::from(timestamp.clone());
            let converted_back = QuarantineAuditTimestamp::from(datetime);
            assert_eq!(timestamp, converted_back, "DateTime conversion should be reversible");

            // Test serialization via serde doesn't panic
            if let Ok(serialized) = serde_json::to_string(&timestamp) {
                // Test deserialization round-trip
                let _: Result<QuarantineAuditTimestamp, _> = serde_json::from_str(&serialized);
            }

            // Test that canonical format follows expected RFC3339 constraints
            assert!(!canonical.is_empty(), "canonical format should not be empty");
            assert!(canonical.contains('T'), "canonical format should contain T separator");
            assert!(canonical.ends_with('Z'), "canonical format should end with Z");
        }

        // Test edge cases that commonly cause RFC3339 parser issues
        let trimmed = rfc3339_str.trim();
        if !trimmed.is_empty() {
            let _ = QuarantineAuditTimestamp::try_from(trimmed);
        }

        // Test with various common RFC3339 prefixes/suffixes that might trigger edge cases
        for suffix in ["", "Z", "+00:00", "-00:00", ".000Z", ".123456Z"] {
            let test_input = format!("{}{}", rfc3339_str, suffix);
            let _ = QuarantineAuditTimestamp::try_from(test_input.as_str());
        }

        for prefix in ["", "2026-", "2026-01-01T"] {
            let test_input = format!("{}{}", prefix, rfc3339_str);
            let _ = QuarantineAuditTimestamp::try_from(test_input.as_str());
        }
    }
});