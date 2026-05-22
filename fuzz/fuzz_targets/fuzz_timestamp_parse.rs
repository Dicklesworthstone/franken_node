#![no_main]

use libfuzzer_sys::fuzz_target;
use chrono::{DateTime, Utc, NaiveDateTime, TimeZone};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(timestamp_input) = std::str::from_utf8(data) {
        // Guard against excessively long timestamp strings
        if timestamp_input.len() > 1000 {
            return;
        }

        // Test various timestamp parsing formats

        // 1. Test RFC 3339 parsing (most common format)
        if let Ok(dt) = timestamp_input.parse::<DateTime<Utc>>() {
            // Valid RFC 3339 parse - verify invariants

            // Re-formatting should produce valid timestamp
            let formatted = dt.to_rfc3339();
            let re_parsed = formatted.parse::<DateTime<Utc>>();
            assert!(re_parsed.is_ok(), "Round-trip RFC 3339 parsing should succeed");

            // Verify temporal bounds (prevent overflow/underflow attacks)
            assert!(dt.timestamp() >= -62135596800, "Timestamp should not underflow");
            assert!(dt.timestamp() <= 253402300799, "Timestamp should not overflow");

            // Verify nanosecond precision is reasonable
            assert!(dt.timestamp_subsec_nanos() < 1_000_000_000, "Nanoseconds should be valid");

            // Test timestamp consistency
            let unix_timestamp = dt.timestamp();
            let reconstructed = Utc.timestamp_opt(unix_timestamp, dt.timestamp_subsec_nanos());
            assert!(reconstructed.single().is_some(), "Timestamp reconstruction should succeed");
        }

        // 2. Test NaiveDateTime parsing (no timezone)
        if let Ok(naive_dt) = NaiveDateTime::parse_from_str(timestamp_input, "%Y-%m-%d %H:%M:%S") {
            // Valid naive datetime parse

            // Re-formatting should be consistent
            let formatted = naive_dt.format("%Y-%m-%d %H:%M:%S").to_string();
            let re_parsed = NaiveDateTime::parse_from_str(&formatted, "%Y-%m-%d %H:%M:%S");
            assert!(re_parsed.is_ok(), "Round-trip naive datetime should succeed");
            assert_eq!(naive_dt, re_parsed.unwrap(), "Round-trip should preserve value");

            // Verify date components are reasonable
            let year = naive_dt.year();
            assert!(year >= -262144 && year <= 262143, "Year should be within reasonable bounds");

            let month = naive_dt.month();
            assert!(month >= 1 && month <= 12, "Month should be 1-12");

            let day = naive_dt.day();
            assert!(day >= 1 && day <= 31, "Day should be 1-31");

            let hour = naive_dt.hour();
            assert!(hour < 24, "Hour should be 0-23");

            let minute = naive_dt.minute();
            assert!(minute < 60, "Minute should be 0-59");

            let second = naive_dt.second();
            assert!(second < 60, "Second should be 0-59");
        }

        // 3. Test various common timestamp formats
        let common_formats = [
            "%Y-%m-%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y",
            "%m/%d/%Y",
            "%Y%m%d",
            "%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%.3fZ",
        ];

        for format in &common_formats {
            if let Ok(parsed) = NaiveDateTime::parse_from_str(timestamp_input, format) {
                // Successful parse with this format

                // Re-format and verify consistency
                let reformatted = parsed.format(format).to_string();
                let re_parsed = NaiveDateTime::parse_from_str(&reformatted, format);

                if re_parsed.is_ok() {
                    assert_eq!(parsed, re_parsed.unwrap(),
                              "Format round-trip should be consistent");
                }
            }
        }

        // 4. Test epoch timestamp parsing (Unix timestamp)
        if let Ok(timestamp_num) = timestamp_input.parse::<i64>() {
            // Numeric timestamp
            if timestamp_num >= -62135596800 && timestamp_num <= 253402300799 {
                // Reasonable timestamp range
                if let Some(dt) = Utc.timestamp_opt(timestamp_num, 0).single() {
                    // Valid timestamp conversion

                    // Verify round-trip
                    assert_eq!(dt.timestamp(), timestamp_num,
                              "Timestamp round-trip should be exact");

                    // Test formatting
                    let formatted = dt.to_rfc3339();
                    assert!(!formatted.is_empty(), "Formatted timestamp should not be empty");
                }
            }
        }

        // 5. Test malformed timestamp handling

        // Test obviously invalid formats
        if timestamp_input.contains("32/") || timestamp_input.contains("/32/") ||
           timestamp_input.contains("25:") || timestamp_input.contains(":70") {
            // These should fail parsing in most reasonable formats
            let rfc3339_result = timestamp_input.parse::<DateTime<Utc>>();
            // Don't assert failure here as some edge cases might be valid
        }

        // Test null byte handling
        if timestamp_input.contains('\0') {
            let result = timestamp_input.parse::<DateTime<Utc>>();
            // Null bytes should be rejected
            assert!(result.is_err(), "Null bytes in timestamps should be rejected");
        }

        // Test extremely long numeric strings (potential DoS)
        if timestamp_input.chars().all(|c| c.is_ascii_digit()) && timestamp_input.len() > 50 {
            let result = timestamp_input.parse::<i64>();
            // Extremely long numbers should be rejected
            assert!(result.is_err(), "Extremely long numeric timestamps should be rejected");
        }

        // Test special date edge cases
        if timestamp_input == "1970-01-01T00:00:00Z" {
            let result = timestamp_input.parse::<DateTime<Utc>>();
            assert!(result.is_ok(), "Unix epoch should parse correctly");
            if let Ok(dt) = result {
                assert_eq!(dt.timestamp(), 0, "Unix epoch timestamp should be 0");
            }
        }

        // Test leap year handling
        if timestamp_input.contains("02-29") {
            // February 29th - should only be valid in leap years
            if let Ok(dt) = timestamp_input.parse::<DateTime<Utc>>() {
                let year = dt.year();
                // Verify it's actually a leap year
                assert!(year % 4 == 0 && (year % 100 != 0 || year % 400 == 0),
                        "February 29th should only occur in leap years");
            }
        }
    }
});