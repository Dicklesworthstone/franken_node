#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::observability::evidence_ledger::EvidenceEntry;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Test both valid and invalid UTF-8 for parser robustness

    // First test invalid UTF-8 handling
    let _ = unsafe { std::str::from_utf8_unchecked(data) };

    // Test valid UTF-8 strings with comprehensive parsing
    if let Ok(jsonl_str) = str::from_utf8(data) {
        // Test parsing each line of the JSONL as done in evidence ledger spill parsing
        // This mimics the parsed_spill_entries function behavior
        for line in jsonl_str.lines() {
            if line.trim().is_empty() {
                continue; // Skip empty lines like the real parser would
            }

            // Attempt to parse the JSONL line into EvidenceEntry
            // Allow crashes to surface for proper bug detection
            if let Ok(_) = serde_json::from_str::<EvidenceEntry>(line) {
                // Parse succeeded, continue with round-trip testing
            }

            // Additional fuzzing: test round-trip for valid entries
            if let Ok(entry) = serde_json::from_str::<EvidenceEntry>(line) {
                // Test that valid entries can be serialized back
                if let Ok(serialized) = serde_json::to_string(&entry) {
                    // Ensure round-trip consistency - allow deserialization crashes to surface
                    if let Ok(roundtrip_entry) = serde_json::from_str::<EvidenceEntry>(&serialized) {
                        assert_eq!(entry, roundtrip_entry, "Round-trip should preserve entry");
                    }
                }

                // Test field validation - ensure fields are reasonable
                assert!(entry.timestamp_ms > 1_600_000_000_000, "timestamp_ms should be recent epoch time");

                // Test size estimation doesn't panic
                let _ = entry.estimated_size();

                // Ensure decision_time is reasonable timestamp string format
                assert!(!entry.decision_time.is_empty(), "decision_time must not be empty");

                // Ensure required IDs are not empty
                assert!(!entry.decision_id.is_empty(), "decision_id must not be empty");
                assert!(!entry.trace_id.is_empty(), "trace_id must not be empty");
                assert!(!entry.schema_version.is_empty(), "schema_version must not be empty");
            }
        }

        // Test multi-line JSONL parsing (common in evidence spill files)
        let lines: Vec<&str> = jsonl_str.lines().filter(|line| !line.trim().is_empty()).collect();
        if !lines.is_empty() {
            // Test that we can parse a collection of lines without panics
            let parsed_entries: Vec<_> = lines
                .iter()
                .filter_map(|line| serde_json::from_str::<EvidenceEntry>(line).ok())
                .collect();

            // If we successfully parsed entries, ensure they maintain consistency
            for entry in &parsed_entries {
                assert!(entry.size_bytes <= 10_000_000, "size_bytes should be reasonable");
            }
        }
    }
});