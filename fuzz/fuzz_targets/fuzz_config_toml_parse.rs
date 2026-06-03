#![no_main]
#![forbid(unsafe_code)]

use frankenengine_node::config::Config;
use libfuzzer_sys::fuzz_target;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Guard against very large inputs to prevent OOM
    if data.len() > 1_000_000 {
        return;
    }

    // Only fuzz valid UTF-8 strings since TOML requires valid UTF-8
    if let Ok(toml_str) = str::from_utf8(data) {
        // Attempt to parse the TOML configuration
        // Test deterministic parsing behavior
        let result1 = toml::from_str::<Config>(toml_str);
        let result2 = toml::from_str::<Config>(toml_str);
        assert_eq!(
            result1.is_ok(),
            result2.is_ok(),
            "TOML parsing should be deterministic"
        );

        // Additional fuzzing: parsed configs should serialize and reparse
        // deterministically. The full public validation path lives behind
        // Config::load(), which is intentionally filesystem-based and outside
        // this in-memory parser harness.
        if let Ok(config) = result1 {
            // Test serialization round-trip to catch serialization bugs
            if let Ok(serialized) = toml::to_string(&config) {
                let round_trip_result1 = toml::from_str::<Config>(&serialized);
                let round_trip_result2 = toml::from_str::<Config>(&serialized);
                assert_eq!(
                    round_trip_result1.is_ok(),
                    round_trip_result2.is_ok(),
                    "Round-trip serialization should be deterministic"
                );
            }
        }
    }
});
