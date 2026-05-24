#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::config::Config;
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
        assert_eq!(result1.is_ok(), result2.is_ok(), "TOML parsing should be deterministic");

        // Additional fuzzing: test the error handling path explicitly
        // by trying to validate malformed configs if they parse
        if let Ok(config) = result1 {
            // The validate() method should never panic, even on malformed data
            let validation_result = config.validate();
            // Validation should be deterministic
            let validation_result2 = config.validate();
            assert_eq!(validation_result.is_ok(), validation_result2.is_ok(), "Config validation should be deterministic");

            // Test serialization round-trip to catch serialization bugs
            if let Ok(serialized) = toml::to_string(&config) {
                let round_trip_result = toml::from_str::<Config>(&serialized);
                assert!(round_trip_result.is_ok(), "Round-trip serialization should succeed for valid configs");
            }
        }
    }
});