#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::config::NetworkAllowlistEntry;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Increase size limit to allow larger inputs for better coverage
    if data.len() > 1_000_000 {
        return;
    }

    // Test both valid and invalid UTF-8 to catch edge cases in error handling
    match str::from_utf8(data) {
        Ok(toml_str) => {
            // Fuzz valid UTF-8 TOML parsing
            fuzz_valid_utf8(toml_str);
        }
        Err(_) => {
            // Fuzz invalid UTF-8 handling - convert lossy and test
            let lossy_str = String::from_utf8_lossy(data);
            fuzz_valid_utf8(&lossy_str);
        }
    }
});

fn fuzz_valid_utf8(toml_str: &str) {
    // Attempt to parse the TOML network allowlist entry
    // We expect most random inputs to fail parsing, which is normal
    if let Ok(entry) = toml::from_str::<NetworkAllowlistEntry>(toml_str) {
        // Test serialization round-trip to catch serialization bugs
        if let Ok(serialized) = toml::to_string(&entry) {
            // Don't use `let _ = ` to catch potential panics in re-parsing
            if toml::from_str::<NetworkAllowlistEntry>(&serialized).is_err() {
                // Round-trip serialization failed - this is a bug
                panic!("Round-trip serialization failed for valid entry");
            }
        }

        // Test field access without trivial operations that waste fuzz cycles
        // Just accessing the fields exercises the important code paths
        let _host = &entry.host;
        let _port = entry.port;
        let _reason = &entry.reason;
    }

    // Test parsing as part of a TOML document with surrounding structure
    let wrapped_toml = format!("[network]\nallowlist = [{}]", toml_str);
    if let Ok(table) = toml::from_str::<toml::Table>(&wrapped_toml) {
        if let Some(network) = table.get("network") {
            if let Some(allowlist) = network.get("allowlist") {
                // Try to deserialize the allowlist array
                // Don't use `let _ = ` to catch potential crashes
                let _result = allowlist.clone().try_into::<Vec<NetworkAllowlistEntry>>();
            }
        }
    }
}