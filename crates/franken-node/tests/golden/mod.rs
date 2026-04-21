//! Golden artifact testing infrastructure for trust-card, registry, and claims modules
//!
//! This module provides utilities for golden file testing with proper scrubbing
//! of dynamic values (UUIDs, timestamps, paths, etc.) following the patterns
//! from the testing-golden-artifacts skill.

use regex::Regex;
use serde_json::Value;
use std::{fs, path::Path, path::PathBuf};

/// Universal golden comparison function that supports scrubbing
pub fn assert_golden(test_name: &str, actual: &str) {
    let golden_path = golden_path_for(test_name);

    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(&golden_path, actual).unwrap();
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff tests/golden/",
            golden_path.display()
        )
    });

    if actual != expected {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, actual).unwrap();

        panic!(
            "GOLDEN MISMATCH: {test_name}\n\n\
             To update: UPDATE_GOLDENS=1 cargo test -- {test_name}\n\
             To review: diff {} {}",
            golden_path.display(),
            actual_path.display(),
        );
    }
}

/// Assert golden for JSON with automatic pretty-printing
pub fn assert_json_golden(test_name: &str, value: &Value) {
    let actual = serde_json::to_string_pretty(value).unwrap();
    assert_golden(test_name, &actual);
}

/// Assert golden with dynamic value scrubbing
pub fn assert_scrubbed_golden(test_name: &str, actual: &str) {
    let scrubbed = scrub_dynamic_values(actual);
    assert_golden(test_name, &scrubbed);
}

/// Assert JSON golden with scrubbing
pub fn assert_scrubbed_json_golden(test_name: &str, value: &Value) {
    let actual = serde_json::to_string_pretty(value).unwrap();
    assert_scrubbed_golden(test_name, &actual);
}

/// Standard scrubber for dynamic values common in franken-node outputs
pub fn scrub_dynamic_values(input: &str) -> String {
    let mut result = input.to_string();

    // UUIDs → [UUID]
    let uuid_re =
        Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap();
    result = uuid_re.replace_all(&result, "[UUID]").to_string();

    // ISO timestamps → [TIMESTAMP]
    let ts_re =
        Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?").unwrap();
    result = ts_re.replace_all(&result, "[TIMESTAMP]").to_string();

    // Unix timestamps → [UNIX_TIMESTAMP]
    let unix_ts_re = Regex::new(r"\b\d{10}(\.\d+)?\b").unwrap();
    result = unix_ts_re
        .replace_all(&result, "[UNIX_TIMESTAMP]")
        .to_string();

    // Memory addresses → [ADDR]
    let addr_re = Regex::new(r"0x[0-9a-f]{6,16}").unwrap();
    result = addr_re.replace_all(&result, "[ADDR]").to_string();

    // Durations → [DURATION]
    let dur_re = Regex::new(r"\d+(\.\d+)?\s*(ms|us|ns|s|sec|min)").unwrap();
    result = dur_re.replace_all(&result, "[DURATION]").to_string();

    // Absolute paths → [PATH]
    let path_re = Regex::new(r"/[a-zA-Z0-9/_.-]+").unwrap();
    result = path_re.replace_all(&result, "[PATH]").to_string();

    // Hash values → [HASH]
    let hash_re = Regex::new(r"\b[a-f0-9]{40,64}\b").unwrap();
    result = hash_re.replace_all(&result, "[HASH]").to_string();

    // Artifact IDs → [ARTIFACT_ID]
    let artifact_id_re = Regex::new(r"artifact_id=[a-f0-9]{16}").unwrap();
    result = artifact_id_re
        .replace_all(&result, "artifact_id=[ARTIFACT_ID]")
        .to_string();

    // Extension IDs with version → normalize versions
    let ext_id_re = Regex::new(r"(npm:[@a-z0-9-/]+)@\d+\.\d+\.\d+").unwrap();
    result = ext_id_re.replace_all(&result, "${1}@[VERSION]").to_string();

    // Key IDs (hexadecimal, 8-16 chars) → [KEY_ID]
    let key_id_re = Regex::new(r"\b[a-f0-9]{8,16}\b").unwrap();
    result = key_id_re.replace_all(&result, "[KEY_ID]").to_string();

    result
}

/// Get path to golden file for test
fn golden_path_for(test_name: &str) -> PathBuf {
    PathBuf::from("tests/golden").join(format!("{}.golden", test_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrubber_handles_uuids() {
        let input = "uuid: 550e8400-e29b-41d4-a716-446655440000";
        let output = scrub_dynamic_values(input);
        assert_eq!(output, "uuid: [UUID]");
    }

    #[test]
    fn test_scrubber_handles_timestamps() {
        let input = "created_at: 2024-01-15T10:30:00Z";
        let output = scrub_dynamic_values(input);
        assert_eq!(output, "created_at: [TIMESTAMP]");
    }

    #[test]
    fn test_scrubber_handles_paths() {
        let input = "path: /home/user/project/file.txt";
        let output = scrub_dynamic_values(input);
        assert_eq!(output, "path: [PATH]");
    }

    #[test]
    fn test_scrubber_handles_extension_ids() {
        let input = "npm:@acme/auth-guard@1.4.2";
        let output = scrub_dynamic_values(input);
        assert_eq!(output, "npm:@acme/auth-guard@[VERSION]");
    }
}

// Include incident golden tests module
pub mod incident_golden_tests;
