#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::supply_chain::extension_registry::{
    parse_signed_registration_manifest, ExtensionRegistrationManifest, VersionEntry,
    EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

const MAX_MANIFEST_SIZE: usize = 64 * 1024; // 64KB limit
const MAX_STRING_LEN: usize = 1024;
const MAX_TAGS: usize = 16;

fuzz_target!(|input: FuzzInput| {
    // Limit input size to prevent excessive memory usage
    if input.raw_bytes.len() > MAX_MANIFEST_SIZE {
        return;
    }

    // Test 1: Raw bytes fuzzing (any bytes)
    fuzz_raw_bytes(&input.raw_bytes);

    // Test 2: Structure-aware fuzzing (valid JSON structure with fuzzed values)
    fuzz_structured_manifest(input);
});

fn fuzz_raw_bytes(bytes: &[u8]) {
    // Test deterministic behavior on raw bytes
    let result1 = parse_signed_registration_manifest(bytes);
    let result2 = parse_signed_registration_manifest(bytes);
    assert_eq!(result1.is_ok(), result2.is_ok(),
              "Manifest parsing should be deterministic");

    // Empty input should be rejected
    if bytes.is_empty() {
        assert!(result1.is_err(), "Empty manifest should be rejected");
    }

    // Very small inputs should be rejected (not valid JSON)
    if bytes.len() < 10 && !bytes.is_empty() {
        assert!(result1.is_err(), "Very small input should not parse as valid manifest");
    }

    // Malformed JSON should be safely rejected
    if !std::str::from_utf8(bytes).is_ok() {
        assert!(result1.is_err(), "Non-UTF8 bytes should be rejected");
    }
}

fn fuzz_structured_manifest(input: FuzzInput) {
    // Generate various manifest structures to test edge cases
    let test_cases = vec![
        // Valid manifest with fuzzed values
        ("valid", generate_manifest(&input.manifest_data)),
        // Invalid schema version
        ("invalid_schema", generate_manifest_with_schema(&input.manifest_data, &input.invalid_schema)),
        // Malformed JSON structures
        ("malformed", generate_malformed_manifest(&input.manifest_data)),
        // Edge cases: empty fields, very long fields, special characters
        ("edge_case", generate_edge_case_manifest(&input.manifest_data)),
    ];

    for (test_type, manifest_json) in test_cases {
        let result = parse_signed_registration_manifest(&manifest_json);

        // Test deterministic behavior
        let result2 = parse_signed_registration_manifest(&manifest_json);
        assert_eq!(result.is_ok(), result2.is_ok(),
                  "Manifest parsing should be deterministic for {}", test_type);

        match test_type {
            "valid" => {
                // Valid manifest structure should either parse or fail gracefully
                // (may fail due to missing signature verification)
            },
            "invalid_schema" => {
                // Invalid schema version should be rejected
                if !input.invalid_schema.is_empty() &&
                   input.invalid_schema != EXTENSION_REGISTRATION_MANIFEST_SCHEMA {
                    assert!(result.is_err(), "Invalid schema version should be rejected");
                }
            },
            "malformed" => {
                // Malformed JSON should be rejected
                // (verify the test case actually produced malformed JSON first)
            },
            "edge_case" => {
                // Edge cases should be handled safely without panic
                // Function should complete without crashing
            },
            _ => unreachable!(),
        }
    }
}

fn generate_manifest(data: &ManifestData) -> Vec<u8> {
    let manifest = json!({
        "schema_version": EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
        "name": truncate_string(&data.name, MAX_STRING_LEN),
        "publisher_id": truncate_string(&data.publisher_id, MAX_STRING_LEN),
        "initial_version": {
            "version": truncate_string(&data.version, 128),
            "parent_version": null,
            "content_hash": truncate_string(&data.content_hash, 128),
            "registered_at": "2026-04-23T00:00:00Z",
            "compatible_with": data.compatible_with.iter()
                .take(8)
                .map(|s| truncate_string(s, 128))
                .collect::<Vec<_>>()
        },
        "tags": data.tags.iter()
            .take(MAX_TAGS)
            .map(|s| truncate_string(s, 256))
            .collect::<Vec<_>>()
    });

    serde_json::to_vec(&manifest).unwrap_or_default()
}

fn generate_manifest_with_schema(data: &ManifestData, schema: &str) -> Vec<u8> {
    let manifest = json!({
        "schema_version": truncate_string(schema, 512),
        "name": truncate_string(&data.name, MAX_STRING_LEN),
        "publisher_id": truncate_string(&data.publisher_id, MAX_STRING_LEN),
        "initial_version": {
            "version": truncate_string(&data.version, 128),
            "parent_version": null,
            "content_hash": truncate_string(&data.content_hash, 128),
            "registered_at": "2026-04-23T00:00:00Z",
            "compatible_with": []
        },
        "tags": []
    });

    serde_json::to_vec(&manifest).unwrap_or_default()
}

fn generate_malformed_manifest(data: &ManifestData) -> Vec<u8> {
    // Create various malformed JSON to test parser robustness
    let malformed_cases = [
        // Missing required fields
        json!({
            "schema_version": EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
            "name": truncate_string(&data.name, MAX_STRING_LEN)
            // missing other required fields
        }),
        // Wrong field types
        json!({
            "schema_version": EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
            "name": 12345, // number instead of string
            "publisher_id": truncate_string(&data.publisher_id, MAX_STRING_LEN),
            "initial_version": "not_an_object",
            "tags": "not_an_array"
        }),
        // Extra unexpected fields
        json!({
            "schema_version": EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
            "name": truncate_string(&data.name, MAX_STRING_LEN),
            "publisher_id": truncate_string(&data.publisher_id, MAX_STRING_LEN),
            "initial_version": {
                "version": truncate_string(&data.version, 128),
                "content_hash": truncate_string(&data.content_hash, 128),
                "registered_at": "2026-04-23T00:00:00Z",
                "compatible_with": []
            },
            "tags": [],
            "malicious_field": "injection_attempt",
            "nested": {
                "deep": {
                    "attack": "vector"
                }
            }
        }),
    ];

    // Return one of the malformed cases based on data
    let index = data.case_selector as usize % malformed_cases.len();
    serde_json::to_vec(&malformed_cases[index]).unwrap_or_default()
}

fn generate_edge_case_manifest(data: &ManifestData) -> Vec<u8> {
    let manifest = json!({
        "schema_version": EXTENSION_REGISTRATION_MANIFEST_SCHEMA,
        "name": if data.use_empty_name { "" } else { &data.name },
        "publisher_id": if data.use_long_publisher {
            &"x".repeat(MAX_STRING_LEN)
        } else {
            &data.publisher_id
        },
        "initial_version": {
            "version": if data.use_unicode_version {
                "1.0.0-α.β.γ.δ.ε.ζ.η.θ.ι.κ.λ.μ.ν.ξ.ο.π.ρ.σ.τ.υ.φ.χ.ψ.ω"
            } else {
                &data.version
            },
            "parent_version": null,
            "content_hash": &data.content_hash,
            "registered_at": "2026-04-23T00:00:00Z",
            "compatible_with": if data.use_huge_compatible {
                (0..100).map(|i| format!("compat-{}", i)).collect::<Vec<_>>()
            } else {
                vec![]
            }
        },
        "tags": if data.use_huge_tags {
            (0..100).map(|i| format!("tag-{}", i)).collect::<Vec<_>>()
        } else {
            data.tags.clone()
        }
    });

    serde_json::to_vec(&manifest).unwrap_or_default()
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        s.chars().take(max_len.saturating_sub(3)).collect::<String>() + "..."
    }
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    raw_bytes: Vec<u8>,
    manifest_data: ManifestData,
    invalid_schema: String,
}

#[derive(Debug, Arbitrary)]
struct ManifestData {
    name: String,
    publisher_id: String,
    version: String,
    content_hash: String,
    tags: Vec<String>,
    compatible_with: Vec<String>,
    case_selector: u8,
    use_empty_name: bool,
    use_long_publisher: bool,
    use_unicode_version: bool,
    use_huge_compatible: bool,
    use_huge_tags: bool,
}