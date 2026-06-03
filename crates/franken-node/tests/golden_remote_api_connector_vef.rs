//! Comprehensive golden artifacts tests for remote/api/connector/vef modules
//!
//! This test suite covers the canonical form serialization and validation
//! outputs for the three key domain areas:
//! - Remote capability envelopes with scope validation
//! - Connector lifecycle messages with frame validation
//! - VEF receipts with chain integrity
//!
//! All outputs use timestamp/nonce scrubbing for deterministic comparison.
//! Golden files are stored under tests/golden/ with hierarchical organization.

// Import the golden test infrastructure
#[path = "golden/mod.rs"]
mod golden;

// Import the domain-specific golden test modules
#[path = "golden/remote_capability_envelope_golden_tests.rs"]
mod remote_capability_envelope_golden_tests;

#[path = "golden/connector_lifecycle_message_golden_tests.rs"]
mod connector_lifecycle_message_golden_tests;

#[path = "golden/vef_receipt_envelope_golden_tests.rs"]
mod vef_receipt_envelope_golden_tests;

use std::env;

#[test]
fn golden_tests_usage_documentation() {
    // This test documents how to create/update golden files
    println!();
    println!("=== Golden Artifacts Test Suite ===");
    println!();
    println!("This suite tests canonical forms for:");
    println!("  • Remote capability envelopes with scope validation");
    println!("  • Connector lifecycle messages with frame validation");
    println!("  • VEF receipts with chain integrity verification");
    println!();
    println!("To create or update golden files:");
    println!("  UPDATE_GOLDENS=1 cargo test golden_remote_api_connector_vef");
    println!();
    println!("To review changes after update:");
    println!("  git diff tests/golden/");
    println!();
    println!("Golden file organization:");
    println!("  tests/golden/remote_capability_envelope/");
    println!("  tests/golden/connector_lifecycle_message/");
    println!("  tests/golden/vef_receipt_envelope/");
    println!();
    println!("All dynamic values are scrubbed for determinism:");
    println!("  • Timestamps → [TIMESTAMP]");
    println!("  • UUIDs → [UUID]");
    println!("  • Nonces → [NONCE]");
    println!("  • Hashes → [HASH]");
    println!("  • Trace IDs → [TRACE_ID]");
    println!();
}

#[test]
fn verify_scrubber_for_domain_specific_patterns() {
    // Test the scrubber handles domain-specific dynamic patterns
    let test_inputs = vec![
        (
            "remote_capability_token",
            r#"{"token_id": "cap-550e8400-e29b-41d4-a716-446655440000", "issued_at": "2026-04-20T12:00:00Z", "trace_id": "trace-12345"}"#,
        ),
        (
            "connector_frame_message",
            r#"{"frame_id": "frame-2026-04-20-001", "timestamp": "2026-04-20T12:00:00Z", "nonce_abc123def": "test"}"#,
        ),
        (
            "vef_receipt_chain",
            r#"{"receipt_hash": "sha256:abcd1234567890ef", "timestamp_millis": 1713628800000, "trace_id": "trace-vef-001"}"#,
        ),
        (
            "mixed_dynamic_content",
            r#"{"uuid": "550e8400-e29b-41d4-a716-446655440000", "timestamp": "2026-04-20T12:00:00.123Z", "mac:abcdef123456": "signature", "task-87654321": "completed"}"#,
        ),
    ];

    for (test_name, input) in test_inputs {
        let scrubbed = golden::scrub_dynamic_values(input);

        // Verify scrubbing worked
        assert!(!scrubbed.contains("2026-04-20"));
        assert!(!scrubbed.contains("550e8400"));
        assert!(!scrubbed.contains("1713628800"));

        // Test the scrubbed version as golden
        golden::assert_golden(&format!("scrubber_verification/{}", test_name), &scrubbed);
    }
}

#[test]
fn test_golden_infrastructure_integration() {
    // Test that the golden infrastructure works with complex nested structures
    use serde_json::json;

    let complex_test_structure = json!({
        "remote_capability": {
            "token_id": "cap-550e8400-e29b-41d4-a716-446655440000",
            "issuer": "test-issuer",
            "issued_at": "2026-04-20T12:00:00Z",
            "expires_at": "2026-04-20T13:00:00Z",
            "scope": {
                "operations": ["network_egress", "telemetry_export"],
                "endpoints": ["https://api.example.com/"]
            },
            "signature": "mac:abcdef1234567890"
        },
        "connector_frame": {
            "frame_id": "lifecycle-frame-001",
            "timestamp": "2026-04-20T12:00:00.456Z",
            "raw_bytes_len": 1024,
            "nesting_depth": 5,
            "decode_cpu_ms": 25,
            "trace_id": "trace-12345"
        },
        "vef_receipt": {
            "schema_version": "vef-receipt-chain-v1",
            "receipt_hash": "sha256:fedcba0987654321fedcba0987654321fedcba09",
            "chain_hash": "sha256:abcd1234567890efabcd1234567890efabcd1234",
            "timestamp_millis": 1713628800000,
            "sequence_number": 42,
            "trace_id": "trace-vef-receipt-001",
            "witness_references": [
                "witness-550e8400-e29b-41d4-a716-446655440000",
                "witness-another-uuid-here"
            ]
        }
    });

    golden::assert_scrubbed_json_golden(
        "infrastructure_integration/complex_nested_structure",
        &complex_test_structure,
    );
}

#[test]
fn validate_golden_directory_structure() {
    // Ensure golden directories exist when UPDATE_GOLDENS is set
    if env::var("UPDATE_GOLDENS").is_ok() {
        use std::fs;
        use std::path::Path;

        let golden_dirs = vec![
            "tests/golden/remote_capability_envelope",
            "tests/golden/connector_lifecycle_message",
            "tests/golden/vef_receipt_envelope",
            "tests/golden/scrubber_verification",
            "tests/golden/infrastructure_integration",
        ];

        for dir_path in golden_dirs {
            let path = Path::new(dir_path);
            if !path.exists() {
                fs::create_dir_all(path)
                    .unwrap_or_else(|_| panic!("Should create golden directory: {}", dir_path));
            }
        }
    }
}

#[test]
fn test_determinism_across_runs() {
    // Test that golden generation is deterministic across multiple runs
    use serde_json::json;
    use std::collections::BTreeMap;

    // Create identical structures that should produce identical golden output
    let create_test_structure = || {
        let mut capability_context = BTreeMap::new();
        capability_context.insert("capability_type".to_string(), "network_egress".to_string());
        capability_context.insert(
            "endpoint".to_string(),
            "https://api.example.com".to_string(),
        );

        json!({
            "determinism_test": {
                "timestamp": "2026-04-20T12:00:00Z",
                "uuid": "550e8400-e29b-41d4-a716-446655440000",
                "capability_context": capability_context,
                "sorted_array": ["alpha", "beta", "gamma"],
                "numeric_values": [1, 2, 3, 4, 5],
                "boolean_flags": {
                    "enabled": true,
                    "verified": false,
                    "authenticated": true
                }
            }
        })
    };

    let structure1 = create_test_structure();
    let structure2 = create_test_structure();

    // Structures should be identical
    assert_eq!(structure1, structure2);

    // Both should produce identical scrubbed output
    let scrubbed1 =
        golden::scrub_dynamic_values(&serde_json::to_string_pretty(&structure1).unwrap());
    let scrubbed2 =
        golden::scrub_dynamic_values(&serde_json::to_string_pretty(&structure2).unwrap());

    assert_eq!(scrubbed1, scrubbed2);

    golden::assert_golden("determinism_test/identical_structures", &scrubbed1);
}

#[test]
fn test_cross_domain_data_flow() {
    // Test a realistic data flow across all three domains
    use serde_json::json;

    let cross_domain_scenario = json!({
        "scenario": "capability_grant_with_receipt_chain",
        "flow": [
            {
                "step": 1,
                "domain": "remote_capability",
                "action": "issue_capability",
                "data": {
                    "token_id": "cross-domain-cap-001",
                    "issuer": "central-authority",
                    "issued_at": "2026-04-20T12:00:00Z",
                    "scope": {
                        "operations": ["remote_computation"],
                        "endpoints": ["https://compute.example.com/"]
                    },
                    "trace_id": "trace-cross-domain-001"
                }
            },
            {
                "step": 2,
                "domain": "connector_lifecycle",
                "action": "validate_frame",
                "data": {
                    "frame_id": "computation-request-frame",
                    "timestamp": "2026-04-20T12:00:01Z",
                    "raw_bytes_len": 2048,
                    "nesting_depth": 3,
                    "decode_cpu_ms": 15,
                    "trace_id": "trace-cross-domain-001"
                }
            },
            {
                "step": 3,
                "domain": "vef_receipt",
                "action": "create_execution_receipt",
                "data": {
                    "schema_version": "vef-receipt-chain-v1",
                    "action_type": "capability_grant",
                    "actor_identity": "computation-service",
                    "artifact_identity": "cross-domain-computation",
                    "timestamp_millis": 1713628801000,
                    "sequence_number": 1,
                    "trace_id": "trace-cross-domain-001",
                    "capability_context": {
                        "granted_capability": "cross-domain-cap-001",
                        "frame_validation": "computation-request-frame"
                    }
                }
            }
        ],
        "integrity_checks": {
            "trace_id_consistency": true,
            "temporal_ordering": true,
            "capability_chain_valid": true
        }
    });

    golden::assert_scrubbed_json_golden(
        "cross_domain_integration/capability_grant_flow",
        &cross_domain_scenario,
    );
}

// Re-export the domain-specific tests so they run with this suite
pub use connector_lifecycle_message_golden_tests::*;
pub use remote_capability_envelope_golden_tests::*;
pub use vef_receipt_envelope_golden_tests::*;
