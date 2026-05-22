//! Quick smoke test for trust card snapshot parsing fuzzing
//!
//! This module provides a quick way to test our fuzzing logic without
//! waiting for the full libfuzzer compilation.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use frankenengine_node::supply_chain::trust_card::{
    SnapshotSourceContext, TrustCard, TrustCardError, TrustCardRegistry, TrustCardRegistrySnapshot,
};
use serde_json::{Map, Value};

const DEFAULT_TEST_REGISTRY_KEY: &[u8] = b"franken-node-trust-card-registry-key-v1";

fn assert_snapshot_roundtrips(snapshot: &TrustCardRegistrySnapshot) {
    let encoded =
        serde_json::to_vec(snapshot).expect("parsed trust-card snapshot should serialize");
    let decoded = serde_json::from_slice::<TrustCardRegistrySnapshot>(&encoded)
        .expect("serialized trust-card snapshot should parse from bytes");
    assert_eq!(
        snapshot, &decoded,
        "trust-card snapshot must survive byte serde roundtrip"
    );

    let encoded_string =
        serde_json::to_string(snapshot).expect("parsed trust-card snapshot should stringify");
    let decoded_string = serde_json::from_str::<TrustCardRegistrySnapshot>(&encoded_string)
        .expect("serialized trust-card snapshot should parse from string");
    assert_eq!(
        snapshot, &decoded_string,
        "trust-card snapshot must survive string serde roundtrip"
    );
}

fn assert_snapshot_debug_redacts_authentication_material(
    snapshot: &TrustCardRegistrySnapshot,
    label: &str,
) {
    let debug = format!("{snapshot:?}");

    assert!(
        !debug.contains(&snapshot.snapshot_hash),
        "{label} debug output must redact snapshot_hash"
    );
    assert!(
        !debug.contains(&snapshot.registry_signature),
        "{label} debug output must redact registry_signature"
    );
}

fn signed_empty_snapshot_value() -> Value {
    let snapshot = TrustCardRegistry::default()
        .snapshot()
        .expect("default trust-card registry snapshot should sign");
    serde_json::to_value(snapshot).expect("signed trust-card snapshot should convert to JSON")
}

fn snapshot_bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("trust-card snapshot corpus value should serialize")
}

fn mutated_snapshot_bytes(value: &Value, mutate: impl FnOnce(&mut Map<String, Value>)) -> Vec<u8> {
    let mut mutated = value.clone();
    mutate(
        mutated
            .as_object_mut()
            .expect("signed trust-card snapshot should serialize as an object"),
    );
    snapshot_bytes(mutated)
}

fn signed_snapshot_value_with_empty_history(extension_id: &str) -> Value {
    let mut cards_by_extension: BTreeMap<String, Vec<TrustCard>> = BTreeMap::new();
    cards_by_extension.insert(extension_id.to_string(), Vec::new());
    let snapshot =
        TrustCardRegistrySnapshot::signed(60, cards_by_extension, DEFAULT_TEST_REGISTRY_KEY)
            .expect("empty-history fuzz snapshot should sign before semantic validation");
    serde_json::to_value(snapshot)
        .expect("signed empty-history trust-card snapshot should convert to JSON")
}

fn trust_card_high_water_path(snapshot_path: &Path) -> PathBuf {
    let parent = snapshot_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = snapshot_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("trust-card-registry-state");
    parent.join(format!("{file_name}.high-water.json"))
}

fn structure_aware_snapshot_fuzz_corpus() -> Vec<(&'static str, Vec<u8>, bool)> {
    let valid_snapshot = signed_empty_snapshot_value();

    vec![
        (
            "valid-signed-empty-snapshot",
            snapshot_bytes(valid_snapshot.clone()),
            true,
        ),
        ("invalid-utf8", vec![0xff, 0xfe, b'{'], false),
        ("non-object-json", b"[]".to_vec(), false),
        (
            "unknown-field",
            mutated_snapshot_bytes(&valid_snapshot, |object| {
                object.insert("unexpected_field".to_string(), Value::Bool(true));
            }),
            false,
        ),
        (
            "tampered-snapshot-hash",
            mutated_snapshot_bytes(&valid_snapshot, |object| {
                object.insert("snapshot_hash".to_string(), Value::String("00".repeat(32)));
            }),
            false,
        ),
        (
            "tampered-registry-signature",
            mutated_snapshot_bytes(&valid_snapshot, |object| {
                object.insert(
                    "registry_signature".to_string(),
                    Value::String("00".repeat(32)),
                );
            }),
            false,
        ),
        (
            "missing-registry-signature",
            mutated_snapshot_bytes(&valid_snapshot, |object| {
                object.remove("registry_signature");
            }),
            false,
        ),
        (
            "zero-cache-ttl",
            mutated_snapshot_bytes(&valid_snapshot, |object| {
                object.insert("cache_ttl_secs".to_string(), Value::Number(0_u64.into()));
            }),
            false,
        ),
        (
            "cards-wrong-type",
            mutated_snapshot_bytes(&valid_snapshot, |object| {
                object.insert(
                    "cards_by_extension".to_string(),
                    Value::Array(vec![Value::String("not-a-registry-map".to_string())]),
                );
            }),
            false,
        ),
        (
            "unsupported-schema",
            mutated_snapshot_bytes(&valid_snapshot, |object| {
                object.insert(
                    "schema_version".to_string(),
                    Value::String("franken-node/trust-card-registry-state/v0".to_string()),
                );
            }),
            false,
        ),
        (
            "oversized-schema-string",
            mutated_snapshot_bytes(&valid_snapshot, |object| {
                object.insert(
                    "schema_version".to_string(),
                    Value::String("A".repeat(16_384)),
                );
            }),
            false,
        ),
        (
            "deep-nested-malformed-json",
            b"{\"schema_version\":{\"nested\":{\"nested\":{\"nested\":true}}}}".to_vec(),
            false,
        ),
    ]
}

fn signed_postparse_invalid_snapshot_fuzz_corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![(
        "signed-empty-history-bucket",
        snapshot_bytes(signed_snapshot_value_with_empty_history(
            "npm:@acme/postparse-fuzz",
        )),
    )]
}

/// Structure-aware supply-chain fuzz regression for untrusted trust-card snapshots.
#[test]
fn structure_aware_snapshot_fuzz_corpus_fails_closed_for_untrusted_loads() {
    for (label, bytes, should_load) in structure_aware_snapshot_fuzz_corpus() {
        if let Ok(snapshot) = serde_json::from_slice::<TrustCardRegistrySnapshot>(&bytes) {
            assert_snapshot_roundtrips(&snapshot);
            assert_snapshot_debug_redacts_authentication_material(&snapshot, label);
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("{label}.json"));
        std::fs::write(&path, &bytes).expect("write trust-card fuzz seed");

        let result = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::UntrustedNetwork,
        );

        if should_load {
            assert!(result.is_ok(), "{label} should load, got {result:?}");
            assert!(
                trust_card_high_water_path(&path).exists(),
                "{label} should persist a signed high-water marker after successful load"
            );
            continue;
        }

        let err = result.unwrap_err();
        assert!(
            !trust_card_high_water_path(&path).exists(),
            "{label} must not persist high-water state after failed untrusted validation"
        );
        match err {
            TrustCardError::InvalidSnapshot(detail) => {
                assert_eq!(
                    detail, "snapshot validation failed",
                    "{label} should return sanitized validation detail"
                );
            }
            TrustCardError::SnapshotParse { detail, .. } => {
                assert_eq!(
                    detail, "parsing failed",
                    "{label} should return sanitized parse detail"
                );
            }
            TrustCardError::UnsupportedSnapshotSchema(schema) => {
                assert!(
                    !schema.chars().any(char::is_control),
                    "{label} unsupported schema error must not echo control characters"
                );
            }
            TrustCardError::SnapshotRead { detail, .. } => {
                assert!(
                    detail.contains("valid UTF-8"),
                    "{label} should only fail during read for non-UTF-8 fuzz bytes"
                );
            }
            other => assert!(
                matches!(&other, TrustCardError::InvalidSnapshot(_)),
                "{label} returned unexpected untrusted-load error: {other:?}"
            ),
        }
    }
}

/// Fuzz signed snapshots that pass signature preflight but fail during semantic restore.
#[test]
fn signed_postparse_invalid_snapshot_fuzz_corpus_sanitizes_untrusted_failures() {
    for (label, bytes) in signed_postparse_invalid_snapshot_fuzz_corpus() {
        let snapshot = serde_json::from_slice::<TrustCardRegistrySnapshot>(&bytes)
            .expect("post-parse invalid fuzz seed should remain syntactically valid");
        assert_snapshot_roundtrips(&snapshot);
        assert_snapshot_debug_redacts_authentication_material(&snapshot, label);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(format!("{label}.json"));
        std::fs::write(&path, &bytes).expect("write post-parse trust-card fuzz seed");

        let result = TrustCardRegistry::load_authoritative_state(
            &path,
            60,
            2_000,
            SnapshotSourceContext::UntrustedNetwork,
        );

        assert!(
            result.is_err(),
            "{label} should fail after signature preflight but before high-water persistence"
        );
        let err =
            result.expect_err("post-parse invalid signed snapshot should fail untrusted loading");
        assert!(
            !trust_card_high_water_path(&path).exists(),
            "{label} must not persist high-water state after semantic restore rejection"
        );
        match err {
            TrustCardError::InvalidSnapshot(detail) => {
                assert_eq!(
                    detail, "snapshot validation failed",
                    "{label} should sanitize post-parse InvalidSnapshot detail"
                );
            }
            other => assert!(
                matches!(&other, TrustCardError::InvalidSnapshot(_)),
                "{label} returned unexpected post-parse untrusted-load error: {other:?}"
            ),
        }
    }
}

/// Test that the fuzzing target logic works correctly
#[test]
fn test_trust_card_snapshot_parse_fuzz_logic() {
    // Test cases that mirror what our fuzz harness will encounter
    let test_cases: &[&[u8]] = &[
        b"", // Empty
        b"{}", // Minimal JSON
        b"{\"schema_version\":\"test\",\"snapshot_epoch\":123,\"cache_ttl_secs\":300,\"cards_by_extension\":{},\"snapshot_hash\":\"abc\",\"registry_signature\":\"def\"}", // Valid-ish structure
        b"invalid json", // Invalid
        b"\x00\xff\x00\xff", // Binary data
        b"{\"snapshot_epoch\":18446744073709551615}", // Large number
        b"null", // Null
        b"[]", // Array instead of object
        b"{{}}", // Nested empty objects
    ];

    let mut parsed_count = 0;
    let mut error_count = 0;
    let mut byte_parsed_count = 0;
    let mut byte_error_count = 0;

    for (i, test_data) in test_cases.iter().enumerate() {
        println!(
            "Testing case {}: {:?}",
            i,
            std::str::from_utf8(test_data).unwrap_or("<binary>")
        );

        // Test UTF-8 conversion
        let utf8_result = std::str::from_utf8(test_data);

        // Test JSON parsing if UTF-8 succeeds
        let parsed_snapshot = if let Ok(json_str) = utf8_result {
            match serde_json::from_str::<TrustCardRegistrySnapshot>(json_str) {
                Ok(snapshot) => {
                    assert_snapshot_roundtrips(&snapshot);
                    parsed_count += 1;
                    println!("  → Parsed successfully");
                    Some(snapshot)
                }
                Err(e) => {
                    error_count += 1;
                    println!("  → Parse error (expected): {}", e);
                    None
                }
            }
        } else {
            println!("  → Invalid UTF-8 (expected)");
            error_count += 1;
            None
        };

        // Test direct byte parsing
        match serde_json::from_slice::<TrustCardRegistrySnapshot>(test_data) {
            Ok(byte_snapshot) => {
                assert_snapshot_roundtrips(&byte_snapshot);
                if let Some(parsed_snapshot) = &parsed_snapshot {
                    assert_eq!(
                        &byte_snapshot, parsed_snapshot,
                        "string and byte parsing must agree for case {i}"
                    );
                }
                byte_parsed_count += 1;
                println!("  → Byte parse succeeded");
            }
            Err(e) => {
                assert!(
                    parsed_snapshot.is_none(),
                    "byte parsing failed after string parsing succeeded for case {i}: {e}"
                );
                byte_error_count += 1;
                println!("  → Byte parse error (expected): {}", e);
            }
        }

        println!();
    }

    println!(
        "Summary: {} string parses, {} string errors, {} byte parses, {} byte errors",
        parsed_count, error_count, byte_parsed_count, byte_error_count
    );

    assert!(
        parsed_count > 0,
        "fuzz smoke corpus should include at least one valid trust-card snapshot"
    );
    assert_eq!(
        parsed_count, byte_parsed_count,
        "string and byte parsing should accept the same trust-card snapshot corpus cases"
    );
    assert_eq!(
        error_count, byte_error_count,
        "string and byte parsing should reject the same malformed corpus cases"
    );

    // We expect mostly errors since most test cases are malformed
    assert!(
        error_count > 0,
        "Should have parsing errors for malformed inputs"
    );

    // Verify that no panics occurred (test itself would have failed)
    println!("✅ No panics occurred during fuzzing logic test");
}

/// Test edge cases that could cause issues
#[test]
fn test_trust_card_snapshot_parse_edge_cases() {
    // Large JSON string that could cause allocation issues
    let large_string = "A".repeat(50000);
    let large_json = format!("{{\"schema_version\":\"{}\"}}", large_string);

    serde_json::from_str::<TrustCardRegistrySnapshot>(&large_json)
        .expect_err("partial snapshot with huge schema_version must be rejected");

    // Deeply nested JSON that could cause stack overflow
    let mut nested = "{}".to_string();
    for _ in 0..100 {
        nested = format!("{{{}}}", nested);
    }

    serde_json::from_str::<TrustCardRegistrySnapshot>(&nested)
        .expect_err("deeply nested malformed JSON must be rejected");

    println!("✅ Edge case tests completed without panics");
}
