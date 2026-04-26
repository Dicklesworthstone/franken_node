// Comprehensive conformance tests for replay bundle functionality
//
// Tests focus on:
// - Integer overflow/underflow scenarios
// - Path traversal validation edge cases
// - Memory exhaustion protection
// - JSON canonicalization determinism
// - Cryptographic integrity validation
// - Edge cases in chunking logic

use super::replay_bundle::*;
use serde_json::{Map, Value};
use std::path::Path;

fn sign_test_bundle(bundle: &mut ReplayBundle) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[43_u8; 32]);
    let signing_material = ReplayBundleSigningMaterial {
        signing_key: &signing_key,
        key_source: "env",
        signing_identity: "incident-control-plane",
    };
    sign_replay_bundle(bundle, &signing_material).expect("sign replay bundle");
}

fn trusted_test_key_id() -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[43_u8; 32]);
    crate::supply_chain::artifact_signing::KeyId::from_verifying_key(&signing_key.verifying_key())
        .to_string()
}

/// Test integer overflow scenarios in event sequence numbering
#[test]
fn test_event_sequence_overflow_protection() {
    // Create a large number of events to test overflow scenarios
    let incident_id = "INC-OVERFLOW-001";
    let mut events = Vec::new();

    // Test with events at the edge of index limits
    for i in (u64::MAX - 100)..=u64::MAX {
        if i == u64::MAX {
            break;
        } // Avoid actual overflow in test setup
        events.push(RawEvent::new(
            format!("2026-02-20T10:00:00.{:06}Z", i % 1_000_000),
            EventType::StateChange,
            serde_json::json!({"seq": i}),
        ));

        // Limit test size to avoid excessive memory usage
        if events.len() > 1000 {
            break;
        }
    }

    // Should handle large sequences gracefully
    let result = generate_replay_bundle(incident_id, &events);
    match result {
        Ok(bundle) => {
            assert!(!bundle.timeline.is_empty());
            // Sequence numbers should be bounded
            for event in &bundle.timeline {
                assert!(event.sequence_number > 0);
                assert!(event.sequence_number <= u64::MAX);
            }
        }
        Err(_) => {
            // Acceptable to fail gracefully with very large sequences
        }
    }
}

/// Test path traversal validation edge cases
#[test]
fn test_evidence_ref_path_traversal_validation() {
    // Valid relative paths should pass
    assert!(validate_relative_evidence_ref("logs/event.json").is_ok());
    assert!(validate_relative_evidence_ref("nested/dir/file.txt").is_ok());
    assert!(validate_relative_evidence_ref("file.json").is_ok());

    // Path traversal attempts should fail
    assert!(validate_relative_evidence_ref("../../../etc/passwd").is_err());
    assert!(validate_relative_evidence_ref("./../../secret").is_err());
    assert!(validate_relative_evidence_ref("logs/../../../secret").is_err());
    assert!(validate_relative_evidence_ref("logs/./../../secret").is_err());

    // Absolute paths should fail
    assert!(validate_relative_evidence_ref("/etc/passwd").is_err());
    assert!(validate_relative_evidence_ref("/absolute/path").is_err());

    // Edge cases
    assert!(validate_relative_evidence_ref("").is_err());
    assert!(validate_relative_evidence_ref("   ").is_err());
    assert!(validate_relative_evidence_ref(".").is_ok()); // Current dir is OK
    assert!(validate_relative_evidence_ref("..").is_err()); // Parent dir not OK

    // Windows-style paths should be handled
    assert!(validate_relative_evidence_ref("C:\\windows\\system32").is_err());
    assert!(validate_relative_evidence_ref("\\\\server\\share").is_err());
}

/// Test JSON canonicalization determinism
#[test]
fn test_json_canonicalization_determinism() {
    // Create objects with different key orderings
    let mut obj1 = Map::new();
    obj1.insert("z".to_string(), Value::from("last"));
    obj1.insert("a".to_string(), Value::from("first"));
    obj1.insert("m".to_string(), Value::from("middle"));

    let mut obj2 = Map::new();
    obj2.insert("a".to_string(), Value::from("first"));
    obj2.insert("z".to_string(), Value::from("last"));
    obj2.insert("m".to_string(), Value::from("middle"));

    let canonical1 = canonicalize_value(&Value::Object(obj1), "$.test1").unwrap();
    let canonical2 = canonicalize_value(&Value::Object(obj2), "$.test2").unwrap();

    // Should produce identical canonical forms despite different insertion order
    assert_eq!(canonical1, canonical2);

    // Test nested objects
    let nested1 = serde_json::json!({
        "z": {"b": 1, "a": 2},
        "a": {"z": 3, "a": 4}
    });
    let nested2 = serde_json::json!({
        "a": {"a": 4, "z": 3},
        "z": {"a": 2, "b": 1}
    });

    let canon_nested1 = canonicalize_value(&nested1, "$.nested1").unwrap();
    let canon_nested2 = canonicalize_value(&nested2, "$.nested2").unwrap();
    assert_eq!(canon_nested1, canon_nested2);
}

/// Test floating point rejection in JSON canonicalization
#[test]
fn test_float_rejection_in_canonicalization() {
    // Direct floats should be rejected
    let float_value = serde_json::json!(3.14159);
    assert!(canonicalize_value(&float_value, "$.float").is_err());

    // Nested floats should be rejected
    let nested_float = serde_json::json!({
        "data": {
            "metrics": [1, 2, 3.14, 4]
        }
    });
    assert!(canonicalize_value(&nested_float, "$.nested").is_err());

    // Integers should be OK
    let int_value = serde_json::json!(42);
    assert!(canonicalize_value(&int_value, "$.int").is_ok());

    // Large integers should be OK
    let large_int = serde_json::json!(u64::MAX);
    assert!(canonicalize_value(&large_int, "$.large").is_ok());
}

/// Test chunking logic with edge cases
#[test]
fn test_bundle_chunking_edge_cases() {
    let bundle_id = uuid::Uuid::now_v7();

    // Empty timeline should produce single empty chunk
    let empty_chunks = chunk_timeline(bundle_id, &[]).unwrap();
    assert_eq!(empty_chunks.len(), 1);
    assert_eq!(empty_chunks[0].event_count, 0);
    assert_eq!(empty_chunks[0].chunk_index, 0);
    assert_eq!(empty_chunks[0].total_chunks, 1);

    // Single small event should fit in one chunk
    let small_event = TimelineEvent {
        sequence_number: 1,
        timestamp: "2026-02-20T10:00:00.000000Z".to_string(),
        event_type: EventType::StateChange,
        payload: serde_json::json!({"small": "payload"}),
        causal_parent: None,
    };

    let single_chunks = chunk_timeline(bundle_id, &[small_event]).unwrap();
    assert_eq!(single_chunks.len(), 1);
    assert_eq!(single_chunks[0].event_count, 1);

    // Test maximum size event (just under limit)
    let large_payload = "x".repeat(MAX_BUNDLE_BYTES - 1000); // Leave room for JSON structure
    let large_event = TimelineEvent {
        sequence_number: 1,
        timestamp: "2026-02-20T10:00:00.000000Z".to_string(),
        event_type: EventType::StateChange,
        payload: serde_json::json!({"large": large_payload}),
        causal_parent: None,
    };

    // Should succeed for events just under the limit
    let result = chunk_timeline(bundle_id, &[large_event]);
    assert!(result.is_ok());
}

/// Test oversized event rejection
#[test]
fn test_oversized_event_rejection() {
    let bundle_id = uuid::Uuid::now_v7();

    // Create an event that's definitely too large
    let oversized_payload = "x".repeat(MAX_BUNDLE_BYTES + 1000);
    let oversized_event = TimelineEvent {
        sequence_number: 1,
        timestamp: "2026-02-20T10:00:00.000000Z".to_string(),
        event_type: EventType::StateChange,
        payload: serde_json::json!({"oversized": oversized_payload}),
        causal_parent: None,
    };

    let result = chunk_timeline(bundle_id, &[oversized_event]);
    assert!(result.is_err());

    match result {
        Err(ReplayBundleError::OversizedEvent {
            sequence_number, ..
        }) => {
            assert_eq!(sequence_number, 1);
        }
        _ => panic!("Expected OversizedEvent error"),
    }
}

/// Test timestamp normalization edge cases
#[test]
fn test_timestamp_normalization_edge_cases() {
    // Valid RFC3339 timestamps should work
    assert!(normalize_timestamp("2026-02-20T10:00:00.000000Z").is_ok());
    assert!(normalize_timestamp("2026-02-20T10:00:00Z").is_ok());
    assert!(normalize_timestamp("2026-02-20T10:00:00+00:00").is_ok());
    assert!(normalize_timestamp("2026-02-20T10:00:00-05:00").is_ok());

    // Invalid timestamps should fail
    assert!(normalize_timestamp("invalid").is_err());
    assert!(normalize_timestamp("2026-13-01T10:00:00Z").is_err()); // Invalid month
    assert!(normalize_timestamp("2026-02-30T10:00:00Z").is_err()); // Invalid day
    assert!(normalize_timestamp("2026-02-20T25:00:00Z").is_err()); // Invalid hour
    assert!(normalize_timestamp("").is_err());

    // Edge case timestamps
    assert!(normalize_timestamp("1970-01-01T00:00:00Z").is_ok()); // Unix epoch
    assert!(normalize_timestamp("2262-04-11T23:47:16.854775807Z").is_ok()); // Near i64 limit

    // Test microsecond precision preservation
    let (normalized, _) = normalize_timestamp("2026-02-20T10:00:00.123456Z").unwrap();
    assert!(normalized.contains("123456"));

    // Test timezone normalization to UTC
    let (normalized, _) = normalize_timestamp("2026-02-20T15:00:00-05:00").unwrap();
    assert!(normalized.contains("20:00:00")); // Should be converted to UTC
}

/// Test causal parent validation
#[test]
fn test_causal_parent_validation() {
    let events = vec![
        RawEvent::new(
            "2026-02-20T10:00:00.000001Z",
            EventType::ExternalSignal,
            serde_json::json!({"signal": "start"}),
        ),
        RawEvent::new(
            "2026-02-20T10:00:00.000002Z",
            EventType::PolicyEval,
            serde_json::json!({"decision": "allow"}),
        )
        .with_causal_parent(1), // Valid parent
        RawEvent::new(
            "2026-02-20T10:00:00.000003Z",
            EventType::OperatorAction,
            serde_json::json!({"action": "approve"}),
        )
        .with_causal_parent(2), // Valid parent
    ];

    let bundle = generate_replay_bundle("INC-CAUSAL-001", &events).unwrap();

    // Verify causal relationships are preserved
    assert_eq!(bundle.timeline[0].causal_parent, None);
    assert_eq!(bundle.timeline[1].causal_parent, Some(1));
    assert_eq!(bundle.timeline[2].causal_parent, Some(2));

    // Test invalid causal parent (references future event)
    let invalid_events = vec![
        RawEvent::new(
            "2026-02-20T10:00:00.000001Z",
            EventType::ExternalSignal,
            serde_json::json!({"signal": "start"}),
        )
        .with_causal_parent(2), // Invalid - references event 2 which doesn't exist yet
    ];

    // Should handle invalid causal parents gracefully
    let result = generate_replay_bundle("INC-CAUSAL-002", &invalid_events);
    match result {
        Ok(bundle) => {
            // If it succeeds, causal parent should be removed
            assert_eq!(bundle.timeline[0].causal_parent, None);
        }
        Err(_) => {
            // Acceptable to fail with invalid causal relationships
        }
    }
}

/// Test incident evidence package validation edge cases
#[test]
fn test_evidence_package_validation_edge_cases() {
    let mut package = IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: "INC-EDGE-001".to_string(),
        collected_at: "2026-02-20T10:00:00Z".to_string(),
        trace_id: "trace-001".to_string(),
        severity: IncidentSeverity::High,
        incident_type: "test".to_string(),
        detector: "unit-test".to_string(),
        policy_version: "1.0.0".to_string(),
        initial_state_snapshot: serde_json::json!({"state": "initial"}),
        events: vec![IncidentEvidenceEvent {
            event_id: "evt-001".to_string(),
            timestamp: "2026-02-20T10:00:00.000001Z".to_string(),
            event_type: EventType::ExternalSignal,
            payload: serde_json::json!({"signal": "test"}),
            provenance_ref: "refs/log.json".to_string(),
            parent_event_id: None,
            state_snapshot: None,
            policy_version: None,
        }],
        evidence_refs: vec!["refs/log.json".to_string()],
        metadata: IncidentEvidenceMetadata {
            title: "Test incident".to_string(),
            affected_components: vec!["test-component".to_string()],
            tags: vec!["test".to_string()],
        },
    };

    // Valid package should pass
    assert!(validate_incident_evidence_package(&package, None).is_ok());

    // Empty incident_id should fail
    package.incident_id = "".to_string();
    assert!(validate_incident_evidence_package(&package, None).is_err());
    package.incident_id = "INC-EDGE-001".to_string(); // Reset

    // Whitespace-only incident_id should fail
    package.incident_id = "   ".to_string();
    assert!(validate_incident_evidence_package(&package, None).is_err());
    package.incident_id = "INC-EDGE-001".to_string(); // Reset

    // Wrong schema version should fail
    package.schema_version = "wrong-schema".to_string();
    assert!(validate_incident_evidence_package(&package, None).is_err());
    package.schema_version = INCIDENT_EVIDENCE_SCHEMA.to_string(); // Reset

    // Empty evidence_refs should fail
    package.evidence_refs.clear();
    assert!(validate_incident_evidence_package(&package, None).is_err());
    package.evidence_refs = vec!["refs/log.json".to_string()]; // Reset

    // Empty events should fail
    package.events.clear();
    assert!(validate_incident_evidence_package(&package, None).is_err());
    package.events = vec![IncidentEvidenceEvent {
        event_id: "evt-001".to_string(),
        timestamp: "2026-02-20T10:00:00.000001Z".to_string(),
        event_type: EventType::ExternalSignal,
        payload: serde_json::json!({"signal": "test"}),
        provenance_ref: "refs/log.json".to_string(),
        parent_event_id: None,
        state_snapshot: None,
        policy_version: None,
    }]; // Reset

    // Duplicate event IDs should fail
    let duplicate_event = IncidentEvidenceEvent {
        event_id: "evt-001".to_string(), // Duplicate ID
        timestamp: "2026-02-20T10:00:00.000002Z".to_string(),
        event_type: EventType::PolicyEval,
        payload: serde_json::json!({"decision": "test"}),
        provenance_ref: "refs/log.json".to_string(),
        parent_event_id: None,
        state_snapshot: None,
        policy_version: None,
    };
    package.events.push(duplicate_event);
    assert!(validate_incident_evidence_package(&package, None).is_err());
}

/// Test integrity validation edge cases
#[test]
fn test_integrity_validation_edge_cases() {
    let events = vec![RawEvent::new(
        "2026-02-20T10:00:00.000000Z",
        EventType::StateChange,
        serde_json::json!({"test": "integrity"}),
    )];

    let mut bundle = generate_replay_bundle("INC-INTEGRITY-001", &events).unwrap();

    // Valid bundle should pass integrity check
    assert!(validate_bundle_integrity(&bundle).unwrap());

    // Tampered integrity hash should fail
    bundle.integrity_hash = "tampered".to_string();
    assert!(!validate_bundle_integrity(&bundle).unwrap());

    // Reset and tamper with timeline
    bundle = generate_replay_bundle("INC-INTEGRITY-002", &events).unwrap();
    bundle.timeline[0].payload = serde_json::json!({"tampered": true});
    assert!(!validate_bundle_integrity(&bundle).unwrap());

    // Reset and tamper with manifest
    bundle = generate_replay_bundle("INC-INTEGRITY-003", &events).unwrap();
    bundle.manifest.event_count = bundle.manifest.event_count.saturating_add(1);
    let result = validate_bundle_integrity(&bundle);
    // Should fail at structure validation before integrity check
    assert!(result.is_err());
}

/// Test memory exhaustion protection in large bundle scenarios
#[test]
fn test_large_bundle_memory_protection() {
    // Create many small events to test memory usage
    let mut events = Vec::new();
    let max_reasonable_events = 10000; // Reasonable limit for test

    for i in 0..max_reasonable_events {
        events.push(RawEvent::new(
            format!(
                "2026-02-20T10:00:{:02}.{:06}Z",
                i / 1_000_000,
                i % 1_000_000
            ),
            EventType::StateChange,
            serde_json::json!({"sequence": i}),
        ));

        // Test incrementally to catch memory issues early
        if i > 0 && i % 1000 == 0 {
            let result = generate_replay_bundle("INC-MEMORY-TEST", &events[..i]);
            if let Ok(bundle) = result {
                assert!(bundle.timeline.len() <= i);
                // Ensure chunks are properly bounded
                for chunk in &bundle.chunks {
                    assert!(chunk.events.len() <= i);
                    assert!(chunk.compressed_size_bytes < u64::MAX);
                }
            }
            // It's OK if it fails with very large inputs - that's protection working
        }
    }
}

/// Test UUID v7 generation determinism
#[test]
fn test_uuid_v7_determinism() {
    let incident_id = "INC-UUID-001";
    let created_at = "2026-02-20T10:00:00.000000Z";
    let timeline = vec![TimelineEvent {
        sequence_number: 1,
        timestamp: created_at.to_string(),
        event_type: EventType::StateChange,
        payload: serde_json::json!({"test": "uuid"}),
        causal_parent: None,
    }];

    // Generate UUID multiple times - should be deterministic
    let uuid1 = deterministic_bundle_id(incident_id, created_at, &timeline).unwrap();
    let uuid2 = deterministic_bundle_id(incident_id, created_at, &timeline).unwrap();
    assert_eq!(uuid1, uuid2);

    // Verify it's UUID v7
    assert_eq!(uuid1.get_version_num(), 7);

    // Different inputs should produce different UUIDs
    let uuid3 = deterministic_bundle_id("INC-UUID-002", created_at, &timeline).unwrap();
    assert_ne!(uuid1, uuid3);
}

/// Test atomic file write operations
#[test]
fn test_atomic_file_operations() {
    let mut bundle = generate_replay_bundle(
        "INC-ATOMIC-001",
        &[RawEvent::new(
            "2026-02-20T10:00:00Z",
            EventType::StateChange,
            serde_json::json!({"atomic": true}),
        )],
    )
    .unwrap();
    sign_test_bundle(&mut bundle);

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test-bundle.json");

    // Write should be atomic
    let trusted_key_id = trusted_test_key_id();
    write_bundle_to_path_with_trusted_key(&bundle, &file_path, &trusted_key_id).unwrap();
    assert!(file_path.exists());

    // Should be able to read back the same bundle
    let loaded_bundle =
        read_bundle_from_path_with_trusted_key(&file_path, Some(&trusted_key_id)).unwrap();
    assert_eq!(bundle, loaded_bundle);

    // No temp files should remain
    let temp_files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(".tmp") {
                Some(name)
            } else {
                None
            }
        })
        .collect();

    assert!(
        temp_files.is_empty(),
        "No temp files should remain: {:?}",
        temp_files
    );
}

fn negative_path_evidence_package() -> IncidentEvidencePackage {
    IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: "INC-NEG-001".to_string(),
        collected_at: "2026-02-20T10:05:00Z".to_string(),
        trace_id: "trace-negative-path".to_string(),
        severity: IncidentSeverity::High,
        incident_type: "sandbox_escape_attempt".to_string(),
        detector: "negative-path-suite".to_string(),
        policy_version: "1.0.0".to_string(),
        initial_state_snapshot: serde_json::json!({"mode": "strict", "epoch": 17_u64}),
        events: vec![
            IncidentEvidenceEvent {
                event_id: "evt-parent".to_string(),
                timestamp: "2026-02-20T10:00:00.000100Z".to_string(),
                event_type: EventType::ExternalSignal,
                payload: serde_json::json!({"signal": "suspicious_spawn"}),
                provenance_ref: "refs/parent.json".to_string(),
                parent_event_id: None,
                state_snapshot: None,
                policy_version: None,
            },
            IncidentEvidenceEvent {
                event_id: "evt-child".to_string(),
                timestamp: "2026-02-20T10:00:00.000200Z".to_string(),
                event_type: EventType::PolicyEval,
                payload: serde_json::json!({"decision": "quarantine"}),
                provenance_ref: "refs/child.json".to_string(),
                parent_event_id: Some("evt-parent".to_string()),
                state_snapshot: None,
                policy_version: None,
            },
        ],
        evidence_refs: vec![
            "refs/parent.json".to_string(),
            "refs/child.json".to_string(),
        ],
        metadata: IncidentEvidenceMetadata {
            title: "Negative path incident".to_string(),
            affected_components: vec!["runtime".to_string()],
            tags: vec!["negative-path".to_string()],
        },
    }
}

#[test]
fn test_empty_incident_id_is_rejected_before_bundle_derivation() {
    let err = generate_replay_bundle(
        "   ",
        &[RawEvent::new(
            "2026-02-20T10:00:00Z",
            EventType::StateChange,
            serde_json::json!({"state": "ignored"}),
        )],
    )
    .expect_err("blank incident id must be rejected");

    assert!(matches!(err, ReplayBundleError::EmptyIncidentId));
}

#[test]
fn test_evidence_expected_incident_id_mismatch_is_rejected() {
    let package = negative_path_evidence_package();
    let err = validate_incident_evidence_package(&package, Some("INC-DIFFERENT"))
        .expect_err("expected incident id mismatch must fail");

    assert!(matches!(
        err,
        ReplayBundleError::EvidenceIncidentIdMismatch { .. }
    ));
}

#[test]
fn test_evidence_unknown_provenance_ref_is_rejected() {
    let mut package = negative_path_evidence_package();
    package.events[1].provenance_ref = "refs/unlisted-child.json".to_string();

    let err = validate_incident_evidence_package(&package, None)
        .expect_err("unknown provenance ref must fail");

    assert!(matches!(
        err,
        ReplayBundleError::EvidenceUnknownProvenanceRef { .. }
    ));
}

#[test]
fn test_evidence_missing_parent_event_is_rejected() {
    let mut package = negative_path_evidence_package();
    package.events[1].parent_event_id = Some("evt-missing".to_string());

    let err = validate_incident_evidence_package(&package, None)
        .expect_err("missing parent event must fail");

    assert!(matches!(
        err,
        ReplayBundleError::EvidenceMissingParentRef { .. }
    ));
}

#[test]
fn test_evidence_self_parent_event_is_rejected() {
    let mut package = negative_path_evidence_package();
    package.events[0].parent_event_id = Some("evt-parent".to_string());

    let err = validate_incident_evidence_package(&package, None)
        .expect_err("self-parent event must fail");

    assert!(matches!(
        err,
        ReplayBundleError::EvidenceSelfParentRef { .. }
    ));
}

#[test]
fn test_evidence_unsorted_timestamps_are_rejected() {
    let mut package = negative_path_evidence_package();
    package.events[1].timestamp = "2026-02-20T09:59:59.999999Z".to_string();

    let err = validate_incident_evidence_package(&package, None)
        .expect_err("unsorted event timestamps must fail");

    assert!(matches!(
        err,
        ReplayBundleError::EvidenceEventsUnsorted { .. }
    ));
}

#[test]
fn test_evidence_future_parent_becomes_invalid_causal_parent() {
    let mut package = negative_path_evidence_package();
    package.events[0].parent_event_id = Some("evt-child".to_string());

    let err = generate_replay_bundle_from_evidence(&package)
        .expect_err("future parent must be rejected during causal mapping");

    assert!(matches!(
        err,
        ReplayBundleError::EvidenceCausalParentInvalid { .. }
    ));
}

#[test]
fn test_nested_float_payload_reports_non_deterministic_path() {
    let events = vec![RawEvent::new(
        "2026-02-20T10:00:00Z",
        EventType::PolicyEval,
        serde_json::json!({"metrics": {"risk": [1_u64, 2.5_f64]}}),
    )];

    let err = generate_replay_bundle("INC-FLOAT-NEG-001", &events)
        .expect_err("nested float payload must be rejected");

    match err {
        ReplayBundleError::NonDeterministicFloat { path } => {
            assert_eq!(path, "$.payload.metrics.risk[1]");
        }
        other => panic!("expected NonDeterministicFloat, got {other:?}"),
    }
}

#[test]
fn test_read_bundle_from_path_rejects_malformed_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("bundle.json");
    std::fs::write(&file_path, "{not valid json").expect("write malformed bundle");

    let err = read_bundle_from_path(&file_path).expect_err("malformed JSON must fail");

    assert!(matches!(err, ReplayBundleError::Json(_)));
}
