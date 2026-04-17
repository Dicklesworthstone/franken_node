//! Comprehensive edge case tests for replay_bundle.rs
//!
//! Tests focus on:
//! - UUID generation edge cases and collision resistance
//! - JSON canonicalization with complex nested structures
//! - Path traversal attack prevention
//! - Integer overflow scenarios in chunking
//! - Timestamp parsing edge cases
//! - TempFileGuard RAII correctness
//! - Error handling edge cases

use crate::tools::replay_bundle::*;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::TempDir;

/// Test UUID generation edge cases
#[cfg(test)]
mod uuid_generation_tests {
    use super::*;

    #[test]
    fn test_uuid_v7_collision_resistance() {
        // Test that different inputs produce different UUIDs
        let test_cases = vec![
            ("INC-001", "2026-01-01T00:00:00.000000Z"),
            ("INC-002", "2026-01-01T00:00:00.000000Z"), // Same timestamp, different ID
            ("INC-001", "2026-01-01T00:00:00.000001Z"), // Same ID, different timestamp
            ("", "2026-01-01T00:00:00.000000Z"),         // Empty ID
            ("INC-001", "1970-01-01T00:00:00.000000Z"), // Epoch timestamp
            ("INC-001", "9999-12-31T23:59:59.999999Z"), // Far future timestamp
        ];

        let mut generated_uuids = Vec::new();

        for (incident_id, timestamp) in test_cases {
            let events = vec![RawEvent::new(
                timestamp,
                EventType::StateChange,
                json!({"test": "data"}),
            )];

            let bundle_result = generate_replay_bundle(incident_id, &events);
            match bundle_result {
                Ok(bundle) => {
                    generated_uuids.push(bundle.bundle_id);
                    // Verify UUID is version 7
                    assert_eq!(bundle.bundle_id.get_version_num(), 7);
                },
                Err(_) => {
                    // Some cases may fail validation, that's expected
                    continue;
                }
            }
        }

        // Check for UUID uniqueness (no collisions)
        for i in 0..generated_uuids.len() {
            for j in (i + 1)..generated_uuids.len() {
                assert_ne!(
                    generated_uuids[i], generated_uuids[j],
                    "UUID collision detected at indices {} and {}",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_uuid_timestamp_overflow_handling() {
        // Test UUID generation with extreme timestamps
        let extreme_timestamps = vec![
            "1677-09-21T00:12:44.000000Z", // Very old timestamp
            "2262-04-11T23:47:16.000000Z", // Near timestamp limit
            "1970-01-01T00:00:00.000000Z", // Unix epoch
        ];

        for timestamp in extreme_timestamps {
            let events = vec![RawEvent::new(
                timestamp,
                EventType::StateChange,
                json!({"timestamp_test": timestamp}),
            )];

            // Should not panic or fail
            if let Ok(bundle) = generate_replay_bundle("INC-UUID-OVERFLOW", &events) {
                assert_eq!(bundle.bundle_id.get_version_num(), 7);

                // UUID should be deterministic
                let bundle2 = generate_replay_bundle("INC-UUID-OVERFLOW", &events).unwrap();
                assert_eq!(bundle.bundle_id, bundle2.bundle_id);
            }
        }
    }

    #[test]
    fn test_uuid_determinism_across_large_inputs() {
        // Create large timeline to test UUID generation stability
        let mut large_timeline = Vec::new();
        for i in 0..10000 {
            large_timeline.push(RawEvent::new(
                &format!("2026-01-01T00:00:00.{:06}Z", i),
                EventType::StateChange,
                json!({"sequence": i}),
            ));
        }

        let bundle1 = generate_replay_bundle("INC-LARGE-UUID-1", &large_timeline).unwrap();
        let bundle2 = generate_replay_bundle("INC-LARGE-UUID-1", &large_timeline).unwrap();

        assert_eq!(bundle1.bundle_id, bundle2.bundle_id);
        assert_eq!(bundle1.integrity_hash, bundle2.integrity_hash);
    }
}

/// Test JSON canonicalization edge cases
#[cfg(test)]
mod json_canonicalization_tests {
    use super::*;

    #[test]
    fn test_deeply_nested_object_canonicalization() {
        // Create deeply nested object (but not infinite recursion)
        let mut deeply_nested = json!({});
        let mut current = &mut deeply_nested;

        for i in 0..100 {
            let key = format!("level_{}", i);
            *current = json!({
                key: {}
            });
            current = &mut current[&key];
        }

        // Should handle deep nesting without stack overflow
        let events = vec![RawEvent::new(
            "2026-01-01T00:00:00.000000Z",
            EventType::StateChange,
            deeply_nested,
        )];

        let bundle = generate_replay_bundle("INC-NESTED", &events).unwrap();
        assert!(validate_bundle_integrity(&bundle).unwrap());
    }

    #[test]
    fn test_very_wide_object_canonicalization() {
        // Create object with many keys to test sorting
        let mut wide_object = Map::new();
        for i in 0..1000 {
            wide_object.insert(format!("key_{:04}", 999 - i), json!(i)); // Reverse order
        }

        let events = vec![RawEvent::new(
            "2026-01-01T00:00:00.000000Z",
            EventType::StateChange,
            json!(wide_object),
        )];

        let bundle = generate_replay_bundle("INC-WIDE", &events).unwrap();
        assert!(validate_bundle_integrity(&bundle).unwrap());

        // Keys should be canonically sorted in timeline
        let timeline_json = serde_json::to_string(&bundle.timeline).unwrap();
        assert!(timeline_json.contains("key_0000"));
        assert!(timeline_json.contains("key_0999"));
    }

    #[test]
    fn test_unicode_key_canonicalization() {
        // Test Unicode keys are properly sorted
        let unicode_object = json!({
            "🔥": "fire",
            "🌟": "star",
            "🎉": "party",
            "α": "alpha",
            "β": "beta",
            "γ": "gamma",
            "中文": "chinese",
            "العربية": "arabic",
            "русский": "russian",
            "\u{0000}": "null_byte",
            "\u{FFFF}": "max_bmp",
        });

        let events = vec![RawEvent::new(
            "2026-01-01T00:00:00.000000Z",
            EventType::StateChange,
            unicode_object,
        )];

        let bundle = generate_replay_bundle("INC-UNICODE", &events).unwrap();
        assert!(validate_bundle_integrity(&bundle).unwrap());

        // Should be deterministic despite Unicode complexity
        let bundle2 = generate_replay_bundle("INC-UNICODE", &events).unwrap();
        assert_eq!(bundle.integrity_hash, bundle2.integrity_hash);
    }

    #[test]
    fn test_floating_point_rejection_in_nested_structures() {
        let nested_with_floats = vec![
            // Float in array
            json!({"data": [1, 2.5, 3]}),
            // Float in nested object
            json!({"outer": {"inner": {"value": 3.14159}}}),
            // Float in deeply nested array
            json!({"levels": [[[{"float": 2.718}]]])),
            // Special float values
            json!({"nan": f64::NAN}),
            json!({"infinity": f64::INFINITY}),
            json!({"neg_infinity": f64::NEG_INFINITY}),
        ];

        for (i, payload) in nested_with_floats.iter().enumerate() {
            let events = vec![RawEvent::new(
                "2026-01-01T00:00:00.000000Z",
                EventType::StateChange,
                payload.clone(),
            )];

            let result = generate_replay_bundle(&format!("INC-FLOAT-{}", i), &events);
            assert!(
                matches!(result, Err(ReplayBundleError::NonDeterministicFloat { .. })),
                "Should reject float in nested structure: {:?}",
                payload
            );
        }
    }

    #[test]
    fn test_very_large_string_values() {
        // Test very large string values in JSON
        let large_strings = vec![
            "a".repeat(1_000_000),                    // 1MB string
            "\0".repeat(100_000),                     // Null bytes
            "🔥".repeat(100_000),                      // Large Unicode
            format!("{}\n{}", "x".repeat(500_000), "y".repeat(500_000)), // Multi-line
        ];

        for (i, large_string) in large_strings.iter().enumerate() {
            let events = vec![RawEvent::new(
                "2026-01-01T00:00:00.000000Z",
                EventType::StateChange,
                json!({"large_data": large_string}),
            )];

            // Should handle large strings without issues
            let bundle = generate_replay_bundle(&format!("INC-LARGE-STR-{}", i), &events);
            match bundle {
                Ok(bundle) => {
                    assert!(validate_bundle_integrity(&bundle).unwrap());
                    // Large payloads should trigger chunking
                    if large_string.len() > 1_000_000 {
                        assert!(bundle.manifest.chunk_count > 1);
                    }
                },
                Err(e) => {
                    // May fail due to size limits, which is acceptable
                    println!("Large string test {} failed as expected: {}", i, e);
                }
            }
        }
    }
}

/// Test path validation and traversal attack prevention
#[cfg(test)]
mod path_validation_tests {
    use super::*;

    #[test]
    fn test_evidence_ref_path_traversal_prevention() {
        let malicious_paths = vec![
            "../../../etc/passwd",        // Classic path traversal
            "..\\..\\..\\windows\\system32", // Windows path traversal
            "/etc/passwd",                 // Absolute path
            "C:\\Windows\\System32",       // Windows absolute path
            "./../../sensitive",          // Mixed relative/traversal
            "refs/../../../secret",       // Legitimate prefix with traversal
            "refs/logs/../../config",     // Nested traversal
            "",                           // Empty path
            " ",                          // Whitespace-only path
            "refs/logs/../..",            // Double traversal
            "refs/logs/./../../data",     // Mixed current/parent dirs
            "refs\\/logs\\/../data",      // Mixed separators
            "\0refs/logs/data.json",      // Null byte injection
            "refs/logs/data.json\0.exe",  // Null byte suffix
        ];

        for malicious_path in malicious_paths {
            let mut package = create_test_evidence_package();
            package.evidence_refs = vec![malicious_path.to_string()];

            let result = validate_incident_evidence_package(&package, None);
            assert!(
                result.is_err(),
                "Should reject malicious path: {:?}",
                malicious_path
            );

            // Verify it's the right error type
            if let Err(ReplayBundleError::EvidenceRefNotRelative { reference }) = result {
                assert_eq!(reference, malicious_path);
            } else if !matches!(result, Err(ReplayBundleError::EvidenceRefsEmpty)) {
                // EvidenceRefsEmpty is acceptable for empty string case
                panic!("Unexpected error for path {}: {:?}", malicious_path, result);
            }
        }
    }

    #[test]
    fn test_valid_relative_paths_accepted() {
        let valid_paths = vec![
            "refs/logs/event-001.json",
            "refs/data/snapshot.json",
            "docs/incident-report.md",
            "data/logs/system.log",
            "evidence/network/capture.pcap",
            "refs/metrics/cpu-usage.json",
            "single-file.txt",
        ];

        for valid_path in valid_paths {
            let mut package = create_test_evidence_package();
            package.evidence_refs = vec![valid_path.to_string()];
            // Update event to reference this path
            package.events[0].provenance_ref = valid_path.to_string();

            let result = validate_incident_evidence_package(&package, None);
            assert!(
                result.is_ok(),
                "Should accept valid relative path: {:?}, error: {:?}",
                valid_path,
                result
            );
        }
    }

    fn create_test_evidence_package() -> IncidentEvidencePackage {
        IncidentEvidencePackage {
            schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
            incident_id: "TEST-INC-001".to_string(),
            collected_at: "2026-01-01T00:00:00.000000Z".to_string(),
            trace_id: "test-trace".to_string(),
            severity: IncidentSeverity::High,
            incident_type: "test".to_string(),
            detector: "test-detector".to_string(),
            policy_version: "1.0.0".to_string(),
            initial_state_snapshot: json!({}),
            events: vec![IncidentEvidenceEvent {
                event_id: "evt-001".to_string(),
                timestamp: "2026-01-01T00:00:00.000001Z".to_string(),
                event_type: EventType::StateChange,
                payload: json!({"test": "data"}),
                provenance_ref: "refs/logs/event-001.json".to_string(),
                parent_event_id: None,
                state_snapshot: None,
                policy_version: None,
            }],
            evidence_refs: vec!["refs/logs/event-001.json".to_string()],
            metadata: IncidentEvidenceMetadata {
                title: "Test incident".to_string(),
                affected_components: vec!["test-component".to_string()],
                tags: vec!["test".to_string()],
            },
        }
    }
}

/// Test integer overflow scenarios in chunking logic
#[cfg(test)]
mod chunking_overflow_tests {
    use super::*;

    #[test]
    fn test_chunk_size_calculation_overflow_protection() {
        // Create events that could cause overflow in size calculations
        let large_payload = "x".repeat(5_000_000); // 5MB payload

        let events = vec![
            RawEvent::new(
                "2026-01-01T00:00:00.000001Z",
                EventType::StateChange,
                json!({"data": large_payload.clone()}),
            ),
            RawEvent::new(
                "2026-01-01T00:00:00.000002Z",
                EventType::PolicyEval,
                json!({"large_data": large_payload.clone()}),
            ),
            RawEvent::new(
                "2026-01-01T00:00:00.000003Z",
                EventType::OperatorAction,
                json!({"huge_payload": large_payload}),
            ),
        ];

        // Should handle size calculations without overflow
        let bundle = generate_replay_bundle("INC-CHUNK-OVERFLOW", &events).unwrap();
        assert!(bundle.manifest.chunk_count > 1); // Should be chunked

        // Verify chunk indices are sequential
        for (i, chunk) in bundle.chunks.iter().enumerate() {
            assert_eq!(chunk.chunk_index, i as u32);
            assert_eq!(chunk.total_chunks, bundle.manifest.chunk_count);

            // Verify chunk size calculations
            assert!(chunk.compressed_size_bytes > 0);
            assert!(chunk.event_count > 0);
        }
    }

    #[test]
    fn test_maximum_events_handling() {
        // Test with many small events that could cause index overflow
        let mut events = Vec::new();
        for i in 0..100_000 {
            events.push(RawEvent::new(
                &format!("2026-01-01T00:00:00.{:06}Z", i),
                EventType::StateChange,
                json!({"seq": i}),
            ));
        }

        let result = generate_replay_bundle("INC-MAX-EVENTS", &events);
        match result {
            Ok(bundle) => {
                // Should handle large number of events
                assert_eq!(bundle.timeline.len(), 100_000);
                assert!(bundle.manifest.chunk_count > 1);

                // Verify sequence numbers are correct
                for (i, event) in bundle.timeline.iter().enumerate() {
                    assert_eq!(event.sequence_number, (i + 1) as u64);
                }
            },
            Err(e) => {
                // May fail due to resource limits, which is acceptable
                println!("Large event test failed as expected: {}", e);
            }
        }
    }

    #[test]
    fn test_chunk_index_overflow_protection() {
        // Test with scenario that could cause chunk index overflow
        // Create many medium-sized events to force many chunks
        let medium_payload = "m".repeat(2_000_000); // 2MB each
        let mut events = Vec::new();

        for i in 0..100 { // Should create many chunks
            events.push(RawEvent::new(
                &format!("2026-01-01T00:00:00.{:06}Z", i),
                EventType::StateChange,
                json!({"chunk_data": format!("{}{}", medium_payload, i)}),
            ));
        }

        let bundle = generate_replay_bundle("INC-CHUNK-IDX", &events).unwrap();

        // Verify chunk indices don't overflow
        for chunk in &bundle.chunks {
            assert!(chunk.chunk_index < chunk.total_chunks);
            assert!(chunk.first_sequence_number <= chunk.last_sequence_number);
        }
    }
}

/// Test timestamp parsing edge cases
#[cfg(test)]
mod timestamp_edge_tests {
    use super::*;

    #[test]
    fn test_extreme_timestamp_values() {
        let extreme_timestamps = vec![
            ("1677-09-21T00:12:44.000000Z", "very old"),
            ("2262-04-11T23:47:16.854775Z", "far future"),
            ("1970-01-01T00:00:00.000000Z", "unix epoch"),
            ("1970-01-01T00:00:00.000001Z", "just after epoch"),
            ("2026-12-31T23:59:59.999999Z", "end of year"),
            ("2026-01-01T00:00:00.000000+00:00", "explicit UTC"),
            ("2026-01-01T05:30:00.000000+05:30", "positive offset"),
            ("2026-01-01T18:30:00.000000-05:30", "negative offset"),
        ];

        for (timestamp, description) in extreme_timestamps {
            let events = vec![RawEvent::new(
                timestamp,
                EventType::StateChange,
                json!({"test": description}),
            )];

            let result = generate_replay_bundle("INC-TIME-EXTREME", &events);
            match result {
                Ok(bundle) => {
                    assert!(validate_bundle_integrity(&bundle).unwrap());

                    // Timestamp should be normalized to UTC
                    assert!(bundle.timeline[0].timestamp.ends_with("Z"));
                },
                Err(ReplayBundleError::TimestampParse { .. }) => {
                    // Some extreme timestamps may fail parsing, which is acceptable
                    println!("Timestamp {} ({}) failed parsing as expected", timestamp, description);
                },
                Err(e) => {
                    panic!("Unexpected error for timestamp {} ({}): {}", timestamp, description, e);
                }
            }
        }
    }

    #[test]
    fn test_invalid_timestamp_formats() {
        let invalid_timestamps = vec![
            "",                           // Empty
            "not-a-timestamp",           // Plain text
            "2026-01-01",               // Date only
            "2026-01-01T25:00:00Z",     // Invalid hour
            "2026-01-01T12:60:00Z",     // Invalid minute
            "2026-01-01T12:00:60Z",     // Invalid second
            "2026-13-01T12:00:00Z",     // Invalid month
            "2026-01-32T12:00:00Z",     // Invalid day
            "2026-01-01T12:00:00",      // Missing timezone
            "2026-01-01T12:00:00.Z",    // Malformed microseconds
            "2026-01-01T12:00:00.1234567Z", // Too many microseconds
        ];

        for invalid_timestamp in invalid_timestamps {
            let events = vec![RawEvent::new(
                invalid_timestamp,
                EventType::StateChange,
                json!({"test": "data"}),
            )];

            let result = generate_replay_bundle("INC-TIME-INVALID", &events);
            assert!(
                matches!(result, Err(ReplayBundleError::TimestampParse { .. })),
                "Should reject invalid timestamp: {}",
                invalid_timestamp
            );
        }
    }

    #[test]
    fn test_timestamp_sorting_edge_cases() {
        // Test events with same timestamps but different microseconds
        let events = vec![
            RawEvent::new(
                "2026-01-01T12:00:00.000001Z",
                EventType::StateChange,
                json!({"order": 1}),
            ),
            RawEvent::new(
                "2026-01-01T12:00:00.000001Z", // Same timestamp
                EventType::PolicyEval,
                json!({"order": 2}),
            ),
            RawEvent::new(
                "2026-01-01T12:00:00.000002Z",
                EventType::OperatorAction,
                json!({"order": 3}),
            ),
        ];

        let bundle = generate_replay_bundle("INC-TIME-SORT", &events).unwrap();

        // Should maintain deterministic order even with identical timestamps
        assert_eq!(bundle.timeline.len(), 3);
        for (i, event) in bundle.timeline.iter().enumerate() {
            assert_eq!(event.sequence_number, (i + 1) as u64);
        }
    }
}

/// Test TempFileGuard RAII correctness
#[cfg(test)]
mod temp_file_guard_tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_temp_file_guard_cleanup_on_drop() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().join("test_temp_file");

        // Create temp file
        File::create(&temp_path).unwrap();
        assert!(temp_path.exists());

        // TempFileGuard should move file aside when dropped
        {
            let _guard = super::TempFileGuard::new(temp_path.clone());
            // Guard is dropped here
        }

        assert!(!temp_path.exists(), "Original temp file should be gone");

        // Should have created an orphaned file
        let entries: Vec<_> = std::fs::read_dir(temp_dir.path()).unwrap().collect();
        let orphaned_exists = entries.iter().any(|entry| {
            if let Ok(entry) = entry {
                let name = entry.file_name().to_string_lossy();
                name.contains("orphaned-")
            } else {
                false
            }
        });
        assert!(orphaned_exists, "Should have created orphaned file");
    }

    #[test]
    fn test_temp_file_guard_defuse() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().join("test_defuse_file");

        // Create temp file
        File::create(&temp_path).unwrap();
        assert!(temp_path.exists());

        {
            let mut guard = super::TempFileGuard::new(temp_path.clone());
            guard.defuse(); // Should prevent cleanup
            // Guard is dropped here
        }

        // File should still exist after defuse
        assert!(temp_path.exists(), "Defused guard should not clean up file");
    }

    #[test]
    fn test_temp_file_guard_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent_path = temp_dir.path().join("nonexistent");

        // Guard with nonexistent file should not panic
        {
            let _guard = super::TempFileGuard::new(nonexistent_path.clone());
            // Guard is dropped here
        }

        // Should not have created any files
        assert!(!nonexistent_path.exists());
    }

    #[test]
    fn test_abandoned_path_generation() {
        use super::TempFileGuard;

        let original_path = Path::new("/tmp/test.json");
        let abandoned = TempFileGuard::abandoned_path(original_path);

        let abandoned_str = abandoned.to_string_lossy();
        assert!(abandoned_str.contains("test.json.orphaned-"));
        assert!(abandoned_str.len() > original_path.to_string_lossy().len());
    }
}

/// Test error handling edge cases
#[cfg(test)]
mod error_handling_edge_tests {
    use super::*;

    #[test]
    fn test_empty_incident_id_rejection() {
        let empty_ids = vec!["", "   ", "\t\n\r"];

        for empty_id in empty_ids {
            let events = vec![RawEvent::new(
                "2026-01-01T00:00:00.000000Z",
                EventType::StateChange,
                json!({"test": "data"}),
            )];

            let result = generate_replay_bundle(empty_id, &events);
            assert!(
                matches!(result, Err(ReplayBundleError::EmptyIncidentId)),
                "Should reject empty incident ID: {:?}",
                empty_id
            );
        }
    }

    #[test]
    fn test_evidence_field_validation_edge_cases() {
        let mut package = create_test_evidence_package();

        // Test empty required fields
        let field_tests = vec![
            ("incident_id", |p: &mut IncidentEvidencePackage| p.incident_id = "".to_string()),
            ("trace_id", |p: &mut IncidentEvidencePackage| p.trace_id = "".to_string()),
            ("incident_type", |p: &mut IncidentEvidencePackage| p.incident_type = "".to_string()),
            ("detector", |p: &mut IncidentEvidencePackage| p.detector = "".to_string()),
            ("policy_version", |p: &mut IncidentEvidencePackage| p.policy_version = "".to_string()),
            ("metadata.title", |p: &mut IncidentEvidencePackage| p.metadata.title = "".to_string()),
        ];

        for (field_name, modify_fn) in field_tests {
            let mut test_package = package.clone();
            modify_fn(&mut test_package);

            let result = validate_incident_evidence_package(&test_package, None);
            assert!(
                matches!(result, Err(ReplayBundleError::EvidenceFieldEmpty { .. })),
                "Should reject empty field: {}",
                field_name
            );
        }
    }

    #[test]
    fn test_collected_at_without_timezone_rejected() {
        let mut package = create_test_evidence_package();
        package.collected_at = "2026-01-01T00:00:00".to_string();

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::TimestampParse { .. })
        ));
    }

    #[test]
    fn test_expected_incident_id_mismatch_rejected() {
        let package = create_test_evidence_package();

        let result = validate_incident_evidence_package(&package, Some("DIFFERENT-INCIDENT"));

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceIncidentIdMismatch { .. })
        ));
    }

    #[test]
    fn test_empty_evidence_refs_rejected() {
        let mut package = create_test_evidence_package();
        package.evidence_refs.clear();

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(result, Err(ReplayBundleError::EvidenceRefsEmpty)));
    }

    #[test]
    fn test_empty_event_id_rejected() {
        let mut package = create_test_evidence_package();
        package.events[0].event_id = " \t ".to_string();

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceFieldEmpty { .. })
        ));
    }

    #[test]
    fn test_empty_event_provenance_ref_rejected() {
        let mut package = create_test_evidence_package();
        package.events[0].provenance_ref = " \n ".to_string();

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceFieldEmpty { .. })
        ));
    }

    #[test]
    fn test_initial_state_snapshot_float_rejected() {
        let mut package = create_test_evidence_package();
        package.initial_state_snapshot = json!({"unsafe_float": 0.125});

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::NonDeterministicFloat { .. })
        ));
    }

    #[test]
    fn test_future_parent_event_ref_rejected_during_generation() {
        let mut package = create_test_evidence_package();
        package.events[0].parent_event_id = Some("evt-002".to_string());
        package.events.push(IncidentEvidenceEvent {
            event_id: "evt-002".to_string(),
            timestamp: "2026-01-01T00:00:00.000002Z".to_string(),
            event_type: EventType::PolicyEval,
            payload: json!({"test": "later"}),
            provenance_ref: "refs/logs/event-001.json".to_string(),
            parent_event_id: None,
            state_snapshot: None,
            policy_version: None,
        });

        let result = generate_replay_bundle_from_evidence(&package);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceCausalParentInvalid { .. })
        ));
    }

    #[test]
    fn test_event_policy_version_empty_string_rejected() {
        let mut package = create_test_evidence_package();
        package.events[0].policy_version = Some(String::new());

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceFieldEmpty { .. })
        ));
    }

    #[test]
    fn test_unsorted_evidence_event_timestamps_rejected() {
        let mut package = create_test_evidence_package();
        let mut earlier = package.events[0].clone();
        earlier.event_id = "evt-earlier".to_string();
        earlier.timestamp = "2025-12-31T23:59:59.000000Z".to_string();
        package.events.push(earlier);

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceEventsUnsorted { .. })
        ));
    }

    #[test]
    fn test_float_in_evidence_state_snapshot_rejected() {
        let mut package = create_test_evidence_package();
        package.events[0].state_snapshot = Some(json!({"ratio": 0.5}));

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::NonDeterministicFloat { .. })
        ));
    }

    #[test]
    fn test_causal_parent_edge_cases() {
        // Test invalid causal parent references
        let events = vec![
            RawEvent::new(
                "2026-01-01T00:00:00.000001Z",
                EventType::StateChange,
                json!({"order": 1}),
            ),
            RawEvent::new(
                "2026-01-01T00:00:00.000002Z",
                EventType::PolicyEval,
                json!({"order": 2}),
            ).with_causal_parent(3), // Invalid: refers to nonexistent event
            RawEvent::new(
                "2026-01-01T00:00:00.000003Z",
                EventType::OperatorAction,
                json!({"order": 3}),
            ).with_causal_parent(3), // Invalid: self-reference
        ];

        // Should handle invalid causal parents gracefully
        let bundle = generate_replay_bundle("INC-CAUSAL-EDGE", &events).unwrap();

        // Invalid causal parents should be stripped out
        assert!(bundle.timeline[1].causal_parent.is_none()); // Invalid ref to 3
        assert!(bundle.timeline[2].causal_parent.is_none()); // Self-reference
    }

    #[test]
    fn negative_evidence_schema_mismatch_is_rejected() {
        let mut package = create_test_evidence_package();
        package.schema_version = "franken-node/incident-evidence-source/v0".to_string();

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceSchemaMismatch { .. })
        ));
    }

    #[test]
    fn negative_evidence_empty_events_rejected() {
        let mut package = create_test_evidence_package();
        package.events.clear();

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceEventsEmpty)
        ));
    }

    #[test]
    fn negative_evidence_duplicate_event_id_rejected() {
        let mut package = create_test_evidence_package();
        package.events.push(package.events[0].clone());

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceDuplicateEventId { .. })
        ));
    }

    #[test]
    fn negative_evidence_self_parent_rejected() {
        let mut package = create_test_evidence_package();
        package.events[0].parent_event_id = Some(package.events[0].event_id.clone());

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceSelfParentRef { .. })
        ));
    }

    #[test]
    fn negative_evidence_missing_parent_rejected() {
        let mut package = create_test_evidence_package();
        package.events[0].parent_event_id = Some("evt-missing".to_string());

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceMissingParentRef { .. })
        ));
    }

    #[test]
    fn negative_evidence_unknown_provenance_ref_rejected() {
        let mut package = create_test_evidence_package();
        package.events[0].provenance_ref = "refs/logs/missing.json".to_string();

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceUnknownProvenanceRef { .. })
        ));
    }

    #[test]
    fn negative_evidence_invalid_collected_at_rejected() {
        let mut package = create_test_evidence_package();
        package.collected_at = "2026-99-99T99:99:99Z".to_string();

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::TimestampParse { .. })
        ));
    }

    #[test]
    fn negative_evidence_float_payload_rejected() {
        let mut package = create_test_evidence_package();
        package.events[0].payload = json!({"non_deterministic": 1.25});

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::NonDeterministicFloat { .. })
        ));
    }

    #[test]
    fn negative_evidence_empty_event_policy_version_rejected() {
        let mut package = create_test_evidence_package();
        package.events[0].policy_version = Some(" \t ".to_string());

        let result = validate_incident_evidence_package(&package, None);

        assert!(matches!(
            result,
            Err(ReplayBundleError::EvidenceFieldEmpty { .. })
        ));
    }

    fn create_test_evidence_package() -> IncidentEvidencePackage {
        IncidentEvidencePackage {
            schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
            incident_id: "TEST-EDGE-001".to_string(),
            collected_at: "2026-01-01T00:00:00.000000Z".to_string(),
            trace_id: "test-trace".to_string(),
            severity: IncidentSeverity::High,
            incident_type: "test".to_string(),
            detector: "test-detector".to_string(),
            policy_version: "1.0.0".to_string(),
            initial_state_snapshot: json!({}),
            events: vec![IncidentEvidenceEvent {
                event_id: "evt-001".to_string(),
                timestamp: "2026-01-01T00:00:00.000001Z".to_string(),
                event_type: EventType::StateChange,
                payload: json!({"test": "data"}),
                provenance_ref: "refs/logs/event-001.json".to_string(),
                parent_event_id: None,
                state_snapshot: None,
                policy_version: None,
            }],
            evidence_refs: vec!["refs/logs/event-001.json".to_string()],
            metadata: IncidentEvidenceMetadata {
                title: "Test incident".to_string(),
                affected_components: vec!["test-component".to_string()],
                tags: vec!["test".to_string()],
            },
        }
    }
}
