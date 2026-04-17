//! Logic bug regression tests for replay_bundle.rs
//! Focus: validation edge cases, boundary conditions, canonicalization bugs

#[cfg(test)]
mod replay_bundle_logic_tests {
    use super::super::replay_bundle::*;
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};

    // ── push_bounded function correctness tests ──

    #[test]
    fn push_bounded_saturating_arithmetic_protection() {
        use super::super::replay_bundle::push_bounded;

        // Test the correct implementation from replay_bundle.rs
        let mut items = vec![1, 2, 3, 4, 5];
        push_bounded(&mut items, 6, 3);

        // Should remove excess items and add new one
        assert_eq!(items.len(), 3);
        assert_eq!(items, vec![4, 5, 6]);
    }

    #[test]
    fn push_bounded_zero_capacity_edge_case() {
        use super::super::replay_bundle::push_bounded;

        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 0);

        // With zero capacity, should remove all and add new
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], 4);
    }

    #[test]
    fn push_bounded_exact_capacity_boundary() {
        use super::super::replay_bundle::push_bounded;

        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 3);

        // At exact capacity, should replace oldest
        assert_eq!(items.len(), 3);
        assert_eq!(items, vec![2, 3, 4]);
    }

    #[test]
    fn push_bounded_massive_overflow_protection() {
        use super::super::replay_bundle::push_bounded;

        // Test with very large collection
        let mut items: Vec<u32> = (0..10000).collect();
        push_bounded(&mut items, 99999, 5);

        // Should be bounded to exactly 5 items
        assert_eq!(items.len(), 5);
        assert_eq!(items[4], 99999);
        // Should preserve latest items before the new one
        assert!(items.contains(&9999));
        assert!(items.contains(&9998));
    }

    // ── Canonicalization logic edge cases ──

    #[test]
    fn canonicalize_value_float_detection() {
        // Should detect and reject f64 values
        let float_value = json!(3.14159);
        let result = canonicalize_value(&float_value, "test.float");
        assert!(result.is_err(), "Should reject floating-point numbers");

        if let Err(ReplayBundleError::NonDeterministicFloat { path }) = result {
            assert_eq!(path, "test.float");
        } else {
            panic!("Expected NonDeterministicFloat error");
        }
    }

    #[test]
    fn canonicalize_value_nested_float_detection() {
        // Should detect floats deep in nested structures
        let nested_value = json!({
            "outer": {
                "inner": {
                    "array": [1, 2, 3.0, 4]
                }
            }
        });

        let result = canonicalize_value(&nested_value, "root");
        assert!(result.is_err(), "Should detect nested float");
    }

    #[test]
    fn canonicalize_value_preserves_order() {
        // BTreeMap should preserve key order for determinism
        let mut obj = serde_json::Map::new();
        obj.insert("zebra".into(), json!("last"));
        obj.insert("alpha".into(), json!("first"));
        obj.insert("beta".into(), json!("middle"));

        let value = Value::Object(obj);
        let result = canonicalize_value(&value, "test").unwrap();

        if let Value::Object(canonical_obj) = result {
            let keys: Vec<_> = canonical_obj.keys().collect();
            // Should be sorted alphabetically due to BTreeMap
            assert_eq!(keys, vec!["alpha", "beta", "zebra"]);
        } else {
            panic!("Expected canonical object");
        }
    }

    #[test]
    fn canonicalize_value_large_numbers() {
        // Should handle large integers correctly
        let large_int = json!(u64::MAX);
        let result = canonicalize_value(&large_int, "test");
        assert!(result.is_ok(), "Should handle large integers");

        let very_large = json!(i64::MAX);
        let result = canonicalize_value(&very_large, "test");
        assert!(result.is_ok(), "Should handle max i64");
    }

    #[test]
    fn canonicalize_value_null_and_bool() {
        // Should preserve null and boolean values
        let null_val = json!(null);
        assert!(canonicalize_value(&null_val, "test").is_ok());

        let bool_val = json!(true);
        assert!(canonicalize_value(&bool_val, "test").is_ok());

        let false_val = json!(false);
        assert!(canonicalize_value(&false_val, "test").is_ok());
    }

    #[test]
    fn canonicalize_value_empty_structures() {
        // Should handle empty arrays and objects
        let empty_array = json!([]);
        assert!(canonicalize_value(&empty_array, "test").is_ok());

        let empty_object = json!({});
        assert!(canonicalize_value(&empty_object, "test").is_ok());
    }

    #[test]
    fn canonicalize_value_path_tracking() {
        // Path should accurately reflect nesting
        let nested = json!({
            "level1": {
                "level2": {
                    "bad_float": 2.718
                }
            }
        });

        let result = canonicalize_value(&nested, "root");
        assert!(result.is_err());

        if let Err(ReplayBundleError::NonDeterministicFloat { path }) = result {
            assert_eq!(path, "root.level1.level2.bad_float");
        }
    }

    // ── Evidence validation edge cases ──

    fn minimal_evidence() -> IncidentEvidencePackage {
        IncidentEvidencePackage {
            schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
            incident_id: "INC-001".to_string(),
            collected_at: "2026-02-20T10:00:00.000000Z".to_string(),
            trace_id: "trace-001".to_string(),
            severity: IncidentSeverity::Medium,
            incident_type: "test".to_string(),
            detector: "unit-test".to_string(),
            policy_version: "1.0.0".to_string(),
            initial_state_snapshot: json!({"test": true}),
            events: vec![IncidentEvidenceEvent {
                event_id: "evt-001".to_string(),
                timestamp: "2026-02-20T10:00:00.001000Z".to_string(),
                event_type: EventType::StateChange,
                payload: json!({"change": "test"}),
                provenance_ref: "refs/test.json".to_string(),
                parent_event_id: None,
            }],
            evidence_refs: vec!["refs/test.json".to_string()],
            metadata: json!({"test": "metadata"}),
        }
    }

    #[test]
    fn evidence_validation_empty_incident_id() {
        let mut evidence = minimal_evidence();
        evidence.incident_id = "".to_string();

        let result = evidence.validate();
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ReplayBundleError::EvidenceFieldEmpty { field } if field == "incident_id")
        );
    }

    #[test]
    fn evidence_validation_empty_events() {
        let mut evidence = minimal_evidence();
        evidence.events.clear();

        let result = evidence.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplayBundleError::EvidenceEventsEmpty
        ));
    }

    #[test]
    fn evidence_validation_duplicate_event_ids() {
        let mut evidence = minimal_evidence();
        evidence.events.push(IncidentEvidenceEvent {
            event_id: "evt-001".to_string(), // Duplicate ID
            timestamp: "2026-02-20T10:00:00.002000Z".to_string(),
            event_type: EventType::PolicyEval,
            payload: json!({"duplicate": true}),
            provenance_ref: "refs/test2.json".to_string(),
            parent_event_id: None,
        });

        let result = evidence.validate();
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ReplayBundleError::EvidenceDuplicateEventId { event_id } if event_id == "evt-001")
        );
    }

    #[test]
    fn evidence_validation_self_parent_reference() {
        let mut evidence = minimal_evidence();
        evidence.events[0].parent_event_id = Some("evt-001".to_string()); // Self-reference

        let result = evidence.validate();
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ReplayBundleError::EvidenceSelfParentRef { event_id } if event_id == "evt-001")
        );
    }

    #[test]
    fn evidence_validation_missing_parent_reference() {
        let mut evidence = minimal_evidence();
        evidence.events[0].parent_event_id = Some("nonexistent".to_string());

        let result = evidence.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplayBundleError::EvidenceMissingParentRef {
                event_id,
                parent_event_id
            }
            if event_id == "evt-001" && parent_event_id == "nonexistent"
        ));
    }

    #[test]
    fn evidence_validation_unknown_provenance_ref() {
        let mut evidence = minimal_evidence();
        evidence.events[0].provenance_ref = "refs/unknown.json".to_string();

        let result = evidence.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplayBundleError::EvidenceUnknownProvenanceRef {
                event_id,
                provenance_ref
            }
            if event_id == "evt-001" && provenance_ref == "refs/unknown.json"
        ));
    }

    #[test]
    fn evidence_validation_absolute_reference_path() {
        let mut evidence = minimal_evidence();
        evidence.evidence_refs = vec!["/absolute/path.json".to_string()]; // Absolute path

        let result = evidence.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplayBundleError::EvidenceRefNotRelative { reference }
            if reference == "/absolute/path.json"
        ));
    }

    #[test]
    fn evidence_validation_events_sorting() {
        let mut evidence = minimal_evidence();
        evidence.events.push(IncidentEvidenceEvent {
            event_id: "evt-002".to_string(),
            timestamp: "2026-02-20T09:59:00.000000Z".to_string(), // Earlier timestamp
            event_type: EventType::ExternalSignal,
            payload: json!({"earlier": true}),
            provenance_ref: "refs/test.json".to_string(),
            parent_event_id: None,
        });

        let result = evidence.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplayBundleError::EvidenceEventsUnsorted { .. }
        ));
    }

    // ── Boundary condition tests ──

    #[test]
    fn max_chunks_boundary() {
        // Test MAX_CHUNKS_PER_BUNDLE boundary
        assert_eq!(MAX_CHUNKS_PER_BUNDLE, 1000, "Should maintain chunk limit");
    }

    #[test]
    fn max_event_log_boundary() {
        // Test MAX_EVENT_LOG boundary
        assert_eq!(MAX_EVENT_LOG, 50000, "Should maintain event log limit");
    }

    #[test]
    fn max_bundle_bytes_boundary() {
        // Test MAX_BUNDLE_BYTES boundary
        assert_eq!(MAX_BUNDLE_BYTES, 10 * 1024 * 1024, "Should be 10 MiB");
    }

    // ── TempFileGuard RAII edge cases ──

    #[test]
    fn temp_file_guard_defuse_prevents_cleanup() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("test.tmp");
        std::fs::write(&temp_path, "test").unwrap();

        {
            let mut guard = TempFileGuard::new(temp_path.clone());
            guard.defuse(); // Should prevent cleanup
        }

        assert!(temp_path.exists(), "File should still exist after defuse");
    }

    #[test]
    fn temp_file_guard_cleanup_nonexistent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let nonexistent = temp_dir.path().join("nonexistent.tmp");

        {
            let _guard = TempFileGuard::new(nonexistent.clone());
            // Drop guard for nonexistent file - should not crash
        }

        // Test passes if no panic occurred
    }

    // ── Schema validation edge cases ──

    #[test]
    fn evidence_schema_mismatch() {
        let mut evidence = minimal_evidence();
        evidence.schema_version = "wrong/schema/v1".to_string();

        let result = evidence.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReplayBundleError::EvidenceSchemaMismatch { .. }
        ));
    }

    #[test]
    fn timestamp_parsing_edge_cases() {
        let mut evidence = minimal_evidence();

        // Invalid RFC3339 timestamp
        evidence.collected_at = "not-a-timestamp".to_string();
        let result = evidence.validate();
        assert!(result.is_err());

        // Test with various timestamp formats
        evidence.collected_at = "2026-02-20T10:00:00Z".to_string(); // Without microseconds
        assert!(
            evidence.validate().is_ok(),
            "Should accept timestamp without microseconds"
        );

        evidence.collected_at = "2026-02-20T10:00:00.000Z".to_string(); // With milliseconds
        assert!(
            evidence.validate().is_ok(),
            "Should accept timestamp with milliseconds"
        );
    }

    // ── Performance and stress testing ──

    #[test]
    fn large_event_payload_handling() {
        let mut evidence = minimal_evidence();

        // Create large payload near boundary
        let large_string = "x".repeat(1_000_000); // 1MB string
        evidence.events[0].payload = json!({
            "large_field": large_string
        });

        // Should handle large payloads without crashing
        let result = evidence.validate();
        assert!(result.is_ok(), "Should handle large payloads");
    }

    #[test]
    fn many_events_performance() {
        let mut evidence = minimal_evidence();
        evidence.events.clear();

        // Create many events near MAX_EVENT_LOG limit
        for i in 0..1000 {
            evidence.events.push(IncidentEvidenceEvent {
                event_id: format!("evt-{:06}", i),
                timestamp: format!("2026-02-20T10:{:02}:{:02}.000000Z", i / 60, i % 60),
                event_type: EventType::StateChange,
                payload: json!({"sequence": i}),
                provenance_ref: "refs/test.json".to_string(),
                parent_event_id: if i > 0 {
                    Some(format!("evt-{:06}", i - 1))
                } else {
                    None
                },
            });
        }
        evidence.evidence_refs = vec!["refs/test.json".to_string()];

        // Should handle many events efficiently
        let result = evidence.validate();
        assert!(result.is_ok(), "Should handle many events");
    }
}
