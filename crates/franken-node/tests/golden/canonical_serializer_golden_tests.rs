//! Golden artifact tests for canonical serializer outputs
//!
//! Tests the deterministic outputs of canonical serialization including:
//! - Trust object canonical byte representation
//! - Schema-driven field ordering determinism
//! - Cross-version serialization stability

use std::collections::BTreeMap;
use frankenengine_node::connector::canonical_serializer::{
    CanonicalSerializer, TrustObjectType, SerializerEvent
};
use serde_json::{json, Value};

// Golden utilities from parent module
use super::{assert_golden, assert_scrubbed_golden};

/// Create deterministic test objects for each trust object type
fn create_test_objects() -> BTreeMap<TrustObjectType, Value> {
    let mut objects = BTreeMap::new();

    // Trust card test object
    objects.insert(
        TrustObjectType::TrustCard,
        json!({
            "extension_id": "npm:@test/golden-extension",
            "version": "1.0.0",
            "publisher_id": "test-publisher",
            "certification_level": "Gold",
            "reputation_trend": "Rising",
            "risk_level": "Low",
            "audit_records": [
                {
                    "audit_id": "AUD-001",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "status": "Passed"
                }
            ],
            "capabilities": [
                {
                    "name": "filesystem.read",
                    "risk": "Medium"
                },
                {
                    "name": "network.http",
                    "risk": "Low"
                }
            ]
        })
    );

    // Remote capability test object
    objects.insert(
        TrustObjectType::RemoteCap,
        json!({
            "scope": "network",
            "operation": "http_request",
            "endpoint": "api.example.com",
            "timestamp": "2026-01-01T00:00:00Z",
            "authorization": {
                "token": "test-auth-token",
                "expires": "2026-01-02T00:00:00Z"
            }
        })
    );

    // Evidence entry test object
    objects.insert(
        TrustObjectType::EvidenceEntry,
        json!({
            "schema_version": "1.0",
            "decision_id": "DEC-001",
            "decision_kind": "Policy",
            "decision_time": "2026-01-01T00:00:00Z",
            "timestamp_ms": 1000000000000_u64,
            "trace_id": "trace-001",
            "epoch_id": 1_u64,
            "payload": {
                "action": "trust_evaluation",
                "result": "approved",
                "confidence": 0.95
            },
            "signature": ""
        })
    );

    objects
}

#[test]
fn canonical_serializer_trust_card_deterministic_output() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let test_objects = create_test_objects();

    if let Some(trust_card_obj) = test_objects.get(&TrustObjectType::TrustCard) {
        let serialized = serializer
            .serialize_value(TrustObjectType::TrustCard, trust_card_obj, "test-trace-001")
            .expect("Trust card serialization should succeed");

        // Convert to hex for readable golden comparison
        let hex_output = hex::encode(&serialized);
        assert_golden("canonical_serializer/trust_card_deterministic", &hex_output);
    } else {
        panic!("Trust card test object not found");
    }
}

#[test]
fn canonical_serializer_remote_cap_deterministic_output() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let test_objects = create_test_objects();

    if let Some(remote_cap_obj) = test_objects.get(&TrustObjectType::RemoteCap) {
        let serialized = serializer
            .serialize_value(TrustObjectType::RemoteCap, remote_cap_obj, "test-trace-002")
            .expect("Remote capability serialization should succeed");

        // Convert to hex for readable golden comparison
        let hex_output = hex::encode(&serialized);
        assert_golden("canonical_serializer/remote_cap_deterministic", &hex_output);
    } else {
        panic!("Remote capability test object not found");
    }
}

#[test]
fn canonical_serializer_evidence_entry_deterministic_output() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let test_objects = create_test_objects();

    if let Some(evidence_obj) = test_objects.get(&TrustObjectType::EvidenceEntry) {
        let serialized = serializer
            .serialize_value(TrustObjectType::EvidenceEntry, evidence_obj, "test-trace-003")
            .expect("Evidence entry serialization should succeed");

        // Convert to hex for readable golden comparison
        let hex_output = hex::encode(&serialized);
        assert_golden("canonical_serializer/evidence_entry_deterministic", &hex_output);
    } else {
        panic!("Evidence entry test object not found");
    }
}

#[test]
fn canonical_serializer_cross_object_batch_determinism() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let test_objects = create_test_objects();

    let mut batch_output = String::new();

    // Serialize all object types in deterministic order
    for (object_type, test_obj) in &test_objects {
        let trace_id = format!("batch-trace-{}", object_type.label());
        let serialized = serializer
            .serialize_value(*object_type, test_obj, &trace_id)
            .expect("Batch serialization should succeed");

        let hex_output = hex::encode(&serialized);
        batch_output.push_str(&format!(
            "{}:\n{}\n\n",
            object_type.label(),
            hex_output
        ));
    }

    // Scrub dynamic trace IDs for stable golden
    assert_scrubbed_golden("canonical_serializer/batch_determinism", &batch_output);
}

#[test]
fn canonical_serializer_event_log_format() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let test_objects = create_test_objects();

    // Clear any existing events
    let _initial_events = serializer.events().clone();

    // Serialize multiple objects to generate events
    for (object_type, test_obj) in &test_objects {
        let trace_id = format!("event-trace-{}", object_type.label());
        let _ = serializer
            .serialize_value(*object_type, test_obj, &trace_id)
            .expect("Event generation serialization should succeed");
    }

    // Capture event log for golden comparison
    let events = serializer.events();
    let events_json = serde_json::to_string_pretty(events)
        .expect("Event serialization should succeed");

    // Scrub dynamic values (trace IDs, timestamps)
    assert_scrubbed_golden("canonical_serializer/event_log_format", &events_json);
}