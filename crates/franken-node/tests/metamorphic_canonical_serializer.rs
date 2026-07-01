//! Metamorphic Testing for Canonical Serializer
//!
//! Implements metamorphic relations for oracle problem areas in canonical serialization:
//! 1. Field-order invariance (permutation insensitivity)
//! 2. Round-trip serialization consistency
//! 3. Domain-tag signature preimage determinism
//! 4. Schema-driven canonicalization idempotence

use frankenengine_node::connector::canonical_serializer::{
    CanonicalSerializer, TrustObjectType, SignaturePreimage,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

// === ORACLE PROBLEM AREAS ===
//
// 1. **Serialization Output Prediction**: Can't predict exact byte sequence
//    for arbitrary JSON inputs, but can verify relational properties
// 2. **Field Ordering Canonicalization**: Different input orders should
//    produce identical output (oracle: what is "canonical"?)
// 3. **Domain Tag Behavior**: Domain separation should be consistent
//    but can't predict preimage bytes without implementation
// 4. **Round-trip Consistency**: serialize → parse → serialize again
//    should be invariant (oracle: intermediate representation correctness)

// === METAMORPHIC RELATIONS ===

/// MR1: Field-order invariance (Equivalence Pattern)
/// Property: serialize(reorder_fields(obj)) == serialize(obj)
/// Detects: Non-deterministic field ordering, schema violations
mod field_order_invariance_tests {
    use super::*;

    pub(crate) fn reorder_json_fields(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                // Create new object with fields in different (but still deterministic) order
                let mut reordered: BTreeMap<String, Value> = BTreeMap::new();

                // Reverse alphabetical order to create different ordering
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                keys.reverse();

                for key in keys {
                    reordered.insert(key.clone(), reorder_json_fields(&map[key]));
                }

                Value::Object(reordered.into_iter().collect())
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(reorder_json_fields).collect())
            }
            _ => value.clone(),
        }
    }

    #[test]
    fn mr_field_order_invariance_policy_checkpoint() {
        let mut serializer = CanonicalSerializer::with_all_schemas();

        let original_policy = json!({
            "policy_id": "policy-12345",
            "version": 1,
            "issuer": "security-team",
            "rules": ["allow_read", "deny_write"],
            "metadata": {
                "created_at": "2026-04-21T10:00:00Z",
                "expires_at": "2027-04-21T10:00:00Z"
            }
        });

        let reordered_policy = reorder_json_fields(&original_policy);

        // Verify they're structurally different in JSON representation
        let original_str = serde_json::to_string(&original_policy).unwrap();
        let reordered_str = serde_json::to_string(&reordered_policy).unwrap();
        assert_ne!(original_str, reordered_str,
            "Test setup error: reordered JSON should differ in string form");

        // MR assertion: canonical serialization should be identical
        let result1 = serializer.serialize_value(
            TrustObjectType::PolicyCheckpoint,
            &original_policy,
            "mr-field-order-1"
        ).expect("original serialization should succeed");

        let result2 = serializer.serialize_value(
            TrustObjectType::PolicyCheckpoint,
            &reordered_policy,
            "mr-field-order-2"
        ).expect("reordered serialization should succeed");

        assert_eq!(result1, result2,
            "Field-order invariance violated: different JSON field orders produced different canonical serialization.\n\
             Original JSON:   {original_str}\n\
             Reordered JSON:  {reordered_str}\n\
             This indicates the canonicalizer is not properly enforcing field order from schema");
    }

    #[test]
    fn mr_field_order_invariance_delegation_token() {
        let mut serializer = CanonicalSerializer::with_all_schemas();

        let original_token = json!({
            "token_id": "tok-abcdef",
            "principal": "user@example.com",
            "scope": "read:documents",
            "issued_at": 1713700800,
            "expires_at": 1714305600,
            "capabilities": {
                "read": true,
                "write": false,
                "admin": false
            }
        });

        let reordered_token = reorder_json_fields(&original_token);

        let result1 = serializer.serialize_value(
            TrustObjectType::DelegationToken,
            &original_token,
            "mr-delegation-1"
        ).expect("original delegation token should serialize");

        let result2 = serializer.serialize_value(
            TrustObjectType::DelegationToken,
            &reordered_token,
            "mr-delegation-2"
        ).expect("reordered delegation token should serialize");

        assert_eq!(result1, result2,
            "Delegation token field-order invariance violated");
    }

    #[test]
    fn mr_field_order_invariance_all_types() {
        // Test field-order invariance across all trust object types
        let mut serializer = CanonicalSerializer::with_all_schemas();

        let test_cases = vec![
            (TrustObjectType::PolicyCheckpoint, json!({
                "policy_id": "test-policy",
                "version": 1,
                "rules": ["rule1", "rule2"]
            })),
            (TrustObjectType::DelegationToken, json!({
                "token_id": "test-token",
                "principal": "test@example.com",
                "scope": "test:scope"
            })),
            (TrustObjectType::RevocationAssertion, json!({
                "assertion_id": "test-assertion",
                "revoked_object": "obj-12345",
                "reason": "security_breach"
            })),
            (TrustObjectType::SessionTicket, json!({
                "ticket_id": "test-ticket",
                "session": "sess-12345",
                "valid_until": 1714305600
            })),
            (TrustObjectType::ZoneBoundaryClaim, json!({
                "claim_id": "test-claim",
                "source_zone": "zone-a",
                "target_zone": "zone-b"
            })),
            (TrustObjectType::OperatorReceipt, json!({
                "receipt_id": "test-receipt",
                "operation": "deploy",
                "timestamp": 1713700800
            })),
        ];

        for (object_type, original_value) in test_cases {
            let reordered_value = reorder_json_fields(&original_value);

            let result1 = serializer.serialize_value(object_type, &original_value, "mr-all-1")
                .expect("original should serialize");
            let result2 = serializer.serialize_value(object_type, &reordered_value, "mr-all-2")
                .expect("reordered should serialize");

            assert_eq!(result1, result2,
                "Field-order invariance violated for {:?}", object_type);
        }
    }
}

/// MR2: Round-trip serialization consistency (Invertive Pattern)
/// Property: serialize(parse(serialize(x))) == serialize(x)
/// Detects: Lossy serialization, parsing inconsistencies, canonical drift
mod round_trip_consistency_tests {
    use super::*;

    fn test_roundtrip_consistency(object_type: TrustObjectType, value: &Value) {
        let mut serializer = CanonicalSerializer::with_all_schemas();

        // Step 1: First serialization
        let serialized_1 = serializer.serialize_value(object_type, value, "rt-1")
            .expect("initial serialization should succeed");

        // Step 2: Parse back to JSON (simulating deserialization)
        // Note: In real usage, this would be actual deserialization,
        // but for metamorphic testing we verify the canonical property
        let canonical_json_str = String::from_utf8(serialized_1.clone())
            .expect("serialized output should be valid UTF-8");
        let parsed_value: Value = serde_json::from_str(&canonical_json_str)
            .expect("serialized output should parse as JSON");

        // Step 3: Re-serialize the parsed value
        let serialized_2 = serializer.serialize_value(object_type, &parsed_value, "rt-2")
            .expect("re-serialization should succeed");

        // MR assertion: round-trip should be stable
        assert_eq!(serialized_1, serialized_2,
            "Round-trip consistency violated for {:?}:\n\
             Original serialization:   {:?}\n\
             Re-serialization:         {:?}\n\
             This indicates canonical serialization is not stable",
            object_type, String::from_utf8_lossy(&serialized_1),
            String::from_utf8_lossy(&serialized_2));
    }

    #[test]
    fn mr_roundtrip_policy_checkpoint() {
        let policy = json!({
            "policy_id": "rt-policy-test",
            "version": 42,
            "issuer": "test-issuer",
            "rules": ["allow", "deny", "audit"],
            "metadata": {
                "description": "Test policy for roundtrip",
                "tags": ["test", "metamorphic"]
            }
        });

        test_roundtrip_consistency(TrustObjectType::PolicyCheckpoint, &policy);
    }

    #[test]
    fn mr_roundtrip_complex_nested_structure() {
        let complex_token = json!({
            "token_id": "complex-test-token",
            "principal": "complex-user@example.com",
            "scope": "complex:read:write:admin",
            "nested_data": {
                "level1": {
                    "level2": {
                        "level3": {
                            "deep_value": "deep-data",
                            "deep_array": [1, 2, 3, 4, 5],
                            "deep_bool": true
                        }
                    }
                }
            },
            "array_of_objects": [
                {"id": "obj1", "type": "TypeA"},
                {"id": "obj2", "type": "TypeB"},
                {"id": "obj3", "type": "TypeC"}
            ]
        });

        test_roundtrip_consistency(TrustObjectType::DelegationToken, &complex_token);
    }

    #[test]
    fn mr_roundtrip_edge_cases() {
        let edge_cases = vec![
            // Empty object
            json!({"minimal_id": "empty-test"}),

            // Large strings
            json!({
                "id": "large-string-test",
                "large_field": "x".repeat(1000),
                "description": "Testing large string handling"
            }),

            // Many fields
            json!({
                "field_01": "value_01", "field_02": "value_02", "field_03": "value_03",
                "field_04": "value_04", "field_05": "value_05", "field_06": "value_06",
                "field_07": "value_07", "field_08": "value_08", "field_09": "value_09",
                "field_10": "value_10"
            }),

            // Special characters
            json!({
                "id": "special-chars-test",
                "special_field": "Unicode: 🔒🛡️⚠️ Quotes: \"'` Escapes: \\n\\t\\r",
                "json_chars": "{\"nested\": [1,2,3]}"
            })
        ];

        for edge_case in edge_cases.iter() {
            test_roundtrip_consistency(
                TrustObjectType::SessionTicket,
                edge_case
            );
        }
    }
}

/// MR3: Domain-tag signature preimage determinism (Equivalence Pattern)
/// Property: preimage(type_A, data) != preimage(type_B, data) for type_A != type_B
/// Detects: Domain separation failures, tag collision bugs
mod domain_tag_determinism_tests {
    use super::*;

    #[test]
    fn mr_domain_tag_separation() {
        let mut serializer = CanonicalSerializer::with_all_schemas();

        // Same JSON payload for different trust object types
        let shared_payload = json!({
            "shared_id": "test-12345",
            "shared_field": "shared-value",
            "timestamp": 1713700800
        });

        let all_types = TrustObjectType::all();
        let mut serialization_results = Vec::new();

        // Serialize same payload as different object types
        for &object_type in all_types {
            let result = serializer.serialize_value(object_type, &shared_payload, "mr-domain")
                .expect("serialization should succeed for all types");
            serialization_results.push((object_type, result));
        }

        // MR assertion: different trust object types must produce different serializations
        for i in 0..serialization_results.len() {
            for j in (i+1)..serialization_results.len() {
                let (type_a, result_a) = &serialization_results[i];
                let (type_b, result_b) = &serialization_results[j];

                assert_ne!(result_a, result_b,
                    "Domain tag separation failed: {:?} and {:?} produced identical serialization for same payload.\n\
                     This violates INV-CAN-DOMAIN-TAG and creates signature collision risk.",
                    type_a, type_b);
            }
        }
    }

    #[test]
    fn mr_domain_tag_consistency() {
        let mut serializer1 = CanonicalSerializer::with_all_schemas();
        let mut serializer2 = CanonicalSerializer::with_all_schemas();

        let test_payload = json!({
            "consistency_test_id": "domain-consistency-check",
            "data": "test-data-for-consistency"
        });

        // MR assertion: same object type should always produce same domain tag behavior
        for &object_type in TrustObjectType::all() {
            let result1 = serializer1.serialize_value(object_type, &test_payload, "consistency-1")
                .expect("first serializer should work");
            let result2 = serializer2.serialize_value(object_type, &test_payload, "consistency-2")
                .expect("second serializer should work");

            assert_eq!(result1, result2,
                "Domain tag consistency violated: same object type {:?} produced different results across serializer instances",
                object_type);
        }
    }

    #[test]
    fn mr_signature_preimage_determinism() {
        // Test SignaturePreimage construction determinism
        let test_cases = vec![
            (1, [0x10, 0x01], b"test payload 1".to_vec()),
            (2, [0x20, 0x02], b"test payload 2".to_vec()),
            (1, [0x10, 0x02], b"test payload 1".to_vec()), // Same version, different tag
            (2, [0x10, 0x01], b"test payload 2".to_vec()), // Different version, same tag
        ];

        let mut preimage_bytes = Vec::new();

        for (version, domain_tag, payload) in test_cases {
            let preimage = SignaturePreimage::build(version, domain_tag, payload);
            let bytes = preimage.to_bytes();
            preimage_bytes.push((preimage.clone(), bytes));
        }

        // MR assertion: different inputs should produce different preimage bytes
        for i in 0..preimage_bytes.len() {
            for j in (i+1)..preimage_bytes.len() {
                let (preimage_a, bytes_a) = &preimage_bytes[i];
                let (preimage_b, bytes_b) = &preimage_bytes[j];

                assert_ne!(bytes_a, bytes_b,
                    "Signature preimage collision detected:\n\
                     Preimage A: {:?}\n\
                     Preimage B: {:?}\n\
                     Both produced bytes: {:?}",
                    preimage_a, preimage_b, bytes_a);
            }
        }
    }
}

/// MR4: Schema-driven canonicalization idempotence (Inclusive Pattern)
/// Property: canonicalize(canonicalize(x)) == canonicalize(x)
/// Detects: Non-idempotent canonicalization, unstable schema application
mod canonicalization_idempotence_tests {
    use super::*;

    #[test]
    fn mr_serialization_idempotence() {
        let mut serializer = CanonicalSerializer::with_all_schemas();

        let test_object = json!({
            "idempotence_test_id": "test-idempotent-serialization",
            "field_a": "value_a",
            "field_b": {"nested": "value"},
            "field_c": [1, 2, 3, 4, 5]
        });

        // First serialization
        let result1 = serializer.serialize_value(
            TrustObjectType::ZoneBoundaryClaim,
            &test_object,
            "idempotent-1"
        ).expect("first serialization should succeed");

        // Parse the result back to JSON
        let canonical_str = String::from_utf8(result1.clone())
            .expect("serialized output should be UTF-8");
        let canonical_value: Value = serde_json::from_str(&canonical_str)
            .expect("serialized output should parse as JSON");

        // Second serialization of the canonical form
        let result2 = serializer.serialize_value(
            TrustObjectType::ZoneBoundaryClaim,
            &canonical_value,
            "idempotent-2"
        ).expect("second serialization should succeed");

        // MR assertion: serialization should be idempotent
        assert_eq!(result1, result2,
            "Serialization idempotence violated:\n\
             First result:  {:?}\n\
             Second result: {:?}\n\
             Canonicalization should be stable under re-application",
            String::from_utf8_lossy(&result1),
            String::from_utf8_lossy(&result2));
    }

    #[test]
    fn mr_multiple_serialization_passes() {
        let mut serializer = CanonicalSerializer::with_all_schemas();

        let initial_object = json!({
            "multi_pass_test": "multiple-serialization-stability",
            "complex_nested": {
                "array": [
                    {"item": "first", "order": 3},
                    {"item": "second", "order": 1},
                    {"item": "third", "order": 2}
                ],
                "metadata": {
                    "version": 1,
                    "flags": {"enabled": true, "debug": false}
                }
            }
        });

        let mut current_value = initial_object;
        let mut serialization_results = Vec::new();

        // Perform multiple rounds of serialize → parse → serialize
        for round in 0..5 {
            let serialized = serializer.serialize_value(
                TrustObjectType::OperatorReceipt,
                &current_value,
                &format!("multi-pass-{round}")
            ).expect("serialization should succeed in all rounds");

            serialization_results.push(serialized.clone());

            // Parse back for next round
            let serialized_str = String::from_utf8(serialized)
                .expect("serialized output should be UTF-8");
            current_value = serde_json::from_str(&serialized_str)
                .expect("should parse back to JSON");
        }

        // MR assertion: all rounds should produce identical results
        for (round, result) in serialization_results.iter().enumerate() {
            assert_eq!(&serialization_results[0], result,
                "Multi-pass serialization stability violated at round {round}:\n\
                 Round 0 result: {:?}\n\
                 Round {round} result: {:?}",
                String::from_utf8_lossy(&serialization_results[0]),
                String::from_utf8_lossy(result));
        }
    }
}

/// Composite metamorphic relations testing interaction between patterns
mod composite_metamorphic_tests {
    use super::*;

    #[test]
    fn mr_composite_field_order_and_roundtrip() {
        // Test composition: field reordering + round-trip should both be stable
        let mut serializer = CanonicalSerializer::with_all_schemas();

        let original_object = json!({
            "composite_test_id": "field-order-roundtrip-composition",
            "metadata": {"version": 1, "type": "test"},
            "data": {"values": [1, 2, 3], "flags": {"active": true}}
        });

        // Step 1: Reorder fields
        let reordered = super::field_order_invariance_tests::reorder_json_fields(&original_object);

        // Step 2: Serialize both
        let orig_serialized = serializer.serialize_value(
            TrustObjectType::PolicyCheckpoint, &original_object, "composite-orig")
            .expect("original should serialize");
        let reord_serialized = serializer.serialize_value(
            TrustObjectType::PolicyCheckpoint, &reordered, "composite-reord")
            .expect("reordered should serialize");

        // MR1: Field order invariance should hold
        assert_eq!(orig_serialized, reord_serialized, "Field order invariance violated in composite test");

        // Step 3: Round-trip both results
        let orig_str = String::from_utf8(orig_serialized.clone()).expect("UTF-8");
        let orig_parsed: Value = serde_json::from_str(&orig_str).expect("JSON parse");
        let orig_roundtrip = serializer.serialize_value(
            TrustObjectType::PolicyCheckpoint, &orig_parsed, "composite-orig-rt")
            .expect("original roundtrip should work");

        let reord_str = String::from_utf8(reord_serialized.clone()).expect("UTF-8");
        let reord_parsed: Value = serde_json::from_str(&reord_str).expect("JSON parse");
        let reord_roundtrip = serializer.serialize_value(
            TrustObjectType::PolicyCheckpoint, &reord_parsed, "composite-reord-rt")
            .expect("reordered roundtrip should work");

        // MR2: Round-trip should be stable for both
        assert_eq!(orig_serialized, orig_roundtrip, "Original roundtrip failed");
        assert_eq!(reord_serialized, reord_roundtrip, "Reordered roundtrip failed");

        // MR3: Composition should be commutative
        assert_eq!(orig_roundtrip, reord_roundtrip,
            "Composite field-reorder + roundtrip not commutative");
    }

    #[test]
    fn mr_composite_domain_separation_and_idempotence() {
        let mut serializer = CanonicalSerializer::with_all_schemas();

        let test_payload = json!({
            "domain_idempotence_test": "composite-domain-separation-idempotence",
            "shared_data": "test-data"
        });

        // Test domain separation + idempotence for each type
        for &object_type in TrustObjectType::all() {
            // First serialization
            let result1 = serializer.serialize_value(object_type, &test_payload, "comp-1")
                .expect("first serialization should succeed");

            // Parse and re-serialize (idempotence test)
            let parsed_str = String::from_utf8(result1.clone()).expect("UTF-8");
            let parsed_value: Value = serde_json::from_str(&parsed_str).expect("JSON");
            let result2 = serializer.serialize_value(object_type, &parsed_value, "comp-2")
                .expect("second serialization should succeed");

            // MR: Should be idempotent for each type
            assert_eq!(result1, result2,
                "Composite idempotence failed for {:?}", object_type);
        }
    }
}