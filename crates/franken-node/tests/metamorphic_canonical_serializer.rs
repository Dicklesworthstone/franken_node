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

/// Returns a canonical-schema-VALID JSON payload for the given trust object
/// type.
///
/// Prod's `CanonicalSerializer` (see `default_schema` in
/// `src/connector/canonical_serializer.rs`) now enforces a STRICT schema: the
/// top-level object must contain EXACTLY the schema's `field_order` (unknown
/// fields are rejected with `NonCanonicalInput { reason: "unknown field ...
/// outside canonical schema" }`, and missing required fields are rejected too).
/// Each object type has a DISJOINT required field set, so no single payload can
/// satisfy more than one type. Tests that need to drive "all types" therefore
/// must supply a per-type valid payload via this helper rather than reusing one
/// shared object (which the old fixtures did — and which the strict schema now
/// rejects before any metamorphic property can be checked).
///
/// Field sets (cited from prod `default_schema`):
///   policy_checkpoint    : checkpoint_id, epoch, sequence, policy_hash, timestamp
///   delegation_token     : token_id, issuer, delegate, scope, expiry
///   revocation_assertion : assertion_id, target_id, reason, effective_at, evidence_hash
///   session_ticket       : session_id, client_id, server_id, issued_at, ttl
///   zone_boundary_claim  : zone_id, boundary_type, peer_zone, trust_level, established_at
///   operator_receipt     : receipt_id, operator_id, action, artifact_hash, timestamp
pub(crate) fn canonical_payload_for(object_type: TrustObjectType) -> Value {
    match object_type {
        TrustObjectType::PolicyCheckpoint => json!({
            "checkpoint_id": "cp-shared",
            "epoch": 1,
            "sequence": 1,
            "policy_hash": "sha256:policy",
            "timestamp": "2026-04-21T00:00:00Z"
        }),
        TrustObjectType::DelegationToken => json!({
            "token_id": "tok-shared",
            "issuer": "issuer-a",
            "delegate": "delegate-b",
            "scope": "read:fleet",
            "expiry": 4102444800_i64
        }),
        TrustObjectType::RevocationAssertion => json!({
            "assertion_id": "rev-shared",
            "target_id": "tok-001",
            "reason": "compromise",
            "effective_at": "2026-04-21T00:00:00Z",
            "evidence_hash": "sha256:evidence"
        }),
        TrustObjectType::SessionTicket => json!({
            "session_id": "sess-shared",
            "client_id": "client-a",
            "server_id": "server-b",
            "issued_at": "2026-04-21T00:00:00Z",
            "ttl": 300
        }),
        TrustObjectType::ZoneBoundaryClaim => json!({
            "zone_id": "zone-shared",
            "boundary_type": "trust",
            "peer_zone": "zone-b",
            "trust_level": "strict",
            "established_at": "2026-04-21T00:00:00Z"
        }),
        TrustObjectType::OperatorReceipt => json!({
            "receipt_id": "rec-shared",
            "operator_id": "operator-a",
            "action": "approve",
            "artifact_hash": "sha256:artifact",
            "timestamp": "2026-04-21T00:00:00Z"
        }),
    }
}

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

        // Canonical policy_checkpoint fields: checkpoint_id, epoch, sequence,
        // policy_hash, timestamp. Inputs are varied by using REAL field values
        // (never by injecting marker keys the strict schema would reject).
        let original_policy = json!({
            "checkpoint_id": "policy-12345",
            "epoch": 1,
            "sequence": 7,
            "policy_hash": "sha256:allow_read:deny_write",
            "timestamp": "2026-04-21T10:00:00Z"
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

        // Canonical delegation_token fields: token_id, issuer, delegate, scope,
        // expiry. The old fixture's `principal`/`issued_at`/`expires_at`/
        // `capabilities` are NOT in the schema; `principal` maps to `delegate`.
        let original_token = json!({
            "token_id": "tok-abcdef",
            "issuer": "issuer-a",
            "delegate": "user@example.com",
            "scope": "read:documents",
            "expiry": 1714305600_i64
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

        // Every fixture must carry EXACTLY its type's canonical field set (see
        // `default_schema` in prod). The old fixtures used renamed/partial keys
        // (`policy_id`, `principal`, `revoked_object`, `ticket_id`/`session`/
        // `valid_until`, `claim_id`/`source_zone`/`target_zone`, `operation`)
        // that the strict schema rejects.
        let test_cases = vec![
            (TrustObjectType::PolicyCheckpoint, json!({
                "checkpoint_id": "test-policy",
                "epoch": 1,
                "sequence": 1,
                "policy_hash": "sha256:rule1:rule2",
                "timestamp": "2026-04-21T00:00:00Z"
            })),
            (TrustObjectType::DelegationToken, json!({
                "token_id": "test-token",
                "issuer": "issuer-a",
                "delegate": "test@example.com",
                "scope": "test:scope",
                "expiry": 1714305600_i64
            })),
            (TrustObjectType::RevocationAssertion, json!({
                "assertion_id": "test-assertion",
                "target_id": "obj-12345",
                "reason": "security_breach",
                "effective_at": "2026-04-21T00:00:00Z",
                "evidence_hash": "sha256:evidence"
            })),
            (TrustObjectType::SessionTicket, json!({
                "session_id": "test-ticket",
                "client_id": "client-a",
                "server_id": "sess-12345",
                "issued_at": "2026-04-21T00:00:00Z",
                "ttl": 1714305600_i64
            })),
            (TrustObjectType::ZoneBoundaryClaim, json!({
                "zone_id": "test-claim",
                "boundary_type": "trust",
                "peer_zone": "zone-b",
                "trust_level": "strict",
                "established_at": "2026-04-21T00:00:00Z"
            })),
            (TrustObjectType::OperatorReceipt, json!({
                "receipt_id": "test-receipt",
                "operator_id": "operator-a",
                "action": "deploy",
                "artifact_hash": "sha256:artifact",
                "timestamp": "2026-04-21T00:00:00Z"
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

        // Step 1: First serialization. Prod output is a length-prefixed BINARY
        // FRAME: `[u32 big-endian length][canonical JSON payload]` (see
        // `canonical_encode` in prod canonical_serializer.rs). It is NOT plain
        // JSON text, so `String::from_utf8`/`serde_json::from_str` on the raw
        // frame would fail on the leading NUL length bytes.
        let serialized_1 = serializer.serialize_value(object_type, value, "rt-1")
            .expect("initial serialization should succeed");

        // Step 2: Decode the frame with the PUBLIC prod decoder
        // (`CanonicalSerializer::deserialize` -> `canonical_decode`), which
        // strips the 4-byte length prefix and returns the canonical JSON payload
        // bytes. Those bytes are UTF-8 and parse as JSON.
        let canonical_payload = serializer.deserialize(object_type, &serialized_1)
            .expect("serialized frame should decode via prod deserialize");
        let parsed_value: Value = serde_json::from_slice(&canonical_payload)
            .expect("decoded canonical payload should parse as JSON");

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
        // Canonical policy_checkpoint fields only. Nested structure (which
        // exercises nested-key sorting stability under round-trip) lives UNDER a
        // canonical field value — nested objects are not strict-schema-checked.
        let policy = json!({
            "checkpoint_id": "rt-policy-test",
            "epoch": 42,
            "sequence": 3,
            "policy_hash": {
                "rules": ["allow", "deny", "audit"],
                "description": "Test policy for roundtrip",
                "tags": ["test", "metamorphic"]
            },
            "timestamp": "2026-04-21T00:00:00Z"
        });

        test_roundtrip_consistency(TrustObjectType::PolicyCheckpoint, &policy);
    }

    #[test]
    fn mr_roundtrip_complex_nested_structure() {
        // Top-level keys must be exactly the delegation_token canonical set
        // (token_id, issuer, delegate, scope, expiry). The complex nested
        // structure the test wants to exercise lives UNDER the `scope` value —
        // nested objects/arrays are canonicalized (keys sorted) but not
        // strict-schema-checked, so arbitrary depth is allowed there.
        let complex_token = json!({
            "token_id": "complex-test-token",
            "issuer": "issuer-a",
            "delegate": "complex-user@example.com",
            "scope": {
                "label": "complex:read:write:admin",
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
            },
            "expiry": 1714305600_i64
        });

        test_roundtrip_consistency(TrustObjectType::DelegationToken, &complex_token);
    }

    #[test]
    fn mr_roundtrip_edge_cases() {
        // Every fixture is a VALID session_ticket (session_id, client_id,
        // server_id, issued_at, ttl). The edge-case variety the test wants
        // (minimal marker, large strings, many fields, special chars) is
        // expressed through canonical field VALUES or nested-object values —
        // never through extra top-level keys the strict schema would reject.
        let edge_cases = vec![
            // Minimal-marker case (was `minimal_id`): vary the real session_id.
            json!({
                "session_id": "empty-test",
                "client_id": "client-a",
                "server_id": "server-b",
                "issued_at": "2026-04-21T00:00:00Z",
                "ttl": 300
            }),

            // Large strings: carried in a canonical field value.
            json!({
                "session_id": "large-string-test",
                "client_id": "x".repeat(1000),
                "server_id": "Testing large string handling",
                "issued_at": "2026-04-21T00:00:00Z",
                "ttl": 300
            }),

            // Many fields: nested UNDER a canonical field (nested objects allow
            // arbitrary keys and are sorted deterministically).
            json!({
                "session_id": "many-fields-test",
                "client_id": "client-a",
                "server_id": {
                    "field_01": "value_01", "field_02": "value_02", "field_03": "value_03",
                    "field_04": "value_04", "field_05": "value_05", "field_06": "value_06",
                    "field_07": "value_07", "field_08": "value_08", "field_09": "value_09",
                    "field_10": "value_10"
                },
                "issued_at": "2026-04-21T00:00:00Z",
                "ttl": 300
            }),

            // Special characters: carried in canonical field values.
            json!({
                "session_id": "special-chars-test",
                "client_id": "Unicode: 🔒🛡️⚠️ Quotes: \"'` Escapes: \\n\\t\\r",
                "server_id": "{\"nested\": [1,2,3]}",
                "issued_at": "2026-04-21T00:00:00Z",
                "ttl": 300
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

        // NOTE (strict-schema constraint): the original relation fed ONE shared
        // payload to every type and asserted the outputs differed (domain-tag
        // separation for identical content). Under the strict canonical schema
        // this is no longer expressible: (1) each type's required field set is
        // DISJOINT, so no single payload validates against more than one type,
        // and (2) `serialize_value` output does NOT embed the domain tag (only
        // `SignaturePreimage`/`build_preimage` prepends it). We therefore drive
        // each type with its own canonical-valid payload and assert the
        // serializations are pairwise distinct — i.e. distinct trust object
        // types never collide to identical canonical bytes. (See report:
        // testing domain-tag separation for IDENTICAL content requires
        // build_preimage, not serialize_value.)
        let all_types = TrustObjectType::all();
        let mut serialization_results = Vec::new();

        for &object_type in all_types {
            let payload = canonical_payload_for(object_type);
            let result = serializer.serialize_value(object_type, &payload, "mr-domain")
                .expect("serialization should succeed for all types");
            serialization_results.push((object_type, result));
        }

        // MR assertion: different trust object types must produce different serializations
        for i in 0..serialization_results.len() {
            for j in (i+1)..serialization_results.len() {
                let (type_a, result_a) = &serialization_results[i];
                let (type_b, result_b) = &serialization_results[j];

                assert_ne!(result_a, result_b,
                    "Domain tag separation failed: {:?} and {:?} produced identical canonical serialization.\n\
                     Distinct trust object types must never collide to identical canonical bytes (signature collision risk).",
                    type_a, type_b);
            }
        }
    }

    #[test]
    fn mr_domain_tag_consistency() {
        let mut serializer1 = CanonicalSerializer::with_all_schemas();
        let mut serializer2 = CanonicalSerializer::with_all_schemas();

        // The marker-keyed single payload can't validate against every type's
        // disjoint schema; drive each type with its own valid payload. The
        // property under test (same type + same input → same output across two
        // independent serializer instances = determinism) is unchanged.
        for &object_type in TrustObjectType::all() {
            let test_payload = canonical_payload_for(object_type);

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

        // Canonical zone_boundary_claim fields: zone_id, boundary_type,
        // peer_zone, trust_level, established_at. The marker `idempotence_test_id`
        // is dropped; the input is varied via real field values, and the nested
        // object / array that exercise nested-canonicalization idempotence live
        // UNDER canonical field values.
        let test_object = json!({
            "zone_id": "test-idempotent-serialization",
            "boundary_type": "trust",
            "peer_zone": {"nested": "value"},
            "trust_level": {"levels": [1, 2, 3, 4, 5]},
            "established_at": "2026-04-21T00:00:00Z"
        });

        // First serialization
        let result1 = serializer.serialize_value(
            TrustObjectType::ZoneBoundaryClaim,
            &test_object,
            "idempotent-1"
        ).expect("first serialization should succeed");

        // Decode the binary frame via the prod decoder (strips the 4-byte
        // length prefix) before parsing the canonical JSON payload.
        let canonical_payload = serializer.deserialize(TrustObjectType::ZoneBoundaryClaim, &result1)
            .expect("serialized frame should decode via prod deserialize");
        let canonical_value: Value = serde_json::from_slice(&canonical_payload)
            .expect("decoded canonical payload should parse as JSON");

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

        // Canonical operator_receipt fields: receipt_id, operator_id, action,
        // artifact_hash, timestamp. The marker `multi_pass_test` is dropped
        // (input varied via receipt_id); the `complex_nested` structure that
        // stresses multi-pass stability lives UNDER the `action` field value.
        let initial_object = json!({
            "receipt_id": "multiple-serialization-stability",
            "operator_id": "operator-a",
            "action": {
                "array": [
                    {"item": "first", "order": 3},
                    {"item": "second", "order": 1},
                    {"item": "third", "order": 2}
                ],
                "metadata": {
                    "version": 1,
                    "flags": {"enabled": true, "debug": false}
                }
            },
            "artifact_hash": "sha256:artifact",
            "timestamp": "2026-04-21T00:00:00Z"
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

            // Parse back for next round: decode the binary frame (strip the
            // 4-byte length prefix) via the prod decoder, then parse the JSON.
            let canonical_payload = serializer
                .deserialize(TrustObjectType::OperatorReceipt, &serialized)
                .expect("serialized frame should decode via prod deserialize");
            current_value = serde_json::from_slice(&canonical_payload)
                .expect("decoded canonical payload should parse back to JSON");
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

        // Canonical policy_checkpoint fields only. The marker `composite_test_id`
        // is dropped (input varied via checkpoint_id); the `metadata`/`data`
        // structures the composite relation reorders + round-trips live UNDER
        // canonical field values (reordering canonical top-level keys is what the
        // relation asserts is invariant).
        let original_object = json!({
            "checkpoint_id": "field-order-roundtrip-composition",
            "epoch": 1,
            "sequence": 2,
            "policy_hash": {
                "metadata": {"version": 1, "type": "test"},
                "data": {"values": [1, 2, 3], "flags": {"active": true}}
            },
            "timestamp": "2026-04-21T00:00:00Z"
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

        // Step 3: Round-trip both results. Decode each binary frame via the prod
        // decoder (strips the 4-byte length prefix) before parsing the JSON.
        let orig_payload = serializer
            .deserialize(TrustObjectType::PolicyCheckpoint, &orig_serialized)
            .expect("original frame should decode via prod deserialize");
        let orig_parsed: Value = serde_json::from_slice(&orig_payload).expect("JSON parse");
        let orig_roundtrip = serializer.serialize_value(
            TrustObjectType::PolicyCheckpoint, &orig_parsed, "composite-orig-rt")
            .expect("original roundtrip should work");

        let reord_payload = serializer
            .deserialize(TrustObjectType::PolicyCheckpoint, &reord_serialized)
            .expect("reordered frame should decode via prod deserialize");
        let reord_parsed: Value = serde_json::from_slice(&reord_payload).expect("JSON parse");
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

        // Each type has a DISJOINT canonical field set, so the old single
        // `test_payload` (marker `domain_idempotence_test` + `shared_data`) can
        // never be valid for every type. Drive each type with its own valid
        // payload; the per-type idempotence property is unchanged.
        for &object_type in TrustObjectType::all() {
            let test_payload = canonical_payload_for(object_type);

            // First serialization
            let result1 = serializer.serialize_value(object_type, &test_payload, "comp-1")
                .expect("first serialization should succeed");

            // Decode the binary frame (strip the 4-byte length prefix) via the
            // prod decoder, then re-serialize (idempotence test).
            let parsed_payload = serializer.deserialize(object_type, &result1)
                .expect("serialized frame should decode via prod deserialize");
            let parsed_value: Value = serde_json::from_slice(&parsed_payload).expect("JSON");
            let result2 = serializer.serialize_value(object_type, &parsed_value, "comp-2")
                .expect("second serialization should succeed");

            // MR: Should be idempotent for each type
            assert_eq!(result1, result2,
                "Composite idempotence failed for {:?}", object_type);
        }
    }
}