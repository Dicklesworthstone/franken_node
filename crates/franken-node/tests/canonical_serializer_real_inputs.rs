use frankenengine_node::connector::canonical_serializer::{
    CanonicalSchema, CanonicalSerializationRequest, CanonicalSerializer, TrustObjectType,
    canonical_serialization_round_trips, error_codes,
};
use serde_json::{Map, Value};

const POLICY_CHECKPOINT_PREIMAGE_GOLDEN_HEX: &str =
    include_str!("goldens/canonical_serializer/policy_checkpoint_preimage.hex");

fn decode_len_prefixed(bytes: &[u8]) -> &[u8] {
    assert!(bytes.len() >= 4, "canonical payload missing length prefix");
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    assert_eq!(bytes.len().saturating_sub(4), len);
    &bytes[4..]
}

fn decode_hex_golden(hex_text: &str) -> Vec<u8> {
    hex::decode(hex_text.trim()).expect("golden hex should decode to exact bytes")
}

#[test]
fn canonical_serializer_round_trips_real_caller_payload() {
    let payload = br#"{"checkpoint_id":"caller-cp","epoch":7,"sequence":9,"policy_hash":"sha256:caller-policy","timestamp":"2026-04-21T00:00:00Z"}"#;
    let request = CanonicalSerializationRequest {
        object_type: TrustObjectType::PolicyCheckpoint,
        payload,
        trace_id: "caller-trace",
    };

    let batch = canonical_serialization_round_trips(&[request]).unwrap();

    assert_eq!(batch.records.len(), 1);
    assert_eq!(
        batch.records[0].signature_preimage.domain_tag,
        TrustObjectType::PolicyCheckpoint.domain_tag()
    );
    let decoded = decode_len_prefixed(&batch.records[0].canonical_payload);
    assert!(
        std::str::from_utf8(decoded)
            .unwrap()
            .contains("\"checkpoint_id\":\"caller-cp\"")
    );
    assert_eq!(batch.events.len(), 3);
    assert!(
        batch
            .events
            .iter()
            .all(|event| event.trace_id == "caller-trace")
    );
}

#[test]
fn canonical_serializer_propagates_noncanonical_input_error() {
    let payload = br#"{"checkpoint_id":"bad-cp","epoch":7,"sequence":9,"policy_hash":"sha256:caller-policy","timestamp":"2026-04-21T00:00:00Z","unexpected":"field"}"#;
    let request = CanonicalSerializationRequest {
        object_type: TrustObjectType::PolicyCheckpoint,
        payload,
        trace_id: "bad-trace",
    };

    let err = canonical_serialization_round_trips(&[request]).unwrap_err();

    assert_eq!(err.code(), error_codes::ERR_CAN_NON_CANONICAL);
}

#[test]
fn canonical_serializer_round_trips_large_registered_schema() {
    let fields: Vec<String> = (0..128).map(|index| format!("field_{index:03}")).collect();
    let schema = CanonicalSchema {
        object_type: TrustObjectType::PolicyCheckpoint,
        field_order: fields.clone(),
        domain_tag: TrustObjectType::PolicyCheckpoint.domain_tag(),
        version: 1,
        no_float: true,
    };
    let mut serializer = CanonicalSerializer::new();
    serializer.register_schema(schema);

    let mut object = Map::new();
    for field in &fields {
        object.insert(field.clone(), Value::String("value".to_string()));
    }

    let canonical = serializer
        .serialize_value(
            TrustObjectType::PolicyCheckpoint,
            &Value::Object(object.clone()),
            "large-schema",
        )
        .expect("large registered schema should serialize");
    let decoded = decode_len_prefixed(&canonical);
    let decoded_text = std::str::from_utf8(decoded).expect("canonical JSON should be UTF-8");
    let expected_body = fields
        .iter()
        .map(|field| format!(r#""{field}":"value""#))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(decoded_text, format!("{{{expected_body}}}"));

    object.insert("zz_unknown".to_string(), Value::Bool(true));
    let err = serializer
        .serialize_value(
            TrustObjectType::PolicyCheckpoint,
            &Value::Object(object),
            "large-schema-unknown",
        )
        .expect_err("unknown fields outside the cached schema should be rejected");
    assert_eq!(err.code(), error_codes::ERR_CAN_NON_CANONICAL);
    assert!(err.to_string().contains("unknown field `zz_unknown`"));
}

#[test]
fn canonical_serializer_policy_checkpoint_preimage_matches_exact_golden_bytes() {
    let payload = br#"{"sequence":7,"timestamp":"2026-04-30T00:00:00Z","policy_hash":"sha256:000102030405060708090a0b0c0d0e0f","epoch":42,"checkpoint_id":"golden-cp-001"}"#;
    let request = CanonicalSerializationRequest {
        object_type: TrustObjectType::PolicyCheckpoint,
        payload,
        trace_id: "golden-policy-checkpoint",
    };

    let first = canonical_serialization_round_trips(&[request]).unwrap();
    let second = canonical_serialization_round_trips(&[request]).unwrap();
    let expected = decode_hex_golden(POLICY_CHECKPOINT_PREIMAGE_GOLDEN_HEX);

    assert_eq!(first.records.len(), 1);
    assert_eq!(
        first.records[0].signature_preimage.to_bytes(),
        second.records[0].signature_preimage.to_bytes(),
        "canonical serializer preimage bytes must be deterministic"
    );
    assert_eq!(
        first.records[0].signature_preimage.to_bytes(),
        expected,
        "policy checkpoint signature preimage bytes changed from the reviewed golden"
    );
}
