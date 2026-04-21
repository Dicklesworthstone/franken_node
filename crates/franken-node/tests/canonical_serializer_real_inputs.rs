use frankenengine_node::connector::canonical_serializer::{
    CanonicalSerializationRequest, TrustObjectType, canonical_serialization_round_trips,
    error_codes,
};

fn decode_len_prefixed(bytes: &[u8]) -> &[u8] {
    assert!(bytes.len() >= 4, "canonical payload missing length prefix");
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    assert_eq!(bytes.len().saturating_sub(4), len);
    &bytes[4..]
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
