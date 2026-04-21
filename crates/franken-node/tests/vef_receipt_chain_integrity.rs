use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionReceipt, RECEIPT_SCHEMA_VERSION, receipt_hash_sha256, round_trip_canonical_bytes,
    serialize_canonical, validate_receipt, verify_hash,
};
use serde::Deserialize;
use std::path::Path;

const RECEIPT_SCHEMA_VECTORS_JSON: &str =
    include_str!("../../../artifacts/10.18/vef_receipt_schema_vectors.json");

#[derive(Debug, Deserialize)]
struct ReceiptSchemaVectorBundle {
    bead_id: String,
    schema_version: String,
    receipt_schema_version: String,
    vectors: Vec<ReceiptSchemaVector>,
}

#[derive(Debug, Deserialize)]
struct ReceiptSchemaVector {
    name: String,
    input_receipt: ExecutionReceipt,
    expected_hash: String,
    expected_canonical_witnesses: Vec<String>,
}

fn receipt_schema_vectors() -> ReceiptSchemaVectorBundle {
    serde_json::from_str(RECEIPT_SCHEMA_VECTORS_JSON).expect("receipt schema vectors parse")
}

#[test]
fn conformance_fixture_exists() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/vef_receipt_chain_integrity.rs");
    assert!(
        fixture.is_file(),
        "expected conformance fixture at {}",
        fixture.display()
    );
}

#[test]
fn receipt_schema_vectors_match_metadata_and_canonical_contract() {
    let bundle = receipt_schema_vectors();

    assert_eq!(bundle.bead_id, "bd-p73r");
    assert_eq!(bundle.schema_version, "vef-receipt-vectors-v1");
    assert_eq!(bundle.receipt_schema_version, RECEIPT_SCHEMA_VERSION);
    assert!(
        !bundle.vectors.is_empty(),
        "schema vector artifact must publish at least one receipt"
    );

    for vector in bundle.vectors {
        validate_receipt(&vector.input_receipt)
            .unwrap_or_else(|err| panic!("{} must validate: {}", vector.name, err));

        let canonicalized = vector.input_receipt.canonicalized();
        assert_eq!(
            canonicalized.witness_references, vector.expected_canonical_witnesses,
            "{} witness ordering must match artifact canonicalization",
            vector.name
        );

        let canonical_bytes = serialize_canonical(&vector.input_receipt)
            .unwrap_or_else(|err| panic!("{} must serialize canonically: {}", vector.name, err));
        let canonical_receipt: ExecutionReceipt = serde_json::from_slice(&canonical_bytes)
            .unwrap_or_else(|err| panic!("{} canonical bytes must parse: {}", vector.name, err));
        assert_eq!(
            canonical_receipt, canonicalized,
            "{} canonical bytes must decode to the canonicalized receipt",
            vector.name
        );
    }
}

#[test]
fn receipt_schema_vectors_round_trip_without_byte_drift() {
    let bundle = receipt_schema_vectors();

    for vector in bundle.vectors {
        let first_bytes = serialize_canonical(&vector.input_receipt).unwrap_or_else(|err| {
            panic!("{} first serialization must succeed: {}", vector.name, err)
        });
        let round_tripped =
            round_trip_canonical_bytes(&vector.input_receipt).unwrap_or_else(|err| {
                panic!(
                    "{} round-trip bytes must remain stable: {}",
                    vector.name, err
                )
            });

        assert_eq!(
            first_bytes, round_tripped,
            "{} canonical JSON bytes must be byte-stable across reparse",
            vector.name
        );
    }
}

#[test]
fn receipt_schema_vectors_match_published_hashes() {
    let bundle = receipt_schema_vectors();

    for vector in bundle.vectors {
        let computed_hash = receipt_hash_sha256(&vector.input_receipt)
            .unwrap_or_else(|err| panic!("{} must hash canonically: {}", vector.name, err));
        assert_eq!(
            computed_hash, vector.expected_hash,
            "{} canonical hash must match checked-in vector",
            vector.name
        );
        verify_hash(&vector.input_receipt, &vector.expected_hash)
            .unwrap_or_else(|err| panic!("{} hash verification must pass: {}", vector.name, err));
    }
}
