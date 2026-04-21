use frankenengine_node::connector::canonical_serializer::{CanonicalSerializer, TrustObjectType};
use frankenengine_node::observability::evidence_ledger::{EvidenceEntry, test_entry};
use fsqlite::{Connection, Row, SqliteValue};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FrankensqliteEvidenceRow {
    evidence_id: String,
    schema_version: String,
    payload_hash: String,
    canonical_payload: Vec<u8>,
}

fn canonical_evidence_entry() -> EvidenceEntry {
    let mut entry = test_entry("bd-19unt-canonical-evidence", 42);
    entry.decision_time = "2026-04-20T12:34:56Z".to_string();
    entry.payload = serde_json::json!({
        "bundle_id": "replay-bundle-001",
        "evidence_class": "operator_receipt",
        "policy": "strict",
        "verdict": "admit",
        "witnesses": ["alpha", "beta"],
    });
    entry
}

fn canonical_evidence_row() -> FrankensqliteEvidenceRow {
    let entry = canonical_evidence_entry();
    let payload = serde_json::to_vec(&entry).expect("evidence entry should serialize");
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let canonical_payload = serializer
        .round_trip_canonical(
            TrustObjectType::OperatorReceipt,
            &payload,
            "bd-19unt-frankensqlite-persistence",
        )
        .expect("evidence payload should round-trip canonically");

    FrankensqliteEvidenceRow {
        evidence_id: entry.decision_id.clone(),
        schema_version: entry.schema_version.clone(),
        payload_hash: hex::encode(Sha256::digest(&canonical_payload)),
        canonical_payload,
    }
}

fn parse_text(value: &SqliteValue, column: &str) -> Result<String, String> {
    match value {
        SqliteValue::Text(text) => Ok(text.to_string()),
        other => Err(format!("expected TEXT in {column}, got {other:?}")),
    }
}

fn parse_blob(value: &SqliteValue, column: &str) -> Result<Vec<u8>, String> {
    match value {
        SqliteValue::Blob(bytes) => Ok(bytes.to_vec()),
        other => Err(format!("expected BLOB in {column}, got {other:?}")),
    }
}

fn row_from_query(row: &Row) -> Result<FrankensqliteEvidenceRow, String> {
    let values = row.values();
    if values.len() != 4 {
        return Err(format!(
            "expected 4 columns in persisted evidence row, got {}",
            values.len()
        ));
    }

    Ok(FrankensqliteEvidenceRow {
        evidence_id: parse_text(&values[0], "evidence_id")?,
        schema_version: parse_text(&values[1], "schema_version")?,
        payload_hash: parse_text(&values[2], "payload_hash")?,
        canonical_payload: parse_blob(&values[3], "canonical_payload")?,
    })
}

#[test]
fn frankensqlite_persistence_integration_writes_and_reopens_canonical_evidence_row() {
    let expected_row = canonical_evidence_row();
    let expected_row_bytes =
        serde_json::to_vec(&expected_row).expect("expected evidence row should serialize");
    let decoded_row: FrankensqliteEvidenceRow =
        serde_json::from_slice(&expected_row_bytes).expect("evidence row should deserialize");
    assert_eq!(decoded_row, expected_row);
    let reserialized_row =
        serde_json::to_vec(&decoded_row).expect("decoded evidence row should reserialize");
    assert_eq!(reserialized_row, expected_row_bytes);

    let temp_dir = tempfile::tempdir().expect("tempdir should be created");
    let db_path = temp_dir
        .path()
        .join("frankensqlite-persistence-integration.db");
    let db_path = db_path.to_string_lossy().into_owned();

    let connection = Connection::open(&db_path).expect("file-backed database should open");
    connection
        .query("PRAGMA journal_mode=WAL;")
        .expect("WAL mode should be enabled");
    connection
        .execute(
            "CREATE TABLE IF NOT EXISTS franken_node_evidence_rows (
                evidence_id TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                canonical_payload BLOB NOT NULL
            );",
        )
        .expect("evidence table should be created");
    let inserted = connection
        .execute_with_params(
            "INSERT INTO franken_node_evidence_rows
                (evidence_id, schema_version, payload_hash, canonical_payload)
             VALUES (?1, ?2, ?3, ?4);",
            &[
                SqliteValue::Text(expected_row.evidence_id.clone().into()),
                SqliteValue::Text(expected_row.schema_version.clone().into()),
                SqliteValue::Text(expected_row.payload_hash.clone().into()),
                SqliteValue::Blob(expected_row.canonical_payload.clone().into()),
            ],
        )
        .expect("canonical evidence row should insert");
    assert_eq!(inserted, 1);
    connection
        .query("PRAGMA wal_checkpoint(FULL);")
        .expect("checkpoint should flush evidence row");
    drop(connection);

    let reopened = Connection::open(&db_path).expect("reopened database should open");
    let persisted_query = reopened
        .query_row_with_params(
            "SELECT evidence_id, schema_version, payload_hash, canonical_payload
             FROM franken_node_evidence_rows
             WHERE evidence_id = ?1;",
            &[SqliteValue::Text(expected_row.evidence_id.clone().into())],
        )
        .expect("persisted evidence row should be readable after reopen");
    let persisted_row =
        row_from_query(&persisted_query).expect("persisted row should match evidence schema");
    assert_eq!(
        persisted_row.payload_hash,
        hex::encode(Sha256::digest(&persisted_row.canonical_payload))
    );
    assert_eq!(persisted_row, expected_row);

    let persisted_row_bytes =
        serde_json::to_vec(&persisted_row).expect("persisted row should serialize");
    assert_eq!(persisted_row_bytes, expected_row_bytes);

    let serializer = CanonicalSerializer::with_all_schemas();
    let decoded_payload = serializer
        .deserialize(
            TrustObjectType::OperatorReceipt,
            &persisted_row.canonical_payload,
        )
        .expect("canonical payload should decode");
    let decoded_entry: EvidenceEntry =
        serde_json::from_slice(&decoded_payload).expect("decoded payload should parse");
    let reserialized_payload =
        serde_json::to_vec(&decoded_entry).expect("decoded entry should reserialize");
    let mut repeat_serializer = CanonicalSerializer::with_all_schemas();
    let recanonical_payload = repeat_serializer
        .round_trip_canonical(
            TrustObjectType::OperatorReceipt,
            &reserialized_payload,
            "bd-19unt-frankensqlite-persistence-repeat",
        )
        .expect("reencoded payload should round-trip canonically");
    assert_eq!(recanonical_payload, persisted_row.canonical_payload);
}
