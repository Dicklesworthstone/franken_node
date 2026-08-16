use frankenengine_node::connector::canonical_serializer::canonical_bytes;
use serde::{Deserialize, Serialize};
use sqlmodel::SchemaBuilder;
use sqlmodel_schema::{Migration, MigrationFormat, MigrationWriter};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION_V1: &str = "franken-node/sqlmodel-rust-schema/v1";
const DECLARED_V1_CONSUMER: &str = "franken-node-declared-v1-consumer";
const MIGRATION_ID_V1: &str = "00000000000001";

#[derive(sqlmodel::Model, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[sqlmodel(table = "franken_node_evidence_rows")]
struct SqlmodelEvidenceRow {
    #[sqlmodel(primary_key)]
    evidence_id: String,
    schema_version: String,
    payload_hash: String,
    canonical_payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ColumnDeclaration {
    name: String,
    column_name: String,
    sql_type: String,
    nullable: bool,
    primary_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MigrationDeclaration {
    id: String,
    description: String,
    up: String,
    down: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SqlmodelSchemaEnvelope {
    schema_version: String,
    consumer_version: String,
    table_name: String,
    primary_key: Vec<String>,
    columns: Vec<ColumnDeclaration>,
    create_statements: Vec<String>,
    migration: MigrationDeclaration,
    persisted_migration_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DeclaredV1ConsumerEnvelope {
    schema_version: String,
    consumer_version: String,
    table_name: String,
    create_statements: Vec<String>,
    migration: MigrationDeclaration,
}

fn deterministic_migration_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken-node-sqlmodel-schema-integration-{}-{nanos}",
        std::process::id()
    ))
}

fn schema_columns() -> Vec<ColumnDeclaration> {
    <SqlmodelEvidenceRow as sqlmodel::Model>::fields()
        .iter()
        .map(|field| ColumnDeclaration {
            name: field.name.to_string(),
            column_name: field.column_name.to_string(),
            sql_type: field.effective_sql_type(),
            nullable: field.nullable,
            primary_key: field.primary_key,
        })
        .collect()
}

fn schema_envelope_from_persisted_migration(
    create_statements: Vec<String>,
    migration: Migration,
    persisted_migration_source: String,
) -> SqlmodelSchemaEnvelope {
    SqlmodelSchemaEnvelope {
        schema_version: SCHEMA_VERSION_V1.to_string(),
        consumer_version: DECLARED_V1_CONSUMER.to_string(),
        table_name: <SqlmodelEvidenceRow as sqlmodel::Model>::TABLE_NAME.to_string(),
        primary_key: <SqlmodelEvidenceRow as sqlmodel::Model>::PRIMARY_KEY
            .iter()
            .map(|key| (*key).to_string())
            .collect(),
        columns: schema_columns(),
        create_statements,
        migration: MigrationDeclaration {
            id: migration.id,
            description: migration.description,
            up: migration.up,
            down: migration.down,
        },
        persisted_migration_source,
    }
}

#[test]
fn sqlmodel_rust_schema_roundtrip_uses_real_schema_builder_and_migration_writer() {
    let create_statements = SchemaBuilder::new()
        .create_table::<SqlmodelEvidenceRow>()
        .build();
    assert_eq!(create_statements.len(), 1);
    assert_eq!(
        create_statements[0],
        "CREATE TABLE IF NOT EXISTS \"franken_node_evidence_rows\" (\n  \"evidence_id\" TEXT NOT NULL,\n    \"schema_version\" TEXT NOT NULL,\n    \"payload_hash\" TEXT NOT NULL,\n    \"canonical_payload\" TEXT NOT NULL,\n  PRIMARY KEY (\"evidence_id\")\n)"
    );

    let migration = Migration::new(
        MIGRATION_ID_V1,
        "declare franken node evidence schema v1",
        format!("{};", create_statements.join(";\n")),
        "DROP TABLE \"franken_node_evidence_rows\";",
    );
    let migration_path = MigrationWriter::new(deterministic_migration_dir())
        .with_format(MigrationFormat::Rust)
        .write(&migration)
        .expect("sqlmodel_schema should persist the migration file");
    let persisted_migration_source =
        std::fs::read_to_string(&migration_path).expect("persisted migration should be readable");

    let envelope = schema_envelope_from_persisted_migration(
        create_statements,
        migration,
        persisted_migration_source,
    );
    let payload = serde_json::to_vec(&envelope).expect("schema envelope should serialize");

    let consumer: DeclaredV1ConsumerEnvelope =
        serde_json::from_slice(&payload).expect("declared v1 consumer should deserialize");
    assert_eq!(consumer.schema_version, SCHEMA_VERSION_V1);
    assert_eq!(consumer.consumer_version, DECLARED_V1_CONSUMER);
    assert_eq!(consumer.table_name, "franken_node_evidence_rows");
    assert_eq!(consumer.migration.id, MIGRATION_ID_V1);
    assert_eq!(consumer.create_statements, envelope.create_statements);

    let decoded: SqlmodelSchemaEnvelope =
        serde_json::from_slice(&payload).expect("schema envelope should deserialize");
    assert_eq!(decoded, envelope);
    let reserialized = serde_json::to_vec(&decoded).expect("decoded envelope should reserialize");
    assert_eq!(reserialized, payload);

    let envelope_value =
        serde_json::to_value(&envelope).expect("schema envelope should convert to JSON");
    let canonical = canonical_bytes(&envelope_value);
    let decoded_canonical: SqlmodelSchemaEnvelope =
        serde_json::from_slice(&canonical).expect("canonical sqlmodel payload should decode");
    assert_eq!(decoded_canonical, envelope);

    for iteration in 0..16 {
        let repeated_value = serde_json::to_value(&decoded_canonical)
            .expect("decoded canonical envelope should convert to JSON");
        let repeated = canonical_bytes(&repeated_value);
        assert_eq!(
            repeated, canonical,
            "canonical output changed on iteration {iteration}"
        );
    }
}
