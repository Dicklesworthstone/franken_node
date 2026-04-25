//! Golden artifact test for migration report export schema
//!
//! Tests that migration artifact JSON serialization remains stable across versions.
//! Migration artifacts are used for compliance audits and regulatory requirements,
//! any schema change would break audit tooling and compliance validation.

use std::{fs, path::Path};
use serde_json::Value;
use frankenengine_node::connector::migration_artifact::{
    MigrationArtifact, generate_reference_artifact
};

/// Create a deterministic migration artifact for golden testing
fn create_deterministic_migration_artifact() -> MigrationArtifact {
    // Use the reference artifact generator which produces deterministic output
    generate_reference_artifact()
}

#[test]
fn migration_report_schema_export_format_golden() {
    let migration_artifact = create_deterministic_migration_artifact();

    // Serialize to pretty-printed JSON (this is the compliance export format)
    let json_output = serde_json::to_string_pretty(&migration_artifact)
        .expect("Migration artifact should serialize to JSON");

    let golden_path = Path::new("artifacts/golden/migration_report_schema.json");

    // Check if we're in update mode
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(golden_path, &json_output).unwrap();
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    // Read expected golden output
    let expected_json = fs::read_to_string(golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff artifacts/golden/",
            golden_path.display()
        )
    });

    // Compare byte-for-byte
    if json_output != expected_json {
        let actual_path = Path::new("artifacts/golden/migration_report_schema.actual.json");
        fs::write(actual_path, &json_output).unwrap();

        panic!(
            "GOLDEN MISMATCH: Migration report schema changed\n\n\
             This indicates a breaking change to migration artifact serialization\n\
             that could break audit compliance and regulatory requirements.\n\n\
             To update: UPDATE_GOLDENS=1 cargo test migration_report_schema_export_format_golden\n\
             To review: diff {} {}",
            golden_path.display(),
            actual_path.display(),
        );
    }
}

#[test]
fn migration_report_schema_structure_stability() {
    let migration_artifact = create_deterministic_migration_artifact();
    let json_value: Value = serde_json::to_value(&migration_artifact)
        .expect("Migration artifact should convert to JSON value");

    // Verify critical schema elements are present and correctly typed
    assert!(json_value.get("schema_version").unwrap().is_string());
    assert!(json_value.get("plan_id").unwrap().is_string());
    assert!(json_value.get("plan_version").unwrap().is_number());
    assert!(json_value.get("preconditions").unwrap().is_array());
    assert!(json_value.get("steps").unwrap().is_array());
    assert!(json_value.get("rollback_receipt").unwrap().is_object());
    assert!(json_value.get("confidence_interval").unwrap().is_object());
    assert!(json_value.get("verifier_metadata").unwrap().is_object());
    assert!(json_value.get("signature").unwrap().is_string());
    assert!(json_value.get("content_hash").unwrap().is_string());
    assert!(json_value.get("created_at").unwrap().is_string());

    // Verify rollback receipt structure
    let rollback_receipt = json_value.get("rollback_receipt").unwrap();
    assert!(rollback_receipt.get("original_state_ref").unwrap().is_string());
    assert!(rollback_receipt.get("rollback_procedure_hash").unwrap().is_string());
    assert!(rollback_receipt.get("max_rollback_time_ms").unwrap().is_number());
    assert!(rollback_receipt.get("signer_identity").unwrap().is_string());
    assert!(rollback_receipt.get("signature").unwrap().is_string());

    // Verify confidence interval structure
    let confidence_interval = json_value.get("confidence_interval").unwrap();
    assert!(confidence_interval.get("probability").unwrap().is_number());
    assert!(confidence_interval.get("dry_run_success_rate").unwrap().is_number());
    assert!(confidence_interval.get("historical_similarity").unwrap().is_number());
    assert!(confidence_interval.get("precondition_coverage").unwrap().is_number());
    assert!(confidence_interval.get("rollback_validation").unwrap().is_boolean());

    // Verify verifier metadata structure
    let verifier_metadata = json_value.get("verifier_metadata").unwrap();
    assert!(verifier_metadata.get("replay_capsule_refs").unwrap().is_array());
    assert!(verifier_metadata.get("expected_state_hashes").unwrap().is_object());
    assert!(verifier_metadata.get("assertion_schemas").unwrap().is_array());
    assert!(verifier_metadata.get("verification_procedures").unwrap().is_array());

    // Verify migration steps array structure
    let steps = json_value.get("steps").unwrap().as_array().unwrap();
    assert!(!steps.is_empty(), "Migration should have at least one step");

    for step in steps {
        assert!(step.get("action_type").unwrap().is_string());
        assert!(step.get("target_resource").unwrap().is_string());
        assert!(step.get("pre_state_hash").unwrap().is_string());
        assert!(step.get("post_state_hash").unwrap().is_string());
        assert!(step.get("rollback_action").unwrap().is_string());
        assert!(step.get("estimated_duration_ms").unwrap().is_number());
    }
}