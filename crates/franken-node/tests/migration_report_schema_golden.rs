//! Golden artifact test for migration report export schema
//!
//! Tests that migration artifact JSON serialization remains stable across versions.
//! Migration artifacts are used for compliance audits and regulatory requirements,
//! any schema change would break audit tooling and compliance validation.

use frankenengine_node::connector::migration_artifact::{
    BEHAVIORAL_CONFORMANCE_CERTIFICATE_SCHEMA_VERSION, ConformancePropertyClass, MigrationArtifact,
    compute_behavioral_conformance_certificate_hash, compute_differential_witness_hash,
    error_codes, generate_reference_artifact,
    generate_reference_behavioral_conformance_certificate,
    validate_behavioral_conformance_certificate,
    verify_behavioral_conformance_certificate_signature,
};
use serde_json::Value;
use std::{fs, path::Path};

/// Create a deterministic migration artifact for golden testing
fn create_deterministic_migration_artifact() -> MigrationArtifact {
    // Use the reference artifact generator which produces deterministic output
    generate_reference_artifact()
}

fn assert_real_hex_field(value: &Value, field: &str) {
    assert!(
        value.is_string(),
        "{field} should be serialized as a string"
    );
    let text = value.as_str().unwrap_or("");
    let lowered = text.to_ascii_lowercase();
    assert!(
        !lowered.contains("placeholder") && !lowered.contains("sentinel"),
        "{field} must not contain placeholder or sentinel material: {text}"
    );
    assert_eq!(text.len(), 64, "{field} should be 64 hex characters");
    assert!(
        text.chars().all(|ch| ch.is_ascii_hexdigit()),
        "{field} should be hex encoded: {text}"
    );
}

#[test]
fn behavioral_conformance_certificate_schema_exports_bound_and_ledger_chain() {
    let certificate = generate_reference_behavioral_conformance_certificate();
    let json_value: Value = serde_json::to_value(&certificate)
        .expect("Behavioral conformance certificate should convert to JSON value");

    assert_eq!(
        json_value["schema_version"],
        BEHAVIORAL_CONFORMANCE_CERTIFICATE_SCHEMA_VERSION
    );
    assert_real_hex_field(json_value.get("source_hash").unwrap(), "source_hash");
    assert_real_hex_field(json_value.get("target_hash").unwrap(), "target_hash");
    assert_real_hex_field(
        json_value.get("lockstep_verdict_hash").unwrap(),
        "lockstep_verdict_hash",
    );
    assert_real_hex_field(json_value.get("content_hash").unwrap(), "content_hash");
    let differential_witness = json_value
        .get("differential_witness")
        .and_then(Value::as_object)
        .expect("certificate must expose differential_witness object");
    assert_eq!(
        differential_witness["lockstep_oracle_id"],
        "compat-lockstep-oracle-v1"
    );
    assert_real_hex_field(
        differential_witness.get("fixture_corpus_digest").unwrap(),
        "differential_witness.fixture_corpus_digest",
    );
    assert_eq!(
        differential_witness["proptest_seed"],
        "proptest-seed:cjs-esm:0000000000000001"
    );
    assert_eq!(differential_witness["fixture_cases"], 64);
    assert_eq!(differential_witness["proptest_cases"], 32);
    assert_eq!(differential_witness["effect_receipt_equivalence_cases"], 32);
    assert_eq!(differential_witness["divergence_count"], 0);
    assert_eq!(differential_witness["verdict"], "pass");
    assert_real_hex_field(
        differential_witness.get("witness_hash").unwrap(),
        "differential_witness.witness_hash",
    );
    assert_eq!(
        json_value["lockstep_verdict_hash"],
        differential_witness["witness_hash"]
    );

    let bound = json_value
        .get("bound")
        .and_then(Value::as_object)
        .expect("certificate must expose first-class bound object");
    let input_scope = bound
        .get("input_scope")
        .and_then(Value::as_array)
        .expect("bound.input_scope must be an array");
    assert_eq!(input_scope.len(), 1);
    assert_eq!(input_scope[0]["input_class"], "commonjs-module");
    assert_eq!(
        input_scope[0]["selector"],
        "fixtures/migration/commonjs/*.js"
    );
    assert_eq!(input_scope[0]["count"], 128);
    assert_real_hex_field(&input_scope[0]["digest"], "bound.input_scope[0].digest");

    let property_classes = bound
        .get("property_classes")
        .and_then(Value::as_array)
        .expect("bound.property_classes must be an array");
    assert_eq!(
        property_classes,
        &vec![
            Value::String("syntax_equivalence".to_string()),
            Value::String("observable_output".to_string()),
            Value::String("error_behavior".to_string()),
        ]
    );
    assert_eq!(
        certificate.bound.property_classes,
        vec![
            ConformancePropertyClass::SyntaxEquivalence,
            ConformancePropertyClass::ObservableOutput,
            ConformancePropertyClass::ErrorBehavior,
        ]
    );

    let coverage = bound
        .get("coverage")
        .and_then(Value::as_object)
        .expect("bound.coverage must be an object");
    assert_eq!(coverage["covered_cases"], 128);
    assert_eq!(coverage["total_cases"], 128);
    assert_eq!(coverage["coverage_ratio"], 1.0);
    assert_eq!(
        coverage["measurement_method"],
        "deterministic-lockstep-corpus-v1"
    );

    let ledger_chain = json_value
        .get("ledger_chain")
        .and_then(Value::as_object)
        .expect("certificate must expose ledger_chain object");
    assert!(ledger_chain["previous_certificate_hash"].is_null());
    assert_eq!(ledger_chain["certificate_sequence"], 0);
    assert_eq!(
        ledger_chain["ledger_domain"],
        "observability:evidence-ledger-v2"
    );
    assert_real_hex_field(
        ledger_chain.get("evidence_ledger_entry_hash").unwrap(),
        "ledger_chain.evidence_ledger_entry_hash",
    );

    let validation = validate_behavioral_conformance_certificate(&certificate);
    assert!(validation.valid, "errors: {:?}", validation.errors);
    assert!(verify_behavioral_conformance_certificate_signature(
        &certificate
    ));
}

#[test]
fn behavioral_conformance_certificate_rejects_unbounded_and_unlinked_claims() {
    let mut missing_bound = generate_reference_behavioral_conformance_certificate();
    missing_bound.bound.input_scope.clear();
    missing_bound.content_hash = compute_behavioral_conformance_certificate_hash(&missing_bound);
    let validation = validate_behavioral_conformance_certificate(&missing_bound);
    assert!(!validation.valid);
    assert!(
        validation
            .errors
            .iter()
            .any(|error| error.contains(error_codes::ERR_MA_BOUND_INVALID)),
        "expected bound validation error, got {:?}",
        validation.errors
    );

    let mut bad_chain = generate_reference_behavioral_conformance_certificate();
    bad_chain.ledger_chain.previous_certificate_hash = Some("not-a-sha256".to_string());
    bad_chain.content_hash = compute_behavioral_conformance_certificate_hash(&bad_chain);
    let validation = validate_behavioral_conformance_certificate(&bad_chain);
    assert!(!validation.valid);
    assert!(
        validation.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_INVALID_SCHEMA)
                && error.contains("ledger_chain.previous_certificate_hash")
        }),
        "expected previous hash validation error, got {:?}",
        validation.errors
    );

    let mut tampered_bound = generate_reference_behavioral_conformance_certificate();
    assert!(verify_behavioral_conformance_certificate_signature(
        &tampered_bound
    ));
    tampered_bound.bound.coverage.covered_cases = 127;
    assert!(!verify_behavioral_conformance_certificate_signature(
        &tampered_bound
    ));

    let mut divergent_witness = generate_reference_behavioral_conformance_certificate();
    divergent_witness.differential_witness.divergence_count = 1;
    divergent_witness.differential_witness.witness_hash =
        compute_differential_witness_hash(&divergent_witness.differential_witness);
    divergent_witness.lockstep_verdict_hash =
        divergent_witness.differential_witness.witness_hash.clone();
    divergent_witness.content_hash =
        compute_behavioral_conformance_certificate_hash(&divergent_witness);
    let validation = validate_behavioral_conformance_certificate(&divergent_witness);
    assert!(!validation.valid);
    assert!(
        validation
            .errors
            .iter()
            .any(|error| error.contains(error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID)),
        "expected differential witness validation error, got {:?}",
        validation.errors
    );
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
    assert_real_hex_field(json_value.get("signature").unwrap(), "signature");
    assert_real_hex_field(json_value.get("content_hash").unwrap(), "content_hash");

    // Verify rollback receipt structure
    let rollback_receipt = json_value.get("rollback_receipt").unwrap();
    assert!(
        rollback_receipt
            .get("original_state_ref")
            .unwrap()
            .is_string()
    );
    assert!(
        rollback_receipt
            .get("rollback_procedure_hash")
            .unwrap()
            .is_string()
    );
    assert!(
        rollback_receipt
            .get("max_rollback_time_ms")
            .unwrap()
            .is_number()
    );
    assert!(rollback_receipt.get("signer_identity").unwrap().is_string());
    assert!(rollback_receipt.get("signature").unwrap().is_string());
    assert_real_hex_field(
        rollback_receipt.get("signature").unwrap(),
        "rollback_receipt.signature",
    );

    // Verify confidence interval structure
    let confidence_interval = json_value.get("confidence_interval").unwrap();
    assert!(confidence_interval.get("probability").unwrap().is_number());
    assert!(
        confidence_interval
            .get("dry_run_success_rate")
            .unwrap()
            .is_number()
    );
    assert!(
        confidence_interval
            .get("historical_similarity")
            .unwrap()
            .is_number()
    );
    assert!(
        confidence_interval
            .get("precondition_coverage")
            .unwrap()
            .is_number()
    );
    assert!(
        confidence_interval
            .get("rollback_validation")
            .unwrap()
            .is_boolean()
    );

    // Verify verifier metadata structure
    let verifier_metadata = json_value.get("verifier_metadata").unwrap();
    assert!(
        verifier_metadata
            .get("replay_capsule_refs")
            .unwrap()
            .is_array()
    );
    assert!(
        verifier_metadata
            .get("expected_state_hashes")
            .unwrap()
            .is_object()
    );
    assert!(
        verifier_metadata
            .get("assertion_schemas")
            .unwrap()
            .is_array()
    );
    assert!(
        verifier_metadata
            .get("verification_procedures")
            .unwrap()
            .is_array()
    );

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
