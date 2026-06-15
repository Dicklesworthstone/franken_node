//! Golden artifact test for migration report export schema
//!
//! Tests that migration artifact JSON serialization remains stable across versions.
//! Migration artifacts are used for compliance audits and regulatory requirements,
//! any schema change would break audit tooling and compliance validation.

use frankenengine_node::connector::migration_artifact::{
    BEHAVIORAL_CONFORMANCE_CERTIFICATE_SCHEMA_VERSION, ConformancePropertyClass, MigrationArtifact,
    compute_behavioral_conformance_certificate_hash, compute_differential_witness_hash,
    error_codes, event_codes, generate_reference_artifact,
    generate_reference_behavioral_conformance_certificate,
    validate_behavioral_conformance_certificate,
    verify_behavioral_conformance_certificate_signature,
};
use frankenengine_verifier_sdk::{
    MIGRATION_EQUIVALENCE_ARTIFACT_PATH, MIGRATION_EQUIVALENCE_SCHEMA_VERSION, SDK_VERSION,
    VerificationVerdict, bundle, create_verifier_sdk,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
use tree_sitter::{Language, Node, Parser as JsParser};

const SDK_MIGRATION_SOURCE_HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:migration-source:v1:";
const SDK_MIGRATION_AST_HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:migration-js-ast:v1:";
const SDK_MIGRATION_LOCKSTEP_VERDICT_HASH_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:migration-lockstep-verdict:v1:";

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

#[derive(Debug, Clone, Serialize)]
struct TestMigrationSourceSnapshot {
    path: String,
    source_hash: String,
    ast_hash: String,
    source_text: String,
}

#[derive(Debug, Clone, Serialize)]
struct TestMigrationPreconditionProof {
    rule_id: String,
    source_contains: Vec<String>,
    source_not_contains: Vec<String>,
    target_contains: Vec<String>,
    target_not_contains: Vec<String>,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct TestMigrationLockstepWitness {
    lockstep_oracle_id: String,
    fixture_corpus_digest: String,
    proptest_seed: String,
    fixture_cases: u64,
    proptest_cases: u64,
    effect_receipt_equivalence_cases: u64,
    effect_receipt_ids: Vec<String>,
    divergence_count: u64,
    verdict: String,
    lockstep_verdict_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct TestMigrationEquivalenceCapsule {
    schema_version: String,
    rule_id: String,
    source: TestMigrationSourceSnapshot,
    target: TestMigrationSourceSnapshot,
    precondition: TestMigrationPreconditionProof,
    lockstep_witness: TestMigrationLockstepWitness,
}

fn push_sdk_length_prefixed(payload: &mut Vec<u8>, bytes: &[u8]) {
    payload.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    payload.extend_from_slice(bytes);
}

fn sdk_migration_source_hash(source_text: &str) -> String {
    let mut payload = Vec::new();
    push_sdk_length_prefixed(&mut payload, SDK_MIGRATION_SOURCE_HASH_DOMAIN);
    push_sdk_length_prefixed(&mut payload, source_text.as_bytes());
    hex::encode(Sha256::digest(&payload))
}

fn push_sdk_js_ast_node(payload: &mut Vec<u8>, node: Node<'_>) {
    push_sdk_length_prefixed(payload, node.kind().as_bytes());
    payload.push(u8::from(node.is_named()));
    payload.extend_from_slice(
        &u64::try_from(node.start_byte())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(node.end_byte())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(node.child_count())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(node.named_child_count())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for index in 0..node.child_count() {
        let Ok(child_index) = u32::try_from(index) else {
            continue;
        };
        if let Some(child) = node.child(child_index) {
            push_sdk_js_ast_node(payload, child);
        }
    }
}

fn sdk_js_ast_hash(source_text: &str) -> String {
    let mut parser = JsParser::new();
    let language: Language = tree_sitter_javascript::LANGUAGE.into();
    parser
        .set_language(&language)
        .expect("JavaScript parser must be available");
    let tree = parser
        .parse(source_text, None)
        .expect("JavaScript parser must produce a syntax tree");
    assert!(
        !tree.root_node().has_error(),
        "test JavaScript fixture must parse without syntax errors"
    );

    let mut payload = Vec::new();
    push_sdk_length_prefixed(&mut payload, SDK_MIGRATION_AST_HASH_DOMAIN);
    push_sdk_js_ast_node(&mut payload, tree.root_node());
    hex::encode(Sha256::digest(&payload))
}

fn sdk_migration_lockstep_verdict_hash(capsule: &TestMigrationEquivalenceCapsule) -> String {
    let witness = &capsule.lockstep_witness;
    let canonical = json!({
        "schema_version": &capsule.schema_version,
        "rule_id": &capsule.rule_id,
        "source_hash": &capsule.source.source_hash,
        "target_hash": &capsule.target.source_hash,
        "source_ast_hash": &capsule.source.ast_hash,
        "target_ast_hash": &capsule.target.ast_hash,
        "precondition_passed": capsule.precondition.passed,
        "lockstep_oracle_id": &witness.lockstep_oracle_id,
        "fixture_corpus_digest": &witness.fixture_corpus_digest,
        "proptest_seed": &witness.proptest_seed,
        "fixture_cases": witness.fixture_cases,
        "proptest_cases": witness.proptest_cases,
        "effect_receipt_equivalence_cases": witness.effect_receipt_equivalence_cases,
        "effect_receipt_ids": &witness.effect_receipt_ids,
        "divergence_count": witness.divergence_count,
        "verdict": &witness.verdict,
    });
    let canonical_bytes =
        serde_json::to_vec(&canonical).expect("lockstep verdict JSON should serialize");
    let mut payload = Vec::new();
    push_sdk_length_prefixed(&mut payload, SDK_MIGRATION_LOCKSTEP_VERDICT_HASH_DOMAIN);
    push_sdk_length_prefixed(&mut payload, &canonical_bytes);
    hex::encode(Sha256::digest(&payload))
}

fn reference_sdk_equivalence_capsule() -> TestMigrationEquivalenceCapsule {
    let certificate = generate_reference_behavioral_conformance_certificate();
    let source_text = "const value = require(\"dep\");\nmodule.exports = value;\n".to_string();
    let target_text = "import value from \"dep\";\nexport default value;\n".to_string();
    let mut capsule = TestMigrationEquivalenceCapsule {
        schema_version: MIGRATION_EQUIVALENCE_SCHEMA_VERSION.to_string(),
        rule_id: certificate.rule_id.clone(),
        source: TestMigrationSourceSnapshot {
            path: "src/input.cjs".to_string(),
            source_hash: sdk_migration_source_hash(&source_text),
            ast_hash: sdk_js_ast_hash(&source_text),
            source_text,
        },
        target: TestMigrationSourceSnapshot {
            path: "src/output.mjs".to_string(),
            source_hash: sdk_migration_source_hash(&target_text),
            ast_hash: sdk_js_ast_hash(&target_text),
            source_text: target_text,
        },
        precondition: TestMigrationPreconditionProof {
            rule_id: certificate.rule_id.clone(),
            source_contains: vec!["require(\"dep\")".to_string()],
            source_not_contains: vec!["import value".to_string()],
            target_contains: vec!["import value".to_string(), "export default".to_string()],
            target_not_contains: vec!["require(\"dep\")".to_string()],
            passed: true,
        },
        lockstep_witness: TestMigrationLockstepWitness {
            lockstep_oracle_id: certificate.differential_witness.lockstep_oracle_id,
            fixture_corpus_digest: certificate.differential_witness.fixture_corpus_digest,
            proptest_seed: certificate.differential_witness.proptest_seed,
            fixture_cases: certificate.differential_witness.fixture_cases,
            proptest_cases: certificate.differential_witness.proptest_cases,
            effect_receipt_equivalence_cases: certificate
                .differential_witness
                .effect_receipt_equivalence_cases,
            effect_receipt_ids: vec!["evt-effect-1".to_string()],
            divergence_count: certificate.differential_witness.divergence_count,
            verdict: "pass".to_string(),
            lockstep_verdict_hash: String::new(),
        },
    };
    capsule.lockstep_witness.lockstep_verdict_hash = sdk_migration_lockstep_verdict_hash(&capsule);
    capsule
}

fn make_sdk_migration_equivalence_bundle(capsule: &TestMigrationEquivalenceCapsule) -> Vec<u8> {
    let replay_artifact_bytes = b"migration-replay-witness";
    let replay_artifact_path = "artifacts/replay.json".to_string();
    let capsule_artifact_bytes =
        serde_json::to_vec(capsule).expect("migration equivalence capsule serializes");
    let replay_payload_length =
        u64::try_from(replay_artifact_bytes.len()).expect("replay artifact length should fit u64");
    let capsule_payload_length = u64::try_from(capsule_artifact_bytes.len())
        .expect("capsule artifact length should fit u64");

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        replay_artifact_path.clone(),
        bundle::BundleArtifact {
            media_type: "application/json".to_string(),
            digest: bundle::hash(replay_artifact_bytes),
            bytes_hex: hex::encode(replay_artifact_bytes),
        },
    );
    artifacts.insert(
        MIGRATION_EQUIVALENCE_ARTIFACT_PATH.to_string(),
        bundle::BundleArtifact {
            media_type: "application/vnd.franken-node.migration-equivalence+json".to_string(),
            digest: bundle::hash(&capsule_artifact_bytes),
            bytes_hex: hex::encode(&capsule_artifact_bytes),
        },
    );

    let mut replay_bundle = bundle::ReplayBundle {
        header: bundle::BundleHeader {
            hash_algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            payload_length_bytes: replay_payload_length.saturating_add(capsule_payload_length),
            chunk_count: 2,
        },
        schema_version: bundle::REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
        sdk_version: SDK_VERSION.to_string(),
        bundle_id: "bundle-migcert-product-golden".to_string(),
        incident_id: "incident-migcert-product-golden".to_string(),
        created_at: "2026-06-15T00:00:00Z".to_string(),
        policy_version: "policy.migration-cert.v1".to_string(),
        verifier_identity: "verifier://alpha".to_string(),
        timeline: vec![
            bundle::TimelineEvent {
                sequence_number: 1,
                event_id: "evt-start".to_string(),
                timestamp: "2026-06-15T00:00:01Z".to_string(),
                event_type: "verification.started".to_string(),
                payload: json!({"phase": "migration_equivalence"}),
                state_snapshot: json!({"step": 1}),
                causal_parent: None,
                policy_version: "policy.migration-cert.v1".to_string(),
            },
            bundle::TimelineEvent {
                sequence_number: 2,
                event_id: "evt-effect-1".to_string(),
                timestamp: "2026-06-15T00:00:02Z".to_string(),
                event_type: bundle::EFFECT_RECEIPT_EVENT_TYPE.to_string(),
                payload: json!({"effect": "module_resolve", "result": "equivalent"}),
                state_snapshot: json!({"step": 2}),
                causal_parent: Some(1),
                policy_version: "policy.migration-cert.v1".to_string(),
            },
        ],
        initial_state_snapshot: json!({"migration_certificate": true}),
        evidence_refs: vec!["evidence://migration-cert/product-golden".to_string()],
        artifacts,
        chunks: vec![
            bundle::BundleChunk {
                chunk_index: 0,
                total_chunks: 2,
                artifact_path: replay_artifact_path,
                payload_length_bytes: replay_payload_length,
                payload_digest: bundle::hash(replay_artifact_bytes),
            },
            bundle::BundleChunk {
                chunk_index: 1,
                total_chunks: 2,
                artifact_path: MIGRATION_EQUIVALENCE_ARTIFACT_PATH.to_string(),
                payload_length_bytes: capsule_payload_length,
                payload_digest: bundle::hash(&capsule_artifact_bytes),
            },
        ],
        metadata: BTreeMap::from([(
            "artifact_kind".to_string(),
            "migration_equivalence".to_string(),
        )]),
        integrity_hash: String::new(),
        signature: bundle::BundleSignature {
            algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            signature_hex: String::new(),
        },
    };
    bundle::seal(&mut replay_bundle).expect("migration equivalence bundle seals");
    bundle::serialize(&replay_bundle).expect("migration equivalence bundle serializes")
}

fn assertion_passed(result: &frankenengine_verifier_sdk::VerificationResult, name: &str) -> bool {
    result
        .checked_assertions
        .iter()
        .any(|assertion| assertion.assertion == name && assertion.passed)
}

fn assertion_failed(result: &frankenengine_verifier_sdk::VerificationResult, name: &str) -> bool {
    result
        .checked_assertions
        .iter()
        .any(|assertion| assertion.assertion == name && !assertion.passed)
}

fn assert_lower_sha256_hex(value: &str, field: &str) {
    assert_eq!(value.len(), 64, "{field} should be 64 hex characters");
    assert!(
        value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
        "{field} should be lowercase SHA-256 hex: {value}"
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
fn behavioral_conformance_certificate_transcript_uses_stable_migcert_event_codes() {
    let certificate = generate_reference_behavioral_conformance_certificate();
    let validation = validate_behavioral_conformance_certificate(&certificate);
    assert!(validation.valid, "errors: {:?}", validation.errors);

    let transcript = json!([
        {
            "event_code": event_codes::FN_MIGCERT_GENERATED,
            "rule_id": certificate.rule_id,
            "schema_version": certificate.schema_version,
            "bound": certificate.bound,
        },
        {
            "event_code": event_codes::FN_MIGCERT_BOUND_VERIFIED,
            "coverage_ratio": certificate.bound.coverage.coverage_ratio,
            "covered_cases": certificate.bound.coverage.covered_cases,
            "total_cases": certificate.bound.coverage.total_cases,
        },
        {
            "event_code": event_codes::FN_MIGCERT_DIFFERENTIAL_WITNESS_VERIFIED,
            "lockstep_oracle_id": certificate.differential_witness.lockstep_oracle_id,
            "divergence_count": certificate.differential_witness.divergence_count,
            "effect_receipt_equivalence_cases": certificate
                .differential_witness
                .effect_receipt_equivalence_cases,
        },
        {
            "event_code": event_codes::FN_MIGCERT_SDK_CERTIFIED,
            "sdk_artifact": MIGRATION_EQUIVALENCE_ARTIFACT_PATH,
            "sdk_schema_version": MIGRATION_EQUIVALENCE_SCHEMA_VERSION,
        },
    ]);

    let events = transcript.as_array().expect("transcript must be an array");
    assert_eq!(events.len(), 4);
    assert_eq!(events[0]["event_code"], event_codes::FN_MIGCERT_GENERATED);
    assert_eq!(
        events[1]["event_code"],
        event_codes::FN_MIGCERT_BOUND_VERIFIED
    );
    assert_eq!(
        events[2]["event_code"],
        event_codes::FN_MIGCERT_DIFFERENTIAL_WITNESS_VERIFIED
    );
    assert_eq!(
        events[3]["event_code"],
        event_codes::FN_MIGCERT_SDK_CERTIFIED
    );
    assert_eq!(events[0]["bound"]["input_scope"][0]["count"], 128);
    assert_eq!(events[1]["coverage_ratio"], 1.0);
    assert_eq!(events[2]["divergence_count"], 0);
    assert_eq!(
        events[3]["sdk_artifact"],
        MIGRATION_EQUIVALENCE_ARTIFACT_PATH
    );
}

#[test]
fn behavioral_conformance_certificate_rejects_bound_and_witness_case_drift() {
    let mut bad_precondition = generate_reference_behavioral_conformance_certificate();
    bad_precondition.precondition_proof.clear();
    bad_precondition.content_hash =
        compute_behavioral_conformance_certificate_hash(&bad_precondition);
    let validation = validate_behavioral_conformance_certificate(&bad_precondition);
    assert!(!validation.valid);
    assert!(
        validation
            .errors
            .iter()
            .any(|error| error.contains("precondition_proof is required")),
        "expected machine-readable precondition proof error, got {:?}",
        validation.errors
    );

    let mut bad_case_total = generate_reference_behavioral_conformance_certificate();
    bad_case_total.bound.coverage.total_cases =
        bad_case_total.bound.coverage.total_cases.saturating_add(1);
    bad_case_total.content_hash = compute_behavioral_conformance_certificate_hash(&bad_case_total);
    let validation = validate_behavioral_conformance_certificate(&bad_case_total);
    assert!(!validation.valid);
    assert!(
        validation.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID)
                && error.contains("case total")
        }),
        "expected differential witness case-total error, got {:?}",
        validation.errors
    );

    let mut missing_effect_receipts = generate_reference_behavioral_conformance_certificate();
    missing_effect_receipts
        .differential_witness
        .effect_receipt_equivalence_cases = 0;
    missing_effect_receipts.differential_witness.witness_hash =
        compute_differential_witness_hash(&missing_effect_receipts.differential_witness);
    missing_effect_receipts.lockstep_verdict_hash = missing_effect_receipts
        .differential_witness
        .witness_hash
        .clone();
    missing_effect_receipts.content_hash =
        compute_behavioral_conformance_certificate_hash(&missing_effect_receipts);
    let validation = validate_behavioral_conformance_certificate(&missing_effect_receipts);
    assert!(!validation.valid);
    assert!(
        validation.errors.iter().any(|error| {
            error.contains(error_codes::ERR_MA_DIFFERENTIAL_WITNESS_INVALID)
                && error.contains("effect-receipt")
        }),
        "expected effect-receipt witness error, got {:?}",
        validation.errors
    );
}

#[test]
fn verifier_sdk_certifies_reference_migration_equivalence_bundle_offline() {
    let certificate = generate_reference_behavioral_conformance_certificate();
    let capsule = reference_sdk_equivalence_capsule();
    assert_ne!(
        certificate.lockstep_verdict_hash, capsule.lockstep_witness.lockstep_verdict_hash,
        "product certificate and SDK equivalence hashes use distinct domains"
    );
    assert_eq!(
        certificate.differential_witness.lockstep_oracle_id,
        capsule.lockstep_witness.lockstep_oracle_id
    );
    assert_eq!(
        certificate
            .differential_witness
            .effect_receipt_equivalence_cases,
        capsule.lockstep_witness.effect_receipt_equivalence_cases
    );

    let artifact = make_sdk_migration_equivalence_bundle(&capsule);
    let result = create_verifier_sdk("verifier://alpha")
        .verify_migration_artifact(&artifact)
        .expect("SDK should verify product migration-equivalence bundle");

    assert_eq!(result.verdict, VerificationVerdict::Pass);
    assert!(
        result
            .checked_assertions
            .iter()
            .all(|assertion| assertion.passed)
    );
    assert!(assertion_passed(
        &result,
        "migration_equivalence_capsule_present"
    ));
    assert!(assertion_passed(&result, "migration_source_ast_reparsed"));
    assert!(assertion_passed(&result, "migration_target_ast_reparsed"));
    assert!(assertion_passed(
        &result,
        "migration_precondition_rechecked"
    ));
    assert!(assertion_passed(
        &result,
        "migration_effect_receipt_refs_resolve"
    ));
    assert!(assertion_passed(
        &result,
        "migration_lockstep_verdict_hash_recomputed"
    ));
    assert_lower_sha256_hex(&result.artifact_binding_hash, "artifact_binding_hash");
}

#[test]
fn verifier_sdk_refuses_migration_bundle_when_precondition_does_not_hold() {
    let mut capsule = reference_sdk_equivalence_capsule();
    capsule
        .precondition
        .source_contains
        .push("require(\"missing-precondition\")".to_string());
    capsule.lockstep_witness.lockstep_verdict_hash = sdk_migration_lockstep_verdict_hash(&capsule);
    let artifact = make_sdk_migration_equivalence_bundle(&capsule);

    let result = create_verifier_sdk("verifier://alpha")
        .verify_migration_artifact(&artifact)
        .expect("SDK should return a signed failure result for precondition drift");

    assert_eq!(result.verdict, VerificationVerdict::Fail);
    assert!(assertion_failed(
        &result,
        "migration_precondition_rechecked"
    ));
    assert!(assertion_passed(
        &result,
        "migration_lockstep_verdict_hash_recomputed"
    ));
}

#[test]
fn verifier_sdk_refuses_behavior_changing_migration_witness() {
    let mut capsule = reference_sdk_equivalence_capsule();
    capsule.lockstep_witness.divergence_count = 1;
    capsule.lockstep_witness.verdict = "fail".to_string();
    capsule.lockstep_witness.lockstep_verdict_hash = sdk_migration_lockstep_verdict_hash(&capsule);
    let artifact = make_sdk_migration_equivalence_bundle(&capsule);

    let result = create_verifier_sdk("verifier://alpha")
        .verify_migration_artifact(&artifact)
        .expect("SDK should return a signed failure result for divergent witness");

    assert_eq!(result.verdict, VerificationVerdict::Fail);
    assert!(assertion_failed(
        &result,
        "migration_lockstep_zero_divergence"
    ));
    assert!(assertion_passed(
        &result,
        "migration_lockstep_verdict_hash_recomputed"
    ));
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
