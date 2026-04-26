//! Product-level conformance harness for the verifier SDK public API fixtures.
//!
//! Coverage matrix:
//! - MUST: `VerificationResult` golden fixture round-trips under the live serde contract
//! - MUST: `SessionStep` golden fixture round-trips under the live serde contract
//! - MUST: `TransparencyLogEntry` golden fixture round-trips under the live serde contract
//! - MUST: live facade/session/transparency outputs preserve the documented public invariants

use std::collections::BTreeMap;

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use frankenengine_verifier_sdk::{
    SDK_VERSION, SessionStep, TransparencyLogEntry, VerificationOperation, VerificationResult,
    VerificationVerdict, bundle, capsule, create_verifier_sdk,
};

const FACADE_RESULT_FIXTURE: &str =
    include_str!("../../../sdk/verifier/tests/fixtures/public_api/facade_result.json");
const SESSION_STEP_FIXTURE: &str =
    include_str!("../../../sdk/verifier/tests/fixtures/public_api/session_step.json");
const TRANSPARENCY_ENTRY_FIXTURE: &str =
    include_str!("../../../sdk/verifier/tests/fixtures/public_api/transparency_entry.json");

fn reference_capsule() -> capsule::ReplayCapsule {
    let mut inputs = BTreeMap::new();
    inputs.insert("artifact_a".to_string(), "content_of_a".to_string());
    inputs.insert("artifact_b".to_string(), "content_of_b".to_string());

    let payload = "reference_payload_data".to_string();
    let expected_output_hash = {
        let mut payload_bytes = Vec::new();
        payload_bytes.extend_from_slice(&u64::try_from(payload.len()).unwrap_or(u64::MAX).to_le_bytes());
        payload_bytes.extend_from_slice(payload.as_bytes());

        let mut input_bytes = Vec::new();
        for (key, value) in &inputs {
            input_bytes.extend_from_slice(&u64::try_from(key.len()).unwrap_or(u64::MAX).to_le_bytes());
            input_bytes.extend_from_slice(key.as_bytes());
            input_bytes.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
            input_bytes.extend_from_slice(value.as_bytes());
        }

        bundle::hash(&[payload_bytes, input_bytes].concat())
    };

    let manifest = capsule::CapsuleManifest {
        schema_version: SDK_VERSION.to_string(),
        capsule_id: "capsule-ref-001".to_string(),
        description: "Reference capsule for testing".to_string(),
        claim_type: "migration_safety".to_string(),
        input_refs: vec!["artifact_a".to_string(), "artifact_b".to_string()],
        expected_output_hash,
        created_at: "2026-02-21T00:00:00Z".to_string(),
        creator_identity: "creator://test@example.com".to_string(),
        metadata: BTreeMap::new(),
    };

    let mut capsule = capsule::ReplayCapsule {
        manifest,
        payload,
        inputs,
        signature: String::new(),
    };
    capsule::sign_capsule(&mut capsule);
    capsule
}

fn parse_fixture_value(raw: &str, fixture_name: &str) -> Value {
    serde_json::from_str(raw)
        .unwrap_or_else(|err| panic!("failed to parse {fixture_name} fixture as JSON: {err}"))
}

fn assert_fixture_round_trip<T>(raw: &str, fixture_name: &str) -> T
where
    T: DeserializeOwned + Serialize + std::fmt::Debug,
{
    let expected_value = parse_fixture_value(raw, fixture_name);
    let parsed: T = serde_json::from_value(expected_value.clone())
        .unwrap_or_else(|err| panic!("failed to deserialize {fixture_name} fixture: {err}"));
    let round_tripped = serde_json::to_value(&parsed)
        .unwrap_or_else(|err| panic!("failed to serialize {fixture_name} fixture: {err}"));
    assert_eq!(
        round_tripped, expected_value,
        "{fixture_name} fixture drifted from the live serde contract"
    );
    parsed
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn assert_rfc3339_timestamp(value: &str, context: &str) {
    chrono::DateTime::parse_from_rfc3339(value)
        .unwrap_or_else(|err| panic!("{context} must be RFC3339: {err}"));
}

fn assert_merkle_proof_shape(entry: &TransparencyLogEntry, context: &str) {
    assert!(
        entry.merkle_proof.len() >= 3,
        "{context} must include root, leaf_index, and tree_size proof segments"
    );

    let root = entry.merkle_proof[0]
        .strip_prefix("root:")
        .unwrap_or_else(|| panic!("{context} merkle_proof[0] must start with root:"));
    assert!(
        is_lower_hex_digest(root),
        "{context} merkle root must be a bare lowercase 64-hex digest"
    );

    entry.merkle_proof[1]
        .strip_prefix("leaf_index:")
        .unwrap_or_else(|| panic!("{context} merkle_proof[1] must start with leaf_index:"))
        .parse::<usize>()
        .unwrap_or_else(|err| panic!("{context} leaf_index must parse as usize: {err}"));

    entry.merkle_proof[2]
        .strip_prefix("tree_size:")
        .unwrap_or_else(|| panic!("{context} merkle_proof[2] must start with tree_size:"))
        .parse::<usize>()
        .unwrap_or_else(|err| panic!("{context} tree_size must parse as usize: {err}"));

    for step in &entry.merkle_proof[3..] {
        let digest = step
            .strip_prefix("left:")
            .or_else(|| step.strip_prefix("right:"))
            .unwrap_or_else(|| {
                panic!("{context} sibling proof steps must start with left: or right:")
            });
        assert!(
            is_lower_hex_digest(digest),
            "{context} sibling proof digest must be a bare lowercase 64-hex digest"
        );
    }
}

#[test]
fn sdk_verifier_public_api_golden_conformance() {
    let facade: VerificationResult =
        assert_fixture_round_trip(FACADE_RESULT_FIXTURE, "facade_result");
    assert_eq!(facade.operation, VerificationOperation::Claim);
    assert_eq!(facade.verdict, VerificationVerdict::Pass);
    assert!((0.0..=1.0).contains(&facade.confidence_score));
    assert!(!facade.checked_assertions.is_empty());
    assert_eq!(facade.verifier_identity, "verifier://facade-test");
    assert_eq!(facade.sdk_version, SDK_VERSION);
    assert!(is_lower_hex_digest(&facade.artifact_binding_hash));
    assert!(is_lower_hex_digest(&facade.verifier_signature));
    assert_rfc3339_timestamp(
        &facade.execution_timestamp,
        "facade_result execution_timestamp",
    );
    let facade_value = parse_fixture_value(FACADE_RESULT_FIXTURE, "facade_result");
    assert!(
        facade_value.get("result_origin_nonce").is_none(),
        "facade_result must not expose the private result_origin_nonce field"
    );

    let step: SessionStep = assert_fixture_round_trip(SESSION_STEP_FIXTURE, "session_step");
    assert_eq!(step.step_index, 1);
    assert_eq!(step.operation, VerificationOperation::Claim);
    assert_eq!(step.verdict, VerificationVerdict::Pass);
    assert!(is_lower_hex_digest(&step.artifact_binding_hash));
    assert!(is_lower_hex_digest(&step.step_signature));
    assert_rfc3339_timestamp(&step.timestamp, "session_step timestamp");

    let entry: TransparencyLogEntry =
        assert_fixture_round_trip(TRANSPARENCY_ENTRY_FIXTURE, "transparency_entry");
    assert_eq!(entry.verifier_id, "verifier://facade-test");
    assert!(is_lower_hex_digest(&entry.result_hash));
    assert_rfc3339_timestamp(&entry.timestamp, "transparency_entry timestamp");
    assert_merkle_proof_shape(&entry, "transparency_entry");
}

#[test]
fn sdk_verifier_public_api_live_contract_invariants() {
    let sdk = create_verifier_sdk("verifier://shape-test");
    let result = sdk
        .verify_claim(&reference_capsule())
        .expect("reference capsule verification should succeed");

    assert_eq!(result.operation, VerificationOperation::Claim);
    assert_eq!(result.verdict, VerificationVerdict::Pass);
    assert_eq!(result.verifier_identity, "verifier://shape-test");
    assert_eq!(result.sdk_version, SDK_VERSION);
    assert!(is_lower_hex_digest(&result.artifact_binding_hash));
    assert!(is_lower_hex_digest(&result.verifier_signature));
    assert_rfc3339_timestamp(
        &result.execution_timestamp,
        "live result execution_timestamp",
    );

    let result_json = serde_json::to_value(&result).expect("result should serialize to JSON");
    assert!(
        result_json
            .get("checked_assertions")
            .and_then(Value::as_array)
            .is_some_and(|assertions| !assertions.is_empty()),
        "live result must contain at least one checked assertion"
    );
    assert!(
        result_json.get("result_origin_nonce").is_none(),
        "live result must not expose the private result_origin_nonce field"
    );

    let mut session = sdk
        .create_session("session-shape-test")
        .expect("session creation should succeed");
    let step = sdk
        .record_session_step(&mut session, &result)
        .expect("session should accept a result from the same verifier");
    assert_eq!(step.step_index, 0);
    assert_eq!(step.operation, result.operation);
    assert_eq!(step.verdict, result.verdict);
    assert_eq!(step.artifact_binding_hash, result.artifact_binding_hash);
    assert!(is_lower_hex_digest(&step.step_signature));
    assert_rfc3339_timestamp(&step.timestamp, "live session_step timestamp");
    assert_eq!(session.steps(), [step.clone()]);

    let mut log = Vec::new();
    let entry = sdk
        .append_transparency_log(&mut log, &result)
        .expect("transparency append should succeed");
    assert_eq!(entry.verifier_id, result.verifier_identity);
    assert!(is_lower_hex_digest(&entry.result_hash));
    assert_rfc3339_timestamp(&entry.timestamp, "live transparency_entry timestamp");
    assert_eq!(entry.merkle_proof[1], "leaf_index:0");
    assert_eq!(entry.merkle_proof[2], "tree_size:1");
    assert_merkle_proof_shape(&entry, "live transparency_entry");
    assert_eq!(log, vec![entry]);

    let verdict = sdk
        .seal_session(&mut session)
        .expect("session sealing should succeed");
    assert_eq!(verdict, VerificationVerdict::Pass);
    assert!(session.sealed);
    assert_eq!(session.final_verdict, Some(VerificationVerdict::Pass));
}
