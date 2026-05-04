//! Product-level conformance harness for the verifier SDK public API fixtures.
//!
//! Coverage matrix:
//! - MUST: `VerificationResult` golden fixture round-trips under the live serde contract
//! - MUST: `SessionStep` golden fixture round-trips under the live serde contract
//! - MUST: `TransparencyLogEntry` golden fixture round-trips under the live serde contract
//! - MUST: live facade/session/transparency outputs preserve the documented public invariants

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::Digest;

#[cfg(feature = "verifier-tools")]
use frankenengine_node::sdk::{
    replay_capsule::{
        CapsuleInput as NodeCapsuleInput, EnvironmentSnapshot as NodeEnvironmentSnapshot,
        create_capsule as create_node_capsule,
    },
    verifier_sdk::{
        STRUCTURAL_ONLY_SECURITY_POSTURE as NODE_STRUCTURAL_ONLY_SECURITY_POSTURE,
        VerificationReport as NodeVerificationReport,
        VerificationRequest as NodeVerificationRequest, VerifierConfig as NodeVerifierConfig,
        VerifierSdk as NodeVerifierSdk, VerifyVerdict as NodeVerifyVerdict,
    },
};
use frankenengine_verifier_sdk::{
    SDK_VERSION, SessionStep, TransparencyLogEntry, VerificationOperation, VerificationResult,
    VerificationVerdict, capsule, create_verifier_sdk,
};

const FACADE_RESULT_FIXTURE: &str =
    include_str!("../../../sdk/verifier/tests/fixtures/public_api/facade_result.json");
const SESSION_STEP_FIXTURE: &str =
    include_str!("../../../sdk/verifier/tests/fixtures/public_api/session_step.json");
const TRANSPARENCY_ENTRY_FIXTURE: &str =
    include_str!("../../../sdk/verifier/tests/fixtures/public_api/transparency_entry.json");
#[cfg(feature = "verifier-tools")]
const NODE_CAPSULE_BYTES_PER_COUNT_UNIT: usize = 1024;
#[cfg(feature = "verifier-tools")]
const NODE_CLAIM_TOTAL_BYTES_PER_COUNT_UNIT: usize = 1024;
#[cfg(feature = "verifier-tools")]
const NODE_CLAIM_BYTES_PER_CLAIM_LIMIT: usize = 4096;
#[cfg(feature = "verifier-tools")]
const NODE_VERIFIER_SDK_SOURCE: &str = include_str!("../src/sdk/verifier_sdk.rs");

#[cfg(feature = "verifier-tools")]
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(feature = "verifier-tools")]
fn legacy_artifact_id_hash(artifact_id: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"verifier_sdk_v1:");
    hasher.update(artifact_id.as_bytes());
    hex::encode(hasher.finalize())
}

fn reference_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7_u8; 32])
}

fn reference_verifying_key() -> VerifyingKey {
    VerifyingKey::from(&reference_signing_key())
}

fn expected_replay_hash(payload: &str, inputs: &BTreeMap<String, String>) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"verifier_sdk_capsule_replay_v1:");
    hasher.update(
        u64::try_from(payload.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(payload.as_bytes());
    hasher.update(
        u64::try_from(inputs.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (key, value) in inputs {
        hasher.update(u64::try_from(key.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(key.as_bytes());
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn reference_capsule() -> capsule::ReplayCapsule {
    let mut inputs = BTreeMap::new();
    inputs.insert("artifact_a".to_string(), "content_of_a".to_string());
    inputs.insert("artifact_b".to_string(), "content_of_b".to_string());

    let payload = "reference_payload_data".to_string();
    let expected_output_hash = expected_replay_hash(&payload, &inputs);

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
    let signing_key = reference_signing_key();
    capsule::sign_capsule(&signing_key, &mut capsule);
    capsule
}

#[cfg(feature = "verifier-tools")]
fn node_verifier_sdk_with_capsule_count(max_capsule_count: usize) -> NodeVerifierSdk {
    NodeVerifierSdk::new(NodeVerifierConfig {
        verifier_identity: "verifier://node-sdk-capacity-test".to_string(),
        require_hash_match: true,
        strict_claims: true,
        max_claims_per_request: 1000,
        max_capsule_count,
        max_chain_depth: 64,
        extensions: BTreeMap::new(),
    })
}

#[cfg(feature = "verifier-tools")]
fn node_verifier_sdk_with_claim_count(max_claims_per_request: usize) -> NodeVerifierSdk {
    NodeVerifierSdk::new(NodeVerifierConfig {
        verifier_identity: "verifier://node-sdk-claim-capacity-test".to_string(),
        require_hash_match: true,
        strict_claims: true,
        max_claims_per_request,
        max_capsule_count: 1000,
        max_chain_depth: 64,
        extensions: BTreeMap::new(),
    })
}

#[cfg(feature = "verifier-tools")]
fn reference_node_capsule() -> frankenengine_node::sdk::replay_capsule::ReplayCapsule {
    let inputs = vec![
        NodeCapsuleInput {
            seq: 0,
            data: b"input-0".to_vec(),
            metadata: BTreeMap::new(),
        },
        NodeCapsuleInput {
            seq: 1,
            data: b"input-1".to_vec(),
            metadata: BTreeMap::new(),
        },
    ];

    create_node_capsule(
        "node-capsule-ref-001",
        inputs,
        NodeEnvironmentSnapshot {
            runtime_version: "1.0.0".to_string(),
            platform: "linux-x86_64".to_string(),
            config_hash: "aabb".repeat(8),
            properties: BTreeMap::new(),
        },
    )
    .expect("node replay capsule should be valid")
}

#[cfg(feature = "verifier-tools")]
fn assert_node_capsule_byte_capacity_failed_before_replay(report: &NodeVerificationReport) {
    assert!(matches!(report.verdict, NodeVerifyVerdict::Fail(_)));
    let failed = report
        .evidence
        .iter()
        .filter(|entry| !entry.passed)
        .map(|entry| entry.check_name.as_str())
        .collect::<Vec<_>>();
    assert!(failed.contains(&"capsule_byte_capacity_check"));
    assert!(failed.contains(&"capsule_replay_skipped_due_to_capacity"));
    assert!(
        !report
            .evidence
            .iter()
            .any(|entry| entry.check_name == "replay_deterministic_match"),
        "node verifier SDK must not replay an oversized capsule"
    );
}

#[cfg(feature = "verifier-tools")]
fn assert_node_claim_capacity_failed_before_binding(
    report: &NodeVerificationReport,
    expected_failure: &str,
) {
    assert!(matches!(report.verdict, NodeVerifyVerdict::Fail(_)));
    let failed = report
        .evidence
        .iter()
        .filter(|entry| !entry.passed)
        .map(|entry| entry.check_name.as_str())
        .collect::<Vec<_>>();
    assert!(failed.contains(&expected_failure));
    assert!(failed.contains(&"claims_skipped_due_to_capacity"));
    assert!(
        !report
            .evidence
            .iter()
            .any(|entry| entry.check_name.starts_with("claim_")),
        "node verifier SDK must not run per-claim checks after claim capacity fails"
    );
    assert!(
        !report
            .evidence
            .iter()
            .any(|entry| entry.check_name == "artifact_content_hash_match"),
        "node verifier SDK must not run artifact content hash verification after claim capacity fails"
    );
}

fn replay_capsule_from_ordered_inputs(
    input_pairs: &[(&str, &str)],
    input_refs: Vec<String>,
) -> capsule::ReplayCapsule {
    let inputs = input_pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect::<BTreeMap<_, _>>();

    let payload = "reference_payload_data".to_string();
    let manifest = capsule::CapsuleManifest {
        schema_version: SDK_VERSION.to_string(),
        capsule_id: "capsule-metamorphic-input-order".to_string(),
        description: "Metamorphic replay input ordering capsule".to_string(),
        claim_type: "migration_safety".to_string(),
        input_refs,
        expected_output_hash: expected_replay_hash(&payload, &inputs),
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
    capsule::sign_capsule(&reference_signing_key(), &mut capsule);
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

#[cfg(feature = "verifier-tools")]
#[test]
fn node_verifier_sdk_rejects_oversized_capsule_bytes_before_replay() {
    let sdk = node_verifier_sdk_with_capsule_count(4);
    let mut capsule = reference_node_capsule();
    capsule.inputs[0].data = vec![0x42; NODE_CAPSULE_BYTES_PER_COUNT_UNIT * 4];

    let report = sdk
        .verify_capsule(&capsule)
        .expect("oversized capsule should produce a fail-closed report");

    assert_node_capsule_byte_capacity_failed_before_replay(&report);
    let component_capacity = report
        .evidence
        .iter()
        .find(|entry| entry.check_name == "capsule_capacity_check")
        .expect("component capacity evidence should be present");
    assert!(
        component_capacity.passed,
        "raw byte growth should fail the byte cap even when component count is in bounds"
    );

    let sdk = node_verifier_sdk_with_capsule_count(5);
    let mut capsule = reference_node_capsule();
    capsule.inputs[0].metadata.insert(
        "input-metadata".to_string(),
        "x".repeat(NODE_CAPSULE_BYTES_PER_COUNT_UNIT * 3),
    );
    capsule.environment.properties.insert(
        "environment-property".to_string(),
        "y".repeat(NODE_CAPSULE_BYTES_PER_COUNT_UNIT * 3),
    );

    let report = sdk
        .verify_capsule(&capsule)
        .expect("oversized metadata should produce a fail-closed report");

    assert_node_capsule_byte_capacity_failed_before_replay(&report);
}

#[cfg(feature = "verifier-tools")]
#[test]
fn node_verifier_sdk_rejects_oversized_claim_bytes_before_binding() {
    let sdk = node_verifier_sdk_with_claim_count(10);
    let artifact_id = "node-oversized-single-claim".to_string();
    let request = NodeVerificationRequest {
        artifact_hash: {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"verifier_sdk_v1:");
            hasher.update(
                u64::try_from(artifact_id.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
            hasher.update(artifact_id.as_bytes());
            hex::encode(hasher.finalize())
        },
        artifact_id,
        claims: vec!["x".repeat(NODE_CLAIM_BYTES_PER_CLAIM_LIMIT + 1)],
    };

    let report = sdk
        .verify_artifact(&request)
        .expect("oversized claim should produce a fail-closed report");

    assert_node_claim_capacity_failed_before_binding(
        &report,
        "claims_per_claim_byte_capacity_check",
    );
    let count_capacity = report
        .evidence
        .iter()
        .find(|entry| entry.check_name == "claims_capacity_check")
        .expect("claim count capacity evidence should be present");
    assert!(count_capacity.passed);
    let total_capacity = report
        .evidence
        .iter()
        .find(|entry| entry.check_name == "claims_total_byte_capacity_check")
        .expect("total claim byte capacity evidence should be present");
    assert!(total_capacity.passed);

    let sdk = node_verifier_sdk_with_claim_count(4);
    let artifact_id = "node-oversized-total-claims".to_string();
    let request = NodeVerificationRequest {
        artifact_hash: {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"verifier_sdk_v1:");
            hasher.update(
                u64::try_from(artifact_id.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
            hasher.update(artifact_id.as_bytes());
            hex::encode(hasher.finalize())
        },
        artifact_id,
        claims: vec!["a".repeat(3000), "b".repeat(3000)],
    };

    let report = sdk
        .verify_artifact(&request)
        .expect("oversized claim set should produce a fail-closed report");

    assert_node_claim_capacity_failed_before_binding(&report, "claims_total_byte_capacity_check");
    let per_claim_capacity = report
        .evidence
        .iter()
        .find(|entry| entry.check_name == "claims_per_claim_byte_capacity_check")
        .expect("per-claim byte capacity evidence should be present");
    assert!(per_claim_capacity.passed);
    let expected_total_limit = NODE_CLAIM_TOTAL_BYTES_PER_COUNT_UNIT * 4;
    let total_capacity = report
        .evidence
        .iter()
        .find(|entry| entry.check_name == "claims_total_byte_capacity_check")
        .expect("total claim byte capacity evidence should be present");
    assert!(
        total_capacity
            .detail
            .contains(&format!("limit of {expected_total_limit}")),
        "total capacity evidence should expose the bounded byte limit"
    );
}

#[cfg(feature = "verifier-tools")]
#[test]
fn node_verifier_sdk_artifact_hash_verification_uses_content_bytes() {
    let sdk = NodeVerifierSdk::with_defaults();
    let artifact_id = "node-content-hash-artifact";
    let artifact_bytes = b"real artifact bytes whose digest is the integrity input";
    let content_hash = sha256_hex(artifact_bytes);

    let request = NodeVerificationRequest {
        artifact_id: artifact_id.to_string(),
        artifact_hash: content_hash,
        claims: vec!["content-hash-bound".to_string()],
    };

    let report = sdk
        .verify_artifact_bytes(&request, artifact_bytes)
        .expect("content-backed verification should produce a report");
    assert_eq!(report.verdict, NodeVerifyVerdict::Pass);
    let content_hash_evidence = report
        .evidence
        .iter()
        .find(|entry| entry.check_name == "artifact_content_hash_match")
        .expect("content hash evidence must be present");
    assert!(content_hash_evidence.passed);

    let legacy_id_bound_request = NodeVerificationRequest {
        artifact_id: artifact_id.to_string(),
        artifact_hash: legacy_artifact_id_hash(artifact_id),
        claims: vec!["content-hash-bound".to_string()],
    };
    let legacy_report = sdk
        .verify_artifact_bytes(&legacy_id_bound_request, artifact_bytes)
        .expect("legacy id-bound hash should produce a fail report");
    assert!(matches!(legacy_report.verdict, NodeVerifyVerdict::Fail(_)));
    assert!(
        legacy_report
            .evidence
            .iter()
            .any(|entry| entry.check_name == "artifact_content_hash_match" && !entry.passed),
        "old artifact-id-derived hashes must not satisfy content hash verification"
    );

    let metadata_only_report = sdk
        .verify_artifact(&request)
        .expect("metadata-only verification should fail closed with a report");
    assert!(matches!(
        metadata_only_report.verdict,
        NodeVerifyVerdict::Fail(_)
    ));
    let metadata_only_hash_evidence = metadata_only_report
        .evidence
        .iter()
        .find(|entry| entry.check_name == "artifact_content_hash_match")
        .expect("metadata-only call should explain missing artifact bytes");
    assert!(!metadata_only_hash_evidence.passed);
    assert!(
        metadata_only_hash_evidence
            .detail
            .contains("artifact bytes not provided")
    );
}

#[cfg(feature = "verifier-tools")]
#[test]
fn node_verifier_sdk_report_set_validation_declares_structural_only_scope() {
    let sdk = NodeVerifierSdk::with_defaults();
    let first_bytes = b"first independent artifact";
    let second_bytes = b"second independent artifact";
    let first_request = NodeVerificationRequest {
        artifact_id: "node-report-set-first".to_string(),
        artifact_hash: sha256_hex(first_bytes),
        claims: vec!["structural-set-member".to_string()],
    };
    let second_request = NodeVerificationRequest {
        artifact_id: "node-report-set-second".to_string(),
        artifact_hash: sha256_hex(second_bytes),
        claims: vec!["structural-set-member".to_string()],
    };
    let first_report = sdk
        .verify_artifact_bytes(&first_request, first_bytes)
        .expect("first report should verify");
    let second_report = sdk
        .verify_artifact_bytes(&second_request, second_bytes)
        .expect("second report should verify");

    let report_set = sdk
        .verify_report_set_uniqueness(&[first_report, second_report])
        .expect("report-set validation should produce evidence");

    assert_eq!(
        NODE_STRUCTURAL_ONLY_SECURITY_POSTURE,
        "structural_only_not_replacement_critical"
    );
    assert_eq!(report_set.verdict, NodeVerifyVerdict::Pass);
    assert!(report_set.request_id.starts_with("vrps-"));
    let scope = report_set
        .evidence
        .iter()
        .find(|entry| entry.check_name == "report_set_structural_scope")
        .expect("report-set validation must declare its structural-only scope");
    assert!(scope.passed);
    assert!(
        scope
            .detail
            .contains("structural-only report-set validation")
    );
    assert!(scope.detail.contains("no predecessor hash"));
    assert!(scope.detail.contains("signature verification"));

    assert!(NODE_VERIFIER_SDK_SOURCE.contains("pub fn verify_report_set_uniqueness("));
    assert!(!NODE_VERIFIER_SDK_SOURCE.contains("pub fn verify_chain("));
    assert!(
        !NODE_VERIFIER_SDK_SOURCE
            .contains("Verify a chain of verification reports for consistency and integrity")
    );
    assert!(
        !NODE_VERIFIER_SDK_SOURCE
            .contains("Hash-chain: each report's binding_hash should reference its own input")
    );
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
    let verifying_key = reference_verifying_key();
    let result = sdk
        .verify_claim(&verifying_key, &reference_capsule())
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

#[test]
fn sdk_verifier_replay_capsule_input_order_metamorphic_relation() {
    let verifying_key = reference_verifying_key();
    let forward = replay_capsule_from_ordered_inputs(
        &[
            ("artifact_a", "content_of_a"),
            ("artifact_b", "content_of_b"),
            ("artifact_c", "content_of_c"),
        ],
        vec![
            "artifact_a".to_string(),
            "artifact_b".to_string(),
            "artifact_c".to_string(),
        ],
    );
    let reversed = replay_capsule_from_ordered_inputs(
        &[
            ("artifact_c", "content_of_c"),
            ("artifact_b", "content_of_b"),
            ("artifact_a", "content_of_a"),
        ],
        vec![
            "artifact_c".to_string(),
            "artifact_b".to_string(),
            "artifact_a".to_string(),
        ],
    );

    let forward_result = capsule::replay(&verifying_key, &forward, "verifier://metamorphic")
        .expect("forward capsule should replay");
    let reversed_result = capsule::replay(&verifying_key, &reversed, "verifier://metamorphic")
        .expect("reversed capsule should replay");

    assert_eq!(forward_result.verdict, capsule::CapsuleVerdict::Pass);
    assert_eq!(reversed_result.verdict, capsule::CapsuleVerdict::Pass);
    assert_eq!(
        forward_result.actual_hash, reversed_result.actual_hash,
        "equivalent input maps must have an insertion-order-invariant replay hash"
    );
    assert_eq!(
        forward_result.expected_hash, reversed_result.expected_hash,
        "expected replay hash must canonicalize equivalent input maps"
    );

    let mut perturbed = forward.clone();
    perturbed
        .inputs
        .insert("artifact_b".to_string(), "content_of_b_changed".to_string());
    capsule::sign_capsule(&reference_signing_key(), &mut perturbed);
    let perturbed_result = capsule::replay(&verifying_key, &perturbed, "verifier://metamorphic")
        .expect("value-perturbed capsule should still produce a replay verdict");

    assert_eq!(perturbed_result.verdict, capsule::CapsuleVerdict::Fail);
    assert_eq!(perturbed_result.expected_hash, forward_result.expected_hash);
    assert_ne!(
        perturbed_result.actual_hash, forward_result.actual_hash,
        "changing an input value must perturb the replay hash"
    );
}
