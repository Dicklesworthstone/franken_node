use std::collections::BTreeMap;

use frankenengine_verifier_sdk::SDK_VERSION;
use frankenengine_verifier_sdk::bundle::{
    BundleArtifact, BundleChunk, BundleHeader, BundleSignature, REPLAY_BUNDLE_HASH_ALGORITHM,
    REPLAY_BUNDLE_SCHEMA_VERSION, ReplayBundle, TimelineEvent, hash, seal, serialize,
};
use frankenengine_verifier_sdk::capsule;
use frankenengine_verifier_sdk::{
    ValidationWorkflow, VerificationOperation, VerificationVerdict, VerifierSdkError,
    create_verifier_sdk,
};
use serde_json::json;

#[test]
fn verifier_sdk_facade_verifies_claim_artifact_trust_state_and_session() {
    let sdk = create_verifier_sdk("verifier://facade-test");

    let claim = capsule::build_reference_capsule();
    let claim_result = sdk
        .verify_claim(&claim)
        .expect("reference claim capsule should verify");
    assert_eq!(claim_result.verdict, VerificationVerdict::Pass);
    assert!(!claim_result.verifier_signature.is_empty());

    let trust_bundle = canonical_replay_bundle();
    let trust_bundle_bytes = serialize(&trust_bundle).expect("bundle should serialize");
    let migration_result = sdk
        .verify_migration_artifact(&trust_bundle_bytes)
        .expect("canonical replay bundle should verify as migration artifact");
    assert_eq!(migration_result.verdict, VerificationVerdict::Pass);

    let trust_result = sdk
        .verify_trust_state(&trust_bundle_bytes, &trust_bundle.integrity_hash)
        .expect("trust state should verify against matching anchor");
    assert_eq!(trust_result.verdict, VerificationVerdict::Pass);

    let mismatched_trust_result = sdk
        .verify_trust_state(&trust_bundle_bytes, &"0".repeat(64))
        .expect("valid trust bundle with mismatched anchor should produce fail verdict");
    assert_eq!(mismatched_trust_result.verdict, VerificationVerdict::Fail);

    let mut session = sdk.create_session("session-facade-001");
    let first_step = sdk
        .record_session_step(&mut session, &claim_result)
        .expect("first session step should append");
    assert_eq!(first_step.step_index, 0);
    let second_step = sdk
        .record_session_step(&mut session, &migration_result)
        .expect("second session step should append");
    assert_eq!(second_step.step_index, 1);

    let final_verdict = sdk
        .seal_session(&mut session)
        .expect("session should seal once");
    assert_eq!(final_verdict, VerificationVerdict::Pass);
    assert!(session.sealed);
    assert_eq!(session.final_verdict, Some(VerificationVerdict::Pass));

    let sealed_error = sdk
        .record_session_step(&mut session, &trust_result)
        .expect_err("sealed session should reject later steps");
    assert!(matches!(sealed_error, VerifierSdkError::SessionSealed(_)));
}

#[test]
fn verifier_sdk_facade_validates_bundles_workflows_and_transparency_log() {
    let sdk = create_verifier_sdk("verifier://facade-test");
    let bundle = canonical_replay_bundle();
    let bundle_bytes = serialize(&bundle).expect("bundle should serialize");

    sdk.validate_bundle(&bundle_bytes)
        .expect("canonical replay bundle should validate");
    let mut tampered_bundle = bundle_bytes.clone();
    let tamper_index = tampered_bundle
        .iter()
        .position(|byte| *byte == b'7')
        .expect("fixture should contain a tamperable byte");
    tampered_bundle[tamper_index] = b'8';
    assert!(sdk.validate_bundle(&tampered_bundle).is_err());

    for workflow in [
        ValidationWorkflow::ReleaseValidation,
        ValidationWorkflow::IncidentValidation,
        ValidationWorkflow::ComplianceAudit,
    ] {
        let workflow_result = sdk
            .execute_workflow(workflow, &bundle_bytes)
            .expect("workflow should execute against verified bundle");
        assert_eq!(workflow_result.operation, VerificationOperation::Workflow);
        assert_eq!(workflow_result.verdict, VerificationVerdict::Pass);
        assert!(
            workflow_result
                .checked_assertions
                .iter()
                .any(|assertion| assertion.assertion.starts_with("workflow_"))
        );
    }

    let workflow_result = sdk
        .execute_workflow(ValidationWorkflow::ReleaseValidation, &bundle_bytes)
        .expect("workflow should produce transparency-loggable result");
    let migration_result = sdk
        .verify_migration_artifact(&bundle_bytes)
        .expect("migration result should be loggable");
    let mut log = Vec::new();
    let first_entry = sdk
        .append_transparency_log(&mut log, &workflow_result)
        .expect("first transparency log append should succeed");
    assert_eq!(first_entry.merkle_proof[0], "0".repeat(64));
    assert_eq!(first_entry.verifier_id, "verifier://facade-test");

    let second_entry = sdk
        .append_transparency_log(&mut log, &migration_result)
        .expect("second transparency log append should succeed");
    assert_eq!(second_entry.merkle_proof[0], first_entry.result_hash);
    assert_eq!(log.len(), 2);

    let mut forged_result = workflow_result;
    forged_result.verifier_signature = "not-the-facade-signature".to_string();
    assert!(
        sdk.append_transparency_log(&mut log, &forged_result)
            .is_err()
    );
    assert_eq!(log.len(), 2);
}

fn canonical_replay_bundle() -> ReplayBundle {
    let evidence_json =
        br#"{"schema_version":"facade-test-v1","decision":"trust-state-anchor","epoch":7}"#;

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        "evidence/trust-state.json".to_string(),
        artifact("application/json", evidence_json),
    );
    let chunks = chunks_from_artifacts(&artifacts);

    let mut bundle = ReplayBundle {
        header: BundleHeader {
            hash_algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            payload_length_bytes: payload_length_bytes(&artifacts),
            chunk_count: chunks
                .len()
                .try_into()
                .expect("fixture chunk count should fit u32"),
        },
        schema_version: REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
        sdk_version: SDK_VERSION.to_string(),
        bundle_id: "facade-bundle-001".to_string(),
        incident_id: "facade-incident-001".to_string(),
        created_at: "2026-04-21T00:00:00.000000Z".to_string(),
        policy_version: "strict@2026-04-21".to_string(),
        verifier_identity: "sdk-facade-test".to_string(),
        timeline: vec![TimelineEvent {
            sequence_number: 1,
            event_id: "evt-facade-001".to_string(),
            timestamp: "2026-04-21T00:00:00.000001Z".to_string(),
            event_type: "trust_state_snapshot".to_string(),
            payload: json!({
                "anchor": "trust-state-anchor",
                "epoch": 7_u64
            }),
            state_snapshot: json!({
                "trust_state": "anchored",
                "epoch": 7_u64
            }),
            causal_parent: None,
            policy_version: "strict@2026-04-21".to_string(),
        }],
        initial_state_snapshot: json!({
            "baseline_epoch": 6_u64,
            "policy": "strict"
        }),
        evidence_refs: vec!["evidence/trust-state.json".to_string()],
        artifacts,
        chunks,
        metadata: BTreeMap::new(),
        integrity_hash: String::new(),
        signature: BundleSignature {
            algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            signature_hex: String::new(),
        },
    };
    seal(&mut bundle).expect("fixture should seal");
    bundle
}

fn artifact(media_type: &str, bytes: &[u8]) -> BundleArtifact {
    BundleArtifact {
        media_type: media_type.to_string(),
        digest: hash(bytes),
        bytes_hex: hex_encode(bytes),
    }
}

fn chunks_from_artifacts(artifacts: &BTreeMap<String, BundleArtifact>) -> Vec<BundleChunk> {
    let total_chunks = artifacts
        .len()
        .try_into()
        .expect("fixture chunk count should fit u32");
    artifacts
        .iter()
        .enumerate()
        .map(|(index, (path, artifact))| BundleChunk {
            chunk_index: index
                .try_into()
                .expect("fixture chunk index should fit u32"),
            total_chunks,
            artifact_path: path.clone(),
            payload_length_bytes: u64::try_from(artifact.bytes_hex.len() / 2)
                .expect("fixture artifact length should fit u64"),
            payload_digest: artifact.digest.clone(),
        })
        .collect()
}

fn payload_length_bytes(artifacts: &BTreeMap<String, BundleArtifact>) -> u64 {
    artifacts
        .values()
        .map(|artifact| {
            u64::try_from(artifact.bytes_hex.len() / 2)
                .expect("fixture artifact length should fit u64")
        })
        .sum()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
