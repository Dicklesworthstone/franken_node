//! Conformance test for the verifier SDK session monotonicity invariant.
//!
//! Exercises the live public facade instead of a copied session model. The
//! harness proves that session steps are appended by SDK methods, sealed
//! sessions fail closed, and empty sessions seal to an inconclusive verdict.

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::Digest;

use frankenengine_verifier_sdk::{
    SDK_VERSION, VerificationResult, VerificationVerdict, VerifierSdkError, capsule,
    create_verifier_sdk,
};

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
        description: "Reference capsule for session monotonicity conformance".to_string(),
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
    capsule::sign_capsule(&reference_signing_key(), &mut capsule);
    capsule
}

fn passing_claim_result(verifier_identity: &str) -> VerificationResult {
    let sdk = create_verifier_sdk(verifier_identity);
    sdk.verify_claim(&reference_verifying_key(), &reference_capsule())
        .expect("reference capsule should verify")
}

#[test]
fn session_steps_are_appended_with_monotonic_indices() {
    let sdk = create_verifier_sdk("verifier://session-monotonic");
    let result = passing_claim_result("verifier://session-monotonic");
    let mut session = sdk
        .create_session("session-monotonic-indices")
        .expect("valid session id should create a session");

    let first = sdk
        .record_session_step(&mut session, &result)
        .expect("first step should append");
    let second = sdk
        .record_session_step(&mut session, &result)
        .expect("second step should append");

    assert_eq!(first.step_index, 0);
    assert_eq!(second.step_index, 1);
    assert_eq!(session.steps(), [first.clone(), second.clone()]);
    assert_eq!(session.steps()[0].verdict, VerificationVerdict::Pass);
    assert_eq!(
        session.steps()[1].artifact_binding_hash,
        result.artifact_binding_hash
    );
    assert!(!session.steps()[0].step_signature.is_empty());
    assert!(!session.steps()[1].step_signature.is_empty());
    assert!(!session.sealed);
    assert_eq!(session.final_verdict, None);
}

#[test]
fn sealed_session_rejects_new_steps_without_appending() {
    let sdk = create_verifier_sdk("verifier://session-sealed");
    let result = passing_claim_result("verifier://session-sealed");
    let mut session = sdk
        .create_session("session-sealed-rejects-new-steps")
        .expect("valid session id should create a session");

    sdk.record_session_step(&mut session, &result)
        .expect("pre-seal step should append");
    let verdict = sdk
        .seal_session(&mut session)
        .expect("session with one passing step should seal");

    assert_eq!(verdict, VerificationVerdict::Pass);
    assert!(session.sealed);
    assert_eq!(session.final_verdict, Some(VerificationVerdict::Pass));

    let err = sdk
        .record_session_step(&mut session, &result)
        .expect_err("sealed session must reject additional steps");

    assert_eq!(
        err,
        VerifierSdkError::SessionSealed(session.session_id.clone())
    );
    assert_eq!(session.steps().len(), 1);
}

#[test]
fn empty_session_seals_inconclusive() {
    let sdk = create_verifier_sdk("verifier://session-empty");
    let mut session = sdk
        .create_session("session-empty-inconclusive")
        .expect("valid session id should create a session");

    let verdict = sdk
        .seal_session(&mut session)
        .expect("empty session should still seal");

    assert_eq!(verdict, VerificationVerdict::Inconclusive);
    assert!(session.sealed);
    assert_eq!(
        session.final_verdict,
        Some(VerificationVerdict::Inconclusive)
    );
    assert!(session.steps().is_empty());
}

#[test]
fn foreign_verifier_result_is_rejected_without_appending() {
    let sdk = create_verifier_sdk("verifier://session-alpha");
    let foreign_result = passing_claim_result("verifier://session-beta");
    let mut session = sdk
        .create_session("session-foreign-result")
        .expect("valid session id should create a session");

    let err = sdk
        .record_session_step(&mut session, &foreign_result)
        .expect_err("foreign verifier result must not append to this session");

    assert!(
        matches!(
            err,
            VerifierSdkError::ResultOriginMismatch { .. }
                | VerifierSdkError::SessionVerifierMismatch { .. }
        ),
        "unexpected foreign-result error: {err:?}"
    );
    assert!(session.steps().is_empty());
}

#[test]
fn invalid_session_ids_fail_closed() {
    let sdk = create_verifier_sdk("verifier://session-validation");

    let err = sdk
        .create_session("")
        .expect_err("empty session id must be rejected");

    assert!(
        matches!(err, VerifierSdkError::InvalidSessionId { .. }),
        "unexpected invalid-session error: {err:?}"
    );
}
