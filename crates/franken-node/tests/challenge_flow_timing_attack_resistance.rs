//! Challenge-flow proof hash timing-attack regressions.
//!
//! The challenge controller accepts externally supplied proof verifiers. These
//! tests lock the recommended verifier path to the challenge-flow constant-time
//! helper so first-byte, middle-byte, and last-byte digest mismatches all reject
//! without promoting the challenge.

use frankenengine_node::security::challenge_flow::{
    ArtifactId, ChallengeConfig, ChallengeError, ChallengeFlowController, ChallengeState,
    ERR_PROOF_INVALID, ProofSubmission, RequiredProofType, SuspicionReason,
    proof_data_hash_matches_constant_time,
};

const EXPECTED_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FIRST_BYTE_MISMATCH: &str =
    "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const MIDDLE_BYTE_MISMATCH: &str =
    "0123456789abcdef0123456789abcdef1123456789abcdef0123456789abcdef";
const LAST_BYTE_MISMATCH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee";

fn challenge_controller_for_expected_hash() -> ChallengeFlowController {
    ChallengeFlowController::with_proof_verifier(
        ChallengeConfig::default(),
        |_artifact_id, proof| {
            if proof_data_hash_matches_constant_time(&proof.data_hash, EXPECTED_HASH) {
                Ok(())
            } else {
                Err(ChallengeError::new(
                    ERR_PROOF_INVALID,
                    "challenge proof data_hash mismatch",
                ))
            }
        },
    )
}

fn issue_integrity_challenge(
    controller: &mut ChallengeFlowController,
    artifact_id: &str,
) -> frankenengine_node::security::challenge_flow::ChallengeId {
    controller
        .issue_challenge(
            ArtifactId::new(artifact_id),
            SuspicionReason::UnexpectedProvenance,
            vec![RequiredProofType::IntegrityProof],
            "operator",
            1_000,
        )
        .expect("integrity challenge should issue")
}

fn issue_custom_challenge(
    controller: &mut ChallengeFlowController,
    expected_label: &str,
    artifact_id: &str,
) -> frankenengine_node::security::challenge_flow::ChallengeId {
    controller
        .issue_challenge(
            ArtifactId::new(artifact_id),
            SuspicionReason::UnexpectedProvenance,
            vec![RequiredProofType::Custom(expected_label.to_string())],
            "operator",
            1_000,
        )
        .expect("custom challenge should issue")
}

fn proof_with_hash(data_hash: &str) -> ProofSubmission {
    ProofSubmission {
        proof_type: RequiredProofType::IntegrityProof,
        data_hash: data_hash.to_string(),
        submitter_id: "prover".to_string(),
        submitted_at_ms: 1_100,
    }
}

fn custom_proof(label: &str) -> ProofSubmission {
    ProofSubmission {
        proof_type: RequiredProofType::Custom(label.to_string()),
        data_hash: EXPECTED_HASH.to_string(),
        submitter_id: "prover".to_string(),
        submitted_at_ms: 1_100,
    }
}

#[test]
fn challenge_flow_proof_hash_helper_rejects_mismatch_positions() {
    assert!(proof_data_hash_matches_constant_time(
        EXPECTED_HASH,
        EXPECTED_HASH
    ));

    for candidate in [
        FIRST_BYTE_MISMATCH,
        MIDDLE_BYTE_MISMATCH,
        LAST_BYTE_MISMATCH,
    ] {
        assert!(
            !proof_data_hash_matches_constant_time(candidate, EXPECTED_HASH),
            "same-length mismatch should reject regardless of mismatch position"
        );
    }

    assert!(!proof_data_hash_matches_constant_time(
        &EXPECTED_HASH[..EXPECTED_HASH.len() - 1],
        EXPECTED_HASH
    ));
}

#[test]
fn challenge_flow_verifier_rejects_tampered_hashes_without_promotion() {
    for (case_name, candidate_hash) in [
        ("first-byte", FIRST_BYTE_MISMATCH),
        ("middle-byte", MIDDLE_BYTE_MISMATCH),
        ("last-byte", LAST_BYTE_MISMATCH),
    ] {
        let mut controller = challenge_controller_for_expected_hash();
        let challenge_id =
            issue_integrity_challenge(&mut controller, &format!("artifact-{case_name}"));

        controller
            .submit_proof(
                &challenge_id,
                proof_with_hash(candidate_hash),
                "prover",
                1_100,
            )
            .expect("well-formed tampered proof should be recorded before verification");

        let error = controller
            .verify_proof(&challenge_id, "verifier", 1_200)
            .expect_err("tampered proof hash must fail verification");

        assert_eq!(error.code, ERR_PROOF_INVALID);
        assert_eq!(
            controller
                .get_challenge(&challenge_id)
                .expect("challenge should remain available")
                .state,
            ChallengeState::ProofReceived,
            "tampered proof must not advance to ProofVerified for {case_name}"
        );
        assert_eq!(controller.metrics().challenges_promoted_total, 0);
    }
}

#[test]
fn challenge_flow_custom_proof_type_labels_reject_mismatch_positions() {
    const EXPECTED_LABEL: &str = "custom-proof-label-v1";
    const FIRST_LABEL_MISMATCH: &str = "xustom-proof-label-v1";
    const MIDDLE_LABEL_MISMATCH: &str = "custom-xroof-label-v1";
    const LAST_LABEL_MISMATCH: &str = "custom-proof-label-v2";

    for (case_name, candidate_label) in [
        ("first-byte", FIRST_LABEL_MISMATCH),
        ("middle-byte", MIDDLE_LABEL_MISMATCH),
        ("last-byte", LAST_LABEL_MISMATCH),
    ] {
        let mut controller = challenge_controller_for_expected_hash();
        let challenge_id = issue_custom_challenge(
            &mut controller,
            EXPECTED_LABEL,
            &format!("custom-artifact-{case_name}"),
        );

        let error = controller
            .submit_proof(
                &challenge_id,
                custom_proof(candidate_label),
                "prover",
                1_100,
            )
            .expect_err("custom proof label mismatch must be rejected");

        assert_eq!(error.code, ERR_PROOF_INVALID);
        let challenge = controller
            .get_challenge(&challenge_id)
            .expect("challenge should remain available");
        assert_eq!(challenge.state, ChallengeState::ChallengeIssued);
        assert!(challenge.received_proofs.is_empty());
    }
}

#[test]
fn challenge_flow_verifier_accepts_exact_hash_match() {
    let mut controller = challenge_controller_for_expected_hash();
    let challenge_id = issue_integrity_challenge(&mut controller, "artifact-valid");

    controller
        .submit_proof(
            &challenge_id,
            proof_with_hash(EXPECTED_HASH),
            "prover",
            1_100,
        )
        .expect("valid proof should submit");
    controller
        .verify_proof(&challenge_id, "verifier", 1_200)
        .expect("exact proof hash should verify");

    assert_eq!(
        controller
            .get_challenge(&challenge_id)
            .expect("challenge should remain available")
            .state,
        ChallengeState::ProofVerified
    );
}
