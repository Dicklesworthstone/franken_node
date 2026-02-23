//! Security-focused tests for bd-1l62 durable claim gate bypass resistance.

#[path = "../../crates/franken-node/src/connector/durable_claim_gate.rs"]
mod durable_claim_gate;

use durable_claim_gate::{
    ClaimDenialReason, DurableClaim, DurableClaimGate, DurableClaimGateConfig, ProofArtifact,
    ProofType, VerificationInput,
};
use std::collections::BTreeSet;

fn gate() -> DurableClaimGate {
    DurableClaimGate::new(DurableClaimGateConfig::default()).expect("gate")
}

fn claim() -> DurableClaim {
    DurableClaim {
        claim_id: "claim-security".to_string(),
        claim_type: "repair_completion".to_string(),
        claim_hash: "claim-security-hash".to_string(),
        epoch: 42,
        required_markers: vec!["marker-security".to_string()],
        required_proofs: vec![
            ProofType::MerkleInclusion,
            ProofType::MarkerMmr,
            ProofType::EpochBoundary,
        ],
        trace_id: "trace-security".to_string(),
    }
}

fn valid_input() -> VerificationInput {
    let mut markers = BTreeSet::new();
    markers.insert("marker-security".to_string());
    VerificationInput {
        available_markers: markers,
        proofs: vec![
            ProofArtifact {
                proof_type: ProofType::MerkleInclusion,
                claim_id: "claim-security".to_string(),
                claim_hash: "claim-security-hash".to_string(),
                issued_at_epoch: 42,
                expires_at_epoch: 44,
                proof_hash: "proof-hash-a".to_string(),
                verified: true,
            },
            ProofArtifact {
                proof_type: ProofType::MarkerMmr,
                claim_id: "claim-security".to_string(),
                claim_hash: "claim-security-hash".to_string(),
                issued_at_epoch: 42,
                expires_at_epoch: 44,
                proof_hash: "proof-hash-b".to_string(),
                verified: true,
            },
            ProofArtifact {
                proof_type: ProofType::EpochBoundary,
                claim_id: "claim-security".to_string(),
                claim_hash: "claim-security-hash".to_string(),
                issued_at_epoch: 42,
                expires_at_epoch: 44,
                proof_hash: "proof-hash-c".to_string(),
                verified: true,
            },
        ],
        verification_complete: true,
        simulated_elapsed_ms: 1,
    }
}

#[test]
fn forged_proof_payload_is_rejected() {
    let mut g = gate();
    let mut input = valid_input();
    input.proofs[0].claim_hash = "forged-hash".to_string();

    let decision = g.evaluate_claim(&claim(), &input, 42).expect("decision");
    assert!(!decision.accepted);
    assert_eq!(
        decision.denial_reason.expect("reason").code(),
        "CLAIM_PROOF_INVALID"
    );
}

#[test]
fn wrong_epoch_proof_is_rejected() {
    let mut g = gate();
    let mut input = valid_input();
    input.proofs[1].issued_at_epoch = 1;
    input.proofs[1].expires_at_epoch = 3;

    let decision = g.evaluate_claim(&claim(), &input, 42).expect("decision");
    assert!(!decision.accepted);
    assert_eq!(
        decision.denial_reason.expect("reason").code(),
        "CLAIM_PROOF_EXPIRED"
    );
}

#[test]
fn claim_for_different_id_is_rejected() {
    let mut g = gate();
    let mut input = valid_input();
    input.proofs[2].claim_id = "different-claim".to_string();

    let decision = g.evaluate_claim(&claim(), &input, 42).expect("decision");
    assert!(!decision.accepted);
    assert_eq!(
        decision.denial_reason.expect("reason").code(),
        "CLAIM_PROOF_MISSING"
    );
}

#[test]
fn denial_codes_are_stable_for_all_variants() {
    let variants = vec![
        ClaimDenialReason::ProofMissing {
            proof_type: ProofType::MarkerMmr,
        },
        ClaimDenialReason::ProofInvalid {
            proof_type: ProofType::MerkleInclusion,
            detail: "invalid".to_string(),
        },
        ClaimDenialReason::ProofExpired {
            proof_type: ProofType::EpochBoundary,
            proof_epoch: 1,
            current_epoch: 2,
        },
        ClaimDenialReason::ProofVerificationTimeout {
            timeout_ms: 1000,
            elapsed_ms: 1500,
        },
        ClaimDenialReason::MarkerUnavailable {
            marker_id: "m".to_string(),
        },
    ];

    let mut codes = BTreeSet::new();
    for variant in variants {
        codes.insert(variant.code().to_string());
    }

    assert_eq!(codes.len(), 5);
    assert!(codes.contains("CLAIM_PROOF_MISSING"));
    assert!(codes.contains("CLAIM_PROOF_INVALID"));
    assert!(codes.contains("CLAIM_PROOF_EXPIRED"));
    assert!(codes.contains("CLAIM_PROOF_VERIFICATION_TIMEOUT"));
    assert!(codes.contains("CLAIM_MARKER_UNAVAILABLE"));
}
