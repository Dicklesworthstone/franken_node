//! Integration tests for bd-1ah provenance verification chain.

use std::collections::BTreeMap;

use frankenengine_node::supply_chain::provenance::{
    AttestationEnvelopeFormat, AttestationLink, ChainLinkRole, DownstreamGateRequirements,
    ProvenanceAttestation, ProvenanceEventCode, ProvenanceLevel, VerificationErrorCode,
    VerificationMode, VerificationPolicy, enforce_fail_closed, sign_links_in_place,
    verify_and_project_gates, verify_attestation_chain,
};

fn valid_attestation() -> ProvenanceAttestation {
    let mut attestation = ProvenanceAttestation {
        schema_version: "1.0".to_string(),
        source_repository_url: "https://example.com/extensions/repo.git".to_string(),
        build_system_identifier: "github-actions".to_string(),
        builder_identity: "builder@ci".to_string(),
        builder_version: "2026.02".to_string(),
        vcs_commit_sha: "aabbccddeeff00112233445566778899aabbccdd".to_string(),
        build_timestamp_epoch: 1_700_000_100,
        reproducibility_hash: "sha256:repro-123".to_string(),
        input_hash: "sha256:input-123".to_string(),
        output_hash: "sha256:output-123".to_string(),
        slsa_level_claim: 3,
        envelope_format: AttestationEnvelopeFormat::InToto,
        links: vec![
            AttestationLink {
                role: ChainLinkRole::Publisher,
                signer_id: "publisher-key".to_string(),
                signer_version: "v1".to_string(),
                signature: String::new(),
                signed_payload_hash: "sha256:output-123".to_string(),
                issued_at_epoch: 1_700_000_200,
                expires_at_epoch: 1_700_100_000,
                revoked: false,
            },
            AttestationLink {
                role: ChainLinkRole::BuildSystem,
                signer_id: "builder-key".to_string(),
                signer_version: "v1".to_string(),
                signature: String::new(),
                signed_payload_hash: "sha256:output-123".to_string(),
                issued_at_epoch: 1_700_000_210,
                expires_at_epoch: 1_700_100_000,
                revoked: false,
            },
            AttestationLink {
                role: ChainLinkRole::SourceVcs,
                signer_id: "vcs-key".to_string(),
                signer_version: "v1".to_string(),
                signature: String::new(),
                signed_payload_hash: "sha256:output-123".to_string(),
                issued_at_epoch: 1_700_000_220,
                expires_at_epoch: 1_700_100_000,
                revoked: false,
            },
        ],
        custom_claims: BTreeMap::from([(
            "slsa.predicateType".to_string(),
            "https://slsa.dev/provenance/v1".to_string(),
        )]),
    };
    sign_links_in_place(&mut attestation).expect("sign links");
    attestation
}

#[test]
fn inv_pat_full_chain_verifies_fail_closed() {
    let policy = VerificationPolicy::production_default();
    let report = verify_attestation_chain(&valid_attestation(), &policy, 1_700_000_400, "trace-a");

    assert!(report.chain_valid);
    assert_eq!(
        report.provenance_level,
        ProvenanceLevel::Level3IndependentReproduced
    );
    assert!(report.issues.is_empty());
    assert!(
        report
            .events
            .contains(&ProvenanceEventCode::AttestationVerified)
    );
    assert!(enforce_fail_closed(&report).is_ok());
}

#[test]
fn inv_pat_missing_source_vcs_link_rejected_with_chain_incomplete() {
    let mut attestation = valid_attestation();
    attestation.links.truncate(2);
    sign_links_in_place(&mut attestation).expect("re-sign links");

    let policy = VerificationPolicy::production_default();
    let report = verify_attestation_chain(&attestation, &policy, 1_700_000_400, "trace-b");

    assert!(!report.chain_valid);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == VerificationErrorCode::ChainIncomplete)
    );
    let failure = enforce_fail_closed(&report).expect_err("must fail closed");
    assert_eq!(failure.code, VerificationErrorCode::ChainIncomplete);
}

#[test]
fn inv_pat_broken_signature_marks_specific_link() {
    let mut attestation = valid_attestation();
    attestation.links[1].signature = "bad-signature".to_string();

    let policy = VerificationPolicy::production_default();
    let report = verify_attestation_chain(&attestation, &policy, 1_700_000_500, "trace-c");

    assert!(!report.chain_valid);
    assert!(report.issues.iter().any(|issue| {
        issue.code == VerificationErrorCode::InvalidSignature
            && issue.link_role == Some(ChainLinkRole::BuildSystem)
    }));
}

#[test]
fn inv_pat_cached_window_allows_soft_stale_but_emits_event() {
    let mut attestation = valid_attestation();
    attestation.build_timestamp_epoch = 960;
    for link in &mut attestation.links {
        link.issued_at_epoch = 960;
        link.expires_at_epoch = 970;
    }
    sign_links_in_place(&mut attestation).expect("re-sign stale links");

    let mut policy = VerificationPolicy::production_default();
    policy.mode = VerificationMode::CachedTrustWindow;
    policy.max_attestation_age_secs = 10;
    policy.cached_trust_window_secs = 100;

    let report = verify_attestation_chain(&attestation, &policy, 1_000, "trace-d");

    assert!(report.chain_valid);
    assert!(!report.issues.is_empty());
    assert!(
        report
            .events
            .contains(&ProvenanceEventCode::ProvenanceDegradedModeEntered)
    );
    assert!(
        report
            .issues
            .iter()
            .all(|issue| issue.code == VerificationErrorCode::ChainStale)
    );
}

#[test]
fn inv_pat_downstream_gate_projection_requires_10_13_checks() {
    let policy = VerificationPolicy::production_default();
    let outcome = verify_and_project_gates(&valid_attestation(), &policy, 1_700_000_500, "trace-e");

    assert!(outcome.report.chain_valid);
    assert_eq!(
        outcome.downstream_gates,
        DownstreamGateRequirements {
            threshold_signature_required: true,
            transparency_log_required: true,
        }
    );
}
