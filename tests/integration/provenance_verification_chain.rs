//! Integration tests for bd-1ah provenance verification chain.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use frankenengine_node::supply_chain::provenance::{
    AttestationEnvelopeFormat, AttestationLink, ChainLinkRole, DownstreamGateRequirements,
    ProvenanceAttestation, ProvenanceEventCode, ProvenanceLevel, VerificationErrorCode,
    VerificationMode, VerificationPolicy, enforce_fail_closed, sign_links_in_place,
    verify_and_project_gates, verify_attestation_chain,
};

fn test_signing_key_for(signer_id: &str) -> SigningKey {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"provenance_integration_signing_key_v1:");
    hasher.update((u64::try_from(signer_id.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(signer_id.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&digest);
    SigningKey::from_bytes(&seed)
}

fn signing_keys_for(attestation: &ProvenanceAttestation) -> BTreeMap<String, SigningKey> {
    attestation
        .links
        .iter()
        .map(|link| {
            (
                link.signer_id.clone(),
                test_signing_key_for(&link.signer_id),
            )
        })
        .collect()
}

fn sign_attestation_links(attestation: &mut ProvenanceAttestation) {
    sign_links_in_place(attestation, &signing_keys_for(attestation)).expect("sign links");
}

fn production_policy_for(attestation: &ProvenanceAttestation) -> VerificationPolicy {
    let mut policy = VerificationPolicy::production_default();
    for link in &attestation.links {
        let signing_key = test_signing_key_for(&link.signer_id);
        policy.add_trusted_signer_key(&link.signer_id, &signing_key.verifying_key());
    }
    policy
}

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
    sign_attestation_links(&mut attestation);
    attestation
}

#[test]
fn inv_pat_full_chain_verifies_fail_closed() {
    let attestation = valid_attestation();
    let policy = production_policy_for(&attestation);
    let report = verify_attestation_chain(&attestation, &policy, 1_700_000_400, "trace-a");

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
    sign_attestation_links(&mut attestation);

    let policy = production_policy_for(&attestation);
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
    let build_link = attestation
        .links
        .iter_mut()
        .find(|link| link.role == ChainLinkRole::BuildSystem)
        .expect("valid attestation includes build-system link");
    build_link.signature = "bad-signature".to_string();

    let policy = production_policy_for(&attestation);
    let report = verify_attestation_chain(&attestation, &policy, 1_700_000_500, "trace-c");

    assert!(!report.chain_valid);
    assert!(report.issues.iter().any(|issue| {
        issue.code == VerificationErrorCode::InvalidSignature
            && issue.link_role == Some(ChainLinkRole::BuildSystem)
    }));
}

#[test]
fn inv_pat_same_signer_source_link_is_downgraded_to_level_two() {
    let mut attestation = valid_attestation();
    let build_signer_id = attestation
        .links
        .iter()
        .find(|link| link.role == ChainLinkRole::BuildSystem)
        .expect("valid attestation includes build-system link")
        .signer_id
        .clone();
    let source_link = attestation
        .links
        .iter_mut()
        .find(|link| link.role == ChainLinkRole::SourceVcs)
        .expect("valid attestation includes source VCS link");
    source_link.signer_id = build_signer_id;
    sign_attestation_links(&mut attestation);

    let policy = production_policy_for(&attestation);
    let report = verify_attestation_chain(&attestation, &policy, 1_700_000_500, "trace-c2");

    assert!(report.chain_valid);
    assert_eq!(
        report.provenance_level,
        ProvenanceLevel::Level2SignedReproducible
    );
    assert!(
        report
            .events
            .contains(&ProvenanceEventCode::ProvenanceDegradedModeEntered)
    );
    assert!(
        report
            .events
            .contains(&ProvenanceEventCode::AttestationVerified)
    );
}

#[test]
fn inv_pat_cached_window_allows_soft_stale_but_emits_event() {
    let mut attestation = valid_attestation();
    attestation.build_timestamp_epoch = 960;
    for link in &mut attestation.links {
        link.issued_at_epoch = 960;
        link.expires_at_epoch = 970;
    }
    sign_attestation_links(&mut attestation);

    let mut policy = production_policy_for(&attestation);
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
    let attestation = valid_attestation();
    let policy = production_policy_for(&attestation);
    let outcome = verify_and_project_gates(&attestation, &policy, 1_700_000_500, "trace-e");

    assert!(outcome.report.chain_valid);
    assert_eq!(
        outcome.downstream_gates,
        DownstreamGateRequirements {
            threshold_signature_required: true,
            transparency_log_required: true,
        }
    );
}
