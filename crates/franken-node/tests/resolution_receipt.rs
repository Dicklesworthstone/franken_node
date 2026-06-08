use ed25519_dalek::SigningKey;
use frankenengine_node::supply_chain::resolution_receipt::{
    AdmissionDecision, AdmissionProfile, CandidateAssessment, CompatibilityStatus,
    RESOLUTION_RECEIPT_SCHEMA, ResolutionRejectionReason, RevocationFreshness, RiskTier,
    TrustCardStatus, build_resolution_receipt, candidate_is_admissible,
    serialize_signed_resolution_receipt, sign_resolution_receipt, verify_signed_resolution_receipt,
};
use frankenengine_verifier_sdk::VerifierSdk;
use frankenengine_verifier_sdk::resolution::{
    FN_VSDK_RESOLUTION_RECEIPT_PASS, FN_VSDK_RESOLUTION_RECEIPT_START,
    FN_VSDK_RESOLUTION_RECEIPT_VERIFIED, ResolutionReceiptError,
};

const GRAPH_HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn profile_policy_changes_admitted_version_and_records_rationale() {
    let candidates = fixture_candidates();

    let strict = build_resolution_receipt(
        "receipt-strict",
        1_778_000_000_000,
        GRAPH_HASH,
        "left-pad",
        "^2 || ^1",
        AdmissionProfile::Strict,
        candidates.clone(),
    )
    .expect("strict receipt");
    let balanced = build_resolution_receipt(
        "receipt-balanced",
        1_778_000_000_000,
        GRAPH_HASH,
        "left-pad",
        "^2 || ^1",
        AdmissionProfile::Balanced,
        candidates,
    )
    .expect("balanced receipt");

    assert_eq!(strict.schema_version, RESOLUTION_RECEIPT_SCHEMA);
    assert_eq!(strict.decision, AdmissionDecision::Admit);
    assert_eq!(
        strict
            .selected_version
            .as_ref()
            .map(|candidate| candidate.version.as_str()),
        Some("1.5.0"),
        "strict rejects the high-risk newer version"
    );
    assert!(
        strict
            .rejected_alternatives
            .iter()
            .any(|alternative| alternative.candidate.version == "2.0.0"
                && alternative.reason == ResolutionRejectionReason::ProfilePolicy)
    );

    assert_eq!(
        balanced
            .selected_version
            .as_ref()
            .map(|candidate| candidate.version.as_str()),
        Some("2.0.0"),
        "balanced admits the higher-risk compatible candidate"
    );
    assert_ne!(strict.canonical_hash, balanced.canonical_hash);
    assert!(
        balanced
            .evidence_refs
            .trust_card_refs
            .iter()
            .any(|item| item == "trust-card://left-pad@2.0.0")
    );
}

#[test]
fn signed_receipt_exports_to_canonical_bytes_and_verifies_in_sdk() {
    let receipt = build_resolution_receipt(
        "receipt-sdk",
        1_778_000_000_001,
        GRAPH_HASH,
        "left-pad",
        "^2 || ^1",
        AdmissionProfile::Balanced,
        fixture_candidates(),
    )
    .expect("receipt");
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let signed = sign_resolution_receipt(&receipt, &signing_key).expect("signed");
    assert!(
        verify_signed_resolution_receipt(&signed, &signing_key.verifying_key())
            .expect("product verification")
    );

    let bytes = serialize_signed_resolution_receipt(&signed).expect("canonical bytes");
    let sdk = VerifierSdk::new("verifier://resolution-receipt-test");
    let verified = sdk
        .verify_resolution_receipt(&signing_key.verifying_key(), &bytes)
        .expect("SDK verifies signed resolution receipt");

    assert_eq!(verified.package_name, "left-pad");
    assert_eq!(
        verified.decision,
        frankenengine_verifier_sdk::resolution::AdmissionDecision::Admit
    );
    assert_eq!(verified.selected_version.as_deref(), Some("2.0.0"));
    assert_eq!(
        verified.event_codes,
        vec![
            FN_VSDK_RESOLUTION_RECEIPT_START.to_string(),
            FN_VSDK_RESOLUTION_RECEIPT_VERIFIED.to_string(),
            FN_VSDK_RESOLUTION_RECEIPT_PASS.to_string(),
        ]
    );
}

#[test]
fn sdk_rejects_noncanonical_and_tampered_receipt_bytes() {
    let receipt = build_resolution_receipt(
        "receipt-tamper",
        1_778_000_000_002,
        GRAPH_HASH,
        "left-pad",
        "^2 || ^1",
        AdmissionProfile::Balanced,
        fixture_candidates(),
    )
    .expect("receipt");
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let signed = sign_resolution_receipt(&receipt, &signing_key).expect("signed");
    let canonical = serialize_signed_resolution_receipt(&signed).expect("canonical bytes");
    let pretty = serde_json::to_vec_pretty(&signed).expect("pretty JSON");
    let sdk = VerifierSdk::new("verifier://resolution-receipt-test");

    let noncanonical = sdk
        .verify_resolution_receipt(&signing_key.verifying_key(), &pretty)
        .expect_err("pretty JSON must be rejected");
    assert!(noncanonical.to_string().contains("not canonical"));

    let mut tampered = canonical.clone();
    let offset = find_subsequence(&tampered, b"2.0.0").expect("selected version bytes");
    for (index, byte) in tampered.iter_mut().enumerate() {
        if index == offset {
            *byte = b'3';
            break;
        }
    }
    let err = sdk
        .verify_resolution_receipt(&signing_key.verifying_key(), &tampered)
        .expect_err("tampered bytes must fail");
    assert!(matches!(
        err,
        frankenengine_verifier_sdk::VerifierSdkError::Json(ref message)
            if message.contains(&ResolutionReceiptError::SignatureInvalid.to_string())
                || message.contains("canonical hash mismatch")
    ));
}

#[test]
fn fail_closed_reject_receipt_has_no_selected_version() {
    let revoked_only = vec![candidate(
        "3.0.0",
        TrustCardStatus::Revoked,
        RiskTier::Low,
        RiskTier::Low,
        RevocationFreshness::Revoked,
        CompatibilityStatus::Compatible,
    )];

    let receipt = build_resolution_receipt(
        "receipt-reject",
        1_778_000_000_003,
        GRAPH_HASH,
        "left-pad",
        "^3",
        AdmissionProfile::LegacyRisky,
        revoked_only,
    )
    .expect("reject receipt");

    assert_eq!(receipt.decision, AdmissionDecision::Reject);
    assert!(receipt.selected_version.is_none());
    assert_eq!(receipt.rejected_alternatives.len(), 1);
    assert!(!candidate_is_admissible(
        AdmissionProfile::LegacyRisky,
        &receipt.rejected_alternatives[0].candidate
    ));
}

fn fixture_candidates() -> Vec<CandidateAssessment> {
    vec![
        candidate(
            "2.0.0",
            TrustCardStatus::Trusted,
            RiskTier::High,
            RiskTier::Moderate,
            RevocationFreshness::Stale,
            CompatibilityStatus::NeedsShim,
        ),
        candidate(
            "1.5.0",
            TrustCardStatus::Trusted,
            RiskTier::Low,
            RiskTier::Low,
            RevocationFreshness::Fresh,
            CompatibilityStatus::Compatible,
        ),
        candidate(
            "3.0.0",
            TrustCardStatus::Revoked,
            RiskTier::Low,
            RiskTier::Low,
            RevocationFreshness::Revoked,
            CompatibilityStatus::Compatible,
        ),
    ]
}

fn candidate(
    version: &str,
    trust_status: TrustCardStatus,
    bpet_risk: RiskTier,
    dgis_risk: RiskTier,
    revocation_freshness: RevocationFreshness,
    compat_status: CompatibilityStatus,
) -> CandidateAssessment {
    CandidateAssessment {
        version: version.to_string(),
        package_path: format!("node_modules/left-pad-{version}"),
        resolved_url: Some(format!(
            "https://registry.npmjs.org/left-pad/-/left-pad-{version}.tgz"
        )),
        integrity: Some(format!("sha512-left-pad-{version}")),
        trust_card_ref: format!("trust-card://left-pad@{version}"),
        trust_status,
        bpet_risk_ref: format!("bpet://left-pad@{version}"),
        bpet_risk,
        dgis_risk_ref: format!("dgis://left-pad@{version}"),
        dgis_risk,
        revocation_freshness_ref: format!("revocation://left-pad@{version}"),
        revocation_freshness,
        compat_oracle_ref: format!("compat-oracle://left-pad@{version}"),
        compat_status,
        capability_budget_ref: format!("cap-budget://left-pad@{version}"),
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
