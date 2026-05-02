use std::collections::BTreeMap;

use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, SnapshotSourceContext, TrustCard,
    TrustCardInput, TrustCardMutation, TrustCardRegistry, TrustCardRegistrySnapshot,
    compute_card_hash,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const DEFAULT_REGISTRY_KEY: &[u8] = b"franken-node-trust-card-registry-key-v1";

type HmacSha256 = Hmac<Sha256>;

fn real_trust_card_input() -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: "npm:@operator/auth-guard".to_string(),
            version: "2.3.1".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "pub-operator-security".to_string(),
            display_name: "Operator Security Team".to_string(),
        },
        certification_level: CertificationLevel::Gold,
        capability_declarations: vec![CapabilityDeclaration {
            name: "auth.validate-token".to_string(),
            description: "Validate signed session tokens against the policy registry".to_string(),
            risk: CapabilityRisk::Medium,
        }],
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: false,
            subprocess_access: false,
            profile_summary: "Network-only validation with no local write authority".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "slsa-l3".to_string(),
            source_uri: "https://github.com/operator/auth-guard".to_string(),
            artifact_hashes: vec![
                "sha256:8d1f6a7eac587f8b2ef4c8c06e86fbfdb59af6dd6b56d6ec7fa7f0efda09a39d"
                    .to_string(),
            ],
            verified_at: "2026-04-21T16:30:00Z".to_string(),
        },
        reputation_score_basis_points: 915,
        reputation_trend: ReputationTrend::Improving,
        active_quarantine: false,
        dependency_trust_summary: vec![DependencyTrustStatus {
            dependency_id: "npm:jose@5".to_string(),
            trust_level: "verified".to_string(),
        }],
        last_verified_timestamp: "2026-04-21T16:30:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Strong provenance and bounded runtime capabilities".to_string(),
        },
        evidence_refs: vec![VerifiedEvidenceRef {
            evidence_id: "prov-operator-auth-guard-20260421".to_string(),
            evidence_type: EvidenceType::ProvenanceChain,
            verified_at_epoch: 1_776_792_600,
            verification_receipt_hash:
                "4ef6f8d5e8e0f0b778e7ca4a68697c139e91fbf18d8d1f8af5fcb5e628dd5c6a".to_string(),
        }],
    }
}

fn sign_trust_card_for_real_input_test(card: &mut TrustCard) {
    card.card_hash = compute_card_hash(card).expect("compute card hash");
    let mut mac = HmacSha256::new_from_slice(DEFAULT_REGISTRY_KEY).expect("hmac key");
    mac.update(b"trust_card_registry_sig_v1:");
    mac.update(card.card_hash.as_bytes());
    card.registry_signature = hex::encode(mac.finalize().into_bytes());
}

fn registry_with_exhausted_trust_card_version() -> TrustCardRegistry {
    let mut source = TrustCardRegistry::default();
    let mut card = source
        .create(
            real_trust_card_input(),
            1_776_792_600,
            "trace-exhausted-version-seed",
        )
        .expect("create seed card");
    card.trust_card_version = u64::MAX;
    sign_trust_card_for_real_input_test(&mut card);

    let mut cards_by_extension = BTreeMap::new();
    cards_by_extension.insert(card.extension.extension_id.clone(), vec![card]);
    let snapshot = TrustCardRegistrySnapshot::signed(60, cards_by_extension, DEFAULT_REGISTRY_KEY)
        .expect("signed snapshot");
    TrustCardRegistry::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, 1_776_792_601)
        .expect("load exhausted-version registry")
}

#[test]
fn authoritative_registry_round_trips_without_fixture_helper() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let snapshot_path = temp_dir
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    let mut registry = TrustCardRegistry::default();

    let created = registry
        .create(
            real_trust_card_input(),
            1_776_792_600,
            "trace-authoritative-write",
        )
        .expect("create real trust card");
    registry
        .persist_authoritative_state(&snapshot_path)
        .expect("persist authoritative state");

    let mut loaded = TrustCardRegistry::load_authoritative_state(
        &snapshot_path,
        60,
        1_776_792_610,
        SnapshotSourceContext::TrustedFile,
    )
    .expect("load authoritative state");
    let reloaded = loaded
        .read(
            "npm:@operator/auth-guard",
            1_776_792_611,
            "trace-authoritative-read",
        )
        .expect("read reloaded card")
        .expect("card exists");

    assert_eq!(created.card_hash, reloaded.card_hash);
    assert_eq!(created.registry_signature, reloaded.registry_signature);
    assert_eq!(
        reloaded.provenance_summary.source_uri,
        "https://github.com/operator/auth-guard"
    );
}

#[test]
fn authoritative_registry_rejects_tampered_snapshot() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let snapshot_path = temp_dir
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    let mut registry = TrustCardRegistry::default();
    registry
        .create(
            real_trust_card_input(),
            1_776_792_600,
            "trace-authoritative-write",
        )
        .expect("create real trust card");
    registry
        .persist_authoritative_state(&snapshot_path)
        .expect("persist authoritative state");

    let mut raw = std::fs::read_to_string(&snapshot_path).expect("read snapshot");
    raw = raw.replace(
        "https://github.com/operator/auth-guard",
        "fixture://tampered",
    );
    std::fs::write(&snapshot_path, raw).expect("tamper snapshot");

    let err = TrustCardRegistry::load_authoritative_state(
        &snapshot_path,
        60,
        1_776_792_610,
        SnapshotSourceContext::TrustedFile,
    )
    .expect_err("tampered authoritative state must fail closed");
    assert!(
        err.to_string().contains("signature")
            || err.to_string().contains("hash")
            || err.to_string().contains("snapshot")
    );
}

#[test]
fn authoritative_registry_rejects_stale_writer_after_high_water_advances() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let snapshot_path = temp_dir
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    let mut stale_writer = TrustCardRegistry::default();
    stale_writer
        .create(
            real_trust_card_input(),
            1_776_792_600,
            "trace-stale-writer-seed",
        )
        .expect("create stale writer state");

    let mut newer_writer = stale_writer.clone();
    newer_writer
        .update(
            "npm:@operator/auth-guard",
            TrustCardMutation {
                certification_level: Some(CertificationLevel::Platinum),
                revocation_status: None,
                active_quarantine: None,
                reputation_score_basis_points: None,
                reputation_trend: None,
                user_facing_risk_assessment: None,
                last_verified_timestamp: Some("2026-04-21T16:31:00Z".to_string()),
                evidence_refs: Some(real_trust_card_input().evidence_refs),
            },
            1_776_792_660,
            "trace-newer-writer",
        )
        .expect("advance newer writer state");
    newer_writer
        .persist_authoritative_state(&snapshot_path)
        .expect("persist newer writer state");

    let err = stale_writer
        .persist_authoritative_state(&snapshot_path)
        .expect_err("stale writer must fail after high-water advances");
    assert!(
        err.to_string().contains("rollback rejected"),
        "unexpected error: {err:?}"
    );

    let mut loaded = TrustCardRegistry::load_authoritative_state(
        &snapshot_path,
        60,
        1_776_792_700,
        SnapshotSourceContext::TrustedFile,
    )
    .expect("load authoritative state");
    let card = loaded
        .read(
            "npm:@operator/auth-guard",
            1_776_792_701,
            "trace-authoritative-stale-check",
        )
        .expect("read authoritative card")
        .expect("card exists");
    assert_eq!(card.certification_level, CertificationLevel::Platinum);
}

#[test]
fn trust_card_create_rejects_exhausted_trust_card_version() {
    let mut registry = registry_with_exhausted_trust_card_version();

    let err = registry
        .create(
            real_trust_card_input(),
            1_776_792_610,
            "trace-exhausted-version-create",
        )
        .expect_err("u64::MAX trust_card_version must fail closed");

    assert!(err.to_string().contains("trust_card_version exhausted"));
}

#[test]
fn trust_card_update_rejects_exhausted_trust_card_version() {
    let mut registry = registry_with_exhausted_trust_card_version();

    let err = registry
        .update(
            "npm:@operator/auth-guard",
            TrustCardMutation {
                certification_level: Some(CertificationLevel::Platinum),
                revocation_status: None,
                active_quarantine: None,
                reputation_score_basis_points: None,
                reputation_trend: None,
                user_facing_risk_assessment: None,
                last_verified_timestamp: None,
                evidence_refs: Some(real_trust_card_input().evidence_refs),
            },
            1_776_792_620,
            "trace-exhausted-version-update",
        )
        .expect_err("u64::MAX trust_card_version must fail closed");

    assert!(err.to_string().contains("trust_card_version exhausted"));
}
