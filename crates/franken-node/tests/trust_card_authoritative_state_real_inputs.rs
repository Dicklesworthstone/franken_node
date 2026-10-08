use std::collections::{BTreeMap, BTreeSet};

use frankenengine_node::security::trajectory_gaming::{CamouflageHint, CamouflageKind};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, ExtensionIdentity, MAX_QUARANTINE_SOURCES, ProvenanceSummary,
    PublisherIdentity, QuarantineSource, ReputationTrend, RevocationStatus, RiskAssessment,
    RiskLevel, SnapshotSourceContext, TRUST_CARD_CAMOUFLAGE_SUSPECTED, TrustCard, TrustCardError,
    TrustCardInput, TrustCardMutation, TrustCardRegistry, TrustCardRegistrySnapshot,
    compute_card_hash, sign_card_in_place, verify_card_signature,
};
use frankenengine_node::supply_chain::trust_card_registry_store::TrustCardRegistryStore;
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

fn fleet_source(zone_id: &str, incident_id: &str) -> QuarantineSource {
    QuarantineSource::Fleet {
        zone_id: zone_id.to_string(),
        incident_id: incident_id.to_string(),
    }
}

#[test]
fn quarantine_owners_survive_restart_and_independent_releases() {
    let dir = tempfile::tempdir().expect("state directory");
    let path = dir.path().join("registry.json");
    let input = real_trust_card_input();
    let id = input.extension.extension_id.clone();
    let mut registry = TrustCardRegistry::default();
    registry.create(input, 1_800_000_000, "create").unwrap();
    let east = fleet_source("east", "shared-incident");
    let all = fleet_source("all", "shared-incident");
    for source in [east.clone(), all.clone(), QuarantineSource::Local] {
        registry
            .set_quarantine_source(&id, source, true, 1_800_000_001, "contain")
            .unwrap();
    }
    registry.persist_authoritative_state(&path).unwrap();
    drop(registry);
    let mut loaded = TrustCardRegistry::load_authoritative_state(
        &path,
        60,
        1_800_000_002,
        SnapshotSourceContext::TrustedFile,
    )
    .unwrap();
    let after_east = loaded
        .set_quarantine_source(&id, east.clone(), false, 1_800_000_003, "release-east")
        .unwrap();
    assert!(after_east.active_quarantine);
    assert_eq!(
        after_east.quarantine_sources,
        BTreeSet::from([all.clone(), QuarantineSource::Local])
    );
    let retry = loaded
        .set_quarantine_source(&id, east, false, 1_800_000_004, "retry-release")
        .unwrap();
    assert_eq!(
        retry.card_hash, after_east.card_hash,
        "idempotent retry must not create a new version"
    );
    let after_all = loaded
        .set_quarantine_source(&id, all, false, 1_800_000_005, "release-global")
        .unwrap();
    assert!(
        after_all.active_quarantine,
        "fleet cannot release the local decision"
    );
    assert_eq!(
        after_all.quarantine_sources,
        BTreeSet::from([QuarantineSource::Local])
    );
    let released = loaded
        .set_quarantine_source(
            &id,
            QuarantineSource::Local,
            false,
            1_800_000_006,
            "release-local",
        )
        .unwrap();
    assert!(!released.active_quarantine);
    assert!(released.quarantine_sources.is_empty());
    loaded.persist_authoritative_state(&path).unwrap();
    let mut restarted = TrustCardRegistry::load_authoritative_state(
        &path,
        60,
        1_800_000_007,
        SnapshotSourceContext::TrustedFile,
    )
    .unwrap();
    assert_eq!(
        restarted
            .read(&id, 1_800_000_008, "read")
            .unwrap()
            .unwrap()
            .card_hash,
        released.card_hash
    );
}

#[test]
fn generic_local_release_cannot_remove_fleet_quarantine() {
    let input = real_trust_card_input();
    let id = input.extension.extension_id.clone();
    let mut registry = TrustCardRegistry::default();
    registry.create(input, 100, "create").unwrap();
    let source = fleet_source("east", "supply-chain-incident");
    registry
        .set_quarantine_source(&id, source.clone(), true, 101, "fleet")
        .unwrap();
    let mutation = |active| TrustCardMutation {
        certification_level: None,
        revocation_status: None,
        active_quarantine: Some(active),
        reputation_score_basis_points: None,
        reputation_trend: None,
        user_facing_risk_assessment: None,
        last_verified_timestamp: None,
        evidence_refs: None,
    };
    registry
        .update(&id, mutation(true), 102, "local-quarantine")
        .unwrap();
    let card = registry
        .update(&id, mutation(false), 103, "local-release")
        .unwrap();
    assert!(card.active_quarantine);
    assert_eq!(card.quarantine_sources, BTreeSet::from([source]));
}

#[test]
fn historical_unowned_quarantine_is_local_and_cannot_be_claimed_by_fleet() {
    let mut input = real_trust_card_input();
    input.active_quarantine = true;
    let id = input.extension.extension_id.clone();
    let mut registry = TrustCardRegistry::default();
    let mut historical = registry.create(input, 100, "historical").unwrap();
    historical.quarantine_sources.clear();
    sign_card_in_place(&mut historical, DEFAULT_REGISTRY_KEY).unwrap();
    let raw = serde_json::to_string(&historical).unwrap();
    assert!(
        !raw.contains("quarantine_sources"),
        "historical encoding remains verifiable"
    );
    let snapshot = TrustCardRegistrySnapshot::signed(
        60,
        BTreeMap::from([(id.clone(), vec![historical])]),
        DEFAULT_REGISTRY_KEY,
    )
    .unwrap();
    let mut loaded = TrustCardRegistry::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, 101).unwrap();
    let source = fleet_source("east", "later-incident");
    let claimed = loaded
        .set_quarantine_source(&id, source.clone(), true, 102, "fleet-quarantine")
        .unwrap();
    assert!(
        claimed
            .quarantine_sources
            .contains(&QuarantineSource::Local)
    );
    let released = loaded
        .set_quarantine_source(&id, source, false, 103, "fleet-release")
        .unwrap();
    assert!(released.active_quarantine);
    assert_eq!(
        released.quarantine_sources,
        BTreeSet::from([QuarantineSource::Local])
    );
}

#[test]
fn replacement_artifact_preserves_containment_and_permanent_revocation() {
    let input = real_trust_card_input();
    let id = input.extension.extension_id.clone();
    let mut registry = TrustCardRegistry::default();
    registry.create(input.clone(), 100, "create").unwrap();
    let source = fleet_source("east", "compromised-publisher");
    registry
        .set_quarantine_source(&id, source.clone(), true, 101, "fleet")
        .unwrap();
    registry
        .update(
            &id,
            TrustCardMutation {
                certification_level: None,
                revocation_status: Some(RevocationStatus::Revoked {
                    reason: "confirmed compromise".to_string(),
                    revoked_at: "2026-10-08T00:00:00Z".to_string(),
                }),
                active_quarantine: Some(true),
                reputation_score_basis_points: None,
                reputation_trend: None,
                user_facing_risk_assessment: None,
                last_verified_timestamp: None,
                evidence_refs: None,
            },
            102,
            "revoke",
        )
        .unwrap();
    let mut replacement = input;
    replacement.extension.version = "2.4.0".to_string();
    let card = registry
        .create(replacement, 103, "replace-artifact")
        .unwrap();
    assert!(matches!(
        card.revocation_status,
        RevocationStatus::Revoked { .. }
    ));
    assert!(card.active_quarantine);
    assert_eq!(
        card.quarantine_sources,
        BTreeSet::from([source.clone(), QuarantineSource::Local])
    );
    registry
        .set_quarantine_source(&id, source, false, 104, "fleet-release")
        .unwrap();
    let card = registry
        .set_quarantine_source(&id, QuarantineSource::Local, false, 105, "local-release")
        .unwrap();
    assert!(
        matches!(card.revocation_status, RevocationStatus::Revoked { .. }),
        "releasing containment never restores revoked trust"
    );
}

#[test]
fn quarantine_ownership_is_signed_and_inconsistent_states_are_rejected() {
    let input = real_trust_card_input();
    let id = input.extension.extension_id.clone();
    let mut registry = TrustCardRegistry::default();
    registry.create(input, 100, "create").unwrap();
    let card = registry
        .set_quarantine_source(
            &id,
            fleet_source("east", "incident"),
            true,
            101,
            "quarantine",
        )
        .unwrap();
    let mut tampered = card.clone();
    tampered.quarantine_sources = BTreeSet::from([fleet_source("west", "incident")]);
    assert!(verify_card_signature(&tampered, DEFAULT_REGISTRY_KEY).is_err());
    let mut inconsistent = card;
    inconsistent.active_quarantine = false;
    assert!(sign_card_in_place(&mut inconsistent, DEFAULT_REGISTRY_KEY).is_err());
}

#[test]
fn quarantine_source_capacity_and_invalid_identity_fail_without_losing_decisions() {
    let input = real_trust_card_input();
    let id = input.extension.extension_id.clone();
    let mut seed = TrustCardRegistry::default();
    let mut card = seed.create(input, 100, "create").unwrap();
    card.active_quarantine = true;
    card.quarantine_sources = (0..MAX_QUARANTINE_SOURCES)
        .map(|index| fleet_source("east", &format!("incident-{index}")))
        .collect();
    sign_card_in_place(&mut card, DEFAULT_REGISTRY_KEY).unwrap();
    let snapshot = TrustCardRegistrySnapshot::signed(
        60,
        BTreeMap::from([(id.clone(), vec![card.clone()])]),
        DEFAULT_REGISTRY_KEY,
    )
    .unwrap();
    let mut registry =
        TrustCardRegistry::from_snapshot(snapshot, DEFAULT_REGISTRY_KEY, 101).unwrap();
    for source in [
        fleet_source("east", "overflow"),
        fleet_source(" east", "bad"),
        fleet_source("east", "bad\nidentity"),
    ] {
        assert!(
            registry
                .set_quarantine_source(&id, source, true, 102, "invalid")
                .is_err()
        );
        let unchanged = registry.read(&id, 103, "read").unwrap().unwrap();
        assert_eq!(unchanged.card_hash, card.card_hash);
        assert_eq!(unchanged.quarantine_sources.len(), MAX_QUARANTINE_SOURCES);
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
fn authoritative_registry_marks_camouflage_hints_on_signed_card() {
    let mut registry = TrustCardRegistry::default();
    let created = registry
        .create(
            real_trust_card_input(),
            1_776_792_600,
            "trace-camouflage-seed",
        )
        .expect("create real trust card");
    let hints = vec![CamouflageHint {
        kind: CamouflageKind::DistributionMismatch,
        severity: 0.93,
        evidence: BTreeMap::from([("distribution_delta".to_string(), 0.93)]),
        sample_indices: vec![7, 8, 9],
    }];

    let marked = registry
        .mark_camouflage_suspected(
            "npm:@operator/auth-guard",
            &hints,
            vec![VerifiedEvidenceRef {
                evidence_id: "trajectory-camouflage-detector-20260514".to_string(),
                evidence_type: EvidenceType::AuditReport,
                verified_at_epoch: 1_778_768_400,
                verification_receipt_hash:
                    "52c4b30c3a1e9a8ef4bbf3160f8f944a52ff604fdc7f502a8c97f9e71f6f3bb8".to_string(),
            }],
            1_778_768_400,
            "trace-camouflage-mark",
        )
        .expect("mark camouflage");

    assert_eq!(marked.trust_card_version, created.trust_card_version + 1);
    assert_eq!(
        marked.previous_version_hash.as_deref(),
        Some(created.card_hash.as_str())
    );
    assert_eq!(
        marked.user_facing_risk_assessment.level,
        RiskLevel::Critical
    );
    assert!(
        marked
            .user_facing_risk_assessment
            .summary
            .contains("suspected trajectory camouflage")
    );
    assert!(
        marked.audit_history.iter().any(|record| {
            record.event_code == TRUST_CARD_CAMOUFLAGE_SUSPECTED
                && record.detail.contains("distribution_mismatch")
        }),
        "camouflage mark must be operator-auditable"
    );
    assert!(
        registry
            .telemetry()
            .iter()
            .any(|event| event.event_code == TRUST_CARD_CAMOUFLAGE_SUSPECTED)
    );

    let fetched = registry
        .read(
            "npm:@operator/auth-guard",
            1_778_768_401,
            "trace-camouflage-read",
        )
        .expect("read marked card")
        .expect("marked card exists");
    assert_eq!(fetched.card_hash, marked.card_hash);
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

    let store = TrustCardRegistryStore::open(&snapshot_path).expect("open durable authority");
    let (raw, high_water) = store
        .load_state()
        .expect("read durable snapshot")
        .expect("authoritative snapshot exists");
    let mut snapshot: TrustCardRegistrySnapshot =
        serde_json::from_str(&raw).expect("parse valid signed snapshot");
    let card = snapshot
        .cards_by_extension
        .get_mut("npm:@operator/auth-guard")
        .expect("extension history")
        .last_mut()
        .expect("latest signed card");
    card.provenance_summary.source_uri = "https://example.invalid/tampered".to_string();
    let tampered = serde_json::to_string(&snapshot).expect("encode structurally valid tampering");
    // Edit the actual authoritative row without recomputing any card or
    // snapshot signature. The database remains readable and its signed
    // high-water marker stays intact, so only integrity validation can refuse.
    store
        .with_immediate_transaction(|_connection, tx| {
            tx.execute_with_params(
                "UPDATE registry_state SET canonical_json = ?1 WHERE slot = 'snapshot';",
                &[fsqlite::SqliteValue::Text(tampered.as_str().into())],
            )
            .map_err(|error| TrustCardError::SnapshotWrite {
                path: store.db_path().to_path_buf(),
                detail: error.to_string(),
            })?;
            Ok(())
        })
        .expect("commit tampered authoritative snapshot");
    assert_eq!(
        store.load_state().expect("database remains readable"),
        Some((tampered, high_water))
    );
    drop(store);

    let err = TrustCardRegistry::load_authoritative_state(
        &snapshot_path,
        60,
        1_776_792_610,
        SnapshotSourceContext::TrustedFile,
    )
    .expect_err("tampered authoritative state must fail closed");
    assert!(
        matches!(
            &err,
            TrustCardError::CardHashMismatch(extension_id)
                if extension_id == "npm:@operator/auth-guard"
        ),
        "expected signed card integrity refusal, got {err}"
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
