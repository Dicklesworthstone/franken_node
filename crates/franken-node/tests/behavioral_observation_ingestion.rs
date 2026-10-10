//! Collector-signed test measurements exercising the real verifier, BPET
//! detector, trust-card mutation and WAL-backed registry transaction.
//! These fixtures are not measurements of an npm package or a native run.

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use frankenengine_node::config::{Config, Profile, TrustConfig};
use frankenengine_node::security::trajectory_gaming::CamouflageKind;
use frankenengine_node::supply_chain::behavioral_observation::{
    BehavioralIngestionStatus, BehavioralObservation, SignedBehavioralObservation,
    ingest_observation,
};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    ExtensionIdentity, MAX_CAMOUFLAGE_HINTS_ON_CARD, ProvenanceSummary, PublisherIdentity,
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, SnapshotSourceContext, TrustCard,
    TrustCardInput, TrustCardMutation, TrustCardRegistry, TrustCardRegistrySnapshot,
};
use frankenengine_node::supply_chain::trust_card_registry_store::{
    TrustCardRegistryStore, registry_snapshot_path,
};
use fsqlite::SqliteValue;
use fsqlite::compat::TransactionExt;
use tempfile::TempDir;

const NOW: u64 = 2_000;
const EXTENSION: &str = "npm:@fixture/observed-package";

struct Fixture {
    _directory: TempDir,
    snapshot: PathBuf,
    trust: TrustConfig,
    collector: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("fixture directory");
        let snapshot = registry_snapshot_path(directory.path());
        let mut trust = Config::for_profile(Profile::Balanced).trust;
        trust.registry_signing_key =
            Some(base64::engine::general_purpose::STANDARD.encode([0x51_u8; 32]));
        let mut registry = TrustCardRegistry::from_config(&trust).expect("configured registry");
        registry
            .create(card_input("1.0.0", &artifact(1)), NOW, "fixture-seed")
            .expect("seed known artifact");
        registry
            .persist_authoritative_state(&snapshot)
            .expect("persist fixture");
        Self {
            _directory: directory,
            snapshot,
            trust,
            collector: SigningKey::from_bytes(&[0x72; 32]),
        }
    }

    fn registry(&self) -> TrustCardRegistry {
        TrustCardRegistry::load_authoritative_state_from_config(
            &self.snapshot,
            &self.trust,
            NOW,
            SnapshotSourceContext::TrustedFile,
        )
        .expect("reload authentic registry")
    }

    fn card(&self) -> TrustCard {
        self.registry()
            .read(EXTENSION, NOW, "fixture-read")
            .unwrap()
            .unwrap()
    }

    fn state(&self) -> (String, Option<String>) {
        TrustCardRegistryStore::open(&self.snapshot)
            .unwrap()
            .load_state()
            .unwrap()
            .unwrap()
    }

    fn journal(&self, stream: &str) -> String {
        TrustCardRegistryStore::open(&self.snapshot)
            .unwrap()
            .with_immediate_transaction(|connection, _| {
                let rows = connection
                    .query_with_params(
                        "SELECT canonical_json FROM registry_state WHERE slot = ?1;",
                        &[SqliteValue::Text(
                            format!("behavioral-observations:{stream}").into(),
                        )],
                    )
                    .expect("read fixture journal");
                let SqliteValue::Text(value) = &rows[0].values()[0] else {
                    panic!("journal must contain text");
                };
                Ok(value.to_string())
            })
            .unwrap()
    }

    // Simulate storage corruption without the registry signing key: the signed
    // snapshot/high-water remain untouched, and the real WAL store is used.
    fn replace_journal(&self, stream: &str, encoded: Option<&str>) {
        TrustCardRegistryStore::open(&self.snapshot)
            .unwrap()
            .with_immediate_transaction(|_, tx| {
                let slot = SqliteValue::Text(format!("behavioral-observations:{stream}").into());
                match encoded {
                    Some(value) => {
                        tx.execute_with_params(
                            "INSERT INTO registry_state(slot, canonical_json) VALUES (?1, ?2)
                             ON CONFLICT(slot) DO UPDATE SET canonical_json = excluded.canonical_json;",
                            &[slot, SqliteValue::Text(value.into())],
                        )
                        .expect("replace fixture journal");
                    }
                    None => {
                        tx.execute_with_params(
                            "DELETE FROM registry_state WHERE slot = ?1;",
                            &[slot],
                        )
                        .expect("remove fixture journal row");
                    }
                }
                Ok(())
            })
            .unwrap();
    }

    fn ingest(
        &self,
        observation: &SignedBehavioralObservation,
    ) -> anyhow::Result<
        frankenengine_node::supply_chain::behavioral_observation::BehavioralIngestionReport,
    > {
        ingest_observation(
            &self.snapshot,
            &self.trust,
            &serde_json::to_vec(observation)?,
            &self.collector.verifying_key(),
            NOW,
        )
    }
}

fn artifact(byte: u8) -> String {
    format!("sha256:{}", hex::encode([byte; 32]))
}

fn card_input(version: &str, digest: &str) -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: EXTENSION.to_string(),
            version: version.to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "fixture-collector-subject".to_string(),
            display_name: "Explicit test package".to_string(),
        },
        certification_level: CertificationLevel::Bronze,
        capability_declarations: vec![CapabilityDeclaration {
            name: "network.requests".to_string(),
            description: "Test workload dimension".to_string(),
            risk: CapabilityRisk::Medium,
        }],
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: false,
            subprocess_access: false,
            profile_summary: "Collector-signed fixture; not a measured npm package".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "fixture".to_string(),
            source_uri: "fixture://behavioral-observation".to_string(),
            artifact_hashes: vec![digest.to_string()],
            verified_at: "1970-01-01T00:30:00Z".to_string(),
        },
        reputation_score_basis_points: 900,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: vec![],
        last_verified_timestamp: "1970-01-01T00:30:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Fixture baseline".to_string(),
        },
        evidence_refs: vec![VerifiedEvidenceRef {
            evidence_id: "fixture-seed".to_string(),
            evidence_type: EvidenceType::ProvenanceChain,
            verified_at_epoch: NOW,
            verification_receipt_hash: artifact(9),
        }],
    }
}

fn observation(
    sequence: u64,
    previous: Option<&SignedBehavioralObservation>,
    count: u64,
) -> BehavioralObservation {
    BehavioralObservation {
        extension_id: EXTENSION.to_string(),
        package_version: "1.0.0".to_string(),
        artifact_hash: artifact(1),
        workload_id: "isolated-request-fixture-v1".to_string(),
        measurement_scope: "isolated_package".to_string(),
        sequence,
        observed_at_epoch_secs: 1_000 + sequence,
        window_duration_ms: 1_000,
        workload_iterations: 1,
        previous_observation_id: previous.map(|value| value.observation_id().unwrap()),
        observed_capabilities: BTreeMap::from([("network.requests".to_string(), count)]),
        declared_capabilities: BTreeMap::from([("network.requests".to_string(), 100)]),
    }
}

#[test]
fn authentic_observations_survive_restart_and_raise_card_risk_through_real_bpet() {
    let fixture = Fixture::new();
    let mut previous = None;
    let mut last_report = None;
    for sequence in 0..4 {
        let signed = SignedBehavioralObservation::sign(
            observation(sequence, previous.as_ref(), 100 + sequence * 5),
            &fixture.collector,
        )
        .unwrap();
        let report = fixture
            .ingest(&signed)
            .expect("authenticated observation admitted");
        assert_eq!(report.status, BehavioralIngestionStatus::Accepted);
        assert_eq!(report.sample_count, usize::try_from(sequence).unwrap() + 1);
        assert_eq!(fixture.card().card_hash, report.card_hash);
        if sequence < 3 {
            assert!(
                report.hints.is_empty(),
                "insufficient samples are not findings"
            );
        }
        previous = Some(signed);
        last_report = Some(report);
    }
    let report = last_report.unwrap();
    assert!(
        report
            .hints
            .iter()
            .any(|hint| hint.kind == CamouflageKind::GradualCreep)
    );
    assert!(report.risk_level >= RiskLevel::High);
    let card = fixture.card();
    assert!(!card.camouflage_hints.is_empty());
    let reference = &card.derivation_evidence.unwrap().evidence_refs[0];
    assert_eq!(reference.evidence_id, report.evidence_ref);
    assert_eq!(reference.verification_receipt_hash, report.observation_id);

    let before = fixture.state();
    let duplicate = fixture.ingest(previous.as_ref().unwrap()).unwrap();
    assert_eq!(duplicate.status, BehavioralIngestionStatus::Duplicate);
    assert_eq!(duplicate.card_hash, report.card_hash);
    assert_eq!(duplicate.sample_count, 4);
    assert_eq!(
        fixture.state(),
        before,
        "duplicate must not append a card or advance the high-water"
    );
}

#[test]
fn untrusted_or_modified_observation_cannot_mutate_any_registry_state() {
    let fixture = Fixture::new();
    let good =
        SignedBehavioralObservation::sign(observation(0, None, 100), &fixture.collector).unwrap();
    let before = fixture.state();
    let mut tampered = good.clone();
    tampered
        .observation
        .observed_capabilities
        .insert("network.requests".to_string(), 900);
    assert!(
        fixture
            .ingest(&tampered)
            .unwrap_err()
            .to_string()
            .contains("signature")
    );
    let other = SigningKey::from_bytes(&[0x73; 32]);
    let wrong_key = SignedBehavioralObservation::sign(observation(0, None, 100), &other).unwrap();
    assert!(
        fixture
            .ingest(&wrong_key)
            .unwrap_err()
            .to_string()
            .contains("pinned")
    );
    assert_eq!(fixture.state(), before);

    for wrong_field in ["version", "artifact", "subject"] {
        let mut value = observation(0, None, 100);
        match wrong_field {
            "version" => value.package_version = "2.0.0".to_string(),
            "artifact" => value.artifact_hash = artifact(2),
            _ => value.extension_id = "npm:@fixture/untracked".to_string(),
        }
        let signed = SignedBehavioralObservation::sign(value, &fixture.collector).unwrap();
        assert!(
            fixture.ingest(&signed).is_err(),
            "must reject mismatched {wrong_field}"
        );
        assert_eq!(fixture.state(), before);
    }
    assert_eq!(
        fixture.ingest(&good).unwrap().sample_count,
        1,
        "rejections cannot consume sequence zero"
    );
}

#[test]
fn forks_skips_reordered_time_and_changed_measurement_contract_are_rejected() {
    let fixture = Fixture::new();
    let first =
        SignedBehavioralObservation::sign(observation(0, None, 100), &fixture.collector).unwrap();
    fixture.ingest(&first).unwrap();
    let before = fixture.state();
    for invalid in [
        "fork",
        "skip",
        "predecessor",
        "time",
        "window",
        "iterations",
        "declarations",
    ] {
        let mut value = observation(1, Some(&first), 105);
        match invalid {
            "fork" => value.sequence = 0,
            "skip" => value.sequence = 2,
            "predecessor" => value.previous_observation_id = Some(artifact(7)),
            "time" => value.observed_at_epoch_secs = 1_000,
            "window" => value.window_duration_ms = 2_000,
            "iterations" => value.workload_iterations = 2,
            _ => {
                value
                    .declared_capabilities
                    .insert("network.requests".to_string(), 200);
            }
        }
        let signed = SignedBehavioralObservation::sign(value, &fixture.collector).unwrap();
        assert!(fixture.ingest(&signed).is_err(), "must reject {invalid}");
        assert_eq!(fixture.state(), before);
    }
    let next =
        SignedBehavioralObservation::sign(observation(1, Some(&first), 105), &fixture.collector)
            .unwrap();
    assert_eq!(fixture.ingest(&next).unwrap().sample_count, 2);
}

#[test]
fn version_transition_keeps_lineage_but_requires_the_new_verified_artifact() {
    let fixture = Fixture::new();
    let first =
        SignedBehavioralObservation::sign(observation(0, None, 100), &fixture.collector).unwrap();
    fixture.ingest(&first).unwrap();
    let mut registry = fixture.registry();
    registry
        .create(
            card_input("2.0.0", &artifact(2)),
            NOW,
            "fixture-version-change",
        )
        .unwrap();
    registry
        .persist_authoritative_state(&fixture.snapshot)
        .unwrap();
    let mut next = observation(1, Some(&first), 105);
    next.package_version = "2.0.0".to_string();
    let wrong_artifact =
        SignedBehavioralObservation::sign(next.clone(), &fixture.collector).unwrap();
    assert!(fixture.ingest(&wrong_artifact).is_err());
    next.artifact_hash = artifact(2);
    let next = SignedBehavioralObservation::sign(next, &fixture.collector).unwrap();
    let report = fixture.ingest(&next).unwrap();
    assert_eq!(report.sample_count, 2);
    assert_eq!(report.package_version, "2.0.0");
    assert_eq!(
        fixture.ingest(&first).unwrap().status,
        BehavioralIngestionStatus::Duplicate
    );
}

#[test]
fn signature_preimage_is_order_independent_at_transport_and_rejects_duplicate_metrics() {
    let fixture = Fixture::new();
    let signed =
        SignedBehavioralObservation::sign(observation(0, None, 100), &fixture.collector).unwrap();
    let pretty = serde_json::to_vec_pretty(&serde_json::to_value(&signed).unwrap()).unwrap();
    let report = ingest_observation(
        &fixture.snapshot,
        &fixture.trust,
        &pretty,
        &fixture.collector.verifying_key(),
        NOW,
    )
    .unwrap();
    assert_eq!(report.observation_id, signed.observation_id().unwrap());
    let before = fixture.state();
    let raw = serde_json::to_string(&signed).unwrap().replace(
        "\"observed_capabilities\":{\"network.requests\":100}",
        "\"observed_capabilities\":{\"network.requests\":999,\"network.requests\":100}",
    );
    assert!(raw.contains("999"));
    assert!(
        ingest_observation(
            &fixture.snapshot,
            &fixture.trust,
            raw.as_bytes(),
            &fixture.collector.verifying_key(),
            NOW
        )
        .is_err()
    );
    assert_eq!(fixture.state(), before);
}

#[test]
fn incomplete_scope_and_numeric_claims_are_not_accepted_as_measurements() {
    let key = SigningKey::from_bytes(&[0x74; 32]);
    for invalid in [
        "scope",
        "unknown",
        "zero_denominator",
        "future_range",
        "range_version",
        "prerelease",
        "short_digest",
    ] {
        let mut value = observation(0, None, 100);
        match invalid {
            "scope" => value.measurement_scope = "whole_application".to_string(),
            "unknown" => value.observed_capabilities.clear(),
            "zero_denominator" => {
                value
                    .declared_capabilities
                    .insert("network.requests".to_string(), 0);
            }
            "future_range" => value.observed_at_epoch_secs = u64::MAX,
            "range_version" => value.package_version = "^1.0.0".to_string(),
            "prerelease" => value.package_version = "1.0.0-01".to_string(),
            _ => value.artifact_hash = "sha256:abcd".to_string(),
        }
        assert!(
            SignedBehavioralObservation::sign(value, &key).is_err(),
            "invalid {invalid}"
        );
    }
}

#[test]
fn equivalent_workload_rates_have_equivalent_findings_and_small_noise_is_not_a_phase_shift() {
    let fixture = Fixture::new();
    let mut comparable_hints = Vec::new();
    for factor in [1_u64, 10] {
        let mut previous = None;
        for sequence in 0..16 {
            let count = if sequence < 8 { 100 } else { 150 };
            let mut value = observation(sequence, previous.as_ref(), count * factor);
            value.workload_id = format!("rate-equivalence-{factor}");
            value.workload_iterations = 100 * factor;
            value
                .declared_capabilities
                .insert("network.requests".to_string(), 100 * factor);
            let signed = SignedBehavioralObservation::sign(value, &fixture.collector).unwrap();
            let report = fixture.ingest(&signed).unwrap();
            if sequence == 15 {
                comparable_hints.push(report.hints);
            }
            previous = Some(signed);
        }
    }
    assert!(
        comparable_hints[0]
            .iter()
            .any(|hint| hint.kind == CamouflageKind::PhaseShift)
    );
    assert_eq!(comparable_hints[0], comparable_hints[1]);

    let mut previous = None;
    // The detector needs two complete eight-sample phase windows. A shorter
    // sequence would not test its scale-dependent phase threshold at all.
    for sequence in 0..16 {
        let mut value = observation(
            sequence,
            previous.as_ref(),
            if sequence < 8 { 100 } else { 101 },
        );
        value.workload_id = "one-extra-event-in-one-hundred-iterations".to_string();
        value.workload_iterations = 100;
        let signed = SignedBehavioralObservation::sign(value, &fixture.collector).unwrap();
        let report = fixture.ingest(&signed).unwrap();
        assert!(
            report
                .hints
                .iter()
                .all(|hint| hint.kind != CamouflageKind::PhaseShift),
            "one event across one hundred iterations is 0.01 events/iteration, not a unit phase shift"
        );
        previous = Some(signed);
    }
}

#[test]
fn standalone_verification_enforces_clock_skew_without_a_registry() {
    let key = SigningKey::from_bytes(&[0x75; 32]);
    let mut value = observation(0, None, 100);
    value.observed_at_epoch_secs = NOW + 301;
    let future = SignedBehavioralObservation::sign(value.clone(), &key).unwrap();
    assert!(future.verify(&key.verifying_key(), NOW).is_err());
    value.observed_at_epoch_secs = NOW + 300;
    SignedBehavioralObservation::sign(value.clone(), &key)
        .unwrap()
        .verify(&key.verifying_key(), NOW)
        .unwrap();
    value.observed_at_epoch_secs = 0;
    SignedBehavioralObservation::sign(value, &key)
        .unwrap()
        .verify(&key.verifying_key(), NOW)
        .unwrap();
}

#[test]
fn modified_rolled_back_or_deleted_journal_cannot_reopen_an_admitted_stream() {
    let fixture = Fixture::new();
    let first =
        SignedBehavioralObservation::sign(observation(0, None, 100), &fixture.collector).unwrap();
    let first_report = fixture.ingest(&first).unwrap();
    let first_journal = fixture.journal(&first_report.stream_id);
    let next =
        SignedBehavioralObservation::sign(observation(1, Some(&first), 105), &fixture.collector)
            .unwrap();
    fixture.ingest(&next).unwrap();
    let current_journal = fixture.journal(&first_report.stream_id);
    let before = fixture.state();

    let mut modified: serde_json::Value = serde_json::from_str(&current_journal).unwrap();
    modified["entries"][0]["report"]["risk_level"] = serde_json::json!("critical");
    fixture.replace_journal(&first_report.stream_id, Some(&modified.to_string()));
    assert!(
        fixture
            .ingest(&first)
            .unwrap_err()
            .to_string()
            .contains("authentication")
    );
    assert_eq!(fixture.state(), before);

    fixture.replace_journal(&first_report.stream_id, Some(&first_journal));
    assert!(
        fixture
            .ingest(&next)
            .unwrap_err()
            .to_string()
            .contains("retained signed registry head")
    );
    assert_eq!(fixture.state(), before);

    fixture.replace_journal(&first_report.stream_id, None);
    assert!(
        fixture
            .ingest(&first)
            .unwrap_err()
            .to_string()
            .contains("retained signed registry head")
    );
    assert_eq!(fixture.state(), before);

    fixture.replace_journal(&first_report.stream_id, Some(&current_journal));
    assert_eq!(
        fixture.ingest(&first).unwrap().status,
        BehavioralIngestionStatus::Duplicate
    );
    assert_eq!(fixture.state(), before);
}

#[test]
fn retained_stream_head_survives_card_history_eviction_and_is_authenticated() {
    let fixture = Fixture::new();
    let first =
        SignedBehavioralObservation::sign(observation(0, None, 100), &fixture.collector).unwrap();
    let report = fixture.ingest(&first).unwrap();
    let mut registry = fixture.registry();
    // Exercise the production bounded-history eviction path. Each newly
    // derived card has its own audit list, leaving no observation trace in
    // retained card history after the old versions age out.
    for _ in 0..512 {
        registry
            .create(card_input("1.0.0", &artifact(1)), NOW, "fixture-rederive")
            .unwrap();
    }
    let snapshot = registry.snapshot().unwrap();
    assert!(snapshot.cards_by_extension[EXTENSION].iter().all(|card| {
        card.audit_history
            .iter()
            .all(|event| !event.trace_id.starts_with("behavior:"))
    }));
    assert_eq!(
        snapshot.behavioral_observation_heads.get(&report.stream_id),
        Some(&report.observation_id)
    );
    registry
        .persist_authoritative_state(&fixture.snapshot)
        .unwrap();
    let before = fixture.state();
    fixture.replace_journal(&report.stream_id, None);
    assert!(
        fixture
            .ingest(&first)
            .unwrap_err()
            .to_string()
            .contains("retained signed registry head")
    );
    assert_eq!(fixture.state(), before);

    let mut tampered = snapshot;
    tampered.behavioral_observation_heads.clear();
    assert!(
        TrustCardRegistry::from_snapshot(tampered, &[0x51; 32], NOW).is_err(),
        "removing retained commitments invalidates the snapshot signature"
    );
}

#[test]
fn snapshots_without_observations_keep_the_legacy_signed_shape() {
    let snapshot = TrustCardRegistrySnapshot::signed(60, BTreeMap::new(), &[0x51; 32]).unwrap();
    let encoded = serde_json::to_value(&snapshot).unwrap();
    assert!(encoded.get("behavioral_observation_heads").is_none());
    let restored: TrustCardRegistrySnapshot = serde_json::from_value(encoded).unwrap();
    assert_eq!(restored, snapshot);
    TrustCardRegistry::from_snapshot(restored, &[0x51; 32], NOW).unwrap();
}

#[test]
fn generic_risk_updates_preserve_the_retained_camouflage_floor() {
    let fixture = Fixture::new();
    let mut previous = None;
    for sequence in 0..4 {
        let signed = SignedBehavioralObservation::sign(
            observation(sequence, previous.as_ref(), 100 + sequence * 5),
            &fixture.collector,
        )
        .unwrap();
        fixture.ingest(&signed).unwrap();
        previous = Some(signed);
    }
    let mut registry = fixture.registry();
    let card = registry
        .update(
            EXTENSION,
            TrustCardMutation {
                certification_level: None,
                revocation_status: None,
                active_quarantine: None,
                reputation_score_basis_points: None,
                reputation_trend: None,
                user_facing_risk_assessment: Some(RiskAssessment {
                    level: RiskLevel::Low,
                    summary: "An unrelated source is clean".to_string(),
                }),
                last_verified_timestamp: None,
                evidence_refs: None,
            },
            NOW,
            "fixture-clean-refresh",
        )
        .unwrap();
    assert_eq!(card.user_facing_risk_assessment.level, RiskLevel::Critical);
    assert!(
        card.user_facing_risk_assessment
            .summary
            .contains("suspected trajectory camouflage")
    );
}

#[test]
fn more_detector_findings_than_card_capacity_still_commit_with_full_evidence_and_max_risk() {
    let fixture = Fixture::new();
    let mut previous = None;
    let mut last_report = None;
    // Seventeen real detector windows: repeated measured-zero dropouts and
    // alternating spike magnitudes produce phase/distribution findings too.
    // This exceeds the card's 64-record bound within the supported stream.
    for sequence in 0..136 {
        let count = if sequence % 8 == 7 {
            if (sequence / 8) % 2 == 0 { 100 } else { 1_000 }
        } else {
            0
        };
        let mut value = observation(sequence, previous.as_ref(), count);
        value.workload_id = "many-findings-fixture".to_string();
        value.observed_capabilities = (0..32)
            .map(|dimension| (format!("fixture.dimension.{dimension:02}"), count))
            .collect();
        value.declared_capabilities = (0..32)
            .map(|dimension| (format!("fixture.dimension.{dimension:02}"), 100))
            .collect();
        let signed = SignedBehavioralObservation::sign(value, &fixture.collector).unwrap();
        let report = fixture
            .ingest(&signed)
            .expect("valid stream remains ingestible above card hint capacity");
        assert_eq!(report.status, BehavioralIngestionStatus::Accepted);
        previous = Some(signed);
        last_report = Some(report);
    }
    let report = last_report.unwrap();
    assert!(report.hints.len() > MAX_CAMOUFLAGE_HINTS_ON_CARD);
    let card = fixture.card();
    assert_eq!(card.camouflage_hints.len(), MAX_CAMOUFLAGE_HINTS_ON_CARD);
    let strongest_report = report
        .hints
        .iter()
        .map(|hint| hint.severity)
        .max_by(f64::total_cmp)
        .unwrap();
    let strongest_card = card
        .camouflage_hints
        .iter()
        .map(|hint| hint.severity)
        .max_by(f64::total_cmp)
        .unwrap();
    assert_eq!(strongest_card, strongest_report);
    assert_eq!(card.user_facing_risk_assessment.level, RiskLevel::Critical);
    assert_eq!(report.risk_level, RiskLevel::Critical);
    let stored: serde_json::Value =
        serde_json::from_str(&fixture.journal(&report.stream_id)).unwrap();
    assert_eq!(
        stored["entries"][135]["report"]["hints"]
            .as_array()
            .unwrap()
            .len(),
        report.hints.len()
    );
    let duplicate = fixture.ingest(previous.as_ref().unwrap()).unwrap();
    assert_eq!(duplicate.status, BehavioralIngestionStatus::Duplicate);
    assert_eq!(duplicate.hints, report.hints);
}
