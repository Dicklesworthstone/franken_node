//! Mock-free end-to-end test for the trust card lifecycle.
//!
//! Drives the public surface of `frankenengine_node::supply_chain::trust_card`
//! through the canonical issue → register → upgrade → revoke flow plus a
//! snapshot round-trip:
//!
//!   1. real `TrustCardRegistry::new` keyed with an HMAC secret,
//!   2. `create` issues a v1 card with a real verified evidence reference,
//!   3. `read` returns the card and the cache hit re-verifies the signature,
//!   4. `update` upgrades the certification with NEW evidence (monotone
//!      upgrade gate enforced),
//!   5. `update` revokes the card (INV-TC-MONOTONIC-REVOCATION emits a
//!      `TRUST_CARD_REVOKED` event and bans subsequent re-activation),
//!   6. `snapshot` + `from_snapshot` round-trips the registry through a
//!      signed envelope and the loaded registry returns the same revoked
//!      card.
//!
//! Bead: bd-mdc0z.
//!
//! No mocks: real HMAC signatures, real canonical JSON hashing, real
//! BTreeMap-backed cards, real audit history. Each phase emits a structured
//! tracing event PLUS a JSON-line on stderr so a CI failure can be
//! reconstructed from the test transcript.

use std::collections::BTreeMap;
use std::sync::Once;
use std::time::Instant;

use frankenengine_node::security::trajectory_gaming::{CamouflageHint, CamouflageKind};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
    ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCardError, TrustCardInput,
    TrustCardListFilter, TrustCardMutation, TrustCardRegistry, compute_card_hash,
    verify_card_signature,
};
use serde_json::json;
use tracing::{error, info};

static TEST_TRACING_INIT: Once = Once::new();

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

#[derive(serde::Serialize)]
struct PhaseLog<'a> {
    timestamp: String,
    test_name: &'a str,
    phase: &'a str,
    duration_ms: u64,
    success: bool,
    detail: serde_json::Value,
}

struct Harness {
    test_name: &'static str,
    started: Instant,
}

impl Harness {
    fn new(test_name: &'static str) -> Self {
        init_test_tracing();
        let h = Self {
            test_name,
            started: Instant::now(),
        };
        h.log_phase("setup", true, json!({}));
        h
    }

    fn log_phase(&self, phase: &str, success: bool, detail: serde_json::Value) {
        let entry = PhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name,
            phase,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            success,
            detail,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&entry).expect("phase log serializes")
        );
        if success {
            info!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase completed"
            );
        } else {
            error!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase failed"
            );
        }
    }
}

const REGISTRY_KEY: &[u8] = b"e2e-trust-card-lifecycle-key-v1";

fn evidence(id: &str, epoch: u64, hash: &str) -> VerifiedEvidenceRef {
    VerifiedEvidenceRef {
        evidence_id: id.to_string(),
        evidence_type: EvidenceType::ProvenanceChain,
        verified_at_epoch: epoch,
        verification_receipt_hash: hash.to_string(),
    }
}

fn realistic_input(extension_id: &str, version: &str) -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: extension_id.to_string(),
            version: version.to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "pub-e2e-vendor".to_string(),
            display_name: "E2E Vendor".to_string(),
        },
        certification_level: CertificationLevel::Silver,
        capability_declarations: vec![CapabilityDeclaration {
            name: "fs.read".to_string(),
            description: "read a bounded set of project paths".to_string(),
            risk: CapabilityRisk::Low,
        }],
        behavioral_profile: BehavioralProfile {
            network_access: false,
            filesystem_access: true,
            subprocess_access: false,
            profile_summary: "filesystem-only read".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "slsa-l3".to_string(),
            source_uri: "https://example.invalid/e2e-vendor/fs-reader".to_string(),
            artifact_hashes: vec!["sha256:e2e-artifact-hash-001".to_string()],
            verified_at: "2026-04-26T22:00:00Z".to_string(),
        },
        reputation_score_basis_points: 8_500,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: vec![DependencyTrustStatus {
            dependency_id: "npm:fs-utils@1".to_string(),
            trust_level: "verified".to_string(),
        }],
        last_verified_timestamp: "2026-04-26T22:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "low-impact filesystem reader with verified provenance".to_string(),
        },
        evidence_refs: vec![evidence(
            "ev-create-001",
            1_745_750_000,
            "sha256:create-evidence-hash-aaaaaa",
        )],
    }
}

#[test]
fn e2e_trust_card_lifecycle_create_upgrade_revoke_snapshot() {
    let h = Harness::new("e2e_trust_card_lifecycle_create_upgrade_revoke_snapshot");

    // ── ARRANGE: real registry ─────────────────────────────────────
    let mut reg = TrustCardRegistry::new(60, REGISTRY_KEY);
    let extension_id = "npm:@e2e/fs-reader";
    let now0 = 1_745_750_000u64;
    h.log_phase("registry_built", true, json!({"cache_ttl_secs": 60}));

    // ── ACT 1: create v1 card and verify the signed result ─────────
    let v1 = reg
        .create(realistic_input(extension_id, "1.0.0"), now0, "trace-create")
        .expect("v1 create succeeds");
    assert_eq!(v1.trust_card_version, 1);
    assert_eq!(v1.previous_version_hash, None);
    assert!(matches!(v1.revocation_status, RevocationStatus::Active));
    let v1_hash = compute_card_hash(&v1).expect("compute v1 hash");
    assert_eq!(
        v1.card_hash, v1_hash,
        "card_hash field must match compute_card_hash output"
    );
    verify_card_signature(&v1, REGISTRY_KEY).expect("v1 signature verifies");
    h.log_phase(
        "v1_created",
        true,
        json!({"version": v1.trust_card_version, "hash": v1.card_hash}),
    );

    // ── ACT 2: read the card back (cache hit re-verifies signature) ─
    let read = reg
        .read(extension_id, now0 + 1, "trace-read")
        .expect("read succeeds")
        .expect("card is present");
    assert_eq!(read.card_hash, v1.card_hash);
    h.log_phase("read_cache_hit", true, json!({"hash": read.card_hash}));

    // ── ACT 3: upgrade certification with NEW evidence ─────────────
    let upgrade_evidence = vec![evidence(
        "ev-upgrade-002",
        now0 + 100,
        "sha256:upgrade-evidence-hash-bbbbbb",
    )];
    let v2 = reg
        .update(
            extension_id,
            TrustCardMutation {
                certification_level: Some(CertificationLevel::Gold),
                revocation_status: None,
                active_quarantine: None,
                reputation_score_basis_points: None,
                reputation_trend: None,
                user_facing_risk_assessment: None,
                last_verified_timestamp: None,
                evidence_refs: Some(upgrade_evidence.clone()),
            },
            now0 + 100,
            "trace-upgrade",
        )
        .expect("v2 upgrade with evidence succeeds");
    assert_eq!(v2.trust_card_version, 2);
    assert_eq!(
        v2.previous_version_hash.as_deref(),
        Some(v1.card_hash.as_str())
    );
    assert_eq!(v2.certification_level, CertificationLevel::Gold);
    verify_card_signature(&v2, REGISTRY_KEY).expect("v2 signature verifies");
    h.log_phase("v2_upgraded", true, json!({"version": 2, "level": "Gold"}));

    // ── ASSERT: upgrade WITHOUT evidence is rejected ────────────────
    let mutation_without_evidence = TrustCardMutation {
        certification_level: Some(CertificationLevel::Platinum),
        revocation_status: None,
        active_quarantine: None,
        reputation_score_basis_points: None,
        reputation_trend: None,
        user_facing_risk_assessment: None,
        last_verified_timestamp: None,
        evidence_refs: None,
    };
    let bad_upgrade = reg.update(
        extension_id,
        mutation_without_evidence,
        now0 + 200,
        "trace-upgrade-noev",
    );
    assert!(matches!(
        bad_upgrade,
        Err(TrustCardError::EvidenceRequiredForUpgrade)
    ));
    h.log_phase("upgrade_without_evidence_rejected", true, json!({}));

    // ── ACT 4: revoke the card ──────────────────────────────────────
    let revoke = TrustCardMutation {
        certification_level: None,
        revocation_status: Some(RevocationStatus::Revoked {
            reason: "policy-violation".to_string(),
            revoked_at: "2026-04-26T22:05:00Z".to_string(),
        }),
        active_quarantine: Some(true),
        reputation_score_basis_points: None,
        reputation_trend: None,
        user_facing_risk_assessment: None,
        last_verified_timestamp: Some("2026-04-26T22:05:00Z".to_string()),
        evidence_refs: None,
    };
    let v3 = reg
        .update(extension_id, revoke, now0 + 300, "trace-revoke")
        .expect("revoke succeeds");
    assert!(matches!(
        v3.revocation_status,
        RevocationStatus::Revoked { .. }
    ));
    assert!(v3.active_quarantine);
    verify_card_signature(&v3, REGISTRY_KEY).expect("v3 signature verifies");
    h.log_phase(
        "v3_revoked",
        true,
        json!({"version": v3.trust_card_version}),
    );

    // ── ASSERT: INV-TC-MONOTONIC-REVOCATION — cannot transition back ─
    let try_reactivate = TrustCardMutation {
        certification_level: None,
        revocation_status: Some(RevocationStatus::Active),
        active_quarantine: None,
        reputation_score_basis_points: None,
        reputation_trend: None,
        user_facing_risk_assessment: None,
        last_verified_timestamp: None,
        evidence_refs: None,
    };
    let irreversible = reg.update(extension_id, try_reactivate, now0 + 400, "trace-reactivate");
    assert!(matches!(
        irreversible,
        Err(TrustCardError::RevocationIrreversible)
    ));
    h.log_phase("reactivation_rejected", true, json!({}));

    // ── ACT 5: snapshot the registry ───────────────────────────────
    let snapshot = reg.snapshot().expect("snapshot serializes and signs");
    assert!(!snapshot.snapshot_hash.is_empty());
    assert!(!snapshot.registry_signature.is_empty());
    h.log_phase(
        "snapshot",
        true,
        json!({
            "snapshot_hash_len": snapshot.snapshot_hash.len(),
            "epoch": snapshot.snapshot_epoch,
        }),
    );

    // ── ACT 6: round-trip via from_snapshot ─────────────────────────
    let mut reloaded = TrustCardRegistry::from_snapshot(snapshot, REGISTRY_KEY, now0 + 500)
        .expect("from_snapshot succeeds");
    let reloaded_cards = reloaded
        .list(
            &TrustCardListFilter::empty(),
            "trace-list-after-reload",
            now0 + 500,
        )
        .expect("list succeeds after reload");
    let reloaded_v3 = reloaded_cards
        .into_iter()
        .find(|c| c.extension.extension_id == extension_id)
        .expect("v3 present after reload");
    assert_eq!(reloaded_v3.card_hash, v3.card_hash);
    assert!(matches!(
        reloaded_v3.revocation_status,
        RevocationStatus::Revoked { .. }
    ));
    h.log_phase(
        "snapshot_roundtrip_preserves_revocation",
        true,
        json!({"hash": reloaded_v3.card_hash}),
    );

    h.log_phase("teardown", true, json!({}));
}

#[test]
fn e2e_trust_card_evidence_required_at_creation() {
    let h = Harness::new("e2e_trust_card_evidence_required_at_creation");
    let mut reg = TrustCardRegistry::new(60, REGISTRY_KEY);
    let mut input = realistic_input("npm:@e2e/missing-evidence", "0.1.0");
    input.evidence_refs.clear();
    let err = reg
        .create(input, 1_745_750_000, "trace-no-ev")
        .expect_err("creating a card with no evidence is rejected");
    // Don't pin the exact error variant — the contract is "create rejects
    // empty evidence". The internal error variant name (EvidenceRefsMissing /
    // EvidenceRequired / etc.) is private to the implementation.
    h.log_phase(
        "missing_evidence_rejected",
        true,
        json!({"err": format!("{err:?}")}),
    );
}

#[test]
fn e2e_trust_card_revoked_card_signature_still_verifies() {
    let h = Harness::new("e2e_trust_card_revoked_card_signature_still_verifies");
    let mut reg = TrustCardRegistry::new(60, REGISTRY_KEY);
    let extension_id = "npm:@e2e/sig-after-revoke";
    let now = 1_745_750_000u64;
    reg.create(realistic_input(extension_id, "0.0.1"), now, "trace-c")
        .expect("create");
    let revoked = reg
        .update(
            extension_id,
            TrustCardMutation {
                certification_level: None,
                revocation_status: Some(RevocationStatus::Revoked {
                    reason: "anomaly".into(),
                    revoked_at: "2026-04-26T22:10:00Z".into(),
                }),
                active_quarantine: Some(true),
                reputation_score_basis_points: None,
                reputation_trend: None,
                user_facing_risk_assessment: None,
                last_verified_timestamp: None,
                evidence_refs: None,
            },
            now + 50,
            "trace-r",
        )
        .expect("revoke");
    // Even after revocation, the card signature must still verify under the
    // registry key — revocation does NOT invalidate the signed envelope; it
    // moves the card into a non-trusted lifecycle state.
    verify_card_signature(&revoked, REGISTRY_KEY).expect("signature still verifies");
    h.log_phase("post_revoke_signature_ok", true, json!({}));
}

fn no_mutation() -> TrustCardMutation {
    TrustCardMutation {
        certification_level: None,
        revocation_status: None,
        active_quarantine: None,
        reputation_score_basis_points: None,
        reputation_trend: None,
        user_facing_risk_assessment: None,
        last_verified_timestamp: None,
        evidence_refs: None,
    }
}

/// bd-reality-20260923-26n9r.15: a `trust scan --deep/--audit` rescan
/// replaces the scan-owned fields of an existing card while certification,
/// quarantine, revocation, camouflage risk and audit history carry over.
#[test]
fn e2e_trust_card_refresh_from_scan_keeps_operator_decisions() {
    let h = Harness::new("e2e_trust_card_refresh_from_scan_keeps_operator_decisions");
    let mut reg = TrustCardRegistry::new(60, REGISTRY_KEY);
    let extension_id = "npm:@e2e/rescanned";
    let now = 1_745_750_000u64;
    reg.create(realistic_input(extension_id, "2.0.0"), now, "trace-c")
        .expect("create");
    reg.update(
        extension_id,
        TrustCardMutation {
            active_quarantine: Some(true),
            ..no_mutation()
        },
        now + 1,
        "trace-q",
    )
    .expect("quarantine");
    let marked = reg
        .mark_camouflage_suspected(
            extension_id,
            &[CamouflageHint {
                kind: CamouflageKind::GradualCreep,
                severity: 0.7,
                evidence: BTreeMap::from([("slope".to_string(), 0.4)]),
                sample_indices: vec![0, 1, 2, 3],
            }],
            vec![evidence("ev-camo", now + 2, "sha256:camouflage-evidence")],
            now + 2,
            "trace-camo",
        )
        .expect("camouflage mark");
    assert_eq!(marked.user_facing_risk_assessment.level, RiskLevel::High);

    let mut rescan = realistic_input(extension_id, "2.0.0");
    rescan.publisher = PublisherIdentity {
        publisher_id: "npm:maintainer-x".to_string(),
        display_name: "maintainer-x".to_string(),
    };
    rescan.provenance_summary.artifact_hashes = vec!["sha512:rescanned".to_string()];
    rescan.certification_level = CertificationLevel::Unknown;
    rescan.reputation_score_basis_points = 6_000;
    rescan.user_facing_risk_assessment = RiskAssessment {
        level: RiskLevel::Low,
        summary: "rescan: no findings".to_string(),
    };
    rescan.evidence_refs = vec![evidence("ev-rescan", now + 3, "sha256:rescan-evidence")];
    let refreshed = reg
        .refresh_from_scan(rescan, now + 3, "trace-rescan")
        .expect("refresh");
    verify_card_signature(&refreshed, REGISTRY_KEY).expect("refreshed card verifies");
    assert_eq!(refreshed.trust_card_version, marked.trust_card_version + 1);
    assert_eq!(
        refreshed.previous_version_hash.as_deref(),
        Some(marked.card_hash.as_str())
    );
    // Scan-owned fields come from the rescan.
    assert_eq!(refreshed.publisher.publisher_id, "npm:maintainer-x");
    assert_eq!(
        refreshed.provenance_summary.artifact_hashes,
        vec!["sha512:rescanned".to_string()]
    );
    assert_eq!(refreshed.reputation_score_basis_points, 6_000);
    // Operator decisions carry over.
    assert_eq!(refreshed.certification_level, CertificationLevel::Silver);
    assert!(refreshed.active_quarantine);
    assert!(matches!(
        refreshed.revocation_status,
        RevocationStatus::Active
    ));
    assert_eq!(refreshed.camouflage_hints, marked.camouflage_hints);
    // The camouflage floor survives a clean rescan.
    assert_eq!(refreshed.user_facing_risk_assessment.level, RiskLevel::High);
    let summary = &refreshed.user_facing_risk_assessment.summary;
    assert!(summary.starts_with("rescan: no findings"), "{summary}");
    assert!(
        summary.contains("suspected trajectory camouflage (gradual_creep;"),
        "{summary}"
    );
    assert_eq!(
        refreshed.audit_history.len(),
        marked.audit_history.len() + 1
    );
    assert_eq!(
        refreshed
            .audit_history
            .last()
            .map(|record| record.detail.as_str()),
        Some("trust card refreshed from scan")
    );
    h.log_phase(
        "refreshed",
        true,
        json!({"version": refreshed.trust_card_version, "risk": "high"}),
    );

    // Revocation carries over too.
    let revoked_id = "npm:@e2e/rescanned-revoked";
    reg.create(realistic_input(revoked_id, "1.0.0"), now, "trace-c2")
        .expect("create");
    reg.update(
        revoked_id,
        TrustCardMutation {
            revocation_status: Some(RevocationStatus::Revoked {
                reason: "compromised publisher".into(),
                revoked_at: "2026-04-26T22:10:00Z".into(),
            }),
            ..no_mutation()
        },
        now + 1,
        "trace-r",
    )
    .expect("revoke");
    let rescanned_revoked = reg
        .refresh_from_scan(realistic_input(revoked_id, "1.0.0"), now + 2, "trace-rr")
        .expect("refresh revoked card");
    assert!(matches!(
        rescanned_revoked.revocation_status,
        RevocationStatus::Revoked { .. }
    ));

    // A different version is a new artifact, and a missing card has nothing
    // to refresh.
    let err = reg
        .refresh_from_scan(realistic_input(extension_id, "2.1.0"), now + 4, "trace-v")
        .expect_err("version change is not a refresh");
    assert!(
        matches!(err, TrustCardError::InvalidInput { .. }),
        "{err:?}"
    );
    let err = reg
        .refresh_from_scan(
            realistic_input("npm:@e2e/never-scanned", "1.0.0"),
            now + 4,
            "trace-n",
        )
        .expect_err("nothing to refresh");
    assert!(matches!(err, TrustCardError::NotFound(_)), "{err:?}");
    h.log_phase("refusals", true, json!({}));
}
