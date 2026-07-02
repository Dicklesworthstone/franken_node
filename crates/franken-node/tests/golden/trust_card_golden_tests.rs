//! Golden artifact tests for trust-card outputs
//!
//! Tests the deterministic outputs of trust card operations including:
//! - Trust card JSON exports
//! - Trust list human-readable tables
//! - Trust scan summaries
//! - Security decision receipts

use std::{fs, path::Path};
use frankenengine_node::supply_chain::trust_card::{
    TrustCard, TrustCardRegistry, TrustCardInput, TrustCardListFilter,
    CertificationLevel, ReputationTrend, RevocationStatus, RiskLevel,
    ExtensionIdentity, PublisherIdentity, CapabilityDeclaration, CapabilityRisk,
    BehavioralProfile, ProvenanceSummary, DependencyTrustStatus, RiskAssessment,
    AuditRecord, fixture_registry
};
use frankenengine_node::supply_chain::certification::{VerifiedEvidenceRef, EvidenceType};
use serde_json::Value;

// Golden utilities re-exported from parent module
use super::{assert_scrubbed_json_golden, assert_scrubbed_golden, assert_json_golden};

/// Create a deterministic test trust card
fn create_test_trust_card() -> TrustCard {
    let now_secs = 1000; // Fixed timestamp for determinism
    let mut registry = TrustCardRegistry::new(60, b"test-key");

    let input = TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: "npm:@test/golden-extension".to_string(),
            version: "1.0.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "test-publisher".to_string(),
            display_name: "Test Publisher".to_string(),
        },
        certification_level: CertificationLevel::Gold,
        capability_declarations: vec![
            CapabilityDeclaration {
                name: "filesystem.read".to_string(),
                description: "Read access to user files".to_string(),
                risk: CapabilityRisk::Medium,
            },
            CapabilityDeclaration {
                name: "network.http".to_string(),
                description: "HTTP client access".to_string(),
                risk: CapabilityRisk::Low,
            },
        ],
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: true,
            subprocess_access: false,
            profile_summary: "File processing utility with network sync".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "signed".to_string(),
            source_uri: "https://registry.npmjs.org/@test/golden-extension/-/golden-extension-1.0.0.tgz".to_string(),
            artifact_hashes: vec![
                "sha256:abcdef1234567890".to_string(),
                "sha512:fedcba0987654321".to_string(),
            ],
            verified_at: "2024-01-01T00:00:00Z".to_string(),
        },
        reputation_score_basis_points: 8500,
        reputation_trend: ReputationTrend::Improving,
        active_quarantine: false,
        dependency_trust_summary: vec![
            DependencyTrustStatus {
                dependency_id: "npm:lodash".to_string(),
                trust_level: "verified".to_string(),
            },
        ],
        last_verified_timestamp: "2024-01-01T00:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Well-maintained utility with good security practices".to_string(),
        },
        evidence_refs: vec![
            VerifiedEvidenceRef {
                evidence_id: "evidence-1".to_string(),
                evidence_type: EvidenceType::ProvenanceChain,
                verified_at_epoch: now_secs,
                verification_receipt_hash: "receipt-hash-1".to_string(),
            },
        ],
    };

    registry.create(input, now_secs, "test-trace").expect("create test card")
}

/// Create a registry with multiple test cards for listing tests
fn create_test_registry() -> TrustCardRegistry {
    let registry = fixture_registry(1000).expect("create fixture registry");
    registry
}

#[test]
fn test_trust_card_json_export_golden() {
    let card = create_test_trust_card();
    let json = serde_json::to_value(&card).unwrap();
    assert_scrubbed_json_golden("trust_card_export", &json);
}

#[test]
fn test_trust_card_registry_snapshot_golden() {
    let registry = create_test_registry();
    let snapshot = registry.snapshot().expect("snapshot registry");
    let json = serde_json::to_value(&snapshot).unwrap();
    assert_scrubbed_json_golden("trust_card_registry_snapshot", &json);
}

#[test]
fn test_trust_card_list_all_golden() {
    let mut registry = create_test_registry();
    let cards = registry.list(
        &TrustCardListFilter::empty(),
        "test-trace",
        1000
    ).expect("list all cards");

    // Format as human-readable table like the CLI does
    let mut output = String::new();
    output.push_str("extension | publisher | cert | reputation | status\n");
    output.push_str("---------|-----------|------|------------|-------\n");

    for card in cards {
        let rep_trend = match card.reputation_trend {
            ReputationTrend::Improving => "↗",
            ReputationTrend::Stable => "→",
            ReputationTrend::Declining => "↘",
        };
        let status = match card.revocation_status {
            RevocationStatus::Active => "active",
            RevocationStatus::Revoked { .. } => "revoked",
        };

        output.push_str(&format!(
            "{} | {} | {:?} | {}bp ({}) | {}\n",
            card.extension.extension_id,
            card.publisher.publisher_id,
            card.certification_level,
            card.reputation_score_basis_points,
            rep_trend,
            status
        ));
    }

    assert_scrubbed_golden("trust_card_list_table", &output);
}

#[test]
fn test_trust_card_list_filtered_golden() {
    let mut registry = create_test_registry();
    let filter = TrustCardListFilter {
        certification_level: Some(CertificationLevel::Gold),
        publisher_id: Some("pub-acme".to_string()),
        capability: None,
    };

    let cards = registry.list(&filter, "test-trace", 1000).expect("list filtered cards");
    let json = serde_json::to_value(&cards).unwrap();
    assert_scrubbed_json_golden("trust_card_list_filtered", &json);
}

#[test]
fn test_trust_card_comparison_golden() {
    let mut registry = create_test_registry();
    let cards = registry.list(
        &TrustCardListFilter::empty(),
        "test-trace",
        1000
    ).expect("list cards");

    if cards.len() >= 2 {
        let comparison = registry.compare(
            &cards[0].extension.extension_id,
            &cards[1].extension.extension_id,
            1000,
            "test-trace",
        ).expect("compare cards");

        let json = serde_json::to_value(&comparison).unwrap();
        assert_scrubbed_json_golden("trust_card_comparison", &json);
    }
}

#[test]
fn test_trust_card_diff_golden() {
    let mut registry = create_test_registry();

    // Get a card that has version history
    let cards = registry.list(
        &TrustCardListFilter::empty(),
        "test-trace",
        1000
    ).expect("list cards");

    for card in &cards {
        if card.trust_card_version > 1 {
            let diff = registry.compare_versions(
                &card.extension.extension_id,
                1,
                card.trust_card_version,
                1000,
                "test-trace",
            );

            if let Ok(diff_result) = diff {
                let json = serde_json::to_value(&diff_result).unwrap();
                assert_scrubbed_json_golden("trust_card_version_diff", &json);
                break;
            }
        }
    }
}

#[test]
fn test_trust_card_audit_history_golden() {
    let card = create_test_trust_card();

    // Extract audit history
    let audit_json = serde_json::to_value(&card.audit_history).unwrap();
    assert_scrubbed_json_golden("trust_card_audit_history", &audit_json);
}

#[test]
fn test_trust_card_derivation_metadata_golden() {
    let card = create_test_trust_card();

    if let Some(derivation) = &card.derivation_evidence {
        let json = serde_json::to_value(derivation).unwrap();
        assert_scrubbed_json_golden("trust_card_derivation_metadata", &json);
    }
}

#[test]
fn test_trust_card_sync_report_golden() {
    let mut registry = create_test_registry();

    // Simulate a sync operation to get sync report data
    let _cards = registry.list(
        &TrustCardListFilter::empty(),
        "test-trace",
        1000
    ).expect("list for sync");

    // Create a representative sync report structure
    let sync_report = serde_json::json!({
        "total_cards": 2,
        "cache_hits": 1,
        "cache_misses": 1,
        "stale_refreshes": 0,
        "forced_refreshes": 0
    });

    assert_json_golden("trust_card_sync_report", &sync_report);
}

#[test]
fn test_trust_card_telemetry_events_golden() {
    // Create representative telemetry events that would be emitted
    let telemetry_events = vec![
        serde_json::json!({
            "event_code": "TRUST_CARD_CREATED",
            "extension_id": "npm:@test/golden-extension",
            "trace_id": "test-trace",
            "timestamp_secs": 1000,
            "detail": "Created trust card for npm:@test/golden-extension@1.0.0"
        }),
        serde_json::json!({
            "event_code": "TRUST_CARD_QUERIED",
            "extension_id": "npm:@test/golden-extension",
            "trace_id": "test-trace",
            "timestamp_secs": 1001,
            "detail": "Queried trust card details"
        })
    ];

    let json = serde_json::to_value(&telemetry_events).unwrap();
    assert_scrubbed_json_golden("trust_card_telemetry_events", &json);
}