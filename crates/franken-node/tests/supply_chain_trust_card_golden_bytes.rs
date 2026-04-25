//! Golden byte tests for the trust-card canonical encoder.
//!
//! Freezes representative canonical JSON byte outputs so serializer drift
//! requires an explicit golden update review.

use std::{fs, path::PathBuf};

use frankenengine_node::{
    security::constant_time::ct_eq_bytes,
    supply_chain::trust_card::{
        AuditRecord, BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
        DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
        ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCard, to_canonical_json,
    },
};

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/trust_card_encoder")
        .join(format!("{name}.golden"))
}

fn repeated_hex(byte: &str, count: usize) -> String {
    byte.repeat(count)
}

fn base_trust_card() -> TrustCard {
    TrustCard {
        schema_version: "trust-card-v1.0".to_string(),
        trust_card_version: 7,
        previous_version_hash: None,
        extension: ExtensionIdentity {
            extension_id: "npm:@acme/trust-probe".to_string(),
            version: "3.2.1".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "acme-publisher".to_string(),
            display_name: "ACME Publisher".to_string(),
        },
        certification_level: CertificationLevel::Silver,
        capability_declarations: vec![CapabilityDeclaration {
            name: "network.scan".to_string(),
            description: "Inspect remote endpoints for known signatures".to_string(),
            risk: CapabilityRisk::Medium,
        }],
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: false,
            subprocess_access: false,
            profile_summary: "Network-only inspection with no local mutation.".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "L3-verified-build".to_string(),
            source_uri: "https://github.com/acme/trust-probe".to_string(),
            artifact_hashes: vec![
                format!("sha256:{}", repeated_hex("1a", 32)),
                format!("sha256:{}", repeated_hex("2b", 32)),
            ],
            verified_at: "2026-04-24T12:00:00Z".to_string(),
        },
        reputation_score_basis_points: 8450,
        reputation_trend: ReputationTrend::Improving,
        active_quarantine: false,
        dependency_trust_summary: vec![DependencyTrustStatus {
            dependency_id: "npm:serde-json-bridge".to_string(),
            trust_level: "high".to_string(),
        }],
        last_verified_timestamp: "2026-04-24T12:34:56Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Verified provenance with bounded network-only capabilities.".to_string(),
        },
        audit_history: vec![AuditRecord {
            timestamp: "2026-04-24T12:34:56Z".to_string(),
            event_code: "TRUST_CARD_CREATED".to_string(),
            detail: "Initial deterministic trust-card emission".to_string(),
            trace_id: "trace-golden-0001".to_string(),
        }],
        derivation_evidence: None,
        card_hash: repeated_hex("3c", 32),
        registry_signature: repeated_hex("4d", 64),
    }
}

fn minimal_active_card() -> TrustCard {
    let mut card = base_trust_card();
    card.trust_card_version = 1;
    card.extension.version = "1.0.0".to_string();
    card.certification_level = CertificationLevel::Bronze;
    card.capability_declarations.clear();
    card.behavioral_profile = BehavioralProfile {
        network_access: false,
        filesystem_access: false,
        subprocess_access: false,
        profile_summary: "Passive extension with no privileged capabilities.".to_string(),
    };
    card.provenance_summary.artifact_hashes = vec![format!("sha256:{}", repeated_hex("aa", 32))];
    card.reputation_score_basis_points = 7000;
    card.reputation_trend = ReputationTrend::Stable;
    card.dependency_trust_summary.clear();
    card.user_facing_risk_assessment = RiskAssessment {
        level: RiskLevel::Low,
        summary: "No privileged behavior declared.".to_string(),
    };
    card.audit_history.clear();
    card.card_hash = repeated_hex("10", 32);
    card.registry_signature = repeated_hex("20", 64);
    card
}

fn dependency_rich_card() -> TrustCard {
    let mut card = base_trust_card();
    card.trust_card_version = 12;
    card.previous_version_hash = Some(repeated_hex("55", 32));
    card.extension.extension_id = "npm:@acme/dependency-bridge".to_string();
    card.capability_declarations.push(CapabilityDeclaration {
        name: "fs.read_config".to_string(),
        description: "Read local configuration for dependency analysis".to_string(),
        risk: CapabilityRisk::Low,
    });
    card.behavioral_profile.filesystem_access = true;
    card.behavioral_profile.profile_summary =
        "Dependency analysis with read-only filesystem access.".to_string();
    card.dependency_trust_summary = vec![
        DependencyTrustStatus {
            dependency_id: "npm:axios".to_string(),
            trust_level: "medium".to_string(),
        },
        DependencyTrustStatus {
            dependency_id: "npm:uuid".to_string(),
            trust_level: "high".to_string(),
        },
    ];
    card.audit_history.push(AuditRecord {
        timestamp: "2026-04-24T13:00:00Z".to_string(),
        event_code: "TRUST_CARD_UPDATED".to_string(),
        detail: "Dependency telemetry refresh incorporated.".to_string(),
        trace_id: "trace-golden-0002".to_string(),
    });
    card.card_hash = repeated_hex("30", 32);
    card.registry_signature = repeated_hex("40", 64);
    card
}

fn revoked_quarantine_card() -> TrustCard {
    let mut card = base_trust_card();
    card.trust_card_version = 21;
    card.previous_version_hash = Some(repeated_hex("66", 32));
    card.extension.extension_id = "npm:@acme/revoked-plugin".to_string();
    card.certification_level = CertificationLevel::Gold;
    card.revocation_status = RevocationStatus::Revoked {
        reason: "Publisher key rotation failed signature continuity checks.".to_string(),
        revoked_at: "2026-04-24T18:45:00Z".to_string(),
    };
    card.reputation_trend = ReputationTrend::Declining;
    card.active_quarantine = true;
    card.user_facing_risk_assessment = RiskAssessment {
        level: RiskLevel::Critical,
        summary: "Revoked and quarantined until operator review completes.".to_string(),
    };
    card.audit_history.push(AuditRecord {
        timestamp: "2026-04-24T18:45:00Z".to_string(),
        event_code: "TRUST_CARD_REVOKED".to_string(),
        detail: "Quarantine followed failed continuity verification.".to_string(),
        trace_id: "trace-golden-0003".to_string(),
    });
    card.card_hash = repeated_hex("50", 32);
    card.registry_signature = repeated_hex("60", 64);
    card
}

fn audit_heavy_card() -> TrustCard {
    let mut card = base_trust_card();
    card.trust_card_version = 33;
    card.previous_version_hash = Some(repeated_hex("77", 32));
    card.extension.extension_id = "npm:@acme/audit-heavy".to_string();
    card.extension.version = "5.0.0".to_string();
    card.certification_level = CertificationLevel::Platinum;
    card.capability_declarations.push(CapabilityDeclaration {
        name: "subprocess.exec".to_string(),
        description: "Launch isolated helper processes for evidence capture".to_string(),
        risk: CapabilityRisk::High,
    });
    card.behavioral_profile.subprocess_access = true;
    card.behavioral_profile.profile_summary =
        "Captures evidence through isolated subprocess helpers.".to_string();
    card.provenance_summary.attestation_level = "L4-independent-replication".to_string();
    card.reputation_score_basis_points = 9100;
    card.audit_history = vec![
        AuditRecord {
            timestamp: "2026-04-20T08:00:00Z".to_string(),
            event_code: "TRUST_CARD_CREATED".to_string(),
            detail: "Initial registry creation.".to_string(),
            trace_id: "trace-golden-0100".to_string(),
        },
        AuditRecord {
            timestamp: "2026-04-22T09:15:00Z".to_string(),
            event_code: "TRUST_CARD_COMPUTED".to_string(),
            detail: "Canonical hash recalculated after provenance refresh.".to_string(),
            trace_id: "trace-golden-0101".to_string(),
        },
        AuditRecord {
            timestamp: "2026-04-24T10:30:00Z".to_string(),
            event_code: "TRUST_CARD_SERVED".to_string(),
            detail: "Card served to operator-facing API.".to_string(),
            trace_id: "trace-golden-0102".to_string(),
        },
    ];
    card.card_hash = repeated_hex("70", 32);
    card.registry_signature = repeated_hex("80", 64);
    card
}

fn assert_golden_bytes(name: &str, actual: &[u8]) -> Result<(), String> {
    let golden_path = golden_path(name);

    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        let parent = golden_path.parent().ok_or_else(|| {
            format!(
                "trust-card golden path is missing a parent directory: {}",
                golden_path.display()
            )
        })?;
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create trust-card golden directory {}: {err}",
                parent.display()
            )
        })?;
        fs::write(&golden_path, actual).map_err(|err| {
            format!(
                "write trust-card golden bytes {}: {err}",
                golden_path.display()
            )
        })?;
        return Ok(());
    }

    let expected = fs::read(&golden_path)
        .map_err(|err| format!("read golden {}: {err}", golden_path.display()))?;
    if !ct_eq_bytes(actual, &expected) {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, actual).map_err(|err| {
            format!(
                "write trust-card actual bytes {}: {err}",
                actual_path.display()
            )
        })?;
        return Err(format!(
            "trust-card golden mismatch for {}; wrote actual to {}",
            golden_path.display(),
            actual_path.display()
        ));
    }

    Ok(())
}

fn assert_trust_card_golden(name: &str, card: &TrustCard) -> Result<(), String> {
    let canonical =
        to_canonical_json(card).map_err(|err| format!("trust card should canonicalize: {err}"))?;
    assert_golden_bytes(name, canonical.as_bytes())
}

#[test]
fn supply_chain_trust_card_encoder_active_minimal_golden_bytes() -> Result<(), String> {
    let card = minimal_active_card();
    assert_trust_card_golden("active_minimal", &card)
}

#[test]
fn supply_chain_trust_card_encoder_dependency_rich_golden_bytes() -> Result<(), String> {
    let card = dependency_rich_card();
    assert_trust_card_golden("dependency_rich", &card)
}

#[test]
fn supply_chain_trust_card_encoder_revoked_quarantine_golden_bytes() -> Result<(), String> {
    let card = revoked_quarantine_card();
    assert_trust_card_golden("revoked_quarantine", &card)
}

#[test]
fn supply_chain_trust_card_encoder_audit_heavy_golden_bytes() -> Result<(), String> {
    let card = audit_heavy_card();
    assert_trust_card_golden("audit_heavy", &card)
}
