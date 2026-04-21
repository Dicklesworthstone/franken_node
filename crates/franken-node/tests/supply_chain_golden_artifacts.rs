//! Golden artifact tests for supply_chain domain
//!
//! Tests trust-card rendering, registry receipts, and claim envelope serialization
//! with proper canonicalization for cross-platform stability.

use frankenengine_node::claims::{ClaimCompiler, ClaimContent, CompilerConfig, EvidenceBundle, ExternalClaim, ValidityPeriod};
use frankenengine_node::registry::staking_governance::{
    AppealOutcome, AppealRecord, PublisherId, RiskTier, SlashEvent, SlashEvidence,
    SlashRecord, StakeId, StakeRecord, StakeState, StakingAuditEntry, StakingLedger,
    TrustGovernanceState, ViolationType
};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    DependencyTrustStatus, EvidenceType, ExtensionIdentity, ProvenanceSummary,
    PublisherIdentity, ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel,
    TrustCard, TrustCardComparison, TrustCardDiffEntry, VerifiedEvidenceRef,
    render_comparison_human, render_trust_card_human, to_canonical_json
};

use insta::Settings;
use regex::Regex;

/// Scrub non-deterministic values for golden comparison
fn scrub_output(output: &str) -> String {
    let mut scrubbed = output.to_string();

    // UUIDs → [UUID]
    let uuid_re = Regex::new(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    ).unwrap();
    scrubbed = uuid_re.replace_all(&scrubbed, "[UUID]").to_string();

    // ISO timestamps → [TIMESTAMP]
    let ts_re = Regex::new(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?"
    ).unwrap();
    scrubbed = ts_re.replace_all(&scrubbed, "[TIMESTAMP]").to_string();

    // Epoch timestamps → [EPOCH]
    let epoch_re = Regex::new(r"\b\d{10,13}\b").unwrap();
    scrubbed = epoch_re.replace_all(&scrubbed, "[EPOCH]").to_string();

    // SHA256 hashes → [HASH]
    let hash_re = Regex::new(r"sha256:[a-f0-9]{64}").unwrap();
    scrubbed = hash_re.replace_all(&scrubbed, "sha256:[HASH]").to_string();

    // Hex signatures → [SIG]
    let sig_re = Regex::new(r"[a-f0-9]{128,256}").unwrap();
    scrubbed = sig_re.replace_all(&scrubbed, "[SIG]").to_string();

    scrubbed
}

fn canonical_trust_card_fixture() -> TrustCard {
    TrustCard {
        schema_version: "trust-card-v1.0".to_string(),
        trust_card_version: 42,
        extension: ExtensionIdentity {
            extension_id: "npm:@acme/security-scanner".to_string(),
            version: "2.1.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "acme-corp".to_string(),
            display_name: "ACME Corporation".to_string(),
        },
        certification_level: CertificationLevel::Gold,
        revocation_status: RevocationStatus::Active,
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: false,
            sandbox_escape_risk: false,
            profile_summary: "Network scanner with read-only file access".to_string(),
        },
        capabilities: vec![
            CapabilityDeclaration {
                name: "network.scan".to_string(),
                description: "Scan network endpoints for vulnerabilities".to_string(),
                risk: CapabilityRisk::Medium,
            },
            CapabilityDeclaration {
                name: "fs.read_config".to_string(),
                description: "Read configuration files".to_string(),
                risk: CapabilityRisk::Low,
            },
        ],
        provenance: ProvenanceSummary {
            attestation_level: "L3-verified-build".to_string(),
            source_uri: "https://github.com/acme-corp/security-scanner".to_string(),
            build_reproducible: true,
            verified_at: "2026-04-21T00:00:00Z".to_string(),
        },
        dependency_trust_status: vec![
            DependencyTrustStatus {
                dependency_id: "npm:lodash".to_string(),
                trust_level: "high".to_string(),
            },
            DependencyTrustStatus {
                dependency_id: "npm:axios".to_string(),
                trust_level: "medium".to_string(),
            },
        ],
        reputation_score_basis_points: 8750, // 87.5%
        reputation_trend: ReputationTrend::Improving,
        active_quarantine: false,
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Well-maintained security tool with verified provenance".to_string(),
        },
        last_verified_timestamp: "2026-04-21T12:00:00Z".to_string(),
        evidence_refs: vec![
            VerifiedEvidenceRef {
                evidence_id: "slsa-provenance-v1.0".to_string(),
                evidence_type: EvidenceType::ProvenanceAttestation,
                verified_at_epoch: 1735689600,
                verification_receipt_hash: "sha256:abc123def456789".to_string(),
            },
            VerifiedEvidenceRef {
                evidence_id: "security-audit-2026-Q1".to_string(),
                evidence_type: EvidenceType::CertificationEvidence,
                verified_at_epoch: 1735689600,
                verification_receipt_hash: "sha256:fed987cba654321".to_string(),
            },
        ],
        derivation_hash: "computed-hash-placeholder".to_string(),
        registry_signature: "signature-placeholder".to_string(),
    }
}

fn canonical_external_claim() -> ExternalClaim {
    ExternalClaim {
        claim_id: "claim-12345".to_string(),
        claim_type: "security-audit".to_string(),
        subject_extension_id: "npm:@acme/security-lib".to_string(),
        subject_version: "1.2.3".to_string(),
        issuer_identity: "security-auditor-corp".to_string(),
        claim_content: ClaimContent {
            summary: "Comprehensive security audit passed with minor recommendations".to_string(),
            detailed_findings: vec![
                "No critical vulnerabilities found".to_string(),
                "Input validation patterns are robust".to_string(),
                "Authentication mechanisms properly implemented".to_string(),
                "Recommendation: Add rate limiting to API endpoints".to_string(),
            ],
            risk_assessment: "LOW".to_string(),
            compliance_tags: vec![
                "SOC2-TYPE2".to_string(),
                "NIST-800-53".to_string(),
                "OWASP-TOP10".to_string(),
            ],
        },
        validity_period: ValidityPeriod {
            issued_at: "2026-04-21T00:00:00Z".to_string(),
            expires_at: "2027-04-21T00:00:00Z".to_string(),
            not_before: "2026-04-21T00:00:00Z".to_string(),
        },
        evidence_bundle: EvidenceBundle {
            evidence_refs: vec![
                "audit-report-2026-Q1.pdf".to_string(),
                "penetration-test-results.json".to_string(),
                "static-analysis-sarif.json".to_string(),
            ],
            attestation_signatures: vec![
                "sig1:0123456789abcdef".to_string(),
                "sig2:fedcba9876543210".to_string(),
            ],
            provenance_chain: vec![
                "github.com/acme-corp/security-lib@v1.2.3".to_string(),
                "build-server.acme.com/build/12345".to_string(),
            ],
        },
    }
}

// === TRUST CARD GOLDEN TESTS ===

#[test]
fn golden_trust_card_human_rendering() {
    let card = canonical_trust_card_fixture();
    let rendered = render_trust_card_human(&card);
    let scrubbed = scrub_output(&rendered);

    insta::assert_snapshot!("trust_card_human_render", scrubbed);
}

#[test]
fn golden_trust_card_human_rendering_revoked() {
    let mut card = canonical_trust_card_fixture();
    card.revocation_status = RevocationStatus::Revoked {
        reason: "Security vulnerability discovered in dependency".to_string(),
        revoked_at: "2026-04-20T15:30:00Z".to_string(),
    };
    card.active_quarantine = true;
    card.user_facing_risk_assessment = RiskAssessment {
        level: RiskLevel::Critical,
        summary: "REVOKED: Security vulnerability in transitive dependency".to_string(),
    };

    let rendered = render_trust_card_human(&card);
    let scrubbed = scrub_output(&rendered);

    insta::assert_snapshot!("trust_card_human_render_revoked", scrubbed);
}

#[test]
fn golden_trust_card_canonical_json() {
    let card = canonical_trust_card_fixture();
    let canonical_json = to_canonical_json(&card).expect("canonical JSON should serialize");
    let scrubbed = scrub_output(&canonical_json);

    insta::assert_snapshot!("trust_card_canonical_json", scrubbed);
}

#[test]
fn golden_trust_card_comparison_human_rendering() {
    let card1 = canonical_trust_card_fixture();
    let mut _card2 = canonical_trust_card_fixture();

    // Create comparison with differences
    let comparison = TrustCardComparison {
        left_extension_id: card1.extension.extension_id.clone(),
        right_extension_id: card1.extension.extension_id.clone(),
        changes: vec![
            TrustCardDiffEntry {
                field: "certification_level".to_string(),
                left: "gold".to_string(),
                right: "platinum".to_string(),
            },
            TrustCardDiffEntry {
                field: "reputation_score_basis_points".to_string(),
                left: "8750".to_string(),
                right: "9500".to_string(),
            },
        ],
    };

    let rendered = render_comparison_human(&comparison);
    // Comparison output should be deterministic
    insta::assert_snapshot!("trust_card_comparison_human", rendered);
}

// === CLAIM ENVELOPE GOLDEN TESTS ===

#[test]
fn golden_external_claim_envelope_serialization() {
    let claim = canonical_external_claim();
    let serialized = serde_json::to_string_pretty(&claim)
        .expect("claim should serialize");
    let scrubbed = scrub_output(&serialized);

    insta::assert_snapshot!("external_claim_envelope", scrubbed);
}

#[test]
fn golden_compiled_contract_envelope() {
    let claim = canonical_external_claim();
    let config = CompilerConfig::new("test-signer", "test-key-id", 60);
    let compiler = ClaimCompiler::new(config);

    let result = compiler.compile(&claim, "test-trace")
        .expect("compilation should succeed");

    let contract_json = serde_json::to_string_pretty(&result.compiled_contract)
        .expect("contract should serialize");
    let scrubbed = scrub_output(&contract_json);

    insta::assert_snapshot!("compiled_contract_envelope", scrubbed);
}

// === REGISTRY RECEIPT GOLDEN TESTS ===

#[test]
fn golden_staking_audit_entry_receipt() {
    let audit_entry = StakingAuditEntry {
        entry_id: 12345,
        operation_type: "DEPOSIT".to_string(),
        publisher_id: PublisherId("acme-corp".to_string()),
        stake_id: Some(StakeId(67890)),
        amount: Some(1000),
        timestamp: 1735689600,
        trace_id: "trace-audit-12345".to_string(),
        details: "Stake deposit for high-risk tier capability".to_string(),
        risk_tier: Some(RiskTier::High),
        metadata: Some("compliance_check=passed,automated=true".to_string()),
    };

    let json = serde_json::to_string_pretty(&audit_entry)
        .expect("audit entry should serialize");
    let scrubbed = scrub_output(&json);

    insta::assert_snapshot!("staking_audit_entry_receipt", scrubbed);
}

#[test]
fn golden_slash_event_receipt() {
    let evidence = SlashEvidence::new(
        ViolationType::PolicyViolation,
        "Critical security policy violation detected",
        "unauthorized file system access outside sandbox",
        "security-monitor-alpha",
        1735689600,
    );

    let slash_event = SlashEvent {
        slash_id: 9876,
        stake_id: StakeId(54321),
        publisher_id: PublisherId("rogue-publisher".to_string()),
        violation_type: ViolationType::PolicyViolation,
        evidence_digest: "sha256:abcdef123456789".to_string(),
        penalty_amount: 500,
        slashed_at: 1735689600,
        slash_record: SlashRecord {
            violation_id: "VIOL-2026-001".to_string(),
            description: "Unauthorized sandbox escape detected".to_string(),
            penalty_amount: 500,
            slashed_at: 1735689600,
            evidence,
        },
    };

    let json = serde_json::to_string_pretty(&slash_event)
        .expect("slash event should serialize");
    let scrubbed = scrub_output(&json);

    insta::assert_snapshot!("slash_event_receipt", scrubbed);
}

#[test]
fn golden_registry_complete_lifecycle_receipt() {
    let mut ledger = StakingLedger::new();

    // Complete lifecycle: deposit → slash → appeal → restore
    let stake_id = ledger
        .deposit("lifecycle-publisher", 2000, RiskTier::High, 1000)
        .expect("deposit should succeed");

    let evidence = SlashEvidence::new(
        ViolationType::PolicyViolation,
        "Lifecycle test violation",
        "Test payload for complete lifecycle",
        "test-collector",
        1100,
    );

    let slash_event = ledger
        .slash(stake_id, evidence, 1200)
        .expect("slash should succeed");

    let appeal_record = ledger
        .file_appeal(stake_id, slash_event.slash_id, "False positive test appeal", 1300)
        .expect("appeal should succeed");

    let _restore_result = ledger
        .restore_appeal(appeal_record.appeal_id, AppealOutcome::Upheld, "Test restoration", "test-reviewer", 1400)
        .expect("restore should succeed");

    // Serialize just the governance state (not the full ledger for size)
    let json = serde_json::to_string_pretty(&ledger.state)
        .expect("ledger state should serialize");
    let scrubbed = scrub_output(&json);

    insta::assert_snapshot!("registry_complete_lifecycle_receipt", scrubbed);
}