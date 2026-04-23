//! Metamorphic tests for real trust-card canonicalization surfaces.

use frankenengine_node::supply_chain::{
    certification::{EvidenceType, VerifiedEvidenceRef},
    trust_card::{
        BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
        DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
        ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCardInput,
        TrustCardRegistry, render_trust_card_human, to_canonical_json,
    },
};

const REGISTRY_KEY: &[u8] = b"trust-card-metamorphic-real-key";
const NOW_SECS: u64 = 1_777_000_000;
const TRACE_ID: &str = "trace-trust-card-metamorphic";

fn evidence_refs() -> Vec<VerifiedEvidenceRef> {
    vec![
        VerifiedEvidenceRef {
            evidence_id: "ev-provenance-001".to_string(),
            evidence_type: EvidenceType::ProvenanceChain,
            verified_at_epoch: NOW_SECS.saturating_sub(10),
            verification_receipt_hash: "a".repeat(64),
        },
        VerifiedEvidenceRef {
            evidence_id: "ev-test-coverage-001".to_string(),
            evidence_type: EvidenceType::TestCoverageReport,
            verified_at_epoch: NOW_SECS.saturating_sub(5),
            verification_receipt_hash: "b".repeat(64),
        },
    ]
}

fn input_with_order(
    capability_declarations: Vec<CapabilityDeclaration>,
    dependency_trust_summary: Vec<DependencyTrustStatus>,
) -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: "npm:@metamorphic/order-stable".to_string(),
            version: "1.2.3".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "pub-metamorphic".to_string(),
            display_name: "Metamorphic Security Team".to_string(),
        },
        certification_level: CertificationLevel::Gold,
        capability_declarations,
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: false,
            subprocess_access: false,
            profile_summary: "Network-only policy checks".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "slsa-l3".to_string(),
            source_uri: "https://example.invalid/metamorphic/order-stable".to_string(),
            artifact_hashes: vec![
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            ],
            verified_at: "2026-04-22T10:00:00Z".to_string(),
        },
        reputation_score_basis_points: 912,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary,
        last_verified_timestamp: "2026-04-22T10:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Bounded capabilities with verified provenance".to_string(),
        },
        evidence_refs: evidence_refs(),
    }
}

fn capabilities() -> Vec<CapabilityDeclaration> {
    vec![
        CapabilityDeclaration {
            name: "net.fetch".to_string(),
            description: "Fetch policy bundles from approved endpoints".to_string(),
            risk: CapabilityRisk::Medium,
        },
        CapabilityDeclaration {
            name: "auth.validate-token".to_string(),
            description: "Validate signed session tokens".to_string(),
            risk: CapabilityRisk::Low,
        },
        CapabilityDeclaration {
            name: "telemetry.emit".to_string(),
            description: "Emit bounded policy telemetry".to_string(),
            risk: CapabilityRisk::Low,
        },
    ]
}

fn dependencies() -> Vec<DependencyTrustStatus> {
    vec![
        DependencyTrustStatus {
            dependency_id: "npm:zod@3".to_string(),
            trust_level: "verified".to_string(),
        },
        DependencyTrustStatus {
            dependency_id: "npm:jose@5".to_string(),
            trust_level: "verified".to_string(),
        },
        DependencyTrustStatus {
            dependency_id: "npm:undici@6".to_string(),
            trust_level: "monitored".to_string(),
        },
    ]
}

#[test]
fn capability_and_dependency_order_permutations_preserve_canonical_and_textual_content() {
    let mut baseline_registry = TrustCardRegistry::new(60, REGISTRY_KEY);
    let mut permuted_registry = TrustCardRegistry::new(60, REGISTRY_KEY);

    let baseline = baseline_registry
        .create(input_with_order(capabilities(), dependencies()), NOW_SECS, TRACE_ID)
        .expect("baseline trust card");

    let mut permuted_capabilities = capabilities();
    permuted_capabilities.reverse();
    let mut permuted_dependencies = dependencies();
    permuted_dependencies.rotate_left(1);
    let permuted = permuted_registry
        .create(
            input_with_order(permuted_capabilities, permuted_dependencies),
            NOW_SECS,
            TRACE_ID,
        )
        .expect("permuted trust card");

    assert_eq!(
        baseline
            .capability_declarations
            .iter()
            .map(|capability| capability.name.as_str())
            .collect::<Vec<_>>(),
        vec!["auth.validate-token", "net.fetch", "telemetry.emit"],
        "baseline capabilities should be canonicalized by name"
    );
    assert_eq!(
        baseline.capability_declarations,
        permuted.capability_declarations,
        "capability declaration order should be semantic, not caller-order dependent"
    );
    assert_eq!(
        baseline.dependency_trust_summary,
        permuted.dependency_trust_summary,
        "dependency trust order should be semantic, not caller-order dependent"
    );
    assert_eq!(
        baseline.card_hash, permuted.card_hash,
        "card hash changed for an order-only input permutation"
    );
    assert_eq!(
        baseline.registry_signature, permuted.registry_signature,
        "registry signature changed for an order-only input permutation"
    );
    assert_eq!(
        to_canonical_json(&baseline).expect("baseline canonical JSON"),
        to_canonical_json(&permuted).expect("permuted canonical JSON"),
        "canonical JSON changed for an order-only input permutation"
    );
    assert_eq!(
        render_trust_card_human(&baseline),
        render_trust_card_human(&permuted),
        "user-facing textual content changed for an order-only input permutation"
    );
}
