//! Registered trust-card conformance runner.
//!
//! This target verifies the real registry and API-route surfaces used by the
//! trust-card conformance contract. It intentionally avoids local substitutes so
//! Cargo fails if the actual product paths stop compiling or stop enforcing
//! evidence, lookup, filtering, and pagination behavior.

use frankenengine_node::api::trust_card_routes::{
    Pagination, create_trust_card, get_trust_card, list_trust_cards, search_trust_cards,
};
use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
    ExtensionIdentity, ProvenanceSummary, PublisherIdentity, ReputationTrend, RevocationStatus,
    RiskAssessment, RiskLevel, TrustCardError, TrustCardInput, TrustCardListFilter,
    TrustCardRegistry,
};

const BASE_TIMESTAMP: u64 = 1_764_000_000;
const REGISTRY_KEY: &[u8] = b"trust-card-conformance-runner-real-registry-key-v1";

fn registry() -> TrustCardRegistry {
    TrustCardRegistry::new(300, REGISTRY_KEY)
}

fn evidence_refs(id: &str) -> Vec<VerifiedEvidenceRef> {
    vec![VerifiedEvidenceRef {
        evidence_id: format!("runner-evidence-{id}"),
        evidence_type: EvidenceType::TestCoverageReport,
        verified_at_epoch: BASE_TIMESTAMP,
        verification_receipt_hash: "a".repeat(64),
    }]
}

fn trust_card_input(
    extension_id: &str,
    publisher_id: &str,
    capability_name: &str,
    certification_level: CertificationLevel,
) -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: extension_id.to_string(),
            version: "1.0.0".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: publisher_id.to_string(),
            display_name: format!("Publisher {publisher_id}"),
        },
        certification_level,
        capability_declarations: vec![CapabilityDeclaration {
            name: capability_name.to_string(),
            description: format!("{capability_name} capability"),
            risk: CapabilityRisk::Medium,
        }],
        behavioral_profile: BehavioralProfile {
            network_access: capability_name.contains("net."),
            filesystem_access: capability_name.contains("fs."),
            subprocess_access: false,
            profile_summary: format!("{capability_name} profile"),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "registered-runner".to_string(),
            source_uri: format!("conformance-runner://{extension_id}"),
            artifact_hashes: vec!["sha256:".to_string() + &"b".repeat(64)],
            verified_at: "2026-05-06T18:00:00Z".to_string(),
        },
        reputation_score_basis_points: 9_100,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: Vec::new(),
        last_verified_timestamp: "2026-05-06T18:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Medium,
            summary: format!("{capability_name} requires policy review"),
        },
        evidence_refs: evidence_refs(extension_id),
    }
}

#[test]
fn registered_runner_reads_real_trust_card_through_api_route() {
    let mut registry = registry();
    let extension_id = "npm:@runner/api-route";

    let created = create_trust_card(
        &mut registry,
        trust_card_input(
            extension_id,
            "publisher:runner-api",
            "net.fetch",
            CertificationLevel::Silver,
        ),
        BASE_TIMESTAMP,
        "runner-create",
    )
    .expect("real trust card create route must succeed");

    assert!(created.ok);
    assert_eq!(created.data.extension.extension_id, extension_id);
    assert_eq!(created.data.registry_signature.len(), 64);
    assert_eq!(created.data.card_hash.len(), 64);

    let read = get_trust_card(
        &mut registry,
        extension_id,
        BASE_TIMESTAMP + 1,
        "runner-read",
    )
    .expect("real trust card read route must succeed");

    let card = read
        .data
        .expect("created card must be returned by read route");
    assert!(read.ok);
    assert_eq!(card.extension.extension_id, extension_id);
    assert_eq!(card.card_hash, created.data.card_hash);
    assert_eq!(card.registry_signature, created.data.registry_signature);
}

#[test]
fn registered_runner_rejects_missing_evidence_without_persisting_card() {
    let mut registry = registry();
    let extension_id = "npm:@runner/no-evidence";
    let mut input = trust_card_input(
        extension_id,
        "publisher:runner-no-evidence",
        "fs.read",
        CertificationLevel::Bronze,
    );
    input.evidence_refs.clear();

    let err = create_trust_card(
        &mut registry,
        input,
        BASE_TIMESTAMP,
        "runner-create-no-evidence",
    )
    .expect_err("missing evidence must fail closed through the real create route");

    assert!(matches!(err, TrustCardError::EvidenceMissing));

    let read = get_trust_card(
        &mut registry,
        extension_id,
        BASE_TIMESTAMP + 1,
        "runner-read-rejected",
    )
    .expect("read after rejected create must still be well-formed");
    assert!(read.data.is_none());
}

#[test]
fn registered_runner_exercises_real_search_filter_and_pagination() {
    let mut registry = registry();

    create_trust_card(
        &mut registry,
        trust_card_input(
            "npm:@runner/network",
            "publisher:runner-search",
            "net.fetch",
            CertificationLevel::Gold,
        ),
        BASE_TIMESTAMP,
        "runner-create-network",
    )
    .expect("network card create route must succeed");
    create_trust_card(
        &mut registry,
        trust_card_input(
            "npm:@runner/filesystem",
            "publisher:runner-search",
            "fs.read",
            CertificationLevel::Silver,
        ),
        BASE_TIMESTAMP + 1,
        "runner-create-filesystem",
    )
    .expect("filesystem card create route must succeed");

    let search = search_trust_cards(
        &mut registry,
        "net.fetch",
        BASE_TIMESTAMP + 2,
        "runner-search",
        Pagination {
            page: 1,
            per_page: 10,
        },
    )
    .expect("search route must succeed");
    assert!(search.ok);
    assert_eq!(search.data.len(), 1);
    assert_eq!(search.data[0].extension.extension_id, "npm:@runner/network");
    assert_eq!(
        search
            .page
            .expect("search response must be paged")
            .total_items,
        1
    );

    let gold_filter = TrustCardListFilter {
        certification_level: Some(CertificationLevel::Gold),
        publisher_id: None,
        capability: None,
    };
    let listed = list_trust_cards(
        &mut registry,
        &gold_filter,
        BASE_TIMESTAMP + 3,
        "runner-list",
        Pagination {
            page: 1,
            per_page: 10,
        },
    )
    .expect("list route must succeed");
    assert_eq!(listed.data.len(), 1);
    assert_eq!(listed.data[0].certification_level, CertificationLevel::Gold);

    let err = list_trust_cards(
        &mut registry,
        &TrustCardListFilter::empty(),
        BASE_TIMESTAMP + 4,
        "runner-invalid-pagination",
        Pagination {
            page: 1,
            per_page: 0,
        },
    )
    .expect_err("invalid pagination must fail through the real route");
    assert!(matches!(
        err,
        TrustCardError::InvalidPagination {
            page: 1,
            per_page: 0
        }
    ));
}
