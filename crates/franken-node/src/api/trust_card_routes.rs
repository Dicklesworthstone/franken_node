//! API-style route handlers for trust-card operations.
//!
//! These functions provide stable surfaces matching:
//! - `GET /trust-cards/{extension_id}`
//! - `GET /trust-cards/publisher/{publisher_id}`
//! - `GET /trust-cards/search?query=...`
//!
//! plus create/update/list/compare helpers for internal services.

use serde::{Deserialize, Serialize};

use crate::supply_chain::trust_card::{
    TrustCard, TrustCardComparison, TrustCardError, TrustCardListFilter, TrustCardRegistry,
    paginate,
};
#[cfg(any(test, feature = "control-plane"))]
use crate::supply_chain::trust_card::{TrustCardInput, TrustCardMutation};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, arbitrary::Arbitrary)]
pub struct Pagination {
    pub page: usize,
    pub per_page: usize,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, arbitrary::Arbitrary)]
pub struct PageMeta {
    pub page: usize,
    pub per_page: usize,
    pub total_items: usize,
    pub total_pages: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, arbitrary::Arbitrary)]
pub struct ApiResponse<T> {
    pub ok: bool,
    pub data: T,
    pub page: Option<PageMeta>,
}

fn paged_response<T: Clone>(
    all: &[T],
    pagination: Pagination,
) -> Result<ApiResponse<Vec<T>>, TrustCardError> {
    if pagination.page == 0 || pagination.per_page == 0 {
        return Err(TrustCardError::InvalidPagination {
            page: pagination.page,
            per_page: pagination.per_page,
        });
    }
    let per_page = pagination.per_page;
    let total_items = all.len();
    let data = paginate(all, pagination.page, per_page)?;
    let total_pages = if total_items == 0 {
        0
    } else {
        (total_items - 1) / per_page + 1
    };
    Ok(ApiResponse {
        ok: true,
        data,
        page: Some(PageMeta {
            page: pagination.page,
            per_page,
            total_items,
            total_pages,
        }),
    })
}

#[cfg(any(test, feature = "control-plane"))]
pub fn create_trust_card(
    registry: &mut TrustCardRegistry,
    input: TrustCardInput,
    now_secs: u64,
    trace_id: &str,
) -> Result<ApiResponse<TrustCard>, TrustCardError> {
    let card = registry.create(input, now_secs, trace_id)?;
    Ok(ApiResponse {
        ok: true,
        data: card,
        page: None,
    })
}

#[cfg(any(test, feature = "control-plane"))]
pub fn update_trust_card(
    registry: &mut TrustCardRegistry,
    extension_id: &str,
    mutation: TrustCardMutation,
    now_secs: u64,
    trace_id: &str,
) -> Result<ApiResponse<TrustCard>, TrustCardError> {
    let card = registry.update(extension_id, mutation, now_secs, trace_id)?;
    Ok(ApiResponse {
        ok: true,
        data: card,
        page: None,
    })
}

pub fn get_trust_card(
    registry: &mut TrustCardRegistry,
    extension_id: &str,
    now_secs: u64,
    trace_id: &str,
) -> Result<ApiResponse<Option<TrustCard>>, TrustCardError> {
    let card = registry.read(extension_id, now_secs, trace_id)?;
    Ok(ApiResponse {
        ok: true,
        data: card,
        page: None,
    })
}

pub fn list_trust_cards(
    registry: &mut TrustCardRegistry,
    filter: &TrustCardListFilter,
    now_secs: u64,
    trace_id: &str,
    pagination: Pagination,
) -> Result<ApiResponse<Vec<TrustCard>>, TrustCardError> {
    let all = registry.list(filter, trace_id, now_secs)?;
    paged_response(&all, pagination)
}

pub fn get_trust_cards_by_publisher(
    registry: &mut TrustCardRegistry,
    publisher_id: &str,
    now_secs: u64,
    trace_id: &str,
    pagination: Pagination,
) -> Result<ApiResponse<Vec<TrustCard>>, TrustCardError> {
    let all = registry.list_by_publisher(publisher_id, now_secs, trace_id)?;
    paged_response(&all, pagination)
}

pub fn search_trust_cards(
    registry: &mut TrustCardRegistry,
    query: &str,
    now_secs: u64,
    trace_id: &str,
    pagination: Pagination,
) -> Result<ApiResponse<Vec<TrustCard>>, TrustCardError> {
    let all = registry.search(query, now_secs, trace_id)?;
    paged_response(&all, pagination)
}

pub fn compare_trust_cards(
    registry: &mut TrustCardRegistry,
    left_extension_id: &str,
    right_extension_id: &str,
    now_secs: u64,
    trace_id: &str,
) -> Result<ApiResponse<TrustCardComparison>, TrustCardError> {
    let diff = registry.compare(left_extension_id, right_extension_id, now_secs, trace_id)?;
    Ok(ApiResponse {
        ok: true,
        data: diff,
        page: None,
    })
}

pub fn compare_trust_card_versions(
    registry: &mut TrustCardRegistry,
    extension_id: &str,
    left_version: u64,
    right_version: u64,
    now_secs: u64,
    trace_id: &str,
) -> Result<ApiResponse<TrustCardComparison>, TrustCardError> {
    let diff = registry.compare_versions(
        extension_id,
        left_version,
        right_version,
        now_secs,
        trace_id,
    )?;
    Ok(ApiResponse {
        ok: true,
        data: diff,
        page: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
    use crate::supply_chain::trust_card::{
        CapabilityDeclaration, CapabilityRisk, CertificationLevel, ExtensionIdentity,
        PublisherIdentity, ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel,
        TrustCardInput, TrustCardMutation, fixture_registry,
    };

    fn route_test_evidence_refs() -> Vec<VerifiedEvidenceRef> {
        vec![
            VerifiedEvidenceRef {
                evidence_id: "ev-route-prov-001".to_string(),
                evidence_type: EvidenceType::ProvenanceChain,
                verified_at_epoch: 500,
                verification_receipt_hash: "e".repeat(64),
            },
            VerifiedEvidenceRef {
                evidence_id: "ev-route-rep-001".to_string(),
                evidence_type: EvidenceType::ReputationSignal,
                verified_at_epoch: 500,
                verification_receipt_hash: "f".repeat(64),
            },
        ]
    }

    fn sample_input(extension_id: &str) -> TrustCardInput {
        TrustCardInput {
            extension: ExtensionIdentity {
                extension_id: extension_id.to_string(),
                version: "1.0.0".to_string(),
            },
            publisher: PublisherIdentity {
                publisher_id: "pub-test".to_string(),
                display_name: "Test Publisher".to_string(),
            },
            certification_level: CertificationLevel::Silver,
            capability_declarations: vec![CapabilityDeclaration {
                name: "net.fetch".to_string(),
                description: "fetch data".to_string(),
                risk: CapabilityRisk::Medium,
            }],
            behavioral_profile: crate::supply_chain::trust_card::BehavioralProfile {
                network_access: true,
                filesystem_access: false,
                subprocess_access: false,
                profile_summary: "network only".to_string(),
            },
            revocation_status: RevocationStatus::Active,
            provenance_summary: crate::supply_chain::trust_card::ProvenanceSummary {
                attestation_level: "slsa-l1".to_string(),
                source_uri: "fixture://trust-card/unit-route".to_string(),
                artifact_hashes: vec!["sha256:".to_string() + &"f".repeat(64)],
                verified_at: "2026-01-01T00:00:00Z".to_string(),
            },
            reputation_score_basis_points: 700,
            reputation_trend: ReputationTrend::Stable,
            active_quarantine: false,
            dependency_trust_summary: vec![],
            last_verified_timestamp: "2026-02-20T00:00:00Z".to_string(),
            user_facing_risk_assessment: RiskAssessment {
                level: RiskLevel::Medium,
                summary: "medium".to_string(),
            },
            evidence_refs: route_test_evidence_refs(),
        }
    }

    fn empty_mutation() -> TrustCardMutation {
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

    #[test]
    fn get_card_returns_data() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let response = get_trust_card(&mut registry, "npm:@acme/auth-guard", 1_001, "trace")
            .expect("response");
        assert!(response.ok);
        assert!(response.data.is_some());
    }

    #[test]
    fn publisher_list_paginates() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let response = get_trust_cards_by_publisher(
            &mut registry,
            "pub-acme",
            1_001,
            "trace",
            Pagination {
                page: 1,
                per_page: 10,
            },
        )
        .expect("response");
        assert!(response.ok);
        assert_eq!(response.data.len(), 1);
        assert_eq!(response.page.expect("page").total_items, 1);
    }

    #[test]
    fn search_supports_pagination() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let response = search_trust_cards(
            &mut registry,
            "npm:@",
            1_001,
            "trace",
            Pagination {
                page: 1,
                per_page: 1,
            },
        )
        .expect("response");
        assert!(response.ok);
        assert_eq!(response.data.len(), 1);
        assert_eq!(response.page.expect("page").total_pages, 2);
    }

    #[test]
    fn create_and_update_route_round_trip() {
        let mut registry = TrustCardRegistry::default();
        let create = create_trust_card(
            &mut registry,
            sample_input("npm:@unit/route"),
            2_000,
            "trace-create",
        )
        .expect("create");
        assert!(create.ok);
        assert_eq!(create.data.trust_card_version, 1);

        let update = update_trust_card(
            &mut registry,
            "npm:@unit/route",
            TrustCardMutation {
                certification_level: Some(CertificationLevel::Gold),
                revocation_status: None,
                active_quarantine: None,
                reputation_score_basis_points: None,
                reputation_trend: None,
                user_facing_risk_assessment: None,
                last_verified_timestamp: Some("2026-02-20T01:00:00Z".to_string()),
                evidence_refs: Some(route_test_evidence_refs()),
            },
            2_100,
            "trace-update",
        )
        .expect("update");
        assert!(update.ok);
        assert_eq!(update.data.trust_card_version, 2);
    }

    #[test]
    fn list_route_filters_by_publisher() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let response = list_trust_cards(
            &mut registry,
            &TrustCardListFilter {
                certification_level: None,
                publisher_id: Some("pub-acme".to_string()),
                capability: None,
            },
            1_001,
            "trace",
            Pagination {
                page: 1,
                per_page: 10,
            },
        )
        .expect("response");
        assert!(response.ok);
        assert_eq!(response.data.len(), 1);
    }

    #[test]
    fn list_route_rejects_invalid_zero_per_page() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let err = list_trust_cards(
            &mut registry,
            &TrustCardListFilter::empty(),
            1_001,
            "trace",
            Pagination {
                page: 1,
                per_page: 0,
            },
        )
        .expect_err("zero per_page must be rejected");
        assert!(matches!(
            err,
            TrustCardError::InvalidPagination {
                page: 1,
                per_page: 0
            }
        ));
    }

    #[test]
    fn pagination_default_values() {
        let p = Pagination::default();
        assert_eq!(p.page, 1);
        assert_eq!(p.per_page, 20);
    }

    #[test]
    fn get_nonexistent_card_returns_none() {
        let mut registry = TrustCardRegistry::default();
        let response =
            get_trust_card(&mut registry, "npm:@no/such", 1_000, "trace").expect("response");
        assert!(response.ok);
        assert!(response.data.is_none());
    }

    #[test]
    fn list_empty_registry_returns_empty() {
        let mut registry = TrustCardRegistry::default();
        let response = list_trust_cards(
            &mut registry,
            &TrustCardListFilter {
                certification_level: None,
                publisher_id: None,
                capability: None,
            },
            1_000,
            "trace",
            Pagination::default(),
        )
        .expect("response");
        assert!(response.ok);
        assert!(response.data.is_empty());
        assert_eq!(response.page.expect("page").total_items, 0);
    }

    #[test]
    fn search_no_results_returns_empty() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let response = search_trust_cards(
            &mut registry,
            "zzz-nonexistent-query",
            1_001,
            "trace",
            Pagination::default(),
        )
        .expect("response");
        assert!(response.ok);
        assert!(response.data.is_empty());
    }

    #[test]
    fn create_card_has_version_one() {
        let mut registry = TrustCardRegistry::default();
        let response =
            create_trust_card(&mut registry, sample_input("npm:@unit/new"), 2_000, "trace")
                .expect("create");
        assert!(response.ok);
        assert_eq!(response.data.trust_card_version, 1);
        assert!(response.page.is_none());
    }

    #[test]
    fn publisher_list_empty_publisher_returns_empty() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let response = get_trust_cards_by_publisher(
            &mut registry,
            "pub-nonexistent",
            1_001,
            "trace",
            Pagination::default(),
        )
        .expect("response");
        assert!(response.ok);
        assert!(response.data.is_empty());
    }

    #[test]
    fn list_filter_by_certification_level() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let response = list_trust_cards(
            &mut registry,
            &TrustCardListFilter {
                certification_level: Some(CertificationLevel::Silver),
                publisher_id: None,
                capability: None,
            },
            1_001,
            "trace",
            Pagination::default(),
        )
        .expect("response");
        assert!(response.ok);
        // Should return cards matching certification level
    }

    #[test]
    fn page_meta_serde_roundtrip() {
        let meta = PageMeta {
            page: 3,
            per_page: 10,
            total_items: 42,
            total_pages: 5,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: PageMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, meta);
    }

    #[test]
    fn pagination_serde_roundtrip() {
        let p = Pagination {
            page: 2,
            per_page: 25,
        };
        let json = serde_json::to_string(&p).unwrap();
        let parsed: Pagination = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn compare_routes_produce_diffs() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");
        let compare = compare_trust_cards(
            &mut registry,
            "npm:@acme/auth-guard",
            "npm:@beta/telemetry-bridge",
            1_010,
            "trace",
        )
        .expect("compare");
        assert!(compare.ok);
        assert!(!compare.data.changes.is_empty());

        let version_diff = compare_trust_card_versions(
            &mut registry,
            "npm:@beta/telemetry-bridge",
            1,
            2,
            1_011,
            "trace",
        )
        .expect("version diff");
        assert!(version_diff.ok);
        assert!(!version_diff.data.changes.is_empty());
    }

    #[test]
    fn create_route_rejects_missing_evidence_refs() {
        let mut registry = TrustCardRegistry::default();
        let mut input = sample_input("npm:@unit/no-evidence");
        input.evidence_refs.clear();

        let err = create_trust_card(&mut registry, input, 2_000, "trace-no-evidence")
            .expect_err("create without evidence must fail closed");

        assert!(matches!(err, TrustCardError::EvidenceMissing));
        assert!(
            get_trust_card(&mut registry, "npm:@unit/no-evidence", 2_001, "trace-read")
                .expect("read after rejected create")
                .data
                .is_none()
        );
    }

    #[test]
    fn update_route_rejects_missing_extension() {
        let mut registry = TrustCardRegistry::default();

        let err = update_trust_card(
            &mut registry,
            "npm:@unit/missing",
            empty_mutation(),
            2_000,
            "trace-missing-update",
        )
        .expect_err("missing extension update must fail");

        assert!(matches!(err, TrustCardError::NotFound(id) if id == "npm:@unit/missing"));
    }

    #[test]
    fn update_route_rejects_certification_upgrade_without_evidence() {
        let mut registry = TrustCardRegistry::default();
        create_trust_card(
            &mut registry,
            sample_input("npm:@unit/upgrade-without-evidence"),
            2_000,
            "trace-create-upgrade",
        )
        .expect("create");
        let mut mutation = empty_mutation();
        mutation.certification_level = Some(CertificationLevel::Gold);

        let err = update_trust_card(
            &mut registry,
            "npm:@unit/upgrade-without-evidence",
            mutation,
            2_001,
            "trace-upgrade-denied",
        )
        .expect_err("upgrade without evidence must fail");

        assert!(matches!(err, TrustCardError::EvidenceRequiredForUpgrade));
    }

    #[test]
    fn update_route_rejects_empty_evidence_refs_on_mutation() {
        let mut registry = TrustCardRegistry::default();
        create_trust_card(
            &mut registry,
            sample_input("npm:@unit/empty-evidence-update"),
            2_000,
            "trace-create-empty-evidence",
        )
        .expect("create");
        let mut mutation = empty_mutation();
        mutation.evidence_refs = Some(Vec::new());

        let err = update_trust_card(
            &mut registry,
            "npm:@unit/empty-evidence-update",
            mutation,
            2_001,
            "trace-empty-evidence-update",
        )
        .expect_err("empty mutation evidence must fail");

        assert!(matches!(err, TrustCardError::EvidenceMissing));
    }

    #[test]
    fn update_route_rejects_revocation_reactivation() {
        let mut registry = TrustCardRegistry::default();
        create_trust_card(
            &mut registry,
            sample_input("npm:@unit/revoked-route"),
            2_000,
            "trace-create-revoked",
        )
        .expect("create");
        let mut revoke = empty_mutation();
        revoke.revocation_status = Some(RevocationStatus::Revoked {
            reason: "malicious behavior".to_string(),
            revoked_at: "2026-02-20T02:00:00Z".to_string(),
        });
        update_trust_card(
            &mut registry,
            "npm:@unit/revoked-route",
            revoke,
            2_001,
            "trace-revoke",
        )
        .expect("revoke");

        let mut reactivate = empty_mutation();
        reactivate.revocation_status = Some(RevocationStatus::Active);
        let err = update_trust_card(
            &mut registry,
            "npm:@unit/revoked-route",
            reactivate,
            2_002,
            "trace-reactivate-denied",
        )
        .expect_err("revocation must be irreversible");

        assert!(matches!(err, TrustCardError::RevocationIrreversible));
    }

    #[test]
    fn compare_route_rejects_missing_left_extension() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = compare_trust_cards(
            &mut registry,
            "npm:@missing/left",
            "npm:@acme/auth-guard",
            1_010,
            "trace-missing-left",
        )
        .expect_err("missing left side must fail");

        assert!(matches!(err, TrustCardError::NotFound(id) if id == "npm:@missing/left"));
    }

    #[test]
    fn compare_versions_route_rejects_missing_version() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = compare_trust_card_versions(
            &mut registry,
            "npm:@beta/telemetry-bridge",
            1,
            99,
            1_010,
            "trace-missing-version",
        )
        .expect_err("missing version must fail");

        assert!(matches!(
            err,
            TrustCardError::VersionNotFound {
                extension_id,
                version: 99
            } if extension_id == "npm:@beta/telemetry-bridge"
        ));
    }

    #[test]
    fn search_route_rejects_zero_page() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = search_trust_cards(
            &mut registry,
            "npm",
            1_001,
            "trace-zero-page-search",
            Pagination {
                page: 0,
                per_page: 10,
            },
        )
        .expect_err("zero page must fail");

        assert!(matches!(
            err,
            TrustCardError::InvalidPagination {
                page: 0,
                per_page: 10
            }
        ));
    }

    #[test]
    fn publisher_route_rejects_zero_page() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = get_trust_cards_by_publisher(
            &mut registry,
            "pub-acme",
            1_001,
            "trace-zero-page-publisher",
            Pagination {
                page: 0,
                per_page: 10,
            },
        )
        .expect_err("zero page must fail");

        assert!(matches!(
            err,
            TrustCardError::InvalidPagination {
                page: 0,
                per_page: 10
            }
        ));
    }

    #[test]
    fn list_route_rejects_zero_page() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = list_trust_cards(
            &mut registry,
            &TrustCardListFilter::empty(),
            1_001,
            "trace-zero-page-list",
            Pagination {
                page: 0,
                per_page: 10,
            },
        )
        .expect_err("zero page must fail");

        assert!(matches!(
            err,
            TrustCardError::InvalidPagination {
                page: 0,
                per_page: 10
            }
        ));
    }

    #[test]
    fn search_route_rejects_zero_per_page() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = search_trust_cards(
            &mut registry,
            "npm",
            1_001,
            "trace-zero-per-page-search",
            Pagination {
                page: 1,
                per_page: 0,
            },
        )
        .expect_err("zero per_page must fail");

        assert!(matches!(
            err,
            TrustCardError::InvalidPagination {
                page: 1,
                per_page: 0
            }
        ));
    }

    #[test]
    fn publisher_route_rejects_zero_per_page() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = get_trust_cards_by_publisher(
            &mut registry,
            "pub-acme",
            1_001,
            "trace-zero-per-page-publisher",
            Pagination {
                page: 1,
                per_page: 0,
            },
        )
        .expect_err("zero per_page must fail");

        assert!(matches!(
            err,
            TrustCardError::InvalidPagination {
                page: 1,
                per_page: 0
            }
        ));
    }

    #[test]
    fn compare_route_rejects_missing_right_extension() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = compare_trust_cards(
            &mut registry,
            "npm:@acme/auth-guard",
            "npm:@missing/right",
            1_010,
            "trace-missing-right",
        )
        .expect_err("missing right side must fail");

        assert!(matches!(err, TrustCardError::NotFound(id) if id == "npm:@missing/right"));
    }

    #[test]
    fn compare_versions_route_rejects_missing_extension() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = compare_trust_card_versions(
            &mut registry,
            "npm:@missing/versions",
            1,
            2,
            1_010,
            "trace-missing-extension-versions",
        )
        .expect_err("missing extension version comparison must fail");

        assert!(matches!(err, TrustCardError::NotFound(id) if id == "npm:@missing/versions"));
    }

    #[test]
    fn compare_versions_route_rejects_missing_left_version() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = compare_trust_card_versions(
            &mut registry,
            "npm:@beta/telemetry-bridge",
            99,
            2,
            1_010,
            "trace-missing-left-version",
        )
        .expect_err("missing left version must fail");

        assert!(matches!(
            err,
            TrustCardError::VersionNotFound {
                extension_id,
                version: 99
            } if extension_id == "npm:@beta/telemetry-bridge"
        ));
    }

    #[test]
    fn update_route_rejects_gold_upgrade_with_empty_evidence_refs() {
        let mut registry = TrustCardRegistry::default();
        create_trust_card(
            &mut registry,
            sample_input("npm:@unit/upgrade-empty-evidence"),
            2_000,
            "trace-create-upgrade-empty",
        )
        .expect("create");
        let mut mutation = empty_mutation();
        mutation.certification_level = Some(CertificationLevel::Gold);
        mutation.evidence_refs = Some(Vec::new());

        let err = update_trust_card(
            &mut registry,
            "npm:@unit/upgrade-empty-evidence",
            mutation,
            2_001,
            "trace-upgrade-empty-evidence",
        )
        .expect_err("empty evidence refs must fail before upgrade");

        assert!(matches!(err, TrustCardError::EvidenceMissing));
    }

    #[test]
    fn create_route_rejects_empty_evidence_refs_even_with_high_reputation() {
        let mut registry = TrustCardRegistry::default();
        let mut input = sample_input("npm:@unit/high-rep-no-evidence");
        input.reputation_score_basis_points = 999;
        input.evidence_refs = Vec::new();

        let err = create_trust_card(&mut registry, input, 2_000, "trace-high-rep-no-evidence")
            .expect_err("high reputation cannot replace evidence refs");

        assert!(matches!(err, TrustCardError::EvidenceMissing));
        assert!(
            get_trust_card(
                &mut registry,
                "npm:@unit/high-rep-no-evidence",
                2_001,
                "trace-read-high-rep-no-evidence"
            )
            .expect("read rejected card")
            .data
            .is_none()
        );
    }

    #[test]
    fn pagination_deserialize_rejects_missing_page() {
        let value = serde_json::json!({
            "per_page": 20
        });

        let result = serde_json::from_value::<Pagination>(value);

        assert!(result.is_err());
    }

    #[test]
    fn pagination_deserialize_rejects_negative_page() {
        let value = serde_json::json!({
            "page": -1,
            "per_page": 20
        });

        let result = serde_json::from_value::<Pagination>(value);

        assert!(result.is_err());
    }

    #[test]
    fn pagination_deserialize_rejects_string_per_page() {
        let value = serde_json::json!({
            "page": 1,
            "per_page": "20"
        });

        let result = serde_json::from_value::<Pagination>(value);

        assert!(result.is_err());
    }

    #[test]
    fn page_meta_deserialize_rejects_missing_total_pages() {
        let value = serde_json::json!({
            "page": 1,
            "per_page": 20,
            "total_items": 40
        });

        let result = serde_json::from_value::<PageMeta>(value);

        assert!(result.is_err());
    }

    #[test]
    fn page_meta_deserialize_rejects_negative_total_items() {
        let value = serde_json::json!({
            "page": 1,
            "per_page": 20,
            "total_items": -1,
            "total_pages": 1
        });

        let result = serde_json::from_value::<PageMeta>(value);

        assert!(result.is_err());
    }

    #[test]
    fn api_response_deserialize_rejects_missing_ok() {
        let value = serde_json::json!({
            "data": [],
            "page": null
        });

        let result = serde_json::from_value::<ApiResponse<Vec<String>>>(value);

        assert!(result.is_err());
    }

    #[test]
    fn api_response_deserialize_rejects_malformed_page_meta() {
        let value = serde_json::json!({
            "ok": true,
            "data": [],
            "page": {
                "page": 1,
                "per_page": "twenty",
                "total_items": 0,
                "total_pages": 0
            }
        });

        let result = serde_json::from_value::<ApiResponse<Vec<String>>>(value);

        assert!(result.is_err());
    }

    #[test]
    fn pagination_deserialize_rejects_missing_per_page() {
        let value = serde_json::json!({
            "page": 1
        });

        let result = serde_json::from_value::<Pagination>(value);

        assert!(result.is_err());
    }

    #[test]
    fn pagination_deserialize_rejects_string_page() {
        let value = serde_json::json!({
            "page": "1",
            "per_page": 20
        });

        let result = serde_json::from_value::<Pagination>(value);

        assert!(result.is_err());
    }

    #[test]
    fn pagination_deserialize_rejects_negative_per_page() {
        let value = serde_json::json!({
            "page": 1,
            "per_page": -20
        });

        let result = serde_json::from_value::<Pagination>(value);

        assert!(result.is_err());
    }

    #[test]
    fn page_meta_deserialize_rejects_negative_page() {
        let value = serde_json::json!({
            "page": -1,
            "per_page": 20,
            "total_items": 0,
            "total_pages": 0
        });

        let result = serde_json::from_value::<PageMeta>(value);

        assert!(result.is_err());
    }

    #[test]
    fn page_meta_deserialize_rejects_string_total_pages() {
        let value = serde_json::json!({
            "page": 1,
            "per_page": 20,
            "total_items": 0,
            "total_pages": "0"
        });

        let result = serde_json::from_value::<PageMeta>(value);

        assert!(result.is_err());
    }

    #[test]
    fn api_response_deserialize_rejects_string_ok_flag() {
        let value = serde_json::json!({
            "ok": "true",
            "data": [],
            "page": null
        });

        let result = serde_json::from_value::<ApiResponse<Vec<String>>>(value);

        assert!(result.is_err());
    }

    #[test]
    fn api_response_deserialize_rejects_non_array_data() {
        let value = serde_json::json!({
            "ok": true,
            "data": "not-a-list",
            "page": null
        });

        let result = serde_json::from_value::<ApiResponse<Vec<String>>>(value);

        assert!(result.is_err());
    }

    #[test]
    fn api_response_deserialize_rejects_non_object_page() {
        let value = serde_json::json!({
            "ok": true,
            "data": [],
            "page": "page-one"
        });

        let result = serde_json::from_value::<ApiResponse<Vec<String>>>(value);

        assert!(result.is_err());
    }

    #[test]
    fn pagination_deserialize_rejects_null_page() {
        let value = serde_json::json!({
            "page": null,
            "per_page": 20
        });

        let result = serde_json::from_value::<Pagination>(value);

        assert!(result.is_err());
    }

    #[test]
    fn pagination_deserialize_rejects_float_per_page() {
        let value = serde_json::json!({
            "page": 1,
            "per_page": 20.5
        });

        let result = serde_json::from_value::<Pagination>(value);

        assert!(result.is_err());
    }

    #[test]
    fn pagination_deserialize_rejects_u64_overflow_page() {
        let result =
            serde_json::from_str::<Pagination>(r#"{"page":18446744073709551616,"per_page":20}"#);

        assert!(result.is_err());
    }

    #[test]
    fn page_meta_deserialize_rejects_null_total_items() {
        let value = serde_json::json!({
            "page": 1,
            "per_page": 20,
            "total_items": null,
            "total_pages": 0
        });

        let result = serde_json::from_value::<PageMeta>(value);

        assert!(result.is_err());
    }

    #[test]
    fn api_response_deserialize_rejects_missing_data() {
        let value = serde_json::json!({
            "ok": true,
            "page": null
        });

        let result = serde_json::from_value::<ApiResponse<Vec<String>>>(value);

        assert!(result.is_err());
    }

    #[test]
    fn api_response_deserialize_rejects_null_data_for_vec() {
        let value = serde_json::json!({
            "ok": true,
            "data": null,
            "page": null
        });

        let result = serde_json::from_value::<ApiResponse<Vec<String>>>(value);

        assert!(result.is_err());
    }

    #[test]
    fn pagination_deserialize_rejects_u64_overflow_per_page() {
        let result =
            serde_json::from_str::<Pagination>(r#"{"page":1,"per_page":18446744073709551616}"#);

        assert!(result.is_err());
    }

    #[test]
    fn pagination_deserialize_rejects_boolean_page() {
        let value = serde_json::json!({
            "page": false,
            "per_page": 20
        });

        let result = serde_json::from_value::<Pagination>(value);

        assert!(result.is_err());
    }

    #[test]
    fn page_meta_deserialize_rejects_u64_overflow_total_pages() {
        let result = serde_json::from_str::<PageMeta>(
            r#"{"page":1,"per_page":20,"total_items":0,"total_pages":18446744073709551616}"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn page_meta_deserialize_rejects_float_page() {
        let value = serde_json::json!({
            "page": 1.5,
            "per_page": 20,
            "total_items": 0,
            "total_pages": 0
        });

        let result = serde_json::from_value::<PageMeta>(value);

        assert!(result.is_err());
    }

    #[test]
    fn api_response_deserialize_rejects_nested_page_missing_per_page() {
        let value = serde_json::json!({
            "ok": true,
            "data": [],
            "page": {
                "page": 1,
                "total_items": 0,
                "total_pages": 0
            }
        });

        let result = serde_json::from_value::<ApiResponse<Vec<String>>>(value);

        assert!(result.is_err());
    }

    #[test]
    fn api_response_deserialize_rejects_nested_page_negative_total_pages() {
        let value = serde_json::json!({
            "ok": true,
            "data": [],
            "page": {
                "page": 1,
                "per_page": 20,
                "total_items": 0,
                "total_pages": -1
            }
        });

        let result = serde_json::from_value::<ApiResponse<Vec<String>>>(value);

        assert!(result.is_err());
    }

    #[test]
    fn empty_registry_list_rejects_invalid_page_before_empty_success() {
        let mut registry = TrustCardRegistry::default();

        let err = list_trust_cards(
            &mut registry,
            &TrustCardListFilter::empty(),
            1_001,
            "trace-empty-invalid-page",
            Pagination {
                page: 0,
                per_page: 20,
            },
        )
        .expect_err("invalid page must fail even when the registry is empty");

        assert!(matches!(
            err,
            TrustCardError::InvalidPagination {
                page: 0,
                per_page: 20
            }
        ));
    }

    #[test]
    fn missing_publisher_route_rejects_invalid_per_page_before_empty_success() {
        let mut registry = fixture_registry(1_000).expect("fixture registry");

        let err = get_trust_cards_by_publisher(
            &mut registry,
            "pub-does-not-exist",
            1_001,
            "trace-missing-publisher-invalid-page",
            Pagination {
                page: 1,
                per_page: 0,
            },
        )
        .expect_err("invalid per_page must fail even for missing publisher");

        assert!(matches!(
            err,
            TrustCardError::InvalidPagination {
                page: 1,
                per_page: 0
            }
        ));
    }
}
