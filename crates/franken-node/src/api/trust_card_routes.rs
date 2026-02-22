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
    TrustCard, TrustCardComparison, TrustCardError, TrustCardInput, TrustCardListFilter,
    TrustCardMutation, TrustCardRegistry, paginate,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageMeta {
    pub page: usize,
    pub per_page: usize,
    pub total_items: usize,
    pub total_pages: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub ok: bool,
    pub data: T,
    pub page: Option<PageMeta>,
}

fn paged_response<T: Clone>(
    all: &[T],
    pagination: Pagination,
) -> Result<ApiResponse<Vec<T>>, TrustCardError> {
    let per_page = pagination.per_page.max(1);
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
    let all = registry.list(filter, trace_id, now_secs);
    paged_response(&all, pagination)
}

pub fn get_trust_cards_by_publisher(
    registry: &mut TrustCardRegistry,
    publisher_id: &str,
    now_secs: u64,
    trace_id: &str,
    pagination: Pagination,
) -> Result<ApiResponse<Vec<TrustCard>>, TrustCardError> {
    let all = registry.list_by_publisher(publisher_id, now_secs, trace_id);
    paged_response(&all, pagination)
}

pub fn search_trust_cards(
    registry: &mut TrustCardRegistry,
    query: &str,
    now_secs: u64,
    trace_id: &str,
    pagination: Pagination,
) -> Result<ApiResponse<Vec<TrustCard>>, TrustCardError> {
    let all = registry.search(query, now_secs, trace_id);
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
    use crate::supply_chain::trust_card::{
        CapabilityDeclaration, CapabilityRisk, CertificationLevel, ExtensionIdentity,
        PublisherIdentity, ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel,
        TrustCardInput, TrustCardMutation, demo_registry,
    };

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
                attestation_level: "slsa-l2".to_string(),
                source_uri: "registry://test".to_string(),
                verified_at: "2026-02-20T00:00:00Z".to_string(),
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
        }
    }

    #[test]
    fn get_card_returns_data() {
        let mut registry = demo_registry(1_000).expect("demo");
        let response = get_trust_card(&mut registry, "npm:@acme/auth-guard", 1_001, "trace")
            .expect("response");
        assert!(response.ok);
        assert!(response.data.is_some());
    }

    #[test]
    fn publisher_list_paginates() {
        let mut registry = demo_registry(1_000).expect("demo");
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
        let mut registry = demo_registry(1_000).expect("demo");
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
        let mut registry = demo_registry(1_000).expect("demo");
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
    fn compare_routes_produce_diffs() {
        let mut registry = demo_registry(1_000).expect("demo");
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
}
