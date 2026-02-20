//! API-style route handlers for trust-card queries.
//!
//! These are pure functions over `TrustCardRegistry` to keep behavior
//! consistent between CLI and API surfaces.

use serde::{Deserialize, Serialize};

use crate::supply_chain::trust_card::{
    paginate, TrustCard, TrustCardError, TrustCardRegistry,
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

pub fn get_trust_cards_by_publisher(
    registry: &TrustCardRegistry,
    publisher_id: &str,
    now_secs: u64,
    trace_id: &str,
    pagination: Pagination,
) -> Result<ApiResponse<Vec<TrustCard>>, TrustCardError> {
    let all = registry.list_by_publisher(publisher_id, now_secs, trace_id);
    let total_items = all.len();
    let data = paginate(&all, pagination.page, pagination.per_page)?;
    let total_pages = if total_items == 0 {
        0
    } else {
        (total_items - 1) / pagination.per_page + 1
    };
    Ok(ApiResponse {
        ok: true,
        data,
        page: Some(PageMeta {
            page: pagination.page,
            per_page: pagination.per_page,
            total_items,
            total_pages,
        }),
    })
}

pub fn search_trust_cards(
    registry: &TrustCardRegistry,
    query: &str,
    now_secs: u64,
    trace_id: &str,
    pagination: Pagination,
) -> Result<ApiResponse<Vec<TrustCard>>, TrustCardError> {
    let all = registry.search(query, now_secs, trace_id);
    let total_items = all.len();
    let data = paginate(&all, pagination.page, pagination.per_page)?;
    let total_pages = if total_items == 0 {
        0
    } else {
        (total_items - 1) / pagination.per_page + 1
    };
    Ok(ApiResponse {
        ok: true,
        data,
        page: Some(PageMeta {
            page: pagination.page,
            per_page: pagination.per_page,
            total_items,
            total_pages,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::trust_card::demo_registry;

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
        let registry = demo_registry(1_000).expect("demo");
        let response = get_trust_cards_by_publisher(
            &registry,
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
        let registry = demo_registry(1_000).expect("demo");
        let response = search_trust_cards(
            &registry,
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
}
