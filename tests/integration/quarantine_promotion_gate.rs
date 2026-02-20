//! Integration tests for bd-3cm3: Schema-gated quarantine promotion.

use frankenengine_node::connector::quarantine_promotion::*;

fn rule() -> PromotionRule {
    PromotionRule {
        required_schema_version: "1.0".into(),
        require_reachability: true,
        require_pin: false,
    }
}

fn req(id: &str, auth: bool, schema: &str, reachable: bool) -> PromotionRequest {
    PromotionRequest {
        object_id: id.into(),
        requester_id: "admin".into(),
        authenticated: auth,
        schema_version: schema.into(),
        reachable,
        pinned: false,
        reason: "integration test".into(),
    }
}

#[test]
fn inv_qpr_schema_gated() {
    let r = req("obj1", true, "2.0", true);
    let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
    assert!(!result.promoted, "INV-QPR-SCHEMA-GATED: wrong schema must block promotion");
    assert!(result.rejection_reasons.iter().any(|r| matches!(r, RejectionReason::SchemaFailed { .. })));
}

#[test]
fn inv_qpr_authenticated() {
    let r = req("obj1", false, "1.0", true);
    let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
    assert!(!result.promoted, "INV-QPR-AUTHENTICATED: unauthenticated must be rejected");
    assert!(result.rejection_reasons.contains(&RejectionReason::NotAuthenticated));
}

#[test]
fn inv_qpr_receipt() {
    let r = req("obj1", true, "1.0", true);
    let result = evaluate_promotion(&r, &rule(), "validator-1", "trace-abc", "2026-01-01").unwrap();
    assert!(result.promoted, "INV-QPR-RECEIPT: valid promotion must succeed");
    let receipt = result.receipt.unwrap();
    assert_eq!(receipt.object_id, "obj1");
    assert_eq!(receipt.validator_id, "validator-1");
    assert_eq!(receipt.trace_id, "trace-abc");
    assert!(!receipt.reason.is_empty(), "INV-QPR-RECEIPT: must include promotion reason");
}

#[test]
fn inv_qpr_fail_closed() {
    // Multiple failures: all must result in no promotion
    let r = req("obj1", false, "2.0", false);
    let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
    assert!(!result.promoted, "INV-QPR-FAIL-CLOSED: any error must deny promotion");
    assert!(result.receipt.is_none(), "INV-QPR-FAIL-CLOSED: no receipt on rejection");
    assert!(result.rejection_reasons.len() >= 3, "INV-QPR-FAIL-CLOSED: all failures recorded");
}
