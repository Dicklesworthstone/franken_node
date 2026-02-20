//! Integration tests for bd-21z signed decision receipt export.

use frankenengine_node::security::decision_receipt::{
    Decision, HighImpactActionRegistry, Receipt, ReceiptQuery, append_signed_receipt,
    demo_public_key, demo_signing_key, enforce_high_impact_receipt, export_receipts,
    export_receipts_cbor, import_receipts_cbor, verify_hash_chain, verify_receipt,
};
use serde_json::json;

fn sample_receipt(action: &str, decision: Decision, timestamp: &str) -> Receipt {
    let mut receipt = Receipt::new(
        action,
        "control-plane@test",
        &json!({"action": action}),
        &json!({"status": "ok"}),
        decision,
        "integration test decision",
        vec!["ledger-42".to_string()],
        vec!["policy.rule.demo".to_string()],
        0.88,
        "franken-node trust sync --force",
    )
    .expect("receipt should build");
    receipt.timestamp = timestamp.to_string();
    receipt
}

#[test]
fn sign_verify_chain_export_roundtrip() {
    let mut chain = Vec::new();
    let key = demo_signing_key();
    let pub_key = demo_public_key();

    append_signed_receipt(
        &mut chain,
        sample_receipt("quarantine", Decision::Approved, "2026-02-20T10:00:00Z"),
        &key,
    )
    .expect("append #1");
    append_signed_receipt(
        &mut chain,
        sample_receipt("revocation", Decision::Denied, "2026-02-20T11:00:00Z"),
        &key,
    )
    .expect("append #2");

    verify_hash_chain(&chain).expect("chain should verify");
    assert!(verify_receipt(&chain[0], &pub_key).expect("verify #1"));
    assert!(verify_receipt(&chain[1], &pub_key).expect("verify #2"));

    let cbor = export_receipts_cbor(&chain, &ReceiptQuery::default()).expect("encode");
    let decoded = import_receipts_cbor(&cbor).expect("decode");
    assert_eq!(decoded, chain);
}

#[test]
fn query_and_high_impact_enforcement_work() {
    let mut chain = Vec::new();
    let key = demo_signing_key();
    append_signed_receipt(
        &mut chain,
        sample_receipt("quarantine", Decision::Approved, "2026-02-20T10:00:00Z"),
        &key,
    )
    .expect("append");

    let filter = ReceiptQuery {
        action_name: Some("quarantine".to_string()),
        from_timestamp: Some("2026-02-20T09:00:00Z".to_string()),
        to_timestamp: Some("2026-02-20T12:00:00Z".to_string()),
        limit: Some(5),
    };
    let filtered = export_receipts(&chain, &filter);
    assert_eq!(filtered.len(), 1);

    let registry = HighImpactActionRegistry::with_defaults();
    enforce_high_impact_receipt("quarantine", &registry, Some(&chain[0]))
        .expect("receipt should satisfy high-impact requirement");
    assert!(enforce_high_impact_receipt("quarantine", &registry, None).is_err());
}
