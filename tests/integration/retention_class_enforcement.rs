//! Integration tests for bd-1p2b: Control-plane retention policy.

use frankenengine_node::connector::retention_policy::*;

fn registry() -> RetentionRegistry {
    let mut reg = RetentionRegistry::new();
    reg.register(RetentionPolicy {
        message_type: "invoke".into(),
        retention_class: RetentionClass::Required,
        ephemeral_ttl_seconds: 0,
    }).unwrap();
    reg.register(RetentionPolicy {
        message_type: "heartbeat".into(),
        retention_class: RetentionClass::Ephemeral,
        ephemeral_ttl_seconds: 60,
    }).unwrap();
    reg
}

#[test]
fn inv_cpr_classified() {
    let mut store = RetentionStore::new(registry(), 10000).unwrap();
    let err = store.store("m1", "unknown_type", 100, 1000).unwrap_err();
    assert_eq!(err.code(), "CPR_UNCLASSIFIED", "INV-CPR-CLASSIFIED: unclassified must be rejected");
}

#[test]
fn inv_cpr_required_durable() {
    let mut store = RetentionStore::new(registry(), 10000).unwrap();
    store.store("m1", "invoke", 100, 1000).unwrap();
    // Cannot be dropped
    let err = store.drop_message("m1", 2000).unwrap_err();
    assert_eq!(err.code(), "CPR_DROP_REQUIRED", "INV-CPR-REQUIRED-DURABLE: required objects never dropped");
    // Survives ephemeral cleanup
    store.cleanup_ephemeral(2000);
    assert!(store.contains("m1"), "INV-CPR-REQUIRED-DURABLE: must survive cleanup");
}

#[test]
fn inv_cpr_ephemeral_policy() {
    let mut store = RetentionStore::new(registry(), 10000).unwrap();
    store.store("m1", "heartbeat", 50, 1000).unwrap();
    // Before TTL: not dropped
    let dropped = store.cleanup_ephemeral(1050);
    assert!(dropped.is_empty(), "INV-CPR-EPHEMERAL-POLICY: not dropped before TTL");
    assert!(store.contains("m1"));
    // After TTL: dropped
    let dropped = store.cleanup_ephemeral(1060);
    assert!(!dropped.is_empty(), "INV-CPR-EPHEMERAL-POLICY: dropped after TTL");
    assert!(!store.contains("m1"));
}

#[test]
fn inv_cpr_auditable() {
    let mut store = RetentionStore::new(registry(), 10000).unwrap();
    store.store("m1", "invoke", 100, 1000).unwrap();
    store.store("m2", "heartbeat", 50, 1000).unwrap();
    store.drop_message("m2", 1001).unwrap();
    let decisions = store.decisions();
    assert!(decisions.len() >= 3, "INV-CPR-AUDITABLE: must record all decisions");
    assert!(decisions.iter().any(|d| d.action == "store"), "INV-CPR-AUDITABLE: store decisions");
    assert!(decisions.iter().any(|d| d.action == "drop"), "INV-CPR-AUDITABLE: drop decisions");
}
