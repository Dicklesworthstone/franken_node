//! CRDT merge law conformance tests (bd-19u).
//!
//! Verifies commutativity, associativity, and idempotency for all four
//! CRDT types: LWW-Map, OR-Set, GCounter, PNCounter.

use frankenengine_node::connector::crdt::*;
use serde_json::json;

// === LWW-Map conformance ===

#[test]
fn lww_map_commutativity() {
    let mut a = LwwMap::new();
    a.set("k".into(), json!("a"), 1);
    let mut b = LwwMap::new();
    b.set("k".into(), json!("b"), 2);

    let ab = a.merge(&b).unwrap();
    let ba = b.merge(&a).unwrap();
    assert_eq!(ab.entries, ba.entries);
}

#[test]
fn lww_map_associativity() {
    let mut a = LwwMap::new();
    a.set("k".into(), json!("a"), 1);
    let mut b = LwwMap::new();
    b.set("k".into(), json!("b"), 2);
    let mut c = LwwMap::new();
    c.set("k".into(), json!("c"), 3);

    let ab_c = a.merge(&b).unwrap().merge(&c).unwrap();
    let a_bc = a.merge(&b.merge(&c).unwrap()).unwrap();
    assert_eq!(ab_c.entries, a_bc.entries);
}

#[test]
fn lww_map_idempotency() {
    let mut a = LwwMap::new();
    a.set("k".into(), json!("v"), 1);
    let aa = a.merge(&a).unwrap();
    assert_eq!(aa.entries, a.entries);
}

// === OR-Set conformance ===

#[test]
fn or_set_commutativity() {
    let mut a = OrSet::new();
    a.add("x".into());
    let mut b = OrSet::new();
    b.add("y".into());

    let ab = a.merge(&b).unwrap();
    let ba = b.merge(&a).unwrap();
    assert_eq!(ab.elements(), ba.elements());
}

#[test]
fn or_set_associativity() {
    let mut a = OrSet::new();
    a.add("x".into());
    let mut b = OrSet::new();
    b.add("y".into());
    let mut c = OrSet::new();
    c.add("z".into());
    c.remove("x".into());

    let ab_c = a.merge(&b).unwrap().merge(&c).unwrap();
    let a_bc = a.merge(&b.merge(&c).unwrap()).unwrap();
    assert_eq!(ab_c.elements(), a_bc.elements());
}

#[test]
fn or_set_idempotency() {
    let mut a = OrSet::new();
    a.add("x".into());
    a.add("y".into());
    a.remove("y".into());
    let aa = a.merge(&a).unwrap();
    assert_eq!(aa.elements(), a.elements());
}

// === GCounter conformance ===

#[test]
fn gcounter_commutativity() {
    let mut a = GCounter::new();
    a.increment("r1", 5);
    let mut b = GCounter::new();
    b.increment("r2", 3);

    let ab = a.merge(&b).unwrap();
    let ba = b.merge(&a).unwrap();
    assert_eq!(ab.value(), ba.value());
    assert_eq!(ab.counts, ba.counts);
}

#[test]
fn gcounter_associativity() {
    let mut a = GCounter::new();
    a.increment("r1", 5);
    let mut b = GCounter::new();
    b.increment("r1", 3);
    b.increment("r2", 7);
    let mut c = GCounter::new();
    c.increment("r2", 10);
    c.increment("r3", 2);

    let ab_c = a.merge(&b).unwrap().merge(&c).unwrap();
    let a_bc = a.merge(&b.merge(&c).unwrap()).unwrap();
    assert_eq!(ab_c.value(), a_bc.value());
    assert_eq!(ab_c.counts, a_bc.counts);
}

#[test]
fn gcounter_idempotency() {
    let mut a = GCounter::new();
    a.increment("r1", 5);
    let aa = a.merge(&a).unwrap();
    assert_eq!(aa.value(), a.value());
    assert_eq!(aa.counts, a.counts);
}

// === PNCounter conformance ===

#[test]
fn pncounter_commutativity() {
    let mut a = PnCounter::new();
    a.increment("r1", 10);
    a.decrement("r1", 3);
    let mut b = PnCounter::new();
    b.increment("r2", 5);

    let ab = a.merge(&b).unwrap();
    let ba = b.merge(&a).unwrap();
    assert_eq!(ab.value(), ba.value());
}

#[test]
fn pncounter_associativity() {
    let mut a = PnCounter::new();
    a.increment("r1", 10);
    a.decrement("r1", 3);
    let mut b = PnCounter::new();
    b.increment("r2", 5);
    b.decrement("r2", 1);
    let mut c = PnCounter::new();
    c.increment("r3", 2);
    c.decrement("r3", 8);

    let ab_c = a.merge(&b).unwrap().merge(&c).unwrap();
    let a_bc = a.merge(&b.merge(&c).unwrap()).unwrap();
    assert_eq!(ab_c.value(), a_bc.value());
}

#[test]
fn pncounter_idempotency() {
    let mut a = PnCounter::new();
    a.increment("r1", 10);
    a.decrement("r1", 3);
    let aa = a.merge(&a).unwrap();
    assert_eq!(aa.value(), a.value());
}

// === Cross-type error ===

#[test]
fn type_mismatch_returns_error() {
    let a = LwwMap::new();
    // Construct a fake LwwMap with wrong type tag
    let bad = LwwMap {
        crdt_type: CrdtType::OrSet,
        entries: std::collections::BTreeMap::new(),
    };
    let result = a.merge(&bad);
    assert!(result.is_err());
    match result.unwrap_err() {
        CrdtError::TypeMismatch { expected, actual } => {
            assert_eq!(expected, CrdtType::LwwMap);
            assert_eq!(actual, CrdtType::OrSet);
        }
    }
}
