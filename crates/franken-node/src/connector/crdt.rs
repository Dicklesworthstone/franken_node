//! CRDT state mode scaffolding.
//!
//! Provides four conflict-free replicated data types for connector state:
//! LWW-Map, OR-Set, GCounter, PNCounter. Each supports deterministic,
//! commutative, and idempotent merge operations.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Schema tag for CRDT type identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrdtType {
    LwwMap,
    OrSet,
    GCounter,
    PnCounter,
}

impl CrdtType {
    pub const ALL: [CrdtType; 4] = [Self::LwwMap, Self::OrSet, Self::GCounter, Self::PnCounter];
}

impl fmt::Display for CrdtType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LwwMap => write!(f, "lww_map"),
            Self::OrSet => write!(f, "or_set"),
            Self::GCounter => write!(f, "gcounter"),
            Self::PnCounter => write!(f, "pncounter"),
        }
    }
}

/// Error for CRDT operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrdtError {
    #[serde(rename = "CRDT_TYPE_MISMATCH")]
    TypeMismatch {
        expected: CrdtType,
        actual: CrdtType,
    },
}

impl fmt::Display for CrdtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeMismatch { expected, actual } => {
                write!(f, "CRDT_TYPE_MISMATCH: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for CrdtError {}

// === LWW-Map ===

/// Last-Writer-Wins Map: per-key timestamp determines the winning value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LwwMap {
    pub crdt_type: CrdtType,
    pub entries: BTreeMap<String, LwwEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LwwEntry {
    pub value: serde_json::Value,
    pub timestamp: u64,
}

impl Default for LwwMap {
    fn default() -> Self {
        Self {
            crdt_type: CrdtType::LwwMap,
            entries: BTreeMap::new(),
        }
    }
}

impl LwwMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: String, value: serde_json::Value, timestamp: u64) {
        match self.entries.get(&key) {
            Some(existing) if existing.timestamp >= timestamp => {}
            _ => {
                self.entries.insert(key, LwwEntry { value, timestamp });
            }
        }
    }

    pub fn merge(&self, other: &LwwMap) -> Result<LwwMap, CrdtError> {
        if self.crdt_type != other.crdt_type {
            return Err(CrdtError::TypeMismatch {
                expected: self.crdt_type,
                actual: other.crdt_type,
            });
        }
        let mut result = self.clone();
        for (key, entry) in &other.entries {
            result.set(key.clone(), entry.value.clone(), entry.timestamp);
        }
        Ok(result)
    }
}

// === OR-Set ===

/// Observed-Remove Set: add wins over concurrent remove.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrSet {
    pub crdt_type: CrdtType,
    pub adds: BTreeSet<String>,
    pub removes: BTreeSet<String>,
}

impl Default for OrSet {
    fn default() -> Self {
        Self {
            crdt_type: CrdtType::OrSet,
            adds: BTreeSet::new(),
            removes: BTreeSet::new(),
        }
    }
}

impl OrSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, element: String) {
        self.adds.insert(element);
    }

    pub fn remove(&mut self, element: String) {
        self.removes.insert(element);
    }

    pub fn elements(&self) -> BTreeSet<&String> {
        self.adds.difference(&self.removes).collect()
    }

    pub fn merge(&self, other: &OrSet) -> Result<OrSet, CrdtError> {
        if self.crdt_type != other.crdt_type {
            return Err(CrdtError::TypeMismatch {
                expected: self.crdt_type,
                actual: other.crdt_type,
            });
        }
        Ok(OrSet {
            crdt_type: CrdtType::OrSet,
            adds: self.adds.union(&other.adds).cloned().collect(),
            removes: self.removes.union(&other.removes).cloned().collect(),
        })
    }
}

// === GCounter ===

/// Grow-only Counter: each replica has its own monotonically increasing count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GCounter {
    pub crdt_type: CrdtType,
    pub counts: BTreeMap<String, u64>,
}

impl Default for GCounter {
    fn default() -> Self {
        Self {
            crdt_type: CrdtType::GCounter,
            counts: BTreeMap::new(),
        }
    }
}

impl GCounter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment(&mut self, replica_id: &str, amount: u64) {
        let count = self.counts.entry(replica_id.to_string()).or_insert(0);
        *count += amount;
    }

    pub fn value(&self) -> u64 {
        self.counts.values().sum()
    }

    pub fn merge(&self, other: &GCounter) -> Result<GCounter, CrdtError> {
        if self.crdt_type != other.crdt_type {
            return Err(CrdtError::TypeMismatch {
                expected: self.crdt_type,
                actual: other.crdt_type,
            });
        }
        let mut counts = self.counts.clone();
        for (replica, &count) in &other.counts {
            let entry = counts.entry(replica.clone()).or_insert(0);
            *entry = (*entry).max(count);
        }
        Ok(GCounter {
            crdt_type: CrdtType::GCounter,
            counts,
        })
    }
}

// === PNCounter ===

/// Positive-Negative Counter: tracks increments and decrements separately.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PnCounter {
    pub crdt_type: CrdtType,
    pub positive: GCounter,
    pub negative: GCounter,
}

impl Default for PnCounter {
    fn default() -> Self {
        Self {
            crdt_type: CrdtType::PnCounter,
            positive: GCounter::new(),
            negative: GCounter::new(),
        }
    }
}

impl PnCounter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment(&mut self, replica_id: &str, amount: u64) {
        self.positive.increment(replica_id, amount);
    }

    pub fn decrement(&mut self, replica_id: &str, amount: u64) {
        self.negative.increment(replica_id, amount);
    }

    pub fn value(&self) -> i64 {
        self.positive.value() as i64 - self.negative.value() as i64
    }

    pub fn merge(&self, other: &PnCounter) -> Result<PnCounter, CrdtError> {
        if self.crdt_type != other.crdt_type {
            return Err(CrdtError::TypeMismatch {
                expected: self.crdt_type,
                actual: other.crdt_type,
            });
        }
        Ok(PnCounter {
            crdt_type: CrdtType::PnCounter,
            positive: self.positive.merge(&other.positive)?,
            negative: self.negative.merge(&other.negative)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // === LWW-Map tests ===

    #[test]
    fn lww_map_set_and_get() {
        let mut m = LwwMap::new();
        m.set("key1".into(), json!("val1"), 1);
        assert_eq!(m.entries["key1"].value, json!("val1"));
    }

    #[test]
    fn lww_map_later_timestamp_wins() {
        let mut m = LwwMap::new();
        m.set("key1".into(), json!("old"), 1);
        m.set("key1".into(), json!("new"), 2);
        assert_eq!(m.entries["key1"].value, json!("new"));
    }

    #[test]
    fn lww_map_older_timestamp_ignored() {
        let mut m = LwwMap::new();
        m.set("key1".into(), json!("new"), 2);
        m.set("key1".into(), json!("old"), 1);
        assert_eq!(m.entries["key1"].value, json!("new"));
    }

    #[test]
    fn lww_map_merge_commutative() {
        let mut a = LwwMap::new();
        a.set("k".into(), json!("a"), 1);
        let mut b = LwwMap::new();
        b.set("k".into(), json!("b"), 2);
        let ab = a.merge(&b).unwrap();
        let ba = b.merge(&a).unwrap();
        assert_eq!(ab.entries["k"].value, ba.entries["k"].value);
    }

    #[test]
    fn lww_map_merge_idempotent() {
        let mut a = LwwMap::new();
        a.set("k".into(), json!("v"), 1);
        let aa = a.merge(&a).unwrap();
        assert_eq!(aa.entries, a.entries);
    }

    // === OR-Set tests ===

    #[test]
    fn or_set_add_visible() {
        let mut s = OrSet::new();
        s.add("x".into());
        assert!(s.elements().contains(&&"x".to_string()));
    }

    #[test]
    fn or_set_remove_hides() {
        let mut s = OrSet::new();
        s.add("x".into());
        s.remove("x".into());
        assert!(!s.elements().contains(&&"x".to_string()));
    }

    #[test]
    fn or_set_merge_commutative() {
        let mut a = OrSet::new();
        a.add("x".into());
        let mut b = OrSet::new();
        b.add("y".into());
        let ab = a.merge(&b).unwrap();
        let ba = b.merge(&a).unwrap();
        assert_eq!(ab.elements(), ba.elements());
    }

    #[test]
    fn or_set_merge_idempotent() {
        let mut a = OrSet::new();
        a.add("x".into());
        let aa = a.merge(&a).unwrap();
        assert_eq!(aa.elements(), a.elements());
    }

    // === GCounter tests ===

    #[test]
    fn gcounter_increment() {
        let mut c = GCounter::new();
        c.increment("r1", 5);
        assert_eq!(c.value(), 5);
    }

    #[test]
    fn gcounter_multi_replica() {
        let mut c = GCounter::new();
        c.increment("r1", 3);
        c.increment("r2", 7);
        assert_eq!(c.value(), 10);
    }

    #[test]
    fn gcounter_merge_commutative() {
        let mut a = GCounter::new();
        a.increment("r1", 5);
        let mut b = GCounter::new();
        b.increment("r2", 3);
        let ab = a.merge(&b).unwrap();
        let ba = b.merge(&a).unwrap();
        assert_eq!(ab.value(), ba.value());
    }

    #[test]
    fn gcounter_merge_idempotent() {
        let mut a = GCounter::new();
        a.increment("r1", 5);
        let aa = a.merge(&a).unwrap();
        assert_eq!(aa.value(), a.value());
    }

    #[test]
    fn gcounter_merge_takes_max() {
        let mut a = GCounter::new();
        a.increment("r1", 5);
        let mut b = GCounter::new();
        b.increment("r1", 3);
        let ab = a.merge(&b).unwrap();
        assert_eq!(ab.value(), 5); // max(5, 3) = 5
    }

    // === PNCounter tests ===

    #[test]
    fn pncounter_increment() {
        let mut c = PnCounter::new();
        c.increment("r1", 10);
        assert_eq!(c.value(), 10);
    }

    #[test]
    fn pncounter_decrement() {
        let mut c = PnCounter::new();
        c.increment("r1", 10);
        c.decrement("r1", 3);
        assert_eq!(c.value(), 7);
    }

    #[test]
    fn pncounter_negative_value() {
        let mut c = PnCounter::new();
        c.decrement("r1", 5);
        assert_eq!(c.value(), -5);
    }

    #[test]
    fn pncounter_merge_commutative() {
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
    fn pncounter_merge_idempotent() {
        let mut a = PnCounter::new();
        a.increment("r1", 10);
        let aa = a.merge(&a).unwrap();
        assert_eq!(aa.value(), a.value());
    }

    // === Type mismatch tests ===

    #[test]
    fn type_mismatch_error() {
        let err = CrdtError::TypeMismatch {
            expected: CrdtType::LwwMap,
            actual: CrdtType::OrSet,
        };
        assert!(err.to_string().contains("CRDT_TYPE_MISMATCH"));
    }

    #[test]
    fn four_crdt_types() {
        assert_eq!(CrdtType::ALL.len(), 4);
    }

    #[test]
    fn serde_roundtrip_type() {
        for &t in &CrdtType::ALL {
            let json = serde_json::to_string(&t).unwrap();
            let parsed: CrdtType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, parsed);
        }
    }
}
