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
        if let Some(existing) = self.entries.get(&key) {
            if existing.timestamp > timestamp {
                return;
            }
            if existing.timestamp == timestamp {
                // Deterministic tie-break via lexicographic JSON comparison.
                // If either serialization fails, keep existing (deterministic choice).
                let current_str = match serde_json::to_string(&existing.value) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let new_str = match serde_json::to_string(&value) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                if current_str >= new_str {
                    return;
                }
            }
        }
        self.entries.insert(key, LwwEntry { value, timestamp });
    }

    pub fn merge(&self, other: &LwwMap) -> Result<LwwMap, CrdtError> {
        if self.crdt_type != CrdtType::LwwMap {
            return Err(CrdtError::TypeMismatch {
                expected: CrdtType::LwwMap,
                actual: self.crdt_type,
            });
        }
        if other.crdt_type != CrdtType::LwwMap {
            return Err(CrdtError::TypeMismatch {
                expected: CrdtType::LwwMap,
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
    pub adds: BTreeMap<String, BTreeSet<OrTag>>,
    pub removes: BTreeMap<String, BTreeSet<OrTag>>,
    pub next_dot_by_replica: BTreeMap<String, u64>,
}

/// Deterministic add-tag for OR-Set elements.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrTag {
    pub replica_id: String,
    pub counter: u64,
}

impl Default for OrSet {
    fn default() -> Self {
        Self {
            crdt_type: CrdtType::OrSet,
            adds: BTreeMap::new(),
            removes: BTreeMap::new(),
            next_dot_by_replica: BTreeMap::new(),
        }
    }
}

impl OrSet {
    pub fn new() -> Self {
        Self::default()
    }

    fn max_observed_counter_for_replica(&self, replica_id: &str) -> u64 {
        self.adds
            .values()
            .chain(self.removes.values())
            .flat_map(|tags| tags.iter())
            .filter(|tag| tag.replica_id == replica_id)
            .map(|tag| tag.counter)
            .max()
            .unwrap_or(0)
    }

    fn sync_next_dot_floors(&mut self) {
        let mut observed_by_replica = BTreeMap::new();
        for tag in self
            .adds
            .values()
            .chain(self.removes.values())
            .flat_map(|tags| tags.iter())
        {
            let observed = observed_by_replica
                .entry(tag.replica_id.clone())
                .or_insert(0_u64);
            *observed = (*observed).max(tag.counter);
        }

        for (replica_id, observed) in observed_by_replica {
            let stored = self.next_dot_by_replica.entry(replica_id).or_insert(0);
            *stored = (*stored).max(observed);
        }
    }

    pub fn add(&mut self, replica_id: &str, element: String) {
        if replica_id.is_empty() {
            return;
        }
        let observed_counter = self.max_observed_counter_for_replica(replica_id);
        let replica_id = replica_id.to_string();
        let counter = self
            .next_dot_by_replica
            .entry(replica_id.clone())
            .or_insert(0);
        let next_dot_floor = (*counter).max(observed_counter);
        if next_dot_floor == u64::MAX {
            *counter = u64::MAX;
            return;
        }
        *counter = next_dot_floor.saturating_add(1);
        self.adds.entry(element).or_default().insert(OrTag {
            replica_id,
            counter: *counter,
        });
    }

    pub fn remove(&mut self, element: String) {
        let Some(observed_tags) = self.adds.get(&element) else {
            return;
        };
        self.removes
            .entry(element)
            .or_default()
            .extend(observed_tags.iter().cloned());
    }

    pub fn elements(&self) -> BTreeSet<&String> {
        self.adds
            .iter()
            .filter_map(|(element, add_tags)| {
                let removed_tags = self.removes.get(element);
                add_tags
                    .iter()
                    .any(|tag| removed_tags.is_none_or(|removed| !removed.contains(tag)))
                    .then_some(element)
            })
            .collect()
    }

    pub fn merge(&self, other: &OrSet) -> Result<OrSet, CrdtError> {
        if self.crdt_type != CrdtType::OrSet {
            return Err(CrdtError::TypeMismatch {
                expected: CrdtType::OrSet,
                actual: self.crdt_type,
            });
        }
        if other.crdt_type != CrdtType::OrSet {
            return Err(CrdtError::TypeMismatch {
                expected: CrdtType::OrSet,
                actual: other.crdt_type,
            });
        }
        let mut result = OrSet {
            crdt_type: CrdtType::OrSet,
            adds: self.adds.iter().chain(other.adds.iter()).fold(
                BTreeMap::new(),
                |mut acc, (element, tags)| {
                    acc.entry(element.clone())
                        .or_insert_with(BTreeSet::new)
                        .extend(tags.iter().cloned());
                    acc
                },
            ),
            removes: self.removes.iter().chain(other.removes.iter()).fold(
                BTreeMap::new(),
                |mut acc, (element, tags)| {
                    acc.entry(element.clone())
                        .or_insert_with(BTreeSet::new)
                        .extend(tags.iter().cloned());
                    acc
                },
            ),
            next_dot_by_replica: self
                .next_dot_by_replica
                .iter()
                .chain(other.next_dot_by_replica.iter())
                .fold(BTreeMap::new(), |mut acc, (replica_id, counter)| {
                    let entry = acc.entry(replica_id.clone()).or_insert(0);
                    *entry = (*entry).max(*counter);
                    acc
                }),
        };
        result.sync_next_dot_floors();
        Ok(result)
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
        *count = count.saturating_add(amount);
    }

    pub fn value(&self) -> u64 {
        self.counts.values().fold(0u64, |a, b| a.saturating_add(*b))
    }

    pub fn merge(&self, other: &GCounter) -> Result<GCounter, CrdtError> {
        if self.crdt_type != CrdtType::GCounter {
            return Err(CrdtError::TypeMismatch {
                expected: CrdtType::GCounter,
                actual: self.crdt_type,
            });
        }
        if other.crdt_type != CrdtType::GCounter {
            return Err(CrdtError::TypeMismatch {
                expected: CrdtType::GCounter,
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

    pub fn value(&self) -> i128 {
        self.positive.value() as i128 - self.negative.value() as i128
    }

    pub fn merge(&self, other: &PnCounter) -> Result<PnCounter, CrdtError> {
        if self.crdt_type != CrdtType::PnCounter {
            return Err(CrdtError::TypeMismatch {
                expected: CrdtType::PnCounter,
                actual: self.crdt_type,
            });
        }
        if other.crdt_type != CrdtType::PnCounter {
            return Err(CrdtError::TypeMismatch {
                expected: CrdtType::PnCounter,
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

    #[test]
    fn lww_map_merge_equal_timestamp_commutative() {
        let mut a = LwwMap::new();
        a.set("k".into(), json!("a"), 1);
        let mut b = LwwMap::new();
        b.set("k".into(), json!("b"), 1);
        let ab = a.merge(&b).unwrap();
        let ba = b.merge(&a).unwrap();
        assert_eq!(ab.entries["k"].value, ba.entries["k"].value);
    }

    #[test]
    fn lww_map_equal_timestamp_lower_json_ignored() {
        let mut m = LwwMap::new();
        m.set("k".into(), json!("z"), 7);
        m.set("k".into(), json!("a"), 7);
        assert_eq!(m.entries["k"].value, json!("z"));
    }

    #[test]
    fn lww_map_merge_rejects_type_mismatch() {
        let a = LwwMap::new();
        let mut b = LwwMap::new();
        b.crdt_type = CrdtType::OrSet;

        let err = a.merge(&b).unwrap_err();

        assert_eq!(
            err,
            CrdtError::TypeMismatch {
                expected: CrdtType::LwwMap,
                actual: CrdtType::OrSet
            }
        );
    }

    #[test]
    fn lww_map_merge_rejects_matching_corrupt_type_tags() {
        let mut a = LwwMap::new();
        let mut b = LwwMap::new();
        a.crdt_type = CrdtType::OrSet;
        b.crdt_type = CrdtType::OrSet;

        let err = a.merge(&b).unwrap_err();

        assert_eq!(
            err,
            CrdtError::TypeMismatch {
                expected: CrdtType::LwwMap,
                actual: CrdtType::OrSet
            }
        );
    }

    // === OR-Set tests ===

    #[test]
    fn or_set_add_visible() {
        let mut s = OrSet::new();
        s.add("r1", "x".into());
        assert!(s.elements().contains(&&"x".to_string()));
    }

    #[test]
    fn or_set_remove_hides() {
        let mut s = OrSet::new();
        s.add("r1", "x".into());
        s.remove("x".into());
        assert!(!s.elements().contains(&&"x".to_string()));
    }

    #[test]
    fn or_set_merge_commutative() {
        let mut a = OrSet::new();
        a.add("r1", "x".into());
        let mut b = OrSet::new();
        b.add("r2", "y".into());
        let ab = a.merge(&b).unwrap();
        let ba = b.merge(&a).unwrap();
        assert_eq!(ab.elements(), ba.elements());
    }

    #[test]
    fn or_set_merge_idempotent() {
        let mut a = OrSet::new();
        a.add("r1", "x".into());
        let aa = a.merge(&a).unwrap();
        assert_eq!(aa.elements(), a.elements());
    }

    #[test]
    fn or_set_remove_without_observation_does_not_tombstone_future_add() {
        let mut s = OrSet::new();
        s.remove("x".into());
        s.add("r1", "x".into());
        assert!(s.elements().contains(&&"x".to_string()));
    }

    #[test]
    fn or_set_readd_after_remove_visible_again() {
        let mut s = OrSet::new();
        s.add("r1", "x".into());
        s.remove("x".into());
        s.add("r1", "x".into());
        assert!(s.elements().contains(&&"x".to_string()));
    }

    #[test]
    fn or_set_concurrent_add_wins_over_remove() {
        let mut remove_branch = OrSet::new();
        remove_branch.add("r1", "x".into());

        let mut add_branch = remove_branch.clone();
        remove_branch.remove("x".into());
        add_branch.add("r2", "x".into());

        let merged = remove_branch.merge(&add_branch).unwrap();
        let reverse_merged = add_branch.merge(&remove_branch).unwrap();

        assert!(merged.elements().contains(&&"x".to_string()));
        assert_eq!(merged.elements(), reverse_merged.elements());
    }

    #[test]
    fn or_set_add_empty_replica_ignored() {
        let mut s = OrSet::new();

        s.add("", "x".into());

        assert!(s.adds.is_empty());
        assert!(s.next_dot_by_replica.is_empty());
        assert!(s.elements().is_empty());
    }

    #[test]
    fn or_set_add_at_max_counter_ignored() {
        let mut s = OrSet::new();
        s.next_dot_by_replica.insert("r1".to_string(), u64::MAX);

        s.add("r1", "x".into());

        assert!(s.adds.is_empty());
        assert_eq!(s.next_dot_by_replica["r1"], u64::MAX);
    }

    #[test]
    fn or_set_add_after_stale_next_dot_uses_observed_tag_floor() {
        let mut s = OrSet::new();
        let removed_tag = OrTag {
            replica_id: "r1".to_string(),
            counter: 5,
        };
        s.adds
            .entry("x".to_string())
            .or_default()
            .insert(removed_tag.clone());
        s.removes
            .entry("x".to_string())
            .or_default()
            .insert(removed_tag);
        s.next_dot_by_replica.insert("r1".to_string(), 4);

        s.add("r1", "x".into());

        assert_eq!(s.next_dot_by_replica["r1"], 6);
        assert!(s.adds["x"].contains(&OrTag {
            replica_id: "r1".to_string(),
            counter: 6,
        }));
        assert!(s.elements().contains(&&"x".to_string()));
    }

    #[test]
    fn or_set_merge_lifts_next_dot_to_observed_tag_floor() {
        let mut remote = OrSet::new();
        remote
            .adds
            .entry("x".to_string())
            .or_default()
            .insert(OrTag {
                replica_id: "r1".to_string(),
                counter: 9,
            });
        remote.next_dot_by_replica.insert("r1".to_string(), 2);

        let mut merged = OrSet::new().merge(&remote).unwrap();

        assert_eq!(merged.next_dot_by_replica["r1"], 9);
        merged.add("r1", "y".into());
        assert_eq!(merged.next_dot_by_replica["r1"], 10);
        assert!(merged.adds["y"].contains(&OrTag {
            replica_id: "r1".to_string(),
            counter: 10,
        }));
    }

    #[test]
    fn or_set_merge_rejects_type_mismatch() {
        let a = OrSet::new();
        let mut b = OrSet::new();
        b.crdt_type = CrdtType::GCounter;

        let err = a.merge(&b).unwrap_err();

        assert_eq!(
            err,
            CrdtError::TypeMismatch {
                expected: CrdtType::OrSet,
                actual: CrdtType::GCounter
            }
        );
    }

    #[test]
    fn or_set_merge_rejects_matching_corrupt_type_tags() {
        let mut a = OrSet::new();
        let mut b = OrSet::new();
        a.crdt_type = CrdtType::GCounter;
        b.crdt_type = CrdtType::GCounter;

        let err = a.merge(&b).unwrap_err();

        assert_eq!(
            err,
            CrdtError::TypeMismatch {
                expected: CrdtType::OrSet,
                actual: CrdtType::GCounter
            }
        );
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

    #[test]
    fn gcounter_merge_rejects_type_mismatch() {
        let a = GCounter::new();
        let mut b = GCounter::new();
        b.crdt_type = CrdtType::LwwMap;

        let err = a.merge(&b).unwrap_err();

        assert_eq!(
            err,
            CrdtError::TypeMismatch {
                expected: CrdtType::GCounter,
                actual: CrdtType::LwwMap
            }
        );
    }

    #[test]
    fn gcounter_merge_rejects_matching_corrupt_type_tags() {
        let mut a = GCounter::new();
        let mut b = GCounter::new();
        a.crdt_type = CrdtType::LwwMap;
        b.crdt_type = CrdtType::LwwMap;

        let err = a.merge(&b).unwrap_err();

        assert_eq!(
            err,
            CrdtError::TypeMismatch {
                expected: CrdtType::GCounter,
                actual: CrdtType::LwwMap
            }
        );
    }

    #[test]
    fn gcounter_value_saturates_instead_of_wrapping() {
        let mut c = GCounter::new();
        c.counts.insert("r1".to_string(), u64::MAX);
        c.counts.insert("r2".to_string(), 1);

        assert_eq!(c.value(), u64::MAX);
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

    #[test]
    fn pncounter_merge_rejects_outer_type_mismatch() {
        let a = PnCounter::new();
        let mut b = PnCounter::new();
        b.crdt_type = CrdtType::GCounter;

        let err = a.merge(&b).unwrap_err();

        assert_eq!(
            err,
            CrdtError::TypeMismatch {
                expected: CrdtType::PnCounter,
                actual: CrdtType::GCounter
            }
        );
    }

    #[test]
    fn pncounter_merge_rejects_matching_corrupt_outer_type_tags() {
        let mut a = PnCounter::new();
        let mut b = PnCounter::new();
        a.crdt_type = CrdtType::GCounter;
        b.crdt_type = CrdtType::GCounter;

        let err = a.merge(&b).unwrap_err();

        assert_eq!(
            err,
            CrdtError::TypeMismatch {
                expected: CrdtType::PnCounter,
                actual: CrdtType::GCounter
            }
        );
    }

    #[test]
    fn pncounter_merge_rejects_nested_counter_type_mismatch() {
        let a = PnCounter::new();
        let mut b = PnCounter::new();
        b.positive.crdt_type = CrdtType::OrSet;

        let err = a.merge(&b).unwrap_err();

        assert_eq!(
            err,
            CrdtError::TypeMismatch {
                expected: CrdtType::GCounter,
                actual: CrdtType::OrSet
            }
        );
    }

    #[test]
    fn pncounter_merge_rejects_matching_corrupt_nested_counter_type_tags() {
        let mut a = PnCounter::new();
        let mut b = PnCounter::new();
        a.positive.crdt_type = CrdtType::OrSet;
        b.positive.crdt_type = CrdtType::OrSet;

        let err = a.merge(&b).unwrap_err();

        assert_eq!(
            err,
            CrdtError::TypeMismatch {
                expected: CrdtType::GCounter,
                actual: CrdtType::OrSet
            }
        );
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

    #[test]
    fn serde_unknown_crdt_type_fails() {
        let err = serde_json::from_str::<CrdtType>("\"unknown\"");
        assert!(err.is_err());
    }

    #[test]
    fn serde_lww_map_missing_entries_fails() {
        let err = serde_json::from_str::<LwwMap>(r#"{"crdt_type":"lww_map"}"#);
        assert!(err.is_err());
    }

    #[test]
    fn serde_crdt_type_is_case_sensitive() {
        let err = serde_json::from_str::<CrdtType>("\"LWW_MAP\"");

        assert!(err.is_err());
    }

    #[test]
    fn serde_or_set_missing_adds_fails() {
        let err = serde_json::from_str::<OrSet>(
            r#"{"crdt_type":"or_set","removes":{},"next_dot_by_replica":{}}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn serde_or_set_negative_tag_counter_fails() {
        let err = serde_json::from_str::<OrSet>(
            r#"{
  "crdt_type":"or_set",
  "adds":{"x":[{"replica_id":"r1","counter":-1}]},
  "removes":{},
  "next_dot_by_replica":{"r1":1}
}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn serde_gcounter_missing_counts_fails() {
        let err = serde_json::from_str::<GCounter>(r#"{"crdt_type":"gcounter"}"#);

        assert!(err.is_err());
    }

    #[test]
    fn serde_gcounter_negative_count_fails() {
        let err =
            serde_json::from_str::<GCounter>(r#"{"crdt_type":"gcounter","counts":{"r1":-1}}"#);

        assert!(err.is_err());
    }

    #[test]
    fn serde_pncounter_missing_negative_counter_fails() {
        let err = serde_json::from_str::<PnCounter>(
            r#"{
  "crdt_type":"pncounter",
  "positive":{"crdt_type":"gcounter","counts":{}}
}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn serde_pncounter_malformed_nested_counter_fails() {
        let err = serde_json::from_str::<PnCounter>(
            r#"{
  "crdt_type":"pncounter",
  "positive":{"crdt_type":"gcounter"},
  "negative":{"crdt_type":"gcounter","counts":{}}
}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn negative_serde_lww_entry_rejects_negative_timestamp() {
        let err = serde_json::from_str::<LwwEntry>(r#"{"value":"x","timestamp":-1}"#);

        assert!(err.is_err());
    }

    #[test]
    fn negative_serde_lww_map_rejects_object_timestamp() {
        let err = serde_json::from_str::<LwwMap>(
            r#"{
  "crdt_type":"lww_map",
  "entries":{"k":{"value":"x","timestamp":{"nested":1}}}
}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn negative_serde_or_set_rejects_string_tag_counter() {
        let err = serde_json::from_str::<OrSet>(
            r#"{
  "crdt_type":"or_set",
  "adds":{"x":[{"replica_id":"r1","counter":"1"}]},
  "removes":{},
  "next_dot_by_replica":{"r1":1}
}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn negative_serde_or_set_rejects_malformed_next_dot_map() {
        let err = serde_json::from_str::<OrSet>(
            r#"{
  "crdt_type":"or_set",
  "adds":{},
  "removes":{},
  "next_dot_by_replica":["r1"]
}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn negative_serde_or_set_rejects_remove_value_that_is_not_tag_set() {
        let err = serde_json::from_str::<OrSet>(
            r#"{
  "crdt_type":"or_set",
  "adds":{},
  "removes":{"x":{"replica_id":"r1","counter":1}},
  "next_dot_by_replica":{}
}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn negative_serde_gcounter_rejects_string_count() {
        let err =
            serde_json::from_str::<GCounter>(r#"{"crdt_type":"gcounter","counts":{"r1":"1"}}"#);

        assert!(err.is_err());
    }

    #[test]
    fn negative_serde_pncounter_rejects_array_positive_counter() {
        let err = serde_json::from_str::<PnCounter>(
            r#"{
  "crdt_type":"pncounter",
  "positive":[],
  "negative":{"crdt_type":"gcounter","counts":{}}
}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn negative_serde_crdt_error_rejects_missing_actual_type() {
        let err =
            serde_json::from_str::<CrdtError>(r#"{"CRDT_TYPE_MISMATCH":{"expected":"lww_map"}}"#);

        assert!(err.is_err());
    }

    #[test]
    fn negative_serde_crdt_error_rejects_unknown_variant() {
        let err = serde_json::from_str::<CrdtError>(
            r#"{"CRDT_NOT_A_REAL_ERROR":{"expected":"lww_map","actual":"or_set"}}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn or_set_remove_unknown_element_does_not_create_tombstone() {
        let mut s = OrSet::new();

        s.remove("unknown".into());

        assert!(s.removes.is_empty());
        assert!(s.elements().is_empty());
    }
}
