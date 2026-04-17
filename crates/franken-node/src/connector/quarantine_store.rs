//! bd-2eun: Quarantine-by-default store for unreferenced objects.
//!
//! Unknown objects enter quarantine class by default. Quota and TTL eviction
//! enforce hard caps. Quarantined objects are excluded from primary gossip state.

use std::collections::BTreeMap;

/// Quarantine configuration.
#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    pub max_objects: usize,
    pub max_bytes: u64,
    pub ttl_seconds: u64,
}

impl QuarantineConfig {
    pub fn default_config() -> Self {
        Self {
            max_objects: 10_000,
            max_bytes: 100_000_000,
            ttl_seconds: 3600,
        }
    }
}

/// A quarantined object entry.
#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub object_id: String,
    pub size_bytes: u64,
    pub ingested_at: u64,
    pub source_peer: String,
}

/// Current quarantine statistics.
#[derive(Debug, Clone)]
pub struct QuarantineStats {
    pub object_count: usize,
    pub total_bytes: u64,
    pub oldest_entry_age: u64,
    pub evictions_total: u64,
}

/// Record of an eviction.
#[derive(Debug, Clone)]
pub struct EvictionRecord {
    pub object_id: String,
    pub reason: String,
    pub evicted_at: u64,
    pub age_seconds: u64,
}

/// Errors from quarantine operations.
#[derive(Debug, Clone, PartialEq)]
pub enum QuarantineError {
    QuotaExceeded {
        current_bytes: u64,
        max_bytes: u64,
    },
    TtlExpired {
        object_id: String,
        age: u64,
        ttl: u64,
    },
    Duplicate {
        object_id: String,
    },
    NotFound {
        object_id: String,
    },
    InvalidConfig {
        reason: String,
    },
}

impl QuarantineError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::QuotaExceeded { .. } => "QDS_QUOTA_EXCEEDED",
            Self::TtlExpired { .. } => "QDS_TTL_EXPIRED",
            Self::Duplicate { .. } => "QDS_DUPLICATE",
            Self::NotFound { .. } => "QDS_NOT_FOUND",
            Self::InvalidConfig { .. } => "QDS_INVALID_CONFIG",
        }
    }
}

impl std::fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QuotaExceeded {
                current_bytes,
                max_bytes,
            } => write!(f, "QDS_QUOTA_EXCEEDED: {current_bytes}/{max_bytes} bytes"),
            Self::TtlExpired {
                object_id,
                age,
                ttl,
            } => write!(f, "QDS_TTL_EXPIRED: {object_id} age={age}s ttl={ttl}s"),
            Self::Duplicate { object_id } => write!(f, "QDS_DUPLICATE: {object_id}"),
            Self::NotFound { object_id } => write!(f, "QDS_NOT_FOUND: {object_id}"),
            Self::InvalidConfig { reason } => write!(f, "QDS_INVALID_CONFIG: {reason}"),
        }
    }
}

/// Validate quarantine config.
pub fn validate_config(config: &QuarantineConfig) -> Result<(), QuarantineError> {
    if config.max_objects == 0 {
        return Err(QuarantineError::InvalidConfig {
            reason: "max_objects must be > 0".into(),
        });
    }
    if config.max_bytes == 0 {
        return Err(QuarantineError::InvalidConfig {
            reason: "max_bytes must be > 0".into(),
        });
    }
    if config.ttl_seconds == 0 {
        return Err(QuarantineError::InvalidConfig {
            reason: "ttl_seconds must be > 0".into(),
        });
    }
    Ok(())
}

/// Quarantine store with quota and TTL enforcement.
#[derive(Debug)]
pub struct QuarantineStore {
    config: QuarantineConfig,
    entries: BTreeMap<String, QuarantineEntry>,
    total_bytes: u64,
    evictions_total: u64,
}

impl QuarantineStore {
    pub fn new(config: QuarantineConfig) -> Result<Self, QuarantineError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            entries: BTreeMap::new(),
            total_bytes: 0,
            evictions_total: 0,
        })
    }

    /// Evict all TTL-expired entries. INV-QDS-TTL: eviction before admission.
    pub fn evict_expired(&mut self, now: u64) -> Vec<EvictionRecord> {
        let mut evicted = Vec::new();
        let expired_ids: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.ingested_at) >= self.config.ttl_seconds)
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired_ids {
            if let Some(entry) = self.entries.remove(&id) {
                self.total_bytes = self.total_bytes.saturating_sub(entry.size_bytes);
                self.evictions_total = self.evictions_total.saturating_add(1);
                evicted.push(EvictionRecord {
                    object_id: id,
                    reason: "ttl_expired".into(),
                    evicted_at: now,
                    age_seconds: now.saturating_sub(entry.ingested_at),
                });
            }
        }

        evicted
    }

    /// Evict oldest entries to fit within quota.
    fn evict_for_quota(&mut self, needed_bytes: u64, now: u64) -> Vec<EvictionRecord> {
        let mut evicted = Vec::new();

        // Evict by oldest first until we have room
        while (self.entries.len() >= self.config.max_objects
            || self.total_bytes.saturating_add(needed_bytes) > self.config.max_bytes)
            && !self.entries.is_empty()
        {
            // Find oldest entry (deterministic: break ties by object_id)
            let oldest_id = self
                .entries
                .iter()
                .min_by(|a, b| a.1.ingested_at.cmp(&b.1.ingested_at).then(a.0.cmp(b.0)))
                .map(|(id, _)| id.clone());

            if let Some(id) = oldest_id {
                if let Some(entry) = self.entries.remove(&id) {
                    self.total_bytes = self.total_bytes.saturating_sub(entry.size_bytes);
                    self.evictions_total = self.evictions_total.saturating_add(1);
                    evicted.push(EvictionRecord {
                        object_id: id,
                        reason: "quota_exceeded".into(),
                        evicted_at: now,
                        age_seconds: now.saturating_sub(entry.ingested_at),
                    });
                }
            } else {
                break;
            }
        }

        evicted
    }

    /// Ingest an object into quarantine.
    ///
    /// INV-QDS-DEFAULT: all unknown objects go here.
    /// INV-QDS-TTL: expired entries evicted first.
    /// INV-QDS-BOUNDED: quota enforced via eviction.
    pub fn ingest(
        &mut self,
        object_id: &str,
        size_bytes: u64,
        source_peer: &str,
        now: u64,
    ) -> Result<Vec<EvictionRecord>, QuarantineError> {
        // Step 1: evict TTL-expired entries
        let mut evictions = self.evict_expired(now);

        // Duplicate check must happen after TTL cleanup so expired entries do
        // not block re-ingest of the same object ID.
        if self.entries.contains_key(object_id) {
            return Err(QuarantineError::Duplicate {
                object_id: object_id.to_string(),
            });
        }

        // If the incoming object can never fit, reject without evicting healthy
        // entries for quota pressure.
        if size_bytes > self.config.max_bytes {
            return Err(QuarantineError::QuotaExceeded {
                current_bytes: self.total_bytes,
                max_bytes: self.config.max_bytes,
            });
        }

        // Step 2: if still over quota, evict oldest
        if self.entries.len() >= self.config.max_objects
            || self.total_bytes.saturating_add(size_bytes) > self.config.max_bytes
        {
            evictions.extend(self.evict_for_quota(size_bytes, now));
        }

        self.entries.insert(
            object_id.to_string(),
            QuarantineEntry {
                object_id: object_id.to_string(),
                size_bytes,
                ingested_at: now,
                source_peer: source_peer.to_string(),
            },
        );
        self.total_bytes = self.total_bytes.saturating_add(size_bytes);

        Ok(evictions)
    }

    /// Promote an object out of quarantine (after schema validation).
    pub fn promote(&mut self, object_id: &str) -> Result<QuarantineEntry, QuarantineError> {
        match self.entries.remove(object_id) {
            Some(entry) => {
                self.total_bytes = self.total_bytes.saturating_sub(entry.size_bytes);
                Ok(entry)
            }
            None => Err(QuarantineError::NotFound {
                object_id: object_id.to_string(),
            }),
        }
    }

    /// Check if an object is quarantined.
    pub fn contains(&self, object_id: &str) -> bool {
        self.entries.contains_key(object_id)
    }

    /// Get current stats.
    pub fn stats(&self, now: u64) -> QuarantineStats {
        let oldest_age = self
            .entries
            .values()
            .map(|e| now.saturating_sub(e.ingested_at))
            .max()
            .unwrap_or(0);

        QuarantineStats {
            object_count: self.entries.len(),
            total_bytes: self.total_bytes,
            oldest_entry_age: oldest_age,
            evictions_total: self.evictions_total,
        }
    }

    /// Snapshot of quarantined object IDs, sorted for determinism.
    /// INV-QDS-EXCLUDED: these IDs must NOT appear in primary gossip state.
    pub fn quarantined_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.entries.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Get the quarantine config.
    pub fn config(&self) -> &QuarantineConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> QuarantineConfig {
        QuarantineConfig {
            max_objects: 5,
            max_bytes: 500,
            ttl_seconds: 100,
        }
    }

    #[test]
    fn ingest_single_object() {
        let mut store = QuarantineStore::new(config()).unwrap();
        let evictions = store.ingest("obj1", 100, "peer1", 1000).unwrap();
        assert!(evictions.is_empty());
        assert!(store.contains("obj1"));
        assert_eq!(store.stats(1000).object_count, 1);
    }

    #[test]
    fn reject_duplicate() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 100, "peer1", 1000).unwrap();
        let err = store.ingest("obj1", 100, "peer2", 1001).unwrap_err();
        assert_eq!(err.code(), "QDS_DUPLICATE");
    }

    #[test]
    fn ttl_eviction() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 100, "peer1", 1000).unwrap();
        // After TTL
        let evictions = store.evict_expired(1100);
        assert_eq!(evictions.len(), 1);
        assert_eq!(evictions[0].object_id, "obj1");
        assert_eq!(evictions[0].reason, "ttl_expired");
        assert!(!store.contains("obj1"));
    }

    #[test]
    fn quota_count_eviction() {
        let mut store = QuarantineStore::new(config()).unwrap();
        for i in 0..5 {
            store
                .ingest(&format!("obj{i}"), 10, "peer1", 1000 + i as u64)
                .unwrap();
        }
        // 6th object triggers quota eviction
        let evictions = store.ingest("obj5", 10, "peer1", 1010).unwrap();
        assert!(!evictions.is_empty());
        assert_eq!(store.stats(1010).object_count, 5);
    }

    #[test]
    fn quota_bytes_eviction() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 400, "peer1", 1000).unwrap();
        // This would exceed 500 bytes
        let evictions = store.ingest("obj2", 200, "peer1", 1001).unwrap();
        assert!(!evictions.is_empty());
        assert!(store.stats(1001).total_bytes <= 500);
    }

    #[test]
    fn object_too_large() {
        let mut store = QuarantineStore::new(config()).unwrap();
        let err = store.ingest("big", 600, "peer1", 1000).unwrap_err();
        assert_eq!(err.code(), "QDS_QUOTA_EXCEEDED");
    }

    #[test]
    fn promote_removes_from_quarantine() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 100, "peer1", 1000).unwrap();
        let entry = store.promote("obj1").unwrap();
        assert_eq!(entry.object_id, "obj1");
        assert!(!store.contains("obj1"));
        assert_eq!(store.stats(1000).total_bytes, 0);
    }

    #[test]
    fn promote_not_found() {
        let mut store = QuarantineStore::new(config()).unwrap();
        let err = store.promote("missing").unwrap_err();
        assert_eq!(err.code(), "QDS_NOT_FOUND");
    }

    #[test]
    fn quarantined_ids_sorted() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("z-obj", 10, "peer1", 1000).unwrap();
        store.ingest("a-obj", 10, "peer1", 1001).unwrap();
        store.ingest("m-obj", 10, "peer1", 1002).unwrap();
        let ids = store.quarantined_ids();
        assert_eq!(ids, vec!["a-obj", "m-obj", "z-obj"]);
    }

    #[test]
    fn stats_oldest_age() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 10, "peer1", 1000).unwrap();
        store.ingest("obj2", 10, "peer1", 1050).unwrap();
        let stats = store.stats(1080);
        assert_eq!(stats.oldest_entry_age, 80);
    }

    #[test]
    fn eviction_count_tracked() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 10, "peer1", 1000).unwrap();
        store.evict_expired(1200);
        assert_eq!(store.stats(1200).evictions_total, 1);
    }

    #[test]
    fn ttl_eviction_before_ingest() {
        let mut store = QuarantineStore::new(config()).unwrap();
        // Fill up
        for i in 0..5 {
            store.ingest(&format!("obj{i}"), 10, "peer1", 1000).unwrap();
        }
        // All should be expired at t=1200, so new ingest should work after eviction
        let evictions = store.ingest("new", 10, "peer1", 1200).unwrap();
        assert_eq!(evictions.len(), 5); // all 5 evicted
        assert!(store.contains("new"));
        assert_eq!(store.stats(1200).object_count, 1);
    }

    #[test]
    fn invalid_config_zero_objects() {
        let mut cfg = config();
        cfg.max_objects = 0;
        let err = QuarantineStore::new(cfg).unwrap_err();
        assert_eq!(err.code(), "QDS_INVALID_CONFIG");
    }

    #[test]
    fn invalid_config_zero_bytes() {
        let mut cfg = config();
        cfg.max_bytes = 0;
        let err = QuarantineStore::new(cfg).unwrap_err();
        assert_eq!(err.code(), "QDS_INVALID_CONFIG");
    }

    #[test]
    fn invalid_config_zero_ttl() {
        let mut cfg = config();
        cfg.ttl_seconds = 0;
        let err = QuarantineStore::new(cfg).unwrap_err();
        assert_eq!(err.code(), "QDS_INVALID_CONFIG");
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            QuarantineError::QuotaExceeded {
                current_bytes: 0,
                max_bytes: 0
            }
            .code(),
            "QDS_QUOTA_EXCEEDED"
        );
        assert_eq!(
            QuarantineError::TtlExpired {
                object_id: "".into(),
                age: 0,
                ttl: 0
            }
            .code(),
            "QDS_TTL_EXPIRED"
        );
        assert_eq!(
            QuarantineError::Duplicate {
                object_id: "".into()
            }
            .code(),
            "QDS_DUPLICATE"
        );
        assert_eq!(
            QuarantineError::NotFound {
                object_id: "".into()
            }
            .code(),
            "QDS_NOT_FOUND"
        );
        assert_eq!(
            QuarantineError::InvalidConfig { reason: "".into() }.code(),
            "QDS_INVALID_CONFIG"
        );
    }

    #[test]
    fn error_display() {
        let e = QuarantineError::QuotaExceeded {
            current_bytes: 500,
            max_bytes: 400,
        };
        assert!(e.to_string().contains("QDS_QUOTA_EXCEEDED"));
    }

    #[test]
    fn default_config_valid() {
        assert!(validate_config(&QuarantineConfig::default_config()).is_ok());
    }

    #[test]
    fn bytes_tracked_correctly() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 100, "peer1", 1000).unwrap();
        store.ingest("obj2", 150, "peer1", 1001).unwrap();
        assert_eq!(store.stats(1001).total_bytes, 250);
        store.promote("obj1").unwrap();
        assert_eq!(store.stats(1001).total_bytes, 150);
    }

    #[test]
    fn oversized_ingest_does_not_evict_existing_entries() {
        let mut store = QuarantineStore::new(config()).unwrap();
        for i in 0..5 {
            store
                .ingest(&format!("obj{i}"), 10, "peer1", 1000 + i as u64)
                .unwrap();
        }

        let err = store.ingest("oversized", 600, "peer2", 1006).unwrap_err();
        assert_eq!(err.code(), "QDS_QUOTA_EXCEEDED");
        assert_eq!(store.stats(1006).object_count, 5);
        assert!(store.contains("obj0"));
    }

    #[test]
    fn quota_eviction_handles_large_totals_without_overflow() {
        let cfg = QuarantineConfig {
            max_objects: 1,
            max_bytes: u64::MAX,
            ttl_seconds: 100,
        };
        let mut store = QuarantineStore::new(cfg).unwrap();
        store.ingest("obj1", u64::MAX - 1, "peer1", 1000).unwrap();

        let evictions = store.ingest("obj2", 10, "peer1", 1001).unwrap();
        assert_eq!(evictions.len(), 1);
        assert!(store.contains("obj2"));
        assert!(!store.contains("obj1"));
    }

    #[test]
    fn reingest_same_object_after_ttl_expiry_succeeds() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 100, "peer1", 1000).unwrap();

        let evictions = store.ingest("obj1", 120, "peer2", 1200).unwrap();
        assert_eq!(evictions.len(), 1);
        assert_eq!(evictions[0].object_id, "obj1");
        assert_eq!(evictions[0].reason, "ttl_expired");
        assert!(store.contains("obj1"));
        assert_eq!(store.stats(1200).total_bytes, 120);
    }

    #[test]
    fn duplicate_one_second_before_ttl_boundary_is_rejected() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 100, "peer1", 1000).unwrap();

        let err = store.ingest("obj1", 120, "peer2", 1099).unwrap_err();

        assert_eq!(err.code(), "QDS_DUPLICATE");
        assert!(store.contains("obj1"));
        assert_eq!(store.stats(1099).object_count, 1);
        assert_eq!(store.stats(1099).total_bytes, 100);
    }

    #[test]
    fn ttl_eviction_does_not_fire_before_boundary() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 100, "peer1", 1000).unwrap();

        let evictions = store.evict_expired(1099);

        assert!(evictions.is_empty());
        assert!(store.contains("obj1"));
        assert_eq!(store.stats(1099).evictions_total, 0);
    }

    #[test]
    fn oversized_ingest_after_ttl_cleanup_still_rejects() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("expired", 100, "peer1", 1000).unwrap();

        let err = store.ingest("too-big", 501, "peer2", 1200).unwrap_err();

        assert_eq!(err.code(), "QDS_QUOTA_EXCEEDED");
        assert!(!store.contains("expired"));
        assert!(!store.contains("too-big"));
        assert_eq!(store.stats(1200).object_count, 0);
        assert_eq!(store.stats(1200).evictions_total, 1);
    }

    #[test]
    fn oversized_ingest_reports_current_bytes_without_mutating_store() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 200, "peer1", 1000).unwrap();
        store.ingest("obj2", 150, "peer1", 1001).unwrap();

        let err = store.ingest("too-big", 501, "peer2", 1002).unwrap_err();

        assert_eq!(
            err,
            QuarantineError::QuotaExceeded {
                current_bytes: 350,
                max_bytes: 500,
            }
        );
        assert_eq!(store.stats(1002).object_count, 2);
        assert_eq!(store.stats(1002).total_bytes, 350);
        assert_eq!(store.quarantined_ids(), vec!["obj1", "obj2"]);
    }

    #[test]
    fn promote_missing_after_ttl_eviction_returns_not_found() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("expired", 100, "peer1", 1000).unwrap();
        let evictions = store.evict_expired(1200);

        let err = store.promote("expired").unwrap_err();

        assert_eq!(evictions.len(), 1);
        assert_eq!(
            err,
            QuarantineError::NotFound {
                object_id: "expired".to_string(),
            }
        );
        assert_eq!(store.stats(1200).total_bytes, 0);
    }

    #[test]
    fn evict_expired_with_clock_skew_does_not_underflow_or_evict() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("future", 100, "peer1", 1000).unwrap();

        let evictions = store.evict_expired(900);

        assert!(evictions.is_empty());
        assert!(store.contains("future"));
        assert_eq!(store.stats(900).oldest_entry_age, 0);
        assert_eq!(store.stats(900).evictions_total, 0);
    }

    #[test]
    fn promote_missing_keeps_existing_entries_and_bytes() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("kept", 125, "peer1", 1000).unwrap();

        let err = store.promote("missing").unwrap_err();

        assert_eq!(err.code(), "QDS_NOT_FOUND");
        assert!(store.contains("kept"));
        assert_eq!(store.stats(1001).object_count, 1);
        assert_eq!(store.stats(1001).total_bytes, 125);
    }

    #[test]
    fn duplicate_at_exact_ttl_boundary_reingests_after_eviction() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("boundary", 100, "peer1", 1000).unwrap();

        let evictions = store.ingest("boundary", 120, "peer2", 1100).unwrap();

        assert_eq!(evictions.len(), 1);
        assert_eq!(evictions[0].reason, "ttl_expired");
        assert!(store.contains("boundary"));
        assert_eq!(store.stats(1100).object_count, 1);
        assert_eq!(store.stats(1100).total_bytes, 120);
    }

    #[test]
    fn quota_eviction_ties_break_by_object_id() {
        let cfg = QuarantineConfig {
            max_objects: 2,
            max_bytes: 500,
            ttl_seconds: 100,
        };
        let mut store = QuarantineStore::new(cfg).unwrap();
        store.ingest("b-old", 100, "peer1", 1000).unwrap();
        store.ingest("a-old", 100, "peer1", 1000).unwrap();

        let evictions = store.ingest("new", 100, "peer1", 1001).unwrap();

        assert_eq!(evictions.len(), 1);
        assert_eq!(evictions[0].object_id, "a-old");
        assert!(!store.contains("a-old"));
        assert!(store.contains("b-old"));
        assert!(store.contains("new"));
    }

    #[test]
    fn byte_quota_eviction_removes_multiple_oldest_entries_until_room() {
        let cfg = QuarantineConfig {
            max_objects: 10,
            max_bytes: 300,
            ttl_seconds: 100,
        };
        let mut store = QuarantineStore::new(cfg).unwrap();
        store.ingest("oldest", 120, "peer1", 1000).unwrap();
        store.ingest("middle", 120, "peer1", 1001).unwrap();
        store.ingest("newest", 20, "peer1", 1002).unwrap();

        let evictions = store.ingest("large", 200, "peer2", 1003).unwrap();

        assert_eq!(
            evictions
                .iter()
                .map(|record| record.object_id.as_str())
                .collect::<Vec<_>>(),
            vec!["oldest", "middle"]
        );
        assert!(!store.contains("oldest"));
        assert!(!store.contains("middle"));
        assert!(store.contains("newest"));
        assert!(store.contains("large"));
        assert_eq!(store.stats(1003).total_bytes, 220);
    }

    #[test]
    fn evictions_total_saturates_during_ttl_cleanup() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("expired", 100, "peer1", 1000).unwrap();
        store.evictions_total = u64::MAX;

        let evictions = store.evict_expired(1100);

        assert_eq!(evictions.len(), 1);
        assert_eq!(store.stats(1100).evictions_total, u64::MAX);
        assert_eq!(store.stats(1100).total_bytes, 0);
    }

    #[test]
    fn evict_expired_saturates_corrupt_total_bytes_to_zero() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.entries.insert(
            "corrupt".to_string(),
            QuarantineEntry {
                object_id: "corrupt".to_string(),
                size_bytes: 250,
                ingested_at: 1000,
                source_peer: "peer1".to_string(),
            },
        );
        store.total_bytes = 10;

        let evictions = store.evict_expired(1100);

        assert_eq!(evictions.len(), 1);
        assert_eq!(store.stats(1100).total_bytes, 0);
        assert!(!store.contains("corrupt"));
    }

    #[test]
    fn promote_saturates_corrupt_total_bytes_to_zero() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.entries.insert(
            "corrupt-promote".to_string(),
            QuarantineEntry {
                object_id: "corrupt-promote".to_string(),
                size_bytes: 250,
                ingested_at: 1000,
                source_peer: "peer1".to_string(),
            },
        );
        store.total_bytes = 10;

        let entry = store.promote("corrupt-promote").unwrap();

        assert_eq!(entry.object_id, "corrupt-promote");
        assert_eq!(store.stats(1001).total_bytes, 0);
        assert!(!store.contains("corrupt-promote"));
    }

    #[test]
    fn quota_rejection_after_clock_skew_ttl_check_preserves_future_entry() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("future-entry", 100, "peer1", 1000).unwrap();

        let err = store.ingest("too-big", 501, "peer2", 900).unwrap_err();

        assert_eq!(err.code(), "QDS_QUOTA_EXCEEDED");
        assert!(store.contains("future-entry"));
        assert!(!store.contains("too-big"));
        assert_eq!(store.stats(900).object_count, 1);
        assert_eq!(store.stats(900).total_bytes, 100);
    }

    #[test]
    fn invalid_config_reports_zero_objects_before_zero_bytes_and_ttl() {
        let err = validate_config(&QuarantineConfig {
            max_objects: 0,
            max_bytes: 0,
            ttl_seconds: 0,
        })
        .unwrap_err();

        assert!(matches!(
            err,
            QuarantineError::InvalidConfig { ref reason } if reason == "max_objects must be > 0"
        ));
    }

    #[test]
    fn invalid_config_reports_zero_bytes_before_zero_ttl() {
        let err = validate_config(&QuarantineConfig {
            max_objects: 1,
            max_bytes: 0,
            ttl_seconds: 0,
        })
        .unwrap_err();

        assert!(matches!(
            err,
            QuarantineError::InvalidConfig { ref reason } if reason == "max_bytes must be > 0"
        ));
    }

    #[test]
    fn duplicate_oversized_object_reports_duplicate_before_quota() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("obj1", 100, "peer1", 1000).unwrap();

        let err = store.ingest("obj1", 501, "peer2", 1001).unwrap_err();
        let entry = store.promote("obj1").unwrap();

        assert!(matches!(
            err,
            QuarantineError::Duplicate { ref object_id } if object_id == "obj1"
        ));
        assert_eq!(entry.size_bytes, 100);
        assert_eq!(entry.source_peer, "peer1");
        assert_eq!(entry.ingested_at, 1000);
    }

    #[test]
    fn duplicate_after_ttl_cleanup_can_still_be_rejected_by_oversize() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("expired-dup", 100, "peer1", 1000).unwrap();

        let err = store.ingest("expired-dup", 501, "peer2", 1100).unwrap_err();

        assert!(matches!(
            err,
            QuarantineError::QuotaExceeded {
                current_bytes: 0,
                max_bytes: 500
            }
        ));
        assert!(!store.contains("expired-dup"));
        let stats = store.stats(1100);
        assert_eq!(stats.object_count, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.evictions_total, 1);
    }

    #[test]
    fn promote_missing_does_not_increment_evictions_total() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("kept", 100, "peer1", 1000).unwrap();

        let err = store.promote("missing").unwrap_err();

        assert!(matches!(
            err,
            QuarantineError::NotFound { ref object_id } if object_id == "missing"
        ));
        assert_eq!(store.stats(1001).evictions_total, 0);
        assert!(store.contains("kept"));
    }

    #[test]
    fn evict_expired_is_idempotent_after_first_cleanup() {
        let mut store = QuarantineStore::new(config()).unwrap();
        store.ingest("expired-once", 100, "peer1", 1000).unwrap();

        let first = store.evict_expired(1100);
        let second = store.evict_expired(1200);

        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
        assert_eq!(store.stats(1200).evictions_total, 1);
        assert_eq!(store.stats(1200).total_bytes, 0);
    }

    #[test]
    fn quota_rejection_when_empty_does_not_create_entry_or_eviction() {
        let mut store = QuarantineStore::new(config()).unwrap();

        let err = store.ingest("too-big-empty", 501, "peer1", 1000).unwrap_err();

        assert!(matches!(
            err,
            QuarantineError::QuotaExceeded {
                current_bytes: 0,
                max_bytes: 500
            }
        ));
        assert!(!store.contains("too-big-empty"));
        let stats = store.stats(1000);
        assert_eq!(stats.object_count, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.evictions_total, 0);
    }
}
