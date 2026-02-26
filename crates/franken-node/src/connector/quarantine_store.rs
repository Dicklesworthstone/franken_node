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
                self.evictions_total += 1;
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
            || self.total_bytes + needed_bytes > self.config.max_bytes)
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
                    self.evictions_total += 1;
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
        if self.entries.contains_key(object_id) {
            return Err(QuarantineError::Duplicate {
                object_id: object_id.to_string(),
            });
        }

        // Step 1: evict TTL-expired entries
        let mut evictions = self.evict_expired(now);

        // Step 2: if still over quota, evict oldest
        if self.entries.len() >= self.config.max_objects
            || self.total_bytes.saturating_add(size_bytes) > self.config.max_bytes
        {
            evictions.extend(self.evict_for_quota(size_bytes, now));
        }

        // Step 3: check if we can fit after eviction
        if size_bytes > self.config.max_bytes {
            return Err(QuarantineError::QuotaExceeded {
                current_bytes: self.total_bytes,
                max_bytes: self.config.max_bytes,
            });
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
}
