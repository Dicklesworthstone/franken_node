//! bd-206h: Idempotency dedupe store with at-most-once execution guarantee.
//!
//! Tracks idempotency keys and their outcomes. Same key + same payload returns
//! cached outcome. Same key + different payload hard-fails with conflict error.
//!
//! # Invariants
//!
//! - `INV-IDS-AT-MOST-ONCE`: A completed entry's outcome is immutable; the same
//!   key with the same payload always returns the cached result.
//! - `INV-IDS-CONFLICT-DETECT`: If the same key arrives with a different payload
//!   hash, the store MUST reject it with `ERR_IDEMPOTENCY_CONFLICT`.
//! - `INV-IDS-TTL-BOUND`: Every entry has a bounded TTL; expired entries are
//!   treated as absent and may be swept.
//! - `INV-IDS-CRASH-SAFE`: In-flight entries surviving a crash are marked
//!   `Abandoned` during recovery and may be retried.
//! - `INV-IDS-AUDITABLE`: Every state transition is recorded in a structured
//!   audit log with trace context.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::idempotency::IdempotencyKey;

/// Schema version tag for serialised store snapshots.
pub const SCHEMA_VERSION: &str = "ids-v1.0";

/// Default time-to-live: 7 days in seconds.
pub const DEFAULT_TTL_SECS: u64 = 604_800;

// ── Event codes ──────────────────────────────────────────────────────────

/// Structured event codes emitted by the dedupe store.
pub mod event_codes {
    /// A brand-new entry was inserted (status = Processing).
    pub const ID_ENTRY_NEW: &str = "ID_ENTRY_NEW";
    /// A duplicate request matched an existing completed entry.
    pub const ID_ENTRY_DUPLICATE: &str = "ID_ENTRY_DUPLICATE";
    /// Same key but different payload hash — hard conflict.
    pub const ID_ENTRY_CONFLICT: &str = "ID_ENTRY_CONFLICT";
    /// An entry was removed because its TTL elapsed.
    pub const ID_ENTRY_EXPIRED: &str = "ID_ENTRY_EXPIRED";
    /// Store recovery completed: in-flight entries resolved.
    pub const ID_STORE_RECOVERY: &str = "ID_STORE_RECOVERY";
    /// An in-flight entry was marked complete with an outcome.
    pub const ID_INFLIGHT_RESOLVED: &str = "ID_INFLIGHT_RESOLVED";
    /// Periodic sweep of expired entries finished.
    pub const ID_SWEEP_COMPLETE: &str = "ID_SWEEP_COMPLETE";
}

/// Error code for payload-mismatch conflicts.
pub const ERR_IDEMPOTENCY_CONFLICT: &str = "ERR_IDEMPOTENCY_CONFLICT";
/// Error code for corrupted persisted entries that violate completion invariants.
pub const ERR_IDEMPOTENCY_CORRUPT_ENTRY: &str = "ERR_IDEMPOTENCY_CORRUPT_ENTRY";

// ── Invariant constants ──────────────────────────────────────────────────

/// Invariant identifiers referenced in audit records and documentation.
pub mod invariants {
    pub const INV_IDS_AT_MOST_ONCE: &str = "INV-IDS-AT-MOST-ONCE";
    pub const INV_IDS_CONFLICT_DETECT: &str = "INV-IDS-CONFLICT-DETECT";
    pub const INV_IDS_TTL_BOUND: &str = "INV-IDS-TTL-BOUND";
    pub const INV_IDS_CRASH_SAFE: &str = "INV-IDS-CRASH-SAFE";
    pub const INV_IDS_AUDITABLE: &str = "INV-IDS-AUDITABLE";
}

// ── Core types ───────────────────────────────────────────────────────────

/// Status of a dedupe entry in the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryStatus {
    /// Operation is currently being executed.
    Processing,
    /// Operation completed successfully; outcome is cached.
    Complete,
    /// Entry survived a crash and was abandoned during recovery.
    Abandoned,
}

impl fmt::Display for EntryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Processing => write!(f, "Processing"),
            Self::Complete => write!(f, "Complete"),
            Self::Abandoned => write!(f, "Abandoned"),
        }
    }
}

/// A cached outcome for a completed idempotent operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedOutcome {
    /// SHA-256 hex digest of `result_data`.
    pub result_hash: String,
    /// Serialised result bytes.
    pub result_data: Vec<u8>,
    /// Completion timestamp (seconds since epoch).
    pub completed_at_secs: u64,
}

/// A stored dedupe entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupeEntry {
    /// The idempotency key for this entry.
    pub key: IdempotencyKey,
    /// SHA-256 hex digest of the original request payload.
    pub payload_hash: String,
    /// Current lifecycle status.
    pub status: EntryStatus,
    /// Cached outcome (present only when `status == Complete`).
    pub outcome: Option<CachedOutcome>,
    /// Creation timestamp (seconds since epoch).
    pub created_at_secs: u64,
    /// Time-to-live in seconds from `created_at_secs`.
    pub ttl_secs: u64,
}

impl DedupeEntry {
    /// Returns `true` if this entry has outlived its TTL at `now_secs`.
    #[must_use]
    pub fn is_expired(&self, now_secs: u64) -> bool {
        now_secs > self.created_at_secs.saturating_add(self.ttl_secs)
    }
}

/// Result of a `check_or_insert` operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DedupeResult {
    /// First time seeing this key — proceed with execution.
    New,
    /// Same key + same payload — return cached outcome.
    Duplicate(CachedOutcome),
    /// Same key + different payload — conflict error
    /// (`ERR_IDEMPOTENCY_CONFLICT`).
    Conflict {
        key_hex: String,
        expected_hash: String,
        actual_hash: String,
    },
    /// Entry exists but is still processing (in-flight).
    InFlight,
}

/// Structured audit record for the dedupe store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsAuditRecord {
    /// One of the `event_codes::*` constants.
    pub event_code: String,
    /// Distributed trace identifier.
    pub trace_id: String,
    /// Free-form structured detail payload.
    pub detail: serde_json::Value,
}

// ── Helper ───────────────────────────────────────────────────────────────

/// SHA-256 hex digest of a payload byte slice.
#[must_use]
pub fn hash_payload(payload: &[u8]) -> String {
    format!(
        "{:x}",
        Sha256::digest([b"idempotency_payload_v1:" as &[u8], payload].concat())
    )
}

// ── Dedupe store ─────────────────────────────────────────────────────────

/// The idempotency dedupe store.
///
/// Provides at-most-once execution semantics by tracking idempotency keys
/// and their outcomes.  Same key + same payload returns the cached result;
/// same key + different payload is rejected as a conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyDedupeStore {
    entries: BTreeMap<String, DedupeEntry>,
    ttl_secs: u64,
    audit_log: Vec<IdsAuditRecord>,
    total_new: u64,
    total_duplicate: u64,
    total_conflict: u64,
    total_expired: u64,
    total_recovered: u64,
}

impl IdempotencyDedupeStore {
    /// Create a new store with the given default TTL.
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            ttl_secs,
            audit_log: Vec::new(),
            total_new: 0,
            total_duplicate: 0,
            total_conflict: 0,
            total_expired: 0,
            total_recovered: 0,
        }
    }

    /// Create a new store and emit a recovery event (for startup / restart).
    #[must_use]
    pub fn init(ttl_secs: u64, trace_id: &str) -> Self {
        let mut store = Self::new(ttl_secs);
        store.log(
            event_codes::ID_STORE_RECOVERY,
            trace_id,
            serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "ttl_secs": ttl_secs,
                "message": "store initialised",
            }),
        );
        store
    }

    // ── internal logging ─────────────────────────────────────────────

    fn log(&mut self, event_code: &str, trace_id: &str, detail: serde_json::Value) {
        self.audit_log.push(IdsAuditRecord {
            event_code: event_code.to_string(),
            trace_id: trace_id.to_string(),
            detail,
        });
    }

    // ── primary operations ───────────────────────────────────────────

    /// Check whether `key` already exists.
    ///
    /// | Existing entry? | Payload match? | Status     | Result          |
    /// |-----------------|----------------|------------|-----------------|
    /// | No              | —              | —          | `New`           |
    /// | Yes (expired)   | —              | —          | `New`           |
    /// | Yes             | Different      | any        | `Conflict`      |
    /// | Yes             | Same           | Complete   | `Duplicate`     |
    /// | Yes             | Same           | Processing | `InFlight`      |
    /// | Yes             | Same           | Abandoned  | `New` (retry)   |
    pub fn check_or_insert(
        &mut self,
        key: IdempotencyKey,
        payload: &[u8],
        now_secs: u64,
        trace_id: &str,
    ) -> DedupeResult {
        let key_hex = key.to_hex();
        let payload_hash = hash_payload(payload);

        // Classify the existing entry with an immutable borrow.
        enum Action {
            InsertNew,
            Expired,
            CorruptComplete { expected_hash: String },
            Conflict { expected_hash: String },
            Duplicate(CachedOutcome),
            InFlight,
            RetryAbandoned,
        }

        let action = if let Some(entry) = self.entries.get(&key_hex) {
            if entry.is_expired(now_secs) {
                Action::Expired
            } else if entry.payload_hash != payload_hash {
                Action::Conflict {
                    expected_hash: entry.payload_hash.clone(),
                }
            } else {
                match &entry.status {
                    EntryStatus::Complete => match entry.outcome.clone() {
                        Some(outcome) => Action::Duplicate(outcome),
                        // Corrupted persisted state: fail closed instead of panicking.
                        None => Action::CorruptComplete {
                            expected_hash: entry.payload_hash.clone(),
                        },
                    },
                    EntryStatus::Processing => Action::InFlight,
                    EntryStatus::Abandoned => Action::RetryAbandoned,
                }
            }
        } else {
            Action::InsertNew
        };

        // Now process with mutable borrows (entry borrow is dropped).
        match action {
            Action::Expired => {
                self.total_expired += 1;
                self.log(
                    event_codes::ID_ENTRY_EXPIRED,
                    trace_id,
                    serde_json::json!({
                        "key_hex": key_hex,
                        "invariant": invariants::INV_IDS_TTL_BOUND,
                    }),
                );
                // Fall through to insert as new
            }
            Action::CorruptComplete { expected_hash } => {
                self.total_conflict += 1;
                self.log(
                    event_codes::ID_ENTRY_CONFLICT,
                    trace_id,
                    serde_json::json!({
                        "key_hex": &key_hex,
                        "expected_hash": &expected_hash,
                        "actual_hash": &payload_hash,
                        "error_code": ERR_IDEMPOTENCY_CORRUPT_ENTRY,
                        "detail": "complete_entry_missing_outcome",
                        "invariant": invariants::INV_IDS_AT_MOST_ONCE,
                    }),
                );
                return DedupeResult::Conflict {
                    key_hex,
                    expected_hash,
                    actual_hash: payload_hash,
                };
            }
            Action::Conflict { expected_hash } => {
                self.total_conflict += 1;
                self.log(
                    event_codes::ID_ENTRY_CONFLICT,
                    trace_id,
                    serde_json::json!({
                        "key_hex": &key_hex,
                        "expected_hash": &expected_hash,
                        "actual_hash": &payload_hash,
                        "error_code": ERR_IDEMPOTENCY_CONFLICT,
                        "invariant": invariants::INV_IDS_CONFLICT_DETECT,
                    }),
                );
                return DedupeResult::Conflict {
                    key_hex,
                    expected_hash,
                    actual_hash: payload_hash,
                };
            }
            Action::Duplicate(outcome) => {
                self.total_duplicate += 1;
                self.log(
                    event_codes::ID_ENTRY_DUPLICATE,
                    trace_id,
                    serde_json::json!({
                        "key_hex": &key_hex,
                        "invariant": invariants::INV_IDS_AT_MOST_ONCE,
                    }),
                );
                return DedupeResult::Duplicate(outcome);
            }
            Action::InFlight => {
                return DedupeResult::InFlight;
            }
            Action::InsertNew | Action::RetryAbandoned => {
                // Fall through to insert as new
            }
        }

        let entry = DedupeEntry {
            key,
            payload_hash,
            status: EntryStatus::Processing,
            outcome: None,
            created_at_secs: now_secs,
            ttl_secs: self.ttl_secs,
        };
        self.entries.insert(key_hex.clone(), entry);
        self.total_new += 1;
        self.log(
            event_codes::ID_ENTRY_NEW,
            trace_id,
            serde_json::json!({
                "key_hex": &key_hex,
                "invariant": invariants::INV_IDS_AUDITABLE,
            }),
        );

        DedupeResult::New
    }

    /// Complete an in-flight entry with its outcome.
    ///
    /// Returns `Err` if the key is not found or is not in `Processing` status.
    pub fn complete(
        &mut self,
        key: IdempotencyKey,
        outcome_data: Vec<u8>,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<(), String> {
        let key_hex = key.to_hex();
        let entry = self
            .entries
            .get_mut(&key_hex)
            .ok_or_else(|| format!("no entry for key {key_hex}"))?;

        if entry.status != EntryStatus::Processing {
            return Err(format!(
                "entry {key_hex} is not Processing (status={})",
                entry.status
            ));
        }

        let result_hash = hash_payload(&outcome_data);
        entry.status = EntryStatus::Complete;
        entry.outcome = Some(CachedOutcome {
            result_hash,
            result_data: outcome_data,
            completed_at_secs: now_secs,
        });

        self.log(
            event_codes::ID_INFLIGHT_RESOLVED,
            trace_id,
            serde_json::json!({
                "key_hex": &key_hex,
                "completed_at_secs": now_secs,
                "invariant": invariants::INV_IDS_AT_MOST_ONCE,
            }),
        );

        Ok(())
    }

    /// Sweep expired entries. Returns the number of entries removed.
    pub fn sweep_expired(&mut self, now_secs: u64, trace_id: &str) -> usize {
        let expired_keys: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_expired(now_secs))
            .map(|(k, _)| k.clone())
            .collect();

        let count = expired_keys.len();
        for k in &expired_keys {
            self.entries.remove(k);
        }
        self.total_expired += count as u64;

        self.log(
            event_codes::ID_SWEEP_COMPLETE,
            trace_id,
            serde_json::json!({
                "swept": count,
                "remaining": self.entries.len(),
                "invariant": invariants::INV_IDS_TTL_BOUND,
            }),
        );

        count
    }

    /// Recover from crash: mark all `Processing` entries as `Abandoned`.
    ///
    /// Returns the number of entries transitioned.
    pub fn recover_inflight(&mut self, trace_id: &str) -> usize {
        let mut count = 0_usize;
        for entry in self.entries.values_mut() {
            if entry.status == EntryStatus::Processing {
                entry.status = EntryStatus::Abandoned;
                count += 1;
            }
        }
        self.total_recovered += count as u64;

        self.log(
            event_codes::ID_STORE_RECOVERY,
            trace_id,
            serde_json::json!({
                "recovered": count,
                "invariant": invariants::INV_IDS_CRASH_SAFE,
            }),
        );

        count
    }

    // ── observability ────────────────────────────────────────────────

    /// Export the audit log as new-line-delimited JSON (JSONL).
    #[must_use]
    pub fn export_audit_log_jsonl(&self) -> String {
        self.audit_log
            .iter()
            .map(|r| serde_json::to_string(r).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Deterministic content hash over the ordered entry map.
    #[must_use]
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"idempotency_content_hash_v1:");
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(b"|");
        for (k, entry) in &self.entries {
            hasher.update(k.as_bytes());
            hasher.update(b"|");
            hasher.update(entry.payload_hash.as_bytes());
            hasher.update(b"|");
            hasher.update(format!("{}", entry.status).as_bytes());
            hasher.update(b"|");
            if let Some(ref outcome) = entry.outcome {
                hasher.update(outcome.result_hash.as_bytes());
                hasher.update(b"|");
            }
        }
        format!("{:x}", hasher.finalize())
    }

    /// Return `(total_new, total_duplicate, total_conflict, total_expired)`.
    #[must_use]
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.total_new,
            self.total_duplicate,
            self.total_conflict,
            self.total_expired,
        )
    }

    /// Number of live entries in the store.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of audit records accumulated so far.
    #[must_use]
    pub fn audit_log_len(&self) -> usize {
        self.audit_log.len()
    }

    /// Access the raw audit log slice.
    #[must_use]
    pub fn audit_log(&self) -> &[IdsAuditRecord] {
        &self.audit_log
    }
}

impl Default for IdempotencyDedupeStore {
    fn default() -> Self {
        Self::new(DEFAULT_TTL_SECS)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic key for testing.
    fn test_key(seed: u8) -> IdempotencyKey {
        let mut bytes = [0_u8; 32];
        bytes[0] = seed;
        IdempotencyKey::from_bytes(bytes)
    }

    #[test]
    fn test_new_entry() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let result = store.check_or_insert(test_key(1), b"payload-a", 1000, "t1");
        assert_eq!(result, DedupeResult::New);
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn test_duplicate_same_payload() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(2);
        let payload = b"dup-payload";

        let r1 = store.check_or_insert(key, payload, 1000, "t2");
        assert_eq!(r1, DedupeResult::New);

        store
            .complete(key, b"result-ok".to_vec(), 1001, "t2")
            .unwrap();

        let r2 = store.check_or_insert(key, payload, 1002, "t2");
        match r2 {
            DedupeResult::Duplicate(outcome) => {
                assert_eq!(outcome.result_data, b"result-ok");
            }
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    #[test]
    fn test_conflict_different_payload() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(3);

        store.check_or_insert(key, b"payload-x", 1000, "t3");
        store
            .complete(key, b"result-x".to_vec(), 1001, "t3")
            .unwrap();

        let r = store.check_or_insert(key, b"payload-y", 1002, "t3");
        match r {
            DedupeResult::Conflict {
                expected_hash,
                actual_hash,
                ..
            } => {
                assert_ne!(expected_hash, actual_hash);
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn test_inflight_detection() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(4);
        let payload = b"inflight-payload";

        store.check_or_insert(key, payload, 1000, "t4");
        let r = store.check_or_insert(key, payload, 1001, "t4");
        assert_eq!(r, DedupeResult::InFlight);
    }

    #[test]
    fn test_complete_entry() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(5);

        store.check_or_insert(key, b"p5", 1000, "t5");
        store
            .complete(key, b"outcome-5".to_vec(), 1001, "t5")
            .unwrap();

        // Re-check returns the cached outcome.
        let r = store.check_or_insert(key, b"p5", 1002, "t5");
        match r {
            DedupeResult::Duplicate(outcome) => {
                assert_eq!(outcome.result_data, b"outcome-5");
                assert_eq!(outcome.completed_at_secs, 1001);
                assert!(!outcome.result_hash.is_empty());
            }
            other => panic!("expected Duplicate, got {other:?}"),
        }
    }

    #[test]
    fn test_corrupted_complete_entry_fails_closed_without_panic() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(92);
        let payload = b"corrupt-payload";
        let payload_hash = hash_payload(payload);

        store.entries.insert(
            key.to_hex(),
            DedupeEntry {
                key,
                payload_hash: payload_hash.clone(),
                status: EntryStatus::Complete,
                outcome: None,
                created_at_secs: 1000,
                ttl_secs: 3600,
            },
        );

        let result = store.check_or_insert(key, payload, 1001, "t-corrupt");
        match result {
            DedupeResult::Conflict {
                expected_hash,
                actual_hash,
                ..
            } => {
                assert_eq!(expected_hash, payload_hash);
                assert_eq!(actual_hash, payload_hash);
            }
            other => panic!("expected Conflict for corrupted complete entry, got {other:?}"),
        }

        let has_corrupt_conflict_audit = store.audit_log().iter().any(|record| {
            record.event_code == event_codes::ID_ENTRY_CONFLICT
                && record
                    .detail
                    .get("error_code")
                    .and_then(serde_json::Value::as_str)
                    == Some(ERR_IDEMPOTENCY_CORRUPT_ENTRY)
        });
        assert!(has_corrupt_conflict_audit);
    }

    #[test]
    fn test_ttl_expiration() {
        let ttl = 100;
        let mut store = IdempotencyDedupeStore::new(ttl);
        let key = test_key(6);

        store.check_or_insert(key, b"ttl-payload", 1000, "t6");
        store.complete(key, b"res".to_vec(), 1001, "t6").unwrap();

        // Within TTL -> Duplicate.
        let r1 = store.check_or_insert(key, b"ttl-payload", 1050, "t6");
        assert!(matches!(r1, DedupeResult::Duplicate(_)));

        // Past TTL -> New (entry treated as expired).
        let r2 = store.check_or_insert(key, b"ttl-payload", 1101, "t6");
        assert_eq!(r2, DedupeResult::New);
    }

    #[test]
    fn test_sweep_expired() {
        let ttl = 60;
        let mut store = IdempotencyDedupeStore::new(ttl);

        // Insert three entries at t=1000.
        for seed in 10..13 {
            store.check_or_insert(test_key(seed), &[seed], 1000, "ts");
            store
                .complete(test_key(seed), vec![seed], 1001, "ts")
                .unwrap();
        }
        assert_eq!(store.entry_count(), 3);

        // Sweep at t=1061 (past TTL of 60).
        let swept = store.sweep_expired(1061, "ts");
        assert_eq!(swept, 3);
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn test_recover_inflight() {
        let mut store = IdempotencyDedupeStore::new(3600);

        // Insert two in-flight entries.
        store.check_or_insert(test_key(20), b"r1", 1000, "tr");
        store.check_or_insert(test_key(21), b"r2", 1000, "tr");

        // Complete one.
        store
            .complete(test_key(20), b"done".to_vec(), 1001, "tr")
            .unwrap();

        // Recover — only key 21 should transition to Abandoned.
        let recovered = store.recover_inflight("tr");
        assert_eq!(recovered, 1);
    }

    #[test]
    fn test_abandoned_allows_retry() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(30);
        let payload = b"retry-me";

        store.check_or_insert(key, payload, 1000, "ta");
        // Crash recovery abandons the entry.
        let recovered = store.recover_inflight("ta");
        assert_eq!(recovered, 1);

        // Same key + same payload after abandon -> New (retry allowed).
        let r = store.check_or_insert(key, payload, 1002, "ta");
        assert_eq!(r, DedupeResult::New);
    }

    #[test]
    fn test_content_hash_deterministic() {
        let build = || {
            let mut s = IdempotencyDedupeStore::new(3600);
            s.check_or_insert(test_key(40), b"det", 1000, "td");
            s.complete(test_key(40), b"res-det".to_vec(), 1001, "td")
                .unwrap();
            s.content_hash()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn test_audit_log() {
        let mut store = IdempotencyDedupeStore::init(3600, "init-trace");
        store.check_or_insert(test_key(50), b"audit", 1000, "ta");
        store
            .complete(test_key(50), b"done".to_vec(), 1001, "ta")
            .unwrap();

        // At least 3 events: recovery, new entry, inflight resolved.
        assert_eq!(store.audit_log_len(), 3);

        let jsonl = store.export_audit_log_jsonl();
        assert!(!jsonl.is_empty());
        // Each line must be valid JSON.
        for line in jsonl.lines() {
            let _: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
        }
    }

    #[test]
    fn test_stats() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(60);

        store.check_or_insert(key, b"s1", 1000, "ts");
        store.complete(key, b"sr".to_vec(), 1001, "ts").unwrap();

        // Duplicate.
        store.check_or_insert(key, b"s1", 1002, "ts");

        // Conflict.
        store.check_or_insert(key, b"s2", 1003, "ts");

        let (new, dup, conflict, _expired) = store.stats();
        assert_eq!(new, 1);
        assert_eq!(dup, 1);
        assert_eq!(conflict, 1);
    }

    #[test]
    fn test_default_ttl() {
        let store = IdempotencyDedupeStore::default();
        assert_eq!(store.ttl_secs, DEFAULT_TTL_SECS);
        assert_eq!(DEFAULT_TTL_SECS, 604_800); // 7 days
    }

    #[test]
    fn test_entry_count() {
        let mut store = IdempotencyDedupeStore::new(3600);
        assert_eq!(store.entry_count(), 0);
        store.check_or_insert(test_key(70), b"c1", 1000, "tc");
        assert_eq!(store.entry_count(), 1);
        store.check_or_insert(test_key(71), b"c2", 1000, "tc");
        assert_eq!(store.entry_count(), 2);
    }

    #[test]
    fn test_hash_payload_deterministic() {
        let h1 = hash_payload(b"hello-world");
        let h2 = hash_payload(b"hello-world");
        assert_eq!(h1, h2);

        let h3 = hash_payload(b"different");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_complete_unknown_key_errors() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let err = store
            .complete(test_key(99), b"no-key".to_vec(), 1000, "tx")
            .unwrap_err();
        assert!(err.contains("no entry"));
    }

    #[test]
    fn test_complete_already_complete_errors() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(80);
        store.check_or_insert(key, b"ac", 1000, "tac");
        store.complete(key, b"r1".to_vec(), 1001, "tac").unwrap();
        let err = store
            .complete(key, b"r2".to_vec(), 1002, "tac")
            .unwrap_err();
        assert!(err.contains("not Processing"));
    }

    #[test]
    fn test_entry_status_display() {
        assert_eq!(format!("{}", EntryStatus::Processing), "Processing");
        assert_eq!(format!("{}", EntryStatus::Complete), "Complete");
        assert_eq!(format!("{}", EntryStatus::Abandoned), "Abandoned");
    }

    #[test]
    fn test_schema_version_present() {
        assert_eq!(SCHEMA_VERSION, "ids-v1.0");
    }

    #[test]
    fn test_sweep_leaves_unexpired() {
        let ttl = 100;
        let mut store = IdempotencyDedupeStore::new(ttl);

        // Entry at t=1000.
        store.check_or_insert(test_key(90), b"keep", 1000, "tk");
        store
            .complete(test_key(90), b"kept".to_vec(), 1001, "tk")
            .unwrap();

        // Entry at t=1050.
        store.check_or_insert(test_key(91), b"keep2", 1050, "tk");
        store
            .complete(test_key(91), b"kept2".to_vec(), 1051, "tk")
            .unwrap();

        // Sweep at t=1101 — only first entry expired.
        let swept = store.sweep_expired(1101, "tk");
        assert_eq!(swept, 1);
        assert_eq!(store.entry_count(), 1);
    }
}
