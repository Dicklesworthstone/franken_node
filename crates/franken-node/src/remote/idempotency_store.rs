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

/// Maximum dedupe entries before new inserts trigger an automatic expired-entry
/// sweep.  If still at capacity after sweeping, the insert is rejected.
const MAX_DEDUPE_ENTRIES: usize = 65_536;

use crate::{config::RemoteConfig, push_bounded, security::constant_time::ct_eq};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::idempotency::IdempotencyKey;

fn hash_len_prefixed_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((u64::try_from(bytes.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(bytes);
}

fn hash_u64_field(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

/// Schema version tag for serialised store snapshots.
pub const SCHEMA_VERSION: &str = "ids-v1.0";

/// Default time-to-live: 7 days in seconds.
pub const DEFAULT_TTL_SECS: u64 = crate::config::timeouts::REMOTE_IDEMPOTENCY_TTL_SECS;
/// Default maximum number of audit records retained in-memory.
pub const DEFAULT_MAX_AUDIT_RECORDS: usize = 4_096;

fn default_audit_log_capacity() -> usize {
    DEFAULT_MAX_AUDIT_RECORDS
}

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
        now_secs >= self.created_at_secs.saturating_add(self.ttl_secs)
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
    let mut hasher = Sha256::new();
    hasher.update(b"idempotency_payload_v1:");
    hash_len_prefixed_bytes(&mut hasher, payload);
    hex::encode(hasher.finalize())
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
    #[serde(default = "default_audit_log_capacity")]
    max_audit_records: usize,
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
        Self::with_audit_log_capacity(ttl_secs, DEFAULT_MAX_AUDIT_RECORDS)
    }

    /// Create a new store using the resolved remote configuration.
    #[must_use]
    pub fn from_remote_config(config: &RemoteConfig) -> Self {
        Self::new(config.idempotency_ttl_secs)
    }

    /// Return the configured entry TTL in seconds.
    #[must_use]
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Create a new store with explicit audit log capacity.
    ///
    /// Capacity is clamped to at least 1 so every transition remains auditable.
    #[must_use]
    pub fn with_audit_log_capacity(ttl_secs: u64, max_audit_records: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            ttl_secs,
            audit_log: Vec::new(),
            max_audit_records: max_audit_records.max(1),
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
        let cap = self.max_audit_records;
        push_bounded(
            &mut self.audit_log,
            IdsAuditRecord {
                event_code: event_code.to_string(),
                trace_id: trace_id.to_string(),
                detail,
            },
            cap,
        );
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
            } else if !ct_eq(&entry.payload_hash, &payload_hash) {
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
        let reuses_existing_slot = matches!(action, Action::Expired | Action::RetryAbandoned);

        // Now process with mutable borrows (entry borrow is dropped).
        match action {
            Action::Expired => {
                self.total_expired = self.total_expired.saturating_add(1);
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
                self.total_conflict = self.total_conflict.saturating_add(1);
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
                self.total_conflict = self.total_conflict.saturating_add(1);
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
                self.total_duplicate = self.total_duplicate.saturating_add(1);
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

        // Capacity guard only applies when admitting a brand-new key. Replacing
        // an expired or abandoned entry reuses its existing slot.
        if !reuses_existing_slot && self.entries.len() >= MAX_DEDUPE_ENTRIES {
            self.sweep_expired(now_secs, trace_id);
        }
        if !reuses_existing_slot && self.entries.len() >= MAX_DEDUPE_ENTRIES {
            self.log(
                event_codes::ID_ENTRY_CONFLICT,
                trace_id,
                serde_json::json!({
                    "key_hex": &key_hex,
                    "reason": "dedupe store at capacity",
                    "capacity": MAX_DEDUPE_ENTRIES,
                }),
            );
            return DedupeResult::Conflict {
                key_hex: key_hex.clone(),
                expected_hash: String::new(),
                actual_hash: payload_hash.clone(),
            };
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
        self.total_new = self.total_new.saturating_add(1);
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
        self.total_expired = self.total_expired.saturating_add(count as u64);

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
                count = count.saturating_add(1);
            }
        }
        self.total_recovered = self.total_recovered.saturating_add(count as u64);

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
        // Length-prefixed encoding prevents delimiter-collision ambiguity and
        // the timestamp/TTL fields seal expiration-relevant state.
        hash_len_prefixed_bytes(&mut hasher, SCHEMA_VERSION.as_bytes());
        for (k, entry) in &self.entries {
            hash_len_prefixed_bytes(&mut hasher, k.as_bytes());
            hash_len_prefixed_bytes(&mut hasher, entry.payload_hash.as_bytes());
            let status = format!("{}", entry.status);
            hash_len_prefixed_bytes(&mut hasher, status.as_bytes());
            hash_u64_field(&mut hasher, entry.created_at_secs);
            hash_u64_field(&mut hasher, entry.ttl_secs);
            match &entry.outcome {
                Some(outcome) => {
                    hasher.update([1]);
                    hash_len_prefixed_bytes(&mut hasher, outcome.result_hash.as_bytes());
                    hash_len_prefixed_bytes(&mut hasher, &outcome.result_data);
                    hash_u64_field(&mut hasher, outcome.completed_at_secs);
                }
                None => hasher.update([0]),
            }
        }
        hex::encode(hasher.finalize())
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

    /// Configured maximum retained audit records.
    #[must_use]
    pub fn audit_log_capacity(&self) -> usize {
        self.max_audit_records
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
    use crate::security::constant_time;

    /// Deterministic key for testing.
    fn test_key(seed: u8) -> IdempotencyKey {
        let mut bytes = [0_u8; 32];
        bytes[0] = seed;
        IdempotencyKey::from_bytes(bytes)
    }

    fn indexed_test_key(index: usize) -> IdempotencyKey {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
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
            .expect("should succeed");

        let r2 = store.check_or_insert(key, payload, 1002, "t2");
        match r2 {
            DedupeResult::Duplicate(outcome) => {
                assert_eq!(outcome.result_data, b"result-ok");
            }
            other => {
                unreachable!("expected Duplicate, got {other:?}");
            }
        }
    }

    #[test]
    fn test_conflict_different_payload() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(3);

        store.check_or_insert(key, b"payload-x", 1000, "t3");
        store
            .complete(key, b"result-x".to_vec(), 1001, "t3")
            .expect("should succeed");

        let r = store.check_or_insert(key, b"payload-y", 1002, "t3");
        match r {
            DedupeResult::Conflict {
                expected_hash,
                actual_hash,
                ..
            } => {
                assert_ne!(expected_hash, actual_hash);
            }
            other => {
                unreachable!("expected Conflict, got {other:?}");
            }
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
            .expect("should succeed");

        // Re-check returns the cached outcome.
        let r = store.check_or_insert(key, b"p5", 1002, "t5");
        match r {
            DedupeResult::Duplicate(outcome) => {
                assert_eq!(outcome.result_data, b"outcome-5");
                assert_eq!(outcome.completed_at_secs, 1001);
                assert!(!outcome.result_hash.is_empty());
            }
            other => {
                unreachable!("expected Duplicate, got {other:?}");
            }
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
            other => {
                unreachable!(
                    "expected Conflict for corrupted complete entry, got {:?}",
                    other
                );
            }
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
        store
            .complete(key, b"res".to_vec(), 1001, "t6")
            .expect("should succeed");

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
                .expect("should succeed");
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
            .expect("should succeed");

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
    fn test_abandoned_retry_reuses_slot_even_at_capacity() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = indexed_test_key(0);
        let payload = b"retry-me";

        assert_eq!(
            store.check_or_insert(key, payload, 1000, "cap"),
            DedupeResult::New
        );
        assert_eq!(store.recover_inflight("cap"), 1);

        for index in 1..MAX_DEDUPE_ENTRIES {
            let fill_key = indexed_test_key(index);
            let fill_payload = (index as u64).to_le_bytes();
            assert_eq!(
                store.check_or_insert(fill_key, &fill_payload, 1000, "cap-fill"),
                DedupeResult::New
            );
        }
        assert_eq!(store.entry_count(), MAX_DEDUPE_ENTRIES);

        let retry = store.check_or_insert(key, payload, 1001, "cap-retry");
        assert_eq!(retry, DedupeResult::New);
        assert_eq!(store.entry_count(), MAX_DEDUPE_ENTRIES);
    }

    #[test]
    fn test_expired_entry_reuses_slot_even_at_capacity() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = indexed_test_key(0);

        assert_eq!(
            store.check_or_insert(key, b"expired", 1000, "cap-expired"),
            DedupeResult::New
        );
        let entry = store
            .entries
            .get_mut(&key.to_hex())
            .expect("target entry must exist");
        entry.ttl_secs = 1;

        for index in 1..MAX_DEDUPE_ENTRIES {
            let fill_key = indexed_test_key(index);
            let fill_payload = (index as u64).to_le_bytes();
            assert_eq!(
                store.check_or_insert(fill_key, &fill_payload, 1000, "cap-fill"),
                DedupeResult::New
            );
        }
        assert_eq!(store.entry_count(), MAX_DEDUPE_ENTRIES);

        let replacement = store.check_or_insert(key, b"replacement", 1002, "cap-expired");
        assert_eq!(replacement, DedupeResult::New);
        assert_eq!(store.entry_count(), MAX_DEDUPE_ENTRIES);
    }

    #[test]
    fn test_content_hash_deterministic() {
        let build = || {
            let mut s = IdempotencyDedupeStore::new(3600);
            s.check_or_insert(test_key(40), b"det", 1000, "td");
            s.complete(test_key(40), b"res-det".to_vec(), 1001, "td")
                .expect("should succeed");
            s.content_hash()
        };
        assert_eq!(build(), build());
    }

    #[test]
    fn test_content_hash_changes_when_created_at_changes() {
        let build = |created_at_secs| {
            let mut store = IdempotencyDedupeStore::new(3600);
            store.check_or_insert(test_key(41), b"det", created_at_secs, "t-created");
            store
                .complete(test_key(41), b"res-det".to_vec(), 1001, "t-created")
                .expect("should succeed");
            store.content_hash()
        };

        assert_ne!(build(1000), build(1002));
    }

    #[test]
    fn test_content_hash_changes_when_ttl_changes() {
        let build = |ttl_secs| {
            let mut store = IdempotencyDedupeStore::new(ttl_secs);
            store.check_or_insert(test_key(42), b"det", 1000, "t-ttl");
            store
                .complete(test_key(42), b"res-det".to_vec(), 1001, "t-ttl")
                .expect("should succeed");
            store.content_hash()
        };

        assert_ne!(build(3600), build(7200));
    }

    #[test]
    fn test_content_hash_changes_when_completed_at_changes() {
        let build = |completed_at_secs| {
            let mut store = IdempotencyDedupeStore::new(3600);
            store.check_or_insert(test_key(43), b"det", 1000, "t-complete");
            store
                .complete(
                    test_key(43),
                    b"res-det".to_vec(),
                    completed_at_secs,
                    "t-complete",
                )
                .expect("should succeed");
            store.content_hash()
        };

        assert_ne!(build(1001), build(1003));
    }

    #[test]
    fn test_content_hash_changes_when_result_data_changes() {
        let build = |result_data: &[u8]| {
            let mut store = IdempotencyDedupeStore::new(3600);
            store.check_or_insert(test_key(44), b"det", 1000, "t-result");
            store
                .complete(test_key(44), result_data.to_vec(), 1001, "t-result")
                .expect("should succeed");
            store.content_hash()
        };

        assert_ne!(build(b"res-det-a"), build(b"res-det-b"));
    }

    #[test]
    fn test_audit_log() {
        let mut store = IdempotencyDedupeStore::init(3600, "init-trace");
        store.check_or_insert(test_key(50), b"audit", 1000, "ta");
        store
            .complete(test_key(50), b"done".to_vec(), 1001, "ta")
            .expect("should succeed");

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
    fn test_audit_log_capacity_enforces_oldest_first_eviction() {
        let mut store = IdempotencyDedupeStore::with_audit_log_capacity(3600, 2);
        let key = test_key(51);
        let payload = b"cap-audit";

        assert_eq!(
            store.check_or_insert(key, payload, 1000, "tcap"),
            DedupeResult::New
        );
        store
            .complete(key, b"cap-result".to_vec(), 1001, "tcap")
            .expect("should succeed");
        let _ = store.check_or_insert(key, payload, 1002, "tcap");

        assert_eq!(store.audit_log_len(), 2);
        let codes: Vec<&str> = store
            .audit_log()
            .iter()
            .map(|record| record.event_code.as_str())
            .collect();
        assert_eq!(
            codes,
            vec![
                event_codes::ID_INFLIGHT_RESOLVED,
                event_codes::ID_ENTRY_DUPLICATE
            ]
        );
    }

    #[test]
    fn test_audit_log_capacity_clamps_to_one() {
        let mut store = IdempotencyDedupeStore::with_audit_log_capacity(3600, 0);
        let key = test_key(52);
        let payload = b"cap-clamp";

        assert_eq!(store.audit_log_capacity(), 1);
        let _ = store.check_or_insert(key, payload, 1000, "tcap1");
        store
            .complete(key, b"cap-result-1".to_vec(), 1001, "tcap1")
            .expect("should succeed");

        assert_eq!(store.audit_log_len(), 1);
        assert_eq!(
            store.audit_log()[0].event_code,
            event_codes::ID_INFLIGHT_RESOLVED
        );
    }

    #[test]
    fn test_stats() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(60);

        store.check_or_insert(key, b"s1", 1000, "ts");
        store
            .complete(key, b"sr".to_vec(), 1001, "ts")
            .expect("should succeed");

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
        assert_eq!(store.audit_log_capacity(), DEFAULT_MAX_AUDIT_RECORDS);
    }

    #[test]
    fn test_from_remote_config_uses_configured_ttl() {
        let config = RemoteConfig {
            idempotency_ttl_secs: 1_234,
        };
        let store = IdempotencyDedupeStore::from_remote_config(&config);
        assert_eq!(store.ttl_secs, 1_234);
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
        store
            .complete(key, b"r1".to_vec(), 1001, "tac")
            .expect("should succeed");
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
            .expect("should succeed");

        // Entry at t=1050.
        store.check_or_insert(test_key(91), b"keep2", 1050, "tk");
        store
            .complete(test_key(91), b"kept2".to_vec(), 1051, "tk")
            .expect("should succeed");

        // Sweep at t=1101 — only first entry expired.
        let swept = store.sweep_expired(1101, "tk");
        assert_eq!(swept, 1);
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn entry_expired_at_exact_ttl_boundary() {
        // Entry created at t=1000, TTL=100 → expires at t=1100.
        let entry = DedupeEntry {
            key: test_key(99),
            payload_hash: "0".repeat(64),
            status: EntryStatus::Processing,
            outcome: None,
            created_at_secs: 1000,
            ttl_secs: 100,
        };
        // At exact boundary (1100), entry IS expired (fail-closed).
        assert!(
            entry.is_expired(1100),
            "entry must be expired at exact TTL boundary"
        );
        // One second before, entry is NOT expired.
        assert!(!entry.is_expired(1099));
    }

    #[test]
    fn conflict_against_processing_entry_does_not_replace_inflight_payload() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(101);

        assert_eq!(
            store.check_or_insert(key, b"original-payload", 1000, "trace-processing-conflict"),
            DedupeResult::New
        );
        let conflict =
            store.check_or_insert(key, b"different-payload", 1001, "trace-processing-conflict");

        assert!(matches!(conflict, DedupeResult::Conflict { .. }));
        assert_eq!(store.entry_count(), 1);
        assert_eq!(
            store.check_or_insert(key, b"original-payload", 1002, "trace-processing-conflict"),
            DedupeResult::InFlight
        );
        let (_new, _dup, conflicts, _expired) = store.stats();
        assert_eq!(conflicts, 1);
    }

    #[test]
    fn conflicting_payload_after_completion_keeps_cached_outcome_for_original_payload() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(102);

        assert_eq!(
            store.check_or_insert(key, b"stable-request", 1000, "trace-complete-conflict"),
            DedupeResult::New
        );
        store
            .complete(
                key,
                b"stable-result".to_vec(),
                1001,
                "trace-complete-conflict",
            )
            .expect("initial completion should succeed");
        assert!(matches!(
            store.check_or_insert(key, b"changed-request", 1002, "trace-complete-conflict"),
            DedupeResult::Conflict { .. }
        ));
        let duplicate =
            store.check_or_insert(key, b"stable-request", 1003, "trace-complete-conflict");

        match duplicate {
            DedupeResult::Duplicate(outcome) => {
                assert_eq!(outcome.result_data, b"stable-result");
            }
            other => unreachable!("expected Duplicate after conflict, got {other:?}"),
        }
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn abandoned_entry_with_different_payload_conflicts_instead_of_retrying() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(103);

        assert_eq!(
            store.check_or_insert(key, b"retry-original", 1000, "trace-abandoned-conflict"),
            DedupeResult::New
        );
        assert_eq!(store.recover_inflight("trace-abandoned-conflict"), 1);
        let result =
            store.check_or_insert(key, b"retry-different", 1001, "trace-abandoned-conflict");

        assert!(matches!(result, DedupeResult::Conflict { .. }));
        assert_eq!(
            store
                .entries
                .get(&key.to_hex())
                .expect("abandoned entry should remain present")
                .status,
            EntryStatus::Abandoned
        );
    }

    #[test]
    fn complete_abandoned_entry_errors_without_changing_status() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(104);

        assert_eq!(
            store.check_or_insert(key, b"abandoned-complete", 1000, "trace-complete-abandoned"),
            DedupeResult::New
        );
        assert_eq!(store.recover_inflight("trace-complete-abandoned"), 1);
        let err = store
            .complete(
                key,
                b"should-not-complete".to_vec(),
                1001,
                "trace-complete-abandoned",
            )
            .unwrap_err();

        assert!(err.contains("not Processing"));
        let entry = store
            .entries
            .get(&key.to_hex())
            .expect("entry should remain present");
        assert_eq!(entry.status, EntryStatus::Abandoned);
        assert!(entry.outcome.is_none());
    }

    #[test]
    fn complete_unknown_key_does_not_emit_audit_record() {
        let mut store = IdempotencyDedupeStore::new(3600);

        let err = store
            .complete(
                test_key(105),
                b"missing".to_vec(),
                1000,
                "trace-missing-complete",
            )
            .unwrap_err();

        assert!(err.contains("no entry"));
        assert_eq!(store.entry_count(), 0);
        assert_eq!(store.audit_log_len(), 0);
    }

    #[test]
    fn duplicate_at_exact_ttl_boundary_is_not_returned_from_cache() {
        let mut store = IdempotencyDedupeStore::new(100);
        let key = test_key(106);

        assert_eq!(
            store.check_or_insert(key, b"ttl-boundary", 1000, "trace-ttl-boundary"),
            DedupeResult::New
        );
        store
            .complete(key, b"ttl-result".to_vec(), 1001, "trace-ttl-boundary")
            .expect("initial completion should succeed");
        let result = store.check_or_insert(key, b"ttl-boundary", 1100, "trace-ttl-boundary");

        assert_eq!(result, DedupeResult::New);
        let (_new, duplicates, _conflicts, expired) = store.stats();
        assert_eq!(duplicates, 0);
        assert_eq!(expired, 1);
    }

    #[test]
    fn zero_ttl_entry_is_immediately_replaced_instead_of_deduped() {
        let mut store = IdempotencyDedupeStore::new(0);
        let key = test_key(107);

        assert_eq!(
            store.check_or_insert(key, b"zero-ttl", 1000, "trace-zero-ttl"),
            DedupeResult::New
        );
        store
            .complete(key, b"zero-result".to_vec(), 1000, "trace-zero-ttl")
            .expect("initial completion should succeed");
        let result = store.check_or_insert(key, b"zero-ttl", 1000, "trace-zero-ttl");

        assert_eq!(result, DedupeResult::New);
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn empty_sweep_removes_nothing_but_records_sweep_event() {
        let mut store = IdempotencyDedupeStore::new(3600);

        let swept = store.sweep_expired(1000, "trace-empty-sweep");

        assert_eq!(swept, 0);
        assert_eq!(store.entry_count(), 0);
        assert_eq!(store.audit_log_len(), 1);
        assert_eq!(
            store.audit_log()[0].event_code,
            event_codes::ID_SWEEP_COMPLETE
        );
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_uses_saturating_arithmetic_to_prevent_underflow() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 2);

        assert_eq!(items, vec![2, 3, 4]);
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn in_flight_same_payload_does_not_emit_duplicate_audit_or_increment_duplicate_count() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(108);

        assert_eq!(
            store.check_or_insert(key, b"inflight", 1000, "trace-inflight-no-dup"),
            DedupeResult::New
        );
        let audit_len_before = store.audit_log_len();
        let result = store.check_or_insert(key, b"inflight", 1001, "trace-inflight-no-dup");

        assert_eq!(result, DedupeResult::InFlight);
        let (_new, duplicates, _conflicts, _expired) = store.stats();
        assert_eq!(duplicates, 0);
        assert_eq!(store.audit_log_len(), audit_len_before);
    }

    #[test]
    fn corrupt_complete_entry_remains_unmodified_after_fail_closed_check() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(109);
        let payload = b"corrupt-stable";
        let key_hex = key.to_hex();
        store.entries.insert(
            key_hex.clone(),
            DedupeEntry {
                key,
                payload_hash: hash_payload(payload),
                status: EntryStatus::Complete,
                outcome: None,
                created_at_secs: 1000,
                ttl_secs: 3600,
            },
        );

        let result = store.check_or_insert(key, payload, 1001, "trace-corrupt-stable");

        assert!(matches!(result, DedupeResult::Conflict { .. }));
        let entry = store.entries.get(&key_hex).expect("entry should remain");
        assert_eq!(entry.status, EntryStatus::Complete);
        assert!(entry.outcome.is_none());
    }

    #[test]
    fn deserialized_corrupt_complete_entry_fails_closed_without_duplicate() {
        let key = test_key(110);
        let key_hex = key.to_hex();
        let mut store = IdempotencyDedupeStore::new(3600);
        store.entries.insert(
            key_hex.clone(),
            DedupeEntry {
                key,
                payload_hash: hash_payload(b"persisted-payload"),
                status: EntryStatus::Complete,
                outcome: None,
                created_at_secs: 1000,
                ttl_secs: 3600,
            },
        );
        let encoded = serde_json::to_string(&store).expect("store should serialize");
        let mut decoded: IdempotencyDedupeStore =
            serde_json::from_str(&encoded).expect("store should deserialize");

        let result = decoded.check_or_insert(key, b"persisted-payload", 1001, "trace-corrupt-json");

        assert!(matches!(result, DedupeResult::Conflict { .. }));
        let (_new, duplicates, conflicts, _expired) = decoded.stats();
        assert_eq!(duplicates, 0);
        assert_eq!(conflicts, 1);
        assert_eq!(
            decoded.entries.get(&key_hex).unwrap().status,
            EntryStatus::Complete
        );
    }

    #[test]
    fn abandoned_retry_same_payload_resets_status_and_clears_prior_outcome() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(111);
        let key_hex = key.to_hex();
        assert_eq!(
            store.check_or_insert(key, b"retry-reset", 1000, "trace-retry-reset"),
            DedupeResult::New
        );
        assert_eq!(store.recover_inflight("trace-retry-reset"), 1);

        let result = store.check_or_insert(key, b"retry-reset", 1001, "trace-retry-reset");

        assert_eq!(result, DedupeResult::New);
        let entry = store.entries.get(&key_hex).expect("entry should remain");
        assert_eq!(entry.status, EntryStatus::Processing);
        assert!(entry.outcome.is_none());
        assert_eq!(entry.created_at_secs, 1001);
    }

    #[test]
    fn recover_inflight_second_pass_recovers_zero_and_preserves_abandoned_entry() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(112);
        let key_hex = key.to_hex();
        assert_eq!(
            store.check_or_insert(key, b"recover-once", 1000, "trace-recover-once"),
            DedupeResult::New
        );
        assert_eq!(store.recover_inflight("trace-recover-once"), 1);

        let recovered_again = store.recover_inflight("trace-recover-again");

        assert_eq!(recovered_again, 0);
        assert_eq!(
            store.entries.get(&key_hex).unwrap().status,
            EntryStatus::Abandoned
        );
    }

    #[test]
    fn sweep_expired_removes_abandoned_entry_at_exact_boundary() {
        let mut store = IdempotencyDedupeStore::new(10);
        let key = test_key(113);
        assert_eq!(
            store.check_or_insert(key, b"abandoned-expiry", 1000, "trace-abandoned-expiry"),
            DedupeResult::New
        );
        assert_eq!(store.recover_inflight("trace-abandoned-expiry"), 1);

        let swept = store.sweep_expired(1010, "trace-abandoned-expiry");

        assert_eq!(swept, 1);
        assert_eq!(store.entry_count(), 0);
        let (_new, _duplicates, _conflicts, expired) = store.stats();
        assert_eq!(expired, 1);
    }

    #[test]
    fn conflict_after_recovery_does_not_consume_abandoned_retry_slot() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(114);
        let key_hex = key.to_hex();
        assert_eq!(
            store.check_or_insert(key, b"stable-retry", 1000, "trace-conflict-retry-slot"),
            DedupeResult::New
        );
        assert_eq!(store.recover_inflight("trace-conflict-retry-slot"), 1);
        assert!(matches!(
            store.check_or_insert(key, b"bad-retry", 1001, "trace-conflict-retry-slot"),
            DedupeResult::Conflict { .. }
        ));

        let retry = store.check_or_insert(key, b"stable-retry", 1002, "trace-conflict-retry-slot");

        assert_eq!(retry, DedupeResult::New);
        let entry = store.entries.get(&key_hex).expect("entry should remain");
        assert_eq!(entry.status, EntryStatus::Processing);
        assert_eq!(entry.created_at_secs, 1002);
    }

    #[test]
    fn conflict_result_reports_original_and_actual_payload_digests() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(115);
        let original = b"original-conflict-payload";
        let changed = b"changed-conflict-payload";

        assert_eq!(
            store.check_or_insert(key, original, 1000, "trace-conflict-digests"),
            DedupeResult::New
        );
        let result = store.check_or_insert(key, changed, 1001, "trace-conflict-digests");

        match result {
            DedupeResult::Conflict {
                key_hex,
                expected_hash: expected_digest,
                actual_hash: actual_digest,
            } => {
                assert_eq!(key_hex, key.to_hex());
                assert_eq!(expected_digest, hash_payload(original));
                assert_eq!(actual_digest, hash_payload(changed));
            }
            other => unreachable!("expected conflict with digests, got {other:?}"),
        }
    }

    #[test]
    fn conflict_against_abandoned_entry_reports_original_payload_digest() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(116);
        assert_eq!(
            store.check_or_insert(key, b"recover-original", 1000, "trace-abandoned-digest"),
            DedupeResult::New
        );
        assert_eq!(store.recover_inflight("trace-abandoned-digest"), 1);

        let result = store.check_or_insert(key, b"recover-changed", 1001, "trace-abandoned-digest");

        match result {
            DedupeResult::Conflict {
                expected_hash: expected_digest,
                actual_hash: actual_digest,
                ..
            } => {
                assert_eq!(expected_digest, hash_payload(b"recover-original"));
                assert_eq!(actual_digest, hash_payload(b"recover-changed"));
            }
            other => unreachable!("expected abandoned conflict, got {other:?}"),
        }
    }

    #[test]
    fn conflict_after_completion_does_not_increment_duplicate_counter() {
        let mut store = IdempotencyDedupeStore::new(3600);
        let key = test_key(117);
        assert_eq!(
            store.check_or_insert(key, b"complete-original", 1000, "trace-complete-stats"),
            DedupeResult::New
        );
        store
            .complete(
                key,
                b"complete-outcome".to_vec(),
                1001,
                "trace-complete-stats",
            )
            .expect("completion should succeed");

        let result = store.check_or_insert(key, b"complete-changed", 1002, "trace-complete-stats");

        assert!(matches!(result, DedupeResult::Conflict { .. }));
        let (_new, duplicates, conflicts, _expired) = store.stats();
        assert_eq!(duplicates, 0);
        assert_eq!(conflicts, 1);
    }

    #[test]
    fn audit_capacity_one_keeps_conflict_event_after_eviction() {
        let mut store = IdempotencyDedupeStore::with_audit_log_capacity(3600, 1);
        let key = test_key(118);
        assert_eq!(
            store.check_or_insert(key, b"audit-original", 1000, "trace-audit-one"),
            DedupeResult::New
        );

        let result = store.check_or_insert(key, b"audit-changed", 1001, "trace-audit-one");

        assert!(matches!(result, DedupeResult::Conflict { .. }));
        assert_eq!(store.audit_log_len(), 1);
        assert_eq!(
            store.audit_log()[0].event_code,
            event_codes::ID_ENTRY_CONFLICT
        );
    }

    #[test]
    fn recover_with_capacity_one_evicts_prior_new_audit_event() {
        let mut store = IdempotencyDedupeStore::with_audit_log_capacity(3600, 1);
        let key = test_key(119);
        assert_eq!(
            store.check_or_insert(key, b"recover-capacity-one", 1000, "trace-recover-one"),
            DedupeResult::New
        );

        let recovered = store.recover_inflight("trace-recover-one");

        assert_eq!(recovered, 1);
        assert_eq!(store.audit_log_len(), 1);
        assert_eq!(
            store.audit_log()[0].event_code,
            event_codes::ID_STORE_RECOVERY
        );
    }

    #[test]
    fn sweep_before_exact_ttl_boundary_removes_nothing() {
        let mut store = IdempotencyDedupeStore::new(10);
        let key = test_key(120);
        assert_eq!(
            store.check_or_insert(key, b"not-yet-expired", 1000, "trace-before-ttl"),
            DedupeResult::New
        );

        let swept = store.sweep_expired(1009, "trace-before-ttl");

        assert_eq!(swept, 0);
        assert_eq!(store.entry_count(), 1);
        let (_new, _duplicates, _conflicts, expired) = store.stats();
        assert_eq!(expired, 0);
    }

    #[test]
    fn saturating_expiry_deadline_does_not_expire_before_u64_max() {
        let entry = DedupeEntry {
            key: test_key(121),
            payload_hash: hash_payload(b"saturating-deadline"),
            status: EntryStatus::Processing,
            outcome: None,
            created_at_secs: u64::MAX - 5,
            ttl_secs: 10,
        };

        assert!(!entry.is_expired(u64::MAX - 1));
        assert!(entry.is_expired(u64::MAX));
    }
}
