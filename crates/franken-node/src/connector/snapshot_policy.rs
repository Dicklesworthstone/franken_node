//! Snapshot policy and bounded replay targets for connector state.
//!
//! Provides configurable snapshot triggers (`every_updates`, `every_bytes`)
//! that bound replay cost during state recovery. Snapshots are validated
//! against chain heads and policy changes are audited.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::security::constant_time::ct_eq;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }

    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
}

/// Snapshot trigger policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPolicy {
    /// Take a snapshot after this many state updates since last snapshot.
    pub every_updates: u64,
    /// Take a snapshot after this many bytes of accumulated mutations.
    pub every_bytes: u64,
}

impl SnapshotPolicy {
    pub const DEFAULT_EVERY_UPDATES: u64 = 100;
    pub const DEFAULT_EVERY_BYTES: u64 = 65536;

    pub fn new(every_updates: u64, every_bytes: u64) -> Self {
        Self {
            every_updates,
            every_bytes,
        }
    }

    pub fn default_policy() -> Self {
        Self::new(Self::DEFAULT_EVERY_UPDATES, Self::DEFAULT_EVERY_BYTES)
    }

    /// Validate that the policy has positive thresholds.
    pub fn validate(&self) -> Result<(), SnapshotError> {
        if self.every_updates == 0 || self.every_bytes == 0 {
            return Err(SnapshotError::PolicyInvalid {
                reason: format!(
                    "thresholds must be positive: every_updates={}, every_bytes={}",
                    self.every_updates, self.every_bytes
                ),
            });
        }
        Ok(())
    }
}

/// Replay target bounds the cost of replaying from last snapshot to current.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayTarget {
    pub max_replay_ops: u64,
    pub max_replay_bytes: u64,
    pub snapshot_version: u64,
    pub current_version: u64,
    pub replay_bytes: u64,
}

impl ReplayTarget {
    pub fn new(
        max_replay_ops: u64,
        max_replay_bytes: u64,
        snapshot_version: u64,
        current_version: u64,
        replay_bytes: u64,
    ) -> Self {
        Self {
            max_replay_ops,
            max_replay_bytes,
            snapshot_version,
            current_version,
            replay_bytes,
        }
    }

    /// Number of operations that must be replayed.
    pub fn replay_distance(&self) -> u64 {
        self.current_version.saturating_sub(self.snapshot_version)
    }

    /// Check if replay cost exceeds the configured max (fail-closed at boundary).
    pub fn is_within_bounds(&self) -> bool {
        self.replay_distance() < self.max_replay_ops && self.replay_bytes < self.max_replay_bytes
    }
}

/// A snapshot record capturing state at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub connector_id: String,
    pub snapshot_version: u64,
    pub root_hash: String,
    pub taken_at: String,
    pub policy: SnapshotPolicy,
    pub ops_since_last: u64,
    pub bytes_since_last: u64,
}

/// Audit record for policy changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAuditRecord {
    pub connector_id: String,
    pub old_policy: SnapshotPolicy,
    pub new_policy: SnapshotPolicy,
    pub changed_at: String,
    pub reason: String,
}

/// Tracks snapshot state for a connector, evaluating triggers and bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotTracker {
    pub connector_id: String,
    pub policy: SnapshotPolicy,
    pub last_snapshot_version: u64,
    pub last_snapshot_hash: String,
    pub ops_since_snapshot: u64,
    pub bytes_since_snapshot: u64,
    pub audit_log: Vec<PolicyAuditRecord>,
}

impl SnapshotTracker {
    pub fn new(connector_id: String, policy: SnapshotPolicy) -> Result<Self, SnapshotError> {
        policy.validate()?;

        Ok(Self {
            connector_id,
            policy,
            last_snapshot_version: 0,
            last_snapshot_hash: String::new(),
            ops_since_snapshot: 0,
            bytes_since_snapshot: 0,
            audit_log: Vec::new(),
        })
    }

    /// Record a state mutation of the given byte size.
    pub fn record_mutation(&mut self, bytes: u64) {
        self.ops_since_snapshot = self.ops_since_snapshot.saturating_add(1);
        self.bytes_since_snapshot = self.bytes_since_snapshot.saturating_add(bytes);
    }

    /// Check if a snapshot should be triggered based on current policy.
    pub fn should_snapshot(&self) -> bool {
        self.ops_since_snapshot >= self.policy.every_updates
            || self.bytes_since_snapshot >= self.policy.every_bytes
    }

    /// Take a snapshot at the given version with the given root hash.
    pub fn take_snapshot(
        &mut self,
        version: u64,
        root_hash: String,
        timestamp: String,
    ) -> Result<SnapshotRecord, SnapshotError> {
        // Monotonicity check
        if version <= self.last_snapshot_version && self.last_snapshot_version > 0 {
            return Err(SnapshotError::SnapshotStale {
                snapshot_version: version,
                current_version: self.last_snapshot_version,
            });
        }

        let record = SnapshotRecord {
            connector_id: self.connector_id.clone(),
            snapshot_version: version,
            root_hash: root_hash.clone(),
            taken_at: timestamp,
            policy: self.policy.clone(),
            ops_since_last: self.ops_since_snapshot,
            bytes_since_last: self.bytes_since_snapshot,
        };

        self.last_snapshot_version = version;
        self.last_snapshot_hash = root_hash;
        self.ops_since_snapshot = 0;
        self.bytes_since_snapshot = 0;

        Ok(record)
    }

    /// Validate that a snapshot's hash matches the expected chain head hash.
    pub fn validate_snapshot_hash(
        snapshot: &SnapshotRecord,
        chain_head_hash: &str,
    ) -> Result<(), SnapshotError> {
        if !ct_eq(&snapshot.root_hash, chain_head_hash) {
            return Err(SnapshotError::SnapshotHashMismatch {
                expected: chain_head_hash.to_string(),
                actual: snapshot.root_hash.clone(),
            });
        }
        Ok(())
    }

    /// Build a replay target from current tracker state.
    pub fn replay_target(
        &self,
        current_version: u64,
        max_ops: u64,
        max_bytes: u64,
    ) -> ReplayTarget {
        ReplayTarget::new(
            max_ops,
            max_bytes,
            self.last_snapshot_version,
            current_version,
            self.bytes_since_snapshot,
        )
    }

    /// Check that the replay bound is not exceeded.
    pub fn check_replay_bound(
        &self,
        current_version: u64,
        max_replay_ops: u64,
        max_replay_bytes: u64,
    ) -> Result<(), SnapshotError> {
        let replay_target = self.replay_target(current_version, max_replay_ops, max_replay_bytes);
        if !replay_target.is_within_bounds() {
            return Err(SnapshotError::ReplayBoundExceeded {
                replay_ops: replay_target.replay_distance(),
                max_replay_ops,
                replay_bytes: replay_target.replay_bytes,
                max_replay_bytes,
            });
        }
        Ok(())
    }

    /// Update the policy with auditing.
    pub fn update_policy(
        &mut self,
        new_policy: SnapshotPolicy,
        reason: String,
        timestamp: String,
    ) -> Result<PolicyAuditRecord, SnapshotError> {
        new_policy.validate()?;

        let audit = PolicyAuditRecord {
            connector_id: self.connector_id.clone(),
            old_policy: self.policy.clone(),
            new_policy: new_policy.clone(),
            changed_at: timestamp,
            reason,
        };

        self.policy = new_policy;
        push_bounded(&mut self.audit_log, audit.clone(), MAX_AUDIT_LOG_ENTRIES);
        Ok(audit)
    }
}

/// Errors for snapshot operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotError {
    #[serde(rename = "SNAPSHOT_HASH_MISMATCH")]
    SnapshotHashMismatch { expected: String, actual: String },
    #[serde(rename = "SNAPSHOT_STALE")]
    SnapshotStale {
        snapshot_version: u64,
        current_version: u64,
    },
    #[serde(rename = "REPLAY_BOUND_EXCEEDED")]
    ReplayBoundExceeded {
        replay_ops: u64,
        max_replay_ops: u64,
        replay_bytes: u64,
        max_replay_bytes: u64,
    },
    #[serde(rename = "POLICY_INVALID")]
    PolicyInvalid { reason: String },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SnapshotHashMismatch { expected, actual } => {
                write!(
                    f,
                    "SNAPSHOT_HASH_MISMATCH: expected '{expected}', got '{actual}'"
                )
            }
            Self::SnapshotStale {
                snapshot_version,
                current_version,
            } => {
                write!(
                    f,
                    "SNAPSHOT_STALE: snapshot v{snapshot_version} behind current v{current_version}"
                )
            }
            Self::ReplayBoundExceeded {
                replay_ops,
                max_replay_ops,
                replay_bytes,
                max_replay_bytes,
            } => {
                write!(
                    f,
                    "REPLAY_BOUND_EXCEEDED: {replay_ops} ops/{replay_bytes} bytes exceeds max {max_replay_ops} ops/{max_replay_bytes} bytes"
                )
            }
            Self::PolicyInvalid { reason } => {
                write!(f, "POLICY_INVALID: {reason}")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_tracker() -> SnapshotTracker {
        SnapshotTracker::new("conn-1".into(), SnapshotPolicy::default_policy()).unwrap()
    }

    // === Policy tests ===

    #[test]
    fn default_policy_values() {
        let p = SnapshotPolicy::default_policy();
        assert_eq!(p.every_updates, 100);
        assert_eq!(p.every_bytes, 65536);
    }

    #[test]
    fn policy_validate_ok() {
        let p = SnapshotPolicy::new(10, 1024);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn policy_validate_zero_updates_rejected() {
        let p = SnapshotPolicy::new(0, 1024);
        let err = p.validate().unwrap_err();
        assert!(matches!(err, SnapshotError::PolicyInvalid { .. }));
    }

    #[test]
    fn policy_validate_zero_bytes_rejected() {
        let p = SnapshotPolicy::new(10, 0);
        let err = p.validate().unwrap_err();
        assert!(matches!(err, SnapshotError::PolicyInvalid { .. }));
    }

    // === Tracker trigger tests ===

    #[test]
    fn no_trigger_initially() {
        let t = default_tracker();
        assert!(!t.should_snapshot());
    }

    #[test]
    fn trigger_by_updates() {
        let mut t = default_tracker();
        for _ in 0..100 {
            t.record_mutation(10);
        }
        assert!(t.should_snapshot());
    }

    #[test]
    fn trigger_by_bytes() {
        let mut t = default_tracker();
        t.record_mutation(65536);
        assert!(t.should_snapshot());
    }

    #[test]
    fn no_trigger_below_threshold() {
        let mut t = default_tracker();
        for _ in 0..99 {
            t.record_mutation(10);
        }
        assert!(!t.should_snapshot()); // 99 ops, 990 bytes — both below thresholds
    }

    // === Snapshot tests ===

    #[test]
    fn take_snapshot_resets_counters() {
        let mut t = default_tracker();
        for _ in 0..100 {
            t.record_mutation(100);
        }
        let record = t
            .take_snapshot(5, "abc123".into(), "2026-01-01T00:00:00Z".into())
            .unwrap();
        assert_eq!(record.ops_since_last, 100);
        assert_eq!(record.bytes_since_last, 10000);
        assert_eq!(t.ops_since_snapshot, 0);
        assert_eq!(t.bytes_since_snapshot, 0);
        assert_eq!(t.last_snapshot_version, 5);
    }

    #[test]
    fn snapshot_monotonicity_enforced() {
        let mut t = default_tracker();
        t.take_snapshot(5, "hash1".into(), "t1".into()).unwrap();
        let err = t.take_snapshot(3, "hash2".into(), "t2".into()).unwrap_err();
        assert!(matches!(err, SnapshotError::SnapshotStale { .. }));
    }

    #[test]
    fn snapshot_version_equal_rejected() {
        let mut t = default_tracker();
        t.take_snapshot(5, "hash1".into(), "t1".into()).unwrap();
        let err = t.take_snapshot(5, "hash2".into(), "t2".into()).unwrap_err();
        assert!(matches!(err, SnapshotError::SnapshotStale { .. }));
    }

    // === Hash validation ===

    #[test]
    fn validate_hash_match() {
        let record = SnapshotRecord {
            connector_id: "conn-1".into(),
            snapshot_version: 5,
            root_hash: "abc123".into(),
            taken_at: "t".into(),
            policy: SnapshotPolicy::default_policy(),
            ops_since_last: 50,
            bytes_since_last: 1000,
        };
        assert!(SnapshotTracker::validate_snapshot_hash(&record, "abc123").is_ok());
    }

    #[test]
    fn validate_hash_mismatch() {
        let record = SnapshotRecord {
            connector_id: "conn-1".into(),
            snapshot_version: 5,
            root_hash: "abc123".into(),
            taken_at: "t".into(),
            policy: SnapshotPolicy::default_policy(),
            ops_since_last: 50,
            bytes_since_last: 1000,
        };
        let err = SnapshotTracker::validate_snapshot_hash(&record, "different").unwrap_err();
        assert!(matches!(err, SnapshotError::SnapshotHashMismatch { .. }));
    }

    // === Replay bounds ===

    #[test]
    fn replay_target_distance() {
        let rt = ReplayTarget::new(200, 100000, 5, 105, 5000);
        assert_eq!(rt.replay_distance(), 100);
        assert_eq!(rt.replay_bytes, 5000);
        assert!(rt.is_within_bounds());
    }

    #[test]
    fn replay_target_exceeded() {
        let rt = ReplayTarget::new(50, 100000, 5, 105, 5000);
        assert_eq!(rt.replay_distance(), 100);
        assert!(!rt.is_within_bounds());
    }

    #[test]
    fn replay_target_boundary_fail_closed() {
        // distance == max → fail-closed: NOT within bounds
        let rt = ReplayTarget::new(100, 100000, 5, 105, 5000);
        assert_eq!(rt.replay_distance(), 100);
        assert!(!rt.is_within_bounds());
    }

    #[test]
    fn replay_target_byte_bound_exceeded() {
        let rt = ReplayTarget::new(200, 4096, 5, 105, 5000);
        assert!(!rt.is_within_bounds());
    }

    #[test]
    fn replay_target_byte_boundary_fail_closed() {
        let rt = ReplayTarget::new(200, 5000, 5, 105, 5000);
        assert!(!rt.is_within_bounds());
    }

    #[test]
    fn check_replay_bound_ok() {
        let mut t = default_tracker();
        t.take_snapshot(10, "h".into(), "t".into()).unwrap();
        t.record_mutation(1024);
        assert!(t.check_replay_bound(60, 100, 4096).is_ok());
    }

    #[test]
    fn check_replay_bound_exceeded() {
        let mut t = default_tracker();
        t.take_snapshot(10, "h".into(), "t".into()).unwrap();
        t.record_mutation(1024);
        let err = t.check_replay_bound(200, 100, 4096).unwrap_err();
        assert!(matches!(err, SnapshotError::ReplayBoundExceeded { .. }));
    }

    #[test]
    fn check_replay_bound_boundary_fail_closed() {
        // distance == max → fail-closed: reject at boundary
        let mut t = default_tracker();
        t.take_snapshot(10, "h".into(), "t".into()).unwrap();
        t.record_mutation(1024);
        assert!(t.check_replay_bound(110, 100, 4096).is_err());
    }

    #[test]
    fn check_replay_bound_exceeded_by_bytes() {
        let mut t = default_tracker();
        t.take_snapshot(10, "h".into(), "t".into()).unwrap();
        t.record_mutation(4097);
        let err = t.check_replay_bound(11, 100, 4096).unwrap_err();
        assert!(matches!(err, SnapshotError::ReplayBoundExceeded { .. }));
    }

    #[test]
    fn check_replay_bound_byte_boundary_fail_closed() {
        let mut t = default_tracker();
        t.take_snapshot(10, "h".into(), "t".into()).unwrap();
        t.record_mutation(4096);
        assert!(t.check_replay_bound(11, 100, 4096).is_err());
    }

    #[test]
    fn tracker_new_rejects_invalid_policy() {
        let err = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::new(0, 1024)).unwrap_err();
        assert!(matches!(err, SnapshotError::PolicyInvalid { .. }));
    }

    // === Policy update audit ===

    #[test]
    fn update_policy_audited() {
        let mut t = default_tracker();
        let new = SnapshotPolicy::new(50, 32768);
        let audit = t
            .update_policy(
                new.clone(),
                "tighter bounds".into(),
                "2026-01-01T00:00:00Z".into(),
            )
            .unwrap();
        assert_eq!(audit.old_policy.every_updates, 100);
        assert_eq!(audit.new_policy.every_updates, 50);
        assert_eq!(t.policy, new);
        assert_eq!(t.audit_log.len(), 1);
    }

    #[test]
    fn update_policy_invalid_rejected() {
        let mut t = default_tracker();
        let bad = SnapshotPolicy::new(0, 1024);
        let err = t
            .update_policy(bad, "bad policy".into(), "t".into())
            .unwrap_err();
        assert!(matches!(err, SnapshotError::PolicyInvalid { .. }));
        // Original policy unchanged
        assert_eq!(t.policy.every_updates, 100);
    }

    // === Serde roundtrip ===

    #[test]
    fn serde_roundtrip_policy() {
        let p = SnapshotPolicy::new(50, 32768);
        let json = serde_json::to_string(&p).unwrap();
        let parsed: SnapshotPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn serde_roundtrip_error() {
        let err = SnapshotError::ReplayBoundExceeded {
            replay_ops: 150,
            max_replay_ops: 100,
            replay_bytes: 2048,
            max_replay_bytes: 1024,
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: SnapshotError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, parsed);
    }

    #[test]
    fn error_display_messages() {
        let e1 = SnapshotError::SnapshotHashMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(e1.to_string().contains("SNAPSHOT_HASH_MISMATCH"));

        let e2 = SnapshotError::ReplayBoundExceeded {
            replay_ops: 150,
            max_replay_ops: 100,
            replay_bytes: 2048,
            max_replay_bytes: 1024,
        };
        assert!(e2.to_string().contains("REPLAY_BOUND_EXCEEDED"));

        let e3 = SnapshotError::PolicyInvalid {
            reason: "zero".into(),
        };
        assert!(e3.to_string().contains("POLICY_INVALID"));

        let e4 = SnapshotError::SnapshotStale {
            snapshot_version: 3,
            current_version: 5,
        };
        assert!(e4.to_string().contains("SNAPSHOT_STALE"));
    }

    #[test]
    fn policy_validate_rejects_both_zero_thresholds_with_diagnostic_values() {
        let policy = SnapshotPolicy::new(0, 0);

        let err = policy.validate().unwrap_err();

        match err {
            SnapshotError::PolicyInvalid { reason } => {
                assert!(reason.contains("every_updates=0"));
                assert!(reason.contains("every_bytes=0"));
            }
            other => unreachable!("expected invalid policy, got {other:?}"),
        }
    }

    #[test]
    fn stale_snapshot_rejection_does_not_reset_replay_counters() {
        let mut tracker = default_tracker();
        tracker.record_mutation(200);
        tracker
            .take_snapshot(10, "root-v10".into(), "t1".into())
            .expect("initial snapshot should succeed");
        tracker.record_mutation(300);

        let err = tracker
            .take_snapshot(9, "root-v9".into(), "t2".into())
            .unwrap_err();

        assert!(matches!(err, SnapshotError::SnapshotStale { .. }));
        assert_eq!(tracker.last_snapshot_version, 10);
        assert_eq!(tracker.ops_since_snapshot, 1);
        assert_eq!(tracker.bytes_since_snapshot, 300);
    }

    #[test]
    fn equal_version_snapshot_rejection_preserves_existing_tracker_state() {
        let mut tracker = default_tracker();
        tracker
            .take_snapshot(5, "root-v5".into(), "t1".into())
            .expect("initial snapshot should succeed");
        tracker.record_mutation(512);

        let err = tracker
            .take_snapshot(5, "root-v5-replacement".into(), "t2".into())
            .unwrap_err();

        assert!(matches!(err, SnapshotError::SnapshotStale { .. }));
        assert_eq!(tracker.last_snapshot_version, 5);
        assert_eq!(tracker.ops_since_snapshot, 1);
        assert_eq!(tracker.bytes_since_snapshot, 512);
    }

    #[test]
    fn hash_validation_rejects_same_prefix_with_extra_suffix() {
        let record = SnapshotRecord {
            connector_id: "conn-1".into(),
            snapshot_version: 5,
            root_hash: "abcdef".into(),
            taken_at: "t".into(),
            policy: SnapshotPolicy::default_policy(),
            ops_since_last: 1,
            bytes_since_last: 1,
        };

        let err = SnapshotTracker::validate_snapshot_hash(&record, "abcdef00").unwrap_err();

        assert!(matches!(err, SnapshotError::SnapshotHashMismatch { .. }));
    }

    #[test]
    fn hash_validation_rejects_case_variant_digest() {
        let record = SnapshotRecord {
            connector_id: "conn-1".into(),
            snapshot_version: 5,
            root_hash: "abcdef".into(),
            taken_at: "t".into(),
            policy: SnapshotPolicy::default_policy(),
            ops_since_last: 1,
            bytes_since_last: 1,
        };

        let err = SnapshotTracker::validate_snapshot_hash(&record, "ABCDEF").unwrap_err();

        assert!(matches!(err, SnapshotError::SnapshotHashMismatch { .. }));
    }

    #[test]
    fn zero_replay_limits_fail_closed_even_without_mutations() {
        let tracker = default_tracker();

        let err = tracker.check_replay_bound(0, 0, 0).unwrap_err();

        assert_eq!(
            err,
            SnapshotError::ReplayBoundExceeded {
                replay_ops: 0,
                max_replay_ops: 0,
                replay_bytes: 0,
                max_replay_bytes: 0,
            }
        );
    }

    #[test]
    fn invalid_policy_update_zero_bytes_preserves_policy_and_audit_log() {
        let mut tracker = default_tracker();
        let original_policy = tracker.policy.clone();

        let err = tracker
            .update_policy(
                SnapshotPolicy::new(10, 0),
                "bad zero byte threshold".into(),
                "t".into(),
            )
            .unwrap_err();

        assert!(matches!(err, SnapshotError::PolicyInvalid { .. }));
        assert_eq!(tracker.policy, original_policy);
        assert!(tracker.audit_log.is_empty());
    }

    #[test]
    fn invalid_policy_update_both_zero_thresholds_preserves_existing_audit_log() {
        let mut tracker = default_tracker();
        tracker
            .update_policy(
                SnapshotPolicy::new(50, 4096),
                "valid update".into(),
                "t1".into(),
            )
            .expect("valid policy update should be audited");

        let err = tracker
            .update_policy(
                SnapshotPolicy::new(0, 0),
                "invalid update".into(),
                "t2".into(),
            )
            .unwrap_err();

        assert!(matches!(err, SnapshotError::PolicyInvalid { .. }));
        assert_eq!(tracker.policy, SnapshotPolicy::new(50, 4096));
        assert_eq!(tracker.audit_log.len(), 1);
        assert_eq!(tracker.audit_log[0].reason, "valid update");
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_retaining_new_item() {
        let mut items = vec!["old-audit", "older-audit"];

        push_bounded(&mut items, "new-audit", 0);

        assert!(items.is_empty());
    }

    #[test]
    fn invalid_policy_update_zero_updates_preserves_policy_and_audit_log() {
        let mut tracker = default_tracker();
        tracker
            .update_policy(
                SnapshotPolicy::new(25, 2048),
                "valid update".into(),
                "t1".into(),
            )
            .expect("valid policy update should be audited");

        let err = tracker
            .update_policy(
                SnapshotPolicy::new(0, 2048),
                "invalid zero update threshold".into(),
                "t2".into(),
            )
            .unwrap_err();

        assert!(matches!(err, SnapshotError::PolicyInvalid { .. }));
        assert_eq!(tracker.policy, SnapshotPolicy::new(25, 2048));
        assert_eq!(tracker.audit_log.len(), 1);
        assert_eq!(tracker.audit_log[0].reason, "valid update");
    }

    #[test]
    fn stale_snapshot_error_reports_attempted_and_current_versions() {
        let mut tracker = default_tracker();
        tracker
            .take_snapshot(9, "root-v9".into(), "t1".into())
            .expect("initial snapshot should succeed");

        let err = tracker
            .take_snapshot(4, "root-v4".into(), "t2".into())
            .unwrap_err();

        assert_eq!(
            err,
            SnapshotError::SnapshotStale {
                snapshot_version: 4,
                current_version: 9,
            }
        );
    }

    #[test]
    fn hash_validation_rejects_truncated_digest_prefix() {
        let record = SnapshotRecord {
            connector_id: "conn-1".into(),
            snapshot_version: 5,
            root_hash: "abcdef0123456789".into(),
            taken_at: "t".into(),
            policy: SnapshotPolicy::default_policy(),
            ops_since_last: 1,
            bytes_since_last: 1,
        };

        let err = SnapshotTracker::validate_snapshot_hash(&record, "abcdef01").unwrap_err();

        assert!(matches!(err, SnapshotError::SnapshotHashMismatch { .. }));
    }

    #[test]
    fn replay_distance_saturates_when_current_precedes_snapshot() {
        let target = ReplayTarget::new(10, 10, 100, 90, 0);

        assert_eq!(target.replay_distance(), 0);
        assert!(target.is_within_bounds());
    }

    #[test]
    fn replay_bound_rewound_version_still_fails_on_byte_limit() {
        let mut tracker = default_tracker();
        tracker
            .take_snapshot(10, "root-v10".into(), "t1".into())
            .expect("initial snapshot should succeed");
        tracker.record_mutation(4096);

        let err = tracker.check_replay_bound(9, 100, 4096).unwrap_err();

        assert_eq!(
            err,
            SnapshotError::ReplayBoundExceeded {
                replay_ops: 0,
                max_replay_ops: 100,
                replay_bytes: 4096,
                max_replay_bytes: 4096,
            }
        );
    }

    #[test]
    fn serde_policy_missing_byte_threshold_fails() {
        let err = serde_json::from_str::<SnapshotPolicy>(r#"{"every_updates":10}"#);

        assert!(err.is_err());
    }

    #[test]
    fn serde_replay_target_negative_limit_fails() {
        let err = serde_json::from_str::<ReplayTarget>(
            r#"{
  "max_replay_ops":-1,
  "max_replay_bytes":1024,
  "snapshot_version":1,
  "current_version":2,
  "replay_bytes":10
}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn serde_unknown_snapshot_error_code_fails() {
        let err = serde_json::from_str::<SnapshotError>(
            r#"{"UNKNOWN_SNAPSHOT_ERROR":{"reason":"bad"}}"#,
        );

        assert!(err.is_err());
    }

    #[test]
    fn serde_snapshot_record_missing_policy_fails() {
        let json = serde_json::json!({
            "connector_id": "conn-1",
            "snapshot_version": 7,
            "root_hash": "root-v7",
            "taken_at": "t",
            "ops_since_last": 2,
            "bytes_since_last": 128
        });

        let err = serde_json::from_value::<SnapshotRecord>(json).unwrap_err();

        assert!(err.to_string().contains("policy"));
    }

    #[test]
    fn serde_policy_audit_missing_reason_fails() {
        let json = serde_json::json!({
            "connector_id": "conn-1",
            "old_policy": SnapshotPolicy::new(100, 65536),
            "new_policy": SnapshotPolicy::new(50, 4096),
            "changed_at": "t"
        });

        let err = serde_json::from_value::<PolicyAuditRecord>(json).unwrap_err();

        assert!(err.to_string().contains("reason"));
    }

    #[test]
    fn serde_snapshot_error_stale_missing_current_version_fails() {
        let json = serde_json::json!({
            "SNAPSHOT_STALE": {
                "snapshot_version": 4
            }
        });

        let err = serde_json::from_value::<SnapshotError>(json).unwrap_err();

        assert!(err.to_string().contains("current_version"));
    }

    #[test]
    fn serde_snapshot_error_mismatch_missing_actual_fails() {
        let json = serde_json::json!({
            "SNAPSHOT_HASH_MISMATCH": {
                "expected": "chain-head"
            }
        });

        let err = serde_json::from_value::<SnapshotError>(json).unwrap_err();

        assert!(err.to_string().contains("actual"));
    }

    #[test]
    fn serde_policy_string_threshold_fails() {
        let json = serde_json::json!({
            "every_updates": "10",
            "every_bytes": 1024
        });

        let err = serde_json::from_value::<SnapshotPolicy>(json).unwrap_err();

        assert!(err.to_string().contains("invalid type"));
    }

    #[test]
    fn serde_replay_target_missing_replay_bytes_fails() {
        let json = serde_json::json!({
            "max_replay_ops": 10,
            "max_replay_bytes": 1024,
            "snapshot_version": 1,
            "current_version": 2
        });

        let err = serde_json::from_value::<ReplayTarget>(json).unwrap_err();

        assert!(err.to_string().contains("replay_bytes"));
    }

    #[test]
    fn hash_validation_rejects_empty_expected_for_nonempty_record() {
        let record = SnapshotRecord {
            connector_id: "conn-1".into(),
            snapshot_version: 5,
            root_hash: "root-v5".into(),
            taken_at: "t".into(),
            policy: SnapshotPolicy::default_policy(),
            ops_since_last: 1,
            bytes_since_last: 1,
        };

        let err = SnapshotTracker::validate_snapshot_hash(&record, "").unwrap_err();

        assert!(matches!(err, SnapshotError::SnapshotHashMismatch { .. }));
    }

    #[test]
    fn hash_validation_rejects_empty_record_for_nonempty_expected() {
        let record = SnapshotRecord {
            connector_id: "conn-1".into(),
            snapshot_version: 5,
            root_hash: String::new(),
            taken_at: "t".into(),
            policy: SnapshotPolicy::default_policy(),
            ops_since_last: 1,
            bytes_since_last: 1,
        };

        let err = SnapshotTracker::validate_snapshot_hash(&record, "root-v5").unwrap_err();

        assert!(matches!(err, SnapshotError::SnapshotHashMismatch { .. }));
    }
}
