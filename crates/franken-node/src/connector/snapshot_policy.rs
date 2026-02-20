//! Snapshot policy and bounded replay targets for connector state.
//!
//! Provides configurable snapshot triggers (`every_updates`, `every_bytes`)
//! that bound replay cost during state recovery. Snapshots are validated
//! against chain heads and policy changes are audited.

use serde::{Deserialize, Serialize};
use std::fmt;

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
}

impl ReplayTarget {
    pub fn new(
        max_replay_ops: u64,
        max_replay_bytes: u64,
        snapshot_version: u64,
        current_version: u64,
    ) -> Self {
        Self {
            max_replay_ops,
            max_replay_bytes,
            snapshot_version,
            current_version,
        }
    }

    /// Number of operations that must be replayed.
    pub fn replay_distance(&self) -> u64 {
        self.current_version.saturating_sub(self.snapshot_version)
    }

    /// Check if replay distance exceeds the configured max.
    pub fn is_within_bounds(&self) -> bool {
        self.replay_distance() <= self.max_replay_ops
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
    pub fn new(connector_id: String, policy: SnapshotPolicy) -> Self {
        Self {
            connector_id,
            policy,
            last_snapshot_version: 0,
            last_snapshot_hash: String::new(),
            ops_since_snapshot: 0,
            bytes_since_snapshot: 0,
            audit_log: Vec::new(),
        }
    }

    /// Record a state mutation of the given byte size.
    pub fn record_mutation(&mut self, bytes: u64) {
        self.ops_since_snapshot += 1;
        self.bytes_since_snapshot += bytes;
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
        if snapshot.root_hash != chain_head_hash {
            return Err(SnapshotError::SnapshotHashMismatch {
                expected: chain_head_hash.to_string(),
                actual: snapshot.root_hash.clone(),
            });
        }
        Ok(())
    }

    /// Build a replay target from current tracker state.
    pub fn replay_target(&self, current_version: u64, max_ops: u64, max_bytes: u64) -> ReplayTarget {
        ReplayTarget::new(max_ops, max_bytes, self.last_snapshot_version, current_version)
    }

    /// Check that the replay bound is not exceeded.
    pub fn check_replay_bound(
        &self,
        current_version: u64,
        max_replay_ops: u64,
    ) -> Result<(), SnapshotError> {
        let distance = current_version.saturating_sub(self.last_snapshot_version);
        if distance > max_replay_ops {
            return Err(SnapshotError::ReplayBoundExceeded {
                replay_ops: distance,
                max_replay_ops,
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
        self.audit_log.push(audit.clone());
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
            } => {
                write!(
                    f,
                    "REPLAY_BOUND_EXCEEDED: {replay_ops} ops exceeds max {max_replay_ops}"
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
        SnapshotTracker::new("conn-1".into(), SnapshotPolicy::default_policy())
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
        let record = t.take_snapshot(5, "abc123".into(), "2026-01-01T00:00:00Z".into()).unwrap();
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
        let rt = ReplayTarget::new(200, 100000, 5, 105);
        assert_eq!(rt.replay_distance(), 100);
        assert!(rt.is_within_bounds());
    }

    #[test]
    fn replay_target_exceeded() {
        let rt = ReplayTarget::new(50, 100000, 5, 105);
        assert_eq!(rt.replay_distance(), 100);
        assert!(!rt.is_within_bounds());
    }

    #[test]
    fn check_replay_bound_ok() {
        let mut t = default_tracker();
        t.take_snapshot(10, "h".into(), "t".into()).unwrap();
        assert!(t.check_replay_bound(60, 100).is_ok());
    }

    #[test]
    fn check_replay_bound_exceeded() {
        let mut t = default_tracker();
        t.take_snapshot(10, "h".into(), "t".into()).unwrap();
        let err = t.check_replay_bound(200, 100).unwrap_err();
        assert!(matches!(err, SnapshotError::ReplayBoundExceeded { .. }));
    }

    // === Policy update audit ===

    #[test]
    fn update_policy_audited() {
        let mut t = default_tracker();
        let new = SnapshotPolicy::new(50, 32768);
        let audit = t
            .update_policy(new.clone(), "tighter bounds".into(), "2026-01-01T00:00:00Z".into())
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
}
