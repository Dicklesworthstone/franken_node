//! Snapshot policy conformance tests (bd-24s).
//!
//! Verifies snapshot trigger evaluation, replay bound enforcement,
//! hash validation, monotonicity, and policy audit.

use frankenengine_node::connector::snapshot_policy::*;

// === Trigger conformance ===

#[test]
fn trigger_by_update_count() {
    let mut t = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::new(10, 65536)).unwrap();
    for _ in 0..9 {
        t.record_mutation(10);
    }
    assert!(!t.should_snapshot());
    t.record_mutation(10);
    assert!(t.should_snapshot());
}

#[test]
fn trigger_by_byte_threshold() {
    let mut t = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::new(100, 1024)).unwrap();
    t.record_mutation(1023);
    assert!(!t.should_snapshot());
    t.record_mutation(1);
    assert!(t.should_snapshot());
}

#[test]
fn snapshot_resets_accumulators() {
    let mut t = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::new(5, 1024)).unwrap();
    for _ in 0..5 {
        t.record_mutation(100);
    }
    assert!(t.should_snapshot());
    t.take_snapshot(1, "hash".into(), "t".into()).unwrap();
    assert!(!t.should_snapshot());
    assert_eq!(t.ops_since_snapshot, 0);
    assert_eq!(t.bytes_since_snapshot, 0);
}

// === Replay bound conformance ===

#[test]
fn replay_within_bounds_passes() {
    let mut t = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::default_policy()).unwrap();
    t.take_snapshot(10, "h".into(), "t".into()).unwrap();
    t.record_mutation(1024);
    assert!(t.check_replay_bound(60, 100, 4096).is_ok());
}

#[test]
fn replay_exceeding_bound_fails() {
    let mut t = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::default_policy()).unwrap();
    t.take_snapshot(10, "h".into(), "t".into()).unwrap();
    t.record_mutation(1024);
    let err = t.check_replay_bound(200, 100, 4096).unwrap_err();
    assert!(matches!(err, SnapshotError::ReplayBoundExceeded { .. }));
}

#[test]
fn replay_byte_boundary_fails_closed() {
    let mut t = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::default_policy()).unwrap();
    t.take_snapshot(10, "h".into(), "t".into()).unwrap();
    t.record_mutation(4096);
    let err = t.check_replay_bound(11, 100, 4096).unwrap_err();
    assert!(matches!(err, SnapshotError::ReplayBoundExceeded { .. }));
}

// === Hash validation conformance ===

#[test]
fn hash_validation_passes_on_match() {
    let record = SnapshotRecord {
        connector_id: "conn-1".into(),
        snapshot_version: 5,
        root_hash: "correct_hash".into(),
        taken_at: "t".into(),
        policy: SnapshotPolicy::default_policy(),
        ops_since_last: 50,
        bytes_since_last: 1000,
    };
    assert!(SnapshotTracker::validate_snapshot_hash(&record, "correct_hash").is_ok());
}

#[test]
fn hash_validation_fails_on_mismatch() {
    let record = SnapshotRecord {
        connector_id: "conn-1".into(),
        snapshot_version: 5,
        root_hash: "abc".into(),
        taken_at: "t".into(),
        policy: SnapshotPolicy::default_policy(),
        ops_since_last: 50,
        bytes_since_last: 1000,
    };
    let err = SnapshotTracker::validate_snapshot_hash(&record, "xyz").unwrap_err();
    assert!(matches!(err, SnapshotError::SnapshotHashMismatch { .. }));
}

// === Monotonicity conformance ===

#[test]
fn snapshot_version_must_increase() {
    let mut t = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::default_policy()).unwrap();
    t.take_snapshot(5, "h1".into(), "t1".into()).unwrap();
    t.take_snapshot(10, "h2".into(), "t2".into()).unwrap();
    let err = t.take_snapshot(7, "h3".into(), "t3".into()).unwrap_err();
    assert!(matches!(err, SnapshotError::SnapshotStale { .. }));
}

// === Policy audit conformance ===

#[test]
fn policy_change_is_audited() {
    let mut t = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::default_policy()).unwrap();
    let new = SnapshotPolicy::new(50, 32768);
    let audit = t
        .update_policy(new, "tighten".into(), "2026-01-01T00:00:00Z".into())
        .unwrap();
    assert_eq!(audit.old_policy.every_updates, 100);
    assert_eq!(audit.new_policy.every_updates, 50);
    assert_eq!(t.audit_log.len(), 1);
}

#[test]
fn invalid_policy_rejected() {
    let mut t = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::default_policy()).unwrap();
    let bad = SnapshotPolicy::new(0, 1024);
    let err = t.update_policy(bad, "bad".into(), "t".into()).unwrap_err();
    assert!(matches!(err, SnapshotError::PolicyInvalid { .. }));
    assert_eq!(t.policy.every_updates, 100); // unchanged
}

#[test]
fn tracker_construction_rejects_invalid_policy() {
    let err = SnapshotTracker::new("conn-1".into(), SnapshotPolicy::new(0, 1024)).unwrap_err();
    assert!(matches!(err, SnapshotError::PolicyInvalid { .. }));
}
