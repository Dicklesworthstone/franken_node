//! Integration tests for bd-12h8: Artifact persistence with deterministic replay.

use frankenengine_node::connector::artifact_persistence::*;

#[test]
fn inv_pra_complete() {
    let mut store = ArtifactStore::new();
    for (i, t) in ArtifactType::all().iter().enumerate() {
        store.persist(&format!("a{i}"), *t, &format!("h{i}"), "tr", 1000).unwrap();
    }
    assert_eq!(store.total_count(), 6, "INV-PRA-COMPLETE: all 6 types must be persistable");
    for t in ArtifactType::all() {
        assert_eq!(store.count_by_type(*t), 1, "INV-PRA-COMPLETE: type {} missing", t.label());
    }
}

#[test]
fn inv_pra_durable() {
    let mut store = ArtifactStore::new();
    store.persist("a1", ArtifactType::Invoke, "h1", "tr", 1000).unwrap();
    store.persist("a2", ArtifactType::Response, "h2", "tr", 1001).unwrap();
    // Artifacts remain accessible
    assert!(store.get("a1").is_some(), "INV-PRA-DURABLE: persisted artifact must remain");
    assert!(store.get("a2").is_some(), "INV-PRA-DURABLE: persisted artifact must remain");
}

#[test]
fn inv_pra_replay() {
    let mut store = ArtifactStore::new();
    store.persist("a1", ArtifactType::Invoke, "hash-abc", "tr", 1000).unwrap();
    // Verify replay matches
    store.verify_replay("a1", "hash-abc").unwrap();
    // Verify replay detects mismatch
    let err = store.verify_replay("a1", "wrong-hash").unwrap_err();
    assert_eq!(err.code(), "PRA_REPLAY_MISMATCH", "INV-PRA-REPLAY: mismatch must be detected");
}

#[test]
fn inv_pra_ordered() {
    let mut store = ArtifactStore::new();
    store.persist("a1", ArtifactType::Invoke, "h1", "tr", 1000).unwrap();
    store.persist("a2", ArtifactType::Invoke, "h2", "tr", 1001).unwrap();
    store.persist("a3", ArtifactType::Invoke, "h3", "tr", 1002).unwrap();
    let hooks = store.replay_hooks(ArtifactType::Invoke);
    assert_eq!(hooks.len(), 3, "INV-PRA-ORDERED: all hooks returned");
    for (i, hook) in hooks.iter().enumerate() {
        assert_eq!(hook.replay_order, i as u64, "INV-PRA-ORDERED: insertion order preserved");
        assert_eq!(hook.sequence_number, i as u64, "INV-PRA-ORDERED: sequence monotonic");
    }
}
