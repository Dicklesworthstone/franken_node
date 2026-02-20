//! Integration tests for bd-nwhn root pointer crash safety.

#[path = "../../crates/franken-node/src/control_plane/root_pointer.rs"]
mod root_pointer;

use chrono::Utc;
use root_pointer::{
    ControlEpoch, PublishStep, RootPointer, publish_root, publish_root_with_crash_injection,
    read_root,
};
use tempfile::TempDir;

fn signing_key() -> Vec<u8> {
    b"integration-root-pointer-signing-key".to_vec()
}

fn sample_root(epoch: u64, seq: u64, hash: &str) -> RootPointer {
    RootPointer {
        epoch: ControlEpoch(epoch),
        marker_stream_head_seq: seq,
        marker_stream_head_hash: hash.to_string(),
        publication_timestamp: Utc::now().to_rfc3339(),
        publisher_id: "integration-suite".to_string(),
    }
}

#[test]
fn crash_matrix_returns_old_or_new_only() {
    let dir = TempDir::new().expect("tempdir");
    let old_root = sample_root(1, 10, "old-hash");
    let new_root = sample_root(2, 20, "new-hash");
    let key = signing_key();

    publish_root(dir.path(), &old_root, &key, "seed").expect("seed");

    for step in [
        PublishStep::WriteTemp,
        PublishStep::FsyncTemp,
        PublishStep::Rename,
        PublishStep::FsyncDir,
    ] {
        let _ = publish_root_with_crash_injection(dir.path(), &new_root, &key, "crash", step);
        let recovered = read_root(dir.path()).expect("read root");
        assert!(
            recovered == old_root || recovered == new_root,
            "recovered root after {step:?} must be old or new"
        );
    }
}

#[test]
fn rapid_publish_cycles_remain_consistent() {
    let dir = TempDir::new().expect("tempdir");
    let key = signing_key();

    let mut last_seq = 0_u64;
    for epoch in 1_u64..=1000_u64 {
        let root = sample_root(epoch, epoch * 10, &format!("hash-{epoch}"));
        publish_root(dir.path(), &root, &key, "rapid-cycle").expect("publish cycle");
        last_seq = root.marker_stream_head_seq;
    }

    let loaded = read_root(dir.path()).expect("final root");
    assert_eq!(loaded.epoch, ControlEpoch(1000));
    assert_eq!(loaded.marker_stream_head_seq, last_seq);
    assert_eq!(loaded.marker_stream_head_hash, "hash-1000");
}
