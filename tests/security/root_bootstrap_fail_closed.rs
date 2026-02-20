//! Security conformance tests for fail-closed root bootstrap auth (bd-25nl).
//!
//! Normative checks:
//! - missing root is rejected
//! - malformed root is rejected
//! - invalid auth material is rejected
//! - future epoch root is rejected
//! - version mismatch is rejected
//! - valid root + auth succeeds

#[path = "../../crates/franken-node/src/control_plane/root_pointer.rs"]
mod root_pointer;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use root_pointer::{
    BootstrapError, ControlEpoch, ROOT_POINTER_FORMAT_VERSION, RootAuthConfig, RootAuthRecord,
    RootPointer, bootstrap_root, publish_root, root_auth_path, root_pointer_path,
};

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic enough for tests")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fnode-bootstrap-{tag}-{nanos}"));
        fs::create_dir_all(&path).expect("create temp test dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn sample_root(epoch: u64) -> RootPointer {
    RootPointer {
        epoch: ControlEpoch(epoch),
        marker_stream_head_seq: epoch * 10,
        marker_stream_head_hash: format!("head-hash-{epoch}"),
        publication_timestamp: "2026-02-20T00:00:00Z".to_string(),
        publisher_id: "ops.test".to_string(),
    }
}

fn key() -> Vec<u8> {
    b"bootstrap-test-key".to_vec()
}

#[test]
fn missing_root_is_rejected() {
    let dir = TempDirGuard::new("missing");
    let cfg = RootAuthConfig::strict(key(), ControlEpoch(1));

    let err = bootstrap_root(dir.path(), &cfg).expect_err("missing root should fail");
    assert!(matches!(err, BootstrapError::RootMissing { .. }));
}

#[test]
fn malformed_root_is_rejected() {
    let dir = TempDirGuard::new("malformed");
    fs::write(root_pointer_path(dir.path()), b"{ not-json").expect("write malformed root");
    let cfg = RootAuthConfig::strict(key(), ControlEpoch(1));

    let err = bootstrap_root(dir.path(), &cfg).expect_err("malformed root should fail");
    assert!(matches!(err, BootstrapError::RootMalformed { .. }));
}

#[test]
fn invalid_auth_material_is_rejected() {
    let dir = TempDirGuard::new("bad-auth");
    let root = sample_root(3);
    let signing_key = key();
    publish_root(dir.path(), &root, &signing_key, "trace-bad-auth").expect("publish root");

    let auth_path = root_auth_path(dir.path());
    let mut auth: RootAuthRecord = serde_json::from_slice(&fs::read(&auth_path).expect("read auth"))
        .expect("parse auth");
    auth.mac = "tampered".to_string();
    fs::write(
        auth_path,
        serde_json::to_vec_pretty(&auth).expect("serialize tampered auth"),
    )
    .expect("write tampered auth");

    let cfg = RootAuthConfig::strict(signing_key, ControlEpoch(3));
    let err = bootstrap_root(dir.path(), &cfg).expect_err("invalid auth should fail");
    assert!(matches!(err, BootstrapError::RootAuthFailed { .. }));
}

#[test]
fn future_epoch_root_is_rejected() {
    let dir = TempDirGuard::new("future-epoch");
    let root = sample_root(12);
    let signing_key = key();
    publish_root(dir.path(), &root, &signing_key, "trace-future").expect("publish root");

    let cfg = RootAuthConfig {
        trust_anchor: signing_key,
        expected_format_version: ROOT_POINTER_FORMAT_VERSION.to_string(),
        current_epoch: ControlEpoch(10),
        max_future_epochs: 1,
    };
    let err = bootstrap_root(dir.path(), &cfg).expect_err("future epoch should fail");
    assert!(matches!(err, BootstrapError::RootEpochInvalid { .. }));
}

#[test]
fn version_mismatch_is_rejected() {
    let dir = TempDirGuard::new("version-mismatch");
    let root = sample_root(4);
    let signing_key = key();
    publish_root(dir.path(), &root, &signing_key, "trace-version").expect("publish root");

    let cfg = RootAuthConfig {
        trust_anchor: signing_key,
        expected_format_version: "v999".to_string(),
        current_epoch: ControlEpoch(4),
        max_future_epochs: 0,
    };
    let err = bootstrap_root(dir.path(), &cfg).expect_err("version mismatch should fail");
    assert!(matches!(err, BootstrapError::RootVersionMismatch { .. }));
}

#[test]
fn valid_root_auth_bootstrap_succeeds() {
    let dir = TempDirGuard::new("success");
    let root = sample_root(5);
    let signing_key = key();
    publish_root(dir.path(), &root, &signing_key, "trace-success").expect("publish root");

    let cfg = RootAuthConfig::strict(signing_key, ControlEpoch(5));
    let verified = bootstrap_root(dir.path(), &cfg).expect("bootstrap should succeed");

    assert_eq!(verified.root, root);
    assert_eq!(verified.auth.root_format_version, ROOT_POINTER_FORMAT_VERSION);
    assert_eq!(verified.auth.epoch, ControlEpoch(5));
}
