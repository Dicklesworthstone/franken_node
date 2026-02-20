//! bd-nwhn: Atomic root pointer publication protocol.
//!
//! Protocol (POSIX):
//! 1) write temp
//! 2) fsync temp
//! 3) rename temp -> canonical root path
//! 4) fsync directory
//!
//! The canonical root pointer is always either the previous durable value or the
//! new durable value, never a partial intermediate.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Canonical root pointer filename.
pub const ROOT_POINTER_FILE: &str = "root_pointer.json";
/// Canonical detached auth record filename for root pointer bootstrap checks.
pub const ROOT_POINTER_AUTH_FILE: &str = "root_pointer.auth.json";
/// Canonical root pointer format version.
pub const ROOT_POINTER_FORMAT_VERSION: &str = "v1";

/// Canonical event code for root publication start.
pub const ROOT_PUBLISH_START: &str = "ROOT_PUBLISH_START";

/// Canonical event code for root publication completion.
pub const ROOT_PUBLISH_COMPLETE: &str = "ROOT_PUBLISH_COMPLETE";

/// Canonical event code for root publication crash injection.
pub const ROOT_PUBLISH_CRASH_RECOVERY: &str = "ROOT_PUBLISH_CRASH_RECOVERY";

/// Epoch type used for control-plane ordering and evidence anchoring.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ControlEpoch(pub u64);

impl fmt::Display for ControlEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Canonical root pointer payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootPointer {
    pub epoch: ControlEpoch,
    pub marker_stream_head_seq: u64,
    pub marker_stream_head_hash: String,
    pub publication_timestamp: String,
    pub publisher_id: String,
}

/// Detached root authentication record written alongside the root pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootAuthRecord {
    pub root_format_version: String,
    pub root_hash: String,
    pub epoch: ControlEpoch,
    pub issued_at: String,
    pub mac: String,
}

impl RootPointer {
    /// Create a deterministic root pointer with the current RFC3339 timestamp.
    #[must_use]
    pub fn new(
        epoch: ControlEpoch,
        marker_stream_head_seq: u64,
        marker_stream_head_hash: String,
        publisher_id: String,
    ) -> Self {
        Self {
            epoch,
            marker_stream_head_seq,
            marker_stream_head_hash,
            publication_timestamp: Utc::now().to_rfc3339(),
            publisher_id,
        }
    }
}

/// Atomic publication protocol steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishStep {
    WriteTemp,
    FsyncTemp,
    Rename,
    FsyncDir,
}

impl PublishStep {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::WriteTemp => "write_temp",
            Self::FsyncTemp => "fsync_temp",
            Self::Rename => "rename",
            Self::FsyncDir => "fsync_dir",
        }
    }
}

/// Step trace used by tests/evidence to prove protocol ordering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishTrace {
    pub steps: Vec<PublishStep>,
}

/// Signed control event produced after successful publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootPublishEvent {
    pub event_code: String,
    pub trace_id: String,
    pub old_epoch: Option<ControlEpoch>,
    pub new_epoch: ControlEpoch,
    pub marker_stream_head_seq: u64,
    pub manifest_hash: String,
    pub timestamp: String,
    pub signature: String,
}

/// Publish result containing both signed event and step trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootPublishOutcome {
    pub event: RootPublishEvent,
    pub trace: PublishTrace,
}

/// Bootstrap auth policy for root pointer verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAuthConfig {
    pub trust_anchor: Vec<u8>,
    pub expected_format_version: String,
    pub current_epoch: ControlEpoch,
    pub max_future_epochs: u64,
}

impl RootAuthConfig {
    #[must_use]
    pub fn strict(trust_anchor: Vec<u8>, current_epoch: ControlEpoch) -> Self {
        Self {
            trust_anchor,
            expected_format_version: ROOT_POINTER_FORMAT_VERSION.to_string(),
            current_epoch,
            max_future_epochs: 0,
        }
    }

    #[must_use]
    pub fn max_allowed_epoch(&self) -> ControlEpoch {
        ControlEpoch(self.current_epoch.0.saturating_add(self.max_future_epochs))
    }
}

/// Bootstrap-verified root pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedRoot {
    pub root: RootPointer,
    pub auth: RootAuthRecord,
    pub verified_at: String,
}

/// Fail-closed bootstrap errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BootstrapError {
    #[error("root pointer missing at {path}")]
    RootMissing { path: String },
    #[error("root pointer malformed at {path}: {reason}")]
    RootMalformed { path: String, reason: String },
    #[error("root pointer authentication failed: {reason}")]
    RootAuthFailed { reason: String },
    #[error(
        "root epoch invalid: root_epoch={root_epoch}, current_epoch={current_epoch}, max_allowed_epoch={max_allowed_epoch}"
    )]
    RootEpochInvalid {
        current_epoch: ControlEpoch,
        root_epoch: ControlEpoch,
        max_allowed_epoch: ControlEpoch,
    },
    #[error("root version mismatch: expected={expected}, actual={actual}")]
    RootVersionMismatch { expected: String, actual: String },
}

impl BootstrapError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::RootMissing { .. } => "ROOT_BOOTSTRAP_MISSING",
            Self::RootMalformed { .. } => "ROOT_BOOTSTRAP_MALFORMED",
            Self::RootAuthFailed { .. } => "ROOT_BOOTSTRAP_AUTH_FAILED",
            Self::RootEpochInvalid { .. } => "ROOT_BOOTSTRAP_EPOCH_INVALID",
            Self::RootVersionMismatch { .. } => "ROOT_BOOTSTRAP_VERSION_MISMATCH",
        }
    }
}

/// Root publication/read errors.
#[derive(Debug, thiserror::Error)]
pub enum RootPointerError {
    #[error("failed to serialize root pointer payload: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to serialize publication event payload: {0}")]
    EventSerialize(serde_json::Error),
    #[error("failed to deserialize root pointer from {path}: {source}")]
    Deserialize {
        path: String,
        source: serde_json::Error,
    },
    #[error("root pointer missing at {path}")]
    MissingRoot { path: String },
    #[error("I/O failure during {step} at {path}: {source}")]
    Io {
        step: &'static str,
        path: String,
        source: std::io::Error,
    },
    #[error("epoch regression blocked: attempted={attempted}, current={current}")]
    EpochRegression {
        attempted: ControlEpoch,
        current: ControlEpoch,
    },
    #[error("crash injected after step {0:?}")]
    CrashInjected(PublishStep),
}

impl RootPointerError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Serialize(_) => "ROOT_SERIALIZE_FAILED",
            Self::EventSerialize(_) => "ROOT_EVENT_SERIALIZE_FAILED",
            Self::Deserialize { .. } => "ROOT_DESERIALIZE_FAILED",
            Self::MissingRoot { .. } => "ROOT_NOT_FOUND",
            Self::Io { step, .. } => match *step {
                "write_temp" => "ROOT_WRITE_TEMP_FAILED",
                "fsync_temp" => "ROOT_FSYNC_TEMP_FAILED",
                "rename" => "ROOT_RENAME_FAILED",
                "fsync_dir" => "ROOT_FSYNC_DIR_FAILED",
                "read_root" => "ROOT_READ_FAILED",
                _ => "ROOT_IO_FAILED",
            },
            Self::EpochRegression { .. } => "EPOCH_REGRESSION_BLOCKED",
            Self::CrashInjected(_) => "ROOT_CRASH_INJECTED",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PublishOptions {
    crash_after: Option<PublishStep>,
    delay_after_lock: Option<Duration>,
}

fn publish_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Compute canonical path for the root pointer inside `dir`.
#[must_use]
pub fn root_pointer_path(dir: &Path) -> PathBuf {
    dir.join(ROOT_POINTER_FILE)
}

/// Compute canonical path for detached root auth data.
#[must_use]
pub fn root_auth_path(dir: &Path) -> PathBuf {
    dir.join(ROOT_POINTER_AUTH_FILE)
}

/// Read and deserialize the canonical root pointer.
pub fn read_root(dir: &Path) -> Result<RootPointer, RootPointerError> {
    let path = root_pointer_path(dir);
    let bytes = fs::read(&path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            RootPointerError::MissingRoot {
                path: path.display().to_string(),
            }
        } else {
            RootPointerError::Io {
                step: "read_root",
                path: path.display().to_string(),
                source,
            }
        }
    })?;
    serde_json::from_slice::<RootPointer>(&bytes).map_err(|source| RootPointerError::Deserialize {
        path: path.display().to_string(),
        source,
    })
}

/// Fail-closed bootstrap gate for root pointer authentication + epoch/version checks.
///
/// No caller should treat root state as trusted until this function succeeds.
pub fn bootstrap_root(dir: &Path, auth_config: &RootAuthConfig) -> Result<VerifiedRoot, BootstrapError> {
    let root_path = root_pointer_path(dir);
    let root_bytes = fs::read(&root_path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            BootstrapError::RootMissing {
                path: root_path.display().to_string(),
            }
        } else {
            BootstrapError::RootMalformed {
                path: root_path.display().to_string(),
                reason: source.to_string(),
            }
        }
    })?;

    let root = serde_json::from_slice::<RootPointer>(&root_bytes).map_err(|source| {
        BootstrapError::RootMalformed {
            path: root_path.display().to_string(),
            reason: source.to_string(),
        }
    })?;

    let auth_path = root_auth_path(dir);
    let auth_bytes = fs::read(&auth_path).map_err(|source| BootstrapError::RootAuthFailed {
        reason: format!(
            "unable to read auth record at {}: {}",
            auth_path.display(),
            source
        ),
    })?;
    let auth = serde_json::from_slice::<RootAuthRecord>(&auth_bytes).map_err(|source| {
        BootstrapError::RootAuthFailed {
            reason: format!(
                "unable to parse auth record at {}: {}",
                auth_path.display(),
                source
            ),
        }
    })?;

    if auth.root_format_version != auth_config.expected_format_version {
        return Err(BootstrapError::RootVersionMismatch {
            expected: auth_config.expected_format_version.clone(),
            actual: auth.root_format_version.clone(),
        });
    }

    let max_allowed_epoch = auth_config.max_allowed_epoch();
    if root.epoch > max_allowed_epoch {
        return Err(BootstrapError::RootEpochInvalid {
            current_epoch: auth_config.current_epoch,
            root_epoch: root.epoch,
            max_allowed_epoch,
        });
    }

    let root_hash = hash_hex(&root_bytes);
    if auth.root_hash != root_hash {
        return Err(BootstrapError::RootAuthFailed {
            reason: format!(
                "root hash mismatch: expected={}, actual={}",
                auth.root_hash, root_hash
            ),
        });
    }
    if auth.epoch != root.epoch {
        return Err(BootstrapError::RootAuthFailed {
            reason: format!(
                "epoch mismatch between root and auth record: root={}, auth={}",
                root.epoch, auth.epoch
            ),
        });
    }

    let expected_mac = sign_payload(&root_hash, &auth_config.trust_anchor);
    if auth.mac != expected_mac {
        return Err(BootstrapError::RootAuthFailed {
            reason: "detached root MAC verification failed".to_string(),
        });
    }

    Ok(VerifiedRoot {
        root,
        auth,
        verified_at: Utc::now().to_rfc3339(),
    })
}

/// Publish a new root pointer atomically (`write -> fsync -> rename -> fsync dir`).
pub fn publish_root(
    dir: &Path,
    root: &RootPointer,
    signing_key: &[u8],
    trace_id: &str,
) -> Result<RootPublishOutcome, RootPointerError> {
    publish_root_internal(dir, root, signing_key, trace_id, PublishOptions::default())
}

/// Publish with crash injection after a specific protocol step.
pub fn publish_root_with_crash_injection(
    dir: &Path,
    root: &RootPointer,
    signing_key: &[u8],
    trace_id: &str,
    crash_after: PublishStep,
) -> Result<RootPublishOutcome, RootPointerError> {
    publish_root_internal(
        dir,
        root,
        signing_key,
        trace_id,
        PublishOptions {
            crash_after: Some(crash_after),
            delay_after_lock: None,
        },
    )
}

/// Verify a signed root publication event with the same key used to sign it.
pub fn verify_publish_event(
    event: &RootPublishEvent,
    signing_key: &[u8],
) -> Result<bool, RootPointerError> {
    let canonical = canonical_event_payload(event)?;
    let expected = sign_payload(&canonical, signing_key);
    Ok(expected == event.signature)
}

fn publish_root_internal(
    dir: &Path,
    root: &RootPointer,
    signing_key: &[u8],
    trace_id: &str,
    options: PublishOptions,
) -> Result<RootPublishOutcome, RootPointerError> {
    let _guard = publish_lock().lock().expect("publish mutex poisoned");
    if let Some(delay) = options.delay_after_lock {
        thread::sleep(delay);
    }

    let start = Instant::now();
    let root_path = root_pointer_path(dir);
    let temp_path = dir.join(format!(".{}.tmp.{}", ROOT_POINTER_FILE, Uuid::now_v7()));
    let old_root = read_root(dir).ok();

    let epoch_regression = old_root
        .as_ref()
        .is_some_and(|previous| root.epoch <= previous.epoch);
    if epoch_regression {
        let current = old_root
            .as_ref()
            .map(|previous| previous.epoch)
            .expect("regression check requires old root");
        return Err(RootPointerError::EpochRegression {
            attempted: root.epoch,
            current,
        });
    }

    let payload = serde_json::to_vec_pretty(root).map_err(RootPointerError::Serialize)?;
    let mut trace = PublishTrace::default();

    let mut temp_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(|source| RootPointerError::Io {
            step: "write_temp",
            path: temp_path.display().to_string(),
            source,
        })?;

    temp_file
        .write_all(&payload)
        .map_err(|source| RootPointerError::Io {
            step: "write_temp",
            path: temp_path.display().to_string(),
            source,
        })?;
    temp_file.flush().map_err(|source| RootPointerError::Io {
        step: "write_temp",
        path: temp_path.display().to_string(),
        source,
    })?;
    trace.steps.push(PublishStep::WriteTemp);
    maybe_crash(options.crash_after, PublishStep::WriteTemp)?;

    temp_file
        .sync_all()
        .map_err(|source| RootPointerError::Io {
            step: "fsync_temp",
            path: temp_path.display().to_string(),
            source,
        })?;
    trace.steps.push(PublishStep::FsyncTemp);
    maybe_crash(options.crash_after, PublishStep::FsyncTemp)?;

    fs::rename(&temp_path, &root_path).map_err(|source| RootPointerError::Io {
        step: "rename",
        path: root_path.display().to_string(),
        source,
    })?;
    trace.steps.push(PublishStep::Rename);
    maybe_crash(options.crash_after, PublishStep::Rename)?;

    sync_directory(dir)?;
    trace.steps.push(PublishStep::FsyncDir);
    maybe_crash(options.crash_after, PublishStep::FsyncDir)?;

    let manifest_hash = hash_hex(&payload);
    let auth_record = RootAuthRecord {
        root_format_version: ROOT_POINTER_FORMAT_VERSION.to_string(),
        root_hash: manifest_hash.clone(),
        epoch: root.epoch,
        issued_at: Utc::now().to_rfc3339(),
        mac: sign_payload(&manifest_hash, signing_key),
    };
    write_root_auth_record(dir, &auth_record)?;

    let event_unsigned = UnsignedRootPublishEvent {
        event_code: ROOT_PUBLISH_COMPLETE.to_string(),
        trace_id: trace_id.to_string(),
        old_epoch: old_root.as_ref().map(|r| r.epoch),
        new_epoch: root.epoch,
        marker_stream_head_seq: root.marker_stream_head_seq,
        manifest_hash: manifest_hash.clone(),
        timestamp: Utc::now().to_rfc3339(),
    };
    let signature_payload =
        serde_json::to_string(&event_unsigned).map_err(RootPointerError::EventSerialize)?;
    let signature = sign_payload(&signature_payload, signing_key);

    let _elapsed = start.elapsed();
    let event = RootPublishEvent {
        event_code: ROOT_PUBLISH_COMPLETE.to_string(),
        trace_id: trace_id.to_string(),
        old_epoch: old_root.as_ref().map(|r| r.epoch),
        new_epoch: root.epoch,
        marker_stream_head_seq: root.marker_stream_head_seq,
        manifest_hash,
        timestamp: event_unsigned.timestamp,
        signature,
    };

    Ok(RootPublishOutcome { event, trace })
}

fn maybe_crash(
    crash_after: Option<PublishStep>,
    step: PublishStep,
) -> Result<(), RootPointerError> {
    if crash_after == Some(step) {
        return Err(RootPointerError::CrashInjected(step));
    }
    Ok(())
}

fn write_root_auth_record(dir: &Path, record: &RootAuthRecord) -> Result<(), RootPointerError> {
    let auth_path = root_auth_path(dir);
    let temp_path = dir.join(format!(".{}.tmp.{}", ROOT_POINTER_AUTH_FILE, Uuid::now_v7()));
    let payload = serde_json::to_vec_pretty(record).map_err(RootPointerError::Serialize)?;

    let mut temp_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(|source| RootPointerError::Io {
            step: "write_root_auth_temp",
            path: temp_path.display().to_string(),
            source,
        })?;
    temp_file
        .write_all(&payload)
        .map_err(|source| RootPointerError::Io {
            step: "write_root_auth_temp",
            path: temp_path.display().to_string(),
            source,
        })?;
    temp_file.flush().map_err(|source| RootPointerError::Io {
        step: "write_root_auth_temp",
        path: temp_path.display().to_string(),
        source,
    })?;
    temp_file
        .sync_all()
        .map_err(|source| RootPointerError::Io {
            step: "fsync_root_auth_temp",
            path: temp_path.display().to_string(),
            source,
        })?;

    fs::rename(&temp_path, &auth_path).map_err(|source| RootPointerError::Io {
        step: "rename_root_auth",
        path: auth_path.display().to_string(),
        source,
    })?;
    sync_directory(dir)?;
    Ok(())
}

fn sync_directory(dir: &Path) -> Result<(), RootPointerError> {
    let handle = File::open(dir).map_err(|source| RootPointerError::Io {
        step: "fsync_dir",
        path: dir.display().to_string(),
        source,
    })?;
    handle.sync_all().map_err(|source| RootPointerError::Io {
        step: "fsync_dir",
        path: dir.display().to_string(),
        source,
    })
}

fn hash_hex(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

fn sign_payload(payload: &str, signing_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(signing_key);
    hasher.update(b":");
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedRootPublishEvent {
    event_code: String,
    trace_id: String,
    old_epoch: Option<ControlEpoch>,
    new_epoch: ControlEpoch,
    marker_stream_head_seq: u64,
    manifest_hash: String,
    timestamp: String,
}

fn canonical_event_payload(event: &RootPublishEvent) -> Result<String, RootPointerError> {
    serde_json::to_string(&UnsignedRootPublishEvent {
        event_code: event.event_code.clone(),
        trace_id: event.trace_id.clone(),
        old_epoch: event.old_epoch,
        new_epoch: event.new_epoch,
        marker_stream_head_seq: event.marker_stream_head_seq,
        manifest_hash: event.manifest_hash.clone(),
        timestamp: event.timestamp.clone(),
    })
    .map_err(RootPointerError::EventSerialize)
}

#[cfg(test)]
fn publish_root_with_delay_for_test(
    dir: &Path,
    root: &RootPointer,
    signing_key: &[u8],
    trace_id: &str,
    delay_after_lock: Duration,
) -> Result<RootPublishOutcome, RootPointerError> {
    publish_root_internal(
        dir,
        root,
        signing_key,
        trace_id,
        PublishOptions {
            crash_after: None,
            delay_after_lock: Some(delay_after_lock),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn key() -> Vec<u8> {
        b"unit-test-control-plane-key".to_vec()
    }

    fn root(epoch: u64, seq: u64, hash: &str) -> RootPointer {
        RootPointer {
            epoch: ControlEpoch(epoch),
            marker_stream_head_seq: seq,
            marker_stream_head_hash: hash.to_string(),
            publication_timestamp: Utc::now().to_rfc3339(),
            publisher_id: "test-publisher".to_string(),
        }
    }

    #[test]
    fn publish_and_read_roundtrip() {
        let dir = TempDir::new().expect("tempdir");
        let r = root(1, 10, "abc123");

        let outcome = publish_root(dir.path(), &r, &key(), "trace-roundtrip").expect("publish");
        let loaded = read_root(dir.path()).expect("read");

        assert_eq!(loaded, r);
        assert_eq!(
            outcome.trace.steps,
            vec![
                PublishStep::WriteTemp,
                PublishStep::FsyncTemp,
                PublishStep::Rename,
                PublishStep::FsyncDir
            ]
        );
        assert!(verify_publish_event(&outcome.event, &key()).expect("verify"));
    }

    #[test]
    fn publish_step_order_includes_all_fsync_points() {
        let dir = TempDir::new().expect("tempdir");
        publish_root(dir.path(), &root(1, 1, "h1"), &key(), "trace-order").expect("publish");

        let next = root(2, 2, "h2");
        let outcome = publish_root(dir.path(), &next, &key(), "trace-order-2").expect("publish");
        let expected = vec![
            PublishStep::WriteTemp,
            PublishStep::FsyncTemp,
            PublishStep::Rename,
            PublishStep::FsyncDir,
        ];
        assert_eq!(outcome.trace.steps, expected);
    }

    #[test]
    fn crash_injection_recovers_old_or_new_root_only() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let old_root = root(1, 100, "old-hash");
        let new_root = root(2, 200, "new-hash");

        publish_root(dir.path(), &old_root, &k, "seed").expect("seed publish");

        for step in [
            PublishStep::WriteTemp,
            PublishStep::FsyncTemp,
            PublishStep::Rename,
            PublishStep::FsyncDir,
        ] {
            let _ =
                publish_root_with_crash_injection(dir.path(), &new_root, &k, "crash-matrix", step);
            let recovered = read_root(dir.path()).expect("recover");
            let valid = recovered == old_root || recovered == new_root;
            assert!(valid, "recovered root must be old or new after {step:?}");

            if matches!(step, PublishStep::WriteTemp | PublishStep::FsyncTemp) {
                assert_eq!(
                    recovered, old_root,
                    "before rename, canonical root must remain old for {step:?}"
                );
            }
        }
    }

    #[test]
    fn epoch_regression_is_rejected() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();

        publish_root(dir.path(), &root(5, 10, "h5"), &k, "trace-seed").expect("seed");
        let err = publish_root(dir.path(), &root(5, 11, "h6"), &k, "trace-regress")
            .expect_err("same epoch should fail");
        assert_eq!(err.code(), "EPOCH_REGRESSION_BLOCKED");

        let err = publish_root(dir.path(), &root(4, 12, "h7"), &k, "trace-regress-2")
            .expect_err("lower epoch should fail");
        assert_eq!(err.code(), "EPOCH_REGRESSION_BLOCKED");
    }

    #[test]
    fn concurrent_publish_calls_are_serialized() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();

        publish_root(dir.path(), &root(1, 1, "h1"), &k, "seed").expect("seed publish");

        let dir_path = dir.path().to_path_buf();
        let key_for_thread = k.clone();
        let t1 = thread::spawn(move || {
            publish_root_with_delay_for_test(
                &dir_path,
                &root(2, 2, "h2"),
                &key_for_thread,
                "thread-1",
                Duration::from_millis(220),
            )
            .expect("thread-1 publish")
        });

        thread::sleep(Duration::from_millis(40));

        let start = Instant::now();
        let t2_outcome =
            publish_root(dir.path(), &root(3, 3, "h3"), &k, "thread-2").expect("thread-2 publish");
        let elapsed = start.elapsed();

        let _ = t1.join().expect("thread-1 join");
        assert!(
            elapsed >= Duration::from_millis(150),
            "second publish should wait behind first (elapsed: {elapsed:?})"
        );
        assert_eq!(t2_outcome.event.event_code, ROOT_PUBLISH_COMPLETE);
    }

    #[test]
    fn signature_verification_fails_for_tampered_event() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let mut outcome =
            publish_root(dir.path(), &root(1, 10, "hash"), &k, "trace-sign").expect("publish");
        assert!(verify_publish_event(&outcome.event, &k).expect("verify"));

        outcome.event.manifest_hash = "tampered".to_string();
        assert!(!verify_publish_event(&outcome.event, &k).expect("verify"));
    }

    #[test]
    fn bootstrap_accepts_valid_root() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(7, 70, "hash-7");
        publish_root(dir.path(), &root, &k, "trace-bootstrap-ok").expect("publish");

        let cfg = RootAuthConfig {
            trust_anchor: k,
            expected_format_version: ROOT_POINTER_FORMAT_VERSION.to_string(),
            current_epoch: ControlEpoch(7),
            max_future_epochs: 0,
        };

        let verified = bootstrap_root(dir.path(), &cfg).expect("bootstrap");
        assert_eq!(verified.root, root);
        assert_eq!(verified.auth.root_format_version, ROOT_POINTER_FORMAT_VERSION);
    }

    #[test]
    fn bootstrap_rejects_missing_root() {
        let dir = TempDir::new().expect("tempdir");
        let cfg = RootAuthConfig::strict(key(), ControlEpoch(1));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("missing root should fail");
        assert!(matches!(err, BootstrapError::RootMissing { .. }));
        assert_eq!(err.code(), "ROOT_BOOTSTRAP_MISSING");
    }

    #[test]
    fn bootstrap_rejects_malformed_root() {
        let dir = TempDir::new().expect("tempdir");
        fs::write(root_pointer_path(dir.path()), b"{ malformed").expect("write malformed root");
        let cfg = RootAuthConfig::strict(key(), ControlEpoch(1));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("malformed root should fail");
        assert!(matches!(err, BootstrapError::RootMalformed { .. }));
        assert_eq!(err.code(), "ROOT_BOOTSTRAP_MALFORMED");
    }

    #[test]
    fn bootstrap_rejects_invalid_auth_material() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(3, 30, "hash-3");
        publish_root(dir.path(), &root, &k, "trace-bootstrap-auth").expect("publish");

        let auth_path = root_auth_path(dir.path());
        let mut auth: RootAuthRecord = serde_json::from_slice(&fs::read(&auth_path).expect("read"))
            .expect("parse auth record");
        auth.mac = "tampered-mac".to_string();
        fs::write(
            &auth_path,
            serde_json::to_vec_pretty(&auth).expect("serialize tampered auth"),
        )
        .expect("write tampered auth");

        let cfg = RootAuthConfig::strict(k, ControlEpoch(3));
        let err = bootstrap_root(dir.path(), &cfg).expect_err("tampered auth should fail");
        assert!(matches!(err, BootstrapError::RootAuthFailed { .. }));
        assert_eq!(err.code(), "ROOT_BOOTSTRAP_AUTH_FAILED");
    }

    #[test]
    fn bootstrap_rejects_future_epoch_root() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(9, 90, "hash-9");
        publish_root(dir.path(), &root, &k, "trace-bootstrap-epoch").expect("publish");

        let cfg = RootAuthConfig {
            trust_anchor: k,
            expected_format_version: ROOT_POINTER_FORMAT_VERSION.to_string(),
            current_epoch: ControlEpoch(7),
            max_future_epochs: 1,
        };

        let err = bootstrap_root(dir.path(), &cfg).expect_err("future epoch must fail");
        assert!(matches!(err, BootstrapError::RootEpochInvalid { .. }));
        assert_eq!(err.code(), "ROOT_BOOTSTRAP_EPOCH_INVALID");
    }

    #[test]
    fn bootstrap_rejects_version_mismatch() {
        let dir = TempDir::new().expect("tempdir");
        let k = key();
        let root = root(4, 40, "hash-4");
        publish_root(dir.path(), &root, &k, "trace-bootstrap-version").expect("publish");

        let cfg = RootAuthConfig {
            trust_anchor: k,
            expected_format_version: "v9".to_string(),
            current_epoch: ControlEpoch(4),
            max_future_epochs: 0,
        };

        let err = bootstrap_root(dir.path(), &cfg).expect_err("version mismatch must fail");
        assert!(matches!(err, BootstrapError::RootVersionMismatch { .. }));
        assert_eq!(err.code(), "ROOT_BOOTSTRAP_VERSION_MISMATCH");
    }
}
